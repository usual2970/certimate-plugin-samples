package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const certificatesPath = "/api/userCertificates"

var certificateID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type consoleClient struct {
	endpoint *url.URL
	http     *http.Client
	token    *http.Cookie
	csrf     string
}

type uploadRequest struct {
	Name string `json:"name"`
	Key  string `json:"key"`
	Cert string `json:"cert"`
}

type certificateEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	Active      *bool  `json:"active"`
}

func newConsoleClient(endpoint *url.URL, allowInsecure bool) *consoleClient {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: allowInsecure}
	return &consoleClient{
		endpoint: endpoint,
		http: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *consoleClient) login(ctx context.Context, access accessConfig) error {
	body := struct {
		accessConfig
		Token      string `json:"token"`
		RememberMe bool   `json:"rememberMe"`
	}{accessConfig: access}
	resp, err := c.request(ctx, "log in", http.MethodPost, "/api/auth/login", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return c.statusError("log in", resp)
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "TOKEN" && cookie.Value != "" {
			c.token = cookie
			break
		}
	}
	if c.token == nil {
		return fmt.Errorf("UniFi OS %s: login did not return a TOKEN cookie", c.endpoint.Host)
	}
	parts := strings.Split(c.token.Value, ".")
	if len(parts) != 3 {
		return fmt.Errorf("UniFi OS %s: invalid login session token", c.endpoint.Host)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return fmt.Errorf("UniFi OS %s: invalid login session token", c.endpoint.Host)
	}
	var claims struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || strings.TrimSpace(claims.CSRFToken) == "" {
		return fmt.Errorf("UniFi OS %s: login session token is missing a CSRF token", c.endpoint.Host)
	}
	c.csrf = claims.CSRFToken
	return nil
}

func (c *consoleClient) upload(ctx context.Context, body uploadRequest, fingerprint string) (string, error) {
	resp, err := c.request(ctx, "upload certificate", http.MethodPost, certificatesPath, body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated:
		var entry certificateEntry
		if err := decodeResponse(resp.Body, &entry); err != nil || !certificateID.MatchString(entry.ID) {
			return "", fmt.Errorf("UniFi OS %s: upload response is missing a valid certificate ID", c.endpoint.Host)
		}
		return entry.ID, nil
	case http.StatusBadRequest:
		data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if err != nil || !bytes.Contains(data, []byte(`"USER_CERTIFICATE_DUPLICATE"`)) {
			return "", c.statusError("upload certificate", resp)
		}
		entries, err := c.list(ctx)
		if err != nil {
			return "", err
		}
		for _, entry := range entries {
			if strings.EqualFold(strings.ReplaceAll(entry.Fingerprint, ":", ""), fingerprint) && certificateID.MatchString(entry.ID) {
				return entry.ID, nil
			}
		}
		return "", fmt.Errorf("UniFi OS %s: upload reported a duplicate but no certificate matched the fingerprint", c.endpoint.Host)
	default:
		return "", c.statusError("upload certificate", resp)
	}
}

func (c *consoleClient) activate(ctx context.Context, id string) error {
	resp, err := c.request(ctx, "activate certificate", http.MethodPut, certificatesPath+"/"+id+"/status", struct {
		Active bool `json:"active"`
	}{Active: true})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return c.statusError("activate certificate", resp)
	}
	return nil
}

func (c *consoleClient) list(ctx context.Context) ([]certificateEntry, error) {
	resp, err := c.request(ctx, "list certificates", http.MethodGet, certificatesPath, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, c.statusError("list certificates", resp)
	}
	var entries []certificateEntry
	if err := decodeResponse(resp.Body, &entries); err != nil || entries == nil {
		return nil, fmt.Errorf("UniFi OS %s: invalid certificate list response", c.endpoint.Host)
	}
	return entries, nil
}

func (c *consoleClient) cleanup(ctx context.Context, logger *slog.Logger, group string, issuedAt int64, id string) {
	entries, err := c.list(ctx)
	if err != nil {
		if logger != nil {
			logger.Warn("Could not list UniFi OS certificates for cleanup", "error", err)
		}
		return
	}
	for _, entry := range entries {
		suffix, managed := strings.CutPrefix(entry.Name, group)
		timestamp, hash, named := strings.Cut(suffix, "-")
		older, timestampErr := strconv.ParseInt(timestamp, 10, 64)
		hashBytes, hashErr := hex.DecodeString(hash)
		if !managed || !named || timestampErr != nil || hashErr != nil || len(hashBytes) != 12 ||
			older >= issuedAt || entry.Active == nil || *entry.Active || entry.ID == id || !certificateID.MatchString(entry.ID) {
			continue
		}
		if err := c.remove(ctx, entry.ID); err != nil && logger != nil {
			logger.Warn("Could not remove older UniFi OS certificate", "error", err)
		}
	}
}

func (c *consoleClient) remove(ctx context.Context, id string) error {
	resp, err := c.request(ctx, "remove older certificate", http.MethodDelete, certificatesPath+"/"+id, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	default:
		return c.statusError("remove older certificate", resp)
	}
}

func (c *consoleClient) verifyTLS(ctx context.Context, expected [sha256.Size]byte) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	port := c.endpoint.Port()
	if port == "" {
		port = "443"
	}
	host := c.endpoint.Hostname()
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 3 * time.Second},
		Config:    &tls.Config{ServerName: host, InsecureSkipVerify: true},
	}
	for {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err == nil {
			peers := conn.(*tls.Conn).ConnectionState().PeerCertificates
			conn.Close()
			if len(peers) > 0 && sha256.Sum256(peers[0].Raw) == expected {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("UniFi OS %s: could not verify the deployed certificate on the management TLS endpoint: %w", c.endpoint.Host, ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

func (c *consoleClient) request(ctx context.Context, operation, method, path string, body any) (*http.Response, error) {
	endpoint := *c.endpoint
	endpoint.Path = path
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("UniFi OS %s: encode %s request", c.endpoint.Host, operation)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
	if err != nil {
		return nil, fmt.Errorf("UniFi OS %s: build %s request", c.endpoint.Host, operation)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != nil {
		req.AddCookie(c.token)
		if method != http.MethodGet {
			req.Header.Set("X-CSRF-Token", c.csrf)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("UniFi OS %s: %s: %w", c.endpoint.Host, operation, ctx.Err())
		}
		if tlsErr, ok := err.(*url.Error); ok {
			if _, ok := tlsErr.Err.(*tls.CertificateVerificationError); ok {
				return nil, fmt.Errorf("UniFi OS %s: %s failed because the management TLS certificate could not be verified", c.endpoint.Host, operation)
			}
		}
		return nil, fmt.Errorf("UniFi OS %s: %s request failed", c.endpoint.Host, operation)
	}
	return resp, nil
}

func (c *consoleClient) statusError(operation string, resp *http.Response) error {
	return fmt.Errorf("UniFi OS %s: %s failed (HTTP %d)", c.endpoint.Host, operation, resp.StatusCode)
}

func decodeResponse(body io.Reader, dest any) error {
	const limit = 4 << 20
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return err
	}
	if len(data) > limit {
		return fmt.Errorf("response exceeds %d bytes", limit)
	}
	return json.Unmarshal(data, dest)
}
