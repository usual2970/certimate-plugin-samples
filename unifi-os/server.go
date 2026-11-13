package main

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/certimate-go/certimate/pkg/plugin"
)

//go:embed schema
var schemaFS embed.FS

const (
	providerType   = "unifi-os"
	displayNameKey = "plugin.unifi-os.name"
	deployCategory = "other"
)

type deployer struct{}

type accessConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type deployConfig struct {
	ServerURL                string `json:"serverUrl"`
	AllowInsecureConnections bool   `json:"allowInsecureConnections"`
	CleanupOldCertificates   bool   `json:"cleanupOldCertificates"`
}

func (*deployer) GetMetadata(context.Context) (*plugin.Metadata, error) {
	return &plugin.Metadata{
		ProviderType:         providerType,
		AccessProviderType:   providerType,
		ProtocolVersion:      plugin.ProtocolVersion,
		DeployCategory:       deployCategory,
		DeployDisplayNameKey: displayNameKey,
		AccessDisplayNameKey: displayNameKey,
	}, nil
}

func (*deployer) GetConfigSchema(context.Context) (*plugin.ConfigSchema, error) {
	deploySchema, err := plugin.LoadDeploySchema(schemaFS)
	if err != nil {
		return nil, err
	}
	if !json.Valid(deploySchema) {
		return nil, fmt.Errorf("invalid embedded deploy schema")
	}
	accessSchema, err := plugin.LoadAccessSchema(schemaFS)
	if err != nil {
		return nil, err
	}
	if !json.Valid(accessSchema) {
		return nil, fmt.Errorf("missing or invalid embedded access schema")
	}
	i18n, err := plugin.LoadI18n(schemaFS)
	if err != nil {
		return nil, err
	}
	return &plugin.ConfigSchema{
		AccessSchemaJSON: accessSchema,
		DeploySchemaJSON: deploySchema,
		I18n:             i18n,
	}, nil
}

func (*deployer) Deploy(ctx context.Context, req *plugin.DeployRequest, logger *slog.Logger) (*plugin.DeployResult, error) {
	var access accessConfig
	if err := json.Unmarshal([]byte(req.AccessConfigJSON), &access); err != nil {
		return nil, fmt.Errorf("invalid UniFi OS credentials configuration")
	}
	access.Username = strings.TrimSpace(access.Username)
	if access.Username == "" || access.Password == "" {
		return nil, fmt.Errorf("UniFi OS local administrator username and password are required")
	}
	var cfg deployConfig
	if err := json.Unmarshal([]byte(req.ExtendedConfigJSON), &cfg); err != nil {
		return nil, fmt.Errorf("invalid UniFi OS deployment configuration")
	}
	endpoint, err := url.Parse(strings.TrimSpace(cfg.ServerURL))
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil ||
		(endpoint.Path != "" && endpoint.Path != "/") || endpoint.RawPath != "" ||
		endpoint.ForceQuery || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, fmt.Errorf("UniFi OS management URL must be an HTTPS origin, such as https://unifi.example.com:11443")
	}
	pair, err := tls.X509KeyPair([]byte(req.CertificatePEM), []byte(req.PrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("invalid UniFi OS certificate or private key: %w", err)
	}
	leaf := pair.Leaf
	fingerprint := sha1.Sum(leaf.Raw)
	group, name := certificateName(leaf)

	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	api := newConsoleClient(endpoint, cfg.AllowInsecureConnections)
	defer api.http.CloseIdleConnections()

	if err := api.login(ctx, access); err != nil {
		return nil, err
	}
	id, err := api.upload(ctx, uploadRequest{Name: name, Key: req.PrivateKeyPEM, Cert: req.CertificatePEM}, hex.EncodeToString(fingerprint[:]))
	if err != nil {
		return nil, err
	}
	if err := api.activate(ctx, id); err != nil {
		return nil, err
	}
	if err := api.verifyTLS(ctx, sha256.Sum256(leaf.Raw)); err != nil {
		return nil, err
	}
	if logger != nil {
		logger.Info("UniFi OS is serving the deployed certificate", "target", endpoint.Host)
	}

	if cfg.CleanupOldCertificates {
		api.cleanup(ctx, logger, group, leaf.NotBefore.Unix(), id)
	}
	return &plugin.DeployResult{}, nil
}

func certificateName(leaf *x509.Certificate) (group, name string) {
	identities := append([]string(nil), leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		identities = append(identities, ip.String())
	}
	for _, uri := range leaf.URIs {
		identities = append(identities, uri.String())
	}
	identities = append(identities, leaf.EmailAddresses...)
	slices.Sort(identities)
	scope := leaf.Subject.String() + "\x00" + leaf.PublicKeyAlgorithm.String() + "\x00" + strings.Join(identities, "\x00")
	groupHash := sha256.Sum256([]byte(scope))
	certHash := sha256.Sum256(leaf.Raw)
	group = "certimate-" + hex.EncodeToString(groupHash[:8]) + "-"
	name = group + strconv.FormatInt(leaf.NotBefore.Unix(), 10) + "-" + hex.EncodeToString(certHash[:12])
	return group, name
}
