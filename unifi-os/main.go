package main

import (
	"github.com/certimate-go/certimate/pkg/plugin"
	githubplugin "github.com/hashicorp/go-plugin"
)

func main() {
	githubplugin.Serve(&githubplugin.ServeConfig{
		HandshakeConfig: plugin.HandshakeConfig,
		Plugins: plugin.PluginSet{
			plugin.PluginName: &plugin.DeployerGRPCPlugin{Impl: &deployer{}},
		},
		GRPCServer: githubplugin.DefaultGRPCServer,
	})
}
