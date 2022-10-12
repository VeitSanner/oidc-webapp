package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/VeitSanner/oidc-webapp/server"
)

func createServeCmd() *cobra.Command {
	var serveCmd = &cobra.Command{
		Use: "serve",
		RunE: func(cmd *cobra.Command, args []string) error {

			serverCfg := &server.Config{
				ListenAddress: viper.GetString("listen"),
				PostLogoutUrl: viper.GetString("postlogout-url"),
				IssuerUrl:     viper.GetString("issuer-url"),
				CallBackUrl:   viper.GetString("callback-url"),

				ClientID:     viper.GetString("client-id"),
				ClientSecret: viper.GetString("client-secret"),
				Scopes:       viper.GetStringSlice("scopes"),
			}

			server.Start(cmd.Context(), serverCfg)

			return nil
		},
	}

	serveCmd.Flags().StringP("listen", "l", ":8080", "Address and port the server listens on, e.g. 127.0.0.1:8080, :8080")
	viper.BindPFlag("listen", serveCmd.Flags().Lookup("listen"))

	serveCmd.Flags().String("template-dir", "templates", "Directory with HTML templates.")
	viper.BindPFlag("template-dir", serveCmd.Flags().Lookup("template-dir"))

	serveCmd.Flags().StringP("issuer-url", "i", "", "Issuer url")
	viper.BindPFlag("issuer-url", serveCmd.Flags().Lookup("issuer-url"))

	serveCmd.Flags().StringP("callback-url", "c", "callback", "Callback url base. Provided URL is extended to [callback-url]/oidc-callback. e.g. http://localhost:9090/oidc-callback")
	viper.BindPFlag("callback-url", serveCmd.Flags().Lookup("callback-url"))

	serveCmd.Flags().StringP("postlogout-url", "p", "postlogout", "postlogout url.")
	viper.BindPFlag("postlogout-url", serveCmd.Flags().Lookup("postlogout-url"))

	serveCmd.Flags().String("client-id", "", "Client ID")
	viper.BindPFlag("client-id", serveCmd.Flags().Lookup("client-id"))

	serveCmd.Flags().String("client-secret", "", "Client Secret")
	viper.BindPFlag("client-secret", serveCmd.Flags().Lookup("client-secret"))

	serveCmd.Flags().StringArrayP("scopes", "s", []string{"openid", "profile"}, "Scopes")
	viper.BindPFlag("scopes", serveCmd.Flags().Lookup("scopes"))

	return serveCmd
}
