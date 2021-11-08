package server

import (
	"context"
	"log"
	"net/http"
	"net/url"

	"github.com/VeitSanner/oidc-webapp/oidc"
	"github.com/gin-gonic/gin"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
)

type Config struct {
	ListenAddress   string
	TemplateDirGlob string
	IssuerUrl       string
	CallBackUrl     string
	PostLogoutUrl   string
	ClientID        string
	ClientSecret    string
	Scopes          []string
}

func Start(ctx context.Context, cfg *Config) error {

	router := gin.Default()
	router.LoadHTMLGlob(cfg.TemplateDirGlob)

	store := cookie.NewStore([]byte("secret"))
	router.Use(sessions.SessionsMany([]string{"session", "auth", "id"}, store))

	issuer, _ := url.Parse(cfg.IssuerUrl)
	callbackUrl, _ := url.Parse(cfg.CallBackUrl)
	postLogoutUrl, _ := url.Parse(cfg.PostLogoutUrl)

	initParams := oidc.InitParams{
		Router:       router,
		ClientId:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Issuer:       *issuer,
		ClientUrl:    *callbackUrl,
		Scopes:       cfg.Scopes,
		ErrorHandler: func(c *gin.Context) {
			log.Fatalf("%v", c)
		},
		PostLogoutUrl: *postLogoutUrl,
	}

	router.GET("/index", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	})

	protectMiddleware := oidc.Init(ctx, initParams)

	router.GET("/login", protectMiddleware, func(c *gin.Context) {
		auth := sessions.DefaultMany(c, "auth")

		accessToken := auth.Get("access_token")
		log.Printf("%v", accessToken)

		idSession := sessions.DefaultMany(c, "id")
		id_token := idSession.Get("id_token")

		c.HTML(http.StatusOK, "login.html", gin.H{
			"access_token": accessToken,
			"id_token":     id_token,
		})
	})

	router.GET("/protected", protectMiddleware, func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	})

	return router.Run(cfg.ListenAddress)
}
