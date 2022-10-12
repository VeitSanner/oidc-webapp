package server

import (
	"context"
	"embed"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/VeitSanner/oidc-webapp/oidc"
	"github.com/gin-gonic/gin"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
)

type Config struct {
	ListenAddress string
	IssuerUrl     string
	CallBackUrl   string
	PostLogoutUrl string
	ClientID      string
	ClientSecret  string
	Scopes        []string
}

//go:embed templates
var templates embed.FS

func Start(ctx context.Context, cfg *Config) error {

	templ := template.Must(template.New("").Funcs(template.FuncMap{
		"prettyHtml": prettyHtml,
	}).ParseFS(templates, "templates/*"))

	router := gin.Default()
	router.SetHTMLTemplate(templ)

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

		atRaw := auth.Get("access_token").(string)
		atPretty, _ := oidc.DecodeJwt(atRaw, true)
		log.Printf("%v", atPretty)

		idSession := sessions.DefaultMany(c, "id")
		itRaw := idSession.Get("id_token").(string)
		itPretty, _ := oidc.DecodeJwt(itRaw, true)
		log.Printf("%v", atPretty)

		c.HTML(http.StatusOK, "login.html", gin.H{
			"access_token": template.HTML(atPretty),
			"id_token":     template.HTML(itPretty),
		})
	})

	router.GET("/protected", protectMiddleware, func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	})

	return router.Run(cfg.ListenAddress)
}

func prettyHtml(t template.HTML) template.HTML {
	c := string(t)
	r := strings.ReplaceAll(c, "\n", "<br>")
	r = strings.ReplaceAll(r, "\t", "&nbsp;&nbsp;&nbsp;&nbsp;")
	return template.HTML(r)
}
