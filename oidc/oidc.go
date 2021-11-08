// oidc package was originally obtained from https://github.com/maximRnback/gin-oidc/. It remains to be seen how the changes made are provided to the original package.
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"

	"net/http"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

type InitParams struct {

	//gin router (used to set handler for OIDC)
	Router *gin.Engine

	//id from the authorization service (OIDC provider)
	ClientId string

	//secret from the authorization service (OIDC provider)
	ClientSecret string

	//the URL identifier for the authorization service. for example: "https://accounts.google.com" - try adding "/.well-known/openid-configuration" to the path to make sure it's correct
	Issuer url.URL

	//your website's/service's URL for example: "http://localhost:8081/" or "https://mydomain.com/
	ClientUrl url.URL

	//OAuth scopes. If you're unsure go with: []string{oidc.ScopeOpenID, "profile", "email"}
	Scopes []string

	//errors handler. for example: func(c *gin.Context) {c.String(http.StatusBadRequest, "ERROR...")}
	ErrorHandler gin.HandlerFunc

	//user will be redirected to this URL after he logs out (i.e. accesses the '/logout' endpoint added in 'Init()')
	PostLogoutUrl url.URL
}

func Init(ctx context.Context, i InitParams) gin.HandlerFunc {
	verifier, config := initVerifierAndConfig(ctx, i)

	i.Router.GET("/logout", logoutHandler(i))

	i.Router.Any("/oidc-callback", callbackHandler(i, verifier, config))

	return protectMiddleware(config)
}

func initVerifierAndConfig(ctx context.Context, i InitParams) (*oidc.IDTokenVerifier, *oauth2.Config) {
	provider, err := oidc.NewProvider(ctx, i.Issuer.String())
	if err != nil {
		log.Fatalf("Failed to init OIDC provider. Error: %v \n", err.Error())
	}
	oidcConfig := &oidc.Config{
		ClientID: i.ClientId,
	}
	verifier := provider.Verifier(oidcConfig)
	i.ClientUrl.Path = "oidc-callback"
	config := &oauth2.Config{
		ClientID:     i.ClientId,
		ClientSecret: i.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  i.ClientUrl.String(),
		Scopes:       i.Scopes,
	}
	return verifier, config
}

func logoutHandler(i InitParams) func(c *gin.Context) {
	return func(c *gin.Context) {
		serverSession := sessions.Default(c)
		serverSession.Set("oidcAuthorized", false)
		serverSession.Set("oidcClaims", nil)
		serverSession.Set("oidcState", nil)
		serverSession.Set("oidcOriginalRequestUrl", nil)
		serverSession.Save()
		logoutUrl := i.Issuer
		logoutUrl.RawQuery = (url.Values{"redirect_uri": []string{i.PostLogoutUrl.String()}}).Encode()
		logoutUrl.Path = "protocol/openid-connect/logout"
		c.Redirect(http.StatusFound, logoutUrl.String())
	}
}

func callbackHandler(i InitParams, verifier *oidc.IDTokenVerifier, config *oauth2.Config) func(c *gin.Context) {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		serverSession := sessions.Default(c)

		state, ok := (serverSession.Get("oidcState")).(string)
		if handleOk(c, i, ok, "failed to parse state") {
			return
		}

		if handleOk(c, i, c.Query("state") == state, "get 'state' param didn't match local 'state' value") {
			return
		}

		oauth2Token, err := config.Exchange(ctx, c.Query("code"))
		if handleError(c, i, err, "failed to exchange token") {
			return
		}

		rawAccessToken := oauth2Token.AccessToken
		if rawAccessToken != "" {
			serverSession.Set("access_token", rawAccessToken)
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if handleOk(c, i, ok, "no id_token field in oauth2 token") {
			return
		}
		serverSession.Set("id_token", rawIDToken)

		idToken, err := verifier.Verify(ctx, rawIDToken)
		if handleError(c, i, err, "failed to verify id token") {
			return
		}

		var claims map[string]interface{}
		err = idToken.Claims(&claims)
		if handleError(c, i, err, "failed to parse id token") {
			return
		}

		claimsJson, err := json.Marshal(claims)
		if handleError(c, i, err, "failed to marshal id token: ") {
			return
		}

		originalRequestUrl, ok := (serverSession.Get("oidcOriginalRequestUrl")).(string)
		if handleOk(c, i, ok, "failed to parse originalRequestUrl") {
			return
		}

		serverSession.Set("oidcAuthorized", true)
		serverSession.Set("oidcState", nil)
		serverSession.Set("oidcOriginalRequestUrl", nil)
		serverSession.Set("oidcClaims", string(claimsJson))

		err = serverSession.Save()
		if handleError(c, i, err, "failed save sessions.") {
			return
		}

		c.Redirect(http.StatusFound, originalRequestUrl)
	}
}

func isAuthorized(s sessions.Session) bool {
	authorized := s.Get("oidcAuthorized")
	authb, _ := authorized.(bool)
	return authb
}

func isCallbackUrl(c *gin.Context) bool {
	return c.Request.URL.Path == "oidc-callback"
}

func protectMiddleware(config *oauth2.Config) func(c *gin.Context) {
	return func(c *gin.Context) {
		serverSession := sessions.Default(c)

		if isAuthorized(serverSession) || isCallbackUrl(c) {
			c.Next()
			return
		}

		state := RandomString(16)
		serverSession.Set("oidcAuthorized", false)
		serverSession.Set("oidcState", state)
		serverSession.Set("oidcOriginalRequestUrl", c.Request.URL.String())
		err := serverSession.Save()
		if err != nil {
			log.Fatal("failed save sessions. error: " + err.Error()) // todo handle more gracefully
		}
		c.Redirect(http.StatusFound, config.AuthCodeURL(state)) //redirect to authorization server
		c.Abort()
	}

}

func handleError(c *gin.Context, i InitParams, err error, message string) bool {
	if err == nil {
		return false
	}
	c.Error(errors.New(message))
	i.ErrorHandler(c)
	c.Abort()
	return true
}

func handleOk(c *gin.Context, i InitParams, ok bool, message string) bool {
	if ok {
		return false
	}
	return handleError(c, i, errors.New("not ok"), message)
}

func RandomString(n int) string {

	b := make([]byte, 2*n)

	rand.Read(b)
	r := base64.StdEncoding.EncodeToString(b)

	return r[:n-1]
}
