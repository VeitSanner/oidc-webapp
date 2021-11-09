package oidc

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

// Decode decodes a raw JWT token to a JSON object. The token provided is not validated,
// if it has been tampered with.
func DecodeJwt(tokenString string, pretty bool) (string, error) {

	parser := jwt.Parser{}

	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("parsing jwt error: %w", err)
	}

	indentString := ""
	if pretty {
		indentString = "\t"
	}

	jsonToken := &strings.Builder{}
	enc := json.NewEncoder(jsonToken)
	enc.SetIndent("", indentString)
	enc.Encode(token)

	return jsonToken.String(), nil
}
