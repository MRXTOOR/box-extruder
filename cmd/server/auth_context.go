package main

import (
	"context"

	"github.com/box-extruder/dast/internal/enterprise/auth"
)

const (
	ciTokenIDContextKey contextKey = "ciTokenId"
	authSourceContextKey contextKey = "authSource"
)

type authSource string

const (
	authSourceJWT     authSource = "jwt"
	authSourceCIToken authSource = "ci_token"
)

func claimsFromContext(ctx context.Context) (*auth.Claims, bool) {
	c, ok := ctx.Value(userContextKey).(*auth.Claims)
	if !ok || c == nil {
		return nil, false
	}
	return c, true
}

func ciTokenIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ciTokenIDContextKey).(string)
	return v
}

func authSourceFromContext(ctx context.Context) authSource {
	v, _ := ctx.Value(authSourceContextKey).(authSource)
	if v == "" {
		return authSourceJWT
	}
	return v
}

func withAuthContext(ctx context.Context, claims *auth.Claims, ciTokenID string, src authSource) context.Context {
	ctx = context.WithValue(ctx, userContextKey, claims)
	if ciTokenID != "" {
		ctx = context.WithValue(ctx, ciTokenIDContextKey, ciTokenID)
	}
	ctx = context.WithValue(ctx, authSourceContextKey, src)
	return ctx
}
