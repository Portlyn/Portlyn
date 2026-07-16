package auth

import (
	"context"

	"portlyn/internal/domain"
)

type contextKey string

const userContextKey contextKey = "user"
const groupIDsContextKey contextKey = "group_ids"
const sessionContextKey contextKey = "session"
const apiTokenAuthContextKey contextKey = "api_token_auth"

func ContextWithAPITokenAuth(ctx context.Context) context.Context {
	return context.WithValue(ctx, apiTokenAuthContextKey, true)
}

func IsAPITokenAuth(ctx context.Context) bool {
	v, _ := ctx.Value(apiTokenAuthContextKey).(bool)
	return v
}

func ContextWithUser(ctx context.Context, user *domain.User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

func ContextWithGroupIDs(ctx context.Context, groupIDs []uint) context.Context {
	return context.WithValue(ctx, groupIDsContextKey, append([]uint(nil), groupIDs...))
}

func ContextWithSession(ctx context.Context, session *domain.Session) context.Context {
	return context.WithValue(ctx, sessionContextKey, session)
}

func UserFromContext(ctx context.Context) (*domain.User, bool) {
	user, ok := ctx.Value(userContextKey).(*domain.User)
	return user, ok
}

func GroupIDsFromContext(ctx context.Context) ([]uint, bool) {
	groupIDs, ok := ctx.Value(groupIDsContextKey).([]uint)
	if !ok {
		return nil, false
	}
	return append([]uint(nil), groupIDs...), true
}

func SessionFromContext(ctx context.Context) (*domain.Session, bool) {
	session, ok := ctx.Value(sessionContextKey).(*domain.Session)
	return session, ok
}
