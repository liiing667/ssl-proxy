package reverseproxy

import "context"

type clientIdentityContextKey struct{}

func contextWithClientIdentity(ctx context.Context, identity *ClientIdentity) context.Context {
	return context.WithValue(ctx, clientIdentityContextKey{}, identity)
}

func clientIdentityFromContext(ctx context.Context) (*ClientIdentity, bool) {
	identity, ok := ctx.Value(clientIdentityContextKey{}).(*ClientIdentity)
	return identity, ok
}
