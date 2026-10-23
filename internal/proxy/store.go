package proxy

import (
	"context"
	"time"

	"portlyn/internal/routing"
)

type RouteFilter = routing.RouteFilter
type RouteConfig = routing.RouteConfig
type RoutingStore = routing.Store

type ConfigCache interface {
	GetRoutesForHost(ctx context.Context, host string) ([]RouteConfig, bool, error)
	SetRoutesForHost(ctx context.Context, host string, routes []RouteConfig, ttl time.Duration) error
	InvalidateHost(ctx context.Context, host string) error
	InvalidateAll(ctx context.Context) error
}

type RouteChangedEvent struct {
	Host      string    `json:"host"`
	ChangedAt time.Time `json:"changed_at"`
}

type ConfigBus interface {
	PublishRouteChanged(ctx context.Context, host string) error
	SubscribeRouteChanged(ctx context.Context) <-chan RouteChangedEvent
}
