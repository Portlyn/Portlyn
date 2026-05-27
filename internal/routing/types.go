package routing

import (
	"context"
	"time"

	"portlyn/internal/domain"
)

type RouteFilter struct {
	Host      string
	ServiceID string
	DomainID  uint
	Limit     int
	Offset    int
}

type RouteConfig struct {
	ID                    string                `json:"id"`
	ServiceID             uint                  `json:"service_id"`
	ServiceName           string                `json:"service_name"`
	DomainID              uint                  `json:"domain_id"`
	Host                  string                `json:"host"`
	Path                  string                `json:"path"`
	TargetURL             string                `json:"target_url"`
	TLSMode               string                `json:"tls_mode"`
	AccessMessage         string                `json:"access_message"`
	Service               domain.Service        `json:"service"`
	EffectivePolicy       domain.AccessPolicy   `json:"effective_policy"`
	EffectiveMethod       string                `json:"effective_method"`
	EffectiveMethodConfig domain.JSONObject     `json:"effective_method_config"`
	InheritedFromGroup    *domain.ServiceGroup  `json:"inherited_from_group,omitempty"`
	AllowCIDRs            []string              `json:"allow_cidrs"`
	BlockCIDRs            []string              `json:"block_cidrs"`
	AllowedCountries      []string              `json:"allowed_countries"`
	BlockedCountries      []string              `json:"blocked_countries"`
	AccessWindows         []domain.AccessWindow `json:"access_windows"`
	DeploymentRevision    uint64                `json:"deployment_revision"`
	LastDeployedAt        *time.Time            `json:"last_deployed_at,omitempty"`
}

type Store interface {
	GetRoutesForHost(ctx context.Context, host string) ([]RouteConfig, error)
	ListRoutes(ctx context.Context, filter RouteFilter) ([]RouteConfig, error)
	GetRouteByID(ctx context.Context, id string) (*RouteConfig, error)
	UpsertRoute(ctx context.Context, route RouteConfig) error
	DeleteRoute(ctx context.Context, id string) error
}
