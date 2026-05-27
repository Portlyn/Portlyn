package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"portlyn/internal/domain"
	"portlyn/internal/routing"
)

type SQLRoutingStore struct {
	db *gorm.DB
}

func NewRoutingStore(db *gorm.DB) *SQLRoutingStore {
	return &SQLRoutingStore{db: db}
}

func (s *SQLRoutingStore) GetRoutesForHost(ctx context.Context, host string) ([]routing.RouteConfig, error) {
	var services []domain.Service
	host = strings.ToLower(strings.TrimSpace(host))
	err := s.baseQuery(ctx).
		Where(`LOWER("Domain"."name") IN ?`, domainCandidatesForHost(host)).
		Order("services.path asc").
		Find(&services).Error
	if err != nil {
		return nil, err
	}
	return filterRoutesByHost(s.toRouteConfigs(services), host), nil
}

func (s *SQLRoutingStore) ListRoutes(ctx context.Context, filter routing.RouteFilter) ([]routing.RouteConfig, error) {
	query := s.baseQuery(ctx)
	if filter.Host != "" {
		query = query.Where(`LOWER("Domain"."name") IN ?`, domainCandidatesForHost(filter.Host))
	}
	if filter.ServiceID != "" {
		if parsed, err := strconv.ParseUint(strings.TrimSpace(filter.ServiceID), 10, strconv.IntSize); err == nil {
			query = query.Where("services.id = ?", uint(parsed))
		}
	}
	if filter.DomainID != 0 {
		query = query.Where("services.domain_id = ?", filter.DomainID)
	}
	if filter.Limit > 0 {
		query = query.Limit(filter.Limit)
	}
	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}

	var services []domain.Service
	if err := query.Order(`"Domain"."name" asc, services.path asc, services.id asc`).Find(&services).Error; err != nil {
		return nil, err
	}
	return filterRoutesByHost(s.toRouteConfigs(services), filter.Host), nil
}

func (s *SQLRoutingStore) GetRouteByID(ctx context.Context, id string) (*routing.RouteConfig, error) {
	parsedID, err := strconv.ParseUint(strings.TrimSpace(id), 10, strconv.IntSize)
	if err != nil {
		return nil, ErrNotFound
	}

	var service domain.Service
	err = s.baseQuery(ctx).First(&service, uint(parsedID)).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	configs := s.toRouteConfigs([]domain.Service{service})
	if len(configs) == 0 {
		return nil, ErrNotFound
	}
	return &configs[0], nil
}

func (s *SQLRoutingStore) UpsertRoute(ctx context.Context, route routing.RouteConfig) error {
	service := route.Service
	service.Name = firstNonEmpty(route.ServiceName, service.Name)
	service.DomainID = firstUint(route.DomainID, service.DomainID)
	service.Path = firstNonEmpty(route.Path, service.Path)
	service.TargetURL = firstNonEmpty(route.TargetURL, service.TargetURL)
	service.TLSMode = firstNonEmpty(route.TLSMode, service.TLSMode)
	service.AccessMessage = firstNonEmpty(route.AccessMessage, service.AccessMessage)

	service.AccessMode = route.EffectivePolicy.AccessMode
	service.AllowedRoles = append(domain.JSONStringSlice(nil), route.EffectivePolicy.AllowedRoles...)
	service.AllowedGroups = append(domain.JSONUintSlice(nil), route.EffectivePolicy.AllowedGroups...)
	service.AllowedServiceGroups = append(domain.JSONUintSlice(nil), route.EffectivePolicy.AllowedServiceGroups...)
	service.AccessMethod = route.EffectiveMethod
	service.AccessMethodConfig = cloneJSONObject(route.EffectiveMethodConfig)
	service.IPAllowlist = append(domain.JSONStringSlice(nil), route.AllowCIDRs...)
	service.IPBlocklist = append(domain.JSONStringSlice(nil), route.BlockCIDRs...)
	service.AccessWindows = append(domain.AccessWindowList(nil), route.AccessWindows...)

	if route.ServiceID != 0 {
		service.ID = route.ServiceID
	}
	if service.ID == 0 && route.ID != "" {
		parsedID, err := strconv.ParseUint(strings.TrimSpace(route.ID), 10, strconv.IntSize)
		if err == nil {
			service.ID = uint(parsedID)
		}
	}
	if service.ID == 0 {
		return s.db.WithContext(ctx).Create(&service).Error
	}
	return s.db.WithContext(ctx).Omit("Domain", "ServiceGroups.*").Save(&service).Error
}

func (s *SQLRoutingStore) DeleteRoute(ctx context.Context, id string) error {
	parsedID, err := strconv.ParseUint(strings.TrimSpace(id), 10, strconv.IntSize)
	if err != nil {
		return ErrNotFound
	}
	result := s.db.WithContext(ctx).Delete(&domain.Service{}, uint(parsedID))
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLRoutingStore) baseQuery(ctx context.Context) *gorm.DB {
	return s.db.WithContext(ctx).
		Model(&domain.Service{}).
		Joins("Domain").
		Preload("Domain").
		Preload("Node").
		Preload("ServiceGroups")
}

func (s *SQLRoutingStore) toRouteConfigs(services []domain.Service) []routing.RouteConfig {
	routes := make([]routing.RouteConfig, 0, len(services))
	for _, service := range services {
		if strings.TrimSpace(service.Domain.Name) == "" {
			continue
		}
		policy, method, methodConfig, inherited := effectiveAccessForService(service)
		routes = append(routes, routing.RouteConfig{
			ID:                    fmt.Sprintf("%d", service.ID),
			ServiceID:             service.ID,
			ServiceName:           service.Name,
			DomainID:              service.DomainID,
			Host:                  domain.ServiceHost(service),
			Path:                  service.Path,
			TargetURL:             service.TargetURL,
			TLSMode:               service.TLSMode,
			AccessMessage:         service.AccessMessage,
			Service:               service,
			EffectivePolicy:       policy,
			EffectiveMethod:       method,
			EffectiveMethodConfig: cloneJSONObject(methodConfig),
			InheritedFromGroup:    inherited,
			AllowCIDRs:            append([]string{}, append(append([]string{}, service.Domain.IPAllowlist...), service.IPAllowlist...)...),
			BlockCIDRs:            append([]string{}, append(append([]string{}, service.Domain.IPBlocklist...), service.IPBlocklist...)...),
			AllowedCountries:      append([]string{}, service.AllowedCountries...),
			BlockedCountries:      append([]string{}, service.BlockedCountries...),
			AccessWindows:         append([]domain.AccessWindow{}, service.AccessWindows...),
			DeploymentRevision:    service.DeploymentRevision,
			LastDeployedAt:        service.LastDeployedAt,
		})
	}
	return routes
}

func filterRoutesByHost(routes []routing.RouteConfig, host string) []routing.RouteConfig {
	normalizedHost := strings.ToLower(strings.TrimSpace(host))
	if normalizedHost == "" {
		return routes
	}
	filtered := make([]routing.RouteConfig, 0, len(routes))
	for _, route := range routes {
		if strings.ToLower(strings.TrimSpace(route.Host)) == normalizedHost {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func domainCandidatesForHost(host string) []string {
	normalizedHost := strings.ToLower(strings.TrimSpace(host))
	if normalizedHost == "" {
		return nil
	}
	parts := strings.Split(normalizedHost, ".")
	candidates := make([]string, 0, len(parts))
	for i := range parts {
		candidate := strings.Join(parts[i:], ".")
		if candidate != "" {
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

func effectiveAccessForService(service domain.Service) (domain.AccessPolicy, string, domain.JSONObject, *domain.ServiceGroup) {
	sort.Slice(service.ServiceGroups, func(i, j int) bool {
		return service.ServiceGroups[i].ID < service.ServiceGroups[j].ID
	})
	serviceMethod := strings.TrimSpace(service.AccessMethod)
	if !service.UseGroupPolicy {
		return normalizedPolicy(domain.AccessPolicy{
				AccessMode:           service.AccessMode,
				AllowedRoles:         service.AllowedRoles,
				AllowedGroups:        service.AllowedGroups,
				AllowedServiceGroups: service.AllowedServiceGroups,
			}, service.AuthPolicy),
			normalizedAccessMethod(serviceMethod),
			cloneJSONObject(service.AccessMethodConfig),
			nil
	}
	for _, group := range service.ServiceGroups {
		if strings.TrimSpace(group.DefaultAccessPolicy.AccessMode) != "" || strings.TrimSpace(group.AccessMethod) != "" {
			copyGroup := group
			method := strings.TrimSpace(group.AccessMethod)
			config := cloneJSONObject(group.AccessMethodConfig)
			if serviceMethod != "" {
				method = serviceMethod
				config = cloneJSONObject(service.AccessMethodConfig)
			}
			return normalizedPolicy(group.DefaultAccessPolicy, service.AuthPolicy), normalizedAccessMethod(method), config, &copyGroup
		}
	}
	return normalizedPolicy(domain.AccessPolicy{}, service.AuthPolicy), normalizedAccessMethod(serviceMethod), cloneJSONObject(service.AccessMethodConfig), nil
}

func normalizedPolicy(policy domain.AccessPolicy, legacy string) domain.AccessPolicy {
	if strings.TrimSpace(policy.AccessMode) == "" {
		switch legacy {
		case domain.AuthPolicyPublic:
			policy.AccessMode = domain.AccessModePublic
		case domain.AuthPolicyAdminOnly:
			policy.AccessMode = domain.AccessModeRestricted
			policy.AllowedRoles = domain.JSONStringSlice{domain.RoleAdmin}
		default:
			policy.AccessMode = domain.AccessModeAuthenticated
		}
	}
	return policy
}

func normalizedAccessMethod(value string) string {
	switch strings.TrimSpace(value) {
	case "", domain.AccessMethodSession:
		return domain.AccessMethodSession
	case domain.AccessMethodOIDCOnly:
		return domain.AccessMethodOIDCOnly
	case domain.AccessMethodPIN:
		return domain.AccessMethodPIN
	case domain.AccessMethodEmailCode:
		return domain.AccessMethodEmailCode
	default:
		return domain.AccessMethodSession
	}
}

func cloneJSONObject(value domain.JSONObject) domain.JSONObject {
	if len(value) == 0 {
		return domain.JSONObject{}
	}
	out := make(domain.JSONObject, len(value))
	for key, item := range value {
		out[key] = item
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func firstUint(values ...uint) uint {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
