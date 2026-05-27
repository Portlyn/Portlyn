package http

import (
	"encoding/json"
	stdhttp "net/http"
	"net/netip"
	"strings"
	"time"

	"portlyn/internal/domain"
	"portlyn/internal/store"
)

type denialEvent struct {
	ID         uint      `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	RequestID  string    `json:"request_id"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	Path       string    `json:"path"`
	StatusCode int       `json:"status_code"`
	LatencyMs  int64     `json:"latency_ms"`
	RemoteAddr string    `json:"remote_addr"`
	UserAgent  string    `json:"user_agent"`
	Outcome    string    `json:"outcome"`
	Reason     string    `json:"reason"`
	UserID     *uint     `json:"user_id,omitempty"`
}

func (s *Server) handleListServiceDenials(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadService(w, r)
	if !ok {
		return
	}
	limit := parseIntQuery(r, "limit", 20)
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	resourceID := item.ID
	params := store.AuditListParams{
		ResourceType: "service",
		ResourceID:   &resourceID,
		ActionLike:   "proxy_access",
		Limit:        200,
		Offset:       0,
	}
	items, _, err := s.auditStore.List(r.Context(), params)
	if err != nil {
		s.internalError(w, err)
		return
	}

	out := make([]denialEvent, 0, limit)
	for _, log := range items {
		if len(out) >= limit {
			break
		}
		details := parseDetailString(log.Details)
		outcome := stringFromMap(details, "outcome")
		if outcome != "denied" && outcome != "not_found" {
			continue
		}
		out = append(out, denialEvent{
			ID:         log.ID,
			Timestamp:  log.Timestamp,
			RequestID:  log.RequestID,
			Method:     log.Method,
			Host:       log.Host,
			Path:       log.Path,
			StatusCode: log.StatusCode,
			LatencyMs:  log.LatencyMs,
			RemoteAddr: log.RemoteAddr,
			UserAgent:  log.UserAgent,
			Outcome:    outcome,
			Reason:     stringFromMap(details, "reason"),
			UserID:     log.UserID,
		})
	}

	writeJSON(w, stdhttp.StatusOK, map[string]any{
		"items": out,
		"limit": limit,
	})
}

type explainRequest struct {
	UserEmail string `json:"user_email"`
	ClientIP  string `json:"client_ip"`
	Time      string `json:"time"`
	Method    string `json:"method"`
	Path      string `json:"path"`
}

type explainStep struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type explainResponse struct {
	ServiceID uint          `json:"service_id"`
	Allowed   bool          `json:"allowed"`
	Decision  string        `json:"decision"`
	Steps     []explainStep `json:"steps"`
}

func (s *Server) handleExplainServiceAccess(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadService(w, r)
	if !ok {
		return
	}

	var req explainRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}

	steps := make([]explainStep, 0, 8)
	allowed := true
	decision := "allowed"

	checkAt := time.Now().UTC()
	if strings.TrimSpace(req.Time) != "" {
		if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(req.Time)); err == nil {
			checkAt = parsed.UTC()
		}
	}

	clientAddr, clientAddrValid := netip.Addr{}, false
	if trimmed := strings.TrimSpace(req.ClientIP); trimmed != "" {
		if addr, err := netip.ParseAddr(trimmed); err == nil {
			clientAddr = addr
			clientAddrValid = true
		}
	}

	steps = append(steps, explainStep{
		Name:    "service_deployed",
		Status:  statusForBool(item.LastDeployedAt != nil),
		Message: statusMessageDeployed(item),
	})
	if item.LastDeployedAt == nil {
		allowed = false
		decision = "deny_not_deployed"
	}

	if len(item.IPBlocklist) > 0 {
		blockHit := false
		if clientAddrValid {
			blockHit = matchesCIDRList(clientAddr, item.IPBlocklist)
		}
		steps = append(steps, explainStep{
			Name:    "ip_blocklist",
			Status:  statusForBool(!blockHit),
			Message: ifThenElse(blockHit, "Client IP is on blocklist.", "Client IP is not on blocklist."),
		})
		if blockHit {
			allowed = false
			decision = "deny_blocklist"
		}
	}

	if len(item.IPAllowlist) > 0 {
		allowed_ip := false
		if clientAddrValid {
			allowed_ip = matchesCIDRList(clientAddr, item.IPAllowlist)
		}
		steps = append(steps, explainStep{
			Name:    "ip_allowlist",
			Status:  statusForBool(allowed_ip),
			Message: ifThenElse(allowed_ip, "Client IP matches allowlist.", "Client IP does not match allowlist."),
		})
		if !allowed_ip {
			allowed = false
			if decision == "allowed" {
				decision = "deny_allowlist"
			}
		}
	}

	if len(item.AccessWindows) > 0 {
		window_hit := windowMatchesAt(item.AccessWindows, checkAt)
		steps = append(steps, explainStep{
			Name:    "access_window",
			Status:  statusForBool(window_hit),
			Message: ifThenElse(window_hit, "Current time falls inside an access window.", "No access window matches the requested time."),
		})
		if !window_hit {
			allowed = false
			if decision == "allowed" {
				decision = "deny_access_window"
			}
		}
	}

	mode := strings.TrimSpace(item.AccessMode)
	if mode == "" {
		mode = "authenticated"
	}
	switch mode {
	case "public":
		steps = append(steps, explainStep{
			Name:    "access_mode",
			Status:  "ok",
			Message: "Access mode is public — no user authentication required.",
		})
	default:
		steps = append(steps, explainStep{
			Name:    "access_mode",
			Status:  "info",
			Message: "Access mode is " + mode + " — user authentication required.",
		})
		var user *domain.User
		if email := strings.TrimSpace(req.UserEmail); email != "" {
			if found, err := s.users.GetByEmail(r.Context(), email); err == nil {
				user = found
			}
		}
		if user == nil {
			steps = append(steps, explainStep{
				Name:    "user_resolved",
				Status:  "fail",
				Message: "Provide a user_email to evaluate authenticated access.",
			})
			allowed = false
			if decision == "allowed" {
				decision = "deny_unauthenticated"
			}
			break
		}
		steps = append(steps, explainStep{
			Name:    "user_resolved",
			Status:  "ok",
			Message: "User found: " + user.Email + " (role=" + user.Role + ")",
		})
		if !user.Active {
			steps = append(steps, explainStep{
				Name:    "user_active",
				Status:  "fail",
				Message: "User account is inactive.",
			})
			allowed = false
			decision = "deny_inactive_user"
			break
		}

		if mode == "restricted" {
			groupIDs, err := s.groups.ListGroupIDsForUser(r.Context(), user.ID)
			if err != nil {
				steps = append(steps, explainStep{
					Name:    "group_lookup",
					Status:  "fail",
					Message: "Group lookup failed: " + err.Error(),
				})
				allowed = false
				decision = "deny_group_lookup"
				break
			}
			groupSet := make(map[uint]struct{}, len(groupIDs))
			for _, gid := range groupIDs {
				groupSet[gid] = struct{}{}
			}
			roleHit := false
			for _, role := range item.AllowedRoles {
				if role == user.Role {
					roleHit = true
					break
				}
			}
			groupHit := false
			for _, gid := range item.AllowedGroups {
				if _, ok := groupSet[gid]; ok {
					groupHit = true
					break
				}
			}
			openPolicy := len(item.AllowedRoles) == 0 && len(item.AllowedGroups) == 0
			pass := roleHit || groupHit || openPolicy
			steps = append(steps, explainStep{
				Name:    "restricted_policy",
				Status:  statusForBool(pass),
				Message: restrictedExplanation(user, item, roleHit, groupHit, openPolicy),
			})
			if !pass {
				allowed = false
				decision = "deny_restricted_policy"
			}
		}
	}

	if allowed {
		decision = "allowed"
	}

	writeJSON(w, stdhttp.StatusOK, explainResponse{
		ServiceID: item.ID,
		Allowed:   allowed,
		Decision:  decision,
		Steps:     steps,
	})
}

func parseDetailString(raw string) map[string]any {
	out := map[string]any{}
	if strings.TrimSpace(raw) == "" {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func stringFromMap(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func statusForBool(ok bool) string {
	if ok {
		return "ok"
	}
	return "fail"
}

func ifThenElse(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func matchesCIDRList(addr netip.Addr, values domain.JSONStringSlice) bool {
	for _, raw := range values {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "/") {
			if prefix, err := netip.ParsePrefix(trimmed); err == nil {
				if prefix.Contains(addr) {
					return true
				}
			}
			continue
		}
		if other, err := netip.ParseAddr(trimmed); err == nil && other == addr {
			return true
		}
	}
	return false
}

func windowMatchesAt(windows domain.AccessWindowList, at time.Time) bool {
	for _, window := range windows {
		location := time.UTC
		if strings.TrimSpace(window.Timezone) != "" {
			if loaded, err := time.LoadLocation(window.Timezone); err == nil {
				location = loaded
			}
		}
		local := at.In(location)
		if len(window.DaysOfWeek) > 0 {
			match := false
			weekday := strings.ToLower(local.Weekday().String())
			for _, day := range window.DaysOfWeek {
				if strings.ToLower(strings.TrimSpace(day)) == weekday {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		start, err := time.Parse("15:04", window.StartTime)
		if err != nil {
			continue
		}
		end, err := time.Parse("15:04", window.EndTime)
		if err != nil {
			continue
		}
		startMin := start.Hour()*60 + start.Minute()
		endMin := end.Hour()*60 + end.Minute()
		cur := local.Hour()*60 + local.Minute()
		if endMin >= startMin {
			if cur >= startMin && cur <= endMin {
				return true
			}
		} else {
			if cur >= startMin || cur <= endMin {
				return true
			}
		}
	}
	return false
}

func restrictedExplanation(user *domain.User, item *domain.Service, roleHit, groupHit, openPolicy bool) string {
	if openPolicy {
		return "Restricted policy has no explicit role/group filters — every authenticated user passes."
	}
	if roleHit {
		return "User role '" + user.Role + "' matches an allowed role."
	}
	if groupHit {
		return "User is in a group allowed for this service."
	}
	parts := []string{}
	if len(item.AllowedRoles) > 0 {
		parts = append(parts, "roles="+strings.Join([]string(item.AllowedRoles), ","))
	}
	if len(item.AllowedGroups) > 0 {
		ids := make([]string, 0, len(item.AllowedGroups))
		for _, gid := range item.AllowedGroups {
			ids = append(ids, formatUint(gid))
		}
		parts = append(parts, "groups="+strings.Join(ids, ","))
	}
	return "User does not match restricted policy (" + strings.Join(parts, "; ") + ")."
}

func statusMessageDeployed(item *domain.Service) string {
	if item.LastDeployedAt == nil {
		return "Service has never been deployed — no traffic will be served yet."
	}
	return "Service deployed at " + item.LastDeployedAt.Format(time.RFC3339) + "."
}

func formatUint(value uint) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for value > 0 {
		pos--
		buf[pos] = digits[value%10]
		value /= 10
	}
	return string(buf[pos:])
}
