package domain

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

const (
	AuthPolicyPublic        = "public"
	AuthPolicyAuthenticated = "authenticated"
	AuthPolicyAdminOnly     = "admin_only"
)

const (
	AccessModePublic        = "public"
	AccessModeAuthenticated = "authenticated"
	AccessModeRestricted    = "restricted"
)

const (
	AccessMethodSession   = "session"
	AccessMethodOIDCOnly  = "oidc_only"
	AccessMethodPIN       = "pin"
	AccessMethodEmailCode = "email_code"
)

const (
	AuthProviderLocal = "local"
	AuthProviderOIDC  = "oidc"
)

const (
	LoginTokenScopeAccountLogin = "account_login"
	LoginTokenScopeRouteAccess  = "route_access"
	LoginTokenScopeMagicLink    = "magic_link"
)

const (
	CertificateTypeSingle   = "single"
	CertificateTypeWildcard = "wildcard"
	CertificateTypeMultiSAN = "multi_san"
)

const (
	CertificateStatusPending      = "pending"
	CertificateStatusIssued       = "issued"
	CertificateStatusFailed       = "failed"
	CertificateStatusExpiringSoon = "expiring_soon"
	CertificateStatusRenewing     = "renewing"
)

const (
	CertificateChallengeHTTP01 = "http-01"
	CertificateChallengeDNS01  = "dns-01"
)

const (
	CertificateIssuerLetsEncryptProd    = "letsencrypt_prod"
	CertificateIssuerLetsEncryptStaging = "letsencrypt_staging"
)

const (
	DNSProviderTypeCloudflare = "cloudflare"
	DNSProviderTypeHetzner    = "hetzner"
	DNSProviderTypeRoute53    = "route53"
	DNSProviderTypeDO         = "digitalocean"
)

const (
	NodeStatusUnknown = "unknown"
	NodeStatusOnline  = "online"
	NodeStatusOffline = "offline"
)

const (
	TunnelStatusInactive    = "inactive"
	TunnelStatusProvisioned = "provisioned"
	TunnelStatusConnected   = "connected"
	TunnelStatusStale       = "stale"
)

type JSONStringSlice []string

func (s JSONStringSlice) Value() (driver.Value, error) {
	if len(s) == 0 {
		return "[]", nil
	}
	bytes, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return string(bytes), nil
}

func (s *JSONStringSlice) Scan(value any) error {
	if value == nil {
		*s = JSONStringSlice{}
		return nil
	}
	return scanJSONValue(value, s)
}

type JSONUintSlice []uint

func (s JSONUintSlice) Value() (driver.Value, error) {
	if len(s) == 0 {
		return "[]", nil
	}
	bytes, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return string(bytes), nil
}

func (s *JSONUintSlice) Scan(value any) error {
	if value == nil {
		*s = JSONUintSlice{}
		return nil
	}
	return scanJSONValue(value, s)
}

type AccessWindow struct {
	Name       string          `json:"name"`
	DaysOfWeek JSONStringSlice `json:"days_of_week"`
	StartTime  string          `json:"start_time"`
	EndTime    string          `json:"end_time"`
	Timezone   string          `json:"timezone"`
}

type AccessWindowList []AccessWindow

func (s AccessWindowList) Value() (driver.Value, error) {
	if len(s) == 0 {
		return "[]", nil
	}
	bytes, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return string(bytes), nil
}

func (s *AccessWindowList) Scan(value any) error {
	if value == nil {
		*s = AccessWindowList{}
		return nil
	}
	return scanJSONValue(value, s)
}

type AccessPolicy struct {
	AccessMode           string          `json:"access_mode"`
	AllowedRoles         JSONStringSlice `json:"allowed_roles"`
	AllowedGroups        JSONUintSlice   `json:"allowed_groups"`
	AllowedServiceGroups JSONUintSlice   `json:"allowed_service_groups"`
}

func (p AccessPolicy) Value() (driver.Value, error) {
	bytes, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return string(bytes), nil
}

func (p *AccessPolicy) Scan(value any) error {
	if value == nil {
		*p = AccessPolicy{}
		return nil
	}
	return scanJSONValue(value, p)
}

type JSONObject map[string]any

func (o JSONObject) Value() (driver.Value, error) {
	if len(o) == 0 {
		return "{}", nil
	}
	bytes, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	return string(bytes), nil
}

func (o *JSONObject) Scan(value any) error {
	if value == nil {
		*o = JSONObject{}
		return nil
	}
	return scanJSONObjectValue(value, o)
}

type User struct {
	ID                      uint            `gorm:"primaryKey" json:"id"`
	Email                   string          `gorm:"uniqueIndex;size:255;not null" json:"email"`
	PasswordHash            string          `gorm:"size:255" json:"-"`
	Role                    string          `gorm:"size:32;not null;default:viewer" json:"role"`
	Active                  bool            `gorm:"not null;default:true" json:"active"`
	MustChangePassword      bool            `gorm:"not null;default:false" json:"must_change_password"`
	MFAEnabled              bool            `gorm:"not null;default:false" json:"mfa_enabled"`
	MFASecret               string          `gorm:"size:1024" json:"-"`
	MFAPendingSecret        string          `gorm:"size:1024" json:"-"`
	MFARecoveryCodes        JSONStringSlice `gorm:"type:text;not null;default:'[]'" json:"-"`
	MFAPendingRecoveryCodes JSONStringSlice `gorm:"type:text;not null;default:'[]'" json:"-"`
	MFALastTOTPCounter      uint64          `gorm:"not null;default:0" json:"-"`
	AuthProvider            string          `gorm:"size:32;not null;default:local" json:"auth_provider"`
	AuthProviderRef         string          `gorm:"size:255;index" json:"auth_provider_ref"`
	AuthIssuer              string          `gorm:"size:512" json:"auth_issuer"`
	DisplayName             string          `gorm:"size:255" json:"display_name"`
	Username                string          `gorm:"size:255" json:"username"`
	LastLoginAt             *time.Time      `json:"last_login_at"`
	CreatedAt               time.Time       `json:"created_at"`
	UpdatedAt               time.Time       `json:"updated_at"`
}

type APIToken struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	Name        string     `gorm:"size:255;not null" json:"name"`
	Prefix      string     `gorm:"uniqueIndex;size:64;not null" json:"prefix"`
	TokenHash   string     `gorm:"size:128;not null" json:"-"`
	Role        string     `gorm:"size:32;not null;default:viewer" json:"role"`
	CreatedByID *uint      `gorm:"index" json:"created_by_id"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type Group struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	Name          string    `gorm:"uniqueIndex;size:255;not null" json:"name"`
	Description   string    `gorm:"type:text" json:"description"`
	IsSystemGroup bool      `gorm:"not null;default:false" json:"is_system_group"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Members       []User    `gorm:"many2many:group_memberships" json:"members,omitempty"`
}

type GroupMembership struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	GroupID   uint      `gorm:"index;not null" json:"group_id"`
	UserID    uint      `gorm:"index;not null" json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
}

type Node struct {
	ID                 uint       `gorm:"primaryKey" json:"id"`
	Name               string     `gorm:"size:255;not null" json:"name"`
	Description        string     `gorm:"type:text" json:"description"`
	EnrollmentTokenID  *uint      `gorm:"index" json:"enrollment_token_id"`
	HeartbeatAuthMode  string     `gorm:"size:64;not null;default:token" json:"heartbeat_auth_mode"`
	HeartbeatEndpoint  string     `gorm:"size:512" json:"heartbeat_endpoint"`
	HeartbeatVersion   string     `gorm:"size:64" json:"heartbeat_version"`
	LastHeartbeatIP    string     `gorm:"size:255" json:"last_heartbeat_ip"`
	LastHeartbeatCode  int        `gorm:"not null;default:0" json:"last_heartbeat_code"`
	LastHeartbeatError string     `gorm:"size:255" json:"last_heartbeat_error"`
	HeartbeatFailedAt  *time.Time `json:"heartbeat_failed_at"`
	LastSeenAt         *time.Time `json:"last_seen_at"`
	LastHeartbeatAt    *time.Time `json:"last_heartbeat_at"`
	Version            string     `gorm:"size:64" json:"version"`
	Status             string     `gorm:"size:64;not null;default:unknown" json:"status"`
	Load               float64    `gorm:"not null;default:0" json:"load"`
	BandwidthInKbps    float64    `gorm:"not null;default:0" json:"bandwidth_in_kbps"`
	BandwidthOutKbps   float64    `gorm:"not null;default:0" json:"bandwidth_out_kbps"`
	HeartbeatTokenHash string     `gorm:"size:128" json:"-"`
	MTLSCertSHA256     string     `gorm:"size:128" json:"mtls_cert_sha256"`
	WGPublicKey        string     `gorm:"size:64;index" json:"wg_public_key"`
	WGPresharedKey     string     `gorm:"size:64" json:"-"`
	WGEndpoint         string     `gorm:"size:255" json:"wg_endpoint"`
	WGAllowedIPs       string     `gorm:"size:255" json:"wg_allowed_ips"`
	WGTunnelIP         string     `gorm:"size:64;index" json:"wg_tunnel_ip"`
	WGLastHandshake    *time.Time `json:"wg_last_handshake"`
	WGRxBytes          int64      `gorm:"not null;default:0" json:"wg_rx_bytes"`
	WGTxBytes          int64      `gorm:"not null;default:0" json:"wg_tx_bytes"`
	AdvertisedSubnets  string     `gorm:"size:512" json:"advertised_subnets"`
	TunnelStatus       string     `gorm:"size:32;not null;default:inactive" json:"tunnel_status"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type Client struct {
	ID              uint       `gorm:"primaryKey" json:"id"`
	Name            string     `gorm:"size:255;not null" json:"name"`
	Description     string     `gorm:"type:text" json:"description"`
	WGPublicKey     string     `gorm:"size:64;index" json:"wg_public_key"`
	WGTunnelIP      string     `gorm:"size:64;index" json:"wg_tunnel_ip"`
	WGAllowedIPs    string     `gorm:"size:512" json:"wg_allowed_ips"`
	AllowedNodeIDs  string     `gorm:"size:512" json:"allowed_node_ids"`
	Enabled         bool       `gorm:"not null;default:true" json:"enabled"`
	WGLastHandshake *time.Time `json:"wg_last_handshake"`
	WGRxBytes       int64      `gorm:"not null;default:0" json:"wg_rx_bytes"`
	WGTxBytes       int64      `gorm:"not null;default:0" json:"wg_tx_bytes"`
	TunnelStatus    string     `gorm:"size:32;not null;default:inactive" json:"tunnel_status"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type NodeEnrollmentToken struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	Name        string     `gorm:"size:255;not null" json:"name"`
	Description string     `gorm:"type:text" json:"description"`
	TokenHash   string     `gorm:"uniqueIndex;size:128;not null" json:"-"`
	ExpiresAt   *time.Time `gorm:"index" json:"expires_at"`
	SingleUse   bool       `gorm:"not null;default:true" json:"single_use"`
	Active      bool       `gorm:"not null;default:true" json:"active"`
	UsedAt      *time.Time `json:"used_at"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type Domain struct {
	ID          uint            `gorm:"primaryKey" json:"id"`
	Name        string          `gorm:"uniqueIndex;size:255;not null" json:"name"`
	Type        string          `gorm:"size:64;not null" json:"type"`
	Provider    string          `gorm:"size:255" json:"provider"`
	Notes       string          `gorm:"type:text" json:"notes"`
	IPAllowlist JSONStringSlice `gorm:"type:text;not null;default:'[]'" json:"ip_allowlist"`
	IPBlocklist JSONStringSlice `gorm:"type:text;not null;default:'[]'" json:"ip_blocklist"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

type Certificate struct {
	ID                uint             `gorm:"primaryKey" json:"id"`
	DomainID          uint             `gorm:"index;not null" json:"domain_id"`
	Domain            Domain           `json:"domain,omitempty"`
	PrimaryDomain     string           `gorm:"size:255;not null;index" json:"primary_domain"`
	Type              string           `gorm:"size:64;not null" json:"type"`
	Status            string           `gorm:"size:64;not null;default:pending" json:"status"`
	LastError         string           `gorm:"type:text" json:"last_error"`
	ChallengeType     string           `gorm:"size:64;not null;default:http-01" json:"challenge_type"`
	Issuer            string           `gorm:"size:64;not null;default:letsencrypt_prod" json:"issuer"`
	IssuedAt          *time.Time       `json:"issued_at"`
	ExpiresAt         time.Time        `json:"expires_at"`
	LastCheckedAt     *time.Time       `json:"last_checked_at"`
	NextRenewalAt     *time.Time       `json:"next_renewal_at"`
	RenewalWindowDays int              `gorm:"not null;default:30" json:"renewal_window_days"`
	IsAutoRenew       bool             `gorm:"not null;default:true" json:"is_auto_renew"`
	DNSProviderID     *uint            `gorm:"index" json:"dns_provider_id"`
	DNSProvider       *DNSProvider     `json:"dns_provider,omitempty"`
	SANs              []CertificateSAN `gorm:"constraint:OnDelete:CASCADE" json:"sans,omitempty"`
	CreatedAt         time.Time        `json:"created_at"`
	UpdatedAt         time.Time        `json:"updated_at"`
}

type CertificateSAN struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	CertificateID uint      `gorm:"index;not null" json:"certificate_id"`
	DomainName    string    `gorm:"size:255;not null" json:"domain_name"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type DNSProvider struct {
	ID                  uint            `gorm:"primaryKey" json:"id"`
	Name                string          `gorm:"uniqueIndex;size:255;not null" json:"name"`
	Type                string          `gorm:"size:64;not null;index" json:"type"`
	ConfigEncrypted     string          `gorm:"type:text" json:"-"`
	ConfigHint          string          `gorm:"size:512" json:"config_hint"`
	IsActive            bool            `gorm:"not null;default:true" json:"is_active"`
	LastTestedAt        *time.Time      `json:"last_tested_at"`
	LastTestStatus      string          `gorm:"size:64" json:"last_test_status"`
	LastTestError       string          `gorm:"type:text" json:"last_test_error"`
	HasStoredSecret     bool            `gorm:"not null;default:false" json:"has_stored_secret"`
	MaskedConfig        JSONObject      `gorm:"-" json:"masked_config,omitempty"`
	SupportedChallenges JSONStringSlice `gorm:"type:text;not null;default:'[\"dns-01\"]'" json:"supported_challenges"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
}

type ServiceGroup struct {
	ID                  uint         `gorm:"primaryKey" json:"id"`
	Name                string       `gorm:"uniqueIndex;size:255;not null" json:"name"`
	Description         string       `gorm:"type:text" json:"description"`
	DefaultAccessPolicy AccessPolicy `gorm:"type:text;not null;default:'{}'" json:"default_access_policy"`
	AccessMethod        string       `gorm:"size:64" json:"access_method"`
	AccessMethodConfig  JSONObject   `gorm:"type:text;not null;default:'{}'" json:"access_method_config"`
	CreatedAt           time.Time    `json:"created_at"`
	UpdatedAt           time.Time    `json:"updated_at"`
	Services            []Service    `gorm:"many2many:service_group_memberships" json:"services,omitempty"`
}

type ServiceGroupMembership struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	ServiceGroupID uint      `gorm:"index;not null" json:"service_group_id"`
	ServiceID      uint      `gorm:"index;not null" json:"service_id"`
	CreatedAt      time.Time `json:"created_at"`
}

type Service struct {
	ID                   uint             `gorm:"primaryKey" json:"id"`
	Name                 string           `gorm:"size:255;not null" json:"name"`
	DomainID             uint             `gorm:"index;not null" json:"domain_id"`
	Domain               Domain           `json:"domain,omitempty"`
	Subdomain            string           `gorm:"size:255" json:"subdomain"`
	Path                 string           `gorm:"size:255;not null;default:/" json:"path"`
	TargetURL            string           `gorm:"size:512;not null" json:"target_url"`
	TLSMode              string           `gorm:"size:64;not null" json:"tls_mode"`
	AuthPolicy           string           `gorm:"size:64;not null;default:authenticated" json:"auth_policy"`
	AccessMode           string           `gorm:"size:64;not null;default:authenticated" json:"access_mode"`
	AllowedRoles         JSONStringSlice  `gorm:"type:text;not null;default:'[]'" json:"allowed_roles"`
	AllowedGroups        JSONUintSlice    `gorm:"type:text;not null;default:'[]'" json:"allowed_groups"`
	AllowedServiceGroups JSONUintSlice    `gorm:"type:text;not null;default:'[]'" json:"allowed_service_groups"`
	UseGroupPolicy       bool             `gorm:"not null;default:false" json:"use_group_policy"`
	AccessMethod         string           `gorm:"size:64" json:"access_method"`
	AccessMethodConfig   JSONObject       `gorm:"type:text;not null;default:'{}'" json:"access_method_config"`
	AccessMessage        string           `gorm:"type:text" json:"access_message"`
	IPAllowlist          JSONStringSlice  `gorm:"type:text;not null;default:'[]'" json:"ip_allowlist"`
	IPBlocklist          JSONStringSlice  `gorm:"type:text;not null;default:'[]'" json:"ip_blocklist"`
	AllowedCountries     JSONStringSlice  `gorm:"type:text;not null;default:'[]'" json:"allowed_countries"`
	BlockedCountries     JSONStringSlice  `gorm:"type:text;not null;default:'[]'" json:"blocked_countries"`
	AccessWindows        AccessWindowList `gorm:"type:text;not null;default:'[]'" json:"access_windows"`
	LastDeployedAt       *time.Time       `json:"last_deployed_at"`
	DeploymentRevision   uint64           `gorm:"not null;default:0" json:"deployment_revision"`
	NodeID               *uint            `gorm:"index" json:"node_id"`
	Node                 *Node            `gorm:"foreignKey:NodeID;references:ID" json:"node,omitempty"`
	ServiceGroups        []ServiceGroup   `gorm:"many2many:service_group_memberships" json:"service_groups,omitempty"`
	CreatedAt            time.Time        `json:"created_at"`
	UpdatedAt            time.Time        `json:"updated_at"`
}

type LoginToken struct {
	ID           uint       `gorm:"primaryKey" json:"id"`
	UserID       *uint      `gorm:"index" json:"user_id"`
	User         User       `json:"user,omitempty"`
	ServiceID    *uint      `gorm:"index" json:"service_id"`
	Email        string     `gorm:"index;size:255;not null" json:"email"`
	Token        string     `gorm:"index;size:128;not null" json:"-"`
	Scope        string     `gorm:"size:64;not null;default:account_login;index" json:"scope"`
	ExpiresAt    time.Time  `gorm:"index;not null" json:"expires_at"`
	UsedAt       *time.Time `json:"used_at"`
	AttemptCount int        `gorm:"not null;default:0" json:"-"`
	RemoteAddr   string     `gorm:"size:255" json:"remote_addr"`
	UserAgent    string     `gorm:"size:512" json:"user_agent"`
	CreatedAt    time.Time  `json:"created_at"`
}

type Session struct {
	ID                 uint       `gorm:"primaryKey" json:"id"`
	UserID             uint       `gorm:"index;not null" json:"user_id"`
	User               User       `json:"user,omitempty"`
	TokenID            string     `gorm:"uniqueIndex;size:64;not null" json:"token_id"`
	RefreshTokenHash   string     `gorm:"uniqueIndex;size:128;not null" json:"-"`
	Label              string     `gorm:"size:255" json:"label"`
	UserAgent          string     `gorm:"size:512" json:"user_agent"`
	RemoteAddr         string     `gorm:"size:255" json:"remote_addr"`
	LastSeenAt         *time.Time `json:"last_seen_at"`
	ExpiresAt          time.Time  `gorm:"index;not null" json:"expires_at"`
	RevokedAt          *time.Time `gorm:"index" json:"revoked_at"`
	BootstrapDismissed bool       `gorm:"not null;default:false" json:"bootstrap_dismissed"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type AuditLog struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Timestamp    time.Time `gorm:"index;not null" json:"timestamp"`
	RequestID    string    `gorm:"size:64;index" json:"request_id"`
	UserID       *uint     `gorm:"index" json:"user_id"`
	Action       string    `gorm:"size:128;not null" json:"action"`
	ResourceType string    `gorm:"size:128;not null;index" json:"resource_type"`
	ResourceID   *uint     `gorm:"index" json:"resource_id"`
	Method       string    `gorm:"size:16;index" json:"method"`
	Host         string    `gorm:"size:255;index" json:"host"`
	Path         string    `gorm:"type:text" json:"path"`
	StatusCode   int       `gorm:"index" json:"status_code"`
	LatencyMs    int64     `gorm:"not null;default:0" json:"latency_ms"`
	RemoteAddr   string    `gorm:"size:255" json:"remote_addr"`
	UserAgent    string    `gorm:"size:512" json:"user_agent"`
	Details      string    `gorm:"type:text" json:"details"`
	PrevHash     string    `gorm:"size:128;index" json:"prev_hash"`
	Hash         string    `gorm:"size:128;index" json:"hash"`
	CreatedAt    time.Time `json:"created_at"`
}

type UserCredential struct {
	ID              uint            `gorm:"primaryKey" json:"id"`
	UserID          uint            `gorm:"index;not null" json:"user_id"`
	CredentialID    string          `gorm:"size:512;uniqueIndex;not null" json:"credential_id"`
	PublicKey       string          `gorm:"type:text;not null" json:"-"`
	AttestationType string          `gorm:"size:64" json:"attestation_type"`
	AAGUID          string          `gorm:"size:64" json:"aaguid"`
	SignCount       uint32          `gorm:"not null;default:0" json:"sign_count"`
	Transports      JSONStringSlice `gorm:"type:text;not null;default:'[]'" json:"transports"`
	Label           string          `gorm:"size:255" json:"label"`
	UserVerified    bool            `gorm:"not null;default:false" json:"user_verified"`
	BackupEligible  bool            `gorm:"not null;default:false" json:"backup_eligible"`
	BackupState     bool            `gorm:"not null;default:false" json:"backup_state"`
	CreatedAt       time.Time       `json:"created_at"`
	LastUsedAt      *time.Time      `json:"last_used_at"`
}

type ServiceExposureReport struct {
	ID              uint            `gorm:"primaryKey" json:"id"`
	ServiceID       uint            `gorm:"uniqueIndex;not null" json:"service_id"`
	Score           int             `gorm:"not null;default:0" json:"score"`
	CheckedAt       time.Time       `json:"checked_at"`
	DNSResolvable   bool            `gorm:"not null;default:false" json:"dns_resolvable"`
	HTTPSValid      bool            `gorm:"not null;default:false" json:"https_valid"`
	HTTPSExpiresIn  int             `gorm:"not null;default:0" json:"https_expires_in_days"`
	HTTPSRedirect   bool            `gorm:"not null;default:false" json:"http_to_https_redirect"`
	HSTSPresent     bool            `gorm:"not null;default:false" json:"hsts_present"`
	CSPPresent      bool            `gorm:"not null;default:false" json:"csp_present"`
	XFrameOptions   bool            `gorm:"not null;default:false" json:"x_frame_options"`
	AuthEnforced    bool            `gorm:"not null;default:false" json:"auth_enforced"`
	GeoIPConfigured bool            `gorm:"not null;default:false" json:"geoip_configured"`
	Findings        JSONStringSlice `gorm:"type:text;not null;default:'[]'" json:"findings"`
	LastError       string          `gorm:"type:text" json:"last_error"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

type AuditWebhook struct {
	ID              uint            `gorm:"primaryKey" json:"id"`
	Name            string          `gorm:"size:255;not null" json:"name"`
	URL             string          `gorm:"size:1024;not null" json:"url"`
	Format          string          `gorm:"size:32;not null;default:generic" json:"format"`
	SecretEncrypted string          `gorm:"column:secret_hashed;type:text" json:"-"`
	SecretPreview   string          `gorm:"size:32" json:"secret_preview"`
	EventTypes      JSONStringSlice `gorm:"type:text;not null;default:'[]'" json:"event_types"`
	Active          bool            `gorm:"not null;default:true" json:"active"`
	LastFiredAt     *time.Time      `json:"last_fired_at"`
	LastStatus      int             `gorm:"not null;default:0" json:"last_status"`
	LastError       string          `gorm:"type:text" json:"last_error"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

type AppSettings struct {
	ID                        uint            `gorm:"primaryKey" json:"id"`
	FrontendBaseURL           string          `gorm:"size:512" json:"frontend_base_url"`
	AuthBrandName             string          `gorm:"size:255" json:"auth_brand_name"`
	AuthLogoURL               string          `gorm:"size:1024" json:"auth_logo_url"`
	AuthBackgroundColor       string          `gorm:"size:32" json:"auth_background_color"`
	AuthBackgroundAccent      string          `gorm:"size:32" json:"auth_background_accent"`
	AuthPanelColor            string          `gorm:"size:32" json:"auth_panel_color"`
	AuthButtonColor           string          `gorm:"size:32" json:"auth_button_color"`
	AuthTextColor             string          `gorm:"size:32" json:"auth_text_color"`
	AuthMutedTextColor        string          `gorm:"size:32" json:"auth_muted_text_color"`
	AuthLoginTitle            string          `gorm:"size:255" json:"auth_login_title"`
	AuthLoginSubtitle         string          `gorm:"type:text" json:"auth_login_subtitle"`
	AuthRouteLoginTitle       string          `gorm:"size:255" json:"auth_route_login_title"`
	AuthRouteLoginSubtitle    string          `gorm:"type:text" json:"auth_route_login_subtitle"`
	AuthForbiddenTitle        string          `gorm:"size:255" json:"auth_forbidden_title"`
	AuthForbiddenSubtitle     string          `gorm:"type:text" json:"auth_forbidden_subtitle"`
	AuthLoginPasswordLabel    string          `gorm:"size:255" json:"auth_login_password_label"`
	AuthLoginOIDCLabel        string          `gorm:"size:255" json:"auth_login_oidc_label"`
	AuthLoginOTPRequestLabel  string          `gorm:"size:255" json:"auth_login_otp_request_label"`
	AuthLoginOTPVerifyLabel   string          `gorm:"size:255" json:"auth_login_otp_verify_label"`
	AuthRouteContinueLabel    string          `gorm:"size:255" json:"auth_route_continue_label"`
	AuthRouteOIDCLabel        string          `gorm:"size:255" json:"auth_route_oidc_label"`
	AuthRoutePINLabel         string          `gorm:"size:255" json:"auth_route_pin_label"`
	AuthRouteEmailSendLabel   string          `gorm:"size:255" json:"auth_route_email_send_label"`
	AuthRouteEmailVerifyLabel string          `gorm:"size:255" json:"auth_route_email_verify_label"`
	AuthForbiddenRetryLabel   string          `gorm:"size:255" json:"auth_forbidden_retry_label"`
	OIDCEnabled               bool            `gorm:"not null;default:false" json:"oidc_enabled"`
	OIDCIssuerURL             string          `gorm:"size:512" json:"oidc_issuer_url"`
	OIDCClientID              string          `gorm:"size:255" json:"oidc_client_id"`
	OIDCClientSecret          string          `gorm:"type:text" json:"-"`
	OIDCRedirectURL           string          `gorm:"size:512" json:"oidc_redirect_url"`
	OIDCAllowedEmailDomains   JSONStringSlice `gorm:"type:text;not null;default:'[]'" json:"oidc_allowed_email_domains"`
	OIDCAdminRoleClaimPath    string          `gorm:"size:255" json:"oidc_admin_role_claim_path"`
	OIDCAdminRoleValue        string          `gorm:"size:255" json:"oidc_admin_role_value"`
	OIDCProviderLabel         string          `gorm:"size:255" json:"oidc_provider_label"`
	OIDCAllowEmailLinking     bool            `gorm:"not null;default:false" json:"oidc_allow_email_linking"`
	OIDCRequireVerifiedEmail  bool            `gorm:"not null;default:true" json:"oidc_require_verified_email"`
	OTPEnabled                bool            `gorm:"not null;default:true" json:"otp_enabled"`
	OTPTokenTTLSeconds        int             `gorm:"not null;default:600" json:"otp_token_ttl_seconds"`
	OTPRequestLimit           int             `gorm:"not null;default:5" json:"otp_request_limit"`
	OTPRequestWindowSeconds   int             `gorm:"not null;default:900" json:"otp_request_window_seconds"`
	RequireMFAForAdmins       bool            `gorm:"not null;default:false" json:"require_mfa_for_admins"`
	SMTPEnabled               bool            `gorm:"not null;default:false" json:"smtp_enabled"`
	SMTPHost                  string          `gorm:"size:255" json:"smtp_host"`
	SMTPPort                  int             `gorm:"not null;default:587" json:"smtp_port"`
	SMTPUsername              string          `gorm:"size:255" json:"smtp_username"`
	SMTPPassword              string          `gorm:"type:text" json:"-"`
	SMTPFromEmail             string          `gorm:"size:255" json:"smtp_from_email"`
	SMTPFromName              string          `gorm:"size:255" json:"smtp_from_name"`
	SMTPEncryption            string          `gorm:"size:32;not null;default:starttls" json:"smtp_encryption"`
	SMTPInsecureSkipVerify    bool            `gorm:"not null;default:false" json:"smtp_insecure_skip_verify"`
	TunnelEnabled             bool            `gorm:"not null;default:false" json:"tunnel_enabled"`
	TunnelServerPrivateKey    string          `gorm:"type:text" json:"-"`
	TunnelServerPublicKey     string          `gorm:"size:64" json:"tunnel_server_public_key"`
	TunnelServerEndpoint      string          `gorm:"size:255" json:"tunnel_server_endpoint"`
	TunnelListenPort          int             `gorm:"not null;default:51820" json:"tunnel_listen_port"`
	TunnelCIDR                string          `gorm:"size:64;not null;default:'10.42.0.0/16'" json:"tunnel_cidr"`
	TunnelServerTunnelIP      string          `gorm:"size:64;not null;default:'10.42.0.1'" json:"tunnel_server_tunnel_ip"`
	TunnelConfigPath          string          `gorm:"size:512" json:"tunnel_config_path"`
	GeoIPDBPath               string          `gorm:"size:512" json:"geoip_db_path"`
	CrowdSecEnabled           bool            `gorm:"not null;default:false" json:"crowdsec_enabled"`
	CrowdSecAPIURL            string          `gorm:"size:512" json:"crowdsec_api_url"`
	CrowdSecAPIKeyEncrypted   string          `gorm:"type:text" json:"-"`
	CrowdSecPollIntervalSecs  int             `gorm:"not null;default:60" json:"crowdsec_poll_interval_secs"`
	CreatedAt                 time.Time       `json:"created_at"`
	UpdatedAt                 time.Time       `json:"updated_at"`
}

func scanJSONValue(value any, target any) error {
	switch typed := value.(type) {
	case []byte:
		if len(typed) == 0 {
			typed = []byte("[]")
		}
		return json.Unmarshal(typed, target)
	case string:
		if typed == "" {
			typed = "[]"
		}
		return json.Unmarshal([]byte(typed), target)
	default:
		return fmt.Errorf("unsupported JSON scan type %T", value)
	}
}

func scanJSONObjectValue(value any, target any) error {
	switch typed := value.(type) {
	case []byte:
		if len(typed) == 0 {
			typed = []byte("{}")
		}
		return json.Unmarshal(typed, target)
	case string:
		if typed == "" {
			typed = "{}"
		}
		return json.Unmarshal([]byte(typed), target)
	default:
		return fmt.Errorf("unsupported JSON scan type %T", value)
	}
}
