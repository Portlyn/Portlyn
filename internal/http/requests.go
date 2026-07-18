package http

import (
	"time"
)

type loginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

type requestOTPRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type verifyOTPRequest struct {
	Email string `json:"email" validate:"required,email"`
	Token string `json:"token" validate:"required,min=6,max=16"`
}

type verifyMFARequest struct {
	MFAToken string `json:"mfa_token" validate:"required,min=8,max=255"`
	Code     string `json:"code" validate:"required,min=6,max=32"`
}

type breakGlassLoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	Token    string `json:"token" validate:"required,min=16,max=512"`
}

type reencryptDataKeyRequest struct {
	DryRun bool `json:"dry_run"`
}

type createNodeRequest struct {
	Name              string     `json:"name" validate:"required,min=2,max=255"`
	Description       string     `json:"description"`
	LastSeenAt        *time.Time `json:"last_seen_at"`
	Version           string     `json:"version" validate:"max=64"`
	Status            string     `json:"status" validate:"required,max=64"`
	AuthMode          string     `json:"heartbeat_auth_mode" validate:"omitempty,oneof=token mtls"`
	MTLSSHA256        string     `json:"mtls_cert_sha256" validate:"omitempty,len=64,hexadecimal"`
	AdvertisedSubnets *string    `json:"advertised_subnets"`
}

type updateNodeRequest struct {
	Name              *string    `json:"name" validate:"omitempty,min=2,max=255"`
	Description       *string    `json:"description"`
	LastSeenAt        *time.Time `json:"last_seen_at"`
	Version           *string    `json:"version" validate:"omitempty,max=64"`
	Status            *string    `json:"status" validate:"omitempty,max=64"`
	AuthMode          *string    `json:"heartbeat_auth_mode" validate:"omitempty,oneof=token mtls"`
	MTLSSHA256        *string    `json:"mtls_cert_sha256" validate:"omitempty,len=64,hexadecimal"`
	AdvertisedSubnets *string    `json:"advertised_subnets"`
}

type heartbeatNodeRequest struct {
	Version          *string    `json:"version" validate:"omitempty,max=64"`
	Status           *string    `json:"status" validate:"omitempty,max=64"`
	Load             *float64   `json:"load"`
	BandwidthInKbps  *float64   `json:"bandwidth_in_kbps"`
	BandwidthOutKbps *float64   `json:"bandwidth_out_kbps"`
	WGLastHandshake  *time.Time `json:"wg_last_handshake"`
	WGRxBytes        *int64     `json:"wg_rx_bytes"`
	WGTxBytes        *int64     `json:"wg_tx_bytes"`
	TunnelStatus     *string    `json:"tunnel_status" validate:"omitempty,oneof=inactive provisioned connected stale"`
}

type createDomainRequest struct {
	Name            string   `json:"name" validate:"required,hostname_rfc1123"`
	Type            string   `json:"type" validate:"required,oneof=root subdomain"`
	Provider        string   `json:"provider" validate:"max=255"`
	Notes           string   `json:"notes"`
	IPAllowlist     []string `json:"ip_allowlist"`
	IPBlocklist     []string `json:"ip_blocklist"`
	AutoCertificate *bool    `json:"auto_certificate"`
	DNSProviderID   *uint    `json:"dns_provider_id" validate:"omitempty,gt=0"`
}

type updateDomainRequest struct {
	Name        *string   `json:"name" validate:"omitempty,hostname_rfc1123"`
	Type        *string   `json:"type" validate:"omitempty,oneof=root subdomain"`
	Provider    *string   `json:"provider" validate:"omitempty,max=255"`
	Notes       *string   `json:"notes"`
	IPAllowlist *[]string `json:"ip_allowlist"`
	IPBlocklist *[]string `json:"ip_blocklist"`
}

type createCertificateRequest struct {
	DomainID          uint              `json:"domain_id" validate:"required,gt=0"`
	Type              string            `json:"type" validate:"required,oneof=single wildcard multi_san"`
	ChallengeType     string            `json:"challenge_type" validate:"required,oneof=http-01 dns-01"`
	Issuer            string            `json:"issuer" validate:"required,oneof=letsencrypt_prod letsencrypt_staging"`
	SANs              []string          `json:"sans"`
	ExpiresAt         *time.Time        `json:"expires_at"`
	IsAutoRenew       bool              `json:"is_auto_renew"`
	RenewalWindowDays int               `json:"renewal_window_days" validate:"omitempty,gte=7,lte=90"`
	DNSProviderID     *uint             `json:"dns_provider_id" validate:"omitempty,gt=0"`
	PrimaryDomain     string            `json:"primary_domain" validate:"omitempty,max=255"`
	DNSProviderConfig map[string]string `json:"dns_provider_config"`
}

type updateCertificateRequest struct {
	DomainID          *uint             `json:"domain_id" validate:"omitempty,gt=0"`
	Type              *string           `json:"type" validate:"omitempty,oneof=single wildcard multi_san"`
	ChallengeType     *string           `json:"challenge_type" validate:"omitempty,oneof=http-01 dns-01"`
	Issuer            *string           `json:"issuer" validate:"omitempty,oneof=letsencrypt_prod letsencrypt_staging"`
	SANs              *[]string         `json:"sans"`
	ExpiresAt         *time.Time        `json:"expires_at"`
	IsAutoRenew       *bool             `json:"is_auto_renew"`
	RenewalWindowDays *int              `json:"renewal_window_days" validate:"omitempty,gte=7,lte=90"`
	DNSProviderID     *uint             `json:"dns_provider_id" validate:"omitempty,gt=0"`
	PrimaryDomain     *string           `json:"primary_domain" validate:"omitempty,max=255"`
	DNSProviderConfig map[string]string `json:"dns_provider_config"`
}

type createDNSProviderRequest struct {
	Name   string            `json:"name" validate:"required,min=2,max=255"`
	Type   string            `json:"type" validate:"required,oneof=cloudflare hetzner route53 digitalocean"`
	Config map[string]string `json:"config"`
	Active *bool             `json:"is_active"`
}

type updateDNSProviderRequest struct {
	Name   *string           `json:"name" validate:"omitempty,min=2,max=255"`
	Type   *string           `json:"type" validate:"omitempty,oneof=cloudflare hetzner route53 digitalocean"`
	Config map[string]string `json:"config"`
	Active *bool             `json:"is_active"`
}

type importCertificatePEMRequest struct {
	CertificatePEM string `json:"certificate_pem" validate:"required"`
	PrivateKeyPEM  string `json:"private_key_pem" validate:"required"`
	IssuerKey      string `json:"issuer_key" validate:"omitempty,max=255"`
}

type accessWindowRequest struct {
	Name       string   `json:"name" validate:"max=255"`
	DaysOfWeek []string `json:"days_of_week"`
	StartTime  string   `json:"start_time" validate:"required"`
	EndTime    string   `json:"end_time" validate:"required"`
	Timezone   string   `json:"timezone"`
}

type accessPolicyRequest struct {
	AccessMode           string   `json:"access_mode" validate:"required,oneof=public authenticated restricted"`
	AllowedRoles         []string `json:"allowed_roles"`
	AllowedGroups        []uint   `json:"allowed_groups"`
	AllowedServiceGroups []uint   `json:"allowed_service_groups"`
}

type accessMethodConfigRequest struct {
	PIN                string   `json:"pin"`
	Hint               string   `json:"hint"`
	AllowedEmailDomain string   `json:"allowed_email_domain"`
	AllowedEmails      []string `json:"allowed_emails"`
}

type createServiceRequest struct {
	Name               string                    `json:"name" validate:"required,min=2,max=255"`
	DomainID           uint                      `json:"domain_id" validate:"required,gt=0"`
	Subdomain          string                    `json:"subdomain" validate:"omitempty,max=255"`
	Path               string                    `json:"path" validate:"required,max=255"`
	TargetURL          string                    `json:"target_url" validate:"required,url"`
	TLSMode            string                    `json:"tls_mode" validate:"required,oneof=offload passthrough none"`
	PassHostHeader     bool                      `json:"pass_host_header"`
	UpstreamSkipVerify bool                      `json:"upstream_skip_verify"`
	UpstreamCAPEM      string                    `json:"upstream_ca_pem" validate:"omitempty,max=32768"`
	AuthPolicy         string                    `json:"auth_policy" validate:"omitempty,oneof=public authenticated admin_only"`
	AccessPolicy       accessPolicyRequest       `json:"access_policy" validate:"required"`
	UseGroupPolicy     bool                      `json:"use_group_policy"`
	AccessMethod       string                    `json:"access_method" validate:"omitempty,oneof=session oidc_only pin email_code"`
	AccessMethodConfig accessMethodConfigRequest `json:"access_method_config"`
	AccessMessage      string                    `json:"access_message"`
	ServiceGroupIDs    []uint                    `json:"service_group_ids"`
	IPAllowlist        []string                  `json:"ip_allowlist"`
	IPBlocklist        []string                  `json:"ip_blocklist"`
	AllowedCountries   []string                  `json:"allowed_countries"`
	BlockedCountries   []string                  `json:"blocked_countries"`
	AccessWindows      []accessWindowRequest     `json:"access_windows"`
	NodeID             *uint                     `json:"node_id"`
	Node               string                    `json:"node" validate:"omitempty,max=255"`
	ClearNodeID        *bool                     `json:"clear_node_id"`
}

type updateServiceRequest struct {
	Name               *string                    `json:"name" validate:"omitempty,min=2,max=255"`
	DomainID           *uint                      `json:"domain_id" validate:"omitempty,gt=0"`
	Subdomain          *string                    `json:"subdomain" validate:"omitempty,max=255"`
	Path               *string                    `json:"path" validate:"omitempty,max=255"`
	TargetURL          *string                    `json:"target_url" validate:"omitempty,url"`
	TLSMode            *string                    `json:"tls_mode" validate:"omitempty,oneof=offload passthrough none"`
	PassHostHeader     *bool                      `json:"pass_host_header"`
	UpstreamSkipVerify *bool                      `json:"upstream_skip_verify"`
	UpstreamCAPEM      *string                    `json:"upstream_ca_pem" validate:"omitempty,max=32768"`
	AuthPolicy         *string                    `json:"auth_policy" validate:"omitempty,oneof=public authenticated admin_only"`
	AccessPolicy       *accessPolicyRequest       `json:"access_policy"`
	UseGroupPolicy     *bool                      `json:"use_group_policy"`
	AccessMethod       *string                    `json:"access_method"`
	AccessMethodConfig *accessMethodConfigRequest `json:"access_method_config"`
	AccessMessage      *string                    `json:"access_message"`
	ServiceGroupIDs    *[]uint                    `json:"service_group_ids"`
	IPAllowlist        *[]string                  `json:"ip_allowlist"`
	IPBlocklist        *[]string                  `json:"ip_blocklist"`
	AllowedCountries   *[]string                  `json:"allowed_countries"`
	BlockedCountries   *[]string                  `json:"blocked_countries"`
	AccessWindows      *[]accessWindowRequest     `json:"access_windows"`
	NodeID             *uint                      `json:"node_id"`
	Node               *string                    `json:"node" validate:"omitempty,max=255"`
	ClearNodeID        *bool                      `json:"clear_node_id"`
}

type createGroupRequest struct {
	Name        string `json:"name" validate:"required,min=2,max=255"`
	Description string `json:"description"`
}

type updateGroupRequest struct {
	Name        *string `json:"name" validate:"omitempty,min=2,max=255"`
	Description *string `json:"description"`
}

type groupMemberRequest struct {
	UserID uint `json:"user_id" validate:"required,gt=0"`
}

type createServiceGroupRequest struct {
	Name                string                    `json:"name" validate:"required,min=2,max=255"`
	Description         string                    `json:"description"`
	DefaultAccessPolicy accessPolicyRequest       `json:"default_access_policy" validate:"required"`
	AccessMethod        string                    `json:"access_method" validate:"omitempty,oneof=session oidc_only pin email_code"`
	AccessMethodConfig  accessMethodConfigRequest `json:"access_method_config"`
	ServiceIDs          []uint                    `json:"service_ids"`
}

type updateServiceGroupRequest struct {
	Name                *string                    `json:"name" validate:"omitempty,min=2,max=255"`
	Description         *string                    `json:"description"`
	DefaultAccessPolicy *accessPolicyRequest       `json:"default_access_policy"`
	AccessMethod        *string                    `json:"access_method"`
	AccessMethodConfig  *accessMethodConfigRequest `json:"access_method_config"`
	ServiceIDs          *[]uint                    `json:"service_ids"`
}

type serviceGroupServiceRequest struct {
	ServiceID uint `json:"service_id" validate:"required,gt=0"`
}

type createUserRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	Role     string `json:"role" validate:"required,oneof=admin viewer"`
	Active   *bool  `json:"active"`
}

type updateUserRequest struct {
	Email    *string `json:"email" validate:"omitempty,email"`
	Password *string `json:"password" validate:"omitempty,min=8"`
	Role     *string `json:"role" validate:"omitempty,oneof=admin viewer"`
	Active   *bool   `json:"active"`
}

type mfaCodeRequest struct {
	Code string `json:"code" validate:"required,min=6,max=32"`
}

type completeAccountSetupRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required,min=8"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
}

type routePINRequest struct {
	ServiceID uint   `json:"service_id" validate:"required,gt=0"`
	PIN       string `json:"pin" validate:"required,min=3,max=64"`
}

type routeEmailCodeRequest struct {
	ServiceID uint   `json:"service_id" validate:"required,gt=0"`
	Email     string `json:"email" validate:"required,email"`
}

type routeVerifyEmailCodeRequest struct {
	ServiceID uint   `json:"service_id" validate:"required,gt=0"`
	Email     string `json:"email" validate:"required,email"`
	Code      string `json:"code" validate:"required,min=6,max=16"`
}

type updateAuthSettingsRequest struct {
	FrontendBaseURL           *string   `json:"frontend_base_url" validate:"omitempty,url"`
	AuthBrandName             *string   `json:"auth_brand_name" validate:"omitempty,max=255"`
	AuthLogoURL               *string   `json:"auth_logo_url" validate:"omitempty,max=1024"`
	AuthBackgroundColor       *string   `json:"auth_background_color" validate:"omitempty,max=32"`
	AuthBackgroundAccent      *string   `json:"auth_background_accent" validate:"omitempty,max=32"`
	AuthPanelColor            *string   `json:"auth_panel_color" validate:"omitempty,max=32"`
	AuthButtonColor           *string   `json:"auth_button_color" validate:"omitempty,max=32"`
	AuthTextColor             *string   `json:"auth_text_color" validate:"omitempty,max=32"`
	AuthMutedTextColor        *string   `json:"auth_muted_text_color" validate:"omitempty,max=32"`
	AuthLoginTitle            *string   `json:"auth_login_title" validate:"omitempty,max=255"`
	AuthLoginSubtitle         *string   `json:"auth_login_subtitle"`
	AuthRouteLoginTitle       *string   `json:"auth_route_login_title" validate:"omitempty,max=255"`
	AuthRouteLoginSubtitle    *string   `json:"auth_route_login_subtitle"`
	AuthForbiddenTitle        *string   `json:"auth_forbidden_title" validate:"omitempty,max=255"`
	AuthForbiddenSubtitle     *string   `json:"auth_forbidden_subtitle"`
	AuthLoginPasswordLabel    *string   `json:"auth_login_password_label" validate:"omitempty,max=255"`
	AuthLoginOIDCLabel        *string   `json:"auth_login_oidc_label" validate:"omitempty,max=255"`
	AuthLoginOTPRequestLabel  *string   `json:"auth_login_otp_request_label" validate:"omitempty,max=255"`
	AuthLoginOTPVerifyLabel   *string   `json:"auth_login_otp_verify_label" validate:"omitempty,max=255"`
	AuthRouteContinueLabel    *string   `json:"auth_route_continue_label" validate:"omitempty,max=255"`
	AuthRouteOIDCLabel        *string   `json:"auth_route_oidc_label" validate:"omitempty,max=255"`
	AuthRoutePINLabel         *string   `json:"auth_route_pin_label" validate:"omitempty,max=255"`
	AuthRouteEmailSendLabel   *string   `json:"auth_route_email_send_label" validate:"omitempty,max=255"`
	AuthRouteEmailVerifyLabel *string   `json:"auth_route_email_verify_label" validate:"omitempty,max=255"`
	AuthForbiddenRetryLabel   *string   `json:"auth_forbidden_retry_label" validate:"omitempty,max=255"`
	OIDCEnabled               *bool     `json:"oidc_enabled"`
	OIDCIssuerURL             *string   `json:"oidc_issuer_url" validate:"omitempty"`
	OIDCClientID              *string   `json:"oidc_client_id" validate:"omitempty,max=255"`
	OIDCClientSecret          *string   `json:"oidc_client_secret"`
	OIDCRedirectURL           *string   `json:"oidc_redirect_url" validate:"omitempty"`
	OIDCAllowedEmailDomains   *[]string `json:"oidc_allowed_email_domains"`
	OIDCAdminRoleClaimPath    *string   `json:"oidc_admin_role_claim_path" validate:"omitempty,max=255"`
	OIDCAdminRoleValue        *string   `json:"oidc_admin_role_value" validate:"omitempty,max=255"`
	OIDCProviderLabel         *string   `json:"oidc_provider_label" validate:"omitempty,max=255"`
	OIDCAllowEmailLinking     *bool     `json:"oidc_allow_email_linking"`
	OIDCRequireVerifiedEmail  *bool     `json:"oidc_require_verified_email"`
	LocalLoginDisabled        *bool     `json:"local_login_disabled"`
	OTPEnabled                *bool     `json:"otp_enabled"`
	OTPTokenTTLSeconds        *int      `json:"otp_token_ttl_seconds" validate:"omitempty,gte=60,lte=86400"`
	OTPRequestLimit           *int      `json:"otp_request_limit" validate:"omitempty,gte=1,lte=100"`
	OTPRequestWindowSeconds   *int      `json:"otp_request_window_seconds" validate:"omitempty,gte=60,lte=86400"`
	RequireMFAForAdmins       *bool     `json:"require_mfa_for_admins"`
	SMTPEnabled               *bool     `json:"smtp_enabled"`
	SMTPHost                  *string   `json:"smtp_host" validate:"omitempty,max=255"`
	SMTPPort                  *int      `json:"smtp_port" validate:"omitempty,gte=1,lte=65535"`
	SMTPUsername              *string   `json:"smtp_username" validate:"omitempty,max=255"`
	SMTPPassword              *string   `json:"smtp_password"`
	SMTPFromEmail             *string   `json:"smtp_from_email" validate:"omitempty,email"`
	SMTPFromName              *string   `json:"smtp_from_name" validate:"omitempty,max=255"`
	SMTPEncryption            *string   `json:"smtp_encryption" validate:"omitempty,oneof=none starttls implicit_tls"`
	SMTPInsecureSkipVerify    *bool     `json:"smtp_insecure_skip_verify"`
}

type sendTestEmailRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type sessionBridgeTokenRequest struct {
	Host string `json:"host" validate:"required,max=255"`
}

type createNodeEnrollmentTokenRequest struct {
	Name        string `json:"name" validate:"required,min=2,max=255"`
	Description string `json:"description"`
	TTLSeconds  *int   `json:"ttl_seconds" validate:"omitempty,gte=60,lte=2592000"`
	SingleUse   *bool  `json:"single_use"`
}

type enrollNodeRequest struct {
	Token       string `json:"token" validate:"required,min=8,max=255"`
	Name        string `json:"name" validate:"required,min=2,max=255"`
	Description string `json:"description"`
	Version     string `json:"version" validate:"omitempty,max=64"`
}

type revokeSessionRequest struct {
	SessionID uint `json:"session_id" validate:"required,gt=0"`
}
