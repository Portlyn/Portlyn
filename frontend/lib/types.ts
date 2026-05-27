export type UserRole = "admin" | "viewer";
export type AuthPolicy = "public" | "authenticated" | "admin_only";
export type AccessMode = "public" | "authenticated" | "restricted";
export type AccessMethod = "session" | "oidc_only" | "pin" | "email_code" | "";
export type TLSMode = "offload" | "passthrough" | "none";
export type NodeStatus = "unknown" | "online" | "offline";
export type AuthProvider = "local" | "oidc";
export type DNSProviderType = "cloudflare" | "hetzner" | "route53" | "digitalocean";

export interface ApiErrorPayload {
  error?: {
    code?: string;
    message?: string;
    status?: number;
    request_id?: string;
    timestamp?: string;
  };
}

export interface User {
  id: number;
  email: string;
  role: UserRole;
  active: boolean;
  must_change_password: boolean;
  mfa_enabled: boolean;
  auth_provider: AuthProvider;
  auth_provider_ref: string;
  auth_issuer: string;
  display_name: string;
  username: string;
  last_login_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface Group {
  id: number;
  name: string;
  description: string;
  is_system_group: boolean;
  member_count?: number;
  members?: User[];
  created_at: string;
  updated_at: string;
}

export interface AccessWindow {
  name: string;
  days_of_week: string[];
  start_time: string;
  end_time: string;
  timezone: string;
}

export interface AccessPolicy {
  access_mode: AccessMode;
  allowed_roles: UserRole[];
  allowed_groups: number[];
  allowed_service_groups: number[];
}

export interface AccessMethodConfig {
  pin?: string;
  pin_configured?: boolean;
  hint?: string;
  allowed_email_domain?: string;
  allowed_emails?: string[];
}

export interface Domain {
  id: number;
  name: string;
  type: string;
  provider: string;
  notes: string;
  ip_allowlist: string[];
  ip_blocklist: string[];
  created_at: string;
  updated_at: string;
}

export interface Certificate {
  id: number;
  domain_id: number;
  domain?: Domain;
  primary_domain: string;
  type: "single" | "wildcard" | "multi_san";
  status: "pending" | "issued" | "failed" | "expiring_soon" | "renewing";
  last_error: string;
  challenge_type: "http-01" | "dns-01";
  issuer: "letsencrypt_prod" | "letsencrypt_staging";
  sans: { id?: number; certificate_id?: number; domain_name: string }[];
  issued_at: string | null;
  expires_at: string;
  next_renewal_at: string | null;
  renewal_window_days: number;
  is_auto_renew: boolean;
  dns_provider_id: number | null;
  dns_provider?: DNSProvider | null;
  last_checked_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface DNSProvider {
  id: number;
  name: string;
  type: DNSProviderType;
  config_hint: string;
  is_active: boolean;
  last_tested_at: string | null;
  last_test_status: string;
  last_test_error: string;
  has_stored_secret: boolean;
  masked_config?: Record<string, string>;
  supported_challenges: string[];
  created_at: string;
  updated_at: string;
}

export type TunnelStatus = "inactive" | "provisioned" | "connected" | "stale";

export interface Node {
  id: number;
  name: string;
  description: string;
  enrollment_token_id: number | null;
  heartbeat_auth_mode: string;
  heartbeat_endpoint: string;
  heartbeat_version: string;
  mtls_cert_sha256: string;
  last_heartbeat_ip: string;
  last_heartbeat_code: number;
  last_heartbeat_error: string;
  heartbeat_failed_at: string | null;
  last_seen_at: string | null;
  last_heartbeat_at: string | null;
  version: string;
  status: NodeStatus | string;
  load: number;
  bandwidth_in_kbps: number;
  bandwidth_out_kbps: number;
  wg_public_key?: string;
  wg_endpoint?: string;
  wg_allowed_ips?: string;
  wg_tunnel_ip?: string;
  wg_last_handshake?: string | null;
  wg_rx_bytes?: number;
  wg_tx_bytes?: number;
  tunnel_status?: TunnelStatus | string;
  created_at: string;
  updated_at: string;
}

export interface TunnelSettings {
  enabled: boolean;
  configured: boolean;
  server_public_key?: string;
  server_endpoint?: string;
  listen_port?: number;
  cidr?: string;
  server_tunnel_ip?: string;
  config_path?: string;
  configured_peer_count: number;
  connected_peer_count: number;
}

export interface ExposureReport {
  id: number;
  service_id: number;
  score: number;
  checked_at: string;
  dns_resolvable: boolean;
  https_valid: boolean;
  https_expires_in_days: number;
  http_to_https_redirect: boolean;
  hsts_present: boolean;
  csp_present: boolean;
  x_frame_options: boolean;
  auth_enforced: boolean;
  geoip_configured: boolean;
  findings: string[];
  last_error: string;
}

export interface AuditWebhook {
  id: number;
  name: string;
  url: string;
  format: "generic" | "slack" | "discord" | "ntfy";
  secret_preview?: string;
  event_types: string[];
  active: boolean;
  last_fired_at: string | null;
  last_status: number;
  last_error: string;
  created_at: string;
  updated_at: string;
}

export interface UserCredential {
  id: number;
  user_id: number;
  credential_id: string;
  attestation_type: string;
  aaguid: string;
  sign_count: number;
  transports: string[];
  label: string;
  user_verified: boolean;
  created_at: string;
  last_used_at: string | null;
}

export interface MagicLinkResponse {
  url: string;
  token: string;
  expires_at: string;
}

export interface TunnelBootstrapResponse {
  node_id: number;
  public_key: string;
  private_key: string;
  address: string;
  server_public_key: string;
  server_endpoint: string;
  allowed_ips: string[];
  persistent_keepalive: number;
  config_text: string;
  issued_at: string;
}

export interface ServiceGroup {
  id: number;
  name: string;
  description: string;
  default_access_policy: AccessPolicy;
  access_method: AccessMethod;
  access_method_config: AccessMethodConfig;
  services?: Service[];
  service_count?: number;
  created_at: string;
  updated_at: string;
}

export interface Service {
  id: number;
  name: string;
  domain_id: number;
  domain?: Domain;
  subdomain: string;
  hostname?: string;
  path: string;
  target_url: string;
  tls_mode: TLSMode;
  auth_policy: AuthPolicy;
  access_mode: AccessMode;
  allowed_roles: UserRole[];
  allowed_groups: number[];
  allowed_service_groups: number[];
  use_group_policy: boolean;
  access_method: AccessMethod;
  access_method_config: AccessMethodConfig;
  effective_access_mode?: AccessMode;
  effective_access_method?: Exclude<AccessMethod, "">;
  effective_access_method_config?: AccessMethodConfig;
  access_message: string;
  risk_score?: string;
  risk_reasons?: string[];
  ip_allowlist: string[];
  ip_blocklist: string[];
  allowed_countries: string[];
  blocked_countries: string[];
  access_windows: AccessWindow[];
  service_groups?: ServiceGroup[];
  inherited_from_group?: { id: number; name: string } | null;
  service_overrides_group?: boolean;
  node_id?: number | null;
  node?: Node | null;
  last_deployed_at: string | null;
  deployment_revision: number;
  service_status?: string;
  service_status_error?: string;
  service_status_checked_at?: string;
  created_at: string;
  updated_at: string;
}

export interface AuditLog {
  id: number;
  timestamp: string;
  request_id?: string;
  user_id: number | null;
  action: string;
  resource_type: string;
  resource_id: number | null;
  method?: string;
  host?: string;
  path?: string;
  status_code?: number;
  latency_ms?: number;
  remote_addr?: string;
  user_agent?: string;
  details: string;
  created_at: string;
}

export interface AuditLogListResponse {
  items: AuditLog[];
  total: number;
  limit: number;
  offset: number;
}

export interface SessionInfo {
  id: number;
  user_id: number;
  token_id: string;
  label: string;
  user_agent: string;
  remote_addr: string;
  last_seen_at: string | null;
  expires_at: string;
  revoked_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface NodeEnrollmentToken {
  id: number;
  name: string;
  description: string;
  expires_at: string | null;
  single_use: boolean;
  active: boolean;
  used_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface NodeEnrollmentTokenCreateResponse extends NodeEnrollmentToken {
  token: string;
  setup_command: string;
}

export interface SystemOverview {
  status: string;
  checked_at: string;
  runtime: {
    version: string;
    api_status: string;
    db_status: string;
    proxy_status: string;
    http_addr: string;
    proxy_http_addr: string;
    proxy_https_addr: string;
    tls_enabled: boolean;
    acme_enabled: boolean;
    acme_challenge_types: string[];
    redirect_http_to_https: boolean;
    checked_at: string;
  };
  certificates: {
    default_issuer: string;
    supported_issuers: string[];
    dns_provider_count: number;
    dns_provider_types: string[];
    expiring_window_days: number;
    supports_wildcard: boolean;
    supports_multi_san: boolean;
    supports_dns_challenges: boolean;
  };
  security: {
    oidc_enabled: boolean;
    otp_enabled: boolean;
    csrf_enabled: boolean;
    cookie_secure: boolean;
    cookie_http_only: boolean;
    cookie_same_site_session: string;
    cookie_same_site_refresh: string;
    require_mfa_for_admins: boolean;
    admins_without_mfa: number;
    node_heartbeat_auth_mode: string;
    node_mtls_enabled: boolean;
    security_headers_enabled: boolean;
    smtp_enabled: boolean;
    smtp_configured: boolean;
    jwt_ttl_seconds: number;
    refresh_token_ttl_seconds: number;
    auth_rate_limit_attempts: number;
    auth_rate_limit_window_seconds: number;
  };
  counts: {
    services: number;
    domains: number;
    certificates: number;
    dns_providers: number;
    nodes_online: number;
    nodes_offline: number;
    users: number;
    groups: number;
    service_groups: number;
    proxy_routes: number;
    auth_failures_24h: number;
  };
  warnings: {
    expiring_certificates: Certificate[];
    failed_certificates: Certificate[];
    offline_nodes: Node[];
    risky_services: Array<{
      id: number;
      name: string;
      domain_name: string;
      path: string;
      access_mode: AccessMode;
      access_method: AccessMethod;
      risk_score: string;
      reasons: string[];
      use_group_policy: boolean;
      inherited_from_group?: string;
    }>;
    config: Array<{ code: string; message: string }>;
  };
  health: {
    livez: { name: string; scope: string; level: string; summary: string; reason?: string; checked_at: string };
    readyz: Array<{ name: string; scope: string; level: string; summary: string; reason?: string; checked_at: string }>;
    services: Array<{ name: string; scope: string; level: string; summary: string; reason?: string; checked_at: string }>;
    cluster: Array<{ name: string; scope: string; level: string; summary: string; reason?: string; checked_at: string }>;
  };
}

export interface LoginResponse {
  token?: string;
  user: User;
  requires_mfa?: boolean;
  mfa_token?: string;
  mfa_expires_at?: string;
  next?: string;
}

export interface AuthConfigResponse {
  oidc_enabled: boolean;
  oidc_label: string;
  otp_enabled: boolean;
  ui: AuthUISettings;
}

export interface AuthUISettings {
  brand_name: string;
  logo_url: string;
  background_color: string;
  background_accent: string;
  panel_color: string;
  button_color: string;
  text_color: string;
  muted_text_color: string;
  login_title: string;
  login_subtitle: string;
  route_login_title: string;
  route_login_subtitle: string;
  forbidden_title: string;
  forbidden_subtitle: string;
  login_password_label: string;
  login_oidc_label: string;
  login_otp_request_label: string;
  login_otp_verify_label: string;
  route_continue_label: string;
  route_oidc_label: string;
  route_pin_label: string;
  route_email_send_label: string;
  route_email_verify_label: string;
  forbidden_retry_label: string;
}

export interface AuthSettings {
  id: number;
  frontend_base_url: string;
  auth_brand_name: string;
  auth_logo_url: string;
  auth_background_color: string;
  auth_background_accent: string;
  auth_panel_color: string;
  auth_button_color: string;
  auth_text_color: string;
  auth_muted_text_color: string;
  auth_login_title: string;
  auth_login_subtitle: string;
  auth_route_login_title: string;
  auth_route_login_subtitle: string;
  auth_forbidden_title: string;
  auth_forbidden_subtitle: string;
  auth_login_password_label: string;
  auth_login_oidc_label: string;
  auth_login_otp_request_label: string;
  auth_login_otp_verify_label: string;
  auth_route_continue_label: string;
  auth_route_oidc_label: string;
  auth_route_pin_label: string;
  auth_route_email_send_label: string;
  auth_route_email_verify_label: string;
  auth_forbidden_retry_label: string;
  oidc_enabled: boolean;
  oidc_issuer_url: string;
  oidc_client_id: string;
  oidc_client_secret_configured: boolean;
  oidc_redirect_url: string;
  oidc_allowed_email_domains: string[];
  oidc_admin_role_claim_path: string;
  oidc_admin_role_value: string;
  oidc_provider_label: string;
  oidc_allow_email_linking: boolean;
  oidc_require_verified_email: boolean;
  otp_enabled: boolean;
  otp_token_ttl_seconds: number;
  otp_request_limit: number;
  otp_request_window_seconds: number;
  require_mfa_for_admins: boolean;
  smtp_enabled: boolean;
  smtp_host: string;
  smtp_port: number;
  smtp_username: string;
  smtp_password_configured: boolean;
  smtp_from_email: string;
  smtp_from_name: string;
  smtp_encryption: "none" | "starttls" | "implicit_tls";
  smtp_insecure_skip_verify: boolean;
  jwt_ttl_seconds?: number;
  refresh_token_ttl_seconds?: number;
  auth_rate_limit_attempts?: number;
  auth_rate_limit_window_seconds?: number;
  csrf_enabled?: boolean;
  cookie_secure?: boolean;
  cookie_http_only?: boolean;
  cookie_same_site_session?: string;
  cookie_same_site_refresh?: string;
  created_at: string;
  updated_at: string;
}

export interface MFAStatus {
  enabled: boolean;
  pending_setup: boolean;
  recovery_code_count: number;
  issuer: string;
  require_for_admins: boolean;
  required_for_current_user: boolean;
}

export interface MFASetup {
  secret: string;
  otpauth_url: string;
  recovery_codes: string[];
}

export interface UserPayload {
  email: string;
  password?: string;
  role: UserRole;
  active: boolean;
}

export interface DomainPayload {
  name: string;
  type: "root" | "subdomain";
  provider: string;
  notes: string;
  ip_allowlist: string[];
  ip_blocklist: string[];
}

export interface NodePayload {
  name: string;
  description: string;
  status: string;
  version: string;
}

export interface ServicePayload {
  name: string;
  domain_id: number;
  subdomain: string;
  path: string;
  target_url: string;
  tls_mode: TLSMode;
  auth_policy: AuthPolicy;
  access_policy: AccessPolicy;
  use_group_policy: boolean;
  access_method: AccessMethod;
  access_method_config: {
    pin?: string;
    hint?: string;
    allowed_email_domain?: string;
    allowed_emails?: string[];
  };
  access_message: string;
  service_group_ids: number[];
  ip_allowlist: string[];
  ip_blocklist: string[];
  allowed_countries: string[];
  blocked_countries: string[];
  access_windows: AccessWindow[];
  node_id?: number | null;
}

export interface ServiceGroupPayload {
  name: string;
  description: string;
  default_access_policy: AccessPolicy;
  access_method: AccessMethod;
  access_method_config: {
    pin?: string;
    hint?: string;
    allowed_email_domain?: string;
    allowed_emails?: string[];
  };
  service_ids: number[];
}

export interface CertificatePayload {
  domain_id: number;
  primary_domain?: string;
  type: "single" | "wildcard" | "multi_san";
  challenge_type: "http-01" | "dns-01";
  issuer: "letsencrypt_prod" | "letsencrypt_staging";
  sans: string[];
  expires_at?: string;
  renewal_window_days: number;
  is_auto_renew: boolean;
  dns_provider_id?: number | null;
}

export interface DNSProviderPayload {
  name: string;
  type: DNSProviderType;
  config: Record<string, string>;
  is_active: boolean;
}

export interface RouteAuthService {
  id: number;
  name: string;
  domain_name: string;
  path: string;
  access_mode: AccessMode;
  access_method: Exclude<AccessMethod, "">;
  access_method_config: AccessMethodConfig;
  access_message: string;
  inherited_from_group?: { id: number; name: string } | null;
  service_overrides_group: boolean;
}
