package auth

import "errors"

var (
	ErrInactiveUser        = errors.New("inactive user")
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrInvalidToken        = errors.New("invalid token")
	ErrOIDCDisabled        = errors.New("oidc disabled")
	ErrLocalLoginDisabled  = errors.New("local login disabled")
	ErrOTPDisabled         = errors.New("otp disabled")
	ErrRateLimited         = errors.New("rate limited")
	ErrOTPExpired          = errors.New("otp expired")
	ErrOTPUsed             = errors.New("otp already used")
	ErrOIDCEmailBlocked    = errors.New("oidc email domain blocked")
	ErrOIDCEmailUnverified = errors.New("oidc email not verified")
	ErrOIDCLinkDenied      = errors.New("oidc account linking denied")
	ErrSMTPNotConfigured   = errors.New("smtp not configured")
	ErrSMTPDeliveryFailed  = errors.New("smtp delivery failed")
	ErrSessionRevoked      = errors.New("session revoked")
	ErrRefreshExpired      = errors.New("refresh expired")
	ErrMFARequired         = errors.New("mfa required")
	ErrMFACodeInvalid      = errors.New("invalid mfa code")
	ErrMFASetupRequired    = errors.New("mfa setup required")
	ErrBreakGlassRejected  = errors.New("break-glass rejected")
)
