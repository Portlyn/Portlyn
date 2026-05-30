package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"portlyn/internal/mail"
)

func (s *Service) sendOTPEmail(ctx context.Context, email, code string, expiresAt time.Time, routeAccess bool) error {
	cfg := s.currentSMTPConfig(ctx)
	includeCode := s.currentOTPConfig(ctx).ResponseIncludesCode
	if !cfg.Enabled {
		if includeCode {
			return nil
		}
		return ErrSMTPNotConfigured
	}

	subject := "Your Portlyn login code"
	title := "Your Portlyn login code"
	intro := "Use this code to finish signing in."
	if routeAccess {
		subject = "Your Portlyn route access code"
		title = "Your Portlyn route access code"
		intro = "Use this code to unlock the protected route."
	}
	outro := "If you did not request this code, you can ignore this email."
	textBody := otpEmailText(title, intro, code, expiresAt, outro)
	htmlBody := otpEmailHTML(title, intro, code, expiresAt, outro)

	if err := mail.Send(cfg, []string{strings.ToLower(strings.TrimSpace(email))}, subject, textBody, htmlBody); err != nil {
		return fmt.Errorf("%w: %v", ErrSMTPDeliveryFailed, err)
	}
	return nil
}

func (s *Service) SendTestEmail(ctx context.Context, email string) error {
	cfg := s.currentSMTPConfig(ctx)
	if !cfg.Enabled {
		return ErrSMTPNotConfigured
	}
	textBody := testEmailText()
	htmlBody := testEmailHTML()
	if err := mail.Send(cfg, []string{strings.ToLower(strings.TrimSpace(email))}, "Portlyn SMTP test", textBody, htmlBody); err != nil {
		return fmt.Errorf("%w: %v", ErrSMTPDeliveryFailed, err)
	}
	return nil
}

func otpEmailText(title, intro, code string, expiresAt time.Time, outro string) string {
	return fmt.Sprintf(`%s

%s

  ┌──────────────────────────┐
  │  Verification code       │
  │  %s                    │
  └──────────────────────────┘

Valid until %s UTC.

%s

— Sent by Portlyn
`, title, intro, code, expiresAt.UTC().Format("2006-01-02 15:04:05"), outro)
}

func testEmailText() string {
	return `SMTP test

This is a test email sent from Portlyn. SMTP delivery is working.

— Sent by Portlyn
`
}

func otpEmailHTML(title, intro, code string, expiresAt time.Time, outro string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
  <body style="margin:0;padding:0;background:#0d0e11;color:#d5d9e2;font-family:Inter,Segoe UI,Arial,sans-serif;">
    <div style="max-width:560px;margin:0 auto;padding:32px 20px;">
      <div style="background:linear-gradient(180deg,#1a1b1e 0%%,#121316 100%%);border:1px solid rgba(184,154,222,0.22);border-radius:18px;padding:32px;">
        <h1 style="margin:0 0 12px 0;font-size:26px;line-height:1.2;color:#f4f7fb;">%s</h1>
        <p style="margin:0 0 24px 0;font-size:15px;line-height:1.6;color:#b6bdcc;">%s</p>
        <div style="margin:0 0 24px 0;padding:20px;border-radius:14px;background:linear-gradient(180deg,rgba(106,74,153,0.18) 0%%,rgba(85,58,126,0.10) 100%%);border:1px solid rgba(156,121,208,0.35);text-align:center;">
          <div style="font-size:12px;letter-spacing:0.16em;text-transform:uppercase;color:#9c79d0;margin-bottom:8px;">Verification code</div>
          <div style="font-size:34px;font-weight:700;letter-spacing:0.28em;color:#f4f7fb;">%s</div>
        </div>
        <p style="margin:0 0 10px 0;font-size:14px;line-height:1.6;color:#b6bdcc;">Valid until <strong style="color:#f4f7fb;">%s UTC</strong>.</p>
        <p style="margin:0;font-size:13px;line-height:1.6;color:#8d96a8;">%s</p>
      </div>
      <p style="margin:18px 0 0 0;font-size:12px;line-height:1.6;color:#6a7282;text-align:center;">Sent by Portlyn</p>
    </div>
  </body>
</html>`, title, intro, code, expiresAt.UTC().Format("2006-01-02 15:04:05"), outro)
}

func testEmailHTML() string {
	return `<!DOCTYPE html>
<html lang="en">
  <body style="margin:0;padding:0;background:#0d0e11;color:#d5d9e2;font-family:Inter,Segoe UI,Arial,sans-serif;">
    <div style="max-width:560px;margin:0 auto;padding:32px 20px;">
      <div style="background:linear-gradient(180deg,#1a1b1e 0%,#121316 100%);border:1px solid rgba(184,154,222,0.22);border-radius:18px;padding:32px;">
        <h1 style="margin:0 0 12px 0;font-size:26px;line-height:1.2;color:#f4f7fb;">SMTP test</h1>
        <p style="margin:0;font-size:15px;line-height:1.6;color:#b6bdcc;">This is a test email sent from Portlyn. SMTP delivery is working.</p>
      </div>
      <p style="margin:18px 0 0 0;font-size:12px;line-height:1.6;color:#6a7282;text-align:center;">Sent by Portlyn</p>
    </div>
  </body>
</html>`
}
