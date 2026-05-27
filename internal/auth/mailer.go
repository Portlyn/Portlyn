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
	textBody := fmt.Sprintf("Your Portlyn login code is %s.\n\nThis code expires at %s UTC.\n\nIf you did not request this code, you can ignore this email.\n", code, expiresAt.UTC().Format("2006-01-02 15:04:05"))
	htmlBody := otpEmailHTML("Your Portlyn login code", "Use this code to finish signing in.", code, expiresAt, "If you did not request this code, you can ignore this email.")
	if routeAccess {
		subject = "Your Portlyn route access code"
		textBody = fmt.Sprintf("Your Portlyn route access code is %s.\n\nThis code expires at %s UTC.\n\nIf you did not request this code, you can ignore this email.\n", code, expiresAt.UTC().Format("2006-01-02 15:04:05"))
		htmlBody = otpEmailHTML("Your Portlyn route access code", "Use this code to unlock the protected route.", code, expiresAt, "If you did not request this code, you can ignore this email.")
	}

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
	textBody := "This is a test email sent from Portlyn.\n\nSMTP delivery is working."
	htmlBody := testEmailHTML()
	if err := mail.Send(cfg, []string{strings.ToLower(strings.TrimSpace(email))}, "Portlyn SMTP test", textBody, htmlBody); err != nil {
		return fmt.Errorf("%w: %v", ErrSMTPDeliveryFailed, err)
	}
	return nil
}

func otpEmailHTML(title, intro, code string, expiresAt time.Time, outro string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
  <body style="margin:0;padding:0;background:#0b1220;color:#e5e7eb;font-family:Arial,sans-serif;">
    <div style="max-width:560px;margin:0 auto;padding:32px 20px;">
      <div style="background:linear-gradient(180deg,#111827 0%%,#0f172a 100%%);border:1px solid rgba(148,163,184,0.18);border-radius:18px;padding:32px;">
        <h1 style="margin:0 0 12px 0;font-size:26px;line-height:1.2;color:#f8fafc;">%s</h1>
        <p style="margin:0 0 24px 0;font-size:15px;line-height:1.6;color:#cbd5e1;">%s</p>
        <div style="margin:0 0 24px 0;padding:18px 20px;border-radius:14px;background:#020617;border:1px solid rgba(96,165,250,0.25);text-align:center;">
          <div style="font-size:12px;letter-spacing:0.12em;text-transform:uppercase;color:#94a3b8;margin-bottom:8px;">Verification code</div>
          <div style="font-size:34px;font-weight:700;letter-spacing:0.28em;color:#f8fafc;">%s</div>
        </div>
        <p style="margin:0 0 10px 0;font-size:14px;line-height:1.6;color:#cbd5e1;">Valid until <strong style="color:#f8fafc;">%s UTC</strong>.</p>
        <p style="margin:0;font-size:13px;line-height:1.6;color:#94a3b8;">%s</p>
      </div>
    </div>
  </body>
</html>`, title, intro, code, expiresAt.UTC().Format("2006-01-02 15:04:05"), outro)
}

func testEmailHTML() string {
	return `<!DOCTYPE html>
<html lang="en">
  <body style="margin:0;padding:0;background:#0b1220;color:#e5e7eb;font-family:Arial,sans-serif;">
    <div style="max-width:560px;margin:0 auto;padding:32px 20px;">
      <div style="background:linear-gradient(180deg,#111827 0%,#0f172a 100%);border:1px solid rgba(148,163,184,0.18);border-radius:18px;padding:32px;">
        <h1 style="margin:0 0 12px 0;font-size:26px;line-height:1.2;color:#f8fafc;">SMTP test</h1>
        <p style="margin:0;font-size:15px;line-height:1.6;color:#cbd5e1;">This is a test email sent from Portlyn. SMTP delivery is working.</p>
      </div>
    </div>
  </body>
</html>`
}
