package mail

import (
	"crypto/tls"
	"fmt"
	"net"
	stdmail "net/mail"
	"net/smtp"
	"strings"
	"time"
)

const smtpDialTimeout = 15 * time.Second

type SMTPConfig struct {
	Enabled            bool
	Host               string
	Port               int
	Username           string
	Password           string
	FromEmail          string
	FromName           string
	Encryption         string
	InsecureSkipVerify bool
}

func Send(cfg SMTPConfig, to []string, subject, textBody, htmlBody string) error {
	if !cfg.Enabled || strings.TrimSpace(cfg.Host) == "" || cfg.Port <= 0 || strings.TrimSpace(cfg.FromEmail) == "" {
		return fmt.Errorf("smtp config incomplete")
	}
	address := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	switch strings.TrimSpace(cfg.Encryption) {
	case "implicit_tls":
		return sendImplicitTLS(cfg, address, to, subject, textBody, htmlBody)
	case "none":
		return sendPlainOrStartTLS(cfg, address, to, subject, textBody, htmlBody, false)
	default:
		return sendPlainOrStartTLS(cfg, address, to, subject, textBody, htmlBody, true)
	}
}

func sendImplicitTLS(cfg SMTPConfig, address string, to []string, subject, textBody, htmlBody string) error {
	dialer := &net.Dialer{Timeout: smtpDialTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		ServerName:         cfg.Host,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return err
	}
	defer client.Quit()
	return writeMessage(client, cfg, to, subject, textBody, htmlBody)
}

func sendPlainOrStartTLS(cfg SMTPConfig, address string, to []string, subject, textBody, htmlBody string, startTLS bool) error {
	dialer := &net.Dialer{Timeout: smtpDialTimeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(smtpDialTimeout))

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer client.Quit()

	if startTLS {
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			return fmt.Errorf("smtp server does not advertise STARTTLS; refusing to send over plaintext")
		}
		if err := client.StartTLS(&tls.Config{
			ServerName:         cfg.Host,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		}); err != nil {
			return err
		}
	}
	return writeMessage(client, cfg, to, subject, textBody, htmlBody)
}

func writeMessage(client *smtp.Client, cfg SMTPConfig, to []string, subject, textBody, htmlBody string) error {
	if strings.TrimSpace(cfg.Username) != "" {
		auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
		if err := client.Auth(auth); err != nil {
			return err
		}
	}

	from := sanitizeAddress(cfg.FromEmail)
	if from == "" {
		return fmt.Errorf("smtp from address is empty")
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, recipient := range to {
		normalizedRecipient := sanitizeAddress(recipient)
		if normalizedRecipient == "" {
			return fmt.Errorf("smtp recipient is empty")
		}
		if err := client.Rcpt(normalizedRecipient); err != nil {
			return err
		}
	}

	writer, err := client.Data()
	if err != nil {
		return err
	}
	defer writer.Close()

	message := buildMessage(cfg, to, subject, textBody, htmlBody)
	if _, err := writer.Write([]byte(message)); err != nil {
		return err
	}
	return nil
}

func buildMessage(cfg SMTPConfig, to []string, subject, textBody, htmlBody string) string {
	from := sanitizeAddress(cfg.FromEmail)
	if strings.TrimSpace(cfg.FromName) != "" {
		from = fmt.Sprintf("%s <%s>", sanitizeHeaderValue(cfg.FromName), from)
	}
	dateHeader := time.Now().UTC().Format(time.RFC1123Z)
	messageID := buildMessageID(cfg.FromEmail)
	headers := []string{
		fmt.Sprintf("From: %s", from),
		"To: undisclosed-recipients:;",
		fmt.Sprintf("Subject: %s", sanitizeHeaderValue(subject)),
		fmt.Sprintf("Date: %s", dateHeader),
		fmt.Sprintf("Message-ID: %s", messageID),
		"MIME-Version: 1.0",
	}
	if strings.TrimSpace(htmlBody) == "" {
		headers = append(headers, `Content-Type: text/plain; charset="UTF-8"`, "", textBody)
		return strings.Join(headers, "\r\n")
	}

	boundary := fmt.Sprintf("portlyn_%d", time.Now().UnixNano())
	headers = append(headers, fmt.Sprintf(`Content-Type: multipart/alternative; boundary="%s"`, boundary), "")
	parts := []string{
		fmt.Sprintf("--%s", boundary),
		`Content-Type: text/plain; charset="UTF-8"`,
		"Content-Transfer-Encoding: 8bit",
		"",
		textBody,
		fmt.Sprintf("--%s", boundary),
		`Content-Type: text/html; charset="UTF-8"`,
		"Content-Transfer-Encoding: 8bit",
		"",
		htmlBody,
		fmt.Sprintf("--%s--", boundary),
	}
	headers = append(headers, parts...)
	return strings.Join(headers, "\r\n")
}

func buildMessageID(fromEmail string) string {
	domain := "localhost"
	if parts := strings.Split(sanitizeAddress(fromEmail), "@"); len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
		domain = strings.TrimSpace(parts[1])
	}
	return fmt.Sprintf("<%d.%s@%s>", time.Now().UnixNano(), strings.ReplaceAll(domain, " ", ""), domain)
}

func sanitizeAddress(value string) string {
	normalized := sanitizeHeaderValue(value)
	if normalized == "" {
		return ""
	}
	parsed, err := stdmail.ParseAddress(normalized)
	if err != nil || parsed == nil {
		return ""
	}
	return strings.TrimSpace(parsed.Address)
}

func sanitizeAddressList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if sanitized := sanitizeAddress(value); sanitized != "" {
			out = append(out, sanitized)
		}
	}
	return out
}

func sanitizeHeaderValue(value string) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.ReplaceAll(trimmed, "\r", " ")
	trimmed = strings.ReplaceAll(trimmed, "\n", " ")
	return strings.TrimSpace(trimmed)
}

func ResolveHostPort(host string, port int) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}
