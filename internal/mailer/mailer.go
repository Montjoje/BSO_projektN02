package mailer

import (
	"crypto/tls"
	"fmt"
	"log"
	"mime"
	"net/mail"
	"net/smtp"
	"strings"

	"github.com/Montjoje/BSO_projektN02/internal/models"
)

func SendReport(cfg models.MailConfig, textBody, htmlBody string) error {
	if !cfg.Enabled {
		log.Printf("mail: wysyłka wyłączona w konfiguracji")
		return nil
	}
	if cfg.SMTPHost == "" || cfg.Sender == "" || cfg.Password == "" || cfg.Recipient == "" {
		return fmt.Errorf("mail: brak wymaganych parametrów SMTP")
	}
	boundary := "BSO-N02-REPORT-BOUNDARY"
	headers := []string{
		fmt.Sprintf("From: %s", cfg.Sender),
		fmt.Sprintf("To: %s", cfg.Recipient),
		fmt.Sprintf("Subject: %s", mime.QEncoding.Encode("UTF-8", cfg.Subject)),
		"MIME-Version: 1.0",
		fmt.Sprintf("Content-Type: multipart/alternative; boundary=%q", boundary),
		"",
		fmt.Sprintf("--%s", boundary),
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: 8bit",
		"",
		textBody,
		fmt.Sprintf("--%s", boundary),
		"Content-Type: text/html; charset=UTF-8",
		"Content-Transfer-Encoding: 8bit",
		"",
		htmlBody,
		fmt.Sprintf("--%s--", boundary),
		"",
	}
	message := []byte(strings.Join(headers, "\r\n"))
	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	if cfg.SMTPPort == 465 {
		return sendImplicitTLS(addr, cfg, message)
	}
	auth := smtp.PlainAuth("", cfg.Sender, cfg.Password, cfg.SMTPHost)
	log.Printf("mail: wysyłam raport przez %s", addr)
	return smtp.SendMail(addr, auth, cfg.Sender, []string{cfg.Recipient}, message)
}

func sendImplicitTLS(addr string, cfg models.MailConfig, message []byte) error {
	log.Printf("mail: wysyłam raport przez SMTPS %s", addr)
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: cfg.SMTPHost, InsecureSkipVerify: cfg.SkipVerify})
	if err != nil {
		return err
	}
	defer conn.Close()
	client, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		return err
	}
	defer client.Quit()
	if err := client.Auth(smtp.PlainAuth("", cfg.Sender, cfg.Password, cfg.SMTPHost)); err != nil {
		return err
	}
	return finishSMTP(client, cfg, message)
}

func finishSMTP(client *smtp.Client, cfg models.MailConfig, message []byte) error {
	if err := client.Mail(cfg.Sender); err != nil {
		return err
	}
	for _, recipient := range strings.Split(cfg.Recipient, ",") {
		recipient = strings.TrimSpace(recipient)
		if recipient == "" {
			continue
		}
		if _, err := mailAddress(recipient); err != nil {
			return err
		}
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(message); err != nil {
		_ = w.Close()
		return err
	}
	return w.Close()
}

func mailAddress(addr string) (string, error) {
	if strings.ContainsAny(addr, "\r\n") {
		return "", fmt.Errorf("niepoprawny adres e-mail: %q", addr)
	}
	parsed, err := mail.ParseAddress(addr)
	if err != nil {
		return "", fmt.Errorf("niepoprawny adres e-mail %q: %w", addr, err)
	}
	return parsed.Address, nil
}
