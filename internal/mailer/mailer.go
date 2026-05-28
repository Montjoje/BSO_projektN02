package mailer

import (
	"fmt"
	"net/smtp"
	"strings"

	"github.com/Montjoje/BSO_projektN02/internal/models"
)

func Send(cfg models.Config, rep models.Report) error {
	boundary := "BSO-N02-BOUNDARY"
	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPassword, cfg.SMTPHost)
	msg := strings.Join([]string{
		fmt.Sprintf("From: %s", cfg.SMTPFrom),
		fmt.Sprintf("To: %s", cfg.SMTPTo),
		fmt.Sprintf("Subject: %s", rep.Subject),
		"MIME-Version: 1.0",
		fmt.Sprintf("Content-Type: multipart/alternative; boundary=%s", boundary),
		"",
		fmt.Sprintf("--%s", boundary),
		"Content-Type: text/plain; charset=UTF-8",
		"",
		rep.TextBody,
		fmt.Sprintf("--%s", boundary),
		"Content-Type: text/html; charset=UTF-8",
		"",
		rep.HTMLBody,
		fmt.Sprintf("--%s--", boundary),
		"",
	}, "\r\n")
	return smtp.SendMail(addr, auth, cfg.SMTPFrom, []string{cfg.SMTPTo}, []byte(msg))
}
