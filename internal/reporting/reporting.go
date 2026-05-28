package reporting

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Montjoje/BSO_projektN02/internal/models"
)

func Build(hosts []models.Host, cfg models.Config, profile models.Profile) (models.Report, error) {
	rep := models.Report{
		GeneratedAt: time.Now().Format(time.RFC3339),
		Profile:     profile.Name,
		Subnets:     strings.Join(cfg.Subnets, ", "),
		HostCount:   len(hosts),
		Hosts:       hosts,
		Subject:     fmt.Sprintf("%s raport skanowania (%s)", cfg.SubjectPrefix, profile.Name),
	}
	rep.TextBody = buildText(rep)
	htmlBody, err := buildHTML(rep, filepath.Join("templates", "report.html"))
	if err != nil {
		return rep, err
	}
	rep.HTMLBody = htmlBody
	return rep, nil
}

func Write(rep models.Report, workDir string) error {
	reportDir := filepath.Join(workDir, "reports")
	if err := os.MkdirAll(reportDir, 0o755); err != nil { return err }
	base := filepath.Join(reportDir, fmt.Sprintf("report-%d", time.Now().Unix()))
	if err := os.WriteFile(base+".txt", []byte(rep.TextBody), 0o644); err != nil { return err }
	if err := os.WriteFile(base+".html", []byte(rep.HTMLBody), 0o644); err != nil { return err }
	return nil
}

func buildText(rep models.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", rep.Subject)
	fmt.Fprintf(&b, "Data: %s\nProfil: %s\nPodsieci: %s\nWykryte hosty: %d\n\n", rep.GeneratedAt, rep.Profile, rep.Subnets, rep.HostCount)
	for _, h := range rep.Hosts {
		fmt.Fprintf(&b, "Host: %s (%s)\nRyzyko: %s (%d pkt)\n", h.Address, h.Hostname, h.Risk, h.Points)
		for _, p := range h.Ports { fmt.Fprintf(&b, "  - %d/%s %s %s %s\n", p.Port, p.Protocol, p.Service, p.Product, p.Version) }
		for _, f := range h.Findings { fmt.Fprintf(&b, "  * %s\n", f) }
		b.WriteString("\n")
	}
	return b.String()
}

func buildHTML(rep models.Report, templatePath string) (string, error) {
	tpl, err := template.ParseFiles(templatePath)
	if err != nil {
		const fallback = `<html><body><h1>{{.Subject}}</h1><p>{{.GeneratedAt}}</p></body></html>`
		tpl, err = template.New("fallback").Parse(fallback)
		if err != nil { return "", err }
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, rep); err != nil { return "", err }
	return buf.String(), nil
}
