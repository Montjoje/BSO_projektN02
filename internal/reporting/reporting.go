package reporting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Montjoje/BSO_projektN02/internal/models"
)

const htmlTemplate = `<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;margin:0;padding:24px;background:#f6f8fb;color:#18202a;line-height:1.45}.wrap{max-width:1100px;margin:auto;background:white;border-radius:14px;padding:28px;box-shadow:0 4px 18px rgba(0,0,0,.08)}h1,h2{margin-top:0}.muted{color:#5b6675}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:18px 0}.card{border:1px solid #e4e9f0;border-radius:12px;padding:14px;background:#fbfcfe}.num{font-size:28px;font-weight:700}.risk-HIGH{color:#9d1717;font-weight:700}.risk-MEDIUM{color:#946200;font-weight:700}.risk-LOW{color:#236b2c;font-weight:700}.risk-UNKNOWN{color:#5b6675;font-weight:700}table{width:100%;border-collapse:collapse;margin:12px 0 28px}th,td{padding:9px 10px;border-bottom:1px solid #e6ebf2;text-align:left;vertical-align:top}th{background:#eef3f9}.finding{border-left:5px solid #d0d7e2;padding:10px 12px;margin:10px 0;background:#fbfcfe;border-radius:8px}.finding.HIGH{border-left-color:#b42318}.finding.MEDIUM{border-left-color:#c27a00}.finding.LOW{border-left-color:#2e7d32}.finding.INFO{border-left-color:#697386}.code{font-family:Consolas,monospace;background:#f0f3f7;border-radius:5px;padding:2px 5px}.rec{font-weight:600}footer{margin-top:28px;font-size:12px;color:#697386}</style>
</head>
<body><div class="wrap">
<h1>{{.Title}}</h1>
<p class="muted">Wygenerowano: {{.GeneratedAt.Format "2006-01-02 15:04:05"}} | Profil: <strong>{{.Profile.Name}}</strong> ({{.Profile.Mode}}) | Podsieci: {{join .Subnets ", "}}</p>
<div class="summary">
<div class="card"><div class="num">{{.Summary.HostCount}}</div><div>aktywnych hostów</div></div>
<div class="card"><div class="num">{{.Summary.OpenPortCount}}</div><div>otwartych portów</div></div>
<div class="card"><div class="num">{{.Summary.FindingCount}}</div><div>ustaleń bezpieczeństwa</div></div>
<div class="card"><div class="num risk-HIGH">{{.Summary.HighRiskHosts}}</div><div>hostów wysokiego ryzyka</div></div>
<div class="card"><div class="num risk-UNKNOWN">{{.Summary.UnknownRiskHosts}}</div><div>hostów nieocenionych</div></div>
</div>
{{if .Warnings}}
<h2>Ostrzeżenia operacyjne</h2>
<ul>{{range .Warnings}}<li>{{.}}</li>{{end}}</ul>
{{end}}
<h2>Najważniejsze urządzenia</h2>
<table><thead><tr><th>Ryzyko</th><th>Host</th><th>Nazwa / producent</th><th>Status oceny</th><th>Otwarte usługi</th><th>Liczba ustaleń</th></tr></thead><tbody>
{{range .Hosts}}
<tr><td class="risk-{{.RiskLevel}}">{{.RiskLevel}} ({{.RiskScore}} pkt)</td><td><span class="code">{{.IP}}</span></td><td>{{or .Hostname "-"}}<br><span class="muted">{{or .Vendor "-"}}</span></td><td>{{statusLabel .AssessmentStatus}}<br><span class="muted">{{.AssessmentMessage}}</span></td><td>{{range .Services}}{{if eq .State "open"}}<span class="code">{{.Protocol}}/{{.Port}} {{.Name}}</span><br>{{end}}{{end}}</td><td>{{len .Findings}}</td></tr>
{{end}}
</tbody></table>
<h2>Szczegółowe ustalenia i rekomendacje</h2>
{{range .Hosts}}
<h3>{{.IP}} {{if .Hostname}}— {{.Hostname}}{{end}} <span class="risk-{{.RiskLevel}}">{{.RiskLevel}}, {{.RiskScore}} pkt</span></h3>
<p class="muted">Status oceny: {{statusLabel .AssessmentStatus}}{{if .AssessmentMessage}} — {{.AssessmentMessage}}{{end}}</p>
{{if .Findings}}
{{range .Findings}}
<div class="finding {{.Severity}}"><strong>{{.Severity}}: {{.Title}}</strong>{{if .Port}} <span class="code">{{.Protocol}}/{{.Port}} {{.Service}}</span>{{end}}<br>
<span class="muted">Dowód: {{.Evidence}}</span><br>
<span class="rec">Zalecenie:</span> {{.Recommendation}}</div>
{{end}}
{{else}}<p class="muted">Brak istotnych ustaleń dla tego hosta w aktywnym profilu.</p>{{end}}
{{end}}
<footer>Raport wygenerowany przez BSO N02 LAN Security Scanner. Wyniki mają charakter diagnostyczny; decyzje naprawcze pozostają po stronie administratora.</footer>
</div></body></html>`

type View struct {
	Title       string
	GeneratedAt time.Time
	models.ScanResult
}

func SaveAll(result models.ScanResult, reportDir string) (models.ScanArtifacts, string, string, error) {
	if err := os.MkdirAll(reportDir, 0o750); err != nil {
		return result.Artifacts, "", "", err
	}
	stamp := result.GeneratedAt.Format("20060102-150405")
	jsonPath := filepath.Join(reportDir, fmt.Sprintf("scan-report-%s.json", stamp))
	htmlPath := filepath.Join(reportDir, fmt.Sprintf("scan-report-%s.html", stamp))
	textPath := filepath.Join(reportDir, fmt.Sprintf("scan-report-%s.txt", stamp))

	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return result.Artifacts, "", "", err
	}
	if err := os.WriteFile(jsonPath, jsonBytes, 0o640); err != nil {
		return result.Artifacts, "", "", err
	}
	htmlBody, err := RenderHTML(result)
	if err != nil {
		return result.Artifacts, "", "", err
	}
	if err := os.WriteFile(htmlPath, []byte(htmlBody), 0o640); err != nil {
		return result.Artifacts, "", "", err
	}
	textBody := RenderText(result)
	if err := os.WriteFile(textPath, []byte(textBody), 0o640); err != nil {
		return result.Artifacts, "", "", err
	}
	artifacts := result.Artifacts
	artifacts.JSONPath = jsonPath
	artifacts.HTMLPath = htmlPath
	artifacts.TextPath = textPath
	return artifacts, htmlBody, textBody, nil
}

func RenderHTML(result models.ScanResult) (string, error) {
	hosts := sortedHosts(result.Hosts)
	result.Hosts = hosts
	view := View{Title: "Raport BSO N02 - skan lokalnej sieci", GeneratedAt: result.GeneratedAt, ScanResult: result}
	tpl, err := template.New("report").Funcs(template.FuncMap{
		"join": strings.Join,
		"or": func(a, b string) string {
			if strings.TrimSpace(a) != "" {
				return a
			}
			return b
		},
		"statusLabel": assessmentStatusLabel,
	}).Parse(htmlTemplate)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, view); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func RenderText(result models.ScanResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Raport BSO N02 - skan lokalnej sieci\n")
	fmt.Fprintf(&b, "Wygenerowano: %s\n", result.GeneratedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "Profil: %s (%s)\n", result.Profile.Name, result.Profile.Mode)
	fmt.Fprintf(&b, "Podsieci: %s\n\n", strings.Join(result.Subnets, ", "))
	fmt.Fprintf(&b, "Podsumowanie: hosty=%d, otwarte porty=%d, ustalenia=%d, high=%d, medium=%d, low=%d, unknown=%d\n",
		result.Summary.HostCount, result.Summary.OpenPortCount, result.Summary.FindingCount, result.Summary.HighRiskHosts, result.Summary.MediumRiskHosts, result.Summary.LowRiskHosts, result.Summary.UnknownRiskHosts)
	if len(result.Warnings) > 0 {
		fmt.Fprintf(&b, "\nOstrzeżenia operacyjne:\n")
		for _, warning := range result.Warnings {
			fmt.Fprintf(&b, " - %s\n", warning)
		}
	}
	fmt.Fprintf(&b, "\n")
	for _, host := range sortedHosts(result.Hosts) {
		fmt.Fprintf(&b, "Host %s", host.IP)
		if host.Hostname != "" {
			fmt.Fprintf(&b, " (%s)", host.Hostname)
		}
		fmt.Fprintf(&b, " - ryzyko %s, %d pkt\n", host.RiskLevel, host.RiskScore)
		fmt.Fprintf(&b, "  Status oceny: %s", assessmentStatusLabel(host.AssessmentStatus))
		if strings.TrimSpace(host.AssessmentMessage) != "" {
			fmt.Fprintf(&b, " - %s", host.AssessmentMessage)
		}
		fmt.Fprintf(&b, "\n")
		if host.Vendor != "" {
			fmt.Fprintf(&b, "  Producent: %s\n", host.Vendor)
		}
		fmt.Fprintf(&b, "  Otwarte usługi:\n")
		for _, svc := range host.Services {
			if strings.ToLower(svc.State) == "open" {
				fmt.Fprintf(&b, "   - %s/%d %s %s %s\n", svc.Protocol, svc.Port, svc.Name, svc.Product, svc.Version)
			}
		}
		if len(host.Findings) == 0 {
			fmt.Fprintf(&b, "  Brak istotnych ustaleń w aktywnym profilu.\n\n")
			continue
		}
		fmt.Fprintf(&b, "  Ustalenia i zalecenia:\n")
		for _, finding := range host.Findings {
			port := ""
			if finding.Port > 0 {
				port = fmt.Sprintf(" [%s/%d %s]", finding.Protocol, finding.Port, finding.Service)
			}
			fmt.Fprintf(&b, "   - %s%s: %s (%d pkt)\n", finding.Severity, port, finding.Title, finding.Score)
			fmt.Fprintf(&b, "     Dowód: %s\n", finding.Evidence)
			fmt.Fprintf(&b, "     Zalecenie: %s\n", finding.Recommendation)
		}
		fmt.Fprintf(&b, "\n")
	}
	return b.String()
}

func assessmentStatusLabel(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "assessed":
		return "oceniony"
	case "partial":
		return "ocena częściowa"
	case "discovery_only":
		return "tylko discovery"
	case "scan_failed":
		return "skan nieukończony"
	case "parse_failed":
		return "błąd parsowania"
	case "not_assessed", "unknown":
		return "nieoceniony"
	default:
		return "brak danych"
	}
}

func sortedHosts(hosts []models.Host) []models.Host {
	out := append([]models.Host(nil), hosts...)
	rank := map[string]int{"HIGH": 0, "MEDIUM": 1, "UNKNOWN": 2, "LOW": 3}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].RiskLevel] != rank[out[j].RiskLevel] {
			return rank[out[i].RiskLevel] < rank[out[j].RiskLevel]
		}
		if out[i].RiskScore != out[j].RiskScore {
			return out[i].RiskScore > out[j].RiskScore
		}
		return out[i].IP < out[j].IP
	})
	return out
}
