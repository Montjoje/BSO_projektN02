package scoring

import (
	"strings"

	"github.com/Montjoje/BSO_projektN02/internal/models"
	"github.com/Montjoje/BSO_projektN02/internal/parser"
)

func Score(res parser.Result) []models.Host {
	hosts := make([]models.Host, 0, len(res.Hosts))
	for _, h := range res.Hosts {
		points := 0
		findings := make([]string, 0)
		openCount := len(h.Ports)
		if openCount > 5 {
			points += 10
			findings = append(findings, "duża liczba otwartych portów")
		}
		legacy := false
		remote := false
		iot := strings.Contains(strings.ToLower(h.Hostname), "kamera") || strings.Contains(strings.ToLower(h.Hostname), "printer")
		for _, p := range h.Ports {
			svc := strings.ToLower(p.Service)
			prod := strings.ToLower(p.Product)
			if svc == "http" && p.Port == 80 {
				points += 20
				findings = append(findings, "panel HTTP bez TLS")
			}
			if svc == "ftp" || svc == "telnet" || svc == "smb" || svc == "rtsp" {
				legacy = true
			}
			if svc == "ssh" || svc == "telnet" || svc == "rdp" || svc == "vnc" {
				remote = true
			}
			if strings.Contains(prod, "goahead") || strings.Contains(prod, "hikvision") || strings.Contains(prod, "onvif") {
				iot = true
			}
		}
		if legacy {
			points += 20
			findings = append(findings, "wykryto usługę lub protokół o podwyższonym ryzyku")
		}
		if remote {
			points += 15
			findings = append(findings, "usługa zdalnego dostępu dostępna w sieci lokalnej")
		}
		if iot {
			points += 10
			findings = append(findings, "urządzenie IoT lub appliance wymagające dodatkowej kontroli")
		}
		for _, s := range h.Scripts {
			if strings.Contains(strings.ToLower(s), "vuln") || strings.Contains(strings.ToLower(s), "warning") {
				points += 10
				findings = append(findings, "skrypt NSE zwrócił ostrzeżenie lub podatność")
			}
		}
		h.Findings = unique(append(h.Findings, findings...))
		h.Points = points
		switch {
		case points >= 40:
			h.Risk = "HIGH"
		case points >= 20:
			h.Risk = "MEDIUM"
		default:
			h.Risk = "LOW"
		}
		hosts = append(hosts, h)
	}
	return hosts
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] { continue }
		seen[s] = true
		out = append(out, s)
	}
	return out
}
