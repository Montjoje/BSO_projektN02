package scoring

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Montjoje/BSO_projektN02/internal/models"
	"github.com/Montjoje/BSO_projektN02/internal/parser"
)

func Score(res parser.Result) []models.Host {
	hosts := make([]models.Host, 0, len(res.Hosts))
	for _, h := range res.Hosts {
		points := 0
		findings := make([]models.Finding, 0)

		if len(h.Ports) > 5 {
			points += 10
			findings = append(findings, newFinding(
				"Duża liczba otwartych portów",
				formatOpenPorts(h.Ports),
				"Ograniczyć ekspozycję hosta przez wyłączenie zbędnych usług i zastosowanie reguł zapory dla ruchu wewnątrzsieciowego.",
				"medium",
			))
		}

		var smbPorts, remotePorts, legacyPorts []string
		iotLike := strings.Contains(strings.ToLower(h.Hostname), "kamera") || strings.Contains(strings.ToLower(h.Hostname), "printer")

		for _, p := range h.Ports {
			svc := strings.ToLower(p.Service)
			prod := strings.ToLower(p.Product)
			portLabel := fmt.Sprintf("%d/%s (%s %s %s)", p.Port, p.Protocol, p.Service, p.Product, p.Version)
			portLabel = strings.TrimSpace(strings.Join(strings.Fields(portLabel), " "))

			if p.Port == 80 && svc == "http" {
				points += 20
				findings = append(findings, newFinding(
					"Panel HTTP bez TLS",
					fmt.Sprintf("Na porcie 80 wykryto usługę HTTP: %s.", portLabel),
					"Włączyć HTTPS, przekierować ruch z HTTP na HTTPS albo całkowicie wyłączyć panel WWW, jeśli nie jest wymagany.",
					"high",
				))
			}

			if p.Port == 135 || p.Port == 139 || p.Port == 445 || svc == "msrpc" || svc == "netbios-ssn" || svc == "microsoft-ds" || svc == "smb" {
				smbPorts = append(smbPorts, portLabel)
			}

			if p.Port == 22 || p.Port == 23 || p.Port == 3389 || p.Port == 5900 || svc == "ssh" || svc == "telnet" || svc == "rdp" || svc == "vnc" || svc == "ms-wbt-server" {
				remotePorts = append(remotePorts, portLabel)
			}

			if svc == "ftp" || svc == "telnet" || svc == "rtsp" {
				legacyPorts = append(legacyPorts, portLabel)
			}

			if strings.Contains(prod, "goahead") || strings.Contains(prod, "hikvision") || strings.Contains(prod, "onvif") || strings.Contains(prod, "ip camera") || strings.Contains(prod, "printer") {
				iotLike = true
			}
		}

		if len(smbPorts) > 0 {
			points += 15
			findings = append(findings, newFinding(
				"Usługi Windows/RPC/SMB dostępne w sieci lokalnej",
				"Wykryto usługi: "+strings.Join(smbPorts, "; "),
				"Pozostawić tylko niezbędne usługi udostępniania plików, wyłączyć stare protokoły i ograniczyć dostęp do zaufanych hostów lub segmentów sieci.",
				"medium",
			))
		}

		if len(remotePorts) > 0 {
			points += 15
			findings = append(findings, newFinding(
				"Usługa zdalnego dostępu dostępna w sieci lokalnej",
				"Wykryto usługi zdalnego dostępu: "+strings.Join(remotePorts, "; "),
				"Ograniczyć dostęp do interfejsów administracyjnych regułami zapory, dopuszczać tylko zaufane adresy albo korzystać z tunelowania przez VPN.",
				"medium",
			))
		}

		if len(legacyPorts) > 0 {
			points += 20
			findings = append(findings, newFinding(
				"Wykryto usługi lub protokoły o podwyższonym ryzyku",
				"Do tej kategorii należą: "+strings.Join(legacyPorts, "; "),
				"Zweryfikować, czy usługi są nadal potrzebne. Jeżeli nie, wyłączyć je. W przeciwnym razie ograniczyć dostęp i wymusić nowsze, bezpieczniejsze protokoły.",
				"high",
			))
		}

		if iotLike {
			points += 10
			findings = append(findings, newFinding(
				"Urządzenie typu appliance / IoT wymaga dodatkowej kontroli",
				"Nazwa hosta lub sygnatura produktu sugeruje urządzenie o charakterze appliance, IoT albo urządzenie specjalizowane.",
				"Zaleca się wydzielenie urządzenia do osobnej sieci lub VLAN-u, zmianę domyślnych haseł i ograniczenie ekspozycji usług administracyjnych.",
				"medium",
			))
		}

		for _, s := range h.ScriptResults {
			severity, addPoints := scoreScript(s)
			if addPoints == 0 {
				continue
			}
			points += addPoints
			findings = append(findings, newFinding(
				"Wynik skryptu NSE: "+s.ID,
				buildScriptEvidence(s),
				recommendationForScript(s),
				severity,
			))
		}

		h.Findings = uniqueFindings(findings)
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

func newFinding(title, evidence, recommendation, severity string) models.Finding {
	return models.Finding{Title: title, Evidence: evidence, Recommendation: recommendation, Severity: severity}
}

func formatOpenPorts(ports []models.Port) string {
	labels := make([]string, 0, len(ports))
	for _, p := range ports {
		label := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
		if p.Service != "" {
			label += " " + p.Service
		}
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return "Otwarte porty: " + strings.Join(labels, ", ") + "."
}

func scoreScript(s models.ScriptResult) (string, int) {
	text := strings.ToLower(s.Output)
	switch {
	case text == "":
		return "", 0
	case strings.Contains(text, "vulnerable") || strings.Contains(text, "vuln") || strings.Contains(text, "cve-") || strings.Contains(text, "critical"):
		return "high", 20
	case strings.Contains(text, "warning") || strings.Contains(text, "insecure") || strings.Contains(text, "anonymous") || strings.Contains(text, "enabled") || strings.Contains(text, "supported"):
		return "medium", 10
	default:
		return "low", 5
	}
}

func buildScriptEvidence(s models.ScriptResult) string {
	location := "na poziomie hosta"
	if s.Port > 0 {
		location = fmt.Sprintf("na porcie %d/%s", s.Port, s.Protocol)
		if s.Service != "" {
			location += fmt.Sprintf(" (%s)", s.Service)
		}
	}
	output := strings.Join(strings.Fields(s.Output), " ")
	if len(output) > 260 {
		output = output[:257] + "..."
	}
	return fmt.Sprintf("Skrypt %s wykrył problem %s. Wynik: %s", s.ID, location, output)
}

func recommendationForScript(s models.ScriptResult) string {
	id := strings.ToLower(s.ID)
	output := strings.ToLower(s.Output)
	switch {
	case strings.Contains(id, "smb-protocols") && strings.Contains(output, "smbv1"):
		return "Wyłączyć SMBv1 i pozostawić wyłącznie nowsze wersje SMB. Ograniczyć dostęp do udziałów tylko do zaufanych hostów."
	case strings.Contains(id, "ssl-cert"):
		return "Zweryfikować ważność certyfikatu, zgodność nazwy hosta i stosowane algorytmy kryptograficzne. Wymienić certyfikat, jeżeli jest przestarzały lub nieprawidłowy."
	case strings.Contains(id, "http-methods"):
		return "Ograniczyć dozwolone metody HTTP do niezbędnego minimum i wyłączyć metody administracyjne, jeśli nie są potrzebne."
	case strings.Contains(id, "http-headers"):
		return "Zweryfikować nagłówki bezpieczeństwa aplikacji WWW i ograniczyć ujawnianie informacji o serwerze."
	case strings.Contains(id, "ssh2-enum-algos"):
		return "Wyłączyć słabe algorytmy SSH i pozostawić wyłącznie współczesne, zalecane zestawy szyfrów, MAC i wymiany kluczy."
	case strings.Contains(id, "vuln"):
		return "Zweryfikować pełny wynik skryptu NSE, porównać go z dokumentacją danej usługi i niezwłocznie załatać lub ograniczyć podatną usługę."
	default:
		return "Zweryfikować szczegółowy wynik skryptu NSE, potwierdzić jego znaczenie dla danej usługi i zastosować odpowiednie utwardzenie konfiguracji lub ograniczenie dostępu."
	}
}

func uniqueFindings(in []models.Finding) []models.Finding {
	seen := map[string]bool{}
	out := make([]models.Finding, 0, len(in))
	for _, f := range in {
		if f.Title == "" {
			continue
		}
		k := f.Title + "|" + f.Evidence
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}
