package scoring

import (
	"fmt"
	"strings"

	"github.com/Montjoje/BSO_projektN02/internal/models"
)

func ClassifyHosts(hosts []models.Host, openPortsThreshold int, profileName string) []models.Host {
	out := make([]models.Host, 0, len(hosts))
	for _, host := range hosts {
		host.ScanProfile = profileName
		host.Findings = AnalyzeHost(host, openPortsThreshold)
		host.RiskScore = 0
		for _, finding := range host.Findings {
			host.RiskScore += finding.Score
		}
		host.RiskLevel = RiskLevel(host.RiskScore)
		out = append(out, host)
	}
	return out
}

func AnalyzeHost(host models.Host, openPortsThreshold int) []models.Finding {
	findings := make([]models.Finding, 0)
	openPorts := 0
	seen := map[string]bool{}
	for _, svc := range host.Services {
		if strings.ToLower(svc.State) != "open" {
			continue
		}
		openPorts++
		findings = appendUnique(findings, seen, serviceFindings(host, svc)...)
	}
	if openPorts > openPortsThreshold {
		findings = appendUnique(findings, seen, models.Finding{
			Severity:       "MEDIUM",
			Score:          10,
			Title:          "Duża liczba otwartych portów na jednym hoście",
			Evidence:       fmt.Sprintf("Host ma %d otwartych portów, próg konfiguracyjny wynosi %d.", openPorts, openPortsThreshold),
			Recommendation: "Zweryfikować, które usługi faktycznie są potrzebne. Wyłączyć nieużywane demony, ograniczyć dostęp regułami firewall i rozważyć segmentację urządzenia do osobnej sieci/VLAN.",
		})
	}
	for _, script := range host.HostScripts {
		findings = appendUnique(findings, seen, scriptFinding(script, 0, "", "host")...)
	}
	return findings
}

func serviceFindings(host models.Host, svc models.Service) []models.Finding {
	var findings []models.Finding
	name := strings.ToLower(svc.Name)
	product := strings.ToLower(svc.Product + " " + svc.Version + " " + svc.Extra)
	serviceLabel := labelService(svc)

	if isHTTP(name, svc.Port) && !isTLS(svc) {
		findings = append(findings, models.Finding{
			Severity:       "MEDIUM",
			Score:          20,
			Title:          "Panel lub usługa HTTP działa bez szyfrowania TLS",
			Evidence:       fmt.Sprintf("%s odpowiada jako %q/%q bez tunelu SSL/TLS.", serviceLabel, svc.Name, svc.Product),
			Recommendation: "Włączyć HTTPS dla panelu administracyjnego albo wyłączyć panel HTTP. Jeżeli HTTPS nie jest wspierany, ograniczyć dostęp do panelu wyłącznie do zaufanego adresu administratora lub VLAN administracyjnego.",
			Port:           svc.Port,
			Protocol:       svc.Protocol,
			Service:        svc.Name,
		})
	}

	if isLegacy(name, svc.Port) {
		findings = append(findings, models.Finding{
			Severity:       "HIGH",
			Score:          20,
			Title:          "Wykryto przestarzały lub nieszyfrowany protokół",
			Evidence:       fmt.Sprintf("%s korzysta z usługi %q, która zwykle przesyła dane lub hasła bez wystarczającej ochrony.", serviceLabel, svc.Name),
			Recommendation: "Wyłączyć usługę lub zastąpić ją bezpieczniejszym odpowiednikiem: Telnet -> SSH, FTP -> SFTP/FTPS, HTTP panelu -> HTTPS. Jeżeli usługa jest konieczna, ograniczyć ją firewallem do zaufanych hostów.",
			Port:           svc.Port,
			Protocol:       svc.Protocol,
			Service:        svc.Name,
		})
	}

	if isRemoteAccess(name, svc.Port) {
		findings = append(findings, models.Finding{
			Severity:       "MEDIUM",
			Score:          15,
			Title:          "Usługa zdalnego zarządzania jest dostępna w sieci LAN",
			Evidence:       fmt.Sprintf("%s udostępnia usługę zdalnego dostępu/administracji %q.", serviceLabel, svc.Name),
			Recommendation: "Sprawdzić, czy usługa jest wymagana. Wymusić silne hasła i aktualne oprogramowanie, wyłączyć logowanie domyślne, ograniczyć dostęp do podsieci administracyjnej oraz monitorować nieudane próby logowania.",
			Port:           svc.Port,
			Protocol:       svc.Protocol,
			Service:        svc.Name,
		})
	}

	if strings.Contains(product, "goahead") || strings.Contains(product, "boa") || strings.Contains(product, "busybox") || strings.Contains(product, "camera") || name == "rtsp" || svc.Port == 554 {
		findings = append(findings, models.Finding{
			Severity:       "LOW",
			Score:          10,
			Title:          "Urządzenie IoT lub kamera z usługą często spotykaną w błędnych konfiguracjach",
			Evidence:       fmt.Sprintf("%s zgłasza usługę/produkt %q %q.", serviceLabel, svc.Name, strings.TrimSpace(svc.Product+" "+svc.Version)),
			Recommendation: "Sprawdzić dostępność aktualizacji firmware, zmienić hasła fabryczne, wyłączyć dostęp anonimowy i umieścić urządzenie IoT w odseparowanej sieci gościnnej/VLAN bez dostępu do komputerów użytkownika.",
			Port:           svc.Port,
			Protocol:       svc.Protocol,
			Service:        svc.Name,
		})
	}

	if looksOldVersion(product) {
		findings = append(findings, models.Finding{
			Severity:       "MEDIUM",
			Score:          20,
			Title:          "Usługa wygląda na starą wersję oprogramowania",
			Evidence:       fmt.Sprintf("Nmap rozpoznał %s jako %q.", serviceLabel, strings.TrimSpace(svc.Product+" "+svc.Version+" "+svc.Extra)),
			Recommendation: "Porównać wersję z aktualnym firmware/oprogramowaniem producenta i wykonać aktualizację. Dla urządzeń bez wsparcia producenta rozważyć izolację sieciową albo wymianę urządzenia.",
			Port:           svc.Port,
			Protocol:       svc.Protocol,
			Service:        svc.Name,
		})
	}

	for _, script := range svc.Scripts {
		findings = append(findings, scriptFinding(script, svc.Port, svc.Protocol, svc.Name)...)
	}
	_ = host
	return findings
}

func scriptFinding(script models.Script, port int, proto, service string) []models.Finding {
	id := strings.ToLower(script.ID)
	output := strings.ToLower(script.Output)
	if script.ID == "" && script.Output == "" {
		return nil
	}
	base := models.Finding{Port: port, Protocol: proto, Service: service}
	trimmedOutput := truncate(script.Output, 260)

	if strings.Contains(id, "vuln") || strings.Contains(output, "vulnerable") || strings.Contains(output, "cve-") || strings.Contains(output, "exploit") {
		base.Severity = "HIGH"
		base.Score = 30
		base.Title = "Skrypt NSE wskazał konkretną podatność lub CVE"
		base.Evidence = fmt.Sprintf("%s: %s", script.ID, trimmedOutput)
		base.Recommendation = "Odczytać nazwę CVE/podatności z wyniku NSE, sprawdzić wersję usługi, wykonać aktualizację firmware/oprogramowania i do czasu poprawki ograniczyć dostęp do portu firewallem. Jeżeli usługa nie jest potrzebna, wyłączyć ją."
		return []models.Finding{base}
	}
	if containsAny(output, []string{"anonymous", "default password", "default credentials", "no authentication", "auth not required", "weak", "expired", "self-signed"}) {
		base.Severity = "MEDIUM"
		base.Score = 15
		base.Title = "Skrypt NSE wykrył słabą konfigurację usługi"
		base.Evidence = fmt.Sprintf("%s: %s", script.ID, trimmedOutput)
		base.Recommendation = "Usunąć konfigurację domyślną, wymusić uwierzytelnianie, zmienić hasła, odnowić certyfikat TLS lub ograniczyć usługę firewallem zależnie od treści wyniku NSE."
		return []models.Finding{base}
	}
	if strings.Contains(id, "http-title") && containsAny(output, []string{"admin", "login", "camera", "router", "configuration"}) {
		base.Severity = "LOW"
		base.Score = 5
		base.Title = "NSE rozpoznał prawdopodobny panel administracyjny"
		base.Evidence = fmt.Sprintf("%s: %s", script.ID, trimmedOutput)
		base.Recommendation = "Zweryfikować, czy panel powinien być dostępny dla całej sieci LAN. Dla paneli administracyjnych preferować HTTPS, silne hasło i dostęp tylko z hostów administratora."
		return []models.Finding{base}
	}
	return nil
}

func RiskLevel(score int) string {
	switch {
	case score >= 40:
		return "HIGH"
	case score >= 20:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func BuildSummary(hosts []models.Host) models.ResultSummary {
	summary := models.ResultSummary{HostCount: len(hosts)}
	for _, h := range hosts {
		for _, svc := range h.Services {
			if strings.ToLower(svc.State) == "open" {
				summary.OpenPortCount++
			}
		}
		summary.FindingCount += len(h.Findings)
		switch h.RiskLevel {
		case "HIGH":
			summary.HighRiskHosts++
		case "MEDIUM":
			summary.MediumRiskHosts++
		default:
			summary.LowRiskHosts++
		}
	}
	return summary
}

func appendUnique(findings []models.Finding, seen map[string]bool, candidates ...models.Finding) []models.Finding {
	for _, finding := range candidates {
		key := fmt.Sprintf("%s|%d|%s|%s", finding.Title, finding.Port, finding.Protocol, finding.Evidence)
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, finding)
	}
	return findings
}

func isHTTP(name string, port int) bool {
	return strings.Contains(name, "http") || port == 80 || port == 8080 || port == 8000 || port == 8888
}

func isTLS(svc models.Service) bool {
	name := strings.ToLower(svc.Name)
	tunnel := strings.ToLower(svc.Tunnel)
	return tunnel == "ssl" || strings.Contains(name, "https") || svc.Port == 443 || svc.Port == 8443
}

func isLegacy(name string, port int) bool {
	legacyNames := []string{"telnet", "ftp", "rlogin", "rexec", "rsh", "tftp"}
	if containsAny(name, legacyNames) {
		return true
	}
	return port == 21 || port == 23 || port == 69 || port == 513 || port == 514
}

func isRemoteAccess(name string, port int) bool {
	remoteNames := []string{"ssh", "telnet", "rdp", "ms-wbt-server", "vnc", "winbox", "teamviewer", "remote"}
	if containsAny(name, remoteNames) {
		return true
	}
	switch port {
	case 22, 23, 3389, 5900, 8291, 5985, 5986:
		return true
	default:
		return false
	}
}

func looksOldVersion(product string) bool {
	oldMarkers := []string{"windows xp", "openssl 0.", "openssl 1.0", "openssh 5.", "openssh 6.", "apache 2.2", "php/5", "goahead-webs 2.", "busybox v1.1", "samba 3.", "dropbear 2014", "dropbear 2015"}
	return containsAny(product, oldMarkers)
}

func containsAny(value string, needles []string) bool {
	value = strings.ToLower(value)
	for _, needle := range needles {
		if strings.Contains(value, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func labelService(svc models.Service) string {
	if svc.Port == 0 {
		return "wynik hostscript"
	}
	return fmt.Sprintf("%s/%d", svc.Protocol, svc.Port)
}

func truncate(value string, max int) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) <= max {
		return value
	}
	return value[:max-3] + "..."
}
