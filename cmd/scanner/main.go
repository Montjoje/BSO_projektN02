package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Montjoje/BSO_projektN02/internal/config"
	"github.com/Montjoje/BSO_projektN02/internal/discovery"
	"github.com/Montjoje/BSO_projektN02/internal/mailer"
	"github.com/Montjoje/BSO_projektN02/internal/models"
	"github.com/Montjoje/BSO_projektN02/internal/parser"
	"github.com/Montjoje/BSO_projektN02/internal/reporting"
	"github.com/Montjoje/BSO_projektN02/internal/scanner"
	"github.com/Montjoje/BSO_projektN02/internal/scoring"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	configPath := flag.String("config", getenv("BSO_CONFIG", "configs/config.yaml"), "ścieżka do config.yaml")
	profileOverride := flag.String("profile", "", "nazwa profilu: baseline, deep albo pentest")
	validateOnly := flag.Bool("validate", false, "tylko sprawdź konfigurację i profil")
	dryRun := flag.Bool("dry-run", false, "uruchom bez wywoływania nmap; generuje przykładowe artefakty")
	noEmail := flag.Bool("no-email", false, "nie wysyłaj raportu e-mail")
	once := flag.Bool("once", false, "wykonaj pojedynczy skan i zakończ")
	flag.Parse()

	cfg, profile, err := config.Load(*configPath, *profileOverride)
	if err != nil {
		log.Fatalf("konfiguracja: %v", err)
	}
	if *dryRun {
		cfg.Runtime.DryRun = true
	}
	if *noEmail {
		cfg.Runtime.NoEmail = true
	}
	if *once {
		cfg.Runtime.RunMode = "once"
	}
	if *validateOnly {
		log.Printf("OK: konfiguracja poprawna, profil=%s, podsieci=%s", profile.Name, strings.Join(cfg.Subnets, ","))
		return
	}

	if strings.EqualFold(cfg.Runtime.RunMode, "daemon") {
		interval := time.Duration(cfg.Runtime.IntervalMins) * time.Minute
		if interval <= 0 {
			interval = 24 * time.Hour
		}
		for {
			if err := runScanJob(cfg, profile); err != nil {
				log.Printf("błąd zadania skanowania: %v", err)
			}
			log.Printf("następny skan za %s", interval)
			time.Sleep(interval)
		}
	}
	if err := runScanJob(cfg, profile); err != nil {
		log.Fatalf("błąd zadania skanowania: %v", err)
	}
}

func runScanJob(cfg models.AppConfig, profile models.ScanProfile) error {
	startedAt := time.Now()
	log.Printf("start skanu: profil=%s mode=%s subnets=%s dry_run=%t", profile.Name, profile.Mode, strings.Join(cfg.Subnets, ","), cfg.Runtime.DryRun)
	runner := scanner.NewNmapRunner(cfg)
	discoverer := discovery.New(runner)
	artifacts := models.ScanArtifacts{StartedAt: startedAt}
	warnings := make([]string, 0)

	discoveredHosts, discoveryXML, err := discoverer.Discover(cfg.Subnets)
	artifacts.DiscoveryXMLPath = discoveryXML
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("Etap discovery nie zakończył się poprawnie: %v", err))
		result := models.ScanResult{
			GeneratedAt: time.Now(),
			Profile:     profile,
			Subnets:     cfg.Subnets,
			Hosts:       []models.Host{},
			Summary:     scoring.BuildSummary(nil),
			Warnings:    warnings,
			Artifacts:   artifacts,
		}
		return finalize(cfg, result)
	}
	if len(discoveredHosts) == 0 {
		result := models.ScanResult{
			GeneratedAt: time.Now(),
			Profile:     profile,
			Subnets:     cfg.Subnets,
			Hosts:       []models.Host{},
			Summary:     scoring.BuildSummary(nil),
			Warnings:    warnings,
			Artifacts:   artifacts,
		}
		return finalize(cfg, result)
	}

	targets := discovery.HostTargets(discoveredHosts)
	merged, basePaths, baseWarnings := runBaseScansPerHost(runner, discoveredHosts, targets, profile)
	warnings = append(warnings, baseWarnings...)
	artifacts.BaseXMLPath = strings.Join(basePaths, ";")

	if shouldRunExtended(profile) {
		var extendedPaths []string
		var extendedWarnings []string
		merged, extendedPaths, extendedWarnings = runExtendedScansPerHost(runner, merged, profile)
		warnings = append(warnings, extendedWarnings...)
		artifacts.ExtendedXMLPath = strings.Join(extendedPaths, ";")
	}

	classified := scoring.ClassifyHosts(merged, cfg.OpenPortsThreshold, profile.Name)
	result := models.ScanResult{
		GeneratedAt: time.Now(),
		Profile:     profile,
		Subnets:     cfg.Subnets,
		Hosts:       classified,
		Summary:     scoring.BuildSummary(classified),
		Warnings:    warnings,
		Artifacts:   artifacts,
	}
	return finalize(cfg, result)
}

func runBaseScansPerHost(runner *scanner.NmapRunner, discoveredHosts []models.Host, targets []string, profile models.ScanProfile) ([]models.Host, []string, []string) {
	merged := prepareDiscoveryOnlyHosts(discoveredHosts)
	paths := make([]string, 0, len(targets))
	warnings := make([]string, 0)

	for _, target := range targets {
		baseXML, err := runner.RunBaseScan([]string{target}, profile)
		if baseXML != "" {
			paths = append(paths, baseXML)
		}
		if err != nil {
			message := fmt.Sprintf("Skan bazowy hosta %s nie zakończył się poprawnie: %v", target, err)
			warnings = append(warnings, message)
			merged = markHostAssessment(merged, target, "scan_failed", message)
			continue
		}

		baseHosts, err := parser.ParseFile(baseXML)
		if err != nil {
			message := fmt.Sprintf("Nie udało się sparsować wyniku skanu bazowego hosta %s: %v", target, err)
			warnings = append(warnings, message)
			merged = markHostAssessment(merged, target, "parse_failed", message)
			continue
		}
		for i := range baseHosts {
			baseHosts[i].AssessmentStatus = "assessed"
			baseHosts[i].AssessmentMessage = "Skan bazowy portów i usług zakończył się poprawnie."
		}
		merged = parser.MergeHosts(merged, baseHosts)
		if !hasHost(baseHosts, target) {
			merged = markHostAssessment(merged, target, "assessed", "Skan bazowy zakończył się poprawnie, ale Nmap nie zwrócił szczegółowych usług dla hosta.")
		}
	}
	return merged, paths, warnings
}

func runExtendedScansPerHost(runner *scanner.NmapRunner, hosts []models.Host, profile models.ScanProfile) ([]models.Host, []string, []string) {
	merged := append([]models.Host(nil), hosts...)
	paths := make([]string, 0, len(hosts))
	warnings := make([]string, 0)

	for _, host := range hosts {
		if host.IP == "" || isUnassessedStatus(host.AssessmentStatus) {
			continue
		}
		extendedXML, err := runner.RunExtendedScan([]string{host.IP}, profile)
		if extendedXML != "" {
			paths = append(paths, extendedXML)
		}
		if err != nil {
			message := fmt.Sprintf("Skan rozszerzony hosta %s nie zakończył się poprawnie; ocena opiera się na discovery i skanie bazowym: %v", host.IP, err)
			warnings = append(warnings, message)
			merged = markHostAssessment(merged, host.IP, "partial", message)
			continue
		}

		extendedHosts, err := parser.ParseFile(extendedXML)
		if err != nil {
			message := fmt.Sprintf("Nie udało się sparsować wyniku skanu rozszerzonego hosta %s; ocena opiera się na discovery i skanie bazowym: %v", host.IP, err)
			warnings = append(warnings, message)
			merged = markHostAssessment(merged, host.IP, "partial", message)
			continue
		}
		for i := range extendedHosts {
			extendedHosts[i].AssessmentStatus = "assessed"
			extendedHosts[i].AssessmentMessage = "Skan bazowy i rozszerzony zakończyły się poprawnie."
		}
		merged = parser.MergeHosts(merged, extendedHosts)
	}
	return merged, paths, warnings
}

func prepareDiscoveryOnlyHosts(hosts []models.Host) []models.Host {
	out := make([]models.Host, 0, len(hosts))
	for _, host := range hosts {
		host.AssessmentStatus = "discovery_only"
		host.AssessmentMessage = "Host został wykryty w discovery, ale skan portów i usług nie został jeszcze zakończony."
		out = append(out, host)
	}
	return out
}

func markHostAssessment(hosts []models.Host, ip, status, message string) []models.Host {
	for i := range hosts {
		if hosts[i].IP == ip {
			hosts[i].AssessmentStatus = status
			hosts[i].AssessmentMessage = message
			return hosts
		}
	}
	return append(hosts, models.Host{IP: ip, State: "unknown", AssessmentStatus: status, AssessmentMessage: message})
}

func hasHost(hosts []models.Host, ip string) bool {
	for _, host := range hosts {
		if host.IP == ip {
			return true
		}
	}
	return false
}

func isUnassessedStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "discovery_only", "scan_failed", "parse_failed", "not_assessed", "unknown":
		return true
	default:
		return false
	}
}

func finalize(cfg models.AppConfig, result models.ScanResult) error {
	result.Artifacts.FinishedAt = time.Now()
	artifacts, htmlBody, textBody, err := reporting.SaveAll(result, cfg.ReportDir)
	if err != nil {
		return err
	}
	log.Printf("zapisano raporty: html=%s txt=%s json=%s", artifacts.HTMLPath, artifacts.TextPath, artifacts.JSONPath)
	if cfg.Runtime.NoEmail {
		log.Printf("pomijam e-mail: BSO_NO_EMAIL/--no-email")
		return nil
	}
	if err := mailer.SendReport(cfg.Mail, textBody, htmlBody); err != nil {
		return fmt.Errorf("wysyłka raportu: %w", err)
	}
	return nil
}

func shouldRunExtended(profile models.ScanProfile) bool {
	mode := strings.ToUpper(profile.Mode)
	if mode != "DEEP" && mode != "PENTEST" {
		return false
	}
	return len(profile.ExtendedArgs) > 0 || len(profile.ExtendedScripts) > 0
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
