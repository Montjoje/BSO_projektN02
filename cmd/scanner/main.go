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

	discoveredHosts, discoveryXML, err := discoverer.Discover(cfg.Subnets)
	if err != nil {
		return err
	}
	artifacts := models.ScanArtifacts{StartedAt: startedAt, DiscoveryXMLPath: discoveryXML}
	if len(discoveredHosts) == 0 {
		result := models.ScanResult{
			GeneratedAt: time.Now(),
			Profile:     profile,
			Subnets:     cfg.Subnets,
			Hosts:       []models.Host{},
			Summary:     scoring.BuildSummary(nil),
			Artifacts:   artifacts,
		}
		return finalize(cfg, result)
	}

	targets := discovery.HostTargets(discoveredHosts)
	baseXML, err := runner.RunBaseScan(targets, profile)
	if err != nil {
		return err
	}
	artifacts.BaseXMLPath = baseXML
	baseHosts, err := parser.ParseFile(baseXML)
	if err != nil {
		return err
	}
	merged := parser.MergeHosts(discoveredHosts, baseHosts)

	if shouldRunExtended(profile) {
		extendedXML, err := runner.RunExtendedScan(targets, profile)
		if err != nil {
			return err
		}
		artifacts.ExtendedXMLPath = extendedXML
		extendedHosts, err := parser.ParseFile(extendedXML)
		if err != nil {
			return err
		}
		merged = parser.MergeHosts(merged, extendedHosts)
	}

	classified := scoring.ClassifyHosts(merged, cfg.OpenPortsThreshold, profile.Name)
	result := models.ScanResult{
		GeneratedAt: time.Now(),
		Profile:     profile,
		Subnets:     cfg.Subnets,
		Hosts:       classified,
		Summary:     scoring.BuildSummary(classified),
		Artifacts:   artifacts,
	}
	return finalize(cfg, result)
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
