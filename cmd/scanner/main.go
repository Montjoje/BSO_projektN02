package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Montjoje/BSO_projektN02/internal/config"
	"github.com/Montjoje/BSO_projektN02/internal/discovery"
	"github.com/Montjoje/BSO_projektN02/internal/mailer"
	"github.com/Montjoje/BSO_projektN02/internal/parser"
	"github.com/Montjoje/BSO_projektN02/internal/reporting"
	"github.com/Montjoje/BSO_projektN02/internal/scanner"
	"github.com/Montjoje/BSO_projektN02/internal/scoring"
)

func main() {
	cfgPath := flag.String("config", "./configs/config.example.yaml", "ścieżka do pliku konfiguracyjnego")
	profilesDir := flag.String("profiles", "./profiles", "katalog profili")
	flag.Parse()

	cfg, err := config.LoadConfig(*cfgPath)
	fatalIf(err)
	profile, err := config.LoadProfile(*profilesDir, cfg.Profile)
	fatalIf(err)

	ensureDirs(cfg.WorkDir)
	fmt.Printf("[INFO] profil=%s subnets=%v\n", profile.Name, cfg.Subnets)

	targets, err := discovery.Discover(cfg.Subnets, time.Duration(cfg.BaseTimeoutSeconds)*time.Second)
	fatalIf(err)
	if len(targets) == 0 {
		rep, err := reporting.Build(nil, cfg, profile)
		fatalIf(err)
		fatalIf(reporting.Write(rep, cfg.WorkDir))
		fatalIf(mailer.Send(cfg, rep))
		fmt.Println("[INFO] brak hostów, wysłano pusty raport")
		return
	}

	baseXML, _, err := scanner.RunBaseScan(targets, profile, filepath.Join(cfg.WorkDir, "scans"), time.Duration(cfg.BaseTimeoutSeconds)*time.Second)
	fatalIf(err)
	baseParsed, err := parser.ParseNmapXML(baseXML)
	fatalIf(err)

	merged := baseParsed
	if profile.Extended {
		extXML, _, err := scanner.RunExtendedScan(targets, profile, filepath.Join(cfg.WorkDir, "scans"), time.Duration(cfg.ExtendedTimeoutSeconds)*time.Second)
		fatalIf(err)
		extParsed, err := parser.ParseNmapXML(extXML)
		fatalIf(err)
		merged = parser.Merge(baseParsed, extParsed)
	}

	hosts := scoring.Score(merged)
	rep, err := reporting.Build(hosts, cfg, profile)
	fatalIf(err)
	fatalIf(reporting.Write(rep, cfg.WorkDir))
	fatalIf(mailer.Send(cfg, rep))
	fmt.Printf("[INFO] zakończono skanowanie, hostów=%d\n", len(hosts))
}

func ensureDirs(workDir string) {
	for _, d := range []string{"scans", "reports", "state"} {
		_ = os.MkdirAll(filepath.Join(workDir, d), 0o755)
	}
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		os.Exit(1)
	}
}
