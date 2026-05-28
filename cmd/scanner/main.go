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
	start := time.Now()

	cfgPath := flag.String("config", "./configs/config.example.yaml", "ścieżka do pliku konfiguracyjnego")
	profilesDir := flag.String("profiles", "./profiles", "katalog profili")
	flag.Parse()

	fmt.Println("[STEP 1/8] Wczytywanie konfiguracji")
	cfg, err := config.LoadConfig(*cfgPath)
	fatalIf(err)

	fmt.Println("[STEP 2/8] Wczytywanie profilu skanowania")
	profile, err := config.LoadProfile(*profilesDir, cfg.Profile)
	fatalIf(err)

	ensureDirs(cfg.WorkDir)

	fmt.Printf("[INFO] Profil: %s\n", profile.Name)
	fmt.Printf("[INFO] Subnety: %v\n", cfg.Subnets)
	fmt.Printf("[INFO] Work dir: %s\n", cfg.WorkDir)
	fmt.Printf("[INFO] Base timeout: %d s\n", cfg.BaseTimeoutSeconds)
	fmt.Printf("[INFO] Extended timeout: %d s\n", cfg.ExtendedTimeoutSeconds)

	fmt.Println("[STEP 3/8] Discovery hostów")
	targets, err := discovery.Discover(cfg.Subnets, time.Duration(cfg.BaseTimeoutSeconds)*time.Second)
	fatalIf(err)

	fmt.Printf("[INFO] Wykryte hosty: %d\n", len(targets))
	for _, target := range targets {
		fmt.Printf("[INFO] Host: %s\n", target)
	}

	if len(targets) == 0 {
		fmt.Println("[STEP 4/8] Brak hostów, budowanie pustego raportu")
		rep, err := reporting.Build(nil, cfg, profile)
		fatalIf(err)

		fmt.Println("[STEP 5/8] Zapis raportu")
		fatalIf(reporting.Write(rep, cfg.WorkDir))

		fmt.Println("[STEP 6/8] Wysyłka raportu e-mail")
		fatalIf(mailer.Send(cfg, rep))

		fmt.Printf("[INFO] Koniec pracy, czas całkowity: %s\n", time.Since(start).Round(time.Second))
		return
	}

	fmt.Println("[STEP 4/8] Skan bazowy")
	baseXML, _, err := scanner.RunBaseScan(
		targets,
		profile,
		filepath.Join(cfg.WorkDir, "scans"),
		time.Duration(cfg.BaseTimeoutSeconds)*time.Second,
	)
	fatalIf(err)

	fmt.Println("[STEP 5/8] Parsowanie wyników bazowych")
	baseParsed, err := parser.ParseNmapXML(baseXML)
	fatalIf(err)

	merged := baseParsed

	if profile.Extended {
		fmt.Println("[STEP 6/8] Skan rozszerzony")
		extXML, _, err := scanner.RunExtendedScan(
			targets,
			profile,
			filepath.Join(cfg.WorkDir, "scans"),
			time.Duration(cfg.ExtendedTimeoutSeconds)*time.Second,
		)
		fatalIf(err)

		fmt.Println("[STEP 7/8] Parsowanie i scalanie wyników rozszerzonych")
		extParsed, err := parser.ParseNmapXML(extXML)
		fatalIf(err)

		merged = parser.Merge(baseParsed, extParsed)
	} else {
		fmt.Println("[STEP 6/8] Profil nie wymaga skanu rozszerzonego")
	}

	fmt.Println("[STEP 7/8] Ocena ryzyka")
	hosts := scoring.Score(merged)

	fmt.Println("[STEP 8/8] Budowanie, zapis i wysyłka raportu")
	rep, err := reporting.Build(hosts, cfg, profile)
	fatalIf(err)

	fatalIf(reporting.Write(rep, cfg.WorkDir))
	fatalIf(mailer.Send(cfg, rep))

	fmt.Printf("[INFO] Zakończono skanowanie, hostów: %d\n", len(hosts))
	fmt.Printf("[INFO] Czas całkowity: %s\n", time.Since(start).Round(time.Second))
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