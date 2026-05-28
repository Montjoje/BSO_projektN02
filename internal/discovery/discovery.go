package discovery

import (
	"fmt"
	"log"

	"github.com/Montjoje/BSO_projektN02/internal/models"
	"github.com/Montjoje/BSO_projektN02/internal/parser"
	"github.com/Montjoje/BSO_projektN02/internal/scanner"
)

type Discoverer struct {
	Runner *scanner.NmapRunner
}

func New(runner *scanner.NmapRunner) *Discoverer {
	return &Discoverer{Runner: runner}
}

func (d *Discoverer) Discover(subnets []string) ([]models.Host, string, error) {
	xmlPath, err := d.Runner.RunDiscovery(subnets)
	if err != nil {
		return nil, xmlPath, fmt.Errorf("błąd discovery: %w", err)
	}
	hosts, err := parser.ParseFile(xmlPath)
	if err != nil {
		return nil, xmlPath, fmt.Errorf("błąd parsowania discovery: %w", err)
	}
	log.Printf("discovery: wykryto %d aktywnych hostów", len(hosts))
	return hosts, xmlPath, nil
}

func HostTargets(hosts []models.Host) []string {
	targets := make([]string, 0, len(hosts))
	seen := map[string]bool{}
	for _, h := range hosts {
		if h.IP == "" || seen[h.IP] {
			continue
		}
		seen[h.IP] = true
		targets = append(targets, h.IP)
	}
	return targets
}
