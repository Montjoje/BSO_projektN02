package discovery

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/Montjoje/BSO_projektN02/internal/parser"
)

func Discover(subnets []string, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := []string{"-sn", "-n", "-oX", "-"}
	args = append(args, subnets...)
	cmd := exec.CommandContext(ctx, "nmap", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("discovery nmap: %w", err)
	}

	res, err := parser.ParseNmapXML(out)
	if err != nil {
		return nil, err
	}

	ips := make([]string, 0, len(res.Hosts))
	seen := map[string]bool{}
	for _, h := range res.Hosts {
		ip := strings.TrimSpace(h.Address)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		ips = append(ips, ip)
	}
	return ips, nil
}
