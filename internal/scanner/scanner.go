package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Montjoje/BSO_projektN02/internal/models"
)

func RunBaseScan(targets []string, profile models.Profile, outputDir string, timeout time.Duration) ([]byte, string, error) {
	return run("base", targets, profile.NmapArgs, nil, outputDir, timeout)
}

func RunExtendedScan(targets []string, profile models.Profile, outputDir string, timeout time.Duration) ([]byte, string, error) {
	return run("extended", targets, profile.NmapArgs, profile.NSEScripts, outputDir, timeout)
}

func run(prefix string, targets, args, scripts []string, outputDir string, timeout time.Duration) ([]byte, string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, "", err
	}
	outfile := filepath.Join(outputDir, fmt.Sprintf("%s-%d.xml", prefix, time.Now().Unix()))
	cmdArgs := append([]string{}, args...)
	if len(scripts) > 0 {
		cmdArgs = append(cmdArgs, "--script", strings.Join(scripts, ","))
	}
	cmdArgs = append(cmdArgs, "-oX", outfile)
	cmdArgs = append(cmdArgs, targets...)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nmap", cmdArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, outfile, fmt.Errorf("nmap %s: %w: %s", prefix, err, string(out))
	}
	xmlBytes, err := os.ReadFile(outfile)
	if err != nil {
		return nil, outfile, err
	}
	return xmlBytes, outfile, nil
}
