package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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

	// Pokazuje okresowe statystyki działania Nmapa.
	if !hasArg(cmdArgs, "--stats-every") {
		cmdArgs = append([]string{"--stats-every", "10s", "-v"}, cmdArgs...)
	}

	if len(scripts) > 0 {
		cmdArgs = append(cmdArgs, "--script", strings.Join(scripts, ","))
	}

	cmdArgs = append(cmdArgs, "-oX", outfile)
	cmdArgs = append(cmdArgs, targets...)

	fmt.Printf("[INFO] Start skanu Nmap: %s\n", prefix)
	fmt.Printf("[INFO] Timeout: %s\n", timeout)
	fmt.Printf("[INFO] Wynik XML: %s\n", outfile)
	fmt.Printf("[INFO] Komenda: nmap %s\n", strings.Join(cmdArgs, " "))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nmap", cmdArgs...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, outfile, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, outfile, err
	}

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer

	if err := cmd.Start(); err != nil {
		return nil, outfile, err
	}

	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(2)

	go streamLines(prefix, stdout, os.Stdout, &stdoutBuf, &wg)
	go streamLines(prefix, stderr, os.Stderr, &stderrBuf, &wg)

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case err := <-done:
			wg.Wait()
			elapsed := time.Since(start).Round(time.Second)

			if ctx.Err() == context.DeadlineExceeded {
				return nil, outfile, fmt.Errorf("nmap %s przekroczył timeout po %s", prefix, elapsed)
			}

			if err != nil {
				return nil, outfile, fmt.Errorf("nmap %s zakończony błędem po %s: %w\nstdout:\n%s\nstderr:\n%s",
					prefix, elapsed, err, stdoutBuf.String(), stderrBuf.String())
			}

			fmt.Printf("[INFO] Koniec skanu Nmap: %s, czas: %s\n", prefix, elapsed)

			xmlBytes, err := os.ReadFile(outfile)
			if err != nil {
				return nil, outfile, err
			}

			return xmlBytes, outfile, nil

		case <-ticker.C:
			elapsed := time.Since(start).Round(time.Second)
			fmt.Printf("[INFO] Skan %s nadal trwa, czas od startu: %s\n", prefix, elapsed)
		}
	}
}

func streamLines(prefix string, r io.Reader, w io.Writer, capture *bytes.Buffer, wg *sync.WaitGroup) {
	defer wg.Done()

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		fmt.Fprintf(w, "[NMAP:%s] %s\n", prefix, line)
		capture.WriteString(line)
		capture.WriteByte('\n')
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(w, "[WARN] Problem przy czytaniu wyjścia Nmapa (%s): %v\n", prefix, err)
	}
}

func hasArg(args []string, wanted string) bool {
	for _, arg := range args {
		if arg == wanted {
			return true
		}
	}
	return false
}