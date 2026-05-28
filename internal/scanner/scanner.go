package scanner

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Montjoje/BSO_projektN02/internal/models"
)

type NmapRunner struct {
	NmapPath       string
	OutputDir      string
	TimeoutSeconds int
	DryRun         bool
}

func NewNmapRunner(cfg models.AppConfig) *NmapRunner {
	return &NmapRunner{
		NmapPath:       cfg.Runtime.NmapPath,
		OutputDir:      cfg.ScanDir,
		TimeoutSeconds: cfg.BaseTimeoutSeconds,
		DryRun:         cfg.Runtime.DryRun,
	}
}

func (r *NmapRunner) RunDiscovery(subnets []string) (string, error) {
	path := filepath.Join(r.OutputDir, timestamped("discovery", "xml"))
	args := []string{"-sn", "--max-retries", "1", "--host-timeout", r.timeoutArg(), "-oX", path}
	args = append(args, subnets...)
	if r.DryRun {
		return path, writeDryRunDiscovery(path)
	}
	return path, r.run(args)
}

func (r *NmapRunner) RunBaseScan(targets []string, profile models.ScanProfile) (string, error) {
	path := filepath.Join(r.OutputDir, timestamped("base-"+safeName(profile.Name), "xml"))
	args := make([]string, 0, len(profile.BaseArgs)+len(targets)+8)
	args = append(args, profile.BaseArgs...)
	if len(profile.BaseScripts) > 0 {
		args = append(args, "--script", strings.Join(profile.BaseScripts, ","))
	}
	args = appendHostTimeout(args, r.timeoutArg())
	args = append(args, "-oX", path)
	args = append(args, targets...)
	if r.DryRun {
		return path, writeDryRunBase(path)
	}
	return path, r.run(args)
}

func (r *NmapRunner) RunExtendedScan(targets []string, profile models.ScanProfile) (string, error) {
	path := filepath.Join(r.OutputDir, timestamped("extended-"+safeName(profile.Name), "xml"))
	args := make([]string, 0, len(profile.ExtendedArgs)+len(targets)+8)
	args = append(args, profile.ExtendedArgs...)
	if len(profile.ExtendedScripts) > 0 {
		args = append(args, "--script", strings.Join(profile.ExtendedScripts, ","))
	}
	args = appendHostTimeout(args, r.timeoutArg())
	args = append(args, "-oX", path)
	args = append(args, targets...)
	if r.DryRun {
		return path, writeDryRunExtended(path)
	}
	return path, r.run(args)
}

func (r *NmapRunner) run(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.TimeoutSeconds)*time.Second)
	defer cancel()
	log.Printf("uruchamiam: %s %s", r.NmapPath, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, r.NmapPath, args...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("nmap przekroczył limit czasu %ds", r.TimeoutSeconds)
	}
	if err != nil {
		return fmt.Errorf("nmap zakończył się błędem: %w; wyjście: %s", err, strings.TrimSpace(string(output)))
	}
	if len(output) > 0 {
		log.Printf("nmap: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func (r *NmapRunner) timeoutArg() string {
	if r.TimeoutSeconds <= 0 {
		return "300s"
	}
	return fmt.Sprintf("%ds", r.TimeoutSeconds)
}

func appendHostTimeout(args []string, timeout string) []string {
	for _, a := range args {
		if a == "--host-timeout" {
			return args
		}
	}
	return append(args, "--host-timeout", timeout)
}

func timestamped(prefix, ext string) string {
	return fmt.Sprintf("%s-%d.%s", prefix, time.Now().UnixNano(), ext)
}

func safeName(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	if b.Len() == 0 {
		return "profile"
	}
	return b.String()
}

func writeDryRunDiscovery(path string) error {
	return os.WriteFile(path, []byte(`<?xml version="1.0"?>
<nmaprun scanner="nmap" args="dry-run discovery">
  <host><status state="up" reason="user-set"/><address addr="192.168.88.1" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:01" addrtype="mac" vendor="MikroTik"/><hostnames><hostname name="router.lan" type="PTR"/></hostnames></host>
  <host><status state="up" reason="user-set"/><address addr="192.168.88.15" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:15" addrtype="mac" vendor="Generic IoT"/><hostnames><hostname name="kamera-garaz" type="PTR"/></hostnames></host>
</nmaprun>`), 0o640)
}

func writeDryRunBase(path string) error {
	return os.WriteFile(path, []byte(`<?xml version="1.0"?>
<nmaprun scanner="nmap" args="dry-run base">
  <host>
    <status state="up" reason="user-set"/>
    <address addr="192.168.88.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:01" addrtype="mac" vendor="MikroTik"/>
    <hostnames><hostname name="router.lan" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="RouterOS http config" version="7.x"/></port>
      <port protocol="tcp" portid="8291"><state state="open"/><service name="winbox" product="MikroTik WinBox" version="7.x"/></port>
    </ports>
  </host>
  <host>
    <status state="up" reason="user-set"/>
    <address addr="192.168.88.15" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:15" addrtype="mac" vendor="Generic IoT"/>
    <hostnames><hostname name="kamera-garaz" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="GoAhead-Webs" version="2.5"/></port>
      <port protocol="tcp" portid="554"><state state="open"/><service name="rtsp" product="IP camera RTSP"/></port>
      <port protocol="tcp" portid="23"><state state="open"/><service name="telnet" product="BusyBox telnetd"/></port>
    </ports>
  </host>
</nmaprun>`), 0o640)
}

func writeDryRunExtended(path string) error {
	return os.WriteFile(path, []byte(`<?xml version="1.0"?>
<nmaprun scanner="nmap" args="dry-run extended">
  <host>
    <status state="up" reason="user-set"/>
    <address addr="192.168.88.15" addrtype="ipv4"/>
    <hostnames><hostname name="kamera-garaz" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="GoAhead-Webs" version="2.5"/>
        <script id="http-title" output="IP Camera administration panel"/>
        <script id="http-auth" output="HTTP Basic authentication realm=admin"/>
        <script id="http-vuln-cve2017-8225" output="VULNERABLE: GoAhead IP camera information disclosure CVE-2017-8225"/>
      </port>
      <port protocol="tcp" portid="23"><state state="open"/><service name="telnet" product="BusyBox telnetd"/>
        <script id="banner" output="BusyBox v1.19 telnetd"/>
      </port>
    </ports>
  </host>
</nmaprun>`), 0o640)
}
