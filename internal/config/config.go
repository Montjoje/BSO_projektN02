package config

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Montjoje/BSO_projektN02/internal/models"
)

func Load(configPath, profileOverride string) (models.AppConfig, models.ScanProfile, error) {
	cfg := defaultConfig()
	cfg.ConfigPath = configPath
	if configPath != "" {
		if err := overlayConfigFile(&cfg, configPath); err != nil {
			return cfg, models.ScanProfile{}, err
		}
	}
	overlayEnv(&cfg)
	if profileOverride != "" {
		cfg.ProfileName = profileOverride
	}
	if cfg.ProfileName == "" {
		cfg.ProfileName = "baseline"
	}
	if err := validateAndPrepare(&cfg); err != nil {
		return cfg, models.ScanProfile{}, err
	}
	profilePath := filepath.Join(cfg.ProfileDir, cfg.ProfileName+".yaml")
	profile, err := LoadProfile(profilePath)
	if err != nil {
		return cfg, models.ScanProfile{}, err
	}
	if profile.Name == "" {
		profile.Name = cfg.ProfileName
	}
	return cfg, profile, nil
}

func defaultConfig() models.AppConfig {
	return models.AppConfig{
		Subnets:            []string{"192.168.88.0/24"},
		ProfileName:        "baseline",
		ProfileDir:         "profiles",
		OutputDir:          "data",
		BaseTimeoutSeconds: 300,
		OpenPortsThreshold: 8,
		Mail: models.MailConfig{
			Enabled:   false,
			SMTPPort:  587,
			Subject:   "BSO N02 - raport skanowania sieci LAN",
			UseTLS:    true,
			Recipient: "",
		},
		Runtime: models.RuntimeConfig{
			DryRun:       false,
			NoEmail:      false,
			KeepXML:      true,
			NmapPath:     "nmap",
			RunMode:      "once",
			IntervalMins: 1440,
		},
	}
}

func overlayConfigFile(cfg *models.AppConfig, path string) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("plik konfiguracji %q nie istnieje", path)
		}
		return err
	}
	defer f.Close()

	section := ""
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := stripComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(trimmed, "-") {
			section = ""
		}
		if strings.HasSuffix(trimmed, ":") && !strings.HasPrefix(trimmed, "-") {
			section = strings.TrimSuffix(trimmed, ":")
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			switch section {
			case "subnets":
				cfg.Subnets = appendIfMissing(cfg.Subnets, cleanScalar(value))
			default:
				return fmt.Errorf("nieobsługiwana lista w sekcji %q, linia %d", section, lineNo)
			}
			continue
		}
		key, value, ok := splitKeyValue(trimmed)
		if !ok {
			return fmt.Errorf("niepoprawna linia konfiguracji %d: %q", lineNo, raw)
		}
		value = cleanScalar(value)
		switch section {
		case "":
			applyTopLevel(cfg, key, value)
		case "mail":
			applyMail(&cfg.Mail, key, value)
		case "runtime":
			applyRuntime(&cfg.Runtime, key, value)
		default:
			return fmt.Errorf("nieznana sekcja konfiguracji %q, linia %d", section, lineNo)
		}
	}
	return scanner.Err()
}

func LoadProfile(path string) (models.ScanProfile, error) {
	profile := models.ScanProfile{}
	f, err := os.Open(path)
	if err != nil {
		return profile, fmt.Errorf("nie można otworzyć profilu %q: %w", path, err)
	}
	defer f.Close()

	section := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := stripComment(scanner.Text())
		if strings.TrimSpace(line) == "" {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasSuffix(trimmed, ":") && !strings.HasPrefix(trimmed, "-") {
			section = strings.TrimSuffix(trimmed, ":")
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			value := cleanScalar(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
			switch section {
			case "base_args":
				profile.BaseArgs = append(profile.BaseArgs, value)
			case "base_scripts":
				profile.BaseScripts = append(profile.BaseScripts, value)
			case "extended_args":
				profile.ExtendedArgs = append(profile.ExtendedArgs, value)
			case "extended_scripts":
				profile.ExtendedScripts = append(profile.ExtendedScripts, value)
			default:
				return profile, fmt.Errorf("nieobsługiwana lista w profilu: %q", section)
			}
			continue
		}
		key, value, ok := splitKeyValue(trimmed)
		if !ok {
			return profile, fmt.Errorf("niepoprawna linia profilu: %q", trimmed)
		}
		value = cleanScalar(value)
		switch key {
		case "name":
			profile.Name = value
		case "mode":
			profile.Mode = strings.ToUpper(value)
		case "description":
			profile.Description = value
		case "allow_intrusive":
			profile.AllowIntrusive = parseBool(value)
		}
	}
	if err := scanner.Err(); err != nil {
		return profile, err
	}
	if profile.Name == "" {
		profile.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	if profile.Mode == "" {
		profile.Mode = strings.ToUpper(profile.Name)
	}
	if err := validateProfile(profile); err != nil {
		return profile, err
	}
	return profile, nil
}

func validateProfile(profile models.ScanProfile) error {
	switch strings.ToUpper(profile.Mode) {
	case "BASELINE", "DIAGNOSTIC", "DEEP", "PENTEST":
		return nil
	default:
		return fmt.Errorf("profil %q ma nieobsługiwany tryb %q", profile.Name, profile.Mode)
	}
}

func validateAndPrepare(cfg *models.AppConfig) error {
	if len(cfg.Subnets) == 0 {
		return errors.New("brak podsieci do skanowania")
	}
	for _, subnet := range cfg.Subnets {
		if ip := net.ParseIP(subnet); ip != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(subnet); err != nil {
			return fmt.Errorf("niepoprawna podsieć lub adres IP %q: %w", subnet, err)
		}
	}
	if cfg.ProfileDir == "" {
		cfg.ProfileDir = "profiles"
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = "data"
	}
	cfg.ScanDir = filepath.Join(cfg.OutputDir, "scans")
	cfg.ReportDir = filepath.Join(cfg.OutputDir, "reports")
	cfg.StateDir = filepath.Join(cfg.OutputDir, "state")
	for _, dir := range []string{cfg.OutputDir, cfg.ScanDir, cfg.ReportDir, cfg.StateDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("nie można utworzyć katalogu %q: %w", dir, err)
		}
	}
	if cfg.BaseTimeoutSeconds <= 0 {
		cfg.BaseTimeoutSeconds = 300
	}
	if cfg.OpenPortsThreshold <= 0 {
		cfg.OpenPortsThreshold = 8
	}
	if cfg.Runtime.NmapPath == "" {
		cfg.Runtime.NmapPath = "nmap"
	}
	if cfg.Mail.Enabled && !cfg.Runtime.NoEmail {
		if cfg.Mail.SMTPHost == "" || cfg.Mail.Sender == "" || cfg.Mail.Password == "" || cfg.Mail.Recipient == "" {
			return errors.New("mail.enabled=true, ale brakuje SMTP host/sender/password/recipient")
		}
		if cfg.Mail.SMTPPort == 0 {
			cfg.Mail.SMTPPort = 587
		}
	}
	return nil
}

func applyTopLevel(cfg *models.AppConfig, key, value string) {
	switch key {
	case "profile":
		cfg.ProfileName = value
	case "profile_dir":
		cfg.ProfileDir = value
	case "output_dir":
		cfg.OutputDir = value
	case "base_timeout_seconds":
		cfg.BaseTimeoutSeconds = parseInt(value, cfg.BaseTimeoutSeconds)
	case "open_ports_threshold":
		cfg.OpenPortsThreshold = parseInt(value, cfg.OpenPortsThreshold)
	case "subnets":
		cfg.Subnets = parseCSV(value)
	}
}

func applyMail(mail *models.MailConfig, key, value string) {
	switch key {
	case "enabled":
		mail.Enabled = parseBool(value)
	case "smtp_host":
		mail.SMTPHost = value
	case "smtp_port":
		mail.SMTPPort = parseInt(value, mail.SMTPPort)
	case "sender":
		mail.Sender = value
	case "password":
		mail.Password = value
	case "recipient":
		mail.Recipient = value
	case "subject":
		mail.Subject = value
	case "use_tls":
		mail.UseTLS = parseBool(value)
	case "skip_verify":
		mail.SkipVerify = parseBool(value)
	}
}

func applyRuntime(rt *models.RuntimeConfig, key, value string) {
	switch key {
	case "dry_run":
		rt.DryRun = parseBool(value)
	case "no_email":
		rt.NoEmail = parseBool(value)
	case "keep_xml":
		rt.KeepXML = parseBool(value)
	case "nmap_path":
		rt.NmapPath = value
	case "run_mode":
		rt.RunMode = value
	case "interval_minutes":
		rt.IntervalMins = parseInt(value, rt.IntervalMins)
	}
}

func overlayEnv(cfg *models.AppConfig) {
	if v := os.Getenv("BSO_SUBNETS"); v != "" {
		cfg.Subnets = parseCSV(v)
	}
	if v := os.Getenv("BSO_PROFILE"); v != "" {
		cfg.ProfileName = v
	}
	if v := os.Getenv("BSO_PROFILE_DIR"); v != "" {
		cfg.ProfileDir = v
	}
	if v := os.Getenv("BSO_OUTPUT_DIR"); v != "" {
		cfg.OutputDir = v
	}
	if v := os.Getenv("BSO_BASE_TIMEOUT_SECONDS"); v != "" {
		cfg.BaseTimeoutSeconds = parseInt(v, cfg.BaseTimeoutSeconds)
	}
	if v := os.Getenv("BSO_OPEN_PORTS_THRESHOLD"); v != "" {
		cfg.OpenPortsThreshold = parseInt(v, cfg.OpenPortsThreshold)
	}
	if v := os.Getenv("BSO_DRY_RUN"); v != "" {
		cfg.Runtime.DryRun = parseBool(v)
	}
	if v := os.Getenv("BSO_NO_EMAIL"); v != "" {
		cfg.Runtime.NoEmail = parseBool(v)
	}
	if v := os.Getenv("BSO_NMAP_PATH"); v != "" {
		cfg.Runtime.NmapPath = v
	}
	if v := os.Getenv("BSO_RUN_MODE"); v != "" {
		cfg.Runtime.RunMode = v
	}
	if v := os.Getenv("BSO_INTERVAL_MINUTES"); v != "" {
		cfg.Runtime.IntervalMins = parseInt(v, cfg.Runtime.IntervalMins)
	}
	if v := os.Getenv("BSO_SMTP_HOST"); v != "" {
		cfg.Mail.SMTPHost = v
		cfg.Mail.Enabled = true
	}
	if v := os.Getenv("BSO_SMTP_PORT"); v != "" {
		cfg.Mail.SMTPPort = parseInt(v, cfg.Mail.SMTPPort)
	}
	if v := os.Getenv("BSO_SMTP_SENDER"); v != "" {
		cfg.Mail.Sender = v
	}
	if v := os.Getenv("BSO_SMTP_PASSWORD"); v != "" {
		cfg.Mail.Password = v
	}
	if v := os.Getenv("BSO_SMTP_RECIPIENT"); v != "" {
		cfg.Mail.Recipient = v
	}
	if v := os.Getenv("BSO_MAIL_SUBJECT"); v != "" {
		cfg.Mail.Subject = v
	}
}

func splitKeyValue(line string) (string, string, bool) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]), true
}

func stripComment(line string) string {
	inSingle := false
	inDouble := false
	for i, r := range line {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:i]
			}
		}
	}
	return line
}

func cleanScalar(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, "\"")
	v = strings.Trim(v, "'")
	return v
}

func parseCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = cleanScalar(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func appendIfMissing(values []string, value string) []string {
	if value == "" {
		return values
	}
	// Default subnet is replaced by an explicit list in config when the first list item is read.
	if len(values) == 1 && values[0] == "192.168.88.0/24" {
		values = nil
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func parseInt(v string, fallback int) int {
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "y", "tak", "on", "enabled":
		return true
	default:
		return false
	}
}
