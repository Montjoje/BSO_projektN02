package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Montjoje/BSO_projektN02/internal/models"
)

func LoadConfig(path string) (models.Config, error) {
	data, err := parseSimpleYAML(path)
	if err != nil {
		return models.Config{}, err
	}

	cfg := models.Config{
		Subnets:                data.List("subnets"),
		Profile:                data.StringDefault("profile", "baseline"),
		WorkDir:                data.StringDefault("work_dir", "./data"),
		BaseTimeoutSeconds:     data.IntDefault("base_timeout_seconds", 120),
		ExtendedTimeoutSeconds: data.IntDefault("extended_timeout_seconds", 300),
		SMTPHost:               data.String("smtp_host"),
		SMTPPort:               data.IntDefault("smtp_port", 587),
		SMTPUser:               data.String("smtp_user"),
		SMTPPassword:           data.String("smtp_password"),
		SMTPFrom:               data.String("smtp_from"),
		SMTPTo:                 data.String("smtp_to"),
		SubjectPrefix:          data.StringDefault("subject_prefix", "[BSO N02]"),
	}

	applyEnvOverrides(&cfg)

	if len(cfg.Subnets) == 0 {
		return models.Config{}, fmt.Errorf("brak subnetów w konfiguracji")
	}
	if cfg.SMTPHost == "" || cfg.SMTPFrom == "" || cfg.SMTPTo == "" {
		return models.Config{}, fmt.Errorf("brak wymaganych ustawień SMTP")
	}
	return cfg, nil
}

func LoadProfile(dir, name string) (models.Profile, error) {
	path := filepath.Join(dir, name+".yaml")
	data, err := parseSimpleYAML(path)
	if err != nil {
		return models.Profile{}, err
	}
	return models.Profile{
		Name:       data.StringDefault("name", name),
		Extended:   data.BoolDefault("extended", false),
		NmapArgs:   data.List("nmap_args"),
		NSEScripts: data.List("nse_scripts"),
	}, nil
}

type simpleData struct {
	scalars map[string]string
	lists   map[string][]string
}

func (d simpleData) String(key string) string             { return d.scalars[key] }
func (d simpleData) StringDefault(key, def string) string { if v := d.scalars[key]; v != "" { return v }; return def }
func (d simpleData) List(key string) []string             { return append([]string(nil), d.lists[key]...) }
func (d simpleData) BoolDefault(key string, def bool) bool {
	if v, ok := d.scalars[key]; ok {
		return strings.EqualFold(v, "true")
	}
	return def
}
func (d simpleData) IntDefault(key string, def int) int {
	if v, ok := d.scalars[key]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func parseSimpleYAML(path string) (simpleData, error) {
	f, err := os.Open(path)
	if err != nil {
		return simpleData{}, err
	}
	defer f.Close()

	out := simpleData{scalars: map[string]string{}, lists: map[string][]string{}}
	var currentList string

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "- ") && currentList != "" {
			out.lists[currentList] = append(out.lists[currentList], strings.TrimSpace(strings.TrimPrefix(line, "- ")))
			continue
		}
		currentList = ""
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"`)
		if val == "" {
			currentList = key
			out.lists[key] = out.lists[key]
			continue
		}
		out.scalars[key] = val
	}
	return out, s.Err()
}

func applyEnvOverrides(cfg *models.Config) {
	if v := os.Getenv("BSO_SUBNETS"); v != "" {
		parts := strings.Split(v, ",")
		subnets := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				subnets = append(subnets, p)
			}
		}
		if len(subnets) > 0 {
			cfg.Subnets = subnets
		}
	}
	overrideString(&cfg.Profile, "BSO_PROFILE")
	overrideString(&cfg.WorkDir, "BSO_WORK_DIR")
	overrideInt(&cfg.BaseTimeoutSeconds, "BSO_BASE_TIMEOUT_SECONDS")
	overrideInt(&cfg.ExtendedTimeoutSeconds, "BSO_EXTENDED_TIMEOUT_SECONDS")
	overrideString(&cfg.SMTPHost, "BSO_SMTP_HOST")
	overrideInt(&cfg.SMTPPort, "BSO_SMTP_PORT")
	overrideString(&cfg.SMTPUser, "BSO_SMTP_USER")
	overrideString(&cfg.SMTPPassword, "BSO_SMTP_PASSWORD")
	overrideString(&cfg.SMTPFrom, "BSO_SMTP_FROM")
	overrideString(&cfg.SMTPTo, "BSO_SMTP_TO")
	overrideString(&cfg.SubjectPrefix, "BSO_SUBJECT_PREFIX")
}

func overrideString(dst *string, envKey string) {
	if v := os.Getenv(envKey); v != "" {
		*dst = v
	}
}

func overrideInt(dst *int, envKey string) {
	if v := os.Getenv(envKey); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*dst = n
		}
	}
}
