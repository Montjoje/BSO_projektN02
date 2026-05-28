package models

import "time"

// AppConfig is the normalized runtime configuration used by all modules.
type AppConfig struct {
	Subnets            []string
	ProfileName        string
	ConfigPath         string
	ProfileDir         string
	OutputDir          string
	ScanDir            string
	ReportDir          string
	StateDir           string
	BaseTimeoutSeconds int
	OpenPortsThreshold int
	Mail               MailConfig
	Runtime            RuntimeConfig
}

type RuntimeConfig struct {
	DryRun       bool
	NoEmail      bool
	KeepXML      bool
	NmapPath     string
	RunMode      string
	IntervalMins int
}

type MailConfig struct {
	Enabled    bool
	SMTPHost   string
	SMTPPort   int
	Sender     string
	Password   string
	Recipient  string
	Subject    string
	UseTLS     bool
	SkipVerify bool
}

type ScanProfile struct {
	Name            string
	Mode            string
	Description     string
	BaseArgs        []string
	BaseScripts     []string
	ExtendedArgs    []string
	ExtendedScripts []string
	AllowIntrusive  bool
}

type Host struct {
	IP                string    `json:"ip"`
	MAC               string    `json:"mac,omitempty"`
	Hostname          string    `json:"hostname,omitempty"`
	Vendor            string    `json:"vendor,omitempty"`
	State             string    `json:"state"`
	Services          []Service `json:"services"`
	HostScripts       []Script  `json:"host_scripts,omitempty"`
	Findings          []Finding `json:"findings"`
	RiskScore         int       `json:"risk_score"`
	RiskLevel         string    `json:"risk_level"`
	ScanProfile       string    `json:"scan_profile"`
	AssessmentStatus  string    `json:"assessment_status"`
	AssessmentMessage string    `json:"assessment_message,omitempty"`
}

type Service struct {
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	State    string   `json:"state"`
	Name     string   `json:"name,omitempty"`
	Product  string   `json:"product,omitempty"`
	Version  string   `json:"version,omitempty"`
	Extra    string   `json:"extra,omitempty"`
	Tunnel   string   `json:"tunnel,omitempty"`
	CPEs     []string `json:"cpes,omitempty"`
	Scripts  []Script `json:"scripts,omitempty"`
}

type Script struct {
	ID     string `json:"id"`
	Output string `json:"output"`
}

type Finding struct {
	Severity       string `json:"severity"`
	Score          int    `json:"score"`
	Title          string `json:"title"`
	Evidence       string `json:"evidence"`
	Recommendation string `json:"recommendation"`
	Port           int    `json:"port,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	Service        string `json:"service,omitempty"`
}

type ScanArtifacts struct {
	StartedAt        time.Time
	FinishedAt       time.Time
	DiscoveryXMLPath string
	BaseXMLPath      string
	ExtendedXMLPath  string
	JSONPath         string
	HTMLPath         string
	TextPath         string
}

type ScanResult struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Profile     ScanProfile   `json:"profile"`
	Subnets     []string      `json:"subnets"`
	Hosts       []Host        `json:"hosts"`
	Summary     ResultSummary `json:"summary"`
	Warnings    []string      `json:"warnings,omitempty"`
	Artifacts   ScanArtifacts `json:"-"`
}

type ResultSummary struct {
	HostCount        int `json:"host_count"`
	OpenPortCount    int `json:"open_port_count"`
	FindingCount     int `json:"finding_count"`
	HighRiskHosts    int `json:"high_risk_hosts"`
	MediumRiskHosts  int `json:"medium_risk_hosts"`
	LowRiskHosts     int `json:"low_risk_hosts"`
	UnknownRiskHosts int `json:"unknown_risk_hosts"`
}
