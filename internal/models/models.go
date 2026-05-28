package models

type Config struct {
	Subnets                []string
	Profile                string
	WorkDir                string
	BaseTimeoutSeconds     int
	ExtendedTimeoutSeconds int
	SMTPHost               string
	SMTPPort               int
	SMTPUser               string
	SMTPPassword           string
	SMTPFrom               string
	SMTPTo                 string
	SubjectPrefix          string
}

type Profile struct {
	Name       string
	Extended   bool
	NmapArgs   []string
	NSEScripts []string
}

type Port struct {
	Port     int
	Protocol string
	State    string
	Service  string
	Product  string
	Version  string
}

type Host struct {
	Address  string
	Hostname string
	Ports    []Port
	Scripts  []string
	Findings []string
	Risk     string
	Points   int
}

type Report struct {
	GeneratedAt string
	Profile     string
	Subnets     string
	HostCount   int
	Hosts       []Host
	Subject     string
	TextBody    string
	HTMLBody    string
}
