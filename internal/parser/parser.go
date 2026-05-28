package parser

import (
	"encoding/xml"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/Montjoje/BSO_projektN02/internal/models"
)

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status     nmapStatus      `xml:"status"`
	Addresses  []nmapAddress   `xml:"address"`
	Hostnames  []nmapHostname  `xml:"hostnames>hostname"`
	Ports      []nmapPort      `xml:"ports>port"`
	HostScript []nmapXMLScript `xml:"hostscript>script"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPort struct {
	Protocol string          `xml:"protocol,attr"`
	PortID   string          `xml:"portid,attr"`
	State    nmapPortState   `xml:"state"`
	Service  nmapService     `xml:"service"`
	Scripts  []nmapXMLScript `xml:"script"`
}

type nmapPortState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type nmapService struct {
	Name    string   `xml:"name,attr"`
	Product string   `xml:"product,attr"`
	Version string   `xml:"version,attr"`
	Extra   string   `xml:"extrainfo,attr"`
	Tunnel  string   `xml:"tunnel,attr"`
	CPEs    []string `xml:"cpe"`
}

type nmapXMLScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

func ParseFile(path string) ([]models.Host, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("nie można odczytać XML Nmap %q: %w", path, err)
	}
	return Parse(data)
}

func Parse(data []byte) ([]models.Host, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("nie można sparsować XML Nmap: %w", err)
	}
	hosts := make([]models.Host, 0, len(run.Hosts))
	for _, h := range run.Hosts {
		host := models.Host{State: h.Status.State}
		if host.State == "" {
			host.State = "unknown"
		}
		for _, addr := range h.Addresses {
			switch addr.AddrType {
			case "ipv4", "ipv6":
				if host.IP == "" {
					host.IP = addr.Addr
				}
			case "mac":
				host.MAC = addr.Addr
				host.Vendor = addr.Vendor
			}
		}
		if len(h.Hostnames) > 0 {
			host.Hostname = h.Hostnames[0].Name
		}
		for _, s := range h.HostScript {
			host.HostScripts = append(host.HostScripts, models.Script{ID: s.ID, Output: compactWhitespace(s.Output)})
		}
		for _, p := range h.Ports {
			port, _ := strconv.Atoi(p.PortID)
			service := models.Service{
				Port:     port,
				Protocol: p.Protocol,
				State:    p.State.State,
				Name:     p.Service.Name,
				Product:  p.Service.Product,
				Version:  p.Service.Version,
				Extra:    p.Service.Extra,
				Tunnel:   p.Service.Tunnel,
				CPEs:     trimStrings(p.Service.CPEs),
			}
			for _, script := range p.Scripts {
				service.Scripts = append(service.Scripts, models.Script{ID: script.ID, Output: compactWhitespace(script.Output)})
			}
			host.Services = append(host.Services, service)
		}
		sort.Slice(host.Services, func(i, j int) bool {
			if host.Services[i].Protocol == host.Services[j].Protocol {
				return host.Services[i].Port < host.Services[j].Port
			}
			return host.Services[i].Protocol < host.Services[j].Protocol
		})
		if host.IP != "" {
			hosts = append(hosts, host)
		}
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].IP < hosts[j].IP })
	return hosts, nil
}

func MergeHosts(base, extended []models.Host) []models.Host {
	byIP := make(map[string]*models.Host)
	order := make([]string, 0, len(base)+len(extended))
	upsert := func(h models.Host) {
		if h.IP == "" {
			return
		}
		existing, ok := byIP[h.IP]
		if !ok {
			copyHost := h
			byIP[h.IP] = &copyHost
			order = append(order, h.IP)
			return
		}
		if existing.Hostname == "" {
			existing.Hostname = h.Hostname
		}
		if existing.MAC == "" {
			existing.MAC = h.MAC
		}
		if existing.Vendor == "" {
			existing.Vendor = h.Vendor
		}
		if h.State != "" && h.State != "unknown" {
			existing.State = h.State
		}
		if h.AssessmentStatus != "" {
			existing.AssessmentStatus = h.AssessmentStatus
		}
		if h.AssessmentMessage != "" {
			existing.AssessmentMessage = h.AssessmentMessage
		}
		existing.HostScripts = append(existing.HostScripts, h.HostScripts...)
		mergeServices(existing, h.Services)
	}
	for _, h := range base {
		upsert(h)
	}
	for _, h := range extended {
		upsert(h)
	}
	merged := make([]models.Host, 0, len(byIP))
	for _, ip := range order {
		merged = append(merged, *byIP[ip])
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].IP < merged[j].IP })
	return merged
}

func mergeServices(host *models.Host, services []models.Service) {
	index := map[string]int{}
	for i, svc := range host.Services {
		index[serviceKey(svc)] = i
	}
	for _, svc := range services {
		key := serviceKey(svc)
		if i, ok := index[key]; ok {
			current := &host.Services[i]
			if current.State == "" {
				current.State = svc.State
			}
			if current.Name == "" {
				current.Name = svc.Name
			}
			if current.Product == "" {
				current.Product = svc.Product
			}
			if current.Version == "" {
				current.Version = svc.Version
			}
			if current.Extra == "" {
				current.Extra = svc.Extra
			}
			if current.Tunnel == "" {
				current.Tunnel = svc.Tunnel
			}
			current.CPEs = uniqueStrings(append(current.CPEs, svc.CPEs...))
			current.Scripts = uniqueScripts(append(current.Scripts, svc.Scripts...))
		} else {
			host.Services = append(host.Services, svc)
			index[key] = len(host.Services) - 1
		}
	}
	sort.Slice(host.Services, func(i, j int) bool {
		if host.Services[i].Protocol == host.Services[j].Protocol {
			return host.Services[i].Port < host.Services[j].Port
		}
		return host.Services[i].Protocol < host.Services[j].Protocol
	})
}

func serviceKey(svc models.Service) string {
	return fmt.Sprintf("%s/%d", svc.Protocol, svc.Port)
}

func trimStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func uniqueScripts(values []models.Script) []models.Script {
	seen := make(map[string]bool)
	out := make([]models.Script, 0, len(values))
	for _, s := range values {
		key := s.ID + "\x00" + s.Output
		if s.ID == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	return out
}

func compactWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
