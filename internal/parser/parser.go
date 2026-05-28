package parser

import (
	"encoding/xml"
	"fmt"
	"sort"
	"strings"

	"github.com/Montjoje/BSO_projektN02/internal/models"
)

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus   `xml:"status"`
	Addresses []nmapAddr   `xml:"address"`
	Hostnames []nmapName   `xml:"hostnames>hostname"`
	Ports     []nmapPort   `xml:"ports>port"`
	Scripts   []nmapScript `xml:"hostscript>script"`
}

type nmapStatus struct{ State string `xml:"state,attr"` }
type nmapAddr struct{ Addr string `xml:"addr,attr"`; Type string `xml:"addrtype,attr"` }
type nmapName struct{ Name string `xml:"name,attr"` }

type nmapPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    nmapStatus   `xml:"state"`
	Service  nmapSvc      `xml:"service"`
	Scripts  []nmapScript `xml:"script"`
}

type nmapSvc struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

type nmapScript struct{ ID string `xml:"id,attr"`; Output string `xml:"output,attr"` }

type Result struct{ Hosts []models.Host }

func ParseNmapXML(data []byte) (Result, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return Result{}, fmt.Errorf("parse xml: %w", err)
	}
	res := Result{Hosts: make([]models.Host, 0, len(run.Hosts))}
	for _, h := range run.Hosts {
		if h.Status.State != "up" {
			continue
		}
		host := models.Host{Address: firstIPv4(h.Addresses), Hostname: firstHostname(h.Hostnames)}
		for _, p := range h.Ports {
			if p.State.State != "open" {
				continue
			}
			host.Ports = append(host.Ports, models.Port{Port: p.PortID, Protocol: p.Protocol, State: p.State.State, Service: p.Service.Name, Product: p.Service.Product, Version: p.Service.Version})
			for _, s := range p.Scripts {
				host.ScriptResults = append(host.ScriptResults, models.ScriptResult{ID: s.ID, Output: s.Output, Port: p.PortID, Protocol: p.Protocol, Service: p.Service.Name})
			}
		}
		for _, s := range h.Scripts {
			host.ScriptResults = append(host.ScriptResults, models.ScriptResult{ID: s.ID, Output: s.Output})
		}
		res.Hosts = append(res.Hosts, host)
	}
	return res, nil
}

func Merge(base, extended Result) Result {
	byIP := map[string]*models.Host{}
	for _, h := range base.Hosts {
		copyH := h
		byIP[h.Address] = &copyH
	}
	for _, h := range extended.Hosts {
		if existing, ok := byIP[h.Address]; ok {
			existing.Ports = mergePorts(existing.Ports, h.Ports)
			existing.ScriptResults = mergeScripts(existing.ScriptResults, h.ScriptResults)
			if existing.Hostname == "" {
				existing.Hostname = h.Hostname
			}
		} else {
			copyH := h
			byIP[h.Address] = &copyH
		}
	}
	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	out := Result{Hosts: make([]models.Host, 0, len(ips))}
	for _, ip := range ips {
		out.Hosts = append(out.Hosts, *byIP[ip])
	}
	return out
}

func mergePorts(a, b []models.Port) []models.Port {
	seen := map[string]bool{}
	out := make([]models.Port, 0, len(a)+len(b))
	for _, p := range append(a, b...) {
		k := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

func mergeScripts(a, b []models.ScriptResult) []models.ScriptResult {
	seen := map[string]bool{}
	out := make([]models.ScriptResult, 0, len(a)+len(b))
	for _, s := range append(a, b...) {
		k := fmt.Sprintf("%s|%d|%s|%s", s.ID, s.Port, s.Protocol, s.Output)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port == out[j].Port {
			return out[i].ID < out[j].ID
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func firstIPv4(addrs []nmapAddr) string {
	for _, a := range addrs {
		if strings.EqualFold(a.Type, "ipv4") {
			return a.Addr
		}
	}
	if len(addrs) > 0 {
		return addrs[0].Addr
	}
	return ""
}

func firstHostname(h []nmapName) string {
	if len(h) > 0 {
		return h[0].Name
	}
	return ""
}
