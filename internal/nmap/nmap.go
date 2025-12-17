package nmap

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/log"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/scanner/pem"

	"github.com/Ullaakut/nmap/v3"
)

const (
	nmapSource = "NMAP"
)

// Scanner is a wrapper on top of "github.com/Ullaakut/nmap/v3" Scanner
type Scanner struct {
	nmap    string
	ports   []string
	options []nmap.Option
	rawPath string
}

// NewTLS creates a nmap scanner with -sV and --script ssl-enum-ciphers,ssl-cert
// for TLS/SSL (if available) detection
func New() Scanner {
	return Scanner{
		options: []nmap.Option{
			nmap.WithTimingTemplate(nmap.TimingAggressive),
			nmap.WithServiceInfo(),
			nmap.WithScripts("ssl-enum-ciphers", "ssl-cert", "ssh-hostkey"),
		},
	}
}

func (s Scanner) WithNmapBinary(nmap string) Scanner {
	s.nmap = nmap
	return s
}

func (s Scanner) WithPorts(defs ...string) Scanner {
	ret := s
	ret.ports = append(append([]string(nil), ret.ports...), defs...)
	return ret
}

func (s Scanner) WithRawPath(path string) Scanner {
	s.rawPath = path
	return s
}

func (s Scanner) Scan(ctx context.Context, addr netip.Addr) (model.Nmap, error) {
	options := s.options
	if s.nmap != "" {
		options = append(options, nmap.WithBinaryPath(s.nmap))
	}

	options = append(options, []nmap.Option{
		nmap.WithTargets(addr.String()),
	}...)

	if addr.Is6() {
		options = append(options, nmap.WithIPv6Scanning())
	}

	ports := s.ports
	if ports == nil {
		ports = []string{"1-65535"}
	}
	options = append(options, nmap.WithPorts(ports...))

	logCtx := log.ContextAttrs(
		ctx,
		slog.String("scanner", "nmap"),
		slog.GroupAttrs(
			"options",
			slog.String("nmap", s.nmap),
			slog.Any("ports", ports),
		),
		slog.String("target", addr.String()),
	)
	run, err := scan(logCtx, options)
	if err != nil {
		return model.Nmap{}, fmt.Errorf("nmap scan services: %w", err)
	}

	if run == nil || len(run.Hosts) == 0 {
		slog.WarnContext(ctx, "nmap scan: no hosts results")
		return model.Nmap{}, nil
	}

	return HostToModel(ctx, run.Hosts[0]), nil
}

func scan(ctx context.Context, options []nmap.Option) (*nmap.Run, error) {
	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("creating nmap scanner: %w", err)
	}

	now := time.Now()
	slog.InfoContext(ctx, "scan started")
	scan, warningsp, err := scanner.Run()
	if err != nil {
		slog.DebugContext(ctx, "scan failed", "error", err)
		return nil, fmt.Errorf("nmap scan: %w", err)
	}

	if scan != nil {
		slog.InfoContext(ctx, "scan finished",
			slog.Group("stats",
				"args", scan.Args,
				"start", scan.StartStr,
				"finished", scan.Stats.Finished.TimeStr,
				"elapsed", scan.Stats.Finished.Elapsed,
				"summary", scan.Stats.Finished.Summary,
			),
		)
	}

	if scan == nil || len(scan.Hosts) == 0 {
		slog.DebugContext(ctx, "scan found nothing")
		return nil, nil
	}

	slog.DebugContext(ctx, "scan finished", "elapsed", time.Since(now).String())

	if warningsp != nil && *warningsp != nil {
		for _, warn := range *warningsp {
			slog.WarnContext(ctx, "scan", "warning", warn)
		}
	}

	return scan, nil
}

func HostToModel(ctx context.Context, host nmap.Host) model.Nmap {
	address := getNmapAddress(host.Addresses)
	var status = host.Status.State

	ports := make([]model.NmapPort, len(host.Ports))
	for i, port := range host.Ports {
		location := address + ":" + strconv.Itoa(int(port.ID))
		m := portToModel(ctx, port, location)
		ports[i] = m
	}

	return model.Nmap{
		Address: address,
		Status:  status,
		Ports:   ports,
	}
}

func portToModel(ctx context.Context, port nmap.Port, location string) model.NmapPort {
	ret := model.NmapPort{
		ID:       int(port.ID),
		State:    port.State.State,
		Protocol: port.Protocol,
		Service: model.NmapService{
			Name:    port.Service.Name,
			Product: port.Service.Product,
			Version: port.Service.Version,
		},
	}
	parseScripts(ctx, port.Scripts, location, &ret)
	return ret
}

func parseScripts(ctx context.Context, scripts []nmap.Script, location string, out *model.NmapPort) {
	for _, s := range scripts {
		switch s.ID {
		case "ssl-enum-ciphers":
			out.Ciphers = append(out.Ciphers, sslEnumCiphers(ctx, s, location)...)
		case "ssl-cert":
			out.TLSCerts = append(out.TLSCerts, sslCerts(ctx, s, location)...)
		case "ssh-hostkey":
			out.SSHHostKeys = append(out.SSHHostKeys, sshHostKey(ctx, s, location)...)
		default:
			out.Scripts = append(out.Scripts, model.NmapScript{
				ID:    s.ID,
				Value: s.Output,
			})
		}
	}
}

func sslEnumCiphers(ctx context.Context, s nmap.Script, location string) []model.SSLEnumCiphers {
	ciphers := make([]model.SSLEnumCiphers, len(s.Tables))

	for idx, row := range s.Tables {
		ciphers[idx] = model.SSLEnumCiphers{
			Name:    row.Key,
			Ciphers: cipherSuites(ctx, row.Tables, location),
		}
	}

	return ciphers
}

func cipherSuites(_ context.Context, tables []nmap.Table, location string) []model.SSLCipher {
	var ret []model.SSLCipher
	for _, row := range tables {
		if row.Key != "ciphers" {
			continue
		}
		for _, cipher := range row.Tables {
			item := model.SSLCipher{Location: location, Source: nmapSource}
			for _, element := range cipher.Elements {
				if element.Key == "name" {
					item.Name = element.Value
				}
				if element.Key == "kex_info" {
					item.KexInfo = element.Value
				}
			}
			ret = append(ret, item)
		}
	}
	return ret
}

func sslCerts(ctx context.Context, s nmap.Script, location string) []model.CertHit {
	certs := make([]model.CertHit, 0, len(s.Elements))

	for _, row := range s.Elements {
		if row.Key == "pem" {
			val := html.UnescapeString(row.Value)
			bundle, err := pem.Scanner{}.Scan(ctx, []byte(val), location)
			if err != nil {
				slog.WarnContext(ctx, "failed to scan PEM data: ignoring", "error", err)
				continue
			}

			// Override the certificate source.
			for ii, _ := range bundle.Certificates {
				bundle.Certificates[ii].Source = nmapSource
			}

			certs = append(certs, bundle.Certificates...)
		}
	}
	return certs
}

func sshHostKey(_ context.Context, s nmap.Script, location string) []model.SSHHostKey {
	hostKeys := make([]model.SSHHostKey, len(s.Tables))

	for idx, table := range s.Tables {
		var key, typ, bits, fingerprint string
		for _, row := range table.Elements {
			switch row.Key {
			case "key":
				key = row.Value
			case "type":
				typ = row.Value
			case "bits":
				bits = row.Value
			case "fingerprint":
				fingerprint = row.Value
			}
		}
		hostKeys[idx] = model.SSHHostKey{
			Key:         key,
			Type:        typ,
			Bits:        bits,
			Fingerprint: fingerprint,
			Location:    location,
			Source:      nmapSource,
		}
	}

	return hostKeys
}

func getNmapAddress(addresses []nmap.Address) string {
	for _, address := range addresses {
		if address.Addr != "127.0.0.1" && address.Addr != "0:0:0:0:0:0:0:1" && address.Addr != "localhost" {
			return address.Addr
		}
	}
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "unknown"
}
