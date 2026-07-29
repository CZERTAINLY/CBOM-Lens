package zgrab

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// parsePorts parses port specifications into a sorted, deduplicated list of port numbers.
// Supported formats: "443", "80,443", "1-1024", "80,443,8000-9000".
func parsePorts(specs []string) ([]uint16, error) {
	seen := make(map[uint16]struct{})
	var ports []uint16

	for _, spec := range specs {
		for _, part := range strings.Split(spec, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}

			if idx := strings.Index(part, "-"); idx >= 0 {
				loStr, hiStr := part[:idx], part[idx+1:]
				lo, err := parsePort(loStr)
				if err != nil {
					return nil, fmt.Errorf("invalid port range start %q: %w", loStr, err)
				}
				hi, err := parsePort(hiStr)
				if err != nil {
					return nil, fmt.Errorf("invalid port range end %q: %w", hiStr, err)
				}
				if lo > hi {
					return nil, fmt.Errorf("invalid port range %q: start > end", part)
				}
				for p := uint32(lo); p <= uint32(hi); p++ {
					port := uint16(p)
					if _, ok := seen[port]; !ok {
						seen[port] = struct{}{}
						ports = append(ports, port)
					}
				}
			} else {
				p, err := parsePort(part)
				if err != nil {
					return nil, fmt.Errorf("invalid port %q: %w", part, err)
				}
				if _, ok := seen[p]; !ok {
					seen[p] = struct{}{}
					ports = append(ports, p)
				}
			}
		}
	}

	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, fmt.Errorf("port 0 is not valid")
	}
	return uint16(n), nil
}
