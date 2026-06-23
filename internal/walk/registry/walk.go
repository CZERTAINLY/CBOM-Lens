package registry

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/stats"
)

// Windows REG_* type constants. These are fixed Windows API values.
const (
	regSZ       uint32 = 1
	regExpandSZ uint32 = 2
	regBinary   uint32 = 3
	regMultiSZ  uint32 = 7
	regDWORD    uint32 = 4
	regQWORD    uint32 = 11
)

// compiled holds pre-compiled regex filters.
type compiled struct {
	includeKeys   []*regexp.Regexp
	excludeKeys   []*regexp.Regexp
	includeValues []*regexp.Regexp
	excludeValues []*regexp.Regexp
}

// compile pre-compiles all regex patterns in the Registry config.
// Returns an error immediately if any pattern is invalid.
func compile(cfg model.Registry) (compiled, error) {
	var c compiled
	var err error
	if c.includeKeys, err = compileAll(cfg.Include.Keys); err != nil {
		return c, fmt.Errorf("registry include.keys: %w", err)
	}
	if c.excludeKeys, err = compileAll(cfg.Exclude.Keys); err != nil {
		return c, fmt.Errorf("registry exclude.keys: %w", err)
	}
	if c.includeValues, err = compileAll(cfg.Include.Values); err != nil {
		return c, fmt.Errorf("registry include.values: %w", err)
	}
	if c.excludeValues, err = compileAll(cfg.Exclude.Values); err != nil {
		return c, fmt.Errorf("registry exclude.values: %w", err)
	}
	return c, nil
}

func compileAll(patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		r, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", p, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// matchesAny reports whether s matches any of the compiled patterns.
func matchesAny(s string, patterns []*regexp.Regexp) bool {
	for _, p := range patterns {
		if p.MatchString(s) {
			return true
		}
	}
	return false
}

// valueAllowed reports whether a value name passes the include/exclude value filters.
func valueAllowed(name string, c compiled) bool {
	if len(c.includeValues) > 0 && !matchesAny(name, c.includeValues) {
		return false
	}
	if len(c.excludeValues) > 0 && matchesAny(name, c.excludeValues) {
		return false
	}
	return true
}

// normaliseKey converts backslash separators to forward slashes for URI embedding.
func normaliseKey(keyPath string) string {
	return strings.ReplaceAll(keyPath, `\`, "/")
}

// walkKey recursively walks key and its subkeys, yielding a registryEntry per matching value.
// keyPath is the path relative to the hive root (backslash-separated, as from the Windows API).
// Returns false if the yield function signalled stop.
func walkKey(
	ctx context.Context,
	key RegistryKey,
	keyPath string,
	hive string,
	view string,
	depth int,
	cfg model.Registry,
	c compiled,
	yield func(model.Entry, error) bool,
) bool {
	if ctx.Err() != nil {
		return false
	}

	normPath := normaliseKey(keyPath)

	// Exclude filter prunes the entire subtree (values and all subkeys).
	if len(c.excludeKeys) > 0 && matchesAny(normPath, c.excludeKeys) {
		return true
	}

	// Include filter applies only to value emission.  Subkey traversal
	// continues regardless so that a pattern like "CryptoStore" can match
	// SOFTWARE/CryptoStore even when the scan root is SOFTWARE.
	if len(c.includeKeys) == 0 || matchesAny(normPath, c.includeKeys) {
		names, err := key.ReadValueNames()
		if err != nil {
			if !yield(nil, fmt.Errorf("registry: ReadValueNames %s:%s/%s: %w", hive, view, normPath, err)) {
				return false
			}
		}
		for _, name := range names {
			if ctx.Err() != nil {
				return false
			}
			if !valueAllowed(name, c) {
				continue
			}
			// Skip oversized values before reading them into memory. The
			// Windows API reports the value size without allocating the data,
			// so this caps memory use rather than allocating then discarding.
			if cfg.MaxValueSize > 0 {
				size, err := key.ReadValueSize(name)
				if err != nil {
					if !yield(nil, fmt.Errorf("%s:%s/%s: %w", hive, view, normPath, err)) {
						return false
					}
					continue
				}
				if size > int64(cfg.MaxValueSize) {
					continue
				}
			}
			data, ok, err := convertValue(key, name)
			if err != nil {
				if !yield(nil, fmt.Errorf("%s:%s/%s: %w", hive, view, normPath, err)) {
					return false
				}
				continue
			}
			if !ok {
				continue // unsupported type — silently skip
			}
			// Exact post-read guard: the pre-read size is a byte count that for
			// string types differs from the converted UTF-8 length, so re-check.
			if cfg.MaxValueSize > 0 && len(data) > cfg.MaxValueSize {
				continue
			}
			statName := name
			if statName == "" {
				statName = "(Default)"
			}
			entry := registryEntry{location: buildLocation(hive, view, keyPath, name), name: statName, data: data}
			if !yield(entry, nil) {
				return false
			}
		}
	}

	// Recurse into subkeys unless at depth limit.
	// When MaxDepth == 0 (unlimited) the guard is skipped and the entire
	// subtree is walked.  This is safe because the Windows registry is a
	// strict tree — the hive format cannot contain cycles or symbolic links
	// between keys, so recursion always terminates.
	if cfg.MaxDepth > 0 && depth >= cfg.MaxDepth {
		return true
	}
	subNames, err := key.ReadSubKeyNames()
	if err != nil {
		return yield(nil, fmt.Errorf("registry: ReadSubKeyNames %s:%s/%s: %w", hive, view, normPath, err))
	}
	for _, sub := range subNames {
		if ctx.Err() != nil {
			return false
		}
		subPath := sub
		if keyPath != "" {
			subPath = keyPath + `\` + sub
		}
		normSubPath := normaliseKey(subPath)
		// Pre-check exclude on the subkey path before opening it
		if len(c.excludeKeys) > 0 && matchesAny(normSubPath, c.excludeKeys) {
			continue
		}
		subKey, err := key.OpenSubKey(sub)
		if err != nil {
			if !yield(nil, fmt.Errorf("registry: OpenSubKey %s:%s/%s: %w", hive, view, normSubPath, err)) {
				return false
			}
			continue
		}
		cont := walkKey(ctx, subKey, subPath, hive, view, depth+1, cfg, c, yield)
		_ = subKey.Close()
		if !cont {
			return false
		}
	}
	return true
}

// convertValue reads and converts a registry value to bytes.
// Returns (bytes, true, nil) for supported types on success.
// Returns (nil, false, nil) for unsupported types (silently skipped).
// Returns (nil, false, err) when a read error occurs — the caller should propagate the error.
func convertValue(key RegistryKey, name string) ([]byte, bool, error) {
	valType, err := key.ReadValueType(name)
	if err != nil {
		return nil, false, fmt.Errorf("registry: ReadValueType %s: %w", name, err)
	}
	switch valType {
	case regBinary:
		b, err := key.ReadBinaryValue(name)
		if err != nil {
			return nil, false, fmt.Errorf("registry: ReadBinaryValue %s: %w", name, err)
		}
		return b, true, nil
	case regSZ, regExpandSZ:
		s, err := key.ReadStringValue(name)
		if err != nil {
			return nil, false, fmt.Errorf("registry: ReadStringValue %s: %w", name, err)
		}
		return []byte(s), true, nil
	case regMultiSZ:
		ss, err := key.ReadStringsValue(name)
		if err != nil {
			return nil, false, fmt.Errorf("registry: ReadStringsValue %s: %w", name, err)
		}
		return []byte(strings.Join(ss, "\n")), true, nil
	case regDWORD, regQWORD:
		// Numeric scalar types cannot hold certificates, keys, or PEM/DER
		// blobs, so they are intentionally excluded from crypto discovery.
		return nil, false, nil
	default:
		return nil, false, nil // unsupported type — silently skip
	}
}

// buildLocation renders the registry:// URI for a value. keyPath is the raw
// backslash-separated key path; it is split on the backslash separator and each
// segment — plus the value name — is percent-escaped. Splitting before escaping
// (rather than after backslash→slash normalisation) keeps a literal '/' inside a
// name distinct from the '\' nesting separator. The synthetic "(Default)" label
// for the unnamed default value is emitted verbatim.
func buildLocation(hive, view, keyPath, name string) string {
	var sb strings.Builder
	sb.WriteString("registry://")
	sb.WriteString(hive)
	sb.WriteByte(':')
	sb.WriteString(view)
	if keyPath != "" {
		for _, seg := range strings.Split(keyPath, `\`) {
			sb.WriteByte('/')
			sb.WriteString(url.PathEscape(seg))
		}
	}
	sb.WriteByte('/')
	if name == "" {
		sb.WriteString("(Default)")
	} else {
		sb.WriteString(url.PathEscape(name))
	}
	return sb.String()
}

// regView identifies a registry view to scan. access holds the platform's
// KEY_WOW64_* access mask; label is the URI token ("64" or "32").
type regView struct {
	access uint32
	label  string
}

// selectViews returns the registry views to scan. The 64-bit view is always
// included; the 32-bit view is appended only when WOW64 dual scanning is
// enabled. The access masks are passed in so this stays platform-neutral and
// unit-testable.
func selectViews(cfg model.Registry, access64, access32 uint32) []regView {
	views := []regView{{access: access64, label: "64"}}
	if cfg.WOW64 {
		views = append(views, regView{access: access32, label: "32"})
	}
	return views
}

// walkAll is the platform-neutral orchestration behind Walk: for each
// configured path and view it opens the root key via open, walks it, updates
// counter, and yields entries/errors. Per-path open errors are non-fatal and
// skip to the next path/view. Extracted from the Windows Walk so the path/view
// iteration can be unit-tested with a fake opener.
func walkAll(
	ctx context.Context,
	counter *stats.Stats,
	cfg model.Registry,
	views []regView,
	open func(hive, key string, access uint32) (RegistryKey, error),
	yield func(model.Entry, error) bool,
) {
	if !cfg.Enabled {
		return
	}
	c, err := compile(cfg)
	if err != nil {
		yield(nil, err)
		return
	}
	for _, p := range cfg.Paths {
		for _, view := range views {
			if ctx.Err() != nil {
				return
			}
			counter.IncSources()
			k, err := open(p.Hive, p.Key, view.access)
			if err != nil {
				counter.IncErrSources()
				if !yield(nil, fmt.Errorf("registry: open %s\\%s: %w", p.Hive, p.Key, err)) {
					return
				}
				continue
			}
			countingYield := func(entry model.Entry, err error) bool {
				if err != nil {
					counter.IncErrFiles()
				} else {
					counter.IncFiles()
				}
				return yield(entry, err)
			}
			cont := walkKey(ctx, k, p.Key, p.Hive, view.label, 0, cfg, c, countingYield)
			_ = k.Close()
			if !cont {
				return
			}
		}
	}
}

// registryEntry implements model.Entry for a single registry value.
type registryEntry struct {
	location string
	name     string // raw value name ("(Default)" for the unnamed default value)
	data     []byte
}

func (e registryEntry) Location() string { return e.location }

func (e registryEntry) Open() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(e.data)), nil
}

func (e registryEntry) Stat() (fs.FileInfo, error) {
	return registryStat{name: e.name, size: int64(len(e.data))}, nil
}

// registryStat is a minimal fs.FileInfo for a registry value.
type registryStat struct {
	name string
	size int64
}

func (s registryStat) Name() string       { return s.name }
func (s registryStat) Size() int64        { return s.size }
func (s registryStat) Mode() fs.FileMode  { return 0 }
func (s registryStat) ModTime() time.Time { return time.Time{} }
func (s registryStat) IsDir() bool        { return false }
func (s registryStat) Sys() any           { return nil }
