//go:build windows

package registry

import (
	"context"
	"fmt"
	"iter"
	"log/slog"

	"github.com/OmniTrustILM/cbom-lens/internal/model"
	"github.com/OmniTrustILM/cbom-lens/internal/stats"
	"golang.org/x/sys/windows/registry"
)

// windowsKey wraps registry.Key to implement the RegistryKey interface.
// The access field records KEY_WOW64_64KEY or KEY_WOW64_32KEY so subkey opens inherit the view.
type windowsKey struct {
	k      registry.Key
	access uint32
}

func (w windowsKey) ReadValueNames() ([]string, error) {
	return w.k.ReadValueNames(-1)
}

func (w windowsKey) ReadValueType(name string) (uint32, error) {
	_, valType, err := w.k.GetValue(name, nil)
	return valType, err
}

func (w windowsKey) ReadValueSize(name string) (int64, error) {
	n, _, err := w.k.GetValue(name, nil)
	return int64(n), err
}

func (w windowsKey) ReadBinaryValue(name string) ([]byte, error) {
	b, _, err := w.k.GetBinaryValue(name)
	return b, err
}

func (w windowsKey) ReadStringValue(name string) (string, error) {
	s, _, err := w.k.GetStringValue(name)
	return s, err
}

func (w windowsKey) ReadStringsValue(name string) ([]string, error) {
	ss, _, err := w.k.GetStringsValue(name)
	return ss, err
}

func (w windowsKey) OpenSubKey(path string) (RegistryKey, error) {
	k, err := registry.OpenKey(w.k, path, registry.READ|w.access)
	if err != nil {
		return nil, err
	}
	return windowsKey{k: k, access: w.access}, nil
}

func (w windowsKey) ReadSubKeyNames() ([]string, error) {
	return w.k.ReadSubKeyNames(-1)
}

func (w windowsKey) Close() error {
	return w.k.Close()
}

// hiveRoot maps a hive name string to its registry.Key constant.
func hiveRoot(hive string) (registry.Key, error) {
	switch hive {
	case "HKLM":
		return registry.LOCAL_MACHINE, nil
	case "HKCU":
		return registry.CURRENT_USER, nil
	case "HKCR":
		return registry.CLASSES_ROOT, nil
	case "HKU":
		return registry.USERS, nil
	case "HKCC":
		return registry.CURRENT_CONFIG, nil
	default:
		return 0, fmt.Errorf("unknown hive: %s", hive)
	}
}

// Walk opens each configured registry path and yields entries for all matching values.
// On 64-bit Windows with WOW64 enabled, the walk is performed twice (64-bit and 32-bit views).
func Walk(ctx context.Context, counter *stats.Stats, cfg model.Registry) iter.Seq2[model.Entry, error] {
	return func(yield func(model.Entry, error) bool) {
		if !cfg.Enabled {
			return
		}
		if !cfg.WOW64 {
			slog.DebugContext(ctx, "registry: scanning 64-bit view only; set wow64:true to also scan the 32-bit WOW6432Node view")
		}
		views := selectViews(cfg, registry.READ|registry.WOW64_64KEY, registry.READ|registry.WOW64_32KEY)
		open := func(hive, key string, access uint32) (RegistryKey, error) {
			root, err := hiveRoot(hive)
			if err != nil {
				return nil, err
			}
			k, err := registry.OpenKey(root, key, access)
			if err != nil {
				return nil, err
			}
			return windowsKey{k: k, access: access}, nil
		}
		walkAll(ctx, counter, cfg, views, open, yield)
	}
}
