package registry

// RegistryKey abstracts the Windows registry key API for testability.
// The concrete windowsKey implementation wraps golang.org/x/sys/windows/registry.Key.
//
//go:generate go tool go.uber.org/mock/mockgen -destination mock/mock_registry.go -package mock . RegistryKey
type RegistryKey interface {
	// ReadValueNames returns all value names under this key.
	// The windowsKey wrapper calls registry.Key.ReadValueNames(-1) to return all names.
	ReadValueNames() ([]string, error)

	// ReadValueType returns the Windows registry type constant for the named value.
	// Uses registry.Key.GetValue(name, nil) to retrieve the type without reading data.
	ReadValueType(name string) (uint32, error)

	// ReadValueSize returns the size in bytes of the named value without
	// reading its data, so oversized values can be skipped before allocation.
	ReadValueSize(name string) (int64, error)

	// ReadBinaryValue returns raw bytes for a REG_BINARY value.
	ReadBinaryValue(name string) ([]byte, error)

	// ReadStringValue returns the string for a REG_SZ or REG_EXPAND_SZ value.
	ReadStringValue(name string) (string, error)

	// ReadStringsValue returns the string slice for a REG_MULTI_SZ value.
	ReadStringsValue(name string) ([]string, error)

	// OpenSubKey opens a subkey for reading, inheriting the WOW64 view of the parent.
	OpenSubKey(path string) (RegistryKey, error)

	// ReadSubKeyNames returns names of all direct subkeys.
	// The windowsKey wrapper calls registry.Key.ReadSubKeyNames(-1) to return all names.
	ReadSubKeyNames() ([]string, error)

	// Close releases the key handle.
	Close() error
}
