package model

// Nmap is a result of nmap scan on a given host/ip address
type Nmap struct {
	Address string
	Status  string
	Ports   []NmapPort
}

// NmapPort contains nmap output for a given port
type NmapPort struct {
	PortNumber  int
	State       string
	Protocol    string
	Service     NmapService
	Ciphers     []SSLEnumCiphers
	TLSCerts    []CertHit
	SSHHostKeys []SSHHostKey
	Scripts     []NmapScript
}

type NmapService struct {
	Name    string
	Product string
	Version string
}

// SSHHostKey is an output of `ssh-hostkey` script of nmap
type SSHHostKey struct {
	Key         string
	Type        string
	Bits        string
	Fingerprint string
}

// SSLEnumCiphers is an output of `ssl-enum-ciphers` script of nmap
type SSLEnumCiphers struct {
	Name    string
	Ciphers []SSLCipher
}

type SSLCipher struct {
	Name    string // eg TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	KexInfo string // eg secp256r1
}

// NmapScript is a raw output of nmap script, which is not
// handled
type NmapScript struct {
	ID    string
	Value string
}
