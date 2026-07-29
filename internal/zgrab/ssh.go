package zgrab

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
)

const sshProbeTimeout = 5 * time.Second

// sshKeyTypes lists the host key algorithms to probe in order.
var sshKeyTypes = []string{
	"ecdsa-sha2-nistp256",
	"ecdsa-sha2-nistp384",
	"ecdsa-sha2-nistp521",
	"ssh-ed25519",
	"rsa-sha2-256",
	"rsa-sha2-512",
	"ssh-rsa",
}

type sshProbeResult struct {
	detected bool
	hostKeys []model.SSHHostKey
}

// probeSSH attempts an SSH connection on addr and collects host keys for each
// supported key algorithm.
func probeSSH(ctx context.Context, addr string) sshProbeResult {
	seen := make(map[string]struct{})
	var keys []model.SSHHostKey

	for _, keyType := range sshKeyTypes {
		if ctx.Err() != nil {
			break
		}
		key := captureHostKey(addr, keyType)
		if key == nil {
			continue
		}
		fp := key.Fingerprint
		if _, dup := seen[fp]; dup {
			continue
		}
		seen[fp] = struct{}{}
		keys = append(keys, *key)
	}

	if len(keys) == 0 {
		return sshProbeResult{}
	}
	return sshProbeResult{detected: true, hostKeys: keys}
}

// captureHostKey connects to addr requesting the given host key algorithm and
// returns the server's host key, or nil if the server does not support it.
func captureHostKey(addr string, keyType string) *model.SSHHostKey {
	var captured *model.SSHHostKey

	cfg := &ssh.ClientConfig{
		User: "x",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fp := ssh.FingerprintLegacyMD5(key)
			captured = &model.SSHHostKey{
				Key:         base64.StdEncoding.EncodeToString(key.Marshal()),
				Type:        key.Type(),
				Bits:        strconv.Itoa(publicKeyBits(key)),
				Fingerprint: stripColons(fp),
			}
			// Return an error to abort the connection immediately after
			// host key verification — we don't need to authenticate.
			return fmt.Errorf("key captured")
		},
		HostKeyAlgorithms: []string{keyType},
		Timeout:           sshProbeTimeout,
	}

	_, err := ssh.Dial("tcp", addr, cfg)
	if err != nil && captured == nil {
		return nil
	}
	return captured
}

// publicKeyBits returns the bit length of an SSH public key.
func publicKeyBits(pub ssh.PublicKey) int {
	switch pub.Type() {
	case "ecdsa-sha2-nistp256":
		return 256
	case "ecdsa-sha2-nistp384":
		return 384
	case "ecdsa-sha2-nistp521":
		return 521
	case "ssh-ed25519":
		return 256
	default:
		// For RSA, parse the marshal bytes to determine key size.
		// This returns 0 for unknown types rather than failing.
		cpk, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			return 0
		}
		type bitsizer interface {
			Size() int
		}
		if bs, ok := cpk.CryptoPublicKey().(bitsizer); ok {
			return bs.Size() * 8
		}
		return 0
	}
}

// stripColons removes colon separators from an MD5 fingerprint string to match
// the format used by nmap (e.g. "17f9a4c3..." instead of "17:f9:a4:c3:...").
func stripColons(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != ':' {
			out = append(out, s[i])
		}
	}
	return string(out)
}
