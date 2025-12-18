package cdxprops

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/czertainly"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

const (
	rsaIdentifier = "rsa@1.2.840.113549.1.1.1"
)

var (
	cryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionVerify}
	algoMap         = map[string]cdx.CryptoAlgorithmProperties{
		"ecdsa-sha2-nistp256": {
			ParameterSetIdentifier: "nistp256@1.2.840.10045.3.1.7",
			Curve:                  "nistp256",
		},
		"ecdsa-sha2-nistp384": {
			ParameterSetIdentifier: "nistp384@1.3.132.0.34",
			Curve:                  "nistp384",
		},
		"ecdsa-sha2-nistp521": {
			ParameterSetIdentifier: "nistp521@1.3.132.0.35",
			Curve:                  "nistp521",
		},
		"ssh-ed25519": {
			ParameterSetIdentifier: "ed25519@1.3.101.112",
			Curve:                  "ed25519",
		},
		"rsa-sha2-256": {
			ParameterSetIdentifier: rsaIdentifier,
		},
		"rsa-sha2-512": {
			ParameterSetIdentifier: rsaIdentifier,
		},
		"ssh-rsa": { // legacy
			ParameterSetIdentifier: rsaIdentifier,
		},
	}
)

type TLSInfo struct {
	Name    string
	Version string
	OID     string
}

func (c Converter) parseNmap(ctx context.Context, port model.NmapPort) (compos []cdx.Component, deps []cdx.Dependency, services []cdx.Service, err error) {
	switch port.Service.Name {
	case "ssh":
		compos = append(compos, c.sshToCompos(ctx, port)...)
	case "ssl", "http", "https":
		c := c.tlsToCompos(ctx, port)
		compos = append(compos, c...)
	default:
		slog.WarnContext(ctx, "can't parse unsupported nmap service: ignoring", "service", port.Service.Name)
	}

	// FIXME: handle cdx services too
	return
}

func (c Converter) sshToCompos(_ context.Context, port model.NmapPort) []cdx.Component {
	ret := make([]cdx.Component, 0, len(port.SSHHostKeys))
	for _, hkey := range port.SSHHostKeys {
		compo := c.ParseSSHHostKey(hkey)
		ret = append(ret, compo)
	}
	return ret
}

func (c Converter) tlsToCompos(ctx context.Context, port model.NmapPort) []cdx.Component {
	compos := make([]cdx.Component, 0, len(port.Ciphers)+len(port.TLSCerts))

	for _, certHit := range port.TLSCerts {
		detection := c.CertHit(ctx, certHit)
		if detection == nil {
			slog.WarnContext(ctx, "can't convert nmap TLS certificate to components: ignoring", "location", certHit.Location, "source", certHit.Source)
			continue
		}
		compos = append(compos, detection.Components...)
	}

	var cryptoRefArray *[]cdx.BOMReference
	var authSize string
	for _, compo := range compos {
		if compo.CryptoProperties != nil && compo.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
			var refs = []cdx.BOMReference{
				cdx.BOMReference(compo.BOMRef),
			}
			cryptoRefArray = &refs

			// infer auth size
			if compo.CryptoProperties != nil &&
				compo.CryptoProperties.CertificateProperties != nil {
				authSize = publicKeySizeFromPkeyRef(string(compo.CryptoProperties.CertificateProperties.SubjectPublicKeyRef))
			}
			break
		}
	}

	for _, cipher := range port.Ciphers {
		compos = append(
			compos,
			c.tlsCipherToCompos(ctx, cipher, cryptoRefArray, authSize)...)
	}
	return compos
}

func publicKeySizeFromPkeyRef(ref string) string {
	// Example: "crypto/algorithm/rsa-2048@sha256:..."
	//          "crypto/algorithm/ecdsa-secp256r1@sha256:..."
	parts := strings.Split(ref, "@")
	if len(parts) == 0 {
		return ""
	}
	algo := strings.TrimPrefix(parts[0], "crypto/algorithm/")
	if ret, ok := strings.CutPrefix(algo, "rsa-"); ok {
		return ret // e.g., "2048"
	}
	if ret, ok := strings.CutPrefix(algo, "ecdsa-"); ok {
		return ret // e.g., "secp256r1"
	}
	return ""
}

func ParseTLSInfo(input string) TLSInfo {
	patterns := map[string]TLSInfo{
		"TLSv1.3": {Name: "tls", Version: "1.3", OID: "1.3.6.1.5.5.7.6.2"},
		"TLSv1.2": {Name: "tls", Version: "1.2", OID: "1.3.6.1.5.5.7.6.1"},
		"TLSv1.1": {Name: "tls", Version: "1.1", OID: "1.3.6.1.5.5.7.6.0"},
		"TLSv1.0": {Name: "tls", Version: "1.0", OID: "1.3.6.1.4.1.311.10.3.3"},
		"TLSv1":   {Name: "tls", Version: "1.0", OID: "1.3.6.1.4.1.311.10.3.3"},
		"SSLv3":   {Name: "ssl", Version: "3.0", OID: "1.3.6.1.4.1.311.10.3.2"},
		"SSLv2":   {Name: "ssl", Version: "2.0", OID: "1.3.6.1.4.1.311.10.3.1"},
		"TLS1.3":  {Name: "tls", Version: "1.3", OID: "1.3.6.1.5.5.7.6.2"},
		"TLS1.2":  {Name: "tls", Version: "1.2", OID: "1.3.6.1.5.5.7.6.1"},
		"TLS1.1":  {Name: "tls", Version: "1.1", OID: "1.3.6.1.5.5.7.6.0"},
		"TLS1.0":  {Name: "tls", Version: "1.0", OID: "1.3.6.1.4.1.311.10.3.3"},
		"TLS 1.3": {Name: "tls", Version: "1.3", OID: "1.3.6.1.5.5.7.6.2"},
		"TLS 1.2": {Name: "tls", Version: "1.2", OID: "1.3.6.1.5.5.7.6.1"},
		"TLS 1.1": {Name: "tls", Version: "1.1", OID: "1.3.6.1.5.5.7.6.0"},
		"TLS 1.0": {Name: "tls", Version: "1.0", OID: "1.3.6.1.4.1.311.10.3.3"},
	}
	if result, ok := patterns[input]; ok {
		return result
	}
	return TLSInfo{Name: "n/a", Version: "n/a", OID: "n/a"}
}

func (cv Converter) parseTLSCiphers(ctx context.Context, ciphers []model.SSLCipher, authKeyLen string) []cipherSuite {
	ret := make([]cipherSuite, 0, len(ciphers))
	for _, c := range ciphers {
		suite, ok := ParseCipherSuite(c)
		if !ok {
			slog.WarnContext(ctx, "cipher suite not supported: ignoring", "name", c)
			continue
		}
		var identifiers = []string{
			fmt.Sprintf("0x%X", byte(suite.Code>>8)),
			fmt.Sprintf("0x%X", byte(suite.Code&0xFF)),
		}

		compos := make([]cdx.Component, 0, 4)
		// kex info
		info, ok := suite.KeyExchange.Exchange.info(suite.KexInfo)
		if ok {
			compo := info.componentWOBomRef(cv.czertainly)
			setAlgorithmPrimitive(&compo, cdx.CryptoPrimitiveKeyAgree)
			cv.BOMRefHash(&compo, info.algorithmName)
			compos = append(compos, compo)
		}

		// kex-auth
		info, ok = suite.KeyExchange.Auth.info(authKeyLen)
		if ok {
			compo := info.componentWOBomRef(cv.czertainly)
			if suite.KeyExchange.Auth != "" {
				setAlgorithmPrimitive(&compo, cdx.CryptoPrimitiveSignature)
			}
			cv.BOMRefHash(&compo, info.algorithmName)
			compos = append(compos, compo)
		}

		// cipher algorithm
		info, ok = suite.Cipher.info(suite.KeyLen, suite.Mode)
		if ok {
			compo := info.componentWOBomRef(cv.czertainly)
			setAlgorithmPrimitive(&compo, cdx.CryptoPrimitiveBlockCipher)
			cv.BOMRefHash(&compo, info.algorithmName)
			compos = append(compos, compo)
		}

		// hash algorithm
		if suite.Hash != "" {
			compo := cv.hashAlgorithmCompo(string(suite.Hash))
			cv.BOMRefHash(&compo, "crypto/algorithm/"+string(suite.Hash))
			compos = append(compos, compo)
		}

		s := cipherSuite{
			name:        c.Name,
			identifiers: identifiers,
			compos:      compos,
		}

		ret = append(ret, s)
	}
	return ret
}

type cipherSuite struct {
	name        string
	compos      []cdx.Component
	identifiers []string
}

func (c cipherSuite) cdx() cdx.CipherSuite {
	var algos = make([]cdx.BOMReference, 0, len(c.compos))
	for _, compo := range c.compos {
		algos = append(algos, cdx.BOMReference(compo.BOMRef))
	}
	var algop *[]cdx.BOMReference
	if len(algos) != 0 {
		algop = &algos
	}
	return cdx.CipherSuite{
		Name:        c.name,
		Algorithms:  algop,
		Identifiers: &c.identifiers,
	}
}

func (c Converter) tlsCipherToCompos(ctx context.Context, cipher model.SSLEnumCiphers, cryptoRefArray *[]cdx.BOMReference, authKeyLen string) []cdx.Component {
	info := ParseTLSInfo(cipher.Name)

	var compos []cdx.Component
	var suites []cdx.CipherSuite

	for _, cs := range c.parseTLSCiphers(ctx, cipher.Ciphers, authKeyLen) {
		compos = append(compos, cs.compos...)
		suites = append(suites, cs.cdx())
	}

	var suitesp *[]cdx.CipherSuite
	if len(suites) != 0 {
		suitesp = &suites
	}

	protoCompo := cdx.Component{
		Name:   cipher.Name,
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: "crypto/protocol/" + info.Name + "@" + info.Version,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeProtocol,
			ProtocolProperties: &cdx.CryptoProtocolProperties{
				Type:           cdx.CryptoProtocolTypeTLS,
				Version:        info.Version,
				CipherSuites:   suitesp,
				CryptoRefArray: cryptoRefArray,
			},
			OID: info.OID,
		},
	}
	return append([]cdx.Component{protoCompo}, compos...)
}

// ParseSSHAlgorithm returns CycloneDX crypto algorithm properties for a known SSH
// host key algorithm string. It reports ok=false if the algorithm is unsupported.
func parseSSHAlgorithm(algo string) cdx.CryptoAlgorithmProperties {
	p, ok := algoMap[algo]

	if !ok {
		p.ParameterSetIdentifier = "unknown"
		p.Curve = ""
	}

	p.Primitive = cdx.CryptoPrimitiveSignature
	p.CryptoFunctions = cryptoFunctions
	return p
}

func (c Converter) ParseSSHHostKey(key model.SSHHostKey) cdx.Component {
	algoProp := parseSSHAlgorithm(key.Type)
	compo := cdx.Component{
		BOMRef: "crypto/algorithm/" + key.Type + "@" + key.Bits,
		Name:   key.Type,
		Type:   cdx.ComponentTypeCryptographicAsset,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:           cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &algoProp,
			OID:                 algoProp.ParameterSetIdentifier,
		},
	}

	if c.czertainly {
		props := czertainly.SSHHostKeyProperties(nil, key)
		compo.Properties = &props
	}

	return compo
}
