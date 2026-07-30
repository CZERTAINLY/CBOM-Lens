package cdxprops

import (
	"strconv"
	"strings"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/czertainly"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

// expectedAlgorithm is one hand-transcribed row of standards data.
//
// The whole point of this table is that it is NOT derived from
// unsupportedAlgorithms. Every number below was read out of the document named
// in the row's comment. Copying a value from algorithm.go into this file
// defeats the test — hash_test.go used to assert a nonexistent SHAKE OID for
// exactly that reason.
type expectedAlgorithm struct {
	name       string
	paramSetID string
	// oid is the value that must be emitted. "" means the algorithm has no
	// assigned OID and none may be emitted.
	oid       string
	functions []cdx.CryptoFunction
	classical int
	// nqsl is the NIST quantum security level. nil means the assigning
	// standard defines no category, and the field must be omitted entirely
	// (not emitted as 0 -- CycloneDX defines 0 as "meets none of the
	// categories", which is a different and much stronger claim).
	nqsl *int
	// pqc holds the size metadata. nil means the sizes are parameter-set
	// dependent or unpublished, so no czertainly size properties may appear.
	pqc isPqcInfo
}

var (
	signVerify    = []cdx.CryptoFunction{cdx.CryptoFunctionSign, cdx.CryptoFunctionVerify}
	nistCategory1 = ptr(1)
	nistCategory2 = ptr(2)
	nistCategory3 = ptr(3)
	nistCategory5 = ptr(5)
)

// wantRegistry is the expected content of unsupportedAlgorithms.
//
// Sources, once, for the whole table:
//
//	RFC 9881 sec. 3    - ML-DSA object identifiers
//	FIPS 204 Table 1   - ML-DSA claimed security category and lambda
//	FIPS 204 Table 2   - ML-DSA key and signature sizes in bytes
//	NIST CSOR          - SLH-DSA object identifiers (sigAlgs 20..31)
//	FIPS 205 Table 2   - SLH-DSA security category, pk bytes, sig bytes
//	RFC 9909 App. B    - SLH-DSA sig / pub / priv sizes in bytes
//	RFC 9802 sec. 2    - XMSS and XMSS-MT object identifiers
//	RFC 9708 sec. 2    - HSS/LMS object identifier
//	SP 800-208         - stateful hash-based signatures; assigns no category
var wantRegistry = map[string]expectedAlgorithm{

	// ---------- ML-DSA (FIPS 204) ----------
	//
	// classical is FIPS 204 Table 1's lambda, "collision strength of c-tilde":
	// 128 / 192 / 256. That also matches the NIST category reference
	// primitives (cat 2 = SHA-256 collision = 128 bits, cat 5 = AES-256 key
	// search = 256 bits).

	"2.16.840.1.101.3.4.3.17": {
		// RFC 9881: id-ml-dsa-44 ::= { ... nistAlgorithm(4) sigAlgs(3) 17 }
		name: "ML-DSA-44", paramSetID: "44",
		oid: "2.16.840.1.101.3.4.3.17", functions: signVerify,
		classical: 128,
		// FIPS 204 Table 1: "Claimed security strength ... Category 2".
		//
		// REGRESSION GUARD: this is 2, not 1. Do not "fix" it to 1 by analogy
		// with ML-KEM-512. FIPS 204 sec. 3.6.1 is the only path to category 1:
		// "If an approved RBG with at least 128 bits of security but less than
		// 192 bits of security is used, then the claimed security strength of
		// ML-DSA-44 is reduced from category 2 to category 1." We do not
		// observe the signer's RBG, so the standard's headline claim applies.
		nqsl: nistCategory2,
		// FIPS 204 Table 2.
		pqc: pqcInfo{privKeySize: 2560, pubKeySize: 1312, signatureSize: 2420},
	},
	"2.16.840.1.101.3.4.3.18": {
		// RFC 9881: id-ml-dsa-65 ::= { ... sigAlgs(3) 18 }
		name: "ML-DSA-65", paramSetID: "65",
		oid: "2.16.840.1.101.3.4.3.18", functions: signVerify,
		classical: 192,           // FIPS 204 Table 1, lambda
		nqsl:      nistCategory3, // FIPS 204 Table 1, Category 3
		pqc:       pqcInfo{privKeySize: 4032, pubKeySize: 1952, signatureSize: 3309},
	},
	"2.16.840.1.101.3.4.3.19": {
		// RFC 9881: id-ml-dsa-87 ::= { ... sigAlgs(3) 19 }
		name: "ML-DSA-87", paramSetID: "87",
		oid: "2.16.840.1.101.3.4.3.19", functions: signVerify,
		// FIPS 204 Table 1 gives lambda = 256 for ML-DSA-87 and Category 5.
		// This was 192 -- a duplicate of ML-DSA-65's row.
		classical: 256,
		nqsl:      nistCategory5,
		pqc:       pqcInfo{privKeySize: 4896, pubKeySize: 2592, signatureSize: 4627},
	},

	// ---------- SLH-DSA (FIPS 205), SHA2 ----------
	//
	// classical comes from RFC 9909 sec. 1: the three security levels "were
	// chosen to be at least as secure as a generic block cipher of 128, 192,
	// or 256 bits".
	//
	// Sizes are RFC 9909 App. B Table 1, cross-checked against FIPS 205
	// Table 2 (which tabulates "pk bytes" and "sig bytes"; the private key is
	// 4n bytes, so n=16/24/32 gives 64/96/128).

	"2.16.840.1.101.3.4.3.20": {
		name: "SLH-DSA-SHA2-128S", paramSetID: "128S",
		oid: "2.16.840.1.101.3.4.3.20", functions: signVerify,
		classical: 128, nqsl: nistCategory1,
		pqc: pqcInfo{privKeySize: 64, pubKeySize: 32, signatureSize: 7856},
	},
	"2.16.840.1.101.3.4.3.21": {
		name: "SLH-DSA-SHA2-128F", paramSetID: "128F",
		oid: "2.16.840.1.101.3.4.3.21", functions: signVerify,
		classical: 128, nqsl: nistCategory1,
		pqc: pqcInfo{privKeySize: 64, pubKeySize: 32, signatureSize: 17088},
	},
	"2.16.840.1.101.3.4.3.22": {
		name: "SLH-DSA-SHA2-192S", paramSetID: "192S",
		oid: "2.16.840.1.101.3.4.3.22", functions: signVerify,
		classical: 192, nqsl: nistCategory3,
		// 192-bit sets are 48/96, not the 32/64 of the 128-bit sets.
		pqc: pqcInfo{privKeySize: 96, pubKeySize: 48, signatureSize: 16224},
	},
	"2.16.840.1.101.3.4.3.23": {
		name: "SLH-DSA-SHA2-192F", paramSetID: "192F",
		oid: "2.16.840.1.101.3.4.3.23", functions: signVerify,
		classical: 192, nqsl: nistCategory3,
		pqc: pqcInfo{privKeySize: 96, pubKeySize: 48, signatureSize: 35664},
	},
	"2.16.840.1.101.3.4.3.24": {
		name: "SLH-DSA-SHA2-256S", paramSetID: "256S",
		oid: "2.16.840.1.101.3.4.3.24", functions: signVerify,
		classical: 256, nqsl: nistCategory5,
		// sig 29792. The old value 17088 was SLH-DSA-*-128f's signature size.
		pqc: pqcInfo{privKeySize: 128, pubKeySize: 64, signatureSize: 29792},
	},
	"2.16.840.1.101.3.4.3.25": {
		name: "SLH-DSA-SHA2-256F", paramSetID: "256F",
		oid: "2.16.840.1.101.3.4.3.25", functions: signVerify,
		classical: 256, nqsl: nistCategory5,
		// sig 49856, not 37760 (which matches no parameter set at all).
		pqc: pqcInfo{privKeySize: 128, pubKeySize: 64, signatureSize: 49856},
	},

	// ---------- SLH-DSA (FIPS 205), SHAKE ----------
	//
	// RFC 9909 App. B: the SHAKE sets have byte-identical sizes to their SHA2
	// counterparts. FIPS 205 Table 2 lists them on shared rows.

	"2.16.840.1.101.3.4.3.26": {
		name: "SLH-DSA-SHAKE-128S", paramSetID: "128S",
		oid: "2.16.840.1.101.3.4.3.26", functions: signVerify,
		classical: 128, nqsl: nistCategory1,
		pqc: pqcInfo{privKeySize: 64, pubKeySize: 32, signatureSize: 7856},
	},
	"2.16.840.1.101.3.4.3.27": {
		name: "SLH-DSA-SHAKE-128F", paramSetID: "128F",
		oid: "2.16.840.1.101.3.4.3.27", functions: signVerify,
		classical: 128, nqsl: nistCategory1,
		pqc: pqcInfo{privKeySize: 64, pubKeySize: 32, signatureSize: 17088},
	},
	"2.16.840.1.101.3.4.3.28": {
		name: "SLH-DSA-SHAKE-192S", paramSetID: "192S",
		oid: "2.16.840.1.101.3.4.3.28", functions: signVerify,
		classical: 192, nqsl: nistCategory3,
		pqc: pqcInfo{privKeySize: 96, pubKeySize: 48, signatureSize: 16224},
	},
	"2.16.840.1.101.3.4.3.29": {
		name: "SLH-DSA-SHAKE-192F", paramSetID: "192F",
		oid: "2.16.840.1.101.3.4.3.29", functions: signVerify,
		classical: 192, nqsl: nistCategory3,
		pqc: pqcInfo{privKeySize: 96, pubKeySize: 48, signatureSize: 35664},
	},
	"2.16.840.1.101.3.4.3.30": {
		name: "SLH-DSA-SHAKE-256S", paramSetID: "256S",
		oid: "2.16.840.1.101.3.4.3.30", functions: signVerify,
		classical: 256, nqsl: nistCategory5,
		pqc: pqcInfo{privKeySize: 128, pubKeySize: 64, signatureSize: 29792},
	},
	"2.16.840.1.101.3.4.3.31": {
		name: "SLH-DSA-SHAKE-256F", paramSetID: "256F",
		oid: "2.16.840.1.101.3.4.3.31", functions: signVerify,
		classical: 256, nqsl: nistCategory5,
		pqc: pqcInfo{privKeySize: 128, pubKeySize: 64, signatureSize: 49856},
	},

	// ---------- Stateful hash-based signatures (SP 800-208) ----------
	//
	// nqsl is nil for all three. SP 800-208 contains no occurrence of the
	// phrase "security category" and assigns none to LMS/HSS/XMSS/XMSS^MT.
	// Claiming category 5 here, as the registry used to, invents a NIST
	// classification that no NIST document makes.
	//
	// pqc is nil for all three. RFC 9802 sec. 2: "The public key and signature
	// values for XMSS identify the hash function and the height used in the
	// XMSS tree" -- the sizes are properties of the parameter set carried
	// inside the key, not of the AlgorithmIdentifier we matched on, so we
	// cannot report them from the OID alone.
	//
	// classical 256 is retained from the pre-existing rows and assumes the
	// n=32 (SHA-256) parameter families. Also not derivable from the OID;
	// documented as a known limitation in docs/pqc-support.md.

	"1.3.6.1.5.5.7.6.34": {
		// RFC 9802: id-alg-xmss-hashsig ::= { iso(1)
		//   identified-organization(3) dod(6) internet(1) security(5)
		//   mechanisms(5) pkix(7) algorithms(6) 34 }
		name: "XMSS", paramSetID: "xmss",
		oid: "1.3.6.1.5.5.7.6.34", functions: signVerify,
		classical: 256, nqsl: nil, pqc: nil,
	},
	"1.3.6.1.5.5.7.6.35": {
		// RFC 9802: id-alg-xmssmt-hashsig ::= { ... algorithms(6) 35 }
		name: "XMSS-MT", paramSetID: "xmss-mt",
		oid: "1.3.6.1.5.5.7.6.35", functions: signVerify,
		classical: 256, nqsl: nil, pqc: nil,
	},
	"1.2.840.113549.1.9.16.3.17": {
		// RFC 9708: id-alg-hss-lms-hashsig ::= { iso(1) member-body(2)
		//   us(840) rsadsi(113549) pkcs(1) pkcs9(9) smime(16) alg(3) 17 }
		name: "HSS-LMS", paramSetID: "hss-lms",
		oid: "1.2.840.113549.1.9.16.3.17", functions: signVerify,
		classical: 256, nqsl: nil, pqc: nil,
	},

	// ---------- Deliberately absent: HQC ----------
	//
	// HQC has no assigned OID. The NIST CSOR algorithm registration page lists
	// no HQC arc (FIPS 207 is unpublished), and open-quantum-safe/oqs-provider
	// records every HQC variant's OID as NULL in ALGORITHMS.md.
	//
	// The registry used to claim 1.3.9999.6.1.{1,2,3} for HQC-128/192/256.
	// Those three OIDs are real, but they are not HQC: in oqs-provider's
	// oqs-template/generate.yml they are SPHINCS+-Haraka-128f-robust
	// (NIST Round 3) and its p256 and rsa3072 hybrids. Keeping them as HQC
	// keys would misreport a SPHINCS+ artifact as an HQC KEM.
	//
	// See docs/pqc-support.md for the documented gap.
}

// TestRegistryMatchesStandards compares unsupportedAlgorithms field by field
// against wantRegistry, and asserts the two have exactly the same key set in
// both directions so a silent addition or removal fails the build.
func TestRegistryMatchesStandards(t *testing.T) {
	t.Parallel()

	require.Equal(t, len(wantRegistry), len(unsupportedAlgorithms),
		"registry size drifted from the standards table; add or remove an expectation row")

	for oid, want := range wantRegistry {
		t.Run(want.name, func(t *testing.T) {
			t.Parallel()

			got, ok := unsupportedAlgorithms[oid]
			require.True(t, ok, "registry has no entry for %s", oid)

			require.Equal(t, want.name, got.name, "name")
			require.Equal(t, want.paramSetID, got.paramSetID, "parameterSetIdentifier")
			require.Equal(t, want.oid, got.oid, "oid")
			require.ElementsMatch(t, want.functions, got.cryptoFunctions, "cryptoFunctions")
			require.Equal(t, want.classical, got.classicalSecurityLevel,
				"classicalSecurityLevel")

			if want.nqsl == nil {
				require.Nil(t, got.nistQuantumSecurityLevel,
					"nistQuantumSecurityLevel must be unset when no standard assigns a category")
			} else {
				require.NotNil(t, got.nistQuantumSecurityLevel, "nistQuantumSecurityLevel")
				require.Equal(t, *want.nqsl, *got.nistQuantumSecurityLevel,
					"nistQuantumSecurityLevel")
			}

			require.Equal(t, want.pqc, got.pqc, "pqc size metadata")
		})
	}

	// Reverse direction: nothing may live in the registry without a sourced
	// expectation row.
	for oid, got := range unsupportedAlgorithms {
		_, ok := wantRegistry[oid]
		require.True(t, ok,
			"registry entry %s (%s) has no standards-sourced expectation row", oid, got.name)
	}
}

// TestComponentEmissionShape checks what actually reaches the CycloneDX
// document, driven from the same standards table.
func TestComponentEmissionShape(t *testing.T) {
	t.Parallel()

	for oid, want := range wantRegistry {
		t.Run(want.name, func(t *testing.T) {
			t.Parallel()

			info, ok := unsupportedAlgorithms[oid]
			require.True(t, ok)

			compo := info.componentWOBomRef(true)

			require.Equal(t, cdx.ComponentTypeCryptographicAsset, compo.Type)
			require.Equal(t, want.name, compo.Name)
			require.NotNil(t, compo.CryptoProperties)
			require.Equal(t, cdx.CryptoAssetTypeAlgorithm, compo.CryptoProperties.AssetType)
			require.Equal(t, want.oid, compo.CryptoProperties.OID,
				"emitted oid (empty string means omitted, since the field is omitempty)")

			algoProps := compo.CryptoProperties.AlgorithmProperties
			require.NotNil(t, algoProps)
			require.Equal(t, want.paramSetID, algoProps.ParameterSetIdentifier)

			if want.nqsl == nil {
				require.Nil(t, algoProps.NistQuantumSecurityLevel,
					"nistQuantumSecurityLevel must be omitted, not emitted as 0")
			} else {
				require.NotNil(t, algoProps.NistQuantumSecurityLevel)
				require.Equal(t, *want.nqsl, *algoProps.NistQuantumSecurityLevel)
			}

			require.NotNil(t, algoProps.CryptoFunctions)
			require.ElementsMatch(t, want.functions, *algoProps.CryptoFunctions)
			require.True(t, sortedFunctions(*algoProps.CryptoFunctions),
				"cryptoFunctions must be emitted in sorted order")

			// czertainly size properties appear if and only if the registry
			// has sourced sizes to report.
			assertSizeProps(t, compo, want.pqc)
		})
	}
}

// TestComponentEmissionOmitsEmptyOID covers the componentWOBomRef guard that
// suppresses the oid field. No registry row exercises it today -- every
// remaining entry has a standards-assigned OID -- but the guard is what lets
// an algorithm be reported by name when no OID exists (HQC, FN-DSA), so it
// must stay covered.
func TestComponentEmissionOmitsEmptyOID(t *testing.T) {
	t.Parallel()

	info := algorithmInfo{
		name:                     "HQC-128",
		oid:                      "",
		paramSetID:               "128",
		algorithmName:            "crypto/algorithm/hqc-128",
		classicalSecurityLevel:   128,
		nistQuantumSecurityLevel: ptr(1),
	}

	compo := info.componentWOBomRef(true)
	require.Equal(t, "HQC-128", compo.Name)
	require.Empty(t, compo.CryptoProperties.OID,
		"an algorithm with no assigned OID must emit no oid field")
	require.Equal(t, "128", compo.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier,
		"the parameter set is still reportable without an OID")
}

// TestNistQuantumSecurityLevelZeroIsEmitted proves the *int migration bought
// something real: a genuine "meets none of the NIST categories" claim of 0 is
// distinguishable from "no category assigned" and is emitted.
func TestNistQuantumSecurityLevelZeroIsEmitted(t *testing.T) {
	t.Parallel()

	info := algorithmInfo{name: "Hypothetical", nistQuantumSecurityLevel: ptr(0)}
	compo := info.componentWOBomRef(false)

	nqsl := compo.CryptoProperties.AlgorithmProperties.NistQuantumSecurityLevel
	require.NotNil(t, nqsl, "an explicit level of 0 is a claim and must survive")
	require.Equal(t, 0, *nqsl)
}

// TestComponentWOBomRefDoesNotAliasRegistry makes sure the emitted component
// does not hand out a pointer into the shared registry table.
func TestComponentWOBomRefDoesNotAliasRegistry(t *testing.T) {
	t.Parallel()

	const mlDSA44 = "2.16.840.1.101.3.4.3.17"
	info := unsupportedAlgorithms[mlDSA44]
	compo := info.componentWOBomRef(false)

	nqsl := compo.CryptoProperties.AlgorithmProperties.NistQuantumSecurityLevel
	require.NotNil(t, nqsl)
	require.NotSame(t, info.nistQuantumSecurityLevel, nqsl,
		"emitted pointer aliases the registry; a mutating consumer would corrupt the table")

	*nqsl = 99
	require.Equal(t, 2, *unsupportedAlgorithms[mlDSA44].nistQuantumSecurityLevel,
		"registry was mutated through the emitted component")
}

// TestRegistryInternalConsistency checks conventions, not truth. These
// assertions cannot catch a wrong OID or a wrong key size -- that is
// TestRegistryMatchesStandards' job. They catch structural drift: a key that
// disagrees with its own entry, a bom-ref stem that no longer follows the
// naming convention, a signature OID missing from the cert-path lookup.
func TestRegistryInternalConsistency(t *testing.T) {
	t.Parallel()

	for key, entry := range unsupportedAlgorithms {
		if entry.oid != "" {
			require.Equal(t, key, entry.oid,
				"map key and entry.oid disagree for %s", entry.name)
		}
		require.Equal(t, "crypto/algorithm/"+strings.ToLower(entry.name), entry.algorithmName,
			"algorithmName convention for %s", entry.name)
		require.NotEmpty(t, entry.cryptoFunctions, "%s has no cryptoFunctions", entry.name)
	}

	// pqcSigOIDRef is the cert-path signature-algorithm lookup. It must cover
	// exactly the registry entries that can sign.
	var wantSigOIDs []string
	for oid, entry := range unsupportedAlgorithms {
		if sliceContains(entry.cryptoFunctions, cdx.CryptoFunctionSign) {
			wantSigOIDs = append(wantSigOIDs, oid)
		}
	}
	var gotSigOIDs []string
	for oid := range pqcSigOIDRef {
		gotSigOIDs = append(gotSigOIDs, oid)
	}
	require.ElementsMatch(t, wantSigOIDs, gotSigOIDs,
		"pqcSigOIDRef must key exactly the sign-capable registry OIDs")
}

// ---------- helpers ----------

func sortedFunctions(fns []cdx.CryptoFunction) bool {
	for i := 1; i < len(fns); i++ {
		if string(fns[i-1]) > string(fns[i]) {
			return false
		}
	}
	return true
}

func sliceContains(fns []cdx.CryptoFunction, want cdx.CryptoFunction) bool {
	for _, f := range fns {
		if f == want {
			return true
		}
	}
	return false
}

// assertSizeProps checks the czertainly size properties against the expected
// pqc metadata, including that they are entirely absent when it is nil.
func assertSizeProps(t *testing.T, compo cdx.Component, want isPqcInfo) {
	t.Helper()

	sizeProps := map[string]string{}
	if compo.Properties != nil {
		for _, p := range *compo.Properties {
			if strings.HasPrefix(p.Name, "czertainly:component:algorithm:pqc:") {
				sizeProps[p.Name] = p.Value
			}
		}
	}

	switch w := want.(type) {
	case nil:
		require.Empty(t, sizeProps,
			"no size properties may be emitted when the sizes are not derivable from the OID")
	case pqcInfo:
		require.Equal(t, map[string]string{
			czertainly.AlgorithmPrivateKeySize: strconv.Itoa(w.privKeySize),
			czertainly.AlgorithmPublicKeySize:  strconv.Itoa(w.pubKeySize),
			czertainly.AlgorithmSignatureSize:  strconv.Itoa(w.signatureSize),
		}, sizeProps)
	default:
		t.Fatalf("unhandled pqc metadata type %T", want)
	}
}
