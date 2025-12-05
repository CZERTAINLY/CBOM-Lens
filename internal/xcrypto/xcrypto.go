// xcrypro extends support of stdlib crypto
// mainly Post Quantum crypto support via github.com/cloudflare/circl
package xcrypto

import "encoding/asn1"

var (
	MLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	MLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	MLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)
