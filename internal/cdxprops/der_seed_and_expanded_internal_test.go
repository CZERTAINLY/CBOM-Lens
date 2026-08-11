package cdxprops

import (
	"encoding/asn1"
	"fmt"
	"testing"
)

// TestDerSeedAndExpandedOf pins derSeedAndExpandedOf directly, the way its
// sibling test pins derOctetStringOf, rather than through the
// PKCS#8/algorithm-registry plumbing in pqc_body_shape_test.go.
//
// It sweeps PAIRS of sizes, not one size. Every fixture and every indirect case
// in this repository uses ML-DSA-65's (32, 4032) or ML-KEM-768's (64, 2400), and
// a helper that reads two lengths out of one SEQUENCE has failure modes a single
// pair cannot see: a comparison loosened to >=, a length checked against the
// wrong member, a child read with a length form the other member never exercises.
// So the sweep covers all six registry pairs, small sizes, the child
// short-form/long-form boundaries at 128 and 256 bytes, and -- because nothing
// else in the repo moves it -- the OUTER SEQUENCE's own length across the same
// two boundaries. Every pair has seed != expanded, so the swapped-halves case is
// always a real test of positionality.
//
// One case per pair is an accept and the rest are rejects, and each reject names
// the mutation it exists to kill: the three-children cases are the finding this
// test was written for (the previous implementation unmarshalled into a
// two-field struct, and Go's asn1 tolerates unconsumed trailing elements in a
// SEQUENCE), while the primitive/SET/context-tagged outer cases guard the
// opposite direction -- the struct destination asserted the outer element's
// class, tag and constructed bit for free, and an asn1.RawValue does not.
func TestDerSeedAndExpandedOf(t *testing.T) {
	t.Parallel()

	pairs := []struct {
		seed     int
		expanded int
		why      string
	}{
		// The six pairs the registry actually declares.
		{32, 2560, "ML-DSA-44"},
		{32, 4032, "ML-DSA-65"},
		{32, 4896, "ML-DSA-87"},
		{64, 1632, "ML-KEM-512"},
		{64, 2400, "ML-KEM-768"},
		{64, 3168, "ML-KEM-1024"},
		// Small sizes, and the two DER length-form boundaries as seen by a
		// CHILD: 127/128 is short form to long form, 255/256 is one length
		// octet to two.
		{1, 2, "smallest meaningful pair"},
		{16, 127, "child length short form, at the limit"},
		{32, 128, "child length long form, 81 80"},
		{127, 128, "both children astride the boundary"},
		{128, 255, "both children long form, one octet"},
		{255, 256, "child length long form, 82 01 00"},
		// The same two boundaries as seen by the OUTER SEQUENCE, which no
		// existing case moves: with a 32-byte seed the seed child costs 34
		// bytes, so the expanded child's total is what pushes the outer
		// content across 127 and 255.
		{32, 91, "outer content 127, short form"},
		{32, 92, "outer content 128, long form 81 80"},
		{32, 218, "outer content 255, one length octet"},
		{32, 219, "outer content 256, 82 01 00"},
	}

	// content returns n distinct, deterministic bytes so a decode that
	// silently truncates or shifts content is visible as a length mismatch
	// rather than an accidental match against zeroed bytes.
	content := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i)
		}
		return b
	}

	// marshal DER-encodes v with the standard library's own encoder, so the
	// long-form length math for the sizes above is never hand-rolled.
	marshal := func(t *testing.T, v any) []byte {
		t.Helper()
		b, err := asn1.Marshal(v)
		if err != nil {
			t.Fatalf("asn1.Marshal(%T): %v", v, err)
		}
		return b
	}

	marshalParams := func(t *testing.T, v any, p string) []byte {
		t.Helper()
		b, err := asn1.MarshalWithParams(v, p)
		if err != nil {
			t.Fatalf("asn1.MarshalWithParams(%T, %q): %v", v, p, err)
		}
		return b
	}

	// both builds the legal encoding for the two sizes given, which is also
	// the base every mutated case starts from.
	both := func(t *testing.T, seedLen, expandedLen int) []byte {
		t.Helper()
		return marshal(t, struct {
			Seed     []byte
			Expanded []byte
		}{content(seedLen), content(expandedLen)})
	}

	// retagged copies body and rewrites its outer identifier octet, so the
	// content and every length octet stay byte-identical and the tag is the
	// only difference.
	retagged := func(body []byte, tag byte) []byte {
		b := append([]byte(nil), body...)
		b[0] = tag
		return b
	}

	// contentOf returns what is INSIDE body's outer SEQUENCE, and resealed
	// wraps arbitrary content back up in a universal constructed SEQUENCE with
	// a correctly recomputed length. Together they build the one shape
	// asn1.Marshal cannot: a SEQUENCE whose content is two legal children plus
	// bytes that are not an element. Appending after the outer element instead
	// -- what the trailing-N-bytes cases below do -- lands in Unmarshal's rest
	// and is caught by a different clause, so it does not cover this.
	contentOf := func(t *testing.T, body []byte) []byte {
		t.Helper()
		var outer asn1.RawValue
		rest, err := asn1.Unmarshal(body, &outer)
		if err != nil || len(rest) != 0 || outer.Tag != asn1.TagSequence {
			t.Fatalf("fixture is not a single SEQUENCE: err=%v rest=%d tag=%d", err, len(rest), outer.Tag)
		}
		return outer.Bytes
	}

	resealed := func(t *testing.T, content []byte) []byte {
		t.Helper()
		return marshal(t, asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      content,
		})
	}

	tails := []int{1, 3, 16}

	// strays are appended INSIDE the outer SEQUENCE's content, after the two
	// children, and they exist for one mutation: a completeness check LOOSENED
	// into a tolerance rather than deleted -- `len(afterExpanded) <= 1`, `<= 2`,
	// `< 4`, the shape a later "be tolerant of encoders" change takes. The
	// three-children cases above reach the top of that band and no further. The
	// INTEGER row's third element is `02 01 2A`, three leftover bytes, so it
	// kills deletion and every tolerance of `< 4` or wider; the two OCTET STRING
	// rows leave six and kill less. Neither reaches a leftover of one or two
	// bytes, so `<= 1` and `<= 2` survive every case above. These four land
	// exactly there: one raw byte, too few to BE an element at all; two raw
	// bytes that are the right length for one and are not a well-formed one,
	// since 0xFF opens the high-tag-number form and the 0xFF after it is a
	// truncated base-128 tag; and two elements that are as small as a
	// well-formed element gets, two bytes each.
	strays := []struct {
		name  string
		bytes []byte
	}{
		{"one-raw-byte", []byte{0xFF}},
		{"two-raw-bytes", []byte{0xFF, 0xFF}},
		{"zero-length-octet-string", []byte{0x04, 0x00}},
		{"null", []byte{0x05, 0x00}},
	}

	for _, p := range pairs {
		s, e := p.seed, p.expanded
		pair := fmt.Sprintf("seed=%d/expanded=%d", s, e)

		t.Run(pair+"/legal-accept", func(t *testing.T) {
			if !derSeedAndExpandedOf(both(t, s, e), s, e) {
				t.Fatalf("rejected a correctly-shaped SEQUENCE { %d, %d } (%s)", s, e, p.why)
			}
		})

		// The finding: a third element inside the SEQUENCE. RFC 9881 sec. 6
		// and RFC 9935 sec. 6 give the production no extension marker, so
		// this is not a key -- but the two-field struct destination this
		// helper used to have accepted it in silence.
		t.Run(pair+"/third-child-octet-string", func(t *testing.T) {
			body := marshal(t, struct {
				Seed     []byte
				Expanded []byte
				Extra    []byte
			}{content(s), content(e), content(4)})
			if derSeedAndExpandedOf(body, s, e) {
				t.Fatalf("accepted a SEQUENCE { %d, %d, OCTET STRING } (%s)", s, e, p.why)
			}
		})

		// The same, tagged so a fix that only looks for a trailing OCTET
		// STRING does not pass.
		t.Run(pair+"/third-child-context-tagged", func(t *testing.T) {
			body := marshal(t, struct {
				Seed     []byte
				Expanded []byte
				Extra    []byte `asn1:"tag:0"`
			}{content(s), content(e), content(4)})
			if derSeedAndExpandedOf(body, s, e) {
				t.Fatalf("accepted a SEQUENCE { %d, %d, [0] OCTET STRING } (%s)", s, e, p.why)
			}
		})

		// And once more with a type that shares nothing with the two
		// members, so the rejection cannot be type-specific.
		t.Run(pair+"/third-child-integer", func(t *testing.T) {
			body := marshal(t, struct {
				Seed     []byte
				Expanded []byte
				Extra    int
			}{content(s), content(e), 42})
			if derSeedAndExpandedOf(body, s, e) {
				t.Fatalf("accepted a SEQUENCE { %d, %d, INTEGER } (%s)", s, e, p.why)
			}
		})

		// Both lengths are legal somewhere; neither is legal in that
		// position.
		t.Run(pair+"/halves-swapped", func(t *testing.T) {
			if derSeedAndExpandedOf(both(t, e, s), s, e) {
				t.Fatalf("accepted a SEQUENCE { %d, %d } when checking { %d, %d } (%s)", e, s, s, e, p.why)
			}
		})

		// `[0] OCTET STRING` is the seed CHOICE alternative's own tagging and
		// is illegal inside `both`, in either position. A rewrite that reads
		// the children as RawValues to measure their length loses this.
		t.Run(pair+"/first-child-context-tagged", func(t *testing.T) {
			body := marshal(t, struct {
				Seed     []byte `asn1:"tag:0"`
				Expanded []byte
			}{content(s), content(e)})
			if derSeedAndExpandedOf(body, s, e) {
				t.Fatalf("accepted a SEQUENCE whose seed is `[0] OCTET STRING` (%s)", p.why)
			}
		})

		t.Run(pair+"/second-child-context-tagged", func(t *testing.T) {
			body := marshal(t, struct {
				Seed     []byte
				Expanded []byte `asn1:"tag:0"`
			}{content(s), content(e)})
			if derSeedAndExpandedOf(body, s, e) {
				t.Fatalf("accepted a SEQUENCE whose expandedKey is `[0] OCTET STRING` (%s)", p.why)
			}
		})

		t.Run(pair+"/first-child-nested-sequence", func(t *testing.T) {
			body := marshal(t, struct {
				Seed struct {
					Inner []byte
				}
				Expanded []byte
			}{struct{ Inner []byte }{content(s)}, content(e)})
			if derSeedAndExpandedOf(body, s, e) {
				t.Fatalf("accepted a SEQUENCE whose seed is a nested SEQUENCE (%s)", p.why)
			}
		})

		// A missing child is a missing child, not an absent OPTIONAL.
		t.Run(pair+"/empty-sequence", func(t *testing.T) {
			if derSeedAndExpandedOf([]byte{0x30, 0x00}, s, e) {
				t.Fatalf("accepted an empty SEQUENCE (%s)", p.why)
			}
		})

		t.Run(pair+"/one-child-sequence", func(t *testing.T) {
			body := marshal(t, struct {
				Seed []byte
			}{content(s)})
			if derSeedAndExpandedOf(body, s, e) {
				t.Fatalf("accepted a one-child SEQUENCE { %d } (%s)", s, p.why)
			}
		})

		// A third element is caught by "the SEQUENCE's content is not fully
		// consumed", and so is anything else left over -- including bytes too
		// few to BE an element. asn1.Marshal cannot build these, which is why
		// they are resealed by hand.
		for _, stray := range strays {
			t.Run(fmt.Sprintf("%s/stray-inside-sequence=%s", pair, stray.name), func(t *testing.T) {
				body := resealed(t, append(contentOf(t, both(t, s, e)), stray.bytes...))
				if derSeedAndExpandedOf(body, s, e) {
					t.Fatalf("accepted a SEQUENCE { %d, %d } with %d stray byte(s) (%s) inside it (%s)",
						s, e, len(stray.bytes), stray.name, p.why)
				}
			})
		}

		// The body has to END where the outer SEQUENCE ends.
		for _, tail := range tails {
			t.Run(fmt.Sprintf("%s/trailing-%d-bytes", pair, tail), func(t *testing.T) {
				junk := make([]byte, tail)
				for i := range junk {
					junk[i] = 0xFF
				}
				body := append(both(t, s, e), junk...)
				if derSeedAndExpandedOf(body, s, e) {
					t.Fatalf("accepted a SEQUENCE { %d, %d } with %d trailing byte(s) (%s)", s, e, tail, p.why)
				}
			})
		}

		t.Run(pair+"/truncated-outer", func(t *testing.T) {
			body := both(t, s, e)
			body = body[:len(body)-1]
			if derSeedAndExpandedOf(body, s, e) {
				t.Fatalf("accepted a truncated SEQUENCE { %d, %d } (%s)", s, e, p.why)
			}
		})

		// The three regression guards for reading the outer element as an
		// asn1.RawValue, which matches ANY class, tag and form: the content
		// octets below are identical to the legal case and only the
		// identifier octet differs.
		t.Run(pair+"/primitive-outer", func(t *testing.T) {
			if derSeedAndExpandedOf(retagged(both(t, s, e), 0x10), s, e) {
				t.Fatalf("accepted a primitively-encoded outer element (%s)", p.why)
			}
		})

		t.Run(pair+"/set-outer", func(t *testing.T) {
			if derSeedAndExpandedOf(retagged(both(t, s, e), 0x31), s, e) {
				t.Fatalf("accepted a SET as the outer element (%s)", p.why)
			}
		})

		t.Run(pair+"/context-constructed-outer", func(t *testing.T) {
			if derSeedAndExpandedOf(retagged(both(t, s, e), 0xA0), s, e) {
				t.Fatalf("accepted a `[0] constructed` outer element (%s)", p.why)
			}
		})

		// 0xA0 above carries tag 0, so the tag assertion rejects it whether
		// or not the class is checked. 0xB0 is `[16] constructed`: the same
		// tag NUMBER as SEQUENCE in a different class, so it isolates the
		// class assertion and nothing else does.
		t.Run(pair+"/context-constructed-tag-16-outer", func(t *testing.T) {
			if derSeedAndExpandedOf(retagged(both(t, s, e), 0xB0), s, e) {
				t.Fatalf("accepted a `[16] constructed` outer element (%s)", p.why)
			}
		})

		// There are four tag classes and 0xA0/0xB0 exercise only one of the
		// three wrong ones. A class check written as `outer.Class ==
		// asn1.ClassContextSpecific` -- the wrong CONSTANT rather than a
		// missing clause, and the shape a reader who has only ever seen
		// `[0]`-tagged DER reaches for -- rejects both cases above and lets
		// these two through with content octets identical to the legal
		// encoding's. `[APPLICATION 16]` is 0x70 and `[PRIVATE 16]` is 0xF0.
		t.Run(pair+"/application-constructed-outer", func(t *testing.T) {
			if derSeedAndExpandedOf(retagged(both(t, s, e), 0x70), s, e) {
				t.Fatalf("accepted an `[APPLICATION 16] constructed` outer element (%s)", p.why)
			}
		})

		t.Run(pair+"/private-constructed-outer", func(t *testing.T) {
			if derSeedAndExpandedOf(retagged(both(t, s, e), 0xF0), s, e) {
				t.Fatalf("accepted a `[PRIVATE 16] constructed` outer element (%s)", p.why)
			}
		})

		// The other two CHOICE alternatives are well-formed DER and are not
		// this one. rejectPrivateKeyBody tries them separately.
		t.Run(pair+"/seed-alternative-alone", func(t *testing.T) {
			if derSeedAndExpandedOf(marshalParams(t, content(s), "tag:0"), s, e) {
				t.Fatalf("accepted the bare seed alternative (%s)", p.why)
			}
		})

		t.Run(pair+"/expanded-alternative-alone", func(t *testing.T) {
			if derSeedAndExpandedOf(marshal(t, content(e)), s, e) {
				t.Fatalf("accepted the bare expandedKey alternative (%s)", p.why)
			}
		})

		// Either length off by one, in either direction, so no comparison
		// can be loosened to >= or <=.
		t.Run(pair+"/seed-one-short", func(t *testing.T) {
			if derSeedAndExpandedOf(both(t, s-1, e), s, e) {
				t.Fatalf("accepted a SEQUENCE { %d, %d } when checking { %d, %d } (%s)", s-1, e, s, e, p.why)
			}
		})

		t.Run(pair+"/expanded-one-long", func(t *testing.T) {
			if derSeedAndExpandedOf(both(t, s, e+1), s, e) {
				t.Fatalf("accepted a SEQUENCE { %d, %d } when checking { %d, %d } (%s)", s, e+1, s, e, p.why)
			}
		})

		// The two cases above move each length in ONE direction, which pins
		// only one half of each comparison: `len(seed) < wantSeed` still
		// rejects a short seed, and `len(expanded) >= wantExpanded` still
		// rejects a long expanded key. Both mutations survive the pair above
		// and accept a SEQUENCE whose member is the wrong size, so each length
		// is moved the other way too.
		t.Run(pair+"/seed-one-long", func(t *testing.T) {
			if derSeedAndExpandedOf(both(t, s+1, e), s, e) {
				t.Fatalf("accepted a SEQUENCE { %d, %d } when checking { %d, %d } (%s)", s+1, e, s, e, p.why)
			}
		})

		t.Run(pair+"/expanded-one-short", func(t *testing.T) {
			if derSeedAndExpandedOf(both(t, s, e-1), s, e) {
				t.Fatalf("accepted a SEQUENCE { %d, %d } when checking { %d, %d } (%s)", s, e-1, s, e, p.why)
			}
		})

		// A wanted length of zero is the one regime where an unmarshalling
		// error and a satisfied length check coincide: asn1.Unmarshal leaves a
		// []byte destination nil when it fails, so len() is 0 and every other
		// clause is happy. Reading the second child out of an EMPTY remainder
		// fails exactly that way, which makes the third `err` check the only
		// thing standing between a one-child SEQUENCE and an accept.
		//
		// rejectPrivateKeyBody never asks for zero today -- it returns early
		// when the registry states no expanded size, and guards the two
		// seed-bearing alternatives with `seed > 0`. That guard is one
		// condition written twice, and the SLH-DSA rows in
		// pqc_body_shape_test.go are what pin it, so
		// the helper is pinned at the boundary rather than at the caller's
		// current habits.
		//
		// The pin is at wantExpanded == 0 only, and the asymmetry is
		// deliberate. derSeedAndExpandedOf(both(0, e), 0, e) returns TRUE today:
		// an empty first OCTET STRING is a child that PARSES, and len(seed) == 0
		// then satisfies the length check, so on that side an error and a
		// satisfied comparison never coincide and there is nothing to catch.
		// Refusing a seed alternative to an algorithm that has none is the CALL
		// SITE's job and has to stay there, because the same `seed > 0` also
		// gates the seed-only `tag:0` probe one line above. A self-defending
		// leading `if wantSeed <= 0 || wantExpanded <= 0 { return false }` was
		// tried and rejected, because it MASKS rather than closes. Delete the
		// call site's guard today and both SLH-DSA rows catch it; delete it with
		// the helper defending itself and only the zero-length `[0] OCTET
		// STRING` row still does, because the empty-seed `both` row is then
		// refused by the helper instead of by the guard -- so the guard would
		// end up half as pinned as it is now. The same clause's
		// `wantExpanded <= 0` half returns before the third `err` check, which
		// would leave this very case green with that check deleted.
		t.Run(pair+"/one-child-sequence-wanting-zero-expanded", func(t *testing.T) {
			body := marshal(t, struct {
				Seed []byte
			}{content(s)})
			if derSeedAndExpandedOf(body, s, 0) {
				t.Fatalf("accepted a one-child SEQUENCE { %d } as { %d, 0 } (%s)", s, s, p.why)
			}
		})

		// Non-DER noise: fixed, deterministic byte patterns that are not a
		// valid encoding of anything, at several lengths. A helper that
		// parses a prefix and stops accepts some of these.
		noisePatterns := map[string]func(n int) []byte{
			"all-zero": func(n int) []byte { return make([]byte, n) },
			"all-0xff": func(n int) []byte {
				b := make([]byte, n)
				for i := range b {
					b[i] = 0xFF
				}
				return b
			},
			"ascending": content,
		}
		for _, n := range []int{0, 1, 2, 5, 10, 34, 66} {
			for name, build := range noisePatterns {
				t.Run(fmt.Sprintf("%s/noise=%s/len=%d", pair, name, n), func(t *testing.T) {
					if derSeedAndExpandedOf(build(n), s, e) {
						t.Fatalf("accepted %d bytes of %s noise as a SEQUENCE { %d, %d } (%s)", n, name, s, e, p.why)
					}
				})
			}
		}
	}
}
