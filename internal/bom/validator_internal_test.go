package bom

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

func TestNewStrictCompiler_NoLoaders(t *testing.T) {
	compiler := newStrictCompiler()
	require.Empty(t, compiler.Loaders,
		"strict compiler must have no remote loaders registered")
}

func TestCompileSchemaSet_FailsClosedOnUnresolvedRef(t *testing.T) {
	fsys := fstest.MapFS{
		"schemas/dangling.schema.json": &fstest.MapFile{
			Data: []byte(`{
				"$schema": "https://json-schema.org/draft/2020-12/schema",
				"$id": "http://example.com/dangling.schema.json",
				"type": "object",
				"properties": {
					"foo": {"$ref": "http://example.com/missing.json"}
				}
			}`),
		},
	}
	set := schemaSet{main: "schemas/dangling.schema.json"}

	_, err := compileSchemaSet(fsys, set)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unresolved")
	require.Contains(t, err.Error(), "http://example.com/missing.json")
}

func TestCompileSchemaSet_FailsClosedOnUnresolvedRefInSubschema(t *testing.T) {
	// The main schema resolves cleanly against the subschema, but the
	// subschema itself carries a dangling external $ref. The gate must catch
	// it: the main schema's ref walker stops at resolved refs and never
	// descends into the referenced subschema.
	fsys := fstest.MapFS{
		"schemas/main.schema.json": &fstest.MapFile{
			Data: []byte(`{
				"$schema": "https://json-schema.org/draft/2020-12/schema",
				"$id": "http://example.com/main.schema.json",
				"type": "object",
				"properties": {
					"foo": {"$ref": "http://example.com/sub.schema.json"}
				}
			}`),
		},
		"schemas/sub.schema.json": &fstest.MapFile{
			Data: []byte(`{
				"$schema": "https://json-schema.org/draft/2020-12/schema",
				"$id": "http://example.com/sub.schema.json",
				"type": "object",
				"properties": {
					"bar": {"$ref": "http://example.com/other-missing.json"}
				}
			}`),
		},
	}
	set := schemaSet{
		main: "schemas/main.schema.json",
		subs: []subschema{
			{uri: "http://example.com/sub.schema.json", path: "schemas/sub.schema.json"},
		},
	}

	_, err := compileSchemaSet(fsys, set)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unresolved")
	require.Contains(t, err.Error(), "http://example.com/other-missing.json")
}

func TestSchemaSets_AllSubschemasEmbedded(t *testing.T) {
	require.NotEmpty(t, schemaSets)
	for ver, set := range schemaSets {
		t.Run(ver.String(), func(t *testing.T) {
			schema, err := compileSchemaSet(schemaFS, set)
			require.NoError(t, err)
			require.NotNil(t, schema)
		})
	}
}

// TestSchemaSets_AllExternalRefsDeclared audits the raw JSON of every
// embedded schema file: each external (non-"#") $ref, resolved against the
// base URI derived from the file's $id, must point at a URI declared in the
// set. This is schema-agnostic and independent of the library's ref walker,
// closing its blind spots (the walker does not descend into keyword
// positions like if/then/else) -- see the gate in compileSchemaSet.
func TestSchemaSets_AllExternalRefsDeclared(t *testing.T) {
	require.NotEmpty(t, schemaSets)
	for ver, set := range schemaSets {
		t.Run(ver.String(), func(t *testing.T) {
			declared := make(map[string]bool, len(set.subs)+1)
			for _, sub := range set.subs {
				declared[sub.uri] = true
			}

			paths := make([]string, 0, len(set.subs)+1)
			paths = append(paths, set.main)
			for _, sub := range set.subs {
				paths = append(paths, sub.path)
			}

			// Every file's own $id is a legal target too (self-references).
			ids := make(map[string]*url.URL, len(paths))
			for _, path := range paths {
				data, err := fs.ReadFile(schemaFS, path)
				require.NoError(t, err)
				var doc map[string]any
				require.NoError(t, json.Unmarshal(data, &doc))
				id, _ := doc["$id"].(string)
				require.NotEmpty(t, id, "schema %s must declare an $id", path)
				base, err := url.Parse(id)
				require.NoError(t, err, "schema %s: unparseable $id %q", path, id)
				ids[path] = base
				declared[id] = true
			}

			for _, path := range paths {
				data, err := fs.ReadFile(schemaFS, path)
				require.NoError(t, err)
				var doc any
				require.NoError(t, json.Unmarshal(data, &doc))

				for _, ref := range collectExternalRefs(doc) {
					refURL, err := url.Parse(ref)
					require.NoError(t, err, "schema %s: unparseable $ref %q", path, ref)
					resolved := *ids[path].ResolveReference(refURL)
					resolved.Fragment = ""
					require.True(t, declared[resolved.String()],
						"schema %s references %q (resolves to %s), which is not a declared subschema of the %s set",
						path, ref, resolved.String(), ver)
				}
			}
		})
	}
}

// collectExternalRefs walks arbitrary JSON and collects every string value
// under a "$ref" key that is not an internal "#..." reference.
func collectExternalRefs(node any) []string {
	var refs []string
	switch n := node.(type) {
	case map[string]any:
		for key, value := range n {
			if key == "$ref" {
				if ref, ok := value.(string); ok {
					if !strings.HasPrefix(ref, "#") {
						refs = append(refs, ref)
					}
					continue
				}
			}
			refs = append(refs, collectExternalRefs(value)...)
		}
	case []any:
		for _, value := range n {
			refs = append(refs, collectExternalRefs(value)...)
		}
	}
	return refs
}

// TestCompileSchemaSet_NeverFetchesRemoteRefs guards against the strict
// compiler regressing to the library default with HTTP loaders: a remote
// $ref must fail closed as unresolved without a single network request,
// even when a server is ready to serve a valid schema.
func TestCompileSchemaSet_NeverFetchesRemoteRefs(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id": %q,
			"type": "object"
		}`, "http://"+r.Host+r.URL.Path)
	}))
	defer srv.Close()

	remote := srv.URL + "/remote.schema.json"
	fsys := fstest.MapFS{
		"schemas/main.schema.json": &fstest.MapFile{
			Data: fmt.Appendf(nil, `{
				"$schema": "https://json-schema.org/draft/2020-12/schema",
				"$id": "http://example.com/main.schema.json",
				"type": "object",
				"properties": {
					"foo": {"$ref": %q}
				}
			}`, remote),
		},
	}
	set := schemaSet{main: "schemas/main.schema.json"}

	_, err := compileSchemaSet(fsys, set)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unresolved")
	require.Contains(t, err.Error(), remote)
	require.Zero(t, requests.Load(),
		"compileSchemaSet must never fetch remote schemas")
}

func TestCompileSchemaSet_Errors(t *testing.T) {
	validMain := &fstest.MapFile{Data: []byte(`{
		"$id": "http://example.com/main.schema.json",
		"type": "object"
	}`)}

	tests := []struct {
		scenario string
		fsys     fstest.MapFS
		set      schemaSet
		wantErr  string
	}{
		{
			scenario: "missing main schema file",
			fsys:     fstest.MapFS{},
			set:      schemaSet{main: "schemas/missing.schema.json"},
			wantErr:  "reading embedded schema",
		},
		{
			scenario: "missing subschema file",
			fsys:     fstest.MapFS{"schemas/main.schema.json": validMain},
			set: schemaSet{
				main: "schemas/main.schema.json",
				subs: []subschema{
					{uri: "http://example.com/sub.schema.json", path: "schemas/missing.schema.json"},
				},
			},
			wantErr: "reading embedded subschema",
		},
		{
			scenario: "main schema is not JSON",
			fsys: fstest.MapFS{
				"schemas/main.schema.json": {Data: []byte("not-json")},
			},
			set:     schemaSet{main: "schemas/main.schema.json"},
			wantErr: "compiling schema",
		},
		{
			scenario: "subschema is not JSON",
			fsys: fstest.MapFS{
				"schemas/main.schema.json": validMain,
				"schemas/sub.schema.json":  {Data: []byte("not-json")},
			},
			set: schemaSet{
				main: "schemas/main.schema.json",
				subs: []subschema{
					{uri: "http://example.com/sub.schema.json", path: "schemas/sub.schema.json"},
				},
			},
			wantErr: "compiling subschema",
		},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			_, err := compileSchemaSet(tt.fsys, tt.set)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestSchemaSets_EveryEmbeddedSchemaDeclared closes the audit gap between the
// //go:embed glob and schemaSets: a schema file that is embedded but not
// declared in any set would ship in the binary with its $refs unaudited by
// TestSchemaSets_AllExternalRefsDeclared, which iterates sets only.
func TestSchemaSets_EveryEmbeddedSchemaDeclared(t *testing.T) {
	declared := map[string]struct{}{}
	for _, set := range schemaSets {
		declared[set.main] = struct{}{}
		for _, sub := range set.subs {
			declared[sub.path] = struct{}{}
		}
	}
	files, err := fs.Glob(schemaFS, "schemas/*.schema.json")
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, f := range files {
		_, ok := declared[f]
		require.Truef(t, ok,
			"%s is embedded but not declared in any schemaSet - its $refs are unaudited; declare it or remove the file", f)
	}
}

// TestStrictCompiler_IDNEmailFormat pins the idn-email format validator:
// AssertFormat is on, so an unknown format would reject every value, while
// the previous accept-all shim let malformed addresses through.
func TestStrictCompiler_IDNEmailFormat(t *testing.T) {
	schema, err := newStrictCompiler().Compile([]byte(`{"type": "string", "format": "idn-email"}`))
	require.NoError(t, err)

	for _, valid := range []string{
		"user@example.com",
		"Real Name <user@example.com>",
		"tester@例え.jp", // RFC 6532 internationalized domain
	} {
		require.Truef(t, schema.Validate([]byte(fmt.Sprintf("%q", valid))).Valid,
			"%q must be accepted", valid)
	}
	for _, invalid := range []string{
		"not-an-email",
		"missing-at.example.com",
		"two@@example.com",
	} {
		require.Falsef(t, schema.Validate([]byte(fmt.Sprintf("%q", invalid))).Valid,
			"%q must be rejected", invalid)
	}
}
