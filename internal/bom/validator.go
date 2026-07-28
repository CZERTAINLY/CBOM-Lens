package bom

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	jss "github.com/kaptinlin/jsonschema"
)

//go:embed schemas/*.schema.json
var schemaFS embed.FS

// subschema is one embedded schema file registered under the absolute URI
// that $refs in other schemas of the set resolve to (relative $refs resolve
// against the base URI derived from the referencing schema's $id).
type subschema struct {
	uri  string
	path string
}

// schemaSet describes one CycloneDX schema and the subschemas its $refs
// resolve to. subs is ordered: subschemas are compiled first, in slice order,
// so a subschema may $ref only subschemas listed before it.
type schemaSet struct {
	main string
	subs []subschema
}

// schemaSets maps each supported spec version to its embedded schema files.
// CycloneDX 1.7 (issue #175, ticket 2) will add bom-1.7.schema.json together
// with its cryptography-defs.schema.json subschema here.
var schemaSets = map[cdx.SpecVersion]schemaSet{
	cdx.SpecVersion1_6: {
		main: "schemas/bom-1.6.schema.json",
		subs: []subschema{
			{uri: "http://cyclonedx.org/schema/spdx.schema.json", path: "schemas/spdx.schema.json"},
			{uri: "http://cyclonedx.org/schema/jsf-0.82.schema.json", path: "schemas/jsf-0.82.schema.json"},
		},
	},
}

// Validator validates the CycloneDX BOM against the schema
type Validator struct {
	schemas map[cdx.SpecVersion]*jss.Schema
}

func NewValidator(versions ...cdx.SpecVersion) (Validator, error) {
	var zero Validator
	if len(versions) == 0 {
		return zero, errors.New("no schema versions given: at least one CycloneDX spec version is required")
	}
	schemas := make(map[cdx.SpecVersion]*jss.Schema, len(versions))
	for _, ver := range versions {
		set, ok := schemaSets[ver]
		if !ok {
			return zero, fmt.Errorf("unknown schema version: %s", ver)
		}
		schema, err := compileSchemaSet(schemaFS, set)
		if err != nil {
			return zero, err
		}
		schemas[ver] = schema
	}
	return Validator{
		schemas: schemas,
	}, nil
}

// newStrictCompiler returns a schema compiler with every remote loader
// removed, so $refs can only resolve against explicitly registered schemas.
// The library's default compiler would otherwise fetch http(s) $refs over the
// network at compile time and silently skip them on failure.
func newStrictCompiler() *jss.Compiler {
	compiler := jss.NewCompiler()
	clear(compiler.Loaders)
	// Enforce "format" keywords (the library defaults AssertFormat to
	// false). Without this, jsf-0.82's signer.algorithm, a oneOf of
	// [enum of standard algorithms, {type: string, format: "uri"}], is
	// validated inverted: the uri branch matches any string, so standard
	// algorithms match both branches (a oneOf violation) while garbage
	// matches exactly one.
	compiler.SetAssertFormat(true)
	// The library has no built-in validator for "idn-email" (used by
	// bom-1.6's organizationalContact.email and identifiableAction.email);
	// with AssertFormat on, an unknown format rejects every value. Register
	// an accept-all validator to keep the annotation-only semantics the
	// draft prescribes for unknown formats.
	compiler.RegisterFormat("idn-email", func(any) bool { return true })
	return compiler
}

// compileSchemaSet compiles the schema set from fsys into a single schema
// with all $refs resolved offline, failing closed on any unresolved $ref.
func compileSchemaSet(fsys fs.FS, set schemaSet) (*jss.Schema, error) {
	compiler := newStrictCompiler()

	// compiled tracks every schema of the set for the unresolved-refs gate
	// below: an unresolved $ref inside a registered subschema is just as
	// silently fail-open at validate time as one in the main schema.
	type compiled struct {
		path   string
		schema *jss.Schema
	}
	all := make([]compiled, 0, len(set.subs)+1)

	// The subschemas must be compiled before the main schema: the library
	// retro-resolves pending $refs keyed by the raw (relative) ref string,
	// which never matches the absolute URIs the main schema resolves against.
	for _, sub := range set.subs {
		data, err := fs.ReadFile(fsys, sub.path)
		if err != nil {
			return nil, fmt.Errorf("reading embedded subschema %s: %w", sub.path, err)
		}
		subSchema, err := compiler.Compile(data, sub.uri)
		if err != nil {
			return nil, fmt.Errorf("compiling subschema %s: %w", sub.uri, err)
		}
		// Belt and braces: force-register the subschema under the absolute
		// URI, even when its $id already matches it.
		compiler.SetSchema(sub.uri, subSchema)
		all = append(all, compiled{path: sub.path, schema: subSchema})
	}

	data, err := fs.ReadFile(fsys, set.main)
	if err != nil {
		return nil, fmt.Errorf("reading embedded schema %s: %w", set.main, err)
	}
	schema, err := compiler.Compile(data)
	if err != nil {
		return nil, fmt.Errorf("compiling schema %s: %w", set.main, err)
	}
	all = append(all, compiled{path: set.main, schema: schema})

	// Fail closed: the library silently skips unresolved $refs at validate
	// time (they impose no constraints), so refuse to build a validator with
	// any $ref left dangling in any schema of the set. The gate runs after
	// all schemas compiled, so legitimate sub-to-sub references do not
	// trigger false positives. Note the library's schema walker does not
	// descend into every keyword position (e.g. if/then/else), so a $ref
	// hidden there would escape this gate; clearing the loaders only
	// guarantees such a ref is never fetched, not that it fails validation.
	// The actual mitigation for the walker's blind spots is
	// TestSchemaSets_AllExternalRefsDeclared, which audits the raw JSON of
	// every embedded schema for undeclared external $refs.
	var unresolved []string
	for _, c := range all {
		for _, uri := range c.schema.UnresolvedReferenceURIs() {
			unresolved = append(unresolved, fmt.Sprintf("%s: %s", c.path, uri))
		}
	}
	if len(unresolved) > 0 {
		return nil, fmt.Errorf("schema set for %s has unresolved references: %s",
			set.main, strings.Join(unresolved, ", "))
	}
	return schema, nil
}

func (v Validator) Validate(bom *cdx.BOM) error {
	schema, err := v.versionToSchema(bom.SpecVersion)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	encoder := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	err = encoder.Encode(bom)
	if err != nil {
		return fmt.Errorf("encoding bom to JSON: %w", err)
	}
	return v.validateBytes(schema, buf.Bytes())
}

func (v Validator) ValidateBytes(b []byte) error {
	var bom struct {
		SpecVersion cdx.SpecVersion `json:"specVersion"`
	}
	err := json.Unmarshal(b, &bom)
	if err != nil {
		return fmt.Errorf("reading spec version: %w", err)
	}

	schema, err := v.versionToSchema(bom.SpecVersion)
	if err != nil {
		return err
	}
	return v.validateBytes(schema, b)
}

func (v Validator) versionToSchema(version cdx.SpecVersion) (*jss.Schema, error) {
	schema, ok := v.schemas[version]
	if !ok {
		supported := make([]string, 0, len(v.schemas))
		for k := range v.schemas {
			supported = append(supported, k.String())
		}
		return nil, fmt.Errorf("unsupported BOM specification version: supported %s: got: %s",
			strings.Join(supported, ","),
			version,
		)
	}
	return schema, nil
}

func (v Validator) validateBytes(schema *jss.Schema, b []byte) error {
	res := schema.Validate(b)
	if !res.Valid {
		var errorMsgs []string
		for _, err := range res.Errors {
			errorMsgs = append(errorMsgs, fmt.Sprintf("%s: %s", err.Keyword, err.Error()))
		}
		// Join all errors with newlines for readability
		return fmt.Errorf("BOM validation failed:\n%s", strings.Join(errorMsgs, "\n"))
	}
	return nil
}
