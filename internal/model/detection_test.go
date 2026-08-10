package model_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/OmniTrustILM/cbom-lens/internal/model"
	"github.com/OmniTrustILM/cbom-lens/internal/model/cbom"

	"github.com/stretchr/testify/require"
)

// detectionTypeConstants returns every DetectionType constant declared in the
// Go file at path, as constant name -> wire string.
//
// It reads the source rather than the package because the two packages'
// constants are untyped-at-a-distance twins: nothing in either package
// enumerates them, so a set can only be recovered from the declarations
// themselves. A test written as a hand-maintained table cannot do this, which
// is the whole point -- see TestDetectionTypesMatchCBOMTwins.
//
// Only `Name DetectionType = "VALUE"` specs count. A const of another type in
// the same block is skipped, and a value that is not a plain string literal
// fails the test rather than being ignored: silently skipping it would let a
// constant leave the compared set without anyone noticing.
func detectionTypeConstants(t *testing.T, path string) map[string]string {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	require.NoError(t, err, "parsing %s", path)

	out := map[string]string{}
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			continue
		}
		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			typeIdent, ok := valueSpec.Type.(*ast.Ident)
			if !ok || typeIdent.Name != "DetectionType" {
				continue
			}
			require.Len(t, valueSpec.Values, len(valueSpec.Names),
				"%s: every DetectionType constant must state its own value", path)

			for i, name := range valueSpec.Names {
				lit, ok := valueSpec.Values[i].(*ast.BasicLit)
				require.True(t, ok && lit.Kind == token.STRING,
					"%s: %s must be a plain string literal, or this test stops "+
						"seeing it", path, name.Name)
				value, err := strconv.Unquote(lit.Value)
				require.NoError(t, err)
				out[name.Name] = value
			}
		}
	}
	return out
}

// TestDetectionTypesMatchCBOMTwins enforces the "keep the two in sync" note on
// cbom.DetectionType. The 1.7 IR duplicates model.DetectionType with the same
// wire strings until the converter migration removes the old copy.
//
// This used to be a hand-written table, justified as making "a constant added
// to one package and not the other" leave an obvious hole. It did not: adding
// DetectionTypeSSH to internal/model alone left both packages and this test
// green, because a table only checks the rows it lists. Removals and typos
// were caught; additions -- the failure mode it exists for -- were not.
//
// So the constants are enumerated from both source files and the two sets are
// compared. An addition on either side now fails here, named, with no table to
// remember to update.
func TestDetectionTypesMatchCBOMTwins(t *testing.T) {
	t.Parallel()

	modelConstants := detectionTypeConstants(t, filepath.Join("detection.go"))
	cbomConstants := detectionTypeConstants(t, filepath.Join("cbom", "cbom.go"))

	require.NotEmpty(t, modelConstants,
		"no DetectionType constants found in detection.go -- the parse found "+
			"nothing to compare, so this test would pass vacuously")

	// Equal on the whole map rather than key-by-key: testify prints the diff,
	// so the failure names the constant that is missing or the string that
	// drifted, on whichever side it happened.
	require.Equal(t, modelConstants, cbomConstants,
		"internal/model and internal/model/cbom declare different DetectionType "+
			"constants; the two are twins until the converter migration removes "+
			"the old copy")

	// The parse is only worth something if it agrees with the compiler. These
	// are the two ends of the set as the AST sees them, checked against the
	// real symbols so a parser that quietly matched nothing, or matched the
	// wrong declarations, cannot pass.
	require.Equal(t, string(model.DetectionTypeUNKNOWN), modelConstants["DetectionTypeUNKNOWN"])
	require.Equal(t, string(model.DetectionTypeLeakPrivateKey), modelConstants["DetectionTypeLeakPrivateKey"])
	require.Equal(t, string(cbom.DetectionTypeUNKNOWN), cbomConstants["DetectionTypeUNKNOWN"])
	require.Equal(t, string(cbom.DetectionTypeLeakPrivateKey), cbomConstants["DetectionTypeLeakPrivateKey"])
}
