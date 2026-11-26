// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package impact

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cerbos/internal/verify"
)

// TestGeneratedSuitesPassRealVerifier writes each scenario's new policies and
// the generated test suite to a temporary Cerbos policy directory and runs the
// actual cerbos verify engine. This proves the generated cases are compatible
// with the existing policy/test format and that their expectations match the
// real decision engine.
func TestGeneratedSuitesPassRealVerifier(t *testing.T) {
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			ctx := t.Context()
			newP := parseScenarioPolicies(t, sc.newPolicies)
			report := Analyze(parseScenarioPolicies(t, sc.oldPolicies), newP)
			gen, err := GenerateTestSuite(report)
			require.NoError(t, err)

			dir := t.TempDir()
			for i, p := range newP {
				f, err := os.Create(filepath.Join(dir, policyFileName(i)))
				require.NoError(t, err)
				require.NoError(t, util.WriteYAML(f, p))
				require.NoError(t, f.Close())
			}
			require.NoError(t, os.WriteFile(filepath.Join(dir, "impact_generated_test.yaml"), gen.YAML, 0o600))

			eng := newDiskEngine(t, ctx, dir)

			results, err := verify.Verify(ctx, os.DirFS(dir), eng, verify.Config{})
			require.NoError(t, err)
			require.NotNil(t, results)
			if results.Summary.GetOverallResult() != policyv1.TestResults_RESULT_PASSED {
				t.Fatalf("generated suite did not pass cerbos verify:\n%s", protojson.Format(results))
			}
			require.Equal(t, uint32(len(report.Branches)), results.Summary.GetTestsCount())
		})
	}
}

func policyFileName(i int) string {
	return "policy_" + string(rune('a'+i/26)) + string(rune('a'+i%26)) + ".yaml"
}

func newDiskEngine(t *testing.T, ctx context.Context, dir string) *engine.Engine {
	t.Helper()

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(t, err)

	mgr := compile.NewManager(store)

	ruleTable, err := ruletable.NewRuleTableFromLoader(ctx, mgr)
	require.NoError(t, err)

	schemaMgr, err := schema.New(ctx, store)
	require.NoError(t, err)

	ruletableMgr, err := ruletable.NewRuleTableManager(ruleTable, mgr, schemaMgr)
	require.NoError(t, err)

	eng, err := engine.New(ctx, engine.Components{
		PolicyLoader:      mgr,
		RuleTableManager:  ruletableMgr,
		SchemaMgr:         schemaMgr,
		AuditLog:          audit.NewNopLog(),
		MetadataExtractor: audit.NewMetadataExtractorFromConf(&audit.Conf{}),
	})
	require.NoError(t, err)

	return eng
}
