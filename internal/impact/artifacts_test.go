// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package impact

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/require"
)

// TestExportTenChangeArtifacts materialises the ten acceptance groups under
// testdata/ten_changes for manual review and for running with
// `cerbos compile`. Regenerate with:
//
//	IMPACT_UPDATE_ARTIFACTS=1 go test ./internal/impact/ -run TestExportTenChangeArtifacts
func TestExportTenChangeArtifacts(t *testing.T) {
	if os.Getenv("IMPACT_UPDATE_ARTIFACTS") == "" {
		t.Skip("set IMPACT_UPDATE_ARTIFACTS=1 to write scenario artifacts")
	}

	root := filepath.Join("testdata", "ten_changes")
	require.NoError(t, os.MkdirAll(root, 0o755))

	for _, sc := range scenarios {
		dir := filepath.Join(root, sc.name)
		require.NoError(t, os.MkdirAll(dir, 0o755))

		writePolicyDir(t, filepath.Join(dir, "old"), sc.oldPolicies)
		writePolicyDir(t, filepath.Join(dir, "new"), sc.newPolicies)

		expected := struct {
			Name       string   `yaml:"name"`
			Rationale  string   `yaml:"manual_derivation"`
			Principals []string `yaml:"affected_principals"`
			Resources  []string `yaml:"affected_resources"`
			Actions    []string `yaml:"affected_actions"`
			Triples    []Triple `yaml:"impact_set"`
			Branches   []string `yaml:"expected_branch_kinds"`
		}{
			Name:       sc.name,
			Rationale:  sc.rationale,
			Principals: distinctPrincipals(sc.wantTriples),
			Resources:  distinctResources(sc.wantTriples),
			Actions:    distinctActions(sc.wantTriples),
			Triples:    sc.wantTriples,
		}
		for _, k := range sc.wantKinds {
			expected.Branches = append(expected.Branches, string(k))
		}
		data, err := yaml.Marshal(expected)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "expected_impact.yaml"), data, 0o644))

		report := Analyze(parseScenarioPolicies(t, sc.oldPolicies), parseScenarioPolicies(t, sc.newPolicies))
		gen, err := GenerateTestSuite(report, WithSuiteName("Impact_"+sc.name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "impact_generated_test.yaml"), gen.YAML, 0o644))

		writePolicyDir(t, filepath.Join(dir, "verify"), sc.newPolicies)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "verify", "impact_test.yaml"), gen.YAML, 0o644))

		cov, err := json.MarshalIndent(gen.Coverage, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "coverage.json"), cov, 0o644))
	}
}

func writePolicyDir(t *testing.T, dir string, docs []string) {
	t.Helper()
	for i, d := range docs {
		require.NoError(t, os.MkdirAll(dir, 0o755))
		name := filepath.Join(dir, fmt.Sprintf("policy_%02d.yaml", i+1))
		require.NoError(t, os.WriteFile(name, []byte(d), 0o644))
	}
}
