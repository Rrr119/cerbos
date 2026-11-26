// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package impact

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPatternContainment(t *testing.T) {
	require.True(t, patternCovers("*", "anything"))
	require.True(t, patternCovers("read*", "read-all"))
	require.True(t, patternCovers("read", "read"))
	require.False(t, patternCovers("read", "read-all"))

	// Old "*" already covered every action, so adding a literal action is not
	// a new impact branch; removing "*" in favour of literals is reported.
	require.Empty(t, addedPatterns([]string{"*"}, []string{"*", "create"}))
	require.Equal(t, []string{"*"}, removedPatterns([]string{"*"}, []string{"read", "write"}))

	// Prefix wildcard containment.
	require.Empty(t, addedPatterns([]string{"read*"}, []string{"read-all"}))
	require.Equal(t, []string{"write*"}, addedPatterns([]string{"read*"}, []string{"read-all", "write*"}))
}

func TestPrincipalDirectoryExpansion(t *testing.T) {
	report := Analyze(
		parseScenarioPolicies(t, scenarios[0].oldPolicies),
		parseScenarioPolicies(t, scenarios[0].newPolicies),
	)
	directory := map[string][]string{
		"alice": {"user", "admin"},
		"bob":   {"user"},
		"carol": {"auditor"},
	}

	got := report.ExpandPrincipals(directory)
	want := []Triple{
		T("principal:alice", "contact", "create"),
		T("principal:bob", "contact", "create"),
	}
	require.Equal(t, want, got)
}

func TestUnnamedRulesPairByOverlap(t *testing.T) {
	oldYAML := `---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: widget
  rules:
    - actions: ["read", "write"]
      effect: EFFECT_ALLOW
      roles: ["maker"]
`
	newYAML := `---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: widget
  rules:
    - actions: ["read", "write", "publish"]
      effect: EFFECT_ALLOW
      roles: ["maker"]
`
	report := Analyze(
		parseScenarioPolicies(t, []string{oldYAML}),
		parseScenarioPolicies(t, []string{newYAML}),
	)
	require.Equal(t, []Triple{T("role:maker", "widget", "publish")}, report.Impact.Triples)
	require.Len(t, report.Branches, 1)
	require.Equal(t, BranchActionAdded, report.Branches[0].Kind)
}

func TestLoadPoliciesFromPathsIgnoresTests(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(scenarios[0].newPolicies[0]), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "policy_test.yaml"), []byte("name: x\n"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "testdata"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "testdata", "skip.yaml"), []byte("x"), 0o600))

	policies, err := LoadPoliciesFromPaths(dir)
	require.NoError(t, err)
	require.Len(t, policies, 1)

	policies, err = LoadPoliciesFromPaths(filepath.Join(dir, "policy.yaml"))
	require.NoError(t, err)
	require.Len(t, policies, 1)
}

func TestEmptyDiffGeneratesNoSuite(t *testing.T) {
	p := parseScenarioPolicies(t, scenarios[0].newPolicies)
	report := Analyze(p, p)
	require.Empty(t, report.Branches)
	gen, err := GenerateTestSuite(report)
	require.NoError(t, err)
	require.Nil(t, gen.Suite)
	require.True(t, gen.Coverage.Complete)
}

func TestReportJSONRoundTrip(t *testing.T) {
	report := Analyze(
		parseScenarioPolicies(t, scenarios[5].oldPolicies),
		parseScenarioPolicies(t, scenarios[5].newPolicies),
	)

	dir := t.TempDir()
	jf := filepath.Join(dir, "report.json")
	f, err := os.Create(jf)
	require.NoError(t, err)
	require.NoError(t, report.RenderJSON(f))
	require.NoError(t, f.Close())

	data, err := os.ReadFile(jf)
	require.NoError(t, err)
	require.Contains(t, string(data), "CONDITION_ADDED")
	require.Contains(t, string(data), "leave_request")
}

func TestConditionSynthesis(t *testing.T) {
	p := parseScenarioPolicies(t, scenarios[5].newPolicies)[0]
	cond := p.GetResourcePolicy().Rules[0].Condition

	_, resMatch := matchAttrs(cond)
	require.Equal(t, "draft", resMatch["status"].GetStringValue())

	_, resNoMatch := noMatchAttrs(cond)
	require.NotEqual(t, "draft", resNoMatch["status"].GetStringValue())
}
