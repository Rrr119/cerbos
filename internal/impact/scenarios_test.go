// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package impact

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/parser"
)

// scenario is one hand-derived policy change. WantTriples is the impact set
// obtained by manual policy review; WantKinds is the expected multiset of
// diff branch kinds (one entry per branch, condition outcomes duplicated).
type scenario struct {
	name         string
	rationale    string
	oldPolicies  []string
	newPolicies  []string
	wantTriples  []Triple
	wantKinds    []BranchKind
	directory    map[string][]string
	wantResolved []Triple
}

func T(principal, resource, action string) Triple {
	return Triple{Principal: principal, Resource: resource, Action: action}
}

var scenarios = []scenario{
	{
		name:      "01_action_added_to_allow_rule",
		rationale: "create is newly added to the user rule on contact; user/contact/create flips DENY->ALLOW. read is unchanged.",
		oldPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: contact
  rules:
    - name: user-access
      actions: ["read"]
      effect: EFFECT_ALLOW
      roles: ["user"]
`},
		newPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: contact
  rules:
    - name: user-access
      actions: ["read", "create"]
      effect: EFFECT_ALLOW
      roles: ["user"]
`},
		wantTriples: []Triple{T("role:user", "contact", "create")},
		wantKinds:   []BranchKind{BranchActionAdded},
	},
	{
		name:      "02_action_removed_from_allow_rule",
		rationale: "delete is removed from the editor rule on document; editor/document/delete flips ALLOW->DENY.",
		oldPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: document
  rules:
    - name: editor-access
      actions: ["read", "write", "delete"]
      effect: EFFECT_ALLOW
      roles: ["editor"]
`},
		newPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: document
  rules:
    - name: editor-access
      actions: ["read", "write"]
      effect: EFFECT_ALLOW
      roles: ["editor"]
`},
		wantTriples: []Triple{T("role:editor", "document", "delete")},
		wantKinds:   []BranchKind{BranchActionRemoved},
	},
	{
		name:      "03_effect_flip_allow_to_deny",
		rationale: "the manager approve rule flips ALLOW->DENY; the single cell manager/invoice/approve is impacted.",
		oldPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: invoice
  rules:
    - name: manager-approve
      actions: ["approve"]
      effect: EFFECT_ALLOW
      roles: ["manager"]
`},
		newPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: invoice
  rules:
    - name: manager-approve
      actions: ["approve"]
      effect: EFFECT_DENY
      roles: ["manager"]
`},
		wantTriples: []Triple{T("role:manager", "invoice", "approve")},
		wantKinds:   []BranchKind{BranchEffectChanged},
	},
	{
		name:      "04_role_added_to_rule",
		rationale: "manager is added to the auditor view rule; manager/report/view becomes allowed. auditor/report/view is unchanged.",
		oldPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: report
  rules:
    - name: view-report
      actions: ["view"]
      effect: EFFECT_ALLOW
      roles: ["auditor"]
`},
		newPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: report
  rules:
    - name: view-report
      actions: ["view"]
      effect: EFFECT_ALLOW
      roles: ["auditor", "manager"]
`},
		wantTriples: []Triple{T("role:manager", "report", "view")},
		wantKinds:   []BranchKind{BranchRoleAdded},
	},
	{
		name:      "05_role_removed_from_rule",
		rationale: "viewer is dropped from the document read rule; viewer/document/read loses access. editor is unchanged.",
		oldPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: document
  rules:
    - name: read-document
      actions: ["read"]
      effect: EFFECT_ALLOW
      roles: ["editor", "viewer"]
`},
		newPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: document
  rules:
    - name: read-document
      actions: ["read"]
      effect: EFFECT_ALLOW
      roles: ["editor"]
`},
		wantTriples: []Triple{T("role:viewer", "document", "read")},
		wantKinds:   []BranchKind{BranchRoleRemoved},
	},
	{
		name:      "06_condition_added",
		rationale: "the unconditional employee create rule becomes conditional on status==draft. The cell employee/leave_request/create is impacted and splits into match/no_match branches.",
		oldPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: leave_request
  rules:
    - name: create-request
      actions: ["create"]
      effect: EFFECT_ALLOW
      roles: ["employee"]
`},
		newPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: leave_request
  rules:
    - name: create-request
      actions: ["create"]
      effect: EFFECT_ALLOW
      roles: ["employee"]
      condition:
        match:
          expr: request.resource.attr.status == "draft"
`},
		wantTriples: []Triple{T("role:employee", "leave_request", "create")},
		wantKinds:   []BranchKind{BranchConditionAdded, BranchConditionAdded},
	},
	{
		name:      "07_rule_added",
		rationale: "a new viewer comment rule is added to the blog policy; viewer/blog/comment is the only new cell.",
		oldPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: blog
  rules:
    - name: reader-read
      actions: ["read"]
      effect: EFFECT_ALLOW
      roles: ["reader"]
`},
		newPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: blog
  rules:
    - name: reader-read
      actions: ["read"]
      effect: EFFECT_ALLOW
      roles: ["reader"]
    - name: viewer-comment
      actions: ["comment"]
      effect: EFFECT_ALLOW
      roles: ["viewer"]
`},
		wantTriples: []Triple{T("role:viewer", "blog", "comment")},
		wantKinds:   []BranchKind{BranchRuleAdded},
	},
	{
		name:      "08_rule_removed",
		rationale: "the contractor download ALLOW rule is deleted; contractor/file/download falls through to default deny. The unchanged admin rule produces no impact.",
		oldPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: file
  rules:
    - name: admin-manage
      actions: ["read", "write", "delete"]
      effect: EFFECT_ALLOW
      roles: ["admin"]
    - name: contractor-download
      actions: ["download"]
      effect: EFFECT_ALLOW
      roles: ["contractor"]
`},
		newPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: file
  rules:
    - name: admin-manage
      actions: ["read", "write", "delete"]
      effect: EFFECT_ALLOW
      roles: ["admin"]
`},
		wantTriples: []Triple{T("role:contractor", "file", "download")},
		wantKinds:   []BranchKind{BranchRuleRemoved},
	},
	{
		name:      "09_principal_policy_action_added",
		rationale: "principal alice gains export on report in her principal policy; the concrete principal cell principal:alice/report/export is impacted.",
		oldPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
principalPolicy:
  principal: alice
  version: default
  rules:
    - resource: report
      actions:
        - name: alice-view
          action: view
          effect: EFFECT_ALLOW
`},
		newPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
principalPolicy:
  principal: alice
  version: default
  rules:
    - resource: report
      actions:
        - name: alice-view
          action: view
          effect: EFFECT_ALLOW
        - name: alice-export
          action: export
          effect: EFFECT_ALLOW
`},
		wantTriples: []Triple{T("principal:alice", "report", "export")},
		wantKinds:   []BranchKind{BranchActionAdded},
	},
	{
		name:      "10_derived_role_parent_added_propagates",
		rationale: "the project_admin derived role gains owner as a parent role. The resource policy importing team_roles and using project_admin on project/update is affected at the derived-role selector level, and owner/project/update is the newly granted concrete role cell.",
		oldPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
derivedRoles:
  name: team_roles
  definitions:
    - name: project_admin
      parentRoles: ["admin"]
`, `---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: project
  importDerivedRoles: ["team_roles"]
  rules:
    - name: admin-update
      actions: ["update"]
      effect: EFFECT_ALLOW
      derivedRoles: ["project_admin"]
`},
		newPolicies: []string{`---
apiVersion: api.cerbos.dev/v1
derivedRoles:
  name: team_roles
  definitions:
    - name: project_admin
      parentRoles: ["admin", "owner"]
`, `---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: project
  importDerivedRoles: ["team_roles"]
  rules:
    - name: admin-update
      actions: ["update"]
      effect: EFFECT_ALLOW
      derivedRoles: ["project_admin"]
`},
		wantTriples: []Triple{
			T("derived_role:project_admin", "project", "update"),
			T("role:owner", "project", "update"),
		},
		wantKinds: []BranchKind{
			BranchDerivedRoleDefChanged,
			BranchDerivedRoleParentAdded,
		},
	},
}

func parseScenarioPolicies(t *testing.T, yamls []string) []*policyv1.Policy {
	t.Helper()
	var out []*policyv1.Policy
	for _, doc := range yamls {
		p, err := ParsePolicyYAML(doc)
		require.NoError(t, err)
		out = append(out, p)
	}
	return out
}

// TestTenScenarioImpactSets is the headline acceptance test: for ten policy
// changes, the computed impact set must exactly match the manually derived
// principal/resource/action set.
func TestTenScenarioImpactSets(t *testing.T) {
	require.Len(t, scenarios, 10, "acceptance requires exactly 10 policy-change groups")

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			oldP := parseScenarioPolicies(t, sc.oldPolicies)
			newP := parseScenarioPolicies(t, sc.newPolicies)

			report := Analyze(oldP, newP)

			if diff := cmp.Diff(sc.wantTriples, report.Impact.Triples); diff != "" {
				t.Fatalf("impact set mismatch vs manual derivation (%s):\n%s", sc.rationale, diff)
			}

			var gotKinds []BranchKind
			for _, b := range report.Branches {
				gotKinds = append(gotKinds, b.Kind)
			}
			if diff := cmp.Diff(sc.wantKinds, gotKinds); diff != "" {
				t.Fatalf("branch kinds mismatch:\n%s", diff)
			}

			// Aggregate dimensions must be derivable from the triples.
			require.ElementsMatch(t, distinctPrincipals(sc.wantTriples), report.Impact.Principals)
			require.ElementsMatch(t, distinctResources(sc.wantTriples), report.Impact.Resources)
			require.ElementsMatch(t, distinctActions(sc.wantTriples), report.Impact.Actions)
		})
	}
}

// TestGeneratedSuitesCoverAllDiffBranches guarantees 100% structural branch
// coverage and that the emitted YAML parses back as a Cerbos TestSuite.
func TestGeneratedSuitesCoverAllDiffBranches(t *testing.T) {
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			report := Analyze(parseScenarioPolicies(t, sc.oldPolicies), parseScenarioPolicies(t, sc.newPolicies))
			gen, err := GenerateTestSuite(report)
			require.NoError(t, err)
			require.NotNil(t, gen.Suite)

			require.True(t, gen.Coverage.Complete, "coverage: %+v", gen.Coverage)
			require.Equal(t, len(report.Branches), gen.Coverage.BranchCount)
			require.Equal(t, len(report.Branches), gen.Coverage.CoveredCount)
			require.InDelta(t, 100.0, gen.Coverage.Percent, 0.001)

			// Every branch ID must be referenced by at least one generated case.
			covered := map[string]bool{}
			for _, c := range gen.Cases {
				covered[c.BranchID] = true
			}
			for _, b := range report.Branches {
				require.True(t, covered[b.ID], "branch not covered: %s", b.ID)
			}

			// The YAML must round-trip through the real Cerbos parser.
			docs, _, err := parser.Unmarshal[policyv1.TestSuite](strings.NewReader(string(gen.YAML)))
			require.NoError(t, err)
			require.Len(t, docs, 1)
			require.NotEmpty(t, docs[0].Tests)
			require.Len(t, docs[0].Tests, len(report.Branches))
		})
	}
}

func distinctPrincipals(ts []Triple) []string {
	set := map[string]struct{}{}
	for _, x := range ts {
		set[x.Principal] = struct{}{}
	}
	return sortedKeys(set)
}

func distinctResources(ts []Triple) []string {
	set := map[string]struct{}{}
	for _, x := range ts {
		set[x.Resource] = struct{}{}
	}
	return sortedKeys(set)
}

func distinctActions(ts []Triple) []string {
	set := map[string]struct{}{}
	for _, x := range ts {
		set[x.Action] = struct{}{}
	}
	return sortedKeys(set)
}
