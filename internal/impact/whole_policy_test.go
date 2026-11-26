// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package impact

import "testing"

func TestWholePolicyAdditionAndRemoval(t *testing.T) {
	policy := `---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: v1
  resource: ledger
  rules:
    - name: accountant-post
      actions: ["post", "close"]
      effect: EFFECT_ALLOW
      roles: ["accountant"]
`
	p := parseScenarioPolicies(t, []string{policy})

	added := Analyze(nil, p)
	assertTriples(t, added,
		T("role:accountant", "ledger", "post"),
		T("role:accountant", "ledger", "close"),
	)
	for _, b := range added.Branches {
		if b.Kind != BranchRuleAdded {
			t.Fatalf("expected only RULE_ADDED branches, got %s", b.Kind)
		}
	}

	removed := Analyze(p, nil)
	assertTriples(t, removed,
		T("role:accountant", "ledger", "post"),
		T("role:accountant", "ledger", "close"),
	)
	for _, b := range removed.Branches {
		if b.Kind != BranchRuleRemoved {
			t.Fatalf("expected only RULE_REMOVED branches, got %s", b.Kind)
		}
	}
}

func assertTriples(t *testing.T, r *Report, want ...Triple) {
	t.Helper()
	if len(r.Impact.Triples) != len(want) {
		t.Fatalf("expected %d triples, got %d: %+v", len(want), len(r.Impact.Triples), r.Impact.Triples)
	}
	wantSet := map[Triple]struct{}{}
	for _, w := range want {
		wantSet[w] = struct{}{}
	}
	for _, got := range r.Impact.Triples {
		if _, ok := wantSet[got]; !ok {
			t.Fatalf("unexpected triple %+v in %+v", got, r.Impact.Triples)
		}
	}
}
