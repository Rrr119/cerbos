// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package impact analyses changes between two sets of Cerbos policies and
// generates Cerbos-compatible test suites that cover every branch of the
// detected diff.
//
// The analysis is performed purely on the policy definitions: no running
// Policy Decision Point is required. An "impact triple" is the smallest
// principal/resource/action decision cell whose effective decision may differ
// between the old and the new policy revision.
//
// Principals are represented by the selector that the policy rule uses:
//
//   - "role:<name>"          for entries in a resource rule's roles list
//   - "derived_role:<name>"  for entries in a resource rule's derived_roles list
//   - "principal:<id>"       for principal policies (the concrete principal ID)
//   - "any"                  for wildcard role selectors
//
// Use Report.ExpandPrincipals to resolve role selectors against a principal
// directory when one is available.
package impact

import (
	"cmp"
	"slices"
	"strings"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

// ChangeKind classifies how an impact cell or branch changed.
type ChangeKind string

const (
	// ChangeAdded means the cell is newly governed by an allowing/denying rule.
	ChangeAdded ChangeKind = "ADDED"
	// ChangeRemoved means the cell is no longer governed as before.
	ChangeRemoved ChangeKind = "REMOVED"
	// ChangeModified means the cell still exists but its effect or condition changed.
	ChangeModified ChangeKind = "MODIFIED"
)

// BranchKind identifies the atomic diff facet that produced a branch.
type BranchKind string

const (
	BranchPolicyAdded              BranchKind = "POLICY_ADDED"
	BranchPolicyRemoved            BranchKind = "POLICY_REMOVED"
	BranchRuleAdded                BranchKind = "RULE_ADDED"
	BranchRuleRemoved              BranchKind = "RULE_REMOVED"
	BranchActionAdded              BranchKind = "ACTION_ADDED"
	BranchActionRemoved            BranchKind = "ACTION_REMOVED"
	BranchRoleAdded                BranchKind = "ROLE_ADDED"
	BranchRoleRemoved              BranchKind = "ROLE_REMOVED"
	BranchDerivedRoleAdded         BranchKind = "DERIVED_ROLE_ADDED"
	BranchDerivedRoleRemoved       BranchKind = "DERIVED_ROLE_REMOVED"
	BranchEffectChanged            BranchKind = "EFFECT_CHANGED"
	BranchConditionAdded           BranchKind = "CONDITION_ADDED"
	BranchConditionRemoved         BranchKind = "CONDITION_REMOVED"
	BranchConditionChanged         BranchKind = "CONDITION_CHANGED"
	BranchDerivedRoleDefChanged    BranchKind = "DERIVED_ROLE_DEFINITION_CHANGED"
	BranchDerivedRoleParentAdded   BranchKind = "DERIVED_ROLE_PARENT_ADDED"
	BranchDerivedRoleParentRemoved BranchKind = "DERIVED_ROLE_PARENT_REMOVED"
)

// Condition outcome tags used on condition branches.
const (
	OutcomeMatch   = "match"
	OutcomeNoMatch = "no_match"
)

// SelectorType enumerates the ways a policy rule can name a principal set.
type SelectorType string

const (
	SelectorRole        SelectorType = "role"
	SelectorDerivedRole SelectorType = "derived_role"
	SelectorPrincipal   SelectorType = "principal"
	SelectorAny         SelectorType = "any"
)

// Selector identifies a principal set referenced by a policy rule.
type Selector struct {
	Type SelectorType
	Name string
}

// String renders the canonical "type:name" selector used in Triple.Principal.
func (s Selector) String() string {
	switch s.Type {
	case SelectorAny:
		return "any"
	case SelectorPrincipal:
		return "principal:" + s.Name
	case SelectorDerivedRole:
		return "derived_role:" + s.Name
	default:
		return "role:" + s.Name
	}
}

// ParseSelector parses the canonical selector representation.
func ParseSelector(v string) (Selector, bool) {
	switch {
	case v == "any" || v == "*":
		return Selector{Type: SelectorAny}, true
	case strings.HasPrefix(v, "role:"):
		return Selector{Type: SelectorRole, Name: strings.TrimPrefix(v, "role:")}, true
	case strings.HasPrefix(v, "derived_role:"):
		return Selector{Type: SelectorDerivedRole, Name: strings.TrimPrefix(v, "derived_role:")}, true
	case strings.HasPrefix(v, "principal:"):
		return Selector{Type: SelectorPrincipal, Name: strings.TrimPrefix(v, "principal:")}, true
	default:
		return Selector{}, false
	}
}

// Triple is one impacted principal/resource/action decision cell.
type Triple struct {
	Principal string `json:"principal" yaml:"principal"`
	Resource  string `json:"resource" yaml:"resource"`
	Action    string `json:"action" yaml:"action"`
}

// Entry aggregates all branches touching the same impact Triple.
type Entry struct {
	Triple    `json:",inline" yaml:",inline"`
	Change    ChangeKind `json:"change" yaml:"change"`
	OldEffect string     `json:"oldEffect,omitempty" yaml:"oldEffect,omitempty"`
	NewEffect string     `json:"newEffect,omitempty" yaml:"newEffect,omitempty"`
	PolicyKey string     `json:"policyKey" yaml:"policyKey"`
	Rule      string     `json:"rule,omitempty" yaml:"rule,omitempty"`
	Branches  []string   `json:"branches" yaml:"branches"`
}

// Branch is one atomic diff branch. The generator emits at least one test
// case per branch ID.
type Branch struct {
	ID        string     `json:"id" yaml:"id"`
	Kind      BranchKind `json:"kind" yaml:"kind"`
	Outcome   string     `json:"outcome,omitempty" yaml:"outcome,omitempty"`
	Change    ChangeKind `json:"change" yaml:"change"`
	PolicyKey string     `json:"policyKey" yaml:"policyKey"`
	Rule      string     `json:"rule,omitempty" yaml:"rule,omitempty"`
	Selector  string     `json:"selector" yaml:"selector"`
	Resource  string     `json:"resource" yaml:"resource"`
	Action    string     `json:"action" yaml:"action"`
	OldEffect string     `json:"oldEffect,omitempty" yaml:"oldEffect,omitempty"`
	NewEffect string     `json:"newEffect,omitempty" yaml:"newEffect,omitempty"`
	// ExpectedEffect is the effect the generated test case should assert under
	// the new policy revision. It is derived from diff semantics (default deny
	// for cells whose matching rule was removed).
	ExpectedEffect string `json:"expectedEffect,omitempty" yaml:"expectedEffect,omitempty"`
	Detail         string `json:"detail,omitempty" yaml:"detail,omitempty"`

	// Generation context (not serialised).
	newCondition *policyv1.Condition `json:"-" yaml:"-"`
	oldCondition *policyv1.Condition `json:"-" yaml:"-"`
	parentRoles  []string            `json:"-" yaml:"-"`
}

// Impact is the set of impacted dimensions and decision triples.
type Impact struct {
	Principals []string `json:"principals" yaml:"principals"`
	Resources  []string `json:"resources" yaml:"resources"`
	Actions    []string `json:"actions" yaml:"actions"`
	Triples    []Triple `json:"triples" yaml:"triples"`
}

// PolicyChange summarises a changed policy.
type PolicyChange struct {
	Key    string     `json:"key" yaml:"key"`
	Kind   string     `json:"kind" yaml:"kind"`
	Change ChangeKind `json:"change" yaml:"change"`
}

// Report is the complete result of analysing an old/new policy revision.
type Report struct {
	Summary       string         `json:"summary,omitempty" yaml:"summary,omitempty"`
	Impact        Impact         `json:"impact" yaml:"impact"`
	Entries       []Entry        `json:"entries" yaml:"entries"`
	Branches      []Branch       `json:"branches" yaml:"branches"`
	PolicyChanges []PolicyChange `json:"policyChanges" yaml:"policyChanges"`
	// ResolvedTriples optionally holds concrete principal triples after
	// ExpandPrincipals against a principal directory.
	ResolvedTriples []Triple `json:"resolvedTriples,omitempty" yaml:"resolvedTriples,omitempty"`
}

func effectName(e effectv1.Effect) string {
	switch e {
	case effectv1.Effect_EFFECT_ALLOW:
		return "EFFECT_ALLOW"
	case effectv1.Effect_EFFECT_DENY:
		return "EFFECT_DENY"
	default:
		return "EFFECT_UNSPECIFIED"
	}
}

func dedupSorted[S ~[]E, E cmp.Ordered](s S) S {
	if len(s) == 0 {
		return s
	}
	seen := make(map[E]struct{}, len(s))
	out := make(S, 0, len(s))
	for _, v := range s {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}
