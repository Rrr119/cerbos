// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package impact

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/util"
	"google.golang.org/protobuf/types/known/structpb"
)

// GeneratedCase describes one generated table row and the branch it covers.
type GeneratedCase struct {
	TableName    string
	BranchID     string
	BranchKind   BranchKind
	PrincipalKey string
	ResourceKey  string
	Action       string
	Expected     effectv1.Effect
}

// BranchCoverage records whether a diff branch has a generated case.
type BranchCoverage struct {
	BranchID string   `json:"branchId" yaml:"branchId"`
	Kind     string   `json:"kind" yaml:"kind"`
	Covered  bool     `json:"covered" yaml:"covered"`
	Cases    []string `json:"cases,omitempty" yaml:"cases,omitempty"`
}

// CoverageReport maps every diff branch to its generated cases.
type CoverageReport struct {
	BranchCount  int              `json:"branchCount" yaml:"branchCount"`
	CoveredCount int              `json:"coveredCount" yaml:"coveredCount"`
	Complete     bool             `json:"complete" yaml:"complete"`
	Percent      float64          `json:"percent" yaml:"percent"`
	Branches     []BranchCoverage `json:"branches" yaml:"branches"`
}

// GeneratedSuite is the result of test generation.
type GeneratedSuite struct {
	// Suite is the Cerbos TestSuite proto, directly compatible with cerbos verify.
	Suite *policyv1.TestSuite
	// YAML is the serialised suite in the existing *_test.yaml format.
	YAML []byte
	// Cases are the generated table entries in branch order.
	Cases []GeneratedCase
	// Coverage proves that every diff branch has at least one case.
	Coverage *CoverageReport
}

// GenerateOption customises suite generation.
type GenerateOption func(*genConfig)

type genConfig struct {
	suiteName        string
	suiteDescription string
}

// WithSuiteName sets the generated test suite name.
func WithSuiteName(name string) GenerateOption {
	return func(c *genConfig) { c.suiteName = name }
}

// WithSuiteDescription sets the generated test suite description.
func WithSuiteDescription(desc string) GenerateOption {
	return func(c *genConfig) { c.suiteDescription = desc }
}

// GenerateTestSuite creates a Cerbos-compatible test suite covering every diff
// branch in the report. Each branch gets its own test table with dedicated
// principal/resource fixtures and an expectation derived from the diff.
func GenerateTestSuite(report *Report, opts ...GenerateOption) (*GeneratedSuite, error) {
	cfg := genConfig{
		suiteName:        "PolicyChangeImpactSuite",
		suiteDescription: "Auto-generated impact tests covering every branch of the policy diff.",
	}
	for _, o := range opts {
		o(&cfg)
	}

	coverage := &CoverageReport{}
	if report == nil || len(report.Branches) == 0 {
		coverage.Complete = true
		coverage.Percent = 100
		return &GeneratedSuite{Coverage: coverage}, nil
	}

	suite := &policyv1.TestSuite{
		Name:        cfg.suiteName,
		Description: cfg.suiteDescription,
		Principals:  map[string]*enginev1.Principal{},
		Resources:   map[string]*enginev1.Resource{},
	}

	gc := &GeneratedSuite{Suite: suite}
	caseNamesByBranch := map[string][]string{}

	for i, b := range report.Branches {
		idx := i + 1
		pKey, principal := buildPrincipalFixture(b, idx)
		rKey, resource := buildResourceFixture(b, idx)
		action := probeAction(b.Action)
		expected := parseEffect(b.ExpectedEffect)

		suite.Principals[pKey] = principal
		suite.Resources[rKey] = resource

		tableName := fmt.Sprintf("impact-%03d %s %s/%s as %s",
			idx, b.Kind, b.Resource, action, shortSelector(b.Selector))

		description := fmt.Sprintf("branch=%s", b.ID)
		if b.OldEffect != "" || b.NewEffect != "" {
			description += fmt.Sprintf(" effects=%s -> %s", effectOrNone(b.OldEffect), effectOrNone(b.NewEffect))
		}

		table := &policyv1.TestTable{
			Name:        tableName,
			Description: description,
			Input: &policyv1.TestTable_Input{
				Principals: []string{pKey},
				Resources:  []string{rKey},
				Actions:    []string{action},
			},
			Expected: []*policyv1.TestTable_Expectation{
				{
					Principal: pKey,
					Resource:  rKey,
					Actions:   map[string]effectv1.Effect{action: expected},
				},
			},
		}
		suite.Tests = append(suite.Tests, table)

		gc.Cases = append(gc.Cases, GeneratedCase{
			TableName:    tableName,
			BranchID:     b.ID,
			BranchKind:   b.Kind,
			PrincipalKey: pKey,
			ResourceKey:  rKey,
			Action:       action,
			Expected:     expected,
		})
		caseNamesByBranch[b.ID] = append(caseNamesByBranch[b.ID], tableName)
	}

	for _, b := range report.Branches {
		names := caseNamesByBranch[b.ID]
		bc := BranchCoverage{
			BranchID: b.ID,
			Kind:     string(b.Kind),
			Covered:  len(names) > 0,
			Cases:    names,
		}
		coverage.Branches = append(coverage.Branches, bc)
		coverage.BranchCount++
		if bc.Covered {
			coverage.CoveredCount++
		}
	}
	coverage.Complete = coverage.CoveredCount == coverage.BranchCount
	if coverage.BranchCount > 0 {
		coverage.Percent = float64(coverage.CoveredCount) / float64(coverage.BranchCount) * 100
	} else {
		coverage.Percent = 100
	}
	gc.Coverage = coverage

	var buf bytes.Buffer
	if err := util.WriteYAML(&buf, suite); err != nil {
		return nil, fmt.Errorf("failed to serialise generated test suite: %w", err)
	}
	gc.YAML = buf.Bytes()
	return gc, nil
}

func buildPrincipalFixture(b Branch, idx int) (string, *enginev1.Principal) {
	key := fmt.Sprintf("p%03d_%s", idx, sanitizeKey(b.Selector))
	principal := &enginev1.Principal{Id: key}

	sel, ok := ParseSelector(b.Selector)
	if !ok {
		principal.Roles = []string{sanitizeKey(b.Selector)}
	} else {
		switch sel.Type {
		case SelectorPrincipal:
			// Principal policies match on the concrete principal ID.
			principal.Id = sel.Name
			// Cerbos principals require at least one role; the placeholder role
			// does not grant anything by itself.
			principal.Roles = []string{"impact_principal_subject"}
		case SelectorRole:
			principal.Roles = []string{sel.Name}
		case SelectorAny:
			principal.Roles = []string{"impact_wildcard_role_holder"}
		case SelectorDerivedRole:
			if len(b.parentRoles) > 0 {
				principal.Roles = dedupSorted(append([]string{}, b.parentRoles...))
			} else {
				principal.Roles = []string{"impact_parent_of_" + sanitizeKey(sel.Name)}
			}
		}
	}

	var attrs map[string]*structpb.Value
	switch b.Outcome {
	case OutcomeMatch:
		attrs, _ = matchAttrs(b.newCondition)
	case OutcomeNoMatch:
		attrs, _ = noMatchAttrs(b.newCondition)
	default:
		if b.newCondition != nil {
			attrs, _ = matchAttrs(b.newCondition)
		}
	}
	if len(attrs) > 0 {
		principal.Attr = attrs
	}
	return key, principal
}

func buildResourceFixture(b Branch, idx int) (string, *enginev1.Resource) {
	kind := b.Resource
	if kind == "" || kind == "*" {
		kind = "impact_probe_resource"
	}
	key := fmt.Sprintf("r%03d_%s", idx, sanitizeKey(b.Resource))
	resource := &enginev1.Resource{
		Kind: kind,
		Id:   fmt.Sprintf("impact-resource-%03d", idx),
	}

	var attrs map[string]*structpb.Value
	switch b.Outcome {
	case OutcomeMatch:
		_, attrs = matchAttrs(b.newCondition)
	case OutcomeNoMatch:
		_, attrs = noMatchAttrs(b.newCondition)
	default:
		if b.newCondition != nil {
			_, attrs = matchAttrs(b.newCondition)
		}
	}
	if len(attrs) > 0 {
		resource.Attr = attrs
	}
	return key, resource
}

var nonKeyChars = regexp.MustCompile(`[^a-zA-Z0-9_]+`)

func sanitizeKey(v string) string {
	s := nonKeyChars.ReplaceAllString(v, "_")
	s = strings.Trim(s, "_")
	if len(s) > 48 {
		h := sha1.Sum([]byte(v))
		s = s[:40] + "_" + hex.EncodeToString(h[:])[:8]
	}
	if s == "" {
		return "x"
	}
	return s
}

func shortSelector(v string) string {
	if idx := strings.Index(v, ":"); idx >= 0 {
		return v[idx+1:]
	}
	return v
}

// probeAction turns a wildcard action pattern into a concrete request action.
func probeAction(pattern string) string {
	if pattern == "" {
		return "impact_probe_action"
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return pattern
	}
	a := strings.NewReplacer("*", "probe", "?", "x").Replace(pattern)
	a = strings.Trim(a, ".")
	if a == "" {
		return "impact_probe_action"
	}
	return a
}

func parseEffect(name string) effectv1.Effect {
	if v, ok := effectv1.Effect_value[name]; ok {
		return effectv1.Effect(v)
	}
	return effectv1.Effect_EFFECT_DENY
}

func effectOrNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
