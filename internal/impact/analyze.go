// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package impact

import (
	"fmt"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

// Analyze compares the old and new policy revisions and returns the impact
// report containing affected principal/resource/action triples and every
// diff branch that the test generator must cover.
func Analyze(oldPolicies, newPolicies []*policyv1.Policy) *Report {
	a := &analyzer{
		oldByKey: indexPolicies(oldPolicies),
		newByKey: indexPolicies(newPolicies),
	}

	for key, np := range a.newByKey {
		op, exists := a.oldByKey[key]
		if !exists {
			a.changes = append(a.changes, PolicyChange{Key: key, Kind: policyKind(np), Change: ChangeAdded})
			a.diffWholePolicy(np, nil)
			continue
		}
		if !proto.Equal(op, np) {
			a.changes = append(a.changes, PolicyChange{Key: key, Kind: policyKind(np), Change: ChangeModified})
			a.diffPolicy(op, np)
		}
	}
	for key, op := range a.oldByKey {
		if _, exists := a.newByKey[key]; !exists {
			a.changes = append(a.changes, PolicyChange{Key: key, Kind: policyKind(op), Change: ChangeRemoved})
			a.diffWholePolicy(op, op)
		}
	}

	a.propagateDerivedRoles()

	return a.finalize()
}

type analyzer struct {
	oldByKey map[string]*policyv1.Policy
	newByKey map[string]*policyv1.Policy
	branches []Branch
	changes  []PolicyChange
}

func indexPolicies(policies []*policyv1.Policy) map[string]*policyv1.Policy {
	m := make(map[string]*policyv1.Policy, len(policies))
	for _, p := range policies {
		m[policyKey(p)] = p
	}
	return m
}

func (a *analyzer) addBranch(b Branch) {
	b.ID = branchIdentity(b)
	a.branches = append(a.branches, b)
}

func branchIdentity(b Branch) string {
	parts := []string{
		string(b.Kind), b.PolicyKey, b.Rule, b.Selector,
		b.Resource, b.Action, b.Outcome, string(b.Change),
	}
	return strings.Join(parts, "|")
}

// diffWholePolicy handles a policy that was added (oldP == nil) or removed
// (newP == nil). Every rule is reported as added/removed.
func (a *analyzer) diffWholePolicy(p *policyv1.Policy, oldP *policyv1.Policy) {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		key := policyKey(p)
		for _, rule := range pt.ResourcePolicy.Rules {
			if oldP == nil {
				a.resourceRuleAdded(key, pt.ResourcePolicy.Resource, rule)
			} else {
				a.resourceRuleRemoved(key, pt.ResourcePolicy.Resource, rule)
			}
		}
	case *policyv1.Policy_PrincipalPolicy:
		key := policyKey(p)
		pp := pt.PrincipalPolicy
		sel := Selector{Type: SelectorPrincipal, Name: pp.Principal}.String()
		for _, pr := range pp.Rules {
			for _, act := range pr.Actions {
				if oldP == nil {
					a.addBranch(Branch{
						Kind: BranchActionAdded, Change: ChangeAdded, PolicyKey: key,
						Rule: act.Name, Selector: sel, Resource: pr.Resource, Action: act.Action,
						NewEffect: effectName(act.Effect), ExpectedEffect: effectName(act.Effect),
						newCondition: act.Condition,
					})
				} else {
					a.addBranch(Branch{
						Kind: BranchActionRemoved, Change: ChangeRemoved, PolicyKey: key,
						Rule: act.Name, Selector: sel, Resource: pr.Resource, Action: act.Action,
						OldEffect: effectName(act.Effect), ExpectedEffect: effectv1.Effect_EFFECT_DENY.String(),
					})
				}
			}
		}
	case *policyv1.Policy_RolePolicy:
		key := policyKey(p)
		role := Selector{Type: SelectorRole, Name: pt.RolePolicy.GetRole()}.String()
		for _, rr := range pt.RolePolicy.Rules {
			for _, act := range rr.AllowActions {
				if oldP == nil {
					a.addBranch(Branch{
						Kind: BranchActionAdded, Change: ChangeAdded, PolicyKey: key,
						Rule: rr.Name, Selector: role, Resource: rr.Resource, Action: act,
						NewEffect:      effectName(effectv1.Effect_EFFECT_ALLOW),
						ExpectedEffect: effectName(effectv1.Effect_EFFECT_ALLOW),
						newCondition:   rr.Condition,
					})
				} else {
					a.addBranch(Branch{
						Kind: BranchActionRemoved, Change: ChangeRemoved, PolicyKey: key,
						Rule: rr.Name, Selector: role, Resource: rr.Resource, Action: act,
						OldEffect:      effectName(effectv1.Effect_EFFECT_ALLOW),
						ExpectedEffect: effectName(effectv1.Effect_EFFECT_DENY),
					})
				}
			}
		}
	case *policyv1.Policy_DerivedRoles:
		// Handled by propagateDerivedRoles through the old/new index.
	}
}

func (a *analyzer) diffPolicy(oldP, newP *policyv1.Policy) {
	switch oldPT := oldP.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		newRP := newP.GetResourcePolicy()
		a.diffResourcePolicy(policyKey(newP), oldPT.ResourcePolicy, newRP)
	case *policyv1.Policy_PrincipalPolicy:
		newPP := newP.GetPrincipalPolicy()
		a.diffPrincipalPolicy(policyKey(newP), oldPT.PrincipalPolicy, newPP)
	case *policyv1.Policy_DerivedRoles:
		// Derived role propagation is done globally after all policies are diffed.
	case *policyv1.Policy_RolePolicy:
		newRP := newP.GetRolePolicy()
		a.diffRolePolicy(policyKey(newP), oldPT.RolePolicy, newRP)
	}
}

func selectorsOf(rule *policyv1.ResourceRule) []Selector {
	var out []Selector
	for _, r := range rule.Roles {
		if r == "*" {
			out = append(out, Selector{Type: SelectorAny})
		} else {
			out = append(out, Selector{Type: SelectorRole, Name: r})
		}
	}
	for _, d := range rule.DerivedRoles {
		out = append(out, Selector{Type: SelectorDerivedRole, Name: d})
	}
	return out
}

func selectorStrings(sels []Selector) []string {
	out := make([]string, len(sels))
	for i, s := range sels {
		out[i] = s.String()
	}
	return out
}

func (a *analyzer) resourceRuleAdded(key, resource string, rule *policyv1.ResourceRule) {
	for _, sel := range selectorsOf(rule) {
		for _, action := range rule.Actions {
			a.addBranch(Branch{
				Kind: BranchRuleAdded, Change: ChangeAdded, PolicyKey: key,
				Rule: rule.Name, Selector: sel.String(), Resource: resource, Action: action,
				NewEffect: effectName(rule.Effect), ExpectedEffect: effectName(rule.Effect),
				newCondition: rule.Condition,
			})
		}
	}
}

func (a *analyzer) resourceRuleRemoved(key, resource string, rule *policyv1.ResourceRule) {
	for _, sel := range selectorsOf(rule) {
		for _, action := range rule.Actions {
			a.addBranch(Branch{
				Kind: BranchRuleRemoved, Change: ChangeRemoved, PolicyKey: key,
				Rule: rule.Name, Selector: sel.String(), Resource: resource, Action: action,
				OldEffect: effectName(rule.Effect), ExpectedEffect: effectName(effectv1.Effect_EFFECT_DENY),
				oldCondition: rule.Condition,
			})
		}
	}
}

type resourceRulePair struct {
	old *policyv1.ResourceRule
	new *policyv1.ResourceRule
}

// pairResourceRules matches old and new rules, preferring stable rule names
// and falling back to action/selector overlap for unnamed rules.
func pairResourceRules(oldRules, newRules []*policyv1.ResourceRule) ([]resourceRulePair, []*policyv1.ResourceRule, []*policyv1.ResourceRule) {
	var pairs []resourceRulePair
	var oldAdded []*policyv1.ResourceRule // old rules without a new counterpart (removed)
	var newAdded []*policyv1.ResourceRule // new rules without an old counterpart (added)

	oldByName := make(map[string]*policyv1.ResourceRule)
	var oldUnnamed []*policyv1.ResourceRule
	for _, r := range oldRules {
		if r.Name != "" {
			oldByName[r.Name] = r
		} else {
			oldUnnamed = append(oldUnnamed, r)
		}
	}

	var newUnnamed []*policyv1.ResourceRule
	matchedOldNamed := make(map[string]struct{})
	for _, nr := range newRules {
		if nr.Name != "" {
			if or, ok := oldByName[nr.Name]; ok {
				pairs = append(pairs, resourceRulePair{old: or, new: nr})
				matchedOldNamed[nr.Name] = struct{}{}
			} else {
				newAdded = append(newAdded, nr)
			}
		} else {
			newUnnamed = append(newUnnamed, nr)
		}
	}
	for name, or := range oldByName {
		if _, ok := matchedOldNamed[name]; !ok {
			oldAdded = append(oldAdded, or)
		}
	}

	// Greedy highest-overlap pairing for unnamed rules.
	type candidate struct {
		score int
		o     *policyv1.ResourceRule
		n     *policyv1.ResourceRule
	}
	var candidates []candidate
	for _, ou := range oldUnnamed {
		for _, nu := range newUnnamed {
			score := len(intersectStrings(ou.Actions, nu.Actions)) +
				len(intersectStrings(selectorStrings(selectorsOf(ou)), selectorStrings(selectorsOf(nu))))
			candidates = append(candidates, candidate{score: score, o: ou, n: nu})
		}
	}
	slices.SortFunc(candidates, func(x, y candidate) int { return y.score - x.score })
	usedOld := map[*policyv1.ResourceRule]struct{}{}
	usedNew := map[*policyv1.ResourceRule]struct{}{}
	for _, c := range candidates {
		if c.score <= 0 {
			break
		}
		if _, ok := usedOld[c.o]; ok {
			continue
		}
		if _, ok := usedNew[c.n]; ok {
			continue
		}
		usedOld[c.o] = struct{}{}
		usedNew[c.n] = struct{}{}
		pairs = append(pairs, resourceRulePair{old: c.o, new: c.n})
	}
	for _, ou := range oldUnnamed {
		if _, ok := usedOld[ou]; !ok {
			oldAdded = append(oldAdded, ou)
		}
	}
	for _, nu := range newUnnamed {
		if _, ok := usedNew[nu]; !ok {
			newAdded = append(newAdded, nu)
		}
	}

	return pairs, oldAdded, newAdded
}

func (a *analyzer) diffResourcePolicy(key string, oldRP, newRP *policyv1.ResourcePolicy) {
	pairs, removed, added := pairResourceRules(oldRP.Rules, newRP.Rules)
	for _, r := range added {
		a.resourceRuleAdded(key, newRP.Resource, r)
	}
	for _, r := range removed {
		a.resourceRuleRemoved(key, oldRP.Resource, r)
	}
	for _, p := range pairs {
		a.diffResourceRule(key, newRP.Resource, p.old, p.new)
	}
}

func (a *analyzer) diffResourceRule(key, resource string, oldRule, newRule *policyv1.ResourceRule) {
	ruleName := firstNonEmpty(newRule.Name, oldRule.Name)
	oldSels := selectorStrings(selectorsOf(oldRule))
	newSels := selectorStrings(selectorsOf(newRule))

	// Action space changes.
	for _, action := range addedPatterns(oldRule.Actions, newRule.Actions) {
		for _, sel := range newSels {
			a.addBranch(Branch{
				Kind: BranchActionAdded, Change: ChangeAdded, PolicyKey: key, Rule: ruleName,
				Selector: sel, Resource: resource, Action: action,
				NewEffect: effectName(newRule.Effect), ExpectedEffect: effectName(newRule.Effect),
				newCondition: newRule.Condition,
			})
		}
	}
	for _, action := range removedPatterns(oldRule.Actions, newRule.Actions) {
		for _, sel := range oldSels {
			a.addBranch(Branch{
				Kind: BranchActionRemoved, Change: ChangeRemoved, PolicyKey: key, Rule: ruleName,
				Selector: sel, Resource: resource, Action: action,
				OldEffect: effectName(oldRule.Effect), ExpectedEffect: effectName(effectv1.Effect_EFFECT_DENY),
			})
		}
	}

	retainedActions := intersectStrings(oldRule.Actions, newRule.Actions)

	// Selector set changes, relevant for actions that exist in both revisions.
	for _, sel := range setDifference(newSels, oldSels) {
		kind := BranchRoleAdded
		if strings.HasPrefix(sel, string(SelectorDerivedRole)+":") {
			kind = BranchDerivedRoleAdded
		}
		for _, action := range retainedActions {
			a.addBranch(Branch{
				Kind: kind, Change: ChangeAdded, PolicyKey: key, Rule: ruleName,
				Selector: sel, Resource: resource, Action: action,
				NewEffect: effectName(newRule.Effect), ExpectedEffect: effectName(newRule.Effect),
				newCondition: newRule.Condition,
			})
		}
	}
	for _, sel := range setDifference(oldSels, newSels) {
		kind := BranchRoleRemoved
		if strings.HasPrefix(sel, string(SelectorDerivedRole)+":") {
			kind = BranchDerivedRoleRemoved
		}
		for _, action := range retainedActions {
			a.addBranch(Branch{
				Kind: kind, Change: ChangeRemoved, PolicyKey: key, Rule: ruleName,
				Selector: sel, Resource: resource, Action: action,
				OldEffect: effectName(oldRule.Effect), ExpectedEffect: effectName(effectv1.Effect_EFFECT_DENY),
			})
		}
	}

	commonSels := intersectStrings(oldSels, newSels)

	// Effect flips.
	if oldRule.Effect != newRule.Effect {
		for _, sel := range commonSels {
			for _, action := range retainedActions {
				a.addBranch(Branch{
					Kind: BranchEffectChanged, Change: ChangeModified, PolicyKey: key, Rule: ruleName,
					Selector: sel, Resource: resource, Action: action,
					OldEffect: effectName(oldRule.Effect), NewEffect: effectName(newRule.Effect),
					ExpectedEffect: effectName(newRule.Effect), newCondition: newRule.Condition,
				})
			}
		}
	}

	// Condition changes.
	if !proto.Equal(oldRule.Condition, newRule.Condition) {
		a.addConditionBranches(key, ruleName, commonSels, resource, retainedActions,
			oldRule.Effect, newRule.Effect, oldRule.Condition, newRule.Condition)
	}
}

func (a *analyzer) addConditionBranches(key, ruleName string, sels []string, resource string, actions []string,
	oldEffect, newEffect effectv1.Effect, oldCond, newCond *policyv1.Condition,
) {
	kind := BranchConditionChanged
	switch {
	case oldCond == nil && newCond != nil:
		kind = BranchConditionAdded
	case oldCond != nil && newCond == nil:
		kind = BranchConditionRemoved
	}

	for _, sel := range sels {
		for _, action := range actions {
			if kind == BranchConditionRemoved {
				a.addBranch(Branch{
					Kind: kind, Change: ChangeModified, PolicyKey: key, Rule: ruleName,
					Selector: sel, Resource: resource, Action: action,
					OldEffect: effectName(oldEffect), NewEffect: effectName(newEffect),
					ExpectedEffect: effectName(newEffect),
				})
				continue
			}
			// New/changed condition: generate both the match and no-match outcomes.
			a.addBranch(Branch{
				Kind: kind, Outcome: OutcomeMatch, Change: ChangeModified, PolicyKey: key, Rule: ruleName,
				Selector: sel, Resource: resource, Action: action,
				OldEffect: effectName(oldEffect), NewEffect: effectName(newEffect),
				ExpectedEffect: effectName(newEffect), newCondition: newCond, oldCondition: oldCond,
			})
			a.addBranch(Branch{
				Kind: kind, Outcome: OutcomeNoMatch, Change: ChangeModified, PolicyKey: key, Rule: ruleName,
				Selector: sel, Resource: resource, Action: action,
				OldEffect: effectName(oldEffect), NewEffect: effectName(newEffect),
				ExpectedEffect: effectName(effectv1.Effect_EFFECT_DENY), newCondition: newCond, oldCondition: oldCond,
			})
		}
	}
}

func (a *analyzer) diffPrincipalPolicy(key string, oldPP, newPP *policyv1.PrincipalPolicy) {
	sel := Selector{Type: SelectorPrincipal, Name: newPP.Principal}.String()

	oldActions := indexPrincipalActions(oldPP)
	newActions := indexPrincipalActions(newPP)

	for loc, na := range newActions {
		oa, ok := oldActions[loc]
		if !ok {
			a.addBranch(Branch{
				Kind: BranchActionAdded, Change: ChangeAdded, PolicyKey: key, Rule: na.act.Name,
				Selector: sel, Resource: na.resource, Action: na.act.Action,
				NewEffect: effectName(na.act.Effect), ExpectedEffect: effectName(na.act.Effect),
				newCondition: na.act.Condition,
			})
			continue
		}
		if oa.act.Effect != na.act.Effect {
			a.addBranch(Branch{
				Kind: BranchEffectChanged, Change: ChangeModified, PolicyKey: key, Rule: na.act.Name,
				Selector: sel, Resource: na.resource, Action: na.act.Action,
				OldEffect: effectName(oa.act.Effect), NewEffect: effectName(na.act.Effect),
				ExpectedEffect: effectName(na.act.Effect), newCondition: na.act.Condition,
			})
		}
		if !proto.Equal(oa.act.Condition, na.act.Condition) {
			a.addConditionBranches(key, na.act.Name, []string{sel}, na.resource, []string{na.act.Action},
				oa.act.Effect, na.act.Effect, oa.act.Condition, na.act.Condition)
		}
	}
	for loc, oa := range oldActions {
		if _, ok := newActions[loc]; !ok {
			a.addBranch(Branch{
				Kind: BranchActionRemoved, Change: ChangeRemoved, PolicyKey: key, Rule: oa.act.Name,
				Selector: sel, Resource: oa.resource, Action: oa.act.Action,
				OldEffect: effectName(oa.act.Effect), ExpectedEffect: effectName(effectv1.Effect_EFFECT_DENY),
			})
		}
	}
}

type locatedPrincipalAction struct {
	resource string
	act      *policyv1.PrincipalRule_Action
}

func indexPrincipalActions(pp *policyv1.PrincipalPolicy) map[string]locatedPrincipalAction {
	m := make(map[string]locatedPrincipalAction)
	for _, rule := range pp.Rules {
		for _, act := range rule.Actions {
			loc := rule.Resource + "\x00" + act.Action
			m[loc] = locatedPrincipalAction{resource: rule.Resource, act: act}
		}
	}
	return m
}

func (a *analyzer) diffRolePolicy(key string, oldRP, newRP *policyv1.RolePolicy) {
	sel := Selector{Type: SelectorRole, Name: newRP.GetRole()}.String()
	oldByName := make(map[string]*policyv1.RoleRule)
	for _, r := range oldRP.Rules {
		oldByName[roleRuleIdentity(r)] = r
	}
	newByName := make(map[string]*policyv1.RoleRule)
	for _, r := range newRP.Rules {
		newByName[roleRuleIdentity(r)] = r
	}
	for id, nr := range newByName {
		or, ok := oldByName[id]
		if !ok {
			for _, action := range nr.AllowActions {
				a.addBranch(Branch{
					Kind: BranchRuleAdded, Change: ChangeAdded, PolicyKey: key, Rule: nr.Name,
					Selector: sel, Resource: nr.Resource, Action: action,
					NewEffect:      effectName(effectv1.Effect_EFFECT_ALLOW),
					ExpectedEffect: effectName(effectv1.Effect_EFFECT_ALLOW), newCondition: nr.Condition,
				})
			}
			continue
		}
		for _, action := range addedPatterns(or.AllowActions, nr.AllowActions) {
			a.addBranch(Branch{
				Kind: BranchActionAdded, Change: ChangeAdded, PolicyKey: key, Rule: nr.Name,
				Selector: sel, Resource: nr.Resource, Action: action,
				NewEffect:      effectName(effectv1.Effect_EFFECT_ALLOW),
				ExpectedEffect: effectName(effectv1.Effect_EFFECT_ALLOW), newCondition: nr.Condition,
			})
		}
		for _, action := range removedPatterns(or.AllowActions, nr.AllowActions) {
			a.addBranch(Branch{
				Kind: BranchActionRemoved, Change: ChangeRemoved, PolicyKey: key, Rule: nr.Name,
				Selector: sel, Resource: nr.Resource, Action: action,
				ExpectedEffect: effectName(effectv1.Effect_EFFECT_DENY),
			})
		}
		if !proto.Equal(or.Condition, nr.Condition) {
			a.addConditionBranches(key, nr.Name, []string{sel}, nr.Resource,
				intersectStrings(or.AllowActions, nr.AllowActions),
				effectv1.Effect_EFFECT_ALLOW, effectv1.Effect_EFFECT_ALLOW, or.Condition, nr.Condition)
		}
	}
	for id, or := range oldByName {
		if _, ok := newByName[id]; !ok {
			for _, action := range or.AllowActions {
				a.addBranch(Branch{
					Kind: BranchRuleRemoved, Change: ChangeRemoved, PolicyKey: key, Rule: or.Name,
					Selector: sel, Resource: or.Resource, Action: action,
					OldEffect:      effectName(effectv1.Effect_EFFECT_ALLOW),
					ExpectedEffect: effectName(effectv1.Effect_EFFECT_DENY),
				})
			}
		}
	}
}

func roleRuleIdentity(r *policyv1.RoleRule) string {
	if r.Name != "" {
		return "name:" + r.Name
	}
	return fmt.Sprintf("rule:%s\x00%s", r.Resource, strings.Join(r.AllowActions, ","))
}

// propagateDerivedRoles maps derived-role definition changes onto the
// resource policies that import and use them.
func (a *analyzer) propagateDerivedRoles() {
	drChanges := a.collectDerivedRoleChanges()
	if len(drChanges) == 0 {
		return
	}

	// Union of resource policies from both revisions, keyed by policy key.
	resourcePolicies := make(map[string]*policyv1.ResourcePolicy)
	for key, p := range a.newByKey {
		if rp := p.GetResourcePolicy(); rp != nil {
			resourcePolicies[key] = rp
		}
	}
	for key, p := range a.oldByKey {
		if rp := p.GetResourcePolicy(); rp != nil {
			if _, ok := resourcePolicies[key]; !ok {
				resourcePolicies[key] = rp
			}
		}
	}

	for _, drc := range drChanges {
		propagated := false
		for rpKey, rp := range resourcePolicies {
			if !slices.Contains(rp.ImportDerivedRoles, drc.setName) {
				continue
			}
			for _, rule := range rp.Rules {
				if !slices.Contains(rule.DerivedRoles, drc.defName) {
					continue
				}
				propagated = true
				effect := effectName(rule.Effect)
				drSelector := Selector{Type: SelectorDerivedRole, Name: drc.defName}.String()
				for _, action := range rule.Actions {
					a.addBranch(Branch{
						Kind: BranchDerivedRoleDefChanged, Change: ChangeModified,
						PolicyKey: rpKey, Rule: drc.defName, Selector: drSelector,
						Resource: rp.Resource, Action: action,
						NewEffect: effect, ExpectedEffect: effect,
						parentRoles: drc.newParentRoles, newCondition: drc.newCondition,
					})
					for _, pr := range drc.addedParents {
						sel := Selector{Type: SelectorRole, Name: pr}.String()
						a.addBranch(Branch{
							Kind: BranchDerivedRoleParentAdded, Change: ChangeAdded,
							PolicyKey: rpKey, Rule: drc.defName, Selector: sel,
							Resource: rp.Resource, Action: action,
							NewEffect: effect, ExpectedEffect: effect, parentRoles: drc.newParentRoles,
						})
					}
					for _, pr := range drc.removedParents {
						sel := Selector{Type: SelectorRole, Name: pr}.String()
						a.addBranch(Branch{
							Kind: BranchDerivedRoleParentRemoved, Change: ChangeRemoved,
							PolicyKey: rpKey, Rule: drc.defName, Selector: sel,
							Resource: rp.Resource, Action: action,
							OldEffect: effect, ExpectedEffect: effectName(effectv1.Effect_EFFECT_DENY),
							parentRoles: drc.oldParentRoles,
						})
					}
				}
			}
		}
		if !propagated {
			// Orphan derived-role change: surface it with wildcard coordinates so
			// that it still appears in the impact set and coverage report.
			drSelector := Selector{Type: SelectorDerivedRole, Name: drc.defName}.String()
			a.addBranch(Branch{
				Kind: BranchDerivedRoleDefChanged, Change: ChangeModified,
				PolicyKey: drc.setName, Rule: drc.defName, Selector: drSelector,
				Resource: "*", Action: "*", ExpectedEffect: effectName(effectv1.Effect_EFFECT_DENY),
				parentRoles: drc.newParentRoles, newCondition: drc.newCondition,
			})
		}
	}
}

type derivedRoleChange struct {
	setName        string
	defName        string
	addedParents   []string
	removedParents []string
	oldParentRoles []string
	newParentRoles []string
	oldCondition   *policyv1.Condition
	newCondition   *policyv1.Condition
}

func (a *analyzer) collectDerivedRoleChanges() []derivedRoleChange {
	var out []derivedRoleChange
	drKeys := map[string]struct{}{}
	for k, p := range a.newByKey {
		if p.GetDerivedRoles() != nil {
			drKeys[k] = struct{}{}
		}
	}
	for k, p := range a.oldByKey {
		if p.GetDerivedRoles() != nil {
			drKeys[k] = struct{}{}
		}
	}

	for key := range drKeys {
		var oldDR, newDR *policyv1.DerivedRoles
		if p, ok := a.oldByKey[key]; ok {
			oldDR = p.GetDerivedRoles()
		}
		if p, ok := a.newByKey[key]; ok {
			newDR = p.GetDerivedRoles()
		}
		setName := key
		if newDR != nil {
			setName = newDR.Name
		} else if oldDR != nil {
			setName = oldDR.Name
		}

		oldDefs := map[string]*policyv1.RoleDef{}
		newDefs := map[string]*policyv1.RoleDef{}
		if oldDR != nil {
			for _, d := range oldDR.Definitions {
				oldDefs[d.Name] = d
			}
		}
		if newDR != nil {
			for _, d := range newDR.Definitions {
				newDefs[d.Name] = d
			}
		}
		for name, nd := range newDefs {
			od, ok := oldDefs[name]
			if !ok {
				out = append(out, derivedRoleChange{
					setName: setName, defName: name,
					addedParents: nd.ParentRoles, newParentRoles: nd.ParentRoles, newCondition: nd.Condition,
				})
				continue
			}
			added := setDifference(nd.ParentRoles, od.ParentRoles)
			removed := setDifference(od.ParentRoles, nd.ParentRoles)
			condChanged := !proto.Equal(od.Condition, nd.Condition)
			if len(added) == 0 && len(removed) == 0 && !condChanged {
				continue
			}
			out = append(out, derivedRoleChange{
				setName: setName, defName: name,
				addedParents: added, removedParents: removed,
				oldParentRoles: od.ParentRoles, newParentRoles: nd.ParentRoles,
				oldCondition: od.Condition, newCondition: nd.Condition,
			})
		}
		for name, od := range oldDefs {
			if _, ok := newDefs[name]; !ok {
				out = append(out, derivedRoleChange{
					setName: setName, defName: name,
					removedParents: od.ParentRoles, oldParentRoles: od.ParentRoles, oldCondition: od.Condition,
				})
			}
		}
	}
	return out
}

func (a *analyzer) finalize() *Report {
	slices.SortFunc(a.branches, func(x, y Branch) int {
		return strings.Compare(x.ID, y.ID)
	})
	slices.SortFunc(a.changes, func(x, y PolicyChange) int {
		return strings.Compare(x.Key, y.Key)
	})

	tripleSet := map[Triple]struct{}{}
	principalSet := map[string]struct{}{}
	resourceSet := map[string]struct{}{}
	actionSet := map[string]struct{}{}
	for _, b := range a.branches {
		t := Triple{Principal: b.Selector, Resource: b.Resource, Action: b.Action}
		tripleSet[t] = struct{}{}
		principalSet[b.Selector] = struct{}{}
		resourceSet[b.Resource] = struct{}{}
		actionSet[b.Action] = struct{}{}
	}

	triples := make([]Triple, 0, len(tripleSet))
	for t := range tripleSet {
		triples = append(triples, t)
	}
	slices.SortFunc(triples, func(x, y Triple) int {
		if c := strings.Compare(x.Principal, y.Principal); c != 0 {
			return c
		}
		if c := strings.Compare(x.Resource, y.Resource); c != 0 {
			return c
		}
		return strings.Compare(x.Action, y.Action)
	})

	principals := sortedKeys(principalSet)
	resources := sortedKeys(resourceSet)
	actions := sortedKeys(actionSet)

	r := &Report{
		Impact: Impact{
			Principals: principals,
			Resources:  resources,
			Actions:    actions,
			Triples:    triples,
		},
		Branches:      a.branches,
		PolicyChanges: a.changes,
	}
	r.Entries = buildEntries(a.branches)
	r.Summary = fmt.Sprintf(
		"%d impacted decision cell(s), %d diff branch(es), %d changed polic(y/ies)",
		len(triples), len(a.branches), len(a.changes))
	return r
}

func buildEntries(branches []Branch) []Entry {
	byTriple := map[Triple]*Entry{}
	var order []Triple
	for _, b := range branches {
		t := Triple{Principal: b.Selector, Resource: b.Resource, Action: b.Action}
		e, ok := byTriple[t]
		if !ok {
			e = &Entry{Triple: t, PolicyKey: b.PolicyKey, Rule: b.Rule}
			byTriple[t] = e
			order = append(order, t)
		}
		e.Branches = append(e.Branches, b.ID)
		e.Change = mergeChange(e.Change, b.Change)
		if e.OldEffect == "" && b.OldEffect != "" {
			e.OldEffect = b.OldEffect
		}
		if e.NewEffect == "" && b.NewEffect != "" {
			e.NewEffect = b.NewEffect
		}
	}

	out := make([]Entry, 0, len(order))
	for _, t := range order {
		e := byTriple[t]
		e.Branches = dedupSorted(e.Branches)
		out = append(out, *e)
	}
	slices.SortFunc(out, func(x, y Entry) int {
		if c := strings.Compare(x.Principal, y.Principal); c != 0 {
			return c
		}
		if c := strings.Compare(x.Resource, y.Resource); c != 0 {
			return c
		}
		return strings.Compare(x.Action, y.Action)
	})
	return out
}

func mergeChange(cur, next ChangeKind) ChangeKind {
	if cur == "" {
		return next
	}
	if cur == next {
		return cur
	}
	return ChangeModified
}

func intersectStrings(a, b []string) []string {
	set := map[string]struct{}{}
	for _, x := range b {
		set[x] = struct{}{}
	}
	var out []string
	for _, x := range a {
		if _, ok := set[x]; ok {
			out = append(out, x)
		}
	}
	return dedupSorted(out)
}

func setDifference(a, b []string) []string {
	set := map[string]struct{}{}
	for _, x := range b {
		set[x] = struct{}{}
	}
	var out []string
	for _, x := range a {
		if _, ok := set[x]; !ok {
			out = append(out, x)
		}
	}
	return dedupSorted(out)
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
