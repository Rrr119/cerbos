// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package impact

import (
	"slices"
	"strings"
)

// ExpandPrincipals resolves role selectors in the impact set against a
// principal directory. The directory maps concrete principal IDs to the roles
// they hold. Principal-policy selectors ("principal:<id>") are kept as-is.
//
// Derived-role selectors cannot be resolved from role membership alone; they
// remain selector-level entries in Report.Impact.Triples.
func (r *Report) ExpandPrincipals(directory map[string][]string) []Triple {
	roleToPrincipals := map[string][]string{}
	for id, roles := range directory {
		for _, role := range roles {
			roleToPrincipals[role] = append(roleToPrincipals[role], id)
		}
	}

	var out []Triple
	for _, t := range r.Impact.Triples {
		sel, ok := ParseSelector(t.Principal)
		if !ok {
			continue
		}
		switch sel.Type {
		case SelectorPrincipal:
			out = append(out, t)
		case SelectorRole:
			for _, id := range roleToPrincipals[sel.Name] {
				out = append(out, Triple{
					Principal: "principal:" + id,
					Resource:  t.Resource,
					Action:    t.Action,
				})
			}
		case SelectorAny:
			for id := range directory {
				out = append(out, Triple{
					Principal: "principal:" + id,
					Resource:  t.Resource,
					Action:    t.Action,
				})
			}
		}
	}
	slices.SortFunc(out, func(x, y Triple) int {
		if c := strings.Compare(x.Principal, y.Principal); c != 0 {
			return c
		}
		if c := strings.Compare(x.Resource, y.Resource); c != 0 {
			return c
		}
		return strings.Compare(x.Action, y.Action)
	})
	return dedupTriples(out)
}

func dedupTriples(in []Triple) []Triple {
	seen := map[Triple]struct{}{}
	out := in[:0]
	for _, t := range in {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}
