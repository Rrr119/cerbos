// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package impact

import "strings"

// patternCovers reports whether Cerbos action/role pattern q covers every
// literal value that pattern p can match. Cerbos patterns support a trailing
// "*" wildcard and the standalone "*" matches everything.
//
// This is a conservative syntactic check: it returns true only for the common
// cases (equality, "*" and prefix wildcards) and false otherwise, in which
// case callers treat the patterns as distinct and may over-approximate impact.
func patternCovers(q, p string) bool {
	if q == p {
		return true
	}
	if q == "*" {
		return true
	}
	if strings.HasSuffix(q, "*") && !strings.ContainsAny(q[:len(q)-1], "*?[") {
		prefix := q[:len(q)-1]
		return strings.HasPrefix(p, prefix)
	}
	return false
}

// addedPatterns returns patterns in newPatterns that are not covered by any
// pattern in oldPatterns (i.e. genuinely new action/role space).
func addedPatterns(oldPatterns, newPatterns []string) []string {
	var out []string
	for _, n := range newPatterns {
		covered := false
		for _, o := range oldPatterns {
			if patternCovers(o, n) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, n)
		}
	}
	return out
}

// removedPatterns returns patterns in oldPatterns whose covered space is not
// covered by any pattern in newPatterns.
func removedPatterns(oldPatterns, newPatterns []string) []string {
	var out []string
	for _, o := range oldPatterns {
		covered := false
		for _, n := range newPatterns {
			if patternCovers(n, o) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, o)
		}
	}
	return out
}
