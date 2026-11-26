// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package impact

import (
	"regexp"
	"strconv"
	"strings"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

// simpleComparison matches a leaf CEL expression of the form
//
//	request.resource.attr.path.to.field == "value"
//
// Only a small, side-effect-free subset is synthesised automatically. More
// complex conditions still get structurally covering test cases, but their
// attribute fixtures may need manual tuning for true/false outcomes.
var simpleComparison = regexp.MustCompile(
	`^\s*(request\.(?:resource|principal)\.attr(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\s*(==|!=)\s*(` +
		`"(?:[^"\\]|\\.)*"|'[^']*'|-?\d+(?:\.\d+)?|true|false)\s*$`)

type comparison struct {
	root       string // "resource" or "principal"
	path       []string
	op         string
	literal    any
	literalRaw string
}

func extractComparisons(cond *policyv1.Condition) []comparison {
	if cond == nil {
		return nil
	}
	var exprs []string
	collectExprs(cond, &exprs)

	var out []comparison
	for _, e := range exprs {
		if c, ok := parseComparison(e); ok {
			out = append(out, c)
		}
	}
	return out
}

func collectExprs(cond *policyv1.Condition, out *[]string) {
	switch c := cond.Condition.(type) {
	case *policyv1.Condition_Match:
		collectMatchExprs(c.Match, out)
	case *policyv1.Condition_Script:
		// Scripts are not parseable into simple comparisons.
	}
}

func collectMatchExprs(m *policyv1.Match, out *[]string) {
	if m == nil {
		return
	}
	switch op := m.Op.(type) {
	case *policyv1.Match_Expr:
		*out = append(*out, op.Expr)
	case *policyv1.Match_All:
		for _, sub := range op.All.Of {
			collectMatchExprs(sub, out)
		}
	case *policyv1.Match_Any:
		for _, sub := range op.Any.Of {
			collectMatchExprs(sub, out)
		}
	case *policyv1.Match_None:
		for _, sub := range op.None.Of {
			collectMatchExprs(sub, out)
		}
	}
}

func parseComparison(expr string) (comparison, bool) {
	m := simpleComparison.FindStringSubmatch(expr)
	if m == nil {
		return comparison{}, false
	}
	fullPath := m[1]
	op := m[2]
	raw := m[3]

	trimmed := strings.TrimPrefix(fullPath, "request.")
	parts := strings.Split(trimmed, ".")
	// parts: [resource|principal, attr, field...]
	if len(parts) < 3 || parts[1] != "attr" {
		return comparison{}, false
	}

	c := comparison{root: parts[0], path: parts[2:], op: op, literalRaw: raw}
	switch {
	case strings.HasPrefix(raw, "\"") || strings.HasPrefix(raw, "'"):
		unquoted, err := strconv.Unquote("\"" + strings.Trim(raw, `"'`) + "\"")
		if err != nil {
			unquoted = strings.Trim(raw, `"'`)
		}
		c.literal = unquoted
	case raw == "true":
		c.literal = true
	case raw == "false":
		c.literal = false
	case strings.Contains(raw, "."):
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return comparison{}, false
		}
		c.literal = f
	default:
		i, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return comparison{}, false
		}
		c.literal = i
	}
	return c, true
}

// matchAttrs builds attribute maps that make the condition evaluate true
// under the supported simple-comparison subset.
func matchAttrs(cond *policyv1.Condition) (principal, resource map[string]*structpb.Value) {
	cmps := extractComparisons(cond)
	if len(cmps) == 0 {
		return nil, nil
	}
	principal = map[string]*structpb.Value{}
	resource = map[string]*structpb.Value{}
	for _, c := range cmps {
		target := resource
		if c.root == "principal" {
			target = principal
		}
		val := c.literal
		if c.op == "!=" {
			val = otherValue(c.literal)
		}
		setAttrPath(target, c.path, val)
	}
	return principal, resource
}

// noMatchAttrs builds attribute maps that make the first supported comparison
// false while keeping the others true.
func noMatchAttrs(cond *policyv1.Condition) (principal, resource map[string]*structpb.Value) {
	cmps := extractComparisons(cond)
	if len(cmps) == 0 {
		return nil, nil
	}
	principal = map[string]*structpb.Value{}
	resource = map[string]*structpb.Value{}
	for i, c := range cmps {
		target := resource
		if c.root == "principal" {
			target = principal
		}
		val := c.literal
		invert := i == 0
		if invert {
			if c.op == "==" {
				val = otherValue(c.literal)
			} else { // != : make equality true so != is false
				val = c.literal
			}
		} else if c.op == "!=" {
			val = otherValue(c.literal)
		}
		setAttrPath(target, c.path, val)
	}
	return principal, resource
}

func otherValue(v any) any {
	switch t := v.(type) {
	case string:
		return t + "__impact_other"
	case int64:
		return t + 1
	case float64:
		return t + 1
	case bool:
		return !t
	default:
		return "__impact_other"
	}
}

func setAttrPath(attrs map[string]*structpb.Value, path []string, val any) {
	if len(path) == 0 {
		return
	}
	if len(path) == 1 {
		v, err := structpb.NewValue(val)
		if err == nil {
			attrs[path[0]] = v
		}
		return
	}
	child, ok := attrs[path[0]]
	var nested map[string]*structpb.Value
	if ok {
		nested = child.GetStructValue().GetFields()
	}
	if nested == nil {
		nested = map[string]*structpb.Value{}
	}
	setAttrPath(nested, path[1:], val)
	attrs[path[0]] = structpb.NewStructValue(&structpb.Struct{Fields: nested})
}
