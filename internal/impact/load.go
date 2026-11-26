// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package impact

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/parser"
	"github.com/cerbos/cerbos/internal/util"
)

// ParsePolicies parses one or more YAML/JSON policy documents. The input uses
// the exact same api.cerbos.dev/v1 policy format as Cerbos itself, including
// multi-document files separated by "---".
func ParsePolicies(r io.Reader) ([]*policyv1.Policy, error) {
	docs, _, err := parser.Unmarshal[policyv1.Policy](r)
	if err != nil {
		return nil, err
	}
	return docs, nil
}

// ParsePolicyYAML parses a single policy YAML document.
func ParsePolicyYAML(data string) (*policyv1.Policy, error) {
	docs, err := ParsePolicies(strings.NewReader(data))
	if err != nil {
		return nil, err
	}
	if len(docs) != 1 {
		return nil, fmt.Errorf("expected exactly one policy document, got %d", len(docs))
	}
	return docs[0], nil
}

// LoadPoliciesFromPaths loads policies from the given files or directories.
// Directories are walked recursively and all supported policy files are read.
// Cerbos test files ("*_test.yaml") and testdata directories are ignored.
func LoadPoliciesFromPaths(paths ...string) ([]*policyv1.Policy, error) {
	var files []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("cannot access %s: %w", p, err)
		}
		if !info.IsDir() {
			files = append(files, p)
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == util.TestDataDirectory {
					return filepath.SkipDir
				}
				return nil
			}
			if util.IsSupportedFileType(path) && !util.IsSupportedTestFile(path) {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to scan %s: %w", p, err)
		}
	}

	sort.Strings(files)
	var policies []*policyv1.Policy
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", f, err)
		}
		docs, err := ParsePolicies(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", f, err)
		}
		policies = append(policies, docs...)
	}
	return policies, nil
}

// policyKey returns the stable identity key of a policy revision. Policies
// with the same key in the old and new sets are considered two revisions of
// the same policy.
func policyKey(p *policyv1.Policy) string {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		rp := pt.ResourcePolicy
		return fmt.Sprintf("resourcePolicy:%s:%s:%s", rp.Resource, rp.Version, rp.Scope)
	case *policyv1.Policy_PrincipalPolicy:
		pp := pt.PrincipalPolicy
		return fmt.Sprintf("principalPolicy:%s:%s:%s", pp.Principal, pp.Version, pp.Scope)
	case *policyv1.Policy_DerivedRoles:
		return "derivedRoles:" + pt.DerivedRoles.Name
	case *policyv1.Policy_RolePolicy:
		rp := pt.RolePolicy
		role := rp.GetRole()
		return fmt.Sprintf("rolePolicy:%s:%s:%s", role, rp.Version, rp.Scope)
	case *policyv1.Policy_ExportVariables:
		return "exportVariables:" + pt.ExportVariables.Name
	case *policyv1.Policy_ExportConstants:
		return "exportConstants:" + pt.ExportConstants.Name
	default:
		return fmt.Sprintf("unknownPolicy:%p", p)
	}
}

func policyKind(p *policyv1.Policy) string {
	switch p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return "resourcePolicy"
	case *policyv1.Policy_PrincipalPolicy:
		return "principalPolicy"
	case *policyv1.Policy_DerivedRoles:
		return "derivedRoles"
	case *policyv1.Policy_RolePolicy:
		return "rolePolicy"
	case *policyv1.Policy_ExportVariables:
		return "exportVariables"
	case *policyv1.Policy_ExportConstants:
		return "exportConstants"
	default:
		return "unknown"
	}
}
