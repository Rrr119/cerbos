// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package impact

import (
	"fmt"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

func ExampleAnalyze() {
	oldPolicy, err := ParsePolicyYAML(`---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  resource: contact
  version: default
  rules:
    - name: user-access
      actions: ["read"]
      effect: EFFECT_ALLOW
      roles: ["user"]
`)
	if err != nil {
		panic(err)
	}
	newPolicy, err := ParsePolicyYAML(`---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  resource: contact
  version: default
  rules:
    - name: user-access
      actions: ["read", "create"]
      effect: EFFECT_ALLOW
      roles: ["user"]
`)
	if err != nil {
		panic(err)
	}

	var oldSet, newSet []*policyv1.Policy
	oldSet = append(oldSet, oldPolicy)
	newSet = append(newSet, newPolicy)

	report := Analyze(oldSet, newSet)
	for _, triple := range report.Impact.Triples {
		fmt.Printf("%s | %s | %s\n", triple.Principal, triple.Resource, triple.Action)
	}

	generated, err := GenerateTestSuite(report)
	if err != nil {
		panic(err)
	}
	fmt.Printf("branches=%d coverage=%.0f%%\n", generated.Coverage.BranchCount, generated.Coverage.Percent)
	// Output:
	// role:user | contact | create
	// branches=1 coverage=100%
}
