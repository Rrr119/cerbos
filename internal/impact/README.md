# Policy change impact analysis & test generation

When Cerbos policies change, it is hard to know **who** is affected. The
`impact` package compares two revisions of a policy set, computes the exact
set of impacted `principal / resource / action` decision cells, and generates
a Cerbos-compatible test suite that covers every branch of the diff.

It works entirely on the existing `api.cerbos.dev/v1` policy YAML format and
emits the existing `TestSuite` format (`*_test.yaml`) — generated suites run
unchanged under `cerbos compile` / `cerbos verify`.

## Impact model

An **impact triple** is the smallest decision cell whose result may differ
between the old and new revision:

```text
principal / resource / action
```

Policies name principals indirectly, so the principal coordinate is a typed
selector:

| Selector                | Meaning                                                        |
|-------------------------|----------------------------------------------------------------|
| `role:<name>`           | Any principal holding role `<name>` (resource/role policies)  |
| `derived_role:<name>`   | Principals that acquire the derived role                       |
| `principal:<id>`        | Concrete principal ID (principal policies)                     |
| `any`                   | Wildcard (`roles: ["*"]`) selector                             |

When an identity directory is available (`principal ID -> roles`),
`Report.ExpandPrincipals` resolves `role:` selectors to concrete
`principal:<id>` triples.

## Library usage

```go
oldPolicies, _ := impact.LoadPoliciesFromPaths("policies/old")
newPolicies, _ := impact.LoadPoliciesFromPaths("policies/new")

report := impact.Analyze(oldPolicies, newPolicies)
fmt.Println(report.Summary)
_ = report.RenderText(os.Stdout)      // or RenderJSON / RenderYAML

gen, _ := impact.GenerateTestSuite(report)
_ = os.WriteFile("impact_test.yaml", gen.YAML, 0o600)
fmt.Printf("branch coverage: %.0f%%\n", gen.Coverage.Percent)
```

## CLI

```bash
# Affected principal/resource/action sets
cerbosctl impact analyze ./policies@v1 ./policies@v2
cerbosctl impact analyze old.yaml new.yaml -f json
cerbosctl impact analyze old ./new --principal-directory principals.yaml

# Generate a runnable test suite covering every diff branch
cerbosctl impact gen-tests old ./new -o impact_test.yaml --coverage-out coverage.json
cerbos compile .   # runs the generated *_test.yaml
```

## Diff branches

Every atomic change produces one or more branches; the generator emits one
test table per branch and `CoverageReport.Complete` is true only when every
branch has a case.

Branch kinds: `ACTION_ADDED`, `ACTION_REMOVED`, `ROLE_ADDED`,
`ROLE_REMOVED`, `DERIVED_ROLE_ADDED/REMOVED`, `RULE_ADDED/REMOVED`,
`EFFECT_CHANGED`, `CONDITION_ADDED/REMOVED/CHANGED` (condition changes emit
`match` and `no_match` outcomes), and derived-role propagation
`DERIVED_ROLE_DEFINITION_CHANGED`,
`DERIVED_ROLE_PARENT_ADDED/REMOVED`.

Action wildcards are handled containment-aware: if old rules already contain
`actions: ["*"]`, adding a literal action is not reported as new impact.

## Acceptance: ten change groups vs. manual derivation

`TestTenScenarioImpactSets` in `scenarios_test.go` encodes ten hand-derived
changes and asserts **exact** equality of the impact set and branch kinds.
The reviewable projections live in `testdata/ten_changes/<group>/`
(`old/`, `new/`, `expected_impact.yaml`, `coverage.json`, and a runnable
`verify/` directory).

| # | Change | Manually derived impact set | Branches |
|---|--------|------------------------------|----------|
| 1 | add `create` to `user` rule on `contact` | `role:user / contact / create` | `ACTION_ADDED` |
| 2 | remove `delete` from `editor` rule on `document` | `role:editor / document / delete` | `ACTION_REMOVED` |
| 3 | flip `manager/invoice/approve` ALLOW→DENY | `role:manager / invoice / approve` | `EFFECT_CHANGED` |
| 4 | add `manager` to auditor `report/view` | `role:manager / report / view` | `ROLE_ADDED` |
| 5 | remove `viewer` from `document/read` | `role:viewer / document / read` | `ROLE_REMOVED` |
| 6 | add `status == "draft"` condition | `role:employee / leave_request / create` | `CONDITION_ADDED` ×`match`,`no_match` |
| 7 | add viewer `comment` rule on `blog` | `role:viewer / blog / comment` | `RULE_ADDED` |
| 8 | delete contractor `download` rule on `file` | `role:contractor / file / download` | `RULE_REMOVED` |
| 9 | principal `alice` gains `export` on `report` | `principal:alice / report / export` | `ACTION_ADDED` |
| 10 | derived role `project_admin` gains parent `owner`, used on `project/update` | `derived_role:project_admin / project / update`; `role:owner / project / update` | `DERIVED_ROLE_DEFINITION_CHANGED`, `DERIVED_ROLE_PARENT_ADDED` |

Coverage and execution evidence:

- `TestGeneratedSuitesCoverAllDiffBranches` — every branch ID is covered and
  the emitted YAML parses back as `cerbos.policy.v1.TestSuite`.
- `TestGeneratedSuitesPassRealVerifier` — writes the new policies plus the
  generated suite to a store and runs the real `internal/verify` engine; all
  ten groups pass (including condition true/false outcomes, principal
  policies and derived-role propagation).
- Every `testdata/ten_changes/*/verify` directory also passes
  `cerbos compile`.

## Limitations

- Without an identity directory, role selectors cannot name concrete users;
  this is inherent to policy-only analysis and is resolved via
  `ExpandPrincipals` / `--principal-directory`.
- Generated expectations encode the intended new-revision decision (default
  deny for removed rules). Overlapping allow/deny rules in the same policy
  set can make the semantic expectation differ; regenerate against an engine
  or run `cerbos compile` to confirm. The acceptance scenarios are
  overlap-free and are verified by the real engine.
- Attribute synthesis covers simple
  `request.{resource,principal}.attr.path ==/!= literal` expressions; complex
  CEL/scripts still receive structural cases but may need fixture tuning for
  both condition outcomes.
- Changes to exported variables/constants are reported as policy changes but
  do not yet propagate through CEL references to consuming rules.
