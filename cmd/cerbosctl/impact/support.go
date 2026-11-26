// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package impact

import (
	"encoding/json"
	"fmt"
	"os"

	impactlib "github.com/cerbos/cerbos/internal/impact"
	"github.com/goccy/go-yaml"
)

func buildReport(oldPath, newPath, directoryPath string) (*impactlib.Report, error) {
	oldPolicies, err := impactlib.LoadPoliciesFromPaths(oldPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load old policies: %w", err)
	}
	newPolicies, err := impactlib.LoadPoliciesFromPaths(newPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load new policies: %w", err)
	}

	report := impactlib.Analyze(oldPolicies, newPolicies)

	if directoryPath != "" {
		directory, err := loadPrincipalDirectory(directoryPath)
		if err != nil {
			return nil, err
		}
		report.ResolvedTriples = report.ExpandPrincipals(directory)
	}
	return report, nil
}

func loadPrincipalDirectory(path string) (map[string][]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read principal directory: %w", err)
	}
	var directory map[string][]string
	if err := yaml.Unmarshal(data, &directory); err != nil {
		if jerr := json.Unmarshal(data, &directory); jerr != nil {
			return nil, fmt.Errorf("principal directory must be a YAML/JSON map of principal ID to roles: %w", err)
		}
	}
	return directory, nil
}

func generate(report *impactlib.Report, suiteName string) (*impactlib.GeneratedSuite, error) {
	if len(report.Branches) == 0 {
		return nil, fmt.Errorf("no policy changes detected between the two paths; nothing to generate")
	}
	return impactlib.GenerateTestSuite(report, impactlib.WithSuiteName(suiteName))
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

func writeCoverage(path string, coverage *impactlib.CoverageReport) error {
	data, err := json.MarshalIndent(coverage, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
