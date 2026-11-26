// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package impact implements the local "cerbosctl impact" commands for policy
// change impact analysis and impact-aware test generation.
package impact

import (
	"github.com/alecthomas/kong"
)

// Cmd is the "cerbosctl impact" command group.
type Cmd struct {
	Analyze  AnalyzeCmd  `cmd:"" name:"analyze" help:"Analyse the principal/resource/action impact of policy changes"`
	GenTests GenTestsCmd `cmd:"" name:"gen-tests" aliases:"gentests" help:"Generate a Cerbos test suite covering every diff branch"`
}

// AnalyzeCmd compares an old and a new policy set.
type AnalyzeCmd struct {
	OldPath   string `arg:"" name:"old" type:"existingpath" help:"File or directory containing the OLD policy revision"`
	NewPath   string `arg:"" name:"new" type:"existingpath" help:"File or directory containing the NEW policy revision"`
	Format    string `name:"format" short:"f" enum:"text,json,yaml" default:"text" help:"Output format (text, json, yaml)"`
	Directory string `name:"principal-directory" type:"path" help:"Optional YAML/JSON file mapping principal IDs to roles for concrete principal expansion"`
}

// Run executes the analyze command.
func (c *AnalyzeCmd) Run(k *kong.Kong) error {
	report, err := buildReport(c.OldPath, c.NewPath, c.Directory)
	if err != nil {
		return err
	}

	switch c.Format {
	case "json":
		return report.RenderJSON(k.Stdout)
	case "yaml":
		return report.RenderYAML(k.Stdout)
	default:
		return report.RenderText(k.Stdout)
	}
}

// GenTestsCmd generates a test suite from a policy diff.
type GenTestsCmd struct {
	OldPath     string `arg:"" name:"old" type:"existingpath" help:"File or directory containing the OLD policy revision"`
	NewPath     string `arg:"" name:"new" type:"existingpath" help:"File or directory containing the NEW policy revision"`
	Out         string `name:"out" short:"o" type:"path" help:"Output file for the generated test suite (defaults to stdout)"`
	SuiteName   string `name:"suite-name" default:"PolicyChangeImpactSuite" help:"Name of the generated test suite"`
	CoverageOut string `name:"coverage-out" type:"path" help:"Optional file to write the branch coverage report (JSON)"`
}

// Run executes the gen-tests command.
func (c *GenTestsCmd) Run(k *kong.Kong) error {
	report, err := buildReport(c.OldPath, c.NewPath, "")
	if err != nil {
		return err
	}

	generated, err := generate(report, c.SuiteName)
	if err != nil {
		return err
	}

	if c.Out != "" {
		if err := writeFile(c.Out, generated.YAML); err != nil {
			return err
		}
	} else if _, err := k.Stdout.Write(generated.YAML); err != nil {
		return err
	}

	if c.CoverageOut != "" {
		if err := writeCoverage(c.CoverageOut, generated.Coverage); err != nil {
			return err
		}
	}

	if c.Out != "" {
		k.Printf("Generated %d test(s) covering %d/%d diff branches (%.0f%%) -> %s",
			len(generated.Cases), generated.Coverage.CoveredCount, generated.Coverage.BranchCount,
			generated.Coverage.Percent, c.Out)
		if c.CoverageOut != "" {
			k.Printf("Coverage report -> %s", c.CoverageOut)
		}
	}
	return nil
}
