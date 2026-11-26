// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package impact

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/goccy/go-yaml"
)

// RenderText writes a human-readable impact report.
func (r *Report) RenderText(w io.Writer) error {
	if r.Summary != "" {
		fmt.Fprintln(w, r.Summary)
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "Affected principals:")
	for _, p := range r.Impact.Principals {
		fmt.Fprintf(w, "  - %s\n", p)
	}
	fmt.Fprintln(w, "Affected resources:")
	for _, res := range r.Impact.Resources {
		fmt.Fprintf(w, "  - %s\n", res)
	}
	fmt.Fprintln(w, "Affected actions:")
	for _, a := range r.Impact.Actions {
		fmt.Fprintf(w, "  - %s\n", a)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Impact triples (principal / resource / action):")
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "PRINCIPAL\tRESOURCE\tACTION\tCHANGE\tEFFECTS")
	for _, e := range r.Entries {
		effects := e.OldEffect
		if e.OldEffect != "" || e.NewEffect != "" {
			effects = effectOrNone(e.OldEffect) + " -> " + effectOrNone(e.NewEffect)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.Principal, e.Resource, e.Action, e.Change, effects)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if len(r.ResolvedTriples) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Concrete principal impact (from principal directory):")
		for _, t := range r.ResolvedTriples {
			fmt.Fprintf(w, "  - %s / %s / %s\n", t.Principal, t.Resource, t.Action)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Diff branches (%d):\n", len(r.Branches))
	for _, b := range r.Branches {
		outcome := ""
		if b.Outcome != "" {
			outcome = " [" + b.Outcome + "]"
		}
		fmt.Fprintf(w, "  - %s%s on %s/%s as %s (%s)\n",
			b.Kind, outcome, b.Resource, b.Action, b.Selector, b.Change)
	}
	return nil
}

// RenderJSON writes the report as indented JSON.
func (r *Report) RenderJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// RenderYAML writes the report as YAML.
func (r *Report) RenderYAML(w io.Writer) error {
	data, err := yaml.Marshal(r)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
