package ui

import (
	"fmt"
	"strings"

	"gordian-tui/internal/api"
	"gordian-tui/internal/state"
)

type scanBuilder struct {
	req api.ScanStartRequest
	err error
}

func newScanBuilder() *scanBuilder {
	return &scanBuilder{
		req: api.ScanStartRequest{
			RunRemediation:   true,
			TopPatches:       5,
			AssetAwareCVEs:   false,
			AssetCVEMinScore: 2,
			AssetCVEKeepTop:  120,
		},
	}
}

func (b *scanBuilder) withString(ptr *string, raw string) *scanBuilder {
	if b.err != nil {
		return b
	}
	*ptr = strings.TrimSpace(raw)
	return b
}

func (b *scanBuilder) withOptionalInt(raw, field string, setter func(*int)) *scanBuilder {
	if b.err != nil {
		return b
	}
	v, err := parseOptionalInt(raw)
	if err != nil {
		b.err = fmt.Errorf("invalid %s: %w", field, err)
		return b
	}
	if v != nil {
		setter(v)
	}
	return b
}

func (b *scanBuilder) withOptionalBool(raw, field string, setter func(*bool)) *scanBuilder {
	if b.err != nil {
		return b
	}
	v, err := parseOptionalBool(raw)
	if err != nil {
		b.err = fmt.Errorf("invalid %s: %w", field, err)
		return b
	}
	if v != nil {
		setter(v)
	}
	return b
}

func (b *scanBuilder) withTools(cfg state.ScanConfig, tools []state.Tool) *scanBuilder {
	if b.err != nil {
		return b
	}

	enabled := []string{}
	for _, t := range tools {
		if t.Enabled {
			enabled = append(enabled, t.Name)
		}
	}

	selected := enabled
	if override := parseCSVList(cfg.OffensiveTools); len(override) > 0 {
		selected = override
	}
	b.req.OffensiveTools = selected
	return b
}

func (b *scanBuilder) withToolOverrides(cfg state.ScanConfig) *scanBuilder {
	if b.err != nil {
		return b
	}

	bins := buildToolBinMap(cfg)
	if len(bins) > 0 {
		b.req.ToolBin = bins
	}

	extra, err := buildToolArgMap(cfg, false)
	if err != nil {
		b.err = err
		return b
	}
	if len(extra) > 0 {
		b.req.ToolExtraArgs = extra
	}

	command, err := buildToolArgMap(cfg, true)
	if err != nil {
		b.err = err
		return b
	}
	if len(command) > 0 {
		b.req.ToolCommand = command
	}
	return b
}

func (b *scanBuilder) build() (api.ScanStartRequest, error) {
	if b.err != nil {
		return api.ScanStartRequest{}, b.err
	}
	return b.req, nil
}
