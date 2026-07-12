package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cortalabs/cortasentry/internal/application"
	"github.com/cortalabs/cortasentry/internal/fingerprint"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"log/slog"
	"net/url"
	"os"
	"strings"
)

const Version = "0.1.0"

type Empty struct{}
type PageInput struct {
	Limit int `json:"limit,omitempty" jsonschema:"maximum number of records, from 1 to 500"`
	Page  int `json:"page,omitempty" jsonschema:"one-based page number"`
}
type AssetInput struct {
	AssetID string `json:"asset_id" jsonschema:"required asset UUID"`
}
type ObservationInput struct {
	AssetID string `json:"asset_id,omitempty"`
	Source  string `json:"source,omitempty"`
	IP      string `json:"ip,omitempty"`
	Limit   int    `json:"limit,omitempty"`
	Page    int    `json:"page,omitempty"`
}
type ScanInput struct {
	Targets        []string `json:"targets" jsonschema:"authorized literal IP addresses"`
	Ports          []int    `json:"ports"`
	IdempotencyKey string   `json:"idempotency_key,omitempty"`
}
type CancelInput struct {
	JobID string `json:"job_id"`
}
type MergeInput struct {
	SourceAssetID string `json:"source_asset_id"`
	TargetAssetID string `json:"target_asset_id"`
	Confirm       bool   `json:"confirm"`
}
type FindingInput struct {
	FindingID   string `json:"finding_id"`
	Disposition string `json:"disposition"`
}
type ChangeInput struct {
	ChangeID     string `json:"change_id"`
	Acknowledged bool   `json:"acknowledged"`
}
type JSONOutput struct {
	JSON string `json:"json" jsonschema:"JSON-encoded CortaSentry result"`
}

func boolp(v bool) *bool { return &v }
func readTool(name, title, description string) *mcp.Tool {
	return &mcp.Tool{Name: name, Description: description, Annotations: &mcp.ToolAnnotations{Title: title, ReadOnlyHint: true, IdempotentHint: true, DestructiveHint: boolp(false), OpenWorldHint: boolp(false)}}
}
func writeTool(name, title, description string, destructive, open bool) *mcp.Tool {
	return &mcp.Tool{Name: name, Description: description, Annotations: &mcp.ToolAnnotations{Title: title, ReadOnlyHint: false, IdempotentHint: true, DestructiveHint: boolp(destructive), OpenWorldHint: boolp(open)}}
}
func encode(v any) (JSONOutput, error) {
	b, err := json.Marshal(v)
	return JSONOutput{JSON: string(b)}, err
}
func toolError(err error) (*mcp.CallToolResult, JSONOutput, error) {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, JSONOutput{}, nil
}
func New(app *application.Service, logger *slog.Logger) *mcp.Server {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "cortasentry", Version: Version}, &mcp.ServerOptions{Instructions: "CortaSentry provides authorized defensive asset intelligence. Read tools are safe by default. Write and active scan tools require explicit CortaSentry configuration gates and all scans remain scope constrained.", Logger: logger})
	srv.AddResource(&mcp.Resource{Name: "System status", URI: "cortasentry://status", MIMEType: "application/json"}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		out := mustEncode(map[string]any{"version": Version, "scope": app.Scope.Summary(), "mcp_write_enabled": app.Config.MCP.WriteEnabled, "mcp_active_tools_enabled": app.Config.MCP.ActiveToolsEnabled})
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: "application/json", Text: out.JSON}}}, nil
	})
	srv.AddResource(&mcp.Resource{Name: "Authorization scope", URI: "cortasentry://scope", MIMEType: "application/json"}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		out := mustEncode(app.Scope.Summary())
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: "application/json", Text: out.JSON}}}, nil
	})
	srv.AddResourceTemplate(&mcp.ResourceTemplate{Name: "Asset detail", URITemplate: "cortasentry://assets/{asset_id}", MIMEType: "application/json"}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		u, err := url.Parse(req.Params.URI)
		if err != nil || u.Scheme != "cortasentry" || u.Host != "assets" {
			return nil, fmt.Errorf("invalid asset resource URI")
		}
		id := strings.TrimPrefix(u.Path, "/")
		a, err := app.Store.GetAsset(ctx, id)
		if err != nil {
			return nil, mcp.ResourceNotFoundError(req.Params.URI)
		}
		out := mustEncode(a)
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: "application/json", Text: out.JSON}}}, nil
	})
	mcp.AddTool(srv, readTool("system_status", "System status", "Return database, scope, rule, and MCP safety-gate status."), func(ctx context.Context, req *mcp.CallToolRequest, in Empty) (*mcp.CallToolResult, JSONOutput, error) {
		c := app.Rules.Current()
		digest := ""
		count := 0
		if c != nil {
			digest = c.Digest
			count = len(c.Rules)
		}
		return nil, mustEncode(map[string]any{"version": Version, "scope": app.Scope.Summary(), "rules_digest": digest, "rules_count": count, "mcp_write_enabled": app.Config.MCP.WriteEnabled, "mcp_active_tools_enabled": app.Config.MCP.ActiveToolsEnabled}), nil
	})
	mcp.AddTool(srv, readTool("scope_preview", "Preview scan scope", "Normalize literal IP targets and ports and report whether the configured policy would authorize them without probing."), func(ctx context.Context, req *mcp.CallToolRequest, in ScanInput) (*mcp.CallToolResult, JSONOutput, error) {
		return nil, mustEncode(app.PreviewScan(application.ScanRequest{Targets: in.Targets, Ports: in.Ports})), nil
	})
	mcp.AddTool(srv, readTool("assets_list", "List assets", "List bounded asset identity summaries."), func(ctx context.Context, req *mcp.CallToolRequest, in PageInput) (*mcp.CallToolResult, JSONOutput, error) {
		limit, offset := page(in.Limit, in.Page)
		v, err := app.Store.ListAssets(ctx, "", "", "", limit, offset)
		if err != nil {
			return toolError(err)
		}
		return nil, mustEncode(v), nil
	})
	mcp.AddTool(srv, readTool("asset_get", "Get asset", "Get one asset by UUID."), func(ctx context.Context, req *mcp.CallToolRequest, in AssetInput) (*mcp.CallToolResult, JSONOutput, error) {
		v, err := app.Store.GetAsset(ctx, in.AssetID)
		if err != nil {
			return toolError(err)
		}
		return nil, mustEncode(v), nil
	})
	mcp.AddTool(srv, readTool("observations_list", "List observations", "List sanitized immutable observations with bounded filters."), func(ctx context.Context, req *mcp.CallToolRequest, in ObservationInput) (*mcp.CallToolResult, JSONOutput, error) {
		limit, offset := page(in.Limit, in.Page)
		v, err := app.Store.ListObservations(ctx, in.AssetID, in.Source, in.IP, limit, offset)
		if err != nil {
			return toolError(err)
		}
		return nil, mustEncode(v), nil
	})
	mcp.AddTool(srv, readTool("changes_list", "List changes", "List explainable asset change events."), func(ctx context.Context, req *mcp.CallToolRequest, in struct {
		AssetID string `json:"asset_id,omitempty"`
		Limit   int    `json:"limit,omitempty"`
	}) (*mcp.CallToolResult, JSONOutput, error) {
		v, err := app.Store.ListChanges(ctx, in.AssetID, bounded(in.Limit))
		if err != nil {
			return toolError(err)
		}
		return nil, mustEncode(v), nil
	})
	mcp.AddTool(srv, readTool("findings_list", "List findings", "List uncertainty-preserving security findings."), func(ctx context.Context, req *mcp.CallToolRequest, in struct {
		AssetID  string `json:"asset_id,omitempty"`
		Severity string `json:"severity,omitempty"`
		Limit    int    `json:"limit,omitempty"`
	}) (*mcp.CallToolResult, JSONOutput, error) {
		v, err := app.Store.ListFindings(ctx, in.AssetID, in.Severity, bounded(in.Limit))
		if err != nil {
			return toolError(err)
		}
		return nil, mustEncode(v), nil
	})
	mcp.AddTool(srv, readTool("jobs_list", "List jobs", "List durable scan/import/derivation jobs and progress."), func(ctx context.Context, req *mcp.CallToolRequest, in PageInput) (*mcp.CallToolResult, JSONOutput, error) {
		v, err := app.Store.ListJobs(ctx, bounded(in.Limit))
		if err != nil {
			return toolError(err)
		}
		return nil, mustEncode(v), nil
	})
	mcp.AddTool(srv, readTool("job_get", "Get job", "Get one durable job and current progress by ID."), func(ctx context.Context, req *mcp.CallToolRequest, in CancelInput) (*mcp.CallToolResult, JSONOutput, error) {
		v, err := app.Store.GetJob(ctx, in.JobID)
		if err != nil {
			return toolError(err)
		}
		return nil, mustEncode(v), nil
	})
	mcp.AddTool(srv, readTool("audit_list", "List audit events", "List immutable operator/system authorization and action history."), func(ctx context.Context, req *mcp.CallToolRequest, in PageInput) (*mcp.CallToolResult, JSONOutput, error) {
		v, err := app.Store.ListAudit(ctx, bounded(in.Limit))
		if err != nil {
			return toolError(err)
		}
		return nil, mustEncode(v), nil
	})
	mcp.AddTool(srv, readTool("rules_list", "List fingerprint rules", "Return active typed fingerprint rules and their bundle digest."), func(ctx context.Context, req *mcp.CallToolRequest, in Empty) (*mcp.CallToolResult, JSONOutput, error) {
		return nil, mustEncode(app.Rules.Current()), nil
	})
	mcp.AddTool(srv, readTool("rules_validate", "Validate rules", "Compile and fixture-test configured fingerprint rules without changing the active set."), func(ctx context.Context, req *mcp.CallToolRequest, in Empty) (*mcp.CallToolResult, JSONOutput, error) {
		c, err := fingerprint.LoadPaths(app.Config.Rules.DevicePaths)
		if err != nil {
			return toolError(err)
		}
		if err = fingerprint.TestCompiled(c); err != nil {
			return toolError(err)
		}
		return nil, mustEncode(map[string]any{"rules": len(c.Rules), "digest": c.Digest, "fixtures": "passed"}), nil
	})
	mcp.AddTool(srv, writeTool("scan_create", "Create authorized scan", "Queue a durable active scan. Requires both MCP write and active-tool gates; target scope is still enforced.", false, true), func(ctx context.Context, req *mcp.CallToolRequest, in ScanInput) (*mcp.CallToolResult, JSONOutput, error) {
		if err := app.RequireMCPWrite(true); err != nil {
			return toolError(err)
		}
		if strings.TrimSpace(in.IdempotencyKey) == "" {
			return toolError(fmt.Errorf("idempotency_key is required"))
		}
		j, err := app.SubmitScan(ctx, principal(req), application.ScanRequest{Targets: in.Targets, Ports: in.Ports, IdempotencyKey: in.IdempotencyKey})
		if err != nil {
			return toolError(err)
		}
		return nil, mustEncode(j), nil
	})
	mcp.AddTool(srv, writeTool("job_cancel", "Cancel job", "Request durable cancellation of a queued or running job.", true, false), func(ctx context.Context, req *mcp.CallToolRequest, in CancelInput) (*mcp.CallToolResult, JSONOutput, error) {
		if err := app.RequireMCPWrite(false); err != nil {
			return toolError(err)
		}
		if err := app.CancelJob(ctx, principal(req), in.JobID); err != nil {
			return toolError(err)
		}
		return nil, mustEncode(map[string]string{"status": "cancellation_requested"}), nil
	})
	mcp.AddTool(srv, writeTool("rules_reload", "Reload rules", "Atomically compile, validate, test, and swap configured fingerprint rules.", true, false), func(ctx context.Context, req *mcp.CallToolRequest, in Empty) (*mcp.CallToolResult, JSONOutput, error) {
		if err := app.RequireMCPWrite(false); err != nil {
			return toolError(err)
		}
		if err := app.ReloadRules(ctx, principal(req)); err != nil {
			return toolError(err)
		}
		return nil, mustEncode(map[string]string{"status": "reloaded"}), nil
	})
	mcp.AddTool(srv, writeTool("asset_merge", "Merge assets", "Merge a source asset into a target after explicit confirmation; strong identifier conflicts are rejected.", true, false), func(ctx context.Context, req *mcp.CallToolRequest, in MergeInput) (*mcp.CallToolResult, JSONOutput, error) {
		if err := app.RequireMCPWrite(false); err != nil {
			return toolError(err)
		}
		if !in.Confirm {
			return toolError(fmt.Errorf("confirm must be true"))
		}
		if err := app.MergeAssets(ctx, principal(req), in.SourceAssetID, in.TargetAssetID); err != nil {
			return toolError(err)
		}
		return nil, mustEncode(map[string]string{"status": "merged"}), nil
	})
	mcp.AddTool(srv, writeTool("finding_set_disposition", "Set finding disposition", "Set accepted_risk, false_positive, remediated, or clear disposition with audit history.", true, false), func(ctx context.Context, req *mcp.CallToolRequest, in FindingInput) (*mcp.CallToolResult, JSONOutput, error) {
		if err := app.RequireMCPWrite(false); err != nil {
			return toolError(err)
		}
		if err := app.SetFindingDisposition(ctx, principal(req), in.FindingID, in.Disposition); err != nil {
			return toolError(err)
		}
		return nil, mustEncode(map[string]string{"status": "updated"}), nil
	})
	mcp.AddTool(srv, writeTool("change_acknowledge", "Acknowledge change", "Set or clear operator acknowledgment on a change event.", true, false), func(ctx context.Context, req *mcp.CallToolRequest, in ChangeInput) (*mcp.CallToolResult, JSONOutput, error) {
		if err := app.RequireMCPWrite(false); err != nil {
			return toolError(err)
		}
		if err := app.AcknowledgeChange(ctx, principal(req), in.ChangeID, in.Acknowledged); err != nil {
			return toolError(err)
		}
		return nil, mustEncode(map[string]any{"status": "updated", "acknowledged": in.Acknowledged}), nil
	})
	return srv
}
func Serve(ctx context.Context, app *application.Service, logger *slog.Logger) error {
	return New(app, logger).Run(ctx, &mcp.StdioTransport{})
}
func mustEncode(v any) JSONOutput {
	o, err := encode(v)
	if err != nil {
		return JSONOutput{JSON: `{"error":"encoding failed"}`}
	}
	return o
}
func bounded(n int) int {
	if n < 1 || n > 500 {
		return 100
	}
	return n
}
func page(limit, p int) (int, int) {
	limit = bounded(limit)
	if p < 1 {
		p = 1
	}
	return limit, (p - 1) * limit
}
func principal(req *mcp.CallToolRequest) application.Principal {
	id := "client"
	if req != nil && req.Session != nil {
		id = req.Session.ID()
	}
	return application.Principal{Kind: "mcp", ID: id}
}
