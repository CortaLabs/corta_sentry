package mcpserver

import (
	"context"
	"github.com/cortalabs/cortasentry/internal/application"
	"github.com/cortalabs/cortasentry/internal/config"
	"github.com/cortalabs/cortasentry/internal/fingerprint"
	"github.com/cortalabs/cortasentry/internal/scope"
	"github.com/cortalabs/cortasentry/internal/storage/sqlite"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"path/filepath"
	"testing"
)

func TestMCPToolsAndSafetyGates(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "mcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := config.Default()
	cfg.Server.Database = filepath.Join(t.TempDir(), "unused")
	sc, err := scope.New(cfg.Scope, store)
	if err != nil {
		t.Fatal(err)
	}
	app, err := application.New(cfg, store, sc, fingerprint.New(.1), nil)
	if err != nil {
		t.Fatal(err)
	}
	server := New(app, nil)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	listed, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) != 18 {
		t.Fatalf("tools=%d", len(listed.Tools))
	}
	var sawScan bool
	for _, tool := range listed.Tools {
		if tool.Name == "scan_create" {
			sawScan = true
			if tool.Annotations == nil || tool.Annotations.ReadOnlyHint || tool.Annotations.OpenWorldHint == nil || !*tool.Annotations.OpenWorldHint {
				t.Fatalf("bad scan annotations %#v", tool.Annotations)
			}
		}
	}
	if !sawScan {
		t.Fatal("scan_create missing")
	}
	status, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "system_status", Arguments: map[string]any{}})
	if err != nil || status.IsError {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	denied, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "scan_create", Arguments: map[string]any{"targets": []string{"127.0.0.1"}, "ports": []int{80}}})
	if err != nil {
		t.Fatal(err)
	}
	if !denied.IsError {
		t.Fatal("disabled MCP write tool succeeded")
	}
}
