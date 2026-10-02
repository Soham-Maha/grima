package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/score"
)

func verdict(pid int32, pids ...int32) score.Verdict {
	return score.Verdict{
		PID:         pid,
		ProcName:    "python.exe",
		PIDs:        pids,
		Score:       91.5,
		Level:       score.LevelCritical,
		EvaluatedAt: time.Now(),
		Signals: []score.Signal{{
			Name:   "write_burst",
			Class:  score.ClassPrimary,
			Value:  0.9,
			Detail: "120.0 writes/s vs baseline 2.0/s",
		}},
	}
}

func memberPIDs(t treeDTO) []int32 {
	out := make([]int32, 0, len(t.Members))
	for _, m := range t.Members {
		out = append(out, m.PID)
	}
	return out
}

func TestBuildTreesGroupsContributors(t *testing.T) {
	tests := []struct {
		name    string
		input   []score.Verdict
		roots   []int32
		members map[int32][]int32
	}{
		{
			name:    "tree of one",
			input:   []score.Verdict{verdict(7, 7)},
			roots:   []int32{7},
			members: map[int32][]int32{7: {}},
		},
		{
			name:    "tree of many",
			input:   []score.Verdict{verdict(7, 7, 8, 9)},
			roots:   []int32{7},
			members: map[int32][]int32{7: {8, 9}},
		},
		{
			name:    "member shares the root pid",
			input:   []score.Verdict{verdict(7, 7, 7, 8)},
			roots:   []int32{7},
			members: map[int32][]int32{7: {8}},
		},
		{
			name:    "empty member list keeps the root",
			input:   []score.Verdict{verdict(7)},
			roots:   []int32{7},
			members: map[int32][]int32{7: {}},
		},
		{
			name:    "claimed member is folded into its tree",
			input:   []score.Verdict{verdict(7, 7, 8), verdict(8, 8)},
			roots:   []int32{7},
			members: map[int32][]int32{7: {8}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildTrees(tc.input)
			roots := make([]int32, 0, len(got))
			for _, tr := range got {
				roots = append(roots, tr.Root)
				if want := tc.members[tr.Root]; !reflect.DeepEqual(memberPIDs(tr), want) {
					t.Fatalf("tree %d members = %v, want %v", tr.Root, memberPIDs(tr), want)
				}
			}
			if !reflect.DeepEqual(roots, tc.roots) {
				t.Fatalf("roots = %v, want %v", roots, tc.roots)
			}
		})
	}
}

func TestBuildTreesMemberKeepsOwnVerdict(t *testing.T) {
	parent := verdict(7, 7, 8)
	child := score.Verdict{
		PID: 8, ProcName: "worker.exe", PIDs: []int32{8},
		Score: 33.0, Level: score.LevelLow,
	}
	got := buildTrees([]score.Verdict{parent, child})
	if len(got) != 1 || got[0].Root != 7 {
		t.Fatalf("trees = %+v, want only root 7", got)
	}
	if len(got[0].Members) != 1 {
		t.Fatalf("members = %+v, want the child", got[0].Members)
	}
	m := got[0].Members[0]
	if !m.Own || m.Level != "low" || m.Score != 33.0 {
		t.Fatalf("member = %+v, want the child's own low verdict", m)
	}
}

func TestBuildTreesInheritsAggregateForPlainMember(t *testing.T) {
	got := buildTrees([]score.Verdict{verdict(7, 7, 8)})
	m := got[0].Members[0]
	if m.Own {
		t.Fatalf("member = %+v, want inherited aggregate, not an own verdict", m)
	}
	if m.Level != "critical" || m.Score != 91.5 {
		t.Fatalf("member = %+v, want the tree's aggregate level and score", m)
	}
}

func TestBuildTreesEmptyIsEmptyNotNil(t *testing.T) {
	got := buildTrees(nil)
	if got == nil || len(got) != 0 {
		t.Fatalf("buildTrees(nil) = %#v, want a non-nil empty slice so JSON is []", got)
	}
}

func newTestServer(t *testing.T, hub *Hub) *Server {
	t.Helper()
	srv, err := NewServer(config.Default(), hub, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func getJSON(t *testing.T, h http.HandlerFunc, path string) []byte {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s status = %d, want 200", path, rec.Code)
	}
	return rec.Body.Bytes()
}

func TestTreesEndpointShape(t *testing.T) {
	hub := NewHub(func() Health { return Health{} })
	hub.Publish(score.Verdict{
		PID: 42, ProcName: "crypt.exe", PIDs: []int32{42, 43},
		Score: 77.25, Level: score.LevelHigh,
		Signals: []score.Signal{{
			Name: "ngram_rename_chain", Value: 0.4,
			Detail: "12 of 30 4-grams hold a write>rename chain",
		}},
	})
	srv := newTestServer(t, hub)

	var got []map[string]any
	if err := json.Unmarshal(getJSON(t, srv.trees, "/api/trees"), &got); err != nil {
		t.Fatalf("decode /api/trees: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("trees = %v, want exactly one", got)
	}
	tree := got[0]
	for _, key := range []string{"root", "proc_name", "level", "score", "signals", "members"} {
		if _, ok := tree[key]; !ok {
			t.Fatalf("tree JSON is missing %q: %v", key, tree)
		}
	}
	if tree["root"] != float64(42) || tree["level"] != "high" || tree["score"] != 77.25 {
		t.Fatalf("aggregate fields = %v", tree)
	}
	sig := tree["signals"].([]any)[0].(map[string]any)
	if sig["name"] != "ngram_rename_chain" || sig["detail"] == "" {
		t.Fatalf("signal = %v", sig)
	}
	mem := tree["members"].([]any)[0].(map[string]any)
	if mem["pid"] != float64(43) || mem["level"] != "high" || mem["own"] != false {
		t.Fatalf("member = %v, want the root's inherited aggregate", mem)
	}
}

func TestTreesEndpointEmpty(t *testing.T) {
	srv := newTestServer(t, NewHub(func() Health { return Health{} }))
	if body := string(getJSON(t, srv.trees, "/api/trees")); body != "[]\n" {
		t.Fatalf("/api/trees empty body = %q, want []", body)
	}
}

// The tree view reads /api/trees, but the scenario scripts poll /api/verdicts
// and the tree fields must stay there too.
func TestVerdictsEndpointKeepsMemberPIDs(t *testing.T) {
	hub := NewHub(func() Health { return Health{} })
	hub.Publish(score.Verdict{PID: 5, PIDs: []int32{5, 6}, Level: score.LevelLow})
	srv := newTestServer(t, hub)

	var got []map[string]any
	if err := json.Unmarshal(getJSON(t, srv.verdicts, "/api/verdicts"), &got); err != nil {
		t.Fatalf("decode /api/verdicts: %v", err)
	}
	pids, ok := got[0]["PIDs"].([]any)
	if !ok || len(pids) != 2 || pids[0] != float64(5) || pids[1] != float64(6) {
		t.Fatalf("/api/verdicts PIDs = %v, want [5 6]", got[0]["PIDs"])
	}
}

func TestTreeForMatchesTheListEndpoint(t *testing.T) {
	hub := NewHub(func() Health { return Health{} })
	hub.Publish(verdict(7, 7, 8))
	srv := newTestServer(t, hub)

	tree, ok := srv.treeFor(7)
	if !ok || tree.Root != 7 || len(tree.Members) != 1 || tree.Members[0].PID != 8 {
		t.Fatalf("treeFor(7) = %+v, %v", tree, ok)
	}
	if _, ok := srv.treeFor(999); ok {
		t.Fatal("treeFor of an unknown root should report no tree")
	}
}

// The history is what lets the dashboard show an incident that has already
// scrolled past, so its order matters: oldest first, so a chart plots it as is.
func TestHistoryIsChronologicalAndCountsWhatItOverwrites(t *testing.T) {
	hub := NewHub(func() Health { return Health{} })

	const overflow = 5
	for i := range historyDepth + overflow {
		v := verdict(1)
		v.Score = float64(i)
		hub.Publish(v)
	}

	history := hub.History()
	if len(history) != historyDepth {
		t.Fatalf("history holds %d entries, want the ring depth %d", len(history), historyDepth)
	}
	for i := 1; i < len(history); i++ {
		if history[i].Score <= history[i-1].Score {
			t.Fatalf("history is not oldest-first at %d: %.0f then %.0f", i, history[i-1].Score, history[i].Score)
		}
	}
	if got, want := history[0].Score, float64(overflow); got != want {
		t.Errorf("oldest entry = %.0f, want %.0f (the first %d were overwritten)", got, want, overflow)
	}

	size, dropped, depth := hub.HistoryStats()
	if size != historyDepth || depth != historyDepth {
		t.Errorf("size %d depth %d, want both %d", size, depth, historyDepth)
	}
	if dropped != overflow {
		t.Errorf("dropped = %d, want %d: a bounded history must count what it lost", dropped, overflow)
	}
}

func TestHistoryEndpointReportsTheGap(t *testing.T) {
	hub := NewHub(func() Health { return Health{} })
	first := verdict(7, 7, 8)
	hub.Publish(first)
	hub.Publish(verdict(9))
	srv := newTestServer(t, hub)

	var payload historyPayload
	if err := json.Unmarshal(getJSON(t, srv.history, "/api/history"), &payload); err != nil {
		t.Fatalf("history payload: %v", err)
	}
	if len(payload.Entries) != 2 || payload.Size != 2 || payload.Depth != historyDepth {
		t.Fatalf("payload = %d entries, size %d, depth %d; want 2/2/%d",
			len(payload.Entries), payload.Size, payload.Depth, historyDepth)
	}
	entry := payload.Entries[0]
	if entry.Root != 7 || entry.Members != 2 {
		t.Errorf("first entry = root %d, %d members; want 7 and 2", entry.Root, entry.Members)
	}
	if len(entry.Signals) != 1 || entry.Signals[0].Name != "write_burst" {
		t.Errorf("first entry carries %v, want the verdict's signal", entry.Signals)
	}
	if entry.At.IsZero() {
		t.Error("entry has no timestamp, so a timeline cannot place it")
	}
}

// A bounded queue's drops are surfaced where every other counter is read.
func TestHealthzSurfacesTheHistoryCounters(t *testing.T) {
	hub := NewHub(func() Health { return Health{} })
	hub.Publish(verdict(1))
	srv := newTestServer(t, hub)

	var health Health
	if err := json.Unmarshal(getJSON(t, srv.healthz, "/healthz"), &health); err != nil {
		t.Fatalf("health payload: %v", err)
	}
	if health.Extra["history_size"] != 1 {
		t.Errorf("history_size = %d, want 1", health.Extra["history_size"])
	}
	if _, ok := health.Extra["history_dropped"]; !ok {
		t.Error("history_dropped is missing, so a gap would be invisible")
	}
	if health.Extra["history_depth"] != historyDepth {
		t.Errorf("history_depth = %d, want %d", health.Extra["history_depth"], historyDepth)
	}
}

// The dashboard must render from the single embedded file with no build step
// and no network: the incident view is useless offline if it pulls an asset.
func TestDashboardLoadsNoExternalAsset(t *testing.T) {
	srv := newTestServer(t, NewHub(func() Health { return Health{} }))
	rec := httptest.NewRecorder()
	srv.dashboard(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, forbidden := range []string{"<script src", "<link", "@import", "url(http", "srcset=", "integrity="} {
		if strings.Contains(body, forbidden) {
			t.Errorf("dashboard references %q; it must be self-contained", forbidden)
		}
	}
}

// The three additions read the alert level from config, so the operator sees
// the findings the responder would page on, not a hard-coded level.
func TestDashboardWiresTheAlertLevelAndPanels(t *testing.T) {
	cfg := config.Default()
	cfg.Response.AlertMinLevel = "high"
	srv, err := NewServer(cfg, NewHub(func() Health { return Health{} }), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.dashboard(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	body := rec.Body.String()
	if !strings.Contains(body, `data-alert-min="high"`) {
		t.Error("dashboard does not carry the configured alert level")
	}
	for _, id := range []string{`id="chart"`, `id="feed"`, `id="signals"`, `id="rows"`, `id="completeness"`} {
		if !strings.Contains(body, id) {
			t.Errorf("dashboard is missing the %s container", id)
		}
	}
	// The four band thresholds are drawn from the scoring defaults.
	for _, band := range []string{"low", "medium", "high", "critical"} {
		if !strings.Contains(body, `"`+band+`"`) {
			t.Errorf("dashboard does not name the %q band", band)
		}
	}
	if !strings.Contains(body, "/api/history") || !strings.Contains(body, "/events") {
		t.Error("dashboard must read history and the live stream")
	}
}

// The feed renders signal details and the signal panel ranks by value, so both
// fields must be on the wire, not only the count the chart uses.
func TestHistoryEntryCarriesSignalValueAndDetail(t *testing.T) {
	hub := NewHub(func() Health { return Health{} })
	v := verdict(3)
	v.Signals = []score.Signal{
		{Name: "rename_chain", Value: 0.75, Detail: "12 renames follow a write"},
		{Name: "entropy_delta", Value: 0.5, Detail: "entropy +3.1 bits"},
	}
	hub.Publish(v)
	srv := newTestServer(t, hub)

	var payload historyPayload
	if err := json.Unmarshal(getJSON(t, srv.history, "/api/history"), &payload); err != nil {
		t.Fatalf("history payload: %v", err)
	}
	if len(payload.Entries) != 1 || len(payload.Entries[0].Signals) != 2 {
		t.Fatalf("entries = %+v, want one entry with two signals", payload.Entries)
	}
	first := payload.Entries[0].Signals[0]
	if first.Name != "rename_chain" || first.Value != 0.75 || first.Detail == "" {
		t.Fatalf("signal = %+v, want name, value and detail on the wire", first)
	}
}

// An empty history must serialise as an array: the dashboard is expected to run
// with no findings at all and must not have to guard a null.
func TestHistoryEndpointEmptyIsAnArray(t *testing.T) {
	srv := newTestServer(t, NewHub(func() Health { return Health{} }))
	body := string(getJSON(t, srv.history, "/api/history"))
	if !strings.Contains(body, `"entries": []`) {
		t.Fatalf("empty /api/history = %q, want an empty entries array", body)
	}
}

// A browser cannot see an SSE connection until the response headers arrive, so
// the stream must open before the first verdict; otherwise an idle detector
// looks like a dead stream and the dashboard falls back to polling for no
// reason. The forwarded message proves the hello did not consume the channel.
func TestStreamOpensImmediatelyAndForwardsTrees(t *testing.T) {
	hub := NewHub(func() Health { return Health{} })
	srv := newTestServer(t, hub)

	ctx, cancel := context.WithCancel(context.Background())
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		srv.stream(rec, httptest.NewRequest(http.MethodGet, "/events", nil).WithContext(ctx))
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	hub.Publish(verdict(7, 7, 8))
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	body := rec.Body.String()
	if !strings.Contains(body, ": connected") {
		t.Errorf("stream did not open immediately: %q", body)
	}
	if !strings.Contains(body, "data: ") || !strings.Contains(body, `"root":7`) {
		t.Errorf("stream did not forward the tree: %q", body)
	}
}
