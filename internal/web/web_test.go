package web

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/score"
)

func verdict(pid int32, pids ...int32) score.Verdict {
	return score.Verdict{
		PID:      pid,
		ProcName: "python.exe",
		PIDs:     pids,
		Score:    91.5,
		Level:    score.LevelCritical,
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
