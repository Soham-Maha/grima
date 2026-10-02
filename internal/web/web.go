// Package web serves the operator dashboard, the health endpoint, and a live
// verdict stream. The UI is served from the binary; there is no build step.
package web

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/score"
	"github.com/prateekpurohit13/grima/internal/sensor"
)

//go:embed dashboard.html
var dashboardHTML string

// Health is the snapshot served at /healthz.
type Health struct {
	CalibrationReady bool                    `json:"calibration_ready"`
	CalibrationAge   float64                 `json:"calibration_age_seconds"`
	BusPublished     uint64                  `json:"bus_published"`
	BusDropped       uint64                  `json:"bus_dropped"`
	LiveProcesses    int                     `json:"live_processes"`
	Sensors          map[string]sensor.Stats `json:"sensors"`
	Uptime           float64                 `json:"uptime_seconds"`
	Extra            map[string]uint64       `json:"extra,omitempty"`
}

// treeDTO is one process tree as the dashboard renders it: the aggregate
// verdict for its root plus the processes the aggregate was computed from.
type treeDTO struct {
	Root    int32       `json:"root"`
	Name    string      `json:"proc_name"`
	Level   string      `json:"level"`
	Score   float64     `json:"score"`
	Signals []signalDTO `json:"signals"`
	Members []memberDTO `json:"members,omitempty"`
}

// memberDTO is one process contributing to a tree's aggregate. Own is true when
// the process carries its own verdict; otherwise Level and Score are the tree's
// aggregate, which is the risk assessment its activity feeds into.
type memberDTO struct {
	PID   int32   `json:"pid"`
	Level string  `json:"level"`
	Score float64 `json:"score"`
	Own   bool    `json:"own"`
}

// signalDTO is one piece of evidence behind a tree's score.
type signalDTO struct {
	Name   string  `json:"name"`
	Level  string  `json:"level"`
	Value  float64 `json:"value"`
	Detail string  `json:"detail"`
}

// buildTrees turns the per-root verdicts into the dashboard's tree view: one
// entry per root, each carrying its contributing processes. A process that also
// has its own verdict is folded into the tree that claims it as a member
// instead of being reported twice.
func buildTrees(verdicts []score.Verdict) []treeDTO {
	byPID := make(map[int32]score.Verdict, len(verdicts))
	for _, v := range verdicts {
		byPID[v.PID] = v
	}
	claimed := make(map[int32]bool)
	for _, v := range verdicts {
		for _, pid := range v.PIDs {
			if pid != v.PID {
				if _, own := byPID[pid]; own {
					claimed[pid] = true
				}
			}
		}
	}

	out := make([]treeDTO, 0, len(verdicts))
	for _, v := range verdicts {
		if claimed[v.PID] {
			continue
		}
		out = append(out, treeDTO{
			Root:    v.PID,
			Name:    v.ProcName,
			Level:   v.Level.String(),
			Score:   v.Score,
			Signals: signalDTOs(v.Signals),
			Members: memberDTOs(v, byPID),
		})
	}
	return out
}

// memberDTOs lists a tree's contributors. The aggregator counts the root in
// PIDs, so it is dropped here — it already has the tree's own row.
func memberDTOs(v score.Verdict, byPID map[int32]score.Verdict) []memberDTO {
	var members []memberDTO
	seen := make(map[int32]bool, len(v.PIDs))
	for _, pid := range v.PIDs {
		if pid == v.PID || seen[pid] {
			continue
		}
		seen[pid] = true
		m := memberDTO{PID: pid, Level: v.Level.String(), Score: v.Score}
		if own, ok := byPID[pid]; ok {
			m.Level, m.Score, m.Own = own.Level.String(), own.Score, true
		}
		members = append(members, m)
	}
	return members
}

func signalDTOs(signals []score.Signal) []signalDTO {
	out := make([]signalDTO, 0, len(signals))
	for _, s := range signals {
		out = append(out, signalDTO{Name: s.Name, Level: s.Level.String(), Value: s.Value, Detail: s.Detail})
	}
	return out
}

// historyDepth bounds the verdict history the dashboard can show. One verdict is
// recorded per root per scoring tick, so this is tens of minutes of activity at
// the default cadence. It is bounded and counted: a dashboard must not be able to
// grow the detector's memory, and a history that drops entries says so rather
// than silently showing a gap.
const historyDepth = 4096

// historyDTO is one recorded verdict on the timeline: what the dashboard needs
// to draw a point and, when it alerted, a feed entry. The member list is a count
// here — a chart does not need every PID, and the tree view already carries them.
type historyDTO struct {
	At       time.Time   `json:"at"`
	Root     int32       `json:"root"`
	Name     string      `json:"proc_name"`
	Level    string      `json:"level"`
	Score    float64     `json:"score"`
	Override string      `json:"override,omitempty"`
	Signals  []signalDTO `json:"signals"`
	Members  int         `json:"members"`
}

// historyPayload is the history endpoint's envelope. The counters travel with the
// entries so a dashboard can say "showing the last N, M overwritten" instead of
// implying the record is complete.
type historyPayload struct {
	Entries []historyDTO `json:"entries"`
	Size    int          `json:"size"`
	Dropped uint64       `json:"dropped"`
	Depth   int          `json:"depth"`
}

func historyDTOs(verdicts []score.Verdict) []historyDTO {
	out := make([]historyDTO, 0, len(verdicts))
	for _, v := range verdicts {
		out = append(out, historyDTO{
			At:       v.EvaluatedAt,
			Root:     v.PID,
			Name:     v.ProcName,
			Level:    v.Level.String(),
			Score:    v.Score,
			Override: v.Override,
			Signals:  signalDTOs(v.Signals),
			Members:  len(v.PIDs),
		})
	}
	return out
}

// Hub keeps the latest verdict per process, a bounded history of recent
// verdicts, and fans them out to live listeners.
type Hub struct {
	mu      sync.RWMutex
	latest  map[int32]score.Verdict
	history []score.Verdict
	histPos int
	dropped uint64
	// subDropped counts verdicts a live listener did not keep up with. A listener
	// is a bounded queue like every other in the system, so its losses are
	// counted rather than silent.
	subDropped uint64
	subs       map[int]chan score.Verdict
	nextSub    int
	health     func() Health
}

// NewHub returns a hub that reports health through the given function.
func NewHub(health func() Health) *Hub {
	return &Hub{
		latest:  make(map[int32]score.Verdict),
		history: make([]score.Verdict, 0, historyDepth),
		subs:    make(map[int]chan score.Verdict),
		health:  health,
	}
}

// Publish records a verdict and forwards it to live listeners. A listener that
// is not keeping up loses messages rather than blocking the detector.
func (h *Hub) Publish(v score.Verdict) {
	h.mu.Lock()
	h.latest[v.PID] = v
	if len(h.history) < historyDepth {
		h.history = append(h.history, v)
	} else {
		// The ring is full: the oldest entry goes and the loss is counted.
		h.history[h.histPos] = v
		h.histPos = (h.histPos + 1) % historyDepth
		h.dropped++
	}
	subs := make([]chan score.Verdict, 0, len(h.subs))
	for _, ch := range h.subs {
		subs = append(subs, ch)
	}
	h.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- v:
		default:
			// The listener is not keeping up. Counted, not silent: a dashboard
			// that misses updates should be able to say so.
			h.mu.Lock()
			h.subDropped++
			h.mu.Unlock()
		}
	}
}

// History returns the recorded verdicts oldest first, so a chart can plot them
// without reordering. The slice is a copy: a caller must not be able to mutate
// what the hub is holding.
func (h *Hub) History() []score.Verdict {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(h.history) < historyDepth {
		return append([]score.Verdict(nil), h.history...)
	}
	out := make([]score.Verdict, 0, historyDepth)
	out = append(out, h.history[h.histPos:]...)
	out = append(out, h.history[:h.histPos]...)
	return out
}

// HistoryStats reports how much of the history is in use and how many entries
// have been overwritten, so a dashboard can show the gap rather than imply it
// holds everything.
func (h *Hub) HistoryStats() (size int, dropped uint64, depth int) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.history), h.dropped, historyDepth
}

// SubscriberDrops reports verdicts that live listeners did not keep up with.
func (h *Hub) SubscriberDrops() uint64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.subDropped
}

// Retain drops the recorded verdicts whose root is no longer live.
//
// The latest-verdict view is a current assessment, so a verdict for a process
// that has exited is a ghost: it stays at the top of the dashboard for as long
// as the detector runs, and the operator reads it as present tense. The history
// ring keeps the incident, which is where a past finding belongs.
//
// The host pseudo-root is always retained: it is not a process that can exit,
// and in the shipped attribution mode it is where most evidence is filed.
func (h *Hub) Retain(roots []int32) {
	h.mu.Lock()
	defer h.mu.Unlock()

	live := make(map[int32]struct{}, len(roots)+1)
	live[0] = struct{}{}
	for _, root := range roots {
		live[root] = struct{}{}
	}
	for pid := range h.latest {
		if _, ok := live[pid]; !ok {
			delete(h.latest, pid)
		}
	}
}

// Latest returns recorded verdicts, highest score first.
func (h *Hub) Latest() []score.Verdict {
	h.mu.RLock()
	out := make([]score.Verdict, 0, len(h.latest))
	for _, v := range h.latest {
		out = append(out, v)
	}
	h.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

// LatestByPID returns the current verdicts keyed by root.
//
// Unlike Latest it does not rank them, so a caller resolving one process's
// members does not re-sort every process on the host. That matters on the SSE
// path, which does the lookup once per message per connected dashboard.
func (h *Hub) LatestByPID() map[int32]score.Verdict {
	h.mu.RLock()
	defer h.mu.RUnlock()

	out := make(map[int32]score.Verdict, len(h.latest))
	for pid, v := range h.latest {
		out[pid] = v
	}
	return out
}

// Subscribe returns a stream of verdicts and a function to stop listening.
func (h *Hub) Subscribe() (<-chan score.Verdict, func()) {
	ch := make(chan score.Verdict, 64)

	h.mu.Lock()
	id := h.nextSub
	h.nextSub++
	h.subs[id] = ch
	h.mu.Unlock()

	return ch, func() {
		h.mu.Lock()
		delete(h.subs, id)
		h.mu.Unlock()
	}
}

// Server serves the dashboard and health endpoints.
type Server struct {
	cfg  config.Config
	hub  *Hub
	log  *slog.Logger
	tmpl *template.Template
}

// NewServer builds the HTTP server.
func NewServer(cfg config.Config, hub *Hub, log *slog.Logger) (*Server, error) {
	tmpl, err := template.New("dashboard").Parse(dashboardHTML)
	if err != nil {
		return nil, fmt.Errorf("parse dashboard template: %w", err)
	}
	return &Server{cfg: cfg, hub: hub, log: log, tmpl: tmpl}, nil
}

// Start serves until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.dashboard)
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/api/verdicts", s.verdicts)
	mux.HandleFunc("/api/trees", s.trees)
	mux.HandleFunc("/api/history", s.history)
	mux.HandleFunc("/events", s.stream)

	srv := &http.Server{
		Addr:              s.cfg.Web.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	s.log.Info("dashboard listening", "url", "http://"+s.cfg.Web.Listen)

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", err)
	}
	return nil
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.Execute(w, map[string]any{
		"Listen": s.cfg.Web.Listen,
		// The dashboard marks a finding at the level an operator would be paged
		// at, so it comes from the response policy rather than being hard-coded.
		"AlertMin": s.cfg.Response.AlertMinLevel,
	}); err != nil {
		s.log.Warn("dashboard render failed", "error", err)
	}
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	health := s.hub.health()
	// The history is a bounded queue, so its drops belong where every other
	// counter is read rather than only on the dashboard that consumes it.
	if health.Extra == nil {
		health.Extra = make(map[string]uint64)
	}
	size, dropped, depth := s.hub.HistoryStats()
	health.Extra["history_size"] = uint64(size)
	health.Extra["history_dropped"] = dropped
	health.Extra["history_depth"] = uint64(depth)
	health.Extra["sse_dropped"] = s.hub.SubscriberDrops()
	writeJSON(w, health)
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	size, dropped, depth := s.hub.HistoryStats()
	writeJSON(w, historyPayload{
		Entries: historyDTOs(s.hub.History()),
		Size:    size,
		Dropped: dropped,
		Depth:   depth,
	})
}

func (s *Server) verdicts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.hub.Latest())
}

func (s *Server) trees(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, buildTrees(s.hub.Latest()))
}

// treeForVerdict renders one root's tree from the verdict being published, so a
// member that also carries its own verdict resolves the same way the list
// endpoint resolves it.
func (s *Server) treeForVerdict(v score.Verdict) treeDTO {
	return treeDTO{
		Root:    v.PID,
		Name:    v.ProcName,
		Level:   v.Level.String(),
		Score:   v.Score,
		Signals: signalDTOs(v.Signals),
		Members: memberDTOs(v, s.hub.LatestByPID()),
	}
}

func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Open the stream before the first verdict arrives. A browser's EventSource
	// only reports the connection once it sees response headers, so an idle
	// detector would otherwise leave the dashboard unable to tell a live stream
	// from a fallback poll.
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ch, unsubscribe := s.hub.Subscribe()
	defer unsubscribe()

	for {
		select {
		case <-r.Context().Done():
			return
		case v := <-ch:
			data, err := json.Marshal(s.treeForVerdict(v))
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(value)
}
