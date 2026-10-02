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

// Hub keeps the latest verdict per process and fans them out to live listeners.
type Hub struct {
	mu      sync.RWMutex
	latest  map[int32]score.Verdict
	subs    map[int]chan score.Verdict
	nextSub int
	health  func() Health
}

// NewHub returns a hub that reports health through the given function.
func NewHub(health func() Health) *Hub {
	return &Hub{
		latest: make(map[int32]score.Verdict),
		subs:   make(map[int]chan score.Verdict),
		health: health,
	}
}

// Publish records a verdict and forwards it to live listeners. A listener that
// is not keeping up loses messages rather than blocking the detector.
func (h *Hub) Publish(v score.Verdict) {
	h.mu.Lock()
	h.latest[v.PID] = v
	subs := make([]chan score.Verdict, 0, len(h.subs))
	for _, ch := range h.subs {
		subs = append(subs, ch)
	}
	h.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- v:
		default:
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
	}); err != nil {
		s.log.Warn("dashboard render failed", "error", err)
	}
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.hub.health())
}

func (s *Server) verdicts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.hub.Latest())
}

func (s *Server) trees(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, buildTrees(s.hub.Latest()))
}

// treeFor renders one root's tree from the hub's current set, so a member that
// also carries its own verdict resolves the same way the list endpoint does.
func (s *Server) treeFor(root int32) (treeDTO, bool) {
	for _, t := range buildTrees(s.hub.Latest()) {
		if t.Root == root {
			return t, true
		}
	}
	return treeDTO{}, false
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

	ch, unsubscribe := s.hub.Subscribe()
	defer unsubscribe()

	for {
		select {
		case <-r.Context().Done():
			return
		case v := <-ch:
			tree, ok := s.treeFor(v.PID)
			if !ok {
				continue
			}
			data, err := json.Marshal(tree)
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
