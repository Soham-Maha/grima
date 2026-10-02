// Package score turns tree vectors and rule hits into explainable verdicts.
// Every verdict decomposes into named signals; there is no opaque output.
package score

import (
	"sort"
	"time"

	"github.com/prateekpurohit13/grima/internal/calibrate"
	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/fingerprint"
)

// Level is a risk level.
type Level uint8

const (
	LevelInfo Level = iota
	LevelLow
	LevelMedium
	LevelHigh
	LevelCritical
)

var levelNames = [...]string{"info", "low", "medium", "high", "critical"}

func (l Level) String() string {
	if int(l) < len(levelNames) {
		return levelNames[l]
	}
	return "level(?)"
}

// ParseLevel resolves a configuration string to a level.
func ParseLevel(s string) (Level, bool) {
	for i, n := range levelNames {
		if n == s {
			return Level(i), true
		}
	}
	return LevelInfo, false
}

// Class determines how a signal participates in fusion.
type Class uint8

const (
	ClassPrimary Class = iota
	ClassSecondary
	ClassOverride
)

var classNames = [...]string{"primary", "secondary", "override"}

func (c Class) String() string {
	if int(c) < len(classNames) {
		return classNames[c]
	}
	return "class(?)"
}

// Signal is one named piece of evidence.
type Signal struct {
	Name   string
	Class  Class
	Value  float64 // normalized 0..1
	Level  Level   // meaningful only for ClassOverride
	Detail string
}

// Override is a rule hit expressed in terms the scorer understands. Defined here
// so the rules package can depend on score without a cycle.
type Override struct {
	ID     string
	Level  Level
	Detail string
}

// Verdict is the scored output for one process tree.
type Verdict struct {
	PID         int32
	ProcName    string
	PIDs        []int32
	Score       float64 // 0..100
	Level       Level
	Signals     []Signal
	Override    string
	Calibrated  bool
	EvaluatedAt time.Time
}

// Inputs is everything needed for one evaluation.
type Inputs struct {
	Tree       fingerprint.TreeVector
	Baseline   *calibrate.Baseline
	BusDropped uint64
	Overrides  []Override
}

// Scorer fuses signals into verdicts.
type Scorer struct {
	cfg config.Config
}

// NewScorer returns a scorer bound to a configuration.
func NewScorer(cfg config.Config) *Scorer {
	return &Scorer{cfg: cfg}
}

// Evaluate computes signals, fuses them, and applies override floors.
func (s *Scorer) Evaluate(in Inputs) Verdict {
	calibrated := in.Baseline != nil && in.Baseline.Ready()

	signals := s.computeSignals(in, calibrated)
	for _, ov := range in.Overrides {
		signals = append(signals, Signal{
			Name:   ov.ID,
			Class:  ClassOverride,
			Value:  1,
			Level:  ov.Level,
			Detail: ov.Detail,
		})
	}

	v := Verdict{
		PID:         in.Tree.Root,
		ProcName:    in.Tree.ProcName,
		PIDs:        in.Tree.PIDs,
		Calibrated:  calibrated,
		EvaluatedAt: time.Now(),
	}

	// Independent signals combine as independent evidence, not as an average.
	//
	// With a weighted mean, adding a weak signal LOWERS the score: a saturated
	// extension-novelty signal alone scored 100, while the same signal alongside
	// three weaker ones scored 56.4, so more evidence of the same attack read as
	// less severe. Noisy-OR is monotonic — a signal can only add — which is the
	// property a risk score has to have.
	//
	// Corroboration is structural, not arithmetic (Sprint 4, item 4.9). A
	// Secondary signal may not carry a verdict; its weight applies only while at
	// least one Primary signal is present. The arithmetic alternative — keep
	// every Secondary weight below the medium band — bounds each signal but not
	// a combination of them, and it is a property of the (weight, band) pair
	// rather than of the tier: with the shipped weights, delete_rate +
	// dir_fanout + cum_bytes_rewritten + ngram_rename_chain + bus_drops, all
	// saturated and nothing else present, fuses to 86.2 high. static_reputation,
	// a Secondary in design.md §5, is configured at 0.6 — 60.0 medium — for the
	// day Phase 7 emits it. Gating on a Primary makes both impossible at any
	// band value, so the tier's meaning no longer depends on where the band is
	// set.
	hasPrimary := false
	for _, sg := range signals {
		if sg.Class == ClassPrimary {
			hasPrimary = true
			break
		}
	}

	combined := 1.0
	for _, sg := range signals {
		if sg.Class == ClassOverride {
			continue
		}
		if sg.Class == ClassSecondary && !hasPrimary {
			// Still reported below; it simply does not fuse on its own.
			continue
		}
		w := s.cfg.WeightFor(sg.Name)
		if w <= 0 {
			continue
		}
		combined *= 1 - clamp01(w*sg.Value)
	}
	v.Score = (1 - combined) * 100
	v.Level = s.levelFor(v.Score)

	// Overrides set a floor and are never averaged away by benign signals.
	for _, sg := range signals {
		if sg.Class != ClassOverride {
			continue
		}
		if sg.Level > v.Level {
			v.Level = sg.Level
		}
		if v.Override == "" {
			v.Override = sg.Name
		}
	}

	sort.SliceStable(signals, func(i, j int) bool {
		if signals[i].Class != signals[j].Class {
			return signals[i].Class > signals[j].Class
		}
		return signals[i].Value > signals[j].Value
	})
	v.Signals = signals

	return v
}

func (s *Scorer) levelFor(score float64) Level {
	b := s.cfg.Scoring.LevelBands
	switch {
	case score >= b.Critical:
		return LevelCritical
	case score >= b.High:
		return LevelHigh
	case score >= b.Medium:
		return LevelMedium
	case score >= b.Low:
		return LevelLow
	}
	return LevelInfo
}
