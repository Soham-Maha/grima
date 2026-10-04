// Package decoy plants canary files and records which paths are canaries.
//
// A decoy is the highest-precision signal in the system: no legitimate process
// has business touching a file the user never created. Decoys are planted by
// this package and detected by the file sensor, which consults the registry.
package decoy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/prateekpurohit13/grima/internal/config"
)

const decoyBody = "Confidential - internal reference copy. Do not modify.\n"

// Registry records which paths are decoy files.
type Registry struct {
	mu     sync.RWMutex
	byPath map[string]string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byPath: make(map[string]string)}
}

// Add registers a decoy path with an identifier used for post-incident
// attribution.
func (r *Registry) Add(path, id string) {
	r.mu.Lock()
	r.byPath[filepath.Clean(path)] = id
	r.mu.Unlock()
}

// Lookup reports whether a path is a decoy and returns its identifier.
func (r *Registry) Lookup(path string) (string, bool) {
	r.mu.RLock()
	id, ok := r.byPath[filepath.Clean(path)]
	r.mu.RUnlock()
	return id, ok
}

// Count returns how many decoys are registered.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byPath)
}

// Plant writes canary files into the monitored directories, registers them, and
// records their paths in the manifest so they can be taken out again.
//
// Depth is bounded by decoy.max_depth and defaults to zero: decoys go in the
// monitored roots and nowhere else. Recursing writes count_per_dir files into
// every directory of the tree, which on a real home directory is thousands of
// plausible-looking documents left in the user's folders, their version control
// and their backups — measured at 66 files across 33 directories from a
// three-second run over a small tree. An operator who wants that reach asks for
// it.
//
// Directories that cannot be written are skipped rather than failing the run:
// planting decoys in some directories is still useful, and an unreadable system
// directory must not stop the detector from starting.
func Plant(cfg config.Config, reg *Registry) (int, error) {
	if !cfg.Decoy.Enabled || len(cfg.Decoy.Names) == 0 {
		return 0, nil
	}

	maxDepth := cfg.Decoy.MaxDepth

	planted := 0
	var paths []string
	var firstErr error

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > maxDepth {
			return
		}
		items, err := os.ReadDir(dir)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("read %s: %w", dir, err)
			}
			return
		}

		found := plantIn(dir, cfg.Decoy, reg)
		planted += len(found)
		paths = append(paths, found...)

		for _, it := range items {
			if !it.IsDir() {
				continue
			}
			name := it.Name()
			if name[0] == '.' || name == "node_modules" || name == "AppData" {
				continue
			}
			walk(filepath.Join(dir, name), depth+1)
		}
	}

	for _, root := range cfg.General.MonitorPaths {
		walk(root, 0)
	}

	if err := recordPlanted(cfg.Decoy.ManifestPath, paths); err != nil && firstErr == nil {
		firstErr = err
	}

	return planted, firstErr
}

// plantIn writes this directory's decoys and returns the paths that are decoys
// afterwards, whether this run wrote them or an earlier one did.
func plantIn(dir string, dc config.DecoyConfig, reg *Registry) []string {
	var planted []string
	for i, name := range dc.Names {
		if i >= dc.CountPerDir {
			break
		}
		path := filepath.Join(dir, name)

		if _, err := os.Stat(path); err == nil {
			reg.Add(path, decoyID(path)) // already there from a previous run
			planted = append(planted, path)
			continue
		}
		if err := os.WriteFile(path, []byte(decoyBody), 0o644); err != nil {
			continue
		}
		reg.Add(path, decoyID(path))
		planted = append(planted, path)
	}
	return planted
}

// decoyID is a short stable hash of the path, so a touched decoy can be named
// without exposing the full path in alerts.
func decoyID(path string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(path)))
	return hex.EncodeToString(sum[:4])
}
