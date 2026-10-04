package decoy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// manifestVersion is the schema of the decoy manifest. A file from another
// version is ignored rather than misread.
const manifestVersion = 1

// Manifest records every file this tool planted.
//
// Decoys are written into the user's directories, so the tool has to be able to
// take them out again — including after a crash, and including decoys planted
// under a configuration that has since changed. A manifest is the only thing
// that distinguishes a file we wrote from a file the user wrote.
type Manifest struct {
	Version   int       `json:"version"`
	WrittenAt time.Time `json:"written_at"`
	Paths     []string  `json:"paths"`
}

// LoadManifest reads the manifest at path. A missing manifest is not an error:
// it means nothing has been planted, or nothing was recorded.
func LoadManifest(path string) (*Manifest, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read decoy manifest %s: %w", path, err)
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse decoy manifest %s: %w", path, err)
	}
	if m.Version != manifestVersion {
		return nil, fmt.Errorf("decoy manifest %s is version %d, want %d", path, m.Version, manifestVersion)
	}
	return &m, nil
}

// Save writes the manifest, creating parent directories as needed.
func (m *Manifest) Save(path string) error {
	if path == "" {
		return nil
	}
	m.Version = manifestVersion
	m.WrittenAt = time.Now()
	sort.Strings(m.Paths)

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode decoy manifest: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write decoy manifest %s: %w", path, err)
	}
	return nil
}

// recordPlanted folds this run's decoys into the manifest and saves it.
//
// The union is deliberate. A decoy planted by an earlier run — at a different
// depth, or before a crash — must still be removable, and dropping it from the
// record would strand the file in the user's directory forever.
func recordPlanted(path string, paths []string) error {
	if path == "" {
		return nil
	}

	existing, err := LoadManifest(path)
	if err != nil {
		// A manifest that cannot be read is replaced rather than trusted: the
		// decoys this run planted still have to be removable.
		existing = nil
	}
	if existing == nil {
		existing = &Manifest{}
	}

	seen := make(map[string]struct{}, len(existing.Paths)+len(paths))
	for _, p := range existing.Paths {
		seen[p] = struct{}{}
	}
	for _, p := range paths {
		seen[filepath.Clean(p)] = struct{}{}
	}

	merged := make([]string, 0, len(seen))
	for p := range seen {
		merged = append(merged, p)
	}
	existing.Paths = merged

	return existing.Save(path)
}

// Remove deletes the decoys the manifest records and then the manifest itself.
//
// A file is only removed when its contents are still the canary body. If the
// user replaced a decoy with a real document of the same name, that document is
// left alone and counted as skipped: the manifest says where we wrote, not that
// whatever is there now is ours to delete.
func Remove(manifestPath string) (removed, skipped int, err error) {
	manifest, err := LoadManifest(manifestPath)
	if err != nil || manifest == nil {
		return 0, 0, err
	}

	for _, path := range manifest.Paths {
		body, readErr := os.ReadFile(path)
		switch {
		case os.IsNotExist(readErr):
			continue // already gone; nothing to undo
		case readErr != nil:
			skipped++
			continue
		case string(body) != decoyBody:
			skipped++
			continue
		}
		if err := os.Remove(path); err != nil {
			skipped++
			continue
		}
		removed++
	}

	if err := os.Remove(manifestPath); err != nil && !os.IsNotExist(err) {
		return removed, skipped, fmt.Errorf("remove decoy manifest %s: %w", manifestPath, err)
	}
	return removed, skipped, nil
}
