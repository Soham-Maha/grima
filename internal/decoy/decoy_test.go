package decoy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prateekpurohit13/grima/internal/config"
)

func plantConfig(t *testing.T, dir string) config.Config {
	t.Helper()

	cfg := config.Default()
	cfg.General.MonitorPaths = []string{dir}
	cfg.Decoy.Enabled = true
	cfg.Decoy.Names = []string{"_grima_canary.doc", "quarterly_report_2019.xlsx", "invoices_backup.pdf"}
	cfg.Decoy.CountPerDir = 2
	// The manifest is a scratch file: tests must not write one into the package
	// directory, and a real manifest does not belong in a monitored tree either.
	cfg.Decoy.ManifestPath = filepath.Join(t.TempDir(), "grima-decoys.json")
	return cfg
}

func TestPlantWritesAndRegistersDecoys(t *testing.T) {
	dir := t.TempDir()
	cfg := plantConfig(t, dir)
	reg := NewRegistry()

	planted, err := Plant(cfg, reg)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}
	if planted != cfg.Decoy.CountPerDir {
		t.Fatalf("planted = %d, want %d", planted, cfg.Decoy.CountPerDir)
	}
	if reg.Count() != cfg.Decoy.CountPerDir {
		t.Fatalf("registered = %d, want %d", reg.Count(), cfg.Decoy.CountPerDir)
	}

	for i := 0; i < cfg.Decoy.CountPerDir; i++ {
		path := filepath.Join(dir, cfg.Decoy.Names[i])

		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("decoy file %s missing: %v", path, err)
		}
		if string(body) != decoyBody {
			t.Fatalf("decoy body = %q, want %q", body, decoyBody)
		}

		id, ok := reg.Lookup(path)
		if !ok {
			t.Fatalf("Lookup(%s) says not a decoy", path)
		}
		if id == "" {
			t.Fatalf("decoy id for %s is empty", path)
		}
	}

	// The name past count_per_dir must not be planted.
	beyond := filepath.Join(dir, cfg.Decoy.Names[cfg.Decoy.CountPerDir])
	if _, err := os.Stat(beyond); err == nil {
		t.Fatalf("%s was planted beyond count_per_dir", beyond)
	}
	if id, ok := reg.Lookup(beyond); ok {
		t.Fatalf("Lookup(%s) = %q, want not a decoy", beyond, id)
	}
}

func TestLookupRejectsPathsThatAreNotDecoys(t *testing.T) {
	dir := t.TempDir()
	cfg := plantConfig(t, dir)
	reg := NewRegistry()
	if _, err := Plant(cfg, reg); err != nil {
		t.Fatalf("Plant: %v", err)
	}

	plain := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(plain, []byte("mine"), 0o644); err != nil {
		t.Fatalf("write %s: %v", plain, err)
	}

	if id, ok := reg.Lookup(plain); ok {
		t.Fatalf("Lookup(%s) = %q, want not a decoy", plain, id)
	}
	if id, ok := reg.Lookup(filepath.Join(dir, "does-not-exist.doc")); ok {
		t.Fatalf("Lookup of a missing file = %q, want not a decoy", id)
	}
}

// A registry keyed by path must match the same file however the path is spelled.
// filepath.Join cleans, so the unclean spelling is built by concatenation —
// otherwise the test would only ever exercise clean paths on both sides.
func TestLookupIgnoresPathSpelling(t *testing.T) {
	dir := t.TempDir()
	reg := NewRegistry()

	sep := string(filepath.Separator)
	clean := filepath.Join(dir, "_grima_canary.doc")
	unclean := filepath.Join(dir, "sub") + sep + ".." + sep + "_grima_canary.doc"
	if unclean == clean {
		t.Fatalf("fixture is not actually unclean: %q", unclean)
	}

	reg.Add(unclean, "canary-1")

	if id, ok := reg.Lookup(clean); !ok || id != "canary-1" {
		t.Fatalf("Lookup(%s) = %q, %v; want canary-1, true", clean, id, ok)
	}
	if id, ok := reg.Lookup(unclean); !ok || id != "canary-1" {
		t.Fatalf("Lookup(%s) = %q, %v; want canary-1, true", unclean, id, ok)
	}
}

func TestPlantTwiceKeepsOneEntryPerDecoy(t *testing.T) {
	dir := t.TempDir()
	cfg := plantConfig(t, dir)
	reg := NewRegistry()

	if _, err := Plant(cfg, reg); err != nil {
		t.Fatalf("first Plant: %v", err)
	}
	first, _ := reg.Lookup(filepath.Join(dir, cfg.Decoy.Names[0]))

	if _, err := Plant(cfg, reg); err != nil {
		t.Fatalf("second Plant: %v", err)
	}
	if reg.Count() != cfg.Decoy.CountPerDir {
		t.Fatalf("registered = %d after planting twice, want %d", reg.Count(), cfg.Decoy.CountPerDir)
	}
	second, ok := reg.Lookup(filepath.Join(dir, cfg.Decoy.Names[0]))
	if !ok || second != first {
		t.Fatalf("decoy id changed between plants: %q then %q", first, second)
	}
}

func TestPlantKeepsAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	cfg := plantConfig(t, dir)

	existing := filepath.Join(dir, cfg.Decoy.Names[0])
	const operatorContent = "the operator's own file"
	if err := os.WriteFile(existing, []byte(operatorContent), 0o644); err != nil {
		t.Fatalf("write %s: %v", existing, err)
	}

	reg := NewRegistry()
	planted, err := Plant(cfg, reg)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}
	if planted != cfg.Decoy.CountPerDir {
		t.Fatalf("planted = %d, want %d", planted, cfg.Decoy.CountPerDir)
	}

	body, err := os.ReadFile(existing)
	if err != nil {
		t.Fatalf("read %s: %v", existing, err)
	}
	if string(body) != operatorContent {
		t.Fatalf("existing file was overwritten: %q", body)
	}
	if _, ok := reg.Lookup(existing); !ok {
		t.Fatalf("Lookup(%s) says not a decoy", existing)
	}
}

func TestPlantDisabledPlantsNothing(t *testing.T) {
	dir := t.TempDir()
	cfg := plantConfig(t, dir)
	cfg.Decoy.Enabled = false

	reg := NewRegistry()
	planted, err := Plant(cfg, reg)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}
	if planted != 0 || reg.Count() != 0 {
		t.Fatalf("planted = %d, registered = %d; want 0 and 0", planted, reg.Count())
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	if len(entries) != 0 {
		t.Fatalf("%d files created with decoys disabled", len(entries))
	}
}

func TestPlantSkipsAnUnreadableRootAndPlantsTheRest(t *testing.T) {
	dir := t.TempDir()
	cfg := plantConfig(t, dir)
	missing := filepath.Join(dir, "missing")
	cfg.General.MonitorPaths = []string{missing, dir}

	reg := NewRegistry()
	planted, err := Plant(cfg, reg)
	if err == nil {
		t.Fatalf("Plant reported no error for the unreadable root %s", missing)
	}
	if planted != cfg.Decoy.CountPerDir {
		t.Fatalf("planted = %d, want %d from the readable root", planted, cfg.Decoy.CountPerDir)
	}
	if reg.Count() != cfg.Decoy.CountPerDir {
		t.Fatalf("registered = %d, want %d", reg.Count(), cfg.Decoy.CountPerDir)
	}
}

// Decoys are planted in the monitored roots by default. Recursing writes files
// into every directory of the tree, which on a real home directory is thousands
// of documents left in the user's folders — so it is opt-in.
func TestPlantDefaultDepthStaysInTheMonitoredRoot(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "Documents", "reports")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := plantConfig(t, dir)
	if cfg.Decoy.MaxDepth != 0 {
		t.Fatalf("default max_depth = %d, want 0", cfg.Decoy.MaxDepth)
	}

	reg := NewRegistry()
	planted, err := Plant(cfg, reg)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}
	if planted != cfg.Decoy.CountPerDir {
		t.Fatalf("planted = %d, want %d in the root only", planted, cfg.Decoy.CountPerDir)
	}

	for _, below := range []string{filepath.Join(dir, "Documents"), sub} {
		for i := range cfg.Decoy.CountPerDir {
			path := filepath.Join(below, cfg.Decoy.Names[i])
			if _, err := os.Stat(path); err == nil {
				t.Fatalf("%s was planted below the monitored root at the default depth", path)
			}
		}
	}
}

// An operator who wants decoys deeper in the tree asks for it, and gets exactly
// the depth they asked for.
func TestPlantHonoursMaxDepth(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := plantConfig(t, dir)
	cfg.Decoy.MaxDepth = 1

	reg := NewRegistry()
	planted, err := Plant(cfg, reg)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}

	// The root and one level below it, and not the level below that.
	want := cfg.Decoy.CountPerDir * 2
	if planted != want {
		t.Fatalf("planted = %d, want %d (root and depth 1)", planted, want)
	}
	entries, err := os.ReadDir(deep)
	if err != nil {
		t.Fatalf("read %s: %v", deep, err)
	}
	if len(entries) != 0 {
		t.Fatalf("depth 2 was planted with max_depth = 1 (%d files)", len(entries))
	}
}

// A decoy planted by an earlier run has to stay removable, so the manifest is a
// union rather than a snapshot of the latest run.
func TestManifestKeepsEarlierPaths(t *testing.T) {
	dir := t.TempDir()
	cfg := plantConfig(t, dir)

	reg := NewRegistry()
	if _, err := Plant(cfg, reg); err != nil {
		t.Fatalf("Plant: %v", err)
	}

	first, err := LoadManifest(cfg.Decoy.ManifestPath)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	if len(first.Paths) != cfg.Decoy.CountPerDir {
		t.Fatalf("manifest holds %d paths, want %d", len(first.Paths), cfg.Decoy.CountPerDir)
	}

	// A second root, as an operator who widened monitor_paths would have.
	second := t.TempDir()
	cfg.General.MonitorPaths = []string{second}
	if _, err := Plant(cfg, reg); err != nil {
		t.Fatalf("second Plant: %v", err)
	}

	merged, err := LoadManifest(cfg.Decoy.ManifestPath)
	if err != nil {
		t.Fatalf("load merged manifest: %v", err)
	}
	if len(merged.Paths) != cfg.Decoy.CountPerDir*2 {
		t.Fatalf("manifest holds %d paths after a second root, want %d",
			len(merged.Paths), cfg.Decoy.CountPerDir*2)
	}
}

// The undo has to work after a restart, which is the whole reason the manifest
// is on disk rather than in memory.
func TestRemoveDeletesPlantedDecoysAndTheManifest(t *testing.T) {
	dir := t.TempDir()
	cfg := plantConfig(t, dir)
	cfg.Decoy.MaxDepth = 1
	sub := filepath.Join(dir, "nested")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	reg := NewRegistry()
	planted, err := Plant(cfg, reg)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}

	removed, skipped, err := Remove(cfg.Decoy.ManifestPath)
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if removed != planted {
		t.Fatalf("removed = %d, want %d", removed, planted)
	}
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0", skipped)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	if len(entries) != 1 || entries[0].Name() != "nested" {
		t.Fatalf("root holds %v after removal, want only the nested directory", entries)
	}
	if _, err := os.Stat(cfg.Decoy.ManifestPath); !os.IsNotExist(err) {
		t.Fatalf("manifest survived removal: %v", err)
	}
}

// The manifest records where we wrote, not that whatever is there now is ours.
// A decoy the user replaced with a real document must not be deleted.
func TestRemoveLeavesAReplacedDecoyAlone(t *testing.T) {
	dir := t.TempDir()
	cfg := plantConfig(t, dir)

	reg := NewRegistry()
	if _, err := Plant(cfg, reg); err != nil {
		t.Fatalf("Plant: %v", err)
	}

	replaced := filepath.Join(dir, cfg.Decoy.Names[0])
	const operatorContent = "the operator's own document"
	if err := os.WriteFile(replaced, []byte(operatorContent), 0o644); err != nil {
		t.Fatalf("write %s: %v", replaced, err)
	}

	removed, skipped, err := Remove(cfg.Decoy.ManifestPath)
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if removed != cfg.Decoy.CountPerDir-1 || skipped != 1 {
		t.Fatalf("removed = %d, skipped = %d; want %d and 1",
			removed, skipped, cfg.Decoy.CountPerDir-1)
	}

	body, err := os.ReadFile(replaced)
	if err != nil {
		t.Fatalf("the operator's file was deleted: %v", err)
	}
	if string(body) != operatorContent {
		t.Fatalf("the operator's file was modified: %q", body)
	}
}

// Removing with nothing planted is a no-op, not an error: the manifest is
// absent on a host that never ran the detector.
func TestRemoveWithoutAManifestDoesNothing(t *testing.T) {
	removed, skipped, err := Remove(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if removed != 0 || skipped != 0 {
		t.Fatalf("removed = %d, skipped = %d; want 0 and 0", removed, skipped)
	}
}
