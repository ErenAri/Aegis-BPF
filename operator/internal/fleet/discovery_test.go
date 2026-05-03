package fleet

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverTargetsFromDir(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"prod-eu.kubeconfig", "prod-us.yaml", "staging"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fake"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	// Sub-directory should be ignored.
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	got, err := DiscoverTargets(dir, nil)
	if err != nil {
		t.Fatalf("DiscoverTargets: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 targets, got %d (%+v)", len(got), got)
	}
	names := map[string]bool{}
	for _, tgt := range got {
		names[tgt.Name] = true
	}
	for _, want := range []string{"prod-eu", "prod-us", "staging"} {
		if !names[want] {
			t.Errorf("missing cluster name %q in %+v", want, names)
		}
	}
}

func TestDiscoverTargetsExplicitNamePathPairs(t *testing.T) {
	got, err := DiscoverTargets("", []string{
		"prod-eu=/srv/k/eu",
		"/srv/k/staging.yaml",
	})
	if err != nil {
		t.Fatalf("DiscoverTargets: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 targets, got %+v", got)
	}
	if got[0].Name != "prod-eu" || got[0].KubeconfigPath != "/srv/k/eu" {
		t.Errorf("first entry wrong: %+v", got[0])
	}
	if got[1].Name != "staging" {
		t.Errorf("second entry name should derive from filename; got %q", got[1].Name)
	}
}

func TestDiscoverTargetsRejectsDuplicates(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "prod.kubeconfig"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := DiscoverTargets(dir, []string{"prod=/somewhere/else"})
	if err == nil {
		t.Fatal("expected duplicate-name error, got nil")
	}
}

func TestDiscoverTargetsRejectsEmptyPath(t *testing.T) {
	_, err := DiscoverTargets("", []string{"name="})
	if err == nil {
		t.Fatal("expected error for empty path, got nil")
	}
}
