package fleet

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DiscoverTargets builds a list of ClusterTarget from CLI inputs.
//
//   - kubeconfigDir: every regular file in the directory is treated as
//     a kubeconfig; the cluster name is the file's basename with any
//     extension stripped.
//   - kubeconfigs: explicit "name=path" or just "path" entries; a path
//     without "=" derives the name from the file basename.
//
// Either source may be empty. If both are empty the caller will get
// an empty slice and is expected to surface a helpful error.
func DiscoverTargets(kubeconfigDir string, kubeconfigs []string) ([]ClusterTarget, error) {
	var targets []ClusterTarget
	seen := map[string]bool{}

	if kubeconfigDir != "" {
		entries, err := os.ReadDir(kubeconfigDir)
		if err != nil {
			return nil, fmt.Errorf("read kubeconfig dir %s: %w", kubeconfigDir, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(kubeconfigDir, e.Name())
			name := stripExt(e.Name())
			if seen[name] {
				return nil, fmt.Errorf("duplicate cluster name %q from %s", name, path)
			}
			seen[name] = true
			targets = append(targets, ClusterTarget{Name: name, KubeconfigPath: path})
		}
	}

	for _, raw := range kubeconfigs {
		name, path := splitNamePath(raw)
		if path == "" {
			return nil, fmt.Errorf("invalid --kubeconfig entry %q (expected path or name=path)", raw)
		}
		if name == "" {
			name = stripExt(filepath.Base(path))
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate cluster name %q (kubeconfig %s)", name, path)
		}
		seen[name] = true
		targets = append(targets, ClusterTarget{Name: name, KubeconfigPath: path})
	}

	return targets, nil
}

// splitNamePath splits "name=path" into its parts, or returns
// ("", path) for a bare path.
func splitNamePath(raw string) (string, string) {
	idx := strings.Index(raw, "=")
	if idx < 0 {
		return "", raw
	}
	return raw[:idx], raw[idx+1:]
}

// stripExt drops the file extension (".yaml", ".kubeconfig", …) so
// the cluster name in the table is short and stable.
func stripExt(name string) string {
	ext := filepath.Ext(name)
	if ext == "" {
		return name
	}
	return strings.TrimSuffix(name, ext)
}
