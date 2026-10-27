package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const snapshotManifestName = "current.json"

const snapshotGenerationRetention = 30 * time.Hour

// snapshotManifest is the single atomic publication point for a snapshot
// generation. The three artifacts are immutable once published. Running VMs
// may therefore keep mapping an older generation while a replacement is built.
type snapshotManifest struct {
	VMState  string `json:"vmstate"`
	Memory   string `json:"memory"`
	BaseExt4 string `json:"base_ext4"`
}

func readSnapshotManifest(dir string) (*snapshotFiles, error) {
	body, err := os.ReadFile(filepath.Join(dir, snapshotManifestName))
	if err != nil {
		return nil, err
	}
	var manifest snapshotManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, fmt.Errorf("parse snapshot manifest: %w", err)
	}
	if manifest.VMState == "" || manifest.Memory == "" || manifest.BaseExt4 == "" {
		return nil, fmt.Errorf("snapshot manifest has empty artifact name")
	}
	// Artifact names, never paths, keep the manifest confined to its shape
	// directory even if the file is corrupted or maliciously replaced.
	for _, name := range []string{manifest.VMState, manifest.Memory, manifest.BaseExt4} {
		if filepath.Base(name) != name || name == "." || name == ".." {
			return nil, fmt.Errorf("invalid snapshot artifact name %q", name)
		}
	}
	return &snapshotFiles{
		VmStatePath: filepath.Join(dir, manifest.VMState),
		MemFilePath: filepath.Join(dir, manifest.Memory),
		BaseOverlay: filepath.Join(dir, manifest.BaseExt4),
		Ready:       true,
	}, nil
}

func publishSnapshotManifest(dir string, files *snapshotFiles) error {
	manifest := snapshotManifest{
		VMState:  filepath.Base(files.VmStatePath),
		Memory:   filepath.Base(files.MemFilePath),
		BaseExt4: filepath.Base(files.BaseOverlay),
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".current-*.json")
	if err != nil {
		return fmt.Errorf("create snapshot manifest: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chown(0, 0); err != nil {
		tmp.Close()
		return fmt.Errorf("secure snapshot manifest owner: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, filepath.Join(dir, snapshotManifestName)); err != nil {
		return fmt.Errorf("publish snapshot manifest: %w", err)
	}
	return nil
}

// StartSnapshotJanitor removes immutable generations that have not been
// current for at least 30 hours. It is deliberately independent of Create:
// cleanup never adds directory scans or locks to the sandbox spawn path.
func (m *Manager) StartSnapshotJanitor(ctx context.Context) {
	run := func() {
		removed, err := cleanupObsoleteSnapshotGenerations(m.SnapshotDir, time.Now().Add(-snapshotGenerationRetention))
		if err != nil {
			log.WithContext(ctx).Warnf("[snapshot.janitor] %v", err)
		} else if removed > 0 {
			log.WithContext(ctx).Infof("[snapshot.janitor] removed %d obsolete artifact(s) older than %s", removed, snapshotGenerationRetention)
		}
	}
	run()
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run()
			}
		}
	}()
}

func cleanupObsoleteSnapshotGenerations(root string, cutoff time.Time) (int, error) {
	dirs, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("scan snapshot generations: %w", err)
	}
	removed := 0
	for _, entry := range dirs {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		current, err := readSnapshotManifest(dir)
		if err != nil {
			// A missing/invalid manifest can be a legacy snapshot or an
			// interrupted publication. Never guess which files are live.
			continue
		}
		keep := map[string]struct{}{}
		for _, path := range []string{current.VmStatePath, current.MemFilePath, current.BaseOverlay, baseExt4MetaPath(current.BaseOverlay)} {
			keep[filepath.Base(path)] = struct{}{}
		}
		artifacts, err := os.ReadDir(dir)
		if err != nil {
			return removed, fmt.Errorf("scan %s: %w", dir, err)
		}
		for _, artifact := range artifacts {
			if artifact.IsDir() || !isGenerationArtifact(artifact.Name()) {
				continue
			}
			if _, ok := keep[artifact.Name()]; ok {
				continue
			}
			info, err := artifact.Info()
			if err != nil || !info.ModTime().Before(cutoff) {
				continue
			}
			if err := os.Remove(filepath.Join(dir, artifact.Name())); err == nil || os.IsNotExist(err) {
				removed++
			}
		}
	}
	return removed, nil
}

func isGenerationArtifact(name string) bool {
	return name == "vmstate" || name == "mem" ||
		strings.HasPrefix(name, "vmstate.") ||
		strings.HasPrefix(name, "mem.") ||
		(strings.HasPrefix(name, "base.") && (strings.HasSuffix(name, ".ext4") || strings.HasSuffix(name, ".ext4.meta")))
}
