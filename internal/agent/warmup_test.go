package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"syscall"
)

func TestWarmupLimits(t *testing.T) {
	valid := warmupPlan{Files: []warmupFile{{Path: "/runtime", Ranges: []warmupRange{{0, 4096}}}}}
	cases := map[string]warmupPlan{}
	files := make([]warmupFile, 6)
	for i := range files {
		files[i] = valid.Files[0]
	}
	cases["six files"] = warmupPlan{files}
	for name, r := range map[string]warmupRange{"overflow": {1<<63 - 4096, 4096}, "negative": {-4096, 4096}, "unaligned": {1, 4096}, "too large": {0, warmupMaxBytes + 1}, "empty": {0, 0}} {
		cases[name] = warmupPlan{[]warmupFile{{"/runtime", []warmupRange{r}}}}
	}
	cases["traversal"] = warmupPlan{[]warmupFile{{"/../runtime", nil}}}
	cases["range count"] = warmupPlan{[]warmupFile{{"/runtime", make([]warmupRange, 257)}}}
	cases["combined bytes"] = warmupPlan{[]warmupFile{{"/runtime", []warmupRange{{0, warmupMaxBytes}, {0, 1}}}}}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(p)
			if _, err := decodeWarmup(b); err == nil {
				t.Fatal("accepted invalid plan")
			}
		})
	}
	b, _ := json.Marshal(valid)
	if _, err := decodeWarmup(b); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeWarmup(append(b, []byte(" {}")...)); err == nil {
		t.Fatal("accepted trailing JSON")
	}
	if _, err := decodeWarmup(make([]byte, warmupMaxManifest+1)); err == nil {
		t.Fatal("accepted oversized manifest")
	}
}

func TestWarmupConfinesFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "runtime"), make([]byte, 8192), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/runtime", filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	f, err := openWarmupFile(dir, "/alias")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	for _, p := range []string{"/fifo", "/", "/../runtime"} {
		if f, err := openWarmupFile(dir, p); err == nil {
			f.Close()
			t.Fatalf("opened %s", p)
		}
	}
	// An absolute symlink must not resolve against the agent's initrd.
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte("secret"), 0600)
	os.Symlink(outside, filepath.Join(root, "escape"))
	if f, err := openWarmupFile(dir, "/escape"); err == nil {
		f.Close()
		t.Fatal("escaped image root")
	}
	os.MkdirAll(filepath.Join(root, "etc/createos"), 0755)
	write := func(p warmupPlan) {
		t.Helper()
		b, _ := json.Marshal(p)
		if err := os.WriteFile(filepath.Join(root, warmupManifest), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(warmupPlan{[]warmupFile{{"/missing", []warmupRange{{0, 4096}}}, {"/alias", []warmupRange{{0, 4096}}}}})
	if err := warmImage(root); err != nil {
		t.Fatal(err)
	}
	write(warmupPlan{[]warmupFile{{"/runtime", nil}, {"/alias", nil}}})
	if err := warmImage(root); err == nil {
		t.Fatal("accepted inode alias twice")
	}
	write(warmupPlan{[]warmupFile{{"/runtime", []warmupRange{{8192, 1}}}}})
	if err := warmImage(root); err == nil {
		t.Fatal("accepted out of file range")
	}
}
