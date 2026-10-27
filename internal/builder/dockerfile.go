package builder

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
)

// AllowedBases is the canonical set of bases users may extend. Templates
// whose FROM doesn't appear in this list are rejected at submit time.
var AllowedBases = []string{
	"nodeops/sandbox:debian",
	"nodeops/sandbox:alpine",
}

// allowedInstructions is the instruction allowlist. Anything outside this
// set is rejected — denylist scales poorly as Docker adds new directives
// (we'd have to chase every release). The current allowlist covers
// legitimate single-stage builds without exposing the surface that ONBUILD
// (time bomb), SHELL (interpreter swap), CMD/ENTRYPOINT (persistent boot
// hooks that we don't even use), HEALTHCHECK/STOPSIGNAL (Docker-only) etc.
// open up. Bare-metal sandbox boots fc-agent as PID 1, so CMD/ENTRYPOINT
// from a template are dead weight even if "harmless"; reject for clarity.
var allowedInstructions = map[string]struct{}{
	"FROM":    {}, // base image — separately constrained to AllowedBases
	"RUN":     {}, // the actual build step
	"ENV":     {}, // env vars baked into the rootfs (read by build-time RUNs)
	"ARG":     {}, // build-time args
	"USER":    {}, // affects RUN's uid; harmless at runtime (agent is PID 1)
	"WORKDIR": {}, // cwd for subsequent RUNs
	"LABEL":   {}, // image metadata
}

// ValidateDockerfile inspects a Dockerfile and returns the resolved base
// image when the document satisfies our v1 restrictions:
//   - exactly one FROM instruction
//   - that FROM resolves to a base in allowedBases (case-insensitive on
//     the instruction; image string compared as-is)
//   - every instruction is in `allowedInstructions` — rejects COPY/ADD
//     (no build context), ONBUILD (time bomb if template inheritance
//     lands later), SHELL (interpreter swap), CMD/ENTRYPOINT/HEALTHCHECK
//     (persistent boot hooks createos doesn't honor anyway), VOLUME,
//     EXPOSE, STOPSIGNAL.
//   - no ARG-substituted FROM (e.g. `ARG B; FROM ${B}`) — keeps the
//     allowlist check honest
//
// The parser is intentionally line-based and deliberately strict; we
// don't want to silently accept exotic Dockerfile syntax.
func ValidateDockerfile(content []byte, allowedBases []string) (string, error) {
	if len(allowedBases) == 0 {
		allowedBases = AllowedBases
	}
	allowed := make(map[string]struct{}, len(allowedBases))
	for _, b := range allowedBases {
		allowed[b] = struct{}{}
	}

	lines, err := joinContinuations(content)
	if err != nil {
		return "", err
	}

	froms := 0
	var base string
	for _, raw := range lines {
		instr, args := splitInstruction(raw)
		if instr == "" {
			continue
		}
		if _, ok := allowedInstructions[instr]; !ok {
			return "", fmt.Errorf("instruction %s is not allowed (allowed: FROM, RUN, ENV, ARG, USER, WORKDIR, LABEL)", instr)
		}
		switch instr {
		case "FROM":
			froms++
			if froms > 1 {
				return "", fmt.Errorf("multi-stage builds not supported (multiple FROM instructions)")
			}
			img, err := extractFromImage(args)
			if err != nil {
				return "", err
			}
			if img == "scratch" {
				return "", fmt.Errorf("FROM scratch not supported")
			}
			if strings.Contains(img, "$") {
				return "", fmt.Errorf("ARG-substituted FROM not supported (image: %q)", img)
			}
			if _, ok := allowed[img]; !ok {
				return "", fmt.Errorf("base %q not in allowlist (must be one of: %s)",
					img, strings.Join(allowedBases, ", "))
			}
			base = img
		}
	}
	if froms == 0 {
		return "", fmt.Errorf("no FROM instruction found")
	}
	return base, nil
}

// joinContinuations folds backslash-continued lines into single logical
// lines and strips comments. Empty/blank lines drop out.
func joinContinuations(content []byte) ([]string, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var (
		out    []string
		buf    strings.Builder
		inCont bool
	)
	for scanner.Scan() {
		line := scanner.Text()
		// Strip leading whitespace once for comment detection but keep
		// the content for buffer joining.
		trimmed := strings.TrimSpace(line)
		if !inCont {
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
		}
		// Continuation: line ends with `\` (after stripping trailing whitespace).
		stripped := strings.TrimRight(line, " \t")
		if strings.HasSuffix(stripped, `\`) {
			buf.WriteString(strings.TrimSuffix(stripped, `\`))
			buf.WriteByte(' ')
			inCont = true
			continue
		}
		buf.WriteString(line)
		out = append(out, buf.String())
		buf.Reset()
		inCont = false
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if buf.Len() > 0 {
		out = append(out, buf.String())
	}
	return out, nil
}

// splitInstruction returns the upper-cased instruction keyword and the
// remainder of the line. Returns ("", "") for non-instruction lines.
func splitInstruction(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}
	// First whitespace-separated word is the instruction.
	idx := strings.IndexAny(line, " \t")
	if idx < 0 {
		return strings.ToUpper(line), ""
	}
	return strings.ToUpper(line[:idx]), strings.TrimSpace(line[idx:])
}

// extractFromImage parses the args of a FROM instruction. Strips
// `--platform=...` flags and an optional trailing `AS <stage>`.
var asAlias = regexp.MustCompile(`(?i)\s+AS\s+\S+\s*$`)

func extractFromImage(args string) (string, error) {
	if args == "" {
		return "", fmt.Errorf("FROM with no image")
	}
	args = asAlias.ReplaceAllString(args, "")
	// Drop --platform= and any other `--` flags before the image.
	tokens := strings.Fields(args)
	imageIdx := 0
	for i, t := range tokens {
		if !strings.HasPrefix(t, "--") {
			imageIdx = i
			break
		}
	}
	if imageIdx >= len(tokens) {
		return "", fmt.Errorf("FROM with only flags, no image")
	}
	return tokens[imageIdx], nil
}
