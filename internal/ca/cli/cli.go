// Package cacli implements the `admin ca` subcommand — operator
// tooling for issuing, listing, and revoking leaf certs against the
// issued_certs ledger directly. Same control.yaml the API server
// reads supplies the CA paths + Postgres DSN.
package cacli

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/NodeOps-app/createos-sandbox/config"
	"github.com/NodeOps-app/createos-sandbox/database"
	"github.com/NodeOps-app/createos-sandbox/internal/ca"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// Commands returns the `admin ca` group: issue / list / revoke.
func Commands() *cli.Command {
	return &cli.Command{
		Name:  "ca",
		Usage: "operator tooling: issue, list, and revoke leaf certs from the issued_certs ledger",
		Subcommands: []*cli.Command{
			issueCmd(),
			listCmd(),
			revokeCmd(),
		},
	}
}

func issueCmd() *cli.Command {
	return &cli.Command{
		Name:  "issue",
		Usage: "sign a leaf cert from a CSR and persist it to the ledger",
		Flags: append(config.ControlFlags(),
			&cli.StringFlag{Name: "kind", Required: true, Usage: "subject kind (host, control, ingress, gateway, proxy, scheduler)"},
			&cli.StringFlag{Name: "id", Required: true, Usage: "subject id (host id, or actor id)"},
			&cli.StringFlag{Name: "csr", Required: true, Usage: "path to PEM-encoded PKCS#10 CSR"},
			&cli.StringFlag{Name: "out", Required: true, Usage: "output directory; writes <id>.crt + ca.crt"},
		),
		Action: runIssue,
	}
}

func listCmd() *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "print the cert ledger for a subject (newest first)",
		Flags: append(config.ControlFlags(),
			&cli.StringFlag{Name: "kind", Required: true, Usage: "subject kind"},
			&cli.StringFlag{Name: "id", Required: true, Usage: "subject id"},
		),
		Action: runList,
	}
}

func revokeCmd() *cli.Command {
	return &cli.Command{
		Name:  "revoke",
		Usage: "tombstone a single leaf cert by serial",
		Flags: append(config.ControlFlags(),
			&cli.StringFlag{Name: "serial", Required: true, Usage: "cert serial (hex)"},
			&cli.StringFlag{Name: "by", Required: true, Usage: "operator id stamped into revoked_by as 'admin:<by>'"},
		),
		Action: runRevoke,
	}
}

func runIssue(c *cli.Context) error {
	cfg, err := config.ControlFromContext(c)
	if err != nil {
		return err
	}
	kind := models.CertKind(strings.TrimSpace(c.String("kind")))
	if _, ok := models.ValidCertKinds[kind]; !ok {
		return fmt.Errorf("unknown --kind %q (valid: host, control, ingress, gateway, proxy, scheduler)", kind)
	}
	subjectID := strings.TrimSpace(c.String("id"))
	if subjectID == "" {
		return fmt.Errorf("--id required")
	}
	if cfg.CAKeyPath == "" || cfg.CACertPath == "" {
		return fmt.Errorf("ca-key-path / ca-cert-path must be configured")
	}
	if cfg.PostgresDSN == "" {
		return fmt.Errorf("postgres-dsn required")
	}

	csrPEM, err := os.ReadFile(c.String("csr"))
	if err != nil {
		return fmt.Errorf("read CSR: %w", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return fmt.Errorf("csr: not a CSR PEM block")
	}

	authority, err := ca.LoadOrCreateCA(cfg.CAKeyPath, cfg.CACertPath)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	var ident ca.URIIdentity
	if kind == models.CertKindHost {
		ident = ca.URIIdentity{HostID: subjectID}
	} else {
		ident = ca.URIIdentity{Role: string(kind)}
	}

	ttl := models.CertTTL(kind)
	leafDER, serial, err := authority.IssueCert(block.Bytes, ident, ttl)
	if err != nil {
		return fmt.Errorf("issue cert: %w", err)
	}
	expiresAt := time.Now().UTC().Add(ttl)

	ctx := context.Background()
	db, err := database.OpenDb(ctx, cfg.PostgresDSN)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	rec := models.IssuedCert{
		CertSerial:  serial.Text(16),
		SubjectKind: kind,
		SubjectID:   subjectID,
		ExpiresAt:   expiresAt,
	}
	if kind == models.CertKindHost {
		if err := models.RotateCertWithGrace(ctx, db, rec, models.HostRotateRevokeGrace); err != nil {
			return fmt.Errorf("persist cert: %w", err)
		}
	} else {
		if err := models.RotateCertImmediate(ctx, db, rec); err != nil {
			return fmt.Errorf("persist cert: %w", err)
		}
	}

	outDir := c.String("out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir out: %w", err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	leafPath := filepath.Join(outDir, subjectID+".crt")
	if err := os.WriteFile(leafPath, leafPEM, 0o644); err != nil {
		return fmt.Errorf("write leaf: %w", err)
	}
	caPath := filepath.Join(outDir, "ca.crt")
	if err := os.WriteFile(caPath, authority.CertPEM, 0o644); err != nil {
		return fmt.Errorf("write ca: %w", err)
	}
	fmt.Printf("issued cert\n  serial:     %s\n  kind:       %s\n  subject:    %s\n  expires_at: %s\n  leaf:       %s\n  ca:         %s\n",
		rec.CertSerial, kind, subjectID, expiresAt.Format(time.RFC3339), leafPath, caPath)
	return nil
}

func runList(c *cli.Context) error {
	cfg, err := config.ControlFromContext(c)
	if err != nil {
		return err
	}
	kind := models.CertKind(strings.TrimSpace(c.String("kind")))
	if _, ok := models.ValidCertKinds[kind]; !ok {
		return fmt.Errorf("unknown --kind %q", kind)
	}
	subjectID := strings.TrimSpace(c.String("id"))
	if subjectID == "" {
		return fmt.Errorf("--id required")
	}
	if cfg.PostgresDSN == "" {
		return fmt.Errorf("postgres-dsn required")
	}
	ctx := context.Background()
	db, err := database.OpenDb(ctx, cfg.PostgresDSN)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	certs, err := models.ListIssuedCerts(ctx, db, kind, subjectID)
	if err != nil {
		return err
	}
	// Defensive sort newest-first in case the query ordering changes.
	sort.SliceStable(certs, func(i, j int) bool { return certs[i].IssuedAt.After(certs[j].IssuedAt) })

	now := time.Now().UTC()
	fmt.Println("serial\tissued_at\texpires_at\tstatus\trevoked_by\treplaced_by")
	for _, cert := range certs {
		revokedBy := ""
		if cert.RevokedBy != nil {
			revokedBy = *cert.RevokedBy
		}
		replacedBy := ""
		if cert.ReplacedBy != nil && len(*cert.ReplacedBy) >= 12 {
			replacedBy = (*cert.ReplacedBy)[:12]
		} else if cert.ReplacedBy != nil {
			replacedBy = *cert.ReplacedBy
		}
		serialPrefix := cert.CertSerial
		if len(serialPrefix) > 12 {
			serialPrefix = serialPrefix[:12]
		}
		fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\n",
			serialPrefix,
			cert.IssuedAt.Format(time.RFC3339),
			cert.ExpiresAt.Format(time.RFC3339),
			cert.Status(now),
			revokedBy,
			replacedBy,
		)
	}
	return nil
}

func runRevoke(c *cli.Context) error {
	cfg, err := config.ControlFromContext(c)
	if err != nil {
		return err
	}
	if cfg.PostgresDSN == "" {
		return fmt.Errorf("postgres-dsn required")
	}
	serial := strings.TrimSpace(c.String("serial"))
	by := strings.TrimSpace(c.String("by"))
	if serial == "" || by == "" {
		return fmt.Errorf("--serial and --by required")
	}
	ctx := context.Background()
	db, err := database.OpenDb(ctx, cfg.PostgresDSN)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()
	if err := models.RevokeIssuedCert(ctx, db, serial, models.RevokeByAdminPrefix+by); err != nil {
		return err
	}
	fmt.Printf("revoked %s\n", serial)
	return nil
}
