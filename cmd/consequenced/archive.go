package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/config"
	"github.com/matutozi/consequence-os/internal/receipt"
)

// consequenced -archive-audit FILE -before DATE writes the oldest entries
// of the audit log, those before DATE, to FILE and deletes them from the
// log. consequenced -verify-audit -archive FILE checks such a file on its
// own. See internal/audit/archive.go for how the chain survives it.

// parseBefore reads -before: a date, meaning midnight UTC, or an RFC 3339
// time.
func parseBefore(s string) (time.Time, error) {
	if t, err := time.Parse(time.DateOnly, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("-before %q must be a date like 2026-01-01 (midnight UTC) or a time like 2026-01-01T00:00:00Z", s)
}

// errEnough ends a walk of the log early.
var errEnough = errors.New("enough")

// runArchiveAudit archives the entries before before to file. In order:
// it checks the whole chain, since archiving a broken log would destroy
// the evidence; writes the file beside its final name and checks it; puts
// it in place without overwriting anything; and only then deletes the
// entries, recording that in the log. A failure before the delete changes
// nothing in the log.
func runArchiveAudit(ctx context.Context, out io.Writer, cfg *config.Config, local bool, file string, before time.Time) error {
	if before.IsZero() {
		return errors.New("-archive-audit needs -before: a date like 2026-01-01; entries before it are archived")
	}
	if _, err := os.Lstat(file); err == nil {
		return fmt.Errorf("%s already exists; archives are never overwritten", file)
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	st, err := openForChanging(ctx, cfg, local, "archive", log)
	if err != nil {
		return err
	}
	defer st.Close()
	// The local modes have no signing keys, so their anchors are unsigned.
	var keys *receipt.Keys
	var check audit.HeadChecker
	if !local {
		if keys, err = loadKeys(cfg); err != nil {
			return err
		}
		check = headChecker(keys)
	}

	report, err := audit.VerifyChainWith(ctx, st, &audit.ChainVerifier{CheckHead: check})
	if err != nil {
		return err
	}
	if !report.Intact {
		return fmt.Errorf("the audit log's chain is broken (%s), so nothing was archived: archiving would delete the evidence. consequenced -verify-audit says more", report.Problem)
	}

	// The entries to archive: the oldest ones, up to the first from
	// before or later, so what's left is still one unbroken chain.
	var first, last audit.Entry
	var n int64
	err = st.ForEachAudit(ctx, func(e audit.Entry) error {
		if !e.Time.Before(before) {
			return errEnough
		}
		if n == 0 {
			first = e
		}
		last, n = e, n+1
		return nil
	})
	if err != nil && !errors.Is(err, errEnough) {
		return err
	}
	switch {
	case n == 0:
		fmt.Fprintf(out, "Nothing to archive: no entry is from before %s.\n", before.Format(time.RFC3339))
		return nil
	case last.Hash == "":
		return fmt.Errorf("the entries before %s are all from before the log was chained, so there is no hash to anchor the rest to; archive up to a later date", before.Format(time.RFC3339))
	}

	now := time.Now().UTC()
	through := audit.Anchor{Seq: last.Seq, Hash: last.Hash, At: now}
	if keys != nil {
		if through.Head, err = keys.SignAuditHead(cfg.PublicURL, last.Seq, last.Hash, now); err != nil {
			return err
		}
	}
	header := audit.ArchiveHeader{Through: through, Entries: n}
	if a, ok, err := st.AuditAnchor(ctx); err != nil {
		return err
	} else if ok {
		header.After = &a
	}
	if err := writeArchiveFile(ctx, st, file, header, check); err != nil {
		return err
	}

	deleted, err := st.ArchiveAudit(ctx, through)
	if err != nil && deleted == 0 {
		return fmt.Errorf("%s was written, but the entries weren't deleted: %w", file, err)
	}
	// Recorded in the log itself, so the gap it leaves is explained there.
	_, recErr := st.AppendAudit(ctx, audit.Entry{Time: now, Tool: "", Outcome: audit.OutcomeArchived,
		Detail: fmt.Sprintf("archived %d entries, %d to %d, from before %s, to %s; the log now starts after entry %d, %s",
			deleted, first.Seq, last.Seq, before.Format(time.RFC3339), filepath.Base(file), last.Seq, last.Hash)})
	fmt.Fprintf(out, "Archived %d entries (%d to %d, from %s to %s) to %s, and deleted them from the log.\n",
		deleted, first.Seq, last.Seq, first.Time.Local().Format("2006-01-02 15:04"), last.Time.Local().Format("2006-01-02 15:04"), file)
	fmt.Fprintf(out, "The log now starts after entry %d. Keep the file: consequenced -verify-audit -archive %s checks it.\n", last.Seq, file)
	if keys == nil {
		fmt.Fprintln(out, "The local modes have no signing keys, so the archive and the log's new start aren't signed.")
	}
	if err != nil {
		return err // archived, but the file store's journal still holds the entries
	}
	if recErr != nil {
		return fmt.Errorf("archived, but the archiving couldn't be recorded in the log: %w", recErr)
	}
	return nil
}

// writeArchiveFile writes the archive to a temporary file beside file,
// checks it, and links it into place, which fails rather than overwrite
// a file that appeared meanwhile.
func writeArchiveFile(ctx context.Context, st interface {
	ForEachAudit(context.Context, func(audit.Entry) error) error
}, file string, header audit.ArchiveHeader, check audit.HeadChecker) (err error) {
	dir := filepath.Dir(file)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(file)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // the archive is linked in under its own name
	defer tmp.Close()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	var written int64
	err = audit.WriteArchive(tmp, header, func(yield func(audit.Entry) error) error {
		err := st.ForEachAudit(ctx, func(e audit.Entry) error {
			if e.Seq > header.Through.Seq {
				return errEnough
			}
			written++
			return yield(e)
		})
		if errors.Is(err, errEnough) {
			return nil
		}
		return err
	})
	if err != nil {
		return err
	}
	if written != header.Entries {
		return fmt.Errorf("the log changed while it was archived (%d entries, then %d); nothing was archived", header.Entries, written)
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	// Check what was written, as -verify-audit -archive will.
	rep, err := audit.VerifyArchive(tmp, check)
	if err != nil {
		return err
	}
	if !rep.Intact || rep.Header.Entries != header.Entries {
		return fmt.Errorf("the archive written doesn't check out (%s); nothing was archived", rep.Problem)
	}
	if err := os.Link(tmp.Name(), file); err != nil {
		return fmt.Errorf("put the archive in place: %w", err)
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// verifyArchiveFile checks an archive file on its own, with the server's
// keys when the config has them.
func verifyArchiveFile(out io.Writer, cfg *config.Config, local bool, file string) error {
	var check audit.HeadChecker
	if !local {
		keys, err := loadKeys(cfg)
		if err != nil {
			return err
		}
		check = headChecker(keys)
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	rep, err := audit.VerifyArchive(f, check)
	if err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	h := rep.Header
	start := "from the start of the log"
	if h.After != nil {
		start = fmt.Sprintf("after entry %d (head %s)", h.After.Seq, rep.Anchor)
	}
	if !rep.Intact {
		where := ""
		if rep.BrokenAt != "" {
			where = " at entry " + rep.BrokenAt
		}
		fmt.Fprintf(out, "archive BROKEN%s: %s\n  %d entries checked before it\n", where, rep.Problem, rep.Checked)
		return errors.New("the archive has been changed")
	}
	fmt.Fprintf(out, "archive intact: %d entries, %s through entry %d (head %s)\n", h.Entries, start, h.Through.Seq, rep.Through)
	return nil
}
