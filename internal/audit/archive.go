package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Old entries can be archived: written to a file and deleted from the log,
// for retention rules, or to keep the log small. Deleting them would break
// the chain at the first entry kept, whose PrevHash names an entry that's
// gone. So the store keeps an Anchor: the last archived entry's place and
// hash, with a head signed for them. The chain is then checked from the
// anchor, and the head's signature vouches for everything before it.

// Anchor is where the log starts after archiving.
type Anchor struct {
	Seq  int64  `json:"seq"`  // the last archived entry
	Hash string `json:"hash"` // its chain hash
	// Head is a signed audit head for Seq and Hash. The local modes have
	// no signing keys, so their anchors have none.
	Head json.RawMessage `json:"head,omitempty"`
	At   time.Time       `json:"at"` // when the entries were archived
}

// check checks a's head with check, and that it names a's entry.
func (a Anchor) check(check HeadChecker) (string, error) {
	switch {
	case len(a.Head) == 0:
		return AnchorUnsigned, nil
	case check == nil:
		return AnchorNotChecked, nil
	}
	seq, hash, err := check(a.Head)
	if err != nil {
		return "", err
	}
	if seq != a.Seq || hash != a.Hash {
		return "", fmt.Errorf("its signed head names entry %d, %s, not entry %d, %s", seq, hash, a.Seq, a.Hash)
	}
	return AnchorChecked, nil
}

// ArchiveType is the type of an archive file's header line.
const ArchiveType = "consequenceos.audit-archive.v0"

// ArchiveHeader is the first line of an archive file. The entries follow,
// one JSON object per line, oldest first.
type ArchiveHeader struct {
	Type string `json:"type"`
	// After is where the entries start: the anchor left by the archive
	// before this one. nil when they start at the beginning of the log.
	After *Anchor `json:"after,omitempty"`
	// Through is the last entry in the file, with its signed head: the
	// anchor the log starts from once these entries are deleted.
	Through Anchor `json:"through"`
	Entries int64  `json:"entries"`
}

// WriteArchive writes an archive file: the header, then each entry.
func WriteArchive(w io.Writer, h ArchiveHeader, entries func(yield func(Entry) error) error) error {
	h.Type = ArchiveType
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // entries come back byte for byte
	if err := enc.Encode(h); err != nil {
		return err
	}
	return entries(func(e Entry) error { return enc.Encode(e) })
}

// ArchiveReport is the result of checking an archive file on its own.
type ArchiveReport struct {
	ChainReport
	Header ArchiveHeader `json:"header"`
	// Through says how far the head at the end was checked, as
	// ChainReport.Anchor does for the head at the start.
	Through string `json:"through_head"`
}

// VerifyArchive checks an archive file on its own: that its entries chain
// from where it says they start to where it says they end, and that the
// signed heads at both ends are good, when check is given. A broken file
// comes back with Intact false; an error means it couldn't be read.
func VerifyArchive(r io.Reader, check HeadChecker) (ArchiveReport, error) {
	br := bufio.NewReader(r)
	var rep ArchiveReport
	line, err := br.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return rep, err
	}
	if err := decodeLine(line, &rep.Header); err != nil || rep.Header.Type != ArchiveType {
		return rep, fmt.Errorf("audit: not an archive file: the first line isn't a %s header", ArchiveType)
	}
	v := &ChainVerifier{CheckHead: check}
	if a := rep.Header.After; a != nil {
		if err := v.StartAfter(*a); err != nil {
			rep.ChainReport = v.Report()
			return rep, nil
		}
	}
	var n int64
	for lineNo := 2; ; lineNo++ {
		line, err := br.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			var e Entry
			if derr := decodeLine(line, &e); derr != nil {
				return rep, fmt.Errorf("audit: archive line %d: %w", lineNo, derr)
			}
			n++
			if !v.Add(e) {
				break
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return rep, err
		}
	}
	rep.ChainReport = v.Report()
	if !rep.Intact {
		return rep, nil
	}
	t := rep.Header.Through
	switch {
	case n != rep.Header.Entries:
		rep.Problem = fmt.Sprintf("the file holds %d entries, but its header says %d (entries were removed or added)", n, rep.Header.Entries)
	case rep.HeadSeq != t.Seq || rep.HeadHash != t.Hash:
		rep.Problem = fmt.Sprintf("the last entry is %d, %s, but the header says it ends at %d, %s (entries were removed from the end)", rep.HeadSeq, rep.HeadHash, t.Seq, t.Hash)
	default:
		status, err := t.check(check)
		rep.Through = status
		if err != nil {
			rep.Problem = "the signed head at the end doesn't check out: " + err.Error()
		}
	}
	rep.Intact = rep.Problem == ""
	return rep, nil
}

// decodeLine decodes one JSON line strictly: an archive written by a newer
// version shouldn't be half understood.
func decodeLine(line []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
