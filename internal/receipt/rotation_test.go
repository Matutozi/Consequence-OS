package receipt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/pkg/verify"
)

// rotated is a server before and after a key rotation at testStart: old
// signed until then, new signs from then, with old as its previous keys
// until an hour later.
type rotated struct {
	old, new harness
	until    time.Time
}

func rotate(t *testing.T) rotated {
	t.Helper()
	old, new := newHarness(t), newHarness(t)
	jwks, err := json.Marshal(old.keys.All())
	if err != nil {
		t.Fatal(err)
	}
	until := testStart.Add(time.Hour)
	if err := new.keys.AddPrevious(jwks, until); err != nil {
		t.Fatal(err)
	}
	// The checker's clock is new's; old issues on its own clock.
	return rotated{old: old, new: new, until: until}
}

func kids(set verify.JWKS) []string {
	var out []string
	for _, k := range set.Keys {
		out = append(out, k.Kid)
	}
	return out
}

func TestRotationPublishesPreviousKeysUntilTheirTime(t *testing.T) {
	r := rotate(t)
	if got := kids(r.new.keys.Published(testStart)); len(got) != 4 {
		t.Errorf("published during the window: %v, want the 2 new keys and the 2 old", got)
	}
	if got := kids(r.new.keys.Published(r.until)); strings.Join(got, ",") != strings.Join(kids(r.new.keys.JWKS()), ",") {
		t.Errorf("published at the end of the window: %v, want the new keys alone", got)
	}
	if got := kids(r.new.keys.All()); len(got) != 4 {
		t.Errorf("All after the window: %v, want all 4", got)
	}

	// The JWKS endpoint, and how long receivers may cache it.
	for _, tt := range []struct {
		at      time.Time
		keys    int
		control string
	}{
		{testStart, 4, "public, max-age=300"},
		{r.until.Add(-time.Minute), 4, "public, max-age=60"},
		{r.until, 2, "public, max-age=300"},
	} {
		rec := httptest.NewRecorder()
		keysHandler(r.new.keys, func() time.Time { return tt.at }).ServeHTTP(rec, httptest.NewRequest("GET", verify.KeysPath, nil))
		var set verify.JWKS
		if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
			t.Fatal(err)
		}
		if len(set.Keys) != tt.keys || rec.Header().Get("Cache-Control") != tt.control {
			t.Errorf("at %s: %d keys, %q; want %d, %q", tt.at, len(set.Keys), rec.Header().Get("Cache-Control"), tt.keys, tt.control)
		}
	}
}

func TestRotationReceipts(t *testing.T) {
	r := rotate(t)
	// A receipt the old keys signed just before the rotation still works.
	inFlight := r.old.issue(t, "")
	if _, err := r.new.checker.Verify(context.Background(), "", inFlight, "purchase_order.confirm", []byte(args)); err != nil {
		t.Errorf("a receipt signed just before the rotation: %v", err)
	}
	// So does one from the new keys.
	if _, err := r.new.checker.Verify(context.Background(), "", r.new.issue(t, ""), "purchase_order.confirm", []byte(args)); err != nil {
		t.Errorf("a receipt from the new keys: %v", err)
	}
	// After the window, a receipt the old keys sign is refused, even a
	// fresh one: whoever still has those keys can't issue receipts.
	*r.old.clock, *r.new.clock = r.until, r.until
	late := r.old.issue(t, "")
	if _, err := r.new.checker.Verify(context.Background(), "", late, "purchase_order.confirm", []byte(args)); !errors.Is(err, verify.ErrUnknownKey) {
		t.Errorf("an old-key receipt after the window: %v, want ErrUnknownKey", err)
	}
}

func TestRotationKeepsAuditHeadsVerifying(t *testing.T) {
	r := rotate(t)
	head, err := r.old.keys.SignAuditHead("http://cos.test", 42, "sha256:abc", testStart.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify.VerifyAuditHead(head, r.new.keys.HeadKeys()); err != nil {
		t.Errorf("a head the old keys signed: %v", err)
	}
	// Without the previous keys, it wouldn't.
	if _, err := verify.VerifyAuditHead(head, newHarness(t).keys.HeadKeys()); !errors.Is(err, verify.ErrUnknownKey) {
		t.Errorf("a head checked with unrelated keys: %v", err)
	}
}

func TestAddPreviousRejects(t *testing.T) {
	h := newHarness(t)
	other := newHarness(t)
	current, _ := json.Marshal(h.keys.JWKS())
	good := other.keys.All()
	badKid := verify.JWKS{Keys: append([]verify.JWK(nil), good.Keys...)}
	badKid.Keys[0].Kid = "ed25519-0000000000000000"
	rsa := verify.JWKS{Keys: append(append([]verify.JWK(nil), good.Keys...), verify.JWK{Kty: "RSA", Alg: "RS256", Kid: "r1"})}
	for name, tt := range map[string]struct {
		jwks any
		want string
	}{
		"the current keys":  {json.RawMessage(current), "is a current signing key"},
		"a kid not derived": {badKid, "its kid isn't the one derived from the key"},
		"another kind":      {rsa, "neither an Ed25519 nor an ML-DSA-87 key"},
		"not a JWKS":        {json.RawMessage(`"keys"`), "bad JWKS"},
		"one algorithm":     {verify.JWKS{Keys: good.Keys[:1]}, "needs at least one Ed25519 and one ML-DSA-87 key"},
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(tt.jwks)
			k, _ := LoadKeys(seedsOf(t, h))
			if err := k.AddPrevious(raw, testStart); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
	// The same keys twice are kept once.
	twice := verify.JWKS{Keys: append(append([]verify.JWK(nil), good.Keys...), good.Keys...)}
	raw, _ := json.Marshal(twice)
	if err := h.keys.AddPrevious(raw, testStart); err != nil {
		t.Fatal(err)
	}
	if n := len(h.keys.All().Keys); n != 4 {
		t.Errorf("%d keys after adding the same two twice, want 4", n)
	}
}

// seedsOf returns the seeds the harness's keys came from, so a test can
// load the same current keys afresh.
func seedsOf(t *testing.T, h harness) (string, string) {
	t.Helper()
	if h.seeds[0] == "" {
		t.Fatal("harness without seeds")
	}
	return h.seeds[0], h.seeds[1]
}

// After a rotation, an offline receiver with Refresh picks up the new keys
// on the first receipt that names one, and doesn't fetch again and again
// for receipts naming keys nobody has.
func TestOfflineRefresh(t *testing.T) {
	r := rotate(t)
	oldSet, _ := keySet(r.old.keys.JWKS())
	newSet, _ := keySet(r.new.keys.Published(testStart))
	fetches := 0
	fail := false
	v := &verify.Offline{Keys: oldSet, Now: func() time.Time { return testStart },
		Refresh: func(context.Context) (*verify.KeySet, error) {
			fetches++
			if fail {
				return nil, errors.New("server down")
			}
			return newSet, nil
		}}
	ctx := context.Background()
	if _, err := v.Verify(ctx, r.old.issue(t, ""), "purchase_order.confirm", []byte(args)); err != nil || fetches != 0 {
		t.Fatalf("a receipt from the keys it has: %v, %d fetches", err, fetches)
	}
	if _, err := v.Verify(ctx, r.new.issue(t, ""), "purchase_order.confirm", []byte(args)); err != nil || fetches != 1 {
		t.Fatalf("the first receipt from the new keys: %v, %d fetches", err, fetches)
	}
	// A receipt from keys nobody publishes: one fetch at most per minute.
	stranger := newHarness(t)
	for i := 0; i < 3; i++ {
		if _, err := v.Verify(ctx, stranger.issue(t, ""), "purchase_order.confirm", []byte(args)); !errors.Is(err, verify.ErrUnknownKey) {
			t.Fatalf("a stranger's receipt: %v", err)
		}
	}
	if fetches != 1 {
		t.Errorf("%d fetches after the stranger's receipts, want no more within the minute", fetches)
	}
	// A minute later it may fetch again; a failed fetch keeps the keys.
	fail = true
	v.Now = func() time.Time { return testStart.Add(time.Minute) }
	if _, err := v.Verify(ctx, stranger.issue(t, ""), "purchase_order.confirm", []byte(args)); !errors.Is(err, verify.ErrUnknownKey) || fetches != 2 {
		t.Errorf("after a minute: %v, %d fetches", err, fetches)
	}
	if _, err := v.Verify(ctx, r.new.issue(t, ""), "purchase_order.confirm", []byte(args)); err != nil {
		t.Errorf("the keys were lost to a failed fetch: %v", err)
	}

	// No keys to start with: the first receipt fetches them.
	empty := &verify.Offline{Now: func() time.Time { return testStart },
		Refresh: func(context.Context) (*verify.KeySet, error) { return newSet, nil }}
	if _, err := empty.Verify(ctx, r.new.issue(t, ""), "purchase_order.confirm", []byte(args)); err != nil {
		t.Errorf("starting without keys: %v", err)
	}
	none := &verify.Offline{}
	if _, err := none.Verify(ctx, r.new.issue(t, ""), "purchase_order.confirm", []byte(args)); !errors.Is(err, verify.ErrUnknownKey) {
		t.Errorf("no keys and no Refresh: %v", err)
	}
}
