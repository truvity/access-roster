package rails_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/rails"
)

type report struct{ Note string }

type plainStore struct {
	got map[string]string
	err error
}

func (s *plainStore) Replace(_ context.Context, d map[string]string) error { s.got = d; return s.err }
func (s *plainStore) Put(_ context.Context, k, d string) error {
	if s.got == nil {
		s.got = map[string]string{}
	}
	s.got[k] = d
	return s.err
}

type readableStore struct {
	plainStore
	have    map[string]string
	readErr error
}

func (s *readableStore) Reports(context.Context) (map[string]string, error) { return s.have, s.readErr }

func journalOver(store rails.Store) *rails.Journal[report] {
	return &rails.Journal[report]{
		Store: store,
		Key:   func(t string) string { return "k-" + t },
		Encode: func(r report) (string, error) {
			if r.Note == "unencodable" {
				return "", errors.New("no")
			}
			return r.Note, nil
		},
		Decode: func(s string) (report, error) {
			if s == "garbage" {
				return report{}, errors.New("no")
			}
			return report{Note: s}, nil
		},
		Log: quiet(),
	}
}

func TestJournalPrefersItsOwnLastGoodReport(t *testing.T) {
	t.Parallel()
	j := journalOver(&readableStore{have: map[string]string{"k-x": "persisted"}})
	if got := j.Previous(context.Background(), "x"); got.Note != "persisted" {
		t.Errorf("before remembering: %v", got)
	}
	j.Remember("x", report{Note: "mine"})
	if got := j.Previous(context.Background(), "x"); got.Note != "mine" {
		t.Errorf("after remembering: %v", got)
	}
	if got := j.Previous(context.Background(), "y"); got.Note != "" {
		t.Errorf("another target: %v", got)
	}
}

func TestJournalFallsBackToNothingWhenItCannotRead(t *testing.T) {
	t.Parallel()
	for name, store := range map[string]rails.Store{
		"a store that cannot be read": &plainStore{},
		"a read that fails":           &readableStore{readErr: errors.New("down")},
		"no document":                 &readableStore{have: map[string]string{}},
		"a document that is garbage":  &readableStore{have: map[string]string{"k-x": "garbage"}},
	} {
		if got := journalOver(store).Previous(context.Background(), "x"); got != (report{}) {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestJournalPublishesEveryEncodableReportInOneReplace(t *testing.T) {
	t.Parallel()
	store := &plainStore{}
	journalOver(store).Publish(context.Background(), map[string]report{
		"a": {Note: "one"}, "b": {Note: "unencodable"}, "c": {Note: "three"},
	})
	if len(store.got) != 2 || store.got["k-a"] != "one" || store.got["k-c"] != "three" {
		t.Errorf("replaced %v", store.got)
	}
}

func TestJournalReplacesEvenWithNothingToPublishAndSurvivesAFailingStore(t *testing.T) {
	t.Parallel()
	store := &plainStore{err: errors.New("down")}
	journalOver(store).Publish(context.Background(), nil)
	if store.got == nil || len(store.got) != 0 {
		t.Errorf("an empty publish did not replace: %v", store.got)
	}
}

func TestJournalNamesTheTargetInItsLogLines(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	j := journalOver(&readableStore{readErr: errors.New("down")})
	j.Log = slogTo(&out)
	j.Label = "org"
	j.Previous(context.Background(), "globex")
	if !strings.Contains(out.String(), "org=globex") {
		t.Errorf("log line %q does not carry org=globex", out.String())
	}
}
