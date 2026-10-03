package portstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/portstore"
	"github.com/truvity/access-roster/internal/portstore/portstoretest"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
)

var ctx = context.Background()

type env struct{ portstoretest.Env }

func (e env) base(t *testing.T) *portstore.Base { t.Helper(); return portstore.New(e.Open(t)) }
func (e env) open(t *testing.T) port.Set        { return e.Open(t) }
func (e env) advance(d time.Duration)           { e.Advance(d) }

func each(t *testing.T, test func(t *testing.T, e env)) {
	t.Helper()
	portstoretest.Each(t, func(t *testing.T, e portstoretest.Env) { test(t, env{e}) })
}

func reconcileMember(id, email string, deleted bool) reconcile.Member {
	return reconcile.Member{ID: id, Email: email, TeamID: "T1", Deleted: deleted}
}
