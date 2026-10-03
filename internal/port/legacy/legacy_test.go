package legacy_test

import (
	"context"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/port/legacy"
	"github.com/truvity/access-roster/internal/port/porttest"
	"github.com/truvity/access-roster/internal/valkey"
)

// fixture is today's storage on a fake API server and a miniredis.
type fixture struct {
	redis  *miniredis.Miniredis
	client *kube.Client
	api    *fake.Clientset
	state  *valkey.State
	ports  port.Set
}

var configMaps = schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}

// enforceVersions makes the fake API server do what a real one does and the
// fake does not: refuse an update whose resourceVersion is not the stored
// one, atomically, and move the version on every write. Without it a
// compare-and-swap built on the version could not be tested.
func enforceVersions(api *fake.Clientset) {
	var mu sync.Mutex
	api.PrependReactor("update", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
		update := action.(k8stesting.UpdateAction)
		obj := update.GetObject().(*corev1.ConfigMap)
		mu.Lock()
		defer mu.Unlock()
		cur, err := api.Tracker().Get(configMaps, obj.Namespace, obj.Name)
		if err != nil {
			return true, nil, err
		}
		stored := cur.(*corev1.ConfigMap)
		if obj.ResourceVersion != stored.ResourceVersion {
			return true, nil, apierrors.NewConflict(configMaps.GroupResource(), obj.Name, nil)
		}
		n, _ := strconv.Atoi(stored.ResourceVersion)
		next := obj.DeepCopy()
		next.ResourceVersion = strconv.Itoa(n + 1)
		if err = api.Tracker().Update(configMaps, next, obj.Namespace); err != nil {
			return true, nil, err
		}
		return true, next, nil
	})
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	server := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = rc.Close() })

	api := fake.NewSimpleClientset()
	enforceVersions(api)
	api.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authnv1.TokenReview)
		out := review.DeepCopy()
		if review.Spec.Token == "good" && slices.Contains(review.Spec.Audiences, "access-roster") {
			out.Status = authnv1.TokenReviewStatus{
				Authenticated: true, User: authnv1.UserInfo{Username: "system:serviceaccount:ns:sa"},
			}
		}
		return true, out, nil
	})
	client := kube.NewClient(api, "ns", "rel")
	ctx := context.Background()
	if err := kube.NewGitHubStatus(client).Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	if err := kube.NewSlackStatus(client).Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	state := valkey.NewState(rc, "t")
	backend := &legacy.Backend{Kube: client, Valkey: state, ReviewToken: client.ReviewToken}
	return &fixture{
		redis: server, client: client, api: api, state: state,
		ports: backend.Ports(legacy.Options{SnapshotTTL: time.Hour, WatchEvery: 10 * time.Millisecond}),
	}
}

// The conformance suite of docs/design/ports.md against today's storage:
// every assertion either passes or is skipped with the engine's reason.
func TestConformance(t *testing.T) {
	porttest.Run(t, func(t *testing.T) porttest.Env {
		f := newFixture(t)
		return porttest.Env{
			Set:              f.ports,
			Advance:          f.redis.FastForward,
			BlobPrefixes:     []string{"snapshots/"},
			TextBlobPrefixes: []string{"reports/github/", "reports/slack/"},
			Proof: func() porttest.Proof {
				return porttest.Proof{Token: "good", Subject: "system:serviceaccount:ns:sa", Audience: "access-roster"}
			},
			Skips: map[string]string{
				"revisions/change-on-identical-rewrite": "a revision is the SHA-1 of the stored bytes: neither Valkey nor a " +
					"ConfigMap entry keeps a version of a key, and adding one would change what is written",
				"sealing/context": "nothing is sealed in today's storage (credentials are Secrets), and a " +
					"process-local key would make envelopes no restart could open",
			},
		}
	})
}
