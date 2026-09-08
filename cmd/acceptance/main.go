package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/truvity/access-roster/backend/fake"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "acceptance: %v\n", err)
		os.Exit(1)
	}
}

// run owns the cleanup, which is why it returns an error rather than
// exiting: os.Exit skips deferred work, and the deferred work here is
// removing everything this wrote from somebody's namespace.
func run() error {
	namespace := flag.String("namespace", "", "namespace to create objects in; it must already exist")
	kubeconfig := flag.String("kubeconfig", os.Getenv("KUBECONFIG"), "kubeconfig to use; empty uses the default")
	keep := flag.Bool("keep", false, "leave the objects behind, to look at them")
	flag.Parse()

	if *namespace == "" {
		return errors.New("give -namespace: this creates and deletes objects, " +
			"and it should be somewhere you chose")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	api, err := connect(*kubeconfig)
	if err != nil {
		return err
	}
	if _, err = api.CoreV1().Namespaces().Get(ctx, *namespace, metav1.GetOptions{}); err != nil {
		return fmt.Errorf("namespace %s: %w", *namespace, err)
	}

	checks := &acceptance{
		client: kube.NewClient(api, *namespace, "acceptance"),
		api:    api,
		ns:     *namespace,
		log:    slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}
	if !*keep {
		// WithoutCancel so that an interrupted run still tidies up: the
		// objects it leaves behind are a workspace record and a
		// credential in somebody else's namespace.
		defer checks.clean(context.WithoutCancel(ctx))
	}

	for _, check := range []struct {
		name string
		run  func(context.Context) error
	}{
		{"a workspace and its credential survive a restart", checks.store},
		{"every tenant id produces an object the API server accepts", checks.names},
		{"the session key is the same for two replicas", checks.sessionKey},
		{"recovery admits the recovery account and nobody else", checks.recovery},
		{"the API listener admits a declared consumer and nobody else", checks.consumers},
	} {
		started := time.Now()
		if err = check.run(ctx); err != nil {
			return fmt.Errorf("%s: %w", check.name, err)
		}
		checks.log.Info("ok", "check", check.name, "took", time.Since(started).Round(time.Millisecond))
	}
	checks.log.Info("every check passed", "namespace", *namespace)
	return nil
}

type acceptance struct {
	client *kube.Client
	api    kubernetes.Interface
	ns     string
	log    *slog.Logger
}

// store writes a workspace and its credential, reads them back through a
// second set of stores — which is what a restarted process does — and
// checks that disconnecting takes both away.
func (a *acceptance) store(ctx context.Context) error {
	workspaces, credentials := kube.NewWorkspaces(a.client), kube.NewCredentials(a.client)
	directory := fake.New("C0acceptance", "acceptance.example").
		WithAccount("ada@acceptance.example", "Ada", "North").
		WithGroup("everyone@acceptance.example", "ada@acceptance.example")

	first := hub.New(workspaces, hub.NewMemorySnapshots(), hub.Config{}, a.log)
	first.UseCredentials(credentials)
	if _, err := first.Adopt(ctx, hub.Workspace{Admin: "admin@acceptance.example"}, directory); err != nil {
		return fmt.Errorf("adopt: %w", err)
	}

	second := hub.New(kube.NewWorkspaces(a.client), hub.NewMemorySnapshots(), hub.Config{}, a.log)
	stored, err := second.WorkspaceViews(ctx)
	if err != nil {
		return fmt.Errorf("read back: %w", err)
	}
	if len(stored) != 1 || stored[0].Workspace.ID != "C0acceptance" {
		return fmt.Errorf("read back %d workspaces", len(stored))
	}
	if _, found, credErr := kube.NewCredentials(a.client).Load(ctx, "C0acceptance"); credErr != nil || !found {
		return fmt.Errorf("credential: %v, %w", found, credErr)
	}
	second.UseCredentials(kube.NewCredentials(a.client))
	if err = second.Attach(ctx, "C0acceptance", directory); err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	if err = second.Disconnect(ctx, "C0acceptance"); err != nil {
		return fmt.Errorf("disconnect: %w", err)
	}
	if _, found, _ := kube.NewCredentials(a.client).Load(ctx, "C0acceptance"); found {
		return errors.New("the credential outlived the workspace")
	}
	return nil
}

// names writes ids a backend could plausibly hand us and lets the API
// server judge the object names. A fake clientset accepts anything.
func (a *acceptance) names(ctx context.Context) error {
	store := kube.NewWorkspaces(a.client)
	for _, id := range []string{
		"C030qgizn",
		strings.Repeat("long", 80),
		"UPPER.and.dots",
		"-edges-",
		"tenant/with/slashes",
		"тенант",
	} {
		if err := store.Put(ctx, hub.Workspace{ID: id, Backend: "google"}); err != nil {
			return fmt.Errorf("the API server refused the object for id %q: %w", id, err)
		}
		got, err := store.Get(ctx, id)
		if err != nil || got.ID != id {
			return fmt.Errorf("id %q read back as %q: %w", id, got.ID, err)
		}
		if err = store.Delete(ctx, id); err != nil {
			return fmt.Errorf("delete %q: %w", id, err)
		}
	}
	return nil
}

// sessionKey checks that a second process takes the first one's key. A
// key minted per process signs everyone out on every rollout, and two
// replicas would reject each other's cookies.
func (a *acceptance) sessionKey(ctx context.Context) error {
	first, err := a.client.SessionKey(ctx, func() ([]byte, error) { return []byte("first-key"), nil })
	if err != nil {
		return err
	}
	second, err := a.client.SessionKey(ctx, func() ([]byte, error) {
		return nil, errors.New("a second start minted a new key instead of reading the stored one")
	})
	if err != nil {
		return err
	}
	if string(first) != string(second) {
		return fmt.Errorf("two starts, two keys: %q and %q", first, second)
	}
	return nil
}

// recovery is the check a fake cannot do at all: only an API server can
// say whether a token is genuine and for which audience.
func (a *acceptance) recovery(ctx context.Context) error {
	const audience = "acceptance-recovery"
	allowed, err := a.serviceAccount(ctx, "acceptance-recovery")
	if err != nil {
		return err
	}
	stranger, err := a.serviceAccount(ctx, "acceptance-stranger")
	if err != nil {
		return err
	}
	recovery := &server.TokenRecovery{
		Review:    a.client.ReviewToken,
		Namespace: a.ns,
		Account:   "acceptance-recovery",
		Audience:  audience,
		Subjects:  []string{kube.ServiceAccountSubject(a.ns, "acceptance-recovery")},
	}

	token, err := a.token(ctx, allowed, audience)
	if err != nil {
		return err
	}
	who, err := recovery.Verify(ctx, token)
	if err != nil {
		return fmt.Errorf("the recovery account was refused: %w", err)
	}
	if who != kube.ServiceAccountSubject(a.ns, "acceptance-recovery") {
		return fmt.Errorf("recovered as %q", who)
	}

	// Another account's token authenticates perfectly and may not recover.
	other, err := a.token(ctx, stranger, audience)
	if err != nil {
		return err
	}
	if _, err = recovery.Verify(ctx, other); !errors.Is(err, server.ErrRecoveryRefused) {
		return fmt.Errorf("another account's token = %v, want refused", err)
	}
	// A token for the wrong audience is not a token for this purpose:
	// without the audience check, every mounted token in the cluster
	// would be a recovery token.
	wrong, err := a.token(ctx, allowed, "something-else")
	if err != nil {
		return err
	}
	if _, err = recovery.Verify(ctx, wrong); !errors.Is(err, kube.ErrTokenRejected) {
		return fmt.Errorf("a token for another audience = %v, want rejected", err)
	}
	if _, err = recovery.Verify(ctx, "not-a-token"); !errors.Is(err, kube.ErrTokenRejected) {
		return fmt.Errorf("a forged token = %v, want rejected", err)
	}
	return nil
}

// consumers is the same question for the API listener's guard.
func (a *acceptance) consumers(ctx context.Context) error {
	const audience = "acceptance-api"
	consumer, err := a.serviceAccount(ctx, "acceptance-consumer")
	if err != nil {
		return err
	}
	stranger, err := a.serviceAccount(ctx, "acceptance-stranger")
	if err != nil {
		return err
	}
	guard := &server.Consumers{
		Review:   a.client.ReviewToken,
		Audience: audience,
		Allowed:  []string{kube.ServiceAccountSubject(a.ns, "acceptance-consumer")},
		Log:      a.log,
	}
	handler := guard.Middleware(okHandler{})

	allowedToken, err := a.token(ctx, consumer, audience)
	if err != nil {
		return err
	}
	strangerToken, err := a.token(ctx, stranger, audience)
	if err != nil {
		return err
	}
	for _, tc := range []struct {
		name, token string
		want        int
	}{
		{"the declared consumer", allowedToken, 200},
		{"another workload", strangerToken, 401},
		{"a forged token", "not-a-token", 401},
		{"no token", "", 401},
	} {
		if got := probe(ctx, handler, tc.token); got != tc.want {
			return fmt.Errorf("%s = %d, want %d", tc.name, got, tc.want)
		}
	}
	return nil
}

// serviceAccount creates one if it is not there, and returns its name.
func (a *acceptance) serviceAccount(ctx context.Context, name string) (string, error) {
	_, err := a.api.CoreV1().ServiceAccounts(a.ns).Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: a.ns,
			Labels:    map[string]string{"app.kubernetes.io/managed-by": "access-roster-acceptance"},
		},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return "", fmt.Errorf("create ServiceAccount %s: %w", name, err)
	}
	return name, nil
}

// token asks the API server for a short-lived token, which is what an
// operator does by hand to recover and what a pod's projected volume does
// for a consumer.
func (a *acceptance) token(ctx context.Context, account, audience string) (string, error) {
	seconds := int64(600)
	minted, err := a.api.CoreV1().ServiceAccounts(a.ns).CreateToken(ctx, account, &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{Audiences: []string{audience}, ExpirationSeconds: &seconds},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("mint a token for %s: %w", account, err)
	}
	return minted.Status.Token, nil
}

// clean removes everything this wrote, by the labels it wrote it with.
func (a *acceptance) clean(ctx context.Context) {
	options := metav1.ListOptions{LabelSelector: "app.kubernetes.io/managed-by=directory-roster"}
	for _, remove := range []func() error{
		func() error {
			return a.api.CoreV1().ConfigMaps(a.ns).DeleteCollection(ctx, metav1.DeleteOptions{}, options)
		},
		func() error {
			return a.api.CoreV1().Secrets(a.ns).DeleteCollection(ctx, metav1.DeleteOptions{}, options)
		},
		func() error {
			return a.api.CoreV1().ServiceAccounts(a.ns).DeleteCollection(ctx, metav1.DeleteOptions{},
				metav1.ListOptions{LabelSelector: "app.kubernetes.io/managed-by=access-roster-acceptance"})
		},
	} {
		if err := remove(); err != nil {
			a.log.Warn("could not clean up", "error", err)
		}
	}
}

func connect(kubeconfig string) (kubernetes.Interface, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("read the kubeconfig: %w", err)
	}
	return kubernetes.NewForConfig(cfg)
}

// okHandler stands in for DirectoryService: the guard's job is to decide
// whether anything reaches it at all.
type okHandler struct{}

func (okHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

// probe puts one request through the guard and reports what came back.
func probe(ctx context.Context, handler http.Handler, token string) int {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"/directory.v1.DirectoryService/Describe", nil)
	if err != nil {
		return 0
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Code
}
