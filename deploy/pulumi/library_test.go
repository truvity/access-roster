package sluispulumi_test

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	yaml "go.yaml.in/yaml/v3"

	policyconfig "github.com/truvity/policy/config"

	arp "github.com/truvity/sluis/deploy/pulumi"
)

const (
	bucket  = "acme-sluis"
	table   = "acme-sluis"
	cluster = "acme"
)

type opts struct {
	versioning bool
	tableKey   pulumi.StringInput
	noState    bool
	noSlack    bool
	noGitHub   bool
	boundary   string
	serveSA    string
}

// stack is the three components wired the way a stack would wire them.
func stack(t *testing.T, o opts) (*recorder, map[string]string, error) {
	t.Helper()
	if o.boundary == "" {
		o.boundary = arnp + "iam::" + account + ":policy/boundary"
	}
	if o.serveSA == "" {
		o.serveSA = "sluis"
	}
	return run(t, func(ctx *pulumi.Context, collect func(string, pulumi.StringInput)) error {
		store, err := arp.NewStorage(ctx, "kernel", &arp.StorageArgs{BucketName: bucket, Versioning: o.versioning})
		if err != nil {
			return err
		}
		id := &arp.KubernetesIdentityArgs{
			ClusterName: cluster, ClusterArn: arnp + "eks:eu-west-1:" + account + ":cluster/" + cluster, AccountID: account,
			Namespace: "sluis", PermissionsBoundaryArn: o.boundary,
			Serve:   arp.ProcessArgs{ServiceAccount: o.serveSA},
			GitHub:  arp.ProcessArgs{ServiceAccount: "sluis-github"},
			Slack:   arp.ProcessArgs{ServiceAccount: "sluis-slack"},
			Storage: store.Grant(),
		}
		if o.noSlack {
			id.Slack = arp.ProcessArgs{}
		}
		if o.noGitHub {
			id.GitHub = arp.ProcessArgs{}
		}
		collect("bucketName", store.BucketName)
		collect("bucketArn", store.BucketArn)
		collect("keyArn", store.KeyArn)
		collect("keyAlias", store.KeyAlias)
		if !o.noState {
			st, err := arp.NewState(ctx, "kernel", &arp.StateArgs{TableName: table, KeyArn: o.tableKey})
			if err != nil {
				return err
			}
			id.State = st.Grant()
			collect("tableName", st.TableName)
			collect("tableArn", st.TableArn)
		}
		ids, err := arp.NewKubernetesIdentity(ctx, "kernel", id)
		if err != nil {
			return err
		}
		collect("serveRoleArn", ids.ServeRoleArn)
		collect("serveRoleName", ids.ServeRoleName)
		collect("githubRoleArn", ids.GitHubRoleArn)
		collect("slackRoleArn", ids.SlackRoleArn)
		collect("slackRoleName", ids.SlackRoleName)
		return nil
	})
}

func mustStack(t *testing.T, o opts) (*recorder, map[string]string) {
	t.Helper()
	rec, out, err := stack(t, o)
	if err != nil {
		t.Fatal(err)
	}
	return rec, out
}

func TestTheBucketIsEncryptedClosedAndProtected(t *testing.T) {
	rec, out := mustStack(t, opts{})
	b := rec.one(t, "aws:s3/bucket:Bucket", "kernel-bucket")
	if prop(b, "bucket").StringValue() != bucket || prop(b, "forceDestroy").IsBool() && prop(b, "forceDestroy").BoolValue() {
		t.Errorf("bucket inputs: %v", b.Inputs)
	}
	if !rec.isProtected("aws:s3/bucket:Bucket", "kernel-bucket") {
		t.Error("the bucket is not protected")
	}
	if out["bucketName"] != bucket || out["bucketArn"] != arnp+"s3:::"+bucket {
		t.Errorf("outputs: %v", out)
	}
	sse := rec.one(t, "aws:s3/bucketServerSideEncryptionConfigurationV2:BucketServerSideEncryptionConfigurationV2", "kernel-bucket-encryption")
	rule := prop(sse, "rules").ArrayValue()[0].ObjectValue()
	if rule["applyServerSideEncryptionByDefault"].ObjectValue()["sseAlgorithm"].StringValue() != "AES256" {
		t.Errorf("encryption: %v", rule)
	}
	pab := rec.one(t, "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock", "kernel-bucket-public-access")
	for _, k := range []string{"blockPublicAcls", "blockPublicPolicy", "ignorePublicAcls", "restrictPublicBuckets"} {
		if !prop(pab, k).BoolValue() {
			t.Errorf("public access block: %s is not set", k)
		}
	}
}

func TestTheBucketPolicyDeniesPlainHTTP(t *testing.T) {
	rec, _ := mustStack(t, opts{})
	p := rec.one(t, "aws:s3/bucketPolicy:BucketPolicy", "kernel-bucket-policy")
	st := statements(t, prop(p, "policy").StringValue())
	if len(st) != 1 || st[0]["Effect"] != "Deny" || st[0]["Principal"] != "*" || st[0]["Action"] != "s3:*" {
		t.Fatalf("policy: %v", st)
	}
	want := []string{arnp + "s3:::" + bucket, arnp + "s3:::" + bucket + "/*"}
	if got := strs(st[0]["Resource"]); !reflect.DeepEqual(got, want) {
		t.Errorf("resources %v, want %v", got, want)
	}
	cond := st[0]["Condition"].(map[string]any)["Bool"].(map[string]any)
	if cond["aws:SecureTransport"] != "false" {
		t.Errorf("condition: %v", cond)
	}
}

func TestVersioningIsOptional(t *testing.T) {
	rec, _ := mustStack(t, opts{})
	if len(rec.ofType("aws:s3/bucketVersioningV2:BucketVersioningV2")) != 0 {
		t.Error("versioning was turned on unasked")
	}
	rec, _ = mustStack(t, opts{versioning: true})
	v := rec.one(t, "aws:s3/bucketVersioningV2:BucketVersioningV2", "kernel-bucket-versioning")
	if prop(v, "versioningConfiguration").ObjectValue()["status"].StringValue() != "Enabled" {
		t.Errorf("versioning: %v", v.Inputs)
	}
}

func TestTheSealerKeyRotatesWaitsThirtyDaysIsProtectedAndHasAnAlias(t *testing.T) {
	rec, out := mustStack(t, opts{})
	k := rec.one(t, "aws:kms/key:Key", "kernel-sealer-key")
	if !prop(k, "enableKeyRotation").BoolValue() || prop(k, "deletionWindowInDays").NumberValue() != 30 {
		t.Errorf("key inputs: %v", k.Inputs)
	}
	// Symmetric is the provider's default: neither a spec nor a usage is set.
	for _, key := range []string{"customerMasterKeySpec", "keySpec", "keyUsage", "policy"} {
		if prop(k, key).HasValue() {
			t.Errorf("%s is set: the key is symmetric encrypt/decrypt with the default key policy", key)
		}
	}
	if !rec.isProtected("aws:kms/key:Key", "kernel-sealer-key") {
		t.Error("the key is not protected")
	}
	a := rec.one(t, "aws:kms/alias:Alias", "kernel-sealer-alias")
	if prop(a, "name").StringValue() != "alias/kernel-sluis" || out["keyAlias"] != "alias/kernel-sluis" {
		t.Errorf("alias: %v / %v", a.Inputs, out["keyAlias"])
	}
}

func TestAKeyAliasMustBeAnAlias(t *testing.T) {
	_, _, err := run(t, func(ctx *pulumi.Context, _ func(string, pulumi.StringInput)) error {
		_, err := arp.NewStorage(ctx, "x", &arp.StorageArgs{BucketName: bucket, KeyAlias: "no-prefix"})
		return err
	})
	if err == nil {
		t.Fatal("an alias without the alias/ prefix was accepted")
	}
}

func TestTheTableIsTheAdaptersAndProtected(t *testing.T) {
	rec, out := mustStack(t, opts{})
	d := rec.one(t, "aws:dynamodb/table:Table", "kernel-table")
	if prop(d, "name").StringValue() != table || prop(d, "billingMode").StringValue() != "PAY_PER_REQUEST" ||
		prop(d, "hashKey").StringValue() != "pk" || prop(d, "rangeKey").StringValue() != "sk" {
		t.Errorf("table inputs: %v", d.Inputs)
	}
	attrs := map[string]string{}
	for _, a := range prop(d, "attributes").ArrayValue() {
		attrs[a.ObjectValue()["name"].StringValue()] = a.ObjectValue()["type"].StringValue()
	}
	if !reflect.DeepEqual(attrs, map[string]string{"pk": "S", "sk": "S"}) {
		t.Errorf("attributes %v: only the keys are declared, and both are strings", attrs)
	}
	ttl := prop(d, "ttl").ObjectValue()
	if ttl["attributeName"].StringValue() != "expires" || !ttl["enabled"].BoolValue() {
		t.Errorf("ttl: %v", ttl)
	}
	if !prop(d, "pointInTimeRecovery").ObjectValue()["enabled"].BoolValue() || !prop(d, "deletionProtectionEnabled").BoolValue() {
		t.Errorf("recovery / deletion protection: %v", d.Inputs)
	}
	if prop(d, "serverSideEncryption").HasValue() {
		t.Errorf("a key was set unasked: %v", prop(d, "serverSideEncryption"))
	}
	if !rec.isProtected("aws:dynamodb/table:Table", "kernel-table") {
		t.Error("the table is not protected")
	}
	if out["tableName"] != table || out["tableArn"] != arnp+"dynamodb:eu-west-1:"+account+":table/"+table {
		t.Errorf("outputs: %v", out)
	}
}

func TestATableTakesACustomerManagedKeyAndTheRolesMayUseItOnlyThroughDynamoDB(t *testing.T) {
	cmk := arnp + "kms:eu-west-1:" + account + ":key/state"
	rec, _ := mustStack(t, opts{tableKey: pulumi.String(cmk)})
	d := rec.one(t, "aws:dynamodb/table:Table", "kernel-table")
	sse := prop(d, "serverSideEncryption").ObjectValue()
	if !sse["enabled"].BoolValue() || sse["kmsKeyArn"].StringValue() != cmk {
		t.Errorf("sse: %v", sse)
	}
	p := rec.one(t, "aws:iam/policy:Policy", "kernel-sluis-serve-policy")
	var found bool
	for _, s := range statements(t, prop(p, "policy").StringValue()) {
		if s["Sid"] == "SluisStateKey" {
			found = true
			if !reflect.DeepEqual(strs(s["Resource"]), []string{cmk}) {
				t.Errorf("resource: %v", s["Resource"])
			}
			via := s["Condition"].(map[string]any)["StringLike"].(map[string]any)["kms:ViaService"]
			if via != "dynamodb.*.amazonaws.com" {
				t.Errorf("condition: %v", s["Condition"])
			}
		}
	}
	if !found {
		t.Error("no grant on the table's key")
	}
}

func TestEveryRoleHasItsOwnPolicyRoleAttachmentAndAssociation(t *testing.T) {
	rec, out := mustStack(t, opts{})
	want := map[string]string{ // role -> ServiceAccount
		"kernel-sluis-serve":  "sluis",
		"kernel-sluis-github": "sluis-github",
		"kernel-sluis-slack":  "sluis-slack",
	}
	for role, sa := range want {
		r := rec.one(t, "aws:iam/role:Role", role+"-role")
		if prop(r, "name").StringValue() != role || prop(r, "permissionsBoundary").StringValue() != arnp+"iam::"+account+":policy/boundary" {
			t.Errorf("%s: %v", role, r.Inputs)
		}
		pol := rec.one(t, "aws:iam/policy:Policy", role+"-policy")
		if prop(pol, "name").StringValue() != role {
			t.Errorf("%s policy: %v", role, pol.Inputs)
		}
		att := rec.one(t, "aws:iam/rolePolicyAttachment:RolePolicyAttachment", role+"-attachment")
		if prop(att, "role").StringValue() != role || prop(att, "policyArn").StringValue() != arnp+"iam::"+account+":policy/"+role {
			t.Errorf("%s attachment: %v", role, att.Inputs)
		}
		pia := rec.one(t, "aws:eks/podIdentityAssociation:PodIdentityAssociation", role+"-pia")
		if prop(pia, "clusterName").StringValue() != cluster || prop(pia, "namespace").StringValue() != "sluis" ||
			prop(pia, "serviceAccount").StringValue() != sa || prop(pia, "roleArn").StringValue() != arnp+"iam::"+account+":role/"+role {
			t.Errorf("%s association: %v", role, pia.Inputs)
		}
	}
	if len(rec.ofType("aws:eks/podIdentityAssociation:PodIdentityAssociation")) != 3 {
		t.Error("not exactly one association per process")
	}
	if out["serveRoleArn"] != arnp+"iam::"+account+":role/kernel-sluis-serve" || out["serveRoleName"] != "kernel-sluis-serve" {
		t.Errorf("outputs: %v", out)
	}
}

func TestTheTrustPolicyNamesTheClusterTheNamespaceAndOneServiceAccount(t *testing.T) {
	rec, _ := mustStack(t, opts{})
	r := rec.one(t, "aws:iam/role:Role", "kernel-sluis-github-role")
	st := statements(t, prop(r, "assumeRolePolicy").StringValue())
	if len(st) != 1 || st[0]["Effect"] != "Allow" {
		t.Fatalf("trust: %v", st)
	}
	if st[0]["Principal"].(map[string]any)["Service"] != "pods.eks.amazonaws.com" {
		t.Errorf("principal: %v", st[0]["Principal"])
	}
	if got := strs(st[0]["Action"]); !reflect.DeepEqual(got, []string{"sts:AssumeRole", "sts:TagSession"}) {
		t.Errorf("actions %v", got)
	}
	c := st[0]["Condition"].(map[string]any)
	eq := c["StringEquals"].(map[string]any)
	if eq["aws:SourceAccount"] != account || eq["aws:RequestTag/kubernetes-namespace"] != "sluis" ||
		eq["aws:RequestTag/kubernetes-service-account"] != "sluis-github" {
		t.Errorf("StringEquals: %v", eq)
	}
	if c["ArnEquals"].(map[string]any)["aws:SourceArn"] != arnp+"eks:eu-west-1:"+account+":cluster/"+cluster {
		t.Errorf("ArnEquals: %v", c["ArnEquals"])
	}
}

// What a role may do is asserted whole: an extra action fails here.
func TestEachRoleGetsExactlyTheStorageAndTheTable(t *testing.T) {
	rec, _ := mustStack(t, opts{})
	bucketArn := arnp + "s3:::" + bucket
	keyArn := arnp + "kms:eu-west-1:" + account + ":key/kernel-sealer-key"
	tableArn := arnp + "dynamodb:eu-west-1:" + account + ":table/" + table
	want := map[string][]string{
		"s3:GetObject":           {bucketArn + "/*"},
		"s3:PutObject":           {bucketArn + "/*"},
		"s3:DeleteObject":        {bucketArn + "/*"},
		"s3:ListBucket":          {bucketArn},
		"kms:Encrypt":            {keyArn},
		"kms:Decrypt":            {keyArn},
		"dynamodb:GetItem":       {tableArn},
		"dynamodb:PutItem":       {tableArn},
		"dynamodb:DeleteItem":    {tableArn},
		"dynamodb:Query":         {tableArn},
		"dynamodb:Scan":          {tableArn},
		"dynamodb:DescribeTable": {tableArn},
	}
	for _, role := range []string{"serve", "github", "slack"} {
		p := rec.one(t, "aws:iam/policy:Policy", "kernel-sluis-"+role+"-policy")
		got := grants(statements(t, prop(p, "policy").StringValue()))
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s grants:\n got %v\nwant %v", role, got, want)
		}
	}
}

func TestWithoutStateNoRoleCarriesADynamoDBGrant(t *testing.T) {
	rec, _ := mustStack(t, opts{noState: true})
	for _, role := range []string{"serve", "github", "slack"} {
		p := rec.one(t, "aws:iam/policy:Policy", "kernel-sluis-"+role+"-policy")
		doc := prop(p, "policy").StringValue()
		if strings.Contains(doc, "dynamodb") {
			t.Errorf("%s has a DynamoDB grant without a table: %s", role, doc)
		}
		if got := len(statements(t, doc)); got != 3 {
			t.Errorf("%s has %d statements, want the 3 of the storage", role, got)
		}
	}
	if len(rec.ofType("aws:dynamodb/table:Table")) != 0 {
		t.Error("a table was made")
	}
}

func TestTheSealerIsGrantedOnlyWithTheBindingContextAndTheContextIsMandatory(t *testing.T) {
	rec, _ := mustStack(t, opts{})
	p := rec.one(t, "aws:iam/policy:Policy", "kernel-sluis-serve-policy")
	var n int
	for _, s := range statements(t, prop(p, "policy").StringValue()) {
		acts := strs(s["Action"])
		if !contains(acts, "kms:Encrypt") && !contains(acts, "kms:Decrypt") {
			continue
		}
		if s["Sid"] != "SluisSealer" {
			continue
		}
		n++
		c := s["Condition"].(map[string]any)
		forAll := c["ForAllValues:StringEquals"].(map[string]any)
		if got := strs(forAll["kms:EncryptionContextKeys"]); !reflect.DeepEqual(got, []string{"sluis:binding"}) {
			t.Errorf("context keys %v, want only sluis:binding", got)
		}
		if c["Null"].(map[string]any)["kms:EncryptionContextKeys"] != "false" {
			t.Errorf("Null: %v: without it a request with no context is admitted", c["Null"])
		}
		if len(c) != 2 {
			t.Errorf("conditions %v", c)
		}
	}
	if n != 1 {
		t.Errorf("%d sealer statements", n)
	}
	if arp.BindingContextKey != "sluis:binding" {
		t.Error(arp.BindingContextKey)
	}
}

func TestNoGrantIsOnAWildcardResourceOrAWildcardAction(t *testing.T) {
	rec, _ := mustStack(t, opts{})
	for _, d := range rec.ofType("aws:iam/policy:Policy") {
		for _, s := range statements(t, prop(d, "policy").StringValue()) {
			for _, r := range strs(s["Resource"]) {
				if r == "*" {
					t.Errorf("%s: a grant on every resource: %v", d.Name, s)
				}
			}
			for _, a := range strs(s["Action"]) {
				if strings.HasSuffix(a, "*") {
					t.Errorf("%s: a wildcard action: %v", d.Name, s)
				}
			}
		}
	}
}

func TestAControllerThatIsNotRunIsNotGivenARole(t *testing.T) {
	rec, out := mustStack(t, opts{noSlack: true, noGitHub: true})
	if rec.has("aws:iam/role:Role", "kernel-sluis-slack-role") || rec.has("aws:iam/role:Role", "kernel-sluis-github-role") {
		t.Errorf("roles for processes that were not asked for: %v", rec.names())
	}
	if out["slackRoleArn"] != "" || out["githubRoleArn"] != "" || out["serveRoleArn"] == "" {
		t.Errorf("outputs: %v", out)
	}
}

func TestAServiceAccountTakesOneAssociation(t *testing.T) {
	_, _, err := stack(t, opts{serveSA: "sluis-github"})
	if err == nil || !strings.Contains(err.Error(), "ServiceAccount") {
		t.Fatalf("two processes on one ServiceAccount: %v", err)
	}
}

func TestTheRequiredInputsAreRequired(t *testing.T) {
	_, _, err := run(t, func(ctx *pulumi.Context, _ func(string, pulumi.StringInput)) error {
		_, err := arp.NewKubernetesIdentity(ctx, "x", &arp.KubernetesIdentityArgs{})
		return err
	})
	if err == nil {
		t.Fatal("empty arguments were accepted")
	}
	for _, want := range []string{"ClusterName", "ClusterArn", "AccountID", "Namespace", "Serve.ServiceAccount"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name %s: %v", want, err)
		}
	}
	_, _, err = run(t, func(ctx *pulumi.Context, _ func(string, pulumi.StringInput)) error {
		_, err := arp.NewState(ctx, "x", &arp.StateArgs{})
		return err
	})
	if err == nil {
		t.Error("a table with no name was accepted")
	}
}

func TestTheRolePrefixDefaultsToTheComponentsName(t *testing.T) {
	rec, _, err := run(t, func(ctx *pulumi.Context, _ func(string, pulumi.StringInput)) error {
		s, err := arp.NewStorage(ctx, "ar", &arp.StorageArgs{BucketName: bucket})
		if err != nil {
			return err
		}
		_, err = arp.NewKubernetesIdentity(ctx, "ar", &arp.KubernetesIdentityArgs{
			ClusterName: cluster, ClusterArn: "c", AccountID: account, Namespace: "n",
			Serve: arp.ProcessArgs{ServiceAccount: "s"}, Storage: s.Grant(),
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	r := rec.one(t, "aws:iam/role:Role", "ar-sluis-serve-role")
	if prop(r, "name").StringValue() != "ar-sluis-serve" || prop(r, "permissionsBoundary").HasValue() {
		t.Errorf("role: %v", r.Inputs)
	}
}

// ---- the configuration

func schemaOf(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "config", name+".schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The minimum each binary's file needs beside the ports.
var required = map[string]map[string]any{
	"serve":             {"issuerURL": "https://access.example.test"},
	"controller-github": {"policyDir": "/var/run/sluis/policy", "consoleURL": "https://access.example.test"},
	"controller-slack":  {"policyDir": "/var/run/sluis/policy", "consoleURL": "https://access.example.test"},
}

func validate(t *testing.T, name string, ports map[string]any) error {
	t.Helper()
	doc := map[string]any{}
	for k, v := range required[name] {
		doc[k] = v
	}
	for k, v := range ports {
		doc[k] = v
	}
	// Through YAML, as the binary reads it.
	raw, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var back any
	if err := yaml.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	return policyconfig.Validate(back, schemaOf(t, name))
}

// The rendered block is held to the schema of each binary that reads it, so the
// library cannot drift from the code it configures: a key renamed in
// schemas/config fails here.
func TestTheRenderedPortsValidateAgainstEveryBinarysSchema(t *testing.T) {
	for _, p := range []arp.PortsArgs{
		{BucketName: bucket, KeyID: arp.DefaultKeyAlias("kernel"), TableName: table, Region: "eu-west-1"},
		{BucketName: bucket, KeyID: "alias/x", TableName: table},
		{BucketName: bucket, KeyID: "alias/x", TableName: table, Adapter: "dynamodb", BlobPrefix: "/roster/"},
		{BucketName: bucket, KeyID: "alias/x"},
	} {
		ports, err := arp.RenderPorts(p)
		if err != nil {
			t.Fatal(err)
		}
		for name := range required {
			if err := validate(t, name, ports); err != nil {
				t.Errorf("%s: %+v does not validate: %v\n%v", name, p, err, ports)
			}
		}
	}
}

func TestThePortsNameTheBucketTheKeyTheTableAndTheRegion(t *testing.T) {
	y, err := arp.RenderPortsYAML(arp.PortsArgs{BucketName: bucket, KeyID: "alias/kernel-sluis", TableName: table, Region: "eu-west-1"})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Ports struct {
			Adapter  string
			DynamoDB map[string]any `yaml:"dynamodb"`
			Blob     struct {
				Adapter string
				S3      map[string]any
			}
			Sealer struct {
				Adapter string
				KMS     map[string]any
			}
		}
	}
	if err := yaml.Unmarshal([]byte(y), &doc); err != nil {
		t.Fatal(err)
	}
	p := doc.Ports
	if p.Adapter != "dynamodb" || !reflect.DeepEqual(p.DynamoDB, map[string]any{"table": table, "region": "eu-west-1"}) ||
		p.Blob.Adapter != "s3" || !reflect.DeepEqual(p.Blob.S3, map[string]any{"bucket": bucket, "region": "eu-west-1"}) ||
		p.Sealer.Adapter != "kms" || !reflect.DeepEqual(p.Sealer.KMS, map[string]any{"keyId": "alias/kernel-sluis", "region": "eu-west-1"}) {
		t.Errorf("ports:\n%s", y)
	}
	if strings.Contains(y, "create") || strings.Contains(y, "arn:") {
		t.Errorf("a create flag or an ARN in the block:\n%s", y)
	}
}

func TestWithoutATableNoStateAdapterIsRendered(t *testing.T) {
	ports, err := arp.RenderPorts(arp.PortsArgs{BucketName: bucket, KeyID: "alias/x"})
	if err != nil {
		t.Fatal(err)
	}
	inner := ports["ports"].(map[string]any)
	keys := make([]string, 0, len(inner))
	for k := range inner {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if !reflect.DeepEqual(keys, []string{"blob", "sealer"}) {
		t.Errorf("keys %v", keys)
	}
}

func TestPortsThatCannotBeRenderedAreRefused(t *testing.T) {
	for name, p := range map[string]arp.PortsArgs{
		"no bucket":         {KeyID: "alias/x", TableName: table},
		"no key":            {BucketName: bucket, TableName: table},
		"dynamodb no table": {BucketName: bucket, KeyID: "alias/x", Adapter: "dynamodb"},
		"nats":              {BucketName: bucket, KeyID: "alias/x", Adapter: "nats"},
	} {
		if _, err := arp.RenderPorts(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The schema is the oracle, and it does refuse: the test above would pass on a
// validator that accepts anything.
func TestTheSchemaRefusesAWrongPortsBlock(t *testing.T) {
	bad := map[string]any{"ports": map[string]any{"adapter": "dynamodb"}}
	if err := validate(t, "serve", bad); err == nil {
		t.Error("the schema accepted the dynamodb adapter with no table")
	}
	bad = map[string]any{"ports": map[string]any{"blob": map[string]any{"adapter": "s3", "s3": map[string]any{"bucketName": "x"}}}}
	if err := validate(t, "serve", bad); err == nil {
		t.Error("the schema accepted a blob block with a wrong key")
	}
}

func contains(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}
