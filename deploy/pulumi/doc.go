// Package sluispulumi is the AWS shape of sluis as a Pulumi Go
// library: the storage the service keeps its blobs and its sealed credentials
// in, the DynamoDB table of the State port, and the EKS Pod Identity roles of
// the three processes that use them.
//
// It is a library, not a program: a stack calls the constructors below and
// gets components with the outputs a deployment needs. It creates nothing by
// being imported, this repository deploys nothing with it, and it is a module
// of its own (github.com/truvity/sluis/deploy/pulumi) so that Pulumi is
// not in the root module's dependency graph.
//
//	store, err := sluispulumi.NewStorage(ctx, "kernel", &sluispulumi.StorageArgs{
//		BucketName: "acme-sluis",
//	}, pulumi.Providers(aws))
//	state, err := sluispulumi.NewState(ctx, "kernel", &sluispulumi.StateArgs{
//		TableName: "acme-sluis",
//	}, pulumi.Providers(aws))
//	ids, err := sluispulumi.NewKubernetesIdentity(ctx, "kernel", &sluispulumi.KubernetesIdentityArgs{
//		ClusterName: "acme", ClusterArn: clusterArn, AccountID: accountID,
//		Namespace:              "sluis",
//		PermissionsBoundaryArn: boundary,
//		Serve:                  sluispulumi.ProcessArgs{ServiceAccount: "sluis"},
//		GitHub:                 sluispulumi.ProcessArgs{ServiceAccount: "sluis-github"},
//		Slack:                  sluispulumi.ProcessArgs{ServiceAccount: "sluis-slack"},
//		Storage:                store.Grant(),
//		State:                  state.Grant(),
//	}, pulumi.Providers(aws))
//
// RenderPorts renders the `ports:` block of the processes' configuration from
// the same names.
//
// docs/deployment/aws.md is the guide: every input and output and the IAM.
package sluispulumi
