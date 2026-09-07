# accessctl

```sh
accessctl login   --issuer https://issuer.example.internal
accessctl whoami
accessctl kubeconfig                         # a context per granted cluster
accessctl aws-config                         # a profile per granted cloud role
kubectl --context kernel get nodes           # exec plugin: accessctl kube-token
aws --profile power@1111 sts get-caller-identity   # credential_process: accessctl aws
accessctl exchange --audience k8s:devel < subject-token
accessctl policy test policy.yaml
```

Configuration: `~/.config/accessctl/config.yaml` (issuer, client id,
cache location) written by `login`. In CI the same binary detects the
platform's identity-token environment and exchanges instead of reading a
cache; no configuration file is needed there beyond `--issuer`.

Exit codes: `0`, `2` usage, `3` not signed in, `4` audience not granted,
`5` issuer unreachable.
