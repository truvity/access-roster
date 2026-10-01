# Roadmap

Work that is wanted but not started. Each entry is a note, not a commitment:
nothing here is built, and none of it changes what the pages elsewhere
describe.

## To do

### Evaluate running on Cloudflare Containers

- **Shape.** The existing OCI image behind a Worker, with at least 2 warm
  instances (a sleeping container's cold start is seconds) and a Cron Trigger
  for the controller passes.
- **State.** Either it stays on AWS (SSM, DynamoDB, KMS), or it moves to new
  Durable Objects or Secrets Store adapters. Workers KV is eventually
  consistent, so it cannot hold sessions.
- **Compare with** AWS Lambda plus Lambda Web Adapter plus API Gateway, which
  is the primary serverless target.
- **Deliverable.** A measured go/no-go. No code before it.
