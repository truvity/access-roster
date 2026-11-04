#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! store@'s facts reach the audit transport through the real emitter, over the kit's transport.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use connectrpc::{RequestContext, Response, Router, ServiceRequest, ServiceResult, ServiceStream};
use sluis_kit::{Allow, Identities, ServerConfig, refusal};
use sluis_proto::sluis::port::transport::v2alpha1::{
    AckRequest, AckResponse, EmitRequest, EmitResponse, ReceiveRequest, ReceiveResponse,
    TransportService, TransportServiceExt as _,
};
use store::audit::{AuditEvent, AuditSink, Auditor, EmitterSink};

#[derive(Default)]
struct Spool {
    reqs: Mutex<Vec<EmitRequest>>,
}

impl TransportService for Spool {
    async fn emit(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, EmitRequest>,
    ) -> ServiceResult<EmitResponse> {
        self.reqs.lock().unwrap().push(request.to_owned_message());
        Response::ok(EmitResponse::default())
    }
    async fn receive(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, ReceiveRequest>,
    ) -> ServiceResult<ServiceStream<ReceiveResponse>> {
        Err(refusal(
            connectrpc::error::ErrorCode::Unimplemented,
            "unsupported",
            "",
        ))
    }
    async fn ack(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, AckRequest>,
    ) -> ServiceResult<AckResponse> {
        Err(refusal(
            connectrpc::error::ErrorCode::Unimplemented,
            "unsupported",
            "",
        ))
    }
}

async fn spool(dir: &std::path::Path) -> (Arc<Spool>, std::path::PathBuf) {
    let spool = Arc::new(Spool::default());
    let sock = dir.join("emit.sock");
    let me = rustix::process::geteuid().as_raw();
    tokio::spawn(sluis_kit::serve_with(
        ServerConfig {
            actor: "transport",
            boundary: "dev".into(),
            socket: sock.clone(),
            mode: 0o660,
            socket_gid: None,
            allow: Allow::Exact("store"),
            default_deadline: Duration::from_secs(5),
        },
        Arc::clone(&spool).register(Router::new()),
        std::future::pending(),
        Identities::with(0, move |u| (u == me).then_some(("store", 0))),
    ));
    for _ in 0..300 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (spool, sock)
}

fn emitter(sock: &std::path::Path) -> sluis_audit::Emitter {
    sluis_audit::Emitter::new(sluis_audit::Config {
        actor: "store".into(),
        boundary: "dev".into(),
        release: "0.0.0".into(),
        transport_socket: sock.to_owned(),
        key_socket: None,
        now: None,
    })
    .unwrap()
}

fn refused() -> AuditEvent {
    AuditEvent {
        action: "store.refused",
        failure: true,
        reason: "rule".into(),
        fields: vec![("caller", "quota".into()), ("kind", "Person".into())],
        correlation_id: Some("req-7".into()),
    }
}

#[tokio::test]
async fn a_fact_is_one_non_blocking_message_on_the_transport() {
    let dir = tempfile::tempdir().unwrap();
    let (spool, sock) = spool(dir.path()).await;
    let audit = Auditor::new(EmitterSink(emitter(&sock)));
    audit.emit(refused()).await;
    assert_eq!(audit.failed(), 0);
    let reqs = spool.reqs.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    assert!(!reqs[0].blocking, "store@ makes no credential change");
    let m = &reqs[0].message;
    let rec: serde_json::Value = serde_json::from_slice(&m.record).unwrap();
    assert_eq!(rec["metadata"]["uid"], m.uid);
    assert_eq!(rec["metadata"]["event_code"], "store.refused");
    assert_eq!(rec["metadata"]["correlation_uid"], "req-7");
}

#[tokio::test]
async fn an_emit_that_fails_is_returned_counted_and_not_retried() {
    let dir = tempfile::tempdir().unwrap();
    // No transport is listening.
    let sink = EmitterSink(emitter(&dir.path().join("none.sock")));
    assert!(sink.emit(refused()).await.is_err());
    let audit = Auditor::new(sink);
    audit.emit(refused()).await;
    assert_eq!(audit.failed(), 1);
}
