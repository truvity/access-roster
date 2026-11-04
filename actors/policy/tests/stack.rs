#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The build of the set and each evaluation run on a thread with a stack of their own, so a caller
//! with a small stack (the main thread of a static musl binary) still gets the local policy built.

mod common;

use common::local_inputs;
use policy::engine::Engine;
use policy::stack::{STACK_BYTES, run};

/// The stack of the caller: smaller than the local policy needs to build (MEASURED 2026-11-04 on a
/// debug build: it fails at 256 KiB, passes at 512 KiB).
const SMALL: usize = 256 * 1024;

/// Runs `f` to the end on a thread with a `SMALL` stack and a current-thread runtime of its own,
/// which is how the main thread of the binary drives `serve` and `check`.
fn on_small_stack<T: Send + 'static>(
    f: impl std::future::Future<Output = T> + Send + 'static,
) -> T {
    std::thread::Builder::new()
        .stack_size(SMALL)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(f)
        })
        .unwrap()
        .join()
        .unwrap()
}

#[test]
fn the_local_policy_builds_from_a_caller_with_a_small_stack() {
    let built = on_small_stack(async {
        let inputs = local_inputs();
        Engine::build_on_stack(&inputs)
            .await
            .map(|e| e.digest().to_owned())
            .map_err(|e| e.to_string())
    });
    let digest = built.unwrap_or_else(|e| panic!("the local policy is refused: {e}"));
    // The same set as a build on an ordinary stack: the thread changes nothing but the stack.
    assert_eq!(digest, Engine::build(&local_inputs()).unwrap().digest());
}

/// A function that really uses stack: about 1 KiB a frame, `depth` deep.
#[inline(never)]
fn deep(depth: usize) -> usize {
    let pad = [1u8; 1024];
    if depth == 0 {
        0
    } else {
        deep(depth - 1) + usize::from(std::hint::black_box(pad)[depth % 1024])
    }
}

#[test]
fn the_thread_has_the_documented_stack_whatever_the_stack_of_the_caller() {
    // At least 1 KiB a frame (a debug build uses a few KiB): from 2 MiB to 8 MiB, which is far past
    // the stack of the caller and inside the documented one.
    let depth = STACK_BYTES / 8 / 1024;
    assert!(depth * 1024 >= 8 * SMALL && depth * 4096 < STACK_BYTES);
    let got = on_small_stack(async move { run(move || deep(depth)).await.unwrap() });
    assert_eq!(got, depth, "each frame added its one");
}

#[test]
fn a_panic_on_the_thread_is_a_lost_result_and_not_a_hang() {
    let lost = on_small_stack(async {
        run(|| -> usize { panic!("a fault in evaluation") })
            .await
            .is_err()
    });
    assert!(lost);
}
