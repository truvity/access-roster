//! The conformance suite of the destination port (REQ-EXPORT-027): the cases every driver passes, run by a driver's
//! `conformance` command against a destination of its own making, and by the tests of the in-memory driver. A case
//! that fails is the error; there is no skip. The suite writes under the prefix `conformance/` and removes what it
//! wrote.

use anyhow::{Result, bail, ensure};

use crate::{BODY_MAX, Destination, Document, Error, Page, Purged, check_address, sha256_hex};

/// What the destination under test is.
#[derive(Debug, Clone, Default)]
pub struct Caps {
    /// The base of the public addresses (`<base>/<address>`), or `None` for a destination with no public address:
    /// `read_back` must then be unsupported.
    pub public_base: Option<String>,
    /// Whether an edge cache sits in front of the public address: `purge` must then answer [`Purged::Purged`] and make
    /// the next `read_back` fetch the document again. Without one it answers [`Purged::None`].
    pub edge: bool,
}

const ROOT: &str = "conformance/";

fn doc(address: &str, body: &[u8]) -> Document {
    Document {
        address: address.to_owned(),
        content_type: "application/json".into(),
        cache_control: "public, max-age=300".into(),
        body: body.to_vec(),
    }
}

async fn list_all<D: Destination>(d: &D, prefix: &str, size: usize) -> Result<Vec<crate::Listed>> {
    let mut out = Vec::new();
    let mut token: Option<String> = None;
    for _ in 0..1000 {
        let Page { documents, next } = d.list(prefix, token.as_deref(), size).await?;
        ensure!(
            size == 0 || documents.len() <= size,
            "a page of {} documents for a page size of {size}",
            documents.len()
        );
        out.extend(documents);
        match next {
            Some(t) => token = Some(t),
            None => return Ok(out),
        }
    }
    bail!("a listing that does not end")
}

macro_rules! rejected {
    ($e:expr, $what:expr) => {{
        let got = $e.await;
        ensure!(
            matches!(got, Err(Error::Invalid(_))),
            "{}: answered {got:?}, not invalid",
            $what
        )
    }};
}

/// Runs every case against `d`.
///
/// # Errors
///
/// The first case that fails.
pub async fn run<D: Destination>(d: &D, caps: &Caps) -> Result<()> {
    let outcome = cases(d, caps).await;
    // What the cases wrote goes, whatever happened.
    if let Ok(left) = list_all(d, ROOT, 0).await {
        for l in left {
            let _ = d.delete(&l.address).await;
        }
    }
    outcome
}

async fn cases<D: Destination>(d: &D, caps: &Caps) -> Result<()> {
    ensure!(
        list_all(d, ROOT, 0).await?.is_empty(),
        "the destination holds documents under {ROOT} before the suite: it needs an empty one"
    );

    // Put, then List shows the digest, the sizes and the headers it was written with.
    let a = format!("{ROOT}a.json");
    let body1 = br#"{"keys":[]}"#.to_vec();
    let w = d.put(doc(&a, &body1)).await?;
    ensure!(w.sha256 == sha256_hex(&body1), "put: the digest it reports");
    ensure!(!w.version.is_empty(), "put: no version");
    let l = list_all(d, ROOT, 0).await?;
    ensure!(l.len() == 1, "list: {} documents after one put", l.len());
    ensure!(
        l[0].address == a
            && l[0].sha256 == w.sha256
            && l[0].size == body1.len() as u64
            && l[0].content_type == "application/json"
            && l[0].cache_control == "public, max-age=300",
        "list: {:?} is not what was put",
        l[0]
    );
    println!("ok: put and list");

    // A second put at the address replaces the whole document, and a put of the same bytes is harmless.
    let body2 = br#"{"keys":[{"kid":"k"}],"x":"a longer document than the first"}"#.to_vec();
    let w2 = d.put(doc(&a, &body2)).await?;
    ensure!(w2.sha256 == sha256_hex(&body2), "overwrite: the digest");
    let l = list_all(d, ROOT, 0).await?;
    ensure!(
        l.len() == 1 && l[0].sha256 == w2.sha256 && l[0].size == body2.len() as u64,
        "overwrite: {l:?}"
    );
    let shorter = d.put(doc(&a, b"{}")).await?;
    ensure!(
        list_all(d, ROOT, 0).await?[0].size == 2 && shorter.sha256 == sha256_hex(b"{}"),
        "a shorter document leaves the end of the longer one"
    );
    d.put(doc(&a, b"{}")).await?;
    println!("ok: overwrite");

    // Paging in address order, and the prefix.
    for i in 0..5 {
        d.put(doc(
            &format!("{ROOT}p/{i}.json"),
            format!("{{\"n\":{i}}}").as_bytes(),
        ))
        .await?;
    }
    let paged = list_all(d, &format!("{ROOT}p/"), 2).await?;
    let names: Vec<_> = paged.iter().map(|l| l.address.as_str()).collect();
    let want: Vec<String> = (0..5).map(|i| format!("{ROOT}p/{i}.json")).collect();
    ensure!(
        names == want.iter().map(String::as_str).collect::<Vec<_>>(),
        "paging: {names:?}"
    );
    ensure!(
        list_all(d, ROOT, 0).await?.len() == 6,
        "the prefix {ROOT} lists every document"
    );
    ensure!(
        list_all(d, &format!("{ROOT}zzz"), 0).await?.is_empty(),
        "a prefix nothing has lists nothing"
    );
    println!("ok: paging and prefix");

    // A large binary body survives byte for byte.
    let big: Vec<u8> = (0..(1 << 20)).map(|i: u32| (i % 251) as u8).collect();
    let bw = d.put(doc(&format!("{ROOT}big.bin"), &big)).await?;
    ensure!(bw.sha256 == sha256_hex(&big), "a binary body of 1 MiB");
    println!("ok: a large body");

    // A reader of the listing sees the old document or the new one while it is replaced, never a mixture.
    let (x, y) = (vec![b'x'; 40_000], vec![b'y'; 70_001]);
    let (dx, dy) = (sha256_hex(&x), sha256_hex(&y));
    let target = format!("{ROOT}race.json");
    d.put(doc(&target, &x)).await?;
    let writer = async {
        for i in 0..40 {
            d.put(doc(&target, if i % 2 == 0 { &y } else { &x }))
                .await
                .map(|_| ())?;
        }
        Ok::<(), Error>(())
    };
    let reader = async {
        for _ in 0..40 {
            for l in list_all(d, &target, 0).await.map_err(|e| e.to_string())? {
                let whole =
                    (l.sha256 == dx && l.size == 40_000) || (l.sha256 == dy && l.size == 70_001);
                if !whole {
                    return Err(format!("a listing saw a document that is neither: {l:?}"));
                }
            }
        }
        Ok(())
    };
    let (wr, rd) = tokio::join!(writer, reader);
    wr?;
    if let Err(why) = rd {
        bail!("atomic write: {why}");
    }
    println!("ok: a write is whole");

    // Delete removes what was written, and says so; a second delete finds nothing.
    ensure!(
        d.delete(&target).await?,
        "delete: the document was not found"
    );
    ensure!(
        !d.delete(&target).await?,
        "delete: a document that is gone was found"
    );
    ensure!(
        !list_all(d, ROOT, 0)
            .await?
            .iter()
            .any(|l| l.address == target),
        "delete: still listed"
    );
    println!("ok: delete");

    // What is not an address, a prefix or a header value is refused before anything is written.
    for bad in [
        "", "/x", "x/", "a//b", "../x", "a/../b", "./a", "A.json", "a b", ".sluis/x",
    ] {
        rejected!(d.put(doc(bad, b"{}")), format!("put at {bad:?}"));
        rejected!(d.delete(bad), format!("delete at {bad:?}"));
    }
    ensure!(
        check_address(&format!("{ROOT}ok")).is_ok(),
        "the suite's own address"
    );
    rejected!(d.list("../", None, 0), "list of ../");
    rejected!(d.list("/", None, 0), "list of /");
    rejected!(
        d.put(doc(&format!("{ROOT}big"), &vec![0; BODY_MAX + 1])),
        "a body over the limit"
    );
    let mut bad = doc(&format!("{ROOT}hdr"), b"{}");
    bad.cache_control = "public\r\nSet-Cookie: x=1".into();
    rejected!(d.put(bad), "a header value with a line break");
    ensure!(
        !list_all(d, ROOT, 0)
            .await?
            .iter()
            .any(|l| l.address.ends_with("hdr")),
        "a refused put left a document"
    );
    println!("ok: refusals");

    public(d, caps).await?;
    Ok(())
}

async fn public<D: Destination>(d: &D, caps: &Caps) -> Result<()> {
    let Some(base) = caps.public_base.as_deref().map(|b| b.trim_end_matches('/')) else {
        // No public address: nothing to read back, and nothing to purge at.
        let r = d.read_back("https://example.invalid/x").await;
        ensure!(
            r == Err(Error::Unsupported),
            "read_back with no public address: {r:?}"
        );
        let p = d.purge(&["https://example.invalid/x".to_owned()]).await;
        ensure!(p == Ok(Purged::None), "purge with no edge: {p:?}");
        println!("ok: no public address");
        return Ok(());
    };
    let address = format!("{ROOT}pub.json");
    let url = format!("{base}/{address}");
    let v1 = br#"{"v":1}"#.to_vec();
    d.put(doc(&address, &v1)).await?;
    let f = d.read_back(&url).await?;
    ensure!(
        f.status == 200 && f.body == v1,
        "read back: status {} or body",
        f.status
    );
    ensure!(
        f.cache_control == "public, max-age=300" && f.content_type == "application/json",
        "read back: headers {:?} {:?}",
        f.cache_control,
        f.content_type
    );
    // After a replacement and a purge, a verifier sees the new document.
    let v2 = br#"{"v":2,"more":true}"#.to_vec();
    d.put(doc(&address, &v2)).await?;
    let purged = d.purge(std::slice::from_ref(&url)).await?;
    ensure!(
        purged
            == if caps.edge {
                Purged::Purged
            } else {
                Purged::None
            },
        "purge answered {purged:?} for edge={}",
        caps.edge
    );
    let f = d.read_back(&url).await?;
    ensure!(
        f.status == 200 && f.body == v2,
        "after a purge a read back sees the old document"
    );
    // A purge of an address that is not this destination's is refused, and a missing document is a 404.
    rejected!(
        d.purge(&["https://example.invalid/other".to_owned()]),
        "a purge of another host"
    );
    rejected!(
        d.read_back("https://example.invalid/other"),
        "a read back of another host"
    );
    let missing = d.read_back(&format!("{base}/{ROOT}missing.json")).await?;
    ensure!(
        missing.status == 404,
        "a missing document read back with status {}",
        missing.status
    );
    println!("ok: public address, purge and read back");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::Memory;

    #[tokio::test]
    async fn the_memory_driver_with_no_public_address_passes() {
        run(&Memory::new(), &Caps::default()).await.unwrap();
    }

    #[tokio::test]
    async fn the_memory_driver_with_a_public_address_and_no_edge_passes() {
        let caps = Caps {
            public_base: Some("https://sluis.example.com".into()),
            edge: false,
        };
        run(
            &Memory::with_public("https://sluis.example.com", false),
            &caps,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn the_memory_driver_with_an_edge_passes() {
        let caps = Caps {
            public_base: Some("https://sluis.example.com/".into()),
            edge: true,
        };
        run(
            &Memory::with_public("https://sluis.example.com", true),
            &caps,
        )
        .await
        .unwrap();
    }

    /// The suite fails a driver that is wrong, so it is not a check that passes anything: a destination whose purge
    /// does nothing leaves a stale copy, which the suite catches.
    #[tokio::test]
    async fn the_suite_fails_an_edge_whose_purge_does_nothing() {
        let m = Memory::with_public("https://sluis.example.com", true);
        m.purge_does_nothing(true);
        let caps = Caps {
            public_base: Some("https://sluis.example.com".into()),
            edge: true,
        };
        let why = run(&m, &caps).await.unwrap_err().to_string();
        assert!(why.contains("old document"), "{why}");
    }

    #[tokio::test]
    async fn the_suite_fails_a_driver_that_has_an_address_it_cannot_read_back() {
        // Claims no public address while the caps say there is one.
        let caps = Caps {
            public_base: Some("https://sluis.example.com".into()),
            edge: false,
        };
        assert!(run(&Memory::new(), &caps).await.is_err());
    }
}
