//! The pages whose policy is not the strict one. A reply of `session` names its page with `HttpReply.page`, and `entry` gives the
//! policy of the word from the closed table below; a word the table does not hold is a server error, never a guess, so a
//! compromised or confused `session` cannot ask for a looser policy than the table allows.
//!
//! The registration page of a passkey needs one inline script. It is allowed by its SHA-256 hash (CSP Level 3 `script-src`
//! hash-source), never by `'unsafe-inline'`, and the page holds no other script. The script holds no data: the options of the
//! ceremony are in an attribute of the form, as text. The page posts a form to this origin and loads nothing, so everything
//! else is denied: `default-src 'none'`, which leaves `connect-src` at none as well, and `form-action 'self'`.

/// The page word of the registration page.
pub(crate) const PAGE_PASSKEY: &str = "passkey";

/// The one inline script of the registration page, byte for byte: the text between `<script>` and `</script>`. `session` builds
/// the page (actors/session/internal/sessiond/passkey_routes.go, `passkeyScript`) and a Go test there compares the hash in
/// [`CSP_PASSKEY`] with the hash of the script it serves. A change of the text changes the hash: the test
/// `the_passkey_policy_holds_the_hash_of_the_script` fails until both agree.
#[cfg(test)]
const PASSKEY_SCRIPT: &str = "(function(){var f=document.forms[0],m=document.getElementById(\"message\");f.addEventListener(\"submit\",function(e){e.preventDefault();if(!window.PublicKeyCredential||!PublicKeyCredential.parseCreationOptionsFromJSON){m.textContent=\"This browser cannot make a passkey.\";return}var o;try{o=PublicKeyCredential.parseCreationOptionsFromJSON(JSON.parse(f.dataset.options))}catch(x){m.textContent=\"The passkey could not be started.\";return}navigator.credentials.create({publicKey:o}).then(function(c){f.elements.response.value=JSON.stringify(c.toJSON());f.submit()},function(){m.textContent=\"The passkey was not made. You can try again.\"})})})();";

/// The policy of the registration page.
pub(crate) const CSP_PASSKEY: &str = "default-src 'none'; script-src 'sha256-ItJ88/dToB9XgzbCO8XUWMJ2VcXw8QjxEUZGe6QfvH0='; \
frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/// The policy of a page word, or `None` for a word `entry` does not know.
pub(crate) fn policy_of(word: &str) -> Option<&'static str> {
    match word {
        PAGE_PASSKEY => Some(CSP_PASSKEY),
        _ => None,
    }
}

/// Whether a response is an HTML 200: only such a reply may carry a page word.
pub(crate) fn is_html_ok(resp: &crate::handler::Reply) -> bool {
    resp.status() == http::StatusCode::OK
        && resp
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().starts_with("text/html"))
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::digest::{SHA256, digest};
    use base64::Engine as _;

    use super::{CSP_PASSKEY, PAGE_PASSKEY, PASSKEY_SCRIPT, policy_of};

    /// verifies: REQ-AUTHN-018
    #[test]
    fn the_passkey_policy_holds_the_hash_of_the_script() {
        let hash = base64::engine::general_purpose::STANDARD
            .encode(digest(&SHA256, PASSKEY_SCRIPT.as_bytes()).as_ref());
        let want = format!("script-src 'sha256-{hash}';");
        assert!(
            CSP_PASSKEY.contains(&want),
            "the script changed: put script-src 'sha256-{hash}' in CSP_PASSKEY"
        );
    }

    /// The policy allows nothing inline but the one hash, loads nothing, and posts only to this origin.
    ///
    /// verifies: REQ-AUTHN-018
    #[test]
    fn the_passkey_policy_allows_one_script_and_nothing_else() {
        let dirs: Vec<&str> = CSP_PASSKEY.split(';').map(str::trim).collect();
        assert!(!CSP_PASSKEY.contains("unsafe-inline"), "{CSP_PASSKEY}");
        assert!(!CSP_PASSKEY.contains("unsafe-eval"), "{CSP_PASSKEY}");
        assert!(dirs.contains(&"default-src 'none'"), "{CSP_PASSKEY}");
        assert!(dirs.contains(&"form-action 'self'"), "{CSP_PASSKEY}");
        assert!(dirs.contains(&"frame-ancestors 'none'"), "{CSP_PASSKEY}");
        assert!(dirs.contains(&"base-uri 'none'"), "{CSP_PASSKEY}");
        assert!(
            !dirs.iter().any(|d| d.starts_with("connect-src")
                || d.starts_with("img-src")
                || d.starts_with("style-src")
                || d.starts_with("frame-src")),
            "{CSP_PASSKEY}"
        );
        assert_eq!(
            dirs.iter().filter(|d| d.starts_with("script-src")).count(),
            1
        );
    }

    #[test]
    fn only_the_known_word_has_a_policy() {
        assert_eq!(policy_of(PAGE_PASSKEY), Some(CSP_PASSKEY));
        for w in [
            "",
            "Passkey",
            "passkey ",
            "passkeys",
            "form_post",
            "none",
            "*",
        ] {
            assert_eq!(policy_of(w), None, "{w:?}");
        }
    }
}
