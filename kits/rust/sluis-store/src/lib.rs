//! The typed store client of [0005 Typed clients](https://sluis.id/decisions/0005-the-store/#typed-clients):
//! `Store<K: Kind>` binds one kind, names it by its registry segment, validates the address before
//! the call, and encodes and decodes the kind's Protobuf message.
//!
//! The message trait is buffa's, because that is the runtime `connectrpc` 0.9 generates for
//! (PLAN.md D-23); the record spells `prost::Message`.
//!
//! The client does not seal. A sealed kind's helper arrives with the first sealed-kind caller
//! (session, #1221).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use buffa::Message;
use buffa_types::google::protobuf::Duration as PbDuration;
use connectrpc::ConnectError;
use connectrpc::error::ErrorCode;
use sluis_kit::{Client, Transport, refusal_reason};
use sluis_proto::sluis::store::v2alpha1::{
    GetRequest, Item as WireItem, ListRequest, Operation, StoreServiceClient, Verb, WriteRequest,
};
use sluis_proto::sluis::r#type::v2alpha1::{Address, IndexEntry};
use sluis_registry::Scope;

/// A kind, bound to its Protobuf message at compile time.
pub trait Kind {
    /// The type of the id (`AsRef<str>`; the client takes `&str`).
    type Id: AsRef<str>;
    /// The kind's Protobuf message.
    type Value: Message + Default;
    /// The registry name, PascalCase: `"SigningRing"`.
    const NAME: &'static str;
}

/// An item as the store returned it.
#[derive(Clone, Debug, PartialEq)]
pub struct Item<K: Kind> {
    /// The tenant; empty for a kind with none.
    pub tenant: String,
    /// The id.
    pub id: String,
    /// 1 at create, plus 1 at each change.
    pub version: u64,
    /// The decoded message.
    pub value: K::Value,
    /// When the item expires, for a kind with a TTL.
    pub expires_at: Option<SystemTime>,
}

/// What a write may carry.
#[derive(Clone, Debug, Default)]
pub struct WriteOpts {
    /// The sealed grant, required when an address is tenant-scoped.
    pub grant: Option<Vec<u8>>,
    /// A TTL shorter than the kind's maximum.
    pub ttl: Option<Duration>,
    /// The declared indexes, computed by the writer.
    pub indexes: Vec<(String, Vec<u8>)>,
}

/// Why a store call did not give an item.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No such item, or an expired one (`not_found`).
    #[error("not found")]
    NotFound,
    /// A create found the address in use (`already_exists`).
    #[error("already exists")]
    Exists,
    /// An update or delete named a version that is no longer current (`aborted`).
    #[error("version moved")]
    Version,
    /// The address does not fit store-api.md "Address encoding"; the string is a field path.
    #[error("address: {0}")]
    Address(String),
    /// The name is not a kind of the registry.
    #[error("not a kind of the registry: {0}")]
    UnknownKind(&'static str),
    /// The store returned bytes that are not the kind's message.
    #[error("the stored value is not the kind's message")]
    Decode,
    /// Any other refusal or transport failure, with the reason of its `Refusal` detail if any.
    #[error("{} ({})", .0.code.as_str(), .1.as_deref().unwrap_or("-"))]
    Rpc(ConnectError, Option<String>),
}

impl From<ConnectError> for Error {
    fn from(e: ConnectError) -> Self {
        match e.code {
            ErrorCode::NotFound => Error::NotFound,
            ErrorCode::AlreadyExists => Error::Exists,
            ErrorCode::Aborted => Error::Version,
            _ => {
                let reason = refusal_reason(&e);
                Error::Rpc(e, reason)
            }
        }
    }
}

/// The kebab-case segment of a PascalCase kind name: a hyphen before each capital that follows a
/// lower-case letter or a digit, then lower-cased (store-api.md "Address encoding").
#[must_use]
pub fn segment_of(pascal: &str) -> String {
    let mut out = String::with_capacity(pascal.len() + 4);
    let mut prev: Option<char> = None;
    for c in pascal.chars() {
        if c.is_ascii_uppercase()
            && prev.is_some_and(|p| p.is_ascii_lowercase() || p.is_ascii_digit())
        {
            out.push('-');
        }
        out.push(c.to_ascii_lowercase());
        prev = Some(c);
    }
    out
}

const PART_MAX: usize = 128;
const ADDRESS_MAX: usize = 300;

fn valid_part(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= PART_MAX
        && p != "."
        && p != ".."
        && p.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'))
}

/// Checks an id: one or more parts separated by `/`, each 1 to 128 characters of lower-case
/// letters, digits, `-`, `_` and `.`, never `.` or `..` (store-api.md "Address encoding").
///
/// # Errors
///
/// [`Error::Address`] with the path of the part at fault; never the value.
pub fn validate_id(id: &str) -> Result<(), Error> {
    for (i, part) in id.split('/').enumerate() {
        if !valid_part(part) {
            return Err(Error::Address(format!("id[{i}]")));
        }
    }
    Ok(())
}

/// Checks a whole address `<boundary>/<tenant | ->/<kind>/<id>`: four or more parts, every part
/// valid, and at most 300 bytes.
///
/// # Errors
///
/// [`Error::Address`] with the path of the part at fault.
pub fn validate_address(address: &str) -> Result<(), Error> {
    if address.len() > ADDRESS_MAX {
        return Err(Error::Address("address".into()));
    }
    let mut it = address.splitn(4, '/');
    for (name, part) in ["boundary", "tenant", "kind"].iter().zip(&mut it) {
        if !valid_part(part) {
            return Err(Error::Address((*name).into()));
        }
    }
    validate_id(it.next().ok_or_else(|| Error::Address("id".into()))?)
}

/// The typed client of one kind.
pub struct Store<K: Kind> {
    client: StoreServiceClient<Transport>,
    segment: &'static str,
    scope: Scope,
    _kind: std::marker::PhantomData<fn() -> K>,
}

impl<K: Kind> Store<K> {
    /// Binds a client to the kind `K::NAME`; the segment comes from the registry.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownKind`] when the name is not in the registry.
    pub fn new(client: Client) -> Result<Self, Error> {
        let kind = sluis_registry::kind_by_name(K::NAME).ok_or(Error::UnknownKind(K::NAME))?;
        Ok(Self {
            client: StoreServiceClient::new(client.transport(), client.config()),
            segment: kind.segment,
            scope: kind.scope,
            _kind: std::marker::PhantomData,
        })
    }

    /// The wire tenant: empty for a kind with none, the tenant id otherwise. `-` is only the text
    /// form of "no tenant" inside an address and is never a tenant id, so it is refused here.
    fn wire_tenant(&self, tenant: &str) -> Result<String, Error> {
        match (self.scope, tenant.is_empty()) {
            (Scope::Boundary, true) => Ok(String::new()),
            (Scope::BoundaryTenant, false) if tenant != "-" && valid_part(tenant) => {
                Ok(tenant.to_owned())
            }
            _ => Err(Error::Address("tenant".into())),
        }
    }

    fn address(&self, tenant: &str, id: &str) -> Result<Address, Error> {
        let tenant = self.wire_tenant(tenant)?;
        validate_id(id)?;
        Ok(Address {
            kind: self.segment.to_owned(),
            tenant,
            id: id.to_owned(),
            ..Address::default()
        })
    }

    fn item(&self, w: &WireItem) -> Result<Item<K>, Error> {
        let value = K::Value::decode_from_slice(&w.value).map_err(|_| Error::Decode)?;
        let expires_at = w.expires_at.as_option().and_then(|t| {
            let secs = u64::try_from(t.seconds).ok()?;
            let nanos = u32::try_from(t.nanos).ok()?;
            Some(UNIX_EPOCH + Duration::new(secs, nanos))
        });
        Ok(Item {
            tenant: w.address.tenant.clone(),
            id: w.address.id.clone(),
            version: w.version,
            value,
            expires_at,
        })
    }

    /// One item by address.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`], [`Error::Address`], or the store's refusal.
    pub async fn get(&self, tenant: &str, id: &str) -> Result<Item<K>, Error> {
        let req = GetRequest {
            address: self.address(tenant, id)?.into(),
            ..GetRequest::default()
        };
        let resp = self.client.get(req).await?.into_owned();
        self.item(&resp.item)
    }

    /// One page of the tenant's items of the kind, and the token of the next page.
    ///
    /// # Errors
    ///
    /// [`Error::Address`], or the store's refusal.
    pub async fn list(
        &self,
        tenant: &str,
        page: Option<String>,
    ) -> Result<(Vec<Item<K>>, Option<String>), Error> {
        let req = ListRequest {
            kind: self.segment.to_owned(),
            tenant: self.wire_tenant(tenant)?,
            page_token: page.unwrap_or_default(),
            ..ListRequest::default()
        };
        let resp = self.client.list(req).await?.into_owned();
        let items = resp
            .items
            .iter()
            .map(|i| self.item(i))
            .collect::<Result<Vec<_>, _>>()?;
        let next = (!resp.next_page_token.is_empty()).then_some(resp.next_page_token);
        Ok((items, next))
    }

    async fn write(
        &self,
        verb: Verb,
        tenant: &str,
        id: &str,
        value: Option<&K::Value>,
        if_version: u64,
        w: WriteOpts,
    ) -> Result<Option<Item<K>>, Error> {
        let op = Operation {
            verb: verb.into(),
            address: self.address(tenant, id)?.into(),
            value: value.map(Message::encode_to_vec).unwrap_or_default(),
            if_version,
            ttl: w
                .ttl
                .map(|d| PbDuration {
                    seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
                    nanos: i32::try_from(d.subsec_nanos()).unwrap_or(0),
                    ..PbDuration::default()
                })
                .into(),
            indexes: w
                .indexes
                .into_iter()
                .map(|(name, value)| IndexEntry {
                    name,
                    value,
                    ..IndexEntry::default()
                })
                .collect(),
            ..Operation::default()
        };
        let req = WriteRequest {
            operations: vec![op],
            grant: w.grant.unwrap_or_default(),
            ..WriteRequest::default()
        };
        let resp = self.client.write(req).await?.into_owned();
        resp.items.first().map(|i| self.item(i)).transpose()
    }

    async fn written(&self, r: Result<Option<Item<K>>, Error>) -> Result<Item<K>, Error> {
        r?.ok_or(Error::Decode)
    }

    /// Writes the item if the address is free.
    ///
    /// # Errors
    ///
    /// [`Error::Exists`] when the address is in use.
    pub async fn create(
        &self,
        tenant: &str,
        id: &str,
        v: &K::Value,
        w: WriteOpts,
    ) -> Result<Item<K>, Error> {
        self.written(self.write(Verb::CREATE, tenant, id, Some(v), 0, w).await)
            .await
    }

    /// Writes the item if it is still at `if_version`.
    ///
    /// # Errors
    ///
    /// [`Error::Version`] when the version has moved.
    pub async fn update(
        &self,
        tenant: &str,
        id: &str,
        v: &K::Value,
        if_version: u64,
        w: WriteOpts,
    ) -> Result<Item<K>, Error> {
        self.written(
            self.write(Verb::UPDATE, tenant, id, Some(v), if_version, w)
                .await,
        )
        .await
    }

    /// Creates the item or sets it to the value; never refused for a version.
    ///
    /// # Errors
    ///
    /// The store's refusal.
    pub async fn apply(
        &self,
        tenant: &str,
        id: &str,
        v: &K::Value,
        w: WriteOpts,
    ) -> Result<Item<K>, Error> {
        self.written(self.write(Verb::APPLY, tenant, id, Some(v), 0, w).await)
            .await
    }

    /// Removes the item, at `if_version` when given.
    ///
    /// # Errors
    ///
    /// [`Error::Version`] when the version has moved.
    pub async fn delete(
        &self,
        tenant: &str,
        id: &str,
        if_version: Option<u64>,
        w: WriteOpts,
    ) -> Result<(), Error> {
        self.write(Verb::DELETE, tenant, id, None, if_version.unwrap_or(0), w)
            .await
            .map(|_| ())
    }
}
