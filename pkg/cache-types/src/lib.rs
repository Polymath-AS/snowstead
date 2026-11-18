//! The cache protocols Snowstead serves. Every name derived from one — the
//! value in `cache_protocols`, a token permission, a bandwidth product, an
//! eviction kind — comes from here, so adding a protocol is a compile error
//! at each place that must decide what it means.
use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Declares a fieldless enum together with `ALL`, its variants in declaration
/// order. The list is generated from the declaration, so it cannot miss one.
macro_rules! listed {
    ($(#[$meta:meta])* pub enum $name:ident { $($variant:ident),+ $(,)? }) => {
        $(#[$meta])*
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub const ALL: [Self; [$(Self::$variant),+].len()] = [$(Self::$variant),+];
        }
    };
}

listed! {
    /// What a cache can store. A cache enables any number of these.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum Protocol {
        Nix,
        Go,
        Sccache,
        Bazel,
    }
}

impl Protocol {
    /// The name stored in SQL and sent on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nix => "nix",
            Self::Go => "go",
            Self::Sccache => "sccache",
            Self::Bazel => "bazel",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == value)
    }

    /// The name used in messages to people.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Nix => "Nix",
            Self::Go => "Go",
            Self::Sccache => "sccache",
            Self::Bazel => "Bazel",
        }
    }

    pub const fn permission(self, access: Access) -> Permission {
        Permission {
            protocol: self,
            access,
        }
    }

    pub const fn read(self) -> Permission {
        self.permission(Access::Read)
    }

    pub const fn write(self) -> Permission {
        self.permission(Access::Write)
    }

    /// The compiler cache behind this protocol, when it is one.
    pub const fn compiler(self) -> Option<Compiler> {
        match self {
            Self::Go => Some(Compiler::Go),
            Self::Sccache => Some(Compiler::Sccache),
            Self::Nix | Self::Bazel => None,
        }
    }

    /// Whether each stored entry is a SQL row, as an [`Entry`] names it. Such
    /// entries count toward the org's storage limit, are evicted least
    /// recently used across the org, and have their downloads metered. Bazel
    /// instead keeps a fixed allocation that its own store trims.
    pub const fn tracks_entries(self) -> bool {
        match self {
            Self::Nix | Self::Go | Self::Sccache => true,
            Self::Bazel => false,
        }
    }

    /// The names as a sentence lists them, for messages giving the choices.
    pub fn names() -> String {
        let names = Self::ALL.map(Self::as_str);
        let (last, rest) = names.split_last().expect("protocols exist");
        format!("{}, or {last}", rest.join(", "))
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct UnknownProtocol;

impl fmt::Display for UnknownProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "expected {}", Protocol::names())
    }
}

impl std::error::Error for UnknownProtocol {}

impl FromStr for Protocol {
    type Err = UnknownProtocol;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or(UnknownProtocol)
    }
}

listed! {
    /// The two protocols that store compiler artifacts under an action key and
    /// share one implementation, retention, and generation scheme.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Compiler {
        Go,
        Sccache,
    }
}

impl Compiler {
    pub const fn protocol(self) -> Protocol {
        match self {
            Self::Go => Protocol::Go,
            Self::Sccache => Protocol::Sccache,
        }
    }

    pub const fn as_str(self) -> &'static str {
        self.protocol().as_str()
    }
}

impl From<Compiler> for Protocol {
    fn from(compiler: Compiler) -> Self {
        compiler.protocol()
    }
}

listed! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Access {
        Read,
        Write,
    }
}

impl Access {
    pub const fn of(write: bool) -> Self {
        if write { Self::Write } else { Self::Read }
    }
}

/// What an API token may do with one protocol, as stored in
/// `token_permissions`. Nix keeps its original names, `pull` and `push`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Permission {
    pub protocol: Protocol,
    pub access: Access,
}

impl Permission {
    pub const PULL: Self = Protocol::Nix.permission(Access::Read);
    pub const PUSH: Self = Protocol::Nix.permission(Access::Write);

    /// Every protocol's read then write, in protocol order.
    pub const ALL: [Self; Protocol::ALL.len() * Access::ALL.len()] = {
        let mut all = [Self::PULL; Protocol::ALL.len() * Access::ALL.len()];
        let mut i = 0;
        while i < all.len() {
            all[i] =
                Protocol::ALL[i / Access::ALL.len()].permission(Access::ALL[i % Access::ALL.len()]);
            i += 1;
        }
        all
    };

    pub const fn as_str(self) -> &'static str {
        match (self.protocol, self.access) {
            (Protocol::Nix, Access::Read) => "pull",
            (Protocol::Nix, Access::Write) => "push",
            (Protocol::Go, Access::Read) => "go:read",
            (Protocol::Go, Access::Write) => "go:write",
            (Protocol::Sccache, Access::Read) => "sccache:read",
            (Protocol::Sccache, Access::Write) => "sccache:write",
            (Protocol::Bazel, Access::Read) => "bazel:read",
            (Protocol::Bazel, Access::Write) => "bazel:write",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == value)
    }

    /// The quoted names, for messages listing the choices.
    pub fn names() -> String {
        let quoted = Self::ALL.map(|p| format!("\"{p}\""));
        let (last, rest) = quoted.split_last().expect("permissions exist");
        format!("{}, or {last}", rest.join(", "))
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Permission {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Permission {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "invalid permission: {value}, expected {}",
                Self::names()
            ))
        })
    }
}

/// One stored entry of a protocol that [tracks them](Protocol::tracks_entries),
/// identified the way that protocol's table keys it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Entry {
    /// `published_paths.id`
    Nix(i64),
    /// `go_entries.id`
    Go(String),
    /// `sccache_entries.id`
    Sccache(String),
}

impl Entry {
    /// Read the `(kind, id)` text pair SQL reports an entry as.
    pub fn parse(kind: &str, id: &str) -> Option<Self> {
        match Protocol::parse(kind)? {
            Protocol::Nix => id.parse().ok().map(Self::Nix),
            Protocol::Go => Some(Self::Go(id.to_owned())),
            Protocol::Sccache => Some(Self::Sccache(id.to_owned())),
            Protocol::Bazel => None,
        }
    }

    pub fn compiler(compiler: Compiler, id: String) -> Self {
        match compiler {
            Compiler::Go => Self::Go(id),
            Compiler::Sccache => Self::Sccache(id),
        }
    }

    pub const fn protocol(&self) -> Protocol {
        match self {
            Self::Nix(_) => Protocol::Nix,
            Self::Go(_) => Protocol::Go,
            Self::Sccache(_) => Protocol::Sccache,
        }
    }

    pub const fn nix_id(&self) -> Option<i64> {
        match self {
            Self::Nix(id) => Some(*id),
            Self::Go(_) | Self::Sccache(_) => None,
        }
    }

    /// This entry's ID when it belongs to `compiler`.
    pub fn compiler_id(&self, compiler: Compiler) -> Option<&str> {
        match (self, compiler) {
            (Self::Go(id), Compiler::Go) | (Self::Sccache(id), Compiler::Sccache) => Some(id),
            (Self::Nix(_), Compiler::Go | Compiler::Sccache)
            | (Self::Go(_), Compiler::Sccache)
            | (Self::Sccache(_), Compiler::Go) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_names_round_trip_in_text_and_json() {
        for protocol in Protocol::ALL {
            assert_eq!(Protocol::parse(protocol.as_str()), Some(protocol));
            assert_eq!(protocol.to_string().parse(), Ok(protocol));
            let json = serde_json::to_value(protocol).unwrap();
            assert_eq!(json, protocol.as_str());
            assert_eq!(serde_json::from_value::<Protocol>(json).unwrap(), protocol);
        }
        assert_eq!(Protocol::names(), "nix, go, sccache, or bazel");
        assert_eq!(Protocol::parse("Nix"), None);
        assert_eq!("docker".parse::<Protocol>(), Err(UnknownProtocol));
    }

    #[test]
    fn permissions_keep_their_stored_names() {
        assert_eq!(
            Permission::ALL.map(Permission::as_str),
            [
                "pull",
                "push",
                "go:read",
                "go:write",
                "sccache:read",
                "sccache:write",
                "bazel:read",
                "bazel:write"
            ]
        );
        for permission in Permission::ALL {
            assert_eq!(Permission::parse(permission.as_str()), Some(permission));
            let json = serde_json::to_value(permission).unwrap();
            assert_eq!(
                serde_json::from_value::<Permission>(json).unwrap(),
                permission
            );
        }
        assert_eq!(Permission::parse("nix:read"), None);
        assert!(serde_json::from_str::<Permission>("\"admin\"").is_err());
        assert_eq!(
            Permission::names(),
            r#""pull", "push", "go:read", "go:write", "sccache:read", "sccache:write", "bazel:read", or "bazel:write""#
        );
    }

    #[test]
    fn compilers_are_exactly_the_protocols_that_name_one() {
        for protocol in Protocol::ALL {
            assert_eq!(
                protocol.compiler().map(Compiler::protocol),
                Compiler::ALL
                    .map(Compiler::protocol)
                    .contains(&protocol)
                    .then_some(protocol)
            );
        }
    }

    #[test]
    fn entries_exist_only_for_protocols_that_track_them() {
        for protocol in Protocol::ALL {
            let entry = Entry::parse(protocol.as_str(), "7");
            assert_eq!(entry.is_some(), protocol.tracks_entries());
            assert!(entry.is_none_or(|e| e.protocol() == protocol));
        }
        assert_eq!(Entry::parse("nix", "7"), Some(Entry::Nix(7)));
        assert_eq!(Entry::parse("nix", "seven"), None);
        let go = Entry::compiler(Compiler::Go, "a".into());
        assert_eq!(go, Entry::Go("a".into()));
        assert_eq!(go.compiler_id(Compiler::Go), Some("a"));
        assert_eq!(go.compiler_id(Compiler::Sccache), None);
        assert_eq!(go.nix_id(), None);
    }
}
