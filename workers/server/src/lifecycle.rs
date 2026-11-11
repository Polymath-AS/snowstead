//! The service's persisted state machines, in one place.
//!
//! PostgreSQL stores these as text, guarded by the CHECK constraints in
//! `migrations/0014_lifecycle_constraints.sql`. Rust branches and binds only
//! through these enums. SQL inside `sqlx::query!` keeps its literals, since
//! the macro needs the statement text: `tests::constraints_match_enums` fails
//! when an enum and its constraint drift apart.
use sqlx::{
    Decode, Encode, Postgres, Type,
    encode::IsNull,
    error::BoxDynError,
    postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef},
};

/// A closed set of text values: `ALL`, `as_str`, `parse`, and text-column
/// encoding. Decoding a value outside the set is an error, never a silent
/// fallback into some other state.
macro_rules! text_states {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        impl $name {
            /// Every state, for the drift test against the migration.
            #[cfg(test)]
            pub(crate) const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub(crate) const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }

            pub(crate) fn parse(value: &str) -> Option<Self> {
                match value {
                    $($text => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }

        // JSON carries the same text the column does.
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl Type<Postgres> for $name {
            fn type_info() -> PgTypeInfo {
                <&str as Type<Postgres>>::type_info()
            }
            fn compatible(ty: &PgTypeInfo) -> bool {
                <&str as Type<Postgres>>::compatible(ty)
            }
        }

        impl<'r> Decode<'r, Postgres> for $name {
            fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
                let text = <&str as Decode<Postgres>>::decode(value)?;
                Self::parse(text)
                    .ok_or_else(|| format!("unknown {} {text:?}", stringify!($name)).into())
            }
        }

        impl Encode<'_, Postgres> for $name {
            fn encode_by_ref(&self, buffer: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
                <&str as Encode<Postgres>>::encode(self.as_str(), buffer)
            }
        }
    };
}

/// `upload_sessions.status`.
///
/// ```text
/// streaming ──seal──▶ finalizing ──publish──▶ completed
///     │                   │
///     └──────┬────────────┘
///            ├─▶ aborted   (client abort, path withdrawal, cache deletion)
///            └─▶ expired   (maintenance, after `expires_at`)
/// ```
///
/// - `streaming`: written by `uploads::create`. Parts may be reserved and
///   received.
/// - `streaming → finalizing`: `uploads::seal`, once the receipt matches every
///   stored part. The file hash is immutable from here on; the same receipt
///   may be replayed, and assembly, verification, and publication may be
///   retried until the session expires.
/// - `finalizing → completed`: `uploads::publish`, in the transaction which
///   inserts the published path. Terminal: its `publication_result` is
///   replayed and never changed, not even by withdrawal of the path.
/// - `streaming | finalizing → aborted`: `uploads::abort` (the client), the
///   `invalidate_deleted_publications` trigger and `management_policy` path
///   withdrawal (eviction, retention, deletion), and cache deletion. Abort is
///   idempotent.
/// - any state but `completed` → `expired`: `maintenance::expire_session`,
///   just before the expired row is removed.
/// - `pending`, `uploading`, and `completing` were written only by the retired
///   TypeScript service. Rust never writes them. Such rows can remain: an
///   unfinished canonical multipart upload is never reclaimed automatically.
///
/// Every transition out of `streaming` or `finalizing` is made under the
/// `org:<id>` advisory lock, which the publication transaction also holds and
/// under which it re-reads the status. Publication and abort cannot both win.
///
/// Two "active" predicates exist on purpose; they are not the same question:
/// - Quota (`uploads::create`, `uploads::reserve_tx`): `expires_at > NOW() AND
///   status IN ('streaming', 'finalizing')`. Only a live lease counts against
///   the org's session and staging budgets.
/// - Protection and reporting (`capacity`, `management`, `management_policy`):
///   `status = 'finalizing' OR (status IN ('pending', 'uploading', 'streaming')
///   AND expires_at > NOW())`. A sealed session keeps its path safe from
///   eviction even after its lease expires, because its publication may still
///   be in flight; the legacy states are included for rows created before
///   cutover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UploadStatus {
    LegacyPending,
    LegacyUploading,
    LegacyCompleting,
    Streaming,
    Finalizing,
    Completed,
    Aborted,
    Expired,
}

text_states!(UploadStatus {
    LegacyPending => "pending",
    LegacyUploading => "uploading",
    LegacyCompleting => "completing",
    Streaming => "streaming",
    Finalizing => "finalizing",
    Completed => "completed",
    Aborted => "aborted",
    Expired => "expired",
});

/// `nar_installations.phase`: a publication attempt's claim on one immutable
/// destination key. A row is deleted, not moved to a terminal phase, when the
/// attempt ends.
///
/// - `preparing`: the column default, inserted by `uploads::allocate_candidate`
///   (and by `management`'s narinfo backfill) before the copy. Only a
///   `preparing`, unexpired row can be adopted.
/// - `preparing`: also holds an execution lease (`lease_expires_at`) while one
///   worker copies and verifies; another may take over once the lease lapses.
/// - `preparing → ready`: the verified candidate is in place and waits for
///   publication, which may be a later request or a push-job worker.
/// - `ready → (deleted)`: publication adopts it in its transaction, or retires
///   it into `object_cleanup` when the attempt fails; `uploads::abort` and
///   `maintenance::expire_installations` retire a `preparing` or `ready` row
///   the same way for an aborted or expired session.
/// - `preparing → revoked`: path withdrawal (`management_policy` and the
///   `invalidate_deleted_publications` trigger). A revoked row can never be
///   adopted; maintenance retires it.
/// - `legacy-unresolved`: written by cache deletion for an unfinished legacy
///   canonical multipart upload. It has no expiry and is never reclaimed
///   automatically, because the provider may still complete it.
/// - `copying` was written only by the retired TypeScript service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InstallationPhase {
    Preparing,
    Ready,
    LegacyCopying,
    Revoked,
    LegacyUnresolved,
}

text_states!(InstallationPhase {
    Preparing => "preparing",
    Ready => "ready",
    LegacyCopying => "copying",
    Revoked => "revoked",
    LegacyUnresolved => "legacy-unresolved",
});

/// `cache_signing_keys.state`.
///
/// ```text
/// staged ──activate──▶ active ──next activation──▶ retired
/// ```
///
/// - `staged`: the column default, written by `signing_management::create_key`.
///   Not signing yet.
/// - `staged → active`: `signing_management::activate_key`, by an org's owner
///   or admin. A new cache's initial managed key is inserted `active` by
///   `management::create_cache`.
/// - `active → retired`: the same activation transaction retires the previous
///   active key (and drops its sealed secret) before activating its target. A
///   key the cache used before it had history rows is inserted `retired`.
/// - `retired` is terminal: the public key is kept for trust, and can be
///   neither reactivated nor deleted.
///
/// Activation holds the cache row `FOR UPDATE` and retires before it
/// activates, so a cache never has two `active` rows, even mid-transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SigningKeyState {
    Staged,
    Active,
    Retired,
}

text_states!(SigningKeyState {
    Staged => "staged",
    Active => "active",
    Retired => "retired",
});

/// `pins.keep_kind`, with `pins.keep_value`: how long a pin protects the
/// revisions it has superseded. Not a state machine: `management_policy`'s
/// `put_pin` replaces the whole policy at once.
///
/// - `forever`: every revision stays pinned; `keep_value` is NULL.
/// - `revisions`: the newest `keep_value` revisions stay pinned.
/// - `days`: a revision stays pinned for `keep_value` days after it is
///   superseded.
///
/// The current revision is always pinned. `keep_value` is 1 to 10000 for the
/// counted kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PinKeep {
    Forever,
    Revisions,
    Days,
}

text_states!(PinKeep {
    Forever => "forever",
    Revisions => "revisions",
    Days => "days",
});

#[cfg(test)]
mod tests {
    use super::*;

    const CONSTRAINTS: &str = include_str!("../migrations/0014_lifecycle_constraints.sql");

    /// The quoted values of `<column> IN (...)` inside the named constraint.
    fn allowed(constraint: &str, column: &str) -> Vec<String> {
        let start = CONSTRAINTS
            .find(&format!("ADD CONSTRAINT {constraint} "))
            .unwrap_or_else(|| panic!("no constraint {constraint}"));
        let statement = &CONSTRAINTS[start..];
        let statement = &statement[..statement.find(';').expect("statement terminator")];
        let list = statement
            .split_once(&format!("{column} IN ("))
            .unwrap_or_else(|| panic!("{constraint} does not list {column}"))
            .1;
        let list = &list[..list.find(')').expect("list terminator")];
        let mut values: Vec<String> = list
            .split(',')
            .map(|value| value.trim().trim_matches('\'').to_owned())
            .collect();
        values.sort();
        values
    }

    fn sorted(values: impl Iterator<Item = &'static str>) -> Vec<String> {
        let mut values: Vec<String> = values.map(str::to_owned).collect();
        values.sort();
        values
    }

    #[test]
    fn constraints_match_enums() {
        assert_eq!(
            allowed("upload_sessions_status_valid", "status"),
            sorted(UploadStatus::ALL.iter().map(|s| s.as_str()))
        );
        assert_eq!(
            allowed("nar_installations_phase_valid", "phase"),
            sorted(InstallationPhase::ALL.iter().map(|s| s.as_str()))
        );
        assert_eq!(
            allowed("cache_signing_keys_state_valid", "state"),
            sorted(SigningKeyState::ALL.iter().map(|s| s.as_str()))
        );
        // `forever` stands alone; the counted kinds share the second list.
        let mut kinds = vec![PinKeep::Forever.as_str().to_owned()];
        kinds.extend(allowed("pins_keep_valid", "keep_kind"));
        kinds.sort();
        assert_eq!(kinds, sorted(PinKeep::ALL.iter().map(|s| s.as_str())));
        assert!(CONSTRAINTS.contains("keep_kind = 'forever' AND keep_value IS NULL"));
    }

    #[test]
    fn text_round_trips_and_rejects_unknown_values() {
        for status in UploadStatus::ALL {
            assert_eq!(UploadStatus::parse(status.as_str()), Some(*status));
        }
        for phase in InstallationPhase::ALL {
            assert_eq!(InstallationPhase::parse(phase.as_str()), Some(*phase));
        }
        for state in SigningKeyState::ALL {
            assert_eq!(SigningKeyState::parse(state.as_str()), Some(*state));
        }
        for keep in PinKeep::ALL {
            assert_eq!(PinKeep::parse(keep.as_str()), Some(*keep));
        }
        assert_eq!(UploadStatus::parse("Streaming"), None);
        assert_eq!(InstallationPhase::parse(""), None);
    }
}
