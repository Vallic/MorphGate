use rusqlite::Connection;

use crate::Result;

/// Ordered migrations; index + 1 is the schema version they produce.
const MIGRATIONS: &[&str] = &[
    // v1
    "
    CREATE TABLE account (
        id                      INTEGER PRIMARY KEY CHECK (id = 1),
        kdf_m_kib               INTEGER NOT NULL,
        kdf_t                   INTEGER NOT NULL,
        kdf_p                   INTEGER NOT NULL,
        kdf_salt                BLOB    NOT NULL,
        enc_public_key          BLOB    NOT NULL,
        sign_public_key         BLOB    NOT NULL,
        wrapped_private_keys    BLOB    NOT NULL,
        wrapped_private_keys_rk BLOB    NOT NULL,
        created_at              INTEGER NOT NULL
    );
    CREATE TABLE vaults (
        id                TEXT    PRIMARY KEY,
        key_id            BLOB    NOT NULL,
        wrapped_vault_key BLOB    NOT NULL,
        head_rev          INTEGER NOT NULL DEFAULT 0, -- highest server rev seen (rollback guard)
        created_at        INTEGER NOT NULL
    );
    CREATE TABLE items (
        id         TEXT    PRIMARY KEY,
        vault_id   TEXT    NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
        envelope   BLOB,                        -- NULL for tombstones
        deleted    INTEGER NOT NULL DEFAULT 0,
        rev        INTEGER NOT NULL DEFAULT 0,  -- server rev this copy is based on; 0 = never synced
        dirty      INTEGER NOT NULL DEFAULT 1,  -- local change not yet pushed
        updated_at INTEGER NOT NULL
    );
    CREATE INDEX items_vault ON items (vault_id, deleted);
    ",
    // v2: sync
    "
    ALTER TABLE account ADD COLUMN recovery_proof BLOB;   -- HKDF(RK), sent at registration
    CREATE TABLE sync_state (
        id                INTEGER PRIMARY KEY CHECK (id = 1),
        server_url        TEXT    NOT NULL,
        email             TEXT    NOT NULL,
        account_id        TEXT    NOT NULL,
        device_id         TEXT    NOT NULL,
        device_public_key BLOB    NOT NULL,
        token             BLOB,                -- refresh token, sealed as an envelope
        last_sync_at      INTEGER,
        last_error        TEXT
    );
    ",
    // v3: unlock with the OS keychain, device settings
    "
    CREATE TABLE device_unlock (
        id         INTEGER PRIMARY KEY CHECK (id = 1),
        key_id     TEXT    NOT NULL,  -- names the device key in the OS keychain
        wrapped    BLOB    NOT NULL,  -- account private keys under the device key
        created_at INTEGER NOT NULL
    );
    CREATE TABLE settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    ",
    // v4: shared vaults. Items are keyed by vault too (a server can't make an organization item
    // collide with a personal one), vaults hold key rings, and organizations pin their root.
    "
    CREATE TABLE items_v4 (
        vault_id   TEXT    NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
        id         TEXT    NOT NULL,
        envelope   BLOB,
        deleted    INTEGER NOT NULL DEFAULT 0,
        rev        INTEGER NOT NULL DEFAULT 0,
        dirty      INTEGER NOT NULL DEFAULT 1,
        updated_at INTEGER NOT NULL,
        author_id  TEXT,                         -- who wrote it; NULL = this account
        PRIMARY KEY (vault_id, id)
    );
    INSERT INTO items_v4 (vault_id, id, envelope, deleted, rev, dirty, updated_at)
        SELECT vault_id, id, envelope, deleted, rev, dirty, updated_at FROM items;
    DROP TABLE items;
    ALTER TABLE items_v4 RENAME TO items;
    CREATE INDEX items_vault ON items (vault_id, deleted);
    CREATE INDEX items_id ON items (id);

    ALTER TABLE vaults ADD COLUMN personal INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE vaults ADD COLUMN org_id TEXT;
    ALTER TABLE vaults ADD COLUMN permission TEXT NOT NULL DEFAULT 'manage';
    ALTER TABLE vaults ADD COLUMN name TEXT;
    ALTER TABLE vaults ADD COLUMN rotation_due INTEGER NOT NULL DEFAULT 0;
    UPDATE vaults SET personal = 1 WHERE id = (SELECT id FROM vaults ORDER BY created_at, id LIMIT 1);

    -- Every key generation of a shared vault, sealed to this account.
    CREATE TABLE vault_keys (
        vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
        key_id   BLOB NOT NULL,
        wrapped  BLOB NOT NULL,
        PRIMARY KEY (vault_id, key_id)
    );
    -- Organizations this account belongs to, with the root of trust pinned on joining.
    CREATE TABLE orgs (
        id           TEXT PRIMARY KEY,
        name         TEXT NOT NULL,
        role         TEXT NOT NULL,
        status       TEXT NOT NULL,
        root_account TEXT NOT NULL,
        root_enc     BLOB NOT NULL,
        root_sign    BLOB NOT NULL
    );
    -- Account keys this device verified (through certificates); a change is a hard error.
    CREATE TABLE pinned_keys (
        account_id TEXT PRIMARY KEY,
        enc        BLOB NOT NULL,
        sign       BLOB NOT NULL,
        email      TEXT
    );
    ",
    // v5: an organization's member key directory (its meta says so).
    "ALTER TABLE vaults ADD COLUMN directory INTEGER NOT NULL DEFAULT 0;",
    // v6: blobs (sealed session logs and attachments), uploaded by sync.
    "
    CREATE TABLE blobs (
        vault_id   TEXT NOT NULL,
        hash       TEXT NOT NULL,
        kind       TEXT NOT NULL,
        data       BLOB NOT NULL,
        -- pending (to upload), uploaded, or failed (refused by the server; error says why)
        state      TEXT NOT NULL DEFAULT 'pending',
        error      TEXT,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (vault_id, hash)
    );
    -- Blobs deleted here that the server may still have.
    CREATE TABLE blob_deletes (
        vault_id TEXT NOT NULL,
        hash     TEXT NOT NULL,
        PRIMARY KEY (vault_id, hash)
    );
    CREATE TRIGGER vault_blobs_gone AFTER DELETE ON vaults BEGIN
        DELETE FROM blobs WHERE vault_id = OLD.id;
        DELETE FROM blob_deletes WHERE vault_id = OLD.id;
    END;
    ",
    // v7: where to get the plan a refused blob needs.
    "ALTER TABLE blobs ADD COLUMN upgrade_url TEXT;",
    // v8: item history. `version`: the one in the item's envelope (0: none, from an app before
    // item history). `seen_version`: the one of the last copy the server confirmed, pulled or
    // pushed (0: it had none). NULL in both: not read yet, from before this migration. A
    // deletion made on this device keeps its signed envelope in `envelope`.
    "
    ALTER TABLE items ADD COLUMN version INTEGER;
    ALTER TABLE items ADD COLUMN seen_version INTEGER;
    ",
];

pub(crate) fn migrate(conn: &mut Connection) -> Result<()> {
    let current: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let current = usize::try_from(current).unwrap_or(0);
    if current > MIGRATIONS.len() {
        return Err(crate::Error::NewerVault {
            found: current,
            known: MIGRATIONS.len(),
        });
    }
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(current) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(
            None,
            "user_version",
            i64::try_from(i + 1).expect("few migrations"),
        )?;
        tx.commit()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A vault from before shared vaults: its items keep their vault, the vault becomes the
    /// personal one, and an item id may now exist once per vault.
    #[test]
    fn v3_to_v4_keeps_items() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        for sql in &MIGRATIONS[..3] {
            conn.execute_batch(sql).unwrap();
        }
        conn.pragma_update(None, "user_version", 3).unwrap();
        conn.execute_batch(
            "INSERT INTO vaults (id, key_id, wrapped_vault_key, created_at) VALUES ('V', x'01', x'02', 1);
             INSERT INTO items (id, vault_id, envelope, deleted, rev, dirty, updated_at) VALUES ('I', 'V', x'03', 0, 5, 0, 7);",
        )
        .unwrap();
        migrate(&mut conn).unwrap();
        let (vault, rev, author): (String, i64, Option<String>) = conn
            .query_row(
                "SELECT vault_id, rev, author_id FROM items WHERE id = 'I'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!((vault.as_str(), rev, author), ("V", 5, None));
        let personal: bool = conn
            .query_row("SELECT personal FROM vaults WHERE id = 'V'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(personal);
        conn.execute_batch(
            "INSERT INTO vaults (id, key_id, wrapped_vault_key, created_at) VALUES ('W', x'01', x'02', 2);
             INSERT INTO items (id, vault_id, envelope, updated_at) VALUES ('I', 'W', x'04', 8);",
        )
        .unwrap();
    }

    /// A vault from a newer MorphGate is refused as such (not as corrupt), and left as it was.
    #[test]
    fn newer_schema_is_refused() {
        let mut conn = Connection::open_in_memory().unwrap();
        let newer = i64::try_from(MIGRATIONS.len() + 1).unwrap();
        conn.pragma_update(None, "user_version", newer).unwrap();
        let e = migrate(&mut conn).unwrap_err();
        assert!(
            matches!(e, crate::Error::NewerVault { found, known } if found == MIGRATIONS.len() + 1 && known == MIGRATIONS.len())
        );
        assert!(e.to_string().contains("newer version of MorphGate"));
        let after: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(after, newer);
    }
}
