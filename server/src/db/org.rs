//! Organization / organization-unit model, split out as its own domain
//! module.
//!
//! - `organizations`: the top-level tenant/institution.
//! - `organization_units`: an optional hierarchy underneath an
//!   organization (`parent_unit_id` self-references, so "Regional Unit →
//!   Department → Team" nests to arbitrary depth).
//! - `user_memberships`: which organization (and, optionally, which unit
//!   within it) a user belongs to. A user may hold more than one
//!   membership; `primary_organization_id` picks the first one created,
//!   used to stamp new resources (searches, audit events) with an owning
//!   organization at creation time.
//!
//! Nothing in this module ever trusts a client-supplied organization/unit
//! id for authorization — see `permission::can_view_scoped_resource` and
//! its call sites, which always resolve the *actor's own* membership
//! server-side from their authenticated user id.

use sqlx::{FromRow, PgPool, SqlitePool};
use uuid::Uuid;

use super::DbBackend;

pub(super) async fn migrate_pg(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS organizations (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name VARCHAR(200) NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS organization_units (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id UUID NOT NULL REFERENCES organizations(id),
            parent_unit_id UUID REFERENCES organization_units(id),
            name VARCHAR(200) NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_organization_units_organization_id \
         ON organization_units (organization_id)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS user_memberships (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL,
            organization_id UUID NOT NULL REFERENCES organizations(id),
            organization_unit_id UUID REFERENCES organization_units(id),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_user_memberships_user_id ON user_memberships (user_id)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_user_memberships_unique \
         ON user_memberships (user_id, organization_id, organization_unit_id)",
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub(super) async fn migrate_sqlite(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS organizations (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS organization_units (
            id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            parent_unit_id TEXT,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_organization_units_organization_id \
         ON organization_units (organization_id)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS user_memberships (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            organization_id TEXT NOT NULL,
            organization_unit_id TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_user_memberships_user_id ON user_memberships (user_id)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_user_memberships_unique \
         ON user_memberships (user_id, organization_id, organization_unit_id)",
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, FromRow, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationRow {
    pub id: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, FromRow, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationUnitRow {
    pub id: String,
    pub organization_id: String,
    pub parent_unit_id: Option<String>,
    pub name: String,
    pub created_at: String,
}

pub async fn create_organization(
    backend: &DbBackend,
    name: &str,
) -> Result<OrganizationRow, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            sqlx::query_as(
                "INSERT INTO organizations (name) VALUES ($1) \
                 RETURNING id::text, name, created_at::text",
            )
            .bind(name)
            .fetch_one(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            let id = Uuid::new_v4().to_string();
            sqlx::query("INSERT INTO organizations (id, name) VALUES (?1, ?2)")
                .bind(&id)
                .bind(name)
                .execute(pool)
                .await?;
            sqlx::query_as("SELECT id, name, created_at FROM organizations WHERE id = ?1")
                .bind(&id)
                .fetch_one(pool)
                .await
        }
    }
}

pub async fn list_organizations(backend: &DbBackend) -> Result<Vec<OrganizationRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            sqlx::query_as(
                "SELECT id::text, name, created_at::text FROM organizations ORDER BY name",
            )
            .fetch_all(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as("SELECT id, name, created_at FROM organizations ORDER BY name")
                .fetch_all(pool)
                .await
        }
    }
}

pub async fn create_organization_unit(
    backend: &DbBackend,
    organization_id: &str,
    parent_unit_id: Option<&str>,
    name: &str,
) -> Result<Option<OrganizationUnitRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(org_uuid) = Uuid::parse_str(organization_id) else {
                return Ok(None);
            };
            let parent_uuid = parent_unit_id.and_then(|v| Uuid::parse_str(v).ok());
            let row = sqlx::query_as(
                "INSERT INTO organization_units (organization_id, parent_unit_id, name) \
                 VALUES ($1, $2, $3) \
                 RETURNING id::text, organization_id::text, parent_unit_id::text, name, created_at::text",
            )
            .bind(org_uuid)
            .bind(parent_uuid)
            .bind(name)
            .fetch_one(pool)
            .await?;
            Ok(Some(row))
        }
        DbBackend::Sqlite(pool) => {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO organization_units (id, organization_id, parent_unit_id, name) \
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(&id)
            .bind(organization_id)
            .bind(parent_unit_id)
            .bind(name)
            .execute(pool)
            .await?;
            let row = sqlx::query_as(
                "SELECT id, organization_id, parent_unit_id, name, created_at \
                 FROM organization_units WHERE id = ?1",
            )
            .bind(&id)
            .fetch_one(pool)
            .await?;
            Ok(Some(row))
        }
    }
}

pub async fn list_organization_units(
    backend: &DbBackend,
    organization_id: &str,
) -> Result<Vec<OrganizationUnitRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(org_uuid) = Uuid::parse_str(organization_id) else {
                return Ok(Vec::new());
            };
            sqlx::query_as(
                "SELECT id::text, organization_id::text, parent_unit_id::text, name, created_at::text \
                 FROM organization_units WHERE organization_id = $1 ORDER BY name",
            )
            .bind(org_uuid)
            .fetch_all(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as(
                "SELECT id, organization_id, parent_unit_id, name, created_at \
                 FROM organization_units WHERE organization_id = ?1 ORDER BY name",
            )
            .bind(organization_id)
            .fetch_all(pool)
            .await
        }
    }
}

/// Assigns `user_id` to `organization_id` (and, optionally, a specific
/// unit within it). Idempotent — assigning the same membership twice is a
/// silent no-op rather than a uniqueness error, since the caller has no
/// reason to distinguish "already a member" from "just joined".
pub async fn assign_membership(
    backend: &DbBackend,
    user_id: &str,
    organization_id: &str,
    organization_unit_id: Option<&str>,
) -> Result<(), sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let (Ok(user_uuid), Ok(org_uuid)) =
                (Uuid::parse_str(user_id), Uuid::parse_str(organization_id))
            else {
                return Ok(());
            };
            let unit_uuid = organization_unit_id.and_then(|v| Uuid::parse_str(v).ok());
            sqlx::query(
                "INSERT INTO user_memberships (user_id, organization_id, organization_unit_id) \
                 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            )
            .bind(user_uuid)
            .bind(org_uuid)
            .bind(unit_uuid)
            .execute(pool)
            .await?;
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query(
                "INSERT OR IGNORE INTO user_memberships (id, user_id, organization_id, organization_unit_id) \
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(user_id)
            .bind(organization_id)
            .bind(organization_unit_id)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

pub async fn remove_membership(
    backend: &DbBackend,
    user_id: &str,
    organization_id: &str,
) -> Result<(), sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let (Ok(user_uuid), Ok(org_uuid)) =
                (Uuid::parse_str(user_id), Uuid::parse_str(organization_id))
            else {
                return Ok(());
            };
            sqlx::query("DELETE FROM user_memberships WHERE user_id = $1 AND organization_id = $2")
                .bind(user_uuid)
                .bind(org_uuid)
                .execute(pool)
                .await?;
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query("DELETE FROM user_memberships WHERE user_id = ?1 AND organization_id = ?2")
                .bind(user_id)
                .bind(organization_id)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}

/// The organization ids `user_id` belongs to (usually zero or one, but a
/// user may hold memberships in more than one organization). An account
/// with no membership at all returns an empty list — see
/// `permission::can_view_scoped_resource` for what that means for
/// visibility.
pub async fn user_organization_ids(
    backend: &DbBackend,
    user_id: &str,
) -> Result<Vec<String>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(user_uuid) = Uuid::parse_str(user_id) else {
                return Ok(Vec::new());
            };
            sqlx::query_scalar(
                "SELECT organization_id::text FROM user_memberships WHERE user_id = $1",
            )
            .bind(user_uuid)
            .fetch_all(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_scalar("SELECT organization_id FROM user_memberships WHERE user_id = ?1")
                .bind(user_id)
                .fetch_all(pool)
                .await
        }
    }
}

/// The organization a newly-created resource (a search, an audit event)
/// should be stamped with: the first organization `user_id` is a member
/// of, or `None` if they belong to none. Deliberately server-derived —
/// never accepts a client-supplied organization id.
pub async fn primary_organization_id(
    backend: &DbBackend,
    user_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    Ok(user_organization_ids(backend, user_id)
        .await?
        .into_iter()
        .next())
}
