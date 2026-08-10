//! Centralized authorization policy.
//!
//! Every "which roles may do X" decision lives here as a single named
//! function instead of being re-declared as a role list next to each
//! handler. Handlers call `auth::require_role` with one of these functions
//! rather than hard-coding an allowed-role slice, so a permission has
//! exactly one definition and cannot silently drift between call sites.

use crate::roles;

/// May submit a new biometric search.
pub fn can_create_search(role: &str) -> bool {
    matches!(
        role,
        roles::OPERATOR | roles::REVIEWER | roles::SECURITY_ADMIN | roles::SYSTEM_ADMIN
    )
}

/// May see search/candidate records: everyone who may create a search,
/// plus AUDITOR — whose entire purpose is read-only oversight of exactly
/// this data, per docs/SECURITY_ARCHITECTURE.md.
pub fn can_view_search(role: &str) -> bool {
    can_create_search(role) || role == roles::AUDITOR
}

/// May record a review decision (confirm/reject/inconclusive) on a candidate.
pub fn can_review_candidate(role: &str) -> bool {
    matches!(
        role,
        roles::REVIEWER | roles::SECURITY_ADMIN | roles::SYSTEM_ADMIN
    )
}

/// May read the append-only audit trail.
pub fn can_view_audit_log(role: &str) -> bool {
    matches!(
        role,
        roles::AUDITOR | roles::SECURITY_ADMIN | roles::SYSTEM_ADMIN
    )
}

/// May administer user accounts (create/approve/ban/delete/list).
pub fn can_administer_users(role: &str) -> bool {
    matches!(role, roles::SYSTEM_ADMIN | roles::SECURITY_ADMIN)
}

/// May enroll/manage candidate records and their biometric reference
/// templates: create a candidate, upload a reference photo, or revoke a
/// template. Same operational roles as `can_create_search` — enrollment is
/// a day-to-day operational task, not a system-administration one.
pub fn can_manage_candidates(role: &str) -> bool {
    matches!(
        role,
        roles::OPERATOR | roles::SECURITY_ADMIN | roles::SYSTEM_ADMIN
    )
}

/// May manage the organization/unit structure itself (create
/// organizations/units, assign/remove memberships) — deliberately
/// narrower than `can_administer_users`: this is a cross-organization
/// concern, so only the one truly global role may touch it. A
/// `SECURITY_ADMIN` scoped to one organization must not be able to spin
/// up a sibling organization or move users into/out of others.
pub fn can_manage_organizations(role: &str) -> bool {
    role == roles::SYSTEM_ADMIN
}

/// Object-level authorization: whether an actor with `role`
/// may view a resource owned by `resource_org_id`, given the
/// organizations the actor actually belongs to (`actor_org_ids` —
/// resolved server-side from `user_memberships`, never taken from the
/// client). This is layered *on top of* the ordinary role check
/// (`can_view_search` etc.), not a replacement for it — callers must
/// still check the role first.
///
/// `SYSTEM_ADMIN` is the one explicit global exception (per the
/// instructions: holding a global role must not by itself grant access
/// to every organization's records — only an explicitly-designated role
/// like `SYSTEM_ADMIN` may bypass scoping). A resource with no owning
/// organization (`resource_org_id: None` — legacy data predating the org
/// model, or a deployment that never configured one) is visible to
/// anyone who already passed the role check, so introducing organizations
/// doesn't retroactively hide anything that existed before it.
pub fn can_view_scoped_resource(
    role: &str,
    actor_org_ids: &[String],
    resource_org_id: Option<&str>,
) -> bool {
    if role == roles::SYSTEM_ADMIN {
        return true;
    }
    match resource_org_id {
        None => true,
        Some(id) => actor_org_ids.iter().any(|actor_id| actor_id == id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_search_excludes_auditor_and_pending() {
        assert!(can_create_search(roles::OPERATOR));
        assert!(can_create_search(roles::REVIEWER));
        assert!(can_create_search(roles::SECURITY_ADMIN));
        assert!(can_create_search(roles::SYSTEM_ADMIN));
        assert!(!can_create_search(roles::AUDITOR));
        assert!(!can_create_search(roles::PENDING));
    }

    #[test]
    fn view_search_includes_auditor() {
        assert!(can_view_search(roles::AUDITOR));
        assert!(can_view_search(roles::OPERATOR));
        assert!(!can_view_search(roles::PENDING));
    }

    #[test]
    fn review_candidate_excludes_operator_and_auditor() {
        assert!(can_review_candidate(roles::REVIEWER));
        assert!(can_review_candidate(roles::SECURITY_ADMIN));
        assert!(can_review_candidate(roles::SYSTEM_ADMIN));
        assert!(!can_review_candidate(roles::OPERATOR));
        assert!(!can_review_candidate(roles::AUDITOR));
    }

    #[test]
    fn view_audit_log_excludes_operational_roles() {
        assert!(can_view_audit_log(roles::AUDITOR));
        assert!(can_view_audit_log(roles::SECURITY_ADMIN));
        assert!(can_view_audit_log(roles::SYSTEM_ADMIN));
        assert!(!can_view_audit_log(roles::OPERATOR));
        assert!(!can_view_audit_log(roles::REVIEWER));
    }

    #[test]
    fn administer_users_is_admin_only() {
        assert!(can_administer_users(roles::SYSTEM_ADMIN));
        assert!(can_administer_users(roles::SECURITY_ADMIN));
        assert!(!can_administer_users(roles::OPERATOR));
        assert!(!can_administer_users(roles::REVIEWER));
        assert!(!can_administer_users(roles::AUDITOR));
    }

    #[test]
    fn manage_organizations_is_system_admin_only() {
        assert!(can_manage_organizations(roles::SYSTEM_ADMIN));
        assert!(!can_manage_organizations(roles::SECURITY_ADMIN));
        assert!(!can_manage_organizations(roles::AUDITOR));
    }

    #[test]
    fn system_admin_bypasses_org_scoping_entirely() {
        assert!(can_view_scoped_resource(
            roles::SYSTEM_ADMIN,
            &[],
            Some("org-b")
        ));
    }

    #[test]
    fn security_admin_is_not_exempt_from_org_scoping() {
        let actor_orgs = vec!["org-a".to_string()];
        assert!(can_view_scoped_resource(
            roles::SECURITY_ADMIN,
            &actor_orgs,
            Some("org-a")
        ));
        assert!(!can_view_scoped_resource(
            roles::SECURITY_ADMIN,
            &actor_orgs,
            Some("org-b")
        ));
    }

    #[test]
    fn resource_with_no_organization_is_visible_to_anyone_past_the_role_check() {
        assert!(can_view_scoped_resource(roles::AUDITOR, &[], None));
    }

    #[test]
    fn actor_with_no_membership_cannot_see_an_org_scoped_resource() {
        assert!(!can_view_scoped_resource(
            roles::REVIEWER,
            &[],
            Some("org-a")
        ));
    }
}
