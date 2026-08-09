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
}
