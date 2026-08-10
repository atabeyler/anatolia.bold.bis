//! RBAC role identifiers. See docs/SECURITY_ARCHITECTURE.md for what each
//! role is permitted to do.

pub const PENDING: &str = "pending";
pub const SYSTEM_ADMIN: &str = "SYSTEM_ADMIN";
pub const SECURITY_ADMIN: &str = "SECURITY_ADMIN";
pub const OPERATOR: &str = "OPERATOR";
pub const REVIEWER: &str = "REVIEWER";
pub const AUDITOR: &str = "AUDITOR";

/// Role granted to a registration once an admin approves it. Least
/// privilege by default — an admin can promote the account afterward.
pub const DEFAULT_APPROVED_ROLE: &str = OPERATOR;

/// The five roles an administrator may assign to an already-approved
/// account. `PENDING` is deliberately excluded — it is only ever set by
/// registration and cleared by `approve_user`/`reject_user`, never by the
/// role-change endpoint.
pub const ASSIGNABLE_ROLES: [&str; 5] = [SYSTEM_ADMIN, SECURITY_ADMIN, OPERATOR, REVIEWER, AUDITOR];

pub fn is_assignable_role(role: &str) -> bool {
    ASSIGNABLE_ROLES.contains(&role)
}
