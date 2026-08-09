//! Registration-approval email notifications via Resend. If
//! `RESEND_API_KEY` is unset, sending is silently skipped (logged as a
//! warning) rather than failing the request that triggered it — see
//! docs/ENVIRONMENT.md.

use serde_json::json;

fn admin_email() -> String {
    std::env::var("ADMIN_EMAIL").unwrap_or_else(|_| "info@boldkimya.com.tr".to_string())
}

fn app_url() -> String {
    std::env::var("APP_URL")
        .or_else(|_| std::env::var("RENDER_EXTERNAL_URL"))
        .unwrap_or_else(|_| "http://localhost:8080".to_string())
}

pub(crate) fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

async fn deliver(to: &str, subject: &str, text: &str, html: Option<&str>) {
    let Ok(api_key) = std::env::var("RESEND_API_KEY") else {
        tracing::warn!(%subject, %to, "RESEND_API_KEY not set — email not sent");
        return;
    };
    let from = std::env::var("RESEND_FROM")
        .unwrap_or_else(|_| "Anatolia B.I.S. <onboarding@resend.dev>".to_string());
    let mut body = json!({
        "from": from,
        "to": [to],
        "subject": subject,
        "text": text,
    });
    if let Some(html) = html {
        body["html"] = json!(html);
    }
    let client = reqwest::Client::new();
    match client
        .post("https://api.resend.com/emails")
        .bearer_auth(&api_key)
        .json(&body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            tracing::info!(%subject, %to, "email sent via Resend");
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(%subject, %to, %status, %body, "Resend send failed");
        }
        Err(err) => {
            tracing::warn!(%subject, %to, error = %err, "Resend request failed");
        }
    }
}

pub struct RegistrationInfo<'a> {
    pub first_name: &'a str,
    pub last_name: &'a str,
    pub email: &'a str,
    pub user_code: &'a str,
    pub approval_token: &'a str,
}

pub async fn send_admin_registration_notification(info: RegistrationInfo<'_>) {
    let review_link = format!("{}/api/v1/admin/review/{}", app_url(), info.approval_token);
    let text = format!(
        "New operator registration request — Anatolia B.I.S.\n\nFull name: {} {}\nEmail: {}\nUser code: {}\n\nReview: {}",
        info.first_name, info.last_name, info.email, info.user_code, review_link
    );
    let html = format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="background:#0b0e14;color:#e4e7ee;font-family:system-ui,sans-serif;padding:32px;max-width:480px;margin:0 auto">
<h2 style="color:#3b82f6;font-size:14px;letter-spacing:.1em;margin-bottom:20px">ANATOLIA B.I.S. — NEW REGISTRATION REQUEST</h2>
<table style="width:100%;border-collapse:collapse;margin-bottom:24px;font-size:14px">
  <tr><td style="color:#8b93a7;padding:6px 0;width:140px">Full name</td><td style="font-weight:bold">{} {}</td></tr>
  <tr><td style="color:#8b93a7;padding:6px 0">Email</td><td>{}</td></tr>
  <tr><td style="color:#8b93a7;padding:6px 0">User code</td><td style="font-weight:bold">{}</td></tr>
</table>
<a href="{}" style="display:inline-block;padding:14px 32px;background:rgba(59,130,246,0.15);border:1px solid rgba(59,130,246,0.6);color:#3b82f6;text-decoration:none;font-size:13px;letter-spacing:.05em">REVIEW &amp; DECIDE</a>
<p style="margin-top:24px;font-size:11px;color:#8b93a7">Link valid for 7 days &middot; Bold Askeri Teknoloji ve Savunma Sanayi A.Ş.</p>
</body></html>"#,
        escape_html(info.first_name),
        escape_html(info.last_name),
        escape_html(info.email),
        escape_html(info.user_code),
        escape_html(&review_link),
    );
    deliver(
        &admin_email(),
        &format!(
            "[Registration request] {} {}",
            info.first_name, info.last_name
        ),
        &text,
        Some(&html),
    )
    .await;
}

pub async fn send_approval_email(first_name: &str, last_name: &str, email: &str, user_code: &str) {
    let text = format!(
        "Dear {first_name} {last_name},\n\nYour Anatolia B.I.S. registration has been approved.\n\nYour user code: {user_code}\nSign in at: {}\n\nBold Askeri Teknoloji ve Savunma Sanayi A.Ş.",
        app_url()
    );
    deliver(
        email,
        "Anatolia B.I.S. — Your registration has been approved",
        &text,
        None,
    )
    .await;
}

/// Sent directly to the account holder — only possible when the account
/// has an email on file. Distinct from `send_password_reset_request`
/// (below), which notifies the admin instead, for accounts without one.
pub async fn send_password_reset_email(
    first_name: &str,
    last_name: &str,
    email: &str,
    reset_link: &str,
) {
    let text = format!(
        "Dear {first_name} {last_name},\n\nA password reset was requested for your Anatolia B.I.S. account. \
         If this was you, set a new password here (valid 1 hour):\n\n{reset_link}\n\n\
         If you did not request this, you can ignore this email — your password will not change.\n\n\
         Bold Askeri Teknoloji ve Savunma Sanayi A.Ş."
    );
    deliver(
        email,
        "Anatolia B.I.S. — Password reset request",
        &text,
        None,
    )
    .await;
}

pub async fn send_password_reset_request(
    first_name: &str,
    last_name: &str,
    user_code: &str,
    email: Option<&str>,
) {
    let text = format!(
        "A user has requested a password reset — Anatolia B.I.S.\n\nFull name: {first_name} {last_name}\nUser code: {user_code}\nEmail on file: {}\n\nSet a new password for this account from the management panel's \"Edit\" action.",
        email.unwrap_or("-")
    );
    deliver(
        &admin_email(),
        &format!("[Password reset request] {first_name} {last_name}"),
        &text,
        None,
    )
    .await;
}

pub async fn send_rejection_email(first_name: &str, last_name: &str, email: &str) {
    let text = format!(
        "Dear {first_name} {last_name},\n\nYour registration request has been rejected. For questions, contact {}.\n\nBold Askeri Teknoloji ve Savunma Sanayi A.Ş.",
        admin_email()
    );
    deliver(
        email,
        "Anatolia B.I.S. — Registration request rejected",
        &text,
        None,
    )
    .await;
}
