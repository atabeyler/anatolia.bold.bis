# Kapsamlı Güvenlik / Mimari Sağlamlaştırma Kontrol Listesi

Bu dosya, projenin sahibi tarafından verilen orijinal 75 maddelik (+ OSINT eki)
güvenlik ve kurumsallaştırma talimatının tam listesidir. Her madde `[x]`
(tamamlandı), `[~]` (kısmen tamamlandı — notta neyin eksik olduğu yazılı) veya
`[ ]` (yapılmadı) olarak işaretlidir.

**Bu dosya oturumlar arası tek gerçek kaynak (source of truth) olarak
kullanılmalıdır.** Yeni bir çalışma oturumuna başlarken önce bu dosya
okunmalı, iş bittikçe ilgili madde işaretlenip commit edilmelidir. Genel
ilerleme özeti için `docs/ROADMAP.md`'ye de bakılabilir (Phase numaralandırması
kullanır); milestone harfleri (A, B, C, ...) ile Phase numaraları arasındaki
eşleşme bu dosyanın sonunda listelidir.

---

## P0 — Kritik Güvenlik Eksikleri

1. [x] Production JWT fallback secret'larını kaldır — `Config::from_env`
   production'da `JWT_SECRET`/`JWT_REFRESH_SECRET`/`APPROVAL_TOKEN_SECRET`
   eksik veya <32 byte ise startup'ta panic ediyor. (Milestone A)
2. [x] Gerçek session yönetimi ekle — `sessions` tablosu, refresh-token
   rotation, reuse/theft detection, `logout`/`logout-all`, ban anında
   session revoke. (Milestone A)
3. [x] Approval token'ı refresh secret'tan ayır — ayrı
   `APPROVAL_TOKEN_SECRET`, ayrı `approval_tokens` tablosu, tek kullanımlık.
   (Milestone A)
4. [x] CORS method eksiğini düzelt — `PATCH` eklendi. (Milestone A)
5. [x] Content-Security-Policy ekle — production'da CSP + Permissions-Policy.
   (Milestone A)
6. [x] HSTS environment kontrolü — yalnızca production'da gönderiliyor.
   (Milestone A)

## P0 — Audit Log Sistemi

- [x] Append-only `audit_events` tablosu, merkezi `AuditService`/
  `AuditRecorder`, `GET /api/v1/audit` (filtreli+paginated), frontend Audit
  Logs ekranı, 6 dilde çeviri. (Milestone B)
- [ ] Organization/unit bazlı audit görünürlük kapsamı (organization modeli
  henüz yok).

## P1 — Auth ve Hesap Güvenliği

7. [~] Login rate limiting'i geliştir — per-account + per-IP + burst
   pencereleri eklendi (Milestone A). Ayrı bir **rate limiter provider
   interface'i** (ileride Redis/DB-backed limiter takılabilecek soyutlama)
   **oluşturulmadı** — hâlâ tek in-memory `RateLimiter` var.
8. [x] User enumeration açığını kapat — `registrationTrackingToken` +
   `registration-status/:token`. (Milestone A)
9. [x] Password reset akışını tamamla — e-postası kayıtlı hesaplar için gerçek
   self-service `reset-password` eklendi: tek kullanımlık, hash'li saklanan,
   1 saat TTL'li token (`approval_tokens` tablosu, `purpose =
   "password_reset"`), sıfırlama linki doğrudan hesap sahibine e-postayla
   gönderiliyor, token kullanılmadan önce atomik olarak tüketiliyor, başarılı
   sıfırlamada hesabın tüm oturumları iptal ediliyor ve
   `AUTH_PASSWORD_RESET_COMPLETED` audit kaydı düşülüyor. E-postası olmayan
   hesaplar için eski admin-bildirim akışı korunuyor. Backend
   (`server/tests/password_reset.rs`, 3 test) ve frontend
   (`ResetPasswordPage`, `App.tsx` `resetToken` query-param yönlendirmesi, 6
   dilde i18n) tamamlandı ve doğrulandı.
10. [ ] MFA altyapısı ekle — TOTP altyapısı **yapılmadı**.
11. [~] Role değişiminde JWT stale yetki sorunu — ban anında session revoke
    var (Milestone A). Role **downgrade** anında session revoke / auth_version
    increment **yapılmadı**.

## P1 — Authorization ve Organizasyon

12. [ ] Organization / Unit modeli ekle — **bilinçli olarak ertelendi**, ayrı
    büyük mimari iş (docs/ROADMAP.md'de not edildi).
13. [ ] Merkezi permission policy (`can_create_search` vb. fonksiyonlar) —
    **yapılmadı**, rol kontrolleri hâlâ handler'larda dağınık
    (`require_role(..., ROLES)` çağrıları).

## P1 — Image Upload

14. [x] Gerçek image validation — magic-byte + gerçek decode, JPEG/PNG/WEBP,
    10MB limit, boyut/piksel limitleri, decompression-bomb koruması.
    (Milestone C)
15. [ ] EXIF metadata temizle — **yapılmadı**.
16. [x] Latitude/longitude validation — aralık + eşleşen çift zorunluluğu.
    (Milestone C)
17. [ ] Face quality pipeline (`FaceDetector`/`FaceAligner`/
    `FaceQualityEvaluator`/`EmbeddingProvider` interface'leri) — **yapılmadı**.
18. [ ] Raw image retention (config + retention job) — **yapılmadı**.

## P1 — Gerçek Biyometrik Motor

19. [x] Mevcut `BiometricProvider` abstraction'ı korundu (zaten vardı).
    `BIOMETRIC_PROVIDER` config + `ALLOW_MOCK_BIOMETRICS` production guard'ı
    eklendi: production'da mock provider'ın kullanılabilmesi için
    `ALLOW_MOCK_BIOMETRICS=true` açıkça set edilmesi gerekiyor, aksi halde
    startup fail ediyor; `mock` dışında bir `BIOMETRIC_PROVIDER` değeri her
    ortamda hard failure (henüz başka bir implementasyon yok). (Milestone D,
    kısmi)
20. [ ] Production face provider (ONNX Runtime / `ort`) — **yapılmadı**.
    Gerçek bir model kaynağı/lisansı gerektiriyor; repo sahibinin kararı
    bekleniyor (hangi model, nereden temin edilecek).
21. [ ] Embedding storage (`biometric_templates` tablosu, pgvector vb.) —
    **yapılmadı**.
22. [ ] Enrollment pipeline (çoklu reference image, kalite kontrolü) —
    **yapılmadı**.
23. [ ] Duplicate candidate control — **yapılmadı**.
24. [x] Score semantics (probability dili yasak, "Similarity Score" olarak
    gösteriliyor) — zaten mevcuttu, korundu.
25. [ ] Threshold calibration / evaluation tool (FAR/FRR/ROC/Top-K) —
    **yapılmadı**.
26. [ ] Biyometrik test koşulları (lighting/pose/resolution benchmark) —
    **yapılmadı**.

## P1 — Search Consistency

27. [x] Search işlemini transactional yap — `create_search_with_candidates`,
    BEGIN/COMMIT/ROLLBACK, kritik insert hatası artık sessizce yutulmuyor.
    (Milestone C)
28. [x] Search status state machine — `queued`/`processing`/`completed`/
    `failed` + `started_at`/`completed_at`/`failure_code`/
    `failure_message_key`. `cancelled` henüz erişilebilir değil (async search
    milestone'una bağlı). (Milestone C)
29. [x] TOP_K config — `SEARCH_DEFAULT_TOP_K`/`SEARCH_MAX_TOP_K`, requested
    top-k search kaydında saklanıyor. (Milestone C)
30. [~] Pagination — search history (`GET /api/v1/search`) ve audit logs
    paginated (Milestone B/C). **Users listesi** (`GET /api/v1/admin/users`)
    bilinçli olarak ertelendi (küçük/sınırlı veri seti). Tek bir search'ün
    candidate listesi zaten top-k ile sınırlı, ayrı pagination gerekmedi.

## P1 — Data Privacy

31. [ ] Data domain ayrımı (Identity/Biometric/Search/Audit domain'lerinin
    repository/service katmanlarında ayrılması) — **yapılmadı**.
32. [ ] National ID hassasiyeti (encrypted/lookup-hash, maskeleme, response'a
    gereksiz koymama) — **yapılmadı**, national_id hâlâ plaintext saklanıyor.
33. [~] Database index/constraint — `sessions`, `audit_events`,
    `verification_events` için indexler eklendi (Milestone A/B/C).
    `search_candidates` üzerinde `unique(search_id, candidate_id)` ve
    `searches.created_at/case_reference/requested_by` indexleri **eklenmedi**.
34. [ ] Soft delete (users için `disabled_at`/`deleted_at`) — **yapılmadı**,
    `delete_user` hâlâ hard delete.

## P1 — Review Sistemi

35. [x] Immutable review history — `verification_events` tablosu, her
    confirm/reject yeni bir event olarak ekleniyor,
    `GET /api/v1/search/{id}/candidates/{id}/history`. (Milestone C)
36. [~] Review decisions — sadece `confirmed`/`rejected` var. `inconclusive`
    ve `needs_second_review` decision tipleri **eklenmedi**.
37. [ ] Second review / four-eyes policy (`REQUIRE_SECOND_REVIEW`) —
    **yapılmadı**.

## P1 — API Kalitesi

38. [x] Error format (`{code, messageKey, requestId, details}`) — zaten
    mevcuttu, korundu ve tüm yeni endpoint'lerde kullanıldı.
39. [~] Request ID — `x-request-id` her response'ta dönüyor, audit log'a
    yazılıyor. Client'ın gönderdiği request id için **length/charset
    validation eklenmedi** (kör kabul ediliyor).
40. [ ] OpenAPI (machine-readable spec, CI'da docs drift kontrolü) —
    **yapılmadı**, API.md hâlâ elle yazılan markdown.

## P2 — Admin

41. [~] Admin seed — rate-limited + constant-time token comparison zaten
    vardı. `BOOTSTRAP_ENABLED=false` production default'u ve ilk admin
    sonrası seed endpoint'ini disable etme **yapılmadı**.
42. [~] Sensitive admin confirmation — silme işleminde frontend confirm
    modal'ı zaten vardı. Ban/role-change için confirm modal'ları
    **doğrulanmadı/eklenmedi**.
43. [ ] Son SYSTEM_ADMIN koruması (ban/delete/downgrade engeli + test) —
    **yapılmadı**.

## P2 — Frontend

44. [ ] Global CSS'i parçala (`styles/tokens.css` vb.) — **yapılmadı**,
    `index.css` hâlâ tek dosya.
45. [~] Error/empty/loading state — Audit Logs ekranında eklendi. Diğer
    sayfalarda sistematik olarak gözden geçirilmedi.
46. [ ] Accessibility denetimi (keyboard nav, focus trap, aria, contrast,
    RTL, reduced-motion) — **yapılmadı**.
47. [~] Search result UX (rank/score/source/review status/reviewer/
    timestamp/evidence count) — çoğu zaten mevcuttu; "evidence count" OSINT
    katmanına bağlı, henüz yok.
48. [x] Session expired UX — refresh fail → signed-out + login route (zaten
    mevcuttu).
49. [ ] Multi-tab logout (BroadcastChannel) — **yapılmadı**.

## P2 — I18n

50. [x] 6 dil korunuyor (en/tr/de/fr/ar/ru), Arabic RTL bozulmadı.
51. [x] Locale parity test — zaten vardı, her yeni key eklemesinde korundu.
52. [~] Status translations — mevcut durumlar çevrildi; sistematik bir
    `status.*` haritalama denetimi yapılmadı.
53. [~] Date/number formatting (Intl API) — Audit Logs ekranında
    `Intl.DateTimeFormat` kullanıldı; diğer ekranlarda sistematik değil.

## P2 — Logging ve Observability

54. [x] Structured logging (JSON) — zaten vardı, hassas alan eklenmedi.
55. [ ] Metrics interface (latency, auth failures, db pool vb.) —
    **yapılmadı**.
56. [~] Health/readiness — `GET /api/health` var. `GET /api/health/ready`
    (DB + kritik bağımlılık kontrolü) **yapılmadı**.

## P2 — Background Job

57. [ ] Async search hazırlığı (queue-ready `SearchService` tasarımı, 202 +
    polling/SSE) — **yapılmadı** (hâlâ senkron; state machine kavramsal
    olarak queue-ready ama gerçek async akış yok).
58. [ ] Retention job'ları (expired sessions/approval tokens/reset tokens/
    probe images) — **yapılmadı**.

## P2 — Connector / OSINT Katmanı (P2 eki, 40 madde)

- [ ] **Tamamının hiçbiri yapılmadı.** Web search / news / social provider
  abstraction'ları, entity resolution, evidence model, reverse image search,
  entity graph, source registry, OSINT UI, mock OSINT provider — hiçbiri
  başlanmadı. Bu, ayrı bir milestone (F) olarak planlanıyor.

## P2 — Test

62. [~] Security testleri — production secret eksikliği, weak secret, refresh
    rotation, reuse detection, banned session, rate limit, approval
    single-use, invalid/oversized image, coordinate range, review permission,
    audit generated kapsandı. **Kapsanmayan:** last-admin protection (madde
    43), organization scoping (madde 12), password reset single-use (madde 9
    henüz yok).
63. [ ] Role matrix test (table-driven, her hassas endpoint × her rol) —
    **yapılmadı** (rol kontrolleri endpoint bazlı ad-hoc test edildi, sistemik
    matris testi yok).
64. [ ] Frontend test genişletme (dil değişimi, RTL, login/logout, session
    expiry, search validation, review/audit/admin permission, error state) —
    **yapılmadı**, mevcut 8 test korunuyor ama yeni özellikler için test
    eklenmedi.

## P2 — CI

65. [ ] CI genişletme (dependency vuln scan, secret scan, locale parity CI
    testi, docs/API consistency testi) — **yapılmadı**, `.github/workflows/
    ci.yml` bu oturumlarda değiştirilmedi.
66. [x] Lockfile (`Cargo.lock`, `package-lock.json`) commitli ve reproducible
    — zaten öyleydi, korundu.

## P2 — Deployment

67. [ ] Self-ping'i opsiyonel yap (`ENABLE_SELF_PING=false` default) —
    **yapılmadı**, hâlâ `RENDER_EXTERNAL_URL` varsa koşulsuz aktif.
68. [x] Production DB zorunluluğu — production'da SQLite'a düşme zaten
    panic ediyordu, korundu.
69. [~] Migration — inline `ALTER TABLE IF NOT EXISTS` tabanlı migration var
    (yeni tablolar için de aynı desen kullanıldı). Ayrı bir rollback
    dokümanı **yok**.
70. [ ] Backup dokümantasyonu (DB backup, biometric template backup,
    encryption, restore procedure) — **yapılmadı**.

## P3 — Dokümantasyon

71. [x] README status'u düzeltildi, gerçek durumu yansıtıyor.
72. [x] Implemented/Mock/Planned ayrımı README/API.md/ROADMAP.md'de açık.
73. [x] SECURITY.md / docs/SECURITY_ARCHITECTURE.md her milestone'da
    güncellendi.
74. [ ] `docs/DATA_FLOW.md` — **yapılmadı**.
75. [ ] `docs/THREAT_MODEL.md` — **yapılmadı**.

---

## Milestone harfi ↔ Roadmap Phase eşleşmesi

| Milestone | Konu | docs/ROADMAP.md Phase | Durum |
|---|---|---|---|
| A | Authentication hardening | Phase 3.5 | Tamamlandı |
| B | Audit log | Phase 3.6 | Tamamlandı |
| C | Search/data correctness | Phase 3.7 | Tamamlandı |
| D | Gerçek biyometrik motor | Phase 4 | Yapılmadı |
| E | Evaluation (FAR/FRR/ROC) | Phase 4 içinde ayrı değil | Yapılmadı |
| F | Yetkili connector'lar / OSINT | Phase 5 | Yapılmadı |
| G | Deployment hardening | Phase 6 | Yapılmadı |

## Bu dosyayı güncel tutma kuralı

Bir madde tamamlandığında: `[ ]` veya `[~]` → `[x]` yapılır, kısmi
tamamlanan maddelerde not güncellenir, ve bu dosya ilgili milestone'un
commit'iyle birlikte commit edilir. Asla test edilmemiş/implement
edilmemiş bir şey `[x]` olarak işaretlenmez (CLAUDE.md'nin "never claim a
feature is implemented or tested unless it was actually run and verified"
kuralı burada da geçerli).
