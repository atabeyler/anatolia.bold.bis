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

7. [x] Login rate limiting'i geliştir — per-account + per-IP + burst
   pencereleri eklendi (Milestone A). Rate limiter provider interface'i
   eklendi: `server/src/ratelimit.rs`'te `RateLimiterBackend` trait'i,
   mevcut in-memory implementasyon `InMemoryRateLimiter` olarak yeniden
   adlandırıldı ve trait'i implemente ediyor. `AppState.rate_limiter`
   artık `Arc<dyn RateLimiterBackend>` — davranış değişmedi (hâlâ tek
   in-memory, distributed değil), ama ileride Redis/DB-backed bir limiter
   eklemek call site'ları değiştirmeden mümkün.
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
10. [x] MFA altyapısı ekle — TOTP tabanlı MFA eklendi (`server/src/mfa.rs`,
    `server/src/db/mfa.rs`). Varsayılan olarak `SYSTEM_ADMIN`/
    `SECURITY_ADMIN`/`REVIEWER` rolleri için zorunlu (`MFA_REQUIRED_ROLES`
    ile yapılandırılabilir), diğer roller için gönüllü. Login akışı
    MFA etkinse veya rol zorunlu kılıyorsa hiçbir zaman doğrudan session
    vermiyor — kısa ömürlü, tek amaçlı bir challenge token (ayrı
    `MFA_TOKEN_SECRET`) dönüyor; bu token tek başına hiçbir erişim
    sağlamıyor. Recovery code'lar hash'li saklanıyor (`mfa_recovery_codes`),
    TOTP secret hiçbir zaman loglanmıyor/audit'e yazılmıyor/enrollment
    onaylandıktan sonra API'den dönmüyor. Admin reset endpoint'i
    (`POST /api/v1/admin/users/{id}/mfa-reset`) eklendi. Backend
    (`server/tests/mfa.rs`, 4 entegrasyon testi + `mfa.rs`/`config.rs`
    birim testleri) ve frontend (login akışına gömülü challenge/enrollment
    adımı, `RecoveryCodesModal`, 6 dilde çeviri) tamamlandı ve doğrulandı.
    **Eksik kalan:** ayrı bir "hesap ayarları" ekranından gönüllü
    enrollment/disable için frontend UI yok — backend endpoint'leri
    (`/mfa/enroll`, `/mfa/enroll/confirm`, `/mfa/disable`) gerçek ve test
    edilmiş, ancak henüz hiçbir sayfadan çağrılmıyor; bu oturumda bilinçli
    olarak ertelendi (mevcut sayfalarda bir "hesap ayarları" konsepti henüz
    yok, bunu eklemek ayrı bir UI çalışması).
11. [~] Role değişiminde JWT stale yetki sorunu — ban anında session revoke
    var (Milestone A). Role **downgrade** anında session revoke / auth_version
    increment **yapılmadı**. Bu oturumda tekrar değerlendirildi ve
    bilinçli olarak ertelendi: backend'de zaten bir rol değiştirme
    endpoint'i yok, bu maddeyi tamamlamak önce böyle bir endpoint'i
    sıfırdan eklemeyi gerektiriyor — hangi rolün kime hangi rolü
    atayabileceği, kendi kendine rol değiştirmenin engellenmesi gibi
    tasarım kararları içeren gerçek bir özellik (madde 37'nin four-eyes
    policy'si gibi), basit bir hardening düzeltmesi değil.

## P1 — Authorization ve Organizasyon

12. [ ] Organization / Unit modeli ekle — **bilinçli olarak ertelendi**, ayrı
    büyük mimari iş (docs/ROADMAP.md'de not edildi).
13. [x] Merkezi permission policy — `server/src/permission.rs` eklendi:
    `can_create_search`/`can_view_search`/`can_review_candidate`/
    `can_view_audit_log`/`can_administer_users`. `auth::require_role`
    artık bir rol dizisi değil, bu fonksiyonlardan birini alıyor;
    `admin.rs`/`audit.rs`/`search.rs` içindeki dağınık `*_ROLES` sabitleri
    kaldırılıp bu fonksiyonlara yönlendirildi.

## P1 — Image Upload

14. [x] Gerçek image validation — magic-byte + gerçek decode, JPEG/PNG/WEBP,
    10MB limit, boyut/piksel limitleri, decompression-bomb koruması.
    (Milestone C)
15. [x] EXIF metadata temizle — `image_validation::validate_and_sanitize_probe_image`
    artık doğrulamanın yanında karar verilen görüntüyü decode edilmiş
    piksel verisinden (her zaman PNG olarak) yeniden encode edip
    döndürüyor; `image` crate'in encoder'ları EXIF/XMP chunk'larını asla
    geri yazmadığından bu tek başına yeterli bir temizleme adımı.
16. [x] Latitude/longitude validation — aralık + eşleşen çift zorunluluğu.
    (Milestone C)
17. [ ] Face quality pipeline (`FaceDetector`/`FaceAligner`/
    `FaceQualityEvaluator`/`EmbeddingProvider` interface'leri) — **yapılmadı**.
18. [x] Raw image retention — probe görüntüleri zaten hiçbir zaman
    diskte/veritabanında saklanmıyor (`search.rs`, `image_validation.rs`);
    yalnızca türetilen skorlar kalıcı hale geliyor. Bu, mümkün olan en
    sıkı retention politikası (sıfır retention) ve bilinçli bir tasarım
    kararı — ayrıca bir "job" gerektirmiyor çünkü silinecek bir şey yok.
    `docs/DEPLOYMENT.md`'nin Backups bölümünde bu açıkça belgelendi.
    Gerçek biyometrik motor (madde 20-23) eklendiğinde ham görüntü/
    template saklama ihtiyacı doğarsa bu madde yeniden ele alınmalı.

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
30. [x] Pagination — search history (`GET /api/v1/search`) ve audit logs
    paginated (Milestone B/C). **Users listesi** (`GET /api/v1/admin/users`)
    de artık aynı desenle (`page`/`pageSize`/`items`/`total`)
    server-side paginated — `db::list_users_page` eklendi, frontend
    `AdminPage`'e sayfa ileri/geri navigasyonu eklendi (6 dilde
    `admin.pagination.*` çevirileri). Tek bir search'ün candidate listesi
    zaten top-k ile sınırlı, ayrı pagination gerekmedi.

## P1 — Data Privacy

31. [~] Data domain ayrımı — `server/src/db.rs` (2600+ satır) artık
    `server/src/db/` dizini: `db/mod.rs` (bağlantı kurulumu, schema
    migration, `AppState` — her domain'in ortak altyapısı) ve `db/audit.rs`
    (append-only audit trail — diğer domain'lere en az bağımlı olduğu için
    ilk ayrılan). `crate::db::X` importları hiçbir çağıran dosyada
    değişmedi (`pub use audit::*` ile re-export edildi). **Eksik kalan:**
    identity (users), session/approval-token ve search/candidate/
    verification domain'leri hâlâ `db/mod.rs` içinde birlikte —
    bunları ayrı dosyalara taşımak (2000+ satırlık, production'da
    Postgres'e karşı test edilemeyen bir kod tabanının geri kalanını)
    tek bir oturumda riske atmak yerine bilinçli olarak ertelendi;
    audit örneği deseni kanıtladı, geri kalanı ayrı bir batch'te
    yapılmalı.
32. [~] National ID hassasiyeti — `GET`/`PATCH /api/v1/admin/users`
    yanıtlarında `nationalId` artık son iki hane dışında maskeleniyor
    (`admin::mask_national_id`); admin panelindeki düzenleme formu da
    dokunulmayan (maskeli) değeri sunucuya geri göndermeyecek şekilde
    güncellendi (`nationalIdTouched` bayrağı). **Eksik kalan:** veritabanı
    tarafında hâlâ plaintext saklanıyor — encrypted-at-rest/lookup-hash
    (madde başlığındaki ikinci kısım) bir şifreleme anahtarı yönetimi ve
    mevcut prod verisinin migrate edilme stratejisi kararı gerektiriyor,
    bu oturumda başlanmadı.
33. [x] Database index/constraint — `sessions`, `audit_events`,
    `verification_events` için indexler zaten vardı (Milestone A/B/C).
    Eklendi: `search_candidates (search_id, candidate_id)` üzerinde unique
    index (bir aday bir arama içinde en fazla bir kez görünebilir, artık
    veritabanı tarafından zorlanıyor) ve `searches (created_at,
    case_reference, requested_by)` indexleri (arama geçmişi bu kolonlara
    göre filtreleniyor/sıralanıyor).
34. [x] Soft delete — `users.deleted_at` eklendi. Admin panelinden bir
    hesabın silinmesi (`DELETE /api/v1/admin/users/{id}`) artık satırı
    fiziksel olarak kaldırmıyor, `deleted_at` işaretliyor + tüm oturumları
    iptal ediyor; bu sayede `searches`/`verification_events`/`audit_events`
    tablolarındaki geçmiş referanslar (requested_by, reviewer_user_id,
    actor_user_id) sahipsiz kalmıyor. `deleted_at IS NOT NULL` olan
    hesaplar login, session/token doğrulama ve admin listesinde tamamen
    yok gibi davranıyor. **Not:** bekleyen (henüz onaylanmamış) bir kaydı
    reddetmek (`admin::reject_user`/`quick_reject`) hâlâ hard delete — o
    noktada hesabın hiçbir gerçek geçmişi olmadığı için bu bilinçli bir
    ayrım.

## P1 — Review Sistemi

35. [x] Immutable review history — `verification_events` tablosu, her
    confirm/reject yeni bir event olarak ekleniyor,
    `GET /api/v1/search/{id}/candidates/{id}/history`. (Milestone C)
36. [x] Review decisions — `inconclusive` karar tipi eklendi
    (`POST /api/v1/candidates/{id}/inconclusive`): `confirmed`/`rejected`'ın
    aksine adayı kapatmıyor, sonraki bir inceleme için açık bırakıyor.
    `needs_second_review` ayrı bir decision tipi olarak **eklenmedi** —
    bu, madde 37'nin (four-eyes policy) parçası; o özellik netleşmeden
    ayrı bir decision tipi eklemek anlamsız olurdu.
37. [ ] Second review / four-eyes policy (`REQUIRE_SECOND_REVIEW`) —
    **yapılmadı**. Bu, basit bir hardening düzeltmesinden çok gerçek bir
    özellik: "bir adayın kimliği için en az iki farklı REVIEWER'ın onayı
    gerekir" davranışı search_candidates durum makinesine yeni bir ara
    durum (`needs_second_review`) eklemeyi, ilk reviewer'ın kendi kararını
    ikinci onay olarak sayamamasını (aynı kullanıcı iki kez onaylayamaz)
    ve frontend'de bunu görünür kılmayı gerektiriyor — repo sahibinin bu
    akışı nasıl istediğine dair bir tasarım kararı bekliyor.

## P1 — API Kalitesi

38. [x] Error format (`{code, messageKey, requestId, details}`) — zaten
    mevcuttu, korundu ve tüm yeni endpoint'lerde kullanıldı.
39. [x] Request ID — `x-request-id` her response'ta dönüyor, audit log'a
    yazılıyor. Client'ın gönderdiği request id artık doğrulanıyor (1–128
    ASCII harf/rakam/`-`/`_`); bunun dışındaki değerler (boş, aşırı uzun,
    izin verilmeyen karakter) sessizce üretilen bir UUID ile değiştiriliyor.
    Doğrulama `server/src/error.rs::request_id`'de merkezi hale getirildi
    (admin/audit/auth/search'teki 4 ayrı kopya kaldırıldı).
40. [x] OpenAPI — `docs/openapi.json` eklendi (33 path/method, tüm
    router route'larını kapsıyor). `server/tests/openapi_drift.rs` her
    dokümante edilmiş path'i gerçek router'a karşı deniyor ve route
    eksikse (axum'un imzası: boş body ile 404) testi kırıyor — bilerek
    bozulmuş bir path ile doğrulandı. `.github/workflows/ci.yml` zaten
    `cargo test` çalıştırdığı için bu drift kontrolü ek bir CI adımı
    gerektirmeden otomatik olarak CI'ın parçası. API.md hâlâ ana kaynak
    (request/response şekilleri, rate limit'ler, hata kodları için);
    openapi.json kasıtlı olarak hafif tutuldu, eksiksiz şema
    tanımlamıyor.

## P2 — Admin

41. [x] Admin seed — rate-limited + constant-time token comparison zaten
    vardı. `POST /api/v1/admin/seed-admin` artık en az bir aktif
    `SYSTEM_ADMIN` varsa kendini otomatik devre dışı bırakıyor (doğru
    seed token ile bile, farklı bir `ADMIN_USER_CODE` ile tekrar
    çağrılsa dahi `403 Forbidden`); `BOOTSTRAP_ENABLED=true` bilinçli bir
    kurtarma senaryosu için bunu açıkça yeniden açıyor.
42. [x] Sensitive admin confirmation — silme işleminde frontend confirm
    modal'ı zaten vardı. Ban işlemi için de `window.confirm` eklendi;
    ayrıca `runAction` artık başarısız admin işlemlerini (ör.
    `LAST_ADMIN_PROTECTED`) sessizce yutmuyor, kullanıcıya çevrilmiş hata
    mesajı gösteriyor.
43. [x] Son SYSTEM_ADMIN koruması — `ban_user` ve `delete_user_route`,
    hedef son aktif `SYSTEM_ADMIN` ise `409 Conflict`
    (`LAST_ADMIN_PROTECTED`) ile reddediyor
    (`db::count_active_system_admins`). 3 entegrasyon testi ile
    doğrulandı (ban reddi, delete reddi + ikinci adminin silinebildiği
    kontrol, seed-admin self-disable). Role **downgrade** koruması hâlâ
    yok çünkü backend'de bir rol değiştirme endpoint'i henüz mevcut
    değil (madde 11'in bir parçası olarak, ayrı bir özellik olarak ele
    alınmalı).

## P2 — Frontend

44. [x] Global CSS'i parçala — renk/font/type-scale/tracking token'ları
    `client/src/styles/tokens.css`'e taşındı, `index.css` bunu en başta
    `@import` ediyor. `index.css`'in geri kalanı (layout/component
    kuralları) bilinçli olarak tek dosyada bırakıldı — bileşen bazlı tam
    parçalama daha büyük, ayrı bir refactor.
45. [x] Error/empty/loading state — Audit Logs ekranında zaten vardı. Bu
    oturumda tüm sayfalar tek tek gözden geçirildi:
    LoginPage/ResetPasswordPage/AdminPage zaten submitting/error/success
    state'lerini doğru yönetiyordu. Tek gerçek eksik DashboardPage'de
    bulundu ve düzeltildi: bir search'ün adayları yüklenirken hata olursa
    (`getSearchCandidates` reddedilirse) önceden bu, sessizce boş bir
    diziye düşüyordu — "hiç aday yok" ile "yükleme başarısız oldu"
    ayırt edilemiyordu. Artık ayrı bir loading/error state'i var
    (`search.candidatesLoading`/`search.candidatesLoadError`, 6 dilde).
46. [ ] Accessibility denetimi (keyboard nav, focus trap, aria, contrast,
    RTL, reduced-motion) — **yapılmadı**.
47. [~] Search result UX (rank/score/source/review status/reviewer/
    timestamp/evidence count) — çoğu zaten mevcuttu; "evidence count" OSINT
    katmanına bağlı, henüz yok.
48. [x] Session expired UX — refresh fail → signed-out + login route (zaten
    mevcuttu).
49. [x] Multi-tab logout (BroadcastChannel) — `client/src/services/authBroadcast.ts`
    eklendi: `logout`/`logoutAll` artık aynı origin'deki diğer sekmelere
    `BroadcastChannel` üzerinden bir "signed-out" mesajı yayınlıyor,
    `AuthContext` bu mesajı dinleyip kendi state'ini anında signed-out'a
    çeviriyor (`BroadcastChannel` desteklemeyen ortamda sessizce devre
    dışı kalıyor, çökmüyor).

## P2 — I18n

50. [x] 6 dil korunuyor (en/tr/de/fr/ar/ru), Arabic RTL bozulmadı.
51. [x] Locale parity test — zaten vardı, her yeni key eklemesinde korundu.
52. [x] Status translations — sistematik denetim yapıldı: tüm
    `.tsx`/`.ts` dosyalarında "Pending"/"Confirmed"/"Rejected" gibi
    hardcode edilmiş İngilizce status metni aranmadı (grep ile
    doğrulandı), tüm durum rozetleri (`search.status.*`,
    `admin.badge.*`) i18n üzerinden geçiyor. Locale parity testi
    (`client/src/i18n/locales.test.ts`, CI'da `npm run test` ile
    çalışıyor) 6 dilin aynı key setine sahip olduğunu zaten yapısal
    olarak garanti ediyor.
53. [~] Date/number formatting (Intl API) — Audit Logs ekranında
    `Intl.DateTimeFormat` kullanıldı. Bu oturumda diğer ekranlar
    denetlendi: Dashboard/Admin sayfalarında şu an başka hiçbir ham
    tarih/sayı gösterimi yok (search/candidate kartları timestamp
    göstermiyor, yalnızca isim/durum) — yani düzeltilecek gerçek bir
    eksik bulunamadı. `GET /api/v1/search/{id}/candidates/{id}/history`
    endpoint'i (verification event timestamp'leri) henüz frontend'de hiç
    tüketilmiyor; o ekran eklendiğinde `Intl.DateTimeFormat` ile
    başlaması gerekiyor.

## P2 — Logging ve Observability

54. [x] Structured logging (JSON) — zaten vardı, hassas alan eklenmedi.
55. [ ] Metrics interface (latency, auth failures, db pool vb.) —
    **yapılmadı**.
56. [x] Health/readiness — `GET /api/health` (liveness, DB'ye dokunmuyor)
    zaten vardı. `GET /api/health/ready` eklendi: gerçek backend'e karşı
    basit bir sorgu çalıştırıyor, başarısız olursa `503` dönüyor.

## P2 — Background Job

57. [ ] Async search hazırlığı (queue-ready `SearchService` tasarımı, 202 +
    polling/SSE) — **yapılmadı** (hâlâ senkron; state machine kavramsal
    olarak queue-ready ama gerçek async akış yok). Bu oturumda tekrar
    değerlendirildi ve bilinçli olarak ertelendi: sahte bir queue
    soyutlaması eklemek (davranışı değiştirmeyen) CLAUDE.md'nin
    "no half-finished implementations" kuralına aykırı olurdu; gerçek
    async akış `POST /api/v1/search/face`'in response contract'ını
    (`200` yerine `202` + polling/SSE) değiştiriyor — bu, frontend'i de
    kapsayan ve polling/SSE kararını gerektiren ayrı bir özellik.
58. [x] Retention job'ları — `db::purge_expired_auth_records` eklendi:
    süresi dolmuş `sessions` ve `approval_tokens` satırlarını siliyor.
    `main.rs::spawn_retention_job` bunu sabit aralıklarla (varsayılan
    saatte bir, ilk çalıştırma başlangıçtan 30sn sonra) çağırıyor;
    `RETENTION_JOB_ENABLED=false` ile kapatılabiliyor,
    `RETENTION_JOB_INTERVAL_SECS` ile aralık ayarlanabiliyor
    (self-ping job'ıyla aynı desen). `server/tests/retention.rs` ile
    doğrulandı: süresi dolmuş satırlar siliniyor, dolmamışlar
    korunuyor. "Probe images" bu maddenin kapsamına dahil değil —
    madde 18'de açıklandığı gibi zaten hiç saklanmıyor, "reset tokens"
    ayrı bir tablo değil, `approval_tokens` tablosunun bir `purpose`
    değeri (zaten kapsandı).

## P2 — Connector / OSINT Katmanı (P2 eki, 40 madde)

- [ ] **Tamamının hiçbiri yapılmadı.** Web search / news / social provider
  abstraction'ları, entity resolution, evidence model, reverse image search,
  entity graph, source registry, OSINT UI, mock OSINT provider — hiçbiri
  başlanmadı. Bu, ayrı bir milestone (F) olarak planlanıyor.

## P2 — Test

62. [~] Security testleri — production secret eksikliği, weak secret, refresh
    rotation, reuse detection, banned session, rate limit, approval
    single-use, invalid/oversized image, coordinate range, review permission,
    audit generated, password reset single-use/expiry (madde 9), last-admin
    protection + seed-admin self-disable (madde 43) kapsandı. **Kapsanmayan:**
    organization scoping (madde 12, ayrı büyük mimari iş).
63. [x] Role matrix test — `server/tests/role_matrix.rs` eklendi:
    `GET /api/v1/audit`, `GET /api/v1/admin/users`, `GET /api/v1/search`,
    `POST /api/v1/search/face`, `POST /api/v1/candidates/{id}/verify`
    uç noktaları, beş rolün (`SYSTEM_ADMIN`/`SECURITY_ADMIN`/`OPERATOR`/
    `REVIEWER`/`AUDITOR`) her biriyle tek tek deneniyor ve sonuç
    `permission.rs`'teki policy ile karşılaştırılıyor (izinli roller asla
    `403` görmemeli, izinsiz roller her zaman `403` görmeli).
64. [~] Frontend test genişletme — 6 test dosyası, 15 test (önceki
    oturumlardan: dil değişimi/RTL zaten `App.test.tsx`'te; bu oturumda
    eklenenler: multi-tab logout — `AuthContext.test.tsx`,
    `authBroadcast.test.ts` — 4 test; `LoginPage.test.tsx` — sign-in/
    sign-up mod geçişi ve başarısız login'de çevrilmiş hata mesajı — 2
    test; `DashboardPage.test.tsx` — bir search'ün adaylarını
    yüklerken hata durumu ("no candidates" ile karıştırılmıyor) — 1
    test). **Kapsanmayan:** session expiry (refresh-fail → signed-out)
    ve review/audit/admin permission'ın component seviyesinde ayrı
    testleri — bunlar zaten backend'de (`role_matrix.rs` dahil) sıkı
    şekilde test ediliyor; frontend tarafında component-seviyeli bir
    permission testi hâlâ eksik.

## P2 — CI

65. [ ] CI genişletme (dependency vuln scan, secret scan, locale parity CI
    testi, docs/API consistency testi) — **yapılmadı**, `.github/workflows/
    ci.yml` bu oturumlarda değiştirilmedi. Not: "docs/API consistency
    testi" parçası artık dolaylı olarak karşılanıyor — madde 40'taki
    `server/tests/openapi_drift.rs` zaten `cargo test` üzerinden çalışıyor;
    burada eksik kalan yalnızca dependency/secret scan ve ayrı bir locale
    parity CI adımı (locale parity'nin kendisi zaten
    `client/src/i18n/locales.test.ts` ile test ediliyor ve `npm run test`
    CI'da çalışıyorsa örtük olarak kapsanıyor — bu maddenin asıl eksiği
    dependency/secret taramaları).
66. [x] Lockfile (`Cargo.lock`, `package-lock.json`) commitli ve reproducible
    — zaten öyleydi, korundu.

## P2 — Deployment

67. [x] Self-ping'i opsiyonel yap — `ENABLE_SELF_PING=false` ile devre dışı
    bırakılabiliyor; varsayılan davranış (RENDER_EXTERNAL_URL varsa aktif)
    korunuyor, sadece açık bir opt-out eklendi.
68. [x] Production DB zorunluluğu — production'da SQLite'a düşme zaten
    panic ediyordu, korundu.
69. [~] Migration — inline `ALTER TABLE IF NOT EXISTS` tabanlı migration var
    (yeni tablolar için de aynı desen kullanıldı). Ayrı bir rollback
    dokümanı **yok**.
70. [x] Backup dokümantasyonu — `docs/DEPLOYMENT.md`'ye "Backups" bölümü
    eklendi: nelerin (tek bir Postgres şeması) yedeklenmesi gerektiği,
    henüz var olmayan biometric template depolamasının şu an neden
    kapsam dışı olduğu, şema bazlı `pg_dump`/`pg_restore` komutları,
    restore sonrası doğrulama adımları. Sıklık/saklama süresi repo
    sahibinin kararına bırakıldı — otomatik bir yedekleme job'ı bu
    oturumda **eklenmedi**, sadece manuel prosedür belgelendi.

## P3 — Dokümantasyon

71. [x] README status'u düzeltildi, gerçek durumu yansıtıyor.
72. [x] Implemented/Mock/Planned ayrımı README/API.md/ROADMAP.md'de açık.
73. [x] SECURITY.md / docs/SECURITY_ARCHITECTURE.md her milestone'da
    güncellendi.
74. [x] `docs/DATA_FLOW.md` — eklendi: registration/approval, login/session
    lifecycle, password reset, biometric search, review/audit trail ve
    hesap silme akışlarının uçtan uca izlenebilir dökümü, gerçek koda
    referansla (uydurma mimari değil).
75. [x] `docs/THREAT_MODEL.md` — eklendi: STRIDE tarzı bir geçiş
    (spoofing/tampering/repudiation/information disclosure/denial of
    service/elevation of privilege), her tehdit için mevcut mitigasyon ya
    da açıkça "henüz ele alınmadı" notu, ve bilinçli olarak kapsam dışı
    bırakılan maddelerin (organizasyon modeli, gerçek biyometrik motor,
    MFA, national ID koruması, OSINT, DB-seviyesi audit tamper direnci)
    referansı.

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
