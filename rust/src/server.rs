//! Loopback-only HTTP API. Static assets are embedded; request paths never reach disk.
use crate::{
    crypto,
    vault::{Vault, s},
    workspace::{Workspace, is_text, media},
};
use anyhow::{Result, anyhow, ensure};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::any,
};
use include_dir::{Dir, include_dir};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
static WEB: Dir = include_dir!("$CARGO_MANIFEST_DIR/../src/empreinte/web");
struct Session {
    vault: Vault,
    workspace: Workspace,
    token: String,
    last: Instant,
}
struct Inner {
    session: Option<Session>,
    failures: u32,
    retry: Instant,
}
pub struct App {
    path: PathBuf,
    page: String,
    port: u16,
    demo: bool,
    generation: AtomicU64,
    inner: Mutex<Inner>,
}
impl App {
    pub fn new(path: PathBuf, port: u16, demo: bool) -> Arc<Self> {
        Arc::new(Self {
            path,
            page: hex::encode(crypto::random(32)),
            port,
            demo,
            generation: AtomicU64::new(0),
            inner: Mutex::new(Inner {
                session: None,
                failures: 0,
                retry: Instant::now(),
            }),
        })
    }
}
fn equal(a: &str, b: &str) -> bool {
    !a.is_empty() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
fn error(status: StatusCode, code: &str, message: &str) -> Response {
    response(
        status,
        "application/json",
        serde_json::to_vec(&json!({"error":code,"message":message})).unwrap(),
    )
}
fn response(status: StatusCode, kind: &str, body: Vec<u8>) -> Response {
    let mut res = (status, body).into_response();
    let h = res.headers_mut();
    h.insert("content-type", kind.parse().unwrap());
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    ] {
        h.insert(name, value.parse().unwrap());
    }
    res
}
fn header<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}
pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .fallback(any(handle))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(app)
}
async fn handle(
    State(app): State<Arc<App>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let host = header(&headers, "host");
    let hosts = [
        format!("127.0.0.1:{}", app.port),
        format!("localhost:{}", app.port),
    ];
    if !hosts.iter().any(|h| h == host) {
        return error(StatusCode::FORBIDDEN, "bad_host", "Hôte refusé");
    }
    let path = uri.path();
    if !path.starts_with("/api/") {
        if method != Method::GET && method != Method::HEAD {
            return error(StatusCode::METHOD_NOT_ALLOWED, "method", "Méthode refusée");
        }
        let file = if path == "/" {
            "index.html"
        } else {
            path.trim_start_matches('/')
        };
        if file.contains("..") || file.ends_with(".test.mjs") {
            return error(StatusCode::NOT_FOUND, "not_found", "Introuvable");
        }
        let Some(asset) = WEB.get_file(file) else {
            return error(StatusCode::NOT_FOUND, "not_found", "Introuvable");
        };
        let kind = if file.ends_with(".html") {
            "text/html; charset=utf-8"
        } else if file.ends_with(".js") {
            "text/javascript; charset=utf-8"
        } else if file.ends_with(".css") {
            "text/css; charset=utf-8"
        } else {
            "image/svg+xml"
        };
        let bytes = if file == "index.html" {
            String::from_utf8_lossy(asset.contents())
                .replace("__EMPREINTE_PAGE_TOKEN__", &app.page)
                .into_bytes()
        } else {
            asset.contents().to_vec()
        };
        return response(
            StatusCode::OK,
            kind,
            if method == Method::HEAD {
                vec![]
            } else {
                bytes
            },
        );
    }
    if !equal(header(&headers, "x-empreinte-token"), &app.page) {
        return error(
            StatusCode::UNAUTHORIZED,
            "bad_token",
            "Jeton de page invalide",
        );
    }
    if !["", "same-origin", "none"].contains(&header(&headers, "sec-fetch-site")) {
        return error(
            StatusCode::FORBIDDEN,
            "cross_site",
            "Requête externe refusée",
        );
    }
    if method != Method::GET
        && !hosts
            .iter()
            .any(|h| format!("http://{h}") == header(&headers, "origin"))
    {
        return error(StatusCode::FORBIDDEN, "bad_origin", "Origine refusée");
    }
    let parsed = if body.is_empty() {
        json!({})
    } else {
        match serde_json::from_slice::<Value>(&body) {
            Ok(v) if v.is_object() => v,
            _ => return error(StatusCode::BAD_REQUEST, "invalid", "Objet JSON attendu"),
        }
    };
    let generation = app.generation.load(Ordering::SeqCst);
    if path == "/api/lock" && method == Method::POST {
        app.generation.fetch_add(1, Ordering::SeqCst);
    }
    let path = path.to_owned();
    let query = percent_encoding::percent_decode_str(uri.query().unwrap_or(""))
        .decode_utf8_lossy()
        .into_owned();
    let token = header(&headers, "x-empreinte-unlock").to_owned();
    let task = tokio::task::spawn_blocking(move || {
        dispatch(&app, &method, &path, &query, &token, parsed, generation)
    });
    match task.await {
        Ok(Ok(v)) => response(
            StatusCode::OK,
            "application/json",
            serde_json::to_vec(&v).unwrap(),
        ),
        Ok(Err((status, code, message))) => error(status, &code, &message),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "Erreur interne",
        ),
    }
}
type ApiResult = std::result::Result<Value, (StatusCode, String, String)>;
fn fail(status: StatusCode, code: &str, message: &str) -> ApiResult {
    Err((status, code.into(), message.into()))
}
fn dispatch(
    app: &App,
    method: &Method,
    path: &str,
    query: &str,
    token: &str,
    mut body: Value,
    generation: u64,
) -> ApiResult {
    let mut state = app.inner.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal".into(),
            "Session indisponible".into(),
        )
    })?;
    if state
        .session
        .as_ref()
        .is_some_and(|s| s.last.elapsed() > Duration::from_secs(900))
    {
        state.session = None;
        app.generation.fetch_add(1, Ordering::SeqCst);
    }
    if path == "/api/status" && method == Method::GET {
        return Ok(
            json!({"exists":app.path.join("header.json").is_file(),"unlocked":state.session.as_ref().is_some_and(|s|equal(&s.token,token)),"demo":app.demo,"features":{"import":true,"previews":false,"export":false,"watch":false,"anchor_methods":[]},"idle_timeout":900,"retry_after":state.retry.saturating_duration_since(Instant::now()).as_secs(),"runtime":"rust","coverage":null,"watch":null}),
        );
    }
    if path == "/api/lock" && method == Method::POST {
        if state
            .session
            .as_ref()
            .is_some_and(|s| !equal(&s.token, token))
        {
            return fail(
                StatusCode::UNAUTHORIZED,
                "locked",
                "Jeton de session requis",
            );
        }
        state.session = None;
        return Ok(json!({"locked":true}));
    }
    if ["/api/unlock", "/api/create"].contains(&path) && method == Method::POST {
        if state.session.is_some() {
            return fail(
                StatusCode::CONFLICT,
                "active_session",
                "Verrouillez la session existante avant de la remplacer",
            );
        }
        if state.retry > Instant::now() {
            return fail(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Trop d'essais ; réessayez plus tard",
            );
        }
        let pass = Zeroizing::new(body["passphrase"].take().as_str().unwrap_or("").to_owned());
        if pass.is_empty() || pass.len() > 4096 {
            return fail(
                StatusCode::BAD_REQUEST,
                "invalid",
                "Phrase de passe invalide",
            );
        }
        let opened = if path == "/api/create" {
            Vault::create(&app.path, &pass, false).map(|(v, r)| (v, Some(r)))
        } else {
            Vault::open(&app.path, &pass).map(|v| (v, None))
        };
        let (vault, recovery) = match opened {
            Ok(v) => v,
            Err(_) => {
                state.failures += 1;
                state.retry =
                    Instant::now() + Duration::from_secs((1u64 << state.failures.min(6)).min(60));
                return fail(
                    StatusCode::UNAUTHORIZED,
                    "wrong_passphrase",
                    "Impossible de déverrouiller : phrase de passe, intégrité ou archive déjà ouverte",
                );
            }
        };
        if app.generation.load(Ordering::SeqCst) != generation {
            return fail(StatusCode::CONFLICT, "cancelled", "Déverrouillage annulé");
        }
        let workspace = Workspace::new(&vault).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "corrupted".into(),
                "Échec de lecture des documents".into(),
            )
        })?;
        let token = hex::encode(crypto::random(32));
        state.session = Some(Session {
            vault,
            workspace,
            token: token.clone(),
            last: Instant::now(),
        });
        state.failures = 0;
        return Ok(
            json!({"unlock_token":token,"idle_timeout":900,"recovery_key":recovery.as_ref().map(|r|r.as_str())}),
        );
    }
    let Some(session) = state.session.as_mut() else {
        return fail(StatusCode::UNAUTHORIZED, "locked", "Archive verrouillée");
    };
    if !equal(token, &session.token) {
        return fail(StatusCode::UNAUTHORIZED, "locked", "Session expirée");
    }
    session.last = Instant::now();
    let result = operation(session, method, path, query, &body);
    result.map_err(|e| (StatusCode::BAD_REQUEST, "invalid".into(), e.to_string()))
}
fn param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        pair.split_once('=')
            .filter(|(k, _)| *k == key)
            .map(|(_, v)| v)
    })
}
fn operation(
    session: &mut Session,
    method: &Method,
    path: &str,
    query: &str,
    body: &Value,
) -> Result<Value> {
    let v = &mut session.vault;
    let ws = &session.workspace;
    match (method.as_str(), path) {
        ("GET", "/api/entries") => return Ok(json!(v.entries())),
        ("GET", "/api/graph") => {
            return Ok(ws.graph(param(query, "until"), param(query, "tags") == Some("1")));
        }
        ("POST", "/api/search") => {
            return Ok(json!(ws.search(
                &s(body, "q"),
                body["limit"].as_u64().unwrap_or(30).min(200) as usize
            )));
        }
        ("GET", "/api/activity") => {
            return Ok(ws.activity(v, param(query, "basis").unwrap_or("claimed")));
        }
        ("GET", "/api/ledger") => {
            let offset = param(query, "offset")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);
            let limit = param(query, "limit")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(50)
                .min(500);
            let records = if param(query, "order") == Some("desc") {
                v.records
                    .iter()
                    .rev()
                    .skip(offset)
                    .take(limit)
                    .collect::<Vec<_>>()
            } else {
                v.records
                    .iter()
                    .skip(offset)
                    .take(limit)
                    .collect::<Vec<_>>()
            };
            return Ok(
                json!({"records":records,"offset":offset,"total":v.records.len(),"head_hash":v.head()}),
            );
        }
        ("GET", "/api/anchors") => return Ok(json!(v.anchors)),
        ("POST", "/api/verify") => return Ok(v.verify()),
        ("GET", "/api/licenses") | ("GET", "/api/royalties") => {
            let field = if path.ends_with("licenses") {
                "licenses"
            } else {
                "royalties"
            };
            return Ok(json!(
                v.catalog[field]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(|r| serde_json::from_str::<Value>(&s(r, "committed")).ok())
                    .collect::<Vec<_>>()
            ));
        }
        ("GET", "/api/prefs") => {
            return Ok(v
                .aux_get("ui.prefs.v1")?
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                .unwrap_or(json!({})));
        }
        ("PUT", "/api/prefs") => {
            let data = crypto::canonical(body);
            ensure!(data.len() <= 65536, "préférences trop grandes");
            v.aux_put("ui.prefs.v1", &data)?;
            return Ok(json!({"saved":true}));
        }
        ("POST", "/api/import") => {
            let report = import_folder(v, Path::new(&s(body, "path")))?;
            session.workspace = Workspace::new(v)?;
            return Ok(report);
        }
        _ => {}
    }
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    if parts.len() >= 3 && parts[0] == "api" && parts[1] == "entries" {
        let id = parts[2];
        let number = param(query, "version")
            .map(str::parse::<usize>)
            .transpose()?;
        match (method.as_str(), parts.get(3).copied().unwrap_or("")) {
            ("GET", "") => return ws.entry(v, id),
            ("GET", "versions") => return Ok(json!(v.versions(id)?)),
            ("GET", "proof") => return v.proof(id, number),
            ("GET", "text") => {
                let entry = v.entry(id)?;
                let text = if is_text(&s(entry, "media_type")) {
                    String::from_utf8_lossy(&v.read(id, number)?).into_owned()
                } else {
                    String::new()
                };
                let doc = crate::workspace::parsed(&text, &s(entry, "path"));
                return Ok(
                    json!({"entry_id":id,"version":number.unwrap_or(entry["versions"].as_array().unwrap().len()),"media_type":entry["media_type"],"text":text,"link_targets":ws.targets(id,Some(&doc))}),
                );
            }
            ("POST", "remove") => {
                ensure!(body["confirm"] == true, "confirmation requise");
                v.remove(id)?;
                session.workspace = Workspace::new(v)?;
                return Ok(json!({"removed":true}));
            }
            _ => {}
        }
    }
    Err(anyhow!(
        "Fonction non disponible dans cette étape du portage Rust"
    ))
}
pub fn import_folder(v: &mut Vault, folder: &Path) -> Result<Value> {
    ensure!(
        folder.is_absolute() && folder.is_dir(),
        "dossier absolu requis"
    );
    let root = folder.canonicalize()?;
    ensure!(
        !v.path.starts_with(&root) && !root.starts_with(&v.path),
        "le coffre ne peut être importé dans lui-même"
    );
    let mut added = 0;
    let mut updated = 0;
    let mut unchanged = 0;
    let mut skipped = 0;
    for item in walkdir::WalkDir::new(&root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| !e.file_name().to_string_lossy().starts_with('.'))
    {
        let item = item?;
        if !item.file_type().is_file() {
            continue;
        }
        let path = item.path();
        let before = path.metadata()?;
        if before.len() > 32 * 1024 * 1024 {
            skipped += 1;
            continue;
        }
        let data = crate::vault::read_bounded(path, 32 * 1024 * 1024)?;
        let after = path.metadata()?;
        if before.len() != after.len()
            || before.modified()? != after.modified()?
            || data.len() as u64 != after.len()
        {
            skipped += 1;
            continue;
        }
        let logical = path
            .strip_prefix(&root)?
            .to_string_lossy()
            .replace('\\', "/");
        let old = v.entries().into_iter().find(|e| e["path"] == logical);
        let date: chrono::DateTime<chrono::Utc> = before.modified()?.into();
        let stamp = date.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
        let version = v.put(&logical, &data, media(&logical), Some(&stamp))?;
        match old {
            None => added += 1,
            Some(e) if e["n_versions"] == version["version"] => unchanged += 1,
            _ => updated += 1,
        }
    }
    Ok(json!({"added":added,"updated":updated,"unchanged":unchanged,"skipped":skipped}))
}
pub async fn serve(path: PathBuf, port: u16, demo: bool) -> Result<()> {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    let port = listener.local_addr()?.port();
    let app = App::new(path, port, demo);
    let idle = app.clone();
    let timer = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let mut state = idle.inner.lock().unwrap();
            if state
                .session
                .as_ref()
                .is_some_and(|s| s.last.elapsed() > Duration::from_secs(900))
            {
                state.session = None;
                idle.generation.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    println!("Empreinte Rust : http://127.0.0.1:{port}/");
    let permits = Arc::new(tokio::sync::Semaphore::new(32));
    let mut jobs = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            accepted=listener.accept()=>{
                let (stream,_)=accepted?;
                let Ok(permit)=permits.clone().try_acquire_owned()else{drop(stream);continue};
                let router=router(app.clone());
                jobs.spawn(async move{
                    let _permit=permit;
                    let service=hyper_util::service::TowerToHyperService::new(router);
                    let mut builder=hyper::server::conn::http1::Builder::new();
                    builder.keep_alive(false).timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(Duration::from_secs(10));
                    let connection=builder.serve_connection(hyper_util::rt::TokioIo::new(stream),service);
                    let _=tokio::time::timeout(Duration::from_secs(120),connection).await;
                });
            },
            _=jobs.join_next(),if !jobs.is_empty()=>{}
        }
    }
    app.generation.fetch_add(1, Ordering::SeqCst);
    jobs.abort_all();
    timer.abort();
    app.inner.lock().unwrap().session = None;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use tower::ServiceExt;
    async fn call(
        app: Arc<App>,
        method: &str,
        path: &str,
        token: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "127.0.0.1:19999")
            .header("origin", "http://127.0.0.1:19999")
            .header("x-empreinte-token", &app.page)
            .header("x-empreinte-unlock", token)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let response = router(app).oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    fn fixture() -> (tempfile::TempDir, Arc<App>) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault");
        let (mut vault, _) = Vault::create(&path, "test", true).unwrap();
        vault
            .put("a.md", b"private words", "text/markdown", None)
            .unwrap();
        drop(vault);
        let app = App::new(path, 19999, false);
        (temp, app)
    }
    #[tokio::test]
    async fn unlock_read_lock_revokes_token() {
        let (_temp, app) = fixture();
        let (_, auth) = call(
            app.clone(),
            "POST",
            "/api/unlock",
            "",
            json!({"passphrase":"test"}),
        )
        .await;
        let token = s(&auth, "unlock_token");
        assert!(!token.is_empty());
        let (status, entries) = call(app.clone(), "GET", "/api/entries", &token, json!({})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(entries.as_array().unwrap().len(), 1);
        call(app.clone(), "POST", "/api/lock", &token, json!({})).await;
        assert_eq!(
            call(app, "GET", "/api/entries", &token, json!({})).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    #[tokio::test]
    async fn second_client_cannot_replace_or_lock_session() {
        let (_temp, app) = fixture();
        let (_, auth) = call(
            app.clone(),
            "POST",
            "/api/unlock",
            "",
            json!({"passphrase":"test"}),
        )
        .await;
        let token = s(&auth, "unlock_token");
        assert_eq!(
            call(
                app.clone(),
                "POST",
                "/api/unlock",
                "",
                json!({"passphrase":"wrong"})
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            call(app.clone(), "POST", "/api/lock", "wrong", json!({}))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(app, "GET", "/api/entries", &token, json!({})).await.0,
            StatusCode::OK
        );
    }
    #[tokio::test]
    async fn rejects_foreign_host_and_missing_page_token() {
        let (_temp, app) = fixture();
        for (host, path, expected) in [
            ("evil.invalid", "/", StatusCode::FORBIDDEN),
            ("127.0.0.1:19999", "/api/status", StatusCode::UNAUTHORIZED),
        ] {
            let request = Request::builder()
                .uri(path)
                .header("host", host)
                .body(axum::body::Body::empty())
                .unwrap();
            let response = router(app.clone()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), expected);
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
    }
    #[tokio::test]
    async fn cancelled_auth_never_installs() {
        let (_temp, app) = fixture();
        let generation = app.generation.load(Ordering::SeqCst);
        app.generation.fetch_add(1, Ordering::SeqCst);
        let result = tokio::task::spawn_blocking(move || {
            let result = dispatch(
                &app,
                &Method::POST,
                "/api/unlock",
                "",
                "",
                json!({"passphrase":"test"}),
                generation,
            );
            assert!(app.inner.lock().unwrap().session.is_none());
            result
        })
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().1, "cancelled");
    }
}
