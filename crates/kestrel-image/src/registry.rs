use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::StreamExt;
use reqwest::StatusCode;

use crate::auth::{fetch_token, parse_www_authenticate};
use crate::digest::{Digest, VerifyingReader};
use crate::manifest::MANIFEST_ACCEPT_HEADER;
use crate::reference::ImageReference;

/// Bound on total attempts (the first request plus retries) for a blob
/// download that keeps hitting 5xx/429 — so a registry that is
/// permanently unhappy fails loudly instead of retrying forever.
const MAX_BLOB_DOWNLOAD_ATTEMPTS: u32 = 4;

pub struct RegistryClient {
    http: reqwest::Client,
    /// The cached bearer token, if any. `RwLock` (rather than plain
    /// `Option<String>`) gives interior mutability so a single
    /// `RegistryClient` can be shared (typically behind an `Arc`) across
    /// concurrently-spawned tasks — e.g. Task 8's bounded-parallel layer
    /// downloads — without needing `&mut self` and without serializing
    /// all requests behind a client-wide `Mutex`. Reads (attaching the
    /// token to an outgoing request) are frequent and cheap; writes
    /// (fetching a fresh token) are rare, so a read-write lock rather
    /// than a plain `Mutex` lets concurrent requests attach the token in
    /// parallel instead of contending with each other.
    token: tokio::sync::RwLock<Option<String>>,
    /// When set, every request goes to this base URL instead of an
    /// `https://<api_host>` derived from the reference's registry.
    /// Production code never sets this (see `new`); `with_base_url`
    /// exists so this module's own tests can point a client at a
    /// `wiremock` server over plain HTTP, and doubles as the hook a real
    /// insecure/local registry would need.
    base_url_override: Option<String>,
}

impl RegistryClient {
    pub fn new() -> Result<Self> {
        let http = Self::build_http_client()?;
        Ok(RegistryClient { http, token: tokio::sync::RwLock::new(None), base_url_override: None })
    }

    /// See `base_url_override`'s doc comment. `base_url` is used as-is,
    /// e.g. `http://127.0.0.1:PORT` — no scheme is added.
    pub fn with_base_url(base_url: impl Into<String>) -> Result<Self> {
        let http = Self::build_http_client()?;
        Ok(RegistryClient { http, token: tokio::sync::RwLock::new(None), base_url_override: Some(base_url.into()) })
    }

    fn build_http_client() -> Result<reqwest::Client> {
        reqwest::Client::builder().timeout(Duration::from_secs(30)).build().context("building HTTP client")
    }

    fn base_url(&self, reference: &ImageReference) -> String {
        match &self.base_url_override {
            Some(base) => base.clone(),
            None => format!("https://{}", reference.api_host()),
        }
    }

    fn manifest_url(&self, reference: &ImageReference) -> String {
        format!("{}/v2/{}/manifests/{}", self.base_url(reference), reference.repository, reference.manifest_reference())
    }

    fn blob_url(&self, reference: &ImageReference, digest: &Digest) -> String {
        format!("{}/v2/{}/blobs/{}", self.base_url(reference), reference.repository, digest)
    }

    /// A GET request carrying the current bearer token, if any. Callers
    /// layer on any request-specific headers (Accept, Range, ...) via
    /// `get_with_auth`'s `configure` closure rather than here, since this
    /// builder gets used twice (pre- and post-auth-retry) with the same
    /// extra headers each time.
    async fn build_get(&self, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.http.get(url);
        if let Some(t) = self.token.read().await.as_ref() {
            req = req.bearer_auth(t);
        }
        req
    }

    /// Performs one request, and if it comes back 401 with a Bearer
    /// challenge, fetches a token and retries ONCE with it attached —
    /// covers both "never authenticated yet" and "token expired
    /// mid-pull", for manifest fetches and blob downloads alike.
    /// `configure` attaches any request-specific headers on top of the
    /// auth header this method manages; it's applied to both the
    /// original and (if needed) the retried request.
    ///
    /// Takes `&self`, not `&mut self`: the token lives behind a
    /// `tokio::sync::RwLock` so this (and everything that calls it) can
    /// run concurrently across tasks sharing one `Arc<RegistryClient>`.
    /// If two concurrent requests both hit a 401 around the same time,
    /// each independently fetches and writes a fresh token — see the
    /// doc comment on `token` for why that race is left as-is rather
    /// than deduplicated.
    async fn get_with_auth(
        &self,
        url: &str,
        configure: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response> {
        let resp = configure(self.build_get(url).await).send().await.context("sending request")?;
        if resp.status() != StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }

        let Some(challenge) = parse_www_authenticate(resp.headers())? else {
            return Ok(resp); // 401 with no bearer challenge — nothing more we can do
        };
        let token = fetch_token(&self.http, &challenge).await.context("fetching auth token")?;
        *self.token.write().await = Some(token);
        configure(self.build_get(url).await).send().await.context("retrying request with auth token")
    }

    /// Fetches a manifest (or index) as raw bytes plus its content digest
    /// (computed locally from the response body — registries also return
    /// a `Docker-Content-Digest` header, but computing it ourselves is
    /// what actually proves the bytes we received are what we think they
    /// are, matching this project's "verify, don't trust the transport"
    /// bias elsewhere).
    pub async fn fetch_manifest_bytes(&self, reference: &ImageReference) -> Result<(Vec<u8>, Digest, String)> {
        let url = self.manifest_url(reference);
        let resp = self.get_with_auth(&url, |req| req.header(reqwest::header::ACCEPT, MANIFEST_ACCEPT_HEADER)).await?;
        let resp = resp.error_for_status().context("manifest fetch returned an error status")?;
        let media_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/vnd.oci.image.manifest.v1+json")
            .to_string();
        let bytes = resp.bytes().await.context("reading manifest body")?;
        let digest = Digest::of_bytes(&bytes);
        Ok((bytes.to_vec(), digest, media_type))
    }

    /// Downloads a blob into the file at `dest`, verifying its digest
    /// before returning success. If `resume_from` is given, sends a
    /// `Range: bytes=<resume_from>-` header and APPENDS to whatever is
    /// already at `dest` rather than truncating it, per the resume
    /// requirement — and, critically, re-hashes the WHOLE assembled file
    /// afterward rather than just the newly-streamed tail (see
    /// `hash_whole_file`'s doc comment for why). On a digest mismatch,
    /// `dest` is truncated back to empty rather than left holding corrupt
    /// bytes under a name that looks complete.
    ///
    /// Retries on 5xx/429 up to `MAX_BLOB_DOWNLOAD_ATTEMPTS` total
    /// attempts with exponential backoff; any other error status (e.g. a
    /// 404) is NOT retried — retrying a permanent client error would
    /// just waste time reproducing the same failure.
    pub async fn download_blob_verified(
        &self,
        reference: &ImageReference,
        digest: &Digest,
        dest: &Path,
        resume_from: Option<u64>,
    ) -> Result<()> {
        let url = self.blob_url(reference, digest);
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let resp = self
                .get_with_auth(&url, |req| match resume_from {
                    Some(from) => req.header(reqwest::header::RANGE, format!("bytes={from}-")),
                    None => req,
                })
                .await
                .context("sending blob request")?;

            if resp.status().is_server_error() || resp.status() == StatusCode::TOO_MANY_REQUESTS {
                if attempt >= MAX_BLOB_DOWNLOAD_ATTEMPTS {
                    anyhow::bail!("blob download failed after {attempt} attempts: {}", resp.status());
                }
                let backoff = Duration::from_millis(200 * 2u64.pow(attempt - 1));
                tokio::time::sleep(backoff).await;
                continue;
            }
            let resp = resp.error_for_status().context("blob download returned an error status")?;

            let streamed_digest = stream_to_file(resp, dest, resume_from).await?;

            // The streaming hash above only covers bytes received in
            // THIS request. On a fresh (non-resumed) download that's the
            // whole file, so it's the answer directly. On a resumed
            // download it's only the newly-fetched tail — bytes a prior
            // attempt already wrote to `dest` aren't included — so it
            // must NOT be compared against the full-blob digest; the
            // whole file has to be re-read and hashed instead.
            let actual = match resume_from {
                Some(_) => hash_whole_file(dest).await?,
                None => streamed_digest,
            };

            if &actual != digest {
                // Truncate back to empty rather than leave corrupt bytes
                // under a name that looks complete.
                let _ = tokio::fs::File::create(dest).await;
                anyhow::bail!("blob digest mismatch: expected {digest}, got {actual}");
            }
            return Ok(());
        }
    }
}

/// Streams `resp`'s body into `dest` — appending if `resume_from` is
/// `Some` (the file is expected to already hold the first `resume_from`
/// bytes), truncating/creating fresh otherwise — hashing each chunk as
/// it arrives. Returns the digest of just the bytes streamed in THIS
/// call; see `download_blob_verified` for why that's only usable
/// directly in the non-resume case.
async fn stream_to_file(resp: reqwest::Response, dest: &Path, resume_from: Option<u64>) -> Result<Digest> {
    use sha2::{Digest as _, Sha256};
    use tokio::io::AsyncWriteExt;

    let mut file = if resume_from.is_some() {
        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dest)
            .await
            .with_context(|| format!("opening {} to resume download", dest.display()))?
    } else {
        tokio::fs::File::create(dest).await.with_context(|| format!("creating {}", dest.display()))?
    };

    let mut hasher = Sha256::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("reading blob chunk")?;
        hasher.update(&chunk);
        file.write_all(&chunk).await.context("writing blob chunk")?;
    }
    file.flush().await.context("flushing blob file")?;

    format!("sha256:{:x}", hasher.finalize()).parse().context("formatting streamed-chunk digest")
}

/// Re-opens `path` and hashes its ENTIRE contents from the start. `sha2`'s
/// `Sha256` can't have its internal state restored from a partial digest,
/// so there is no way to "resume" a hash computed only over the
/// newly-streamed tail of a resumed download — the only correct way to
/// verify a resumed download's digest is to re-read the fully assembled
/// file and hash it in one pass, which is what this does. Runs the
/// (synchronous, but on a real blob far too large to want on the async
/// executor thread) read-and-hash loop via `spawn_blocking`, reusing
/// `VerifyingReader` from `digest.rs` rather than duplicating its logic.
async fn hash_whole_file(path: &Path) -> Result<Digest> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<Digest> {
        let file = std::fs::File::open(&path).with_context(|| format!("opening {} to verify", path.display()))?;
        let mut reader = VerifyingReader::new(file);
        std::io::copy(&mut reader, &mut std::io::sink()).with_context(|| format!("hashing {}", path.display()))?;
        Ok(reader.finish())
    })
    .await
    .context("hashing task panicked")?
}
