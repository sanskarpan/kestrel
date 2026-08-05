use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use kestrel_image::auth::{fetch_token, BearerChallenge};
use kestrel_image::digest::Digest;
use kestrel_image::manifest::MANIFEST_ACCEPT_HEADER;
use kestrel_image::reference;
use kestrel_image::registry::RegistryClient;
use wiremock::matchers::{header, headers, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

#[tokio::test]
async fn test_fetch_token_sends_service_and_scope_and_parses_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .and(query_param("service", "registry.example.com"))
        .and(query_param("scope", "repository:foo:pull"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "token": "test-token-123" })))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let challenge = BearerChallenge {
        realm: format!("{}/token", server.uri()),
        service: Some("registry.example.com".to_string()),
        scope: Some("repository:foo:pull".to_string()),
    };
    let token = fetch_token(&client, &challenge).await.unwrap();
    assert_eq!(token, "test-token-123");
}

#[tokio::test]
async fn test_fetch_token_accepts_access_token_field_too() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "access_token": "alt-field-token" })))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let challenge = BearerChallenge { realm: format!("{}/token", server.uri()), service: None, scope: None };
    let token = fetch_token(&client, &challenge).await.unwrap();
    assert_eq!(token, "alt-field-token");
}

// --- Task 7: RegistryClient (manifest fetch, auth-retry, blob download,
// resume, retry-on-server-error) ---
//
// All of these point a `RegistryClient` at a `wiremock` server via
// `RegistryClient::with_base_url`, which talks plain HTTP to whatever base
// URL it's given instead of deriving an `https://<host>` URL from the
// image reference — the reference's registry/repository still drive the
// URL *path*, just not the scheme+host, since `wiremock` only ever serves
// HTTP.

fn test_reference() -> kestrel_image::reference::ImageReference {
    reference::parse("myrepo/myimage:latest").unwrap()
}

#[tokio::test]
async fn test_fetch_manifest_bytes_sends_accept_header_and_returns_bytes_digest_and_media_type() {
    let server = MockServer::start().await;
    let body = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#.to_vec();
    Mock::given(method("GET"))
        .and(path("/v2/myrepo/myimage/manifests/latest"))
        // `wiremock`'s `header()` matcher splits the actual header value on
        // commas and expects the same count of expected values, so a
        // single comma-joined `Accept` value needs `headers()` (plural)
        // with each media type as its own element, not `header()`.
        .and(headers(
            "accept",
            MANIFEST_ACCEPT_HEADER.split(", ").collect::<Vec<_>>(),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(body.clone())
                .insert_header("content-type", "application/vnd.oci.image.manifest.v1+json"),
        )
        .mount(&server)
        .await;

    let client = RegistryClient::with_base_url(server.uri()).unwrap();
    let (bytes, digest, media_type) = client.fetch_manifest_bytes(&test_reference()).await.unwrap();

    assert_eq!(bytes, body);
    assert_eq!(digest, Digest::of_bytes(&body), "digest must be computed locally from the body, not trusted from a header");
    assert_eq!(media_type, "application/vnd.oci.image.manifest.v1+json");
}

#[tokio::test]
async fn test_manifest_fetch_retries_once_after_401_then_succeeds_with_token() {
    let server = MockServer::start().await;
    let body = br#"{"schemaVersion":2}"#.to_vec();

    Mock::given(method("GET"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "token": "retried-token" })))
        .mount(&server)
        .await;

    let www_authenticate = format!(r#"Bearer realm="{}/token",service="test-registry""#, server.uri());
    let manifest_body = body.clone();
    Mock::given(method("GET"))
        .and(path("/v2/myrepo/myimage/manifests/latest"))
        .respond_with(move |req: &Request| {
            let authorized =
                req.headers.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer retried-token");
            if authorized {
                ResponseTemplate::new(200).set_body_bytes(manifest_body.clone())
            } else {
                ResponseTemplate::new(401).insert_header("www-authenticate", www_authenticate.as_str())
            }
        })
        .mount(&server)
        .await;

    let client = RegistryClient::with_base_url(server.uri()).unwrap();
    let (bytes, _digest, _media_type) = client.fetch_manifest_bytes(&test_reference()).await.unwrap();
    assert_eq!(bytes, body, "must end up with the manifest body after the auth retry, not the 401");

    // One unauthenticated manifest request (401), one token request, one
    // authenticated manifest request that succeeds.
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3, "expected exactly one auth-retry, not zero or more than one: {requests:#?}");
}

#[tokio::test]
async fn test_download_blob_verified_accepts_correct_digest() {
    let server = MockServer::start().await;
    let content = b"hello from the registry, this is a blob".to_vec();
    let digest = Digest::of_bytes(&content);

    Mock::given(method("GET"))
        .and(path(format!("/v2/myrepo/myimage/blobs/{digest}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(content.clone()))
        .mount(&server)
        .await;

    let client = RegistryClient::with_base_url(server.uri()).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("blob");

    client.download_blob_verified(&test_reference(), &digest, &dest, None).await.unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), content);
}

#[tokio::test]
async fn test_download_blob_verified_rejects_digest_mismatch_and_truncates_dest() {
    let server = MockServer::start().await;
    let wrong_bytes = b"these are not the bytes you're looking for".to_vec();
    let expected_digest = Digest::of_bytes(b"the actual correct content");

    Mock::given(method("GET"))
        .and(path(format!("/v2/myrepo/myimage/blobs/{expected_digest}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(wrong_bytes))
        .mount(&server)
        .await;

    let client = RegistryClient::with_base_url(server.uri()).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("blob");

    let err = client.download_blob_verified(&test_reference(), &expected_digest, &dest, None).await.unwrap_err();
    assert!(err.to_string().contains("digest mismatch"), "unexpected error: {err}");
    assert_eq!(std::fs::read(&dest).unwrap().len(), 0, "dest must be truncated back to empty on mismatch, not left holding corrupt bytes");
}

#[tokio::test]
async fn test_download_blob_verified_resume_sends_range_header_and_verifies_the_whole_reassembled_file() {
    let server = MockServer::start().await;
    let full_content = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec();
    let digest = Digest::of_bytes(&full_content);
    let split_at = 10usize;
    let (already_have, remaining) = full_content.split_at(split_at);

    Mock::given(method("GET"))
        .and(path(format!("/v2/myrepo/myimage/blobs/{digest}")))
        .and(header("range", format!("bytes={split_at}-").as_str()))
        .respond_with(ResponseTemplate::new(206).set_body_bytes(remaining.to_vec()))
        .mount(&server)
        .await;

    let client = RegistryClient::with_base_url(server.uri()).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("blob");
    // Simulate a prior attempt that got cut off after writing the first
    // `split_at` bytes.
    std::fs::write(&dest, already_have).unwrap();

    client.download_blob_verified(&test_reference(), &digest, &dest, Some(split_at as u64)).await.unwrap();

    assert_eq!(std::fs::read(&dest).unwrap(), full_content, "resume must APPEND to the existing bytes, reassembling the full original content");

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].headers.get("range").and_then(|v| v.to_str().ok()),
        Some(format!("bytes={split_at}-").as_str()),
        "the Range header must actually be sent on a resumed request"
    );
}

#[tokio::test]
async fn test_download_blob_verified_resume_catches_corruption_in_the_previously_written_portion() {
    // This is the case the naive "hash only the resumed tail" approach
    // gets wrong: the newly-streamed bytes match perfectly, but bytes a
    // prior attempt already wrote to `dest` were corrupted, so the FULL
    // assembled file does not match `digest`. Only re-hashing the whole
    // file catches this.
    let server = MockServer::start().await;
    let full_content = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec();
    let digest = Digest::of_bytes(&full_content);
    let split_at = 10usize;
    let remaining = &full_content[split_at..];

    Mock::given(method("GET"))
        .and(path(format!("/v2/myrepo/myimage/blobs/{digest}")))
        .and(header("range", format!("bytes={split_at}-").as_str()))
        .respond_with(ResponseTemplate::new(206).set_body_bytes(remaining.to_vec()))
        .mount(&server)
        .await;

    let client = RegistryClient::with_base_url(server.uri()).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("blob");
    let mut corrupted_prefix = full_content[..split_at].to_vec();
    corrupted_prefix[0] ^= 0xFF; // flip a byte in what "the prior attempt" wrote
    std::fs::write(&dest, &corrupted_prefix).unwrap();

    let err =
        client.download_blob_verified(&test_reference(), &digest, &dest, Some(split_at as u64)).await.unwrap_err();
    assert!(err.to_string().contains("digest mismatch"), "must catch corruption in the pre-resume portion, not just verify the resumed tail: {err}");
    assert_eq!(std::fs::read(&dest).unwrap().len(), 0, "must truncate the corrupt assembled file rather than leave it looking complete");
}

#[tokio::test]
async fn test_download_blob_verified_retries_503_twice_then_succeeds() {
    let server = MockServer::start().await;
    let content = b"eventually this blob shows up".to_vec();
    let digest = Digest::of_bytes(&content);
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_responder = calls.clone();
    let body_for_responder = content.clone();

    Mock::given(method("GET"))
        .and(path(format!("/v2/myrepo/myimage/blobs/{digest}")))
        .respond_with(move |_req: &Request| {
            let n = calls_for_responder.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                ResponseTemplate::new(503)
            } else {
                ResponseTemplate::new(200).set_body_bytes(body_for_responder.clone())
            }
        })
        .mount(&server)
        .await;

    let client = RegistryClient::with_base_url(server.uri()).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("blob");

    client.download_blob_verified(&test_reference(), &digest, &dest, None).await.unwrap();

    assert_eq!(std::fs::read(&dest).unwrap(), content);
    assert_eq!(calls.load(Ordering::SeqCst), 3, "must retry exactly twice (3 total requests) before succeeding, not give up early or retry forever");
}

#[tokio::test]
async fn test_download_blob_verified_does_not_retry_a_404() {
    let server = MockServer::start().await;
    let digest = Digest::of_bytes(b"this blob does not exist on the registry");
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_responder = calls.clone();

    Mock::given(method("GET"))
        .and(path(format!("/v2/myrepo/myimage/blobs/{digest}")))
        .respond_with(move |_req: &Request| {
            calls_for_responder.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(404)
        })
        .mount(&server)
        .await;

    let client = RegistryClient::with_base_url(server.uri()).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("blob");

    let result = client.download_blob_verified(&test_reference(), &digest, &dest, None).await;
    assert!(result.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1, "a permanent client error like 404 must not be retried");
}
