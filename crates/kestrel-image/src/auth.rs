use anyhow::{Context, Result};
use reqwest::header::HeaderMap;

/// A parsed `WWW-Authenticate: Bearer realm="...",service="...",scope="..."`
/// challenge, per the Docker Registry HTTP API V2 auth spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerChallenge {
    pub realm: String,
    pub service: Option<String>,
    pub scope: Option<String>,
}

/// Parses the `WWW-Authenticate` header from a 401 response. Only the
/// `Bearer` scheme is handled (what every major registry, including
/// Docker Hub, actually uses); `Basic` challenges are treated as "no
/// bearer challenge found" and the caller falls back accordingly.
pub fn parse_www_authenticate(headers: &HeaderMap) -> Result<Option<BearerChallenge>> {
    let Some(value) = headers.get(reqwest::header::WWW_AUTHENTICATE) else { return Ok(None) };
    let value = value.to_str().context("WWW-Authenticate header is not valid UTF-8")?;
    let Some(rest) = value.strip_prefix("Bearer ") else { return Ok(None) };

    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for pair in split_challenge_params(rest) {
        let Some((key, val)) = pair.split_once('=') else { continue };
        let val = val.trim_matches('"').to_string();
        match key {
            "realm" => realm = Some(val),
            "service" => service = Some(val),
            "scope" => scope = Some(val),
            _ => {}
        }
    }

    let realm = realm.context("Bearer challenge missing realm")?;
    Ok(Some(BearerChallenge { realm, service, scope }))
}

/// Splits `key="value with, commas",key2="value2"` on the commas that
/// separate PARAMETERS, not the ones that might appear inside a quoted
/// value — tracks quote state rather than a naive `split(',')`.
fn split_challenge_params(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                parts.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(s[start..].trim());
    parts
}

/// Fetches a bearer token from `challenge.realm`, with `service`/`scope`
/// query parameters if the challenge specified them. Anonymous (no
/// credentials) — CHECKLIST.md's 🟡 basic-auth item is out of scope for
/// this task's core flow but the `Client` parameter here is where it
/// would plug in later (`.basic_auth(user, Some(pass))` before `.send()`).
pub async fn fetch_token(client: &reqwest::Client, challenge: &BearerChallenge) -> Result<String> {
    let mut req = client.get(&challenge.realm);
    if let Some(service) = &challenge.service {
        req = req.query(&[("service", service)]);
    }
    if let Some(scope) = &challenge.scope {
        req = req.query(&[("scope", scope)]);
    }
    let resp = req.send().await.context("requesting auth token")?;
    let resp = resp.error_for_status().context("token endpoint returned an error status")?;
    let body: serde_json::Value = resp.json().await.context("parsing token response as JSON")?;
    // Registries use either "token" or "access_token" for the same thing.
    body.get("token")
        .or_else(|| body.get("access_token"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .context("token response missing both \"token\" and \"access_token\" fields")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(reqwest::header::WWW_AUTHENTICATE, value.parse().unwrap());
        h
    }

    #[test]
    fn test_parse_full_bearer_challenge() {
        let h = headers_with(r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#);
        let c = parse_www_authenticate(&h).unwrap().unwrap();
        assert_eq!(c.realm, "https://auth.docker.io/token");
        assert_eq!(c.service.as_deref(), Some("registry.docker.io"));
        assert_eq!(c.scope.as_deref(), Some("repository:library/alpine:pull"));
    }

    #[test]
    fn test_parse_realm_only() {
        let h = headers_with(r#"Bearer realm="https://example.com/token""#);
        let c = parse_www_authenticate(&h).unwrap().unwrap();
        assert_eq!(c.realm, "https://example.com/token");
        assert_eq!(c.service, None);
    }

    #[test]
    fn test_parse_no_header_returns_none() {
        let h = HeaderMap::new();
        assert_eq!(parse_www_authenticate(&h).unwrap(), None);
    }

    #[test]
    fn test_parse_basic_scheme_returns_none() {
        let h = headers_with(r#"Basic realm="something""#);
        assert_eq!(parse_www_authenticate(&h).unwrap(), None);
    }

    #[test]
    fn test_parse_missing_realm_is_an_error() {
        let h = headers_with(r#"Bearer service="registry.docker.io""#);
        assert!(parse_www_authenticate(&h).is_err());
    }
}
