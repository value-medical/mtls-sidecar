use hyper::header::{HeaderName, HeaderValue, HOST};
use hyper::HeaderMap;

/// Filters headers based on common rules and optional x-client header filtering.
///
/// # Arguments
/// * `headers` - The header map to filter
/// * `filter_x_client` - Whether to filter out headers starting with "x-client-"
///
/// # Returns
/// An iterator over the filtered headers
pub fn filter_headers(
    headers: &HeaderMap,
    filter_x_client: bool,
) -> impl Iterator<Item = (&HeaderName, &HeaderValue)> {
    headers.iter().filter(move |(key, _)| {
        if key == &HOST {
            false
        } else if key.as_str().starts_with("proxy-") {
            false
        } else if filter_x_client && key.as_str().starts_with("x-client-") {
            false
        } else {
            true
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;

    #[test]
    fn test_filter_headers_basic() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "example.com".parse().unwrap());
        headers.insert("proxy-auth", "value".parse().unwrap());
        headers.insert("x-client-test", "value".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());

        // With filter_x_client = false
        let filtered: Vec<_> = filter_headers(&headers, false).collect();
        let keys: Vec<_> = filtered.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains(&"host"));
        assert!(!keys.contains(&"proxy-auth"));
        assert!(keys.contains(&"x-client-test"));
        assert!(keys.contains(&"content-type"));

        // With filter_x_client = true
        let filtered: Vec<_> = filter_headers(&headers, true).collect();
        let keys: Vec<_> = filtered.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains(&"host"));
        assert!(!keys.contains(&"proxy-auth"));
        assert!(!keys.contains(&"x-client-test"));
        assert!(keys.contains(&"content-type"));
    }
}
