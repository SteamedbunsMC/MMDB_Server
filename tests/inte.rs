use MMDB_Server::*;

#[test]
fn testcrypt() {
    assert_eq!(
        "678uijhgyt78u9ijhugyt7y89iokjhgyt7689iojkhuy89iokljiu89i0okjiu89ioji".to_string(),
        decrypt(
            crypt(
                "678uijhgyt78u9ijhugyt7y89iokjhgyt7689iojkhuy89iokljiu89i0okjiu89ioji".to_string(),
                "testkey".to_string()
            ),
            "testkey".to_string()
        )
    );
}
