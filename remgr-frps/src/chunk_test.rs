//! Round-trip: both ends are CryptoStreams, exactly like a frp control pair.

#[tokio::test]
async fn chunked_roundtrip() {
    let (a, b) = tokio::io::duplex(64);
    let mut reader = crate::crypto::CryptoStream::new(b, b"test123");
    let mut writer = crate::crypto::CryptoStream::new(a, b"test123");

    let wtask = tokio::spawn(async move {
        let body = b"{\"version\":\"0.61.2\"}";
        crate::msg::write_frame(&mut writer, b'1', body).await.unwrap();
        let body2 = vec![b'x'; 138];
        crate::msg::write_frame(&mut writer, b'p', &body2).await.unwrap();
    });

    let (tb, body) = crate::msg::read_frame(&mut reader).await.unwrap();
    assert_eq!(tb, b'1');
    assert_eq!(&body, b"{\"version\":\"0.61.2\"}");
    let (tb2, body2) = crate::msg::read_frame(&mut reader).await.unwrap();
    assert_eq!(tb2, b'p');
    assert_eq!(body2.len(), 138);
    assert!(body2.iter().all(|&b| b == b'x'));
    wtask.await.unwrap();
}

#[tokio::test]
async fn byte_by_byte_read() {
    let (a, b) = tokio::io::duplex(64);
    let mut reader = crate::crypto::CryptoStream::new(b, b"test123");
    let mut writer = crate::crypto::CryptoStream::new(a, b"test123");
    let wtask = tokio::spawn(async move {
        crate::msg::write_frame(&mut writer, b'p', &vec![b'q'; 138]).await.unwrap();
    });
    use tokio::io::AsyncReadExt;
    let mut hdr = [0u8; 9];
    for b in hdr.iter_mut() {
        reader.read_exact(std::slice::from_mut(b)).await.unwrap();
    }
    assert_eq!(hdr[0], b'p');
    let len = i64::from_be_bytes(hdr[1..9].try_into().unwrap());
    assert_eq!(len, 138);
    let mut body = vec![0u8; 138];
    for b in body.iter_mut() {
        reader.read_exact(std::slice::from_mut(b)).await.unwrap();
    }
    assert!(body.iter().all(|&b| b == b'q'));
    wtask.await.unwrap();
}
