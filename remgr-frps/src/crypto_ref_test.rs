// Quick check: our Cfb + pbkdf2 must match the Go reference output.
#[test]
fn cfb_matches_go_reference() {
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(b"test123", b"frp", 64, &mut key);
    assert_eq!(hex_str(&key), "9b5d8b1c03c1963651fc65d3c394ca13");

    let iv = [0xAAu8; 16];
    let mut cfb = Cfb::new(&key, &iv, false);
    let mut data = b"hello frp world, this is a CFB test payload!!".to_vec();
    cfb.apply(&mut data);
    assert_eq!(
        hex_str(&data),
        "574751e5e7da738cf520b7b405523edd5871db98ba2dfff5dd16fb5b26b9778ef2189e15b39c92826d43d94022"
    );
}

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
