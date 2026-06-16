use pumpbin::plugin::Plugin;
use pumpbin::{BinaryType, Platform, ShellcodeSaveType};

fn make_test_plugin() -> Plugin {
    let template = b"HEADER$$SHELLCODE$$PADDING0000$$99999$$TAIL";
    pumpbin::pack::B1nBuilder {
        template_bytes: template.to_vec(),
        name: "roundtrip-test".to_string(),
        author: "test".to_string(),
        plugin_version: "1.0.0".to_string(),
        desc: "Round-trip test plugin".to_string(),
        platform: Platform::Linux,
        binary_type: BinaryType::Executable,
        save_type: ShellcodeSaveType::Local,
        src_prefix: "$$SHELLCODE$$".to_string(),
        size_holder: "$$99999$$".to_string(),
        max_len_override: None,
        primary_module: None,
        post_modules: vec![],
        module_config: Default::default(),
    }
    .assemble()
    .and_then(|bytes| Plugin::decode_from_slice(&bytes))
    .expect("failed to build test plugin")
}

#[test]
fn encode_decode_roundtrip_preserves_fields() {
    let original = make_test_plugin();

    let encoded = original.encode_to_vec().expect("encode failed");
    let decoded = Plugin::decode_from_slice(&encoded).expect("decode failed");

    assert_eq!(decoded.info().plugin_name(), original.info().plugin_name());
    assert_eq!(decoded.info().author(), original.info().author());
    assert_eq!(decoded.info().version(), original.info().version());
    assert_eq!(decoded.info().desc(), original.info().desc());

    assert_eq!(
        decoded.replace().src_prefix(),
        original.replace().src_prefix()
    );
    assert_eq!(
        decoded.replace().size_holder(),
        original.replace().size_holder()
    );
    assert_eq!(decoded.replace().max_len(), original.replace().max_len());

    assert_eq!(
        decoded
            .bins()
            .has_binary(Platform::Linux, BinaryType::Executable),
        original
            .bins()
            .has_binary(Platform::Linux, BinaryType::Executable),
    );
    assert!(!decoded
        .bins()
        .has_binary(Platform::Windows, BinaryType::Executable));
}

#[test]
fn double_roundtrip_is_stable() {
    let original = make_test_plugin();
    let enc1 = original.encode_to_vec().unwrap();
    let dec1 = Plugin::decode_from_slice(&enc1).unwrap();
    let enc2 = dec1.encode_to_vec().unwrap();
    let dec2 = Plugin::decode_from_slice(&enc2).unwrap();

    assert_eq!(dec2.info().plugin_name(), original.info().plugin_name());
    assert_eq!(
        dec2.bins()
            .get_that_binary(Platform::Linux, BinaryType::Executable),
        original
            .bins()
            .get_that_binary(Platform::Linux, BinaryType::Executable),
    );
}

#[test]
fn decode_garbage_errors() {
    assert!(Plugin::decode_from_slice(b"this is not a plugin").is_err());
    assert!(Plugin::decode_from_slice(&[]).is_err());
}
