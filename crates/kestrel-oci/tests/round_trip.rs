use kestrel_oci::raw::RawSpec;

const FIXTURE: &str = include_str!("fixtures/oci_example_config.json");

/// `process.capabilities.{bounding,effective,inheritable,permitted,ambient}`
/// are modeled by `oci-spec` as `HashSet<Capability>`, not an ordered list
/// (the OCI runtime spec treats them as sets, and set membership - not
/// order - is what's semantically meaningful for capabilities). That means
/// a parse-then-reserialize round trip can legitimately permute the
/// elements of those five arrays without losing or adding any data. Sort
/// them in both documents before comparing so the assertion below stays
/// strict about every other field (no field may be added, dropped, or have
/// its order changed) while tolerating the one field that's genuinely
/// unordered.
fn normalize_capability_sets(value: &mut serde_json::Value) {
    if let Some(serde_json::Value::Object(caps)) = value.pointer_mut("/process/capabilities") {
        for set in caps.values_mut() {
            if let serde_json::Value::Array(arr) = set {
                arr.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
            }
        }
    }
}

#[test]
fn test_official_example_round_trips_without_loss() {
    let parsed: RawSpec = serde_json::from_str(FIXTURE).expect("parse fixture");
    let mut reserialized = serde_json::to_value(&parsed).expect("serialize back");
    let mut original: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    normalize_capability_sets(&mut reserialized);
    normalize_capability_sets(&mut original);
    assert_eq!(
        reserialized, original,
        "round trip must not add, drop, or reorder-lose fields"
    );
}

#[test]
fn test_unknown_top_level_field_survives_round_trip() {
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    value["ociVendorExtensionField"] = serde_json::json!("kept-me");

    let parsed: RawSpec = serde_json::from_value(value.clone()).expect("parse with extra field");
    let reserialized = serde_json::to_value(&parsed).expect("serialize back");

    assert_eq!(
        reserialized.get("ociVendorExtensionField"),
        Some(&serde_json::json!("kept-me")),
        "unknown field must survive the round trip (forward compatibility)"
    );
}
