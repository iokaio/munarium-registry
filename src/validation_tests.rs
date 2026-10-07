// SPDX-License-Identifier: Apache-2.0
use super::*;
use serde_json::json;

#[test]
fn canonical_encoding_and_size_depth_boundaries_fail_closed() {
    for bytes in [
        br#"{"a":1,"a":2}"#.as_slice(),
        br#"{"a":1,"\u0061":2}"#,
        br#"{"a":-0}"#,
        br#"{"a":1e0}"#,
        br#"{"a":9007199254740992}"#,
        br#"{"a":-9007199254740992}"#,
        br#"{"a":"\ud800"}"#,
        b"{\"a\":\"\xff\"}",
        b"\xef\xbb\xbf{}",
        b"{}\n",
        br#"{"a":null, "b":false}"#,
        b"[]",
        "{\"é\":1}".as_bytes(),
    ] {
        assert_eq!(
            canonical(bytes, MAX_JSON),
            Err(Error::InvalidArtifact),
            "{bytes:?}"
        );
    }
    for bytes in [
        br#"{"a":null,"b":false}"#.as_slice(),
        br#"{"a":9007199254740991}"#,
        br#"{"a":-9007199254740991}"#,
        "{\"a\":\"é😀\"}".as_bytes(),
    ] {
        canonical(bytes, MAX_JSON).unwrap();
    }
    let exact = format!("{{\"a\":\"{}\"}}", "x".repeat(65_528));
    assert_eq!(exact.len(), MAX_JSON);
    canonical(exact.as_bytes(), MAX_JSON).unwrap();
    let oversized = format!("{{\"a\":\"{}\"}}", "x".repeat(65_529));
    assert!(canonical(oversized.as_bytes(), MAX_JSON).is_err());
    let depth16 = format!("{{\"a\":{}0{}}}", "[".repeat(15), "]".repeat(15));
    canonical(depth16.as_bytes(), MAX_JSON).unwrap();
    let depth17 = format!("{{\"a\":{}0{}}}", "[".repeat(16), "]".repeat(16));
    assert!(canonical(depth17.as_bytes(), MAX_JSON).is_err());
}

#[test]
fn capability_profile_rejects_ignored_keywords_references_and_unbounded_shapes() {
    let dialect = "https://json-schema.org/draft/2020-12/schema";
    for value in [
        json!({"$schema":dialect,"type":"string","minLength":0,"maxLength":4097}),
        json!({"$schema":dialect,"type":"string","minLength":2,"maxLength":1}),
        json!({"$schema":dialect,"type":"integer","minimum":0,"maximum":1.0}),
        json!({"$schema":dialect,"type":"boolean","format":"ignored"}),
        json!({"$schema":dialect,"$ref":"https://invalid.example/schema"}),
        json!({"$schema":dialect,"type":"object","properties":{},"required":["absent"],"additionalProperties":false}),
        json!({"$schema":dialect,"type":"object","properties":{},"required":[],"additionalProperties":true}),
        json!({"$schema":dialect,"type":"array","minItems":0,"maxItems":257,"items":{"type":"boolean"}}),
    ] {
        assert!(
            capability_schema(&serde_json::to_vec(&value).unwrap()).is_err(),
            "{value}"
        );
    }
    for value in [
        json!({"$schema":dialect,"type":"boolean"}),
        json!({"$schema":dialect,"type":"string","minLength":0,"maxLength":4096}),
        json!({"$schema":dialect,"type":"integer","minimum":-9007199254740991_i64,"maximum":9007199254740991_i64}),
        json!({"$schema":dialect,"type":"array","minItems":0,"maxItems":256,"items":{"type":"boolean"}}),
        json!({"$schema":dialect,"type":"object","properties":{},"required":[],"additionalProperties":false}),
    ] {
        capability_schema(&serde_json::to_vec(&value).unwrap()).unwrap();
    }
    let mut node = json!({"type":"boolean"});
    for _ in 0..7 {
        node = json!({"type":"array","items":node,"minItems":0,"maxItems":1});
    }
    node["$schema"] = json!(dialect);
    capability_schema(&serde_json::to_vec(&node).unwrap()).unwrap();
    node.as_object_mut().unwrap().remove("$schema");
    node = json!({"$schema":dialect,"type":"array","items":node,"minItems":0,"maxItems":1});
    assert!(capability_schema(&serde_json::to_vec(&node).unwrap()).is_err());

    let leaves: serde_json::Map<String, Value> = (0..16)
        .map(|i| (format!("leaf{i}"), json!({"type":"boolean"})))
        .collect();
    let branch =
        json!({"type":"object","properties":leaves,"required":[],"additionalProperties":false});
    let branches: serde_json::Map<String, Value> = (0..15)
        .map(|i| (format!("branch{i}"), branch.clone()))
        .collect();
    let mut exact = json!({"$schema":dialect,"type":"object","properties":branches,"required":[],"additionalProperties":false});
    capability_schema(&serde_json::to_vec(&exact).unwrap()).unwrap(); // 1 + 15 * 17 = 256
    exact["properties"]["extra"] = json!({"type":"boolean"});
    assert!(capability_schema(&serde_json::to_vec(&exact).unwrap()).is_err());
}
