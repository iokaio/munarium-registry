// SPDX-License-Identifier: Apache-2.0
//! Bounded candidate JSON and contract validation; no network or authority lookup.

use crate::candidate::Error;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[cfg(test)]
#[path = "validation_tests.rs"]
mod tests;

pub(crate) const MAX_JSON: usize = 65_536;
const SAFE: i64 = 9_007_199_254_740_991;

pub(crate) fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b":._/-".contains(&c))
}

pub(crate) fn is_digest(s: &str) -> bool {
    s.len() == 71
        && s.starts_with("sha256:")
        && s.as_bytes()[7..]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}

pub(crate) fn digest(domain: &str, bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update(bytes);
    format!("sha256:{:x}", hash.finalize())
}

fn profile(value: &Value, depth: usize) -> Result<(), Error> {
    match value {
        Value::Object(items) => {
            if depth >= 16 || items.keys().any(|k| !k.is_ascii()) {
                return Err(Error::InvalidArtifact);
            }
            for item in items.values() {
                profile(item, depth + 1)?;
            }
        }
        Value::Array(items) => {
            if depth >= 16 {
                return Err(Error::InvalidArtifact);
            }
            for item in items {
                profile(item, depth + 1)?;
            }
        }
        Value::Number(n) if n.as_i64().is_none_or(|n| !(-SAFE..=SAFE).contains(&n)) => {
            return Err(Error::InvalidArtifact);
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn canonical(bytes: &[u8], limit: usize) -> Result<Value, Error> {
    if bytes.len() > limit {
        return Err(Error::InvalidArtifact);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Error::InvalidArtifact)?;
    if !value.is_object() {
        return Err(Error::InvalidArtifact);
    }
    profile(&value, 0)?;
    // Equality also rejects duplicate decoded keys: a map cannot serialize to
    // an input containing the same key twice.
    if serde_json::to_vec(&value).map_err(|_| Error::InvalidArtifact)? != bytes {
        return Err(Error::InvalidArtifact);
    }
    Ok(value)
}

pub(crate) fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, Error> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or(Error::InvalidManifest)
}

pub(crate) fn array<'a>(v: &'a Value, key: &str) -> Result<&'a Vec<Value>, Error> {
    v.get(key)
        .and_then(Value::as_array)
        .ok_or(Error::InvalidManifest)
}

// Only the vocabulary in the immutable bundled contract is supported.
pub(crate) fn shape(v: &Value, s: &Value, root: &Value) -> Result<(), Error> {
    let schema = s.as_object().ok_or(Error::InvalidManifest)?;
    let allowed = [
        "$ref",
        "anyOf",
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minLength",
        "maxLength",
        "pattern",
        "minimum",
        "maximum",
        "const",
        "enum",
    ];
    if schema.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(Error::InvalidManifest);
    }
    if let Some(alternatives) = s.get("anyOf") {
        if schema.len() != 1 {
            return Err(Error::InvalidManifest);
        }
        return if alternatives
            .as_array()
            .is_some_and(|choices| choices.iter().any(|choice| shape(v, choice, root).is_ok()))
        {
            Ok(())
        } else {
            Err(Error::InvalidManifest)
        };
    }
    if let Some(reference) = s.get("$ref").and_then(Value::as_str) {
        if schema.len() != 1 || !reference.starts_with("#/$defs/") {
            return Err(Error::InvalidManifest);
        }
        return shape(
            v,
            root.pointer(&reference[1..])
                .ok_or(Error::InvalidManifest)?,
            root,
        );
    }
    if s.get("const").is_some_and(|c| c != v)
        || s.get("enum")
            .and_then(Value::as_array)
            .is_some_and(|e| !e.contains(v))
    {
        return Err(Error::InvalidManifest);
    }
    let valid = match s.get("type").and_then(Value::as_str) {
        Some("object") => {
            let values = v.as_object().ok_or(Error::InvalidManifest)?;
            let props = s["properties"].as_object().ok_or(Error::InvalidManifest)?;
            if s["additionalProperties"] != false
                || values.keys().any(|k| !props.contains_key(k))
                || array(s, "required")?
                    .iter()
                    .any(|k| k.as_str().is_none_or(|k| !values.contains_key(k)))
            {
                return Err(Error::InvalidManifest);
            }
            for (key, value) in values {
                shape(value, &props[key], root)?;
            }
            true
        }
        Some("array") => {
            let values = v.as_array().ok_or(Error::InvalidManifest)?;
            bounds(values.len() as i64, s, "minItems", "maxItems")?;
            for (index, value) in values.iter().enumerate() {
                if s["uniqueItems"] == true && values[..index].contains(value) {
                    return Err(Error::InvalidManifest);
                }
                shape(value, &s["items"], root)?;
            }
            true
        }
        Some("string") => {
            let value = v.as_str().ok_or(Error::InvalidManifest)?;
            bounds(value.chars().count() as i64, s, "minLength", "maxLength")?;
            match s.get("pattern").and_then(Value::as_str) {
                None => true,
                Some("^[a-zA-Z0-9][a-zA-Z0-9:._/-]*$") => identifier(value),
                Some("^sha256:[0-9a-f]{64}$") => is_digest(value),
                Some(_) => false,
            }
        }
        Some("integer") => {
            let value = v.as_i64().ok_or(Error::InvalidManifest)?;
            bounds(value, s, "minimum", "maximum")?;
            true
        }
        Some("boolean") => v.is_boolean(),
        Some("null") => v.is_null(),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidManifest)
    }
}

fn bounds(n: i64, schema: &Value, min: &str, max: &str) -> Result<(), Error> {
    if schema
        .get(min)
        .and_then(Value::as_i64)
        .is_some_and(|min| n < min)
        || schema
            .get(max)
            .and_then(Value::as_i64)
            .is_some_and(|max| n > max)
    {
        Err(Error::InvalidManifest)
    } else {
        Ok(())
    }
}

pub(crate) fn capability_schema(raw: &[u8]) -> Result<(), Error> {
    let value = canonical(raw, MAX_JSON)?;
    if value["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
        return Err(Error::MissingReference);
    }
    schema_node(&value, 0, &mut 0)
}

fn schema_node(s: &Value, depth: usize, nodes: &mut usize) -> Result<(), Error> {
    *nodes += 1;
    if depth >= 8 || *nodes > 256 {
        return Err(Error::MissingReference);
    }
    let fields = s.as_object().ok_or(Error::MissingReference)?;
    let kind = text(s, "type")?;
    let expected: &[&str] = match kind {
        "object" => &["type", "properties", "required", "additionalProperties"],
        "array" => &["type", "items", "minItems", "maxItems"],
        "string" => &["type", "minLength", "maxLength"],
        "integer" => &["type", "minimum", "maximum"],
        "boolean" => &["type"],
        _ => return Err(Error::MissingReference),
    };
    if fields.len() != expected.len() + usize::from(depth == 0)
        || expected.iter().any(|k| !fields.contains_key(*k))
        || fields
            .keys()
            .any(|k| !expected.contains(&k.as_str()) && !(depth == 0 && k == "$schema"))
    {
        return Err(Error::MissingReference);
    }
    match kind {
        "object" => {
            let props = s["properties"].as_object().ok_or(Error::MissingReference)?;
            let required = array(s, "required")?;
            let unique: BTreeSet<_> = required.iter().filter_map(Value::as_str).collect();
            if s["additionalProperties"] != false
                || props.len() > 32
                || props.keys().any(|k| !identifier(k))
                || unique.len() != required.len()
                || unique.iter().any(|k| !props.contains_key(*k))
            {
                return Err(Error::MissingReference);
            }
            for value in props.values() {
                schema_node(value, depth + 1, nodes)?;
            }
        }
        "array" | "string" | "integer" => {
            let (lo, hi, floor, ceiling) = match kind {
                "array" => ("minItems", "maxItems", 0, 256),
                "string" => ("minLength", "maxLength", 0, 4096),
                _ => ("minimum", "maximum", -SAFE, SAFE),
            };
            let min = s[lo].as_i64().ok_or(Error::MissingReference)?;
            let max = s[hi].as_i64().ok_or(Error::MissingReference)?;
            if min < floor || max > ceiling || min > max {
                return Err(Error::MissingReference);
            }
            if kind == "array" {
                schema_node(&s["items"], depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}
