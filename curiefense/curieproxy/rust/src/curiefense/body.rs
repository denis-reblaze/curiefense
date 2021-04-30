/// body parsing functions
use serde_json::Value;

use crate::curiefense::logs::Logs;
use crate::curiefense::requestfields::RequestField;

fn flatten_json(args: &mut RequestField, prefix: &mut Vec<String>, value: Value) {
  match value {
    Value::Array(array) => {
      prefix.push(String::new());
      let idx = prefix.len() - 1;
      for (i, v) in array.into_iter().enumerate() {
        prefix[idx] = format!("{}", i);
        flatten_json(args, prefix, v);
      }
      prefix.pop();
    }
    Value::Object(mp) => {
      prefix.push(String::new());
      let idx = prefix.len() - 1;
      for (k, v) in mp.into_iter() {
        prefix[idx] = k;
        flatten_json(args, prefix, v);
      }
      prefix.pop();
    }
    Value::String(str) => {
      args.add(prefix.join("_"), str);
    }
    Value::Bool(b) => {
      args.add(
        prefix.join("_"),
        (if b { "true" } else { "false" }).to_string(),
      );
    }
    Value::Number(n) => {
      args.add(prefix.join("_"), format!("{}", n));
    }
    Value::Null => {
      args.add(prefix.join("_"), "null".to_string());
    }
  }
}

/// alpha quality code: should work with a stream of json items, not deserialize all at once
fn json_body(logs: &mut Logs, args: &mut RequestField, body: &[u8]) -> Result<(), ()> {
  let value: Value =
    serde_json::from_slice(body).map_err(|rr| logs.info(format!("Invalid JSON body: {}", rr)))?;

  let mut prefix = Vec::new();
  flatten_json(args, &mut prefix, value);
  Ok(())
}

fn xml_body(logs: &mut Logs, _args: &mut RequestField, _body: &[u8]) -> Result<(), ()> {
  logs.warning("XML body decoding is not yet implemented!".to_string());
  Ok(())
}

fn forms_body(logs: &mut Logs, _args: &mut RequestField, _body: &[u8]) -> Result<(), ()> {
  logs.warning("Form encoded body decoding is not yet implemented!".to_string());
  Ok(())
}

fn multipart_form_encoded(
  logs: &mut Logs,
  _boundary: &str,
  _args: &mut RequestField,
  _body: &[u8],
) {
  logs.warning("Multipart form encoded body decoding is not yet implemented!".to_string())
}

pub fn parse_body(
  logs: &mut Logs,
  args: &mut RequestField,
  mcontent_type: Option<&str>,
  body: &[u8],
) {
  logs.debug("Body parsing start".to_string());

  if let Some(content_type) = mcontent_type {
    if let Some(boundary) = content_type
      .strip_prefix("application/x-www-form-urlencoded;boundary=\"")
      .and_then(|s| s.strip_suffix('"'))
    {
      return multipart_form_encoded(logs, boundary, args, body);
    }

    if content_type.ends_with("/json") {
      return json_body(logs, args, body).unwrap_or(());
    }

    if content_type.ends_with("/xml") {
      return xml_body(logs, args, body).unwrap_or(());
    }
  }

  // unhandled content type, default to json and forms_body
  json_body(logs, args, body)
    .or_else(|()| forms_body(logs, args, body))
    .unwrap_or_else(|()| {
      logs.info(format!(
        "Could not decode body of type {}",
        mcontent_type.unwrap_or("unknown")
      ))
    })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::curiefense::logs::LogLevel;

  fn test_parse_ok(mcontent_type: Option<&str>, body: &[u8]) -> RequestField {
    let mut logs = Logs::new();
    let mut args = RequestField::new();
    parse_body(&mut logs, &mut args, mcontent_type, body);
    for lg in logs.0 {
      if lg.level > LogLevel::Debug {
        panic!("unexpected log: {:?}", lg);
      }
    }
    args
  }

  #[test]
  fn json_empty_body() {
    let args = test_parse_ok(Some("application/json"), br#"{}"#);
    assert_eq!(args, RequestField::new());
  }

  #[test]
  fn json_simple_object() {
    let args = test_parse_ok(Some("application/json"), br#"{"a": "b", "c": "d"}"#);
    assert_eq!(args.len(), 2);
    assert_eq!(args.get("a").map(|s| s.as_str()), Some("b"));
    assert_eq!(args.get("c").map(|s| s.as_str()), Some("d"));
  }

  #[test]
  fn json_simple_array() {
    let args = test_parse_ok(Some("application/json"), br#"["a", "b"]"#);
    assert_eq!(args.len(), 2);
    assert_eq!(args.get("0").map(|s| s.as_str()), Some("a"));
    assert_eq!(args.get("1").map(|s| s.as_str()), Some("b"));
  }

  #[test]
  fn json_nested_objects() {
    let args = test_parse_ok(Some("application/json"), br#"{"a": [true,null,{"z": 0}], "c": {"d": 12}}"#);
    assert_eq!(args.len(), 4);
    assert_eq!(args.get("a_0").map(|s| s.as_str()), Some("true"));
    assert_eq!(args.get("a_1").map(|s| s.as_str()), Some("null"));
    assert_eq!(args.get("a_2_z").map(|s| s.as_str()), Some("0"));
    assert_eq!(args.get("c_d").map(|s| s.as_str()), Some("12"));
  }
}
