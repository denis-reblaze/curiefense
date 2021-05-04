/// body parsing functions
use multipart::server::Multipart;
use serde_json::Value;
use std::io::Read;
use xmlparser::{ElementEnd, Token};

use crate::curiefense::logs::Logs;
use crate::curiefense::requestfields::RequestField;
use crate::curiefense::utils::url::parse_urlencoded_params_bytes;

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

fn xml_path(stack: &[(String, u64)]) -> String {
  let mut out = String::new();
  for (s, i) in stack {
    out += s;
    if *i > 0 {
      out.extend(format!("{}", i).chars());
    }
  }
  out
}

fn close_xml_element(
  logs: &mut Logs,
  args: &mut RequestField,
  stack: &mut Vec<(String, u64)>,
  close_name: Option<&str>,
) -> Result<(), ()> {
  match stack.pop() {
    None => {
      logs.error(format!(
        "Invalid XML, extraneous element end: {:?}",
        close_name
      ));
      args.add("INVALID_XML".to_string(), "extra end".to_string());
      Err(())
    }
    Some((openname, idx)) => {
      if let Some(local) = close_name {
        if openname != local {
          logs.error(format!(
            "Invalid XML, wrong closing element. Expected: {}, got {}",
            openname, local
          ));
          args.add("INVALID_XML".to_string(), "wrong end".to_string());
          return Err(());
        }
      }
      if idx == 0 {
        // empty XML element, save it with an empty string
        let path = xml_path(&stack) + openname.as_str() + "1";
        args.add(path, String::new());
      }
      Ok(())
    }
  }
}

fn xml_increment_last(stack: &mut Vec<(String, u64)>) -> u64 {
  if let Some(curtop) = stack.last_mut() {
    let prev = curtop.1;
    curtop.1 = prev + 1;
    return prev;
  }
  return 0;
}

fn xml_body(logs: &mut Logs, args: &mut RequestField, body: &[u8]) -> Result<(), ()> {
  let body_utf8 = String::from_utf8_lossy(body);
  let mut stack: Vec<(String, u64)> = Vec::new();
  for rtoken in xmlparser::Tokenizer::from(body_utf8.as_ref()) {
    let token = rtoken.map_err(|rr| logs.error(format!("XML parsing error: {}", rr)))?;
    match token {
      Token::ProcessingInstruction { .. } => (),
      Token::Comment { .. } => (),
      Token::Declaration { .. } => (),
      Token::DtdStart { .. } => (),
      Token::DtdEnd { .. } => (),
      Token::EmptyDtd { .. } => (),
      Token::EntityDeclaration {
        name, definition, ..
      } => args.add(
        "_XMLENTITY_".to_string() + name.as_str(),
        format!("{:?}", definition),
      ),
      Token::ElementStart { local, .. } => {
        // increment element index for the current element
        xml_increment_last(&mut stack);
        // and push the new element
        stack.push((local.to_string(), 0))
      }
      Token::ElementEnd { end, .. } => match end {
        //  <foo/>
        ElementEnd::Empty => close_xml_element(logs, args, &mut stack, None)?,
        //  <foo>
        ElementEnd::Open => (),
        //  </foo>
        ElementEnd::Close(_, local) => {
          close_xml_element(logs, args, &mut stack, Some(local.as_str()))?
        }
      },
      Token::Attribute { local, value, .. } => {
        let path = xml_path(&stack) + local.as_str();
        args.add(path, value.to_string());
      }
      Token::Text { text } => {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
          xml_increment_last(&mut stack);
          args.add(xml_path(&stack), trimmed.to_string());
        }
      }
      Token::Cdata { text, .. } => {
        xml_increment_last(&mut stack);
        args.add(xml_path(&stack), text.to_string());
      }
    }
  }
  Ok(())
}

/// parses bodies that are url encoded forms, like query params
fn forms_body(logs: &mut Logs, args: &mut RequestField, body: &[u8]) -> Result<(), ()> {
  // TODO: body is traversed twice here, this is inefficient
  if body.contains(&b'=') && body.iter().all(|x| *x > 0x20 && *x < 0x7f) {
    parse_urlencoded_params_bytes(args, body);
    Ok(())
  } else {
    logs.warning("Body is not forms encoded".to_string());
    Err(())
  }
}

fn multipart_form_encoded(logs: &mut Logs, boundary: &str, args: &mut RequestField, body: &[u8]) {
  let mut multipart = Multipart::with_body(body, boundary);
  multipart
    .foreach_entry(|mut entry| {
      let mut content = Vec::new();
      let _ = entry.data.read_to_end(&mut content);
      let name = entry.headers.name.to_string();
      let scontent = String::from_utf8_lossy(&content);
      args.add(name, scontent.to_string());
    })
    .unwrap_or_else(|rr| logs.error(format!("Could not parse multipart body: {}", rr)))
}

/// body parsing function
///
/// fails if the
pub fn parse_body(
  logs: &mut Logs,
  args: &mut RequestField,
  mcontent_type: Option<&str>,
  body: &[u8],
) {
  logs.debug("Body parsing start".to_string());

  if let Some(content_type) = mcontent_type {
    if let Some(boundary) = content_type.strip_prefix("multipart/form-data; boundary=") {
      return multipart_form_encoded(logs, boundary, args, body);
    }

    if content_type.ends_with("/json") {
      return json_body(logs, args, body).unwrap_or(());
    }

    if content_type.ends_with("/xml") {
      return xml_body(logs, args, body).unwrap_or(());
    }

    if content_type == "application/x-www-form-urlencoded" {
      return forms_body(logs, args, body).unwrap_or(());
    }
  }

  // unhandled content type, default to json and forms_body
  json_body(logs, args, body)
    .or_else(|()| forms_body(logs, args, body))
    .unwrap_or_else(|()| {
      logs.info(format!(
        "Could not decode body of type {}",
        mcontent_type.unwrap_or("unknown")
      ));
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
    assert_eq!(args.get_str("a"), Some("b"));
    assert_eq!(args.get_str("c"), Some("d"));
  }

  #[test]
  fn json_simple_array() {
    let args = test_parse_ok(Some("application/json"), br#"["a", "b"]"#);
    assert_eq!(args.len(), 2);
    assert_eq!(args.get_str("0"), Some("a"));
    assert_eq!(args.get_str("1"), Some("b"));
  }

  #[test]
  fn json_nested_objects() {
    let args = test_parse_ok(
      Some("application/json"),
      br#"{"a": [true,null,{"z": 0}], "c": {"d": 12}}"#,
    );
    assert_eq!(args.len(), 4);
    assert_eq!(args.get_str("a_0"), Some("true"));
    assert_eq!(args.get_str("a_1"), Some("null"));
    assert_eq!(args.get_str("a_2_z"), Some("0"));
    assert_eq!(args.get_str("c_d"), Some("12"));
  }

  #[test]
  fn arguments_collision() {
    let mut logs = Logs::new();
    let mut args = RequestField::new();
    args.add("a".to_string(), "query_arg".to_string());
    parse_body(
      &mut logs,
      &mut args,
      Some("application/json"),
      br#"{"a": "body_arg"}"#,
    );
    assert_eq!(args.get_str("a"), Some("query_arg body_arg"));
  }

  #[test]
  fn xml_simple() {
    let args = test_parse_ok(Some("text/xml"), br#"<a>content</a>"#);
    assert_eq!(args.len(), 1);
    assert_eq!(args.get_str("a1"), Some("content"));
  }

  #[test]
  fn xml_nested() {
    let args = test_parse_ok(Some("text/xml"), br#"<a>a<b foo="bar">xxx</b>z</a>"#);
    println!("{:?}", args);
    assert_eq!(args.get_str("a1"), Some("a"));
    assert_eq!(args.get_str("a3"), Some("z"));
    assert_eq!(args.get_str("a2bfoo"), Some("bar"));
    assert_eq!(args.get_str("a2b1"), Some("xxx"));
    assert_eq!(args.len(), 4)
  }

  #[test]
  fn xml_nested_empty() {
    // behavior differs from the Lua code
    let args = test_parse_ok(Some("text/xml"), br#"<a><b><c></c></b></a>"#);
    assert_eq!(args.get_str("a1b1c1"), Some(""));
    assert_eq!(args.len(), 1)
  }

  #[test]
  fn xml_nested_empty_b() {
    // behavior differs from the Lua code
    let args = test_parse_ok(Some("application/xml"), br#"<a><b><c> </c></b></a>"#);
    assert_eq!(args.get_str("a1b1c1"), Some(""));
    assert_eq!(args.len(), 1)
  }

  #[test]
  fn xml_spaces() {
    let args = test_parse_ok(Some("text/xml"), br#"<a>a <b><c> c </c>  </b>  </a>"#);
    assert_eq!(args.get_str("a1"), Some("a"));
    assert_eq!(args.get_str("a2b1c1"), Some("c"));
    assert_eq!(args.len(), 2)
  }

  #[test]
  fn xml_space_in_attribute() {
    let args = test_parse_ok(
      Some("application/xml"),
      br#"<a foo1=" lo l "><foo>lol</foo></a>"#,
    );
    assert_eq!(args.get_str("afoo1"), Some(" lo l "));
    assert_eq!(args.get_str("a1foo1"), Some("lol"));
    assert_eq!(args.len(), 2)
  }

  #[test]
  fn xml_indent() {
    let args = test_parse_ok(
      Some("text/xml"),
      br#"
    <a>x1
      <b>x2</b>
    </a>"#,
    );
    assert_eq!(args.get_str("a1"), Some("x1"));
    assert_eq!(args.get_str("a2b1"), Some("x2"));
    assert_eq!(args.len(), 2)
  }
}
