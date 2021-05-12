use curiefense::body::parse_body;
use curiefense::logs::Logs;
use curiefense::requestfields::RequestField;

use criterion::*;
use std::collections::HashMap;

fn body_test(mcontent_type: Option<&str>, body: &[u8]) {
  let mut logs = Logs::new();
  let mut args = RequestField::new();
  parse_body(&mut logs, &mut args, mcontent_type, body).unwrap();
}

fn json_values(c: &mut Criterion) {
  let val = serde_json::json!({
    "a": 1,
    "b": {
      "c": [1, true, null],
      "d": "ls,lqsdfné€€"
    }
  });
  let val_content = serde_json::to_string(&val).unwrap();
  let val_bytes = val_content.as_bytes();
  c.bench_function("json values", |b| {
    b.iter(|| body_test(Some("text/json"), black_box(val_bytes)))
  });
}

fn create_string_map(sz: usize) -> String {
  let mp: HashMap<String, String> = (1..sz)
    .map(|x| {
      let xs = format!("{}", x);
      (xs.clone(), xs)
    })
    .collect();
  serde_json::to_string(&mp).unwrap()
}

fn json_string_map(c: &mut Criterion) {
  let mut group = c.benchmark_group("json string map");
  for sz in [1, 10, 100, 1000, 10000].iter() {
    group.bench_with_input(BenchmarkId::from_parameter(sz), sz, |b, &size| {
      let mp = create_string_map(size);
      b.iter(|| body_test(Some("text/json"), black_box(mp.as_bytes())))
    });
  }
}

criterion_group!(json, json_values, json_string_map);
criterion_main!(json);
