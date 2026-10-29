//! Allocation-free preflight for the schemas in opentelemetry-proto 0.31.
//!
//! Keep this table in sync when upgrading generated types. This is a budget
//! validator, not a replacement protobuf decoder: prost still validates types,
//! UTF-8, enums, and merge semantics. Unknown fields remain opaque/skippable.
//!
//! Conservative materialization budget: 64 MiB charged as 4 * input bytes,
//! 4096 per known message occurrence (including empty/duplicate singular ones),
//! and 64 per repeated primitive. This bounds both generated structs and their
//! serde Value expansion; it is an accounting limit, not an exact RSS promise.
//! Rich batches can therefore be rejected below the 10000 normalized-record cap.
//! Also limit each repeated wire field to 10000 elements, global resources,
//! scopes, records and metric points separately to 10000 each, and depth to 32.
//! Repeated primitives have a separate request-wide ceiling of 100000 elements.
use anyhow::{bail, ensure, Result};

const MAX_DEPTH: usize = 32;
const MAX_MATERIALIZATION: usize = 64 * 1024 * 1024;
const MESSAGE_COST: usize = 4096;
const PRIMITIVE_COST: usize = 64;
const LIMIT: usize = super::MAX_RECORDS;

#[derive(Clone, Copy)]
enum Schema {
    Export(Signal),
    ResourceGroup(Signal),
    ScopeGroup(Signal),
    Resource,
    Scope,
    Entity,
    KeyValue,
    AnyValue,
    Array,
    KvList,
    Log,
    Span,
    Event,
    Link,
    Status,
    Metric,
    Points(PointKind),
    Point(PointKind),
    Buckets,
    Quantile,
    Exemplar,
}

#[derive(Clone, Copy)]
enum Signal {
    Logs,
    Metrics,
    Traces,
}

#[derive(Clone, Copy)]
enum PointKind {
    Number,
    Histogram,
    Exponential,
    Summary,
}

enum Field {
    Message(Schema, bool), // bool: repeated, rather than singular/oneof.
    Numbers(u8),           // unpacked wire type; packed encoding is also accepted.
    Strings,
    Opaque,
}

// All message-valued and repeated primitive fields reachable from the three
// Export*ServiceRequest roots. Scalar/string/bytes leaves need no traversal:
// the initial input-byte charge covers their storage and base64/hex expansion.
fn field(schema: Schema, tag: u32) -> Field {
    use Field::*;
    use Schema::*;
    match (schema, tag) {
        (Export(s), 1) => Message(ResourceGroup(s), true),
        (ResourceGroup(_), 1) => Message(Resource, false),
        (ResourceGroup(s), 2) => Message(ScopeGroup(s), true),
        (ScopeGroup(_), 1) => Message(Scope, false),
        (ScopeGroup(Signal::Logs), 2) => Message(Log, true),
        (ScopeGroup(Signal::Metrics), 2) => Message(Metric, true),
        (ScopeGroup(Signal::Traces), 2) => Message(Span, true),
        (Resource, 1) | (KvList, 1) => Message(KeyValue, true),
        (Resource, 3) => Message(Entity, true),
        (Scope, 3) => Message(KeyValue, true),
        (Entity, 3 | 4) => Strings,
        (KeyValue, 2) => Message(AnyValue, false),
        (AnyValue, 5) => Message(Array, false),
        (AnyValue, 6) => Message(KvList, false),
        (Array, 1) => Message(AnyValue, true),
        (Log, 5) => Message(AnyValue, false),
        (Log, 6) | (Span, 9) | (Event, 3) | (Link, 4) | (Metric, 12) => Message(KeyValue, true),
        (Span, 11) => Message(Event, true),
        (Span, 13) => Message(Link, true),
        (Span, 15) => Message(Status, false),
        (Metric, 5 | 7) => Message(Points(PointKind::Number), false),
        (Metric, 9) => Message(Points(PointKind::Histogram), false),
        (Metric, 10) => Message(Points(PointKind::Exponential), false),
        (Metric, 11) => Message(Points(PointKind::Summary), false),
        (Points(p), 1) => Message(Schema::Point(p), true),
        (Schema::Point(PointKind::Number | PointKind::Summary), 7)
        | (Schema::Point(PointKind::Histogram), 9)
        | (Schema::Point(PointKind::Exponential), 1)
        | (Exemplar, 7) => Message(KeyValue, true),
        (Schema::Point(PointKind::Number), 5)
        | (Schema::Point(PointKind::Histogram), 8)
        | (Schema::Point(PointKind::Exponential), 11) => Message(Exemplar, true),
        (Schema::Point(PointKind::Histogram), 6 | 7) => Numbers(1),
        (Schema::Point(PointKind::Exponential), 8 | 9) => Message(Buckets, false),
        (Schema::Point(PointKind::Summary), 6) => Message(Quantile, true),
        (Buckets, 2) => Numbers(0),
        _ => Opaque,
    }
}

struct Budget {
    remaining: usize,
    resources: usize,
    scopes: usize,
    records: usize,
    points: usize,
    primitives: usize,
}

impl Budget {
    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.remaining = self.remaining.checked_sub(bytes).ok_or_else(|| {
            anyhow::anyhow!("OTLP protobuf materialization budget exceeds 64 MiB")
        })?;
        Ok(())
    }

    fn message(&mut self, schema: Schema) -> Result<()> {
        self.charge(MESSAGE_COST)?;
        let count = match schema {
            Schema::ResourceGroup(_) => &mut self.resources,
            Schema::ScopeGroup(_) => &mut self.scopes,
            Schema::Log | Schema::Span | Schema::Metric => &mut self.records,
            Schema::Point(_) => &mut self.points,
            _ => return Ok(()),
        };
        *count += 1;
        ensure!(
            *count <= LIMIT,
            "OTLP protobuf container count exceeds 10000"
        );
        Ok(())
    }

    fn primitives(&mut self, n: usize) -> Result<()> {
        self.primitives += n;
        ensure!(
            self.primitives <= 100_000,
            "OTLP protobuf primitive count exceeds 100000"
        );
        self.charge(n * PRIMITIVE_COST)
    }
}

pub(super) fn preflight(signal: &str, bytes: &[u8]) -> Result<()> {
    let signal = match signal {
        "logs" => Signal::Logs,
        "metrics" => Signal::Metrics,
        "traces" => Signal::Traces,
        _ => bail!("unsupported OTLP signal"),
    };
    let mut budget = Budget {
        remaining: MAX_MATERIALIZATION,
        resources: 0,
        scopes: 0,
        records: 0,
        points: 0,
        primitives: 0,
    };
    budget.charge(
        bytes
            .len()
            .checked_mul(4)
            .ok_or_else(|| anyhow::anyhow!("OTLP protobuf size overflow"))?,
    )?;
    walk(bytes, Schema::Export(signal), 0, &mut budget)
}

fn walk(mut input: &[u8], schema: Schema, depth: usize, budget: &mut Budget) -> Result<()> {
    ensure!(depth <= MAX_DEPTH, "OTLP protobuf nesting exceeds 32");
    budget.message(schema)?;
    // Schema tags above are <= 15. Stack storage, independent of input length.
    let mut counts = [0usize; 16];
    while !input.is_empty() {
        let (tag, wire) = key(&mut input)?;
        match field(schema, tag) {
            Field::Message(child, repeated) => {
                ensure!(wire == 2, "invalid OTLP protobuf message wire type");
                if repeated {
                    count(&mut counts[tag as usize], 1)?;
                }
                walk(delimited(&mut input)?, child, depth + 1, budget)?;
            }
            Field::Strings => {
                ensure!(wire == 2, "invalid OTLP protobuf string wire type");
                count(&mut counts[tag as usize], 1)?;
                budget.primitives(1)?;
                delimited(&mut input)?;
            }
            Field::Numbers(scalar_wire) => {
                let n = if wire == 2 {
                    let mut packed = delimited(&mut input)?;
                    if scalar_wire == 1 {
                        ensure!(packed.len() % 8 == 0, "invalid OTLP packed fixed64");
                        packed.len() / 8
                    } else {
                        let mut n = 0;
                        while !packed.is_empty() {
                            varint(&mut packed)?;
                            n += 1;
                            ensure!(n <= LIMIT, "OTLP protobuf collection exceeds 10000");
                        }
                        n
                    }
                } else {
                    ensure!(
                        wire == scalar_wire,
                        "invalid OTLP protobuf numeric wire type"
                    );
                    skip(&mut input, tag, wire, depth)?;
                    1
                };
                count(&mut counts[tag as usize], n)?;
                budget.primitives(n)?;
            }
            Field::Opaque => skip(&mut input, tag, wire, depth)?,
        }
    }
    Ok(())
}

fn count(count: &mut usize, n: usize) -> Result<()> {
    *count += n;
    ensure!(*count <= LIMIT, "OTLP protobuf collection exceeds 10000");
    Ok(())
}

fn varint(input: &mut &[u8]) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = take(input, 1)?[0];
        ensure!(shift != 63 || byte <= 1, "invalid OTLP protobuf varint");
        value |= u64::from(byte & 127) << shift;
        if byte < 128 {
            return Ok(value);
        }
    }
    bail!("invalid OTLP protobuf varint")
}

fn key(input: &mut &[u8]) -> Result<(u32, u8)> {
    let key = varint(input)?;
    ensure!(
        key >> 3 != 0 && key >> 3 <= 0x1fff_ffff,
        "invalid OTLP protobuf field tag"
    );
    Ok(((key >> 3) as u32, (key & 7) as u8))
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8]> {
    ensure!(length <= input.len(), "truncated OTLP protobuf");
    let (head, tail) = input.split_at(length);
    *input = tail;
    Ok(head)
}

fn delimited<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
    let length = usize::try_from(varint(input)?)
        .map_err(|_| anyhow::anyhow!("OTLP protobuf length overflow"))?;
    take(input, length)
}

fn skip(input: &mut &[u8], tag: u32, wire: u8, depth: usize) -> Result<()> {
    match wire {
        0 => {
            varint(input)?;
        }
        1 => {
            take(input, 8)?;
        }
        2 => {
            delimited(input)?;
        }
        3 => {
            ensure!(depth < MAX_DEPTH, "OTLP protobuf nesting exceeds 32");
            loop {
                let (inner, kind) = key(input)?;
                if kind == 4 {
                    ensure!(inner == tag, "invalid OTLP protobuf end group");
                    break;
                }
                skip(input, inner, kind, depth + 1)?;
            }
        }
        5 => {
            take(input, 4)?;
        }
        _ => bail!("invalid OTLP protobuf wire type"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn integer(mut n: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        while n >= 128 {
            bytes.push((n as u8 & 127) | 128);
            n >>= 7;
        }
        bytes.push(n as u8);
        bytes
    }

    fn message(tag: usize, body: &[u8]) -> Vec<u8> {
        let mut bytes = integer(tag * 8 + 2);
        bytes.extend(integer(body.len()));
        bytes.extend(body);
        bytes
    }

    fn logs(records: &[u8]) -> Vec<u8> {
        message(1, &message(2, records))
    }

    fn local(schema: Schema, input: &[u8]) -> Result<()> {
        let mut budget = Budget {
            remaining: MAX_MATERIALIZATION,
            resources: 0,
            scopes: 0,
            records: 0,
            points: 0,
            primitives: 0,
        };
        walk(input, schema, 0, &mut budget)
    }

    #[test]
    fn compact_200k_empty_logs_rejected_before_decode_then_healthy_control() {
        // Only ~400 KiB of wire bytes: never construct 200000 generated records
        // or Values in the test itself. The public decode must run preflight.
        let wire = logs(&[0x12, 0].repeat(200_000));
        assert_eq!(wire.len(), 400_008);
        let error = super::super::decode("logs", "application/x-protobuf", &wire).unwrap_err();
        assert!(error
            .to_string()
            .contains("OTLP protobuf collection exceeds 10000"));
        let healthy =
            super::super::decode("logs", "application/x-protobuf", &logs(&[0x12, 0])).unwrap();
        assert_eq!(
            super::super::normalize("codex-otel", "logs", &healthy)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn every_repeated_message_and_string_family_has_a_predecode_bound() {
        use Schema::*;
        // Explicit schema inventory, independent of field() dispatch. Include
        // content-bearing fields even though normalization ultimately drops them.
        for (schema, tag) in [
            (Export(Signal::Logs), 1),
            (Export(Signal::Metrics), 1),
            (Export(Signal::Traces), 1),
            (ResourceGroup(Signal::Logs), 2),
            (ResourceGroup(Signal::Metrics), 2),
            (ResourceGroup(Signal::Traces), 2),
            (ScopeGroup(Signal::Logs), 2),
            (ScopeGroup(Signal::Metrics), 2),
            (ScopeGroup(Signal::Traces), 2),
            (Resource, 1),
            (Resource, 3),
            (Scope, 3),
            (Entity, 3),
            (Entity, 4),
            (KvList, 1),
            (Array, 1),
            (Log, 6),
            (Span, 9),
            (Event, 3),
            (Link, 4),
            (Metric, 12),
            (Span, 11),
            (Span, 13),
            (Points(PointKind::Number), 1),
            (Points(PointKind::Histogram), 1),
            (Points(PointKind::Exponential), 1),
            (Points(PointKind::Summary), 1),
            (Point(PointKind::Number), 7),
            (Point(PointKind::Summary), 7),
            (Point(PointKind::Histogram), 9),
            (Point(PointKind::Exponential), 1),
            (Exemplar, 7),
            (Point(PointKind::Number), 5),
            (Point(PointKind::Histogram), 8),
            (Point(PointKind::Exponential), 11),
            (Point(PointKind::Summary), 6),
        ] {
            let one = message(tag, &[]);
            assert!(local(schema, &one).is_ok());
            assert!(local(schema, &one.repeat(LIMIT + 1)).is_err(), "tag {tag}");
        }
    }

    #[test]
    fn packed_unpacked_and_fragmented_numeric_arrays_are_bounded() {
        for (schema, tag, width, wire) in [
            (Schema::Point(PointKind::Histogram), 6, 8, 1),
            (Schema::Point(PointKind::Histogram), 7, 8, 1),
            (Schema::Buckets, 2, 1, 0),
        ] {
            assert!(local(schema, &message(tag, &vec![0; width * 2])).is_ok());
            assert!(local(schema, &message(tag, &vec![0; width * (LIMIT + 1)])).is_err());
            let mut unpacked = integer(tag * 8 + wire);
            unpacked.extend(vec![0; width]);
            assert!(local(schema, &unpacked).is_ok());
            assert!(local(schema, &unpacked.repeat(LIMIT + 1)).is_err());
            let mut fragmented = message(tag, &vec![0; width * LIMIT]);
            fragmented.extend(unpacked);
            assert!(local(schema, &fragmented).is_err());
        }
        assert!(local(Schema::Point(PointKind::Histogram), &message(6, &[0])).is_err());
    }

    #[test]
    fn export_roots_reach_nested_allocation_limits() {
        // Full envelopes also exercise singular/oneof parent edges. A local
        // collection test alone would miss a missing parent in the schema table.
        let paths: &[(&str, &[usize], usize)] = &[
            ("logs", &[1, 1], 1),                // resource attributes
            ("logs", &[1, 1], 3),                // entity references
            ("logs", &[1, 1, 3], 3),             // entity id keys
            ("logs", &[1, 2, 1], 3),             // instrumentation attributes
            ("logs", &[1, 2, 2], 6),             // log attributes
            ("logs", &[1, 2, 2, 5, 5], 1),       // body AnyValue array
            ("logs", &[1, 2, 2, 6, 2, 6], 1),    // attribute AnyValue kvlist
            ("traces", &[1, 2, 2], 11),          // events
            ("traces", &[1, 2, 2], 13),          // links
            ("traces", &[1, 2, 2, 11], 3),       // event attributes
            ("traces", &[1, 2, 2, 13], 4),       // link attributes
            ("metrics", &[1, 2, 2], 12),         // metric metadata
            ("metrics", &[1, 2, 2, 5], 1),       // gauge
            ("metrics", &[1, 2, 2, 7], 1),       // sum
            ("metrics", &[1, 2, 2, 9], 1),       // histogram
            ("metrics", &[1, 2, 2, 10], 1),      // exponential histogram
            ("metrics", &[1, 2, 2, 11], 1),      // summary
            ("metrics", &[1, 2, 2, 5, 1], 5),    // number exemplars
            ("metrics", &[1, 2, 2, 9, 1], 8),    // histogram exemplars
            ("metrics", &[1, 2, 2, 10, 1], 11),  // exponential exemplars
            ("metrics", &[1, 2, 2, 11, 1], 6),   // quantiles
            ("metrics", &[1, 2, 2, 5, 1, 5], 7), // exemplar attributes
        ];
        for &(signal, parents, tag) in paths {
            for n in [1, LIMIT + 1] {
                let mut bytes = message(tag, &[]).repeat(n);
                for &parent in parents.iter().rev() {
                    bytes = message(parent, &bytes);
                }
                assert_eq!(
                    preflight(signal, &bytes).is_ok(),
                    n == 1,
                    "{signal} {parents:?} {tag}"
                );
            }
        }
        for sign in [8, 9] {
            let mut bytes = message(2, &vec![0; LIMIT + 1]);
            for tag in [sign, 1, 10, 2, 2, 1] {
                bytes = message(tag, &bytes);
            }
            assert!(preflight("metrics", &bytes).is_err());
        }
    }

    #[test]
    fn singular_merges_and_distributed_collections_cannot_reset_aggregate_budget() {
        // Repeated occurrences of a singular embedded message merge in prost.
        // Charge every occurrence, rather than resetting at each wire envelope.
        let duplicates = message(2, &[]).repeat(MAX_MATERIALIZATION / MESSAGE_COST);
        let error = local(Schema::KeyValue, &duplicates).unwrap_err();
        assert!(error.to_string().contains("materialization budget"));
        let many_scopes = message(2, &message(2, &[]).repeat(5001));
        let request = message(1, &many_scopes.repeat(2));
        assert!(preflight("logs", &request)
            .unwrap_err()
            .to_string()
            .contains("container count"));
        // A duplicate singular buckets envelope must not bypass total primitive
        // accounting, even though each wire occurrence fits the local limit.
        let buckets = message(8, &message(2, &vec![0; LIMIT]));
        assert!(
            local(Schema::Point(PointKind::Exponential), &buckets.repeat(11))
                .unwrap_err()
                .to_string()
                .contains("primitive count")
        );
    }

    #[test]
    fn nested_values_and_unknown_groups_have_bounded_depth() {
        let mut value = message(1, b"safe");
        for _ in 0..4 {
            value = message(5, &message(1, &value));
        }
        assert!(local(Schema::AnyValue, &value).is_ok());
        for _ in 0..MAX_DEPTH {
            value = message(5, &message(1, &value));
        }
        assert!(local(Schema::AnyValue, &value)
            .unwrap_err()
            .to_string()
            .contains("nesting"));
        let mut groups = vec![0x7b; MAX_DEPTH + 1]; // unknown field15 start/end group
        groups.extend(vec![0x7c; MAX_DEPTH + 1]);
        assert!(preflight("logs", &groups).is_err());
    }

    #[test]
    fn unknown_fields_are_skipped_and_malformed_wire_is_rejected() {
        let mut request = logs(&[0x12, 0]);
        // Unknown length-delimited data must remain opaque, not parsed as a
        // message; unknown varint/fixed32/fixed64/groups retain protobuf semantics.
        request.extend(message(100, &[0xff, 0xff]));
        request.extend([0x78, 1, 0x7d, 0, 0, 0, 0, 0x79]);
        request.extend([0; 8]);
        request.extend([0x7b, 0x08, 1, 0x7c]);
        assert!(super::super::decode("logs", "application/x-protobuf", &request).is_ok());
        for malformed in [
            vec![0],
            vec![0x0a, 5, 0],
            vec![0x0a, 0xff],
            vec![0x7b, 0x74],
            vec![0x7c],
            vec![0x7e],
            vec![0xff; 10],
            vec![0x0a, 0x80, 0x80],
        ] {
            assert!(preflight("logs", &malformed).is_err());
        }
    }
}
