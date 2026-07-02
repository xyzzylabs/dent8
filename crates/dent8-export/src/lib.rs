//! Parquet export of the dent8 event log — the analytical/export lane.
//!
//! dent8's operational store is the append-only event log (file or Postgres); this crate
//! writes a **flattened, columnar Parquet** view of that log so it can be queried offline with
//! **`DuckDB`** (which reads Parquet directly — no embedded engine here). One row per event,
//! with the queryable scalars promoted to columns (the value carries an explicit `value_kind`
//! discriminator so redacted is never confused with absent; `authority` is a stable name, not a
//! debug string) *and* the `DerivedFrom` dependency edges as a `derived_from` **list** column
//! (`UNNEST` it — a claim id may contain any character, so it is not delimiter-packed). So
//! forensic/audit/replay questions ("every write by `source:web-scrape`", "what was derived from
//! `claim:X`", "events per predicate over time") are plain SQL. The full canonical event is
//! retained in `event_json` for anything the columns omit.
//!
//! This is **read-only export**, not a runtime store (see `docs/storage.md`). The log remains
//! the source of truth; a Parquet file is a derived snapshot.

use std::sync::Arc;

use arrow::array::{ArrayRef, Int64Array, ListBuilder, StringArray, StringBuilder};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use dent8_core::{ClaimEvent, ClaimValue};
use parquet::arrow::ArrowWriter;

/// A failure to build or write the Parquet export.
#[derive(Debug)]
pub enum ExportError {
    /// An event could not be serialized to its `event_json` column.
    Serialize(serde_json::Error),
    /// The Arrow record batch could not be built (schema/column mismatch — should not happen).
    Arrow(arrow::error::ArrowError),
    /// The Parquet writer failed.
    Parquet(parquet::errors::ParquetError),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialize(error) => write!(f, "serialize event: {error}"),
            Self::Arrow(error) => write!(f, "arrow: {error}"),
            Self::Parquet(error) => write!(f, "parquet: {error}"),
        }
    }
}

impl std::error::Error for ExportError {}

/// The columnar schema of an exported event row. `derived_from` is a `List<Utf8>` so its
/// element type must match what the [`ListBuilder`] produces — the caller passes the built
/// column's data type in rather than hard-coding it.
#[must_use]
fn event_schema(derived_from_type: DataType) -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("sequence", DataType::Int64, false),
        Field::new("event_id", DataType::Utf8, false),
        Field::new("claim_id", DataType::Utf8, false),
        Field::new("kind", DataType::Utf8, false),
        Field::new("subject_kind", DataType::Utf8, false),
        Field::new("subject_key", DataType::Utf8, false),
        Field::new("predicate", DataType::Utf8, false),
        // `value` carries the raw text/JSON; `value_kind` is the discriminator so a redacted
        // value (kind="redacted", value=NULL) is never confused with a genuinely absent value
        // (kind=NULL, value=NULL), and Text vs Json need not be inferred from string shape.
        Field::new("value", DataType::Utf8, true),
        Field::new("value_kind", DataType::Utf8, true),
        Field::new("authority", DataType::Utf8, false),
        Field::new("source", DataType::Utf8, false),
        Field::new("actor", DataType::Utf8, false),
        Field::new("recorded_at_ms", DataType::Int64, false),
        Field::new("derived_from", derived_from_type, true),
        Field::new("event_json", DataType::Utf8, false),
    ]))
}

/// Split a claim value into `(value, value_kind)`: the raw string plus a discriminator
/// (`"text"` / `"json"` / `"redacted"`), or `(None, None)` for a genuinely absent value (the
/// lifecycle events — retract/supersede/expire — carry no value). Keeping the kind explicit
/// avoids the two lossy collapses a bare `value` column would have: redacted-vs-absent, and
/// inferring Text-vs-Json from the string's shape.
fn value_parts(value: Option<&ClaimValue>) -> (Option<String>, Option<&'static str>) {
    match value {
        Some(ClaimValue::Text(text)) => (Some(text.clone()), Some("text")),
        Some(ClaimValue::Json(json)) => (Some(json.as_str().to_string()), Some("json")),
        Some(ClaimValue::Redacted) => (None, Some("redacted")),
        None => (None, None),
    }
}

/// Write `events` (in global order) as a flattened Parquet table to `writer`.
///
/// `writer` is any `Write` sink — a `File` for `dent8 export`, or a buffer in tests. The row
/// order is the slice order, captured in the `sequence` column.
pub fn export_events<W: std::io::Write + Send>(
    events: &[ClaimEvent],
    writer: W,
) -> Result<(), ExportError> {
    let len = events.len();
    let mut sequence = Vec::with_capacity(len);
    let mut event_id = Vec::with_capacity(len);
    let mut claim_id = Vec::with_capacity(len);
    let mut kind = Vec::with_capacity(len);
    let mut subject_kind = Vec::with_capacity(len);
    let mut subject_key = Vec::with_capacity(len);
    let mut predicate = Vec::with_capacity(len);
    let mut value = Vec::with_capacity(len);
    let mut value_kind = Vec::with_capacity(len);
    let mut authority = Vec::with_capacity(len);
    let mut source = Vec::with_capacity(len);
    let mut actor = Vec::with_capacity(len);
    let mut recorded_at = Vec::with_capacity(len);
    // `derived_from` is a genuine list column (one row → zero-or-more source claim ids), not a
    // delimiter-packed string: a claim id may legally contain a comma, so a join would be
    // ambiguous. A null list means "no DerivedFrom edges".
    let mut derived_from = ListBuilder::new(StringBuilder::new());
    let mut event_json = Vec::with_capacity(len);

    for (index, event) in events.iter().enumerate() {
        sequence.push(i64::try_from(index).unwrap_or(i64::MAX));
        event_id.push(event.event_id.as_str().to_string());
        claim_id.push(event.claim_id.as_str().to_string());
        kind.push(event.kind.name().to_string());
        subject_kind.push(event.subject.kind().to_string());
        subject_key.push(event.subject.key().to_string());
        predicate.push(event.predicate.as_str().to_string());
        let (raw_value, kind_tag) = value_parts(event.value.as_ref());
        value.push(raw_value);
        value_kind.push(kind_tag);
        authority.push(event.authority.level.name().to_string());
        source.push(event.provenance.source.as_str().to_string());
        actor.push(event.provenance.actor.as_str().to_string());
        recorded_at.push(event.provenance.recorded_at.as_unix_millis());
        let edges = event.dependency_edges();
        if edges.is_empty() {
            derived_from.append_null();
        } else {
            for edge in &edges {
                derived_from.values().append_value(edge.as_str());
            }
            derived_from.append(true);
        }
        event_json.push(serde_json::to_string(event).map_err(ExportError::Serialize)?);
    }

    let derived_from: ArrayRef = Arc::new(derived_from.finish());
    let schema = event_schema(derived_from.data_type().clone());
    let columns: Vec<ArrayRef> = vec![
        Arc::new(Int64Array::from(sequence)),
        Arc::new(StringArray::from(event_id)),
        Arc::new(StringArray::from(claim_id)),
        Arc::new(StringArray::from(kind)),
        Arc::new(StringArray::from(subject_kind)),
        Arc::new(StringArray::from(subject_key)),
        Arc::new(StringArray::from(predicate)),
        Arc::new(StringArray::from(value)),
        Arc::new(StringArray::from(value_kind)),
        Arc::new(StringArray::from(authority)),
        Arc::new(StringArray::from(source)),
        Arc::new(StringArray::from(actor)),
        Arc::new(Int64Array::from(recorded_at)),
        derived_from,
        Arc::new(StringArray::from(event_json)),
    ];
    let batch = RecordBatch::try_new(schema.clone(), columns).map_err(ExportError::Arrow)?;

    let mut parquet = ArrowWriter::try_new(writer, schema, None).map_err(ExportError::Parquet)?;
    parquet.write(&batch).map_err(ExportError::Parquet)?;
    parquet.close().map_err(ExportError::Parquet)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::export_events;
    use arrow::array::{Array, StringArray};
    use dent8_core::{
        ActorId, Authority, AuthorityLevel, ClaimEvent, ClaimEventId, ClaimEventKind, ClaimId,
        ClaimValue, Confidence, EntityRef, Evidence, EvidenceId, EvidenceKind, Predicate,
        Provenance, SourceId, TimestampMillis, Ttl,
    };
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    fn asserted(event_id: &str, claim_id: &str, derived_from: &[&str]) -> ClaimEvent {
        let mut evidence = vec![Evidence {
            id: EvidenceId::new("evidence:base").unwrap(),
            kind: EvidenceKind::UserStatement,
            locator: "x".to_string(),
            digest: None,
            summary: None,
        }];
        for (index, src) in derived_from.iter().enumerate() {
            evidence.push(Evidence {
                id: EvidenceId::new(format!("evidence:d{index}")).unwrap(),
                kind: EvidenceKind::DerivedFrom,
                locator: (*src).to_string(),
                digest: None,
                summary: None,
            });
        }
        ClaimEvent {
            event_id: ClaimEventId::new(event_id).unwrap(),
            claim_id: ClaimId::new(claim_id).unwrap(),
            kind: ClaimEventKind::Asserted,
            subject: EntityRef::new("repo", "proj").unwrap(),
            predicate: Predicate::new("database").unwrap(),
            value: Some(ClaimValue::Text("postgres".to_string())),
            confidence: Confidence::from_millis(900).unwrap(),
            authority: Authority {
                level: AuthorityLevel::High,
                issuer: None,
                scope: None,
            },
            ttl: Ttl::Never,
            provenance: Provenance {
                source: SourceId::new("source:owner").unwrap(),
                actor: ActorId::new("actor:test").unwrap(),
                tool: None,
                run_id: None,
                input_digest: None,
                recorded_at: TimestampMillis::from_unix_millis(42),
                attestation: None,
            },
            evidence,
            observed_at: None,
            valid_from: None,
        }
    }

    #[test]
    fn events_round_trip_through_parquet_with_columns_and_edges() {
        let events = vec![
            asserted("event:0", "claim:source", &[]),
            asserted("event:1", "claim:derived", &["claim:source"]),
        ];
        let mut buffer: Vec<u8> = Vec::new();
        export_events(&events, &mut buffer).expect("export");

        let reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(buffer))
            .expect("reader")
            .build()
            .expect("build");
        let batch = reader.into_iter().next().expect("a batch").expect("batch");
        assert_eq!(batch.num_rows(), 2);
        assert_eq!(batch.num_columns(), 15);

        let col = |name: &str| {
            let idx = batch.schema().index_of(name).unwrap();
            batch
                .column(idx)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap()
                .clone()
        };
        let event_id = col("event_id");
        assert_eq!(event_id.value(0), "event:0");
        let kind = col("kind");
        assert_eq!(kind.value(0), "claim.asserted");
        let source = col("source");
        assert_eq!(source.value(1), "source:owner");
        // The value carries its kind discriminator (text/json/redacted), not an inferred shape.
        let value_kind = col("value_kind");
        assert_eq!(value_kind.value(0), "text");
        // The authority column uses the stable name(), not Debug.
        let authority = col("authority");
        assert_eq!(authority.value(0), "High");
        // The dependency edges are a real list: a null list for the source row, a one-element
        // list for the derived row (no delimiter ambiguity even if an id contained a comma).
        let derived_idx = batch.schema().index_of("derived_from").unwrap();
        let derived = batch
            .column(derived_idx)
            .as_any()
            .downcast_ref::<arrow::array::ListArray>()
            .unwrap();
        assert!(derived.is_null(0));
        let row1 = derived.value(1);
        let row1 = row1.as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(row1.len(), 1);
        assert_eq!(row1.value(0), "claim:source");
    }
}
