//! Vendor-neutral instrumentation. The embedding application owns subscribers,
//! exporters, credentials, sampling, and telemetry shutdown.
use std::{
    future::Future,
    pin::Pin,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Instant,
};

use axum::{
    extract::{MatchedPath, Request},
    http::HeaderMap,
    response::Response,
};
use futures_util::Stream;
use opentelemetry::{
    KeyValue,
    metrics::{Counter, Histogram, Meter},
    propagation::{Extractor, TextMapPropagator},
};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing::{Instrument, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

static MEASUREMENTS: OnceLock<Measurements> = OnceLock::new();
static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

/// Install the embedding application's meter before constructing database pools.
pub fn init_metrics(meter: Meter) {
    let _ = MEASUREMENTS.set(Measurements {
        requests: meter.u64_counter("snowstead.http.requests").build(),
        headers: meter
            .f64_histogram("snowstead.http.headers_duration")
            .with_unit("s")
            .build(),
        body: meter
            .f64_histogram("snowstead.http.body_duration")
            .with_unit("s")
            .build(),
        operations: meter
            .f64_histogram("snowstead.operation.duration")
            .with_unit("s")
            .build(),
        pool_wait: meter
            .f64_histogram("snowstead.database.pool_acquire_duration")
            .with_unit("s")
            .build(),
    });
}

struct Measurements {
    requests: Counter<u64>,
    headers: Histogram<f64>,
    body: Histogram<f64>,
    operations: Histogram<f64>,
    pool_wait: Histogram<f64>,
}

pub(crate) fn enabled() -> bool {
    MEASUREMENTS.get().is_some()
}

/// Records only SQLx's numeric acquisition duration, never SQL or parameters.
/// Install with a filter for the `sqlx::pool::acquire` target.
pub struct PoolTimingLayer;
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for PoolTimingLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Elapsed(Option<f64>);
        impl tracing::field::Visit for Elapsed {
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
            fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
                if field.name() == "acquired_after_secs" {
                    self.0 = Some(value);
                }
            }
        }
        let mut elapsed = Elapsed(None);
        event.record(&mut elapsed);
        if let Some(metrics) = MEASUREMENTS.get()
            && let Some(seconds) = elapsed.0
        {
            metrics.pool_wait.record(seconds, &[]);
        }
    }
}

#[derive(Clone)]
pub(crate) struct RequestObservation {
    started: Instant,
    attributes: Vec<KeyValue>,
    pub(crate) span: Span,
}

impl RequestObservation {
    pub(crate) fn new(request: &Request) -> Self {
        let id = NEXT_REQUEST.fetch_add(1, Ordering::Relaxed);
        let operation = request
            .extensions()
            .get::<MatchedPath>()
            .map_or("cache.read", MatchedPath::as_str)
            .to_owned();
        let method = match request.method().as_str() {
            "GET" => "GET",
            "HEAD" => "HEAD",
            "POST" => "POST",
            "PUT" => "PUT",
            "DELETE" => "DELETE",
            "PATCH" => "PATCH",
            "OPTIONS" => "OPTIONS",
            _ => "OTHER",
        };
        let span = tracing::info_span!(target: "snowstead_observability", "http.request",
            otel.name = %format!("{method} {operation}"), request_id = id,
            otel.kind = "server", otel.status_code = tracing::field::Empty,
            http.request.method = method, http.route = %operation,
            http.response.status_code = tracing::field::Empty,
            organization_id = tracing::field::Empty, actor_id = tracing::field::Empty);
        let parent = TraceContextPropagator::new().extract(&TraceHeaders(request.headers()));
        let _ = span.set_parent(parent);
        let attributes = vec![
            KeyValue::new("operation", operation.clone()),
            KeyValue::new("method", method),
        ];
        if let Some(metrics) = MEASUREMENTS.get() {
            metrics.requests.add(1, &attributes);
        }
        Self {
            started: Instant::now(),
            attributes,
            span,
        }
    }

    pub(crate) fn response(self, response: Response) -> Response {
        let status = response.status();
        self.span
            .record("http.response.status_code", status.as_u16());
        if status.is_server_error() {
            self.span.record("otel.status_code", "ERROR");
        }
        if status.is_server_error() && status != axum::http::StatusCode::SERVICE_UNAVAILABLE {
            self.span.in_scope(|| {
                if enabled() {
                    tracing::error!(target: "snowstead_observability", kind = "http_5xx", "Unexpected server failure");
                }
            });
        }
        let mut attributes = self.attributes;
        attributes.push(KeyValue::new("status", i64::from(status.as_u16())));
        if let Some(metrics) = MEASUREMENTS.get() {
            metrics
                .headers
                .record(self.started.elapsed().as_secs_f64(), &attributes);
        }
        let (parts, body) = response.into_parts();
        let stream = ObservedStream {
            inner: Box::pin(body.into_data_stream()),
            operation: Operation {
                started: self.started,
                attributes,
                metric: Metric::Body,
                completed: false,
            },
            span: self.span,
        };
        Response::from_parts(parts, axum::body::Body::from_stream(stream))
    }
}

struct TraceHeaders<'a>(&'a HeaderMap);
impl Extractor for TraceHeaders<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        if key != "traceparent" {
            return None;
        }
        self.0.get(key)?.to_str().ok().filter(|v| v.len() == 55)
    }
    fn keys(&self) -> Vec<&str> {
        vec!["traceparent"]
    }
}

/// Record only already-authenticated IDs, never credentials or raw claims.
pub(crate) fn identity(identity: &crate::authz::Principal, org: Option<&str>) {
    let span = Span::current();
    let org = org.unwrap_or_else(|| identity.org());
    if safe_id(org) {
        span.record("organization_id", org);
    }
    // JWT subject may be an email supplied by the client. Use its token ID,
    // not the full claims, subject, or bearer token.
    let actor = identity.actor();
    if safe_id(&actor) {
        span.record("actor_id", actor);
    }
}

fn safe_id(value: &str) -> bool {
    value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-:".contains(&b))
}

enum Metric {
    Operation,
    Body,
}
struct Operation {
    started: Instant,
    attributes: Vec<KeyValue>,
    metric: Metric,
    completed: bool,
}
impl Operation {
    fn new(label: &'static str) -> Self {
        Self {
            started: Instant::now(),
            attributes: vec![KeyValue::new("operation", label)],
            metric: Metric::Operation,
            completed: false,
        }
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        if let Some(metrics) = MEASUREMENTS.get() {
            self.attributes.push(KeyValue::new(
                "completion",
                if self.completed {
                    "complete"
                } else {
                    "cancelled"
                },
            ));
            let histogram = match self.metric {
                Metric::Operation => &metrics.operations,
                Metric::Body => &metrics.body,
            };
            histogram.record(self.started.elapsed().as_secs_f64(), &self.attributes);
        }
    }
}

pub(crate) fn future<F: Future>(future: F, label: &'static str) -> impl Future<Output = F::Output> {
    let span =
        tracing::info_span!(target: "snowstead_observability", "operation", otel.name = label);
    async move {
        let mut operation = Operation::new(label);
        let result = future.await;
        operation.completed = true;
        result
    }
    .instrument(span)
}

pub(crate) struct ObservedStream<S> {
    inner: Pin<Box<S>>,
    operation: Operation,
    span: Span,
}
impl<S: Stream> Stream for ObservedStream<S> {
    type Item = S::Item;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let _entered = this.span.enter();
        let result = this.inner.as_mut().poll_next(cx);
        if matches!(result, Poll::Ready(None)) {
            this.operation.completed = true;
        }
        result
    }
}

pub(crate) fn stream<S: Stream>(stream: S, label: &'static str) -> ObservedStream<S> {
    ObservedStream {
        inner: Box::pin(stream),
        operation: Operation::new(label),
        span: tracing::info_span!(target: "snowstead_observability", "operation", otel.name = label),
    }
}
