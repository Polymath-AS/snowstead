//! Opt-in, best-effort export. Only deliberately constructed fields leave the
//! process: dependency logs, URLs, SQL, headers, and error payloads do not.
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use axum::{
    extract::{MatchedPath, Request},
    http::HeaderMap,
    response::Response,
};
use futures_util::Stream;
use opentelemetry::{
    KeyValue,
    metrics::{Counter, Histogram},
    propagation::{Extractor, TextMapPropagator},
    trace::{TraceContextExt, TracerProvider},
};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::{
    Resource,
    logs::{BatchConfigBuilder as LogBatchConfig, BatchLogProcessor, SdkLoggerProvider},
    metrics::{PeriodicReader, SdkMeterProvider},
    propagation::TraceContextPropagator,
    trace::{BatchConfigBuilder, BatchSpanProcessor, Sampler, SdkTracerProvider},
};
use tracing::{Instrument, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

const EXPORT_TIMEOUT: Duration = Duration::from_secs(2);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(8);
static MEASUREMENTS: OnceLock<Measurements> = OnceLock::new();
static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

struct Settings {
    token: String,
    host: String,
    sample_rate: f64,
    service: String,
    release: Option<String>,
}

impl Settings {
    fn read(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, &'static str> {
        let token = get("POSTHOG_PROJECT_TOKEN").filter(|v| !v.trim().is_empty());
        let host = get("POSTHOG_HOST").filter(|v| !v.trim().is_empty());
        let (token, host) = match (token, host) {
            (None, None) => return Ok(None),
            (Some(token), Some(host)) => (token, host),
            _ => return Err("Set both POSTHOG_PROJECT_TOKEN and POSTHOG_HOST; export disabled"),
        };
        let url =
            reqwest::Url::parse(&host).map_err(|_| "Invalid POSTHOG_HOST; export disabled")?;
        // HTTP is only allowed for local collectors/tests. No credentials,
        // paths, or query parameters can become exporter endpoints.
        if !(url.scheme() == "https"
            || url.scheme() == "http"
                && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("POSTHOG_HOST must be an ingestion origin; export disabled");
        }
        let sample_rate = get("OBSERVABILITY_SAMPLE_RATE")
            .unwrap_or_else(|| "0.4".into())
            .parse::<f64>()
            .ok()
            .filter(|v| v.is_finite() && (0.0..=1.0).contains(v))
            .ok_or("OBSERVABILITY_SAMPLE_RATE must be between 0 and 1; export disabled")?;
        let service = get("OTEL_SERVICE_NAME").unwrap_or_else(|| "snowstead-api".into());
        let release = get("SNOWSTEAD_RELEASE");
        if token.len() > 256
            || token
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
            || service.is_empty()
            || service.len() > 128
            || release.as_ref().is_some_and(|v| v.len() > 128)
        {
            return Err("Invalid observability configuration; export disabled");
        }
        Ok(Some(Self {
            token,
            host: host.trim_end_matches('/').into(),
            sample_rate,
            service,
            release,
        }))
    }
}

/// Own the exporters until requests, streams, and tracked work have drained.
pub struct Telemetry {
    traces: SdkTracerProvider,
    logs: SdkLoggerProvider,
    metrics: SdkMeterProvider,
}

/// Initialize once, before serving. No configuration means journal logging only.
pub async fn init() -> Option<Telemetry> {
    let settings = Settings::read(|name| std::env::var(name).ok());
    let (settings, warning) = match settings {
        Ok(value) => (value, None),
        Err(warning) => (None, Some(warning)),
    };
    if let Some(settings) = settings {
        match tokio::task::spawn_blocking(move || Telemetry::build(settings)).await {
            Ok(Ok(telemetry)) => return Some(telemetry),
            _ => {
                journal();
                tracing::warn!("Observability initialization failed; export disabled");
                return None;
            }
        }
    }
    journal();
    if let Some(warning) = warning {
        tracing::warn!("{warning}");
    }
    None
}

fn journal() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();
}

impl Telemetry {
    fn build(settings: Settings) -> anyhow::Result<Self> {
        let mut attributes = vec![KeyValue::new("service.name", settings.service.clone())];
        if let Some(release) = &settings.release {
            attributes.push(KeyValue::new("service.version", release.clone()));
        }
        // Do not inherit OTEL_RESOURCE_ATTRIBUTES, which might contain secrets.
        let resource = Resource::builder_empty()
            .with_attributes(attributes)
            .build();
        let headers =
            HashMap::from([("Authorization".into(), format!("Bearer {}", settings.token))]);
        let client = reqwest::blocking::Client::builder()
            .timeout(EXPORT_TIMEOUT)
            .connect_timeout(EXPORT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let spans = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(format!("{}/i/v1/traces", settings.host))
            .with_timeout(EXPORT_TIMEOUT)
            .with_retry_policy(opentelemetry_otlp::RetryPolicy::disabled())
            .with_max_request_body_size(1024 * 1024)
            .with_http_client(client.clone())
            .with_headers(headers.clone())
            .build()?;
        let logs = opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .with_endpoint(format!("{}/i/v1/logs", settings.host))
            .with_timeout(EXPORT_TIMEOUT)
            .with_retry_policy(opentelemetry_otlp::RetryPolicy::disabled())
            .with_max_request_body_size(1024 * 1024)
            .with_http_client(client.clone())
            .with_headers(headers.clone())
            .build()?;
        let metrics = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_endpoint(format!("{}/i/v1/metrics", settings.host))
            .with_timeout(EXPORT_TIMEOUT)
            .with_retry_policy(opentelemetry_otlp::RetryPolicy::disabled())
            .with_max_request_body_size(1024 * 1024)
            .with_http_client(client.clone())
            .with_headers(headers)
            .build()?;
        let traces = SdkTracerProvider::builder()
            .with_resource(resource.clone())
            // A remote sampling bit must not override our server's volume budget.
            .with_sampler(Sampler::TraceIdRatioBased(settings.sample_rate))
            .with_span_processor(
                BatchSpanProcessor::builder(spans)
                    .with_batch_config(
                        BatchConfigBuilder::default()
                            .with_max_queue_size(256)
                            .with_max_export_batch_size(64)
                            .build(),
                    )
                    .build(),
            )
            .build();
        let logs = SdkLoggerProvider::builder()
            .with_resource(resource.clone())
            .with_log_processor(
                BatchLogProcessor::builder(logs)
                    .with_batch_config(
                        LogBatchConfig::default()
                            .with_max_queue_size(128)
                            .with_max_export_batch_size(32)
                            .build(),
                    )
                    .build(),
            )
            .build();
        let metrics = SdkMeterProvider::builder()
            .with_resource(resource)
            .with_reader(
                PeriodicReader::builder(metrics)
                    .with_interval(Duration::from_secs(15))
                    .build(),
            )
            .build();
        let error_tracking = posthog_rs::ErrorTrackingOptionsBuilder::default()
            .capture_panics(true)
            .trace_context_provider(|| {
                let context = Span::current().context();
                let span = context.span();
                let context = span.span_context();
                context.is_valid().then(|| {
                    posthog_rs::TraceContext::new(
                        context.trace_id().to_string(),
                        context.span_id().to_string(),
                    )
                })
            })
            .build()?;
        let mut builder = posthog_rs::ClientOptionsBuilder::default();
        builder.before_send(|mut event| {
            if event.properties().contains_key("$exception_panic_file")
                && let Some(mut exceptions) = event.remove_prop("$exception_list")
            {
                if let Some(items) = exceptions.as_array_mut() {
                    for item in items {
                        item["value"] = "Server panic (payload redacted)".into();
                    }
                }
                let _ = event.insert_prop("$exception_list", exceptions);
            }
            Some(event)
        });
        let options = builder
            .api_key(settings.token)
            .host(settings.host)
            .blocking_http_client(client)
            .request_timeout_seconds(2)
            .max_queue_size(32)
            .max_batch_size(32)
            .flush_at(16)
            .flush_interval_ms(5000)
            .shutdown_timeout_ms(2000)
            .error_tracking(error_tracking)
            .disable_geoip(true)
            .build()?;
        posthog_rs::init_global(options)?;
        let tracer = traces.tracer("snowstead-api");
        let journal_filter =
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_filter(journal_filter))
            .with(
                PoolTimingLayer.with_filter(tracing_subscriber::filter::filter_fn(|meta| {
                    meta.target() == "sqlx::pool::acquire"
                })),
            )
            .with(
                tracing_opentelemetry::layer()
                    .with_tracer(tracer)
                    .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
                        meta.is_span() && meta.target() == "snowstead_observability"
                    })),
            )
            .with(
                opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&logs)
                    .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
                        meta.is_event() && meta.target() == "snowstead_observability"
                    })),
            )
            .try_init()?;
        let _ = MEASUREMENTS.set(Measurements::new(
            &metrics,
            settings.service,
            settings.release,
        ));
        tracing::info!(target: "snowstead_observability", "Observability export enabled");
        Ok(Self {
            traces,
            logs,
            metrics,
        })
    }

    pub async fn shutdown(self) {
        // Use a detached OS thread, not spawn_blocking: Tokio waits for blocking
        // tasks on exit, which would defeat the outer shutdown deadline.
        let (done, wait) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let _ = self.traces.shutdown_with_timeout(EXPORT_TIMEOUT);
            let _ = self.logs.shutdown_with_timeout(EXPORT_TIMEOUT);
            let _ = self.metrics.shutdown_with_timeout(EXPORT_TIMEOUT);
            posthog_rs::shutdown();
            let _ = done.send(());
        });
        if tokio::time::timeout(SHUTDOWN_TIMEOUT, wait).await.is_err() {
            tracing::warn!(
                "Observability shutdown deadline reached; remaining telemetry discarded"
            );
        }
    }
}

struct Measurements {
    service: String,
    release: Option<String>,
    requests: Counter<u64>,
    headers: Histogram<f64>,
    body: Histogram<f64>,
    operations: Histogram<f64>,
    pool_wait: Histogram<f64>,
}

impl Measurements {
    fn new(provider: &SdkMeterProvider, service: String, release: Option<String>) -> Self {
        use opentelemetry::metrics::MeterProvider;
        let meter = provider.meter("snowstead-api");
        Self {
            service,
            release,
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
        }
    }
}

pub(crate) fn enabled() -> bool {
    MEASUREMENTS.get().is_some()
}

// SQLx publishes a dedicated numeric-only acquisition event. Consume only its
// elapsed field, not query logs or messages, and keep this independent of RUST_LOG.
struct PoolTimingLayer;
impl<S: tracing::Subscriber> Layer<S> for PoolTimingLayer {
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
            self.span.in_scope(|| failure("http_5xx"));
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
pub(crate) fn identity(identity: &crate::auth::Identity, org: Option<&str>) {
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

pub(crate) fn failure(kind: &'static str) {
    let Some(metrics) = MEASUREMENTS.get() else {
        return;
    };
    tracing::error!(target: "snowstead_observability", kind, "Unexpected server failure");
    let context = Span::current().context();
    let span = context.span();
    let context = span.span_context();
    let mut options = posthog_rs::CaptureExceptionOptions::new().fingerprint(kind);
    if context.is_valid() {
        options = options.trace_context(
            context.trace_id().to_string(),
            context.span_id().to_string(),
        );
    }
    if let Ok(value) = options.clone().property("service", &metrics.service) {
        options = value;
    }
    if let Some(release) = &metrics.release
        && let Ok(value) = options.clone().property("release", release)
    {
        options = value;
    }
    // Generic values prevent errors from smuggling SQL parameters, URLs, or
    // secrets into exception messages. The SDK captures the local stack.
    let _ = posthog_rs::capture_exception_with(&std::io::Error::other(kind), options);
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::{Body, Bytes, to_bytes},
        http::StatusCode,
        routing::any,
    };
    use opentelemetry_proto::tonic::{
        collector::{
            logs::v1::ExportLogsServiceRequest, metrics::v1::ExportMetricsServiceRequest,
            trace::v1::ExportTraceServiceRequest,
        },
        metrics::v1::Metric,
    };
    use prost::Message;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    #[test]
    fn configuration_is_explicit_and_invalid_values_fail_closed() {
        let read = |entries: &[(&str, &str)]| {
            Settings::read(|key| {
                entries
                    .iter()
                    .find(|(name, _)| *name == key)
                    .map(|(_, value)| value.to_string())
            })
        };
        assert!(read(&[]).unwrap().is_none());
        assert!(read(&[("POSTHOG_PROJECT_TOKEN", "test")]).is_err());
        assert_eq!(
            read(&[
                ("POSTHOG_PROJECT_TOKEN", "test"),
                ("POSTHOG_HOST", "https://eu.i.posthog.com"),
            ])
            .unwrap()
            .unwrap()
            .sample_rate,
            0.4
        );
        for host in [
            "https://eu.i.posthog.com/path",
            "https://user:password@eu.i.posthog.com",
            "https://eu.i.posthog.com?secret=test",
            "http://remote.example.com",
        ] {
            assert!(read(&[("POSTHOG_PROJECT_TOKEN", "test"), ("POSTHOG_HOST", host)]).is_err());
        }
        for sample in ["NaN", "inf", "-0.1", "1.01", "invalid"] {
            assert!(
                read(&[
                    ("POSTHOG_PROJECT_TOKEN", "test"),
                    ("POSTHOG_HOST", "https://eu.i.posthog.com"),
                    ("OBSERVABILITY_SAMPLE_RATE", sample)
                ])
                .is_err()
            );
        }
        for sample in ["0", "0.37", "1"] {
            assert!(
                read(&[
                    ("POSTHOG_PROJECT_TOKEN", "test"),
                    ("POSTHOG_HOST", "https://eu.i.posthog.com/"),
                    ("OBSERVABILITY_SAMPLE_RATE", sample)
                ])
                .unwrap()
                .is_some()
            );
        }
    }

    // SDKs and the subscriber are process globals. Separate processes exercise
    // production initialization without mutating the test runner's environment.
    #[test]
    fn export_contract() {
        if let Ok(mode) = std::env::var("SNOWSTEAD_TELEMETRY_TEST") {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap()
                .block_on(scenario(&mode));
            return;
        }
        for mode in ["export", "unsampled", "unavailable"] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "observability::tests::export_contract",
                    "--nocapture",
                ])
                .env("SNOWSTEAD_TELEMETRY_TEST", mode)
                .env("RUST_LOG", "off")
                .status()
                .unwrap();
            assert!(status.success(), "observability scenario {mode} failed");
        }
    }

    #[derive(Clone)]
    struct Capture {
        path: String,
        body: Bytes,
    }

    fn metrics(captures: &[Capture]) -> Vec<Metric> {
        captures
            .iter()
            .filter(|c| c.path == "/i/v1/metrics")
            .flat_map(|c| {
                ExportMetricsServiceRequest::decode(c.body.clone())
                    .unwrap()
                    .resource_metrics
                    .into_iter()
                    .flat_map(|r| r.scope_metrics)
                    .flat_map(|s| s.metrics)
            })
            .collect()
    }

    async fn flush_metrics(telemetry: &Telemetry) {
        let metrics = telemetry.metrics.clone();
        tokio::task::spawn_blocking(move || metrics.force_flush().unwrap())
            .await
            .unwrap();
    }

    async fn scenario(mode: &str) {
        let captured = Arc::new(Mutex::new(Vec::<Capture>::new()));
        let received = captured.clone();
        let collector = Router::new().fallback(any(move |request: Request| {
            let received = received.clone();
            async move {
                let path = request.uri().path().to_owned();
                if path.starts_with("/i/v1/") {
                    assert_eq!(request.headers()["authorization"], "Bearer test-project");
                }
                let body = to_bytes(request.into_body(), 2 * 1024 * 1024)
                    .await
                    .unwrap();
                received.lock().unwrap().push(Capture { path, body });
                (
                    StatusCode::OK,
                    [("content-type", "application/x-protobuf")],
                    Bytes::new(),
                )
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = format!("http://{}", listener.local_addr().unwrap());
        let collector = tokio::spawn(async move {
            axum::serve(listener, collector).await.unwrap();
        });
        let settings = Settings {
            token: "test-project".into(),
            host,
            sample_rate: if mode == "unsampled" { 0.0 } else { 1.0 },
            service: "contract-api".into(),
            release: Some("test-release".into()),
        };
        let telemetry = tokio::task::spawn_blocking(move || Telemetry::build(settings).unwrap())
            .await
            .unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let config = crate::config::Config {
            admin_secret: "private-operator-token".into(),
            ..Default::default()
        };
        let storage = crate::storage::Storage::from_stores(
            Arc::new(object_store::memory::InMemory::new()),
            Arc::new(object_store::memory::InMemory::new()),
        );
        let state = crate::AppState::new(
            pool.clone(),
            config,
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap();
        let app = crate::router(state);
        let request = || {
            Request::builder()
                .uri("/?secret=private-query-secret")
                .header("authorization", "Bearer private-bearer-secret")
                .header("cookie", "private-cookie-secret")
                .header(
                    "traceparent",
                    "00-11111111111111111111111111111111-2222222222222222-01",
                )
                .header("tracestate", "secret=private-tracestate-secret")
                .body(Body::from("private-body-secret"))
                .unwrap()
        };
        if mode == "unavailable" {
            collector.abort();
            let started = Instant::now();
            for _ in 0..300 {
                let response = app.clone().oneshot(request()).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                to_bytes(response.into_body(), 4096).await.unwrap();
            }
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "requests waited for telemetry"
            );
            let started = Instant::now();
            telemetry.shutdown().await;
            assert!(started.elapsed() < Duration::from_secs(9));
            return;
        }
        let first = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        flush_metrics(&telemetry).await;
        {
            let received = captured.lock().unwrap();
            let snapshot = metrics(&received);
            assert!(
                snapshot
                    .iter()
                    .any(|m| m.name == "snowstead.http.headers_duration")
            );
        }
        drop(first);
        // Exercise real storage boundaries, including the spawned multipart
        // initiation. Keys and payloads must never become span attributes.
        async {
            storage
                .put(true, "private-storage-key/object", b"private-storage-body")
                .await
                .unwrap();
            assert_eq!(
                storage
                    .list(true, "private-storage-key", None, 10)
                    .await
                    .unwrap()
                    .len(),
                1
            );
            storage
                .copy(
                    true,
                    "private-storage-key/object",
                    false,
                    "private-copy-key",
                )
                .await
                .unwrap();
            assert_eq!(
                storage.head(false, "private-copy-key").await.unwrap().size,
                20
            );
            storage
                .delete_many(vec![
                    (true, "private-storage-key/object".into()),
                    (false, "private-copy-key".into()),
                ])
                .await
                .unwrap();
        }
        .instrument(tracing::info_span!(target: "snowstead_observability", "storage.contract"))
        .await;
        // A closed pool forces a real API failure, without a network/database
        // dependency. Its sanitized exception must correlate with the request.
        pool.close().await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/_api/v1/admin/caches")
                    .header("authorization", "Bearer private-operator-token")
                    .header(
                        "traceparent",
                        "00-33333333333333333333333333333333-4444444444444444-01",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        to_bytes(response.into_body(), 4096).await.unwrap();
        let _ = tokio::task::spawn_blocking(|| {
            std::panic::catch_unwind(|| panic!("private-panic-secret"))
        })
        .await
        .unwrap();
        flush_metrics(&telemetry).await;
        telemetry.shutdown().await;
        let received = captured.lock().unwrap();
        let snapshot = metrics(&received);
        assert!(
            snapshot
                .iter()
                .any(|m| m.name == "snowstead.http.body_duration")
        );
        let mut spans = Vec::new();
        let mut exceptions = Vec::new();
        let mut logs = Vec::new();
        for capture in received.iter() {
            let text = String::from_utf8_lossy(&capture.body);
            for secret in [
                "private-query-secret",
                "private-bearer-secret",
                "private-cookie-secret",
                "private-tracestate-secret",
                "private-body-secret",
                "private-panic-secret",
                "private-operator-token",
                "private-storage-key",
                "private-storage-body",
                "private-copy-key",
            ] {
                assert!(
                    !text.contains(secret),
                    "secret exported via {}",
                    capture.path
                );
            }
            match capture.path.as_str() {
                "/i/v1/traces" => spans.extend(
                    ExportTraceServiceRequest::decode(capture.body.clone())
                        .unwrap()
                        .resource_spans
                        .into_iter()
                        .flat_map(|r| r.scope_spans)
                        .flat_map(|s| s.spans),
                ),
                "/i/v1/logs" => logs.extend(
                    ExportLogsServiceRequest::decode(capture.body.clone())
                        .unwrap()
                        .resource_logs
                        .into_iter()
                        .flat_map(|r| r.scope_logs)
                        .flat_map(|s| s.log_records),
                ),
                "/batch/" | "/batch" => {
                    let value: serde_json::Value = serde_json::from_slice(&capture.body).unwrap();
                    exceptions.extend(
                        value["batch"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .filter(|e| e["event"] == "$exception")
                            .cloned(),
                    );
                }
                _ => {}
            }
        }
        assert!(
            logs.iter().any(|log| log.trace_id == vec![0x33; 16]),
            "error log lost request context"
        );
        assert_eq!(
            exceptions.len(),
            2,
            "API error and panic should create exceptions"
        );
        assert!(
            exceptions
                .iter()
                .any(|event| event["properties"]["$exception_list"][0]["value"] == "http_5xx")
        );
        if mode == "unsampled" {
            assert!(spans.is_empty(), "zero sampling still exported traces");
        } else {
            let root = spans
                .iter()
                .find(|span| span.name == "GET /" && span.trace_id == vec![0x11; 16])
                .expect("incoming trace missing");
            assert_eq!(root.parent_span_id, vec![0x22; 8]);
            assert_eq!(root.kind, 2, "request must be an OTLP server span");
            let failed = spans
                .iter()
                .find(|span| span.trace_id == vec![0x33; 16] && span.kind == 2)
                .unwrap();
            assert_eq!(
                failed.status.as_ref().unwrap().code,
                2,
                "5xx must mark the trace as failed"
            );
            let database = spans
                .iter()
                .find(|span| span.name == "management.cache_summaries_sql")
                .expect("database span missing");
            assert_eq!(database.trace_id, failed.trace_id);
            let summaries = spans
                .iter()
                .find(|span| span.name == "management.cache_summaries")
                .unwrap();
            assert_eq!(database.parent_span_id, summaries.span_id);
            let storage_root = spans
                .iter()
                .find(|span| span.name == "storage.contract")
                .unwrap();
            for name in [
                "storage.put",
                "storage.list",
                "storage.copy",
                "storage.head",
                "storage.delete_many",
            ] {
                let span = spans
                    .iter()
                    .find(|span| span.name == name)
                    .unwrap_or_else(|| panic!("missing {name}"));
                assert_eq!(span.trace_id, storage_root.trace_id);
                assert_eq!(span.parent_span_id, storage_root.span_id);
            }
            let upload = spans
                .iter()
                .find(|span| span.name == "storage.upload")
                .unwrap();
            for name in [
                "storage.multipart_start",
                "storage.multipart_part",
                "storage.multipart_complete",
            ] {
                let span = spans
                    .iter()
                    .find(|span| span.name == name)
                    .unwrap_or_else(|| panic!("missing {name}"));
                assert_eq!(span.trace_id, upload.trace_id);
                assert_eq!(
                    span.parent_span_id, upload.span_id,
                    "{name} lost upload context"
                );
            }
        }
        collector.abort();
    }
}
