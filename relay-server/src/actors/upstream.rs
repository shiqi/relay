//! This actor can be used for sending signed requests to the upstream relay.
use std::borrow::Cow;
use std::str;
use std::sync::Arc;

use ::actix::fut;
use ::actix::prelude::*;
use actix_web::client::{ClientRequest, ClientRequestBuilder, ClientResponse, SendRequestError};
use actix_web::error::{JsonPayloadError, PayloadError};
use actix_web::http::{header, Method, StatusCode};
use actix_web::{Error as ActixError, HttpMessage};
use failure::Fail;
use futures::{future, prelude::*};
use itertools::Itertools;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;

use relay_auth::{RegisterChallenge, RegisterRequest, RegisterResponse, Registration};
use relay_common::{tryf, LogError, RetryBackoff};
use relay_config::{Config, RelayMode};
use relay_quotas::{
    DataCategories, QuotaScope, RateLimit, RateLimitScope, RateLimits, RetryAfter, Scoping,
};

use crate::utils::{self, ApiErrorResponse};

#[derive(Fail, Debug)]
pub enum UpstreamRequestError {
    #[fail(display = "attempted to send request while not yet authenticated")]
    NotAuthenticated,

    #[fail(display = "attempted to send upstream request without credentials configured")]
    NoCredentials,

    #[fail(display = "could not parse json payload returned by upstream")]
    InvalidJson(#[cause] JsonPayloadError),

    #[fail(display = "could not send request to upstream")]
    SendFailed(#[cause] SendRequestError),

    #[fail(display = "failed to create upstream request: {}", _0)]
    BuildFailed(ActixError),

    #[fail(display = "failed to receive response from upstream")]
    PayloadFailed(#[cause] PayloadError),

    #[fail(display = "upstream requests rate limited")]
    RateLimited(UpstreamRateLimits),

    #[fail(display = "upstream request returned error {}", _0)]
    ResponseError(StatusCode, #[cause] ApiErrorResponse),
}

/// Represents the current auth state.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum AuthState {
    Unknown,
    RegisterRequestChallenge,
    RegisterChallengeResponse,
    Registered,
    Error,
}

impl AuthState {
    /// Returns true if the state is considered authenticated
    pub fn is_authenticated(self) -> bool {
        // XXX: the goal of auth state is that it also tracks auth
        // failures from queries.  Later we will need to
        // extend the states here for it.
        self == AuthState::Registered
    }
}

/// Rate limits returned by the upstream.
///
/// Upstream rate limits can come in two forms:
///  - `Retry-After` header with a generic timeout for all categories.
///  - `X-Sentry-Rate-Limits` header with fine-grained information on applied rate limits.
///
/// These limits do not carry scope information. Use `UpstreamRateLimits::scope` to attach scope
/// identifiers and return a fully populated `RateLimits` instance.
#[derive(Debug)]
pub struct UpstreamRateLimits {
    retry_after: RetryAfter,
    rate_limits: String,
}

impl UpstreamRateLimits {
    /// Creates an empty `UpstreamRateLimits` instance.
    fn new() -> Self {
        Self {
            retry_after: RetryAfter::from_secs(0),
            rate_limits: String::new(),
        }
    }

    /// Adds the `Retry-After` header to this rate limits instance.
    fn retry_after(mut self, header: Option<&str>) -> Self {
        if let Some(retry_after) = header.and_then(|s| s.parse().ok()) {
            self.retry_after = retry_after;
        }
        self
    }

    /// Adds the `X-Sentry-Rate-Limits` header to this instance.
    ///
    /// If multiple header values are given, this header should be joined. If the header is empty,
    /// an empty string should be passed.
    fn rate_limits(mut self, header: String) -> Self {
        self.rate_limits = header;
        self
    }

    /// Creates a scoped rate limit instance based on the provided `Scoping`.
    pub fn scope(self, scoping: &Scoping) -> RateLimits {
        // Try to parse the `X-Sentry-Rate-Limits` header in the most lenient way possible. If
        // anything goes wrong, skip over the invalid parts.
        let mut rate_limits = utils::parse_rate_limits(scoping, &self.rate_limits);

        // If there are no new-style rate limits in the header, fall back to the `Retry-After`
        // header. Create a default rate limit that only applies to the current data category at the
        // most specific scope (Key).
        if !rate_limits.is_limited() {
            rate_limits.add(RateLimit {
                categories: DataCategories::new(),
                scope: RateLimitScope::for_quota(scoping, QuotaScope::Key),
                reason_code: None,
                retry_after: self.retry_after,
            });
        }

        rate_limits
    }
}

/// Handles a response returned from the upstream.
///
/// If the response indicates success via 2XX status codes, `Ok(response)` is returned. Otherwise,
/// the response is consumed and an error is returned. Depending on the status code and details
/// provided in the payload, one of the following errors can be returned:
///
///  1. `RateLimited` for a `429` status code.
///  2. `ResponseError` in all other cases.
fn handle_response(
    response: ClientResponse,
) -> ResponseFuture<ClientResponse, UpstreamRequestError> {
    let status = response.status();

    if status.is_success() {
        return Box::new(future::ok(response));
    }

    // At this point, we consume the ClientResponse. This means we need to consume the response
    // payload stream, regardless of the status code. Parsing the JSON body may fail, which is a
    // non-fatal failure as the upstream is not expected to always include a valid JSON response.
    let future = response.json().then(move |json_result| {
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            let headers = response.headers();
            let retry_after = headers
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok());

            let rate_limits = headers
                .get_all(utils::RATE_LIMITS_HEADER)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .join(", ");

            let upstream_limits = UpstreamRateLimits::new()
                .retry_after(retry_after)
                .rate_limits(rate_limits);

            Err(UpstreamRequestError::RateLimited(upstream_limits))
        } else {
            // Coerce the result into an empty `ApiErrorResponse` if parsing JSON did not succeed.
            let api_response = json_result.unwrap_or_default();
            Err(UpstreamRequestError::ResponseError(status, api_response))
        }
    });

    Box::new(future)
}

pub struct UpstreamRelay {
    backoff: RetryBackoff,
    config: Arc<Config>,
    auth_state: AuthState,
}

impl UpstreamRelay {
    pub fn new(config: Arc<Config>) -> Self {
        UpstreamRelay {
            backoff: RetryBackoff::new(config.http_max_retry_interval()),
            config,
            auth_state: AuthState::Unknown,
        }
    }

    fn assert_authenticated(&self) -> Result<(), UpstreamRequestError> {
        if !self.auth_state.is_authenticated() {
            Err(UpstreamRequestError::NotAuthenticated)
        } else {
            Ok(())
        }
    }

    fn send_request<P, F>(
        &self,
        method: Method,
        path: P,
        build: F,
    ) -> ResponseFuture<ClientResponse, UpstreamRequestError>
    where
        F: FnOnce(&mut ClientRequestBuilder) -> Result<ClientRequest, ActixError>,
        P: AsRef<str>,
    {
        let host_header = self
            .config
            .http_host_header()
            .unwrap_or_else(|| self.config.upstream_descriptor().host());

        let mut builder = ClientRequest::build();
        builder
            .method(method)
            .uri(self.config.upstream_descriptor().get_url(path.as_ref()))
            .set_header("Host", host_header);

        if let Some(ref credentials) = self.config.credentials() {
            builder.header("X-Sentry-Relay-Id", credentials.id.to_string());
        }

        let request = tryf!(build(&mut builder).map_err(UpstreamRequestError::BuildFailed));
        let future = request
            .send()
            // We currently use the main connection pool size limit to control how many events get
            // sent out at once, and "queue" up the rest (queueing means that there are a lot of
            // futures hanging around, waiting for an open connection). We need to adjust this
            // timeout to prevent the queued events from timing out while waiting for a free
            // connection in the pool.
            //
            // This may not be good enough in the long run. Right now, filling up the "request
            // queue" means that requests unrelated to `store` (queries, proxied/forwarded requests)
            // are blocked by store requests. Ideally, those requests would bypass this queue.
            //
            // Two options come to mind:
            //   1. Have own connection pool for `store` requests
            //   2. Buffer up/queue/synchronize events before creating the request
            .wait_timeout(self.config.event_buffer_expiry())
            .conn_timeout(self.config.http_connection_timeout())
            // This is the timeout after wait + connect.
            .timeout(self.config.http_timeout())
            .map_err(UpstreamRequestError::SendFailed)
            .and_then(handle_response);

        Box::new(future)
    }

    fn send_query<Q: UpstreamQuery>(
        &self,
        query: Q,
    ) -> ResponseFuture<Q::Response, UpstreamRequestError> {
        let method = query.method();
        let path = query.path();

        let credentials = tryf!(self
            .config
            .credentials()
            .ok_or(UpstreamRequestError::NoCredentials));

        let (json, signature) = credentials.secret_key.pack(query);

        let max_response_size = self.config.max_api_payload_size();

        let future = self
            .send_request(method, path, |builder| {
                builder
                    .header("X-Sentry-Relay-Signature", signature)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(json)
            })
            .and_then(move |r| {
                r.json()
                    .limit(max_response_size)
                    .map_err(UpstreamRequestError::InvalidJson)
            });

        Box::new(future)
    }
}

impl Actor for UpstreamRelay {
    type Context = Context<Self>;

    fn started(&mut self, context: &mut Self::Context) {
        log::info!("upstream relay started");

        self.backoff.reset();

        if self.config.relay_mode() == RelayMode::Managed {
            context.notify(Authenticate);
        }
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        log::info!("upstream relay stopped");
    }
}

struct Authenticate;

impl Message for Authenticate {
    type Result = Result<(), ()>;
}

impl Handler<Authenticate> for UpstreamRelay {
    type Result = ResponseActFuture<Self, (), ()>;

    fn handle(&mut self, _msg: Authenticate, _ctx: &mut Self::Context) -> Self::Result {
        let credentials = match self.config.credentials() {
            Some(x) => x,
            None => return Box::new(fut::err(())),
        };

        log::info!(
            "registering with upstream ({})",
            self.config.upstream_descriptor()
        );

        self.auth_state = AuthState::RegisterRequestChallenge;
        let request = RegisterRequest::new(&credentials.id, &credentials.public_key);

        let future = self
            .send_query(request)
            .into_actor(self)
            .and_then(|challenge, slf, _ctx| {
                log::debug!("got register challenge (token = {})", challenge.token());
                slf.auth_state = AuthState::RegisterChallengeResponse;
                let challenge_response = challenge.create_response();

                log::debug!("sending register challenge response");
                slf.send_query(challenge_response).into_actor(slf)
            })
            .map(|_, slf, _ctx| {
                log::debug!("relay successfully registered with upstream");
                slf.auth_state = AuthState::Registered;
            })
            .map_err(|err, slf, ctx| {
                log::error!("authentication encountered error: {}", LogError(&err));
                slf.auth_state = AuthState::Error;

                // Do not retry client errors including authentication failures since client errors
                // are usually permanent. This allows the upstream to reject unsupported Relays
                // without infinite retries.
                let should_retry = match err {
                    UpstreamRequestError::ResponseError(code, _) => !code.is_client_error(),
                    _ => true,
                };

                if should_retry {
                    let interval = slf.backoff.next_backoff();
                    log::debug!(
                        "scheduling authentication retry in {} seconds",
                        interval.as_secs()
                    );

                    ctx.notify_later(Authenticate, interval);
                }
            });

        Box::new(future)
    }
}

pub struct IsAuthenticated;

impl Message for IsAuthenticated {
    type Result = bool;
}

impl Handler<IsAuthenticated> for UpstreamRelay {
    type Result = bool;

    fn handle(&mut self, _msg: IsAuthenticated, _ctx: &mut Self::Context) -> Self::Result {
        self.auth_state.is_authenticated()
    }
}

pub trait RequestBuilder: 'static {
    fn build_request(self, _: &mut ClientRequestBuilder) -> Result<ClientRequest, ActixError>;
}

pub trait ResponseTransformer: 'static {
    type Result: 'static;

    fn transform_response(self, _: ClientResponse) -> Self::Result;
}

impl RequestBuilder for () {
    fn build_request(
        self,
        builder: &mut ClientRequestBuilder,
    ) -> Result<ClientRequest, ActixError> {
        builder.finish()
    }
}

impl<F> RequestBuilder for F
where
    F: FnOnce(&mut ClientRequestBuilder) -> Result<ClientRequest, ActixError> + 'static,
{
    fn build_request(
        self,
        builder: &mut ClientRequestBuilder,
    ) -> Result<ClientRequest, ActixError> {
        self(builder)
    }
}

impl ResponseTransformer for () {
    type Result = ResponseFuture<(), UpstreamRequestError>;

    fn transform_response(self, response: ClientResponse) -> Self::Result {
        let future = response
            .payload()
            .for_each(|_| Ok(()))
            .map_err(UpstreamRequestError::PayloadFailed);

        Box::new(future)
    }
}

impl<F, T: 'static> ResponseTransformer for F
where
    F: FnOnce(ClientResponse) -> T + 'static,
{
    type Result = T;

    fn transform_response(self, response: ClientResponse) -> Self::Result {
        self(response)
    }
}

pub struct SendRequest<B = (), T = ()> {
    method: Method,
    path: String,
    builder: B,
    transformer: T,
}

impl SendRequest {
    pub fn new<S: Into<String>>(method: Method, path: S) -> Self {
        SendRequest {
            method,
            path: path.into(),
            builder: (),
            transformer: (),
        }
    }

    pub fn post<S: Into<String>>(path: S) -> Self {
        Self::new(Method::POST, path)
    }
}

impl<B, T> SendRequest<B, T> {
    pub fn build<F>(self, callback: F) -> SendRequest<F, T>
    where
        F: FnOnce(&mut ClientRequestBuilder) -> Result<ClientRequest, ActixError> + 'static,
    {
        SendRequest {
            method: self.method,
            path: self.path,
            builder: callback,
            transformer: self.transformer,
        }
    }
}

impl<B, R, T: 'static, E: 'static> Message for SendRequest<B, R>
where
    R: ResponseTransformer,
    R::Result: IntoFuture<Item = T, Error = E>,
{
    type Result = Result<T, E>;
}

impl<B, R, T: 'static, E: 'static> Handler<SendRequest<B, R>> for UpstreamRelay
where
    B: RequestBuilder,
    R: ResponseTransformer,
    R::Result: IntoFuture<Item = T, Error = E>,
    T: Send,
    E: From<UpstreamRequestError> + Send,
{
    type Result = ResponseFuture<T, E>;

    fn handle(&mut self, message: SendRequest<B, R>, _ctx: &mut Self::Context) -> Self::Result {
        let SendRequest {
            method,
            path,
            builder,
            transformer,
        } = message;

        Box::new(
            self.send_request(method, path, |b| builder.build_request(b))
                .from_err()
                .and_then(|r| transformer.transform_response(r)),
        )
    }
}

pub trait UpstreamQuery: Serialize {
    type Response: DeserializeOwned + 'static + Send;

    fn method(&self) -> Method;

    fn path(&self) -> Cow<'static, str>;
}

pub struct SendQuery<T: UpstreamQuery>(pub T);

impl<T: UpstreamQuery> Message for SendQuery<T> {
    type Result = Result<T::Response, UpstreamRequestError>;
}

impl<T: UpstreamQuery> Handler<SendQuery<T>> for UpstreamRelay {
    type Result = ResponseFuture<T::Response, UpstreamRequestError>;

    fn handle(&mut self, message: SendQuery<T>, _ctx: &mut Self::Context) -> Self::Result {
        tryf!(self.assert_authenticated());
        self.send_query(message.0)
    }
}

impl UpstreamQuery for RegisterRequest {
    type Response = RegisterChallenge;

    fn method(&self) -> Method {
        Method::POST
    }
    fn path(&self) -> Cow<'static, str> {
        Cow::Borrowed("/api/0/relays/register/challenge/")
    }
}

impl UpstreamQuery for RegisterResponse {
    type Response = Registration;

    fn method(&self) -> Method {
        Method::POST
    }
    fn path(&self) -> Cow<'static, str> {
        Cow::Borrowed("/api/0/relays/register/response/")
    }
}
