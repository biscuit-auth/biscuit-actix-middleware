use crate::error::{MiddlewareError, MiddlewareResult};
use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::header::Header,
    Error, HttpMessage, HttpResponse, ResponseError,
};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use biscuit::{Biscuit, RootKeyProvider};
use futures_util::future::LocalBoxFuture;
use std::{
    future::{ready, Ready},
    rc::Rc,
};
#[cfg(feature = "tracing")]
use tracing::warn;

type ErrorHandler = fn(MiddlewareError, &ServiceRequest) -> HttpResponse;
type TokenExtractor = fn(&ServiceRequest) -> Option<Vec<u8>>;

/// On incoming request if there is a valid [bearer token](https://datatracker.ietf.org/doc/html/rfc6750#section-2.1) authorization header:
/// - deserialize it using the provided public key
/// - inject a biscuit as extension in handler
///
/// else return an 401 Unauthorized (missing or invalid header) or 403 Forbidden (deserialization error)
/// with an error message in the body
///
/// # Example
///
/// ```rust
/// use actix_web::{get, web, App, HttpResponse, HttpServer};
/// use biscuit_actix_middleware::BiscuitMiddleware;
/// use biscuit_auth::{macros::*, Biscuit, KeyPair};
///
/// #[actix_web::main]
/// async fn main() -> std::io::Result<()> {
///     let root = KeyPair::new();
///     let public_key = root.public();
///
///     HttpServer::new(move || {
///         App::new()
///             .wrap(BiscuitMiddleware::new(public_key))
///             .service(hello)     
///     })
///     .bind(("127.0.0.1", 8080))?;
///     // this code is ran during tests so we can't start a long-running server
///     // uncomment the two lines below and remove the `Ok(())`.
///     //.run()
///     //.await
///     Ok(())
/// }
///   
/// #[get("/hello")]
/// async fn hello(biscuit: web::ReqData<Biscuit>) -> HttpResponse {
///     println!("{}", biscuit.print());
///     let mut authorizer = authorizer!(
///         r#"
///       allow if role("admin");
///     "#
///     );
///
///     authorizer.add_token(&biscuit).unwrap();
///     if authorizer.authorize().is_err() {
///         return HttpResponse::Forbidden().finish();
///     }
///
///     HttpResponse::Ok().body("Hello admin!")
/// }
/// ```

pub struct BiscuitMiddleware {
    public_key: Rc<dyn RootKeyProvider>,
    error_handler: ErrorHandler,
    token_extractor: TokenExtractor,
}

impl BiscuitMiddleware {
    /// Instantiate a new middleware.
    ///
    /// [RootKeyProvider] is a [biscuit-auth](biscuit) trait used to delegate [PublicKey](biscuit::PublicKey) selection/rotation implementation.
    ///
    /// If either selection or rotation are not required, you can pass a [PublicKey](biscuit::PublicKey) (it already implements [RootKeyProvider] in [biscuit-auth](biscuit) lib).
    ///
    /// # Examples
    ///
    /// Selection and rotation are not required
    ///
    /// ```rust
    /// use biscuit_actix_middleware::BiscuitMiddleware;
    /// use biscuit_auth::KeyPair;
    ///
    /// BiscuitMiddleware::new(KeyPair::new().public());
    /// ```
    ///
    /// Setup a simple KeyProvider that only accepts tokens with a root_key_id corresponding to an index of an existing [PublicKey](biscuit_auth::PublicKey)
    /// ```rust
    /// use biscuit_auth::{error::Format, Biscuit, KeyPair, PublicKey, RootKeyProvider};
    /// use biscuit_actix_middleware::BiscuitMiddleware;
    ///
    /// struct KeyProvider {
    ///     roots: Vec<KeyPair>,
    /// }
    ///
    /// impl KeyProvider {
    ///     fn new() -> Self {
    ///         let mut new = KeyProvider { roots: vec![] };
    ///
    ///         for _ in 1..11 {
    ///             new.roots.push(KeyPair::new());
    ///         }
    ///
    ///         new
    ///     }
    /// }
    ///
    /// impl RootKeyProvider for KeyProvider {
    ///     fn choose(&self, key_id: Option<u32>) -> Result<PublicKey, Format> {
    ///         Ok(self
    ///             .roots
    ///             .get(key_id.ok_or(Format::UnknownPublicKey)? as usize)
    ///             .ok_or(Format::UnknownPublicKey)?
    ///             .public())
    ///     }
    /// }
    ///
    /// let key_provider = KeyProvider::new();
    ///
    /// let mut builder = Biscuit::builder();
    /// builder.set_root_key_id(2);
    ///
    /// let biscuit = builder.build(&key_provider.roots[2]).unwrap();
    ///
    /// assert!(Biscuit::from_base64(biscuit.to_base64().unwrap(), &key_provider).is_ok());
    /// assert!(Biscuit::from_base64(biscuit.to_base64().unwrap(), &KeyPair::new().public()).is_err());
    ///
    /// let middleware = BiscuitMiddleware::new(key_provider);
    /// ```
    pub fn new<KP>(public_key: KP) -> BiscuitMiddleware
    where
        KP: RootKeyProvider + 'static,
    {
        BiscuitMiddleware {
            public_key: Rc::new(public_key),
            error_handler: |err: MiddlewareError, _: &ServiceRequest| err.error_response(),
            token_extractor: Self::default_token_extractor,
        }
    }

    /// Add a custom error handler to customize [HttpResponse] according to [MiddlewareError] and [ServiceRequest] params
    ///
    /// # Example
    /// ```rust
    /// use biscuit_actix_middleware::{BiscuitMiddleware, error::*};
    ///
    /// let root = KeyPair::new();
    /// let public_key = root.public();
    ///     
    /// BiscuitMiddleware::new(public_key)
    ///     .error_handler(
    ///         |err: MiddlewareError, _: &ServiceRequest| -> HttpResponse {
    ///             AppError::BiscuitToken.error_response()
    ///         });
    ///     
    /// #[derive(Debug, Display)]
    /// enum AppError {
    ///     BiscuitToken,
    /// }
    ///
    /// impl ResponseError for AppError {
    ///     fn error_response(&self) -> HttpResponse {
    ///         match self {
    ///             AppError::BiscuitToken => HttpResponse::Unauthorized().finish(),
    ///         }
    ///     }
    /// }    
    ///
    /// use actix_web::{error::ResponseError, dev::ServiceRequest, HttpResponse};
    /// use derive_more::Display;
    /// use biscuit_auth::KeyPair;
    /// ```
    pub fn error_handler(
        mut self,
        handler: fn(MiddlewareError, &ServiceRequest) -> HttpResponse,
    ) -> Self {
        self.error_handler = handler;

        self
    }

    /// Add a custom token extractor to an existing middleware
    ///
    /// # Example
    /// ```rust
    /// use biscuit_actix_middleware::BiscuitMiddleware;
    /// use actix_web::{dev::ServiceRequest};
    /// use biscuit_auth::KeyPair;
    ///
    /// let root = KeyPair::new();
    /// let public_key = root.public();
    ///     
    /// BiscuitMiddleware::new(public_key)
    ///     .token_extractor(|req: &ServiceRequest| {
    ///         Some(
    ///             req.headers()
    ///                 .get("biscuit")?
    ///                 .to_str()
    ///                 .ok()?
    ///                 .to_string()
    ///                 .into_bytes(),
    ///         )
    ///     });
    /// ```
    pub fn token_extractor(mut self, extractor: fn(&ServiceRequest) -> Option<Vec<u8>>) -> Self {
        self.token_extractor = extractor;

        self
    }

    /// Middleware default token extraction logic. It can be use as a base of a [custom token extractor](BiscuitMiddleware#method.token_extractor) to add pre/post processing to token extraction.
    pub fn default_token_extractor(req: &ServiceRequest) -> Option<Vec<u8>> {
        Some(
            Authorization::<Bearer>::parse(req)
                .map_err(|_e| {
                    #[cfg(feature = "tracing")]
                    warn!("{}", _e.to_string());
                })
                .ok()?
                .as_ref()
                .token()
                .to_string()
                .into_bytes(),
        )
    }
}

impl<S, B> Transform<S, ServiceRequest> for BiscuitMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = ImplBiscuitMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ImplBiscuitMiddleware {
            service,
            public_key: self.public_key.clone(),
            error_handler: self.error_handler,
            token_extractor: self.token_extractor,
        }))
    }
}

pub struct ImplBiscuitMiddleware<S> {
    service: S,
    public_key: Rc<dyn RootKeyProvider>,
    error_handler: ErrorHandler,
    token_extractor: TokenExtractor,
}

impl<S> ImplBiscuitMiddleware<S> {
    fn extract_biscuit(&self, req: &ServiceRequest) -> MiddlewareResult<Biscuit> {
        let token = (self.token_extractor)(req)
            .ok_or((self.error_handler)(MiddlewareError::InvalidHeader, req))?;

        // Parse token
        Biscuit::from_base64(token, self.public_key.clone()).map_err(|_e| {
            #[cfg(feature = "tracing")]
            warn!("{}", _e.to_string());
            (self.error_handler)(MiddlewareError::InvalidToken, req)
        })
    }
}

impl<S, B> Service<ServiceRequest> for ImplBiscuitMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        match self.extract_biscuit(&req) {
            Ok(biscuit) => {
                req.extensions_mut().insert(biscuit);
                let fut = self.service.call(req);

                Box::pin(async move {
                    let res = fut.await?;
                    Ok(res.map_into_left_body())
                })
            }
            Err(e) => Box::pin(async move {
                let r = req.into_response(e).map_into_right_body::<B>();
                Ok(r)
            }),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use actix_web::{http::StatusCode, test, web, App, HttpResponse};
    use biscuit::KeyPair;

    #[actix_web::test]
    async fn test_nominal() {
        let root = KeyPair::new();
        let app = test::init_service(
            App::new()
                .wrap(BiscuitMiddleware::new(root.public()))
                .service(web::resource("/test").route(web::get().to(handler_biscuit_token_test))),
        )
        .await;

        let biscuit = Biscuit::builder().build(&root).unwrap();
        let req = test::TestRequest::get()
            .insert_header((
                "authorization",
                String::from("Bearer ") + &biscuit.to_base64().unwrap(),
            ))
            .uri("/test")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_header_missing() {
        let root = KeyPair::new();
        let app = test::init_service(
            App::new()
                .wrap(BiscuitMiddleware::new(root.public()))
                .service(web::resource("/test").route(web::get().to(handler_biscuit_token_test))),
        )
        .await;

        let req = test::TestRequest::get().uri("/test").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn test_incorrect_headers() {
        let root = KeyPair::new();
        let app = test::init_service(
            App::new()
                .wrap(BiscuitMiddleware::new(root.public()))
                .service(web::resource("/test").route(web::get().to(handler_biscuit_token_test))),
        )
        .await;

        let req = test::TestRequest::get()
            .insert_header(("authorization", "ééé"))
            .uri("/test")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = test::TestRequest::get()
            .insert_header(("authorization", "Accessible foo"))
            .uri("/test")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = test::TestRequest::get()
            .insert_header(("authorization", "Bearer foo"))
            .uri("/test")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[actix_web::test]
    async fn test_error_handling() {
        let root = KeyPair::new();
        let app = test::init_service(
            App::new()
                .wrap(BiscuitMiddleware::new(root.public()).error_handler(
                    |_: MiddlewareError, _: &ServiceRequest| HttpResponse::BadRequest().finish(),
                ))
                .service(web::resource("/test").route(web::get().to(handler_biscuit_token_test))),
        )
        .await;

        let req = test::TestRequest::get().uri("/test").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn test_token_extractor() {
        let root = KeyPair::new();
        let biscuit = Biscuit::builder().build(&root).unwrap();

        let app = test::init_service(
            App::new()
                .wrap(BiscuitMiddleware::new(root.public()).token_extractor(
                    |req: &ServiceRequest| {
                        Some(
                            req.headers()
                                .get("biscuit")?
                                .to_str()
                                .ok()?
                                .to_string()
                                .into_bytes(),
                        )
                    },
                ))
                .service(web::resource("/test").route(web::get().to(handler_biscuit_token_test))),
        )
        .await;

        let req = test::TestRequest::get()
            .insert_header(("biscuit", biscuit.to_base64().unwrap()))
            .uri("/test")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_token_extractor_with_error_handling() {
        let root = KeyPair::new();

        let app = test::init_service(
            App::new()
                .wrap(
                    BiscuitMiddleware::new(root.public())
                        .token_extractor(|req: &ServiceRequest| {
                            Some(
                                req.headers()
                                    .get("biscuit")?
                                    .to_str()
                                    .ok()?
                                    .to_string()
                                    .into_bytes(),
                            )
                        })
                        .error_handler(|_: MiddlewareError, _: &ServiceRequest| {
                            HttpResponse::BadRequest().finish()
                        }),
                )
                .service(web::resource("/test").route(web::get().to(handler_biscuit_token_test))),
        )
        .await;

        let req = test::TestRequest::get().uri("/test").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    async fn handler_biscuit_token_test(_: web::ReqData<Biscuit>) -> HttpResponse {
        HttpResponse::Ok().finish()
    }
}
