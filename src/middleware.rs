use crate::error::{MiddlewareError, MiddlewareResult};
use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::header::Header,
    Error, HttpMessage, ResponseError,
};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use biscuit::{Biscuit, PublicKey};
use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};
#[cfg(feature = "tracing")]
use tracing::warn;

/// On incoming request if there is a valid [bearer token](https://datatracker.ietf.org/doc/html/rfc6750#section-2.1) authorization header:
/// - deserialize it using the provided public key
/// - inject a biscuit as extension in handler
///
/// else return an 401 Unauthorized (missing or invalid header) or 403 Forbidden (deserialization error)
/// with an error message in the body
///
/// ```rust
///  use actix_web::{get, web, App, HttpResponse, HttpServer};
///  use biscuit_actix_middleware::BiscuitMiddleware;
///  use biscuit_auth::{macros::*, Biscuit, KeyPair};
///
///  #[actix_web::main]
///  async fn main() -> std::io::Result<()> {
///    let root = KeyPair::new();
///    let public_key = root.public();
///  
///    HttpServer::new(move || {
///       App::new()
///         .wrap(BiscuitMiddleware {
///           public_key
///         }).service(hello)     
///     })
///     .bind(("127.0.0.1", 8080))?;
///     // this code is ran during tests so we can't start a long-running server
///     // uncomment the two lines below and remove the `Ok(())`.
///     //.run()
///     //.await
///     Ok(())
///   }
///   
///   #[get("/hello")]
///   async fn hello(biscuit: web::ReqData<Biscuit>) -> HttpResponse {
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
///   }
/// ```

pub struct BiscuitMiddleware {
    pub public_key: PublicKey,
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
            public_key: self.public_key,
        }))
    }
}

pub struct ImplBiscuitMiddleware<S> {
    service: S,
    public_key: PublicKey,
}

impl<S> ImplBiscuitMiddleware<S> {
    fn extract_biscuit(&self, req: &ServiceRequest) -> MiddlewareResult<Biscuit> {
        // extract token
        let header_value = Authorization::<Bearer>::parse(req).map_err(|_e| {
            #[cfg(feature = "tracing")]
            warn!("{}", _e.to_string());
            MiddlewareError::InvalidHeader
        })?;
        let token = header_value.as_ref().token();

        // deserialize token into a biscuit
        Biscuit::from_base64(token, self.public_key).map_err(|_e| {
            #[cfg(feature = "tracing")]
            warn!("{}", _e.to_string());
            MiddlewareError::InvalidToken
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
                let r = req
                    .into_response(e.error_response())
                    .map_into_right_body::<B>();
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
                .wrap(BiscuitMiddleware {
                    public_key: root.public(),
                })
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
                .wrap(BiscuitMiddleware {
                    public_key: root.public(),
                })
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
                .wrap(BiscuitMiddleware {
                    public_key: root.public(),
                })
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

    async fn handler_biscuit_token_test(_: web::ReqData<Biscuit>) -> HttpResponse {
        HttpResponse::Ok().finish()
    }
}
