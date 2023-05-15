use std::future::{ready, Ready};
use biscuit::{Biscuit, PublicKey};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, body::EitherBody, HttpMessage, ResponseError
};
#[cfg(feature = "tracing")]
use tracing::{warn};
use crate::error::{MiddlewareError, MiddlewareResult};
use futures_util::future::LocalBoxFuture;

/// On incoming request if there is a valid [bearer token](https://developer.mozilla.org/fr/docs/Web/HTTP/Authentication#bearer) authorization header:
/// - deserialize it using public key attribute
/// - inject a biscuit as extension in handler
/// 
/// else return an Unauthorized (invalid header format) or Forbidden (deserialization error)
/// with an error message in the body
/// 
/// ```rust
///  use actix_web::{App, web,
///   HttpResponse, get, HttpServer};
///  use biscuit_auth::{Biscuit, KeyPair};
///  use biscuit_actix_middleware::BiscuitMiddleware;
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
///     //.run()
///     //.await;
/// 
///     Ok(())
///   }
///   
///   #[get("/hello")]
///   async fn hello(biscuit: web::ReqData<Biscuit>) -> HttpResponse {
///     println!("{}", biscuit.print());
///  
///     HttpResponse::Ok().finish()
///   }
/// ```

pub struct BiscuitMiddleware {
  pub public_key: PublicKey
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
    ready(Ok(
      ImplBiscuitMiddleware { 
        service, 
        public_key: self.public_key 
    }))
  }
}

pub struct ImplBiscuitMiddleware<S> {
  service: S,
  public_key: PublicKey
}

impl<S> ImplBiscuitMiddleware<S> {
  fn generate_biscuit_token(&self, req: &ServiceRequest) -> MiddlewareResult<Biscuit> {
    // extract a slice from authorization header
    let token = &req.headers().get("authorization")
      .ok_or_else(|| {
        let trace = "Missing Authorization header".to_string();
        #[cfg(feature = "tracing")]
        warn!(trace);
        MiddlewareError::Unauthorized(trace)
      })?
      .to_str().map_err(|_| {
        let trace = "Biscuit token contains non ASCII chars".to_string();
        #[cfg(feature = "tracing")]
        warn!(trace);
        MiddlewareError::Unauthorized(trace)
      })?[7..];

    // deserialize token into a biscuit
    Ok(Biscuit::from_base64(token, self.public_key)
      .map_err(|e| {
        let trace = e.to_string();
        #[cfg(feature = "tracing")]
        warn!(trace);
        MiddlewareError::Forbidden(trace)
      })?)
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
    match self.generate_biscuit_token(&req) {
      Ok(biscuit) => {
        req.extensions_mut().insert(biscuit);
        let fut = self.service.call(req);

        Box::pin(async move {
          let res = fut.await?;
          Ok(res.map_into_left_body())
        })
      },
      Err(e) => {
        Box::pin(async move {
          let r = req.into_response(e.error_response()).map_into_right_body::<B>();

          Ok(r)
        })
      }
    }
  }
}

#[cfg(test)]
mod test {
  use actix_web::{test, App, web, HttpResponse,
  http::StatusCode};
  use super::*;
  use biscuit::KeyPair;

  #[actix_web::test]
  async fn test_nominal() {
    let root = KeyPair::new();
    let app = test::init_service(
      App::new()
        .wrap(BiscuitMiddleware{public_key: root.public()})
        .service(
          web::resource("/test")
            .route(web::get().to(handler_biscuit_token_test))
        )
    ).await;

    let biscuit = Biscuit::builder()
      .build(&root)
      .unwrap();
    let req = test::TestRequest::get()
      .insert_header((
        "authorization",
        String::from("Bearer ") + &biscuit.to_base64().unwrap()
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
        .wrap(BiscuitMiddleware{public_key: root.public()})
        .service(
          web::resource("/test")
            .route(web::get().to(handler_biscuit_token_test))
        )
    ).await;

    let req = test::TestRequest::get()
      .uri("/test")
      .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
  }

  #[actix_web::test]
  async fn test_incorrect_headers() {
    let root = KeyPair::new();
    let app = test::init_service(
      App::new()
        .wrap(BiscuitMiddleware{public_key: root.public()})
        .service(
          web::resource("/test")
            .route(web::get().to(handler_biscuit_token_test))
        )
    ).await;

    let req = test::TestRequest::get()
      .insert_header((
        "authorization",
        "ééé"
      ))
      .uri("/test")
      .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let req = test::TestRequest::get()
      .insert_header((
        "authorization",
        "Bearer foo"
      ))
      .uri("/test")
      .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
  }

  async fn handler_biscuit_token_test(_: web::ReqData<Biscuit>) -> HttpResponse {
    HttpResponse::Ok().finish()
  }
}