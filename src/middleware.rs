use std::future::{ready, Ready};
use biscuit::{Biscuit, PublicKey};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, body::EitherBody, web, HttpMessage, ResponseError
};
#[cfg(feature = "tracing")]
use tracing::{error, warn};
use crate::error::{MiddlewareError, MiddlewareResult}/*,  RevokedTokenList} */;
#[cfg(feature = "ttl")]
use crate::ttl::has_biscuit_expired;
use futures_util::future::LocalBoxFuture;

/// If a valid token is present inject the biscuit token 
/// as extension for handlers else return an Unauthorized with error message in body
/// 
/// ```rust
/// # use actix_web::{web, HttpResponse};
/// # use biscuit_auth::Biscuit;
/// 
/// async fn book(biscuit: web::ReqData<Biscuit>) -> HttpResponse {
///   # println!("{}", biscuit.print());
/// 
///   HttpResponse::Ok().finish()
/// }
/// ```
pub struct BiscuitToken;

impl<S, B> Transform<S, ServiceRequest> for BiscuitToken
where
  S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
  S::Future: 'static,
  B: 'static,
{
  type Response = ServiceResponse<EitherBody<B>>;
  type Error = Error;
  type InitError = ();
  type Transform = BiscuitTokenMiddleware<S>;
  type Future = Ready<Result<Self::Transform, Self::InitError>>;

  fn new_transform(&self, service: S) -> Self::Future {
      ready(Ok(BiscuitTokenMiddleware { service }))
  }
}

pub struct BiscuitTokenMiddleware<S> {
    service: S,
}

impl<S> BiscuitTokenMiddleware<S> {
  fn generate_biscuit_token(&self, req: &ServiceRequest) -> MiddlewareResult<Biscuit> {
    let pk = req.app_data::<web::Data<PublicKey>>()
      .ok_or_else(|| {
        let trace = "Public key app state is missing".to_string();
        #[cfg(feature = "tracing")]
        error!(trace);
        MiddlewareError::InternalServerError(trace)
      })?;
    
    let token = req.headers().get("Biscuit")
      .ok_or_else(|| {
        let trace = "Biscuit token header is missing".to_string();
        #[cfg(feature = "tracing")]
        warn!(trace);
        MiddlewareError::BadRequest(trace)
      })?
      .to_str().map_err(|_| {
        let trace = "Biscuit token contains non ASCII chars".to_string();
        #[cfg(feature = "tracing")]
        warn!(trace);
        MiddlewareError::BadRequest(trace)
      })?;

    // check if expiration date is not ok
    match Biscuit::from_base64(token, ***pk) {
      Ok(biscuit) => {

        #[cfg(feature = "ttl")]
        if has_biscuit_expired(&biscuit)? {
          let trace = "Biscuit token has expired".to_string();
          #[cfg(feature = "tracing")]
          warn!(trace);
          return Err(MiddlewareError::Unauthorized(trace))
        }

        // check if token is revoked
        #[cfg(feature = "revocation")]
        {
          todo!()
        }
    
        Ok(biscuit)
      },
      Err(error) => {
        let trace = error.to_string();
        #[cfg(feature = "tracing")]
        warn!(trace);
        Err(MiddlewareError::Unauthorized(trace))
      }
    }
  }
}

impl<S, B> Service<ServiceRequest> for BiscuitTokenMiddleware<S>
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
  #[cfg(feature = "ttl")]
  use crate::ttl::add_ttl_to_biscuit;

  #[actix_web::test]
  async fn test_nominal() {
    let root = KeyPair::new();
    let pk = web::Data::new(root.public());
    let app = test::init_service(
      App::new()
        .app_data(pk)
        .wrap(BiscuitToken)
        .service(
          web::resource("/test")
            .route(web::get().to(handler_biscuit_token_test))
        )
    ).await;

    #[cfg(feature = "revocation")]
    {
      todo!();
    }

    let biscuit = {
      #[cfg(feature = "ttl")]
      {
        let mut builder = Biscuit::builder();
        add_ttl_to_biscuit(&mut builder, 100).unwrap();
        builder.build(&root)
          .unwrap()
      }
      #[cfg(not(feature = "ttl"))]
      {
        Biscuit::builder()
          .build(&root)
          .unwrap()
      }
      
    };
    let req = test::TestRequest::get()
      .insert_header((
        "Biscuit",
        biscuit.to_base64().unwrap()
      ))
      .uri("/test")
      .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
  }

  #[actix_web::test]
  async fn test_pk_missing() {
    let app = test::init_service(
      App::new()
        .wrap(BiscuitToken)
        .service(
          web::resource("/test")
            .route(web::get().to(handler_biscuit_token_test))
        )
    ).await;

    let req = test::TestRequest::get()
      .uri("/test")
      .to_request();
    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
  }

  #[actix_web::test]
  async fn test_header_missing() {
    let root = KeyPair::new();
    let pk = web::Data::new(root.public());
    let app = test::init_service(
      App::new()
        .app_data(pk)
        .wrap(BiscuitToken)
        .service(
          web::resource("/test")
            .route(web::get().to(handler_biscuit_token_test))
        )
    ).await;

    let req = test::TestRequest::get()
      .uri("/test")
      .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
  }

  #[actix_web::test]
  async fn test_incorrect_header() {
    let root = KeyPair::new();
    let pk = web::Data::new(root.public());
    let app = test::init_service(
      App::new()
        .app_data(pk)
        .wrap(BiscuitToken)
        .service(
          web::resource("/test")
            .route(web::get().to(handler_biscuit_token_test))
        )
    ).await;

    let req = test::TestRequest::get()
      .insert_header((
        "Biscuit",
        "ééé"
      ))
      .uri("/test")
      .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
  }

  #[cfg(feature = "revocation")]
  #[actix_web::test]
  async fn test_revoke_missing() {
    todo!();
  }

  #[cfg(feature = "revocation")]
  #[actix_web::test]
  async fn test_revoked() {
    todo!();
  }

  #[cfg(feature = "ttl")]
  #[actix_web::test]
  async fn test_expired() {
    let root = KeyPair::new();
    let pk = web::Data::new(root.public());
    let app = test::init_service(
      App::new()
        .app_data(pk)
        .wrap(BiscuitToken)
        .service(
          web::resource("/test")
            .route(web::get().to(handler_biscuit_token_test))
        )
    ).await;

    let mut builder = Biscuit::builder();
    add_ttl_to_biscuit(&mut builder, -100).unwrap();
    let biscuit = builder.build(&root)
      .unwrap();
    let req = test::TestRequest::get()
      .insert_header((
        "Biscuit",
        biscuit.to_base64().unwrap()
      ))
      .uri("/test")
      .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
  }

  async fn handler_biscuit_token_test(_: web::ReqData<Biscuit>) -> HttpResponse {
    HttpResponse::Ok().finish()
  }
}