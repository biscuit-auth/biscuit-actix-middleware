use derive_more::Display;
use actix_web::{error::{ResponseError}, HttpResponse};

pub type MiddlewareResult<R> = Result<R, MiddlewareError>;

#[derive(Debug, Display)]
pub enum MiddlewareError {
  #[display(fmt = "Forbidden: {}", _0)]
  Forbidden(String),

  #[display(fmt = "Unauthorized: {}", _0)]
  Unauthorized(String),
}

impl ResponseError for MiddlewareError {
  fn error_response(&self) -> HttpResponse {
    match self {
      MiddlewareError::Unauthorized(ref trace) => {
        HttpResponse::Unauthorized().body(trace.clone())
      }
      MiddlewareError::Forbidden(ref trace) => {
        HttpResponse::Forbidden().body(trace.clone())
      }
    }
  }
}