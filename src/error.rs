use derive_more::Display;
use actix_web::{error::{ResponseError, PayloadError}, HttpResponse};
use biscuit::error::Token as BiscuitError;

pub type MiddlewareResult<R> = Result<R, MiddlewareError>;

#[derive(Debug, Display)]
pub enum MiddlewareError {
  #[display(fmt = "Internal Server Error: {}", _0)]
  InternalServerError(String),
  
  #[display(fmt = "Forbidden: {}", _0)]
  Forbidden(String),

  #[display(fmt = "Unauthorized: {}", _0)]
  Unauthorized(String),
}

impl ResponseError for MiddlewareError {
  fn error_response(&self) -> HttpResponse {
    match self {
      MiddlewareError::InternalServerError(ref trace) => {
        HttpResponse::InternalServerError()
          .body(trace.clone())
      }
      MiddlewareError::Unauthorized(ref trace) => {
        HttpResponse::Unauthorized().body(trace.clone())
      }
      MiddlewareError::Forbidden(ref trace) => {
        HttpResponse::Forbidden().body(trace.clone())
      }
    }
  }
}

impl From<PayloadError> for MiddlewareError {
  fn from(error: PayloadError) -> MiddlewareError {
    MiddlewareError::InternalServerError(format!("Payload error: {}", error.to_string()))
  }
}

impl From<BiscuitError> for MiddlewareError {
  fn from(error: BiscuitError) -> MiddlewareError {
    match error {
      BiscuitError::Format(_) | BiscuitError::AppendOnSealed | 
      BiscuitError::AlreadySealed | BiscuitError::FailedLogic(_)
        => MiddlewareError::Unauthorized(error.to_string()),
      _ => MiddlewareError::InternalServerError(error.to_string())
    }
  }
}