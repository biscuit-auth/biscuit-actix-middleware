use actix_web::{error::ResponseError, HttpResponse};
use derive_more::Display;

pub type MiddlewareResult<R> = Result<R, MiddlewareError>;

#[derive(Debug, Display)]
pub enum MiddlewareError {
    InvalidHeader,
    InvalidToken,
}

impl ResponseError for MiddlewareError {
    fn error_response(&self) -> HttpResponse {
        match self {
            MiddlewareError::InvalidHeader => HttpResponse::Unauthorized().finish(),
            MiddlewareError::InvalidToken => HttpResponse::Forbidden().finish(),
        }
    }
}
