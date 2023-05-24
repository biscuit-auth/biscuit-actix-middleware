use actix_web::{get, web, App, HttpResponse, HttpServer};
use biscuit_actix_middleware::BiscuitMiddleware;
use biscuit_auth::{macros::*, Biscuit, PublicKey};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let public_key = PublicKey::from_bytes_hex(
        &std::env::var("BISCUIT_PUBLIC_KEY")
            .expect("Missing BISCUIT_PUBLIC_KEY environment variable. You can fix it by using the following command to run the example: BISCUIT_PUBLIC_KEY=2d6a07768e5768192870f91a6949cd09ce49865f2e2eb1241369c300ee7cc21f cargo run --example error_handling"),
    )
    .expect("Couldn't parse public key");

    println!(
        r#"
This server exposes a single endpoint on `GET /hello`.
The whole server requires a valid biscuit token. Its signature is verified
by a public key provided through the `BISCUIT_PUBLIC_KEY` environment variable.
The `GET /hello` endpoints expects a token containg `role("admin");`.

You can generate a keypair and a token with the biscuit CLI:
> biscuit keypair # generates a key pair
> echo 'role("admin");' | biscuit generate --private-key <the private key> -

You can also use the following:

  public key: 2d6a07768e5768192870f91a6949cd09ce49865f2e2eb1241369c300ee7cc21f
  token: EnYKDBgDIggKBggGEgIYDRIkCAASIDZy3NpVVceLLr5Xqcv08H7BeBQry38djs13jJz6uDxVGkBWQyFbDLPYaEo1PMZxB6In0mbYFiAjWEJfd2kr7P2qu8YQDNCoyIBsRP4A-4OzfvzFr2o3x9b7jOHksiRxbpILIiIKIITNLF9dFYE_tbpsqBEgno0bbwLi56dvpM43SaK7o8Iu

The token has to be set in the authorization header:

  curl -v http://localhost:8080/hello \
    -H "Authorization: Bearer <token>"
"#
    );

    println!("Starting server on 127.0.0.1:8080");
    HttpServer::new(move || {
        App::new()
            .wrap(
                BiscuitMiddleware::new(public_key)
                    .error_handler(error::middleware_app_error_handler),
            )
            .service(hello)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[get("/hello")]
async fn hello(biscuit: web::ReqData<Biscuit>) -> HttpResponse {
    let mut authorizer = authorizer!(
        r#"
      allow if role("admin");
    "#
    );

    authorizer.add_token(&biscuit).unwrap();
    if let Err(_e) = authorizer.authorize() {
        return HttpResponse::Forbidden().finish();
    }

    HttpResponse::Ok().body("Hello admin!")
}

mod error {
    use actix_web::{dev::ServiceRequest, HttpResponse, ResponseError};
    use biscuit_actix_middleware::error::*;
    use derive_more::Display;

    #[derive(Debug, Display)]
    pub enum AppError {
        TokenMissing,
        Forbidden,
    }

    impl ResponseError for AppError {
        fn error_response(&self) -> HttpResponse {
            match self {
                AppError::TokenMissing => HttpResponse::Unauthorized().finish(),
                AppError::Forbidden => HttpResponse::Forbidden().finish(),
            }
        }
    }

    // ResponseError handler
    pub fn middleware_app_error_handler<'a>(
        err: MiddlewareError,
        _: &'a ServiceRequest,
    ) -> MiddlewareErrorResponse {
        MiddlewareErrorResponse::ResponseError(match err {
            MiddlewareError::InvalidHeader => Box::new(AppError::TokenMissing),
            MiddlewareError::InvalidToken => {
                // Eventually trace caller IP to detect brut force attack
                Box::new(AppError::Forbidden)
            }
        })
    }

    #[allow(dead_code)]
    // HttpResponse handler
    pub fn middleware_raw_error_handler<'a>(
        _: MiddlewareError,
        _: &'a ServiceRequest,
    ) -> MiddlewareErrorResponse {
        MiddlewareErrorResponse::HttpResponse(HttpResponse::Unauthorized().finish())
    }
}
