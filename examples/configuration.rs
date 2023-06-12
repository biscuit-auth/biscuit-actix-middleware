use actix_web::{dev::ServiceRequest, get, web, App, HttpResponse, HttpServer};
use biscuit_actix_middleware::BiscuitMiddleware;
use biscuit_auth::{macros::*, Biscuit, PublicKey};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let required_public_key = PublicKey::from_bytes_hex(
        &std::env::var("BISCUIT_PUBLIC_KEY")
            .expect("Missing BISCUIT_PUBLIC_KEY environment variable. You can fix it by using the following command to run the example: BISCUIT_PUBLIC_KEY=2d6a07768e5768192870f91a6949cd09ce49865f2e2eb1241369c300ee7cc21f cargo run --example configuration"),
    )
    .expect("Couldn't parse public key");

    let optional_public_key =
        std::env::var("BISCUIT_OPTIONAL_PUBLIC_KEY")
            .ok()
            .and_then(|bytes_hex| {
                Some(
                    PublicKey::from_bytes_hex(&bytes_hex)
                        .expect("Couldn't parse optional public key"),
                )
            });

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

Because of custom configuration, the token has to be set in the biscuit header:

  curl -v http://localhost:8080/hello \
    -H "biscuit: <token>"

An optional secondary public key can be provided through the `BISCUIT_OPTIONAL_PUBLIC_KEY` environment variable. 
Once set, each token must be generated with a root-key-id parameter equal to 0 or 1. Tokens signature are verified respectively with `BISCUIT_PUBLIC_KEY` (0) AND `BISCUIT_PUBLIC_KEY` (1).

You can generate token with a root-key-id parameter with the biscuit CLI:
> echo 'role("admin");' | biscuit generate --private-key <the private key> -root-key-id <root key id> -
"#
    );

    println!("Starting server on 127.0.0.1:8080");
    HttpServer::new(move || {
        App::new()
            .wrap(
                BiscuitMiddleware::new(key_provider::KeyProvider::new(
                    required_public_key,
                    optional_public_key,
                ))
                .error_handler(error::middleware_app_error_handler)
                .token_extractor(|req: &ServiceRequest| {
                    println!("Extracting token with custom extractor");

                    Some(
                        req.headers()
                            .get("biscuit")?
                            .to_str()
                            .ok()?
                            .to_string()
                            .into_bytes(),
                    )
                }),
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

mod key_provider {
    use biscuit_auth::{error::Format, PublicKey, RootKeyProvider};

    pub struct KeyProvider {
        roots: Vec<PublicKey>,
    }

    impl KeyProvider {
        pub fn new(required_key: PublicKey, optional_key: Option<PublicKey>) -> Self {
            let mut new = KeyProvider {
                roots: vec![required_key],
            };

            if let Some(pk) = optional_key {
                new.roots.push(pk);
            }

            new
        }
    }

    impl RootKeyProvider for KeyProvider {
        fn choose(&self, key_id: Option<u32>) -> Result<PublicKey, Format> {
            if self.roots.len() > 1 {
                Ok(self
                    .roots
                    .get(key_id.ok_or(Format::UnknownPublicKey)? as usize)
                    .ok_or(Format::UnknownPublicKey)?
                    .clone())
            } else if self.roots.len() == 1 {
                Ok(self.roots.last().unwrap().clone())
            } else {
                Err(Format::EmptyKeys)
            }
        }
    }
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
    ) -> HttpResponse {
        match err {
            MiddlewareError::InvalidHeader => {
                println!("Handle InvalidHeader error with custom handler");
                AppError::TokenMissing
            }
            MiddlewareError::InvalidToken => {
                // Eventually trace caller IP to detect brut force attack
                println!("Handle InvalidToken error with custom handler");
                AppError::Forbidden
            }
        }
        .error_response()
    }
}
