# Biscuit actix middleware

This middleware allows service-wide extraction and parsing of [biscuit][biscuit] tokens.

**Authorization itself still need to be handled from within endpoint handlers.**

The middleware expects a base64-encoded token through the [bearer token HTTP authorization scheme][bearer-token-auth] (an `Authorization: Bearer <token>` HTTP header). This token is deserialized and its cryptographic signatures verified with the provided public key.

- Requests without a bearer token are rejected with a HTTP `401 Unauthorized` error;
- Requests with tokens that fail parsing or cryptographic verification are rejected with a HTTP `403 Forbidden` error.

Token extraction logic, token parsing logic and error handling are not configurable yet.

## Working example

Here is a web server exposing `GET /hello`, only to tokens containing the `role("admin")` fact. The public key used for verifying tokens is provided through the `BISCUIT_PUBLIC_KEY` environment variable.

A complete, runnable example can be found in `examples/readme.rs`, and can be run with `BISCUIT_PUBLIC_KEY=<public key> cargo run --example readme`.

```rust
use actix_web::{get, web, App, HttpResponse, HttpServer};
use biscuit_actix_middleware::BiscuitMiddleware;
use biscuit_auth::{macros::*, Biscuit, PublicKey};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let public_key = PublicKey::from_bytes_hex(
        &std::env::var("BISCUIT_PUBLIC_KEY")
            .expect("Missing BISCUIT_PUBLIC_KEY environment variable"),
    )
    .expect("Couldn't parse public key");

    HttpServer::new(move || {
        App::new()
            .wrap(BiscuitMiddleware { public_key })
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
    if authorizer.authorize().is_err() {
        return HttpResponse::Forbidden().finish();
    }

    HttpResponse::Ok().body("Hello admin!")
}

```

[biscuit]: https://biscuitsec.org
[bearer-token-auth]: https://datatracker.ietf.org/doc/html/rfc6750#section-2.1

