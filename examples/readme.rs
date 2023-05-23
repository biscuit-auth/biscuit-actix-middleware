use actix_web::{get, web, App, HttpResponse, HttpServer};
use biscuit_actix_middleware::BiscuitMiddleware;
use biscuit_auth::{macros::*, Biscuit, PublicKey};
#[cfg(feature = "tracing")]
use tracing::warn;
#[cfg(feature = "tracing")]
use tracing_actix_web::TracingLogger;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let public_key = PublicKey::from_bytes_hex(
        &std::env::var("BISCUIT_PUBLIC_KEY")
            .expect("Missing BISCUIT_PUBLIC_KEY environment variable. You can fix it by using the following command to run the example: BISCUIT_PUBLIC_KEY=2d6a07768e5768192870f91a6949cd09ce49865f2e2eb1241369c300ee7cc21f cargo run --example readme"),
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

    #[cfg(feature = "tracing")]
    tracer::init_logger();

    println!("Starting server on 127.0.0.1:8080");
    HttpServer::new(move || {
        let app = App::new()
            .wrap(BiscuitMiddleware { public_key })
            .service(hello);

        #[cfg(feature = "tracing")]
        // Wrap [tracing-actix-web](https://crates.io/crates/tracing-actix-web) middleware
        let app = app.wrap(TracingLogger::default());

        app
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
        #[cfg(feature = "tracing")]
        warn!("{}", _e.to_string());
        return HttpResponse::Forbidden().finish();
    }

    HttpResponse::Ok().body("Hello admin!")
}

#[cfg(feature = "tracing")]
// Simple tracing logger
// See [tracing crate](https://crates.io/crates/tracing) for more info on
// how to use traces for logs and telemetry
mod tracer {
    use std::fmt::Write;
    use tracing::{
        field::{Field, Visit},
        Subscriber,
    };
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{layer::Context, registry::LookupSpan, EnvFilter, Layer};

    pub fn init_logger() {
        // Set custom log layer
        let log = LogLayer {};

        // Disable all layers with env_filter (ie with level <= RUST_LOG)
        // create a subscriber with log layer
        let env_filter = EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new("info"));
        let subscriber = tracing_subscriber::Registry::default()
            .with(env_filter)
            .with(log);

        // Register the subscriber
        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to init global subscriber.");
    }

    struct LogLayer;

    impl<S> Layer<S> for LogLayer
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        // on an incoming trace event, print it to stdout
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = StrVisitor {
                field: "message",
                value: String::new(),
            };
            event.record(&mut visitor);
            if visitor.value.len() == 0 {
                visitor.field = "trace";
                event.record(&mut visitor);
            }

            println!(
                "[{}] [{}] - {}",
                event.metadata().level(),
                event.metadata().target(),
                visitor.value
            );
        }
    }

    // visitor used to read log message
    struct StrVisitor {
        field: &'static str,
        value: String,
    }

    impl Visit for StrVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == self.field {
                write!(self.value, "{:?}", value).unwrap_or_default();
            }
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == self.field {
                self.value = value.to_string();
            }
        }
    }
}
