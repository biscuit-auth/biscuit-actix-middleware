# Biscuit actix middleware

On incoming request if there is a valid [bearer token](https://developer.mozilla.org/fr/docs/Web/HTTP/Authentication#bearer) authorization header:
- deserialize it using public key attribute
- inject a biscuit as extension in handler
 
 else return an Unauthorized (invalid header format) or Forbidden (deserialization error)
 with an error message in the body
 
```rust
  use actix_web::{App, web,
   HttpResponse, get, HttpServer};
  use biscuit_auth::{Biscuit, KeyPair};
  use biscuit_actix_middleware::BiscuitMiddleware;
 
  #[actix_web::main]
  async fn main() -> std::io::Result<()> {
    let root = KeyPair::new();
    let public_key = root.public();
  
    HttpServer::new(move || {
       App::new()
         .wrap(BiscuitMiddleware {
           public_key
         }).service(hello)     
     })
     .bind(("127.0.0.1", 8080))?
     .run()
     .await
   }
   
  #[get("/hello")]
  async fn hello(biscuit: web::ReqData<Biscuit>) -> HttpResponse {
    println!("{}", biscuit.print());

    HttpResponse::Ok().finish()
  }
```