use actix_web::{App, web, Responder,
  HttpResponse, get, test};
use biscuit_auth::{Biscuit, KeyPair, biscuit};
use biscuit_actix_middleware::BiscuitMiddleware;

#[get("/hello")]
async fn hello(biscuit: web::ReqData<Biscuit>) -> impl Responder {

  HttpResponse::Ok().body("Hello world!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
  let root = KeyPair::new();
  let user_role = "admin";

  let biscuit = biscuit!(
    r#"
      role({user_role});
    "#).build(&root)
    .unwrap();

  println!("{biscuit}");

  let biscuit_token = biscuit
    .to_base64()
    .unwrap();

  let app = test::init_service(
    App::new()
      .wrap(BiscuitMiddleware{
        public_key: root.public()
      }).service(hello)
  ).await;
  
  let req = test::TestRequest::get()
    .insert_header((
      "authorization",
      String::from("Bearer ") + &biscuit_token
    ))
    .uri("/hello")
    .to_request();
  
  test::call_service(&app, req).await;

  Ok(())
}