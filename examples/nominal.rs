use actix_web::{App, web, Responder,
  HttpResponse, get, test};
use biscuit_auth::{Biscuit, KeyPair, 
  macros::{biscuit, authorizer}};
use biscuit_actix_middleware::BiscuitMiddleware;

#[get("/hello-admin")]
async fn hello_admin(token: web::ReqData<Biscuit>) -> impl Responder {
  // authorizer that allow only if role is admin
  let mut authorizer = authorizer!(
    r#"
      allow if role("admin");
    "#
  );

  // link authorizer and token
  if authorizer.add_token(&token).is_err() {
    return HttpResponse::InternalServerError().finish()
  }

  // check authorization
  if authorizer.authorize().is_err() {
    return HttpResponse::Forbidden().finish()
  }

  HttpResponse::Ok().body("Hello admin!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
  let root = KeyPair::new();
  let user_role = "admin";

  // instantiate a new biscuit
  let biscuit = biscuit!(
    r#"
      role({user_role});
    "#).build(&root)
    .unwrap();

  // serialize biscuit into a token
  let biscuit_token = biscuit
    .to_base64()
    .unwrap();

  println!("Biscuit token: {}", biscuit_token);

  // instantiate app using actix test tools
  let app = test::init_service(
    App::new()
      .wrap(BiscuitMiddleware{
        public_key: root.public()
      }).service(hello_admin)
  ).await;
  
  // test request with authorization header
  let req = test::TestRequest::get()
    .insert_header((
      "authorization",
      String::from("Bearer ") + &biscuit_token
    ))
    .uri("/hello-admin")
    .to_request();
  
  let response = test::call_service(&app, req).await;

  println!("Response status: {}", response.status());

  Ok(())
}