use std::path::PathBuf;
use actix_files::{NamedFile, Files};
use actix_web::{get, middleware::{self, Logger}, App, Error, HttpServer};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use env_logger::Env;

#[get("/")]
async fn index() -> Result<NamedFile, Error> {
    let path: PathBuf = PathBuf::from("static/index.html");
    let file = actix_files::NamedFile::open(path)?;
    Ok(file.use_last_modified(true))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    
    env_logger::init_from_env(Env::default().default_filter_or("info"));
    
    builder.set_private_key_file("private.key.pem", SslFiletype::PEM).unwrap();
    builder.set_certificate_chain_file("domain.cert.pem").unwrap();

    HttpServer::new(|| {
        App::new()
            .service(index)
            .service(Files::new("/entries", "entries"))
            .service(Files::new("/", "static"))
            .wrap(middleware::DefaultHeaders::new().add(("X-Version", "0.2")))
            .wrap(Logger::default())
            .wrap(Logger::new("%a %{User-Agent}i"))
    }).bind_openssl("0.0.0.0:443", builder)?
    .run()
    .await
}
