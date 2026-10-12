fn main() {
    println!("cargo:rerun-if-changed=assets/dns-shunt.ico");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut resource = winres::WindowsResource::new();
        resource.set_icon("assets/dns-shunt.ico");
        resource
            .compile()
            .expect("failed to embed Windows application icon");
    }
}
