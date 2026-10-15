use chrono::Datelike;

fn main() {
    println!("cargo:rerun-if-changed=assets/dns-shunt.ico");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let (version, version_info) = windows_version(env!("CARGO_PKG_VERSION"));
        let description = env!("CARGO_PKG_DESCRIPTION");
        let manifest_path = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap())
            .join("dns-shunt.manifest");
        std::fs::write(
            &manifest_path,
            manifest(env!("CARGO_PKG_NAME"), &version, description),
        )
        .expect("failed to write Windows application manifest");

        let mut resource = winres::WindowsResource::new();
        resource.set_icon("assets/dns-shunt.ico");
        resource.set("ProductName", "DNS Shunt");
        resource.set("FileDescription", description);
        resource.set("FileVersion", &version);
        resource.set_version_info(winres::VersionInfo::FILEVERSION, version_info);
        resource.set("ProductVersion", &version);
        resource.set_version_info(winres::VersionInfo::PRODUCTVERSION, version_info);
        resource.set("InternalName", &format!("{}.exe", env!("CARGO_PKG_NAME")));
        resource.set(
            "LegalCopyright",
            &format!("Joni Kollani © {}", chrono::Local::now().year()),
        );
        resource.set_manifest_file(&manifest_path.to_string_lossy());
        resource
            .compile()
            .expect("failed to embed Windows application resources");
    }
}

fn windows_version(version: &str) -> (String, u64) {
    let core = version.split(['-', '+']).next().unwrap_or_default();
    let components: Vec<u16> = core
        .split('.')
        .map(|component| {
            component.parse().unwrap_or_else(|_| {
                panic!("invalid package version for Windows resources: {version}")
            })
        })
        .collect();
    if components.len() != 3 {
        panic!("invalid package version for Windows resources: {version}");
    }

    let packed = ((components[0] as u64) << 48)
        | ((components[1] as u64) << 32)
        | ((components[2] as u64) << 16);
    (
        format!("{}.{}.{}.0", components[0], components[1], components[2]),
        packed,
    )
}

fn manifest(name: &str, version: &str, description: &str) -> String {
    let description = escape_xml(description);
    format!(
        r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1"
  manifestVersion="1.0">
  <assemblyIdentity version="{version}"
    processorArchitecture="*"
    name="github.sop.{name}"
    type="win32" />
  <description>{description}</description>
</assembly>
"#
    )
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
