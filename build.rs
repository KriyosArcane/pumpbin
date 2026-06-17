fn main() {
    // Regenerate plugin_capnp.rs from plugin.capnp on every build, debug or
    // release. The previous `#[cfg(debug_assertions)]` gate meant a release-
    // only build of a fresh checkout failed with "couldn't read
    // src/../capnp/plugin_capnp.rs" if the checked-in generated file was
    // missing: surfaced when bundling source for a Darwin test on 2026-05-28.
    println!("cargo:rerun-if-changed=capnp/plugin.capnp");
    capnpc::CompilerCommand::new()
        .src_prefix("capnp")
        .file("capnp/plugin.capnp")
        .output_path("capnp")
        .run()
        .expect("schema compiler command");

    // Re-run when module directories change (new modules added/removed).
    for dir in &[
        "src/modules/encrypt",
        "src/modules/post_build",
        "src/modules/external",
    ] {
        println!("cargo:rerun-if-changed={}", dir);
    }

    #[cfg(target_os = "windows")]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("logo/icon.ico");
        res.compile().unwrap();
    }

    #[cfg(target_os = "macos")]
    {
        use std::fs;

        let version = env!("CARGO_PKG_VERSION");
        fs::write("VERSION", version).unwrap();
    }
}
