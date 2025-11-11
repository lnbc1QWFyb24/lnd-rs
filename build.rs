use std::{env, fs, path::PathBuf};
use walkdir::WalkDir;

fn main() {
    // Build only LND lnrpc lightning.proto (and includes) from the latest downloaded tag
    let protos_root = PathBuf::from("protos/lnd");

    // Deterministically select a tag directory, or use LND_TAG if provided.
    let tag = env::var("LND_TAG").ok().or_else(|| {
        // Collect immediate child directories and sort lexicographically; pick the last.
        let mut dirs: Vec<String> = WalkDir::new(&protos_root)
            .max_depth(1)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path() != protos_root && e.file_type().is_dir())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        dirs.sort();
        dirs.pop()
    });

    let Some(tag) = tag else {
        println!("cargo:warning=No LND tag found under protos/lnd. Skipping proto build.");
        return;
    };

    let proto_dir = protos_root.join(&tag);
    println!("cargo:rerun-if-env-changed=LND_TAG");
    println!("cargo:rerun-if-changed={}", proto_dir.display());

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::create_dir_all(&out_dir).unwrap();

    let serde_attr = "#[derive(serde::Serialize, serde::Deserialize)]";
    let builder = tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .out_dir(&out_dir)
        .type_attribute(".lnrpc", serde_attr)
        .compile_well_known_types(true)
        .extern_path(".google.protobuf", "::prost_types");

    let proto_file = proto_dir.join("lightning.proto");
    if !proto_file.exists() {
        println!(
            "cargo:warning=Expected {} but it was not found. Skipping proto build.",
            proto_file.display()
        );
        return;
    }

    let includes = [proto_dir.clone()];

    match builder.compile_protos(&[proto_file], &includes) {
        Ok(()) => {}
        Err(e) => {
            println!("cargo:warning=proto compile failed: {e}");
        }
    }
}
