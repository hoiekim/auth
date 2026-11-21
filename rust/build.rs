// Lists the migrations in ../src/migrations, the one copy both servers
// apply, so that adding a file there is all it takes for this one too.

use std::{env, fs, path::Path};

fn main() {
    let dir = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("../src/migrations");
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut names: Vec<String> = fs::read_dir(&dir)
        .expect("src/migrations")
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|f| is_migration(f))
        .collect();
    names.sort();
    let mut out = String::from("pub const MIGRATIONS: &[(&str, &str)] = &[\n");
    for name in names {
        let path = dir.join(&name).canonicalize().unwrap();
        println!("cargo:rerun-if-changed={}", path.display());
        out.push_str(&format!("    ({:?}, include_str!({:?})),\n", name.trim_end_matches(".sql"), path.display().to_string()));
    }
    out.push_str("];\n");
    fs::write(Path::new(&env::var("OUT_DIR").unwrap()).join("migrations.rs"), out).unwrap();
}

// ^\d{4}_[a-z0-9_]+\.sql$
fn is_migration(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".sql") else { return false };
    let b = stem.as_bytes();
    b.len() > 5
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'_'
        && b[5..].iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}
