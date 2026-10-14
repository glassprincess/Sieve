//! Иконка в exe через системный rc.exe. Без rc.exe билд идёт без иконки.

fn main() {
    println!("cargo:rerun-if-changed=assets/sieve.rc");
    println!("cargo:rerun-if-changed=assets/icon.ico");

    #[cfg(windows)]
    {
        let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
        let out = std::env::var("OUT_DIR").unwrap_or_else(|_| ".".into());
        let rc_file = format!("{}/assets/sieve.rc", manifest);
        let res_file = format!("{}/sieve.res", out);

        match find_rc_exe() {
            Some(rc_exe) => {
                let ok = std::process::Command::new(&rc_exe)
                    .args(["/fo", &res_file, &rc_file])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if ok && std::path::Path::new(&res_file).exists() {
                    println!("cargo:rustc-link-arg-bins={}", res_file);
                } else {
                    println!("cargo:warning=sieve: rc.exe failed, exe icon skipped");
                }
            }
            None => println!("cargo:warning=sieve: rc.exe not found, exe icon skipped"),
        }
    }
}

#[cfg(windows)]
fn find_rc_exe() -> Option<String> {
    if let (Ok(dir), Ok(ver)) =
        (std::env::var("WindowsSdkDir"), std::env::var("WindowsSDKVersion"))
    {
        let c = format!(
            "{}\\bin\\{}\\x64\\rc.exe",
            dir.trim_end_matches(['/', '\\']),
            ver.trim_end_matches(['/', '\\'])
        );
        if std::path::Path::new(&c).is_file() {
            return Some(c);
        }
    }
    if let Ok(entries) = std::fs::read_dir("C:\\Program Files (x86)\\Windows Kits\\10\\bin") {
        let mut vers: Vec<String> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("10."))
            .collect();
        vers.sort();
        for v in vers.iter().rev() {
            let c = format!(
                "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\{}\\x64\\rc.exe",
                v
            );
            if std::path::Path::new(&c).is_file() {
                return Some(c);
            }
        }
    }
    Some("rc.exe".to_string())
}
