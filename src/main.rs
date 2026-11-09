use std::error::Error;
use std::ffi::c_void;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, FreeLibrary,

};

use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows_sys::Win32::System::SystemInformation::{
    IMAGE_FILE_MACHINE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_UNKNOWN,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, GetCurrentProcess, GetExitCodeThread, IsWow64Process2, OpenProcess,
    WaitForSingleObject, LPTHREAD_START_ROUTINE, PROCESS_ALL_ACCESS, PROCESS_CREATE_THREAD,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

fn wide_to_string(buffer: &[u16]) -> String {
    let len = buffer
        .iter()
        .position(|&ch| ch == 0)
        .unwrap_or(buffer.len());

    String::from_utf16_lossy(&buffer[..len])
}

fn find_process_by_name(name: &str) -> io::Result<Option<u32>> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }

        let mut entry: PROCESSENTRY32W = zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        let mut result = None;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let process_name = wide_to_string(&entry.szExeFile);

                if process_name.eq_ignore_ascii_case(name) {
                    result = Some(entry.th32ProcessID);
                    break;
                }

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
        Ok(result)
    }
}

fn pe_machine(path: &Path) -> io::Result<IMAGE_FILE_MACHINE> {
    let mut file = File::open(path)?;
    let mut dos_header = [0u8; 64];
    file.read_exact(&mut dos_header)?;

    if &dos_header[..2] != b"MZ" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Not a PE file: {}", path.display()),
        ));
    }

    let pe_offset = u32::from_le_bytes(dos_header[0x3c..0x40].try_into().unwrap()) as u64;
    file.seek(SeekFrom::Start(pe_offset))?;

    let mut pe_header = [0u8; 6];
    file.read_exact(&mut pe_header)?;
    if &pe_header[..4] != b"PE\0\0" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid PE header: {}", path.display()),
        ));
    }

    Ok(u16::from_le_bytes([pe_header[4], pe_header[5]]))
}

fn process_machine(process: HANDLE) -> io::Result<IMAGE_FILE_MACHINE> {
    let mut process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    let mut native_machine = IMAGE_FILE_MACHINE_UNKNOWN;

    if unsafe { IsWow64Process2(process, &mut process_machine, &mut native_machine) } == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(if process_machine == IMAGE_FILE_MACHINE_UNKNOWN {
        native_machine
    } else {
        process_machine
    })
}

fn machine_name(machine: IMAGE_FILE_MACHINE) -> &'static str {
    match machine {
        IMAGE_FILE_MACHINE_I386 => "x86",
        IMAGE_FILE_MACHINE_AMD64 => "x64",
        IMAGE_FILE_MACHINE_ARM64 => "ARM64",
        _ => "unknown",
    }
}

fn normalize_windows_path(path: &str) -> &str {
    path.strip_prefix(r"\\?\").unwrap_or(path)
}

fn is_module_loaded(pid: u32, dll_path: &Path) -> io::Result<bool> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }

        let mut entry: MODULEENTRY32W = zeroed();
        entry.dwSize = size_of::<MODULEENTRY32W>() as u32;
        let expected_path = dll_path.to_string_lossy();
        let mut found = false;

        if Module32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let module_path = wide_to_string(&entry.szExePath);
                if normalize_windows_path(&module_path)
                    .eq_ignore_ascii_case(normalize_windows_path(&expected_path))
                {
                    found = true;
                    break;
                }

                if Module32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
        Ok(found)
    }
}

fn inject_sensor_into_target(process_name: &str, dll_path: &str) -> Result<(), Box<dyn Error>> {
    println!(
        "[INJECT_DIAG][01] Start: target={process_name}, payload={dll_path}"
    );
    println!("[INJECT_DIAG][02] Searching for target process");
    let pid = find_process_by_name(process_name)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("Process not found: {process_name}"),
        )
    })?;
    println!("[INJECT_DIAG][02] Target found: pid={pid}");

    println!("[INJECT_DIAG][03] Resolving payload path");
    let dll_path = Path::new(dll_path).canonicalize()?;
    if !dll_path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("DLL path is not a file: {}", dll_path.display()),
        )
        .into());
    }
    let dll_machine = pe_machine(&dll_path)?;
    println!(
        "[INJECT_DIAG][03] Payload ready: path={}, architecture={}",
        dll_path.display(),
        machine_name(dll_machine)
    );

    let dll_path_wide: Vec<u16> = dll_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let dll_path_size = dll_path_wide.len() * size_of::<u16>();
    println!(
        "[INJECT_DIAG][04] Payload path encoded: utf16_bytes={dll_path_size}"
    );

    unsafe {
        println!("[INJECT_DIAG][05] Calling OpenProcess: pid={pid}");
        let process = OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE
                | PROCESS_ALL_ACCESS,
            0,
            pid,
        );
        if process.is_null() {
            let error = io::Error::last_os_error();
            eprintln!("[INJECT_DIAG][05] OpenProcess failed: {error}");
            return Err(error.into());
        }
        println!("[INJECT_DIAG][05] OpenProcess succeeded: handle={process:p}");

        println!("[INJECT_DIAG][06] Checking process architectures");
        let injector_machine = process_machine(GetCurrentProcess());
        let target_machine = process_machine(process);
        let (injector_machine, target_machine) = match (injector_machine, target_machine) {
            (Ok(injector_machine), Ok(target_machine)) => (injector_machine, target_machine),
            (Err(error), _) | (_, Err(error)) => {
                CloseHandle(process);
                return Err(error.into());
            }
        };
        println!(
            "[INJECT_DIAG][06] Architecture: injector={}, target={}, payload={}",
            machine_name(injector_machine),
            machine_name(target_machine),
            machine_name(dll_machine)
        );

        if injector_machine != target_machine {
            CloseHandle(process);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Architecture mismatch: injector is {}, target is {}. Build the injector for the target architecture",
                    machine_name(injector_machine),
                    machine_name(target_machine),
                ),
            )
            .into());
        }

        if dll_machine != target_machine {
            CloseHandle(process);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Architecture mismatch: DLL is {}, target is {}",
                    machine_name(dll_machine),
                    machine_name(target_machine),
                ),
            )
            .into());
        }

        println!(
            "[INJECT_DIAG][07] Calling VirtualAllocEx: bytes={dll_path_size}"
        );
        let remote_path = VirtualAllocEx(
            process,
            null(),
            dll_path_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_path.is_null() {
            let error = io::Error::last_os_error();
            eprintln!("[INJECT_DIAG][07] VirtualAllocEx failed: {error}");
            CloseHandle(process);
            return Err(error.into());
        }
        println!(
            "[INJECT_DIAG][07] VirtualAllocEx succeeded: remote_address={remote_path:p}"
        );

        let result = (|| -> Result<(), Box<dyn Error>> {
            let mut bytes_written = 0;
            println!(
                "[INJECT_DIAG][08] Calling WriteProcessMemory: address={remote_path:p}, bytes={dll_path_size}"
            );
            if WriteProcessMemory(
                process,
                remote_path,
                dll_path_wide.as_ptr().cast::<c_void>(),
                dll_path_size,
                &mut bytes_written,
            ) == 0
            {
                let error = io::Error::last_os_error();
                eprintln!("[INJECT_DIAG][08] WriteProcessMemory failed: {error}");
                return Err(error.into());
            }
            println!(
                "[INJECT_DIAG][08] WriteProcessMemory succeeded: written={bytes_written}/{dll_path_size}"
            );
            if bytes_written != dll_path_size {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!("WriteProcessMemory wrote {bytes_written} of {dll_path_size} bytes"),
                )
                .into());
            }

            let kernel32_wide: Vec<u16> = "kernel32.dll"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            println!("[INJECT_DIAG][09] Resolving kernel32!LoadLibraryW");
            let kernel32 = GetModuleHandleW(kernel32_wide.as_ptr());
            if kernel32.is_null() {
                let error = io::Error::last_os_error();
                eprintln!("[INJECT_DIAG][09] GetModuleHandleW failed: {error}");
                return Err(error.into());
            }

            let load_library_w = GetProcAddress(kernel32, c"LoadLibraryW".as_ptr().cast());
            let Some(load_library_w) = load_library_w else {
                let error = io::Error::last_os_error();
                eprintln!("[INJECT_DIAG][09] GetProcAddress(LoadLibraryW) failed: {error}");
                return Err(error.into());
            };
            println!(
                "[INJECT_DIAG][09] LoadLibraryW resolved: kernel32={kernel32:p}, address={:p}",
                load_library_w as *const ()
            );
            let thread_start: LPTHREAD_START_ROUTINE = Some(std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                unsafe extern "system" fn(*mut c_void) -> u32,
            >(load_library_w));

            println!(
                "[INJECT_DIAG][10] Calling CreateRemoteThread: parameter={remote_path:p}"
            );
            let thread =
                CreateRemoteThread(process, null(), 0, thread_start, remote_path, 0, null_mut());
            if thread.is_null() {
                let error = io::Error::last_os_error();
                eprintln!("[INJECT_DIAG][10] CreateRemoteThread failed: {error}");
                return Err(error.into());
            }
            println!(
                "[INJECT_DIAG][10] CreateRemoteThread succeeded: handle={thread:p}"
            );

            println!("[INJECT_DIAG][11] Waiting for remote thread");
            let wait_result = WaitForSingleObject(thread, u32::MAX);
            println!(
                "[INJECT_DIAG][11] WaitForSingleObject result=0x{wait_result:08X}"
            );
            let result = if wait_result == WAIT_OBJECT_0 {
                let mut exit_code = 0;
                if GetExitCodeThread(thread, &mut exit_code) == 0 {
                    let error = io::Error::last_os_error();
                    eprintln!("[INJECT_DIAG][12] GetExitCodeThread failed: {error}");
                    Err(error.into())
                } else {
                    println!(
                        "[INJECT_DIAG][12] Remote LoadLibraryW exit_code=0x{exit_code:08X}"
                    );

                    if exit_code != 0 {
                        println!(
                            "[INJECT_DIAG][13] Injection confirmed by non-zero LoadLibraryW result"
                        );
                        Ok(())
                    } else {
                        println!(
                            "[INJECT_DIAG][13] LoadLibraryW returned zero; checking target module list"
                        );
                        let loaded = is_module_loaded(pid, &dll_path)?;
                        println!(
                            "[INJECT_DIAG][13] Module-list verification: loaded={loaded}"
                        );

                        if loaded {
                            Ok(())
                        } else {
                            Err(io::Error::other(format!(
                                "LoadLibraryW returned NULL in the target process ({}). The DLL architecture matches; check missing DLL dependencies or a DLL_PROCESS_ATTACH failure in DllMain",
                                machine_name(target_machine),
                            ))
                            .into())
                        }
                    }
                }
            } else if wait_result == WAIT_FAILED {
                let error = io::Error::last_os_error();
                eprintln!("[INJECT_DIAG][11] WaitForSingleObject failed: {error}");
                Err(error.into())
            } else {
                eprintln!(
                    "[INJECT_DIAG][11] Unexpected wait result: 0x{wait_result:08X}"
                );
                Err(io::Error::other(format!(
                    "Unexpected WaitForSingleObject result: {wait_result}"
                ))
                .into())
            };

            CloseHandle(thread);
            result
        })();

        println!("[INJECT_DIAG][14] Releasing remote buffer and process handle");
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);

        if result.is_ok() {
            println!("[INJECT_DIAG][15] Injection flow completed successfully");
        } else {
            eprintln!("[INJECT_DIAG][15] Injection flow completed with an error");
        }

        result
    }
}

fn main() -> io::Result<()> {
    // std::thread::sleep(Duration::from_secs(1000));

    // if let Err(e) = load_dll(r"E:\inject-fix-1-2\x64\Release\hook.dll"){
    //     println!("load failed {:#?}", e);
    // };

    match inject_sensor_into_target(
        "Notepad.exe",
        r"C:\Windows\Temp\test_dll.dll",
    ) {
        Ok(()) => println!("[+] DLL injected successfully"),
        Err(e) => eprintln!("[-] Injection failed: {e}"),
    }
    std::thread::sleep(Duration::from_mins(30));
    Ok(())
}


use std::{
    ffi::OsStr,
};

use windows_sys::Win32::System::LibraryLoader::{
    LoadLibraryW,
};

pub fn load_dll(path: &str) -> io::Result<()> {
    // Convert path -> UTF-16
    let wide_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        // Load DLL vao process hien tai
        let module = LoadLibraryW(wide_path.as_ptr());

        if module.is_null() {
            return Err(io::Error::last_os_error());
        }

        println!("[+] DLL loaded successfully");
        println!("[+] Module handle: {:?}", module);

        // // Giu DLL duoc load cho den khi nhan Enter
        // println!("Press Enter to unload DLL...");
        // let mut input = String::new();
        // io::stdin().read_line(&mut input)?;

        // // Unload DLL
        // if FreeLibrary(module) == 0 {
        //     return Err(io::Error::last_os_error());
        // }

        // println!("[+] DLL unloaded");
    }

    Ok(())
}
