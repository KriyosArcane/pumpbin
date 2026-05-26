use std::{fs, iter};

fn main() {
    let mut shellcode = "$$SHELLCODE$$".as_bytes().to_vec();
    shellcode.extend(iter::repeat_n(b'0', 1024 * 1024));
    fs::write("shellcode", shellcode.as_slice()).unwrap();
}
