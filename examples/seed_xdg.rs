//! QA helper: pre-seed an XDG plugin registry with a single .b1n so the GUI
//! starts with the plugin already loaded. Avoids the GTK file-dialog
//! ydotool-keystroke fragility on Hyprland.
//!
//! Usage: cargo run --release --example seed_xdg -- <path-to.b1n> <xdg-target>
//! where xdg-target is typically $XDG_DATA_HOME/PumpBin/plugins

use bincode::config;
use pumpbin::plugin::{Plugin, Plugins};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: seed_xdg <path-to.b1n> <xdg-target-plugins-file>");
        std::process::exit(2);
    }
    let buf = std::fs::read(&args[1]).expect("read .b1n");
    let plugin = Plugin::decode_from_slice(&buf).expect("decode .b1n");
    let mut plugins = Plugins::default();
    plugins.insert(plugin.info().plugin_name().to_string(), buf);
    let encoded = bincode::encode_to_vec(&plugins, config::standard()).expect("encode");
    if let Some(parent) = std::path::Path::new(&args[2]).parent() {
        std::fs::create_dir_all(parent).expect("create_dir_all");
    }
    std::fs::write(&args[2], encoded).expect("write registry");
    println!(
        "Seeded {} with plugin {:?}",
        args[2],
        plugin.info().plugin_name()
    );
}
