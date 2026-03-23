pub mod plugin;
mod plugin_system;
pub mod style;
pub mod utils;
pub mod plugin_capnp {
    include!("../capnp/plugin_capnp.rs");
}

use std::{fmt::Display, fs, ops::Not, path::PathBuf};

use anyhow::anyhow;
use dirs::{desktop_dir, home_dir};
use open;
use chrono::Local;
use iced::{
    alignment::{Horizontal, Vertical},
    futures::TryFutureExt,
    keyboard,
    event,
    widget::{
        button, column, container, horizontal_rule, pick_list, row,
        svg::{self, Handle},
        text, text_editor, text_input, vertical_rule, Column, Scrollable, Svg,
    },
    Background, Length, Task, Theme, Subscription, Event, Border,
};
use plugin::{Plugin, Plugins};
use plugin_system::Pass;
use rfd::{AsyncFileDialog, MessageLevel, MessageDialogResult};
use utils::{message_dialog, confirm_dialog, JETBRAINS_MONO_FONT};

#[derive(Debug, Clone)]
pub enum Message {
    ShellcodeSrcChanged(String),
    ChooseShellcodeClicked,
    ChooseShellcodeDone(Option<PathBuf>),
    EncryptShellcode(Option<PathBuf>),
    EncryptShellcodeDone(Result<(Vec<Pass>, String), String>),
    PlatformChanged(Platform),
    GenerateClicked,
    GenerateDone(Result<(), String>),
    BinaryTypeChanged(BinaryType),
    AddPluginClicked,
    AddPluginDone(Result<(u32, u32, Plugins), String>),
    ConfirmRemovePlugin(String),
    ConfirmRemovePluginResult(MessageDialogResult),
    RemovePlugin(String),
    RemovePluginDone(Result<Plugins, String>),
    PluginItemClicked(String),
    EditorAction(text_editor::Action),
    B1nClicked,
    GithubClicked,
    ThemeChanged(Theme),
    ClearShellcodeSource,
    OpenRecentFile(PathBuf),
    ShowAbout,
    KeyboardShortcut(KeyboardShortcut),
    // Drag & Drop Support
    FilesDropped(Vec<PathBuf>),
}

#[derive(Debug, Clone)]
pub enum KeyboardShortcut {
    AddPlugin,
    Generate,
    ChooseShellcode,
    ClearSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryType {
    Executable,
    DynamicLibrary,
}

impl Display for BinaryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Executable => write!(f, "Exe"),
            Self::DynamicLibrary => write!(f, "Lib"),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ShellcodeSaveType {
    #[default]
    Local,
    Remote,
}

impl Display for ShellcodeSaveType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShellcodeSaveType::Local => write!(f, "Local"),
            ShellcodeSaveType::Remote => write!(f, "Remote"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Linux,
    Darwin,
}

impl Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::Windows => write!(f, "Windows"),
            Platform::Linux => write!(f, "Linux"),
            Platform::Darwin => write!(f, "Darwin"),
        }
    }
}

#[derive(Debug)]
pub struct Pumpbin {
    shellcode_src: String,
    shellcode_save_type: ShellcodeSaveType,
    supported_binary_types: Vec<BinaryType>,
    selected_binary_type: Option<BinaryType>,
    supported_platforms: Vec<Platform>,
    selected_platform: Option<Platform>,
    plugins: Plugins,
    selected_plugin: Option<Plugin>,
    plugin_desc: text_editor::Content,
    pass: Vec<Pass>,
    selected_theme: Theme,
    recent_files: Vec<PathBuf>,
    is_loading: bool,
    loading_message: String,
    pending_remove_plugin: Option<String>,
}

impl Default for Pumpbin {
    fn default() -> Self {
        Self {
            shellcode_src: Default::default(),
            shellcode_save_type: Default::default(),
            supported_binary_types: Default::default(),
            selected_binary_type: Default::default(),
            supported_platforms: Default::default(),
            selected_platform: Default::default(),
            plugins: Plugins::reade_plugins().unwrap_or_default(),
            selected_plugin: Default::default(),
            plugin_desc: Default::default(),
            pass: Default::default(),
            selected_theme: Theme::CatppuccinMacchiato,
            recent_files: Vec::new(),
            is_loading: false,
            loading_message: String::new(),
            pending_remove_plugin: None,
        }
    }
}

impl Pumpbin {
    fn update_supported_binary_types(&mut self, platform: Platform) {
        let bins = self.selected_plugin().unwrap().bins();
        let bin_types = match platform {
            Platform::Windows => bins.windows(),
            Platform::Linux => bins.linux(),
            Platform::Darwin => bins.darwin(),
        }
        .supported_binary_types();

        self.selected_binary_type = None;
        self.supported_binary_types = bin_types;
    }

    fn update_supported_platforms(&mut self, plugin: &Plugin) {
        let platforms = plugin.bins().supported_plaforms();

        self.supported_binary_types = Default::default();
        self.selected_binary_type = Default::default();
        self.supported_platforms = platforms;
        self.selected_platform = Default::default();
    }
}

impl Pumpbin {
    pub fn shellcode_src(&self) -> &str {
        &self.shellcode_src
    }

    pub fn shellcode_save_type(&self) -> ShellcodeSaveType {
        self.shellcode_save_type
    }

    pub fn supported_binary_types(&self) -> &[BinaryType] {
        &self.supported_binary_types
    }

    pub fn selected_binary_type(&self) -> Option<BinaryType> {
        self.selected_binary_type
    }

    pub fn supported_platforms(&self) -> &[Platform] {
        &self.supported_platforms
    }

    pub fn selected_platform(&self) -> Option<Platform> {
        self.selected_platform
    }

    pub fn plugins(&self) -> &Plugins {
        &self.plugins
    }

    pub fn selected_plugin(&self) -> Option<&Plugin> {
        self.selected_plugin.as_ref()
    }

    pub fn plugin_desc(&self) -> &text_editor::Content {
        &self.plugin_desc
    }

    pub fn pass(&self) -> &[Pass] {
        &self.pass
    }

    pub fn selected_theme(&self) -> Theme {
        self.selected_theme.clone()
    }

    pub fn recent_files(&self) -> &[PathBuf] {
        &self.recent_files
    }

    pub fn is_loading(&self) -> bool {
        self.is_loading
    }

    pub fn loading_message(&self) -> &str {
        &self.loading_message
    }

    // Helper methods for new QoL features
    fn add_recent_file(&mut self, path: PathBuf) {
        // Remove if already exists to avoid duplicates
        self.recent_files.retain(|p| p != &path);
        
        // Add to front
        self.recent_files.insert(0, path);
        
        // Keep only last 5 files
        self.recent_files.truncate(5);
    }

    fn set_loading(&mut self, loading: bool, message: String) {
        self.is_loading = loading;
        self.loading_message = message;
    }

    fn clear_source(&mut self) {
        self.shellcode_src = String::new();
        self.pass = Vec::new();
    }
}

impl Pumpbin {
    pub fn update(&mut self, message: Message) -> iced::Task<Message> {
        match message {
            Message::ShellcodeSrcChanged(x) => self.shellcode_src = x,
            Message::ChooseShellcodeClicked => {
                let choose_shellcode = async {
                    AsyncFileDialog::new()
                        .set_directory(home_dir().unwrap_or(".".into()))
                        .set_title("Select shellcode file")
                        .pick_file()
                        .await
                        .map(|x| x.path().to_path_buf())
                };

                return Task::perform(
                    choose_shellcode,
                    match self.shellcode_save_type() {
                        ShellcodeSaveType::Local => Message::ChooseShellcodeDone,
                        ShellcodeSaveType::Remote => Message::EncryptShellcode,
                    },
                );
            }
            Message::ChooseShellcodeDone(x) => {
                if let Some(path) = x {
                    self.shellcode_src = path.to_string_lossy().to_string();
                    self.add_recent_file(path);
                }
            }
            Message::PlatformChanged(x) => {
                // do nothing if selected this platform
                if let Some(selected_platform) = self.selected_platform {
                    if x == selected_platform {
                        return Task::none();
                    }
                }

                self.selected_platform = Some(x);
                self.update_supported_binary_types(x);
            }
            Message::EncryptShellcode(x) => {
                let Some(path) = x else {
                    return Task::none();
                };

                let plugin = self.selected_plugin().unwrap().to_owned();
                let write_encrypted = async move {
                    let output = plugin.plugins().run_encrypt_shellcode(&path)?;
                    let final_shellcode = plugin
                        .plugins()
                        .run_format_encrypted_shellcode(output.encrypted())?;
                    let url = plugin
                        .plugins()
                        .run_upload_final_shellcode_remote(final_shellcode.formated_shellcode())?
                        .url()
                        .to_string();

                    if url.is_empty() {
                        let file = AsyncFileDialog::new()
                            .set_directory(desktop_dir().unwrap_or(".".into()))
                            .set_file_name("shellcode.enc")
                            .set_title("Save encrypted shellcode")
                            .save_file()
                            .await
                            .ok_or(anyhow!("Canceled the saving of encrypted shellcode."))?;

                        fs::write(file.path(), final_shellcode.formated_shellcode())
                            .map_err(anyhow::Error::from)?;
                    }

                    anyhow::Ok((output.pass().to_vec(), url))
                }
                .map_err(|e| e.to_string());

                return Task::perform(write_encrypted, Message::EncryptShellcodeDone);
            }
            Message::EncryptShellcodeDone(x) => {
                match x {
                    Ok((pass, url)) => {
                        self.pass = pass;
                        if url.is_empty().not() {
                            self.shellcode_src = url;
                        }
                        message_dialog("Encrypted shellcode done.".into(), MessageLevel::Info)
                    }
                    Err(e) => message_dialog(e, MessageLevel::Error),
                };
            }
            Message::GenerateClicked => {
                self.set_loading(true, "Generating implant...".to_string());
                // unwrap is safe.
                // UI implemented strict restrictions.
                let plugin = self.selected_plugin().unwrap().to_owned();
                let shellcode_src = self.shellcode_src().to_owned();
                let pass = self.pass().to_vec();
                let platform = self.selected_platform().unwrap();
                let binary_type = self.selected_binary_type().unwrap();

                // get that binary
                let mut bin = plugin.bins().get_that_binary(
                    platform,
                    binary_type,
                );

                let generate = async move {
                    // Improved error handling for shellcode file
                    let save_type = if plugin.replace().size_holder().is_some() {
                        ShellcodeSaveType::Local
                    } else {
                        ShellcodeSaveType::Remote
                    };
                    if save_type == ShellcodeSaveType::Local {
                        let path = std::path::Path::new(&shellcode_src);
                        if !path.exists() {
                            return Err(anyhow!("Shellcode file not found: {}", shellcode_src));
                        }
                        let data = std::fs::read(path)
                            .map_err(|e| anyhow!("Failed to read shellcode file: {}: {}", shellcode_src, e))?;
                        if data.is_empty() {
                            return Err(anyhow!("Shellcode file is empty: {}", shellcode_src));
                        }
                        if data.windows(b"$$SHELLCODE$$".len()).any(|w| w == b"$$SHELLCODE$$") {
                            return Err(anyhow!("Shellcode file contains placeholder: {}", shellcode_src));
                        }
                    }
                    plugin.replace_binary(&mut bin, shellcode_src, pass)?;

                    // Determine the appropriate file extension based on platform and binary type
                    let (filename, file_description) = match (platform, binary_type) {
                        (Platform::Windows, BinaryType::Executable) => ("binary.exe", "Windows executable"),
                        (Platform::Windows, BinaryType::DynamicLibrary) => ("binary.dll", "Windows library"),
                        (Platform::Linux, BinaryType::Executable) => ("binary", "Linux executable"),
                        (Platform::Linux, BinaryType::DynamicLibrary) => ("binary.so", "Linux library"),
                        (Platform::Darwin, BinaryType::Executable) => ("binary", "macOS executable"),
                        (Platform::Darwin, BinaryType::DynamicLibrary) => ("binary.dylib", "macOS library"),
                    };

                    // write generated binary
                    let now = Local::now();
                    let timestamp = now.format("%Y%m%d_%H%M%S").to_string();
                    let plugin_name_sanitized = plugin.info().plugin_name().to_lowercase().replace(' ', "_");
                    let platform_str = platform.to_string().to_lowercase();
                    let bin_type_str = match binary_type {
                        BinaryType::Executable => "exe",
                        BinaryType::DynamicLibrary => "dll"
                    };
                                        let default_name = format!("{}_{}_{}_{}.{}", plugin_name_sanitized, platform_str, bin_type_str, timestamp, match (platform, binary_type) {
                        (Platform::Windows, BinaryType::Executable) => "exe",
                        (Platform::Windows, BinaryType::DynamicLibrary) => "dll",
                        (Platform::Linux, BinaryType::Executable) => "elf",
                        (Platform::Linux, BinaryType::DynamicLibrary) => "so",
                        (Platform::Darwin, BinaryType::Executable) => "macho",
                        (Platform::Darwin, BinaryType::DynamicLibrary) => "dylib",
                    });

                    let file = AsyncFileDialog::new()
                        .set_directory(desktop_dir().unwrap_or(".".into()))
                        .set_file_name(&default_name)
                        .set_can_create_directories(true)
                        .set_title(&format!("Save generated {}", file_description))
                        .save_file()
                        .await
                        .ok_or(anyhow!("Canceled the saving of the generated binary."))?;

                    fs::write(file.path(), bin).map_err(anyhow::Error::from)?;

                    Ok(())
                }
                .map_err(|e: anyhow::Error| e.to_string());

                return Task::perform(generate, Message::GenerateDone);
            }
            Message::GenerateDone(x) => {
                self.set_loading(false, String::new());
                match x {
                    Ok(_) => {
                        message_dialog("Generate done.".into(), MessageLevel::Info);
                    },
                    Err(e) => {
                        message_dialog(e, MessageLevel::Error);
                    },
                };
            }
            Message::BinaryTypeChanged(x) => self.selected_binary_type = Some(x),
            Message::AddPluginClicked => {
                self.set_loading(true, "Adding plugins...".to_string());
                let mut plugins = self.plugins().clone();

                let add_plugins = async move {
                    let files = AsyncFileDialog::new()
                        .add_filter("b1n", &["b1n"])
                        .set_directory(home_dir().unwrap_or(".".into()))
                        .set_title("Select plugin files")
                        .pick_files()
                        .await
                        .ok_or(anyhow!("Canceled the selection of plugin files."))?;

                    let mut success = 0;
                    let mut failed = 0;

                    for path in files.iter().map(|x| x.path()) {
                        let Ok(buf) = fs::read(path) else {
                            failed += 1;
                            continue;
                        };
                        if let Ok(plugin) = Plugin::decode_from_slice(buf.as_slice()) {
                            let plugin_name = plugin.info().plugin_name();

                            plugins.insert(plugin_name.to_string(), buf);
                            success += 1;
                        } else {
                            failed += 1;
                        }
                    }

                    plugins.uptade_plugins()?;
                    anyhow::Ok((success, failed, plugins))
                }
                .map_err(|e| e.to_string());

                return Task::perform(add_plugins, Message::AddPluginDone);
            }
            Message::AddPluginDone(x) => {
                self.set_loading(false, String::new());
                match x {
                    Ok((success, failed, plugins)) => {
                        // if selected_plugin, reselect this plugin
                        if let Some(selected_plugin) = self.selected_plugin() {
                            let plugin_name = selected_plugin.info().plugin_name().to_owned();

                            // bypass check
                            self.selected_plugin = None;
                            self.update(Message::PluginItemClicked(plugin_name));
                        }
                        self.plugins = plugins;
                        message_dialog(
                            format!("Added {} plugins, {} failed.", success, failed),
                            MessageLevel::Info,
                        );
                    }
                    Err(e) => {
                        message_dialog(e, MessageLevel::Error);
                    }
                }
            }
            Message::ConfirmRemovePlugin(x) => {
                self.pending_remove_plugin = Some(x.clone());
                let confirm_message = format!("Are you sure you want to remove the plugin '{}'?\n\nThis action cannot be undone.", x);
                let confirm_task = confirm_dialog(confirm_message, "Confirm Plugin Removal".to_string());
                
                return confirm_task.map(Message::ConfirmRemovePluginResult);
            }
            Message::ConfirmRemovePluginResult(result) => {
                if let Some(plugin_name) = self.pending_remove_plugin.take() {
                    match result {
                        MessageDialogResult::Yes => {
                            return self.update(Message::RemovePlugin(plugin_name));
                        }
                        _ => {
                            // User cancelled, do nothing
                        }
                    }
                }
            }
            Message::RemovePlugin(x) => {
                if x.is_empty() {
                    return Task::none(); // Handle no-op case
                }
                
                self.set_loading(true, "Removing plugin...".to_string());
                let mut plugins = self.plugins().clone();

                let remove_plugin = async move {
                    plugins.remove(&x);
                    plugins.uptade_plugins()?;

                    anyhow::Ok(plugins)
                }
                .map_err(|e| e.to_string());

                return Task::perform(remove_plugin, Message::RemovePluginDone);
            }
            Message::RemovePluginDone(x) => {
                self.set_loading(false, String::new());
                match x {
                    Ok(plugins) => {
                        self.plugins = plugins;

                        if let Some(name) = self.plugins().get_sorted_names().first() {
                            _ = self.update(Message::PluginItemClicked(name.to_owned()));
                        } else {
                            // Reset all state when no plugins remain
                            self.supported_binary_types = Default::default();
                            self.selected_binary_type = None;
                            self.supported_platforms = Default::default();
                            self.selected_platform = None;
                            self.selected_plugin = None;
                            self.shellcode_save_type = ShellcodeSaveType::Local;
                            self.shellcode_src = String::new();
                            self.plugin_desc = text_editor::Content::new();
                            self.pass = Vec::new();
                        }
                        
                        message_dialog("Plugin removed successfully.".to_string(), MessageLevel::Info);
                    }
                    Err(e) => {
                        message_dialog(format!("Failed to remove plugin: {}", e), MessageLevel::Error);
                    }
                };
            }
            Message::PluginItemClicked(x) => {
                // unwrap is safe.
                // UI implemented strict restrictions.
                let plugin = self.plugins().get(&x).unwrap();

                if let Some(selected_plugin) = self.selected_plugin() {
                    if plugin.info().plugin_name() == selected_plugin.info().plugin_name() {
                        return Task::none();
                    }
                }

                self.selected_plugin = Some(plugin.clone());
                self.plugin_desc = text_editor::Content::with_text(plugin.info().desc());

                if plugin.replace().size_holder().is_some() {
                    self.shellcode_save_type = ShellcodeSaveType::Local;
                } else {
                    self.shellcode_save_type = ShellcodeSaveType::Remote;
                }

                self.update_supported_platforms(&plugin);
            }
            Message::EditorAction(x) => match x {
                text_editor::Action::Edit(_) => (),
                _ => self.plugin_desc.perform(x),
            },
            Message::B1nClicked => {
                if open::that(env!("CARGO_PKG_HOMEPAGE")).is_err() {
                    message_dialog("Open home failed.".into(), MessageLevel::Error);
                }
            }
            Message::GithubClicked => {
                if open::that(env!("CARGO_PKG_REPOSITORY")).is_err() {
                    message_dialog("Open repo failed.".into(), MessageLevel::Error);
                }
            }
            Message::ThemeChanged(x) => self.selected_theme = x,
            Message::ClearShellcodeSource => {
                self.clear_source();
                message_dialog("Shellcode source cleared.".to_string(), MessageLevel::Info);
            }
            Message::OpenRecentFile(path) => {
                self.shellcode_src = path.to_string_lossy().to_string();
                self.add_recent_file(path);
            }
            Message::ShowAbout => {
                let about_text = format!(
                    "PumpBin v{}\n\nAn Implant Generation Platform\n\n• Powerful, simple, and comfortable UI\n• Support for Local and Remote plugins\n• Extism plugin system for extensibility\n• Unique encrypted implants with random keys\n\nHomepage: {}\nRepository: {}",
                    env!("CARGO_PKG_VERSION"),
                    env!("CARGO_PKG_HOMEPAGE"),
                    env!("CARGO_PKG_REPOSITORY")
                );
                message_dialog(about_text, MessageLevel::Info);
            }
            Message::KeyboardShortcut(shortcut) => {
                match shortcut {
                    KeyboardShortcut::AddPlugin => {
                        return self.update(Message::AddPluginClicked);
                    }
                    KeyboardShortcut::Generate => {
                        if self.selected_binary_type().is_some() && !self.shellcode_src().is_empty() {
                            return self.update(Message::GenerateClicked);
                        }
                    }
                    KeyboardShortcut::ChooseShellcode => {
                        return self.update(Message::ChooseShellcodeClicked);
                    }
                    KeyboardShortcut::ClearSource => {
                        return self.update(Message::ClearShellcodeSource);
                    }
                }
            }
            Message::FilesDropped(paths) => {
                // Handle drag & drop files
                let mut shellcode_files = Vec::new();
                let mut plugin_files = Vec::new();
                
                // Categorize dropped files
                for path in paths {
                    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
                    
                    match extension.to_lowercase().as_str() {
                        "b1n" => plugin_files.push(path),
                        _ => shellcode_files.push(path),
                    }
                }
                
                // Handle plugin files first
                if !plugin_files.is_empty() {
                    self.set_loading(true, "Adding dropped plugins...".to_string());
                    let mut plugins = self.plugins().clone();
                    
                    let add_dropped_plugins = async move {
                        let mut success = 0;
                        let mut failed = 0;
                        
                        for path in plugin_files {
                            match fs::read(&path) {
                                Ok(buf) => {
                                    if let Ok(plugin) = Plugin::decode_from_slice(&buf) {
                                        let plugin_name = plugin.info().plugin_name();
                                        plugins.insert(plugin_name.to_string(), buf);
                                        success += 1;
                                    } else {
                                        failed += 1;
                                    }
                                }
                                Err(_) => {
                                    failed += 1;
                                }
                            }
                        }
                        
                        plugins.uptade_plugins()?;
                        anyhow::Ok((success, failed, plugins))
                    }
                    .map_err(|e| e.to_string());
                    
                    return Task::perform(add_dropped_plugins, Message::AddPluginDone);
                }
                
                // Handle shellcode files
                if let Some(path) = shellcode_files.first() {
                    if self.shellcode_save_type() == ShellcodeSaveType::Local {
                        self.shellcode_src = path.to_string_lossy().to_string();
                        self.add_recent_file(path.clone());
                        message_dialog(
                            format!("Shellcode file loaded: {}", path.file_name().unwrap_or_default().to_string_lossy()),
                            MessageLevel::Info,
                        );
                    } else {
                        // For remote mode, process the file for encryption
                        return self.update(Message::EncryptShellcode(Some(path.clone())));
                    }
                }
            }
        }

        Task::none()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        event::listen_with(|event, _status, _window| match event {
            Event::Keyboard(keyboard::Event::KeyPressed {
                key: keyboard::Key::Character(c),
                modifiers,
                ..
            }) => {
                // Ctrl+O: Open file
                if modifiers.command() && c.as_ref() == "o" {
                    Some(Message::KeyboardShortcut(KeyboardShortcut::ChooseShellcode))
                }
                // Ctrl+Shift+A: Add plugin
                else if modifiers.command() && modifiers.shift() && c.as_ref() == "a" {
                    Some(Message::KeyboardShortcut(KeyboardShortcut::AddPlugin))
                }
                // Ctrl+G: Generate
                else if modifiers.command() && c.as_ref() == "g" {
                    Some(Message::KeyboardShortcut(KeyboardShortcut::Generate))
                }
                // Ctrl+K: Clear source
                else if modifiers.command() && c.as_ref() == "k" {
                    Some(Message::KeyboardShortcut(KeyboardShortcut::ClearSource))
                }
                else {
                    None
                }
            }
            Event::Keyboard(keyboard::Event::KeyPressed {
                key: keyboard::Key::Named(keyboard::key::Named::F1),
                ..
            }) => {
                Some(Message::ShowAbout)
            }
            Event::Window(iced::window::Event::FileDropped(path)) => {
                Some(Message::FilesDropped(vec![path]))
            }
            _ => None,
        })
    }

    pub fn view(&self) -> Column<Message> {
        let padding = 20;
        let spacing = 20;

        let shellcode_src = column![
            row![
                text_input(
                    match self.shellcode_save_type() {
                        ShellcodeSaveType::Local => "Shellcode path:",
                        ShellcodeSaveType::Remote => "Shellcode url:",
                    },
                    &self.shellcode_src
                )
                .on_input(Message::ShellcodeSrcChanged)
                .icon(text_input::Icon {
                    font: JETBRAINS_MONO_FONT,
                    code_point: '󱓞',
                    size: None,
                    spacing: 12.0,
                    side: text_input::Side::Left,
                }),
                button(match self.shellcode_save_type() {
                    ShellcodeSaveType::Local => row![Svg::new(Handle::from_memory(include_bytes!(
                        "../assets/svg/three-dots.svg"
                    )))
                    .width(20)],
                    ShellcodeSaveType::Remote => row![text("󰒃 Encrypt")],
                })
                .on_press(Message::ChooseShellcodeClicked),
                button("󰝒 Clear")
                    .on_press(Message::ClearShellcodeSource)
                    .style(button::secondary),
            ]
            .spacing(3)
            .align_y(Vertical::Center),
            // Recent files section (only show if we have recent files and it's local mode)
            if !self.recent_files().is_empty() && self.shellcode_save_type() == ShellcodeSaveType::Local {
                container(
                    column(
                        self.recent_files().iter().take(3).map(|path| {
                            button(
                                row![
                                    text("󰈙"),
                                    text(path.file_name().unwrap_or_default().to_string_lossy())
                                        .size(12)
                                ]
                                .spacing(5)
                                .align_y(Vertical::Center)
                            )
                            .on_press(Message::OpenRecentFile(path.clone()))
                            .style(button::text)
                            .width(Length::Fill)
                            .into()
                        }).collect::<Vec<_>>()
                    )
                    .spacing(2)
                )
                .padding(5)
                .style(|theme: &Theme| {
                    let palette = theme.extended_palette();
                    container::Style::default()
                        .background(palette.background.weak.color)
                        .border(Border {
                            color: palette.background.strong.color,
                            width: 1.0,
                            radius: iced::border::Radius::from(0.0),
                        })
                })
            } else {
                container(text(""))
            }
        ]
        .spacing(5);

        let pick_list_handle = || pick_list::Handle::Dynamic {
            closed: pick_list::Icon {
                font: JETBRAINS_MONO_FONT,
                code_point: '',
                size: None,
                line_height: text::LineHeight::Relative(1.0),
                shaping: text::Shaping::Basic,
            },
            open: pick_list::Icon {
                font: JETBRAINS_MONO_FONT,
                code_point: '',
                size: None,
                line_height: text::LineHeight::Relative(1.0),
                shaping: text::Shaping::Basic,
            },
        };

        let platform = pick_list(
            self.supported_platforms(),
            self.selected_platform(),
            Message::PlatformChanged,
        )
        .placeholder("Platform")
        .width(100)
        .handle(pick_list_handle());

        let binary_type = pick_list(
            self.supported_binary_types(),
            self.selected_binary_type(),
            Message::BinaryTypeChanged,
        )
        .placeholder("BinType")
        .width(100)
        .handle(pick_list_handle());

        let generate = button(
            row![
                Svg::new(Handle::from_memory(include_bytes!(
                    "../assets/svg/rust-svgrepo-com.svg"
                )))
                .width(20),
                text!("Generate")
            ]
            .spacing(3)
            .align_y(Vertical::Center),
        )
        .on_press_maybe(
            if self.selected_binary_type().is_some() && self.shellcode_src().is_empty().not() {
                Some(Message::GenerateClicked)
            } else {
                None
            },
        );

        let setting_panel = row![shellcode_src, platform, binary_type, generate]
            .spacing(spacing)
            .align_y(Vertical::Center);

        let mut plugin_items = column![]
            .align_x(Horizontal::Center)
            .spacing(10)
            .width(Length::Fill)
            .padding(3);

        if self.plugins().is_empty() {
            plugin_items = plugin_items.push(
                row![
                    Svg::new(Handle::from_memory(include_bytes!(
                        "../assets/svg/magic-star-svgrepo-com.svg"
                    )))
                    .width(30)
                    .height(30)
                    .style(style::svg::svg_primary_base),
                    text("Did you see that  sign? 󰁂")
                        .color(self.theme().extended_palette().primary.base.color)
                ]
                .spacing(spacing)
                .align_y(Vertical::Center),
            );
        }

        let plugin_names = self.plugins().get_sorted_names();

        // dynamic push plugin item
        for plugin_name in plugin_names {
            let plugin = match self.plugins().get(&plugin_name) {
                Ok(x) => x,
                Err(_) => continue,
            };

            let item = button(
                column![
                    text!(" {}", plugin_name).width(Length::Fill),
                    row![
                        column![text!(" {}", plugin.info().author())]
                            .width(Length::Fill)
                            .align_x(Horizontal::Left),
                        column![row!(
                            text(" ").color(self.theme().extended_palette().primary.base.color),
                            if plugin.bins().windows().is_platform_supported() {
                                text(" ").color(self.theme().extended_palette().success.base.color)
                            } else {
                                text(" ").color(self.theme().extended_palette().danger.base.color)
                            },
                            text(" ").color(self.theme().extended_palette().primary.base.color),
                            if plugin.bins().linux().is_platform_supported() {
                                text(" ").color(self.theme().extended_palette().success.base.color)
                            } else {
                                text(" ").color(self.theme().extended_palette().danger.base.color)
                            },
                            text(" ").color(self.theme().extended_palette().primary.base.color),
                            if plugin.bins().darwin().is_platform_supported() {
                                text(" ").color(self.theme().extended_palette().success.base.color)
                            } else {
                                text(" ").color(self.theme().extended_palette().danger.base.color)
                            }
                        )
                        .align_y(Vertical::Center)]
                        .width(Length::Shrink)
                        .align_x(Horizontal::Right)
                    ]
                    .align_y(Vertical::Center),
                ]
                .align_x(Horizontal::Center),
            )
            .width(Length::Fill)
            .style(match self.selected_plugin() {
                Some(x) if x.info().plugin_name() == plugin_name => style::button::selected,
                _ => style::button::unselected,
            })
            .on_press(Message::PluginItemClicked(plugin_name));

            plugin_items = plugin_items.push(item);
        }

        let pumpkin = Svg::new(Handle::from_memory(include_bytes!(
            "../assets/svg/pumpkin-svgrepo-com.svg"
        )))
        .style(|theme: &Theme, _| svg::Style {
            color: Some(theme.extended_palette().background.weak.color),
        });

        let plugin_info_title = |x: &str| {
            text(x.to_owned())
                .size(16)
                .style(|theme: &Theme| text::Style {
                    color: Some(theme.extended_palette().primary.base.color),
                })
        };

        let binary_type_some = || {
            text(" ")
                .style(|theme: &Theme| text::Style {
                    color: Some(theme.extended_palette().success.base.color),
                })
                .size(16)
        };

        let binary_type_none = || {
            text(" ")
                .style(|theme: &Theme| text::Style {
                    color: Some(theme.extended_palette().danger.base.color),
                })
                .size(16)
        };

        let plugin_info_panel = column![match self.selected_plugin() {
            Some(plugin) => {
                row![
                    column![
                        row![column![
                            plugin_info_title(" Name:"),
                            plugin_info_title(" Author:"),
                            plugin_info_title(" Version:"),
                            plugin_info_title("󰰥 Type:"),
                            plugin_info_title(" MaxLen:"),
                            plugin_info_title(" Windows:"),
                            plugin_info_title(" Linux:"),
                            plugin_info_title(" Darwin:"),
                            plugin_info_title(" Description:"),
                        ]
                        .align_x(Horizontal::Left)]
                        .align_y(Vertical::Top),
                        row![pumpkin].height(Length::Fill).align_y(Vertical::Bottom),
                    ]
                    .width(Length::FillPortion(1))
                    .align_x(Horizontal::Left),
                    column![
                        text(plugin.info().plugin_name()).size(16),
                        text(plugin.info().author()).size(16),
                        text(plugin.info().version()).size(16),
                        text(match plugin.replace().size_holder().is_none() {
                            true => "Remote",
                            false => "Local",
                        })
                        .size(16),
                        text!("{} Bytes", plugin.replace().max_len()).size(16),
                        row![
                            text(BinaryType::Executable.to_string()),
                            {
                                let bins = plugin.bins().windows();
                                if bins.executable().is_some() {
                                    binary_type_some()
                                } else {
                                    binary_type_none()
                                }
                            },
                            text(BinaryType::DynamicLibrary.to_string()),
                            {
                                let bins = plugin.bins().windows();
                                if bins.dynamic_library().is_some() {
                                    binary_type_some()
                                } else {
                                    binary_type_none()
                                }
                            }
                        ]
                        .spacing(3)
                        .align_y(Vertical::Center),
                        row![
                            text(BinaryType::Executable.to_string()),
                            {
                                let bins = plugin.bins().linux();
                                if bins.executable().is_some() {
                                    binary_type_some()
                                } else {
                                    binary_type_none()
                                }
                            },
                            text(BinaryType::DynamicLibrary.to_string()),
                            {
                                let bins = plugin.bins().linux();
                                if bins.dynamic_library().is_some() {
                                    binary_type_some()
                                } else {
                                    binary_type_none()
                                }
                            }
                        ]
                        .spacing(3)
                        .align_y(Vertical::Center),
                        row![
                            text(BinaryType::Executable.to_string()),
                            {
                                let bins = plugin.bins().darwin();
                                if bins.executable().is_some() {
                                    binary_type_some()
                                } else {
                                    binary_type_none()
                                }
                            },
                            text(BinaryType::DynamicLibrary.to_string()),
                            {
                                let bins = plugin.bins().darwin();
                                if bins.dynamic_library().is_some() {
                                    binary_type_some()
                                } else {
                                    binary_type_none()
                                }
                            }
                        ]
                        .spacing(3)
                        .align_y(Vertical::Center),
                        text_editor(self.plugin_desc())
                            .padding(10)
                            .height(Length::Fill)
                            .on_action(Message::EditorAction),
                    ]
                    .width(Length::FillPortion(3))
                    .align_x(Horizontal::Left)
                ]
                .spacing(spacing)
                .align_y(Vertical::Center)
            }
            None => row![pumpkin],
        }]
        .align_x(Horizontal::Left);

        let plugin_list_view = container(
            column![
                Scrollable::new(plugin_items)
                    .width(Length::Fill)
                    .height(Length::Fill),
                column![
                    horizontal_rule(0),
                    row![
                        button(
                            Svg::new(Handle::from_memory(include_bytes!(
                                "../assets/svg/iconmonstr-plus-lined.svg"
                            )))
                            .width(20)
                            .height(Length::Fill)
                            .style(style::svg::svg_primary_base)
                        )
                        .on_press(Message::AddPluginClicked)
                        .style(button::text),
                        vertical_rule(0),
                        button(
                            Svg::new(Handle::from_memory(include_bytes!(
                                "../assets/svg/iconmonstr-line-one-horizontal-lined.svg"
                            )))
                            .width(20)
                            .height(Length::Fill)
                            .style(style::svg::svg_primary_base)
                        )
                        .on_press_maybe(
                            self.selected_plugin()
                                .map(|x| Message::ConfirmRemovePlugin(x.info().plugin_name().to_string()))
                        )
                        .style(|theme: &Theme, status| {
                            let palette = theme.extended_palette();
                            let mut style = button::text(theme, status);
                            if status == button::Status::Disabled {
                                style.background =
                                    Some(Background::Color(palette.background.weak.color));
                            }

                            style
                        }),
                        vertical_rule(0),
                    ]
                    .width(Length::Fill)
                    .align_y(Vertical::Center),
                ]
                .width(Length::Fill)
                .height(20)
                .align_x(Horizontal::Center)
            ]
            .spacing(3)
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(Horizontal::Center),
        )
        .height(Length::Fill)
        .style(|theme: &Theme| {
            let palette = theme.extended_palette();
            container::Style::default().border(Border {
                color: palette.background.strong.color,
                width: 1.0,
                radius: iced::border::Radius::from(0.0),
            })
        });

        let plugin_panel = row![
            plugin_info_panel.width(Length::FillPortion(2)),
            plugin_list_view.width(Length::FillPortion(1))
        ]
        .spacing(spacing)
        .align_y(Vertical::Center)
        .width(Length::Fill)
        .height(Length::Fill);

        let version = text(format!("PumpBin  v{}", env!("CARGO_PKG_VERSION")))
            .color(self.theme().extended_palette().primary.base.color);

        let b1n = button(
            Svg::new(Handle::from_memory(include_bytes!(
                "../assets/svg/house-heart-fill.svg"
            )))
            .width(30)
            .height(30)
            .style(style::svg::svg_primary_base),
        )
        .style(button::text)
        .on_press(Message::B1nClicked);
        let github = button(
            Svg::new(Handle::from_memory(include_bytes!(
                "../assets/svg/github.svg"
            )))
            .width(30)
            .height(30)
            .style(style::svg::svg_primary_base),
        )
        .style(button::text)
        .on_press(Message::GithubClicked);

        let theme_list = pick_list(
            Theme::ALL,
            Some(self.selected_theme.clone()),
            Message::ThemeChanged,
        );

        let footer = column![
            horizontal_rule(0),
            row![
                column![
                    version,
                    text("F1: About • Ctrl+O: Open • Ctrl+G: Generate • Ctrl+Shift+A: Add Plugin • Ctrl+K: Clear • Drag & Drop: Files")
                        .size(10)
                        .color(self.theme().extended_palette().background.base.text)
                ]
                .width(Length::Fill)
                .align_x(Horizontal::Left),
                column![row![b1n, github].align_y(Vertical::Center)]
                    .width(Length::Shrink)
                    .align_x(Horizontal::Center),
                column![theme_list]
                    .width(Length::Fill)
                    .align_x(Horizontal::Right)
            ]
            .padding([0, padding])
            .align_y(Vertical::Center)
        ]
        .align_x(Horizontal::Center);

        let mut home = column![
            column![setting_panel, plugin_panel]
                .padding(padding)
                .align_x(Horizontal::Center)
                .spacing(spacing),
            footer
        ]
        .align_x(Horizontal::Center);

        // Add loading overlay if loading
        if self.is_loading() {
            home = home.push(
                container(
                    column![
                        text("󰔟").size(30),
                        text(&self.loading_message).size(14)
                    ]
                    .spacing(10)
                    .align_x(Horizontal::Center)
                )
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill)
                .style(|_theme: &Theme| {
                    container::Style::default()
                        .background(iced::Color::from_rgba(0.0, 0.0, 0.0, 0.7))
                })
            );
        }

        home
    }

    pub fn theme(&self) -> Theme {
        self.selected_theme.clone()
    }
}
