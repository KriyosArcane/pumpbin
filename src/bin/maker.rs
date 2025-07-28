#![windows_subsystem = "windows"]

use std::{fs, ops::Not, path::PathBuf};

use anyhow::{anyhow, bail};
use dirs::{desktop_dir, home_dir};
use iced::{
    alignment::{Horizontal, Vertical},
    application,
    event::{self, Event},
    futures::TryFutureExt,
    keyboard::{self, Key},
    widget::{
        button, column, container, horizontal_rule, pick_list, radio, row, svg::Handle, text, text_editor,
        text_input, Column, Svg,
    },
    window, Length, Size, Subscription, Task, Theme,
};
use memchr::memmem;
use pumpbin::{
    plugin::{Plugin, PluginInfo, PluginReplace},
    utils::{self, error_dialog, message_dialog},
};
use pumpbin::{style, ShellcodeSaveType};
use rfd::{AsyncFileDialog, MessageLevel};

fn main() {
    if let Err(e) = try_main() {
        error_dialog(e);
    }
}

fn try_main() -> anyhow::Result<()> {
    let size = Size::new(1200.0, 800.0);

    let mut window_settings = utils::window_settings();
    window_settings.size = size;
    window_settings.min_size = Some(size);

    application("PumpBin Maker", Maker::update, Maker::view)
        .settings(utils::settings())
        .window(window_settings)
        .theme(Maker::theme)
        .subscription(Maker::subscription)
        .run()?;

    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum ChooseFileType {
    WindowsExe,
    WindowsLib,
    LinuxExe,
    LinuxLib,
    DarwinExe,
    DarwinLib,
    EncryptShellcodePlugin,
    FormatEncryptedShellcodePlugin,
    FormatUrlRemote,
    UploadFinalShellcodeRemote,
}



#[derive(Debug, Clone)]
enum MakerMessage {
    PluginNameChanged(String),
    AuthorChanged(String),
    VersionChanged(String),
    SrcPrefixChanged(String),
    MaxLenChanged(String),
    ShellcodeSaveTypeChanged(ShellcodeSaveType),
    SizeHolderChanged(String),
    WindowsExeChanged(String),
    WindowsLibChanged(String),
    LinuxExeChanged(String),
    LinuxLibChanged(String),
    DarwinExeChanged(String),
    DarwinLibChanged(String),
    EncryptShllcodePluginChanged(String),
    FormatEncryptedShellcodePluginChanged(String),
    FormatUrlRemotePluginChanged(String),
    UploadFinalShellcodeRemotePluginChanged(String),
    DescAction(text_editor::Action),
    GenerateClicked,
    GenerateDone(Result<(), String>),
    ChooseFileClicked(ChooseFileType),
    ChooseFileDone((Option<String>, ChooseFileType)),
    OpenB1nClicked,
    OpenB1nDone(Result<String, String>),
    OpenRecentFile(String),
    NewPluginClicked,
    B1nClicked,
    GithubClicked,
    ThemeChanged(Theme),
    KeyboardEvent(Event),
    // Drag & Drop Support
    FilesDropped(Vec<PathBuf>),
    FileDroppedOnField(PathBuf, ChooseFileType),
}

#[derive(Debug)]
struct Maker {
    plugin_name: String,
    author: String,
    version: String,
    src_prefix: String,
    max_len: String,
    shellcode_save_type: ShellcodeSaveType,
    size_holder: String,
    windows_exe: String,
    windows_lib: String,
    linux_exe: String,
    linux_lib: String,
    darwin_exe: String,
    darwin_lib: String,
    encrypt_shellcode_plugin: String,
    format_encrypted_shellcode_plugin: String,
    format_url_remote_plugin: String,
    upload_final_shellcode_remote_plugin: String,
    desc: text_editor::Content,
    pumpbin_version: String,
    selected_theme: Theme,
    current_file_path: Option<String>,
    // Recent files
    recent_files: Vec<String>,
}

impl Maker {
    fn load_from_plugin(&mut self, plugin: Plugin) {
        // Load basic info
        self.plugin_name = plugin.info().plugin_name().to_string();
        self.author = plugin.info().author().to_string();
        self.version = plugin.info().version().to_string();
        
        // Load replacement settings
        self.src_prefix = String::from_utf8_lossy(plugin.replace().src_prefix()).to_string();
        self.max_len = plugin.replace().max_len().to_string();
        
        // Determine shellcode save type and size holder
        if let Some(size_holder) = plugin.replace().size_holder() {
            self.shellcode_save_type = ShellcodeSaveType::Local;
            self.size_holder = String::from_utf8_lossy(size_holder).to_string();
        } else {
            self.shellcode_save_type = ShellcodeSaveType::Remote;
            self.size_holder.clear();
        }
        
        // Load description
        self.desc = text_editor::Content::with_text(plugin.info().desc());
        
        // Note: Binary paths are not loaded as they represent the original source files
        // Users will need to re-select binary paths if they want to regenerate
        self.windows_exe.clear();
        self.windows_lib.clear();
        self.linux_exe.clear();
        self.linux_lib.clear();
        self.darwin_exe.clear();
        self.darwin_lib.clear();
        self.encrypt_shellcode_plugin.clear();
        self.format_encrypted_shellcode_plugin.clear();
        self.format_url_remote_plugin.clear();
        self.upload_final_shellcode_remote_plugin.clear();
    }
    
    fn reset_to_new(&mut self) {
        *self = Self {
            current_file_path: None,
            recent_files: self.recent_files.clone(), // Keep recent files
            ..Default::default()
        };
    }

    fn add_recent_file(&mut self, path: String) {
        // Remove if already exists
        self.recent_files.retain(|p| p != &path);
        // Add to front
        self.recent_files.insert(0, path);
        // Keep only last 10
        self.recent_files.truncate(10);
    }

    fn check_generate(&self) -> anyhow::Result<()> {
        if self.plugin_name.is_empty() {
            bail!("Plugin Name is empty.");
        }

        if self.src_prefix.is_empty() {
            bail!("Prefix is empty.");
        }

        let max_len = self.max_len();
        if max_len.is_empty() {
            bail!("Max Len is empty.");
        }

        if max_len.parse::<usize>().is_err() {
            bail!("Max Len numeric only.");
        };

        if let ShellcodeSaveType::Local = self.shellcode_save_type() {
            if self.size_holder().is_empty() {
                bail!("Size Holder is empty.");
            }
            
            // Validate that size holder is a valid number
            if self.size_holder().parse::<usize>().is_err() {
                bail!("Size Holder must be a valid number.");
            }
        };

        anyhow::Ok(())
    }
}

impl Default for Maker {
    fn default() -> Self {
        Self {
            plugin_name: Default::default(),
            author: Default::default(),
            version: Default::default(),
            src_prefix: Default::default(),
            max_len: Default::default(),
            shellcode_save_type: Default::default(),
            size_holder: Default::default(),
            windows_exe: Default::default(),
            windows_lib: Default::default(),
            linux_exe: Default::default(),
            linux_lib: Default::default(),
            darwin_exe: Default::default(),
            darwin_lib: Default::default(),
            encrypt_shellcode_plugin: Default::default(),
            format_encrypted_shellcode_plugin: Default::default(),
            format_url_remote_plugin: Default::default(),
            upload_final_shellcode_remote_plugin: Default::default(),
            desc: text_editor::Content::new(),
            pumpbin_version: env!("CARGO_PKG_VERSION").into(),
            selected_theme: Theme::CatppuccinMacchiato,
            current_file_path: None,
            recent_files: Vec::new(),
        }
    }
}

impl Maker {
    fn plugin_name(&self) -> &str {
        &self.plugin_name
    }

    fn author(&self) -> &str {
        &self.author
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn src_prefix(&self) -> &str {
        &self.src_prefix
    }

    fn max_len(&self) -> &str {
        &self.max_len
    }

    fn shellcode_save_type(&self) -> ShellcodeSaveType {
        self.shellcode_save_type
    }

    fn size_holder(&self) -> &str {
        &self.size_holder
    }

    fn windows_exe(&self) -> &str {
        &self.windows_exe
    }

    fn windows_lib(&self) -> &str {
        &self.windows_lib
    }

    fn linux_exe(&self) -> &str {
        &self.linux_exe
    }

    fn linux_lib(&self) -> &str {
        &self.linux_lib
    }

    fn darwin_exe(&self) -> &str {
        &self.darwin_exe
    }

    fn darwin_lib(&self) -> &str {
        &self.darwin_lib
    }

    fn encrypt_shellcode_plugin(&self) -> &str {
        &self.encrypt_shellcode_plugin
    }

    fn format_encrypted_shellcode_plugin(&self) -> &str {
        &self.format_encrypted_shellcode_plugin
    }

    fn format_url_remote_plugin(&self) -> &str {
        &self.format_url_remote_plugin
    }

    fn upload_final_shellcode_remote_plugin(&self) -> &str {
        &self.upload_final_shellcode_remote_plugin
    }

    fn desc(&self) -> &text_editor::Content {
        &self.desc
    }

    fn desc_mut(&mut self) -> &mut text_editor::Content {
        &mut self.desc
    }

    fn selected_theme(&self) -> Theme {
        self.selected_theme.clone()
    }

    fn pumpbin_version(&self) -> &str {
        &self.pumpbin_version
    }
}

impl Maker {
    pub fn update(&mut self, message: MakerMessage) -> iced::Task<MakerMessage> {
        match message {
            MakerMessage::PluginNameChanged(x) => self.plugin_name = x,
            MakerMessage::AuthorChanged(x) => self.author = x,
            MakerMessage::VersionChanged(x) => self.version = x,
            MakerMessage::SrcPrefixChanged(x) => self.src_prefix = x,
            MakerMessage::MaxLenChanged(x) => self.max_len = x,
            MakerMessage::ShellcodeSaveTypeChanged(x) => self.shellcode_save_type = x,
            MakerMessage::SizeHolderChanged(x) => self.size_holder = x,
            MakerMessage::WindowsExeChanged(x) => self.windows_exe = x,
            MakerMessage::WindowsLibChanged(x) => self.windows_lib = x,
            MakerMessage::LinuxExeChanged(x) => self.linux_exe = x,
            MakerMessage::LinuxLibChanged(x) => self.linux_lib = x,
            MakerMessage::DarwinExeChanged(x) => self.darwin_exe = x,
            MakerMessage::DarwinLibChanged(x) => self.darwin_lib = x,
            MakerMessage::EncryptShllcodePluginChanged(x) => self.encrypt_shellcode_plugin = x,
            MakerMessage::FormatEncryptedShellcodePluginChanged(x) => {
                self.format_encrypted_shellcode_plugin = x
            }
            MakerMessage::FormatUrlRemotePluginChanged(x) => self.format_url_remote_plugin = x,
            MakerMessage::UploadFinalShellcodeRemotePluginChanged(x) => {
                self.upload_final_shellcode_remote_plugin = x
            }
            MakerMessage::DescAction(x) => self.desc_mut().perform(x),
            MakerMessage::GenerateClicked => {
                if let Err(e) = self.check_generate() {
                    message_dialog(e.to_string(), MessageLevel::Error);
                    return Task::none();
                }

                let src_prefix_bytes = self.src_prefix().as_bytes().to_vec();

                let mut plugin = Plugin {
                    version: self.pumpbin_version().to_string(),
                    info: PluginInfo {
                        plugin_name: self.plugin_name().to_string(),
                        author: {
                            let author = self.author().to_string();
                            if author.is_empty() {
                                "None".to_string()
                            } else {
                                author
                            }
                        },
                        version: {
                            let version = self.version().to_string();
                            if version.is_empty() {
                                "None".to_string()
                            } else {
                                version
                            }
                        },
                        desc: {
                            let desc = self.desc().text();
                            if desc.is_empty() {
                                "None".to_string()
                            } else {
                                desc
                            }
                        },
                    },
                    replace: PluginReplace {
                        src_prefix: src_prefix_bytes.clone(),
                        size_holder: match self.shellcode_save_type() {
                            ShellcodeSaveType::Local => {
                                Some(self.size_holder().as_bytes().to_vec())
                            }
                            ShellcodeSaveType::Remote => None,
                        },
                        max_len: self.max_len().parse().unwrap(),
                    },
                    ..Default::default()
                };

                let paths: Vec<(String, ChooseFileType)> = vec![
                    (self.windows_exe(), ChooseFileType::WindowsExe),
                    (self.windows_lib(), ChooseFileType::WindowsLib),
                    (self.linux_exe(), ChooseFileType::LinuxExe),
                    (self.linux_lib(), ChooseFileType::LinuxLib),
                    (self.darwin_exe(), ChooseFileType::DarwinExe),
                    (self.darwin_lib(), ChooseFileType::DarwinLib),
                    (
                        self.encrypt_shellcode_plugin(),
                        ChooseFileType::EncryptShellcodePlugin,
                    ),
                    (
                        self.format_encrypted_shellcode_plugin(),
                        ChooseFileType::FormatEncryptedShellcodePlugin,
                    ),
                    (
                        self.format_url_remote_plugin(),
                        ChooseFileType::FormatUrlRemote,
                    ),
                    (
                        self.upload_final_shellcode_remote_plugin(),
                        ChooseFileType::UploadFinalShellcodeRemote,
                    ),
                ]
                .into_iter()
                .map(|(x, y)| (x.to_string(), y))
                .collect();

                let make_plugin = async move {
                    for (path_str, file_type) in paths {
                        if path_str.is_empty().not() {
                            let path = PathBuf::from(path_str);
                            let data = fs::read(&path)?;

                            // Check if the binary still contains the placeholder
                            if memmem::find(&data, &src_prefix_bytes).is_none() {
                                bail!(
                                    "The binary at '{}' does not contain the specified shellcode prefix ('{}'). Please recompile it with the correct placeholder.",
                                    path.display(),
                                    String::from_utf8_lossy(&src_prefix_bytes)
                                );
                            }

                            let bin = match file_type {
                                ChooseFileType::WindowsExe => plugin.bins.windows.executable_mut(),
                                ChooseFileType::WindowsLib => {
                                    plugin.bins.windows.dynamic_library_mut()
                                }
                                ChooseFileType::LinuxExe => plugin.bins.linux.executable_mut(),
                                ChooseFileType::LinuxLib => plugin.bins.linux.dynamic_library_mut(),
                                ChooseFileType::DarwinExe => plugin.bins.darwin.executable_mut(),
                                ChooseFileType::DarwinLib => {
                                    plugin.bins.darwin.dynamic_library_mut()
                                }
                                ChooseFileType::EncryptShellcodePlugin => {
                                    plugin.plugins.encrypt_shellcode_mut()
                                }
                                ChooseFileType::FormatEncryptedShellcodePlugin => {
                                    plugin.plugins.format_encrypted_shellcode_mut()
                                }
                                ChooseFileType::FormatUrlRemote => {
                                    plugin.plugins.format_url_remote_mut()
                                }
                                ChooseFileType::UploadFinalShellcodeRemote => {
                                    plugin.plugins.upload_final_shellcode_remote_mut()
                                }
                            };
                            *bin = Some(data);
                        }
                    }

                    // All PumpBin plugins should have .b1n extension regardless of binary type
                    let plugin_name = plugin.info().plugin_name();
                    let filename = format!("{}.b1n", plugin_name);

                    // Provide user feedback about what binary types are included
                    let binary_types = [
                        (plugin.bins.windows.executable().is_some(), "Windows .exe"),
                        (plugin.bins.linux.executable().is_some(), "Linux executable"),
                        (plugin.bins.darwin.executable().is_some(), "macOS executable"),
                        (plugin.bins.windows.dynamic_library().is_some(), "Windows .dll"),
                        (plugin.bins.linux.dynamic_library().is_some(), "Linux .so"),
                        (plugin.bins.darwin.dynamic_library().is_some(), "macOS .dylib"),
                    ]
                    .iter()
                    .filter_map(|(present, name)| if *present { Some(*name) } else { None })
                    .collect::<Vec<_>>();

                    let file_type_info = if binary_types.is_empty() {
                        "PumpBin plugin (no binaries included)".to_string()
                    } else {
                        format!("PumpBin plugin containing: {}", binary_types.join(", "))
                    };

                    println!("Generating {}", file_type_info);

                    let file = AsyncFileDialog::new()
                        .set_directory(desktop_dir().unwrap_or(".".into()))
                        .set_file_name(filename)
                        .set_title("Save PumpBin plugin (.b1n)")
                        .save_file()
                        .await
                        .ok_or(anyhow!("Canceled the saving of the plugin."))?;

                    fs::write(file.path(), plugin.encode_to_vec()?)?;

                    anyhow::Ok(())
                }
                .map_err(|e| e.to_string());

                return Task::perform(make_plugin, MakerMessage::GenerateDone);
            }
            MakerMessage::GenerateDone(x) => {
                match x {
                    Ok(_) => message_dialog("Generate done.".to_string(), MessageLevel::Info),
                    Err(e) => message_dialog(e, MessageLevel::Error),
                };
            }
            MakerMessage::OpenB1nClicked => {
                let open_file = async move {
                    let file = AsyncFileDialog::new()
                        .set_directory(home_dir().unwrap_or(".".into()))
                        .set_title("Open .b1n plugin file")
                        .add_filter("PumpBin Plugin", &["b1n"])
                        .pick_file()
                        .await
                        .map(|x| x.path().to_string_lossy().to_string());

                    match file {
                        Some(path) => {
                            match std::fs::read(&path) {
                                Ok(data) => {
                                    match Plugin::decode_from_slice(&data) {
                                        Ok(_plugin) => Ok(path),
                                        Err(e) => Err(format!("Failed to parse plugin file: {}", e)),
                                    }
                                }
                                Err(e) => Err(format!("Failed to read file: {}", e)),
                            }
                        }
                        None => Err("No file selected".to_string()),
                    }
                };

                return Task::perform(open_file, MakerMessage::OpenB1nDone);
            }
            MakerMessage::OpenB1nDone(result) => {
                match result {
                    Ok(path) => {
                        // Load the plugin data
                        if let Ok(data) = std::fs::read(&path) {
                            if let Ok(plugin) = Plugin::decode_from_slice(&data) {
                                self.load_from_plugin(plugin);
                                self.current_file_path = Some(path.clone());
                                self.add_recent_file(path.clone());
                                message_dialog(
                                    format!("Plugin loaded successfully from: {}", path),
                                    MessageLevel::Info,
                                );
                            } else {
                                message_dialog("Failed to parse plugin file".to_string(), MessageLevel::Error);
                            }
                        } else {
                            message_dialog("Failed to read plugin file".to_string(), MessageLevel::Error);
                        }
                    }
                    Err(e) => {
                        message_dialog(e, MessageLevel::Error);
                    }
                }
            }
            MakerMessage::OpenRecentFile(path) => {
                // Load the plugin data from recent file
                if let Ok(data) = std::fs::read(&path) {
                    if let Ok(plugin) = Plugin::decode_from_slice(&data) {
                        self.load_from_plugin(plugin);
                        self.current_file_path = Some(path.clone());
                        self.add_recent_file(path.clone());
                        message_dialog(
                            format!("Plugin loaded successfully from: {}", path),
                            MessageLevel::Info,
                        );
                    } else {
                        message_dialog("Failed to parse plugin file".to_string(), MessageLevel::Error);
                    }
                } else {
                    message_dialog("Failed to read plugin file".to_string(), MessageLevel::Error);
                }
            }
            MakerMessage::NewPluginClicked => {
                // Reset all fields to default
                self.reset_to_new();
                message_dialog("New plugin created. All fields have been reset.".to_string(), MessageLevel::Info);
            }
            MakerMessage::ChooseFileClicked(x) => {
                let choose_file = async move {
                    let file = AsyncFileDialog::new()
                        .set_directory(home_dir().unwrap_or(".".into()))
                        .set_title("Choose file")
                        .pick_file()
                        .await
                        .map(|x| x.path().to_string_lossy().to_string());

                    (file, x)
                };

                return Task::perform(choose_file, MakerMessage::ChooseFileDone);
            }
            MakerMessage::ChooseFileDone((path, choose_type)) => {
                if let Some(path) = path {
                    match choose_type {
                        ChooseFileType::WindowsExe => self.windows_exe = path,
                        ChooseFileType::WindowsLib => self.windows_lib = path,
                        ChooseFileType::LinuxExe => self.linux_exe = path,
                        ChooseFileType::LinuxLib => self.linux_lib = path,
                        ChooseFileType::DarwinExe => self.darwin_exe = path,
                        ChooseFileType::DarwinLib => self.darwin_lib = path,
                        ChooseFileType::EncryptShellcodePlugin => {
                            self.encrypt_shellcode_plugin = path
                        }
                        ChooseFileType::FormatEncryptedShellcodePlugin => {
                            self.format_encrypted_shellcode_plugin = path
                        }
                        ChooseFileType::FormatUrlRemote => self.format_url_remote_plugin = path,
                        ChooseFileType::UploadFinalShellcodeRemote => {
                            self.upload_final_shellcode_remote_plugin = path
                        }
                    }
                }
            }
            MakerMessage::B1nClicked => {
                if open::that(env!("CARGO_PKG_HOMEPAGE")).is_err() {
                    message_dialog("Open home failed.".into(), MessageLevel::Error);
                }
            }
            MakerMessage::GithubClicked => {
                if open::that(env!("CARGO_PKG_REPOSITORY")).is_err() {
                    message_dialog("Open repo failed.".into(), MessageLevel::Error);
                }
            }
            MakerMessage::ThemeChanged(x) => self.selected_theme = x,
            MakerMessage::KeyboardEvent(event) => {
                if let Event::Keyboard(keyboard::Event::KeyPressed {
                    key,
                    modifiers,
                    ..
                }) = event
                {
                    match key {
                        Key::Named(keyboard::key::Named::Tab) => {
                            // Tab navigation is handled by the framework automatically
                        }
                        Key::Character(ch) => {
                            if modifiers.control() {
                                match ch.as_str() {
                                    "o" => {
                                        return Task::perform(async {}, |_| MakerMessage::OpenB1nClicked);
                                    }
                                    "n" => {
                                        return Task::perform(async {}, |_| MakerMessage::NewPluginClicked);
                                    }
                                    "g" => {
                                        return Task::perform(async {}, |_| MakerMessage::GenerateClicked);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            MakerMessage::FilesDropped(paths) => {
                // Handle drag & drop files on the general area
                for path in paths {
                    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
                    
                    match extension.to_lowercase().as_str() {
                        "b1n" => {
                            // Load .b1n plugin file
                            let path_str = path.to_string_lossy().to_string();
                            return self.update(MakerMessage::OpenB1nDone(Ok(path_str)));
                        }
                        _ => {
                            // For other files, we'll need context about which field to populate
                            // For now, just show a helpful message
                            message_dialog(
                                format!("File dropped: {}. Please drag onto a specific input field to set its value.", 
                                    path.file_name().unwrap_or_default().to_string_lossy()),
                                MessageLevel::Info,
                            );
                            break;
                        }
                    }
                }
            }
            MakerMessage::FileDroppedOnField(path, field_type) => {
                // Handle file dropped on a specific field
                let path_str = path.to_string_lossy().to_string();
                match field_type {
                    ChooseFileType::WindowsExe => self.windows_exe = path_str,
                    ChooseFileType::WindowsLib => self.windows_lib = path_str,
                    ChooseFileType::LinuxExe => self.linux_exe = path_str,
                    ChooseFileType::LinuxLib => self.linux_lib = path_str,
                    ChooseFileType::DarwinExe => self.darwin_exe = path_str,
                    ChooseFileType::DarwinLib => self.darwin_lib = path_str,
                    ChooseFileType::EncryptShellcodePlugin => self.encrypt_shellcode_plugin = path_str,
                    ChooseFileType::FormatEncryptedShellcodePlugin => self.format_encrypted_shellcode_plugin = path_str,
                    ChooseFileType::FormatUrlRemote => self.format_url_remote_plugin = path_str,
                    ChooseFileType::UploadFinalShellcodeRemote => self.upload_final_shellcode_remote_plugin = path_str,
                }
                message_dialog(
                    format!("File set: {}", path.file_name().unwrap_or_default().to_string_lossy()),
                    MessageLevel::Info,
                );
            }
        }

        Task::none()
    }

    pub fn view(&self) -> Column<MakerMessage> {
        let choose_button = || {
            button(
                Svg::new(Handle::from_memory(include_bytes!(
                    "../../assets/svg/three-dots.svg"
                )))
                .width(20),
            )
        };

        let maker = column![
            // File operations row with current file display and recent files
            column![
                row![
                    button(" Open .b1n").on_press(MakerMessage::OpenB1nClicked),
                    button(" New Plugin").on_press(MakerMessage::NewPluginClicked),
                ]
                .spacing(10)
                .align_y(Vertical::Center),
                if let Some(ref path) = self.current_file_path {
                    row![
                        text("Current file: ").size(12),
                        text(path).size(12)
                            .style(|theme: &Theme| text::Style {
                                color: Some(theme.extended_palette().primary.base.color),
                            })
                    ]
                    .spacing(5)
                } else {
                    row![]
                },
                // Recent files section
                if !self.recent_files.is_empty() {
                    column![
                        text("Recent files:").size(12),
                        column(
                            self.recent_files.iter().take(5).map(|path| {
                                let filename = std::path::Path::new(path)
                                    .file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .to_string();
                                button(
                                    row![
                                        text("📄"),
                                        text(filename).size(12)
                                    ]
                                    .spacing(5)
                                    .align_y(Vertical::Center)
                                )
                                .style(button::text)
                                .on_press(MakerMessage::OpenRecentFile(path.clone()))
                                .into()
                            }).collect::<Vec<_>>()
                        )
                        .spacing(2)
                    ]
                    .spacing(5)
                } else {
                    column![]
                }
            ]
            .spacing(5),
            row![
                column![
                    text("Plugin Name"),
                    text_input("first_plugin", self.plugin_name())
                        .on_input(MakerMessage::PluginNameChanged)
                        .width(Length::Fill),
                ]
                .align_x(Horizontal::Left),
                column![
                    text("Author"),
                    text_input("your_name", self.author())
                        .on_input(MakerMessage::AuthorChanged)
                        .width(Length::Fill),
                ]
                .align_x(Horizontal::Left),
                column![
                    text("Version"),
                    text_input("1.0.0", self.version())
                        .on_input(MakerMessage::VersionChanged)
                        .width(Length::Fill),
                ]
                .align_x(Horizontal::Left),
                column![
                    text("Prefix"),
                    text_input("$$SHELLCODE$$", self.src_prefix())
                        .on_input(MakerMessage::SrcPrefixChanged)
                        .width(Length::Fill),
                ]
                .align_x(Horizontal::Left),
                column![
                    text("Max Len"),
                    text_input("1048589", self.max_len())
                        .on_input(MakerMessage::MaxLenChanged)
                        .width(Length::Fill),
                ]
                .align_x(Horizontal::Left),
            ]
            .spacing(10)
            .align_y(Vertical::Center),
            column![
                text("Type"),
                row![
                    radio(
                        ShellcodeSaveType::Local.to_string(),
                        ShellcodeSaveType::Local,
                        Some(self.shellcode_save_type()),
                        MakerMessage::ShellcodeSaveTypeChanged
                    ),
                    radio(
                        ShellcodeSaveType::Remote.to_string(),
                        ShellcodeSaveType::Remote,
                        Some(self.shellcode_save_type()),
                        MakerMessage::ShellcodeSaveTypeChanged
                    )
                ]
                .push_maybe(match self.shellcode_save_type() {
                    ShellcodeSaveType::Local => Some(
                        row![
                            text("Size Holder: "),
                            text_input("$$99999$$", self.size_holder())
                                .on_input(MakerMessage::SizeHolderChanged)
                                .width(Length::Fill)
                        ]
                        .spacing(5)
                        .align_y(Vertical::Center)
                    ),
                    ShellcodeSaveType::Remote => None,
                })
                .align_y(Vertical::Center)
                .spacing(20)
            ]
            .spacing(5)
            .align_x(Horizontal::Left),
            column![
                text("Windows"),
                row![
                    text("Exe:"),
                    text_input(
                        if self.windows_exe().is_empty() {
                            "Required for Windows executable template"
                        } else {
                            self.windows_exe()
                        }, 
                        self.windows_exe()
                    ).on_input(MakerMessage::WindowsExeChanged),
                    choose_button()
                        .on_press(MakerMessage::ChooseFileClicked(ChooseFileType::WindowsExe)),
                    text("Lib:"),
                    text_input(
                        if self.windows_lib().is_empty() {
                            "Optional for library-based templates"
                        } else {
                            "Path to Windows .dll file (drag & drop or click browse)"
                        }, 
                        self.windows_lib()
                    ).on_input(MakerMessage::WindowsLibChanged),
                    choose_button()
                        .on_press(MakerMessage::ChooseFileClicked(ChooseFileType::WindowsLib)),
                ]
                .align_y(Vertical::Center)
                .spacing(10)
            ]
            .align_x(Horizontal::Left),
            column![
                text("Linux"),
                row![
                    text("Exe:"),
                    text_input(
                        if self.linux_exe().is_empty() {
                            "Select your compiled Linux executable (no extension needed)"
                        } else {
                            "Path to Linux executable (drag & drop or click browse)"
                        }, 
                        self.linux_exe()
                    ).on_input(MakerMessage::LinuxExeChanged),
                    choose_button()
                        .on_press(MakerMessage::ChooseFileClicked(ChooseFileType::LinuxExe)),
                    text("Lib:"),
                    text_input(
                        if self.linux_lib().is_empty() {
                            "Select your compiled Linux .so library (for library-based templates)"
                        } else {
                            "Path to Linux .so library (drag & drop or click browse)"
                        }, 
                        self.linux_lib()
                    ).on_input(MakerMessage::LinuxLibChanged),
                    choose_button()
                        .on_press(MakerMessage::ChooseFileClicked(ChooseFileType::LinuxLib)),
                ]
                .align_y(Vertical::Center)
                .spacing(10)
            ]
            .align_x(Horizontal::Left),
            column![
                text("Darwin"),
                row![
                    text("Exe:"),
                    text_input(
                        if self.darwin_exe().is_empty() {
                            "Select your compiled macOS executable (no extension needed)"
                        } else {
                            "Path to macOS executable (drag & drop or click browse)"
                        }, 
                        self.darwin_exe()
                    ).on_input(MakerMessage::DarwinExeChanged),
                    choose_button()
                        .on_press(MakerMessage::ChooseFileClicked(ChooseFileType::DarwinExe)),
                    text("Lib:"),
                    text_input(
                        if self.darwin_lib().is_empty() {
                            "Select your compiled macOS .dylib library (for library-based templates)"
                        } else {
                            "Path to macOS .dylib library (drag & drop or click browse)"
                        }, 
                        self.darwin_lib()
                    ).on_input(MakerMessage::DarwinLibChanged),
                    choose_button()
                        .on_press(MakerMessage::ChooseFileClicked(ChooseFileType::DarwinLib)),
                ]
                .align_y(Vertical::Center)
                .spacing(10)
            ]
            .align_x(Horizontal::Left),
            row![
                column![column![
                    text("Encrypt Shellcode Plug-in"),
                    row![
                        text_input(
                            if self.encrypt_shellcode_plugin().is_empty() {
                                "Select your encrypt plugin .wasm file (optional for encrypted shellcode)"
                            } else {
                                "Path to encrypt plugin .wasm file (drag & drop or click browse)"
                            }, 
                            self.encrypt_shellcode_plugin()
                        ).on_input(MakerMessage::EncryptShllcodePluginChanged),
                        choose_button().on_press(MakerMessage::ChooseFileClicked(
                            ChooseFileType::EncryptShellcodePlugin
                        ))
                    ]
                    .align_y(Vertical::Center)
                    .spacing(10),
                ]
                .align_x(Horizontal::Left)]
                .push_maybe(match self.shellcode_save_type() {
                    ShellcodeSaveType::Local => None,
                    ShellcodeSaveType::Remote => Some(column![
                        text("Format Url Remote Plug-in"),
                    row![
                        text_input(
                            if self.format_url_remote_plugin().is_empty() {
                                "Select format URL plugin .wasm file (optional for remote type)"
                            } else {
                                "Path to format URL plugin .wasm file"
                            }, 
                            self.format_url_remote_plugin()
                        ).on_input(MakerMessage::FormatUrlRemotePluginChanged),
                            choose_button().on_press(MakerMessage::ChooseFileClicked(
                                ChooseFileType::FormatUrlRemote
                            ))
                        ]
                        .align_y(Vertical::Center)
                        .spacing(10)
                    ]),
                })
                .width(Length::FillPortion(1))
                .align_x(Horizontal::Center),
                column![column![
                    text("Format Encrypted Shellcode Plug-in"),
                    row![
                        text_input(
                            if self.format_encrypted_shellcode_plugin().is_empty() {
                                "Select format encrypted shellcode plugin .wasm file (optional)"
                            } else {
                                "Path to format encrypted shellcode plugin .wasm file"
                            }, 
                            self.format_encrypted_shellcode_plugin()
                        ).on_input(MakerMessage::FormatEncryptedShellcodePluginChanged),
                        choose_button().on_press(MakerMessage::ChooseFileClicked(
                            ChooseFileType::FormatEncryptedShellcodePlugin
                        ))
                    ]
                    .align_y(Vertical::Center)
                    .spacing(10),
                ]
                .align_x(Horizontal::Left)]
                .push_maybe(match self.shellcode_save_type() {
                    ShellcodeSaveType::Local => None,
                    ShellcodeSaveType::Remote => Some(
                        column![
                            text("Upload Final Shellcode Remote Plug-in"),
                            row![
                                text_input("/path/to/upload_plugin.wasm", self.upload_final_shellcode_remote_plugin())
                                    .on_input(
                                        MakerMessage::UploadFinalShellcodeRemotePluginChanged
                                    ),
                                choose_button().on_press(MakerMessage::ChooseFileClicked(
                                    ChooseFileType::UploadFinalShellcodeRemote
                                ))
                            ]
                            .align_y(Vertical::Center)
                            .spacing(10)
                        ]
                        .align_x(Horizontal::Left)
                    ),
                })
                .width(Length::FillPortion(1))
                .align_x(Horizontal::Center)
            ]
            .align_y(Vertical::Center)
            .spacing(10),
            column![
                text("Description"),
                text_editor(self.desc())
                    .on_action(MakerMessage::DescAction)
                    .height(Length::Fill)
            ]
            .align_x(Horizontal::Left),
            column![row![
                button("Generate").on_press(MakerMessage::GenerateClicked)
            ]]
            .align_x(Horizontal::Center)
            .width(Length::Fill),
        ]
        .align_x(Horizontal::Left)
        .padding(20)
        .spacing(10);

        let version = text(format!("PumpBin  v{}", self.pumpbin_version()))
            .color(self.theme().extended_palette().primary.base.color);

        let b1n = button(
            Svg::new(Handle::from_memory(include_bytes!(
                "../../assets/svg/house-heart-fill.svg"
            )))
            .width(30)
            .height(30)
            .style(style::svg::svg_primary_base),
        )
        .style(button::text)
        .on_press(MakerMessage::B1nClicked);
        let github = button(
            Svg::new(Handle::from_memory(include_bytes!(
                "../../assets/svg/github.svg"
            )))
            .width(30)
            .height(30)
            .style(style::svg::svg_primary_base),
        )
        .style(button::text)
        .on_press(MakerMessage::GithubClicked);

        let theme_list = pick_list(
            Theme::ALL,
            Some(self.selected_theme.clone()),
            MakerMessage::ThemeChanged,
        );

        let footer = column![
            horizontal_rule(0),
            row![
                column![
                    version,
                    text("Ctrl+O: Open .b1n • Ctrl+N: New • Ctrl+G: Generate • Drag & Drop: Files")
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
            .padding(20)
            .align_y(Vertical::Center)
        ]
        .align_x(Horizontal::Center);

        column![maker, footer].align_x(Horizontal::Center)
    }

    pub fn theme(&self) -> Theme {
        self.selected_theme()
    }

    pub fn subscription(&self) -> Subscription<MakerMessage> {
        event::listen_with(|event, _status, _window| match event {
            Event::Window(window::Event::FileDropped(path)) => {
                Some(MakerMessage::FilesDropped(vec![path]))
            }
            _ => Some(MakerMessage::KeyboardEvent(event)),
        })
    }
}
