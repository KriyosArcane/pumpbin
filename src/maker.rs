use std::{fs, path::PathBuf};

use crate::config_utils;

use crate::{
    plugin::{Plugin, PluginInfo, PluginReplace},
    plugin_system::{get_plugin_config_schema, PluginConfigField},
    utils::{message_dialog, JETBRAINS_MONO_FONT},
};
use crate::{style, ShellcodeSaveType};
use anyhow::{anyhow, bail};
use dirs::{data_dir, desktop_dir, home_dir};
use iced::{
    alignment::{Horizontal, Vertical},
    event::{self, Event},
    futures::TryFutureExt,
    keyboard::{self, Key},
    widget::{
        button, checkbox, column, horizontal_rule, pick_list, radio, row, scrollable, svg::Handle,
        text, text_editor, text_input, Column, Svg,
    },
    window, Length, Subscription, Task, Theme,
};
use memchr::memmem;
use rfd::{AsyncFileDialog, MessageLevel};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ChooseFileType {
    WindowsExe,
    WindowsLib,
    LinuxExe,
    LinuxLib,
    DarwinExe,
    DarwinLib,
    MegaPluginWasm,
}

#[derive(Debug, Clone)]
pub struct GeneratedPluginResult {
    pub plugin_name: String,
    pub plugin_bytes: Vec<u8>,
    pub saved_path: String,
    pub preflight_report: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MakerPersistedState {
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
    mega_plugin_wasm: String,
    plugin_config: Vec<(String, String)>,
    desc: String,
    current_file_path: Option<String>,
    recent_files: Vec<String>,
    #[serde(default = "maker_defaults_on_open")]
    apply_schema_defaults_on_open: bool,
}

fn maker_defaults_on_open() -> bool {
    true
}

pub type SchemaLoadResult = Result<(String, Vec<(String, String)>, Vec<PluginConfigField>), String>;

#[derive(Debug, Clone)]
pub enum MakerMessage {
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
    MegaPluginWasmChanged(String),
    ConfigKeyChanged(usize, String),
    ConfigValueChanged(usize, String),
    ConfigBrowseClicked(usize),
    ConfigBrowseDone(usize, Option<String>),
    ApplySchemaDefaultsOnOpenChanged(bool),
    AddConfigRow,
    RemoveConfigRow(usize),
    DescAction(text_editor::Action),
    GenerateClicked,
    GenerateDone(Result<GeneratedPluginResult, String>),
    ChooseFileClicked(ChooseFileType),
    ChooseFileDone((Option<String>, ChooseFileType)),
    MegaPluginSchemaLoaded(SchemaLoadResult),
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
pub struct Maker {
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
    mega_plugin_wasm: String,
    plugin_config: Vec<(String, String)>,
    plugin_config_schema: Vec<PluginConfigField>,
    apply_schema_defaults_on_open: bool,
    desc: text_editor::Content,
    pumpbin_version: String,
    selected_theme: Theme,
    current_file_path: Option<String>,
    // Recent files
    recent_files: Vec<String>,
}

impl Maker {
    fn schema_field_for_key<'a>(
        schema: &'a [PluginConfigField],
        key: &str,
    ) -> Option<&'a PluginConfigField> {
        schema.iter().find(|f| f.key == key)
    }

    fn schema_field(&self, key: &str) -> Option<&PluginConfigField> {
        Self::schema_field_for_key(&self.plugin_config_schema, key)
    }

    fn plugin_schema_fields(plugin: &Plugin) -> Vec<PluginConfigField> {
        for wasm in plugin.plugins().modules() {
            if let Ok(Some(schema)) = get_plugin_config_schema(wasm) {
                return schema.fields;
            }
        }

        let wasm = plugin
            .plugins()
            .encrypt_shellcode()
            .or(plugin.plugins().format_encrypted_shellcode())
            .or(plugin.plugins().format_url_remote())
            .or(plugin.plugins().upload_final_shellcode_remote());

        if let Some(wasm) = wasm {
            if let Ok(Some(schema)) = get_plugin_config_schema(wasm) {
                return schema.fields;
            }
        }

        Vec::new()
    }

    fn merge_config_with_schema(
        config: &[(String, String)],
        schema: &[PluginConfigField],
        apply_defaults_on_open: bool,
    ) -> Vec<(String, String)> {
        config_utils::merge_config_with_schema(config, schema, apply_defaults_on_open)
    }

    fn load_schema_task(path: String) -> Task<MakerMessage> {
        let load_schema = async move {
            // v2.0.0: WASM schema loading was removed with the Extism
            // runtime. The maker GUI is frozen until the CLI rewrite
            // lands; this stub keeps the code path compilable.
            let _ = fs::read(&path);
            let schema = get_plugin_config_schema("")
                .map_err(|e| format!("Failed to parse plugin_schema: {}", e))?
                .unwrap_or_default();
            let defaults = schema
                .fields
                .iter()
                .filter(|f| !f.key.trim().is_empty())
                .map(|f| (f.key.clone(), f.default.clone().unwrap_or_default()))
                .collect::<Vec<_>>();

            Ok((path, defaults, schema.fields))
        };

        Task::perform(load_schema, MakerMessage::MegaPluginSchemaLoaded)
    }

    fn maybe_expand_home_path(value: &str) -> PathBuf {
        config_utils::maybe_expand_home_path(value)
    }

    fn config_key_is_file_like(key: &str) -> bool {
        config_utils::config_key_is_file_like(key)
    }

    fn config_errors(&self) -> Vec<String> {
        self.plugin_config
            .iter()
            .filter_map(|(key, value)| {
                Self::config_value_error(self.schema_field(key), key, value)
                    .map(|e| format!("{}: {}", key, e))
            })
            .collect()
    }

    fn config_value_error(
        field: Option<&PluginConfigField>,
        key: &str,
        value: &str,
    ) -> Option<String> {
        config_utils::config_value_error(field, key, value)
    }

    fn portable_plugin_config(
        entries: &[(String, String)],
        schema: &[PluginConfigField],
    ) -> Vec<(String, String)> {
        config_utils::sanitize_config(entries, schema)
    }

    fn state_file_path() -> Option<PathBuf> {
        let mut base = data_dir()?;
        base.push("PumpBin");
        if fs::create_dir_all(&base).is_err() {
            return None;
        }
        base.push("maker_state.json");
        Some(base)
    }

    fn to_persisted_state(&self) -> MakerPersistedState {
        MakerPersistedState {
            plugin_name: self.plugin_name.clone(),
            author: self.author.clone(),
            version: self.version.clone(),
            src_prefix: self.src_prefix.clone(),
            max_len: self.max_len.clone(),
            shellcode_save_type: self.shellcode_save_type,
            size_holder: self.size_holder.clone(),
            windows_exe: self.windows_exe.clone(),
            windows_lib: self.windows_lib.clone(),
            linux_exe: self.linux_exe.clone(),
            linux_lib: self.linux_lib.clone(),
            darwin_exe: self.darwin_exe.clone(),
            darwin_lib: self.darwin_lib.clone(),
            mega_plugin_wasm: self.mega_plugin_wasm.clone(),
            plugin_config: self.plugin_config.clone(),
            desc: self.desc.text(),
            current_file_path: self.current_file_path.clone(),
            recent_files: self.recent_files.clone(),
            apply_schema_defaults_on_open: self.apply_schema_defaults_on_open,
        }
    }

    fn apply_persisted_state(&mut self, state: MakerPersistedState) {
        self.plugin_name = state.plugin_name;
        self.author = state.author;
        self.version = state.version;
        self.src_prefix = state.src_prefix;
        self.max_len = state.max_len;
        self.shellcode_save_type = state.shellcode_save_type;
        self.size_holder = state.size_holder;
        self.windows_exe = state.windows_exe;
        self.windows_lib = state.windows_lib;
        self.linux_exe = state.linux_exe;
        self.linux_lib = state.linux_lib;
        self.darwin_exe = state.darwin_exe;
        self.darwin_lib = state.darwin_lib;
        self.mega_plugin_wasm = state.mega_plugin_wasm;
        self.plugin_config = state.plugin_config;
        self.desc = text_editor::Content::with_text(&state.desc);
        self.current_file_path = state.current_file_path;
        self.recent_files = state.recent_files;
        self.apply_schema_defaults_on_open = state.apply_schema_defaults_on_open;
    }

    fn load_state(&mut self) {
        let Some(path) = Self::state_file_path() else {
            return;
        };

        let Ok(raw) = fs::read_to_string(path) else {
            return;
        };

        let Ok(state) = serde_json::from_str::<MakerPersistedState>(&raw) else {
            return;
        };

        self.apply_persisted_state(state);
    }

    fn save_state(&self) {
        let Some(path) = Self::state_file_path() else {
            return;
        };

        let Ok(raw) = serde_json::to_string_pretty(&self.to_persisted_state()) else {
            return;
        };

        let _ = crate::utils::atomic_write(&path, raw.as_bytes());
    }

    // v1.1.13: The synchronous preflight_binary + preflight_readiness_report
    // pair was removed. Their fs::read of every platform binary blocked the
    // Iced runtime on large templates. The preflight check is now inlined in
    // the MakerMessage::GenerateClicked async block (search for
    // "plugin.replace.preflight_template" in this file), which already reads
    // each binary for the actual encode step — so removing the sync pre-check
    // also eliminates a redundant double-read.
    //
    // PB-E0019 (MakerPreflightFailed) is no longer produced; per-file
    // preflight now surfaces as anyhow with the template path on the
    // generate failure path. PB-E0019 is reserved in error.rs for
    // backward compatibility with downstream consumers that match on it.

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
        self.mega_plugin_wasm.clear();
        self.plugin_config_schema = Self::plugin_schema_fields(&plugin);
        self.plugin_config = Self::merge_config_with_schema(
            plugin.plugins().plugin_config(),
            &self.plugin_config_schema,
            self.apply_schema_defaults_on_open,
        );
        self.save_state();
    }

    fn reset_to_new(&mut self) {
        *self = Self {
            current_file_path: None,
            recent_files: self.recent_files.clone(), // Keep recent files
            ..Default::default()
        };
        self.save_state();
    }

    fn add_recent_file(&mut self, path: String) {
        // LRU dedup: drop any existing entry for this path before
        // re-inserting at the front. Bumped from cap 10 to
        // crate::RECENT_FILES_CAP (20) in v1.1.10.
        self.recent_files.retain(|p| p != &path);
        self.recent_files.insert(0, path);
        self.recent_files.truncate(crate::RECENT_FILES_CAP);
        self.save_state();
    }

    /// Returns (has_prefix, has_size_holder) for a binary path.
    /// Returns None if the path is empty or the file can't be read.
    fn binary_placeholder_status(&self, path: &str) -> Option<(bool, bool)> {
        if path.trim().is_empty() {
            return None;
        }
        let data = fs::read(path.trim()).ok()?;
        let src_prefix = self.src_prefix.trim().as_bytes();
        let has_prefix = memmem::find(&data, src_prefix).is_some();
        let has_size_holder = match self.shellcode_save_type() {
            ShellcodeSaveType::Local => {
                let holder = self.size_holder.trim().as_bytes();
                memmem::find(&data, holder).is_some()
            }
            ShellcodeSaveType::Remote => true,
        };
        Some((has_prefix, has_size_holder))
    }

    fn check_generate(&self) -> anyhow::Result<()> {
        use crate::error::PumpBinError;

        if self.plugin_name.is_empty() {
            return Err(PumpBinError::MakerFieldEmpty {
                field: "plugin_name",
            }
            .into());
        }

        if self.src_prefix.is_empty() {
            return Err(PumpBinError::MakerFieldEmpty {
                field: "src_prefix",
            }
            .into());
        }

        let max_len = self.max_len();
        if max_len.is_empty() {
            return Err(PumpBinError::MakerMaxLenInvalid { reason: "empty" }.into());
        }

        let Ok(max_len_num) = max_len.parse::<usize>() else {
            return Err(PumpBinError::MakerMaxLenInvalid {
                reason: "not a non-negative integer",
            }
            .into());
        };

        if max_len_num == 0 {
            return Err(PumpBinError::MakerMaxLenInvalid {
                reason: "must be greater than zero",
            }
            .into());
        }

        if let ShellcodeSaveType::Local = self.shellcode_save_type() {
            if self.size_holder().trim().is_empty() {
                return Err(PumpBinError::MakerFieldEmpty {
                    field: "size_holder",
                }
                .into());
            }

            if self.size_holder().trim() == self.src_prefix().trim() {
                return Err(PumpBinError::MakerSourcePrefixCollision.into());
            }
        };

        let cfg_errors = self.config_errors();
        if !cfg_errors.is_empty() {
            bail!(
                "Module Config has {} invalid entr{}:\n{}",
                cfg_errors.len(),
                if cfg_errors.len() == 1 { "y" } else { "ies" },
                cfg_errors.join("\n")
            );
        }

        anyhow::Ok(())
    }
}

impl Default for Maker {
    fn default() -> Self {
        let mut maker = Self {
            plugin_name: "first_plugin".to_string(),
            author: "researcher".to_string(),
            version: "1.0.0".to_string(),
            src_prefix: "$$SHELLCODE$$".to_string(),
            max_len: "1048589".to_string(),
            shellcode_save_type: ShellcodeSaveType::Local,
            size_holder: "$$99999$$".to_string(),
            windows_exe: Default::default(),
            windows_lib: Default::default(),
            linux_exe: Default::default(),
            linux_lib: Default::default(),
            darwin_exe: Default::default(),
            darwin_lib: Default::default(),
            mega_plugin_wasm: Default::default(),
            plugin_config: Vec::new(),
            plugin_config_schema: Vec::new(),
            apply_schema_defaults_on_open: true,
            desc: text_editor::Content::new(),
            pumpbin_version: env!("CARGO_PKG_VERSION").into(),
            selected_theme: Theme::CatppuccinMacchiato,
            current_file_path: None,
            recent_files: Vec::new(),
        };

        maker.load_state();
        maker
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

    fn mega_plugin_wasm(&self) -> &str {
        &self.mega_plugin_wasm
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
        let mut should_persist = false;

        match message {
            MakerMessage::PluginNameChanged(x) => {
                self.plugin_name = x;
                should_persist = true;
            }
            MakerMessage::AuthorChanged(x) => {
                self.author = x;
                should_persist = true;
            }
            MakerMessage::VersionChanged(x) => {
                self.version = x;
                should_persist = true;
            }
            MakerMessage::SrcPrefixChanged(x) => {
                self.src_prefix = x;
                should_persist = true;
            }
            MakerMessage::MaxLenChanged(x) => {
                self.max_len = x;
                should_persist = true;
            }
            MakerMessage::ShellcodeSaveTypeChanged(x) => {
                self.shellcode_save_type = x;
                should_persist = true;
            }
            MakerMessage::SizeHolderChanged(x) => {
                self.size_holder = x;
                should_persist = true;
            }
            MakerMessage::WindowsExeChanged(x) => {
                self.windows_exe = x;
                should_persist = true;
            }
            MakerMessage::WindowsLibChanged(x) => {
                self.windows_lib = x;
                should_persist = true;
            }
            MakerMessage::LinuxExeChanged(x) => {
                self.linux_exe = x;
                should_persist = true;
            }
            MakerMessage::LinuxLibChanged(x) => {
                self.linux_lib = x;
                should_persist = true;
            }
            MakerMessage::DarwinExeChanged(x) => {
                self.darwin_exe = x;
                should_persist = true;
            }
            MakerMessage::DarwinLibChanged(x) => {
                self.darwin_lib = x;
                should_persist = true;
            }
            MakerMessage::MegaPluginWasmChanged(x) => {
                self.mega_plugin_wasm = x.clone();
                should_persist = true;

                let candidate = Self::maybe_expand_home_path(x.trim());
                if candidate.is_file() {
                    self.save_state();
                    return Self::load_schema_task(candidate.to_string_lossy().to_string());
                }
            }
            MakerMessage::ConfigKeyChanged(idx, x) => {
                if let Some((key, _)) = self.plugin_config.get_mut(idx) {
                    *key = x;
                    should_persist = true;
                }
            }
            MakerMessage::ConfigValueChanged(idx, x) => {
                if let Some((_, value)) = self.plugin_config.get_mut(idx) {
                    *value = x;
                    should_persist = true;
                }
            }
            MakerMessage::ConfigBrowseClicked(idx) => {
                let choose_file = async move {
                    let file = AsyncFileDialog::new()
                        .set_directory(home_dir().unwrap_or(".".into()))
                        .set_title("Choose config file")
                        .pick_file()
                        .await
                        .map(|x| x.path().to_string_lossy().to_string());

                    (idx, file)
                };

                return Task::perform(choose_file, |(idx, path)| {
                    MakerMessage::ConfigBrowseDone(idx, path)
                });
            }
            MakerMessage::ConfigBrowseDone(idx, path) => {
                if let (Some((_, value)), Some(path)) = (self.plugin_config.get_mut(idx), path) {
                    *value = path;
                    should_persist = true;
                }
            }
            MakerMessage::ApplySchemaDefaultsOnOpenChanged(value) => {
                self.apply_schema_defaults_on_open = value;
                should_persist = true;
            }
            MakerMessage::AddConfigRow => {
                self.plugin_config.push((String::new(), String::new()));
                should_persist = true;
            }
            MakerMessage::RemoveConfigRow(idx) => {
                if idx < self.plugin_config.len() {
                    self.plugin_config.remove(idx);
                    should_persist = true;
                }
            }
            MakerMessage::DescAction(x) => {
                self.desc_mut().perform(x);
                should_persist = true;
            }
            MakerMessage::GenerateClicked => {
                eprintln!("[maker] GenerateClicked");
                if let Err(e) = self.check_generate() {
                    eprintln!("[maker] check_generate failed: {e}");
                    let _ = message_dialog(e.to_string(), MessageLevel::Error);
                    return Task::none();
                }
                eprintln!("[maker] check_generate passed");

                // v1.1.13: preflight moved into the async block below so
                // its fs::read of every platform binary doesn't freeze the
                // UI on large templates. The save dialog is launched
                // *after* preflight passes (still inside the async block);
                // failure still surfaces via message_dialog through the
                // existing GenerateDone Err path. Pre-v1.1.13 preflight
                // ran here synchronously, blocking the Iced runtime for
                // the duration of every read.
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
                    (self.mega_plugin_wasm(), ChooseFileType::MegaPluginWasm),
                ]
                .into_iter()
                .map(|(x, y)| (x.to_string(), y))
                .collect();

                let plugin_config =
                    Self::portable_plugin_config(&self.plugin_config, &self.plugin_config_schema);

                let make_plugin = async move {
                    plugin.plugins.plugin_config = plugin_config;
                    let mut preflight_lines: Vec<String> =
                        vec!["PumpBin Maker preflight:".to_string()];

                    for (path_str, file_type) in paths {
                        if !path_str.is_empty() {
                            let path = PathBuf::from(path_str);
                            let data = fs::read(&path)?;

                            // Only binary templates (not WASM modules) need preflight.
                            // Delegates to Plugin::PluginReplace::preflight_template so the
                            // CLI's create-b1n subcommand and the Maker GUI enforce the
                            // exact same template requirements. v1.1.13: preflight is now
                            // ONLY here (inside the async Task) so its fs::read doesn't
                            // freeze the UI on large templates; the pre-1.1.13 sync call
                            // before this async block was redundant with this one.
                            if file_type != ChooseFileType::MegaPluginWasm {
                                plugin.replace.preflight_template(&data).map_err(|e| {
                                    anyhow!("Template at '{}': {}", path.display(), e)
                                })?;
                                preflight_lines.push(format!("  {:?}: READY", file_type));
                            }

                            match file_type {
                                ChooseFileType::WindowsExe => {
                                    *plugin.bins.windows.executable_mut() = Some(data)
                                }
                                ChooseFileType::WindowsLib => {
                                    *plugin.bins.windows.dynamic_library_mut() = Some(data)
                                }
                                ChooseFileType::LinuxExe => {
                                    *plugin.bins.linux.executable_mut() = Some(data)
                                }
                                ChooseFileType::LinuxLib => {
                                    *plugin.bins.linux.dynamic_library_mut() = Some(data)
                                }
                                ChooseFileType::DarwinExe => {
                                    *plugin.bins.darwin.executable_mut() = Some(data)
                                }
                                ChooseFileType::DarwinLib => {
                                    *plugin.bins.darwin.dynamic_library_mut() = Some(data)
                                }
                                ChooseFileType::MegaPluginWasm => {
                                    // v2.0.0: the slot now stores a
                                    // native module id, not WASM bytes.
                                    // The maker GUI is frozen pending
                                    // CLI rewrite; this stub preserves
                                    // the historical behavior shape.
                                    let id = String::from_utf8_lossy(&data).to_string();
                                    plugin.plugins.modules_mut().push(id);
                                }
                            }
                        }
                    }

                    // All PumpBin plugins should have .b1n extension regardless of binary type
                    let plugin_name = plugin.info().plugin_name();
                    let filename = format!("{}.b1n", plugin_name);

                    // Provide user feedback about what binary types are included
                    let binary_types = [
                        (plugin.bins.windows.executable().is_some(), "Windows .exe"),
                        (plugin.bins.linux.executable().is_some(), "Linux executable"),
                        (
                            plugin.bins.darwin.executable().is_some(),
                            "macOS executable",
                        ),
                        (
                            plugin.bins.windows.dynamic_library().is_some(),
                            "Windows .dll",
                        ),
                        (plugin.bins.linux.dynamic_library().is_some(), "Linux .so"),
                        (
                            plugin.bins.darwin.dynamic_library().is_some(),
                            "macOS .dylib",
                        ),
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

                    let plugin_bytes = plugin.encode_to_vec()?;
                    crate::utils::atomic_write(file.path(), plugin_bytes.as_slice())?;

                    anyhow::Ok(GeneratedPluginResult {
                        plugin_name: plugin_name.to_string(),
                        plugin_bytes,
                        saved_path: file.path().to_string_lossy().to_string(),
                        preflight_report: preflight_lines.join("\n"),
                    })
                }
                .map_err(|e| e.to_string());

                return Task::perform(make_plugin, MakerMessage::GenerateDone);
            }
            MakerMessage::GenerateDone(x) => {
                eprintln!(
                    "[maker] GenerateDone: {:?}",
                    x.as_ref().map(|r| &r.saved_path)
                );
                match x {
                    Ok(result) => {
                        self.current_file_path = Some(result.saved_path.clone());
                        self.add_recent_file(result.saved_path.clone());
                        // Note: not setting should_persist=true here because
                        // we immediately `return` — the persist-on-fall-through
                        // path at the bottom of update() would never see it.
                        // add_recent_file + current_file_path mutation is
                        // already enough for the next Generate to find the
                        // right state.
                        return message_dialog(
                            format!(
                                "Generate done.\nSaved: {}\n\n{}",
                                result.saved_path, result.preflight_report
                            ),
                            MessageLevel::Info,
                        )
                        .discard();
                    }
                    Err(e) => {
                        eprintln!("[maker] GenerateDone error: {e}");
                        return message_dialog(e, MessageLevel::Error).discard();
                    }
                };
            }
            MakerMessage::OpenB1nClicked => {
                let open_file = async move {
                    let file = AsyncFileDialog::new()
                        .set_directory(home_dir().unwrap_or(".".into()))
                        .set_title("Open .b1n plugin pack")
                        .add_filter("PumpBin Plugin", &["b1n"])
                        .pick_file()
                        .await
                        .map(|x| x.path().to_string_lossy().to_string());

                    match file {
                        Some(path) => match std::fs::read(&path) {
                            Ok(data) => match Plugin::decode_from_slice(&data) {
                                Ok(_plugin) => Ok(path),
                                Err(e) => Err(format!("Failed to parse plugin file: {}", e)),
                            },
                            Err(e) => Err(format!("Failed to read file: {}", e)),
                        },
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
                                should_persist = true;
                                let _ = message_dialog(
                                    format!("Plugin pack loaded successfully from: {}", path),
                                    MessageLevel::Info,
                                );
                            } else {
                                let _ = message_dialog(
                                    "Failed to parse plugin file".to_string(),
                                    MessageLevel::Error,
                                );
                            }
                        } else {
                            let _ = message_dialog(
                                "Failed to read plugin file".to_string(),
                                MessageLevel::Error,
                            );
                        }
                    }
                    Err(e) => {
                        let _ = message_dialog(e, MessageLevel::Error);
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
                        should_persist = true;
                        let _ = message_dialog(
                            format!("Plugin pack loaded successfully from: {}", path),
                            MessageLevel::Info,
                        );
                    } else {
                        let _ = message_dialog(
                            "Failed to parse plugin file".to_string(),
                            MessageLevel::Error,
                        );
                    }
                } else {
                    let _ = message_dialog(
                        "Failed to read plugin file".to_string(),
                        MessageLevel::Error,
                    );
                }
            }
            MakerMessage::NewPluginClicked => {
                // Reset all fields to default
                self.reset_to_new();
                should_persist = true;
                let _ = message_dialog(
                    "New plugin created. All fields have been reset.".to_string(),
                    MessageLevel::Info,
                );
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
                        ChooseFileType::MegaPluginWasm => {
                            self.mega_plugin_wasm = path.clone();
                            self.save_state();
                            return Self::load_schema_task(path);
                        }
                    }
                    should_persist = true;
                }
            }
            MakerMessage::MegaPluginSchemaLoaded(result) => match result {
                Ok((wasm_path, defaults, schema_fields)) => {
                    let normalized_current =
                        Self::maybe_expand_home_path(self.mega_plugin_wasm.trim())
                            .to_string_lossy()
                            .to_string();
                    if self.mega_plugin_wasm == wasm_path || normalized_current == wasm_path {
                        self.plugin_config_schema = schema_fields;
                        self.plugin_config = Self::merge_config_with_schema(
                            &defaults,
                            &self.plugin_config_schema,
                            self.apply_schema_defaults_on_open,
                        );
                        should_persist = true;
                    }
                }
                Err(e) => {
                    let _ = message_dialog(e, MessageLevel::Error);
                }
            },
            MakerMessage::B1nClicked => {
                if open::that(env!("CARGO_PKG_HOMEPAGE")).is_err() {
                    let _ = message_dialog("Open home failed.".into(), MessageLevel::Error);
                }
            }
            MakerMessage::GithubClicked => {
                if open::that(env!("CARGO_PKG_REPOSITORY")).is_err() {
                    let _ = message_dialog("Open repo failed.".into(), MessageLevel::Error);
                }
            }
            MakerMessage::ThemeChanged(x) => {
                self.selected_theme = x;
                should_persist = true;
            }
            MakerMessage::KeyboardEvent(event) => {
                if let Event::Keyboard(keyboard::Event::KeyPressed { key, modifiers, .. }) = event {
                    match key {
                        Key::Named(keyboard::key::Named::Tab) => {
                            // Tab navigation is handled by the framework automatically
                        }
                        Key::Character(ch) if modifiers.control() => match ch.as_str() {
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
                        },
                        _ => {}
                    }
                }
            }
            MakerMessage::FilesDropped(paths) => {
                for path in paths {
                    let ext = path
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("")
                        .to_lowercase();
                    let path_str = path.to_string_lossy().to_string();
                    match ext.as_str() {
                        "b1n" => {
                            return self.update(MakerMessage::OpenB1nDone(Ok(path_str)));
                        }
                        "exe" => {
                            self.windows_exe = path_str;
                            should_persist = true;
                        }
                        "dll" => {
                            self.windows_lib = path_str;
                            should_persist = true;
                        }
                        "so" => {
                            self.linux_lib = path_str;
                            should_persist = true;
                        }
                        "dylib" => {
                            self.darwin_lib = path_str;
                            should_persist = true;
                        }
                        "wasm" => {
                            self.mega_plugin_wasm = path_str.clone();
                            self.save_state();
                            return Self::load_schema_task(path_str);
                        }
                        _ => {
                            // Unknown extension: try to assign as Linux exe (most common
                            // ELF executables have no extension), otherwise inform user.
                            if ext.is_empty() {
                                // No extension — heuristic: assign as Linux exe if empty
                                self.linux_exe = path_str;
                                should_persist = true;
                            } else {
                                let _ = message_dialog(
                                    format!(
                                        "Unknown file type '.{}'. Drag .exe → Windows Exe, .dll → Windows Lib, .so → Linux Lib, .dylib → Darwin Lib, .wasm → Module, no extension → Linux Exe.",
                                        ext
                                    ),
                                    MessageLevel::Info,
                                );
                            }
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
                    ChooseFileType::MegaPluginWasm => {
                        self.mega_plugin_wasm = path_str.clone();
                        self.save_state();
                        let _ = message_dialog(
                            format!(
                                "File set: {}",
                                path.file_name().unwrap_or_default().to_string_lossy()
                            ),
                            MessageLevel::Info,
                        );

                        return Self::load_schema_task(path_str);
                    }
                }
                should_persist = true;
                let _ = message_dialog(
                    format!(
                        "File set: {}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ),
                    MessageLevel::Info,
                );
            }
        }

        if should_persist {
            self.save_state();
        }

        Task::none()
    }

    fn render_config_rows(&self) -> iced::widget::Column<'_, MakerMessage> {
        column(
            self.plugin_config
                .iter()
                .enumerate()
                .map(|(idx, (key, value))| {
                    let field = self.schema_field(key);
                    let mut config_row = row![].spacing(8).align_y(Vertical::Center);

                    if let Some(schema_field) = field {
                        let tag = if schema_field.required {
                            "required"
                        } else {
                            "optional"
                        };
                        let mut label_col = column![text(format!("{} ({})", key, tag))];
                        if !schema_field.description.is_empty() {
                            label_col =
                                label_col.push(text(&schema_field.description).size(11).style(
                                    |theme: &Theme| {
                                        let mut c = theme.palette().text;
                                        c.a = 0.55;
                                        text::Style { color: Some(c) }
                                    },
                                ));
                        }
                        config_row = config_row.push(label_col.width(Length::FillPortion(2)));
                    } else {
                        config_row = config_row.push(
                            text_input("key", key)
                                .on_input(move |x| MakerMessage::ConfigKeyChanged(idx, x))
                                .width(Length::FillPortion(2)),
                        );
                    }

                    match field.map(|f| f.field_type.as_str()) {
                        Some("choice") => {
                            let options = field.map(|f| f.options.clone()).unwrap_or_default();
                            let selected = options.contains(value).then(|| value.clone());
                            config_row = config_row.push(
                                pick_list(options, selected, move |choice| {
                                    MakerMessage::ConfigValueChanged(idx, choice)
                                })
                                .width(Length::FillPortion(3)),
                            );
                        }
                        Some("boolean") => {
                            let options = vec!["true".to_string(), "false".to_string()];
                            let normalized = value.to_ascii_lowercase();
                            let selected = (normalized == "true" || normalized == "false")
                                .then_some(normalized);
                            config_row = config_row.push(
                                pick_list(options, selected, move |choice| {
                                    MakerMessage::ConfigValueChanged(idx, choice)
                                })
                                .width(Length::FillPortion(3)),
                            );
                        }
                        _ => {
                            config_row = config_row.push(
                                text_input("value", value)
                                    .on_input(move |x| MakerMessage::ConfigValueChanged(idx, x))
                                    .width(Length::FillPortion(3)),
                            );
                        }
                    }

                    if field
                        .map(|f| {
                            f.field_type.eq_ignore_ascii_case("file")
                                || f.field_type.eq_ignore_ascii_case("file_base64")
                                || f.field_type.eq_ignore_ascii_case("file_path")
                        })
                        .unwrap_or_else(|| Self::config_key_is_file_like(key))
                    {
                        config_row = config_row.push(
                            button("Browse").on_press(MakerMessage::ConfigBrowseClicked(idx)),
                        );
                    }

                    config_row =
                        config_row.push(button("X").on_press(MakerMessage::RemoveConfigRow(idx)));

                    let mut entry = column![config_row].spacing(2);
                    if let Some(err) = Self::config_value_error(field, key, value) {
                        entry = entry.push(text(err).size(11).style(|theme: &Theme| text::Style {
                            color: Some(theme.extended_palette().danger.base.color),
                        }));
                    }

                    entry.into()
                })
                .collect::<Vec<_>>(),
        )
        .spacing(6)
    }

    pub fn view(&self) -> Column<'_, MakerMessage> {
        // Helper closure: renders a colored status indicator for a binary slot
        let binary_status_text = |path: &str| -> iced::widget::Text<'static> {
            match self.binary_placeholder_status(path) {
                None => text("—").style(|theme: &Theme| text::Style {
                    color: Some(theme.extended_palette().background.strong.text),
                }),
                Some((true, true)) => text("✓").style(|theme: &Theme| text::Style {
                    color: Some(theme.extended_palette().success.base.color),
                }),
                Some((true, false)) => {
                    text("⚠ missing size holder").style(|theme: &Theme| text::Style {
                        color: Some(theme.extended_palette().danger.base.color),
                    })
                }
                Some((false, _)) => text("⚠ missing prefix").style(|theme: &Theme| text::Style {
                    color: Some(theme.extended_palette().danger.base.color),
                }),
            }
        };

        let choose_button = || {
            button(
                Svg::new(Handle::from_memory(include_bytes!(
                    "../assets/svg/three-dots.svg"
                )))
                .width(20),
            )
            .style(style::button::secondary)
        };

        let plugin_config_rows = self.render_config_rows();
        let config_errors = self.config_errors();

        let maker = column![
            column![
                text("Maker Workspace")
                    .size(22)
                    .font(JETBRAINS_MONO_FONT)
                    .style(|theme: &Theme| text::Style {
                        color: Some(theme.extended_palette().primary.base.color),
                    }),
                horizontal_rule(0),
            ]
            .spacing(6),
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
                        text(path).size(12).style(|theme: &Theme| text::Style {
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
                            self.recent_files
                                .iter()
                                .take(10)
                                .map(|path| {
                                    let p = std::path::Path::new(path);
                                    let basename = p
                                        .file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy()
                                        .to_string();
                                    let parent = p
                                        .parent()
                                        .and_then(|pp| pp.file_name())
                                        .map(|pp| pp.to_string_lossy().to_string())
                                        .unwrap_or_default();
                                    let label = if parent.is_empty() {
                                        basename
                                    } else {
                                        format!("{} ({})", basename, parent)
                                    };
                                    let display = if label.len() > 50 {
                                        format!("{}...", &label[..47])
                                    } else {
                                        label
                                    };
                                    button(
                                        row![text("📄"), text(display).size(12)]
                                            .spacing(5)
                                            .align_y(Vertical::Center),
                                    )
                                    .style(button::text)
                                    .on_press(MakerMessage::OpenRecentFile(path.clone()))
                                    .into()
                                })
                                .collect::<Vec<_>>()
                        )
                        .spacing(2)
                    ]
                    .spacing(5)
                } else {
                    column![]
                }
            ]
            .spacing(5),
            text("General").font(JETBRAINS_MONO_FONT).size(14),
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
            text("Template Binaries").font(JETBRAINS_MONO_FONT).size(14),
            column![
                text("Windows"),
                row![
                    text("Exe:"),
                    text_input("windows.exe", self.windows_exe())
                        .on_input(MakerMessage::WindowsExeChanged),
                    choose_button()
                        .on_press(MakerMessage::ChooseFileClicked(ChooseFileType::WindowsExe)),
                    binary_status_text(self.windows_exe()),
                    text("Lib:"),
                    text_input("windows.dll", self.windows_lib())
                        .on_input(MakerMessage::WindowsLibChanged),
                    choose_button()
                        .on_press(MakerMessage::ChooseFileClicked(ChooseFileType::WindowsLib)),
                    binary_status_text(self.windows_lib()),
                ]
                .align_y(Vertical::Center)
                .spacing(10)
            ]
            .align_x(Horizontal::Left),
            column![
                text("Linux"),
                row![
                    text("Exe:"),
                    text_input("linux executable", self.linux_exe())
                        .on_input(MakerMessage::LinuxExeChanged),
                    choose_button()
                        .on_press(MakerMessage::ChooseFileClicked(ChooseFileType::LinuxExe)),
                    binary_status_text(self.linux_exe()),
                    text("Lib:"),
                    text_input("linux.so", self.linux_lib())
                        .on_input(MakerMessage::LinuxLibChanged),
                    choose_button()
                        .on_press(MakerMessage::ChooseFileClicked(ChooseFileType::LinuxLib)),
                    binary_status_text(self.linux_lib()),
                ]
                .align_y(Vertical::Center)
                .spacing(10)
            ]
            .align_x(Horizontal::Left),
            column![
                text("Darwin"),
                row![
                    text("Exe:"),
                    text_input("macOS executable", self.darwin_exe())
                        .on_input(MakerMessage::DarwinExeChanged),
                    choose_button()
                        .on_press(MakerMessage::ChooseFileClicked(ChooseFileType::DarwinExe)),
                    binary_status_text(self.darwin_exe()),
                    text("Lib:"),
                    text_input("macOS.dylib", self.darwin_lib())
                        .on_input(MakerMessage::DarwinLibChanged),
                    choose_button()
                        .on_press(MakerMessage::ChooseFileClicked(ChooseFileType::DarwinLib)),
                    binary_status_text(self.darwin_lib()),
                ]
                .align_y(Vertical::Center)
                .spacing(10)
            ]
            .align_x(Horizontal::Left),
            text("WASM Pipeline").font(JETBRAINS_MONO_FONT).size(14),
            column![
                text("Module (.wasm)"),
                row![
                    text_input("module.wasm", self.mega_plugin_wasm())
                        .on_input(MakerMessage::MegaPluginWasmChanged),
                    choose_button().on_press(MakerMessage::ChooseFileClicked(
                        ChooseFileType::MegaPluginWasm
                    ))
                ]
                .align_y(Vertical::Center)
                .spacing(10),
                text("Module Config (required/optional)"),
                checkbox("Use defaults on open", self.apply_schema_defaults_on_open,)
                    .on_toggle(MakerMessage::ApplySchemaDefaultsOnOpenChanged),
                plugin_config_rows,
                if !config_errors.is_empty() {
                    text(format!(
                        "{} invalid config entr{}",
                        config_errors.len(),
                        if config_errors.len() == 1 { "y" } else { "ies" }
                    ))
                    .size(11)
                    .style(|theme: &Theme| text::Style {
                        color: Some(theme.extended_palette().danger.base.color),
                    })
                } else {
                    text("").size(1)
                },
                button("Add Row").on_press(MakerMessage::AddConfigRow),
            ]
            .align_x(Horizontal::Left)
            .spacing(8),
            column![
                text("Description"),
                text_editor(self.desc())
                    .on_action(MakerMessage::DescAction)
                    .height(150)
            ]
            .align_x(Horizontal::Left),
            column![row![button("Generate").on_press_maybe(
                if config_errors.is_empty() {
                    Some(MakerMessage::GenerateClicked)
                } else {
                    None
                }
            )]]
            .align_x(Horizontal::Center)
            .width(Length::Fill),
        ]
        .align_x(Horizontal::Left)
        .padding(20)
        .spacing(10);

        let footer = self.render_footer();

        column![scrollable(maker).height(Length::Fill), footer].align_x(Horizontal::Center)
    }

    fn render_footer(&self) -> iced::widget::Column<'_, MakerMessage> {
        let version = text(format!("PumpBin  v{}", self.pumpbin_version()))
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
        .on_press(MakerMessage::B1nClicked);

        let github = button(
            Svg::new(Handle::from_memory(include_bytes!(
                "../assets/svg/github.svg"
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

        column![
            horizontal_rule(0),
            row![
                column![version]
                    .width(Length::Fill)
                    .align_x(Horizontal::Left),
                column![row![b1n, github].align_y(Vertical::Center)]
                    .width(Length::Shrink)
                    .align_x(Horizontal::Center),
                column![theme_list]
                    .width(Length::Fill)
                    .align_x(Horizontal::Right)
            ]
            .padding([0, 20])
            .align_y(Vertical::Center)
        ]
        .align_x(Horizontal::Center)
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
