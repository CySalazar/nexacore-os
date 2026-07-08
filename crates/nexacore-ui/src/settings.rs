//! Settings / Control Center framework and panels (WS7-13).
//!
//! A typed settings framework whose panels bind to the config store (WS17):
//! each [`Setting`] declares a [`SettingKind`] constraint, [`Setting::set`]
//! validates before it mutates, and a [`SettingsPanel`] can [`SettingsPanel::load`]
//! its values from and [`SettingsPanel::commit`] them back to any [`ConfigStore`]
//! — the live read/write binding of WS7-13.1. The bundled [`audio_panel`],
//! [`power_panel`], and [`input_panel`] are concrete panels (WS7-13.2/.3/.4);
//! accessibility/users/updates/system-info panels follow the same shape.

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

/// A typed setting value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingValue {
    /// A boolean toggle.
    Toggle(bool),
    /// An integer within a range.
    Number(i64),
    /// A free-text value.
    Text(String),
    /// The index of the selected option in a [`SettingKind::Select`].
    Choice(usize),
}

/// The constraint a [`Setting`] enforces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingKind {
    /// A boolean toggle.
    Toggle,
    /// An integer in `[min, max]`.
    Range {
        /// Inclusive minimum.
        min: i64,
        /// Inclusive maximum.
        max: i64,
    },
    /// One of a fixed set of options (value is the index).
    Select {
        /// The selectable option labels.
        options: Vec<String>,
    },
    /// Free text.
    Text,
}

/// Why a setting value was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsError {
    /// The value's variant did not match the setting's kind.
    TypeMismatch,
    /// A number was outside the allowed range.
    OutOfRange,
    /// A choice index was outside the option list.
    BadChoice,
    /// A serialised value could not be parsed for its kind.
    Unparsable,
}

/// A single configurable setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// The config-store key (e.g. `audio.output.volume`).
    pub key: String,
    /// The human-readable label.
    pub label: String,
    /// The type/constraint.
    pub kind: SettingKind,
    /// The current value.
    pub value: SettingValue,
}

impl Setting {
    /// Whether `value` is valid for this setting's kind.
    ///
    /// # Errors
    /// [`SettingsError::TypeMismatch`] / [`SettingsError::OutOfRange`] /
    /// [`SettingsError::BadChoice`].
    pub fn validate(&self, value: &SettingValue) -> Result<(), SettingsError> {
        match (&self.kind, value) {
            (SettingKind::Toggle, SettingValue::Toggle(_))
            | (SettingKind::Text, SettingValue::Text(_)) => Ok(()),
            (SettingKind::Range { min, max }, SettingValue::Number(n)) => {
                if n >= min && n <= max {
                    Ok(())
                } else {
                    Err(SettingsError::OutOfRange)
                }
            }
            (SettingKind::Select { options }, SettingValue::Choice(i)) => {
                if *i < options.len() {
                    Ok(())
                } else {
                    Err(SettingsError::BadChoice)
                }
            }
            _ => Err(SettingsError::TypeMismatch),
        }
    }

    /// Validate and store `value`.
    ///
    /// # Errors
    /// As [`Setting::validate`].
    pub fn set(&mut self, value: SettingValue) -> Result<(), SettingsError> {
        self.validate(&value)?;
        self.value = value;
        Ok(())
    }

    /// The value serialised for the config store.
    #[must_use]
    pub fn serialize_value(&self) -> String {
        match &self.value {
            SettingValue::Toggle(b) => if *b { "true" } else { "false" }.to_string(),
            SettingValue::Number(n) => {
                let mut s = String::new();
                let mut num = *n;
                if num < 0 {
                    s.push('-');
                    num = -num;
                }
                s.push_str(itoa(num).as_str());
                s
            }
            SettingValue::Text(t) => t.clone(),
            SettingValue::Choice(i) => match &self.kind {
                SettingKind::Select { options } => options.get(*i).cloned().unwrap_or_default(),
                _ => String::new(),
            },
        }
    }

    /// Parse a stored string into this setting's value and store it.
    ///
    /// # Errors
    /// [`SettingsError::Unparsable`] if the text does not fit the kind, or a
    /// validation error.
    pub fn set_from_str(&mut self, raw: &str) -> Result<(), SettingsError> {
        let value = match &self.kind {
            SettingKind::Toggle => SettingValue::Toggle(raw == "true"),
            SettingKind::Range { .. } => {
                SettingValue::Number(raw.parse().map_err(|_| SettingsError::Unparsable)?)
            }
            SettingKind::Text => SettingValue::Text(raw.to_string()),
            SettingKind::Select { options } => {
                let idx = options
                    .iter()
                    .position(|o| o == raw)
                    .ok_or(SettingsError::Unparsable)?;
                SettingValue::Choice(idx)
            }
        };
        self.set(value)
    }
}

/// The config-store seam (WS17): live read/write by key.
pub trait ConfigStore {
    /// The stored value for `key`, if any.
    fn get(&self, key: &str) -> Option<String>;
    /// Store `value` under `key`.
    fn set(&mut self, key: &str, value: &str);
}

/// A titled group of settings — one Control Center panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsPanel {
    /// Panel identifier (e.g. `audio`).
    pub id: String,
    /// Panel title.
    pub title: String,
    /// The panel's settings.
    pub settings: Vec<Setting>,
}

impl SettingsPanel {
    /// Find a setting by key.
    #[must_use]
    pub fn find(&self, key: &str) -> Option<&Setting> {
        self.settings.iter().find(|s| s.key == key)
    }

    /// Validate and update the working value of the setting `key`.
    ///
    /// # Errors
    /// [`SettingsError::BadChoice`] if `key` is unknown (no such setting), or a
    /// validation error from [`Setting::set`].
    pub fn set(&mut self, key: &str, value: SettingValue) -> Result<(), SettingsError> {
        let setting = self
            .settings
            .iter_mut()
            .find(|s| s.key == key)
            .ok_or(SettingsError::BadChoice)?;
        setting.set(value)
    }

    /// Load each setting's value from `store` (WS7-13.1 live read). A missing or
    /// unparsable key leaves that setting at its default.
    pub fn load(&mut self, store: &impl ConfigStore) {
        for setting in &mut self.settings {
            if let Some(raw) = store.get(&setting.key) {
                let _ = setting.set_from_str(&raw);
            }
        }
    }

    /// Persist every setting to `store` (WS7-13.1 live write).
    pub fn commit(&self, store: &mut impl ConfigStore) {
        for setting in &self.settings {
            store.set(&setting.key, &setting.serialize_value());
        }
    }
}

/// Base-10 unsigned integer to string (`no_std`, no `format!`).
fn itoa(mut n: i64) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut digits = Vec::new();
    while n > 0 {
        digits.push(b'0' + u8::try_from(n % 10).unwrap_or(0));
        n /= 10;
    }
    digits.reverse();
    String::from_utf8(digits).unwrap_or_default()
}

fn toggle(key: &str, label: &str, on: bool) -> Setting {
    Setting {
        key: key.to_string(),
        label: label.to_string(),
        kind: SettingKind::Toggle,
        value: SettingValue::Toggle(on),
    }
}

fn range(key: &str, label: &str, min: i64, max: i64, value: i64) -> Setting {
    Setting {
        key: key.to_string(),
        label: label.to_string(),
        kind: SettingKind::Range { min, max },
        value: SettingValue::Number(value),
    }
}

fn select(key: &str, label: &str, options: &[&str], chosen: usize) -> Setting {
    Setting {
        key: key.to_string(),
        label: label.to_string(),
        kind: SettingKind::Select {
            options: options.iter().map(|o| (*o).to_string()).collect(),
        },
        value: SettingValue::Choice(chosen),
    }
}

/// The audio panel: output/input devices and volume (WS7-13.2).
#[must_use]
pub fn audio_panel(outputs: &[&str], inputs: &[&str]) -> SettingsPanel {
    SettingsPanel {
        id: "audio".to_string(),
        title: "Audio".to_string(),
        settings: vec![
            select("audio.output.device", "Output device", outputs, 0),
            range("audio.output.volume", "Output volume", 0, 100, 60),
            toggle("audio.output.mute", "Mute output", false),
            select("audio.input.device", "Input device", inputs, 0),
            range("audio.input.volume", "Input volume", 0, 100, 40),
            toggle("audio.input.mute", "Mute input", false),
        ],
    }
}

/// The power / battery panel (WS7-13.3).
#[must_use]
pub fn power_panel() -> SettingsPanel {
    SettingsPanel {
        id: "power".to_string(),
        title: "Power & Battery".to_string(),
        settings: vec![
            select(
                "power.profile",
                "Power profile",
                &["power-saver", "balanced", "performance"],
                1,
            ),
            range(
                "power.sleep_timeout_min",
                "Sleep after (minutes)",
                1,
                120,
                15,
            ),
            toggle("power.dim_on_battery", "Dim screen on battery", true),
        ],
    }
}

/// The keyboard / mouse / layout panel (WS7-13.4).
#[must_use]
pub fn input_panel(layouts: &[&str]) -> SettingsPanel {
    SettingsPanel {
        id: "input".to_string(),
        title: "Keyboard & Mouse".to_string(),
        settings: vec![
            range("input.key_repeat_rate", "Key repeat rate", 1, 100, 30),
            range(
                "input.key_repeat_delay_ms",
                "Key repeat delay (ms)",
                100,
                1000,
                300,
            ),
            toggle("input.mouse_acceleration", "Pointer acceleration", true),
            range("input.pointer_speed", "Pointer speed", 1, 10, 5),
            select("input.keyboard_layout", "Keyboard layout", layouts, 0),
        ],
    }
}

/// The accessibility panel (WS7-13.5) — hooks the WS7-16 a11y options.
#[must_use]
pub fn accessibility_panel() -> SettingsPanel {
    SettingsPanel {
        id: "accessibility".to_string(),
        title: "Accessibility".to_string(),
        settings: vec![
            toggle("a11y.high_contrast", "High contrast", false),
            select(
                "a11y.text_scale",
                "Text size",
                &["100%", "125%", "150%", "200%"],
                0,
            ),
            toggle("a11y.screen_reader", "Screen reader", false),
            toggle("a11y.reduce_motion", "Reduce motion", false),
            toggle("a11y.keyboard_focus_ring", "Focus ring", true),
        ],
    }
}

/// The accessibility options resolved from [`accessibility_panel`].
///
/// Maps the panel values onto the WS7-16 a11y primitives (`text_scale` becomes
/// a [`crate::a11y::TextScale`]; `high_contrast` selects
/// [`crate::a11y::high_contrast_theme`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent a11y on/off options"
)]
pub struct A11ySettings {
    /// Whether the high-contrast theme is enabled.
    pub high_contrast: bool,
    /// The global text scale.
    pub text_scale: crate::a11y::TextScale,
    /// Whether the screen reader is enabled.
    pub screen_reader: bool,
    /// Whether motion should be reduced.
    pub reduce_motion: bool,
    /// Whether the keyboard focus ring is shown.
    pub focus_ring: bool,
}

fn read_toggle(panel: &SettingsPanel, key: &str, default: bool) -> bool {
    match panel.find(key).map(|s| &s.value) {
        Some(SettingValue::Toggle(b)) => *b,
        _ => default,
    }
}

impl A11ySettings {
    /// Resolve the accessibility options from an [`accessibility_panel`].
    #[must_use]
    pub fn from_panel(panel: &SettingsPanel) -> Self {
        let permille = match panel.find("a11y.text_scale").map(|s| &s.value) {
            Some(SettingValue::Choice(1)) => 1250,
            Some(SettingValue::Choice(2)) => 1500,
            Some(SettingValue::Choice(3)) => 2000,
            _ => 1000,
        };
        Self {
            high_contrast: read_toggle(panel, "a11y.high_contrast", false),
            text_scale: crate::a11y::TextScale::new(permille),
            screen_reader: read_toggle(panel, "a11y.screen_reader", false),
            reduce_motion: read_toggle(panel, "a11y.reduce_motion", false),
            focus_ring: read_toggle(panel, "a11y.keyboard_focus_ring", true),
        }
    }
}

/// An account row in the users & auth panel (WS7-13.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRow {
    /// The login name.
    pub username: String,
    /// Whether the account has administrator rights.
    pub is_admin: bool,
    /// Whether the account is enabled (can log in).
    pub enabled: bool,
}

/// An account-management action the panel requests; the `nexacore-auth` backend
/// (WS12-05) applies it. No secret is carried here — password entry happens in a
/// secure prompt the backend owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountOp {
    /// Create a new account.
    Create {
        /// The new login name.
        username: String,
        /// Whether it is an administrator.
        admin: bool,
    },
    /// Delete an account.
    Delete {
        /// The login name to remove.
        username: String,
    },
    /// Change an account's administrator status.
    SetAdmin {
        /// The login name.
        username: String,
        /// The new administrator status.
        admin: bool,
    },
    /// Enable or disable an account.
    SetEnabled {
        /// The login name.
        username: String,
        /// The new enabled status.
        enabled: bool,
    },
    /// Request a password change (the backend prompts for the new secret).
    ChangePassword {
        /// The login name.
        username: String,
    },
}

/// Why an account operation was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsersError {
    /// The username violates the naming rules.
    InvalidUsername,
    /// An account with that name already exists.
    DuplicateUser,
    /// No account with that name exists.
    NoSuchUser,
    /// The operation would leave no enabled administrator.
    LastAdmin,
}

/// The users & auth panel (WS7-13.6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsersPanel {
    /// The known accounts.
    pub accounts: Vec<AccountRow>,
}

/// Whether `u` is a valid login name (mirrors `nexacore-auth`: `[a-z0-9_-]`,
/// first char `[a-z_]`, at most 32 chars).
fn is_valid_username(u: &str) -> bool {
    if u.is_empty() || u.len() > 32 {
        return false;
    }
    let Some(first) = u.chars().next() else {
        return false;
    };
    if !(first.is_ascii_lowercase() || first == '_') {
        return false;
    }
    u.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

impl UsersPanel {
    /// A panel over `accounts`.
    #[must_use]
    pub fn new(accounts: Vec<AccountRow>) -> Self {
        Self { accounts }
    }

    /// Find an account by name.
    #[must_use]
    pub fn find(&self, username: &str) -> Option<&AccountRow> {
        self.accounts.iter().find(|a| a.username == username)
    }

    /// The number of enabled administrator accounts.
    #[must_use]
    pub fn enabled_admin_count(&self) -> usize {
        self.accounts
            .iter()
            .filter(|a| a.is_admin && a.enabled)
            .count()
    }

    /// Whether removing/demoting/disabling `username` would strand the system
    /// with no enabled administrator.
    fn is_sole_enabled_admin(&self, username: &str) -> bool {
        self.find(username).is_some_and(|a| a.is_admin && a.enabled)
            && self.enabled_admin_count() <= 1
    }

    /// Validate an operation against account policy before the backend applies it.
    ///
    /// # Errors
    /// [`UsersError::InvalidUsername`], [`UsersError::DuplicateUser`],
    /// [`UsersError::NoSuchUser`], or [`UsersError::LastAdmin`] (the system must
    /// always keep at least one enabled administrator).
    pub fn validate(&self, op: &AccountOp) -> Result<(), UsersError> {
        match op {
            AccountOp::Create { username, .. } => {
                if !is_valid_username(username) {
                    return Err(UsersError::InvalidUsername);
                }
                if self.find(username).is_some() {
                    return Err(UsersError::DuplicateUser);
                }
                Ok(())
            }
            AccountOp::Delete { username } => {
                self.find(username).ok_or(UsersError::NoSuchUser)?;
                if self.is_sole_enabled_admin(username) {
                    return Err(UsersError::LastAdmin);
                }
                Ok(())
            }
            AccountOp::SetAdmin { username, admin } => {
                self.find(username).ok_or(UsersError::NoSuchUser)?;
                if !admin && self.is_sole_enabled_admin(username) {
                    return Err(UsersError::LastAdmin);
                }
                Ok(())
            }
            AccountOp::SetEnabled { username, enabled } => {
                self.find(username).ok_or(UsersError::NoSuchUser)?;
                if !enabled && self.is_sole_enabled_admin(username) {
                    return Err(UsersError::LastAdmin);
                }
                Ok(())
            }
            AccountOp::ChangePassword { username } => {
                self.find(username).ok_or(UsersError::NoSuchUser)?;
                Ok(())
            }
        }
    }
}

/// Read-only system facts for the System-Info panel (WS7-13.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemInfo {
    /// Product name (e.g. `NexaCore OS`).
    pub product: String,
    /// OS version.
    pub version: String,
    /// Kernel version string.
    pub kernel: String,
    /// CPU model string.
    pub cpu_model: String,
    /// Logical CPU count.
    pub cpu_cores: u32,
    /// Total RAM in bytes.
    pub total_ram_bytes: u64,
    /// Uptime in seconds.
    pub uptime_secs: u64,
    /// Host name.
    pub hostname: String,
}

/// The System-Info panel: labelled read-only rows (WS7-13.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemInfoPanel {
    /// The `(label, value)` display rows.
    pub rows: Vec<(String, String)>,
}

impl SystemInfoPanel {
    /// Build the panel rows from live [`SystemInfo`] (memory and uptime are
    /// formatted for display).
    #[must_use]
    pub fn from_info(info: &SystemInfo) -> Self {
        let rows = vec![
            ("Product".to_string(), info.product.clone()),
            ("Version".to_string(), info.version.clone()),
            ("Kernel".to_string(), info.kernel.clone()),
            ("Hostname".to_string(), info.hostname.clone()),
            ("Processor".to_string(), info.cpu_model.clone()),
            ("Cores".to_string(), itoa(i64::from(info.cpu_cores))),
            ("Memory".to_string(), format_bytes(info.total_ram_bytes)),
            ("Uptime".to_string(), format_uptime(info.uptime_secs)),
        ];
        Self { rows }
    }

    /// The value for a labelled row, if present.
    #[must_use]
    pub fn value(&self, label: &str) -> Option<&str> {
        self.rows
            .iter()
            .find(|(l, _)| l == label)
            .map(|(_, v)| v.as_str())
    }
}

/// Human-readable byte size (`B`/`KiB`/`MiB`/`GiB`/`TiB`, one decimal).
#[allow(clippy::integer_division, reason = "display rounding of a byte count")]
fn format_bytes(bytes: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut idx = 0usize;
    let mut scale = 1u64;
    while idx + 1 < units.len() && bytes >= scale * 1024 {
        scale *= 1024;
        idx += 1;
    }
    let unit = units.get(idx).copied().unwrap_or("B");
    if idx == 0 {
        let mut s = itoa(i64::try_from(bytes).unwrap_or(i64::MAX));
        s.push(' ');
        s.push_str(unit);
        return s;
    }
    let whole = bytes / scale;
    let frac = (bytes % scale) * 10 / scale;
    let mut s = itoa(i64::try_from(whole).unwrap_or(i64::MAX));
    s.push('.');
    s.push(char::from(b'0' + u8::try_from(frac).unwrap_or(0)));
    s.push(' ');
    s.push_str(unit);
    s
}

/// Human-readable uptime as `Nd Nh Nm`.
#[allow(clippy::integer_division, reason = "display breakdown of a duration")]
fn format_uptime(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    let mut s = itoa(i64::try_from(days).unwrap_or(i64::MAX));
    s.push_str("d ");
    s.push_str(itoa(i64::try_from(hours).unwrap_or(0)).as_str());
    s.push_str("h ");
    s.push_str(itoa(i64::try_from(mins).unwrap_or(0)).as_str());
    s.push('m');
    s
}

/// The result state of a software-update check (WS7-13.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateState {
    /// No update available.
    UpToDate,
    /// A check is in progress.
    Checking,
    /// An update is available.
    Available {
        /// The available version.
        version: String,
    },
    /// The check failed.
    Error(String),
}

/// The software-updates panel (WS7-13.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePanel {
    /// The currently installed version.
    pub current_version: String,
    /// The update channel (`stable`/`beta`).
    pub channel: Setting,
    /// Whether to check automatically.
    pub auto_check: bool,
    /// The last check result.
    pub state: UpdateState,
}

impl UpdatePanel {
    /// A panel for `current_version` on the stable channel, up to date.
    #[must_use]
    pub fn new(current_version: &str) -> Self {
        Self {
            current_version: current_version.to_string(),
            channel: select("update.channel", "Update channel", &["stable", "beta"], 0),
            auto_check: true,
            state: UpdateState::UpToDate,
        }
    }

    /// Mark a check as started.
    pub fn begin_check(&mut self) {
        self.state = UpdateState::Checking;
    }

    /// Record that `version` is available.
    pub fn report_available(&mut self, version: &str) {
        self.state = UpdateState::Available {
            version: version.to_string(),
        };
    }

    /// Record that the system is up to date.
    pub fn report_up_to_date(&mut self) {
        self.state = UpdateState::UpToDate;
    }

    /// Record a failed check.
    pub fn fail(&mut self, reason: &str) {
        self.state = UpdateState::Error(reason.to_string());
    }

    /// Whether an update is available.
    #[must_use]
    pub fn has_update(&self) -> bool {
        matches!(self.state, UpdateState::Available { .. })
    }

    /// Switch the update channel by name.
    ///
    /// # Errors
    /// [`SettingsError::Unparsable`] if `name` is not a known channel.
    pub fn set_channel(&mut self, name: &str) -> Result<(), SettingsError> {
        self.channel.set_from_str(name)
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    use super::*;

    struct MapStore(BTreeMap<String, String>);
    impl ConfigStore for MapStore {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
        fn set(&mut self, key: &str, value: &str) {
            self.0.insert(key.to_string(), value.to_string());
        }
    }

    #[test]
    fn validation_enforces_kind_and_bounds() {
        let mut vol = range("v", "V", 0, 100, 50);
        assert_eq!(
            vol.set(SettingValue::Number(101)),
            Err(SettingsError::OutOfRange)
        );
        assert_eq!(
            vol.set(SettingValue::Toggle(true)),
            Err(SettingsError::TypeMismatch)
        );
        vol.set(SettingValue::Number(80)).unwrap();
        assert_eq!(vol.value, SettingValue::Number(80));

        let mut sel = select("s", "S", &["a", "b"], 0);
        assert_eq!(
            sel.set(SettingValue::Choice(2)),
            Err(SettingsError::BadChoice)
        );
        sel.set(SettingValue::Choice(1)).unwrap();
    }

    #[test]
    fn commit_then_load_round_trips_through_the_store() {
        let mut panel = audio_panel(&["HDMI", "Speakers"], &["Mic"]);
        panel
            .set("audio.output.volume", SettingValue::Number(75))
            .unwrap();
        panel
            .set("audio.output.device", SettingValue::Choice(1))
            .unwrap();
        panel
            .set("audio.output.mute", SettingValue::Toggle(true))
            .unwrap();

        let mut store = MapStore(BTreeMap::new());
        panel.commit(&mut store);
        assert_eq!(store.get("audio.output.volume").as_deref(), Some("75"));
        assert_eq!(
            store.get("audio.output.device").as_deref(),
            Some("Speakers")
        );
        assert_eq!(store.get("audio.output.mute").as_deref(), Some("true"));

        // A fresh panel loads the same values back.
        let mut reloaded = audio_panel(&["HDMI", "Speakers"], &["Mic"]);
        reloaded.load(&store);
        assert_eq!(
            reloaded.find("audio.output.volume").unwrap().value,
            SettingValue::Number(75)
        );
        assert_eq!(
            reloaded.find("audio.output.device").unwrap().value,
            SettingValue::Choice(1)
        );
    }

    #[test]
    fn panels_expose_expected_settings() {
        assert!(power_panel().find("power.profile").is_some());
        let input = input_panel(&["us", "it"]);
        assert!(input.find("input.keyboard_layout").is_some());
        // Unknown key is rejected.
        let mut p = power_panel();
        assert_eq!(
            p.set("nope", SettingValue::Toggle(true)),
            Err(SettingsError::BadChoice)
        );
    }

    #[test]
    fn number_serialisation_handles_zero_and_negatives() {
        let mut s = range("n", "N", -50, 50, 0);
        assert_eq!(s.serialize_value(), "0");
        s.set(SettingValue::Number(-12)).unwrap();
        assert_eq!(s.serialize_value(), "-12");
        s.set_from_str("42").unwrap();
        assert_eq!(s.value, SettingValue::Number(42));
    }

    #[test]
    fn system_info_panel_formats_memory_and_uptime() {
        let info = SystemInfo {
            product: "NexaCore OS".to_string(),
            version: "0.2.0".to_string(),
            kernel: "nexacore 0.2".to_string(),
            cpu_model: "Test CPU".to_string(),
            cpu_cores: 8,
            total_ram_bytes: 8 * 1024 * 1024 * 1024,
            uptime_secs: 273_132, // 3d 3h 52m
            hostname: "nexacore-01".to_string(),
        };
        let panel = SystemInfoPanel::from_info(&info);
        assert_eq!(panel.value("Memory"), Some("8.0 GiB"));
        assert_eq!(panel.value("Uptime"), Some("3d 3h 52m"));
        assert_eq!(panel.value("Cores"), Some("8"));
        assert_eq!(panel.value("Hostname"), Some("nexacore-01"));
    }

    #[test]
    fn byte_formatting_picks_units() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
    }

    #[test]
    fn users_panel_enforces_account_policy() {
        let panel = UsersPanel::new(alloc::vec![
            AccountRow {
                username: "admin".to_string(),
                is_admin: true,
                enabled: true
            },
            AccountRow {
                username: "guest".to_string(),
                is_admin: false,
                enabled: true
            },
        ]);
        // Valid create.
        assert!(
            panel
                .validate(&AccountOp::Create {
                    username: "dev".to_string(),
                    admin: false
                })
                .is_ok()
        );
        // Duplicate + invalid username.
        assert_eq!(
            panel.validate(&AccountOp::Create {
                username: "guest".to_string(),
                admin: false
            }),
            Err(UsersError::DuplicateUser)
        );
        assert_eq!(
            panel.validate(&AccountOp::Create {
                username: "Bad".to_string(),
                admin: false
            }),
            Err(UsersError::InvalidUsername)
        );
        // Can't delete/demote/disable the sole enabled admin.
        assert_eq!(
            panel.validate(&AccountOp::Delete {
                username: "admin".to_string()
            }),
            Err(UsersError::LastAdmin)
        );
        assert_eq!(
            panel.validate(&AccountOp::SetAdmin {
                username: "admin".to_string(),
                admin: false
            }),
            Err(UsersError::LastAdmin)
        );
        // Unknown user + a normal delete are handled.
        assert_eq!(
            panel.validate(&AccountOp::Delete {
                username: "nobody".to_string()
            }),
            Err(UsersError::NoSuchUser)
        );
        assert!(
            panel
                .validate(&AccountOp::Delete {
                    username: "guest".to_string()
                })
                .is_ok()
        );
    }

    #[test]
    fn accessibility_panel_resolves_a11y_settings() {
        let mut panel = accessibility_panel();
        // Defaults: 100% scale, no high contrast, focus ring on.
        let base = A11ySettings::from_panel(&panel);
        assert_eq!(base.text_scale.percent(), 100);
        assert!(!base.high_contrast);
        assert!(base.focus_ring);

        panel
            .set("a11y.high_contrast", SettingValue::Toggle(true))
            .unwrap();
        panel
            .set("a11y.text_scale", SettingValue::Choice(2))
            .unwrap(); // 150%
        panel
            .set("a11y.screen_reader", SettingValue::Toggle(true))
            .unwrap();
        let a = A11ySettings::from_panel(&panel);
        assert!(a.high_contrast);
        assert_eq!(a.text_scale.percent(), 150);
        assert!(a.screen_reader);
    }

    #[test]
    fn update_panel_tracks_check_state() {
        let mut p = UpdatePanel::new("0.2.0");
        assert_eq!(p.state, UpdateState::UpToDate);
        assert!(!p.has_update());
        p.begin_check();
        assert_eq!(p.state, UpdateState::Checking);
        p.report_available("0.3.0");
        assert!(p.has_update());
        assert_eq!(
            p.state,
            UpdateState::Available {
                version: "0.3.0".to_string()
            }
        );
        // Channel switch is validated.
        p.set_channel("beta").unwrap();
        assert_eq!(p.channel.value, SettingValue::Choice(1));
        assert_eq!(p.set_channel("nope"), Err(SettingsError::Unparsable));
    }
}
