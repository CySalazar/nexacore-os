//! First-boot wizard: user, locale/timezone, network (WS11-04.5/.6/.7).
//!
//! A small linear state machine the first-boot experience drives: it collects
//! the primary user, the locale/timezone/keymap, and the network choice — each
//! step validated as it is entered — and finishes by producing the validated
//! [`InitialConfig`] the system persists.

use alloc::string::{String, ToString};

use crate::config::{ConfigError, InitialConfig, is_valid_hostname, is_valid_username};

/// The wizard's current step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Collecting the hostname and primary user.
    CreateUser,
    /// Collecting locale, timezone, and keymap.
    SelectLocale,
    /// Collecting the network choice.
    ConfigureNetwork,
    /// All steps done; [`FirstBootWizard::finish`] is ready.
    Complete,
}

/// Why a wizard step was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardError {
    /// The input was submitted for the wrong step.
    WrongStep,
    /// A field failed validation.
    Invalid(ConfigError),
    /// [`FirstBootWizard::finish`] was called before completion.
    Incomplete,
}

/// The linear first-boot wizard.
#[derive(Debug, Clone, Default)]
pub struct FirstBootWizard {
    step: Step,
    hostname: String,
    primary_user: String,
    locale: String,
    timezone: String,
    keymap: String,
    enable_networking: bool,
}

impl Default for Step {
    fn default() -> Self {
        Self::CreateUser
    }
}

impl FirstBootWizard {
    /// A fresh wizard at [`Step::CreateUser`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The current step.
    #[must_use]
    pub fn step(&self) -> Step {
        self.step
    }

    /// Step 1: set the hostname and primary user, advancing to
    /// [`Step::SelectLocale`].
    ///
    /// # Errors
    /// [`WizardError::WrongStep`] if not on [`Step::CreateUser`];
    /// [`WizardError::Invalid`] if the hostname or username is invalid.
    pub fn set_user(&mut self, hostname: &str, username: &str) -> Result<(), WizardError> {
        if self.step != Step::CreateUser {
            return Err(WizardError::WrongStep);
        }
        if !is_valid_hostname(hostname) {
            return Err(WizardError::Invalid(ConfigError::InvalidHostname));
        }
        if !is_valid_username(username) {
            return Err(WizardError::Invalid(ConfigError::InvalidUsername));
        }
        self.hostname = hostname.to_string();
        self.primary_user = username.to_string();
        self.step = Step::SelectLocale;
        Ok(())
    }

    /// Step 2: set locale, timezone, and keymap, advancing to
    /// [`Step::ConfigureNetwork`].
    ///
    /// # Errors
    /// [`WizardError::WrongStep`] if not on [`Step::SelectLocale`].
    pub fn set_locale(
        &mut self,
        locale: &str,
        timezone: &str,
        keymap: &str,
    ) -> Result<(), WizardError> {
        if self.step != Step::SelectLocale {
            return Err(WizardError::WrongStep);
        }
        self.locale = locale.to_string();
        self.timezone = timezone.to_string();
        self.keymap = keymap.to_string();
        self.step = Step::ConfigureNetwork;
        Ok(())
    }

    /// Step 3: set the network choice, advancing to [`Step::Complete`].
    ///
    /// # Errors
    /// [`WizardError::WrongStep`] if not on [`Step::ConfigureNetwork`].
    pub fn set_network(&mut self, enable: bool) -> Result<(), WizardError> {
        if self.step != Step::ConfigureNetwork {
            return Err(WizardError::WrongStep);
        }
        self.enable_networking = enable;
        self.step = Step::Complete;
        Ok(())
    }

    /// Produce the validated [`InitialConfig`] once the wizard is complete.
    ///
    /// # Errors
    /// [`WizardError::Incomplete`] before completion, or
    /// [`WizardError::Invalid`] if final validation fails.
    pub fn finish(&self) -> Result<InitialConfig, WizardError> {
        if self.step != Step::Complete {
            return Err(WizardError::Incomplete);
        }
        let config = InitialConfig {
            hostname: self.hostname.clone(),
            timezone: self.timezone.clone(),
            locale: self.locale.clone(),
            keymap: self.keymap.clone(),
            primary_user: self.primary_user.clone(),
            enable_networking: self.enable_networking,
        };
        config.validate().map_err(WizardError::Invalid)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_walk_produces_a_valid_config() {
        let mut w = FirstBootWizard::new();
        assert_eq!(w.step(), Step::CreateUser);
        w.set_user("nexacore-01", "matteo").unwrap();
        assert_eq!(w.step(), Step::SelectLocale);
        w.set_locale("en_US.UTF-8", "Europe/Rome", "us").unwrap();
        assert_eq!(w.step(), Step::ConfigureNetwork);
        w.set_network(true).unwrap();
        assert_eq!(w.step(), Step::Complete);
        let config = w.finish().unwrap();
        assert_eq!(config.hostname, "nexacore-01");
        assert_eq!(config.primary_user, "matteo");
        assert!(config.enable_networking);
    }

    #[test]
    fn steps_are_ordered_and_validated() {
        let mut w = FirstBootWizard::new();
        // Can't skip ahead.
        assert_eq!(w.set_network(true), Err(WizardError::WrongStep));
        assert_eq!(w.finish().err(), Some(WizardError::Incomplete));
        // Invalid user is rejected and does not advance.
        assert_eq!(
            w.set_user("Bad_Host", "matteo"),
            Err(WizardError::Invalid(ConfigError::InvalidHostname))
        );
        assert_eq!(w.step(), Step::CreateUser);
        assert_eq!(
            w.set_user("host", "1bad"),
            Err(WizardError::Invalid(ConfigError::InvalidUsername))
        );
    }
}
