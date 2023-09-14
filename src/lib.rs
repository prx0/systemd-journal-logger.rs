// Copyright Sebastian Wiesner <sebastian@swsnr.de>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A pure Rust [log] logger for the [systemd journal][1].
//!
//! [log]: https://docs.rs/log
//! [1]: https://www.freedesktop.org/software/systemd/man/journalctl.html
//!
//! # Usage
//!
//! Create a [`JournalLog`] with [`JournalLog::default`] and then use [`JournalLog::install`] to
//! setup journal logging.  Then configure the logging level and now you can use the standard macros
//! from the [`log`] crate to send log messages to the systemd journal:
//!
//! ```edition2018
//! use log::{info, warn, error, LevelFilter};
//! use systemd_journal_logger::JournalLog;
//!
//! # fn main(){
//! JournalLog::default().install().unwrap();
//! log::set_max_level(LevelFilter::Info);
//!
//! info!("hello log");
//! warn!("warning");
//! error!("oops");
//! # }
//! ```
//!
//! In a service you can use [`connected_to_journal`] to check whether
//! the standard output or error stream of the current process is directly
//! connected to the systemd journal (the default for services started by
//! systemd) and fall back to logging to standard error if that's not the
//! case.  Take a look at the [systemd_service.rs] example for details.
//!
//! [systemd_service.rs]: https://codeberg.org/flausch/systemd-journal-logger.rs/src/branch/main/examples/systemd_service.rs
//!
//! # Journal fields
//!
//! The journald logger always sets the following standard [journal fields][2]:
//!
//! - `PRIORITY`: The log level mapped to a priority (see below).
//! - `MESSAGE`: The formatted log message (see [`log::Record::args()`]).
//! - `SYSLOG_PID`: The PID of the running process (see [`std::process::id()`]).
//! - `CODE_FILE`: The filename the log message originates from (see [`log::Record::file()`], only if present).
//! - `CODE_LINE`: The line number the log message originates from (see [`log::Record::line()`], only if present).
//!
//! It also sets `SYSLOG_IDENTIFIER` if non-empty (see [`JournalLog::with_syslog_identifier`] and [`JournalLog::default`]).
//!
//! Additionally it also adds the following non-standard fields:
//!
//! - `TARGET`: The target of the log record (see [`log::Record::target()`]).
//! - `CODE_MODULE`: The module path of the log record (see [`log::Record::module_path()`], only if present).
//!
//! In addition to these fields the logger also adds all structures key-values (see [`log::Record::key_values`])
//! from each log record as journal fields, after converting the keys to uppercase letters and replacing invalid
//! characters with underscores.
//!
//! You can also add custom fields to every log entry with [`JournalLog::with_extra_fields`] and customize the
//! syslog identifier with [`JournalLog::with_syslog_identifier`]:
//!
//! ```edition2018
//! use log::{info, warn, error, LevelFilter};
//! use systemd_journal_logger::JournalLog;
//!
//! # fn main(){
//! JournalLog::default()
//!     .with_extra_fields(vec![("VERSION", env!("CARGO_PKG_VERSION"))])
//!     .with_syslog_identifier("foo".to_string())
//!     .install().unwrap();
//! log::set_max_level(LevelFilter::Info);
//!
//! info!("this message has an extra VERSION field in the journal");
//! # }
//! ```
//!
//! You can display these extra fields with `journalctl --output=verbose` and extract them with any of the structured
//! output formats of `journalctl`, e.g. `journalctl --output=json`.
//!
//! [2]: https://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html
//!
//! # Log levels and priorities
//!
//! The journal logger maps [`log::Level`] to journal priorities as follows:
//!
//! - [`Level::Error`] → [`libsystemd::logging::Priority::Error`]
//! - [`Level::Warn`] → [`libsystemd::logging::Priority::Warning`]
//! - [`Level::Info`] → [`libsystemd::logging::Priority::Notice`]
//! - [`Level::Debug`] → [`libsystemd::logging::Priority::Info`]
//! - [`Level::Trace`] → [`libsystemd::logging::Priority::Debug`]
//!
//! # Errors
//!
//! This crate currently does not implement any kind of error handling for journal messages.
//! In particular it will **panic** when sending a record to journald fails, e.g. if journald is
//! not running.  There are no plans to change this behaviour, give that journald is reliable in
//! general.
//!
//! To implement an alternative error handling behaviour define a custom log implementation around
//! [`journal_send`] which sends a single log record to the journal.
#![deny(warnings, missing_docs, clippy::all)]

use std::borrow::Cow;

use libsystemd::errors::SdError;
use libsystemd::logging::Priority;
use log::kv::{Error as LogError, Key, Value, Visitor};
use log::{Level, Log, Metadata, Record, SetLoggerError};
use std::cmp::min;
use std::fmt::Display;
use std::io::ErrorKind;

pub use libsystemd::logging::connected_to_journal;

/// Base error type
#[derive(Debug)]
pub enum Error {
    /// Handle error given by libsystemd
    Journald(SdError),
    /// Handle error given by log::kv
    Log(LogError),
}

impl From<SdError> for Error {
    fn from(err: SdError) -> Self {
        Self::Journald(err)
    }
}

impl From<LogError> for Error {
    fn from(err: LogError) -> Self {
        Self::Log(err)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("Error {}", self))
    }
}

impl std::error::Error for Error {}

/// Convert a a log level to a journal priority.
fn level_to_priority(level: Level) -> Priority {
    match level {
        Level::Error => Priority::Error,
        Level::Warn => Priority::Warning,
        Level::Info => Priority::Notice,
        Level::Debug => Priority::Info,
        Level::Trace => Priority::Debug,
    }
}

/// Whether `c` is a valid character in the key of a journal field.
///
/// Journal field keys may only contain ASCII uppercase letters A to Z,
/// numbers 0 to 9 and the underscore.
fn is_valid_key_char(c: char) -> bool {
    matches!(c, 'A'..='Z' | '0'..='9' | '_')
}

/// Escape a `key` for use in a systemd journal field.
///
/// Journal keys must only contain ASCII uppercase letters, numbers and
/// the underscore, and the must not start with an underscore.
///
/// If all characters in `key` are valid return `key`, otherwise transform
/// `key` to a ASCII uppercase, and replace all invalid characters with
/// an underscore.
///
/// If the result string starts with an underscore or a digit
/// prepend the string `ESCAPED_` to the result.
///
/// If `key` is the empty string return `"EMPTY"` instead.
///
/// In all cases cap the resulting value at 64 bytes; journald doesn't
/// permit longer fields.
pub fn escape_journal_key(key: &str) -> Cow<str> {
    if key.is_empty() {
        Cow::Borrowed("EMPTY")
    } else if key.chars().all(is_valid_key_char) {
        Cow::Borrowed(&key[..min(key.len(), 64)])
    } else {
        let mut escaped = key
            .to_ascii_uppercase()
            .replace(|c| !is_valid_key_char(c), "_");
        if escaped.starts_with(|c: char| matches!(c, '_' | '0'..='9')) {
            escaped = format!("ESCAPED_{}", escaped);
        }
        escaped.truncate(64);
        escaped.into()
    }
}

/// Create a syslog identifier from the current executable.
pub fn current_exe_identifier() -> std::io::Result<String> {
    let executable = std::env::current_exe()?;
    let filename = executable.file_name().ok_or(std::io::Error::new(
        ErrorKind::InvalidData,
        format!(
            "Current executable {} has no filename",
            executable.display()
        ),
    ))?;
    Ok(filename.to_string_lossy().into_owned())
}

/// Send a single log record to the journal.
///
/// Extract the standard fields from `record` (see [`crate`] documentation), inject the standard
/// `SYSLOG_PID` field, and add a `SYSLOG_IDENTIFIER` field for the given `syslog_identifier`, if
/// not empty.
///
/// Then append all `extra_fields` and send the all these fields to the systemd journal with
/// [`libsystemd::logging::journal_send`].
///
/// Return the result of [`libsystemd::logging::journal_send`].
pub fn journal_send<'a, K, V, I>(
    syslog_identifier: &str,
    record: &Record,
    extra_fields: I,
) -> Result<(), Error>
where
    I: Iterator<Item = &'a (K, V)>,
    K: AsRef<str> + 'a,
    V: AsRef<str> + 'a,
{
    let mut record_fields = Vec::with_capacity(record.key_values().count());
    record
        .key_values()
        .visit(&mut CollectKeyValues(&mut record_fields))?;
    let mut global_fields: Vec<(Cow<str>, Cow<str>)> =
        vec![("SYSLOG_PID".into(), std::process::id().to_string().into())];
    if !syslog_identifier.is_empty() {
        global_fields.push(("SYSLOG_IDENTIFIER".into(), syslog_identifier.into()));
    }
    libsystemd::logging::journal_send(
        level_to_priority(record.level()),
        &format!("{}", record.args()),
        global_fields
            .into_iter()
            .chain(standard_record_fields(record).into_iter())
            .chain(extra_fields.map(|(k, v)| (escape_journal_key(k.as_ref()), v.as_ref().into())))
            .chain(
                record_fields
                    .iter()
                    .map(|(k, v)| (escape_journal_key(k.as_ref()), format!("{}", v).into())),
            ),
    )?;
    Ok(())
}

struct CollectKeyValues<'a, 'kvs>(&'a mut Vec<(Key<'kvs>, Value<'kvs>)>);

impl<'a, 'kvs> Visitor<'kvs> for CollectKeyValues<'a, 'kvs> {
    fn visit_pair(&mut self, key: Key<'kvs>, value: Value<'kvs>) -> Result<(), LogError> {
        self.0.push((key, value));
        Ok(())
    }
}

/// Collect the standard journal fields for `record`.
///
/// Sets
///
/// - the standard `CODE_FILE` and `CODE_LINE` fields to the file and line of `record`,
/// - the custom `TARGET` field to `record.target`, and
/// - the custom `CODE_MODULE` to the module path of `record`.
fn standard_record_fields<'a>(record: &'a Record) -> Vec<(Cow<'a, str>, Cow<'a, str>)> {
    let mut fields: Vec<(Cow<'a, str>, Cow<'a, str>)> = Vec::with_capacity(4);
    if let Some(file) = record.file() {
        fields.push(("CODE_FILE".into(), file.into()));
    }
    if let Some(line) = record.line().map(|l| l.to_string()) {
        fields.push(("CODE_LINE".into(), line.into()));
    }
    // Non-standard fields
    fields.push(("TARGET".into(), record.target().into()));
    if let Some(module) = record.module_path() {
        fields.push(("CODE_MODULE".into(), module.into()))
    }
    fields
}

/// A systemd journal logger.
pub struct JournalLog<K: AsRef<str>, V: AsRef<str>> {
    /// Extra fields to add to every logged message.
    extra_fields: Vec<(K, V)>,
    /// The syslog identifier.
    syslog_identifier: String,
}

impl<K: AsRef<str>, V: AsRef<str>> JournalLog<K, V> {
    /// Set extra fields to be added to every log entry.
    ///
    /// # Journal fields
    ///
    /// `extra_fields` is a sequence of key value pairs to add as extra fields
    /// to every log entry logged through the new logger.  The extra fields will
    /// be *appended* to the standard journal fields written by the logger.
    ///
    /// ## Restrictions on field names
    ///
    /// Each key in the sequence must be a valid journal field name, i.e.
    /// contain only uppercase alphanumeric characters and the underscore, and
    /// it must not start with an underscore.
    ///
    /// Invalid keys in `extra_fields` are escaped with [`escape_journal_key`],
    /// which transforms them to ASCII uppercase and replaces all invalid
    /// characters with underscores.
    ///
    /// `extra_fields` should **not** contain any of the journal fields already
    /// added by this logger; while journald supports multiple values for a field
    /// journald clients may not handle unexpected multi-value fields properly and
    /// likely show only the first value.  Specifically even `journalctl` will only
    /// shouw the first `MESSAGE` value of journal entries.
    ///
    /// See the [`crate`] documentation at [`crate`] for details about the standard
    /// journal fields this logger uses.
    ///
    /// ## Restrictions on values
    ///
    /// There are no restrictions on the value.
    pub fn with_extra_fields<KK: AsRef<str>, VV: AsRef<str>>(
        self,
        extra_fields: Vec<(KK, VV)>,
    ) -> JournalLog<KK, VV> {
        JournalLog {
            extra_fields,
            syslog_identifier: self.syslog_identifier,
        }
    }

    /// Set the given syslog identifier for this logger.
    ///
    /// The logger writes this string in the `SYSLOG_IDENTIFIER` field, which can be filtered for
    /// with `journalctl -t`.
    ///
    /// Use [`current_exe_identifier()`] to obtain the standard identifier for the current executable.
    pub fn with_syslog_identifier(mut self, identifier: String) -> Self {
        self.syslog_identifier = identifier;
        self
    }

    /// Send a single log record to the journal.
    ///
    /// Extract the standard fields from `record` (see [`crate`] documentation),
    /// and append all `extra_fields`; the send the resulting fields to the
    /// systemd journal with [`libsystemd::logging::journal_send`] and return
    /// the result of that function.
    pub fn journal_send(&self, record: &Record) -> Result<(), Error> {
        journal_send(&self.syslog_identifier, record, self.extra_fields.iter())
    }
}

impl<K, V> JournalLog<K, V>
where
    K: AsRef<str> + Send + Sync + 'static,
    V: AsRef<str> + Send + Sync + 'static,
{
    /// Install this logger globally.
    ///
    /// See [`log::set_boxed_logger`].
    pub fn install(self) -> Result<(), SetLoggerError> {
        log::set_boxed_logger(Box::new(self))
    }
}

impl JournalLog<String, String> {
    /// Create an empty journal log instance, with no extra fields and no syslog identifier.
    pub fn empty() -> Self {
        Self {
            extra_fields: Vec::new(),
            syslog_identifier: String::new(),
        }
    }
}

impl Default for JournalLog<String, String> {
    /// Create a journal logger with no extra fields and a syslog identifier obtained with
    /// [`current_exe_identifier()`].
    ///
    /// If `current_exe_identifier()` fails use no syslog identifier.
    fn default() -> Self {
        let log = Self::empty();
        log.with_syslog_identifier(current_exe_identifier().unwrap_or_default())
    }
}

/// The [`Log`] interface for [`JournalLog`].
impl<K, V> Log for JournalLog<K, V>
where
    K: AsRef<str> + Sync + Send,
    V: AsRef<str> + Sync + Send,
{
    /// Whether this logger is enabled.
    ///
    /// Always returns `true`.
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    /// Send the given `record` to the systemd journal.
    ///
    /// # Errors
    ///
    /// print a systemd error if sending the `record` to journald fails,
    /// i.e. if journald is not running.
    ///
    /// See [`JournalLog::journal_send`] for a function which returns any error which might have
    /// occurred while sending the `record` to the journal.
    fn log(&self, record: &Record) {
        if let Err(err) = self.journal_send(record) {
            eprintln!("{}", err)
        }
    }

    /// Flush log records.
    ///
    /// A no-op for journal logging.
    fn flush(&self) {}
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use libsystemd::logging::Priority;
    use log::{Level, Record};
    use pretty_assertions::assert_eq;

    #[test]
    fn level_to_priority() {
        assert!(matches!(
            crate::level_to_priority(Level::Error),
            Priority::Error
        ));
        assert!(matches!(
            crate::level_to_priority(Level::Warn),
            Priority::Warning
        ));
        assert!(matches!(
            crate::level_to_priority(Level::Info),
            Priority::Notice
        ));
        assert!(matches!(
            crate::level_to_priority(Level::Debug),
            Priority::Info
        ));
        assert!(matches!(
            crate::level_to_priority(Level::Trace),
            Priority::Debug
        ));
    }

    #[test]
    fn is_valid_key_char() {
        for c in 'A'..='Z' {
            assert!(super::is_valid_key_char(c));
        }
        for c in '0'..='9' {
            assert!(super::is_valid_key_char(c));
        }
        assert!(super::is_valid_key_char('_'));

        for c in 'a'..='z' {
            assert!(!super::is_valid_key_char(c));
        }
        assert!(!super::is_valid_key_char('ö'));
        assert!(!super::is_valid_key_char('ß'));
    }

    #[test]
    fn escape_journal_key() {
        for case in &["FOO", "123_FOO_BAR", "123"] {
            assert_eq!(super::escape_journal_key(case), *case);
            assert!(matches!(super::escape_journal_key(case), Cow::Borrowed(_)));
        }

        let cases = vec![
            ("foo", "FOO"),
            ("_foo", "ESCAPED__FOO"),
            ("1foo", "ESCAPED_1FOO"),
            ("Hallöchen", "HALL_CHEN"),
        ];
        for (key, expected) in cases {
            assert_eq!(super::escape_journal_key(key), expected);
        }
    }

    #[test]
    fn standard_record_fields() {
        let record = Record::builder()
            .level(Level::Warn)
            .line(Some(10))
            .file(Some("foo.rs"))
            .target("testlog")
            .module_path(Some(module_path!()))
            .build();
        let fields = super::standard_record_fields(&record);

        assert_eq!(
            fields,
            vec![
                (Cow::Borrowed("CODE_FILE"), Cow::Borrowed("foo.rs")),
                (Cow::Borrowed("CODE_LINE"), Cow::Borrowed("10")),
                (Cow::Borrowed("TARGET"), Cow::Borrowed("testlog")),
                (
                    Cow::Borrowed("CODE_MODULE"),
                    Cow::Borrowed("systemd_journal_logger::tests")
                )
            ]
        )
    }
}
