//! `cd` / `pwd` — current-working-directory model over the seam (WS8-10.1).
//!
//! There is **no global state**: navigation operates on an explicit [`Cwd`]
//! value. `cd` resolves a target (absolute, relative, `.`, or `..`) against the
//! current directory, validates via the [`FileSystem`] that it names a
//! directory, and returns a *new* [`Cwd`]; `pwd` reads the normalized current
//! path back out. This keeps a shell's working directory a pure, testable value
//! that threads through commands rather than ambient mutable state.

use alloc::string::{String, ToString};

use crate::{
    fs::{FileKind, FileSystem, FsError},
    path,
};

/// A shell's current working directory: always a normalized absolute path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cwd {
    /// The normalized absolute path of the current directory.
    path: String,
}

impl Default for Cwd {
    fn default() -> Self {
        Self::root()
    }
}

impl Cwd {
    /// A working directory rooted at `/`.
    #[must_use]
    pub fn root() -> Self {
        Self {
            path: String::from("/"),
        }
    }

    /// A working directory at `path`, if `path` is absolute.
    ///
    /// The path is normalized. Returns `None` for a relative path. This does
    /// **not** consult a filesystem; use [`Cwd::cd`] to validate against one.
    #[must_use]
    pub fn new(path: &str) -> Option<Self> {
        if path::is_absolute(path) {
            Some(Self {
                path: path::normalize(path),
            })
        } else {
            None
        }
    }

    /// The normalized current path — this is `pwd`.
    #[must_use]
    pub fn pwd(&self) -> &str {
        &self.path
    }

    /// Resolve `target` against this directory to a normalized absolute path,
    /// without touching a filesystem.
    ///
    /// Absolute targets replace the current path; relative targets (including
    /// `.` and `..`) are joined onto it.
    #[must_use]
    pub fn resolve(&self, target: &str) -> String {
        path::join(&self.path, target)
    }

    /// `cd target`: resolve `target` and return the new [`Cwd`] if it names a
    /// directory in `fs`.
    ///
    /// # Errors
    ///
    /// [`FsError::NotFound`] if the resolved path does not exist,
    /// [`FsError::NotADirectory`] if it exists but is a file or symlink.
    pub fn cd<F: FileSystem>(&self, fs: &F, target: &str) -> Result<Self, FsError> {
        let resolved = self.resolve(target);
        let meta = fs.metadata(&resolved)?;
        if meta.kind == FileKind::Dir {
            Ok(Self { path: resolved })
        } else {
            Err(FsError::NotADirectory)
        }
    }
}

/// Free-function form of `pwd` for a borrowed [`Cwd`].
#[must_use]
pub fn pwd(cwd: &Cwd) -> String {
    cwd.pwd().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemFs;

    fn fs() -> MemFs {
        MemFs::new()
            .with_dir("/home/user/docs")
            .with_text_file("/home/user/file.txt", "x")
    }

    #[test]
    fn root_pwd() {
        assert_eq!(Cwd::root().pwd(), "/");
    }

    #[test]
    fn cd_into_absolute_dir() {
        let cwd = Cwd::root().cd(&fs(), "/home/user").unwrap();
        assert_eq!(cwd.pwd(), "/home/user");
    }

    #[test]
    fn cd_relative_and_dotdot() {
        let cwd = Cwd::new("/home/user").unwrap();
        let into = cwd.cd(&fs(), "docs").unwrap();
        assert_eq!(into.pwd(), "/home/user/docs");
        let up = into.cd(&fs(), "..").unwrap();
        assert_eq!(up.pwd(), "/home/user");
    }

    #[test]
    fn cd_dot_stays_put() {
        let cwd = Cwd::new("/home/user").unwrap();
        let same = cwd.cd(&fs(), ".").unwrap();
        assert_eq!(same.pwd(), "/home/user");
    }

    #[test]
    fn cd_into_file_is_not_a_directory() {
        let cwd = Cwd::new("/home/user").unwrap();
        assert_eq!(cwd.cd(&fs(), "file.txt"), Err(FsError::NotADirectory));
    }

    #[test]
    fn cd_into_missing_is_not_found() {
        assert_eq!(Cwd::root().cd(&fs(), "/nope"), Err(FsError::NotFound));
    }

    #[test]
    fn new_rejects_relative() {
        assert_eq!(Cwd::new("home/user"), None);
    }

    #[test]
    fn resolve_without_fs() {
        let cwd = Cwd::new("/a/b").unwrap();
        assert_eq!(cwd.resolve("../c"), "/a/c");
        assert_eq!(cwd.resolve("/x"), "/x");
        assert_eq!(pwd(&cwd), "/a/b");
    }
}
