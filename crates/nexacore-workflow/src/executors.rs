//! Concrete action executors behind effect seams (WS16-04.4 / .5 / .6).
//!
//! [`SystemActionExecutor`] is the production [`ActionExecutor`]: it dispatches
//! each [`Action`] to the right typed effect seam — [`AppLauncher`] for app
//! launches (.4), [`FileOps`] for file actions (.5), [`NetClient`] for network
//! requests (.6). The real OS effects live in the seam implementations (the
//! runtime backs them with process/VFS/socket syscalls); the dispatch routing is
//! host-tested with mocks.

use crate::{engine::ActionExecutor, model::Action};

/// Launches applications (WS16-04.4).
pub trait AppLauncher {
    /// Launch `app` with `args`, returning a success detail or failure reason.
    ///
    /// # Errors
    ///
    /// `Err(reason)` if the app could not be launched.
    fn launch(&mut self, app: &str, args: &[String]) -> Result<String, String>;
}

/// Performs file actions (WS16-04.5).
pub trait FileOps {
    /// Classify the file at `path` (e.g. by content/type) without moving it.
    ///
    /// # Errors
    ///
    /// `Err(reason)` on failure.
    fn classify(&mut self, path: &str) -> Result<String, String>;
    /// Move a file from `from` to `to`.
    ///
    /// # Errors
    ///
    /// `Err(reason)` on failure.
    fn move_file(&mut self, from: &str, to: &str) -> Result<String, String>;
    /// Copy a file from `from` to `to`.
    ///
    /// # Errors
    ///
    /// `Err(reason)` on failure.
    fn copy_file(&mut self, from: &str, to: &str) -> Result<String, String>;
    /// Delete the file at `path`.
    ///
    /// # Errors
    ///
    /// `Err(reason)` on failure.
    fn delete_file(&mut self, path: &str) -> Result<String, String>;
}

/// Performs capability-bound network requests (WS16-04.6).
pub trait NetClient {
    /// Make a `method` request to `url`, returning a success detail or reason.
    ///
    /// # Errors
    ///
    /// `Err(reason)` on failure.
    fn request(&mut self, url: &str, method: &str) -> Result<String, String>;
}

/// The production [`ActionExecutor`]: routes each action to its effect seam
/// (WS16-04.4 / .5 / .6).
#[derive(Debug, Clone, Copy)]
pub struct SystemActionExecutor<A, F, N> {
    /// The application launcher (WS16-04.4).
    pub apps: A,
    /// The file-operation backend (WS16-04.5).
    pub files: F,
    /// The network client (WS16-04.6).
    pub net: N,
}

impl<A, F, N> SystemActionExecutor<A, F, N> {
    /// Assemble an executor from the three effect seams.
    pub const fn new(apps: A, files: F, net: N) -> Self {
        Self { apps, files, net }
    }
}

impl<A: AppLauncher, F: FileOps, N: NetClient> ActionExecutor for SystemActionExecutor<A, F, N> {
    fn execute(&mut self, action: &Action) -> Result<String, String> {
        match action {
            Action::LaunchApp { app, args } => self.apps.launch(app, args),
            Action::ClassifyFile { path } => self.files.classify(path),
            Action::MoveFile { from, to } => self.files.move_file(from, to),
            Action::CopyFile { from, to } => self.files.copy_file(from, to),
            Action::DeleteFile { path } => self.files.delete_file(path),
            Action::NetworkRequest { url, method } => self.net.request(url, method),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[derive(Default)]
    struct MockApps {
        launched: Vec<String>,
    }
    impl AppLauncher for MockApps {
        fn launch(&mut self, app: &str, args: &[String]) -> Result<String, String> {
            self.launched.push(app.to_string());
            Ok(format!("launched {app} with {} args", args.len()))
        }
    }

    #[derive(Default)]
    struct MockFiles {
        ops: Vec<String>,
    }
    impl FileOps for MockFiles {
        fn classify(&mut self, path: &str) -> Result<String, String> {
            self.ops.push(format!("classify {path}"));
            Ok("document".to_string())
        }
        fn move_file(&mut self, from: &str, to: &str) -> Result<String, String> {
            self.ops.push(format!("move {from}->{to}"));
            Ok("moved".to_string())
        }
        fn copy_file(&mut self, from: &str, to: &str) -> Result<String, String> {
            self.ops.push(format!("copy {from}->{to}"));
            Ok("copied".to_string())
        }
        fn delete_file(&mut self, path: &str) -> Result<String, String> {
            self.ops.push(format!("delete {path}"));
            Ok("deleted".to_string())
        }
    }

    #[derive(Default)]
    struct MockNet {
        requests: Vec<String>,
        fail: bool,
    }
    impl NetClient for MockNet {
        fn request(&mut self, url: &str, method: &str) -> Result<String, String> {
            if self.fail {
                return Err(format!("network down for {method} {url}"));
            }
            self.requests.push(format!("{method} {url}"));
            Ok("200 OK".to_string())
        }
    }

    fn executor() -> SystemActionExecutor<MockApps, MockFiles, MockNet> {
        SystemActionExecutor::new(
            MockApps::default(),
            MockFiles::default(),
            MockNet::default(),
        )
    }

    #[test]
    fn dispatches_app_action_to_launcher() {
        let mut ex = executor();
        let out = ex
            .execute(&Action::LaunchApp {
                app: "editor".into(),
                args: alloc_vec(["a.txt"]),
            })
            .expect("ok");
        assert!(out.contains("launched editor"));
        assert_eq!(ex.apps.launched, alloc_vec(["editor"]));
    }

    #[test]
    fn dispatches_file_actions_to_fileops() {
        let mut ex = executor();
        ex.execute(&Action::ClassifyFile { path: "/a".into() })
            .expect("ok");
        ex.execute(&Action::MoveFile {
            from: "/a".into(),
            to: "/b".into(),
        })
        .expect("ok");
        ex.execute(&Action::DeleteFile { path: "/c".into() })
            .expect("ok");
        assert_eq!(
            ex.files.ops,
            alloc_vec(["classify /a", "move /a->/b", "delete /c"])
        );
    }

    #[test]
    fn dispatches_network_action_and_propagates_failure() {
        let mut ex = executor();
        ex.net.fail = true;
        let err = ex
            .execute(&Action::NetworkRequest {
                url: "https://x".into(),
                method: "GET".into(),
            })
            .unwrap_err();
        assert!(err.contains("network down"));
    }

    /// Build a `Vec<String>` from string literals (test helper).
    fn alloc_vec<const N: usize>(items: [&str; N]) -> Vec<String> {
        items.iter().map(|&s| s.to_string()).collect()
    }
}
