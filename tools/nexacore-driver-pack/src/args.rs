//! Command-line argument parsing for `nexacore-driver-pack`.
//!
//! Arguments are parsed manually from [`std::env::args`] — no external
//! parser dependency is required for the simple four-flag surface.

// In a binary crate's private module, `pub(super)` is technically redundant
// (the parent can always access private-module items), but it documents that
// these items are intentionally visible to `main.rs` and nothing else.
// `clippy::redundant_pub_crate` fires for `pub(super)` in private modules, so
// we suppress it at file scope rather than fighting the `pub` / `pub(crate)` /
// `pub(super)` three-way lint conflict.
#![allow(clippy::redundant_pub_crate)]

use std::path::PathBuf;

use nexacore_driver_pack::error::PackError;

/// Parsed, validated command-line arguments for `nexacore-driver-pack`.
///
/// All four positional flags are required; absence of any one is
/// reported as [`PackError::MissingArg`] with exit code 1.
pub(super) struct Args {
    /// Path to the driver manifest (`--manifest`). Format is
    /// auto-detected from the file extension: `.toml` → TOML
    /// (NCIP-Driver-Framework-013 § R4 canonical format); any
    /// other extension → JSON (backwards-compatible).
    pub(super) manifest: PathBuf,
    /// Path to the Ring 3 ELF image (`--image`).
    pub(super) image: PathBuf,
    /// Path to the 32-byte Ed25519 seed file (`--signing-key`).
    pub(super) signing_key: PathBuf,
    /// Desired output path for the `.opack` blob (`--output`).
    pub(super) output: PathBuf,
    /// If `true`, the signing-key file permission warning is suppressed
    /// (`--allow-loose-permissions`).
    pub(super) allow_loose_permissions: bool,
}

impl Args {
    /// Parse [`std::env::args`] into an [`Args`] value.
    ///
    /// Recognizes:
    /// - `--manifest <path>` (required)
    /// - `--image <path>` (required)
    /// - `--signing-key <path>` (required)
    /// - `--output <path>` (required)
    /// - `--allow-loose-permissions` (optional flag)
    /// - `--help` / `-h` — prints help and exits 0
    /// - `--version` / `-V` — prints version and exits 0
    ///
    /// # Errors
    ///
    /// Returns [`PackError::MissingArg`] when a required flag is absent,
    /// or [`PackError::UnknownArg`] when an unrecognized flag is passed.
    // `std::process::exit` and `println!` are intentionally used here: the
    // `--help` / `--version` handlers are CLI exits, not library logic.  The
    // project's `disallowed_*` lints guard against accidental use in library
    // code; these binary-local uses are the exact cases the lint notes permit.
    #[allow(clippy::disallowed_methods, clippy::disallowed_macros)]
    pub(super) fn parse() -> Result<Self, PackError> {
        let mut iter = std::env::args().skip(1);

        let mut manifest: Option<PathBuf> = None;
        let mut image: Option<PathBuf> = None;
        let mut signing_key: Option<PathBuf> = None;
        let mut output: Option<PathBuf> = None;
        let mut allow_loose = false;

        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "--help" | "-h" => {
                    print!("{}", help_text());
                    std::process::exit(0);
                }
                "--version" | "-V" => {
                    println!("nexacore-driver-pack {}", env!("CARGO_PKG_VERSION"));
                    std::process::exit(0);
                }
                "--manifest" => {
                    let val = iter.next().ok_or(PackError::MissingArg("manifest"))?;
                    manifest = Some(PathBuf::from(val));
                }
                "--image" => {
                    let val = iter.next().ok_or(PackError::MissingArg("image"))?;
                    image = Some(PathBuf::from(val));
                }
                "--signing-key" => {
                    let val = iter.next().ok_or(PackError::MissingArg("signing-key"))?;
                    signing_key = Some(PathBuf::from(val));
                }
                "--output" => {
                    let val = iter.next().ok_or(PackError::MissingArg("output"))?;
                    output = Some(PathBuf::from(val));
                }
                "--allow-loose-permissions" => {
                    allow_loose = true;
                }
                other => {
                    return Err(PackError::UnknownArg(other.to_string()));
                }
            }
        }

        Ok(Self {
            manifest: manifest.ok_or(PackError::MissingArg("manifest"))?,
            image: image.ok_or(PackError::MissingArg("image"))?,
            signing_key: signing_key.ok_or(PackError::MissingArg("signing-key"))?,
            output: output.ok_or(PackError::MissingArg("output"))?,
            allow_loose_permissions: allow_loose,
        })
    }
}

/// Return the `--help` text for `nexacore-driver-pack`.
fn help_text() -> String {
    format!(
        concat!(
            "nexacore-driver-pack {version}\n",
            "\n",
            "NexaCore OS driver-pack v1 producer (NCIP-013 § S5.5).\n",
            "Converts a TOML / JSON driver manifest + Ring 3 ELF image into a\n",
            "signed NexaCore-Pack v1 (.opack) blob for ingestion by DriverLoad\n",
            "(syscall 73). TOML is the canonical developer-side format per\n",
            "NCIP-013 § R4; JSON is supported for backwards compatibility.\n",
            "\n",
            "USAGE:\n",
            "  nexacore-driver-pack --manifest <path> --image <path> \\\n",
            "                   --signing-key <path> --output <path> [OPTIONS]\n",
            "\n",
            "REQUIRED FLAGS:\n",
            "  --manifest <path>      Driver manifest (.toml or .json — format\n",
            "                         auto-detected from extension)\n",
            "  --image <path>         Ring 3 ELF image file\n",
            "  --signing-key <path>   64-char hex Ed25519 seed file (32 raw bytes)\n",
            "  --output <path>        Output .opack file path\n",
            "\n",
            "OPTIONS:\n",
            "  --allow-loose-permissions   Suppress signing-key permission warning\n",
            "  --help, -h                  Print this help and exit 0\n",
            "  --version, -V               Print version and exit 0\n",
            "\n",
            "EXIT CODES:\n",
            "  0  success\n",
            "  1  usage / I/O error\n",
            "  2  manifest parse error\n",
            "  3  signing key error\n",
            "  4  pack build / write error\n",
            "\n",
            "JSON MANIFEST SCHEMA (see tools/nexacore-driver-pack/README.md):\n",
            "  {{\n",
            "    \"meta\": {{\n",
            "      \"name\": \"nexacore-driver-net-virtio\",\n",
            "      \"version\": \"0.2.0\",\n",
            "      \"nexacore_issuer_pubkey\": \"<64 lowercase hex chars>\"\n",
            "    }},\n",
            "    \"capabilities\": {{\n",
            "      \"mmio_regions\": [ {{ \"MmioRegion\": {{ \"phys_base\": 4294967296, \"len\": 65536 }} }} ],\n",
            "      \"dma_windows\":  [ {{ \"DmaWindow\":  {{ \"iova_base\": 0, \"len\": 4294967296 }} }} ],\n",
            "      \"irq_lines\":    [],\n",
            "      \"pci_devices\":  []\n",
            "    }},\n",
            "    \"matchers\": {{\n",
            "      \"pci_vendor_device\": [ {{ \"vendor\": 6900, \"device\": 4161 }} ],\n",
            "      \"acpi_hid\": []\n",
            "    }}\n",
            "  }}\n",
            "\n",
            "SIGNING KEY FORMAT:\n",
            "  A file containing exactly 64 lowercase hex chars (= 32 raw bytes),\n",
            "  optionally followed by a single newline. The Ed25519 verifying key\n",
            "  is derived deterministically from this seed. The derived key MUST\n",
            "  match nexacore_issuer_pubkey in the JSON manifest.\n",
        ),
        version = env!("CARGO_PKG_VERSION")
    )
}
