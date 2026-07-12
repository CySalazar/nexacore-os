//! Contextual AI actions: selection → AI (WS16-03).
//!
//! NexaCore's AI is meant to be a selection away in every app: pick some text,
//! a file, or an image and act on it — *summarise*, *translate*, *explain*,
//! *rewrite*, *extract*, or hand it to an agent. This module is the toolkit-side
//! framework (`nexacore-ui`) that models that surface:
//!
//! - [`SelectionInput`] — what the user selected (text / file / image),
//!   captured from the active app (WS16-03.2/.3). A text selection is built
//!   straight from an [`crate::edit::TextBuffer`] selection.
//! - [`AiAction`] + [`applicable_actions`] — the contextual action set offered
//!   for a given input (WS16-03.1/.4).
//! - [`ActionCapability`] + [`authorize`] — every action is bound to the calling
//!   app's capability grant, so an app can only invoke the AI actions it was
//!   granted (WS16-03.7).
//! - [`TierRouter`] + [`ActionTokenizer`] + [`prepare_action`] — routing to the
//!   provider-agnostic runtime under the Tier policy (WS16-03.5, consumes WS5-05)
//!   and PII tokenisation on egress / detokenisation on ingress (WS16-03.6,
//!   consumes WS5-06/WS5-11). Both effects sit behind traits injected by the app
//!   layer (WS16-03.8), so the *policy* — derive the latency class, and never let
//!   a selection leave the origin device untokenised — stays pure and host-tested
//!   here, while the concrete router (`nexacore_runtime::router`) and tokeniser
//!   (`nexacore_tokenization`) live `std`-side and are wired in by the app.
//!
//! The native-app wiring (editor / file-manager) is WS16-03.8. Pure logic,
//! `no_std + alloc`, no runtime/tokenisation dependency.

use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};

use crate::edit::TextBuffer;

/// What the user selected, as input to an AI action (WS16-03.2/.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionInput {
    /// A run of selected text.
    Text(String),
    /// A selected file, by path + MIME type (contents fetched on demand).
    File {
        /// Absolute path of the selected file.
        path: String,
        /// MIME type of the file.
        mime: String,
    },
    /// A selected image, by MIME type + bytes.
    Image {
        /// MIME type of the image (e.g. `image/png`).
        mime: String,
        /// Raw image bytes.
        bytes: Vec<u8>,
    },
}

impl SelectionInput {
    /// Capture the current selection of a [`TextBuffer`] as a text input, or
    /// `None` when nothing is selected (WS16-03.2).
    #[must_use]
    pub fn from_text_selection(buffer: &TextBuffer) -> Option<Self> {
        buffer.selected_text().map(Self::Text)
    }

    /// Build a file input (WS16-03.3).
    #[must_use]
    pub fn file(path: &str, mime: &str) -> Self {
        Self::File {
            path: path.to_string(),
            mime: mime.to_string(),
        }
    }

    /// Build an image input (WS16-03.3).
    #[must_use]
    pub fn image(mime: &str, bytes: &[u8]) -> Self {
        Self::Image {
            mime: mime.to_string(),
            bytes: bytes.to_vec(),
        }
    }

    /// A stable kind tag, useful for routing and capability checks.
    #[must_use]
    pub fn kind(&self) -> InputKind {
        match self {
            Self::Text(_) => InputKind::Text,
            Self::File { .. } => InputKind::File,
            Self::Image { .. } => InputKind::Image,
        }
    }

    /// `true` when the selection carries no usable payload (empty text / empty
    /// image bytes). A file reference is never considered empty here.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Text(t) => t.is_empty(),
            Self::Image { bytes, .. } => bytes.is_empty(),
            Self::File { .. } => false,
        }
    }
}

/// The kind of a [`SelectionInput`], independent of its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InputKind {
    /// A text selection.
    Text,
    /// A file reference.
    File,
    /// An image payload.
    Image,
}

/// A contextual AI action offered on a selection (WS16-03.4).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AiAction {
    /// Condense the selection.
    Summarize,
    /// Translate the selection (into the given BCP-47 language tag).
    Translate(String),
    /// Explain the selection in plain language.
    Explain,
    /// Rewrite / rephrase the selection.
    Rewrite,
    /// Pull structured data out of the selection.
    Extract,
    /// Hand the selection to an agent to act on (agentic).
    Act,
    /// A first- or third-party custom action, by id.
    Custom(String),
}

impl AiAction {
    /// A stable, capability-checkable kind for this action (dropping any
    /// parameters like the translation target language).
    #[must_use]
    pub fn kind(&self) -> ActionKind {
        match self {
            Self::Summarize => ActionKind::Summarize,
            Self::Translate(_) => ActionKind::Translate,
            Self::Explain => ActionKind::Explain,
            Self::Rewrite => ActionKind::Rewrite,
            Self::Extract => ActionKind::Extract,
            Self::Act => ActionKind::Act,
            Self::Custom(_) => ActionKind::Custom,
        }
    }

    /// A short human-facing label for the action menu.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::Summarize => "Riassumi",
            Self::Translate(_) => "Traduci",
            Self::Explain => "Spiega",
            Self::Rewrite => "Riscrivi",
            Self::Extract => "Estrai",
            Self::Act => "Agisci",
            Self::Custom(id) => id,
        }
    }
}

/// Capability-checkable kind of an [`AiAction`] (WS16-03.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActionKind {
    /// Condense the selection.
    Summarize,
    /// Translate the selection.
    Translate,
    /// Explain the selection in plain language.
    Explain,
    /// Rewrite / rephrase the selection.
    Rewrite,
    /// Pull structured data out of the selection.
    Extract,
    /// Hand the selection to an agent.
    Act,
    /// A custom action.
    Custom,
}

/// The contextual action menu for a selection (WS16-03.1/.4): the ordered set of
/// actions applicable to `input`.
///
/// Text can be summarised, translated, explained, rewritten, extracted from, or
/// acted on. An image supports the vision-capable subset (summarise/describe,
/// explain, extract=OCR, act). A file supports summarise/explain/extract/act
/// (its bytes are read on demand). `Translate` is offered only for text, since
/// translating an image or opaque file is not meaningful without first
/// extracting its text.
#[must_use]
pub fn applicable_actions(input: &SelectionInput) -> Vec<AiAction> {
    match input.kind() {
        InputKind::Text => alloc::vec![
            AiAction::Summarize,
            AiAction::Translate(String::new()),
            AiAction::Explain,
            AiAction::Rewrite,
            AiAction::Extract,
            AiAction::Act,
        ],
        // Image (summarise/describe, explain, extract=OCR, act) and file
        // (bytes read on demand) share the same non-translate action set.
        InputKind::Image | InputKind::File => alloc::vec![
            AiAction::Summarize,
            AiAction::Explain,
            AiAction::Extract,
            AiAction::Act,
        ],
    }
}

/// An app's grant of which AI actions it may invoke (WS16-03.7).
///
/// Every contextual action is bound to the *calling app's* capability: the
/// action fires only if the app was granted that [`ActionKind`]. This keeps the
/// AI surface capability-bound rather than ambient.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActionCapability {
    app_id: String,
    allowed: BTreeSet<ActionKind>,
}

impl ActionCapability {
    /// A capability for `app_id` granting no actions.
    #[must_use]
    pub fn new(app_id: &str) -> Self {
        Self {
            app_id: app_id.to_string(),
            allowed: BTreeSet::new(),
        }
    }

    /// Grant `kind` (builder-style).
    #[must_use]
    pub fn grant(mut self, kind: ActionKind) -> Self {
        self.allowed.insert(kind);
        self
    }

    /// Grant every action kind (builder-style) — a fully-trusted first-party app.
    #[must_use]
    pub fn grant_all(mut self) -> Self {
        for k in [
            ActionKind::Summarize,
            ActionKind::Translate,
            ActionKind::Explain,
            ActionKind::Rewrite,
            ActionKind::Extract,
            ActionKind::Act,
            ActionKind::Custom,
        ] {
            self.allowed.insert(k);
        }
        self
    }

    /// The app this capability belongs to.
    #[must_use]
    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    /// Whether `kind` is granted.
    #[must_use]
    pub fn allows(&self, kind: ActionKind) -> bool {
        self.allowed.contains(&kind)
    }
}

/// Why an [`authorize`] check rejected an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionDenied {
    /// The calling app was not granted this action kind.
    NotPermitted,
    /// The selection carried no usable payload.
    EmptySelection,
}

/// Authorize `action` on `input` for the app holding `cap` (WS16-03.7).
///
/// Fails closed: an empty selection or a missing capability grant is rejected
/// before the action is ever routed to the runtime.
///
/// # Errors
///
/// - [`ActionDenied::EmptySelection`] when `input` has no payload.
/// - [`ActionDenied::NotPermitted`] when `cap` does not grant `action.kind()`.
pub fn authorize(
    cap: &ActionCapability,
    action: &AiAction,
    input: &SelectionInput,
) -> Result<(), ActionDenied> {
    if input.is_empty() {
        return Err(ActionDenied::EmptySelection);
    }
    if !cap.allows(action.kind()) {
        return Err(ActionDenied::NotPermitted);
    }
    Ok(())
}

/// How urgently the user is waiting on an action's result — an input to the
/// Tier-routing policy (WS5-05, which weighs latency alongside sensitivity).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LatencyClass {
    /// The user is blocked on the selection (summarise/translate/explain/rewrite
    /// /extract) — route for responsiveness.
    Interactive,
    /// An agentic task ([`AiAction::Act`]) that may run long — route as batch.
    Batch,
}

impl AiAction {
    /// The latency class this action should be routed with (WS16-03.5).
    ///
    /// Selection-driven actions block the user and are [`Interactive`]; handing
    /// the selection to an agent ([`Self::Act`]) is a potentially long-running
    /// [`Batch`] task.
    ///
    /// [`Interactive`]: LatencyClass::Interactive
    /// [`Batch`]: LatencyClass::Batch
    #[must_use]
    pub fn latency_class(&self) -> LatencyClass {
        match self {
            Self::Act => LatencyClass::Batch,
            _ => LatencyClass::Interactive,
        }
    }
}

/// The execution tier an action was routed to — the UI-facing projection of
/// `nexacore_runtime::router::ExecutionTier` (WS5-05).
///
/// The framework keeps its own small mirror so it needn't depend on the `std`
/// runtime crate; the app's [`TierRouter`] maps between the two. [`badge`]
/// returns the stable backend badges defined by WS5-05.7, so the UI can show the
/// user which tier answered (a privacy-transparency cue: `local` vs `cloud`).
///
/// [`badge`]: RouteTier::badge
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteTier {
    /// Tier 0 — on the origin device.
    Local,
    /// Tier 1 — the user's personal cluster.
    PersonalCluster,
    /// Tier 2 — the federated mesh.
    FederatedMesh,
    /// Tier 3 — the cloud.
    Cloud,
}

impl RouteTier {
    /// The stable backend badge for this tier, matching WS5-05.7
    /// (`local` / `personal-cluster` / `mesh` / `cloud`).
    #[must_use]
    pub fn badge(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::PersonalCluster => "personal-cluster",
            Self::FederatedMesh => "mesh",
            Self::Cloud => "cloud",
        }
    }

    /// `true` only for [`Self::Local`]: the workload runs on the origin device
    /// and never crosses a process/device boundary. Drives the egress
    /// tokenisation gate in [`prepare_action`].
    #[must_use]
    pub fn is_on_device(self) -> bool {
        matches!(self, Self::Local)
    }
}

/// A provider-agnostic AI request the runtime dispatches (WS16-03.5).
///
/// Built from an authorised (action, selection) pair; carries the derived
/// [`LatencyClass`] so the router can honour the Tier policy. After
/// [`prepare_action`] its `input` is the *egress-safe* selection: on-device when
/// routed [`RouteTier::Local`], tokenised otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiActionRequest {
    /// The action to run.
    pub action: AiAction,
    /// The (possibly tokenised) selection to run it on.
    pub input: SelectionInput,
    /// The latency class to route with.
    pub latency: LatencyClass,
}

/// Seam to the Tier-policy router (WS5-05).
///
/// Implemented at the app layer (WS16-03.8) by delegating to
/// `nexacore_runtime::router::decide_tier`, which weighs the selection's
/// sensitivity, the request's latency, resource availability and cloud consent.
pub trait TierRouter {
    /// Decide the execution tier for `request`.
    fn route(&self, request: &AiActionRequest) -> RouteTier;
}

/// The on-device tokenisation pipeline was unavailable (WS5-11 fail-closed).
///
/// A zero-sized marker returned by [`ActionTokenizer::tokenize_egress`] so the
/// framework can refuse an off-device action rather than sending raw PII out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenizationUnavailable;

/// Seam to the on-device tokenisation / PII vault service (WS5-06, WS5-11).
///
/// Implemented at the app layer over `nexacore_tokenization`. The framework
/// calls [`tokenize_egress`] before a selection may leave the origin device, and
/// [`detokenize_ingress`] to restore the model's answer — detokenisation is
/// permitted *only on the origin device*, inside its local sealing perimeter.
///
/// [`tokenize_egress`]: ActionTokenizer::tokenize_egress
/// [`detokenize_ingress`]: ActionTokenizer::detokenize_ingress
pub trait ActionTokenizer {
    /// Tokenise any PII in an outbound selection before it leaves the device.
    ///
    /// # Errors
    ///
    /// Returns [`TokenizationUnavailable`] when the pipeline is down; the
    /// framework then refuses the action rather than sending raw PII out
    /// (fail-closed, WS5-11).
    fn tokenize_egress(
        &self,
        input: &SelectionInput,
    ) -> Result<SelectionInput, TokenizationUnavailable>;

    /// Detokenise the model's response on ingress (origin device only).
    fn detokenize_ingress(&self, output: &str) -> String;
}

/// Why [`prepare_action`] refused to route an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionError {
    /// The action failed the capability / empty-selection check (WS16-03.7).
    Denied(ActionDenied),
    /// The action was routed off-device but the on-device tokenisation pipeline
    /// was unavailable, so it was refused rather than sent out untokenised
    /// (fail-closed, WS5-11).
    TokenizationUnavailable,
}

impl From<ActionDenied> for ActionError {
    fn from(d: ActionDenied) -> Self {
        Self::Denied(d)
    }
}

/// An authorised, routed, egress-safe action ready to dispatch (WS16-03.5/.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedAction {
    /// The request to dispatch; its `input` is already egress-safe.
    pub request: AiActionRequest,
    /// The tier it was routed to.
    pub tier: RouteTier,
}

/// Authorise (WS16-03.7) → route per the Tier policy (WS16-03.5) → tokenise the
/// selection on egress for any off-device tier (WS16-03.6). Fail-closed.
///
/// This is the single entry point an app uses to turn a picked menu action into
/// a dispatchable request. The order matters: authorisation and the
/// empty-selection check run *before* anything is routed; the egress
/// tokenisation gate runs *before* the request is handed back, so a
/// [`RoutedAction`] can never carry raw PII bound for an off-device tier.
///
/// # Errors
///
/// - [`ActionError::Denied`] when [`authorize`] rejects the action.
/// - [`ActionError::TokenizationUnavailable`] when the action routes off-device
///   but the tokeniser cannot sanitise the selection.
pub fn prepare_action(
    cap: &ActionCapability,
    action: AiAction,
    input: SelectionInput,
    router: &dyn TierRouter,
    tokenizer: &dyn ActionTokenizer,
) -> Result<RoutedAction, ActionError> {
    authorize(cap, &action, &input)?;
    let latency = action.latency_class();
    let request = AiActionRequest {
        action,
        input,
        latency,
    };
    let tier = router.route(&request);
    // WS5-11 invariant: nothing leaves the origin device untokenised.
    let request = if tier.is_on_device() {
        request
    } else {
        let input = tokenizer
            .tokenize_egress(&request.input)
            .map_err(|TokenizationUnavailable| ActionError::TokenizationUnavailable)?;
        AiActionRequest { input, ..request }
    };
    Ok(RoutedAction { request, tier })
}

/// Restore an AI result on ingress (WS16-03.6).
///
/// On-device results were never tokenised, so they pass through untouched; an
/// off-device result is detokenised via the origin device's vault. Keeping this
/// symmetric with [`prepare_action`]'s egress gate means the round trip is
/// PII-safe end to end.
#[must_use]
pub fn restore_result(
    routed: &RoutedAction,
    tokenizer: &dyn ActionTokenizer,
    output: &str,
) -> String {
    if routed.tier.is_on_device() {
        output.to_string()
    } else {
        tokenizer.detokenize_ingress(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_selection_captured_from_buffer() {
        let mut buf = TextBuffer::from_text("hello world");
        buf.select_range(6, 11);
        let input = SelectionInput::from_text_selection(&buf).unwrap();
        assert_eq!(input, SelectionInput::Text("world".to_string()));
        assert_eq!(input.kind(), InputKind::Text);
    }

    #[test]
    fn no_selection_captures_nothing() {
        let buf = TextBuffer::from_text("hello");
        assert!(SelectionInput::from_text_selection(&buf).is_none());
    }

    #[test]
    fn text_offers_the_full_action_set_including_translate() {
        let input = SelectionInput::Text("ciao".to_string());
        let actions = applicable_actions(&input);
        assert!(actions.contains(&AiAction::Summarize));
        assert!(actions.iter().any(|a| a.kind() == ActionKind::Translate));
        assert!(actions.contains(&AiAction::Act));
    }

    #[test]
    fn image_and_file_omit_translate() {
        let img = SelectionInput::image("image/png", &[1, 2, 3]);
        let file = SelectionInput::file("/docs/a.pdf", "application/pdf");
        for input in [img, file] {
            let actions = applicable_actions(&input);
            assert!(
                !actions.iter().any(|a| a.kind() == ActionKind::Translate),
                "translate should not be offered for {:?}",
                input.kind()
            );
            assert!(actions.contains(&AiAction::Extract)); // OCR / structured pull
        }
    }

    #[test]
    fn action_labels_are_present() {
        assert_eq!(AiAction::Summarize.label(), "Riassumi");
        assert_eq!(AiAction::Custom("Ripara".to_string()).label(), "Ripara");
    }

    #[test]
    fn translate_kind_drops_the_language_param() {
        assert_eq!(
            AiAction::Translate("en".to_string()).kind(),
            ActionKind::Translate
        );
        assert_eq!(
            AiAction::Translate("de".to_string()).kind(),
            ActionKind::Translate
        );
    }

    #[test]
    fn authorize_requires_the_capability_grant() {
        let input = SelectionInput::Text("x".to_string());
        let cap = ActionCapability::new("editor").grant(ActionKind::Summarize);
        assert_eq!(authorize(&cap, &AiAction::Summarize, &input), Ok(()));
        // Rewrite was not granted.
        assert_eq!(
            authorize(&cap, &AiAction::Rewrite, &input),
            Err(ActionDenied::NotPermitted)
        );
    }

    #[test]
    fn authorize_rejects_empty_selection_first() {
        let input = SelectionInput::Text(String::new());
        let cap = ActionCapability::new("editor").grant_all();
        assert_eq!(
            authorize(&cap, &AiAction::Summarize, &input),
            Err(ActionDenied::EmptySelection)
        );
    }

    #[test]
    fn empty_image_is_empty_but_file_is_not() {
        assert!(SelectionInput::image("image/png", &[]).is_empty());
        assert!(!SelectionInput::file("/a", "text/plain").is_empty());
    }

    #[test]
    fn grant_all_permits_every_kind() {
        let cap = ActionCapability::new("nexacore-editor").grant_all();
        assert_eq!(cap.app_id(), "nexacore-editor");
        for kind in [
            ActionKind::Summarize,
            ActionKind::Translate,
            ActionKind::Explain,
            ActionKind::Rewrite,
            ActionKind::Extract,
            ActionKind::Act,
            ActionKind::Custom,
        ] {
            assert!(cap.allows(kind));
        }
    }

    // --- WS16-03.5/.6: routing + tokenisation seam -------------------------

    /// A router pinned to one tier, for asserting the egress gate.
    struct FixedRouter(RouteTier);
    impl TierRouter for FixedRouter {
        fn route(&self, _request: &AiActionRequest) -> RouteTier {
            self.0
        }
    }

    /// A tokeniser that brackets text with `TOK(..)` on egress and strips it on
    /// ingress; `available` toggles the fail-closed path.
    struct FakeTokenizer {
        available: bool,
    }
    impl ActionTokenizer for FakeTokenizer {
        fn tokenize_egress(
            &self,
            input: &SelectionInput,
        ) -> Result<SelectionInput, TokenizationUnavailable> {
            if !self.available {
                return Err(TokenizationUnavailable);
            }
            match input {
                SelectionInput::Text(t) => Ok(SelectionInput::Text(alloc::format!("TOK({t})"))),
                other => Ok(other.clone()),
            }
        }
        fn detokenize_ingress(&self, output: &str) -> String {
            output
                .strip_prefix("TOK(")
                .and_then(|s| s.strip_suffix(')'))
                .map_or_else(|| output.to_string(), ToString::to_string)
        }
    }

    fn editor_cap() -> ActionCapability {
        ActionCapability::new("nexacore-editor").grant_all()
    }

    #[test]
    fn latency_class_is_batch_only_for_act() {
        assert_eq!(AiAction::Act.latency_class(), LatencyClass::Batch);
        for a in [
            AiAction::Summarize,
            AiAction::Translate("en".to_string()),
            AiAction::Explain,
            AiAction::Rewrite,
            AiAction::Extract,
        ] {
            assert_eq!(a.latency_class(), LatencyClass::Interactive);
        }
    }

    #[test]
    fn route_tier_badges_match_ws5_05() {
        assert_eq!(RouteTier::Local.badge(), "local");
        assert_eq!(RouteTier::PersonalCluster.badge(), "personal-cluster");
        assert_eq!(RouteTier::FederatedMesh.badge(), "mesh");
        assert_eq!(RouteTier::Cloud.badge(), "cloud");
        assert!(RouteTier::Local.is_on_device());
        assert!(!RouteTier::Cloud.is_on_device());
    }

    #[test]
    fn prepare_action_authorizes_before_routing() {
        let cap = ActionCapability::new("editor").grant(ActionKind::Summarize);
        let input = SelectionInput::Text("secret note".to_string());
        let router = FixedRouter(RouteTier::Local);
        let tok = FakeTokenizer { available: true };
        // Rewrite was never granted → denied before any routing happens.
        assert_eq!(
            prepare_action(&cap, AiAction::Rewrite, input, &router, &tok),
            Err(ActionError::Denied(ActionDenied::NotPermitted))
        );
    }

    #[test]
    fn on_device_routing_leaves_selection_untokenized() {
        let input = SelectionInput::Text("private data".to_string());
        let router = FixedRouter(RouteTier::Local);
        let tok = FakeTokenizer { available: true };
        let prepared = prepare_action(
            &editor_cap(),
            AiAction::Summarize,
            input.clone(),
            &router,
            &tok,
        )
        .unwrap();
        assert_eq!(prepared.tier, RouteTier::Local);
        assert_eq!(prepared.request.input, input); // raw text stayed raw on-device
        assert_eq!(prepared.request.latency, LatencyClass::Interactive);
    }

    #[test]
    fn off_device_routing_tokenizes_selection_on_egress() {
        let input = SelectionInput::Text("alice@example.com".to_string());
        let router = FixedRouter(RouteTier::Cloud);
        let tok = FakeTokenizer { available: true };
        let prepared =
            prepare_action(&editor_cap(), AiAction::Summarize, input, &router, &tok).unwrap();
        assert_eq!(prepared.tier, RouteTier::Cloud);
        // The selection was sanitised before it could leave the device.
        assert_eq!(
            prepared.request.input,
            SelectionInput::Text("TOK(alice@example.com)".to_string())
        );
    }

    #[test]
    fn off_device_routing_fails_closed_when_tokenizer_unavailable() {
        let input = SelectionInput::Text("ssn 123-45-6789".to_string());
        let router = FixedRouter(RouteTier::FederatedMesh);
        let tok = FakeTokenizer { available: false };
        // Pipeline down + off-device tier ⇒ refuse, never send raw PII out.
        assert_eq!(
            prepare_action(&editor_cap(), AiAction::Summarize, input, &router, &tok),
            Err(ActionError::TokenizationUnavailable)
        );
    }

    #[test]
    fn restore_result_detokenizes_only_off_device() {
        let tok = FakeTokenizer { available: true };
        let base = AiActionRequest {
            action: AiAction::Summarize,
            input: SelectionInput::Text("x".to_string()),
            latency: LatencyClass::Interactive,
        };
        let local = RoutedAction {
            request: base.clone(),
            tier: RouteTier::Local,
        };
        let cloud = RoutedAction {
            request: base,
            tier: RouteTier::Cloud,
        };
        // On-device answers were never tokenised → passthrough.
        assert_eq!(restore_result(&local, &tok, "TOK(bob)"), "TOK(bob)");
        // Off-device answers are detokenised on the origin device.
        assert_eq!(restore_result(&cloud, &tok, "TOK(bob)"), "bob");
    }
}
