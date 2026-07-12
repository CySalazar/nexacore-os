//! Natural-language workflow generation (WS16-04.7).
//!
//! A user describes an automation in plain language ("when a file lands in
//! /Inbox, classify it and move it to Documents") and the AI runtime (WS5-03)
//! turns that intent into a structured [`Workflow`]. This module owns the
//! *protocol* of that generation — trimming and rejecting empty intents,
//! invoking the model behind a seam, and, crucially, **validating** whatever the
//! model returns before it is ever handed back.
//!
//! The generative model is untrusted: a hallucinated, malformed automation must
//! never reach the execution engine. [`generate_workflow`] therefore runs the
//! candidate through [`Workflow::validate`] and returns
//! [`GenerationError::Invalid`] if it does not conform — the same validation any
//! hand-authored or config-as-code workflow passes.
//!
//! Following the effects-behind-traits pattern (as in the WS16-06 system-AI
//! seams), the model itself lives behind [`WorkflowGenerator`]: production wires
//! an `ai_stream`-backed generator (WS5-03), while host tests use a
//! deterministic double.

use crate::model::{Workflow, WorkflowError};

/// Bridges the AI runtime (WS5-03): turns a natural-language intent into a
/// *candidate* [`Workflow`]. The candidate is not trusted until validated.
pub trait WorkflowGenerator {
    /// Produce a candidate workflow for `intent`, or a reason it could not.
    ///
    /// # Errors
    ///
    /// Returns `Err(reason)` if the model could not produce a candidate (e.g.
    /// the runtime is unavailable or refused the request).
    fn generate(&self, intent: &str) -> Result<Workflow, String>;
}

/// Why natural-language workflow generation failed (WS16-04.7).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GenerationError {
    /// The intent was empty or whitespace only.
    #[error("workflow generation intent is empty")]
    EmptyIntent,
    /// The model runtime could not produce a candidate.
    #[error("workflow generation model unavailable: {0}")]
    ModelUnavailable(String),
    /// The model produced a workflow that failed validation — rejected, not run.
    #[error("generated workflow is invalid: {0}")]
    Invalid(WorkflowError),
}

/// Generate a validated [`Workflow`] from a natural-language `intent`
/// (WS16-04.7).
///
/// The intent is trimmed and rejected if empty; the model is invoked behind the
/// [`WorkflowGenerator`] seam; and the candidate it returns MUST pass
/// [`Workflow::validate`] before it is returned. A malformed generation is a
/// hard failure ([`GenerationError::Invalid`]) — the generative path cannot
/// smuggle an invalid automation past the same checks every other workflow
/// faces.
///
/// # Errors
///
/// - [`GenerationError::EmptyIntent`] if `intent` is empty or whitespace.
/// - [`GenerationError::ModelUnavailable`] if the generator returns an error.
/// - [`GenerationError::Invalid`] if the generated workflow fails validation.
pub fn generate_workflow<G: WorkflowGenerator + ?Sized>(
    generator: &G,
    intent: &str,
) -> Result<Workflow, GenerationError> {
    let intent = intent.trim();
    if intent.is_empty() {
        return Err(GenerationError::EmptyIntent);
    }
    let workflow = generator
        .generate(intent)
        .map_err(GenerationError::ModelUnavailable)?;
    workflow.validate().map_err(GenerationError::Invalid)?;
    Ok(workflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Action, Step, Trigger};

    /// A deterministic stand-in for the WS5-03 model: returns whatever workflow
    /// it was configured with, or a fixed error, so the generation protocol can
    /// be tested without a real model.
    struct FixedGenerator(Result<Workflow, String>);

    impl WorkflowGenerator for FixedGenerator {
        fn generate(&self, _intent: &str) -> Result<Workflow, String> {
            self.0.clone()
        }
    }

    fn tidy_inbox() -> Workflow {
        Workflow::new(
            "tidy-inbox",
            Trigger::FileCreated {
                directory: "/Inbox".to_owned(),
            },
            vec![Step::new(
                "move it to Documents",
                Action::MoveFile {
                    from: "/Inbox/report.pdf".to_owned(),
                    to: "/Documents/report.pdf".to_owned(),
                },
            )],
        )
    }

    #[test]
    fn a_valid_generation_is_returned() {
        let generator = FixedGenerator(Ok(tidy_inbox()));
        let result = generate_workflow(&generator, "tidy my inbox");
        assert_eq!(result, Ok(tidy_inbox()));
    }

    #[test]
    fn an_empty_intent_is_rejected_before_the_model() {
        let generator = FixedGenerator(Ok(tidy_inbox()));
        assert_eq!(
            generate_workflow(&generator, "   "),
            Err(GenerationError::EmptyIntent)
        );
    }

    #[test]
    fn a_model_error_surfaces_as_model_unavailable() {
        let generator = FixedGenerator(Err("runtime offline".to_owned()));
        assert_eq!(
            generate_workflow(&generator, "do something"),
            Err(GenerationError::ModelUnavailable(
                "runtime offline".to_owned()
            ))
        );
    }

    #[test]
    fn a_malformed_generation_is_rejected_by_validation() {
        // The model hallucinated a workflow with no steps — it must not pass.
        let empty = Workflow::new("noop", Trigger::Manual, Vec::new());
        let generator = FixedGenerator(Ok(empty));
        assert_eq!(
            generate_workflow(&generator, "do nothing"),
            Err(GenerationError::Invalid(WorkflowError::NoSteps))
        );
    }

    #[test]
    fn a_generation_with_a_malformed_step_is_rejected() {
        // A step with an empty required field must be caught by validate().
        let bad = Workflow::new(
            "bad",
            Trigger::Manual,
            vec![Step::new(
                "delete nothing",
                Action::DeleteFile {
                    path: String::new(),
                },
            )],
        );
        let generator = FixedGenerator(Ok(bad));
        assert_eq!(
            generate_workflow(&generator, "delete the file"),
            Err(GenerationError::Invalid(WorkflowError::MalformedStep {
                index: 0
            }))
        );
    }
}
