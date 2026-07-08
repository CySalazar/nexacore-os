//! ncScript tree-walking interpreter (WS18-02.4) over the [`crate::ast`],
//! with a reference-counted value model (WS18-02.5).
//!
//! Heap values (strings, lists, structs, enum payloads) are held behind
//! [`alloc::rc::Rc`] / [`core::cell::RefCell`], giving the
//! value-semantics-with-reference-counting model of `NCIP-ncScript-030` § S3.
//! Cycle collection (the GC half of § S3) is a documented follow-up; v1 relies
//! on reference counting.
//!
//! Scope of this milestone (WS18-02.4): scalars, arithmetic (checked integer,
//! IEEE float), comparisons, short-circuit boolean logic, `let`/assignment with
//! lexical scoping, blocks, `if`, `while`, `for` over lists, `loop` with
//! `break`/`continue`, user functions + recursion, `return`, list/struct/enum
//! construction, field/index access, `match` (wildcard / literal / binding /
//! variant / or-patterns + guards), the `?` operator on `Result`/`Option`, and
//! a small built-in surface (`print`, `len`, list `push`, `to_string`).
//! Capability gating (WS18-02.9/.10) and deterministic resource limits
//! (WS18-02.6/.7/.8) build on this in later milestones.

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    format,
    rc::Rc,
    string::{String, ToString},
    vec::Vec,
};
use core::cell::{Cell, RefCell};

use crate::{
    ast::{BinOp, Block, CapScope, Expr, FnDef, Item, MatchArm, Pattern, Program, Stmt, UnOp},
    parser::{ParseError, parse},
};

/// Shared live-memory account: the total bytes currently held by heap values
/// charged against the interpreter's [`Limits::max_alloc_bytes`] budget.
type MemAccount = Rc<Cell<usize>>;

/// An opaque RAII charge against the interpreter's live-memory account.
///
/// Each heap [`Value`] holds one, shared via [`Rc`], so when the value's last
/// reference is dropped the bytes are credited back — giving a *live* (not
/// cumulative) memory limit (WS18-02.7). The inner byte count is a [`Cell`] so
/// in-place growth (e.g. list `push`) can be charged onto the same guard.
/// It has no public fields or methods; pattern-match heap values with `_` to
/// ignore it.
#[derive(Debug)]
pub struct MemGuard {
    bytes: Cell<usize>,
    account: MemAccount,
}

impl Drop for MemGuard {
    fn drop(&mut self) {
        let credited = self.account.get().saturating_sub(self.bytes.get());
        self.account.set(credited);
    }
}

/// A runtime value. Heap-backed variants share their payload and a
/// [`MemGuard`] via [`Rc`] (reference-counted value semantics, § S3).
#[derive(Debug, Clone)]
pub enum Value {
    /// The unit value `()`.
    Unit,
    /// Boolean.
    Bool(bool),
    /// 64-bit signed integer.
    Int(i64),
    /// 64-bit float.
    Float(f64),
    /// String (shared) + its memory guard.
    Str(Rc<String>, Rc<MemGuard>),
    /// List (shared, mutable) + its memory guard.
    List(Rc<RefCell<Vec<Value>>>, Rc<MemGuard>),
    /// Struct instance: type name + named fields (shared, mutable).
    Struct {
        /// The struct type name.
        name: String,
        /// Field values by name.
        fields: Rc<RefCell<BTreeMap<String, Value>>>,
        /// Memory guard.
        guard: Rc<MemGuard>,
    },
    /// Enum value: enum name, variant name, positional payload.
    Enum {
        /// The enum type name (`Result`/`Option` for built-ins).
        enum_name: String,
        /// The variant name.
        variant: String,
        /// Positional payload.
        payload: Rc<Vec<Value>>,
        /// Memory guard.
        guard: Rc<MemGuard>,
    },
}

impl Value {
    /// The value's type name, for diagnostics.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Unit => "unit",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::Str(..) => "string",
            Self::List(..) => "list",
            Self::Struct { .. } => "struct",
            Self::Enum { .. } => "enum",
        }
    }

    /// Render the value for `print` / `to_string`.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Unit => String::from("()"),
            Self::Bool(b) => b.to_string(),
            Self::Int(i) => i.to_string(),
            Self::Float(x) => x.to_string(),
            Self::Str(s, _) => (**s).clone(),
            Self::List(items, _) => {
                let mut out = String::from("[");
                for (i, v) in items.borrow().iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&v.display());
                }
                out.push(']');
                out
            }
            Self::Struct { name, fields, .. } => {
                let mut out = format!("{name} {{ ");
                for (i, (k, v)) in fields.borrow().iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&format!("{k}: {}", v.display()));
                }
                out.push_str(" }");
                out
            }
            Self::Enum {
                variant, payload, ..
            } => {
                if payload.is_empty() {
                    variant.clone()
                } else {
                    let mut out = format!("{variant}(");
                    for (i, v) in payload.iter().enumerate() {
                        if i > 0 {
                            out.push_str(", ");
                        }
                        out.push_str(&v.display());
                    }
                    out.push(')');
                    out
                }
            }
        }
    }

    /// Truthiness for conditions (only `Bool` is allowed; everything else is a
    /// type error reported by the caller).
    fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// Structural value equality (for `==`/`!=` and literal patterns).
#[must_use]
pub fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Unit, Value::Unit) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Int(x), Value::Int(y)) => x == y,
        #[allow(
            clippy::float_cmp,
            reason = "ncScript `==` on floats is bit-for-bit value equality"
        )]
        (Value::Float(x), Value::Float(y)) => x == y,
        (Value::Str(x, _), Value::Str(y, _)) => x == y,
        (Value::List(x, _), Value::List(y, _)) => {
            let (x, y) = (x.borrow(), y.borrow());
            x.len() == y.len() && x.iter().zip(y.iter()).all(|(a, b)| values_equal(a, b))
        }
        (
            Value::Enum {
                enum_name: en1,
                variant: v1,
                payload: p1,
                ..
            },
            Value::Enum {
                enum_name: en2,
                variant: v2,
                payload: p2,
                ..
            },
        ) => {
            en1 == en2
                && v1 == v2
                && p1.len() == p2.len()
                && p1.iter().zip(p2.iter()).all(|(a, b)| values_equal(a, b))
        }
        _ => false,
    }
}

/// A runtime error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    /// Reference to an unbound name.
    Undefined(String),
    /// An operation applied to the wrong type.
    Type(String),
    /// Callee is not a function.
    NotCallable(String),
    /// Wrong number of arguments.
    Arity {
        /// Function name.
        func: String,
        /// Expected count.
        expected: usize,
        /// Supplied count.
        got: usize,
    },
    /// Integer overflow or divide-by-zero.
    Arithmetic(&'static str),
    /// List index out of bounds.
    IndexOutOfBounds,
    /// No such field on a struct.
    NoField(String),
    /// No such method on the value.
    NoMethod(String),
    /// `match` had no arm covering the value.
    NonExhaustiveMatch,
    /// A value was used as a condition but is not a bool.
    NotBool(&'static str),
    /// A deterministic resource limit was hit; the run was cleanly aborted.
    LimitExceeded(Limit),
    /// An effect was attempted without the required capability being granted
    /// (deny-by-default, WS18-02.10). Holds the denied capability name.
    CapabilityDenied(String),
    /// A generic message.
    Msg(String),
}

/// Which deterministic resource limit was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// The instruction / evaluation-step budget (WS18-02.6).
    Steps,
    /// The live heap-memory budget (WS18-02.7).
    Memory,
    /// The wall-clock deadline, read from the injected [`Clock`] (WS18-02.8).
    Time,
    /// The maximum function-call recursion depth.
    CallDepth,
}

impl core::fmt::Display for Limit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Steps => "instruction budget",
            Self::Memory => "memory budget",
            Self::Time => "time deadline",
            Self::CallDepth => "call-depth limit",
        })
    }
}

impl core::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Undefined(n) => write!(f, "undefined name `{n}`"),
            Self::Type(m) => write!(f, "type error: {m}"),
            Self::NotCallable(n) => write!(f, "`{n}` is not callable"),
            Self::Arity {
                func,
                expected,
                got,
            } => write!(f, "`{func}` expected {expected} args, got {got}"),
            Self::Arithmetic(m) => write!(f, "arithmetic error: {m}"),
            Self::IndexOutOfBounds => f.write_str("index out of bounds"),
            Self::NoField(n) => write!(f, "no field `{n}`"),
            Self::NoMethod(n) => write!(f, "no method `{n}`"),
            Self::NonExhaustiveMatch => f.write_str("no match arm covered the value"),
            Self::NotBool(ctx) => write!(f, "{ctx} condition is not a bool"),
            Self::LimitExceeded(limit) => write!(f, "resource limit exceeded: {limit}"),
            Self::CapabilityDenied(cap) => write!(f, "capability denied: `{cap}`"),
            Self::Msg(m) => f.write_str(m),
        }
    }
}

impl core::error::Error for RuntimeError {}

/// Non-local control flow threaded through evaluation.
enum Control {
    Error(RuntimeError),
    Return(Value),
    Break(Option<String>, Value),
    Continue(Option<String>),
}

impl From<RuntimeError> for Control {
    fn from(e: RuntimeError) -> Self {
        Self::Error(e)
    }
}

type Eval<T> = Result<T, Control>;

/// A monotonic time source the interpreter polls to enforce the time limit
/// (WS18-02.8).
///
/// The runtime is `no_std` and has no ambient clock, so the embedder injects
/// one. On the host this can wrap `std::time::Instant`; on bare metal it can
/// read a monotonic counter. Tests use a deterministic tick source.
pub trait Clock {
    /// The current time in microseconds, monotonic and non-decreasing.
    fn now_micros(&self) -> u64;
}

/// Deterministic resource limits for a run.
///
/// All `None` (the [`Default`]) means unlimited. Exceeding any limit aborts the
/// run cleanly with [`RuntimeError::LimitExceeded`] — never a panic or partial
/// state leak.
#[derive(Debug, Clone, Default)]
pub struct Limits {
    /// Maximum evaluation steps before aborting (WS18-02.6).
    pub max_steps: Option<u64>,
    /// Maximum live heap bytes held by values at once (WS18-02.7). This is a
    /// *live* budget: memory freed when a value's last reference drops is
    /// credited back, so a script that reuses a binding does not accumulate.
    pub max_alloc_bytes: Option<usize>,
    /// Absolute deadline in [`Clock::now_micros`] units (WS18-02.8). Requires a
    /// clock to be set via [`Interpreter::with_clock`]; ignored otherwise.
    pub deadline_micros: Option<u64>,
    /// Maximum function-call recursion depth (guards against stack overflow).
    pub max_call_depth: Option<usize>,
}

/// A single capability: a dotted effect name (e.g. `fs.read`, `net.connect`)
/// with an optional scope (e.g. a path prefix or host).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    /// Dotted capability name.
    pub name: String,
    /// Optional scope; `None` means "any argument".
    pub scope: Option<String>,
}

impl Capability {
    /// A capability for `name` with no scope restriction.
    #[must_use]
    pub fn any(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            scope: None,
        }
    }

    /// A capability for `name` scoped to `scope`.
    #[must_use]
    pub fn scoped(name: impl Into<String>, scope: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            scope: Some(scope.into()),
        }
    }

    /// Whether this grant covers an effect `name` invoked with optional `arg`.
    #[must_use]
    fn covers(&self, name: &str, arg: Option<&str>) -> bool {
        if self.name != name {
            return false;
        }
        // An unscoped grant covers any argument; a scoped grant requires an
        // argument equal to, or hierarchically under, the scope (`/` boundary).
        self.scope
            .as_ref()
            .is_none_or(|s| arg.is_some_and(|a| a == s || a.starts_with(&format!("{s}/"))))
    }
}

/// The set of capabilities granted to a script at invocation (WS18-02.9).
///
/// Empty is deny-all: with no grant, every effect is denied. This is the
/// runtime authority for the capability gate (WS18-02.10).
#[derive(Debug, Clone, Default)]
pub struct Grants {
    caps: Vec<Capability>,
}

impl Grants {
    /// An empty grant set (deny-all).
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Build a grant set from a list of capabilities.
    #[must_use]
    pub fn from_caps(caps: Vec<Capability>) -> Self {
        Self { caps }
    }

    /// Add a capability (builder style).
    #[must_use]
    pub fn with(mut self, cap: Capability) -> Self {
        self.caps.push(cap);
        self
    }

    /// Whether an effect `name` invoked with optional argument `arg` is granted.
    #[must_use]
    pub fn allows(&self, name: &str, arg: Option<&str>) -> bool {
        self.caps.iter().any(|c| c.covers(name, arg))
    }

    /// Whether the grant set is empty (deny-all).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.caps.is_empty()
    }
}

/// A value returned by a host effect, before it is interned into a [`Value`].
///
/// Kept free of interpreter internals so [`EffectHandler`] implementations need
/// no knowledge of the memory accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostValue {
    /// The unit value.
    Unit,
    /// A boolean.
    Bool(bool),
    /// An integer.
    Int(i64),
    /// A string (charged to the memory budget when interned).
    Str(String),
}

/// The host's bridge for capability-gated effects (WS18-02.10).
///
/// The interpreter has no ambient access to the outside world: the only way a
/// script can cause an effect is a `namespace::function(..)` call that this
/// handler recognises *and* whose capability the caller granted. The handler
/// declares, per `(namespace, function)`, which capability is required; the
/// interpreter enforces the grant before ever calling [`perform`](Self::perform).
pub trait EffectHandler {
    /// The capability required to call `namespace::function`, or `None` if this
    /// handler does not provide that effect (in which case the call is treated
    /// as an ordinary enum constructor, never as an effect).
    fn required_capability(&self, namespace: &str, function: &str) -> Option<String>;

    /// Perform the effect. Only called after the capability gate has passed.
    ///
    /// # Errors
    ///
    /// A [`RuntimeError`] if the effect itself fails.
    fn perform(
        &mut self,
        namespace: &str,
        function: &str,
        args: &[Value],
    ) -> Result<HostValue, RuntimeError>;
}

/// Extract an owned string from a [`Value::Str`], for use as a capability
/// scope argument.
fn value_as_str(v: &Value) -> Option<String> {
    match v {
        Value::Str(s, _) => Some((**s).clone()),
        _ => None,
    }
}

/// Render a parsed capability scope as a string for matching.
fn cap_scope_to_string(scope: &CapScope) -> String {
    match scope {
        CapScope::Str(s) => s.clone(),
        CapScope::Int(i) => i.to_string(),
    }
}

/// The tree-walking interpreter.
pub struct Interpreter {
    functions: BTreeMap<String, Rc<FnDef>>,
    /// Stack of lexical scopes (innermost last).
    scopes: Vec<BTreeMap<String, Value>>,
    /// Captured `print` output (the script's own stdout, not a capability).
    output: Vec<String>,
    /// Deterministic resource limits.
    limits: Limits,
    /// Evaluation steps consumed so far.
    steps: u64,
    /// Current function-call recursion depth.
    depth: usize,
    /// Optional injected time source for the deadline limit.
    clock: Option<Rc<dyn Clock>>,
    /// Live heap-memory account shared with every value's [`MemGuard`].
    mem: MemAccount,
    /// Capabilities granted to this run (deny-all when empty).
    grants: Grants,
    /// Optional host bridge for capability-gated effects.
    handler: Option<Box<dyn EffectHandler>>,
    /// Capabilities declared in the loaded program's header.
    declared: Vec<Capability>,
}

impl Default for Interpreter {
    fn default() -> Self {
        Self::new()
    }
}

impl Interpreter {
    /// A fresh interpreter with no program loaded and no resource limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            functions: BTreeMap::new(),
            scopes: alloc::vec![BTreeMap::new()],
            output: Vec::new(),
            limits: Limits::default(),
            steps: 0,
            depth: 0,
            clock: None,
            mem: Rc::new(Cell::new(0)),
            grants: Grants::none(),
            handler: None,
            declared: Vec::new(),
        }
    }

    /// Live heap bytes currently charged against the memory budget.
    #[must_use]
    pub fn live_bytes(&self) -> usize {
        self.mem.get()
    }

    /// Reserve `bytes` against the memory budget, failing cleanly if it would
    /// exceed [`Limits::max_alloc_bytes`].
    fn reserve(&self, bytes: usize) -> Eval<()> {
        let live = self.mem.get();
        if let Some(max) = self.limits.max_alloc_bytes {
            if live.saturating_add(bytes) > max {
                return Err(RuntimeError::LimitExceeded(Limit::Memory).into());
            }
        }
        self.mem.set(live.saturating_add(bytes));
        Ok(())
    }

    /// Reserve `bytes` and return an RAII [`MemGuard`] that credits them back
    /// when the owning value is fully dropped.
    fn guard(&self, bytes: usize) -> Eval<Rc<MemGuard>> {
        self.reserve(bytes)?;
        Ok(Rc::new(MemGuard {
            bytes: Cell::new(bytes),
            account: Rc::clone(&self.mem),
        }))
    }

    /// Allocate a string value, charged to the memory budget.
    fn new_str(&self, s: String) -> Eval<Value> {
        let g = self.guard(STR_OVERHEAD + s.len())?;
        Ok(Value::Str(Rc::new(s), g))
    }

    /// Allocate a list value, charged to the memory budget.
    fn new_list(&self, items: Vec<Value>) -> Eval<Value> {
        let g = self.guard(list_bytes(items.len()))?;
        Ok(Value::List(Rc::new(RefCell::new(items)), g))
    }

    /// Allocate an enum value, charged to the memory budget.
    fn new_enum(&self, enum_name: &str, variant: &str, payload: Vec<Value>) -> Eval<Value> {
        let bytes = ENUM_OVERHEAD
            + enum_name.len()
            + variant.len()
            + payload.len().saturating_mul(VALUE_SIZE);
        let g = self.guard(bytes)?;
        Ok(Value::Enum {
            enum_name: String::from(enum_name),
            variant: String::from(variant),
            payload: Rc::new(payload),
            guard: g,
        })
    }

    /// Allocate a struct value, charged to the memory budget.
    fn new_struct(&self, name: String, fields: BTreeMap<String, Value>) -> Eval<Value> {
        let keys: usize = fields.keys().map(String::len).sum();
        let bytes = STRUCT_OVERHEAD + name.len() + keys + fields.len().saturating_mul(VALUE_SIZE);
        let g = self.guard(bytes)?;
        Ok(Value::Struct {
            name,
            fields: Rc::new(RefCell::new(fields)),
            guard: g,
        })
    }

    /// Set the deterministic resource limits (builder style).
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Set the time source used to enforce [`Limits::deadline_micros`] (builder
    /// style).
    #[must_use]
    pub fn with_clock(mut self, clock: Rc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Grant a set of capabilities for this run (builder style). Without this,
    /// the grant set is empty and every effect is denied (WS18-02.9/.10).
    #[must_use]
    pub fn with_capabilities(mut self, grants: Grants) -> Self {
        self.grants = grants;
        self
    }

    /// Install the host effect handler (builder style). Without one, no
    /// `namespace::function` call is treated as an effect.
    #[must_use]
    pub fn with_effect_handler(mut self, handler: Box<dyn EffectHandler>) -> Self {
        self.handler = Some(handler);
        self
    }

    /// Capabilities declared by the loaded program's `#![capabilities(..)]`
    /// header.
    #[must_use]
    pub fn declared_capabilities(&self) -> &[Capability] {
        &self.declared
    }

    /// Steps consumed by the most recent run, for budgeting diagnostics.
    #[must_use]
    pub fn steps(&self) -> u64 {
        self.steps
    }

    /// Charge one evaluation step and enforce the step and time limits.
    ///
    /// Called at every expression and on each loop iteration, so any
    /// non-terminating script (even an empty `loop {}`) is interrupted cleanly
    /// once a limit is set.
    fn tick(&mut self) -> Eval<()> {
        self.steps = self.steps.saturating_add(1);
        if let Some(max) = self.limits.max_steps {
            if self.steps > max {
                return Err(RuntimeError::LimitExceeded(Limit::Steps).into());
            }
        }
        if let (Some(clock), Some(deadline)) = (self.clock.as_ref(), self.limits.deadline_micros) {
            if clock.now_micros() >= deadline {
                return Err(RuntimeError::LimitExceeded(Limit::Time).into());
            }
        }
        Ok(())
    }

    /// Load a parsed program: register its functions and record the declared
    /// capability header.
    pub fn load(&mut self, program: &Program) {
        for item in &program.items {
            if let Item::Fn(f) = item {
                self.functions.insert(f.name.clone(), Rc::new(f.clone()));
            }
            // struct/enum/const/use/impl are accepted; field/variant resolution
            // is structural at run time (no nominal type table needed for v1).
        }
        self.declared = program
            .capabilities
            .iter()
            .map(|c| Capability {
                name: c.name.clone(),
                scope: c.scope.as_ref().map(cap_scope_to_string),
            })
            .collect();
    }

    /// The captured `print` output lines.
    #[must_use]
    pub fn output(&self) -> &[String] {
        &self.output
    }

    /// Call the program's `main` (no args) and return its value.
    ///
    /// # Errors
    ///
    /// A [`RuntimeError`] if `main` is missing or evaluation fails.
    pub fn run_main(&mut self) -> Result<Value, RuntimeError> {
        let main = self
            .functions
            .get("main")
            .cloned()
            .ok_or_else(|| RuntimeError::Undefined(String::from("main")))?;
        self.call_fn(&main, Vec::new()).map_err(unwrap_error)
    }

    // ---- scopes -----------------------------------------------------------

    fn push_scope(&mut self) {
        self.scopes.push(BTreeMap::new());
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    fn define(&mut self, name: &str, v: Value) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(String::from(name), v);
        }
    }

    fn lookup(&self, name: &str) -> Option<Value> {
        for scope in self.scopes.iter().rev() {
            if let Some(v) = scope.get(name) {
                return Some(v.clone());
            }
        }
        None
    }

    fn assign(&mut self, name: &str, v: Value) -> bool {
        for scope in self.scopes.iter_mut().rev() {
            if scope.contains_key(name) {
                scope.insert(String::from(name), v);
                return true;
            }
        }
        false
    }

    // ---- calls ------------------------------------------------------------

    fn call_fn(&mut self, f: &FnDef, args: Vec<Value>) -> Eval<Value> {
        let real_params: Vec<&_> = f.params.iter().filter(|p| !p.is_self).collect();
        if real_params.len() != args.len() {
            return Err(RuntimeError::Arity {
                func: f.name.clone(),
                expected: real_params.len(),
                got: args.len(),
            }
            .into());
        }
        // Enforce the recursion-depth limit before descending (this also turns
        // unbounded recursion into a clean abort instead of a stack overflow).
        if let Some(max) = self.limits.max_call_depth {
            if self.depth >= max {
                return Err(RuntimeError::LimitExceeded(Limit::CallDepth).into());
            }
        }
        self.depth += 1;
        self.push_scope();
        for (p, a) in real_params.iter().zip(args) {
            self.define(&p.name, a);
        }
        let result = self.eval_block(&f.body);
        self.pop_scope();
        self.depth -= 1;
        match result {
            Ok(v) | Err(Control::Return(v)) => Ok(v),
            Err(other) => Err(other),
        }
    }

    // ---- blocks + statements ----------------------------------------------

    fn eval_block(&mut self, block: &Block) -> Eval<Value> {
        self.push_scope();
        let r = self.eval_block_inner(block);
        self.pop_scope();
        r
    }

    fn eval_block_inner(&mut self, block: &Block) -> Eval<Value> {
        for stmt in &block.statements {
            self.exec_stmt(stmt)?;
        }
        block
            .tail
            .as_ref()
            .map_or(Ok(Value::Unit), |tail| self.eval_expr(tail))
    }

    fn exec_stmt(&mut self, stmt: &Stmt) -> Eval<()> {
        match stmt {
            Stmt::Let { pat, value, .. } => {
                let v = match value {
                    Some(e) => self.eval_expr(e)?,
                    None => Value::Unit,
                };
                self.bind_pattern_irrefutable(pat, v)?;
                Ok(())
            }
            Stmt::Expr(e) => {
                self.eval_expr(e)?;
                Ok(())
            }
            Stmt::Assign { place, op, value } => {
                let rhs = self.eval_expr(value)?;
                self.exec_assign(place, *op, rhs)
            }
            Stmt::Item(Item::Fn(f)) => {
                self.functions.insert(f.name.clone(), Rc::new(f.clone()));
                Ok(())
            }
            Stmt::Item(_) => Ok(()),
        }
    }

    fn exec_assign(&mut self, place: &Expr, op: crate::ast::AssignOp, rhs: Value) -> Eval<()> {
        use crate::ast::AssignOp;
        // Only simple variable places are supported in v1 (field/index assign
        // targets land with the mutable-place work).
        let Expr::Path(segs) = place else {
            return Err(RuntimeError::Msg(String::from(
                "only simple variable assignment is supported",
            ))
            .into());
        };
        let [name] = segs.as_slice() else {
            return Err(RuntimeError::Msg(String::from(
                "only simple variable assignment is supported",
            ))
            .into());
        };
        let new = if matches!(op, AssignOp::Assign) {
            rhs
        } else {
            let cur = self
                .lookup(name)
                .ok_or_else(|| RuntimeError::Undefined(name.clone()))?;
            let bin = match op {
                AssignOp::Add => BinOp::Add,
                AssignOp::Sub => BinOp::Sub,
                AssignOp::Mul => BinOp::Mul,
                AssignOp::Div => BinOp::Div,
                AssignOp::Rem => BinOp::Rem,
                // `Assign` took the early branch above; treat defensively.
                AssignOp::Assign => return Ok(()),
            };
            eval_binary(self, bin, cur, rhs)?
        };
        if self.assign(name, new) {
            Ok(())
        } else {
            Err(RuntimeError::Undefined(name.clone()).into())
        }
    }

    // ---- expressions ------------------------------------------------------

    fn eval_expr(&mut self, expr: &Expr) -> Eval<Value> {
        self.tick()?;
        match expr {
            Expr::Int(v) => Ok(Value::Int(*v)),
            Expr::Float(v) => Ok(Value::Float(*v)),
            Expr::Str(s) => self.new_str(s.clone()),
            Expr::Bool(b) => Ok(Value::Bool(*b)),
            Expr::Unit => Ok(Value::Unit),
            Expr::Path(segs) => self.eval_path(segs),
            Expr::Unary { op, expr } => {
                let v = self.eval_expr(expr)?;
                eval_unary(*op, v)
            }
            Expr::Binary { op, lhs, rhs } => self.eval_binary_expr(*op, lhs, rhs),
            Expr::Call { callee, args } => self.eval_call(callee, args),
            Expr::MethodCall { recv, method, args } => self.eval_method(recv, method, args),
            Expr::Field { recv, name } => {
                let v = self.eval_expr(recv)?;
                match v {
                    Value::Struct { fields, .. } => fields
                        .borrow()
                        .get(name)
                        .cloned()
                        .ok_or_else(|| RuntimeError::NoField(name.clone()).into()),
                    other => Err(RuntimeError::Type(format!(
                        "field access on {}",
                        other.type_name()
                    ))
                    .into()),
                }
            }
            Expr::Index { recv, index } => {
                let r = self.eval_expr(recv)?;
                let i = self.eval_expr(index)?;
                match (r, i) {
                    (Value::List(items, _), Value::Int(idx)) => {
                        let items = items.borrow();
                        usize::try_from(idx)
                            .ok()
                            .and_then(|u| items.get(u).cloned())
                            .ok_or_else(|| RuntimeError::IndexOutOfBounds.into())
                    }
                    (r, _) => Err(RuntimeError::Type(format!("indexing {}", r.type_name())).into()),
                }
            }
            Expr::List(items) => {
                let mut out = Vec::with_capacity(items.len());
                for e in items {
                    out.push(self.eval_expr(e)?);
                }
                self.new_list(out)
            }
            Expr::Tuple(items) => {
                // v1 models tuples as lists.
                let mut out = Vec::with_capacity(items.len());
                for e in items {
                    out.push(self.eval_expr(e)?);
                }
                self.new_list(out)
            }
            Expr::StructLit { path, fields } => self.eval_struct_lit(path, fields),
            Expr::If {
                cond,
                then_block,
                else_branch,
            } => {
                if self.eval_cond(cond, "if")? {
                    self.eval_block(then_block)
                } else if let Some(e) = else_branch {
                    self.eval_expr(e)
                } else {
                    Ok(Value::Unit)
                }
            }
            // `scope { }` (structured concurrency) runs inline in v1.
            Expr::Block(b) | Expr::Scope(b) => self.eval_block(b),
            Expr::Match { scrutinee, arms } => self.eval_match(scrutinee, arms),
            Expr::While { cond, body } => self.eval_while(cond, body),
            Expr::For { pat, iter, body } => self.eval_for(pat, iter, body),
            Expr::Loop { label, body } => self.eval_loop(label.as_deref(), body),
            Expr::Return(e) => {
                let v = match e {
                    Some(e) => self.eval_expr(e)?,
                    None => Value::Unit,
                };
                Err(Control::Return(v))
            }
            Expr::Break { label, value } => {
                let v = match value {
                    Some(e) => self.eval_expr(e)?,
                    None => Value::Unit,
                };
                Err(Control::Break(label.clone(), v))
            }
            Expr::Continue { label } => Err(Control::Continue(label.clone())),
            Expr::Try(e) => self.eval_try(e),
            // `await`/`spawn` run inline in v1 (no async scheduler yet).
            Expr::Await(e) | Expr::Spawn(e) => self.eval_expr(e),
            Expr::Map(_) => {
                Err(RuntimeError::Msg(String::from("map literals are not yet supported")).into())
            }
        }
    }

    fn eval_cond(&mut self, cond: &Expr, ctx: &'static str) -> Eval<bool> {
        let v = self.eval_expr(cond)?;
        v.as_bool().ok_or_else(|| RuntimeError::NotBool(ctx).into())
    }

    fn eval_path(&self, segs: &[String]) -> Eval<Value> {
        match segs {
            // Built-in nullary enum constructor, then variable lookup.
            [name] if name == "None" => self.new_enum("Option", "None", Vec::new()),
            [name] => self
                .lookup(name)
                .ok_or_else(|| RuntimeError::Undefined(name.clone()).into()),
            // `Enum::Variant` used as a value → a unit variant value.
            [enum_name, variant] => self.new_enum(enum_name, variant, Vec::new()),
            _ => Err(RuntimeError::Undefined(segs.join("::")).into()),
        }
    }

    fn eval_binary_expr(&mut self, op: BinOp, lhs: &Expr, rhs: &Expr) -> Eval<Value> {
        // Short-circuit boolean operators.
        if matches!(op, BinOp::And | BinOp::Or) {
            let l = self.eval_cond(lhs, "boolean operand")?;
            return match op {
                BinOp::And if !l => Ok(Value::Bool(false)),
                BinOp::Or if l => Ok(Value::Bool(true)),
                _ => Ok(Value::Bool(self.eval_cond(rhs, "boolean operand")?)),
            };
        }
        let l = self.eval_expr(lhs)?;
        let r = self.eval_expr(rhs)?;
        eval_binary(self, op, l, r)
    }

    fn eval_call(&mut self, callee: &Expr, args: &[Expr]) -> Eval<Value> {
        // Resolve a path callee: user fn, built-in fn, or enum constructor.
        let Expr::Path(segs) = callee else {
            return Err(RuntimeError::NotCallable(String::from("<expr>")).into());
        };
        let mut vals = Vec::with_capacity(args.len());
        for arg in args {
            vals.push(self.eval_expr(arg)?);
        }
        match segs.as_slice() {
            [name] => self.call_named(name, vals),
            // A two-segment call is either a gated effect (`ns::func`, if the
            // host's effect handler recognises it) or an enum constructor.
            [namespace, func] => self.call_namespaced(namespace, func, vals),
            _ => Err(RuntimeError::NotCallable(segs.join("::")).into()),
        }
    }

    /// Call a single-segment callee: a built-in, a `Result`/`Option`
    /// constructor, or a user function.
    fn call_named(&mut self, name: &str, vals: Vec<Value>) -> Eval<Value> {
        match name {
            "print" => {
                let line = vals
                    .iter()
                    .map(Value::display)
                    .collect::<Vec<_>>()
                    .join(" ");
                self.output.push(line);
                return Ok(Value::Unit);
            }
            "len" => {
                return match vals.into_iter().next() {
                    Some(Value::List(l, _)) => Ok(int_from_len(l.borrow().len())),
                    Some(Value::Str(s, _)) => Ok(int_from_len(s.chars().count())),
                    _ => Err(
                        RuntimeError::Type(String::from("len() expects a list or string")).into(),
                    ),
                };
            }
            "Ok" => return self.new_enum("Result", "Ok", vals),
            "Err" => return self.new_enum("Result", "Err", vals),
            "Some" => return self.new_enum("Option", "Some", vals),
            _ => {}
        }
        if let Some(f) = self.functions.get(name).cloned() {
            return self.call_fn(&f, vals);
        }
        Err(RuntimeError::NotCallable(String::from(name)).into())
    }

    /// Resolve a two-segment call `namespace::func(args)`.
    ///
    /// If the host effect handler recognises it (returns a required capability),
    /// it is a gated effect: the call is denied unless the capability is granted
    /// (deny-by-default, WS18-02.9/.10), and only then dispatched to the host —
    /// there is no ambient path to any effect. Otherwise it is an enum
    /// constructor `Enum::Variant(args)`.
    fn call_namespaced(&mut self, namespace: &str, func: &str, vals: Vec<Value>) -> Eval<Value> {
        let required = self
            .handler
            .as_ref()
            .and_then(|h| h.required_capability(namespace, func));
        let Some(reqcap) = required else {
            // Not an effect: try the pure stdlib, else an enum constructor.
            if let Some(v) = self.stdlib_call(namespace, func, &vals)? {
                return Ok(v);
            }
            return self.new_enum(namespace, func, vals);
        };
        // The first string argument is the capability scope (e.g. a path/host).
        let scope = vals.iter().find_map(value_as_str);
        if !self.grants.allows(&reqcap, scope.as_deref()) {
            return Err(RuntimeError::CapabilityDenied(reqcap).into());
        }
        // Gate passed: dispatch to the host. Take the handler out to satisfy the
        // borrow checker, then restore it.
        let Some(mut handler) = self.handler.take() else {
            return Err(RuntimeError::Msg(String::from("effect handler unavailable")).into());
        };
        let outcome = handler.perform(namespace, func, &vals);
        self.handler = Some(handler);
        self.intern_host_value(outcome?)
    }

    /// Convert a host effect result into an interpreter value, charging any
    /// allocated string against the memory budget.
    fn intern_host_value(&self, hv: HostValue) -> Eval<Value> {
        match hv {
            HostValue::Unit => Ok(Value::Unit),
            HostValue::Bool(b) => Ok(Value::Bool(b)),
            HostValue::Int(i) => Ok(Value::Int(i)),
            HostValue::Str(s) => self.new_str(s),
        }
    }

    /// Dispatch a pure (effect-free) standard-library call `namespace::func`.
    ///
    /// Returns `Ok(None)` if `namespace` is not a stdlib module (so the caller
    /// falls back to enum-constructor handling); `Ok(Some(value))` on success;
    /// `Err` if the module is known but the function or arguments are invalid.
    /// Stdlib calls need no capability — they are computation, not effects.
    fn stdlib_call(&self, namespace: &str, func: &str, args: &[Value]) -> Eval<Option<Value>> {
        match namespace {
            "string" => self.string_op(func, args).map(Some),
            "math" => math_op(func, args).map(Some),
            "datetime" => self.datetime_op(func, args).map(Some),
            "collections" => self.collections_op(func, args).map(Some),
            "json" => self.json_op(func, args).map(Some),
            _ => Ok(None),
        }
    }

    /// The `json` stdlib module (WS18-03.4): JSON / `.oss` serialization and
    /// parsing.
    ///
    /// - `stringify(value) -> string`: serialize a value to JSON text. Unit
    ///   maps to `null`, structs to objects (the type name is dropped — JSON
    ///   objects are nameless), lists to arrays. Enums and non-finite floats
    ///   cannot be represented and yield a clean error.
    /// - `parse(string) -> Option`: parse JSON text into a value, returning
    ///   `Some(value)` on success and `None` on malformed input. Objects become
    ///   anonymous structs (name `"object"`). Recursion is depth-limited so a
    ///   deeply-nested document cannot overflow the host stack.
    fn json_op(&self, func: &str, args: &[Value]) -> Eval<Value> {
        match func {
            "stringify" => {
                let mut out = String::new();
                json_stringify(arg_at(args, 0, func)?, &mut out)?;
                self.new_str(out)
            }
            "parse" => {
                let parsed = self.json_parse(str_arg(args, 0, func)?)?;
                self.option_of(parsed)
            }
            _ => Err(RuntimeError::NoMethod(format!("json::{func}")).into()),
        }
    }

    /// Parse a complete JSON document, returning `Ok(Some(value))` on success,
    /// `Ok(None)` on malformed input, and `Err` only on a hard error (e.g. the
    /// memory budget was exhausted while materializing the value).
    fn json_parse(&self, input: &str) -> Eval<Option<Value>> {
        let mut parser = JsonParser { src: input, pos: 0 };
        let Some(value) = parser.parse_value(self, 0)? else {
            return Ok(None);
        };
        parser.skip_ws();
        // Reject trailing, non-whitespace garbage after the top-level value.
        if parser.pos != input.len() {
            return Ok(None);
        }
        Ok(Some(value))
    }

    /// The `collections` stdlib module (WS18-03.1): pure operations on lists.
    ///
    /// Every function is effect-free and non-mutating: queries return scalars
    /// or an `Option`, and transforms (`reverse`/`concat`/`slice`) return a
    /// fresh list, leaving their arguments untouched. Out-of-range indices
    /// yield `Option::None` rather than panicking.
    fn collections_op(&self, func: &str, args: &[Value]) -> Eval<Value> {
        match func {
            "len" => Ok(int_from_len(list_ref(args, 0, func)?.len())),
            "is_empty" => Ok(Value::Bool(list_ref(args, 0, func)?.is_empty())),
            "get" => {
                let idx = int_arg(args, 1, func)?;
                let elem = {
                    let list = list_ref(args, 0, func)?;
                    usize::try_from(idx).ok().and_then(|i| list.get(i).cloned())
                };
                self.option_of(elem)
            }
            "first" => {
                let elem = list_ref(args, 0, func)?.first().cloned();
                self.option_of(elem)
            }
            "last" => {
                let elem = list_ref(args, 0, func)?.last().cloned();
                self.option_of(elem)
            }
            "contains" => {
                let needle = arg_at(args, 1, func)?;
                let found = list_ref(args, 0, func)?
                    .iter()
                    .any(|v| values_equal(v, needle));
                Ok(Value::Bool(found))
            }
            "index_of" => {
                let needle = arg_at(args, 1, func)?;
                let pos = list_ref(args, 0, func)?
                    .iter()
                    .position(|v| values_equal(v, needle));
                self.option_of(pos.map(int_from_len))
            }
            "reverse" => {
                let items: Vec<Value> = list_ref(args, 0, func)?.iter().rev().cloned().collect();
                self.new_list(items)
            }
            "concat" => {
                let mut items: Vec<Value> = list_ref(args, 0, func)?.iter().cloned().collect();
                let tail: Vec<Value> = list_ref(args, 1, func)?.iter().cloned().collect();
                items.extend(tail);
                self.new_list(items)
            }
            "slice" => {
                let start = int_arg(args, 1, func)?;
                let end = int_arg(args, 2, func)?;
                let items: Vec<Value> = {
                    let list = list_ref(args, 0, func)?;
                    let n = list.len();
                    // Clamp to `[0, n]` and ensure `s <= e` (empty on inversion).
                    let s = usize::try_from(start).unwrap_or(0).min(n);
                    let e = usize::try_from(end).unwrap_or(0).min(n).max(s);
                    list.iter().skip(s).take(e - s).cloned().collect()
                };
                self.new_list(items)
            }
            _ => Err(RuntimeError::NoMethod(format!("collections::{func}")).into()),
        }
    }

    /// Wrap an optional value into an `Option::Some`/`Option::None` enum value.
    fn option_of(&self, value: Option<Value>) -> Eval<Value> {
        value.map_or_else(
            || self.new_enum("Option", "None", Vec::new()),
            |v| self.new_enum("Option", "Some", alloc::vec![v]),
        )
    }

    /// The `string` stdlib module (WS18-03.2): pure string operations.
    fn string_op(&self, func: &str, args: &[Value]) -> Eval<Value> {
        match func {
            "len" => Ok(int_from_len(str_arg(args, 0, func)?.chars().count())),
            "upper" => self.new_str(str_arg(args, 0, func)?.to_uppercase()),
            "lower" => self.new_str(str_arg(args, 0, func)?.to_lowercase()),
            "trim" => self.new_str(String::from(str_arg(args, 0, func)?.trim())),
            "contains" => Ok(Value::Bool(
                str_arg(args, 0, func)?.contains(str_arg(args, 1, func)?),
            )),
            "starts_with" => Ok(Value::Bool(
                str_arg(args, 0, func)?.starts_with(str_arg(args, 1, func)?),
            )),
            "ends_with" => Ok(Value::Bool(
                str_arg(args, 0, func)?.ends_with(str_arg(args, 1, func)?),
            )),
            "replace" => self.new_str(
                str_arg(args, 0, func)?.replace(str_arg(args, 1, func)?, str_arg(args, 2, func)?),
            ),
            "split" => {
                let s = str_arg(args, 0, func)?;
                let sep = str_arg(args, 1, func)?;
                let mut parts = Vec::new();
                for piece in s.split(sep) {
                    parts.push(self.new_str(String::from(piece))?);
                }
                self.new_list(parts)
            }
            "repeat" => {
                let s = str_arg(args, 0, func)?;
                let n = usize::try_from(int_arg(args, 1, func)?).unwrap_or(0);
                // Reserve the projected size up-front so an oversized `repeat`
                // aborts cleanly instead of OOM-ing the host before charging.
                let bytes = STR_OVERHEAD + s.len().saturating_mul(n);
                let g = self.guard(bytes)?;
                Ok(Value::Str(Rc::new(s.repeat(n)), g))
            }
            "from_int" => self.new_str(int_arg(args, 0, func)?.to_string()),
            "to_int" => str_arg(args, 0, func)?.trim().parse::<i64>().map_or_else(
                |_| self.new_enum("Option", "None", Vec::new()),
                |n| self.new_enum("Option", "Some", alloc::vec![Value::Int(n)]),
            ),
            _ => Err(RuntimeError::NoMethod(format!("string::{func}")).into()),
        }
    }

    /// The `datetime` stdlib module (WS18-03.5): pure operations on Unix
    /// timestamps (seconds since 1970-01-01T00:00:00Z), proleptic Gregorian.
    ///
    /// All functions are deterministic and take the timestamp as an argument —
    /// there is no ambient clock (reading "now" is a capability-gated effect,
    /// not part of this pure module).
    #[allow(
        clippy::integer_division,
        reason = "calendar fields are computed by intentional flooring division"
    )]
    fn datetime_op(&self, func: &str, args: &[Value]) -> Eval<Value> {
        match func {
            "year" => Ok(Value::Int(
                civil_from_days(days_of(int_arg(args, 0, func)?)).0,
            )),
            "month" => Ok(Value::Int(
                civil_from_days(days_of(int_arg(args, 0, func)?)).1,
            )),
            "day" => Ok(Value::Int(
                civil_from_days(days_of(int_arg(args, 0, func)?)).2,
            )),
            "hour" => Ok(Value::Int(secs_of_day(int_arg(args, 0, func)?) / 3600)),
            "minute" => Ok(Value::Int(secs_of_day(int_arg(args, 0, func)?) / 60 % 60)),
            "second" => Ok(Value::Int(secs_of_day(int_arg(args, 0, func)?) % 60)),
            // 0 = Sunday … 6 = Saturday. Day 0 (1970-01-01) was a Thursday, so
            // shift by 4 before reducing mod 7.
            "weekday" => Ok(Value::Int(
                (days_of(int_arg(args, 0, func)?) + 4).rem_euclid(7),
            )),
            "format_iso" => {
                let ts = int_arg(args, 0, func)?;
                let (y, m, d) = civil_from_days(days_of(ts));
                let sod = secs_of_day(ts);
                self.new_str(format!(
                    "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
                    sod / 3600,
                    sod / 60 % 60,
                    sod % 60
                ))
            }
            "from_ymd" => {
                let y = int_arg(args, 0, func)?;
                let m = int_arg(args, 1, func)?;
                let d = int_arg(args, 2, func)?;
                if !(1..=12).contains(&m) {
                    return Err(
                        RuntimeError::Type(String::from("from_ymd: month must be 1..=12")).into(),
                    );
                }
                if !(1..=31).contains(&d) {
                    return Err(
                        RuntimeError::Type(String::from("from_ymd: day must be 1..=31")).into(),
                    );
                }
                days_from_civil(y, m, d)
                    .checked_mul(86400)
                    .map(Value::Int)
                    .ok_or_else(|| RuntimeError::Arithmetic("from_ymd overflow").into())
            }
            "add_seconds" => int_arg(args, 0, func)?
                .checked_add(int_arg(args, 1, func)?)
                .map(Value::Int)
                .ok_or_else(|| RuntimeError::Arithmetic("add_seconds overflow").into()),
            "add_days" => {
                let secs = int_arg(args, 1, func)?
                    .checked_mul(86400)
                    .ok_or(RuntimeError::Arithmetic("add_days overflow"))?;
                int_arg(args, 0, func)?
                    .checked_add(secs)
                    .map(Value::Int)
                    .ok_or_else(|| RuntimeError::Arithmetic("add_days overflow").into())
            }
            _ => Err(RuntimeError::NoMethod(format!("datetime::{func}")).into()),
        }
    }

    fn eval_method(&mut self, recv: &Expr, method: &str, args: &[Expr]) -> Eval<Value> {
        let receiver = self.eval_expr(recv)?;
        let mut vals = Vec::with_capacity(args.len());
        for arg in args {
            vals.push(self.eval_expr(arg)?);
        }
        match (method, &receiver) {
            ("len", Value::List(l, _)) => Ok(int_from_len(l.borrow().len())),
            ("len", Value::Str(s, _)) => Ok(int_from_len(s.chars().count())),
            ("push", Value::List(l, g)) => {
                if let Some(v) = vals.into_iter().next() {
                    // Charge the in-place growth onto the list's own guard so it
                    // is credited back when the list is dropped (live limit).
                    self.reserve(VALUE_SIZE)?;
                    g.bytes.set(g.bytes.get().saturating_add(VALUE_SIZE));
                    l.borrow_mut().push(v);
                }
                Ok(Value::Unit)
            }
            ("to_string", v) => self.new_str(v.display()),
            _ => {
                Err(RuntimeError::NoMethod(format!("{method} on {}", receiver.type_name())).into())
            }
        }
    }

    fn eval_struct_lit(
        &mut self,
        path: &[String],
        fields: &[(String, Option<Expr>)],
    ) -> Eval<Value> {
        let name = path.last().cloned().unwrap_or_default();
        let mut map = BTreeMap::new();
        for (fname, fexpr) in fields {
            let v = match fexpr {
                Some(e) => self.eval_expr(e)?,
                // field shorthand `{ name }` → bind the variable `name`
                None => self
                    .lookup(fname)
                    .ok_or_else(|| RuntimeError::Undefined(fname.clone()))?,
            };
            map.insert(fname.clone(), v);
        }
        self.new_struct(name, map)
    }

    fn eval_try(&mut self, e: &Expr) -> Eval<Value> {
        let v = self.eval_expr(e)?;
        match v {
            Value::Enum {
                ref enum_name,
                ref variant,
                ref payload,
                ..
            } if enum_name == "Result" => match variant.as_str() {
                "Ok" => Ok(payload.first().cloned().unwrap_or(Value::Unit)),
                "Err" => Err(Control::Return(v.clone())),
                _ => Err(RuntimeError::Type(String::from("`?` on a non-Result")).into()),
            },
            Value::Enum {
                ref enum_name,
                ref variant,
                ref payload,
                ..
            } if enum_name == "Option" => match variant.as_str() {
                "Some" => Ok(payload.first().cloned().unwrap_or(Value::Unit)),
                "None" => Err(Control::Return(v.clone())),
                _ => Err(RuntimeError::Type(String::from("`?` on a non-Option")).into()),
            },
            other => Err(RuntimeError::Type(format!("`?` on {}", other.type_name())).into()),
        }
    }

    fn eval_while(&mut self, cond: &Expr, body: &Block) -> Eval<Value> {
        while self.eval_cond(cond, "while")? {
            match self.eval_block(body) {
                // `while`/`for` carry no label, so only unlabeled break/continue
                // act here; a labeled one propagates to its target loop.
                Ok(_) | Err(Control::Continue(None)) => {}
                Err(Control::Break(None, _)) => break,
                Err(other) => return Err(other),
            }
        }
        Ok(Value::Unit)
    }

    fn eval_for(&mut self, pat: &Pattern, iter: &Expr, body: &Block) -> Eval<Value> {
        let iterable = self.eval_expr(iter)?;
        let Value::List(items, _) = iterable else {
            return Err(RuntimeError::Type(format!("`for` over {}", iterable.type_name())).into());
        };
        let snapshot: Vec<Value> = items.borrow().clone();
        for item in snapshot {
            self.tick()?;
            self.push_scope();
            let bound = self.bind_pattern_irrefutable(pat, item);
            let step = bound.and_then(|()| self.eval_block_inner(body));
            self.pop_scope();
            match step {
                Ok(_) | Err(Control::Continue(None)) => {}
                Err(Control::Break(None, _)) => break,
                Err(other) => return Err(other),
            }
        }
        Ok(Value::Unit)
    }

    fn eval_loop(&mut self, label: Option<&str>, body: &Block) -> Eval<Value> {
        loop {
            // Charge a step per iteration so even an empty `loop {}` body is
            // interrupted cleanly once a step or time limit is set.
            self.tick()?;
            match self.eval_block(body) {
                Ok(_) => {}
                Err(Control::Break(blabel, v)) => {
                    if blabel.is_none() || blabel.as_deref() == label {
                        return Ok(v);
                    }
                    // Labeled break aimed at an outer loop: keep propagating.
                    return Err(Control::Break(blabel, v));
                }
                Err(Control::Continue(clabel)) => {
                    if clabel.is_none() || clabel.as_deref() == label {
                        continue;
                    }
                    return Err(Control::Continue(clabel));
                }
                Err(other) => return Err(other),
            }
        }
    }

    fn eval_match(&mut self, scrutinee: &Expr, arms: &[MatchArm]) -> Eval<Value> {
        let value = self.eval_expr(scrutinee)?;
        for arm in arms {
            self.push_scope();
            let matched = self.match_pattern(&arm.pat, &value);
            if matched {
                let guard_ok = arm
                    .guard
                    .as_ref()
                    .map_or(Ok(true), |g| self.eval_cond(g, "match guard"));
                match guard_ok {
                    Ok(true) => {
                        let r = self.eval_expr(&arm.body);
                        self.pop_scope();
                        return r;
                    }
                    Ok(false) => {
                        self.pop_scope();
                    }
                    Err(e) => {
                        self.pop_scope();
                        return Err(e);
                    }
                }
            } else {
                self.pop_scope();
            }
        }
        Err(RuntimeError::NonExhaustiveMatch.into())
    }

    /// Try to match `pat` against `value`, binding into the current scope.
    /// Returns whether it matched. (Bindings made on a failed match are
    /// discarded by the caller popping the scope.)
    fn match_pattern(&mut self, pat: &Pattern, value: &Value) -> bool {
        match pat {
            Pattern::Wildcard => true,
            Pattern::Binding(name) => {
                self.define(name, value.clone());
                true
            }
            Pattern::Literal(lit) => {
                // Literal patterns are constant expressions.
                self.eval_expr(lit)
                    .map(|lv| values_equal(&lv, value))
                    .unwrap_or(false)
            }
            Pattern::Path(segs) => match value {
                Value::Enum { variant, .. } => segs.last().is_some_and(|v| v == variant),
                _ => false,
            },
            Pattern::Or(alts) => alts.iter().any(|p| self.match_pattern(p, value)),
            Pattern::TupleStruct(path, sub) => match value {
                Value::Enum {
                    variant, payload, ..
                } => {
                    if path.last().is_none_or(|v| v != variant) || sub.len() != payload.len() {
                        return false;
                    }
                    sub.iter()
                        .zip(payload.iter())
                        .all(|(p, v)| self.match_pattern(p, v))
                }
                _ => false,
            },
            Pattern::Tuple(sub) => match value {
                Value::List(items, _) => {
                    let items = items.borrow();
                    sub.len() == items.len()
                        && sub
                            .iter()
                            .zip(items.iter())
                            .all(|(p, v)| self.match_pattern(p, v))
                }
                _ => false,
            },
            Pattern::Struct(path, fpats) => match value {
                Value::Struct { name, fields, .. } => {
                    if path.last().is_some_and(|n| n != name) {
                        return false;
                    }
                    let fields = fields.borrow();
                    fpats.iter().all(|(fname, sub)| {
                        fields.get(fname).is_some_and(|v| {
                            if let Some(p) = sub {
                                self.match_pattern(p, v)
                            } else {
                                self.define(fname, v.clone());
                                true
                            }
                        })
                    })
                }
                _ => false,
            },
        }
    }

    fn bind_pattern_irrefutable(&mut self, pat: &Pattern, value: Value) -> Eval<()> {
        match pat {
            Pattern::Wildcard => Ok(()),
            Pattern::Binding(name) => {
                self.define(name, value);
                Ok(())
            }
            other => {
                if self.match_pattern(other, &value) {
                    Ok(())
                } else {
                    Err(
                        RuntimeError::Msg(String::from("refutable pattern in binding position"))
                            .into(),
                    )
                }
            }
        }
    }
}

/// Convert a container length to an `Int`, saturating on the (impossible on
/// 64-bit) overflow rather than wrapping.
fn int_from_len(n: usize) -> Value {
    Value::Int(i64::try_from(n).unwrap_or(i64::MAX))
}

/// Approximate in-memory size of one [`Value`] slot.
const VALUE_SIZE: usize = core::mem::size_of::<Value>();
/// Per-string bookkeeping overhead charged on top of the byte length.
const STR_OVERHEAD: usize = 24;
/// Per-list bookkeeping overhead.
const LIST_OVERHEAD: usize = 24;
/// Per-struct bookkeeping overhead.
const STRUCT_OVERHEAD: usize = 32;
/// Per-enum bookkeeping overhead.
const ENUM_OVERHEAD: usize = 32;

/// Bytes charged for a list holding `len` elements.
fn list_bytes(len: usize) -> usize {
    LIST_OVERHEAD + len.saturating_mul(VALUE_SIZE)
}

/// Borrow argument `i` as a string, or report a type error tagged with `func`.
fn str_arg<'a>(args: &'a [Value], i: usize, func: &str) -> Eval<&'a str> {
    match args.get(i) {
        Some(Value::Str(s, _)) => Ok(s.as_str()),
        _ => Err(RuntimeError::Type(format!("{func}: expected a string at argument {i}")).into()),
    }
}

/// Read argument `i` as an integer, or report a type error tagged with `func`.
fn int_arg(args: &[Value], i: usize, func: &str) -> Eval<i64> {
    match args.get(i) {
        Some(Value::Int(n)) => Ok(*n),
        _ => Err(RuntimeError::Type(format!("{func}: expected an int at argument {i}")).into()),
    }
}

/// Borrow argument `i` (any value), or report an arity error tagged with `func`.
fn arg_at<'a>(args: &'a [Value], i: usize, func: &str) -> Eval<&'a Value> {
    args.get(i).ok_or_else(|| {
        RuntimeError::Type(format!("{func}: expected a value at argument {i}")).into()
    })
}

/// Borrow argument `i` as a list's element view, or report a type error.
fn list_ref<'a>(args: &'a [Value], i: usize, func: &str) -> Eval<core::cell::Ref<'a, Vec<Value>>> {
    match args.get(i) {
        Some(Value::List(l, _)) => Ok(l.borrow()),
        _ => Err(RuntimeError::Type(format!("{func}: expected a list at argument {i}")).into()),
    }
}

// ---- json helpers (WS18-03.4): JSON / `.oss` serialization + parsing --------

/// Maximum nesting depth accepted by [`JsonParser`], guarding the host stack
/// against adversarially-nested input.
const MAX_JSON_DEPTH: usize = 128;

/// Serialize `v` to JSON text appended onto `out`.
///
/// # Errors
///
/// Returns a type error for values with no JSON representation: enum values and
/// non-finite floats (JSON has no `NaN`/`Infinity`).
fn json_stringify(v: &Value, out: &mut String) -> Eval<()> {
    match v {
        Value::Unit => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(n) => out.push_str(&n.to_string()),
        Value::Float(f) => {
            if !f.is_finite() {
                return Err(RuntimeError::Type(String::from(
                    "json::stringify: non-finite floats have no JSON representation",
                ))
                .into());
            }
            let mut repr = f.to_string();
            // Keep floats distinguishable from ints on round-trip: an integral
            // float renders without a fraction (`2`), so re-add `.0`.
            if !repr.bytes().any(|c| matches!(c, b'.' | b'e' | b'E')) {
                repr.push_str(".0");
            }
            out.push_str(&repr);
        }
        Value::Str(s, _) => json_escape(s, out),
        Value::List(items, _) => {
            out.push('[');
            for (i, e) in items.borrow().iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_stringify(e, out)?;
            }
            out.push(']');
        }
        Value::Struct { fields, .. } => {
            out.push('{');
            for (i, (k, val)) in fields.borrow().iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_escape(k, out);
                out.push(':');
                json_stringify(val, out)?;
            }
            out.push('}');
        }
        Value::Enum { .. } => {
            return Err(RuntimeError::Type(String::from(
                "json::stringify: enum values have no JSON representation",
            ))
            .into());
        }
    }
    Ok(())
}

/// Append `s` as a quoted, escaped JSON string onto `out`.
fn json_escape(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if u32::from(c) < 0x20 => {
                let n = u32::from(c);
                out.push_str("\\u00");
                out.push(char::from_digit(n >> 4, 16).unwrap_or('0'));
                out.push(char::from_digit(n & 0xf, 16).unwrap_or('0'));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A minimal recursive-descent JSON parser over a UTF-8 source string.
///
/// Position-based, char-aware (multibyte-safe), and allocation-free except via
/// the interpreter's budgeted constructors. Syntax errors surface as
/// `Ok(None)`; only memory-budget exhaustion produces `Err`.
struct JsonParser<'a> {
    src: &'a str,
    pos: usize,
}

impl JsonParser<'_> {
    /// The not-yet-consumed remainder of the source.
    fn rest(&self) -> &str {
        self.src.get(self.pos..).unwrap_or("")
    }

    /// The next char without consuming it.
    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    /// Consume and return the next char.
    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    /// Skip JSON whitespace.
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.bump();
        }
    }

    /// Consume `lit` if it appears next; report whether it did.
    fn eat(&mut self, lit: &str) -> bool {
        if self.rest().starts_with(lit) {
            self.pos += lit.len();
            true
        } else {
            false
        }
    }

    /// Parse any JSON value.
    fn parse_value(&mut self, it: &Interpreter, depth: usize) -> Eval<Option<Value>> {
        if depth > MAX_JSON_DEPTH {
            return Ok(None);
        }
        self.skip_ws();
        match self.peek() {
            Some('{') => self.parse_object(it, depth),
            Some('[') => self.parse_array(it, depth),
            Some('"') => self
                .parse_string_raw()
                .map_or_else(|| Ok(None), |s| it.new_str(s).map(Some)),
            Some('t') => Ok(self.eat("true").then_some(Value::Bool(true))),
            Some('f') => Ok(self.eat("false").then_some(Value::Bool(false))),
            Some('n') => Ok(self.eat("null").then_some(Value::Unit)),
            Some(c) if c == '-' || c.is_ascii_digit() => Ok(self.parse_number()),
            _ => Ok(None),
        }
    }

    /// Parse a JSON array `[ v, v, ... ]`.
    fn parse_array(&mut self, it: &Interpreter, depth: usize) -> Eval<Option<Value>> {
        self.bump(); // '['
        let mut items: Vec<Value> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(']') {
            self.bump();
            return it.new_list(items).map(Some);
        }
        loop {
            let Some(v) = self.parse_value(it, depth + 1)? else {
                return Ok(None);
            };
            items.push(v);
            self.skip_ws();
            match self.bump() {
                Some(',') => {}
                Some(']') => return it.new_list(items).map(Some),
                _ => return Ok(None),
            }
        }
    }

    /// Parse a JSON object `{ "k": v, ... }` into an anonymous struct.
    fn parse_object(&mut self, it: &Interpreter, depth: usize) -> Eval<Option<Value>> {
        self.bump(); // '{'
        let mut fields: BTreeMap<String, Value> = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some('}') {
            self.bump();
            return it.new_struct(String::from("object"), fields).map(Some);
        }
        loop {
            self.skip_ws();
            if self.peek() != Some('"') {
                return Ok(None);
            }
            let Some(key) = self.parse_string_raw() else {
                return Ok(None);
            };
            self.skip_ws();
            if self.bump() != Some(':') {
                return Ok(None);
            }
            let Some(val) = self.parse_value(it, depth + 1)? else {
                return Ok(None);
            };
            fields.insert(key, val);
            self.skip_ws();
            match self.bump() {
                Some(',') => {}
                Some('}') => return it.new_struct(String::from("object"), fields).map(Some),
                _ => return Ok(None),
            }
        }
    }

    /// Parse a JSON number into an `Int` (when integral and in range) or a
    /// `Float`. Returns `None` on a malformed token.
    fn parse_number(&mut self) -> Option<Value> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || matches!(c, '-' | '+' | '.' | 'e' | 'E') {
                self.bump();
            } else {
                break;
            }
        }
        let token = self.src.get(start..self.pos)?;
        let is_float = token.bytes().any(|c| matches!(c, b'.' | b'e' | b'E'));
        if is_float {
            token.parse::<f64>().ok().map(Value::Float)
        } else {
            // Integer literal out of `i64` range falls back to a float.
            token.parse::<i64>().map_or_else(
                |_| token.parse::<f64>().ok().map(Value::Float),
                |n| Some(Value::Int(n)),
            )
        }
    }

    /// Parse the body of a JSON string (the opening quote is at `peek`),
    /// returning the decoded contents or `None` on a malformed string.
    fn parse_string_raw(&mut self) -> Option<String> {
        self.bump(); // opening quote
        let mut out = String::new();
        loop {
            match self.bump()? {
                '"' => return Some(out),
                '\\' => match self.bump()? {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'b' => out.push('\u{08}'),
                    'f' => out.push('\u{0c}'),
                    'u' => out.push(self.parse_unicode_escape()?),
                    _ => return None,
                },
                // Raw control characters are not permitted inside JSON strings.
                c if u32::from(c) < 0x20 => return None,
                c => out.push(c),
            }
        }
    }

    /// Parse four hex digits into a code unit.
    fn parse_hex4(&mut self) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..4 {
            v = v * 16 + self.bump()?.to_digit(16)?;
        }
        Some(v)
    }

    /// Parse a `\uXXXX` escape (the `u` is already consumed), combining a
    /// surrogate pair when present.
    fn parse_unicode_escape(&mut self) -> Option<char> {
        let hi = self.parse_hex4()?;
        if (0xD800..=0xDBFF).contains(&hi) {
            // High surrogate: a low surrogate `\uXXXX` must follow.
            if !self.eat("\\u") {
                return None;
            }
            let lo = self.parse_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&lo) {
                return None;
            }
            let scalar = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
            char::from_u32(scalar)
        } else if (0xDC00..=0xDFFF).contains(&hi) {
            None // lone low surrogate
        } else {
            char::from_u32(hi)
        }
    }
}

// ---- datetime helpers (WS18-03.5): proleptic Gregorian, Hinnant's algorithms

/// Days since the Unix epoch for a timestamp, floored toward negative infinity.
fn days_of(ts: i64) -> i64 {
    ts.div_euclid(86400)
}

/// Seconds within the day, in `[0, 86400)`, for a timestamp.
fn secs_of_day(ts: i64) -> i64 {
    ts.rem_euclid(86400)
}

/// Decompose days-since-epoch into `(year, month, day)` in the proleptic
/// Gregorian calendar (Howard Hinnant's `civil_from_days`). All-integer; the
/// intermediates stay within `i64` for any timestamp expressible in seconds.
#[allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::integer_division,
    reason = "z/y/m/d and era/doe/yoe/doy/mp are the algorithm's canonical names; flooring division is intended"
)]
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

/// Days since the Unix epoch for a `(year, month, day)` (Howard Hinnant's
/// `days_from_civil`). `month` and `day` must already be validated in range.
#[allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::integer_division,
    reason = "y/m/d and era/yoe/doy/doe are the algorithm's canonical names; flooring division is intended"
)]
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1; // [0,365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// The `math` stdlib module (WS18-03.3): pure, dependency-free integer math
/// plus float `abs`/`min`/`max` (no `libm` needed).
#[allow(
    clippy::float_arithmetic,
    reason = "math::abs negates user floats; no transcendental functions are used"
)]
fn math_op(func: &str, args: &[Value]) -> Eval<Value> {
    match func {
        "abs" => match args.first() {
            Some(Value::Int(i)) => i
                .checked_abs()
                .map(Value::Int)
                .ok_or_else(|| RuntimeError::Arithmetic("abs overflow").into()),
            Some(Value::Float(x)) => Ok(Value::Float(if *x < 0.0 { -*x } else { *x })),
            _ => Err(RuntimeError::Type(String::from("math::abs: expected a number")).into()),
        },
        "min" => Ok(Value::Int(
            int_arg(args, 0, func)?.min(int_arg(args, 1, func)?),
        )),
        "max" => Ok(Value::Int(
            int_arg(args, 0, func)?.max(int_arg(args, 1, func)?),
        )),
        "pow" => {
            let base = int_arg(args, 0, func)?;
            let exp = u32::try_from(int_arg(args, 1, func)?)
                .map_err(|_| RuntimeError::Arithmetic("pow: negative exponent"))?;
            base.checked_pow(exp)
                .map(Value::Int)
                .ok_or_else(|| RuntimeError::Arithmetic("pow overflow").into())
        }
        "gcd" => {
            let mut a = int_arg(args, 0, func)?.unsigned_abs();
            let mut b = int_arg(args, 1, func)?.unsigned_abs();
            while b != 0 {
                let t = b;
                b = a % b;
                a = t;
            }
            Ok(Value::Int(i64::try_from(a).unwrap_or(i64::MAX)))
        }
        "isqrt" => {
            let n = int_arg(args, 0, func)?;
            if n < 0 {
                return Err(RuntimeError::Arithmetic("isqrt of a negative number").into());
            }
            Ok(Value::Int(n.isqrt()))
        }
        _ => Err(RuntimeError::NoMethod(format!("math::{func}")).into()),
    }
}

/// Evaluate a unary operator on a value.
fn eval_unary(op: UnOp, v: Value) -> Eval<Value> {
    match (op, v) {
        (UnOp::Neg, Value::Int(i)) => Ok(Value::Int(i.wrapping_neg())),
        #[allow(
            clippy::float_arithmetic,
            reason = "the interpreter evaluates user float expressions"
        )]
        (UnOp::Neg, Value::Float(x)) => Ok(Value::Float(-x)),
        (UnOp::Not, Value::Bool(b)) => Ok(Value::Bool(!b)),
        (op, v) => Err(RuntimeError::Type(format!("unary {op:?} on {}", v.type_name())).into()),
    }
}

/// Evaluate a (non-short-circuit) binary operator on two values.
#[allow(
    clippy::float_arithmetic,
    reason = "the interpreter evaluates user float expressions"
)]
#[allow(
    clippy::many_single_char_names,
    reason = "`a`/`b`/`l`/`r` are the conventional operand names"
)]
fn eval_binary(interp: &Interpreter, op: BinOp, l: Value, r: Value) -> Eval<Value> {
    use BinOp::{Add, Div, Eq, Ge, Gt, Le, Lt, Mul, Ne, Rem, Sub};
    // Equality works across comparable values.
    match op {
        Eq => return Ok(Value::Bool(values_equal(&l, &r))),
        Ne => return Ok(Value::Bool(!values_equal(&l, &r))),
        _ => {}
    }
    match (l, r) {
        (Value::Int(a), Value::Int(b)) => {
            let res = match op {
                Add => a.checked_add(b),
                Sub => a.checked_sub(b),
                Mul => a.checked_mul(b),
                Div => a.checked_div(b),
                Rem => a.checked_rem(b),
                Lt => return Ok(Value::Bool(a < b)),
                Le => return Ok(Value::Bool(a <= b)),
                Gt => return Ok(Value::Bool(a > b)),
                Ge => return Ok(Value::Bool(a >= b)),
                Eq | Ne | BinOp::And | BinOp::Or => return Ok(Value::Unit),
            };
            res.map(Value::Int).ok_or_else(|| {
                RuntimeError::Arithmetic("integer overflow or divide by zero").into()
            })
        }
        (Value::Float(a), Value::Float(b)) => Ok(match op {
            Add => Value::Float(a + b),
            Sub => Value::Float(a - b),
            Mul => Value::Float(a * b),
            Div => Value::Float(a / b),
            Rem => Value::Float(a % b),
            Lt => Value::Bool(a < b),
            Le => Value::Bool(a <= b),
            Gt => Value::Bool(a > b),
            Ge => Value::Bool(a >= b),
            Eq | Ne | BinOp::And | BinOp::Or => Value::Unit,
        }),
        // String concatenation with `+`.
        (Value::Str(a, _), Value::Str(b, _)) if matches!(op, Add) => {
            let mut s = (*a).clone();
            s.push_str(&b);
            interp.new_str(s)
        }
        (l, r) => Err(RuntimeError::Type(format!(
            "binary {op:?} on {} and {}",
            l.type_name(),
            r.type_name()
        ))
        .into()),
    }
}

/// Collapse a non-error control signal that escaped to the top into an error.
fn unwrap_error(c: Control) -> RuntimeError {
    match c {
        Control::Error(e) => e,
        Control::Return(_) => RuntimeError::Msg(String::from("`return` outside a function")),
        Control::Break(..) => RuntimeError::Msg(String::from("`break` outside a loop")),
        Control::Continue(_) => RuntimeError::Msg(String::from("`continue` outside a loop")),
    }
}

/// Errors from [`run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    /// A parse error.
    Parse(ParseError),
    /// A runtime error.
    Runtime(RuntimeError),
}

impl core::fmt::Display for RunError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "{e}"),
            Self::Runtime(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for RunError {}

/// Parse and run an ncScript program's `main`, returning its value and the
/// captured `print` output.
///
/// # Errors
///
/// A [`RunError`] on a parse or runtime failure.
pub fn run(src: &str) -> Result<(Value, Vec<String>), RunError> {
    let program = parse(src).map_err(RunError::Parse)?;
    let mut interp = Interpreter::new();
    interp.load(&program);
    let value = interp.run_main().map_err(RunError::Runtime)?;
    Ok((value, interp.output))
}

/// Like [`run`], but enforcing the given deterministic [`Limits`].
///
/// Exceeding a limit returns `Err(RunError::Runtime(RuntimeError::LimitExceeded(_)))`.
/// To enforce [`Limits::deadline_micros`], build an [`Interpreter`] directly and
/// attach a [`Clock`] with [`Interpreter::with_clock`].
///
/// # Errors
///
/// A [`RunError`] on a parse failure, a runtime error, or a limit being hit.
pub fn run_with_limits(src: &str, limits: Limits) -> Result<(Value, Vec<String>), RunError> {
    let program = parse(src).map_err(RunError::Parse)?;
    let mut interp = Interpreter::new().with_limits(limits);
    interp.load(&program);
    let value = interp.run_main().map_err(RunError::Runtime)?;
    Ok((value, interp.output))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval_main(src: &str) -> Value {
        run(src).expect("program should run").0
    }

    #[test]
    fn arithmetic_precedence_and_int_result() {
        assert!(matches!(
            eval_main("fn main() { 2 + 3 * 4 }"),
            Value::Int(14)
        ));
        assert!(matches!(
            eval_main("fn main() { (2 + 3) * 4 }"),
            Value::Int(20)
        ));
        assert!(matches!(eval_main("fn main() { 7 % 3 }"), Value::Int(1)));
    }

    #[test]
    fn let_bindings_and_lexical_scope() {
        let v = eval_main("fn main() { let a = 10; let b = a * 2; b - 5 }");
        assert!(matches!(v, Value::Int(15)));
    }

    #[test]
    fn assignment_and_compound_assignment() {
        let v = eval_main("fn main() { let mut x = 1; x = x + 4; x += 5; x }");
        assert!(matches!(v, Value::Int(10)));
    }

    #[test]
    fn if_else_and_bool_short_circuit() {
        assert!(matches!(
            eval_main("fn main() { if 3 > 2 { 1 } else { 0 } }"),
            Value::Int(1)
        ));
        // short-circuit: the rhs (which would divide by zero) is never evaluated
        assert!(matches!(
            eval_main("fn main() { if false && (1 / 0 == 0) { 1 } else { 2 } }"),
            Value::Int(2)
        ));
    }

    #[test]
    fn while_loop_accumulates() {
        let v = eval_main(
            "fn main() { let mut i = 0; let mut s = 0; while i < 5 { s = s + i; i = i + 1; } s }",
        );
        assert!(matches!(v, Value::Int(10))); // 0+1+2+3+4
    }

    #[test]
    fn for_loop_over_list() {
        let v = eval_main("fn main() { let mut s = 0; for x in [1, 2, 3, 4] { s = s + x; } s }");
        assert!(matches!(v, Value::Int(10)));
    }

    #[test]
    fn recursion_fibonacci() {
        let src =
            "fn fib(n) { if n < 2 { n } else { fib(n - 1) + fib(n - 2) } } fn main() { fib(10) }";
        assert!(matches!(eval_main(src), Value::Int(55)));
    }

    #[test]
    fn string_concat_and_print_output() {
        let (_v, out) =
            run(r#"fn main() { let who = "NexaCore"; print("hello, " + who); }"#).unwrap();
        assert_eq!(out, ["hello, NexaCore"]);
    }

    #[test]
    fn list_push_len_index() {
        let v = eval_main("fn main() { let xs = [10, 20]; xs.push(30); xs[1] + xs.len() }");
        // xs[1]=20, len=3 → 23
        assert!(matches!(v, Value::Int(23)));
    }

    #[test]
    fn struct_literal_and_field_access() {
        let src = r"struct P { x: Int, y: Int } fn main() { let p = P { x: 3, y: 4 }; p.x + p.y }";
        assert!(matches!(eval_main(src), Value::Int(7)));
    }

    #[test]
    fn match_with_or_pattern_and_guard() {
        let src = "fn classify(n) { match n { 0 | 1 => 100, p if p < 0 => -1, p => p } } \
                   fn main() { classify(0) + classify(-5) + classify(9) }";
        // 100 + (-1) + 9 = 108
        assert!(matches!(eval_main(src), Value::Int(108)));
    }

    #[test]
    fn result_match_and_try_operator() {
        let src = "fn get(ok) { if ok { Ok(7) } else { Err(0) } } \
                   fn use_it(ok) { let v = get(ok)?; Ok(v + 1) } \
                   fn main() { match use_it(true) { Ok(x) => x, Err(_) => -1 } }";
        assert!(matches!(eval_main(src), Value::Int(8)));
        let src2 = "fn get(ok) { if ok { Ok(7) } else { Err(42) } } \
                    fn use_it(ok) { let v = get(ok)?; Ok(v + 1) } \
                    fn main() { match use_it(false) { Ok(x) => x, Err(e) => e } }";
        assert!(matches!(eval_main(src2), Value::Int(42))); // `?` propagated Err(42)
    }

    #[test]
    fn divide_by_zero_is_a_clean_error() {
        let e = run("fn main() { 1 / 0 }").unwrap_err();
        assert!(matches!(e, RunError::Runtime(RuntimeError::Arithmetic(_))));
    }

    #[test]
    fn undefined_variable_errors() {
        let e = run("fn main() { nope }").unwrap_err();
        assert!(matches!(e, RunError::Runtime(RuntimeError::Undefined(_))));
    }

    // ---- deterministic resource limits (WS18-02.6/.7/.8) ------------------

    #[test]
    fn step_limit_aborts_an_infinite_loop_cleanly() {
        let e = run_with_limits(
            "fn main() { loop {} }",
            Limits {
                max_steps: Some(1000),
                ..Limits::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            e,
            RunError::Runtime(RuntimeError::LimitExceeded(Limit::Steps))
        ));
    }

    #[test]
    fn step_limit_lets_a_bounded_program_finish() {
        let v = run_with_limits(
            "fn fib(n) { if n < 2 { n } else { fib(n - 1) + fib(n - 2) } } fn main() { fib(10) }",
            Limits {
                max_steps: Some(1_000_000),
                ..Limits::default()
            },
        )
        .expect("bounded program stays within budget")
        .0;
        assert!(matches!(v, Value::Int(55)));
    }

    #[test]
    fn call_depth_limit_aborts_unbounded_recursion() {
        // Without the limit this would overflow the host stack; with it the run
        // aborts cleanly instead.
        let e = run_with_limits(
            "fn f() { f() } fn main() { f() }",
            Limits {
                max_call_depth: Some(64),
                ..Limits::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            e,
            RunError::Runtime(RuntimeError::LimitExceeded(Limit::CallDepth))
        ));
    }

    /// A deterministic clock that advances one microsecond per reading.
    struct TickClock(core::cell::Cell<u64>);

    impl Clock for TickClock {
        fn now_micros(&self) -> u64 {
            let now = self.0.get();
            self.0.set(now.saturating_add(1));
            now
        }
    }

    #[test]
    fn time_limit_aborts_via_injected_clock() {
        use alloc::rc::Rc;

        let program = parse("fn main() { loop {} }").unwrap();
        let clock = Rc::new(TickClock(core::cell::Cell::new(0)));
        let mut interp = Interpreter::new()
            .with_limits(Limits {
                deadline_micros: Some(5),
                ..Limits::default()
            })
            .with_clock(clock);
        interp.load(&program);
        let e = interp.run_main().unwrap_err();
        assert!(matches!(e, RuntimeError::LimitExceeded(Limit::Time)));
    }

    #[test]
    fn memory_limit_aborts_unbounded_list_growth() {
        // One live list grows without bound; the live budget trips cleanly.
        let e = run_with_limits(
            "fn main() { let xs = []; let mut i = 0; while i < 100000 { xs.push(i); i = i + 1; } }",
            Limits {
                max_alloc_bytes: Some(4000),
                ..Limits::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            e,
            RunError::Runtime(RuntimeError::LimitExceeded(Limit::Memory))
        ));
    }

    #[test]
    fn memory_limit_is_live_not_cumulative() {
        // Each iteration replaces `s`, dropping the previous string, so only one
        // string is live at a time. A cumulative accounting would trip on the
        // tight budget; a live one does not.
        let v = run_with_limits(
            "fn main() { let mut s = \"x\"; let mut i = 0; \
             while i < 1000 { s = \"abcdefgh\"; i = i + 1; } i }",
            Limits {
                max_alloc_bytes: Some(4000),
                ..Limits::default()
            },
        )
        .expect("reused binding stays within the live budget")
        .0;
        assert!(matches!(v, Value::Int(1000)));
    }

    // ---- capability gating (WS18-02.9/.10) --------------------------------

    /// A host handler that "opens sockets" for `net::connect` and reads files
    /// for `fs::read`, recording how many times it actually ran.
    struct TestHost {
        calls: alloc::rc::Rc<core::cell::Cell<u32>>,
    }

    impl EffectHandler for TestHost {
        fn required_capability(&self, namespace: &str, function: &str) -> Option<String> {
            match (namespace, function) {
                ("net", "connect") => Some(String::from("net.connect")),
                ("fs", "read") => Some(String::from("fs.read")),
                _ => None,
            }
        }

        fn perform(
            &mut self,
            namespace: &str,
            _function: &str,
            _args: &[Value],
        ) -> Result<HostValue, RuntimeError> {
            self.calls.set(self.calls.get().saturating_add(1));
            if namespace == "fs" {
                Ok(HostValue::Str(String::from("file-contents")))
            } else {
                Ok(HostValue::Bool(true))
            }
        }
    }

    fn host_with_counter() -> (TestHost, alloc::rc::Rc<core::cell::Cell<u32>>) {
        let calls = alloc::rc::Rc::new(core::cell::Cell::new(0u32));
        (
            TestHost {
                calls: alloc::rc::Rc::clone(&calls),
            },
            calls,
        )
    }

    #[test]
    fn effect_denied_without_capability_and_handler_not_run() {
        let (host, calls) = host_with_counter();
        let program = parse(r#"fn main() { net::connect("1.2.3.4:80") }"#).unwrap();
        let mut interp = Interpreter::new().with_effect_handler(Box::new(host));
        // No capabilities granted → deny-by-default.
        interp.load(&program);
        let e = interp.run_main().unwrap_err();
        assert!(matches!(e, RuntimeError::CapabilityDenied(ref c) if c == "net.connect"));
        // The handler must never have been reached.
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn effect_allowed_when_capability_granted() {
        let (host, calls) = host_with_counter();
        let program = parse(r#"fn main() { net::connect("1.2.3.4:80") }"#).unwrap();
        let mut interp = Interpreter::new()
            .with_effect_handler(Box::new(host))
            .with_capabilities(Grants::none().with(Capability::any("net.connect")));
        interp.load(&program);
        let v = interp.run_main().unwrap();
        assert!(matches!(v, Value::Bool(true)));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn effect_scope_is_enforced() {
        let program_ok = parse(r#"fn main() { fs::read("/etc/nexacore/notes/a.txt") }"#).unwrap();
        let program_bad = parse(r#"fn main() { fs::read("/etc/passwd") }"#).unwrap();
        let grant = || Grants::none().with(Capability::scoped("fs.read", "/etc/nexacore"));

        // In-scope read is allowed and returns the host string.
        let (host, _calls) = host_with_counter();
        let mut interp = Interpreter::new()
            .with_effect_handler(Box::new(host))
            .with_capabilities(grant());
        interp.load(&program_ok);
        let (v, _out) = (interp.run_main().unwrap(), interp.output());
        assert_eq!(v.display(), "file-contents");

        // Out-of-scope read is denied.
        let (host, calls) = host_with_counter();
        let mut interp = Interpreter::new()
            .with_effect_handler(Box::new(host))
            .with_capabilities(grant());
        interp.load(&program_bad);
        let e = interp.run_main().unwrap_err();
        assert!(matches!(e, RuntimeError::CapabilityDenied(ref c) if c == "fs.read"));
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn namespaced_call_without_handler_is_an_enum_constructor() {
        // No handler ⇒ no effects exist ⇒ `net::connect(..)` is inert data, never
        // I/O. This is the "no ambient access" guarantee.
        let v = eval_main(r#"fn main() { net::connect("x") }"#);
        assert!(matches!(v, Value::Enum { .. }));
    }

    #[test]
    fn header_capabilities_are_recorded() {
        let program =
            parse("#![capabilities(fs.read(\"/etc\"), ai.invoke)]\nfn main() {}").unwrap();
        let mut interp = Interpreter::new();
        interp.load(&program);
        let declared = interp.declared_capabilities();
        assert_eq!(declared.len(), 2);
        assert_eq!(declared[0], Capability::scoped("fs.read", "/etc"));
        assert_eq!(declared[1], Capability::any("ai.invoke"));
    }

    // ---- pure stdlib modules (WS18-03.2/.3, host vectors WS18-03.11) -------

    #[test]
    fn stdlib_string_scalars() {
        assert!(matches!(
            eval_main(r#"fn main() { string::len("héllo") }"#),
            Value::Int(5)
        ));
        assert_eq!(
            eval_main(r#"fn main() { string::upper("abc") }"#).display(),
            "ABC"
        );
        assert_eq!(
            eval_main(r#"fn main() { string::lower("ABC") }"#).display(),
            "abc"
        );
        assert_eq!(
            eval_main(r#"fn main() { string::trim("  hi  ") }"#).display(),
            "hi"
        );
        assert!(matches!(
            eval_main(r#"fn main() { string::contains("hello", "ell") }"#),
            Value::Bool(true)
        ));
        assert!(matches!(
            eval_main(r#"fn main() { string::starts_with("hello", "he") }"#),
            Value::Bool(true)
        ));
        assert!(matches!(
            eval_main(r#"fn main() { string::ends_with("hello", "lo") }"#),
            Value::Bool(true)
        ));
        assert_eq!(
            eval_main(r#"fn main() { string::replace("a.b.c", ".", "-") }"#).display(),
            "a-b-c"
        );
        assert_eq!(
            eval_main(r#"fn main() { string::repeat("ab", 3) }"#).display(),
            "ababab"
        );
        assert_eq!(
            eval_main("fn main() { string::from_int(42) }").display(),
            "42"
        );
    }

    #[test]
    fn stdlib_string_split_and_parse() {
        let count = eval_main(r#"fn main() { let p = string::split("a,b,c", ","); p.len() }"#);
        assert!(matches!(count, Value::Int(3)));
        let second = eval_main(r#"fn main() { let p = string::split("a,b,c", ","); p[2] }"#);
        assert_eq!(second.display(), "c");
        let ok =
            eval_main(r#"fn main() { match string::to_int("123") { Some(n) => n, None => -1 } }"#);
        assert!(matches!(ok, Value::Int(123)));
        let bad =
            eval_main(r#"fn main() { match string::to_int("nope") { Some(n) => n, None => -1 } }"#);
        assert!(matches!(bad, Value::Int(-1)));
    }

    #[test]
    fn stdlib_repeat_respects_memory_limit() {
        let e = run_with_limits(
            r#"fn main() { string::repeat("x", 100000) }"#,
            Limits {
                max_alloc_bytes: Some(1000),
                ..Limits::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            e,
            RunError::Runtime(RuntimeError::LimitExceeded(Limit::Memory))
        ));
    }

    #[test]
    fn stdlib_math_module() {
        assert!(matches!(
            eval_main("fn main() { math::abs(-7) }"),
            Value::Int(7)
        ));
        assert_eq!(eval_main("fn main() { math::abs(-2.5) }").display(), "2.5");
        assert!(matches!(
            eval_main("fn main() { math::min(3, 8) }"),
            Value::Int(3)
        ));
        assert!(matches!(
            eval_main("fn main() { math::max(3, 8) }"),
            Value::Int(8)
        ));
        assert!(matches!(
            eval_main("fn main() { math::pow(2, 10) }"),
            Value::Int(1024)
        ));
        assert!(matches!(
            eval_main("fn main() { math::gcd(48, 36) }"),
            Value::Int(12)
        ));
        assert!(matches!(
            eval_main("fn main() { math::isqrt(99) }"),
            Value::Int(9)
        ));
    }

    #[test]
    fn stdlib_math_errors_are_clean() {
        let neg_exp = run("fn main() { math::pow(2, -1) }").unwrap_err();
        assert!(matches!(
            neg_exp,
            RunError::Runtime(RuntimeError::Arithmetic(_))
        ));
        let unknown = run("fn main() { math::nope(1) }").unwrap_err();
        assert!(matches!(
            unknown,
            RunError::Runtime(RuntimeError::NoMethod(_))
        ));
    }

    #[test]
    fn unknown_namespace_is_still_an_enum_constructor() {
        // A genuinely unknown two-segment call remains inert data, not stdlib.
        let v = eval_main("fn main() { Color::Red }");
        assert!(matches!(v, Value::Enum { .. }));
    }

    #[test]
    fn stdlib_datetime_decomposition() {
        // 1_700_000_000 = 2023-11-14T22:13:20Z (a Tuesday).
        assert!(matches!(
            eval_main("fn main() { datetime::year(1700000000) }"),
            Value::Int(2023)
        ));
        assert!(matches!(
            eval_main("fn main() { datetime::month(1700000000) }"),
            Value::Int(11)
        ));
        assert!(matches!(
            eval_main("fn main() { datetime::day(1700000000) }"),
            Value::Int(14)
        ));
        assert!(matches!(
            eval_main("fn main() { datetime::hour(1700000000) }"),
            Value::Int(22)
        ));
        assert!(matches!(
            eval_main("fn main() { datetime::minute(1700000000) }"),
            Value::Int(13)
        ));
        assert!(matches!(
            eval_main("fn main() { datetime::second(1700000000) }"),
            Value::Int(20)
        ));
        // Day 0 (1970-01-01) is a Thursday (4); the sample is a Tuesday (2).
        assert!(matches!(
            eval_main("fn main() { datetime::weekday(0) }"),
            Value::Int(4)
        ));
        assert!(matches!(
            eval_main("fn main() { datetime::weekday(1700000000) }"),
            Value::Int(2)
        ));
    }

    #[test]
    fn stdlib_datetime_format_and_construct() {
        assert_eq!(
            eval_main("fn main() { datetime::format_iso(0) }").display(),
            "1970-01-01T00:00:00Z"
        );
        assert_eq!(
            eval_main("fn main() { datetime::format_iso(1700000000) }").display(),
            "2023-11-14T22:13:20Z"
        );
        assert!(matches!(
            eval_main("fn main() { datetime::from_ymd(1970, 1, 1) }"),
            Value::Int(0)
        ));
        // Round-trip through a leap day.
        let leap = "fn main() { let t = datetime::from_ymd(2024, 2, 29); \
                    datetime::year(t) * 10000 + datetime::month(t) * 100 + datetime::day(t) }";
        assert!(matches!(eval_main(leap), Value::Int(20_240_229)));
    }

    #[test]
    fn stdlib_datetime_arithmetic() {
        assert!(matches!(
            eval_main("fn main() { datetime::add_seconds(0, 3661) }"),
            Value::Int(3661)
        ));
        assert!(matches!(
            eval_main("fn main() { datetime::add_days(0, 365) }"),
            Value::Int(31_536_000)
        ));
        // 1970 is not a leap year, so +365 days lands on 1971-01-01.
        assert!(matches!(
            eval_main("fn main() { datetime::year(datetime::add_days(0, 365)) }"),
            Value::Int(1971)
        ));
    }

    #[test]
    fn stdlib_datetime_errors_are_clean() {
        let bad_month = run("fn main() { datetime::from_ymd(2020, 13, 1) }").unwrap_err();
        assert!(matches!(
            bad_month,
            RunError::Runtime(RuntimeError::Type(_))
        ));
        let overflow = run("fn main() { datetime::add_days(0, 9000000000000000) }").unwrap_err();
        assert!(matches!(
            overflow,
            RunError::Runtime(RuntimeError::Arithmetic(_))
        ));
        let unknown = run("fn main() { datetime::nope(0) }").unwrap_err();
        assert!(matches!(
            unknown,
            RunError::Runtime(RuntimeError::NoMethod(_))
        ));
    }

    // ---- collections stdlib module (WS18-03.1, host vectors WS18-03.11) ----

    #[test]
    fn stdlib_collections_len_and_is_empty() {
        assert!(matches!(
            eval_main("fn main() { collections::len([10, 20, 30]) }"),
            Value::Int(3)
        ));
        assert!(matches!(
            eval_main("fn main() { collections::is_empty([]) }"),
            Value::Bool(true)
        ));
        assert!(matches!(
            eval_main("fn main() { collections::is_empty([1]) }"),
            Value::Bool(false)
        ));
    }

    #[test]
    fn stdlib_collections_get_first_last() {
        assert!(matches!(
            eval_main(
                "fn main() { match collections::get([10, 20], 1) { Some(n) => n, None => -1 } }"
            ),
            Value::Int(20)
        ));
        // Out-of-range and negative indices yield None, never a panic.
        assert!(matches!(
            eval_main(
                "fn main() { match collections::get([10, 20], 5) { Some(n) => n, None => -1 } }"
            ),
            Value::Int(-1)
        ));
        assert!(matches!(
            eval_main(
                "fn main() { match collections::get([10, 20], -1) { Some(n) => n, None => -1 } }"
            ),
            Value::Int(-1)
        ));
        assert!(matches!(
            eval_main(
                "fn main() { match collections::first([7, 8, 9]) { Some(n) => n, None => -1 } }"
            ),
            Value::Int(7)
        ));
        assert!(matches!(
            eval_main(
                "fn main() { match collections::last([7, 8, 9]) { Some(n) => n, None => -1 } }"
            ),
            Value::Int(9)
        ));
        assert!(matches!(
            eval_main("fn main() { match collections::first([]) { Some(_n) => 1, None => 0 } }"),
            Value::Int(0)
        ));
    }

    #[test]
    fn stdlib_collections_contains_and_index_of() {
        assert!(matches!(
            eval_main("fn main() { collections::contains([1, 2, 3], 2) }"),
            Value::Bool(true)
        ));
        assert!(matches!(
            eval_main("fn main() { collections::contains([1, 2, 3], 9) }"),
            Value::Bool(false)
        ));
        assert!(matches!(
            eval_main(
                "fn main() { match collections::index_of([5, 6, 7], 7) { Some(i) => i, None => -1 } }"
            ),
            Value::Int(2)
        ));
        assert!(matches!(
            eval_main(
                "fn main() { match collections::index_of([5, 6, 7], 9) { Some(i) => i, None => -1 } }"
            ),
            Value::Int(-1)
        ));
    }

    #[test]
    fn stdlib_collections_reverse_is_pure() {
        // reverse returns a fresh list and leaves the input untouched.
        assert!(matches!(
            eval_main("fn main() { let r = collections::reverse([1, 2, 3]); r[0] }"),
            Value::Int(3)
        ));
        assert!(matches!(
            eval_main("fn main() { let xs = [1, 2, 3]; let _r = collections::reverse(xs); xs[0] }"),
            Value::Int(1)
        ));
    }

    #[test]
    fn stdlib_collections_concat_and_slice() {
        assert!(matches!(
            eval_main("fn main() { let c = collections::concat([1, 2], [3, 4]); c.len() }"),
            Value::Int(4)
        ));
        assert!(matches!(
            eval_main("fn main() { let c = collections::concat([1, 2], [3, 4]); c[2] }"),
            Value::Int(3)
        ));
        assert!(matches!(
            eval_main("fn main() { let s = collections::slice([10, 20, 30, 40], 1, 3); s[0] }"),
            Value::Int(20)
        ));
        // End past the length clamps; an inverted range yields an empty list.
        assert!(matches!(
            eval_main("fn main() { collections::slice([1, 2, 3], 2, 10).len() }"),
            Value::Int(1)
        ));
        assert!(matches!(
            eval_main("fn main() { collections::slice([1, 2, 3], 2, 1).len() }"),
            Value::Int(0)
        ));
    }

    #[test]
    fn stdlib_collections_errors_are_clean() {
        let not_a_list = run("fn main() { collections::len(5) }").unwrap_err();
        assert!(matches!(
            not_a_list,
            RunError::Runtime(RuntimeError::Type(_))
        ));
        let unknown = run("fn main() { collections::nope([1]) }").unwrap_err();
        assert!(matches!(
            unknown,
            RunError::Runtime(RuntimeError::NoMethod(_))
        ));
    }

    // ---- json stdlib module (WS18-03.4, host vectors WS18-03.11) -----------

    #[test]
    fn stdlib_json_stringify_scalars_and_lists() {
        assert_eq!(
            eval_main("fn main() { json::stringify(42) }").display(),
            "42"
        );
        assert_eq!(
            eval_main("fn main() { json::stringify(true) }").display(),
            "true"
        );
        assert_eq!(
            eval_main("fn main() { json::stringify(false) }").display(),
            "false"
        );
        assert_eq!(
            eval_main("fn main() { json::stringify(3.5) }").display(),
            "3.5"
        );
        // An integral float keeps a fraction so it round-trips as a float.
        assert_eq!(
            eval_main("fn main() { json::stringify(2.0) }").display(),
            "2.0"
        );
        assert_eq!(
            eval_main(r#"fn main() { json::stringify("hi") }"#).display(),
            "\"hi\""
        );
        assert_eq!(
            eval_main("fn main() { json::stringify([1, 2, 3]) }").display(),
            "[1,2,3]"
        );
        assert_eq!(
            eval_main("fn main() { json::stringify([[1], [2]]) }").display(),
            "[[1],[2]]"
        );
    }

    #[test]
    fn stdlib_json_parse_scalars() {
        assert!(matches!(
            eval_main(r#"fn main() { match json::parse("42") { Some(n) => n, None => -1 } }"#),
            Value::Int(42)
        ));
        assert!(matches!(
            eval_main(r#"fn main() { match json::parse("true") { Some(_b) => 1, None => 0 } }"#),
            Value::Int(1)
        ));
        assert!(matches!(
            eval_main(r#"fn main() { match json::parse("null") { Some(_u) => 1, None => 0 } }"#),
            Value::Int(1)
        ));
        assert_eq!(
            eval_main(r#"fn main() { match json::parse("3.5") { Some(f) => f, None => -1.0 } }"#)
                .display(),
            "3.5"
        );
    }

    #[test]
    fn stdlib_json_parse_malformed_is_none() {
        // Bare word, trailing garbage, and an unterminated string all fail.
        for src in [
            r#"fn main() { match json::parse("nope") { Some(_x) => 1, None => 0 } }"#,
            r#"fn main() { match json::parse("[1] x") { Some(_x) => 1, None => 0 } }"#,
            r#"fn main() { match json::parse("\"ab") { Some(_x) => 1, None => 0 } }"#,
        ] {
            assert!(
                matches!(eval_main(src), Value::Int(0)),
                "should fail: {src}"
            );
        }
    }

    #[test]
    fn stdlib_json_parse_arrays_and_objects() {
        assert!(matches!(
            eval_main(
                r#"fn main() { match json::parse("[1, 2, 3]") { Some(a) => a.len(), None => -1 } }"#
            ),
            Value::Int(3)
        ));
        assert!(matches!(
            eval_main(
                r#"fn main() { match json::parse(" [ 1, [2, 3] ] ") { Some(a) => a.len(), None => -1 } }"#
            ),
            Value::Int(2)
        ));
        // Object with quoted keys and whitespace parses to a value.
        assert!(matches!(
            eval_main(
                r#"fn main() { match json::parse("{ \"a\": 1, \"b\": 2 }") { Some(_o) => 1, None => 0 } }"#
            ),
            Value::Int(1)
        ));
    }

    #[test]
    fn stdlib_json_round_trip() {
        // A list round-trips through stringify -> parse with element access.
        assert!(matches!(
            eval_main(
                "fn main() { let s = json::stringify([10, 20, 30]); match json::parse(s) { Some(v) => v[2], None => -1 } }"
            ),
            Value::Int(30)
        ));
        // A string containing characters that must be escaped re-parses cleanly.
        assert!(matches!(
            eval_main(
                r#"fn main() { let s = json::stringify("a\"b\nc"); match json::parse(s) { Some(_x) => 1, None => 0 } }"#
            ),
            Value::Int(1)
        ));
        // A `\uXXXX` escape decodes (U+0041 = 'A').
        assert!(matches!(
            eval_main(
                r#"fn main() { match json::parse("\"\\u0041\"") { Some(_s) => 1, None => 0 } }"#
            ),
            Value::Int(1)
        ));
    }

    #[test]
    fn stdlib_json_errors_are_clean() {
        // Enums have no JSON representation (here: `Option::None` from to_int).
        let enum_err = run(r#"fn main() { json::stringify(string::to_int("x")) }"#).unwrap_err();
        assert!(matches!(enum_err, RunError::Runtime(RuntimeError::Type(_))));
        let unknown = run("fn main() { json::nope(1) }").unwrap_err();
        assert!(matches!(
            unknown,
            RunError::Runtime(RuntimeError::NoMethod(_))
        ));
    }
}
