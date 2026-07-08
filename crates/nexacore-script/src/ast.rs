//! ncScript abstract syntax tree (WS18-02.3).
//!
//! Mirrors the `NCIP-ncScript-030` § S13 grammar. Produced by [`crate::parser`]
//! and consumed by the tree-walking interpreter (WS18-02.4+).
//!
//! AST nodes derive `PartialEq` (for tests) but not `Eq`: expression nodes
//! carry `f64` literals, so a uniform `Eq` is impossible and would be
//! inconsistent across node types.
#![allow(
    clippy::derive_partial_eq_without_eq,
    reason = "Expr carries f64 literals; a uniform Eq across AST nodes is impossible"
)]

use alloc::{boxed::Box, string::String, vec::Vec};

/// A parsed compilation unit: an optional capability header, item definitions,
/// and top-level statements.
#[derive(Debug, Clone, PartialEq)]
pub struct Program {
    /// Whether a `#!` shebang line was present.
    pub shebang: bool,
    /// Declared capabilities from the `#![capabilities(...)]` header.
    pub capabilities: Vec<CapDecl>,
    /// Item definitions (fn / struct / enum / const / use / impl).
    pub items: Vec<Item>,
    /// Top-level statements after the items.
    pub statements: Vec<Stmt>,
}

/// One declared capability, e.g. `fs.read("/etc")` or `ai.invoke`.
#[derive(Debug, Clone, PartialEq)]
pub struct CapDecl {
    /// Dotted capability name (e.g. `fs.read`).
    pub name: String,
    /// Optional scope argument.
    pub scope: Option<CapScope>,
}

/// The scope argument of a capability declaration.
#[derive(Debug, Clone, PartialEq)]
pub enum CapScope {
    /// A string scope (e.g. a path or host glob).
    Str(String),
    /// An integer scope.
    Int(i64),
}

/// A top-level item.
#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    /// Function definition.
    Fn(FnDef),
    /// Struct definition.
    Struct(StructDef),
    /// Enum definition.
    Enum(EnumDef),
    /// Constant definition.
    Const(ConstDef),
    /// `use` import path.
    Use(Vec<String>),
    /// `impl` block.
    Impl(ImplDef),
}

/// A function definition.
#[derive(Debug, Clone, PartialEq)]
pub struct FnDef {
    /// Function name.
    pub name: String,
    /// Generic type parameter names.
    pub generics: Vec<String>,
    /// Parameters.
    pub params: Vec<Param>,
    /// Optional return type.
    pub ret: Option<Type>,
    /// Body block.
    pub body: Block,
}

/// A function parameter.
#[derive(Debug, Clone, PartialEq)]
pub struct Param {
    /// Parameter name (or `self`).
    pub name: String,
    /// Optional declared type.
    pub ty: Option<Type>,
    /// Whether this is the `self` receiver.
    pub is_self: bool,
}

/// A struct definition (unit structs have no fields).
#[derive(Debug, Clone, PartialEq)]
pub struct StructDef {
    /// Struct name.
    pub name: String,
    /// Generic parameter names.
    pub generics: Vec<String>,
    /// Fields (empty for a unit struct).
    pub fields: Vec<Field>,
    /// Whether this is a unit struct (`struct X;`).
    pub unit: bool,
}

/// A named, typed field.
#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    /// Field name.
    pub name: String,
    /// Field type.
    pub ty: Type,
}

/// An enum definition.
#[derive(Debug, Clone, PartialEq)]
pub struct EnumDef {
    /// Enum name.
    pub name: String,
    /// Generic parameter names.
    pub generics: Vec<String>,
    /// Variants.
    pub variants: Vec<Variant>,
}

/// An enum variant.
#[derive(Debug, Clone, PartialEq)]
pub struct Variant {
    /// Variant name.
    pub name: String,
    /// Variant payload shape.
    pub kind: VariantKind,
}

/// The payload shape of an enum variant.
#[derive(Debug, Clone, PartialEq)]
pub enum VariantKind {
    /// No payload.
    Unit,
    /// Tuple payload (positional types).
    Tuple(Vec<Type>),
    /// Struct payload (named fields).
    Struct(Vec<Field>),
}

/// A `const` definition.
#[derive(Debug, Clone, PartialEq)]
pub struct ConstDef {
    /// Constant name.
    pub name: String,
    /// Declared type.
    pub ty: Type,
    /// Value expression.
    pub value: Expr,
}

/// An `impl` block.
#[derive(Debug, Clone, PartialEq)]
pub struct ImplDef {
    /// Trait name for `impl Trait for Type`, else `None`.
    pub trait_name: Option<String>,
    /// The type being implemented.
    pub ty: Type,
    /// Methods.
    pub methods: Vec<FnDef>,
}

/// A type expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    /// A named (optionally generic) type, e.g. `Result<T, E>`.
    Path(Vec<String>, Vec<Type>),
    /// A list type `[T]`.
    List(Box<Type>),
    /// A map type `{K: V}`.
    Map(Box<Type>, Box<Type>),
    /// A tuple type `(A, B)`; the empty tuple `()` is Unit.
    Tuple(Vec<Type>),
    /// An optional type `T?`.
    Optional(Box<Type>),
}

/// A block: zero or more statements and an optional trailing expression.
#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    /// Statements.
    pub statements: Vec<Stmt>,
    /// Optional trailing (value) expression.
    pub tail: Option<Box<Expr>>,
}

/// A statement.
#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    /// `let [mut] pat [: ty] [= expr];`
    Let {
        /// Whether the binding is mutable.
        mutable: bool,
        /// The bound pattern.
        pat: Pattern,
        /// Optional declared type.
        ty: Option<Type>,
        /// Optional initializer.
        value: Option<Expr>,
    },
    /// An expression used as a statement (`expr;`).
    Expr(Expr),
    /// `place op= expr;`
    Assign {
        /// The assignment target (a place expression).
        place: Expr,
        /// The assignment operator.
        op: AssignOp,
        /// The assigned value.
        value: Expr,
    },
    /// A nested item.
    Item(Item),
}

/// An assignment operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignOp {
    /// `=`
    Assign,
    /// `+=`
    Add,
    /// `-=`
    Sub,
    /// `*=`
    Mul,
    /// `/=`
    Div,
    /// `%=`
    Rem,
}

/// A unary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    /// `-`
    Neg,
    /// `!`
    Not,
}

/// A binary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    /// `||`
    Or,
    /// `&&`
    And,
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `*`
    Mul,
    /// `/`
    Div,
    /// `%`
    Rem,
}

/// An expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// Integer literal.
    Int(i64),
    /// Float literal.
    Float(f64),
    /// String literal.
    Str(String),
    /// Boolean literal.
    Bool(bool),
    /// Unit value `()`.
    Unit,
    /// A path: variable / enum variant / function reference.
    Path(Vec<String>),
    /// Unary operation.
    Unary {
        /// Operator.
        op: UnOp,
        /// Operand.
        expr: Box<Expr>,
    },
    /// Binary operation.
    Binary {
        /// Operator.
        op: BinOp,
        /// Left operand.
        lhs: Box<Expr>,
        /// Right operand.
        rhs: Box<Expr>,
    },
    /// Function call `callee(args)`.
    Call {
        /// The callee expression.
        callee: Box<Expr>,
        /// Arguments.
        args: Vec<Expr>,
    },
    /// Method call `recv.method(args)`.
    MethodCall {
        /// Receiver.
        recv: Box<Expr>,
        /// Method name.
        method: String,
        /// Arguments.
        args: Vec<Expr>,
    },
    /// Field access `recv.name`.
    Field {
        /// Receiver.
        recv: Box<Expr>,
        /// Field name.
        name: String,
    },
    /// Index `recv[index]`.
    Index {
        /// Receiver.
        recv: Box<Expr>,
        /// Index expression.
        index: Box<Expr>,
    },
    /// Try operator `expr?`.
    Try(Box<Expr>),
    /// Await `expr.await`.
    Await(Box<Expr>),
    /// Struct literal `Path { field: value, ... }`.
    StructLit {
        /// The struct path.
        path: Vec<String>,
        /// Field initializers (`None` value = field shorthand).
        fields: Vec<(String, Option<Expr>)>,
    },
    /// List literal `[a, b, ...]`.
    List(Vec<Expr>),
    /// Map literal `{k: v, ...}`.
    Map(Vec<(Expr, Expr)>),
    /// Tuple `(a, b, ...)`.
    Tuple(Vec<Expr>),
    /// `if cond { } else { }`.
    If {
        /// Condition.
        cond: Box<Expr>,
        /// Then block.
        then_block: Block,
        /// Optional else branch (another `if` or a block).
        else_branch: Option<Box<Expr>>,
    },
    /// `match scrutinee { arms }`.
    Match {
        /// The matched expression.
        scrutinee: Box<Expr>,
        /// Arms.
        arms: Vec<MatchArm>,
    },
    /// `[label:] loop { }`.
    Loop {
        /// Optional loop label.
        label: Option<String>,
        /// Body.
        body: Block,
    },
    /// `while cond { }`.
    While {
        /// Loop condition.
        cond: Box<Expr>,
        /// Body.
        body: Block,
    },
    /// `for pat in iter { }`.
    For {
        /// The binding pattern for each element.
        pat: Pattern,
        /// The iterable expression.
        iter: Box<Expr>,
        /// Body.
        body: Block,
    },
    /// A block expression.
    Block(Block),
    /// `scope { }` — structured-concurrency scope.
    Scope(Block),
    /// `spawn expr`.
    Spawn(Box<Expr>),
    /// `return [expr]`.
    Return(Option<Box<Expr>>),
    /// `break [label] [expr]`.
    Break {
        /// Optional label.
        label: Option<String>,
        /// Optional value.
        value: Option<Box<Expr>>,
    },
    /// `continue [label]`.
    Continue {
        /// Optional label.
        label: Option<String>,
    },
}

/// One `match` arm.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchArm {
    /// The arm pattern.
    pub pat: Pattern,
    /// Optional `if` guard.
    pub guard: Option<Expr>,
    /// Arm body (an expression; a block is `Expr::Block`).
    pub body: Expr,
}

/// A pattern.
#[derive(Debug, Clone, PartialEq)]
pub enum Pattern {
    /// `_` wildcard.
    Wildcard,
    /// A literal pattern.
    Literal(Box<Expr>),
    /// An identifier binding.
    Binding(String),
    /// A path (unit variant / const).
    Path(Vec<String>),
    /// A tuple-struct / variant pattern `Path(p, ...)`.
    TupleStruct(Vec<String>, Vec<Pattern>),
    /// A struct pattern `Path { field: pat, ... }`.
    Struct(Vec<String>, Vec<(String, Option<Pattern>)>),
    /// A tuple pattern `(p, ...)`.
    Tuple(Vec<Pattern>),
    /// An or-pattern `a | b | ...`.
    Or(Vec<Pattern>),
}
