//! ncScript parser (WS18-02.3) — a recursive-descent + precedence-climbing
//! parser that turns the [`crate::lexer`] token stream into the [`crate::ast`]
//! per the `NCIP-ncScript-030` § S13 grammar.
//!
//! Notes / current scope: bare `{...}` in expression position is parsed as a
//! block; map literals (`{k: v}`) are only formed in unambiguous positions and
//! are otherwise deferred (no example uses them). Struct literals are gated out
//! of `if` / `while` / `for` / `match` scrutinee positions (the standard
//! Rust-style ambiguity resolution), where they would clash with the block `{`.

use alloc::{boxed::Box, string::String, vec::Vec};

use crate::{
    ast::{
        AssignOp, BinOp, Block, CapDecl, CapScope, ConstDef, EnumDef, Expr, Field, FnDef, ImplDef,
        Item, MatchArm, Param, Pattern, Program, Stmt, StructDef, Type, UnOp, Variant, VariantKind,
    },
    lexer::{LexError, SpannedToken, Token, tokenize},
};

/// A parse error with source position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Human-readable message.
    pub message: String,
    /// 1-based line (0 if at end of input).
    pub line: u32,
    /// 1-based column (0 if at end of input).
    pub col: u32,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "parse error at {}:{}: {}",
            self.line, self.col, self.message
        )
    }
}

impl core::error::Error for ParseError {}

impl From<LexError> for ParseError {
    fn from(e: LexError) -> Self {
        Self {
            message: alloc::format!("{e}"),
            line: e.line,
            col: e.col,
        }
    }
}

/// Tokenize and parse ncScript source into a [`Program`].
///
/// # Errors
///
/// A [`ParseError`] (wrapping any lex error) on the first malformed construct.
pub fn parse(src: &str) -> Result<Program, ParseError> {
    let toks = tokenize(src)?;
    // The lexer strips a leading `#!` shebang; record whether the source had one.
    let shebang = src.starts_with("#!") && !src.starts_with("#![");
    let mut p = Parser { toks, pos: 0 };
    p.parse_program(shebang)
}

struct Parser {
    toks: Vec<SpannedToken>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.toks.get(self.pos).map(|s| &s.token)
    }

    fn is(&self, t: &Token) -> bool {
        self.peek()
            .is_some_and(|x| core::mem::discriminant(x) == core::mem::discriminant(t))
    }

    fn bump(&mut self) -> Option<SpannedToken> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn eat(&mut self, t: &Token) -> bool {
        if self.is(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn pos_of_current(&self) -> (u32, u32) {
        self.toks.get(self.pos).map_or((0, 0), |s| (s.line, s.col))
    }

    fn error<T>(&self, msg: &str) -> Result<T, ParseError> {
        let (line, col) = self.pos_of_current();
        Err(ParseError {
            message: String::from(msg),
            line,
            col,
        })
    }

    fn expect(&mut self, t: &Token, what: &str) -> Result<(), ParseError> {
        if self.eat(t) {
            Ok(())
        } else {
            self.error(what)
        }
    }

    fn expect_ident(&mut self) -> Result<String, ParseError> {
        match self.peek() {
            Some(Token::Ident(_)) => {
                if let Some(SpannedToken {
                    token: Token::Ident(s),
                    ..
                }) = self.bump()
                {
                    Ok(s)
                } else {
                    unreachable!()
                }
            }
            // `self` is allowed as a parameter / path head in a few spots.
            Some(Token::SelfKw) => {
                self.bump();
                Ok(String::from("self"))
            }
            _ => self.error("expected identifier"),
        }
    }

    // ---- program -----------------------------------------------------------

    fn parse_program(&mut self, shebang: bool) -> Result<Program, ParseError> {
        let capabilities = if self.is(&Token::AttrOpen) {
            self.parse_capability_header()?
        } else {
            Vec::new()
        };

        let mut items = Vec::new();
        let mut statements = Vec::new();
        while self.peek().is_some() {
            if self.at_item_start() {
                items.push(self.parse_item()?);
            } else {
                statements.push(self.parse_statement()?);
            }
        }
        Ok(Program {
            shebang,
            capabilities,
            items,
            statements,
        })
    }

    fn parse_capability_header(&mut self) -> Result<Vec<CapDecl>, ParseError> {
        self.expect(&Token::AttrOpen, "expected `#![`")?;
        let kw = self.expect_ident()?;
        if kw != "capabilities" {
            return self.error("expected `capabilities` in attribute header");
        }
        self.expect(&Token::LParen, "expected `(`")?;
        let mut caps = Vec::new();
        while !self.is(&Token::RParen) {
            // cap_name = ident { "." ident }
            let mut name = self.expect_ident()?;
            while self.eat(&Token::Dot) {
                name.push('.');
                name.push_str(&self.expect_ident()?);
            }
            // optional scope
            let scope = if self.eat(&Token::LParen) {
                let s = match self.bump().map(|s| s.token) {
                    Some(Token::Str(v)) => CapScope::Str(v),
                    Some(Token::Int(v)) => CapScope::Int(v),
                    _ => return self.error("expected string or int capability scope"),
                };
                self.expect(&Token::RParen, "expected `)` after capability scope")?;
                Some(s)
            } else {
                None
            };
            caps.push(CapDecl { name, scope });
            if !self.eat(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RParen, "expected `)` to close capabilities")?;
        self.expect(&Token::RBracket, "expected `]` to close attribute")?;
        Ok(caps)
    }

    // ---- items -------------------------------------------------------------

    fn at_item_start(&self) -> bool {
        matches!(
            self.peek(),
            Some(Token::Fn | Token::Struct | Token::Enum | Token::Const | Token::Use | Token::Impl)
        )
    }

    fn parse_item(&mut self) -> Result<Item, ParseError> {
        match self.peek() {
            Some(Token::Fn) => Ok(Item::Fn(self.parse_fn()?)),
            Some(Token::Struct) => Ok(Item::Struct(self.parse_struct()?)),
            Some(Token::Enum) => Ok(Item::Enum(self.parse_enum()?)),
            Some(Token::Const) => Ok(Item::Const(self.parse_const()?)),
            Some(Token::Use) => Ok(Item::Use(self.parse_use()?)),
            Some(Token::Impl) => Ok(Item::Impl(self.parse_impl()?)),
            _ => self.error("expected an item"),
        }
    }

    fn parse_generics(&mut self) -> Result<Vec<String>, ParseError> {
        let mut g = Vec::new();
        if self.eat(&Token::Lt) {
            while !self.is(&Token::Gt) {
                g.push(self.expect_ident()?);
                if !self.eat(&Token::Comma) {
                    break;
                }
            }
            self.expect(&Token::Gt, "expected `>` to close generics")?;
        }
        Ok(g)
    }

    fn parse_fn(&mut self) -> Result<FnDef, ParseError> {
        self.expect(&Token::Fn, "expected `fn`")?;
        let name = self.expect_ident()?;
        let generics = self.parse_generics()?;
        self.expect(&Token::LParen, "expected `(`")?;
        let mut params = Vec::new();
        while !self.is(&Token::RParen) {
            params.push(self.parse_param()?);
            if !self.eat(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RParen, "expected `)`")?;
        let ret = if self.eat(&Token::Arrow) {
            Some(self.parse_type()?)
        } else {
            None
        };
        let body = self.parse_block()?;
        Ok(FnDef {
            name,
            generics,
            params,
            ret,
            body,
        })
    }

    fn parse_param(&mut self) -> Result<Param, ParseError> {
        if self.is(&Token::SelfKw) {
            self.bump();
            return Ok(Param {
                name: String::from("self"),
                ty: None,
                is_self: true,
            });
        }
        let name = self.expect_ident()?;
        let ty = if self.eat(&Token::Colon) {
            Some(self.parse_type()?)
        } else {
            None
        };
        Ok(Param {
            name,
            ty,
            is_self: false,
        })
    }

    fn parse_struct(&mut self) -> Result<StructDef, ParseError> {
        self.expect(&Token::Struct, "expected `struct`")?;
        let name = self.expect_ident()?;
        let generics = self.parse_generics()?;
        if self.eat(&Token::Semicolon) {
            return Ok(StructDef {
                name,
                generics,
                fields: Vec::new(),
                unit: true,
            });
        }
        self.expect(&Token::LBrace, "expected `{` or `;`")?;
        let fields = self.parse_field_defs()?;
        self.expect(&Token::RBrace, "expected `}`")?;
        Ok(StructDef {
            name,
            generics,
            fields,
            unit: false,
        })
    }

    fn parse_field_defs(&mut self) -> Result<Vec<Field>, ParseError> {
        let mut fields = Vec::new();
        while !self.is(&Token::RBrace) {
            let fname = self.expect_ident()?;
            self.expect(&Token::Colon, "expected `:` in field")?;
            let ty = self.parse_type()?;
            fields.push(Field { name: fname, ty });
            if !self.eat(&Token::Comma) {
                break;
            }
        }
        Ok(fields)
    }

    fn parse_enum(&mut self) -> Result<EnumDef, ParseError> {
        self.expect(&Token::Enum, "expected `enum`")?;
        let name = self.expect_ident()?;
        let generics = self.parse_generics()?;
        self.expect(&Token::LBrace, "expected `{`")?;
        let mut variants = Vec::new();
        while !self.is(&Token::RBrace) {
            let vname = self.expect_ident()?;
            let kind = if self.eat(&Token::LParen) {
                let mut tys = Vec::new();
                while !self.is(&Token::RParen) {
                    tys.push(self.parse_type()?);
                    if !self.eat(&Token::Comma) {
                        break;
                    }
                }
                self.expect(&Token::RParen, "expected `)`")?;
                VariantKind::Tuple(tys)
            } else if self.eat(&Token::LBrace) {
                let fields = self.parse_field_defs()?;
                self.expect(&Token::RBrace, "expected `}`")?;
                VariantKind::Struct(fields)
            } else {
                VariantKind::Unit
            };
            variants.push(Variant { name: vname, kind });
            if !self.eat(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RBrace, "expected `}`")?;
        Ok(EnumDef {
            name,
            generics,
            variants,
        })
    }

    fn parse_const(&mut self) -> Result<ConstDef, ParseError> {
        self.expect(&Token::Const, "expected `const`")?;
        let name = self.expect_ident()?;
        self.expect(&Token::Colon, "expected `:`")?;
        let ty = self.parse_type()?;
        self.expect(&Token::Assign, "expected `=`")?;
        let value = self.parse_expr(true)?;
        self.expect(&Token::Semicolon, "expected `;`")?;
        Ok(ConstDef { name, ty, value })
    }

    fn parse_use(&mut self) -> Result<Vec<String>, ParseError> {
        self.expect(&Token::Use, "expected `use`")?;
        let mut path = Vec::new();
        path.push(self.expect_ident()?);
        while self.eat(&Token::ColonColon) {
            path.push(self.expect_ident()?);
        }
        self.expect(&Token::Semicolon, "expected `;`")?;
        Ok(path)
    }

    fn parse_impl(&mut self) -> Result<ImplDef, ParseError> {
        self.expect(&Token::Impl, "expected `impl`")?;
        // `impl Trait for Type` or `impl Type`.
        let first = self.parse_type()?;
        let (trait_name, ty) = if self.eat(&Token::For) {
            let tname = match &first {
                Type::Path(segs, _) if segs.len() == 1 => segs.first().cloned().unwrap_or_default(),
                _ => return self.error("expected trait name before `for`"),
            };
            (Some(tname), self.parse_type()?)
        } else {
            (None, first)
        };
        self.expect(&Token::LBrace, "expected `{`")?;
        let mut methods = Vec::new();
        while self.is(&Token::Fn) {
            methods.push(self.parse_fn()?);
        }
        self.expect(&Token::RBrace, "expected `}`")?;
        Ok(ImplDef {
            trait_name,
            ty,
            methods,
        })
    }

    // ---- types -------------------------------------------------------------

    fn parse_type(&mut self) -> Result<Type, ParseError> {
        let mut ty = self.parse_type_atom()?;
        while self.eat(&Token::Question) {
            ty = Type::Optional(Box::new(ty));
        }
        Ok(ty)
    }

    fn parse_type_atom(&mut self) -> Result<Type, ParseError> {
        if self.eat(&Token::LBracket) {
            let inner = self.parse_type()?;
            self.expect(&Token::RBracket, "expected `]`")?;
            return Ok(Type::List(Box::new(inner)));
        }
        if self.eat(&Token::LBrace) {
            let k = self.parse_type()?;
            self.expect(&Token::Colon, "expected `:` in map type")?;
            let v = self.parse_type()?;
            self.expect(&Token::RBrace, "expected `}`")?;
            return Ok(Type::Map(Box::new(k), Box::new(v)));
        }
        if self.eat(&Token::LParen) {
            let mut tys = Vec::new();
            while !self.is(&Token::RParen) {
                tys.push(self.parse_type()?);
                if !self.eat(&Token::Comma) {
                    break;
                }
            }
            self.expect(&Token::RParen, "expected `)`")?;
            return Ok(Type::Tuple(tys));
        }
        // named / generic path type
        let mut segs = Vec::new();
        segs.push(self.expect_ident()?);
        while self.eat(&Token::ColonColon) {
            segs.push(self.expect_ident()?);
        }
        let mut generics = Vec::new();
        if self.eat(&Token::Lt) {
            while !self.is(&Token::Gt) {
                generics.push(self.parse_type()?);
                if !self.eat(&Token::Comma) {
                    break;
                }
            }
            self.expect(&Token::Gt, "expected `>`")?;
        }
        Ok(Type::Path(segs, generics))
    }

    // ---- blocks + statements ----------------------------------------------

    fn parse_block(&mut self) -> Result<Block, ParseError> {
        self.expect(&Token::LBrace, "expected `{`")?;
        let mut statements = Vec::new();
        let mut tail = None;
        while !self.is(&Token::RBrace) {
            if self.peek().is_none() {
                return self.error("unexpected end of input in block");
            }
            if self.at_item_start() {
                statements.push(Stmt::Item(self.parse_item()?));
                continue;
            }
            if self.is(&Token::Let) {
                statements.push(self.parse_let()?);
                continue;
            }
            // Expression (possibly an assignment, expr-stmt, or trailing tail).
            let e = self.parse_expr(true)?;
            if let Some(op) = self.assign_op() {
                self.bump();
                let value = self.parse_expr(true)?;
                self.expect(&Token::Semicolon, "expected `;` after assignment")?;
                statements.push(Stmt::Assign {
                    place: e,
                    op,
                    value,
                });
            } else if self.eat(&Token::Semicolon) {
                statements.push(Stmt::Expr(e));
            } else if self.is(&Token::RBrace) {
                tail = Some(Box::new(e));
            } else if is_block_like(&e) {
                statements.push(Stmt::Expr(e));
            } else {
                return self.error("expected `;` or `}` after expression");
            }
        }
        self.expect(&Token::RBrace, "expected `}`")?;
        Ok(Block { statements, tail })
    }

    fn parse_let(&mut self) -> Result<Stmt, ParseError> {
        self.expect(&Token::Let, "expected `let`")?;
        let mutable = self.eat(&Token::Mut);
        let pat = self.parse_pattern()?;
        let ty = if self.eat(&Token::Colon) {
            Some(self.parse_type()?)
        } else {
            None
        };
        let value = if self.eat(&Token::Assign) {
            Some(self.parse_expr(true)?)
        } else {
            None
        };
        self.expect(&Token::Semicolon, "expected `;` after let")?;
        Ok(Stmt::Let {
            mutable,
            pat,
            ty,
            value,
        })
    }

    /// Statement parsing at the top level of a program (mirrors block bodies).
    fn parse_statement(&mut self) -> Result<Stmt, ParseError> {
        if self.is(&Token::Let) {
            return self.parse_let();
        }
        let e = self.parse_expr(true)?;
        if let Some(op) = self.assign_op() {
            self.bump();
            let value = self.parse_expr(true)?;
            self.expect(&Token::Semicolon, "expected `;` after assignment")?;
            return Ok(Stmt::Assign {
                place: e,
                op,
                value,
            });
        }
        if self.eat(&Token::Semicolon) || is_block_like(&e) {
            return Ok(Stmt::Expr(e));
        }
        if self.peek().is_none() {
            return Ok(Stmt::Expr(e));
        }
        self.error("expected `;` after expression")
    }

    fn assign_op(&self) -> Option<AssignOp> {
        Some(match self.peek()? {
            Token::Assign => AssignOp::Assign,
            Token::PlusEq => AssignOp::Add,
            Token::MinusEq => AssignOp::Sub,
            Token::StarEq => AssignOp::Mul,
            Token::SlashEq => AssignOp::Div,
            Token::PercentEq => AssignOp::Rem,
            _ => return None,
        })
    }

    // ---- expressions (precedence climbing) --------------------------------

    fn parse_expr(&mut self, allow_struct: bool) -> Result<Expr, ParseError> {
        self.parse_or(allow_struct)
    }

    fn parse_or(&mut self, allow_struct: bool) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_and(allow_struct)?;
        while self.eat(&Token::OrOr) {
            let rhs = self.parse_and(allow_struct)?;
            lhs = bin(BinOp::Or, lhs, rhs);
        }
        Ok(lhs)
    }

    fn parse_and(&mut self, allow_struct: bool) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_cmp(allow_struct)?;
        while self.eat(&Token::AndAnd) {
            let rhs = self.parse_cmp(allow_struct)?;
            lhs = bin(BinOp::And, lhs, rhs);
        }
        Ok(lhs)
    }

    fn parse_cmp(&mut self, allow_struct: bool) -> Result<Expr, ParseError> {
        let lhs = self.parse_add(allow_struct)?;
        let op = match self.peek() {
            Some(Token::EqEq) => BinOp::Eq,
            Some(Token::NotEq) => BinOp::Ne,
            Some(Token::Lt) => BinOp::Lt,
            Some(Token::Le) => BinOp::Le,
            Some(Token::Gt) => BinOp::Gt,
            Some(Token::Ge) => BinOp::Ge,
            _ => return Ok(lhs),
        };
        self.bump();
        let rhs = self.parse_add(allow_struct)?;
        Ok(bin(op, lhs, rhs))
    }

    fn parse_add(&mut self, allow_struct: bool) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_mul(allow_struct)?;
        loop {
            let op = match self.peek() {
                Some(Token::Plus) => BinOp::Add,
                Some(Token::Minus) => BinOp::Sub,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_mul(allow_struct)?;
            lhs = bin(op, lhs, rhs);
        }
        Ok(lhs)
    }

    fn parse_mul(&mut self, allow_struct: bool) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_unary(allow_struct)?;
        loop {
            let op = match self.peek() {
                Some(Token::Star) => BinOp::Mul,
                Some(Token::Slash) => BinOp::Div,
                Some(Token::Percent) => BinOp::Rem,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_unary(allow_struct)?;
            lhs = bin(op, lhs, rhs);
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self, allow_struct: bool) -> Result<Expr, ParseError> {
        let op = match self.peek() {
            Some(Token::Minus) => Some(UnOp::Neg),
            Some(Token::Not) => Some(UnOp::Not),
            _ => None,
        };
        if let Some(op) = op {
            self.bump();
            let expr = self.parse_unary(allow_struct)?;
            return Ok(Expr::Unary {
                op,
                expr: Box::new(expr),
            });
        }
        self.parse_postfix(allow_struct)
    }

    fn parse_postfix(&mut self, allow_struct: bool) -> Result<Expr, ParseError> {
        let mut e = self.parse_primary(allow_struct)?;
        loop {
            if self.eat(&Token::Question) {
                e = Expr::Try(Box::new(e));
            } else if self.is(&Token::Dot) {
                self.bump();
                if self.eat(&Token::Await) {
                    e = Expr::Await(Box::new(e));
                } else {
                    let name = self.expect_ident()?;
                    if self.is(&Token::LParen) {
                        let args = self.parse_call_args()?;
                        e = Expr::MethodCall {
                            recv: Box::new(e),
                            method: name,
                            args,
                        };
                    } else {
                        e = Expr::Field {
                            recv: Box::new(e),
                            name,
                        };
                    }
                }
            } else if self.is(&Token::LParen) {
                let args = self.parse_call_args()?;
                e = Expr::Call {
                    callee: Box::new(e),
                    args,
                };
            } else if self.eat(&Token::LBracket) {
                let index = self.parse_expr(true)?;
                self.expect(&Token::RBracket, "expected `]`")?;
                e = Expr::Index {
                    recv: Box::new(e),
                    index: Box::new(index),
                };
            } else {
                break;
            }
        }
        Ok(e)
    }

    fn parse_call_args(&mut self) -> Result<Vec<Expr>, ParseError> {
        self.expect(&Token::LParen, "expected `(`")?;
        let mut args = Vec::new();
        while !self.is(&Token::RParen) {
            args.push(self.parse_expr(true)?);
            if !self.eat(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RParen, "expected `)`")?;
        Ok(args)
    }

    fn parse_primary(&mut self, allow_struct: bool) -> Result<Expr, ParseError> {
        match self.peek() {
            Some(Token::Int(_) | Token::Float(_) | Token::Str(_) | Token::Bool(_)) => {
                Ok(self.parse_literal_expr())
            }
            Some(Token::If) => self.parse_if(),
            Some(Token::Match) => self.parse_match(),
            Some(Token::Loop) => {
                self.bump();
                let body = self.parse_block()?;
                Ok(Expr::Loop { label: None, body })
            }
            Some(Token::While) => {
                self.bump();
                let cond = self.parse_expr(false)?; // no struct-lit in condition
                let body = self.parse_block()?;
                Ok(Expr::While {
                    cond: Box::new(cond),
                    body,
                })
            }
            Some(Token::For) => {
                self.bump();
                let pat = self.parse_pattern()?;
                self.expect(&Token::In, "expected `in`")?;
                let iter = self.parse_expr(false)?; // no struct-lit in iterator
                let body = self.parse_block()?;
                Ok(Expr::For {
                    pat,
                    iter: Box::new(iter),
                    body,
                })
            }
            Some(Token::Label(_)) => {
                // labelled loop: 'name: loop/while/for
                let Some(SpannedToken {
                    token: Token::Label(label),
                    ..
                }) = self.bump()
                else {
                    unreachable!("matched Token::Label above")
                };
                self.expect(&Token::Colon, "expected `:` after loop label")?;
                match self.peek() {
                    Some(Token::Loop) => {
                        self.bump();
                        let body = self.parse_block()?;
                        Ok(Expr::Loop {
                            label: Some(label),
                            body,
                        })
                    }
                    _ => self.error("expected `loop` after label"),
                }
            }
            Some(Token::Scope) => {
                self.bump();
                let body = self.parse_block()?;
                Ok(Expr::Scope(body))
            }
            Some(Token::Spawn) => {
                self.bump();
                let e = self.parse_expr(allow_struct)?;
                Ok(Expr::Spawn(Box::new(e)))
            }
            Some(Token::Return) => {
                self.bump();
                let value = if self.is_value_terminator() {
                    None
                } else {
                    Some(Box::new(self.parse_expr(allow_struct)?))
                };
                Ok(Expr::Return(value))
            }
            Some(Token::Break) => {
                self.bump();
                let label = self.try_label();
                let value = if self.is_value_terminator() {
                    None
                } else {
                    Some(Box::new(self.parse_expr(allow_struct)?))
                };
                Ok(Expr::Break { label, value })
            }
            Some(Token::Continue) => {
                self.bump();
                let label = self.try_label();
                Ok(Expr::Continue { label })
            }
            Some(Token::LBracket) => self.parse_list(),
            Some(Token::LBrace) => Ok(Expr::Block(self.parse_block()?)),
            Some(Token::LParen) => self.parse_tuple_or_group(),
            Some(Token::Ident(_) | Token::SelfKw) => {
                let path = self.parse_path()?;
                if allow_struct && self.is(&Token::LBrace) {
                    self.parse_struct_lit(path)
                } else {
                    Ok(Expr::Path(path))
                }
            }
            _ => self.error("expected an expression"),
        }
    }

    fn is_value_terminator(&self) -> bool {
        matches!(
            self.peek(),
            None | Some(Token::Semicolon | Token::RBrace | Token::RParen | Token::Comma)
        )
    }

    fn try_label(&mut self) -> Option<String> {
        if let Some(Token::Label(_)) = self.peek() {
            if let Some(SpannedToken {
                token: Token::Label(s),
                ..
            }) = self.bump()
            {
                return Some(s);
            }
        }
        None
    }

    fn parse_literal_expr(&mut self) -> Expr {
        match self.bump().map(|s| s.token) {
            Some(Token::Int(v)) => Expr::Int(v),
            Some(Token::Float(v)) => Expr::Float(v),
            Some(Token::Str(v)) => Expr::Str(v),
            Some(Token::Bool(v)) => Expr::Bool(v),
            _ => unreachable!("caller checked the token kind"),
        }
    }

    fn parse_path(&mut self) -> Result<Vec<String>, ParseError> {
        let mut segs = Vec::new();
        segs.push(self.expect_ident()?);
        while self.eat(&Token::ColonColon) {
            segs.push(self.expect_ident()?);
        }
        Ok(segs)
    }

    fn parse_struct_lit(&mut self, path: Vec<String>) -> Result<Expr, ParseError> {
        self.expect(&Token::LBrace, "expected `{`")?;
        let mut fields = Vec::new();
        while !self.is(&Token::RBrace) {
            let name = self.expect_ident()?;
            let value = if self.eat(&Token::Colon) {
                Some(self.parse_expr(true)?)
            } else {
                None
            };
            fields.push((name, value));
            if !self.eat(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RBrace, "expected `}`")?;
        Ok(Expr::StructLit { path, fields })
    }

    fn parse_list(&mut self) -> Result<Expr, ParseError> {
        self.expect(&Token::LBracket, "expected `[`")?;
        let mut items = Vec::new();
        while !self.is(&Token::RBracket) {
            items.push(self.parse_expr(true)?);
            if !self.eat(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RBracket, "expected `]`")?;
        Ok(Expr::List(items))
    }

    fn parse_tuple_or_group(&mut self) -> Result<Expr, ParseError> {
        self.expect(&Token::LParen, "expected `(`")?;
        if self.eat(&Token::RParen) {
            return Ok(Expr::Unit);
        }
        let first = self.parse_expr(true)?;
        if self.eat(&Token::Comma) {
            let mut items = alloc::vec![first];
            while !self.is(&Token::RParen) {
                items.push(self.parse_expr(true)?);
                if !self.eat(&Token::Comma) {
                    break;
                }
            }
            self.expect(&Token::RParen, "expected `)`")?;
            Ok(Expr::Tuple(items))
        } else {
            self.expect(&Token::RParen, "expected `)`")?;
            Ok(first) // parenthesized grouping
        }
    }

    fn parse_if(&mut self) -> Result<Expr, ParseError> {
        self.expect(&Token::If, "expected `if`")?;
        let cond = self.parse_expr(false)?; // no struct-lit in condition
        let then_block = self.parse_block()?;
        let else_branch = if self.eat(&Token::Else) {
            if self.is(&Token::If) {
                Some(Box::new(self.parse_if()?))
            } else {
                Some(Box::new(Expr::Block(self.parse_block()?)))
            }
        } else {
            None
        };
        Ok(Expr::If {
            cond: Box::new(cond),
            then_block,
            else_branch,
        })
    }

    fn parse_match(&mut self) -> Result<Expr, ParseError> {
        self.expect(&Token::Match, "expected `match`")?;
        let scrutinee = self.parse_expr(false)?; // no struct-lit in scrutinee
        self.expect(&Token::LBrace, "expected `{`")?;
        let mut arms = Vec::new();
        while !self.is(&Token::RBrace) {
            let pat = self.parse_pattern()?;
            let guard = if self.eat(&Token::If) {
                Some(self.parse_expr(true)?)
            } else {
                None
            };
            self.expect(&Token::FatArrow, "expected `=>`")?;
            let body = if self.is(&Token::LBrace) {
                Expr::Block(self.parse_block()?)
            } else {
                self.parse_expr(true)?
            };
            arms.push(MatchArm { pat, guard, body });
            // arms separated by commas; a trailing comma is allowed, and a
            // block arm may omit the comma.
            let _ = self.eat(&Token::Comma);
        }
        self.expect(&Token::RBrace, "expected `}`")?;
        Ok(Expr::Match {
            scrutinee: Box::new(scrutinee),
            arms,
        })
    }

    // ---- patterns ----------------------------------------------------------

    fn parse_pattern(&mut self) -> Result<Pattern, ParseError> {
        let first = self.parse_pattern_primary()?;
        if self.is(&Token::Pipe) {
            let mut alts = alloc::vec![first];
            while self.eat(&Token::Pipe) {
                alts.push(self.parse_pattern_primary()?);
            }
            Ok(Pattern::Or(alts))
        } else {
            Ok(first)
        }
    }

    fn parse_pattern_primary(&mut self) -> Result<Pattern, ParseError> {
        match self.peek() {
            Some(Token::Underscore) => {
                self.bump();
                Ok(Pattern::Wildcard)
            }
            Some(Token::Int(_) | Token::Float(_) | Token::Str(_) | Token::Bool(_)) => {
                Ok(Pattern::Literal(Box::new(self.parse_literal_expr())))
            }
            Some(Token::Minus) => {
                // negative integer literal pattern
                self.bump();
                match self.parse_literal_expr() {
                    Expr::Int(v) => Ok(Pattern::Literal(Box::new(Expr::Int(v.wrapping_neg())))),
                    _ => self.error("expected an integer after `-` in pattern"),
                }
            }
            Some(Token::LParen) => {
                self.bump();
                let mut pats = Vec::new();
                while !self.is(&Token::RParen) {
                    pats.push(self.parse_pattern()?);
                    if !self.eat(&Token::Comma) {
                        break;
                    }
                }
                self.expect(&Token::RParen, "expected `)`")?;
                Ok(Pattern::Tuple(pats))
            }
            Some(Token::Ident(_)) => {
                let path = self.parse_path()?;
                if self.is(&Token::LParen) {
                    self.bump();
                    let mut elems = Vec::new();
                    while !self.is(&Token::RParen) {
                        elems.push(self.parse_pattern()?);
                        if !self.eat(&Token::Comma) {
                            break;
                        }
                    }
                    self.expect(&Token::RParen, "expected `)`")?;
                    Ok(Pattern::TupleStruct(path, elems))
                } else if self.is(&Token::LBrace) {
                    self.bump();
                    let mut fields = Vec::new();
                    while !self.is(&Token::RBrace) {
                        let name = self.expect_ident()?;
                        let sub = if self.eat(&Token::Colon) {
                            Some(self.parse_pattern()?)
                        } else {
                            None
                        };
                        fields.push((name, sub));
                        if !self.eat(&Token::Comma) {
                            break;
                        }
                    }
                    self.expect(&Token::RBrace, "expected `}`")?;
                    Ok(Pattern::Struct(path, fields))
                } else if path.len() == 1 {
                    Ok(Pattern::Binding(
                        path.into_iter().next().unwrap_or_default(),
                    ))
                } else {
                    Ok(Pattern::Path(path))
                }
            }
            _ => self.error("expected a pattern"),
        }
    }
}

/// Build a binary expression node.
fn bin(op: BinOp, lhs: Expr, rhs: Expr) -> Expr {
    Expr::Binary {
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    }
}

/// Whether an expression is "block-like" and may be a statement without a
/// trailing `;` (Rust-style).
fn is_block_like(e: &Expr) -> bool {
    matches!(
        e,
        Expr::If { .. }
            | Expr::Match { .. }
            | Expr::Loop { .. }
            | Expr::While { .. }
            | Expr::For { .. }
            | Expr::Block(_)
            | Expr::Scope(_)
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::similar_names,
        reason = "lhs/rhs are the canonical names for binary-operand assertions"
    )]

    use super::*;

    #[test]
    fn parses_hello_example() {
        let src = include_str!("../../../oips/examples/omniscript/hello.oss");
        let prog = parse(src).expect("hello.oss must parse");
        assert!(prog.shebang);
        assert!(prog.capabilities.is_empty(), "hello is a pure script");
        assert_eq!(prog.items.len(), 1, "one fn item: main");
        assert!(matches!(prog.items[0], Item::Fn(ref f) if f.name == "main"));
    }

    #[test]
    fn parses_match_result_example() {
        let src = include_str!("../../../oips/examples/omniscript/match_result.oss");
        let prog = parse(src).expect("match_result.oss must parse");
        // parse_port, classify, main
        assert_eq!(prog.items.len(), 3);
        let names: alloc::vec::Vec<&str> = prog
            .items
            .iter()
            .filter_map(|i| match i {
                Item::Fn(f) => Some(f.name.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(names, ["parse_port", "classify", "main"]);
    }

    #[test]
    fn parses_capability_fs_ai_example() {
        let src = include_str!("../../../oips/examples/omniscript/capability_fs_ai.oss");
        let prog = parse(src).expect("capability_fs_ai.oss must parse");
        assert!(prog.shebang);
        // header declares fs.read("/etc/nexacore/notes") and ai.invoke
        assert_eq!(prog.capabilities.len(), 2);
        assert_eq!(prog.capabilities[0].name, "fs.read");
        assert!(matches!(prog.capabilities[0].scope, Some(CapScope::Str(_))));
        assert_eq!(prog.capabilities[1].name, "ai.invoke");
        assert!(prog.capabilities[1].scope.is_none());
        // use std::fs; use std::ai; struct Note; enum DigestError; impl; fns
        assert!(
            prog.items
                .iter()
                .any(|i| matches!(i, Item::Struct(s) if s.name == "Note"))
        );
        assert!(
            prog.items
                .iter()
                .any(|i| matches!(i, Item::Enum(e) if e.name == "DigestError"))
        );
        assert!(prog.items.iter().any(|i| matches!(i, Item::Impl(_))));
        assert!(
            prog.items
                .iter()
                .any(|i| matches!(i, Item::Fn(f) if f.name == "summarize"))
        );
    }

    #[test]
    fn operator_precedence() {
        // 1 + 2 * 3 == 7  →  (1 + (2*3)) == 7
        let prog = parse("let x = 1 + 2 * 3 == 7;").unwrap();
        let Stmt::Let { value: Some(v), .. } = &prog.statements[0] else {
            panic!("expected let");
        };
        // top is `==`
        let Expr::Binary {
            op: BinOp::Eq, lhs, ..
        } = v
        else {
            panic!("top must be ==, got {v:?}");
        };
        // lhs is `+` whose rhs is `*`
        let Expr::Binary {
            op: BinOp::Add,
            rhs,
            ..
        } = lhs.as_ref()
        else {
            panic!("lhs must be +");
        };
        assert!(matches!(rhs.as_ref(), Expr::Binary { op: BinOp::Mul, .. }));
    }

    #[test]
    fn method_chain_and_try() {
        let prog = parse("let n = text.trim().parse_int()?;").unwrap();
        let Stmt::Let { value: Some(v), .. } = &prog.statements[0] else {
            panic!();
        };
        // outermost is Try( MethodCall(parse_int, MethodCall(trim, text)) )
        assert!(matches!(v, Expr::Try(_)));
    }

    #[test]
    fn unexpected_token_errors_with_position() {
        let e = parse("fn f( {").unwrap_err();
        assert!(e.line >= 1);
    }
}
