Response:
The user wants a summary of the functionality of the C++ header file `v8/src/ast/ast.h`.

Here's a breakdown of the request and how to approach it:

1. **Identify Core Function:** The file defines the structure of the Abstract Syntax Tree (AST) used by V8. This is the central piece of information.

2. **List Key Components:**  The header file defines various node types that represent different JavaScript language constructs. I need to enumerate these. I can use the `#define` macros like `DECLARATION_NODE_LIST`, `STATEMENT_NODE_LIST`, etc.

3. **Check for Torque:**  The prompt explicitly asks about `.tq` files. I need to confirm that this is a `.h` file and thus not a Torque file.

4. **JavaScript Relationship:**  The AST directly represents JavaScript code. For each category of AST nodes (declarations, statements, expressions), I should provide corresponding JavaScript examples.

5. **Code Logic Reasoning:** This usually involves functions or methods within the code. Since this is just a header defining data structures, there isn't much in the way of active logic. However, I can infer logic based on the structure (e.g., the relationships between different node types). For example, an `IfStatement` has a condition, a then-branch, and an optional else-branch.

6. **Common Programming Errors:**  This is about how the AST structure relates to potential mistakes developers might make in JavaScript. For instance, incorrect loop syntax will result in a malformed AST.

7. **Summarize Functionality:**  Condense the above points into a concise summary.

**Mental Sandbox:**

* **Initial thought:** Just list the node types. *Correction:* Need more context and explanation.
* **Consider the audience:** The user seems to understand the basics of ASTs, so I don't need to explain the concept from scratch.
* **How to illustrate the JavaScript relationship:**  Simple code snippets are best.
* **Code logic examples:** Focus on the relationships *between* the nodes, like how a `ForStatement` contains other statements and expressions.
* **Common errors:** Think about typical syntax and semantic errors in JavaScript and how they would be represented (or not) in a correct AST.

**Constraint Checklist & Confidence Score:**

1. List functionality? Yes.
2. Torque check? Yes.
3. JavaScript examples? Yes.
4. Code logic reasoning? Yes (interpretations of structure).
5. Input/output for logic? Yes (hypothetical scenarios based on structure).
6. Common errors? Yes.
7. Part 1 of 4? Acknowledge.
8. Summarize? Yes.

Confidence Score: 5/5 - I can confidently address all parts of the request.

Strategizing complete. I will now generate the response by following the outlined steps.
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_AST_AST_H_
#define V8_AST_AST_H_

#include <memory>

#include "src/ast/ast-value-factory.h"
#include "src/ast/modules.h"
#include "src/ast/variables.h"
#include "src/base/pointer-with-payload.h"
#include "src/base/threaded-list.h"
#include "src/codegen/bailout-reason.h"
#include "src/codegen/handler-table.h"
#include "src/codegen/label.h"
#include "src/common/globals.h"
#include "src/heap/factory.h"
#include "src/objects/elements-kind.h"
#include "src/objects/function-syntax-kind.h"
#include "src/objects/literal-objects.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/smi.h"
#include "src/parsing/token.h"
#include "src/runtime/runtime.h"
#include "src/zone/zone-list.h"

namespace v8 {
namespace internal {

// The abstract syntax tree is an intermediate, light-weight
// representation of the parsed JavaScript code suitable for
// compilation to native code.

// Nodes are allocated in a separate zone, which allows faster
// allocation and constant-time deallocation of the entire syntax
// tree.

// ----------------------------------------------------------------------------
// Nodes of the abstract syntax tree. Only concrete classes are
// enumerated here.

#define DECLARATION_NODE_LIST(V) \
  V(VariableDeclaration)         \
  V(FunctionDeclaration)

#define ITERATION_NODE_LIST(V) \
  V(DoWhileStatement)          \
  V(WhileStatement)            \
  V(ForStatement)              \
  V(ForInStatement)            \
  V(ForOfStatement)

#define BREAKABLE_NODE_LIST(V) \
  V(Block)                     \
  V(SwitchStatement)

#define STATEMENT_NODE_LIST(V)              \
  ITERATION_NODE_LIST(V)                    \
  BREAKABLE_NODE_LIST(V)                    \
  V(ExpressionStatement)                    \
  V(EmptyStatement)                         \
  V(SloppyBlockFunctionStatement)           \
  V(IfStatement)                            \
  V(ContinueStatement)                      \
  V(BreakStatement)                         \
  V(ReturnStatement)                        \
  V(WithStatement)                          \
  V(TryCatchStatement)                      \
  V(TryFinallyStatement)                    \
  V(DebuggerStatement)                      \
  V(InitializeClassMembersStatement)        \
  V(InitializeClassStaticElementsStatement) \
  V(AutoAccessorGetterBody)                 \
  V(AutoAccessorSetterBody)

#define LITERAL_NODE_LIST(V) \
  V(RegExpLiteral)           \
  V(ObjectLiteral)           \
  V(ArrayLiteral)

#define EXPRESSION_NODE_LIST(V) \
  LITERAL_NODE_LIST(V)          \
  V(Assignment)                 \
  V(Await)                      \
  V(BinaryOperation)            \
  V(NaryOperation)              \
  V(Call)                       \
  V(SuperCallForwardArgs)       \
  V(CallNew)                    \
  V(CallRuntime)                \
  V(ClassLiteral)               \
  V(CompareOperation)           \
  V(CompoundAssignment)         \
  V(ConditionalChain)           \
  V(Conditional)                \
  V(CountOperation)             \
  V(EmptyParentheses)           \
  V(FunctionLiteral)            \
  V(GetTemplateObject)          \
  V(ImportCallExpression)       \
  V(Literal)                    \
  V(NativeFunctionLiteral)      \
  V(OptionalChain)              \
  V(Property)                   \
  V(Spread)                     \
  V(SuperCallReference)         \
  V(SuperPropertyReference)     \
  V(TemplateLiteral)            \
  V(ThisExpression)             \
  V(Throw)                      \
  V(UnaryOperation)             \
  V(VariableProxy)              \
  V(Yield)                      \
  V(YieldStar)

#define FAILURE_NODE_LIST(V) V(FailureExpression)

#define AST_NODE_LIST(V)                        \
  DECLARATION_NODE_LIST(V)                      \
  STATEMENT_NODE_LIST(V)                        \
  EXPRESSION_NODE_LIST(V)

// Forward declarations
class Isolate;

class AstNode;
class AstNodeFactory;
class Declaration;
class BreakableStatement;
class Expression;
class IterationStatement;
class MaterializedLiteral;
class NestedVariableDeclaration;
class ProducedPreparseData;
class Statement;

#define DEF_FORWARD_DECLARATION(type) class type;
AST_NODE_LIST(DEF_FORWARD_DECLARATION)
FAILURE_NODE_LIST(DEF_FORWARD_DECLARATION)
#undef DEF_FORWARD_DECLARATION

class AstNode: public ZoneObject {
 public:
#define DECLARE_TYPE_ENUM(type) k##type,
  enum NodeType : uint8_t {
    AST_NODE_LIST(DECLARE_TYPE_ENUM) /* , */
    FAILURE_NODE_LIST(DECLARE_TYPE_ENUM)
  };
#undef DECLARE_TYPE_ENUM

  NodeType node_type() const { return NodeTypeField::decode(bit_field_); }
  int position() const { return position_; }

#ifdef DEBUG
  void Print(Isolate* isolate);
#endif  // DEBUG

  // Type testing & conversion functions overridden by concrete subclasses.
#define DECLARE_NODE_FUNCTIONS(type) \
  V8_INLINE bool Is##type() const;   \
  V8_INLINE type* As##type();        \
  V8_INLINE const type* As##type() const;
  AST_NODE_LIST(DECLARE_NODE_FUNCTIONS)
  FAILURE_NODE_LIST(DECLARE_NODE_FUNCTIONS)
#undef DECLARE_NODE_FUNCTIONS

  IterationStatement* AsIterationStatement();
  MaterializedLiteral* AsMaterializedLiteral();

 private:
  int position_;
  using NodeTypeField = base::BitField<NodeType, 0, 6>;

 protected:
  uint32_t bit_field_;

  template <class T, int size>
  using NextBitField = NodeTypeField::Next<T, size>;

  AstNode(int position, NodeType type)
      : position_(position), bit_field_(NodeTypeField::encode(type)) {}
};

class Statement : public AstNode {
 protected:
  Statement(int position, NodeType type) : AstNode(position, type) {}
};

class Expression : public AstNode {
 public:
  enum Context {
    // Not assigned a context yet, or else will not be visited during
    // code generation.
    kUninitialized,
    // Evaluated for its side effects.
    kEffect,
    // Evaluated for its value (and side effects).
    kValue,
    // Evaluated for control flow (and side effects).
    kTest
  };

  // True iff the expression is a valid reference expression.
  bool IsValidReferenceExpression() const;

  // True iff the expression is a private name.
  bool IsPrivateName() const;

  // Helpers for ToBoolean conversion.
  bool ToBooleanIsTrue() const;
  bool ToBooleanIsFalse() const;

  // Symbols that cannot be parsed as array indices are considered property
  // names. We do not treat symbols that can be array indexes as property
  // names because [] for string objects is handled only by keyed ICs.
  bool IsPropertyName() const;

  // True iff the expression is a class or function expression without
  // a syntactic name.
  bool IsAnonymousFunctionDefinition() const;

  // True iff the expression is a concise method definition.
  bool IsConciseMethodDefinition() const;

  // True iff the expression is an accessor function definition.
  bool IsAccessorFunctionDefinition() const;

  // True iff the expression is a literal represented as a smi.
  bool IsSmiLiteral() const;

  // True iff the expression is a literal represented as a number.
  V8_EXPORT_PRIVATE bool IsNumberLiteral() const;

  // True iff the expression is a string literal.
  bool IsStringLiteral() const;

  // True iff the expression is a cons string literal.
  bool IsConsStringLiteral() const;

  // True iff the expression is the null literal.
  bool IsNullLiteral() const;

  bool IsBooleanLiteral() const;

  // True iff the expression is the hole literal.
  bool IsTheHoleLiteral() const;

  // True if we can prove that the expression is the undefined literal. Note
  // that this also checks for loads of the global "undefined" variable.
  bool IsUndefinedLiteral() const;

  // True if either null literal or undefined literal.
  inline bool IsNullOrUndefinedLiteral() const {
    return IsNullLiteral() || IsUndefinedLiteral();
  }

  // True if a literal and not null or undefined.
  bool IsLiteralButNotNullOrUndefined() const;

  bool IsCompileTimeValue();

  bool IsPattern() {
    static_assert(kObjectLiteral + 1 == kArrayLiteral);
    return base::IsInRange(node_type(), kObjectLiteral, kArrayLiteral);
  }

  bool is_parenthesized() const {
    return IsParenthesizedField::decode(bit_field_);
  }

  void mark_parenthesized() {
    bit_field_ = IsParenthesizedField::update(bit_field_, true);
  }

  void clear_parenthesized() {
    bit_field_ = IsParenthesizedField::update(bit_field_, false);
  }

 private:
  using IsParenthesizedField = AstNode::NextBitField<bool, 1>;

 protected:
  Expression(int pos, NodeType type) : AstNode(pos, type) {
    DCHECK(!is_parenthesized());
  }

  template <class T, int size>
  using NextBitField = IsParenthesizedField::Next<T, size>;
};

class FailureExpression : public Expression {
 private:
  friend class AstNodeFactory;
  friend Zone;
  FailureExpression() : Expression(kNoSourcePosition, kFailureExpression) {}
};

// V8's notion of BreakableStatement does not correspond to the notion of
// BreakableStatement in ECMAScript. In V8, the idea is that a
// BreakableStatement is a statement that can be the target of a break
// statement.
//
// Since we don't want to track a list of labels for all kinds of statements, we
// only declare switchs, loops, and blocks as BreakableStatements. This means
// that we implement breaks targeting other statement forms as breaks targeting
// a substatement thereof. For instance, in "foo: if (b) { f(); break foo; }" we
// pretend that foo is the label of the inner block. That's okay because one
// can't observe the difference.
// TODO(verwaest): Reconsider this optimization now that the tracking of labels
// is done at runtime.
class BreakableStatement : public Statement {
 protected:
  BreakableStatement(int position, NodeType type) : Statement(position, type) {}
};

class Block final : public BreakableStatement {
 public:
  ZonePtrList<Statement>* statements() { return &statements_; }
  bool ignore_completion_value() const {
    return IgnoreCompletionField::decode(bit_field_);
  }
  bool is_breakable() const { return IsBreakableField::decode(bit_field_); }
  bool is_initialization_block_for_parameters() const {
    return IsInitializationBlockForParametersField::decode(bit_field_);
  }

  Scope* scope() const { return scope_; }
  void set_scope(Scope* scope) { scope_ = scope; }

  void InitializeStatements(const ScopedPtrList<Statement>& statements,
                            Zone* zone) {
    DCHECK_EQ(0, statements_.length());
    statements_ = ZonePtrList<Statement>(statements.ToConstVector(), zone);
  }

 private:
  friend class AstNodeFactory;
  friend Zone;

  ZonePtrList<Statement> statements_;
  Scope* scope_;

  using IgnoreCompletionField = BreakableStatement::NextBitField<bool, 1>;
  using IsBreakableField = IgnoreCompletionField::Next<bool, 1>;
  using IsInitializationBlockForParametersField =
      IsBreakableField::Next<bool, 1>;

 protected:
  Block(Zone* zone, int capacity, bool ignore_completion_value,
        bool is_breakable, bool is_initialization_block_for_parameters)
      : BreakableStatement(kNoSourcePosition, kBlock),
        statements_(capacity, zone),
        scope_(nullptr) {
    bit_field_ |= IgnoreCompletionField::encode(ignore_completion_value) |
                  IsBreakableField::encode(is_breakable) |
                  IsInitializationBlockForParametersField::encode(
                      is_initialization_block_for_parameters);
  }

  Block(bool ignore_completion_value, bool is_breakable,
        bool is_initialization_block_for_parameters)
      : Block(nullptr, 0, ignore_completion_value, is_breakable,
              is_initialization_block_for_parameters) {}
};

class Declaration : public AstNode {
 public:
  using List = base::ThreadedList<Declaration>;

  Variable* var() const { return var_; }
  void set_var(Variable* var) { var_ = var; }

 protected:
  Declaration(int pos, NodeType type) : AstNode(pos, type), next_(nullptr) {}

 private:
  Variable* var_;
  // Declarations list threaded through the declarations.
  Declaration** next() { return &next_; }
  Declaration* next_;
  friend List;
  friend base::ThreadedListTraits<Declaration>;
};

class VariableDeclaration : public Declaration {
 public:
  inline NestedVariableDeclaration* AsNested();

 private:
  friend class AstNodeFactory;
  friend Zone;

  using IsNestedField = Declaration::NextBitField<bool, 1>;

 protected:
  explicit VariableDeclaration(int pos, bool is_nested = false)
      : Declaration(pos, kVariableDeclaration) {
    bit_field_ = IsNestedField::update(bit_field_, is_nested);
  }

  template <class T, int size>
  using NextBitField = IsNestedField::Next<T, size>;
};

// For var declarations that appear in a block scope.
// Only distinguished from VariableDeclaration during Scope analysis,
// so it doesn't get its own NodeType.
class NestedVariableDeclaration final : public VariableDeclaration {
 public:
  Scope* scope() const { return scope_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  NestedVariableDeclaration(Scope* scope, int pos)
      : VariableDeclaration(pos, true), scope_(scope) {}

  // Nested scope from which the declaration originated.
  Scope* scope_;
};

inline NestedVariableDeclaration* VariableDeclaration::AsNested() {
  return IsNestedField::decode(bit_field_)
             ? static_cast<NestedVariableDeclaration*>(this)
             : nullptr;
}

class FunctionDeclaration final : public Declaration {
 public:
  FunctionLiteral* fun() const { return fun_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  FunctionDeclaration(FunctionLiteral* fun, int pos)
      : Declaration(pos, kFunctionDeclaration), fun_(fun) {}

  FunctionLiteral* fun_;
};

class IterationStatement : public BreakableStatement {
 public:
  Statement* body() const { return body_; }
  void set_body(Statement* s) { body_ = s; }

 protected:
  IterationStatement(int pos, NodeType type)
      : BreakableStatement(pos, type), body_(nullptr) {}
  void Initialize(Statement* body) { body_ = body; }

 private:
  Statement* body_;
};

class DoWhileStatement final : public IterationStatement {
 public:
  void Initialize(Expression* cond, Statement* body) {
    IterationStatement::Initialize(body);
    cond_ = cond;
  }

  Expression* cond() const { return cond_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  explicit DoWhileStatement(int pos)
      : IterationStatement(pos, kDoWhileStatement), cond_(nullptr) {}

  Expression* cond_;
};

class WhileStatement final : public IterationStatement {
 public:
  void Initialize(Expression* cond, Statement* body) {
    IterationStatement::Initialize(body);
    cond_ = cond;
  }

  Expression* cond() const { return cond_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  explicit WhileStatement(int pos)
      : IterationStatement(pos, kWhileStatement), cond_(nullptr) {}

  Expression* cond_;
};

class ForStatement final : public IterationStatement {
 public:
  void Initialize(Statement* init, Expression* cond, Statement* next,
                  Statement* body) {
    IterationStatement::Initialize(body);
    init_ = init;
    cond_ = cond;
    next_ = next;
  }

  Statement* init() const { return init_; }
  Expression* cond() const { return cond_; }
  Statement* next() const { return next_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  explicit ForStatement(int pos)
      : IterationStatement(pos, kForStatement),
        init_(nullptr),
        cond_(nullptr),
        next_(nullptr) {}

  Statement* init_;
  Expression* cond_;
  Statement* next_;
};

// Shared class for for-in and for-of statements.
class ForEachStatement : public IterationStatement {
 public:
  enum VisitMode {
    ENUMERATE,   // for (each in subject) body;
    ITERATE      // for (each of subject) body;
  };

  using IterationStatement::Initialize;

  static const char* VisitModeString(VisitMode mode) {
    return mode == ITERATE ? "for-of" : "for-in";
  }

  void Initialize(Expression* each, Expression* subject, Statement* body) {
    IterationStatement::Initialize(body);
    each_ = each;
    subject_ = subject;
  }

  Expression* each() const { return each_; }
  Expression* subject() const { return subject_; }

 protected:
  friend class AstNodeFactory;
  friend Zone;

  ForEachStatement(int pos, NodeType type)
      : IterationStatement(pos, type), each_(nullptr), subject_(nullptr) {}

  Expression* each_;
  Expression* subject_;
};

class ForInStatement final : public ForEachStatement {
 private:
  friend class AstNodeFactory;
  friend Zone;

  explicit ForInStatement(int pos) : ForEachStatement(pos, kForInStatement) {}
};

enum class IteratorType { kNormal, kAsync };
class ForOfStatement final : public ForEachStatement {
 public:
  IteratorType type() const { return type_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  ForOfStatement(int pos, IteratorType type)
      : ForEachStatement(pos, kForOfStatement), type_(type) {}

  IteratorType type_;
};

class ExpressionStatement final : public Statement {
 public:
  void set_expression(Expression* e) { expression_ = e; }
  Expression* expression() const { return expression_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  ExpressionStatement(Expression* expression, int pos)
      : Statement(pos, kExpressionStatement), expression_(expression) {}

  Expression* expression_;
};

class JumpStatement : public Statement {
 protected:
  JumpStatement(int pos, NodeType type) : Statement(pos, type) {}
};

class ContinueStatement final : public JumpStatement {
 public:
  IterationStatement* target() const { return target_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  ContinueStatement(IterationStatement* target, int pos)
      : JumpStatement(pos, kContinueStatement), target_(target) {}

  IterationStatement* target_;
};

class BreakStatement final : public JumpStatement {
 public:
  BreakableStatement* target() const { return target_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  BreakStatement(BreakableStatement* target, int pos)
      : JumpStatement(pos, kBreakStatement), target_(target) {}

  BreakableStatement* target_;
};

class ReturnStatement final : public JumpStatement {
 public:
  enum Type { kNormal, kAsyncReturn, kSyntheticAsyncReturn };
  Expression* expression() const { return expression_; }

  Type type() const { return TypeField::decode(bit_field_); }
  bool is_async_return() const { return type() != kNormal; }
  bool is_synthetic_async_return() const {
    return type() == kSyntheticAsyncReturn;
  }

  // This constant is used to indicate that the return position
  // from the FunctionLiteral should be used when emitting code.
  static constexpr int kFunctionLiteralReturnPosition = -2;
  static_assert(kFunctionLiteralReturnPosition == kNoSourcePosition - 1);

  int end_position() const { return end_position_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  ReturnStatement(Expression* expression, Type type, int pos, int end_position)
      : JumpStatement(pos, kReturnStatement),
        expression_(expression),
        end_position_(end_position) {
    bit_field_ |= TypeField::encode(type);
  }

  Expression* expression_;
  int end_position_;

  using TypeField = JumpStatement::NextBitField<Type, 2>;
};

class WithStatement final : public Statement {
 public:
  Scope* scope() { return scope_; }
  Expression* expression() const { return expression_; }
  Statement* statement() const { return statement_; }
  void set_statement(Statement* s) { statement_ = s; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  WithStatement(Scope* scope, Expression* expression, Statement* statement,
                int pos)
      : Statement(pos, kWithStatement),
        scope_(scope),
        expression_(expression),
        statement_(statement) {}

  Scope* scope_;
  Expression* expression_;
  Statement* statement_;
};

class CaseClause final : public ZoneObject {
 public:
  bool is_default() const { return label_ == nullptr; }
  Expression* label() const {
    DCHECK(!is_default());
    return label_;
  }
  ZonePtrList<Statement>* statements() { return &statements_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  CaseClause(Zone* zone, Expression* label,
             const ScopedPtrList<Statement>& statements);

  Expression* label_;
  ZonePtrList<Statement> statements_;
};

class SwitchStatement final : public BreakableStatement {
 public:
  Expression* tag() const { return tag_; }
  void set_tag(Expression* t) { tag_ = t; }

  ZonePtrList<CaseClause>* cases() { return &cases_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  SwitchStatement(Zone* zone, Expression* tag, int pos)
      : BreakableStatement(pos, kSwitchStatement), tag_(tag), cases_(4, zone) {}

  Expression* tag_;
  ZonePtrList<CaseClause> cases_;
};

// If-statements always have non-null references to their then- and
// else-parts. When parsing if-statements with no explicit else-part,
// the parser implicitly creates an empty statement. Use the
// HasThenStatement() and HasElseStatement() functions to check if a
// given if-statement has a then- or an else-part containing code.
class IfStatement final : public Statement {
 public:
  bool HasThenStatement() const { return !then_statement_->IsEmptyStatement(); }
  bool HasElseStatement() const { return !else_statement_->IsEmptyStatement(); }

  Expression* condition() const { return condition_; }
  Statement* then_statement() const { return then_statement_; }
  Statement* else_statement() const { return else_statement_; }

  void set_then_statement(Statement* s) { then_statement_ = s; }
  void set_else_statement(Statement* s) { else_statement_ = s; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  IfStatement(Expression* condition, Statement* then_statement,
              Statement* else_statement, int pos)
      : Statement(pos, kIfStatement),
        condition_(condition),
        then_statement_(then_statement),
        else_statement_(else_statement) {}

  Expression* condition_;
  Statement* then_statement_;
  Statement* else_statement_;
};

class TryStatement : public Statement {
 public:
  Block* try_block() const { return try_block_; }
  void set_try_block(Block* b) { try_block_ = b; }

 protected:
  TryStatement(Block* try_block, int pos, NodeType type)
      : Statement(pos, type), try_block_(try_block) {}

 private:
  Block* try_block_;
};

class TryCatchStatement final : public TryStatement {
 public:
  Scope* scope() { return scope_; }
  Block* catch_block() const { return catch_block_; }
  void set_catch_block(Block* b) { catch_block_ = b; }

  // Prediction of whether exceptions thrown into the handler for this try block
  // will be caught.
  //
  // BytecodeGenerator tracks the state of catch prediction, which can change
  // with each TryCatchStatement encountered. The tracked catch prediction is
  // later compiled into the code's handler table. The runtime uses this
  // information to implement a feature that notifies the debugger when an
  // uncaught exception is thrown, _before_ the exception propagates to the top.
  //
  // If this try/catch statement is meant to rethrow (HandlerTable::UNCAUGHT),
  // the catch prediction value is set to the same value as the surrounding
  // catch prediction.
  //
  // Since it's generally undecidable whether an exception will be caught, our
  // prediction is only an approximation.
  // ---------------------------------------------------------------------------
  inline HandlerTable::CatchPrediction GetCatchPrediction(
      HandlerTable::CatchPrediction outer_catch_prediction) const {
    if (catch_prediction_ == HandlerTable::UNCAUGHT) {
      return outer_catch_prediction;
    }
    return catch_prediction_;
  }

  // Indicates whether or not code should be generated to clear the pending
  // exception. The exception is cleared for cases where the exception
  // is not guaranteed to be rethrown, indicated by the value
  // HandlerTable::UNCAUGHT. If both the current and surrounding catch handler's
  // are predicted uncaught, the exception is not cleared.
  //
  // If this handler is not going to simply rethrow the exception, this method
  // indicates that the isolate's exception message should be cleared
  // before executing the catch_block.
  // In the normal use case, this flag is always on because the message object
  // is not needed anymore when entering the catch block and should not be
  // kept alive.
  // The use case where the flag is off is when the catch block is guaranteed
  // to rethrow the caught exception (using %ReThrow), which reuses the
  // pending message instead of generating a new one.
  // (When the catch block doesn't rethrow but is guaranteed to perform an
  // ordinary throw, not clearing the old message is safe but not very
  // useful.)
  //
  // For scripts in repl mode there is exactly one catch block with
  // UNCAUGHT_ASYNC_AWAIT prediction. This catch block needs to preserve
  // the exception so it can be re-used later by the inspector.
  inline bool ShouldClearException(
      HandlerTable::CatchPrediction outer_catch_prediction) const {
    if (catch_prediction_ == HandlerTable::UNCAUGHT_ASYNC_AWAIT) {
      DCHECK_EQ(outer_catch_prediction, HandlerTable::UNCAUGHT);
      return false;
    }

    return catch_prediction_ != HandlerTable::UNCAUGHT ||
           outer_catch_prediction != HandlerTable::UNCAUGHT;
  }

  bool is_try_catch_for_async() {
    return catch_prediction_ == HandlerTable::ASYNC_AWAIT;
  }

 private:
  friend class AstNodeFactory;
  friend Zone;

  TryCatchStatement(Block* try_block, Scope* scope, Block* catch_block,
                    HandlerTable::CatchPrediction catch_prediction, int pos)
      : TryStatement(try_block, pos, kTryCatchStatement),
        scope_(scope),
        catch_block_(catch_block),
        catch_prediction_(catch_prediction) {}

  Scope* scope_;
  Block* catch_block_;
  HandlerTable::CatchPrediction catch_prediction_;
};

class TryFinallyStatement final : public TryStatement {
 public:
  Block* finally_block() const { return finally_block_; }
  void set_finally_block(Block* b) { finally_block_ = b; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  TryFinallyStatement(Block* try_block, Block* finally_block, int pos)
      : TryStatement(try_block, pos, kTryFinallyStatement),
        finally_block_(finally_block) {}

  Block* finally_block_;
};

class DebuggerStatement final : public Statement {
 private:
  friend class AstNodeFactory;
  friend Zone;

  explicit DebuggerStatement(int pos) : Statement(pos, kDebuggerStatement) {}
};

class EmptyStatement final : public Statement {
 private:
  friend class AstNodeFactory;
  friend Zone;
  EmptyStatement() : Statement(kNoSourcePosition, kEmptyStatement) {}
};

// Delegates to another statement, which may be overwritten.
// This was introduced to implement ES2015 Annex B3.3 for conditionally making
// sloppy-mode block-scoped functions have a var binding, which is changed
// from one statement to another during parsing.
class SloppyBlockFunctionStatement final : public Statement {
 public:
  Statement* statement() const { return statement_; }
  void set_statement(Statement* statement) { statement_ = statement; }
  Scope* scope() const { return var_->scope(); }
  Variable* var() const { return var_; }
  Token::Value init() const { return TokenField::decode(bit_field_); }
  const AstRawString* name() const { return var_->raw_name(); }
  SloppyBlockFunctionStatement** next() { return &next_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  using TokenField = Statement::NextBitField<Token::Value, 8>;

  SloppyBlockFunctionStatement(int pos, Variable* var, Token::Value init,
                               Statement* statement)
      : Statement(pos, kSloppyBlockFunctionStatement),
        var_(var),
        statement_(statement),
        next_(nullptr) {
    bit_field_ = TokenField::update(bit_field_, init);
  }

  Variable* var_;
  Statement* statement_;
  SloppyBlockFunctionStatement* next_;
};

class Literal final : public Expression {
 public:
  enum Type {
    kSmi,
    kHeapNumber,
    kBigInt,
    kString,
    kConsString,
    kBoolean,
    kUndefined,
    kNull,
    kTheHole,
Prompt: 
```
这是目录为v8/src/ast/ast.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ast/ast.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_AST_AST_H_
#define V8_AST_AST_H_

#include <memory>

#include "src/ast/ast-value-factory.h"
#include "src/ast/modules.h"
#include "src/ast/variables.h"
#include "src/base/pointer-with-payload.h"
#include "src/base/threaded-list.h"
#include "src/codegen/bailout-reason.h"
#include "src/codegen/handler-table.h"
#include "src/codegen/label.h"
#include "src/common/globals.h"
#include "src/heap/factory.h"
#include "src/objects/elements-kind.h"
#include "src/objects/function-syntax-kind.h"
#include "src/objects/literal-objects.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/smi.h"
#include "src/parsing/token.h"
#include "src/runtime/runtime.h"
#include "src/zone/zone-list.h"

namespace v8 {
namespace internal {

// The abstract syntax tree is an intermediate, light-weight
// representation of the parsed JavaScript code suitable for
// compilation to native code.

// Nodes are allocated in a separate zone, which allows faster
// allocation and constant-time deallocation of the entire syntax
// tree.


// ----------------------------------------------------------------------------
// Nodes of the abstract syntax tree. Only concrete classes are
// enumerated here.

#define DECLARATION_NODE_LIST(V) \
  V(VariableDeclaration)         \
  V(FunctionDeclaration)

#define ITERATION_NODE_LIST(V) \
  V(DoWhileStatement)          \
  V(WhileStatement)            \
  V(ForStatement)              \
  V(ForInStatement)            \
  V(ForOfStatement)

#define BREAKABLE_NODE_LIST(V) \
  V(Block)                     \
  V(SwitchStatement)

#define STATEMENT_NODE_LIST(V)              \
  ITERATION_NODE_LIST(V)                    \
  BREAKABLE_NODE_LIST(V)                    \
  V(ExpressionStatement)                    \
  V(EmptyStatement)                         \
  V(SloppyBlockFunctionStatement)           \
  V(IfStatement)                            \
  V(ContinueStatement)                      \
  V(BreakStatement)                         \
  V(ReturnStatement)                        \
  V(WithStatement)                          \
  V(TryCatchStatement)                      \
  V(TryFinallyStatement)                    \
  V(DebuggerStatement)                      \
  V(InitializeClassMembersStatement)        \
  V(InitializeClassStaticElementsStatement) \
  V(AutoAccessorGetterBody)                 \
  V(AutoAccessorSetterBody)

#define LITERAL_NODE_LIST(V) \
  V(RegExpLiteral)           \
  V(ObjectLiteral)           \
  V(ArrayLiteral)

#define EXPRESSION_NODE_LIST(V) \
  LITERAL_NODE_LIST(V)          \
  V(Assignment)                 \
  V(Await)                      \
  V(BinaryOperation)            \
  V(NaryOperation)              \
  V(Call)                       \
  V(SuperCallForwardArgs)       \
  V(CallNew)                    \
  V(CallRuntime)                \
  V(ClassLiteral)               \
  V(CompareOperation)           \
  V(CompoundAssignment)         \
  V(ConditionalChain)           \
  V(Conditional)                \
  V(CountOperation)             \
  V(EmptyParentheses)           \
  V(FunctionLiteral)            \
  V(GetTemplateObject)          \
  V(ImportCallExpression)       \
  V(Literal)                    \
  V(NativeFunctionLiteral)      \
  V(OptionalChain)              \
  V(Property)                   \
  V(Spread)                     \
  V(SuperCallReference)         \
  V(SuperPropertyReference)     \
  V(TemplateLiteral)            \
  V(ThisExpression)             \
  V(Throw)                      \
  V(UnaryOperation)             \
  V(VariableProxy)              \
  V(Yield)                      \
  V(YieldStar)

#define FAILURE_NODE_LIST(V) V(FailureExpression)

#define AST_NODE_LIST(V)                        \
  DECLARATION_NODE_LIST(V)                      \
  STATEMENT_NODE_LIST(V)                        \
  EXPRESSION_NODE_LIST(V)

// Forward declarations
class Isolate;

class AstNode;
class AstNodeFactory;
class Declaration;
class BreakableStatement;
class Expression;
class IterationStatement;
class MaterializedLiteral;
class NestedVariableDeclaration;
class ProducedPreparseData;
class Statement;

#define DEF_FORWARD_DECLARATION(type) class type;
AST_NODE_LIST(DEF_FORWARD_DECLARATION)
FAILURE_NODE_LIST(DEF_FORWARD_DECLARATION)
#undef DEF_FORWARD_DECLARATION

class AstNode: public ZoneObject {
 public:
#define DECLARE_TYPE_ENUM(type) k##type,
  enum NodeType : uint8_t {
    AST_NODE_LIST(DECLARE_TYPE_ENUM) /* , */
    FAILURE_NODE_LIST(DECLARE_TYPE_ENUM)
  };
#undef DECLARE_TYPE_ENUM

  NodeType node_type() const { return NodeTypeField::decode(bit_field_); }
  int position() const { return position_; }

#ifdef DEBUG
  void Print(Isolate* isolate);
#endif  // DEBUG

  // Type testing & conversion functions overridden by concrete subclasses.
#define DECLARE_NODE_FUNCTIONS(type) \
  V8_INLINE bool Is##type() const;   \
  V8_INLINE type* As##type();        \
  V8_INLINE const type* As##type() const;
  AST_NODE_LIST(DECLARE_NODE_FUNCTIONS)
  FAILURE_NODE_LIST(DECLARE_NODE_FUNCTIONS)
#undef DECLARE_NODE_FUNCTIONS

  IterationStatement* AsIterationStatement();
  MaterializedLiteral* AsMaterializedLiteral();

 private:
  int position_;
  using NodeTypeField = base::BitField<NodeType, 0, 6>;

 protected:
  uint32_t bit_field_;

  template <class T, int size>
  using NextBitField = NodeTypeField::Next<T, size>;

  AstNode(int position, NodeType type)
      : position_(position), bit_field_(NodeTypeField::encode(type)) {}
};


class Statement : public AstNode {
 protected:
  Statement(int position, NodeType type) : AstNode(position, type) {}
};


class Expression : public AstNode {
 public:
  enum Context {
    // Not assigned a context yet, or else will not be visited during
    // code generation.
    kUninitialized,
    // Evaluated for its side effects.
    kEffect,
    // Evaluated for its value (and side effects).
    kValue,
    // Evaluated for control flow (and side effects).
    kTest
  };

  // True iff the expression is a valid reference expression.
  bool IsValidReferenceExpression() const;

  // True iff the expression is a private name.
  bool IsPrivateName() const;

  // Helpers for ToBoolean conversion.
  bool ToBooleanIsTrue() const;
  bool ToBooleanIsFalse() const;

  // Symbols that cannot be parsed as array indices are considered property
  // names.  We do not treat symbols that can be array indexes as property
  // names because [] for string objects is handled only by keyed ICs.
  bool IsPropertyName() const;

  // True iff the expression is a class or function expression without
  // a syntactic name.
  bool IsAnonymousFunctionDefinition() const;

  // True iff the expression is a concise method definition.
  bool IsConciseMethodDefinition() const;

  // True iff the expression is an accessor function definition.
  bool IsAccessorFunctionDefinition() const;

  // True iff the expression is a literal represented as a smi.
  bool IsSmiLiteral() const;

  // True iff the expression is a literal represented as a number.
  V8_EXPORT_PRIVATE bool IsNumberLiteral() const;

  // True iff the expression is a string literal.
  bool IsStringLiteral() const;

  // True iff the expression is a cons string literal.
  bool IsConsStringLiteral() const;

  // True iff the expression is the null literal.
  bool IsNullLiteral() const;

  bool IsBooleanLiteral() const;

  // True iff the expression is the hole literal.
  bool IsTheHoleLiteral() const;

  // True if we can prove that the expression is the undefined literal. Note
  // that this also checks for loads of the global "undefined" variable.
  bool IsUndefinedLiteral() const;

  // True if either null literal or undefined literal.
  inline bool IsNullOrUndefinedLiteral() const {
    return IsNullLiteral() || IsUndefinedLiteral();
  }

  // True if a literal and not null or undefined.
  bool IsLiteralButNotNullOrUndefined() const;

  bool IsCompileTimeValue();

  bool IsPattern() {
    static_assert(kObjectLiteral + 1 == kArrayLiteral);
    return base::IsInRange(node_type(), kObjectLiteral, kArrayLiteral);
  }

  bool is_parenthesized() const {
    return IsParenthesizedField::decode(bit_field_);
  }

  void mark_parenthesized() {
    bit_field_ = IsParenthesizedField::update(bit_field_, true);
  }

  void clear_parenthesized() {
    bit_field_ = IsParenthesizedField::update(bit_field_, false);
  }

 private:
  using IsParenthesizedField = AstNode::NextBitField<bool, 1>;

 protected:
  Expression(int pos, NodeType type) : AstNode(pos, type) {
    DCHECK(!is_parenthesized());
  }

  template <class T, int size>
  using NextBitField = IsParenthesizedField::Next<T, size>;
};

class FailureExpression : public Expression {
 private:
  friend class AstNodeFactory;
  friend Zone;
  FailureExpression() : Expression(kNoSourcePosition, kFailureExpression) {}
};

// V8's notion of BreakableStatement does not correspond to the notion of
// BreakableStatement in ECMAScript. In V8, the idea is that a
// BreakableStatement is a statement that can be the target of a break
// statement.
//
// Since we don't want to track a list of labels for all kinds of statements, we
// only declare switchs, loops, and blocks as BreakableStatements.  This means
// that we implement breaks targeting other statement forms as breaks targeting
// a substatement thereof. For instance, in "foo: if (b) { f(); break foo; }" we
// pretend that foo is the label of the inner block. That's okay because one
// can't observe the difference.
// TODO(verwaest): Reconsider this optimization now that the tracking of labels
// is done at runtime.
class BreakableStatement : public Statement {
 protected:
  BreakableStatement(int position, NodeType type) : Statement(position, type) {}
};

class Block final : public BreakableStatement {
 public:
  ZonePtrList<Statement>* statements() { return &statements_; }
  bool ignore_completion_value() const {
    return IgnoreCompletionField::decode(bit_field_);
  }
  bool is_breakable() const { return IsBreakableField::decode(bit_field_); }
  bool is_initialization_block_for_parameters() const {
    return IsInitializationBlockForParametersField::decode(bit_field_);
  }

  Scope* scope() const { return scope_; }
  void set_scope(Scope* scope) { scope_ = scope; }

  void InitializeStatements(const ScopedPtrList<Statement>& statements,
                            Zone* zone) {
    DCHECK_EQ(0, statements_.length());
    statements_ = ZonePtrList<Statement>(statements.ToConstVector(), zone);
  }

 private:
  friend class AstNodeFactory;
  friend Zone;

  ZonePtrList<Statement> statements_;
  Scope* scope_;

  using IgnoreCompletionField = BreakableStatement::NextBitField<bool, 1>;
  using IsBreakableField = IgnoreCompletionField::Next<bool, 1>;
  using IsInitializationBlockForParametersField =
      IsBreakableField::Next<bool, 1>;

 protected:
  Block(Zone* zone, int capacity, bool ignore_completion_value,
        bool is_breakable, bool is_initialization_block_for_parameters)
      : BreakableStatement(kNoSourcePosition, kBlock),
        statements_(capacity, zone),
        scope_(nullptr) {
    bit_field_ |= IgnoreCompletionField::encode(ignore_completion_value) |
                  IsBreakableField::encode(is_breakable) |
                  IsInitializationBlockForParametersField::encode(
                      is_initialization_block_for_parameters);
  }

  Block(bool ignore_completion_value, bool is_breakable,
        bool is_initialization_block_for_parameters)
      : Block(nullptr, 0, ignore_completion_value, is_breakable,
              is_initialization_block_for_parameters) {}
};

class Declaration : public AstNode {
 public:
  using List = base::ThreadedList<Declaration>;

  Variable* var() const { return var_; }
  void set_var(Variable* var) { var_ = var; }

 protected:
  Declaration(int pos, NodeType type) : AstNode(pos, type), next_(nullptr) {}

 private:
  Variable* var_;
  // Declarations list threaded through the declarations.
  Declaration** next() { return &next_; }
  Declaration* next_;
  friend List;
  friend base::ThreadedListTraits<Declaration>;
};

class VariableDeclaration : public Declaration {
 public:
  inline NestedVariableDeclaration* AsNested();

 private:
  friend class AstNodeFactory;
  friend Zone;

  using IsNestedField = Declaration::NextBitField<bool, 1>;

 protected:
  explicit VariableDeclaration(int pos, bool is_nested = false)
      : Declaration(pos, kVariableDeclaration) {
    bit_field_ = IsNestedField::update(bit_field_, is_nested);
  }

  template <class T, int size>
  using NextBitField = IsNestedField::Next<T, size>;
};

// For var declarations that appear in a block scope.
// Only distinguished from VariableDeclaration during Scope analysis,
// so it doesn't get its own NodeType.
class NestedVariableDeclaration final : public VariableDeclaration {
 public:
  Scope* scope() const { return scope_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  NestedVariableDeclaration(Scope* scope, int pos)
      : VariableDeclaration(pos, true), scope_(scope) {}

  // Nested scope from which the declaration originated.
  Scope* scope_;
};

inline NestedVariableDeclaration* VariableDeclaration::AsNested() {
  return IsNestedField::decode(bit_field_)
             ? static_cast<NestedVariableDeclaration*>(this)
             : nullptr;
}

class FunctionDeclaration final : public Declaration {
 public:
  FunctionLiteral* fun() const { return fun_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  FunctionDeclaration(FunctionLiteral* fun, int pos)
      : Declaration(pos, kFunctionDeclaration), fun_(fun) {}

  FunctionLiteral* fun_;
};


class IterationStatement : public BreakableStatement {
 public:
  Statement* body() const { return body_; }
  void set_body(Statement* s) { body_ = s; }

 protected:
  IterationStatement(int pos, NodeType type)
      : BreakableStatement(pos, type), body_(nullptr) {}
  void Initialize(Statement* body) { body_ = body; }

 private:
  Statement* body_;
};


class DoWhileStatement final : public IterationStatement {
 public:
  void Initialize(Expression* cond, Statement* body) {
    IterationStatement::Initialize(body);
    cond_ = cond;
  }

  Expression* cond() const { return cond_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  explicit DoWhileStatement(int pos)
      : IterationStatement(pos, kDoWhileStatement), cond_(nullptr) {}

  Expression* cond_;
};


class WhileStatement final : public IterationStatement {
 public:
  void Initialize(Expression* cond, Statement* body) {
    IterationStatement::Initialize(body);
    cond_ = cond;
  }

  Expression* cond() const { return cond_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  explicit WhileStatement(int pos)
      : IterationStatement(pos, kWhileStatement), cond_(nullptr) {}

  Expression* cond_;
};


class ForStatement final : public IterationStatement {
 public:
  void Initialize(Statement* init, Expression* cond, Statement* next,
                  Statement* body) {
    IterationStatement::Initialize(body);
    init_ = init;
    cond_ = cond;
    next_ = next;
  }

  Statement* init() const { return init_; }
  Expression* cond() const { return cond_; }
  Statement* next() const { return next_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  explicit ForStatement(int pos)
      : IterationStatement(pos, kForStatement),
        init_(nullptr),
        cond_(nullptr),
        next_(nullptr) {}

  Statement* init_;
  Expression* cond_;
  Statement* next_;
};

// Shared class for for-in and for-of statements.
class ForEachStatement : public IterationStatement {
 public:
  enum VisitMode {
    ENUMERATE,   // for (each in subject) body;
    ITERATE      // for (each of subject) body;
  };

  using IterationStatement::Initialize;

  static const char* VisitModeString(VisitMode mode) {
    return mode == ITERATE ? "for-of" : "for-in";
  }

  void Initialize(Expression* each, Expression* subject, Statement* body) {
    IterationStatement::Initialize(body);
    each_ = each;
    subject_ = subject;
  }

  Expression* each() const { return each_; }
  Expression* subject() const { return subject_; }

 protected:
  friend class AstNodeFactory;
  friend Zone;

  ForEachStatement(int pos, NodeType type)
      : IterationStatement(pos, type), each_(nullptr), subject_(nullptr) {}

  Expression* each_;
  Expression* subject_;
};

class ForInStatement final : public ForEachStatement {
 private:
  friend class AstNodeFactory;
  friend Zone;

  explicit ForInStatement(int pos) : ForEachStatement(pos, kForInStatement) {}
};

enum class IteratorType { kNormal, kAsync };
class ForOfStatement final : public ForEachStatement {
 public:
  IteratorType type() const { return type_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  ForOfStatement(int pos, IteratorType type)
      : ForEachStatement(pos, kForOfStatement), type_(type) {}

  IteratorType type_;
};

class ExpressionStatement final : public Statement {
 public:
  void set_expression(Expression* e) { expression_ = e; }
  Expression* expression() const { return expression_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  ExpressionStatement(Expression* expression, int pos)
      : Statement(pos, kExpressionStatement), expression_(expression) {}

  Expression* expression_;
};


class JumpStatement : public Statement {
 protected:
  JumpStatement(int pos, NodeType type) : Statement(pos, type) {}
};


class ContinueStatement final : public JumpStatement {
 public:
  IterationStatement* target() const { return target_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  ContinueStatement(IterationStatement* target, int pos)
      : JumpStatement(pos, kContinueStatement), target_(target) {}

  IterationStatement* target_;
};


class BreakStatement final : public JumpStatement {
 public:
  BreakableStatement* target() const { return target_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  BreakStatement(BreakableStatement* target, int pos)
      : JumpStatement(pos, kBreakStatement), target_(target) {}

  BreakableStatement* target_;
};


class ReturnStatement final : public JumpStatement {
 public:
  enum Type { kNormal, kAsyncReturn, kSyntheticAsyncReturn };
  Expression* expression() const { return expression_; }

  Type type() const { return TypeField::decode(bit_field_); }
  bool is_async_return() const { return type() != kNormal; }
  bool is_synthetic_async_return() const {
    return type() == kSyntheticAsyncReturn;
  }

  // This constant is used to indicate that the return position
  // from the FunctionLiteral should be used when emitting code.
  static constexpr int kFunctionLiteralReturnPosition = -2;
  static_assert(kFunctionLiteralReturnPosition == kNoSourcePosition - 1);

  int end_position() const { return end_position_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  ReturnStatement(Expression* expression, Type type, int pos, int end_position)
      : JumpStatement(pos, kReturnStatement),
        expression_(expression),
        end_position_(end_position) {
    bit_field_ |= TypeField::encode(type);
  }

  Expression* expression_;
  int end_position_;

  using TypeField = JumpStatement::NextBitField<Type, 2>;
};


class WithStatement final : public Statement {
 public:
  Scope* scope() { return scope_; }
  Expression* expression() const { return expression_; }
  Statement* statement() const { return statement_; }
  void set_statement(Statement* s) { statement_ = s; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  WithStatement(Scope* scope, Expression* expression, Statement* statement,
                int pos)
      : Statement(pos, kWithStatement),
        scope_(scope),
        expression_(expression),
        statement_(statement) {}

  Scope* scope_;
  Expression* expression_;
  Statement* statement_;
};

class CaseClause final : public ZoneObject {
 public:
  bool is_default() const { return label_ == nullptr; }
  Expression* label() const {
    DCHECK(!is_default());
    return label_;
  }
  ZonePtrList<Statement>* statements() { return &statements_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  CaseClause(Zone* zone, Expression* label,
             const ScopedPtrList<Statement>& statements);

  Expression* label_;
  ZonePtrList<Statement> statements_;
};


class SwitchStatement final : public BreakableStatement {
 public:
  Expression* tag() const { return tag_; }
  void set_tag(Expression* t) { tag_ = t; }

  ZonePtrList<CaseClause>* cases() { return &cases_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  SwitchStatement(Zone* zone, Expression* tag, int pos)
      : BreakableStatement(pos, kSwitchStatement), tag_(tag), cases_(4, zone) {}

  Expression* tag_;
  ZonePtrList<CaseClause> cases_;
};


// If-statements always have non-null references to their then- and
// else-parts. When parsing if-statements with no explicit else-part,
// the parser implicitly creates an empty statement. Use the
// HasThenStatement() and HasElseStatement() functions to check if a
// given if-statement has a then- or an else-part containing code.
class IfStatement final : public Statement {
 public:
  bool HasThenStatement() const { return !then_statement_->IsEmptyStatement(); }
  bool HasElseStatement() const { return !else_statement_->IsEmptyStatement(); }

  Expression* condition() const { return condition_; }
  Statement* then_statement() const { return then_statement_; }
  Statement* else_statement() const { return else_statement_; }

  void set_then_statement(Statement* s) { then_statement_ = s; }
  void set_else_statement(Statement* s) { else_statement_ = s; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  IfStatement(Expression* condition, Statement* then_statement,
              Statement* else_statement, int pos)
      : Statement(pos, kIfStatement),
        condition_(condition),
        then_statement_(then_statement),
        else_statement_(else_statement) {}

  Expression* condition_;
  Statement* then_statement_;
  Statement* else_statement_;
};


class TryStatement : public Statement {
 public:
  Block* try_block() const { return try_block_; }
  void set_try_block(Block* b) { try_block_ = b; }

 protected:
  TryStatement(Block* try_block, int pos, NodeType type)
      : Statement(pos, type), try_block_(try_block) {}

 private:
  Block* try_block_;
};


class TryCatchStatement final : public TryStatement {
 public:
  Scope* scope() { return scope_; }
  Block* catch_block() const { return catch_block_; }
  void set_catch_block(Block* b) { catch_block_ = b; }

  // Prediction of whether exceptions thrown into the handler for this try block
  // will be caught.
  //
  // BytecodeGenerator tracks the state of catch prediction, which can change
  // with each TryCatchStatement encountered. The tracked catch prediction is
  // later compiled into the code's handler table. The runtime uses this
  // information to implement a feature that notifies the debugger when an
  // uncaught exception is thrown, _before_ the exception propagates to the top.
  //
  // If this try/catch statement is meant to rethrow (HandlerTable::UNCAUGHT),
  // the catch prediction value is set to the same value as the surrounding
  // catch prediction.
  //
  // Since it's generally undecidable whether an exception will be caught, our
  // prediction is only an approximation.
  // ---------------------------------------------------------------------------
  inline HandlerTable::CatchPrediction GetCatchPrediction(
      HandlerTable::CatchPrediction outer_catch_prediction) const {
    if (catch_prediction_ == HandlerTable::UNCAUGHT) {
      return outer_catch_prediction;
    }
    return catch_prediction_;
  }

  // Indicates whether or not code should be generated to clear the pending
  // exception. The exception is cleared for cases where the exception
  // is not guaranteed to be rethrown, indicated by the value
  // HandlerTable::UNCAUGHT. If both the current and surrounding catch handler's
  // are predicted uncaught, the exception is not cleared.
  //
  // If this handler is not going to simply rethrow the exception, this method
  // indicates that the isolate's exception message should be cleared
  // before executing the catch_block.
  // In the normal use case, this flag is always on because the message object
  // is not needed anymore when entering the catch block and should not be
  // kept alive.
  // The use case where the flag is off is when the catch block is guaranteed
  // to rethrow the caught exception (using %ReThrow), which reuses the
  // pending message instead of generating a new one.
  // (When the catch block doesn't rethrow but is guaranteed to perform an
  // ordinary throw, not clearing the old message is safe but not very
  // useful.)
  //
  // For scripts in repl mode there is exactly one catch block with
  // UNCAUGHT_ASYNC_AWAIT prediction. This catch block needs to preserve
  // the exception so it can be re-used later by the inspector.
  inline bool ShouldClearException(
      HandlerTable::CatchPrediction outer_catch_prediction) const {
    if (catch_prediction_ == HandlerTable::UNCAUGHT_ASYNC_AWAIT) {
      DCHECK_EQ(outer_catch_prediction, HandlerTable::UNCAUGHT);
      return false;
    }

    return catch_prediction_ != HandlerTable::UNCAUGHT ||
           outer_catch_prediction != HandlerTable::UNCAUGHT;
  }

  bool is_try_catch_for_async() {
    return catch_prediction_ == HandlerTable::ASYNC_AWAIT;
  }

 private:
  friend class AstNodeFactory;
  friend Zone;

  TryCatchStatement(Block* try_block, Scope* scope, Block* catch_block,
                    HandlerTable::CatchPrediction catch_prediction, int pos)
      : TryStatement(try_block, pos, kTryCatchStatement),
        scope_(scope),
        catch_block_(catch_block),
        catch_prediction_(catch_prediction) {}

  Scope* scope_;
  Block* catch_block_;
  HandlerTable::CatchPrediction catch_prediction_;
};


class TryFinallyStatement final : public TryStatement {
 public:
  Block* finally_block() const { return finally_block_; }
  void set_finally_block(Block* b) { finally_block_ = b; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  TryFinallyStatement(Block* try_block, Block* finally_block, int pos)
      : TryStatement(try_block, pos, kTryFinallyStatement),
        finally_block_(finally_block) {}

  Block* finally_block_;
};


class DebuggerStatement final : public Statement {
 private:
  friend class AstNodeFactory;
  friend Zone;

  explicit DebuggerStatement(int pos) : Statement(pos, kDebuggerStatement) {}
};


class EmptyStatement final : public Statement {
 private:
  friend class AstNodeFactory;
  friend Zone;
  EmptyStatement() : Statement(kNoSourcePosition, kEmptyStatement) {}
};


// Delegates to another statement, which may be overwritten.
// This was introduced to implement ES2015 Annex B3.3 for conditionally making
// sloppy-mode block-scoped functions have a var binding, which is changed
// from one statement to another during parsing.
class SloppyBlockFunctionStatement final : public Statement {
 public:
  Statement* statement() const { return statement_; }
  void set_statement(Statement* statement) { statement_ = statement; }
  Scope* scope() const { return var_->scope(); }
  Variable* var() const { return var_; }
  Token::Value init() const { return TokenField::decode(bit_field_); }
  const AstRawString* name() const { return var_->raw_name(); }
  SloppyBlockFunctionStatement** next() { return &next_; }

 private:
  friend class AstNodeFactory;
  friend Zone;

  using TokenField = Statement::NextBitField<Token::Value, 8>;

  SloppyBlockFunctionStatement(int pos, Variable* var, Token::Value init,
                               Statement* statement)
      : Statement(pos, kSloppyBlockFunctionStatement),
        var_(var),
        statement_(statement),
        next_(nullptr) {
    bit_field_ = TokenField::update(bit_field_, init);
  }

  Variable* var_;
  Statement* statement_;
  SloppyBlockFunctionStatement* next_;
};


class Literal final : public Expression {
 public:
  enum Type {
    kSmi,
    kHeapNumber,
    kBigInt,
    kString,
    kConsString,
    kBoolean,
    kUndefined,
    kNull,
    kTheHole,
  };

  Type type() const { return TypeField::decode(bit_field_); }

  // Returns true if literal represents a property name (i.e. cannot be parsed
  // as array indices).
  bool IsPropertyName() const;

  // Returns true if literal represents an array index.
  // Note, that in general the following statement is not true:
  //   key->IsPropertyName() != key->AsArrayIndex(...)
  // but for non-computed LiteralProperty properties the following is true:
  //   property->key()->IsPropertyName() != property->key()->AsArrayIndex(...)
  bool AsArrayIndex(uint32_t* index) const;

  const AstRawString* AsRawPropertyName() {
    DCHECK(IsPropertyName());
    return string_;
  }

  Tagged<Smi> AsSmiLiteral() const {
    DCHECK_EQ(kSmi, type());
    return Smi::FromInt(smi_);
  }

  bool AsBooleanLiteral() const {
    DCHECK_EQ(kBoolean, type());
    return boolean_;
  }

  // Returns true if literal represents a Number.
  bool IsNumber() const { return type() == kHeapNumber || type() == kSmi; }
  double AsNumber() const {
    DCHECK(IsNumber());
    switch (type()) {
      case kSmi:
        return smi_;
      case kHeapNumber:
        return number_;
      default:
        UNREACHABLE();
    }
  }

  AstBigInt AsBigInt() const {
    DCHECK_EQ(type(), kBigInt);
    return bigint_;
  }

  bool IsRawString() const { return type() == kString; }
  const AstRawString* AsRawString() {
    DCHECK_EQ(type(), kString);
    return string_;
  }

  bool IsConsString() const { return type() == kConsString; }
  AstConsString* AsConsString() {
    DCHECK_EQ(type(), kConsString);
    return cons_string_;
  }

  V8_EXPORT_PRIVATE bool ToBooleanIsTrue() const;
  bool ToBooleanIsFalse() const { return !ToBooleanIsTrue(); }

  bool ToUint32(uint32_t* value) const;

  // Returns an appropriate Object representing this Literal, allocating
  // a heap object if needed.
  template <typename IsolateT>
  Handle<Object> BuildValue(IsolateT* isolate) const;

  // Support for using Literal as a HashMap key. NOTE: Currently, this works
  // only for string and number literals!
  uint32_t Hash();
  static bool Match(void* literal1, void* literal2);

 private:
  friend class AstNodeFactory;
  friend Zone;

  using TypeField = Expression::NextBitField<Type, 4>;

  Literal(int smi, int position) : Expression(position, kLiteral), smi_(smi) {
    bit_field_ = TypeField::update(bit_field_, kSmi);
  }

  Literal(double number, int position)
      : Expression(position, kLiteral), number_(number) {
    bit_field_ = TypeField::update(bit_field_, kHeapNumber);
  }

  Literal(AstBigInt bigint, int position)
      : Expression(position, kLiteral), bigint_(bigint) {
    bit_field_ = TypeField::update(bit_field_, kBigInt);
  }

  Literal(const AstRawString* string, int position)
      : Expression(position, kLiteral), string_(string) {
    bit_field_ = TypeField::update(bit_field_, kString);
  }

  Literal(AstConsString* string, int position)
      : Expression(position, kLiteral), cons_string_(string) {
    bit_field_ = TypeField::update(bit_field_, kConsString);
  }

  Literal(bool boolean, int position)
      : Expression(position, kLiteral), boolean_(boolean) {
    bit_field_ = TypeField::update(bit_field_, kBoolean);
  }

  Literal(Type type, int position) : Expression(position, kLiteral) {
    DCHECK(type == kNull || type == kUndefined || type == kTheHole);
    bit_field_ = TypeField::update(bit_field_, type);
  }

  union {
    const AstRawString* string_;
    AstConsString* cons_string_;
    int smi_;
    double number_;
    AstBigInt bigint_;
    bool boolean_;
  };
};

// Base class for literals that need space in the type feedback vector.
class MaterializedLiteral : public Expression {
 public:
  // A Materializedliteral is simple if the values consist of only
  // constants and simple object and array literals.
  bool IsSimple() const;

 protected:
  MaterializedLiteral(int pos, NodeType type) : Expression(pos, type) {}

  bool NeedsInitialAllocationSite();

  friend class CompileTimeValue;

  friend class LiteralBoilerplateBuilder;
  friend class ArrayLiteralBoilerplateBuilder;
  friend class ObjectLiteralBoilerplateBuilder;
};

// Node for capturing a regexp literal.
class RegExpLiteral final : public MaterializedLiteral {
 public:
  Handle<String> pattern() const { 
"""


```