Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Identify the Core Purpose:** The file is named `parser-base.h` and located in `v8/src/parsing/`. The "parser" part is a strong clue. The `.h` extension indicates a header file, likely containing declarations and potentially some inline definitions for a base parser class.

2. **Scan for Key Components:** Quickly read through the code, noting the major elements:
    * **Includes:**  These tell us about dependencies and what functionalities are being used (e.g., `ast/*`, `base/*`, `objects/*`, `parsing/*`). This immediately suggests interaction with the Abstract Syntax Tree (AST), basic utilities, object representations, and other parsing-related modules.
    * **Namespaces:** The `v8::internal` namespace confirms this is internal V8 code.
    * **Enums:**  `FunctionNameValidity`, `AllowLabelledFunctionStatement`, `ParsingArrowHeadFlag`, `ParseFunctionFlag`, `ParsePropertyKind`. These represent different parsing states and options.
    * **Structs:** `FormalParametersBase`, `DeclarationDescriptor`, `DeclarationParsingResult`, `CatchInfo`, `ForInfo`, `ClassInfo`, `ParsePropertyInfo`. These are data structures used to hold information during the parsing process.
    * **Classes:** `SourceRangeScope`, `ParserTypes`, `ParserBase`, `BlockState`, `Target`, `FunctionState`, `ClassLiteralChecker`. These are the building blocks of the parser. `ParserBase` is clearly central.
    * **Macros:** `RETURN_IF_PARSE_ERROR`. This suggests a common error handling pattern.
    * **Typedefs:** `BlockT`, `ExpressionT`, etc. These are aliases for types defined in `ParserTypes`.
    * **Forward Declarations:** `class PreParserIdentifier;`. This indicates an interaction with a pre-parser.

3. **Focus on `ParserBase`:** Given the name, this is likely the core of the file. Notice the template parameter `<typename Impl>`. This indicates the Curiously Recurring Template Pattern (CRTP), meaning `ParserBase` provides the basic functionality, and derived classes (like `Parser`) will implement specific parsing behaviors.

4. **Analyze `ParserBase` Members:** Examine the members of `ParserBase`, grouping them by function:
    * **Constructors/Destructors:**  Initialization of the parser state.
    * **Flags and Options:** `flags_`, `allow_eval_cache_`, etc. These control the parsing process.
    * **Error Handling:** `has_error()`, `RETURN_IF_PARSE_ERROR`.
    * **Stack Management:** `stack_limit_`, `CheckStackOverflow()`.
    * **Scope Management:** `scope_`, `BlockState`, `FunctionState`. This is crucial for understanding how the parser tracks variable visibility and context.
    * **Target Management (for `break`/`continue`):** `Target`.
    * **AST Node Creation:**  `ast_value_factory_`, `ast_node_factory_`.
    * **Token Stream Access:** `scanner()`.
    * **Information Tracking:** `info_id_`.
    * **Various Data Structures for Parsing Constructs:**  `DeclarationDescriptor`, `CatchInfo`, `ForInfo`, `ClassInfo`, `ParsePropertyInfo`.

5. **Understand Key Concepts and Relationships:**
    * **CRTP:** The template structure of `ParserBase` is essential to understand.
    * **Scopes:**  The nested structure of scopes (Block, Function, Class, etc.) is fundamental to how JavaScript code is parsed and interpreted.
    * **Targets:** How `break` and `continue` statements are resolved.
    * **AST:** The connection to the Abstract Syntax Tree.

6. **Relate to JavaScript (as requested):** Think about how the structures and functions relate to JavaScript language features:
    * **Functions:** `FunctionState`, `ParseFunctionFlag`, handling of `async`, `generator`.
    * **Blocks:** `BlockState`, how curly braces define scope.
    * **Loops:** `Target`, handling of `break` and `continue`.
    * **Variables:** `DeclarationDescriptor`, tracking variable modes (`var`, `let`, `const`).
    * **Classes:** `ClassInfo`, parsing `class` syntax, `extends`, methods, fields.
    * **Objects:** `ParsePropertyInfo`, parsing object literal properties.
    * **Error Handling:** How syntax errors are detected.

7. **Consider Potential Programming Errors:** Think about common mistakes developers make that this parser needs to handle:
    * **Redeclared labels:** `DeclareLabel`.
    * **Stack overflow:** `CheckStackOverflow`.
    * **Invalid syntax:**  (Though not explicitly detailed in this header, the presence of error handling suggests this).

8. **Structure the Summary:** Organize the findings into logical categories to answer the prompt effectively. Use clear and concise language.

9. **Address Specific Questions:** Go back through the prompt and ensure all parts are covered:
    * **Functionality:**  List the key roles of the header.
    * **`.tq` extension:** Note that this file is `.h`, not `.tq`.
    * **JavaScript relation and examples:** Provide illustrative JavaScript snippets.
    * **Code logic and examples:** Explain scenarios like label handling.
    * **Common errors:** Give examples of programmer mistakes.
    * **Overall summarization:** Provide a concise high-level summary.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Is this just about tokenizing?  **Correction:** The includes for AST suggest a deeper involvement in constructing the program's structure.
* **Confusion about templates:**  What's the purpose of `<typename Impl>`? **Correction:** Recognize the CRTP pattern and how it enables code reuse and customization.
* **Overly detailed explanation:** Avoid getting bogged down in minor details. Focus on the main purpose of each component. Keep the summary high-level for this part.

By following these steps, combining careful reading with knowledge of compiler design and JavaScript language features, a comprehensive understanding and summary of the header file can be achieved.
This is part 1 of a 9-part description of the V8 source code file `v8/src/parsing/parser-base.h`. Based on the provided content, here's a breakdown of its functionality:

**Core Functionality:**

* **Defines the foundation for V8's parsing process:** `parser-base.h` acts as a base class (`ParserBase`) and provides common data structures and methods used by the actual JavaScript parser and potentially a pre-parser. It sets up the fundamental infrastructure for analyzing JavaScript code.
* **Manages parsing state:** It holds and manipulates the state of the parser, including:
    * **Scope management:**  Uses `Scope`, `BlockState`, and `FunctionState` to track the current lexical scope, handling block scopes and function scopes.
    * **Error handling:**  Provides mechanisms to detect and report parsing errors (`has_error()`, `RETURN_IF_PARSE_ERROR`).
    * **Stack limit checking:** Prevents stack overflow during parsing (`stack_limit()`, `CheckStackOverflow()`).
    * **Function compilation hints:**  Allows setting hints for how functions should be compiled (`default_eager_compile_hint()`).
    * **Loop nesting depth:** Tracks the current depth of nested loops.
    * **Information IDs:**  Manages unique IDs for parsed elements.
* **Facilitates Abstract Syntax Tree (AST) construction:** It interacts heavily with the AST by including headers like `src/ast/ast.h` and provides access to `AstValueFactory` and `AstNodeFactory` for creating AST nodes.
* **Provides access to the token stream:**  It holds a pointer to a `Scanner` object (`scanner_`) which is responsible for tokenizing the input JavaScript code.
* **Supports different parsing modes and flags:**  It uses `UnoptimizedCompileFlags` to configure the parsing process, including handling modules (`has_module_in_scope_chain()`) and debugging scenarios (`IsParsingWhileDebugging()`).
* **Manages labels for `break` and `continue` statements:**  The `Target` class helps track valid targets for these control flow statements.
* **Defines data structures for various JavaScript constructs:**  It includes structs like `FormalParametersBase`, `DeclarationDescriptor`, `CatchInfo`, `ForInfo`, `ClassInfo`, and `ParsePropertyInfo` to store information about parsed functions, variables, catch clauses, for loops, classes, and object properties.

**Regarding the specific questions:**

* **`.tq` extension:** The file ends with `.h`, not `.tq`. Therefore, it is a standard C++ header file, not a V8 Torque source file.
* **Relationship with JavaScript functionality and JavaScript examples:** Yes, this file is fundamentally related to all JavaScript functionality since it's a core component of the parsing process, which is the first step in interpreting and executing JavaScript code. Here are some examples of how the concepts in this header relate to JavaScript:

   ```javascript
   // Scope Management (BlockState, FunctionState, Scope)
   function example() { // FunctionState starts here
     let x = 10; // Variable declaration within function scope
     if (true) { // BlockState starts here
       let y = 20; // Variable declaration within block scope
       console.log(x + y);
     } // BlockState ends here
     // console.log(y); // Error: y is not defined (out of block scope)
   } // FunctionState ends here

   // Labels for break and continue (Target)
   outerLoop: for (let i = 0; i < 5; i++) {
     innerLoop: for (let j = 0; j < 5; j++) {
       if (i === 2 && j === 2) {
         break outerLoop; // Break out of the outer loop
       }
       console.log(i, j);
     }
   }

   // Class parsing (ClassInfo, ParsePropertyInfo)
   class MyClass {
     constructor(value) {
       this.myValue = value;
     }
     getMethod() {
       return this.myValue;
     }
     static staticMethod() {
       return "Static!";
     }
   }

   // Object literal parsing (ParsePropertyInfo)
   const myObject = {
     name: "Example",
     value: 123,
     ['computed' + 'Key']: true
   };

   // Function parsing (FormalParametersBase, ParseFunctionFlag)
   function add(a, b = 0, ...rest) { // Parameters, default value, rest parameter
     return a + b + rest.reduce((sum, val) => sum + val, 0);
   }

   async function fetchData() { // Async function
     // ...
   }

   function* generateNumbers() { // Generator function
     yield 1;
     yield 2;
   }
   ```

* **Code logic推理 and examples:** The `DeclareLabel` function demonstrates code logic:

   * **Assumption:** The parser encounters a labeled statement (e.g., `myLabel: for (...)`).
   * **Input:** A pointer to the current list of labels (`labels`), a pointer to the list of labels specific to the current iteration statement (`own_labels`), and the label string (`label`).
   * **Output:** The label is added to the appropriate lists if it's not already present in the current scope or any enclosing scopes (tracked by `TargetStackContainsLabel`). If the label is a redeclaration, an error message is reported.

* **User-common programming errors:**

   ```javascript
   // Redeclaring a label (caught by DeclareLabel)
   myLabel: for (let i = 0; i < 5; i++) {
     myLabel: console.log(i); // This would cause a "Label redeclaration" error
   }

   // Stack overflow (potentially caught by CheckStackOverflow, though more related to deeply nested structures)
   function recursiveFunction() {
     recursiveFunction(); // Calling itself infinitely
   }
   // recursiveFunction(); // Could lead to a stack overflow
   ```

**Summary of Functionality (Part 1):**

In essence, `v8/src/parsing/parser-base.h` lays the groundwork for V8's JavaScript parser. It defines the core data structures, state management mechanisms, and access points to crucial components like the scanner and AST factories. It provides the basic building blocks and error-handling infrastructure upon which the specific parsing logic for JavaScript syntax is built in other parts of the V8 codebase. It's concerned with the fundamental aspects of breaking down the code and representing its structure.

### 提示词
```
这是目录为v8/src/parsing/parser-base.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/parsing/parser-base.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共9部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_PARSING_PARSER_BASE_H_
#define V8_PARSING_PARSER_BASE_H_

#include <stdint.h>

#include <optional>
#include <utility>
#include <vector>

#include "src/ast/ast-source-ranges.h"
#include "src/ast/ast.h"
#include "src/ast/scopes.h"
#include "src/base/flags.h"
#include "src/base/hashmap.h"
#include "src/base/pointer-with-payload.h"
#include "src/codegen/bailout-reason.h"
#include "src/common/globals.h"
#include "src/common/message-template.h"
#include "src/logging/log.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/function-kind.h"
#include "src/parsing/expression-scope.h"
#include "src/parsing/func-name-inferrer.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/scanner.h"
#include "src/parsing/token.h"
#include "src/regexp/regexp.h"
#include "src/zone/zone-chunk-list.h"

namespace v8::internal {

class PreParserIdentifier;

enum FunctionNameValidity {
  kFunctionNameIsStrictReserved,
  kSkipFunctionNameCheck,
  kFunctionNameValidityUnknown
};

enum AllowLabelledFunctionStatement {
  kAllowLabelledFunctionStatement,
  kDisallowLabelledFunctionStatement,
};

enum ParsingArrowHeadFlag { kCertainlyNotArrowHead, kMaybeArrowHead };

enum class ParseFunctionFlag : uint8_t {
  kIsNormal = 0,
  kIsGenerator = 1 << 0,
  kIsAsync = 1 << 1
};

using ParseFunctionFlags = base::Flags<ParseFunctionFlag>;

struct FormalParametersBase {
  explicit FormalParametersBase(DeclarationScope* scope) : scope(scope) {}

  int num_parameters() const {
    // Don't include the rest parameter into the function's formal parameter
    // count (esp. the SharedFunctionInfo::internal_formal_parameter_count,
    // which says whether we need to create an inlined arguments frame).
    return arity - has_rest;
  }

  void UpdateArityAndFunctionLength(bool is_optional, bool is_rest) {
    if (!is_optional && !is_rest && function_length == arity) {
      ++function_length;
    }
    ++arity;
  }

  DeclarationScope* scope;
  bool has_rest = false;
  bool is_simple = true;
  int function_length = 0;
  int arity = 0;
};

// Stack-allocated scope to collect source ranges from the parser.
class V8_NODISCARD SourceRangeScope final {
 public:
  SourceRangeScope(const Scanner* scanner, SourceRange* range)
      : scanner_(scanner), range_(range) {
    range_->start = scanner->peek_location().beg_pos;
    DCHECK_NE(range_->start, kNoSourcePosition);
    DCHECK_EQ(range_->end, kNoSourcePosition);
  }

  ~SourceRangeScope() {
    DCHECK_EQ(kNoSourcePosition, range_->end);
    range_->end = scanner_->location().end_pos;
    DCHECK_NE(range_->end, kNoSourcePosition);
  }

 private:
  const Scanner* scanner_;
  SourceRange* range_;

  DISALLOW_IMPLICIT_CONSTRUCTORS(SourceRangeScope);
};

// ----------------------------------------------------------------------------
// The RETURN_IF_PARSE_ERROR macro is a convenient macro to enforce error
// handling for functions that may fail (by returning if there was an parser
// error).
//
// Usage:
//     foo = ParseFoo(); // may fail
//     RETURN_IF_PARSE_ERROR
//
//     SAFE_USE(foo);

#define RETURN_IF_PARSE_ERROR \
  if (has_error()) return impl()->NullStatement();

// Common base class template shared between parser and pre-parser.
// The Impl parameter is the actual class of the parser/pre-parser,
// following the Curiously Recurring Template Pattern (CRTP).
// The structure of the parser objects is roughly the following:
//
//   // A structure template containing type definitions, needed to
//   // avoid a cyclic dependency.
//   template <typename Impl>
//   struct ParserTypes;
//
//   // The parser base object, which should just implement pure
//   // parser behavior.  The Impl parameter is the actual derived
//   // class (according to CRTP), which implements impure parser
//   // behavior.
//   template <typename Impl>
//   class ParserBase { ... };
//
//   // And then, for each parser variant (e.g., parser, preparser, etc):
//   class Parser;
//
//   template <>
//   class ParserTypes<Parser> { ... };
//
//   class Parser : public ParserBase<Parser> { ... };
//
// The parser base object implements pure parsing, according to the
// language grammar.  Different parser implementations may exhibit
// different parser-driven behavior that is not considered as pure
// parsing, e.g., early error detection and reporting, AST generation, etc.

// The ParserTypes structure encapsulates the differences in the
// types used in parsing methods.  E.g., Parser methods use Expression*
// and PreParser methods use PreParserExpression.  For any given parser
// implementation class Impl, it is expected to contain the following typedefs:
//
// template <>
// struct ParserTypes<Impl> {
//   // Synonyms for ParserBase<Impl> and Impl, respectively.
//   typedef Base;
//   typedef Impl;
//   // Return types for traversing functions.
//   typedef Identifier;
//   typedef Expression;
//   typedef FunctionLiteral;
//   typedef ObjectLiteralProperty;
//   typedef ClassLiteralProperty;
//   typedef ExpressionList;
//   typedef ObjectPropertyList;
//   typedef ClassPropertyList;
//   typedef FormalParameters;
//   typedef Statement;
//   typedef StatementList;
//   typedef Block;
//   typedef BreakableStatement;
//   typedef ForStatement;
//   typedef IterationStatement;
//   // For constructing objects returned by the traversing functions.
//   typedef Factory;
//   // For other implementation-specific tasks.
//   typedef Target;
//   typedef TargetScope;
// };

template <typename Impl>
struct ParserTypes;

enum class ParsePropertyKind : uint8_t {
  kAutoAccessorClassField,
  kAccessorGetter,
  kAccessorSetter,
  kValue,
  kShorthand,
  kAssign,
  kMethod,
  kClassField,
  kShorthandOrClassField,
  kSpread,
  kNotSet
};

template <typename Impl>
class ParserBase {
 public:
  // Shorten type names defined by ParserTypes<Impl>.
  using Types = ParserTypes<Impl>;
  using ExpressionScope = typename v8::internal::ExpressionScope<Types>;
  using ExpressionParsingScope =
      typename v8::internal::ExpressionParsingScope<Types>;
  using AccumulationScope = typename v8::internal::AccumulationScope<Types>;
  using ArrowHeadParsingScope =
      typename v8::internal::ArrowHeadParsingScope<Types>;
  using VariableDeclarationParsingScope =
      typename v8::internal::VariableDeclarationParsingScope<Types>;
  using ParameterDeclarationParsingScope =
      typename v8::internal::ParameterDeclarationParsingScope<Types>;

  // Return types for traversing functions.
  using BlockT = typename Types::Block;
  using BreakableStatementT = typename Types::BreakableStatement;
  using ClassLiteralPropertyT = typename Types::ClassLiteralProperty;
  using ClassPropertyListT = typename Types::ClassPropertyList;
  using ClassStaticElementListT = typename Types::ClassStaticElementList;
  using ExpressionT = typename Types::Expression;
  using ExpressionListT = typename Types::ExpressionList;
  using FormalParametersT = typename Types::FormalParameters;
  using ForStatementT = typename Types::ForStatement;
  using FunctionLiteralT = typename Types::FunctionLiteral;
  using IdentifierT = typename Types::Identifier;
  using IterationStatementT = typename Types::IterationStatement;
  using ObjectLiteralPropertyT = typename Types::ObjectLiteralProperty;
  using ObjectPropertyListT = typename Types::ObjectPropertyList;
  using StatementT = typename Types::Statement;
  using StatementListT = typename Types::StatementList;
  using SuspendExpressionT = typename Types::Suspend;
  // For constructing objects returned by the traversing functions.
  using FactoryT = typename Types::Factory;
  // Other implementation-specific tasks.
  using FuncNameInferrer = typename Types::FuncNameInferrer;
  using FuncNameInferrerState = typename Types::FuncNameInferrer::State;
  using SourceRange = typename Types::SourceRange;
  using SourceRangeScope = typename Types::SourceRangeScope;

  // All implementation-specific methods must be called through this.
  Impl* impl() { return static_cast<Impl*>(this); }
  const Impl* impl() const { return static_cast<const Impl*>(this); }

  ParserBase(Zone* zone, Scanner* scanner, uintptr_t stack_limit,
             AstValueFactory* ast_value_factory,
             PendingCompilationErrorHandler* pending_error_handler,
             RuntimeCallStats* runtime_call_stats, V8FileLogger* v8_file_logger,
             UnoptimizedCompileFlags flags, bool parsing_on_main_thread,
             bool compile_hints_magic_enabled)
      : scope_(nullptr),
        original_scope_(nullptr),
        function_state_(nullptr),
        fni_(ast_value_factory),
        ast_value_factory_(ast_value_factory),
        ast_node_factory_(ast_value_factory, zone),
        runtime_call_stats_(runtime_call_stats),
        v8_file_logger_(v8_file_logger),
        parsing_on_main_thread_(parsing_on_main_thread),
        stack_limit_(stack_limit),
        pending_error_handler_(pending_error_handler),
        zone_(zone),
        expression_scope_(nullptr),
        scanner_(scanner),
        flags_(flags),
        info_id_(0),
        has_module_in_scope_chain_(flags_.is_module()),
        default_eager_compile_hint_(FunctionLiteral::kShouldLazyCompile),
        compile_hints_magic_enabled_(compile_hints_magic_enabled) {
    pointer_buffer_.reserve(32);
    variable_buffer_.reserve(32);
  }

  const UnoptimizedCompileFlags& flags() const { return flags_; }
  bool has_module_in_scope_chain() const { return has_module_in_scope_chain_; }

  // DebugEvaluate code
  bool IsParsingWhileDebugging() const {
    return flags().parsing_while_debugging() == ParsingWhileDebugging::kYes;
  }

  bool allow_eval_cache() const { return allow_eval_cache_; }
  void set_allow_eval_cache(bool allow) { allow_eval_cache_ = allow; }

  V8_INLINE bool has_error() const { return scanner()->has_parser_error(); }

  uintptr_t stack_limit() const { return stack_limit_; }

  void set_stack_limit(uintptr_t stack_limit) { stack_limit_ = stack_limit; }

  void set_default_eager_compile_hint(
      FunctionLiteral::EagerCompileHint eager_compile_hint) {
    default_eager_compile_hint_ = eager_compile_hint;
  }

  FunctionLiteral::EagerCompileHint default_eager_compile_hint() const {
    return default_eager_compile_hint_;
  }

  int loop_nesting_depth() const {
    return function_state_->loop_nesting_depth();
  }
  int PeekNextInfoId() { return info_id_ + 1; }
  int GetNextInfoId() { return ++info_id_; }
  int GetLastInfoId() const { return info_id_; }

  void SkipInfos(int delta) { info_id_ += delta; }

  void ResetInfoId() { info_id_ = 0; }

  // The Zone where the parsing outputs are stored.
  Zone* main_zone() const { return ast_value_factory()->single_parse_zone(); }

  // The current Zone, which might be the main zone or a temporary Zone.
  Zone* zone() const { return zone_; }

  V8_INLINE bool IsExtraordinaryPrivateNameAccessAllowed() const;

 protected:
  friend class v8::internal::ExpressionScope<ParserTypes<Impl>>;
  friend class v8::internal::ExpressionParsingScope<ParserTypes<Impl>>;
  friend class v8::internal::ArrowHeadParsingScope<ParserTypes<Impl>>;

  enum VariableDeclarationContext {
    kStatementListItem,
    kStatement,
    kForStatement
  };

  class ClassLiteralChecker;

  // ---------------------------------------------------------------------------
  // BlockState and FunctionState implement the parser's scope stack.
  // The parser's current scope is in scope_. BlockState and FunctionState
  // constructors push on the scope stack and the destructors pop. They are also
  // used to hold the parser's per-funcion state.
  class BlockState {
   public:
    BlockState(Scope** scope_stack, Scope* scope)
        : scope_stack_(scope_stack), outer_scope_(*scope_stack) {
      *scope_stack_ = scope;
    }

    BlockState(Zone* zone, Scope** scope_stack)
        : BlockState(scope_stack,
                     zone->New<Scope>(zone, *scope_stack, BLOCK_SCOPE)) {}

    ~BlockState() { *scope_stack_ = outer_scope_; }

   private:
    Scope** const scope_stack_;
    Scope* const outer_scope_;
  };

  // ---------------------------------------------------------------------------
  // Target is a support class to facilitate manipulation of the
  // Parser's target_stack_ (the stack of potential 'break' and
  // 'continue' statement targets). Upon construction, a new target is
  // added; it is removed upon destruction.

  // |labels| is a list of all labels that can be used as a target for break.
  // |own_labels| is a list of all labels that an iteration statement is
  // directly prefixed with, i.e. all the labels that a continue statement in
  // the body can use to continue this iteration statement. This is always a
  // subset of |labels|.
  //
  // Example: "l1: { l2: if (b) l3: l4: for (;;) s }"
  // labels() of the Block will be l1.
  // labels() of the ForStatement will be l2, l3, l4.
  // own_labels() of the ForStatement will be l3, l4.
  class Target {
   public:
    enum TargetType { TARGET_FOR_ANONYMOUS, TARGET_FOR_NAMED_ONLY };

    Target(ParserBase* parser, BreakableStatementT statement,
           ZonePtrList<const AstRawString>* labels,
           ZonePtrList<const AstRawString>* own_labels, TargetType target_type)
        : stack_(parser->function_state_->target_stack_address()),
          statement_(statement),
          labels_(labels),
          own_labels_(own_labels),
          target_type_(target_type),
          previous_(*stack_) {
      DCHECK_IMPLIES(Impl::IsIterationStatement(statement_),
                     target_type == Target::TARGET_FOR_ANONYMOUS);
      DCHECK_IMPLIES(!Impl::IsIterationStatement(statement_),
                     own_labels == nullptr);
      *stack_ = this;
    }

    ~Target() { *stack_ = previous_; }

    const Target* previous() const { return previous_; }
    const BreakableStatementT statement() const { return statement_; }
    const ZonePtrList<const AstRawString>* labels() const { return labels_; }
    const ZonePtrList<const AstRawString>* own_labels() const {
      return own_labels_;
    }
    bool is_iteration() const { return Impl::IsIterationStatement(statement_); }
    bool is_target_for_anonymous() const {
      return target_type_ == TARGET_FOR_ANONYMOUS;
    }

   private:
    Target** const stack_;
    const BreakableStatementT statement_;
    const ZonePtrList<const AstRawString>* const labels_;
    const ZonePtrList<const AstRawString>* const own_labels_;
    const TargetType target_type_;
    Target* const previous_;
  };

  Target* target_stack() { return *function_state_->target_stack_address(); }

  BreakableStatementT LookupBreakTarget(IdentifierT label) {
    bool anonymous = impl()->IsNull(label);
    for (const Target* t = target_stack(); t != nullptr; t = t->previous()) {
      if ((anonymous && t->is_target_for_anonymous()) ||
          (!anonymous &&
           ContainsLabel(t->labels(),
                         impl()->GetRawNameFromIdentifier(label)))) {
        return t->statement();
      }
    }
    return impl()->NullStatement();
  }

  IterationStatementT LookupContinueTarget(IdentifierT label) {
    bool anonymous = impl()->IsNull(label);
    for (const Target* t = target_stack(); t != nullptr; t = t->previous()) {
      if (!t->is_iteration()) continue;

      DCHECK(t->is_target_for_anonymous());
      if (anonymous || ContainsLabel(t->own_labels(),
                                     impl()->GetRawNameFromIdentifier(label))) {
        return impl()->AsIterationStatement(t->statement());
      }
    }
    return impl()->NullStatement();
  }

  class FunctionState final : public BlockState {
   public:
    FunctionState(FunctionState** function_state_stack, Scope** scope_stack,
                  DeclarationScope* scope);
    ~FunctionState();

    DeclarationScope* scope() const { return scope_->AsDeclarationScope(); }

    void AddProperty() { expected_property_count_++; }
    int expected_property_count() { return expected_property_count_; }

    void DisableOptimization(BailoutReason reason) {
      dont_optimize_reason_ = reason;
    }
    BailoutReason dont_optimize_reason() { return dont_optimize_reason_; }

    void AddSuspend() { suspend_count_++; }
    int suspend_count() const { return suspend_count_; }
    bool CanSuspend() const { return suspend_count_ > 0; }

    FunctionKind kind() const { return scope()->function_kind(); }

    bool next_function_is_likely_called() const {
      return next_function_is_likely_called_;
    }

    bool previous_function_was_likely_called() const {
      return previous_function_was_likely_called_;
    }

    void set_next_function_is_likely_called() {
      next_function_is_likely_called_ = !v8_flags.max_lazy;
    }

    void RecordFunctionOrEvalCall() { contains_function_or_eval_ = true; }
    bool contains_function_or_eval() const {
      return contains_function_or_eval_;
    }

    class V8_NODISCARD FunctionOrEvalRecordingScope {
     public:
      explicit FunctionOrEvalRecordingScope(FunctionState* state)
          : state_and_prev_value_(state, state->contains_function_or_eval_) {
        state->contains_function_or_eval_ = false;
      }
      ~FunctionOrEvalRecordingScope() {
        bool found = state_and_prev_value_->contains_function_or_eval_;
        if (!found) {
          state_and_prev_value_->contains_function_or_eval_ =
              state_and_prev_value_.GetPayload();
        }
      }

     private:
      base::PointerWithPayload<FunctionState, bool, 1> state_and_prev_value_;
    };

    class V8_NODISCARD LoopScope final {
     public:
      explicit LoopScope(FunctionState* function_state)
          : function_state_(function_state) {
        function_state_->loop_nesting_depth_++;
      }

      ~LoopScope() { function_state_->loop_nesting_depth_--; }

     private:
      FunctionState* function_state_;
    };

    int loop_nesting_depth() const { return loop_nesting_depth_; }

    Target** target_stack_address() { return &target_stack_; }

   private:
    // Properties count estimation.
    int expected_property_count_;

    // How many suspends are needed for this function.
    int suspend_count_;

    // How deeply nested we currently are in this function.
    int loop_nesting_depth_ = 0;

    FunctionState** function_state_stack_;
    FunctionState* outer_function_state_;
    DeclarationScope* scope_;
    Target* target_stack_ = nullptr;  // for break, continue statements

    // A reason, if any, why this function should not be optimized.
    BailoutReason dont_optimize_reason_;

    // Record whether the next (=== immediately following) function literal is
    // preceded by a parenthesis / exclamation mark. Also record the previous
    // state.
    // These are managed by the FunctionState constructor; the caller may only
    // call set_next_function_is_likely_called.
    bool next_function_is_likely_called_;
    bool previous_function_was_likely_called_;

    // Track if a function or eval occurs within this FunctionState
    bool contains_function_or_eval_;

    friend Impl;
  };

  struct DeclarationDescriptor {
    VariableMode mode;
    VariableKind kind;
    int declaration_pos;
    int initialization_pos;
  };

  struct DeclarationParsingResult {
    struct Declaration {
      Declaration(ExpressionT pattern, ExpressionT initializer)
          : pattern(pattern), initializer(initializer) {
        DCHECK_IMPLIES(Impl::IsNull(pattern), Impl::IsNull(initializer));
      }

      ExpressionT pattern;
      ExpressionT initializer;
      int value_beg_pos = kNoSourcePosition;
    };

    DeclarationParsingResult()
        : first_initializer_loc(Scanner::Location::invalid()),
          bindings_loc(Scanner::Location::invalid()) {}

    DeclarationDescriptor descriptor;
    std::vector<Declaration> declarations;
    Scanner::Location first_initializer_loc;
    Scanner::Location bindings_loc;
  };

  struct CatchInfo {
   public:
    explicit CatchInfo(ParserBase* parser)
        : pattern(parser->impl()->NullExpression()),
          variable(nullptr),
          scope(nullptr) {}
    ExpressionT pattern;
    Variable* variable;
    Scope* scope;
  };

  struct ForInfo {
   public:
    explicit ForInfo(ParserBase* parser)
        : bound_names(1, parser->zone()),
          mode(ForEachStatement::ENUMERATE),
          position(kNoSourcePosition),
          parsing_result() {}
    ZonePtrList<const AstRawString> bound_names;
    ForEachStatement::VisitMode mode;
    int position;
    DeclarationParsingResult parsing_result;
  };

  struct ClassInfo {
   public:
    explicit ClassInfo(ParserBase* parser)
        : extends(parser->impl()->NullExpression()),
          public_members(parser->impl()->NewClassPropertyList(4)),
          private_members(parser->impl()->NewClassPropertyList(4)),
          static_elements(parser->impl()->NewClassStaticElementList(4)),
          instance_fields(parser->impl()->NewClassPropertyList(4)),
          constructor(parser->impl()->NullExpression()) {}
    ExpressionT extends;
    ClassPropertyListT public_members;
    ClassPropertyListT private_members;
    ClassStaticElementListT static_elements;
    ClassPropertyListT instance_fields;
    FunctionLiteralT constructor;

    bool has_static_elements() const {
      return static_elements_scope != nullptr;
    }
    bool has_instance_members() const {
      return instance_members_scope != nullptr;
    }

    DeclarationScope* EnsureStaticElementsScope(ParserBase* parser, int beg_pos,
                                                int info_id) {
      if (!has_static_elements()) {
        static_elements_scope = parser->NewFunctionScope(
            FunctionKind::kClassStaticInitializerFunction);
        static_elements_scope->SetLanguageMode(LanguageMode::kStrict);
        static_elements_scope->set_start_position(beg_pos);
        static_elements_function_id = info_id;
        // Actually consume the id. The id that was passed in might be an
        // earlier id in case of computed property names.
        parser->GetNextInfoId();
      }
      return static_elements_scope;
    }

    DeclarationScope* EnsureInstanceMembersScope(ParserBase* parser,
                                                 int beg_pos, int info_id) {
      if (!has_instance_members()) {
        instance_members_scope = parser->NewFunctionScope(
            FunctionKind::kClassMembersInitializerFunction);
        instance_members_scope->SetLanguageMode(LanguageMode::kStrict);
        instance_members_scope->set_start_position(beg_pos);
        instance_members_function_id = info_id;
        // Actually consume the id. The id that was passed in might be an
        // earlier id in case of computed property names.
        parser->GetNextInfoId();
      }
      return instance_members_scope;
    }

    DeclarationScope* static_elements_scope = nullptr;
    DeclarationScope* instance_members_scope = nullptr;
    Variable* home_object_variable = nullptr;
    Variable* static_home_object_variable = nullptr;
    int autoaccessor_count = 0;
    int static_elements_function_id = -1;
    int instance_members_function_id = -1;
    int computed_field_count = 0;
    bool has_seen_constructor = false;
    bool has_static_computed_names : 1 = false;
    bool has_static_private_methods_or_accessors : 1 = false;
    bool has_static_blocks : 1 = false;
    bool requires_brand : 1 = false;
    bool is_anonymous : 1 = false;
  };

  enum class PropertyPosition { kObjectLiteral, kClassLiteral };
  struct ParsePropertyInfo {
   public:
    explicit ParsePropertyInfo(ParserBase* parser,
                               AccumulationScope* accumulation_scope = nullptr)
        : accumulation_scope(accumulation_scope),
          name(parser->impl()->NullIdentifier()),
          position(PropertyPosition::kClassLiteral),
          function_flags(ParseFunctionFlag::kIsNormal),
          kind(ParsePropertyKind::kNotSet),
          is_computed_name(false),
          is_private(false),
          is_static(false),
          is_rest(false) {}

    bool ParsePropertyKindFromToken(Token::Value token) {
      // This returns true, setting the property kind, iff the given token is
      // one which must occur after a property name, indicating that the
      // previous token was in fact a name and not a modifier (like the "get" in
      // "get x").
      switch (token) {
        case Token::kColon:
          kind = ParsePropertyKind::kValue;
          return true;
        case Token::kComma:
          kind = ParsePropertyKind::kShorthand;
          return true;
        case Token::kRightBrace:
          kind = ParsePropertyKind::kShorthandOrClassField;
          return true;
        case Token::kAssign:
          kind = ParsePropertyKind::kAssign;
          return true;
        case Token::kLeftParen:
          kind = ParsePropertyKind::kMethod;
          return true;
        case Token::kMul:
        case Token::kSemicolon:
          kind = ParsePropertyKind::kClassField;
          return true;
        default:
          break;
      }
      return false;
    }

    AccumulationScope* accumulation_scope;
    IdentifierT name;
    PropertyPosition position;
    ParseFunctionFlags function_flags;
    ParsePropertyKind kind;
    bool is_computed_name;
    bool is_private;
    bool is_static;
    bool is_rest;
  };

  void DeclareLabel(ZonePtrList<const AstRawString>** labels,
                    ZonePtrList<const AstRawString>** own_labels,
                    const AstRawString* label) {
    if (ContainsLabel(*labels, label) || TargetStackContainsLabel(label)) {
      ReportMessage(MessageTemplate::kLabelRedeclaration, label);
      return;
    }

    // Add {label} to both {labels} and {own_labels}.
    if (*labels == nullptr) {
      DCHECK_NULL(*own_labels);
      *labels =
          zone()->template New<ZonePtrList<const AstRawString>>(1, zone());
      *own_labels =
          zone()->template New<ZonePtrList<const AstRawString>>(1, zone());
    } else {
      if (*own_labels == nullptr) {
        *own_labels =
            zone()->template New<ZonePtrList<const AstRawString>>(1, zone());
      }
    }
    (*labels)->Add(label, zone());
    (*own_labels)->Add(label, zone());
  }

  bool ContainsLabel(const ZonePtrList<const AstRawString>* labels,
                     const AstRawString* label) {
    DCHECK_NOT_NULL(label);
    if (labels != nullptr) {
      for (int i = labels->length(); i-- > 0;) {
        if (labels->at(i) == label) return true;
      }
    }
    return false;
  }

  bool TargetStackContainsLabel(const AstRawString* label) {
    for (const Target* t = target_stack(); t != nullptr; t = t->previous()) {
      if (ContainsLabel(t->labels(), label)) return true;
    }
    return false;
  }

  ClassLiteralProperty::Kind ClassPropertyKindFor(ParsePropertyKind kind) {
    switch (kind) {
      case ParsePropertyKind::kAutoAccessorClassField:
        return ClassLiteralProperty::AUTO_ACCESSOR;
      case ParsePropertyKind::kAccessorGetter:
        return ClassLiteralProperty::GETTER;
      case ParsePropertyKind::kAccessorSetter:
        return ClassLiteralProperty::SETTER;
      case ParsePropertyKind::kMethod:
        return ClassLiteralProperty::METHOD;
      case ParsePropertyKind::kClassField:
        return ClassLiteralProperty::FIELD;
      default:
        // Only returns for deterministic kinds
        UNREACHABLE();
    }
  }

  VariableMode GetVariableMode(ClassLiteralProperty::Kind kind) {
    switch (kind) {
      case ClassLiteralProperty::Kind::FIELD:
        return VariableMode::kConst;
      case ClassLiteralProperty::Kind::METHOD:
        return VariableMode::kPrivateMethod;
      case ClassLiteralProperty::Kind::GETTER:
        return VariableMode::kPrivateGetterOnly;
      case ClassLiteralProperty::Kind::SETTER:
        return VariableMode::kPrivateSetterOnly;
      case ClassLiteralProperty::Kind::AUTO_ACCESSOR:
        return VariableMode::kPrivateGetterAndSetter;
    }
  }

  const AstRawString* ClassFieldVariableName(AstValueFactory* ast_value_factory,
                                             int index) {
    std::string name = ".class-field-" + std::to_string(index);
    return ast_value_factory->GetOneByteString(name.c_str());
  }

  const AstRawString* AutoAccessorVariableName(
      AstValueFactory* ast_value_factory, int index) {
    std::string name = ".accessor-storage-" + std::to_string(index);
    return ast_value_factory->GetOneByteString(name.c_str());
  }

  DeclarationScope* NewScriptScope(REPLMode repl_mode) const {
    return zone()->template New<DeclarationScope>(zone(), ast_value_factory(),
                                                  repl_mode);
  }

  DeclarationScope* NewVarblockScope() const {
    return zone()->template New<DeclarationScope>(zone(), scope(), BLOCK_SCOPE);
  }

  ModuleScope* NewModuleScope(DeclarationScope* parent) const {
    return zone()->template New<ModuleScope>(parent, ast_value_factory());
  }

  DeclarationScope* NewEvalScope(Scope* parent) const {
    return zone()->template New<DeclarationScope>(zone(), parent, EVAL_SCOPE);
  }

  ClassScope* NewClassScope(Scope* parent, bool is_anonymous) const {
    return zone()->template New<ClassScope>(zone(), parent, is_anonymous);
  }

  Scope* NewBlockScopeForObjectLiteral() {
    Scope* scope = NewScope(BLOCK_SCOPE);
    scope->set_is_block_scope_for_object_literal();
    return scope;
  }

  Scope* NewScope(ScopeType scope_type) const {
    return NewScopeWithParent(scope(), scope_type);
  }

  // This constructor should only be used when absolutely necessary. Most scopes
  // should automatically use scope() as parent, and be fine with
  // NewScope(ScopeType) above.
  Scope* NewScopeWithParent(Scope* parent, ScopeType scope_type) const {
    // Must always use the specific constructors for the blocklisted scope
    // types.
    DCHECK_NE(FUNCTION_SCOPE, scope_type);
    DCHECK_NE(SCRIPT_SCOPE, scope_type);
    DCHECK_NE(REPL_MODE_SCOPE, scope_type);
    DCHECK_NE(MODULE_SCOPE, scope_type);
    DCHECK_NOT_NULL(parent);
    return zone()->template New<Scope>(zone(), parent, scope_type);
  }

  // Creates a function scope that always allocates in zone(). The function
  // scope itself is either allocated in zone() or in target_zone if one is
  // passed in.
  DeclarationScope* NewFunctionScope(FunctionKind kind,
                                     Zone* parse_zone = nullptr) const {
    DCHECK(ast_value_factory());
    if (parse_zone == nullptr) parse_zone = zone();
    DeclarationScope* result = zone()->template New<DeclarationScope>(
        parse_zone, scope(), FUNCTION_SCOPE, kind);

    // Record presence of an inner function scope
    function_state_->RecordFunctionOrEvalCall();

    // TODO(verwaest): Move into the DeclarationScope constructor.
    if (!IsArrowFunction(kind)) {
      result->DeclareDefaultFunctionVariables(ast_value_factory());
    }
    return result;
  }

  V8_INLINE DeclarationScope* GetDeclarationScope() const {
    return scope()->GetDeclarationScope();
  }
  V8_INLINE DeclarationScope* GetClosureScope() const {
    return scope()->GetClosureScope();
  }

  VariableProxy* NewRawVariable(const AstRawString* name, int pos) {
    return factory()->ast_node_factory()->NewVariableProxy(
        name, NORMAL_VARIABLE, pos);
  }

  VariableProxy* NewUnresolved(const AstRawString* name) {
    return scope()->NewUnresolved(factory()->ast_node_factory(), name,
                                  scanner()->location().beg_pos);
  }

  VariableProxy* NewUnresolved(const AstRawString* name, int begin_pos,
                               VariableKind kind = NORMAL_VARIABLE) {
    return scope()->NewUnresolved(factory()->ast_node_factory(), name,
                                  begin_pos, kind);
  }

  Scanner* scanner() const { return scanner_; }
  AstValueFactory* ast_value_factory() const { return ast_value_factory_; }
  int position() const { return scanner_->location().beg_pos; }
  int peek_position() const { return scanner_->peek_location().beg_pos; }
  int end_position() const { return scanner_->location().end_pos; }
  int peek_end_position() const { return scanner_->peek_location().end_pos; }
  bool stack_overflow() const {
    return pending_error_handler()->stack_overflow();
  }
  void set_stack_overflow() {
    scanner_->set_parser_error();
    pending_error_handler()->set_stack_overflow();
  }
  void CheckStackOverflow() {
    // Any further calls to Next or peek will return the illegal token.
    if (GetCurrentStackPosition() < stack_limit_) set_stack_overflow();
```