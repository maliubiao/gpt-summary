Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The user wants a summary of the functionality of `v8/src/parsing/parser.h`. They also specify extra conditions related to Torque, JavaScript examples, logic examples, common errors, and a final overall summary.

2. **Initial Analysis of the Header File:** I scan the provided C++ header file for key elements:
    * **Copyright and License:** Standard boilerplate, indicates V8 project.
    * **Includes:**  These are crucial for understanding dependencies and what the parser interacts with. I note includes like `ast/*`, `base/*`, `parsing/*`, and `zone/*`. This immediately tells me the parser deals with Abstract Syntax Trees (AST), basic utilities, other parsing components, and memory management.
    * **Namespaces:** The code is within `v8::internal`, indicating internal V8 implementation details.
    * **Class `ParserFormalParameters`:** This struct deals with function parameters, including handling duplicates and strict mode errors. This is a good starting point for understanding a specific responsibility.
    * **Template `ParserTypes<Parser>`:**  This defines the types used within the parser, connecting the generic `ParserBase` with the concrete `Parser` class. It lists things like `Expression`, `Statement`, `FunctionLiteral`, which are core AST node types.
    * **Class `Parser`:** This is the main class. I look at its public and private members and methods:
        * **Constructor/Destructor:** Standard lifecycle management. The destructor hints at a `reusable_preparser_`.
        * **Static `IsPreParser()`:**  Indicates this is the *full* parser, not the pre-parser.
        * **`ParseOnBackground()`, `ParseProgram()`, `ParseFunction()`:** These are key parsing entry points, suggesting the parser handles different levels of granularity (full script, function).
        * **`InitializeEmptyScopeChain()`, `DeserializeScopeChain()`:**  Scope management is a vital part of parsing.
        * **`UpdateStatistics()`:**  The parser gathers performance or usage data.
        * **Private members and methods:** A large number of private methods suggests a complex parsing process broken down into smaller, manageable steps. I notice patterns like `Parse...`, `Build...`, `Rewrite...`, `Declare...`, which hint at the different stages of parsing (tokenizing/scanning is likely handled elsewhere by `Scanner`). Methods related to classes, modules, and different types of functions (generators, async) are apparent.
        * **Helper methods:**  Methods like `IsEval`, `IsArguments`, `IsIdentifier` are for checking syntax and semantics.
        * **Function name inference (`FuncNameInferrer`):**  A separate component assists in naming functions.
        * **Template literals:**  Specific handling for template literals.
        * **Error reporting:**  Methods like `ReportUnexpectedTokenAt`.

3. **Categorize Functionality:** Based on the analysis, I group the functionalities into logical categories:
    * **Core Parsing:**  Parsing programs, functions, and modules.
    * **AST Construction:** Creating and manipulating AST nodes (expressions, statements, literals, etc.).
    * **Scope Management:** Handling variable declarations, scope chains, and lexical scoping.
    * **Error Handling:** Detecting and reporting syntax and semantic errors.
    * **Language Feature Support:** Specific handling for ES6+ features like classes, modules, generators, async functions, destructuring, etc.
    * **Pre-parsing:** Interacting with a pre-parser for optimization.
    * **Statistics and Debugging:** Collecting parsing statistics and potentially supporting debugging.
    * **REPL Support:** Handling REPL-specific parsing needs.

4. **Address Specific Requirements:**

    * **`.tq` Extension:**  The header file ends with `.h`, not `.tq`. So, it's C++, not Torque.
    * **JavaScript Examples:** I select features directly mentioned in the header (function declarations, variable declarations, classes, modules) and provide simple JavaScript code snippets to illustrate the parser's role.
    * **Logic Examples:** I choose a straightforward example like parsing function parameters and demonstrating how the `ParserFormalParameters` struct would capture the information. I create hypothetical input (JavaScript code) and show the expected output (the data structure).
    * **Common Errors:** I think about frequent mistakes developers make related to parsing (syntax errors, duplicate declarations, strict mode violations) and provide corresponding JavaScript examples.
    * **Overall Summary:** I synthesize the categorized functionalities into a concise summary of the header's purpose.

5. **Structure the Output:** I organize the information clearly with headings and bullet points to make it easy to read and understand. I follow the order of the user's requests.

6. **Refine and Review:** I reread my answer to ensure accuracy, completeness, and clarity. I check that the JavaScript examples are valid and that the logic example is easy to follow. I make sure the summary accurately reflects the content of the header file. For instance, initially, I might have missed emphasizing the interaction with the pre-parser, so I'd add that upon review.
这是对 V8 源代码文件 `v8/src/parsing/parser.h` 的功能进行分析和总结的第一部分。

**功能列举:**

`v8/src/parsing/parser.h` 文件定义了 V8 JavaScript 引擎中 `Parser` 类的接口和相关的数据结构。`Parser` 类的主要职责是将 JavaScript 源代码转换为抽象语法树 (AST)。  以下是其主要功能的详细列表：

* **核心解析功能:**
    * **程序和函数解析:** 包含 `ParseProgram` 和 `ParseFunction` 方法，负责解析完整的 JavaScript 程序或单个函数。
    * **模块解析:**  支持 ES 模块的语法解析，包括 `ParseModuleItemList`, `ParseImportDeclaration`, `ParseExportDeclaration` 等方法。
    * **表达式和语句解析:**  通过一系列私有方法（例如 `Parse...` 开头的方法）来解析各种 JavaScript 表达式和语句，构建 AST 节点。
    * **字面量解析:** 处理各种字面量，如数字、字符串、布尔值、正则表达式、对象字面量、数组字面量和模板字面量。

* **抽象语法树 (AST) 构建:**
    * **创建 AST 节点:**  使用 `AstNodeFactory` 创建不同类型的 AST 节点，如 `FunctionLiteral` (函数字面量), `Block` (代码块), `VariableProxy` (变量引用), `ExpressionStatement` (表达式语句) 等。
    * **连接 AST 节点:**  将解析出的语法单元连接成树状结构，形成完整的 AST。

* **作用域管理:**
    * **作用域创建和管理:**  维护和管理不同类型的作用域 (例如全局作用域、函数作用域、块级作用域、类作用域)。
    * **变量声明和绑定:**  处理变量的声明 (`DeclareVariable`, `DeclareBoundVariable`)，并将变量引用绑定到其声明。
    * **处理重复声明:**  检测并报告在同一作用域内的重复变量声明。

* **错误处理:**
    * **语法错误检测:**  在解析过程中检测语法错误，并通过 `ReportUnexpectedTokenAt` 等方法报告。
    * **严格模式错误处理:**  识别并处理严格模式下的语法和语义限制。

* **语言特性支持:**
    * **ES6+ 特性支持:**  支持 ECMAScript 2015 及更高版本引入的新特性，如类 (`DeclareClass`), 模块, 解构赋值, 箭头函数, 生成器函数, 异步函数等。
    * **模板字面量处理:**  专门处理模板字面量的解析和 AST 构建 (`OpenTemplateLiteral`, `AddTemplateSpan`, `CloseTemplateLiteral`)。
    * **`super` 关键字处理:**  重写包含 `super` 调用的表达式 (`RewriteSuperCall`)。

* **预解析 (Pre-parsing) 集成:**
    * **利用预解析信息:**  可以利用 `PreParser` 提供的预解析信息来加速解析过程，尤其是在延迟解析的情况下。
    * **跳过函数体:**  在延迟解析模式下，可以跳过函数体的详细解析，使用预解析的信息 (`SkipFunction`)。

* **其他辅助功能:**
    * **函数名推断:**  使用 `FuncNameInferrer` 类来推断匿名函数的名称。
    * **代码补全模式支持:**  尽管从提供的代码中看不明显，但 `Parser` 类通常也会支持代码补全等编辑器功能所需的解析。
    * **统计信息更新:**  在解析完成后更新统计信息 (`UpdateStatistics`)。
    * **处理源 URL 注释:**  `HandleSourceURLComments` 方法处理源代码中的 URL 注释，这对于调试和错误报告很重要。

**关于 `.tq` 扩展名:**

如果 `v8/src/parsing/parser.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是一种 V8 内部使用的类型化的中间语言，用于编写性能关键的运行时代码。然而，根据您提供的文件名，它以 `.h` 结尾，这意味着它是一个 **C++ 头文件**。因此，它不是 Torque 源代码。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`v8/src/parsing/parser.h` 中定义的 `Parser` 类直接负责将 JavaScript 代码转换为 V8 能够理解和执行的内部表示形式。 几乎所有的 JavaScript 语法和语义都与这个解析器有关。

**示例:**

1. **变量声明:**
   ```javascript
   let x = 10;
   const PI = 3.14;
   var greeting = "hello";
   ```
   `Parser` 会识别 `let`, `const`, `var` 关键字，创建相应的 AST 节点来表示变量声明，并将其添加到当前作用域。

2. **函数声明:**
   ```javascript
   function add(a, b) {
     return a + b;
   }
   ```
   `Parser` 会识别 `function` 关键字，解析函数名 (`add`)，参数 (`a`, `b`)，函数体 (`return a + b;`)，并创建一个 `FunctionLiteral` AST 节点。

3. **类声明:**
   ```javascript
   class Rectangle {
     constructor(width, height) {
       this.width = width;
       this.height = height;
     }

     getArea() {
       return this.width * this.height;
     }
   }
   ```
   `Parser` 会识别 `class` 关键字，解析类名 (`Rectangle`)，构造函数 (`constructor`)，方法 (`getArea`)，并创建相应的 AST 节点来表示类。

4. **模块导入/导出:**
   ```javascript
   import { calculateSum } from './utils.js';
   export function multiply(a, b) {
     return a * b;
   }
   ```
   `Parser` 会识别 `import` 和 `export` 关键字，解析导入和导出的模块名、变量名等信息。

**代码逻辑推理 (假设输入与输出):**

假设输入一段简单的 JavaScript 函数声明：

```javascript
function greet(name) {
  return "Hello, " + name + "!";
}
```

`Parser` 经过解析后，可能会产生以下抽象的输出表示（简化说明，实际 AST 结构更复杂）：

* **FunctionLiteral 节点:**
    * `name`: "greet"
    * `parameters`:  一个包含一个 `Identifier` 节点的列表，表示参数 "name"。
    * `body`: 一个 `Block` 节点，包含一个 `ReturnStatement` 节点。
        * `ReturnStatement`:  包含一个 `BinaryExpression` 节点（字符串连接操作）。
            * 左侧:  一个 `BinaryExpression` 节点 (连接 "Hello, " 和 `VariableProxy` "name")
            * 右侧:  一个 `Literal` 节点，表示字符串 "!"

**用户常见的编程错误:**

与解析器相关的常见编程错误通常是语法错误：

1. **缺少分号:**
   ```javascript
   let message = "Hello"
   console.log(message) // 解析器会报错，因为第一行缺少分号
   ```
   解析器会报告 "Unexpected token console"。

2. **拼写错误或非法字符:**
   ```javascript
   functoin myFunction() { // "functoin" 拼写错误
     console.log("Hello");
   }
   ```
   解析器会报告 "Unexpected identifier"。

3. **括号不匹配:**
   ```javascript
   function calculate(a, b { // 缺少一个右括号
     return a + b;
   }
   ```
   解析器会报告 "Unexpected token {" 或 "Expected ')'"。

4. **在不应该使用的地方使用保留字:**
   ```javascript
   let class = 10; // "class" 是保留字
   ```
   解析器会报告 "Unexpected token 'class'"。

5. **在严格模式下的赋值错误:**
   ```javascript
   "use strict";
   eval = 10; // 在严格模式下不允许给 eval 赋值
   ```
   解析器会报告 "Assignment to eval or arguments is not allowed in strict mode"。

**功能归纳 (第 1 部分):**

总的来说，`v8/src/parsing/parser.h` 定义了 V8 JavaScript 引擎中核心的语法解析器 `Parser` 类的接口。这个类负责将输入的 JavaScript 源代码转化为机器可理解的抽象语法树 (AST)。它处理各种语法结构，包括变量声明、函数、类、模块、表达式和语句，并负责进行作用域管理和基本的错误检测。 这个头文件是 V8 引擎理解和执行 JavaScript 代码的关键组成部分。

Prompt: 
```
这是目录为v8/src/parsing/parser.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/parsing/parser.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_PARSING_PARSER_H_
#define V8_PARSING_PARSER_H_

#include <cstddef>

#include "src/ast/ast-source-ranges.h"
#include "src/ast/ast-value-factory.h"
#include "src/ast/ast.h"
#include "src/ast/scopes.h"
#include "src/base/compiler-specific.h"
#include "src/base/pointer-with-payload.h"
#include "src/base/small-vector.h"
#include "src/base/threaded-list.h"
#include "src/common/globals.h"
#include "src/parsing/import-attributes.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/parser-base.h"
#include "src/parsing/parsing.h"
#include "src/parsing/preparser.h"
#include "src/zone/zone-chunk-list.h"

namespace v8 {

class ScriptCompiler;

namespace internal {

class ConsumedPreparseData;
class ParseInfo;
class ParserTarget;
class ParserTargetScope;
class PendingCompilationErrorHandler;
class PreparseData;

// ----------------------------------------------------------------------------
// JAVASCRIPT PARSING

class Parser;


struct ParserFormalParameters : FormalParametersBase {
  struct Parameter : public ZoneObject {
    Parameter(Expression* pattern, Expression* initializer, int position,
              int initializer_end_position, bool is_rest)
        : initializer_and_is_rest(initializer, is_rest),
          pattern(pattern),
          position(position),
          initializer_end_position(initializer_end_position) {}

    base::PointerWithPayload<Expression, bool, 1> initializer_and_is_rest;

    Expression* pattern;
    Expression* initializer() const {
      return initializer_and_is_rest.GetPointer();
    }
    int position;
    int initializer_end_position;
    inline bool is_rest() const { return initializer_and_is_rest.GetPayload(); }

    Parameter* next_parameter = nullptr;
    bool is_simple() const {
      return pattern->IsVariableProxy() && initializer() == nullptr &&
             !is_rest();
    }

    const AstRawString* name() const {
      DCHECK(is_simple());
      return pattern->AsVariableProxy()->raw_name();
    }

    Parameter** next() { return &next_parameter; }
    Parameter* const* next() const { return &next_parameter; }
  };

  void set_strict_parameter_error(const Scanner::Location& loc,
                                  MessageTemplate message) {
    strict_error_loc = loc;
    strict_error_message = message;
  }

  bool has_duplicate() const { return duplicate_loc.IsValid(); }
  void ValidateDuplicate(Parser* parser) const;
  void ValidateStrictMode(Parser* parser) const;

  explicit ParserFormalParameters(DeclarationScope* scope)
      : FormalParametersBase(scope) {}

  base::ThreadedList<Parameter> params;
  Scanner::Location duplicate_loc = Scanner::Location::invalid();
  Scanner::Location strict_error_loc = Scanner::Location::invalid();
  MessageTemplate strict_error_message = MessageTemplate::kNone;
};

template <>
struct ParserTypes<Parser> {
  using Base = ParserBase<Parser>;
  using Impl = Parser;

  // Return types for traversing functions.
  using Block = v8::internal::Block*;
  using BreakableStatement = v8::internal::BreakableStatement*;
  using ClassLiteralProperty = ClassLiteral::Property*;
  using ClassLiteralStaticElement = ClassLiteral::StaticElement*;
  using ClassPropertyList = ZonePtrList<ClassLiteral::Property>*;
  using ClassStaticElementList = ZonePtrList<ClassLiteral::StaticElement>*;
  using Expression = v8::internal::Expression*;
  using ExpressionList = ScopedPtrList<v8::internal::Expression>;
  using FormalParameters = ParserFormalParameters;
  using ForStatement = v8::internal::ForStatement*;
  using FunctionLiteral = v8::internal::FunctionLiteral*;
  using Identifier = const AstRawString*;
  using IterationStatement = v8::internal::IterationStatement*;
  using ObjectLiteralProperty = ObjectLiteral::Property*;
  using ObjectPropertyList = ScopedPtrList<v8::internal::ObjectLiteralProperty>;
  using Statement = v8::internal::Statement*;
  using StatementList = ScopedPtrList<v8::internal::Statement>;
  using Suspend = v8::internal::Suspend*;

  // For constructing objects returned by the traversing functions.
  using Factory = AstNodeFactory;

  // Other implementation-specific functions.
  using FuncNameInferrer = v8::internal::FuncNameInferrer;
  using SourceRange = v8::internal::SourceRange;
  using SourceRangeScope = v8::internal::SourceRangeScope;
};

class V8_EXPORT_PRIVATE Parser : public NON_EXPORTED_BASE(ParserBase<Parser>) {
 public:
  Parser(LocalIsolate* local_isolate, ParseInfo* info);
  ~Parser() {
    delete reusable_preparser_;
    reusable_preparser_ = nullptr;
  }

  static bool IsPreParser() { return false; }

  // Sets the literal on |info| if parsing succeeded.
  void ParseOnBackground(LocalIsolate* isolate, ParseInfo* info,
                         DirectHandle<Script> script, int start_position,
                         int end_position, int function_literal_id);

  // Initializes an empty scope chain for top-level scripts, or scopes which
  // consist of only the native context.
  void InitializeEmptyScopeChain(ParseInfo* info);

  // Deserialize the scope chain prior to parsing in which the script is going
  // to be executed. If the script is a top-level script, or the scope chain
  // consists of only a native context, maybe_outer_scope_info should be an
  // empty handle.
  //
  // This only deserializes the scope chain, but doesn't connect the scopes to
  // their corresponding scope infos. Therefore, looking up variables in the
  // deserialized scopes is not possible.
  template <typename IsolateT>
  void DeserializeScopeChain(IsolateT* isolate, ParseInfo* info,
                             MaybeHandle<ScopeInfo> maybe_outer_scope_info,
                             Scope::DeserializationMode mode =
                                 Scope::DeserializationMode::kScopesOnly);

  // Move statistics to Isolate
  void UpdateStatistics(Isolate* isolate, DirectHandle<Script> script);
  void UpdateStatistics(
      DirectHandle<Script> script,
      base::SmallVector<v8::Isolate::UseCounterFeature, 8>* use_counters,
      int* preparse_skipped);
  template <typename IsolateT>
  void HandleSourceURLComments(IsolateT* isolate, DirectHandle<Script> script);

 private:
  friend class ParserBase<Parser>;
  friend struct ParserFormalParameters;
  friend class i::ExpressionScope<ParserTypes<Parser>>;
  friend class i::VariableDeclarationParsingScope<ParserTypes<Parser>>;
  friend class i::ParameterDeclarationParsingScope<ParserTypes<Parser>>;
  friend class i::ArrowHeadParsingScope<ParserTypes<Parser>>;
  friend bool v8::internal::parsing::ParseProgram(
      ParseInfo*, DirectHandle<Script>,
      MaybeHandle<ScopeInfo> maybe_outer_scope_info, Isolate*,
      parsing::ReportStatisticsMode stats_mode);
  friend bool v8::internal::parsing::ParseFunction(
      ParseInfo*, Handle<SharedFunctionInfo> shared_info, Isolate*,
      parsing::ReportStatisticsMode stats_mode);

  bool AllowsLazyParsingWithoutUnresolvedVariables() const {
    return !MaybeParsingArrowhead() &&
           scope()->AllowsLazyParsingWithoutUnresolvedVariables(
               original_scope_);
  }

  bool parse_lazily() const { return mode_ == PARSE_LAZILY; }
  enum Mode { PARSE_LAZILY, PARSE_EAGERLY };

  class V8_NODISCARD ParsingModeScope {
   public:
    ParsingModeScope(Parser* parser, Mode mode)
        : parser_(parser), old_mode_(parser->mode_) {
      parser_->mode_ = mode;
    }
    ~ParsingModeScope() { parser_->mode_ = old_mode_; }

   private:
    Parser* parser_;
    Mode old_mode_;
  };

  // Runtime encoding of different completion modes.
  enum CompletionKind {
    kNormalCompletion,
    kThrowCompletion,
    kAbruptCompletion
  };

  Variable* NewTemporary(const AstRawString* name) {
    return scope()->NewTemporary(name);
  }

  void PrepareGeneratorVariables();

  // Sets the literal on |info| if parsing succeeded.
  void ParseProgram(Isolate* isolate, DirectHandle<Script> script,
                    ParseInfo* info,
                    MaybeHandle<ScopeInfo> maybe_outer_scope_info);

  // Sets the literal on |info| if parsing succeeded.
  void ParseFunction(Isolate* isolate, ParseInfo* info,
                     DirectHandle<SharedFunctionInfo> shared_info);

  template <typename IsolateT>
  void PostProcessParseResult(IsolateT* isolate, ParseInfo* info,
                              FunctionLiteral* literal);

  FunctionLiteral* DoParseFunction(Isolate* isolate, ParseInfo* info,
                                   int start_position, int end_position,
                                   int function_literal_id,
                                   const AstRawString* raw_name);

  FunctionLiteral* ParseClassForMemberInitialization(
      FunctionKind initalizer_kind, int initializer_pos, int initializer_id,
      int initializer_end_pos, const AstRawString* class_name);

  // Called by ParseProgram after setting up the scanner.
  FunctionLiteral* DoParseProgram(Isolate* isolate, ParseInfo* info);

  // Parse with the script as if the source is implicitly wrapped in a function.
  // We manually construct the AST and scopes for a top-level function and the
  // function wrapper.
  void ParseWrapped(Isolate* isolate, ParseInfo* info,
                    ScopedPtrList<Statement>* body, DeclarationScope* scope,
                    Zone* zone);

  void ParseREPLProgram(ParseInfo* info, ScopedPtrList<Statement>* body,
                        DeclarationScope* scope);
  Expression* WrapREPLResult(Expression* value);

  ZonePtrList<const AstRawString>* PrepareWrappedArguments(Isolate* isolate,
                                                           ParseInfo* info,
                                                           Zone* zone);

  PreParser* reusable_preparser() {
    if (reusable_preparser_ == nullptr) {
      reusable_preparser_ = new PreParser(
          &preparser_zone_, &scanner_, stack_limit_, ast_value_factory(),
          pending_error_handler(), runtime_call_stats_, v8_file_logger_,
          flags(), parsing_on_main_thread_);
      reusable_preparser_->set_allow_eval_cache(allow_eval_cache());
      preparse_data_buffer_.reserve(128);
    }
    return reusable_preparser_;
  }

  void ParseModuleItemList(ScopedPtrList<Statement>* body);
  Statement* ParseModuleItem();
  const AstRawString* ParseModuleSpecifier();
  void ParseImportDeclaration();
  Statement* ParseExportDeclaration();
  Statement* ParseExportDefault();
  void ParseExportStar();
  struct ExportClauseData {
    const AstRawString* export_name;
    const AstRawString* local_name;
    Scanner::Location location;
  };
  ZoneChunkList<ExportClauseData>* ParseExportClause(
      Scanner::Location* reserved_loc,
      Scanner::Location* string_literal_local_name_loc);
  struct NamedImport : public ZoneObject {
    const AstRawString* import_name;
    const AstRawString* local_name;
    const Scanner::Location location;
    NamedImport(const AstRawString* import_name, const AstRawString* local_name,
                Scanner::Location location)
        : import_name(import_name),
          local_name(local_name),
          location(location) {}
  };
  const AstRawString* ParseExportSpecifierName();
  ZonePtrList<const NamedImport>* ParseNamedImports(int pos);

  ImportAttributes* ParseImportWithOrAssertClause();
  Statement* BuildInitializationBlock(DeclarationParsingResult* parsing_result);
  Statement* RewriteSwitchStatement(SwitchStatement* switch_statement,
                                    Scope* scope);
  Block* RewriteCatchPattern(CatchInfo* catch_info);
  void ReportVarRedeclarationIn(const AstRawString* name, Scope* scope);
  Statement* RewriteTryStatement(Block* try_block, Block* catch_block,
                                 const SourceRange& catch_range,
                                 Block* finally_block,
                                 const SourceRange& finally_range,
                                 const CatchInfo& catch_info, int pos);
  void ParseGeneratorFunctionBody(int pos, FunctionKind kind,
                                  ScopedPtrList<Statement>* body);
  void ParseAsyncGeneratorFunctionBody(int pos, FunctionKind kind,
                                       ScopedPtrList<Statement>* body);
  void DeclareFunctionNameVar(const AstRawString* function_name,
                              FunctionSyntaxKind function_syntax_kind,
                              DeclarationScope* function_scope);

  Statement* DeclareFunction(const AstRawString* variable_name,
                             FunctionLiteral* function, VariableMode mode,
                             VariableKind kind, int beg_pos, int end_pos,
                             ZonePtrList<const AstRawString>* names);
  VariableProxy* CreateSyntheticContextVariableProxy(ClassScope* scope,
                                                     ClassInfo* class_info,
                                                     const AstRawString* name,
                                                     bool is_static);
  VariableProxy* CreatePrivateNameVariable(ClassScope* scope, VariableMode mode,
                                           IsStaticFlag is_static_flag,
                                           const AstRawString* name);
  FunctionLiteral* CreateInitializerFunction(const AstRawString* class_name,
                                             DeclarationScope* scope,
                                             int function_literal_id,
                                             Statement* initializer_stmt);

  bool IdentifierEquals(const AstRawString* identifier,
                        const AstRawString* other) {
    return identifier == other;
  }

  Statement* DeclareClass(const AstRawString* variable_name, Expression* value,
                          ZonePtrList<const AstRawString>* names,
                          int class_token_pos, int end_pos);
  void DeclareClassVariable(ClassScope* scope, const AstRawString* name,
                            ClassInfo* class_info, int class_token_pos);
  void DeclareClassBrandVariable(ClassScope* scope, ClassInfo* class_info,
                                 int class_token_pos);
  void AddInstanceFieldOrStaticElement(ClassLiteralProperty* property,
                                       ClassInfo* class_info, bool is_static);
  void DeclarePrivateClassMember(ClassScope* scope,
                                 const AstRawString* property_name,
                                 ClassLiteralProperty* property,
                                 ClassLiteralProperty::Kind kind,
                                 bool is_static, ClassInfo* class_info);
  void DeclarePublicClassMethod(const AstRawString* class_name,
                                ClassLiteralProperty* property,
                                bool is_constructor, ClassInfo* class_info);
  void DeclarePublicClassField(ClassScope* scope,
                               ClassLiteralProperty* property, bool is_static,
                               bool is_computed_name, ClassInfo* class_info);
  void DeclareClassProperty(ClassScope* scope, const AstRawString* class_name,
                            ClassLiteralProperty* property, bool is_constructor,
                            ClassInfo* class_info);
  void DeclareClassField(ClassScope* scope, ClassLiteralProperty* property,
                         const AstRawString* property_name, bool is_static,
                         bool is_computed_name, bool is_private,
                         ClassInfo* class_info);
  void AddClassStaticBlock(Block* block, ClassInfo* class_info);
  FunctionLiteral* CreateStaticElementsInitializer(const AstRawString* name,
                                                   ClassInfo* class_info);
  FunctionLiteral* CreateInstanceMembersInitializer(const AstRawString* name,
                                                    ClassInfo* class_info);
  Expression* RewriteClassLiteral(ClassScope* block_scope,
                                  const AstRawString* name,
                                  ClassInfo* class_info, int pos);
  Statement* DeclareNative(const AstRawString* name, int pos);

  Block* IgnoreCompletion(Statement* statement);

  bool HasCheckedSyntax() {
    return scope()->GetDeclarationScope()->has_checked_syntax();
  }

  void InitializeVariables(
      ScopedPtrList<Statement>* statements, VariableKind kind,
      const DeclarationParsingResult::Declaration* declaration);

  Block* RewriteForVarInLegacy(const ForInfo& for_info);
  void DesugarBindingInForEachStatement(ForInfo* for_info, Block** body_block,
                                        Expression** each_variable);
  Block* CreateForEachStatementTDZ(Block* init_block, const ForInfo& for_info);

  Statement* DesugarLexicalBindingsInForStatement(
      ForStatement* loop, Statement* init, Expression* cond, Statement* next,
      Statement* body, Scope* inner_scope, const ForInfo& for_info);

  FunctionLiteral* ParseFunctionLiteral(
      const AstRawString* name, Scanner::Location function_name_location,
      FunctionNameValidity function_name_validity, FunctionKind kind,
      int function_token_position, FunctionSyntaxKind type,
      LanguageMode language_mode,
      ZonePtrList<const AstRawString>* arguments_for_wrapped_function);

  ObjectLiteral* InitializeObjectLiteral(ObjectLiteral* object_literal) {
    object_literal->CalculateEmitStore(main_zone());
    return object_literal;
  }

  // Insert initializer statements for var-bindings shadowing parameter bindings
  // from a non-simple parameter list.
  void InsertShadowingVarBindingInitializers(Block* block);

  // Implement sloppy block-scoped functions, ES2015 Annex B 3.3
  void InsertSloppyBlockFunctionVarBindings(DeclarationScope* scope);

  void DeclareUnboundVariable(const AstRawString* name, VariableMode mode,
                              InitializationFlag init, int pos);
  V8_WARN_UNUSED_RESULT
  VariableProxy* DeclareBoundVariable(const AstRawString* name,
                                      VariableMode mode, int pos);
  void DeclareAndBindVariable(VariableProxy* proxy, VariableKind kind,
                              VariableMode mode, Scope* declaration_scope,
                              bool* was_added, int initializer_position);
  V8_WARN_UNUSED_RESULT
  Variable* DeclareVariable(const AstRawString* name, VariableKind kind,
                            VariableMode mode, InitializationFlag init,
                            Scope* declaration_scope, bool* was_added,
                            int begin, int end = kNoSourcePosition);
  void Declare(Declaration* declaration, const AstRawString* name,
               VariableKind kind, VariableMode mode, InitializationFlag init,
               Scope* declaration_scope, bool* was_added, int var_begin_pos,
               int var_end_pos = kNoSourcePosition);

  // Factory methods.
  FunctionLiteral* DefaultConstructor(const AstRawString* name, bool call_super,
                                      int pos);

  FunctionLiteral* MakeAutoAccessorGetter(VariableProxy* name_proxy,
                                          const AstRawString* name,
                                          bool is_static, int pos);

  FunctionLiteral* MakeAutoAccessorSetter(VariableProxy* name_proxy,
                                          const AstRawString* name,
                                          bool is_static, int pos);

  AutoAccessorInfo* NewAutoAccessorInfo(ClassScope* scope,
                                        ClassInfo* class_info,
                                        const AstRawString* name,
                                        bool is_static, int pos);
  ClassLiteralProperty* NewClassLiteralPropertyWithAccessorInfo(
      ClassScope* scope, ClassInfo* class_info, const AstRawString* name,
      Expression* key, Expression* value, bool is_static, bool is_computed_name,
      bool is_private, int pos);

  // Skip over a lazy function, either using cached data if we have it, or
  // by parsing the function with PreParser. Consumes the ending }.
  // In case the preparser detects an error it cannot identify, it resets the
  // scanner- and preparser state to the initial one, before PreParsing the
  // function.
  // SkipFunction returns true if it correctly parsed the function, including
  // cases where we detect an error. It returns false, if we needed to stop
  // parsing or could not identify an error correctly, meaning the caller needs
  // to fully reparse. In this case it resets the scanner and preparser state.
  bool SkipFunction(const AstRawString* function_name, FunctionKind kind,
                    FunctionSyntaxKind function_syntax_kind,
                    DeclarationScope* function_scope, int* num_parameters,
                    int* function_length,
                    ProducedPreparseData** produced_preparsed_scope_data);

  Block* BuildParameterInitializationBlock(
      const ParserFormalParameters& parameters);

  void ParseFunction(
      ScopedPtrList<Statement>* body, const AstRawString* function_name,
      int pos, FunctionKind kind, FunctionSyntaxKind function_syntax_kind,
      DeclarationScope* function_scope, int* num_parameters,
      int* function_length, bool* has_duplicate_parameters,
      int* expected_property_count, int* suspend_count,
      ZonePtrList<const AstRawString>* arguments_for_wrapped_function);

  void ThrowPendingError(Isolate* isolate, Handle<Script> script);

  class TemplateLiteral : public ZoneObject {
   public:
    TemplateLiteral(Zone* zone, int pos)
        : cooked_(8, zone), raw_(8, zone), expressions_(8, zone), pos_(pos) {}

    const ZonePtrList<const AstRawString>* cooked() const { return &cooked_; }
    const ZonePtrList<const AstRawString>* raw() const { return &raw_; }
    const ZonePtrList<Expression>* expressions() const { return &expressions_; }
    int position() const { return pos_; }

    void AddTemplateSpan(const AstRawString* cooked, const AstRawString* raw,
                         int end, Zone* zone) {
      DCHECK_NOT_NULL(raw);
      cooked_.Add(cooked, zone);
      raw_.Add(raw, zone);
    }

    void AddExpression(Expression* expression, Zone* zone) {
      expressions_.Add(expression, zone);
    }

   private:
    ZonePtrList<const AstRawString> cooked_;
    ZonePtrList<const AstRawString> raw_;
    ZonePtrList<Expression> expressions_;
    int pos_;
  };

  using TemplateLiteralState = TemplateLiteral*;

  TemplateLiteralState OpenTemplateLiteral(int pos);
  // "should_cook" means that the span can be "cooked": in tagged template
  // literals, both the raw and "cooked" representations are available to user
  // code ("cooked" meaning that escape sequences are converted to their
  // interpreted values). Invalid escape sequences cause the cooked span
  // to be represented by undefined, instead of being a syntax error.
  // "tail" indicates that this span is the last in the literal.
  void AddTemplateSpan(TemplateLiteralState* state, bool should_cook,
                       bool tail);
  void AddTemplateExpression(TemplateLiteralState* state,
                             Expression* expression);
  Expression* CloseTemplateLiteral(TemplateLiteralState* state, int start,
                                   Expression* tag);

  Expression* RewriteSuperCall(Expression* call_expression);

  void SetLanguageMode(Scope* scope, LanguageMode mode);
#if V8_ENABLE_WEBASSEMBLY
  void SetAsmModule();
#endif  // V8_ENABLE_WEBASSEMBLY

  Expression* RewriteSpreads(ArrayLiteral* lit);

  Expression* BuildInitialYield(int pos, FunctionKind kind);
  Assignment* BuildCreateJSGeneratorObject(int pos, FunctionKind kind);

  // Generic AST generator for throwing errors from compiled code.
  Expression* NewThrowError(Runtime::FunctionId function_id,
                            MessageTemplate message, const AstRawString* arg,
                            int pos);

  void AddArrowFunctionFormalParameters(ParserFormalParameters* parameters,
                                        Expression* params, int end_pos);
  void SetFunctionName(Expression* value, const AstRawString* name,
                       const AstRawString* prefix = nullptr);

  // Helper functions for recursive descent.
  V8_INLINE bool IsEval(const AstRawString* identifier) const {
    return identifier == ast_value_factory()->eval_string();
  }

  V8_INLINE bool IsAsync(const AstRawString* identifier) const {
    return identifier == ast_value_factory()->async_string();
  }

  V8_INLINE bool IsArguments(const AstRawString* identifier) const {
    return identifier == ast_value_factory()->arguments_string();
  }

  V8_INLINE bool IsEvalOrArguments(const AstRawString* identifier) const {
    return IsEval(identifier) || IsArguments(identifier);
  }

  // Returns true if the expression is of type "this.foo".
  V8_INLINE static bool IsThisProperty(Expression* expression) {
    DCHECK_NOT_NULL(expression);
    Property* property = expression->AsProperty();
    return property != nullptr && property->obj()->IsThisExpression();
  }

  // Returns true if the expression is of type "obj.#foo" or "obj?.#foo".
  V8_INLINE static bool IsPrivateReference(Expression* expression) {
    DCHECK_NOT_NULL(expression);
    Property* property = expression->AsProperty();
    if (expression->IsOptionalChain()) {
      Expression* expr_inner = expression->AsOptionalChain()->expression();
      property = expr_inner->AsProperty();
    }
    return property != nullptr && property->IsPrivateReference();
  }

  // This returns true if the expression is an identifier (wrapped
  // inside a variable proxy).  We exclude the case of 'this', which
  // has been converted to a variable proxy.
  V8_INLINE static bool IsIdentifier(Expression* expression) {
    VariableProxy* operand = expression->AsVariableProxy();
    return operand != nullptr && !operand->is_new_target();
  }

  V8_INLINE static const AstRawString* AsIdentifier(Expression* expression) {
    DCHECK(IsIdentifier(expression));
    return expression->AsVariableProxy()->raw_name();
  }

  V8_INLINE VariableProxy* AsIdentifierExpression(Expression* expression) {
    return expression->AsVariableProxy();
  }

  V8_INLINE bool IsConstructor(const AstRawString* identifier) const {
    return identifier == ast_value_factory()->constructor_string();
  }

  V8_INLINE static bool IsBoilerplateProperty(
      ObjectLiteral::Property* property) {
    return !property->IsPrototype();
  }

  V8_INLINE v8::Extension* extension() const { return info_->extension(); }

  V8_INLINE bool ParsingExtension() const { return extension() != nullptr; }

  V8_INLINE bool IsNative(Expression* expr) const {
    DCHECK_NOT_NULL(expr);
    return expr->IsVariableProxy() &&
           expr->AsVariableProxy()->raw_name() ==
               ast_value_factory()->native_string();
  }

  V8_INLINE static bool IsArrayIndex(const AstRawString* string,
                                     uint32_t* index) {
    return string->AsArrayIndex(index);
  }

  // Returns true if the statement is an expression statement containing
  // a single string literal.  If a second argument is given, the literal
  // is also compared with it and the result is true only if they are equal.
  V8_INLINE bool IsStringLiteral(Statement* statement,
                                 const AstRawString* arg = nullptr) const {
    ExpressionStatement* e_stat = statement->AsExpressionStatement();
    if (e_stat == nullptr) return false;
    Literal* literal = e_stat->expression()->AsLiteral();
    if (literal == nullptr || !literal->IsRawString()) return false;
    return arg == nullptr || literal->AsRawString() == arg;
  }

  V8_INLINE void GetDefaultStrings(const AstRawString** default_string,
                                   const AstRawString** dot_default_string) {
    *default_string = ast_value_factory()->default_string();
    *dot_default_string = ast_value_factory()->dot_default_string();
  }

  // Functions for encapsulating the differences between parsing and preparsing;
  // operations interleaved with the recursive descent.
  V8_INLINE void PushLiteralName(const AstRawString* id) {
    fni_.PushLiteralName(id);
  }

  V8_INLINE void PushVariableName(const AstRawString* id) {
    fni_.PushVariableName(id);
  }

  V8_INLINE void PushPropertyName(Expression* expression) {
    if (expression->IsPropertyName()) {
      fni_.PushLiteralName(expression->AsLiteral()->AsRawPropertyName());
    } else {
      fni_.PushLiteralName(ast_value_factory()->computed_string());
    }
  }

  V8_INLINE void PushEnclosingName(const AstRawString* name) {
    fni_.PushEnclosingName(name);
  }

  V8_INLINE void AddFunctionForNameInference(FunctionLiteral* func_to_infer) {
    fni_.AddFunction(func_to_infer);
  }

  V8_INLINE void InferFunctionName() { fni_.Infer(); }

  // If we assign a function literal to a property we pretenure the
  // literal so it can be added as a constant function property.
  V8_INLINE static void CheckAssigningFunctionLiteralToProperty(
      Expression* left, Expression* right) {
    DCHECK_NOT_NULL(left);
    if (left->IsProperty() && right->IsFunctionLiteral()) {
      right->AsFunctionLiteral()->set_pretenure();
    }
  }

  // Returns true if we have a binary expression between two literals. In that
  // case, *x will be changed to an expression which is the computed value.
  bool ShortcutLiteralBinaryExpression(Expression** x, Expression* y,
                                       Token::Value op, int pos);

  bool CollapseConditionalChain(Expression** x, Expression* cond,
                                Expression* then_expression,
                                Expression* else_expression, int pos,
                                const SourceRange& then_range);

  void AppendConditionalChainElse(Expression** x,
                                  const SourceRange& else_range);

  // Returns true if we have a binary operation between a binary/n-ary
  // expression (with the same operation) and a value, which can be collapsed
  // into a single n-ary expression. In that case, *x will be changed to an
  // n-ary expression.
  bool CollapseNaryExpression(Expression** x, Expression* y, Token::Value op,
                              int pos, const SourceRange& range);

  // Returns a UnaryExpression or, in one of the following cases, a Literal.
  // ! <literal> -> true / false
  // + <Number literal> -> <Number literal>
  // - <Number literal> -> <Number literal with value negated>
  // ~ <literal> -> true / false
  Expression* BuildUnaryExpression(Expression* expression, Token::Value op,
                                   int pos);

  // Generate AST node that throws a ReferenceError with the given type.
  V8_INLINE Expression* NewThrowReferenceError(MessageTemplate message,
                                               int pos) {
    return NewThrowError(Runtime::kNewReferenceError, message,
                         ast_value_factory()->empty_string(), pos);
  }

  // Dummy implementation. The parser should never have a unidentifiable
  // error.
  V8_INLINE void ReportUnidentifiableError() { UNREACHABLE(); }

  const AstRawString* GetRawNameFromIdentifier(const AstRawString* arg) {
    return arg;
  }

  const AstRawString* PreParserIdentifierToAstRawString(
      const PreParserIdentifier& arg) {
    // This method definition is only needed due to an MSVC oddity that
    // instantiates the method despite it being unused. See crbug.com/v8/12266 .
    UNREACHABLE();
  }

  IterationStatement* AsIterationStatement(BreakableStatement* s) {
    return s->AsIterationStatement();
  }

  void ReportUnexpectedTokenAt(
      Scanner::Location location, Token::Value token,
      MessageTemplate message = MessageTemplate::kUnexpectedToken);

  // "null" return type creators.
  V8_INLINE static std::nullptr_t NullIdentifier() { return nullptr; }
  V8_INLINE static std::nullptr_t NullExpression() { return nullptr; }
  V8_INLINE static std::nullptr_t NullLiteralProperty() { return nullptr; }
  V8_INLINE static ZonePtrList<Expression>* NullExpressionList() {
    return nullptr;
  }
  V8_INLINE static ZonePtrList<Statement>* NullStatementList() {
    return nullptr;
  }
  V8_INLINE static std::nullptr_t NullStatement() { return nullptr; }
  V8_INLINE static std::nullptr_t NullBlock() { return nullptr; }
  Expression* FailureExpression() { return factory()->FailureExpression(); }

  template <typename T>
  V8_INLINE static bool IsNull(T subject) {
    return subject == nullptr;
  }

  V8_INLINE static bool IsIterationStatement(Statement* subject) {
    return subject->A
"""


```