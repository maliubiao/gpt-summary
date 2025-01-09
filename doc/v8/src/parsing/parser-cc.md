Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/parsing/parser.cc`. Here's a breakdown of the thinking process to achieve that:

1. **Identify the Core Task:** The primary role of `parser.cc` is, as the name suggests, *parsing*. This involves taking source code (likely JavaScript in the V8 context) and converting it into an Abstract Syntax Tree (AST).

2. **Scan for Keywords and Data Structures:** Look for recurring terms and data structures that hint at the parser's operations. Key terms that stand out include:
    * `Parser` (the class itself)
    * `FunctionLiteral`
    * `Statement`
    * `Expression`
    * `Scope` (DeclarationScope, FunctionScope, etc.)
    * `Token`
    * `AstRawString`
    * `factory()` (likely an AST node factory)
    * `New...` methods (e.g., `NewFunctionLiteral`, `NewStatement`)
    * `Parse...` methods (e.g., `ParseProgram`, `ParseStatementList`)
    * `scanner()`
    * `ReportMessage` (error reporting)

3. **Analyze Key Functionalities Based on Keywords:**  Group the observed terms into functional categories:

    * **AST Construction:** The frequent use of `factory()->New...` strongly indicates the parser's role in building the AST. Specifically, it's creating nodes for functions (`FunctionLiteral`), various statements (`Statement`), and expressions (`Expression`).

    * **Scope Management:**  The presence of `Scope` objects and methods like `NewFunctionScope`, `NewScriptScope`, and `DeserializeScopeChain` suggests the parser handles the creation and management of lexical scopes. This is crucial for understanding variable visibility and closures.

    * **Tokenization and Lexing:**  The `scanner()` member and references to `Token` indicate interaction with a lexer/scanner. The parser receives tokens from the scanner to build the AST.

    * **Error Handling:**  The `ReportMessage` calls and `pending_error_handler()` suggest error detection and reporting during parsing.

    * **Language Features:** The code mentions concepts like "classes", "accessors", "super calls", "import.meta", and different `FunctionKind` values. This points to the parser's support for various JavaScript language features, including ES6 and beyond.

    * **Constant Folding/Optimization:** The `ShortcutLiteralBinaryExpression` function suggests the parser performs basic constant folding optimizations during parsing.

    * **Lazy Parsing:** The code mentions `PARSE_LAZILY` and `PARSE_EAGERLY`, indicating the parser can operate in different modes to optimize compilation.

4. **Address Specific Questions:**  Now address the user's specific questions:

    * **`.tq` extension:**  The code explicitly checks for `.tq` and identifies it as a V8 Torque source file.

    * **Relationship to JavaScript:**  Emphasize that the code *parses* JavaScript. Provide JavaScript examples that correspond to the C++ code's actions (e.g., a default constructor for `DefaultConstructor`).

    * **Code Logic Inference:** Choose a relatively straightforward function to demonstrate logic inference. `DefaultConstructor` is a good choice because its logic is explicit in the code (creating a `super()` call if `call_super` is true). Provide clear input assumptions and expected output based on those assumptions.

    * **Common Programming Errors:** Think about the kinds of errors a parser would catch. Syntax errors (like `ReportUnexpectedTokenAt`) are primary. Provide a simple JavaScript syntax error as an example.

5. **Summarize Functionality:**  Combine the observations into a concise summary that captures the core responsibilities of `parser.cc`.

6. **Structure the Response:** Organize the information logically, using headings and bullet points for clarity. Place the summary at the end as requested.

7. **Review and Refine:**  Read through the generated response to ensure accuracy, completeness, and clarity. Check that all aspects of the user's request have been addressed. For instance, initially, I might not have explicitly mentioned constant folding, but reviewing the code, `ShortcutLiteralBinaryExpression` is a significant feature to include. Similarly, ensuring a JavaScript example is provided for a relevant C++ function like `DefaultConstructor` strengthens the explanation.
好的，根据你提供的V8源代码 `v8/src/parsing/parser.cc` 的第一部分，我们可以归纳出以下功能：

**核心功能：JavaScript 代码解析器**

`v8/src/parsing/parser.cc` 文件的核心功能是实现 V8 引擎的 **JavaScript 代码解析器**。它负责将输入的 JavaScript 源代码（文本形式）转换成 V8 引擎内部可以理解和执行的抽象语法树 (AST, Abstract Syntax Tree)。

**具体功能点：**

1. **构建抽象语法树 (AST)：**
   - 包含了创建各种 AST 节点的方法，例如：
     - `NewFunctionLiteral`: 创建函数字面量节点 (包括普通函数、构造函数、getter/setter 等)。
     - `NewStatement`: 创建各种语句节点（例如，返回语句 `NewReturnStatement`）。
     - `NewExpression`: 创建各种表达式节点（例如，`NewSuperCallForwardArgs` 用于构建 `super()` 调用）。
     - `NewClassLiteralProperty`:  创建类字面量属性节点。
     - `NewAutoAccessorInfo`: 创建自动访问器 (getter/setter) 的信息。
     - `NewBinaryOperation`, `NewUnaryOperation`, `NewNaryOperation`: 创建二元、一元和多元运算表达式节点。
     - `NewCallRuntime`: 创建调用运行时函数的节点。
     - `NewThrow`: 创建抛出异常的节点。
     - `NewSuperPropertyReference`, `NewSuperCallReference`: 创建 `super` 关键字相关的引用。
     - `NewTargetExpression`: 创建 `new.target` 表达式。
     - `NewUndefinedLiteral`, `NewNullLiteral`, `NewBooleanLiteral`, `NewSmiLiteral`, `NewNumberLiteral`, `NewStringLiteral`, `NewBigIntLiteral`: 创建各种字面量节点。

2. **处理类 (Class) 相关的语法：**
   - `DefaultConstructor`:  用于生成默认的构造函数。
   - `MakeAutoAccessorGetter`, `MakeAutoAccessorSetter`:  用于创建自动访问器的 getter 和 setter 函数。
   - `NewAutoAccessorInfo`, `NewClassLiteralPropertyWithAccessorInfo`: 用于创建和关联自动访问器信息。

3. **错误处理和报告：**
   - `ReportUnexpectedTokenAt`:  报告遇到了不期望的 token。
   - 其他 `ReportMessageAt` 和 `ReportMessage` 系列函数用于报告不同类型的解析错误。

4. **字面量优化和处理：**
   - `ShortcutLiteralBinaryExpression`:  尝试对字面量二元表达式进行常量折叠优化，例如：计算 `1 + 2` 的结果。
   - `GetBigIntAsSymbol`: 将 BigInt 字面量转换为符号表示。
   - `ExpressionFromLiteral`:  根据 token 类型创建相应的字面量表达式。

5. **处理 `super` 关键字：**
   - `NewSuperCallReference`, `NewSuperPropertyReference`:  处理 `super()` 调用和 `super.property` 访问。

6. **处理 `new.target` 和 `import.meta`：**
   - `NewTargetExpression`: 创建 `new.target` 表达式节点。
   - `ImportMetaExpression`: 创建 `import.meta` 表达式节点。

7. **处理 V8 内部函数 (`%...`)：**
   - `NewV8Intrinsic`:  用于创建调用 V8 内部函数的节点。

8. **作用域 (Scope) 管理：**
   - `NewFunctionScope`, `NewScriptScope`, `NewEvalScope`, `NewModuleScope`: 创建不同类型的的作用域。
   - `DeserializeScopeChain`:  反序列化作用域链。
   - `InitializeEmptyScopeChain`: 初始化空的作用域链。

9. **处理条件链 (Conditional Chain) 表达式：**
   - `CollapseConditionalChain`, `AppendConditionalChainElse`:  用于处理可选链式调用 (Optional Chaining) 相关的表达式 (`?.`)。

10. **处理多元表达式 (Nary Expression)：**
    - `CollapseNaryExpression`: 用于将多个相同操作符的二元表达式合并成一个多元表达式，提高 AST 的紧凑性。

11. **支持懒解析 (Lazy Parsing)：**
    - 提到 `PARSE_LAZILY` 和 `PARSE_EAGERLY`，表明解析器可以支持延迟解析，只在需要时解析函数体。

**关于 .tq 结尾：**

根据你提供的描述，**如果 `v8/src/parsing/parser.cc` 以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。**  目前你提供的文件名是 `.cc`，因此它是一个 **C++ 源代码文件**。Torque 是 V8 用于生成高效运行时代码的一种领域特定语言。

**与 JavaScript 功能的关系和 JavaScript 示例：**

`v8/src/parsing/parser.cc` 直接负责解析 JavaScript 代码。以下是一些 C++ 代码功能与对应的 JavaScript 例子：

* **`DefaultConstructor` (C++)**:  当 JavaScript 类没有显式定义构造函数，且继承了其他类时，V8 会生成默认的构造函数。

   ```javascript
   class Parent {}
   class Child extends Parent {} // Child 类会有一个默认构造函数，类似于 constructor(...args) { super(...args); }
   ```

* **`MakeAutoAccessorGetter` 和 `MakeAutoAccessorSetter` (C++)**:  对应于 JavaScript 类的属性简写形式，或者使用 `accessor` 关键字定义的访问器。

   ```javascript
   class MyClass {
     myProperty; // 隐式创建了 getter 和 setter

     get myAccessor() { // 显式定义的 getter
       return this.myProperty;
     }
     set myAccessor(value) { // 显式定义的 setter
       this.myProperty = value;
     }
   }
   ```

* **`ShortcutLiteralBinaryExpression` (C++)**:  解析器会在编译时尝试计算常量表达式。

   ```javascript
   const result = 1 + 2; // 解析器在解析时就知道 result 的值是 3
   ```

* **`NewSuperCallReference` (C++)**:  对应于 JavaScript 中的 `super()` 调用。

   ```javascript
   class Child extends Parent {
     constructor() {
       super(); // 调用父类的构造函数
     }
   }
   ```

* **`NewTargetExpression` (C++)**: 对应于 JavaScript 中的 `new.target`。

   ```javascript
   function MyFunction() {
     console.log(new.target);
   }
   new MyFunction(); // 输出 MyFunction
   MyFunction();      // 输出 undefined
   ```

* **`ImportMetaExpression` (C++)**: 对应于 JavaScript 中的 `import.meta`。

   ```javascript
   // 在一个模块文件中
   console.log(import.meta.url);
   ```

**代码逻辑推理：假设输入与输出**

以 `DefaultConstructor` 函数为例：

**假设输入：**

* `name`:  一个表示构造函数名称的 `AstRawString`，例如 "Child"。
* `call_super`: 一个布尔值，指示是否需要调用 `super()`。
    * 假设输入 `true`。
* `pos`:  构造函数在源代码中的位置，例如 10。

**预期输出：**

一个 `FunctionLiteral` 对象，表示默认的构造函数，其主体包含一个调用 `super()` 的 `ReturnStatement`。  AST 结构大致如下：

```
FunctionLiteral {
  name: "Child",
  kind: kDefaultDerivedConstructor,
  body: [
    ReturnStatement {
      expression: SuperCall {
        // ... super 调用的相关信息
      }
    }
  ]
  // ... 其他属性
}
```

如果 `call_super` 是 `false`，则 `body` 将为空，因为基类的默认构造函数不需要显式调用 `super()`。

**涉及用户常见的编程错误：**

* **语法错误：** `ReportUnexpectedTokenAt` 捕捉的就是这类错误。例如，在 JavaScript 中写错关键字或缺少必要的符号。

   ```javascript
   functoin myFunction() { // 拼写错误 "function"
     console.log("Hello); // 缺少引号
   }
   ```

* **在子类的构造函数中忘记调用 `super()` (如果需要)：**  V8 的解析器会处理默认构造函数的生成，但在手动编写构造函数时，这是常见的错误。

   ```javascript
   class Parent {
     constructor(name) {
       this.name = name;
     }
   }

   class Child extends Parent {
     constructor() {
       // 忘记调用 super()，会导致错误
       console.log("Child constructor");
     }
   }

   new Child(); // ReferenceError: Must call super constructor in derived class ...
   ```

**归纳 `v8/src/parsing/parser.cc` 第一部分的功能：**

总而言之，`v8/src/parsing/parser.cc` 的这一部分定义了 V8 引擎中负责将 JavaScript 源代码文本解析成抽象语法树 (AST) 的核心组件。它包含了创建各种 AST 节点、处理类语法、进行基本的字面量优化、处理 `super` 关键字、管理作用域以及进行错误报告的关键逻辑。这个解析器是 V8 引擎将 JavaScript 代码转换为可执行形式的第一步，至关重要。

Prompt: 
```
这是目录为v8/src/parsing/parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/parsing/parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/parsing/parser.h"

#include <algorithm>
#include <memory>
#include <optional>

#include "src/ast/ast-function-literal-id-reindexer.h"
#include "src/ast/ast-traversal-visitor.h"
#include "src/ast/ast.h"
#include "src/ast/source-range-ast-visitor.h"
#include "src/base/ieee754.h"
#include "src/base/overflowing-math.h"
#include "src/base/platform/platform.h"
#include "src/codegen/bailout-reason.h"
#include "src/common/globals.h"
#include "src/common/message-template.h"
#include "src/compiler-dispatcher/lazy-compile-dispatcher.h"
#include "src/heap/parked-scope.h"
#include "src/logging/counters.h"
#include "src/logging/log.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/numbers/conversions-inl.h"
#include "src/numbers/ieee754.h"
#include "src/objects/scope-info.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/rewriter.h"
#include "src/runtime/runtime.h"
#include "src/strings/char-predicates-inl.h"
#include "src/strings/string-stream.h"
#include "src/strings/unicode-inl.h"
#include "src/tracing/trace-event.h"
#include "src/zone/zone-list-inl.h"

namespace v8::internal {

FunctionLiteral* Parser::DefaultConstructor(const AstRawString* name,
                                            bool call_super, int pos) {
  int expected_property_count = 0;
  const int parameter_count = 0;

  FunctionKind kind = call_super ? FunctionKind::kDefaultDerivedConstructor
                                 : FunctionKind::kDefaultBaseConstructor;
  DeclarationScope* function_scope = NewFunctionScope(kind);
  SetLanguageMode(function_scope, LanguageMode::kStrict);
  // Set start and end position to the same value
  function_scope->set_start_position(pos);
  function_scope->set_end_position(pos);
  ScopedPtrList<Statement> body(pointer_buffer());

  {
    FunctionState function_state(&function_state_, &scope_, function_scope);

    // ES#sec-runtime-semantics-classdefinitionevaluation
    //
    // 14.a
    //  ...
    //  iv. If F.[[ConstructorKind]] is DERIVED, then
    //    1. NOTE: This branch behaves similarly to constructor(...args) {
    //       super(...args); }. The most notable distinction is that while the
    //       aforementioned ECMAScript source text observably calls the
    //       @@iterator method on %Array.prototype%, this function does not.
    //    2. Let func be ! F.[[GetPrototypeOf]]().
    //    3. If IsConstructor(func) is false, throw a TypeError exception.
    //    4. Let result be ? Construct(func, args, NewTarget).
    //  ...
    if (call_super) {
      SuperCallReference* super_call_ref = NewSuperCallReference(pos);
      Expression* call =
          factory()->NewSuperCallForwardArgs(super_call_ref, pos);
      body.Add(factory()->NewReturnStatement(call, pos));
    }

    expected_property_count = function_state.expected_property_count();
  }

  FunctionLiteral* function_literal = factory()->NewFunctionLiteral(
      name, function_scope, body, expected_property_count, parameter_count,
      parameter_count, FunctionLiteral::kNoDuplicateParameters,
      FunctionSyntaxKind::kAnonymousExpression, default_eager_compile_hint(),
      pos, true, GetNextInfoId());
  return function_literal;
}

FunctionLiteral* Parser::MakeAutoAccessorGetter(VariableProxy* name_proxy,
                                                const AstRawString* name,
                                                bool is_static, int pos) {
  ScopedPtrList<Statement> body(pointer_buffer());
  DeclarationScope* function_scope =
      NewFunctionScope(is_static ? FunctionKind::kGetterFunction
                                 : FunctionKind::kStaticGetterFunction);
  SetLanguageMode(function_scope, LanguageMode::kStrict);
  function_scope->set_start_position(pos);
  function_scope->set_end_position(pos);
  {
    FunctionState function_state(&function_state_, &scope_, function_scope);
    body.Add(factory()->NewAutoAccessorGetterBody(name_proxy, pos));
  }
  // TODO(42202709): Enable lazy compilation by adding custom handling in
  //                 `Parser::DoParseFunction`.
  FunctionLiteral* getter = factory()->NewFunctionLiteral(
      nullptr, function_scope, body, 0, 0, 0,
      FunctionLiteral::kNoDuplicateParameters,
      FunctionSyntaxKind::kAccessorOrMethod,
      FunctionLiteral::kShouldEagerCompile, pos, true, GetNextInfoId());
  const AstRawString* prefix =
      name ? ast_value_factory()->get_space_string() : nullptr;
  SetFunctionName(getter, name, prefix);
  return getter;
}

FunctionLiteral* Parser::MakeAutoAccessorSetter(VariableProxy* name_proxy,
                                                const AstRawString* name,
                                                bool is_static, int pos) {
  ScopedPtrList<Statement> body(pointer_buffer());
  DeclarationScope* function_scope =
      NewFunctionScope(is_static ? FunctionKind::kSetterFunction
                                 : FunctionKind::kStaticSetterFunction);
  SetLanguageMode(function_scope, LanguageMode::kStrict);
  function_scope->set_start_position(pos);
  function_scope->set_end_position(pos);
  function_scope->DeclareParameter(ast_value_factory()->empty_string(),
                                   VariableMode::kTemporary, false, false,
                                   ast_value_factory(), kNoSourcePosition);
  {
    FunctionState function_state(&function_state_, &scope_, function_scope);
    body.Add(factory()->NewAutoAccessorSetterBody(name_proxy, pos));
  }
  // TODO(42202709): Enable lazy compilation by adding custom handling in
  //                 `Parser::DoParseFunction`.
  FunctionLiteral* setter = factory()->NewFunctionLiteral(
      nullptr, function_scope, body, 0, 1, 0,
      FunctionLiteral::kNoDuplicateParameters,
      FunctionSyntaxKind::kAccessorOrMethod,
      FunctionLiteral::kShouldEagerCompile, pos, true, GetNextInfoId());
  const AstRawString* prefix =
      name ? ast_value_factory()->set_space_string() : nullptr;
  SetFunctionName(setter, name, prefix);
  return setter;
}

AutoAccessorInfo* Parser::NewAutoAccessorInfo(ClassScope* scope,
                                              ClassInfo* class_info,
                                              const AstRawString* name,
                                              bool is_static, int pos) {
  VariableProxy* accessor_storage_name_proxy =
      CreateSyntheticContextVariableProxy(
          scope, class_info,
          AutoAccessorVariableName(ast_value_factory(),
                                   class_info->autoaccessor_count++),
          is_static);
  // The property value position will match the beginning of the "accessor"
  // keyword, which can be the same as the start of the parent class scope, use
  // the position of the next two characters to distinguish them.
  FunctionLiteral* getter = MakeAutoAccessorGetter(accessor_storage_name_proxy,
                                                   name, is_static, pos + 1);
  FunctionLiteral* setter = MakeAutoAccessorSetter(accessor_storage_name_proxy,
                                                   name, is_static, pos + 2);
  return factory()->NewAutoAccessorInfo(getter, setter,
                                        accessor_storage_name_proxy);
}

ClassLiteralProperty* Parser::NewClassLiteralPropertyWithAccessorInfo(
    ClassScope* scope, ClassInfo* class_info, const AstRawString* name,
    Expression* key, Expression* value, bool is_static, bool is_computed_name,
    bool is_private, int pos) {
  AutoAccessorInfo* accessor_info =
      NewAutoAccessorInfo(scope, class_info, name, is_static, pos);
  return factory()->NewClassLiteralProperty(
      key, value, accessor_info, is_static, is_computed_name, is_private);
}

void Parser::ReportUnexpectedTokenAt(Scanner::Location location,
                                     Token::Value token,
                                     MessageTemplate message) {
  const char* arg = nullptr;
  switch (token) {
    case Token::kEos:
      message = MessageTemplate::kUnexpectedEOS;
      break;
    case Token::kSmi:
    case Token::kNumber:
    case Token::kBigInt:
      message = MessageTemplate::kUnexpectedTokenNumber;
      break;
    case Token::kString:
      message = MessageTemplate::kUnexpectedTokenString;
      break;
    case Token::kPrivateName:
    case Token::kIdentifier:
      message = MessageTemplate::kUnexpectedTokenIdentifier;
      // Use ReportMessageAt with the AstRawString parameter; skip the
      // ReportMessageAt below.
      ReportMessageAt(location, message, GetIdentifier());
      return;
    case Token::kAwait:
    case Token::kEnum:
      message = MessageTemplate::kUnexpectedReserved;
      break;
    case Token::kLet:
    case Token::kStatic:
    case Token::kYield:
    case Token::kFutureStrictReservedWord:
      message = is_strict(language_mode())
                    ? MessageTemplate::kUnexpectedStrictReserved
                    : MessageTemplate::kUnexpectedTokenIdentifier;
      arg = Token::String(token);
      break;
    case Token::kTemplateSpan:
    case Token::kTemplateTail:
      message = MessageTemplate::kUnexpectedTemplateString;
      break;
    case Token::kEscapedStrictReservedWord:
    case Token::kEscapedKeyword:
      message = MessageTemplate::kInvalidEscapedReservedWord;
      break;
    case Token::kIllegal:
      if (scanner()->has_error()) {
        message = scanner()->error();
        location = scanner()->error_location();
      } else {
        message = MessageTemplate::kInvalidOrUnexpectedToken;
      }
      break;
    case Token::kRegExpLiteral:
      message = MessageTemplate::kUnexpectedTokenRegExp;
      break;
    default:
      const char* name = Token::String(token);
      DCHECK_NOT_NULL(name);
      arg = name;
      break;
  }
  ReportMessageAt(location, message, arg);
}

// ----------------------------------------------------------------------------
// Implementation of Parser

bool Parser::ShortcutLiteralBinaryExpression(Expression** x, Expression* y,
                                             Token::Value op, int pos) {
  // Constant fold numeric operations.
  if ((*x)->IsNumberLiteral() && y->IsNumberLiteral()) {
    double x_val = (*x)->AsLiteral()->AsNumber();
    double y_val = y->AsLiteral()->AsNumber();
    switch (op) {
      case Token::kAdd:
        *x = factory()->NewNumberLiteral(x_val + y_val, pos);
        return true;
      case Token::kSub:
        *x = factory()->NewNumberLiteral(x_val - y_val, pos);
        return true;
      case Token::kMul:
        *x = factory()->NewNumberLiteral(x_val * y_val, pos);
        return true;
      case Token::kDiv:
        *x = factory()->NewNumberLiteral(base::Divide(x_val, y_val), pos);
        return true;
      case Token::kMod:
        *x = factory()->NewNumberLiteral(Modulo(x_val, y_val), pos);
        return true;
      case Token::kBitOr: {
        int value = DoubleToInt32(x_val) | DoubleToInt32(y_val);
        *x = factory()->NewNumberLiteral(value, pos);
        return true;
      }
      case Token::kBitAnd: {
        int value = DoubleToInt32(x_val) & DoubleToInt32(y_val);
        *x = factory()->NewNumberLiteral(value, pos);
        return true;
      }
      case Token::kBitXor: {
        int value = DoubleToInt32(x_val) ^ DoubleToInt32(y_val);
        *x = factory()->NewNumberLiteral(value, pos);
        return true;
      }
      case Token::kShl: {
        int value =
            base::ShlWithWraparound(DoubleToInt32(x_val), DoubleToInt32(y_val));
        *x = factory()->NewNumberLiteral(value, pos);
        return true;
      }
      case Token::kShr: {
        uint32_t shift = DoubleToInt32(y_val) & 0x1F;
        uint32_t value = DoubleToUint32(x_val) >> shift;
        *x = factory()->NewNumberLiteral(value, pos);
        return true;
      }
      case Token::kSar: {
        uint32_t shift = DoubleToInt32(y_val) & 0x1F;
        int value = ArithmeticShiftRight(DoubleToInt32(x_val), shift);
        *x = factory()->NewNumberLiteral(value, pos);
        return true;
      }
      case Token::kExp:
        *x = factory()->NewNumberLiteral(math::pow(x_val, y_val), pos);
        return true;
      default:
        break;
    }
  }

  // Constant fold string concatenation.
  if (op == Token::kAdd) {
    // Only consider string concatenation of two strings.
    // TODO(leszeks): We could also eagerly convert other literals to string if
    // one side of the addition is a string.
    if (y->IsStringLiteral()) {
      if ((*x)->IsStringLiteral()) {
        const AstRawString* x_val = (*x)->AsLiteral()->AsRawString();
        const AstRawString* y_val = y->AsLiteral()->AsRawString();
        AstConsString* cons = ast_value_factory()->NewConsString(x_val, y_val);
        *x = factory()->NewConsStringLiteral(cons, (*x)->position());
        return true;
      }
      if ((*x)->IsConsStringLiteral()) {
        const AstRawString* y_val = y->AsLiteral()->AsRawString();
        (*x)->AsLiteral()->AsConsString()->AddString(zone(), y_val);
        return true;
      }
    }
  }
  return false;
}

bool Parser::CollapseConditionalChain(Expression** x, Expression* cond,
                                      Expression* then_expression,
                                      Expression* else_expression, int pos,
                                      const SourceRange& then_range) {
  if (*x && (*x)->IsConditionalChain()) {
    ConditionalChain* conditional_chain = (*x)->AsConditionalChain();
    if (then_expression != nullptr) {
      conditional_chain->AddChainEntry(cond, then_expression, pos);
      AppendConditionalChainSourceRange(conditional_chain, then_range);
    }
    if (else_expression != nullptr) {
      conditional_chain->set_else_expression(else_expression);
      DCHECK_GT(conditional_chain->conditional_chain_length(), 1);
    }
    return true;
  }
  return false;
}

void Parser::AppendConditionalChainElse(Expression** x,
                                        const SourceRange& else_range) {
  if (*x && (*x)->IsConditionalChain()) {
    ConditionalChain* conditional_chain = (*x)->AsConditionalChain();
    AppendConditionalChainElseSourceRange(conditional_chain, else_range);
  }
}

bool Parser::CollapseNaryExpression(Expression** x, Expression* y,
                                    Token::Value op, int pos,
                                    const SourceRange& range) {
  // Filter out unsupported ops.
  if (!Token::IsBinaryOp(op) || op == Token::kExp) return false;

  // Convert *x into an nary operation with the given op, returning false if
  // this is not possible.
  NaryOperation* nary = nullptr;
  if ((*x)->IsBinaryOperation()) {
    BinaryOperation* binop = (*x)->AsBinaryOperation();
    if (binop->op() != op) return false;

    nary = factory()->NewNaryOperation(op, binop->left(), 2);
    nary->AddSubsequent(binop->right(), binop->position());
    ConvertBinaryToNaryOperationSourceRange(binop, nary);
    *x = nary;
  } else if ((*x)->IsNaryOperation()) {
    nary = (*x)->AsNaryOperation();
    if (nary->op() != op) return false;
  } else {
    return false;
  }

  // Append our current expression to the nary operation.
  // TODO(leszeks): Do some literal collapsing here if we're appending Smi or
  // String literals.
  nary->AddSubsequent(y, pos);
  nary->clear_parenthesized();
  AppendNaryOperationSourceRange(nary, range);

  return true;
}

const AstRawString* Parser::GetBigIntAsSymbol() {
  base::Vector<const uint8_t> literal = scanner()->BigIntLiteral();
  if (literal[0] != '0' || literal.length() == 1) {
    return ast_value_factory()->GetOneByteString(literal);
  }
  std::unique_ptr<char[]> decimal =
      BigIntLiteralToDecimal(local_isolate_, literal);
  return ast_value_factory()->GetOneByteString(decimal.get());
}

Expression* Parser::BuildUnaryExpression(Expression* expression,
                                         Token::Value op, int pos) {
  DCHECK_NOT_NULL(expression);
  const Literal* literal = expression->AsLiteral();
  if (literal != nullptr) {
    if (op == Token::kNot) {
      // Convert the literal to a boolean condition and negate it.
      return factory()->NewBooleanLiteral(literal->ToBooleanIsFalse(), pos);
    } else if (literal->IsNumberLiteral()) {
      // Compute some expressions involving only number literals.
      double value = literal->AsNumber();
      switch (op) {
        case Token::kAdd:
          return expression;
        case Token::kSub:
          return factory()->NewNumberLiteral(-value, pos);
        case Token::kBitNot:
          return factory()->NewNumberLiteral(~DoubleToInt32(value), pos);
        default:
          break;
      }
    }
  }
  return factory()->NewUnaryOperation(op, expression, pos);
}

Expression* Parser::NewThrowError(Runtime::FunctionId id,
                                  MessageTemplate message,
                                  const AstRawString* arg, int pos) {
  ScopedPtrList<Expression> args(pointer_buffer());
  args.Add(factory()->NewSmiLiteral(static_cast<int>(message), pos));
  args.Add(factory()->NewStringLiteral(arg, pos));
  CallRuntime* call_constructor = factory()->NewCallRuntime(id, args, pos);
  return factory()->NewThrow(call_constructor, pos);
}

Expression* Parser::NewSuperPropertyReference(int pos) {
  const AstRawString* home_object_name;
  if (IsStatic(scope()->GetReceiverScope()->function_kind())) {
    home_object_name = ast_value_factory_->dot_static_home_object_string();
  } else {
    home_object_name = ast_value_factory_->dot_home_object_string();
  }

  VariableProxy* proxy = NewUnresolved(home_object_name, pos);
  proxy->set_is_home_object();
  return factory()->NewSuperPropertyReference(proxy, pos);
}

SuperCallReference* Parser::NewSuperCallReference(int pos) {
  VariableProxy* new_target_proxy =
      NewUnresolved(ast_value_factory()->new_target_string(), pos);
  VariableProxy* this_function_proxy =
      NewUnresolved(ast_value_factory()->this_function_string(), pos);
  return factory()->NewSuperCallReference(new_target_proxy, this_function_proxy,
                                          pos);
}

Expression* Parser::NewTargetExpression(int pos) {
  auto proxy = NewUnresolved(ast_value_factory()->new_target_string(), pos);
  proxy->set_is_new_target();
  return proxy;
}

Expression* Parser::ImportMetaExpression(int pos) {
  ScopedPtrList<Expression> args(pointer_buffer());
  if (!has_module_in_scope_chain()) {
    DCHECK(IsParsingWhileDebugging());
    // When debugging, we permit import.meta invocations -- however, they will
    // never produce a non-undefined result outside of a module.
    return factory()->NewUndefinedLiteral(pos);
  }
  return factory()->NewCallRuntime(Runtime::kInlineGetImportMetaObject, args,
                                   pos);
}

Expression* Parser::ExpressionFromLiteral(Token::Value token, int pos) {
  switch (token) {
    case Token::kNullLiteral:
      return factory()->NewNullLiteral(pos);
    case Token::kTrueLiteral:
      return factory()->NewBooleanLiteral(true, pos);
    case Token::kFalseLiteral:
      return factory()->NewBooleanLiteral(false, pos);
    case Token::kSmi: {
      uint32_t value = scanner()->smi_value();
      return factory()->NewSmiLiteral(value, pos);
    }
    case Token::kNumber: {
      double value = scanner()->DoubleValue();
      return factory()->NewNumberLiteral(value, pos);
    }
    case Token::kBigInt:
      return factory()->NewBigIntLiteral(
          AstBigInt(scanner()->CurrentLiteralAsCString(zone())), pos);
    case Token::kString: {
      return factory()->NewStringLiteral(GetSymbol(), pos);
    }
    default:
      DCHECK(false);
  }
  return FailureExpression();
}

Expression* Parser::NewV8Intrinsic(const AstRawString* name,
                                   const ScopedPtrList<Expression>& args,
                                   int pos) {
  if (ParsingExtension()) {
    // The extension structures are only accessible while parsing the
    // very first time, not when reparsing because of lazy compilation.
    GetClosureScope()->ForceEagerCompilation();
  }

  if (!name->is_one_byte()) {
    // There are no two-byte named intrinsics.
    ReportMessage(MessageTemplate::kNotDefined, name);
    return FailureExpression();
  }

  const Runtime::Function* function =
      Runtime::FunctionForName(name->raw_data(), name->length());

  // Be more permissive when fuzzing. Intrinsics are not supported.
  if (v8_flags.fuzzing) {
    return NewV8RuntimeFunctionForFuzzing(function, args, pos);
  }

  if (function == nullptr) {
    ReportMessage(MessageTemplate::kNotDefined, name);
    return FailureExpression();
  }

  // Check that the expected number of arguments are being passed.
  if (function->nargs != -1 && function->nargs != args.length()) {
    ReportMessage(MessageTemplate::kRuntimeWrongNumArgs);
    return FailureExpression();
  }

  return factory()->NewCallRuntime(function, args, pos);
}

// More permissive runtime-function creation on fuzzers.
Expression* Parser::NewV8RuntimeFunctionForFuzzing(
    const Runtime::Function* function, const ScopedPtrList<Expression>& args,
    int pos) {
  CHECK(v8_flags.fuzzing);

  // Intrinsics are not supported for fuzzing. Only allow runtime functions
  // marked as fuzzing-safe. Also prevent later errors due to too few arguments
  // and just ignore this call.
  if (function == nullptr ||
      !Runtime::IsEnabledForFuzzing(function->function_id) ||
      function->nargs > args.length()) {
    return factory()->NewUndefinedLiteral(kNoSourcePosition);
  }

  // Flexible number of arguments permitted.
  if (function->nargs == -1) {
    return factory()->NewCallRuntime(function, args, pos);
  }

  // Otherwise ignore superfluous arguments.
  ScopedPtrList<Expression> permissive_args(pointer_buffer());
  for (int i = 0; i < function->nargs; i++) {
    permissive_args.Add(args.at(i));
  }
  return factory()->NewCallRuntime(function, permissive_args, pos);
}

Parser::Parser(LocalIsolate* local_isolate, ParseInfo* info)
    : ParserBase<Parser>(
          info->zone(), &scanner_, info->stack_limit(),
          info->ast_value_factory(), info->pending_error_handler(),
          info->runtime_call_stats(), info->v8_file_logger(), info->flags(),
          true, info->flags().compile_hints_magic_enabled()),
      local_isolate_(local_isolate),
      info_(info),
      scanner_(info->character_stream(), flags()),
      preparser_zone_(info->zone()->allocator(), "pre-parser-zone"),
      reusable_preparser_(nullptr),
      mode_(PARSE_EAGERLY),  // Lazy mode must be set explicitly.
      source_range_map_(info->source_range_map()),
      total_preparse_skipped_(0),
      consumed_preparse_data_(info->consumed_preparse_data()),
      preparse_data_buffer_(),
      parameters_end_pos_(info->parameters_end_pos()) {
  // Even though we were passed ParseInfo, we should not store it in
  // Parser - this makes sure that Isolate is not accidentally accessed via
  // ParseInfo during background parsing.
  DCHECK_NOT_NULL(info->character_stream());
  // Determine if functions can be lazily compiled. This is necessary to
  // allow some of our builtin JS files to be lazily compiled. These
  // builtins cannot be handled lazily by the parser, since we have to know
  // if a function uses the special natives syntax, which is something the
  // parser records.
  // If the debugger requests compilation for break points, we cannot be
  // aggressive about lazy compilation, because it might trigger compilation
  // of functions without an outer context when setting a breakpoint through
  // Debug::FindSharedFunctionInfoInScript
  // We also compile eagerly for kProduceExhaustiveCodeCache.
  bool can_compile_lazily = flags().allow_lazy_compile() && !flags().is_eager();

  set_default_eager_compile_hint(can_compile_lazily
                                     ? FunctionLiteral::kShouldLazyCompile
                                     : FunctionLiteral::kShouldEagerCompile);
  allow_lazy_ = flags().allow_lazy_compile() && flags().allow_lazy_parsing() &&
                info->extension() == nullptr && can_compile_lazily;
  for (int feature = 0; feature < v8::Isolate::kUseCounterFeatureCount;
       ++feature) {
    use_counts_[feature] = 0;
  }
}

void Parser::InitializeEmptyScopeChain(ParseInfo* info) {
  DCHECK_NULL(original_scope_);
  DCHECK_NULL(info->script_scope());
  DeclarationScope* script_scope =
      NewScriptScope(flags().is_repl_mode() ? REPLMode::kYes : REPLMode::kNo);
  info->set_script_scope(script_scope);
  original_scope_ = script_scope;
}

template <typename IsolateT>
void Parser::DeserializeScopeChain(
    IsolateT* isolate, ParseInfo* info,
    MaybeHandle<ScopeInfo> maybe_outer_scope_info,
    Scope::DeserializationMode mode) {
  InitializeEmptyScopeChain(info);
  Handle<ScopeInfo> outer_scope_info;
  if (maybe_outer_scope_info.ToHandle(&outer_scope_info)) {
    DCHECK_EQ(ThreadId::Current(), isolate->thread_id());
    original_scope_ = Scope::DeserializeScopeChain(
        isolate, zone(), *outer_scope_info, info->script_scope(),
        ast_value_factory(), mode, info);

    DeclarationScope* receiver_scope = original_scope_->GetReceiverScope();
    if (receiver_scope->HasReceiverToDeserialize()) {
      receiver_scope->DeserializeReceiver(ast_value_factory());
    }
    if (info->has_module_in_scope_chain()) {
      set_has_module_in_scope_chain();
    }
  }
}

template void Parser::DeserializeScopeChain(
    Isolate* isolate, ParseInfo* info,
    MaybeHandle<ScopeInfo> maybe_outer_scope_info,
    Scope::DeserializationMode mode);
template void Parser::DeserializeScopeChain(
    LocalIsolate* isolate, ParseInfo* info,
    MaybeHandle<ScopeInfo> maybe_outer_scope_info,
    Scope::DeserializationMode mode);

namespace {

void MaybeProcessSourceRanges(ParseInfo* parse_info, Expression* root,
                              uintptr_t stack_limit_) {
  if (parse_info->source_range_map() != nullptr) {
    SourceRangeAstVisitor visitor(stack_limit_, root,
                                  parse_info->source_range_map());
    visitor.Run();
  }
}

}  // namespace

void Parser::ParseProgram(Isolate* isolate, DirectHandle<Script> script,
                          ParseInfo* info,
                          MaybeHandle<ScopeInfo> maybe_outer_scope_info) {
  DCHECK_EQ(script->id(), flags().script_id());

  // It's OK to use the Isolate & counters here, since this function is only
  // called in the main thread.
  DCHECK(parsing_on_main_thread_);
  RCS_SCOPE(runtime_call_stats_, flags().is_eval()
                                     ? RuntimeCallCounterId::kParseEval
                                     : RuntimeCallCounterId::kParseProgram);
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"), "V8.ParseProgram");
  base::ElapsedTimer timer;
  if (V8_UNLIKELY(v8_flags.log_function_events)) timer.Start();

  // Initialize parser state.
  DeserializeScopeChain(isolate, info, maybe_outer_scope_info,
                        Scope::DeserializationMode::kIncludingVariables);

  DCHECK_EQ(script->is_wrapped(), info->is_wrapped_as_function());
  if (script->is_wrapped()) {
    maybe_wrapped_arguments_ = handle(script->wrapped_arguments(), isolate);
  }

  scanner_.Initialize();
  FunctionLiteral* result = DoParseProgram(isolate, info);
  HandleSourceURLComments(isolate, script);
  if (result == nullptr) return;
  MaybeProcessSourceRanges(info, result, stack_limit_);
  PostProcessParseResult(isolate, info, result);

  if (V8_UNLIKELY(v8_flags.log_function_events)) {
    double ms = timer.Elapsed().InMillisecondsF();
    const char* event_name = "parse-eval";
    int start = -1;
    int end = -1;
    if (!flags().is_eval()) {
      event_name = "parse-script";
      start = 0;
      end = Cast<String>(script->source())->length();
    }
    LOG(isolate,
        FunctionEvent(event_name, flags().script_id(), ms, start, end, "", 0));
  }
}

FunctionLiteral* Parser::DoParseProgram(Isolate* isolate, ParseInfo* info) {
  // Note that this function can be called from the main thread or from a
  // background thread. We should not access anything Isolate / heap dependent
  // via ParseInfo, and also not pass it forward. If not on the main thread
  // isolate will be nullptr.
  DCHECK_EQ(parsing_on_main_thread_, isolate != nullptr);
  DCHECK_NULL(scope_);

  ParsingModeScope mode(this, allow_lazy_ ? PARSE_LAZILY : PARSE_EAGERLY);
  ResetInfoId();

  FunctionLiteral* result = nullptr;
  {
    Scope* outer = original_scope_;
    DCHECK_NOT_NULL(outer);
    if (flags().is_eval()) {
      outer = NewEvalScope(outer);
    } else if (flags().is_module()) {
      DCHECK_EQ(outer, info->script_scope());
      outer = NewModuleScope(info->script_scope());
    }

    DeclarationScope* scope = outer->AsDeclarationScope();
    scope->set_start_position(0);

    FunctionState function_state(&function_state_, &scope_, scope);
    ScopedPtrList<Statement> body(pointer_buffer());
    int beg_pos = scanner()->location().beg_pos;
    if (flags().is_module()) {
      DCHECK(flags().is_module());

      PrepareGeneratorVariables();
      Expression* initial_yield = BuildInitialYield(
          kNoSourcePosition, FunctionKind::kGeneratorFunction);
      body.Add(
          factory()->NewExpressionStatement(initial_yield, kNoSourcePosition));
      ParseModuleItemList(&body);
      // Modules will always have an initial yield. If there are any
      // additional suspends, they are awaits, and we treat the module as a
      // ModuleWithTopLevelAwait.
      if (function_state.suspend_count() > 1) {
        scope->set_module_has_toplevel_await();
      }
      if (!has_error() &&
          !module()->Validate(this->scope()->AsModuleScope(),
                              pending_error_handler(), zone())) {
        scanner()->set_parser_error();
      }
    } else if (info->is_wrapped_as_function()) {
      DCHECK(parsing_on_main_thread_);
      ParseWrapped(isolate, info, &body, scope, zone());
    } else if (flags().is_repl_mode()) {
      ParseREPLProgram(info, &body, scope);
    } else {
      // Don't count the mode in the use counters--give the program a chance
      // to enable script-wide strict mode below.
      this->scope()->SetLanguageMode(info->language_mode());
      ParseStatementList(&body, Token::kEos);
    }

    // The parser will peek but not consume kEos.  Our scope logically goes all
    // the way to the kEos, though.
    scope->set_end_position(peek_position());

    if (is_strict(language_mode())) {
      CheckStrictOctalLiteral(beg_pos, end_position());
    }
    if (is_sloppy(language_mode())) {
      // TODO(littledan): Function bindings on the global object that modify
      // pre-existing bindings should be made writable, enumerable and
      // nonconfigurable if possible, whereas this code will leave attributes
      // unchanged if the property already exists.
      InsertSloppyBlockFunctionVarBindings(scope);
    }
    // Internalize the ast strings in the case of eval so we can check for
    // conflicting var declarations with outer scope-info-backed scopes.
    if (flags().is_eval()) {
      DCHECK(parsing_on_main_thread_);
      DCHECK(!isolate->main_thread_local_heap()->IsParked());
      info->ast_value_factory()->Internalize(isolate);
    }
    CheckConflictingVarDeclarations(scope);

    if (flags().parse_restriction() == ONLY_SINGLE_FUNCTION_LITERAL) {
      if (body.length() != 1 || !body.at(0)->IsExpressionStatement() ||
          !body.at(0)
               ->AsExpressionStatement()
               ->expression()
               ->IsFunctionLiteral()) {
        ReportMessage(MessageTemplate::kSingleFunctionLiteral);
      }
    }

    int parameter_count = 0;
    result = factory()->NewScriptOrEvalFunctionLiteral(
        scope, body, function_state.expected_property_count(), parameter_count);
    result->set_suspend_count(function_state.suspend_count());
  }

  info->set_max_info_id(GetLastInfoId());

  if (has_error()) return nullptr;

  RecordFunctionLiteralSourceRange(result);

  return result;
}

template <typename IsolateT>
void Parser::PostProcessParseResult(IsolateT* isolate, ParseInfo* info,
                                    FunctionLiteral* literal) {
  DCHECK_NOT_NULL(literal);

  info->set_literal(literal);
  info->set_language_mode(literal->language_mode());
  if (info->flags().is_eval()) {
    info->set_allow_eval_cache(allow_eval_cache());
  }

  info->ast_value_factory()->Internalize(isolate);

  {
    RCS_SCOPE(info->runtime_call_stats(), RuntimeCallCounterId::kCompileAnalyse,
              RuntimeCallStats::k
"""


```