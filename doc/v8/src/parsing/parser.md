Response: The user wants a summary of the functionality of the C++ code in `v8/src/parsing/parser.cc`. I need to identify the main responsibilities of this file within the V8 JavaScript engine. Since the prompt mentions a connection to JavaScript, I should also provide a JavaScript example illustrating the file's role.

Based on the code, the file appears to be responsible for:

1. **Parsing JavaScript code:** This is evident from the numerous parsing functions like `ParseProgram`, `DoParseProgram`, `ParseFunction`, `DoParseFunction`, `ParseStatementList`, etc. It involves tokenizing the input and building an Abstract Syntax Tree (AST).
2. **Handling different JavaScript constructs:** The code includes logic for various language features like functions, classes, modules, imports, exports, literals, operators, etc.
3. **Creating AST nodes:** The code frequently uses `factory()->New...` to create AST nodes, indicating its role in building the tree representation of the parsed code.
4. **Managing scopes:**  Functions like `NewFunctionScope`, `NewScriptScope`, and the use of `DeclarationScope` suggest that the parser is responsible for managing the scope of variables and functions.
5. **Error reporting:**  The `ReportMessageAt` and `ReportUnexpectedTokenAt` functions indicate that the parser handles syntax errors.
6. **Handling different parsing modes:** The presence of `PARSE_EAGERLY` and `PARSE_LAZILY` suggests the parser supports different strategies for parsing.
7. **Supporting module features:** The code includes functions like `ParseModuleItem`, `ParseImportDeclaration`, and `ParseExportDeclaration`, highlighting its role in parsing JavaScript modules.
8. **Supporting class features:**  Functions like `DefaultConstructor`, `MakeAutoAccessorGetter`, `MakeAutoAccessorSetter`, and `ParseClassLiteralBody` demonstrate its handling of JavaScript classes.

A simple JavaScript example that demonstrates the parser's work would be parsing a function declaration:

```javascript
function add(a, b) {
  return a + b;
}
```

The `parser.cc` file would take this code as input, tokenize it (identifying `function`, `add`, `(`, `a`, `,`, `b`, `)`, `{`, `return`, `a`, `+`, `b`, `}`, etc.), and then construct an AST representing this function. This AST would contain nodes for the function declaration, parameters, return statement, and the binary addition expression.
这个C++源代码文件 `v8/src/parsing/parser.cc` 的主要功能是 **解析 JavaScript 源代码并构建抽象语法树 (AST)**。

更具体地说，它负责以下几个方面：

1. **词法分析的驱动和管理**:  虽然词法分析本身由 `scanner.cc` 完成，但 `parser.cc` 会使用 `Scanner` 类来获取 tokens，并根据这些 tokens 来构建语法结构。
2. **语法分析**: 这是文件的核心功能。它实现了 JavaScript 语法的分析规则，将 tokens 组织成符合 JavaScript 语法结构的 AST 节点。这包括处理各种 JavaScript 语法结构，例如：
    * 函数声明和表达式
    * 类声明和表达式
    * 模块的导入和导出
    * 各种类型的语句（例如 `if`, `for`, `while`, `try`, `return` 等）
    * 表达式（例如算术运算、逻辑运算、赋值等）
    * 字面量（例如数字、字符串、布尔值、null）
3. **作用域管理**:  `Parser` 类维护着当前的作用域信息，用于处理变量的声明和引用。它会创建不同类型的作用域，例如函数作用域、块级作用域、模块作用域等。
4. **错误处理**:  当解析过程中遇到不符合 JavaScript 语法规则的情况时，`Parser` 类会报告错误。
5. **辅助功能的提供**:  文件中包含一些辅助函数，用于创建特定的 AST 节点，例如默认构造函数、自动访问器等。
6. **支持不同的解析模式**: 文件中提到了 `PARSE_EAGERLY` 和 `PARSE_LAZILY`，表明 Parser 支持不同的解析策略，例如立即解析和延迟解析。
7. **处理模块特性**:  代码中包含了处理 ES 模块导入 (`import`) 和导出 (`export`) 的逻辑。
8. **处理类特性**: 代码中包含了处理 ES 类的声明、构造函数、方法和访问器的逻辑。

**与 JavaScript 功能的关系及 JavaScript 示例**

`parser.cc` 文件是 V8 引擎将 JavaScript 源代码转换为可执行代码的关键步骤。它直接对应于 JavaScript 代码的理解和结构化表示。

**JavaScript 示例:**

假设有以下简单的 JavaScript 代码：

```javascript
function greet(name) {
  return "Hello, " + name + "!";
}

console.log(greet("World"));
```

当 V8 引擎执行这段代码时，`parser.cc` 文件会执行以下操作（简化描述）：

1. **词法分析**: `Scanner` 将代码分解成 tokens，例如 `function`, `greet`, `(`, `name`, `)`, `{`, `return`, `"Hello, "`, `+`, `name`, `+`, `"!"`, `}`, `console`, `.`, `log`, `(`, `greet`, `(`, `"World"`, `)`, `)`, `;`。
2. **语法分析**: `Parser` 根据 JavaScript 的语法规则，将这些 tokens 组织成 AST 节点。例如：
    * 创建一个 `FunctionLiteral` 节点来表示 `greet` 函数。
    * 在 `FunctionLiteral` 节点下，创建一个 `Block` 节点来表示函数体。
    * 在 `Block` 节点下，创建一个 `ReturnStatement` 节点来表示 `return` 语句。
    * 在 `ReturnStatement` 节点下，创建一个 `BinaryOperation` 节点来表示字符串拼接操作。
    * 创建一个 `Call` 节点来表示 `console.log(greet("World"))`。
3. **作用域管理**: `Parser` 会为 `greet` 函数创建一个函数作用域，并将参数 `name` 添加到该作用域中。

**简而言之，`parser.cc` 的功能是将人类可读的 JavaScript 代码转换成 V8 引擎可以理解和执行的结构化表示 (AST)。**  如果解析过程中出现语法错误，例如缺少分号或者使用了错误的关键字，`parser.cc` 会检测到并报告错误，阻止代码的执行。

### 提示词
```
这是目录为v8/src/parsing/parser.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
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
              RuntimeCallStats::kThreadSpecific);
    if (!Rewriter::Rewrite(info) || !DeclarationScope::Analyze(info)) {
      // Null out the literal to indicate that something failed.
      info->set_literal(nullptr);
      return;
    }
  }
}

template void Parser::PostProcessParseResult(Isolate* isolate, ParseInfo* info,
                                             FunctionLiteral* literal);
template void Parser::PostProcessParseResult(LocalIsolate* isolate,
                                             ParseInfo* info,
                                             FunctionLiteral* literal);

ZonePtrList<const AstRawString>* Parser::PrepareWrappedArguments(
    Isolate* isolate, ParseInfo* info, Zone* zone) {
  DCHECK(parsing_on_main_thread_);
  DCHECK_NOT_NULL(isolate);
  DirectHandle<FixedArray> arguments =
      maybe_wrapped_arguments_.ToHandleChecked();
  int arguments_length = arguments->length();
  ZonePtrList<const AstRawString>* arguments_for_wrapped_function =
      zone->New<ZonePtrList<const AstRawString>>(arguments_length, zone);
  for (int i = 0; i < arguments_length; i++) {
    const AstRawString* argument_string = ast_value_factory()->GetString(
        Cast<String>(arguments->get(i)),
        SharedStringAccessGuardIfNeeded(isolate));
    arguments_for_wrapped_function->Add(argument_string, zone);
  }
  return arguments_for_wrapped_function;
}

void Parser::ParseWrapped(Isolate* isolate, ParseInfo* info,
                          ScopedPtrList<Statement>* body,
                          DeclarationScope* outer_scope, Zone* zone) {
  DCHECK(parsing_on_main_thread_);
  DCHECK(info->is_wrapped_as_function());
  ParsingModeScope parsing_mode(this, PARSE_EAGERLY);

  // Set function and block state for the outer eval scope.
  DCHECK(outer_scope->is_eval_scope());
  FunctionState function_state(&function_state_, &scope_, outer_scope);

  const AstRawString* function_name = nullptr;
  Scanner::Location location(0, 0);

  ZonePtrList<const AstRawString>* arguments_for_wrapped_function =
      PrepareWrappedArguments(isolate, info, zone);

  FunctionLiteral* function_literal =
      ParseFunctionLiteral(function_name, location, kSkipFunctionNameCheck,
                           FunctionKind::kNormalFunction, kNoSourcePosition,
                           FunctionSyntaxKind::kWrapped, LanguageMode::kSloppy,
                           arguments_for_wrapped_function);

  Statement* return_statement =
      factory()->NewReturnStatement(function_literal, kNoSourcePosition);
  body->Add(return_statement);
}

void Parser::ParseREPLProgram(ParseInfo* info, ScopedPtrList<Statement>* body,
                              DeclarationScope* scope) {
  // REPL scripts are handled nearly the same way as the body of an async
  // function. The difference is the value used to resolve the async
  // promise.
  // For a REPL script this is the completion value of the
  // script instead of the expression of some "return" statement. The
  // completion value of the script is obtained by manually invoking
  // the {Rewriter} which will return a VariableProxy referencing the
  // result.
  DCHECK(flags().is_repl_mode());
  this->scope()->SetLanguageMode(info->language_mode());
  PrepareGeneratorVariables();

  BlockT block = impl()->NullBlock();
  {
    StatementListT statements(pointer_buffer());
    ParseStatementList(&statements, Token::kEos);
    block = factory()->NewBlock(true, statements);
  }

  if (has_error()) return;

  std::optional<VariableProxy*> maybe_result =
      Rewriter::RewriteBody(info, scope, block->statements());
  Expression* result_value =
      (maybe_result && *maybe_result)
          ? static_cast<Expression*>(*maybe_result)
          : factory()->NewUndefinedLiteral(kNoSourcePosition);
  Expression* wrapped_result_value = WrapREPLResult(result_value);
  block->statements()->Add(factory()->NewAsyncReturnStatement(
                               wrapped_result_value, kNoSourcePosition),
                           zone());
  body->Add(block);
}

Expression* Parser::WrapREPLResult(Expression* value) {
  // REPL scripts additionally wrap the ".result" variable in an
  // object literal:
  //
  //     return %_AsyncFunctionResolve(
  //               .generator_object, {__proto__: null, .repl_result: .result});
  //
  // Should ".result" be a resolved promise itself, the async return
  // would chain the promises and return the resolve value instead of
  // the promise.

  Literal* property_name = factory()->NewStringLiteral(
      ast_value_factory()->dot_repl_result_string(), kNoSourcePosition);
  ObjectLiteralProperty* property =
      factory()->NewObjectLiteralProperty(property_name, value, true);

  Literal* proto_name = factory()->NewStringLiteral(
      ast_value_factory()->proto_string(), kNoSourcePosition);
  ObjectLiteralProperty* prototype = factory()->NewObjectLiteralProperty(
      proto_name, factory()->NewNullLiteral(kNoSourcePosition), false);

  ScopedPtrList<ObjectLiteralProperty> properties(pointer_buffer());
  properties.Add(property);
  properties.Add(prototype);
  return factory()->NewObjectLiteral(properties, false, kNoSourcePosition,
                                     false);
}

void Parser::ParseFunction(Isolate* isolate, ParseInfo* info,
                           DirectHandle<SharedFunctionInfo> shared_info) {
  // It's OK to use the Isolate & counters here, since this function is only
  // called in the main thread.
  DCHECK(parsing_on_main_thread_);
  RCS_SCOPE(runtime_call_stats_, RuntimeCallCounterId::kParseFunction);
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"), "V8.ParseFunction");
  base::ElapsedTimer timer;
  if (V8_UNLIKELY(v8_flags.log_function_events)) timer.Start();

  MaybeHandle<ScopeInfo> maybe_outer_scope_info;
  if (shared_info->HasOuterScopeInfo()) {
    maybe_outer_scope_info = handle(shared_info->GetOuterScopeInfo(), isolate);
  }
  int start_position = shared_info->StartPosition();
  int end_position = shared_info->EndPosition();

  DeserializeScopeChain(isolate, info, maybe_outer_scope_info,
                        Scope::DeserializationMode::kIncludingVariables);
  DCHECK_EQ(factory()->zone(), info->zone());

  DirectHandle<Script> script(Cast<Script>(shared_info->script()), isolate);
  if (shared_info->is_wrapped()) {
    maybe_wrapped_arguments_ = handle(script->wrapped_arguments(), isolate);
  }

  int function_literal_id = shared_info->function_literal_id();

  // Initialize parser state.
  info->set_function_name(ast_value_factory()->GetString(
      shared_info->Name(), SharedStringAccessGuardIfNeeded(isolate)));
  scanner_.Initialize();

  FunctionKind function_kind = flags().function_kind();
  FunctionLiteral* result;
  if (V8_UNLIKELY(IsClassMembersInitializerFunction(function_kind))) {
    // Reparsing of class member initializer functions has to be handled
    // specially because they require reparsing of the whole class body,
    // function start/end positions correspond to the class literal body
    // positions.
    result = ParseClassForMemberInitialization(
        function_kind, start_position, function_literal_id, end_position,
        info->function_name());
    info->set_max_info_id(GetLastInfoId());
  } else if (V8_UNLIKELY(shared_info->private_name_lookup_skips_outer_class() &&
                         original_scope_->is_class_scope())) {
    // If the function skips the outer class and the outer scope is a class, the
    // function is in heritage position. Otherwise the function scope's skip bit
    // will be correctly inherited from the outer scope.
    ClassScope::HeritageParsingScope heritage(original_scope_->AsClassScope());
    result = DoParseFunction(isolate, info, start_position, end_position,
                             function_literal_id, info->function_name());
  } else {
    result = DoParseFunction(isolate, info, start_position, end_position,
                             function_literal_id, info->function_name());
  }
  if (result == nullptr) return;
  MaybeProcessSourceRanges(info, result, stack_limit_);
  PostProcessParseResult(isolate, info, result);
  if (V8_UNLIKELY(v8_flags.log_function_events)) {
    double ms = timer.Elapsed().InMillisecondsF();
    // We should already be internalized by now, so the debug name will be
    // available.
    DeclarationScope* function_scope = result->scope();
    std::unique_ptr<char[]> function_name = shared_info->DebugNameCStr();
    LOG(isolate,
        FunctionEvent("parse-function", flags().script_id(), ms,
                      function_scope->start_position(),
                      function_scope->end_position(), function_name.get(),
                      strlen(function_name.get())));
  }
}

FunctionLiteral* Parser::DoParseFunction(Isolate* isolate, ParseInfo* info,
                                         int start_position, int end_position,
                                         int function_literal_id,
                                         const AstRawString* raw_name) {
  DCHECK_EQ(parsing_on_main_thread_, isolate != nullptr);
  DCHECK_NOT_NULL(raw_name);
  DCHECK_NULL(scope_);

  DCHECK(ast_value_factory());
  fni_.PushEnclosingName(raw_name);

  ResetInfoId();
  DCHECK_LT(0, function_literal_id);
  SkipInfos(function_literal_id - 1);

  ParsingModeScope parsing_mode(this, PARSE_EAGERLY);

  // Place holder for the result.
  FunctionLiteral* result = nullptr;

  {
    // Parse the function literal.
    Scope* outer = original_scope_;
    DeclarationScope* outer_function = outer->GetClosureScope();
    DCHECK(outer);
    FunctionState function_state(&function_state_, &scope_, outer_function);
    BlockState block_state(&scope_, outer);
    DCHECK(is_sloppy(outer->language_mode()) ||
           is_strict(info->language_mode()));
    FunctionKind kind = flags().function_kind();
    DCHECK_IMPLIES(IsConciseMethod(kind) || IsAccessorFunction(kind),
                   flags().function_syntax_kind() ==
                       FunctionSyntaxKind::kAccessorOrMethod);

    if (IsArrowFunction(kind)) {
      if (IsAsyncFunction(kind)) {
        DCHECK(!scanner()->HasLineTerminatorAfterNext());
        if (!Check(Token::kAsync)) {
          CHECK(stack_overflow());
          return nullptr;
        }
        if (!(peek_any_identifier() || peek() == Token::kLeftParen)) {
          CHECK(stack_overflow());
          return nullptr;
        }
      }

      CHECK_EQ(function_literal_id, GetNextInfoId());

      // TODO(adamk): We should construct this scope from the ScopeInfo.
      DeclarationScope* scope = NewFunctionScope(kind);
      scope->set_has_checked_syntax(true);

      // This bit only needs to be explicitly set because we're
      // not passing the ScopeInfo to the Scope constructor.
      SetLanguageMode(scope, info->language_mode());

      scope->set_start_position(start_position);
      ParserFormalParameters formals(scope);
      {
        ParameterDeclarationParsingScope formals_scope(this);
        // Parsing patterns as variable reference expression creates
        // NewUnresolved references in current scope. Enter arrow function
        // scope for formal parameter parsing.
        BlockState inner_block_state(&scope_, scope);
        if (Check(Token::kLeftParen)) {
          // '(' StrictFormalParameters ')'
          ParseFormalParameterList(&formals);
          Expect(Token::kRightParen);
        } else {
          // BindingIdentifier
          ParameterParsingScope parameter_parsing_scope(impl(), &formals);
          ParseFormalParameter(&formals);
          DeclareFormalParameters(&formals);
        }
        formals.duplicate_loc = formals_scope.duplicate_location();
      }

      // It doesn't really matter what value we pass here for
      // could_be_immediately_invoked since we already introduced an eager
      // compilation scope above.
      bool could_be_immediately_invoked = false;
      Expression* expression = ParseArrowFunctionLiteral(
          formals, function_literal_id, could_be_immediately_invoked);
      // Scanning must end at the same position that was recorded
      // previously. If not, parsing has been interrupted due to a stack
      // overflow, at which point the partially parsed arrow function
      // concise body happens to be a valid expression. This is a problem
      // only for arrow functions with single expression bodies, since there
      // is no end token such as "}" for normal functions.
      if (scanner()->location().end_pos == end_position) {
        // The pre-parser saw an arrow function here, so the full parser
        // must produce a FunctionLiteral.
        DCHECK(expression->IsFunctionLiteral());
        result = expression->AsFunctionLiteral();
      }
    } else if (IsDefaultConstructor(kind)) {
      DCHECK_EQ(scope(), outer);
      result = DefaultConstructor(raw_name, IsDerivedConstructor(kind),
                                  start_position);
    } else {
      ZonePtrList<const AstRawString>* arguments_for_wrapped_function =
          info->is_wrapped_as_function()
              ? PrepareWrappedArguments(isolate, info, zone())
              : nullptr;
      result = ParseFunctionLiteral(
          raw_name, Scanner::Location::invalid(), kSkipFunctionNameCheck, kind,
          kNoSourcePosition, flags().function_syntax_kind(),
          info->language_mode(), arguments_for_wrapped_function);
    }

    if (has_error()) return nullptr;
    result->set_requires_instance_members_initializer(
        flags().requires_instance_members_initializer());
    result->set_class_scope_has_private_brand(
        flags().class_scope_has_private_brand());
    result->set_has_static_private_methods_or_accessors(
        flags().has_static_private_methods_or_accessors());
  }

  info->set_max_info_id(GetLastInfoId());

  DCHECK_IMPLIES(result, function_literal_id == result->function_literal_id());
  return result;
}

FunctionLiteral* Parser::ParseClassForMemberInitialization(
    FunctionKind initalizer_kind, int initializer_pos, int initializer_id,
    int initializer_end_pos, const AstRawString* class_name) {
  // When the function is a class members initializer function, we record the
  // source range of the entire class body as its positions in its SFI, so at
  // this point the scanner should be rewound to the position of the class
  // token.
  DCHECK_EQ(peek_position(), initializer_pos);
  // Insert a FunctionState with the closest outer Declaration scope
  DeclarationScope* nearest_decl_scope = original_scope_->GetDeclarationScope();
  DCHECK_NOT_NULL(nearest_decl_scope);
  FunctionState function_state(&function_state_, &scope_, nearest_decl_scope);

  // We will reindex the function literals later.
  ResetInfoId();
  SkipInfos(initializer_id - 1);

  // We preparse the class members that are not fields with initializers
  // in order to collect the function literal ids.
  ParsingModeScope mode(this, PARSE_LAZILY);

  ExpressionParsingScope no_expression_scope(impl());

  // Reparse the whole class body to build member initializer functions.
  FunctionLiteral* initializer;
  {
    bool is_anonymous = IsEmptyIdentifier(class_name);
    BlockState block_state(&scope_, original_scope_);
    RaiseLanguageMode(LanguageMode::kStrict);

    BlockState object_literal_scope_state(&object_literal_scope_, nullptr);

    ClassInfo class_info(this);
    class_info.is_anonymous = is_anonymous;

    // Create an arbitrary non-Null expression to indicate that the class
    // extends something. Doing so unconditionally is fine because:
    //  - the fact whether the class extends something affects parsing of
    //    'super' expressions which cause parse-time SyntaxError if the class
    //    is not a derived one. However, all such errors must have been
    //    reported during initial parse of the class declaration.
    //  - "extends" clause affects class constructor's FunctionKind, but here
    //    we are interested only in the member initializer functions and thus
    //    we can ignore the constructor function details.
    //
    // Given all the above we can simplify things and for the purpose of class
    // member initializers reparsing don't bother propagating the existence of
    // the "extends" clause through scope serialization/deserialization.
    class_info.extends = factory()->NewNullLiteral(kNoSourcePosition);

    // Note that we don't recheck class_name for strict-reserved words or eval
    // because all such checks have already been done during initial paring and
    // respective SyntaxErrors must have been thrown if necessary.

    // Class initializers don't care about position of the class token.
    int class_token_pos = kNoSourcePosition;

#ifdef DEBUG
    scope()->MarkReparsingForClassInitializer();
#endif

    ParseClassLiteralBody(class_info, class_name, class_token_pos, Token::kEos);

    if (initalizer_kind == FunctionKind::kClassMembersInitializerFunction) {
      DCHECK_EQ(class_info.instance_members_function_id, initializer_id);
      initializer = CreateInstanceMembersInitializer(class_name, &class_info);
    } else {
      DCHECK_EQ(class_info.static_elements_function_id, initializer_id);
      initializer = CreateStaticElementsInitializer(class_name, &class_info);
    }
    initializer->scope()->TakeUnresolvedReferencesFromParent();
  }

  if (has_error()) return nullptr;

  DCHECK(IsClassMembersInitializerFunction(initalizer_kind));

  no_expression_scope.ValidateExpression();

  DCHECK_EQ(initializer->kind(), initalizer_kind);
  DCHECK_EQ(initializer->function_literal_id(), initializer_id);
  DCHECK_EQ(initializer->end_position(), initializer_end_pos);

  return initializer;
}

Statement* Parser::ParseModuleItem() {
  // ecma262/#prod-ModuleItem
  // ModuleItem :
  //    ImportDeclaration
  //    ExportDeclaration
  //    StatementListItem

  Token::Value next = peek();

  if (next == Token::kExport) {
    return ParseExportDeclaration();
  }

  if (next == Token::kImport) {
    // We must be careful not to parse a dynamic import expression as an import
    // declaration. Same for import.meta expressions.
    Token::Value peek_ahead = PeekAhead();
    if (peek_ahead != Token::kLeftParen && peek_ahead != Token::kPeriod) {
      ParseImportDeclaration();
      return factory()->EmptyStatement();
    }
  }

  return ParseStatementListItem();
}

void Parser::ParseModuleItemList(ScopedPtrList<Statement>* body) {
  // ecma262/#prod-Module
  // Module :
  //    ModuleBody?
  //
  // ecma262/#prod-ModuleItemList
  // ModuleBody :
  //    ModuleItem*

  DCHECK(scope()->is_module_scope());
  while (peek() != Token::kEos) {
    Statement* stat = ParseModuleItem();
    if (stat == nullptr) return;
    if (stat->IsEmptyStatement()) continue;
    body->Add(stat);
  }
}

const AstRawString* Parser::ParseModuleSpecifier() {
  // ModuleSpecifier :
  //    StringLiteral

  Expect(Token::kString);
  return GetSymbol();
}

ZoneChunkList<Parser::ExportClauseData>* Parser::ParseExportClause(
    Scanner::Location* reserved_loc,
    Scanner::Location* string_literal_local_name_loc) {
  // ExportClause :
  //   '{' '}'
  //   '{' ExportsList '}'
  //   '{' ExportsList ',' '}'
  //
  // ExportsList :
  //   ExportSpecifier
  //   ExportsList ',' ExportSpecifier
  //
  // ExportSpecifier :
  //   IdentifierName
  //   IdentifierName 'as' IdentifierName
  //   IdentifierName 'as' ModuleExportName
  //   ModuleExportName
  //   ModuleExportName 'as' ModuleExportName
  //
  // ModuleExportName :
  //   StringLiteral
  ZoneChunkList<ExportClauseData>* export_data =
      zone()->New<ZoneChunkList<ExportClauseData>>(zone());

  Expect(Token::kLeftBrace);

  Token::Value name_tok;
  while ((name_tok = peek()) != Token::kRightBrace) {
    const AstRawString* local_name = ParseExportSpecifierName();
    if (!string_literal_local_name_loc->IsValid() &&
        name_tok == Token::kString) {
      // Keep track of the first string literal local name exported for error
      // reporting. These must be followed by a 'from' clause.
      *string_literal_local_name_loc = scanner()->location();
    } else if (!reserved_loc->IsValid() &&
               !Token::IsValidIdentifier(name_tok, LanguageMode::kStrict, false,
                                         flags().is_module())) {
      // Keep track of the first reserved word encountered in case our
      // caller needs to report an error.
      *reserved_loc = scanner()->location();
    }
    const AstRawString* export_name;
    Scanner::Location location = scanner()->location();
    if (CheckContextualKeyword(ast_value_factory()->as_string())) {
      export_name = ParseExportSpecifierName();
      // Set the location to the whole "a as b" string, so that it makes sense
      // both for errors due to "a" and for errors due to "b".
      location.end_pos = scanner()->location().end_pos;
    } else {
      export_name = local_name;
    }
    export_data->push_back({export_name, local_name, location});
    if (peek() == Token::kRightBrace) break;
    if (V8_UNLIKELY(!Check(Token::kComma))) {
      ReportUnexpectedToken(Next());
      break;
    }
  }

  Expect(Token::kRightBrace);
  return export_data;
}

const AstRawString* Parser::ParseExportSpecifierName() {
  Token::Value next = Next();

  // IdentifierName
  if (V8_LIKELY(Token::IsPropertyName(next))) {
    return GetSymbol();
  }

  // ModuleExportName
  if (next == Token::kString) {
    const AstRawString* export_name = GetSymbol();
    if (V8_LIKELY(export_name->is_one_byte())) return export_name;
    if (!unibrow::Utf16::HasUnpairedSurrogate(
            reinterpret_cast<const uint16_t*>(export_name->raw_data()),
            export_name->length())) {
      return export_name;
    }
    ReportMessage(MessageTemplate::kInvalidModuleExportName);
    return EmptyIdentifierString();
  }

  ReportUnexpectedToken(next);
  return EmptyIdentifierString();
}

ZonePtrList<const Parser::NamedImport>* Parser::ParseNamedImports(int pos) {
  // NamedImports :
  //   '{' '}'
  //   '{' ImportsList '}'
  //   '{' ImportsList ',' '}'
  //
  // ImportsList :
  //   ImportSpecifier
  //   ImportsList ',' ImportSpecifier
  //
  // ImportSpecifier :
  //   BindingIdentifier
  //   IdentifierName 'as' BindingIdentifier
  //   ModuleExportName 'as' BindingIdentifier

  Expect(Token::kLeftBrace);

  auto result = zone()->New<ZonePtrList<const NamedImport>>(1, zone());
  while (peek() != Token::kRightBrace) {
    const AstRawString* import_name = ParseExportSpecifierName();
    const AstRawString* local_name = import_name;
    Scanner::Location location = scanner()->location();
    // In the presence of 'as', the left-side of the 'as' can
    // be any IdentifierName. But without 'as', it must be a valid
    // BindingIdentifier.
    if (CheckContextualKeyword(ast_value_factory()->as_string())) {
      local_name = ParsePropertyName();
    }
    if (!Token::IsValidIdentifier(scanner()->current_token(),
                                  LanguageMode::kStrict, false,
                                  flags().is_module())) {
      ReportMessage(MessageTemplate::kUnexpectedReserved);
      return nullptr;
    } else if (IsEvalOrArguments(local_name)) {
      ReportMessage(MessageTemplate::kStrictEvalArguments);
      return nullptr;
    }

    DeclareUnboundVariable(local_name, VariableMode::kConst,
                           kNeedsInitialization, position());

    NamedImport* import =
        zone()->New<NamedImport>(import_name, local_name, location);
    result->Add(import, zone());

    if (peek() == Token::kRightBrace) break;
    Expect(Token::kComma);
  }

  Expect(Token::kRightBrace);
  return result;
}

ImportAttributes* Parser::ParseImportWithOrAssertClause() {
  // WithClause :
  //    with '{' '}'
  //    with '{' WithEntries ','? '}'

  // WithEntries :
  //    LiteralPropertyName
  //    LiteralPropertyName ':' StringLiteral , WithEntries

  auto import_attributes = zone()->New<ImportAttributes>(zone());

  if (v8_flags.harmony_import_attributes && Check(Token::kWith)) {
    // 'with' keyword consumed
  } else {
    return import_attributes;
  }

  Expect(Token::kLeftBrace);

  while (peek() != Token::kRightBrace) {
    const AstRawString* attribute_key =
        Check(Token::kString) ? GetSymbol() : ParsePropertyName();

    Scanner::Location location = scanner()->location();

    Expect(Token::kColon);
    Expect(Token::kString);

    const AstRawString* attribute_value = GetSymbol();

    // Set the location to the whole "key: 'value'"" string, so that it makes
    // sense both for errors due to the key and errors due to the value.
    location.end_pos = scanner()->location().end_pos;

    auto result = import_attributes->insert(std::make_pair(
        attribute_key, std::make_pair(attribute_value, location)));
    if (!result.second) {
      // It is a syntax error if two WithEntries have the same key.
      ReportMessageAt(location, MessageTemplate::kImportAttributesDuplicateKey,
                      attribute_key);
      break;
    }

    if (peek() == Token::kRightBrace) break;
    if (V8_UNLIKELY(!Check(Token::kComma))) {
      ReportUnexpectedToken(Next());
      break;
    }
  }

  Expect(Token::kRightBrace);

  return import_attributes;
}

void Parser::ParseImportDeclaration() {
  // ImportDeclaration :
  //   'import' ImportClause 'from' ModuleSpecifier ';'
  //   'import' ModuleSpecifier ';'
  //   'import' ImportClause 'from' ModuleSpecifier [no LineTerminator here]
  //       AssertClause ';'
  //   'import' ModuleSpecifier [no LineTerminator here] AssertClause';'
  //   'import' 'source' ImportedBinding 'from' ModuleSpecifier ';'
  //
  // ImportClause :
  //   ImportedDefaultBinding
  //   NameSpaceImport
  //   NamedImports
  //   ImportedDefaultBinding ',' NameSpaceImport
  //   ImportedDefaultBinding ',' NamedImports
  //
  // NameSpaceImport :
  //   '*' 'as' ImportedBinding

  int pos = peek_position();
  Expect(Token::kImport);

  Token::Value tok = peek();

  // 'import' ModuleSpecifier ';'
  if (tok == Token::kString) {
    Scanner::Location specifier_loc = scanner()->peek_location();
    const AstRawString* module_specifier = ParseModuleSpecifier();
    const ImportAttributes* import_attributes = ParseImportWithOrAssertClause();
    ExpectSemicolon();
    module()->AddEmptyImport(module_specifier, import_attributes, specifier_loc,
                             zone());
    return;
  }

  // Parse ImportedDefaultBinding or 'source' ImportedBinding if present.
  const AstRawString* import_default_binding = nullptr;
  Scanner::Location import_default_binding_loc;
  ModuleImportPhase import_phase = ModuleImportPhase::kEvaluation;
  if (tok != Token::kMul && tok != Token::kLeftBrace) {
    if (v8_flags.js_source_phase_imports &&
        PeekContextualKeyword(ast_value_factory()->source_string()) &&
        PeekAhead() == Token::kIdentifier &&
        PeekAheadAhead() == Token::kIdentifier) {
      Consume(Token::kIdentifier);
      import_phase = ModuleImportPhase::kSource;
    }
    import_default_binding = ParseNonRestrictedIdentifier();
    import_default_binding_loc = scanner()->location();
    DeclareUnboundVariable(import_default_binding, VariableMode::kConst,
                           kNeedsInitialization, pos);
  }

  // Parse NameSpaceImport or NamedImports if present.
  const AstRawString* module_namespace_binding = nullptr;
  Scanner::Location module_namespace_binding_loc;
  const ZonePtrList<const NamedImport>* named_imports = nullptr;
  if (import_phase == ModuleImportPhase::kEvaluation &&
      (import_default_binding == nullptr || Check(Token::kComma))) {
    switch (peek()) {
      case Token::kMul: {
        Consume(Token::kMul);
        ExpectContextualKeyword(ast_value_factory()->as_string());
        module_namespace_binding = ParseNonRestrictedIdentifier();
        module_namespace_binding_loc = scanner()->location();
        DeclareUnboundVariable(module_namespace_binding, VariableMode::kConst,
                               kCreatedInitialized, pos);
        break;
      }

      case Token::kLeftBrace:
        named_imports = ParseNamedImports(pos);
        break;

      default:
        ReportUnexpectedToken(scanner()->current_token());
        return;
    }
  }

  ExpectContextualKeyword(ast_value_factory()->from_string());
  Scanner::Location specifier_loc = scanner()->peek_location();
  const AstRawString* module_specifier = ParseModuleSpecifier();
  // TODO(42204365): Enable import attributes with source phase import once
  // specified.
  const ImportAttributes* import_attributes =
      import_phase == ModuleImportPhase::kEvaluation
          ? ParseImportWithOrAssertClause()
          : zone()->New<ImportAttributes>(zone());
  ExpectSemicolon();

  // Now that we have all the information, we can make the appropriate
  // declarations.

  // TODO(neis): Would prefer to call DeclareVariable for each case below rather
  // than above and in ParseNamedImports, but then a possible error message
  // would point to the wrong location.  Maybe have a DeclareAt version of
  // Declare that takes a location?

  if (module_namespace_binding != nullptr) {
    DCHECK_EQ(ModuleImportPhase::kEvaluation, import_phase);
    module()->AddStarImport(module_namespace_binding, module_specifier,
                            import_attributes, module_namespace_binding_loc,
                            specifier_loc, zone());
  }

  if (import_default_binding != nullptr) {
    DCHECK_IMPLIES(import_phase == ModuleImportPhase::kSource,
                   v8_flags.js_source_phase_imports);
    module()->AddImport(ast_value_factory()->default_string(),
                        import_default_binding, module_specifier, import_phase,
                        import_attributes, import_default_binding_loc,
                        specifier_loc, zone());
  }

  if (named_imports != nullptr) {
    DCHECK_EQ(ModuleImportPhase::kEvaluation, import_phase);
    if (named_imports->length() == 0) {
      module()->AddEmptyImport(module_specifier, import_attributes,
                               specifier_loc, zone());
    } else {
      for (const NamedImport* import : *named_imports) {
        module()->AddImport(import->import_name, import->local_name,
                            module_specifier, import_phase, import_attributes,
                            import->location, specifier_loc, zone());
      }
    }
  }
}

Statement* Parser::ParseExportDefault() {
  //  Supports the following productions, starting after the 'default' token:
  //    'export' 'default' HoistableDeclaration
  //    'export' 'default' ClassDeclaration
  //    'export' 'default' AssignmentExpression[In] ';'

  Expect(Token::kDefault);
  Scanner::Location default_loc = scanner()->location();

  ZonePtrList<const AstRawString> local_names(1, zone());
  Statement* result = nullptr;
  switch (peek()) {
    case Token::kFunction:
      result = ParseHoistableDeclaration(&local_names, true);
      break;

    case Token::kClass:
      Consume(Token::kClass);
      result = ParseClassDeclaration(&local_names, true);
      break;

    case Token::kAsync:
      if (PeekAhead() == Token::kFunction &&
          !scanner()->HasLineTerminatorAfterNext()) {
        Consume(Token::kAsync);
        result = ParseAsyncFunctionDeclaration(&local_names, true);
        break;
      }
      [[fallthrough]];

    default: {
      int pos = position();
      AcceptINScope scope(this, true);
      Expression* value = ParseAssignmentExpression();
      SetFunctionName(value, ast_value_factory()->default_string());

      const AstRawString* local_name =
          ast_value_factory()->dot_default_string();
      local_names.Add(local_name, zone());

      // It's fine to declare this as VariableMode::kConst because the user has
      // no way of writing to it.
      VariableProxy* proxy =
          DeclareBoundVariable(local_name, VariableMode::kConst, pos);
      proxy->var()->set_initializer_position(position());

      Assignment* assignment = factory()->NewAssignment(
          Token::kInit, proxy, value, kNoSourcePosition);
      result = IgnoreCompletion(
          factory()->NewExpressionStatement(assignment, kNoSourcePosition));

      ExpectSemicolon();
      break;
    }
  }

  if (result != nullptr) {
    DCHECK_EQ(local_names.length(), 1);
    module()->AddExport(local_names.first(),
                        ast_value_factory()->default_string(), default_loc,
                        zone());
  }

  return result;
}

const AstRawString* Parser::NextInternalNamespaceExportName() {
  const char* prefix = ".ns-export";
  std::string s(prefix);
  s.append(std::to_string(number_of_named_namespace_exports_++));
  return ast_value_factory()->GetOneByteString(s.c_str()
```