Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/torque/torque-parser.cc`. The request also includes several constraints and specific questions related to Torque, JavaScript, code logic, and potential errors.

Here's a breakdown of the thinking process:

1. **Identify the Core Functionality:** The filename `torque-parser.cc` and the included headers like `torque/ast.h`, `torque/declarations.h`, and `torque/earley-parser.h` strongly suggest that this file is responsible for parsing Torque code. The presence of `ParseResult`, `ParseResultIterator`, and many `Make...` functions further supports this.

2. **Analyze Key Structures:**  The code defines various structs like `ExpressionWithSource`, `TypeswitchCase`, and `EnumEntry`. These seem to represent intermediate data structures used during parsing. The `BuildFlags` class suggests the parser is aware of various build configurations.

3. **Focus on `Make...` Functions:** The numerous `Make...` functions are crucial. They take parsed components (likely from the Earley parser) and construct Abstract Syntax Tree (AST) nodes. This confirms the parsing role. Each `Make...` function corresponds to a specific Torque language construct (e.g., `MakeCall` for function calls, `MakeNewExpression` for object creation).

4. **Look for Connections to Torque Language Elements:** The names of the `Make...` functions and the arguments they take map directly to elements of a programming language:
    * `MakeCall`: Function calls with arguments and optional "otherwise" blocks (for non-throwing calls).
    * `MakeMethodCall`: Method calls (invoking a function on an object).
    * `MakeNewExpression`: Object creation.
    * `MakeBinaryOperator`, `MakeUnaryOperator`: Operators.
    * `MakeIntrinsicCallExpression`: Calls to intrinsic functions.
    * `MakeParameterList`: Defining function parameters.
    * `MakeAssertStatement`, `MakeDebugStatement`: Debugging and assertion mechanisms.
    * `MakeExternalMacro`, `MakeIntrinsicDeclaration`, `MakeTorqueMacroDeclaration`: Declarations of functions/macros with different characteristics (external, intrinsic, Torque-specific).
    * `MakeConstDeclaration`, `MakeExternConstDeclaration`: Constant declarations.
    * `MakeTypeAliasDeclaration`, `MakeAbstractTypeDeclaration`: Type declarations and aliases.
    * `MakeMethodDeclaration`: Method declarations within classes/structs.

5. **Consider the "If it ends in .tq..." constraint:** The prompt mentions `.tq` files. While this file is `.cc`, the parsing logic within it is specifically for the Torque language. This confirms the connection to Torque.

6. **Address the JavaScript relationship:**  Torque is used to generate C++ code for V8, which executes JavaScript. While this file *parses* Torque, it's indirectly related to JavaScript. The parsed Torque constructs often correspond to operations performed when running JavaScript code (e.g., function calls, object creation).

7. **Think about Code Logic and Assumptions:**  The `BuildFlags` class demonstrates conditional logic based on compilation flags. The naming convention checks (`IsLowerCamelCase`, `IsUpperCamelCase`, `IsValidNamespaceConstName`) imply assumptions about coding style. The "otherwise" clause in `MakeCall` suggests a way to handle non-throwing calls.

8. **Consider User Programming Errors:** The naming convention checks directly relate to potential programmer errors. Also, using `deferred` with block statements where it has no effect is flagged as a linting issue, indicating a possible misunderstanding of the language.

9. **Structure the Summary:** Organize the findings into a clear and concise summary, addressing each part of the prompt:
    * Core functionality (parsing Torque).
    * Connection to `.tq` files (parser for Torque language).
    * Relationship to JavaScript (indirect, Torque generates C++ for V8).
    * Code logic examples (build flags, naming conventions, "otherwise" clauses).
    * Common programming errors (naming conventions, ineffective `deferred`).

10. **Review and Refine:** Ensure the summary is accurate, addresses all constraints, and is easy to understand. For example, explicitly state that the file *parses* Torque and doesn't *execute* JavaScript directly.
好的，让我们来分析一下 `v8/src/torque/torque-parser.cc` 这个文件的功能。

**核心功能归纳：**

`v8/src/torque/torque-parser.cc` 是 V8 JavaScript 引擎中 Torque 语言的**语法解析器**的实现。它的主要功能是将 Torque 源代码（以 `.tq` 结尾的文件）转换成一种中间表示形式，通常是抽象语法树 (AST)。这个 AST 随后会被 Torque 编译器用于生成 C++ 代码，最终集成到 V8 引擎中。

**更详细的功能点：**

1. **读取 Torque 源代码:**  该文件中的代码负责接收 Torque 源代码作为输入。
2. **词法分析和语法分析:** 它会使用某种解析技术（从代码中引入的 `earley-parser.h` 来看，很可能是 Earley 算法）将输入的 Torque 代码分解成词法单元（tokens），并根据 Torque 语言的语法规则构建 AST。
3. **构建抽象语法树 (AST):**  解析器的核心任务是创建代表 Torque 代码结构的 AST 节点。代码中定义了许多 `Make...` 形式的函数（例如 `MakeCall`, `MakeNewExpression`, `MakeTorqueMacroDeclaration` 等），这些函数负责根据解析的结果创建不同类型的 AST 节点，例如函数调用、对象创建、宏声明等。这些 AST 节点的定义可以在 `src/torque/ast.h` 中找到。
4. **处理 Torque 语言的各种结构:**  解析器需要理解并处理 Torque 语言的各种语法结构，包括：
    * **声明 (Declarations):** 例如宏 (macros)、内置函数 (intrinsics)、类型别名 (type aliases)、抽象类型 (abstract types)、常量 (constants) 等。
    * **表达式 (Expressions):** 例如函数调用、方法调用、二元运算、一元运算、字面量等。
    * **语句 (Statements):** 例如断言 (assert)、调试语句 (debug)、返回语句 (return) 等。
    * **类型 (Types):** 解析类型表达式。
    * **泛型 (Generics):** 处理泛型参数。
    * **注解 (Annotations):** 解析和处理代码中的注解信息。
5. **进行初步的语义检查或提示 (Linting):**  代码中包含一些 `Lint` 函数的调用，这表明解析器在解析过程中可能会进行一些初步的语义检查，例如命名规范的检查。
6. **处理构建标志 (Build Flags):**  `BuildFlags` 类表明解析器能够识别和使用 V8 的构建标志，这允许 Torque 代码根据不同的构建配置有条件地编译。

**关于 `.tq` 文件：**

正如你所说，如果 `v8/src/torque/torque-parser.cc` 处理的源代码以 `.tq` 结尾，那么它就是 V8 Torque 的源代码文件。

**与 JavaScript 的关系以及示例：**

Torque 是一种用于编写 V8 内部代码的 DSL (领域特定语言)。它的主要目的是提供一种更安全、更易于管理的方式来编写性能关键的 V8 C++ 代码，例如内置函数 (built-in functions) 和运行时函数 (runtime functions)。

因此，`v8/src/torque/torque-parser.cc` 解析的 Torque 代码最终会生成 C++ 代码，这些 C++ 代码实现了 JavaScript 的各种功能。

**JavaScript 示例：**

假设在 Torque 中定义了一个名为 `StringAdd` 的宏，用于实现字符串连接操作。当 JavaScript 代码执行字符串连接时，V8 引擎可能会调用由 `StringAdd` 宏生成的 C++ 代码。

```javascript
let str1 = "hello";
let str2 = " world";
let result = str1 + str2; // 这个加法操作可能会触发 V8 内部调用 Torque 定义的 StringAdd 逻辑
console.log(result); // 输出 "hello world"
```

**代码逻辑推理（假设输入与输出）：**

**假设输入 (Torque 代码片段):**

```torque
macro Increment(i: int32): int32 {
  return i + 1;
}
```

**预期输出 (AST 的一部分，概念性表示):**

```
MacroDeclaration {
  name: Identifier("Increment"),
  parameters: [
    Parameter { name: Identifier("i"), type: BasicType("int32") }
  ],
  returnType: BasicType("int32"),
  body: BlockStatement {
    statements: [
      ReturnStatement {
        expression: BinaryOperation {
          operator: "+",
          left: IdentifierExpression("i"),
          right: IntegerLiteral(1)
        }
      }
    ]
  }
}
```

这个输出表示了解析器成功地将 Torque 宏声明转换成了一个包含名称、参数、返回类型和函数体的结构化表示。

**用户常见的编程错误 (在编写 Torque 代码时):**

1. **命名规范错误:** Torque 强制执行特定的命名规范（例如，宏名用 UpperCamelCase，参数用 lowerCamelCase）。如果用户违反了这些规范，解析器会报错。

   **Torque 错误示例:**

   ```torque
   macro increment_value(i: int32): int32 { // 错误：宏名应为 UpperCamelCase
     return i + 1;
   }
   ```

   解析器会产生类似 "Lint: Macro \"increment_value\" does not follow \"UpperCamelCase\" naming convention." 的错误信息。

2. **类型错误:**  在 Torque 中，类型是强校验的。如果用户传递了不兼容的类型，解析器或后续的编译器会报错。

   **Torque 错误示例:**

   ```torque
   macro PrintLength(s: String): int32 {
     return s; // 错误：尝试返回 String 类型，但声明返回 int32
   }
   ```

   编译器会报告类型不匹配的错误。

3. **使用了未定义的标识符:**  如果用户尝试使用未声明的变量、宏或类型，解析器会报错。

   **Torque 错误示例:**

   ```torque
   macro AddOne(i: int32): int32 {
     return i + j; // 错误：j 未定义
   }
   ```

   解析器会报告 `j` 未声明的错误。

**总结 `v8/src/torque/torque-parser.cc` 的功能 (第 1 部分):**

`v8/src/torque/torque-parser.cc` 的主要功能是作为 V8 JavaScript 引擎中 Torque 语言的**语法解析器**。它负责读取 `.tq` 结尾的 Torque 源代码，并将其转换成抽象语法树 (AST)，为后续的 Torque 编译过程提供结构化的表示。它还会进行初步的语义检查和命名规范的验证，帮助开发者尽早发现潜在的错误。该解析器理解 Torque 语言的各种声明、表达式、语句和类型，并能处理泛型和注解等特性。 它的工作是 V8 理解和执行 JavaScript 代码的关键步骤之一，因为 Torque 用于编写 V8 的核心功能。

### 提示词
```
这是目录为v8/src/torque/torque-parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/torque-parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/torque/torque-parser.h"

#include <algorithm>
#include <cctype>
#include <optional>
#include <set>
#include <stdexcept>
#include <unordered_map>

#include "include/v8config.h"
#include "src/common/globals.h"
#include "src/flags/flags.h"
#include "src/torque/ast.h"
#include "src/torque/constants.h"
#include "src/torque/declarations.h"
#include "src/torque/earley-parser.h"
#include "src/torque/global-context.h"
#include "src/torque/utils.h"

namespace v8::internal::torque {

using TypeList = std::vector<TypeExpression*>;

struct ExpressionWithSource {
  Expression* expression;
  std::string source;
};

struct TypeswitchCase {
  SourcePosition pos;
  std::optional<Identifier*> name;
  TypeExpression* type;
  Statement* block;
};

struct EnumEntry {
  Identifier* name;
  std::optional<TypeExpression*> type;
  std::optional<std::string> alias_entry;
};

class BuildFlags : public base::ContextualClass<BuildFlags> {
 public:
  BuildFlags() {
    build_flags_["V8_EXTERNAL_CODE_SPACE"] = V8_EXTERNAL_CODE_SPACE_BOOL;
    build_flags_["TAGGED_SIZE_8_BYTES"] = TargetArchitecture::TaggedSize() == 8;
#ifdef V8_INTL_SUPPORT
    build_flags_["V8_INTL_SUPPORT"] = true;
#else
    build_flags_["V8_INTL_SUPPORT"] = false;
#endif
    build_flags_["V8_ENABLE_SWISS_NAME_DICTIONARY"] =
        V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL;
#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
    build_flags_["V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS"] = true;
#else
    build_flags_["V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS"] = false;
#endif
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    build_flags_["V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA"] = true;
#else
    build_flags_["V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA"] = false;
#endif
    build_flags_["TRUE_FOR_TESTING"] = true;
    build_flags_["FALSE_FOR_TESTING"] = false;
#ifdef V8_SCRIPTORMODULE_LEGACY_LIFETIME
    build_flags_["V8_SCRIPTORMODULE_LEGACY_LIFETIME"] = true;
#else
    build_flags_["V8_SCRIPTORMODULE_LEGACY_LIFETIME"] = false;
#endif
#ifdef V8_ENABLE_WEBASSEMBLY
    build_flags_["V8_ENABLE_WEBASSEMBLY"] = true;
    build_flags_["V8_ENABLE_WASM_CODE_POINTER_TABLE"] =
        V8_ENABLE_WASM_CODE_POINTER_TABLE_BOOL;
    build_flags_["WASM_CODE_POINTER_NEEDS_PADDING"] =
        V8_ENABLE_WASM_CODE_POINTER_TABLE_BOOL &&
        TargetArchitecture::TaggedSize() == 8;
#else
    build_flags_["V8_ENABLE_WEBASSEMBLY"] = false;
#endif
    build_flags_["V8_ENABLE_SANDBOX"] = V8_ENABLE_SANDBOX_BOOL;
    build_flags_["V8_ENABLE_LEAPTIERING"] = V8_ENABLE_LEAPTIERING_BOOL;
    build_flags_["DEBUG"] = DEBUG_BOOL;
#ifdef V8_ENABLE_DRUMBRAKE
    build_flags_["V8_ENABLE_DRUMBRAKE"] = true;
#else
    build_flags_["V8_ENABLE_DRUMBRAKE"] = false;
#endif
  }
  static bool GetFlag(const std::string& name, const char* production) {
    auto it = Get().build_flags_.find(name);
    if (it == Get().build_flags_.end()) {
      ReportError("Unknown flag used in ", production, ": ", name,
                  ". Please add it to the list in BuildFlags.");
    }
    return it->second;
  }

 private:
  std::unordered_map<std::string, bool> build_flags_;
};

template <>
V8_EXPORT_PRIVATE const ParseResultTypeId ParseResultHolder<std::string>::id =
    ParseResultTypeId::kStdString;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId ParseResultHolder<bool>::id =
    ParseResultTypeId::kBool;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId ParseResultHolder<int32_t>::id =
    ParseResultTypeId::kInt32;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId ParseResultHolder<double>::id =
    ParseResultTypeId::kDouble;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<IntegerLiteral>::id = ParseResultTypeId::kIntegerLiteral;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::vector<std::string>>::id =
        ParseResultTypeId::kStdVectorOfString;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId ParseResultHolder<Declaration*>::id =
    ParseResultTypeId::kDeclarationPtr;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<TypeExpression*>::id =
        ParseResultTypeId::kTypeExpressionPtr;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::optional<TypeExpression*>>::id =
        ParseResultTypeId::kOptionalTypeExpressionPtr;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId ParseResultHolder<TryHandler*>::id =
    ParseResultTypeId::kTryHandlerPtr;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId ParseResultHolder<Expression*>::id =
    ParseResultTypeId::kExpressionPtr;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId ParseResultHolder<Identifier*>::id =
    ParseResultTypeId::kIdentifierPtr;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::optional<Identifier*>>::id =
        ParseResultTypeId::kOptionalIdentifierPtr;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId ParseResultHolder<Statement*>::id =
    ParseResultTypeId::kStatementPtr;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<NameAndTypeExpression>::id =
        ParseResultTypeId::kNameAndTypeExpression;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId ParseResultHolder<EnumEntry>::id =
    ParseResultTypeId::kEnumEntry;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::vector<EnumEntry>>::id =
        ParseResultTypeId::kStdVectorOfEnumEntry;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<NameAndExpression>::id =
        ParseResultTypeId::kNameAndExpression;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId ParseResultHolder<Annotation>::id =
    ParseResultTypeId::kAnnotation;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::vector<Annotation>>::id =
        ParseResultTypeId::kVectorOfAnnotation;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<AnnotationParameter>::id =
        ParseResultTypeId::kAnnotationParameter;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::optional<AnnotationParameter>>::id =
        ParseResultTypeId::kOptionalAnnotationParameter;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<ClassFieldExpression>::id =
        ParseResultTypeId::kClassFieldExpression;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<StructFieldExpression>::id =
        ParseResultTypeId::kStructFieldExpression;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<BitFieldDeclaration>::id =
        ParseResultTypeId::kBitFieldDeclaration;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::vector<NameAndTypeExpression>>::id =
        ParseResultTypeId::kStdVectorOfNameAndTypeExpression;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<ImplicitParameters>::id =
        ParseResultTypeId::kImplicitParameters;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::optional<ImplicitParameters>>::id =
        ParseResultTypeId::kOptionalImplicitParameters;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::vector<NameAndExpression>>::id =
        ParseResultTypeId::kStdVectorOfNameAndExpression;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::vector<ClassFieldExpression>>::id =
        ParseResultTypeId::kStdVectorOfClassFieldExpression;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::vector<StructFieldExpression>>::id =
        ParseResultTypeId::kStdVectorOfStructFieldExpression;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::vector<BitFieldDeclaration>>::id =
        ParseResultTypeId::kStdVectorOfBitFieldDeclaration;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<IncrementDecrementOperator>::id =
        ParseResultTypeId::kIncrementDecrementOperator;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::optional<std::string>>::id =
        ParseResultTypeId::kOptionalStdString;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::vector<Statement*>>::id =
        ParseResultTypeId::kStdVectorOfStatementPtr;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::vector<Declaration*>>::id =
        ParseResultTypeId::kStdVectorOfDeclarationPtr;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::vector<std::vector<Declaration*>>>::id =
        ParseResultTypeId::kStdVectorOfStdVectorOfDeclarationPtr;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::vector<Expression*>>::id =
        ParseResultTypeId::kStdVectorOfExpressionPtr;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<ExpressionWithSource>::id =
        ParseResultTypeId::kExpressionWithSource;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId ParseResultHolder<ParameterList>::id =
    ParseResultTypeId::kParameterList;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId ParseResultHolder<TypeList>::id =
    ParseResultTypeId::kTypeList;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::optional<TypeList>>::id =
        ParseResultTypeId::kOptionalTypeList;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId ParseResultHolder<LabelAndTypes>::id =
    ParseResultTypeId::kLabelAndTypes;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::vector<LabelAndTypes>>::id =
        ParseResultTypeId::kStdVectorOfLabelAndTypes;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::vector<TryHandler*>>::id =
        ParseResultTypeId::kStdVectorOfTryHandlerPtr;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::optional<Statement*>>::id =
        ParseResultTypeId::kOptionalStatementPtr;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::optional<Expression*>>::id =
        ParseResultTypeId::kOptionalExpressionPtr;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<TypeswitchCase>::id = ParseResultTypeId::kTypeswitchCase;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::vector<TypeswitchCase>>::id =
        ParseResultTypeId::kStdVectorOfTypeswitchCase;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::vector<Identifier*>>::id =
        ParseResultTypeId::kStdVectorOfIdentifierPtr;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<std::optional<ClassBody*>>::id =
        ParseResultTypeId::kOptionalClassBody;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<GenericParameter>::id =
        ParseResultTypeId::kGenericParameter;
template <>
V8_EXPORT_PRIVATE const ParseResultTypeId
    ParseResultHolder<GenericParameters>::id =
        ParseResultTypeId::kGenericParameters;

namespace {

bool ProcessIfAnnotation(ParseResultIterator* child_results);

std::optional<ParseResult> AddGlobalDeclarations(
    ParseResultIterator* child_results) {
  auto declarations = child_results->NextAs<std::vector<Declaration*>>();
  for (Declaration* declaration : declarations) {
    CurrentAst::Get().declarations().push_back(declaration);
  }
  return std::nullopt;
}

void NamingConventionError(const std::string& type, const std::string& name,
                           const std::string& convention,
                           SourcePosition pos = CurrentSourcePosition::Get()) {
  Lint(type, " \"", name, "\" does not follow \"", convention,
       "\" naming convention.")
      .Position(pos);
}

void NamingConventionError(const std::string& type, const Identifier* name,
                           const std::string& convention) {
  NamingConventionError(type, name->value, convention, name->pos);
}

void LintGenericParameters(const GenericParameters& parameters) {
  for (auto parameter : parameters) {
    if (!IsUpperCamelCase(parameter.name->value)) {
      NamingConventionError("Generic parameter", parameter.name,
                            "UpperCamelCase");
    }
  }
}

std::optional<ParseResult> ConcatList(ParseResultIterator* child_results) {
  auto list_of_lists =
      child_results->NextAs<std::vector<std::vector<Declaration*>>>();
  std::vector<Declaration*> result;
  for (auto& list : list_of_lists) {
    result.insert(result.end(), list.begin(), list.end());
  }
  return ParseResult{std::move(result)};
}

void CheckNotDeferredStatement(Statement* statement) {
  CurrentSourcePosition::Scope source_position(statement->pos);
  if (BlockStatement* block = BlockStatement::DynamicCast(statement)) {
    if (block->deferred) {
      Lint(
          "cannot use deferred with a statement block here, it will have no "
          "effect");
    }
  }
}

TypeExpression* AddConstexpr(TypeExpression* type) {
  BasicTypeExpression* basic = BasicTypeExpression::DynamicCast(type);
  if (!basic) Error("Unsupported extends clause.").Throw();
  return MakeNode<BasicTypeExpression>(
      basic->namespace_qualification,
      MakeNode<Identifier>(CONSTEXPR_TYPE_PREFIX + basic->name->value),
      basic->generic_arguments);
}

Expression* MakeCall(IdentifierExpression* callee,
                     std::optional<Expression*> target,
                     std::vector<Expression*> arguments,
                     const std::vector<Statement*>& otherwise) {
  std::vector<Identifier*> labels;

  // All IdentifierExpressions are treated as label names and can be directly
  // used as labels identifiers. All other statements in a call's otherwise
  // must create intermediate Labels for the otherwise's statement code.
  size_t label_id_count = 0;
  std::vector<TryHandler*> temp_labels;
  for (auto* statement : otherwise) {
    if (auto* e = ExpressionStatement::DynamicCast(statement)) {
      if (auto* id = IdentifierExpression::DynamicCast(e->expression)) {
        if (!id->generic_arguments.empty()) {
          ReportError("An otherwise label cannot have generic parameters");
        }
        labels.push_back(id->name);
        continue;
      }
    }
    auto label_name = std::string("__label") + std::to_string(label_id_count++);
    auto label_id = MakeNode<Identifier>(label_name);
    label_id->pos = SourcePosition::Invalid();
    labels.push_back(label_id);
    auto* handler =
        MakeNode<TryHandler>(TryHandler::HandlerKind::kLabel, label_id,
                             ParameterList::Empty(), statement);
    temp_labels.push_back(handler);
  }

  // Create nested try-label expression for all of the temporary Labels that
  // were created.
  Expression* result = nullptr;
  if (target) {
    result = MakeNode<CallMethodExpression>(
        *target, callee, std::move(arguments), std::move(labels));
  } else {
    result = MakeNode<CallExpression>(callee, std::move(arguments),
                                      std::move(labels));
  }

  for (auto* label : temp_labels) {
    result = MakeNode<TryLabelExpression>(result, label);
  }
  return result;
}

Expression* MakeCall(Identifier* callee,
                     const std::vector<TypeExpression*>& generic_arguments,
                     const std::vector<Expression*>& arguments,
                     const std::vector<Statement*>& otherwise) {
  return MakeCall(MakeNode<IdentifierExpression>(callee, generic_arguments),
                  std::nullopt, arguments, otherwise);
}

std::optional<ParseResult> MakeCall(ParseResultIterator* child_results) {
  auto callee = child_results->NextAs<Expression*>();
  auto args = child_results->NextAs<std::vector<Expression*>>();
  auto otherwise = child_results->NextAs<std::vector<Statement*>>();
  IdentifierExpression* target = IdentifierExpression::cast(callee);
  return ParseResult{
      MakeCall(target, std::nullopt, std::move(args), otherwise)};
}

std::optional<ParseResult> MakeMethodCall(ParseResultIterator* child_results) {
  auto this_arg = child_results->NextAs<Expression*>();
  auto callee = child_results->NextAs<Identifier*>();
  auto args = child_results->NextAs<std::vector<Expression*>>();
  auto otherwise = child_results->NextAs<std::vector<Statement*>>();
  return ParseResult{MakeCall(MakeNode<IdentifierExpression>(callee), this_arg,
                              std::move(args), otherwise)};
}

std::optional<ParseResult> MakeNewExpression(
    ParseResultIterator* child_results) {
  bool pretenured = child_results->NextAs<bool>();
  bool clear_padding = child_results->NextAs<bool>();

  auto type = child_results->NextAs<TypeExpression*>();
  auto initializers = child_results->NextAs<std::vector<NameAndExpression>>();

  Expression* result = MakeNode<NewExpression>(type, std::move(initializers),
                                               pretenured, clear_padding);
  return ParseResult{result};
}

std::optional<ParseResult> MakeBinaryOperator(
    ParseResultIterator* child_results) {
  auto left = child_results->NextAs<Expression*>();
  auto op = child_results->NextAs<Identifier*>();
  auto right = child_results->NextAs<Expression*>();
  return ParseResult{MakeCall(op, TypeList{},
                              std::vector<Expression*>{left, right},
                              std::vector<Statement*>{})};
}

std::optional<ParseResult> MakeIntrinsicCallExpression(
    ParseResultIterator* child_results) {
  auto callee = child_results->NextAs<Identifier*>();
  auto generic_arguments =
      child_results->NextAs<std::vector<TypeExpression*>>();
  auto args = child_results->NextAs<std::vector<Expression*>>();
  Expression* result = MakeNode<IntrinsicCallExpression>(
      callee, std::move(generic_arguments), std::move(args));
  return ParseResult{result};
}

std::optional<ParseResult> MakeUnaryOperator(
    ParseResultIterator* child_results) {
  auto op = child_results->NextAs<Identifier*>();
  auto e = child_results->NextAs<Expression*>();
  return ParseResult{MakeCall(op, TypeList{}, std::vector<Expression*>{e},
                              std::vector<Statement*>{})};
}

std::optional<ParseResult> MakeSpreadExpression(
    ParseResultIterator* child_results) {
  auto spreadee = child_results->NextAs<Expression*>();
  Expression* result = MakeNode<SpreadExpression>(spreadee);
  return ParseResult{result};
}

std::optional<ParseResult> MakeImplicitParameterList(
    ParseResultIterator* child_results) {
  auto kind = child_results->NextAs<Identifier*>();
  auto parameters = child_results->NextAs<std::vector<NameAndTypeExpression>>();
  return ParseResult{ImplicitParameters{kind, std::move(parameters)}};
}

void AddParameter(ParameterList* parameter_list,
                  const NameAndTypeExpression& param) {
  if (!IsLowerCamelCase(param.name->value)) {
    NamingConventionError("Parameter", param.name, "lowerCamelCase");
  }
  parameter_list->names.push_back(param.name);
  parameter_list->types.push_back(param.type);
}

template <bool has_varargs, bool has_explicit_parameter_names>
std::optional<ParseResult> MakeParameterList(
    ParseResultIterator* child_results) {
  auto implicit_params =
      child_results->NextAs<std::optional<ImplicitParameters>>();
  ParameterList result;
  result.has_varargs = has_varargs;
  result.implicit_count = 0;
  result.implicit_kind = ImplicitKind::kNoImplicit;
  if (implicit_params) {
    result.implicit_count = implicit_params->parameters.size();
    if (implicit_params->kind->value == "implicit") {
      result.implicit_kind = ImplicitKind::kImplicit;
    } else {
      DCHECK_EQ(implicit_params->kind->value, "js-implicit");
      result.implicit_kind = ImplicitKind::kJSImplicit;
    }
    result.implicit_kind_pos = implicit_params->kind->pos;
    for (NameAndTypeExpression& implicit_param : implicit_params->parameters) {
      AddParameter(&result, implicit_param);
    }
  }
  if (has_explicit_parameter_names) {
    auto explicit_params =
        child_results->NextAs<std::vector<NameAndTypeExpression>>();
    std::string arguments_variable = "";
    if (has_varargs) {
      arguments_variable = child_results->NextAs<std::string>();
    }
    for (NameAndTypeExpression& param : explicit_params) {
      AddParameter(&result, param);
    }
    result.arguments_variable = arguments_variable;
  } else {
    auto explicit_types = child_results->NextAs<TypeList>();
    for (auto* explicit_type : explicit_types) {
      result.types.push_back(explicit_type);
    }
  }
  return ParseResult{std::move(result)};
}

std::optional<ParseResult> MakeAssertStatement(
    ParseResultIterator* child_results) {
  auto kind_string = child_results->NextAs<Identifier*>()->value;
  auto expr_with_source = child_results->NextAs<ExpressionWithSource>();
  AssertStatement::AssertKind kind;
  if (kind_string == "dcheck") {
    kind = AssertStatement::AssertKind::kDcheck;
  } else if (kind_string == "check") {
    kind = AssertStatement::AssertKind::kCheck;
  } else if (kind_string == "sbxcheck") {
#ifdef V8_ENABLE_SANDBOX
    kind = AssertStatement::AssertKind::kSbxCheck;
#else
    kind = AssertStatement::AssertKind::kDcheck;
#endif  // V8_ENABLE_SANDBOX
  } else if (kind_string == "static_assert") {
    kind = AssertStatement::AssertKind::kStaticAssert;
  } else {
    UNREACHABLE();
  }
  Statement* result = MakeNode<AssertStatement>(
      kind, expr_with_source.expression, expr_with_source.source);
  return ParseResult{result};
}

std::optional<ParseResult> MakeDebugStatement(
    ParseResultIterator* child_results) {
  auto kind = child_results->NextAs<Identifier*>()->value;
  DCHECK(kind == "unreachable" || kind == "debug");
  Statement* result = MakeNode<DebugStatement>(
      kind == "unreachable" ? DebugStatement::Kind::kUnreachable
                            : DebugStatement::Kind::kDebug);
  return ParseResult{result};
}

std::optional<ParseResult> DeprecatedMakeVoidType(
    ParseResultIterator* child_results) {
  Error("Default void return types are deprecated. Add `: void`.");
  TypeExpression* result = MakeNode<BasicTypeExpression>(
      std::vector<std::string>{}, MakeNode<Identifier>("void"),
      std::vector<TypeExpression*>{});
  return ParseResult{result};
}

std::optional<ParseResult> MakeExternalMacro(
    ParseResultIterator* child_results) {
  auto transitioning = child_results->NextAs<bool>();
  auto operator_name = child_results->NextAs<std::optional<std::string>>();
  auto external_assembler_name =
      child_results->NextAs<std::optional<std::string>>();
  auto name = child_results->NextAs<Identifier*>();
  auto generic_parameters = child_results->NextAs<GenericParameters>();
  LintGenericParameters(generic_parameters);

  auto args = child_results->NextAs<ParameterList>();
  auto return_type = child_results->NextAs<TypeExpression*>();
  auto labels = child_results->NextAs<LabelAndTypesVector>();

  Declaration* result = MakeNode<ExternalMacroDeclaration>(
      transitioning,
      external_assembler_name ? *external_assembler_name : "CodeStubAssembler",
      name, operator_name, args, return_type, std::move(labels));
  if (!generic_parameters.empty()) {
    Error("External builtins cannot be generic.");
  }
  return ParseResult{result};
}

std::optional<ParseResult> MakeIntrinsicDeclaration(
    ParseResultIterator* child_results) {
  auto name = child_results->NextAs<Identifier*>();
  auto generic_parameters = child_results->NextAs<GenericParameters>();
  LintGenericParameters(generic_parameters);

  auto args = child_results->NextAs<ParameterList>();
  auto return_type = child_results->NextAs<TypeExpression*>();
  auto body = child_results->NextAs<std::optional<Statement*>>();
  CallableDeclaration* declaration;
  if (body) {
    declaration = MakeNode<TorqueMacroDeclaration>(
        false, name, std::optional<std::string>{}, args, return_type,
        LabelAndTypesVector{}, false, body);
  } else {
    declaration = MakeNode<IntrinsicDeclaration>(name, args, return_type);
  }
  Declaration* result = declaration;
  if (!generic_parameters.empty()) {
    result = MakeNode<GenericCallableDeclaration>(std::move(generic_parameters),
                                                  declaration);
  }
  return ParseResult{result};
}

namespace {
bool HasAnnotation(ParseResultIterator* child_results, const char* annotation,
                   const char* declaration) {
  auto annotations = child_results->NextAs<std::vector<Annotation>>();
  if (!annotations.empty()) {
    if (annotations.size() > 1 || annotations[0].name->value != annotation) {
      Error(declaration, " declarations only support a single ", annotation,
            " annotation");
    }
    return true;
  }
  return false;
}

bool HasExportAnnotation(ParseResultIterator* child_results,
                         const char* declaration) {
  return HasAnnotation(child_results, ANNOTATION_EXPORT, declaration);
}
}  // namespace

std::optional<ParseResult> MakeTorqueMacroDeclaration(
    ParseResultIterator* child_results) {
  bool export_to_csa = HasExportAnnotation(child_results, "macro");
  auto transitioning = child_results->NextAs<bool>();
  auto operator_name = child_results->NextAs<std::optional<std::string>>();
  auto name = child_results->NextAs<Identifier*>();
  if (!IsUpperCamelCase(name->value)) {
    NamingConventionError("Macro", name, "UpperCamelCase");
  }

  auto generic_parameters = child_results->NextAs<GenericParameters>();
  LintGenericParameters(generic_parameters);

  auto args = child_results->NextAs<ParameterList>();
  auto return_type = child_results->NextAs<TypeExpression*>();
  auto labels = child_results->NextAs<LabelAndTypesVector>();
  auto body = child_results->NextAs<std::optional<Statement*>>();
  CallableDeclaration* declaration = MakeNode<TorqueMacroDeclaration>(
      transitioning, name, operator_name, args, return_type, std::move(labels),
      export_to_csa, body);
  Declaration* result = declaration;
  if (generic_parameters.empty()) {
    if (!body) ReportError("A non-generic declaration needs a body.");
  } else {
    if (export_to_csa) ReportError("Cannot export generics to CSA.");
    result = MakeNode<GenericCallableDeclaration>(std::move(generic_parameters),
                                                  declaration);
  }
  return ParseResult{result};
}

std::optional<ParseResult> MakeConstDeclaration(
    ParseResultIterator* child_results) {
  auto name = child_results->NextAs<Identifier*>();
  if (!IsValidNamespaceConstName(name->value)) {
    NamingConventionError("Constant", name, "kUpperCamelCase");
  }

  auto type = child_results->NextAs<TypeExpression*>();
  auto expression = child_results->NextAs<Expression*>();
  Declaration* result = MakeNode<ConstDeclaration>(name, type, expression);
  return ParseResult{result};
}

std::optional<ParseResult> MakeExternConstDeclaration(
    ParseResultIterator* child_results) {
  auto name = child_results->NextAs<Identifier*>();
  auto type = child_results->NextAs<TypeExpression*>();
  auto literal = child_results->NextAs<std::string>();
  Declaration* result =
      MakeNode<ExternConstDeclaration>(name, type, std::move(literal));
  return ParseResult{result};
}

std::optional<ParseResult> MakeTypeAliasDeclaration(
    ParseResultIterator* child_results) {
  bool enabled = ProcessIfAnnotation(child_results);
  auto name = child_results->NextAs<Identifier*>();
  auto type = child_results->NextAs<TypeExpression*>();
  std::vector<Declaration*> result = {};
  if (enabled) result = {MakeNode<TypeAliasDeclaration>(name, type)};
  return ParseResult{std::move(result)};
}

std::optional<ParseResult> MakeAbstractTypeDeclaration(
    ParseResultIterator* child_results) {
  bool use_parent_type_checker = HasAnnotation(
      child_results, ANNOTATION_USE_PARENT_TYPE_CHECKER, "abstract type");
  auto transient = child_results->NextAs<bool>();
  auto name = child_results->NextAs<Identifier*>();
  if (!IsValidTypeName(name->value)) {
    NamingConventionError("Type", name, "UpperCamelCase");
  }
  auto generic_parameters = child_results->NextAs<GenericParameters>();
  auto extends = child_results->NextAs<std::optional<TypeExpression*>>();
  auto generates = child_results->NextAs<std::optional<std::string>>();
  AbstractTypeFlags flags(AbstractTypeFlag::kNone);
  if (transient) flags |= AbstractTypeFlag::kTransient;
  if (use_parent_type_checker) flags |= AbstractTypeFlag::kUseParentTypeChecker;
  TypeDeclaration* type_decl = MakeNode<AbstractTypeDeclaration>(
      name, flags, extends, std::move(generates));
  Declaration* decl = type_decl;
  if (!generic_parameters.empty()) {
    decl = MakeNode<GenericTypeDeclaration>(generic_parameters, type_decl);
  }

  auto constexpr_generates =
      child_results->NextAs<std::optional<std::string>>();
  std::vector<Declaration*> result{decl};

  if (constexpr_generates) {
    // Create a AbstractTypeDeclaration for the associated constexpr type.
    Identifier* constexpr_name =
        MakeNode<Identifier>(CONSTEXPR_TYPE_PREFIX + name->value);
    constexpr_name->pos = name->pos;

    std::optional<TypeExpression*> constexpr_extends;
    if (extends) {
      constexpr_extends = AddConstexpr(*extends);
    }
    TypeDeclaration* constexpr_decl = MakeNode<AbstractTypeDeclaration>(
        constexpr_name, flags | AbstractTypeFlag::kConstexpr, constexpr_extends,
        constexpr_generates);
    constexpr_decl->pos = name->pos;
    decl = constexpr_decl;
    if (!generic_parameters.empty()) {
      decl = MakeNode<GenericTypeDeclaration>(std::move(generic_parameters),
                                              constexpr_decl);
    }
    result.push_back(decl);
  }

  return ParseResult{std::move(result)};
}

std::optional<ParseResult> MakeMethodDeclaration(
    ParseResultIterator* child_results) {
  auto transitioning = child_results->NextAs<bool>();
  auto operator_name = child_results->NextAs<std::optional<std::string>>();
  auto name = child_results->NextAs<Identifier*>();
  if (!IsUpperCamelCase(name->value)) {
    NamingConventionError("Method", name, "UpperCamelCase");
  }

  auto args = child_results->NextAs<ParameterList>();
  auto return_type = child_results->NextAs<TypeExpression*>();
  auto labels = child_results->NextAs<LabelAndTypesVector>();
  auto body = child_results->NextAs<Statement*>();
  Declaration* result = MakeNode<TorqueMacroDeclaration>(
      transitioning, name, operator_name, args, return_type, std::move(labels),
      false, body);
  return ParseResult{result};
}

class AnnotationSet {
 public:
  AnnotationSet(ParseResultIterator* iter,
                const std::set<std::string>& allowed_without_param,
                const std::set<std::string>& allowed_with_param) {
    auto list = iter->NextAs<std::vector<Annotation>>();
    for (const Annotation& a : list) {
      if (a.param.has_value()) {
        if (allowed_with_param.find(a.name->value) ==
            allowed_with_param.end()) {
          const char* error_message =
              allowed_without_param.find(a.name->value) ==
                      allowed_without_param.end()
                  ? " is not allowed here"
                  : " cannot have parameter here";
          Lint("Annotation ", a.name->value, error_message)
              .Position(a.name->pos);
        }
        if (!map_.insert({a.name->value, {*a.param, a.name->pos}}).second) {
          Lint("Duplicate annotation ", a.name->value).Position(a.name->pos);
        }
      } else {
        if (allowed_without_param.find(a.name->value) ==
            allowed_without_param.end()) {
          const char* error_message =
              allowed_with_param.find(a.name->value) == allowed_with_param.end()
                  ? " is not allowed here"
                  : " requires a parameter here";
          Lint("Annotation ", a.name->value, error_message)
              .Position(a.name->pos);
        }
        if (!set_.insert(a.name->value).second) {
          Lint("Duplicate annotation ", a.name->value).Position(a.name->pos);
        }
      }
    }
  }

  bool Contains(const std::string& s) const {
    return set_.find(s) != set_.end();
  }
  std::optional<std::string> GetStringParam(const std::string& s) const {
    auto it = map_.find(s);
    if (it == map_.end()) {
      return {};
    }
    if (it->second.first.is_int) {
      Error("Annotation ", s, " requires a string parameter but has an int")
          .Position(it->second.second);
    }
    return it->second
```