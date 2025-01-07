Response:
Let's break down the thought process for analyzing the given C++ code snippet.

1. **Understanding the Request:** The request asks for the functionality of `v8/src/ast/ast.cc`, assuming it's the first part of a larger file. It also asks for specific considerations: if it were Torque, JavaScript examples, logical reasoning with inputs/outputs, common programming errors, and a final summary of the functionality.

2. **Initial Scan and Keywords:** I'd start by quickly scanning the code for recognizable keywords and patterns. Things that jump out are:

    * `#include`: Indicates dependencies on other V8 components. The included headers like `ast.h`, `prettyprinter.h`, `scopes.h`, `objects/*.h`, and `strings/string-stream.h` give strong hints about the file's purpose.
    * `namespace v8 { namespace internal {`: Confirms this is internal V8 code.
    * Class definitions like `AstNode`, `Expression`, `Literal`, `FunctionLiteral`, `ObjectLiteral`, `ArrayLiteral`, `VariableProxy`, `Assignment`, `BinaryOperation`, `CompareOperation`, `MaterializedLiteral`, etc. This is a core set of AST node types.
    * Macros like `RETURN_NODE`, `ITERATION_NODE_LIST`, `LITERAL_NODE_LIST`. These suggest a pattern-based way of handling different node types, likely related to a visitor pattern or similar.
    * Methods like `Print`, `AsIterationStatement`, `AsMaterializedLiteral`, `IsSmiLiteral`, `IsStringLiteral`, `ToBooleanIsTrue`, `BindTo`, `GetInferredName`, `ShouldEagerCompile`, `CalculateEmitStore`, `BuildBoilerplateDescription`, `IsFastCloningSupported`, `IsSimple`, `IsLiteralCompareUndefined`, etc. These method names clearly describe actions related to inspecting and manipulating AST nodes.
    * Comments like `// Copyright`, `// Implementation of other node functionality.`, and more specific comments within functions.

3. **Inferring Core Functionality:** Based on the class names, methods, and included headers, the primary function of this file is clearly **defining and implementing the Abstract Syntax Tree (AST) node structure for JavaScript code within the V8 engine**. It provides the building blocks for representing the parsed JavaScript code.

4. **Addressing Specific Requirements:**

    * **Torque:** The prompt explicitly asks about `.tq`. Since the file ends in `.cc`, it's standard C++. I'd state this clearly.
    * **JavaScript Relationship:**  The AST directly represents JavaScript code. To illustrate this, I need to connect AST node types to corresponding JavaScript syntax. For example:
        * `Literal` maps to JavaScript literals (numbers, strings, booleans, `null`, `undefined`).
        * `VariableProxy` maps to variable references.
        * `Assignment` maps to assignment expressions.
        * `FunctionLiteral` maps to function declarations/expressions.
        * `ObjectLiteral` and `ArrayLiteral` map to object and array literal syntax.
        I'd provide simple JavaScript examples and explain how they would be represented by the corresponding AST nodes.
    * **Code Logic Reasoning (Input/Output):**  Many of the methods are predicates (return `bool`). I can create hypothetical scenarios and trace the execution of these methods. For example, for `IsSmiLiteral`, an input of an AST node representing the number `5` would yield `true`, while an AST node representing `"hello"` would yield `false`. For methods like `CalculateEmitStore`, which modifies the state of `ObjectLiteral` properties, I can describe a hypothetical object literal and explain how the `emit_store` flags would be set.
    * **Common Programming Errors:** Since this is V8 internal code, the "users" are likely V8 developers or those working on related tooling. Common errors might involve:
        * Incorrectly assuming a node is of a specific type (e.g., expecting a `VariableProxy` but getting a `Literal`). The `As...` methods return `nullptr` for type mismatches.
        * Mishandling the properties of AST nodes.
        * Misunderstanding the purpose of different node types.
        I'd provide examples of such errors and how the code might prevent or detect them (e.g., through assertions or `nullptr` checks).
    * **Summary of Functionality:** This is the final consolidation of all the identified functions. I'd reiterate that it's about defining and implementing the AST, focusing on the core responsibilities.

5. **Structuring the Output:**  I'd organize the information according to the prompt's structure:

    * Introduction stating the file's likely purpose.
    * Explicitly address the `.tq` question.
    * Provide JavaScript examples for relevant AST node types.
    * Present logical reasoning with clear input/output scenarios for selected methods.
    * Illustrate common programming errors related to AST manipulation.
    * Conclude with a concise summary of the file's overall functionality.

6. **Refinement and Clarity:** After drafting the initial response, I would review it for clarity, accuracy, and completeness. Are the JavaScript examples easy to understand? Are the input/output scenarios clear? Is the language precise?

By following this structured approach, combining keyword analysis, understanding the domain (compiler internals and ASTs), and directly addressing each point in the prompt, I can generate a comprehensive and accurate description of the provided V8 source code.
好的，这是对 `v8/src/ast/ast.cc` 第一部分的分析和功能归纳。

**文件功能概述：**

`v8/src/ast/ast.cc` 文件是 V8 JavaScript 引擎中用于定义和操作抽象语法树 (AST) 节点的核心 C++ 代码文件。它实现了各种 AST 节点的具体行为和辅助方法，这些节点用于表示 JavaScript 代码的结构。

**详细功能列举：**

1. **AST 节点类的实现:**  该文件实现了 `ast.h` 中声明的各种 AST 节点类的方法。这些类代表了 JavaScript 语法中的不同元素，例如：
   - 表达式 (Expressions):  `Literal`, `VariableProxy`, `Assignment`, `BinaryOperation`, `CompareOperation`, `FunctionLiteral`, `ObjectLiteral`, `ArrayLiteral` 等。
   - 语句 (Statements): 虽然这段代码片段主要关注表达式相关的节点，但它也提供了 `AsIterationStatement` 这样的方法，暗示了对语句节点的支持。

2. **节点类型判断和转换:** 提供了多种方法来判断和转换 AST 节点的类型，例如：
   - `AsIterationStatement()`: 将节点尝试转换为迭代语句节点。
   - `AsMaterializedLiteral()`: 将节点尝试转换为物化字面量节点 (例如对象字面量，数组字面量)。
   - `IsSmiLiteral()`, `IsNumberLiteral()`, `IsStringLiteral()`, `IsNullLiteral()`, `IsBooleanLiteral()`, `IsUndefinedLiteral()` 等:  判断表达式是否为特定类型的字面量。

3. **字面量节点的特性判断:** 针对不同的字面量类型，提供了判断其特性的方法：
   - `IsPropertyName()`: 判断字面量是否可以用作属性名。
   - `ToBooleanIsTrue()`, `ToBooleanIsFalse()`: 判断字面量转换为布尔值的结果。
   - `IsCompileTimeValue()`: 判断表达式的值是否在编译时可以确定。

4. **变量代理 (VariableProxy) 的操作:**  `VariableProxy` 用于表示对变量的引用。该文件提供了：
   - `BindTo(Variable* var)`: 将 `VariableProxy` 绑定到实际的变量对象。
   - 判断变量是否已赋值 (`is_assigned()`) 和是否已解析 (`is_resolved()`).

5. **赋值 (Assignment) 表达式的处理:** 提供了 `Assignment` 类的构造函数，用于表示赋值操作。

6. **函数字面量 (FunctionLiteral) 的处理:**  `FunctionLiteral` 代表函数定义。该文件提供了：
   - `set_raw_inferred_name()` 和 `GetInferredName()`: 用于处理函数名推断。
   - `set_shared_function_info()`:  关联共享的函数信息。
   - `ShouldEagerCompile()`, `AllowsLazyCompilation()`:  与编译优化相关的判断。
   - `GetDebugName()`: 获取调试用的函数名。

7. **对象字面量 (ObjectLiteral) 的处理:**  `ObjectLiteral` 代表对象字面量定义。
   - `ObjectLiteralProperty` 类表示对象字面量中的属性。
   - `CalculateEmitStore()`:  一个关键的方法，用于确定是否需要为对象字面量的属性生成存储操作。这涉及到处理重复属性定义和访问器属性。
   - `ObjectLiteralBoilerplateBuilder`:  用于构建对象字面量的样板，优化对象字面量的创建过程。它涉及到计算标志位，确定属性的深度和类型，以及构建 `ObjectBoilerplateDescription`。

8. **数组字面量 (ArrayLiteral) 的处理:**
   - `ArrayLiteralBoilerplateBuilder`:  类似于对象字面量，用于构建数组字面量的样板，优化数组字面量的创建过程。它涉及到确定数组元素的类型 (`ElementsKind`)，以及构建 `ArrayBoilerplateDescription`。

9. **模板字面量 (TemplateObject) 的处理:** `GetTemplateObject` 结构体用于获取或构建模板字面量的描述信息。

10. **二元和比较操作的特定模式匹配:**  提供了针对特定二元运算和比较运算的模式匹配方法，例如：
    - `IsSmiLiteralOperation()`: 检查是否是对一个表达式和一个小的整数 (Smi) 字面量进行运算。
    - `IsLiteralStrictCompareBoolean()`: 检查是否将一个表达式与布尔字面量进行严格比较。
    - `IsLiteralCompareUndefined()`: 检查是否将一个表达式与 `undefined` 进行比较。

**关于文件类型和 JavaScript 功能的关系:**

- **文件类型:** 正如代码开头所示，这个文件是以 `.cc` 结尾的，因此它是 **C++ 源代码**，而不是 Torque 源代码 (`.tq`)。
- **JavaScript 功能关系:** `v8/src/ast/ast.cc` 中的代码直接关系到 JavaScript 代码的解析和表示。AST 是编译器将源代码转换为可执行代码的中间表示形式。

**JavaScript 举例说明:**

```javascript
// 字面量
const num = 10;         // Literal::kSmi
const str = "hello";    // Literal::kString
const bool = true;      // Literal::kBoolean
const nothing = null;   // Literal::kNull
const undef = undefined; // Literal::kUndefined

// 变量代理
let x = 5;
console.log(x);        // x 会被表示为一个 VariableProxy

// 赋值
y = x + 1;             // Assignment 节点，target 是 y 的 VariableProxy，value 是 BinaryOperation

// 函数字面量
function add(a, b) {   // FunctionLiteral 节点
  return a + b;
}

// 对象字面量
const obj = {          // ObjectLiteral 节点
  name: "Alice",      // ObjectLiteralProperty (CONSTANT)
  age: 30,            // ObjectLiteralProperty (CONSTANT)
  greet() {           // ObjectLiteralProperty (COMPUTED, 如果是简写方法)
    console.log("Hi");
  }
};

// 数组字面量
const arr = [1, 2, 3]; // ArrayLiteral 节点

// 模板字面量
const name = "Bob";
const greeting = `Hello, ${name}!`; // GetTemplateObject 用于处理模板
```

**代码逻辑推理和假设输入/输出:**

**示例 1: `Expression::IsSmiLiteral()`**

- **假设输入:**  一个 `Literal` 节点，其 `Literal::type()` 为 `Literal::kSmi`。
- **预期输出:** `true`

- **假设输入:** 一个 `Literal` 节点，其 `Literal::type()` 为 `Literal::kString`。
- **预期输出:** `false`

**示例 2: `ObjectLiteral::CalculateEmitStore()`**

- **假设输入:**  一个 `ObjectLiteral` 节点，其 `properties()` 包含以下属性（按顺序）：
  ```javascript
  { a: 1, b: 2, a: 3, get b() {} }
  ```
- **代码逻辑:**
  1. 遍历属性，从后向前。
  2. 遇到 `get b() {}`，`emit_store` 为 `true`。
  3. 遇到 `a: 3`，查找已有的 `a`，发现是 `a: 1`，由于不是访问器，将 `a: 1` 的 `emit_store` 设置为 `false`。
  4. 遇到 `b: 2`，查找已有的 `b`，发现是 `get b()`，由于是互补访问器，`emit_store` 保持 `true`。
  5. 遇到 `a: 1`，由于之前已被设置为 `false`，保持 `false`。
- **预期输出:**
  - `a: 1` 的 `emit_store` 为 `false`
  - `b: 2` 的 `emit_store` 为 `true`
  - `a: 3` 的 `emit_store` 为 `true`
  - `get b()` 的 `emit_store` 为 `true`

**用户常见的编程错误示例:**

1. **类型假设错误:**  在编写操作 AST 的代码时，可能会错误地假设一个表达式总是某种类型。例如，假设一个属性的值总是 `Literal` 节点，但实际上它可能是一个更复杂的表达式。
   ```c++
   // 假设 property->value() 总是 Literal*
   Literal* lit = property->value()->AsLiteral();
   if (lit->type() == Literal::kNumber) {
       // ...
   }
   ```
   **错误:** 如果 `property->value()` 是一个 `BinaryOperation`，`AsLiteral()` 将返回 `nullptr`，导致空指针解引用或未定义的行为。
   **正确做法:**  在使用 `As...()` 方法前检查返回值是否为 `nullptr`。

2. **忘记处理所有可能的节点类型:**  在编写处理 AST 节点的逻辑时，可能会遗漏某些节点类型，导致某些 JavaScript 语法结构未被正确处理。例如，在处理表达式时，只考虑了字面量和变量，而忘记了处理函数调用或二元运算。

3. **错误地修改 AST 结构:**  在某些情况下，开发者可能需要修改 AST。但是，不小心地修改 AST 的结构可能会导致后续的编译或执行阶段出现错误。例如，错误地删除或移动一个节点可能会破坏程序的逻辑。

**功能归纳（针对第 1 部分）：**

`v8/src/ast/ast.cc` 的第一部分主要负责 **定义和实现 JavaScript 抽象语法树 (AST) 中各种表达式节点的核心功能**。它提供了创建、检查、转换和操作这些节点的方法，特别是针对字面量、变量、赋值、函数和对象/数组字面量等表达式。 此外，它还包含了用于优化对象和数组字面量创建的样板构建逻辑，以及一些针对特定语法模式的匹配方法。  这段代码是 V8 引擎理解和处理 JavaScript 代码结构的基础。

请提供第 2 部分的内容，以便进行更全面的分析。

Prompt: 
```
这是目录为v8/src/ast/ast.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ast/ast.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/ast/ast.h"

#include <cmath>  // For isfinite.
#include <vector>

#include "src/ast/prettyprinter.h"
#include "src/ast/scopes.h"
#include "src/base/hashmap.h"
#include "src/base/logging.h"
#include "src/base/numbers/double.h"
#include "src/builtins/builtins-constructor.h"
#include "src/builtins/builtins.h"
#include "src/common/assert-scope.h"
#include "src/heap/local-factory-inl.h"
#include "src/numbers/conversions-inl.h"
#include "src/objects/contexts.h"
#include "src/objects/elements-kind.h"
#include "src/objects/elements.h"
#include "src/objects/fixed-array.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/literal-objects.h"
#include "src/objects/map.h"
#include "src/objects/objects-inl.h"
#include "src/objects/property-details.h"
#include "src/objects/property.h"
#include "src/strings/string-stream.h"
#include "src/zone/zone-list-inl.h"

namespace v8 {
namespace internal {

// ----------------------------------------------------------------------------
// Implementation of other node functionality.

#ifdef DEBUG

void AstNode::Print(Isolate* isolate) { AstPrinter::PrintOut(isolate, this); }

#endif  // DEBUG

#define RETURN_NODE(Node) \
  case k##Node:           \
    return static_cast<Node*>(this);

IterationStatement* AstNode::AsIterationStatement() {
  switch (node_type()) {
    ITERATION_NODE_LIST(RETURN_NODE);
    default:
      return nullptr;
  }
}

MaterializedLiteral* AstNode::AsMaterializedLiteral() {
  switch (node_type()) {
    LITERAL_NODE_LIST(RETURN_NODE);
    default:
      return nullptr;
  }
}

#undef RETURN_NODE

bool Expression::IsSmiLiteral() const {
  return IsLiteral() && AsLiteral()->type() == Literal::kSmi;
}

bool Expression::IsNumberLiteral() const {
  return IsLiteral() && AsLiteral()->IsNumber();
}

bool Expression::IsStringLiteral() const {
  return IsLiteral() && AsLiteral()->type() == Literal::kString;
}

bool Expression::IsConsStringLiteral() const {
  return IsLiteral() && AsLiteral()->type() == Literal::kConsString;
}

bool Expression::IsPropertyName() const {
  return IsLiteral() && AsLiteral()->IsPropertyName();
}

bool Expression::IsNullLiteral() const {
  return IsLiteral() && AsLiteral()->type() == Literal::kNull;
}

bool Expression::IsBooleanLiteral() const {
  return IsLiteral() && AsLiteral()->type() == Literal::kBoolean;
}

bool Expression::IsTheHoleLiteral() const {
  return IsLiteral() && AsLiteral()->type() == Literal::kTheHole;
}

bool Expression::IsCompileTimeValue() {
  if (IsLiteral()) return true;
  MaterializedLiteral* literal = AsMaterializedLiteral();
  if (literal == nullptr) return false;
  return literal->IsSimple();
}

bool Expression::IsUndefinedLiteral() const {
  if (IsLiteral() && AsLiteral()->type() == Literal::kUndefined) return true;

  const VariableProxy* var_proxy = AsVariableProxy();
  if (var_proxy == nullptr) return false;
  Variable* var = var_proxy->var();
  // The global identifier "undefined" is immutable. Everything
  // else could be reassigned.
  return var != nullptr && var->IsUnallocated() &&
         var_proxy->raw_name()->IsOneByteEqualTo("undefined");
}

bool Expression::IsLiteralButNotNullOrUndefined() const {
  return IsLiteral() && !IsNullOrUndefinedLiteral();
}

bool Expression::ToBooleanIsTrue() const {
  return IsLiteral() && AsLiteral()->ToBooleanIsTrue();
}

bool Expression::ToBooleanIsFalse() const {
  return IsLiteral() && AsLiteral()->ToBooleanIsFalse();
}

bool Expression::IsPrivateName() const {
  return IsVariableProxy() && AsVariableProxy()->IsPrivateName();
}

bool Expression::IsValidReferenceExpression() const {
  return IsProperty() ||
         (IsVariableProxy() && AsVariableProxy()->IsValidReferenceExpression());
}

bool Expression::IsAnonymousFunctionDefinition() const {
  return (IsFunctionLiteral() &&
          AsFunctionLiteral()->IsAnonymousFunctionDefinition()) ||
         (IsClassLiteral() &&
          AsClassLiteral()->IsAnonymousFunctionDefinition());
}

bool Expression::IsConciseMethodDefinition() const {
  return IsFunctionLiteral() && IsConciseMethod(AsFunctionLiteral()->kind());
}

bool Expression::IsAccessorFunctionDefinition() const {
  return IsFunctionLiteral() && IsAccessorFunction(AsFunctionLiteral()->kind());
}

VariableProxy::VariableProxy(Variable* var, int start_position)
    : Expression(start_position, kVariableProxy),
      raw_name_(var->raw_name()),
      next_unresolved_(nullptr) {
  DCHECK(!var->is_this());
  bit_field_ |= IsAssignedField::encode(false) |
                IsResolvedField::encode(false) |
                HoleCheckModeField::encode(HoleCheckMode::kElided);
  BindTo(var);
}

VariableProxy::VariableProxy(const VariableProxy* copy_from)
    : Expression(copy_from->position(), kVariableProxy),
      next_unresolved_(nullptr) {
  bit_field_ = copy_from->bit_field_;
  DCHECK(!copy_from->is_resolved());
  raw_name_ = copy_from->raw_name_;
}

void VariableProxy::BindTo(Variable* var) {
  DCHECK_EQ(raw_name(), var->raw_name());
  set_var(var);
  set_is_resolved();
  var->set_is_used();
  if (is_assigned()) var->SetMaybeAssigned();
}

Assignment::Assignment(NodeType node_type, Token::Value op, Expression* target,
                       Expression* value, int pos)
    : Expression(pos, node_type), target_(target), value_(value) {
  bit_field_ |= TokenField::encode(op);
}

void FunctionLiteral::set_raw_inferred_name(AstConsString* raw_inferred_name) {
  DCHECK_NOT_NULL(raw_inferred_name);
  DCHECK(shared_function_info_.is_null());
  raw_inferred_name_ = raw_inferred_name;
  scope()->set_has_inferred_function_name(true);
}

Handle<String> FunctionLiteral::GetInferredName(Isolate* isolate) {
  if (raw_inferred_name_ != nullptr) {
    return raw_inferred_name_->GetString(isolate);
  }
  DCHECK(!shared_function_info_.is_null());
  return handle(shared_function_info_->inferred_name(), isolate);
}

void FunctionLiteral::set_shared_function_info(
    Handle<SharedFunctionInfo> shared_function_info) {
  DCHECK(shared_function_info_.is_null());
  CHECK_EQ(shared_function_info->function_literal_id(), function_literal_id_);
  shared_function_info_ = shared_function_info;
}

bool FunctionLiteral::ShouldEagerCompile() const {
  return scope()->ShouldEagerCompile();
}

void FunctionLiteral::SetShouldEagerCompile() {
  scope()->set_should_eager_compile();
}

bool FunctionLiteral::AllowsLazyCompilation() {
  return scope()->AllowsLazyCompilation();
}

int FunctionLiteral::start_position() const {
  return scope()->start_position();
}

int FunctionLiteral::end_position() const { return scope()->end_position(); }

LanguageMode FunctionLiteral::language_mode() const {
  return scope()->language_mode();
}

FunctionKind FunctionLiteral::kind() const { return scope()->function_kind(); }

std::unique_ptr<char[]> FunctionLiteral::GetDebugName() const {
  const AstConsString* cons_string;
  if (raw_name_ != nullptr && !raw_name_->IsEmpty()) {
    cons_string = raw_name_;
  } else if (raw_inferred_name_ != nullptr && !raw_inferred_name_->IsEmpty()) {
    cons_string = raw_inferred_name_;
  } else if (!shared_function_info_.is_null()) {
    return shared_function_info_->inferred_name()->ToCString();
  } else {
    char* empty_str = new char[1];
    empty_str[0] = 0;
    return std::unique_ptr<char[]>(empty_str);
  }

  // TODO(rmcilroy): Deal with two-character strings.
  std::vector<char> result_vec;
  std::forward_list<const AstRawString*> strings = cons_string->ToRawStrings();
  for (const AstRawString* string : strings) {
    if (!string->is_one_byte()) break;
    for (int i = 0; i < string->length(); i++) {
      result_vec.push_back(string->raw_data()[i]);
    }
  }
  std::unique_ptr<char[]> result(new char[result_vec.size() + 1]);
  memcpy(result.get(), result_vec.data(), result_vec.size());
  result[result_vec.size()] = '\0';
  return result;
}

bool FunctionLiteral::private_name_lookup_skips_outer_class() const {
  return scope()->private_name_lookup_skips_outer_class();
}

bool FunctionLiteral::class_scope_has_private_brand() const {
  return scope()->class_scope_has_private_brand();
}

void FunctionLiteral::set_class_scope_has_private_brand(bool value) {
  return scope()->set_class_scope_has_private_brand(value);
}

ObjectLiteralProperty::ObjectLiteralProperty(Expression* key, Expression* value,
                                             Kind kind, bool is_computed_name)
    : LiteralProperty(key, value, is_computed_name),
      kind_(kind),
      emit_store_(true) {}

ObjectLiteralProperty::ObjectLiteralProperty(AstValueFactory* ast_value_factory,
                                             Expression* key, Expression* value,
                                             bool is_computed_name)
    : LiteralProperty(key, value, is_computed_name), emit_store_(true) {
  if (!is_computed_name && key->AsLiteral()->IsRawString() &&
      key->AsLiteral()->AsRawString() == ast_value_factory->proto_string()) {
    kind_ = PROTOTYPE;
  } else if (value_->AsMaterializedLiteral() != nullptr) {
    kind_ = MATERIALIZED_LITERAL;
  } else if (value_->IsLiteral()) {
    kind_ = CONSTANT;
  } else {
    kind_ = COMPUTED;
  }
}

bool LiteralProperty::NeedsSetFunctionName() const {
  return is_computed_name() && (value_->IsAnonymousFunctionDefinition() ||
                                value_->IsConciseMethodDefinition() ||
                                value_->IsAccessorFunctionDefinition());
}

ClassLiteralProperty::ClassLiteralProperty(Expression* key, Expression* value,
                                           Kind kind, bool is_static,
                                           bool is_computed_name,
                                           bool is_private)
    : LiteralProperty(key, value, is_computed_name),
      kind_(kind),
      is_static_(is_static),
      is_private_(is_private),
      private_or_computed_name_proxy_(nullptr) {}

ClassLiteralProperty::ClassLiteralProperty(Expression* key, Expression* value,
                                           AutoAccessorInfo* info,
                                           bool is_static,
                                           bool is_computed_name,
                                           bool is_private)
    : LiteralProperty(key, value, is_computed_name),
      kind_(Kind::AUTO_ACCESSOR),
      is_static_(is_static),
      is_private_(is_private),
      auto_accessor_info_(info) {
  DCHECK_NOT_NULL(info);
}

bool ObjectLiteral::Property::IsCompileTimeValue() const {
  return kind_ == CONSTANT ||
         (kind_ == MATERIALIZED_LITERAL && value_->IsCompileTimeValue());
}

void ObjectLiteral::Property::set_emit_store(bool emit_store) {
  emit_store_ = emit_store;
}

bool ObjectLiteral::Property::emit_store() const { return emit_store_; }

void ObjectLiteral::CalculateEmitStore(Zone* zone) {
  const auto GETTER = ObjectLiteral::Property::GETTER;
  const auto SETTER = ObjectLiteral::Property::SETTER;

  CustomMatcherZoneHashMap table(Literal::Match,
                                 ZoneHashMap::kDefaultHashMapCapacity,
                                 ZoneAllocationPolicy(zone));
  for (int i = properties()->length() - 1; i >= 0; i--) {
    ObjectLiteral::Property* property = properties()->at(i);
    if (property->is_computed_name()) continue;
    if (property->IsPrototype()) continue;
    Literal* literal = property->key()->AsLiteral();
    DCHECK(!literal->IsNullLiteral());

    uint32_t hash = literal->Hash();
    ZoneHashMap::Entry* entry = table.LookupOrInsert(literal, hash);
    if (entry->value == nullptr) {
      entry->value = property;
    } else {
      // We already have a later definition of this property, so we don't need
      // to emit a store for the current one.
      //
      // There are two subtleties here.
      //
      // (1) Emitting a store might actually be incorrect. For example, in {get
      // foo() {}, foo: 42}, the getter store would override the data property
      // (which, being a non-computed compile-time valued property, is already
      // part of the initial literal object.
      //
      // (2) If the later definition is an accessor (say, a getter), and the
      // current definition is a complementary accessor (here, a setter), then
      // we still must emit a store for the current definition.

      auto later_kind =
          static_cast<ObjectLiteral::Property*>(entry->value)->kind();
      bool complementary_accessors =
          (property->kind() == GETTER && later_kind == SETTER) ||
          (property->kind() == SETTER && later_kind == GETTER);
      if (!complementary_accessors) {
        property->set_emit_store(false);
        if (later_kind == GETTER || later_kind == SETTER) {
          entry->value = property;
        }
      }
    }
  }
}

int ObjectLiteralBoilerplateBuilder::ComputeFlags(bool disable_mementos) const {
  int flags = LiteralBoilerplateBuilder::ComputeFlags(disable_mementos);
  if (fast_elements()) flags |= ObjectLiteral::kFastElements;
  if (has_null_prototype()) flags |= ObjectLiteral::kHasNullPrototype;
  return flags;
}

void ObjectLiteralBoilerplateBuilder::InitFlagsForPendingNullPrototype(int i) {
  // We still check for __proto__:null after computed property names.
  for (; i < properties()->length(); i++) {
    if (properties()->at(i)->IsNullPrototype()) {
      set_has_null_protoype(true);
      break;
    }
  }
}

int ObjectLiteralBoilerplateBuilder::EncodeLiteralType() {
  int flags = AggregateLiteral::kNoFlags;
  if (fast_elements()) flags |= ObjectLiteral::kFastElements;
  if (has_null_prototype()) flags |= ObjectLiteral::kHasNullPrototype;
  return flags;
}

void ObjectLiteralBoilerplateBuilder::InitDepthAndFlags() {
  if (is_initialized()) return;
  bool is_simple = true;
  bool has_seen_prototype = false;
  bool needs_initial_allocation_site = false;
  DepthKind depth_acc = kShallow;
  uint32_t nof_properties = 0;
  uint32_t elements = 0;
  uint32_t max_element_index = 0;
  for (int i = 0; i < properties()->length(); i++) {
    ObjectLiteral::Property* property = properties()->at(i);
    if (property->IsPrototype()) {
      has_seen_prototype = true;
      // __proto__:null has no side-effects and is set directly on the
      // boilerplate.
      if (property->IsNullPrototype()) {
        set_has_null_protoype(true);
        continue;
      }
      DCHECK(!has_null_prototype());
      is_simple = false;
      continue;
    }
    if (nof_properties == boilerplate_properties_) {
      DCHECK(property->is_computed_name());
      is_simple = false;
      if (!has_seen_prototype) InitFlagsForPendingNullPrototype(i);
      break;
    }
    DCHECK(!property->is_computed_name());

    MaterializedLiteral* literal = property->value()->AsMaterializedLiteral();
    if (literal != nullptr) {
      LiteralBoilerplateBuilder::InitDepthAndFlags(literal);
      depth_acc = kNotShallow;
      needs_initial_allocation_site |= literal->NeedsInitialAllocationSite();
    }

    Literal* key = property->key()->AsLiteral();
    Expression* value = property->value();

    bool is_compile_time_value = value->IsCompileTimeValue();
    is_simple = is_simple && is_compile_time_value;

    // Keep track of the number of elements in the object literal and
    // the largest element index.  If the largest element index is
    // much larger than the number of elements, creating an object
    // literal with fast elements will be a waste of space.
    uint32_t element_index = 0;
    if (key->AsArrayIndex(&element_index)) {
      max_element_index = std::max(element_index, max_element_index);
      elements++;
    } else {
      DCHECK(key->IsPropertyName());
    }

    nof_properties++;
  }

  set_depth(depth_acc);
  set_is_simple(is_simple);
  set_needs_initial_allocation_site(needs_initial_allocation_site);
  set_has_elements(elements > 0);
  set_fast_elements((max_element_index <= 32) ||
                    ((2 * elements) >= max_element_index));
}

template <typename IsolateT>
void ObjectLiteralBoilerplateBuilder::BuildBoilerplateDescription(
    IsolateT* isolate) {
  if (!boilerplate_description_.is_null()) return;

  int index_keys = 0;
  bool has_seen_proto = false;
  for (int i = 0; i < properties()->length(); i++) {
    ObjectLiteral::Property* property = properties()->at(i);
    if (property->IsPrototype()) {
      has_seen_proto = true;
      continue;
    }
    if (property->is_computed_name()) continue;

    Literal* key = property->key()->AsLiteral();
    if (!key->IsPropertyName()) index_keys++;
  }

  Handle<ObjectBoilerplateDescription> boilerplate_description =
      isolate->factory()->NewObjectBoilerplateDescription(
          boilerplate_properties_, properties()->length(), index_keys,
          has_seen_proto);

  int position = 0;
  for (int i = 0; i < properties()->length(); i++) {
    ObjectLiteral::Property* property = properties()->at(i);
    if (property->IsPrototype()) continue;

    if (static_cast<uint32_t>(position) == boilerplate_properties_) {
      DCHECK(property->is_computed_name());
      break;
    }
    DCHECK(!property->is_computed_name());

    MaterializedLiteral* m_literal = property->value()->AsMaterializedLiteral();
    if (m_literal != nullptr) {
      BuildConstants(isolate, m_literal);
    }

    // Add CONSTANT and COMPUTED properties to boilerplate. Use the
    // 'uninitialized' Oddball for COMPUTED properties, the real value is filled
    // in at runtime. The enumeration order is maintained.
    Literal* key_literal = property->key()->AsLiteral();
    uint32_t element_index = 0;
    DirectHandle<Object> key =
        key_literal->AsArrayIndex(&element_index)
            ? isolate->factory()
                  ->template NewNumberFromUint<AllocationType::kOld>(
                      element_index)
            : Cast<Object>(key_literal->AsRawPropertyName()->string());
    DirectHandle<Object> value =
        GetBoilerplateValue(property->value(), isolate);
    boilerplate_description->set_key_value(position++, *key, *value);
  }

  boilerplate_description->set_flags(EncodeLiteralType());

  boilerplate_description_ = boilerplate_description;
}
template EXPORT_TEMPLATE_DEFINE(
    V8_BASE_EXPORT) void ObjectLiteralBoilerplateBuilder::
    BuildBoilerplateDescription(Isolate* isolate);
template EXPORT_TEMPLATE_DEFINE(
    V8_BASE_EXPORT) void ObjectLiteralBoilerplateBuilder::
    BuildBoilerplateDescription(LocalIsolate* isolate);

bool ObjectLiteralBoilerplateBuilder::IsFastCloningSupported() const {
  // The CreateShallowObjectLiteratal builtin doesn't copy elements, and object
  // literals don't support copy-on-write (COW) elements for now.
  // TODO(mvstanton): make object literals support COW elements.
  return fast_elements() && is_shallow() &&
         properties_count() <=
             ConstructorBuiltins::kMaximumClonedShallowObjectProperties;
}

// static
template <typename IsolateT>
Handle<Object> LiteralBoilerplateBuilder::GetBoilerplateValue(
    Expression* expression, IsolateT* isolate) {
  if (expression->IsLiteral()) {
    return expression->AsLiteral()->BuildValue(isolate);
  }
  if (expression->IsCompileTimeValue()) {
    if (expression->IsObjectLiteral()) {
      ObjectLiteral* object_literal = expression->AsObjectLiteral();
      DCHECK(object_literal->builder()->is_simple());
      return object_literal->builder()->boilerplate_description();
    } else {
      DCHECK(expression->IsArrayLiteral());
      ArrayLiteral* array_literal = expression->AsArrayLiteral();
      DCHECK(array_literal->builder()->is_simple());
      return array_literal->builder()->boilerplate_description();
    }
  }
  return isolate->factory()->uninitialized_value();
}
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<Object> LiteralBoilerplateBuilder::GetBoilerplateValue(
        Expression* expression, Isolate* isolate);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<Object> LiteralBoilerplateBuilder::GetBoilerplateValue(
        Expression* expression, LocalIsolate* isolate);

void ArrayLiteralBoilerplateBuilder::InitDepthAndFlags() {
  if (is_initialized()) return;

  int constants_length =
      first_spread_index_ >= 0 ? first_spread_index_ : values_->length();

  // Fill in the literals.
  bool is_simple = first_spread_index_ < 0;
  bool is_holey = false;
  ElementsKind kind = FIRST_FAST_ELEMENTS_KIND;
  DepthKind depth_acc = kShallow;
  int array_index = 0;
  for (; array_index < constants_length; array_index++) {
    Expression* element = values_->at(array_index);
    MaterializedLiteral* materialized_literal =
        element->AsMaterializedLiteral();
    if (materialized_literal != nullptr) {
      LiteralBoilerplateBuilder::InitDepthAndFlags(materialized_literal);
      depth_acc = kNotShallow;
    }

    if (!element->IsCompileTimeValue()) {
      is_simple = false;

      // Don't change kind here: non-compile time values resolve to an unknown
      // elements kind, so we allow them to be considered as any one of them.

      // TODO(leszeks): It would be nice to DCHECK here that GetBoilerplateValue
      // will return IsUninitialized, but that would require being on the main
      // thread which we may not be.
    } else {
      Literal* literal = element->AsLiteral();

      if (!literal) {
        // Only arrays and objects are compile-time values but not (primitive)
        // literals.
        DCHECK(element->IsObjectLiteral() || element->IsArrayLiteral());
        kind = PACKED_ELEMENTS;
      } else {
        switch (literal->type()) {
          case Literal::kTheHole:
            is_holey = true;
            // The hole is allowed in holey double arrays (and holey Smi
            // arrays), so ignore it as far as is_all_number is concerned.
            break;
          case Literal::kHeapNumber:
            if (kind == PACKED_SMI_ELEMENTS) kind = PACKED_DOUBLE_ELEMENTS;
            DCHECK_EQ(kind,
                      GetMoreGeneralElementsKind(kind, PACKED_DOUBLE_ELEMENTS));
            break;
          case Literal::kSmi:
            DCHECK_EQ(kind,
                      GetMoreGeneralElementsKind(kind, PACKED_SMI_ELEMENTS));
            break;
          case Literal::kBigInt:
          case Literal::kString:
          case Literal::kConsString:
          case Literal::kBoolean:
          case Literal::kUndefined:
          case Literal::kNull:
            kind = PACKED_ELEMENTS;
            break;
        }
      }
    }
  }

  if (is_holey) {
    kind = GetHoleyElementsKind(kind);
  }

  set_depth(depth_acc);
  set_is_simple(is_simple);
  set_boilerplate_descriptor_kind(kind);

  // Array literals always need an initial allocation site to properly track
  // elements transitions.
  set_needs_initial_allocation_site(true);
}

template <typename IsolateT>
void ArrayLiteralBoilerplateBuilder::BuildBoilerplateDescription(
    IsolateT* isolate) {
  if (!boilerplate_description_.is_null()) return;

  int constants_length =
      first_spread_index_ >= 0 ? first_spread_index_ : values_->length();
  ElementsKind kind = boilerplate_descriptor_kind();
  bool use_doubles = IsDoubleElementsKind(kind);

  Handle<FixedArrayBase> elements;
  if (use_doubles) {
    elements = isolate->factory()->NewFixedDoubleArray(constants_length,
                                                       AllocationType::kOld);
  } else {
    elements = isolate->factory()->NewFixedArrayWithHoles(constants_length,
                                                          AllocationType::kOld);
  }

  // Fill in the literals.
  int array_index = 0;
  for (; array_index < constants_length; array_index++) {
    Expression* element = values_->at(array_index);
    DCHECK(!element->IsSpread());
    if (use_doubles) {
      Literal* literal = element->AsLiteral();

      if (literal && literal->type() == Literal::kTheHole) {
        DCHECK(IsHoleyElementsKind(kind));
        DCHECK(IsTheHole(*GetBoilerplateValue(element, isolate), isolate));
        Cast<FixedDoubleArray>(*elements)->set_the_hole(array_index);
        continue;
      } else if (literal && literal->IsNumber()) {
        Cast<FixedDoubleArray>(*elements)->set(array_index,
                                               literal->AsNumber());
      } else {
        DCHECK(
            IsUninitialized(*GetBoilerplateValue(element, isolate), isolate));
        Cast<FixedDoubleArray>(*elements)->set(array_index, 0);
      }

    } else {
      MaterializedLiteral* m_literal = element->AsMaterializedLiteral();
      if (m_literal != nullptr) {
        BuildConstants(isolate, m_literal);
      }

      // New handle scope here, needs to be after BuildContants().
      typename IsolateT::HandleScopeType scope(isolate);

      Tagged<Object> boilerplate_value = *GetBoilerplateValue(element, isolate);
      // We shouldn't allocate after creating the boilerplate value.
      DisallowGarbageCollection no_gc;

      if (IsTheHole(boilerplate_value, isolate)) {
        DCHECK(IsHoleyElementsKind(kind));
        continue;
      }

      if (IsUninitialized(boilerplate_value, isolate)) {
        boilerplate_value = Smi::zero();
      }

      DCHECK_EQ(kind, GetMoreGeneralElementsKind(
                          kind, Object::OptimalElementsKind(
                                    boilerplate_value,
                                    GetPtrComprCageBase(*elements))));

      Cast<FixedArray>(*elements)->set(array_index, boilerplate_value);
    }
  }  // namespace internal

  // Simple and shallow arrays can be lazily copied, we transform the
  // elements array to a copy-on-write array.
  if (is_simple() && depth() == kShallow && array_index > 0 &&
      IsSmiOrObjectElementsKind(kind)) {
    elements->set_map_safe_transition(
        isolate, ReadOnlyRoots(isolate).fixed_cow_array_map(), kReleaseStore);
  }

  boilerplate_description_ =
      isolate->factory()->NewArrayBoilerplateDescription(kind, elements);
}
template EXPORT_TEMPLATE_DEFINE(
    V8_BASE_EXPORT) void ArrayLiteralBoilerplateBuilder::
    BuildBoilerplateDescription(Isolate* isolate);
template EXPORT_TEMPLATE_DEFINE(
    V8_BASE_EXPORT) void ArrayLiteralBoilerplateBuilder::
    BuildBoilerplateDescription(LocalIsolate*

                                    isolate);

bool ArrayLiteralBoilerplateBuilder::IsFastCloningSupported() const {
  return depth() <= kShallow &&
         values_->length() <=
             ConstructorBuiltins::kMaximumClonedShallowArrayElements;
}

bool MaterializedLiteral::IsSimple() const {
  if (IsArrayLiteral()) return AsArrayLiteral()->builder()->is_simple();
  if (IsObjectLiteral()) return AsObjectLiteral()->builder()->is_simple();
  DCHECK(IsRegExpLiteral());
  return false;
}

// static
void LiteralBoilerplateBuilder::InitDepthAndFlags(MaterializedLiteral* expr) {
  if (expr->IsArrayLiteral()) {
    return expr->AsArrayLiteral()->builder()->InitDepthAndFlags();
  }
  if (expr->IsObjectLiteral()) {
    return expr->AsObjectLiteral()->builder()->InitDepthAndFlags();
  }
  DCHECK(expr->IsRegExpLiteral());
}

bool MaterializedLiteral::NeedsInitialAllocationSite(

) {
  if (IsArrayLiteral()) {
    return AsArrayLiteral()->builder()->needs_initial_allocation_site();
  }
  if (IsObjectLiteral()) {
    return AsObjectLiteral()->builder()->needs_initial_allocation_site();
  }
  DCHECK(IsRegExpLiteral());
  return false;
}

template <typename IsolateT>
void LiteralBoilerplateBuilder::BuildConstants(IsolateT* isolate,
                                               MaterializedLiteral* expr) {
  if (expr->IsArrayLiteral()) {
    expr->AsArrayLiteral()->builder()->BuildBoilerplateDescription(isolate);
    return;
  }
  if (expr->IsObjectLiteral()) {
    expr->AsObjectLiteral()->builder()->BuildBoilerplateDescription(isolate);
    return;
  }
  DCHECK(expr->IsRegExpLiteral());
}
template EXPORT_TEMPLATE_DEFINE(V8_BASE_EXPORT) void LiteralBoilerplateBuilder::
    BuildConstants(Isolate* isolate, MaterializedLiteral* expr);
template EXPORT_TEMPLATE_DEFINE(V8_BASE_EXPORT) void LiteralBoilerplateBuilder::
    BuildConstants(LocalIsolate* isolate, MaterializedLiteral* expr);

template <typename IsolateT>
Handle<TemplateObjectDescription> GetTemplateObject::GetOrBuildDescription(
    IsolateT* isolate) {
  Handle<FixedArray> raw_strings_handle = isolate->factory()->NewFixedArray(
      this->raw_strings()->length(), AllocationType::kOld);
  bool raw_and_cooked_match = true;
  {
    DisallowGarbageCollection no_gc;
    Tagged<FixedArray> raw_strings = *raw_strings_handle;

    for (int i = 0; i < raw_strings->length(); ++i) {
      if (this->raw_strings()->at(i) != this->cooked_strings()->at(i)) {
        // If the AstRawStrings don't match, then neither should the allocated
        // Strings, since the AstValueFactory should have deduplicated them
        // already.
        DCHECK_IMPLIES(this->cooked_strings()->at(i) != nullptr,
                       *this->cooked_strings()->at(i)->string() !=
                           *this->raw_strings()->at(i)->string());

        raw_and_cooked_match = false;
      }
      raw_strings->set(i, *this->raw_strings()->at(i)->string());
    }
  }
  Handle<FixedArray> cooked_strings_handle = raw_strings_handle;
  if (!raw_and_cooked_match) {
    cooked_strings_handle = isolate->factory()->NewFixedArray(
        this->cooked_strings()->length(), AllocationType::kOld);
    DisallowGarbageCollection no_gc;
    Tagged<FixedArray> cooked_strings = *cooked_strings_handle;
    ReadOnlyRoots roots(isolate);
    for (int i = 0; i < cooked_strings->length(); ++i) {
      if (this->cooked_strings()->at(i) != nullptr) {
        cooked_strings->set(i, *this->cooked_strings()->at(i)->string());
      } else {
        cooked_strings->set(i, roots.undefined_value(), SKIP_WRITE_BARRIER);
      }
    }
  }
  return isolate->factory()->NewTemplateObjectDescription(
      raw_strings_handle, cooked_strings_handle);
}
template EXPORT_TEMPLATE_DEFINE(V8_BASE_EXPORT)
    Handle<TemplateObjectDescription> GetTemplateObject::GetOrBuildDescription(
        Isolate* isolate);
template EXPORT_TEMPLATE_DEFINE(V8_BASE_EXPORT)
    Handle<TemplateObjectDescription> GetTemplateObject::GetOrBuildDescription(
        LocalIsolate* isolate);

static bool IsCommutativeOperationWithSmiLiteral(Token::Value op) {
  // Add is not commutative due to potential for string addition.
  return op == Token::kMul || op == Token::kBitAnd || op == Token::kBitOr ||
         op == Token::kBitXor;
}

// Check for the pattern: x + 1.
static bool MatchSmiLiteralOperation(Expression* left, Expression* right,
                                     Expression** expr, Tagged<Smi>* literal) {
  if (right->IsSmiLiteral()) {
    *expr = left;
    *literal = right->AsLiteral()->AsSmiLiteral();
    return true;
  }
  return false;
}

bool BinaryOperation::IsSmiLiteralOperation(Expression** subexpr,
                                            Tagged<Smi>* literal) {
  return MatchSmiLiteralOperation(left_, right_, subexpr, literal) ||
         (IsCommutativeOperationWithSmiLiteral(op()) &&
          MatchSmiLiteralOperation(right_, left_, subexpr, literal));
}

static bool IsVoidOfLiteral(Expression* expr) {
  UnaryOperation* maybe_unary = expr->AsUnaryOperation();
  return maybe_unary != nullptr && maybe_unary->op() == Token::kVoid &&
         maybe_unary->expression()->IsLiteral();
}

static bool MatchLiteralStrictCompareBoolean(Expression* left, Token::Value op,
                                             Expression* right,
                                             Expression** expr,
                                             Literal** literal) {
  if (left->IsBooleanLiteral() && op == Token::kEqStrict) {
    *expr = right;
    *literal = left->AsLiteral();
    return true;
  }
  return false;
}

bool CompareOperation::IsLiteralStrictCompareBoolean(Expression** expr,
                                                     Literal** literal) {
  return MatchLiteralStrictCompareBoolean(left_, op(), right_, expr, literal) ||
         MatchLiteralStrictCompareBoolean(right_, op(), left_, expr, literal);
}

// Check for the pattern: void <literal> equals <expression> or
// undefined equals <expression>
static bool MatchLiteralCompareUndefined(Expression* left, Token::Value op,
                                         Expression* right, Expression** expr) {
  if (IsVoidOfLiteral(left) && Token::IsEqualityOp(op)) {
    *expr = right;
    return true;
  }
  if (left->IsUndefinedLiteral() && Token::IsEqualityOp(op)) {
    *expr = right;
    return true;
  }
  return false;
}

bool CompareOperation::IsLiteralCompareUndefined(Expression** expr) {
  re
"""


```