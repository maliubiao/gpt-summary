Response:
Let's break down the thought process for analyzing the provided C++ header file (`v8/src/torque/ast.h`).

**1. Initial Scan and High-Level Understanding:**

* **Keywords:**  The first thing that jumps out are keywords like `#ifndef`, `#define`, `#include`, `namespace`, `struct`, `class`, `enum`. This immediately signals C++ header file.
* **`torque`:** The path `v8/src/torque/` strongly suggests this file is related to V8's Torque language.
* **`ast.h`:** The name "ast" is a very common abbreviation for "Abstract Syntax Tree". This is a crucial clue. ASTs are used in compilers and interpreters to represent the structure of code.
* **Comments:** The copyright notice and the initial comment block confirm it's part of the V8 project and likely related to Torque.

**2. Identifying Core Components (Based on Definitions):**

* **Macros:**  The `#define` blocks like `AST_EXPRESSION_NODE_KIND_LIST`, `AST_TYPE_EXPRESSION_NODE_KIND_LIST`, etc., define lists of things. The naming convention `*_NODE_KIND_LIST` points to different categories of nodes within the AST. This strongly suggests a hierarchical structure.
* **`enum class Kind`:** Inside the `AstNode` struct, this enum lists all the possible types of nodes in the AST. Comparing this enum to the macros confirms that the macros are indeed defining the members of this enum.
* **`struct AstNode`:**  This looks like the base class for all nodes in the AST. It has a `Kind` and `SourcePosition`. This is typical of AST designs – a base class with common properties.
* **Boilerplate Macros:**  `DEFINE_AST_NODE_LEAF_BOILERPLATE` and `DEFINE_AST_NODE_INNER_BOILERPLATE` are macros for generating common code related to casting and type checking. This is a common C++ pattern to reduce code duplication.
* **Derived Structs:**  Following `AstNode`, there's a series of structs like `Expression`, `LocationExpression`, `TypeExpression`, `Declaration`, `Statement`. These clearly inherit from `AstNode` and likely represent fundamental syntactic categories.
* **Further Derived Structs:** Then there are more specific structs like `CallExpression`, `IdentifierExpression`, `IfStatement`, `VarDeclarationStatement`, `ClassDeclaration`, etc. These are the concrete node types that make up the Torque AST.

**3. Understanding Relationships and Functionality:**

* **Inheritance:** The use of `struct ... : AstNode` and the boilerplate macros clearly indicate an inheritance hierarchy. `Expression`, `Statement`, `Declaration`, `TypeExpression` are base classes for more specific node types.
* **Data Representation:** The structs primarily hold data related to the syntax of the Torque language. For example, `CallExpression` stores the `callee`, `arguments`, and `labels`. `IfStatement` stores the `condition`, `if_true`, and `if_false`.
* **Visitor Pattern (Clue):** The `VisitAllSubExpressions` method in `Expression` hints at the possibility of using the Visitor pattern to traverse and operate on the AST.
* **Source Information:** The `SourcePosition pos` member in `AstNode` indicates that each node tracks its location in the original source code. This is crucial for error reporting and debugging.
* **`Ast` Class:** The `Ast` class seems to be the top-level container for the entire AST. It manages a list of declarations.

**4. Connecting to Torque and JavaScript (Conceptual):**

* **Torque Source:** The comment about `.tq` files confirms that this AST is for the Torque language.
* **Relationship to JavaScript:**  Torque is used to implement built-in functionality in V8 (the JavaScript engine). So, the elements in this AST represent the *underlying implementation details* of JavaScript features. The provided example of `console.log()` is a good way to illustrate this – Torque would define the implementation of how `console.log()` works.

**5. Identifying Potential Programming Errors (Based on AST Structure):**

* **Type Errors:**  The presence of `TypeExpression` and the different type-related nodes suggests that Torque is a typed language (or at least has type information). Common errors would involve type mismatches, incorrect type casting, etc. The provided example of assigning a string to a number variable is a classic example.
* **Syntax Errors:** The AST structure itself reflects the grammar of the language. Incorrect syntax would lead to parsing errors and the inability to build the AST.
* **Scope Issues:**  While not directly evident in *this* header file, the presence of `NamespaceDeclaration` hints at the concept of scope, which can lead to variable naming conflicts and resolution errors.

**6. Inferring Code Logic (Hypothetical):**

* **Example: Function Call:**  Imagine Torque code like `Call(MyFunction, arg1, arg2)`. The AST would represent this with a `CallExpression` node. The `callee` would be an `IdentifierExpression` for `MyFunction`, and the `arguments` would be a list of `Expression` nodes for `arg1` and `arg2`.

**7. Structuring the Summary:**

Finally, the information needs to be organized logically. Starting with the core purpose (representing the Torque AST), then detailing the major components, their relationships, and connections to Torque and JavaScript is a good approach. Adding examples and discussing potential errors makes the explanation more concrete.

**Self-Correction/Refinement during the Process:**

* Initially, one might just see a bunch of structs. Realizing the significance of the inheritance relationships and the `Kind` enum is key to understanding the overall structure.
* Connecting the abstract AST nodes to concrete Torque syntax requires some thought. Thinking about how different language constructs would be represented in this tree is crucial.
* The link to JavaScript isn't always immediately obvious. Remembering the purpose of Torque within V8 helps bridge this gap.

By following this kind of detailed examination and reasoning, it's possible to arrive at a comprehensive understanding of the `v8/src/torque/ast.h` header file.
这是v8/src/torque/ast.h的源代码，它定义了用于表示 **Torque 抽象语法树 (AST)** 的数据结构。 Torque 是一种用于编写 V8 内部代码的领域特定语言。

**功能归纳：**

1. **定义 Torque 语言的语法结构：** `ast.h` 文件通过定义各种 C++ 结构体 (struct) 来建模 Torque 语言的各种语法元素，例如表达式、语句、声明和类型表达式。

2. **构建抽象语法树：** 这些结构体可以被用来在 Torque 代码的编译过程中构建一个抽象语法树。AST 是源代码的树状表示，它去除了源代码中的无关紧要的细节（如空格和注释），并着重表达程序的结构。

3. **类型信息和源代码位置追踪：** 每个 AST 节点都包含类型信息（例如 `TypeExpression`）和源代码位置信息 (`SourcePosition`)，这对于类型检查、错误报告和代码生成至关重要。

4. **支持多种语言构造：**  文件中定义了各种用于表示不同 Torque 语言构造的节点类型，包括：
    * **表达式 (Expressions):**  例如函数调用 (`CallExpression`)、方法调用 (`CallMethodExpression`)、字面量 (`StringLiteralExpression`, `IntegerLiteralExpression`)、变量引用 (`IdentifierExpression`)、逻辑运算 (`LogicalOrExpression`, `LogicalAndExpression`)、赋值 (`AssignmentExpression`) 等。
    * **类型表达式 (Type Expressions):** 例如基本类型 (`BasicTypeExpression`)、函数类型 (`FunctionTypeExpression`)、联合类型 (`UnionTypeExpression`) 等。
    * **语句 (Statements):** 例如代码块 (`BlockStatement`)、条件语句 (`IfStatement`)、循环语句 (`WhileStatement`, `ForLoopStatement`)、返回语句 (`ReturnStatement`)、变量声明 (`VarDeclarationStatement`) 等。
    * **声明 (Declarations):** 例如类型声明 (`AbstractTypeDeclaration`, `TypeAliasDeclaration`, `StructDeclaration`, `ClassDeclaration`)、函数/宏声明 (`GenericCallableDeclaration`, `TorqueMacroDeclaration`, `TorqueBuiltinDeclaration`)、常量声明 (`ConstDeclaration`)、命名空间声明 (`NamespaceDeclaration`) 等。

5. **支持泛型和模板：**  通过 `generic_arguments` 等成员，AST 结构支持表示 Torque 中的泛型类型和函数。

6. **支持控制流：**  定义了表示控制流语句的节点，如 `IfStatement`、`WhileStatement`、`ForLoopStatement`、`BreakStatement`、`ContinueStatement` 和 `GotoStatement`。

7. **支持异常处理：**  定义了 `TryHandler` 和 `TryLabelExpression` 来表示 Torque 中的异常处理机制。

**关于 .tq 结尾：**

是的，如果一个文件以 `.tq` 结尾，那么它很可能是一个 **V8 Torque 源代码文件**。 `ast.h` 中定义的结构体就是用来表示这些 `.tq` 文件内容的。

**与 JavaScript 的关系和示例：**

Torque 代码通常用于实现 V8 引擎内部的内置函数和类型。虽然开发者不会直接编写 Torque 代码来扩展 JavaScript 的功能，但 JavaScript 的行为在底层是由 Torque 代码定义的。

例如，JavaScript 中的 `console.log()` 函数的实现就可能涉及到 Torque 代码。在 Torque 的 AST 中，对 `console.log()` 的调用可能被表示为一个 `CallExpression` 节点，其中：

* `callee` 是一个 `IdentifierExpression`，其 `name` 可能是 "console.log" 或者一个内部的 Torque 函数名。
* `arguments` 是一个 `Expression` 列表，表示传递给 `console.log()` 的参数。

```javascript
// JavaScript 代码
console.log("Hello", 123);
```

在 Torque 的 AST 中，这可能会被抽象表示为类似于：

```
CallExpression {
  callee: IdentifierExpression {
    name: "ConsoleLog" // 假设的 Torque 内部函数名
  },
  arguments: [
    StringLiteralExpression {
      literal: "Hello"
    },
    IntegerLiteralExpression {
      value: 123
    }
  ]
}
```

**代码逻辑推理示例：**

**假设输入 (Torque 代码片段):**

```torque
let x: int32 = 10;
if (x > 5) {
  x = x + 1;
}
return x;
```

**输出 (部分可能的 AST 结构):**

* `VarDeclarationStatement`:
    * `name`: "x"
    * `type`: `BasicTypeExpression` (int32)
    * `initializer`: `IntegerLiteralExpression` (10)
* `IfStatement`:
    * `condition`: `CallExpression` (假设 `>` 运算符被实现为函数调用) 或 `LogicalOrExpression`/`LogicalAndExpression` 的组合。
        * 左侧: `IdentifierExpression` ("x")
        * 右侧: `IntegerLiteralExpression` (5)
    * `if_true`: `BlockStatement`
        * `ExpressionStatement`:
            * `expression`: `AssignmentExpression`
                * `location`: `IdentifierExpression` ("x")
                * `value`: `CallExpression` (假设 `+` 运算符被实现为函数调用)
                    * 参数 1: `IdentifierExpression` ("x")
                    * 参数 2: `IntegerLiteralExpression` (1)
* `ReturnStatement`:
    * `value`: `IdentifierExpression` ("x")

**用户常见的编程错误示例：**

在编写类似 Torque 的强类型语言时，常见的错误包括：

1. **类型不匹配：**  例如，尝试将一个字符串赋值给一个声明为整数的变量。

   ```torque
   let count: int32 = "hello"; // 错误：类型不匹配
   ```

   在构建 AST 时，类型检查阶段会检测到这种错误。`VarDeclarationStatement` 节点的类型信息会与 `StringLiteralExpression` 的类型不匹配。

2. **未声明的变量：**  尝试使用一个没有声明的变量。

   ```torque
   y = 20; // 错误：y 未声明
   ```

   解析器在构建 AST 时，如果遇到 `IdentifierExpression` 指向一个未声明的变量，会报告错误。

3. **函数调用参数不匹配：**  调用函数时提供的参数数量或类型与函数声明不符。

   ```torque
   function add(a: int32, b: int32): int32 { ... }
   let result = add(10, "world"); // 错误：第二个参数类型不匹配
   ```

   `CallExpression` 节点会记录参数的类型，类型检查器会将其与函数 `add` 的参数类型进行比较。

**总结：**

`v8/src/torque/ast.h` 定义了用于表示 Torque 语言抽象语法树的各种 C++ 数据结构。 它的主要功能是为 Torque 编译器提供一个结构化的、类型化的源代码表示，用于后续的语义分析、优化和代码生成。 这对于 V8 引擎内部高效地实现 JavaScript 的内置功能至关重要。

### 提示词
```
这是目录为v8/src/torque/ast.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/ast.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_TORQUE_AST_H_
#define V8_TORQUE_AST_H_

#include <algorithm>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "src/numbers/integer-literal.h"
#include "src/torque/constants.h"
#include "src/torque/source-positions.h"
#include "src/torque/utils.h"

namespace v8::internal::torque {

#define AST_EXPRESSION_NODE_KIND_LIST(V) \
  V(CallExpression)                      \
  V(CallMethodExpression)                \
  V(IntrinsicCallExpression)             \
  V(StructExpression)                    \
  V(LogicalOrExpression)                 \
  V(LogicalAndExpression)                \
  V(SpreadExpression)                    \
  V(ConditionalExpression)               \
  V(IdentifierExpression)                \
  V(StringLiteralExpression)             \
  V(IntegerLiteralExpression)            \
  V(FloatingPointLiteralExpression)      \
  V(FieldAccessExpression)               \
  V(ElementAccessExpression)             \
  V(DereferenceExpression)               \
  V(AssignmentExpression)                \
  V(IncrementDecrementExpression)        \
  V(NewExpression)                       \
  V(AssumeTypeImpossibleExpression)      \
  V(StatementExpression)                 \
  V(TryLabelExpression)

#define AST_TYPE_EXPRESSION_NODE_KIND_LIST(V) \
  V(BasicTypeExpression)                      \
  V(FunctionTypeExpression)                   \
  V(PrecomputedTypeExpression)                \
  V(UnionTypeExpression)

#define AST_STATEMENT_NODE_KIND_LIST(V) \
  V(BlockStatement)                     \
  V(ExpressionStatement)                \
  V(IfStatement)                        \
  V(WhileStatement)                     \
  V(ForLoopStatement)                   \
  V(BreakStatement)                     \
  V(ContinueStatement)                  \
  V(ReturnStatement)                    \
  V(DebugStatement)                     \
  V(AssertStatement)                    \
  V(TailCallStatement)                  \
  V(VarDeclarationStatement)            \
  V(GotoStatement)

#define AST_TYPE_DECLARATION_NODE_KIND_LIST(V) \
  V(AbstractTypeDeclaration)                   \
  V(TypeAliasDeclaration)                      \
  V(BitFieldStructDeclaration)                 \
  V(ClassDeclaration)                          \
  V(StructDeclaration)

#define AST_DECLARATION_NODE_KIND_LIST(V) \
  AST_TYPE_DECLARATION_NODE_KIND_LIST(V)  \
  V(GenericCallableDeclaration)           \
  V(GenericTypeDeclaration)               \
  V(SpecializationDeclaration)            \
  V(ExternConstDeclaration)               \
  V(NamespaceDeclaration)                 \
  V(ConstDeclaration)                     \
  V(CppIncludeDeclaration)                \
  V(TorqueMacroDeclaration)               \
  V(TorqueBuiltinDeclaration)             \
  V(ExternalMacroDeclaration)             \
  V(ExternalBuiltinDeclaration)           \
  V(ExternalRuntimeDeclaration)           \
  V(IntrinsicDeclaration)

#define AST_NODE_KIND_LIST(V)           \
  AST_EXPRESSION_NODE_KIND_LIST(V)      \
  AST_TYPE_EXPRESSION_NODE_KIND_LIST(V) \
  AST_STATEMENT_NODE_KIND_LIST(V)       \
  AST_DECLARATION_NODE_KIND_LIST(V)     \
  V(Identifier)                         \
  V(TryHandler)                         \
  V(ClassBody)

struct AstNode {
 public:
  enum class Kind {
#define ENUM_ITEM(name) k##name,
    AST_NODE_KIND_LIST(ENUM_ITEM)
#undef ENUM_ITEM
  };

  AstNode(Kind kind, SourcePosition pos) : kind(kind), pos(pos) {}
  virtual ~AstNode() = default;

  const Kind kind;
  SourcePosition pos;
};

struct AstNodeClassCheck {
  template <class T>
  static bool IsInstanceOf(AstNode* node);
};

// Boilerplate for most derived classes.
#define DEFINE_AST_NODE_LEAF_BOILERPLATE(T)  \
  static const Kind kKind = Kind::k##T;      \
  static T* cast(AstNode* node) {            \
    DCHECK_EQ(node->kind, kKind);            \
    return static_cast<T*>(node);            \
  }                                          \
  static T* DynamicCast(AstNode* node) {     \
    if (!node) return nullptr;               \
    if (node->kind != kKind) return nullptr; \
    return static_cast<T*>(node);            \
  }

// Boilerplate for classes with subclasses.
#define DEFINE_AST_NODE_INNER_BOILERPLATE(T)                       \
  static T* cast(AstNode* node) {                                  \
    DCHECK(AstNodeClassCheck::IsInstanceOf<T>(node));              \
    return static_cast<T*>(node);                                  \
  }                                                                \
  static T* DynamicCast(AstNode* node) {                           \
    if (!node) return nullptr;                                     \
    if (!AstNodeClassCheck::IsInstanceOf<T>(node)) return nullptr; \
    return static_cast<T*>(node);                                  \
  }

struct Expression : AstNode {
  Expression(Kind kind, SourcePosition pos) : AstNode(kind, pos) {}
  DEFINE_AST_NODE_INNER_BOILERPLATE(Expression)

  using VisitCallback = std::function<void(Expression*)>;
  virtual void VisitAllSubExpressions(VisitCallback callback) {
    // TODO(szuend): Hoist this up to AstNode and make it a
    //               general Ast visitor.
  }
};

struct LocationExpression : Expression {
  LocationExpression(Kind kind, SourcePosition pos) : Expression(kind, pos) {}
  DEFINE_AST_NODE_INNER_BOILERPLATE(LocationExpression)
};

struct TypeExpression : AstNode {
  TypeExpression(Kind kind, SourcePosition pos) : AstNode(kind, pos) {}
  DEFINE_AST_NODE_INNER_BOILERPLATE(TypeExpression)
};

struct Declaration : AstNode {
  Declaration(Kind kind, SourcePosition pos) : AstNode(kind, pos) {}
  DEFINE_AST_NODE_INNER_BOILERPLATE(Declaration)
};

struct Statement : AstNode {
  Statement(Kind kind, SourcePosition pos) : AstNode(kind, pos) {}
  DEFINE_AST_NODE_INNER_BOILERPLATE(Statement)
};

class Namespace;

struct NamespaceDeclaration : Declaration {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(NamespaceDeclaration)
  NamespaceDeclaration(SourcePosition pos, std::string name,
                       std::vector<Declaration*> declarations)
      : Declaration(kKind, pos),
        declarations(std::move(declarations)),
        name(name) {}
  std::vector<Declaration*> declarations;
  std::string name;
};

struct EnumDescription {
  struct Entry {
    std::string name;
    std::string alias_entry;
    Entry(std::string name, std::string alias_entry)
        : name(std::move(name)), alias_entry(std::move(alias_entry)) {}
  };
  SourcePosition pos;
  std::string name;
  std::string constexpr_generates;
  bool is_open;
  std::vector<Entry> entries;

  EnumDescription(SourcePosition pos, std::string name,
                  std::string constexpr_generates, bool is_open,
                  std::vector<Entry> entries = {})
      : pos(std::move(pos)),
        name(std::move(name)),
        constexpr_generates(std::move(constexpr_generates)),
        is_open(is_open),
        entries(std::move(entries)) {}
};

class Ast {
 public:
  Ast() = default;

  std::vector<Declaration*>& declarations() { return declarations_; }
  const std::vector<Declaration*>& declarations() const {
    return declarations_;
  }
  template <class T>
  T* AddNode(std::unique_ptr<T> node) {
    T* result = node.get();
    nodes_.push_back(std::move(node));
    return result;
  }

  void DeclareImportForCurrentFile(SourceId import_id) {
    declared_imports_[CurrentSourcePosition::Get().source].insert(import_id);
  }

  void AddEnumDescription(EnumDescription description) {
    std::string name = description.name;
    DCHECK(!name.empty());
    auto f = [&](const auto& d) { return d.name == name; };
    USE(f);  // Suppress unused in release.
    DCHECK_EQ(
        std::find_if(enum_descriptions_.begin(), enum_descriptions_.end(), f),
        enum_descriptions_.end());
    enum_descriptions_.push_back(std::move(description));
  }

  std::vector<EnumDescription>& EnumDescriptions() {
    return enum_descriptions_;
  }

 private:
  std::vector<Declaration*> declarations_;
  std::vector<std::unique_ptr<AstNode>> nodes_;
  std::map<SourceId, std::set<SourceId>> declared_imports_;
  std::vector<EnumDescription> enum_descriptions_;
};

static const char* const kThisParameterName = "this";

// A Identifier is a string with a SourcePosition attached.
struct Identifier : AstNode {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(Identifier)
  Identifier(SourcePosition pos, std::string identifier)
      : AstNode(kKind, pos), value(std::move(identifier)) {}
  std::string value;
};

inline std::ostream& operator<<(std::ostream& os, Identifier* id) {
  return os << id->value;
}

struct IdentifierPtrValueEq {
  bool operator()(const Identifier* a, const Identifier* b) {
    return a->value < b->value;
  }
};

struct IdentifierExpression : LocationExpression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(IdentifierExpression)
  IdentifierExpression(SourcePosition pos,
                       std::vector<std::string> namespace_qualification,
                       Identifier* name, std::vector<TypeExpression*> args = {})
      : LocationExpression(kKind, pos),
        namespace_qualification(std::move(namespace_qualification)),
        name(name),
        generic_arguments(std::move(args)) {}
  IdentifierExpression(SourcePosition pos, Identifier* name,
                       std::vector<TypeExpression*> args = {})
      : IdentifierExpression(pos, {}, name, std::move(args)) {}
  bool IsThis() const { return name->value == kThisParameterName; }

  void VisitAllSubExpressions(VisitCallback callback) override {
    callback(this);
  }

  std::vector<std::string> namespace_qualification;
  Identifier* name;
  std::vector<TypeExpression*> generic_arguments;
};

struct IntrinsicCallExpression : Expression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(IntrinsicCallExpression)
  IntrinsicCallExpression(SourcePosition pos, Identifier* name,
                          std::vector<TypeExpression*> generic_arguments,
                          std::vector<Expression*> arguments)
      : Expression(kKind, pos),
        name(name),
        generic_arguments(std::move(generic_arguments)),
        arguments(std::move(arguments)) {}

  void VisitAllSubExpressions(VisitCallback callback) override {
    for (auto argument : arguments) {
      argument->VisitAllSubExpressions(callback);
    }
    callback(this);
  }

  Identifier* name;
  std::vector<TypeExpression*> generic_arguments;
  std::vector<Expression*> arguments;
};

struct CallMethodExpression : Expression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(CallMethodExpression)
  CallMethodExpression(SourcePosition pos, Expression* target,
                       IdentifierExpression* method,
                       std::vector<Expression*> arguments,
                       std::vector<Identifier*> labels)
      : Expression(kKind, pos),
        target(target),
        method(method),
        arguments(std::move(arguments)),
        labels(std::move(labels)) {}

  void VisitAllSubExpressions(VisitCallback callback) override {
    target->VisitAllSubExpressions(callback);
    method->VisitAllSubExpressions(callback);
    for (auto argument : arguments) {
      argument->VisitAllSubExpressions(callback);
    }
    callback(this);
  }

  Expression* target;
  IdentifierExpression* method;
  std::vector<Expression*> arguments;
  std::vector<Identifier*> labels;
};

struct CallExpression : Expression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(CallExpression)
  CallExpression(SourcePosition pos, IdentifierExpression* callee,
                 std::vector<Expression*> arguments,
                 std::vector<Identifier*> labels)
      : Expression(kKind, pos),
        callee(callee),
        arguments(std::move(arguments)),
        labels(std::move(labels)) {}

  void VisitAllSubExpressions(VisitCallback callback) override {
    callee->VisitAllSubExpressions(callback);
    for (auto argument : arguments) {
      argument->VisitAllSubExpressions(callback);
    }
    callback(this);
  }

  IdentifierExpression* callee;
  std::vector<Expression*> arguments;
  std::vector<Identifier*> labels;
};

struct NameAndExpression {
  Identifier* name;
  Expression* expression;
};

struct StructExpression : Expression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(StructExpression)
  StructExpression(SourcePosition pos, TypeExpression* type,
                   std::vector<NameAndExpression> initializers)
      : Expression(kKind, pos),
        type(type),
        initializers(std::move(initializers)) {}

  void VisitAllSubExpressions(VisitCallback callback) override {
    for (auto& initializer : initializers) {
      initializer.expression->VisitAllSubExpressions(callback);
    }
    callback(this);
  }

  TypeExpression* type;
  std::vector<NameAndExpression> initializers;
};

struct LogicalOrExpression : Expression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(LogicalOrExpression)
  LogicalOrExpression(SourcePosition pos, Expression* left, Expression* right)
      : Expression(kKind, pos), left(left), right(right) {}

  void VisitAllSubExpressions(VisitCallback callback) override {
    left->VisitAllSubExpressions(callback);
    right->VisitAllSubExpressions(callback);
    callback(this);
  }

  Expression* left;
  Expression* right;
};

struct LogicalAndExpression : Expression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(LogicalAndExpression)
  LogicalAndExpression(SourcePosition pos, Expression* left, Expression* right)
      : Expression(kKind, pos), left(left), right(right) {}

  void VisitAllSubExpressions(VisitCallback callback) override {
    left->VisitAllSubExpressions(callback);
    right->VisitAllSubExpressions(callback);
    callback(this);
  }

  Expression* left;
  Expression* right;
};

struct SpreadExpression : Expression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(SpreadExpression)
  SpreadExpression(SourcePosition pos, Expression* spreadee)
      : Expression(kKind, pos), spreadee(spreadee) {}

  void VisitAllSubExpressions(VisitCallback callback) override {
    spreadee->VisitAllSubExpressions(callback);
    callback(this);
  }

  Expression* spreadee;
};

struct ConditionalExpression : Expression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(ConditionalExpression)
  ConditionalExpression(SourcePosition pos, Expression* condition,
                        Expression* if_true, Expression* if_false)
      : Expression(kKind, pos),
        condition(condition),
        if_true(if_true),
        if_false(if_false) {}

  void VisitAllSubExpressions(VisitCallback callback) override {
    condition->VisitAllSubExpressions(callback);
    if_true->VisitAllSubExpressions(callback);
    if_false->VisitAllSubExpressions(callback);
    callback(this);
  }

  Expression* condition;
  Expression* if_true;
  Expression* if_false;
};

struct StringLiteralExpression : Expression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(StringLiteralExpression)
  StringLiteralExpression(SourcePosition pos, std::string literal)
      : Expression(kKind, pos), literal(std::move(literal)) {}

  void VisitAllSubExpressions(VisitCallback callback) override {
    callback(this);
  }

  std::string literal;
};

struct IntegerLiteralExpression : Expression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(IntegerLiteralExpression)
  IntegerLiteralExpression(SourcePosition pos, IntegerLiteral value)
      : Expression(kKind, pos), value(std::move(value)) {}

  void VisitAllSubExpressions(VisitCallback callback) override {
    callback(this);
  }

  IntegerLiteral value;
};

struct FloatingPointLiteralExpression : Expression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(FloatingPointLiteralExpression)
  FloatingPointLiteralExpression(SourcePosition pos, double value)
      : Expression(kKind, pos), value(value) {}

  void VisitAllSubExpressions(VisitCallback callback) override {
    callback(this);
  }

  double value;
};

struct ElementAccessExpression : LocationExpression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(ElementAccessExpression)
  ElementAccessExpression(SourcePosition pos, Expression* array,
                          Expression* index)
      : LocationExpression(kKind, pos), array(array), index(index) {}

  void VisitAllSubExpressions(VisitCallback callback) override {
    array->VisitAllSubExpressions(callback);
    index->VisitAllSubExpressions(callback);
    callback(this);
  }

  Expression* array;
  Expression* index;
};

struct FieldAccessExpression : LocationExpression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(FieldAccessExpression)
  FieldAccessExpression(SourcePosition pos, Expression* object,
                        Identifier* field)
      : LocationExpression(kKind, pos), object(object), field(field) {}

  void VisitAllSubExpressions(VisitCallback callback) override {
    object->VisitAllSubExpressions(callback);
    callback(this);
  }

  Expression* object;
  Identifier* field;
};

struct DereferenceExpression : LocationExpression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(DereferenceExpression)
  DereferenceExpression(SourcePosition pos, Expression* reference)
      : LocationExpression(kKind, pos), reference(reference) {}

  void VisitAllSubExpressions(VisitCallback callback) override {
    reference->VisitAllSubExpressions(callback);
    callback(this);
  }

  Expression* reference;
};

struct AssignmentExpression : Expression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(AssignmentExpression)
  AssignmentExpression(SourcePosition pos, Expression* location,
                       Expression* value)
      : AssignmentExpression(pos, location, std::nullopt, value) {}
  AssignmentExpression(SourcePosition pos, Expression* location,
                       std::optional<std::string> op, Expression* value)
      : Expression(kKind, pos),
        location(location),
        op(std::move(op)),
        value(value) {}

  void VisitAllSubExpressions(VisitCallback callback) override {
    location->VisitAllSubExpressions(callback);
    value->VisitAllSubExpressions(callback);
    callback(this);
  }

  Expression* location;
  std::optional<std::string> op;
  Expression* value;
};

enum class IncrementDecrementOperator { kIncrement, kDecrement };

struct IncrementDecrementExpression : Expression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(IncrementDecrementExpression)
  IncrementDecrementExpression(SourcePosition pos, Expression* location,
                               IncrementDecrementOperator op, bool postfix)
      : Expression(kKind, pos), location(location), op(op), postfix(postfix) {}

  void VisitAllSubExpressions(VisitCallback callback) override {
    location->VisitAllSubExpressions(callback);
    callback(this);
  }

  Expression* location;
  IncrementDecrementOperator op;
  bool postfix;
};

// This expression is only used in the desugaring of typeswitch, and it allows
// to bake in the static information that certain types are impossible at a
// certain position in the control flow.
// The result type is the type of {expression} minus the provided type.
struct AssumeTypeImpossibleExpression : Expression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(AssumeTypeImpossibleExpression)
  AssumeTypeImpossibleExpression(SourcePosition pos,
                                 TypeExpression* excluded_type,
                                 Expression* expression)
      : Expression(kKind, pos),
        excluded_type(excluded_type),
        expression(expression) {}

  void VisitAllSubExpressions(VisitCallback callback) override {
    expression->VisitAllSubExpressions(callback);
    callback(this);
  }

  TypeExpression* excluded_type;
  Expression* expression;
};

struct NewExpression : Expression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(NewExpression)
  NewExpression(SourcePosition pos, TypeExpression* type,
                std::vector<NameAndExpression> initializers, bool pretenured,
                bool clear_padding)
      : Expression(kKind, pos),
        type(type),
        initializers(std::move(initializers)),
        pretenured(pretenured),
        clear_padding(clear_padding) {}

  void VisitAllSubExpressions(VisitCallback callback) override {
    for (auto& initializer : initializers) {
      initializer.expression->VisitAllSubExpressions(callback);
    }
    callback(this);
  }

  TypeExpression* type;
  std::vector<NameAndExpression> initializers;
  bool pretenured;
  bool clear_padding;
};

enum class ImplicitKind { kNoImplicit, kJSImplicit, kImplicit };

struct ParameterList {
  std::vector<Identifier*> names;
  std::vector<TypeExpression*> types;
  ImplicitKind implicit_kind = ImplicitKind::kNoImplicit;
  SourcePosition implicit_kind_pos = SourcePosition::Invalid();
  size_t implicit_count = 0;
  bool has_varargs = false;
  std::string arguments_variable = "";

  static ParameterList Empty() { return {}; }
  std::vector<TypeExpression*> GetImplicitTypes() {
    return std::vector<TypeExpression*>(types.begin(),
                                        types.begin() + implicit_count);
  }
  std::vector<TypeExpression*> GetExplicitTypes() {
    return std::vector<TypeExpression*>(types.begin() + implicit_count,
                                        types.end());
  }
};

struct BasicTypeExpression : TypeExpression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(BasicTypeExpression)
  BasicTypeExpression(SourcePosition pos,
                      std::vector<std::string> namespace_qualification,
                      Identifier* name,
                      std::vector<TypeExpression*> generic_arguments)
      : TypeExpression(kKind, pos),
        namespace_qualification(std::move(namespace_qualification)),
        is_constexpr(IsConstexprName(name->value)),
        name(name),
        generic_arguments(std::move(generic_arguments)) {}
  BasicTypeExpression(SourcePosition pos, Identifier* name)
      : BasicTypeExpression(pos, {}, name, {}) {}
  std::vector<std::string> namespace_qualification;
  bool is_constexpr;
  Identifier* name;
  std::vector<TypeExpression*> generic_arguments;
};

struct FunctionTypeExpression : TypeExpression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(FunctionTypeExpression)
  FunctionTypeExpression(SourcePosition pos,
                         std::vector<TypeExpression*> parameters,
                         TypeExpression* return_type)
      : TypeExpression(kKind, pos),
        parameters(std::move(parameters)),
        return_type(return_type) {}
  std::vector<TypeExpression*> parameters;
  TypeExpression* return_type;
};

// A PrecomputedTypeExpression is never created directly by the parser. Later
// stages can use this to insert AST snippets where the type has already been
// resolved.
class Type;
struct PrecomputedTypeExpression : TypeExpression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(PrecomputedTypeExpression)
  PrecomputedTypeExpression(SourcePosition pos, const Type* type)
      : TypeExpression(kKind, pos), type(type) {}
  const Type* type;
};

struct UnionTypeExpression : TypeExpression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(UnionTypeExpression)
  UnionTypeExpression(SourcePosition pos, TypeExpression* a, TypeExpression* b)
      : TypeExpression(kKind, pos), a(a), b(b) {}
  TypeExpression* a;
  TypeExpression* b;
};

struct ExpressionStatement : Statement {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(ExpressionStatement)
  ExpressionStatement(SourcePosition pos, Expression* expression)
      : Statement(kKind, pos), expression(expression) {}
  Expression* expression;
};

struct IfStatement : Statement {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(IfStatement)
  IfStatement(SourcePosition pos, bool is_constexpr, Expression* condition,
              Statement* if_true, std::optional<Statement*> if_false)
      : Statement(kKind, pos),
        condition(condition),
        is_constexpr(is_constexpr),
        if_true(if_true),
        if_false(if_false) {}
  Expression* condition;
  bool is_constexpr;
  Statement* if_true;
  std::optional<Statement*> if_false;
};

struct WhileStatement : Statement {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(WhileStatement)
  WhileStatement(SourcePosition pos, Expression* condition, Statement* body)
      : Statement(kKind, pos), condition(condition), body(body) {}
  Expression* condition;
  Statement* body;
};

struct ReturnStatement : Statement {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(ReturnStatement)
  ReturnStatement(SourcePosition pos, std::optional<Expression*> value)
      : Statement(kKind, pos), value(value) {}
  std::optional<Expression*> value;
};

struct DebugStatement : Statement {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(DebugStatement)
  enum class Kind { kUnreachable, kDebug };
  DebugStatement(SourcePosition pos, Kind kind)
      : Statement(kKind, pos), kind(kind) {}
  Kind kind;
};

struct AssertStatement : Statement {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(AssertStatement)
  enum class AssertKind { kDcheck, kCheck, kSbxCheck, kStaticAssert };
  AssertStatement(SourcePosition pos, AssertKind kind, Expression* expression,
                  std::string source)
      : Statement(kKind, pos),
        kind(kind),
        expression(expression),
        source(std::move(source)) {}
  AssertKind kind;
  Expression* expression;
  std::string source;
};

struct TailCallStatement : Statement {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(TailCallStatement)
  TailCallStatement(SourcePosition pos, CallExpression* call)
      : Statement(kKind, pos), call(call) {}
  CallExpression* call;
};

struct VarDeclarationStatement : Statement {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(VarDeclarationStatement)
  VarDeclarationStatement(SourcePosition pos, bool const_qualified,
                          Identifier* name, std::optional<TypeExpression*> type,
                          std::optional<Expression*> initializer = std::nullopt)
      : Statement(kKind, pos),
        const_qualified(const_qualified),
        name(name),
        type(type),
        initializer(initializer) {}
  bool const_qualified;
  Identifier* name;
  std::optional<TypeExpression*> type;
  std::optional<Expression*> initializer;
};

struct BreakStatement : Statement {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(BreakStatement)
  explicit BreakStatement(SourcePosition pos) : Statement(kKind, pos) {}
};

struct ContinueStatement : Statement {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(ContinueStatement)
  explicit ContinueStatement(SourcePosition pos) : Statement(kKind, pos) {}
};

struct GotoStatement : Statement {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(GotoStatement)
  GotoStatement(SourcePosition pos, Identifier* label,
                const std::vector<Expression*>& arguments)
      : Statement(kKind, pos), label(label), arguments(std::move(arguments)) {}
  Identifier* label;
  std::vector<Expression*> arguments;
};

struct ForLoopStatement : Statement {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(ForLoopStatement)
  ForLoopStatement(SourcePosition pos, std::optional<Statement*> declaration,
                   std::optional<Expression*> test,
                   std::optional<Statement*> action, Statement* body)
      : Statement(kKind, pos),
        var_declaration(),
        test(std::move(test)),
        action(std::move(action)),
        body(std::move(body)) {
    if (declaration)
      var_declaration = VarDeclarationStatement::cast(*declaration);
  }
  std::optional<VarDeclarationStatement*> var_declaration;
  std::optional<Expression*> test;
  std::optional<Statement*> action;
  Statement* body;
};

struct TryHandler : AstNode {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(TryHandler)
  enum class HandlerKind { kCatch, kLabel };
  TryHandler(SourcePosition pos, HandlerKind handler_kind, Identifier* label,
             const ParameterList& parameters, Statement* body)
      : AstNode(kKind, pos),
        handler_kind(handler_kind),
        label(label),
        parameters(parameters),
        body(std::move(body)) {}
  HandlerKind handler_kind;
  Identifier* label;
  ParameterList parameters;
  Statement* body;
};

struct StatementExpression : Expression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(StatementExpression)
  StatementExpression(SourcePosition pos, Statement* statement)
      : Expression(kKind, pos), statement(statement) {}
  Statement* statement;
};

struct TryLabelExpression : Expression {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(TryLabelExpression)
  TryLabelExpression(SourcePosition pos, Expression* try_expression,
                     TryHandler* label_block)
      : Expression(kKind, pos),
        try_expression(try_expression),
        label_block(label_block) {}
  Expression* try_expression;
  TryHandler* label_block;
};

struct BlockStatement : Statement {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(BlockStatement)
  explicit BlockStatement(SourcePosition pos, bool deferred = false,
                          std::vector<Statement*> statements = {})
      : Statement(kKind, pos),
        deferred(deferred),
        statements(std::move(statements)) {}
  bool deferred;
  std::vector<Statement*> statements;
};

struct TypeDeclaration : Declaration {
  DEFINE_AST_NODE_INNER_BOILERPLATE(TypeDeclaration)
  TypeDeclaration(Kind kKind, SourcePosition pos, Identifier* name)
      : Declaration(kKind, pos), name(name) {}
  Identifier* name;
};

struct InstanceTypeConstraints {
  InstanceTypeConstraints() : value(-1), num_flags_bits(-1) {}
  int value;
  int num_flags_bits;
};

struct AbstractTypeDeclaration : TypeDeclaration {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(AbstractTypeDeclaration)
  AbstractTypeDeclaration(SourcePosition pos, Identifier* name,
                          AbstractTypeFlags flags,
                          std::optional<TypeExpression*> extends,
                          std::optional<std::string> generates)
      : TypeDeclaration(kKind, pos, name),
        flags(flags),
        extends(extends),
        generates(std::move(generates)) {
    CHECK_EQ(IsConstexprName(name->value),
             !!(flags & AbstractTypeFlag::kConstexpr));
  }

  bool IsConstexpr() const { return flags & AbstractTypeFlag::kConstexpr; }
  bool IsTransient() const { return flags & AbstractTypeFlag::kTransient; }

  AbstractTypeFlags flags;
  std::optional<TypeExpression*> extends;
  std::optional<std::string> generates;
};

struct TypeAliasDeclaration : TypeDeclaration {
  DEFINE_AST_NODE_LEAF_BOILERPLATE(TypeAliasDeclaration)
  TypeAliasDeclaration(SourcePosition pos, Identifier* name,
                       TypeExpression* type)
      : TypeDeclaration(kKind, pos, name), type(type) {}
  TypeExpression* type;
};

struct NameAndTypeExpression {
  Identifier* name;
  TypeExpression* type;
};

struct ImplicitParameters {
  Identifier* kind;
  std::vector<NameAndTypeExpression> parameters;
};

struct StructFieldExpression {
  NameAndTypeExpression name_and_type;
  bool const_qualified;
};

struct BitFieldDeclaration {
  NameAndTypeExpression name_and_type;
  int num_bits;
};

enum class ConditionalAnnotationType {
  kPositive,
  kNegative,
};

struct ConditionalAnnotation {
  std::string condition;
  ConditionalAnnotationType type;
};

struct AnnotationParameter {
  std::string string_value;
  int int_value;
  bool is_int;
};

struct Annotation {
  Identifier* name;
  std::optional<AnnotationParameter> param;
};

struct ClassFieldIndexInfo {
  // The expression that can compute how many items are in the indexed field.
  Expression* expr;

  // Whether the field was declared as optional, meaning it can only hold zero
  // or one values, and thus should not require an index expression to access.
  bool optional;
};

struct ClassFieldExpression {
  NameAndTypeExpression name_and_type;
  std::optional<ClassFieldIndexInfo> index;
  std::vector<ConditionalAnnotation> conditions;
  bool custom_weak_marking;
  bool const_qualified;
  FieldSynchronization synchronization;
};

struct LabelAndTypes {
  Identifier* name;
  std::vector<TypeExpression*> types;
};

using LabelAndTypesVector = std::vector<LabelAndTypes>;

struct CallableDeclaration : Declaration {
  CallableDeclaration(AstNode::Kind kind, SourcePosition pos,
                      bool transitioning, Identifier* name,
                      ParameterList parameters, TypeExpression* return_type,
                      LabelAndTypesVector labels)
      : Declaration(kind, pos),
        transitioning(transitioning),
        name(name),
        parameters(std::move(parameters)),
        return_type(return_type),
        labels(std::move(labels)) {}
  DEFINE_AST_NODE_INNER_BOILERPLATE(CallableDeclaration)
  bool transitioning;
  Identifier* name;
  ParameterList parameters;
  TypeExpression* return_type;
  LabelAndTypesVector labels;
};

struct MacroDeclaration : CallableDeclaration {
  DEFINE_AST_NODE_INNER_BOILERPLATE(MacroDeclaration)
  MacroDeclaration(AstNode::Kind kind, SourcePosition pos, bool transitioning,
```