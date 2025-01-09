Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Understand the Goal:** The primary goal is to explain the functionality of `v8/src/torque/declarable.h`. This involves identifying its key components, their purpose, and how they relate to Torque and potentially JavaScript.

2. **Initial Scan and Identification of Key Concepts:**  Read through the header file, looking for keywords, class names, and common patterns. Immediately noticeable elements include:
    * `#ifndef V8_TORQUE_DECLARABLE_H_` (header guard)
    * `#include` directives (dependencies)
    * `namespace v8::internal::torque` (namespace)
    * Classes like `Declarable`, `Scope`, `Namespace`, `Callable`, `Macro`, `Builtin`, `TypeAlias`, `GenericCallable`, `GenericType`, `Value`, `ExternConstant`, `NamespaceConstant`.
    * Enums like `Declarable::Kind` and `Builtin::Kind`.
    * Structs like `QualifiedName` and `SpecializationRequester`.
    * Macros like `DECLARE_DECLARABLE_BOILERPLATE`.

3. **Focus on the Core Class: `Declarable`:**  The name "Declarable" strongly suggests this is the base class for things that can be declared in the Torque language. Examine its members:
    * `Kind kind_`:  An enum indicating the type of declarable. This is crucial for understanding the different kinds of things Torque can declare.
    * `ParentScope()`:  Indicates a hierarchical structure (scoping).
    * `Position()` and `IdentifierPosition()`:  Information about the location of the declaration in the source code, important for error reporting and debugging.
    * `IsUserDefined()`:  Distinguishes between user-written code and potentially built-in or generated elements.
    * Virtual functions:  Suggests polymorphism and inheritance, meaning different kinds of declarables will have specialized behavior.

4. **Explore the Hierarchy:**  Note the inheritance relationships: `Scope` inherits from `Declarable`, `Namespace` inherits from `Scope`, `Callable` inherits from `Scope`, `Macro` inherits from `Callable`, and so on. This hierarchical structure is key to understanding how different language elements are organized and share common properties.

5. **Analyze Each Class Individually:** Go through each class, understanding its purpose and specific members:
    * **`QualifiedName`:** Represents a name that might include a namespace prefix. The `Parse` method and the `DropFirstNamespaceQualification` method are important for handling namespaced identifiers.
    * **`Scope`:** Represents a lexical scope, holding a collection of `Declarable` objects. The `LookupShallow` and `Lookup` methods are fundamental for symbol resolution.
    * **`Namespace`:**  A specific type of scope used for organizing code into logical groups.
    * **`Value`:** Represents a constant value with a type.
    * **`NamespaceConstant` and `ExternConstant`:** Specific kinds of values, potentially with different origins (within the current namespace vs. external).
    * **`Callable`:** The base class for functions, macros, and builtins. It includes information about the signature (parameters, return type, labels), whether it has a body, and how it should be handled during code generation.
    * **`Macro`, `ExternMacro`, `TorqueMacro`, `Method`:** Different types of callable entities with varying characteristics (Torque-defined vs. externally defined, associated with a type, etc.).
    * **`Builtin`, `RuntimeFunction`, `Intrinsic`:**  Callable entities with specific roles within the V8 runtime.
    * **`TypeAlias`:**  A way to give an existing type a new name.
    * **`GenericCallable`, `GenericType`:**  Represent parameterized functions and types, allowing for code reuse with different type arguments.
    * **`SpecializationRequester`:**  Used for tracking the origin of specializations, helpful for error reporting in generic contexts.

6. **Connect to Torque and JavaScript:**  Consider how these elements relate to the Torque language:
    * Torque uses a syntax that allows declaring namespaces, functions (macros, builtins), types, and constants. The classes in this header directly correspond to these concepts.
    * Torque is used to generate C++ code for V8. The `CCName` and `CCDebugName` methods in `Callable` and its subclasses, along with the `OutputType` enum, hint at this code generation aspect.
    * Builtins are often wrappers around fundamental JavaScript operations or internal V8 functions.

7. **Consider Potential JavaScript Connections:** Think about the JavaScript equivalents of these concepts:
    * Namespaces in Torque might relate to object properties or modules in JavaScript.
    * Torque macros and builtins are used to implement JavaScript built-in functions and methods.
    * Torque types correspond to internal V8 object representations and JavaScript data types.
    * Generic types and callables in Torque are analogous to generic functions and classes in languages like TypeScript (though JavaScript itself doesn't have built-in generics in the same way).

8. **Look for Code Logic and Assumptions:**
    * The `QualifiedName::Parse` method suggests parsing of namespaced identifiers.
    * The `Scope::Lookup` methods implement symbol resolution, searching for declarations within the current and parent scopes.
    * The `GenericDeclarable` class and its specializations involve type checking and instantiation based on type arguments.

9. **Identify Potential User Errors:** Think about how a Torque developer might misuse these features:
    * Name collisions in scopes.
    * Incorrect type arguments for generic functions or types.
    * Trying to access declarations that are not in the current scope.

10. **Organize and Explain:**  Structure the explanation logically, starting with the overall purpose and then detailing each component. Use examples (even if high-level) to illustrate the concepts. Address the specific points in the prompt (Torque file extension, JavaScript relevance, code logic, user errors).

11. **Refine and Review:** Read through the explanation to ensure clarity, accuracy, and completeness. Check for any jargon that needs further explanation.

By following these steps, you can systematically analyze a complex header file like `declarable.h` and extract its essential functionality and purpose within the larger context of the V8 JavaScript engine and the Torque language.
这个`v8/src/torque/declarable.h` 文件是 V8 JavaScript 引擎中 Torque 语言的一个关键头文件。它定义了 Torque 语言中可以声明的各种实体的抽象基类和相关的类。

**主要功能:**

1. **定义了 `Declarable` 抽象基类:**  `Declarable` 是所有可以在 Torque 中声明的元素的基类。它提供了一些通用的属性和方法，例如：
   - `Kind`:  枚举类型，表示声明的类型（例如，命名空间、Torque 宏、外部宏、内置函数等）。
   - `ParentScope()`:  指向声明所在作用域的指针，用于实现作用域查找。
   - `Position()` 和 `IdentifierPosition()`:  记录声明在源代码中的位置，用于错误报告。
   - `IsUserDefined()`:  指示声明是否由用户定义。

2. **定义了各种继承自 `Declarable` 的子类，代表 Torque 中不同类型的声明:** 这些子类代表了 Torque 语言的各种构建块，例如：
   - **`Namespace`:**  表示 Torque 中的命名空间，用于组织代码。
   - **`Callable`:**  表示可调用的实体，是 `Macro`、`Builtin`、`RuntimeFunction` 和 `Intrinsic` 的基类。
   - **`Macro` (及其子类 `TorqueMacro` 和 `ExternMacro`)**: 表示 Torque 宏，类似于函数，可以有自己的代码体。`TorqueMacro` 是用 Torque 语言编写的宏，而 `ExternMacro` 是对外部 C++ 函数的封装。`Method` 是与特定类型关联的宏。
   - **`Builtin`:** 表示内置函数，通常是对 V8 引擎内部功能的封装，可以直接在 Torque 代码中使用。
   - **`RuntimeFunction`:** 表示 V8 运行时函数，是 V8 引擎提供的在运行时执行的函数。
   - **`Intrinsic`:**  表示 Torque 的内联函数，通常用于执行一些底层的操作。
   - **`Value` (及其子类 `NamespaceConstant` 和 `ExternConstant`)**: 表示常量值。`NamespaceConstant` 是在 Torque 命名空间中定义的常量，而 `ExternConstant` 是从外部（例如，C++ 代码）导入的常量。
   - **`TypeAlias`:**  表示类型别名，允许为现有类型定义一个新的名称。
   - **`GenericCallable` 和 `GenericType`:** 表示泛型函数和泛型类型，允许在不指定具体类型的情况下定义函数和类型，然后在需要时进行特化。

3. **定义了 `Scope` 类:** `Scope` 表示一个作用域，可以包含多个 `Declarable` 对象。它是实现符号查找的关键，允许在当前作用域和父作用域中查找声明。

4. **定义了 `QualifiedName` 结构体:**  用于表示带有可选命名空间限定符的名字，例如 `std::vector`。

5. **定义了 `SpecializationRequester` 结构体:**  用于跟踪泛型特化的请求者，帮助进行错误报告。

**如果 `v8/src/torque/declarable.h` 以 `.tq` 结尾：**

如果文件以 `.tq` 结尾，那么它的内容将会是 **Torque 源代码**，而不是 C++ 头文件。这个 `.h` 文件定义的是 Torque 语言的内部表示和数据结构，用于 Torque 编译器理解和处理 Torque 代码。

**与 JavaScript 功能的关系 (示例):**

Torque 的主要目的是为 V8 引擎生成高效的 C++ 代码，特别是用于实现 JavaScript 的内置对象和操作。`declarable.h` 中定义的各种声明类型都与 JavaScript 的功能息息相关。

例如：

- **`Builtin`**:  许多 JavaScript 的全局函数和对象方法都是通过 Torque 的 `Builtin` 来实现的。
  ```javascript
  // JavaScript 中的 Array.prototype.push 方法
  const arr = [1, 2, 3];
  arr.push(4); // 这个操作的底层实现可能涉及一个 Torque Builtin
  ```

- **`Macro`**:  一些复杂的 JavaScript 操作可能由多个 Torque 宏组合而成。

- **`TypeAlias`**:  Torque 中的类型别名可以对应 JavaScript 中概念上的类型或内部 V8 对象的表示。

**代码逻辑推理 (假设输入与输出):**

假设有一个 Torque 源代码片段：

```torque
namespace foo {
  const kMagicNumber: int31 = 42;

  macro Add(a: int31, b: int31): int31 {
    return a + b;
  }
}

const globalValue: float64 = 3.14;
```

当 Torque 编译器解析这段代码时，`declarable.h` 中定义的类将被用来创建内部表示：

**假设输入:** 上述 Torque 代码片段的抽象语法树 (AST)。

**输出 (部分):**

- 创建一个 `Namespace` 对象，名为 "foo"。
- 在 "foo" 命名空间的作用域中，创建一个 `NamespaceConstant` 对象，名为 "kMagicNumber"，类型为 `int31`，值为 42。
- 在 "foo" 命名空间的作用域中，创建一个 `TorqueMacro` 对象，名为 "Add"，参数类型为 `int31` 和 `int31`，返回类型为 `int31`，并包含表示 `a + b` 的语句。
- 在全局作用域中，创建一个 `NamespaceConstant` 对象，名为 "globalValue"，类型为 `float64`，值为 3.14。

**用户常见的编程错误 (如果用户编写 Torque 代码):**

虽然 `declarable.h` 是 V8 引擎内部的头文件，普通 JavaScript 开发者不会直接接触，但 Torque 开发者在使用 Torque 语言时可能会犯以下错误，这些错误与 `declarable.h` 中定义的概念有关：

1. **命名冲突:** 在同一个作用域内声明了相同名称的 `Declarable` 对象，例如：
   ```torque
   const x: int31 = 10;
   macro x(): void {} // 错误：与常量 x 命名冲突
   ```

2. **类型不匹配:** 在使用 `Callable` 对象时，提供的参数类型与声明的签名不匹配。
   ```torque
   macro Print(value: string): void { ... }
   // ...
   Print(123); // 错误：期望字符串，但提供了数字
   ```

3. **作用域错误:** 尝试访问当前作用域不可见的 `Declarable` 对象。
   ```torque
   namespace foo {
     const secret: int31 = 100;
   }

   macro AccessSecret(): int31 {
     return foo::secret; // 假设 AccessSecret 不在 foo 命名空间内
   }
   ```

4. **泛型特化错误:**  为泛型 `Callable` 或 `Type` 提供了不满足约束的类型参数。

**总结:**

`v8/src/torque/declarable.h` 是 V8 中 Torque 语言的核心定义文件，它描述了 Torque 语言中可以声明的各种元素及其属性。理解这个文件对于深入了解 Torque 编译器的工作原理以及 V8 引擎中 JavaScript 功能的实现至关重要。 虽然 JavaScript 开发者不会直接修改这个文件，但它背后的概念直接影响着 JavaScript 的执行效率和底层实现方式。

Prompt: 
```
这是目录为v8/src/torque/declarable.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/declarable.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_TORQUE_DECLARABLE_H_
#define V8_TORQUE_DECLARABLE_H_

#include <cassert>
#include <optional>
#include <string>
#include <unordered_map>

#include "src/base/functional.h"
#include "src/base/logging.h"
#include "src/torque/ast.h"
#include "src/torque/types.h"
#include "src/torque/utils.h"

namespace v8::internal::torque {

class Scope;
class Namespace;
class TypeArgumentInference;

DECLARE_CONTEXTUAL_VARIABLE(CurrentScope, Scope*);

struct QualifiedName {
  std::vector<std::string> namespace_qualification;
  std::string name;

  QualifiedName(std::vector<std::string> namespace_qualification,
                std::string name)
      : namespace_qualification(std::move(namespace_qualification)),
        name(std::move(name)) {}
  explicit QualifiedName(std::string name)
      : QualifiedName({}, std::move(name)) {}

  static QualifiedName Parse(std::string qualified_name);

  bool HasNamespaceQualification() const {
    return !namespace_qualification.empty();
  }

  QualifiedName DropFirstNamespaceQualification() const {
    return QualifiedName{
        std::vector<std::string>(namespace_qualification.begin() + 1,
                                 namespace_qualification.end()),
        name};
  }

  friend std::ostream& operator<<(std::ostream& os, const QualifiedName& name);
};

class Declarable {
 public:
  virtual ~Declarable() = default;
  enum Kind {
    kNamespace,
    kTorqueMacro,
    kExternMacro,
    kMethod,
    kBuiltin,
    kRuntimeFunction,
    kIntrinsic,
    kGenericCallable,
    kGenericType,
    kTypeAlias,
    kExternConstant,
    kNamespaceConstant
  };
  Kind kind() const { return kind_; }
  bool IsNamespace() const { return kind() == kNamespace; }
  bool IsMacro() const { return IsTorqueMacro() || IsExternMacro(); }
  bool IsTorqueMacro() const { return kind() == kTorqueMacro || IsMethod(); }
  bool IsMethod() const { return kind() == kMethod; }
  bool IsExternMacro() const { return kind() == kExternMacro; }
  bool IsIntrinsic() const { return kind() == kIntrinsic; }
  bool IsBuiltin() const { return kind() == kBuiltin; }
  bool IsRuntimeFunction() const { return kind() == kRuntimeFunction; }
  bool IsGenericCallable() const { return kind() == kGenericCallable; }
  bool IsGenericType() const { return kind() == kGenericType; }
  bool IsTypeAlias() const { return kind() == kTypeAlias; }
  bool IsExternConstant() const { return kind() == kExternConstant; }
  bool IsNamespaceConstant() const { return kind() == kNamespaceConstant; }
  bool IsValue() const { return IsExternConstant() || IsNamespaceConstant(); }
  bool IsScope() const { return IsNamespace() || IsCallable(); }
  bool IsCallable() const {
    return IsMacro() || IsBuiltin() || IsRuntimeFunction() || IsIntrinsic() ||
           IsMethod();
  }
  virtual const char* type_name() const { return "<<unknown>>"; }
  Scope* ParentScope() const { return parent_scope_; }

  // The SourcePosition of the whole declarable. For example, for a macro
  // this will encompass not only the signature, but also the body.
  SourcePosition Position() const { return position_; }
  void SetPosition(const SourcePosition& position) { position_ = position; }

  // The SourcePosition of the identifying name of the declarable. For example,
  // for a macro this will be the SourcePosition of the name.
  // Note that this SourcePosition might not make sense for all kinds of
  // declarables, in that case, the default SourcePosition is returned.
  SourcePosition IdentifierPosition() const {
    return identifier_position_.source.IsValid() ? identifier_position_
                                                 : position_;
  }
  void SetIdentifierPosition(const SourcePosition& position) {
    identifier_position_ = position;
  }

  bool IsUserDefined() const { return is_user_defined_; }
  void SetIsUserDefined(bool is_user_defined) {
    is_user_defined_ = is_user_defined;
  }

 protected:
  explicit Declarable(Kind kind) : kind_(kind) {}

 private:
  const Kind kind_;
  Scope* const parent_scope_ = CurrentScope::Get();
  SourcePosition position_ = CurrentSourcePosition::Get();
  SourcePosition identifier_position_ = SourcePosition::Invalid();
  bool is_user_defined_ = true;
};

#define DECLARE_DECLARABLE_BOILERPLATE(x, y)                  \
  static x* cast(Declarable* declarable) {                    \
    DCHECK(declarable->Is##x());                              \
    return static_cast<x*>(declarable);                       \
  }                                                           \
  static const x* cast(const Declarable* declarable) {        \
    DCHECK(declarable->Is##x());                              \
    return static_cast<const x*>(declarable);                 \
  }                                                           \
  const char* type_name() const override { return #y; }       \
  static x* DynamicCast(Declarable* declarable) {             \
    if (!declarable) return nullptr;                          \
    if (!declarable->Is##x()) return nullptr;                 \
    return static_cast<x*>(declarable);                       \
  }                                                           \
  static const x* DynamicCast(const Declarable* declarable) { \
    if (!declarable) return nullptr;                          \
    if (!declarable->Is##x()) return nullptr;                 \
    return static_cast<const x*>(declarable);                 \
  }

// Information about what code caused a specialization to exist. This is used
// for error reporting.
struct SpecializationRequester {
  // The position of the expression that caused this specialization.
  SourcePosition position;
  // The Scope which contains the expression that caused this specialization.
  // It may in turn also be within a specialization, which allows us to print
  // the stack of requesters when an error occurs.
  Scope* scope;
  // The name of the specialization.
  std::string name;

  static SpecializationRequester None() {
    return {SourcePosition::Invalid(), nullptr, ""};
  }

  bool IsNone() const {
    return position == SourcePosition::Invalid() && scope == nullptr &&
           name == "";
  }
  SpecializationRequester(SourcePosition position, Scope* scope,
                          std::string name);
};

class Scope : public Declarable {
 public:
  DECLARE_DECLARABLE_BOILERPLATE(Scope, scope)
  explicit Scope(Declarable::Kind kind) : Declarable(kind) {}

  std::vector<Declarable*> LookupShallow(const QualifiedName& name) {
    if (!name.HasNamespaceQualification()) return declarations_[name.name];
    Scope* child = nullptr;
    for (Declarable* declarable :
         declarations_[name.namespace_qualification.front()]) {
      if (Scope* scope = Scope::DynamicCast(declarable)) {
        if (child != nullptr) {
          ReportError("ambiguous reference to scope ",
                      name.namespace_qualification.front());
        }
        child = scope;
      }
    }
    if (child == nullptr) return {};
    return child->LookupShallow(name.DropFirstNamespaceQualification());
  }

  std::vector<Declarable*> Lookup(const QualifiedName& name);
  template <class T>
  T* AddDeclarable(const std::string& name, T* declarable) {
    declarations_[name].push_back(declarable);
    return declarable;
  }

  const SpecializationRequester& GetSpecializationRequester() const {
    return requester_;
  }
  void SetSpecializationRequester(const SpecializationRequester& requester) {
    requester_ = requester;
  }

 private:
  std::unordered_map<std::string, std::vector<Declarable*>> declarations_;

  // If this Scope was created for specializing a generic type or callable,
  // then {requester_} refers to the place that caused the specialization so we
  // can construct useful error messages.
  SpecializationRequester requester_ = SpecializationRequester::None();
};

class Namespace : public Scope {
 public:
  DECLARE_DECLARABLE_BOILERPLATE(Namespace, namespace)
  explicit Namespace(const std::string& name)
      : Scope(Declarable::kNamespace), name_(name) {}
  const std::string& name() const { return name_; }
  bool IsDefaultNamespace() const;
  bool IsTestNamespace() const;

 private:
  std::string name_;
};

inline Namespace* CurrentNamespace() {
  Scope* scope = CurrentScope::Get();
  while (true) {
    if (Namespace* n = Namespace::DynamicCast(scope)) {
      return n;
    }
    scope = scope->ParentScope();
  }
}

class Value : public Declarable {
 public:
  DECLARE_DECLARABLE_BOILERPLATE(Value, value)
  const Identifier* name() const { return name_; }
  virtual bool IsConst() const { return true; }
  VisitResult value() const { return *value_; }
  const Type* type() const { return type_; }

  void set_value(VisitResult value) {
    DCHECK(!value_);
    value_ = value;
  }

 protected:
  Value(Kind kind, const Type* type, Identifier* name)
      : Declarable(kind), type_(type), name_(name) {}

 private:
  const Type* type_;
  Identifier* name_;
  std::optional<VisitResult> value_;
};

class NamespaceConstant : public Value {
 public:
  DECLARE_DECLARABLE_BOILERPLATE(NamespaceConstant, constant)

  const std::string& external_name() const { return external_name_; }
  Expression* body() const { return body_; }

 private:
  friend class Declarations;
  explicit NamespaceConstant(Identifier* constant_name,
                             std::string external_name, const Type* type,
                             Expression* body)
      : Value(Declarable::kNamespaceConstant, type, constant_name),
        external_name_(std::move(external_name)),
        body_(body) {}

  std::string external_name_;
  Expression* body_;
};

class ExternConstant : public Value {
 public:
  DECLARE_DECLARABLE_BOILERPLATE(ExternConstant, constant)

 private:
  friend class Declarations;
  explicit ExternConstant(Identifier* name, const Type* type, std::string value)
      : Value(Declarable::kExternConstant, type, name) {
    set_value(VisitResult(type, std::move(value)));
  }
};

enum class OutputType {
  kCSA,
  kCC,
  kCCDebug,
};

class Callable : public Scope {
 public:
  DECLARE_DECLARABLE_BOILERPLATE(Callable, callable)
  const std::string& ExternalName() const { return external_name_; }
  const std::string& ReadableName() const { return readable_name_; }
  const Signature& signature() const { return signature_; }
  bool IsTransitioning() const { return signature().transitioning; }
  const NameVector& parameter_names() const {
    return signature_.parameter_names;
  }
  bool HasReturnValue() const {
    return !signature_.return_type->IsVoidOrNever();
  }
  void IncrementReturns() { ++returns_; }
  bool HasReturns() const { return returns_; }
  std::optional<Statement*> body() const { return body_; }
  bool IsExternal() const { return !body_.has_value(); }
  virtual bool ShouldBeInlined(OutputType output_type) const {
    // C++ output doesn't support exiting to labels, so functions with labels in
    // the signature must be inlined.
    return output_type == OutputType::kCC && !signature().labels.empty();
  }
  bool ShouldGenerateExternalCode(OutputType output_type) const {
    return !ShouldBeInlined(output_type);
  }

  static std::string PrefixNameForCCOutput(const std::string& name) {
    // If a Torque macro requires a C++ runtime function to be generated, then
    // the generated function begins with this prefix to avoid any naming
    // collisions with the generated CSA function for the same macro.
    return "TqRuntime" + name;
  }

  static std::string PrefixNameForCCDebugOutput(const std::string& name) {
    // If a Torque macro requires a C++ runtime function to be generated, then
    // the generated function begins with this prefix to avoid any naming
    // collisions with the generated CSA function for the same macro.
    return "TqDebug" + name;
  }

  // Name to use in runtime C++ code.
  virtual std::string CCName() const {
    return PrefixNameForCCOutput(ExternalName());
  }

  // Name to use in debug C++ code.
  virtual std::string CCDebugName() const {
    return PrefixNameForCCDebugOutput(ExternalName());
  }

 protected:
  Callable(Declarable::Kind kind, std::string external_name,
           std::string readable_name, Signature signature,
           std::optional<Statement*> body)
      : Scope(kind),
        external_name_(std::move(external_name)),

        readable_name_(std::move(readable_name)),
        signature_(std::move(signature)),
        returns_(0),
        body_(body) {
    DCHECK(!body || *body);
  }

 private:
  std::string external_name_;
  std::string readable_name_;
  Signature signature_;
  size_t returns_;
  std::optional<Statement*> body_;
};

class Macro : public Callable {
 public:
  DECLARE_DECLARABLE_BOILERPLATE(Macro, macro)
  bool ShouldBeInlined(OutputType output_type) const override {
    for (const LabelDeclaration& label : signature().labels) {
      for (const Type* type : label.types) {
        if (type->StructSupertype()) return true;
      }
    }
    // Intrinsics that are used internally in Torque and implemented as torque
    // code should be inlined and not generate C++ definitions.
    if (ReadableName()[0] == '%') return true;
    return Callable::ShouldBeInlined(output_type);
  }

  void SetUsed() { used_ = true; }
  bool IsUsed() const { return used_; }

 protected:
  Macro(Declarable::Kind kind, std::string external_name,
        std::string readable_name, const Signature& signature,
        std::optional<Statement*> body)
      : Callable(kind, std::move(external_name), std::move(readable_name),
                 signature, body),
        used_(false) {
    if (signature.parameter_types.var_args) {
      ReportError("Varargs are not supported for macros.");
    }
  }

 private:
  bool used_;
};

class ExternMacro : public Macro {
 public:
  DECLARE_DECLARABLE_BOILERPLATE(ExternMacro, ExternMacro)

  const std::string& external_assembler_name() const {
    return external_assembler_name_;
  }

  std::string CCName() const override {
    return "TorqueRuntimeMacroShims::" + external_assembler_name() +
           "::" + ExternalName();
  }

  std::string CCDebugName() const override {
    return "TorqueDebugMacroShims::" + external_assembler_name() +
           "::" + ExternalName();
  }

 private:
  friend class Declarations;
  ExternMacro(const std::string& name, std::string external_assembler_name,
              Signature signature)
      : Macro(Declarable::kExternMacro, name, name, std::move(signature),
              std::nullopt),
        external_assembler_name_(std::move(external_assembler_name)) {}

  std::string external_assembler_name_;
};

class TorqueMacro : public Macro {
 public:
  DECLARE_DECLARABLE_BOILERPLATE(TorqueMacro, TorqueMacro)
  bool IsExportedToCSA() const { return exported_to_csa_; }
  std::string CCName() const override {
    // Exported functions must have unique and C++-friendly readable names, so
    // prefer those wherever possible.
    return PrefixNameForCCOutput(IsExportedToCSA() ? ReadableName()
                                                   : ExternalName());
  }
  std::string CCDebugName() const override {
    // Exported functions must have unique and C++-friendly readable names, so
    // prefer those wherever possible.
    return PrefixNameForCCDebugOutput(IsExportedToCSA() ? ReadableName()
                                                        : ExternalName());
  }

 protected:
  TorqueMacro(Declarable::Kind kind, std::string external_name,
              std::string readable_name, const Signature& signature,
              std::optional<Statement*> body, bool is_user_defined,
              bool exported_to_csa)
      : Macro(kind, std::move(external_name), std::move(readable_name),
              signature, body),
        exported_to_csa_(exported_to_csa) {
    SetIsUserDefined(is_user_defined);
  }

 private:
  friend class Declarations;
  TorqueMacro(std::string external_name, std::string readable_name,
              const Signature& signature, std::optional<Statement*> body,
              bool is_user_defined, bool exported_to_csa)
      : TorqueMacro(Declarable::kTorqueMacro, std::move(external_name),
                    std::move(readable_name), signature, body, is_user_defined,
                    exported_to_csa) {}

  bool exported_to_csa_ = false;
};

class Method : public TorqueMacro {
 public:
  DECLARE_DECLARABLE_BOILERPLATE(Method, Method)
  bool ShouldBeInlined(OutputType output_type) const override {
    return Macro::ShouldBeInlined(output_type) ||
           signature()
               .parameter_types.types[signature().implicit_count]
               ->IsStructType();
  }
  AggregateType* aggregate_type() const { return aggregate_type_; }

 private:
  friend class Declarations;
  Method(AggregateType* aggregate_type, std::string external_name,
         std::string readable_name, const Signature& signature, Statement* body)
      : TorqueMacro(Declarable::kMethod, std::move(external_name),
                    std::move(readable_name), signature, body, true, false),
        aggregate_type_(aggregate_type) {}
  AggregateType* aggregate_type_;
};

class Builtin : public Callable {
 public:
  enum Kind { kStub, kFixedArgsJavaScript, kVarArgsJavaScript };
  enum class Flag { kNone = 0, kCustomInterfaceDescriptor = 1 << 0 };
  using Flags = base::Flags<Flag>;
  DECLARE_DECLARABLE_BOILERPLATE(Builtin, builtin)
  Kind kind() const { return kind_; }
  Flags flags() const { return flags_; }
  std::optional<std::string> use_counter_name() const {
    return use_counter_name_;
  }
  bool IsStub() const { return kind_ == kStub; }
  bool IsVarArgsJavaScript() const { return kind_ == kVarArgsJavaScript; }
  bool IsFixedArgsJavaScript() const { return kind_ == kFixedArgsJavaScript; }
  bool IsJavaScript() const {
    return IsVarArgsJavaScript() || IsFixedArgsJavaScript();
  }
  bool HasCustomInterfaceDescriptor() const {
    return flags_ & Flag::kCustomInterfaceDescriptor;
  }

 private:
  friend class Declarations;
  Builtin(std::string external_name, std::string readable_name,
          Builtin::Kind kind, Flags flags, const Signature& signature,
          std::optional<std::string> use_counter_name,
          std::optional<Statement*> body)
      : Callable(Declarable::kBuiltin, std::move(external_name),
                 std::move(readable_name), signature, body),
        kind_(kind),
        flags_(flags),
        use_counter_name_(use_counter_name) {}

  Kind kind_;
  Flags flags_;
  std::optional<std::string> use_counter_name_;
};

class RuntimeFunction : public Callable {
 public:
  DECLARE_DECLARABLE_BOILERPLATE(RuntimeFunction, runtime)

 private:
  friend class Declarations;
  RuntimeFunction(const std::string& name, const Signature& signature)
      : Callable(Declarable::kRuntimeFunction, name, name, signature,
                 std::nullopt) {}
};

class Intrinsic : public Callable {
 public:
  DECLARE_DECLARABLE_BOILERPLATE(Intrinsic, intrinsic)

 private:
  friend class Declarations;
  Intrinsic(std::string name, const Signature& signature)
      : Callable(Declarable::kIntrinsic, name, name, signature, std::nullopt) {
    if (signature.parameter_types.var_args) {
      ReportError("Varargs are not supported for intrinsics.");
    }
  }
};

class TypeConstraint {
 public:
  std::optional<std::string> IsViolated(const Type*) const;

  static TypeConstraint Unconstrained() { return {}; }
  static TypeConstraint SubtypeConstraint(const Type* upper_bound) {
    TypeConstraint result;
    result.upper_bound = {upper_bound};
    return result;
  }

 private:
  std::optional<const Type*> upper_bound;
};

std::optional<std::string> FindConstraintViolation(
    const std::vector<const Type*>& types,
    const std::vector<TypeConstraint>& constraints);

std::vector<TypeConstraint> ComputeConstraints(
    Scope* scope, const GenericParameters& parameters);

template <class SpecializationType, class DeclarationType>
class GenericDeclarable : public Declarable {
 private:
  using Map = std::unordered_map<TypeVector, SpecializationType,
                                 base::hash<TypeVector>>;

 public:
  void AddSpecialization(const TypeVector& type_arguments,
                         SpecializationType specialization) {
    DCHECK_EQ(0, specializations_.count(type_arguments));
    if (auto violation =
            FindConstraintViolation(type_arguments, Constraints())) {
      Error(*violation).Throw();
    }
    specializations_[type_arguments] = specialization;
  }
  std::optional<SpecializationType> GetSpecialization(
      const TypeVector& type_arguments) const {
    auto it = specializations_.find(type_arguments);
    if (it != specializations_.end()) return it->second;
    return std::nullopt;
  }

  using iterator = typename Map::const_iterator;
  iterator begin() const { return specializations_.begin(); }
  iterator end() const { return specializations_.end(); }

  const std::string& name() const { return name_; }
  auto declaration() const { return generic_declaration_->declaration; }
  const GenericParameters& generic_parameters() const {
    return generic_declaration_->generic_parameters;
  }

  const std::vector<TypeConstraint>& Constraints() {
    if (!constraints_)
      constraints_ = {ComputeConstraints(ParentScope(), generic_parameters())};
    return *constraints_;
  }

 protected:
  GenericDeclarable(Declarable::Kind kind, const std::string& name,
                    DeclarationType generic_declaration)
      : Declarable(kind),
        name_(name),
        generic_declaration_(generic_declaration) {
    DCHECK(!generic_declaration->generic_parameters.empty());
  }

 private:
  std::string name_;
  DeclarationType generic_declaration_;
  Map specializations_;
  std::optional<std::vector<TypeConstraint>> constraints_;
};

class GenericCallable
    : public GenericDeclarable<Callable*, GenericCallableDeclaration*> {
 public:
  DECLARE_DECLARABLE_BOILERPLATE(GenericCallable, generic_callable)

  std::optional<Statement*> CallableBody();

  TypeArgumentInference InferSpecializationTypes(
      const TypeVector& explicit_specialization_types,
      const std::vector<std::optional<const Type*>>& arguments);

 private:
  friend class Declarations;
  GenericCallable(const std::string& name,
                  GenericCallableDeclaration* generic_declaration)
      : GenericDeclarable<Callable*, GenericCallableDeclaration*>(
            Declarable::kGenericCallable, name, generic_declaration) {}
};

class GenericType
    : public GenericDeclarable<const Type*, GenericTypeDeclaration*> {
 public:
  DECLARE_DECLARABLE_BOILERPLATE(GenericType, generic_type)

 private:
  friend class Declarations;
  GenericType(const std::string& name,
              GenericTypeDeclaration* generic_declaration)
      : GenericDeclarable<const Type*, GenericTypeDeclaration*>(
            Declarable::kGenericType, name, generic_declaration) {}
};

class TypeAlias : public Declarable {
 public:
  DECLARE_DECLARABLE_BOILERPLATE(TypeAlias, type_alias)

  const Type* type() const {
    if (type_) return *type_;
    return Resolve();
  }
  const Type* Resolve() const;
  bool IsRedeclaration() const { return redeclaration_; }
  SourcePosition GetDeclarationPosition() const {
    return declaration_position_;
  }

 private:
  friend class Declarations;
  friend class TypeVisitor;

  explicit TypeAlias(
      const Type* type, bool redeclaration,
      SourcePosition declaration_position = SourcePosition::Invalid())
      : Declarable(Declarable::kTypeAlias),
        type_(type),
        redeclaration_(redeclaration),
        declaration_position_(declaration_position) {}
  explicit TypeAlias(
      TypeDeclaration* type, bool redeclaration,
      SourcePosition declaration_position = SourcePosition::Invalid())
      : Declarable(Declarable::kTypeAlias),
        delayed_(type),
        redeclaration_(redeclaration),
        declaration_position_(declaration_position) {}

  mutable bool being_resolved_ = false;
  mutable std::optional<TypeDeclaration*> delayed_;
  mutable std::optional<const Type*> type_;
  bool redeclaration_;
  const SourcePosition declaration_position_;
};

std::ostream& operator<<(std::ostream& os, const Callable& m);
std::ostream& operator<<(std::ostream& os, const Builtin& b);
std::ostream& operator<<(std::ostream& os, const RuntimeFunction& b);
std::ostream& operator<<(std::ostream& os, const GenericCallable& g);

#undef DECLARE_DECLARABLE_BOILERPLATE

}  // namespace v8::internal::torque

#endif  // V8_TORQUE_DECLARABLE_H_

"""

```