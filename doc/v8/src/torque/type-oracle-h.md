Response:
Let's break down the thought process for analyzing this C++ header file.

**1. Initial Understanding of the Request:**

The request asks for the functionality of `v8/src/torque/type-oracle.h`. Key points include:

* Identifying its purpose within the V8 project.
* Recognizing if it's related to Torque (based on the directory and potential `.tq` extension hint).
* Connecting its functionality to JavaScript if applicable.
* Providing examples, especially in JavaScript, to illustrate the connection.
* Explaining code logic with hypothetical inputs and outputs.
* Highlighting potential programming errors related to the functionality.

**2. High-Level Analysis of the Header File:**

* **Filename and Path:** `v8/src/torque/type-oracle.h` strongly suggests this file is part of Torque, V8's internal language for code generation. The "type oracle" name hints at a component responsible for managing and understanding types within the Torque system.
* **Copyright and License:** Standard V8 header. Confirms it's an official part of the project.
* **Include Guards:** `#ifndef V8_TORQUE_TYPE_ORACLE_H_` prevents multiple inclusions.
* **Includes:**  These are crucial for understanding dependencies and the role of `TypeOracle`. We see includes related to:
    * `memory` and `optional`: Standard C++ for memory management and optional values.
    * `src/base/contextual.h`: Likely for managing context-specific data, hinting at the `TypeOracle` being a singleton or having some form of global state.
    * `src/torque/constants.h`, `src/torque/declarable.h`, `src/torque/declarations.h`, `src/torque/types.h`, `src/torque/utils.h`:  These are Torque-specific headers, confirming the file's purpose within Torque. They suggest `TypeOracle` interacts with declarations, type representations, and potentially some utilities within Torque.
* **Namespace:** `v8::internal::torque` reinforces the Torque context.
* **Class Declaration:** The core of the file is the `TypeOracle` class. The inheritance from `base::ContextualClass<TypeOracle>` strongly suggests a singleton pattern.

**3. Analyzing the `TypeOracle` Class Members (Method by Method):**

This is where the detailed understanding emerges. We go through each public static method and infer its purpose based on its name, parameters, and return type.

* **`GetAbstractType`:** Creates and registers abstract types. Parameters like `parent`, `flags`, `generated`, `non_constexpr_version` provide clues about the nature of abstract types in Torque (potentially related to inheritance, properties, and constexpr evaluation).
* **`GetStructType`, `GetBitFieldStructType`, `GetClassType`:** Similar to `GetAbstractType`, but for specific kinds of composite types (structs, bitfield structs, classes). The parameters link these types to their declarations in Torque.
* **`GetBuiltinPointerType`:** Deals with function pointers. The `TypeVector argument_types` and `return_type` clearly indicate this. The internal caching (`function_pointer_types_`, `all_builtin_pointer_types_`) suggests optimization and uniqueness.
* **`GetGenericTypeInstance`:**  Manages instantiation of generic types. This is a placeholder, indicating this logic is defined elsewhere.
* **`GetReferenceGeneric`, `GetConstReferenceGeneric`, `GetMutableReferenceGeneric`, `MatchReferenceGeneric`, `GetMutableSliceGeneric`, `GetConstSliceGeneric`, `GetWeakGeneric`, `GetSmiTaggedGeneric`, `GetLazyGeneric`:** These methods handle specific built-in generic types like references, slices, and weak references. They interact with the `Declarations` system to look up these pre-defined generics.
* **`GetReferenceType`, `GetConstReferenceType`, `GetMutableReferenceType`, `GetMutableSliceType`, `GetConstSliceType`:** Convenience methods for creating instances of the generic types.
* **`AllBuiltinPointerTypes`:**  Provides access to the cached function pointer types.
* **`GetUnionType` (both versions):**  Manages union types, combining different types. The logic to handle subtypes efficiently is notable.
* **`GetTopType`:** Creates a "top type," often used to represent the most general type or an error condition.
* **`GetArgumentsType`, `GetBoolType`, ..., `GetFixedArrayBaseType`:**  These methods return predefined built-in types within Torque. The names are self-explanatory.
* **`ImplicitlyConvertableFrom`:**  Determines if a type can be implicitly converted from another. It uses a lookup of "from constexpr" macros, hinting at compile-time conversion logic.
* **`GetAggregateTypes`, `GetBitFieldStructTypes`, `GetClasses`:**  Accessors for collections of registered types. The comment about topological sorting of classes is important.
* **`FinalizeAggregateTypes`:**  Likely performs post-processing on aggregate types after they've been registered.
* **`FreshTypeId`:**  Generates unique IDs for types.
* **`CreateGenericTypeInstantiationNamespace`:**  Creates namespaces for instantiating generic types, likely for managing naming and scope.
* **Private Methods:** `GetBuiltinType` (both versions) is used internally to retrieve built-in types.
* **Private Members:**  These are the internal data structures that store the registered types and manage uniqueness. The use of `Deduplicator` is key for efficient storage and comparison of types.

**4. Connecting to JavaScript and Providing Examples:**

Now we link the Torque concepts to their JavaScript counterparts. This involves understanding how Torque is used in V8 to implement JavaScript features.

* **Types:** Torque's types relate to JavaScript's internal representations of values (numbers, strings, objects, functions, etc.).
* **References and Slices:** These relate to how JavaScript engines handle memory and data access. While JavaScript doesn't have explicit pointers in the same way C++ does, the underlying engine uses similar concepts.
* **Generic Types:**  Connect to JavaScript's generic classes or parameterized types (though JavaScript's generics are runtime-based, while Torque's are compile-time).
* **Built-in Types:**  Map directly to JavaScript's primitive types and built-in objects (e.g., `Number`, `String`, `Object`, `Function`).

The JavaScript examples aim to demonstrate the *conceptual* relationship, not a direct one-to-one mapping in syntax.

**5. Code Logic Inference (Hypothetical Input/Output):**

This involves choosing a method and illustrating its behavior. `GetUnionType` is a good example because it has some logic. The thought process is:

* Pick a method with some conditional behavior.
* Define clear input types.
* Trace the execution path based on the input.
* Determine the resulting output type.

**6. Common Programming Errors:**

This requires thinking about how the functionality of `TypeOracle` could be misused or lead to errors *within the Torque compilation process*. Examples include:

* Incorrect type assumptions.
* Trying to use incompatible types.
* Issues with generic type instantiation.

**7. Addressing the `.tq` Extension and Torque Relation:**

The request specifically asks about the `.tq` extension. It's important to explicitly state that `.tq` files are Torque source code and that this `.h` file is part of the Torque infrastructure.

**8. Structuring the Answer:**

Organize the information logically:

* Start with a high-level summary of the file's purpose.
* Explain the key functionalities by categorizing the methods.
* Provide clear JavaScript examples.
* Illustrate code logic with input/output.
* Discuss common programming errors.
* Address the `.tq` extension.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe focus too much on the C++ implementation details. **Correction:** Shift focus to the *functionality* and how it relates to Torque's role in V8.
* **Realization:** The JavaScript examples need to be conceptual, not syntactically equivalent. **Correction:** Frame the examples as illustrating the *idea* behind the Torque types.
* **Considering edge cases:** Think about what happens with null pointers, empty type lists, etc. in the methods. This helps in understanding the robustness of the code.

By following this thought process, one can systematically analyze the header file and provide a comprehensive and informative answer.
`v8/src/torque/type-oracle.h` 是 V8 中 Torque 编译器的核心组件之一，它负责管理和维护 Torque 语言中所有类型的定义和关系。你可以把它想象成 Torque 的“类型系统数据库”。

**功能列举:**

1. **类型注册与存储:** `TypeOracle` 负责注册和存储 Torque 中定义的所有类型，包括：
    * **抽象类型 (AbstractType):**  类似于接口或者抽象基类。
    * **结构体类型 (StructType):**  表示由多个字段组成的复合数据结构。
    * **位域结构体类型 (BitFieldStructType):** 结构体的特殊形式，允许字段占用少于一个字节的位。
    * **类类型 (ClassType):**  表示具有继承关系的类。
    * **内置指针类型 (BuiltinPointerType):**  表示指向特定函数签名的指针。
    * **联合类型 (UnionType):**  表示可以存储多种不同类型的值的类型。
    * **Top 类型 (TopType):**  表示所有类型的超类型，通常用于表示类型推断的起点或错误情况。
    * **内置类型:**  例如 `bool`, `int32`, `string`, `Object` 等在 Torque 中预定义的类型。
    * **泛型类型实例 (GenericTypeInstance):**  例如 `ConstReference<T>`, `MutableSlice<T>` 等。

2. **类型查找与获取:** `TypeOracle` 提供了各种静态方法来获取已注册的类型，例如 `GetAbstractType`, `GetStructType`, `GetBuiltinType` 等。这使得 Torque 编译器的其他部分可以方便地访问和使用类型信息。

3. **类型关系维护:** `TypeOracle` 维护类型之间的关系，例如继承关系 (通过 `parent` 指针)，以及是否可以进行隐式转换 (`ImplicitlyConvertableFrom`)。

4. **泛型类型处理:**  `TypeOracle` 负责处理泛型类型的定义和实例化，例如 `GetReferenceGeneric`, `GetMutableSliceGeneric` 等方法用于获取泛型类型定义，而 `GetGenericTypeInstance` 用于创建特定类型参数的泛型类型实例。

5. **内置类型管理:**  `TypeOracle` 存储和提供对 Torque 内置类型的访问，例如 `GetBoolType`, `GetStringType`, `GetObjectType` 等。

6. **唯一性保证:** 对于某些类型的创建 (例如 `BuiltinPointerType`, `UnionType`)，`TypeOracle` 使用 `Deduplicator` 来确保相同类型的唯一性，避免重复创建。

7. **类型 ID 生成:** `FreshTypeId` 方法用于生成唯一的类型 ID。

**关于 `.tq` 结尾的文件:**

你说的很对。如果 `v8/src/torque/type-oracle.h` 文件以 `.tq` 结尾，那么它将是一个 **Torque 源代码文件**。`.h` 结尾表示这是一个 C++ 头文件，用于声明 `TypeOracle` 类。Torque 编译器会读取 `.tq` 文件并生成相应的 C++ 代码，其中就可能包含对 `TypeOracle` 类的使用。

**与 Javascript 的关系 (并通过 Javascript 举例说明):**

Torque 被 V8 用于实现 JavaScript 的内置函数、操作符和对象。`TypeOracle` 在这个过程中扮演着至关重要的角色，因为它定义了 Torque 中操作的数据类型，这些类型最终会映射到 V8 的内部表示和 JavaScript 的概念。

例如，在 Torque 中，你可能会定义一个表示 JavaScript 数组的类型。`TypeOracle` 会存储这个类型的定义，包括它的字段（例如，存储元素的 `FixedArray`），以及它与其他类型的关系（例如，它是 `JSObject` 的子类型）。

```javascript
// JavaScript 示例

// 当你创建一个 JavaScript 数组时：
const myArray = [1, 2, 3];

// V8 内部 (通过 Torque 实现的概念):
// Torque 可能会定义一个类似这样的类型来表示 JavaScript 数组
// (这只是一个简化的概念性表示):
// class JSArray extends JSObject {
//   elements: FixedArray<Tagged>; // 存储数组元素，Tagged 表示可以是任意 JavaScript 值
//   length: Smi;                // 存储数组长度
// }

// 在 Torque 代码中，可能会使用 TypeOracle 获取 JSArray 类型：
// const jsArrayType = TypeOracle::GetClassType("JSArray");

// 当你访问数组元素时：
const firstElement = myArray[0]; // 访问第一个元素

// V8 内部 (通过 Torque 实现的概念):
// Torque 代码可能会根据 JSArray 类型的定义，知道如何访问 `elements` 字段，
// 并执行相应的操作来获取数组中的第一个元素。
```

**代码逻辑推理 (假设输入与输出):**

假设我们想获取表示 JavaScript 布尔值的 Torque 类型。

**假设输入:** 调用 `TypeOracle::GetBoolType()`

**代码逻辑:** `GetBoolType` 方法会调用私有的 `GetBuiltinType` 方法，并传入预定义的布尔类型名称 `BOOL_TYPE_STRING`。`GetBuiltinType` 会在内部查找已注册的内置类型，如果找到，则返回指向该类型的指针。

**假设输出:** 返回指向 `Bool` 类型的 `const Type*` 指针。这个 `Bool` 类型在 Torque 中可能被定义为内置的原始值类型。

**涉及用户常见的编程错误 (通过 Javascript 举例说明):**

虽然用户不会直接与 `TypeOracle` 交互，但 `TypeOracle` 定义的类型系统会影响 Torque 代码的编写，而 Torque 代码的错误最终可能导致 JavaScript 的行为不符合预期。

一个相关的概念是 **类型错误**。在 JavaScript 中，类型错误通常在运行时发生。Torque 的类型系统旨在在编译时捕获一些潜在的类型不匹配问题，从而避免某些运行时的错误。

**例子：尝试将一个非数字值传递给一个期望数字的 Torque 函数**

假设 Torque 中有一个函数 `Add(Number a, Number b)`，它期望两个 `Number` 类型的参数。

```javascript
// JavaScript 示例

function add(a, b) {
  return a + b;
}

const result = add(5, "hello"); // JavaScript 不会立即报错，会将 "hello" 转换为数字 NaN

// 在 Torque 实现 `add` 函数时 (概念性例子):
// 如果 Torque 的类型系统强制要求参数是 Number 类型：
// Torque 函数 Add(Number a, Number b) {
//   // ... 执行加法操作
// }

// 如果传递的参数类型不匹配，Torque 编译器可能会报错，
// 提示类型不匹配，从而在编译时发现潜在的错误。

// 用户在编写 Torque 代码时，如果错误地使用了类型，
// 例如尝试将一个字符串类型的变量赋值给一个声明为 Number 类型的变量，
// `TypeOracle` 维护的类型信息会被用来检测这种类型错误。
```

**总结:**

`v8/src/torque/type-oracle.h` 是 Torque 类型系统的核心，负责管理和维护 Torque 中所有类型的定义和关系。它对于 Torque 编译器的正确运行至关重要，并间接地影响着 V8 生成的代码的正确性和性能，最终体现在 JavaScript 的执行行为上。 虽然开发者不会直接操作 `TypeOracle`，但理解其功能有助于理解 Torque 的工作原理以及 V8 如何实现 JavaScript 的语义。

Prompt: 
```
这是目录为v8/src/torque/type-oracle.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/type-oracle.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_TORQUE_TYPE_ORACLE_H_
#define V8_TORQUE_TYPE_ORACLE_H_

#include <memory>
#include <optional>

#include "src/base/contextual.h"
#include "src/torque/constants.h"
#include "src/torque/declarable.h"
#include "src/torque/declarations.h"
#include "src/torque/types.h"
#include "src/torque/utils.h"

namespace v8::internal::torque {

class TypeOracle : public base::ContextualClass<TypeOracle> {
 public:
  static const AbstractType* GetAbstractType(
      const Type* parent, std::string name, AbstractTypeFlags flags,
      std::string generated, const Type* non_constexpr_version,
      MaybeSpecializationKey specialized_from) {
    auto ptr = std::unique_ptr<AbstractType>(
        new AbstractType(parent, flags, std::move(name), std::move(generated),
                         non_constexpr_version, specialized_from));
    const AbstractType* result = ptr.get();
    if (non_constexpr_version) {
      DCHECK(ptr->IsConstexpr());
      non_constexpr_version->SetConstexprVersion(result);
    }
    Get().nominal_types_.push_back(std::move(ptr));
    return result;
  }

  static StructType* GetStructType(const StructDeclaration* decl,
                                   MaybeSpecializationKey specialized_from) {
    auto ptr = std::unique_ptr<StructType>(
        new StructType(CurrentNamespace(), decl, specialized_from));
    StructType* result = ptr.get();
    Get().aggregate_types_.push_back(std::move(ptr));
    return result;
  }

  static BitFieldStructType* GetBitFieldStructType(
      const Type* parent, const BitFieldStructDeclaration* decl) {
    auto ptr = std::unique_ptr<BitFieldStructType>(
        new BitFieldStructType(CurrentNamespace(), parent, decl));
    BitFieldStructType* result = ptr.get();
    Get().bit_field_struct_types_.push_back(std::move(ptr));
    return result;
  }

  static ClassType* GetClassType(const Type* parent, const std::string& name,
                                 ClassFlags flags, const std::string& generates,
                                 ClassDeclaration* decl,
                                 const TypeAlias* alias) {
    std::unique_ptr<ClassType> type(new ClassType(
        parent, CurrentNamespace(), name, flags, generates, decl, alias));
    ClassType* result = type.get();
    Get().aggregate_types_.push_back(std::move(type));
    return result;
  }

  static const BuiltinPointerType* GetBuiltinPointerType(
      TypeVector argument_types, const Type* return_type) {
    TypeOracle& self = Get();
    const Type* builtin_type = self.GetBuiltinType(BUILTIN_POINTER_TYPE_STRING);
    const BuiltinPointerType* result = self.function_pointer_types_.Add(
        BuiltinPointerType(builtin_type, std::move(argument_types), return_type,
                           self.all_builtin_pointer_types_.size()));
    if (result->function_pointer_type_id() ==
        self.all_builtin_pointer_types_.size()) {
      self.all_builtin_pointer_types_.push_back(result);
    }
    return result;
  }

  static const Type* GetGenericTypeInstance(GenericType* generic_type,
                                            TypeVector arg_types);

  static GenericType* GetReferenceGeneric(bool is_const) {
    return Declarations::LookupUniqueGenericType(
        QualifiedName({TORQUE_INTERNAL_NAMESPACE_STRING},
                      is_const ? CONST_REFERENCE_TYPE_STRING
                               : MUTABLE_REFERENCE_TYPE_STRING));
  }
  static GenericType* GetConstReferenceGeneric() {
    return GetReferenceGeneric(true);
  }
  static GenericType* GetMutableReferenceGeneric() {
    return GetReferenceGeneric(false);
  }

  static std::optional<const Type*> MatchReferenceGeneric(
      const Type* reference_type, bool* is_const = nullptr);

  static GenericType* GetMutableSliceGeneric() {
    return Declarations::LookupUniqueGenericType(
        QualifiedName(MUTABLE_SLICE_TYPE_STRING));
  }
  static GenericType* GetConstSliceGeneric() {
    return Declarations::LookupUniqueGenericType(
        QualifiedName(CONST_SLICE_TYPE_STRING));
  }

  static GenericType* GetWeakGeneric() {
    return Declarations::LookupGlobalUniqueGenericType(WEAK_TYPE_STRING);
  }

  static GenericType* GetSmiTaggedGeneric() {
    return Declarations::LookupGlobalUniqueGenericType(SMI_TAGGED_TYPE_STRING);
  }

  static GenericType* GetLazyGeneric() {
    return Declarations::LookupGlobalUniqueGenericType(LAZY_TYPE_STRING);
  }

  static const Type* GetReferenceType(const Type* referenced_type,
                                      bool is_const) {
    return GetGenericTypeInstance(GetReferenceGeneric(is_const),
                                  {referenced_type});
  }
  static const Type* GetConstReferenceType(const Type* referenced_type) {
    return GetReferenceType(referenced_type, true);
  }
  static const Type* GetMutableReferenceType(const Type* referenced_type) {
    return GetReferenceType(referenced_type, false);
  }

  static const Type* GetMutableSliceType(const Type* referenced_type) {
    return GetGenericTypeInstance(GetMutableSliceGeneric(), {referenced_type});
  }
  static const Type* GetConstSliceType(const Type* referenced_type) {
    return GetGenericTypeInstance(GetConstSliceGeneric(), {referenced_type});
  }

  static const std::vector<const BuiltinPointerType*>&
  AllBuiltinPointerTypes() {
    return Get().all_builtin_pointer_types_;
  }

  static const Type* GetUnionType(UnionType type) {
    if (std::optional<const Type*> single = type.GetSingleMember()) {
      return *single;
    }
    return Get().union_types_.Add(std::move(type));
  }

  static const Type* GetUnionType(const Type* a, const Type* b) {
    if (a->IsSubtypeOf(b)) return b;
    if (b->IsSubtypeOf(a)) return a;
    UnionType result = UnionType::FromType(a);
    result.Extend(b);
    return GetUnionType(std::move(result));
  }

  static const TopType* GetTopType(std::string reason,
                                   const Type* source_type) {
    std::unique_ptr<TopType> type(new TopType(std::move(reason), source_type));
    TopType* result = type.get();
    Get().top_types_.push_back(std::move(type));
    return result;
  }

  static const Type* GetArgumentsType() {
    return Get().GetBuiltinType(ARGUMENTS_TYPE_STRING);
  }

  static const Type* GetBoolType() {
    return Get().GetBuiltinType(BOOL_TYPE_STRING);
  }

  static const Type* GetConstexprBoolType() {
    return Get().GetBuiltinType(CONSTEXPR_BOOL_TYPE_STRING);
  }

  static const Type* GetConstexprStringType() {
    return Get().GetBuiltinType(CONSTEXPR_STRING_TYPE_STRING);
  }

  static const Type* GetConstexprIntPtrType() {
    return Get().GetBuiltinType(CONSTEXPR_INTPTR_TYPE_STRING);
  }

  static const Type* GetConstexprInstanceTypeType() {
    return Get().GetBuiltinType(CONSTEXPR_INSTANCE_TYPE_TYPE_STRING);
  }

  static const Type* GetVoidType() {
    return Get().GetBuiltinType(VOID_TYPE_STRING);
  }

  static const Type* GetRawPtrType() {
    return Get().GetBuiltinType(RAWPTR_TYPE_STRING);
  }

  static const Type* GetExternalPointerType() {
    return Get().GetBuiltinType(EXTERNALPTR_TYPE_STRING);
  }

  static const Type* GetCppHeapPointerType() {
    return Get().GetBuiltinType(CPPHEAPPTR_TYPE_STRING);
  }

  static const Type* GetTrustedPointerType() {
    return Get().GetBuiltinType(TRUSTEDPTR_TYPE_STRING);
  }

  static const Type* GetProtectedPointerType() {
    return Get().GetBuiltinType(PROTECTEDPTR_TYPE_STRING);
  }

  static const Type* GetDispatchHandleType() {
    return Get().GetBuiltinType(DISPATCH_HANDLE_TYPE_STRING);
  }

  static const Type* GetMapType() {
    return Get().GetBuiltinType(MAP_TYPE_STRING);
  }

  static const Type* GetObjectType() {
    return Get().GetBuiltinType(OBJECT_TYPE_STRING);
  }

  static const Type* GetHeapObjectType() {
    return Get().GetBuiltinType(HEAP_OBJECT_TYPE_STRING);
  }

  static const Type* GetTaggedZeroPatternType() {
    return Get().GetBuiltinType(TAGGED_ZERO_PATTERN_TYPE_STRING);
  }

  static const Type* GetJSAnyType() {
    return Get().GetBuiltinType(JSANY_TYPE_STRING);
  }

  static const Type* GetJSObjectType() {
    return Get().GetBuiltinType(JSOBJECT_TYPE_STRING);
  }

  static const Type* GetTaggedType() {
    return Get().GetBuiltinType(TAGGED_TYPE_STRING);
  }

  static const Type* GetStrongTaggedType() {
    return Get().GetBuiltinType(STRONG_TAGGED_TYPE_STRING);
  }

  static const Type* GetUninitializedType() {
    return Get().GetBuiltinType(UNINITIALIZED_TYPE_STRING);
  }

  static const Type* GetUninitializedHeapObjectType() {
    return Get().GetBuiltinType(
        QualifiedName({TORQUE_INTERNAL_NAMESPACE_STRING},
                      UNINITIALIZED_HEAP_OBJECT_TYPE_STRING));
  }

  static const Type* GetSmiType() {
    return Get().GetBuiltinType(SMI_TYPE_STRING);
  }

  static const Type* GetConstStringType() {
    return Get().GetBuiltinType(CONST_STRING_TYPE_STRING);
  }

  static const Type* GetStringType() {
    return Get().GetBuiltinType(STRING_TYPE_STRING);
  }

  static const Type* GetNumberType() {
    return Get().GetBuiltinType(NUMBER_TYPE_STRING);
  }

  static const Type* GetIntPtrType() {
    return Get().GetBuiltinType(INTPTR_TYPE_STRING);
  }

  static const Type* GetUIntPtrType() {
    return Get().GetBuiltinType(UINTPTR_TYPE_STRING);
  }

  static const Type* GetInt64Type() {
    return Get().GetBuiltinType(INT64_TYPE_STRING);
  }

  static const Type* GetUint64Type() {
    return Get().GetBuiltinType(UINT64_TYPE_STRING);
  }

  static const Type* GetInt32Type() {
    return Get().GetBuiltinType(INT32_TYPE_STRING);
  }

  static const Type* GetUint32Type() {
    return Get().GetBuiltinType(UINT32_TYPE_STRING);
  }

  static const Type* GetUint31Type() {
    return Get().GetBuiltinType(UINT31_TYPE_STRING);
  }

  static const Type* GetInt16Type() {
    return Get().GetBuiltinType(INT16_TYPE_STRING);
  }

  static const Type* GetUint16Type() {
    return Get().GetBuiltinType(UINT16_TYPE_STRING);
  }

  static const Type* GetInt8Type() {
    return Get().GetBuiltinType(INT8_TYPE_STRING);
  }

  static const Type* GetUint8Type() {
    return Get().GetBuiltinType(UINT8_TYPE_STRING);
  }

  static const Type* GetFloat64Type() {
    return Get().GetBuiltinType(FLOAT64_TYPE_STRING);
  }

  static const Type* GetFloat64OrHoleType() {
    return Get().GetBuiltinType(FLOAT64_OR_HOLE_TYPE_STRING);
  }

  static const Type* GetConstFloat64Type() {
    return Get().GetBuiltinType(CONST_FLOAT64_TYPE_STRING);
  }

  static const Type* GetIntegerLiteralType() {
    return Get().GetBuiltinType(INTEGER_LITERAL_TYPE_STRING);
  }

  static const Type* GetNeverType() {
    return Get().GetBuiltinType(NEVER_TYPE_STRING);
  }

  static const Type* GetConstInt31Type() {
    return Get().GetBuiltinType(CONST_INT31_TYPE_STRING);
  }

  static const Type* GetConstInt32Type() {
    return Get().GetBuiltinType(CONST_INT32_TYPE_STRING);
  }

  static const Type* GetContextType() {
    return Get().GetBuiltinType(CONTEXT_TYPE_STRING);
  }

  static const Type* GetNoContextType() {
    return Get().GetBuiltinType(NO_CONTEXT_TYPE_STRING);
  }

  static const Type* GetNativeContextType() {
    return Get().GetBuiltinType(NATIVE_CONTEXT_TYPE_STRING);
  }

  static const Type* GetJSFunctionType() {
    return Get().GetBuiltinType(JS_FUNCTION_TYPE_STRING);
  }

  static const Type* GetUninitializedIteratorType() {
    return Get().GetBuiltinType(UNINITIALIZED_ITERATOR_TYPE_STRING);
  }

  static const Type* GetFixedArrayBaseType() {
    return Get().GetBuiltinType(FIXED_ARRAY_BASE_TYPE_STRING);
  }

  static std::optional<const Type*> ImplicitlyConvertableFrom(
      const Type* to, const Type* from) {
    while (from != nullptr) {
      for (GenericCallable* from_constexpr :
           Declarations::LookupGeneric(kFromConstexprMacroName)) {
        if (std::optional<const Callable*> specialization =
                from_constexpr->GetSpecialization({to, from})) {
          if ((*specialization)->signature().GetExplicitTypes() ==
              TypeVector{from}) {
            return from;
          }
        }
      }
      from = from->parent();
    }
    return std::nullopt;
  }

  static const std::vector<std::unique_ptr<AggregateType>>& GetAggregateTypes();
  static const std::vector<std::unique_ptr<BitFieldStructType>>&
  GetBitFieldStructTypes();

  // By construction, this list of all classes is topologically sorted w.r.t.
  // inheritance.
  static std::vector<const ClassType*> GetClasses();

  static void FinalizeAggregateTypes();

  static size_t FreshTypeId() { return Get().next_type_id_++; }

  static Namespace* CreateGenericTypeInstantiationNamespace();

 private:
  const Type* GetBuiltinType(const QualifiedName& name) {
    return Declarations::LookupGlobalType(name);
  }
  const Type* GetBuiltinType(const std::string& name) {
    return GetBuiltinType(QualifiedName(name));
  }

  Deduplicator<BuiltinPointerType> function_pointer_types_;
  std::vector<const BuiltinPointerType*> all_builtin_pointer_types_;
  Deduplicator<UnionType> union_types_;
  std::vector<std::unique_ptr<Type>> nominal_types_;
  std::vector<std::unique_ptr<AggregateType>> aggregate_types_;
  std::vector<std::unique_ptr<BitFieldStructType>> bit_field_struct_types_;
  std::vector<std::unique_ptr<Type>> top_types_;
  std::vector<std::unique_ptr<Namespace>>
      generic_type_instantiation_namespaces_;
  size_t next_type_id_ = 0;
};

}  // namespace v8::internal::torque

#endif  // V8_TORQUE_TYPE_ORACLE_H_

"""

```