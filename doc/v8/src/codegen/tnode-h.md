Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Understand the Goal:** The request asks for the *functionality* of the `tnode.h` header, specifically in the context of V8's codegen. It also prompts for connections to JavaScript, code logic examples, and common programming errors.

2. **Initial Skim for High-Level Understanding:** Quickly read through the file, paying attention to:
    * **Includes:**  What other V8 components does this file depend on?  (`v8config.h`, `machine-type.h`, `tagged.h`, `compiler/node.h`). This immediately suggests it's related to low-level code generation and type management.
    * **Namespaces:**  `v8::internal::compiler`. Confirms it's an internal part of the compiler.
    * **Key Structures:** Look for prominent `struct` and `class` definitions. The `TNode` and various type aliases (like `WordT`, `Int32T`, `TaggedT`) stand out.
    * **Macros/Directives:** `#ifndef`, `#define`, `#ifdef`. Standard C++ header guards and conditional compilation.

3. **Focus on the Core Concept: `TNode`:** The comment above the `TNode` class is crucial: "TNode<T> is an SSA value with the static type tag T...". This is the central concept. The `TNode` represents a value in the Static Single Assignment (SSA) form used in compilers, and it carries type information.

4. **Analyze the Type Tags:** The structs like `IntegralT`, `WordT`, `Int32T`, `Float64T`, etc., are the type tags. Notice the inheritance relationships (e.g., `Int32T` inherits from `Word32T`, which inherits from `IntegralT`). This establishes a type hierarchy.

5. **Connect Type Tags to Machine Types:** Observe the `kMachineRepresentation` and `kMachineType` static members within the type tag structs. This is the crucial link to the underlying machine architecture. For example, `Int32T` is associated with `MachineType::Int32()`.

6. **Understand `MachineType` and `MachineRepresentation` (Inferred):** Even without seeing the `machine-type.h` file, infer their purpose. `MachineType` likely represents a specific data type at the machine level (int32, float64, pointer), and `MachineRepresentation` might be a more general categorization (word32, word64, float).

7. **Examine `TNode` in Detail:**
    * **Template Parameter `T`:**  This confirms `TNode` is parameterized by the type tags we just analyzed.
    * **Constructor and Assignment:**  How are `TNode` objects created and copied?  Pay attention to the template constructor and the `is_subtype` check. This is about type safety.
    * **`operator compiler::Node*()`:**  This allows implicit conversion of a `TNode` to a raw compiler `Node*`. Crucial for interacting with the rest of the compiler.
    * **`UncheckedCast`:**  A way to bypass type checking, likely for internal use where the type is guaranteed.
    * **`LazyTemplateChecks`:**  Assertions to enforce type safety at compile time.

8. **Investigate Supporting Structures:**
    * **`PairT`:** Represents a node that produces two results.
    * **`UnionOf`:** Represents a value that can be one of several types.
    * **`MachineTypeOf` and `MachineRepresentationOf`:**  Traits to extract the machine type and representation from the type tags.
    * **`is_subtype` and `types_have_common_values`:** Traits for type relationship checking. Fundamental for type safety and implicit conversions.
    * **`SloppyTNode`:** A temporary construct to ease the transition from untyped `Node*` to typed `TNode`. Important for understanding the file's context in a larger codebase undergoing changes.

9. **Connect to JavaScript (Conceptual):**  While this file is C++, think about how the types represented here relate to JavaScript concepts. JavaScript has numbers, strings (represented by pointers to objects), booleans, etc. The `TaggedT` likely represents JavaScript values, as they are tagged with type information at runtime. `Smi` represents small integers that are encoded directly in pointers.

10. **Consider the `.tq` Question:**  Acknowledge that if the file ended in `.tq`, it would be a Torque file, V8's domain-specific language for expressing compiler builtins. This adds context about different ways V8's compiler is implemented.

11. **Think about Code Logic and Errors:**
    * **Logic:** Focus on type conversions and operations that rely on type information. Comparisons, arithmetic, memory access.
    * **Errors:**  Consider what happens if you misuse the types. Incorrect casts, treating a value as a different type, memory safety issues.

12. **Structure the Answer:** Organize the findings into logical categories: Functionality, `.tq` context, JavaScript relationship, code logic examples, and common errors. Use clear and concise language. Provide illustrative examples.

13. **Refine and Review:**  Read through the answer to ensure accuracy and clarity. Check for any missing pieces or areas that could be explained better. For instance, explicitly mentioning SSA form is important. Double-check the JavaScript examples for correctness and relevance.

This systematic approach, starting with a broad overview and progressively focusing on key details, helps in understanding complex code like this C++ header file. The key is to recognize the core purpose of type management in the context of a compiler's code generation phase.
The C++ header file `v8/src/codegen/tnode.h` defines a system of **type tags** and a template class `TNode` for representing **typed nodes** within V8's TurboFan compiler infrastructure. Essentially, it brings static typing to the intermediate representation used during compilation.

Here's a breakdown of its functionalities:

**1. Defining Type Tags:**

* **Purpose:**  The file defines various `struct`s (like `WordT`, `Int32T`, `Float64T`, `TaggedT`) that act as **static type tags**. These tags represent different kinds of data that can be manipulated within the compiler's intermediate representation.
* **Hierarchy:**  There's a clear hierarchy among these tags. For example, `Int32T` inherits from `Word32T`, which inherits from `IntegralT`, forming a type system. This allows the compiler to understand relationships between different data types.
* **Machine Representation:** Each type tag is associated with a `MachineRepresentation` and a `MachineType`. This links the abstract type information to the actual low-level representation of the data in memory (e.g., a 32-bit word, a 64-bit float, a pointer).
* **Examples of Type Tags:**
    * `WordT`: Represents a machine word (pointer-sized integer).
    * `Int32T`: Represents a 32-bit signed integer.
    * `Float64T`: Represents a 64-bit floating-point number.
    * `TaggedT`: Represents a tagged value, which is V8's fundamental representation for JavaScript values (can be a small integer, a pointer to an object, etc.).
    * `BoolT`: Represents a boolean value.
    * `PairT<T1, T2>`: Represents a value that is a pair of two other typed values.
    * `UnionOf<T1, T2, ...>`: Represents a value that can be one of several different types.

**2. The `TNode` Template Class:**

* **Purpose:** The `TNode<T>` template class is the core of this file. It represents a value in the compiler's intermediate representation (often in Static Single Assignment - SSA form) and associates it with a specific type tag `T`.
* **Static Typing:** `TNode` enforces static typing within the compiler. This allows for better type checking and optimization during compilation. The compiler knows the type of each `TNode` at compile time.
* **Implicit Conversions (with constraints):**  `TNode` supports implicit conversions between compatible types based on the `is_subtype` relationship. For example, a `TNode<Int32T>` can be implicitly converted to a `TNode<Word32T>`.
* **Interaction with Compiler Nodes:** `TNode` holds a raw pointer to a `compiler::Node`. This `compiler::Node` is the actual representation of the operation or value in the compiler's graph-based intermediate representation.
* **`SloppyTNode`:**  This is a temporary class to ease the transition from untyped `compiler::Node*` to the typed `TNode`. It allows implicit construction from raw `compiler::Node*`.

**Functionality Summary:**

In essence, `tnode.h` provides a type system for V8's TurboFan compiler, allowing it to reason about the types of intermediate values during code generation. This enables:

* **Improved Code Generation:** By knowing the types of values, the compiler can generate more efficient machine code.
* **Static Analysis and Optimization:** Type information allows for more sophisticated static analysis and optimizations.
* **Reduced Errors:** Static typing helps catch type-related errors during the compilation process rather than at runtime.

**If `v8/src/codegen/tnode.h` ended with `.tq`:**

Yes, if the file extension were `.tq`, it would be a **V8 Torque source file**. Torque is V8's domain-specific language for writing compiler builtins and some parts of the compiler itself. Torque files are compiled into C++ code. The concepts defined in the `.h` file would likely be used and extended within the `.tq` file.

**Relationship with JavaScript and Examples:**

The type tags in `tnode.h` directly relate to the types of values manipulated in JavaScript.

* **JavaScript Numbers:**  JavaScript numbers can be represented by `Smi` (small integers), `HeapNumber` (for larger or fractional numbers), corresponding to type tags like `Int32T`, `Float64T`, or `TaggedT` (which can hold both).

```javascript
// JavaScript example
let x = 10;  // Could be represented by a TNode<Smi> or TNode<TaggedT>
let y = 3.14; // Likely represented by a TNode<HeapNumber> or TNode<TaggedT>
```

* **JavaScript Booleans:** JavaScript boolean values (`true`, `false`) would correspond to the `BoolT` type tag.

```javascript
// JavaScript example
let isTrue = true; // Could be represented by a TNode<BoolT>
```

* **JavaScript Objects and Pointers:** JavaScript objects are stored on the heap. A `TNode` representing a JavaScript object would likely have the `TaggedT` type tag, signifying a tagged pointer to the object.

```javascript
// JavaScript example
let obj = { a: 1 }; // 'obj' would be a pointer to a heap object, potentially a TNode<TaggedT>
```

**Code Logic Reasoning Example:**

Imagine a TurboFan compiler stage performing addition of two numbers.

**Hypothetical Input:**

* `node1`: A `compiler::Node` representing the JavaScript value `5`. Assume it's wrapped in a `TNode<Smi>`.
* `node2`: A `compiler::Node` representing the JavaScript value `7`. Assume it's wrapped in a `TNode<Smi>`.

**Code Logic (within the compiler):**

The compiler might have logic that checks the types of `node1` and `node2`. Since both are `TNode<Smi>`, it knows they are small integers. It can then generate efficient machine code for integer addition.

**Hypothetical Output:**

* A new `compiler::Node` representing the result of the addition (`12`), wrapped in a `TNode<Smi>`.

**If one of the inputs was a floating-point number (`TNode<HeapNumber>` or `TNode<TaggedT>` holding a HeapNumber), the compiler logic would be different, potentially generating code for floating-point addition.**

**User-Common Programming Errors (Relating to Underlying Concepts):**

While users don't directly interact with `tnode.h`, understanding its principles helps in avoiding performance pitfalls in JavaScript:

* **Type Coercion Surprises:** JavaScript's dynamic typing can lead to unexpected type coercions. Understanding that V8 internally deals with specific types can explain why certain operations might be slower due to the need for runtime type checks and conversions.

```javascript
// Example of potential performance impact due to type coercion
function add(a, b) {
  return a + b;
}

add(5, 10);     // V8 might optimize this for integer addition
add("5", 10);   // V8 needs to handle string concatenation, less efficient
```

* **Hidden Class Changes:**  When the structure or types of properties in a JavaScript object change dynamically, V8 might need to create new "hidden classes" (internal representations of object structure). This can lead to deoptimization. The static typing within TurboFan, as supported by `TNode`, aims to avoid such runtime surprises.

```javascript
// Example of hidden class change
function Point(x, y) {
  this.x = x;
  this.y = y;
}

let p1 = new Point(1, 2); // V8 infers a structure for Point objects
let p2 = new Point(3, 4);

p1.z = 5; // Adding a property changes the structure of p1
          // Subsequent operations on p1 might be slower if V8 needs to
          // handle the new structure dynamically.
```

In summary, `v8/src/codegen/tnode.h` is a crucial part of V8's compilation process, providing a system for statically typing intermediate values. This enables better code generation, optimization, and error detection within the compiler, ultimately contributing to the performance of JavaScript execution. While JavaScript developers don't directly use these types, understanding the underlying concepts can help them write more performant code.

### 提示词
```
这是目录为v8/src/codegen/tnode.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/tnode.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CODEGEN_TNODE_H_
#define V8_CODEGEN_TNODE_H_

#include <type_traits>

#include "include/v8config.h"
#include "src/codegen/machine-type.h"
#include "src/objects/tagged.h"

namespace v8 {
namespace internal {

class HeapNumber;
class BigInt;

namespace compiler {

class Node;

}  // namespace compiler

struct UntaggedT {};

struct IntegralT : UntaggedT {};

struct WordT : IntegralT {
  static const MachineRepresentation kMachineRepresentation =
      MachineType::PointerRepresentation();
};

struct RawPtrT : WordT {
  static constexpr MachineType kMachineType = MachineType::Pointer();
};

// A RawPtrT that is guaranteed to point into the sandbox.
struct SandboxedPtrT : WordT {
  static constexpr MachineType kMachineType = MachineType::SandboxedPointer();
};

template <class To>
struct RawPtr : RawPtrT {};

struct Word32T : IntegralT {
  static const MachineRepresentation kMachineRepresentation =
      MachineRepresentation::kWord32;
};
struct Int32T : Word32T {
  static constexpr MachineType kMachineType = MachineType::Int32();
};
struct Uint32T : Word32T {
  static constexpr MachineType kMachineType = MachineType::Uint32();
};
struct Int16T : Int32T {
  static constexpr MachineType kMachineType = MachineType::Int16();
};
struct Uint16T : Uint32T, Int32T {
  static constexpr MachineType kMachineType = MachineType::Uint16();
};
struct Int8T : Int16T {
  static constexpr MachineType kMachineType = MachineType::Int8();
};
struct Uint8T : Uint16T, Int16T {
  static constexpr MachineType kMachineType = MachineType::Uint8();
};

struct Word64T : IntegralT {
  static const MachineRepresentation kMachineRepresentation =
      MachineRepresentation::kWord64;
};
struct Int64T : Word64T {
  static constexpr MachineType kMachineType = MachineType::Int64();
};
struct Uint64T : Word64T {
  static constexpr MachineType kMachineType = MachineType::Uint64();
};

struct IntPtrT : WordT {
  static constexpr MachineType kMachineType = MachineType::IntPtr();
};
struct UintPtrT : WordT {
  static constexpr MachineType kMachineType = MachineType::UintPtr();
};

struct ExternalPointerHandleT : Uint32T {
  static constexpr MachineType kMachineType = MachineType::Uint32();
};

struct CppHeapPointerHandleT : Uint32T {
  static constexpr MachineType kMachineType = MachineType::Uint32();
};

struct IndirectPointerHandleT : Uint32T {
  static constexpr MachineType kMachineType = MachineType::Uint32();
};

struct JSDispatchHandleT : Uint32T {
  static constexpr MachineType kMachineType = MachineType::Uint32();
};

#ifdef V8_ENABLE_SANDBOX
struct ExternalPointerT : Uint32T {
  static constexpr MachineType kMachineType = MachineType::Uint32();
};
#else
struct ExternalPointerT : UntaggedT {
  static constexpr MachineType kMachineType = MachineType::Pointer();
};
#endif

#ifdef V8_COMPRESS_POINTERS
struct CppHeapPointerT : Uint32T {
  static constexpr MachineType kMachineType = MachineType::Uint32();
};
#else   // !V8_COMPRESS_POINTERS
struct CppHeapPointerT : UntaggedT {
  static constexpr MachineType kMachineType = MachineType::Pointer();
};
#endif  // !V8_COMPRESS_POINTERS

struct Float16RawBitsT : Word32T {
  static constexpr MachineType kMachineType = MachineType::Uint16();
};

struct Float32T : UntaggedT {
  static const MachineRepresentation kMachineRepresentation =
      MachineRepresentation::kFloat32;
  static constexpr MachineType kMachineType = MachineType::Float32();
};

struct Float64T : UntaggedT {
  static const MachineRepresentation kMachineRepresentation =
      MachineRepresentation::kFloat64;
  static constexpr MachineType kMachineType = MachineType::Float64();
};

#ifdef V8_COMPRESS_POINTERS
using TaggedT = Int32T;
#else
using TaggedT = IntPtrT;
#endif

#ifdef V8_ENABLE_SANDBOX
using TrustedPointerT = IndirectPointerHandleT;
#else
using TrustedPointerT = TaggedT;
#endif

// Result of a comparison operation.
struct BoolT : Word32T {
  static constexpr MachineType kMachineType = MachineType::Int32();
};

// Value type of a Turbofan node with two results.
template <class T1, class T2>
struct PairT {};

struct Simd128T : UntaggedT {
  static const MachineRepresentation kMachineRepresentation =
      MachineRepresentation::kSimd128;
  static constexpr MachineType kMachineType = MachineType::Simd128();
};

struct I8x16T : Simd128T {};
struct I16x8T : Simd128T {};
struct I32x2T : Simd128T {};

inline constexpr MachineType CommonMachineType(MachineType type1,
                                               MachineType type2) {
  return (type1 == type2) ? type1
                          : ((type1.IsTagged() && type2.IsTagged())
                                 ? MachineType::AnyTagged()
                                 : MachineType::None());
}

template <class Type, class Enable = void>
struct MachineTypeOf {
  static constexpr MachineType value = Type::kMachineType;
};

template <class Type, class Enable>
constexpr MachineType MachineTypeOf<Type, Enable>::value;

template <>
struct MachineTypeOf<Object> {
  static constexpr MachineType value = MachineType::AnyTagged();
};
template <>
struct MachineTypeOf<MaybeObject> {
  static constexpr MachineType value = MachineType::AnyTagged();
};
template <>
struct MachineTypeOf<Smi> {
  static constexpr MachineType value = MachineType::TaggedSigned();
};
template <>
struct MachineTypeOf<TaggedIndex> {
  static constexpr MachineType value = MachineType::Pointer();
};
template <class HeapObjectSubtype>
struct MachineTypeOf<
    HeapObjectSubtype,
    std::enable_if_t<std::is_base_of_v<HeapObject, HeapObjectSubtype> ||
                     std::is_base_of_v<HeapObjectLayout, HeapObjectSubtype>>> {
  static constexpr MachineType value = MachineType::TaggedPointer();
};

template <class HeapObjectSubtype>
constexpr MachineType MachineTypeOf<
    HeapObjectSubtype,
    std::enable_if_t<std::is_base_of_v<HeapObject, HeapObjectSubtype> ||
                     std::is_base_of_v<HeapObjectLayout, HeapObjectSubtype>>>::
    value;

template <>
struct MachineTypeOf<ExternalReference> {
  static constexpr MachineType value = MachineType::Pointer();
};

template <class T>
struct MachineTypeOf<Union<T>> {
  static constexpr MachineType value = MachineTypeOf<T>::value;
};

template <class T, class... Ts>
struct MachineTypeOf<Union<T, Ts...>> {
  static constexpr MachineType value = CommonMachineType(
      MachineTypeOf<T>::value, MachineTypeOf<Union<Ts...>>::value);

  static_assert(value.representation() != MachineRepresentation::kNone,
                "no common representation");
};

template <class Type, class Enable = void>
struct MachineRepresentationOf {
  static const MachineRepresentation value = Type::kMachineRepresentation;
};
// If T defines kMachineType, then we take the machine representation from
// there.
template <class T>
struct MachineRepresentationOf<T, std::void_t<decltype(T::kMachineType)>> {
  static constexpr MachineRepresentation value =
      T::kMachineType.representation();
};
template <class T>
struct MachineRepresentationOf<T, std::enable_if_t<is_taggable_v<T>>> {
  static constexpr MachineRepresentation value =
      MachineTypeOf<T>::value.representation();
};
template <>
struct MachineRepresentationOf<ExternalReference> {
  static constexpr MachineRepresentation value =
      RawPtrT::kMachineRepresentation;
};

template <typename T>
constexpr bool IsMachineRepresentationOf(MachineRepresentation r) {
  return MachineRepresentationOf<T>::value == r;
}

template <class T>
constexpr MachineRepresentation PhiMachineRepresentationOf =
    std::is_base_of<Word32T, T>::value ? MachineRepresentation::kWord32
                                       : MachineRepresentationOf<T>::value;

template <class T>
struct is_valid_type_tag {
  static const bool value = is_taggable_v<T> ||
                            std::is_base_of<UntaggedT, T>::value ||
                            std::is_same<ExternalReference, T>::value;
  static const bool is_tagged = is_taggable_v<T>;
};

template <class T1, class T2>
struct is_valid_type_tag<PairT<T1, T2>> {
  static const bool value =
      is_valid_type_tag<T1>::value && is_valid_type_tag<T2>::value;
  static const bool is_tagged = false;
};

template <class... T>
struct is_valid_type_tag<Union<T...>> {
  static const bool is_tagged = (is_valid_type_tag<T>::is_tagged && ...);
  static const bool value = is_tagged;

  static_assert(is_tagged, "union types are only possible for tagged values");
};

using AnyTaggedT = UnionOf<Object, MaybeObject>;
using ContextOrEmptyContext = UnionOf<Context, Smi>;

// A pointer to a builtin function, used by Torque's function pointers.
using BuiltinPtr = Smi;

template <>
struct is_subtype<ExternalReference, RawPtrT> {
  static const bool value = true;
};
template <>
struct is_subtype<IntPtrT, RawPtrT> {
  static const bool value = true;
};

template <class T, class U>
struct types_have_common_values {
  static const bool value = is_subtype<T, U>::value || is_subtype<U, T>::value;
};
template <class U>
struct types_have_common_values<BoolT, U> {
  static const bool value = types_have_common_values<Word32T, U>::value;
};
template <class U>
struct types_have_common_values<Uint32T, U> {
  static const bool value = types_have_common_values<Word32T, U>::value;
};
template <class U>
struct types_have_common_values<Int32T, U> {
  static const bool value = types_have_common_values<Word32T, U>::value;
};
template <class U>
struct types_have_common_values<Uint64T, U> {
  static const bool value = types_have_common_values<Word64T, U>::value;
};
template <class U>
struct types_have_common_values<Int64T, U> {
  static const bool value = types_have_common_values<Word64T, U>::value;
};
template <class U>
struct types_have_common_values<IntPtrT, U> {
  static const bool value = types_have_common_values<WordT, U>::value;
};
template <class U>
struct types_have_common_values<UintPtrT, U> {
  static const bool value = types_have_common_values<WordT, U>::value;
};
template <class... Ts, class U>
struct types_have_common_values<Union<Ts...>, U> {
  static const bool value =
      std::disjunction_v<types_have_common_values<Ts, U>...>;
};
template <class T, class... Us>
struct types_have_common_values<T, Union<Us...>> {
  static const bool value =
      std::disjunction_v<types_have_common_values<T, Us>...>;
};
template <class... Ts, class... Us>
struct types_have_common_values<Union<Ts...>, Union<Us...>> {
  static const bool value =
      std::disjunction_v<types_have_common_values<Ts, Union<Us...>>...>;
};

// TNode<T> is an SSA value with the static type tag T, which is one of the
// following:
//   - MaybeObject> represents the type of all tagged values, including weak
//     pointers.
//   - a subclass of internal::Object represents a non-weak tagged type.
//   - a subclass of internal::UntaggedT represents an untagged type
//   - ExternalReference
//   - PairT<T1, T2> for an operation returning two values, with types T1
//     and T2
//   - UnionOf<T1, T2, ...> represents a value of one of types T1, T2, etc.
template <class T>
class TNode {
 public:
  template <class U, typename = std::enable_if_t<is_subtype<U, T>::value>>
  TNode(const TNode<U>& other) V8_NOEXCEPT : node_(other.node_) {
    LazyTemplateChecks();
  }

  TNode(const TNode& other) V8_NOEXCEPT : node_(other.node_) {}
  TNode() : node_(nullptr) {}

  TNode operator=(TNode other) {
    DCHECK_NOT_NULL(other.node_);
    node_ = other.node_;
    return *this;
  }

  operator compiler::Node*() const { return node_; }

  explicit operator bool() const { return node_ != nullptr; }

  static TNode UncheckedCast(compiler::Node* node) { return TNode(node); }

 protected:
  template <typename U>
  friend class TNode;

  explicit TNode(compiler::Node* node) : node_(node) { LazyTemplateChecks(); }
  // These checks shouldn't be checked before TNode is actually used.
  void LazyTemplateChecks() const {
    static_assert(is_valid_type_tag<T>::value, "invalid type tag");
  }

  compiler::Node* node_;
};

template <class T>
class TNode<Tagged<T>> {
  static_assert(!std::is_same_v<T, T>,
                "Don't write TNode<Tagged<T>>, just write TNode<T> directly.");
};

// SloppyTNode<T> is a variant of TNode<T> and allows implicit casts from
// Node*. It is intended for function arguments as long as some call sites
// still use untyped Node* arguments.
// TODO(turbofan): Delete this class once transition is finished.
template <class T>
class SloppyTNode : public TNode<T> {
 public:
  SloppyTNode(compiler::Node* node)  // NOLINT(runtime/explicit)
      : TNode<T>(node) {}
  template <class U, typename std::enable_if<is_subtype<U, T>::value,
                                             int>::type = 0>
  SloppyTNode(const TNode<U>& other) V8_NOEXCEPT  // NOLINT(runtime/explicit)
      : TNode<T>(other) {}
};

}  // namespace internal
}  // namespace v8

#endif  // V8_CODEGEN_TNODE_H_
```