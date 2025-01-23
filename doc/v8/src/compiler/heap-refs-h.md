Response:
My goal is to analyze the provided C++ header file (`v8/src/compiler/heap-refs.h`) and address the user's request about its functionality, potential Torque origin, relationship with JavaScript, code logic, common programming errors, and a summary of its purpose.

Here's a breakdown of the thinking process:

1. **Understanding the Request:** The user wants a comprehensive overview of `heap-refs.h`. Keywords like "functionality," "Torque," "JavaScript," "code logic," "programming errors," and "summary" indicate the scope. The "Part 1" suggests there's more context to come, but I should focus on this file in isolation for now.

2. **Initial Scan and High-Level Understanding:**  I'll first read through the code, noting key structures and concepts. I see `#ifndef`, `#define` which indicates a header guard. Includes like `<optional>`, `<type_traits>`, and V8-specific headers (`src/ic/call-optimization.h`, `src/objects/...`) are important. The `namespace v8` and `namespace internal` further contextualize the code within the V8 project. The `namespace compiler` is a strong indicator this file is related to the compilation process.

3. **Identifying Core Concepts:**  The name "heap-refs" strongly suggests this file deals with representing references to objects on the V8 heap. I see enums like `AccessMode`, `OddballType`, `HoleType`, and `RefSerializationKind`. These define different categories or states related to heap object access and management. The `HEAP_BROKER_OBJECT_LIST` macro is central, defining a long list of V8 object types. The `ObjectRef` class appears to be a foundational element.

4. **Addressing Specific Questions:**

    * **Functionality:**  The file defines a system for representing and working with references to V8 heap objects within the compiler. This includes different types of references (`ObjectRef`, `JSObjectRef`, etc.), ways to access their data, and information about their properties (like mutability, type). It's likely used during compilation to reason about the structure and behavior of JavaScript objects.

    * **Torque Origin (.tq):** The code clearly uses C++ syntax. There's no indication of Torque syntax. The user provides a conditional statement in their request – if the filename ended in `.tq`, it would be Torque. Since it's `.h`, it's a C++ header.

    * **Relationship with JavaScript:** This is a crucial connection. The listed object types (`JSArray`, `JSFunction`, `String`, etc.) directly correspond to JavaScript language features and built-in objects. The file provides a way for the compiler to understand and manipulate these JavaScript entities. I'll need to think of simple JavaScript examples that would involve these objects.

    * **Code Logic Inference:**  The nested classes and the inheritance structure (`HeapObjectRef` inheriting from `ObjectRef`, `JSObjectRef` inheriting from `HeapObjectRef`, etc.) suggest a type hierarchy representing the V8 object model. The presence of methods like `IsJSArray()`, `AsJSArray()`, `map()`, and accessors for object properties indicate logic for querying and accessing heap object information. I can make assumptions about input and output for some basic methods like `IsSmi()` or `AsSmi()`.

    * **Common Programming Errors:**  Given this is low-level compiler code, typical user-level JavaScript errors aren't directly relevant. Instead, potential errors would be related to incorrect usage of these reference types within the compiler itself – type mismatches, accessing non-existent properties, or failing to handle different object states correctly.

    * **归纳功能 (Summarizing Functionality):** The core function is to provide a type-safe and structured way to represent and interact with V8 heap objects during compilation. It allows the compiler to reason about object properties, types, and relationships.

5. **Generating Examples (JavaScript and Logic):**

    * **JavaScript:** Simple examples demonstrating the existence of the listed object types are needed. Creating arrays, functions, objects, etc. will suffice.

    * **Logic:** For methods like `IsSmi()`, if the input `ObjectRef` represents a small integer, the output should be `true`. If it's a different type, the output should be `false`. For `AsSmi()`, the input needs to be a `Smi`, and the output is the integer value.

6. **Considering Common Programming Errors:**  As mentioned earlier, these will be compiler-specific errors rather than user JavaScript errors. Examples include casting a `JSObjectRef` to a `JSFunctionRef` when the underlying object isn't a function, or accessing a property on an object without checking if it exists.

7. **Structuring the Response:** I'll organize the information according to the user's request, addressing each point systematically. I'll start with the general functionality, then the Torque question, the JavaScript relationship with examples, the code logic with assumptions, potential errors, and finally the summary.

8. **Refinement and Review:** I'll reread the generated response to ensure clarity, accuracy, and completeness, sticking to the information available in the provided header file. I need to avoid making assumptions about the implementation details beyond what's visible in the header.

By following this thought process, I can systematically break down the header file and generate a comprehensive and informative response to the user's request.
好的，让我们来分析一下 `v8/src/compiler/heap-refs.h` 这个 V8 源代码文件的功能。

**1. 文件功能归纳:**

`v8/src/compiler/heap-refs.h` 定义了一套用于在 V8 编译器中安全且方便地操作 V8 堆对象的引用机制。它提供了一系列类（以 `Ref` 结尾，例如 `ObjectRef`, `JSObjectRef`）来表示指向 V8 堆中各种对象的引用，并提供了一些方法来访问这些对象的基本属性和执行类型检查。

**更详细的功能点包括：**

* **类型安全的堆对象引用:**  定义了各种 `XXXRef` 类，例如 `JSObjectRef`、`JSFunctionRef`、`StringRef` 等，为不同类型的堆对象提供了类型安全的引用。这有助于编译器在编译时进行更强的类型检查，减少错误。
* **访问堆对象属性:**  为每个 `XXXRef` 类提供了访问对应堆对象属性的方法，例如 `JSFunctionRef` 可以访问其 `context`、`shared`、`code` 等属性。
* **类型检查:** 提供了 `IsXXX()` 方法（例如 `IsSmi()`, `IsJSObject()`) 用于判断 `ObjectRef` 指向的具体对象类型。
* **类型转换:** 提供了 `AsXXX()` 方法（例如 `AsJSObject()`) 用于将 `ObjectRef` 转换为特定类型的引用，但通常需要先进行类型检查。
* **空值表示:** 使用 `OptionalRef<T>` 模板类来表示可能为空的堆对象引用，类似于 `std::optional`。
* **哈希和比较:** 提供了比较 (`equals`, `operator==`, `operator!=`, `operator<`) 和哈希 (`hash_value`) 操作，方便在集合中使用这些引用。
* **访问模式定义:** 定义了 `AccessMode` 枚举，用于区分属性访问是加载、存储还是定义等操作，这在编译器进行优化时非常重要。
* **Oddball 和 Hole 类型:** 定义了 `OddballType` 和 `HoleType` 枚举，用于表示特殊的 JavaScript 值（例如 `undefined`, `null`, `true`, `false`）和 V8 堆中的 "洞" (hole) 值。
* **序列化控制:**  定义了 `RefSerializationKind` 枚举，用于控制堆对象引用是否以及如何被序列化，这对于编译缓存等功能非常重要。
* **与 Broker 的交互:**  很多方法需要 `JSHeapBroker* broker` 参数，这表明这些引用机制与 V8 的 `JSHeapBroker` 组件紧密相关，`JSHeapBroker` 负责管理堆对象的访问和生命周期。

**2. 是否为 Torque 源代码:**

`v8/src/compiler/heap-refs.h` 以 `.h` 结尾，这是一个标准的 C++ 头文件扩展名。因此，**它不是一个 Torque 源代码文件**。如果文件名以 `.tq` 结尾，那才表示它是一个 Torque 文件。

**3. 与 Javascript 的功能关系:**

`v8/src/compiler/heap-refs.h` 直接关系到 JavaScript 的功能，因为它定义了编译器如何理解和操作 JavaScript 中的各种对象。

**JavaScript 举例说明:**

```javascript
// 假设在 V8 内部编译这段代码

function foo(obj) {
  return obj.x;
}

const myObject = { x: 10 };
foo(myObject);
```

在 V8 编译 `foo` 函数时，`heap-refs.h` 中定义的类会被用来表示 `obj` 和 `myObject`。

* **`myObject` 会被表示为 `JSObjectRef`。**
* **`obj.x` 的属性访问操作会被编译器理解为需要访问 `JSObjectRef` 的某个属性。** 编译器可能会使用 `AccessMode::kLoad` 来表示这是一个加载操作。
* **如果 `obj` 的形状 (Map) 在编译时已知，编译器甚至可以确定 `x` 属性在 `JSObjectRef` 中的偏移量。**

**4. 代码逻辑推理 (假设输入与输出):**

假设我们有一个 `ObjectRef` 实例 `ref`：

* **假设输入:** `ref` 指向一个 JavaScript 数字 `42` (在 V8 堆中表示为 Smi)。
* **输出:** `ref.IsSmi()` 将返回 `true`。`ref.AsSmi()` 将返回 `42`。

* **假设输入:** `ref` 指向一个 JavaScript 对象 `{ value: 'hello' }`。
* **输出:** `ref.IsJSObject()` 将返回 `true`。`ref.AsJSObject()` 可以将 `ref` 转换为 `JSObjectRef`。

* **假设输入:** `ref` 指向 `undefined`。
* **输出:** `ref.IsUndefined()` 将返回 `true`。

**5. 涉及用户常见的编程错误:**

虽然 `heap-refs.h` 是编译器内部使用的，但理解其背后的概念有助于理解一些常见的 JavaScript 编程错误，这些错误最终会在编译或运行时被 V8 处理：

* **`TypeError: Cannot read properties of undefined (reading 'x')`:**  这与 `OptionalRef` 的概念有关。如果编译器在编译时无法确定某个对象一定存在，它可能使用 `OptionalRef` 来表示。如果运行时该对象为 `undefined`，尝试访问其属性就会导致这种错误。

   ```javascript
   function bar(obj) {
     return obj.y; // 如果 obj 是 undefined，就会报错
   }

   let myVar;
   bar(myVar);
   ```

* **类型不匹配导致的性能问题:** V8 编译器会根据对象的类型进行优化。如果对象的类型在运行时发生变化（例如，一个数组开始只包含数字，后来又加入了字符串），编译器可能需要进行去优化。`heap-refs.h` 中对不同对象类型的区分是实现这些优化的基础。

* **访问不存在的属性:** 尽管在 JavaScript 中访问不存在的属性不会立即抛出错误（会返回 `undefined`），但在编译器的角度，它仍然需要判断属性是否存在。`AccessMode` 的区分在处理这种情况时很重要。

**6. 功能总结 (基于提供的代码片段):**

提供的 `heap-refs.h` 代码片段的主要功能是：

* **定义了 V8 编译器内部使用的、类型安全的堆对象引用框架。**
* **为各种 V8 堆对象（如 JS 对象、函数、字符串等）提供了对应的引用类型。**
* **提供了访问堆对象基本属性、进行类型检查和类型转换的方法。**
* **使用了 `OptionalRef` 来处理可能为空的堆对象引用。**
* **定义了属性访问模式，Oddball 类型和 Hole 类型等编译器相关的概念。**
* **通过 `RefSerializationKind` 控制引用的序列化行为。**

总而言之，`v8/src/compiler/heap-refs.h` 是 V8 编译器理解和操作 JavaScript 代码的核心基础设施之一，它为编译器的各种优化和代码生成过程提供了必要的类型信息和访问机制。

### 提示词
```
这是目录为v8/src/compiler/heap-refs.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/heap-refs.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_HEAP_REFS_H_
#define V8_COMPILER_HEAP_REFS_H_

#include <optional>
#include <type_traits>

#include "src/ic/call-optimization.h"
#include "src/objects/elements-kind.h"
#include "src/objects/feedback-vector.h"
#include "src/objects/instance-type.h"
#include "src/objects/object-list-macros.h"
#include "src/utils/boxed-float.h"
#include "src/zone/zone-compact-set.h"

namespace v8 {

class CFunctionInfo;

namespace internal {

class BytecodeArray;
class FixedDoubleArray;
class FunctionTemplateInfo;
class HeapNumber;
class InternalizedString;
class JSBoundFunction;
class JSDataView;
class JSGlobalProxy;
class JSTypedArray;
class NativeContext;
class ScriptContextTable;
template <typename>
class Signature;

namespace interpreter {
class Register;
}  // namespace interpreter

namespace wasm {
class ValueType;
struct WasmModule;
}  // namespace wasm

namespace compiler {

class CompilationDependencies;
struct FeedbackSource;
class JSHeapBroker;
class ObjectData;
class PerIsolateCompilerCache;
class PropertyAccessInfo;

// Whether we are loading a property or storing to a property.
// For a store during literal creation, do not walk up the prototype chain.
// For a define operation, we behave similarly to kStoreInLiteral, but with
// distinct semantics for private class fields (in which private field
// accesses must throw when storing a field which does not exist, or
// adding/defining a field which already exists).
enum class AccessMode { kLoad, kStore, kStoreInLiteral, kHas, kDefine };

inline bool IsAnyStore(AccessMode mode) {
  return mode == AccessMode::kStore || mode == AccessMode::kStoreInLiteral ||
         mode == AccessMode::kDefine;
}

inline bool IsDefiningStore(AccessMode mode) {
  return mode == AccessMode::kStoreInLiteral || mode == AccessMode::kDefine;
}

enum class OddballType : uint8_t {
  kNone,     // Not an Oddball.
  kBoolean,  // True or False.
  kUndefined,
  kNull,
};

enum class HoleType : uint8_t {
  kNone,  // Not a Hole.

#define FOR_HOLE(Name, name, Root) k##Name,
  HOLE_LIST(FOR_HOLE)
#undef FOR_HOLE

      kGeneric = kTheHole,
};

enum class RefSerializationKind {
  // Skips serialization.
  kNeverSerialized,
  // Can be serialized on demand from the background thread.
  kBackgroundSerialized,
};

// This list is sorted such that subtypes appear before their supertypes.
// DO NOT VIOLATE THIS PROPERTY!
#define HEAP_BROKER_OBJECT_LIST_BASE(BACKGROUND_SERIALIZED, NEVER_SERIALIZED) \
  /* Subtypes of JSObject */                                                  \
  BACKGROUND_SERIALIZED(JSArray)                                              \
  BACKGROUND_SERIALIZED(JSBoundFunction)                                      \
  BACKGROUND_SERIALIZED(JSDataView)                                           \
  BACKGROUND_SERIALIZED(JSFunction)                                           \
  BACKGROUND_SERIALIZED(JSGlobalObject)                                       \
  BACKGROUND_SERIALIZED(JSGlobalProxy)                                        \
  BACKGROUND_SERIALIZED(JSTypedArray)                                         \
  BACKGROUND_SERIALIZED(JSPrimitiveWrapper)                                   \
  /* Subtypes of Context */                                                   \
  NEVER_SERIALIZED(NativeContext)                                             \
  /* Subtypes of FixedArray */                                                \
  NEVER_SERIALIZED(ObjectBoilerplateDescription)                              \
  BACKGROUND_SERIALIZED(ScriptContextTable)                                   \
  /* Subtypes of String */                                                    \
  NEVER_SERIALIZED(InternalizedString)                                        \
  /* Subtypes of FixedArrayBase */                                            \
  BACKGROUND_SERIALIZED(FixedArray)                                           \
  NEVER_SERIALIZED(FixedDoubleArray)                                          \
  /* Subtypes of Name */                                                      \
  NEVER_SERIALIZED(String)                                                    \
  NEVER_SERIALIZED(Symbol)                                                    \
  /* Subtypes of JSReceiver */                                                \
  BACKGROUND_SERIALIZED(JSObject)                                             \
  /* Subtypes of HeapObject */                                                \
  NEVER_SERIALIZED(AccessorInfo)                                              \
  NEVER_SERIALIZED(AllocationSite)                                            \
  NEVER_SERIALIZED(ArrayBoilerplateDescription)                               \
  BACKGROUND_SERIALIZED(BigInt)                                               \
  NEVER_SERIALIZED(BytecodeArray)                                             \
  NEVER_SERIALIZED(Cell)                                                      \
  NEVER_SERIALIZED(Code)                                                      \
  NEVER_SERIALIZED(Context)                                                   \
  NEVER_SERIALIZED(DescriptorArray)                                           \
  NEVER_SERIALIZED(FeedbackCell)                                              \
  NEVER_SERIALIZED(FeedbackVector)                                            \
  BACKGROUND_SERIALIZED(FixedArrayBase)                                       \
  NEVER_SERIALIZED(FunctionTemplateInfo)                                      \
  NEVER_SERIALIZED(HeapNumber)                                                \
  BACKGROUND_SERIALIZED(JSReceiver)                                           \
  BACKGROUND_SERIALIZED(Map)                                                  \
  NEVER_SERIALIZED(Name)                                                      \
  BACKGROUND_SERIALIZED(PropertyCell)                                         \
  NEVER_SERIALIZED(RegExpBoilerplateDescription)                              \
  NEVER_SERIALIZED(ScopeInfo)                                                 \
  NEVER_SERIALIZED(SharedFunctionInfo)                                        \
  NEVER_SERIALIZED(SourceTextModule)                                          \
  NEVER_SERIALIZED(TemplateObjectDescription)                                 \
  /* Subtypes of Object */                                                    \
  BACKGROUND_SERIALIZED(HeapObject)

#define HEAP_BROKER_OBJECT_LIST(V) HEAP_BROKER_OBJECT_LIST_BASE(V, V)
#define IGNORE_CASE(...)
#define HEAP_BROKER_BACKGROUND_SERIALIZED_OBJECT_LIST(V) \
  HEAP_BROKER_OBJECT_LIST_BASE(V, IGNORE_CASE)

#define FORWARD_DECL(Name) class Name##Ref;
HEAP_BROKER_OBJECT_LIST(FORWARD_DECL)
FORWARD_DECL(Object)
#undef FORWARD_DECL

template <class T>
struct is_ref : public std::false_type {};

#define DEFINE_IS_REF(Name) \
  template <>               \
  struct is_ref<Name##Ref> : public std::true_type {};
HEAP_BROKER_OBJECT_LIST(DEFINE_IS_REF)
DEFINE_IS_REF(Object)
#undef DEFINE_IS_REF

template <class T>
struct ref_traits;

#define FORWARD_DECL(Name) class Name##Data;
HEAP_BROKER_BACKGROUND_SERIALIZED_OBJECT_LIST(FORWARD_DECL)
#undef FORWARD_DECL

#define BACKGROUND_SERIALIZED_REF_TRAITS(Name)                     \
  template <>                                                      \
  struct ref_traits<Name> {                                        \
    using ref_type = Name##Ref;                                    \
    using data_type = Name##Data;                                  \
    static constexpr RefSerializationKind ref_serialization_kind = \
        RefSerializationKind::kBackgroundSerialized;               \
  };

#define NEVER_SERIALIZED_REF_TRAITS(Name)                          \
  template <>                                                      \
  struct ref_traits<Name> {                                        \
    using ref_type = Name##Ref;                                    \
    using data_type = ObjectData;                                  \
    static constexpr RefSerializationKind ref_serialization_kind = \
        RefSerializationKind::kNeverSerialized;                    \
  };

HEAP_BROKER_OBJECT_LIST_BASE(BACKGROUND_SERIALIZED_REF_TRAITS,
                             NEVER_SERIALIZED_REF_TRAITS)
#undef NEVER_SERIALIZED_REF_TRAITS
#undef BACKGROUND_SERIALIZED_REF_TRAITS

template <>
struct ref_traits<Object> {
  using ref_type = ObjectRef;
  using data_type = ObjectData;
  // Note: While a bit awkward, this artificial ref serialization kind value is
  // okay: smis are never-serialized, and we never create raw non-smi
  // ObjectRefs (they would at least be HeapObjectRefs instead).
  static constexpr RefSerializationKind ref_serialization_kind =
      RefSerializationKind::kNeverSerialized;
};

// For types which don't have a corresponding Ref type, use the next best
// existing Ref.
template <>
struct ref_traits<Oddball> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<Null> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<Undefined> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<True> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<False> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<Hole> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<EnumCache> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<PropertyArray> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<ByteArray> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<TrustedFixedArray> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<ClosureFeedbackCellArray> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<NumberDictionary> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<OrderedHashMap> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<OrderedHashSet> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<FeedbackMetadata> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<NameDictionary> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<OrderedNameDictionary> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<SwissNameDictionary> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<InterceptorInfo> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<ArrayList> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<WeakFixedArray> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<WeakArrayList> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<RegisteredSymbolTable> : public ref_traits<HeapObject> {};
#if V8_ENABLE_WEBASSEMBLY
template <>
struct ref_traits<WasmNull> : public ref_traits<HeapObject> {};
#endif  // V8_ENABLE_WEBASSEMBLY
template <>
struct ref_traits<Smi> : public ref_traits<Object> {};
template <>
struct ref_traits<Boolean> : public ref_traits<HeapObject> {};
template <>
struct ref_traits<JSProxy> : public ref_traits<JSReceiver> {};
template <>
struct ref_traits<JSWrappedFunction> : public ref_traits<JSFunction> {};

template <class... T>
struct ref_traits<Union<T...>> {
  // There's no good way in C++ to find a common base class, so just test a few
  // common cases.
  static constexpr bool kAllJSReceiverRef =
      (std::is_base_of_v<JSReceiverRef, typename ref_traits<T>::ref_type> &&
       ...);
  static constexpr bool kAllHeapObjectRef =
      (std::is_base_of_v<JSReceiverRef, typename ref_traits<T>::ref_type> &&
       ...);

  using ref_type = std::conditional_t<
      kAllJSReceiverRef, JSReceiverRef,
      std::conditional_t<kAllHeapObjectRef, HeapObjectRef, ObjectRef>>;
  using data_type = std::conditional_t<
      kAllJSReceiverRef, JSReceiverData,
      std::conditional_t<kAllHeapObjectRef, HeapObjectData, ObjectData>>;

  static constexpr RefSerializationKind ref_serialization_kind =
      ((ref_traits<T>::ref_serialization_kind ==
        RefSerializationKind::kNeverSerialized) &&
       ...)
          ? RefSerializationKind::kNeverSerialized
          : RefSerializationKind::kBackgroundSerialized;
};

// Wrapper around heap refs which works roughly like a std::optional, but
// doesn't use extra storage for a boolean, but instead uses a null data pointer
// as a sentinel no value.
template <typename TRef>
class OptionalRef {
 public:
  // {ArrowOperatorHelper} is returned by {OptionalRef::operator->}. It should
  // never be stored anywhere or used in any other code; no one should ever have
  // to spell out {ArrowOperatorHelper} in code. Its only purpose is to be
  // dereferenced immediately by "operator-> chaining". Returning the address of
  // the field is valid because this objects lifetime only ends at the end of
  // the full statement.
  class ArrowOperatorHelper {
   public:
    TRef* operator->() { return &object_; }

   private:
    friend class OptionalRef<TRef>;
    explicit ArrowOperatorHelper(TRef object) : object_(object) {}

    TRef object_;
  };

  OptionalRef() = default;
  // NOLINTNEXTLINE
  OptionalRef(std::nullopt_t) : OptionalRef() {}

  // Allow implicit upcasting from OptionalRefs with compatible refs.
  template <typename SRef, typename = typename std::enable_if<
                               std::is_convertible<SRef*, TRef*>::value>::type>
  // NOLINTNEXTLINE
  V8_INLINE OptionalRef(OptionalRef<SRef> ref) : data_(ref.data_) {}

  // Allow implicit upcasting from compatible refs.
  template <typename SRef, typename = typename std::enable_if<
                               std::is_convertible<SRef*, TRef*>::value>::type>
  // NOLINTNEXTLINE
  V8_INLINE OptionalRef(SRef ref) : data_(ref.data_) {}

  constexpr bool has_value() const { return data_ != nullptr; }
  constexpr explicit operator bool() const { return has_value(); }

  TRef value() const {
    DCHECK(has_value());
    return TRef(data_, false);
  }
  TRef operator*() const { return value(); }
  ArrowOperatorHelper operator->() const {
    return ArrowOperatorHelper(value());
  }

  bool equals(OptionalRef other) const { return data_ == other.data_; }

  size_t hash_value() const {
    return has_value() ? value().hash_value() : base::hash_value(0);
  }

 private:
  explicit OptionalRef(ObjectData* data) : data_(data) {
    CHECK_NOT_NULL(data_);
  }
  ObjectData* data_ = nullptr;

  template <typename SRef>
  friend class OptionalRef;
};

template <typename T>
inline bool operator==(OptionalRef<T> lhs, OptionalRef<T> rhs) {
  return lhs.equals(rhs);
}

template <typename T>
inline size_t hash_value(OptionalRef<T> ref) {
  return ref.hash_value();
}

// Define aliases for OptionalFooRef = OptionalRef<FooRef>.
#define V(Name) using Optional##Name##Ref = OptionalRef<Name##Ref>;
V(Object)
HEAP_BROKER_OBJECT_LIST(V)
#undef V

class V8_EXPORT_PRIVATE ObjectRef {
 public:
  explicit ObjectRef(ObjectData* data, bool check_type = true) : data_(data) {
    CHECK_NOT_NULL(data_);
  }

  IndirectHandle<Object> object() const;

  bool equals(ObjectRef other) const;

  size_t hash_value() const { return base::hash_combine(object().address()); }

  bool IsSmi() const;
  int AsSmi() const;

#define HEAP_IS_METHOD_DECL(Name) bool Is##Name() const;
  HEAP_BROKER_OBJECT_LIST(HEAP_IS_METHOD_DECL)
#undef HEAP_IS_METHOD_DECL

#define HEAP_AS_METHOD_DECL(Name) Name##Ref As##Name() const;
  HEAP_BROKER_OBJECT_LIST(HEAP_AS_METHOD_DECL)
#undef HEAP_AS_METHOD_DECL

  bool IsNull() const;
  bool IsUndefined() const;
  enum HoleType HoleType() const;
  bool IsTheHole() const;
  bool IsPropertyCellHole() const;
  bool IsHashTableHole() const;
  bool IsPromiseHole() const;
  bool IsNullOrUndefined() const;

  std::optional<bool> TryGetBooleanValue(JSHeapBroker* broker) const;
  Maybe<double> OddballToNumber(JSHeapBroker* broker) const;

  bool should_access_heap() const;

  ObjectData* data() const;

  struct Hash {
    size_t operator()(ObjectRef ref) const { return ref.hash_value(); }
  };

 protected:
  ObjectData* data_;  // Should be used only by object() getters.

 private:
  friend class FunctionTemplateInfoRef;
  friend class JSArrayData;
  friend class JSFunctionData;
  friend class JSGlobalObjectData;
  friend class JSGlobalObjectRef;
  friend class JSHeapBroker;
  friend class JSObjectData;
  friend class StringData;

  template <typename TRef>
  friend class OptionalRef;

  friend std::ostream& operator<<(std::ostream& os, ObjectRef ref);
  friend bool operator<(ObjectRef lhs, ObjectRef rhs);
  template <typename T, typename Enable>
  friend struct ::v8::internal::ZoneCompactSetTraits;
};

inline bool operator==(ObjectRef lhs, ObjectRef rhs) { return lhs.equals(rhs); }

inline bool operator!=(ObjectRef lhs, ObjectRef rhs) {
  return !lhs.equals(rhs);
}

inline bool operator<(ObjectRef lhs, ObjectRef rhs) {
  return lhs.data_ < rhs.data_;
}

inline size_t hash_value(ObjectRef ref) { return ref.hash_value(); }

template <class T>
using ZoneRefUnorderedSet = ZoneUnorderedSet<T, ObjectRef::Hash>;

template <class K, class V>
using ZoneRefMap = ZoneMap<K, V>;

// Temporary class that carries information from a Map. We'd like to remove
// this class and use MapRef instead, but we can't as long as we support the
// kDisabled broker mode. That's because obtaining the MapRef via
// HeapObjectRef::map() requires a HandleScope when the broker is disabled.
// During OptimizeGraph we generally don't have a HandleScope, however. There
// are two places where we therefore use GetHeapObjectType() instead. Both that
// function and this class should eventually be removed.
class HeapObjectType {
 public:
  enum Flag : uint8_t { kUndetectable = 1 << 0, kCallable = 1 << 1 };

  using Flags = base::Flags<Flag>;

  HeapObjectType(InstanceType instance_type, ElementsKind elements_kind,
                 Flags flags, OddballType oddball_type, HoleType hole_type)
      : instance_type_(instance_type),
        elements_kind_(elements_kind),
        oddball_type_(oddball_type),
        hole_type_(hole_type),
        flags_(flags) {
    DCHECK_EQ(instance_type == ODDBALL_TYPE,
              oddball_type != OddballType::kNone);
  }

  OddballType oddball_type() const { return oddball_type_; }
  HoleType hole_type() const { return hole_type_; }
  // For compatibility with MapRef.
  OddballType oddball_type(JSHeapBroker* broker) const { return oddball_type_; }
  HoleType hole_type(JSHeapBroker* broker) const { return hole_type_; }
  InstanceType instance_type() const { return instance_type_; }
  Flags flags() const { return flags_; }
  ElementsKind elements_kind() const { return elements_kind_; }

  bool is_callable() const { return flags_ & kCallable; }
  bool is_undetectable() const { return flags_ & kUndetectable; }

 private:
  InstanceType const instance_type_;
  ElementsKind const elements_kind_;
  OddballType const oddball_type_;
  HoleType const hole_type_;
  Flags const flags_;
};

// Constructors are carefully defined such that we do a type check on
// the outermost Ref class in the inheritance chain only.
#define DEFINE_REF_CONSTRUCTOR(Name, Base)                     \
  explicit Name##Ref(ObjectData* data, bool check_type = true) \
      : Base(data, false) {                                    \
    if (check_type) {                                          \
      CHECK(Is##Name());                                       \
    }                                                          \
  }

class HeapObjectRef : public ObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(HeapObject, ObjectRef)

  IndirectHandle<HeapObject> object() const;

  MapRef map(JSHeapBroker* broker) const;

  // Only for use in special situations where we need to read the object's
  // current map (instead of returning the cached map). Use with care.
  OptionalMapRef map_direct_read(JSHeapBroker* broker) const;

  // See the comment on the HeapObjectType class.
  HeapObjectType GetHeapObjectType(JSHeapBroker* broker) const;
};

class PropertyCellRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(PropertyCell, HeapObjectRef)

  IndirectHandle<PropertyCell> object() const;

  V8_WARN_UNUSED_RESULT bool Cache(JSHeapBroker* broker) const;
  void CacheAsProtector(JSHeapBroker* broker) const {
    bool cached = Cache(broker);
    // A protector always holds a Smi value and its cell type never changes, so
    // Cache can't fail.
    CHECK(cached);
  }

  PropertyDetails property_details() const;
  ObjectRef value(JSHeapBroker* broker) const;
};

class JSReceiverRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(JSReceiver, HeapObjectRef)

  IndirectHandle<JSReceiver> object() const;
};

class JSObjectRef : public JSReceiverRef {
 public:
  DEFINE_REF_CONSTRUCTOR(JSObject, JSReceiverRef)

  IndirectHandle<JSObject> object() const;

  OptionalObjectRef raw_properties_or_hash(JSHeapBroker* broker) const;

  // Usable only for in-object properties. Only use this if the underlying
  // value can be an uninitialized-sentinel. Otherwise, use the higher-level
  // GetOwnFastConstantDataProperty/GetOwnFastConstantDoubleProperty.
  OptionalObjectRef RawInobjectPropertyAt(JSHeapBroker* broker,
                                          FieldIndex index) const;

  // Return the element at key {index} if {index} is known to be an own data
  // property of the object that is non-writable and non-configurable. If
  // {dependencies} is non-null, a dependency will be taken to protect
  // against inconsistency due to weak memory concurrency.
  OptionalObjectRef GetOwnConstantElement(
      JSHeapBroker* broker, FixedArrayBaseRef elements_ref, uint32_t index,
      CompilationDependencies* dependencies) const;
  // The direct-read implementation of the above, extracted into a helper since
  // it's also called from compilation-dependency validation. This helper is
  // guaranteed to not create new Ref instances.
  std::optional<Tagged<Object>> GetOwnConstantElementFromHeap(
      JSHeapBroker* broker, Tagged<FixedArrayBase> elements,
      ElementsKind elements_kind, uint32_t index) const;

  // Return the value of the property identified by the field {index}
  // if {index} is known to be an own data property of the object and the field
  // is constant.
  // If a property was successfully read, then the function will take a
  // dependency to check the value of the property at code finalization time.
  //
  // This is *not* allowed to be a double representation field. Those should use
  // GetOwnFastDoubleProperty, to avoid unnecessary HeapNumber allocation.
  OptionalObjectRef GetOwnFastConstantDataProperty(
      JSHeapBroker* broker, Representation field_representation,
      FieldIndex index, CompilationDependencies* dependencies) const;

  // Return the value of the double property identified by the field {index}
  // if {index} is known to be an own data property of the object and the field
  // is constant.
  // If a property was successfully read, then the function will take a
  // dependency to check the value of the property at code finalization time.
  std::optional<Float64> GetOwnFastConstantDoubleProperty(
      JSHeapBroker* broker, FieldIndex index,
      CompilationDependencies* dependencies) const;

  // Return the value of the dictionary property at {index} in the dictionary
  // if {index} is known to be an own data property of the object.
  OptionalObjectRef GetOwnDictionaryProperty(
      JSHeapBroker* broker, InternalIndex index,
      CompilationDependencies* dependencies) const;

  // When concurrent inlining is enabled, reads the elements through a direct
  // relaxed read. This is to ease the transition to unserialized (or
  // background-serialized) elements.
  OptionalFixedArrayBaseRef elements(JSHeapBroker* broker,
                                     RelaxedLoadTag) const;
  bool IsElementsTenured(FixedArrayBaseRef elements);

  OptionalMapRef GetObjectCreateMap(JSHeapBroker* broker) const;
};

class JSDataViewRef : public JSObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(JSDataView, JSObjectRef)

  IndirectHandle<JSDataView> object() const;

  size_t byte_length() const;
};

class JSBoundFunctionRef : public JSObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(JSBoundFunction, JSObjectRef)

  IndirectHandle<JSBoundFunction> object() const;

  JSReceiverRef bound_target_function(JSHeapBroker* broker) const;
  ObjectRef bound_this(JSHeapBroker* broker) const;
  FixedArrayRef bound_arguments(JSHeapBroker* broker) const;
};

class V8_EXPORT_PRIVATE JSFunctionRef : public JSObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(JSFunction, JSObjectRef)

  IndirectHandle<JSFunction> object() const;

  // Returns true, iff the serialized JSFunctionData contents are consistent
  // with the state of the underlying JSFunction object. Must be called from
  // the main thread.
  bool IsConsistentWithHeapState(JSHeapBroker* broker) const;

  ContextRef context(JSHeapBroker* broker) const;
  NativeContextRef native_context(JSHeapBroker* broker) const;
  SharedFunctionInfoRef shared(JSHeapBroker* broker) const;
  OptionalCodeRef code(JSHeapBroker* broker) const;

  bool has_initial_map(JSHeapBroker* broker) const;
  bool PrototypeRequiresRuntimeLookup(JSHeapBroker* broker) const;
  bool has_instance_prototype(JSHeapBroker* broker) const;
  HeapObjectRef instance_prototype(JSHeapBroker* broker) const;
  MapRef initial_map(JSHeapBroker* broker) const;
  int InitialMapInstanceSizeWithMinSlack(JSHeapBroker* broker) const;
  FeedbackCellRef raw_feedback_cell(JSHeapBroker* broker) const;
  OptionalFeedbackVectorRef feedback_vector(JSHeapBroker* broker) const;
};

class RegExpBoilerplateDescriptionRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(RegExpBoilerplateDescription, HeapObjectRef)

  IndirectHandle<RegExpBoilerplateDescription> object() const;

  HeapObjectRef data(JSHeapBroker* broker) const;
  StringRef source(JSHeapBroker* broker) const;
  int flags() const;
};

// HeapNumberRef is only created for immutable HeapNumbers. Mutable
// HeapNumbers (those owned by in-object or backing store fields with
// representation type Double are not exposed to the compiler through
// HeapNumberRef. Instead, we read their value, and protect that read
// with a field-constness Dependency.
class HeapNumberRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(HeapNumber, HeapObjectRef)

  IndirectHandle<HeapNumber> object() const;

  double value() const;
  uint64_t value_as_bits() const;
};

class ContextRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(Context, HeapObjectRef)

  IndirectHandle<Context> object() const;

  // {previous} decrements {depth} by 1 for each previous link successfully
  // followed. If {depth} != 0 on function return, then it only got partway to
  // the desired depth.
  ContextRef previous(JSHeapBroker* broker, size_t* depth) const;

  // Only returns a value if the index is valid for this ContextRef.
  OptionalObjectRef get(JSHeapBroker* broker, int index) const;

  ScopeInfoRef scope_info(JSHeapBroker* broker) const;

  // Only returns a value if the index is valid for this ContextRef.
  OptionalObjectRef TryGetSideData(JSHeapBroker* broker, int index) const;
};

#define BROKER_NATIVE_CONTEXT_FIELDS(V)          \
  V(JSFunction, array_function)                  \
  V(JSFunction, bigint_function)                 \
  V(JSFunction, boolean_function)                \
  V(JSFunction, function_prototype_apply)        \
  V(JSFunction, number_function)                 \
  V(JSFunction, object_function)                 \
  V(JSFunction, promise_function)                \
  V(JSFunction, promise_then)                    \
  V(JSFunction, regexp_exec_function)            \
  V(JSFunction, regexp_function)                 \
  V(JSFunction, string_function)                 \
  V(JSFunction, symbol_function)                 \
  V(JSGlobalObject, global_object)               \
  V(JSGlobalProxy, global_proxy_object)          \
  V(JSObject, initial_array_prototype)           \
  V(JSObject, promise_prototype)                 \
  V(Map, async_function_object_map)              \
  V(Map, block_context_map)                      \
  V(Map, bound_function_with_constructor_map)    \
  V(Map, bound_function_without_constructor_map) \
  V(Map, catch_context_map)                      \
  V(Map, eval_context_map)                       \
  V(Map, fast_aliased_arguments_map)             \
  V(Map, function_context_map)                   \
  V(Map, initial_array_iterator_map)             \
  V(Map, initial_string_iterator_map)            \
  V(Map, iterator_result_map)                    \
  V(Map, js_array_holey_double_elements_map)     \
  V(Map, js_array_holey_elements_map)            \
  V(Map, js_array_holey_smi_elements_map)        \
  V(Map, js_array_packed_double_elements_map)    \
  V(Map, js_array_packed_elements_map)           \
  V(Map, js_array_packed_smi_elements_map)       \
  V(Map, map_key_iterator_map)                   \
  V(Map, map_key_value_iterator_map)             \
  V(Map, map_value_iterator_map)                 \
  V(Map, meta_map)                               \
  V(Map, set_key_value_iterator_map)             \
  V(Map, set_value_iterator_map)                 \
  V(Map, sloppy_arguments_map)                   \
  V(Map, slow_object_with_null_prototype_map)    \
  V(Map, strict_arguments_map)                   \
  V(Map, with_context_map)                       \
  V(ScriptContextTable, script_context_table)

class NativeContextRef : public ContextRef {
 public:
  DEFINE_REF_CONSTRUCTOR(NativeContext, ContextRef)

  IndirectHandle<NativeContext> object() const;

#define DECL_ACCESSOR(type, name) type##Ref name(JSHeapBroker* broker) const;
  BROKER_NATIVE_CONTEXT_FIELDS(DECL_ACCESSOR)
#undef DECL_ACCESSOR

  MapRef GetFunctionMapFromIndex(JSHeapBroker* broker, int index) const;
  MapRef GetInitialJSArrayMap(JSHeapBroker* broker, ElementsKind kind) const;
  OptionalJSFunctionRef GetConstructorFunction(JSHeapBroker* broker,
                                               MapRef map) const;
  bool GlobalIsDetached(JSHeapBroker* broker) const;
};

class NameRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(Name, HeapObjectRef)

  IndirectHandle<Name> object() const;

  bool IsUniqueName() const;
};

class DescriptorArrayRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(DescriptorArray, HeapObjectRef)

  IndirectHandle<DescriptorArray> object() const;

  PropertyDetails GetPropertyDetails(InternalIndex descriptor_index) const;
  NameRef GetPropertyKey(JSHeapBroker* broker,
                         InternalIndex descriptor_index) const;
  OptionalObjectRef GetStrongValue(JSHeapBroker* broker,
                                   InternalIndex descriptor_index) const;
};

class FeedbackCellRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(FeedbackCell, HeapObjectRef)

  IndirectHandle<FeedbackCell> object() const;

  ObjectRef value(JSHeapBroker* broker) const;

  // Convenience wrappers around {value()}:
  OptionalFeedbackVectorRef feedback_vector(JSHeapBroker* broker) const;
  OptionalSharedFunctionInfoRef shared_function_info(
      JSHeapBroker* broker) const;
};

class FeedbackVectorRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(FeedbackVector, HeapObjectRef)

  IndirectHandle<FeedbackVector> object() const;

  SharedFunctionInfoRef shared_function_info(JSHeapBroker* broker) const;

  FeedbackCellRef GetClosureFeedbackCell(JSHeapBroker* broker, int index) const;

  bool was_once_deoptimized() const;
};

class AccessorInfoRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(AccessorInfo, HeapObjectRef)

  IndirectHandle<AccessorInfo> object() const;
};

class AllocationSiteRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(AllocationSite, HeapObjectRef)

  IndirectHandle<AllocationSite> object() const;

  bool PointsToLiteral() const;
  AllocationType GetAllocationType() const;
  ObjectRef nested_site(JSHeapBroker* broker) const;

  OptionalJSObjectRef boilerplate(JSHeapBroker* broker) const;
  ElementsKind GetElementsKind() const;
  bool CanInlineCall() const;
};

class BigIntRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(BigInt, HeapObjectRef)

  IndirectHandle<BigInt> object() const;

  uint64_t AsUint64() const;
  int64_t AsInt64(bool* lossless) const;
};

class V8_EXPORT_PRIVATE MapRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(Map, HeapObjectRef)

  IndirectHandle<Map> object() const;

  int instance_size() const;
  InstanceType instance
```