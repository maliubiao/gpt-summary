Response:
Let's break down the thought process for analyzing the `js-heap-broker.h` file.

1. **Understand the Goal:** The request asks for the functionality of the `JSHeapBroker` class and the file it's in. It also asks about Torque, JavaScript connections, logic, and common errors.

2. **Initial Scan and Key Observations:**
   - The file is a `.h` header file, meaning it primarily declares classes and functions, not implements them. The actual implementation would be in a `.cc` file (likely `js-heap-broker.cc`).
   - The copyright and `#ifndef` guards indicate this is a standard C++ header file.
   - The included headers give clues about dependencies and areas of functionality: `compiler`, `handles`, `heap`, `objects`, `execution`, etc. This strongly suggests a component involved in the V8 compiler and how it interacts with the JavaScript heap.
   - The class name `JSHeapBroker` is suggestive of a middleman or intermediary related to the JavaScript heap. "Broker" often implies managing access or information flow.

3. **Deconstructing the Class Declaration:**  Read through the `JSHeapBroker` class member by member, function by function. For each member or function, ask:
   - What is its purpose?
   - What data does it manage or operate on?
   - Are there any hints in the name or comments?
   - What other parts of V8 does it likely interact with?

4. **Categorizing Functionality:** As you go through the members, start grouping them by related functionality. This helps to organize the information. Initial categories might be:
   - **Initialization and Lifecycle:** Constructor, destructor, `InitializeAndStartSerializing`, `StopSerializing`, `Retire`, `Attach/DetachLocalIsolate`.
   - **Heap Access/Information:** `GetOrCreateData`, `TryGetOrCreateData`, `GetRootHandle`, `CanonicalPersistentHandle`, `IsCanonicalHandle`, `ObjectMayBeUninitialized`.
   - **Feedback and Optimization:**  Functions related to `FeedbackSource`, `ProcessedFeedback`, `BinaryOperationHint`, `CompareOperationHint`, `ForInHint`, `GetPropertyAccessInfo`.
   - **Internal State Management:**  `mode_`, `tracing_enabled_`, `local_isolate_`, `canonical_handles_`, `feedback_`, etc.
   - **Debugging and Tracing:** `TRACE_BROKER`, `TRACE_BROKER_MISSING`, `PrintRefsAnalysis`, `Trace`, `IncrementTracingIndentation`, `DecrementTracingIndentation`, `TraceScope`.
   - **Utility/Helper Functions:** `IsArrayOrObjectPrototype`, `GetTypedArrayStringTag`, `IsMainThread`, `local_isolate_or_isolate`, `FindRootIndex`.
   - **Concurrency Control:** `RecursiveSharedMutexGuardIfNeeded`, `MapUpdaterGuardIfNeeded`, `BoilerplateMigrationGuardIfNeeded`.
   - **Root Object Access:** `READ_ONLY_ROOT_LIST` macros.

5. **Connecting to JavaScript Concepts:** Once you have a good understanding of the C++ code's purpose, think about how these functionalities relate to JavaScript execution and optimization.
   - **Heap Access:**  This directly relates to how JavaScript objects are stored and accessed in memory.
   - **Feedback:** This is crucial for V8's optimizing compilers. Information about how code is executed (e.g., types of variables, called functions) is used to generate more efficient machine code.
   - **Prototypes:**  JavaScript's prototype inheritance mechanism is clearly relevant to functions like `IsArrayOrObjectPrototype`.
   - **Literals:** Functions dealing with `ArrayOrObjectLiteral`, `RegExpLiteral`, and `TemplateObject` show how the broker handles the creation and representation of these JavaScript constructs.
   - **Property Access:**  The functions related to property access and `PropertyAccessInfo` are directly tied to how JavaScript accesses object properties.

6. **Considering Torque (Not Applicable Here):** The prompt specifically asks about `.tq` files. Since this file ends in `.h`, it's a standard C++ header and not a Torque file. So, this part of the request can be addressed by stating that fact.

7. **Illustrative JavaScript Examples:** For the functionalities that relate to JavaScript, create simple JavaScript code snippets that demonstrate those concepts. This makes the explanation more concrete and understandable. Focus on showing *why* the broker needs this information.

8. **Logic and Assumptions (Type Narrowing Example):** Look for places where the broker might be making assumptions or performing logical deductions based on available information. The feedback processing for binary operations is a good example. Illustrate this with input and output based on type information.

9. **Common Programming Errors:** Think about common mistakes JavaScript developers make that could be related to the broker's functionality. Type errors, accessing non-existent properties, and performance issues related to unoptimized code are good examples.

10. **Review and Refine:**  Go back through your explanation and ensure clarity, accuracy, and completeness. Check for any jargon that needs explanation. Make sure the connections between the C++ code and JavaScript concepts are clear. Ensure that the examples are correct and illustrative.

**Self-Correction/Refinement Example During the Process:**

Initially, one might just say "the broker manages heap objects."  But that's too vague. Upon closer inspection of functions like `GetOrCreateData`, `CanonicalPersistentHandle`, and the tracing macros, you realize it's not just about *managing* but also about *tracking*, *identifying*, and potentially *serializing* these objects for compiler optimizations. This leads to a more nuanced understanding of its role. Similarly, realizing the importance of "feedback" for optimization deepens the understanding of the purpose of many functions.
好的，让我们来分析一下 `v8/src/compiler/js-heap-broker.h` 这个 V8 源代码文件的功能。

**主要功能：作为编译器与 JavaScript 堆之间的中介**

`JSHeapBroker` 的核心职责是在 V8 的优化编译器（例如 TurboFan 或 Maglev）和 JavaScript 堆之间建立一个桥梁。它允许编译器以一种安全且高效的方式访问和查询关于堆中对象的信息，而无需直接持有原始的 JavaScript 对象句柄。

更具体地说，`JSHeapBroker` 承担以下关键功能：

1. **对象信息的缓存和抽象 (Caching and Abstraction of Object Information):**
   - 它维护一个关于堆中相关对象的缓存（通过 `ObjectData` 等结构）。这些缓存包含了编译器需要的关于对象的重要信息，例如对象的类型、属性、原型链、反馈向量等。
   - 它提供了对这些信息的抽象访问方式，隐藏了底层的堆布局和对象表示细节。编译器不需要直接操作原始的 `Handle` 或 `Tagged` 指针，而是通过 `JSHeapBroker` 提供的 `ObjectRef` 和其他引用类型来访问。

2. **处理持久句柄 (Handling Persistent Handles):**
   - 在编译过程中，编译器需要持有对某些堆对象的引用，即使在垃圾回收期间这些对象可能会被移动。`JSHeapBroker` 负责创建和管理这些持久句柄（Canonical Persistent Handles），确保编译器引用的对象在整个编译过程中保持有效。

3. **访问和处理反馈向量 (Accessing and Processing Feedback Vectors):**
   - V8 的优化编译器 heavily 依赖于运行时收集的类型反馈信息，以进行类型推断和优化。`JSHeapBroker` 提供了访问和处理与函数和对象关联的反馈向量的功能。它可以查询特定操作（如属性访问、函数调用）的反馈信息，并将其转换为编译器更容易理解和使用的格式 (`ProcessedFeedback`)。

4. **属性访问信息的管理 (Managing Property Access Information):**
   - 为了优化属性访问，编译器需要了解属性的布局、访问模式等信息。`JSHeapBroker` 负责管理和提供关于对象属性访问的详细信息 (`PropertyAccessInfo`)。

5. **只读根对象的访问 (Accessing Read-Only Root Objects):**
   - V8 堆中包含一些只读的根对象（例如 `undefined`, `null` 的表示）。`JSHeapBroker` 提供了高效访问这些根对象的方式。

6. **本地 Isolate 的管理 (Managing Local Isolate):**
   - 在某些编译阶段，编译器可能会关联到一个本地的 `Isolate` 实例。`JSHeapBroker` 负责管理这个本地 `Isolate` 的生命周期。

7. **跟踪和调试 (Tracing and Debugging):**
   - 通过 `TRACE_BROKER` 宏，`JSHeapBroker` 提供了在调试模式下输出详细信息的机制，帮助开发者理解编译过程和堆状态。

**关于 `.tq` 结尾的文件:**

如果 `v8/src/compiler/js-heap-broker.h` 以 `.tq` 结尾，那么它确实会是一个 **V8 Torque 源代码文件**。Torque 是一种 V8 内部使用的类型化的中间语言，用于生成高效的 C++ 代码。Torque 文件通常用于定义 V8 内部的运行时函数和类型。然而，从你提供的文件内容来看，它是一个标准的 C++ 头文件 (`.h`)。

**与 JavaScript 功能的关系以及 JavaScript 示例:**

`JSHeapBroker` 的所有功能都直接或间接地与 JavaScript 的功能相关，因为它服务于优化 JavaScript 代码的编译过程。以下是一些 JavaScript 示例，展示了 `JSHeapBroker` 如何参与到这些功能的背后：

**示例 1: 属性访问优化**

```javascript
function getProperty(obj) {
  return obj.x;
}

const myObject = { x: 10 };
getProperty(myObject); // 第一次调用，可能触发类型反馈

const anotherObject = { x: "hello" };
getProperty(anotherObject); // 第二次调用，类型反馈可能会更新
```

当 V8 编译 `getProperty` 函数时，`JSHeapBroker` 会：

- **第一次调用:** 查询与 `getProperty` 函数关联的反馈向量，以了解 `obj.x` 属性访问的类型信息。最初可能没有足够的信息。
- **第二次调用:**  更新反馈向量，记录 `obj.x` 可能返回数字或字符串。
- **后续编译:**  根据收集到的反馈信息，`JSHeapBroker` 可以提供 `PropertyAccessInfo`，告诉编译器 `obj` 的形状、`x` 属性的偏移量和可能的类型，从而生成更高效的机器码，例如内联属性访问。

**示例 2: 函数调用优化**

```javascript
function add(a, b) {
  return a + b;
}

add(5, 3); // 第一次调用
add(1.5, 2.5); // 第二次调用
```

当编译 `add` 函数时，`JSHeapBroker` 会：

- **查询反馈向量:** 获取关于 `add` 函数参数类型的反馈信息。
- **提供 `ProcessedFeedback`:**  根据反馈，`JSHeapBroker` 会提供关于 `a` 和 `b` 可能的类型信息（例如，可能是 Smi，可能是 HeapNumber）。
- **类型特化:** 编译器可以使用这些信息生成针对不同类型组合的优化代码路径。

**示例 3: 对象字面量优化**

```javascript
function createPoint(x, y) {
  return { x: x, y: y };
}

createPoint(1, 2);
```

当编译 `createPoint` 函数时，`JSHeapBroker` 会：

- **处理对象字面量反馈:**  获取关于对象字面量 `{ x: x, y: y }` 的反馈信息，例如属性的名称和顺序。
- **提供对象形状信息:** `JSHeapBroker` 可以提供关于创建的对象的“形状”（Map）的信息，允许编译器预先分配内存并避免运行时的布局计算。

**代码逻辑推理和假设输入/输出 (假设性例子):**

假设 `JSHeapBroker` 中有一个函数 `GetPropertyType(ObjectRef obj, NameRef propertyName)`，其目的是推断给定对象的给定属性的可能类型。

**假设输入:**

- `obj`: 一个指向 JavaScript 对象的 `ObjectRef`，例如一个表示 `{ a: 10, b: "hello" }` 的对象。
- `propertyName`: 一个表示属性名称的 `NameRef`，例如 "a"。

**代码逻辑推理 (简化):**

1. **查找反馈信息:** `GetPropertyType` 会首先查找与 `obj` 关联的反馈向量，看看是否有关于属性 "a" 的类型信息。
2. **分析反馈:**
   - 如果反馈表明 "a" 总是数字，则推断类型为数字。
   - 如果反馈表明 "a" 总是字符串，则推断类型为字符串。
   - 如果反馈表明 "a" 可以是数字或字符串，则推断类型为 `Number | String` 或 `Tagged<Object>` (更通用的类型)。
   - 如果没有足够的反馈信息，则可能返回一个表示类型不确定的值。
3. **结合对象形状信息:**  `GetPropertyType` 还可以结合对象的形状（Map）信息，查看属性是否总是存在，以及其在对象中的布局。

**假设输出:**

- 如果反馈表明 "a" 总是数字：返回表示数字类型的信息（例如，一个枚举值或一个类型描述对象）。
- 如果反馈信息不足：返回表示类型不确定的信息。

**用户常见的编程错误以及 `JSHeapBroker` 的作用:**

`JSHeapBroker` 并不直接阻止用户编写错误的 JavaScript 代码，但它通过优化编译过程，可以 *间接地* 暴露或缓解某些类型错误的性能影响。以下是一些例子：

1. **类型不一致导致的性能下降:**

   ```javascript
   function calculate(x) {
     return x * 2;
   }

   calculate(5);      // x 是数字
   calculate("hello"); // x 是字符串
   ```

   **错误:**  `calculate` 函数的参数 `x` 的类型在运行时发生了变化。

   **`JSHeapBroker` 的作用:**  `JSHeapBroker` 会通过反馈向量记录 `x` 的类型变化。优化编译器最初可能假设 `x` 是数字并生成了优化的乘法代码。当遇到字符串时，优化的代码可能会失效，导致 deoptimization，降低性能。`JSHeapBroker` 提供的反馈信息可以帮助编译器生成更通用的代码，或者在类型稳定时生成更特化的代码。

2. **访问不存在的属性:**

   ```javascript
   function process(obj) {
     return obj.value;
   }

   const data = { val: 10 };
   process(data); // 错误：属性名拼写错误
   ```

   **错误:**  用户想要访问 `val` 属性，但错误地写成了 `value`。

   **`JSHeapBroker` 的作用:**  当编译器尝试优化 `obj.value` 的访问时，`JSHeapBroker` 可能会提供关于 `obj` 对象形状的信息，指出不存在 `value` 属性。虽然 `JSHeapBroker` 不会阻止代码运行，但它可以帮助编译器理解访问模式，并可能在某些情况下生成更快的“未找到属性”的处理代码。

3. **原型链查找的性能影响:**

   ```javascript
   function find(obj) {
     return obj.toString();
   }

   const myObj = {};
   find(myObj);
   ```

   **`JSHeapBroker` 的作用:**  `toString` 方法存在于 `Object.prototype` 上。`JSHeapBroker` 可以提供关于 `myObj` 的原型链信息。优化编译器可以利用这些信息来优化原型链查找过程，例如通过内联原型属性访问。如果原型链很长，且每次访问都需要向上查找，性能可能会受到影响。`JSHeapBroker` 帮助编译器了解这种模式并进行优化。

**总结:**

`v8/src/compiler/js-heap-broker.h` 定义的 `JSHeapBroker` 类是 V8 优化编译器的关键组件，它充当了编译器和 JavaScript 堆之间的信息桥梁。它负责缓存对象信息、管理持久句柄、处理反馈向量、提供属性访问信息等，所有这些都旨在帮助编译器更好地理解 JavaScript 代码的运行时行为，并生成更高效的机器码。它不会直接阻止用户编写错误的 JavaScript 代码，但其提供的优化能力可以间接地影响代码的性能表现。

Prompt: 
```
这是目录为v8/src/compiler/js-heap-broker.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-heap-broker.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_JS_HEAP_BROKER_H_
#define V8_COMPILER_JS_HEAP_BROKER_H_

#include <optional>

#include "src/base/compiler-specific.h"
#include "src/base/macros.h"
#include "src/base/platform/mutex.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/common/globals.h"
#include "src/compiler/access-info.h"
#include "src/compiler/feedback-source.h"
#include "src/compiler/heap-refs.h"
#include "src/compiler/processed-feedback.h"
#include "src/compiler/refs-map.h"
#include "src/execution/local-isolate.h"
#include "src/handles/handles.h"
#include "src/handles/persistent-handles.h"
#include "src/heap/local-heap.h"
#include "src/heap/parked-scope.h"
#include "src/objects/code-kind.h"
#include "src/objects/feedback-vector.h"
#include "src/objects/objects.h"
#include "src/objects/tagged.h"
#include "src/roots/roots.h"
#include "src/utils/address-map.h"
#include "src/utils/identity-map.h"
#include "src/utils/ostreams.h"
#include "src/zone/zone-containers.h"

namespace v8 {
namespace internal {

namespace maglev {
class MaglevCompilationInfo;
}

namespace compiler {

class ObjectRef;

std::ostream& operator<<(std::ostream& os, ObjectRef ref);

#define TRACE_BROKER(broker, x)                                          \
  do {                                                                   \
    if (broker->tracing_enabled() && v8_flags.trace_heap_broker_verbose) \
      StdoutStream{} << broker->Trace() << x << '\n';                    \
  } while (false)

#define TRACE_BROKER_MISSING(broker, x)                                        \
  do {                                                                         \
    if (broker->tracing_enabled())                                             \
      StdoutStream{} << broker->Trace() << "Missing " << x << " (" << __FILE__ \
                     << ":" << __LINE__ << ")" << std::endl;                   \
  } while (false)

struct PropertyAccessTarget {
  MapRef map;
  NameRef name;
  AccessMode mode;

  struct Hash {
    size_t operator()(const PropertyAccessTarget& pair) const {
      return base::hash_combine(
          base::hash_combine(pair.map.object().address(),
                             pair.name.object().address()),
          static_cast<int>(pair.mode));
    }
  };
  struct Equal {
    bool operator()(const PropertyAccessTarget& lhs,
                    const PropertyAccessTarget& rhs) const {
      return lhs.map.equals(rhs.map) && lhs.name.equals(rhs.name) &&
             lhs.mode == rhs.mode;
    }
  };
};

enum GetOrCreateDataFlag {
  // If set, a failure to create the data object results in a crash.
  kCrashOnError = 1 << 0,
  // If set, data construction assumes that the given object is protected by
  // a memory fence (e.g. acquire-release) and thus fields required for
  // construction (like Object::map) are safe to read. The protection can
  // extend to some other situations as well.
  kAssumeMemoryFence = 1 << 1,
};
using GetOrCreateDataFlags = base::Flags<GetOrCreateDataFlag>;
DEFINE_OPERATORS_FOR_FLAGS(GetOrCreateDataFlags)

class V8_EXPORT_PRIVATE JSHeapBroker {
 public:
  JSHeapBroker(Isolate* isolate, Zone* broker_zone, bool tracing_enabled,
               CodeKind code_kind);

  // For use only in tests, sets default values for some arguments. Avoids
  // churn when new flags are added.
  JSHeapBroker(Isolate* isolate, Zone* broker_zone)
      : JSHeapBroker(isolate, broker_zone, v8_flags.trace_heap_broker,
                     CodeKind::TURBOFAN_JS) {}

  ~JSHeapBroker();

  // The compilation target's native context. We need the setter because at
  // broker construction time we don't yet have the canonical handle.
  NativeContextRef target_native_context() const {
    return target_native_context_.value();
  }
  void SetTargetNativeContextRef(DirectHandle<NativeContext> native_context);

  void InitializeAndStartSerializing(
      DirectHandle<NativeContext> native_context);

  Isolate* isolate() const { return isolate_; }

  // The pointer compression cage base value used for decompression of all
  // tagged values except references to InstructionStream objects.
  PtrComprCageBase cage_base() const {
#if V8_COMPRESS_POINTERS
    return cage_base_;
#else
    return PtrComprCageBase{};
#endif  // V8_COMPRESS_POINTERS
  }

  Zone* zone() const { return zone_; }
  bool tracing_enabled() const { return tracing_enabled_; }

  NexusConfig feedback_nexus_config() const {
    return IsMainThread() ? NexusConfig::FromMainThread(isolate())
                          : NexusConfig::FromBackgroundThread(
                                isolate(), local_isolate()->heap());
  }

  enum BrokerMode { kDisabled, kSerializing, kSerialized, kRetired };
  BrokerMode mode() const { return mode_; }

  void StopSerializing();
  void Retire();
  bool SerializingAllowed() const;

#ifdef DEBUG
  // Get the current heap broker for this thread. Only to be used for DCHECKs.
  static JSHeapBroker* Current();
#endif

  // Remember the local isolate and initialize its local heap with the
  // persistent and canonical handles provided by {info}.
  void AttachLocalIsolate(OptimizedCompilationInfo* info,
                          LocalIsolate* local_isolate);
  // Forget about the local isolate and pass the persistent and canonical
  // handles provided back to {info}. {info} is responsible for disposing of
  // them.
  void DetachLocalIsolate(OptimizedCompilationInfo* info);

  // TODO(v8:7700): Refactor this once the broker is no longer
  // Turbofan-specific.
  void AttachLocalIsolateForMaglev(maglev::MaglevCompilationInfo* info,
                                   LocalIsolate* local_isolate);
  void DetachLocalIsolateForMaglev(maglev::MaglevCompilationInfo* info);

  // Attaches the canonical handles map from the compilation info to the broker.
  // Ownership of the map remains in the compilation info.
  template <typename CompilationInfoT>
  void AttachCompilationInfo(CompilationInfoT* info) {
    set_canonical_handles(info->canonical_handles());
  }

  bool StackHasOverflowed() const;

#ifdef DEBUG
  void PrintRefsAnalysis() const;
#endif  // DEBUG

  // Returns the handle from root index table for read only heap objects.
  Handle<Object> GetRootHandle(Tagged<Object> object);

  // Never returns nullptr.
  ObjectData* GetOrCreateData(Handle<Object> object,
                              GetOrCreateDataFlags flags = {});
  ObjectData* GetOrCreateData(Tagged<Object> object,
                              GetOrCreateDataFlags flags = {});

  // Gets data only if we have it. However, thin wrappers will be created for
  // smis, read-only objects and never-serialized objects.
  ObjectData* TryGetOrCreateData(Handle<Object> object,
                                 GetOrCreateDataFlags flags = {});
  ObjectData* TryGetOrCreateData(Tagged<Object> object,
                                 GetOrCreateDataFlags flags = {});

  // Check if {object} is any native context's %ArrayPrototype% or
  // %ObjectPrototype%.
  bool IsArrayOrObjectPrototype(JSObjectRef object) const;
  bool IsArrayOrObjectPrototype(Handle<JSObject> object) const;

  bool HasFeedback(FeedbackSource const& source) const;
  void SetFeedback(FeedbackSource const& source,
                   ProcessedFeedback const* feedback);
  FeedbackSlotKind GetFeedbackSlotKind(FeedbackSource const& source) const;

  ElementAccessFeedback const& ProcessFeedbackMapsForElementAccess(
      ZoneVector<MapRef>& maps, KeyedAccessMode const& keyed_mode,
      FeedbackSlotKind slot_kind);

  // Binary, comparison and for-in hints can be fully expressed via
  // an enum. Insufficient feedback is signaled by <Hint enum>::kNone.
  BinaryOperationHint GetFeedbackForBinaryOperation(
      FeedbackSource const& source);
  CompareOperationHint GetFeedbackForCompareOperation(
      FeedbackSource const& source);
  ForInHint GetFeedbackForForIn(FeedbackSource const& source);

  ProcessedFeedback const& GetFeedbackForCall(FeedbackSource const& source);
  ProcessedFeedback const& GetFeedbackForGlobalAccess(
      FeedbackSource const& source);
  ProcessedFeedback const& GetFeedbackForInstanceOf(
      FeedbackSource const& source);
  TypeOfFeedback::Result GetFeedbackForTypeOf(FeedbackSource const& source);
  ProcessedFeedback const& GetFeedbackForArrayOrObjectLiteral(
      FeedbackSource const& source);
  ProcessedFeedback const& GetFeedbackForRegExpLiteral(
      FeedbackSource const& source);
  ProcessedFeedback const& GetFeedbackForTemplateObject(
      FeedbackSource const& source);
  ProcessedFeedback const& GetFeedbackForPropertyAccess(
      FeedbackSource const& source, AccessMode mode,
      OptionalNameRef static_name);

  ProcessedFeedback const& ProcessFeedbackForBinaryOperation(
      FeedbackSource const& source);
  ProcessedFeedback const& ProcessFeedbackForCompareOperation(
      FeedbackSource const& source);
  ProcessedFeedback const& ProcessFeedbackForForIn(
      FeedbackSource const& source);
  ProcessedFeedback const& ProcessFeedbackForTypeOf(
      FeedbackSource const& source);

  bool FeedbackIsInsufficient(FeedbackSource const& source) const;

  OptionalNameRef GetNameFeedback(FeedbackNexus const& nexus);

  PropertyAccessInfo GetPropertyAccessInfo(MapRef map, NameRef name,
                                           AccessMode access_mode);

  StringRef GetTypedArrayStringTag(ElementsKind kind);

  bool IsMainThread() const {
    return local_isolate() == nullptr || local_isolate()->is_main_thread();
  }

  LocalIsolate* local_isolate() const { return local_isolate_; }

  // TODO(jgruber): Consider always having local_isolate_ set to a real value.
  // This seems not entirely trivial since we currently reset local_isolate_ to
  // nullptr at some point in the JSHeapBroker lifecycle.
  LocalIsolate* local_isolate_or_isolate() const {
    return local_isolate() != nullptr ? local_isolate()
                                      : isolate()->AsLocalIsolate();
  }

  std::optional<RootIndex> FindRootIndex(HeapObjectRef object) {
    // No root constant is a JSReceiver.
    if (object.IsJSReceiver()) return {};
    Address address = object.object()->ptr();
    RootIndex root_index;
    if (root_index_map_.Lookup(address, &root_index)) {
      return root_index;
    }
    return {};
  }

  // Return the corresponding canonical persistent handle for {object}. Create
  // one if it does not exist.
  // If a local isolate is attached, we can create the persistent handle through
  // it. This commonly happens during the Execute phase.
  // If we don't, that means we are calling this method from serialization. If
  // that happens, we should be inside a persistent handle scope. Then, we would
  // just use the regular handle creation.
  template <typename T>
  Handle<T> CanonicalPersistentHandle(Tagged<T> object) {
    DCHECK_NOT_NULL(canonical_handles_);
    Address address = object.ptr();
    if (Internals::HasHeapObjectTag(address)) {
      RootIndex root_index;
      // CollectArrayAndObjectPrototypes calls this function often with T equal
      // to JSObject. The root index map only contains immortal, immutable
      // objects; it never contains any instances of type JSObject, since
      // JSObjects must exist within a NativeContext, and NativeContexts can be
      // created and destroyed. Thus, we can skip the lookup in the root index
      // map for those values and save a little time.
      if constexpr (std::is_convertible_v<T, JSObject>) {
        DCHECK(!root_index_map_.Lookup(address, &root_index));
      } else if (root_index_map_.Lookup(address, &root_index)) {
        return Handle<T>(isolate_->root_handle(root_index).location());
      }
    }

    Tagged<Object> obj(address);
    auto find_result = canonical_handles_->FindOrInsert(obj);
    if (find_result.already_exists) return Handle<T>(*find_result.entry);

    // Allocate new PersistentHandle if one wasn't created before.
    if (local_isolate()) {
      *find_result.entry =
          local_isolate()->heap()->NewPersistentHandle(obj).location();
    } else {
      DCHECK(PersistentHandlesScope::IsActive(isolate()));
      *find_result.entry = IndirectHandle<T>(object, isolate()).location();
    }
    return Handle<T>(*find_result.entry);
  }

  template <typename T>
  Handle<T> CanonicalPersistentHandle(Handle<T> object) {
    if (object.is_null()) return object;  // Can't deref a null handle.
    return CanonicalPersistentHandle<T>(*object);
  }

  // Checks if a canonical persistent handle for {object} exists.
  template <typename T>
  bool IsCanonicalHandle(Handle<T> handle) {
    DCHECK_NOT_NULL(canonical_handles_);
    Address* location = handle.location();
    Address address = *location;
    if (Internals::HasHeapObjectTag(address)) {
      RootIndex root_index;
      if (root_index_map_.Lookup(address, &root_index)) {
        return true;
      }
      // Builtins use pseudo handles that are canonical and persistent by
      // design.
      if (isolate()->IsBuiltinTableHandleLocation(location)) {
        return true;
      }
    }
    return canonical_handles_->Find(Tagged<Object>(address)) != nullptr;
  }

  std::string Trace() const;
  void IncrementTracingIndentation();
  void DecrementTracingIndentation();

  // Locks {mutex} through the duration of this scope iff it is the first
  // occurrence. This is done to have a recursive shared lock on {mutex}.
  class V8_NODISCARD RecursiveSharedMutexGuardIfNeeded {
   protected:
    V8_INLINE RecursiveSharedMutexGuardIfNeeded(LocalIsolate* local_isolate,
                                                base::SharedMutex* mutex,
                                                int* mutex_depth_address);

    ~RecursiveSharedMutexGuardIfNeeded() {
      DCHECK_GE((*mutex_depth_address_), 1);
      (*mutex_depth_address_)--;
      DCHECK_EQ(initial_mutex_depth_, (*mutex_depth_address_));
    }

   private:
    int* const mutex_depth_address_;
    const int initial_mutex_depth_;
    ParkedSharedMutexGuardIf<base::kShared> shared_mutex_guard_;
  };

  class MapUpdaterGuardIfNeeded final
      : public RecursiveSharedMutexGuardIfNeeded {
   public:
    V8_INLINE explicit MapUpdaterGuardIfNeeded(JSHeapBroker* broker);
  };

  class BoilerplateMigrationGuardIfNeeded final
      : public RecursiveSharedMutexGuardIfNeeded {
   public:
    V8_INLINE explicit BoilerplateMigrationGuardIfNeeded(JSHeapBroker* broker);
  };

  // If this returns false, the object is guaranteed to be fully initialized and
  // thus safe to read from a memory safety perspective. The converse does not
  // necessarily hold.
  bool ObjectMayBeUninitialized(DirectHandle<Object> object) const;
  bool ObjectMayBeUninitialized(Tagged<Object> object) const;
  bool ObjectMayBeUninitialized(Tagged<HeapObject> object) const;

  void set_dependencies(CompilationDependencies* dependencies) {
    DCHECK_NOT_NULL(dependencies);
    DCHECK_NULL(dependencies_);
    dependencies_ = dependencies;
  }
  CompilationDependencies* dependencies() const {
    DCHECK_NOT_NULL(dependencies_);
    return dependencies_;
  }

#define V(Type, name, Name) inline typename ref_traits<Type>::ref_type name();
  READ_ONLY_ROOT_LIST(V)
#undef V

 private:
  friend class JSHeapBrokerScopeForTesting;
  friend class HeapObjectRef;
  friend class ObjectRef;
  friend class ObjectData;
  friend class PropertyCellData;

  ProcessedFeedback const& GetFeedback(FeedbackSource const& source) const;
  const ProcessedFeedback& NewInsufficientFeedback(FeedbackSlotKind kind) const;

  // Bottleneck FeedbackNexus access here, for storage in the broker
  // or on-the-fly usage elsewhere in the compiler.
  ProcessedFeedback const& ReadFeedbackForArrayOrObjectLiteral(
      FeedbackSource const& source);
  ProcessedFeedback const& ReadFeedbackForBinaryOperation(
      FeedbackSource const& source) const;
  ProcessedFeedback const& ReadFeedbackForTypeOf(
      FeedbackSource const& source) const;
  ProcessedFeedback const& ReadFeedbackForCall(FeedbackSource const& source);
  ProcessedFeedback const& ReadFeedbackForCompareOperation(
      FeedbackSource const& source) const;
  ProcessedFeedback const& ReadFeedbackForForIn(
      FeedbackSource const& source) const;
  ProcessedFeedback const& ReadFeedbackForGlobalAccess(
      JSHeapBroker* broker, FeedbackSource const& source);
  ProcessedFeedback const& ReadFeedbackForInstanceOf(
      FeedbackSource const& source);
  ProcessedFeedback const& ReadFeedbackForPropertyAccess(
      FeedbackSource const& source, AccessMode mode,
      OptionalNameRef static_name);
  ProcessedFeedback const& ReadFeedbackForRegExpLiteral(
      FeedbackSource const& source);
  ProcessedFeedback const& ReadFeedbackForTemplateObject(
      FeedbackSource const& source);

  void CollectArrayAndObjectPrototypes();

  void set_persistent_handles(
      std::unique_ptr<PersistentHandles> persistent_handles) {
    DCHECK_NULL(ph_);
    ph_ = std::move(persistent_handles);
    DCHECK_NOT_NULL(ph_);
  }
  std::unique_ptr<PersistentHandles> DetachPersistentHandles() {
    DCHECK_NOT_NULL(ph_);
    return std::move(ph_);
  }

  void set_canonical_handles(CanonicalHandlesMap* canonical_handles) {
    canonical_handles_ = canonical_handles;
  }

#define V(Type, name, Name) void Init##Name();
  READ_ONLY_ROOT_LIST(V)
#undef V

  Isolate* const isolate_;
#if V8_COMPRESS_POINTERS
  const PtrComprCageBase cage_base_;
#endif  // V8_COMPRESS_POINTERS
  Zone* const zone_;
  OptionalNativeContextRef target_native_context_;
  RefsMap* refs_;
  RootIndexMap root_index_map_;
  ZoneUnorderedSet<IndirectHandle<JSObject>, IndirectHandle<JSObject>::hash,
                   IndirectHandle<JSObject>::equal_to>
      array_and_object_prototypes_;
  BrokerMode mode_ = kDisabled;
  bool const tracing_enabled_;
  CodeKind const code_kind_;
  std::unique_ptr<PersistentHandles> ph_;
  LocalIsolate* local_isolate_ = nullptr;
  // The CanonicalHandlesMap is owned by the compilation info.
  CanonicalHandlesMap* canonical_handles_;
  unsigned trace_indentation_ = 0;
  ZoneUnorderedMap<FeedbackSource, ProcessedFeedback const*,
                   FeedbackSource::Hash, FeedbackSource::Equal>
      feedback_;
  ZoneUnorderedMap<PropertyAccessTarget, PropertyAccessInfo,
                   PropertyAccessTarget::Hash, PropertyAccessTarget::Equal>
      property_access_infos_;

  // Cache read only roots to avoid needing to look them up via the map.
#define V(Type, name, Name) \
  OptionalRef<typename ref_traits<Type>::ref_type> name##_;
  READ_ONLY_ROOT_LIST(V)
#undef V

  CompilationDependencies* dependencies_ = nullptr;

  // The MapUpdater mutex is used in recursive patterns; for example,
  // ComputePropertyAccessInfo may call itself recursively. Thus we need to
  // emulate a recursive mutex, which we do by checking if this heap broker
  // instance already holds the mutex when a lock is requested. This field
  // holds the locking depth, i.e. how many times the mutex has been
  // recursively locked. Only the outermost locker actually locks underneath.
  int map_updater_mutex_depth_ = 0;
  // Likewise for boilerplate migrations.
  int boilerplate_migration_mutex_depth_ = 0;

  static constexpr uint32_t kMinimalRefsBucketCount = 8;
  static_assert(base::bits::IsPowerOfTwo(kMinimalRefsBucketCount));
  static constexpr uint32_t kInitialRefsBucketCount = 1024;
  static_assert(base::bits::IsPowerOfTwo(kInitialRefsBucketCount));
};

#ifdef DEBUG
// In debug builds, store the current heap broker on a thread local, for
// DCHECKs to access it via JSHeapBroker::Current();
class V8_NODISCARD V8_EXPORT_PRIVATE CurrentHeapBrokerScope {
 public:
  explicit CurrentHeapBrokerScope(JSHeapBroker* broker);
  ~CurrentHeapBrokerScope();

 private:
  JSHeapBroker* const prev_broker_;
};
#else
class V8_NODISCARD V8_EXPORT_PRIVATE CurrentHeapBrokerScope {
 public:
  explicit CurrentHeapBrokerScope(JSHeapBroker* broker) {}
  ~CurrentHeapBrokerScope() {}
};
#endif

class V8_NODISCARD TraceScope {
 public:
  TraceScope(JSHeapBroker* broker, const char* label)
      : TraceScope(broker, static_cast<void*>(broker), label) {}

  TraceScope(JSHeapBroker* broker, ObjectData* data, const char* label)
      : TraceScope(broker, static_cast<void*>(data), label) {}

  TraceScope(JSHeapBroker* broker, void* subject, const char* label)
      : broker_(broker) {
    TRACE_BROKER(broker_, "Running " << label << " on " << subject);
    broker_->IncrementTracingIndentation();
  }

  ~TraceScope() { broker_->DecrementTracingIndentation(); }

 private:
  JSHeapBroker* const broker_;
};

// Scope that unparks the LocalHeap, if:
//   a) We have a JSHeapBroker,
//   b) Said JSHeapBroker has a LocalIsolate and thus a LocalHeap,
//   c) Said LocalHeap has been parked and
//   d) The given condition evaluates to true.
// Used, for example, when printing the graph with --trace-turbo with a
// previously parked LocalHeap.
class V8_NODISCARD UnparkedScopeIfNeeded {
 public:
  explicit UnparkedScopeIfNeeded(JSHeapBroker* broker,
                                 bool extra_condition = true) {
    if (broker != nullptr && extra_condition) {
      LocalIsolate* local_isolate = broker->local_isolate();
      if (local_isolate != nullptr && local_isolate->heap()->IsParked()) {
        unparked_scope.emplace(local_isolate->heap());
      }
    }
  }

 private:
  std::optional<UnparkedScope> unparked_scope;
};

class V8_NODISCARD JSHeapBrokerScopeForTesting {
 public:
  JSHeapBrokerScopeForTesting(JSHeapBroker* broker, Isolate* isolate,
                              Zone* zone)
      : JSHeapBrokerScopeForTesting(
            broker, std::make_unique<CanonicalHandlesMap>(
                        isolate->heap(), ZoneAllocationPolicy(zone))) {}
  JSHeapBrokerScopeForTesting(
      JSHeapBroker* broker,
      std::unique_ptr<CanonicalHandlesMap> canonical_handles)
      : canonical_handles_(std::move(canonical_handles)), broker_(broker) {
    broker_->set_canonical_handles(canonical_handles_.get());
  }
  ~JSHeapBrokerScopeForTesting() { broker_->set_canonical_handles(nullptr); }

 private:
  std::unique_ptr<CanonicalHandlesMap> canonical_handles_;
  JSHeapBroker* const broker_;
};

template <class T, typename = std::enable_if_t<is_subtype_v<T, Object>>>
OptionalRef<typename ref_traits<T>::ref_type> TryMakeRef(JSHeapBroker* broker,
                                                         ObjectData* data) {
  if (data == nullptr) return {};
  return {typename ref_traits<T>::ref_type(data)};
}

// Usage:
//
//  OptionalFooRef ref = TryMakeRef(broker, o);
//  if (!ref.has_value()) return {};  // bailout
//
// or
//
//  FooRef ref = MakeRef(broker, o);
template <class T, typename = std::enable_if_t<is_subtype_v<T, Object>>>
OptionalRef<typename ref_traits<T>::ref_type> TryMakeRef(
    JSHeapBroker* broker, Tagged<T> object, GetOrCreateDataFlags flags = {}) {
  ObjectData* data = broker->TryGetOrCreateData(object, flags);
  if (data == nullptr) {
    TRACE_BROKER_MISSING(broker, "ObjectData for " << Brief(object));
  }
  return TryMakeRef<T>(broker, data);
}

template <class T, typename = std::enable_if_t<is_subtype_v<T, Object>>>
OptionalRef<typename ref_traits<T>::ref_type> TryMakeRef(
    JSHeapBroker* broker, Handle<T> object, GetOrCreateDataFlags flags = {}) {
  ObjectData* data = broker->TryGetOrCreateData(object, flags);
  if (data == nullptr) {
    DCHECK_EQ(flags & kCrashOnError, 0);
    TRACE_BROKER_MISSING(broker, "ObjectData for " << Brief(*object));
  }
  return TryMakeRef<T>(broker, data);
}

template <class T, typename = std::enable_if_t<is_subtype_v<T, Object>>>
typename ref_traits<T>::ref_type MakeRef(JSHeapBroker* broker,
                                         Tagged<T> object) {
  return TryMakeRef(broker, object, kCrashOnError).value();
}

template <class T, typename = std::enable_if_t<is_subtype_v<T, Object>>>
typename ref_traits<T>::ref_type MakeRef(JSHeapBroker* broker,
                                         Handle<T> object) {
  return TryMakeRef(broker, object, kCrashOnError).value();
}

template <class T, typename = std::enable_if_t<is_subtype_v<T, Object>>>
typename ref_traits<T>::ref_type MakeRefAssumeMemoryFence(JSHeapBroker* broker,
                                                          Tagged<T> object) {
  return TryMakeRef(broker, object, kAssumeMemoryFence | kCrashOnError).value();
}

template <class T, typename = std::enable_if_t<is_subtype_v<T, Object>>>
typename ref_traits<T>::ref_type MakeRefAssumeMemoryFence(JSHeapBroker* broker,
                                                          Handle<T> object) {
  return TryMakeRef(broker, object, kAssumeMemoryFence | kCrashOnError).value();
}

#define V(Type, name, Name)                                         \
  inline typename ref_traits<Type>::ref_type JSHeapBroker::name() { \
    if (!name##_) {                                                 \
      Init##Name();                                                 \
    }                                                               \
    return name##_.value();                                         \
  }
READ_ONLY_ROOT_LIST(V)
#undef V

}  // namespace compiler
}  // namespace internal
}  // namespace v8

#endif  // V8_COMPILER_JS_HEAP_BROKER_H_

"""

```