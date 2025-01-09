Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Identify the Core Purpose:** The filename `heap-visitor-inl.h` and the presence of `VisitorId` strongly suggest this code is about iterating or "visiting" objects within the V8 heap. The `.inl.h` suffix usually indicates inline function definitions for a related header file (likely `heap-visitor.h`).

2. **Examine Includes:** The `#include` directives give clues about the functionality and dependencies:
    * `<optional>`: Suggests the possibility of returning absent values.
    * `"src/base/logging.h"`: Indicates the use of logging/debugging macros (like `DCHECK`).
    * `"src/heap/*"`:  Confirms its role within the heap management system. Specifically, `heap-layout-inl.h`, `mark-compact.h`, `object-lock-inl.h` point towards memory organization, garbage collection, and synchronization.
    * `"src/objects/*"`: Shows interaction with various V8 object types (arrays, buffers, functions, etc.).
    * `"src/objects/visitors.h"`:  Reinforces the idea of a visitor pattern.
    * `"src/wasm/wasm-objects.h"`: Suggests WebAssembly support.

3. **Analyze Templates:** The extensive use of templates, particularly `template <typename ConcreteVisitor>`, is a key observation. This means the `HeapVisitor` class is a template class designed to be customized by different concrete visitor implementations. This is a classic use case for the Visitor design pattern.

4. **Focus on Key Structures and Functions:**
    * **`VisitorId` enum (implied):** The code uses `VisitorId` as a template parameter and in switch statements. This hints at an underlying enum (likely defined elsewhere) that identifies different ways of visiting objects.
    * **`SupportsRightTrim()`:** This function seems related to optimization, potentially skipping trailing parts of arrays during visitation.
    * **`ContainsReadOnlyMap()`:** This deals with read-only memory regions, which are important for performance and security.
    * **`HeapVisitor` class:**  The core class. Pay attention to its constructors, the `Visit()` overloads, and the template helper functions like `Cast()`.
    * **`Visit##TypeName()` functions:**  The pattern here (`VisitFixedArray`, `VisitJSObject`, etc.) clearly shows how different object types are handled. The macros `TYPED_VISITOR_ID_LIST`, `TORQUE_VISITOR_ID_LIST`, etc., suggest a way to generate these functions systematically.
    * **`VisitWithBodyDescriptor()`:** This function seems to handle the core logic of visiting an object's fields based on its "body descriptor."
    * **`ConcurrentHeapVisitor`:**  Indicates support for concurrent garbage collection or other parallel operations.
    * **`VisitStringLocked()`:**  Highlights the need for synchronization when dealing with strings, especially in a concurrent context.

5. **Infer Functionality from Usage Patterns:**
    * **Switch statement on `map->visitor_id()`:** This is the central dispatch mechanism for the visitor pattern. The `visitor_id` determines which specific `Visit` method is called.
    * **`DCHECK` statements:** These are assertions that help in debugging. They often reveal important assumptions about the code. For instance, the `DCHECK(!IsTrustedObject(object) || !HeapLayout::InTrustedSpace(object))` suggests security considerations.
    * **Macros like `DEFINE_READ_ONLY_MAP_SPECIALIZATION`, `VISIT`, etc.:**  These are code generation mechanisms to avoid repetitive code. Understanding the intent behind these macros is crucial.

6. **Connect to JavaScript:**  Since V8 is the JavaScript engine, any operation on the heap directly relates to JavaScript objects. Think about how JavaScript constructs like arrays, functions, and objects are represented in memory. The examples provided in the initial prompt are good starting points.

7. **Consider Error Scenarios:** Think about what could go wrong during heap visitation. Accessing freed memory, type mismatches, and concurrent modifications are common issues in memory management. The `DCHECK` statements sometimes hint at potential errors.

8. **Address Specific Questions:**  Once the general functionality is understood, go back to the prompt's specific questions:
    * **List functionalities:** Summarize the identified roles of the header file.
    * **`.tq` extension:** Recognize that `.tq` implies Torque (V8's internal language).
    * **JavaScript relation:**  Provide concrete JavaScript examples demonstrating the concepts.
    * **Code logic reasoning:**  For complex functions, provide hypothetical inputs and outputs.
    * **Common programming errors:**  Relate the code's functionality to potential real-world errors.

9. **Refine and Organize:**  Structure the analysis logically with clear headings and explanations. Use bullet points or numbered lists for better readability.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:**  "This is just about iterating through the heap."
* **Correction:** "It's more structured than that. The Visitor pattern is clearly being used, allowing different actions to be performed on the heap objects."
* **Initial thought:** "The `DCHECK` statements are just for basic error checking."
* **Correction:** "Some `DCHECK` statements, like the one involving `IsTrustedObject`, point to security concerns and the separation of sandboxed and trusted memory regions."
* **Initial thought:**  "The templates are just for code reuse."
* **Correction:** "The `ConcreteVisitor` template parameter is fundamental to the Visitor pattern. It allows the core `HeapVisitor` to be generic and the specific actions to be defined by the concrete visitor implementations."

By following this thought process, combining code analysis with knowledge of V8's architecture and common programming patterns, one can effectively understand the purpose and functionality of a complex header file like `heap-visitor-inl.h`.
看起来你提供的是V8 JavaScript引擎中 `v8/src/heap/heap-visitor-inl.h` 文件的内容。这个文件是一个内联头文件，它定义了 `HeapVisitor` 模板类的内联成员函数。`HeapVisitor` 类是 V8 垃圾回收（Garbage Collection, GC）机制中的核心组件，用于遍历堆中的对象。

下面列举一下 `v8/src/heap/heap-visitor-inl.h` 的功能：

1. **定义 `HeapVisitor` 模板类及其成员函数的内联实现:** 这个头文件主要包含了 `HeapVisitor` 模板类的各种成员函数的具体实现。由于是 `.inl.h` 文件，这些函数通常是比较短小且频繁调用的，内联可以减少函数调用开销，提高性能。

2. **实现基于 Visitor ID 的对象访问分发:**  `HeapVisitor` 使用 `visitor_id()` 从 `Map` 对象中获取信息，并根据这个 ID 将访问操作分发到特定的 `Visit##TypeName` 函数。这是一种典型的 **Visitor 设计模式**的应用，允许在不修改对象结构的前提下定义新的操作。

3. **提供各种具体类型的对象的访问方法 (`Visit##TypeName`)**:  文件中定义了针对各种 V8 堆对象的访问方法，例如 `VisitFixedArray`, `VisitJSObjectFast`, `VisitString`, 等等。这些方法负责执行针对特定对象类型的访问逻辑。

4. **处理只读 Map 的特殊情况:**  `ContainsReadOnlyMap` 模板函数及其特化版本用于处理只读内存空间中的 `Map` 对象，这在性能和安全方面有重要意义。

5. **支持预计算对象大小:** 通过模板参数 `UsePrecomputedObjectSize`，`HeapVisitor` 可以选择是否使用预先计算好的对象大小，这在某些 GC 场景下可以提高效率。

6. **支持并发访问:** `ConcurrentHeapVisitor` 模板类继承自 `HeapVisitor`，并提供了一些针对并发场景的特殊处理，例如使用锁来访问某些类型的对象（如字符串）。

7. **处理 Trusted Object:**  代码中包含了对 "Trusted Object" 的处理，这些对象通常位于沙箱之外，被认为是可信的，需要进行额外的安全检查。

8. **处理 Slack Tracking (空间回收):**  对于 `JSObject` 等类型，`HeapVisitor` 考虑了 slack tracking，即对象可能包含未使用的额外空间，在访问时需要特别处理。

**如果 `v8/src/heap/heap-visitor-inl.h` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**

当前提供的文件内容显示它是 `.h` 文件，因此它是 C++ 头文件，而不是 Torque 文件。如果它是 `.tq` 文件，那么它将是用 V8 的 Torque 语言编写的，Torque 是一种用于生成高效的 C++ 代码的领域特定语言。

**它与 javascript 的功能有密切关系:**

`HeapVisitor` 是 V8 垃圾回收的核心组成部分。垃圾回收是 JavaScript 引擎自动管理内存的关键机制。当 JavaScript 代码创建对象时，V8 会在堆上分配内存。当这些对象不再被使用时，垃圾回收器会识别并回收这些内存。`HeapVisitor` 正是在垃圾回收过程中，用于遍历堆中的所有存活对象，标记它们，并为后续的清理和整理阶段做准备。

**JavaScript 示例说明:**

```javascript
// 当我们创建 JavaScript 对象时，V8 会在堆上分配内存
let obj = { a: 1, b: "hello" };
let arr = [1, 2, 3];

// 当这些对象不再被引用时，垃圾回收器会回收它们占用的内存
obj = null;
arr = null;

// 在垃圾回收的过程中，V8 会使用 HeapVisitor 遍历堆，
// 找到仍然被引用的对象，并标记它们。
```

在这个简单的例子中，当 `obj` 和 `arr` 被设置为 `null` 后，如果它们不再被其他代码引用，垃圾回收器最终会回收它们占用的内存。`HeapVisitor` 在这个过程中扮演着关键的角色，它会遍历堆，检查哪些对象仍然是可达的（例如，通过全局变量或当前执行栈）。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个简单的 `MarkingVisitor`，它是 `HeapVisitor` 的一个具体实现，用于标记存活对象。

**假设输入:**

* 堆中存在一个 `JSObject` 类型的对象，它的 `Map` 对象的 `visitor_id()` 返回 `kVisitJSObjectFast`。
* `MarkingVisitor` 的 `VisitJSObjectFast` 方法会将对象的某个标志位设置为已标记。

**输出:**

当 `HeapVisitor::Visit(Tagged<HeapObject> object)` 被调用，且 `object` 是上述的 `JSObject` 时，代码逻辑会如下进行：

1. 获取 `object` 的 `Map`。
2. 获取 `Map` 的 `visitor_id()`，得到 `kVisitJSObjectFast`。
3. `switch` 语句会匹配到 `case kVisitJSObjectFast:`。
4. 调用 `visitor->VisitJSObjectFast(map, ConcreteVisitor::template Cast<JSObject>(object), maybe_object_size);`。
5. `MarkingVisitor` 的 `VisitJSObjectFast` 方法被执行，该 `JSObject` 对象会被标记。

**涉及用户常见的编程错误 (可能导致 GC 行为异常):**

1. **内存泄漏:**  在 JavaScript 中，如果对象不再被使用但仍然被引用，垃圾回收器就无法回收它们，导致内存占用不断增加，最终可能导致程序崩溃。例如，意外地将对象添加到全局数组中而忘记移除。

   ```javascript
   let leakyArray = [];
   function createLeakyObject() {
     let obj = { data: new Array(1000000) };
     leakyArray.push(obj); // 忘记移除，导致 obj 无法被回收
   }

   for (let i = 0; i < 1000; i++) {
     createLeakyObject();
   }
   ```

2. **意外地保持对不再需要的对象的引用:** 闭包可能会意外地捕获并保持对大型对象的引用，即使这些对象在逻辑上已经不再需要。

   ```javascript
   function createExpensiveOperation() {
     let largeData = new Array(1000000);
     return function() {
       console.log("Operation done");
       // largeData 仍然被闭包引用，即使外部函数已执行完毕
     };
   }

   let operation = createExpensiveOperation();
   // operation 变量仍然持有对 largeData 的引用
   ```

3. **循环引用:** 当一组对象相互引用，但外部没有任何对象引用这组对象时，垃圾回收器可能无法立即回收它们（取决于具体的 GC 算法）。现代 V8 使用标记-清除算法，可以处理这种情况，但在某些旧的或简单的 GC 算法中可能会导致问题。

虽然用户通常不需要直接与 `HeapVisitor` 交互，但理解其背后的原理有助于理解 JavaScript 的内存管理机制，并避免可能导致性能问题或内存泄漏的编程错误。这个头文件是 V8 引擎内部实现细节的一部分，对于深入理解 V8 的工作原理非常有价值。

Prompt: 
```
这是目录为v8/src/heap/heap-visitor-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/heap-visitor-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_HEAP_HEAP_VISITOR_INL_H_
#define V8_HEAP_HEAP_VISITOR_INL_H_

#include <optional>

#include "src/base/logging.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-visitor.h"
#include "src/heap/mark-compact.h"
#include "src/heap/object-lock-inl.h"
#include "src/objects/arguments.h"
#include "src/objects/data-handler-inl.h"
#include "src/objects/free-space-inl.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-objects.h"
#include "src/objects/js-weak-refs-inl.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/map.h"
#include "src/objects/module-inl.h"
#include "src/objects/objects-body-descriptors-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/oddball.h"
#include "src/objects/ordered-hash-table.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/synthetic-module-inl.h"
#include "src/objects/torque-defined-classes.h"
#include "src/objects/visitors.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

template <VisitorId visitor_id>
constexpr bool SupportsRightTrim() {
  switch (visitor_id) {
    case kVisitFixedArray:
    case kVisitFixedDoubleArray:
    case kVisitWeakFixedArray:
      return true;
    default:
      return false;
  }
  UNREACHABLE();
}

template <VisitorId visitor_id>
inline bool ContainsReadOnlyMap(PtrComprCageBase, Tagged<HeapObject>) {
  return false;
}

#define DEFINE_READ_ONLY_MAP_SPECIALIZATION(VisitorIdType)                    \
  template <>                                                                 \
  inline bool ContainsReadOnlyMap<VisitorId::kVisit##VisitorIdType>(          \
      PtrComprCageBase cage_base, Tagged<HeapObject> object) {                \
    /* If you see this DCHECK fail we encountered a Map with a VisitorId that \
     * should have only ever appeared in read-only space. */                  \
    DCHECK(HeapLayout::InReadOnlySpace(object->map(cage_base)));              \
    return true;                                                              \
  }
VISITOR_IDS_WITH_READ_ONLY_MAPS_LIST(DEFINE_READ_ONLY_MAP_SPECIALIZATION)
#undef DEFINE_READ_ONLY_MAP_SPECIALIZATION

template <typename ConcreteVisitor>
HeapVisitor<ConcreteVisitor>::HeapVisitor(PtrComprCageBase cage_base,
                                          PtrComprCageBase code_cage_base)
    : ObjectVisitorWithCageBases(cage_base, code_cage_base) {}

template <typename ConcreteVisitor>
HeapVisitor<ConcreteVisitor>::HeapVisitor(Isolate* isolate)
    : ObjectVisitorWithCageBases(isolate) {}

template <typename ConcreteVisitor>
HeapVisitor<ConcreteVisitor>::HeapVisitor(Heap* heap)
    : ObjectVisitorWithCageBases(heap) {}

template <typename ConcreteVisitor>
template <typename T>
Tagged<T> HeapVisitor<ConcreteVisitor>::Cast(Tagged<HeapObject> object) {
  if constexpr (ConcreteVisitor::ShouldUseUncheckedCast()) {
    return i::UncheckedCast<T>(object);
  }
  return i::Cast<T>(object);
}

template <typename ConcreteVisitor>
size_t HeapVisitor<ConcreteVisitor>::Visit(Tagged<HeapObject> object)
  requires(!ConcreteVisitor::UsePrecomputedObjectSize())
{
  return Visit(object->map(cage_base()), object);
}

template <typename ConcreteVisitor>
size_t HeapVisitor<ConcreteVisitor>::Visit(Tagged<Map> map,
                                           Tagged<HeapObject> object)
  requires(!ConcreteVisitor::UsePrecomputedObjectSize())
{
  return Visit(map, object, MaybeObjectSize());
}

template <typename ConcreteVisitor>
size_t HeapVisitor<ConcreteVisitor>::Visit(Tagged<Map> map,
                                           Tagged<HeapObject> object,
                                           int object_size)
  requires(ConcreteVisitor::UsePrecomputedObjectSize())
{
  return Visit(map, object, MaybeObjectSize(object_size));
}

template <typename ConcreteVisitor>
size_t HeapVisitor<ConcreteVisitor>::Visit(Tagged<Map> map,
                                           Tagged<HeapObject> object,
                                           MaybeObjectSize maybe_object_size) {
  if constexpr (ConcreteVisitor::UsePrecomputedObjectSize()) {
    DCHECK_EQ(maybe_object_size.AssumeSize(), object->SizeFromMap(map));
    static_assert(!ConcreteVisitor::EnableConcurrentVisitation());
  } else {
    DCHECK(maybe_object_size.IsNone());
  }

  ConcreteVisitor* visitor = static_cast<ConcreteVisitor*>(this);
  switch (map->visitor_id()) {
#define CASE(TypeName)                                                        \
  case kVisit##TypeName:                                                      \
    /* If this DCHECK fails, it means that the object type wasn't added       \
     * to the TRUSTED_VISITOR_ID_LIST.                                        \
     * Note: This would normally be just !IsTrustedObject(obj), however we    \
     * might see trusted objects here before they've been migrated to trusted \
     * space, hence the second condition. */                                  \
    DCHECK(!IsTrustedObject(object) || !HeapLayout::InTrustedSpace(object));  \
    return visitor->Visit##TypeName(                                          \
        map, ConcreteVisitor::template Cast<TypeName>(object),                \
        maybe_object_size);
    TYPED_VISITOR_ID_LIST(CASE)
    TYPED_VISITOR_WITH_SLACK_ID_LIST(CASE)
    TORQUE_VISITOR_ID_LIST(CASE)
#undef CASE
#define CASE(TypeName)                                                     \
  case kVisit##TypeName:                                                   \
    DCHECK(IsTrustedObject(object));                                       \
    /* Trusted objects are protected from modifications by an attacker as  \
     * they are located outside of the sandbox. However, an attacker can   \
     * still craft their own fake trusted objects inside the sandbox. In   \
     * this case, bad things might happen if these objects are then        \
     * processed by e.g. an object visitor as they will typically assume   \
     * that these objects are trustworthy. The following check defends     \
     * against that by ensuring that the object is outside of the sandbox. \
     * See also crbug.com/c/1505089. */                                    \
    SBXCHECK(OutsideSandboxOrInReadonlySpace(object));                     \
    return visitor->Visit##TypeName(                                       \
        map, ConcreteVisitor::template Cast<TypeName>(object),             \
        maybe_object_size);
    TRUSTED_VISITOR_ID_LIST(CASE)
#undef CASE
    case kVisitShortcutCandidate:
      return visitor->VisitShortcutCandidate(
          map, ConcreteVisitor::template Cast<ConsString>(object),
          maybe_object_size);
    case kVisitJSObjectFast:
      return visitor->VisitJSObjectFast(
          map, ConcreteVisitor::template Cast<JSObject>(object),
          maybe_object_size);
    case kVisitJSApiObject:
      return visitor->VisitJSApiObject(
          map, ConcreteVisitor::template Cast<JSObject>(object),
          maybe_object_size);
    case kVisitStruct:
      return visitor->VisitStruct(map, object, maybe_object_size);
    case kVisitFiller:
      return visitor->VisitFiller(map, object, maybe_object_size);
    case kVisitFreeSpace:
      return visitor->VisitFreeSpace(map, Cast<FreeSpace>(object),
                                     maybe_object_size);
    case kDataOnlyVisitorIdCount:
    case kVisitorIdCount:
      UNREACHABLE();
  }
  // TODO(chromium:327992715): Remove once we have some clarity why execution
  // can reach this point.
  {
    Isolate* isolate;
    if (GetIsolateFromHeapObject(object, &isolate)) {
      isolate->PushParamsAndDie(
          reinterpret_cast<void*>(object.ptr()),
          reinterpret_cast<void*>(map.ptr()),
          reinterpret_cast<void*>(static_cast<intptr_t>(map->visitor_id())));
    }
  }
  UNREACHABLE();
}

template <typename ConcreteVisitor>
template <VisitorId visitor_id>
void HeapVisitor<ConcreteVisitor>::VisitMapPointerIfNeeded(
    Tagged<HeapObject> host) {
  if constexpr (!ConcreteVisitor::ShouldVisitMapPointer()) {
    return;
  }
  if constexpr (!ConcreteVisitor::ShouldVisitReadOnlyMapPointer()) {
    if (ContainsReadOnlyMap<visitor_id>(cage_base(), host)) {
      return;
    }
  }
  static_cast<ConcreteVisitor*>(this)->VisitMapPointer(host);
}

#define VISIT(TypeName)                                                 \
  template <typename ConcreteVisitor>                                   \
  size_t HeapVisitor<ConcreteVisitor>::Visit##TypeName(                 \
      Tagged<Map> map, Tagged<TypeName> object,                         \
      MaybeObjectSize maybe_object_size) {                              \
    return static_cast<ConcreteVisitor*>(this)                          \
        ->template VisitWithBodyDescriptor<                             \
            VisitorId::kVisit##TypeName, TypeName,                      \
            ObjectTraits<TypeName>::BodyDescriptor>(map, object,        \
                                                    maybe_object_size); \
  }

TYPED_VISITOR_ID_LIST(VISIT)
TORQUE_VISITOR_ID_LIST(VISIT)
TRUSTED_VISITOR_ID_LIST(VISIT)
#undef VISIT

#define VISIT_WITH_SLACK(TypeName)                                            \
  template <typename ConcreteVisitor>                                         \
  size_t HeapVisitor<ConcreteVisitor>::Visit##TypeName(                       \
      Tagged<Map> map, Tagged<TypeName> object,                               \
      MaybeObjectSize maybe_object_size) {                                    \
    return static_cast<ConcreteVisitor*>(this)                                \
        ->template VisitJSObjectSubclass<TypeName, TypeName::BodyDescriptor>( \
            map, object, maybe_object_size);                                  \
  }

TYPED_VISITOR_WITH_SLACK_ID_LIST(VISIT_WITH_SLACK)
#undef VISIT_WITH_SLACK

template <typename ConcreteVisitor>
size_t HeapVisitor<ConcreteVisitor>::VisitShortcutCandidate(
    Tagged<Map> map, Tagged<ConsString> object,
    MaybeObjectSize maybe_object_size) {
  return static_cast<ConcreteVisitor*>(this)->VisitConsString(
      map, object, maybe_object_size);
}

template <typename ConcreteVisitor>
size_t HeapVisitor<ConcreteVisitor>::VisitFiller(
    Tagged<Map> map, Tagged<HeapObject> object,
    MaybeObjectSize maybe_object_size) {
  if constexpr (!ConcreteVisitor::CanEncounterFillerOrFreeSpace()) {
    UNREACHABLE();
  }
  ConcreteVisitor* visitor = static_cast<ConcreteVisitor*>(this);
  visitor->template VisitMapPointerIfNeeded<VisitorId::kVisitFiller>(object);
  return ConcreteVisitor::UsePrecomputedObjectSize()
             ? maybe_object_size.AssumeSize()
             : map->instance_size();
}

template <typename ConcreteVisitor>
size_t HeapVisitor<ConcreteVisitor>::VisitFreeSpace(
    Tagged<Map> map, Tagged<FreeSpace> object,
    MaybeObjectSize maybe_object_size) {
  if constexpr (!ConcreteVisitor::CanEncounterFillerOrFreeSpace()) {
    UNREACHABLE();
  }
  ConcreteVisitor* visitor = static_cast<ConcreteVisitor*>(this);
  visitor->template VisitMapPointerIfNeeded<VisitorId::kVisitFreeSpace>(object);
  return object->size(kRelaxedLoad);
}

template <typename ConcreteVisitor>
size_t HeapVisitor<ConcreteVisitor>::VisitJSObjectFast(
    Tagged<Map> map, Tagged<JSObject> object,
    MaybeObjectSize maybe_object_size) {
  return static_cast<ConcreteVisitor*>(this)
      ->template VisitJSObjectSubclass<JSObject, JSObject::FastBodyDescriptor>(
          map, object, maybe_object_size);
}

template <typename ConcreteVisitor>
size_t HeapVisitor<ConcreteVisitor>::VisitJSApiObject(
    Tagged<Map> map, Tagged<JSObject> object,
    MaybeObjectSize maybe_object_size) {
  return static_cast<ConcreteVisitor*>(this)
      ->template VisitJSObjectSubclass<
          JSObject, JSAPIObjectWithEmbedderSlots::BodyDescriptor>(
          map, object, maybe_object_size);
}

template <typename ConcreteVisitor>
size_t HeapVisitor<ConcreteVisitor>::VisitStruct(
    Tagged<Map> map, Tagged<HeapObject> object,
    MaybeObjectSize maybe_object_size) {
  ConcreteVisitor* visitor = static_cast<ConcreteVisitor*>(this);
  int size = ConcreteVisitor::UsePrecomputedObjectSize()
                 ? static_cast<int>(maybe_object_size.AssumeSize())
                 : map->instance_size();
  visitor->template VisitMapPointerIfNeeded<VisitorId::kVisitStruct>(object);
  StructBodyDescriptor::IterateBody(map, object, size, visitor);
  return size;
}

template <typename ConcreteVisitor>
template <typename T, typename TBodyDescriptor>
size_t HeapVisitor<ConcreteVisitor>::VisitJSObjectSubclass(
    Tagged<Map> map, Tagged<T> object, MaybeObjectSize maybe_object_size) {
  // JSObject types are subject to slack tracking. At the end of slack tracking
  // a Map's instance size is adjusted properly. Since this changes the instance
  // size, we cannot DCHECK that `SizeFromMap()` is consistent with
  // `TBodyDescriptor::SizeOf()` as that would require taking a snapshot of the
  // Map.

  ConcreteVisitor* visitor = static_cast<ConcreteVisitor*>(this);
  visitor->template VisitMapPointerIfNeeded<VisitorId::kVisitJSObject>(object);

  const size_t size = ConcreteVisitor::UsePrecomputedObjectSize()
                          ? maybe_object_size.AssumeSize()
                          : TBodyDescriptor::SizeOf(map, object);

  int visitation_size = static_cast<int>(size);

  if (!ConcreteVisitor::ShouldVisitFullJSObject()) {
    // It is important to visit only the used field and ignore the slack fields
    // because the slack fields may be trimmed concurrently and we don't want to
    // find fillers (slack) during pointer visitation.
    const int used_size = map->UsedInstanceSize();
    DCHECK_LE(used_size, size);
    DCHECK_GE(used_size, JSObject::GetHeaderSize(map));

    visitation_size = used_size;
  }

  TBodyDescriptor::IterateBody(map, object, visitation_size, visitor);

  return size;
}

template <typename ConcreteVisitor>
template <VisitorId visitor_id, typename T, typename TBodyDescriptor>
size_t HeapVisitor<ConcreteVisitor>::VisitWithBodyDescriptor(
    Tagged<Map> map, Tagged<T> object, MaybeObjectSize maybe_object_size) {
  // If you see the following DCHECK fail, then the size computation of
  // BodyDescriptor doesn't match the size return via obj.Size(). This is
  // problematic as the GC requires those sizes to match for accounting reasons.
  // The fix likely involves adding a padding field in the object definitions.
  //
  // We can only perform this check for types that do not support right trimming
  // when running concurrently. `RefineAllocatedBytesAfterSweeping()` ensures
  // that we only see sizes that get smaller during marking.
#ifdef DEBUG
  if (!SupportsRightTrim<visitor_id>() ||
      !ConcreteVisitor::EnableConcurrentVisitation()) {
    DCHECK_EQ(object->SizeFromMap(map), TBodyDescriptor::SizeOf(map, object));
  }
#endif  // DEBUG
  DCHECK(!map->IsInobjectSlackTrackingInProgress());

  ConcreteVisitor* visitor = static_cast<ConcreteVisitor*>(this);
  visitor->template VisitMapPointerIfNeeded<visitor_id>(object);
  const int size = ConcreteVisitor::UsePrecomputedObjectSize()
                       ? static_cast<int>(maybe_object_size.AssumeSize())
                       : TBodyDescriptor::SizeOf(map, object);
  TBodyDescriptor::IterateBody(map, object, size, visitor);
  return size;
}

template <typename ConcreteVisitor>
template <typename TSlot>
std::optional<Tagged<Object>>
HeapVisitor<ConcreteVisitor>::GetObjectFilterReadOnlyAndSmiFast(
    TSlot slot) const {
  auto raw = slot.Relaxed_Load_Raw();
  // raw is either Tagged_t or Address depending on the slot type. Both can be
  // cast to Tagged_t for the fast check.
  if (FastInReadOnlySpaceOrSmallSmi(static_cast<Tagged_t>(raw))) {
    return std::nullopt;
  }
  return TSlot::RawToTagged(ObjectVisitorWithCageBases::cage_base(), raw);
}

template <typename ConcreteVisitor>
ConcurrentHeapVisitor<ConcreteVisitor>::ConcurrentHeapVisitor(Isolate* isolate)
    : HeapVisitor<ConcreteVisitor>(isolate) {}

template <typename T>
struct ConcurrentVisitorCastHelper {
  static V8_INLINE Tagged<T> Cast(Tagged<HeapObject> object) {
    return i::Cast<T>(object);
  }
};

#define UNCHECKED_CAST(VisitorId, TypeName)                               \
  template <>                                                             \
  V8_INLINE Tagged<TypeName> ConcurrentVisitorCastHelper<TypeName>::Cast( \
      Tagged<HeapObject> object) {                                        \
    return UncheckedCast<TypeName>(object);                               \
  }
SAFE_STRING_TRANSITION_SOURCES(UNCHECKED_CAST)
// Casts are also needed for unsafe ones for the initial dispatch in
// HeapVisitor.
UNSAFE_STRING_TRANSITION_SOURCES(UNCHECKED_CAST)
#undef UNCHECKED_CAST

template <typename ConcreteVisitor>
template <typename T>
Tagged<T> ConcurrentHeapVisitor<ConcreteVisitor>::Cast(
    Tagged<HeapObject> object) {
  if constexpr (ConcreteVisitor::EnableConcurrentVisitation()) {
    return ConcurrentVisitorCastHelper<T>::Cast(object);
  }
  return i::Cast<T>(object);
}

#define VISIT_AS_LOCKED_STRING(VisitorId, TypeName)                          \
  template <typename ConcreteVisitor>                                        \
  size_t ConcurrentHeapVisitor<ConcreteVisitor>::Visit##TypeName(            \
      Tagged<Map> map, Tagged<TypeName> object,                              \
      MaybeObjectSize maybe_object_size) {                                   \
    if constexpr (ConcreteVisitor::EnableConcurrentVisitation()) {           \
      return VisitStringLocked(object);                                      \
    }                                                                        \
    return HeapVisitor<ConcreteVisitor>::Visit##TypeName(map, object,        \
                                                         maybe_object_size); \
  }

UNSAFE_STRING_TRANSITION_SOURCES(VISIT_AS_LOCKED_STRING)
#undef VISIT_AS_LOCKED_STRING

template <typename ConcreteVisitor>
template <typename T>
size_t ConcurrentHeapVisitor<ConcreteVisitor>::VisitStringLocked(
    Tagged<T> object) {
  ConcreteVisitor* visitor = static_cast<ConcreteVisitor*>(this);
  SharedObjectLockGuard guard(object);
  // The object has been locked. At this point shared read access is
  // guaranteed but we must re-read the map and check whether the string has
  // transitioned.
  Tagged<Map> map = object->map();
  int size;
  switch (map->visitor_id()) {
#define UNSAFE_STRING_TRANSITION_TARGET_CASE(VisitorIdType, TypeName)         \
  case kVisit##VisitorIdType:                                                 \
    visitor                                                                   \
        ->template VisitMapPointerIfNeeded<VisitorId::kVisit##VisitorIdType>( \
            object);                                                          \
    size = ObjectTraits<TypeName>::BodyDescriptor::SizeOf(map, object);       \
    ObjectTraits<TypeName>::BodyDescriptor::IterateBody(                      \
        map, UncheckedCast<TypeName>(object), size, visitor);                 \
    break;

    UNSAFE_STRING_TRANSITION_TARGETS(UNSAFE_STRING_TRANSITION_TARGET_CASE)
#undef UNSAFE_STRING_TRANSITION_TARGET_CASE
    default:
      UNREACHABLE();
  }
  return size;
}

template <typename ConcreteVisitor>
NewSpaceVisitor<ConcreteVisitor>::NewSpaceVisitor(Isolate* isolate)
    : ConcurrentHeapVisitor<ConcreteVisitor>(isolate) {}

}  // namespace internal
}  // namespace v8

#endif  // V8_HEAP_HEAP_VISITOR_INL_H_

"""

```