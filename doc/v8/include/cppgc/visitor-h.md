Response:
Let's break down the thought process to analyze the `v8/include/cppgc/visitor.h` file.

1. **Initial Understanding of the Goal:** The core request is to understand the *purpose* and *functionality* of this header file within the V8 garbage collection system. Keywords like "visitor," "garbage collected," and the copyright notice immediately suggest a connection to memory management.

2. **File Extension Check:** The prompt specifically mentions checking for a `.tq` extension. This is crucial. Since the extension is `.h`, we know it's a C++ header file, *not* a Torque file. This immediately eliminates the Torque-related part of the prompt.

3. **High-Level Overview from Comments:** The initial comments are invaluable:
    * `"// Copyright 2020 the V8 project authors. All rights reserved."` - Confirms it's V8 code.
    * `"Visitor passed to trace methods."` - This is the central concept. The `Visitor` class is used when "tracing" objects.
    * The code example with `Foo::Trace` solidifies this: `visitor->Trace(foo_);` means the `Visitor` is responsible for traversing the object graph.

4. **Key Class: `Visitor`:**  The majority of the file defines the `Visitor` class. We need to analyze its members (methods and nested classes).

5. **Public Interface of `Visitor`:**  Focus on the public methods first, as they define how external code interacts with the `Visitor`. Group them logically:
    * **Constructor/Destructor:** `Visitor(Key)`, `~Visitor()`. The `Key` suggests a controlled instantiation mechanism (likely a friend class).
    * **`Trace` Methods (various overloads):**  These are clearly the core functionality. Notice the different `Trace` methods for `Member`, `WeakMember`, `UncompressedMember`, raw pointers, inlined objects, and arrays. This hints at how the garbage collector tracks different types of object relationships.
    * **`RegisterWeakCallbackMethod` and `RegisterWeakCallback`:**  Related to weak references and cleanup.
    * **`TraceEphemeron`:**  Specific handling for ephemerons (key-value pairs where the value's liveness depends on the key).
    * **`TraceStrongly`, `TraceStrongContainer`, `TraceWeakContainer`:** Different levels of strong/weak referencing for containers.
    * **`RegisterMovableReference`:** Deals with objects that might be moved in memory during garbage collection.
    * **`DeferTraceToMutatorThreadIfConcurrent`:**  Indicates support for concurrent garbage collection.

6. **Protected and Private Members of `Visitor`:** These are implementation details, but provide further insight:
    * **`Visit...` methods:**  Virtual methods like `Visit`, `VisitWeak`, `VisitEphemeron`, etc. These are the *actual actions* performed during tracing. The base `Visitor` class likely provides default implementations, and subclasses (used by specific garbage collection algorithms) will override these.
    * **`HandleMovableReference`:**  Another low-level operation.
    * **`WeakCallbackMethodDelegate` and `HandleWeak`:**  Helper functions for weak reference handling.
    * **`TraceImpl`:** A private helper to avoid code duplication in the `Trace` methods.
    * **`CheckObjectNotInConstruction`:** A debug assertion.

7. **Nested Class: `Visitor::Key`:**  The private constructor confirms it's a mechanism for controlled creation, likely used by a friend class.

8. **Related Class: `internal::RootVisitor`:**  This class has a similar structure to `Visitor` but seems to handle *roots* – objects directly accessible by the program (not just reachable through other garbage-collected objects). The `Trace` methods here handle `Persistent` handles, which are V8's way of keeping track of important objects.

9. **Answering the Specific Questions:** Now, armed with a solid understanding of the file's contents, address the prompt's questions systematically:
    * **Functionality:** Summarize the role of the `Visitor` in traversing the object graph and registering various types of references.
    * **`.tq` Extension:**  Clearly state it's a `.h` file, so it's C++, not Torque.
    * **Relationship to JavaScript:** This requires connecting the C++ garbage collector to the JavaScript engine. Explain how the C++ layer manages the memory of JavaScript objects. Provide a simple JavaScript example to illustrate the concept of garbage collection (even though the `Visitor` itself isn't directly used in JS code).
    * **Code Logic Inference (with assumptions):**  Choose a simple `Trace` method (e.g., `Trace(const Member<T>&)`) and describe what happens step-by-step, making reasonable assumptions about the internal workings (like the sentinel pointer). Provide a simple input/output scenario.
    * **Common Programming Errors:** Think about how developers might misuse the garbage collection system. Forgetting to call `Trace`, holding onto raw pointers, and creating cycles are common issues.

10. **Refinement and Clarity:** Review the generated answer for clarity, accuracy, and completeness. Ensure the language is precise and avoids jargon where possible. Organize the information logically with clear headings and bullet points.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe the `.tq` check is about a related file. **Correction:** The prompt asks specifically about *this* file.
* **Overly detailed analysis:**  Resist the urge to dive too deeply into every single line of code. Focus on the *purpose* of each method.
* **Assuming too much about internal implementation:**  Acknowledge assumptions when inferring code logic. For instance, "we assume `kSentinelPointer` indicates a null or invalid pointer."
* **Not connecting C++ to JavaScript effectively:** Ensure the JavaScript example clearly illustrates the *outcome* of the C++ garbage collection, even if the `Visitor` isn't directly visible in JS.

By following this structured approach, combining top-down understanding with detailed analysis, and constantly checking against the prompt's requirements, we can generate a comprehensive and accurate explanation of the `v8/include/cppgc/visitor.h` file.
这是 V8 JavaScript 引擎中 `cppgc`（C++ Garbage Collection）库中的一个头文件，定义了 `Visitor` 类。`Visitor` 类在垃圾回收过程中扮演着核心角色，用于遍历对象图并标记存活对象。

**`v8/include/cppgc/visitor.h` 的功能：**

1. **定义 `Visitor` 基类：** `Visitor` 是一个抽象基类，定义了访问和处理堆中对象的接口。它提供了一系列 `Trace` 方法，用于告知垃圾回收器哪些对象是存活的，需要被保留。

2. **对象图遍历的核心机制：**  垃圾回收器使用 `Visitor` 来遍历由 `cppgc` 管理的对象构成的图。当垃圾回收器访问一个对象时，它会调用该对象的 `Trace` 方法，并将一个 `Visitor` 对象传递给它。

3. **`Trace` 方法族：** `Visitor` 类提供了多个重载的 `Trace` 方法，用于处理不同类型的成员变量：
   - `Trace(const Member<T>& member)`: 用于追踪 `Member<T>` 类型的强引用成员。`Member` 表示一个指向垃圾回收堆中对象的智能指针，它拥有对象的所有权。
   - `Trace(const WeakMember<T>& weak_member)`: 用于追踪 `WeakMember<T>` 类型的弱引用成员。`WeakMember` 表示一个不阻止对象被回收的智能指针。
   - `Trace(const subtle::UncompressedMember<T>& member)`: 用于追踪未压缩的成员指针（在启用指针压缩的架构中）。
   - `TraceMultiple(...)`: 用于追踪数组或容器中的多个成员。
   - `Trace(const T& object)`: 用于追踪内联对象，这些对象本身不是在堆上分配的，但遵循堆对象的布局并具有 `Trace()` 方法。
   - `Trace(const EphemeronPair<K, V>& ephemeron_pair)`: 用于追踪 EphemeronPair，这是一种键值对，其中值的存活状态取决于键的存活状态。
   - `TraceEphemeron(...)`: 用于追踪单独的 Ephemeron 关系。
   - `TraceStrongly(const WeakMember<T>& weak_member)`:  将弱引用提升为强引用进行追踪。
   - `TraceStrongContainer(...)` 和 `TraceWeakContainer(...)`: 用于追踪容器对象，可以强引用或弱引用容器内的元素。

4. **注册弱回调：**  `RegisterWeakCallback` 和 `RegisterWeakCallbackMethod` 方法允许对象注册回调函数，当对象即将被回收时，垃圾回收器会调用这些回调函数。这对于执行清理操作非常有用。

5. **处理可移动引用：** `RegisterMovableReference` 用于注册指向可移动空间中对象的指针。垃圾回收器在压缩堆时可能会移动这些对象，因此需要特殊处理。

6. **延迟追踪（针对并发）：** `DeferTraceToMutatorThreadIfConcurrent` 允许在并发垃圾回收时将某些对象的追踪操作延迟到主线程进行，以保证线程安全。

7. **`RootVisitor` 类：**  `internal::RootVisitor` 是一个相关的类，用于遍历垃圾回收根，即那些可以直接从全局变量、栈等访问到的对象。

**关于 `.tq` 结尾的文件：**

如果 `v8/include/cppgc/visitor.h` 以 `.tq` 结尾，那么它的确是 V8 Torque 源代码。Torque 是 V8 使用的一种领域特定语言，用于生成高效的 C++ 代码，特别是用于实现内置函数和运行时功能。**但根据你提供的文件名，它是 `.h` 结尾，因此是 C++ 头文件。**

**与 JavaScript 的功能关系：**

`v8/include/cppgc/visitor.h` 中定义的 `Visitor` 类是 V8 JavaScript 引擎垃圾回收机制的核心组成部分。JavaScript 对象的内存管理由 V8 的垃圾回收器负责。

当 JavaScript 代码创建对象时，这些对象会被分配在 V8 的堆上。垃圾回收器定期运行，找出不再被引用的对象并回收它们的内存。`Visitor` 类就是在这个过程中发挥作用的。

当垃圾回收器执行标记阶段时，它会从一组根对象开始，使用 `Visitor` 来遍历对象图。对于每个访问到的对象，垃圾回收器会调用其 `Trace` 方法，并将一个 `Visitor` 实例传递给它。对象自身的 `Trace` 方法会调用 `visitor->Trace(...)` 来标记其持有的其他存活对象。这样，垃圾回收器就能沿着引用链追踪所有可达的对象，并将它们标记为存活。未被标记的对象则被认为是垃圾，可以在后续的清理阶段被回收。

**JavaScript 示例说明：**

虽然 JavaScript 代码本身不直接操作 `Visitor` 类，但其行为受到 `Visitor` 和垃圾回收机制的影响。

```javascript
let obj1 = { data: "hello" };
let obj2 = { ref: obj1 }; // obj2 引用 obj1

// 在垃圾回收的标记阶段，当访问到 obj2 时，
// obj2 的 Trace 方法（在 C++ 层实现）会调用 visitor->Trace(ref);
// 从而标记 obj1 为存活。

// 如果将 obj2 的引用解除：
obj2 = null;

// 此时，如果垃圾回收器运行，并且没有其他对象引用 obj1，
// 那么 obj1 将不会被标记为存活，最终会被回收。
```

在这个例子中，虽然我们看不到 C++ 的 `Visitor` 对象，但垃圾回收器在幕后使用它来确定 `obj1` 是否应该被保留。`obj2` 持有对 `obj1` 的引用，这在垃圾回收的追踪过程中通过 `Visitor` 的 `Trace` 方法体现出来。

**代码逻辑推理（假设）：**

假设我们有一个简单的类 `MyObject`，它包含一个指向另一个 `MyObject` 的 `Member` 成员：

```c++
// 假设的 MyObject 类
class MyObject : public GarbageCollected<MyObject> {
 public:
  void Trace(Visitor* visitor) const {
    visitor->Trace(next_);
  }

 private:
  Member<MyObject> next_;
};
```

**假设输入：**

- 垃圾回收器开始标记阶段。
- 存在一个根对象 `root_obj`，它是 `MyObject` 的实例。
- `root_obj.next_` 指向另一个 `MyObject` 实例 `linked_obj`。

**输出和推理：**

1. 垃圾回收器访问根对象 `root_obj`。
2. 垃圾回收器调用 `root_obj->Trace(visitor)`。
3. 在 `root_obj` 的 `Trace` 方法中，`visitor->Trace(next_)` 被调用，其中 `next_` 指向 `linked_obj`。
4. `visitor->Trace(next_)` 内部会调用 `visitor->Visit(linked_obj, ...)` （实际实现可能更复杂）。
5. 垃圾回收器会将 `linked_obj` 标记为存活。

**用户常见的编程错误示例：**

1. **忘记在 `Trace` 方法中追踪成员：**

   ```c++
   class MyObject : public GarbageCollected<MyObject> {
    public:
     void SomeMethod() {
       data_ = new int[10]; // 错误：直接使用 new 分配内存，cppgc 不知道
     }

     void Trace(Visitor* visitor) const {
       // 忘记追踪 data_，垃圾回收器可能错误地回收这块内存
     }

    private:
     int* data_ = nullptr;
   };
   ```
   **后果：** `data_` 指向的内存可能在垃圾回收时被错误地回收，导致悬挂指针和程序崩溃。

2. **在 `Trace` 方法中访问可能已被回收的对象：**

   ```c++
   class Container : public GarbageCollected<Container> {
    public:
     void Trace(Visitor* visitor) const {
       visitor->Trace(member_);
       if (member_) {
         // 错误：假设 member_ 在 Trace 方法执行期间一直有效
         member_->DoSomething();
       }
     }
    private:
     WeakMember<OtherObject> member_;
   };
   ```
   **后果：** 如果 `member_` 指向的对象在 `Trace` 方法执行期间被并发的垃圾回收器回收，访问 `member_->DoSomething()` 将导致错误。应该始终检查弱引用是否有效。

3. **循环引用导致内存泄漏（虽然 `Visitor` 的目的是避免，但配置不当或存在 Finalizer 可能导致问题）：**

   ```c++
   class ObjectA : public GarbageCollected<ObjectA> {
    public:
     void Trace(Visitor* visitor) const {
       visitor->Trace(b_);
     }
    private:
     Member<ObjectB> b_;
   };

   class ObjectB : public GarbageCollected<ObjectB> {
    public:
     void Trace(Visitor* visitor) const {
       visitor->Trace(a_);
     }
    private:
     Member<ObjectA> a_;
   };

   // 如果 ObjectA 和 ObjectB 互相引用，且没有外部强引用断开环，
   // 垃圾回收器可以识别并回收这种环状结构。
   ```
   **后果：**  如果垃圾回收器无法正确处理循环引用（通常可以），或者存在带有副作用的析构函数（Finalizer），可能会导致内存泄漏或资源未释放。`cppgc` 通常能处理简单的循环引用。

总而言之，`v8/include/cppgc/visitor.h` 定义的 `Visitor` 类是 V8 `cppgc` 库中用于垃圾回收的关键组件，它通过 `Trace` 方法族实现对象图的遍历和存活对象的标记，从而支持 JavaScript 的内存管理。理解 `Visitor` 的作用对于理解 V8 的垃圾回收机制至关重要。

Prompt: 
```
这是目录为v8/include/cppgc/visitor.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/cppgc/visitor.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_CPPGC_VISITOR_H_
#define INCLUDE_CPPGC_VISITOR_H_

#include <type_traits>

#include "cppgc/custom-space.h"
#include "cppgc/ephemeron-pair.h"
#include "cppgc/garbage-collected.h"
#include "cppgc/internal/logging.h"
#include "cppgc/internal/member-storage.h"
#include "cppgc/internal/pointer-policies.h"
#include "cppgc/liveness-broker.h"
#include "cppgc/member.h"
#include "cppgc/sentinel-pointer.h"
#include "cppgc/source-location.h"
#include "cppgc/trace-trait.h"
#include "cppgc/type-traits.h"

namespace cppgc {

namespace internal {
template <typename T, typename WeaknessPolicy, typename LocationPolicy,
          typename CheckingPolicy>
class BasicCrossThreadPersistent;
template <typename T, typename WeaknessPolicy, typename LocationPolicy,
          typename CheckingPolicy>
class BasicPersistent;
class ConservativeTracingVisitor;
class VisitorBase;
class VisitorFactory;
}  // namespace internal

using WeakCallback = void (*)(const LivenessBroker&, const void*);

/**
 * Visitor passed to trace methods. All managed pointers must have called the
 * Visitor's trace method on them.
 *
 * \code
 * class Foo final : public GarbageCollected<Foo> {
 *  public:
 *   void Trace(Visitor* visitor) const {
 *     visitor->Trace(foo_);
 *     visitor->Trace(weak_foo_);
 *   }
 *  private:
 *   Member<Foo> foo_;
 *   WeakMember<Foo> weak_foo_;
 * };
 * \endcode
 */
class V8_EXPORT Visitor {
 public:
  class Key {
   private:
    Key() = default;
    friend class internal::VisitorFactory;
  };

  explicit Visitor(Key) {}

  virtual ~Visitor() = default;

  /**
   * Trace method for Member.
   *
   * \param member Member reference retaining an object.
   */
  template <typename T>
  void Trace(const Member<T>& member) {
    const T* value = member.GetRawAtomic();
    CPPGC_DCHECK(value != kSentinelPointer);
    TraceImpl(value);
  }

  /**
   * Trace method for WeakMember.
   *
   * \param weak_member WeakMember reference weakly retaining an object.
   */
  template <typename T>
  void Trace(const WeakMember<T>& weak_member) {
    static_assert(sizeof(T), "Pointee type must be fully defined.");
    static_assert(internal::IsGarbageCollectedOrMixinType<T>::value,
                  "T must be GarbageCollected or GarbageCollectedMixin type");
    static_assert(!internal::IsAllocatedOnCompactableSpace<T>::value,
                  "Weak references to compactable objects are not allowed");

    const T* value = weak_member.GetRawAtomic();

    // Bailout assumes that WeakMember emits write barrier.
    if (!value) {
      return;
    }

    CPPGC_DCHECK(value != kSentinelPointer);
    VisitWeak(value, TraceTrait<T>::GetTraceDescriptor(value),
              &HandleWeak<WeakMember<T>>, &weak_member);
  }

#if defined(CPPGC_POINTER_COMPRESSION)
  /**
   * Trace method for UncompressedMember.
   *
   * \param member UncompressedMember reference retaining an object.
   */
  template <typename T>
  void Trace(const subtle::UncompressedMember<T>& member) {
    const T* value = member.GetRawAtomic();
    CPPGC_DCHECK(value != kSentinelPointer);
    TraceImpl(value);
  }
#endif  // defined(CPPGC_POINTER_COMPRESSION)

  template <typename T>
  void TraceMultiple(const subtle::UncompressedMember<T>* start, size_t len) {
    static_assert(sizeof(T), "Pointee type must be fully defined.");
    static_assert(internal::IsGarbageCollectedOrMixinType<T>::value,
                  "T must be GarbageCollected or GarbageCollectedMixin type");
    VisitMultipleUncompressedMember(start, len,
                                    &TraceTrait<T>::GetTraceDescriptor);
  }

  template <typename T,
            std::enable_if_t<!std::is_same_v<
                Member<T>, subtle::UncompressedMember<T>>>* = nullptr>
  void TraceMultiple(const Member<T>* start, size_t len) {
    static_assert(sizeof(T), "Pointee type must be fully defined.");
    static_assert(internal::IsGarbageCollectedOrMixinType<T>::value,
                  "T must be GarbageCollected or GarbageCollectedMixin type");
#if defined(CPPGC_POINTER_COMPRESSION)
    static_assert(std::is_same_v<Member<T>, subtle::CompressedMember<T>>,
                  "Member and CompressedMember must be the same.");
    VisitMultipleCompressedMember(start, len,
                                  &TraceTrait<T>::GetTraceDescriptor);
#endif  // defined(CPPGC_POINTER_COMPRESSION)
  }

  /**
   * Trace method for inlined objects that are not allocated themselves but
   * otherwise follow managed heap layout and have a Trace() method.
   *
   * \param object reference of the inlined object.
   */
  template <typename T>
  void Trace(const T& object) {
#if V8_ENABLE_CHECKS
    // This object is embedded in potentially multiple nested objects. The
    // outermost object must not be in construction as such objects are (a) not
    // processed immediately, and (b) only processed conservatively if not
    // otherwise possible.
    CheckObjectNotInConstruction(&object);
#endif  // V8_ENABLE_CHECKS
    TraceTrait<T>::Trace(this, &object);
  }

  template <typename T>
  void TraceMultiple(const T* start, size_t len) {
#if V8_ENABLE_CHECKS
    // This object is embedded in potentially multiple nested objects. The
    // outermost object must not be in construction as such objects are (a) not
    // processed immediately, and (b) only processed conservatively if not
    // otherwise possible.
    CheckObjectNotInConstruction(start);
#endif  // V8_ENABLE_CHECKS
    for (size_t i = 0; i < len; ++i) {
      const T* object = &start[i];
      if constexpr (std::is_polymorphic_v<T>) {
        // The object's vtable may be uninitialized in which case the object is
        // not traced.
        if (*reinterpret_cast<const uintptr_t*>(object) == 0) continue;
      }
      TraceTrait<T>::Trace(this, object);
    }
  }

  /**
   * Registers a weak callback method on the object of type T. See
   * LivenessBroker for an usage example.
   *
   * \param object of type T specifying a weak callback method.
   */
  template <typename T, void (T::*method)(const LivenessBroker&)>
  void RegisterWeakCallbackMethod(const T* object) {
    RegisterWeakCallback(&WeakCallbackMethodDelegate<T, method>, object);
  }

  /**
   * Trace method for EphemeronPair.
   *
   * \param ephemeron_pair EphemeronPair reference weakly retaining a key object
   * and strongly retaining a value object in case the key object is alive.
   */
  template <typename K, typename V>
  void Trace(const EphemeronPair<K, V>& ephemeron_pair) {
    TraceEphemeron(ephemeron_pair.key, &ephemeron_pair.value);
    RegisterWeakCallbackMethod<EphemeronPair<K, V>,
                               &EphemeronPair<K, V>::ClearValueIfKeyIsDead>(
        &ephemeron_pair);
  }

  /**
   * Trace method for a single ephemeron. Used for tracing a raw ephemeron in
   * which the `key` and `value` are kept separately.
   *
   * \param weak_member_key WeakMember reference weakly retaining a key object.
   * \param member_value Member reference with ephemeron semantics.
   */
  template <typename KeyType, typename ValueType>
  void TraceEphemeron(const WeakMember<KeyType>& weak_member_key,
                      const Member<ValueType>* member_value) {
    const KeyType* key = weak_member_key.GetRawAtomic();
    if (!key) return;

    // `value` must always be non-null.
    CPPGC_DCHECK(member_value);
    const ValueType* value = member_value->GetRawAtomic();
    if (!value) return;

    // KeyType and ValueType may refer to GarbageCollectedMixin.
    TraceDescriptor value_desc =
        TraceTrait<ValueType>::GetTraceDescriptor(value);
    CPPGC_DCHECK(value_desc.base_object_payload);
    const void* key_base_object_payload =
        TraceTrait<KeyType>::GetTraceDescriptor(key).base_object_payload;
    CPPGC_DCHECK(key_base_object_payload);

    VisitEphemeron(key_base_object_payload, value, value_desc);
  }

  /**
   * Trace method for a single ephemeron. Used for tracing a raw ephemeron in
   * which the `key` and `value` are kept separately. Note that this overload
   * is for non-GarbageCollected `value`s that can be traced though.
   *
   * \param key `WeakMember` reference weakly retaining a key object.
   * \param value Reference weakly retaining a value object. Note that
   *   `ValueType` here should not be `Member`. It is expected that
   *   `TraceTrait<ValueType>::GetTraceDescriptor(value)` returns a
   *   `TraceDescriptor` with a null base pointer but a valid trace method.
   */
  template <typename KeyType, typename ValueType>
  void TraceEphemeron(const WeakMember<KeyType>& weak_member_key,
                      const ValueType* value) {
    static_assert(!IsGarbageCollectedOrMixinTypeV<ValueType>,
                  "garbage-collected types must use WeakMember and Member");
    const KeyType* key = weak_member_key.GetRawAtomic();
    if (!key) return;

    // `value` must always be non-null.
    CPPGC_DCHECK(value);
    TraceDescriptor value_desc =
        TraceTrait<ValueType>::GetTraceDescriptor(value);
    // `value_desc.base_object_payload` must be null as this override is only
    // taken for non-garbage-collected values.
    CPPGC_DCHECK(!value_desc.base_object_payload);

    // KeyType might be a GarbageCollectedMixin.
    const void* key_base_object_payload =
        TraceTrait<KeyType>::GetTraceDescriptor(key).base_object_payload;
    CPPGC_DCHECK(key_base_object_payload);

    VisitEphemeron(key_base_object_payload, value, value_desc);
  }

  /**
   * Trace method that strongifies a WeakMember.
   *
   * \param weak_member WeakMember reference retaining an object.
   */
  template <typename T>
  void TraceStrongly(const WeakMember<T>& weak_member) {
    const T* value = weak_member.GetRawAtomic();
    CPPGC_DCHECK(value != kSentinelPointer);
    TraceImpl(value);
  }

  /**
   * Trace method for retaining containers strongly.
   *
   * \param object reference to the container.
   */
  template <typename T>
  void TraceStrongContainer(const T* object) {
    TraceImpl(object);
  }

  /**
   * Trace method for retaining containers weakly. Note that weak containers
   * should emit write barriers.
   *
   * \param object reference to the container.
   * \param callback to be invoked.
   * \param callback_data custom data that is passed to the callback.
   */
  template <typename T>
  void TraceWeakContainer(const T* object, WeakCallback callback,
                          const void* callback_data) {
    if (!object) return;
    VisitWeakContainer(object, TraceTrait<T>::GetTraceDescriptor(object),
                       TraceTrait<T>::GetWeakTraceDescriptor(object), callback,
                       callback_data);
  }

  /**
   * Registers a slot containing a reference to an object allocated on a
   * compactable space. Such references maybe be arbitrarily moved by the GC.
   *
   * \param slot location of reference to object that might be moved by the GC.
   * The slot must contain an uncompressed pointer.
   */
  template <typename T>
  void RegisterMovableReference(const T** slot) {
    static_assert(internal::IsAllocatedOnCompactableSpace<T>::value,
                  "Only references to objects allocated on compactable spaces "
                  "should be registered as movable slots.");
    static_assert(!IsGarbageCollectedMixinTypeV<T>,
                  "Mixin types do not support compaction.");
    HandleMovableReference(reinterpret_cast<const void**>(slot));
  }

  /**
   * Registers a weak callback that is invoked during garbage collection.
   *
   * \param callback to be invoked.
   * \param data custom data that is passed to the callback.
   */
  virtual void RegisterWeakCallback(WeakCallback callback, const void* data) {}

  /**
   * Defers tracing an object from a concurrent thread to the mutator thread.
   * Should be called by Trace methods of types that are not safe to trace
   * concurrently.
   *
   * \param parameter tells the trace callback which object was deferred.
   * \param callback to be invoked for tracing on the mutator thread.
   * \param deferred_size size of deferred object.
   *
   * \returns false if the object does not need to be deferred (i.e. currently
   * traced on the mutator thread) and true otherwise (i.e. currently traced on
   * a concurrent thread).
   */
  virtual V8_WARN_UNUSED_RESULT bool DeferTraceToMutatorThreadIfConcurrent(
      const void* parameter, TraceCallback callback, size_t deferred_size) {
    // By default tracing is not deferred.
    return false;
  }

 protected:
  virtual void Visit(const void* self, TraceDescriptor) {}
  virtual void VisitWeak(const void* self, TraceDescriptor, WeakCallback,
                         const void* weak_member) {}
  virtual void VisitEphemeron(const void* key, const void* value,
                              TraceDescriptor value_desc) {}
  virtual void VisitWeakContainer(const void* self, TraceDescriptor strong_desc,
                                  TraceDescriptor weak_desc,
                                  WeakCallback callback, const void* data) {}
  virtual void HandleMovableReference(const void**) {}

  virtual void VisitMultipleUncompressedMember(
      const void* start, size_t len,
      TraceDescriptorCallback get_trace_descriptor) {
    // Default implementation merely delegates to Visit().
    const char* it = static_cast<const char*>(start);
    const char* end = it + len * internal::kSizeOfUncompressedMember;
    for (; it < end; it += internal::kSizeOfUncompressedMember) {
      const auto* current = reinterpret_cast<const internal::RawPointer*>(it);
      const void* object = current->LoadAtomic();
      if (!object) continue;

      Visit(object, get_trace_descriptor(object));
    }
  }

#if defined(CPPGC_POINTER_COMPRESSION)
  virtual void VisitMultipleCompressedMember(
      const void* start, size_t len,
      TraceDescriptorCallback get_trace_descriptor) {
    // Default implementation merely delegates to Visit().
    const char* it = static_cast<const char*>(start);
    const char* end = it + len * internal::kSizeofCompressedMember;
    for (; it < end; it += internal::kSizeofCompressedMember) {
      const auto* current =
          reinterpret_cast<const internal::CompressedPointer*>(it);
      const void* object = current->LoadAtomic();
      if (!object) continue;

      Visit(object, get_trace_descriptor(object));
    }
  }
#endif  // defined(CPPGC_POINTER_COMPRESSION)

 private:
  template <typename T, void (T::*method)(const LivenessBroker&)>
  static void WeakCallbackMethodDelegate(const LivenessBroker& info,
                                         const void* self) {
    // Callback is registered through a potential const Trace method but needs
    // to be able to modify fields. See HandleWeak.
    (const_cast<T*>(static_cast<const T*>(self))->*method)(info);
  }

  template <typename PointerType>
  static void HandleWeak(const LivenessBroker& info, const void* object) {
    const PointerType* weak = static_cast<const PointerType*>(object);
    if (!info.IsHeapObjectAlive(weak->GetFromGC())) {
      weak->ClearFromGC();
    }
  }

  template <typename T>
  void TraceImpl(const T* t) {
    static_assert(sizeof(T), "Pointee type must be fully defined.");
    static_assert(internal::IsGarbageCollectedOrMixinType<T>::value,
                  "T must be GarbageCollected or GarbageCollectedMixin type");
    if (!t) {
      return;
    }
    Visit(t, TraceTrait<T>::GetTraceDescriptor(t));
  }

#if V8_ENABLE_CHECKS
  void CheckObjectNotInConstruction(const void* address);
#endif  // V8_ENABLE_CHECKS

  template <typename T, typename WeaknessPolicy, typename LocationPolicy,
            typename CheckingPolicy>
  friend class internal::BasicCrossThreadPersistent;
  template <typename T, typename WeaknessPolicy, typename LocationPolicy,
            typename CheckingPolicy>
  friend class internal::BasicPersistent;
  friend class internal::ConservativeTracingVisitor;
  friend class internal::VisitorBase;
};

namespace internal {

class V8_EXPORT RootVisitor {
 public:
  explicit RootVisitor(Visitor::Key) {}

  virtual ~RootVisitor() = default;

  template <typename AnyStrongPersistentType,
            std::enable_if_t<
                AnyStrongPersistentType::IsStrongPersistent::value>* = nullptr>
  void Trace(const AnyStrongPersistentType& p) {
    using PointeeType = typename AnyStrongPersistentType::PointeeType;
    const void* object = Extract(p);
    if (!object) {
      return;
    }
    VisitRoot(object, TraceTrait<PointeeType>::GetTraceDescriptor(object),
              p.Location());
  }

  template <typename AnyWeakPersistentType,
            std::enable_if_t<
                !AnyWeakPersistentType::IsStrongPersistent::value>* = nullptr>
  void Trace(const AnyWeakPersistentType& p) {
    using PointeeType = typename AnyWeakPersistentType::PointeeType;
    static_assert(!internal::IsAllocatedOnCompactableSpace<PointeeType>::value,
                  "Weak references to compactable objects are not allowed");
    const void* object = Extract(p);
    if (!object) {
      return;
    }
    VisitWeakRoot(object, TraceTrait<PointeeType>::GetTraceDescriptor(object),
                  &HandleWeak<AnyWeakPersistentType>, &p, p.Location());
  }

 protected:
  virtual void VisitRoot(const void*, TraceDescriptor, const SourceLocation&) {}
  virtual void VisitWeakRoot(const void* self, TraceDescriptor, WeakCallback,
                             const void* weak_root, const SourceLocation&) {}

 private:
  template <typename AnyPersistentType>
  static const void* Extract(AnyPersistentType& p) {
    using PointeeType = typename AnyPersistentType::PointeeType;
    static_assert(sizeof(PointeeType),
                  "Persistent's pointee type must be fully defined");
    static_assert(internal::IsGarbageCollectedOrMixinType<PointeeType>::value,
                  "Persistent's pointee type must be GarbageCollected or "
                  "GarbageCollectedMixin");
    return p.GetFromGC();
  }

  template <typename PointerType>
  static void HandleWeak(const LivenessBroker& info, const void* object) {
    const PointerType* weak = static_cast<const PointerType*>(object);
    if (!info.IsHeapObjectAlive(weak->GetFromGC())) {
      weak->ClearFromGC();
    }
  }
};

}  // namespace internal
}  // namespace cppgc

#endif  // INCLUDE_CPPGC_VISITOR_H_

"""

```