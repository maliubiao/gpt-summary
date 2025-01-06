Response:
Let's break down the thought process for analyzing this C++ header file and generating the explanation.

**1. Initial Scan and Identification of Key Areas:**

The first step is to quickly skim the code and identify the major components and their purpose. Keywords like `WriteBarrier`, `Type`, `Params`, and function names like `GetWriteBarrierType`, `DijkstraMarkingBarrier`, `GenerationalBarrier` immediately jump out. The `#ifdef` blocks for `CPPGC_CAGED_HEAP` and `CPPGC_YOUNG_GENERATION` also signal conditional compilation based on different heap configurations.

**2. Understanding the Core Concept: Write Barriers:**

Based on the class name `WriteBarrier`, the core functionality likely involves managing writes to memory, particularly in the context of garbage collection. The comments "Copyright 2020 the V8 project authors" and the inclusion of files like `cppgc/heap-handle.h` and `cppgc/trace-trait.h` confirm this is related to V8's garbage collection system (cppgc).

**3. Analyzing the `WriteBarrier` Class:**

* **Enums (`Type`, `GenerationalBarrierType`):**  These define the different kinds of write barriers. `kNone`, `kMarking`, `kGenerational` are the primary types, and `kPreciseSlot`, `kPreciseUncompressedSlot`, `kImpreciseSlot` specify different flavors of generational barriers. This hints at different strategies for tracking object references.
* **`Params` struct:** This structure holds context information needed for determining the appropriate write barrier, such as the `HeapHandle`, barrier `type`, and offset information (especially relevant for the caged heap).
* **`ValueMode` enum:**  This likely indicates whether the write barrier is being applied before the value is written (so the value is "present") or if it's being applied without knowing the exact value (e.g., when initializing a slot).
* **`GetWriteBarrierType` methods:** These are crucial for determining *which* write barrier, if any, needs to be applied for a given memory write. The overloads suggest different ways to provide the slot and value information.
* **Barrier Execution Methods (`DijkstraMarkingBarrier`, `SteeleMarkingBarrier`, `GenerationalBarrier`):** These are the functions that actually *execute* the chosen write barrier logic. The names "Dijkstra" and "Steele" refer to specific marking algorithms used in garbage collection.
* **Conditional Compilation (`CPPGC_CAGED_HEAP`, `CPPGC_YOUNG_GENERATION`):**  The presence of these `#ifdef` blocks suggests that the write barrier implementation adapts based on whether the caged heap and young generation garbage collection are enabled. This is a common pattern for optimizing garbage collection strategies.
* **`FlagUpdater` and `IsEnabled()`:** This indicates a mechanism to enable or disable write barriers dynamically.

**4. Focusing on the Conditional Logic:**

The `#ifdef CPPGC_CAGED_HEAP` and `#else` blocks are important. They reveal that the implementation of `WriteBarrierTypePolicy` (which dictates how to determine the barrier type) differs significantly based on the heap configuration. The caged heap implementation appears to involve offset calculations and checks for whether addresses are "within the cage."

**5. Connecting to Garbage Collection Concepts:**

Based on the names and structure, we can infer the following connections to garbage collection:

* **Marking Barriers (Dijkstra, Steele):** These are used during the marking phase of garbage collection to ensure that reachable objects are not mistakenly collected. They update the garbage collector's knowledge of object references when a pointer is modified.
* **Generational Barriers:**  Used in generational garbage collection to track pointers from older generations to younger generations. This is an optimization that allows the garbage collector to focus on the more frequently collected younger generation.

**6. Considering JavaScript Relevance:**

Since V8 is the JavaScript engine for Chrome and Node.js, this code directly impacts JavaScript's memory management. Every time a JavaScript object's property (which is essentially a memory write) is updated, these write barriers might be involved behind the scenes.

**7. Generating Examples and Use Cases:**

To illustrate the concepts, it's helpful to create simplified scenarios:

* **JavaScript Example:** A simple object assignment demonstrates the potential need for a write barrier.
* **Logic Inference:** Creating a hypothetical scenario with caged and non-caged heaps helps to illustrate how the `GetWriteBarrierType` function might behave.
* **Common Programming Errors:** Pointing out potential issues like forgetting write barriers (if manually managing memory, which isn't typical in JavaScript but relevant in C++) is important.

**8. Structuring the Explanation:**

Finally, organizing the information into logical sections (Functionality, Torque, JavaScript Relationship, Logic Inference, Common Errors) makes the explanation clearer and easier to understand. Using bullet points and code formatting enhances readability.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe write barriers are only for marking.
* **Correction:** The presence of `GenerationalBarrier` indicates they have a role in generational GC as well.
* **Initial thought:** The `Params` struct might just be for internal use.
* **Refinement:** The `CheckParams` function suggests it's used for verification and debugging, making its content relevant to understanding how barriers are expected to be used.
* **Initial thought:**  Focus heavily on the low-level pointer manipulation.
* **Refinement:** While important, also emphasize the *purpose* of these mechanisms in the broader context of garbage collection and JavaScript's memory management.

By following these steps, combining code analysis with knowledge of garbage collection principles, and iteratively refining the understanding, one can produce a comprehensive explanation like the example provided.
这个C++头文件 `v8/include/cppgc/internal/write-barrier.h` 定义了 cppgc (Chromium's portable garbage collector) 内部使用的**写屏障 (Write Barrier)** 机制。

**主要功能:**

1. **定义写屏障的类型 (Write Barrier Types):**
   - `Type` 枚举定义了不同类型的写屏障：
     - `kNone`: 不需要写屏障。
     - `kMarking`: 用于标记阶段的写屏障，确保在并发标记过程中，对象的引用更新能被正确追踪，防止悬挂指针。
     - `kGenerational`: 用于分代垃圾回收的写屏障，当一个老年代对象引用了一个新生代对象时，需要记录这个引用，以便新生代垃圾回收时能正确处理。
   - `GenerationalBarrierType` 枚举定义了分代写屏障的更精细类型，涉及到槽 (slot) 的精度和压缩状态。

2. **确定需要的写屏障类型 (Determining Required Write Barrier):**
   - 提供了一系列静态方法 `GetWriteBarrierType`，用于根据不同的上下文（例如，被写入的槽的地址、写入的值的地址、当前堆的状态等）来判断是否需要写屏障，以及需要哪种类型的写屏障。
   - 这些方法是策略化的，使用了 `WriteBarrierTypePolicy`，根据是否启用 `CPPGC_CAGED_HEAP` 来选择不同的策略实现。
   - `ValueMode` 枚举区分了在调用 `GetWriteBarrierType` 时，被写入的值是否已知。

3. **执行写屏障操作 (Executing Write Barrier Operations):**
   - 提供了一系列静态方法来执行具体的写屏障操作：
     - `DijkstraMarkingBarrier`: 实现 Dijkstra 风格的增量标记写屏障。
     - `DijkstraMarkingBarrierRange`: 对一段连续内存区域执行 Dijkstra 标记写屏障。
     - `SteeleMarkingBarrier`: 实现 Steele 风格的标记写屏障。
     - `GenerationalBarrier`: 执行分代写屏障操作。

4. **管理写屏障的启用状态 (Managing Write Barrier Enablement):**
   - 使用 `AtomicEntryFlag write_barrier_enabled_` 来原子地管理写屏障的全局启用状态。
   - 提供了 `IsEnabled()` 方法来检查写屏障是否已启用。
   - `FlagUpdater` 类允许 cppgc 内部更新写屏障的启用状态。

5. **参数校验 (Parameter Checking):**
   - 在 `V8_ENABLE_CHECKS` 宏定义启用的情况下，`CheckParams` 方法用于检查传递给写屏障执行函数的参数是否符合预期类型。

**关于 .tq 结尾:**

如果 `v8/include/cppgc/internal/write-barrier.h` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码文件**。Torque 是一种 V8 使用的领域特定语言 (DSL)，用于定义 V8 内部的运行时函数和类型。这个头文件目前不是以 `.tq` 结尾，所以它是一个标准的 C++ 头文件。

**与 JavaScript 的功能关系 (Relationship with JavaScript):**

写屏障是垃圾回收器实现的关键组成部分，而垃圾回收器负责管理 JavaScript 对象的内存。每当 JavaScript 代码执行涉及对象属性的写入操作时，底层的 V8 引擎可能需要执行写屏障来维护垃圾回收器的数据结构的正确性。

**JavaScript 示例:**

```javascript
let obj1 = { data: 1 };
let obj2 = { ref: obj1 }; // 第一次写入引用

// ... 一段时间后 ...

let obj3 = { otherData: 2 };
obj2.ref = obj3; // 第二次写入引用
```

在上面的 JavaScript 代码中，当 `obj2.ref = obj1;` 和 `obj2.ref = obj3;` 执行时，V8 的垃圾回收器可能需要在底层执行写屏障。

- **第一次写入 `obj1` 的引用时：** 如果 `obj2` 是老年代对象，而 `obj1` 是新生代对象，则可能需要执行分代写屏障，记录下这个老年代到新生代的引用。
- **第二次写入 `obj3` 的引用时：** 同样，根据 `obj2` 和 `obj3` 的年代，可能需要执行相应的写屏障操作。如果并发标记正在进行，则可能需要执行标记写屏障。

**代码逻辑推理 (Code Logic Inference):**

**假设输入：**

- `slot`: 指向 `obj2.ref` 属性的内存地址。
- `value`: 指向 `obj3` 对象的内存地址。
- 当前垃圾回收状态：增量标记正在进行。
- 堆类型：`CPPGC_CAGED_HEAP` 未定义（非笼式堆）。

**输出推断：**

根据 `WriteBarrier::GetWriteBarrierType` 的实现，特别是 `WriteBarrierTypeForNonCagedHeapPolicy` 的部分：

1. `WriteBarrier::GetWriteBarrierType(slot, value, params)` 会被调用。
2. 由于 `CPPGC_CAGED_HEAP` 未定义，会使用 `WriteBarrierTypeForNonCagedHeapPolicy::Get<ValueMode::kValuePresent>`。
3. 在 `ValueModeDispatch<ValueMode::kValuePresent>::Get` 中，会检查 `object <= static_cast<void*>(kSentinelPointer)`。假设 `obj3` 不是哨兵指针，则继续。
4. 检查 `WriteBarrier::IsEnabled()`。假设写屏障已启用。
5. 获取 `value` (即 `obj3`) 所在页的 `BasePageHandle`，并从中获取 `HeapHandle`。
6. 检查 `heap_handle.is_incremental_marking_in_progress()`。由于假设增量标记正在进行，这个条件为真。
7. 返回 `SetAndReturnType<WriteBarrier::Type::kMarking>(params)`，即需要的写屏障类型是 `kMarking`。

**假设输入：**

- `slot`: 指向某个老年代对象的槽。
- `value`: 指向一个新生代对象的内存地址。
- 当前垃圾回收状态：年轻代垃圾回收即将开始（或正在进行，但写屏障的目的是记录跨代引用）。
- 堆类型：`CPPGC_CAGED_HEAP` 已定义。
- `CPPGC_YOUNG_GENERATION` 已定义。

**输出推断：**

1. `WriteBarrier::GetWriteBarrierType(slot, value, params)` 会被调用。
2. 由于 `CPPGC_CAGED_HEAP` 已定义，会使用 `WriteBarrierTypeForCagedHeapPolicy::Get<ValueMode::kValuePresent>`。
3. 在 `ValueModeDispatch<ValueMode::kValuePresent>::Get` 中，检查 `WriteBarrier::IsEnabled()`。假设已启用。
4. 检查 `CagedHeapBase::AreWithinCage(slot, value)`，判断 `slot` 和 `value` 是否在笼式堆的管理范围内。假设都在。
5. 获取 `value` 所在页的 `HeapHandle`。
6. 检查 `heap_handle.is_incremental_marking_in_progress()`。假设增量标记未进行。
7. 检查 `heap_handle.is_young_generation_enabled()`。假设已启用。
8. 设置 `params.heap`，`params.slot_offset`，`params.value_offset`。
9. 返回 `SetAndReturnType<WriteBarrier::Type::kGenerational>(params)`，需要的写屏障类型是 `kGenerational`。

**用户常见的编程错误 (Common Programming Errors):**

虽然用户通常不需要直接操作写屏障（这是 V8 内部管理的），但在某些底层 C++ 开发中，如果直接与 cppgc 交互，可能会出现以下错误：

1. **忘记应用写屏障：** 在手动管理对象引用时，如果忘记在指针更新后调用相应的写屏障函数，可能会导致垃圾回收器无法正确追踪引用，从而可能回收仍在使用的对象。
   ```c++
   class MyObject {
   public:
     cppgc::HeapHandle* ptr;
   };

   // 错误示例：忘记写屏障
   void updatePtr(MyObject* obj, cppgc::HeapHandle* newPtr) {
     obj->ptr = newPtr;
     // 应该根据需要调用 WriteBarrier::GetWriteBarrierType 和相应的 Barrier 函数
   }
   ```

2. **不正确的写屏障类型：**  使用了错误的写屏障函数，例如在需要分代写屏障时使用了标记写屏障，或者反之。这可能导致性能下降或垃圾回收行为异常。

3. **在不应该调用写屏障的时候调用：**  例如，在对象的构造函数中初始化成员变量时，如果该对象尚未完全构造，调用写屏障可能会导致问题。

4. **在多线程环境下未正确同步：**  写屏障操作本身可能需要一定的同步机制，如果在多线程环境下并发地修改对象引用而没有适当的同步，即使调用了写屏障，也可能出现竞争条件。

**总结:**

`v8/include/cppgc/internal/write-barrier.h` 是 cppgc 内部用于管理内存写入时所需屏障的关键头文件。它定义了写屏障的类型、确定何时需要写屏障以及如何执行这些屏障操作，确保垃圾回收器能够正确地追踪对象引用，维护内存管理的正确性。用户通常不需要直接操作这些底层机制，但理解其作用有助于理解 V8 引擎的内存管理方式。

Prompt: 
```
这是目录为v8/include/cppgc/internal/write-barrier.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/cppgc/internal/write-barrier.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_CPPGC_INTERNAL_WRITE_BARRIER_H_
#define INCLUDE_CPPGC_INTERNAL_WRITE_BARRIER_H_

#include <cstddef>
#include <cstdint>

#include "cppgc/heap-handle.h"
#include "cppgc/heap-state.h"
#include "cppgc/internal/api-constants.h"
#include "cppgc/internal/atomic-entry-flag.h"
#include "cppgc/internal/base-page-handle.h"
#include "cppgc/internal/member-storage.h"
#include "cppgc/platform.h"
#include "cppgc/sentinel-pointer.h"
#include "cppgc/trace-trait.h"
#include "v8config.h"  // NOLINT(build/include_directory)

#if defined(CPPGC_CAGED_HEAP)
#include "cppgc/internal/caged-heap-local-data.h"
#include "cppgc/internal/caged-heap.h"
#endif

namespace cppgc {

class HeapHandle;

namespace internal {

#if defined(CPPGC_CAGED_HEAP)
class WriteBarrierTypeForCagedHeapPolicy;
#else   // !CPPGC_CAGED_HEAP
class WriteBarrierTypeForNonCagedHeapPolicy;
#endif  // !CPPGC_CAGED_HEAP

class V8_EXPORT WriteBarrier final {
 public:
  enum class Type : uint8_t {
    kNone,
    kMarking,
    kGenerational,
  };

  enum class GenerationalBarrierType : uint8_t {
    kPreciseSlot,
    kPreciseUncompressedSlot,
    kImpreciseSlot,
  };

  struct Params {
    HeapHandle* heap = nullptr;
#if V8_ENABLE_CHECKS
    Type type = Type::kNone;
#endif  // !V8_ENABLE_CHECKS
#if defined(CPPGC_CAGED_HEAP)
    uintptr_t slot_offset = 0;
    uintptr_t value_offset = 0;
#endif  // CPPGC_CAGED_HEAP
  };

  enum class ValueMode {
    kValuePresent,
    kNoValuePresent,
  };

  // Returns the required write barrier for a given `slot` and `value`.
  static V8_INLINE Type GetWriteBarrierType(const void* slot, const void* value,
                                            Params& params);
  // Returns the required write barrier for a given `slot` and `value`.
  template <typename MemberStorage>
  static V8_INLINE Type GetWriteBarrierType(const void* slot, MemberStorage,
                                            Params& params);
  // Returns the required write barrier for a given `slot`.
  template <typename HeapHandleCallback>
  static V8_INLINE Type GetWriteBarrierType(const void* slot, Params& params,
                                            HeapHandleCallback callback);
  // Returns the required write barrier for a given  `value`.
  static V8_INLINE Type GetWriteBarrierType(const void* value, Params& params);

#ifdef CPPGC_SLIM_WRITE_BARRIER
  // A write barrier that combines `GenerationalBarrier()` and
  // `DijkstraMarkingBarrier()`. We only pass a single parameter here to clobber
  // as few registers as possible.
  template <WriteBarrierSlotType>
  static V8_NOINLINE void V8_PRESERVE_MOST
  CombinedWriteBarrierSlow(const void* slot);
#endif  // CPPGC_SLIM_WRITE_BARRIER

  static V8_INLINE void DijkstraMarkingBarrier(const Params& params,
                                               const void* object);
  static V8_INLINE void DijkstraMarkingBarrierRange(
      const Params& params, const void* first_element, size_t element_size,
      size_t number_of_elements, TraceCallback trace_callback);
  static V8_INLINE void SteeleMarkingBarrier(const Params& params,
                                             const void* object);
#if defined(CPPGC_YOUNG_GENERATION)
  template <GenerationalBarrierType>
  static V8_INLINE void GenerationalBarrier(const Params& params,
                                            const void* slot);
#else  // !CPPGC_YOUNG_GENERATION
  template <GenerationalBarrierType>
  static V8_INLINE void GenerationalBarrier(const Params& params,
                                            const void* slot){}
#endif  // CPPGC_YOUNG_GENERATION

#if V8_ENABLE_CHECKS
  static void CheckParams(Type expected_type, const Params& params);
#else   // !V8_ENABLE_CHECKS
  static void CheckParams(Type expected_type, const Params& params) {}
#endif  // !V8_ENABLE_CHECKS

  // The FlagUpdater class allows cppgc internal to update
  // |write_barrier_enabled_|.
  class FlagUpdater;
  static bool IsEnabled() { return write_barrier_enabled_.MightBeEntered(); }

 private:
  WriteBarrier() = delete;

#if defined(CPPGC_CAGED_HEAP)
  using WriteBarrierTypePolicy = WriteBarrierTypeForCagedHeapPolicy;
#else   // !CPPGC_CAGED_HEAP
  using WriteBarrierTypePolicy = WriteBarrierTypeForNonCagedHeapPolicy;
#endif  // !CPPGC_CAGED_HEAP

  static void DijkstraMarkingBarrierSlow(const void* value);
  static void DijkstraMarkingBarrierSlowWithSentinelCheck(const void* value);
  static void DijkstraMarkingBarrierRangeSlow(HeapHandle& heap_handle,
                                              const void* first_element,
                                              size_t element_size,
                                              size_t number_of_elements,
                                              TraceCallback trace_callback);
  static void SteeleMarkingBarrierSlow(const void* value);
  static void SteeleMarkingBarrierSlowWithSentinelCheck(const void* value);

#if defined(CPPGC_YOUNG_GENERATION)
  static CagedHeapLocalData& GetLocalData(HeapHandle&);
  static void GenerationalBarrierSlow(const CagedHeapLocalData& local_data,
                                      const AgeTable& age_table,
                                      const void* slot, uintptr_t value_offset,
                                      HeapHandle* heap_handle);
  static void GenerationalBarrierForUncompressedSlotSlow(
      const CagedHeapLocalData& local_data, const AgeTable& age_table,
      const void* slot, uintptr_t value_offset, HeapHandle* heap_handle);
  static void GenerationalBarrierForSourceObjectSlow(
      const CagedHeapLocalData& local_data, const void* object,
      HeapHandle* heap_handle);
#endif  // CPPGC_YOUNG_GENERATION

  static AtomicEntryFlag write_barrier_enabled_;
};

template <WriteBarrier::Type type>
V8_INLINE WriteBarrier::Type SetAndReturnType(WriteBarrier::Params& params) {
  if constexpr (type == WriteBarrier::Type::kNone)
    return WriteBarrier::Type::kNone;
#if V8_ENABLE_CHECKS
  params.type = type;
#endif  // !V8_ENABLE_CHECKS
  return type;
}

#if defined(CPPGC_CAGED_HEAP)
class V8_EXPORT WriteBarrierTypeForCagedHeapPolicy final {
 public:
  template <WriteBarrier::ValueMode value_mode, typename HeapHandleCallback>
  static V8_INLINE WriteBarrier::Type Get(const void* slot, const void* value,
                                          WriteBarrier::Params& params,
                                          HeapHandleCallback callback) {
    return ValueModeDispatch<value_mode>::Get(slot, value, params, callback);
  }

  template <WriteBarrier::ValueMode value_mode, typename HeapHandleCallback,
            typename MemberStorage>
  static V8_INLINE WriteBarrier::Type Get(const void* slot, MemberStorage value,
                                          WriteBarrier::Params& params,
                                          HeapHandleCallback callback) {
    return ValueModeDispatch<value_mode>::Get(slot, value, params, callback);
  }

  template <WriteBarrier::ValueMode value_mode, typename HeapHandleCallback>
  static V8_INLINE WriteBarrier::Type Get(const void* value,
                                          WriteBarrier::Params& params,
                                          HeapHandleCallback callback) {
    return GetNoSlot(value, params, callback);
  }

 private:
  WriteBarrierTypeForCagedHeapPolicy() = delete;

  template <typename HeapHandleCallback>
  static V8_INLINE WriteBarrier::Type GetNoSlot(const void* value,
                                                WriteBarrier::Params& params,
                                                HeapHandleCallback) {
    const bool within_cage = CagedHeapBase::IsWithinCage(value);
    if (!within_cage) return WriteBarrier::Type::kNone;

    // We know that |value| points either within the normal page or to the
    // beginning of large-page, so extract the page header by bitmasking.
    BasePageHandle* page =
        BasePageHandle::FromPayload(const_cast<void*>(value));

    HeapHandle& heap_handle = page->heap_handle();
    if (V8_UNLIKELY(heap_handle.is_incremental_marking_in_progress())) {
      return SetAndReturnType<WriteBarrier::Type::kMarking>(params);
    }

    return SetAndReturnType<WriteBarrier::Type::kNone>(params);
  }

  template <WriteBarrier::ValueMode value_mode>
  struct ValueModeDispatch;
};

template <>
struct WriteBarrierTypeForCagedHeapPolicy::ValueModeDispatch<
    WriteBarrier::ValueMode::kValuePresent> {
  template <typename HeapHandleCallback, typename MemberStorage>
  static V8_INLINE WriteBarrier::Type Get(const void* slot,
                                          MemberStorage storage,
                                          WriteBarrier::Params& params,
                                          HeapHandleCallback) {
    if (V8_LIKELY(!WriteBarrier::IsEnabled()))
      return SetAndReturnType<WriteBarrier::Type::kNone>(params);

    return BarrierEnabledGet(slot, storage.Load(), params);
  }

  template <typename HeapHandleCallback>
  static V8_INLINE WriteBarrier::Type Get(const void* slot, const void* value,
                                          WriteBarrier::Params& params,
                                          HeapHandleCallback) {
    if (V8_LIKELY(!WriteBarrier::IsEnabled()))
      return SetAndReturnType<WriteBarrier::Type::kNone>(params);

    return BarrierEnabledGet(slot, value, params);
  }

 private:
  static V8_INLINE WriteBarrier::Type BarrierEnabledGet(
      const void* slot, const void* value, WriteBarrier::Params& params) {
    const bool within_cage = CagedHeapBase::AreWithinCage(slot, value);
    if (!within_cage) return WriteBarrier::Type::kNone;

    // We know that |value| points either within the normal page or to the
    // beginning of large-page, so extract the page header by bitmasking.
    BasePageHandle* page =
        BasePageHandle::FromPayload(const_cast<void*>(value));

    HeapHandle& heap_handle = page->heap_handle();
    if (V8_LIKELY(!heap_handle.is_incremental_marking_in_progress())) {
#if defined(CPPGC_YOUNG_GENERATION)
      if (!heap_handle.is_young_generation_enabled())
        return WriteBarrier::Type::kNone;
      params.heap = &heap_handle;
      params.slot_offset = CagedHeapBase::OffsetFromAddress(slot);
      params.value_offset = CagedHeapBase::OffsetFromAddress(value);
      return SetAndReturnType<WriteBarrier::Type::kGenerational>(params);
#else   // !CPPGC_YOUNG_GENERATION
      return SetAndReturnType<WriteBarrier::Type::kNone>(params);
#endif  // !CPPGC_YOUNG_GENERATION
    }

    // Use marking barrier.
    params.heap = &heap_handle;
    return SetAndReturnType<WriteBarrier::Type::kMarking>(params);
  }
};

template <>
struct WriteBarrierTypeForCagedHeapPolicy::ValueModeDispatch<
    WriteBarrier::ValueMode::kNoValuePresent> {
  template <typename HeapHandleCallback>
  static V8_INLINE WriteBarrier::Type Get(const void* slot, const void*,
                                          WriteBarrier::Params& params,
                                          HeapHandleCallback callback) {
    if (V8_LIKELY(!WriteBarrier::IsEnabled()))
      return SetAndReturnType<WriteBarrier::Type::kNone>(params);

    HeapHandle& handle = callback();
#if defined(CPPGC_YOUNG_GENERATION)
    if (V8_LIKELY(!handle.is_incremental_marking_in_progress())) {
      if (!handle.is_young_generation_enabled()) {
        return WriteBarrier::Type::kNone;
      }
      params.heap = &handle;
      // Check if slot is on stack.
      if (V8_UNLIKELY(!CagedHeapBase::IsWithinCage(slot))) {
        return SetAndReturnType<WriteBarrier::Type::kNone>(params);
      }
      params.slot_offset = CagedHeapBase::OffsetFromAddress(slot);
      return SetAndReturnType<WriteBarrier::Type::kGenerational>(params);
    }
#else   // !defined(CPPGC_YOUNG_GENERATION)
    if (V8_UNLIKELY(!handle.is_incremental_marking_in_progress())) {
      return SetAndReturnType<WriteBarrier::Type::kNone>(params);
    }
#endif  // !defined(CPPGC_YOUNG_GENERATION)
    params.heap = &handle;
    return SetAndReturnType<WriteBarrier::Type::kMarking>(params);
  }
};

#endif  // CPPGC_CAGED_HEAP

class V8_EXPORT WriteBarrierTypeForNonCagedHeapPolicy final {
 public:
  template <WriteBarrier::ValueMode value_mode, typename HeapHandleCallback>
  static V8_INLINE WriteBarrier::Type Get(const void* slot, const void* value,
                                          WriteBarrier::Params& params,
                                          HeapHandleCallback callback) {
    return ValueModeDispatch<value_mode>::Get(slot, value, params, callback);
  }

  template <WriteBarrier::ValueMode value_mode, typename HeapHandleCallback>
  static V8_INLINE WriteBarrier::Type Get(const void* slot, RawPointer value,
                                          WriteBarrier::Params& params,
                                          HeapHandleCallback callback) {
    return ValueModeDispatch<value_mode>::Get(slot, value.Load(), params,
                                              callback);
  }

  template <WriteBarrier::ValueMode value_mode, typename HeapHandleCallback>
  static V8_INLINE WriteBarrier::Type Get(const void* value,
                                          WriteBarrier::Params& params,
                                          HeapHandleCallback callback) {
    // The slot will never be used in `Get()` below.
    return Get<WriteBarrier::ValueMode::kValuePresent>(nullptr, value, params,
                                                       callback);
  }

 private:
  template <WriteBarrier::ValueMode value_mode>
  struct ValueModeDispatch;

  WriteBarrierTypeForNonCagedHeapPolicy() = delete;
};

template <>
struct WriteBarrierTypeForNonCagedHeapPolicy::ValueModeDispatch<
    WriteBarrier::ValueMode::kValuePresent> {
  template <typename HeapHandleCallback>
  static V8_INLINE WriteBarrier::Type Get(const void*, const void* object,
                                          WriteBarrier::Params& params,
                                          HeapHandleCallback callback) {
    // The following check covers nullptr as well as sentinel pointer.
    if (object <= static_cast<void*>(kSentinelPointer)) {
      return SetAndReturnType<WriteBarrier::Type::kNone>(params);
    }
    if (V8_LIKELY(!WriteBarrier::IsEnabled())) {
      return SetAndReturnType<WriteBarrier::Type::kNone>(params);
    }
    // We know that |object| is within the normal page or in the beginning of a
    // large page, so extract the page header by bitmasking.
    BasePageHandle* page =
        BasePageHandle::FromPayload(const_cast<void*>(object));

    HeapHandle& heap_handle = page->heap_handle();
    if (V8_LIKELY(heap_handle.is_incremental_marking_in_progress())) {
      return SetAndReturnType<WriteBarrier::Type::kMarking>(params);
    }
    return SetAndReturnType<WriteBarrier::Type::kNone>(params);
  }
};

template <>
struct WriteBarrierTypeForNonCagedHeapPolicy::ValueModeDispatch<
    WriteBarrier::ValueMode::kNoValuePresent> {
  template <typename HeapHandleCallback>
  static V8_INLINE WriteBarrier::Type Get(const void*, const void*,
                                          WriteBarrier::Params& params,
                                          HeapHandleCallback callback) {
    if (V8_UNLIKELY(WriteBarrier::IsEnabled())) {
      HeapHandle& handle = callback();
      if (V8_LIKELY(handle.is_incremental_marking_in_progress())) {
        params.heap = &handle;
        return SetAndReturnType<WriteBarrier::Type::kMarking>(params);
      }
    }
    return WriteBarrier::Type::kNone;
  }
};

// static
WriteBarrier::Type WriteBarrier::GetWriteBarrierType(
    const void* slot, const void* value, WriteBarrier::Params& params) {
  return WriteBarrierTypePolicy::Get<ValueMode::kValuePresent>(slot, value,
                                                               params, []() {});
}

// static
template <typename MemberStorage>
WriteBarrier::Type WriteBarrier::GetWriteBarrierType(
    const void* slot, MemberStorage value, WriteBarrier::Params& params) {
  return WriteBarrierTypePolicy::Get<ValueMode::kValuePresent>(slot, value,
                                                               params, []() {});
}

// static
template <typename HeapHandleCallback>
WriteBarrier::Type WriteBarrier::GetWriteBarrierType(
    const void* slot, WriteBarrier::Params& params,
    HeapHandleCallback callback) {
  return WriteBarrierTypePolicy::Get<ValueMode::kNoValuePresent>(
      slot, nullptr, params, callback);
}

// static
WriteBarrier::Type WriteBarrier::GetWriteBarrierType(
    const void* value, WriteBarrier::Params& params) {
  return WriteBarrierTypePolicy::Get<ValueMode::kValuePresent>(value, params,
                                                               []() {});
}

// static
void WriteBarrier::DijkstraMarkingBarrier(const Params& params,
                                          const void* object) {
  CheckParams(Type::kMarking, params);
#if defined(CPPGC_CAGED_HEAP)
  // Caged heap already filters out sentinels.
  DijkstraMarkingBarrierSlow(object);
#else   // !CPPGC_CAGED_HEAP
  DijkstraMarkingBarrierSlowWithSentinelCheck(object);
#endif  // !CPPGC_CAGED_HEAP
}

// static
void WriteBarrier::DijkstraMarkingBarrierRange(const Params& params,
                                               const void* first_element,
                                               size_t element_size,
                                               size_t number_of_elements,
                                               TraceCallback trace_callback) {
  CheckParams(Type::kMarking, params);
  DijkstraMarkingBarrierRangeSlow(*params.heap, first_element, element_size,
                                  number_of_elements, trace_callback);
}

// static
void WriteBarrier::SteeleMarkingBarrier(const Params& params,
                                        const void* object) {
  CheckParams(Type::kMarking, params);
#if defined(CPPGC_CAGED_HEAP)
  // Caged heap already filters out sentinels.
  SteeleMarkingBarrierSlow(object);
#else   // !CPPGC_CAGED_HEAP
  SteeleMarkingBarrierSlowWithSentinelCheck(object);
#endif  // !CPPGC_CAGED_HEAP
}

#if defined(CPPGC_YOUNG_GENERATION)

// static
template <WriteBarrier::GenerationalBarrierType type>
void WriteBarrier::GenerationalBarrier(const Params& params, const void* slot) {
  CheckParams(Type::kGenerational, params);

  const CagedHeapLocalData& local_data = CagedHeapLocalData::Get();
  const AgeTable& age_table = local_data.age_table;

  // Bail out if the slot (precise or imprecise) is in young generation.
  if (V8_LIKELY(age_table.GetAge(params.slot_offset) == AgeTable::Age::kYoung))
    return;

  // Dispatch between different types of barriers.
  // TODO(chromium:1029379): Consider reload local_data in the slow path to
  // reduce register pressure.
  if constexpr (type == GenerationalBarrierType::kPreciseSlot) {
    GenerationalBarrierSlow(local_data, age_table, slot, params.value_offset,
                            params.heap);
  } else if constexpr (type ==
                       GenerationalBarrierType::kPreciseUncompressedSlot) {
    GenerationalBarrierForUncompressedSlotSlow(
        local_data, age_table, slot, params.value_offset, params.heap);
  } else {
    GenerationalBarrierForSourceObjectSlow(local_data, slot, params.heap);
  }
}

#endif  // !CPPGC_YOUNG_GENERATION

}  // namespace internal
}  // namespace cppgc

#endif  // INCLUDE_CPPGC_INTERNAL_WRITE_BARRIER_H_

"""

```