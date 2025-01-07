Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Skim and Keyword Identification:**

The first step is to quickly skim the code, looking for recognizable patterns and keywords. Immediately, I notice:

* `// Copyright`:  Standard copyright header.
* `#include`:  Indicates this is C++ code and lists dependencies. The includes give clues about the functionality: `v8-initialization.h`, `api/api.h`, `heap/heap.h`, `objects/objects-inl.h`, `test/cctest/cctest.h`. This strongly suggests it's a test file for V8's internal string handling, specifically shared strings.
* `namespace v8 { namespace internal { namespace test_shared_strings`:  Confirms it's part of V8's internal testing framework and focuses on shared strings.
* `struct`, `class`:  C++ structures and classes define data and behavior. The names are informative: `IsolateWrapper`, `IsolateParkOnDisposeWrapper`, `MultiClientIsolateTest`, `ConcurrentStringThreadBase`, `ConcurrentInternalizationThread`, `ConcurrentStringTableLookupThread`. These names suggest testing scenarios involving multiple V8 isolates and concurrent operations on strings.
* `UNINITIALIZED_TEST`: This is likely a macro from the `cctest` framework, indicating a test case. The names of the tests are very descriptive: `InPlaceInternalizableStringsAreShared`, `InPlaceInternalization`, `YoungInternalization`, `ConcurrentInternalizationMiss`, `ConcurrentInternalizationHit`, `ConcurrentStringTableLookup`, `StringShare`, `PromotionMarkCompact`, `PromotionScavenge`. These directly relate to concepts of string sharing, internalization, and garbage collection.
* `v8_flags.shared_string_table = true;`: This is a crucial flag indicating that the tests are specifically focused on the shared string table feature.
* `factory->NewStringFrom...`, `factory->InternalizeString(...)`, `String::Share(...)`: These are key V8 API calls related to string creation, internalization (making a string canonical and shared), and explicitly sharing a string.
* `CHECK(...)`, `CHECK_EQ(...)`, `CHECK_NE(...)`, `CHECK_IMPLIES(...)`:  These are assertion macros from the testing framework, used to verify expected behavior.
* `ParkingThread`, `ParkingSemaphore`:  These suggest the use of threads and synchronization primitives for concurrent testing.
* Comments explaining the purpose of certain code sections (e.g., the `IsolateParkOnDisposeWrapper`).

**2. Deduction of Core Functionality:**

Based on the keywords and test names, the core functionality revolves around:

* **Shared Strings:**  Testing the mechanism for sharing string objects between different V8 isolates.
* **Internalization:**  Verifying how strings are made canonical and shared across isolates. The tests differentiate between "in-place" internalization (where the original object becomes the shared one) and cases where a copy might be made.
* **Young Generation vs. Old Generation:**  Testing how string sharing and internalization interact with V8's generational garbage collection.
* **Concurrency:**  Testing the thread-safety and correctness of string sharing and internalization when multiple threads access and modify string tables concurrently.
* **String Sharing Mechanics:** Examining the conditions under which strings are shared (e.g., old generation, internalized, explicit sharing).
* **Garbage Collection Interaction:**  Testing how garbage collection (both minor and major) affects shared strings and their promotion between generations.

**3. Structure and Organization:**

The code is structured as a series of independent test cases within the `test_shared_strings` namespace. Helper classes like `MultiClientIsolateTest` are used to set up the testing environment (creating multiple isolates). The concurrent tests use dedicated thread classes to simulate parallel operations.

**4. Answering Specific Questions (Mental Checklist):**

* **Functionality:** Yes, I can summarize the functionality as testing V8's shared string implementation.
* **Torque:** The filename ends in `.cc`, not `.tq`, so it's not Torque.
* **JavaScript Relation:** Yes, shared strings are directly related to JavaScript's string handling. When the same string literal appears in different contexts (potentially across different isolates or even within the same isolate), V8 can use shared strings to save memory.
* **JavaScript Example:** I need to construct a simple JavaScript example that demonstrates the concept of shared strings.
* **Code Logic Reasoning:**  The tests involve comparisons and assertions based on the state of strings (shared, internalized, equality). I can devise simple input scenarios and predict the expected output based on the test logic.
* **Common Programming Errors:** I should think about potential errors users might encounter when dealing with string interning or assuming string identity.
* **Overall Functionality (Part 1 Summary):**  I need to synthesize all the above points into a concise summary of the first part of the file.

**5. Refinement and Example Generation:**

At this point, I would refine my understanding and generate the specific examples:

* **JavaScript Example:**  The core idea is to show that identical string literals can point to the same underlying memory.
* **Input/Output for Logic:**  Choose simple scenarios from the tests, like creating two identical strings in different isolates and checking if their internalized versions are the same.
* **Common Errors:** Focus on the difference between `==` (identity in JavaScript for primitives after interning) and checking for character-by-character equality.

By following these steps, I can systematically analyze the C++ code and generate a comprehensive answer to the prompt. The key is to leverage the descriptive naming, the included headers, and the test structure to understand the underlying purpose and behavior being tested.
这是第一部分，主要功能是测试 V8 引擎中共享字符串的机制。

**具体功能归纳：**

1. **测试共享字符串的基本特性:**
   - 验证在启用共享字符串表的情况下，特定类型的字符串（如旧生代的顺序字符串和内部化字符串）是否被分配到共享堆空间。
   - 验证年轻代的字符串在共享字符串表启用时不会被共享。

2. **测试共享字符串的内部化 (Internalization) 机制:**
   - 验证在不同的 V8 隔离区 (Isolate) 中，内容相同的字符串经过内部化后是否指向同一个共享的字符串对象。
   - 区分旧生代字符串的“原地内部化”（字符串本身移动到共享空间）和年轻代字符串的内部化（创建新的共享字符串）。

3. **测试共享字符串的并发操作:**
   - 使用多线程模拟并发的字符串内部化操作，测试在高并发场景下共享字符串表的正确性。
   - 分别测试并发内部化“命中” (Hit) 和“未命中” (Miss) 的情况。“命中”是指要内部化的字符串在共享字符串表中已经存在，“未命中”则需要将其添加到表中。
   - 测试并发的字符串表查找操作，验证在多个线程同时查找字符串时，结果的正确性。

4. **测试 `String::Share` 方法:**
   - 验证 `String::Share` 方法可以将字符串显式地标记为共享。
   - 测试不同类型的字符串（顺序字符串、内部化字符串、外部字符串、薄字符串、拼接字符串、切片字符串）在调用 `String::Share` 后的行为，以及是否会创建副本。

5. **测试垃圾回收对共享字符串的影响:**
   - 测试在执行主垃圾回收 (Mark-Compact) 和新生代垃圾回收 (Scavenge) 时，共享字符串的晋升 (Promotion) 行为。
   - 验证符合原地内部化条件的年轻代字符串在垃圾回收后是否会被移动到共享堆中。

**关于文件类型和 JavaScript 关系：**

- `v8/test/cctest/test-shared-strings.cc` 的后缀是 `.cc`，这表明它是一个 **C++ 源代码文件**，用于 V8 的 C++ 单元测试。
- 虽然这个文件本身是 C++ 代码，但它测试的功能 **与 JavaScript 的字符串操作密切相关**。在 JavaScript 中，字符串是一种基本类型，V8 引擎负责其高效的管理和存储。共享字符串是一种优化手段，可以减少内存占用，特别是对于在多个上下文或隔离区中重复使用的字符串字面量。

**JavaScript 举例说明：**

```javascript
// 假设在两个不同的 V8 上下文 (模拟不同的 Isolate) 中运行以下代码

// 上下文 1
const str1 = "hello";
const str2 = "hello";

// 上下文 2
const str3 = "hello";
const str4 = "hello";

// 在启用了共享字符串的情况下，V8 可能会让 str1, str2, str3, str4
// 指向同一个底层的共享字符串对象，从而节省内存。

// 内部化 (在 JavaScript 中隐式发生，可以通过某些方式触发) 可以确保
// 具有相同内容的字符串字面量指向同一个对象。
```

**代码逻辑推理 - 假设输入与输出：**

**示例：`UNINITIALIZED_TEST(InPlaceInternalization)`**

**假设输入：**

- 两个独立的 V8 隔离区 (Isolate)。
- 在隔离区 1 中创建字符串 "foo" 和 "bar" (假设以Old Generation方式分配)。
- 在隔离区 2 中创建字符串 "foo" 和 "bar" (假设以Old Generation方式分配)。
- 启用共享字符串表。

**预期输出：**

- 在隔离区 1 中，对 "foo" 和 "bar" 进行内部化后，它们自身会变成共享字符串，且其指针不会改变。
- 在隔离区 2 中，对 "foo" 和 "bar" 进行内部化后，它们会指向与隔离区 1 中相同的共享字符串对象（指针相同）。

**用户常见的编程错误 - 举例说明：**

1. **误认为所有字符串都是共享的：** 用户可能会认为在任何情况下，内容相同的字符串都会指向同一个对象。但在 V8 中，只有特定类型的字符串（例如内部化字符串）才会保证共享。

   ```javascript
   const str1 = "hello";
   const str2 = "hello";
   console.log(str1 === str2); // 输出 true，因为 JavaScript 会隐式地对字面量进行内部化

   const str3 = new String("hello");
   const str4 = new String("hello");
   console.log(str3 === str4); // 输出 false，因为通过 `new String()` 创建的是不同的对象
   ```

2. **在多线程环境下不考虑字符串操作的线程安全性：** 虽然 V8 的共享字符串机制会处理并发访问，但如果用户在多线程 JavaScript 环境中直接操作字符串对象，仍然需要考虑线程安全问题。这个测试文件的一部分正是为了验证 V8 内部共享字符串机制的线程安全性。

**总结 - 第一部分功能：**

总而言之，`v8/test/cctest/test-shared-strings.cc` 的第一部分主要关注 **V8 引擎中共享字符串机制的核心功能和基本特性**，包括其在不同隔离区中的内部化行为、并发场景下的稳定性和正确性，以及与垃圾回收的交互。它通过一系列单元测试来验证 V8 共享字符串实现的正确性和性能。

Prompt: 
```
这是目录为v8/test/cctest/test-shared-strings.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-shared-strings.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "include/v8-initialization.h"
#include "src/api/api-inl.h"
#include "src/api/api.h"
#include "src/base/strings.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/flags/flags.h"
#include "src/heap/factory.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap.h"
#include "src/heap/memory-chunk-layout.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/parked-scope-inl.h"
#include "src/heap/remembered-set.h"
#include "src/heap/safepoint.h"
#include "src/objects/fixed-array.h"
#include "src/objects/heap-object.h"
#include "src/objects/js-weak-refs.h"
#include "src/objects/objects-inl.h"
#include "src/objects/string-forwarding-table-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/heap/heap-utils.h"

// In multi-cage mode we create one cage per isolate
// and we don't share objects between cages.
#if V8_CAN_CREATE_SHARED_HEAP_BOOL && !COMPRESS_POINTERS_IN_MULTIPLE_CAGES_BOOL

namespace v8 {
namespace internal {
namespace test_shared_strings {

struct V8_NODISCARD IsolateWrapper {
  explicit IsolateWrapper(v8::Isolate* isolate) : isolate(isolate) {}
  ~IsolateWrapper() { isolate->Dispose(); }
  v8::Isolate* const isolate;
};

// Some tests in this file allocate two Isolates in the same thread to directly
// test shared string behavior. Because both are considered running, when
// disposing these Isolates, one must be parked to not cause a deadlock in the
// shared heap verification that happens on client Isolate disposal.
struct V8_NODISCARD IsolateParkOnDisposeWrapper {
  IsolateParkOnDisposeWrapper(v8::Isolate* isolate,
                              v8::Isolate* isolate_to_park)
      : isolate(isolate), isolate_to_park(isolate_to_park) {}

  ~IsolateParkOnDisposeWrapper() {
    auto main_isolate = reinterpret_cast<Isolate*>(isolate_to_park)
                            ->main_thread_local_isolate();
    main_isolate->ExecuteMainThreadWhileParked(
        [this]() { isolate->Dispose(); });
  }

  v8::Isolate* const isolate;
  v8::Isolate* const isolate_to_park;
};

class MultiClientIsolateTest {
 public:
  MultiClientIsolateTest() {
    std::unique_ptr<v8::ArrayBuffer::Allocator> allocator(
        v8::ArrayBuffer::Allocator::NewDefaultAllocator());
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = allocator.get();
    main_isolate_ = v8::Isolate::New(create_params);
    i_main_isolate()->Enter();
  }

  ~MultiClientIsolateTest() {
    i_main_isolate()->Exit();
    main_isolate_->Dispose();
  }

  v8::Isolate* main_isolate() const { return main_isolate_; }

  Isolate* i_main_isolate() const {
    return reinterpret_cast<Isolate*>(main_isolate_);
  }

  int& main_isolate_wakeup_counter() { return main_isolate_wakeup_counter_; }

  v8::Isolate* NewClientIsolate() {
    CHECK_NOT_NULL(main_isolate_);
    std::unique_ptr<v8::ArrayBuffer::Allocator> allocator(
        v8::ArrayBuffer::Allocator::NewDefaultAllocator());
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = allocator.get();
    return v8::Isolate::New(create_params);
  }

 private:
  v8::Isolate* main_isolate_;
  int main_isolate_wakeup_counter_ = 0;
};

UNINITIALIZED_TEST(InPlaceInternalizableStringsAreShared) {
  if (v8_flags.single_generation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  MultiClientIsolateTest test;
  Isolate* i_isolate1 = test.i_main_isolate();
  Factory* factory1 = i_isolate1->factory();

  HandleScope handle_scope(i_isolate1);

  const char raw_one_byte[] = "foo";
  base::uc16 raw_two_byte[] = {2001, 2002, 2003};
  base::Vector<const base::uc16> two_byte(raw_two_byte, 3);

  // Old generation 1- and 2-byte seq strings are in-place internalizable.
  DirectHandle<String> old_one_byte_seq =
      factory1->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
  CHECK(HeapLayout::InAnySharedSpace(*old_one_byte_seq));
  DirectHandle<String> old_two_byte_seq =
      factory1->NewStringFromTwoByte(two_byte, AllocationType::kOld)
          .ToHandleChecked();
  CHECK(HeapLayout::InAnySharedSpace(*old_two_byte_seq));

  // Young generation are not internalizable and not shared when sharing the
  // string table.
  DirectHandle<String> young_one_byte_seq =
      factory1->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kYoung);
  CHECK(!HeapLayout::InAnySharedSpace(*young_one_byte_seq));
  DirectHandle<String> young_two_byte_seq =
      factory1->NewStringFromTwoByte(two_byte, AllocationType::kYoung)
          .ToHandleChecked();
  CHECK(!HeapLayout::InAnySharedSpace(*young_two_byte_seq));

  // Internalized strings are shared.
  uint64_t seed = HashSeed(i_isolate1);
  DirectHandle<String> one_byte_intern = factory1->NewOneByteInternalizedString(
      base::OneByteVector(raw_one_byte),
      StringHasher::HashSequentialString<char>(raw_one_byte, 3, seed));
  CHECK(HeapLayout::InAnySharedSpace(*one_byte_intern));
  DirectHandle<String> two_byte_intern = factory1->NewTwoByteInternalizedString(
      two_byte,
      StringHasher::HashSequentialString<uint16_t>(raw_two_byte, 3, seed));
  CHECK(HeapLayout::InAnySharedSpace(*two_byte_intern));
}

UNINITIALIZED_TEST(InPlaceInternalization) {
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  MultiClientIsolateTest test;
  ManualGCScope manual_gc_scope(test.i_main_isolate());

  IsolateParkOnDisposeWrapper isolate_wrapper(test.NewClientIsolate(),
                                              test.main_isolate());
  Isolate* i_isolate1 = test.i_main_isolate();
  Factory* factory1 = i_isolate1->factory();
  Isolate* i_isolate2 = reinterpret_cast<Isolate*>(isolate_wrapper.isolate);
  Factory* factory2 = i_isolate2->factory();

  HandleScope scope1(i_isolate1);
  HandleScope scope2(i_isolate2);

  const char raw_one_byte[] = "foo";
  base::uc16 raw_two_byte[] = {2001, 2002, 2003};
  base::Vector<const base::uc16> two_byte(raw_two_byte, 3);

  // Allocate two in-place internalizable strings in isolate1 then intern
  // them.
  DirectHandle<String> old_one_byte_seq1 =
      factory1->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
  DirectHandle<String> old_two_byte_seq1 =
      factory1->NewStringFromTwoByte(two_byte, AllocationType::kOld)
          .ToHandleChecked();
  DirectHandle<String> one_byte_intern1 =
      factory1->InternalizeString(old_one_byte_seq1);
  DirectHandle<String> two_byte_intern1 =
      factory1->InternalizeString(old_two_byte_seq1);
  CHECK(HeapLayout::InAnySharedSpace(*old_one_byte_seq1));
  CHECK(HeapLayout::InAnySharedSpace(*old_two_byte_seq1));
  CHECK(HeapLayout::InAnySharedSpace(*one_byte_intern1));
  CHECK(HeapLayout::InAnySharedSpace(*two_byte_intern1));
  CHECK(old_one_byte_seq1.equals(one_byte_intern1));
  CHECK(old_two_byte_seq1.equals(two_byte_intern1));
  CHECK_EQ(*old_one_byte_seq1, *one_byte_intern1);
  CHECK_EQ(*old_two_byte_seq1, *two_byte_intern1);

  // Allocate two in-place internalizable strings with the same contents in
  // isolate2 then intern them. They should be the same as the interned strings
  // from isolate1.
  DirectHandle<String> old_one_byte_seq2 =
      factory2->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
  DirectHandle<String> old_two_byte_seq2 =
      factory2->NewStringFromTwoByte(two_byte, AllocationType::kOld)
          .ToHandleChecked();
  DirectHandle<String> one_byte_intern2 =
      factory2->InternalizeString(old_one_byte_seq2);
  DirectHandle<String> two_byte_intern2 =
      factory2->InternalizeString(old_two_byte_seq2);
  CHECK(HeapLayout::InAnySharedSpace(*old_one_byte_seq2));
  CHECK(HeapLayout::InAnySharedSpace(*old_two_byte_seq2));
  CHECK(HeapLayout::InAnySharedSpace(*one_byte_intern2));
  CHECK(HeapLayout::InAnySharedSpace(*two_byte_intern2));
  CHECK(!old_one_byte_seq2.equals(one_byte_intern2));
  CHECK(!old_two_byte_seq2.equals(two_byte_intern2));
  CHECK_NE(*old_one_byte_seq2, *one_byte_intern2);
  CHECK_NE(*old_two_byte_seq2, *two_byte_intern2);
  CHECK_EQ(*one_byte_intern1, *one_byte_intern2);
  CHECK_EQ(*two_byte_intern1, *two_byte_intern2);
}

UNINITIALIZED_TEST(YoungInternalization) {
  if (v8_flags.single_generation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  MultiClientIsolateTest test;
  IsolateParkOnDisposeWrapper isolate_wrapper(test.NewClientIsolate(),
                                              test.main_isolate());
  Isolate* i_isolate1 = test.i_main_isolate();
  Factory* factory1 = i_isolate1->factory();
  Isolate* i_isolate2 = reinterpret_cast<Isolate*>(isolate_wrapper.isolate);
  Factory* factory2 = i_isolate2->factory();

  HandleScope scope1(i_isolate1);
  HandleScope scope2(i_isolate2);

  const char raw_one_byte[] = "foo";
  base::uc16 raw_two_byte[] = {2001, 2002, 2003};
  base::Vector<const base::uc16> two_byte(raw_two_byte, 3);

  // Allocate two young strings in isolate1 then intern them. Young strings
  // aren't in-place internalizable and are copied when internalized.
  Handle<String> young_one_byte_seq1;
  Handle<String> young_two_byte_seq1;
  Handle<String> one_byte_intern1;
  Handle<String> two_byte_intern1;
  i_isolate2->main_thread_local_isolate()->ExecuteMainThreadWhileParked([&]() {
    young_one_byte_seq1 = factory1->NewStringFromAsciiChecked(
        raw_one_byte, AllocationType::kYoung);
    young_two_byte_seq1 =
        factory1->NewStringFromTwoByte(two_byte, AllocationType::kYoung)
            .ToHandleChecked();
    one_byte_intern1 = factory1->InternalizeString(young_one_byte_seq1);
    two_byte_intern1 = factory1->InternalizeString(young_two_byte_seq1);
    CHECK(!HeapLayout::InAnySharedSpace(*young_one_byte_seq1));
    CHECK(!HeapLayout::InAnySharedSpace(*young_two_byte_seq1));
    CHECK(HeapLayout::InAnySharedSpace(*one_byte_intern1));
    CHECK(HeapLayout::InAnySharedSpace(*two_byte_intern1));
    CHECK(!young_one_byte_seq1.equals(one_byte_intern1));
    CHECK(!young_two_byte_seq1.equals(two_byte_intern1));
    CHECK_NE(*young_one_byte_seq1, *one_byte_intern1);
    CHECK_NE(*young_two_byte_seq1, *two_byte_intern1);
  });

  // Allocate two young strings with the same contents in isolate2 then intern
  // them. They should be the same as the interned strings from isolate1.
  Handle<String> young_one_byte_seq2;
  Handle<String> young_two_byte_seq2;
  Handle<String> one_byte_intern2;
  Handle<String> two_byte_intern2;
  {
    v8::Isolate::Scope isolate_scope(isolate_wrapper.isolate);
    young_one_byte_seq2 = factory2->NewStringFromAsciiChecked(
        raw_one_byte, AllocationType::kYoung);
    young_two_byte_seq2 =
        factory2->NewStringFromTwoByte(two_byte, AllocationType::kYoung)
            .ToHandleChecked();
    one_byte_intern2 = factory2->InternalizeString(young_one_byte_seq2);
    two_byte_intern2 = factory2->InternalizeString(young_two_byte_seq2);
    CHECK(!young_one_byte_seq2.equals(one_byte_intern2));
    CHECK(!young_two_byte_seq2.equals(two_byte_intern2));
    CHECK_NE(*young_one_byte_seq2, *one_byte_intern2);
    CHECK_NE(*young_two_byte_seq2, *two_byte_intern2);
    CHECK_EQ(*one_byte_intern1, *one_byte_intern2);
    CHECK_EQ(*two_byte_intern1, *two_byte_intern2);
  }
}

class ConcurrentStringThreadBase : public ParkingThread {
 public:
  ConcurrentStringThreadBase(const char* name, MultiClientIsolateTest* test,
                             IndirectHandle<FixedArray> shared_strings,
                             ParkingSemaphore* sema_ready,
                             ParkingSemaphore* sema_execute_start,
                             ParkingSemaphore* sema_execute_complete)
      : ParkingThread(base::Thread::Options(name)),
        test_(test),
        shared_strings_(shared_strings),
        sema_ready_(sema_ready),
        sema_execute_start_(sema_execute_start),
        sema_execute_complete_(sema_execute_complete) {}

  virtual void Setup() {}
  virtual void RunForString(Handle<String> string, int counter) = 0;
  virtual void Teardown() {}
  void Run() override {
    IsolateWrapper isolate_wrapper(test_->NewClientIsolate());
    i_isolate = reinterpret_cast<Isolate*>(isolate_wrapper.isolate);

    Setup();

    sema_ready_->Signal();
    sema_execute_start_->ParkedWait(i_isolate->main_thread_local_isolate());

    {
      v8::Isolate::Scope isolate_scope(isolate_wrapper.isolate);
      HandleScope scope(i_isolate);
      for (int i = 0; i < shared_strings_->length(); i++) {
        Handle<String> input_string(Cast<String>(shared_strings_->get(i)),
                                    i_isolate);
        RunForString(input_string, i);
      }
    }

    sema_execute_complete_->Signal();

    Teardown();

    i_isolate = nullptr;
  }

 protected:
  Isolate* i_isolate;
  MultiClientIsolateTest* test_;
  IndirectHandle<FixedArray> shared_strings_;
  ParkingSemaphore* sema_ready_;
  ParkingSemaphore* sema_execute_start_;
  ParkingSemaphore* sema_execute_complete_;
};

enum TestHitOrMiss { kTestMiss, kTestHit };

class ConcurrentInternalizationThread final
    : public ConcurrentStringThreadBase {
 public:
  ConcurrentInternalizationThread(MultiClientIsolateTest* test,
                                  IndirectHandle<FixedArray> shared_strings,
                                  TestHitOrMiss hit_or_miss,
                                  ParkingSemaphore* sema_ready,
                                  ParkingSemaphore* sema_execute_start,
                                  ParkingSemaphore* sema_execute_complete)
      : ConcurrentStringThreadBase("ConcurrentInternalizationThread", test,
                                   shared_strings, sema_ready,
                                   sema_execute_start, sema_execute_complete),
        hit_or_miss_(hit_or_miss) {}

  void Setup() override { factory = i_isolate->factory(); }

  void RunForString(Handle<String> input_string, int counter) override {
    CHECK(input_string->IsShared());
    Handle<String> interned = factory->InternalizeString(input_string);
    CHECK(interned->IsShared());
    CHECK(IsInternalizedString(*interned));
    if (hit_or_miss_ == kTestMiss) {
      CHECK_EQ(*input_string, *interned);
    } else {
      CHECK(input_string->HasForwardingIndex(kAcquireLoad));
      CHECK(String::Equals(i_isolate, input_string, interned));
    }
  }

 private:
  TestHitOrMiss hit_or_miss_;
  Factory* factory;
};

namespace {

std::pair<Handle<String>, MaybeHandle<String>> CreateSharedOneByteString(
    Isolate* isolate, Factory* factory, int length, bool internalize) {
  char* ascii = new char[length + 1];
  // Don't make single character strings, which will end up deduplicating to
  // an RO string and mess up the string table hit test.
  CHECK_GT(length, 1);
  for (int j = 0; j < length; j++) ascii[j] = 'a';
  ascii[length] = '\0';
  MaybeHandle<String> internalized;
  if (internalize) {
    // When testing concurrent string table hits, pre-internalize a string
    // of the same contents so all subsequent internalizations are hits.
    internalized =
        factory->InternalizeString(factory->NewStringFromAsciiChecked(ascii));
    CHECK(IsInternalizedString(*internalized.ToHandleChecked()));
  }
  Handle<String> string = String::Share(
      isolate, factory->NewStringFromAsciiChecked(ascii, AllocationType::kOld));
  delete[] ascii;
  CHECK(string->IsShared());
  string->EnsureHash();
  return std::make_pair(string, internalized);
}

IndirectHandle<FixedArray> CreateSharedOneByteStrings(
    Isolate* isolate, Factory* factory, int count, int lo_count,
    int min_length = 2, bool internalize = false) {
  IndirectHandle<FixedArray> shared_strings =
      factory->NewFixedArray(count + lo_count, AllocationType::kSharedOld);
  // Buffer to keep internalized strings alive in the current scope.
  DirectHandle<FixedArray> internalized_handles;
  if (internalize) {
    internalized_handles =
        factory->NewFixedArray(count + lo_count, AllocationType::kOld);
  }
  {
    // Create strings in their own scope to be able to delete and GC them.
    HandleScope scope(isolate);
    for (int i = 0; i < count; i++) {
      int length = i + min_length + 1;
      auto strings =
          CreateSharedOneByteString(isolate, factory, length, internalize);
      shared_strings->set(i, *strings.first);
      if (internalize) {
        internalized_handles->set(i, *strings.second.ToHandleChecked());
      }
    }
    int min_lo_length =
        isolate->heap()->MaxRegularHeapObjectSize(AllocationType::kOld) + 1;
    for (int i = 0; i < lo_count; i++) {
      int length = i + min_lo_length + 1;
      auto strings =
          CreateSharedOneByteString(isolate, factory, length, internalize);
      shared_strings->set(count + i, *strings.first);
      if (internalize) {
        internalized_handles->set(count + i, *strings.second.ToHandleChecked());
      }
    }
  }
  return shared_strings;
}

void TestConcurrentInternalization(TestHitOrMiss hit_or_miss) {
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  constexpr int kThreads = 4;
  constexpr int kStrings = 4096;
  constexpr int kLOStrings = 16;

  MultiClientIsolateTest test;
  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();

  HandleScope scope(i_isolate);

  IndirectHandle<FixedArray> shared_strings =
      CreateSharedOneByteStrings(i_isolate, factory, kStrings - kLOStrings,
                                 kLOStrings, 2, hit_or_miss == kTestHit);

  ParkingSemaphore sema_ready(0);
  ParkingSemaphore sema_execute_start(0);
  ParkingSemaphore sema_execute_complete(0);
  std::vector<std::unique_ptr<ConcurrentInternalizationThread>> threads;
  for (int i = 0; i < kThreads; i++) {
    auto thread = std::make_unique<ConcurrentInternalizationThread>(
        &test, shared_strings, hit_or_miss, &sema_ready, &sema_execute_start,
        &sema_execute_complete);
    CHECK(thread->Start());
    threads.push_back(std::move(thread));
  }

  LocalIsolate* local_isolate = i_isolate->main_thread_local_isolate();
  for (int i = 0; i < kThreads; i++) {
    sema_ready.ParkedWait(local_isolate);
  }
  for (int i = 0; i < kThreads; i++) {
    sema_execute_start.Signal();
  }
  for (int i = 0; i < kThreads; i++) {
    sema_execute_complete.ParkedWait(local_isolate);
  }

  ParkingThread::ParkedJoinAll(local_isolate, threads);
}
}  // namespace

UNINITIALIZED_TEST(ConcurrentInternalizationMiss) {
  TestConcurrentInternalization(kTestMiss);
}

UNINITIALIZED_TEST(ConcurrentInternalizationHit) {
  TestConcurrentInternalization(kTestHit);
}

class ConcurrentStringTableLookupThread final
    : public ConcurrentStringThreadBase {
 public:
  ConcurrentStringTableLookupThread(MultiClientIsolateTest* test,
                                    IndirectHandle<FixedArray> shared_strings,
                                    ParkingSemaphore* sema_ready,
                                    ParkingSemaphore* sema_execute_start,
                                    ParkingSemaphore* sema_execute_complete)
      : ConcurrentStringThreadBase("ConcurrentStringTableLookup", test,
                                   shared_strings, sema_ready,
                                   sema_execute_start, sema_execute_complete) {}

  void RunForString(Handle<String> input_string, int counter) override {
    CHECK(input_string->IsShared());
    Tagged<Object> result =
        Tagged<Object>(StringTable::TryStringToIndexOrLookupExisting(
            i_isolate, input_string->ptr()));
    if (IsString(result)) {
      Tagged<String> internalized = Cast<String>(result);
      CHECK(IsInternalizedString(internalized));
      CHECK_IMPLIES(IsInternalizedString(*input_string),
                    *input_string == internalized);
    } else {
      CHECK_EQ(Cast<Smi>(result).value(), ResultSentinel::kNotFound);
    }
  }
};

UNINITIALIZED_TEST(ConcurrentStringTableLookup) {
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  constexpr int kTotalThreads = 4;
  constexpr int kInternalizationThreads = 1;
  constexpr int kStrings = 4096;
  constexpr int kLOStrings = 16;

  MultiClientIsolateTest test;
  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();

  HandleScope scope(i_isolate);

  IndirectHandle<FixedArray> shared_strings = CreateSharedOneByteStrings(
      i_isolate, factory, kStrings - kLOStrings, kLOStrings, 2, false);

  ParkingSemaphore sema_ready(0);
  ParkingSemaphore sema_execute_start(0);
  ParkingSemaphore sema_execute_complete(0);
  std::vector<std::unique_ptr<ConcurrentStringThreadBase>> threads;
  for (int i = 0; i < kInternalizationThreads; i++) {
    auto thread = std::make_unique<ConcurrentInternalizationThread>(
        &test, shared_strings, kTestMiss, &sema_ready, &sema_execute_start,
        &sema_execute_complete);
    CHECK(thread->Start());
    threads.push_back(std::move(thread));
  }
  for (int i = 0; i < kTotalThreads - kInternalizationThreads; i++) {
    auto thread = std::make_unique<ConcurrentStringTableLookupThread>(
        &test, shared_strings, &sema_ready, &sema_execute_start,
        &sema_execute_complete);
    CHECK(thread->Start());
    threads.push_back(std::move(thread));
  }

  LocalIsolate* local_isolate = i_isolate->main_thread_local_isolate();
  for (int i = 0; i < kTotalThreads; i++) {
    sema_ready.ParkedWait(local_isolate);
  }
  for (int i = 0; i < kTotalThreads; i++) {
    sema_execute_start.Signal();
  }
  for (int i = 0; i < kTotalThreads; i++) {
    sema_execute_complete.ParkedWait(local_isolate);
  }

  ParkingThread::ParkedJoinAll(local_isolate, threads);
}

namespace {

void CheckSharedStringIsEqualCopy(DirectHandle<String> shared,
                                  DirectHandle<String> original) {
  CHECK(shared->IsShared());
  CHECK(shared->Equals(*original));
  CHECK_NE(*shared, *original);
}

Handle<String> ShareAndVerify(Isolate* isolate, Handle<String> string) {
  Handle<String> shared = String::Share(isolate, string);
  CHECK(shared->IsShared());
#ifdef VERIFY_HEAP
  Object::ObjectVerify(*shared, isolate);
  Object::ObjectVerify(*string, isolate);
#endif  // VERIFY_HEAP
  return shared;
}

class OneByteResource : public v8::String::ExternalOneByteStringResource {
 public:
  OneByteResource(const char* data, size_t length)
      : data_(data), length_(length) {}
  const char* data() const override { return data_; }
  size_t length() const override { return length_; }
  void Dispose() override {
    CHECK(!IsDisposed());
    i::DeleteArray(data_);
    data_ = nullptr;
  }
  bool IsDisposed() const { return data_ == nullptr; }

 private:
  const char* data_;
  size_t length_;
};

class TwoByteResource : public v8::String::ExternalStringResource {
 public:
  TwoByteResource(const uint16_t* data, size_t length)
      : data_(data), length_(length) {}
  const uint16_t* data() const override { return data_; }
  size_t length() const override { return length_; }
  void Dispose() override {
    i::DeleteArray(data_);
    data_ = nullptr;
  }
  bool IsDisposed() const { return data_ == nullptr; }

 private:
  const uint16_t* data_;
  size_t length_;
};

class ExternalResourceFactory {
 public:
  ~ExternalResourceFactory() {
    for (auto* res : one_byte_resources_) {
      CHECK(res->IsDisposed());
      delete res;
    }
    for (auto* res : two_byte_resources_) {
      CHECK(res->IsDisposed());
      delete res;
    }
  }
  OneByteResource* CreateOneByte(const char* data, size_t length,
                                 bool copy = true) {
    OneByteResource* res =
        new OneByteResource(copy ? i::StrDup(data) : data, length);
    Register(res);
    return res;
  }
  OneByteResource* CreateOneByte(const char* data, bool copy = true) {
    return CreateOneByte(data, strlen(data), copy);
  }
  TwoByteResource* CreateTwoByte(const uint16_t* data, size_t length,
                                 bool copy = true) {
    TwoByteResource* res = new TwoByteResource(data, length);
    Register(res);
    return res;
  }
  TwoByteResource* CreateTwoByte(base::Vector<base::uc16> vector,
                                 bool copy = true) {
    auto vec = copy ? vector.Clone() : vector;
    return CreateTwoByte(vec.begin(), vec.size(), copy);
  }
  void Register(OneByteResource* res) { one_byte_resources_.push_back(res); }
  void Register(TwoByteResource* res) { two_byte_resources_.push_back(res); }

 private:
  std::vector<OneByteResource*> one_byte_resources_;
  std::vector<TwoByteResource*> two_byte_resources_;
};

}  // namespace

UNINITIALIZED_TEST(StringShare) {
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ManualGCScope manual_gc_scope;
  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;
  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();

  HandleScope scope(i_isolate);

  // A longer string so that concatenated to itself, the result is >
  // ConsString::kMinLength.
  const char raw_one_byte[] =
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit";
  base::uc16 raw_two_byte[] = {2001, 2002, 2003};
  base::Vector<base::uc16> two_byte(raw_two_byte, 3);

  {
    // Old-generation sequential strings are shared in-place.
    Handle<String> one_byte_seq =
        factory->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
    Handle<String> two_byte_seq =
        factory->NewStringFromTwoByte(two_byte, AllocationType::kOld)
            .ToHandleChecked();
    CHECK(!one_byte_seq->IsShared());
    CHECK(!two_byte_seq->IsShared());
    DirectHandle<String> shared_one_byte =
        ShareAndVerify(i_isolate, one_byte_seq);
    DirectHandle<String> shared_two_byte =
        ShareAndVerify(i_isolate, two_byte_seq);
    CHECK_EQ(*one_byte_seq, *shared_one_byte);
    CHECK_EQ(*two_byte_seq, *shared_two_byte);
  }

  {
    // Internalized strings are always shared.
    Handle<String> one_byte_seq =
        factory->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
    Handle<String> two_byte_seq =
        factory->NewStringFromTwoByte(two_byte, AllocationType::kOld)
            .ToHandleChecked();
    CHECK(!one_byte_seq->IsShared());
    CHECK(!two_byte_seq->IsShared());
    Handle<String> one_byte_intern = factory->InternalizeString(one_byte_seq);
    Handle<String> two_byte_intern = factory->InternalizeString(two_byte_seq);
    CHECK(one_byte_intern->IsShared());
    CHECK(two_byte_intern->IsShared());
    DirectHandle<String> shared_one_byte_intern =
        ShareAndVerify(i_isolate, one_byte_intern);
    DirectHandle<String> shared_two_byte_intern =
        ShareAndVerify(i_isolate, two_byte_intern);
    CHECK_EQ(*one_byte_intern, *shared_one_byte_intern);
    CHECK_EQ(*two_byte_intern, *shared_two_byte_intern);
  }

  {
    // Old-generation external strings are shared in-place.
    Handle<String> one_byte_ext =
        factory->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
    Handle<String> two_byte_ext =
        factory->NewStringFromTwoByte(two_byte, AllocationType::kOld)
            .ToHandleChecked();
    OneByteResource* one_byte_res =
        resource_factory.CreateOneByte(raw_one_byte);
    TwoByteResource* two_byte_res = resource_factory.CreateTwoByte(two_byte);
    CHECK(one_byte_ext->MakeExternal(i_isolate, one_byte_res));
    CHECK(two_byte_ext->MakeExternal(i_isolate, two_byte_res));
    if (v8_flags.always_use_string_forwarding_table) {
      i_isolate->heap()->CollectGarbageShared(
          i_isolate->main_thread_local_heap(),
          GarbageCollectionReason::kTesting);
    }
    CHECK(IsExternalString(*one_byte_ext));
    CHECK(IsExternalString(*two_byte_ext));
    CHECK(!one_byte_ext->IsShared());
    CHECK(!two_byte_ext->IsShared());
    DirectHandle<String> shared_one_byte =
        ShareAndVerify(i_isolate, one_byte_ext);
    DirectHandle<String> shared_two_byte =
        ShareAndVerify(i_isolate, two_byte_ext);
    CHECK_EQ(*one_byte_ext, *shared_one_byte);
    CHECK_EQ(*two_byte_ext, *shared_two_byte);
  }

  // All other strings are flattened then copied if the flatten didn't already
  // create a new copy.

  if (!v8_flags.single_generation) {
    // Young strings
    Handle<String> young_one_byte_seq = factory->NewStringFromAsciiChecked(
        raw_one_byte, AllocationType::kYoung);
    Handle<String> young_two_byte_seq =
        factory->NewStringFromTwoByte(two_byte, AllocationType::kYoung)
            .ToHandleChecked();
    CHECK(HeapLayout::InYoungGeneration(*young_one_byte_seq));
    CHECK(HeapLayout::InYoungGeneration(*young_two_byte_seq));
    CHECK(!young_one_byte_seq->IsShared());
    CHECK(!young_two_byte_seq->IsShared());
    DirectHandle<String> shared_one_byte =
        ShareAndVerify(i_isolate, young_one_byte_seq);
    DirectHandle<String> shared_two_byte =
        ShareAndVerify(i_isolate, young_two_byte_seq);
    CheckSharedStringIsEqualCopy(shared_one_byte, young_one_byte_seq);
    CheckSharedStringIsEqualCopy(shared_two_byte, young_two_byte_seq);
  }

  if (!v8_flags.always_use_string_forwarding_table) {
    // Thin strings
    Handle<String> one_byte_seq1 =
        factory->NewStringFromAsciiChecked(raw_one_byte);
    Handle<String> one_byte_seq2 =
        factory->NewStringFromAsciiChecked(raw_one_byte);
    CHECK(!one_byte_seq1->IsShared());
    CHECK(!one_byte_seq2->IsShared());
    factory->InternalizeString(one_byte_seq1);
    factory->InternalizeString(one_byte_seq2);
    CHECK(StringShape(*one_byte_seq2).IsThin());
    DirectHandle<String> shared = ShareAndVerify(i_isolate, one_byte_seq2);
    CheckSharedStringIsEqualCopy(shared, one_byte_seq2);
  }

  {
    // Cons strings
    Handle<String> one_byte_seq1 =
        factory->NewStringFromAsciiChecked(raw_one_byte);
    Handle<String> one_byte_seq2 =
        factory->NewStringFromAsciiChecked(raw_one_byte);
    CHECK(!one_byte_seq1->IsShared());
    CHECK(!one_byte_seq2->IsShared());
    Handle<String> cons =
        factory->NewConsString(one_byte_seq1, one_byte_seq2).ToHandleChecked();
    CHECK(!cons->IsShared());
    CHECK(IsConsString(*cons));
    DirectHandle<String> shared = ShareAndVerify(i_isolate, cons);
    CheckSharedStringIsEqualCopy(shared, cons);
  }

  {
    // Sliced strings
    Handle<String> one_byte_seq =
        factory->NewStringFromAsciiChecked(raw_one_byte);
    CHECK(!one_byte_seq->IsShared());
    Handle<String> sliced =
        factory->NewSubString(one_byte_seq, 1, one_byte_seq->length());
    CHECK(!sliced->IsShared());
    CHECK(IsSlicedString(*sliced));
    DirectHandle<String> shared = ShareAndVerify(i_isolate, sliced);
    CheckSharedStringIsEqualCopy(shared, sliced);
  }
}

UNINITIALIZED_TEST(PromotionMarkCompact) {
  if (v8_flags.single_generation) return;

  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);

  MultiClientIsolateTest test;
  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();
  Heap* heap = i_isolate->heap();
  // Heap* shared_heap = test.i_shared_isolate()->heap();

  const char raw_one_byte[] = "foo";

  {
    HandleScope scope(i_isolate);

    // heap::SealCurrentObjects(heap);
    // heap::SealCurrentObjects(shared_heap);

    IndirectHandle<String> one_byte_seq = factory->NewStringFromAsciiChecked(
        raw_one_byte, AllocationType::kYoung);

    CHECK(String::IsInPlaceInternalizable(*one_byte_seq));
    CHECK(heap->InSpace(*one_byte_seq, NEW_SPACE));

    // 1st GC moves `one_byte_seq` to old space and 2nd GC evacuates it within
    // old space.
    heap::InvokeMajorGC(heap);
    heap::ForceEvacuationCandidate(
        i::PageMetadata::FromHeapObject(*one_byte_seq));

    {
      // We need to invoke GC without stack, otherwise no compaction is
      // performed.
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
      heap::InvokeMajorGC(heap);
    }

    // In-place-internalizable strings are promoted into the shared heap when
    // sharing.
    CHECK(heap->SharedHeapContains(*one_byte_seq));
  }
}

UNINITIALIZED_TEST(PromotionScavenge) {
  if (v8_flags.minor_ms) return;
  if (v8_flags.single_generation) return;

  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  v8_flags.shared_string
"""


```