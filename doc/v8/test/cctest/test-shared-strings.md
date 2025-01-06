Response: The user wants a summary of the C++ code file `v8/test/cctest/test-shared-strings.cc`.
This file seems to be testing the functionality of shared strings in V8, the JavaScript engine.
The code includes tests for:
- Creation and sharing of strings between different isolates.
- Internalization of strings and how it interacts with sharing.
- Concurrent access and modification of shared strings.
- Garbage collection and its effect on shared strings (promotion, transition to thin/external strings).
- External strings and their interaction with shared strings.

The user also wants a JavaScript example if the C++ code is related to JavaScript functionality. Shared strings in V8 are an internal optimization detail, not directly exposed to JavaScript. However, the effects of shared strings can be observed when comparing string equality and identity.

Let's break down the code and identify the key functionalities tested.
```javascript
// 假设我们有两个独立的 JavaScript 执行环境 (在 V8 中称为 Isolate)
// 它们共享同一个字符串表。

// 在环境 1 中创建一个字符串
const str1_env1 = "hello";

// 在环境 2 中创建一个内容相同的字符串
const str1_env2 = "hello";

// 由于字符串表共享，V8 可能会将这两个内容相同的字符串指向同一个内部表示。
// 这种情况下，比较它们的引用是否相同可能会返回 true。
// 注意：这并不是 JavaScript 规范保证的行为，而是一种 V8 的内部优化。

// 比较字符串的值（JavaScript 规范保证）
console.log(str1_env1 === str1_env2); // 输出: true

// 比较字符串的引用 (在 V8 内部，如果使用了共享字符串，可能会返回 true)
// 无法直接在 JavaScript 中获取字符串的内部引用进行比较，
// 但可以使用一些技巧，例如使用 WeakRef，虽然这也不是直接的引用比较。

// 一个更相关的例子是字符串的 "interning" (显式地将字符串放入内部表)
// 虽然 JavaScript 没有直接暴露 interning 的 API，
// 但 V8 内部对于某些字符串 (例如，字面量字符串) 会进行 interning。

const internedStr1 = "world";
const internedStr2 = "world";

// 理论上，如果 "world" 被 V8 内部 intern 了，那么 internedStr1 和 internedStr2
// 在 V8 内部可能指向同一个字符串对象。

// 再次强调，这是一种 V8 的内部优化，JavaScript 开发者通常不需要关心。
// 核心是理解 V8 如何优化内存使用，特别是对于重复出现的字符串。
```

**归纳一下`v8/test/cctest/test-shared-strings.cc` 的功能（基于提供的第 1 部分代码）：**

这个 C++ 源代码文件是 V8 JavaScript 引擎的测试套件的一部分，专门用于测试 **共享字符串 (Shared Strings)** 的功能。 其主要目的是验证在多 `Isolate` (V8 的独立执行环境) 之间，字符串对象能否被有效地共享，以减少内存占用和提高性能。

**更具体地说，该文件中的测试涵盖了以下几个方面：**

1. **基本共享机制:**  验证在启用了共享字符串表的情况下，某些类型的字符串（例如，旧生代的字面量字符串、已内部化的字符串）在不同的 `Isolate` 之间是否能够共享底层的内存表示。

2. **原地内部化 (In-Place Internalization):** 测试某些符合条件的字符串（例如，旧生代的顺序字符串）是否可以直接在共享堆中被内部化，而无需进行复制。

3. **年轻代字符串的处理:** 验证年轻代 (新生代) 的字符串在启用共享字符串表时，是否不会被直接共享，而是会在内部化时被复制到共享堆。

4. **并发访问和修改:** 通过创建多个线程，模拟并发地访问和内部化共享字符串的场景，以确保线程安全性和数据一致性。 这包括测试内部化时的 "命中 (hit)" (字符串已存在于共享表中) 和 "未命中 (miss)" (字符串需要被添加到共享表)。

5. **字符串表的查找:** 测试并发地查找共享字符串表的功能，验证查找操作的正确性和性能。

6. **字符串的 "共享" 操作 (`String::Share`)**: 显式地将一个字符串标记为共享，并验证其行为，例如是否被移动到共享堆。

7. **外部字符串 (External Strings) 的处理:** 测试外部字符串 (其内容由 C++ 代码管理) 与共享字符串机制的交互，包括共享、内部化和外部化操作。

8. **垃圾回收 (Garbage Collection) 的影响:**  验证不同类型的垃圾回收 (例如，主垃圾回收、次垃圾回收) 对共享字符串的影响，例如字符串的晋升 (promotion) 到老生代或共享堆，以及字符串在垃圾回收过程中的状态转换 (例如，从共享字符串转换为 ThinString 或 ExternalString)。

**与 JavaScript 功能的关系：**

虽然 JavaScript 代码本身无法直接控制 V8 内部的共享字符串机制，但这种优化对 JavaScript 程序的性能和内存使用有显著影响。 当多个 JavaScript 执行环境（例如，在不同的 Worker 线程或嵌入式 V8 实例中）使用相同的字符串时，共享字符串可以避免重复存储这些字符串，从而减少内存占用。

提供的 JavaScript 示例展示了即使在不同的上下文中创建了内容相同的字符串，V8 内部也可能出于优化的目的，将它们指向相同的内存地址。 然而，**这种共享是 V8 内部的行为，并非 JavaScript 规范所保证，开发者不应该依赖于这种引用相等性**。  JavaScript 的 `===` 运算符比较的是值，这是跨环境和 V8 版本都保证的行为。

总而言之，`v8/test/cctest/test-shared-strings.cc` 是 V8 引擎为了确保其内部优化机制 (共享字符串) 正确性和稳定性的关键测试文件。 这些优化虽然对 JavaScript 开发者是透明的，但对于构建高性能的 JavaScript 应用至关重要。

Prompt: 
```
这是目录为v8/test/cctest/test-shared-strings.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

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
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

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

    DirectHandle<String> one_byte_seq = factory->NewStringFromAsciiChecked(
        raw_one_byte, AllocationType::kYoung);

    CHECK(String::IsInPlaceInternalizable(*one_byte_seq));
    CHECK(heap->InSpace(*one_byte_seq, NEW_SPACE));

    for (int i = 0; i < 2; i++) {
      heap::InvokeMinorGC(heap);
    }

    // In-place-internalizable strings are promoted into the shared heap when
    // sharing.
    CHECK(heap->SharedHeapContains(*one_byte_seq));
  }
}

UNINITIALIZED_TEST(PromotionScavengeOldToShared) {
  if (v8_flags.minor_ms) {
    // Promoting from new space directly to shared heap is not implemented in
    // MinorMS.
    return;
  }
  if (v8_flags.single_generation) return;
  if (v8_flags.stress_concurrent_allocation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  MultiClientIsolateTest test;
  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();
  Heap* heap = i_isolate->heap();
  ManualGCScope manual_gc(i_isolate);

  const char raw_one_byte[] = "foo";

  {
    HandleScope scope(i_isolate);

    DirectHandle<FixedArray> old_object =
        factory->NewFixedArray(1, AllocationType::kOld);
    MemoryChunk* old_object_chunk = MemoryChunk::FromHeapObject(*old_object);
    CHECK(!old_object_chunk->InYoungGeneration());

    DirectHandle<String> one_byte_seq = factory->NewStringFromAsciiChecked(
        raw_one_byte, AllocationType::kYoung);
    CHECK(String::IsInPlaceInternalizable(*one_byte_seq));
    CHECK(MemoryChunk::FromHeapObject(*one_byte_seq)->InYoungGeneration());

    old_object->set(0, *one_byte_seq);
    ObjectSlot slot = old_object->RawFieldOfFirstElement();
    CHECK(RememberedSet<OLD_TO_NEW>::Contains(
        MutablePageMetadata::cast(
            MutablePageMetadata::cast(old_object_chunk->Metadata())),
        slot.address()));

    for (int i = 0; i < 2; i++) {
      heap::InvokeMinorGC(heap);
    }

    // In-place-internalizable strings are promoted into the shared heap when
    // sharing.
    CHECK(heap->SharedHeapContains(*one_byte_seq));

    // Since the GC promoted that string into shared heap, it also needs to
    // create an OLD_TO_SHARED slot.
    CHECK(RememberedSet<OLD_TO_SHARED>::Contains(
        MutablePageMetadata::cast(old_object_chunk->Metadata()),
        slot.address()));
  }
}

UNINITIALIZED_TEST(PromotionMarkCompactNewToShared) {
  if (v8_flags.single_generation) return;
  if (v8_flags.stress_concurrent_allocation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  v8_flags.page_promotion = false;

  MultiClientIsolateTest test;
  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();
  Heap* heap = i_isolate->heap();

  const char raw_one_byte[] = "foo";

  {
    HandleScope scope(i_isolate);

    IndirectHandle<FixedArray> old_object =
        factory->NewFixedArray(1, AllocationType::kOld);
    MemoryChunk* old_object_chunk = MemoryChunk::FromHeapObject(*old_object);
    CHECK(!old_object_chunk->InYoungGeneration());

    IndirectHandle<String> one_byte_seq = factory->NewStringFromAsciiChecked(
        raw_one_byte, AllocationType::kYoung);
    CHECK(String::IsInPlaceInternalizable(*one_byte_seq));
    CHECK(MemoryChunk::FromHeapObject(*one_byte_seq)->InYoungGeneration());

    old_object->set(0, *one_byte_seq);
    ObjectSlot slot = old_object->RawFieldOfFirstElement();
    CHECK(RememberedSet<OLD_TO_NEW>::Contains(
        MutablePageMetadata::cast(old_object_chunk->Metadata()),
        slot.address()));

    {
      // We need to invoke GC without stack, otherwise no compaction is
      // performed.
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
      heap::InvokeMajorGC(heap);
    }

    // In-place-internalizable strings are promoted into the shared heap when
    // sharing.
    CHECK(heap->SharedHeapContains(*one_byte_seq));

    // Since the GC promoted that string into shared heap, it also needs to
    // create an OLD_TO_SHARED slot.
    CHECK(RememberedSet<OLD_TO_SHARED>::Contains(
        MutablePageMetadata::cast(old_object_chunk->Metadata()),
        slot.address()));
  }
}

UNINITIALIZED_TEST(PromotionMarkCompactOldToShared) {
  if (v8_flags.stress_concurrent_allocation) return;
  if (!v8_flags.page_promotion) return;
  if (v8_flags.single_generation) {
    // String allocated in old space may be "pretenured" to the shared heap.
    return;
  }

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);

  MultiClientIsolateTest test;
  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();
  Heap* heap = i_isolate->heap();

  const char raw_one_byte[] = "foo";

  {
    HandleScope scope(i_isolate);

    IndirectHandle<FixedArray> old_object =
        factory->NewFixedArray(1, AllocationType::kOld);
    MemoryChunk* old_object_chunk = MemoryChunk::FromHeapObject(*old_object);
    CHECK(!old_object_chunk->InYoungGeneration());

    IndirectHandle<String> one_byte_seq = factory->NewStringFromAsciiChecked(
        raw_one_byte, AllocationType::kYoung);
    CHECK(String::IsInPlaceInternalizable(*one_byte_seq));
    CHECK(MemoryChunk::FromHeapObject(*one_byte_seq)->InYoungGeneration());

    DirectHandleVector<FixedArray> handles(i_isolate);
    // Fill the page and do a full GC. Page promotion should kick in and promote
    // the page as is to old space.
    heap::FillCurrentPage(heap->new_space(), &handles);
    heap::InvokeMajorGC(heap);
    // Make sure 'one_byte_seq' is in old space.
    CHECK(!MemoryChunk::FromHeapObject(*one_byte_seq)->InYoungGeneration());
    CHECK(heap->Contains(*one_byte_seq));

    old_object->set(0, *one_byte_seq);
    ObjectSlot slot = old_object->RawFieldOfFirstElement();
    CHECK(!RememberedSet<OLD_TO_NEW>::Contains(
        MutablePageMetadata::cast(old_object_chunk->Metadata()),
        slot.address()));

    heap::ForceEvacuationCandidate(PageMetadata::FromHeapObject(*one_byte_seq));
    {
      // We need to invoke GC without stack, otherwise no compaction is
      // performed.
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
      heap::InvokeMajorGC(heap);
    }

    // In-place-internalizable strings are promoted into the shared heap when
    // sharing.
    CHECK(heap->SharedHeapContains(*one_byte_seq));

    // Since the GC promoted that string into shared heap, it also needs to
    // create an OLD_TO_SHARED slot.
    CHECK(RememberedSet<OLD_TO_SHARED>::Contains(
        MutablePageMetadata::cast(old_object_chunk->Metadata()),
        slot.address()));
  }
}

UNINITIALIZED_TEST(PagePromotionRecordingOldToShared) {
  if (v8_flags.single_generation) return;
  if (v8_flags.stress_concurrent_allocation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);

  MultiClientIsolateTest test;
  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();
  Heap* heap = i_isolate->heap();

  const char raw_one_byte[] = "foo";

  {
    HandleScope scope(i_isolate);

    DirectHandle<FixedArray> young_object =
        factory->NewFixedArray(1, AllocationType::kYoung);
    CHECK(HeapLayout::InYoungGeneration(*young_object));
    Address young_object_address = young_object->address();

    DirectHandleVector<FixedArray> handles(i_isolate);
    // Make the whole page transition from new->old, getting the buffers
    // processed in the sweeper (relying on marking information) instead of
    // processing during newspace evacuation.
    heap::FillCurrentPage(heap->new_space(), &handles);

    DirectHandle<String> shared_string = factory->NewStringFromAsciiChecked(
        raw_one_byte, AllocationType::kSharedOld);
    CHECK(HeapLayout::InWritableSharedSpace(*shared_string));

    young_object->set(0, *shared_string);

    heap::EmptyNewSpaceUsingGC(heap);

    // Object should get promoted using page promotion, so address should remain
    // the same.
    CHECK(!HeapLayout::InYoungGeneration(*shared_string));
    CHECK_EQ(young_object_address, young_object->address());

    // Since the GC promoted that string into shared heap, it also needs to
    // create an OLD_TO_SHARED slot.
    ObjectSlot slot = young_object->RawFieldOfFirstElement();
    CHECK(RememberedSet<OLD_TO_SHARED>::Contains(
        MutablePageMetadata::FromHeapObject(*young_object), slot.address()));
  }
}

namespace {

void TriggerGCWithTransitions(Heap* heap) {
  v8_flags.transition_strings_during_gc_with_stack = true;
  heap::CollectSharedGarbage(heap);
  v8_flags.transition_strings_during_gc_with_stack = false;
}

}  // namespace

UNINITIALIZED_TEST(InternalizedSharedStringsTransitionDuringGC) {
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  constexpr int kStrings = 4096;
  constexpr int kLOStrings = 16;

  MultiClientIsolateTest test;
  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();

  HandleScope scope(i_isolate);

  // Run two times to test that everything is reset correctly during GC.
  for (int run = 0; run < 2; run++) {
    DirectHandle<FixedArray> shared_strings = CreateSharedOneByteStrings(
        i_isolate, factory, kStrings - kLOStrings, kLOStrings, 2, run == 0);

    // Check strings are in the forwarding table after internalization.
    for (int i = 0; i < shared_strings->length(); i++) {
      Handle<String> input_string(Cast<String>(shared_strings->get(i)),
                                  i_isolate);
      Handle<String> interned = factory->InternalizeString(input_string);
      CHECK(input_string->IsShared());
      CHECK(!IsThinString(*input_string));
      CHECK(input_string->HasForwardingIndex(kAcquireLoad));
      CHECK(String::Equals(i_isolate, input_string, interned));
    }

    // Trigger garbage collection on the shared isolate.
    TriggerGCWithTransitions(i_isolate->heap());

    // Check that GC cleared the forwarding table.
    CHECK_EQ(i_isolate->string_forwarding_table()->size(), 0);

    // Check all strings are transitioned to ThinStrings
    for (int i = 0; i < shared_strings->length(); i++) {
      DirectHandle<String> input_string(Cast<String>(shared_strings->get(i)),
                                        i_isolate);
      CHECK(IsThinString(*input_string));
    }
  }
}

UNINITIALIZED_TEST(ShareExternalString) {
  if (v8_flags.single_generation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;
  Isolate* i_isolate1 = test.i_main_isolate();
  Factory* factory1 = i_isolate1->factory();

  HandleScope handle_scope(i_isolate1);

  const char raw_one_byte[] = "external string";

  // External strings in old space can be shared in-place.
  Handle<String> one_byte =
      factory1->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
  CHECK(!one_byte->IsShared());

  OneByteResource* resource = resource_factory.CreateOneByte(raw_one_byte);
  one_byte->MakeExternal(i_isolate1, resource);
  if (v8_flags.always_use_string_forwarding_table) {
    i_isolate1->heap()->CollectGarbageShared(
        i_isolate1->main_thread_local_heap(),
        GarbageCollectionReason::kTesting);
  }
  CHECK(IsExternalString(*one_byte));
  Handle<ExternalOneByteString> one_byte_external =
      Cast<ExternalOneByteString>(one_byte);
  DirectHandle<String> shared_one_byte =
      ShareAndVerify(i_isolate1, one_byte_external);
  CHECK_EQ(*shared_one_byte, *one_byte);
}

namespace {

void CheckExternalStringResource(
    Handle<String> string, v8::String::ExternalStringResourceBase* resource) {
  const bool is_one_byte = string->IsOneByteRepresentation();
  Local<v8::String> api_string = Utils::ToLocal(string);
  v8::String::Encoding encoding;
  CHECK_EQ(resource, api_string->GetExternalStringResourceBase(&encoding));
  if (is_one_byte) {
    CHECK_EQ(encoding, v8::String::Encoding::ONE_BYTE_ENCODING);
    CHECK_EQ(resource, api_string->GetExternalOneByteStringResource());
  } else {
    CHECK(string->IsTwoByteRepresentation());
    CHECK_EQ(encoding, v8::String::Encoding::TWO_BYTE_ENCODING);
    CHECK_EQ(resource, api_string->GetExternalStringResource());
  }
}

}  // namespace

UNINITIALIZED_TEST(ExternalizeSharedString) {
  if (v8_flags.single_generation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;
  Isolate* i_isolate1 = test.i_main_isolate();
  Factory* factory1 = i_isolate1->factory();

  HandleScope handle_scope(i_isolate1);

  const char raw_one_byte[] = "external string";
  base::uc16 raw_two_byte[] = {2001, 2002, 2003};
  base::Vector<base::uc16> two_byte_vec(raw_two_byte, 3);

  Handle<String> one_byte =
      factory1->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
  Handle<String> two_byte =
      factory1->NewStringFromTwoByte(two_byte_vec, AllocationType::kOld)
          .ToHandleChecked();
  CHECK(one_byte->IsOneByteRepresentation());
  CHECK(two_byte->IsTwoByteRepresentation());
  CHECK(!one_byte->IsShared());
  CHECK(!two_byte->IsShared());

  Handle<String> shared_one_byte = ShareAndVerify(i_isolate1, one_byte);
  Handle<String> shared_two_byte = ShareAndVerify(i_isolate1, two_byte);

  OneByteResource* one_byte_res = resource_factory.CreateOneByte(raw_one_byte);
  TwoByteResource* two_byte_res = resource_factory.CreateTwoByte(two_byte_vec);
  shared_one_byte->MakeExternal(i_isolate1, one_byte_res);
  shared_two_byte->MakeExternal(i_isolate1, two_byte_res);
  CHECK(!IsExternalString(*shared_one_byte));
  CHECK(!IsExternalString(*shared_two_byte));
  CHECK(shared_one_byte->HasExternalForwardingIndex(kAcquireLoad));
  CHECK(shared_two_byte->HasExternalForwardingIndex(kAcquireLoad));

  // Check that API calls return the resource from the forwarding table.
  CheckExternalStringResource(shared_one_byte, one_byte_res);
  CheckExternalStringResource(shared_two_byte, two_byte_res);
}

UNINITIALIZED_TEST(ExternalizedSharedStringsTransitionDuringGC) {
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;

  constexpr int kStrings = 4096;
  constexpr int kLOStrings = 16;

  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();

  HandleScope scope(i_isolate);

  // Run two times to test that everything is reset correctly during GC.
  for (int run = 0; run < 2; run++) {
    DirectHandle<FixedArray> shared_strings = CreateSharedOneByteStrings(
        i_isolate, factory, kStrings - kLOStrings, kLOStrings,
        sizeof(UncachedExternalString), run == 0);

    // Check strings are in the forwarding table after internalization.
    for (int i = 0; i < shared_strings->length(); i++) {
      DirectHandle<String> input_string(Cast<String>(shared_strings->get(i)),
                                        i_isolate);
      const int length = input_string->length();
      char* buffer = new char[length + 1];
      String::WriteToFlat(*input_string, reinterpret_cast<uint8_t*>(buffer), 0,
                          length);
      OneByteResource* resource =
          resource_factory.CreateOneByte(buffer, length, false);
      CHECK(input_string->MakeExternal(i_isolate, resource));
      CHECK(input_string->IsShared());
      CHECK(!IsExternalString(*input_string));
      CHECK(input_string->HasExternalForwardingIndex(kAcquireLoad));
    }

    // Trigger garbage collection on the shared isolate.
    TriggerGCWithTransitions(i_isolate->heap());

    // Check that GC cleared the forwarding table.
    CHECK_EQ(i_isolate->string_forwarding_table()->size(), 0);

    // Check all strings are transitioned to ExternalStrings
    for (int i = 0; i < shared_strings->length(); i++) {
      DirectHandle<String> input_string(Cast<String>(shared_strings->get(i)),
                                        i_isolate);
      CHECK(IsExternalString(*input_string));
    }
  }
}

UNINITIALIZED_TEST(ExternalizeInternalizedString) {
  if (v8_flags.single_generation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;
  Isolate* i_isolate1 = test.i_main_isolate();
  Factory* factory1 = i_isolate1->factory();

  HandleScope handle_scope(i_isolate1);

  const char raw_one_byte[] = "external string";
  base::uc16 raw_two_byte[] = {2001, 2002, 2003};
  base::Vector<base::uc16> two_byte_vec(raw_two_byte, 3);

  Handle<String> one_byte =
      factory1->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
  Handle<String> two_byte =
      factory1->NewStringFromTwoByte(two_byte_vec, AllocationType::kOld)
          .ToHandleChecked();
  // Internalize copies, s.t. internalizing the original strings creates a
  // forwarding entry.
  factory1->InternalizeString(
      factory1->NewStringFromAsciiChecked(raw_one_byte));
  factory1->InternalizeString(
      factory1->NewStringFromTwoByte(two_byte_vec).ToHandleChecked());
  Handle<String> one_byte_intern = factory1->InternalizeString(one_byte);
  Handle<String> two_byte_intern = factory1->InternalizeString(two_byte);
  if (v8_flags.always_use_string_forwarding_table) {
    i_isolate1->heap()->CollectGarbageShared(
        i_isolate1->main_thread_local_heap(),
        GarbageCollectionReason::kTesting);
  }
  CHECK(IsThinString(*one_byte));
  CHECK(IsThinString(*two_byte));
  CHECK(one_byte_intern->IsOneByteRepresentation());
  CHECK(two_byte_intern->IsTwoByteRepresentation());
  CHECK(one_byte_intern->IsShared());
  CHECK(two_byte_intern->IsShared());

  uint32_t one_byte_hash = one_byte_intern->hash();
  uint32_t two_byte_hash = two_byte_intern->hash();

  OneByteResource* one_byte_res = resource_factory.CreateOneByte(raw_one_byte);
  TwoByteResource* two_byte_res = resource_factory.CreateTwoByte(two_byte_vec);
  CHECK(one_byte_intern->MakeExternal(i_isolate1, one_byte_res));
  CHECK(two_byte_intern->MakeExternal(i_isolate1, two_byte_res));
  CHECK(!IsExternalString(*one_byte_intern));
  CHECK(!IsExternalString(*two_byte_intern));
  CHECK(one_byte_intern->HasExternalForwardingIndex(kAcquireLoad));
  CHECK(two_byte_intern->HasExternalForwardingIndex(kAcquireLoad));
  // The hash of internalized strings is stored in the forwarding table.
  CHECK_EQ(one_byte_intern->hash(), one_byte_hash);
  CHECK_EQ(two_byte_intern->hash(), two_byte_hash);

  // Check that API calls return the resource from the forwarding table.
  CheckExternalStringResource(one_byte_intern, one_byte_res);
  CheckExternalStringResource(two_byte_intern, two_byte_res);
}

UNINITIALIZED_TEST(InternalizeSharedExternalString) {
  if (v8_flags.single_generation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;
  Isolate* i_isolate1 = test.i_main_isolate();
  Factory* factory1 = i_isolate1->factory();

  HandleScope handle_scope(i_isolate1);

  const char raw_one_byte[] = "external string";
  base::uc16 raw_two_byte[] = {2001, 2002, 2003};
  base::Vector<base::uc16> two_byte_vec(raw_two_byte, 3);

  Handle<String> one_byte =
      factory1->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
  Handle<String> two_byte =
      factory1->NewStringFromTwoByte(two_byte_vec, AllocationType::kOld)
          .ToHandleChecked();

  Handle<String> shared_one_byte = ShareAndVerify(i_isolate1, one_byte);
  DirectHandle<String> shared_two_byte = ShareAndVerify(i_isolate1, two_byte);

  OneByteResource* one_byte_res = resource_factory.CreateOneByte(raw_one_byte);
  TwoByteResource* two_byte_res = resource_factory.CreateTwoByte(two_byte_vec);
  CHECK(shared_one_byte->MakeExternal(i_isolate1, one_byte_res));
  CHECK(shared_two_byte->MakeExternal(i_isolate1, two_byte_res));
  CHECK(shared_one_byte->HasExternalForwardingIndex(kAcquireLoad));
  CHECK(shared_two_byte->HasExternalForwardingIndex(kAcquireLoad));

  // Trigger GC to externalize the shared string.
  TriggerGCWithTransitions(i_isolate1->heap());

  CHECK(shared_one_byte->IsShared());
  CHECK(IsExternalString(*shared_one_byte));
  CHECK(shared_two_byte->IsShared());
  CHECK(IsExternalString(*shared_two_byte));

  // Shared cached external strings are in-place internalizable.
  DirectHandle<String> one_byte_intern =
      factory1->InternalizeString(shared_one_byte);
  CHECK_EQ(*one_byte_intern, *shared_one_byte);
  CHECK(IsExternalString(*shared_one_byte));
  CHECK(IsInternalizedString(*shared_one_byte));

  // Depending on the architecture/build options the two byte string might be
  // cached or uncached.
  const bool is_uncached =
      two_byte->Size() < static_cast<int>(sizeof(ExternalString));

  if (is_uncached) {
    // Shared uncached external strings are not internalizable. A new internal
    // copy will be created.
    DirectHandle<String> two_byte_intern =
        factory1->InternalizeString(two_byte);
    CHECK_NE(*two_byte_intern, *shared_two_byte);
    CHECK(shared_two_byte->HasInternalizedForwardingIndex(kAcquireLoad));
    CHECK(IsInternalizedString(*two_byte_intern));
    CHECK(!IsExternalString(*two_byte_intern));
  } else {
    DirectHandle<String> two_byte_intern =
        factory1->InternalizeString(two_byte);
    CHECK_EQ(*two_byte_intern, *shared_two_byte);
    CHECK(IsExternalString(*shared_two_byte));
    CHECK(IsInternalizedString(*shared_two_byte));
  }

  // Another GC should create an externalized internalized string of the cached
  // (one byte) string and turn the uncached (two byte) string into a
  // ThinString, disposing the external resource.
  TriggerGCWithTransitions(i_isolate1->heap());

  CHECK_EQ(shared_one_byte->map()->instance_type(),
           InstanceType::EXTERNAL_INTERNALIZED_ONE_BYTE_STRING_TYPE);
  if (is_uncached) {
    CHECK(IsThinString(*shared_two_byte));
    CHECK(two_byte_res->IsDisposed());
  } else {
    CHECK_EQ(shared_two_byte->map()->instance_type(),
             InstanceType::EXTERNAL_INTERNALIZED_TWO_BYTE_STRING_TYPE);
  }
}

UNINITIALIZED_TEST(ExternalizeAndInternalizeMissSharedString) {
  if (v8_flags.single_generation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;
  Isolate* i_isolate1 = test.i_main_isolate();
  Factory* factory1 = i_isolate1->factory();

  HandleScope handle_scope(i_isolate1);

  const char raw_one_byte[] = "external string";

  Handle<String> one_byte =
      factory1->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
  uint32_t one_byte_hash = one_byte->EnsureHash();

  Handle<String> shared_one_byte = ShareAndVerify(i_isolate1, one_byte);

  OneByteResource* one_byte_res = resource_factory.CreateOneByte(raw_one_byte);

  CHECK(shared_one_byte->MakeExternal(i_isolate1, one_byte_res));
  CHECK(shared_one_byte->HasExternalForwardingIndex(kAcquireLoad));

  DirectHandle<String> one_byte_intern =
      factory1->InternalizeString(shared_one_byte);
  CHECK_EQ(*one_byte_intern, *shared_one_byte);
  CHECK(IsInternalizedString(*shared_one_byte));
  // Check that we have both, a forwarding index and an accessible hash.
  CHECK(shared_one_byte->HasExternalForwardingIndex(kAcquireLoad));
  CHECK(shared_one_byte->HasHashCode());
  CHECK_EQ(shared_one_byte->hash(), one_byte_hash);
}

UNINITIALIZED_TEST(InternalizeHitAndExternalizeSharedString) {
  if (v8_flags.single_generation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;
  Isolate* i_isolate1 = test.i_main_isolate();
  Factory* factory1 = i_isolate1->factory();

  HandleScope handle_scope(i_isolate1);

  const char raw_one_byte[] = "external string";
  base::uc16 raw_two_byte[] = {2001, 2002, 2003};
  base::Vector<base::uc16> two_byte_vec(raw_two_byte, 3);

  Handle<String> one_byte =
      factory1->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
  Handle<String> two_byte =
      factory1->NewStringFromTwoByte(two_byte_vec, AllocationType::kOld)
          .ToHandleChecked();
  Handle<String> shared_one_byte = ShareAndVerify(i_isolate1, one_byte);
  Handle<String> shared_two_byte = ShareAndVerify(i_isolate1, two_byte);
  // Internalize copies, s.t. internalizing the original strings creates a
  // forwarding entry.
  factory1->InternalizeString(
      factory1->NewStringFromAsciiChecked(raw_one_byte));
  factory1->InternalizeString(
      factory1->NewStringFromTwoByte(two_byte_vec).ToHandleChecked());
  DirectHandle<String> one_byte_intern =
      factory1->InternalizeString(shared_one_byte);
  DirectHandle<String> two_byte_intern =
      factory1->InternalizeString(shared_two_byte);
  CHECK_NE(*one_byte_intern, *shared_one_byte);
  CHECK_NE(*two_byte_intern, *shared_two_byte);
  CHECK(String::IsHashFieldComputed(one_byte_intern->raw_hash_field()));
  CHECK(String::IsHashFieldComputed(two_byte_intern->raw_hash_field()));
  CHECK(shared_one_byte->HasInternalizedForwardingIndex(kAcquireLoad));
  CHECK(shared_two_byte->HasInternalizedForwardingIndex(kAcquireLoad));

  OneByteResource* one_byte_res = resource_factory.CreateOneByte(raw_one_byte);
  TwoByteResource* two_byte_res = resource_factory.CreateTwoByte(two_byte_vec);
  CHECK(shared_one_byte->MakeExternal(i_isolate1, one_byte_res));
  CHECK(shared_two_byte->MakeExternal(i_isolate1, two_byte_res));
  CHECK(shared_one_byte->HasExternalForwardingIndex(kAcquireLoad));
  CHECK(shared_two_byte->HasExternalForwardingIndex(kAcquireLoad));
  CHECK(shared_one_byte->HasInternalizedForwardingIndex(kAcquireLoad));
  CHECK(shared_two_byte->HasInternalizedForwardingIndex(kAcquireLoad));

  // Check that API calls return the resource from the forwarding table.
  CheckExternalStringResource(shared_one_byte, one_byte_res);
  CheckExternalStringResource(shared_two_byte, two_byte_res);
}

UNINITIALIZED_TEST(InternalizeMissAndExternalizeSharedString) {
  if (v8_flags.single_generation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;
  Isolate* i_isolate1 = test.i_main_isolate();
  Factory* factory1 = i_isolate1->factory();

  HandleScope handle_scope(i_isolate1);

  const char raw_one_byte[] = "external string";
  base::uc16 raw_two_byte[] = {2001, 2002, 2003};
  base::Vector<base::uc16> two_byte_vec(raw_two_byte, 3);

  Handle<String> one_byte =
      factory1->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
  Handle<String> two_byte =
      factory1->NewStringFromTwoByte(two_byte_vec, AllocationType::kOld)
          .ToHandleChecked();
  Handle<String> shared_one_byte = ShareAndVerify(i_isolate1, one_byte);
  Handle<String> shared_two_byte = ShareAndVerify(i_isolate1, two_byte);
  DirectHandle<String> one_byte_intern =
      factory1->InternalizeString(shared_one_byte);
  DirectHandle<String> two_byte_intern =
      factory1->InternalizeString(shared_two_byte);
  CHECK_EQ(*one_byte_intern, *shared_one_byte);
  CHECK_EQ(*two_byte_intern, *shared_two_byte);
  CHECK(!shared_one_byte->HasInternalizedForwardingIndex(kAcquireLoad));
  CHECK(!shared_two_byte->HasInternalizedForwardingIndex(kAcquireLoad));

  OneByteResource* one_byte_res = resource_factory.CreateOneByte(raw_one_byte);
  TwoByteResource* two_byte_res = resource_factory.CreateTwoByte(two_byte_vec);
  CHECK(shared_one_byte->MakeExternal(i_isolate1, one_byte_res));
  CHECK(shared_two_byte->MakeExternal(i_isolate1, two_byte_res));
  CHECK(shared_one_byte->HasExternalForwardingIndex(kAcquireLoad));
  CHECK(shared_two_byte->HasExternalForwardingIndex(kAcquireLoad));
  CHECK(one_byte_intern->HasExternalForwardingIndex(kAcquireLoad));
  CHECK(two_byte_intern->HasExternalForwardingIndex(kAcquireLoad));

  // Check that API calls return the resource from the forwarding table.
  CheckExternalStringResource(shared_one_byte, one_byte_res);
  CheckExternalStringResource(shared_two_byte, two_byte_res);
}

class ConcurrentExternalizationThread final
    : public ConcurrentStringThreadBase {
 public:
  ConcurrentExternalizationThread(MultiClientIsolateTest* test,
                                  IndirectHandle<FixedArray> shared_strings,
                                  std::vector<OneByteResource*> resources,
                                  bool share_resources,
                                  ParkingSemaphore* sema_ready,
                                  ParkingSemaphore* sema_execute_start,
                                  ParkingSemaphore* sema_execute_complete)
      : ConcurrentStringThreadBase("ConcurrentExternalizationThread", test,
                                   shared_strings, sema_ready,
                                   sema_execute_start, sema_execute_complete),
        resources_(resources),
        share_resources_(share_resources) {}

  void RunForString(Handle<String> input_string, int counter) override {
    CHECK(input_string->IsShared());
    OneByteResource* resource = Resource(counter);
    if (!input_string->MakeExternal(i_isolate, resource)) {
      if (!share_resources_) {
        resource->Unaccount(reinterpret_cast<v8::Isolate*>(i_isolate));
        resource->Dispose();
      }
    }
    CHECK(input_string->HasForwardingIndex(kAcquireLoad));
  }

  OneByteResource* Resource(int index) const { return resources_[index]; }

 private:
  std::vector<OneByteResource*> resources_;
  const bool share_resources_;
};

namespace {

void CreateExternalResources(Isolate* i_isolate,
                             DirectHandle<FixedArray> strings,
                             std::vector<OneByteResource*>& resources,
                             ExternalResourceFactory& resource_factory) {
  HandleScope scope(i_isolate);
  resources.reserve(strings->length());
  for (int i = 0; i < strings->length(); i++) {
    DirectHandle<String> input_string(Cast<String>(strings->get(i)), i_isolate);
    CHECK(Utils::ToLocal(input_string)
              ->CanMakeExternal(v8::String::Encoding::ONE_BYTE_ENCODING));
    const int length = input_string->length();
    char* buffer = new char[length + 1];
    String::WriteToFlat(*input_string, reinterpret_cast<uint8_t*>(buffer), 0,
                        length);
    resources.push_back(resource_factory.CreateOneByte(buffer, length, false));
  }
}

void CheckStringAndResource(
    Tagged<String> string, int index, bool should_be_alive,
    Tagged<String> deleted_string, bool check_transition, bool shared_resources,
    const std::vector<std::unique_ptr<ConcurrentExternalizationThread>>&
        threads) {
  if (check_transition) {
    if (should_be_alive) {
      CHECK(IsExternalString(string));
    } else {
      CHECK_EQ(string, deleted_string);
    }
  }
  int alive_resources = 0;
  for (size_t t = 0; t < threads.size(); t++) {
    ConcurrentExternalizationThread* thread = threads[t].get();
    if (!thread->Resource(index)->IsDisposed()) {
      alive_resources++;
    }
  }

  // Check exact alive resources only if the string has transitioned, otherwise
  // there can still be multiple resource instances in the forwarding table.
  // Only check no resource is alive if the string is dead.
  const bool check_alive = check_transition || !should_be_alive;
  if (check_alive) {
    size_t expected_alive;
    if (should_be_alive) {
      if (shared_resources) {
        // Since we share the same resource for all threads, we accounted for it
        // in every thread.
        expected_alive = threads.size();
      } else {
        // Check that exactly one resource is alive.
        expected_ali
"""


```