Response: Let's break down the thought process for analyzing this C++ unit test file and explaining its relationship to JavaScript.

**1. Understanding the Goal:**

The request asks for two main things:
    * **Summarize the functionality:** What does this C++ code *do*?
    * **Relate to JavaScript (if applicable):** How does this C++ code connect to how JavaScript works? Provide a JavaScript example.

**2. Initial Scan and Keyword Identification:**

I start by quickly scanning the code for key terms and patterns. I'm looking for things like:

* `#include`:  These tell me what libraries are being used (cppgc, gtest). `cppgc` is a big clue – it's the garbage collection library.
* `namespace cppgc`: This confirms the code is part of the `cppgc` library.
* `struct`, `class`:  These define data structures. I look for names like `GCed`, `Member`, `WeakMember`, `UntracedMember`. These seem to be related to garbage collection and different kinds of references.
* `TEST_F`: This signals the use of Google Test, indicating this is a unit test file.
* `static_assert`: These are compile-time checks, confirming assumptions about the types.
* `Trace`: This method is a standard part of garbage collection – it's how the GC knows what objects an object refers to.
* `Get()`, `Release()`, `Clear()`, `Swap()`: These look like methods for managing the `Member` types.
* `PreciseGC()`, `ConservativeGC()`: These are explicit calls to the garbage collector.

**3. Deeper Dive into Key Structures:**

I focus on the core types: `Member`, `WeakMember`, and `UntracedMember`. The static asserts give me a lot of information:

* `Member` is always strong (it keeps the referenced object alive).
* `WeakMember` is always weak (it doesn't prevent the object from being garbage collected).
* `UntracedMember` is like a regular pointer – the GC doesn't track it.

The code also defines traits (`IsMemberTypeV`, `IsWeakMemberTypeV`, etc.) to check the type of these members at compile time. This is for ensuring correct usage.

**4. Analyzing the Tests:**

The `TEST_F` macros indicate individual test cases. I look for the patterns in these tests:

* **`EmptyTest`:** Tests default construction and null assignment.
* **`AtomicCtorTest`:** Tests constructing members with an "atomic" flag (likely related to thread safety).
* **`ClearTest`:** Tests setting the member to null.
* **`ReleaseTest`:** Tests getting the raw pointer and clearing the member.
* **`SwapTest`:** Tests swapping the contents of two members.
* **`MoveTest`:** Tests move construction and assignment.
* **`HeterogeneousConversionTest`:** Tests assigning between different member types (e.g., `Member<Derived>` to `Member<Base>`).
* **`PersistentConversionTest`:** Tests conversions involving `Persistent` and `WeakPersistent`.
* **`EqualityTest`:** Tests equality comparisons.
* **`WriteBarrierTriggered`:** This test is interesting. It shows how assignments to `Member` might trigger "write barriers," which are important for garbage collection correctness.
* **`CheckingPolicy`:**  Demonstrates a custom policy for checking pointer validity.
* **`MemberHeapTest` and `WeakMemberDoesNotRetainObject`:** These tests demonstrate the core difference between `Member` (keeps the object alive) and `WeakMember` (doesn't).

**5. Connecting to JavaScript:**

This is where the core understanding of garbage collection comes in. I know that JavaScript has automatic garbage collection. The concepts of "strong references" and "weak references" are fundamental.

* **`Member` is like a regular JavaScript variable holding an object:** If a JavaScript variable points to an object, that object won't be garbage collected.
* **`WeakMember` is like a `WeakRef` in JavaScript:**  A `WeakRef` allows you to hold a reference to an object without preventing it from being garbage collected. You need to check if the reference is still valid before using it.
* **`UntracedMember` is like a raw pointer in C++ or a plain number/string in JavaScript:** The garbage collector doesn't track these. If the only thing pointing to an object is an `UntracedMember` (or nothing points to it at all in JavaScript), it can be garbage collected.

**6. Constructing the JavaScript Example:**

Based on the analogy above, I create a simple JavaScript example that demonstrates the behavior of strong and weak references:

```javascript
// Simulating a 'strong' reference (like Member in C++)
let strongReference = { data: "I'm important!" };

// The object will NOT be garbage collected as long as strongReference exists.

// Simulating a 'weak' reference (like WeakMember in C++)
const weakReference = new WeakRef({ data: "I might disappear!" });

// The object referenced by weakReference CAN be garbage collected.

// Later, you need to check if the weak reference is still valid:
const dereferenced = weakReference.deref();
if (dereferenced) {
  console.log("Weak reference is still valid:", dereferenced.data);
} else {
  console.log("Weak reference has been garbage collected.");
}

// If we set strongReference to null, the first object becomes eligible for GC.
strongReference = null;
```

**7. Refining the Explanation:**

Finally, I organize the findings into a clear and concise explanation, highlighting:

* The purpose of the C++ file (testing `Member`, `WeakMember`, etc.).
* The core concepts being tested (strong vs. weak references, construction, assignment, etc.).
* The analogy to JavaScript's garbage collection and `WeakRef`.
* The JavaScript code example to illustrate the connection.

This structured approach, moving from a general understanding to specific details and then drawing parallels to JavaScript, allows for a comprehensive and informative answer.
这个C++源代码文件 `member-unittest.cc` 的主要功能是 **测试 `cppgc` 库中与成员指针相关的类，如 `Member`、`WeakMember` 和 `UntracedMember`。**

更具体地说，它通过一系列单元测试来验证这些成员指针类型的以下特性：

1. **类型特性 (Type Traits):**
   - 验证 `Member` 是否总是强引用。
   - 验证 `WeakMember` 是否总是弱引用。
   - 验证不同成员类型 (如 `Member`, `WeakMember`, `UntracedMember`) 的类型判断 (`IsMemberTypeV`, `IsWeakMemberTypeV`, `IsUntracedMemberTypeV`, `IsAnyMemberTypeV`) 是否正确。

2. **构造和赋值:**
   - 测试默认构造、nullptr 构造、拷贝构造、移动构造、赋值运算符等。
   - 测试从原始指针构造和赋值。
   - 测试从 `Persistent` 和 `WeakPersistent` 指针构造和赋值。
   - 测试原子构造 (`AtomicInitializerTag`)。

3. **基本操作:**
   - 测试 `Get()` 获取原始指针。
   - 测试 `Release()` 释放原始指针并清空 `Member`。
   - 测试 `Clear()` 清空 `Member`。
   - 测试 `Swap()` 交换两个 `Member` 对象的内容。

4. **异构转换 (Heterogeneous Conversion):**
   - 测试不同 `Member` 类型之间的隐式转换 (例如，从 `Member<Derived>` 转换为 `Member<Base>`).

5. **比较操作:**
   - 测试 `==` 和 `!=` 运算符的正确性，包括与原始指针的比较。

6. **写屏障 (Write Barrier):**
   - 测试在赋值时是否触发了自定义的写屏障策略。这对于垃圾回收器跟踪对象引用至关重要。

7. **检查策略 (Checking Policy):**
   - 测试在访问 `Member` 指针时是否应用了自定义的检查策略，例如验证指针是否指向已知的有效对象。

8. **内存管理行为:**
   - **`Member` 的保留行为:** 测试 `Member` 是否会阻止其指向的对象被垃圾回收。
   - **`WeakMember` 的非保留行为:** 测试 `WeakMember` 是否不会阻止其指向的对象被垃圾回收。
   - 测试 `const WeakMember` 在指向的对象被回收后是否会被清除。

9. **安全性检查 (仅在 `V8_ENABLE_CHECKS` 开启时):**
   - 测试在尝试将堆外或栈上的对象赋值给 `Member` 时是否会触发断言或崩溃，以防止内存安全问题。

10. **指针压缩 (仅在 `CPPGC_POINTER_COMPRESSION` 开启时):**
    - 测试 `CompressedPointer` 与 `Member` 之间的存储和加载操作。

**与 JavaScript 的关系：**

这个 C++ 代码文件是 V8 引擎的一部分，V8 是 Google Chrome 和 Node.js 使用的 JavaScript 引擎。 `cppgc` 是 V8 中用于 C++ 对象的垃圾回收机制。

`Member`、`WeakMember` 和 `UntracedMember` 这些类对应了 JavaScript 中对象引用的不同方式：

* **`Member<T>` 类似于 JavaScript 中的普通对象引用 (强引用):**  当一个 JavaScript 变量引用一个对象时，只要该变量存在，该对象就不会被垃圾回收。`Member` 在 C++ 中也是如此，它持有一个对垃圾回收对象的强引用，确保该对象在 `Member` 对象存活期间不会被回收。

* **`WeakMember<T>` 类似于 JavaScript 中的 `WeakRef` (弱引用):**  `WeakRef` 允许你持有对对象的引用，但不会阻止该对象被垃圾回收。当对象只剩下弱引用时，垃圾回收器可以回收该对象，并且 `WeakRef` 会变得无效。`WeakMember` 在 C++ 中也提供了类似的功能。

* **`UntracedMember<T>` 类似于 JavaScript 中直接存储的值类型 (如数字、字符串) 或对非垃圾回收对象的指针:**  垃圾回收器不会追踪 `UntracedMember` 指向的对象。这通常用于指向不归垃圾回收器管理的 C++ 对象或需要手动管理生命周期的场景。

**JavaScript 示例：**

```javascript
// 类似于 C++ 中的 Member<MyObject>
let strongReference = { data: "这是一个对象" };

// 只要 strongReference 存在，这个对象就不会被垃圾回收。

// 类似于 C++ 中的 WeakMember<MyObject>
const weakReference = new WeakRef({ data: "我可能被回收" });

// 对象 `{ data: "我可能被回收" }` 可以被垃圾回收，即使 weakReference 存在。

// 你需要显式地检查弱引用是否仍然有效：
const dereferenced = weakReference.deref();
if (dereferenced) {
  console.log("弱引用仍然有效:", dereferenced.data);
} else {
  console.log("弱引用已被回收。");
}

// 类似于 C++ 中的 UntracedMember<SomeNonGCObject> 或直接存储的值
let primitiveValue = 123;
let externalObjectPointer = // ... 指向一个非垃圾回收的 C++ 对象
```

**总结:**

`member-unittest.cc` 通过详细的单元测试确保了 V8 引擎中用于管理垃圾回收对象引用的核心 C++ 类型 `Member`、`WeakMember` 和 `UntracedMember` 的功能正确性和内存安全性。这些 C++ 类型的设计直接影响了 JavaScript 引擎的垃圾回收行为和对象管理方式。

Prompt: 
```
这是目录为v8/test/unittests/heap/cppgc/member-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "include/cppgc/member.h"

#include <algorithm>
#include <vector>

#include "include/cppgc/allocation.h"
#include "include/cppgc/garbage-collected.h"
#include "include/cppgc/internal/member-storage.h"
#include "include/cppgc/internal/pointer-policies.h"
#include "include/cppgc/persistent.h"
#include "include/cppgc/sentinel-pointer.h"
#include "include/cppgc/type-traits.h"
#include "test/unittests/heap/cppgc/tests.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace cppgc {
namespace internal {

namespace {

struct GCed : GarbageCollected<GCed> {
  double d;
  virtual void Trace(cppgc::Visitor*) const {}
};

struct DerivedMixin : GarbageCollectedMixin {
  void Trace(cppgc::Visitor* v) const override {}
};

struct DerivedGCed : GCed, DerivedMixin {
  void Trace(cppgc::Visitor* v) const override { GCed::Trace(v); }
};

// Compile tests.
static_assert(!IsWeakV<Member<GCed>>, "Member is always strong.");
static_assert(IsWeakV<WeakMember<GCed>>, "WeakMember is always weak.");

static_assert(IsMemberTypeV<Member<GCed>>, "Member must be Member.");
static_assert(IsMemberTypeV<const Member<GCed>>,
              "const Member must be Member.");
static_assert(IsMemberTypeV<const Member<GCed>&>,
              "const Member ref must be Member.");
static_assert(!IsMemberTypeV<WeakMember<GCed>>,
              "WeakMember must not be Member.");
static_assert(!IsMemberTypeV<UntracedMember<GCed>>,
              "UntracedMember must not be Member.");
static_assert(!IsMemberTypeV<int>, "int must not be Member.");
static_assert(!IsWeakMemberTypeV<Member<GCed>>,
              "Member must not be WeakMember.");
static_assert(IsWeakMemberTypeV<WeakMember<GCed>>,
              "WeakMember must be WeakMember.");
static_assert(!IsWeakMemberTypeV<UntracedMember<GCed>>,
              "UntracedMember must not be WeakMember.");
static_assert(!IsWeakMemberTypeV<int>, "int must not be WeakMember.");
static_assert(!IsUntracedMemberTypeV<Member<GCed>>,
              "Member must not be UntracedMember.");
static_assert(!IsUntracedMemberTypeV<WeakMember<GCed>>,
              "WeakMember must not be UntracedMember.");
static_assert(IsUntracedMemberTypeV<UntracedMember<GCed>>,
              "UntracedMember must be UntracedMember.");
static_assert(!IsUntracedMemberTypeV<int>, "int must not be UntracedMember.");
static_assert(IsMemberOrWeakMemberTypeV<Member<GCed>>,
              "Member must be Member.");
static_assert(IsMemberOrWeakMemberTypeV<WeakMember<GCed>>,
              "WeakMember must be WeakMember.");
static_assert(!IsMemberOrWeakMemberTypeV<UntracedMember<GCed>>,
              "UntracedMember is neither Member nor WeakMember.");
static_assert(!IsMemberOrWeakMemberTypeV<int>,
              "int is neither Member nor WeakMember.");
static_assert(IsAnyMemberTypeV<Member<GCed>>, "Member must be a member type.");
static_assert(IsAnyMemberTypeV<WeakMember<GCed>>,
              "WeakMember must be a member type.");
static_assert(IsAnyMemberTypeV<UntracedMember<GCed>>,
              "UntracedMember must be a member type.");
static_assert(!IsAnyMemberTypeV<int>, "int must not be a member type.");
static_assert(
    IsAnyMemberTypeV<
        internal::BasicMember<GCed, class SomeTag, NoWriteBarrierPolicy,
                              DefaultMemberCheckingPolicy, RawPointer>>,
    "Any custom member must be a member type.");

struct CustomWriteBarrierPolicy {
  static size_t InitializingWriteBarriersTriggered;
  static size_t AssigningWriteBarriersTriggered;
  static void InitializingBarrier(const void* slot, const void* value) {
    ++InitializingWriteBarriersTriggered;
  }
  template <WriteBarrierSlotType>
  static void AssigningBarrier(const void* slot, const void* value) {
    ++AssigningWriteBarriersTriggered;
  }
  template <WriteBarrierSlotType>
  static void AssigningBarrier(const void* slot, DefaultMemberStorage) {
    ++AssigningWriteBarriersTriggered;
  }
};
size_t CustomWriteBarrierPolicy::InitializingWriteBarriersTriggered = 0;
size_t CustomWriteBarrierPolicy::AssigningWriteBarriersTriggered = 0;

using MemberWithCustomBarrier =
    BasicMember<GCed, StrongMemberTag, CustomWriteBarrierPolicy>;

struct CustomCheckingPolicy {
  static std::vector<GCed*> Cached;
  static size_t ChecksTriggered;
  template <typename T>
  void CheckPointer(RawPointer raw_pointer) {
    const void* ptr = raw_pointer.Load();
    CheckPointer(static_cast<const T*>(ptr));
  }
#if defined(CPPGC_POINTER_COMPRESSION)
  template <typename T>
  void CheckPointer(CompressedPointer compressed_pointer) {
    const void* ptr = compressed_pointer.Load();
    CheckPointer(static_cast<const T*>(ptr));
  }
#endif
  template <typename T>
  void CheckPointer(const T* ptr) {
    EXPECT_NE(Cached.cend(), std::find(Cached.cbegin(), Cached.cend(), ptr));
    ++ChecksTriggered;
  }
};
std::vector<GCed*> CustomCheckingPolicy::Cached;
size_t CustomCheckingPolicy::ChecksTriggered = 0;

using MemberWithCustomChecking =
    BasicMember<GCed, StrongMemberTag, DijkstraWriteBarrierPolicy,
                CustomCheckingPolicy>;

class MemberTest : public testing::TestSupportingAllocationOnly {};

}  // namespace

template <template <typename> class MemberType>
void EmptyTest() {
  {
    MemberType<GCed> empty;
    EXPECT_EQ(nullptr, empty.Get());
    EXPECT_EQ(nullptr, empty.Release());
  }
  {
    MemberType<GCed> empty = nullptr;
    EXPECT_EQ(nullptr, empty.Get());
    EXPECT_EQ(nullptr, empty.Release());
  }
  {
    // Move-constructs empty from another Member that is created from nullptr.
    MemberType<const GCed> empty = nullptr;
    EXPECT_EQ(nullptr, empty.Get());
    EXPECT_EQ(nullptr, empty.Release());
  }
}

TEST_F(MemberTest, Empty) {
  EmptyTest<Member>();
  EmptyTest<WeakMember>();
  EmptyTest<UntracedMember>();
}

template <template <typename> class MemberType>
void AtomicCtorTest(cppgc::Heap* heap) {
  {
    GCed* gced = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    MemberType<GCed> member(gced,
                            typename MemberType<GCed>::AtomicInitializerTag());
    EXPECT_EQ(gced, member.Get());
  }
  {
    GCed* gced = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    MemberType<GCed> member(*gced,
                            typename MemberType<GCed>::AtomicInitializerTag());
    EXPECT_EQ(gced, member.Get());
  }
  {
    MemberType<GCed> member(nullptr,
                            typename MemberType<GCed>::AtomicInitializerTag());
    EXPECT_FALSE(member.Get());
  }
  {
    SentinelPointer s;
    MemberType<GCed> member(s,
                            typename MemberType<GCed>::AtomicInitializerTag());
    EXPECT_EQ(s, member.Get());
  }
}

TEST_F(MemberTest, AtomicCtor) {
  cppgc::Heap* heap = GetHeap();
  AtomicCtorTest<Member>(heap);
  AtomicCtorTest<WeakMember>(heap);
  AtomicCtorTest<UntracedMember>(heap);
}

template <template <typename> class MemberType>
void ClearTest(cppgc::Heap* heap) {
  MemberType<GCed> member =
      MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
  EXPECT_NE(nullptr, member.Get());
  member.Clear();
  EXPECT_EQ(nullptr, member.Get());
}

TEST_F(MemberTest, Clear) {
  cppgc::Heap* heap = GetHeap();
  ClearTest<Member>(heap);
  ClearTest<WeakMember>(heap);
  ClearTest<UntracedMember>(heap);
}

template <template <typename> class MemberType>
void ReleaseTest(cppgc::Heap* heap) {
  GCed* gced = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
  MemberType<GCed> member = gced;
  EXPECT_NE(nullptr, member.Get());
  GCed* raw = member.Release();
  EXPECT_EQ(gced, raw);
  EXPECT_EQ(nullptr, member.Get());
}

TEST_F(MemberTest, Release) {
  cppgc::Heap* heap = GetHeap();
  ReleaseTest<Member>(heap);
  ReleaseTest<WeakMember>(heap);
  ReleaseTest<UntracedMember>(heap);
}

template <template <typename> class MemberType1,
          template <typename> class MemberType2>
void SwapTest(cppgc::Heap* heap) {
  GCed* gced1 = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
  GCed* gced2 = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
  MemberType1<GCed> member1 = gced1;
  MemberType2<GCed> member2 = gced2;
  EXPECT_EQ(gced1, member1.Get());
  EXPECT_EQ(gced2, member2.Get());
  member1.Swap(member2);
  EXPECT_EQ(gced2, member1.Get());
  EXPECT_EQ(gced1, member2.Get());
}

TEST_F(MemberTest, Swap) {
  cppgc::Heap* heap = GetHeap();
  SwapTest<Member, Member>(heap);
  SwapTest<Member, WeakMember>(heap);
  SwapTest<Member, UntracedMember>(heap);
  SwapTest<WeakMember, Member>(heap);
  SwapTest<WeakMember, WeakMember>(heap);
  SwapTest<WeakMember, UntracedMember>(heap);
  SwapTest<UntracedMember, Member>(heap);
  SwapTest<UntracedMember, WeakMember>(heap);
  SwapTest<UntracedMember, UntracedMember>(heap);
}

template <template <typename> class MemberType1,
          template <typename> class MemberType2>
void MoveTest(cppgc::Heap* heap) {
  {
    GCed* gced1 = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    MemberType1<GCed> member1 = gced1;
    MemberType2<GCed> member2(std::move(member1));
    // Move-from member must be in empty state.
    EXPECT_FALSE(member1);
    EXPECT_EQ(gced1, member2.Get());
  }
  {
    GCed* gced1 = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    MemberType1<GCed> member1 = gced1;
    MemberType2<GCed> member2;
    member2 = std::move(member1);
    // Move-from member must be in empty state.
    EXPECT_FALSE(member1);
    EXPECT_EQ(gced1, member2.Get());
  }
}

TEST_F(MemberTest, Move) {
  cppgc::Heap* heap = GetHeap();
  MoveTest<Member, Member>(heap);
  MoveTest<Member, WeakMember>(heap);
  MoveTest<Member, UntracedMember>(heap);
  MoveTest<WeakMember, Member>(heap);
  MoveTest<WeakMember, WeakMember>(heap);
  MoveTest<WeakMember, UntracedMember>(heap);
  MoveTest<UntracedMember, Member>(heap);
  MoveTest<UntracedMember, WeakMember>(heap);
  MoveTest<UntracedMember, UntracedMember>(heap);
}

template <template <typename> class MemberType1,
          template <typename> class MemberType2>
void HeterogeneousConversionTest(cppgc::Heap* heap) {
  {
    MemberType1<GCed> member1 =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    MemberType2<GCed> member2 = member1;
    EXPECT_EQ(member1.Get(), member2.Get());
  }
  {
    MemberType1<DerivedGCed> member1 =
        MakeGarbageCollected<DerivedGCed>(heap->GetAllocationHandle());
    MemberType2<GCed> member2 = member1;
    EXPECT_EQ(member1.Get(), member2.Get());
  }
  {
    MemberType1<GCed> member1 =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    MemberType2<GCed> member2;
    member2 = member1;
    EXPECT_EQ(member1.Get(), member2.Get());
  }
  {
    MemberType1<DerivedGCed> member1 =
        MakeGarbageCollected<DerivedGCed>(heap->GetAllocationHandle());
    MemberType2<GCed> member2;
    member2 = member1;
    EXPECT_EQ(member1.Get(), member2.Get());
  }
}

TEST_F(MemberTest, HeterogeneousInterface) {
  cppgc::Heap* heap = GetHeap();
  HeterogeneousConversionTest<Member, Member>(heap);
  HeterogeneousConversionTest<Member, WeakMember>(heap);
  HeterogeneousConversionTest<Member, UntracedMember>(heap);
  HeterogeneousConversionTest<WeakMember, Member>(heap);
  HeterogeneousConversionTest<WeakMember, WeakMember>(heap);
  HeterogeneousConversionTest<WeakMember, UntracedMember>(heap);
  HeterogeneousConversionTest<UntracedMember, Member>(heap);
  HeterogeneousConversionTest<UntracedMember, WeakMember>(heap);
  HeterogeneousConversionTest<UntracedMember, UntracedMember>(heap);
}

template <template <typename> class MemberType,
          template <typename> class PersistentType>
void PersistentConversionTest(cppgc::Heap* heap) {
  {
    PersistentType<GCed> persistent =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    MemberType<GCed> member = persistent;
    EXPECT_EQ(persistent.Get(), member.Get());
  }
  {
    PersistentType<DerivedGCed> persistent =
        MakeGarbageCollected<DerivedGCed>(heap->GetAllocationHandle());
    MemberType<GCed> member = persistent;
    EXPECT_EQ(persistent.Get(), member.Get());
  }
  {
    PersistentType<GCed> persistent =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    MemberType<GCed> member;
    member = persistent;
    EXPECT_EQ(persistent.Get(), member.Get());
  }
  {
    PersistentType<DerivedGCed> persistent =
        MakeGarbageCollected<DerivedGCed>(heap->GetAllocationHandle());
    MemberType<GCed> member;
    member = persistent;
    EXPECT_EQ(persistent.Get(), member.Get());
  }
}

TEST_F(MemberTest, PersistentConversion) {
  cppgc::Heap* heap = GetHeap();
  PersistentConversionTest<Member, Persistent>(heap);
  PersistentConversionTest<Member, WeakPersistent>(heap);
  PersistentConversionTest<WeakMember, Persistent>(heap);
  PersistentConversionTest<WeakMember, WeakPersistent>(heap);
  PersistentConversionTest<UntracedMember, Persistent>(heap);
  PersistentConversionTest<UntracedMember, WeakPersistent>(heap);
}

template <template <typename> class MemberType1,
          template <typename> class MemberType2>
void EqualityTest(cppgc::Heap* heap) {
  {
    GCed* gced = MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    MemberType1<GCed> member1 = gced;
    MemberType2<GCed> member2 = gced;
    EXPECT_TRUE(member1 == member2);
    EXPECT_TRUE(member1 == gced);
    EXPECT_TRUE(member2 == gced);
    EXPECT_FALSE(member1 != member2);
    EXPECT_FALSE(member1 != gced);
    EXPECT_FALSE(member2 != gced);

    member2 = member1;
    EXPECT_TRUE(member1 == member2);
    EXPECT_TRUE(member1 == gced);
    EXPECT_TRUE(member2 == gced);
    EXPECT_FALSE(member1 != member2);
    EXPECT_FALSE(member1 != gced);
    EXPECT_FALSE(member2 != gced);
  }
  {
    MemberType1<GCed> member1 =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    MemberType2<GCed> member2 =
        MakeGarbageCollected<GCed>(heap->GetAllocationHandle());
    EXPECT_TRUE(member1 != member2);
    EXPECT_TRUE(member1 != member2.Get());
    EXPECT_FALSE(member1 == member2);
    EXPECT_FALSE(member1 == member2.Get());
  }
}

TEST_F(MemberTest, EqualityTest) {
  cppgc::Heap* heap = GetHeap();
  EqualityTest<Member, Member>(heap);
  EqualityTest<Member, WeakMember>(heap);
  EqualityTest<Member, UntracedMember>(heap);
  EqualityTest<WeakMember, Member>(heap);
  EqualityTest<WeakMember, WeakMember>(heap);
  EqualityTest<WeakMember, UntracedMember>(heap);
  EqualityTest<UntracedMember, Member>(heap);
  EqualityTest<UntracedMember, WeakMember>(heap);
  EqualityTest<UntracedMember, UntracedMember>(heap);
}

TEST_F(MemberTest, HeterogeneousEqualityTest) {
  cppgc::Heap* heap = GetHeap();
  {
    auto* gced = MakeGarbageCollected<DerivedGCed>(heap->GetAllocationHandle());
    auto* derived = static_cast<DerivedMixin*>(gced);
    ASSERT_NE(reinterpret_cast<void*>(gced), reinterpret_cast<void*>(derived));
  }
  {
    auto* gced = MakeGarbageCollected<DerivedGCed>(heap->GetAllocationHandle());
    Member<DerivedGCed> member = gced;
#define EXPECT_MIXIN_EQUAL(Mixin) \
  EXPECT_TRUE(member == mixin);   \
  EXPECT_TRUE(member == gced);    \
  EXPECT_TRUE(mixin == gced);     \
  EXPECT_FALSE(member != mixin);  \
  EXPECT_FALSE(member != gced);   \
  EXPECT_FALSE(mixin != gced);
    {
      // Construct from raw.
      Member<DerivedMixin> mixin = gced;
      EXPECT_MIXIN_EQUAL(mixin);
    }
    {
      // Copy construct from member.
      Member<DerivedMixin> mixin = member;
      EXPECT_MIXIN_EQUAL(mixin);
    }
    {
      // Move construct from member.
      Member<DerivedMixin> mixin = std::move(member);
      member = gced;
      EXPECT_MIXIN_EQUAL(mixin);
    }
    {
      // Copy assign from member.
      Member<DerivedMixin> mixin;
      mixin = member;
      EXPECT_MIXIN_EQUAL(mixin);
    }
    {
      // Move assign from member.
      Member<DerivedMixin> mixin;
      mixin = std::move(member);
      member = gced;
      EXPECT_MIXIN_EQUAL(mixin);
    }
#undef EXPECT_MIXIN_EQUAL
  }
}

TEST_F(MemberTest, WriteBarrierTriggered) {
  CustomWriteBarrierPolicy::InitializingWriteBarriersTriggered = 0;
  CustomWriteBarrierPolicy::AssigningWriteBarriersTriggered = 0;
  GCed* gced = MakeGarbageCollected<GCed>(GetAllocationHandle());
  MemberWithCustomBarrier member1 = gced;
  EXPECT_EQ(1u, CustomWriteBarrierPolicy::InitializingWriteBarriersTriggered);
  EXPECT_EQ(0u, CustomWriteBarrierPolicy::AssigningWriteBarriersTriggered);
  member1 = gced;
  EXPECT_EQ(1u, CustomWriteBarrierPolicy::InitializingWriteBarriersTriggered);
  EXPECT_EQ(1u, CustomWriteBarrierPolicy::AssigningWriteBarriersTriggered);
  member1 = nullptr;
  EXPECT_EQ(1u, CustomWriteBarrierPolicy::InitializingWriteBarriersTriggered);
  EXPECT_EQ(1u, CustomWriteBarrierPolicy::AssigningWriteBarriersTriggered);
  MemberWithCustomBarrier member2 = nullptr;
  // No initializing barriers for std::nullptr_t.
  EXPECT_EQ(1u, CustomWriteBarrierPolicy::InitializingWriteBarriersTriggered);
  EXPECT_EQ(1u, CustomWriteBarrierPolicy::AssigningWriteBarriersTriggered);
  member2 = kSentinelPointer;
  EXPECT_EQ(kSentinelPointer, member2.Get());
  EXPECT_EQ(kSentinelPointer, member2);
  // No initializing barriers for pointer sentinel.
  EXPECT_EQ(1u, CustomWriteBarrierPolicy::InitializingWriteBarriersTriggered);
  EXPECT_EQ(1u, CustomWriteBarrierPolicy::AssigningWriteBarriersTriggered);
  member2.Swap(member1);
  EXPECT_EQ(3u, CustomWriteBarrierPolicy::AssigningWriteBarriersTriggered);
}

TEST_F(MemberTest, CheckingPolicy) {
  static constexpr size_t kElements = 64u;
  CustomCheckingPolicy::ChecksTriggered = 0u;

  for (std::size_t i = 0; i < kElements; ++i) {
    CustomCheckingPolicy::Cached.push_back(
        MakeGarbageCollected<GCed>(GetAllocationHandle()));
  }

  MemberWithCustomChecking member;
  for (GCed* item : CustomCheckingPolicy::Cached) {
    member = item;
  }
  EXPECT_EQ(CustomCheckingPolicy::Cached.size(),
            CustomCheckingPolicy::ChecksTriggered);
}

namespace {

class MemberHeapTest : public testing::TestWithHeap {};

class GCedWithMembers final : public GarbageCollected<GCedWithMembers> {
 public:
  static size_t live_count_;

  GCedWithMembers() : GCedWithMembers(nullptr, nullptr) {}
  explicit GCedWithMembers(GCedWithMembers* strong, GCedWithMembers* weak)
      : strong_nested_(strong), weak_nested_(weak) {
    ++live_count_;
  }

  ~GCedWithMembers() { --live_count_; }

  void Trace(cppgc::Visitor* visitor) const {
    visitor->Trace(strong_nested_);
    visitor->Trace(weak_nested_);
  }

  bool WasNestedCleared() const { return !weak_nested_; }

 private:
  Member<GCedWithMembers> strong_nested_;
  WeakMember<GCedWithMembers> weak_nested_;
};
size_t GCedWithMembers::live_count_ = 0;

}  // namespace

TEST_F(MemberHeapTest, MemberRetainsObject) {
  EXPECT_EQ(0u, GCedWithMembers::live_count_);
  {
    GCedWithMembers* nested_object =
        MakeGarbageCollected<GCedWithMembers>(GetAllocationHandle());
    Persistent<GCedWithMembers> gced_with_members =
        MakeGarbageCollected<GCedWithMembers>(GetAllocationHandle(),
                                              nested_object, nested_object);
    EXPECT_EQ(2u, GCedWithMembers::live_count_);
    PreciseGC();
    EXPECT_EQ(2u, GCedWithMembers::live_count_);
    EXPECT_FALSE(gced_with_members->WasNestedCleared());
  }
  PreciseGC();
  EXPECT_EQ(0u, GCedWithMembers::live_count_);
  {
    GCedWithMembers* nested_object =
        MakeGarbageCollected<GCedWithMembers>(GetAllocationHandle());
    GCedWithMembers* gced_with_members = MakeGarbageCollected<GCedWithMembers>(
        GetAllocationHandle(), nested_object, nested_object);
    EXPECT_EQ(2u, GCedWithMembers::live_count_);
    ConservativeGC();
    EXPECT_EQ(2u, GCedWithMembers::live_count_);
    EXPECT_FALSE(gced_with_members->WasNestedCleared());
  }
  PreciseGC();
  EXPECT_EQ(0u, GCedWithMembers::live_count_);
}

TEST_F(MemberHeapTest, WeakMemberDoesNotRetainObject) {
  EXPECT_EQ(0u, GCedWithMembers::live_count_);
  auto* weak_nested =
      MakeGarbageCollected<GCedWithMembers>(GetAllocationHandle());
  Persistent<GCedWithMembers> gced_with_members(
      MakeGarbageCollected<GCedWithMembers>(GetAllocationHandle(), nullptr,
                                            weak_nested));
  PreciseGC();
  EXPECT_EQ(1u, GCedWithMembers::live_count_);
  EXPECT_TRUE(gced_with_members->WasNestedCleared());
}

namespace {
class GCedWithConstWeakMember
    : public GarbageCollected<GCedWithConstWeakMember> {
 public:
  explicit GCedWithConstWeakMember(const GCedWithMembers* weak)
      : weak_member_(weak) {}

  void Trace(Visitor* visitor) const { visitor->Trace(weak_member_); }

  const GCedWithMembers* weak_member() const { return weak_member_; }

 private:
  const WeakMember<const GCedWithMembers> weak_member_;
};
}  // namespace

TEST_F(MemberHeapTest, ConstWeakRefIsClearedOnGC) {
  const WeakPersistent<const GCedWithMembers> weak_persistent =
      MakeGarbageCollected<GCedWithMembers>(GetAllocationHandle());
  Persistent<GCedWithConstWeakMember> persistent =
      MakeGarbageCollected<GCedWithConstWeakMember>(GetAllocationHandle(),
                                                    weak_persistent);
  PreciseGC();
  EXPECT_FALSE(weak_persistent);
  EXPECT_FALSE(persistent->weak_member());
}

#if V8_ENABLE_CHECKS

namespace {
class MemberHeapDeathTest : public testing::TestWithHeap {};

class LinkedNode final : public GarbageCollected<LinkedNode> {
 public:
  explicit LinkedNode(LinkedNode* next) : next_(next) {}
  void Trace(Visitor* v) const { v->Trace(next_); }

  void SetNext(LinkedNode* next) { next_ = next; }

 private:
  Member<LinkedNode> next_;
};

}  // namespace

// The following tests create multiple heaps per thread, which is not supported
// with pointer compression enabled.
#if !defined(CPPGC_POINTER_COMPRESSION) && defined(ENABLE_SLOW_DCHECKS)
TEST_F(MemberHeapDeathTest, CheckForOffHeapMemberCrashesOnReassignment) {
  std::vector<Member<LinkedNode>> off_heap_member;
  // Verification state is constructed on first assignment.
  off_heap_member.emplace_back(
      MakeGarbageCollected<LinkedNode>(GetAllocationHandle(), nullptr));
  {
    auto tmp_heap = cppgc::Heap::Create(platform_);
    auto* tmp_obj = MakeGarbageCollected<LinkedNode>(
        tmp_heap->GetAllocationHandle(), nullptr);
    EXPECT_DEATH_IF_SUPPORTED(off_heap_member[0] = tmp_obj, "");
  }
}

TEST_F(MemberHeapDeathTest, CheckForOnStackMemberCrashesOnReassignment) {
  Member<LinkedNode> stack_member;
  // Verification state is constructed on first assignment.
  stack_member =
      MakeGarbageCollected<LinkedNode>(GetAllocationHandle(), nullptr);
  {
    auto tmp_heap = cppgc::Heap::Create(platform_);
    auto* tmp_obj = MakeGarbageCollected<LinkedNode>(
        tmp_heap->GetAllocationHandle(), nullptr);
    EXPECT_DEATH_IF_SUPPORTED(stack_member = tmp_obj, "");
  }
}

TEST_F(MemberHeapDeathTest, CheckForOnHeapMemberCrashesOnInitialAssignment) {
  auto* obj = MakeGarbageCollected<LinkedNode>(GetAllocationHandle(), nullptr);
  {
    auto tmp_heap = cppgc::Heap::Create(platform_);
    EXPECT_DEATH_IF_SUPPORTED(
        // For regular on-heap Member references the verification state is
        // constructed eagerly on creating the reference.
        MakeGarbageCollected<LinkedNode>(tmp_heap->GetAllocationHandle(), obj),
        "");
  }
}
#endif  // defined(CPPGC_POINTER_COMPRESSION) && defined(ENABLE_SLOW_DCHECKS)

#if defined(CPPGC_POINTER_COMPRESSION)
TEST_F(MemberTest, CompressDecompress) {
  CompressedPointer cp;
  EXPECT_EQ(nullptr, cp.Load());

  Member<GCed> member;
  cp.Store(member.Get());
  EXPECT_EQ(nullptr, cp.Load());

  cp.Store(kSentinelPointer);
  EXPECT_EQ(kSentinelPointer, cp.Load());

  member = kSentinelPointer;
  cp.Store(member.Get());
  EXPECT_EQ(kSentinelPointer, cp.Load());

  member = MakeGarbageCollected<GCed>(GetAllocationHandle());
  cp.Store(member.Get());
  EXPECT_EQ(member.Get(), cp.Load());
}
#endif  // defined(CPPGC_POINTER_COMPRESSION)

#endif  // V8_ENABLE_CHECKS

}  // namespace internal
}  // namespace cppgc

"""

```