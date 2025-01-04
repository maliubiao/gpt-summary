Response: Let's break down the thought process for analyzing the C++ test file.

1. **Understand the Goal:** The core request is to understand the functionality of the C++ file `traced-reference-unittest.cc` and explain its relationship to JavaScript using examples. The file name strongly suggests it's testing a feature related to "traced references."

2. **Initial Scan for Keywords:** Quickly scan the code for important keywords and patterns. Look for:
    * `#include`:  This tells us about dependencies. `v8-cppgc.h`, `v8-traced-handle.h` are key. `v8.h` is also important.
    * `namespace v8::internal`:  Indicates this is internal V8 implementation testing.
    * `TEST_F`:  This is a Google Test macro, signifying this file is a unit test suite.
    * `TracedReference`:  This is the central concept being tested.
    * `v8::Local`, `v8::Object`, `v8::Context`, `v8::Isolate`:  These are core V8 API types related to JavaScript object management.
    * `Reset`, `Construct`, `Copy`, `Move`, `Equality`:  These are common object lifecycle and comparison operations, suggesting the tests are checking these operations on `TracedReference`.
    * `IsEmpty`: A method likely to check if the reference is currently pointing to an object.
    * `JSVisitor`:  Indicates interaction with the garbage collection system.
    * `WriteBarrier`: A term related to incremental garbage collection.
    * `SimulateIncrementalMarking`, `MarkingState`: Further hints about garbage collection testing.

3. **Identify the Core Class Under Test:** The repeated use of `v8::TracedReference<v8::Object>` (and sometimes `<v8::Value>`) strongly indicates that this is the primary class being tested.

4. **Analyze Individual Tests:** Go through each `TEST_F` function and understand what it's testing:
    * **`ResetFromLocal`:** Checks if a `TracedReference` can be assigned a `v8::Local` and if it correctly tracks the object.
    * **`ConstructFromLocal`:** Similar to `ResetFromLocal` but tests initialization during construction.
    * **`Reset`:** Checks if a `TracedReference` can be emptied using `Reset()`.
    * **`Copy` and `CopyHeterogenous`:**  Tests the copy constructor and assignment operator for `TracedReference`, including cases where the types are different but compatible (e.g., `Object` to `Value`).
    * **`Move` and `MoveHeterogenous`:** Tests the move constructor and move assignment operator, ensuring the original `TracedReference` becomes empty.
    * **`Equality` and `EqualityHeterogenous`:** Checks the equality operators (`==` and `!=`) for `TracedReference` objects, including comparisons between different types.
    * **`TracedReferenceTrace`:** This test uses a custom `JSVisitorForTesting` to simulate a garbage collection trace and verifies that the `TracedReference` is visited correctly. This directly links to garbage collection.
    * **`NoWriteBarrierOnConstruction`:** Tests that constructing a `TracedReference` *doesn't* trigger a write barrier during incremental marking. This is an optimization.
    * **`WriteBarrierForOnHeapReset`, `WriteBarrierForOnStackReset`, `WriteBarrierOnHeapCopy`, `WriteBarrierForOnStackCopy`, `WriteBarrierForOnHeapMove`, `WriteBarrierForOnStackMove`:** These tests are all related to write barriers. They check if assigning, copying, or moving a `TracedReference` triggers a write barrier when incremental marking is enabled. The distinction between "OnHeap" and "OnStack" likely refers to how the `TracedReference` itself is allocated.

5. **Synthesize the Functionality:** Based on the individual tests, summarize the key features of `v8::TracedReference`:
    * Holds a reference to a V8 JavaScript object.
    * Can be constructed, reset, copied, and moved.
    * Supports heterogeneous copying and moving (to a base type).
    * Can be compared for equality.
    * Is involved in the garbage collection process (it's "traced").
    * Integrates with the write barrier mechanism for incremental garbage collection.

6. **Connect to JavaScript:**  Think about how this C++ concept relates to JavaScript.
    * **Holding References:** In JavaScript, you can hold references to objects in variables. `TracedReference` is a C++ mechanism for doing something similar *within the V8 engine*.
    * **Garbage Collection:** JavaScript uses garbage collection. `TracedReference` is part of how V8 tracks which objects are still in use to prevent them from being garbage collected prematurely.
    * **Avoiding Premature Collection:**  If V8 had only "raw" pointers to JavaScript objects in its internal C++ code, those pointers wouldn't prevent garbage collection. `TracedReference` provides a way to *inform* the garbage collector that an object is still being referenced.

7. **Create JavaScript Examples:** Devise simple JavaScript examples that illustrate the *effects* of what `TracedReference` is doing internally:
    * Demonstrate how assigning a JavaScript object to a variable keeps it alive. This mirrors the basic functionality of `TracedReference`.
    * Illustrate the concept of weak references (although `TracedReference` isn't strictly a weak reference, it manages object lifetimes). Explain that `TracedReference` helps V8 manage the "liveness" of objects.
    * If possible (though more complex), explain how V8 might use these references during garbage collection cycles internally.

8. **Refine the Explanation:** Organize the findings logically. Start with a general summary of the file's purpose, then delve into the details of `TracedReference` and its operations. Finally, connect it to JavaScript with clear examples. Use precise language but avoid overly technical jargon when explaining the JavaScript connection.

9. **Review and Iterate:** Read through the explanation to ensure clarity and accuracy. Check if the JavaScript examples effectively illustrate the concepts. Are there any ambiguities?  Could anything be explained more simply?  For example, initially, I might have focused too much on the C++ details of write barriers. The key is to bring it back to the JavaScript impact.
这个C++源代码文件 `traced-reference-unittest.cc` 是 V8 JavaScript 引擎的一部分，专门用于测试 `v8::TracedReference` 这个 C++ 类的功能。

**`v8::TracedReference` 的功能：**

`v8::TracedReference` 是 V8 引擎中一种智能指针，用于持有对 JavaScript 对象的引用，并且能够参与到 V8 的垃圾回收机制中。它的主要目的是：

1. **安全地持有 JavaScript 对象引用:**  与普通的 C++ 指针不同，`TracedReference` 能够感知 V8 的垃圾回收过程。当垃圾回收器运行时，它会遍历所有活跃的 `TracedReference`，并将它们引用的对象标记为可达，从而防止这些对象被错误地回收。
2. **方便地管理对象生命周期:**  `TracedReference` 提供了一些方法来管理它所引用的对象，例如：
    * `Reset()`: 清空引用，不再持有任何对象。
    * 构造函数和赋值操作符：可以从 `v8::Local` 或其他 `TracedReference` 初始化或赋值。
    * 拷贝和移动语义：支持深拷贝和移动操作。
    * 比较操作符：可以比较两个 `TracedReference` 是否引用同一个 JavaScript 对象。

**`traced-reference-unittest.cc` 的功能归纳：**

这个测试文件通过一系列单元测试来验证 `v8::TracedReference` 类的各种功能是否正常工作。它主要测试了以下几个方面：

* **基本操作:**
    *  从 `v8::Local` 对象重置（赋值）`TracedReference`。
    *  从 `v8::Local` 对象构造 `TracedReference`。
    *  清空 `TracedReference` 的引用。
* **拷贝和移动语义:**
    *  拷贝构造函数和拷贝赋值操作符的行为。
    *  移动构造函数和移动赋值操作符的行为。
    *  涉及不同类型的 `TracedReference` (例如 `TracedReference<v8::Object>` 和 `TracedReference<v8::Value>`) 的拷贝和移动。
* **相等性比较:**
    *  比较两个 `TracedReference` 是否引用同一个 JavaScript 对象。
    *  比较不同类型的 `TracedReference` 的相等性。
* **垃圾回收相关:**
    *  验证 `TracedReference` 可以被垃圾回收器追踪 (通过 `JSVisitor`)。
    *  测试在构造 `TracedReference` 时是否会触发写屏障 (Write Barrier)。
    *  测试在重置、拷贝和移动 `TracedReference` 时是否会触发写屏障 (在增量标记的场景下)。

**与 JavaScript 的关系及 JavaScript 示例：**

`v8::TracedReference` 是 V8 引擎内部用于管理 JavaScript 对象的机制，它直接影响着 JavaScript 对象的生命周期。虽然 JavaScript 开发者不能直接操作 `TracedReference`，但了解它的工作原理有助于理解 V8 如何进行垃圾回收。

**JavaScript 示例：**

假设在 V8 引擎的 C++ 代码中，有一个 `TracedReference<v8::Object>` 类型的成员变量 `myObjectRef`。 当你在 JavaScript 中创建一个对象并将其传递给 C++ 代码时，V8 可能会使用 `TracedReference` 来持有这个对象的引用。

```javascript
// JavaScript 代码
let myObject = { value: 10 };

// 假设有一个 C++ 函数接受 JavaScript 对象作为参数
// 并且在 C++ 内部使用 TracedReference 来持有该对象

function processObject(obj) {
  // ... 内部会调用 C++ 代码，并将 obj 传递过去 ...
}

processObject(myObject);

// 即使在 processObject 调用之后，JavaScript 代码中不再直接使用 myObject，
// 但由于 C++ 代码可能仍然通过 TracedReference 持有它，
// 因此这个对象不会立即被 JavaScript 的垃圾回收器回收。

// 如果 C++ 代码调用了 myObjectRef.Reset()，
// 那么对 myObject 的引用将被释放，
// 在下一次 JavaScript 垃圾回收时，myObject 就有可能被回收。
```

**更具体的解释:**

当 JavaScript 引擎需要将 JavaScript 对象传递给 C++ 代码，并且希望确保该对象在 C++ 代码使用期间不会被 JavaScript 垃圾回收器回收时，就会使用类似 `TracedReference` 的机制。

* **`v8::Local`:** 在 C++ 中，`v8::Local` 用于表示一个在当前作用域内有效的 JavaScript 对象句柄。它的生命周期由 `v8::HandleScope` 管理。
* **`v8::TracedReference`:**  与 `v8::Local` 不同，`TracedReference` 的生命周期更长，它可以跨越多个 C++ 函数调用和作用域。它通过参与垃圾回收标记过程来保持其引用的对象存活。

**总结:**

`traced-reference-unittest.cc` 文件测试了 V8 引擎中用于安全且受控地持有 JavaScript 对象引用的关键 C++ 类 `v8::TracedReference` 的功能。理解 `TracedReference` 的作用有助于理解 V8 如何在 C++ 代码中管理 JavaScript 对象的生命周期，以及 V8 的垃圾回收机制是如何工作的。虽然 JavaScript 开发者不直接使用它，但它的存在对 JavaScript 对象的内存管理至关重要。

Prompt: 
```
这是目录为v8/test/unittests/heap/cppgc-js/traced-reference-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "include/v8-cppgc.h"
#include "include/v8-traced-handle.h"
#include "src/api/api-inl.h"
#include "src/handles/global-handles.h"
#include "src/heap/cppgc/visitor.h"
#include "src/heap/marking-state-inl.h"
#include "test/unittests/heap/heap-utils.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {

using TracedReferenceTest = TestWithHeapInternals;

TEST_F(TracedReferenceTest, ResetFromLocal) {
  v8::Local<v8::Context> context = v8::Context::New(v8_isolate());
  v8::Context::Scope context_scope(context);
  v8::TracedReference<v8::Object> ref;
  {
    v8::HandleScope handles(v8_isolate());
    v8::Local<v8::Object> local =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    ASSERT_TRUE(ref.IsEmpty());
    EXPECT_NE(ref, local);
    ref.Reset(v8_isolate(), local);
    EXPECT_FALSE(ref.IsEmpty());
    EXPECT_EQ(ref, local);
  }
}

TEST_F(TracedReferenceTest, ConstructFromLocal) {
  v8::Local<v8::Context> context = v8::Context::New(v8_isolate());
  v8::Context::Scope context_scope(context);
  {
    v8::HandleScope handles(v8_isolate());
    v8::Local<v8::Object> local =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    v8::TracedReference<v8::Object> ref(v8_isolate(), local);
    EXPECT_FALSE(ref.IsEmpty());
    EXPECT_EQ(ref, local);
  }
}

TEST_F(TracedReferenceTest, Reset) {
  v8::Local<v8::Context> context = v8::Context::New(v8_isolate());
  v8::Context::Scope context_scope(context);
  {
    v8::HandleScope handles(v8_isolate());
    v8::Local<v8::Object> local =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    v8::TracedReference<v8::Object> ref(v8_isolate(), local);
    EXPECT_FALSE(ref.IsEmpty());
    EXPECT_EQ(ref, local);
    ref.Reset();
    EXPECT_TRUE(ref.IsEmpty());
    EXPECT_NE(ref, local);
  }
}

TEST_F(TracedReferenceTest, Copy) {
  v8::Local<v8::Context> context = v8::Context::New(v8_isolate());
  v8::Context::Scope context_scope(context);
  {
    v8::HandleScope handles(v8_isolate());
    v8::Local<v8::Object> local =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    v8::TracedReference<v8::Object> ref(v8_isolate(), local);
    v8::TracedReference<v8::Object> ref_copy1(ref);
    v8::TracedReference<v8::Object> ref_copy2 = ref;
    EXPECT_EQ(ref, local);
    EXPECT_EQ(ref_copy1, local);
    EXPECT_EQ(ref_copy2, local);
  }
}

TEST_F(TracedReferenceTest, CopyHeterogenous) {
  v8::Local<v8::Context> context = v8::Context::New(v8_isolate());
  v8::Context::Scope context_scope(context);
  {
    v8::HandleScope handles(v8_isolate());
    v8::Local<v8::Object> local =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    v8::TracedReference<v8::Object> ref(v8_isolate(), local);
    v8::TracedReference<v8::Value> ref_copy1(ref);
    v8::TracedReference<v8::Value> ref_copy2 = ref;
    EXPECT_EQ(ref, local);
    EXPECT_EQ(ref_copy1, local);
    EXPECT_EQ(ref_copy2, local);
  }
}

TEST_F(TracedReferenceTest, Move) {
  v8::Local<v8::Context> context = v8::Context::New(v8_isolate());
  v8::Context::Scope context_scope(context);
  {
    v8::HandleScope handles(v8_isolate());
    v8::Local<v8::Object> local =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    v8::TracedReference<v8::Object> ref(v8_isolate(), local);
    v8::TracedReference<v8::Object> ref_moved1(std::move(ref));
    v8::TracedReference<v8::Object> ref_moved2 = std::move(ref_moved1);
    EXPECT_TRUE(ref.IsEmpty());
    EXPECT_TRUE(ref_moved1.IsEmpty());
    EXPECT_EQ(ref_moved2, local);
  }
}

TEST_F(TracedReferenceTest, MoveHeterogenous) {
  v8::Local<v8::Context> context = v8::Context::New(v8_isolate());
  v8::Context::Scope context_scope(context);
  {
    v8::HandleScope handles(v8_isolate());
    v8::Local<v8::Object> local =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    v8::TracedReference<v8::Object> ref1(v8_isolate(), local);
    v8::TracedReference<v8::Value> ref_moved1(std::move(ref1));
    v8::TracedReference<v8::Object> ref2(v8_isolate(), local);
    v8::TracedReference<v8::Object> ref_moved2 = std::move(ref2);
    EXPECT_TRUE(ref1.IsEmpty());
    EXPECT_EQ(ref_moved1, local);
    EXPECT_TRUE(ref2.IsEmpty());
    EXPECT_EQ(ref_moved2, local);
  }
}

TEST_F(TracedReferenceTest, Equality) {
  v8::Local<v8::Context> context = v8::Context::New(v8_isolate());
  v8::Context::Scope context_scope(context);
  {
    v8::HandleScope handles(v8_isolate());
    v8::Local<v8::Object> local1 =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    v8::TracedReference<v8::Object> ref1(v8_isolate(), local1);
    v8::TracedReference<v8::Object> ref2(v8_isolate(), local1);
    EXPECT_EQ(ref1, ref2);
    EXPECT_EQ(ref2, ref1);
    v8::Local<v8::Object> local2 =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    v8::TracedReference<v8::Object> ref3(v8_isolate(), local2);
    EXPECT_NE(ref2, ref3);
    EXPECT_NE(ref3, ref2);
  }
}

TEST_F(TracedReferenceTest, EqualityHeterogenous) {
  v8::Local<v8::Context> context = v8::Context::New(v8_isolate());
  v8::Context::Scope context_scope(context);
  {
    v8::HandleScope handles(v8_isolate());
    v8::Local<v8::Object> local1 =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    v8::TracedReference<v8::Object> ref1(v8_isolate(), local1);
    v8::TracedReference<v8::Value> ref2(v8_isolate(), local1);
    EXPECT_EQ(ref1, ref2);
    EXPECT_EQ(ref2, ref1);
    v8::Local<v8::Object> local2 =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    v8::TracedReference<v8::Object> ref3(v8_isolate(), local2);
    EXPECT_NE(ref2, ref3);
    EXPECT_NE(ref3, ref2);
  }
}

namespace {

// Must be used on stack.
class JSVisitorForTesting final : public JSVisitor {
 public:
  explicit JSVisitorForTesting(v8::Local<v8::Object> expected_object)
      : JSVisitor(cppgc::internal::VisitorFactory::CreateKey()),
        expected_object_(expected_object) {}

  void Visit(const TracedReferenceBase& ref) final {
    EXPECT_EQ(ref, expected_object_);
    visit_count_++;
  }

  size_t visit_count() const { return visit_count_; }

 private:
  v8::Local<v8::Object> expected_object_;
  size_t visit_count_ = 0;
};

}  // namespace

TEST_F(TracedReferenceTest, TracedReferenceTrace) {
  v8::Local<v8::Context> context = v8::Context::New(v8_isolate());
  v8::Context::Scope context_scope(context);
  {
    v8::HandleScope handles(v8_isolate());
    v8::Local<v8::Object> local =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    v8::TracedReference<v8::Object> js_member(v8_isolate(), local);
    JSVisitorForTesting visitor(local);
    // Cast to cppgc::Visitor to ensure that we dispatch through the base
    // visitor and use traits.
    static_cast<cppgc::Visitor&>(visitor).Trace(js_member);
    EXPECT_EQ(1u, visitor.visit_count());
  }
}

TEST_F(TracedReferenceTest, NoWriteBarrierOnConstruction) {
  if (!v8_flags.incremental_marking)
    GTEST_SKIP() << "Write barrier tests require incremental marking";

  v8::Local<v8::Context> context = v8::Context::New(v8_isolate());
  v8::Context::Scope context_scope(context);
  {
    v8::HandleScope handles(v8_isolate());
    v8::Local<v8::Object> local =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    SimulateIncrementalMarking();
    MarkingState state(i_isolate());
    ASSERT_TRUE(
        state.IsUnmarked(Cast<HeapObject>(*Utils::OpenDirectHandle(*local))));
    auto ref =
        std::make_unique<v8::TracedReference<v8::Object>>(v8_isolate(), local);
    USE(ref);
    EXPECT_TRUE(
        state.IsUnmarked(Cast<HeapObject>(*Utils::OpenDirectHandle(*local))));
  }
}

TEST_F(TracedReferenceTest, WriteBarrierForOnHeapReset) {
  if (!v8_flags.incremental_marking)
    GTEST_SKIP() << "Write barrier tests require incremental marking";

  v8::Local<v8::Context> context = v8::Context::New(v8_isolate());
  v8::Context::Scope context_scope(context);
  {
    v8::HandleScope handles(v8_isolate());
    v8::Local<v8::Object> local =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    auto ref = std::make_unique<v8::TracedReference<v8::Object>>();
    SimulateIncrementalMarking();
    MarkingState state(i_isolate());
    ASSERT_TRUE(
        state.IsUnmarked(Cast<HeapObject>(*Utils::OpenDirectHandle(*local))));
    ref->Reset(v8_isolate(), local);
    EXPECT_FALSE(
        state.IsUnmarked(Cast<HeapObject>(*Utils::OpenDirectHandle(*local))));
  }
}

TEST_F(TracedReferenceTest, WriteBarrierForOnStackReset) {
  if (!v8_flags.incremental_marking)
    GTEST_SKIP() << "Write barrier tests require incremental marking";

  v8::Local<v8::Context> context = v8::Context::New(v8_isolate());
  v8::Context::Scope context_scope(context);
  {
    v8::HandleScope handles(v8_isolate());
    v8::Local<v8::Object> local =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    v8::TracedReference<v8::Object> ref;
    SimulateIncrementalMarking();
    MarkingState state(i_isolate());
    ASSERT_TRUE(
        state.IsUnmarked(Cast<HeapObject>(*Utils::OpenDirectHandle(*local))));
    ref.Reset(v8_isolate(), local);
    EXPECT_FALSE(
        state.IsUnmarked(Cast<HeapObject>(*Utils::OpenDirectHandle(*local))));
  }
}

TEST_F(TracedReferenceTest, WriteBarrierOnHeapCopy) {
  if (!v8_flags.incremental_marking)
    GTEST_SKIP() << "Write barrier tests require incremental marking";

  v8::Local<v8::Context> context = v8::Context::New(v8_isolate());
  v8::Context::Scope context_scope(context);
  {
    v8::HandleScope handles(v8_isolate());
    v8::Local<v8::Object> local =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    auto ref_from =
        std::make_unique<v8::TracedReference<v8::Object>>(v8_isolate(), local);
    auto ref_to = std::make_unique<v8::TracedReference<v8::Object>>();
    SimulateIncrementalMarking();
    MarkingState state(i_isolate());
    ASSERT_TRUE(
        state.IsUnmarked(Cast<HeapObject>(*Utils::OpenDirectHandle(*local))));
    *ref_to = *ref_from;
    EXPECT_TRUE(!ref_from->IsEmpty());
    EXPECT_FALSE(
        state.IsUnmarked(Cast<HeapObject>(*Utils::OpenDirectHandle(*local))));
  }
}

TEST_F(TracedReferenceTest, WriteBarrierForOnStackCopy) {
  if (!v8_flags.incremental_marking)
    GTEST_SKIP() << "Write barrier tests require incremental marking";

  v8::Local<v8::Context> context = v8::Context::New(v8_isolate());
  v8::Context::Scope context_scope(context);
  {
    v8::HandleScope handles(v8_isolate());
    v8::Local<v8::Object> local =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    auto ref_from =
        std::make_unique<v8::TracedReference<v8::Object>>(v8_isolate(), local);
    v8::TracedReference<v8::Object> ref_to;
    SimulateIncrementalMarking();
    MarkingState state(i_isolate());
    ASSERT_TRUE(
        state.IsUnmarked(Cast<HeapObject>(*Utils::OpenDirectHandle(*local))));
    ref_to = *ref_from;
    EXPECT_TRUE(!ref_from->IsEmpty());
    EXPECT_FALSE(
        state.IsUnmarked(Cast<HeapObject>(*Utils::OpenDirectHandle(*local))));
  }
}

TEST_F(TracedReferenceTest, WriteBarrierForOnHeapMove) {
  if (!v8_flags.incremental_marking)
    GTEST_SKIP() << "Write barrier tests require incremental marking";

  v8::Local<v8::Context> context = v8::Context::New(v8_isolate());
  v8::Context::Scope context_scope(context);
  {
    v8::HandleScope handles(v8_isolate());
    v8::Local<v8::Object> local =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    auto ref_from =
        std::make_unique<v8::TracedReference<v8::Object>>(v8_isolate(), local);
    auto ref_to = std::make_unique<v8::TracedReference<v8::Object>>();
    SimulateIncrementalMarking();
    MarkingState state(i_isolate());
    ASSERT_TRUE(
        state.IsUnmarked(Cast<HeapObject>(*Utils::OpenDirectHandle(*local))));
    *ref_to = std::move(*ref_from);
    ASSERT_TRUE(ref_from->IsEmpty());
    EXPECT_FALSE(
        state.IsUnmarked(Cast<HeapObject>(*Utils::OpenDirectHandle(*local))));
  }
}

TEST_F(TracedReferenceTest, WriteBarrierForOnStackMove) {
  if (!v8_flags.incremental_marking)
    GTEST_SKIP() << "Write barrier tests require incremental marking";

  v8::Local<v8::Context> context = v8::Context::New(v8_isolate());
  v8::Context::Scope context_scope(context);
  {
    v8::HandleScope handles(v8_isolate());
    v8::Local<v8::Object> local =
        v8::Local<v8::Object>::New(v8_isolate(), v8::Object::New(v8_isolate()));
    auto ref_from =
        std::make_unique<v8::TracedReference<v8::Object>>(v8_isolate(), local);
    v8::TracedReference<v8::Object> ref_to;
    SimulateIncrementalMarking();
    MarkingState state(i_isolate());
    ASSERT_TRUE(
        state.IsUnmarked(Cast<HeapObject>(*Utils::OpenDirectHandle(*local))));
    ref_to = std::move(*ref_from);
    ASSERT_TRUE(ref_from->IsEmpty());
    EXPECT_FALSE(
        state.IsUnmarked(Cast<HeapObject>(*Utils::OpenDirectHandle(*local))));
  }
}

}  // namespace internal
}  // namespace v8

"""

```