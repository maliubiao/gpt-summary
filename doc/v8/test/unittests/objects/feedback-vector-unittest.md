Response: Let's break down the thought process for analyzing this C++ unit test file and relating it to JavaScript.

1. **Understand the Context:** The file path `v8/test/unittests/objects/feedback-vector-unittest.cc` immediately tells us a few things:
    * It's a test file (`unittest`).
    * It's part of the V8 project (the JavaScript engine in Chrome and Node.js).
    * It's testing the "feedback vector" within the "objects" subsystem. This hints at something related to how V8 tracks information about objects and their usage.

2. **Skim the Header Includes:**  The `#include` statements provide clues about the core functionalities being tested:
    * `"src/api/api-inl.h"`: Likely related to the V8 API that JavaScript code interacts with.
    * `"src/execution/execution.h"`:  Suggests interaction with the execution pipeline of JavaScript code.
    * `"src/heap/factory.h"`: Implies the creation of V8 heap objects.
    * `"src/objects/feedback-cell-inl.h"` and `"src/objects/objects-inl.h"`:  Confirms the focus on V8's internal object representation and specifically feedback mechanisms.
    * `"test/unittests/test-utils.h"`: Standard testing utilities.

3. **Identify the Test Fixture:** The `class FeedbackVectorTest : public TestWithContext` structure sets up the testing environment. The `GetFunction` method is a utility for retrieving V8 internal representations of JavaScript functions defined in the tests.

4. **Analyze the Test Cases (the `TEST_F` macros):** This is where the core functionality is explored. Look for patterns and keywords in the test names and the code within each test:

    * **`VectorStructure`:**  Focuses on the basic layout of the `FeedbackVector`. It creates vectors with different kinds of slots (`ForInSlot`, `CallICSlot`) and verifies the number of slots and how they are indexed. This suggests the `FeedbackVector` is an array-like structure holding different types of feedback data.

    * **`VectorICMetadata`:**  Deals with the metadata associated with "IC slots". The test adds different types of IC slots (`CallICSlot`, `LoadICSlot`, `KeyedLoadICSlot`) and checks that the `FeedbackVector` correctly identifies the *kind* of each slot. "IC" likely stands for "Inline Cache," a performance optimization technique.

    * **`VectorCallICStates`:**  Examines how the "state" of a "Call IC" changes based on the types of functions called. It uses `%EnsureFeedbackVectorForFunction` and then calls the function with different arguments. Keywords like `MONOMORPHIC` and `GENERIC` hint at different levels of optimization based on observed call patterns.

    * **`VectorCallICStateApply`:** Similar to the previous test but specifically focuses on calls using `Function.prototype.apply`.

    * **`VectorCallFeedback`:** Checks the specific feedback stored for call sites. It verifies that after calling a function, the `FeedbackVector` holds information about the *target* function being called.

    * **`VectorPolymorphicCallFeedback`:**  Tests the scenario where a call site becomes "polymorphic" (calling different functions). It checks that the feedback mechanism can handle this.

    * **`VectorCallFeedbackForArray`:**  Specifically tests calls to the `Array` constructor.

    * **`VectorCallCounts`:**  Verifies that the `FeedbackVector` keeps track of how many times a particular call site has been executed.

    * **`VectorConstructCounts`:** Similar to `VectorCallCounts` but for constructor calls (`new`).

    * **`VectorSpeculationMode`:**  Explores a "speculation mode" associated with feedback, possibly related to aggressive optimization.

    * **`VectorCallSpeculationModeAndFeedbackContent`:**  Combines the concepts of speculation mode and the content of the feedback (e.g., receiver or target of a call).

    * **`VectorLoadICStates`:**  Similar to `VectorCallICStates` but for property loads (accessing properties of objects). It checks how the state of a "Load IC" evolves as different object shapes are encountered.

    * **`VectorLoadGlobalICSlotSharing`:** Focuses on how "Load Global ICs" (accessing global variables) are handled, particularly within `typeof` expressions.

    * **`VectorLoadICOnSmi`:**  Specifically tests property loads on primitive values (like numbers, represented as "Smis" internally).

    * **`ReferenceContextAllocatesNoSlots`:**  Examines how different JavaScript constructs (variable assignments, property assignments) lead to the allocation of feedback slots. The name is a bit misleading, as slots *are* allocated, but the test verifies the *types* of slots allocated for different scenarios.

    * **`VectorStoreICBasic`:** Tests the feedback mechanism for property stores (assigning values to object properties).

    * **`DefineNamedOwnIC`:**  Focuses on the feedback for creating object literals with properties.

5. **Infer the Purpose of `FeedbackVector`:** Based on the tests, the `FeedbackVector` seems to be a core component of V8's optimization strategy. It's a data structure associated with JavaScript functions that stores information about:
    * **Call sites:** The functions being called, how often, and with what kinds of arguments/receivers.
    * **Property access:** The shapes (maps) of objects being accessed, helping to optimize property lookups.
    * **Global variable access:**  Tracking access to global variables.
    * **Operator usage:** Information about binary operations.
    * **Object literal creation:** Details about the properties being created in object literals.

6. **Connect to JavaScript:**  Now, try to illustrate how these internal mechanisms relate to observable JavaScript behavior and performance:

    * **Inline Caching (ICs):**  The tests extensively use terms like "Monomorphic," "Polymorphic," and "Megamorphic." These directly correspond to the effectiveness of inline caches. JavaScript's dynamic nature means V8 needs to guess (and then verify) the types of objects and functions at runtime. The `FeedbackVector` helps guide these guesses.

    * **Optimization:** The `%EnsureFeedbackVectorForFunction` and `%PrepareFunctionForOptimization` intrinsics (though not standard JavaScript) signal the connection to V8's optimization pipeline (including TurboFan, the optimizing compiler). The feedback gathered in the `FeedbackVector` is crucial for making informed optimization decisions.

    * **Performance:** The examples show how repeated calls with the same types can lead to "monomorphic" ICs, which are the most performant. When types change, ICs become "polymorphic" or "megamorphic," potentially leading to deoptimization or slower execution.

7. **Construct the JavaScript Examples:** Create simple JavaScript code snippets that demonstrate the concepts tested in the C++ code. Focus on scenarios that trigger different IC states (monomorphic, polymorphic) and illustrate how V8 might optimize based on the feedback.

8. **Refine and Organize:** Structure the explanation clearly, starting with a general summary and then diving into more specific details. Use clear headings and formatting to make the information easy to understand. Explain the connection between the C++ test cases and the JavaScript examples.
这个C++源代码文件 `feedback-vector-unittest.cc` 是 V8 JavaScript 引擎的一部分，专门用于测试 `FeedbackVector` 类的功能。`FeedbackVector` 是 V8 中用于收集运行时类型反馈信息的核心数据结构，这些信息被 V8 的优化编译器（如 TurboFan）用来进行性能优化。

**功能归纳:**

这个单元测试文件主要测试了 `FeedbackVector` 的以下几个方面：

1. **`FeedbackVector` 的基本结构和创建:**
   - 测试了如何创建 `FeedbackVector`，包括指定不同类型的反馈槽 (slots)。
   - 验证了 `FeedbackVector` 能够正确地管理和索引这些反馈槽。
   - 测试了 `FeedbackVector` 的长度和如何通过索引访问特定的反馈槽。

2. **反馈槽的元数据 (Metadata):**
   - 测试了 `FeedbackVector` 如何存储和检索关于每个反馈槽类型的信息，例如 `kForIn`, `kCall`, `kLoadProperty`, `kLoadKeyed` 等。
   - 验证了在创建 `FeedbackVector` 时，可以根据 `FeedbackVectorSpec` 正确地设置这些元数据。

3. **调用点 (Call IC) 的状态追踪:**
   - 测试了 `FeedbackVector` 如何追踪函数调用点的内联缓存 (Inline Cache, IC) 状态，例如 `MONOMORPHIC` (单态), `POLYMORPHIC` (多态), `GENERIC` (通用)。
   - 模拟了不同的调用场景，例如调用同一个函数多次，或者调用不同的函数，并验证了 `FeedbackVector` 中 IC 状态的正确变化。
   - 测试了 `Function.prototype.apply` 对 IC 状态的影响。
   - 验证了垃圾回收后 IC 状态的保持。

4. **调用点的反馈信息:**
   - 测试了 `FeedbackVector` 如何存储关于调用点的反馈信息，例如被调用的函数。
   - 验证了在单态调用情况下，`FeedbackVector` 可以记录被调用的具体函数。
   - 测试了多态调用情况下，`FeedbackVector` 如何记录反馈信息，可能是一个 `FeedbackCell`。

5. **调用计数:**
   - 测试了 `FeedbackVector` 如何记录函数被调用的次数。
   - 验证了即使在 IC 状态变为多态或通用后，调用计数仍然能够正确递增。

6. **构造函数调用计数:**
   - 类似于调用计数，测试了 `FeedbackVector` 如何记录构造函数被调用的次数。

7. **推测模式 (Speculation Mode):**
   - 测试了与反馈槽关联的推测模式，这与 V8 的优化策略有关。
   - 验证了如何设置和获取反馈槽的推测模式。

8. **加载点 (Load IC) 的状态追踪:**
   - 测试了 `FeedbackVector` 如何追踪属性加载点的 IC 状态。
   - 模拟了加载不同对象属性的场景，并验证了 `FeedbackVector` 中 IC 状态的正确变化。
   - 测试了加载全局变量和加载 Smi (小整数) 属性的情况。

9. **全局加载点 (Load Global IC) 的槽位共享:**
   - 测试了在某些情况下，多个全局变量加载操作可以共享同一个反馈槽。

10. **引用上下文 (Reference Context) 的槽位分配:**
    - 测试了不同的 JavaScript 语法结构 (例如变量赋值，属性赋值) 如何影响 `FeedbackVector` 中反馈槽的分配。

11. **存储点 (Store IC) 的基本功能:**
    - 测试了 `FeedbackVector` 如何处理属性存储操作的反馈信息。

12. **定义自有属性 (DefineNamedOwnIC):**
    - 测试了对于对象字面量中定义自有属性的情况，`FeedbackVector` 如何收集反馈信息。

**与 JavaScript 的关系及示例:**

`FeedbackVector` 的核心功能是为 V8 的优化器提供运行时信息，从而使得 JavaScript 代码可以被编译成更高效的机器码。 它的工作对 JavaScript 开发者是透明的，但直接影响了代码的执行性能。

以下是一些与 `FeedbackVector` 功能相关的 JavaScript 示例，以及它们在 V8 内部可能如何使用 `FeedbackVector` 中的信息：

**1. 函数调用优化 (Call IC States 和 Call Feedback):**

```javascript
function add(a, b) {
  return a + b;
}

function calculate(x) {
  return add(x, 5); // 调用点
}

calculate(2); // 第一次调用，V8 可能会记录 add 被调用，参数类型可能是 Number
calculate(3); // 第二次调用，类型信息可能被加强
calculate("hello"); // 第三次调用，参数类型变化，IC 状态可能从 MONOMORPHIC 变为 POLYMORPHIC 或 GENERIC
```

在这个例子中，`FeedbackVector` 会与 `calculate` 函数关联，并在 `return add(x, 5)` 这个调用点上记录关于 `add` 函数的信息。如果 `calculate` 总是以数字参数调用，那么 V8 可能会对这个调用点进行单态优化。如果参数类型发生变化，V8 可能会进行多态优化或者退回到通用的调用路径。

**2. 属性访问优化 (Load IC States):**

```javascript
function getProperty(obj) {
  return obj.name; // 属性加载点
}

const person1 = { name: "Alice", age: 30 };
getProperty(person1); // 第一次调用，V8 可能会记录 obj 的结构 (Map)

const person2 = { name: "Bob", city: "New York" };
getProperty(person2); // 第二次调用，obj 的结构发生变化，IC 状态可能改变
```

在这里，`FeedbackVector` 会与 `getProperty` 函数关联，并在 `return obj.name` 这个属性加载点上记录关于 `obj` 对象结构的信息。如果 `getProperty` 总是接收具有 "name" 属性的对象，V8 可以优化属性访问。如果接收到的对象结构发生变化，V8 需要调整优化策略。

**3. 全局变量访问优化 (Load Global IC Slot Sharing):**

```javascript
var globalCounter = 0;

function increment() {
  globalCounter++; // 全局变量访问
  return globalCounter;
}

increment();
increment();
```

V8 会使用 `FeedbackVector` 来跟踪对 `globalCounter` 的访问。如果多次访问发生在同一个上下文中，V8 可能会应用特定的优化。

**4. 对象字面量创建优化 (DefineNamedOwnIC):**

```javascript
function createPoint(x, y) {
  return { x: x, y: y }; // 对象字面量创建
}

createPoint(1, 2);
createPoint(3, 4);
```

V8 可以利用 `FeedbackVector` 中收集到的信息来优化对象字面量的创建过程，例如预先分配空间或使用特定的对象布局。

**总结:**

`feedback-vector-unittest.cc` 这个 C++ 文件通过各种测试用例，详细验证了 V8 引擎中 `FeedbackVector` 这一关键组件的正确性和功能。`FeedbackVector` 收集的运行时类型反馈信息直接影响着 V8 对 JavaScript 代码的优化效果，从而提升 JavaScript 的执行性能。虽然 JavaScript 开发者无法直接操作 `FeedbackVector`，但理解其背后的原理有助于理解 V8 如何优化代码。

Prompt: 
```
这是目录为v8/test/unittests/objects/feedback-vector-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/api/api-inl.h"
#include "src/execution/execution.h"
#include "src/heap/factory.h"
#include "src/objects/feedback-cell-inl.h"
#include "src/objects/objects-inl.h"
#include "test/unittests/test-utils.h"

namespace v8 {
namespace internal {

class FeedbackVectorTest : public TestWithContext {
 protected:
  Handle<JSFunction> GetFunction(const char* name) {
    v8::MaybeLocal<v8::Value> v8_f =
        v8_context()->Global()->Get(v8_context(), NewString(name));
    Handle<JSFunction> f =
        Cast<JSFunction>(v8::Utils::OpenHandle(*v8_f.ToLocalChecked()));
    return f;
  }
};

#define CHECK_SLOT_KIND(helper, index, expected_kind) \
  CHECK_EQ(expected_kind, helper.vector()->GetKind(helper.slot(index)));

TEST_F(FeedbackVectorTest, VectorStructure) {
  v8::HandleScope scope(v8_isolate());
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();
  Zone zone(isolate->allocator(), ZONE_NAME);

  Handle<FeedbackVector> vector;

  {
    FeedbackVectorSpec one_slot(&zone);
    one_slot.AddForInSlot();
    vector = NewFeedbackVector(isolate, &one_slot);
    FeedbackVectorHelper helper(vector);
    CHECK_EQ(1, helper.slot_count());
  }

  {
    FeedbackVectorSpec one_icslot(&zone);
    one_icslot.AddCallICSlot();
    vector = NewFeedbackVector(isolate, &one_icslot);
    FeedbackVectorHelper helper(vector);
    CHECK_EQ(1, helper.slot_count());
  }

  {
    FeedbackVectorSpec spec(&zone);
    for (int i = 0; i < 3; i++) {
      spec.AddForInSlot();
    }
    for (int i = 0; i < 5; i++) {
      spec.AddCallICSlot();
    }
    vector = NewFeedbackVector(isolate, &spec);
    FeedbackVectorHelper helper(vector);
    CHECK_EQ(8, helper.slot_count());

    int index = vector->GetIndex(helper.slot(0));

    CHECK_EQ(helper.slot(0), vector->ToSlot(index));

    index = vector->GetIndex(helper.slot(3));
    CHECK_EQ(helper.slot(3), vector->ToSlot(index));

    index = vector->GetIndex(helper.slot(7));
    CHECK_EQ(3 + 4 * FeedbackMetadata::GetSlotSize(FeedbackSlotKind::kCall),
             index);
    CHECK_EQ(helper.slot(7), vector->ToSlot(index));

    CHECK_EQ(3 + 5 * FeedbackMetadata::GetSlotSize(FeedbackSlotKind::kCall),
             vector->length());
  }

  {
    FeedbackVectorSpec spec(&zone);
    spec.AddForInSlot();
    spec.AddCreateClosureParameterCount(0);
    spec.AddForInSlot();
    vector = NewFeedbackVector(isolate, &spec);
    FeedbackVectorHelper helper(vector);
    Tagged<FeedbackCell> cell = vector->closure_feedback_cell(0);
    CHECK_EQ(cell->value(), *factory->undefined_value());
  }
}

// IC slots need an encoding to recognize what is in there.
TEST_F(FeedbackVectorTest, VectorICMetadata) {
  v8::HandleScope scope(v8_isolate());
  Isolate* isolate = i_isolate();
  Zone zone(isolate->allocator(), ZONE_NAME);

  FeedbackVectorSpec spec(&zone);
  // Set metadata.
  for (int i = 0; i < 40; i++) {
    switch (i % 4) {
      case 0:
        spec.AddForInSlot();
        break;
      case 1:
        spec.AddCallICSlot();
        break;
      case 2:
        spec.AddLoadICSlot();
        break;
      case 3:
        spec.AddKeyedLoadICSlot();
        break;
    }
  }

  Handle<FeedbackVector> vector = NewFeedbackVector(isolate, &spec);
  FeedbackVectorHelper helper(vector);
  CHECK_EQ(40, helper.slot_count());

  // Meanwhile set some feedback values and type feedback values to
  // verify the data structure remains intact.
  vector->SynchronizedSet(FeedbackSlot(0), *vector);

  // Verify the metadata is correctly set up from the spec.
  for (int i = 0; i < 40; i++) {
    FeedbackSlotKind kind = vector->GetKind(helper.slot(i));
    switch (i % 4) {
      case 0:
        CHECK_EQ(FeedbackSlotKind::kForIn, kind);
        break;
      case 1:
        CHECK_EQ(FeedbackSlotKind::kCall, kind);
        break;
      case 2:
        CHECK_EQ(FeedbackSlotKind::kLoadProperty, kind);
        break;
      case 3:
        CHECK_EQ(FeedbackSlotKind::kLoadKeyed, kind);
        break;
    }
  }
}

TEST_F(FeedbackVectorTest, VectorCallICStates) {
  if (!i::v8_flags.use_ic) return;
  if (i::v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;

  v8::HandleScope scope(v8_isolate());
  Isolate* isolate = i_isolate();
  // Make sure function f has a call that uses a type feedback slot.
  TryRunJS(
      "function foo() { return 17; };"
      "%EnsureFeedbackVectorForFunction(f);"
      "function f(a) { a(); } f(foo);");
  DirectHandle<JSFunction> f = GetFunction("f");
  // There should be one IC.
  Handle<FeedbackVector> feedback_vector =
      Handle<FeedbackVector>(f->feedback_vector(), isolate);
  FeedbackSlot slot(0);
  FeedbackNexus nexus(isolate, feedback_vector, slot);
  CHECK_EQ(InlineCacheState::MONOMORPHIC, nexus.ic_state());

  TryRunJS("f(function() { return 16; })");
  CHECK_EQ(InlineCacheState::GENERIC, nexus.ic_state());

  // After a collection, state should remain GENERIC.
  InvokeMajorGC();
  CHECK_EQ(InlineCacheState::GENERIC, nexus.ic_state());
}

// Test the Call IC states transfer with Function.prototype.apply
TEST_F(FeedbackVectorTest, VectorCallICStateApply) {
  if (!i::v8_flags.use_ic) return;
  if (i::v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;

  v8::HandleScope scope(v8_isolate());
  Isolate* isolate = i_isolate();
  // Make sure function f has a call that uses a type feedback slot.
  TryRunJS(
      "var F;"
      "%EnsureFeedbackVectorForFunction(foo);"
      "function foo() { return F.apply(null, arguments); }"
      "F = Math.min;"
      "foo();");
  DirectHandle<JSFunction> foo = GetFunction("foo");
  DirectHandle<JSFunction> F = GetFunction("F");
  Handle<FeedbackVector> feedback_vector =
      Handle<FeedbackVector>(foo->feedback_vector(), isolate);
  FeedbackSlot slot(4);
  FeedbackNexus nexus(i_isolate(), feedback_vector, slot);
  CHECK_EQ(InlineCacheState::MONOMORPHIC, nexus.ic_state());
  CHECK_EQ(CallFeedbackContent::kReceiver, nexus.GetCallFeedbackContent());
  Tagged<HeapObject> heap_object;
  CHECK(nexus.GetFeedback().GetHeapObjectIfWeak(&heap_object));
  CHECK_EQ(*F, heap_object);

  TryRunJS(
      "F = Math.max;"
      "foo();");
  CHECK_EQ(InlineCacheState::MONOMORPHIC, nexus.ic_state());
  CHECK_EQ(CallFeedbackContent::kTarget, nexus.GetCallFeedbackContent());
  CHECK(nexus.GetFeedback().GetHeapObjectIfWeak(&heap_object));
  CHECK_EQ(*isolate->function_prototype_apply(), heap_object);

  TryRunJS(
      "F.apply = (function () { return; });"
      "foo();");
  CHECK_EQ(InlineCacheState::GENERIC, nexus.ic_state());
}

TEST_F(FeedbackVectorTest, VectorCallFeedback) {
  if (!i::v8_flags.use_ic) return;
  if (i::v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;

  v8::HandleScope scope(v8_isolate());
  Isolate* isolate = i_isolate();
  // Make sure function f has a call that uses a type feedback slot.
  TryRunJS(
      "function foo() { return 17; }"
      "%EnsureFeedbackVectorForFunction(f);"
      "function f(a) { a(); } f(foo);");
  DirectHandle<JSFunction> f = GetFunction("f");
  DirectHandle<JSFunction> foo = GetFunction("foo");
  // There should be one IC.
  Handle<FeedbackVector> feedback_vector =
      Handle<FeedbackVector>(f->feedback_vector(), isolate);
  FeedbackSlot slot(0);
  FeedbackNexus nexus(i_isolate(), feedback_vector, slot);

  CHECK_EQ(InlineCacheState::MONOMORPHIC, nexus.ic_state());
  Tagged<HeapObject> heap_object;
  CHECK(nexus.GetFeedback().GetHeapObjectIfWeak(&heap_object));
  CHECK_EQ(*foo, heap_object);

  InvokeMajorGC();
  // It should stay monomorphic even after a GC.
  CHECK_EQ(InlineCacheState::MONOMORPHIC, nexus.ic_state());
}

TEST_F(FeedbackVectorTest, VectorPolymorphicCallFeedback) {
  if (!i::v8_flags.use_ic) return;
  if (i::v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;
  v8_flags.lazy_feedback_allocation = false;

  v8::HandleScope scope(v8_isolate());
  Isolate* isolate = i_isolate();
  // Make sure the call feedback of a() in f() becomes polymorphic.
  TryRunJS(
      "function foo_maker() { return () => { return 17; } }"
      "a_foo = foo_maker();"
      "function f(a) { a(); } f(foo_maker());"
      "f(foo_maker());");
  DirectHandle<JSFunction> f = GetFunction("f");
  DirectHandle<JSFunction> a_foo = GetFunction("a_foo");
  // There should be one IC.
  Handle<FeedbackVector> feedback_vector =
      Handle<FeedbackVector>(f->feedback_vector(), isolate);
  FeedbackSlot slot(0);
  FeedbackNexus nexus(i_isolate(), feedback_vector, slot);

  CHECK_EQ(InlineCacheState::POLYMORPHIC, nexus.ic_state());
  Tagged<HeapObject> heap_object;
  CHECK(nexus.GetFeedback().GetHeapObjectIfWeak(&heap_object));
  CHECK(IsFeedbackCell(heap_object, isolate));
  // Ensure this is the feedback cell for the closure returned by
  // foo_maker.
  CHECK_EQ(heap_object, a_foo->raw_feedback_cell());
}

TEST_F(FeedbackVectorTest, VectorCallFeedbackForArray) {
  if (!i::v8_flags.use_ic) return;
  if (i::v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;

  v8::HandleScope scope(v8_isolate());
  Isolate* isolate = i_isolate();
  // Make sure function f has a call that uses a type feedback slot.
  TryRunJS(
      "function f(a) { a(); };"
      "%EnsureFeedbackVectorForFunction(f);"
      "f(Array);");
  DirectHandle<JSFunction> f = GetFunction("f");
  // There should be one IC.
  Handle<FeedbackVector> feedback_vector =
      Handle<FeedbackVector>(f->feedback_vector(), isolate);
  FeedbackSlot slot(0);
  FeedbackNexus nexus(i_isolate(), feedback_vector, slot);

  CHECK_EQ(InlineCacheState::MONOMORPHIC, nexus.ic_state());
  Tagged<HeapObject> heap_object;
  CHECK(nexus.GetFeedback().GetHeapObjectIfWeak(&heap_object));
  CHECK_EQ(*isolate->array_function(), heap_object);

  InvokeMajorGC();
  // It should stay monomorphic even after a GC.
  CHECK_EQ(InlineCacheState::MONOMORPHIC, nexus.ic_state());
}

TEST_F(FeedbackVectorTest, VectorCallCounts) {
  if (!i::v8_flags.use_ic) return;
  if (i::v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;

  v8::HandleScope scope(v8_isolate());
  Isolate* isolate = i_isolate();

  // Make sure function f has a call that uses a type feedback slot.
  TryRunJS(
      "function foo() { return 17; }"
      "%EnsureFeedbackVectorForFunction(f);"
      "function f(a) { a(); } f(foo);");
  DirectHandle<JSFunction> f = GetFunction("f");
  // There should be one IC.
  Handle<FeedbackVector> feedback_vector =
      Handle<FeedbackVector>(f->feedback_vector(), isolate);
  FeedbackSlot slot(0);
  FeedbackNexus nexus(i_isolate(), feedback_vector, slot);
  CHECK_EQ(InlineCacheState::MONOMORPHIC, nexus.ic_state());

  TryRunJS("f(foo); f(foo);");
  CHECK_EQ(InlineCacheState::MONOMORPHIC, nexus.ic_state());
  CHECK_EQ(3, nexus.GetCallCount());

  // Send the IC megamorphic, but we should still have incrementing counts.
  TryRunJS("f(function() { return 12; });");
  CHECK_EQ(InlineCacheState::GENERIC, nexus.ic_state());
  CHECK_EQ(4, nexus.GetCallCount());
}

TEST_F(FeedbackVectorTest, VectorConstructCounts) {
  if (!i::v8_flags.use_ic) return;
  if (i::v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;

  v8::HandleScope scope(v8_isolate());
  Isolate* isolate = i_isolate();

  // Make sure function f has a call that uses a type feedback slot.
  TryRunJS(
      "function Foo() {}"
      "%EnsureFeedbackVectorForFunction(f);"
      "function f(a) { new a(); } f(Foo);");
  DirectHandle<JSFunction> f = GetFunction("f");
  Handle<FeedbackVector> feedback_vector =
      Handle<FeedbackVector>(f->feedback_vector(), isolate);

  FeedbackSlot slot(0);
  FeedbackNexus nexus(i_isolate(), feedback_vector, slot);
  CHECK_EQ(InlineCacheState::MONOMORPHIC, nexus.ic_state());

  CHECK(feedback_vector->Get(slot).IsWeak());

  TryRunJS("f(Foo); f(Foo);");
  CHECK_EQ(InlineCacheState::MONOMORPHIC, nexus.ic_state());
  CHECK_EQ(3, nexus.GetCallCount());

  // Send the IC megamorphic, but we should still have incrementing counts.
  TryRunJS("f(function() {});");
  CHECK_EQ(InlineCacheState::GENERIC, nexus.ic_state());
  CHECK_EQ(4, nexus.GetCallCount());
}

TEST_F(FeedbackVectorTest, VectorSpeculationMode) {
  if (!i::v8_flags.use_ic) return;
  if (i::v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;

  v8::HandleScope scope(v8_isolate());
  Isolate* isolate = i_isolate();

  // Make sure function f has a call that uses a type feedback slot.
  TryRunJS(
      "function Foo() {}"
      "%EnsureFeedbackVectorForFunction(f);"
      "function f(a) { new a(); } f(Foo);");
  DirectHandle<JSFunction> f = GetFunction("f");
  Handle<FeedbackVector> feedback_vector =
      Handle<FeedbackVector>(f->feedback_vector(), isolate);

  FeedbackSlot slot(0);
  FeedbackNexus nexus(i_isolate(), feedback_vector, slot);
  CHECK_EQ(SpeculationMode::kAllowSpeculation, nexus.GetSpeculationMode());

  TryRunJS("f(Foo); f(Foo);");
  CHECK_EQ(3, nexus.GetCallCount());
  CHECK_EQ(SpeculationMode::kAllowSpeculation, nexus.GetSpeculationMode());

  nexus.SetSpeculationMode(SpeculationMode::kDisallowSpeculation);
  CHECK_EQ(SpeculationMode::kDisallowSpeculation, nexus.GetSpeculationMode());
  CHECK_EQ(3, nexus.GetCallCount());

  nexus.SetSpeculationMode(SpeculationMode::kAllowSpeculation);
  CHECK_EQ(SpeculationMode::kAllowSpeculation, nexus.GetSpeculationMode());
  CHECK_EQ(3, nexus.GetCallCount());
}

TEST_F(FeedbackVectorTest, VectorCallSpeculationModeAndFeedbackContent) {
  if (!i::v8_flags.use_ic) return;
  if (!i::v8_flags.turbofan) return;
  if (i::v8_flags.always_turbofan) return;
  if (i::v8_flags.jitless) return;
  v8_flags.allow_natives_syntax = true;

  v8::HandleScope scope(v8_isolate());
  Isolate* isolate = i_isolate();

  TryRunJS(
      "function min() { return Math.min.apply(null, arguments); }"
      "function f(x) { return min(x, 0); }"
      "%PrepareFunctionForOptimization(min);"
      "%PrepareFunctionForOptimization(f);"
      "f(1);");
  DirectHandle<JSFunction> min = GetFunction("min");
  Handle<FeedbackVector> feedback_vector =
      Handle<FeedbackVector>(min->feedback_vector(), isolate);
  FeedbackSlot slot(6);
  FeedbackNexus nexus(i_isolate(), feedback_vector, slot);

  CHECK_EQ(InlineCacheState::MONOMORPHIC, nexus.ic_state());
  CHECK_EQ(SpeculationMode::kAllowSpeculation, nexus.GetSpeculationMode());
  CHECK_EQ(CallFeedbackContent::kReceiver, nexus.GetCallFeedbackContent());
  TryRunJS("%OptimizeFunctionOnNextCall(f); f(1);");
  CHECK_EQ(InlineCacheState::MONOMORPHIC, nexus.ic_state());
  CHECK_EQ(SpeculationMode::kAllowSpeculation, nexus.GetSpeculationMode());
  CHECK_EQ(CallFeedbackContent::kReceiver, nexus.GetCallFeedbackContent());
  TryRunJS("f({});");  // Deoptimizes.
  CHECK_EQ(InlineCacheState::MONOMORPHIC, nexus.ic_state());
  CHECK_EQ(SpeculationMode::kDisallowSpeculation, nexus.GetSpeculationMode());
  CHECK_EQ(CallFeedbackContent::kReceiver, nexus.GetCallFeedbackContent());
}

TEST_F(FeedbackVectorTest, VectorLoadICStates) {
  if (!i::v8_flags.use_ic) return;
  if (i::v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;

  v8::HandleScope scope(v8_isolate());
  Isolate* isolate = i_isolate();

  // Make sure function f has a call that uses a type feedback slot.
  TryRunJS(
      "var o = { foo: 3 };"
      "%EnsureFeedbackVectorForFunction(f);"
      "function f(a) { return a.foo; } f(o);");
  DirectHandle<JSFunction> f = GetFunction("f");
  // There should be one IC.
  Handle<FeedbackVector> feedback_vector =
      Handle<FeedbackVector>(f->feedback_vector(), isolate);
  FeedbackSlot slot(0);
  FeedbackNexus nexus(i_isolate(), feedback_vector, slot);

  CHECK_EQ(InlineCacheState::MONOMORPHIC, nexus.ic_state());
  // Verify that the monomorphic map is the one we expect.
  v8::MaybeLocal<v8::Value> v8_o =
      v8_context()->Global()->Get(v8_context(), NewString("o"));
  DirectHandle<JSObject> o =
      Cast<JSObject>(v8::Utils::OpenDirectHandle(*v8_o.ToLocalChecked()));
  CHECK_EQ(o->map(), nexus.GetFirstMap());

  // Now go polymorphic.
  TryRunJS("f({ blarg: 3, foo: 2 })");
  CHECK_EQ(InlineCacheState::POLYMORPHIC, nexus.ic_state());

  TryRunJS(
      "delete o.foo;"
      "f(o)");
  CHECK_EQ(InlineCacheState::POLYMORPHIC, nexus.ic_state());

  TryRunJS("f({ blarg: 3, torino: 10, foo: 2 })");
  CHECK_EQ(InlineCacheState::POLYMORPHIC, nexus.ic_state());
  MapHandles maps;
  nexus.ExtractMaps(&maps);
  CHECK_EQ(4, maps.size());

  // Finally driven megamorphic.
  TryRunJS("f({ blarg: 3, gran: 3, torino: 10, foo: 2 })");
  CHECK_EQ(InlineCacheState::MEGAMORPHIC, nexus.ic_state());
  CHECK(nexus.GetFirstMap().is_null());

  // After a collection, state should not be reset to PREMONOMORPHIC.
  InvokeMajorGC();
  CHECK_EQ(InlineCacheState::MEGAMORPHIC, nexus.ic_state());
}

TEST_F(FeedbackVectorTest, VectorLoadGlobalICSlotSharing) {
  if (!i::v8_flags.use_ic) return;
  if (i::v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;

  v8::HandleScope scope(v8_isolate());
  Isolate* isolate = i_isolate();

  // Function f has 5 LoadGlobalICs: 3 for {o} references outside of "typeof"
  // operator and 2 for {o} references inside "typeof" operator.
  TryRunJS(
      "o = 10;"
      "function f() {"
      "  var x = o || 10;"
      "  var y = typeof o;"
      "  return o , typeof o, x , y, o;"
      "}"
      "%EnsureFeedbackVectorForFunction(f);"
      "f();");
  DirectHandle<JSFunction> f = GetFunction("f");
  // There should be two IC slots for {o} references outside and inside
  // typeof operator respectively.
  Handle<FeedbackVector> feedback_vector =
      Handle<FeedbackVector>(f->feedback_vector(), isolate);
  FeedbackVectorHelper helper(feedback_vector);
  CHECK_EQ(4, helper.slot_count());
  CHECK_SLOT_KIND(helper, 0, FeedbackSlotKind::kLoadGlobalNotInsideTypeof);
  CHECK_SLOT_KIND(helper, 1, FeedbackSlotKind::kLoadGlobalInsideTypeof);
  CHECK_SLOT_KIND(helper, 2, FeedbackSlotKind::kTypeOf);
  CHECK_SLOT_KIND(helper, 3, FeedbackSlotKind::kTypeOf);
  FeedbackSlot slot1 = helper.slot(0);
  FeedbackSlot slot2 = helper.slot(1);
  FeedbackSlot slot3 = helper.slot(2);
  FeedbackSlot slot4 = helper.slot(3);
  CHECK_EQ(InlineCacheState::MONOMORPHIC,
           FeedbackNexus(i_isolate(), feedback_vector, slot1).ic_state());
  CHECK_EQ(InlineCacheState::MONOMORPHIC,
           FeedbackNexus(i_isolate(), feedback_vector, slot2).ic_state());
  CHECK_EQ(InlineCacheState::MONOMORPHIC,
           FeedbackNexus(i_isolate(), feedback_vector, slot3).ic_state());
  CHECK_EQ(InlineCacheState::MONOMORPHIC,
           FeedbackNexus(i_isolate(), feedback_vector, slot4).ic_state());
}

TEST_F(FeedbackVectorTest, VectorLoadICOnSmi) {
  if (!i::v8_flags.use_ic) return;
  if (i::v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;

  v8::HandleScope scope(v8_isolate());
  Isolate* isolate = i_isolate();
  Heap* heap = isolate->heap();

  // Make sure function f has a call that uses a type feedback slot.
  TryRunJS(
      "var o = { foo: 3 };"
      "%EnsureFeedbackVectorForFunction(f);"
      "function f(a) { return a.foo; } f(34);");
  DirectHandle<JSFunction> f = GetFunction("f");
  // There should be one IC.
  Handle<FeedbackVector> feedback_vector =
      Handle<FeedbackVector>(f->feedback_vector(), isolate);
  FeedbackSlot slot(0);
  FeedbackNexus nexus(i_isolate(), feedback_vector, slot);
  CHECK_EQ(InlineCacheState::MONOMORPHIC, nexus.ic_state());
  // Verify that the monomorphic map is the one we expect.
  Tagged<Map> number_map = ReadOnlyRoots(heap).heap_number_map();
  CHECK_EQ(number_map, nexus.GetFirstMap());

  // Now go polymorphic on o.
  TryRunJS("f(o)");
  CHECK_EQ(InlineCacheState::POLYMORPHIC, nexus.ic_state());

  MapHandles maps;
  nexus.ExtractMaps(&maps);
  CHECK_EQ(2, maps.size());

  // One of the maps should be the o map.
  v8::MaybeLocal<v8::Value> v8_o =
      v8_context()->Global()->Get(v8_context(), NewString("o"));
  DirectHandle<JSObject> o =
      Cast<JSObject>(v8::Utils::OpenDirectHandle(*v8_o.ToLocalChecked()));
  bool number_map_found = false;
  bool o_map_found = false;
  for (DirectHandle<Map> current : maps) {
    if (*current == number_map)
      number_map_found = true;
    else if (*current == o->map())
      o_map_found = true;
  }
  CHECK(number_map_found && o_map_found);

  // The degree of polymorphism doesn't change.
  TryRunJS("f(100)");
  CHECK_EQ(InlineCacheState::POLYMORPHIC, nexus.ic_state());
  MapHandles maps2;
  nexus.ExtractMaps(&maps2);
  CHECK_EQ(2, maps2.size());
}

TEST_F(FeedbackVectorTest, ReferenceContextAllocatesNoSlots) {
  if (!i::v8_flags.use_ic) return;
  if (i::v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;

  v8::HandleScope scope(v8_isolate());
  Isolate* isolate = i_isolate();

  {
    TryRunJS(
        "function testvar(x) {"
        "  y = x;"
        "  y = a;"
        "  return y;"
        "}"
        "%EnsureFeedbackVectorForFunction(testvar);"
        "a = 3;"
        "testvar({});");

    DirectHandle<JSFunction> f = GetFunction("testvar");

    // There should be two LOAD_ICs, one for a and one for y at the end.
    Handle<FeedbackVector> feedback_vector =
        handle(f->feedback_vector(), isolate);
    FeedbackVectorHelper helper(feedback_vector);
    CHECK_EQ(3, helper.slot_count());
    CHECK_SLOT_KIND(helper, 0, FeedbackSlotKind::kStoreGlobalSloppy);
    CHECK_SLOT_KIND(helper, 1, FeedbackSlotKind::kLoadGlobalNotInsideTypeof);
    CHECK_SLOT_KIND(helper, 2, FeedbackSlotKind::kLoadGlobalNotInsideTypeof);
  }

  {
    TryRunJS(
        "function testprop(x) {"
        "  'use strict';"
        "  x.blue = a;"
        "}"
        "%EnsureFeedbackVectorForFunction(testprop);"
        "testprop({ blue: 3 });");

    DirectHandle<JSFunction> f = GetFunction("testprop");

    // There should be one LOAD_IC, for the load of a.
    Handle<FeedbackVector> feedback_vector(f->feedback_vector(), isolate);
    FeedbackVectorHelper helper(feedback_vector);
    CHECK_EQ(2, helper.slot_count());
    CHECK_SLOT_KIND(helper, 0, FeedbackSlotKind::kLoadGlobalNotInsideTypeof);
    CHECK_SLOT_KIND(helper, 1, FeedbackSlotKind::kSetNamedStrict);
  }

  {
    TryRunJS(
        "function testpropfunc(x) {"
        "  x().blue = a;"
        "  return x().blue;"
        "}"
        "%EnsureFeedbackVectorForFunction(testpropfunc);"
        "function makeresult() { return { blue: 3 }; }"
        "testpropfunc(makeresult);");

    DirectHandle<JSFunction> f = GetFunction("testpropfunc");

    // There should be 1 LOAD_GLOBAL_IC to load x (in both cases), 2 CALL_ICs
    // to call x and a LOAD_IC to load blue.
    Handle<FeedbackVector> feedback_vector(f->feedback_vector(), isolate);
    FeedbackVectorHelper helper(feedback_vector);
    CHECK_EQ(5, helper.slot_count());
    CHECK_SLOT_KIND(helper, 0, FeedbackSlotKind::kCall);
    CHECK_SLOT_KIND(helper, 1, FeedbackSlotKind::kLoadGlobalNotInsideTypeof);
    CHECK_SLOT_KIND(helper, 2, FeedbackSlotKind::kSetNamedSloppy);
    CHECK_SLOT_KIND(helper, 3, FeedbackSlotKind::kCall);
    CHECK_SLOT_KIND(helper, 4, FeedbackSlotKind::kLoadProperty);
  }

  {
    TryRunJS(
        "function testkeyedprop(x) {"
        "  x[0] = a;"
        "  return x[0];"
        "}"
        "%EnsureFeedbackVectorForFunction(testkeyedprop);"
        "testkeyedprop([0, 1, 2]);");

    DirectHandle<JSFunction> f = GetFunction("testkeyedprop");

    // There should be 1 LOAD_GLOBAL_ICs for the load of a, and one
    // KEYED_LOAD_IC for the load of x[0] in the return statement.
    Handle<FeedbackVector> feedback_vector(f->feedback_vector(), isolate);
    FeedbackVectorHelper helper(feedback_vector);
    CHECK_EQ(3, helper.slot_count());
    CHECK_SLOT_KIND(helper, 0, FeedbackSlotKind::kLoadGlobalNotInsideTypeof);
    CHECK_SLOT_KIND(helper, 1, FeedbackSlotKind::kSetKeyedSloppy);
    CHECK_SLOT_KIND(helper, 2, FeedbackSlotKind::kLoadKeyed);
  }

  {
    TryRunJS(
        "function testkeyedprop(x) {"
        "  'use strict';"
        "  x[0] = a;"
        "  return x[0];"
        "}"
        "%EnsureFeedbackVectorForFunction(testkeyedprop);"
        "testkeyedprop([0, 1, 2]);");

    DirectHandle<JSFunction> f = GetFunction("testkeyedprop");

    // There should be 1 LOAD_GLOBAL_ICs for the load of a, and one
    // KEYED_LOAD_IC for the load of x[0] in the return statement.
    Handle<FeedbackVector> feedback_vector(f->feedback_vector(), isolate);
    FeedbackVectorHelper helper(feedback_vector);
    CHECK_EQ(3, helper.slot_count());
    CHECK_SLOT_KIND(helper, 0, FeedbackSlotKind::kLoadGlobalNotInsideTypeof);
    CHECK_SLOT_KIND(helper, 1, FeedbackSlotKind::kSetKeyedStrict);
    CHECK_SLOT_KIND(helper, 2, FeedbackSlotKind::kLoadKeyed);
  }

  {
    TryRunJS(
        "function testcompound(x) {"
        "  'use strict';"
        "  x.old = x.young = x.in_between = a;"
        "  return x.old + x.young;"
        "}"
        "%EnsureFeedbackVectorForFunction(testcompound);"
        "testcompound({ old: 3, young: 3, in_between: 3 });");

    DirectHandle<JSFunction> f = GetFunction("testcompound");

    // There should be 1 LOAD_GLOBAL_IC for load of a and 2 LOAD_ICs, for load
    // of x.old and x.young.
    Handle<FeedbackVector> feedback_vector(f->feedback_vector(), isolate);
    FeedbackVectorHelper helper(feedback_vector);
    CHECK_EQ(7, helper.slot_count());
    CHECK_SLOT_KIND(helper, 0, FeedbackSlotKind::kLoadGlobalNotInsideTypeof);
    CHECK_SLOT_KIND(helper, 1, FeedbackSlotKind::kSetNamedStrict);
    CHECK_SLOT_KIND(helper, 2, FeedbackSlotKind::kSetNamedStrict);
    CHECK_SLOT_KIND(helper, 3, FeedbackSlotKind::kSetNamedStrict);
    CHECK_SLOT_KIND(helper, 4, FeedbackSlotKind::kBinaryOp);
    CHECK_SLOT_KIND(helper, 5, FeedbackSlotKind::kLoadProperty);
    CHECK_SLOT_KIND(helper, 6, FeedbackSlotKind::kLoadProperty);
  }
}

TEST_F(FeedbackVectorTest, VectorStoreICBasic) {
  if (!i::v8_flags.use_ic) return;
  if (i::v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;

  v8::HandleScope scope(v8_isolate());

  TryRunJS(
      "function f(a) {"
      "  a.foo = 5;"
      "};"
      "%EnsureFeedbackVectorForFunction(f);"
      "var a = { foo: 3 };"
      "f(a);"
      "f(a);"
      "f(a);");
  DirectHandle<JSFunction> f = GetFunction("f");
  // There should be one IC slot.
  Handle<FeedbackVector> feedback_vector(f->feedback_vector(), f->GetIsolate());
  FeedbackVectorHelper helper(feedback_vector);
  CHECK_EQ(1, helper.slot_count());
  FeedbackSlot slot(0);
  FeedbackNexus nexus(i_isolate(), feedback_vector, slot);
  CHECK_EQ(InlineCacheState::MONOMORPHIC, nexus.ic_state());
}

TEST_F(FeedbackVectorTest, DefineNamedOwnIC) {
  if (!i::v8_flags.use_ic) return;
  if (i::v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;

  v8::HandleScope scope(v8_isolate());

  TryRunJS(
      "function f(v) {"
      "  return {a: 0, b: v, c: 0};"
      "}"
      "%EnsureFeedbackVectorForFunction(f);"
      "f(1);"
      "f(2);"
      "f(3);");
  DirectHandle<JSFunction> f = GetFunction("f");
  // There should be one IC slot.
  Handle<FeedbackVector> feedback_vector(f->feedback_vector(), f->GetIsolate());
  FeedbackVectorHelper helper(feedback_vector);
  CHECK_EQ(2, helper.slot_count());
  CHECK_SLOT_KIND(helper, 0, FeedbackSlotKind::kLiteral);
  CHECK_SLOT_KIND(helper, 1, FeedbackSlotKind::kDefineNamedOwn);
  FeedbackNexus nexus(i_isolate(), feedback_vector, helper.slot(1));
  CHECK_EQ(InlineCacheState::MONOMORPHIC, nexus.ic_state());
}

}  // namespace internal
}  // namespace v8

"""

```