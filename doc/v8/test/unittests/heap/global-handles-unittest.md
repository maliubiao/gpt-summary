Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Understanding of the Request:**

The request asks for an analysis of a C++ file (`global-handles-unittest.cc`) within the V8 project. The key aspects to identify are its functionality, relationship to JavaScript (if any), code logic, and common programming errors it might relate to. It also mentions Torque files (which this isn't).

**2. Preliminary Scan and Keyword Recognition:**

I'd start by scanning the code for familiar keywords and patterns related to testing and V8 internals.

* **`// Copyright ...`**:  Standard copyright notice, confirming it's V8 code.
* **`#include ...`**:  Lots of includes. I'd look for V8-specific headers like `v8.h`, `v8-embedder-heap.h`, `isolate.h`, `heap-inl.h`, `objects-inl.h`. This strongly indicates interaction with V8's core functionalities.
* **`namespace v8 { namespace internal { ... } }`**:  Confirms it's in V8's internal namespace.
* **`TEST_F(GlobalHandlesTest, ...)`**:  This immediately signals that it's a unit test using Google Test (`gtest`). The test fixture `GlobalHandlesTest` suggests the tests are specifically about global handles.
* **`v8::Isolate*`**:  Frequent use of `v8::Isolate` points to low-level V8 interactions.
* **`v8::HandleScope`**:  Standard V8 idiom for managing local handles.
* **`v8::Local<...>` and `v8::Global<...>` and `v8::Persistent<...>` and `v8::Eternal<...>` and `v8::TracedReference<...>`**: These are the core handle types in V8. The presence of multiple types suggests the tests cover different aspects of handle management.
* **`SetWeak`**: Indicates testing of weak handles and garbage collection interaction.
* **`InvokeMinorGC()`, `InvokeMajorGC()`, `InvokeMemoryReducingMajorGCs()`**: These are explicit garbage collection calls, central to testing handle behavior during GC.
* **`ManualGCScope`**:  Further reinforces the focus on GC control in the tests.
* **`CHECK(...)`, `CHECK_EQ(...)`, `CHECK_IMPLIES(...)`, `ASSERT_...`**: Standard Google Test assertion macros.

**3. Deciphering the Functionality (Core Purpose):**

Based on the keywords, class names (like `GlobalHandlesTest`, `EternalHandles`), and the operations performed in the test cases, the core functionality of this file is clearly **unit testing the behavior of different types of global handles in V8's heap management system.** This includes:

* **Strong Global Handles (`v8::Global`)**: How they keep objects alive.
* **Weak Global Handles (`v8::Global` with `SetWeak`)**: How they allow objects to be garbage collected and the behavior of their callbacks.
* **Eternal Handles (`v8::Eternal`)**: Handles that persist throughout the isolate's lifetime.
* **Persistent Handles (`v8::Persistent`)**: Similar to globals but older API.
* **Traced References (`v8::TracedReference`)**:  Handles managed by the embedder for custom GC integration.
* **Interactions with Garbage Collection (Scavenge/Minor GC and Mark-Compact/Major GC)**: How different handle types behave during different GC phases.
* **Handle Management APIs**: Testing `Get`, `Reset`, `IsEmpty`, and related methods.
* **Move Semantics**: Testing how moving global handles affects their validity.
* **Size Tracking**: Verifying the accounting of memory used by global handles.

**4. Relationship to JavaScript:**

While the code is C++, it directly tests mechanisms that are fundamental to how JavaScript objects are managed within V8. Global handles are essential for:

* **Keeping JavaScript objects alive** when referenced from native code (e.g., V8 Embedder API).
* **Implementing weak references** in JavaScript (e.g., `WeakRef`, `WeakMap`, `WeakSet`).
* **Managing the lifecycle of objects** accessed across the C++/JavaScript boundary.

**5. JavaScript Examples (Mental Translation):**

I'd think about how the C++ concepts map to JavaScript:

* **`v8::Global<v8::Object> g(isolate, object);`**  is like holding a reference to a JavaScript object from outside the JavaScript engine's usual scope. If this were the only reference, and `g` was a regular variable in C++, the GC could still collect it. But a `v8::Global` *prevents* this by rooting the object.
* **`g.SetWeak(...)`**: This is analogous to creating a `WeakRef` in JavaScript. You have a way to refer to an object, but it won't prevent the object from being garbage collected if there are no other strong references. The callback is similar to the finalizer in `WeakRef`.
* **Garbage Collection tests**: These directly relate to when and how JavaScript objects become unreachable and are reclaimed by the garbage collector.

**6. Code Logic and Hypothetical Inputs/Outputs:**

For specific tests, I'd look for patterns:

* **Construction**:  How are the handles created and initialized?
* **Modification (if any)**:  Is the referenced object changed?
* **Weakness Setup**: Is `SetWeak` called, and with what callback?
* **Garbage Collection Invocation**: When are `InvokeMinorGC()` or `InvokeMajorGC()` called?
* **Assertions**: What conditions are being checked after GC?

For example, in `WeakHandleToUnmodifiedJSObjectDiesOnScavenge`:

* **Input (Implicit):**  A newly created JavaScript object.
* **Setup:** A weak handle is created to this object. No other strong references exist (within the test's scope).
* **Action:** A minor GC (scavenge) is performed.
* **Expected Output:** The weak handle becomes empty (the object is collected), and the flag in the callback data is set to true.

**7. Common Programming Errors:**

I'd consider what mistakes developers often make when working with handles:

* **Forgetting to use `HandleScope`**: Leading to leaks or crashes. (While not explicitly tested here, it's a fundamental V8 concept).
* **Holding onto `v8::Local` handles for too long**:  `Local` handles are stack-bound and become invalid after the `HandleScope` exits.
* **Not understanding weak handles**:  Expecting weak handles to keep objects alive, or not properly handling the case where a weak handle becomes empty.
* **Incorrectly using `v8::Persistent` or `v8::Global`**:  Over-rooting objects and preventing garbage collection, leading to memory leaks.
* **Issues with callbacks on weak handles**:  Not handling the potential for the target object to be gone, or errors in the callback logic. The `GCFromWeakCallbacks` test directly addresses this.

**8. Torque Check:**

The request mentions `.tq` files. A quick scan of the filename shows it ends in `.cc`, so it's definitely C++, not Torque.

**9. Structuring the Output:**

Finally, I would organize the findings into the categories requested: functionality, JavaScript relationship, code logic (with examples), and common errors, ensuring clarity and conciseness. I'd also explicitly state that the file is C++ and not a Torque file.The file `v8/test/unittests/heap/global-handles-unittest.cc` is a **C++ unit test file** within the V8 JavaScript engine project. Its primary function is to **test the behavior and correctness of V8's global handle system**.

Here's a breakdown of its functionalities:

**1. Testing Different Types of Global Handles:**

* **`v8::Global<T>`:**  Tests the creation, manipulation, and destruction of strong global handles. These handles prevent garbage collection of the referenced JavaScript object. The tests verify that objects held by strong global handles remain alive across garbage collections.
* **`v8::Weak<T>` (achieved through `global.SetWeak`)**: Tests the functionality of weak global handles. These handles allow the garbage collector to reclaim the referenced object when there are no other strong references. The tests verify that the weak handle becomes empty after garbage collection and that associated weak callbacks are executed.
* **`v8::Eternal<T>`:** Tests handles that are intended to live for the entire lifetime of the V8 isolate. These tests ensure that objects held by eternal handles are never garbage collected.
* **`v8::Persistent<T>`:**  Tests the older persistent handle mechanism, which is similar to global handles.
* **`v8::TracedReference<T>`:** Tests a specific type of handle used by embedders for custom garbage collection integration. These handles are managed outside of V8's main garbage collection but are considered during embedder-driven garbage collection.

**2. Testing Interactions with Garbage Collection:**

* The tests explicitly trigger different types of garbage collection (minor/scavenge and major/mark-compact) using functions like `InvokeMinorGC()`, `InvokeMajorGC()`, and `InvokeMemoryReducingMajorGCs()`.
* They verify how different handle types behave during these garbage collection cycles – whether they keep objects alive or allow them to be collected.

**3. Testing Weak Callbacks:**

* The tests define and use weak callbacks (`v8::WeakCallbackInfo`) associated with weak handles.
* They verify that these callbacks are executed correctly after the garbage collector has determined that the referenced object is no longer strongly reachable.
* They test different types of weak callbacks, including those with second-pass callbacks.

**4. Testing Handle Management APIs:**

* The tests use various methods associated with global handles, such as `Reset()`, `Get()`, `IsEmpty()`, and `SetWeak()`, to ensure they function as expected.

**5. Testing Move Semantics:**

* Tests like `MoveStrongGlobal` and `MoveWeakGlobal` verify that moving global handles (using `std::move`) maintains the handle's validity and the liveness of the referenced object.

**6. Testing Memory Accounting:**

* The `TotalSizeRegularNode` and `TotalSizeTracedNode` tests verify the internal accounting of memory used by the global handle system.

**Regarding the file extension:**

The file ends with `.cc`, indicating it is a **C++ source file**. Therefore, the statement "if v8/test/unittests/heap/global-handles-unittest.cc ended with .tq, it would be a v8 torque source code" is **incorrect** in this case.

**Relationship with JavaScript and JavaScript Examples:**

Global handles in V8 are crucial for the interaction between native C++ code and JavaScript code. They allow C++ code to hold references to JavaScript objects and manage their lifetime.

Here are some JavaScript analogies to the concepts tested in the C++ file:

* **`v8::Global<v8::Object>` (Strong Global Handle):**  Imagine you have a JavaScript object and you want to ensure it's never garbage collected, even if no JavaScript code directly references it anymore. A strong global handle in C++ achieves this.

   ```javascript
   // In C++ (simplified concept)
   v8::Local<v8::Object> jsObject = ...; // Get a local handle to a JS object
   v8::Global<v8::Object> globalHandle(isolate, jsObject);

   // Now, even if jsObject goes out of scope in C++ or is no longer referenced in JS,
   // the object held by globalHandle will not be garbage collected.
   ```

* **`global.SetWeak(...)` (Weak Global Handle):** This is similar to using `WeakRef` in JavaScript. You want to keep a reference to an object, but you don't want to prevent it from being garbage collected if it becomes otherwise unreachable.

   ```javascript
   let myObject = { data: 123 };
   let weakRef = new WeakRef(myObject);

   // ... later, if myObject is no longer used elsewhere ...

   // The garbage collector might reclaim myObject.
   // weakRef.deref() will return undefined if myObject has been collected.
   ```

* **Weak Callbacks:**  When a weak handle's object is garbage collected, a callback function can be triggered. This is analogous to the finalizer function in JavaScript's `WeakRef`.

   ```javascript
   let myObject = { data: 456 };
   let registry = new FinalizationRegistry(heldValue => {
     console.log("Object with value", heldValue, "was garbage collected.");
   });
   registry.register(myObject, myObject.data);
   ```

**Code Logic Reasoning with Hypothetical Input and Output (Example):**

Let's consider the test case `WeakHandleToUnmodifiedJSObjectDiesOnScavenge`.

**Hypothetical Input:**

1. A newly created JavaScript object in the young generation of the heap.
2. A weak global handle (`fp.handle`) is created to this object.
3. No other strong references to this object exist within the scope of the test.

**Code Logic:**

1. `ConstructJSObject(isolate, context, &fp)` creates the JavaScript object and the initial strong global handle (later used to create the weak handle).
2. `fp.handle.SetWeak(...)` makes the handle weak.
3. `InvokeMinorGC()` triggers a minor garbage collection (scavenge).

**Expected Output:**

1. After the minor GC, the object will be garbage collected because there are no strong references to it.
2. The weak handle `fp.handle` will become empty (`fp.flag` will be true after the weak callback is executed).
3. The assertion `CHECK_IMPLIES(survives == SurvivalMode::kDies, fp.flag);` will pass because `survives` is `SurvivalMode::kDies` and `fp.flag` is true.

**Common Programming Errors Illustrated by the Tests:**

While this file primarily *tests* the global handle system, it implicitly highlights potential programming errors that developers might encounter when working with V8's C++ API:

* **Memory Leaks due to Strong Handles:** If a strong global handle is created and never explicitly reset or goes out of scope appropriately, the referenced JavaScript object will never be garbage collected, leading to a memory leak. The tests for strong global handles ensure that these handles behave as expected in preventing garbage collection.
* **Dangling Pointers with Weak Handles:** If you rely on a weak handle still pointing to a valid object without checking `IsEmpty()`, you might access freed memory, leading to crashes. The tests with weak handles and callbacks demonstrate how to properly handle the potential invalidation of weak handles.
* **Incorrect Use of Weak Callbacks:**  Errors in the logic of weak callbacks (e.g., trying to access the now-freed object without checking, or incorrect cleanup) can lead to issues. The tests with weak callbacks verify the correct execution and timing of these callbacks.
* **Misunderstanding Garbage Collection Behavior:** Developers might incorrectly assume that an object will be collected at a specific time or during a specific type of garbage collection. The tests explicitly explore the interaction of handles with different GC phases.

In summary, `v8/test/unittests/heap/global-handles-unittest.cc` is a crucial part of V8's testing infrastructure, ensuring the reliability and correctness of its global handle mechanism, which is fundamental for interoperability between C++ and JavaScript within the engine.

### 提示词
```
这是目录为v8/test/unittests/heap/global-handles-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/global-handles-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2013 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "src/handles/global-handles.h"

#include "include/v8-embedder-heap.h"
#include "include/v8-function.h"
#include "src/api/api-inl.h"
#include "src/execution/isolate.h"
#include "src/flags/flags.h"
#include "src/heap/factory.h"
#include "src/heap/heap-inl.h"
#include "src/objects/objects-inl.h"
#include "test/unittests/heap/heap-utils.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {

namespace {

struct TracedReferenceWrapper {
  v8::TracedReference<v8::Object> handle;
};

class NonRootingEmbedderRootsHandler final : public v8::EmbedderRootsHandler {
 public:
  NonRootingEmbedderRootsHandler() : v8::EmbedderRootsHandler() {}
  void ResetRoot(const v8::TracedReference<v8::Value>& handle) final {
    for (auto* wrapper : wrappers_) {
      if (wrapper->handle == handle) {
        wrapper->handle.Reset();
      }
    }
  }

  void Register(TracedReferenceWrapper* wrapper) {
    wrappers_.push_back(wrapper);
  }

 private:
  std::vector<TracedReferenceWrapper*> wrappers_;
};

void SimpleCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  info.GetReturnValue().Set(v8::Number::New(isolate, 0));
}

struct FlagAndHandles {
  bool flag;
  v8::Global<v8::Object> handle;
  v8::Local<v8::Object> local;
};

void ResetHandleAndSetFlag(const v8::WeakCallbackInfo<FlagAndHandles>& data) {
  data.GetParameter()->handle.Reset();
  data.GetParameter()->flag = true;
}

template <typename HandleContainer>
void ConstructJSObject(v8::Isolate* isolate, v8::Local<v8::Context> context,
                       HandleContainer* flag_and_persistent) {
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::Object> object(v8::Object::New(isolate));
  CHECK(!object.IsEmpty());
  flag_and_persistent->handle.Reset(isolate, object);
  CHECK(!flag_and_persistent->handle.IsEmpty());
}

void ConstructJSObject(v8::Isolate* isolate, v8::Global<v8::Object>* global) {
  v8::HandleScope scope(isolate);
  v8::Local<v8::Object> object(v8::Object::New(isolate));
  CHECK(!object.IsEmpty());
  *global = v8::Global<v8::Object>(isolate, object);
  CHECK(!global->IsEmpty());
}

void ConstructJSObject(v8::Isolate* isolate,
                       v8::TracedReference<v8::Object>* handle) {
  v8::HandleScope scope(isolate);
  v8::Local<v8::Object> object(v8::Object::New(isolate));
  CHECK(!object.IsEmpty());
  *handle = v8::TracedReference<v8::Object>(isolate, object);
  CHECK(!handle->IsEmpty());
}

template <typename HandleContainer>
void ConstructJSApiObject(v8::Isolate* isolate, v8::Local<v8::Context> context,
                          HandleContainer* flag_and_persistent) {
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::FunctionTemplate> fun =
      v8::FunctionTemplate::New(isolate, SimpleCallback);
  v8::Local<v8::Object> object = fun->GetFunction(context)
                                     .ToLocalChecked()
                                     ->NewInstance(context)
                                     .ToLocalChecked();
  CHECK(!object.IsEmpty());
  flag_and_persistent->handle.Reset(isolate, object);
  CHECK(!flag_and_persistent->handle.IsEmpty());
}

enum class SurvivalMode { kSurvives, kDies };

template <typename ConstructFunction, typename ModifierFunction,
          typename GCFunction>
void WeakHandleTest(v8::Isolate* isolate, ConstructFunction construct_function,
                    ModifierFunction modifier_function, GCFunction gc_function,
                    SurvivalMode survives) {
  ManualGCScope manual_gc_scope(reinterpret_cast<internal::Isolate*>(isolate));
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope context_scope(context);

  FlagAndHandles fp;
  construct_function(isolate, context, &fp);
  CHECK(IsNewObjectInCorrectGeneration(isolate, fp.handle));
  fp.handle.SetWeak(&fp, &ResetHandleAndSetFlag,
                    v8::WeakCallbackType::kParameter);
  fp.flag = false;
  modifier_function(&fp);
  gc_function();
  CHECK_IMPLIES(survives == SurvivalMode::kSurvives, !fp.flag);
  CHECK_IMPLIES(survives == SurvivalMode::kDies, fp.flag);
}

void EmptyWeakCallback(const v8::WeakCallbackInfo<void>& data) {}

class GlobalHandlesTest : public TestWithContext {
 protected:
  template <typename ConstructFunction, typename ModifierFunction>
  void TracedReferenceTestWithScavenge(ConstructFunction construct_function,
                                       ModifierFunction modifier_function,
                                       SurvivalMode survives) {
    v8::Isolate* isolate = v8_isolate();
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        i_isolate()->heap());
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope context_scope(context);

    NonRootingEmbedderRootsHandler roots_handler;
    v8_isolate()->SetEmbedderRootsHandler(&roots_handler);

    auto fp = std::make_unique<TracedReferenceWrapper>();
    roots_handler.Register(fp.get());
    construct_function(isolate, context, fp.get());
    CHECK(IsNewObjectInCorrectGeneration(isolate, fp->handle));
    modifier_function(fp.get());
    InvokeMinorGC();
    // Scavenge clear properly resets the original handle, so we can check the
    // handle directly here.
    CHECK_IMPLIES(survives == SurvivalMode::kSurvives, !fp->handle.IsEmpty());
    CHECK_IMPLIES(survives == SurvivalMode::kDies, fp->handle.IsEmpty());

    v8_isolate()->SetEmbedderRootsHandler(nullptr);
  }
};

}  // namespace

TEST_F(GlobalHandlesTest, EternalHandles) {
  Isolate* isolate = i_isolate();
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  EternalHandles* eternal_handles = isolate->eternal_handles();
  DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      isolate->heap());

  // Create a number of handles that will not be on a block boundary
  const int kArrayLength = 2048 - 1;
  int indices[kArrayLength];
  v8::Eternal<v8::Value> eternals[kArrayLength];

  CHECK_EQ(0, eternal_handles->handles_count());
  for (int i = 0; i < kArrayLength; i++) {
    indices[i] = -1;
    HandleScope scope(isolate);
    v8::Local<v8::Object> object = v8::Object::New(v8_isolate);
    object
        ->Set(v8_isolate->GetCurrentContext(), i,
              v8::Integer::New(v8_isolate, i))
        .FromJust();
    // Create with internal api
    eternal_handles->Create(isolate, *v8::Utils::OpenDirectHandle(*object),
                            &indices[i]);
    // Create with external api
    CHECK(eternals[i].IsEmpty());
    eternals[i].Set(v8_isolate, object);
    CHECK(!eternals[i].IsEmpty());
  }

  InvokeMemoryReducingMajorGCs(isolate);

  for (int i = 0; i < kArrayLength; i++) {
    for (int j = 0; j < 2; j++) {
      HandleScope scope(isolate);
      v8::Local<v8::Value> local;
      if (j == 0) {
        // Test internal api
        local = v8::Utils::ToLocal(eternal_handles->Get(indices[i]));
      } else {
        // Test external api
        local = eternals[i].Get(v8_isolate);
      }
      v8::Local<v8::Object> object = v8::Local<v8::Object>::Cast(local);
      v8::Local<v8::Value> value =
          object->Get(v8_isolate->GetCurrentContext(), i).ToLocalChecked();
      CHECK(value->IsInt32());
      CHECK_EQ(i,
               value->Int32Value(v8_isolate->GetCurrentContext()).FromJust());
    }
  }

  CHECK_EQ(2 * kArrayLength, eternal_handles->handles_count());

  // Create an eternal via the constructor
  {
    HandleScope scope(isolate);
    v8::Local<v8::Object> object = v8::Object::New(v8_isolate);
    v8::Eternal<v8::Object> eternal(v8_isolate, object);
    CHECK(!eternal.IsEmpty());
    CHECK(object == eternal.Get(v8_isolate));
  }

  CHECK_EQ(2 * kArrayLength + 1, eternal_handles->handles_count());
}

TEST_F(GlobalHandlesTest, PersistentBaseGetLocal) {
  v8::Isolate* isolate = v8_isolate();

  v8::HandleScope scope(isolate);
  v8::Local<v8::Object> o = v8::Object::New(isolate);
  CHECK(!o.IsEmpty());
  v8::Persistent<v8::Object> p(isolate, o);
  CHECK(o == p.Get(isolate));
  CHECK(v8::Local<v8::Object>::New(isolate, p) == p.Get(isolate));

  v8::Global<v8::Object> g(isolate, o);
  CHECK(o == g.Get(isolate));
  CHECK(v8::Local<v8::Object>::New(isolate, g) == g.Get(isolate));
}

TEST_F(GlobalHandlesTest, WeakPersistentSmi) {
  v8::Isolate* isolate = v8_isolate();

  v8::HandleScope scope(isolate);
  v8::Local<v8::Number> n = v8::Number::New(isolate, 0);
  v8::Global<v8::Number> g(isolate, n);

  // Should not crash.
  g.SetWeak<void>(nullptr, &EmptyWeakCallback,
                  v8::WeakCallbackType::kParameter);
}

TEST_F(GlobalHandlesTest, PhantomHandlesWithoutCallbacks) {
  v8::Isolate* isolate = v8_isolate();
  DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      i_isolate()->heap());

  v8::Global<v8::Object> g1, g2;
  {
    v8::HandleScope scope(isolate);
    g1.Reset(isolate, v8::Object::New(isolate));
    g1.SetWeak();
    g2.Reset(isolate, v8::Object::New(isolate));
    g2.SetWeak();
  }
  CHECK(!g1.IsEmpty());
  CHECK(!g2.IsEmpty());
  InvokeMemoryReducingMajorGCs(i_isolate());
  CHECK(g1.IsEmpty());
  CHECK(g2.IsEmpty());
}

TEST_F(GlobalHandlesTest, WeakHandleToUnmodifiedJSObjectDiesOnScavenge) {
  if (v8_flags.single_generation) return;

  // We need to invoke GC without stack, otherwise the object may survive.
  DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      i_isolate()->heap());

  WeakHandleTest(
      v8_isolate(), &ConstructJSObject<FlagAndHandles>,
      [](FlagAndHandles* fp) {}, [this]() { InvokeMinorGC(); },
      SurvivalMode::kDies);
}

TEST_F(GlobalHandlesTest, TracedReferenceToUnmodifiedJSObjectSurvivesScavenge) {
  if (v8_flags.single_generation) return;

  ManualGCScope manual_gc(i_isolate());
  TracedReferenceTestWithScavenge(
      &ConstructJSObject<TracedReferenceWrapper>,
      [](TracedReferenceWrapper* fp) {}, SurvivalMode::kSurvives);
}

TEST_F(GlobalHandlesTest, WeakHandleToUnmodifiedJSObjectDiesOnMarkCompact) {
  // We need to invoke GC without stack, otherwise the object may survive.
  DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      i_isolate()->heap());

  WeakHandleTest(
      v8_isolate(), &ConstructJSObject<FlagAndHandles>,
      [](FlagAndHandles* fp) {}, [this]() { InvokeMajorGC(); },
      SurvivalMode::kDies);
}

TEST_F(GlobalHandlesTest,
       WeakHandleToUnmodifiedJSObjectSurvivesMarkCompactWhenInHandle) {
  WeakHandleTest(
      v8_isolate(), &ConstructJSObject<FlagAndHandles>,
      [this](FlagAndHandles* fp) {
        fp->local = v8::Local<v8::Object>::New(v8_isolate(), fp->handle);
      },
      [this]() { InvokeMajorGC(); }, SurvivalMode::kSurvives);
}

TEST_F(GlobalHandlesTest, WeakHandleToUnmodifiedJSApiObjectDiesOnScavenge) {
  if (v8_flags.single_generation) return;

  // We need to invoke GC without stack, otherwise the object may survive.
  DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      i_isolate()->heap());

  WeakHandleTest(
      v8_isolate(), &ConstructJSApiObject<FlagAndHandles>,
      [](FlagAndHandles* fp) {}, [this]() { InvokeMinorGC(); },
      SurvivalMode::kDies);
}

TEST_F(GlobalHandlesTest,
       TracedReferenceToJSApiObjectWithIdentityHashSurvivesScavenge) {
  if (v8_flags.single_generation) return;

  ManualGCScope manual_gc(i_isolate());
  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  Handle<JSWeakMap> weakmap = isolate->factory()->NewJSWeakMap();

  TracedReferenceTestWithScavenge(
      &ConstructJSApiObject<TracedReferenceWrapper>,
      [this, &weakmap, isolate](TracedReferenceWrapper* fp) {
        v8::HandleScope scope(v8_isolate());
        Handle<JSReceiver> key =
            Utils::OpenHandle(*fp->handle.Get(v8_isolate()));
        DirectHandle<Smi> smi(Smi::FromInt(23), isolate);
        int32_t hash = Object::GetOrCreateHash(*key, isolate).value();
        JSWeakCollection::Set(weakmap, key, smi, hash);
      },
      SurvivalMode::kSurvives);
}

TEST_F(GlobalHandlesTest,
       WeakHandleToUnmodifiedJSApiObjectSurvivesScavengeWhenInHandle) {
  if (v8_flags.single_generation) return;

  WeakHandleTest(
      v8_isolate(), &ConstructJSApiObject<FlagAndHandles>,
      [this](FlagAndHandles* fp) {
        fp->local = v8::Local<v8::Object>::New(v8_isolate(), fp->handle);
      },
      [this]() { InvokeMinorGC(); }, SurvivalMode::kSurvives);
}

TEST_F(GlobalHandlesTest, WeakHandleToUnmodifiedJSApiObjectDiesOnMarkCompact) {
  // We need to invoke GC without stack, otherwise the object may survive.
  DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      i_isolate()->heap());

  WeakHandleTest(
      v8_isolate(), &ConstructJSApiObject<FlagAndHandles>,
      [](FlagAndHandles* fp) {}, [this]() { InvokeMajorGC(); },
      SurvivalMode::kDies);
}

TEST_F(GlobalHandlesTest,
       WeakHandleToUnmodifiedJSApiObjectSurvivesMarkCompactWhenInHandle) {
  WeakHandleTest(
      v8_isolate(), &ConstructJSApiObject<FlagAndHandles>,
      [this](FlagAndHandles* fp) {
        fp->local = v8::Local<v8::Object>::New(v8_isolate(), fp->handle);
      },
      [this]() { InvokeMajorGC(); }, SurvivalMode::kSurvives);
}

TEST_F(GlobalHandlesTest,
       TracedReferenceToJSApiObjectWithModifiedMapSurvivesScavenge) {
  if (v8_flags.single_generation) return;

  v8::Isolate* isolate = v8_isolate();

  TracedReference<v8::Object> handle;
  {
    v8::HandleScope scope(isolate);
    // Create an API object which does not have the same map as constructor.
    auto function_template = FunctionTemplate::New(isolate);
    auto instance_t = function_template->InstanceTemplate();
    instance_t->Set(isolate, "a", v8::Number::New(isolate, 10));
    auto function =
        function_template->GetFunction(v8_context()).ToLocalChecked();
    auto i = function->NewInstance(v8_context()).ToLocalChecked();
    handle.Reset(isolate, i);
  }
  InvokeMinorGC();
  CHECK(!handle.IsEmpty());
}

TEST_F(GlobalHandlesTest,
       TracedReferenceTOJsApiObjectWithElementsSurvivesScavenge) {
  if (v8_flags.single_generation) return;

  v8::Isolate* isolate = v8_isolate();

  TracedReference<v8::Object> handle;
  {
    v8::HandleScope scope(isolate);

    // Create an API object which has elements.
    auto function_template = FunctionTemplate::New(isolate);
    auto instance_t = function_template->InstanceTemplate();
    instance_t->Set(isolate, "1", v8::Number::New(isolate, 10));
    instance_t->Set(isolate, "2", v8::Number::New(isolate, 10));
    auto function =
        function_template->GetFunction(v8_context()).ToLocalChecked();
    auto i = function->NewInstance(v8_context()).ToLocalChecked();
    handle.Reset(isolate, i);
  }
  InvokeMinorGC();
  CHECK(!handle.IsEmpty());
}

namespace {

void ForceMinorGC2(const v8::WeakCallbackInfo<FlagAndHandles>& data) {
  data.GetParameter()->flag = true;
  InvokeMinorGC(reinterpret_cast<Isolate*>(data.GetIsolate()));
}

void ForceMinorGC1(const v8::WeakCallbackInfo<FlagAndHandles>& data) {
  data.GetParameter()->handle.Reset();
  data.SetSecondPassCallback(ForceMinorGC2);
}

void ForceMajorGC2(const v8::WeakCallbackInfo<FlagAndHandles>& data) {
  data.GetParameter()->flag = true;
  InvokeMajorGC(reinterpret_cast<Isolate*>(data.GetIsolate()));
}

void ForceMajorGC1(const v8::WeakCallbackInfo<FlagAndHandles>& data) {
  data.GetParameter()->handle.Reset();
  data.SetSecondPassCallback(ForceMajorGC2);
}

}  // namespace

TEST_F(GlobalHandlesTest, GCFromWeakCallbacks) {
  v8::Isolate* isolate = v8_isolate();
  ManualGCScope manual_gc_scope(i_isolate());
  DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      i_isolate()->heap());
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope context_scope(context);

  if (v8_flags.single_generation) {
    FlagAndHandles fp;
    ConstructJSApiObject(isolate, context, &fp);
    CHECK_IMPLIES(!v8_flags.single_generation,
                  !InYoungGeneration(isolate, fp.handle));
    fp.flag = false;
    fp.handle.SetWeak(&fp, &ForceMajorGC1, v8::WeakCallbackType::kParameter);
    InvokeMajorGC();
    EmptyMessageQueues();
    CHECK(fp.flag);
    return;
  }

  static const int kNumberOfGCTypes = 2;
  using Callback = v8::WeakCallbackInfo<FlagAndHandles>::Callback;
  Callback gc_forcing_callback[kNumberOfGCTypes] = {&ForceMinorGC1,
                                                    &ForceMajorGC1};

  using GCInvoker = std::function<void(void)>;
  GCInvoker invoke_gc[kNumberOfGCTypes] = {[this]() { InvokeMinorGC(); },
                                           [this]() { InvokeMajorGC(); }};

  for (int outer_gc = 0; outer_gc < kNumberOfGCTypes; outer_gc++) {
    for (int inner_gc = 0; inner_gc < kNumberOfGCTypes; inner_gc++) {
      FlagAndHandles fp;
      ConstructJSApiObject(isolate, context, &fp);
      CHECK(InYoungGeneration(isolate, fp.handle));
      fp.flag = false;
      fp.handle.SetWeak(&fp, gc_forcing_callback[inner_gc],
                        v8::WeakCallbackType::kParameter);
      invoke_gc[outer_gc]();
      EmptyMessageQueues();
      CHECK(fp.flag);
    }
  }
}

namespace {

void SecondPassCallback(const v8::WeakCallbackInfo<FlagAndHandles>& data) {
  data.GetParameter()->flag = true;
}

void FirstPassCallback(const v8::WeakCallbackInfo<FlagAndHandles>& data) {
  data.GetParameter()->handle.Reset();
  data.SetSecondPassCallback(SecondPassCallback);
}

}  // namespace

TEST_F(GlobalHandlesTest, SecondPassPhantomCallbacks) {
  v8::Isolate* isolate = v8_isolate();
  DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      i_isolate()->heap());
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope context_scope(context);
  FlagAndHandles fp;
  ConstructJSApiObject(isolate, context, &fp);
  fp.flag = false;
  fp.handle.SetWeak(&fp, FirstPassCallback, v8::WeakCallbackType::kParameter);
  CHECK(!fp.flag);
  InvokeMajorGC();
  InvokeMajorGC();
  CHECK(fp.flag);
}

TEST_F(GlobalHandlesTest, MoveStrongGlobal) {
  v8::Isolate* isolate = v8_isolate();
  v8::HandleScope scope(isolate);

  v8::Global<v8::Object>* global = new Global<v8::Object>();
  ConstructJSObject(isolate, global);
  InvokeMajorGC();
  v8::Global<v8::Object> global2(std::move(*global));
  delete global;
  InvokeMajorGC();
}

TEST_F(GlobalHandlesTest, MoveWeakGlobal) {
  v8::Isolate* isolate = v8_isolate();
  v8::HandleScope scope(isolate);

  v8::Global<v8::Object>* global = new Global<v8::Object>();
  ConstructJSObject(isolate, global);
  InvokeMajorGC();
  global->SetWeak();
  v8::Global<v8::Object> global2(std::move(*global));
  delete global;
  InvokeMajorGC();
}

TEST_F(GlobalHandlesTest, TotalSizeRegularNode) {
  v8::Isolate* isolate = v8_isolate();
  v8::HandleScope scope(isolate);

  // This is not necessarily zero, if the implementation of tests uses global
  // handles.
  size_t initial_total = i_isolate()->global_handles()->TotalSize();
  size_t initial_used = i_isolate()->global_handles()->UsedSize();

  v8::Global<v8::Object>* global = new Global<v8::Object>();
  CHECK_EQ(i_isolate()->global_handles()->TotalSize(), initial_total);
  CHECK_EQ(i_isolate()->global_handles()->UsedSize(), initial_used);
  ConstructJSObject(isolate, global);
  CHECK_GE(i_isolate()->global_handles()->TotalSize(), initial_total);
  CHECK_GT(i_isolate()->global_handles()->UsedSize(), initial_used);
  delete global;
  CHECK_GE(i_isolate()->global_handles()->TotalSize(), initial_total);
  CHECK_EQ(i_isolate()->global_handles()->UsedSize(), initial_used);
}

TEST_F(GlobalHandlesTest, TotalSizeTracedNode) {
  ManualGCScope manual_gc(i_isolate());
  v8::Isolate* isolate = v8_isolate();
  v8::HandleScope scope(isolate);

  v8::TracedReference<v8::Object>* handle = new TracedReference<v8::Object>();
  CHECK_EQ(i_isolate()->traced_handles()->total_size_bytes(), 0);
  CHECK_EQ(i_isolate()->traced_handles()->used_size_bytes(), 0);
  ConstructJSObject(isolate, handle);
  CHECK_GT(i_isolate()->traced_handles()->total_size_bytes(), 0);
  CHECK_GT(i_isolate()->traced_handles()->used_size_bytes(), 0);
  delete handle;
  InvokeMajorGC();
  CHECK_GT(i_isolate()->traced_handles()->total_size_bytes(), 0);
  CHECK_EQ(i_isolate()->traced_handles()->used_size_bytes(), 0);
}

}  // namespace internal
}  // namespace v8
```