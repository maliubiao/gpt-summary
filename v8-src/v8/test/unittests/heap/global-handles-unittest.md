Response: Let's break down the thought process to arrive at the summary and JavaScript examples for the `global-handles-unittest.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the C++ file and its relationship to JavaScript, illustrated with JavaScript examples. This means I need to identify the core concepts being tested in the C++ code and how those concepts manifest in the JavaScript API.

2. **Initial Scan for Keywords:**  I'll scan the code for prominent keywords and terms. "Global Handles," "Weak Handles," "Persistent," "Eternal Handles," "TracedReference," "GC," "Isolate," "Context," "Object," "Function," "WeakCallback." These keywords immediately suggest the file is about V8's mechanisms for managing JavaScript objects' lifetimes and preventing premature garbage collection.

3. **Identify Major Concepts (Mental Grouping):** I'll group related tests and structures to identify the key features being tested:

    * **Eternal Handles:** The test `EternalHandles` directly deals with `v8::Eternal`. This suggests a way to hold onto JavaScript objects indefinitely.
    * **Persistent/Global Handles:** The tests `PersistentBaseGetLocal`, `WeakPersistentSmi`, `PhantomHandlesWithoutCallbacks`, `MoveStrongGlobal`, `MoveWeakGlobal`, and parts of `TotalSizeRegularNode` involve `v8::Persistent` and `v8::Global`. These seem to be the standard ways to keep references to JavaScript objects from C++. The "Weak" prefix signifies handles that don't prevent garbage collection.
    * **Weak Handles and Garbage Collection:**  Several tests (`WeakHandleToUnmodifiedJSObjectDiesOnScavenge`, `WeakHandleToUnmodifiedJSObjectDiesOnMarkCompact`, `WeakHandleToUnmodifiedJSApiObjectDiesOnScavenge`, `WeakHandleToUnmodifiedJSApiObjectDiesOnMarkCompact`, `GCFromWeakCallbacks`, `SecondPassPhantomCallbacks`) are specifically about how weak handles behave during different types of garbage collection (scavenge/minor and mark-compact/major). The callbacks are crucial here.
    * **Traced References:**  Tests like `TracedReferenceToUnmodifiedJSObjectSurvivesScavenge`, `TracedReferenceToJSApiObjectWithIdentityHashSurvivesScavenge`, `TracedReferenceToJSApiObjectWithModifiedMapSurvivesScavenge`, `TracedReferenceTOJsApiObjectWithElementsSurvivesScavenge`, and `TotalSizeTracedNode` focus on `v8::TracedReference`. This appears to be another mechanism for holding onto objects, potentially with different GC implications than weak globals. The "Traced" suggests involvement in the garbage collection tracing process.
    * **Embedder Roots:** The `NonRootingEmbedderRootsHandler` class suggests a mechanism for managing how the embedding application (the environment V8 runs in) can influence garbage collection.

4. **Infer Functionality:** Based on the tests and keywords, I can start inferring the purpose of the file:

    * **Testing different types of handles:** The file tests the behavior of various handle types (`Eternal`, `Persistent`, `Global`, `Weak<T>`, `TracedReference`) under different conditions.
    * **Testing interaction with garbage collection:**  A major focus is on how these handles interact with V8's garbage collection, specifically whether they prevent collection and how weak handles get cleared.
    * **Testing weak callbacks:**  The presence of weak callback tests indicates that these callbacks are a core mechanism for being notified when weakly referenced objects are about to be collected.
    * **Testing move semantics:** The `MoveStrongGlobal` and `MoveWeakGlobal` tests ensure that moving these handle objects in C++ doesn't break their functionality.
    * **Testing memory accounting:** The `TotalSizeRegularNode` and `TotalSizeTracedNode` tests verify the memory usage tracking for different handle types.

5. **Relate to JavaScript:** Now I need to connect these C++ concepts to their JavaScript counterparts.

    * **Global/Persistent Handles:** These directly correspond to keeping a reference to a JavaScript object in your embedding application. If you hold a `v8::Global` or `v8::Persistent`, the JavaScript object won't be garbage collected *as long as the handle is alive*.
    * **Weak Handles:** These map to the concept of `WeakRef` in JavaScript (though `WeakRef` is a more recent addition than the C++ weak handle mechanism). A `WeakRef` allows you to hold a reference to an object without preventing its collection.
    * **Eternal Handles:**  There isn't a direct JavaScript equivalent for *truly* eternal handles. JavaScript's garbage collection will eventually reclaim unreachable objects. Perhaps the closest analogy would be attaching a property to the global object, although that's not quite the same semantically in terms of V8's internal management.
    * **Traced References:**  These are more of an internal V8 optimization and don't have a direct JavaScript API counterpart. They are about how V8's embedder can participate in the garbage collection process.

6. **Construct JavaScript Examples:**  Now, create concrete JavaScript examples to illustrate the C++ concepts:

    * **Global/Persistent:** Show how creating a variable in the embedding environment (implicitly through the V8 API) keeps an object alive.
    * **Weak Handles:** Use `WeakRef` to demonstrate how an object can be held weakly and might be collected. Explain the callback mechanism conceptually, even if the direct callback isn't exposed in the same way.
    * **Eternal Handles:**  Explain that there isn't a direct equivalent, but discuss the idea of long-lived references.

7. **Refine and Organize:**  Organize the findings into a clear summary, listing the main functionalities tested. Then provide the JavaScript examples with clear explanations of how they relate to the C++ concepts. Ensure the language is accessible and avoids overly technical V8-specific jargon where possible.

8. **Review:** Finally, review the summary and examples to ensure accuracy and clarity. Double-check that the JavaScript examples accurately reflect the underlying C++ behavior being tested. For instance, make sure the explanation of weak handles and `WeakRef` is correct.

By following these steps, I can effectively analyze the C++ code and translate its functionality and purpose into a comprehensible explanation with relevant JavaScript examples. The key is to identify the core concepts being tested and then map those concepts to their closest analogies or counterparts in the JavaScript world.
这个C++源代码文件 `global-handles-unittest.cc` 是 V8 JavaScript 引擎的一部分，它专门用于测试 V8 堆中 **全局句柄 (Global Handles)** 的功能和行为。

**核心功能归纳:**

这个文件主要测试以下与全局句柄相关的特性：

1. **全局句柄的创建和访问:**  测试如何创建和访问不同类型的全局句柄，包括 `v8::Global`, `v8::Eternal`, 和 `v8::TracedReference`。这些句柄允许 C++ 代码持有对 JavaScript 对象的引用，防止这些对象被垃圾回收器过早回收。

2. **弱全局句柄 (Weak Global Handles):**  重点测试弱全局句柄的行为，包括：
   - **垃圾回收时的清理:**  验证当没有其他强引用指向弱句柄所引用的 JavaScript 对象时，该弱句柄会被正确地清除（reset）。
   - **弱回调 (Weak Callbacks):** 测试与弱句柄关联的回调函数在对象即将被回收时被调用的机制，以及回调函数的各种参数和行为。
   - **不同类型的垃圾回收的影响:**  测试弱句柄在 Minor GC (Scavenge) 和 Major GC (Mark-Compact) 时的不同表现。

3. **跟踪引用 (TracedReference):** 测试 `v8::TracedReference` 的行为，这是一种特殊的全局句柄，它参与垃圾回收的标记阶段，但并不总是阻止对象被回收。测试其在 Scavenge GC 中的存活情况。

4. **持久句柄 (Persistent Handles):**  测试 `v8::Persistent` 的基本功能，例如获取本地句柄。

5. **永生句柄 (Eternal Handles):**  测试 `v8::Eternal`，这是一种用于持有永远不会被垃圾回收的 JavaScript 对象的句柄。

6. **移动语义 (Move Semantics):** 测试全局句柄的移动构造和移动赋值是否正确工作。

7. **内存占用 (Memory Footprint):** 测试全局句柄的内存占用情况。

8. **嵌套回调和强制 GC:** 测试在弱回调函数中触发垃圾回收是否会导致问题。

**与 JavaScript 的关系及 JavaScript 示例:**

全局句柄是 V8 引擎提供给宿主环境（例如 Node.js 或 Chrome 浏览器）的一种机制，用于在 C++ 代码中管理 JavaScript 对象的生命周期。  它们对于在 C++ 和 JavaScript 之间传递对象引用至关重要。

以下用 JavaScript 示例来说明一些测试的功能：

**1. 全局句柄防止垃圾回收:**

```javascript
// 在 C++ 端创建全局句柄指向这个 JavaScript 对象
let myObject = { value: 10 };

// ... 一段时间后，即使在 JavaScript 中没有强引用指向 myObject，
// 由于 C++ 端持有全局句柄，myObject 也不会被垃圾回收。
```

**C++ 代码 (概念性):**

```c++
v8::Isolate* isolate = ...;
v8::HandleScope handle_scope(isolate);
v8::Local<v8::Object> localObject = ...; // 获取 JavaScript 的 myObject
v8::Global<v8::Object> globalHandle(isolate, localObject);

// 即使在 JavaScript 中 myObject 变得不可达，只要 globalHandle 存在，
// 该对象就不会被回收。
```

**2. 弱全局句柄和弱回调:**

```javascript
let myWeaklyHeldObject = { data: "sensitive" };

// 在 C++ 端创建一个指向 myWeaklyHeldObject 的弱全局句柄，
// 并设置一个回调函数，当对象即将被回收时执行。

// ... 当 JavaScript 中不再有强引用指向 myWeaklyHeldObject 时，
// 垃圾回收器可能会回收它。此时，C++ 端设置的弱回调函数会被调用。
```

**C++ 代码 (概念性):**

```c++
v8::Isolate* isolate = ...;
v8::HandleScope handle_scope(isolate);
v8::Local<v8::Object> localObject = ...; // 获取 JavaScript 的 myWeaklyHeldObject

struct CallbackData {
  // ... 一些需要传递给回调函数的数据
};

CallbackData* data = new CallbackData();
v8::Global<v8::Object> weakHandle(isolate, localObject);
weakHandle.SetWeak(data, [](const v8::WeakCallbackInfo<CallbackData>& info) {
  CallbackData* data = info.GetParameter();
  // 当 myWeaklyHeldObject 即将被回收时，这里会被调用
  std::cout << "Object about to be garbage collected!" << std::endl;
  delete data;
}, v8::WeakCallbackType::kParameter);

// ... 当 JavaScript 对象被回收后，weakHandle 会被重置，
// 并且回调函数会被调用。
```

**3. 永生句柄:**

```javascript
// 在 C++ 端创建永生句柄指向一个 JavaScript 对象。
let myEternalObject = { type: "important" };

// ... 即使在 JavaScript 中没有任何引用指向 myEternalObject，
// 由于 C++ 端持有永生句柄，该对象永远不会被垃圾回收。
```

**C++ 代码 (概念性):**

```c++
v8::Isolate* isolate = ...;
v8::HandleScope handle_scope(isolate);
v8::Local<v8::Object> localObject = ...; // 获取 JavaScript 的 myEternalObject
v8::Eternal<v8::Object> eternalHandle(isolate, localObject);

// myEternalObject 将永远不会被 V8 的垃圾回收器回收，
// 除非 eternalHandle 被显式释放。
```

**总结:**

`global-handles-unittest.cc` 通过各种测试用例，确保 V8 引擎提供的全局句柄机制能够正确地管理 JavaScript 对象的生命周期，特别是在 C++ 宿主环境与 JavaScript 代码交互时，能够可靠地控制对象的存活和回收，并提供必要的通知机制（弱回调）。这对于构建基于 V8 的应用（如 Node.js 扩展、Chrome 浏览器功能等）至关重要。

Prompt: 
```
这是目录为v8/test/unittests/heap/global-handles-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```