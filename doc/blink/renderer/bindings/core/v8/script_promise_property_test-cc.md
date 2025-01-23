Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding and Goal:**

The first step is to recognize that this is a C++ test file within the Chromium Blink rendering engine. The filename `script_promise_property_test.cc` immediately suggests it's testing a component named `ScriptPromiseProperty`. The core goal is to understand what this `ScriptPromiseProperty` does and how the tests verify its functionality.

**2. Identifying Key Classes and Concepts:**

Scanning the `#include` directives and the code reveals several important classes and concepts:

* **`ScriptPromiseProperty`:** This is the central class being tested.
* **`ScriptPromise`:**  Promises are a fundamental concept in JavaScript for handling asynchronous operations. The interaction with `ScriptPromise` is a primary focus.
* **`v8`:** This refers to the V8 JavaScript engine, which Blink uses. The presence of `v8::...` types indicates direct interaction with the engine.
* **`ScriptState`:**  Represents the execution state of a JavaScript context. This is crucial for managing different JavaScript worlds (e.g., main world, isolated worlds).
* **`DOMWrapperWorld`:**  Represents different JavaScript execution environments or "worlds."  This is important in the context of extensions or isolated contexts within a browser.
* **`ExecutionContext`:** A broader concept representing the context of execution, which can be a document, worker, etc.
* **`ThenCallable`:** A template likely used for defining the actions to be performed when a promise is resolved or rejected (similar to `.then()` in JavaScript).
* **`GarbageCollectedScriptWrappable`:** A base class for objects that are managed by Blink's garbage collector and can be exposed to JavaScript.
* **`DummyPageHolder`:**  A testing utility to set up a basic page environment.

**3. Deciphering Test Structure and Logic:**

The code uses Google Test (`TEST_F`). Each `TEST_F` function tests a specific aspect of `ScriptPromiseProperty`. I'll look for patterns in how these tests are structured:

* **Setup:** Creating instances of `ScriptPromiseProperty`, often within a `GarbageCollectedHolder`. Sometimes creating multiple properties in different worlds.
* **Action:** Performing actions on the `ScriptPromiseProperty`, such as:
    * Calling `Promise()` to get the associated `ScriptPromise`.
    * Calling `Resolve()` or `Reject()` to settle the promise.
    * Calling `Reset()` to reset the property.
    * Calling `MarkAsHandled()` to influence promise rejection handling.
* **Verification:**  Using `EXPECT_...` macros to assert the expected outcomes. This includes:
    * Checking the state of the `ScriptPromiseProperty` (pending, resolved, rejected).
    * Checking the state of the `ScriptPromise` (handled, creation context).
    * Verifying that resolve/reject callbacks are called the correct number of times with the correct arguments.
    * Testing garbage collection behavior.

**4. Connecting to JavaScript/Web Concepts:**

At this point, I'd start making connections to how these C++ concepts relate to JavaScript:

* **Promises:** The core concept is the same as JavaScript Promises. The C++ `ScriptPromise` mirrors the behavior of `Promise` objects in JavaScript.
* **`.then()`:** The `ThenCallable` classes are essentially mimicking the `.then()` method of JavaScript Promises, allowing for chaining of actions upon resolution or rejection.
* **Asynchronous Operations:**  Promises are used for managing asynchronous operations, so this C++ code is likely part of the infrastructure that supports asynchronous JavaScript APIs in the browser.
* **Global Scope/Worlds:** The concept of `DOMWrapperWorld` is tied to JavaScript's global scope. Testing interactions across different worlds is important for ensuring proper isolation and behavior in scenarios like extensions or iframes.
* **Garbage Collection:**  JavaScript has automatic garbage collection. The tests involving `GCObservation` verify that `ScriptPromiseProperty` doesn't introduce memory leaks or prevent garbage collection of related objects.
* **Unhandled Rejections:** The `MarkAsHandled()` tests relate to how JavaScript handles promise rejections that don't have a corresponding `.catch()` or rejection handler.

**5. Logical Deduction and Hypothetical Scenarios:**

Now, I can start thinking about potential inputs and outputs and how different scenarios would play out:

* **Multiple `Promise()` calls:** The tests verify that calling `Promise()` multiple times returns the same `ScriptPromise` instance *within the same world*. Across different worlds, different promise instances are expected.
* **Resolution/Rejection Order:** Although not explicitly tested in *this* file, I would consider how the order of `Resolve`/`Reject` and setting up `.then()` handlers might affect the outcome. This could lead to further test ideas.
* **Garbage Collection and Promise State:**  A key aspect is that a settled promise (resolved or rejected) generally doesn't prevent the garbage collection of its associated data *once there are no other strong references*. The tests with `GCObservation` explore this.
* **Dead Contexts:**  The tests with `DestroyContext()` check how the `ScriptPromiseProperty` behaves when the JavaScript execution environment is destroyed. This is crucial for preventing crashes or unexpected behavior.

**6. Identifying Potential Errors and Debugging Hints:**

Based on my understanding, I can identify potential user errors or common programming mistakes:

* **Forgetting to handle rejections:**  If a promise is rejected and there's no rejection handler, JavaScript will typically issue an unhandled rejection warning. The `MarkAsHandled()` tests are relevant here.
* **Incorrectly assuming promise identity across worlds:** Developers might mistakenly assume that promises obtained from the same `ScriptPromiseProperty` in different worlds are the same object. The tests highlight that they are distinct.
* **Creating memory leaks with unresolved promises:** While `ScriptPromiseProperty` itself appears designed to avoid leaks, incorrect usage or complex object graphs could still lead to memory issues if promises are kept alive indefinitely.
* **Race conditions in asynchronous code:**  Because promises deal with asynchronicity, race conditions are a common concern. While this file doesn't directly test race conditions, it's a related area to keep in mind.

**7. Tracing User Actions (Debugging Clues):**

To understand how a user might reach this code, I'd consider the following:

* **JavaScript API Usage:**  A web developer using a JavaScript API that relies on promises under the hood is the most likely path. For example, `fetch()`, `async/await`, IndexedDB operations, or custom APIs implemented using promises.
* **Blink Internals:** This code is part of Blink, so any internal Blink component that needs a way to manage a single promise associated with an object could use `ScriptPromiseProperty`.
* **Debugging Scenario:** If a developer is seeing unexpected promise behavior (e.g., a `.then()` handler not being called, unhandled rejection errors), they might investigate the underlying C++ code in Blink to understand how promises are being managed. Setting breakpoints in this test file or the `ScriptPromiseProperty` source code could be part of that debugging process.

**Self-Correction/Refinement during the Process:**

* **Initial focus might be too narrow:** I might initially focus too much on the `ScriptPromiseProperty` class itself. I need to broaden my perspective to understand its interaction with `ScriptPromise`, the V8 engine, and the concept of JavaScript worlds.
* **Overlooking the "test" aspect:** It's important to remember that this is a *test* file. The tests themselves provide valuable clues about the intended functionality and edge cases. Analyzing the assertions is key.
* **Jargon and Internal Knowledge:**  Blink has its own terminology (e.g., `DOMWrapperWorld`, `GarbageCollectedScriptWrappable`). I might need to look up the definitions of these terms to fully grasp the code.

By following this structured approach, I can systematically analyze the C++ test file and extract the necessary information to answer the prompt effectively.
这个C++文件 `script_promise_property_test.cc` 是 Chromium Blink 引擎中用于测试 `ScriptPromiseProperty` 类的单元测试。`ScriptPromiseProperty` 是 Blink 中一个用于管理与特定对象关联的 JavaScript Promise 的工具类。

**功能列举:**

1. **测试 `ScriptPromiseProperty` 的基本功能:**
   - 创建和获取关联的 `ScriptPromise` 对象。
   - 在不同的 JavaScript 执行环境 (Worlds) 中获取 Promise。
   - 验证在相同 World 中多次获取 Promise 返回的是同一个对象。
   - 验证在不同 World 中获取 Promise 返回的是不同的对象。
   - 测试 Promise 对象在 Promise 状态变化后的稳定性。

2. **测试 Promise 的解析 (Resolve) 和拒绝 (Reject):**
   - 验证调用 `Resolve` 后，与该 Property 关联的所有 Promise 都会被解析，并且其 `then` 回调会被执行。
   - 验证调用 `Reject` 后，与该 Property 关联的所有 Promise 都会被拒绝，并且其 `catch` (或者 `then` 的第二个参数) 回调会被执行。
   - 测试在不同的 JavaScript World 中解析和拒绝 Promise 的行为。

3. **测试 `ScriptPromiseProperty` 的生命周期和垃圾回收:**
   - 验证即使存在对 Promise 的引用，当 `ScriptPromiseProperty` 持有的对象被回收时，Promise 也不会阻止垃圾回收。
   - 测试在关联的 ExecutionContext (例如 Window) 被销毁后，获取 Promise 的行为 (应该返回空 Promise)。
   - 测试在关联的 ExecutionContext 被销毁后，尝试解析 Promise 的行为 (应该不会触发回调)。

4. **测试 `ScriptPromiseProperty` 的重置 (Reset):**
   - 验证 `Reset` 操作会创建一个新的 Promise，并且之前的 Promise 的状态和回调不会影响新的 Promise。

5. **测试 `MarkAsHandled` 功能:**
   - 验证 `MarkAsHandled` 可以标记 Promise 已被处理，即使 Promise 被拒绝也没有提供拒绝处理程序，从而避免潜在的未处理拒绝错误。

6. **测试同步解析场景 (SyncResolve):**
   - 模拟在 Promise 的 `then` 方法中进行一些可能导致问题的操作（例如重置 Property），并验证不会崩溃。

7. **测试非 `ScriptWrappable` 类型的解析目标:**
   - 验证 `ScriptPromiseProperty` 可以使用非 `ScriptWrappable` 的类型作为解析的值（例如 String, Integer）。

**与 JavaScript, HTML, CSS 的功能关系举例:**

这个 C++ 文件本身不直接涉及 JavaScript, HTML 或 CSS 的语法，它测试的是 Blink 引擎内部 Promise 管理的逻辑。 然而，`ScriptPromiseProperty` 的功能是为 Blink 引擎中的各种 Web API 提供 Promise 支持，这些 API 最终会暴露给 JavaScript，并用于处理网页中的异步操作。

* **JavaScript `fetch()` API:**
   - **场景:** 当 JavaScript 代码调用 `fetch('https://example.com')` 发起网络请求时。
   - **Blink 内部:**  Blink 可能会使用 `ScriptPromiseProperty` 来管理与这个 `fetch` 操作关联的 Promise。当网络请求完成并返回响应时，Blink 会调用 `Resolve` 来解析 Promise，将响应对象传递给 JavaScript 的 `then` 回调。如果请求失败，则会调用 `Reject`。

* **JavaScript IndexedDB API:**
   - **场景:** JavaScript 代码使用 IndexedDB API 进行数据库操作，例如 `indexedDB.open('mydb').onsuccess = event => { ... }`.
   - **Blink 内部:**  虽然传统的 IndexedDB API 使用事件回调，但现代的 Promise-based API 可能使用 `ScriptPromiseProperty`。例如，`IDBObjectStore.prototype.add()` 方法可能会返回一个 Promise，这个 Promise 的管理就可能用到 `ScriptPromiseProperty`。

* **HTML 自定义元素 (Custom Elements):**
   - **场景:**  一个自定义元素可能需要在其生命周期中的某个异步操作完成后通知 JavaScript 代码。
   - **Blink 内部:**  自定义元素内部的 C++ 代码可以使用 `ScriptPromiseProperty` 来创建一个 Promise，当异步操作完成时解析它，从而允许 JavaScript 代码使用 `.then()` 来等待操作完成。

* **CSS Houdini API (例如 Paint API):**
   - **场景:**  CSS Houdini 的 Paint API 允许开发者使用 JavaScript 定义自定义的 CSS 图像。
   - **Blink 内部:**  在绘制自定义图像的过程中可能涉及异步操作（例如加载资源）。`ScriptPromiseProperty` 可以用来管理与这些异步操作关联的 Promise，确保在所有必要的资源加载完成后再进行绘制。

**逻辑推理的假设输入与输出:**

**假设输入:**

1. 创建一个 `GarbageCollectedHolder` 对象。
2. 通过 `GetProperty()` 获取其 `ScriptPromiseProperty` 实例。
3. 在 JavaScript 中通过 `Promise()` 方法获取与该 Property 关联的 Promise 对象 `promise1`。
4. 注册 `promise1` 的 `then` 回调函数 `resolveCallback` 和 `rejectCallback`。
5. 调用 `GetProperty()->Resolve(someValue)`。

**预期输出:**

1. `promise1` 的状态变为 "已完成" (resolved)。
2. `resolveCallback` 会被调用，并且会接收到 `someValue` 作为参数。
3. `ScriptPromiseProperty` 的内部状态会标记为已完成。

**假设输入:**

1. 创建一个 `GarbageCollectedHolder` 对象。
2. 通过 `GetProperty()` 获取其 `ScriptPromiseProperty` 实例。
3. 在 JavaScript 中通过 `Promise()` 方法获取与该 Property 关联的 Promise 对象 `promise2`。
4. 注册 `promise2` 的 `then` 回调函数 `resolveCallback` 和 `rejectCallback`。
5. 调用 `GetProperty()->Reject(someReason)`。

**预期输出:**

1. `promise2` 的状态变为 "已拒绝" (rejected)。
2. `rejectCallback` 会被调用，并且会接收到 `someReason` 作为参数。
3. `ScriptPromiseProperty` 的内部状态会标记为已拒绝。

**涉及用户或者编程常见的使用错误 (作为调试线索):**

1. **忘记处理 Promise 的拒绝:** 如果一个 Promise 被拒绝，但没有提供拒绝处理程序 (`.catch()` 或 `.then(null, rejectCallback)`)，浏览器通常会发出一个 "未处理的 Promise 拒绝" 的警告。`MarkAsHandled` 的测试就与此相关，它允许 Blink 内部标记 Promise 已被处理，即使没有显式的拒绝处理。用户在调试时可能会看到这类警告，并需要检查是否忘记处理某些异步操作可能产生的错误。

2. **在错误的 JavaScript World 中操作 Promise:** 在 Blink 这样的多 World 环境中 (例如主 World 和扩展的隔离 World)，如果一个 Promise 是在一个 World 中创建的，尝试在另一个 World 中解析或拒绝它可能会导致意外行为。测试中验证了在不同 World 中获取的 Promise 是不同的对象，这有助于开发者理解这种隔离性。

3. **过早地释放资源导致 Promise 无法正常完成:** 如果 `ScriptPromiseProperty` 关联的对象在 Promise 被解析或拒绝之前被意外释放，可能会导致程序崩溃或产生未定义的行为。测试中关于垃圾回收的场景就是为了确保即使持有 Promise 引用，也不会阻止关联对象的回收，反之亦然。

4. **混淆 Promise 的生命周期和 `ScriptPromiseProperty` 的生命周期:** 开发者可能会错误地认为 `ScriptPromiseProperty` 的重置会影响之前创建的 Promise 对象。测试中验证了 `Reset` 操作创建的是新的 Promise，之前的 Promise 不受影响，这有助于澄清概念。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设开发者正在调试一个网页中使用了 `fetch()` API 的功能，并且遇到了以下问题：网络请求失败时，预期的错误处理代码没有被执行。

1. **用户在浏览器中访问了该网页，网页的 JavaScript 代码执行到 `fetch()` 调用。**
2. **Blink 引擎接收到 `fetch()` 请求，并创建一个与该请求关联的 `ScriptPromiseProperty` 对象。** 这个 Property 对象负责管理与该 `fetch()` 操作返回的 JavaScript Promise 的状态。
3. **网络请求发送出去，但由于某种原因失败了 (例如网络问题，服务器错误)。**
4. **Blink 的网络模块检测到请求失败，并调用与该 `ScriptPromiseProperty` 关联的 `Reject` 方法，传递表示错误原因的信息。**
5. **JavaScript 中 `fetch()` 返回的 Promise 对象的状态变为 "已拒绝"。**
6. **如果开发者在 Promise 上注册了拒绝处理程序 (`.catch()` 或 `.then` 的第二个参数)，那么该处理程序会被调用，执行相应的错误处理逻辑。**
7. **如果开发者没有提供拒绝处理程序，浏览器可能会在控制台中显示一个 "未处理的 Promise 拒绝" 的警告。**

在调试这个问题的过程中，开发者可能会：

* **在浏览器的开发者工具中查看控制台，寻找错误信息，包括 "未处理的 Promise 拒绝"。**
* **在 JavaScript 代码中设置断点，检查 Promise 的状态以及拒绝原因。**
* **如果怀疑是 Blink 内部 Promise 管理的问题，可能会查看 Blink 引擎的源代码，例如 `script_promise_property_test.cc` 和 `script_promise_property.h`，来理解 Promise 的创建、解析和拒绝的机制。**
* **可能会尝试在 Blink 引擎的源代码中设置断点，例如在 `ScriptPromiseProperty::Resolve` 或 `ScriptPromiseProperty::Reject` 方法中，来跟踪 Promise 状态的变化。**

因此，`script_promise_property_test.cc` 作为 Blink 引擎的一部分，测试了 Promise 管理的核心逻辑。当开发者在使用涉及 Promise 的 Web API (如 `fetch`) 时遇到问题，并深入到 Blink 引擎内部进行调试时，这个测试文件可以提供关于 Promise 如何在 Blink 中被管理的重要信息。理解这些测试用例覆盖的场景，可以帮助开发者更好地理解 Promise 的行为，并定位问题的原因。

### 提示词
```
这是目录为blink/renderer/bindings/core/v8/script_promise_property_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/bindings/core/v8/script_promise_property.h"

#include <memory>

#include "base/memory/scoped_refptr.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_controller.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/garbage_collected_script_wrappable.h"
#include "third_party/blink/renderer/core/testing/gc_observation.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

class NotReachedResolveFunction
    : public ThenCallable<GarbageCollectedScriptWrappable,
                          NotReachedResolveFunction> {
 public:
  NotReachedResolveFunction() = default;

  void React(ScriptState*, GarbageCollectedScriptWrappable*) {
    ADD_FAILURE() << "'Unreachable' code was reached";
  }
};

class NotReachedRejectFunction
    : public ThenCallable<IDLAny, NotReachedRejectFunction> {
 public:
  NotReachedRejectFunction() = default;

  void React(ScriptState*, ScriptValue) {
    ADD_FAILURE() << "'Unreachable' code was reached";
  }
};

class ScriptWrappableReaction
    : public ThenCallable<GarbageCollectedScriptWrappable,
                          ScriptWrappableReaction> {
 public:
  ScriptWrappableReaction() = default;

  void React(ScriptState*, GarbageCollectedScriptWrappable* arg) {
    result_ = arg;
    call_count_++;
  }

  GarbageCollectedScriptWrappable* Result() const { return result_; }
  size_t CallCount() const { return call_count_; }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(result_);
    ThenCallable<GarbageCollectedScriptWrappable,
                 ScriptWrappableReaction>::Trace(visitor);
  }

 private:
  Member<GarbageCollectedScriptWrappable> result_;
  size_t call_count_ = 0;
};

template <typename IDLType, typename ValueType>
class StubResolveFunction
    : public ThenCallable<IDLType, StubResolveFunction<IDLType, ValueType>> {
 public:
  StubResolveFunction(ValueType& value, size_t& call_count)
      : value_(value), call_count_(call_count) {}

  template <typename T = IDLType>
    requires(std::is_same_v<T, IDLUndefined>)
  void React(ScriptState*) {
    call_count_++;
  }

  template <typename T = IDLType>
    requires(std::is_same_v<T, IDLString>)
  void React(ScriptState*, String arg) {
    value_ = arg;
    call_count_++;
  }

  template <typename T = IDLType>
    requires(std::is_same_v<T, IDLLong>)
  void React(ScriptState*, int32_t arg) {
    value_ = arg;
    call_count_++;
  }

 private:
  ValueType& value_;
  size_t& call_count_;
};

class StubRejectFunction : public ThenCallable<IDLAny, StubRejectFunction> {
 public:
  StubRejectFunction(ScriptValue& value, size_t& call_count)
      : value_(value), call_count_(call_count) {}

  void React(ScriptState*, ScriptValue arg) {
    value_ = arg;
    call_count_++;
  }

 private:
  ScriptValue& value_;
  size_t& call_count_;
};

class GarbageCollectedHolder final : public GarbageCollectedScriptWrappable {
 public:
  typedef ScriptPromiseProperty<GarbageCollectedScriptWrappable,
                                GarbageCollectedScriptWrappable>
      Property;
  GarbageCollectedHolder(ExecutionContext* execution_context)
      : GarbageCollectedScriptWrappable("holder"),
        property_(MakeGarbageCollected<Property>(execution_context)) {}

  Property* GetProperty() { return property_.Get(); }
  GarbageCollectedScriptWrappable* ToGarbageCollectedScriptWrappable() {
    return this;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(property_);
    GarbageCollectedScriptWrappable::Trace(visitor);
  }

 private:
  Member<Property> property_;
};

class ScriptPromisePropertyResetter : public ScriptFunction {
 public:
  using Property = ScriptPromiseProperty<GarbageCollectedScriptWrappable,
                                         GarbageCollectedScriptWrappable>;

  explicit ScriptPromisePropertyResetter(Property* property)
      : property_(property) {}

  void Trace(Visitor* visitor) const override {
    visitor->Trace(property_);
    ScriptFunction::Trace(visitor);
  }

  ScriptValue Call(ScriptState*, ScriptValue arg) override {
    property_->Reset();
    return ScriptValue();
  }

 private:
  const Member<Property> property_;
};

class ScriptPromisePropertyTestBase {
 public:
  ScriptPromisePropertyTestBase()
      : page_(std::make_unique<DummyPageHolder>(gfx::Size(1, 1))),
        other_world_(DOMWrapperWorld::EnsureIsolatedWorld(GetIsolate(), 1)) {
    v8::HandleScope handle_scope(GetIsolate());
    // Force initialization of v8::Context and ScriptState for the other world.
    page_->GetFrame().GetWindowProxy(OtherWorld());
  }

  virtual ~ScriptPromisePropertyTestBase() { DestroyContext(); }

  LocalDOMWindow* DomWindow() { return page_->GetFrame().DomWindow(); }
  v8::Isolate* GetIsolate() { return DomWindow()->GetIsolate(); }
  ScriptState* MainScriptState() {
    return ToScriptStateForMainWorld(&page_->GetFrame());
  }
  DOMWrapperWorld& MainWorld() { return MainScriptState()->World(); }
  ScriptState* OtherScriptState() {
    return ToScriptState(&page_->GetFrame(), OtherWorld());
  }
  DOMWrapperWorld& OtherWorld() { return *other_world_; }
  ScriptState* CurrentScriptState() {
    return ScriptState::ForCurrentRealm(GetIsolate());
  }

  void PerformMicrotaskCheckpoint() {
    {
      ScriptState::Scope scope(MainScriptState());
      MainScriptState()->GetContext()->GetMicrotaskQueue()->PerformCheckpoint(
          GetIsolate());
    }
    {
      ScriptState::Scope scope(OtherScriptState());
      OtherScriptState()->GetContext()->GetMicrotaskQueue()->PerformCheckpoint(
          GetIsolate());
    }
  }

  void DestroyContext() {
    page_.reset();
    other_world_ = nullptr;
  }

  void Gc() { ThreadState::Current()->CollectAllGarbageForTesting(); }

  NotReachedResolveFunction* NotReachedResolve() {
    return MakeGarbageCollected<NotReachedResolveFunction>();
  }
  NotReachedRejectFunction* NotReachedReject() {
    return MakeGarbageCollected<NotReachedRejectFunction>();
  }
  template <typename IDLType = GarbageCollectedScriptWrappable,
            typename ValueType>
  StubResolveFunction<IDLType, ValueType>* StubResolve(ValueType& value,
                                                       size_t& call_count) {
    return MakeGarbageCollected<StubResolveFunction<IDLType, ValueType>>(
        value, call_count);
  }
  StubRejectFunction* StubReject(ScriptValue& value, size_t& call_count) {
    return MakeGarbageCollected<StubRejectFunction>(value, call_count);
  }

  ScriptValue Wrap(DOMWrapperWorld& world,
                   GarbageCollectedScriptWrappable* value) {
    v8::Isolate* isolate = GetIsolate();
    v8::HandleScope handle_scope(isolate);
    ScriptState* script_state =
        ScriptState::From(isolate, ToV8Context(DomWindow(), world));
    ScriptState::Scope scope(script_state);
    return ScriptValue(
        isolate,
        ToV8Traits<GarbageCollectedScriptWrappable>::ToV8(script_state, value));
  }

 private:
  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> page_;
  Persistent<DOMWrapperWorld> other_world_;
};

// This is the main test class.
// If you want to examine a testcase independent of holder types, place the
// test on this class.
class ScriptPromisePropertyGarbageCollectedTest
    : public ScriptPromisePropertyTestBase,
      public testing::Test {
 public:
  typedef GarbageCollectedHolder::Property Property;

  ScriptPromisePropertyGarbageCollectedTest()
      : holder_(MakeGarbageCollected<GarbageCollectedHolder>(DomWindow())) {}

  void ClearHolder() { holder_.Clear(); }
  GarbageCollectedHolder* Holder() { return holder_; }
  Property* GetProperty() { return holder_->GetProperty(); }
  ScriptPromise<GarbageCollectedScriptWrappable> Promise(
      DOMWrapperWorld& world) {
    return GetProperty()->Promise(world);
  }

 private:
  Persistent<GarbageCollectedHolder> holder_;
};

// Tests that ScriptPromiseProperty works with a non ScriptWrappable resolution
// target.
class ScriptPromisePropertyNonScriptWrappableResolutionTargetTest
    : public ScriptPromisePropertyTestBase,
      public testing::Test {
 public:
  template <typename T>
  void Test(const T::ImplType& value,
            const char* expected,
            const char* file,
            int line) {
    typedef ScriptPromiseProperty<T, IDLUndefined> Property;
    Property* property = MakeGarbageCollected<Property>(DomWindow());
    size_t n_resolve_calls = 0;
    typename T::ImplType actual_value;
    {
      ScriptState::Scope scope(MainScriptState());
      property->Promise(DOMWrapperWorld::MainWorld(GetIsolate()))
          .Then(CurrentScriptState(),
                StubResolve<T>(actual_value, n_resolve_calls),
                NotReachedReject());
    }
    property->Resolve(value);
    PerformMicrotaskCheckpoint();
    if (value != actual_value) {
      ADD_FAILURE_AT(file, line) << "toV8 returns an incorrect value.\n";
      return;
    }
  }
};

}  // namespace

TEST_F(ScriptPromisePropertyGarbageCollectedTest,
       Promise_IsStableObjectInMainWorld) {
  auto v = GetProperty()->Promise(DOMWrapperWorld::MainWorld(GetIsolate()));
  auto w = GetProperty()->Promise(DOMWrapperWorld::MainWorld(GetIsolate()));
  EXPECT_EQ(v, w);
  ASSERT_FALSE(v.IsEmpty());
  {
    ScriptState::Scope scope(MainScriptState());
    EXPECT_EQ(v.V8Promise()->GetCreationContextChecked(),
              ToV8Context(DomWindow(), MainWorld()));
  }
  EXPECT_EQ(Property::kPending, GetProperty()->GetState());
}

TEST_F(ScriptPromisePropertyGarbageCollectedTest,
       Promise_IsStableObjectInVariousWorlds) {
  auto u = GetProperty()->Promise(OtherWorld());
  auto v = GetProperty()->Promise(DOMWrapperWorld::MainWorld(GetIsolate()));
  auto w = GetProperty()->Promise(DOMWrapperWorld::MainWorld(GetIsolate()));
  EXPECT_NE(MainScriptState(), OtherScriptState());
  EXPECT_NE(&MainWorld(), &OtherWorld());
  EXPECT_NE(u, v);
  EXPECT_EQ(v, w);
  ASSERT_FALSE(u.IsEmpty());
  ASSERT_FALSE(v.IsEmpty());
  {
    ScriptState::Scope scope(OtherScriptState());
    EXPECT_EQ(u.V8Promise()->GetCreationContextChecked(),
              ToV8Context(DomWindow(), OtherWorld()));
  }
  {
    ScriptState::Scope scope(MainScriptState());
    EXPECT_EQ(v.V8Promise()->GetCreationContextChecked(),
              ToV8Context(DomWindow(), MainWorld()));
  }
  EXPECT_EQ(Property::kPending, GetProperty()->GetState());
}

TEST_F(ScriptPromisePropertyGarbageCollectedTest,
       Promise_IsStableObjectAfterSettling) {
  auto v = Promise(DOMWrapperWorld::MainWorld(GetIsolate()));
  GarbageCollectedScriptWrappable* value =
      MakeGarbageCollected<GarbageCollectedScriptWrappable>("value");

  GetProperty()->Resolve(value);
  EXPECT_EQ(Property::kResolved, GetProperty()->GetState());

  auto w = Promise(DOMWrapperWorld::MainWorld(GetIsolate()));
  EXPECT_EQ(v, w);
  EXPECT_FALSE(v.IsEmpty());
}

TEST_F(ScriptPromisePropertyGarbageCollectedTest,
       Promise_DoesNotImpedeGarbageCollection) {
  Persistent<GCObservation> observation;
  {
    ScriptState::Scope scope(MainScriptState());
    // Here we have a reference cylce between Holder() and the promise.
    Holder()->GetProperty()->Resolve(Holder());

    observation = MakeGarbageCollected<GCObservation>(
        GetIsolate(),
        Promise(DOMWrapperWorld::MainWorld(GetIsolate())).V8Promise());
  }

  Gc();
  EXPECT_FALSE(observation->wasCollected());

  ClearHolder();

  Gc();
  EXPECT_TRUE(observation->wasCollected());
}

TEST_F(ScriptPromisePropertyGarbageCollectedTest,
       Resolve_ResolvesScriptPromise) {
  auto promise =
      GetProperty()->Promise(DOMWrapperWorld::MainWorld(GetIsolate()));
  auto other_promise = GetProperty()->Promise(OtherWorld());

  auto* reaction = MakeGarbageCollected<ScriptWrappableReaction>();
  auto* other_reaction = MakeGarbageCollected<ScriptWrappableReaction>();

  {
    ScriptState::Scope scope(MainScriptState());
    promise.Then(CurrentScriptState(), reaction, NotReachedReject());
  }

  {
    ScriptState::Scope scope(OtherScriptState());
    other_promise.Then(CurrentScriptState(), other_reaction,
                       NotReachedReject());
  }

  EXPECT_NE(promise, other_promise);

  GarbageCollectedScriptWrappable* value =
      MakeGarbageCollected<GarbageCollectedScriptWrappable>("value");
  GetProperty()->Resolve(value);
  EXPECT_EQ(Property::kResolved, GetProperty()->GetState());

  PerformMicrotaskCheckpoint();
  EXPECT_EQ(1u, reaction->CallCount());
  EXPECT_EQ(1u, other_reaction->CallCount());
  EXPECT_EQ(value, reaction->Result());
  EXPECT_EQ(value, other_reaction->Result());
}

TEST_F(ScriptPromisePropertyGarbageCollectedTest,
       ResolveAndGetPromiseOnOtherWorld) {
  auto promise =
      GetProperty()->Promise(DOMWrapperWorld::MainWorld(GetIsolate()));
  auto other_promise = GetProperty()->Promise(OtherWorld());

  auto* reaction = MakeGarbageCollected<ScriptWrappableReaction>();
  auto* other_reaction = MakeGarbageCollected<ScriptWrappableReaction>();

  {
    ScriptState::Scope scope(MainScriptState());
    promise.Then(CurrentScriptState(), reaction, NotReachedReject());
  }

  EXPECT_NE(promise, other_promise);
  GarbageCollectedScriptWrappable* value =
      MakeGarbageCollected<GarbageCollectedScriptWrappable>("value");
  GetProperty()->Resolve(value);
  EXPECT_EQ(Property::kResolved, GetProperty()->GetState());

  PerformMicrotaskCheckpoint();
  EXPECT_EQ(1u, reaction->CallCount());
  EXPECT_EQ(0u, other_reaction->CallCount());
  {
    ScriptState::Scope scope(OtherScriptState());
    other_promise.Then(CurrentScriptState(), other_reaction,
                       NotReachedReject());
  }

  PerformMicrotaskCheckpoint();
  EXPECT_EQ(1u, reaction->CallCount());
  EXPECT_EQ(1u, other_reaction->CallCount());
  EXPECT_EQ(value, reaction->Result());
  EXPECT_EQ(value, other_reaction->Result());
}

TEST_F(ScriptPromisePropertyGarbageCollectedTest, Reject_RejectsScriptPromise) {
  GarbageCollectedScriptWrappable* reason =
      MakeGarbageCollected<GarbageCollectedScriptWrappable>("reason");
  GetProperty()->Reject(reason);
  EXPECT_EQ(Property::kRejected, GetProperty()->GetState());

  ScriptValue actual, other_actual;
  size_t n_reject_calls = 0;
  size_t n_other_reject_calls = 0;
  {
    ScriptState::Scope scope(MainScriptState());
    GetProperty()
        ->Promise(DOMWrapperWorld::MainWorld(GetIsolate()))
        .Then(CurrentScriptState(), NotReachedResolve(),
              StubReject(actual, n_reject_calls));
  }

  {
    ScriptState::Scope scope(OtherScriptState());
    GetProperty()
        ->Promise(OtherWorld())
        .Then(CurrentScriptState(), NotReachedResolve(),
              StubReject(other_actual, n_other_reject_calls));
  }

  PerformMicrotaskCheckpoint();
  EXPECT_EQ(1u, n_reject_calls);
  EXPECT_EQ(Wrap(MainWorld(), reason), actual);
  EXPECT_EQ(1u, n_other_reject_calls);
  EXPECT_NE(actual, other_actual);
  EXPECT_EQ(Wrap(OtherWorld(), reason), other_actual);
}

TEST_F(ScriptPromisePropertyGarbageCollectedTest, Promise_DeadContext) {
  v8::Isolate* isolate = GetIsolate();
  GetProperty()->Resolve(
      MakeGarbageCollected<GarbageCollectedScriptWrappable>("value"));
  EXPECT_EQ(Property::kResolved, GetProperty()->GetState());

  DestroyContext();

  EXPECT_TRUE(
      GetProperty()->Promise(DOMWrapperWorld::MainWorld(isolate)).IsEmpty());
}

TEST_F(ScriptPromisePropertyGarbageCollectedTest, Resolve_DeadContext) {
  {
    ScriptState::Scope scope(MainScriptState());
    GetProperty()
        ->Promise(DOMWrapperWorld::MainWorld(GetIsolate()))
        .Then(CurrentScriptState(), NotReachedResolve(), NotReachedReject());
  }

  DestroyContext();
  EXPECT_TRUE(!GetProperty()->GetExecutionContext() ||
              GetProperty()->GetExecutionContext()->IsContextDestroyed());

  GetProperty()->Resolve(
      MakeGarbageCollected<GarbageCollectedScriptWrappable>("value"));
  EXPECT_EQ(Property::kPending, GetProperty()->GetState());
}

TEST_F(ScriptPromisePropertyGarbageCollectedTest, Reset) {
  ScriptState::Scope scope(MainScriptState());

  ScriptPromise<GarbageCollectedScriptWrappable> old_promise, new_promise;
  ScriptValue new_actual;
  GarbageCollectedScriptWrappable* old_value =
      MakeGarbageCollected<GarbageCollectedScriptWrappable>("old");
  GarbageCollectedScriptWrappable* new_value =
      MakeGarbageCollected<GarbageCollectedScriptWrappable>("new");

  auto* old_reaction = MakeGarbageCollected<ScriptWrappableReaction>();
  size_t n_new_reject_calls = 0;

  {
    ScriptState::Scope scope2(MainScriptState());
    GetProperty()->Resolve(old_value);
    old_promise = GetProperty()->Promise(MainWorld());
    old_promise.Then(CurrentScriptState(), old_reaction, NotReachedReject());
  }

  GetProperty()->Reset();

  {
    ScriptState::Scope scope2(MainScriptState());
    new_promise = GetProperty()->Promise(MainWorld());
    new_promise.Then(CurrentScriptState(), NotReachedResolve(),
                     StubReject(new_actual, n_new_reject_calls));
    GetProperty()->Reject(new_value);
  }

  EXPECT_EQ(0u, old_reaction->CallCount());
  EXPECT_EQ(0u, n_new_reject_calls);

  PerformMicrotaskCheckpoint();
  EXPECT_EQ(1u, old_reaction->CallCount());
  EXPECT_EQ(1u, n_new_reject_calls);
  EXPECT_NE(old_promise, new_promise);
  EXPECT_EQ(old_value, old_reaction->Result());
  EXPECT_EQ(Wrap(MainWorld(), new_value), new_actual);
  EXPECT_NE(Wrap(MainWorld(), old_reaction->Result()), new_actual);
}

TEST_F(ScriptPromisePropertyGarbageCollectedTest, MarkAsHandled) {
  {
    // Unhandled promise.
    ScriptState::Scope scope(MainScriptState());
    auto promise =
        GetProperty()->Promise(DOMWrapperWorld::MainWorld(GetIsolate()));
    GarbageCollectedScriptWrappable* reason =
        MakeGarbageCollected<GarbageCollectedScriptWrappable>("reason");
    GetProperty()->Reject(reason);
    EXPECT_FALSE(promise.V8Promise()->HasHandler());
  }

  GetProperty()->Reset();

  {
    // MarkAsHandled applies to newly created promises.
    ScriptState::Scope scope(MainScriptState());
    GetProperty()->MarkAsHandled();
    auto promise =
        GetProperty()->Promise(DOMWrapperWorld::MainWorld(GetIsolate()));
    GarbageCollectedScriptWrappable* reason =
        MakeGarbageCollected<GarbageCollectedScriptWrappable>("reason");
    GetProperty()->Reject(reason);
    EXPECT_TRUE(promise.V8Promise()->HasHandler());
  }

  GetProperty()->Reset();

  {
    // MarkAsHandled applies to previously vended promises.
    ScriptState::Scope scope(MainScriptState());
    auto promise =
        GetProperty()->Promise(DOMWrapperWorld::MainWorld(GetIsolate()));
    GetProperty()->MarkAsHandled();
    GarbageCollectedScriptWrappable* reason =
        MakeGarbageCollected<GarbageCollectedScriptWrappable>("reason");
    GetProperty()->Reject(reason);
    EXPECT_TRUE(promise.V8Promise()->HasHandler());
  }
}

TEST_F(ScriptPromisePropertyGarbageCollectedTest, SyncResolve) {
  // Call getters to create resolvers in the property.
  GetProperty()->Promise(DOMWrapperWorld::MainWorld(GetIsolate()));
  GetProperty()->Promise(OtherWorld());

  auto* resolution =
      MakeGarbageCollected<GarbageCollectedScriptWrappable>("hi");
  v8::HandleScope handle_scope(GetIsolate());
  v8::Local<v8::Object> main_v8_resolution;
  v8::Local<v8::Object> other_v8_resolution;
  {
    ScriptState::Scope scope(MainScriptState());
    v8::MicrotasksScope microtasks_scope(
        GetIsolate(), ToMicrotaskQueue(MainScriptState()),
        v8::MicrotasksScope::kDoNotRunMicrotasks);
    main_v8_resolution = ToV8Traits<GarbageCollectedScriptWrappable>::ToV8(
                             MainScriptState(), resolution)
                             .As<v8::Object>();
    v8::PropertyDescriptor descriptor(
        MakeGarbageCollected<ScriptPromisePropertyResetter>(GetProperty())
            ->ToV8Function(MainScriptState()),
        v8::Undefined(GetIsolate()));
    ASSERT_EQ(
        v8::Just(true),
        main_v8_resolution->DefineProperty(
            MainScriptState()->GetContext(),
            v8::String::NewFromUtf8Literal(GetIsolate(), "then"), descriptor));
  }
  {
    ScriptState::Scope scope(OtherScriptState());
    v8::MicrotasksScope microtasks_scope(
        GetIsolate(), ToMicrotaskQueue(OtherScriptState()),
        v8::MicrotasksScope::kDoNotRunMicrotasks);
    other_v8_resolution = ToV8Traits<GarbageCollectedScriptWrappable>::ToV8(
                              OtherScriptState(), resolution)
                              .As<v8::Object>();
    v8::PropertyDescriptor descriptor(
        MakeGarbageCollected<ScriptPromisePropertyResetter>(GetProperty())
            ->ToV8Function(OtherScriptState()),
        v8::Undefined(GetIsolate()));
    ASSERT_EQ(
        v8::Just(true),
        other_v8_resolution->DefineProperty(
            OtherScriptState()->GetContext(),
            v8::String::NewFromUtf8Literal(GetIsolate(), "then"), descriptor));
  }

  // This shouldn't crash.
  GetProperty()->Resolve(resolution);
  EXPECT_EQ(GetProperty()->GetState(), Property::State::kPending);
}

TEST_F(ScriptPromisePropertyNonScriptWrappableResolutionTargetTest,
       ResolveWithString) {
  Test<IDLString>(String("hello"), "hello", __FILE__, __LINE__);
}

TEST_F(ScriptPromisePropertyNonScriptWrappableResolutionTargetTest,
       ResolveWithInteger) {
  Test<IDLLong>(-1, "-1", __FILE__, __LINE__);
}

}  // namespace blink
```