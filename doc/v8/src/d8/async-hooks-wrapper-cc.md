Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

**1. Understanding the Goal:**

The request asks for the functionality of the `async-hooks-wrapper.cc` file, specifically within the context of V8's `d8` directory. It also asks about Torque implications, JavaScript relation, code logic, and common errors.

**2. Initial Code Scan and Keyword Spotting:**

I'd start by quickly scanning the code for keywords and recognizable patterns:

* **Includes:**  `v8.h`, `v8-function.h`, `v8-local-handle.h`, `v8-primitive.h`, `v8-template.h`, `api.h`, `d8.h`, `isolate-inl.h`, `managed-inl.h`. This signals that it's part of V8's internal implementation and interacts with V8's API. The `d8.h` suggests it's related to the `d8` shell.
* **Namespaces:** `v8`, the anonymous namespace. This confirms it's V8-specific.
* **Classes:** `AsyncHooks`, `AsyncHooksWrap`. These are the core structures.
* **Methods:** `EnableHook`, `DisableHook`, `CreateHook`, `ShellPromiseHook`, `PromiseHookDispatch`, `Enable`, `Disable`, `set_init_function`, `set_before_function`, etc. These indicate the operations the code performs.
* **Data Structures:** `std::shared_ptr`, `std::vector`, `std::stack`, `v8::Local`, `v8::Persistent`, `v8::Private`. These are common C++ and V8 types for managing memory and objects.
* **V8 Specifics:** `FunctionCallbackInfo`, `HandleScope`, `Local`, `FunctionTemplate`, `ObjectTemplate`, `SetInternalField`, `GetInternalField`, `ThrowError`, `SetPromiseHook`, `GetPrivate`, `SetPrivate`. This strongly confirms interaction with V8's embedding API.
* **Async Related Terms:** "AsyncHooks", "PromiseHook", "async_id", "trigger_async_id", "init", "before", "after", "promiseResolve". This points to asynchronous operations and their monitoring.

**3. Deconstructing the `AsyncHooks` Class:**

I'd focus on the main classes and their responsibilities:

* **`AsyncHooks`:** This appears to be the central manager for asynchronous hooks.
    * The constructor initializes the `asyncContexts` stack (for tracking asynchronous execution context), sets the initial `current_async_id`, creates a `FunctionTemplate` for `AsyncHook` objects, and sets up properties like "enable" and "disable".
    * It also uses `SetPromiseHook`, indicating it's intercepting promise lifecycle events.
    * The `CreateHook` method is crucial for creating new hook instances.
    * `GetExecutionAsyncId` and `GetTriggerAsyncId` provide context information.
    * `ShellPromiseHook` is the core callback triggered by V8's promise mechanism.
    * `PromiseHookDispatch` calls the user-defined hook functions.

**4. Deconstructing the `AsyncHooksWrap` Class:**

* **`AsyncHooksWrap`:** This seems to represent a single set of user-defined asynchronous hook functions.
    * It stores `v8::Persistent` handles to the `init`, `before`, `after`, and `promiseResolve` functions provided by the user.
    * `Enable` and `Disable` control whether this specific hook is active.

**5. Tracing the Execution Flow (Mental Model):**

I'd try to visualize how these components interact:

1. A user in the `d8` shell (or an embedded environment) would use the `AsyncHooks` API (likely through a JavaScript binding, although not shown in this C++ file).
2. The `CreateHook` function is called, creating an `AsyncHooksWrap` object to store the user's callback functions.
3. V8's internal promise mechanism triggers `ShellPromiseHook` at various stages of a promise's lifecycle (init, before, after, resolve).
4. `ShellPromiseHook` retrieves the relevant `AsyncHooks` instance and iterates through the active `AsyncHooksWrap` objects.
5. `PromiseHookDispatch` calls the corresponding user-defined JavaScript functions (`init`, `before`, `after`, `promiseResolve`) based on the `PromiseHookType`.

**6. Addressing Specific Questions:**

* **Functionality:** Based on the analysis, the main function is to provide a mechanism to intercept and monitor the lifecycle events of Promises in V8.
* **Torque:** The filename doesn't end in `.tq`, so it's not a Torque file.
* **JavaScript Relationship:** This C++ code *implements* the underlying functionality that JavaScript's `async_hooks` module (in Node.js) or similar mechanisms (potentially in the browser's DevTools) would use. The example needs to illustrate how the *effects* of this C++ code would be seen in JavaScript.
* **Code Logic/Assumptions:** Focus on the key parts: the `asyncContexts` stack's role in tracking context, the assignment of `async_id` and `trigger_id`, and the dispatching of hooks. Create simple scenarios to show the input and expected output (the calling of hook functions).
* **Common Errors:** Think about what could go wrong from a user's perspective when using asynchronous hooks. Not providing the correct functions, throwing errors in the hooks, performance impact of overly complex hooks are good examples.

**7. Structuring the Answer:**

Organize the findings into logical sections:

* **Core Functionality:** Start with a high-level summary.
* **Torque:** Address this directly.
* **JavaScript Relationship:** Explain the connection and provide a JavaScript example.
* **Code Logic and Assumptions:** Detail the key steps and illustrate with a scenario.
* **Common Errors:** Provide practical examples of user mistakes.

**8. Refinement and Review:**

Read through the generated explanation to ensure accuracy, clarity, and completeness. Are the JavaScript examples correct and illustrative? Is the code logic explanation easy to follow? Are the common errors relevant?

This iterative process of scanning, deconstructing, tracing, and structuring allows for a comprehensive understanding and explanation of the given C++ code. The focus is on connecting the low-level implementation details to the high-level purpose and usage.
`v8/src/d8/async-hooks-wrapper.cc` 是 V8 引擎中 `d8` 命令行工具的一个源代码文件，它实现了 **异步钩子 (Async Hooks)** 的包装器功能。  异步钩子是一种机制，允许开发者追踪和监控 Node.js 和 V8 内部异步操作的生命周期。

**功能列表:**

1. **提供 C++ 接口来管理异步钩子:**  该文件定义了 `AsyncHooks` 和 `AsyncHooksWrap` 类，用于管理和存储异步钩子的相关信息和回调函数。

2. **创建和管理 `AsyncHook` 对象:**  `AsyncHooks::CreateHook` 方法负责创建新的 `AsyncHook` 实例。  这些实例是用户在 JavaScript 中创建异步钩子时在 C++ 层面的表示。

3. **存储用户定义的钩子回调函数:** `AsyncHooksWrap` 类存储了用户通过 JavaScript API 注册的各种钩子回调函数，例如 `init`, `before`, `after`, `promiseResolve`。

4. **拦截 Promise 的生命周期事件:** `AsyncHooks::ShellPromiseHook` 方法是 V8 的 Promise 钩子，它在 Promise 的不同生命周期阶段（例如创建、执行前、执行后、解决）被 V8 引擎调用。

5. **调度用户定义的钩子回调:**  `AsyncHooks::PromiseHookDispatch` 方法在 `ShellPromiseHook` 中被调用，负责根据 Promise 的当前状态和用户注册的回调函数，执行相应的 JavaScript 回调。

6. **维护异步上下文信息:** `AsyncHooks` 类使用一个栈 `asyncContexts` 来跟踪当前的异步执行上下文，包括 `execution_async_id` 和 `trigger_async_id`。

7. **与 JavaScript 代码交互:**  该文件通过 V8 的 C++ API 与 JavaScript 代码进行交互，允许 JavaScript 代码创建、启用、禁用和定义异步钩子的行为。

**关于文件扩展名和 Torque:**

如果 `v8/src/d8/async-hooks-wrapper.cc` 的文件名以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是 V8 用来定义运行时内置函数和类型的领域特定语言。  然而，根据您提供的文件名，它以 `.cc` 结尾，因此是标准的 C++ 源代码文件。

**与 JavaScript 功能的关系 (以及 JavaScript 示例):**

`v8/src/d8/async-hooks-wrapper.cc` 中实现的功能是 Node.js `async_hooks` 模块的基础。  Node.js 的 `async_hooks` 模块允许 JavaScript 代码注册回调函数，以便在异步操作的不同阶段得到通知。

**JavaScript 示例:**

```javascript
const async_hooks = require('async_hooks');
const fs = require('fs');

// 创建一个新的 AsyncHook 实例
const asyncHook = async_hooks.createHook({
  init(asyncId, type, triggerAsyncId, resource) {
    console.log(`New async operation started: Async ID ${asyncId}, Type ${type}, Trigger Async ID ${triggerAsyncId}`);
  },
  before(asyncId) {
    console.log(`Async operation about to start: Async ID ${asyncId}`);
  },
  after(asyncId) {
    console.log(`Async operation completed: Async ID ${asyncId}`);
  },
  destroy(asyncId) {
    console.log(`Async operation destroyed: Async ID ${asyncId}`);
  },
  promiseResolve(asyncId) {
    console.log(`Promise resolved: Async ID ${asyncId}`);
  }
});

// 启用异步钩子
asyncHook.enable();

// 执行一个异步操作
fs.readFile('example.txt', 'utf8', (err, data) => {
  if (err) {
    console.error('Error reading file:', err);
    return;
  }
  console.log('File content:', data);
});

// 创建一个 Promise
const myPromise = new Promise((resolve) => {
  setTimeout(() => {
    resolve('Promise resolved!');
  }, 100);
});

myPromise.then(console.log);

// 禁用异步钩子
// asyncHook.disable();
```

在这个 JavaScript 例子中：

* `async_hooks.createHook` 调用会创建一个与 `v8/src/d8/async-hooks-wrapper.cc` 中 `AsyncHooks::CreateHook` 逻辑相关的 C++ 对象。
* 传递给 `createHook` 的对象中的函数（`init`, `before`, `after`, `destroy`, `promiseResolve`）会被存储在 `AsyncHooksWrap` 对象中。
* 当 `fs.readFile` 和 `myPromise` 的异步操作执行时，V8 引擎会调用 `AsyncHooks::ShellPromiseHook`，进而调用 `PromiseHookDispatch` 来执行我们在 JavaScript 中定义的回调函数。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下 JavaScript 代码：

```javascript
const async_hooks = require('async_hooks');

let initCount = 0;
let beforeCount = 0;

async_hooks.createHook({
  init(asyncId, type, triggerAsyncId, resource) {
    initCount++;
    console.log(`init: ${asyncId}`);
  },
  before(asyncId) {
    beforeCount++;
    console.log(`before: ${asyncId}`);
  }
}).enable();

setTimeout(() => {}, 100);
```

**假设输入:**  执行上述 JavaScript 代码。

**推理:**

1. 当 `setTimeout` 被调用时，V8 引擎会创建一个新的异步操作。
2. `AsyncHooks::ShellPromiseHook` (或类似的钩子，取决于具体的异步操作类型) 会被触发。
3. `AsyncHooks::PromiseHookDispatch` 会被调用，因为它有一个启用的钩子。
4. `wrap->init_function()->Call(...)` 将被执行，调用我们在 JavaScript 中定义的 `init` 回调。
5. `initCount` 的值会增加 1。
6. 当 `setTimeout` 的回调即将执行时，`AsyncHooks::ShellPromiseHook` 的 `kBefore` 类型会被触发。
7. `AsyncHooks::PromiseHookDispatch` 再次被调用。
8. `wrap->before_function()->Call(...)` 将被执行，调用我们在 JavaScript 中定义的 `before` 回调。
9. `beforeCount` 的值会增加 1。

**假设输出:**

```
init: 2 // 假设这是 setTimeout 的 asyncId
before: 2
```

**涉及用户常见的编程错误:**

1. **在钩子回调中抛出错误:** 如果在 `init`, `before`, `after`, `destroy`, 或 `promiseResolve` 回调函数中抛出未捕获的错误，可能会导致程序崩溃或行为异常，因为这些回调是在 V8 引擎的内部循环中调用的。

   ```javascript
   const async_hooks = require('async_hooks');

   async_hooks.createHook({
     init(asyncId, type, triggerAsyncId, resource) {
       throw new Error('Something went wrong during init!');
     }
   }).enable();

   setTimeout(() => {}, 100); // 这可能导致程序崩溃或异常
   ```

2. **性能问题:**  过于复杂的钩子回调函数会显著影响应用程序的性能，因为这些回调会在每次异步操作的生命周期事件中被同步执行。避免在钩子回调中执行耗时的操作。

   ```javascript
   const async_hooks = require('async_hooks');
   const fs = require('fs');

   async_hooks.createHook({
     before(asyncId) {
       // 错误：在 before 钩子中读取文件是耗时的操作
       const data = fs.readFileSync('large_file.txt');
       console.log('Reading file in before hook');
     }
   }).enable();

   setTimeout(() => {}, 100); // 这会使每次 setTimeout 的执行变慢
   ```

3. **不正确的 `this` 上下文:**  在钩子回调中，`this` 的值可能不是用户期望的。通常，应该避免依赖 `this`，或者使用箭头函数来捕获外部作用域的 `this`。

   ```javascript
   const async_hooks = require('async_hooks');

   class MyClass {
     constructor() {
       this.name = 'MyClass instance';
       async_hooks.createHook({
         init: function(asyncId, type, triggerAsyncId, resource) {
           console.log(this.name); // 错误：这里的 this 可能不是 MyClass 的实例
         }.bind(this) // 正确的做法是绑定 this
       }).enable();
     }
   }

   new MyClass();
   setTimeout(() => {}, 100);
   ```

4. **忘记禁用钩子:** 如果在不再需要时忘记禁用异步钩子，可能会导致持续的性能开销。

   ```javascript
   const async_hooks = require('async_hooks');

   const hook = async_hooks.createHook({ /* ... */ }).enable();

   // ... 执行一些操作 ...

   // 错误：忘记禁用钩子
   // hook.disable();
   ```

理解 `v8/src/d8/async-hooks-wrapper.cc` 的功能有助于深入了解 Node.js `async_hooks` 模块的底层实现机制，以及如何正确使用和调试异步操作。

Prompt: 
```
这是目录为v8/src/d8/async-hooks-wrapper.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/d8/async-hooks-wrapper.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/d8/async-hooks-wrapper.h"

#include "include/v8-function.h"
#include "include/v8-local-handle.h"
#include "include/v8-primitive.h"
#include "include/v8-template.h"
#include "src/api/api-inl.h"
#include "src/api/api.h"
#include "src/d8/d8.h"
#include "src/execution/isolate-inl.h"
#include "src/objects/managed-inl.h"

namespace v8 {

namespace {
std::shared_ptr<AsyncHooksWrap> UnwrapHook(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  v8::Isolate* v8_isolate = info.GetIsolate();
  HandleScope scope(v8_isolate);
  Local<Object> hook = info.This();

  AsyncHooks* hooks = PerIsolateData::Get(v8_isolate)->GetAsyncHooks();

  if (!hooks->async_hook_ctor.Get(v8_isolate)->HasInstance(hook)) {
    v8_isolate->ThrowError(
        "Invalid 'this' passed instead of AsyncHooks instance");
    return nullptr;
  }

  i::Handle<i::Object> handle = Utils::OpenHandle(*hook->GetInternalField(0));
  return Cast<i::Managed<AsyncHooksWrap>>(handle)->get();
}

void EnableHook(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  auto wrap = UnwrapHook(info);
  if (wrap) wrap->Enable();
}

void DisableHook(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  auto wrap = UnwrapHook(info);
  if (wrap) wrap->Disable();
}

}  // namespace

AsyncHooks::AsyncHooks(v8::Isolate* v8_isolate) : v8_isolate_(v8_isolate) {
  AsyncContext ctx;
  ctx.execution_async_id = 1;
  ctx.trigger_async_id = 0;
  asyncContexts.push(ctx);
  current_async_id = 1;

  HandleScope handle_scope(v8_isolate_);

  async_hook_ctor.Reset(v8_isolate_, FunctionTemplate::New(v8_isolate_));
  async_hook_ctor.Get(v8_isolate_)
      ->SetClassName(String::NewFromUtf8Literal(v8_isolate_, "AsyncHook"));

  async_hooks_templ.Reset(v8_isolate_,
                          async_hook_ctor.Get(v8_isolate_)->InstanceTemplate());
  async_hooks_templ.Get(v8_isolate_)->SetInternalFieldCount(1);
  async_hooks_templ.Get(v8_isolate_)
      ->Set(v8_isolate_, "enable",
            FunctionTemplate::New(v8_isolate_, EnableHook));
  async_hooks_templ.Get(v8_isolate_)
      ->Set(v8_isolate_, "disable",
            FunctionTemplate::New(v8_isolate_, DisableHook));

  async_id_symbol.Reset(v8_isolate_, Private::New(v8_isolate_));
  trigger_id_symbol.Reset(v8_isolate_, Private::New(v8_isolate_));

  v8_isolate_->SetPromiseHook(ShellPromiseHook);
}

AsyncHooks::~AsyncHooks() {
  v8_isolate_->SetPromiseHook(nullptr);
  async_wraps_.clear();
}

void AsyncHooksWrap::Enable() { enabled_ = true; }

void AsyncHooksWrap::Disable() { enabled_ = false; }

v8::Local<v8::Function> AsyncHooksWrap::init_function() const {
  return init_function_.Get(isolate_);
}
void AsyncHooksWrap::set_init_function(v8::Local<v8::Function> value) {
  init_function_.Reset(isolate_, value);
}
v8::Local<v8::Function> AsyncHooksWrap::before_function() const {
  return before_function_.Get(isolate_);
}
void AsyncHooksWrap::set_before_function(v8::Local<v8::Function> value) {
  before_function_.Reset(isolate_, value);
}
v8::Local<v8::Function> AsyncHooksWrap::after_function() const {
  return after_function_.Get(isolate_);
}
void AsyncHooksWrap::set_after_function(v8::Local<v8::Function> value) {
  after_function_.Reset(isolate_, value);
}
v8::Local<v8::Function> AsyncHooksWrap::promiseResolve_function() const {
  return promiseResolve_function_.Get(isolate_);
}
void AsyncHooksWrap::set_promiseResolve_function(
    v8::Local<v8::Function> value) {
  promiseResolve_function_.Reset(isolate_, value);
}

async_id_t AsyncHooks::GetExecutionAsyncId() const {
  return asyncContexts.top().execution_async_id;
}

async_id_t AsyncHooks::GetTriggerAsyncId() const {
  return asyncContexts.top().trigger_async_id;
}

Local<Object> AsyncHooks::CreateHook(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  v8::Isolate* v8_isolate = info.GetIsolate();
  EscapableHandleScope handle_scope(v8_isolate);

  if (v8_isolate->IsExecutionTerminating()) {
    return Local<Object>();
  }

  Local<Context> currentContext = v8_isolate->GetCurrentContext();

  if (info.Length() != 1 || !info[0]->IsObject()) {
    v8_isolate->ThrowError("Invalid arguments passed to createHook");
    return Local<Object>();
  }

  std::shared_ptr<AsyncHooksWrap> wrap =
      std::make_shared<AsyncHooksWrap>(v8_isolate);

  Local<Object> fn_obj = info[0].As<Object>();

  v8::TryCatch try_catch(v8_isolate);
#define SET_HOOK_FN(name)                                                     \
  MaybeLocal<Value> name##_maybe_func = fn_obj->Get(                          \
      currentContext, String::NewFromUtf8Literal(v8_isolate, #name));         \
  Local<Value> name##_func;                                                   \
  if (name##_maybe_func.ToLocal(&name##_func) && name##_func->IsFunction()) { \
    wrap->set_##name##_function(name##_func.As<Function>());                  \
  } else {                                                                    \
    try_catch.ReThrow();                                                      \
  }

  SET_HOOK_FN(init);
  SET_HOOK_FN(before);
  SET_HOOK_FN(after);
  SET_HOOK_FN(promiseResolve);
#undef SET_HOOK_FN

  Local<Object> obj = async_hooks_templ.Get(v8_isolate)
                          ->NewInstance(currentContext)
                          .ToLocalChecked();
  i::Handle<i::Object> managed = i::Managed<AsyncHooksWrap>::From(
      reinterpret_cast<i::Isolate*>(v8_isolate), sizeof(AsyncHooksWrap), wrap);
  obj->SetInternalField(0, Utils::ToLocal(managed));

  async_wraps_.push_back(std::move(wrap));

  return handle_scope.Escape(obj);
}

void AsyncHooks::ShellPromiseHook(PromiseHookType type, Local<Promise> promise,
                                  Local<Value> parent) {
  v8::Isolate* v8_isolate = promise->GetIsolate();
  AsyncHooks* hooks = PerIsolateData::Get(v8_isolate)->GetAsyncHooks();
  if (v8_isolate->IsExecutionTerminating() || hooks->skip_after_termination_) {
    hooks->skip_after_termination_ = true;
    return;
  }
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);

  HandleScope handle_scope(v8_isolate);
  i::Handle<i::Object> exception;
  // Keep track of any previously thrown exception.
  if (i_isolate->has_exception()) {
    exception = handle(i_isolate->exception(), i_isolate);
  }
  {
    TryCatch try_catch(v8_isolate);
    try_catch.SetVerbose(true);

    Local<Context> currentContext = v8_isolate->GetCurrentContext();
    DCHECK(!currentContext.IsEmpty());

    if (type == PromiseHookType::kInit) {
      ++hooks->current_async_id;
      Local<Integer> async_id =
          Integer::New(v8_isolate, hooks->current_async_id);
      CHECK(!promise
                 ->HasPrivate(currentContext,
                              hooks->async_id_symbol.Get(v8_isolate))
                 .ToChecked());
      promise->SetPrivate(currentContext,
                          hooks->async_id_symbol.Get(v8_isolate), async_id);

      if (parent->IsPromise()) {
        Local<Promise> parent_promise = parent.As<Promise>();
        Local<Value> parent_async_id =
            parent_promise
                ->GetPrivate(currentContext,
                             hooks->async_id_symbol.Get(v8_isolate))
                .ToLocalChecked();
        promise->SetPrivate(currentContext,
                            hooks->trigger_id_symbol.Get(v8_isolate),
                            parent_async_id);
      } else {
        CHECK(parent->IsUndefined());
        promise->SetPrivate(currentContext,
                            hooks->trigger_id_symbol.Get(v8_isolate),
                            Integer::New(v8_isolate, 0));
      }
    } else if (type == PromiseHookType::kBefore) {
      AsyncContext ctx;
      ctx.execution_async_id =
          promise
              ->GetPrivate(currentContext,
                           hooks->async_id_symbol.Get(v8_isolate))
              .ToLocalChecked()
              .As<Integer>()
              ->Value();
      ctx.trigger_async_id =
          promise
              ->GetPrivate(currentContext,
                           hooks->trigger_id_symbol.Get(v8_isolate))
              .ToLocalChecked()
              .As<Integer>()
              ->Value();
      hooks->asyncContexts.push(ctx);
    } else if (type == PromiseHookType::kAfter) {
      hooks->asyncContexts.pop();
    }
    if (!i::StackLimitCheck{i_isolate}.HasOverflowed()) {
      for (size_t i = 0; i < hooks->async_wraps_.size(); ++i) {
        std::shared_ptr<AsyncHooksWrap> wrap = hooks->async_wraps_[i];
        PromiseHookDispatch(type, promise, parent, *wrap, hooks);
        if (try_catch.HasCaught()) break;
      }
      if (try_catch.HasCaught()) Shell::ReportException(v8_isolate, try_catch);
    }
  }
  if (!exception.is_null()) {
    i_isolate->set_exception(*exception);
  }
}

void AsyncHooks::PromiseHookDispatch(PromiseHookType type,
                                     Local<Promise> promise,
                                     Local<Value> parent,
                                     const AsyncHooksWrap& wrap,
                                     AsyncHooks* hooks) {
  if (!wrap.IsEnabled()) return;
  v8::Isolate* v8_isolate = hooks->v8_isolate_;
  if (v8_isolate->IsExecutionTerminating()) return;
  HandleScope handle_scope(v8_isolate);

  Local<Value> rcv = Undefined(v8_isolate);
  Local<Context> context = v8_isolate->GetCurrentContext();
  Local<Value> async_id =
      promise->GetPrivate(context, hooks->async_id_symbol.Get(v8_isolate))
          .ToLocalChecked();
  Local<Value> args[1] = {async_id};

  switch (type) {
    case PromiseHookType::kInit:
      if (!wrap.init_function().IsEmpty()) {
        Local<Value> initArgs[4] = {
            async_id, String::NewFromUtf8Literal(v8_isolate, "PROMISE"),
            promise
                ->GetPrivate(context, hooks->trigger_id_symbol.Get(v8_isolate))
                .ToLocalChecked(),
            promise};
        USE(wrap.init_function()->Call(context, rcv, 4, initArgs));
      }
      break;
    case PromiseHookType::kBefore:
      if (!wrap.before_function().IsEmpty()) {
        USE(wrap.before_function()->Call(context, rcv, 1, args));
      }
      break;
    case PromiseHookType::kAfter:
      if (!wrap.after_function().IsEmpty()) {
        USE(wrap.after_function()->Call(context, rcv, 1, args));
      }
      break;
    case PromiseHookType::kResolve:
      if (!wrap.promiseResolve_function().IsEmpty()) {
        USE(wrap.promiseResolve_function()->Call(context, rcv, 1, args));
      }
  }
}

}  // namespace v8

"""

```