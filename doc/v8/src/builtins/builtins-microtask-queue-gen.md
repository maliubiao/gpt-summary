Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The core request is to understand the functionality of the given C++ file (`builtins-microtask-queue-gen.cc`) within the V8 engine and illustrate its connection to JavaScript.

2. **Initial Scan for Keywords and Structures:**  Quickly scan the code for relevant keywords and structures. Look for:
    * File path: `v8/src/builtins/builtins-microtask-queue-gen.cc` -  The "builtins" part strongly suggests this code implements core JavaScript functionalities. "microtask-queue" is a very explicit hint about its purpose.
    * Includes:  `<api/api.h>`, `<builtins/builtins-utils-gen.h>`, `<codegen/code-stub-assembler-inl.h>`, `<execution/microtask-queue.h>`, `<objects/js-weak-refs.h>`, `<objects/microtask-inl.h>`, `<objects/promise.h>`, `<objects/smi-inl.h>`. These headers confirm the focus on microtasks, promises, and the internal workings of V8's object model and code generation.
    * Namespace: `v8::internal` -  Indicates this is internal V8 implementation, not directly exposed to JavaScript.
    * Class `MicrotaskQueueBuiltinsAssembler`:  The central class. The name and the "Assembler" suffix suggest it's involved in generating low-level code for microtask handling.
    * Method names:  `GetMicrotaskQueue`, `RunSingleMicrotask`, `EnqueueMicrotask`, `RunMicrotasks`, `RunAllPromiseHooks`. These names give strong clues about the operations performed.
    * `TF_BUILTIN`: This macro strongly indicates these are built-in functions directly accessible from JavaScript (though internally implemented). `EnqueueMicrotask` and `RunMicrotasks` are particularly important.

3. **Focus on Key Functionality:** The `EnqueueMicrotask` and `RunMicrotasks` built-ins are the most directly relevant to JavaScript.

    * **`EnqueueMicrotask`:** Notice it takes a `Microtask` and a `Context`. It gets the `microtask_queue`, checks if it's shut down, and then tries to add the microtask to a ring buffer. If the buffer is full, it calls a C++ function to grow it. This strongly suggests this is the mechanism for adding microtasks to the queue.

    * **`RunMicrotasks`:** This function retrieves the `microtask_queue`, enters a loop, and processes microtasks one by one. It fetches a microtask, removes it from the queue, and then calls `RunSingleMicrotask`. The loop continues until the queue is empty. This clearly represents the process of executing queued microtasks.

4. **Analyze `RunSingleMicrotask`:**  This function is crucial for understanding *how* microtasks are executed.
    * It uses a `switch` statement based on the `microtask_type`. This indicates different types of microtasks (callable, callback, promise reactions, etc.).
    * For "callable" tasks, it loads the context and the callable function and then calls it.
    * For "callback" tasks, it calls a runtime function (`kRunMicrotaskCallback`).
    * For "promise" related tasks, it calls other built-ins (`kPromiseFulfillReactionJob`, `kPromiseRejectReactionJob`, `kPromiseResolveThenableJob`) and also manages promise hooks.
    * The inclusion of `ScopedExceptionHandler` suggests error handling within microtask execution.

5. **Identify Supporting Functions:** The other methods in `MicrotaskQueueBuiltinsAssembler` are helper functions:
    * `GetMicrotaskQueue`, `GetMicrotaskRingBuffer`, etc.:  Functions for accessing the internal structure of the microtask queue.
    * `PrepareForContext`, `EnterContext`, `RewindEnteredContext`: Functions related to managing execution contexts.
    * `RunAllPromiseHooks`, `RunPromiseHook`: Functions for triggering promise hook callbacks.

6. **Connect to JavaScript:** Now, bridge the gap between the C++ implementation and the JavaScript API.
    * **`enqueueMicrotask()`:**  The `EnqueueMicrotask` built-in directly corresponds to the JavaScript `queueMicrotask()` function. This is the primary way JavaScript interacts with the microtask queue.
    * **Promises:** The code heavily involves promise reaction jobs. This highlights the connection between promises and the microtask queue. Promise resolutions and rejections trigger microtasks to handle the `.then()` and `.catch()` callbacks.
    * **`process.nextTick()` (Node.js):** While not directly mentioned in the code, it's important to know that `process.nextTick()` also uses the microtask queue (or a similar mechanism in Node.js) for scheduling tasks that execute before the next event loop iteration.

7. **Construct the Summary:**  Synthesize the findings into a concise summary. Focus on the main responsibilities of the file:
    * Implementing the core logic for the microtask queue.
    * Providing built-in functions for enqueueing and running microtasks.
    * Handling different types of microtasks (callbacks, promise reactions).
    * Integrating with the promise implementation.
    * Managing execution contexts during microtask execution.

8. **Create the JavaScript Example:**  Craft a simple JavaScript example that demonstrates the key concepts.
    * Show `queueMicrotask()` for basic microtask scheduling.
    * Illustrate how promises use the microtask queue for their asynchronous operations.
    * Optionally include `process.nextTick()` if the context warrants it (and acknowledge its Node.js specificity).
    * Explain the order of execution to highlight the microtask queue's behavior relative to the regular event loop.

9. **Review and Refine:** Check the summary and example for clarity, accuracy, and completeness. Ensure the JavaScript example correctly demonstrates the connection to the C++ code's functionality. For instance, make sure the example clearly shows that microtasks run *after* the current synchronous execution but *before* the next event loop cycle.

This systematic approach, starting with high-level understanding and progressively diving into details, helps in effectively analyzing and summarizing complex code like this. The key is to connect the internal implementation details to the observable behavior in JavaScript.
这个C++源代码文件 `builtins-microtask-queue-gen.cc` 是 V8 JavaScript 引擎的一部分，它**实现了与微任务队列相关的内置函数**。这些内置函数主要负责管理和执行 JavaScript 中的微任务。

**功能归纳:**

1. **定义了用于操作微任务队列的底层方法:**  该文件定义了一个名为 `MicrotaskQueueBuiltinsAssembler` 的类，它继承自 `CodeStubAssembler`。这个类包含了一系列方法，用于获取和设置微任务队列的各种属性，例如队列的容量、大小、起始位置、环形缓冲区等等。

2. **实现了 `EnqueueMicrotask` 内置函数:** 这个内置函数负责将一个微任务添加到微任务队列中。它会检查队列是否已满，如果满了则调用 C++ 代码进行扩容。

3. **实现了 `RunMicrotasks` 内置函数:** 这个内置函数负责执行当前微任务队列中的所有微任务。它会循环取出队列中的微任务，并调用 `RunSingleMicrotask` 来执行它们。

4. **实现了 `RunSingleMicrotask` 函数:**  这个函数是执行单个微任务的核心逻辑。它根据微任务的类型（例如：普通回调、Promise 的 resolve/reject 回调等）执行相应的操作。 这包括设置正确的执行上下文、调用微任务关联的回调函数，并处理可能发生的异常。

5. **处理 Promise 相关的微任务:**  代码中包含了对不同类型的 Promise 相关的微任务的处理，例如 `PROMISE_FULFILL_REACTION_JOB_TASK_TYPE` 和 `PROMISE_REJECT_REACTION_JOB_TASK_TYPE`。这表明该文件负责 Promise 链中 `.then()` 和 `.catch()` 回调的调度和执行。

6. **管理执行上下文:** 代码中包含了 `PrepareForContext`、`EnterContext` 和 `RewindEnteredContext` 等方法，用于在执行微任务时正确地设置和恢复 JavaScript 的执行上下文。

7. **实现 Promise 钩子 (Hooks):**  代码中包含了 `RunAllPromiseHooks` 和 `RunPromiseHook` 函数，用于在 Promise 微任务执行前后触发 Promise 钩子，这允许开发者或调试工具监控 Promise 的生命周期。

**与 JavaScript 的关系及示例:**

这个 C++ 文件中的代码是 JavaScript 中微任务机制的底层实现。JavaScript 开发者通常不会直接调用这些内置函数，而是通过 JavaScript 语法来使用微任务。

**JavaScript 示例:**

```javascript
// 使用 queueMicrotask API (现代浏览器和 Node.js v16+)
queueMicrotask(() => {
  console.log("这是一个微任务使用 queueMicrotask");
});

// 使用 Promise (Promise 的 then 和 catch 回调会作为微任务执行)
Promise.resolve().then(() => {
  console.log("这是一个微任务使用 Promise.resolve().then()");
});

Promise.reject().catch(() => {
  console.log("这是一个微任务使用 Promise.reject().catch()");
});

async function testAsync() {
  console.log("async 函数开始");
  await Promise.resolve(); // await 会暂停执行，并将后续代码作为微任务添加到队列
  console.log("async 函数 await 之后");
}
testAsync();

console.log("主线程代码");
```

**解释:**

* **`queueMicrotask()`:**  这是 JavaScript 中直接创建和调度微任务的标准 API。当调用 `queueMicrotask(callback)` 时，V8 引擎内部会调用类似 `EnqueueMicrotask` 的 C++ 内置函数将 `callback` 封装成一个微任务对象并添加到队列中。

* **Promise 的 `then` 和 `catch`:**  当一个 Promise 被 resolve 或 reject 时，其 `.then()` 或 `.catch()` 方法中指定的回调函数不会立即执行，而是会被放入微任务队列中。`builtins-microtask-queue-gen.cc` 中的代码负责处理这些 Promise 相关的微任务，并最终执行这些回调。

* **`async/await`:**  `async/await` 语法糖的底层实现也与微任务有关。当 `await` 一个 Promise 时，JavaScript 引擎会暂停当前 async 函数的执行，并将 `await` 之后的代码作为一个微任务添加到队列中，等待 Promise resolve 或 reject 后再执行。

**执行顺序:**

在上面的 JavaScript 示例中，控制台输出的顺序会是：

1. "主线程代码"
2. "async 函数开始"
3. "这是一个微任务使用 queueMicrotask"
4. "这是一个微任务使用 Promise.resolve().then()"
5. "这是一个微任务使用 Promise.reject().catch()"
6. "async 函数 await 之后"

**总结:**

`v8/src/builtins/builtins-microtask-queue-gen.cc` 文件是 V8 引擎中实现 JavaScript 微任务机制的关键部分。它提供了底层的 C++ 函数，用于管理微任务队列、添加微任务和执行微任务，并且与 Promise 的实现紧密相关。JavaScript 开发者通过 `queueMicrotask` API 和 Promise 等语法来间接使用这里实现的底层功能。

### 提示词
```
这是目录为v8/src/builtins/builtins-microtask-queue-gen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/api/api.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/execution/microtask-queue.h"
#include "src/objects/js-weak-refs.h"
#include "src/objects/microtask-inl.h"
#include "src/objects/promise.h"
#include "src/objects/smi-inl.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

using compiler::ScopedExceptionHandler;

class MicrotaskQueueBuiltinsAssembler : public CodeStubAssembler {
 public:
  explicit MicrotaskQueueBuiltinsAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  TNode<RawPtrT> GetMicrotaskQueue(TNode<Context> context);
  TNode<RawPtrT> GetMicrotaskRingBuffer(TNode<RawPtrT> microtask_queue);
  TNode<IntPtrT> GetMicrotaskQueueCapacity(TNode<RawPtrT> microtask_queue);
  TNode<IntPtrT> GetMicrotaskQueueSize(TNode<RawPtrT> microtask_queue);
  void SetMicrotaskQueueSize(TNode<RawPtrT> microtask_queue,
                             TNode<IntPtrT> new_size);
  TNode<IntPtrT> GetMicrotaskQueueStart(TNode<RawPtrT> microtask_queue);
  void SetMicrotaskQueueStart(TNode<RawPtrT> microtask_queue,
                              TNode<IntPtrT> new_start);
  TNode<IntPtrT> CalculateRingBufferOffset(TNode<IntPtrT> capacity,
                                           TNode<IntPtrT> start,
                                           TNode<IntPtrT> index);

  void PrepareForContext(TNode<Context> microtask_context, Label* bailout);
  void RunSingleMicrotask(TNode<Context> current_context,
                          TNode<Microtask> microtask);
  void IncrementFinishedMicrotaskCount(TNode<RawPtrT> microtask_queue);

  TNode<Context> GetCurrentContext();
  void SetCurrentContext(TNode<Context> context);

  TNode<IntPtrT> GetEnteredContextCount();
  void EnterContext(TNode<Context> native_context);
  void RewindEnteredContext(TNode<IntPtrT> saved_entered_context_count);

  void RunAllPromiseHooks(PromiseHookType type, TNode<Context> context,
                          TNode<HeapObject> promise_or_capability);
  void RunPromiseHook(Runtime::FunctionId id, TNode<Context> context,
                      TNode<HeapObject> promise_or_capability,
                      TNode<Uint32T> promiseHookFlags);
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  void SetupContinuationPreservedEmbedderData(TNode<Microtask> microtask);
  void ClearContinuationPreservedEmbedderData();
#endif
};

TNode<RawPtrT> MicrotaskQueueBuiltinsAssembler::GetMicrotaskQueue(
    TNode<Context> native_context) {
  CSA_DCHECK(this, IsNativeContext(native_context));
  return LoadExternalPointerFromObject(native_context,
                                       NativeContext::kMicrotaskQueueOffset,
                                       kNativeContextMicrotaskQueueTag);
}

TNode<RawPtrT> MicrotaskQueueBuiltinsAssembler::GetMicrotaskRingBuffer(
    TNode<RawPtrT> microtask_queue) {
  return Load<RawPtrT>(microtask_queue,
                       IntPtrConstant(MicrotaskQueue::kRingBufferOffset));
}

TNode<IntPtrT> MicrotaskQueueBuiltinsAssembler::GetMicrotaskQueueCapacity(
    TNode<RawPtrT> microtask_queue) {
  return Load<IntPtrT>(microtask_queue,
                       IntPtrConstant(MicrotaskQueue::kCapacityOffset));
}

TNode<IntPtrT> MicrotaskQueueBuiltinsAssembler::GetMicrotaskQueueSize(
    TNode<RawPtrT> microtask_queue) {
  return Load<IntPtrT>(microtask_queue,
                       IntPtrConstant(MicrotaskQueue::kSizeOffset));
}

void MicrotaskQueueBuiltinsAssembler::SetMicrotaskQueueSize(
    TNode<RawPtrT> microtask_queue, TNode<IntPtrT> new_size) {
  StoreNoWriteBarrier(MachineType::PointerRepresentation(), microtask_queue,
                      IntPtrConstant(MicrotaskQueue::kSizeOffset), new_size);
}

TNode<IntPtrT> MicrotaskQueueBuiltinsAssembler::GetMicrotaskQueueStart(
    TNode<RawPtrT> microtask_queue) {
  return Load<IntPtrT>(microtask_queue,
                       IntPtrConstant(MicrotaskQueue::kStartOffset));
}

void MicrotaskQueueBuiltinsAssembler::SetMicrotaskQueueStart(
    TNode<RawPtrT> microtask_queue, TNode<IntPtrT> new_start) {
  StoreNoWriteBarrier(MachineType::PointerRepresentation(), microtask_queue,
                      IntPtrConstant(MicrotaskQueue::kStartOffset), new_start);
}

TNode<IntPtrT> MicrotaskQueueBuiltinsAssembler::CalculateRingBufferOffset(
    TNode<IntPtrT> capacity, TNode<IntPtrT> start, TNode<IntPtrT> index) {
  return TimesSystemPointerSize(
      WordAnd(IntPtrAdd(start, index), IntPtrSub(capacity, IntPtrConstant(1))));
}

void MicrotaskQueueBuiltinsAssembler::PrepareForContext(
    TNode<Context> native_context, Label* bailout) {
  CSA_DCHECK(this, IsNativeContext(native_context));

  // Skip the microtask execution if the associated context is shutdown.
  GotoIf(WordEqual(GetMicrotaskQueue(native_context), IntPtrConstant(0)),
         bailout);

  EnterContext(native_context);
  SetCurrentContext(native_context);
}

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
void MicrotaskQueueBuiltinsAssembler::SetupContinuationPreservedEmbedderData(
    TNode<Microtask> microtask) {
  TNode<Object> continuation_preserved_embedder_data = LoadObjectField(
      microtask, Microtask::kContinuationPreservedEmbedderDataOffset);
  Label continuation_preserved_data_done(this);
  // The isolate's continuation preserved embedder data is cleared at the start
  // of RunMicrotasks and after each microtask, so it only needs to be set if
  // it's not undefined.
  GotoIf(IsUndefined(continuation_preserved_embedder_data),
         &continuation_preserved_data_done);
  SetContinuationPreservedEmbedderData(continuation_preserved_embedder_data);
  Goto(&continuation_preserved_data_done);
  BIND(&continuation_preserved_data_done);
}

void MicrotaskQueueBuiltinsAssembler::ClearContinuationPreservedEmbedderData() {
  SetContinuationPreservedEmbedderData(UndefinedConstant());
}
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

void MicrotaskQueueBuiltinsAssembler::RunSingleMicrotask(
    TNode<Context> current_context, TNode<Microtask> microtask) {
  CSA_DCHECK(this, TaggedIsNotSmi(microtask));
  CSA_DCHECK(this, Word32BinaryNot(IsExecutionTerminating()));

  StoreRoot(RootIndex::kCurrentMicrotask, microtask);
  TNode<IntPtrT> saved_entered_context_count = GetEnteredContextCount();
  TNode<Map> microtask_map = LoadMap(microtask);
  TNode<Uint16T> microtask_type = LoadMapInstanceType(microtask_map);

  TVARIABLE(Object, var_exception);
  Label if_exception(this, Label::kDeferred);
  Label is_callable(this), is_callback(this),
      is_promise_fulfill_reaction_job(this),
      is_promise_reject_reaction_job(this),
      is_promise_resolve_thenable_job(this),
      is_unreachable(this, Label::kDeferred), done(this);

  int32_t case_values[] = {CALLABLE_TASK_TYPE, CALLBACK_TASK_TYPE,
                           PROMISE_FULFILL_REACTION_JOB_TASK_TYPE,
                           PROMISE_REJECT_REACTION_JOB_TASK_TYPE,
                           PROMISE_RESOLVE_THENABLE_JOB_TASK_TYPE};
  Label* case_labels[] = {
      &is_callable, &is_callback, &is_promise_fulfill_reaction_job,
      &is_promise_reject_reaction_job, &is_promise_resolve_thenable_job};
  static_assert(arraysize(case_values) == arraysize(case_labels), "");
  Switch(microtask_type, &is_unreachable, case_values, case_labels,
         arraysize(case_labels));

  BIND(&is_callable);
  {
    // Enter the context of the {microtask}.
    TNode<Context> microtask_context =
        LoadObjectField<Context>(microtask, CallableTask::kContextOffset);
    TNode<NativeContext> native_context = LoadNativeContext(microtask_context);
    PrepareForContext(native_context, &done);

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    SetupContinuationPreservedEmbedderData(microtask);
#endif
    TNode<JSReceiver> callable =
        LoadObjectField<JSReceiver>(microtask, CallableTask::kCallableOffset);
    {
      ScopedExceptionHandler handler(this, &if_exception, &var_exception);
      Call(microtask_context, callable, UndefinedConstant());
    }
    RewindEnteredContext(saved_entered_context_count);
    SetCurrentContext(current_context);
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    ClearContinuationPreservedEmbedderData();
#endif
    Goto(&done);
  }

  BIND(&is_callback);
  {
    const TNode<Object> microtask_callback =
        LoadObjectField(microtask, CallbackTask::kCallbackOffset);
    const TNode<Object> microtask_data =
        LoadObjectField(microtask, CallbackTask::kDataOffset);
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    SetupContinuationPreservedEmbedderData(microtask);
#endif

    // If this turns out to become a bottleneck because of the calls
    // to C++ via CEntry, we can choose to speed them up using a
    // similar mechanism that we use for the CallApiFunction stub,
    // except that calling the MicrotaskCallback is even easier, since
    // it doesn't accept any tagged parameters, doesn't return a value
    // and ignores exceptions.
    //
    // But from our current measurements it doesn't seem to be a
    // serious performance problem, even if the microtask is full
    // of CallHandlerTasks (which is not a realistic use case anyways).
    {
      ScopedExceptionHandler handler(this, &if_exception, &var_exception);
      CallRuntime(Runtime::kRunMicrotaskCallback, current_context,
                  microtask_callback, microtask_data);
    }
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    ClearContinuationPreservedEmbedderData();
#endif
    Goto(&done);
  }

  BIND(&is_promise_resolve_thenable_job);
  {
    // Enter the context of the {microtask}.
    TNode<Context> microtask_context = LoadObjectField<Context>(
        microtask, PromiseResolveThenableJobTask::kContextOffset);
    TNode<NativeContext> native_context = LoadNativeContext(microtask_context);
    PrepareForContext(native_context, &done);

    const TNode<Object> promise_to_resolve = LoadObjectField(
        microtask, PromiseResolveThenableJobTask::kPromiseToResolveOffset);
    const TNode<Object> then =
        LoadObjectField(microtask, PromiseResolveThenableJobTask::kThenOffset);
    const TNode<Object> thenable = LoadObjectField(
        microtask, PromiseResolveThenableJobTask::kThenableOffset);
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    SetupContinuationPreservedEmbedderData(microtask);
#endif
    RunAllPromiseHooks(PromiseHookType::kBefore, microtask_context,
                   CAST(promise_to_resolve));

    {
      ScopedExceptionHandler handler(this, &if_exception, &var_exception);
      CallBuiltin(Builtin::kPromiseResolveThenableJob, native_context,
                  promise_to_resolve, thenable, then);
    }

    RunAllPromiseHooks(PromiseHookType::kAfter, microtask_context,
                   CAST(promise_to_resolve));

    RewindEnteredContext(saved_entered_context_count);
    SetCurrentContext(current_context);
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    ClearContinuationPreservedEmbedderData();
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    Goto(&done);
  }

  BIND(&is_promise_fulfill_reaction_job);
  {
    // Enter the context of the {microtask}.
    TNode<Context> microtask_context = LoadObjectField<Context>(
        microtask, PromiseReactionJobTask::kContextOffset);
    TNode<NativeContext> native_context = LoadNativeContext(microtask_context);
    PrepareForContext(native_context, &done);

    const TNode<Object> argument =
        LoadObjectField(microtask, PromiseReactionJobTask::kArgumentOffset);
    const TNode<Object> job_handler =
        LoadObjectField(microtask, PromiseReactionJobTask::kHandlerOffset);
    const TNode<HeapObject> promise_or_capability = CAST(LoadObjectField(
        microtask, PromiseReactionJobTask::kPromiseOrCapabilityOffset));

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    SetupContinuationPreservedEmbedderData(microtask);
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

    // Run the promise before/debug hook if enabled.
    RunAllPromiseHooks(PromiseHookType::kBefore, microtask_context,
                       promise_or_capability);

    {
      ScopedExceptionHandler handler(this, &if_exception, &var_exception);
      CallBuiltin(Builtin::kPromiseFulfillReactionJob, microtask_context,
                  argument, job_handler, promise_or_capability);
    }

    // Run the promise after/debug hook if enabled.
    RunAllPromiseHooks(PromiseHookType::kAfter, microtask_context,
                       promise_or_capability);

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    ClearContinuationPreservedEmbedderData();
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

    RewindEnteredContext(saved_entered_context_count);
    SetCurrentContext(current_context);
    Goto(&done);
  }

  BIND(&is_promise_reject_reaction_job);
  {
    // Enter the context of the {microtask}.
    TNode<Context> microtask_context = LoadObjectField<Context>(
        microtask, PromiseReactionJobTask::kContextOffset);
    TNode<NativeContext> native_context = LoadNativeContext(microtask_context);
    PrepareForContext(native_context, &done);

    const TNode<Object> argument =
        LoadObjectField(microtask, PromiseReactionJobTask::kArgumentOffset);
    const TNode<Object> job_handler =
        LoadObjectField(microtask, PromiseReactionJobTask::kHandlerOffset);
    const TNode<HeapObject> promise_or_capability = CAST(LoadObjectField(
        microtask, PromiseReactionJobTask::kPromiseOrCapabilityOffset));

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    SetupContinuationPreservedEmbedderData(microtask);
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

    // Run the promise before/debug hook if enabled.
    RunAllPromiseHooks(PromiseHookType::kBefore, microtask_context,
                       promise_or_capability);

    {
      ScopedExceptionHandler handler(this, &if_exception, &var_exception);
      CallBuiltin(Builtin::kPromiseRejectReactionJob, microtask_context,
                  argument, job_handler, promise_or_capability);
    }

    // Run the promise after/debug hook if enabled.
    RunAllPromiseHooks(PromiseHookType::kAfter, microtask_context,
                       promise_or_capability);

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    ClearContinuationPreservedEmbedderData();
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

    RewindEnteredContext(saved_entered_context_count);
    SetCurrentContext(current_context);
    Goto(&done);
  }

  BIND(&is_unreachable);
  Unreachable();

  BIND(&if_exception);
  {
    // Report unhandled exceptions from microtasks.
    CallRuntime(Runtime::kReportMessageFromMicrotask, GetCurrentContext(),
                var_exception.value());
    RewindEnteredContext(saved_entered_context_count);
    SetCurrentContext(current_context);
    Goto(&done);
  }

  BIND(&done);
}

void MicrotaskQueueBuiltinsAssembler::IncrementFinishedMicrotaskCount(
    TNode<RawPtrT> microtask_queue) {
  TNode<IntPtrT> count = Load<IntPtrT>(
      microtask_queue,
      IntPtrConstant(MicrotaskQueue::kFinishedMicrotaskCountOffset));
  TNode<IntPtrT> new_count = IntPtrAdd(count, IntPtrConstant(1));
  StoreNoWriteBarrier(
      MachineType::PointerRepresentation(), microtask_queue,
      IntPtrConstant(MicrotaskQueue::kFinishedMicrotaskCountOffset), new_count);
}

TNode<Context> MicrotaskQueueBuiltinsAssembler::GetCurrentContext() {
  auto ref = ExternalReference::Create(kContextAddress, isolate());
  // TODO(delphick): Add a checked cast. For now this is not possible as context
  // can actually be Tagged<Smi>(0).
  return TNode<Context>::UncheckedCast(LoadFullTagged(ExternalConstant(ref)));
}

void MicrotaskQueueBuiltinsAssembler::SetCurrentContext(
    TNode<Context> context) {
  auto ref = ExternalReference::Create(kContextAddress, isolate());
  StoreFullTaggedNoWriteBarrier(ExternalConstant(ref), context);
}

TNode<IntPtrT> MicrotaskQueueBuiltinsAssembler::GetEnteredContextCount() {
  auto ref = ExternalReference::handle_scope_implementer_address(isolate());
  TNode<RawPtrT> hsi = Load<RawPtrT>(ExternalConstant(ref));

  using ContextStack = DetachableVector<Context>;
  TNode<IntPtrT> size_offset =
      IntPtrConstant(HandleScopeImplementer::kEnteredContextsOffset +
                     ContextStack::kSizeOffset);
  return Load<IntPtrT>(hsi, size_offset);
}

void MicrotaskQueueBuiltinsAssembler::EnterContext(
    TNode<Context> native_context) {
  CSA_DCHECK(this, IsNativeContext(native_context));

  auto ref = ExternalReference::handle_scope_implementer_address(isolate());
  TNode<RawPtrT> hsi = Load<RawPtrT>(ExternalConstant(ref));

  using ContextStack = DetachableVector<Context>;
  TNode<IntPtrT> capacity_offset =
      IntPtrConstant(HandleScopeImplementer::kEnteredContextsOffset +
                     ContextStack::kCapacityOffset);
  TNode<IntPtrT> size_offset =
      IntPtrConstant(HandleScopeImplementer::kEnteredContextsOffset +
                     ContextStack::kSizeOffset);

  TNode<IntPtrT> capacity = Load<IntPtrT>(hsi, capacity_offset);
  TNode<IntPtrT> size = Load<IntPtrT>(hsi, size_offset);

  Label if_append(this), if_grow(this, Label::kDeferred), done(this);
  Branch(WordEqual(size, capacity), &if_grow, &if_append);
  BIND(&if_append);
  {
    TNode<IntPtrT> data_offset =
        IntPtrConstant(HandleScopeImplementer::kEnteredContextsOffset +
                       ContextStack::kDataOffset);
    TNode<RawPtrT> data = Load<RawPtrT>(hsi, data_offset);
    StoreFullTaggedNoWriteBarrier(data, TimesSystemPointerSize(size),
                                  native_context);

    TNode<IntPtrT> new_size = IntPtrAdd(size, IntPtrConstant(1));
    StoreNoWriteBarrier(MachineType::PointerRepresentation(), hsi, size_offset,
                        new_size);
    Goto(&done);
  }

  BIND(&if_grow);
  {
    TNode<ExternalReference> function =
        ExternalConstant(ExternalReference::call_enter_context_function());
    CallCFunction(function, MachineType::Int32(),
                  std::make_pair(MachineType::Pointer(), hsi),
                  std::make_pair(MachineType::Pointer(),
                                 BitcastTaggedToWord(native_context)));
    Goto(&done);
  }

  BIND(&done);
}

void MicrotaskQueueBuiltinsAssembler::RewindEnteredContext(
    TNode<IntPtrT> saved_entered_context_count) {
  auto ref = ExternalReference::handle_scope_implementer_address(isolate());
  TNode<RawPtrT> hsi = Load<RawPtrT>(ExternalConstant(ref));

  using ContextStack = DetachableVector<Context>;
  TNode<IntPtrT> size_offset =
      IntPtrConstant(HandleScopeImplementer::kEnteredContextsOffset +
                     ContextStack::kSizeOffset);

  if (DEBUG_BOOL) {
    TNode<IntPtrT> size = Load<IntPtrT>(hsi, size_offset);
    CSA_CHECK(this, IntPtrLessThan(IntPtrConstant(0), size));
    CSA_CHECK(this, IntPtrLessThanOrEqual(saved_entered_context_count, size));
  }

  StoreNoWriteBarrier(MachineType::PointerRepresentation(), hsi, size_offset,
                      saved_entered_context_count);
}

void MicrotaskQueueBuiltinsAssembler::RunAllPromiseHooks(
    PromiseHookType type, TNode<Context> context,
    TNode<HeapObject> promise_or_capability) {
  TNode<Uint32T> promiseHookFlags = PromiseHookFlags();
#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
  Label hook(this, Label::kDeferred), done_hook(this);
  Branch(NeedsAnyPromiseHooks(promiseHookFlags), &hook, &done_hook);
  BIND(&hook);
  {
#endif
    switch (type) {
      case PromiseHookType::kBefore:
#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
        RunContextPromiseHookBefore(context, promise_or_capability,
                                    promiseHookFlags);
#endif
        RunPromiseHook(Runtime::kPromiseHookBefore, context,
                       promise_or_capability, promiseHookFlags);
        break;
      case PromiseHookType::kAfter:
#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
        RunContextPromiseHookAfter(context, promise_or_capability,
                                   promiseHookFlags);
#endif
        RunPromiseHook(Runtime::kPromiseHookAfter, context,
                       promise_or_capability, promiseHookFlags);
        break;
      default:
        UNREACHABLE();
    }
#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
    Goto(&done_hook);
  }
  BIND(&done_hook);
#endif
}

void MicrotaskQueueBuiltinsAssembler::RunPromiseHook(
    Runtime::FunctionId id, TNode<Context> context,
    TNode<HeapObject> promise_or_capability,
    TNode<Uint32T> promiseHookFlags) {
  Label hook(this, Label::kDeferred), done_hook(this);
  Branch(IsIsolatePromiseHookEnabledOrDebugIsActiveOrHasAsyncEventDelegate(
      promiseHookFlags), &hook, &done_hook);
  BIND(&hook);
  {
    // Get to the underlying JSPromise instance.
    TNode<HeapObject> promise = Select<HeapObject>(
        IsPromiseCapability(promise_or_capability),
        [=, this] {
          return CAST(LoadObjectField(promise_or_capability,
                                      PromiseCapability::kPromiseOffset));
        },

        [=] { return promise_or_capability; });
    GotoIf(IsUndefined(promise), &done_hook);
    CallRuntime(id, context, promise);
    Goto(&done_hook);
  }
  BIND(&done_hook);
}

TF_BUILTIN(EnqueueMicrotask, MicrotaskQueueBuiltinsAssembler) {
  auto microtask = Parameter<Microtask>(Descriptor::kMicrotask);
  auto context = Parameter<Context>(Descriptor::kContext);
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<RawPtrT> microtask_queue = GetMicrotaskQueue(native_context);

  // Do not store the microtask if MicrotaskQueue is not available, that may
  // happen when the context shutdown.
  Label if_shutdown(this, Label::kDeferred);
  GotoIf(WordEqual(microtask_queue, IntPtrConstant(0)), &if_shutdown);

  TNode<RawPtrT> ring_buffer = GetMicrotaskRingBuffer(microtask_queue);
  TNode<IntPtrT> capacity = GetMicrotaskQueueCapacity(microtask_queue);
  TNode<IntPtrT> size = GetMicrotaskQueueSize(microtask_queue);
  TNode<IntPtrT> start = GetMicrotaskQueueStart(microtask_queue);

  Label if_grow(this, Label::kDeferred);
  GotoIf(IntPtrEqual(size, capacity), &if_grow);

  // |microtask_queue| has an unused slot to store |microtask|.
  {
    StoreNoWriteBarrier(MachineType::PointerRepresentation(), ring_buffer,
                        CalculateRingBufferOffset(capacity, start, size),
                        BitcastTaggedToWord(microtask));
    StoreNoWriteBarrier(MachineType::PointerRepresentation(), microtask_queue,
                        IntPtrConstant(MicrotaskQueue::kSizeOffset),
                        IntPtrAdd(size, IntPtrConstant(1)));
    Return(UndefinedConstant());
  }

  // |microtask_queue| has no space to store |microtask|. Fall back to C++
  // implementation to grow the buffer.
  BIND(&if_grow);
  {
    TNode<ExternalReference> isolate_constant =
        ExternalConstant(ExternalReference::isolate_address());
    TNode<ExternalReference> function =
        ExternalConstant(ExternalReference::call_enqueue_microtask_function());
    CallCFunction(function, MachineType::AnyTagged(),
                  std::make_pair(MachineType::Pointer(), isolate_constant),
                  std::make_pair(MachineType::IntPtr(), microtask_queue),
                  std::make_pair(MachineType::AnyTagged(), microtask));
    Return(UndefinedConstant());
  }

  Bind(&if_shutdown);
  Return(UndefinedConstant());
}

TF_BUILTIN(RunMicrotasks, MicrotaskQueueBuiltinsAssembler) {
  // Load the current context from the isolate.
  TNode<Context> current_context = GetCurrentContext();

  auto microtask_queue =
      UncheckedParameter<RawPtrT>(Descriptor::kMicrotaskQueue);

  Label loop(this), done(this);
  Goto(&loop);
  BIND(&loop);

  TNode<IntPtrT> size = GetMicrotaskQueueSize(microtask_queue);

  // Exit if the queue is empty.
  GotoIf(WordEqual(size, IntPtrConstant(0)), &done);

  TNode<RawPtrT> ring_buffer = GetMicrotaskRingBuffer(microtask_queue);
  TNode<IntPtrT> capacity = GetMicrotaskQueueCapacity(microtask_queue);
  TNode<IntPtrT> start = GetMicrotaskQueueStart(microtask_queue);

  TNode<IntPtrT> offset =
      CalculateRingBufferOffset(capacity, start, IntPtrConstant(0));
  TNode<RawPtrT> microtask_pointer = Load<RawPtrT>(ring_buffer, offset);
  TNode<Microtask> microtask = CAST(BitcastWordToTagged(microtask_pointer));

  TNode<IntPtrT> new_size = IntPtrSub(size, IntPtrConstant(1));
  TNode<IntPtrT> new_start = WordAnd(IntPtrAdd(start, IntPtrConstant(1)),
                                     IntPtrSub(capacity, IntPtrConstant(1)));

  // Remove |microtask| from |ring_buffer| before running it, since its
  // invocation may add another microtask into |ring_buffer|.
  SetMicrotaskQueueSize(microtask_queue, new_size);
  SetMicrotaskQueueStart(microtask_queue, new_start);

  RunSingleMicrotask(current_context, microtask);
  IncrementFinishedMicrotaskCount(microtask_queue);
  Goto(&loop);

  BIND(&done);
  {
    // Reset the "current microtask" on the isolate.
    StoreRoot(RootIndex::kCurrentMicrotask, UndefinedConstant());
    Return(UndefinedConstant());
  }
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8
```