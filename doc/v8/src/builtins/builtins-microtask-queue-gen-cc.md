Response:
Let's break down the thought process for analyzing the provided V8 source code.

**1. Initial Understanding and Context:**

* **Language:** The code is in C++. The `#include` directives point to V8 internal headers. The `namespace v8::internal` confirms this.
* **File Name:** `builtins-microtask-queue-gen.cc`. The `builtins` part suggests this code implements built-in functionalities. `microtask-queue` clearly indicates the subject matter. The `-gen.cc` suffix often implies generated code, but in Torque's context, it's also used for the output of the Torque compiler. Since the prompt mentions `.tq`, we need to keep in mind the possibility of it being a generated C++ file from a Torque source.
* **Copyright:** The copyright notice at the top confirms it's part of the V8 project.

**2. High-Level Structure and Key Components:**

* **`MicrotaskQueueBuiltinsAssembler` Class:** This is the central class. It inherits from `CodeStubAssembler`, indicating it's related to V8's code generation and execution infrastructure.
* **Methods within the Class:**  A quick scan of the methods reveals operations related to:
    * Getting and setting microtask queue properties (capacity, size, start, buffer).
    * Running microtasks.
    * Managing execution contexts.
    * Handling promise hooks.
    * Interacting with C++ runtime functions.
* **`TF_BUILTIN` Macros:** These are V8 macros that define built-in functions callable from JavaScript. `EnqueueMicrotask` and `RunMicrotasks` are immediately apparent as the main entry points.

**3. Functionality Breakdown (Iterative Process):**

* **Core Data Structures:**  The methods `GetMicrotaskQueue`, `GetMicrotaskRingBuffer`, etc., point to the existence of a `MicrotaskQueue` data structure. The comments and field names (e.g., `kRingBufferOffset`, `kCapacityOffset`) provide hints about its organization (a ring buffer).
* **`EnqueueMicrotask`:**
    * **Purpose:**  This function is responsible for adding a microtask to the queue.
    * **Logic:** It checks for space in the ring buffer. If space is available, it adds the microtask. If not, it calls a C++ function to grow the buffer. There's also a check for context shutdown.
    * **JavaScript Relation:**  This directly relates to `queueMicrotask()` and promise resolution.
* **`RunMicrotasks`:**
    * **Purpose:**  This function executes the microtasks in the queue.
    * **Logic:** It loops while the queue is not empty, retrieves a microtask, removes it from the queue, and then calls `RunSingleMicrotask`. It also handles context management and promise hooks.
    * **JavaScript Relation:** This is the engine's mechanism for processing the microtasks queued via `queueMicrotask()` and promise resolutions.
* **`RunSingleMicrotask`:**
    * **Purpose:** Executes a single microtask based on its type.
    * **Logic:** Uses a `switch` statement based on the microtask's type (callable, callback, promise reactions). It handles context switching, error handling, and promise hooks.
* **Context Management:**  Methods like `EnterContext`, `RewindEnteredContext`, `GetCurrentContext`, and `SetCurrentContext` indicate how V8 manages the execution context when running microtasks. This is crucial for security and correctness.
* **Promise Hooks:**  `RunAllPromiseHooks` and `RunPromiseHook` show the integration of promise debugging and observability features.
* **Helper Functions:**  Functions like `CalculateRingBufferOffset` are utility functions for managing the ring buffer.

**4. Addressing Specific Prompt Questions:**

* **Functionality Listing:**  Based on the breakdown above, a list of functionalities can be compiled.
* **Torque Source:**  The prompt specifically asks about the `.tq` extension. The code structure with `CodeStubAssembler` and the `-gen.cc` suffix strongly suggests that this *is* likely the output of the Torque compiler.
* **JavaScript Examples:**  Connect the built-in functions to their JavaScript counterparts (`queueMicrotask`, Promises).
* **Code Logic Inference:**  For `EnqueueMicrotask` and `RunMicrotasks`, think about typical queue operations (enqueue, dequeue) and how they are implemented with a ring buffer. Consider edge cases like a full queue. Provide simple input/output scenarios for clarity.
* **Common Programming Errors:**  Think about how developers might misuse microtasks or encounter issues related to their asynchronous nature (e.g., infinite loops, unexpected execution order, unhandled rejections).

**5. Refinement and Organization:**

* **Structure the Answer:**  Use headings and bullet points to organize the information logically.
* **Clarity and Conciseness:**  Explain technical terms clearly and avoid unnecessary jargon.
* **Code Snippets:** Include relevant code snippets to illustrate specific points.
* **Review:**  Read through the answer to ensure accuracy and completeness.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe it's just regular C++.
* **Correction:** The presence of `CodeStubAssembler` and the `-gen.cc` strongly indicates it's related to V8's code generation and, given the prompt's hint, likely generated from Torque.
* **Initial thought:** Focus only on the public API.
* **Correction:** The internal functions are key to understanding the *how* of microtask execution. Include details about the ring buffer and context management.
* **Initial thought:**  Provide very complex JavaScript examples.
* **Correction:** Simple, illustrative examples are more effective for demonstrating the core concepts.

By following this iterative process of understanding the context, breaking down the code, connecting it to JavaScript, and addressing the specific questions, we can arrive at a comprehensive and accurate analysis of the provided V8 source code.
Based on the provided C++ source code `v8/src/builtins/builtins-microtask-queue-gen.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This file implements the built-in functions responsible for managing and executing the microtask queue in V8. Microtasks are short, asynchronous operations that are executed after the current JavaScript task completes but before the event loop proceeds to the next task. Think of them as a higher-priority queue for asynchronous operations compared to the regular event queue.

**Key Responsibilities:**

1. **Enqueueing Microtasks (`EnqueueMicrotask`):**
   - Takes a `Microtask` object (which can be a `CallableTask`, `CallbackTask`, or a promise reaction job) and the current `Context`.
   - Retrieves the microtask queue associated with the current context's native context.
   - Stores the microtask in the microtask queue's ring buffer.
   - If the queue is full, it triggers a resizing mechanism (implemented in C++).

2. **Running Microtasks (`RunMicrotasks`):**
   - Retrieves the microtask queue.
   - Iteratively dequeues and executes microtasks until the queue is empty.
   - For each microtask, it calls `RunSingleMicrotask`.

3. **Executing a Single Microtask (`RunSingleMicrotask`):**
   - Takes the current `Context` and a `Microtask` object.
   - Determines the type of microtask (e.g., callable function, callback, promise reaction job).
   - Sets up the appropriate execution environment, including entering the microtask's context.
   - Executes the microtask's associated logic:
     - For `CallableTask`: Calls the stored JavaScript function.
     - For `CallbackTask`: Executes a C++ callback function.
     - For Promise reaction jobs (`PromiseFulfillReactionJob`, `PromiseRejectReactionJob`, `PromiseResolveThenableJob`): Calls the corresponding built-in functions to handle promise resolution/rejection.
   - Handles exceptions that might occur during microtask execution.
   - Runs promise hooks (for debugging and observability) before and after promise-related microtasks.

4. **Managing the Microtask Queue Data Structure:**
   - Provides methods to get and set properties of the microtask queue:
     - `GetMicrotaskQueue`: Retrieves the microtask queue from the native context.
     - `GetMicrotaskRingBuffer`: Gets the underlying ring buffer where microtasks are stored.
     - `GetMicrotaskQueueCapacity`, `GetMicrotaskQueueSize`, `GetMicrotaskQueueStart`: Access size and indexing information of the ring buffer.
     - `SetMicrotaskQueueSize`, `SetMicrotaskQueueStart`:  Modify the size and starting point of the queue (used during dequeueing).
     - `CalculateRingBufferOffset`: Calculates the memory offset within the ring buffer for a given index.

5. **Context Management:**
   - Provides functions to manage the JavaScript execution context when running microtasks:
     - `PrepareForContext`: Enters the microtask's associated context.
     - `EnterContext`, `RewindEnteredContext`: Manages a stack of entered contexts, crucial for maintaining the correct execution environment.
     - `GetCurrentContext`, `SetCurrentContext`: Get and set the currently executing JavaScript context.

6. **Promise Hook Integration:**
   - Includes logic to trigger promise hooks (`RunAllPromiseHooks`, `RunPromiseHook`) which allow developers and debuggers to observe the lifecycle of promises.

**If `v8/src/builtins/builtins-microtask-queue-gen.cc` ended with `.tq`:**

Yes, if the file ended with `.tq`, it would be a **V8 Torque source file**. Torque is V8's domain-specific language for writing built-in functions. The `.cc` file you provided is likely the **generated C++ code** produced by the Torque compiler from the `.tq` source. Torque provides a higher-level, more type-safe way to define built-ins compared to writing raw C++.

**Relationship with JavaScript Functionality (and JavaScript Examples):**

This C++ code directly implements the underlying mechanisms for JavaScript's microtask queue. The most relevant JavaScript features are:

* **`queueMicrotask(callback)`:** This JavaScript function enqueues a microtask to be executed after the current task. The `EnqueueMicrotask` built-in function is the C++ implementation that handles this.

   ```javascript
   console.log("Start");

   queueMicrotask(() => {
     console.log("Microtask 1");
   });

   Promise.resolve().then(() => {
     console.log("Microtask from Promise");
   });

   console.log("End");
   ```

   **Execution Order:**

   1. "Start"
   2. "End"
   3. "Microtask 1" (from `queueMicrotask`)
   4. "Microtask from Promise" (from the resolved Promise)

   Both `queueMicrotask` and Promise resolutions schedule microtasks. The V8 code in this file ensures they are executed in the correct order after the main synchronous code.

* **Promises:** When a promise resolves or rejects, the associated `then()` or `catch()` handlers are executed as microtasks. The `PromiseFulfillReactionJob` and `PromiseRejectReactionJob` logic in the C++ code handles the execution of these handlers.

**Code Logic Inference (Hypothetical Example):**

**Assumption:** The microtask queue has a capacity of 3, and initially, it's empty (size = 0, start = 0).

**Input:**

1. `EnqueueMicrotask(microtaskA, context)`
2. `EnqueueMicrotask(microtaskB, context)`
3. `RunMicrotasks(microtask_queue)`

**Output and Internal State Changes:**

1. **After Enqueueing `microtaskA`:**
   - `size` becomes 1.
   - `microtaskA` is stored at `ring_buffer[0]` (calculated using `CalculateRingBufferOffset`).

2. **After Enqueueing `microtaskB`:**
   - `size` becomes 2.
   - `microtaskB` is stored at `ring_buffer[1]`.

3. **During `RunMicrotasks`:**
   - **Iteration 1:**
     - `size` is 2.
     - `microtaskA` is retrieved from `ring_buffer[0]`.
     - `RunSingleMicrotask(context, microtaskA)` is called.
     - `size` becomes 1.
     - `start` becomes 1 (moves to the next available slot for dequeueing).
   - **Iteration 2:**
     - `size` is 1.
     - `microtaskB` is retrieved from `ring_buffer[1]` (offset calculated with the updated `start`).
     - `RunSingleMicrotask(context, microtaskB)` is called.
     - `size` becomes 0.
     - `start` becomes 2.
   - The loop terminates because `size` is now 0.

**Common Programming Errors (Related to Microtasks):**

1. **Infinite Microtask Loops:**  A microtask can schedule another microtask. If this is done unconditionally, it can lead to an infinite loop, blocking the event loop and freezing the application.

   ```javascript
   queueMicrotask(function taskA() {
     console.log("Task A");
     queueMicrotask(taskA); // Schedules itself again infinitely
   });
   ```

   **Consequence:** The "Task A" log will print indefinitely, and other events and interactions will be blocked.

2. **Unexpected Execution Order:**  Developers might misunderstand that microtasks execute *before* the next task in the event loop. This can lead to issues if they assume a certain state will be available in a microtask that is actually updated in a later task.

   ```javascript
   let data = null;

   setTimeout(() => {
     data = "Data loaded";
     console.log("Timeout done");
   }, 0);

   Promise.resolve().then(() => {
     console.log(data.toUpperCase()); // Potential error if timeout hasn't completed
   });

   console.log("Initial code");
   ```

   **Potential Error:**  If the Promise microtask executes before the `setTimeout` callback, `data` will still be `null`, leading to a `TypeError`.

3. **Unhandled Promise Rejections:** While not directly a microtask error, unhandled rejections from promises are often reported as part of the microtask queue processing. Failing to catch rejections can lead to errors and warnings.

   ```javascript
   Promise.reject("Something went wrong"); // Unhandled rejection
   ```

   V8 will often report this unhandled rejection during the microtask processing phase.

In summary, `v8/src/builtins/builtins-microtask-queue-gen.cc` is a crucial piece of V8's infrastructure, responsible for the correct and efficient management and execution of JavaScript's microtask queue, which underpins Promises and the `queueMicrotask` API.

Prompt: 
```
这是目录为v8/src/builtins/builtins-microtask-queue-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-microtask-queue-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
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

"""

```