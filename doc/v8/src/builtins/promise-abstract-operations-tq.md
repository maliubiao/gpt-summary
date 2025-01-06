Response: Let's break down the thought process for analyzing this Torque file.

1. **Understand the Goal:** The request asks for a summary of the file's functionality, its relationship to JavaScript, illustrative examples, logical deductions, and common programming errors. This means I need to go beyond a simple description of the code and connect it to user-facing concepts.

2. **Identify the Core Area:** The file path `v8/src/builtins/promise-abstract-operations.tq` and the namespace `promise` immediately indicate that this code deals with the internal workings of JavaScript Promises in V8. The "abstract operations" part suggests it implements the core logic defined in the ECMAScript specification.

3. **Initial Scan for Key Concepts:** I'd quickly scan the file for keywords and function/macro names related to Promises. Terms like "FulfillPromise", "RejectPromise", "TriggerPromiseReactions", "NewPromiseCapability", "PromiseThen", "PromiseResolve", "PromiseReject", "Microtask", "PromiseReaction", "PromiseState" stand out. These provide a high-level understanding of the operations being performed.

4. **Group Related Code:** I'd start grouping related sections of code together. For example:
    * Functions related to promise fulfillment (`FulfillPromise`, `TriggerPromiseReactions` with `kPromiseReactionFulfill`).
    * Functions related to promise rejection (`RejectPromise`, `TriggerPromiseReactions` with `kPromiseReactionReject`).
    * Functions related to creating promises (`NewPromiseCapability`, `InnerNewPromiseCapability`, `CreatePromiseResolvingFunctions`).
    * Functions related to the `then` method (`PerformPromiseThen`, `PerformPromiseThenImpl`).
    * Functions related to the executor function in `new Promise()` (`PromiseGetCapabilitiesExecutor`).
    * Functions related to the internal resolve and reject functions used when a promise is created (`PromiseCapabilityDefaultResolve`, `PromiseCapabilityDefaultReject`).
    * Supporting macros and constants (like `MorphAndEnqueuePromiseReaction`, the various `Constant` macros, and the `ExtractHandlerContext` macros).

5. **Trace the Execution Flow (Mentally or with Notes):** For some key operations, I'd try to trace the flow of execution. For example, what happens when a promise is fulfilled?
    * `FulfillPromise` is called.
    * It gets the reactions.
    * It sets the promise state to fulfilled and stores the value.
    * It calls `TriggerPromiseReactions`.
    * `TriggerPromiseReactions` iterates through the reactions and calls `MorphAndEnqueuePromiseReaction`.
    * `MorphAndEnqueuePromiseReaction` creates a microtask to execute the appropriate fulfillment handler.

6. **Connect to JavaScript Semantics:**  At this point, I'd start connecting the internal operations to their JavaScript equivalents.
    * `FulfillPromise` corresponds to the internal steps when a promise's resolve function is called with a non-Promise value.
    * `RejectPromise` corresponds to the internal steps when a promise's reject function is called.
    * `NewPromiseCapability` is related to `new Promise()`.
    * `PerformPromiseThen` is the internal implementation of the `.then()` method.
    * `PromiseReject` (the builtin) relates to `Promise.reject()`.
    * `PromiseResolve` (the builtin) relates to `Promise.resolve()`.

7. **Provide JavaScript Examples:**  For each key function or concept, I'd create simple JavaScript examples to illustrate how the internal logic is manifested in user code. This helps clarify the connection between the Torque code and user-facing behavior.

8. **Infer Logical Deductions (Input/Output):** Based on the code, I'd think about specific scenarios and predict the input and output of the functions. For example, what happens if a promise is already resolved when its resolve function is called again? The `PromiseCapabilityDefaultResolve` function explicitly handles this.

9. **Identify Potential Programming Errors:** By understanding the internal mechanisms, I can identify common errors that developers might make and how these internal operations are designed to handle or prevent them. Examples include:
    * Calling resolve/reject multiple times.
    * Not handling rejections.
    * Returning non-thenable values from `then` handlers.

10. **Explain the Purpose of Supporting Code:**  Don't just focus on the main functions. Explain the roles of the helper macros and constants. For example, why is `ExtractHandlerContext` needed?  What's the significance of the `PromiseReaction` and `PromiseReactionJobTask` structures?

11. **Structure the Answer Clearly:**  Organize the information logically using headings and bullet points. Start with a high-level summary and then delve into more specific details. Use clear and concise language.

12. **Review and Refine:**  After drafting the initial response, review it for accuracy, clarity, and completeness. Ensure that the JavaScript examples are correct and that the explanations are easy to understand. Check if all parts of the request have been addressed. For example, did I explain the purpose of the `PromiseHook` checks?

Self-Correction Example during the Process:

* **Initial thought:** `TriggerPromiseReactions` just calls the handlers directly.
* **Correction:**  Looking closer at `MorphAndEnqueuePromiseReaction`, it's clear that microtasks are involved. This is crucial for understanding the asynchronous nature of Promises. I need to emphasize the microtask queue.

By following these steps, systematically analyzing the code, and connecting it to JavaScript concepts, I can generate a comprehensive and informative summary like the example provided in the initial prompt.
This Torque file (`v8/src/builtins/promise-abstract-operations.tq`) in the V8 JavaScript engine implements the **abstract operations for Promises** as defined in the ECMAScript specification (ECMA-262). These are the foundational, lower-level operations that underpin the higher-level Promise API available in JavaScript.

Here's a breakdown of its functionality:

**Core Promise State Management:**

* **FulfillPromise(promise, value):**  Handles the transition of a pending promise to the "fulfilled" state with a given `value`. It triggers the execution of any attached fulfillment handlers.
* **RejectPromise(promise, reason, debugEvent):** Handles the transition of a pending promise to the "rejected" state with a given `reason`. It triggers the execution of any attached rejection handlers. It also deals with scenarios where a promise is rejected without a handler.
* **TriggerPromiseReactions(reactions, argument, reactionType):**  A central function responsible for taking a list of pending promise reactions (either fulfillment or rejection) and scheduling them for execution as microtasks. It ensures handlers are executed in the correct order.
* **Promise States:** Implicitly manages the internal state of a promise (pending, fulfilled, rejected) through modifications to the `promise.reactions_or_result` property and the promise's status.

**Promise Reaction Handling:**

* **MorphAndEnqueuePromiseReaction(promiseReaction, argument, reactionType):**  Transforms a `PromiseReaction` object into a `PromiseReactionJobTask` and enqueues it onto the microtask queue. This is the mechanism by which `then`, `catch`, and `finally` handlers are scheduled to run asynchronously.
* **PromiseReaction:**  A data structure (defined elsewhere but used here) that represents a pending handler attached to a promise (via `then`, `catch`). It stores the fulfill and reject handlers, and a reference to the promise or promise capability associated with this reaction.

**Promise Creation and Resolution:**

* **NewPromiseCapability(maybeConstructor, debugEvent):**  Creates a new Promise capability, which is an object containing the promise itself, and its associated resolve and reject functions. This is used internally when creating new Promises.
* **InnerNewPromiseCapability(constructor, debugEvent):**  The internal implementation of `NewPromiseCapability`. It handles cases where the constructor is the native `Promise` constructor or a custom Promise subclass.
* **CreatePromiseResolvingFunctions(promise, debugEvent, nativeContext):** Creates the internal resolve and reject functions that are associated with a newly created Promise. These functions are what the executor function in `new Promise()` receives.
* **PromiseCapabilityDefaultResolve(context, receiver)(resolution):** The default implementation of the promise resolve function. It ensures a promise can only be resolved once and then calls `ResolvePromise`.
* **PromiseCapabilityDefaultReject(context, receiver)(reason):** The default implementation of the promise reject function. It ensures a promise can only be rejected once and then calls `RejectPromise`.
* **ResolvePromise(context, promise, resolution):**  Handles the core logic of resolving a promise. It checks if the resolution value is a thenable (another Promise-like object) and handles promise assimilation if necessary.

**`then` Method Implementation:**

* **PerformPromiseThen(promise, onFulfilled, onRejected, resultPromise):** Implements the core logic of the `then` method. It creates a new promise to represent the eventual result of the `then` call and attaches appropriate fulfillment and rejection handlers to the original promise.
* **PerformPromiseThenImpl(promise, onFulfilled, onRejected, resultPromiseOrCapability):** The internal implementation of `PerformPromiseThen`. It handles both cases: when the promise is still pending and when it's already settled.

**Other Operations:**

* **PromiseReject(context, receiver)(reason):**  Implements the `Promise.reject()` static method, which creates a new rejected promise.
* **PromiseGetCapabilitiesExecutor(context, receiver)(resolve, reject):**  The function that is called with the internal resolve and reject functions when a new Promise is created using a custom constructor.
* **GetPromiseResolve(nativeContext, constructor):** Retrieves the `resolve` method from a given promise constructor.
* **CallResolve(constructor, resolve, value):**  A utility macro for calling the resolve function of a promise.

**Relationship to JavaScript:**

This Torque code directly implements the core behavior of JavaScript Promises. Every time you use `new Promise()`, `.then()`, `.catch()`, `.finally()`, `Promise.resolve()`, or `Promise.reject()` in JavaScript, the underlying logic is implemented (at least in part) by code like this.

**JavaScript Examples:**

* **`FulfillPromise`:**
   ```javascript
   let promise = new Promise((resolve, reject) => {
     // ... some asynchronous operation ...
     resolve("Operation successful!"); // Internally triggers FulfillPromise
   });
   ```

* **`RejectPromise`:**
   ```javascript
   let promise = new Promise((resolve, reject) => {
     // ... some asynchronous operation that fails ...
     reject("Operation failed!"); // Internally triggers RejectPromise
   });
   ```

* **`PerformPromiseThen`:**
   ```javascript
   promise.then(
     (result) => { console.log("Fulfilled:", result); }, // Fulfillment handler
     (error) => { console.error("Rejected:", error); }  // Rejection handler
   ); // Internally triggers PerformPromiseThen
   ```

* **`Promise.resolve`:**
   ```javascript
   let resolvedPromise = Promise.resolve(42); // Internally uses logic similar to ResolvePromise
   ```

* **`Promise.reject`:**
   ```javascript
   let rejectedPromise = Promise.reject("Something went wrong"); // Directly uses the PromiseReject builtin
   ```

**Code Logic Inference (Hypothetical Input/Output):**

**Scenario:** A pending promise `p` has a `then` handler attached: `p.then(onFulfilled, onRejected)`. The promise `p` is later fulfilled with the value `5`.

**Hypothetical Input:**
* `FulfillPromise(p, 5)` is called.
* `p.reactions_or_result` contains a `PromiseReaction` object referencing the `onFulfilled` and `onRejected` functions.

**Hypothetical Output:**
1. `FulfillPromise` sets `p.reactions_or_result` to `5` and the promise state to "fulfilled".
2. `TriggerPromiseReactions` is called with the previously stored `PromiseReaction` and the value `5`, with `reactionType` as `kPromiseReactionFulfill`.
3. `TriggerPromiseReactions` iterates through the reactions (in this case, one).
4. `MorphAndEnqueuePromiseReaction` is called with the `PromiseReaction`, `5`, and `kPromiseReactionFulfill`.
5. A `PromiseFulfillReactionJobTask` is created, containing `onFulfilled` and `5`.
6. This `PromiseFulfillReactionJobTask` is enqueued onto the microtask queue.
7. Eventually, the microtask will be executed, calling `onFulfilled` with the argument `5`.

**Common Programming Errors:**

* **Calling `resolve` or `reject` multiple times:** The `PromiseCapabilityDefaultResolve` and `PromiseCapabilityDefaultReject` functions prevent this by checking the `alreadyResolved` flag. Calling them multiple times after the first resolution/rejection will have no effect (or might trigger a runtime error related to already resolved promises).

   ```javascript
   let promise = new Promise((resolve, reject) => {
     resolve("First resolution");
     resolve("Second resolution"); // This will likely be ignored or cause an error internally
   });
   ```

* **Not handling rejections:** If a promise is rejected and there is no rejection handler attached (via `.catch()` or a second argument to `.then()`), the V8 engine will eventually trigger an "unhandled promise rejection" warning or error. The `RejectPromise` function includes logic to check for handlers and potentially use the `HostPromiseRejectionTracker`.

   ```javascript
   let promise = new Promise((resolve, reject) => {
     reject("Something went wrong");
   });
   // No .catch() or second argument to .then()
   ```

* **Returning a non-thenable value from a `then` handler:**  If a fulfillment handler returns a regular value (not another promise), the promise returned by `then` will be immediately fulfilled with that value. If it returns nothing (or `undefined`), the next promise will be fulfilled with `undefined`. Understanding this behavior is important for chaining promises correctly.

   ```javascript
   promise.then((result) => {
     return result * 2; // Returns a regular value
   }).then((doubledResult) => {
     console.log(doubledResult); // doubledResult will be the result * 2
   });
   ```

This Torque file is a critical piece of V8's implementation of Promises, ensuring they behave according to the JavaScript specification and providing the foundation for asynchronous programming in JavaScript.

Prompt: 
```
这是目录为v8/src/builtins/promise-abstract-operations.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include 'src/builtins/builtins-promise.h'
#include 'src/builtins/builtins-promise-gen.h'

namespace runtime {
extern transitioning runtime RejectPromise(
    implicit context: Context)(JSPromise, JSAny, Boolean): JSAny;

extern transitioning runtime PromiseRevokeReject(
    implicit context: Context)(JSPromise): JSAny;

extern transitioning runtime PromiseRejectAfterResolved(
    implicit context: Context)(JSPromise, JSAny): JSAny;

extern transitioning runtime PromiseResolveAfterResolved(
    implicit context: Context)(JSPromise, JSAny): JSAny;

extern transitioning runtime PromiseRejectEventFromStack(
    implicit context: Context)(JSPromise, JSAny): JSAny;
}

// https://tc39.es/ecma262/#sec-promise-abstract-operations
namespace promise {

extern macro PromiseForwardingHandlerSymbolConstant(): Symbol;
const kPromiseForwardingHandlerSymbol: Symbol =
    PromiseForwardingHandlerSymbolConstant();
extern macro PromiseHandledBySymbolConstant(): Symbol;
const kPromiseHandledBySymbol: Symbol = PromiseHandledBySymbolConstant();
extern macro ResolveStringConstant(): String;
const kResolveString: String = ResolveStringConstant();
extern macro IsPromiseResolveProtectorCellInvalid(): bool;

extern macro AllocateRootFunctionWithContext(
    constexpr intptr, FunctionContext, NativeContext): JSFunction;

extern macro PromiseReactionMapConstant(): Map;
extern macro PromiseFulfillReactionJobTaskMapConstant(): Map;
extern macro PromiseRejectReactionJobTaskMapConstant(): Map;
extern transitioning builtin ResolvePromise(Context, JSPromise, JSAny): JSAny;

extern transitioning builtin EnqueueMicrotask(Context, Microtask): Undefined;

macro ExtractHandlerContextInternal(
    implicit context: Context)(
    handler: Callable|Undefined): Context labels NotFound {
  let iter: JSAny = handler;
  while (true) {
    typeswitch (iter) {
      case (b: JSBoundFunction): {
        iter = b.bound_target_function;
      }
      case (p: JSProxy): {
        iter = p.target;
      }
      case (f: JSFunction): {
        return f.context;
      }
      case (JSAny): {
        break;
      }
    }
  }
  goto NotFound;
}

macro ExtractHandlerContext(
    implicit context: Context)(handler: Callable|Undefined): Context {
  try {
    return ExtractHandlerContextInternal(handler) otherwise NotFound;
  } label NotFound deferred {
    return context;
  }
}

macro ExtractHandlerContext(
    implicit context: Context)(primary: Callable|Undefined,
    secondary: Callable|Undefined): Context {
  try {
    return ExtractHandlerContextInternal(primary) otherwise NotFound;
  } label NotFound deferred {
    return ExtractHandlerContextInternal(secondary) otherwise Default;
  } label Default deferred {
    return context;
  }
}

transitioning macro MorphAndEnqueuePromiseReaction(
    implicit context: Context)(promiseReaction: PromiseReaction,
    argument: JSAny, reactionType: constexpr PromiseReactionType): void {
  let primaryHandler: Callable|Undefined;
  let secondaryHandler: Callable|Undefined;
  if constexpr (reactionType == kPromiseReactionFulfill) {
    primaryHandler = promiseReaction.fulfill_handler;
    secondaryHandler = promiseReaction.reject_handler;
  } else {
    static_assert(reactionType == kPromiseReactionReject);
    primaryHandler = promiseReaction.reject_handler;
    secondaryHandler = promiseReaction.fulfill_handler;
  }

  // According to HTML, we use the context of the appropriate handler as the
  // context of the microtask. See step 3 of HTML's EnqueueJob:
  // https://html.spec.whatwg.org/C/#enqueuejob(queuename,-job,-arguments)
  const handlerContext: Context =
      ExtractHandlerContext(primaryHandler, secondaryHandler);

  // Morph {current} from a PromiseReaction into a PromiseReactionJobTask
  // and schedule that on the microtask queue. We try to minimize the number
  // of stores here to avoid write barrier overhead.
  static_assert(
      kPromiseReactionSize ==
      kPromiseReactionJobTaskSizeOfAllPromiseReactionJobTasks);
  if constexpr (reactionType == kPromiseReactionFulfill) {
    *UnsafeConstCast(&promiseReaction.map) =
        PromiseFulfillReactionJobTaskMapConstant();
    const promiseReactionJobTask =
        UnsafeCast<PromiseFulfillReactionJobTask>(promiseReaction);
    promiseReactionJobTask.argument = argument;
    promiseReactionJobTask.context = handlerContext;
    EnqueueMicrotask(handlerContext, promiseReactionJobTask);
    static_assert(
        kPromiseReactionFulfillHandlerOffset ==
        kPromiseReactionJobTaskHandlerOffset);
    static_assert(
        kPromiseReactionPromiseOrCapabilityOffset ==
        kPromiseReactionJobTaskPromiseOrCapabilityOffset);
    @if(V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA)
      static_assert(
          kPromiseReactionContinuationPreservedEmbedderDataOffset ==
          kPromiseReactionJobTaskContinuationPreservedEmbedderDataOffset);
  } else {
    static_assert(reactionType == kPromiseReactionReject);
    *UnsafeConstCast(&promiseReaction.map) =
        PromiseRejectReactionJobTaskMapConstant();
    const promiseReactionJobTask =
        UnsafeCast<PromiseRejectReactionJobTask>(promiseReaction);
    promiseReactionJobTask.argument = argument;
    promiseReactionJobTask.context = handlerContext;
    promiseReactionJobTask.handler = primaryHandler;
    EnqueueMicrotask(handlerContext, promiseReactionJobTask);
    static_assert(
        kPromiseReactionPromiseOrCapabilityOffset ==
        kPromiseReactionJobTaskPromiseOrCapabilityOffset);
    @if(V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA)
      static_assert(
          kPromiseReactionContinuationPreservedEmbedderDataOffset ==
          kPromiseReactionJobTaskContinuationPreservedEmbedderDataOffset);
  }
}

// https://tc39.es/ecma262/#sec-triggerpromisereactions
transitioning macro TriggerPromiseReactions(
    implicit context: Context)(reactions: Zero|PromiseReaction,
    argument: JSAny, reactionType: constexpr PromiseReactionType): void {
  // We need to reverse the {reactions} here, since we record them on the
  // JSPromise in the reverse order.
  let current = reactions;
  let reversed: Zero|PromiseReaction = kZero;

  // As an additional safety net against misuse of the V8 Extras API, we
  // sanity check the {reactions} to make sure that they are actually
  // PromiseReaction instances and not actual JavaScript values (which
  // would indicate that we're rejecting or resolving an already settled
  // promise), see https://crbug.com/931640 for details on this.
  while (true) {
    typeswitch (current) {
      case (Zero): {
        break;
      }
      case (currentReaction: PromiseReaction): {
        current = currentReaction.next;
        currentReaction.next = reversed;
        reversed = currentReaction;
      }
    }
  }
  // Morph the {reactions} into PromiseReactionJobTasks and push them
  // onto the microtask queue.
  current = reversed;
  while (true) {
    typeswitch (current) {
      case (Zero): {
        break;
      }
      case (currentReaction: PromiseReaction): {
        current = currentReaction.next;
        MorphAndEnqueuePromiseReaction(currentReaction, argument, reactionType);
      }
    }
  }
}

// https://tc39.es/ecma262/#sec-fulfillpromise
transitioning builtin FulfillPromise(
    implicit context: Context)(promise: JSPromise, value: JSAny): Undefined {
  // Assert: The value of promise.[[PromiseState]] is "pending".
  dcheck(promise.Status() == PromiseState::kPending);

  RunContextPromiseHookResolve(promise);

  // 2. Let reactions be promise.[[PromiseFulfillReactions]].
  const reactions =
      UnsafeCast<(Zero | PromiseReaction)>(promise.reactions_or_result);

  // 3. Set promise.[[PromiseResult]] to value.
  // 4. Set promise.[[PromiseFulfillReactions]] to undefined.
  // 5. Set promise.[[PromiseRejectReactions]] to undefined.
  promise.reactions_or_result = value;

  // 6. Set promise.[[PromiseState]] to "fulfilled".
  promise.SetStatus(PromiseState::kFulfilled);

  // 7. Return TriggerPromiseReactions(reactions, value).
  TriggerPromiseReactions(reactions, value, kPromiseReactionFulfill);
  return Undefined;
}

extern macro PromiseBuiltinsAssembler::
    IsIsolatePromiseHookEnabledOrDebugIsActiveOrHasAsyncEventDelegate(): bool;

extern macro PromiseBuiltinsAssembler::
    IsIsolatePromiseHookEnabledOrDebugIsActiveOrHasAsyncEventDelegate(uint32):
        bool;

// https://tc39.es/ecma262/#sec-rejectpromise
transitioning builtin RejectPromise(
    implicit context: Context)(promise: JSPromise, reason: JSAny,
    debugEvent: Boolean): JSAny {
  const promiseHookFlags = PromiseHookFlags();

  // If promise hook is enabled or the debugger is active, let
  // the runtime handle this operation, which greatly reduces
  // the complexity here and also avoids a couple of back and
  // forth between JavaScript and C++ land.
  if (IsIsolatePromiseHookEnabledOrDebugIsActiveOrHasAsyncEventDelegate(
          promiseHookFlags) ||
      !promise.HasHandler()) {
    // 7. If promise.[[PromiseIsHandled]] is false, perform
    //    HostPromiseRejectionTracker(promise, "reject").
    // We don't try to handle rejecting {promise} without handler
    // here, but we let the C++ code take care of this completely.
    return runtime::RejectPromise(promise, reason, debugEvent);
  }

  RunContextPromiseHookResolve(promise, promiseHookFlags);

  // 2. Let reactions be promise.[[PromiseRejectReactions]].
  const reactions =
      UnsafeCast<(Zero | PromiseReaction)>(promise.reactions_or_result);

  // 3. Set promise.[[PromiseResult]] to reason.
  // 4. Set promise.[[PromiseFulfillReactions]] to undefined.
  // 5. Set promise.[[PromiseRejectReactions]] to undefined.
  promise.reactions_or_result = reason;

  // 6. Set promise.[[PromiseState]] to "rejected".
  promise.SetStatus(PromiseState::kRejected);

  // 8. Return TriggerPromiseReactions(reactions, reason).
  TriggerPromiseReactions(reactions, reason, kPromiseReactionReject);
  return Undefined;
}

const kPromiseCapabilitySize:
    constexpr int31 generates 'PromiseCapability::kSize';

type PromiseResolvingFunctionContext extends FunctionContext;
extern enum PromiseResolvingFunctionContextSlot extends intptr
    constexpr 'PromiseBuiltins::PromiseResolvingFunctionContextSlot' {
  kPromiseSlot: Slot<PromiseResolvingFunctionContext, JSPromise>,
  kAlreadyResolvedSlot: Slot<PromiseResolvingFunctionContext, Boolean>,
  kDebugEventSlot: Slot<PromiseResolvingFunctionContext, Boolean>,
  kPromiseContextLength
}

type PromiseCapabilitiesExecutorContext extends FunctionContext;
extern enum FunctionContextSlot extends intptr
    constexpr 'PromiseBuiltins::FunctionContextSlot' {
  kCapabilitySlot: Slot<PromiseCapabilitiesExecutorContext, PromiseCapability>,
  kCapabilitiesContextLength
}

@export
macro CreatePromiseCapabilitiesExecutorContext(
    nativeContext: NativeContext,
    capability: PromiseCapability): PromiseCapabilitiesExecutorContext {
  const executorContext = %RawDownCast<PromiseCapabilitiesExecutorContext>(
      AllocateSyntheticFunctionContext(
          nativeContext, FunctionContextSlot::kCapabilitiesContextLength));

  InitContextSlot(
      executorContext, FunctionContextSlot::kCapabilitySlot, capability);
  return executorContext;
}

@export
macro CreatePromiseCapability(
    promise: JSReceiver|Undefined, resolve: JSFunction|Undefined,
    reject: JSFunction|Undefined): PromiseCapability {
  return new PromiseCapability{
    map: kPromiseCapabilityMap,
    promise: promise,
    resolve: resolve,
    reject: reject
  };
}

@export
struct PromiseResolvingFunctions {
  resolve: JSFunction;
  reject: JSFunction;
  context: Context;
}

const kPromiseCapabilityDefaultResolveSharedFun: constexpr intptr
    generates 'RootIndex::kPromiseCapabilityDefaultResolveSharedFun';
const kPromiseCapabilityDefaultRejectSharedFun: constexpr intptr
    generates 'RootIndex::kPromiseCapabilityDefaultRejectSharedFun';

@export
macro CreatePromiseResolvingFunctions(
    implicit context: Context)(promise: JSPromise, debugEvent: Boolean,
    nativeContext: NativeContext): PromiseResolvingFunctions {
  const promiseContext = CreatePromiseResolvingFunctionsContext(
      promise, debugEvent, nativeContext);

  const resolve: JSFunction = AllocateRootFunctionWithContext(
      kPromiseCapabilityDefaultResolveSharedFun, promiseContext, nativeContext);
  const reject: JSFunction = AllocateRootFunctionWithContext(
      kPromiseCapabilityDefaultRejectSharedFun, promiseContext, nativeContext);
  return PromiseResolvingFunctions{
    resolve: resolve,
    reject: reject,
    context: promiseContext
  };
}

const kPromiseGetCapabilitiesExecutorSharedFun: constexpr intptr
    generates 'RootIndex::kPromiseGetCapabilitiesExecutorSharedFun';

transitioning macro InnerNewPromiseCapability(
    implicit context: Context)(constructor: HeapObject,
    debugEvent: Boolean): PromiseCapability {
  const nativeContext = LoadNativeContext(context);
  if (constructor ==
      *NativeContextSlot(nativeContext, ContextSlot::PROMISE_FUNCTION_INDEX)) {
    const promise = NewJSPromise();

    const pair =
        CreatePromiseResolvingFunctions(promise, debugEvent, nativeContext);

    return CreatePromiseCapability(promise, pair.resolve, pair.reject);
  } else {
    // We have to create the capability before the associated promise
    // because the builtin PromiseConstructor uses the executor.
    const capability = CreatePromiseCapability(Undefined, Undefined, Undefined);
    const executorContext =
        CreatePromiseCapabilitiesExecutorContext(nativeContext, capability);
    const executor = AllocateRootFunctionWithContext(
        kPromiseGetCapabilitiesExecutorSharedFun, executorContext,
        nativeContext);

    const promiseConstructor = UnsafeCast<Constructor>(constructor);
    const promise = Construct(promiseConstructor, executor);
    capability.promise = promise;

    if (!Is<Callable>(capability.resolve) || !Is<Callable>(capability.reject)) {
      ThrowTypeError(MessageTemplate::kPromiseNonCallable);
    }
    return capability;
  }
}

// https://tc39.es/ecma262/#sec-newpromisecapability
transitioning builtin NewPromiseCapability(
    implicit context: Context)(maybeConstructor: Object,
    debugEvent: Boolean): PromiseCapability {
  typeswitch (maybeConstructor) {
    case (Smi): {
      ThrowTypeError(MessageTemplate::kNotConstructor, maybeConstructor);
    }
    case (constructor: HeapObject): {
      if (!IsConstructor(constructor)) {
        ThrowTypeError(MessageTemplate::kNotConstructor, maybeConstructor);
      }
      return InnerNewPromiseCapability(constructor, debugEvent);
    }
  }
}

// https://tc39.es/ecma262/#sec-promise-reject-functions
transitioning javascript builtin PromiseCapabilityDefaultReject(
    js-implicit context: Context, receiver: JSAny)(reason: JSAny): JSAny {
  const context = %RawDownCast<PromiseResolvingFunctionContext>(context);
  // 2. Let promise be F.[[Promise]].
  const promise =
      *ContextSlot(context, PromiseResolvingFunctionContextSlot::kPromiseSlot);

  // 3. Let alreadyResolved be F.[[AlreadyResolved]].
  const alreadyResolved = *ContextSlot(
      context, PromiseResolvingFunctionContextSlot::kAlreadyResolvedSlot);

  // 4. If alreadyResolved.[[Value]] is true, return undefined.
  if (alreadyResolved == True) {
    return runtime::PromiseRejectAfterResolved(promise, reason);
  }

  // 5. Set alreadyResolved.[[Value]] to true.
  *ContextSlot(
      context, PromiseResolvingFunctionContextSlot::kAlreadyResolvedSlot) =
      True;

  // 6. Return RejectPromise(promise, reason).
  const debugEvent = *ContextSlot(
      context, PromiseResolvingFunctionContextSlot::kDebugEventSlot);
  return RejectPromise(promise, reason, debugEvent);
}

// https://tc39.es/ecma262/#sec-promise-resolve-functions
transitioning javascript builtin PromiseCapabilityDefaultResolve(
    js-implicit context: Context, receiver: JSAny)(resolution: JSAny): JSAny {
  const context = %RawDownCast<PromiseResolvingFunctionContext>(context);
  // 2. Let promise be F.[[Promise]].
  const promise: JSPromise =
      *ContextSlot(context, PromiseResolvingFunctionContextSlot::kPromiseSlot);

  // 3. Let alreadyResolved be F.[[AlreadyResolved]].
  const alreadyResolved: Boolean = *ContextSlot(
      context, PromiseResolvingFunctionContextSlot::kAlreadyResolvedSlot);

  // 4. If alreadyResolved.[[Value]] is true, return undefined.
  if (alreadyResolved == True) {
    return runtime::PromiseResolveAfterResolved(promise, resolution);
  }

  // 5. Set alreadyResolved.[[Value]] to true.
  *ContextSlot(
      context, PromiseResolvingFunctionContextSlot::kAlreadyResolvedSlot) =
      True;

  // The rest of the logic (and the catch prediction) is
  // encapsulated in the dedicated ResolvePromise builtin.
  return ResolvePromise(context, promise, resolution);
}

@export
transitioning macro PerformPromiseThenImpl(
    implicit context: Context)(promise: JSPromise,
    onFulfilled: Callable|Undefined, onRejected: Callable|Undefined,
    resultPromiseOrCapability: JSPromise|PromiseCapability|Undefined): void {
  if (promise.Status() == PromiseState::kPending) {
    // The {promise} is still in "Pending" state, so we just record a new
    // PromiseReaction holding both the onFulfilled and onRejected callbacks.
    // Once the {promise} is resolved we decide on the concrete handler to
    // push onto the microtask queue.
    const promiseReactions =
        UnsafeCast<(Zero | PromiseReaction)>(promise.reactions_or_result);

    const reaction = NewPromiseReaction(
        promiseReactions, resultPromiseOrCapability, onFulfilled, onRejected);
    promise.reactions_or_result = reaction;
  } else {
    const reactionsOrResult = promise.reactions_or_result;
    let microtask: PromiseReactionJobTask;
    let handlerContext: Context;
    if (promise.Status() == PromiseState::kFulfilled) {
      handlerContext = ExtractHandlerContext(onFulfilled, onRejected);
      microtask = NewPromiseFulfillReactionJobTask(
          handlerContext, reactionsOrResult, onFulfilled,
          resultPromiseOrCapability);
    } else
      deferred {
        dcheck(promise.Status() == PromiseState::kRejected);
        handlerContext = ExtractHandlerContext(onRejected, onFulfilled);
        microtask = NewPromiseRejectReactionJobTask(
            handlerContext, reactionsOrResult, onRejected,
            resultPromiseOrCapability);
        if (!promise.HasHandler()) {
          runtime::PromiseRevokeReject(promise);
        }
      }
    EnqueueMicrotask(handlerContext, microtask);
  }
  promise.SetHasHandler();
}

transitioning javascript builtin PerformPromiseThenFunction(
    js-implicit context: NativeContext, receiver: JSAny)(onFulfilled: JSAny,
    onRejected: JSAny): JSAny {
  const jsPromise = Cast<JSPromise>(receiver) otherwise unreachable;
  const callableOnFulfilled = Cast<Callable>(onFulfilled) otherwise unreachable;
  const callableOnRejected = Cast<Callable>(onRejected) otherwise unreachable;

  PerformPromiseThenImpl(
      jsPromise, callableOnFulfilled, callableOnRejected, Undefined);
  return Undefined;
}

// https://tc39.es/ecma262/#sec-performpromisethen
transitioning builtin PerformPromiseThen(
    implicit context: Context)(promise: JSPromise,
    onFulfilled: Callable|Undefined, onRejected: Callable|Undefined,
    resultPromise: JSPromise|Undefined): JSAny {
  PerformPromiseThenImpl(promise, onFulfilled, onRejected, resultPromise);
  return resultPromise;
}

// https://tc39.es/ecma262/#sec-promise-reject-functions
transitioning javascript builtin PromiseReject(
    js-implicit context: NativeContext, receiver: JSAny)(
    reason: JSAny): JSAny {
  // 1. Let C be the this value.
  // 2. If Type(C) is not Object, throw a TypeError exception.
  const receiver = Cast<JSReceiver>(receiver) otherwise
  ThrowTypeError(MessageTemplate::kCalledOnNonObject, 'PromiseReject');

  const promiseFun = *NativeContextSlot(ContextSlot::PROMISE_FUNCTION_INDEX);
  if (promiseFun == receiver) {
    const promise = NewJSPromise(PromiseState::kRejected, reason);
    runtime::PromiseRejectEventFromStack(promise, reason);
    return promise;
  } else {
    // 3. Let promiseCapability be ? NewPromiseCapability(C).
    const capability = NewPromiseCapability(receiver, True);

    // 4. Perform ? Call(promiseCapability.[[Reject]], undefined, « r »).
    const reject = UnsafeCast<Callable>(capability.reject);
    Call(context, reject, Undefined, reason);

    // 5. Return promiseCapability.[[Promise]].
    return capability.promise;
  }
}

const kPromiseExecutorAlreadyInvoked: constexpr MessageTemplate
    generates 'MessageTemplate::kPromiseExecutorAlreadyInvoked';

// https://tc39.es/ecma262/#sec-getcapabilitiesexecutor-functions
transitioning javascript builtin PromiseGetCapabilitiesExecutor(
    js-implicit context: Context, receiver: JSAny)(resolve: JSAny,
    reject: JSAny): JSAny {
  const context = %RawDownCast<PromiseCapabilitiesExecutorContext>(context);
  const capability: PromiseCapability =
      *ContextSlot(context, FunctionContextSlot::kCapabilitySlot);
  if (capability.resolve != Undefined || capability.reject != Undefined)
    deferred {
      ThrowTypeError(kPromiseExecutorAlreadyInvoked);
    }

  capability.resolve = resolve;
  capability.reject = reject;
  return Undefined;
}

macro IsPromiseResolveLookupChainIntact(
    implicit context: Context)(nativeContext: NativeContext,
    constructor: JSReceiver): bool {
  if (IsForceSlowPath()) return false;
  const promiseFun =
      *NativeContextSlot(nativeContext, ContextSlot::PROMISE_FUNCTION_INDEX);
  return promiseFun == constructor && !IsPromiseResolveProtectorCellInvalid();
}

// https://tc39.es/ecma262/#sec-getpromiseresolve
transitioning macro GetPromiseResolve(
    implicit context: Context)(nativeContext: NativeContext,
    constructor: Constructor): JSAny {
  // 1. Assert: IsConstructor(constructor) is true.

  // We can skip the "resolve" lookup on {constructor} if it's the
  // Promise constructor and the Promise.resolve protector is intact,
  // as that guards the lookup path for the "resolve" property on the
  // Promise constructor. In this case, promiseResolveFunction is undefined,
  // and when CallResolve is called with it later, it will call Promise.resolve.
  let promiseResolveFunction: JSAny = Undefined;

  if (!IsPromiseResolveLookupChainIntact(nativeContext, constructor)) {
    let promiseResolve: JSAny;

    // 2. Let promiseResolve be ? Get(constructor, "resolve").
    promiseResolve = GetProperty(constructor, kResolveString);

    // 3. If IsCallable(promiseResolve) is false, throw a TypeError exception.
    promiseResolveFunction =
        Cast<Callable>(promiseResolve) otherwise ThrowTypeError(
            MessageTemplate::kCalledNonCallable, 'resolve');
  }
  // 4. return promiseResolve.
  return promiseResolveFunction;
}

transitioning macro CallResolve(
    implicit context: Context)(constructor: Constructor, resolve: JSAny,
    value: JSAny): JSAny {
  // Undefined can never be a valid value for the resolve function,
  // instead it is used as a special marker for the fast path.
  if (resolve == Undefined) {
    return PromiseResolve(constructor, value);
  } else
    deferred {
      return Call(context, UnsafeCast<Callable>(resolve), constructor, value);
    }
}

transitioning javascript builtin PromiseConstructorLazyDeoptContinuation(
    js-implicit context: NativeContext, receiver: JSAny)(promise: JSAny,
    reject: JSAny, exception: JSAny|TheHole, _result: JSAny): JSAny {
  // Clear pending message since the exception is not going to be rethrown.
  torque_internal::SetPendingMessage(TheHole);
  typeswitch (exception) {
    case (TheHole): {
    }
    case (e: JSAny): {
      Call(context, reject, Undefined, e);
    }
  }
  return promise;
}

extern macro PromiseCapabilityDefaultRejectSharedFunConstant():
    SharedFunctionInfo;
extern macro PromiseCapabilityDefaultResolveSharedFunConstant():
    SharedFunctionInfo;
extern macro PromiseGetCapabilitiesExecutorSharedFunConstant():
    SharedFunctionInfo;
}

"""

```