Response: Let's break down the thought process for analyzing this Torque code for `Promise.any`.

1. **Understand the Goal:** The first step is to recognize that this code implements the `Promise.any` functionality in V8. This means it needs to handle an iterable of promises and resolve with the first fulfilled promise, or reject with an `AggregateError` if all promises reject.

2. **Identify Key Components:** Look for the major building blocks and data structures involved. Keywords like `Context`, `PromiseCapability`, `FixedArray`, and function/macro names like `CreatePromiseAnyRejectElementContext`, `PromiseAnyRejectElementClosure`, and `PerformPromiseAny` are strong hints.

3. **Follow the Execution Flow (Top-Down):** Start with the entry point, the `PromiseAny` builtin.

    * **`PromiseAny` Builtin:**
        *  It takes an `iterable` as input.
        *  It creates a new `PromiseCapability` for the resulting promise.
        *  It gets the `promiseResolve` function (used internally for resolving individual promises).
        *  It gets an iterator from the `iterable`.
        *  It calls `PerformPromiseAny`, which seems to be the core logic.
        *  It handles potential errors during iteration and rejects the resulting promise if needed.

4. **Dive into the Core Logic (`PerformPromiseAny`):** This is where the main work happens.

    * **Initialization:**  Notice the creation of `rejectElementContext`. This context seems crucial for the rejection handling. It stores the `PromiseCapability`, the remaining promise count, and the array of errors.
    * **Iteration:** The code uses a `while (true)` loop to iterate through the input iterable.
    * **Handling Each Promise:** Inside the loop:
        *  It gets the next value from the iterator.
        *  It wraps the value in a promise using `CallResolve`.
        *  It creates a `rejectElement` function using `CreatePromiseAnyRejectElementFunction`. This is a closure that will be called if an individual promise rejects.
        *  It attaches the `resolve` handler of the main promise and the `rejectElement` function to the individual promise using `.then()`.
        *  It increments a counter (`index`).
    * **The `rejectElement` Closure:**  This is a critical part. When an individual promise rejects, this closure is executed.
        *  It checks if it has already been called (to avoid double-rejection).
        *  It stores the rejection reason in the `errors` array within the `rejectElementContext`.
        *  It decrements the `remainingElementsCount`.
        *  If `remainingElementsCount` reaches zero, it means all promises have rejected. It creates an `AggregateError` with the collected errors and rejects the main promise.
    * **Handling "Done" State:**  When the iterator finishes, the `Done` label is reached.
        *  It decrements the `remainingElementsCount`.
        *  If `remainingElementsCount` is zero (meaning the iterable was empty), it rejects the main promise with an `AggregateError`.
        *  Otherwise, it returns the main promise (which will eventually be resolved by the first fulfilling promise).

5. **Examine the Support Structures:** Look at the helper functions and data structures:

    * **`PromiseAnyRejectElementContext`:**  Stores data shared by all the reject handlers for a single `Promise.any` call. This is an optimization to avoid creating separate data for each rejection.
    * **`CreatePromiseAnyRejectElementContext`:**  Allocates and initializes this context.
    * **`CreatePromiseAnyRejectElementFunction`:** Creates the actual reject handler closure, linking it to the shared context and assigning it an index. The index is cleverly stored in the function's identity hash.
    * **`PromiseAnyRejectElementClosure`:** The JavaScript-callable function that is executed when an individual promise rejects.
    * **`ConstructAggregateError`:**  Creates the `AggregateError` object when all promises reject.

6. **Connect to JavaScript Concepts:** Relate the Torque code to the JavaScript behavior of `Promise.any`.

    * **Resolution:**  The `resultCapability.resolve` is used when one of the input promises fulfills.
    * **Rejection:** The `rejectElement` closures are called when input promises reject. The `AggregateError` is created when all reject.
    * **Empty Iterable:** The code handles the case of an empty iterable by rejecting immediately with an `AggregateError`.

7. **Infer Input/Output and Edge Cases:**  Think about different scenarios and what the expected behavior is based on the code.

    * **All Promises Fulfill:** The main promise resolves with the value of the first fulfilled promise.
    * **All Promises Reject:** The main promise rejects with an `AggregateError` containing all the rejection reasons.
    * **Some Promises Fulfill, Some Reject:** The main promise resolves with the first fulfillment. Rejections are ignored after the first fulfillment.
    * **Empty Iterable:** The main promise rejects with an `AggregateError`.
    * **Non-Promise Values in Iterable:** These are treated as already resolved promises.

8. **Identify Potential Errors:**  Look for patterns that could lead to common programming mistakes.

    * **Not Handling Rejections:**  If the `AggregateError` isn't handled with a `.catch()` on the `Promise.any` result, the unhandled rejection could cause issues.
    * **Assuming Order of Resolution/Rejection:**  The code doesn't guarantee any specific order for the rejection handlers to be called if multiple promises reject "simultaneously."  The `AggregateError` will contain all the rejections, but the order might not be predictable.

9. **Refine and Summarize:** Organize the findings into a clear and concise explanation, using examples to illustrate the functionality and potential issues. Use the provided headings as a guide.

This detailed breakdown, focusing on the control flow, data structures, and their relation to JavaScript semantics, allows for a thorough understanding of the Torque code's function. The key is to move from the high-level purpose down to the specific implementation details.
This V8 Torque source code implements the functionality of `Promise.any` in JavaScript. Let's break down its components and their purpose:

**1. Functionality of `Promise.any`:**

The core functionality of `Promise.any` is to take an iterable of promises (or thenables) and return a new promise that:

* **Fulfills** as soon as any of the input promises fulfill, with the fulfillment value of that first fulfilled promise.
* **Rejects** if all of the input promises reject. The rejection reason in this case is an `AggregateError` containing all the rejection reasons.
* If the iterable is empty, it rejects immediately with an `AggregateError`.

**2. Relationship to JavaScript:**

The code directly implements the ECMAScript specification for `Promise.any`. Here's a JavaScript example:

```javascript
const promise1 = Promise.reject(new Error('Promise 1 rejected'));
const promise2 = new Promise((resolve) => setTimeout(() => resolve('Promise 2 resolved'), 100));
const promise3 = Promise.reject(new Error('Promise 3 rejected'));

Promise.any([promise1, promise2, promise3])
  .then((value) => {
    console.log('Resolved with:', value); // Expected: "Resolved with: Promise 2 resolved"
  })
  .catch((error) => {
    console.log('Rejected with:', error);
  });

const promise4 = Promise.reject(new Error('Promise 4 rejected'));
const promise5 = Promise.reject(new Error('Promise 5 rejected'));

Promise.any([promise4, promise5])
  .then(() => {})
  .catch((error) => {
    console.log('All rejected:', error instanceof AggregateError); // Expected: "All rejected: true"
    console.log('Rejection reasons:', error.errors); // Expected: Array of the two errors
  });

Promise.any([])
  .catch((error) => {
    console.log('Empty iterable rejected:', error instanceof AggregateError); // Expected: "Empty iterable rejected: true"
  });
```

**3. Code Logic and Reasoning:**

The Torque code implements `Promise.any` through the following main components:

* **`PromiseAnyRejectElementContext`:** This is a special context used by the rejection handlers for each individual promise in the iterable. It stores:
    * `kPromiseAnyRejectElementRemainingSlot`:  The number of promises that haven't yet fulfilled or rejected. It starts with 1 more than the actual number of promises (explained later).
    * `kPromiseAnyRejectElementCapabilitySlot`: The `PromiseCapability` of the `Promise.any` promise being created. This holds the resolve and reject functions for that promise.
    * `kPromiseAnyRejectElementErrorsSlot`: A `FixedArray` to store the rejection reasons of the promises that have rejected.
* **`CreatePromiseAnyRejectElementContext`:**  Creates and initializes the `PromiseAnyRejectElementContext`.
* **`CreatePromiseAnyRejectElementFunction`:** Creates a small JavaScript function (a closure) that will be attached as the rejection handler to each promise in the iterable. It associates this closure with the shared `PromiseAnyRejectElementContext`. The index of the promise in the iterable is cleverly stored in the `identityHash` of this closure.
* **`PromiseAnyRejectElementClosure`:** This is the actual JavaScript function that gets called when an individual promise rejects. Its logic is:
    1. **Check if already called:** It uses the function's `context` to track if this rejection handler has been called before. If so, it does nothing.
    2. **Mark as called:** It updates the function's `context` to mark it as called.
    3. **Get index:** It retrieves the index of the promise from the closure's `identityHash`.
    4. **Store error:** It stores the rejection `value` in the `errors` array at the corresponding `index`. It dynamically expands the `errors` array if needed.
    5. **Decrement remaining count:** It decrements the `remainingElementsCount` in the shared context.
    6. **Check if all rejected:** If `remainingElementsCount` becomes 0, it means all promises have rejected. It creates an `AggregateError` with the collected errors and rejects the `Promise.any` promise using the `reject` function from the `PromiseCapability`.
* **`PerformPromiseAny`:** This macro contains the main logic for processing the iterable of promises:
    1. **Initialization:** Creates the `PromiseAnyRejectElementContext`.
    2. **Iteration:** Iterates through the input `iterable`.
    3. **Wrap in Promise:** For each item in the iterable, it ensures it's a promise using `CallResolve`.
    4. **Create and attach rejection handler:** It creates a `rejectElement` function using `CreatePromiseAnyRejectElementFunction` and attaches it as the rejection handler to the individual promise using `.then()`, along with the `resultCapability.resolve` as the fulfillment handler.
    5. **Increment remaining count:**  Crucially, the `remainingElementsCount` in the context is incremented *after* creating the reject handler for each promise. This is why it's initialized to 1 in `CreatePromiseAnyRejectElementContext` – to account for the initial increment that will happen for the first promise.
    6. **Handle iterator completion:** When the iteration is done (no more promises), it decrements the `remainingElementsCount`. If it's now 0, it means the iterable was empty or all promises have rejected synchronously, so it rejects the `Promise.any` promise with an `AggregateError`.
* **`PromiseAny`:** This is the main builtin function that is called when `Promise.any()` is invoked in JavaScript. It handles setup like getting the constructor and iterator, and then calls `PerformPromiseAny`.
* **`ConstructAggregateError`:** A helper macro to create the `AggregateError` object with the array of rejection reasons.

**Assumptions and Input/Output Examples:**

**Assumption:** The input `iterable` yields promises or thenables.

**Example 1: First promise fulfills**

* **Input `iterable`:** `[Promise.reject(1), Promise.resolve(2), Promise.reject(3)]`
* **Process:**
    1. `PerformPromiseAny` starts iterating.
    2. For the first promise (rejects with 1), a `rejectElement` closure is created.
    3. For the second promise (resolves with 2), the `resolve` handler of the main `Promise.any` promise is called with `2`.
    4. The main `Promise.any` promise fulfills with `2`.
* **Output:** The `Promise.any` promise resolves with `2`.

**Example 2: All promises reject**

* **Input `iterable`:** `[Promise.reject(1), Promise.reject(2)]`
* **Process:**
    1. `PerformPromiseAny` starts iterating.
    2. For the first promise (rejects with 1), a `rejectElement` closure is created and called. It stores `1` in the `errors` array. `remainingElementsCount` becomes 1.
    3. For the second promise (rejects with 2), a `rejectElement` closure is created and called. It stores `2` in the `errors` array. `remainingElementsCount` becomes 0.
    4. Since `remainingElementsCount` is 0, an `AggregateError` is created with `[1, 2]` as its `errors`.
    5. The main `Promise.any` promise rejects with this `AggregateError`.
* **Output:** The `Promise.any` promise rejects with an `AggregateError` whose `errors` property is `[1, 2]`.

**Example 3: Empty iterable**

* **Input `iterable`:** `[]`
* **Process:**
    1. `PerformPromiseAny` starts iterating.
    2. The `while` loop in `PerformPromiseAny` exits immediately because the iterator is done.
    3. The `remainingElementsCount` (initially 1) is decremented to 0.
    4. Since `remainingElementsCount` is 0, an empty `AggregateError` is created.
    5. The main `Promise.any` promise rejects with this `AggregateError`.
* **Output:** The `Promise.any` promise rejects with an `AggregateError` whose `errors` property is an empty array `[]`.

**4. User-Common Programming Errors:**

* **Not handling the rejection of `Promise.any`:** If all input promises reject, `Promise.any` will reject with an `AggregateError`. If this rejection is not caught using a `.catch()` block, it can lead to unhandled promise rejections.

   ```javascript
   const p1 = Promise.reject("error1");
   const p2 = Promise.reject("error2");

   Promise.any([p1, p2]); // No .catch()! This will lead to an unhandled rejection.

   Promise.any([p1, p2])
     .catch(error => {
       console.error("Promise.any rejected:", error);
       console.log("Rejection reasons:", error.errors); // Access the individual errors
     });
   ```

* **Assuming a specific order of errors in `AggregateError`:** While the code iterates through the promises in order, the rejections might happen asynchronously. The order of errors in the `AggregateError`'s `errors` array might not always correspond to the order of promises in the input iterable if they reject at slightly different times.

* **Providing non-promise values in the iterable:** While `Promise.any` will treat non-promise values as already resolved promises, it might not be the intended behavior. It's generally better to ensure the iterable contains actual promises for clarity.

   ```javascript
   Promise.any([1, Promise.reject("error")])
     .then(value => console.log(value)); // Output: 1 (because `1` is treated as a resolved promise)
   ```

In summary, this Torque code meticulously implements the `Promise.any` functionality, handling the complexities of iterating through promises, managing rejection states, and constructing the appropriate `AggregateError` when necessary. Understanding this code provides insights into how V8 optimizes and executes JavaScript promise combinators.

Prompt: 
```
这是目录为v8/src/builtins/promise-any.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include 'src/builtins/builtins-promise-gen.h'

namespace promise {
const kPromiseAny: constexpr UseCounterFeature
    generates 'v8::Isolate::kPromiseAny';
type PromiseAnyRejectElementContext extends FunctionContext;
extern enum PromiseAnyRejectElementContextSlots extends intptr
    constexpr 'PromiseBuiltins::PromiseAnyRejectElementContextSlots' {
  kPromiseAnyRejectElementRemainingSlot:
      Slot<PromiseAnyRejectElementContext, Smi>,
  kPromiseAnyRejectElementCapabilitySlot:
      Slot<PromiseAnyRejectElementContext, PromiseCapability>,
  kPromiseAnyRejectElementErrorsSlot:
      Slot<PromiseAnyRejectElementContext, FixedArray>,
  kPromiseAnyRejectElementLength
}

extern operator '[]=' macro StoreContextElement(
    Context, constexpr PromiseAnyRejectElementContextSlots, Object): void;
extern operator '[]' macro LoadContextElement(
    Context, constexpr PromiseAnyRejectElementContextSlots): Object;

// Creates the context used by all Promise.any reject element closures,
// together with the errors array. Since all closures for a single Promise.any
// call use the same context, we need to store the indices for the individual
// closures somewhere else (we put them into the identity hash field of the
// closures), and we also need to have a separate marker for when the closure
// was called already (we slap the native context onto the closure in that
// case to mark it's done). See Promise.all which uses the same approach.
transitioning macro CreatePromiseAnyRejectElementContext(
    implicit context: Context)(capability: PromiseCapability,
    nativeContext: NativeContext): PromiseAnyRejectElementContext {
  const rejectContext = %RawDownCast<PromiseAnyRejectElementContext>(
      AllocateSyntheticFunctionContext(
          nativeContext,
          PromiseAnyRejectElementContextSlots::kPromiseAnyRejectElementLength));
  InitContextSlot(
      rejectContext,
      PromiseAnyRejectElementContextSlots::
          kPromiseAnyRejectElementRemainingSlot,
      1);
  InitContextSlot(
      rejectContext,
      PromiseAnyRejectElementContextSlots::
          kPromiseAnyRejectElementCapabilitySlot,
      capability);
  InitContextSlot(
      rejectContext,
      PromiseAnyRejectElementContextSlots::kPromiseAnyRejectElementErrorsSlot,
      kEmptyFixedArray);
  return rejectContext;
}

const kPromiseAnyRejectElementClosureSharedFun: constexpr intptr
    generates 'RootIndex::kPromiseAnyRejectElementClosureSharedFun';

macro CreatePromiseAnyRejectElementFunction(
    implicit context: Context)(
    rejectElementContext: PromiseAnyRejectElementContext, index: Smi,
    nativeContext: NativeContext): JSFunction {
  dcheck(index > 0);
  dcheck(index < kPropertyArrayHashFieldMax);
  const reject = AllocateRootFunctionWithContext(
      kPromiseAnyRejectElementClosureSharedFun, rejectElementContext,
      nativeContext);
  dcheck(kPropertyArrayNoHashSentinel == 0);
  reject.properties_or_hash = index;
  return reject;
}

// https://tc39.es/ecma262/#sec-promise.any-reject-element-functions
transitioning javascript builtin PromiseAnyRejectElementClosure(
    js-implicit context: Context, receiver: JSAny, target: JSFunction)(
    value: JSAny): JSAny {
  // 1. Let F be the active function object.

  // 2. Let alreadyCalled be F.[[AlreadyCalled]].

  // 3. If alreadyCalled.[[Value]] is true, return undefined.

  // We use the function's context as the marker to remember whether this
  // reject element closure was already called. It points to the reject
  // element context (which is a FunctionContext) until it was called the
  // first time, in which case we make it point to the native context here
  // to mark this reject element closure as done.
  if (IsNativeContext(context)) deferred {
      return Undefined;
    }

  dcheck(
      context.length ==
      SmiTag(
          PromiseAnyRejectElementContextSlots::kPromiseAnyRejectElementLength));
  const context = %RawDownCast<PromiseAnyRejectElementContext>(context);

  // 4. Set alreadyCalled.[[Value]] to true.
  const nativeContext = LoadNativeContext(context);
  target.context = nativeContext;

  // 5. Let index be F.[[Index]].
  dcheck(kPropertyArrayNoHashSentinel == 0);
  const identityHash = LoadJSReceiverIdentityHash(target) otherwise unreachable;
  dcheck(ChangeUint32ToWord(identityHash) < kSmiMaxValue);
  const index = Signed(ChangeUint32ToWord(identityHash)) - 1;

  // 6. Let errors be F.[[Errors]].
  let errorsRef:&FixedArray = ContextSlot(
      context,
      PromiseAnyRejectElementContextSlots::kPromiseAnyRejectElementErrorsSlot);
  let errors = *errorsRef;

  // 7. Let promiseCapability be F.[[Capability]].

  // 8. Let remainingElementsCount be F.[[RemainingElements]].
  let remainingElementsCount = *ContextSlot(
      context,
      PromiseAnyRejectElementContextSlots::
          kPromiseAnyRejectElementRemainingSlot);

  // 9. Set errors[index] to x.

  // The max computation below is an optimization to avoid excessive allocations
  // in the case of input promises being asynchronously rejected in ascending
  // index order.
  //
  // Note that subtracting 1 from remainingElementsCount is intentional. The
  // value of remainingElementsCount is 1 larger than the actual value during
  // iteration. So in the case of synchronous rejection, newCapacity is the
  // correct size by subtracting 1. In the case of asynchronous rejection this
  // is 1 smaller than the correct size, but is not incorrect as it is maxed
  // with index + 1.
  const newCapacity =
      IntPtrMax(SmiUntag(remainingElementsCount) - 1, index + 1);
  if (newCapacity > errors.length_intptr) deferred {
      errors = ExtractFixedArray(
          errors, 0, errors.length_intptr, newCapacity, PromiseHole);
      *errorsRef = errors;
    }
  errors.objects[index] = value;

  // 10. Set remainingElementsCount.[[Value]] to
  // remainingElementsCount.[[Value]] - 1.
  remainingElementsCount = remainingElementsCount - 1;
  *ContextSlot(
      context,
      PromiseAnyRejectElementContextSlots::
          kPromiseAnyRejectElementRemainingSlot) = remainingElementsCount;

  // 11. If remainingElementsCount.[[Value]] is 0, then
  if (remainingElementsCount == 0) {
    //   a. Let error be a newly created AggregateError object.

    //   b. Set error.[[AggregateErrors]] to errors.
    const error = ConstructAggregateError(errors);

    // After this point, errors escapes to user code. Clear the slot.
    *errorsRef = kEmptyFixedArray;

    //   c. Return ? Call(promiseCapability.[[Reject]], undefined, « error »).
    const capability = *ContextSlot(
        context,
        PromiseAnyRejectElementContextSlots::
            kPromiseAnyRejectElementCapabilitySlot);
    Call(context, UnsafeCast<Callable>(capability.reject), Undefined, error);
  }

  // 12. Return undefined.
  return Undefined;
}

transitioning macro PerformPromiseAny(
    implicit context: Context)(nativeContext: NativeContext,
    iteratorRecord: iterator::IteratorRecord, constructor: Constructor,
    resultCapability: PromiseCapability,
    promiseResolveFunction: JSAny): JSAny labels
Reject(JSAny) {
  // 1. Assert: ! IsConstructor(constructor) is true.
  // 2. Assert: resultCapability is a PromiseCapability Record.

  // 3. Let errors be a new empty List. (Do nothing: errors is
  // initialized lazily when the first Promise rejects.)

  // 4. Let remainingElementsCount be a new Record { [[Value]]: 1 }.
  const rejectElementContext =
      CreatePromiseAnyRejectElementContext(resultCapability, nativeContext);

  // 5. Let index be 0.
  //    (We subtract 1 in the PromiseAnyRejectElementClosure).
  let index: Smi = 1;

  try {
    const fastIteratorResultMap = *NativeContextSlot(
        nativeContext, ContextSlot::ITERATOR_RESULT_MAP_INDEX);
    // 8. Repeat,
    while (true) {
      let nextValue: JSAny;
      try {
        // a. Let next be IteratorStep(iteratorRecord).

        // b. If next is an abrupt completion, set
        // iteratorRecord.[[Done]] to true.

        // c. ReturnIfAbrupt(next).

        // d. if next is false, then [continues below in "Done"]
        const next: JSReceiver = iterator::IteratorStep(
            iteratorRecord, fastIteratorResultMap) otherwise goto Done;
        // e. Let nextValue be IteratorValue(next).

        // f. If nextValue is an abrupt completion, set
        // iteratorRecord.[[Done]] to true.

        // g. ReturnIfAbrupt(nextValue).
        nextValue = iterator::IteratorValue(next, fastIteratorResultMap);
      } catch (e, _message) {
        goto Reject(e);
      }

      // We store the indices as identity hash on the reject element
      // closures. Thus, we need this limit.
      if (index == kPropertyArrayHashFieldMax) {
        // If there are too many elements (currently more than
        // 2**21-1), raise a RangeError here (which is caught later and
        // turned into a rejection of the resulting promise). We could
        // gracefully handle this case as well and support more than
        // this number of elements by going to a separate function and
        // pass the larger indices via a separate context, but it
        // doesn't seem likely that we need this, and it's unclear how
        // the rest of the system deals with 2**21 live Promises
        // anyway.
        ThrowRangeError(
            MessageTemplate::kTooManyElementsInPromiseCombinator, 'any');
      }

      // h. Append undefined to errors. (Do nothing: errors is initialized
      // lazily when the first Promise rejects.)

      let nextPromise: JSAny;
      // i. Let nextPromise be ? Call(constructor, promiseResolve,
      // «nextValue »).
      nextPromise = CallResolve(constructor, promiseResolveFunction, nextValue);

      // j. Let steps be the algorithm steps defined in Promise.any
      // Reject Element Functions.

      // k. Let rejectElement be ! CreateBuiltinFunction(steps, «
      // [[AlreadyCalled]], [[Index]],
      // [[Errors]], [[Capability]], [[RemainingElements]] »).

      // l. Set rejectElement.[[AlreadyCalled]] to a new Record {
      // [[Value]]: false }.

      // m. Set rejectElement.[[Index]] to index.

      // n. Set rejectElement.[[Errors]] to errors.

      // o. Set rejectElement.[[Capability]] to resultCapability.

      // p. Set rejectElement.[[RemainingElements]] to
      // remainingElementsCount.
      const rejectElement = CreatePromiseAnyRejectElementFunction(
          rejectElementContext, index, nativeContext);
      // q. Set remainingElementsCount.[[Value]] to
      // remainingElementsCount.[[Value]] + 1.
      const remainingElementsCount = *ContextSlot(
          rejectElementContext,
          PromiseAnyRejectElementContextSlots::
              kPromiseAnyRejectElementRemainingSlot);
      *ContextSlot(
          rejectElementContext,
          PromiseAnyRejectElementContextSlots::
              kPromiseAnyRejectElementRemainingSlot) =
          remainingElementsCount + 1;

      // r. Perform ? Invoke(nextPromise, "then", «
      // resultCapability.[[Resolve]], rejectElement »).
      let thenResult: JSAny;

      const then = GetProperty(nextPromise, kThenString);
      thenResult = Call(
          context, then, nextPromise,
          UnsafeCast<JSAny>(resultCapability.resolve), rejectElement);

      // s. Increase index by 1.
      index += 1;

      // For catch prediction, mark that rejections here are
      // semantically handled by the combined Promise.
      if (IsDebugActive() && Is<JSPromise>(thenResult)) deferred {
          SetPropertyStrict(
              context, thenResult, kPromiseHandledBySymbol,
              resultCapability.promise);
          SetPropertyStrict(
              context, rejectElement, kPromiseForwardingHandlerSymbol, True);
        }
    }
  } catch (e, _message) deferred {
    iterator::IteratorCloseOnException(iteratorRecord);
    goto Reject(e);
  } label Done {}

  // (8.d)
  //   i. Set iteratorRecord.[[Done]] to true.
  //  ii. Set remainingElementsCount.[[Value]] to
  //  remainingElementsCount.[[Value]] - 1.
  const remainingElementsCount = -- *ContextSlot(
      rejectElementContext,
      PromiseAnyRejectElementContextSlots::
          kPromiseAnyRejectElementRemainingSlot);

  // iii. If remainingElementsCount.[[Value]] is 0, then
  if (remainingElementsCount == 0) deferred {
      // 1. Let error be a newly created AggregateError object.
      // 2. Set error.[[AggregateErrors]] to errors.

      // We may already have elements in "errors" - this happens when the
      // Thenable calls the reject callback immediately.
      const errorsRef:&FixedArray = ContextSlot(
          rejectElementContext,
          PromiseAnyRejectElementContextSlots::
              kPromiseAnyRejectElementErrorsSlot);
      const errors: FixedArray = *errorsRef;

      // After this point, errors escapes to user code. Clear the slot.
      *errorsRef = kEmptyFixedArray;

      check(errors.length == index - 1);
      const error = ConstructAggregateError(errors);
      // 3. Return ThrowCompletion(error).
      goto Reject(error);
    }
  // iv. Return resultCapability.[[Promise]].
  return resultCapability.promise;
}

// https://tc39.es/ecma262/#sec-promise.any
transitioning javascript builtin PromiseAny(
    js-implicit context: Context, receiver: JSAny)(iterable: JSAny): JSAny {
  IncrementUseCounter(context, SmiConstant(kPromiseAny));
  const nativeContext = LoadNativeContext(context);

  // 1. Let C be the this value.
  const receiver = Cast<JSReceiver>(receiver)
      otherwise ThrowTypeError(MessageTemplate::kCalledOnNonObject, 'Promise.any');

  // 2. Let promiseCapability be ? NewPromiseCapability(C).
  const capability = NewPromiseCapability(receiver, False);

  // NewPromiseCapability guarantees that receiver is Constructor.
  dcheck(Is<Constructor>(receiver));
  const constructor = UnsafeCast<Constructor>(receiver);

  try {
    // 3. Let promiseResolve be GetPromiseResolve(C).
    // 4. IfAbruptRejectPromise(promiseResolve, promiseCapability).
    // (catch below)
    const promiseResolveFunction =
        GetPromiseResolve(nativeContext, constructor);

    // 5. Let iteratorRecord be GetIterator(iterable).

    // 6. IfAbruptRejectPromise(iteratorRecord, promiseCapability).
    // (catch below)
    const iteratorRecord = iterator::GetIterator(iterable);

    // 7. Let result be PerformPromiseAny(iteratorRecord, C,
    // promiseCapability).

    // 8. If result is an abrupt completion, then

    //   a. If iteratorRecord.[[Done]] is false, set result to
    //   IteratorClose(iteratorRecord, result).

    //   b. IfAbruptRejectPromise(result, promiseCapability).

    // [Iterator closing handled by PerformPromiseAny]

    // 9. Return Completion(result).
    return PerformPromiseAny(
        nativeContext, iteratorRecord, constructor, capability,
        promiseResolveFunction)
        otherwise Reject;
  } catch (e, _message) deferred {
    goto Reject(e);
  } label Reject(e: JSAny) deferred {
    // Exception must be bound to a JS value.
    dcheck(e != PromiseHole);
    Call(
        context, UnsafeCast<Callable>(capability.reject), Undefined,
        UnsafeCast<JSAny>(e));
    return capability.promise;
  }
}

transitioning macro ConstructAggregateError(
    implicit context: Context)(errors: FixedArray): JSObject {
  const obj: JSObject = error::ConstructInternalAggregateErrorHelper(
      context, SmiConstant(MessageTemplate::kAllPromisesRejected));
  const errorsJSArray = array::CreateJSArrayWithElements(errors);
  SetOwnPropertyIgnoreAttributes(
      obj, ErrorsStringConstant(), errorsJSArray,
      SmiConstant(PropertyAttributes::DONT_ENUM));
  return obj;
}

extern macro PromiseAnyRejectElementSharedFunConstant(): SharedFunctionInfo;
}

"""

```