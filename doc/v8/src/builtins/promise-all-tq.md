Response: Let's break down the thought process for analyzing this Torque code and generating the summary.

1. **Understand the Goal:** The request asks for a summary of the provided V8 Torque code (`v8/src/builtins/promise-all.tq`), focusing on its functionality, relationship to JavaScript, code logic, and potential programming errors.

2. **Identify the Core Functionality:**  The file name "promise-all.tq" immediately suggests this code implements the `Promise.all` and possibly related functionality like `Promise.allSettled`. A quick scan of the `@export` annotations confirms the presence of `PromiseAll` and `PromiseAllSettled` builtins.

3. **Analyze Key Macros and Functions:**  Start by examining the main building blocks. Look for macros and functions that seem to handle core logic:

    * **`CreatePromiseAllResolveElementContext`:**  This clearly creates a context object. The names of the context slots (`kPromiseAllResolveElementRemainingSlot`, `kPromiseAllResolveElementCapabilitySlot`, `kPromiseAllResolveElementValuesSlot`) give strong hints about its purpose: managing the remaining promises, the overall `Promise.all` capability, and the array to store resolved values.

    * **`CreatePromiseAllResolveElementFunction`:** This macro creates a function, taking the context and an index. The comment about storing the index in `properties_or_hash` is important. It suggests that each individual promise's resolution will trigger this function.

    * **`PerformPromiseAll`:** This looks like the central logic. It takes an iterator, a constructor (presumably the `Promise` constructor), and the promise capability. The loop suggests iterating over the input iterable. The calls to `createResolveElementFunctor` and `createRejectElementFunctor` confirm the connection to individual promise resolutions.

    * **`GeneratePromiseAll`:** This seems like a higher-level function that sets up the `PerformPromiseAll` call. It handles type checking of the receiver and getting the iterator.

    * **`PromiseAll` and `PromiseAllSettled`:** These are the exported builtins, calling `GeneratePromiseAll` with different functor implementations.

4. **Map Torque to JavaScript Concepts:**  As you analyze, think about how these Torque constructs relate to JavaScript `Promise.all` behavior:

    * `PromiseCapability`: Directly maps to the concept of a promise's resolve and reject functions.
    * `Iterator`:  Relates to the iterable input of `Promise.all`.
    * The `resolveElement` and `rejectElement` functions created within `PerformPromiseAll` correspond to the handlers that are attached to each individual promise in the input iterable.
    * The `values` array in the context corresponds to the array of resolved values that `Promise.all` returns.

5. **Infer Code Logic and Flow:**  Trace the execution flow within `PerformPromiseAll`:

    * It initializes a context to track progress.
    * It iterates through the input iterable.
    * For each element, it creates resolve and reject functions (`resolveElementFun`, `rejectElementFun`).
    * It gets a promise from the current iterable element (using `CallResolve` or directly if optimizations apply).
    * It attaches the resolve and reject handlers to this promise using `PerformPromiseThenImpl` or by calling `then`.
    * It tracks the number of remaining promises.
    * Once all promises resolve, it resolves the main `Promise.all` promise with the collected values.
    * If any promise rejects, it rejects the main `Promise.all` promise.

6. **Consider Edge Cases and Potential Errors:**  Think about what could go wrong:

    * **Non-iterable input:** `GeneratePromiseAll` checks for this.
    * **Too many promises:** The code explicitly checks for `kPropertyArrayHashFieldMax` and throws a `RangeError`.
    * **Rejection of individual promises:** This is handled by the `rejectElementFun`.
    * **Non-Promise elements in the iterable:** The code handles this by using `Promise.resolve` to coerce non-promise values into promises.

7. **Construct JavaScript Examples:**  Create concrete JavaScript examples to illustrate the behavior of `Promise.all` and `Promise.allSettled`, covering both successful resolutions and rejections.

8. **Formulate Assumptions for Input and Output:**  For the code logic inference, create simple scenarios with a small number of promises, demonstrating both successful resolution and rejection. Specify the expected output in each case.

9. **Identify Common Programming Errors:** Think about how developers might misuse `Promise.all`, such as forgetting to handle rejections or misunderstanding how it behaves with non-promise values.

10. **Structure the Summary:** Organize the information logically with clear headings and bullet points for readability. Start with the main functionality, then delve into the details, JavaScript examples, logic inference, and potential errors.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Maybe the index is just a simple counter."  **Correction:** The comment about `kPropertyArrayHashFieldMax` and storing the index in `properties_or_hash` indicates a potential optimization or limitation related to object properties.

* **Initial thought:** "The `promiseResolveFunction` argument in `PerformPromiseAll` is always used." **Correction:**  The `if` condition with `IsPromiseThenLookupChainIntact` shows there's an optimization path where `then` is directly called without involving `Promise.resolve` in certain cases.

* **Realization:**  The separation of `PerformPromiseAll` and `GeneratePromiseAll` is for clarity and handling setup tasks like iterator retrieval and error handling.

By following these steps and constantly relating the Torque code back to the familiar JavaScript `Promise.all` behavior, you can arrive at a comprehensive and accurate summary.
这段V8 Torque源代码实现了 JavaScript 中的 `Promise.all` 和 `Promise.allSettled` 功能。

**功能归纳:**

这段代码定义了 V8 引擎中实现 `Promise.all` 和 `Promise.allSettled` 的底层逻辑。它主要负责以下任务：

1. **创建上下文 (Context):** 为 `Promise.all` 和 `Promise.allSettled` 的回调函数创建特定的上下文，用于存储状态信息，例如剩余的 Promise 数量、最终结果的数组以及 Promise 的 capability 对象（包含 resolve 和 reject 函数）。

2. **创建解析和拒绝的回调函数:**  定义了当输入的可迭代对象中的 Promise 解析或拒绝时执行的回调函数。这些回调函数会更新上下文中的状态，并将解析的值存储到结果数组中（`Promise.all`），或者存储每个 Promise 的状态和值/原因（`Promise.allSettled`）。

3. **处理迭代:** 迭代输入的可迭代对象，并为每个元素（预期是 Promise）附加解析和拒绝处理程序。

4. **管理 Promise 状态:** 跟踪输入 Promise 的解析和拒绝状态，并在所有 Promise 都完成（无论是解析还是拒绝）后，解析或拒绝最终的 `Promise.all` 或 `Promise.allSettled` Promise。

5. **优化:** 代码中包含一些优化策略，例如在特定条件下跳过 `then` 方法的查找，直接链接 Promise 的后续处理。

**与 JavaScript 功能的关系及示例:**

这段 Torque 代码直接对应于 JavaScript 中全局 `Promise` 对象的静态方法 `Promise.all` 和 `Promise.allSettled`。

**JavaScript `Promise.all` 示例:**

```javascript
const promise1 = Promise.resolve(3);
const promise2 = 42;
const promise3 = new Promise((resolve, reject) => {
  setTimeout(resolve, 100, 'foo');
});

Promise.all([promise1, promise2, promise3]).then((values) => {
  console.log(values); // expected output: Array [3, 42, "foo"]
});

// 如果其中一个 Promise 被拒绝
const promise4 = Promise.reject('出错了');
Promise.all([promise1, promise4, promise3]).catch((error) => {
  console.log(error); // expected output: 出错了
});
```

`Promise.all` 接收一个由 Promise 组成的可迭代对象（例如数组）。它返回一个新的 Promise，该 Promise 在**所有**输入的 Promise 都成功解析时解析，并带有一个包含所有解析值的数组。如果任何一个输入的 Promise 被拒绝，返回的 Promise 将立即被拒绝，并带有被拒绝的 Promise 的原因。

**JavaScript `Promise.allSettled` 示例:**

```javascript
const promise1 = Promise.resolve(3);
const promise2 = new Promise((resolve, reject) => setTimeout(reject, 100, '出错了'));
const promises = [promise1, promise2];

Promise.allSettled(promises).then((results) => {
  console.log(results);
  /* expected output:
  Array [
    Object { status: "fulfilled", value: 3 },
    Object { status: "rejected", reason: "出错了" },
  ]
  */
});
```

`Promise.allSettled` 也接收一个由 Promise 组成的可迭代对象。它返回一个新的 Promise，该 Promise 在**所有**输入的 Promise 都完成（无论是解析还是拒绝）时解析。返回的 Promise 的解析值是一个数组，该数组中的每个元素都描述了相应 Promise 的结果。

**代码逻辑推理 (假设输入与输出):**

**假设 `Promise.all` 的输入是一个包含两个 Promise 的数组:**

```javascript
const promiseA = new Promise((resolve) => setTimeout(resolve, 50, 'A'));
const promiseB = Promise.resolve('B');
const iterable = [promiseA, promiseB];
```

**Torque 代码的执行流程 (简化):**

1. **`GeneratePromiseAll` 被调用:** 接收 `iterable` 和 `Promise` 构造函数。
2. **`PerformPromiseAll` 被调用:**
   - 创建 `PromiseCapability` 用于最终的 `Promise.all` Promise。
   - 创建 `PromiseAllResolveElementContext` 来存储状态。
   - 迭代 `iterable`：
     - 对于 `promiseA`：
       - 创建解析回调函数 `resolveElementFun` 和拒绝回调函数 `rejectElementFun`。
       - 将这些回调函数附加到 `promiseA` 上（相当于调用 `promiseA.then(resolveElementFun, rejectElementFun)`）。
     - 对于 `promiseB`：
       - 创建解析回调函数和拒绝回调函数。
       - 将这些回调函数附加到 `promiseB` 上。
   - `promiseA` 解析后，`resolveElementFun` 被调用：
     - 将 'A' 存储到 `PromiseAllResolveElementContext` 的 `values` 数组中。
     - 将 `remainingElementsCount` 减 1。
   - `promiseB` 解析后，其对应的 `resolveElementFun` 被调用：
     - 将 'B' 存储到 `values` 数组中。
     - `remainingElementsCount` 变为 0。
   - 当 `remainingElementsCount` 为 0 时，创建一个包含 `values` 数组的新的 JavaScript 数组 `['A', 'B']`。
   - 使用 `PromiseCapability` 的 `resolve` 函数解析最终的 `Promise.all` Promise，并将 `['A', 'B']` 作为解析值。

**输出:**  `Promise.all(iterable)` 返回的 Promise 会在一段时间后解析为 `['A', 'B']`。

**假设 `Promise.all` 的输入包含一个会被拒绝的 Promise:**

```javascript
const promiseC = Promise.resolve('C');
const promiseD = Promise.reject('Error D');
const iterableWithError = [promiseC, promiseD];
```

**Torque 代码的执行流程 (简化):**

1. **`GeneratePromiseAll` 被调用。**
2. **`PerformPromiseAll` 被调用。**
3. **迭代 `iterableWithError`。**
4. **`promiseD` 被拒绝后，其对应的 `rejectElementFun` 被调用：**
   - 使用 `PromiseCapability` 的 `reject` 函数立即拒绝最终的 `Promise.all` Promise，并将 `'Error D'` 作为拒绝原因。

**输出:** `Promise.all(iterableWithError)` 返回的 Promise 会立即被拒绝，拒绝原因为 `'Error D'`。

**涉及用户常见的编程错误:**

1. **未处理 `Promise.all` 的拒绝:**  如果 `Promise.all` 接收的 Promise 数组中任何一个 Promise 被拒绝，而返回的 Promise 的 `catch` 方法没有被调用，那么拒绝会被忽略，可能导致程序行为不符合预期。

   ```javascript
   const failingPromise = Promise.reject("Something went wrong!");
   Promise.all([Promise.resolve(1), failingPromise, Promise.resolve(2)]);
   // 这里没有 .catch 来处理拒绝，可能导致 unhandledrejection 错误。

   Promise.all([Promise.resolve(1), failingPromise, Promise.resolve(2)])
     .then(results => console.log("成功了!", results))
     .catch(error => console.error("出错了!", error)); // 正确的做法
   ```

2. **将非 Promise 对象传递给 `Promise.all`:** 虽然 `Promise.all` 会尝试将非 Promise 对象转换为 Promise (相当于 `Promise.resolve(value)`), 但用户可能误以为需要传递的都是 Promise 对象。

   ```javascript
   Promise.all([1, "hello", true]).then(values => console.log(values));
   // 这会正常工作，因为非 Promise 值会被 Promise.resolve 包裹。
   ```

3. **误解 `Promise.allSettled` 的返回值:**  用户可能期望 `Promise.allSettled` 在所有 Promise 都成功解析时才解析，但实际上它在所有 Promise 完成（无论成功或失败）时都会解析。 需要检查返回数组中每个元素的状态来判断 Promise 是否成功。

   ```javascript
   Promise.allSettled([Promise.resolve(1), Promise.reject("error")])
     .then(results => {
       results.forEach(result => {
         if (result.status === 'fulfilled') {
           console.log("成功:", result.value);
         } else {
           console.error("失败:", result.reason);
         }
       });
     });
   ```

总而言之，这段 Torque 代码是 V8 引擎中实现 `Promise.all` 和 `Promise.allSettled` 核心逻辑的关键部分，它负责创建上下文、管理 Promise 状态以及处理异步操作的最终结果。 理解这段代码有助于更深入地理解 JavaScript Promise 的工作原理。

### 提示词
```
这是目录为v8/src/builtins/promise-all.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include 'src/builtins/builtins-promise.h'
#include 'src/builtins/builtins-promise-gen.h'

namespace promise {
const kPromiseBuiltinsPromiseContextLength: constexpr int31
    generates 'PromiseBuiltins::kPromiseContextLength';

// Creates the context used by all Promise.all resolve element closures,
// together with the values array. Since all closures for a single Promise.all
// call use the same context, we need to store the indices for the individual
// closures somewhere else (we put them into the identity hash field of the
// closures).
macro CreatePromiseAllResolveElementContext(
    implicit context: Context)(capability: PromiseCapability,
    nativeContext: NativeContext): PromiseAllResolveElementContext {
  const resolveContext = %RawDownCast<
      PromiseAllResolveElementContext>(AllocateSyntheticFunctionContext(
      nativeContext,
      PromiseAllResolveElementContextSlots::kPromiseAllResolveElementLength));
  InitContextSlot(
      resolveContext,
      PromiseAllResolveElementContextSlots::
          kPromiseAllResolveElementRemainingSlot,
      1);
  InitContextSlot(
      resolveContext,
      PromiseAllResolveElementContextSlots::
          kPromiseAllResolveElementCapabilitySlot,
      capability);
  InitContextSlot(
      resolveContext,
      PromiseAllResolveElementContextSlots::kPromiseAllResolveElementValuesSlot,
      kEmptyFixedArray);
  return resolveContext;
}

macro CreatePromiseAllResolveElementFunction(
    implicit context: Context)(
    resolveElementContext: PromiseAllResolveElementContext, index: Smi,
    resolveFunction: constexpr intptr): JSFunction {
  dcheck(index > 0);
  dcheck(index < kPropertyArrayHashFieldMax);

  const resolve = AllocateRootFunctionWithContext(
      resolveFunction, resolveElementContext,
      LoadNativeContext(resolveElementContext));

  dcheck(kPropertyArrayNoHashSentinel == 0);
  resolve.properties_or_hash = index;
  return resolve;
}

@export
macro CreatePromiseResolvingFunctionsContext(
    implicit context: Context)(promise: JSPromise, debugEvent: Boolean,
    nativeContext: NativeContext): PromiseResolvingFunctionContext {
  const resolveContext = %RawDownCast<PromiseResolvingFunctionContext>(
      AllocateSyntheticFunctionContext(
          nativeContext,
          PromiseResolvingFunctionContextSlot::kPromiseContextLength));
  InitContextSlot(
      resolveContext, PromiseResolvingFunctionContextSlot::kPromiseSlot,
      promise);
  InitContextSlot(
      resolveContext, PromiseResolvingFunctionContextSlot::kAlreadyResolvedSlot,
      False);
  InitContextSlot(
      resolveContext, PromiseResolvingFunctionContextSlot::kDebugEventSlot,
      debugEvent);
  static_assert(
      PromiseResolvingFunctionContextSlot::kPromiseContextLength ==
      ContextSlot::MIN_CONTEXT_SLOTS + 3);
  return resolveContext;
}

macro IsPromiseThenLookupChainIntact(
    implicit context: Context)(nativeContext: NativeContext,
    receiverMap: Map): bool {
  if (IsForceSlowPath()) return false;
  if (!IsJSPromiseMap(receiverMap)) return false;
  if (receiverMap.prototype != *NativeContextSlot(
          nativeContext, ContextSlot::PROMISE_PROTOTYPE_INDEX)) {
    return false;
  }
  return !IsPromiseThenProtectorCellInvalid();
}

const kPromiseAllResolveElementClosureSharedFun: constexpr intptr
    generates 'static_cast<intptr_t>(RootIndex::kPromiseAllResolveElementClosureSharedFun)'
    ;
struct PromiseAllResolveElementFunctor {
  macro Call(
      implicit context: Context)(
      resolveElementContext: PromiseAllResolveElementContext,
      _nativeContext: NativeContext, index: Smi,
      _capability: PromiseCapability): Callable {
    return CreatePromiseAllResolveElementFunction(
        resolveElementContext, index,
        kPromiseAllResolveElementClosureSharedFun);
  }
}

struct PromiseAllRejectElementFunctor {
  macro Call(
      implicit context: Context)(
      _resolveElementContext: PromiseAllResolveElementContext,
      _nativeContext: NativeContext, _index: Smi,
      capability: PromiseCapability): Callable {
    return UnsafeCast<Callable>(capability.reject);
  }
}

const kPromiseAllSettledResolveElementClosureSharedFun: constexpr intptr
    generates 'static_cast<intptr_t>(RootIndex::kPromiseAllSettledResolveElementClosureSharedFun)'
    ;
struct PromiseAllSettledResolveElementFunctor {
  macro Call(
      implicit context: Context)(
      resolveElementContext: PromiseAllResolveElementContext,
      _nativeContext: NativeContext, index: Smi,
      _capability: PromiseCapability): Callable {
    return CreatePromiseAllResolveElementFunction(
        resolveElementContext, index,
        kPromiseAllSettledResolveElementClosureSharedFun);
  }
}

const kPromiseAllSettledRejectElementClosureSharedFun: constexpr intptr
    generates 'static_cast<intptr_t>(RootIndex::kPromiseAllSettledRejectElementClosureSharedFun)'
    ;
struct PromiseAllSettledRejectElementFunctor {
  macro Call(
      implicit context: Context)(
      resolveElementContext: PromiseAllResolveElementContext,
      _nativeContext: NativeContext, index: Smi,
      _capability: PromiseCapability): Callable {
    return CreatePromiseAllResolveElementFunction(
        resolveElementContext, index,
        kPromiseAllSettledRejectElementClosureSharedFun);
  }
}

transitioning macro PerformPromiseAll<F1: type, F2: type>(
    implicit context: Context)(nativeContext: NativeContext,
    iter: iterator::IteratorRecord, constructor: Constructor,
    capability: PromiseCapability, promiseResolveFunction: JSAny,
    createResolveElementFunctor: F1,
    createRejectElementFunctor: F2): JSAny labels
Reject(JSAny) {
  const promise = capability.promise;
  const resolve = capability.resolve;
  const reject = capability.reject;

  // For catch prediction, don't treat the .then calls as handling it;
  // instead, recurse outwards.
  if (IsDebugActive()) deferred {
      SetPropertyStrict(context, reject, kPromiseForwardingHandlerSymbol, True);
    }

  const resolveElementContext =
      CreatePromiseAllResolveElementContext(capability, nativeContext);

  let index: Smi = 1;

  try {
    const fastIteratorResultMap = *NativeContextSlot(
        nativeContext, ContextSlot::ITERATOR_RESULT_MAP_INDEX);
    while (true) {
      let nextValue: JSAny;
      try {
        // Let next be IteratorStep(iteratorRecord.[[Iterator]]).
        // If next is an abrupt completion, set iteratorRecord.[[Done]] to
        // true. ReturnIfAbrupt(next).
        const next: JSReceiver = iterator::IteratorStep(
            iter, fastIteratorResultMap) otherwise goto Done;

        // Let nextValue be IteratorValue(next).
        // If nextValue is an abrupt completion, set iteratorRecord.[[Done]]
        // to true.
        // ReturnIfAbrupt(nextValue).
        nextValue = iterator::IteratorValue(next, fastIteratorResultMap);
      } catch (e, _message) {
        goto Reject(e);
      }

      // Check if we reached the limit.
      if (index == kPropertyArrayHashFieldMax) {
        // If there are too many elements (currently more than 2**21-1),
        // raise a RangeError here (which is caught below and turned into
        // a rejection of the resulting promise). We could gracefully handle
        // this case as well and support more than this number of elements
        // by going to a separate function and pass the larger indices via a
        // separate context, but it doesn't seem likely that we need this,
        // and it's unclear how the rest of the system deals with 2**21 live
        // Promises anyway.
        ThrowRangeError(
            MessageTemplate::kTooManyElementsInPromiseCombinator, 'all');
      }

      // Set remainingElementsCount.[[Value]] to
      //     remainingElementsCount.[[Value]] + 1.
      *ContextSlot(
          resolveElementContext,
          PromiseAllResolveElementContextSlots::
              kPromiseAllResolveElementRemainingSlot) += 1;

      // Let resolveElement be CreateBuiltinFunction(steps,
      //                                             « [[AlreadyCalled]],
      //                                               [[Index]],
      //                                               [[Values]],
      //                                               [[Capability]],
      //                                               [[RemainingElements]]
      //                                               »).
      // Set resolveElement.[[AlreadyCalled]] to a Record { [[Value]]: false
      // }. Set resolveElement.[[Index]] to index. Set
      // resolveElement.[[Values]] to values. Set
      // resolveElement.[[Capability]] to resultCapability. Set
      // resolveElement.[[RemainingElements]] to remainingElementsCount.
      const resolveElementFun = createResolveElementFunctor.Call(
          resolveElementContext, nativeContext, index, capability);
      const rejectElementFun = createRejectElementFunctor.Call(
          resolveElementContext, nativeContext, index, capability);

      // We can skip the "then" lookup on the result of the "resolve" call and
      // immediately chain the continuation onto the {next_value} if:
      //
      //   (a) The {constructor} is the intrinsic %Promise% function, and
      //       looking up "resolve" on {constructor} yields the initial
      //       Promise.resolve() builtin, and
      //   (b) the promise @@species protector cell is valid, meaning that
      //       no one messed with the Symbol.species property on any
      //       intrinsic promise or on the Promise.prototype, and
      //   (c) the {next_value} is a JSPromise whose [[Prototype]] field
      //       contains the intrinsic %PromisePrototype%, and
      //   (d) we're not running with async_hooks or DevTools enabled.
      //
      // In that case we also don't need to allocate a chained promise for
      // the PromiseReaction (aka we can pass undefined to
      // PerformPromiseThen), since this is only necessary for DevTools and
      // PromiseHooks.
      if (promiseResolveFunction != Undefined || NeedsAnyPromiseHooks() ||
          IsPromiseSpeciesProtectorCellInvalid() || Is<Smi>(nextValue) ||
          !IsPromiseThenLookupChainIntact(
              nativeContext, UnsafeCast<HeapObject>(nextValue).map)) {
        // Let nextPromise be ? Call(constructor, _promiseResolve_, «
        // nextValue »).
        const nextPromise =
            CallResolve(constructor, promiseResolveFunction, nextValue);

        // Perform ? Invoke(nextPromise, "then", « resolveElement,
        //                  resultCapability.[[Reject]] »).
        const then = GetProperty(nextPromise, kThenString);
        const thenResult = Call(
            nativeContext, then, nextPromise, resolveElementFun,
            rejectElementFun);

        // For catch prediction, mark that rejections here are
        // semantically handled by the combined Promise.
        if (IsDebugActive() && Is<JSPromise>(thenResult)) deferred {
            SetPropertyStrict(
                context, thenResult, kPromiseHandledBySymbol, promise);
          }
      } else {
        PerformPromiseThenImpl(
            UnsafeCast<JSPromise>(nextValue), resolveElementFun,
            rejectElementFun, Undefined);
      }

      // Set index to index + 1.
      index += 1;
    }
  } catch (e, _message) deferred {
    iterator::IteratorCloseOnException(iter);
    goto Reject(e);
  } label Done {}

  // Set iteratorRecord.[[Done]] to true.
  // Set remainingElementsCount.[[Value]] to
  //    remainingElementsCount.[[Value]] - 1.
  const remainingElementsCount = -- *ContextSlot(
      resolveElementContext,
      PromiseAllResolveElementContextSlots::
          kPromiseAllResolveElementRemainingSlot);

  check(remainingElementsCount >= 0);

  const valuesRef:&FixedArray = ContextSlot(
      resolveElementContext,
      PromiseAllResolveElementContextSlots::
          kPromiseAllResolveElementValuesSlot);
  const values = *valuesRef;

  if (remainingElementsCount > 0) {
    // Pre-allocate the backing store for the {values} to the desired
    // capacity. We may already have elements in "values" - this happens
    // when the Thenable calls the resolve callback immediately.
    // 'index' is a 1-based index and incremented after every Promise. Later we
    // use 'values' as a 0-based array, so capacity 'index - 1' is enough.
    const newCapacity = SmiUntag(index) - 1;

    const oldCapacity = values.length_intptr;
    if (oldCapacity < newCapacity) {
      *valuesRef =
          ExtractFixedArray(values, 0, oldCapacity, newCapacity, PromiseHole);
    }
  } else
    deferred {
      // If remainingElementsCount.[[Value]] is 0, then
      //     Let valuesArray be CreateArrayFromList(values).
      //     Perform ? Call(resultCapability.[[Resolve]], undefined,
      //                    « valuesArray »).
      const arrayMap =
          *NativeContextSlot(
          nativeContext, ContextSlot::JS_ARRAY_PACKED_ELEMENTS_MAP_INDEX);

      // After this point, values escapes to user code. Clear the slot.
      *valuesRef = kEmptyFixedArray;

      const valuesArray = NewJSArray(arrayMap, values);
      Call(nativeContext, UnsafeCast<JSAny>(resolve), Undefined, valuesArray);
    }

  // Return resultCapability.[[Promise]].
  return promise;
}

transitioning macro GeneratePromiseAll<F1: type, F2: type>(
    implicit context: Context)(receiver: JSAny, iterable: JSAny,
    createResolveElementFunctor: F1, createRejectElementFunctor: F2,
    message: constexpr string): JSAny {
  const nativeContext = LoadNativeContext(context);
  // Let C be the this value.
  // If Type(C) is not Object, throw a TypeError exception.
  const receiver = Cast<JSReceiver>(receiver)
      otherwise ThrowTypeError(MessageTemplate::kCalledOnNonObject, message);

  // Let promiseCapability be ? NewPromiseCapability(C).
  // Don't fire debugEvent so that forwarding the rejection through all does
  // not trigger redundant ExceptionEvents
  const capability = NewPromiseCapability(receiver, False);

  // NewPromiseCapability guarantees that receiver is Constructor.
  dcheck(Is<Constructor>(receiver));
  const constructor = UnsafeCast<Constructor>(receiver);

  try {
    // Let promiseResolve be GetPromiseResolve(C).
    // IfAbruptRejectPromise(promiseResolve, promiseCapability).
    const promiseResolveFunction =
        GetPromiseResolve(nativeContext, constructor);

    // Let iterator be GetIterator(iterable).
    // IfAbruptRejectPromise(iterator, promiseCapability).
    let i = iterator::GetIterator(iterable);

    // Let result be PerformPromiseAll(iteratorRecord, C,
    // promiseCapability). If result is an abrupt completion, then
    //   If iteratorRecord.[[Done]] is false, let result be
    //       IteratorClose(iterator, result).
    //    IfAbruptRejectPromise(result, promiseCapability).
    return PerformPromiseAll(
        nativeContext, i, constructor, capability, promiseResolveFunction,
        createResolveElementFunctor, createRejectElementFunctor)
        otherwise Reject;
  } catch (e, _message) deferred {
    goto Reject(e);
  } label Reject(e: JSAny) deferred {
    const reject = UnsafeCast<JSAny>(capability.reject);
    Call(context, reject, Undefined, e);
    return capability.promise;
  }
}

// ES#sec-promise.all
transitioning javascript builtin PromiseAll(
    js-implicit context: Context, receiver: JSAny)(iterable: JSAny): JSAny {
  return GeneratePromiseAll(
      receiver, iterable, PromiseAllResolveElementFunctor{},
      PromiseAllRejectElementFunctor{}, 'Promise.all');
}

// ES#sec-promise.allsettled
// Promise.allSettled ( iterable )
transitioning javascript builtin PromiseAllSettled(
    js-implicit context: Context, receiver: JSAny)(iterable: JSAny): JSAny {
  return GeneratePromiseAll(
      receiver, iterable, PromiseAllSettledResolveElementFunctor{},
      PromiseAllSettledRejectElementFunctor{}, 'Promise.allSettled');
}

extern macro MakeFixedArrayCOW(FixedArray): void;
}
```