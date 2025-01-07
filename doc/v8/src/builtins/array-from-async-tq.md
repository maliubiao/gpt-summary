Response: Let's break down the thought process for analyzing this Torque code.

1. **Understand the Goal:** The first step is to recognize that this code implements `Array.fromAsync` in V8's internals using Torque. The core functionality is converting an asynchronous iterable or an array-like object into a Promise that resolves with a new Array.

2. **Identify Key Structures:**  Scan the code for major building blocks:
    * **Namespaces and Constants:**  `namespace array`, `kArrayFromAsync`,  `ArrayFromAsyncLabels`. These provide context and categorize the code.
    * **Macros:** `ArrayFromAsyncAwaitPoint`, `RejectArrayFromAsyncPromise`. These are reusable code patterns for handling asynchronous operations and promise rejections. Recognizing them as macros is important – they're code generation mechanisms.
    * **Data Structures (Structs):** `ArrayFromAsyncIterableResumeState`, `ArrayFromAsyncArrayLikeResumeState`. These hold the state of the asynchronous operations.
    * **Context Types:** `ArrayFromAsyncIterableResolveContext`, `ArrayFromAsyncArrayLikeResolveContext`. These are specialized `FunctionContext` objects holding all the necessary variables for the asynchronous operations. Pay attention to the `Slot` declarations within these – they represent the variables stored in the context.
    * **Enums:** `ArrayFromAsyncIterableResolveContextSlots`, `ArrayFromAsyncArrayLikeResolveContextSlots`. These define the offsets for the slots within the context objects.
    * **Builtin Functions:** `ArrayFromAsyncIterableOnFulfilled`, `ArrayFromAsyncIterableOnRejected`, `ArrayFromAsyncArrayLikeOnFulfilled`, `ArrayFromAsyncArrayLikeOnRejected`, `ArrayFromAsync`. These are the core functions called from JavaScript or other internal V8 code.

3. **Trace Execution Paths (High-Level):**  Notice the two main paths: one for iterables (using `@@asyncIterator` or falling back to `@@iterator` with async-from-sync conversion) and one for array-like objects. The `ArrayFromAsync` builtin function is the entry point and decides which path to take.

4. **Dive into the Iterable Path:**
    * **`CreateArrayFromIterableAsynchronously`:** This macro contains the main loop for processing asynchronous iterables. Observe the `resumeState` and how it's used to track progress through the different steps defined by `ArrayFromAsyncLabels`.
    * **Asynchronous Handling:**  The `ArrayFromAsyncIterableAwaitPoint` macro is crucial. It saves the current state and sets up the promise `then` handlers (`ArrayFromAsyncIterableOnFulfilled` and `ArrayFromAsyncIterableOnRejected`) to resume execution later.
    * **Mapping:**  Notice the logic for applying the optional `mapfn`.
    * **Error Handling:** The `try...catch` blocks and `ArrayFromAsyncAsyncIteratorCloseOnException` handle potential errors during iteration and ensure the iterator is closed properly.

5. **Dive into the Array-like Path:**
    * **`CreateArrayFromArrayLikeAsynchronously`:** This macro is similar to the iterable version but iterates based on the `length` property of the array-like object.
    * **Asynchronous Handling:**  Again, `ArrayFromAsyncArrayLikeAwaitPoint` handles the asynchronous parts.
    * **Mapping:** The mapping logic is similar to the iterable case.
    * **Error Handling:** A `try...catch` handles potential errors.

6. **Analyze the `ArrayFromAsync` Builtin:**
    * **Argument Handling:** It retrieves the `items`, `mapfn`, and `thisArg`.
    * **Promise Creation:** It creates a new Promise.
    * **Path Selection:** The core logic here is checking for `@@asyncIterator` and `@@iterator` to determine if the input is an async iterable, a sync iterable, or array-like.
    * **Context Creation:** It creates the appropriate context object (`ArrayFromAsyncIterableResolveContext` or `ArrayFromAsyncArrayLikeResolveContext`) and initializes it.
    * **Initiation:** It calls the appropriate "create and start" macro (`CreateArrayFromIterableAsynchronously` or `CreateArrayFromArrayLikeAsynchronously`).
    * **Error Handling:** A top-level `try...catch` handles immediate errors during setup.

7. **Connect to JavaScript:**
    * **Core Functionality:** `Array.fromAsync()` in JavaScript is directly implemented by this code.
    * **Examples:**  Think about how `Array.fromAsync` is used with async generators, async iterators, and array-like objects. This helps solidify understanding.

8. **Identify Potential Errors:** Look for places where things could go wrong:
    * **Non-callable `mapfn`:** Explicitly checked.
    * **Iterator `next` method returning non-objects:** Checked.
    * **Errors during asynchronous operations:** Handled by promise rejections.
    * **Exceptions during iterator closing:** Handled.

9. **Structure the Explanation:** Organize the findings into a logical flow:
    * **Overall Function:** Start with the high-level purpose.
    * **Relationship to JavaScript:** Explain the direct connection.
    * **Core Logic:** Detail the iterable and array-like paths separately.
    * **Code Logic Inference:**  Provide input/output examples for both paths, focusing on the asynchronous nature.
    * **Common Errors:** Give concrete JavaScript examples of errors.

10. **Refine and Review:**  Read through the explanation, ensuring clarity, accuracy, and completeness. Double-check any assumptions or interpretations. For instance, initially, one might overlook the `CreateAsyncFromSyncIterator` part, but careful reading reveals it.

This methodical approach, starting with the big picture and progressively drilling down into the details, is crucial for understanding complex code like this. Paying attention to data structures, control flow, and error handling is key. Connecting the internal implementation to the corresponding JavaScript API helps to solidify the understanding.
这个v8 torque文件 `v8/src/builtins/array-from-async.tq` 实现了 ECMAScript 提议中的 `Array.fromAsync` 方法。这个方法允许从异步可迭代对象（async iterables）或类数组对象异步地创建一个新的 `Array` 实例。

以下是该文件的功能归纳：

**主要功能:**

1. **实现 `Array.fromAsync`:**  这是该文件的核心目标。它定义了 `ArrayFromAsync` 这个 torque 内置函数，该函数在 V8 引擎中作为 `Array.fromAsync` 的实现。
2. **处理异步迭代器 (Async Iterables):**  代码包含处理异步迭代器的逻辑。它会获取异步迭代器的 `next()` 方法，并使用 `await` 来等待每次迭代的结果。
3. **处理同步迭代器 (Sync Iterables):** 如果输入不是异步可迭代对象，代码会尝试将其视为同步可迭代对象，并使用 `CreateAsyncFromSyncIterator` 将其转换为异步迭代器进行处理。
4. **处理类数组对象 (Array-like Objects):** 如果输入既不是异步可迭代对象也不是同步可迭代对象，代码会将其视为类数组对象。它会获取其 `length` 属性，并异步地获取每个索引对应的值。
5. **可选的 `mapfn` 功能:**  `Array.fromAsync` 接受一个可选的 `mapfn` 函数作为第二个参数。代码实现了在异步获取每个元素后应用 `mapfn` 的逻辑。
6. **Promise 的使用:** `Array.fromAsync` 返回一个 `Promise`。代码中使用了 V8 内部的 Promise API 来管理异步操作和最终结果。
7. **错误处理:** 代码包含了用于处理异步操作中可能发生的错误的机制，例如迭代器抛出异常或 `mapfn` 调用失败。
8. **状态管理:**  为了处理异步操作，代码使用了 `FunctionContext` 和 `Slot` 来存储和恢复执行状态，例如当前的迭代步骤、已等待的值和当前的索引。
9. **使用计数器:** 代码中使用了 `UseCounterFeature` 来统计 `Array.fromAsync` 的使用情况。

**与 Javascript 功能的关系和示例:**

`Array.fromAsync` 是 JavaScript 中用于异步创建数组的方法。它与 `Array.from` 类似，但可以处理异步产生值的源。

**JavaScript 示例:**

```javascript
async function* asyncGenerator() {
  yield Promise.resolve(1);
  yield 2;
  yield Promise.resolve(3);
}

async function main() {
  const arr1 = await Array.fromAsync(asyncGenerator());
  console.log(arr1); // 输出: [1, 2, 3]

  const arr2 = await Array.fromAsync(Promise.resolve([4, 5, 6]));
  console.log(arr2); // 输出: [ [Promise, Promise], [Promise, Promise], [Promise, Promise] ]
                      // 注意: 这里因为 Promise.resolve([4, 5, 6]) 本身不是一个异步可迭代对象，
                      //      所以会被当做一个包含一个 Promise 的类数组对象处理。

  const arr3 = await Array.fromAsync(asyncGenerator(), (x) => x * 2);
  console.log(arr3); // 输出: [2, 4, 6]

  const arrayLike = { length: 3, 0: Promise.resolve('a'), 1: 'b', 2: Promise.resolve('c') };
  const arr4 = await Array.fromAsync(arrayLike);
  console.log(arr4); // 输出: ['a', 'b', 'c']
}

main();
```

**代码逻辑推理 (假设输入与输出):**

**场景 1: 输入是异步生成器，没有 `mapfn`**

**假设输入:**
```javascript
async function* inputGenerator() {
  yield 1;
  await Promise.resolve(); // 模拟异步延迟
  yield 2;
}
```

**执行过程 (简化):**

1. `ArrayFromAsync` 被调用，识别输入是异步可迭代对象。
2. 创建一个 Promise 用于返回结果。
3. 获取异步生成器的迭代器。
4. 循环调用迭代器的 `next()` 方法，并 `await` 其结果。
5. 将每次迭代得到的值添加到新创建的数组中。
6. 当迭代完成时，Promise 被 resolve，并将包含 `[1, 2]` 的数组作为结果传递。

**假设输出:** `Promise` resolve 为 `[1, 2]`

**场景 2: 输入是类数组对象，带有 `mapfn`**

**假设输入:**
```javascript
const inputLikeArray = { 0: Promise.resolve(5), 1: 10, length: 2 };
const mapFn = (x) => x * 2;
```

**执行过程 (简化):**

1. `ArrayFromAsync` 被调用，识别输入是类数组对象。
2. 创建一个 Promise 用于返回结果。
3. 获取类数组对象的 `length` (为 2)。
4. 循环从索引 0 到 `length - 1` 获取属性值。
5. 对每个属性值进行 `await` 操作 (如果它是 Promise)。
6. 将 `await` 后的值传递给 `mapFn` 进行处理。
7. 将 `mapFn` 的返回值添加到新创建的数组中。
8. 当所有属性都处理完毕后，Promise 被 resolve，并将包含 `[10, 20]` 的数组作为结果传递。

**假设输出:** `Promise` resolve 为 `[10, 20]`

**用户常见的编程错误:**

1. **将同步可迭代对象误认为异步可迭代对象:**  用户可能会认为所有返回 Promise 的迭代器都是异步迭代器，但实际上只有实现了 `Symbol.asyncIterator` 方法的对象才是真正的异步迭代器。如果将一个返回 Promise 的普通迭代器传递给 `Array.fromAsync`，其行为可能不是用户期望的（例如，Promise 对象本身会被放入数组）。

   ```javascript
   function* syncGeneratorReturningPromises() {
     yield Promise.resolve(1);
     yield Promise.resolve(2);
   }

   async function example() {
     const arr = await Array.fromAsync(syncGeneratorReturningPromises());
     console.log(arr); // 输出: [Promise {<pending>}, Promise {<pending>}]
                      //  而不是预期的 [1, 2]
   }
   ```

2. **`mapfn` 不是一个函数:** 如果传递给 `Array.fromAsync` 的 `mapfn` 参数不是一个函数，将会抛出 `TypeError`。

   ```javascript
   async function* asyncGen() {
     yield 1;
   }

   async function example() {
     try {
       await Array.fromAsync(asyncGen(), 'not a function');
     } catch (error) {
       console.error(error); // 输出: TypeError: 'not a function' is not a function
     }
   }
   ```

3. **异步迭代器或类数组对象的值解析失败:** 如果异步迭代器 `next()` 方法返回的 Promise 被 rejected，或者类数组对象的属性值是 rejected 的 Promise，`Array.fromAsync` 返回的 Promise 也会被 rejected。

   ```javascript
   async function* failingGenerator() {
     yield Promise.reject(new Error("Something went wrong"));
   }

   async function example() {
     try {
       await Array.fromAsync(failingGenerator());
     } catch (error) {
       console.error(error); // 输出: Error: Something went wrong
     }
   }
   ```

4. **忘记 `await` 结果:**  `Array.fromAsync` 返回一个 Promise，用户需要使用 `await` 关键字或者 `.then()` 方法来获取最终的数组结果。如果忘记等待，将得到一个 Promise 对象而不是数组。

   ```javascript
   async function* asyncGen() {
     yield 1;
   }

   async function example() {
     const promise = Array.fromAsync(asyncGen());
     console.log(promise); // 输出: Promise {<pending>}
     const arr = await promise;
     console.log(arr);     // 输出: [1]
   }
   ```

理解这些常见的错误可以帮助开发者更好地使用 `Array.fromAsync` 并避免潜在的问题。这个 Torque 代码文件正是 V8 引擎为了高效、正确地实现这个新的 JavaScript 功能而编写的底层实现。

Prompt: 
```
这是目录为v8/src/builtins/array-from-async.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

namespace array {

const kArrayFromAsync: constexpr UseCounterFeature
    generates 'v8::Isolate::kArrayFromAsync';

extern enum ArrayFromAsyncLabels extends uint31
    constexpr 'ArrayBuiltins::ArrayFromAsyncLabels' {
  kGetIteratorStep,
  kCheckIteratorValueAndMapping,
  kIteratorMapping,
  kGetIteratorValueWithMapping,
  kAddIteratorValueToTheArray,
  kGetArrayLikeValue,
  kCheckArrayLikeValueAndMapping,
  kGetArrayLikeValueWithMapping,
  kAddArrayLikeValueToTheArray,
  kDoneAndResolvePromise,
  kCloseAsyncIterator,
  kRejectPromise
}

transitioning macro ArrayFromAsyncAwaitPoint<T : type extends FunctionContext>(
    implicit context: Context)(resolveContext: T, stepSlot: Slot<T, Smi>,
    promiseFunSlot: Slot<T, JSReceiver>,
    resolveSlot: Slot<T, Undefined|JSFunction>,
    rejectSlot: Slot<T, Undefined|JSFunction>, step: ArrayFromAsyncLabels,
    value: JSAny): JSAny {
  *ContextSlot(resolveContext, stepSlot) = SmiTag<ArrayFromAsyncLabels>(step);

  const promiseFun = *ContextSlot(resolveContext, promiseFunSlot);
  const resolve = *ContextSlot(resolveContext, resolveSlot);
  const reject = *ContextSlot(resolveContext, rejectSlot);

  const resultPromise = promise::PromiseResolve(promiseFun, value);

  promise::PerformPromiseThenImpl(
      UnsafeCast<JSPromise>(resultPromise), resolve, reject, Undefined);
  return Undefined;
}

// This macro reject the promise if any exception occurs in the execution of
// the asynchronous code.
transitioning macro
RejectArrayFromAsyncPromise<T : type extends FunctionContext>(
    implicit context: Context)(resolveContext: T, errorSlot: Slot<T, JSAny>,
    promiseSlot: Slot<T, JSPromise>): JSAny {
  const error = *ContextSlot(resolveContext, errorSlot);
  const promise = *ContextSlot(resolveContext, promiseSlot);

  return promise::RejectPromise(promise, error, False);
}

// --- Iterable path

struct ArrayFromAsyncIterableResumeState {
  step: ArrayFromAsyncLabels;
  awaitedValue: JSAny;
  index: Smi;
}

type ArrayFromAsyncIterableResolveContext extends FunctionContext;
extern enum ArrayFromAsyncIterableResolveContextSlots extends intptr
    constexpr 'ArrayBuiltins::ArrayFromAsyncIterableResolveContextSlots' {
  kArrayFromAsyncIterableResolveResumeStateStepSlot:
      Slot<ArrayFromAsyncIterableResolveContext, Smi>,
  kArrayFromAsyncIterableResolveResumeStateAwaitedValueSlot:
      Slot<ArrayFromAsyncIterableResolveContext, JSAny>,
  kArrayFromAsyncIterableResolveResumeStateIndexSlot:
      Slot<ArrayFromAsyncIterableResolveContext, Smi>,
  kArrayFromAsyncIterableResolvePromiseSlot:
      Slot<ArrayFromAsyncIterableResolveContext, JSPromise>,
  kArrayFromAsyncIterableResolvePromiseFunctionSlot:
      Slot<ArrayFromAsyncIterableResolveContext, JSReceiver>,
  kArrayFromAsyncIterableResolveOnFulfilledFunctionSlot:
      Slot<ArrayFromAsyncIterableResolveContext, JSFunction|Undefined>,
  kArrayFromAsyncIterableResolveOnRejectedFunctionSlot:
      Slot<ArrayFromAsyncIterableResolveContext, JSFunction|Undefined>,
  kArrayFromAsyncIterableResolveResultArraySlot:
      Slot<ArrayFromAsyncIterableResolveContext, JSReceiver>,
  kArrayFromAsyncIterableResolveIteratorSlot:
      Slot<ArrayFromAsyncIterableResolveContext, JSReceiver>,
  kArrayFromAsyncIterableResolveNextMethodSlot:
      Slot<ArrayFromAsyncIterableResolveContext, JSAny>,
  kArrayFromAsyncIterableResolveErrorSlot:
      Slot<ArrayFromAsyncIterableResolveContext, JSAny>,
  kArrayFromAsyncIterableResolveMapfnSlot:
      Slot<ArrayFromAsyncIterableResolveContext, JSAny>,
  kArrayFromAsyncIterableResolveThisArgSlot:
      Slot<ArrayFromAsyncIterableResolveContext, JSAny>,
  kArrayFromAsyncIterableResolveLength
}

extern macro AllocateRootFunctionWithContext(
    constexpr intptr, FunctionContext, NativeContext): JSFunction;

const kArrayFromAsyncIterableOnFulfilledSharedFun: constexpr intptr
    generates 'RootIndex::kArrayFromAsyncIterableOnFulfilledSharedFun';
const kArrayFromAsyncIterableOnRejectedSharedFun: constexpr intptr
    generates 'RootIndex::kArrayFromAsyncIterableOnRejectedSharedFun';

macro CreateArrayFromAsyncIterableResolveContext(
    implicit context: Context)(resumeState: ArrayFromAsyncIterableResumeState,
    promise: JSPromise, promiseFun: JSReceiver, iterator: JSReceiver,
    next: JSAny, arr: JSReceiver, error: JSAny, mapfn: JSAny, thisArg: JSAny,
    nativeContext: NativeContext): ArrayFromAsyncIterableResolveContext {
  const resolveContext = %RawDownCast<ArrayFromAsyncIterableResolveContext>(
      AllocateSyntheticFunctionContext(
          nativeContext,
          ArrayFromAsyncIterableResolveContextSlots::
              kArrayFromAsyncIterableResolveLength));
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveResumeStateStepSlot,
      SmiTag<ArrayFromAsyncLabels>(resumeState.step));
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveResumeStateAwaitedValueSlot,
      resumeState.awaitedValue);
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveResumeStateIndexSlot,
      resumeState.index);
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolvePromiseSlot,
      promise);
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolvePromiseFunctionSlot,
      promiseFun);
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveOnFulfilledFunctionSlot,
      AllocateRootFunctionWithContext(
          kArrayFromAsyncIterableOnFulfilledSharedFun, resolveContext,
          nativeContext));
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveOnRejectedFunctionSlot,
      AllocateRootFunctionWithContext(
          kArrayFromAsyncIterableOnRejectedSharedFun, resolveContext,
          nativeContext));
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveResultArraySlot,
      arr);
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveIteratorSlot,
      iterator);
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveNextMethodSlot,
      next);
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveErrorSlot,
      error);
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveMapfnSlot,
      mapfn);
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveThisArgSlot,
      thisArg);
  return resolveContext;
}

macro GetIteratorRecordFromArrayFromAsyncIterableResolveContext(
    context: ArrayFromAsyncIterableResolveContext): iterator::IteratorRecord {
  const iterator = *ContextSlot(
      context,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveIteratorSlot);

  const nextMethod = *ContextSlot(
      context,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveNextMethodSlot);

  return iterator::IteratorRecord{object: iterator, next: nextMethod};
}

transitioning macro CreateArrayFromIterableAsynchronously(
    context: ArrayFromAsyncIterableResolveContext): JSAny {
  try {
    const fastIteratorResultMap = GetIteratorResultMap();

    const mapfn = *ContextSlot(
        context,
        ArrayFromAsyncIterableResolveContextSlots::
            kArrayFromAsyncIterableResolveMapfnSlot);

    const thisArg = *ContextSlot(
        context,
        ArrayFromAsyncIterableResolveContextSlots::
            kArrayFromAsyncIterableResolveThisArgSlot);

    const arr = *ContextSlot(
        context,
        ArrayFromAsyncIterableResolveContextSlots::
            kArrayFromAsyncIterableResolveResultArraySlot);

    let resumeState = ArrayFromAsyncIterableResumeState{
      step: SmiUntag<ArrayFromAsyncLabels>(
          %RawDownCast<SmiTagged<ArrayFromAsyncLabels>>(*ContextSlot(
              context,
              ArrayFromAsyncIterableResolveContextSlots::
                  kArrayFromAsyncIterableResolveResumeStateStepSlot))),
      awaitedValue: *ContextSlot(
          context,
          ArrayFromAsyncIterableResolveContextSlots::
              kArrayFromAsyncIterableResolveResumeStateAwaitedValueSlot),
      index: *ContextSlot(
          context,
          ArrayFromAsyncIterableResolveContextSlots::
              kArrayFromAsyncIterableResolveResumeStateIndexSlot)
    };

    let mappedValue: JSAny = Undefined;
    let nextValue: JSAny = Undefined;

    // TODO(v8:14290): Replace `if/else` with `switch/case` when the support
    // for `switch` is added.

    while (true) {
      if (resumeState.step == ArrayFromAsyncLabels::kGetIteratorStep) {
        const iteratorRecord =
            GetIteratorRecordFromArrayFromAsyncIterableResolveContext(context);
        let next: JSAny;
        // https://github.com/tc39/proposal-array-from-async/issues/33#issuecomment-1279296963
        //    3. Let nextResult be ? Call(iteratorRecord.[[NextMethod]],
        //    iteratorRecord.[[Iterator]]).
        //    4. Set nextResult to ? Await(nextResult).
        next = Call(context, iteratorRecord.next, iteratorRecord.object);

        return ArrayFromAsyncIterableAwaitPoint(
            context, ArrayFromAsyncLabels::kCheckIteratorValueAndMapping, next);
      } else if (
          resumeState.step ==
          ArrayFromAsyncLabels::kCheckIteratorValueAndMapping) {
        //    5. If nextResult is not an Object, throw a TypeError exception.
        const nextJSReceiver = Cast<JSReceiver>(resumeState.awaitedValue)
            otherwise ThrowTypeError(
            MessageTemplate::kIteratorResultNotAnObject, 'Array.fromAsync');

        try {
          //    6. Let done be ? IteratorComplete(nextResult).
          iterator::IteratorComplete(nextJSReceiver, fastIteratorResultMap)
              otherwise Done;

          //    8. Let nextValue be ? IteratorValue(nextResult).
          nextValue =
              iterator::IteratorValue(nextJSReceiver, fastIteratorResultMap);

          // When mapfn is not undefined, it is guaranteed to be callable as
          // checked upon entry.
          const mapping: bool = (mapfn != Undefined);

          //    9. If mapping is true, then
          if (mapping) {
            resumeState.step = ArrayFromAsyncLabels::kIteratorMapping;
          } else {
            //    10. Else, let mappedValue be nextValue.
            mappedValue = nextValue;
            resumeState.step =
                ArrayFromAsyncLabels::kAddIteratorValueToTheArray;
          }
        } label Done {
          //    7. If done is true,
          //       a. Perform ? Set(A, "length", 𝔽(k), true).
          //       b. Return Completion Record { [[Type]]: return, [[Value]]: A,
          //       [[Target]]: empty }.
          resumeState.step = ArrayFromAsyncLabels::kDoneAndResolvePromise;
        }
      } else if (resumeState.step == ArrayFromAsyncLabels::kIteratorMapping) {
        //      a. Let mappedValue be Call(mapfn, thisArg, « nextValue, 𝔽(k)
        //      »).
        //      b. IfAbruptCloseAsyncIterator(mappedValue,
        //      iteratorRecord).
        const mapResult = Call(
            context, UnsafeCast<Callable>(mapfn), thisArg, nextValue,
            resumeState.index);

        //      c. Set mappedValue to Await(mappedValue).
        //      d. IfAbruptCloseAsyncIterator(mappedValue, iteratorRecord).
        return ArrayFromAsyncIterableAwaitPoint(
            context, ArrayFromAsyncLabels::kGetIteratorValueWithMapping,
            mapResult);
      } else if (
          resumeState.step ==
          ArrayFromAsyncLabels::kGetIteratorValueWithMapping) {
        mappedValue = resumeState.awaitedValue;
        resumeState.step = ArrayFromAsyncLabels::kAddIteratorValueToTheArray;
      } else if (
          resumeState.step ==
          ArrayFromAsyncLabels::kAddIteratorValueToTheArray) {
        //    11. Let defineStatus be CreateDataPropertyOrThrow(A, Pk,
        //    mappedValue).
        //    12. If defineStatus is an abrupt completion, return ?
        //    AsyncIteratorClose(iteratorRecord, defineStatus).
        FastCreateDataProperty(arr, resumeState.index, mappedValue);

        // 13. Set k to k + 1.
        resumeState.index++;

        *ContextSlot(
            context,
            ArrayFromAsyncIterableResolveContextSlots::
                kArrayFromAsyncIterableResolveResumeStateIndexSlot) =
            resumeState.index;

        resumeState.step = ArrayFromAsyncLabels::kGetIteratorStep;
      } else if (
          resumeState.step == ArrayFromAsyncLabels::kDoneAndResolvePromise) {
        array::SetPropertyLength(arr, resumeState.index);
        const promise = *ContextSlot(
            context,
            ArrayFromAsyncIterableResolveContextSlots::
                kArrayFromAsyncIterableResolvePromiseSlot);

        promise::ResolvePromise(promise, arr);
        return Undefined;
      } else if (
          resumeState.step == ArrayFromAsyncLabels::kCloseAsyncIterator) {
        resumeState.step = ArrayFromAsyncLabels::kRejectPromise;

        const iteratorRecord =
            GetIteratorRecordFromArrayFromAsyncIterableResolveContext(context);
        try {
          ArrayFromAsyncAsyncIteratorCloseOnException(iteratorRecord)
              otherwise RejectPromise;
          return Undefined;
        } label RejectPromise {
          // Do nothing so the codeflow continues to the kRejectPromise label.
        }
      } else if (resumeState.step == ArrayFromAsyncLabels::kRejectPromise) {
        return RejectArrayFromAsyncPromise<
            ArrayFromAsyncIterableResolveContext>(
            context,
            ArrayFromAsyncIterableResolveContextSlots::
                kArrayFromAsyncIterableResolveErrorSlot,
            ArrayFromAsyncIterableResolveContextSlots::
                kArrayFromAsyncIterableResolvePromiseSlot);
      }
    }
  } catch (e, _message) {
    *ContextSlot(
        context,
        ArrayFromAsyncIterableResolveContextSlots::
            kArrayFromAsyncIterableResolveErrorSlot) = e;

    const iteratorRecord =
        GetIteratorRecordFromArrayFromAsyncIterableResolveContext(context);
    try {
      ArrayFromAsyncAsyncIteratorCloseOnException(iteratorRecord)
          otherwise RejectPromise;
    } label RejectPromise {
      return RejectArrayFromAsyncPromise<ArrayFromAsyncIterableResolveContext>(
          context,
          ArrayFromAsyncIterableResolveContextSlots::
              kArrayFromAsyncIterableResolveErrorSlot,
          ArrayFromAsyncIterableResolveContextSlots::
              kArrayFromAsyncIterableResolvePromiseSlot);
    }
  }
  return Undefined;
}

transitioning macro ArrayFromAsyncIterableAwaitPoint(
    context: ArrayFromAsyncIterableResolveContext, step: ArrayFromAsyncLabels,
    value: JSAny): JSAny {
  return ArrayFromAsyncAwaitPoint<ArrayFromAsyncIterableResolveContext>(
      context,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveResumeStateStepSlot,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolvePromiseFunctionSlot,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveOnFulfilledFunctionSlot,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveOnRejectedFunctionSlot,
      step, value);
}

// `ArrayFromAsyncIterableOnFulfilled` is the callback function for the
// fulfilled case of the promise in `then` handler.
transitioning javascript builtin ArrayFromAsyncIterableOnFulfilled(
    js-implicit context: Context, receiver: JSAny, target: JSFunction)(
    result: JSAny): JSAny {
  const context = %RawDownCast<ArrayFromAsyncIterableResolveContext>(context);
  *ContextSlot(
      context,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveResumeStateAwaitedValueSlot) = result;

  return CreateArrayFromIterableAsynchronously(context);
}

// `ArrayFromAsyncIterableOnRejected` is the callback function for the rejected
// case of the promise in `then` handler.
transitioning javascript builtin ArrayFromAsyncIterableOnRejected(
    js-implicit context: Context, receiver: JSAny, target: JSFunction)(
    result: JSAny): JSAny {
  const context = %RawDownCast<ArrayFromAsyncIterableResolveContext>(context);

  *ContextSlot(
      context,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveResumeStateStepSlot) =
      SmiTag<ArrayFromAsyncLabels>(ArrayFromAsyncLabels::kCloseAsyncIterator);
  *ContextSlot(
      context,
      ArrayFromAsyncIterableResolveContextSlots::
          kArrayFromAsyncIterableResolveErrorSlot) = result;

  return CreateArrayFromIterableAsynchronously(context);
}

// This is the specialized implementation of `IfAbruptCloseAsyncIterator` for
// Array.fromAsync
// https://tc39.es/proposal-array-from-async/#sec-ifabruptcloseasynciterator
transitioning macro ArrayFromAsyncAsyncIteratorCloseOnException(
    implicit context: Context)(
    iterator: iterator::IteratorRecord): void labels RejectPromise {
  try {
    const context = %RawDownCast<ArrayFromAsyncIterableResolveContext>(context);
    // 3. Let innerResult be GetMethod(iterator, "return").
    const method = GetProperty(iterator.object, kReturnString);

    // 4. If innerResult.[[Type]] is normal, then
    //   a. Let return be innerResult.[[Value]].
    //   b. If return is undefined, return Completion(completion).
    if (method == Undefined || method == Null) {
      goto RejectPromise;
    }

    //   c. Set innerResult to Call(return, iterator).
    // If an exception occurs, the original exception remains bound
    const innerResult = Call(context, method, iterator.object);

    //   d. If innerResult.[[Type]] is normal, set innerResult to
    //   Completion(Await(innerResult.[[Value]])).
    const step = ArrayFromAsyncLabels::kRejectPromise;
    ArrayFromAsyncIterableAwaitPoint(context, step, innerResult);
  } catch (_e, _message) {
    // Swallow the exception.
  }

  // (5. If completion.[[Type]] is throw) return Completion(completion).
}

extern macro ArrayFromAsyncIterableOnFulfilledSharedFunConstant():
    SharedFunctionInfo;
extern macro ArrayFromAsyncIterableOnRejectedSharedFunConstant():
    SharedFunctionInfo;

// --- Array-like path

struct ArrayFromAsyncArrayLikeResumeState {
  step: ArrayFromAsyncLabels;
  awaitedValue: JSAny;
  len: Number;
  index: Smi;
}

type ArrayFromAsyncArrayLikeResolveContext extends FunctionContext;
extern enum ArrayFromAsyncArrayLikeResolveContextSlots extends intptr
    constexpr 'ArrayBuiltins::ArrayFromAsyncArrayLikeResolveContextSlots' {
  kArrayFromAsyncArrayLikeResolveResumeStateStepSlot:
      Slot<ArrayFromAsyncArrayLikeResolveContext, Smi>,
  kArrayFromAsyncArrayLikeResolveResumeStateAwaitedValueSlot:
      Slot<ArrayFromAsyncArrayLikeResolveContext, JSAny>,
  kArrayFromAsyncArrayLikeResolveResumeStateLenSlot:
      Slot<ArrayFromAsyncArrayLikeResolveContext, Number>,
  kArrayFromAsyncArrayLikeResolveResumeStateIndexSlot:
      Slot<ArrayFromAsyncArrayLikeResolveContext, Smi>,
  kArrayFromAsyncArrayLikeResolvePromiseSlot:
      Slot<ArrayFromAsyncArrayLikeResolveContext, JSPromise>,
  kArrayFromAsyncArrayLikeResolvePromiseFunctionSlot:
      Slot<ArrayFromAsyncArrayLikeResolveContext, JSReceiver>,
  kArrayFromAsyncArrayLikeResolveOnFulfilledFunctionSlot:
      Slot<ArrayFromAsyncArrayLikeResolveContext, JSFunction|Undefined>,
  kArrayFromAsyncArrayLikeResolveOnRejectedFunctionSlot:
      Slot<ArrayFromAsyncArrayLikeResolveContext, JSFunction|Undefined>,
  kArrayFromAsyncArrayLikeResolveResultArraySlot:
      Slot<ArrayFromAsyncArrayLikeResolveContext, JSReceiver>,
  kArrayFromAsyncArrayLikeResolveArrayLikeSlot:
      Slot<ArrayFromAsyncArrayLikeResolveContext, JSReceiver>,
  kArrayFromAsyncArrayLikeResolveErrorSlot:
      Slot<ArrayFromAsyncArrayLikeResolveContext, JSAny>,
  kArrayFromAsyncArrayLikeResolveMapfnSlot:
      Slot<ArrayFromAsyncArrayLikeResolveContext, JSAny>,
  kArrayFromAsyncArrayLikeResolveThisArgSlot:
      Slot<ArrayFromAsyncArrayLikeResolveContext, JSAny>,
  kArrayFromAsyncArrayLikeResolveLength
}

const kArrayFromAsyncArrayLikeOnFulfilledSharedFun: constexpr intptr
    generates 'RootIndex::kArrayFromAsyncArrayLikeOnFulfilledSharedFun';
const kArrayFromAsyncArrayLikeOnRejectedSharedFun: constexpr intptr
    generates 'RootIndex::kArrayFromAsyncArrayLikeOnRejectedSharedFun';

macro CreateArrayFromAsyncArrayLikeResolveContext(
    implicit context: Context)(resumeState: ArrayFromAsyncArrayLikeResumeState,
    promise: JSPromise, promiseFun: JSReceiver, arrayLike: JSReceiver,
    arr: JSReceiver, error: JSAny, mapfn: JSAny, thisArg: JSAny,
    nativeContext: NativeContext): ArrayFromAsyncArrayLikeResolveContext {
  const resolveContext = %RawDownCast<ArrayFromAsyncArrayLikeResolveContext>(
      AllocateSyntheticFunctionContext(
          nativeContext,
          ArrayFromAsyncArrayLikeResolveContextSlots::
              kArrayFromAsyncArrayLikeResolveLength));
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolveResumeStateStepSlot,
      SmiTag<ArrayFromAsyncLabels>(resumeState.step));
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolveResumeStateAwaitedValueSlot,
      resumeState.awaitedValue);
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolveResumeStateLenSlot,
      resumeState.len);
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolveResumeStateIndexSlot,
      resumeState.index);
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolvePromiseSlot,
      promise);
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolvePromiseFunctionSlot,
      promiseFun);
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolveOnFulfilledFunctionSlot,
      AllocateRootFunctionWithContext(
          kArrayFromAsyncArrayLikeOnFulfilledSharedFun, resolveContext,
          nativeContext));
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolveOnRejectedFunctionSlot,
      AllocateRootFunctionWithContext(
          kArrayFromAsyncArrayLikeOnRejectedSharedFun, resolveContext,
          nativeContext));
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolveResultArraySlot,
      arr);
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolveArrayLikeSlot,
      arrayLike);
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolveErrorSlot,
      error);
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolveMapfnSlot,
      mapfn);
  InitContextSlot(
      resolveContext,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolveThisArgSlot,
      thisArg);
  return resolveContext;
}

transitioning macro CreateArrayFromArrayLikeAsynchronously(
    context: ArrayFromAsyncArrayLikeResolveContext): JSAny {
  try {
    const mapfn = *ContextSlot(
        context,
        ArrayFromAsyncArrayLikeResolveContextSlots::
            kArrayFromAsyncArrayLikeResolveMapfnSlot);

    const thisArg = *ContextSlot(
        context,
        ArrayFromAsyncArrayLikeResolveContextSlots::
            kArrayFromAsyncArrayLikeResolveThisArgSlot);

    const arr = *ContextSlot(
        context,
        ArrayFromAsyncArrayLikeResolveContextSlots::
            kArrayFromAsyncArrayLikeResolveResultArraySlot);

    let resumeState = ArrayFromAsyncArrayLikeResumeState{
      step: SmiUntag<ArrayFromAsyncLabels>(
          %RawDownCast<SmiTagged<ArrayFromAsyncLabels>>(*ContextSlot(
              context,
              ArrayFromAsyncArrayLikeResolveContextSlots::
                  kArrayFromAsyncArrayLikeResolveResumeStateStepSlot))),
      awaitedValue: *ContextSlot(
          context,
          ArrayFromAsyncArrayLikeResolveContextSlots::
              kArrayFromAsyncArrayLikeResolveResumeStateAwaitedValueSlot),
      len: *ContextSlot(
          context,
          ArrayFromAsyncArrayLikeResolveContextSlots::
              kArrayFromAsyncArrayLikeResolveResumeStateLenSlot),
      index: *ContextSlot(
          context,
          ArrayFromAsyncArrayLikeResolveContextSlots::
              kArrayFromAsyncArrayLikeResolveResumeStateIndexSlot)
    };

    let mappedValue: JSAny = Undefined;

    // TODO(v8:14290): Replace `if/else` with `switch/case` when the support
    // for `switch` is added.

    while (true) {
      if (resumeState.step == ArrayFromAsyncLabels::kGetArrayLikeValue) {
        const arrayLike = *ContextSlot(
            context,
            ArrayFromAsyncArrayLikeResolveContextSlots::
                kArrayFromAsyncArrayLikeResolveArrayLikeSlot);

        //   vii. Repeat, while k < len,
        //     1. Let Pk be ! ToString(𝔽(k)).
        if (resumeState.index < resumeState.len) {
          //     2. Let kValue be ? Get(arrayLike, Pk).
          const kValue = GetProperty(arrayLike, resumeState.index);

          //     3. Set kValue to ? Await(kValue).
          return ArrayFromAsyncArrayLikeAwaitPoint(
              context, ArrayFromAsyncLabels::kCheckArrayLikeValueAndMapping,
              kValue);
        }
        //   viii. Perform ? Set(A, "length", 𝔽(len), true).
        //   ix. Return Completion Record { [[Type]]: return, [[Value]]: A,
        //   [[Target]]: empty }.
        resumeState.step = ArrayFromAsyncLabels::kDoneAndResolvePromise;
      } else if (
          resumeState.step ==
          ArrayFromAsyncLabels::kCheckArrayLikeValueAndMapping) {
        // When mapfn is not undefined, it is guaranteed to be callable as
        // checked upon entry.
        const mapping: bool = (mapfn != Undefined);
        //    4. If mapping is true, then
        if (mapping) {
          resumeState.step =
              ArrayFromAsyncLabels::kGetArrayLikeValueWithMapping;
        } else {
          resumeState.step = ArrayFromAsyncLabels::kAddArrayLikeValueToTheArray;
        }
      } else if (
          resumeState.step ==
          ArrayFromAsyncLabels::kGetArrayLikeValueWithMapping) {
        //      a. Let mappedValue be ? Call(mapfn, thisArg, « kValue, 𝔽(k)
        //      »).
        //      b. Set mappedValue to ? Await(mappedValue).
        const mapResult = Call(
            context, UnsafeCast<Callable>(mapfn), thisArg,
            resumeState.awaitedValue, resumeState.index);
        return ArrayFromAsyncArrayLikeAwaitPoint(
            context, ArrayFromAsyncLabels::kAddArrayLikeValueToTheArray,
            mapResult);
      } else if (
          resumeState.step ==
          ArrayFromAsyncLabels::kAddArrayLikeValueToTheArray) {
        //    5. Else, let mappedValue be kValue.
        mappedValue = resumeState.awaitedValue;

        //    6. Perform ? CreateDataPropertyOrThrow(A, Pk, mappedValue).
        FastCreateDataProperty(arr, resumeState.index, mappedValue);

        resumeState.index++;

        *ContextSlot(
            context,
            ArrayFromAsyncArrayLikeResolveContextSlots::
                kArrayFromAsyncArrayLikeResolveResumeStateIndexSlot) =
            resumeState.index;

        resumeState.step = ArrayFromAsyncLabels::kGetArrayLikeValue;
      } else if (
          resumeState.step == ArrayFromAsyncLabels::kDoneAndResolvePromise) {
        array::SetPropertyLength(arr, resumeState.index);
        const promise = *ContextSlot(
            context,
            ArrayFromAsyncArrayLikeResolveContextSlots::
                kArrayFromAsyncArrayLikeResolvePromiseSlot);

        promise::ResolvePromise(promise, arr);
        return Undefined;
      } else if (resumeState.step == ArrayFromAsyncLabels::kRejectPromise) {
        return RejectArrayFromAsyncPromise<
            ArrayFromAsyncArrayLikeResolveContext>(
            context,
            ArrayFromAsyncArrayLikeResolveContextSlots::
                kArrayFromAsyncArrayLikeResolveErrorSlot,
            ArrayFromAsyncArrayLikeResolveContextSlots::
                kArrayFromAsyncArrayLikeResolvePromiseSlot);
      }
    }
  } catch (e, _message) {
    *ContextSlot(
        context,
        ArrayFromAsyncArrayLikeResolveContextSlots::
            kArrayFromAsyncArrayLikeResolveErrorSlot) = e;

    return RejectArrayFromAsyncPromise<ArrayFromAsyncArrayLikeResolveContext>(
        context,
        ArrayFromAsyncArrayLikeResolveContextSlots::
            kArrayFromAsyncArrayLikeResolveErrorSlot,
        ArrayFromAsyncArrayLikeResolveContextSlots::
            kArrayFromAsyncArrayLikeResolvePromiseSlot);
  }
  return Undefined;
}

transitioning macro ArrayFromAsyncArrayLikeAwaitPoint(
    context: ArrayFromAsyncArrayLikeResolveContext, step: ArrayFromAsyncLabels,
    value: JSAny): JSAny {
  return ArrayFromAsyncAwaitPoint<ArrayFromAsyncArrayLikeResolveContext>(
      context,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolveResumeStateStepSlot,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolvePromiseFunctionSlot,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolveOnFulfilledFunctionSlot,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolveOnRejectedFunctionSlot,
      step, value);
}

// `ArrayFromAsyncArrayLikeOnFulfilled` is the callback function for the
// fulfilled case of the promise in `then` handler.
transitioning javascript builtin ArrayFromAsyncArrayLikeOnFulfilled(
    js-implicit context: Context, receiver: JSAny, target: JSFunction)(
    result: JSAny): JSAny {
  const context = %RawDownCast<ArrayFromAsyncArrayLikeResolveContext>(context);
  *ContextSlot(
      context,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolveResumeStateAwaitedValueSlot) = result;

  return CreateArrayFromArrayLikeAsynchronously(context);
}

// `ArrayFromAsyncArrayLikeOnRejected` is the callback function for the rejected
// case of the promise in `then` handler.
transitioning javascript builtin ArrayFromAsyncArrayLikeOnRejected(
    js-implicit context: Context, receiver: JSAny, target: JSFunction)(
    result: JSAny): JSAny {
  const context = %RawDownCast<ArrayFromAsyncArrayLikeResolveContext>(context);

  *ContextSlot(
      context,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolveResumeStateStepSlot) =
      SmiTag<ArrayFromAsyncLabels>(ArrayFromAsyncLabels::kRejectPromise);
  *ContextSlot(
      context,
      ArrayFromAsyncArrayLikeResolveContextSlots::
          kArrayFromAsyncArrayLikeResolveErrorSlot) = result;

  return CreateArrayFromArrayLikeAsynchronously(context);
}

extern macro ArrayFromAsyncArrayLikeOnFulfilledSharedFunConstant():
    SharedFunctionInfo;
extern macro ArrayFromAsyncArrayLikeOnRejectedSharedFunConstant():
    SharedFunctionInfo;

// --- Array.fromAsync builtin

// https://tc39.es/proposal-array-from-async/#sec-array.fromAsync
// Array.fromAsync ( asyncItems [ , mapfn [ , thisArg ] ] )
// Since we do not have support for `await` in torque, we handled
// asynchronous execution flow manually in torque. More information
// is available in go/array-from-async-implementation.
transitioning javascript builtin ArrayFromAsync(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  IncrementUseCounter(context, SmiConstant(kArrayFromAsync));
  // 1. Let C be the this value.
  const c = HasBuiltinSubclassingFlag() ? receiver : GetArrayFunction();

  const items = arguments[0];
  const mapfn = arguments[1];
  const thisArg = arguments[2];

  // 2. Let promiseCapability be ! NewPromiseCapability(%Promise%).
  const promise = promise::NewJSPromise();

  const promiseFun = *NativeContextSlot(
      context, ContextSlot::PROMISE_FUNCTION_INDEX);

  // 3. Let fromAsyncClosure be a new Abstract Closure with no parameters that
  // captures C, mapfn, and thisArg and performs the following steps when
  // called:

  let usingAsyncIterator: JSAny = Undefined;
  let usingSyncIterator: JSAny = Undefined;

  try {
    if (mapfn != Undefined) {
      // i. If IsCallable(mapfn) is false, throw a TypeError exception.
      if (!Is<Callable>(mapfn)) deferred {
          ThrowTypeError(MessageTemplate::kCalledNonCallable, mapfn);
        }
    }

    try {
      //  c. Let usingAsyncIterator be ?
      //  GetMethod(asyncItems, @@asyncIterator).
      usingAsyncIterator = GetMethod(items, AsyncIteratorSymbolConstant())
          otherwise AsyncIteratorIsUndefined, AsyncIteratorNotCallable;
    } label AsyncIteratorIsUndefined {
      //  d. If usingAsyncIterator is undefined, then
      //    i. Let usingSyncIterator be ?
      //    GetMethod(asyncItems, @@iterator).

      usingSyncIterator = GetMethod(items, IteratorSymbolConstant())
          otherwise SyncIteratorIsUndefined, SyncIteratorNotCallable;
    } label SyncIteratorIsUndefined deferred {
      //  i. Else, (iteratorRecord is undefined)
      //   i. NOTE: asyncItems is neither an AsyncIterable nor an
      //   Iterable so assume it is an array-like object.
      //   ii. Let arrayLike be ! ToObject(asyncItems).
      const arrayLike = ToObject_Inline(context, items);

      //   iii. Let len be ? LengthOfArrayLike(arrayLike).
      const len = GetLengthProperty(arrayLike);

      // TODO(v8:13321): Allocate an array with PACKED elements kind for
      // fast-path rather than calling the constructor which creates an
      // array with HOLEY kind.

      let arr: JSReceiver;
      typeswitch (c) {
        case (c: Constructor): {
          //   iv. If IsConstructor(C) is
          //   true, then
          //     1. Let A be ? Construct(C, « 𝔽(len) »).
          arr = Construct(c, len);
        }
        case (JSAny): {
          //   v. Else,
          //     1. Let A be ? ArrayCreate(len).
          arr = ArrayCreate(len);
        }
      }

      //   vi. Let k be 0.
      // Will be done when creating resumeState later.

      let resumeState = ArrayFromAsyncArrayLikeResumeState{
        step: ArrayFromAsyncLabels::kGetArrayLikeValue,
        awaitedValue: Undefined,
        len: len,
        index: 0
      };

      const arrayLikeResolveContext =
          CreateArrayFromAsyncArrayLikeResolveContext(
              resumeState, promise, promiseFun, arrayLike, arr, Undefined,
              mapfn, thisArg, context);

      CreateArrayFromArrayLikeAsynchronously(arrayLikeResolveContext);
      return promise;
    } label SyncIteratorNotCallable(_value: JSAny)
    deferred {
      ThrowTypeError(
          MessageTemplate::kFirstArgumentIteratorSymbolNonCallable,
          'Array.fromAsync');
    } label AsyncIteratorNotCallable(_value: JSAny)
    deferred {
      ThrowTypeError(
          MessageTemplate::kFirstArgumentAsyncIteratorSymbolNonCallable,
          'Array.fromAsync');
    }

    //  e. Let iteratorRecord be undefined.
    //  f. If usingAsyncIterator is not undefined, then
    //     i. Set iteratorRecord to ? GetIterator(asyncItems, async,
    // usingAsyncIterator).
    //  g. Else if usingSyncIterator is not undefined, then
    //     i. Set iteratorRecord to ?
    // CreateAsyncFromSyncIterator(GetIterator(asyncItems, sync,
    // usingSyncIterator)).

    const iteratorRecord = (usingAsyncIterator != Undefined) ?
        iterator::GetIterator(items, usingAsyncIterator) :
        iterator::GetIteratorRecordAfterCreateAsyncFromSyncIterator(
            context, iterator::GetIterator(items, usingSyncIterator));

    let arr: JSReceiver;
    //  h. If iteratorRecord is not undefined, then
    typeswitch (c) {
      case (c: Constructor): {
        //  i. If IsConstructor(C) is true, then
        //    1. Let A be ? Construct(C).
        arr = Construct(c);
      }
      case (JSAny): {
        //  ii. Else,
        //    1. Let A be ! ArrayCreate(0).
        arr = ArrayCreate(0);
      }
    }

    let iterableResumeState = ArrayFromAsyncIterableResumeState{
      step: ArrayFromAsyncLabels::kGetIteratorStep,
      awaitedValue: Undefined,
      index: 0
    };

    const iterableResolveContext = CreateArrayFromAsyncIterableResolveContext(
        iterableResumeState, promise, promiseFun, iteratorRecord.object,
        iteratorRecord.next, arr, Undefined, mapfn, thisArg, context);

    CreateArrayFromIterableAsynchronously(iterableResolveContext);
    return promise;

  } catch (e, _message) {
    promise::RejectPromise(promise, e, False);
    return promise;
  }
}
}

"""

```