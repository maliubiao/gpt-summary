Response: Let's break down the thought process for analyzing this Torque code.

1. **Initial Understanding of the Context:** The first line is crucial: `v8/src/builtins/iterator.tq`. This tells us immediately we're in the V8 JavaScript engine's implementation, specifically dealing with *iterators*. The `.tq` extension signifies a Torque file, V8's internal language for implementing built-in functions.

2. **Scanning for Key Structures and Macros:** A quick scan reveals several important elements:
    * `struct IteratorRecord`: This likely represents the internal state of an iterator.
    * `extern macro ...`:  These are declarations of macros defined elsewhere. The names are very descriptive (e.g., `FastIterableToList`, `GetIteratorMethod`, `IteratorStep`, `IteratorValue`, `IteratorClose`). This suggests core iterator operations.
    * `transitioning macro ...`: Similar to `extern macro`, but these seem to be defined *within* this file.
    * `transitioning builtin ...`:  These are the actual built-in JavaScript functions being implemented (e.g., `GetIteratorWithFeedback`, `IteratorConstructor`, `IteratorPrototypeDispose`, `AsyncIteratorPrototypeAsyncDispose`). The "transitioning" keyword likely relates to V8's internal compilation pipeline.
    *  Mentions of TC39 proposals (e.g., "iterator helpers," "explicit resource management") provide high-level context about the features being implemented.

3. **Analyzing `IteratorRecord`:** This struct has two fields: `object` (a `JSReceiver`) and `next` (a `JSAny`). This aligns directly with the JavaScript iterator protocol, where an iterator is an object with a `next()` method. `object` is the iterator itself, and `next` is a reference to that method.

4. **Categorizing the Macros and Builtins:**  It's helpful to group related functions:
    * **Getting Iterators:** `GetIteratorMethod`, `GetIterator`, `GetIteratorWithFeedback`, `GetIteratorBaseline`. The "Feedback" and "Baseline" suffixes suggest optimizations or different execution paths.
    * **Iterating:** `IteratorStep`, `IteratorComplete`, `IteratorValue`. These are the fundamental actions of moving through an iterator.
    * **Converting to Lists/Arrays:** `FastIterableToList`, `IterableToList`, `StringListFromIterable`, `IterableToListWithSymbolLookup`, `IterableToFixedArrayWithSymbolLookupSlow`. This indicates functions for materializing iterators into concrete data structures.
    * **Closing Iterators:** `IteratorCloseOnException`, `IteratorClose`. These handle the optional `return()` method for cleanup.
    * **Async Iterators:** `CreateAsyncFromSyncIterator`, `CreateAsyncFromSyncIteratorBaseline`, `GetIteratorRecordAfterCreateAsyncFromSyncIterator`, `AsyncIteratorPrototypeAsyncDispose`. These are clearly related to asynchronous iteration.
    * **Iterator Class Implementation:** `IteratorConstructor`, `IteratorPrototypeGetToStringTag`, `IteratorPrototypeSetToStringTag`, `IteratorPrototypeGetConstructor`, `IteratorPrototypeSetConstructor`. These implement the `Iterator` constructor and its prototype properties, as defined in the "iterator helpers" proposal.
    * **Resource Management:** `IteratorPrototypeDispose`, `AsyncIteratorPrototypeAsyncDispose`. These relate to the "explicit resource management" proposal, enabling deterministic cleanup.

5. **Connecting to JavaScript:**  For each group of functions, try to relate them to concrete JavaScript examples. For instance:
    * `GetIterator`:  Think of `Symbol.iterator` and how it's used in `for...of` loops or when manually getting an iterator.
    * `IteratorStep`/`IteratorValue`: Relate these to calling `next()` on an iterator and accessing the `value` and `done` properties.
    * `IteratorClose`:  Imagine a generator function with a `finally` block or a resource that needs to be cleaned up.
    * `AsyncIteratorPrototypeAsyncDispose`:  Think of asynchronous iterators used with `using await` or manual disposal.

6. **Inferring Code Logic and Assumptions:**  Look for patterns and assumptions:
    * The frequent use of "Feedback" suggests V8 uses feedback mechanisms for optimization during iteration.
    * The existence of both synchronous and asynchronous iterator functions points to the separate handling of these cases.
    * The `IteratorRecord` struct highlights the importance of the `next` method.
    * The `IteratorClose` and `IteratorCloseOnException` functions demonstrate error handling during iteration.

7. **Identifying Potential User Errors:** Consider how developers might misuse iterators, leading to errors that these builtins handle or prevent:
    * Not checking the `done` property.
    * Calling `next()` after the iterator is done.
    * Forgetting to handle errors during iteration, potentially leading to resource leaks.
    * Misunderstanding the difference between synchronous and asynchronous iteration.
    * Trying to construct the abstract `Iterator` class directly.

8. **Structuring the Summary:** Organize the findings into logical sections: Functionality Overview, JavaScript Examples, Code Logic Inference (with input/output examples), and Common Programming Errors.

9. **Refining and Elaborating:**  Review the summary for clarity and completeness. Add more detail to the JavaScript examples and the code logic inferences where possible. Ensure the explanation of common errors is concrete and relatable. For example,  instead of just saying "not checking `done`," provide a code snippet demonstrating the issue.

By following these steps, you can systematically analyze the provided Torque code and arrive at a comprehensive understanding of its functionality and its relationship to JavaScript. The key is to connect the low-level V8 implementation details with the high-level concepts of JavaScript iterators and related language features.
这个 `iterator.tq` 文件是 V8 JavaScript 引擎中关于迭代器功能的 Torque 源代码。Torque 是一种用于定义 V8 内置函数和宏的语言。  这个文件定义了一系列用于处理 JavaScript 迭代器的底层操作和辅助函数。

**主要功能归纳:**

1. **定义了 `IteratorRecord` 结构体:**  该结构体用于表示一个迭代器的状态，包含迭代器对象本身 (`object`) 和它的 `next` 方法 (`next`)。这反映了 JavaScript 迭代器协议的核心概念。

2. **提供了获取迭代器的方法:**
   - `GetIteratorMethod`: 获取一个对象的 `Symbol.iterator` 方法。
   - `GetIterator`:  调用对象的 `Symbol.iterator` 方法来获取迭代器对象。存在两个重载，一个接收单个参数（可迭代对象），另一个接收两个参数（可迭代对象和提示）。
   - `GetIteratorWithFeedback` 和 `GetIteratorBaseline`:  提供了带有反馈机制的获取迭代器的方法，用于性能优化。V8 会收集运行时的信息（feedback）来优化后续的迭代器获取。

3. **实现了迭代器的核心操作:**
   - `IteratorStep`: 调用迭代器的 `next()` 方法。返回一个包含 `value` 和 `done` 属性的对象，或者跳转到 `Done` 标签表示迭代完成。
   - `IteratorComplete`: 检查迭代器 `next()` 方法返回的对象的 `done` 属性，如果为 `true` 则跳转到 `Done` 标签。
   - `IteratorValue`:  获取迭代器 `next()` 方法返回的对象的 `value` 属性。

4. **提供了将可迭代对象转换为其他数据结构的方法:**
   - `FastIterableToList`: 将快速可迭代对象转换为 `JSArray`。
   - `IterableToList`: 将任意可迭代对象转换为 `JSArray`。
   - `StringListFromIterable`:  将可迭代对象转换为字符串数组。
   - `IterableToListWithSymbolLookup` 和 `IterableToFixedArrayWithSymbolLookupSlow`:  提供了更复杂的转换方法，可能涉及到原型链查找。

5. **实现了迭代器的关闭机制:**
   - `IteratorCloseOnException`:  当迭代过程中发生异常时，安全地关闭迭代器（调用其 `return()` 方法，如果存在）。
   - `IteratorClose`:  正常关闭迭代器（调用其 `return()` 方法，如果存在）。

6. **实现了异步迭代器的相关功能:**
   - `CreateAsyncFromSyncIterator`: 将同步迭代器转换为异步迭代器。
   - `CreateAsyncFromSyncIteratorBaseline`:  带有基线优化的同步到异步迭代器转换。
   - `GetIteratorRecordAfterCreateAsyncFromSyncIterator`: 在创建异步迭代器后获取其 `IteratorRecord`。
   - `AsyncIteratorPrototypeAsyncDispose`:  实现异步迭代器的 `@@asyncDispose` 方法，用于资源管理。

7. **实现了 `Iterator` 构造函数和原型对象的相关方法:**  这些部分实现了 TC39 的 "Iterator Helpers" 提案，定义了 `Iterator` 构造函数和其原型上的方法，例如 `@@toStringTag`、`constructor` 和 `@@dispose`。

8. **提供了一些辅助宏和内置函数:**  例如 `ObjectHasOwnProperty` 用于检查对象自身是否拥有某个属性。

**与 JavaScript 功能的关系及示例:**

这个文件中的代码是 V8 引擎内部实现 JavaScript 迭代器功能的基础。JavaScript 中所有涉及到迭代器的操作，例如 `for...of` 循环、展开运算符 (`...`)、`yield*` 语法、以及手动调用迭代器的 `next()` 方法，最终都会依赖于这里定义的底层操作。

**JavaScript 示例:**

```javascript
// 使用 for...of 循环遍历数组
const arr = [1, 2, 3];
for (const item of arr) {
  console.log(item);
}

// 手动获取迭代器并遍历
const iterator = arr[Symbol.iterator]();
let result = iterator.next();
while (!result.done) {
  console.log(result.value);
  result = iterator.next();
}

// 展开运算符使用迭代器
const newArr = [...arr, 4, 5];
console.log(newArr);

// 生成器函数返回一个迭代器
function* myGenerator() {
  yield 1;
  yield 2;
  yield 3;
}
const gen = myGenerator();
console.log(gen.next()); // { value: 1, done: false }

// 异步迭代器
async function* asyncGenerator() {
  yield 1;
  await new Promise(resolve => setTimeout(resolve, 100));
  yield 2;
}

async function main() {
  for await (const item of asyncGenerator()) {
    console.log(item);
  }
}
main();

// 使用 Symbol.iterator 手动定义可迭代对象
const myIterable = {
  data: [10, 20, 30],
  [Symbol.iterator]() {
    let index = 0;
    return {
      next: () => {
        if (index < this.data.length) {
          return { value: this.data[index++], done: false };
        } else {
          return { done: true };
        }
      }
    };
  }
};

for (const item of myIterable) {
  console.log(item);
}
```

**代码逻辑推理及假设输入与输出:**

**示例： `IteratorStep` 宏**

**假设输入:**

- `iteratorRecord`: 一个 `IteratorRecord` 结构体，其 `object` 属性指向一个具有 `next()` 方法的 JavaScript 对象，例如一个数组的迭代器。
- 假设这个迭代器的当前状态是准备返回数组的下一个元素 `value: 5`，并且还没有到达末尾 (`done: false`)。

**输出:**

- `IteratorStep` 宏会调用 `iteratorRecord.object.next()`。
- 返回值是一个 `JSReceiver` (Object)，其结构类似于 `{ value: 5, done: false }`。
- 如果迭代器已经到达末尾，`next()` 方法会返回 `{ value: undefined, done: true }`，并且 `IteratorStep` 会跳转到 `Done` 标签（虽然这个宏本身不直接返回，但它的行为会根据 `next()` 的结果跳转）。

**示例： `IteratorClose` 宏**

**假设输入:**

- `iteratorRecord`: 一个 `IteratorRecord` 结构体，其 `object` 属性指向一个具有 `return()` 方法的生成器对象。

**输出:**

- `IteratorClose` 宏会调用 `iteratorRecord.object.return()`。
- 如果 `return()` 方法存在且调用成功，宏会正常结束。
- 如果 `return()` 方法不存在或为 `undefined`，宏会直接返回。
- 如果 `return()` 方法调用后返回的值不是一个对象，宏会抛出一个 `TypeError`。

**用户常见的编程错误举例:**

1. **忘记检查 `done` 属性:**

   ```javascript
   const iterator = [1, 2, 3][Symbol.iterator]();
   console.log(iterator.next().value); // 1
   console.log(iterator.next().value); // 2
   console.log(iterator.next().value); // 3
   console.log(iterator.next().value); // undefined (错误，应该先检查 done)
   ```
   这段代码没有检查 `iterator.next()` 返回的对象的 `done` 属性，导致在迭代结束后尝试访问 `value` 属性，得到 `undefined`，但本意可能是希望停止迭代。

2. **在迭代器已经完成后继续调用 `next()`:**

   虽然调用 `next()` 不会立即报错，但会一直返回 `{ value: undefined, done: true }`，可能会导致程序逻辑错误，尤其是在手动管理迭代器状态时。

3. **没有正确处理迭代器可能抛出的错误:**

   自定义的迭代器或某些内置迭代器在 `next()` 方法中可能会抛出错误。如果用户代码没有使用 `try...catch` 或其他错误处理机制，可能会导致程序崩溃。

4. **混淆同步和异步迭代器:**

   ```javascript
   async function main() {
     const syncIterator = [1, 2, 3][Symbol.iterator]();
     for await (const item of syncIterator) { // 错误用法，不能在 for await...of 中使用同步迭代器
       console.log(item);
     }
   }
   main();
   ```
   用户可能会尝试在 `for await...of` 循环中使用同步迭代器，或者反过来，这会导致类型错误或逻辑错误。

5. **不理解迭代器的关闭机制:**

   一些迭代器（如生成器）具有 `return()` 方法用于执行清理操作。如果用户不了解这个机制，可能不会在需要的时候手动调用 `return()`，导致资源泄漏或其他问题。V8 内部的 `IteratorClose` 和 `IteratorCloseOnException` 就是为了在适当的时候自动调用 `return()` 来确保资源清理。

总而言之，`v8/src/builtins/iterator.tq` 文件是 V8 引擎中实现 JavaScript 迭代器协议和相关功能的关键组成部分，它定义了底层的操作和辅助函数，使得 JavaScript 能够高效且正确地处理各种迭代场景。理解这个文件的内容有助于深入了解 JavaScript 迭代器的内部工作原理。

### 提示词
```
这是目录为v8/src/builtins/iterator.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include 'src/builtins/builtins-iterator-gen.h'

namespace iterator {
// Returned from IteratorBuiltinsAssembler::GetIterator().
@export
struct IteratorRecord {
  // iteratorRecord.[[Iterator]]
  object: JSReceiver;

  // iteratorRecord.[[NextMethod]]
  next: JSAny;
}

extern macro IteratorBuiltinsAssembler::FastIterableToList(
    implicit context: Context)(JSAny): JSArray labels Slow;

extern transitioning macro IteratorBuiltinsAssembler::GetIteratorMethod(
    implicit context: Context)(JSAny): JSAny;
extern transitioning macro IteratorBuiltinsAssembler::GetIterator(
    implicit context: Context)(JSAny): IteratorRecord;
extern transitioning macro IteratorBuiltinsAssembler::GetIterator(
    implicit context: Context)(JSAny, JSAny): IteratorRecord;

extern transitioning macro IteratorBuiltinsAssembler::IteratorStep(
    implicit context: Context)(IteratorRecord): JSReceiver
    labels Done;
extern transitioning macro IteratorBuiltinsAssembler::IteratorStep(
    implicit context: Context)(IteratorRecord, Map): JSReceiver
    labels Done;
extern transitioning macro IteratorBuiltinsAssembler::IteratorComplete(
    implicit context: Context)(JSReceiver): void labels Done;
extern transitioning macro IteratorBuiltinsAssembler::IteratorComplete(
    implicit context: Context)(JSReceiver, Map): void labels Done;

extern transitioning macro IteratorBuiltinsAssembler::IteratorValue(
    implicit context: Context)(JSReceiver): JSAny;
extern transitioning macro IteratorBuiltinsAssembler::IteratorValue(
    implicit context: Context)(JSReceiver, Map): JSAny;

extern transitioning macro IteratorBuiltinsAssembler::IterableToList(
    implicit context: Context)(JSAny, JSAny): JSArray;

extern transitioning macro IteratorBuiltinsAssembler::StringListFromIterable(
    implicit context: Context)(JSAny): JSArray;

extern transitioning builtin IterableToListWithSymbolLookup(
    implicit context: Context)(JSAny): JSArray;
extern transitioning builtin IterableToFixedArrayWithSymbolLookupSlow(
    implicit context: Context)(JSAny): FixedArray;

extern transitioning runtime ObjectHasOwnProperty(Context, JSAny, JSAny):
    Boolean;

transitioning builtin GetIteratorWithFeedback(
    context: Context, receiver: JSAny, loadSlot: TaggedIndex,
    callSlot: TaggedIndex,
    maybeFeedbackVector: Undefined|FeedbackVector): JSAny {
  // TODO(v8:9891): Remove this dcheck once all callers are ported to Torque.
  // This dcheck ensures correctness of maybeFeedbackVector's type which can
  // be easily broken for calls from CSA.
  dcheck(
      IsUndefined(maybeFeedbackVector) ||
      Is<FeedbackVector>(maybeFeedbackVector));
  let iteratorMethod: JSAny;
  typeswitch (maybeFeedbackVector) {
    case (Undefined): {
      iteratorMethod = GetProperty(receiver, IteratorSymbolConstant());
    }
    case (feedback: FeedbackVector): {
      iteratorMethod = LoadIC(
          context, receiver, IteratorSymbolConstant(), loadSlot, feedback);
    }
  }
  // TODO(v8:10047): Use TaggedIndex here once TurboFan supports it.
  const callSlotSmi: Smi = TaggedIndexToSmi(callSlot);
  return CallIteratorWithFeedback(
      context, receiver, iteratorMethod, callSlotSmi, maybeFeedbackVector);
}

extern macro LoadContextFromBaseline(): Context;
extern macro LoadFeedbackVectorFromBaseline(): FeedbackVector;

transitioning builtin GetIteratorBaseline(
    receiver: JSAny, loadSlot: TaggedIndex, callSlot: TaggedIndex): JSAny {
  const context: Context = LoadContextFromBaseline();
  const feedback: FeedbackVector = LoadFeedbackVectorFromBaseline();
  const iteratorMethod: JSAny =
      LoadIC(context, receiver, IteratorSymbolConstant(), loadSlot, feedback);
  // TODO(v8:10047): Use TaggedIndex here once TurboFan supports it.
  const callSlotSmi: Smi = TaggedIndexToSmi(callSlot);
  return CallIteratorWithFeedback(
      context, receiver, iteratorMethod, callSlotSmi, feedback);
}

extern transitioning macro CreateAsyncFromSyncIterator(Context, JSAny): JSAny;

transitioning builtin CreateAsyncFromSyncIteratorBaseline(syncIterator: JSAny):
    JSAny {
  const context: Context = LoadContextFromBaseline();
  return CreateAsyncFromSyncIterator(context, syncIterator);
}

@export
transitioning macro GetIteratorRecordAfterCreateAsyncFromSyncIterator(
    context: Context, asyncIterator: IteratorRecord): IteratorRecord {
  const iterator = CreateAsyncFromSyncIterator(context, asyncIterator.object);

  const nextMethod = GetProperty(iterator, kNextString);
  return IteratorRecord{
    object: UnsafeCast<JSReceiver>(iterator),
    next: nextMethod
  };
}

macro GetLazyReceiver(receiver: JSAny): JSAny {
  return receiver;
}

transitioning builtin CallIteratorWithFeedback(
    context: Context, receiver: JSAny, iteratorMethod: JSAny, callSlot: Smi,
    feedback: Undefined|FeedbackVector): JSAny {
  // TODO(v8:10047): Use TaggedIndex here once TurboFan supports it.
  const callSlotUnTagged: uintptr = Unsigned(SmiUntag(callSlot));
  ic::CollectCallFeedback(
      iteratorMethod, %MakeLazy<JSAny, JSAny>('GetLazyReceiver', receiver),
      context, feedback, callSlotUnTagged);
  const iteratorCallable: Callable = Cast<Callable>(iteratorMethod)
      otherwise ThrowIteratorError(receiver);
  const iterator = Call(context, iteratorCallable, receiver);
  ThrowIfNotJSReceiver(iterator, MessageTemplate::kSymbolIteratorInvalid, '');
  return iterator;
}

// https://tc39.es/ecma262/#sec-iteratorclose
// IteratorCloseOnException should be used to close iterators due to exceptions
// being thrown.
@export
transitioning macro IteratorCloseOnException(
    implicit context: Context)(iterator: IteratorRecord): void {
  try {
    // 3. Let innerResult be GetMethod(iterator, "return").
    const method = GetProperty(iterator.object, kReturnString);

    // 4. If innerResult.[[Type]] is normal, then
    //   a. Let return be innerResult.[[Value]].
    //   b. If return is undefined, return Completion(completion).
    if (method == Undefined || method == Null) return;

    //   c. Set innerResult to Call(return, iterator).
    // If an exception occurs, the original exception remains bound
    Call(context, method, iterator.object);
  } catch (_e, _message) {
    // Swallow the exception.
  }

  // (5. If completion.[[Type]] is throw) return Completion(completion).
}

@export
transitioning macro IteratorClose(
    implicit context: Context)(iterator: IteratorRecord): void {
  // 3. Let innerResult be GetMethod(iterator, "return").
  const method = GetProperty(iterator.object, kReturnString);

  // 4. If innerResult.[[Type]] is normal, then
  //   a. Let return be innerResult.[[Value]].
  //   b. If return is undefined, return Completion(completion).
  if (method == Undefined || method == Null) return;

  //   c. Set innerResult to Call(return, iterator).
  const result = Call(context, method, iterator.object);

  // 5. If completion.[[Type]] is throw, return Completion(completion).
  // It is handled in IteratorCloseOnException.

  // 7. If innerResult.[[Value]] is not an Object, throw a TypeError
  // exception.
  Cast<JSReceiver>(result)
      otherwise ThrowTypeError(MessageTemplate::kCalledOnNonObject, 'return');
}

// https://tc39.es/proposal-iterator-helpers/#sec-iterator
transitioning javascript builtin IteratorConstructor(
    js-implicit context: NativeContext, receiver: JSAny, newTarget: JSAny,
    target: JSFunction)(): JSObject {
  const methodName: constexpr string = 'Iterator';

  // 1. If NewTarget is undefined or the active function object, throw a
  //    TypeError exception.
  if (newTarget == Undefined) {
    ThrowTypeError(MessageTemplate::kConstructorNotFunction, methodName);
  }
  if (newTarget == target) {
    ThrowTypeError(MessageTemplate::kConstructAbstractClass, methodName);
  }

  // 2. Return ? OrdinaryCreateFromConstructor(NewTarget,
  //    "%Iterator.prototype%").
  const map = GetDerivedMap(target, UnsafeCast<JSReceiver>(newTarget));
  return AllocateFastOrSlowJSObjectFromMap(map);
}

// https://tc39.es/proposal-iterator-helpers/#sec-SetterThatIgnoresPrototypeProperties
transitioning macro SetterThatIgnoresPrototypeProperties(
    implicit context: Context)(receiver: JSAny, home: JSObject, key: JSAny,
    value: JSAny, methodName: constexpr string): JSAny {
  // 1. If this is not an Object, then
  //    a. Throw a TypeError exception.
  const o = Cast<JSReceiver>(receiver)
      otherwise ThrowTypeError(MessageTemplate::kCalledOnNonObject, methodName);

  // 2. If this is home, then
  //   a. NOTE: Throwing here emulates assignment to a non-writable data
  //   property on the home object in strict mode code. b. Throw a TypeError
  //   exception.
  if (o == home) {
    ThrowTypeError(
        MessageTemplate::kStrictReadOnlyProperty, key, objectStringConstant(),
        home);
  }

  // 3. Let desc be ? this.[[GetOwnProperty]](p).
  const hasOwn = ObjectHasOwnProperty(context, o, key);

  // 4. If desc is undefined, then
  if (hasOwn == False) {
    // a. Perform ? CreateDataPropertyOrThrow(this, p, v).
    CreateDataProperty(o, key, value);
  } else {
    // 5. Else,
    //   a. Perform ? Set(this, p, v, true).
    SetProperty(o, key, value);
  }
  // 6. Return unused.
  return Undefined;
}

// https://tc39.es/proposal-iterator-helpers/#sec-get-iteratorprototype-@@tostringtag
transitioning javascript builtin IteratorPrototypeGetToStringTag(
    js-implicit context: NativeContext)(): JSAny {
  // 1. Return "Iterator".
  return IteratorStringConstant();
}

// https://tc39.es/proposal-iterator-helpers/#sec-set-iteratorprototype-@@tostringtag
transitioning javascript builtin IteratorPrototypeSetToStringTag(
    js-implicit context: NativeContext, receiver: JSAny)(value: JSAny): JSAny {
  // 1. Perform ? SetterThatIgnoresPrototypeProperties(this value,
  // %Iterator.prototype%, %Symbol.toStringTag%, v).
  const methodName: constexpr string =
      'set Iterator.prototype[Symbol.toStringTag]';
  SetterThatIgnoresPrototypeProperties(
      receiver, GetIteratorPrototype(), ToStringTagSymbolConstant(), value,
      methodName);

  // 2. Return undefined.
  return Undefined;
}

// https://tc39.es/proposal-iterator-helpers/#sec-get-iteratorprototype-constructor
transitioning javascript builtin IteratorPrototypeGetConstructor(
    js-implicit context: NativeContext)(): JSAny {
  // 1. Return %Iterator%.
  return GetIteratorFunction();
}

// https://tc39.es/proposal-iterator-helpers/#sec-set-iteratorprototype-constructor
transitioning javascript builtin IteratorPrototypeSetConstructor(
    js-implicit context: NativeContext, receiver: JSAny)(value: JSAny): JSAny {
  // 1. Perform ? SetterThatIgnoresPrototypeProperties(this value,
  // %Iterator.prototype%, "constructor", v).
  const methodName: constexpr string = 'set Iterator.prototype.constructor';
  SetterThatIgnoresPrototypeProperties(
      receiver, GetIteratorPrototype(), ConstructorStringConstant(), value,
      methodName);

  // 2. Return undefined.
  return Undefined;
}

// https://tc39.es/proposal-explicit-resource-management/#sec-%iteratorprototype%-@@dispose
transitioning javascript builtin IteratorPrototypeDispose(
    js-implicit context: NativeContext, receiver: JSAny)(): JSAny {
  // 1. Let O be the this value.
  // 2. Let return be ? GetMethod(O, "return").
  try {
    const returnMethod =
        GetMethod(receiver, kReturnString) otherwise IfUndefined;
    // 3. If return is not undefined, then
    //   a. Perform ? Call(return, O, « »).
    Call(context, returnMethod, receiver);
  } label IfUndefined {
    // Do nothing here
  }

  // 4. Return NormalCompletion(undefined).
  return Undefined;
}

extern macro AllocateRootFunctionWithContext(
    constexpr intptr, FunctionContext, NativeContext): JSFunction;

extern macro
AsyncIteratorPrototypeAsyncDisposeResolveClosureSharedFunConstant():
    SharedFunctionInfo;

const kAsyncIteratorPrototypeAsyncDisposeResolveClosureSharedFun:
    constexpr intptr
    generates 'RootIndex::kAsyncIteratorPrototypeAsyncDisposeResolveClosureSharedFun'
    ;

type AsyncIteratorPrototypeAsyncDisposeResolveContext extends FunctionContext;
const kAsyncIteratorPrototypeAsyncDisposeResolveContextLength:
    constexpr intptr = ContextSlot::MIN_CONTEXT_SLOTS;

javascript builtin AsyncIteratorPrototypeAsyncDisposeResolveClosure(
    js-implicit context: NativeContext, receiver: JSAny)(): JSAny {
  return Undefined;
}

// https://tc39.es/proposal-explicit-resource-management/#sec-%asynciteratorprototype%-@@asyncdispose
transitioning javascript builtin AsyncIteratorPrototypeAsyncDispose(
    js-implicit context: Context, receiver: JSAny)(): JSAny {
  // 1. Let O be the this value.
  // 2. Let promiseCapability be ! NewPromiseCapability(%Promise%).
  const capability = promise::NewJSPromise();

  try {
    try {
      // 3. Let return be GetMethod(O, "return").
      // 4. IfAbruptRejectPromise(return, promiseCapability).
      const returnMethod =
          GetMethod(receiver, kReturnString) otherwise IfUndefined;
      // 6. Else,
      // a. Let result be Call(return, O, « undefined »).
      // b. IfAbruptRejectPromise(result, promiseCapability).
      const result = Call(context, returnMethod, receiver, Undefined);

      // c. Let resultWrapper be Completion(PromiseResolve(%Promise%, result)).
      // d. IfAbruptRejectPromise(resultWrapper, promiseCapability).
      const promiseFun = *NativeContextSlot(
          ContextSlot::PROMISE_FUNCTION_INDEX);
      const constructor = SpeciesConstructor(capability, promiseFun);
      const resultWrapper = promise::PromiseResolve(constructor, result);


      // e. Let unwrap be a new Abstract Closure that performs the following
      // steps when called: i. Return undefined.
      // f. Let onFulfilled be CreateBuiltinFunction(unwrap, 1, "", « »).
      const resolveContext =
          %RawDownCast<AsyncIteratorPrototypeAsyncDisposeResolveContext>(
              AllocateSyntheticFunctionContext(
                  %RawDownCast<NativeContext>(context),
                  kAsyncIteratorPrototypeAsyncDisposeResolveContextLength));
      const onFulfilled = AllocateRootFunctionWithContext(
          kAsyncIteratorPrototypeAsyncDisposeResolveClosureSharedFun,
          resolveContext, %RawDownCast<NativeContext>(context));

      // g. Perform PerformPromiseThen(resultWrapper, onFulfilled, undefined,
      // promiseCapability).
      promise::PerformPromiseThenImpl(
          UnsafeCast<JSPromise>(resultWrapper), onFulfilled,
          UndefinedConstant(), capability);
    } label IfUndefined {
      // 5. If return is undefined, then
      // a. Perform ! Call(promiseCapability.[[Resolve]], undefined, « undefined
      // »).
      promise::ResolvePromise(capability, Undefined);
    }

    // 7. Return promiseCapability.[[Promise]].
    return capability;
  } catch (e, _message) {
    promise::RejectPromise(capability, e, False);
    return capability;
  }
}
}  // namespace iterator
```