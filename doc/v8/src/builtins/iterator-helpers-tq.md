Response: Let's break down the thought process for analyzing this Torque code.

**1. Initial Skim and Goal Identification:**

The first step is to quickly read through the code to get a general idea of its purpose. Keywords like "iterator," "helper," "map," "filter," "take," "drop," "flatMap," "reduce," "toArray," "forEach," "some," "every," and "find" jump out. The file path `v8/src/builtins/iterator-helpers.tq` confirms that this code implements the new iterator helper methods in JavaScript. The comments at the top reinforce this. The goal is to understand *how* these helpers are implemented in V8's internal representation (Torque).

**2. Understanding Core Concepts and Data Structures:**

Several key concepts need to be grasped:

* **Iterators in JavaScript:**  Recall how iterators work in JavaScript (the `next()` method, the `done` property).
* **Iterator Helpers:** Understand the purpose of methods like `map`, `filter`, `take`, etc., in transforming and manipulating iterators.
* **Torque:** Recognize that this is a V8-specific language for defining built-in functions. Key aspects of Torque to look for are:
    * `transitioning macro/javascript builtin`:  Indicates a function exposed to JavaScript.
    * `implicit context: Context`:  A parameter providing access to the V8 execution environment.
    * `Cast<>`:  Type assertions.
    * `ThrowTypeError`, `ThrowRangeError`:  Error handling.
    * `GetProperty`, `Call`:  Operations on JavaScript objects.
    * `AllocateJSIteratorResult`: Creating iterator result objects.
    * `IteratorStep`, `IteratorValue`, `IteratorClose`, `IteratorCloseOnException`:  Standard iterator operations.
    * `new JSIterator...Helper`: Instantiation of internal helper objects.
    * `typeswitch`:  A way to dispatch based on object type.
* **Internal Helper Objects (e.g., `JSIteratorMapHelper`):**  These are V8's internal representations of the iterator helper instances. Notice they store the underlying iterator, the transformation function (mapper, predicate), and potentially other state (like the remaining count for `take` and `drop`).
* **Generator States (Exhausted, Executing):** Pay attention to `kIteratorHelperExhausted` and `kIteratorHelperExecuting`. This reveals how V8 manages the state of these helpers, as they are implemented as direct iterators rather than full generators for performance reasons.

**3. Analyzing Individual Helper Implementations:**

Pick one or two helpers to analyze in detail. `map` is a good starting point because it's conceptually simple. Follow the execution flow of `IteratorPrototypeMap` and `IteratorMapHelperNext`:

* **`IteratorPrototypeMap`:**
    * Checks the receiver and the mapper function's validity.
    * Gets the underlying iterator using `GetIteratorDirect`.
    * Creates a `JSIteratorMapHelper` instance, storing the underlying iterator and the mapper.
* **`IteratorMapHelperNext`:**
    * Checks if the iterator is exhausted.
    * Gets the next value from the underlying iterator using `IteratorStep`.
    * Calls the mapper function with the current value and index.
    * Returns a new iterator result object with the mapped value.
    * Handles potential exceptions during iteration or mapping, ensuring proper closing of the underlying iterator.

Once you understand `map`, the other helpers become easier to grasp, as they follow a similar pattern:

* **`filter`:**  Calls the predicate and only yields values for which it returns true.
* **`take`:**  Keeps track of the remaining count and stops iterating after reaching the limit.
* **`drop`:**  Skips the first `n` elements.
* **`flatMap`:**  Maps each element to an iterator and then iterates over the results of those iterators. This is more complex and requires managing an "inner" iterator.
* **`reduce`:**  Accumulates a value by applying a reducer function to each element.
* **`toArray`:**  Collects all the values into an array.
* **`forEach`:**  Calls a function for each element.
* **`some`:**  Returns true if any element satisfies the predicate.
* **`every`:** Returns true if all elements satisfy the predicate.
* **`find`:** Returns the first element that satisfies the predicate.

**4. Identifying Relationships to JavaScript:**

For each helper, think about the equivalent JavaScript code you would write to achieve the same functionality. This helps solidify your understanding of what the Torque code is doing. For example, the `IteratorPrototypeMap` Torque code directly corresponds to the `Iterator.prototype.map()` method in JavaScript.

**5. Code Logic Reasoning (Assumptions and Outputs):**

For each helper, come up with a simple scenario and trace the execution flow:

* **Input:**  An iterator and the necessary function (mapper, predicate, etc.).
* **Process:**  Step through the Torque code, simulating the internal state changes.
* **Output:**  The expected sequence of values yielded by the helper iterator.

**6. Identifying Common Programming Errors:**

Think about how developers might misuse these iterator helpers in JavaScript. Common errors include:

* Passing a non-callable mapper or predicate.
* Expecting side effects in the mapper/predicate to alter the original iterator (they create new iterators).
* Infinite loops if the underlying iterator never completes.
* Incorrectly handling asynchronous operations within the helper functions.
* Calling `next()` or `return()` on an already executing iterator helper.

**7. Structuring the Output:**

Organize your findings logically, covering the requested aspects:

* **Functionality Summary:** A concise overview of the code's purpose.
* **Relationship to JavaScript:**  Demonstrate the connection with JavaScript examples.
* **Code Logic Reasoning:** Provide specific input/output scenarios.
* **Common Programming Errors:** Illustrate potential pitfalls with JavaScript examples.

**Self-Correction/Refinement During the Process:**

* **If you get stuck:** Re-read the relevant parts of the ECMAScript specification for iterator helpers. Look for comments in the Torque code that explain the spec.
* **If something doesn't make sense:**  Try simplifying the code or focusing on a smaller part. Use a debugger if possible (though debugging Torque code can be complex).
* **Double-check your assumptions:** Ensure your understanding of iterator behavior and the semantics of each helper method is correct.

By following these steps, you can systematically analyze and understand complex Torque code like this, ultimately connecting it back to its corresponding JavaScript functionality and potential user errors.
This Torque code defines the implementation of the **Iterator Helpers** proposal in V8. Iterator Helpers are a set of new methods added to the `Iterator.prototype` in JavaScript, providing functional programming style operations on iterators.

Here's a breakdown of its functionality:

**Core Functionality:**

* **Implementation of Iterator Helper Methods:**  The code implements the core logic for various iterator helper methods like `map`, `filter`, `take`, `drop`, `flatMap`, `reduce`, `toArray`, `forEach`, `some`, `every`, and `find`.
* **Lazy Evaluation:**  Most of these helpers (except `reduce`, `toArray`, `forEach`, `some`, `every`, and `find`) operate lazily. They don't perform the operations until their `next()` method is called. This is achieved by creating new iterator helper objects that wrap the original iterator.
* **State Management:** Since iterator helpers are specified as generators but implemented as direct iterators for performance, the code manually manages the "generator state" (executing or completed) using sentinel values on the `underlying_object` property of the helper objects.
* **Error Handling:**  The code includes robust error handling, ensuring that iterators are closed properly even if errors occur during mapping, filtering, etc. It handles `TypeError` for invalid inputs and `RangeError` for invalid limits in `take` and `drop`.
* **Integration with V8 Internals:** The code utilizes V8-specific concepts and macros like `JSIteratorHelper`, `IteratorRecord`, `GetIteratorDirect`, `IteratorStep`, `IteratorValue`, `IteratorClose`, and `AllocateJSIteratorResult`.

**Relationship to JavaScript and Examples:**

The code directly implements the functionality of the following JavaScript methods on `Iterator.prototype`:

* **`map(mapper)`:** Transforms each element of the iterator using the provided `mapper` function.

   ```javascript
   const iterator = [1, 2, 3].values();
   const doubledIterator = iterator.map(x => x * 2);
   console.log(doubledIterator.next()); // { value: 2, done: false }
   console.log(doubledIterator.next()); // { value: 4, done: false }
   console.log(doubledIterator.next()); // { value: 6, done: false }
   console.log(doubledIterator.next()); // { value: undefined, done: true }
   ```

* **`filter(predicate)`:**  Creates a new iterator with elements that pass the provided `predicate` function.

   ```javascript
   const iterator = [1, 2, 3, 4].values();
   const evenIterator = iterator.filter(x => x % 2 === 0);
   console.log(evenIterator.next()); // { value: 2, done: false }
   console.log(evenIterator.next()); // { value: 4, done: false }
   console.log(evenIterator.next()); // { value: undefined, done: true }
   ```

* **`take(limit)`:** Creates a new iterator that yields at most `limit` elements from the original iterator.

   ```javascript
   const iterator = [1, 2, 3, 4, 5].values();
   const firstThree = iterator.take(3);
   console.log(firstThree.next()); // { value: 1, done: false }
   console.log(firstThree.next()); // { value: 2, done: false }
   console.log(firstThree.next()); // { value: 3, done: false }
   console.log(firstThree.next()); // { value: undefined, done: true }
   ```

* **`drop(limit)`:** Creates a new iterator that skips the first `limit` elements and then yields the remaining elements.

   ```javascript
   const iterator = [1, 2, 3, 4, 5].values();
   const afterTwo = iterator.drop(2);
   console.log(afterTwo.next()); // { value: 3, done: false }
   console.log(afterTwo.next()); // { value: 4, done: false }
   console.log(afterTwo.next()); // { value: 5, done: false }
   console.log(afterTwo.next()); // { value: undefined, done: true }
   ```

* **`flatMap(mapper)`:**  Maps each element to an iterator and then flattens the resulting iterators into a single iterator.

   ```javascript
   const iterator = [1, 2, 3].values();
   const flatMapIterator = iterator.flatMap(x => [x, x * 2]);
   console.log(flatMapIterator.next()); // { value: 1, done: false }
   console.log(flatMapIterator.next()); // { value: 2, done: false }
   console.log(flatMapIterator.next()); // { value: 2, done: false }
   console.log(flatMapIterator.next()); // { value: 4, done: false }
   console.log(flatMapIterator.next()); // { value: 3, done: false }
   console.log(flatMapIterator.next()); // { value: 6, done: false }
   console.log(flatMapIterator.next()); // { value: undefined, done: true }
   ```

* **`reduce(reducer, initialValue?)`:** Applies a `reducer` function against an accumulator and each element of the iterator (from left to right) to reduce it to a single value.

   ```javascript
   const iterator = [1, 2, 3, 4].values();
   const sum = iterator.reduce((acc, curr) => acc + curr, 0);
   console.log(sum); // 10
   ```

* **`toArray()`:**  Consumes the iterator and returns an array containing all its elements.

   ```javascript
   const iterator = [1, 2, 3].values();
   const array = iterator.toArray();
   console.log(array); // [1, 2, 3]
   ```

* **`forEach(callbackFn)`:** Executes a provided function once for each element of the iterator.

   ```javascript
   const iterator = [1, 2, 3].values();
   iterator.forEach(item => console.log(item * 2)); // Output: 2, 4, 6
   ```

* **`some(predicate)`:** Returns `true` if at least one element in the iterator passes the test implemented by the provided function.

   ```javascript
   const iterator = [1, 2, 3, 4].values();
   const hasEven = iterator.some(x => x % 2 === 0);
   console.log(hasEven); // true
   ```

* **`every(predicate)`:** Returns `true` if all elements in the iterator pass the test implemented by the provided function.

   ```javascript
   const iterator = [2, 4, 6].values();
   const allEven = iterator.every(x => x % 2 === 0);
   console.log(allEven); // true
   ```

* **`find(predicate)`:** Returns the value of the first element in the iterator that satisfies the provided testing function. Otherwise, `undefined` is returned.

   ```javascript
   const iterator = [1, 3, 5, 6, 7].values();
   const firstEven = iterator.find(x => x % 2 === 0);
   console.log(firstEven); // 6
   ```

**Code Logic Reasoning (Example: `map`)**

**Assumption:** We have an iterator that yields numbers: `[1, 2, 3].values()` and we want to double each number using `map(x => x * 2)`.

**Input:**
* `underlying` (IteratorRecord):  An object representing the original iterator with its `object` (the iterator itself) and `next` method.
* `mapper`: The function `x => x * 2`.

**Process (simplified for `IteratorMapHelperNext`):**

1. **`MarkIteratorHelperAsExecuting(helper)`:**  Marks the `JSIteratorMapHelper` as currently executing to prevent re-entry.
2. **`IteratorStep(underlying, fastIteratorResultMap)`:** Calls the `next()` method of the underlying iterator.
   * **First call:** Returns `{ value: 1, done: false }`.
3. **`IteratorValue(next, fastIteratorResultMap)`:** Extracts the `value` (1) from the result.
4. **`Call(context, helper.mapper, Undefined, value, counter)`:** Calls the `mapper` function with `value = 1` and `counter = 0`. Returns `2`.
5. **`AllocateJSIteratorResult(mapped, False)`:** Creates a new iterator result object `{ value: 2, done: false }`.
6. **`MarkIteratorHelperAsFinishedExecuting(helper, underlying)`:** Marks the helper as finished executing for this step.
7. **Subsequent calls** to `next()` on the `doubledIterator` repeat this process for the remaining elements (2 and 3), producing `{ value: 4, done: false }` and `{ value: 6, done: false }`.
8. When the underlying iterator is exhausted, `IteratorStep` returns an object that satisfies the "Done" label condition.
9. **`MarkIteratorHelperAsExhausted(helper)`:** Marks the helper as exhausted.
10. `AllocateJSIteratorResult(Undefined, True)` is returned, signaling the end of the `doubledIterator`.

**Output:** The `doubledIterator` will yield `{ value: 2, done: false }`, then `{ value: 4, done: false }`, then `{ value: 6, done: false }`, and finally `{ value: undefined, done: true }`.

**Common Programming Errors:**

* **Passing a non-callable to `map`, `filter`, `flatMap`, `forEach`, `some`, `every`, or `find`:**

   ```javascript
   const iterator = [1, 2].values();
   // TypeError: Iterator.prototype.map expects a callable
   iterator.map("not a function");
   ```

* **Modifying the original iterator while using a helper (due to shared state in some cases, though less common with these helpers which create new iterators):** While these specific helpers create new iterators, understanding iterator invalidation is important in general.

* **Infinite loops if the underlying iterator never completes, especially with lazy helpers:**

   ```javascript
   function* infiniteNumbers() {
       let i = 0;
       while (true) {
           yield i++;
       }
   }
   const infiniteIterator = infiniteNumbers();
   const firstFive = infiniteIterator.take(5);
   console.log([...firstFive]); // This will work and output [0, 1, 2, 3, 4]

   // However, if you don't have a terminating condition:
   // const mappedInfinite = infiniteIterator.map(x => x * 2);
   // console.log([...mappedInfinite]); // This will run indefinitely, consuming resources.
   ```

* **Calling `next()` or `return()` on an already executing iterator helper:** This is explicitly checked and throws a `TypeError`.

   ```javascript
   const iterator = [1, 2].values();
   const mapper = x => {
       console.log("Mapping:", x);
       return x * 2;
   };
   const mappedIterator = iterator.map(mapper);

   console.log(mappedIterator.next()); // Mapping: 1, Output: { value: 2, done: false }

   // This would throw a TypeError because the iterator is conceptually "executing"
   // during the first next() call. While not directly observable in this simple
   // synchronous example, this mechanism is in place for more complex scenarios
   // or if the helper was implemented as a true generator.
   // mappedIterator.return();
   ```

This Torque code is a crucial part of V8's implementation, enabling efficient and correct execution of the new Iterator Helper methods in JavaScript. It demonstrates how complex language features are implemented at a lower level using V8's internal mechanisms.

### 提示词
```
这是目录为v8/src/builtins/iterator-helpers.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// --- Utilities

namespace iterator {

const kIteratorMethods: constexpr UseCounterFeature
    generates 'v8::Isolate::kIteratorMethods';

// Iterator helpers are specced as generators but implemented as direct
// iterators. As such generator states need to be tracked manually. To save
// space, this is done by assigning sentinel values to underlying_object.

// Tracks the ~completed~ generator state.
const kIteratorHelperExhausted: Null = Null;
// Tracks the ~executing~ generator state.
const kIteratorHelperExecuting: Undefined = Undefined;

macro IsIteratorHelperExhausted(helper: JSIteratorHelper): bool {
  return helper.underlying_object == kIteratorHelperExhausted;
}

macro MarkIteratorHelperAsExhausted(helper: JSIteratorHelper): void {
  helper.underlying_object = kIteratorHelperExhausted;
}

macro IsIteratorHelperExecuting(helper: JSIteratorHelper): bool {
  return helper.underlying_object == kIteratorHelperExecuting;
}

// When a generator's state is ~executing~, attempts to reenter via next() or
// return() throw a TypeError. See step 6 in ES #sec-generatorvalidate.
macro ThrowIfIteratorHelperExecuting(
    implicit context: Context)(helper: JSIteratorHelper): void {
  if (IsIteratorHelperExecuting(helper)) {
    ThrowTypeError(MessageTemplate::kGeneratorRunning);
  }
}

macro MarkIteratorHelperAsExecuting(helper: JSIteratorHelper):
    IteratorRecord {
  dcheck(!IsIteratorHelperExecuting(helper));
  const object =
      Cast<JSReceiver>(helper.underlying_object) otherwise unreachable;
  helper.underlying_object = kIteratorHelperExecuting;
  return IteratorRecord{object: object, next: helper.underlying_next};
}

macro MarkIteratorHelperAsFinishedExecuting(
    helper: JSIteratorHelper, underlying: IteratorRecord): void {
  dcheck(IsIteratorHelperExecuting(helper));
  dcheck(underlying.object != kIteratorHelperExecuting);
  helper.underlying_object = underlying.object;
}

// https://tc39.es/proposal-iterator-helpers/#sec-getiteratordirect
transitioning macro GetIteratorDirect(
    implicit context: Context)(obj: JSReceiver): IteratorRecord {
  // 1. Let nextMethod be ? Get(obj, "next").
  const nextMethod = GetProperty(obj, kNextString);

  // 2. Let iteratorRecord be Record { [[Iterator]]: obj, [[NextMethod]]:
  //    nextMethod, [[Done]]: false }.
  // 3. Return iteratorRecord.
  return IteratorRecord{object: obj, next: nextMethod};
}

// --- Dispatch functions for all iterator helpers

// https://tc39.es/proposal-iterator-helpers/#sec-%iteratorhelperprototype%.next
transitioning javascript builtin IteratorHelperPrototypeNext(
    js-implicit context: NativeContext, receiver: JSAny)(): JSAny {
  // 1. Return ? GeneratorResume(this value, undefined, "Iterator Helper").

  // Iterator helpers are specified as generators but we implement them as
  // direct iterators.
  const helper = Cast<JSIteratorHelper>(receiver) otherwise ThrowTypeError(
      MessageTemplate::kIncompatibleMethodReceiver,
      'Iterator Helper.prototype.next', receiver);

  ThrowIfIteratorHelperExecuting(helper);

  if (IsIteratorHelperExhausted(helper)) {
    return AllocateJSIteratorResult(Undefined, True);
  }

  typeswitch (helper) {
    case (mapHelper: JSIteratorMapHelper): {
      return IteratorMapHelperNext(mapHelper);
    }
    case (filterHelper: JSIteratorFilterHelper): {
      return IteratorFilterHelperNext(filterHelper);
    }
    case (takeHelper: JSIteratorTakeHelper): {
      return IteratorTakeHelperNext(takeHelper);
    }
    case (dropHelper: JSIteratorDropHelper): {
      return IteratorDropHelperNext(dropHelper);
    }
    case (flatMapHelper: JSIteratorFlatMapHelper): {
      return IteratorFlatMapHelperNext(flatMapHelper);
    }
    case (Object): {
      unreachable;
    }
  }
}

// https://tc39.es/proposal-iterator-helpers/#sec-%iteratorhelperprototype%.return
transitioning javascript builtin IteratorHelperPrototypeReturn(
    js-implicit context: NativeContext, receiver: JSAny)(): JSObject {
  // 1. Let O be this value.
  // 2. Perform ? RequireInternalSlot(O, [[UnderlyingIterator]]).
  // 3. Assert: O has a [[GeneratorState]] slot.
  // 4. If O.[[GeneratorState]] is suspendedStart, then
  //   a. Set O.[[GeneratorState]] to completed.
  //   b. Perform ? IteratorClose(O.[[UnderlyingIterator]],
  //      NormalCompletion(unused)).
  //   c. Return CreateIterResultObject(undefined, true).
  // 5. Let C be Completion { [[Type]]: return, [[Value]]: undefined,
  //    [[Target]]: empty }.
  // 6. Return ? GeneratorResumeAbrupt(O, C, "Iterator Helper").

  // Return for flatMap helper is not the same as other helpers.
  typeswitch (receiver) {
    case (helper: JSIteratorFlatMapHelper): {
      ThrowIfIteratorHelperExecuting(helper);

      if (IsIteratorHelperExhausted(helper)) {
        return AllocateJSIteratorResult(Undefined, True);
      }

      const object =
          Cast<JSReceiver>(helper.underlying_object) otherwise unreachable;
      const underlying =
      IteratorRecord{object: object, next: helper.underlying_next};

      MarkIteratorHelperAsExhausted(helper);

      if (helper.innerAlive == True) {
        try {
          // d. If completion is an abrupt completion, then
          // i. Let backupCompletion be Completion(IteratorClose(innerIterator,
          // completion)).
          IteratorClose(helper.innerIterator);

        } catch (e, message) {
          // ii. IfAbruptCloseIterator(backupCompletion, iterated).
          IteratorCloseOnException(underlying);
          ReThrowWithMessage(context, e, message);
        }
      }

      // iii. Return ? IteratorClose(completion, iterated).
      IteratorClose(underlying);
      return AllocateJSIteratorResult(Undefined, True);
    }
    case (Object): {
      // Iterator helpers are specified as generators. The net effect of this
      // method is to close the underlying and return { value: undefined, done:
      // true }.
      const helper = Cast<JSIteratorHelper>(receiver) otherwise ThrowTypeError(
          MessageTemplate::kIncompatibleMethodReceiver,
          'Iterator Helper.prototype.return', receiver);
      ThrowIfIteratorHelperExecuting(helper);
      if (!IsIteratorHelperExhausted(helper)) {
        const object =
            Cast<JSReceiver>(helper.underlying_object) otherwise unreachable;
        const underlying =
        IteratorRecord{object: object, next: helper.underlying_next};

        MarkIteratorHelperAsExhausted(helper);
        IteratorClose(underlying);
      }
      return AllocateJSIteratorResult(Undefined, True);
    }
  }
}

// --- map helper

macro NewJSIteratorMapHelper(
    implicit context: Context)(underlying: IteratorRecord,
    mapper: Callable): JSIteratorMapHelper {
  return new JSIteratorMapHelper{
    map: *NativeContextSlot(ContextSlot::ITERATOR_MAP_HELPER_MAP_INDEX),
    properties_or_hash: kEmptyFixedArray,
    elements: kEmptyFixedArray,
    underlying_object: underlying.object,
    underlying_next: underlying.next,
    mapper: mapper,
    counter: 0
  };
}

// https://tc39.es/proposal-iterator-helpers/#sec-iteratorprototype.map
transitioning javascript builtin IteratorPrototypeMap(
    js-implicit context: NativeContext, receiver: JSAny)(
    mapper: JSAny): JSIteratorMapHelper {
  const methodName: constexpr string = 'Iterator.prototype.map';
  IncrementUseCounter(context, SmiConstant(kIteratorMethods));

  // 1. Let O be the this value.
  // 2. If O is not an Object, throw a TypeError exception.
  const o = Cast<JSReceiver>(receiver)
      otherwise ThrowTypeError(MessageTemplate::kCalledOnNonObject, methodName);

  // 3. If IsCallable(mapper) is false, throw a TypeError exception.
  const mapper = Cast<Callable>(mapper)
      otherwise ThrowCalledNonCallable(methodName);

  // 4. Let iterated be ? GetIteratorDirect(O).
  const iterated = GetIteratorDirect(o);

  // Step 5 implemented in IteratorMapHelperNext

  // 6. Let result be CreateIteratorFromClosure(closure, "Iterator Helper",
  //    %IteratorHelperPrototype%).
  // 7. Set result.[[UnderlyingIterator]] to iterated.
  // 8. Return result.
  return NewJSIteratorMapHelper(iterated, mapper);
}

transitioning builtin IteratorMapHelperNext(
    implicit context: Context)(helper: JSIteratorMapHelper): JSAny {
  // a. Let counter be 0.
  // (Done when creating JSIteratorMapHelper.)

  const fastIteratorResultMap = GetIteratorResultMap();
  const underlying = MarkIteratorHelperAsExecuting(helper);
  const counter = helper.counter;

  try {
    // b. Repeat,
    let next: JSReceiver;
    try {
      // i. Let next be ? IteratorStep(iterated).
      next = IteratorStep(underlying, fastIteratorResultMap)
          otherwise Done;
    } label Done {
      // ii. If next is false, return undefined.
      MarkIteratorHelperAsExhausted(helper);
      return AllocateJSIteratorResult(Undefined, True);
    }

    // iii. Let value be ? IteratorValue(next).
    const value = IteratorValue(next, fastIteratorResultMap);

    try {
      // iv. Let mapped be Completion(
      //     Call(mapper, undefined, « value, 𝔽(counter) »)).
      const mapped = Call(context, helper.mapper, Undefined, value, counter);

      // viii. Set counter to counter + 1.
      // (Done out of order. Iterator helpers are specified as generators with
      // yields but we implement them as direct iterators.)
      helper.counter = counter + 1;

      // vi. Let completion be Completion(Yield(mapped)).
      MarkIteratorHelperAsFinishedExecuting(helper, underlying);
      return AllocateJSIteratorResult(mapped, False);

      // vii. IfAbruptCloseIterator(completion, iterated).
      // (Done in IteratorHelperPrototypeReturn.)
    } catch (e, message) {
      // v. IfAbruptCloseIterator(mapped, iterated).
      IteratorCloseOnException(underlying);
      ReThrowWithMessage(context, e, message);
    }
  } catch (e, message) {
    MarkIteratorHelperAsExhausted(helper);
    ReThrowWithMessage(context, e, message);
  }
}

// --- filter helper

macro NewJSIteratorFilterHelper(
    implicit context: Context)(underlying: IteratorRecord,
    predicate: Callable): JSIteratorFilterHelper {
  return new JSIteratorFilterHelper{
    map: *NativeContextSlot(ContextSlot::ITERATOR_FILTER_HELPER_MAP_INDEX),
    properties_or_hash: kEmptyFixedArray,
    elements: kEmptyFixedArray,
    underlying_object: underlying.object,
    underlying_next: underlying.next,
    predicate: predicate,
    counter: 0
  };
}

// https://tc39.es/proposal-iterator-helpers/#sec-iteratorprototype.filter
transitioning javascript builtin IteratorPrototypeFilter(
    js-implicit context: NativeContext, receiver: JSAny)(
    predicate: JSAny): JSIteratorFilterHelper {
  const methodName: constexpr string = 'Iterator.prototype.filter';
  IncrementUseCounter(context, SmiConstant(kIteratorMethods));

  // 1. Let O be the this value.
  // 2. If O is not an Object, throw a TypeError exception.
  const o = Cast<JSReceiver>(receiver)
      otherwise ThrowTypeError(MessageTemplate::kCalledOnNonObject, methodName);

  // 3. If IsCallable(predicate) is false, throw a TypeError exception.
  const predicate = Cast<Callable>(predicate)
      otherwise ThrowCalledNonCallable(methodName);

  // 4. Let iterated be ? GetIteratorDirect(O).
  const iterated = GetIteratorDirect(o);

  // Step 5 implemented in IteratorFilterHelperNext

  // 6. Let result be CreateIteratorFromClosure(closure, "Iterator Helper",
  //    %IteratorHelperPrototype%).
  // 7. Set result.[[UnderlyingIterator]] to iterated.
  // 8. Return result.
  return NewJSIteratorFilterHelper(iterated, predicate);
}

transitioning builtin IteratorFilterHelperNext(
    implicit context: Context)(helper: JSIteratorFilterHelper): JSAny {
  // a. Let counter be 0.
  // (Done when creating JSIteratorFilterHelper.)

  const fastIteratorResultMap = GetIteratorResultMap();
  const underlying = MarkIteratorHelperAsExecuting(helper);

  try {
    while (true) {
      const counter = helper.counter;

      // b. Repeat,
      let next: JSReceiver;
      try {
        // i. Let next be ? IteratorStep(iterated).
        next = IteratorStep(underlying, fastIteratorResultMap)
            otherwise Done;
      } label Done {
        // ii. If next is false, return undefined.
        MarkIteratorHelperAsExhausted(helper);
        return AllocateJSIteratorResult(Undefined, True);
      }

      // iii. Let value be ? IteratorValue(next).
      const value = IteratorValue(next, fastIteratorResultMap);

      try {
        // iv. Let selected be Completion(
        //     Call(predicate, undefined, « value, 𝔽(counter) »)).
        const selected =
            Call(context, helper.predicate, Undefined, value, counter);

        // vii. Set counter to counter + 1.
        // (Done out of order. Iterator helpers are specified as generators with
        // yields but we implement them as direct iterators.)
        helper.counter = counter + 1;

        // vi. If ToBoolean(selected) is true, then
        if (ToBoolean(selected)) {
          // 1. Let completion be Completion(Yield(value)).
          MarkIteratorHelperAsFinishedExecuting(helper, underlying);
          return AllocateJSIteratorResult(value, False);
          // 2. IfAbruptCloseIterator(completion, iterated).
          // (Done in IteratorHelperPrototypeReturn.)
        }
      } catch (e, message) {
        // v. IfAbruptCloseIterator(selected, iterated).
        IteratorCloseOnException(underlying);
        ReThrowWithMessage(context, e, message);
      }
    }
  } catch (e, message) {
    MarkIteratorHelperAsExhausted(helper);
    ReThrowWithMessage(context, e, message);
  }
  unreachable;
}

// --- take helper

macro NewJSIteratorTakeHelper(
    implicit context: Context)(underlying: IteratorRecord,
    limit: Number): JSIteratorTakeHelper {
  return new JSIteratorTakeHelper{
    map: *NativeContextSlot(ContextSlot::ITERATOR_TAKE_HELPER_MAP_INDEX),
    properties_or_hash: kEmptyFixedArray,
    elements: kEmptyFixedArray,
    underlying_object: underlying.object,
    underlying_next: underlying.next,
    remaining: limit
  };
}

// https://tc39.es/proposal-iterator-helpers/#sec-iteratorprototype.take
transitioning javascript builtin IteratorPrototypeTake(
    js-implicit context: NativeContext, receiver: JSAny)(
    limit: JSAny): JSIteratorTakeHelper {
  try {
    const methodName: constexpr string = 'Iterator.prototype.take';
    IncrementUseCounter(context, SmiConstant(kIteratorMethods));

    // 1. Let O be the this value.
    // 2. If O is not an Object, throw a TypeError exception.
    const o = Cast<JSReceiver>(receiver)
        otherwise ThrowTypeError(MessageTemplate::kCalledOnNonObject, methodName);

    // 3. Let numLimit be ? ToNumber(limit).
    const numLimit = ToNumber_Inline(limit);

    // 4. If numLimit is NaN, throw a RangeError exception.
    if (NumberIsNaN(numLimit)) goto RangeError;

    // 5. Let integerLimit be ! ToIntegerOrInfinity(numLimit).
    const integerLimit = ToInteger_Inline(numLimit);

    // 6. If integerLimit < 0, throw a RangeError exception.
    if (integerLimit < 0) goto RangeError;

    // 5. Let iterated be ? GetIteratorDirect(O).
    const iterated = GetIteratorDirect(o);

    // Step 6 implemented in IteratorTakeHelperNext

    // 7. Let result be CreateIteratorFromClosure(closure, "Iterator Helper",
    //    %IteratorHelperPrototype%).
    // 8. Set result.[[UnderlyingIterator]] to iterated.
    // 9. Return result.
    return NewJSIteratorTakeHelper(iterated, integerLimit);
  } label RangeError deferred {
    ThrowRangeError(MessageTemplate::kMustBePositive, limit);
  }
}

transitioning builtin IteratorTakeHelperNext(
    implicit context: Context)(helper: JSIteratorTakeHelper): JSAny {
  // a. Let remaining be integerLimit.
  // (Done when creating JSIteratorTakeHelper.)

  const fastIteratorResultMap = GetIteratorResultMap();
  const underlying = MarkIteratorHelperAsExecuting(helper);
  const remaining = helper.remaining;

  try {
    // b. Repeat,
    let next: JSReceiver;

    // i. If remaining is 0, then
    if (remaining == 0) {
      // 1. Return ? IteratorClose(iterated, NormalCompletion(undefined)).
      MarkIteratorHelperAsExhausted(helper);
      IteratorClose(underlying);
      return AllocateJSIteratorResult(Undefined, True);
    }

    // ii. If remaining is not +∞, then
    if (!NumberIsSomeInfinity(remaining)) {
      // 1. Set remaining to remaining - 1.
      helper.remaining = remaining - 1;
    }

    try {
      // iii. Let next be ? IteratorStep(iterated).
      next = IteratorStep(underlying, fastIteratorResultMap)
          otherwise Done;
    } label Done {
      // iv. If next is false, return undefined.
      MarkIteratorHelperAsExhausted(helper);
      return AllocateJSIteratorResult(Undefined, True);
    }

    // v. Let completion be Completion(Yield(? IteratorValue(next))).
    const value = IteratorValue(next, fastIteratorResultMap);
    MarkIteratorHelperAsFinishedExecuting(helper, underlying);
    return AllocateJSIteratorResult(value, False);

    // vi. IfAbruptCloseIterator(completion, iterated).
    // (Done in IteratorHelperPrototypeReturn.)
  } catch (e, message) {
    MarkIteratorHelperAsExhausted(helper);
    ReThrowWithMessage(context, e, message);
  }
}

// --- drop helper

macro NewJSIteratorDropHelper(
    implicit context: Context)(underlying: IteratorRecord,
    limit: Number): JSIteratorDropHelper {
  return new JSIteratorDropHelper{
    map: *NativeContextSlot(ContextSlot::ITERATOR_DROP_HELPER_MAP_INDEX),
    properties_or_hash: kEmptyFixedArray,
    elements: kEmptyFixedArray,
    underlying_object: underlying.object,
    underlying_next: underlying.next,
    remaining: limit
  };
}

// https://tc39.es/proposal-iterator-helpers/#sec-iteratorprototype.drop
transitioning javascript builtin IteratorPrototypeDrop(
    js-implicit context: NativeContext, receiver: JSAny)(
    limit: JSAny): JSIteratorDropHelper {
  try {
    const methodName: constexpr string = 'Iterator.prototype.drop';
    IncrementUseCounter(context, SmiConstant(kIteratorMethods));

    // 1. Let O be the this value.
    // 2. If O is not an Object, throw a TypeError exception.
    const o = Cast<JSReceiver>(receiver)
        otherwise ThrowTypeError(MessageTemplate::kCalledOnNonObject, methodName);

    // 3. Let numLimit be ? ToNumber(limit).
    const numLimit = ToNumber_Inline(limit);

    // 4. If numLimit is NaN, throw a RangeError exception.
    if (NumberIsNaN(numLimit)) goto RangeError;

    // 5. Let integerLimit be ! ToIntegerOrInfinity(numLimit).
    const integerLimit = ToInteger_Inline(numLimit);

    // 6. If integerLimit < 0, throw a RangeError exception.
    if (integerLimit < 0) goto RangeError;

    // 5. Let iterated be ? GetIteratorDirect(O).
    const iterated = GetIteratorDirect(o);

    // Step 6 implemented in IteratorDropHelperNext

    // 7. Let result be CreateIteratorFromClosure(closure, "Iterator Helper",
    //    %IteratorHelperPrototype%).
    // 8. Set result.[[UnderlyingIterator]] to iterated.
    // 9. Return result.
    return NewJSIteratorDropHelper(iterated, integerLimit);
  } label RangeError deferred {
    ThrowRangeError(MessageTemplate::kMustBePositive, limit);
  }
}

transitioning builtin IteratorDropHelperNext(
    implicit context: Context)(helper: JSIteratorDropHelper): JSAny {
  // a. Let remaining be integerLimit.
  // (Done when creating JSIteratorDropHelper.)

  const fastIteratorResultMap = GetIteratorResultMap();
  const underlying = MarkIteratorHelperAsExecuting(helper);
  let remaining = helper.remaining;
  let next: JSReceiver;

  try {
    // b. Repeat, while remaining > 0,
    try {
      while (remaining > 0) {
        // i. If remaining is not +∞, then
        if (!NumberIsSomeInfinity(remaining)) {
          // 1. Set remaining to remaining - 1.
          remaining = remaining - 1;
          helper.remaining = remaining;
        }

        // ii. Let next be ? IteratorStep(iterated).
        IteratorStep(underlying, fastIteratorResultMap)
            otherwise Done;
      }

      // c. Repeat,
      // i. Let next be ? IteratorStep(iterated).
      next = IteratorStep(underlying, fastIteratorResultMap)
          otherwise Done;
    } label Done {
      // ii. If next is false, return undefined.
      MarkIteratorHelperAsExhausted(helper);
      return AllocateJSIteratorResult(Undefined, True);
    }

    // iii. Let completion be Completion(Yield(? IteratorValue(next))).
    const value = IteratorValue(next, fastIteratorResultMap);
    MarkIteratorHelperAsFinishedExecuting(helper, underlying);
    return AllocateJSIteratorResult(value, False);

    // iv. IfAbruptCloseIterator(completion, iterated).
    // (Done in IteratorHelperPrototypeReturn.)
  } catch (e, message) {
    MarkIteratorHelperAsExhausted(helper);
    ReThrowWithMessage(context, e, message);
  }
}

// --- flatMap helper

const kFlatMapMethodName: constexpr string = 'Iterator.prototype.flatMap';

macro NewJSIteratorFlatMapHelper(
    implicit context: Context)(underlying: IteratorRecord,
    mapper: Callable): JSIteratorFlatMapHelper {
  return new JSIteratorFlatMapHelper{
    map: *NativeContextSlot(ContextSlot::ITERATOR_FLAT_MAP_HELPER_MAP_INDEX),
    properties_or_hash: kEmptyFixedArray,
    elements: kEmptyFixedArray,
    underlying_object: underlying.object,
    underlying_next: underlying.next,
    mapper: mapper,
    counter: 0,
    innerIterator: underlying,
    innerAlive: False
  };
}

// https://tc39.es/proposal-iterator-helpers/#sec-iteratorprototype.flatmap
transitioning javascript builtin IteratorPrototypeFlatMap(
    js-implicit context: NativeContext, receiver: JSAny)(
    mapper: JSAny): JSIteratorFlatMapHelper {
  IncrementUseCounter(context, SmiConstant(kIteratorMethods));
  // 1. Let O be the this value.
  // 2. If O is not an Object, throw a TypeError exception.
  const o = Cast<JSReceiver>(receiver)
      otherwise ThrowTypeError(
      MessageTemplate::kCalledOnNonObject, kFlatMapMethodName);

  // 3. If IsCallable(mapper) is false, throw a TypeError exception.
  const mapper = Cast<Callable>(mapper)
      otherwise ThrowTypeError(
      MessageTemplate::kCalledNonCallable, kFlatMapMethodName);

  // 4. Let iterated be ? GetIteratorDirect(O).
  const iterated = GetIteratorDirect(o);

  // Step 5 implemented in IteratorFlatMapHelperNext

  // 6. Let result be CreateIteratorFromClosure(closure, "Iterator Helper",
  //    %IteratorHelperPrototype%).
  // 7. Set result.[[UnderlyingIterator]] to iterated.
  // 8. Return result.
  return NewJSIteratorFlatMapHelper(iterated, mapper);
}

transitioning builtin IteratorFlatMapHelperNext(
    implicit context: Context)(helper: JSIteratorFlatMapHelper): JSAny {
  // a. Let counter be 0.
  // (Done when creating JSIteratorFlatMapHelper.)

  const fastIteratorResultMap = GetIteratorResultMap();
  const underlying = MarkIteratorHelperAsExecuting(helper);

  try {
    while (true) {
      const counter = helper.counter;
      let innerIterator = helper.innerIterator;
      // b. Repeat,
      if (helper.innerAlive == False) {
        let next: JSReceiver;
        try {
          // i. Let next be ? IteratorStep(iterated).
          next = IteratorStep(underlying, fastIteratorResultMap)
              otherwise Done;
        } label Done {
          // ii. If next is false, return undefined.
          MarkIteratorHelperAsExhausted(helper);
          return AllocateJSIteratorResult(Undefined, True);
        }

        // iii. Let value be ? IteratorValue(next).
        const value = IteratorValue(next, fastIteratorResultMap);

        try {
          // iv. Let mapped be Completion(
          //     Call(mapper, undefined, « value, 𝔽(counter) »)).
          const mapped =
              Call(context, helper.mapper, Undefined, value, counter);
          const mappedIter = Cast<JSReceiver>(mapped)
              otherwise ThrowTypeError(
              MessageTemplate::kCalledOnNonObject, kFlatMapMethodName);

          // vi. Let innerIterator be Completion(GetIteratorFlattenable(mapped,
          //     reject-strings)).
          innerIterator = GetIteratorFlattenable(mappedIter);
          helper.innerIterator = innerIterator;

          // viii. Let innerAlive be true.
          helper.innerAlive = True;

        } catch (e, message) {
          // v. IfAbruptCloseIterator(mapped, iterated)
          IteratorCloseOnException(underlying);
          ReThrowWithMessage(context, e, message);
        }
        // x. Set counter to counter + 1.
        helper.counter = counter + 1;
      }

      // ix. Repeat, while innerAlive is true,
      try {
        // 1. Let innerNext be Completion(IteratorStep(innerIterator)).
        let innerNext: JSReceiver;
        innerNext = IteratorStep(innerIterator, fastIteratorResultMap)
            otherwise Done;

        // 4. Else,
        //    a. Let innerValue be Completion(IteratorValue(innerNext)).
        const innerValue = IteratorValue(innerNext, fastIteratorResultMap);

        // c. Let completion be Completion(Yield(innerValue)).
        MarkIteratorHelperAsFinishedExecuting(helper, underlying);
        return AllocateJSIteratorResult(innerValue, False);

        // d. If completion is an abrupt completion, then
        //    i. Let backupCompletion be Completion(IteratorClose(innerIterator,
        // completion)).
        //    ii. IfAbruptCloseIterator(backupCompletion, iterated).
        //    iii. Return ? IteratorClose(completion, iterated).
        // Done in IteratorHelperPrototypeReturn.

      } catch (e, message) {
        // 2. IfAbruptCloseIterator(innerNext, iterated)
        IteratorCloseOnException(underlying);
        ReThrowWithMessage(context, e, message);
      } label Done {
        // 3. If innerNext is false, then
        //    a. Set innerAlive to false.
        helper.innerAlive = False;
      }
    }
  } catch (e, message) {
    MarkIteratorHelperAsExhausted(helper);
    ReThrowWithMessage(context, e, message);
  }
  unreachable;
}

// --- reduce helper

// https://tc39.es/proposal-iterator-helpers/#sec-iteratorprototype.reduce
transitioning javascript builtin IteratorPrototypeReduce(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const methodName: constexpr string = 'Iterator.prototype.reduce';
  IncrementUseCounter(context, SmiConstant(kIteratorMethods));

  // 1. Let O be the this value.
  // 2. If O is not an Object, throw a TypeError exception.
  const o = Cast<JSReceiver>(receiver)
      otherwise ThrowTypeError(MessageTemplate::kCalledOnNonObject, methodName);

  // 3. If IsCallable(reducer) is false, throw a TypeError exception.
  const reducer = Cast<Callable>(arguments[0])
      otherwise ThrowCalledNonCallable(methodName);

  // 4. Let iterated be ? GetIteratorDirect(O).
  const iterated = GetIteratorDirect(o);

  const fastIteratorResultMap = GetIteratorResultMap();
  let next: JSReceiver;
  let accumulator: JSAny;
  let counter: Number;

  // 5. If initialValue is not present, then
  if (arguments.length == 1) {
    //   a. Let next be ? IteratorStep(iterated).
    //   b. If next is false, throw a TypeError exception.
    next = IteratorStep(iterated, fastIteratorResultMap)
        otherwise ThrowTypeError(
        MessageTemplate::kIteratorReduceNoInitial, methodName);
    //   c. Let accumulator be ? IteratorValue(next).
    accumulator = IteratorValue(next, fastIteratorResultMap);
    //   d. Let counter be 1.
    counter = 1;
  } else {
    // 6. Else,
    //   a. Let accumulator be initialValue.
    accumulator = arguments[1];
    //   b. Let counter be 0.
    counter = 0;
  }

  // 7. Repeat,
  while (true) {
    try {
      //  a. Let next be ? IteratorStep(iterated).
      next = IteratorStep(iterated, fastIteratorResultMap)
          otherwise Done;
    } label Done {
      //  b. If next is false, return accumulator.
      return accumulator;
    }

    //  c. Let value be ? IteratorValue(next).
    const value = IteratorValue(next, fastIteratorResultMap);

    try {
      //  d. Let result be Completion(Call(reducer, undefined, « accumulator,
      //  value, 𝔽(counter) »)).
      const result =
          Call(context, reducer, Undefined, accumulator, value, counter);

      //  f. Set accumulator to result.[[Value]].
      accumulator = result;

      //  g. Set counter to counter + 1.
      counter = counter + 1;

    } catch (e, message) {
      //  e. IfAbruptCloseIterator(result, iterated).
      IteratorCloseOnException(iterated);
      ReThrowWithMessage(context, e, message);
    }
  }
  unreachable;
}

// --- toArray helper

// https://tc39.es/proposal-iterator-helpers/#sec-iteratorprototype.toarray
transitioning javascript builtin IteratorPrototypeToArray(
    js-implicit context: NativeContext, receiver: JSAny)(): JSAny {
  const methodName: constexpr string = 'Iterator.prototype.toArray';
  IncrementUseCounter(context, SmiConstant(kIteratorMethods));

  // 1. Let O be the this value.
  // 2. If O is not an Object, throw a TypeError exception.
  const o = Cast<JSReceiver>(receiver)
      otherwise ThrowTypeError(MessageTemplate::kCalledOnNonObject, methodName);

  // 3. Let iterated be ? GetIteratorDirect(O).
  const iterated = GetIteratorDirect(o);

  // 4. Let items be a new empty List.
  let items = growable_fixed_array::NewGrowableFixedArray();

  const fastIteratorResultMap = GetIteratorResultMap();
  let next: JSReceiver;

  // 5. Repeat,
  while (true) {
    try {
      //  a. Let next be ? IteratorStep(iterated).
      next = IteratorStep(iterated, fastIteratorResultMap)
          otherwise Done;
    } label Done {
      //  b. If next is false, return CreateArrayFromList(items).
      return items.ToJSArray();
    }

    //  c. Let value be ? IteratorValue(next).
    const value = IteratorValue(next, fastIteratorResultMap);

    //  d. Append value to items.
    items.Push(value);
  }
  unreachable;
}

// --- forEach helper

// https://tc39.es/proposal-iterator-helpers/#sec-iteratorprototype.foreach
transitioning javascript builtin IteratorPrototypeForEach(
    js-implicit context: NativeContext, receiver: JSAny)(fn: JSAny): JSAny {
  const methodName: constexpr string = 'Iterator.prototype.forEach';
  IncrementUseCounter(context, SmiConstant(kIteratorMethods));

  // 1. Let O be the this value.
  // 2. If O is not an Object, throw a TypeError exception.
  const o = Cast<JSReceiver>(receiver)
      otherwise ThrowTypeError(MessageTemplate::kCalledOnNonObject, methodName);

  // 3. If IsCallable(fn) is false, throw a TypeError exception.
  const fn = Cast<Callable>(fn)
      otherwise ThrowCalledNonCallable(methodName);

  // 4. Let iterated be ? GetIteratorDirect(O).
  const iterated = GetIteratorDirect(o);

  // 5. Let counter be 0.
  let counter: Number = 0;

  const fastIteratorResultMap = GetIteratorResultMap();

  // 5. Repeat,
  while (true) {
    let next: JSReceiver;
    try {
      //  a. Let next be ? IteratorStep(iterated).
      next = IteratorStep(iterated, fastIteratorResultMap)
          otherwise Done;
    } label Done {
      //  b. If next is false, return undefined.
      return Undefined;
    }

    //  c. Let value be ? IteratorValue(next).
    const value = IteratorValue(next, fastIteratorResultMap);

    try {
      //  d. Let result be Completion(Call(fn, undefined, « value, 𝔽(counter)
      //  »)).
      Call(context, fn, Undefined, value, counter);

      //  f. Set counter to counter + 1.
      counter = counter + 1;
    } catch (e, message) {
      //  e. IfAbruptCloseIterator(result, iterated).
      IteratorCloseOnException(iterated);
      ReThrowWithMessage(context, e, message);
    }
  }
  unreachable;
}

// --- some helper

// https://tc39.es/proposal-iterator-helpers/#sec-iteratorprototype.some
transitioning javascript builtin IteratorPrototypeSome(
    js-implicit context: NativeContext, receiver: JSAny)(
    predicate: JSAny): JSAny {
  const methodName: constexpr string = 'Iterator.prototype.some';
  IncrementUseCounter(context, SmiConstant(kIteratorMethods));

  // 1. Let O be the this value.
  // 2. If O is not an Object, throw a TypeError exception.
  const o = Cast<JSReceiver>(receiver)
      otherwise ThrowTypeError(MessageTemplate::kCalledOnNonObject, methodName);

  // 3. If IsCallable(predicate) is false, throw a TypeError exception.
  const predicate = Cast<Callable>(predicate)
      otherwise ThrowCalledNonCallable(methodName);

  // 4. Let iterated be ? GetIteratorDirect(O).
  const iterated = GetIteratorDirect(o);

  // 5. Let counter be 0.
  let counter: Number = 0;

  const fastIteratorResultMap = GetIteratorResultMap();

  // 5. Repeat,
  while (true) {
    let next: JSReceiver;
    try {
      //  a. Let next be ? IteratorStep(iterated).
      next = IteratorStep(iterated, fastIteratorResultMap)
          otherwise Done;
    } label Done {
      //  b. If next is false, return false.
      return False;
    }

    //  c. Let value be ? IteratorValue(next).
    const value = IteratorValue(next, fastIteratorResultMap);

    let result: JSAny;
    try {
      //  d. Let result be Completion(Call(predicate, undefined, « value,
      //  𝔽(counter) »)).
      result = Call(context, predicate, Undefined, value, counter);
    } catch (e, message) {
      //  e. IfAbruptCloseIterator(result, iterated).
      IteratorCloseOnException(iterated);
      ReThrowWithMessage(context, e, message);
    }

    //  f. If ToBoolean(result) is true, return ? IteratorClose(iterated,
    //  NormalCompletion(true)).
    if (ToBoolean(result) == true) {
      IteratorClose(iterated);
      return True;
    }

    //  g. Set counter to counter + 1.
    counter = counter + 1;
  }
  unreachable;
}

// --- every helper

// https://tc39.es/proposal-iterator-helpers/#sec-iteratorprototype.every
transitioning javascript builtin IteratorPrototypeEvery(
    js-implicit context: NativeContext, receiver: JSAny)(
    predicate: JSAny): JSAny {
  const methodName: constexpr string = 'Iterator.prototype.every';
  IncrementUseCounter(context, SmiConstant(kIteratorMethods));

  // 1. Let O be the this value.
  // 2. If O is not an Object, throw a TypeError exception.
  const o = Cast<JSReceiver>(receiver)
      otherwise ThrowTypeError(MessageTemplate::kCalledOnNonObject, methodName);

  // 3. If IsCallable(predicate) is false, throw a TypeError exception.
  const predicate = Cast<Callable>(predicate)
      otherwise ThrowCalledNonCallable(methodName);

  // 4. Let iterated be ? GetIteratorDirect(O).
  const iterated = GetIteratorDirect(o);

  // 5. Let counter be 0.
  let counter: Number = 0;

  const fastIteratorResultMap = GetIteratorResultMap();

  // 5. Repeat,
  while (true) {
    let next: JSReceiver;
    try {
      //  a. Let next be ? IteratorStep(iterated).
      next = IteratorStep(iterated, fastIteratorResultMap)
          otherwise Done;
    } label Done {
      //  b. If next is false, return true.
      return True;
    }

    //  c. Let value be ? IteratorValue(next).
    const value = IteratorValue(next, fastIteratorResultMap);

    let result: JSAny;
    try {
      //  d. Let result be Completion(Call(predicate, undefined, « value,
      //  𝔽(counter) »)).
      result = Call(context, predicate, Undefined, value, counter);
    } catch (e, message) {
      //  e. IfAbruptCloseIterator(result, iterated).
      IteratorCloseOnException(iterated);
      ReThrowWithMessage(context, e, message);
    }

    //  f. If ToBoolean(result) is false, return ? IteratorClose(iterated,
    //  NormalCompletion(false)).
    if (ToBoolean(result) == false) {
      IteratorClose(iterated);
      return False;
    }

    //  g. Set counter to counter + 1.
    counter = counter + 1;
  }
  unreachable;
}

// --- find helper

// https://tc39.es/proposal-iterator-helpers/#sec-iteratorprototype.find
transitioning javascript builtin IteratorPrototypeFind(
    js-implicit context: NativeContext, receiver: JSAny)(
    predicate: JSAny): JSAny {
  const methodName: constexpr string = 'Iterator.prototype.find';
  IncrementUseCounter(context, SmiConstant(kIteratorMethods));

  // 1. Let O be the this value.
  // 2. If O is not an Object, throw a TypeError exception.
  const o = Cast<JSReceiver>(receiver)
      otherwise ThrowTypeError(MessageTemplate::kCalledOnNonObject, methodName);

  // 3. If IsCallable(predicate) is false, throw a TypeError exception.
  const predicate = Cast<Callable>(predicate)
      otherwise ThrowCalledNonCallable(methodName);

  // 4. Let iterated be ? GetIteratorDirect(O).
  const iterated = GetIteratorDirect(o);

  // 5. Let counter be 0.
  let counter: Number = 0;

  const fastIteratorResultMap = GetIteratorResultMap();

  // 5. Repeat,
  while (true) {
    let next: JSReceiver;
    try {
      //  a. Let next be ? IteratorStep(iterated).
      next = IteratorStep(iterated, fastIteratorResultMap)
          otherwise Done;
    } label Done {
      //  b. If next is false, return undefined.
      return Undefined;
    }

    //  c. Let value be ? IteratorValue(next).
    const value = IteratorValue(next, fastIteratorResultMap);

    let result: JSAny;
    try {
      //  d. Let result be Completion(Call(predicate, undefined, « value,
      //  𝔽(counter) »)).
      result = Call(context, predicate, Undefined, value, counter);
    } catch (e, message) {
      //  e. IfAbruptCloseIterator(result, iterated).
      IteratorCloseOnException(iterated);
      ReThrowWithMessage(context, e, message);
    }

    //  f. If ToBoolean(result) is true, return ? IteratorClose(iterated,
    //  NormalCompletion(value)).
    if (ToBoolean(result) == true) {
      IteratorClose(iterated);
      return value;
    }

    //  g. Set counter to counter + 1.
    counter = counter + 1;
  }
  unreachable;
}

}  // namespace iterator
```