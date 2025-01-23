Response: Let's break down the thought process for analyzing this Torque code.

1. **Understand the Goal:** The first step is to realize this is a V8 implementation of `Array.prototype.splice()`. The filename `array-splice.tq` and the comment mentioning the ECMAScript specification are strong hints.

2. **High-Level Structure:** Recognize the `namespace array { ... }` structure indicates this code belongs to the array-related builtins. The `transitioning macro` and `macro` keywords point to Torque's syntax for defining reusable code blocks. The `javascript builtin` declaration at the end confirms the main entry point.

3. **Identify Key Macros and Their Purpose:**  Go through the code and try to understand what each macro does individually. Look for descriptive names and comments.

    * **`Extract`:** The comments clearly state it's for creating a new array with copied elements. The two overloads handle different array types (FixedArray and FixedDoubleArray/EmptyFixedArray).
    * **`DoMoveElements` and `DoCopyElements`:** The names and the `TorqueMoveElements`/`TorqueCopyElements` calls suggest these are low-level memory manipulation operations.
    * **`StoreHoles`:**  The name and the `StoreArrayHole` call indicate it's responsible for filling array slots with holes (undefined values).
    * **`InsertArgumentsIntoFastPackedArray`:**  This macro deals with inserting arguments into a fast array, paying attention to element types.
    * **`FastSplice`:**  The name suggests an optimized path for `splice`. It handles cases where the array elements can be manipulated directly without major reallocations. The logic for shrinking and potentially growing the array is present.
    * **`TransitionElementsKindForInsertionIfNeeded`:** This is about type transitions. If you insert a non-integer into an array of integers, the array's underlying storage needs to change.
    * **`FastArraySplice`:** This is the main fast path for `splice`. It checks preconditions and calls `FastSplice` or falls back to the slow path.
    * **`FillDeletedElementsArray`:**  This macro is responsible for creating the array of deleted elements that `splice` returns.
    * **`HandleForwardCase` and `HandleBackwardCase`:** These handle the element shifting when the number of inserted elements is less than or greater than the number of deleted elements in the "slow" path.
    * **`SlowSplice`:**  This is the more general, spec-compliant implementation of `splice`.
    * **`ArrayPrototypeSplice`:** This is the main entry point, the JavaScript builtin function. It handles argument parsing and decides whether to take the fast or slow path.

4. **Trace the Control Flow:** Follow the execution path of `ArrayPrototypeSplice`. Notice the initial setup, argument parsing, the attempt at `FastArraySplice`, and the fallback to `SlowSplice`.

5. **Focus on the Fast Path:** The `FastSplice` macro is crucial for optimization. Understand how it moves elements, handles shrinking and potentially growing the backing storage, and inserts new arguments. The checks in `FastArraySplice` reveal the conditions under which this fast path is taken (e.g., fast elements, writable length, no prototype modifications).

6. **Analyze the Slow Path:** The `SlowSplice` macro implements the standard `splice` behavior. Pay attention to how it creates the array of deleted elements (`FillDeletedElementsArray`) and how it shifts elements (`HandleForwardCase`, `HandleBackwardCase`).

7. **Connect to JavaScript:**  Think about how the operations in the Torque code translate to JavaScript behavior. For example, `DoMoveElements` and `DoCopyElements` are the underlying mechanisms for how elements shift when you use `splice`. The element kind transitions are why you can have arrays containing a mix of types in JavaScript.

8. **Infer Input/Output and Error Scenarios:**

    * **Input/Output:** Choose simple examples of `splice` calls and manually trace how the code would behave. Consider cases with insertions, deletions, and replacements.
    * **Common Errors:**  Think about what mistakes developers make when using `splice`. Incorrect start and delete counts are prime examples. The code itself reveals potential errors like exceeding the maximum safe integer for array length.

9. **Refine and Organize:**  Structure the findings clearly. Start with a general summary, then delve into specific aspects like fast vs. slow paths, input/output, and error scenarios. Use JavaScript examples to illustrate the concepts.

**Self-Correction/Refinement During Analysis:**

* **Initial Misunderstanding:**  Perhaps initially I might not fully grasp the difference between `FixedArray` and `FixedDoubleArray`. Reading the comments and seeing where they are used clarifies this (one for general objects, one optimized for numbers).
* **Overlooking Details:** I might initially skim over the `TransitionElementsKindForInsertionIfNeeded` macro. Realizing its importance for JavaScript's dynamic typing requires a second look.
* **Confusing Macros:**  Some macros might seem similar at first. Distinguishing their precise roles (e.g., `DoMoveElements` vs. `DoCopyElements`) requires careful examination of their parameters and how they are used.
* **Not Connecting to the Spec:**  If I didn't recognize this as a `splice` implementation, I'd need to look up the ECMAScript specification for `Array.prototype.splice()` to understand the expected behavior. The comments in the code explicitly refer to the spec, which is a strong clue.

By following these steps, including the process of identifying, understanding, connecting, and refining, you can effectively analyze and summarize complex code like this V8 Torque source.
这个V8 Torque 源代码文件 `v8/src/builtins/array-splice.tq` 实现了 JavaScript 中 `Array.prototype.splice()` 方法的核心逻辑。它包含了快速路径优化和慢速的、更符合规范的实现。

**功能归纳:**

该文件主要负责实现以下功能：

1. **删除数组元素:** 根据指定的起始索引和删除计数，从数组中移除元素。
2. **插入数组元素:**  根据指定的起始索引，将新的元素插入到数组中。
3. **返回被删除的元素:**  创建一个包含被删除元素的新的数组并返回。
4. **调整数组长度:**  根据插入和删除的元素数量，更新数组的 `length` 属性。
5. **优化快速路径:**  针对特定场景（例如，可写的 fast elements 数组），提供优化的执行路径以提高性能。
6. **处理元素类型转换:**  在插入新元素时，根据需要处理数组的元素类型转换（例如，从 `SMI` 到 `Double` 或 `Object`）。
7. **遵循 ECMAScript 规范:**  在慢速路径中，严格按照 ECMAScript 规范实现 `splice()` 方法的行为。

**与 JavaScript 功能的关系及示例:**

`Array.prototype.splice()` 是 JavaScript 数组对象的一个内置方法，用于修改数组内容。该 Torque 文件就是 V8 引擎中实现这个方法的底层代码。

**JavaScript 示例:**

```javascript
const arr = [1, 2, 3, 4, 5];

// 删除从索引 1 开始的 2 个元素 (2 和 3)
const removed1 = arr.splice(1, 2);
console.log(arr);       // 输出: [1, 4, 5]
console.log(removed1);  // 输出: [2, 3]

// 从索引 1 开始删除 0 个元素，并插入 'a' 和 'b'
const removed2 = arr.splice(1, 0, 'a', 'b');
console.log(arr);       // 输出: [1, 'a', 'b', 4, 5]
console.log(removed2);  // 输出: []

// 从索引 2 开始删除 1 个元素 ('b')，并插入 'c'
const removed3 = arr.splice(2, 1, 'c');
console.log(arr);       // 输出: [1, 'a', 'c', 4, 5]
console.log(removed3);  // 输出: ['b']
```

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

* `a`: 一个 JavaScript 数组 `[10, 20, 30, 40, 50]` (假设是 fast elements 类型)
* `actualStart`: `1` (起始索引)
* `actualDeleteCount`: `2` (删除计数)
* `insertCount`: `1` (插入元素个数)
* `args`:  `splice(1, 2, 'new')` 对应的 Arguments 对象，其中包含 'new' 这个插入元素。

**基于 `FastSplice` 宏的推理:**

1. **`insertCount != actualDeleteCount` (1 != 2):** 进入条件。
2. **`insertCount < actualDeleteCount` (1 < 2):** 进入 shrink 分支。
3. **`DoMoveElements`:** 将索引 `3` (实际是元素 `40`) 和 `4` (元素 `50`) 的元素移动到索引 `1 + 1 = 2` 和 `3` 的位置。数组变为 `[10, 40, 50, 40, 50]` (移动后可能存在重复，后续会被覆盖或置空)。
4. **`StoreHoles`:** 将索引 `5 - 2 + 1 = 4` (newLength) 到 `5` (length) 的位置填充为 holes (undefined)。数组变为类似 `[10, 40, 50, undefined, undefined]`。
5. **`InsertArgumentsIntoFastPackedArray`:** 将 `args` 中索引 `2` 开始的 `insertCount` 个元素 ('new') 插入到数组 `a` 的 `actualStart` (1) 位置。数组变为 `[10, 'new', 50, undefined, undefined]`。
6. **`a.length = newLength`:** 设置数组的长度为 `5 - 2 + 1 = 4`。数组最终变为 `[10, 'new', 50, undefined]`，length 为 4。  注意，实际 V8 实现可能会有更精细的内存管理，这里为了简化推理，假设直接覆盖或置空。

**预期输出 (被删除的元素):**  `[20, 30]` (由 `ExtractFastJSArray` 或类似的机制创建和返回)

**注意:**  这只是 `FastSplice` 的一个简化推理。实际情况中，V8 会根据数组的具体类型和状态选择不同的优化路径。

**涉及用户常见的编程错误及示例:**

1. **`start` 参数超出数组索引范围:**
   ```javascript
   const arr = [1, 2, 3];
   arr.splice(5, 1); // start 超出范围，不会删除任何元素
   console.log(arr); // 输出: [1, 2, 3]
   ```
   V8 的实现会处理这种情况，`actualStart` 会被限制在有效范围内。

2. **`deleteCount` 为负数:**
   ```javascript
   const arr = [1, 2, 3];
   arr.splice(1, -1); // deleteCount 为负数，会被当作 0 处理，不会删除任何元素
   console.log(arr); // 输出: [1, 2, 3]
   ```
   代码中 `actualDeleteCount = Min(Max(dc, 0), len - actualStart)` 确保了 `actualDeleteCount` 不会小于 0。

3. **期望 `splice` 返回修改后的原数组，但它返回的是被删除的元素:**
   ```javascript
   const arr = [1, 2, 3];
   const removed = arr.splice(1, 1);
   console.log(arr);     // 输出: [1, 3]
   console.log(removed); // 输出: [2]  // 容易忘记 splice 的返回值
   ```

4. **在循环中使用 `splice` 可能导致索引错乱:**
   ```javascript
   const arr = [1, 2, 3, 4, 5];
   for (let i = 0; i < arr.length; i++) {
       if (arr[i] % 2 === 0) {
           arr.splice(i, 1); // 删除元素后，数组长度和后续元素索引会改变
       }
   }
   console.log(arr); // 输出可能不是期望的 [1, 3, 5]，因为删除元素后，索引会向前移动。
   ```
   正确的做法可能是在循环中倒序删除，或者使用 `filter` 等方法。

5. **误用 `splice` 的返回值进行链式操作:**
   ```javascript
   const arr = [1, 2, 3];
   arr.splice(1, 1).push(4); // 错误：splice 返回的是被删除的元素数组，没有 push 方法
   ```
   应该先 `splice` 修改原数组，然后再对原数组进行操作。

总结来说，`v8/src/builtins/array-splice.tq` 是 V8 引擎中实现 `Array.prototype.splice()` 这一重要 JavaScript 方法的关键代码，它既要保证功能的正确性，也要尽可能地优化性能。理解这段代码有助于深入了解 JavaScript 数组操作的底层实现机制。

### 提示词
```
这是目录为v8/src/builtins/array-splice.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

namespace array {
// Given {source}, we want to create a non-zero length array of type
// FixedArrayType with the specified {result_capacity}. Starting from
// {startIndex}, {count} number of elements are copied to the newly
// created result array. Most of this behavior is outsourced to
// ExtractFixedArray(). We handle the case where the {source} is
// EmptyFixedArray but result is expected to be a FixedDoubleArray.
macro Extract(
    implicit context: Context)(source: FixedArray, startIndex: Smi, count: Smi,
    resultCapacity: Smi): FixedArray {
  return ExtractFixedArray(
      source, Convert<intptr>(startIndex), Convert<intptr>(count),
      Convert<intptr>(resultCapacity), TheHole);
}

macro Extract(
    implicit context: Context)(source: FixedDoubleArray|EmptyFixedArray,
    startIndex: Smi, count: Smi, resultCapacity: Smi): FixedDoubleArray
    |EmptyFixedArray {
  typeswitch (source) {
    case (EmptyFixedArray): {
      // ExtractFixedDoubleArray expects {source} to be a FixedDoubleArray.
      // Handle the case where {source} is empty here.
      return AllocateFixedDoubleArrayWithHoles(Convert<intptr>(resultCapacity));
    }
    case (source: FixedDoubleArray): {
      return ExtractFixedDoubleArray(
          source, Convert<intptr>(startIndex), Convert<intptr>(count),
          Convert<intptr>(resultCapacity));
    }
  }
}

macro DoMoveElements<FixedArrayType : type extends FixedArrayBase>(
    elements: FixedArrayType, dstIndex: Smi, srcIndex: Smi, count: Smi): void {
  TorqueMoveElements(
      elements, Convert<intptr>(dstIndex), Convert<intptr>(srcIndex),
      Convert<intptr>(count));
}

macro StoreHoles<FixedArrayType : type extends FixedArrayBase>(
    elements: FixedArrayType, holeStartIndex: Smi, holeEndIndex: Smi): void {
  for (let i: Smi = holeStartIndex; i < holeEndIndex; i++) {
    array::StoreArrayHole(elements, i);
  }
}

macro DoCopyElements<FixedArrayType : type extends FixedArrayBase>(
    dstElements: FixedArrayType, dstIndex: Smi, srcElements: FixedArrayType,
    srcIndex: Smi, count: Smi): void {
  TorqueCopyElements(
      dstElements, Convert<intptr>(dstIndex), srcElements,
      Convert<intptr>(srcIndex), Convert<intptr>(count));
}

macro InsertArgumentsIntoFastPackedArray<
    FixedArrayType : type extends FixedArrayBase, ElementType: type>(
    dst: JSArray, dstStart: Smi, args: Arguments,
    argsStart: constexpr IntegerLiteral, insertCount: Smi): void {
  // Copy arguments.
  let k: Smi = dstStart;
  if (insertCount > 0) {
    dcheck(Convert<intptr>(insertCount) == args.length - argsStart);
    const typedNewElements: FixedArrayType =
        UnsafeCast<FixedArrayType>(dst.elements);
    for (let i: intptr = ConstexprIntegerLiteralToIntptr(argsStart);
         i < args.length; ++i) {
      const e: JSAny = args[i];
      // The argument elements were already validated to be an appropriate
      // {ElementType} to store in {FixedArrayType}.
      typedNewElements[k++] = UnsafeCast<ElementType>(e);
    }
  }
}

macro
FastSplice<FixedArrayType : type extends FixedArrayBase, ElementType: type>(
    implicit context: Context)(args: Arguments, a: JSArray, length: Smi,
    newLength: Smi, actualStart: Smi, insertCount: Smi,
    actualDeleteCount: Smi): void {
  // Make sure elements are writable.
  array::EnsureWriteableFastElements(a);

  if (insertCount != actualDeleteCount) {
    const elements = UnsafeCast<(FixedArrayType | EmptyFixedArray)>(a.elements);
    const dstIndex: Smi = actualStart + insertCount;
    const srcIndex: Smi = actualStart + actualDeleteCount;
    const count: Smi = length - actualDeleteCount - actualStart;
    if (insertCount < actualDeleteCount) {
      // Shrink.
      DoMoveElements(
          UnsafeCast<FixedArrayType>(elements), dstIndex, srcIndex, count);
      StoreHoles(UnsafeCast<FixedArrayType>(elements), newLength, length);
    } else if (insertCount > actualDeleteCount) {
      // If the backing store is big enough, then moving elements is enough.
      if (newLength <= elements.length) {
        DoMoveElements(
            UnsafeCast<FixedArrayType>(elements), dstIndex, srcIndex, count);
      } else {
        // Grow.
        const capacity: Smi = CalculateNewElementsCapacity(newLength);
        const newElements: FixedArrayType = UnsafeCast<FixedArrayType>(
            Extract(elements, 0, actualStart, capacity));
        a.elements = newElements;
        if (elements.length > 0) {
          DoCopyElements(
              newElements, dstIndex, UnsafeCast<FixedArrayType>(elements),
              srcIndex, count);
        }
      }
    }
  }

  // Copy arguments.
  InsertArgumentsIntoFastPackedArray<FixedArrayType, ElementType>(
      a, actualStart, args, 2, insertCount);

  // Update the array's length after all the FixedArray shuffling is done.
  a.length = newLength;
}

transitioning macro TransitionElementsKindForInsertionIfNeeded(
    context: Context, a: JSArray, originalElementsKind: ElementsKind,
    args: Arguments, argsStart: constexpr IntegerLiteral): ElementsKind {
  dcheck(a.map.elements_kind == originalElementsKind);

  let elementsKind = originalElementsKind;
  for (let k: intptr = ConstexprIntegerLiteralToIntptr(argsStart);
       k < args.length; ++k) {
    const e = args[k];
    if (IsFastSmiElementsKind(elementsKind)) {
      if (TaggedIsNotSmi(e)) {
        const heapObject: HeapObject = UnsafeCast<HeapObject>(e);
        elementsKind = IsHeapNumber(heapObject) ?
            AllowDoubleElements(elementsKind) :
            AllowNonNumberElements(elementsKind);
      }
    } else if (IsDoubleElementsKind(elementsKind)) {
      if (!IsNumber(e)) {
        elementsKind = AllowNonNumberElements(elementsKind);
      }
    } else {
      // Already generic.
      break;
    }
  }

  if (elementsKind != originalElementsKind) {
    const smiElementsKind: Smi = Convert<Smi>(Convert<int32>(elementsKind));
    TransitionElementsKindWithKind(context, a, smiElementsKind);
  }

  return elementsKind;
}

transitioning macro FastArraySplice(
    context: Context, args: Arguments, o: JSReceiver,
    originalLengthNumber: Number, actualStartNumber: Number, insertCount: Smi,
    actualDeleteCountNumber: Number): JSAny
    labels Bailout {
  const originalLength: Smi = Cast<Smi>(originalLengthNumber) otherwise Bailout;
  const actualStart: Smi = Cast<Smi>(actualStartNumber) otherwise Bailout;
  const actualDeleteCount: Smi =
      Cast<Smi>(actualDeleteCountNumber) otherwise Bailout;
  const lengthDelta: Smi = insertCount - actualDeleteCount;
  const newLength: Smi = originalLength + lengthDelta;

  const a: JSArray = Cast<JSArray>(o) otherwise Bailout;

  const map: Map = a.map;
  if (!IsPrototypeInitialArrayPrototype(map)) goto Bailout;
  if (IsNoElementsProtectorCellInvalid()) goto Bailout;
  if (IsArraySpeciesProtectorCellInvalid()) goto Bailout;

  // Fast path only works on fast elements kind and with writable length.
  let elementsKind: ElementsKind = EnsureArrayPushable(map) otherwise Bailout;
  if (!IsFastElementsKind(elementsKind)) goto Bailout;

  elementsKind = TransitionElementsKindForInsertionIfNeeded(
      context, a, elementsKind, args, 2);

  // Make sure that the length hasn't been changed by side-effect.
  const length: Smi = Cast<Smi>(a.length) otherwise Bailout;
  if (originalLength != length) goto Bailout;

  const deletedResult: JSArray =
      ExtractFastJSArray(context, a, actualStart, actualDeleteCount);

  if (newLength == 0) {
    a.elements = kEmptyFixedArray;
    a.length = 0;
    return deletedResult;
  }

  if (IsFastSmiOrTaggedElementsKind(elementsKind)) {
    FastSplice<FixedArray, JSAny>(
        args, a, length, newLength, actualStart, insertCount,
        actualDeleteCount);
  } else {
    FastSplice<FixedDoubleArray, Number>(
        args, a, length, newLength, actualStart, insertCount,
        actualDeleteCount);
  }

  return deletedResult;
}

transitioning macro FillDeletedElementsArray(
    context: Context, o: JSReceiver, actualStart: Number,
    actualDeleteCount: Number, a: JSReceiver): JSAny {
  // 10. Let k be 0.
  let k: Number = 0;

  // 11. Repeat, while k < actualDeleteCount
  while (k < actualDeleteCount) {
    // a. Let from be ! ToString(actualStart + k).
    const from: Number = actualStart + k;

    // b. Let fromPresent be ? HasProperty(O, from).
    const fromPresent: Boolean = HasProperty(o, from);

    // c. If fromPresent is true, then
    if (fromPresent == True) {
      // i. Let fromValue be ? Get(O, from).
      const fromValue: JSAny = GetProperty(o, from);

      // ii. Perform ? CreateDataPropertyOrThrow(A, ! ToString(k), fromValue).
      FastCreateDataProperty(a, k, fromValue);
    }

    // d. Increment k by 1.
    k++;
  }
  // 12. Perform ? Set(A, "length", actualDeleteCount, true).
  SetProperty(a, kLengthString, actualDeleteCount);
  return a;
}

// HandleForwardCase implements step 15. "If itemCount < actualDeleteCount,
// then...""
transitioning macro HandleForwardCase(
    context: Context, o: JSReceiver, len: Number, itemCount: Number,
    actualStart: Number, actualDeleteCount: Number): void {
  // 15. If itemCount < actualDeleteCount, then
  // a. Let k be actualStart.
  let k: Number = actualStart;

  // b. Repeat, while k < (len - actualDeleteCount)
  while (k < (len - actualDeleteCount)) {
    // i. Let from be ! ToString(k + actualDeleteCount).
    const from: Number = k + actualDeleteCount;
    // ii. Let to be ! ToString(k + itemCount).
    const to: Number = k + itemCount;

    // iii. Let fromPresent be ? HasProperty(O, from).
    const fromPresent: Boolean = HasProperty(o, from);

    // iv. If fromPresent is true, then
    if (fromPresent == True) {
      // 1. Let fromValue be ? Get(O, from).
      const fromValue: JSAny = GetProperty(o, from);

      // 2. Perform ? Set(O, to, fromValue, true).
      SetProperty(o, to, fromValue);

      // v. Else fromPresent is false,
    } else {
      // 1. Perform ? DeletePropertyOrThrow(O, to).
      DeleteProperty(o, to, LanguageMode::kStrict);
    }
    // vi. Increase k by 1.
    k++;
  }

  // c. Let k be len.
  k = len;

  // d. Repeat, while k > (len - actualDeleteCount + itemCount)
  while (k > (len - actualDeleteCount + itemCount)) {
    // i. Perform ? DeletePropertyOrThrow(O, ! ToString(k - 1)).
    DeleteProperty(o, k - 1, LanguageMode::kStrict);
    // ii. Decrease k by 1.
    k--;
  }
}

// HandleBackwardCase implements step 16. "Else if itemCount >
// actualDeleteCount, then..."
transitioning macro HandleBackwardCase(
    context: Context, o: JSReceiver, len: Number, itemCount: Number,
    actualStart: Number, actualDeleteCount: Number): void {
  // 16. Else if itemCount > actualDeleteCount, then
  // a. Let k be (len - actualDeleteCount).
  let k: Number = len - actualDeleteCount;

  // b. Repeat, while k > actualStart
  while (k > actualStart) {
    // i. Let from be ! ToString(k + actualDeleteCount - 1).
    const from: Number = k + actualDeleteCount - 1;

    // ii. Let to be ! ToString(k + itemCount - 1).
    const to: Number = k + itemCount - 1;

    // iii. Let fromPresent be ? HasProperty(O, from).
    const fromPresent: Boolean = HasProperty(o, from);

    // iv. If fromPresent is true, then
    if (fromPresent == True) {
      // 1. Let fromValue be ? Get(O, from).
      const fromValue: JSAny = GetProperty(o, from);

      // 2. Perform ? Set(O, to, fromValue, true).
      SetProperty(o, to, fromValue);

      // v. Else fromPresent is false,
    } else {
      // 1. Perform ? DeletePropertyOrThrow(O, to).
      DeleteProperty(o, to, LanguageMode::kStrict);
    }

    // vi. Decrease k by 1.
    k--;
  }
}

transitioning macro SlowSplice(
    context: Context, arguments: Arguments, o: JSReceiver, len: Number,
    actualStart: Number, insertCount: Smi, actualDeleteCount: Number): JSAny {
  // 9. Let A be ? ArraySpeciesCreate(O, actualDeleteCount).
  const a: JSReceiver = ArraySpeciesCreate(context, o, actualDeleteCount);
  const itemCount: Number = insertCount;

  // Steps 9 through 12: creating the array of deleted elements.
  FillDeletedElementsArray(context, o, actualStart, actualDeleteCount, a);

  // 13. Let items be a List whose elements are, in left-to-right order,
  //     the portion of the actual argument list starting with the third
  //     argument. The list is empty if fewer than three arguments were
  //     passed.
  // 14. Let itemCount be the Number of elements in items.
  // (done above).

  // 15. If itemCount < actualDeleteCount, then
  if (itemCount < actualDeleteCount) {
    HandleForwardCase(
        context, o, len, itemCount, actualStart, actualDeleteCount);
    // 16. Else if itemCount > actualDeleteCount, then
  } else if (itemCount > actualDeleteCount) {
    HandleBackwardCase(
        context, o, len, itemCount, actualStart, actualDeleteCount);
  }

  // 17. Let k be actualStart.
  let k: Number = actualStart;

  // 18. Repeat, while items is not empty
  //   a. Remove the first element from items and let E be the value of that
  //   element.
  if (arguments.length > 2) {
    for (let i: intptr = 2; i < arguments.length; ++i) {
      const e: JSAny = arguments[i];
      // b. Perform ? Set(O, ! ToString(k), E, true).
      SetProperty(o, k, e);

      // c. Increase k by 1.
      k = k + 1;
    }
  }

  // 19. Perform ? Set(O, "length", len - actualDeleteCount + itemCount,
  // true).
  SetProperty(o, kLengthString, len - actualDeleteCount + itemCount);

  return a;
}

// https://tc39.github.io/ecma262/#sec-array.prototype.splice
transitioning javascript builtin ArrayPrototypeSplice(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  // 1. Let O be ? ToObject(this value).
  const o: JSReceiver = ToObject(context, receiver);

  // 2. Let len be ? ToLength(? Get(O, "length")).
  const len: Number = GetLengthProperty(o);

  // 3. Let relativeStart be ? ToInteger(start).
  const start: JSAny = arguments[0];
  const relativeStart: Number = ToInteger_Inline(start);

  // 4. If relativeStart < 0, let actualStart be max((len + relativeStart),
  // 0);
  //    else let actualStart be min(relativeStart, len).
  const actualStart: Number = relativeStart < 0 ?
      Max((len + relativeStart), 0) :
      Min(relativeStart, len);

  let insertCount: Smi;
  let actualDeleteCount: Number;
  // 5. If the Number of actual arguments is 0, then
  if (arguments.length == 0) {
    // a. Let insertCount be 0.
    insertCount = 0;
    // b. Let actualDeleteCount be 0.
    actualDeleteCount = 0;
    // 6. Else if the Number of actual arguments is 1, then
  } else if (arguments.length == 1) {
    // a. Let insertCount be 0.
    insertCount = 0;
    // b. Let actualDeleteCount be len - actualStart.
    actualDeleteCount = len - actualStart;
    // 7. Else,
  } else {
    // a. Let insertCount be the Number of actual arguments minus 2.
    insertCount = Convert<Smi>(arguments.length) - 2;
    // b. Let dc be ? ToInteger(deleteCount).
    const deleteCount: JSAny = arguments[1];
    const dc: Number = ToInteger_Inline(deleteCount);
    // c. Let actualDeleteCount be min(max(dc, 0), len - actualStart).
    actualDeleteCount = Min(Max(dc, 0), len - actualStart);
  }

  // 8. If len + insertCount - actualDeleteCount > 2^53-1, throw a
  //    Bailout exception.
  const newLength: Number = len + insertCount - actualDeleteCount;
  if (newLength > kMaxSafeInteger) {
    ThrowTypeError(MessageTemplate::kInvalidArrayLength, newLength);
  }

  try {
    return FastArraySplice(
        context, arguments, o, len, actualStart, insertCount, actualDeleteCount)
        otherwise Bailout;
  } label Bailout {}

  // If the fast case fails, just continue with the slow, correct,
  // spec-compliant case.
  return SlowSplice(
      context, arguments, o, len, actualStart, insertCount, actualDeleteCount);
}
}
```