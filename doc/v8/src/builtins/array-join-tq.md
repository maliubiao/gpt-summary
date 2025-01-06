Response: Let's break down the thought process for analyzing this Torque code.

1. **Understand the Goal:** The request asks for a summary of the code's functionality, its relation to JavaScript, examples, logic, and common errors. The filename `array-join.tq` strongly suggests this code is related to the `Array.prototype.join()` method in JavaScript.

2. **Identify Key Functions and Macros:**  Start by scanning the code for top-level `builtin` and `transitioning builtin` declarations. These are the entry points and core logic units. Also, look for `macro` declarations, which represent reusable code snippets. In this file, we find:
    * `LoadJoinElement` (multiple specializations)
    * `ConvertToLocaleString`
    * `ArrayPrototypeJoin`
    * `ArrayPrototypeToLocaleString`
    * `ArrayPrototypeToString`
    * `TypedArrayPrototypeJoin`
    * `TypedArrayPrototypeToLocaleString`
    * Macros like `AddStringLength`, `StoreAndGrowFixedArray`, `Buffer`, `NewBuffer`, `BufferJoin`, `ArrayJoinImpl`, `ArrayJoin`, `CycleProtectedArrayJoin`, `JoinStackPush`, `JoinStackPop`, etc.

3. **Trace the Execution Flow (High-Level):**  Focus on the JavaScript builtins (`ArrayPrototypeJoin`, `ArrayPrototypeToLocaleString`, `TypedArrayPrototypeJoin`, `TypedArrayPrototypeToLocaleString`). Observe how they call other functions and macros. Notice the `CycleProtectedArrayJoin` macro is a common entry point.

4. **Analyze Core Logic (`ArrayJoinImpl` and `ArrayJoin`):**
    * `ArrayJoinImpl`: This macro seems to handle the main iteration over the array elements, converting them to strings and concatenating them with the separator. It uses `LoadJoinElement` to retrieve elements and a `Buffer` to efficiently build the result string.
    * `ArrayJoin`: This macro acts as a dispatcher, choosing the appropriate `LoadJoinElement` function based on the array's element kind (e.g., fast, dictionary, typed array). It includes optimizations for common cases.

5. **Understand `LoadJoinElement` Specializations:**  Each specialization handles a different type of array storage (e.g., fast SMI/object, fast double, dictionary, typed array). This is a performance optimization, allowing V8 to access elements more efficiently based on the underlying data structure.

6. **Examine the `Buffer` Structure:**  The `Buffer` macro and its associated `Add`, `AddSeparators`, `RepeatLast`, and `BufferJoin` functions are crucial for understanding how the string concatenation is performed. It aims for efficiency by avoiding repeated string concatenation.

7. **Investigate the Cycle Protection Mechanism:** The `JoinStackPush`, `JoinStackPop`, and `CycleProtectedArrayJoin` functions implement a mechanism to detect and prevent infinite recursion in cases like `[].join([1])` where the separator itself is an array.

8. **Connect to JavaScript:**  For each JavaScript builtin, identify the corresponding JavaScript method (`Array.prototype.join`, `Array.prototype.toLocaleString`, `Array.prototype.toString`, `TypedArray.prototype.join`, `TypedArray.prototype.toLocaleString`). Explain how the Torque code implements the behavior defined in the ECMAScript specification.

9. **Create Examples:**  Develop JavaScript examples that demonstrate the functionality of each builtin and illustrate different scenarios (e.g., different separators, sparse arrays, typed arrays, `toLocaleString`).

10. **Identify Logic and Assumptions:** For key functions like `ArrayJoinImpl`, trace the flow with example inputs. Hypothesize what happens when the array is empty, has holes, contains different data types, etc.

11. **Recognize Common Errors:** Think about typical mistakes developers make when using `join()` or `toLocaleString()`. Examples include using a non-string separator that gets converted, expecting `undefined` or `null` elements to remain as such, or issues with recursive joining.

12. **Structure the Output:** Organize the information logically with clear headings and bullet points. Start with a high-level summary and then delve into more specific details. Use code snippets to illustrate both the Torque code and the corresponding JavaScript examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This code just implements `Array.prototype.join()`."  **Correction:**  Realize it also handles `toLocaleString()` and `toString()` and their typed array counterparts.
* **Misunderstanding:** Initially might not fully grasp the purpose of the `Buffer`. **Refinement:**  Analyze the `Add` and `BufferJoin` functions to understand its role in efficient string building.
* **Overlooking Optimization:** Might initially focus solely on the basic logic. **Refinement:** Notice the different `LoadJoinElement` specializations and understand they are for performance.
* **Insufficient Examples:**  Initially provide very basic examples. **Refinement:** Add examples demonstrating edge cases (holes, different separators, typed arrays, recursion).

By following these steps, iteratively refining understanding, and connecting the Torque code back to JavaScript concepts, a comprehensive analysis can be achieved.
这个V8 Torque源代码文件 `v8/src/builtins/array-join.tq` 主要实现了 JavaScript 中 `Array.prototype.join()`, `Array.prototype.toLocaleString()` 和 `Array.prototype.toString()` 方法，以及 `TypedArray.prototype.join()` 和 `TypedArray.prototype.toLocaleString()` 方法的核心逻辑。

**功能归纳:**

1. **数组元素的连接 (`Array.prototype.join()`):**  此文件包含了将数组（包括普通数组和类型化数组）中的所有元素连接成一个字符串的实现。用户可以指定一个分隔符，用于连接数组的各个元素。

2. **本地化字符串连接 (`Array.prototype.toLocaleString()`):**  此文件也实现了将数组元素连接成一个本地化字符串的功能。它会调用每个数组元素的 `toLocaleString()` 方法，然后用指定的分隔符（默认为逗号）连接结果。

3. **类型转换到字符串 (`Array.prototype.toString()`):**  当一个数组被用在需要字符串的上下文中时，会隐式调用 `toString()` 方法。这个方法通常会调用数组的 `join()` 方法（如果存在）。此文件包含了这部分逻辑，用于处理当数组没有自定义 `join` 方法时的情况。

4. **类型化数组的支持:**  代码同时处理了类型化数组（如 `Uint8Array`, `Float64Array` 等）的 `join()` 和 `toLocaleString()` 方法，确保它们也能正确地连接元素。

5. **性能优化:**  代码中针对不同类型的数组元素（如快速模式的SMI或对象、双精度浮点数、字典模式等）使用了不同的加载元素的方法 (`LoadJoinElement`)，以提高性能。

6. **循环引用保护:**  为了防止在 `join()` 或 `toLocaleString()` 过程中出现无限循环（例如，当数组的某个元素是它自身或包含它自身的数组时），代码实现了循环引用检测机制 (`JoinStackPush`, `JoinStackPop`)。

7. **字符串长度限制:**  代码会检查最终连接成的字符串的长度是否超过了 JavaScript 的最大字符串长度限制，如果超过则会抛出 `RangeError`。

**与 JavaScript 功能的关系及举例:**

* **`Array.prototype.join()`:**

   ```javascript
   const arr = ['Fire', 'Air', 'Water'];
   console.log(arr.join());       // 输出: Fire,Air,Water
   console.log(arr.join(''));     // 输出: FireAirWater
   console.log(arr.join('-'));    // 输出: Fire-Air-Water
   ```
   这段 Torque 代码实现了 `Array.prototype.join` 的核心逻辑，包括遍历数组、获取元素、将元素转换为字符串以及使用分隔符连接字符串。

* **`Array.prototype.toLocaleString()`:**

   ```javascript
   const prices = [100000, 1000000, 100000000];
   console.log(prices.toLocaleString('en-US')); // 输出类似于: "100,000,1,000,000,100,000,000"
   const dates = [new Date(Date.UTC(2012, 11, 20, 3, 0, 0))];
   console.log(dates.toLocaleString('en-US'));  // 输出类似于: "12/19/2012, 7:00:00 PM"
   ```
   Torque 代码中的 `ConvertToLocaleString` 函数负责调用每个元素的 `toLocaleString` 方法，并处理可能的异常。

* **`Array.prototype.toString()`:**

   ```javascript
   const arr = [1, 2, 3];
   console.log(arr.toString()); // 输出: 1,2,3

   const nestedArr = [1, [2, 3]];
   console.log(nestedArr.toString()); // 输出: 1,2,3 (对嵌套数组也调用 toString)
   ```
   Torque 代码中的 `ArrayPrototypeToString` 实现了当数组没有自定义 `join` 方法时，默认调用 `join()` 的行为。

* **`TypedArray.prototype.join()` 和 `TypedArray.prototype.toLocaleString()`:**

   ```javascript
   const typedArray = new Uint8Array([1, 2, 3]);
   console.log(typedArray.join('-')); // 输出: 1-2-3
   console.log(typedArray.toLocaleString()); // 输出: 1,2,3 (数字通常没有特别的本地化格式)
   ```
   Torque 代码中针对 `JSTypedArray` 的处理逻辑确保了类型化数组也能正确地执行连接操作。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

* `receiver`: 一个 JavaScript 数组 `['hello', 123, null]`
* `sep`: 字符串 `'-'`

**代码逻辑推理:**

1. `ArrayPrototypeJoin` 函数被调用。
2. `CycleProtectedArrayJoin` 负责处理循环引用检查。
3. `ArrayJoin` 根据数组的元素类型选择合适的 `LoadJoinElement` 函数。在这个例子中，可能使用 `LoadJoinElement<array::FastSmiOrObjectElements>` 或 `LoadJoinElement<array::GenericElementsAccessor>`。
4. `ArrayJoinImpl` 遍历数组的每个元素：
   - 第一个元素 `'hello'` 是字符串，直接使用。
   - 第二个元素 `123` 是数字，会被转换为字符串 `'123'`。
   - 第三个元素 `null` 是 null，会根据 `IsNullOrUndefined(element)` 判断，然后被转换为空字符串 `''`。
5. 在每次迭代中，如果不是第一个元素，会在元素前添加分隔符 `'-'`。
6. 使用 `Buffer` 结构来高效地构建最终的字符串。
7. `BufferJoin` 将 `Buffer` 中存储的部分连接起来，形成最终的字符串。

**预期输出:** `'hello-123-'` (注意 `null` 被转换为空字符串)

**涉及用户常见的编程错误及举例:**

1. **期望 `undefined` 或 `null` 元素保持不变:**

   ```javascript
   const arr = ['a', undefined, 'b', null, 'c'];
   console.log(arr.join('-')); // 输出: a---b-c
   ```
   用户可能期望 `undefined` 或 `null` 在连接后仍然是 `undefined` 或 `null`，但实际上它们会被转换为空字符串。

2. **使用对象作为分隔符，期望调用对象的 `toString()` 方法得到特定结果:**

   ```javascript
   const arr = [1, 2, 3];
   const separator = { toString: () => '**' };
   console.log(arr.join(separator)); // 输出: 1**2**3
   ```
   用户可能没有意识到分隔符会被强制转换为字符串，如果分隔符是一个对象，则会调用其 `toString()` 方法。如果对象没有 `toString()` 方法，则会使用默认的 `[object Object]`。

3. **在 `toLocaleString()` 中期望 `undefined` 或 `null` 保持不变:**

   ```javascript
   const arr = [1, undefined, 2, null];
   console.log(arr.toLocaleString()); // 输出: "1,,2,"
   ```
   与 `join()` 类似，`toLocaleString()` 也会将 `undefined` 和 `null` 转换为空字符串。

4. **循环引用导致堆栈溢出 (尽管 V8 有保护机制):**

   ```javascript
   const arr = [1];
   arr.push(arr); // arr 现在包含自身
   // 在没有循环引用保护的情况下，尝试 arr.join() 会导致无限递归
   // V8 的代码中实现了 CycleProtectedArrayJoin 来防止这种情况，通常会返回空字符串 ""
   console.log(arr.join()); // 输出: "" (取决于 V8 的具体实现和优化)
   ```
   用户可能不小心创建了包含循环引用的数组，导致 `join()` 或 `toLocaleString()` 进入无限循环。V8 的代码尝试检测并避免这种情况。

理解这段 Torque 代码对于深入了解 V8 引擎如何高效地实现 JavaScript 的数组连接功能至关重要。它展示了 V8 如何针对不同的数据类型进行优化，并处理一些常见的边界情况和错误。

Prompt: 
```
这是目录为v8/src/builtins/array-join.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

namespace array {

type LoadJoinElementFn = builtin(Context, JSReceiver, uintptr) => JSAny;

const kMaxArrayLength:
    constexpr uint32 generates 'JSArray::kMaxArrayLength';

// Fast C call to write a fixed array (see Buffer.fixedArray) to a single
// string.
extern macro
    ArrayBuiltinsAssembler::CallJSArrayArrayJoinConcatToSequentialString(
        FixedArray, intptr, String, String): String;

transitioning builtin LoadJoinElement<T : type extends ElementsKind>(
    context: Context, receiver: JSReceiver, k: uintptr): JSAny {
  return GetProperty(receiver, Convert<Number>(k));
}

transitioning LoadJoinElement<array::DictionaryElements>(
    context: Context, receiver: JSReceiver, k: uintptr): JSAny {
  const array: JSArray = UnsafeCast<JSArray>(receiver);
  const dict: NumberDictionary = UnsafeCast<NumberDictionary>(array.elements);
  try {
    return BasicLoadNumberDictionaryElement(dict, Signed(k))
        otherwise IfNoData, IfHole;
  } label IfNoData deferred {
    return GetProperty(receiver, Convert<Number>(k));
  } label IfHole {
    return kEmptyString;
  }
}

LoadJoinElement<array::FastSmiOrObjectElements>(
    context: Context, receiver: JSReceiver, k: uintptr): JSAny {
  const array: JSArray = UnsafeCast<JSArray>(receiver);
  const fixedArray: FixedArray = UnsafeCast<FixedArray>(array.elements);
  const element: Object = fixedArray.objects[k];
  return element == TheHole ? kEmptyString : UnsafeCast<JSAny>(element);
}

LoadJoinElement<array::FastDoubleElements>(
    context: Context, receiver: JSReceiver, k: uintptr): JSAny {
  const array: JSArray = UnsafeCast<JSArray>(receiver);
  const fixedDoubleArray: FixedDoubleArray =
      UnsafeCast<FixedDoubleArray>(array.elements);
  const element: float64 =
      fixedDoubleArray.values[k].Value() otherwise return kEmptyString;
  return AllocateHeapNumberWithValue(element);
}

builtin LoadJoinTypedElement<T : type extends ElementsKind>(
    context: Context, receiver: JSReceiver, k: uintptr): JSAny {
  const typedArray: JSTypedArray = UnsafeCast<JSTypedArray>(receiver);
  dcheck(!typed_array::IsJSArrayBufferViewDetachedOrOutOfBoundsBoolean(
      typedArray));
  return typed_array::LoadFixedTypedArrayElementAsTagged(
      typedArray.data_ptr, k, typed_array::KindForArrayType<T>());
}

transitioning builtin ConvertToLocaleString(
    context: Context, element: JSAny, locales: JSAny, options: JSAny): String {
  if (IsNullOrUndefined(element)) return kEmptyString;

  const prop: JSAny = GetProperty(element, 'toLocaleString');
  try {
    const callable: Callable = Cast<Callable>(prop) otherwise TypeError;
    let result: JSAny;

    // According to the ECMA-402 specification, the optional arguments locales
    // and options must be passed.
    @if(V8_INTL_SUPPORT) {
      result = Call(context, callable, element, locales, options);
    }

    // Without the ECMA-402 internationalization API, the optional arguments
    // must not be passed.
    // See: https://tc39.es/ecma262/#sec-array.prototype.tolocalestring
    @ifnot(V8_INTL_SUPPORT) {
      result = Call(context, callable, element);
      // Use the remaining parameters.
      const _locales = locales;
      const _options = options;
    }

    return ToString_Inline(result);
  } label TypeError {
    ThrowCalledNonCallable(prop);
  }
}

// Verifies the current element JSArray accessor can still be safely used
// (see LoadJoinElement<ElementsAccessor>).
macro CannotUseSameArrayAccessor<T: type>(
    implicit context: Context)(loadFn: LoadJoinElementFn, receiver: JSReceiver,
    originalMap: Map, originalLen: Number): bool;

CannotUseSameArrayAccessor<JSArray>(
    implicit context: Context)(loadFn: LoadJoinElementFn, receiver: JSReceiver,
    originalMap: Map, originalLen: Number): bool {
  if (loadFn == LoadJoinElement<array::GenericElementsAccessor>) return false;

  const array: JSArray = UnsafeCast<JSArray>(receiver);
  if (originalMap != array.map) return true;
  if (originalLen != array.length) return true;
  if (IsNoElementsProtectorCellInvalid()) return true;
  return false;
}

CannotUseSameArrayAccessor<JSTypedArray>(
    implicit context: Context)(_loadFn: LoadJoinElementFn,
    receiver: JSReceiver, _initialMap: Map, _initialLen: Number): bool {
  const typedArray: JSTypedArray = UnsafeCast<JSTypedArray>(receiver);
  // When this is called from toLocaleString(), the underlying buffer might get
  // detached / resized (in the case of RAB / GSAB) during iterating the
  // elements. When this is called from join(), it can happen only before the
  // first element (during parameter conversion). The code below doesn't
  // differentiate between these two cases, but does the checks in both cases.
  if (IsDetachedBuffer(typedArray.buffer)) {
    return true;
  }
  if (IsVariableLengthJSArrayBufferView(typedArray)) {
    // TODO(v8:11111): Add a fast(er) path here.
    return true;
  }
  return false;
}

// Calculates the running total length of the resulting string.  If the
// calculated length exceeds the maximum string length (see
// String::kMaxLength), throws a range error.
macro AddStringLength(
    implicit context: Context)(lenA: intptr, lenB: intptr): intptr {
  try {
    const length: intptr = TryIntPtrAdd(lenA, lenB) otherwise IfOverflow;
    if (length > kStringMaxLength) goto IfOverflow;
    return length;
  } label IfOverflow deferred {
    ThrowInvalidStringLength(context);
  }
}

// Stores an element to a fixed array and return the fixed array. If the fixed
// array is not large enough, create and return a new, larger fixed array that
// contains all previously elements and the new element.
macro StoreAndGrowFixedArray<T: type>(
    fixedArray: FixedArray, index: intptr, element: T): FixedArray {
  const length: intptr = fixedArray.length_intptr;
  dcheck(index <= length);
  if (index < length) {
    fixedArray.objects[index] = element;
    return fixedArray;
  } else
    deferred {
      const newLength: intptr = CalculateNewElementsCapacity(length);
      dcheck(index < newLength);
      const newfixedArray: FixedArray =
          ExtractFixedArray(fixedArray, 0, length, newLength, TheHole);
      newfixedArray.objects[index] = element;
      return newfixedArray;
    }
}

// Contains the information necessary to create a single, separator delimited,
// flattened one or two byte string.
// The buffer is maintained and updated by Buffer.constructor, Buffer.Add(),
// Buffer.AddSeparators().
struct Buffer {
  macro Add(
      implicit context: Context)(str: String, nofSeparators: intptr,
      separatorLength: intptr): void {
    // Add separators if necessary (at the beginning or more than one)
    const writeSeparators: bool = this.index == 0 | nofSeparators > 1;
    this.AddSeparators(nofSeparators, separatorLength, writeSeparators);

    this.totalStringLength =
        AddStringLength(this.totalStringLength, str.length_intptr);
    // String comparison is expensive, so we only check for pointer equality
    // (i.e. only works for internalized strings).
    if (TaggedEqual(str, this.lastString)) {
      this.RepeatLast();
    } else {
      this.fixedArray =
          StoreAndGrowFixedArray(this.fixedArray, this.index++, str);
      this.lastString = str;
    }
    this.isOneByte = IsOneByteStringMap(str.map) & this.isOneByte;
  }

  macro AddSeparators(
      implicit context: Context)(nofSeparators: intptr,
      separatorLength: intptr, write: bool): void {
    if (nofSeparators == 0 || separatorLength == 0) return;

    const nofSeparatorsInt: intptr = nofSeparators;
    const sepsLen: intptr = separatorLength * nofSeparatorsInt;
    // Detect integer overflow
    // TODO(turbofan): Replace with overflow-checked multiplication.
    if (sepsLen / separatorLength != nofSeparatorsInt) deferred {
        ThrowInvalidStringLength(context);
      }

    this.totalStringLength = AddStringLength(this.totalStringLength, sepsLen);
    if (write) deferred {
        this.fixedArray = StoreAndGrowFixedArray(
            this.fixedArray, this.index++, Convert<Smi>(nofSeparatorsInt));
        this.lastString = Null;
      }
  }

  macro RepeatLast(): void {
    dcheck(this.index > 0);
    typeswitch (this.fixedArray.objects[this.index - 1]) {
      case (String): {
        this.fixedArray = StoreAndGrowFixedArray(
            this.fixedArray, this.index++, SmiConstant(-1));
      }
      case (count: Smi): {
        dcheck(count < 0);
        dcheck(count - 1 < 0);  // Check that there is no overflow.
        this.fixedArray.objects[this.index - 1] = count - 1;
      }
      case (Object): {
        unreachable;
      }
    }
  }

  // Fixed array holding elements that are either:
  //   1) String result of `ToString(next)`.
  //   2) Smi representing either
  //        - the number of consecutive separators (positive smi).
  //        - the number to repeat the last stored string (negative smi).
  // `BufferJoin()` will iterate and writes these entries to a flat string.
  //
  // To save space, reduce reads and writes, only separators at the beginning,
  // end, or more than one are written.
  //
  // No hole example
  //   receiver:   ['hello', 'world']
  //   fixedArray: ['hello', 'world']
  //
  // Hole example
  //   receiver:   [<hole>, 'hello', <hole>, 'world', <hole>]
  //   fixedArray: [1, 'hello', 2, 'world', 1]
  //
  // Repeat example
  //   receiver:   ['hello', 'hello', hello', 'world']
  //   fixedArray: ['hello', -2, 'world']
  fixedArray: FixedArray;

  // Index to insert a new entry into `fixedArray`.
  index: intptr;

  // Running total of the resulting string length.
  totalStringLength: intptr;

  // `true` if the separator and all strings in the buffer are one-byte,
  // otherwise `false`.
  isOneByte: bool;

  lastString: PrimitiveHeapObject;
}

macro NewBuffer(len: uintptr, sep: String): Buffer {
  const cappedBufferSize: intptr = len > kMaxNewSpaceFixedArrayElements ?
      kMaxNewSpaceFixedArrayElements :
      Signed(len);
  dcheck(cappedBufferSize > 0);
  return Buffer{
    fixedArray: AllocateZeroedFixedArray(cappedBufferSize),
    index: 0,
    totalStringLength: 0,
    isOneByte: IsOneByteStringMap(sep.map),
    lastString: Null
  };
}

macro BufferJoin(implicit context: Context)(buffer: Buffer, sep: String):
    String {
  dcheck(IsValidPositiveSmi(buffer.totalStringLength));
  if (buffer.totalStringLength == 0) return kEmptyString;

  // Fast path when there's only one buffer element.
  if (buffer.index == 1) {
    const fixedArray: FixedArray = buffer.fixedArray;
    typeswitch (fixedArray.objects[0]) {
      // When the element is a string, just return it and completely avoid
      // allocating another string.
      case (str: String): {
        return str;
      }

      // When the element is a smi, use StringRepeat to quickly build a memory
      // efficient separator repeated string.
      case (nofSeparators: Smi): {
        dcheck(nofSeparators > 0);
        return StringRepeat(context, sep, nofSeparators);
      }
      case (Object): {
        unreachable;
      }
    }
  }

  const length: uint32 = Convert<uint32>(Unsigned(buffer.totalStringLength));
  const r: String = buffer.isOneByte ? AllocateSeqOneByteString(length) :
                                       AllocateSeqTwoByteString(length);
  return CallJSArrayArrayJoinConcatToSequentialString(
      buffer.fixedArray, buffer.index, sep, r);
}

transitioning macro ArrayJoinImpl<T: type>(
    implicit context: Context)(receiver: JSReceiver, sep: String,
    lengthNumber: Number, useToLocaleString: constexpr bool, locales: JSAny,
    options: JSAny, initialLoadFn: LoadJoinElementFn): String {
  const initialMap: Map = receiver.map;
  const len: uintptr = Convert<uintptr>(lengthNumber);
  const separatorLength: intptr = sep.length_intptr;
  let nofSeparators: intptr = 0;
  let loadFn: LoadJoinElementFn = initialLoadFn;
  let buffer: Buffer = NewBuffer(len, sep);

  // 6. Let k be 0.
  let k: uintptr = 0;

  // 7. Repeat, while k < len
  while (k < len) {
    if (CannotUseSameArrayAccessor<T>(
            loadFn, receiver, initialMap, lengthNumber))
      deferred {
        loadFn = LoadJoinElement<array::GenericElementsAccessor>;
      }

    if (k > 0) {
      // a. If k > 0, let R be the string-concatenation of R and sep.
      nofSeparators = nofSeparators + 1;
    }

    // b. Let element be ? Get(O, ! ToString(k)).
    const element: JSAny = loadFn(context, receiver, k++);

    // c. If element is undefined or null, let next be the empty String;
    //    otherwise, let next be ? ToString(element).
    let next: String;
    if constexpr (useToLocaleString) {
      next = ConvertToLocaleString(context, element, locales, options);
      if (next == kEmptyString) continue;
    } else {
      typeswitch (element) {
        case (str: String): {
          if (str == kEmptyString) continue;
          next = str;
        }
        case (num: Number): {
          next = NumberToString(num);
        }
        case (obj: JSAny): {
          if (IsNullOrUndefined(obj)) continue;
          const str = string::ToString_Inline(context, obj);
          if (str == kEmptyString) continue;
          next = str;
        }
      }
    }

    // d. Set R to the string-concatenation of R and next.
    buffer.Add(next, nofSeparators, separatorLength);
    nofSeparators = 0;
  }

  // Add any separators at the end.
  buffer.AddSeparators(nofSeparators, separatorLength, true);

  // 8. Return R.
  return BufferJoin(buffer, sep);
}

transitioning macro ArrayJoin<T: type>(
    implicit context: Context)(useToLocaleString: constexpr bool,
    receiver: JSReceiver, sep: String, lenNumber: Number, locales: JSAny,
    options: JSAny): JSAny;

transitioning ArrayJoin<JSArray>(
    implicit context: Context)(useToLocaleString: constexpr bool,
    receiver: JSReceiver, sep: String, lenNumber: Number, locales: JSAny,
    options: JSAny): JSAny {
  const map: Map = receiver.map;
  const kind: ElementsKind = map.elements_kind;
  let loadFn: LoadJoinElementFn;

  try {
    const array: JSArray = Cast<JSArray>(receiver) otherwise IfSlowPath;
    if (array.length != lenNumber) goto IfSlowPath;
    if (!IsPrototypeInitialArrayPrototype(map)) goto IfSlowPath;
    if (IsNoElementsProtectorCellInvalid()) goto IfSlowPath;

    if (IsElementsKindLessThanOrEqual(kind, ElementsKind::HOLEY_ELEMENTS)) {
      loadFn = LoadJoinElement<array::FastSmiOrObjectElements>;
    } else if (IsElementsKindLessThanOrEqual(
                   kind, ElementsKind::HOLEY_DOUBLE_ELEMENTS)) {
      loadFn = LoadJoinElement<array::FastDoubleElements>;
    } else if (kind == ElementsKind::DICTIONARY_ELEMENTS)
      deferred {
        const dict: NumberDictionary =
            UnsafeCast<NumberDictionary>(array.elements);
        const nofElements: Smi = GetNumberDictionaryNumberOfElements(dict);
        if (nofElements == 0) {
          if (sep == kEmptyString) return kEmptyString;
          try {
            const nofSeparators: Smi =
                Cast<Smi>(lenNumber - 1) otherwise IfNotSmi;
            return StringRepeat(context, sep, nofSeparators);
          } label IfNotSmi {
            ThrowInvalidStringLength(context);
          }
        } else {
          loadFn = LoadJoinElement<array::DictionaryElements>;
        }
      }
    else {
      goto IfSlowPath;
    }
  } label IfSlowPath {
    loadFn = LoadJoinElement<array::GenericElementsAccessor>;
  }
  return ArrayJoinImpl<JSArray>(
      receiver, sep, lenNumber, useToLocaleString, locales, options, loadFn);
}

transitioning ArrayJoin<JSTypedArray>(
    implicit context: Context)(useToLocaleString: constexpr bool,
    receiver: JSReceiver, sep: String, lenNumber: Number, locales: JSAny,
    options: JSAny): JSAny {
  const map: Map = receiver.map;
  const kind: ElementsKind = map.elements_kind;
  let loadFn: LoadJoinElementFn;

  if (IsElementsKindGreaterThan(kind, ElementsKind::UINT32_ELEMENTS)) {
    if (kind == ElementsKind::INT32_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Int32Elements>;
    } else if (kind == ElementsKind::FLOAT16_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Float16Elements>;
    } else if (kind == ElementsKind::FLOAT32_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Float32Elements>;
    } else if (kind == ElementsKind::FLOAT64_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Float64Elements>;
    } else if (kind == ElementsKind::UINT8_CLAMPED_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Uint8ClampedElements>;
    } else if (kind == ElementsKind::BIGUINT64_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::BigUint64Elements>;
    } else if (kind == ElementsKind::BIGINT64_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::BigInt64Elements>;
    } else if (kind == ElementsKind::RAB_GSAB_UINT8_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Uint8Elements>;
    } else if (kind == ElementsKind::RAB_GSAB_INT8_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Int8Elements>;
    } else if (kind == ElementsKind::RAB_GSAB_UINT16_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Uint16Elements>;
    } else if (kind == ElementsKind::RAB_GSAB_INT16_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Int16Elements>;
    } else if (kind == ElementsKind::RAB_GSAB_UINT32_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Uint32Elements>;
    } else if (kind == ElementsKind::RAB_GSAB_INT32_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Int32Elements>;
    } else if (kind == ElementsKind::RAB_GSAB_FLOAT16_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Float16Elements>;
    } else if (kind == ElementsKind::RAB_GSAB_FLOAT32_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Float32Elements>;
    } else if (kind == ElementsKind::RAB_GSAB_FLOAT64_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Float64Elements>;
    } else if (kind == ElementsKind::RAB_GSAB_UINT8_CLAMPED_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Uint8ClampedElements>;
    } else if (kind == ElementsKind::RAB_GSAB_BIGUINT64_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::BigUint64Elements>;
    } else if (kind == ElementsKind::RAB_GSAB_BIGINT64_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::BigInt64Elements>;
    } else {
      unreachable;
    }
  } else {
    if (kind == ElementsKind::UINT8_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Uint8Elements>;
    } else if (kind == ElementsKind::INT8_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Int8Elements>;
    } else if (kind == ElementsKind::UINT16_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Uint16Elements>;
    } else if (kind == ElementsKind::INT16_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Int16Elements>;
    } else if (kind == ElementsKind::UINT32_ELEMENTS) {
      loadFn = LoadJoinTypedElement<typed_array::Uint32Elements>;
    } else {
      unreachable;
    }
  }
  return ArrayJoinImpl<JSTypedArray>(
      receiver, sep, lenNumber, useToLocaleString, locales, options, loadFn);
}

// The Join Stack detects cyclical calls to Array Join builtins
// (Array.p.join(), Array.p.toString(), Array.p.toLocaleString()). This
// FixedArray holds a stack of receivers to the current call.
// CycleProtectedArrayJoin() is responsible for calling JoinStackPush and
// JoinStackPop when visiting and leaving a receiver, respectively.
const kMinJoinStackSize:
    constexpr int31 generates 'JSArray::kMinJoinStackSize';
macro LoadJoinStack(implicit context: Context)(): FixedArray
    labels IfUninitialized {
  typeswitch (*NativeContextSlot(ContextSlot::ARRAY_JOIN_STACK_INDEX)) {
    case (Undefined): {
      goto IfUninitialized;
    }
    case (stack: FixedArray): {
      return stack;
    }
  }
}

macro SetJoinStack(implicit context: Context)(stack: FixedArray): void {
  *NativeContextSlot(ContextSlot::ARRAY_JOIN_STACK_INDEX) = stack;
}

// Adds a receiver to the stack. The FixedArray will automatically grow to
// accommodate the receiver. If the receiver already exists on the stack,
// this indicates a cyclical call and False is returned.
builtin JoinStackPush(
    implicit context: Context)(stack: FixedArray,
    receiver: JSReceiver): Boolean {
  const capacity: intptr = stack.length_intptr;
  for (let i: intptr = 0; i < capacity; i++) {
    const previouslyVisited: Object = stack.objects[i];

    // Add `receiver` to the first open slot
    if (previouslyVisited == TheHole) {
      stack.objects[i] = receiver;
      return True;
    }

    // Detect cycles
    if (receiver == previouslyVisited) return False;
  }

  // If no open slots were found, grow the stack and add receiver to the end.
  const newStack: FixedArray =
      StoreAndGrowFixedArray(stack, capacity, receiver);
  SetJoinStack(newStack);
  return True;
}

// Fast path the common non-nested calls. If the receiver is not already on
// the stack, add it to the stack and return true. Otherwise return false.
macro JoinStackPushInline(implicit context: Context)(receiver: JSReceiver):
    bool {
  try {
    const stack: FixedArray = LoadJoinStack()
        otherwise IfUninitialized;
    if (stack.objects[0] == TheHole) {
      stack.objects[0] = receiver;
    } else if (JoinStackPush(stack, receiver) == False)
      deferred {
        return false;
      }
  } label IfUninitialized {
    const stack: FixedArray =
        AllocateFixedArrayWithHoles(kMinJoinStackSize, AllocationFlag::kNone);
    stack.objects[0] = receiver;
    SetJoinStack(stack);
  }
  return true;
}

// Removes a receiver from the stack. The FixedArray will automatically shrink
// to Heap::kMinJoinStackSize once the stack becomes empty.
builtin JoinStackPop(
    implicit context: Context)(stack: FixedArray,
    receiver: JSReceiver): JSAny {
  const len: intptr = stack.length_intptr;
  for (let i: intptr = 0; i < len; i++) {
    if (stack.objects[i] == receiver) {
      // Shrink the Join Stack if the stack will be empty and is larger than
      // the minimum size.
      if (i == 0 && len > kMinJoinStackSize) deferred {
          const newStack: FixedArray = AllocateFixedArrayWithHoles(
              kMinJoinStackSize, AllocationFlag::kNone);
          SetJoinStack(newStack);
        }
      else {
        stack.objects[i] = TheHole;
      }
      return Undefined;
    }
  }
  unreachable;
}

// Fast path the common non-nested calls.
macro JoinStackPopInline(implicit context: Context)(receiver: JSReceiver):
    void {
  const stack: FixedArray = LoadJoinStack()
      otherwise unreachable;
  const len: intptr = stack.length_intptr;

  // Builtin call was not nested (receiver is the first entry) and
  // did not contain other nested arrays that expanded the stack.
  if (stack.objects[0] == receiver && len == kMinJoinStackSize) {
    stack.objects[0] = TheHole;
  } else
    deferred {
      JoinStackPop(stack, receiver);
    }
}

// Main entry point for all builtins using Array Join functionality.
transitioning macro CycleProtectedArrayJoin<T: type>(
    implicit context: Context)(useToLocaleString: constexpr bool,
    o: JSReceiver, len: Number, sepObj: JSAny, locales: JSAny,
    options: JSAny): JSAny {
  // 3. If separator is undefined, let sep be the single-element String ",".
  // 4. Else, let sep be ? ToString(separator).
  const sep: String = sepObj == Undefined ? ',' : ToString_Inline(sepObj);

  // If the receiver is not empty and not already being joined, continue with
  // the normal join algorithm.
  if (len > 0 && JoinStackPushInline(o)) {
    try {
      const result: JSAny =
          ArrayJoin<T>(useToLocaleString, o, sep, len, locales, options);
      JoinStackPopInline(o);
      return result;
    } catch (e, message) deferred {
      JoinStackPopInline(o);
      ReThrowWithMessage(context, e, message);
    }
  } else {
    return kEmptyString;
  }
}

// https://tc39.github.io/ecma262/#sec-array.prototype.join
transitioning javascript builtin ArrayPrototypeJoin(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const separator: JSAny = arguments[0];

  // 1. Let O be ? ToObject(this value).
  const o: JSReceiver = ToObject_Inline(context, receiver);

  // 2. Let len be ? ToLength(? Get(O, "length")).
  const len: Number = GetLengthProperty(o);

  // Only handle valid array lengths. Although the spec allows larger
  // values, this matches historical V8 behavior.
  if (len > kMaxArrayLength) {
    ThrowTypeError(MessageTemplate::kInvalidArrayLength);
  }

  return CycleProtectedArrayJoin<JSArray>(
      false, o, len, separator, Undefined, Undefined);
}

// https://tc39.github.io/ecma262/#sec-array.prototype.tolocalestring
transitioning javascript builtin ArrayPrototypeToLocaleString(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const locales: JSAny = arguments[0];
  const options: JSAny = arguments[1];

  // 1. Let O be ? ToObject(this value).
  const o: JSReceiver = ToObject_Inline(context, receiver);

  // 2. Let len be ? ToLength(? Get(O, "length")).
  const len: Number = GetLengthProperty(o);

  // Only handle valid array lengths. Although the spec allows larger
  // values, this matches historical V8 behavior.
  if (len > kMaxArrayLength) {
    ThrowTypeError(MessageTemplate::kInvalidArrayLength);
  }

  return CycleProtectedArrayJoin<JSArray>(true, o, len, ',', locales, options);
}

// https://tc39.github.io/ecma262/#sec-array.prototype.tostring
transitioning javascript builtin ArrayPrototypeToString(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  // 1. Let array be ? ToObject(this value).
  const array: JSReceiver = ToObject_Inline(context, receiver);

  // 2. Let func be ? Get(array, "join").
  const prop: JSAny = GetProperty(array, 'join');
  try {
    // 3. If IsCallable(func) is false, let func be the intrinsic function
    //    %ObjProto_toString%.
    const func: Callable = Cast<Callable>(prop) otherwise NotCallable;

    // 4. Return ? Call(func, array).
    return Call(context, func, array);
  } label NotCallable {
    return ObjectToString(context, array);
  }
}

// https://tc39.github.io/ecma262/#sec-%typedarray%.prototype.join
transitioning javascript builtin TypedArrayPrototypeJoin(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const separator: JSAny = arguments[0];

  // Spec: ValidateTypedArray is applied to the this value prior to evaluating
  // the algorithm.
  const length = typed_array::ValidateTypedArrayAndGetLength(
      context, receiver, '%TypedArray%.prototype.join');
  const typedArray: JSTypedArray = UnsafeCast<JSTypedArray>(receiver);

  return CycleProtectedArrayJoin<JSTypedArray>(
      false, typedArray, Convert<Number>(length), separator, Undefined,
      Undefined);
}

// https://tc39.github.io/ecma262/#sec-%typedarray%.prototype.tolocalestring
transitioning javascript builtin TypedArrayPrototypeToLocaleString(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const locales: JSAny = arguments[0];
  const options: JSAny = arguments[1];

  // Spec: ValidateTypedArray is applied to the this value prior to evaluating
  // the algorithm.
  const length = typed_array::ValidateTypedArrayAndGetLength(
      context, receiver, '%TypedArray%.prototype.toLocaleString');
  const typedArray: JSTypedArray = UnsafeCast<JSTypedArray>(receiver);

  return CycleProtectedArrayJoin<JSTypedArray>(
      true, typedArray, Convert<Number>(length), ',', locales, options);
}
}

"""

```