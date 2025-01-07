Response:
Let's break down the thought process for analyzing the `js-array.tq` file.

1. **Identify the File Type and Purpose:** The first thing the prompt tells us is that the file ends in `.tq`, indicating it's a Torque source file. Torque is V8's internal language for defining built-in functions and data structures. The file path `v8/src/objects/js-array.tq` suggests it deals with the internal representation and behavior of JavaScript arrays within V8.

2. **Scan for Key Data Structures:**  Look for `class` declarations. These define the fundamental building blocks. We see:
    * `JSArrayIterator`:  This immediately tells us something about how iteration over arrays works. It has properties like `iterated_object`, `next_index`, and `kind`, hinting at the state needed for array iteration.
    * `JSArray`: This is the core array object itself. It has a `length` property, which is fundamental to JavaScript arrays.
    * `TemplateLiteralObject`: This looks like a specialized array for template literals, with additional properties like `raw`, `function_literal_id`, and `slot_id`.
    * `JSArrayConstructor`: This is the constructor function for creating arrays.

3. **Look for Macros and Functions:**  Macros (`macro`) and extern functions/builtins (`extern`) define operations related to these data structures.
    * `CreateArrayIterator`:  This confirms our initial thought about `JSArrayIterator`. It's used to create these iterator objects. There are two versions, one taking an initial `nextIndex`.
    * `NewJSArray`:  These macros create new `JSArray` instances. Different versions allow specifying the map, elements, or defaulting to empty arrays. `NewJSArrayFilledWithZero` shows how arrays are initialized with zeros.
    * `AllocateJSArray`: These extern macros likely handle the low-level memory allocation for arrays.
    * `LoadElementNoHole`: This seems to be a way to access array elements, explicitly handling cases where an element might be a "hole" (for sparse arrays). The `<T : type extends FixedArrayBase>` syntax indicates it works for different types of underlying array storage.
    * `ExtractFastJSArray`, `MoveElements`, `CopyElements`, `CloneFastJSArray`: These are more advanced operations, likely optimizations for manipulating array data efficiently. The "FastJSArray" types suggest optimizations based on array structure.
    * `FastJSArrayWitness`, `FastJSArrayForReadWitness`: These "witness" structures appear to be used for tracking the state and properties of fast arrays, potentially for optimization purposes and ensuring certain invariants hold.

4. **Analyze the Macros and Functions in Detail:**  Read through the code within the macros and functions. Pay attention to:
    * **Properties being accessed:**  What fields of the classes are being read or written? This reveals their purpose. For example, `JSArray.length` is frequently accessed.
    * **Types being used:**  `Number`, `Smi`, `FixedArray`, `FixedDoubleArray`, `Map`, `Context`. Understanding these types gives insight into V8's internal representation.
    * **Keywords and Control Flow:** `if`, `goto`, `typeswitch`, `labels`. This helps understand the logic. The `labels` keyword suggests ways to handle exceptional cases or different execution paths.
    * **`extern` and `builtin`:** These indicate calls to lower-level, likely C++ implementations within V8.

5. **Connect to JavaScript Concepts:** Now, relate the internal structures and operations to how JavaScript arrays behave.
    * **Iteration:** `JSArrayIterator` directly relates to the `for...of` loop and the array iterator protocol in JavaScript.
    * **Array Creation:** `NewJSArray` and `JSArrayConstructor` are behind the scenes when you use `[]` or `new Array()`.
    * **Array Length:** The `length` property in `JSArray` maps directly to the `length` property in JavaScript.
    * **Array Elements:** The `elements` property and the `LoadElementNoHole` macro deal with accessing the actual values stored in the array. The different `ElementsKind` enums (PACKED_SMI_ELEMENTS, HOLEY_ELEMENTS, etc.) explain how V8 optimizes array storage based on the types of elements.
    * **Sparse Arrays:** The handling of "holes" in `LoadElementNoHole` explains the behavior of sparse arrays in JavaScript.

6. **Illustrate with JavaScript Examples:**  Create simple JavaScript code snippets that demonstrate the concepts inferred from the Torque code. This makes the internal workings more concrete.

7. **Infer Code Logic and Provide Examples:** Look for macros that perform specific actions (like `CreateArrayIterator`). Make educated guesses about input and output based on the code. For example, `CreateArrayIterator` takes an array and a kind and produces an iterator object.

8. **Consider Common Programming Errors:** Think about common mistakes developers make with JavaScript arrays and how the underlying implementation might be related. Examples include:
    * Incorrectly assuming array element types.
    * Not understanding how `length` works.
    * Issues with sparse arrays.
    * Modifying arrays while iterating.

9. **Structure the Answer:** Organize the findings into logical sections: file purpose, key features, connections to JavaScript, code logic examples, and common errors. Use clear and concise language.

10. **Review and Refine:**  Read through the answer to ensure accuracy and clarity. Make sure the JavaScript examples are correct and relevant.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Maybe `TemplateLiteralObject` is just a special kind of string."  **Correction:**  The inheritance from `JSArray` indicates it's *still* an array, but with extra properties for template literal functionality.
* **Initial thought:** "The `Witness` structures are probably for debugging." **Correction:** While they *could* be used for debugging, the checks for map and protector cells suggest they are primarily used for runtime optimizations and ensuring type safety in optimized code paths.
* **Realization:** The different `ElementsKind` values are crucial for understanding V8's array optimizations. This should be highlighted.

By following these steps, we can effectively analyze a V8 Torque source file like `js-array.tq` and understand its role in the JavaScript engine.
这个 `v8/src/objects/js-array.tq` 文件是 V8 JavaScript 引擎中关于 `JSArray` 对象和相关迭代器的 Torque 源代码定义。 Torque 是一种 V8 内部使用的语言，用于定义运行时函数的签名和数据结构。

**主要功能列举:**

1. **定义 `JSArrayIterator` 类:**
   - 定义了 JavaScript 数组迭代器对象的内部结构。
   - 包含了迭代器所需的状态信息，例如：
     - `iterated_object`:  被迭代的数组对象。
     - `next_index`:  下一个要返回的元素的索引。
     - `kind`:  迭代的类型 (keys, values, entries)。
   - 详细说明了 `next_index` 在不同类型的可迭代对象（`JSArray`, `JSTypedArray`, 其他 `JSReceiver`）中的取值范围和终止条件，以及为何要保证在某些情况下 `next_index` 能放入 `Unsigned32` 范围以便于 TurboFan 的优化。

2. **定义 `JSArray` 类:**
   - 定义了 JavaScript 数组对象的内部结构。
   - 包含了一个关键属性 `length`，表示数组的长度。
   - 提供了一个内联宏 `IsEmpty()` 用于判断数组是否为空。

3. **定义 `TemplateLiteralObject` 类:**
   - 定义了模板字面量对象的内部结构，它继承自 `JSArray`。
   - 包含额外的属性 `raw` (用于获取原始字符串), `function_literal_id`, `slot_id`，这些是模板字面量特有的信息。

4. **定义 `JSArrayConstructor` 类:**
   - 定义了数组构造函数对象的类型，用于创建新的数组实例。

5. **定义创建 `JSArrayIterator` 的宏 (`CreateArrayIterator`)**:
   - 提供了创建 `JSArrayIterator` 对象的便捷方法。
   - 接收被迭代的数组对象 (`array`) 和迭代类型 (`kind`) 作为参数。
   - 可以选择性地传入初始的 `nextIndex`。

6. **定义创建 `JSArray` 的宏 (`NewJSArray`)**:
   - 提供了多种创建 `JSArray` 对象的方式：
     - 可以指定 `map` 和 `elements`。
     - 可以创建一个空的 `JSArray`。
     - 可以创建一个指定长度并用零填充的 `JSArray` (`NewJSArrayFilledWithZero`)，并处理了长度为 0 和长度过大的情况。

7. **定义不同类型的 `JSArray` 的别名 (type aliases):**
   - 定义了 `FastJSArray`, `FastJSArrayForRead`, `FastJSArrayForCopy`, `FastJSArrayForConcat`, `FastJSArrayWithNoCustomIteration`, `FastJSArrayForReadWithNoCustomIteration` 等类型别名。
   - 这些别名代表了在不同优化场景下的 `JSArray`，例如，当全局的保护器对象 (protectors) 没有失效时，数组可以被认为是 "fast" 的。

8. **定义分配 `JSArray` 的外部宏 (`AllocateJSArray`)**:
   - 声明了用于分配 `JSArray` 对象的外部宏，这些宏可能在 C++ 代码中实现，用于进行底层的内存分配。

9. **定义加载数组元素的宏 (`LoadElementNoHole`)**:
   - 提供了安全加载数组元素的方法，会检查是否是 "hole" (稀疏数组中未赋值的元素)。
   - 针对不同的元素类型 (`FixedArray`, `FixedDoubleArray`) 提供了不同的实现。

10. **定义移动和复制数组元素的宏 (`MoveElements`, `CopyElements`)**:
    - 提供了高效地移动和复制数组元素的宏，针对不同的元素类型有不同的实现。

11. **定义克隆 `FastJSArray` 的外部内建函数 (`CloneFastJSArray`)**:
    - 声明了用于克隆快速数组的外部内建函数。

12. **定义 `FastJSArrayWitness` 和 `FastJSArrayForReadWitness` 结构体:**
    - 这两个结构体用于在 Torque 代码中安全地操作 "快速" 数组。
    - 它们包含了对数组状态的检查 (`Recheck`)，确保在进行优化操作时数组的结构没有发生意外变化。
    - 提供了加载元素 (`LoadElementNoHole`, `LoadElementOrUndefined`)、存储空洞 (`StoreHole`)、确保数组可推送 (`EnsureArrayPushable`)、修改长度 (`ChangeLength`)、推送元素 (`Push`)、移动元素等操作。

**与 JavaScript 功能的关系及举例:**

是的，这个文件中的定义与许多 JavaScript 的数组功能直接相关。

**1. 数组迭代:**

- `JSArrayIterator` 和 `CreateArrayIterator` 宏的定义与 JavaScript 中使用 `for...of` 循环或手动调用数组的 `[Symbol.iterator]()` 方法创建的迭代器密切相关。

```javascript
const arr = [10, 20, 30];
const iterator = arr[Symbol.iterator]();

console.log(iterator.next()); // 输出: { value: 10, done: false }
console.log(iterator.next()); // 输出: { value: 20, done: false }
console.log(iterator.next()); // 输出: { value: 30, done: false }
console.log(iterator.next()); // 输出: { value: undefined, done: true }

// 使用 for...of 循环
for (const value of arr) {
  console.log(value);
}

// 使用 entries() 迭代器
for (const [index, value] of arr.entries()) {
  console.log(`Index: ${index}, Value: ${value}`);
}

// 使用 keys() 迭代器
for (const key of arr.keys()) {
  console.log(key);
}

// 使用 values() 迭代器
for (const value of arr.values()) {
  console.log(value);
}
```

文件中的 `IterationKind` 枚举 (kKeys, kValues, kEntries) 就对应了 `entries()`, `values()`, `keys()` 方法返回的迭代器的类型。

**2. 数组创建:**

- `JSArray` 类和 `NewJSArray` 宏与 JavaScript 中创建数组的方式对应。

```javascript
const arr1 = []; // 对应 NewJSArray()
const arr2 = [1, 2, 3]; // 内部会分配内存并填充元素
const arr3 = new Array(5); // 创建一个长度为 5 的空数组 (可能包含 holes)
const arr4 = new Array(1, 2, 3);
```

**3. 数组长度:**

- `JSArray` 类中的 `length` 属性直接对应 JavaScript 数组的 `length` 属性。

```javascript
const arr = [1, 2, 3];
console.log(arr.length); // 输出: 3

arr.length = 5;
console.log(arr); // 输出: [ 1, 2, 3, <2 empty items> ]

arr.length = 2;
console.log(arr); // 输出: [ 1, 2 ]
```

**4. 模板字面量:**

- `TemplateLiteralObject` 类与 JavaScript 中的模板字面量相关。

```javascript
const name = "World";
const greeting = `Hello, ${name}!`; // greeting 内部会用到 TemplateLiteralObject

function tag(strings, ...values) {
  console.log(strings); // 包含模板字符串的静态部分
  console.log(values);  // 包含插值
}

const count = 5;
const price = 10;
tag`You have ${count} items costing $${price}.`;
```

**5. 数组元素的访问:**

- `LoadElementNoHole` 宏与 JavaScript 中访问数组元素的方式对应。

```javascript
const arr = [10, 20, 30];
console.log(arr[0]); // 输出: 10
console.log(arr[1]); // 输出: 20

const sparseArray = [];
sparseArray[0] = 1;
sparseArray[3] = 4;
console.log(sparseArray[1]); // 输出: undefined (内部可能表示为 "hole")
```

**代码逻辑推理 (假设输入与输出):**

**`CreateArrayIterator` 宏:**

假设输入:
- `array`: 一个 JavaScript 数组对象 `[1, 2, 3]`
- `kind`: `IterationKind.kValues` (迭代值)
- `nextIndex`: `0` (初始索引)

输出:
- 一个 `JSArrayIterator` 对象，其内部状态为:
  - `iterated_object`: 指向 `[1, 2, 3]`
  - `next_index`: `0`
  - `kind`:  表示迭代值的 Smi 标签

**`NewJSArrayFilledWithZero` 宏:**

假设输入:
- `length`: `3`

输出:
- 一个 `JSArray` 对象，其内部状态为:
  - `map`: 指向快速 packed Smi 元素数组的 Map 对象
  - `elements`: 指向一个包含 `[0, 0, 0]` 的 `FixedArrayBase`
  - `length`: `3`

**`LoadElementNoHole` 宏:**

假设输入:
- `a`: 一个 JavaScript 数组对象 `[10, , 30]` (注意中间是空，表示 hole)
- `index`: `0`

输出:
- `10`

假设输入:
- `a`: 一个 JavaScript 数组对象 `[10, , 30]`
- `index`: `1`

输出:
- 会跳转到 `IfHole` 标签，表示访问到了空洞。

**涉及用户常见的编程错误:**

1. **错误地假设数组元素的类型:**

```javascript
const arr = [1, 2.5, 'hello'];
// 错误地假设所有元素都是整数
arr.forEach(num => console.log(num.toFixed(0))); // 'hello' 没有 toFixed 方法，会报错
```

V8 内部会根据数组中实际存储的元素类型进行优化，例如 Packed Smi Elements, Packed Double Elements, Holey Elements 等。如果用户没有注意到类型变化，可能会导致意外错误。

2. **在迭代过程中修改数组的长度或元素:**

```javascript
const arr = [1, 2, 3, 4, 5];
for (let i = 0; i < arr.length; i++) {
  if (arr[i] === 3) {
    arr.splice(i, 1); // 从数组中移除元素，改变了数组的长度和结构
  }
  console.log(arr[i]); // 可能跳过某些元素或导致无限循环
}
```

V8 的数组迭代器在创建时会捕获数组的状态。如果在迭代过程中修改数组结构，可能会导致迭代器行为不符合预期。`JSArrayIterator` 的 `next_index` 的设计就考虑了在迭代过程中数组长度可能发生变化的情况。

3. **混淆稀疏数组和密集数组:**

```javascript
const sparseArray = [];
sparseArray[0] = 1;
sparseArray[5] = 6;

console.log(sparseArray.length); // 输出: 6
sparseArray.forEach(item => console.log(item)); // 只会打印 1 和 6，中间的元素是 "holes"

const denseArray = [1, , 6]; // 语法上允许，但会创建包含 holes 的数组
console.log(denseArray.length); // 输出: 3
denseArray.forEach(item => console.log(item)); // 打印 1, undefined, 6
```

用户可能没有意识到数组中存在 "holes"，这会导致在使用 `forEach` 等方法时产生意想不到的结果。`LoadElementNoHole` 宏的存在就是为了处理这种情况。

总而言之，`v8/src/objects/js-array.tq` 文件定义了 V8 中 `JSArray` 对象的内部表示和相关操作，这些定义直接支撑了 JavaScript 数组的各种功能和行为。理解这个文件的内容有助于深入了解 V8 如何优化和管理 JavaScript 数组。

Prompt: 
```
这是目录为v8/src/objects/js-array.tq的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-array.tq以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern enum IterationKind extends uint31 { kKeys, kValues, kEntries }

extern class JSArrayIterator extends JSObject {
  iterated_object: JSReceiver;

  // [next_index]: The [[ArrayIteratorNextIndex]] inobject property.
  // The next_index is always a positive integer, and it points to
  // the next index that is to be returned by this iterator. It's
  // possible range is fixed depending on the [[iterated_object]]:
  //
  //   1. For JSArray's the next_index is always in Unsigned32
  //      range, and when the iterator reaches the end it's set
  //      to kMaxUInt32 to indicate that this iterator should
  //      never produce values anymore even if the "length"
  //      property of the JSArray changes at some later point.
  //   2. For JSTypedArray's the next_index is always in
  //      UnsignedSmall range, and when the iterator terminates
  //      it's set to Smi::kMaxValue.
  //   3. For all other JSReceiver's it's always between 0 and
  //      kMaxSafeInteger, and the latter value is used to mark
  //      termination.
  //
  // It's important that for 1. and 2. the value fits into the
  // Unsigned32 range (UnsignedSmall is a subset of Unsigned32),
  // since we use this knowledge in the fast-path for the array
  // iterator next calls in TurboFan (in the JSCallReducer) to
  // keep the index in Word32 representation. This invariant is
  // checked in JSArrayIterator::JSArrayIteratorVerify().
  next_index: Number;

  kind: SmiTagged<IterationKind>;
}

// Perform CreateArrayIterator (ES #sec-createarrayiterator).
@export
macro CreateArrayIterator(
    implicit context: NativeContext)(array: JSReceiver,
    kind: constexpr IterationKind, nextIndex: Number): JSArrayIterator {
  return new JSArrayIterator{
    map: *NativeContextSlot(ContextSlot::INITIAL_ARRAY_ITERATOR_MAP_INDEX),
    properties_or_hash: kEmptyFixedArray,
    elements: kEmptyFixedArray,
    iterated_object: array,
    next_index: nextIndex,
    kind: SmiTag<IterationKind>(kind)
  };
}

// Perform CreateArrayIterator (ES #sec-createarrayiterator).
@export
macro CreateArrayIterator(
    implicit context: NativeContext)(array: JSReceiver,
    kind: constexpr IterationKind): JSArrayIterator {
  return CreateArrayIterator(array, kind, 0);
}

extern class JSArray extends JSObject {
  macro IsEmpty(): bool {
    return this.length == 0;
  }
  length: Number;
}

@hasSameInstanceTypeAsParent
@doNotGenerateCast
extern class TemplateLiteralObject extends JSArray {
  raw: JSArray;
  function_literal_id: Smi;
  slot_id: Smi;
}

@doNotGenerateCast
extern class JSArrayConstructor extends JSFunction
    generates 'TNode<JSFunction>';

macro NewJSArray(
    implicit context: Context)(map: Map, elements: FixedArrayBase): JSArray {
  return new JSArray{
    map,
    properties_or_hash: kEmptyFixedArray,
    elements,
    length: elements.length
  };
}

macro NewJSArray(implicit context: Context)(): JSArray {
  return new JSArray{
    map: GetFastPackedSmiElementsJSArrayMap(),
    properties_or_hash: kEmptyFixedArray,
    elements: kEmptyFixedArray,
    length: 0
  };
}

macro NewJSArrayFilledWithZero(
    implicit context: Context)(length: intptr): JSArray labels Slow {
  if (length == 0) return NewJSArray();
  if (length > kMaxFastArrayLength) goto Slow;

  const map: Map = GetFastPackedSmiElementsJSArrayMap();
  const elements: FixedArrayBase =
      AllocateFixedArray(ElementsKind::PACKED_SMI_ELEMENTS, length);
  FillFixedArrayWithSmiZero(
      ElementsKind::PACKED_SMI_ELEMENTS, UnsafeCast<FixedArray>(elements), 0,
      length);
  return NewJSArray(map, elements);
}

// A HeapObject with a JSArray map, and either fast packed elements, or fast
// holey elements when the global NoElementsProtector is not invalidated.
transient type FastJSArray extends JSArray;

// A HeapObject with a JSArray map, and either fast packed elements, or fast
// holey elements or frozen, sealed elements when the global NoElementsProtector
// is not invalidated.
transient type FastJSArrayForRead extends JSArray;

// A FastJSArray when the global ArraySpeciesProtector is not invalidated.
transient type FastJSArrayForCopy extends FastJSArray;

// A FastJSArrayForCopy when the global IsConcatSpreadableProtector is not
// invalidated.
transient type FastJSArrayForConcat extends FastJSArrayForCopy;

// A FastJSArray when the global ArrayIteratorProtector is not invalidated.
transient type FastJSArrayWithNoCustomIteration extends FastJSArray;

// A FastJSArrayForRead when the global ArrayIteratorProtector is not
// invalidated.
transient type FastJSArrayForReadWithNoCustomIteration extends
    FastJSArrayForRead;

extern macro AllocateJSArray(
    constexpr ElementsKind, Map, intptr, Smi,
    constexpr AllocationFlag): JSArray;
extern macro AllocateJSArray(
    constexpr ElementsKind, Map, intptr, Smi): JSArray;
extern macro AllocateJSArray(constexpr ElementsKind, Map, Smi, Smi): JSArray;
extern macro AllocateJSArray(Map, FixedArrayBase, Smi): JSArray;

macro LoadElementNoHole<T : type extends FixedArrayBase>(
    a: JSArray, index: Smi): JSAny
    labels IfHole;

LoadElementNoHole<FixedArray>(
    implicit context: Context)(a: JSArray, index: Smi): JSAny
    labels IfHole {
  const elements: FixedArray =
      Cast<FixedArray>(a.elements) otherwise unreachable;
  const e = UnsafeCast<(JSAny | TheHole)>(elements.objects[index]);
  typeswitch (e) {
    case (TheHole): {
      goto IfHole;
    }
    case (e: JSAny): {
      return e;
    }
  }
}

LoadElementNoHole<FixedDoubleArray>(
    implicit context: Context)(a: JSArray, index: Smi): JSAny
    labels IfHole {
  const elements: FixedDoubleArray =
      Cast<FixedDoubleArray>(a.elements) otherwise unreachable;
  const e: float64 = elements.values[index].Value() otherwise IfHole;
  return AllocateHeapNumberWithValue(e);
}

extern builtin ExtractFastJSArray(Context, JSArray, Smi, Smi): JSArray;

extern macro MoveElements(
    constexpr ElementsKind, FixedArrayBase, intptr, intptr, intptr): void;
macro TorqueMoveElementsSmi(
    elements: FixedArray, dstIndex: intptr, srcIndex: intptr,
    count: intptr): void {
  MoveElements(
      ElementsKind::HOLEY_SMI_ELEMENTS, elements, dstIndex, srcIndex, count);
}
macro TorqueMoveElements(
    elements: FixedArray, dstIndex: intptr, srcIndex: intptr,
    count: intptr): void {
  MoveElements(
      ElementsKind::HOLEY_ELEMENTS, elements, dstIndex, srcIndex, count);
}
macro TorqueMoveElements(
    elements: FixedDoubleArray, dstIndex: intptr, srcIndex: intptr,
    count: intptr): void {
  MoveElements(
      ElementsKind::HOLEY_DOUBLE_ELEMENTS, elements, dstIndex, srcIndex, count);
}

extern macro CopyElements(
    constexpr ElementsKind, FixedArrayBase, intptr, FixedArrayBase, intptr,
    intptr): void;
macro TorqueCopyElements(
    dstElements: FixedArray, dstIndex: intptr, srcElements: FixedArray,
    srcIndex: intptr, count: intptr): void {
  CopyElements(
      ElementsKind::HOLEY_ELEMENTS, dstElements, dstIndex, srcElements,
      srcIndex, count);
}
macro TorqueCopyElements(
    dstElements: FixedDoubleArray, dstIndex: intptr,
    srcElements: FixedDoubleArray, srcIndex: intptr, count: intptr): void {
  CopyElements(
      ElementsKind::HOLEY_DOUBLE_ELEMENTS, dstElements, dstIndex, srcElements,
      srcIndex, count);
}

extern builtin CloneFastJSArray(Context, FastJSArrayForCopy): JSArray;

struct FastJSArrayWitness {
  macro Get(): FastJSArray {
    return this.unstable;
  }

  macro Recheck(): void labels CastError {
    if (this.stable.map != this.map) goto CastError;
    // We don't need to check elements kind or whether the prototype
    // has changed away from the default JSArray prototype, because
    // if the map remains the same then those properties hold.
    //
    // However, we have to make sure there are no elements in the
    // prototype chain.
    if (IsNoElementsProtectorCellInvalid()) goto CastError;
    this.unstable = %RawDownCast<FastJSArray>(this.stable);
  }

  macro LoadElementNoHole(implicit context: Context)(k: Smi): JSAny
      labels FoundHole {
    if (this.hasDoubles) {
      return LoadElementNoHole<FixedDoubleArray>(this.unstable, k)
          otherwise FoundHole;
    } else {
      return LoadElementNoHole<FixedArray>(this.unstable, k)
          otherwise FoundHole;
    }
  }

  macro StoreHole(k: Smi): void {
    if (this.hasDoubles) {
      const elements = Cast<FixedDoubleArray>(this.unstable.elements)
          otherwise unreachable;
      elements.values[k] = kDoubleHole;
    } else {
      const elements = Cast<FixedArray>(this.unstable.elements)
          otherwise unreachable;
      elements.objects[k] = TheHole;
    }
  }

  macro LoadElementOrUndefined(implicit context: Context)(k: Smi): JSAny {
    try {
      return this.LoadElementNoHole(k) otherwise FoundHole;
    } label FoundHole {
      return Undefined;
    }
  }

  macro EnsureArrayPushable(implicit context: Context)(): void labels Failed {
    EnsureArrayPushable(this.map) otherwise Failed;
    array::EnsureWriteableFastElements(this.unstable);
    this.arrayIsPushable = true;
  }

  macro ChangeLength(newLength: Smi): void {
    dcheck(this.arrayIsPushable);
    this.unstable.length = newLength;
  }

  macro Push(value: JSAny): void labels Failed {
    dcheck(this.arrayIsPushable);
    if (this.hasDoubles) {
      BuildAppendJSArray(
          ElementsKind::HOLEY_DOUBLE_ELEMENTS, this.unstable, value)
          otherwise Failed;
    } else if (this.hasSmis) {
      BuildAppendJSArray(ElementsKind::HOLEY_SMI_ELEMENTS, this.unstable, value)
          otherwise Failed;
    } else {
      dcheck(
          this.map.elements_kind == ElementsKind::HOLEY_ELEMENTS ||
          this.map.elements_kind == ElementsKind::PACKED_ELEMENTS);
      BuildAppendJSArray(ElementsKind::HOLEY_ELEMENTS, this.unstable, value)
          otherwise Failed;
    }
  }

  macro MoveElements(dst: intptr, src: intptr, length: intptr): void {
    dcheck(this.arrayIsPushable);
    if (this.hasDoubles) {
      const elements: FixedDoubleArray =
          Cast<FixedDoubleArray>(this.unstable.elements)
          otherwise unreachable;
      TorqueMoveElements(elements, dst, src, length);
    } else {
      const elements: FixedArray = Cast<FixedArray>(this.unstable.elements)
          otherwise unreachable;
      if (this.hasSmis) {
        TorqueMoveElementsSmi(elements, dst, src, length);
      } else {
        TorqueMoveElements(elements, dst, src, length);
      }
    }
  }

  const stable: JSArray;
  unstable: FastJSArray;
  const map: Map;
  const hasDoubles: bool;
  const hasSmis: bool;
  arrayIsPushable: bool;
}

macro NewFastJSArrayWitness(array: FastJSArray): FastJSArrayWitness {
  const kind = array.map.elements_kind;
  return FastJSArrayWitness{
    stable: array,
    unstable: array,
    map: array.map,
    hasDoubles: IsDoubleElementsKind(kind),
    hasSmis:
        IsElementsKindLessThanOrEqual(kind, ElementsKind::HOLEY_SMI_ELEMENTS),
    arrayIsPushable: false
  };
}

struct FastJSArrayForReadWitness {
  macro Get(): FastJSArrayForRead {
    return this.unstable;
  }

  macro Recheck(): void labels CastError {
    if (this.stable.map != this.map) goto CastError;
    // We don't need to check elements kind or whether the prototype
    // has changed away from the default JSArray prototype, because
    // if the map remains the same then those properties hold.
    //
    // However, we have to make sure there are no elements in the
    // prototype chain.
    if (IsNoElementsProtectorCellInvalid()) goto CastError;
    this.unstable = %RawDownCast<FastJSArrayForRead>(this.stable);
  }

  macro LoadElementNoHole(implicit context: Context)(k: Smi): JSAny
      labels FoundHole {
    if (this.hasDoubles) {
      return LoadElementNoHole<FixedDoubleArray>(this.unstable, k)
          otherwise FoundHole;
    } else {
      return LoadElementNoHole<FixedArray>(this.unstable, k)
          otherwise FoundHole;
    }
  }

  const stable: JSArray;
  unstable: FastJSArrayForRead;
  const map: Map;
  const hasDoubles: bool;
}

macro NewFastJSArrayForReadWitness(array: FastJSArrayForRead):
    FastJSArrayForReadWitness {
  const kind = array.map.elements_kind;
  return FastJSArrayForReadWitness{
    stable: array,
    unstable: array,
    map: array.map,
    hasDoubles: IsDoubleElementsKind(kind)
  };
}

"""

```