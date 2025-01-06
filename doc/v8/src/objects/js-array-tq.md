Response: Let's break down the thought process for analyzing this Torque code.

1. **Identify the Core Subject:** The filename `js-array.tq` and the prominent classes `JSArray` and `JSArrayIterator` immediately tell us this code is about the implementation of JavaScript arrays within the V8 engine. The `.tq` extension signifies it's written in Torque, V8's internal DSL.

2. **Understand the Goal:**  The request asks for a summary of functionality, connections to JavaScript, code logic explanation (with examples), and common programming errors. This helps structure the analysis.

3. **Initial Scan and Keyword Spotting:** Read through the code, looking for key classes, macros, and concepts. Keywords like `extern`, `class`, `macro`, `extends`, `implicit context`, `constexpr`, `labels`, `typeswitch`, and comments (especially the ES specification references like `#sec-createarrayiterator`) are important clues.

4. **Focus on Key Classes:**
    * **`JSArrayIterator`:** This is clearly about how array iteration works. The members `iterated_object`, `next_index`, and `kind` are crucial. The comment about `next_index` and its different ranges for JSArrays, TypedArrays, and other receivers is a key insight.
    * **`JSArray`:** This represents a JavaScript array. The `length` property and the macros `IsEmpty`, `NewJSArray`, and `NewJSArrayFilledWithZero` are important. The various `transient type` definitions (`FastJSArray`, `FastJSArrayForRead`, etc.) hint at V8's optimization strategies.

5. **Analyze Macros and Functions:**
    * **`CreateArrayIterator`:** This directly corresponds to the ES spec and shows how to create an iterator object. The different overloads are also significant.
    * **`NewJSArray` (multiple overloads):** These show different ways to construct `JSArray` objects, including with pre-filled elements.
    * **`LoadElementNoHole`:** This function handles accessing array elements, specifically dealing with "holes" (uninitialized elements). The `typeswitch` is interesting, indicating different handling for different element types.
    * **`MoveElements` and `CopyElements`:** These are fundamental for array manipulation.
    * **`CloneFastJSArray`:** This suggests efficient copying of arrays.
    * **`FastJSArrayWitness` and `FastJSArrayForReadWitness`:** These "witness" structures are complex but clearly related to optimizing array operations by checking certain conditions. The `Recheck` method and the protector cell checks are indicators of this.

6. **Connect to JavaScript:**  Now, link the Torque concepts to their JavaScript counterparts.
    * `JSArrayIterator` maps to the behavior of `[Symbol.iterator]()` and the iterator protocol (`next()`).
    * `JSArray` directly corresponds to JavaScript arrays.
    * The different `IterationKind` values (`kKeys`, `kValues`, `kEntries`) match the arguments to `array.keys()`, `array.values()`, and `array.entries()`.
    * The `length` property is the same in JavaScript.
    * The "holes" concept explains why accessing an uninitialized array element returns `undefined`.

7. **Explain Code Logic (with Examples):** Choose key macros and classes and create simple scenarios.
    * `CreateArrayIterator`: Show how it initializes the iterator with the array and the iteration kind.
    * `LoadElementNoHole`: Demonstrate the "hole" handling with an example of a sparse array.
    * `FastJSArrayWitness`: Explain the idea of optimization based on stable array properties.

8. **Identify Common Programming Errors:** Think about how the underlying implementation can reveal potential errors.
    * Modifying an array while iterating over it can lead to unexpected behavior due to the iterator's internal `next_index`.
    * Assuming all array elements exist can lead to errors if the array is sparse (contains holes).

9. **Structure the Output:** Organize the findings into clear sections (Functionality, JavaScript Relationship, Code Logic, Common Errors). Use bullet points, code examples, and clear explanations.

10. **Refine and Review:**  Read through the generated explanation to ensure accuracy, clarity, and completeness. Check if all parts of the original request have been addressed. For instance, initially, I might not have fully grasped the significance of the "witness" structs, but further review and analysis would highlight their role in optimization. Similarly, ensuring the JavaScript examples directly illustrate the Torque code's behavior is crucial.

**Self-Correction Example during the Process:**

Initially, I might have just said `FastJSArrayWitness` is for optimization. However, realizing that `Recheck()` checks the map and the `NoElementsProtectorCellInvalid()` provides more specific information. This leads to a more accurate explanation about how V8 optimizes based on the stability of array properties. Similarly, simply stating "handles array access" for `LoadElementNoHole` is insufficient. Recognizing the `IfHole` label and the `typeswitch` leads to a deeper understanding of how holes are managed.
这个v8 torque文件 `v8/src/objects/js-array.tq` 定义了与 JavaScript 数组相关的内部对象结构和操作。 它的主要功能可以归纳为以下几点：

**1. 定义了 `JSArrayIterator` 对象:**

*   这个对象是 JavaScript 数组迭代器的内部表示。
*   它包含了迭代所需的状态信息，例如被迭代的数组 (`iterated_object`)，下一个要返回的元素的索引 (`next_index`)，以及迭代的类型 (`kind`，例如键、值或键值对）。
*   **与 JavaScript 的关系:**  它对应于 JavaScript 中使用 `[Symbol.iterator]()` 方法或 `array.keys()`, `array.values()`, `array.entries()` 等方法返回的迭代器对象。

    ```javascript
    const arr = [10, 20, 30];
    const iterator1 = arr[Symbol.iterator]();
    console.log(iterator1.next()); // { value: 10, done: false }

    const iterator2 = arr.values();
    console.log(iterator2.next()); // { value: 10, done: false }

    const iterator3 = arr.keys();
    console.log(iterator3.next()); // { value: 0, done: false }

    const iterator4 = arr.entries();
    console.log(iterator4.next()); // { value: [ 0, 10 ], done: false }
    ```

*   **代码逻辑推理:**
    *   **假设输入:** 一个 `JSArray` 对象 `arr` 和 `IterationKind.kValues`。
    *   **输出:**  `CreateArrayIterator` 宏会创建一个 `JSArrayIterator` 对象，其 `iterated_object` 属性指向 `arr`， `kind` 属性为 `kValues`，`next_index` 属性初始化为 0。

**2. 定义了 `JSArray` 对象:**

*   这是 JavaScript 数组在 V8 内部的表示。
*   它包含数组的长度 (`length`) 和存储元素的 `elements`。
*   `IsEmpty()` 宏用于检查数组是否为空。
*   **与 JavaScript 的关系:** 它直接对应于 JavaScript 中的 `Array` 对象。

    ```javascript
    const arr = [1, 2, 3];
    console.log(arr.length); // 3
    ```

*   **代码逻辑推理:**
    *   **假设输入:**  调用 `NewJSArray()` 宏。
    *   **输出:**  会创建一个新的空的 `JSArray` 对象，其 `length` 为 0， `elements` 是一个空的 `FixedArray`。
    *   **假设输入:** 调用 `NewJSArrayFilledWithZero(5)` 宏。
    *   **输出:** 会创建一个新的 `JSArray` 对象，其 `length` 为 5， `elements` 是一个包含 5 个 0 的 `FixedArray`。

**3. 定义了 `TemplateLiteralObject` 对象:**

*   它是用于模板字面量的内部表示，继承自 `JSArray`。
*   它包含原始字符串 (`raw`)、函数字面量 ID (`function_literal_id`) 和槽 ID (`slot_id`)。
*   **与 JavaScript 的关系:**  它与模板字面量（template literals）相关。

    ```javascript
    const name = "World";
    const greeting = `Hello, ${name}!`; // greeting 是一个 TemplateLiteralObject
    console.log(greeting);
    ```

**4. 定义了 `JSArrayConstructor` 对象:**

*   这是 `Array` 构造函数的内部表示。
*   **与 JavaScript 的关系:**  它对应于 JavaScript 中的全局 `Array` 构造函数。

    ```javascript
    const arr = new Array(5); // 使用 Array 构造函数
    ```

**5. 定义了创建 `JSArray` 对象的宏 (`NewJSArray`, `NewJSArrayFilledWithZero`):**

*   这些宏提供了创建不同状态 `JSArray` 对象的方式，例如空数组或用零填充的数组。

**6. 定义了不同类型的 `FastJSArray`:**

*   这些是优化后的 `JSArray` 类型，用于提高性能。它们基于 V8 的类型反馈和内联缓存技术。
*   例如，`FastJSArray`、`FastJSArrayForRead`、`FastJSArrayForCopy`、`FastJSArrayForConcat`、`FastJSArrayWithNoCustomIteration` 等，代表了在不同优化场景下的数组类型。

**7. 定义了加载元素的宏 (`LoadElementNoHole`):**

*   此宏用于加载数组元素，并处理数组中可能存在的 "空洞" (holes)。
*   **与 JavaScript 的关系:**  它对应于 JavaScript 中访问数组元素的操作，例如 `arr[index]`。
*   **代码逻辑推理:**
    *   **假设输入:** 一个 `JSArray` 对象 `a` 和一个索引 `index`。
    *   **输出:** 如果 `a` 在 `index` 位置有值，则返回该值。如果该位置是 "空洞"，则跳转到 `IfHole` 标签。

**8. 定义了移动和复制元素的宏 (`MoveElements`, `CopyElements`):**

*   这些宏用于在数组内部移动或复制元素，是实现数组操作的基础。

**9. 定义了克隆数组的内置函数 (`CloneFastJSArray`):**

*   用于高效地克隆快速数组。

**10. 定义了 `FastJSArrayWitness` 和 `FastJSArrayForReadWitness` 结构体:**

*   这些结构体用于在 TurboFan 优化中提供关于 `FastJSArray` 的稳定性和属性的 "证明" (witness)。它们允许编译器进行更激进的优化，因为它们保证了某些数组属性在执行期间不会改变。
*   它们包含检查数组状态和加载元素的辅助宏。

**常见的编程错误 (与 JavaScript 功能相关):**

*   **读取未初始化的数组元素（空洞）：** 在 JavaScript 中，访问数组的 "空洞" 会返回 `undefined`，但这可能不是预期行为，并可能导致程序错误。

    ```javascript
    const arr = new Array(5); // 创建一个包含 5 个空洞的数组
    console.log(arr[0]); // undefined

    // 假设你期望这里得到一个初始值，但实际上是 undefined，可能导致后续计算错误。
    if (arr[0] > 0) {
      console.log("Element is positive");
    } else {
      console.log("Element is not positive"); // 实际会输出这个
    }
    ```

*   **在迭代过程中修改数组：**  直接修改正在被迭代的数组可能会导致迭代器产生不可预测的行为，例如跳过元素或重复访问元素。`JSArrayIterator` 的 `next_index` 属性在迭代过程中会被更新，如果在迭代过程中数组的结构发生变化，这个索引可能会变得不准确。

    ```javascript
    const arr = [1, 2, 3, 4, 5];
    for (const element of arr) {
      console.log(element);
      if (element === 3) {
        arr.push(6); // 在迭代过程中修改了数组
      }
    }
    // 输出结果可能不是你期望的 [1, 2, 3, 4, 5, 6]，因为迭代器可能不会访问到新添加的元素。
    ```

*   **假设数组的元素类型一致：**  JavaScript 数组可以包含不同类型的元素。 然而，V8 内部会尝试优化数组以存储特定类型的元素（例如，只包含小的整数）。 如果你在运行时向数组添加不同类型的元素，可能会触发数组的 "变形" (transition)，这可能会带来性能开销。

    ```javascript
    const arr = [1, 2, 3]; // 假设 V8 优化为存储小的整数
    arr.push("hello"); // 添加了一个字符串，可能导致数组变形
    ```

总而言之，`v8/src/objects/js-array.tq` 文件是 V8 引擎中关于 JavaScript 数组实现的核心定义，它描述了数组对象的内部结构、迭代机制以及相关的优化策略。理解这个文件有助于深入了解 JavaScript 数组在底层是如何工作的。

Prompt: 
```
这是目录为v8/src/objects/js-array.tq的一个v8 torque源代码， 请归纳一下它的功能, 
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