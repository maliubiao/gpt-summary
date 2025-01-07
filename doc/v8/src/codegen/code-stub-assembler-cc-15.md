Response:
Let's break down the thought process for analyzing this code snippet and fulfilling the user's request.

**1. Initial Understanding of the Request:**

The core request is to understand the functionality of the provided C++ code snippet from V8's `code-stub-assembler.cc`. Specifically, it asks for:

* A summary of its functions.
* Confirmation of its Torque nature (based on file extension, which is irrelevant here as the provided code is clearly C++).
* Connections to JavaScript functionality with examples.
* Logic reasoning with hypothetical inputs and outputs.
* Common programming errors.
* A summary of its function within the larger context (being part 16 of 23).

**2. High-Level Code Overview:**

My first pass through the code involves skimming to identify the major components and patterns. I immediately recognize:

* **Templates:**  The extensive use of `template <>` indicates a focus on generic programming, likely handling different data types (e.g., different typed array element kinds).
* **`CodeStubAssembler` Class:** This is the central class. The methods are members of this class.
* **Typed Array Operations:** Keywords like `StoreElementTypedArray`, `PrepareValueForWriteToTypedArray`, and references to `ElementsKind` strongly suggest the code deals with operations on JavaScript Typed Arrays.
* **Memory Management:**  The use of `RawPtrT`, `IntPtrT`, `UintPtrT`, and functions like `StoreNoWriteBarrier` hint at low-level memory manipulation.
* **Labels and Control Flow:**  The presence of `Label`, `GotoIf`, `Branch`, and `BIND` indicates a control flow mechanism used in the `CodeStubAssembler`.
* **Type Conversions:** Functions like `Int32ToUint8Clamped`, `Float64ToUint8Clamped`, `TruncateFloat64ToWord32`, etc., point to type conversion logic, particularly related to the constraints of typed arrays.

**3. Focusing on Key Functions and Patterns:**

I then zoom in on the prominent functions to understand their individual roles:

* **`StoreElementTypedArray` family:**  These are clearly responsible for writing values into the backing store of Typed Arrays. The template specializations handle various element types (integers, floats, BigInt). The `StoreNoWriteBarrier` function suggests these are performance-critical operations where write barriers (for garbage collection) are potentially bypassed under specific conditions.
* **`PrepareValueForWriteToTypedArray` family:**  These functions are crucial for preparing JavaScript values (which can be various types) for storage in the fixed-type storage of a Typed Array. They handle conversions (e.g., Number to integer, clamping, floating-point truncation) and also deal with potential type errors by calling `Builtin::kNonNumberToNumber`. The logic involving `Smi`, `HeapNumber`, and `Oddball` is about efficiently handling common JavaScript number representations.
* **Clamping Functions (`Int32ToUint8Clamped`, `Float64ToUint8Clamped`):** These implement the specific clamping behavior required for `Uint8ClampedArray`.
* **`BigIntToRawBytes`:** This function handles the conversion of JavaScript BigInt values into their raw byte representation, likely for storage in memory.
* **`EmitElementStoreTypedArray`:** This function orchestrates the process of storing a value into a Typed Array, including checks for detached buffers, bounds checking, and potential bailouts.
* **`EmitElementStore`:** This is a higher-level function that handles storing values into various types of JavaScript objects (including Typed Arrays), handling different element kinds and store modes. It involves checks for COW arrays and calls into `EmitElementStoreTypedArray` for Typed Arrays.
* **`CheckForCapacityGrow`:**  Deals with potentially resizing the backing store of a JavaScript array when an element is added beyond its current capacity.
* **`CopyElementsOnWrite`:** Handles the copy-on-write behavior for certain array types.

**4. Connecting to JavaScript:**

Now I consider how these C++ functions relate to JavaScript. The key is to think about operations a JavaScript programmer can perform that would involve these low-level actions:

* **Creating and manipulating Typed Arrays:**  `new Uint8Array(...)`, `myArray[i] = value`.
* **Assigning values to array elements:** `array[index] = value`.
* **Potential type coercion:**  JavaScript's loose typing means assigning a string to a `Uint8Array` element will trigger a conversion.
* **Out-of-bounds access:**  Trying to access or set elements outside the array's bounds.
* **Detached ArrayBuffers:**  Operations on ArrayBuffers that have been detached.

This leads to the JavaScript examples provided in the good answer.

**5. Logic Reasoning (Hypothetical Inputs and Outputs):**

To illustrate the logic, I pick specific functions and consider simple scenarios:

* **`Int32ToUint8Clamped`:**  Provide inputs below 0, within the range, and above 255 to demonstrate the clamping.
* **`PrepareValueForWriteToTypedArray<Word32T>`:**  Use different JavaScript value types (Smi, HeapNumber, string) to show the conversion process.

**6. Common Programming Errors:**

I consider common mistakes JavaScript developers make when working with Typed Arrays:

* **Incorrect data types:**  Trying to store a string directly into an integer Typed Array.
* **Out-of-bounds writes:**  Accessing indices beyond the array's length.
* **Operating on detached ArrayBuffers:**  Trying to use a Typed Array whose underlying buffer has been detached.

**7. Context within the Series (Part 16 of 23):**

Given that this is part 16 of 23, I infer that the surrounding parts likely deal with other aspects of code generation and execution within V8. Part 16 seems focused on the specifics of *storing* data, particularly into arrays. The earlier parts might cover loading data, control flow, or function calls, while later parts could deal with more complex operations or optimizations.

**8. Structuring the Answer:**

Finally, I organize the information logically, starting with the main functionality, then moving to specific details like JavaScript examples, logic reasoning, and common errors. I ensure to address all points of the original request. The initial thought process doesn't necessarily follow this exact linear order but involves jumping between different aspects of the code and the request to build a comprehensive understanding.
好的，让我们来分析一下这段 `v8/src/codegen/code-stub-assembler.cc` 的代码片段，它是关于在 V8 的代码桩汇编器中处理存储操作的。

**功能归纳:**

这段代码的主要功能是提供了一系列用于在内存中存储数据的底层操作，特别是针对 JavaScript 的类型化数组（Typed Arrays）和普通数组。它定义了多种 `StoreElement` 方法，这些方法根据要存储的数据类型、目标内存的类型（例如，原始指针 `RawPtrT` 或固定数组 `FixedArrayBase`）以及元素类型 `ElementsKind` 来进行分派。

核心功能点包括：

1. **类型化数组存储:** 提供了针对各种类型化数组元素类型（如 `Uint8T`, `Int32T`, `Float32T`, `Float64T`, `BigInt` 等）的存储操作。这些操作考虑了不同类型的数据在内存中的表示方式和大小。
2. **普通数组存储:** 针对普通 JavaScript 数组（底层使用 `FixedArrayBase` 存储）的存储操作，处理了 Smi（小整数）和 Object 类型的存储。
3. **类型转换和钳位:** 提供了将 JavaScript 的 Number 类型转换为适合存储到特定类型化数组的数值类型的逻辑，例如 `Int32ToUint8Clamped` 和 `Float64ToUint8Clamped` 用于将数字钳位到 0-255 的范围内。`PrepareValueForWriteToTypedArray` 负责将 JavaScript 对象转换为可以写入类型化数组的原始值。
4. **BigInt 处理:** 包含了将 JavaScript 的 BigInt 类型转换为原始字节表示形式的逻辑 (`BigIntToRawBytes`)。
5. **越界检查和增长:**  `EmitElementStoreTypedArray` 和 `EmitElementStore` 函数中包含了对数组越界访问的检查，以及在需要时进行数组容量增长的逻辑 (`CheckForCapacityGrow`)。
6. **Copy-on-Write (COW) 处理:** `CopyElementsOnWrite` 函数处理了当尝试修改共享的、写时复制（COW）数组时的复制行为。
7. **共享数组处理:**  针对 `SHARED_ARRAY_ELEMENTS` 类型的数组，包含了 `SharedValueBarrier` 用于确保在多线程环境下的数据一致性。
8. **代码桩汇编器集成:** 这些功能都是作为 `CodeStubAssembler` 类的成员提供的，这意味着它们被用于构建 V8 的代码桩（Code Stubs），这些代码桩是 V8 优化 JavaScript 执行的关键部分。

**关于 .tq 结尾:**

如果 `v8/src/codegen/code-stub-assembler.cc` 文件以 `.tq` 结尾，那么它就是一个 **V8 Torque 源代码**。Torque 是 V8 用来定义运行时函数和生成高效机器码的领域特定语言。然而，你提供的代码片段是 `.cc` 文件，这意味着它是 **C++ 代码**。`.cc` 文件通常包含 `CodeStubAssembler` 类的实现，而 `.tq` 文件会定义可以被 `CodeStubAssembler` 使用的更高级别的操作。

**与 JavaScript 的关系及示例:**

这段代码直接关系到 JavaScript 中数组的元素赋值操作，特别是类型化数组。

**类型化数组示例:**

```javascript
const uint8Array = new Uint8Array(10);
uint8Array[0] = 100; // 直接存储一个整数
uint8Array[1] = 300; // 会被钳位到 255
uint8Array[2] = -50; // 会被钳位到 0

const float32Array = new Float32Array(5);
float32Array[0] = 3.14; // 存储一个浮点数

const bigIntArray = new BigInt64Array(2);
bigIntArray[0] = 10n; // 存储一个 BigInt
```

在这些 JavaScript 操作的背后，V8 的代码桩汇编器会生成相应的机器码，其中就可能使用到 `CodeStubAssembler` 提供的 `StoreElementTypedArray` 等方法来将值存储到内存中的类型化数组的底层缓冲区。

**普通数组示例:**

```javascript
const arr = [1, 'hello', { value: 5 }];
arr[0] = 10; // 存储一个 Smi
arr[1] = 'world'; // 存储一个 Object (String)
```

对于普通数组，当执行 `arr[index] = value` 时，`CodeStubAssembler` 可能会使用 `StoreElement` 的其他重载版本来处理不同类型的 `value`。

**代码逻辑推理:**

**假设输入:**

* `elements`: 指向 `Uint8Array` 底层数据缓冲区的 `RawPtrT` 指针。
* `kind`: `UINT8_ELEMENTS`。
* `index`: 一个 `UintPtrT`，值为 `5`。
* `value`: 一个 `Word32T`，值为 `200`。

**预期输出:**

`StoreElementTypedArrayWord32` 函数会被调用。由于 `kind` 是 `UINT8_ELEMENTS`，所以不会进行钳位检查。函数会计算出偏移量（假设每个 `Uint8` 占 1 字节），然后使用 `StoreNoWriteBarrier` 将值 `200`（其二进制表示）存储到 `elements` 指针偏移 `5` 个字节的位置。

**假设输入 (钳位):**

* `elements`: 指向 `Uint8ClampedArray` 底层数据缓冲区的 `RawPtrT` 指针。
* `kind`: `UINT8_CLAMPED_ELEMENTS`。
* `index`: 一个 `UintPtrT`，值为 `0`。
* `value`: 一个 `Word32T`，值为 `300`。

**预期输出:**

`StoreElementTypedArrayWord32` 函数会被调用。由于 `kind` 是 `UINT8_CLAMPED_ELEMENTS`，代码中的 `CSA_DCHECK` 会检查 `value` 是否等于其与 `0xFF` 的按位与结果。由于 `300` 大于 255，理论上这里会有一个断言（在 DCHECK 编译模式下）。最终，存储到内存中的值会被钳位到 `255`。

**用户常见的编程错误:**

1. **类型不匹配:** 尝试将不兼容的数据类型存储到类型化数组中，例如将字符串直接赋值给 `Int32Array` 的元素，可能会导致类型转换错误或未定义的行为。

   ```javascript
   const int32Array = new Int32Array(1);
   int32Array[0] = "hello"; // JavaScript 会尝试转换，但底层存储可能得到非预期结果
   ```

2. **越界访问:** 尝试访问或写入超出数组边界的元素。对于类型化数组，这通常不会导致动态增长，而是可能抛出错误或在某些情况下导致内存访问错误。

   ```javascript
   const uint8Array = new Uint8Array(5);
   uint8Array[10] = 100; // 越界访问
   ```

3. **对 Detached 的 ArrayBuffer 进行操作:**  尝试操作一个其底层 `ArrayBuffer` 已经被分离的类型化数组。

   ```javascript
   const buffer = new ArrayBuffer(10);
   const uint8Array = new Uint8Array(buffer);
   // ... 分离 buffer 的操作 ...
   uint8Array[0] = 5; // 错误：尝试操作 detached buffer
   ```

4. **不理解钳位行为:**  对于 `Uint8ClampedArray`，开发者可能没有意识到超出 0-255 范围的值会被钳位。

   ```javascript
   const clampedArray = new Uint8ClampedArray(1);
   clampedArray[0] = 300;
   console.log(clampedArray[0]); // 输出 255，可能与预期不符
   ```

**第 16 部分功能归纳:**

作为 23 个部分中的第 16 部分，这段代码很可能专注于 V8 代码生成过程中 **数组元素的存储操作**。考虑到之前和之后的部分，可能：

* **之前的部分 (例如，第 1-15 部分):** 可能涉及代码生成器的初始化、指令的选择、内存分配、加载操作等。
* **之后的部分 (例如，第 17-23 部分):**  可能涉及更复杂的数组操作（如 slice, map, filter）、函数调用、控制流、异常处理、垃圾回收相关的写屏障处理等。

因此，第 16 部分的核心职责是提供用于将各种类型的数据安全且高效地写入到 JavaScript 数组（特别是类型化数组）底层内存的机制，并处理类型转换、边界检查和特殊情况（如 COW 数组）。它是 V8 实现 JavaScript 数组操作的关键底层基础设施。

希望这个详细的分析能够帮助你理解这段 V8 源代码的功能。

Prompt: 
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第16部分，共23部分，请归纳一下它的功能

"""
s,
                          IntPtrAdd(offset, IntPtrConstant(kSystemPointerSize)),
                          var_high.value());
    }
#endif
}

template <>
void CodeStubAssembler::StoreElementTypedArray(TNode<RawPtrT> elements,
                                               ElementsKind kind,
                                               TNode<UintPtrT> index,
                                               TNode<BigInt> value) {
  StoreElementTypedArrayBigInt(elements, kind, index, value);
}

template <>
void CodeStubAssembler::StoreElementTypedArray(TNode<RawPtrT> elements,
                                               ElementsKind kind,
                                               TNode<IntPtrT> index,
                                               TNode<BigInt> value) {
  StoreElementTypedArrayBigInt(elements, kind, index, value);
}

template <typename TIndex>
void CodeStubAssembler::StoreElementTypedArrayWord32(TNode<RawPtrT> elements,
                                                     ElementsKind kind,
                                                     TNode<TIndex> index,
                                                     TNode<Word32T> value) {
  static_assert(std::is_same<TIndex, UintPtrT>::value ||
                    std::is_same<TIndex, IntPtrT>::value,
                "Only UintPtrT or IntPtrT indices is allowed");
  DCHECK(IsTypedArrayElementsKind(kind));
  if (kind == UINT8_CLAMPED_ELEMENTS) {
    CSA_DCHECK(this, Word32Equal(value, Word32And(Int32Constant(0xFF), value)));
  }
  TNode<IntPtrT> offset = ElementOffsetFromIndex(index, kind, 0);
  // TODO(cbruni): Add OOB check once typed.
  MachineRepresentation rep = ElementsKindToMachineRepresentation(kind);
  StoreNoWriteBarrier(rep, elements, offset, value);
}

template <>
void CodeStubAssembler::StoreElementTypedArray(TNode<RawPtrT> elements,
                                               ElementsKind kind,
                                               TNode<UintPtrT> index,
                                               TNode<Word32T> value) {
  StoreElementTypedArrayWord32(elements, kind, index, value);
}

template <>
void CodeStubAssembler::StoreElementTypedArray(TNode<RawPtrT> elements,
                                               ElementsKind kind,
                                               TNode<IntPtrT> index,
                                               TNode<Word32T> value) {
  StoreElementTypedArrayWord32(elements, kind, index, value);
}

template <typename TArray, typename TIndex, typename TValue>
void CodeStubAssembler::StoreElementTypedArray(TNode<TArray> elements,
                                               ElementsKind kind,
                                               TNode<TIndex> index,
                                               TNode<TValue> value) {
  // TODO(v8:9708): Do we want to keep both IntPtrT and UintPtrT variants?
  static_assert(std::is_same<TIndex, Smi>::value ||
                    std::is_same<TIndex, UintPtrT>::value ||
                    std::is_same<TIndex, IntPtrT>::value,
                "Only Smi, UintPtrT or IntPtrT indices is allowed");
  static_assert(std::is_same<TArray, RawPtrT>::value ||
                    std::is_same<TArray, FixedArrayBase>::value,
                "Only RawPtrT or FixedArrayBase elements are allowed");
  static_assert(std::is_same<TValue, Float16RawBitsT>::value ||
                    std::is_same<TValue, Int32T>::value ||
                    std::is_same<TValue, Float32T>::value ||
                    std::is_same<TValue, Float64T>::value ||
                    std::is_same<TValue, Object>::value,
                "Only Int32T, Float32T, Float64T or object value "
                "types are allowed");
  DCHECK(IsTypedArrayElementsKind(kind));
  TNode<IntPtrT> offset = ElementOffsetFromIndex(index, kind, 0);
  // TODO(cbruni): Add OOB check once typed.
  MachineRepresentation rep = ElementsKindToMachineRepresentation(kind);
  StoreNoWriteBarrier(rep, elements, offset, value);
}

template <typename TIndex>
void CodeStubAssembler::StoreElement(TNode<FixedArrayBase> elements,
                                     ElementsKind kind, TNode<TIndex> index,
                                     TNode<Object> value) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT indices are allowed");
  DCHECK(!IsDoubleElementsKind(kind));
  if (IsTypedArrayElementsKind(kind)) {
    StoreElementTypedArray(elements, kind, index, value);
  } else if (IsSmiElementsKind(kind)) {
    TNode<Smi> smi_value = CAST(value);
    StoreFixedArrayElement(CAST(elements), index, smi_value);
  } else {
    StoreFixedArrayElement(CAST(elements), index, value);
  }
}

template <typename TIndex>
void CodeStubAssembler::StoreElement(TNode<FixedArrayBase> elements,
                                     ElementsKind kind, TNode<TIndex> index,
                                     TNode<Float64T> value) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT indices are allowed");
  DCHECK(IsDoubleElementsKind(kind));
  StoreFixedDoubleArrayElement(CAST(elements), index, value);
}

template <typename TIndex, typename TValue>
void CodeStubAssembler::StoreElement(TNode<RawPtrT> elements, ElementsKind kind,
                                     TNode<TIndex> index, TNode<TValue> value) {
  static_assert(std::is_same<TIndex, Smi>::value ||
                    std::is_same<TIndex, IntPtrT>::value ||
                    std::is_same<TIndex, UintPtrT>::value,
                "Only Smi, IntPtrT or UintPtrT indices are allowed");
  static_assert(
      std::is_same<TValue, Float16RawBitsT>::value ||
          std::is_same<TValue, Int32T>::value ||
          std::is_same<TValue, Word32T>::value ||
          std::is_same<TValue, Float32T>::value ||
          std::is_same<TValue, Float64T>::value ||
          std::is_same<TValue, BigInt>::value,
      "Only Int32T, Word32T, Float32T, Float64T or BigInt value types "
      "are allowed");

  DCHECK(IsTypedArrayElementsKind(kind));
  StoreElementTypedArray(elements, kind, index, value);
}
template V8_EXPORT_PRIVATE void CodeStubAssembler::StoreElement(TNode<RawPtrT>,
                                                                ElementsKind,
                                                                TNode<UintPtrT>,
                                                                TNode<Int32T>);
template V8_EXPORT_PRIVATE void CodeStubAssembler::StoreElement(TNode<RawPtrT>,
                                                                ElementsKind,
                                                                TNode<UintPtrT>,
                                                                TNode<Word32T>);
template V8_EXPORT_PRIVATE void CodeStubAssembler::StoreElement(
    TNode<RawPtrT>, ElementsKind, TNode<UintPtrT>, TNode<Float32T>);
template V8_EXPORT_PRIVATE void CodeStubAssembler::StoreElement(
    TNode<RawPtrT>, ElementsKind, TNode<UintPtrT>, TNode<Float64T>);
template V8_EXPORT_PRIVATE void CodeStubAssembler::StoreElement(TNode<RawPtrT>,
                                                                ElementsKind,
                                                                TNode<UintPtrT>,
                                                                TNode<BigInt>);
template V8_EXPORT_PRIVATE void CodeStubAssembler::StoreElement(
    TNode<RawPtrT>, ElementsKind, TNode<UintPtrT>, TNode<Float16RawBitsT>);

TNode<Uint8T> CodeStubAssembler::Int32ToUint8Clamped(
    TNode<Int32T> int32_value) {
  Label done(this);
  TNode<Int32T> int32_zero = Int32Constant(0);
  TNode<Int32T> int32_255 = Int32Constant(255);
  TVARIABLE(Word32T, var_value, int32_value);
  GotoIf(Uint32LessThanOrEqual(int32_value, int32_255), &done);
  var_value = int32_zero;
  GotoIf(Int32LessThan(int32_value, int32_zero), &done);
  var_value = int32_255;
  Goto(&done);
  BIND(&done);
  return UncheckedCast<Uint8T>(var_value.value());
}

TNode<Uint8T> CodeStubAssembler::Float64ToUint8Clamped(
    TNode<Float64T> float64_value) {
  Label done(this);
  TVARIABLE(Word32T, var_value, Int32Constant(0));
  GotoIf(Float64LessThanOrEqual(float64_value, Float64Constant(0.0)), &done);
  var_value = Int32Constant(255);
  GotoIf(Float64LessThanOrEqual(Float64Constant(255.0), float64_value), &done);
  {
    TNode<Float64T> rounded_value = Float64RoundToEven(float64_value);
    var_value = TruncateFloat64ToWord32(rounded_value);
    Goto(&done);
  }
  BIND(&done);
  return UncheckedCast<Uint8T>(var_value.value());
}

template <>
TNode<Word32T> CodeStubAssembler::PrepareValueForWriteToTypedArray<Word32T>(
    TNode<Object> input, ElementsKind elements_kind, TNode<Context> context) {
  DCHECK(IsTypedArrayElementsKind(elements_kind));

  switch (elements_kind) {
    case UINT8_ELEMENTS:
    case INT8_ELEMENTS:
    case UINT16_ELEMENTS:
    case INT16_ELEMENTS:
    case UINT32_ELEMENTS:
    case INT32_ELEMENTS:
    case UINT8_CLAMPED_ELEMENTS:
      break;
    default:
      UNREACHABLE();
  }

  TVARIABLE(Word32T, var_result);
  TVARIABLE(Object, var_input, input);
  Label done(this, &var_result), if_smi(this), if_heapnumber_or_oddball(this),
      convert(this), loop(this, &var_input);
  Goto(&loop);
  BIND(&loop);
  GotoIf(TaggedIsSmi(var_input.value()), &if_smi);
  // We can handle both HeapNumber and Oddball here, since Oddball has the
  // same layout as the HeapNumber for the HeapNumber::value field. This
  // way we can also properly optimize stores of oddballs to typed arrays.
  TNode<HeapObject> heap_object = CAST(var_input.value());
  GotoIf(IsHeapNumber(heap_object), &if_heapnumber_or_oddball);
  STATIC_ASSERT_FIELD_OFFSETS_EQUAL(offsetof(HeapNumber, value_),
                                    offsetof(Oddball, to_number_raw_));
  Branch(HasInstanceType(heap_object, ODDBALL_TYPE), &if_heapnumber_or_oddball,
         &convert);

  BIND(&if_heapnumber_or_oddball);
  {
    TNode<Float64T> value =
        LoadObjectField<Float64T>(heap_object, offsetof(HeapNumber, value_));
    if (elements_kind == UINT8_CLAMPED_ELEMENTS) {
      var_result = Float64ToUint8Clamped(value);
    } else if (elements_kind == FLOAT16_ELEMENTS) {
      var_result = ReinterpretCast<Word32T>(TruncateFloat64ToFloat16(value));
    } else {
      var_result = TruncateFloat64ToWord32(value);
    }
    Goto(&done);
  }

  BIND(&if_smi);
  {
    TNode<Int32T> value = SmiToInt32(CAST(var_input.value()));
    if (elements_kind == UINT8_CLAMPED_ELEMENTS) {
      var_result = Int32ToUint8Clamped(value);
    } else if (elements_kind == FLOAT16_ELEMENTS) {
      var_result = ReinterpretCast<Word32T>(RoundInt32ToFloat16(value));
    } else {
      var_result = value;
    }
    Goto(&done);
  }

  BIND(&convert);
  {
    var_input = CallBuiltin(Builtin::kNonNumberToNumber, context, input);
    Goto(&loop);
  }

  BIND(&done);
  return var_result.value();
}

template <>
TNode<Float16RawBitsT>
CodeStubAssembler::PrepareValueForWriteToTypedArray<Float16RawBitsT>(
    TNode<Object> input, ElementsKind elements_kind, TNode<Context> context) {
  DCHECK(IsTypedArrayElementsKind(elements_kind));
  CHECK_EQ(elements_kind, FLOAT16_ELEMENTS);

  TVARIABLE(Float16RawBitsT, var_result);
  TVARIABLE(Object, var_input, input);
  Label done(this, &var_result), if_smi(this), if_heapnumber_or_oddball(this),
      convert(this), loop(this, &var_input);
  Goto(&loop);
  BIND(&loop);
  GotoIf(TaggedIsSmi(var_input.value()), &if_smi);
  // We can handle both HeapNumber and Oddball here, since Oddball has the
  // same layout as the HeapNumber for the HeapNumber::value field. This
  // way we can also properly optimize stores of oddballs to typed arrays.
  TNode<HeapObject> heap_object = CAST(var_input.value());
  GotoIf(IsHeapNumber(heap_object), &if_heapnumber_or_oddball);
  STATIC_ASSERT_FIELD_OFFSETS_EQUAL(offsetof(HeapNumber, value_),
                                    offsetof(Oddball, to_number_raw_));
  Branch(HasInstanceType(heap_object, ODDBALL_TYPE), &if_heapnumber_or_oddball,
         &convert);

  BIND(&if_heapnumber_or_oddball);
  {
    TNode<Float64T> value =
        LoadObjectField<Float64T>(heap_object, offsetof(HeapNumber, value_));
    var_result = TruncateFloat64ToFloat16(value);
    Goto(&done);
  }

  BIND(&if_smi);
  {
    TNode<Int32T> value = SmiToInt32(CAST(var_input.value()));
    var_result = RoundInt32ToFloat16(value);
    Goto(&done);
  }

  BIND(&convert);
  {
    var_input = CallBuiltin(Builtin::kNonNumberToNumber, context, input);
    Goto(&loop);
  }

  BIND(&done);
  return var_result.value();
}

template <>
TNode<Float32T> CodeStubAssembler::PrepareValueForWriteToTypedArray<Float32T>(
    TNode<Object> input, ElementsKind elements_kind, TNode<Context> context) {
  DCHECK(IsTypedArrayElementsKind(elements_kind));
  CHECK_EQ(elements_kind, FLOAT32_ELEMENTS);

  TVARIABLE(Float32T, var_result);
  TVARIABLE(Object, var_input, input);
  Label done(this, &var_result), if_smi(this), if_heapnumber_or_oddball(this),
      convert(this), loop(this, &var_input);
  Goto(&loop);
  BIND(&loop);
  GotoIf(TaggedIsSmi(var_input.value()), &if_smi);
  // We can handle both HeapNumber and Oddball here, since Oddball has the
  // same layout as the HeapNumber for the HeapNumber::value field. This
  // way we can also properly optimize stores of oddballs to typed arrays.
  TNode<HeapObject> heap_object = CAST(var_input.value());
  GotoIf(IsHeapNumber(heap_object), &if_heapnumber_or_oddball);
  STATIC_ASSERT_FIELD_OFFSETS_EQUAL(offsetof(HeapNumber, value_),
                                    offsetof(Oddball, to_number_raw_));
  Branch(HasInstanceType(heap_object, ODDBALL_TYPE), &if_heapnumber_or_oddball,
         &convert);

  BIND(&if_heapnumber_or_oddball);
  {
    TNode<Float64T> value =
        LoadObjectField<Float64T>(heap_object, offsetof(HeapNumber, value_));
    var_result = TruncateFloat64ToFloat32(value);
    Goto(&done);
  }

  BIND(&if_smi);
  {
    TNode<Int32T> value = SmiToInt32(CAST(var_input.value()));
    var_result = RoundInt32ToFloat32(value);
    Goto(&done);
  }

  BIND(&convert);
  {
    var_input = CallBuiltin(Builtin::kNonNumberToNumber, context, input);
    Goto(&loop);
  }

  BIND(&done);
  return var_result.value();
}

template <>
TNode<Float64T> CodeStubAssembler::PrepareValueForWriteToTypedArray<Float64T>(
    TNode<Object> input, ElementsKind elements_kind, TNode<Context> context) {
  DCHECK(IsTypedArrayElementsKind(elements_kind));
  CHECK_EQ(elements_kind, FLOAT64_ELEMENTS);

  TVARIABLE(Float64T, var_result);
  TVARIABLE(Object, var_input, input);
  Label done(this, &var_result), if_smi(this), if_heapnumber_or_oddball(this),
      convert(this), loop(this, &var_input);
  Goto(&loop);
  BIND(&loop);
  GotoIf(TaggedIsSmi(var_input.value()), &if_smi);
  // We can handle both HeapNumber and Oddball here, since Oddball has the
  // same layout as the HeapNumber for the HeapNumber::value field. This
  // way we can also properly optimize stores of oddballs to typed arrays.
  TNode<HeapObject> heap_object = CAST(var_input.value());
  GotoIf(IsHeapNumber(heap_object), &if_heapnumber_or_oddball);
  STATIC_ASSERT_FIELD_OFFSETS_EQUAL(offsetof(HeapNumber, value_),
                                    offsetof(Oddball, to_number_raw_));
  Branch(HasInstanceType(heap_object, ODDBALL_TYPE), &if_heapnumber_or_oddball,
         &convert);

  BIND(&if_heapnumber_or_oddball);
  {
    var_result =
        LoadObjectField<Float64T>(heap_object, offsetof(HeapNumber, value_));
    Goto(&done);
  }

  BIND(&if_smi);
  {
    TNode<Int32T> value = SmiToInt32(CAST(var_input.value()));
    var_result = ChangeInt32ToFloat64(value);
    Goto(&done);
  }

  BIND(&convert);
  {
    var_input = CallBuiltin(Builtin::kNonNumberToNumber, context, input);
    Goto(&loop);
  }

  BIND(&done);
  return var_result.value();
}

template <>
TNode<BigInt> CodeStubAssembler::PrepareValueForWriteToTypedArray<BigInt>(
    TNode<Object> input, ElementsKind elements_kind, TNode<Context> context) {
  DCHECK(elements_kind == BIGINT64_ELEMENTS ||
         elements_kind == BIGUINT64_ELEMENTS);
  return ToBigInt(context, input);
}

#if V8_ENABLE_WEBASSEMBLY
TorqueStructInt64AsInt32Pair CodeStubAssembler::BigIntToRawBytes(
    TNode<BigInt> value) {
  TVARIABLE(UintPtrT, var_low);
  // Only used on 32-bit platforms.
  TVARIABLE(UintPtrT, var_high);
  BigIntToRawBytes(value, &var_low, &var_high);
  return {var_low.value(), var_high.value()};
}
#endif  // V8_ENABLE_WEBASSEMBLY

void CodeStubAssembler::BigIntToRawBytes(TNode<BigInt> bigint,
                                         TVariable<UintPtrT>* var_low,
                                         TVariable<UintPtrT>* var_high) {
  Label done(this);
  *var_low = Unsigned(IntPtrConstant(0));
  *var_high = Unsigned(IntPtrConstant(0));
  TNode<Word32T> bitfield = LoadBigIntBitfield(bigint);
  TNode<Uint32T> length = DecodeWord32<BigIntBase::LengthBits>(bitfield);
  TNode<Uint32T> sign = DecodeWord32<BigIntBase::SignBits>(bitfield);
  GotoIf(Word32Equal(length, Int32Constant(0)), &done);
  *var_low = LoadBigIntDigit(bigint, 0);
  if (!Is64()) {
    Label load_done(this);
    GotoIf(Word32Equal(length, Int32Constant(1)), &load_done);
    *var_high = LoadBigIntDigit(bigint, 1);
    Goto(&load_done);
    BIND(&load_done);
  }
  GotoIf(Word32Equal(sign, Int32Constant(0)), &done);
  // Negative value. Simulate two's complement.
  if (!Is64()) {
    *var_high = Unsigned(IntPtrSub(IntPtrConstant(0), var_high->value()));
    Label no_carry(this);
    GotoIf(IntPtrEqual(var_low->value(), IntPtrConstant(0)), &no_carry);
    *var_high = Unsigned(IntPtrSub(var_high->value(), IntPtrConstant(1)));
    Goto(&no_carry);
    BIND(&no_carry);
  }
  *var_low = Unsigned(IntPtrSub(IntPtrConstant(0), var_low->value()));
  Goto(&done);
  BIND(&done);
}

template <>
void CodeStubAssembler::EmitElementStoreTypedArrayUpdateValue(
    TNode<Object> value, ElementsKind elements_kind,
    TNode<Word32T> converted_value, TVariable<Object>* maybe_converted_value) {
  switch (elements_kind) {
    case UINT8_ELEMENTS:
    case INT8_ELEMENTS:
    case UINT16_ELEMENTS:
    case INT16_ELEMENTS:
    case UINT8_CLAMPED_ELEMENTS:
      *maybe_converted_value =
          SmiFromInt32(UncheckedCast<Int32T>(converted_value));
      break;
    case UINT32_ELEMENTS:
      *maybe_converted_value =
          ChangeUint32ToTagged(UncheckedCast<Uint32T>(converted_value));
      break;
    case INT32_ELEMENTS:
      *maybe_converted_value =
          ChangeInt32ToTagged(UncheckedCast<Int32T>(converted_value));
      break;
    default:
      UNREACHABLE();
  }
}

template <>
void CodeStubAssembler::EmitElementStoreTypedArrayUpdateValue(
    TNode<Object> value, ElementsKind elements_kind,
    TNode<Float16RawBitsT> converted_value,
    TVariable<Object>* maybe_converted_value) {
  Label dont_allocate_heap_number(this), end(this);
  GotoIf(TaggedIsSmi(value), &dont_allocate_heap_number);
  GotoIf(IsHeapNumber(CAST(value)), &dont_allocate_heap_number);
  {
    *maybe_converted_value =
        AllocateHeapNumberWithValue(ChangeFloat16ToFloat64(converted_value));
    Goto(&end);
  }
  BIND(&dont_allocate_heap_number);
  {
    *maybe_converted_value = value;
    Goto(&end);
  }
  BIND(&end);
}

template <>
void CodeStubAssembler::EmitElementStoreTypedArrayUpdateValue(
    TNode<Object> value, ElementsKind elements_kind,
    TNode<Float32T> converted_value, TVariable<Object>* maybe_converted_value) {
  Label dont_allocate_heap_number(this), end(this);
  GotoIf(TaggedIsSmi(value), &dont_allocate_heap_number);
  GotoIf(IsHeapNumber(CAST(value)), &dont_allocate_heap_number);
  {
    *maybe_converted_value =
        AllocateHeapNumberWithValue(ChangeFloat32ToFloat64(converted_value));
    Goto(&end);
  }
  BIND(&dont_allocate_heap_number);
  {
    *maybe_converted_value = value;
    Goto(&end);
  }
  BIND(&end);
}

template <>
void CodeStubAssembler::EmitElementStoreTypedArrayUpdateValue(
    TNode<Object> value, ElementsKind elements_kind,
    TNode<Float64T> converted_value, TVariable<Object>* maybe_converted_value) {
  Label dont_allocate_heap_number(this), end(this);
  GotoIf(TaggedIsSmi(value), &dont_allocate_heap_number);
  GotoIf(IsHeapNumber(CAST(value)), &dont_allocate_heap_number);
  {
    *maybe_converted_value = AllocateHeapNumberWithValue(converted_value);
    Goto(&end);
  }
  BIND(&dont_allocate_heap_number);
  {
    *maybe_converted_value = value;
    Goto(&end);
  }
  BIND(&end);
}

template <>
void CodeStubAssembler::EmitElementStoreTypedArrayUpdateValue(
    TNode<Object> value, ElementsKind elements_kind,
    TNode<BigInt> converted_value, TVariable<Object>* maybe_converted_value) {
  *maybe_converted_value = converted_value;
}

template <typename TValue>
void CodeStubAssembler::EmitElementStoreTypedArray(
    TNode<JSTypedArray> typed_array, TNode<IntPtrT> key, TNode<Object> value,
    ElementsKind elements_kind, KeyedAccessStoreMode store_mode, Label* bailout,
    TNode<Context> context, TVariable<Object>* maybe_converted_value) {
  Label done(this), update_value_and_bailout(this, Label::kDeferred);

  bool is_rab_gsab = false;
  if (IsRabGsabTypedArrayElementsKind(elements_kind)) {
    is_rab_gsab = true;
    // For the rest of the function, use the corresponding non-RAB/GSAB
    // ElementsKind.
    elements_kind = GetCorrespondingNonRabGsabElementsKind(elements_kind);
  }

  TNode<TValue> converted_value =
      PrepareValueForWriteToTypedArray<TValue>(value, elements_kind, context);

  // There must be no allocations between the buffer load and
  // and the actual store to backing store, because GC may decide that
  // the buffer is not alive or move the elements.
  // TODO(ishell): introduce DisallowGarbageCollectionCode scope here.

  // Check if buffer has been detached. (For RAB / GSAB this is part of loading
  // the length, so no additional check is needed.)
  TNode<JSArrayBuffer> buffer = LoadJSArrayBufferViewBuffer(typed_array);
  if (!is_rab_gsab) {
    GotoIf(IsDetachedBuffer(buffer), &update_value_and_bailout);
  }

  // Bounds check.
  TNode<UintPtrT> length;
  if (is_rab_gsab) {
    length = LoadVariableLengthJSTypedArrayLength(
        typed_array, buffer,
        StoreModeIgnoresTypeArrayOOB(store_mode) ? &done
                                                 : &update_value_and_bailout);
  } else {
    length = LoadJSTypedArrayLength(typed_array);
  }

  if (StoreModeIgnoresTypeArrayOOB(store_mode)) {
    // Skip the store if we write beyond the length or
    // to a property with a negative integer index.
    GotoIfNot(UintPtrLessThan(key, length), &done);
  } else {
    DCHECK(StoreModeIsInBounds(store_mode));
    GotoIfNot(UintPtrLessThan(key, length), &update_value_and_bailout);
  }

  TNode<RawPtrT> data_ptr = LoadJSTypedArrayDataPtr(typed_array);
  StoreElement(data_ptr, elements_kind, key, converted_value);
  Goto(&done);

  if (!is_rab_gsab || !StoreModeIgnoresTypeArrayOOB(store_mode)) {
    BIND(&update_value_and_bailout);
    // We already prepared the incoming value for storing into a typed array.
    // This might involve calling ToNumber in some cases. We shouldn't call
    // ToNumber again in the runtime so pass the converted value to the runtime.
    // The prepared value is an untagged value. Convert it to a tagged value
    // to pass it to runtime. It is not possible to do the detached buffer check
    // before we prepare the value, since ToNumber can detach the ArrayBuffer.
    // The spec specifies the order of these operations.
    if (maybe_converted_value != nullptr) {
      EmitElementStoreTypedArrayUpdateValue(
          value, elements_kind, converted_value, maybe_converted_value);
    }
    Goto(bailout);
  }

  BIND(&done);
}

void CodeStubAssembler::EmitElementStore(
    TNode<JSObject> object, TNode<Object> key, TNode<Object> value,
    ElementsKind elements_kind, KeyedAccessStoreMode store_mode, Label* bailout,
    TNode<Context> context, TVariable<Object>* maybe_converted_value) {
  CSA_DCHECK(this, Word32BinaryNot(IsJSProxy(object)));

  TNode<FixedArrayBase> elements = LoadElements(object);
  if (!(IsSmiOrObjectElementsKind(elements_kind) ||
        IsSealedElementsKind(elements_kind) ||
        IsNonextensibleElementsKind(elements_kind))) {
    CSA_DCHECK(this, Word32BinaryNot(IsFixedCOWArrayMap(LoadMap(elements))));
  } else if (!StoreModeHandlesCOW(store_mode)) {
    GotoIf(IsFixedCOWArrayMap(LoadMap(elements)), bailout);
  }

  // TODO(ishell): introduce TryToIntPtrOrSmi() and use BInt.
  TNode<IntPtrT> intptr_key = TryToIntptr(key, bailout);

  // TODO(rmcilroy): TNodify the converted value once this funciton and
  // StoreElement are templated based on the type elements_kind type.
  if (IsTypedArrayOrRabGsabTypedArrayElementsKind(elements_kind)) {
    TNode<JSTypedArray> typed_array = CAST(object);
    switch (elements_kind) {
      case UINT8_ELEMENTS:
      case INT8_ELEMENTS:
      case UINT16_ELEMENTS:
      case INT16_ELEMENTS:
      case UINT32_ELEMENTS:
      case INT32_ELEMENTS:
      case UINT8_CLAMPED_ELEMENTS:
      case RAB_GSAB_UINT8_ELEMENTS:
      case RAB_GSAB_INT8_ELEMENTS:
      case RAB_GSAB_UINT16_ELEMENTS:
      case RAB_GSAB_INT16_ELEMENTS:
      case RAB_GSAB_UINT32_ELEMENTS:
      case RAB_GSAB_INT32_ELEMENTS:
      case RAB_GSAB_UINT8_CLAMPED_ELEMENTS:
        EmitElementStoreTypedArray<Word32T>(typed_array, intptr_key, value,
                                            elements_kind, store_mode, bailout,
                                            context, maybe_converted_value);
        break;
      case FLOAT32_ELEMENTS:
      case RAB_GSAB_FLOAT32_ELEMENTS:
        EmitElementStoreTypedArray<Float32T>(typed_array, intptr_key, value,
                                             elements_kind, store_mode, bailout,
                                             context, maybe_converted_value);
        break;
      case FLOAT64_ELEMENTS:
      case RAB_GSAB_FLOAT64_ELEMENTS:
        EmitElementStoreTypedArray<Float64T>(typed_array, intptr_key, value,
                                             elements_kind, store_mode, bailout,
                                             context, maybe_converted_value);
        break;
      case BIGINT64_ELEMENTS:
      case BIGUINT64_ELEMENTS:
      case RAB_GSAB_BIGINT64_ELEMENTS:
      case RAB_GSAB_BIGUINT64_ELEMENTS:
        EmitElementStoreTypedArray<BigInt>(typed_array, intptr_key, value,
                                           elements_kind, store_mode, bailout,
                                           context, maybe_converted_value);
        break;
      case FLOAT16_ELEMENTS:
      case RAB_GSAB_FLOAT16_ELEMENTS:
        EmitElementStoreTypedArray<Float16RawBitsT>(
            typed_array, intptr_key, value, elements_kind, store_mode, bailout,
            context, maybe_converted_value);
        break;
      default:
        UNREACHABLE();
    }
    return;
  }
  DCHECK(IsFastElementsKind(elements_kind) ||
         IsSealedElementsKind(elements_kind) ||
         IsNonextensibleElementsKind(elements_kind));

  // In case value is stored into a fast smi array, assure that the value is
  // a smi before manipulating the backing store. Otherwise the backing store
  // may be left in an invalid state.
  std::optional<TNode<Float64T>> float_value;
  if (IsSmiElementsKind(elements_kind)) {
    GotoIfNot(TaggedIsSmi(value), bailout);
  } else if (IsDoubleElementsKind(elements_kind)) {
    float_value = TryTaggedToFloat64(value, bailout);
  }

  TNode<Smi> smi_length = Select<Smi>(
      IsJSArray(object),
      [=, this]() {
        // This is casting Number -> Smi which may not actually be safe.
        return CAST(LoadJSArrayLength(CAST(object)));
      },
      [=, this]() { return LoadFixedArrayBaseLength(elements); });

  TNode<UintPtrT> length = Unsigned(PositiveSmiUntag(smi_length));
  if (StoreModeCanGrow(store_mode) &&
      !(IsSealedElementsKind(elements_kind) ||
        IsNonextensibleElementsKind(elements_kind))) {
    elements = CheckForCapacityGrow(object, elements, elements_kind, length,
                                    intptr_key, bailout);
  } else {
    GotoIfNot(UintPtrLessThan(Unsigned(intptr_key), length), bailout);
  }

  // Cannot store to a hole in holey sealed elements so bailout.
  if (elements_kind == HOLEY_SEALED_ELEMENTS ||
      elements_kind == HOLEY_NONEXTENSIBLE_ELEMENTS) {
    TNode<Object> target_value =
        LoadFixedArrayElement(CAST(elements), intptr_key);
    GotoIf(IsTheHole(target_value), bailout);
  }

  // If we didn't grow {elements}, it might still be COW, in which case we
  // copy it now.
  if (!(IsSmiOrObjectElementsKind(elements_kind) ||
        IsSealedElementsKind(elements_kind) ||
        IsNonextensibleElementsKind(elements_kind))) {
    CSA_DCHECK(this, Word32BinaryNot(IsFixedCOWArrayMap(LoadMap(elements))));
  } else if (StoreModeHandlesCOW(store_mode)) {
    elements = CopyElementsOnWrite(object, elements, elements_kind,
                                   Signed(length), bailout);
  }

  CSA_DCHECK(this, Word32BinaryNot(IsFixedCOWArrayMap(LoadMap(elements))));
  if (float_value) {
    StoreElement(elements, elements_kind, intptr_key, float_value.value());
  } else {
    if (elements_kind == SHARED_ARRAY_ELEMENTS) {
      TVARIABLE(Object, shared_value, value);
      SharedValueBarrier(context, &shared_value);
      StoreElement(elements, elements_kind, intptr_key, shared_value.value());
    } else {
      StoreElement(elements, elements_kind, intptr_key, value);
    }
  }
}

TNode<FixedArrayBase> CodeStubAssembler::CheckForCapacityGrow(
    TNode<JSObject> object, TNode<FixedArrayBase> elements, ElementsKind kind,
    TNode<UintPtrT> length, TNode<IntPtrT> key, Label* bailout) {
  DCHECK(IsFastElementsKind(kind));
  TVARIABLE(FixedArrayBase, checked_elements);
  Label grow_case(this), no_grow_case(this), done(this),
      grow_bailout(this, Label::kDeferred);

  TNode<BoolT> condition;
  if (IsHoleyElementsKind(kind)) {
    condition = UintPtrGreaterThanOrEqual(key, length);
  } else {
    // We don't support growing here unless the value is being appended.
    condition = WordEqual(key, length);
  }
  Branch(condition, &grow_case, &no_grow_case);

  BIND(&grow_case);
  {
    TNode<IntPtrT> current_capacity =
        LoadAndUntagFixedArrayBaseLength(elements);
    checked_elements = elements;
    Label fits_capacity(this);
    // If key is negative, we will notice in Runtime::kGrowArrayElements.
    GotoIf(UintPtrLessThan(key, current_capacity), &fits_capacity);

    {
      TNode<FixedArrayBase> new_elements = TryGrowElementsCapacity(
          object, elements, kind, key, current_capacity, &grow_bailout);
      checked_elements = new_elements;
      Goto(&fits_capacity);
    }

    BIND(&grow_bailout);
    {
      GotoIf(IntPtrLessThan(key, IntPtrConstant(0)), bailout);
      TNode<Number> tagged_key = ChangeUintPtrToTagged(Unsigned(key));
      TNode<Object> maybe_elements = CallRuntime(
          Runtime::kGrowArrayElements, NoContextConstant(), object, tagged_key);
      GotoIf(TaggedIsSmi(maybe_elements), bailout);
      TNode<FixedArrayBase> new_elements = CAST(maybe_elements);
      CSA_DCHECK(this, IsFixedArrayWithKind(new_elements, kind));
      checked_elements = new_elements;
      Goto(&fits_capacity);
    }

    BIND(&fits_capacity);
    GotoIfNot(IsJSArray(object), &done);

    TNode<IntPtrT> new_length = IntPtrAdd(key, IntPtrConstant(1));
    StoreObjectFieldNoWriteBarrier(object, JSArray::kLengthOffset,
                                   SmiTag(new_length));
    Goto(&done);
  }

  BIND(&no_grow_case);
  {
    GotoIfNot(UintPtrLessThan(key, length), bailout);
    checked_elements = elements;
    Goto(&done);
  }

  BIND(&done);
  return checked_elements.value();
}

TNode<FixedArrayBase> CodeStubAssembler::CopyElementsOnWrite(
    TNode<HeapObject> object, TNode<FixedArrayBase> elements, ElementsKind kind,
    TNode<IntPtrT> length, Label* bailout) {
  TVARIABLE(FixedArrayBase, new_elements_var, elements);
  Label done(this);

  GotoIfNot(IsFixedCOWArrayMap(LoadMap(elements)), &done);
  {
    TNode<IntPtrT> capacity = LoadAndUntagFixedArrayBaseLength(elements);
    TNode<FixedArrayBase> new_elements = GrowElementsCapacity(
        object, elements, kind, kind, length, capacity, bailout);
    new_elements_var = new_elements;
    Goto(&done);
  }

  BIND(&done);
  return new_elements_var.value();
}

void CodeStubAssembler::TransitionElementsKind(TNode<JSObject> object,
                                               TNode<Map> map,
                                               ElementsKind from_kind,
                    
"""


```