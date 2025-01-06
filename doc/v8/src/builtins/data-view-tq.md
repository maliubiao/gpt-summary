Response: Let's break down the thought process for analyzing this Torque file.

1. **Understand the Goal:** The request asks for a summary of the file's functionality, its relationship to JavaScript, examples, logic reasoning with inputs/outputs, and common programming errors. This means I need to go beyond just describing what the code does; I need to connect it to a developer's perspective.

2. **Identify the Core Subject:** The filename `data-view.tq` and the namespace `data_view` immediately point to the JavaScript `DataView` object. This is the central concept.

3. **High-Level Structure Scan:**  Quickly skim through the file, noticing key elements:
    * `#include`: Indicates interaction with C++ code (important context).
    * `constexpr string` constants:  These define the names of the built-in methods, linking this code to JavaScript.
    * `macro MakeDataViewGetterNameString` and `MakeDataViewSetterNameString`: These generate the method names dynamically based on `ElementsKind`. This is a pattern to watch for.
    * `macro WasDetached`, `ValidateDataView`: These look like helper functions for checking the state and type of the `DataView`.
    * `javascript builtin` functions: These are the actual implementations of the `DataView` methods in Torque, meant to be called from JavaScript. Notice the names correspond to `DataView.prototype` methods.
    * `macro LoadDataView...` and `macro StoreDataView...`: These macros handle the low-level byte manipulation for different data types and endianness. This is a crucial part of `DataView`'s functionality.
    * `transitioning macro DataViewGet` and `transitioning macro DataViewSet`: These are the core logic for reading and writing data, orchestrating the `LoadDataView...` and `StoreDataView...` macros.
    * The final blocks of `transitioning javascript builtin` functions for each data type: These map the JavaScript method calls to the central `DataViewGet` and `DataViewSet` macros.

4. **Map to JavaScript Concepts:** As I identify these elements, I constantly relate them back to my knowledge of the `DataView` API in JavaScript. For example:
    * The `get DataView.prototype.byteLength` constant directly corresponds to the `byteLength` property.
    * The `DataViewPrototypeGetBuffer` builtin implements the `buffer` getter.
    * The `LoadDataView...` macros are the underlying mechanisms for `getInt8`, `getUint16`, etc.
    * The `requestedLittleEndian` parameter in many functions is clearly related to the optional endianness argument in the JavaScript `DataView` methods.

5. **Focus on Key Logic (Get and Set):** The `DataViewGet` and `DataViewSet` macros are where the core logic resides. Analyze their steps:
    * **Validation:**  Check the receiver is a `DataView`, not detached.
    * **Index Conversion:** `ToIndex` ensures the offset is a valid number.
    * **Endianness:** `ToBoolean` converts the endianness argument.
    * **Bounds Checking:**  Crucially, they check if the access is within the `DataView`'s bounds.
    * **Offset Calculation:**  `bufferIndex = getIndex + viewOffset`.
    * **Delegation to Load/Store Macros:** They call the appropriate `LoadDataView...` or `StoreDataView...` macro based on the `ElementsKind`.

6. **Infer Logic Reasoning (Input/Output):** Based on the `DataViewGet` and `DataViewSet` logic, I can create hypothetical scenarios:
    * **Get Example:** A `DataView` on a buffer, requesting a `Uint16` at a specific offset with little-endianness. The output will be the corresponding 16-bit unsigned integer read from the buffer.
    * **Set Example:**  Similar to the get example, but writing a value. The output is `undefined`, but the side effect is the modification of the underlying buffer.

7. **Identify Common Errors:**  Thinking about how developers use `DataView`, common mistakes come to mind:
    * **Out-of-bounds access:** Trying to read or write beyond the `DataView`'s limits.
    * **Detached buffer:**  Operating on a `DataView` whose underlying `ArrayBuffer` has been detached.
    * **Incorrect endianness:**  Not understanding or specifying the correct endianness, leading to incorrect data interpretation.
    * **Type mismatch:**  Trying to set a value that doesn't fit the specified data type (though JavaScript is generally forgiving, the underlying representation still matters).

8. **Structure the Summary:**  Organize the findings into logical sections as requested:
    * **Functionality:** Describe the overall purpose.
    * **Relationship to JavaScript:** Provide concrete JavaScript examples.
    * **Logic Reasoning:**  Illustrate the `DataViewGet` and `DataViewSet` process with specific inputs and expected outputs.
    * **Common Errors:**  List and explain typical mistakes developers might make.

9. **Refine and Elaborate:** Review the generated summary for clarity and accuracy. Add more detail where necessary, ensuring the explanations are easy to understand for someone familiar with JavaScript but perhaps not with V8 internals or Torque. For instance, emphasize the role of `ElementsKind` or explain the endianness concept clearly.

By following this structured approach, I can systematically analyze the V8 Torque code and generate a comprehensive and informative summary that addresses all aspects of the request. The key is to connect the low-level code to the high-level JavaScript concepts and developer experience.
这个v8 torque文件 `v8/src/builtins/data-view.tq`  定义了 `DataView` 相关的内置函数（builtins）。 Torque 是一种 V8 用来生成高效的 C++ 代码的领域特定语言。 这个文件主要负责实现 `DataView.prototype` 上的一些方法，允许 JavaScript 代码以底层的、类型化的方式访问 `ArrayBuffer` 中的数据。

**功能归纳:**

这个文件的核心功能是为 JavaScript 的 `DataView` 对象提供底层的读写操作能力。 它定义了以下操作：

1. **属性访问器 (Getters):**
   - `get DataView.prototype.buffer`: 获取 `DataView` 关联的 `ArrayBuffer` 对象。
   - `get DataView.prototype.byteLength`: 获取 `DataView` 覆盖的字节长度。
   - `get DataView.prototype.byteOffset`: 获取 `DataView` 相对于 `ArrayBuffer` 的起始偏移量。
   - `DataView.prototype.getUint8`, `getInt8`, `getUint16`, `getInt16`, `getUint32`, `getInt32`, `getFloat32`, `getFloat64`, `getBigInt64`, `getBigUint64`, `getFloat16` (如果支持):  从 `ArrayBuffer` 的指定偏移量读取不同类型的数值。可以指定字节序（大小端）。

2. **属性设置器 (Setters):**
   - `DataView.prototype.setUint8`, `setInt8`, `setUint16`, `setInt16`, `setUint32`, `setInt32`, `setFloat32`, `setFloat64`, `setBigInt64`, `setBigUint64`, `setFloat16` (如果支持): 将不同类型的数值写入 `ArrayBuffer` 的指定偏移量。可以指定字节序（大小端）。

3. **内部辅助函数 (Macros):**
   - `MakeDataViewGetterNameString`, `MakeDataViewSetterNameString`: 根据元素类型生成内置函数的名称字符串。
   - `WasDetached`: 检查 `DataView` 关联的 `ArrayBuffer` 是否已被分离（detached）。
   - `ValidateDataView`: 验证接收者是否为 `DataView` 或 `RabGsabDataView` 对象，如果不是则抛出 `TypeError`。
   - `LoadDataView8`, `LoadDataView16`, `LoadDataView32`, `LoadDataViewFloat16`, `LoadDataViewFloat64`, `LoadDataViewBigInt`:  实现从 `ArrayBuffer` 读取不同类型数据的底层逻辑，包括处理字节序。
   - `StoreDataView8`, `StoreDataView16`, `StoreDataView32`, `StoreDataView64`, `StoreDataViewBigInt`: 实现向 `ArrayBuffer` 写入不同类型数据的底层逻辑，包括处理字节序。
   - `MakeBigIntOn64Bit`, `MakeBigIntOn32Bit`, `MakeBigInt`:  辅助创建 `BigInt` 对象的宏。
   - `DataViewGet`, `DataViewSet`:  封装了获取和设置值的通用逻辑，包括参数校验、边界检查和调用相应的加载/存储宏。

**与 Javascript 功能的关系及示例:**

这个 Torque 代码直接实现了 JavaScript 中 `DataView` 对象的原型方法。  `DataView` 提供了一个与底层二进制数据交互的接口，允许你以指定的格式（例如，有符号/无符号整数，浮点数，大小端）读取和写入 `ArrayBuffer` 中的数据。

```javascript
// 创建一个 ArrayBuffer
const buffer = new ArrayBuffer(16);
// 创建一个 DataView，覆盖整个 buffer
const dataView = new DataView(buffer);

// 使用 setter 设置值 (大端序是默认的)
dataView.setInt32(0, 0x12345678); // 在偏移量 0 写入一个 32 位整数
dataView.setUint16(4, 0xABCD, true); // 在偏移量 4 写入一个 16 位无符号整数，使用小端序

// 使用 getter 读取值
const intValue = dataView.getInt32(0); // 读取偏移量 0 的 32 位整数 (大端序)
const uintValue = dataView.getUint16(4, true); // 读取偏移量 4 的 16 位无符号整数 (小端序)

console.log(intValue);   // 输出 305419896 (0x12345678)
console.log(uintValue);  // 输出 0xABCD (17517)
console.log(dataView.getByteLength()); // 输出 16
console.log(dataView.getByteOffset()); // 输出 0
console.log(dataView.buffer === buffer); // 输出 true
```

**代码逻辑推理 (假设输入与输出):**

假设有以下 JavaScript 代码：

```javascript
const buffer = new ArrayBuffer(4);
const dataView = new DataView(buffer, 1, 2); // offset 1, length 2

// 调用 DataViewPrototypeGetUint16 (对应 Torque 中的 DataViewGet)
const value = dataView.getUint16(0, true); // offset 0 相对于 dataView 的起始位置，小端序
```

**Torque 代码中的 `DataViewGet` 宏的执行过程 (简化版):**

1. **输入假设:**
   - `receiver`:  `dataView` 对象
   - `requestIndex`: 0 (JavaScript 传递的偏移量)
   - `requestedLittleEndian`:  `true`
   - `kind`: `ElementsKind::UINT16_ELEMENTS`

2. **验证 `dataView`:** `ValidateDataView` 检查 `receiver` 是否是 `DataView` 对象。

3. **转换索引:** `ToIndex(requestIndex)` 将 `0` 转换为一个无符号整数 `0`.

4. **获取字节序:** `ToBoolean(requestedLittleEndian)` 返回 `true`。

5. **获取 `ArrayBuffer`:** `dataView.buffer` 获取到 `buffer` 对象。

6. **检查 Detached 状态:** 检查 `buffer` 是否已分离。

7. **获取 `viewOffset` 和 `viewSize`:**
   - `viewOffset`: `dataView.byte_offset` 为 1。
   - `viewSize`: `dataView.byte_length` 为 2。

8. **获取元素大小:** `DataViewElementSize(kind)` 对于 `UINT16_ELEMENTS` 返回 2。

9. **边界检查:** `CheckIntegerIndexAdditionOverflow(0, 2, 2)` 检查 `0 + 2 <= 2`，结果为 true，没有超出边界。

10. **计算 `bufferIndex`:** `bufferIndex = 0 + 1 = 1`。 这是相对于底层 `ArrayBuffer` 的偏移量。

11. **调用 `LoadDataView16`:**  根据 `kind` 调用 `LoadDataView16(buffer, 1, true, false)` (最后一个 `false` 表示无符号)。

12. **`LoadDataView16` 的执行 (假设 `buffer` 在偏移量 1 和 2 的字节分别是 `0xCD` 和 `0xAB`):**
   - `requestedLittleEndian` 为 `true`，所以按照小端序读取。
   - `b0 = LoadUint8(dataPointer, 1)` 读取到 `0xCD`。
   - `b1 = LoadInt8(dataPointer, 2)` 读取到 `0xAB`。
   - `result = (0xAB << 8) + 0xCD = 0xABCD`。
   - 返回 `Convert<Smi>(0xABCD)`。

13. **最终输出:** JavaScript 代码中的 `value` 变量将被赋值为 `43981` (0xABCD 的十进制表示)。

**用户常见的编程错误:**

1. **越界访问:** 尝试读取或写入超出 `DataView` 边界的数据。

   ```javascript
   const buffer = new ArrayBuffer(4);
   const dataView = new DataView(buffer, 0, 2); // byteLength 为 2
   dataView.getInt32(0); // 错误！尝试读取 4 个字节，但 DataView 只有 2 个字节
   // 抛出 RangeError: Offset is outside the bounds of the DataView
   ```

2. **在已分离的 `ArrayBuffer` 上操作:**  如果 `DataView` 关联的 `ArrayBuffer` 已经被分离，尝试读取或写入会抛出 `TypeError`。

   ```javascript
   const buffer = new ArrayBuffer(4);
   const dataView = new DataView(buffer);
   buffer.detached; // 在某些上下文中可以访问，用于检查
   // ... 分离 buffer 的操作 (例如，SharedArrayBuffer.prototype.transfer) ...
   dataView.getInt32(0); // 错误！ArrayBuffer 已分离
   // 抛出 TypeError: Cannot perform %DataViewGet% on a detached ArrayBuffer
   ```

3. **字节序混淆:** 在需要考虑字节序的情况下，使用了错误的字节序参数。

   ```javascript
   const buffer = new ArrayBuffer(2);
   const dataView = new DataView(buffer);
   dataView.setUint16(0, 0x1234); // 默认大端序写入

   const valueLittleEndian = dataView.getUint16(0, true); // 尝试小端序读取
   console.log(valueLittleEndian); // 输出 0x3412，而不是 0x1234

   const valueBigEndian = dataView.getUint16(0, false); // 使用正确的字节序读取
   console.log(valueBigEndian);  // 输出 0x1234
   ```

4. **错误的偏移量计算:** 当 `DataView` 不是从 `ArrayBuffer` 的起始位置开始时，容易混淆相对于 `DataView` 和相对于 `ArrayBuffer` 的偏移量。

   ```javascript
   const buffer = new ArrayBuffer(4);
   const dataView = new DataView(buffer, 1, 2); // offset 1, length 2

   dataView.getInt8(0); // 读取的是 buffer 的索引 1 的字节
   dataView.getInt8(1); // 读取的是 buffer 的索引 2 的字节
   dataView.getInt8(2); // 错误！超出 DataView 的边界
   // 抛出 RangeError: Offset is outside the bounds of the DataView
   ```

了解这些常见的错误可以帮助开发者更有效地使用 `DataView`，避免潜在的运行时问题。  这个 Torque 文件正是 V8 引擎中实现这些行为的关键部分。

Prompt: 
```
这是目录为v8/src/builtins/data-view.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include 'src/builtins/builtins-data-view-gen.h'

namespace data_view {

const kBuiltinNameByteLength: constexpr string =
    'get DataView.prototype.byteLength';
const kBuiltinNameByteOffset: constexpr string =
    'get DataView.prototype.byteOffset';

macro MakeDataViewGetterNameString(kind: constexpr ElementsKind): String {
  if constexpr (kind == ElementsKind::UINT8_ELEMENTS) {
    return 'DataView.prototype.getUint8';
  } else if constexpr (kind == ElementsKind::INT8_ELEMENTS) {
    return 'DataView.prototype.getInt8';
  } else if constexpr (kind == ElementsKind::UINT16_ELEMENTS) {
    return 'DataView.prototype.getUint16';
  } else if constexpr (kind == ElementsKind::INT16_ELEMENTS) {
    return 'DataView.prototype.getInt16';
  } else if constexpr (kind == ElementsKind::UINT32_ELEMENTS) {
    return 'DataView.prototype.getUint32';
  } else if constexpr (kind == ElementsKind::INT32_ELEMENTS) {
    return 'DataView.prototype.getInt32';
  } else if constexpr (kind == ElementsKind::FLOAT16_ELEMENTS) {
    return 'DataView.prototype.getFloat16';
  } else if constexpr (kind == ElementsKind::FLOAT32_ELEMENTS) {
    return 'DataView.prototype.getFloat32';
  } else if constexpr (kind == ElementsKind::FLOAT64_ELEMENTS) {
    return 'DataView.prototype.getFloat64';
  } else if constexpr (kind == ElementsKind::BIGINT64_ELEMENTS) {
    return 'DataView.prototype.getBigInt64';
  } else if constexpr (kind == ElementsKind::BIGUINT64_ELEMENTS) {
    return 'DataView.prototype.getBigUint64';
  } else {
    unreachable;
  }
}

macro MakeDataViewSetterNameString(kind: constexpr ElementsKind): String {
  if constexpr (kind == ElementsKind::UINT8_ELEMENTS) {
    return 'DataView.prototype.setUint8';
  } else if constexpr (kind == ElementsKind::INT8_ELEMENTS) {
    return 'DataView.prototype.setInt8';
  } else if constexpr (kind == ElementsKind::UINT16_ELEMENTS) {
    return 'DataView.prototype.setUint16';
  } else if constexpr (kind == ElementsKind::INT16_ELEMENTS) {
    return 'DataView.prototype.setInt16';
  } else if constexpr (kind == ElementsKind::UINT32_ELEMENTS) {
    return 'DataView.prototype.setUint32';
  } else if constexpr (kind == ElementsKind::INT32_ELEMENTS) {
    return 'DataView.prototype.setInt32';
  } else if constexpr (kind == ElementsKind::FLOAT16_ELEMENTS) {
    return 'DataView.prototype.setFloat16';
  } else if constexpr (kind == ElementsKind::FLOAT32_ELEMENTS) {
    return 'DataView.prototype.setFloat32';
  } else if constexpr (kind == ElementsKind::FLOAT64_ELEMENTS) {
    return 'DataView.prototype.setFloat64';
  } else if constexpr (kind == ElementsKind::BIGINT64_ELEMENTS) {
    return 'DataView.prototype.setBigInt64';
  } else if constexpr (kind == ElementsKind::BIGUINT64_ELEMENTS) {
    return 'DataView.prototype.setBigUint64';
  } else {
    unreachable;
  }
}

macro WasDetached(view: JSArrayBufferView): bool {
  return IsDetachedBuffer(view.buffer);
}

macro ValidateDataView(context: Context, o: JSAny, method: String):
    JSDataViewOrRabGsabDataView {
  typeswitch (o) {
    case (_x: JSDataView): {
      return UnsafeCast<JSDataView>(o);
    }
    case (_x: JSRabGsabDataView): {
      return UnsafeCast<JSRabGsabDataView>(o);
    }
    case (_x: JSAny): {
      ThrowTypeError(MessageTemplate::kIncompatibleMethodReceiver, method, o);
    }
  }
}

// ES6 section 24.2.4.1 get DataView.prototype.buffer
javascript builtin DataViewPrototypeGetBuffer(
    js-implicit context: NativeContext, receiver: JSAny)(
    ...arguments): JSArrayBuffer {
  const dataView: JSDataViewOrRabGsabDataView =
      ValidateDataView(context, receiver, 'get DataView.prototype.buffer');
  return dataView.buffer;
}

// ES6 section 24.2.4.2 get DataView.prototype.byteLength
javascript builtin DataViewPrototypeGetByteLength(
    js-implicit context: NativeContext, receiver: JSAny)(
    ...arguments): Number {
  const dataView: JSDataViewOrRabGsabDataView =
      ValidateDataView(context, receiver, 'get DataView.prototype.byteLength');
  if (IsVariableLengthJSArrayBufferView(dataView)) {
    try {
      const byteLength = LoadVariableLengthJSArrayBufferViewByteLength(
          dataView, dataView.buffer) otherwise DetachedOrOutOfBounds;
      return Convert<Number>(byteLength);
    } label DetachedOrOutOfBounds {
      ThrowTypeError(
          MessageTemplate::kDetachedOperation, kBuiltinNameByteLength);
    }
  } else {
    if (WasDetached(dataView)) {
      ThrowTypeError(
          MessageTemplate::kDetachedOperation, kBuiltinNameByteLength);
    }
    return Convert<Number>(dataView.byte_length);
  }
}

// ES6 section 24.2.4.3 get DataView.prototype.byteOffset
javascript builtin DataViewPrototypeGetByteOffset(
    js-implicit context: NativeContext, receiver: JSAny)(
    ...arguments): Number {
  const dataView: JSDataViewOrRabGsabDataView =
      ValidateDataView(context, receiver, 'get DataView.prototype.byteOffset');
  try {
    typed_array::IsJSArrayBufferViewDetachedOrOutOfBounds(dataView)
        otherwise DetachedOrOutOfBounds, NotDetachedNorOutOfBounds;
  } label DetachedOrOutOfBounds {
    ThrowTypeError(MessageTemplate::kDetachedOperation, kBuiltinNameByteOffset);
  } label NotDetachedNorOutOfBounds {
    return Convert<Number>(dataView.byte_offset);
  }
}

extern macro BitcastInt32ToFloat32(uint32): float32;
extern macro BitcastFloat32ToInt32(float32): uint32;
extern macro Float64ExtractLowWord32(float64): uint32;
extern macro Float64ExtractHighWord32(float64): uint32;
extern macro Float64InsertLowWord32(float64, uint32): float64;
extern macro Float64InsertHighWord32(float64, uint32): float64;

extern macro DataViewBuiltinsAssembler::LoadUint8(RawPtr, uintptr): uint32;
extern macro DataViewBuiltinsAssembler::LoadInt8(RawPtr, uintptr): int32;

macro LoadDataView8(
    buffer: JSArrayBuffer, offset: uintptr, signed: constexpr bool): Smi {
  if constexpr (signed) {
    return Convert<Smi>(LoadInt8(buffer.backing_store_ptr, offset));
  } else {
    return Convert<Smi>(LoadUint8(buffer.backing_store_ptr, offset));
  }
}

macro LoadDataView16(
    buffer: JSArrayBuffer, offset: uintptr, requestedLittleEndian: bool,
    signed: constexpr bool): Number {
  const dataPointer: RawPtr = buffer.backing_store_ptr;

  let b0: int32;
  let b1: int32;
  let result: int32;

  // Sign-extend the most significant byte by loading it as an Int8.
  if (requestedLittleEndian) {
    b0 = Signed(LoadUint8(dataPointer, offset));
    b1 = LoadInt8(dataPointer, offset + 1);
    result = (b1 << 8) + b0;
  } else {
    b0 = LoadInt8(dataPointer, offset);
    b1 = Signed(LoadUint8(dataPointer, offset + 1));
    result = (b0 << 8) + b1;
  }
  if constexpr (signed) {
    return Convert<Smi>(result);
  } else {
    // Bit-mask the higher bits to prevent sign extension if we're unsigned.
    return Convert<Smi>(result & 0xFFFF);
  }
}

macro LoadDataView32(
    buffer: JSArrayBuffer, offset: uintptr, requestedLittleEndian: bool,
    kind: constexpr ElementsKind): Number {
  const dataPointer: RawPtr = buffer.backing_store_ptr;

  const b0: uint32 = LoadUint8(dataPointer, offset);
  const b1: uint32 = LoadUint8(dataPointer, offset + 1);
  const b2: uint32 = LoadUint8(dataPointer, offset + 2);
  const b3: uint32 = LoadUint8(dataPointer, offset + 3);
  let result: uint32;

  if (requestedLittleEndian) {
    result = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
  } else {
    result = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
  }

  if constexpr (kind == ElementsKind::INT32_ELEMENTS) {
    return Convert<Number>(Signed(result));
  } else if constexpr (kind == ElementsKind::UINT32_ELEMENTS) {
    return Convert<Number>(result);
  } else if constexpr (kind == ElementsKind::FLOAT32_ELEMENTS) {
    const floatRes: float64 = Convert<float64>(BitcastInt32ToFloat32(result));
    return Convert<Number>(floatRes);
  } else {
    unreachable;
  }
}
macro LoadDataViewFloat16(
    buffer: JSArrayBuffer, offset: uintptr,
    requestedLittleEndian: bool): Number {
  const dataPointer: RawPtr = buffer.backing_store_ptr;
  const b0: uint32 = LoadUint8(dataPointer, offset);
  const b1: uint32 = LoadUint8(dataPointer, offset + 1);
  let result: uint32;

  if (requestedLittleEndian) {
    result = (b1 << 8) | b0;
  } else {
    result = (b0 << 8) | b1;
  }

  const floatRes: float64 = Convert<float64>(BitcastUint32ToFloat16(result));
  return Convert<Number>(floatRes);
}

macro LoadDataViewFloat64(
    buffer: JSArrayBuffer, offset: uintptr,
    requestedLittleEndian: bool): Number {
  const dataPointer: RawPtr = buffer.backing_store_ptr;

  const b0: uint32 = LoadUint8(dataPointer, offset);
  const b1: uint32 = LoadUint8(dataPointer, offset + 1);
  const b2: uint32 = LoadUint8(dataPointer, offset + 2);
  const b3: uint32 = LoadUint8(dataPointer, offset + 3);
  const b4: uint32 = LoadUint8(dataPointer, offset + 4);
  const b5: uint32 = LoadUint8(dataPointer, offset + 5);
  const b6: uint32 = LoadUint8(dataPointer, offset + 6);
  const b7: uint32 = LoadUint8(dataPointer, offset + 7);
  let lowWord: uint32;
  let highWord: uint32;

  if (requestedLittleEndian) {
    lowWord = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
    highWord = (b7 << 24) | (b6 << 16) | (b5 << 8) | b4;
  } else {
    highWord = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    lowWord = (b4 << 24) | (b5 << 16) | (b6 << 8) | b7;
  }

  let result: float64 = 0;
  result = Float64InsertLowWord32(result, lowWord);
  result = Float64InsertHighWord32(result, highWord);

  return Convert<Number>(result);
}

const kZeroDigitBigInt: constexpr int31 = 0;
const kOneDigitBigInt: constexpr int31 = 1;
const kTwoDigitBigInt: constexpr int31 = 2;

// Create a BigInt on a 64-bit architecture from two 32-bit values.
macro MakeBigIntOn64Bit(
    implicit context: Context)(lowWord: uint32, highWord: uint32,
    signed: constexpr bool): BigInt {
  // 0n is represented by a zero-length BigInt.
  if (lowWord == 0 && highWord == 0) {
    return Convert<BigInt>(bigint::AllocateBigInt(kZeroDigitBigInt));
  }

  let sign: uint32 = bigint::kPositiveSign;
  const highPart: intptr = Signed(Convert<uintptr>(highWord));
  const lowPart: intptr = Signed(Convert<uintptr>(lowWord));
  let rawValue: intptr = (highPart << 32) + lowPart;

  if constexpr (signed) {
    if (rawValue < 0) {
      sign = bigint::kNegativeSign;
      // We have to store the absolute value of rawValue in the digit.
      rawValue = 0 - rawValue;
    }
  }

  // Allocate the BigInt and store the absolute value.
  const result: MutableBigInt =
      bigint::AllocateEmptyBigInt(sign, kOneDigitBigInt);
  bigint::StoreBigIntDigit(result, 0, Unsigned(rawValue));
  return Convert<BigInt>(result);
}

// Create a BigInt on a 32-bit architecture from two 32-bit values.
macro MakeBigIntOn32Bit(
    implicit context: Context)(lowWord: uint32, highWord: uint32,
    signed: constexpr bool): BigInt {
  // 0n is represented by a zero-length BigInt.
  if (lowWord == 0 && highWord == 0) {
    return Convert<BigInt>(bigint::AllocateBigInt(kZeroDigitBigInt));
  }

  // On a 32-bit platform, we might need 1 or 2 digits to store the number.
  let needTwoDigits: bool = false;
  let sign: uint32 = bigint::kPositiveSign;

  // We need to do some math on lowWord and highWord,
  // so Convert them to int32.
  let lowPart: int32 = Signed(lowWord);
  let highPart: int32 = Signed(highWord);

  // If highWord == 0, the number is positive, and we only need 1 digit,
  // so we don't have anything to do.
  // Otherwise, all cases are possible.
  if (highWord != 0) {
    if constexpr (signed) {
      // If highPart < 0, the number is always negative.
      if (highPart < 0) {
        sign = bigint::kNegativeSign;

        // We have to compute the absolute value by hand.
        // There will be a negative carry from the low word
        // to the high word iff low != 0.
        highPart = 0 - highPart;
        if (lowPart != 0) {
          highPart = highPart - 1;
        }
        lowPart = 0 - lowPart;

        // Here, highPart could be 0 again so we might have 1 or 2 digits.
        if (highPart != 0) {
          needTwoDigits = true;
        }

      } else {
        // In this case, the number is positive, and we need 2 digits.
        needTwoDigits = true;
      }

    } else {
      // In this case, the number is positive (unsigned),
      // and we need 2 digits.
      needTwoDigits = true;
    }
  }

  // Allocate the BigInt with the right sign and length.
  let result: MutableBigInt;
  if (needTwoDigits) {
    result = bigint::AllocateEmptyBigInt(sign, kTwoDigitBigInt);
  } else {
    result = bigint::AllocateEmptyBigInt(sign, kOneDigitBigInt);
  }

  // Finally, write the digit(s) to the BigInt.
  bigint::StoreBigIntDigit(result, 0, Unsigned(Convert<intptr>(lowPart)));
  if (needTwoDigits) {
    bigint::StoreBigIntDigit(result, 1, Unsigned(Convert<intptr>(highPart)));
  }
  return Convert<BigInt>(result);
}

macro MakeBigInt(
    implicit context: Context)(lowWord: uint32, highWord: uint32,
    signed: constexpr bool): BigInt {
  // A BigInt digit has the platform word size, so we only need one digit
  // on 64-bit platforms but may need two on 32-bit.
  if constexpr (Is64()) {
    return MakeBigIntOn64Bit(lowWord, highWord, signed);
  } else {
    return MakeBigIntOn32Bit(lowWord, highWord, signed);
  }
}

macro LoadDataViewBigInt(
    implicit context: Context)(buffer: JSArrayBuffer, offset: uintptr,
    requestedLittleEndian: bool, signed: constexpr bool): BigInt {
  const dataPointer: RawPtr = buffer.backing_store_ptr;

  const b0: uint32 = LoadUint8(dataPointer, offset);
  const b1: uint32 = LoadUint8(dataPointer, offset + 1);
  const b2: uint32 = LoadUint8(dataPointer, offset + 2);
  const b3: uint32 = LoadUint8(dataPointer, offset + 3);
  const b4: uint32 = LoadUint8(dataPointer, offset + 4);
  const b5: uint32 = LoadUint8(dataPointer, offset + 5);
  const b6: uint32 = LoadUint8(dataPointer, offset + 6);
  const b7: uint32 = LoadUint8(dataPointer, offset + 7);
  let lowWord: uint32;
  let highWord: uint32;

  if (requestedLittleEndian) {
    lowWord = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
    highWord = (b7 << 24) | (b6 << 16) | (b5 << 8) | b4;
  } else {
    highWord = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    lowWord = (b4 << 24) | (b5 << 16) | (b6 << 8) | b7;
  }

  return MakeBigInt(lowWord, highWord, signed);
}

extern macro DataViewBuiltinsAssembler::DataViewElementSize(
    constexpr ElementsKind): constexpr int31;

// GetViewValue ( view, requestIndex, isLittleEndian, type )
// https://tc39.es/ecma262/#sec-getviewvalue
transitioning macro DataViewGet(
    context: Context, receiver: JSAny, requestIndex: JSAny,
    requestedLittleEndian: JSAny, kind: constexpr ElementsKind): Numeric {
  // 1. Perform ? RequireInternalSlot(view, [[DataView]]).
  // 2. Assert: view has a [[ViewedArrayBuffer]] internal slot.
  const dataView: JSDataViewOrRabGsabDataView =
      ValidateDataView(context, receiver, MakeDataViewGetterNameString(kind));

  try {
    // 3. Let getIndex be ? ToIndex(requestIndex).
    const getIndex: uintptr = ToIndex(requestIndex) otherwise RangeError;

    // 4. Set isLittleEndian to ! ToBoolean(isLittleEndian).
    const littleEndian: bool = ToBoolean(requestedLittleEndian);

    // 5. Let buffer be view.[[ViewedArrayBuffer]].
    const buffer: JSArrayBuffer = dataView.buffer;

    // 6. Let getBufferByteLength be
    // MakeIdempotentArrayBufferByteLengthGetter(Unordered).
    // 7. If IsViewOutOfBounds(view, getBufferByteLength) is true, throw a
    // TypeError exception.
    try {
      typed_array::IsJSArrayBufferViewDetachedOrOutOfBounds(dataView)
          otherwise DetachedOrOutOfBounds, NotDetachedNorOutOfBounds;
    } label DetachedOrOutOfBounds {
      ThrowTypeError(
          MessageTemplate::kDetachedOperation,
          MakeDataViewGetterNameString(kind));
    } label NotDetachedNorOutOfBounds {}

    // 8. Let viewOffset be view.[[ByteOffset]].
    const viewOffset: uintptr = dataView.byte_offset;

    // 9. Let viewSize be GetViewByteLength(view, getBufferByteLength).
    let viewSize: uintptr;
    if (dataView.bit_field.is_length_tracking) {
      viewSize = LoadVariableLengthJSArrayBufferViewByteLength(
          dataView, dataView.buffer) otherwise unreachable;
    } else {
      viewSize = dataView.byte_length;
    }

    // 10. Let elementSize be the Element Size value specified in Table 62
    // for Element Type type.
    const elementSize: uintptr = DataViewElementSize(kind);

    // 11. If getIndex + elementSize > viewSize, throw a RangeError exception.
    CheckIntegerIndexAdditionOverflow(getIndex, elementSize, viewSize)
        otherwise RangeError;

    // 12. Let bufferIndex be getIndex + viewOffset.
    const bufferIndex: uintptr = getIndex + viewOffset;

    if constexpr (kind == ElementsKind::UINT8_ELEMENTS) {
      return LoadDataView8(buffer, bufferIndex, false);
    } else if constexpr (kind == ElementsKind::INT8_ELEMENTS) {
      return LoadDataView8(buffer, bufferIndex, true);
    } else if constexpr (kind == ElementsKind::UINT16_ELEMENTS) {
      return LoadDataView16(buffer, bufferIndex, littleEndian, false);
    } else if constexpr (kind == ElementsKind::INT16_ELEMENTS) {
      return LoadDataView16(buffer, bufferIndex, littleEndian, true);
    } else if constexpr (kind == ElementsKind::UINT32_ELEMENTS) {
      return LoadDataView32(buffer, bufferIndex, littleEndian, kind);
    } else if constexpr (kind == ElementsKind::INT32_ELEMENTS) {
      return LoadDataView32(buffer, bufferIndex, littleEndian, kind);
    } else if constexpr (kind == ElementsKind::FLOAT16_ELEMENTS) {
      return LoadDataViewFloat16(buffer, bufferIndex, littleEndian);
    } else if constexpr (kind == ElementsKind::FLOAT32_ELEMENTS) {
      return LoadDataView32(buffer, bufferIndex, littleEndian, kind);
    } else if constexpr (kind == ElementsKind::FLOAT64_ELEMENTS) {
      return LoadDataViewFloat64(buffer, bufferIndex, littleEndian);
    } else if constexpr (kind == ElementsKind::BIGUINT64_ELEMENTS) {
      return LoadDataViewBigInt(buffer, bufferIndex, littleEndian, false);
    } else if constexpr (kind == ElementsKind::BIGINT64_ELEMENTS) {
      return LoadDataViewBigInt(buffer, bufferIndex, littleEndian, true);
    } else {
      unreachable;
    }
  } label RangeError {
    ThrowRangeError(MessageTemplate::kInvalidDataViewAccessorOffset);
  }
}

transitioning javascript builtin DataViewPrototypeGetUint8(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  return DataViewGet(
      context, receiver, offset, Undefined, ElementsKind::UINT8_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeGetInt8(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  return DataViewGet(
      context, receiver, offset, Undefined, ElementsKind::INT8_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeGetUint16(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const isLittleEndian: JSAny = arguments[1];
  return DataViewGet(
      context, receiver, offset, isLittleEndian, ElementsKind::UINT16_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeGetInt16(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const isLittleEndian: JSAny = arguments[1];
  return DataViewGet(
      context, receiver, offset, isLittleEndian, ElementsKind::INT16_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeGetUint32(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const isLittleEndian: JSAny = arguments[1];
  return DataViewGet(
      context, receiver, offset, isLittleEndian, ElementsKind::UINT32_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeGetInt32(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const isLittleEndian: JSAny = arguments[1];
  return DataViewGet(
      context, receiver, offset, isLittleEndian, ElementsKind::INT32_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeGetFloat16(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const isLittleEndian: JSAny = arguments[1];
  return DataViewGet(
      context, receiver, offset, isLittleEndian,
      ElementsKind::FLOAT16_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeGetFloat32(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const isLittleEndian: JSAny = arguments[1];
  return DataViewGet(
      context, receiver, offset, isLittleEndian,
      ElementsKind::FLOAT32_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeGetFloat64(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const isLittleEndian: JSAny = arguments[1];
  return DataViewGet(
      context, receiver, offset, isLittleEndian,
      ElementsKind::FLOAT64_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeGetBigUint64(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const isLittleEndian: JSAny = arguments[1];
  return DataViewGet(
      context, receiver, offset, isLittleEndian,
      ElementsKind::BIGUINT64_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeGetBigInt64(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const isLittleEndian: JSAny = arguments[1];
  return DataViewGet(
      context, receiver, offset, isLittleEndian,
      ElementsKind::BIGINT64_ELEMENTS);
}

extern macro ToNumber(Context, JSAny): Number;
extern macro TruncateFloat64ToWord32(float64): uint32;

extern macro DataViewBuiltinsAssembler::StoreWord8(RawPtr, uintptr, uint32):
    void;

macro StoreDataView8(buffer: JSArrayBuffer, offset: uintptr, value: uint32):
    void {
  StoreWord8(buffer.backing_store_ptr, offset, value & 0xFF);
}

macro StoreDataView16(
    buffer: JSArrayBuffer, offset: uintptr, value: uint32,
    requestedLittleEndian: bool): void {
  const dataPointer: RawPtr = buffer.backing_store_ptr;

  const b0: uint32 = value & 0xFF;
  const b1: uint32 = (value >>> 8) & 0xFF;

  if (requestedLittleEndian) {
    StoreWord8(dataPointer, offset, b0);
    StoreWord8(dataPointer, offset + 1, b1);
  } else {
    StoreWord8(dataPointer, offset, b1);
    StoreWord8(dataPointer, offset + 1, b0);
  }
}

macro StoreDataView32(
    buffer: JSArrayBuffer, offset: uintptr, value: uint32,
    requestedLittleEndian: bool): void {
  const dataPointer: RawPtr = buffer.backing_store_ptr;

  const b0: uint32 = value & 0xFF;
  const b1: uint32 = (value >>> 8) & 0xFF;
  const b2: uint32 = (value >>> 16) & 0xFF;
  const b3: uint32 = value >>> 24;  // We don't need to mask here.

  if (requestedLittleEndian) {
    StoreWord8(dataPointer, offset, b0);
    StoreWord8(dataPointer, offset + 1, b1);
    StoreWord8(dataPointer, offset + 2, b2);
    StoreWord8(dataPointer, offset + 3, b3);
  } else {
    StoreWord8(dataPointer, offset, b3);
    StoreWord8(dataPointer, offset + 1, b2);
    StoreWord8(dataPointer, offset + 2, b1);
    StoreWord8(dataPointer, offset + 3, b0);
  }
}

macro StoreDataView64(
    buffer: JSArrayBuffer, offset: uintptr, lowWord: uint32, highWord: uint32,
    requestedLittleEndian: bool): void {
  const dataPointer: RawPtr = buffer.backing_store_ptr;

  const b0: uint32 = lowWord & 0xFF;
  const b1: uint32 = (lowWord >>> 8) & 0xFF;
  const b2: uint32 = (lowWord >>> 16) & 0xFF;
  const b3: uint32 = lowWord >>> 24;

  const b4: uint32 = highWord & 0xFF;
  const b5: uint32 = (highWord >>> 8) & 0xFF;
  const b6: uint32 = (highWord >>> 16) & 0xFF;
  const b7: uint32 = highWord >>> 24;

  if (requestedLittleEndian) {
    StoreWord8(dataPointer, offset, b0);
    StoreWord8(dataPointer, offset + 1, b1);
    StoreWord8(dataPointer, offset + 2, b2);
    StoreWord8(dataPointer, offset + 3, b3);
    StoreWord8(dataPointer, offset + 4, b4);
    StoreWord8(dataPointer, offset + 5, b5);
    StoreWord8(dataPointer, offset + 6, b6);
    StoreWord8(dataPointer, offset + 7, b7);
  } else {
    StoreWord8(dataPointer, offset, b7);
    StoreWord8(dataPointer, offset + 1, b6);
    StoreWord8(dataPointer, offset + 2, b5);
    StoreWord8(dataPointer, offset + 3, b4);
    StoreWord8(dataPointer, offset + 4, b3);
    StoreWord8(dataPointer, offset + 5, b2);
    StoreWord8(dataPointer, offset + 6, b1);
    StoreWord8(dataPointer, offset + 7, b0);
  }
}

extern macro DataViewBuiltinsAssembler::DataViewDecodeBigIntLength(BigIntBase):
    uint32;
extern macro DataViewBuiltinsAssembler::DataViewDecodeBigIntSign(BigIntBase):
    uint32;

// We might get here a BigInt that is bigger than 64 bits, but we're only
// interested in the 64 lowest ones. This means the lowest BigInt digit
// on 64-bit platforms, and the 2 lowest BigInt digits on 32-bit ones.
macro StoreDataViewBigInt(
    buffer: JSArrayBuffer, offset: uintptr, bigIntValue: BigInt,
    requestedLittleEndian: bool): void {
  const length: uint32 = DataViewDecodeBigIntLength(bigIntValue);
  const sign: uint32 = DataViewDecodeBigIntSign(bigIntValue);

  // The 32-bit words that will hold the BigInt's value in
  // two's complement representation.
  let lowWord: uint32 = 0;
  let highWord: uint32 = 0;

  // The length is nonzero if and only if the BigInt's value is nonzero.
  if (length != 0) {
    if constexpr (Is64()) {
      // There is always exactly 1 BigInt digit to load in this case.
      const value: uintptr = bigint::LoadBigIntDigit(bigIntValue, 0);
      lowWord = Convert<uint32>(value);  // Truncates value to 32 bits.
      highWord = Convert<uint32>(value >>> 32);
    } else {  // There might be either 1 or 2 BigInt digits we need to load.
      lowWord = Convert<uint32>(bigint::LoadBigIntDigit(bigIntValue, 0));
      if (length >= 2) {  // Only load the second digit if there is one.
        highWord = Convert<uint32>(bigint::LoadBigIntDigit(bigIntValue, 1));
      }
    }
  }

  if (sign != 0) {  // The number is negative, Convert it.
    highWord = Unsigned(0 - Signed(highWord));
    if (lowWord != 0) {
      highWord = Unsigned(Signed(highWord) - 1);
    }
    lowWord = Unsigned(0 - Signed(lowWord));
  }

  StoreDataView64(buffer, offset, lowWord, highWord, requestedLittleEndian);
}

// SetViewValue ( view, requestIndex, isLittleEndian, type, value )
// https://tc39.es/ecma262/#sec-setviewvalue
transitioning macro DataViewSet(
    context: Context, receiver: JSAny, requestIndex: JSAny, value: JSAny,
    requestedLittleEndian: JSAny, kind: constexpr ElementsKind): JSAny {
  // 1. Perform ? RequireInternalSlot(view, [[DataView]]).
  // 2. Assert: view has a [[ViewedArrayBuffer]] internal slot.
  const dataView: JSDataViewOrRabGsabDataView =
      ValidateDataView(context, receiver, MakeDataViewSetterNameString(kind));

  try {
    // 3. Let getIndex be ? ToIndex(requestIndex).
    const getIndex: uintptr = ToIndex(requestIndex) otherwise RangeError;

    let numberValue: Numeric;
    if constexpr (
        kind == ElementsKind::BIGUINT64_ELEMENTS ||
        kind == ElementsKind::BIGINT64_ELEMENTS) {
      // 4. If ! IsBigIntElementType(type) is true, let numberValue be
      // ? ToBigInt(value).
      numberValue = ToBigInt(context, value);
    } else {
      // 5. Otherwise, let numberValue be ? ToNumber(value).
      numberValue = ToNumber(context, value);
    }

    // 6. Set isLittleEndian to !ToBoolean(isLittleEndian).
    const littleEndian: bool = ToBoolean(requestedLittleEndian);

    // 7. Let buffer be view.[[ViewedArrayBuffer]].
    const buffer: JSArrayBuffer = dataView.buffer;

    // 6. If IsDetachedBuffer(buffer) is true, throw a TypeError exception.
    if (IsDetachedBuffer(buffer)) {
      ThrowTypeError(
          MessageTemplate::kDetachedOperation,
          MakeDataViewSetterNameString(kind));
    }
    // 8. Let getBufferByteLength be
    // MakeIdempotentArrayBufferByteLengthGetter(Unordered).
    // 9. NOTE: Bounds checking is not a synchronizing operation when view's
    // backing buffer is a growable SharedArrayBuffer.
    // 10. If IsViewOutOfBounds(view, getBufferByteLength) is true, throw a
    // TypeError exception.
    try {
      typed_array::IsJSArrayBufferViewDetachedOrOutOfBounds(dataView)
          otherwise DetachedOrOutOfBounds, NotDetachedNorOutOfBounds;
    } label DetachedOrOutOfBounds {
      ThrowTypeError(
          MessageTemplate::kDetachedOperation,
          MakeDataViewGetterNameString(kind));
    } label NotDetachedNorOutOfBounds {}

    // 11. Let viewOffset be view.[[ByteOffset]].
    const viewOffset: uintptr = dataView.byte_offset;

    // 12. Let viewSize be GetViewByteLength(view, getBufferByteLength).
    let viewSize: uintptr;
    if (dataView.bit_field.is_length_tracking) {
      viewSize = LoadVariableLengthJSArrayBufferViewByteLength(
          dataView, dataView.buffer) otherwise unreachable;
    } else {
      viewSize = dataView.byte_length;
    }

    // 13. Let elementSize be the Element Size value specified in Table 62
    // for Element Type type.
    const elementSize: uintptr = DataViewElementSize(kind);

    // 14. If getIndex + elementSize > viewSize, throw a RangeError exception.
    CheckIntegerIndexAdditionOverflow(getIndex, elementSize, viewSize)
        otherwise RangeError;

    // 15. Let bufferIndex be getIndex + viewOffset.
    const bufferIndex: uintptr = getIndex + viewOffset;

    if constexpr (
        kind == ElementsKind::BIGUINT64_ELEMENTS ||
        kind == ElementsKind::BIGINT64_ELEMENTS) {
      // For these elements kinds numberValue is BigInt.
      const bigIntValue: BigInt = %RawDownCast<BigInt>(numberValue);
      StoreDataViewBigInt(buffer, bufferIndex, bigIntValue, littleEndian);
    } else {
      // For these elements kinds numberValue is Number.
      const numValue: Number = %RawDownCast<Number>(numberValue);
      const doubleValue: float64 = ChangeNumberToFloat64(numValue);

      if constexpr (
          kind == ElementsKind::UINT8_ELEMENTS ||
          kind == ElementsKind::INT8_ELEMENTS) {
        StoreDataView8(
            buffer, bufferIndex, TruncateFloat64ToWord32(doubleValue));
      } else if constexpr (
          kind == ElementsKind::UINT16_ELEMENTS ||
          kind == ElementsKind::INT16_ELEMENTS) {
        StoreDataView16(
            buffer, bufferIndex, TruncateFloat64ToWord32(doubleValue),
            littleEndian);
      } else if constexpr (kind == ElementsKind::FLOAT16_ELEMENTS) {
        const floatValue: float16_raw_bits =
            TruncateFloat64ToFloat16(doubleValue);
        StoreDataView16(
            buffer, bufferIndex, BitcastFloat16ToUint32(floatValue),
            littleEndian);
      } else if constexpr (
          kind == ElementsKind::UINT32_ELEMENTS ||
          kind == ElementsKind::INT32_ELEMENTS) {
        StoreDataView32(
            buffer, bufferIndex, TruncateFloat64ToWord32(doubleValue),
            littleEndian);
      } else if constexpr (kind == ElementsKind::FLOAT32_ELEMENTS) {
        const floatValue: float32 = TruncateFloat64ToFloat32(doubleValue);
        StoreDataView32(
            buffer, bufferIndex, BitcastFloat32ToInt32(floatValue),
            littleEndian);
      } else if constexpr (kind == ElementsKind::FLOAT64_ELEMENTS) {
        const lowWord: uint32 = Float64ExtractLowWord32(doubleValue);
        const highWord: uint32 = Float64ExtractHighWord32(doubleValue);
        StoreDataView64(buffer, bufferIndex, lowWord, highWord, littleEndian);
      }
    }
    return Undefined;
  } label RangeError {
    ThrowRangeError(MessageTemplate::kInvalidDataViewAccessorOffset);
  }
}

transitioning javascript builtin DataViewPrototypeSetUint8(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const value: JSAny = arguments[1];
  return DataViewSet(
      context, receiver, offset, value, Undefined,
      ElementsKind::UINT8_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeSetInt8(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const value: JSAny = arguments[1];
  return DataViewSet(
      context, receiver, offset, value, Undefined, ElementsKind::INT8_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeSetUint16(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const value: JSAny = arguments[1];
  const isLittleEndian: JSAny = arguments[2];
  return DataViewSet(
      context, receiver, offset, value, isLittleEndian,
      ElementsKind::UINT16_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeSetInt16(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const value: JSAny = arguments[1];
  const isLittleEndian: JSAny = arguments[2];
  return DataViewSet(
      context, receiver, offset, value, isLittleEndian,
      ElementsKind::INT16_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeSetUint32(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const value: JSAny = arguments[1];
  const isLittleEndian: JSAny = arguments[2];
  return DataViewSet(
      context, receiver, offset, value, isLittleEndian,
      ElementsKind::UINT32_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeSetInt32(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const value: JSAny = arguments[1];
  const isLittleEndian: JSAny = arguments[2];
  return DataViewSet(
      context, receiver, offset, value, isLittleEndian,
      ElementsKind::INT32_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeSetFloat16(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const value: JSAny = arguments[1];
  const isLittleEndian: JSAny = arguments[2];
  return DataViewSet(
      context, receiver, offset, value, isLittleEndian,
      ElementsKind::FLOAT16_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeSetFloat32(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const value: JSAny = arguments[1];
  const isLittleEndian: JSAny = arguments[2];
  return DataViewSet(
      context, receiver, offset, value, isLittleEndian,
      ElementsKind::FLOAT32_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeSetFloat64(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const value: JSAny = arguments[1];
  const isLittleEndian: JSAny = arguments[2];
  return DataViewSet(
      context, receiver, offset, value, isLittleEndian,
      ElementsKind::FLOAT64_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeSetBigUint64(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const value: JSAny = arguments[1];
  const isLittleEndian: JSAny = arguments[2];
  return DataViewSet(
      context, receiver, offset, value, isLittleEndian,
      ElementsKind::BIGUINT64_ELEMENTS);
}

transitioning javascript builtin DataViewPrototypeSetBigInt64(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  const offset: JSAny = arguments[0];
  const value: JSAny = arguments[1];
  const isLittleEndian: JSAny = arguments[2];
  return DataViewSet(
      context, receiver, offset, value, isLittleEndian,
      ElementsKind::BIGINT64_ELEMENTS);
}
}

"""

```