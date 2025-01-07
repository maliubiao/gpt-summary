Response:
My thinking process to analyze the provided C++ code snippet goes like this:

1. **Initial Scan for Context:**  I first look for obvious clues about the file's purpose. The path `v8/src/wasm/turboshaft-graph-interface.cc` immediately tells me it's part of V8's WebAssembly (Wasm) implementation and relates to a "turboshaft graph interface." The `.cc` extension confirms it's C++.

2. **Identify Key Classes/Structures:** I look for defined classes or structures within the snippet. Here, `TurboshaftGraphInterface` is the most prominent. This is likely the core component this code defines.

3. **Analyze Member Functions:** I go through each member function of the `TurboshaftGraphInterface` class, trying to understand its individual purpose. I look for:
    * **Descriptive names:** Functions like `MemoryGrow`, `IsExternRefString`, `ExternRefToString`, `GetStringIndexOf`, `ThrowDataViewTypeError`, `DataViewRangeCheck`, `GetDataViewByteLength`, `DataViewGetter`, `DataViewSetter`, `WellKnown_FastApi`, and `HandleWellKnownImport` are quite informative.
    * **Parameter types and return types:** These provide hints about what data the functions operate on and what they produce. For example, functions dealing with `Value` objects and returning `V<...>` suggest they are working with the Turboshaft graph representation. The `FullDecoder* decoder` parameter is common and suggests interaction with the Wasm decoding process.
    * **Internal logic:**  Keywords like `IF`, `GOTO`, `BIND`, and calls to functions starting with `__` (likely assembly or lower-level V8 primitives) reveal the control flow and underlying operations. Calls to `CallBuiltinThroughJumptable` are significant, indicating interaction with built-in JavaScript functions or runtime functionalities.
    * **Specific patterns:**  The repeated patterns involving `DataViewOp` and functions like `ThrowDataViewTypeError`, `DataViewRangeCheck`, and `GetDataViewByteLength` suggest a focus on handling `DataView` objects in Wasm. The section involving `WellKnown_FastApi` and `HandleWellKnownImport` clearly deals with interfacing with specific imported functions or APIs.

4. **Group Related Functionalities:**  As I analyze the functions, I start to group them based on their apparent purpose:
    * **Memory Management:** `MemoryGrow`
    * **String Handling:** `IsExternRefString`, `ExternRefToString`, `IsExplicitStringCast`, `GetStringIndexOf`, `CallStringToLowercase`, the `WKI::kString*` cases in `HandleWellKnownImport`, `DoubleToString`, `IntToString`, `ParseFloat`.
    * **DataView Operations:** `SetDataViewOpForErrorMessage`, `ThrowDataViewTypeError`, `ThrowDataViewOutOfBoundsError`, `ThrowDataViewDetachedError`, `DataViewRangeCheck`, `DataViewBoundsCheck`, `DataViewDetachedBufferCheck`, `GetDataViewByteLength`, `GetDataViewDataPtr`, `DataViewGetter`, `DataViewSetter`.
    * **Fast API Calls:** `WellKnown_FastApi`, `HandleWellKnownImport` (specifically the `WKI::kGeneric` case and the general structure).
    * **Type Checking/Casting:** Functions involving `WasmTypeCheck` and `WasmTypeCast`, as well as `AnnotateAsString`.

5. **Look for Connections to JavaScript:**  The calls to `CallBuiltinThroughJumptable` are the primary links to JavaScript. I note which built-ins are being called (e.g., `WasmMemoryGrow`, `StringIndexOf`, `StringToLowerCaseIntl`, various `ThrowDataView...` built-ins, `StringCompare`, `StringAdd_CheckNone`, `WasmStringFromCodePoint`, `WasmStringNewWtf16Array`, `WasmStringToUtf8Array`, `WasmFloat64ToString`, `WasmIntToString`, `WasmStringToDouble`, `ThrowIndexOfCalledOnNull`). These built-ins perform common JavaScript operations, indicating how the Wasm code interacts with the JavaScript environment.

6. **Consider `.tq` and Torque:** The instruction to check for `.tq` reminds me that V8 uses Torque, a TypeScript-like language for defining built-in functions. While this file is `.cc`, it interacts with Torque-defined built-ins.

7. **Infer Overall Purpose:** Based on the individual functionalities and their groupings, I can infer the overall purpose of the file:  It provides an interface between the Turboshaft compiler (V8's newer Wasm compiler) and various runtime functionalities needed to execute Wasm code. This includes memory management, string manipulation, handling `DataView` objects, and calling into JavaScript built-ins, especially for well-known imported functions.

8. **Address Specific Instructions (JavaScript examples, logic, errors):**
    * **JavaScript Examples:**  I think about how the C++ functions would correspond to JavaScript code. For instance, `MemoryGrow` relates to `WebAssembly.Memory.prototype.grow()`, string functions map to JavaScript string methods, and `DataView` functions correspond to operations on JavaScript `DataView` objects.
    * **Logic and Assumptions:** For functions with conditional logic (`IF`, `GOTO_IF`), I identify the conditions and the different execution paths. I might make assumptions about the input values to trace the logic (as demonstrated in the "Hypothetical Input and Output" section of the example answer).
    * **Common Errors:**  I consider common errors related to the functionalities, such as out-of-bounds access with `DataView`, calling string methods on null, and type mismatches.

9. **Summarize Functionality:** Finally, I condense the analyzed information into a concise summary of the file's purpose, highlighting its key responsibilities within the Wasm compilation and execution pipeline. I focus on the core areas like graph construction, interaction with built-ins, and handling specific Wasm features.

By following these steps, I can systematically dissect the C++ code snippet and understand its role within the larger V8 project. The key is to break down the code into smaller, manageable parts and then piece together the overall picture.
好的，我们来分析一下 `v8/src/wasm/turboshaft-graph-interface.cc` 这部分代码的功能。

**功能归纳:**

这段代码是 V8 的 Turboshaft 编译器中用于构建和操作计算图的一个接口。它提供了一系列方法，允许 Turboshaft 编译器在生成 WebAssembly 代码的过程中，方便地创建表示各种操作的节点，并与 V8 的其他组件（如内置函数、运行时环境）进行交互。

**具体功能列表:**

1. **内存操作:**
   - `MemoryGrow`:  处理 WebAssembly 的 `memory.grow` 指令，调用内置函数进行内存扩展。

2. **字符串操作:**
   - `IsExternRefString`:  检查一个值是否是外部字符串引用。
   - `ExternRefToString`: 将一个值转换为外部字符串。
   - `IsExplicitStringCast`:  检查一个值是否显式地转换为外部字符串。
   - `GetStringIndexOf`:  实现字符串的 `indexOf` 功能，调用内置函数。
   - `CallStringToLowercase`:  调用内置函数将字符串转换为小写（支持国际化）。
   - 处理各种 Well-Known Imports 中的字符串相关操作，如 `kStringCast`, `kStringTest`, `kStringCharCodeAt`, `kStringCodePointAt`, `kStringCompare`, `kStringConcat`, `kStringEquals`, `kStringFromCharCode`, `kStringFromCodePoint`, `kStringFromWtf16Array`, `kStringFromUtf8Array`, `kStringIntoUtf8Array`, `kStringToUtf8Array`, `kStringLength`, `kStringMeasureUtf8`, `kStringSubstring`, `kStringToWtf16Array`。
   - `DoubleToString`, `IntToString`: 将数字转换为字符串。
   - `ParseFloat`: 将字符串解析为浮点数。

3. **DataView 操作:**
   - `SetDataViewOpForErrorMessage`:  设置 DataView 操作类型，用于错误消息。
   - `ThrowDataViewTypeError`, `ThrowDataViewOutOfBoundsError`, `ThrowDataViewDetachedError`: 抛出 DataView 相关的错误。
   - `DataViewRangeCheck`, `DataViewBoundsCheck`, `DataViewDetachedBufferCheck`: 执行 DataView 的边界和状态检查。
   - `GetDataViewByteLength`: 获取 DataView 的字节长度，需要考虑 ArrayBuffer 是否可调整大小以及 DataView 是否是长度跟踪的。
   - `GetDataViewDataPtr`: 获取 DataView 的数据指针。
   - `DataViewGetter`, `DataViewSetter`:  实现 DataView 的读取和写入操作。

4. **外部函数调用 (Fast API):**
   - `WellKnown_FastApi`:  处理 WebAssembly 的 Fast API 调用，包括类型检查、参数转换、调用 C++ 函数等。
   - `HandleWellKnownImport`: 处理预定义的导入函数，特别是与 JavaScript 互操作的函数（例如字符串操作）。

5. **类型注解:**
   - `AnnotateAsString`:  为计算图中的值添加 wasm 类型注解，并将外部引用类型转换为外部字符串类型。

**关于 .tq 结尾:**

正如代码注释中提到的，如果 `v8/src/wasm/turboshaft-graph-interface.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是 V8 用于编写高性能内置函数的领域特定语言。由于该文件以 `.cc` 结尾，它是一个 C++ 源代码文件。但是，它会调用由 Torque 定义的内置函数。

**与 JavaScript 的关系 (举例说明):**

这段代码与 JavaScript 的功能紧密相关，因为它处理了 WebAssembly 与 JavaScript 之间的互操作。以下是一些 JavaScript 示例，说明了代码中某些功能的对应关系：

```javascript
// 内存增长
const memory = new WebAssembly.Memory({ initial: 1 });
memory.grow(1); // 对应于 MemoryGrow 功能

// 字符串操作
const str = "hello";
console.log(str.indexOf("l")); // 对应于 GetStringIndexOf 功能
console.log(str.toLowerCase()); // 对应于 CallStringToLowercase 功能
const charCode = str.charCodeAt(0); // 对应于 WellKnownImport 中的 kStringCharCodeAt

// DataView 操作
const buffer = new ArrayBuffer(16);
const dataView = new DataView(buffer, 0, 8);
dataView.setInt32(0, 12345, true); // 对应于 DataViewSetter 功能
console.log(dataView.getInt32(0, true)); // 对应于 DataViewGetter 功能

// 抛出 DataView 错误
// 如果尝试访问超出 DataView 范围的内存，会抛出错误，
// 这与 ThrowDataViewOutOfBoundsError 等功能相关。
try {
  dataView.getInt32(100, true);
} catch (e) {
  console.error(e);
}
```

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

- `GetStringIndexOf` 函数接收一个字符串 `string = "abcdefg"`，一个搜索字符串 `search = "cde"`，和一个起始索引 `start = 1`。

**输出:**

- `GetStringIndexOf` 函数将调用 V8 的内置字符串查找功能，并返回子字符串 `search` 在 `string` 中从索引 `start` 开始的第一个匹配项的索引，即 `2`。

**用户常见的编程错误 (举例说明):**

1. **DataView 越界访问:**

   ```javascript
   const buffer = new ArrayBuffer(8);
   const dataView = new DataView(buffer);
   dataView.setInt32(10, 123); // 错误：尝试在超出缓冲区范围的位置写入
   ```

   这段 C++ 代码中的 `DataViewRangeCheck` 和相关的 `ThrowDataViewOutOfBoundsError` 功能就是为了防止这种错误。

2. **对 `null` 或未定义的字符串调用字符串方法:**

   ```javascript
   let str = null;
   console.log(str.indexOf("a")); // 错误：无法读取 null 的属性 'indexOf'
   ```

   在 `HandleWellKnownImport` 中处理字符串操作时，代码会进行空值检查，并在必要时抛出异常或采取其他处理措施，以避免此类错误。

3. **类型不匹配的 Fast API 调用:**

   假设 WebAssembly 代码尝试调用一个需要整数参数的 Fast API 函数，但传递了一个浮点数。`WellKnown_FastApi` 函数中的类型检查部分会检测到这种不匹配，并可能采取措施（例如，尝试转换或抛出异常）。

**功能归纳 (针对第 3 部分):**

这段代码作为 Turboshaft 编译器和 V8 运行时环境之间的一个桥梁，主要负责以下功能：

- **处理 WebAssembly 的内存操作，特别是内存增长。**
- **提供了一系列用于操作 WebAssembly 外部字符串的方法，包括创建、比较、查找、截取、编码等，并与 JavaScript 的字符串功能进行互操作。**
- **实现了 WebAssembly 中 DataView 对象的各种操作，包括读取、写入、边界检查和错误处理，确保与 JavaScript 的 DataView 行为一致。**
- **支持 WebAssembly 的 Fast API 调用，允许高效地调用 C++ 实现的函数，并进行必要的类型转换和错误处理。**

总的来说，这段代码是 Turboshaft 编译器生成正确且高性能 WebAssembly 代码的关键组成部分，它确保了 WebAssembly 代码能够安全可靠地与 JavaScript 环境进行交互。

Prompt: 
```
这是目录为v8/src/wasm/turboshaft-graph-interface.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/turboshaft-graph-interface.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共12部分，请归纳一下它的功能

"""
else {
      Label<Word64> done(&asm_);

      IF (LIKELY(__ Uint64LessThanOrEqual(
              value.op, __ Word64Constant(static_cast<int64_t>(kMaxInt))))) {
        GOTO(done, __ ChangeInt32ToInt64(CallBuiltinThroughJumptable<
                                         BuiltinCallDescriptor::WasmMemoryGrow>(
                       decoder, {__ Word32Constant(imm.index),
                                 __ TruncateWord64ToWord32(value.op)})));
      } ELSE {
        GOTO(done, __ Word64Constant(int64_t{-1}));
      }

      BIND(done, result_64);

      result->op = result_64;
    }
    instance_cache_.ReloadCachedMemory();
  }

  V<Word32> IsExternRefString(const Value value) {
    compiler::WasmTypeCheckConfig config{value.type, kWasmRefExternString};
    V<Map> rtt = OpIndex::Invalid();
    return __ WasmTypeCheck(value.op, rtt, config);
  }

  V<String> ExternRefToString(const Value value, bool null_succeeds = false) {
    wasm::ValueType target_type =
        null_succeeds ? kWasmRefNullExternString : kWasmRefExternString;
    compiler::WasmTypeCheckConfig config{value.type, target_type};
    V<Map> rtt = OpIndex::Invalid();
    return V<String>::Cast(__ WasmTypeCast(value.op, rtt, config));
  }

  bool IsExplicitStringCast(const Value value) {
    if (__ generating_unreachable_operations()) return false;
    const WasmTypeCastOp* cast =
        __ output_graph().Get(value.op).TryCast<WasmTypeCastOp>();
    return cast && cast->config.to == kWasmRefExternString;
  }

  V<Word32> GetStringIndexOf(FullDecoder* decoder, V<String> string,
                             V<String> search, V<Word32> start) {
    // Clamp the start index.
    Label<Word32> clamped_start_label(&asm_);
    GOTO_IF(__ Int32LessThan(start, 0), clamped_start_label,
            __ Word32Constant(0));
    V<Word32> length = __ template LoadField<Word32>(
        string, compiler::AccessBuilder::ForStringLength());
    GOTO_IF(__ Int32LessThan(start, length), clamped_start_label, start);
    GOTO(clamped_start_label, length);
    BIND(clamped_start_label, clamped_start);
    start = clamped_start;

    // This can't overflow because we've clamped `start` above.
    V<Smi> start_smi = __ TagSmi(start);
    BuildModifyThreadInWasmFlag(decoder->zone(), false);

    V<Smi> result_value =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::StringIndexOf>(
            decoder, {string, search, start_smi});
    BuildModifyThreadInWasmFlag(decoder->zone(), true);

    return __ UntagSmi(result_value);
  }

#if V8_INTL_SUPPORT
  V<String> CallStringToLowercase(FullDecoder* decoder, V<String> string) {
    BuildModifyThreadInWasmFlag(decoder->zone(), false);
    OpIndex result = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::StringToLowerCaseIntl>(
        decoder, __ NoContextConstant(), {string});
    BuildModifyThreadInWasmFlag(decoder->zone(), true);
    return result;
  }
#endif

  void SetDataViewOpForErrorMessage(DataViewOp op_type) {
    OpIndex isolate_root = __ LoadRootRegister();
    __ Store(isolate_root, __ Word32Constant(op_type),
             StoreOp::Kind::RawAligned(), MemoryRepresentation::Uint8(),
             compiler::kNoWriteBarrier, Isolate::error_message_param_offset());
  }

  void ThrowDataViewTypeError(FullDecoder* decoder, V<Object> dataview,
                              DataViewOp op_type) {
    SetDataViewOpForErrorMessage(op_type);
    CallBuiltinThroughJumptable<BuiltinCallDescriptor::ThrowDataViewTypeError>(
        decoder, {V<JSDataView>::Cast(dataview)});
    __ Unreachable();
  }

  void ThrowDataViewOutOfBoundsError(FullDecoder* decoder, DataViewOp op_type) {
    SetDataViewOpForErrorMessage(op_type);
    CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::ThrowDataViewOutOfBounds>(decoder, {});
    __ Unreachable();
  }

  void ThrowDataViewDetachedError(FullDecoder* decoder, DataViewOp op_type) {
    SetDataViewOpForErrorMessage(op_type);
    CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::ThrowDataViewDetachedError>(decoder, {});
    __ Unreachable();
  }

  void DataViewRangeCheck(FullDecoder* decoder, V<WordPtr> left,
                          V<WordPtr> right, DataViewOp op_type) {
    IF (UNLIKELY(__ IntPtrLessThan(left, right))) {
      ThrowDataViewOutOfBoundsError(decoder, op_type);
    }
  }

  void DataViewBoundsCheck(FullDecoder* decoder, V<WordPtr> left,
                           V<WordPtr> right, DataViewOp op_type) {
    IF (UNLIKELY(__ IntPtrLessThan(left, right))) {
      ThrowDataViewDetachedError(decoder, op_type);
    }
  }

  void DataViewDetachedBufferCheck(FullDecoder* decoder, V<Object> dataview,
                                   DataViewOp op_type) {
    IF (UNLIKELY(
            __ ArrayBufferIsDetached(V<JSArrayBufferView>::Cast(dataview)))) {
      ThrowDataViewDetachedError(decoder, op_type);
    }
  }

  V<WordPtr> GetDataViewByteLength(FullDecoder* decoder, V<Object> dataview,
                                   DataViewOp op_type) {
    DCHECK_EQ(op_type, DataViewOp::kByteLength);
    return GetDataViewByteLength(decoder, dataview, __ IntPtrConstant(0),
                                 op_type);
  }

  // Converts a Smi or HeapNumber to an intptr. The input is not validated.
  V<WordPtr> ChangeTaggedNumberToIntPtr(V<Object> tagged) {
    Label<> smi_label(&asm_);
    Label<> heapnumber_label(&asm_);
    Label<WordPtr> done_label(&asm_);

    GOTO_IF(LIKELY(__ IsSmi(tagged)), smi_label);
    GOTO(heapnumber_label);

    BIND(smi_label);
    V<WordPtr> smi_length =
        __ ChangeInt32ToIntPtr(__ UntagSmi(V<Smi>::Cast(tagged)));
    GOTO(done_label, smi_length);

    BIND(heapnumber_label);
    V<Float64> float_value = __ template LoadField<Float64>(
        tagged, AccessBuilder::ForHeapNumberValue());
    if constexpr (Is64()) {
      DCHECK_EQ(WordPtr::bits, Word64::bits);
      GOTO(done_label,
           V<WordPtr>::Cast(
               __ TruncateFloat64ToInt64OverflowUndefined(float_value)));
    } else {
      GOTO(done_label,
           __ ChangeInt32ToIntPtr(
               __ TruncateFloat64ToInt32OverflowUndefined(float_value)));
    }

    BIND(done_label, length);
    return length;
  }

  // An `ArrayBuffer` can be resizable, i.e. it can shrink or grow.
  // A `SharedArrayBuffer` can be growable, i.e. it can only grow. A `DataView`
  // can be length-tracking or non-legth-tracking . A length-tracking `DataView`
  // is tracking the length of the underlying buffer, i.e. it doesn't have a
  // `byteLength` specified, which means that the length of the `DataView` is
  // the length (or remaining length if `byteOffset != 0`) of the underlying
  // array buffer. On the other hand, a non-length-tracking `DataView` has a
  // `byteLength`.
  // Depending on whether the buffer is resizable or growable and the `DataView`
  // is length-tracking or non-length-tracking, getting the byte length has to
  // be handled differently.
  V<WordPtr> GetDataViewByteLength(FullDecoder* decoder, V<Object> dataview,
                                   V<WordPtr> offset, DataViewOp op_type) {
    Label<WordPtr> done_label(&asm_);
    Label<> rab_ltgsab_label(&asm_);
    Label<> type_error_label(&asm_);

    GOTO_IF(UNLIKELY(__ IsSmi(dataview)), type_error_label);

    // Case 1):
    //  - non-resizable ArrayBuffers, length-tracking and non-length-tracking
    //  - non-growable SharedArrayBuffers, length-tracking and non-length-tr.
    //  - growable SharedArrayBuffers, non-length-tracking
    GOTO_IF_NOT(
        LIKELY(__ HasInstanceType(dataview, InstanceType::JS_DATA_VIEW_TYPE)),
        rab_ltgsab_label);
    if (op_type != DataViewOp::kByteLength) {
      DataViewRangeCheck(decoder, offset, __ IntPtrConstant(0), op_type);
    }
    DataViewDetachedBufferCheck(decoder, dataview, op_type);
    V<WordPtr> view_byte_length = __ LoadField<WordPtr>(
        dataview, AccessBuilder::ForJSArrayBufferViewByteLength());
    GOTO(done_label, view_byte_length);

    // Case 2):
    // - resizable ArrayBuffers, length-tracking and non-length-tracking
    // - growable SharedArrayBuffers, length-tracking
    BIND(rab_ltgsab_label);
    GOTO_IF_NOT(LIKELY(__ HasInstanceType(
                    dataview, InstanceType::JS_RAB_GSAB_DATA_VIEW_TYPE)),
                type_error_label);
    if (op_type != DataViewOp::kByteLength) {
      DataViewRangeCheck(decoder, offset, __ IntPtrConstant(0), op_type);
    }
    DataViewDetachedBufferCheck(decoder, dataview, op_type);

    V<Word32> bit_field = __ LoadField<Word32>(
        dataview, AccessBuilder::ForJSArrayBufferViewBitField());
    V<Word32> length_tracking = __ Word32BitwiseAnd(
        bit_field, JSArrayBufferView::IsLengthTrackingBit::kMask);
    V<Word32> backed_by_rab_bit = __ Word32BitwiseAnd(
        bit_field, JSArrayBufferView::IsBackedByRabBit::kMask);

    V<Object> buffer = __ LoadField<Object>(
        dataview, compiler::AccessBuilder::ForJSArrayBufferViewBuffer());
    V<WordPtr> buffer_byte_length = __ LoadField<WordPtr>(
        buffer, AccessBuilder::ForJSArrayBufferByteLength());
    V<WordPtr> view_byte_offset = __ LoadField<WordPtr>(
        dataview, AccessBuilder::ForJSArrayBufferViewByteOffset());

    // The final length for each case in Case 2) is calculated differently.
    // Case: resizable ArrayBuffers, LT and non-LT.
    IF (backed_by_rab_bit) {
      // DataViews with resizable ArrayBuffers can go out of bounds.
      IF (length_tracking) {
        ScopedVar<WordPtr> final_length(this, 0);
        IF (LIKELY(__ UintPtrLessThanOrEqual(view_byte_offset,
                                             buffer_byte_length))) {
          final_length = __ WordPtrSub(buffer_byte_length, view_byte_offset);
        }
        DataViewBoundsCheck(decoder, buffer_byte_length, view_byte_offset,
                            op_type);
        GOTO(done_label, final_length);
      } ELSE {
        V<WordPtr> view_byte_length = __ LoadField<WordPtr>(
            dataview, AccessBuilder::ForJSArrayBufferViewByteLength());
        DataViewBoundsCheck(decoder, buffer_byte_length,
                            __ WordPtrAdd(view_byte_offset, view_byte_length),
                            op_type);

        GOTO(done_label, view_byte_length);
      }
    }
    // Case: growable SharedArrayBuffers, LT.
    ELSE {
      V<Object> gsab_length_tagged = CallRuntime(
          decoder->zone(), Runtime::kGrowableSharedArrayBufferByteLength,
          {buffer}, __ NoContextConstant());
      V<WordPtr> gsab_length = ChangeTaggedNumberToIntPtr(gsab_length_tagged);
      ScopedVar<WordPtr> gsab_buffer_byte_length(this, 0);
      IF (LIKELY(__ UintPtrLessThanOrEqual(view_byte_offset, gsab_length))) {
        gsab_buffer_byte_length = __ WordPtrSub(gsab_length, view_byte_offset);
      }
      GOTO(done_label, gsab_buffer_byte_length);
    }
    __ Unreachable();

    BIND(type_error_label);
    ThrowDataViewTypeError(decoder, dataview, op_type);

    BIND(done_label, final_view_byte_length);
    return final_view_byte_length;
  }

  V<WordPtr> GetDataViewDataPtr(FullDecoder* decoder, V<Object> dataview,
                                V<WordPtr> offset, DataViewOp op_type) {
    V<WordPtr> view_byte_length =
        GetDataViewByteLength(decoder, dataview, offset, op_type);
    V<WordPtr> view_byte_length_minus_size =
        __ WordPtrSub(view_byte_length, GetTypeSize(op_type));
    DataViewRangeCheck(decoder, view_byte_length_minus_size, offset, op_type);
    return __ LoadField<WordPtr>(
        dataview, compiler::AccessBuilder::ForJSDataViewDataPointer());
  }

  OpIndex DataViewGetter(FullDecoder* decoder, const Value args[],
                         DataViewOp op_type) {
    V<Object> dataview = args[0].op;
    V<WordPtr> offset = __ ChangeInt32ToIntPtr(args[1].op);
    V<Word32> is_little_endian =
        (op_type == DataViewOp::kGetInt8 || op_type == DataViewOp::kGetUint8)
            ? __ Word32Constant(1)
            : args[2].op;

    V<WordPtr> data_ptr =
        GetDataViewDataPtr(decoder, dataview, offset, op_type);
    return __ LoadDataViewElement(dataview, data_ptr, offset, is_little_endian,
                                  GetExternalArrayType(op_type));
  }

  void DataViewSetter(FullDecoder* decoder, const Value args[],
                      DataViewOp op_type) {
    V<Object> dataview = args[0].op;
    V<WordPtr> offset = __ ChangeInt32ToIntPtr(args[1].op);
    V<Word32> value = args[2].op;
    V<Word32> is_little_endian =
        (op_type == DataViewOp::kSetInt8 || op_type == DataViewOp::kSetUint8)
            ? __ Word32Constant(1)
            : args[3].op;

    V<WordPtr> data_ptr =
        GetDataViewDataPtr(decoder, dataview, offset, op_type);
    __ StoreDataViewElement(dataview, data_ptr, offset, value, is_little_endian,
                            GetExternalArrayType(op_type));
  }

  // Adds a wasm type annotation to the graph and replaces any extern type with
  // the extern string type.
  template <typename T>
  V<T> AnnotateAsString(V<T> value, wasm::ValueType type) {
    DCHECK(type.is_reference_to(HeapType::kString) ||
           type.is_reference_to(HeapType::kExternString) ||
           type.is_reference_to(HeapType::kExtern));
    if (type.is_reference_to(HeapType::kExtern)) {
      type =
          ValueType::RefMaybeNull(HeapType::kExternString, type.nullability());
    }
    return __ AnnotateWasmType(value, type);
  }

  void WellKnown_FastApi(FullDecoder* decoder, const CallFunctionImmediate& imm,
                         const Value args[], Value returns[]) {
    uint32_t func_index = imm.index;
    V<Object> receiver = args[0].op;
    // TODO(14616): Fix this.
    V<FixedArray> imports_array = LOAD_IMMUTABLE_INSTANCE_FIELD(
        trusted_instance_data(false), WellKnownImports,
        MemoryRepresentation::TaggedPointer());
    V<Object> data = __ LoadFixedArrayElement(imports_array, func_index);
    V<Object> cached_map = __ Load(data, LoadOp::Kind::TaggedBase(),
                                   MemoryRepresentation::TaggedPointer(),
                                   WasmFastApiCallData::kCachedMapOffset);

    Label<> if_equal_maps(&asm_);
    Label<> if_unknown_receiver(&asm_);
    GOTO_IF(__ IsSmi(receiver), if_unknown_receiver);

    V<Map> map = __ LoadMapField(V<Object>::Cast(receiver));

    // Clear the weak bit.
    cached_map = __ BitcastWordPtrToTagged(__ WordPtrBitwiseAnd(
        __ BitcastTaggedToWordPtr(cached_map), ~kWeakHeapObjectMask));
    GOTO_IF(__ TaggedEqual(map, cached_map), if_equal_maps);
    GOTO(if_unknown_receiver);

    BIND(if_unknown_receiver);
    V<NativeContext> context = instance_cache_.native_context();
    CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmFastApiCallTypeCheckAndUpdateIC>(
        decoder, context, {data, receiver});
    GOTO(if_equal_maps);

    BIND(if_equal_maps);
    OpIndex receiver_handle = __ AdaptLocalArgument(receiver);

    const wasm::FunctionSig* sig = decoder->module_->functions[func_index].sig;
    size_t param_count = sig->parameter_count();
    DCHECK_LE(sig->return_count(), 1);

    const MachineSignature* callback_sig =
        env_->fast_api_signatures[func_index];
    // All normal parameters + the options as additional parameter at the end.
    MachineSignature::Builder builder(decoder->zone(), sig->return_count(),
                                      param_count + 1);
    if (sig->return_count()) {
      builder.AddReturn(callback_sig->GetReturn());
    }
    // The first parameter is the receiver. Because of the fake handle on the
    // stack the type is `Pointer`.
    builder.AddParam(MachineType::Pointer());

    for (size_t i = 0; i < callback_sig->parameter_count(); ++i) {
      builder.AddParam(callback_sig->GetParam(i));
    }
    // Options object.
    builder.AddParam(MachineType::Pointer());

    base::SmallVector<OpIndex, 16> inputs(param_count + 1);

    inputs[0] = receiver_handle;

    Label<> value_out_of_range(&asm_);
    for (size_t i = 1; i < param_count; ++i) {
      if (sig->GetParam(i).is_reference()) {
        inputs[i] = __ AdaptLocalArgument(args[i].op);
      } else if (callback_sig->GetParam(i - 1).representation() ==
                 MachineRepresentation::kWord64) {
        if (sig->GetParam(i) == kWasmI64) {
          // If we already have an I64, then no conversion is needed neither for
          // int64 nor uint64.
          inputs[i] = args[i].op;
        } else if (callback_sig->GetParam(i - 1) == MachineType::Int64()) {
          if (sig->GetParam(i) == kWasmF64) {
            V<Tuple<Word64, Word32>> truncate =
                __ TryTruncateFloat64ToInt64(args[i].op);
            inputs[i] = __ template Projection<0>(truncate);
            GOTO_IF(UNLIKELY(
                        __ Word32Equal(__ template Projection<1>(truncate), 0)),
                    value_out_of_range);
          } else if (sig->GetParam(i) == kWasmI32) {
            inputs[i] = __ ChangeInt32ToInt64(args[i].op);
          } else {
            // TODO(ahaas): Handle values that are out of range of int64.
            CHECK_EQ(sig->GetParam(i), kWasmF32);
            V<Tuple<Word64, Word32>> truncate =
                __ TryTruncateFloat32ToInt64(args[i].op);
            inputs[i] = __ template Projection<0>(truncate);
            GOTO_IF(UNLIKELY(
                        __ Word32Equal(__ template Projection<1>(truncate), 0)),
                    value_out_of_range);
          }
        } else if (callback_sig->GetParam(i - 1) == MachineType::Uint64()) {
          if (sig->GetParam(i) == kWasmF64) {
            V<Tuple<Word64, Word32>> truncate =
                __ TryTruncateFloat64ToUint64(args[i].op);
            inputs[i] = __ template Projection<0>(truncate);
            GOTO_IF(UNLIKELY(
                        __ Word32Equal(__ template Projection<1>(truncate), 0)),
                    value_out_of_range);
          } else if (sig->GetParam(i) == kWasmI32) {
            inputs[i] = __ ChangeUint32ToUint64(args[i].op);
          } else {
            // TODO(ahaas): Handle values that are out of range of int64.
            CHECK_EQ(sig->GetParam(i), kWasmF32);
            V<Tuple<Word64, Word32>> truncate =
                __ TryTruncateFloat32ToUint64(args[i].op);
            inputs[i] = __ template Projection<0>(truncate);
            GOTO_IF(UNLIKELY(
                        __ Word32Equal(__ template Projection<1>(truncate), 0)),
                    value_out_of_range);
          }
        }
      } else {
        inputs[i] = args[i].op;
      }
    }

    OpIndex options_object;
    {
      const int kAlign = alignof(v8::FastApiCallbackOptions);
      const int kSize = sizeof(v8::FastApiCallbackOptions);

      options_object = __ StackSlot(kSize, kAlign);

      static_assert(
          sizeof(v8::FastApiCallbackOptions::isolate) == sizeof(intptr_t),
          "We expected 'isolate' to be pointer sized, but it is not.");
      __ StoreOffHeap(options_object,
                      __ IsolateField(IsolateFieldId::kIsolateAddress),
                      MemoryRepresentation::UintPtr(),
                      offsetof(v8::FastApiCallbackOptions, isolate));

      V<Object> callback_data =
          __ Load(data, LoadOp::Kind::TaggedBase(),
                  MemoryRepresentation::TaggedPointer(),
                  WasmFastApiCallData::kCallbackDataOffset);
      V<WordPtr> data_argument_to_pass = __ AdaptLocalArgument(callback_data);

      __ StoreOffHeap(options_object, data_argument_to_pass,
                      MemoryRepresentation::UintPtr(),
                      offsetof(v8::FastApiCallbackOptions, data));
    }

    inputs[param_count] = options_object;

    const CallDescriptor* call_descriptor =
        compiler::Linkage::GetSimplifiedCDescriptor(__ graph_zone(),
                                                    builder.Get());
    const TSCallDescriptor* ts_call_descriptor = TSCallDescriptor::Create(
        call_descriptor, compiler::CanThrow::kNo,
        compiler::LazyDeoptOnThrow::kNo, __ graph_zone());
    OpIndex target_address = __ ExternalConstant(ExternalReference::Create(
        env_->fast_api_targets[func_index].load(std::memory_order_relaxed),
        ExternalReference::FAST_C_CALL));

    V<Context> native_context = instance_cache_.native_context();

    __ Store(__ LoadRootRegister(),
             __ BitcastHeapObjectToWordPtr(native_context),
             StoreOp::Kind::RawAligned(), MemoryRepresentation::UintPtr(),
             compiler::kNoWriteBarrier, Isolate::context_offset());
    BuildModifyThreadInWasmFlag(__ graph_zone(), false);
    OpIndex ret_val = __ Call(target_address, OpIndex::Invalid(),
                              base::VectorOf(inputs), ts_call_descriptor);

#if DEBUG
    // Reset the context again after the call, to make sure nobody is using the
    // leftover context in the isolate.
    __ Store(__ LoadRootRegister(),
             __ WordPtrConstant(Context::kInvalidContext),
             StoreOp::Kind::RawAligned(), MemoryRepresentation::UintPtr(),
             compiler::kNoWriteBarrier, Isolate::context_offset());
#endif

    V<Object> exception = __ Load(
        __ LoadRootRegister(), LoadOp::Kind::RawAligned(),
        MemoryRepresentation::UintPtr(), IsolateData::exception_offset());

    IF_NOT (LIKELY(
                __ TaggedEqual(exception, LOAD_ROOT(TheHoleValue)))) {
      CallBuiltinThroughJumptable<
          BuiltinCallDescriptor::WasmPropagateException>(
          decoder, {}, CheckForException::kCatchInThisFrame);
    }
    BuildModifyThreadInWasmFlag(__ graph_zone(), true);

    if (callback_sig->return_count() > 0) {
      if (callback_sig->GetReturn() == MachineType::Bool()) {
        ret_val = __ WordBitwiseAnd(ret_val, __ Word32Constant(0xff),
                                    WordRepresentation::Word32());
      } else if (callback_sig->GetReturn() == MachineType::Int64()) {
        if (sig->GetReturn() == kWasmF64) {
          ret_val = __ ChangeInt64ToFloat64(ret_val);
        } else if (sig->GetReturn() == kWasmI32) {
          ret_val = __ TruncateWord64ToWord32(ret_val);
        } else if (sig->GetReturn() == kWasmF32) {
          ret_val = __ ChangeInt64ToFloat32(ret_val);
        }
      } else if (callback_sig->GetReturn() == MachineType::Uint64()) {
        if (sig->GetReturn() == kWasmF64) {
          ret_val = __ ChangeUint64ToFloat64(ret_val);
        } else if (sig->GetReturn() == kWasmI32) {
          ret_val = __ TruncateWord64ToWord32(ret_val);
        } else if (sig->GetReturn() == kWasmF32) {
          ret_val = __ ChangeUint64ToFloat32(ret_val);
        }
      }
    }
    Label<> done(&asm_);
    GOTO(done);
    BIND(value_out_of_range);
    auto [target, implicit_arg] =
        BuildImportedFunctionTargetAndImplicitArg(decoder, imm.index);
    BuildWasmCall(decoder, imm.sig, target, implicit_arg, args, returns);
    __ Unreachable();
    BIND(done);
    if (sig->return_count()) {
      returns[0].op = ret_val;
    }
  }

  bool HandleWellKnownImport(FullDecoder* decoder,
                             const CallFunctionImmediate& imm,
                             const Value args[], Value returns[]) {
    uint32_t index = imm.index;
    if (!decoder->module_) return false;  // Only needed for tests.
    const WellKnownImportsList& well_known_imports =
        decoder->module_->type_feedback.well_known_imports;
    using WKI = WellKnownImport;
    WKI imported_op = well_known_imports.get(index);
    OpIndex result;
    switch (imported_op) {
      case WKI::kUninstantiated:
      case WKI::kGeneric:
      case WKI::kLinkError:
        return false;

      // JS String Builtins proposal.
      case WKI::kStringCast: {
        result = ExternRefToString(args[0]);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringTest: {
        result = IsExternRefString(args[0]);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringCharCodeAt: {
        V<String> string = ExternRefToString(args[0]);
        V<String> view = __ StringAsWtf16(string);
        // TODO(14108): Annotate `view`'s type.
        result = GetCodeUnitImpl(decoder, view, args[1].op);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringCodePointAt: {
        V<String> string = ExternRefToString(args[0]);
        V<String> view = __ StringAsWtf16(string);
        // TODO(14108): Annotate `view`'s type.
        result = StringCodePointAt(decoder, view, args[1].op);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringCompare: {
        V<String> a_string = ExternRefToString(args[0]);
        V<String> b_string = ExternRefToString(args[1]);
        result = __ UntagSmi(
            CallBuiltinThroughJumptable<BuiltinCallDescriptor::StringCompare>(
                decoder, {a_string, b_string}));
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringConcat: {
        V<String> head_string = ExternRefToString(args[0]);
        V<String> tail_string = ExternRefToString(args[1]);
        V<HeapObject> native_context = instance_cache_.native_context();
        V<String> result_value = CallBuiltinThroughJumptable<
            BuiltinCallDescriptor::StringAdd_CheckNone>(
            decoder, V<Context>::Cast(native_context),
            {head_string, tail_string});
        result = __ AnnotateWasmType(result_value, kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringEquals: {
        // Using nullable type guards here because this instruction needs to
        // handle {null} without trapping.
        static constexpr bool kNullSucceeds = true;
        V<String> a_string = ExternRefToString(args[0], kNullSucceeds);
        V<String> b_string = ExternRefToString(args[1], kNullSucceeds);
        result = StringEqImpl(decoder, a_string, b_string, kWasmExternRef,
                              kWasmExternRef);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringFromCharCode: {
        V<Word32> capped = __ Word32BitwiseAnd(args[0].op, 0xFFFF);
        V<String> result_value = CallBuiltinThroughJumptable<
            BuiltinCallDescriptor::WasmStringFromCodePoint>(decoder, {capped});
        result = __ AnnotateWasmType(result_value, kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringFromCodePoint: {
        V<String> result_value = CallBuiltinThroughJumptable<
            BuiltinCallDescriptor::WasmStringFromCodePoint>(decoder,
                                                            {args[0].op});
        result = __ AnnotateWasmType(result_value, kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringFromWtf16Array: {
        V<String> result_value = CallBuiltinThroughJumptable<
            BuiltinCallDescriptor::WasmStringNewWtf16Array>(
            decoder,
            {V<WasmArray>::Cast(NullCheck(args[0])), args[1].op, args[2].op});
        result = __ AnnotateWasmType(result_value, kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringFromUtf8Array:
        result = StringNewWtf8ArrayImpl(
            decoder, unibrow::Utf8Variant::kLossyUtf8, args[0], args[1],
            args[2], kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
      case WKI::kStringIntoUtf8Array: {
        V<String> string = ExternRefToString(args[0]);
        result = StringEncodeWtf8ArrayImpl(
            decoder, unibrow::Utf8Variant::kLossyUtf8, string,
            V<WasmArray>::Cast(NullCheck(args[1])), args[2].op);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringToUtf8Array: {
        V<String> string = ExternRefToString(args[0]);
        V<WasmArray> result_value = CallBuiltinThroughJumptable<
            BuiltinCallDescriptor::WasmStringToUtf8Array>(decoder, {string});
        result = __ AnnotateWasmType(result_value, returns[0].type);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringLength: {
        V<Object> string = ExternRefToString(args[0]);
        result = __ template LoadField<Word32>(
            string, compiler::AccessBuilder::ForStringLength());
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringMeasureUtf8: {
        V<String> string = ExternRefToString(args[0]);
        result = StringMeasureWtf8Impl(
            decoder, unibrow::Utf8Variant::kLossyUtf8, string);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringSubstring: {
        V<String> string = ExternRefToString(args[0]);
        V<String> view = __ StringAsWtf16(string);
        // TODO(12868): Consider annotating {view}'s type when the typing story
        //              for string views has been settled.
        V<String> result_value = CallBuiltinThroughJumptable<
            BuiltinCallDescriptor::WasmStringViewWtf16Slice>(
            decoder, {view, args[1].op, args[2].op});
        result = __ AnnotateWasmType(result_value, kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringToWtf16Array: {
        V<String> string = ExternRefToString(args[0]);
        result = CallBuiltinThroughJumptable<
            BuiltinCallDescriptor::WasmStringEncodeWtf16Array>(
            decoder,
            {string, V<WasmArray>::Cast(NullCheck(args[1])), args[2].op});
        decoder->detected_->add_imported_strings();
        break;
      }

      // Other string-related imports.
      case WKI::kDoubleToString: {
        BuildModifyThreadInWasmFlag(decoder->zone(), false);
        V<String> result_value = CallBuiltinThroughJumptable<
            BuiltinCallDescriptor::WasmFloat64ToString>(decoder, {args[0].op});
        result = AnnotateAsString(result_value, returns[0].type);
        BuildModifyThreadInWasmFlag(decoder->zone(), true);
        decoder->detected_->Add(
            returns[0].type.is_reference_to(wasm::HeapType::kString)
                ? WasmDetectedFeature::stringref
                : WasmDetectedFeature::imported_strings);
        break;
      }
      case WKI::kIntToString: {
        BuildModifyThreadInWasmFlag(decoder->zone(), false);
        V<String> result_value =
            CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmIntToString>(
                decoder, {args[0].op, args[1].op});
        result = AnnotateAsString(result_value, returns[0].type);
        BuildModifyThreadInWasmFlag(decoder->zone(), true);
        decoder->detected_->Add(
            returns[0].type.is_reference_to(wasm::HeapType::kString)
                ? WasmDetectedFeature::stringref
                : WasmDetectedFeature::imported_strings);
        break;
      }
      case WKI::kParseFloat: {
        if (args[0].type.is_nullable()) {
          Label<Float64> done(&asm_);
          GOTO_IF(__ IsNull(args[0].op, args[0].type), done,
                  __ Float64Constant(std::numeric_limits<double>::quiet_NaN()));

          BuildModifyThreadInWasmFlag(decoder->zone(), false);
          V<Float64> not_null_res = CallBuiltinThroughJumptable<
              BuiltinCallDescriptor::WasmStringToDouble>(decoder, {args[0].op});
          BuildModifyThreadInWasmFlag(decoder->zone(), true);
          GOTO(done, not_null_res);

          BIND(done, result_f64);
          result = result_f64;
        } else {
          BuildModifyThreadInWasmFlag(decoder->zone(), false);
          result = CallBuiltinThroughJumptable<
              BuiltinCallDescriptor::WasmStringToDouble>(decoder, {args[0].op});
          BuildModifyThreadInWasmFlag(decoder->zone(), true);
        }
        decoder->detected_->add_stringref();
        break;
      }
      case WKI::kStringIndexOf: {
        V<String> string = args[0].op;
        V<String> search = args[1].op;
        V<Word32> start = args[2].op;

        // If string is null, throw.
        if (args[0].type.is_nullable()) {
          IF (__ IsNull(string, args[0].type)) {
            CallBuiltinThroughJumptable<
                BuiltinCallDescriptor::ThrowIndexOfCalledOnNull>(decoder, {});
            __ Unreachable();
          }
        }

        // If search is null, replace it with "null".
        if (args[1].type.is_nullable()) {
          Label<String> search_done_label(&asm_);
          GOTO_IF_NOT(__ IsNull(search, args[1
"""


```