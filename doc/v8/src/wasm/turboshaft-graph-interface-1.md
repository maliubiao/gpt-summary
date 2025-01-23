Response: The user wants a summary of the C++ code provided, which is part of the `turboshaft-graph-interface.cc` file in the V8 JavaScript engine.

The code seems to be responsible for generating Turboshaft IR (Intermediate Representation) nodes for various WebAssembly operations. It handles interactions with JavaScript built-in functions and manages inline caching and inlining decisions for function calls.

Here's a breakdown of the key functionalities observed in the provided snippet:

1. **Memory Growth:** Handles the `memory.grow` instruction, including checks for exceeding the maximum integer value.
2. **String Conversions and Checks:** Provides functions to check if a value is an externref string and to cast externrefs to strings.
3. **String Operations:** Implements `string.indexOf`, potentially clamping the start index.
4. **Internationalization (Intl) Support:** Includes functionality for converting strings to lowercase, specifically for internationalized strings.
5. **DataView Operations:** Offers support for various DataView operations (getters and setters for different data types), including error handling for type mismatches, out-of-bounds access, and detached buffers. It also deals with resizable and growable ArrayBuffers.
6. **Fast API Calls:** Handles calls to "Fast API" functions, including type checking and calling the underlying C++ implementation.
7. **Well-Known Imports:** Implements logic for handling various well-known imports, primarily related to string manipulation and DataViews, by calling corresponding JavaScript built-ins or generating appropriate IR. This includes handling nullable arguments and potential type conversions.
8. **Function Calls (Direct and Indirect):** Manages both direct and indirect function calls, with logic for inlining based on feedback and heuristics. It handles potential cross-instance calls and ensures signature compatibility during inlining.
9. **Function Reference Calls (`call_ref` and `return_call_ref`):** Implements calls via function references, also with inlining capabilities based on feedback.
10. **Branch on Null/Non-Null:** Implements `br_on_null` and `br_on_non_null` instructions.
11. **SIMD Operations:** Starts defining how SIMD operations are handled.

**Relationship with JavaScript:**

The code heavily interacts with JavaScript by:

*   Calling JavaScript built-in functions for tasks like string manipulation, DataView operations, and type conversions.
*   Using JavaScript objects (like `String`, `DataView`, `ArrayBuffer`) in the generated IR.
*   Potentially throwing JavaScript exceptions (e.g., `TypeError`, `RangeError`).

**Illustrative JavaScript Examples:**

Let's consider the `String.prototype.indexOf` functionality, which relates to the `GetStringIndexOf` function in the C++ code.

```javascript
// JavaScript example using String.prototype.indexOf
const myString = "hello world";
const index = myString.indexOf("world", 2); // Search for "world" starting from index 2
console.log(index); // Output: 6

// Another example showing the clamping behavior
const anotherString = "abc";
const clampedIndex = anotherString.indexOf("b", 5); // Start index out of bounds
console.log(clampedIndex); // Output: 1 (effectively starts from the end)
```

The C++ code in `GetStringIndexOf` ensures that the `start` index is clamped within the bounds of the string's length, similar to how JavaScript's `indexOf` behaves. It achieves this using conditional branching and potentially setting `start` to 0 or the string's length.

Another example involves the `DataView` operations:

```javascript
// JavaScript example using DataView
const buffer = new ArrayBuffer(8);
const view = new DataView(buffer);

view.setInt32(0, 12345, true); // Set an integer at offset 0 (little-endian)
const value = view.getInt32(0, true); // Get the integer back
console.log(value); // Output: 12345
```

The C++ code provides the underlying mechanisms to perform these `setInt32` and `getInt32` operations on the `DataView`, including bounds checking and handling endianness.

The "Fast API" calls relate to how WebAssembly can directly call into JavaScript or native code. For example, if a WebAssembly module imports a function implemented in JavaScript, the `WellKnown_FastApi` function might be involved in efficiently calling that JavaScript function.

The well-known imports for strings directly correspond to JavaScript string methods. For instance, `WKI::kStringConcat` in the C++ code would be used when a WebAssembly module imports a function that performs string concatenation, effectively mapping to the JavaScript `+` operator or `String.prototype.concat()`.
这是 `v8/src/wasm/turboshaft-graph-interface.cc` 文件的第 2 部分，它主要负责为 WebAssembly 指令生成 Turboshaft 图形表示（IR）。这部分代码延续了第 1 部分的功能，继续构建 WebAssembly 代码的 Turboshaft IR，并且涉及到与 JavaScript 功能的交互。

以下是这部分代码归纳的功能点：

1. **处理 `memory.grow` 指令的边缘情况:**  代码检查 `memory.grow` 的增长量是否超过了 JavaScript 的最大安全整数 (`kMaxInt`)。如果超过，则直接返回 -1，否则调用内置函数进行内存增长。
2. **字符串类型检查和转换:** 提供了 `IsExternRefString` 函数来检查一个值是否是外部引用字符串，以及 `ExternRefToString` 函数将外部引用转换为 JavaScript 字符串。`IsExplicitStringCast` 用于判断一个值是否经过显式的字符串类型转换。
3. **实现 `string.indexOf` 功能:**  `GetStringIndexOf` 函数实现了 WebAssembly 中字符串的 `indexOf` 功能，包括对起始索引进行边界处理，并调用 JavaScript 的内置函数 `StringIndexOf`。
4. **支持国际化字符串操作:**  `CallStringToLowercase` 函数调用内置函数 `StringToLowerCaseIntl` 来进行国际化的字符串小写转换。
5. **提供 DataView 操作的辅助函数:**
    *   `SetDataViewOpForErrorMessage` 用于设置 DataView 操作类型，以便在抛出错误时提供更详细的信息。
    *   `ThrowDataViewTypeError`, `ThrowDataViewOutOfBoundsError`, `ThrowDataViewDetachedError` 用于抛出特定类型的 DataView 错误。
    *   `DataViewRangeCheck` 和 `DataViewBoundsCheck` 用于进行 DataView 的越界检查和边界检查。
    *   `DataViewDetachedBufferCheck` 用于检查 DataView 的底层缓冲区是否已分离。
    *   `GetDataViewByteLength` 的多个重载版本用于获取 DataView 的字节长度，需要考虑 ArrayBuffer 是否可调整大小以及 DataView 是否是长度跟踪的。
    *   `ChangeTaggedNumberToIntPtr` 将标记的数字（Smi 或 HeapNumber）转换为 intptr。
    *   `GetDataViewDataPtr` 获取 DataView 的数据指针，并进行必要的范围检查。
6. **实现 DataView 的 getter 和 setter:**  `DataViewGetter` 和 `DataViewSetter` 函数根据不同的 `DataViewOp` 类型，调用相应的内置函数来读取或写入 DataView 的数据。
7. **类型注解和外部字符串处理:** `AnnotateAsString` 函数为 Turboshaft 图中的节点添加 WebAssembly 类型注解，并将外部类型转换为外部字符串类型。
8. **处理 Well-Known Imports 中的 Fast API 调用:** `WellKnown_FastApi` 函数处理对 "Fast API" 函数的调用，包括类型检查、调用 C++ 实现，并处理返回值和异常。
9. **处理 Well-Known Imports:** `HandleWellKnownImport` 函数处理各种预定义的导入函数（Well-Known Imports），特别是与字符串和 DataView 相关的操作，例如字符串的转换、测试、字符码获取、比较、拼接、相等性判断、创建、编码、长度获取、子串获取、以及 DataView 的各种 getter 和 setter。这部分代码通过调用相应的 JavaScript 内置函数或生成相应的 Turboshaft IR 来实现这些导入的功能。
10. **实现直接函数调用 (`CallDirect`):**  `CallDirect` 函数处理 WebAssembly 模块内的直接函数调用。它会检查是否需要内联调用，如果需要则调用 `InlineWasmCall`，否则构建一个普通的函数调用节点。对于导入的函数，它会调用 `HandleWellKnownImport` 或构建一个调用导入函数的节点。
11. **实现尾调用 (`ReturnCall`):** `ReturnCall` 函数处理 WebAssembly 模块内的尾调用。类似于 `CallDirect`，它也会检查是否需要内联尾调用。
12. **实现间接函数调用 (`CallIndirect`):** `CallIndirect` 函数处理通过函数表进行的间接函数调用。它会检查是否开启了 `wasm_inlining_call_indirect` 标志，如果开启并且满足内联条件，则会尝试根据反馈信息进行投机内联。否则，构建一个调用间接函数的节点。
13. **实现间接尾调用 (`ReturnCallIndirect`):** `ReturnCallIndirect` 函数处理间接尾调用，与 `CallIndirect` 类似，也会尝试进行投机内联。
14. **实现通过函数引用调用 (`CallRef`):** `CallRef` 函数处理通过函数引用进行的调用，同样支持基于反馈信息的内联。
15. **实现通过函数引用尾调用 (`ReturnCallRef`):** `ReturnCallRef` 函数处理通过函数引用进行的尾调用，也支持内联。
16. **实现 `br_on_null` 和 `br_on_non_null` 指令:** 这两个函数分别处理当引用为空或非空时的分支跳转。
17. **开始处理 SIMD 操作 (`SimdOp`):**  这部分代码展示了如何开始处理 SIMD 相关的 WebAssembly 指令。

**与 JavaScript 功能的关系和示例:**

这部分代码与 JavaScript 功能紧密相关，因为它大量依赖 JavaScript 的内置对象和函数来实现 WebAssembly 的功能，特别是在处理字符串和 DataView 操作时。

例如，`GetStringIndexOf` 函数在 WebAssembly 中实现字符串查找功能，它最终会调用 JavaScript 的 `String.prototype.indexOf` 的底层实现。

```javascript
// JavaScript 代码
const str = "hello world";
const index = str.indexOf("world"); // 调用 JavaScript 内置的字符串查找功能
console.log(index); // 输出 6

// 在 WebAssembly 中，对应的操作会通过 GetStringIndexOf 调用 JavaScript 的 StringIndexOf 内置函数
```

再例如，DataView 的操作，如 `kDataViewGetInt32`，会调用 JavaScript 引擎中处理 `DataView.prototype.getInt32` 的内置函数。

```javascript
// JavaScript 代码
const buffer = new ArrayBuffer(4);
const dataView = new DataView(buffer);
dataView.setInt32(0, 100);
const value = dataView.getInt32(0); // 调用 JavaScript 内置的 DataView 获取整数功能
console.log(value); // 输出 100

// 在 WebAssembly 中，对应的操作会通过 DataViewGetter 调用 JavaScript 的 DataView 相关内置函数
```

总而言之，这部分代码是 WebAssembly 和 JavaScript 引擎之间交互的关键桥梁，它将 WebAssembly 的指令转换为可以在 V8 引擎中执行的 Turboshaft IR，并且在许多情况下，会委托给 JavaScript 的内置功能来完成具体的实现。

### 提示词
```
这是目录为v8/src/wasm/turboshaft-graph-interface.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```
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
          GOTO_IF_NOT(__ IsNull(search, args[1].type), search_done_label,
                      search);
          GOTO(search_done_label, LOAD_ROOT(null_string));
          BIND(search_done_label, search_value);
          search = search_value;
        }

        result = GetStringIndexOf(decoder, string, search, start);
        decoder->detected_->add_stringref();
        break;
      }
      case WKI::kStringIndexOfImported: {
        // As the `string` and `search` parameters are externrefs, we have to
        // make sure they are strings. To enforce this, we inline only if a
        // (successful) `"js-string":"cast"` was performed before.
        if (!(IsExplicitStringCast(args[0]) && IsExplicitStringCast(args[1]))) {
          return false;
        }
        V<String> string = args[0].op;
        V<String> search = args[1].op;
        V<Word32> start = args[2].op;

        result = GetStringIndexOf(decoder, string, search, start);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringToLocaleLowerCaseStringref:
        // TODO(14108): Implement.
        return false;
      case WKI::kStringToLowerCaseStringref: {
#if V8_INTL_SUPPORT
        V<String> string = args[0].op;
        if (args[0].type.is_nullable()) {
          IF (__ IsNull(string, args[0].type)) {
            CallBuiltinThroughJumptable<
                BuiltinCallDescriptor::ThrowToLowerCaseCalledOnNull>(decoder,
                                                                     {});
            __ Unreachable();
          }
        }
        V<String> result_value = CallStringToLowercase(decoder, string);
        result = __ AnnotateWasmType(result_value, kWasmRefString);
        decoder->detected_->add_stringref();
        break;
#else
        return false;
#endif
      }
      case WKI::kStringToLowerCaseImported: {
        // We have to make sure that the externref `string` parameter is a
        // string. To enforce this, we inline only if a (successful)
        // `"js-string":"cast"` was performed before.
#if V8_INTL_SUPPORT
        if (!IsExplicitStringCast(args[0])) {
          return false;
        }
        V<String> string = args[0].op;
        V<String> result_value = CallStringToLowercase(decoder, string);
        result = __ AnnotateWasmType(result_value, kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
#else
        return false;
#endif
      }

      // DataView related imports.
      // Note that we don't support DataView imports for resizable ArrayBuffers.
      case WKI::kDataViewGetBigInt64: {
        result = DataViewGetter(decoder, args, DataViewOp::kGetBigInt64);
        break;
      }
      case WKI::kDataViewGetBigUint64:
        result = DataViewGetter(decoder, args, DataViewOp::kGetBigUint64);
        break;
      case WKI::kDataViewGetFloat32:
        result = DataViewGetter(decoder, args, DataViewOp::kGetFloat32);
        break;
      case WKI::kDataViewGetFloat64:
        result = DataViewGetter(decoder, args, DataViewOp::kGetFloat64);
        break;
      case WKI::kDataViewGetInt8:
        result = DataViewGetter(decoder, args, DataViewOp::kGetInt8);
        break;
      case WKI::kDataViewGetInt16:
        result = DataViewGetter(decoder, args, DataViewOp::kGetInt16);
        break;
      case WKI::kDataViewGetInt32:
        result = DataViewGetter(decoder, args, DataViewOp::kGetInt32);
        break;
      case WKI::kDataViewGetUint8:
        result = DataViewGetter(decoder, args, DataViewOp::kGetUint8);
        break;
      case WKI::kDataViewGetUint16:
        result = DataViewGetter(decoder, args, DataViewOp::kGetUint16);
        break;
      case WKI::kDataViewGetUint32:
        result = DataViewGetter(decoder, args, DataViewOp::kGetUint32);
        break;
      case WKI::kDataViewSetBigInt64:
        DataViewSetter(decoder, args, DataViewOp::kSetBigInt64);
        break;
      case WKI::kDataViewSetBigUint64:
        DataViewSetter(decoder, args, DataViewOp::kSetBigUint64);
        break;
      case WKI::kDataViewSetFloat32:
        DataViewSetter(decoder, args, DataViewOp::kSetFloat32);
        break;
      case WKI::kDataViewSetFloat64:
        DataViewSetter(decoder, args, DataViewOp::kSetFloat64);
        break;
      case WKI::kDataViewSetInt8:
        DataViewSetter(decoder, args, DataViewOp::kSetInt8);
        break;
      case WKI::kDataViewSetInt16:
        DataViewSetter(decoder, args, DataViewOp::kSetInt16);
        break;
      case WKI::kDataViewSetInt32:
        DataViewSetter(decoder, args, DataViewOp::kSetInt32);
        break;
      case WKI::kDataViewSetUint8:
        DataViewSetter(decoder, args, DataViewOp::kSetUint8);
        break;
      case WKI::kDataViewSetUint16:
        DataViewSetter(decoder, args, DataViewOp::kSetUint16);
        break;
      case WKI::kDataViewSetUint32:
        DataViewSetter(decoder, args, DataViewOp::kSetUint32);
        break;
      case WKI::kDataViewByteLength: {
        V<Object> dataview = args[0].op;

        V<WordPtr> view_byte_length =
            GetDataViewByteLength(decoder, dataview, DataViewOp::kByteLength);
        if constexpr (Is64()) {
          result =
              __ ChangeInt64ToFloat64(__ ChangeIntPtrToInt64(view_byte_length));
        } else {
          result = __ ChangeInt32ToFloat64(
              __ TruncateWordPtrToWord32(view_byte_length));
        }
        break;
      }
      case WKI::kFastAPICall: {
        WellKnown_FastApi(decoder, imm, args, returns);
        result = returns[0].op;
        break;
      }
    }
    if (v8_flags.trace_wasm_inlining) {
      PrintF("[function %d: call to %d is well-known %s]\n", func_index_, index,
             WellKnownImportName(imported_op));
    }
    assumptions_->RecordAssumption(index, imported_op);
    returns[0].op = result;
    return true;
  }

  void CallDirect(FullDecoder* decoder, const CallFunctionImmediate& imm,
                  const Value args[], Value returns[]) {
    feedback_slot_++;
    if (imm.index < decoder->module_->num_imported_functions) {
      if (HandleWellKnownImport(decoder, imm, args, returns)) {
        return;
      }
      auto [target, implicit_arg] =
          BuildImportedFunctionTargetAndImplicitArg(decoder, imm.index);
      BuildWasmCall(decoder, imm.sig, target, implicit_arg, args, returns);
    } else {
      // Locally defined function.
      if (should_inline(decoder, feedback_slot_,
                        decoder->module_->functions[imm.index].code.length())) {
        if (v8_flags.trace_wasm_inlining) {
          PrintF("[function %d%s: inlining direct call #%d to function %d]\n",
                 func_index_, mode_ == kRegular ? "" : " (inlined)",
                 feedback_slot_, imm.index);
        }
        InlineWasmCall(decoder, imm.index, imm.sig, 0, false, args, returns);
      } else {
        V<WordPtr> callee =
            __ RelocatableConstant(imm.index, RelocInfo::WASM_CALL);
        BuildWasmCall(decoder, imm.sig, callee,
                      trusted_instance_data(
                          decoder->module_->function_is_shared(imm.index)),
                      args, returns);
      }
    }
  }

  void ReturnCall(FullDecoder* decoder, const CallFunctionImmediate& imm,
                  const Value args[]) {
    feedback_slot_++;
    if (imm.index < decoder->module_->num_imported_functions) {
      auto [target, implicit_arg] =
          BuildImportedFunctionTargetAndImplicitArg(decoder, imm.index);
      BuildWasmMaybeReturnCall(decoder, imm.sig, target, implicit_arg, args);
    } else {
      // Locally defined function.
      if (should_inline(decoder, feedback_slot_,
                        decoder->module_->functions[imm.index].code.length())) {
        if (v8_flags.trace_wasm_inlining) {
          PrintF(
              "[function %d%s: inlining direct tail call #%d to function %d]\n",
              func_index_, mode_ == kRegular ? "" : " (inlined)",
              feedback_slot_, imm.index);
        }
        InlineWasmCall(decoder, imm.index, imm.sig, 0, true, args, nullptr);
      } else {
        BuildWasmMaybeReturnCall(
            decoder, imm.sig,
            __ RelocatableConstant(imm.index, RelocInfo::WASM_CALL),
            trusted_instance_data(
                decoder->module_->function_is_shared(imm.index)),
            args);
      }
    }
  }

  void CallIndirect(FullDecoder* decoder, const Value& index,
                    const CallIndirectImmediate& imm, const Value args[],
                    Value returns[]) {
    if (v8_flags.wasm_inlining_call_indirect) {
      CHECK(v8_flags.wasm_inlining);
      feedback_slot_++;
      // In case of being unreachable, skip it because it tries to access nodes
      // which might be non-existent (OpIndex::Invalid()) in unreachable code.
      if (__ generating_unreachable_operations()) return;

      if (should_inline(decoder, feedback_slot_,
                        std::numeric_limits<int>::max())) {
        V<WordPtr> index_wordptr = TableAddressToUintPtrOrOOBTrap(
            imm.table_imm.table->address_type, index.op);

        DCHECK(!shared_);
        constexpr bool kNotShared = false;
        // Load the instance here even though it's only used below, in the hope
        // that load elimination can use it when fetching the target next.
        V<WasmTrustedInstanceData> instance = trusted_instance_data(kNotShared);

        // We are only interested in the target here for comparison against
        // the inlined call target below.
        // In particular, we don't need a dynamic type or null check: If the
        // actual call target (at runtime) is equal to the inlined call target,
        // we know already from the static check on the inlinee (see below) that
        // the inlined code has the right signature.
        constexpr bool kNeedsTypeOrNullCheck = false;
        auto [target, implicit_arg] = BuildIndirectCallTargetAndImplicitArg(
            decoder, index_wordptr, imm, kNeedsTypeOrNullCheck);

        size_t return_count = imm.sig->return_count();
        base::Vector<InliningTree*> feedback_cases =
            inlining_decisions_->function_calls()[feedback_slot_];
        std::vector<base::SmallVector<OpIndex, 2>> case_returns(return_count);
        // The slow path is the non-inlined generic `call_indirect`,
        // or a deopt node if that is enabled.
        constexpr int kSlowpathCase = 1;
        base::SmallVector<TSBlock*, wasm::kMaxPolymorphism + kSlowpathCase>
            case_blocks;
        for (size_t i = 0; i < feedback_cases.size() + kSlowpathCase; i++) {
          case_blocks.push_back(__ NewBlock());
        }
        // Block for the slowpath, i.e., the not-inlined call or deopt.
        TSBlock* no_inline_block = case_blocks.back();
        // Block for merging results after the inlined code.
        TSBlock* merge = __ NewBlock();

        // Always create a frame state, but rely on DCE to remove it in case we
        // end up not using deopts. This allows us to share the frame state
        // between a deopt due to wrong instance and deopt due to wrong target.
        V<FrameState> frame_state =
            CreateFrameState(decoder, imm.sig, &index, args);
        bool use_deopt_slowpath = deopts_enabled_;
        DCHECK_IMPLIES(use_deopt_slowpath, frame_state.valid());
        if (use_deopt_slowpath &&
            inlining_decisions_->has_non_inlineable_targets()[feedback_slot_]) {
          if (v8_flags.trace_wasm_inlining) {
            PrintF(
                "[function %d%s: Not emitting deopt slow-path for "
                "call_indirect #%d as feedback contains non-inlineable "
                "targets]\n",
                func_index_, mode_ == kRegular ? "" : " (inlined)",
                feedback_slot_);
          }
          use_deopt_slowpath = false;
        }

        // Wasm functions are semantically closures over the instance, but
        // when we inline a target in the following, we implicitly assume the
        // inlinee instance is the same as the caller's instance.
        // Directly jump to the non-inlined slowpath if that's violated.
        // Note that for `call_ref` this isn't necessary, because the funcref
        // equality check already captures both code and instance equality.
        constexpr BranchHint kUnlikelyCrossInstanceCall = BranchHint::kTrue;
        // Note that the `implicit_arg` can never be a `WasmImportData`,
        // since we don't inline imported functions right now.
        __ Branch({__ TaggedEqual(implicit_arg, instance),
                   kUnlikelyCrossInstanceCall},
                  case_blocks[0], no_inline_block);

        for (size_t i = 0; i < feedback_cases.size(); i++) {
          __ Bind(case_blocks[i]);
          InliningTree* tree = feedback_cases[i];
          if (!tree || !tree->is_inlined()) {
            // Fall through to the next case.
            __ Goto(case_blocks[i + 1]);
            // Do not use the deopt slowpath if we decided to not inline (at
            // least) one call target.
            // Otherwise, this could lead to a deopt loop.
            use_deopt_slowpath = false;
            continue;
          }
          uint32_t inlined_index = tree->function_index();
          // Ensure that we only inline if the inlinee's signature is compatible
          // with the call_indirect. In other words, perform the type check that
          // would normally be done dynamically (see above
          // `BuildIndirectCallTargetAndImplicitArg`) statically on the inlined
          // target. This can fail, e.g., because the mapping of feedback back
          // to function indices may produce spurious targets, or because the
          // feedback in the JS heap has been corrupted by a vulnerability.
          if (!InlineTargetIsTypeCompatible(
                  decoder->module_, imm.sig,
                  decoder->module_->functions[inlined_index].sig)) {
            __ Goto(case_blocks[i + 1]);
            continue;
          }

          V<WasmCodePtr> inlined_target =
              __ RelocatableWasmIndirectCallTarget(inlined_index);

          bool is_last_feedback_case = (i == feedback_cases.size() - 1);
          if (use_deopt_slowpath && is_last_feedback_case) {
              DeoptIfNot(decoder, __ WasmCodePtrEqual(target, inlined_target),
                         frame_state);
            } else {
            TSBlock* inline_block = __ NewBlock();
            BranchHint hint =
                is_last_feedback_case ? BranchHint::kTrue : BranchHint::kNone;
            __ Branch({__ WasmCodePtrEqual(target, inlined_target), hint},
                      inline_block, case_blocks[i + 1]);
            __ Bind(inline_block);
          }

          SmallZoneVector<Value, 4> direct_returns(return_count,
                                                   decoder->zone_);
          if (v8_flags.trace_wasm_inlining) {
            PrintF(
                "[function %d%s: Speculatively inlining call_indirect #%d, "
                "case #%zu, to function %d]\n",
                func_index_, mode_ == kRegular ? "" : " (inlined)",
                feedback_slot_, i, inlined_index);
          }
          InlineWasmCall(decoder, inlined_index, imm.sig,
                         static_cast<uint32_t>(i), false, args,
                         direct_returns.data());

          if (__ current_block() != nullptr) {
            // Only add phi inputs and a Goto to {merge} if the current_block is
            // not nullptr. If the current_block is nullptr, it means that the
            // inlined body unconditionally exits early (likely an unconditional
            // trap or throw).
            for (size_t ret = 0; ret < direct_returns.size(); ret++) {
              case_returns[ret].push_back(direct_returns[ret].op);
            }
            __ Goto(merge);
          }
        }

        __ Bind(no_inline_block);
        if (use_deopt_slowpath) {
          // We need this unconditional deopt only for the "instance check",
          // as the last "target check" already uses a `DeoptIfNot` node.
          Deopt(decoder, frame_state);
        } else {
          auto [target, implicit_arg] = BuildIndirectCallTargetAndImplicitArg(
              decoder, index_wordptr, imm);
          SmallZoneVector<Value, 4> indirect_returns(return_count,
                                                     decoder->zone_);
          BuildWasmCall(decoder, imm.sig, target, implicit_arg, args,
                        indirect_returns.data());
          for (size_t ret = 0; ret < indirect_returns.size(); ret++) {
            case_returns[ret].push_back(indirect_returns[ret].op);
          }
          __ Goto(merge);
        }

        __ Bind(merge);
        for (size_t i = 0; i < case_returns.size(); i++) {
          returns[i].op = __ Phi(base::VectorOf(case_returns[i]),
                                 RepresentationFor(imm.sig->GetReturn(i)));
        }

        return;
      }  // should_inline
    }    // v8_flags.wasm_inlining_call_indirect

    // Didn't inline.
    V<WordPtr> index_wordptr = TableAddressToUintPtrOrOOBTrap(
        imm.table_imm.table->address_type, index.op);
    auto [target, implicit_arg] =
        BuildIndirectCallTargetAndImplicitArg(decoder, index_wordptr, imm);
    BuildWasmCall(decoder, imm.sig, target, implicit_arg, args, returns);
  }

  void ReturnCallIndirect(FullDecoder* decoder, const Value& index,
                          const CallIndirectImmediate& imm,
                          const Value args[]) {
    if (v8_flags.wasm_inlining_call_indirect) {
      CHECK(v8_flags.wasm_inlining);
      feedback_slot_++;

      if (should_inline(decoder, feedback_slot_,
                        std::numeric_limits<int>::max())) {
        V<WordPtr> index_wordptr = TableAddressToUintPtrOrOOBTrap(
            imm.table_imm.table->address_type, index.op);

        DCHECK(!shared_);
        constexpr bool kNotShared = false;
        // Load the instance here even though it's only used below, in the hope
        // that load elimination can use it when fetching the target next.
        V<WasmTrustedInstanceData> instance = trusted_instance_data(kNotShared);

        // We are only interested in the target here for comparison against
        // the inlined call target below.
        // In particular, we don't need a dynamic type or null check: If the
        // actual call target (at runtime) is equal to the inlined call target,
        // we know already from the static check on the inlinee (see below) that
        // the inlined code has the right signature.
        constexpr bool kNeedsTypeOrNullCheck = false;
        auto [target, implicit_arg] = BuildIndirectCallTargetAndImplicitArg(
            decoder, index_wordptr, imm, kNeedsTypeOrNullCheck);

        base::Vector<InliningTree*> feedback_cases =
            inlining_decisions_->function_calls()[feedback_slot_];
        constexpr int kSlowpathCase = 1;
        base::SmallVector<TSBlock*, wasm::kMaxPolymorphism + kSlowpathCase>
            case_blocks;
        for (size_t i = 0; i < feedback_cases.size() + kSlowpathCase; i++) {
          case_blocks.push_back(__ NewBlock());
        }
        // Block for the slowpath, i.e., the not-inlined call.
        TSBlock* no_inline_block = case_blocks.back();

        // Wasm functions are semantically closures over the instance, but
        // when we inline a target in the following, we implicitly assume the
        // inlinee instance is the same as the caller's instance.
        // Directly jump to the non-inlined slowpath if that's violated.
        // Note that for `call_ref` this isn't necessary, because the funcref
        // equality check already captures both code and instance equality.
        constexpr BranchHint kUnlikelyCrossInstanceCall = BranchHint::kTrue;
        // Note that the `implicit_arg` can never be a `WasmImportData`,
        // since we don't inline imported functions right now.
        __ Branch({__ TaggedEqual(implicit_arg, instance),
                   kUnlikelyCrossInstanceCall},
                  case_blocks[0], no_inline_block);

        for (size_t i = 0; i < feedback_cases.size(); i++) {
          __ Bind(case_blocks[i]);
          InliningTree* tree = feedback_cases[i];
          if (!tree || !tree->is_inlined()) {
            // Fall through to the next case.
            __ Goto(case_blocks[i + 1]);
            continue;
          }
          uint32_t inlined_index = tree->function_index();
          // Ensure that we only inline if the inlinee's signature is compatible
          // with the call_indirect. In other words, perform the type check that
          // would normally be done dynamically (see above
          // `BuildIndirectCallTargetAndImplicitArg`) statically on the inlined
          // target. This can fail, e.g., because the mapping of feedback back
          // to function indices may produce spurious targets, or because the
          // feedback in the JS heap has been corrupted by a vulnerability.
          if (!InlineTargetIsTypeCompatible(
                  decoder->module_, imm.sig,
                  decoder->module_->functions[inlined_index].sig)) {
            __ Goto(case_blocks[i + 1]);
            continue;
          }

          V<WasmCodePtr> inlined_target =
              __ RelocatableWasmIndirectCallTarget(inlined_index);

          TSBlock* inline_block = __ NewBlock();
          bool is_last_case = (i == feedback_cases.size() - 1);
          BranchHint hint =
              is_last_case ? BranchHint::kTrue : BranchHint::kNone;
          __ Branch({__ WasmCodePtrEqual(target, inlined_target), hint},
                    inline_block, case_blocks[i + 1]);
          __ Bind(inline_block);
          if (v8_flags.trace_wasm_inlining) {
            PrintF(
                "[function %d%s: Speculatively inlining return_call_indirect "
                "#%d, case #%zu, to function %d]\n",
                func_index_, mode_ == kRegular ? "" : " (inlined)",
                feedback_slot_, i, inlined_index);
          }
          InlineWasmCall(decoder, inlined_index, imm.sig,
                         static_cast<uint32_t>(i), true, args, nullptr);

          // An inlined tail call should still terminate execution.
          DCHECK_NULL(__ current_block());
        }

        __ Bind(no_inline_block);
      }  // should_inline
    }    // v8_flags.wasm_inlining_call_indirect

    // Didn't inline.
    V<WordPtr> index_wordptr = TableAddressToUintPtrOrOOBTrap(
        imm.table_imm.table->address_type, index.op);
    auto [target, implicit_arg] =
        BuildIndirectCallTargetAndImplicitArg(decoder, index_wordptr, imm);
    BuildWasmMaybeReturnCall(decoder, imm.sig, target, implicit_arg, args);
  }

  void CallRef(FullDecoder* decoder, const Value& func_ref,
               const FunctionSig* sig, const Value args[], Value returns[]) {
    // TODO(14108): As the slot needs to be aligned with Liftoff, ideally the
    // stack slot index would be provided by the decoder and passed to both
    // Liftoff and Turbofan.
    feedback_slot_++;
    // In case of being unreachable, skip it because it tries to access nodes
    // which might be non-existent (OpIndex::Invalid()) in unreachable code.
    if (__ generating_unreachable_operations()) return;

#if V8_ENABLE_SANDBOX
    uint64_t signature_hash = SignatureHasher::Hash(sig);
#else
    uint64_t signature_hash = 0;
#endif  // V8_ENABLE_SANDBOX

    if (should_inline(decoder, feedback_slot_,
                      std::numeric_limits<int>::max())) {
      DCHECK(!shared_);
      constexpr bool kNotShared = false;
      V<FixedArray> func_refs = LOAD_IMMUTABLE_INSTANCE_FIELD(
          trusted_instance_data(kNotShared), FuncRefs,
          MemoryRepresentation::TaggedPointer());

      size_t return_count = sig->return_count();
      base::Vector<InliningTree*> feedback_cases =
          inlining_decisions_->function_calls()[feedback_slot_];
      std::vector<base::SmallVector<OpIndex, 2>> case_returns(return_count);
      // The slow path is the non-inlined generic `call_ref`,
      // or a deopt node if that is enabled.
      constexpr int kSlowpathCase = 1;
      base::SmallVector<TSBlock*, wasm::kMaxPolymorphism + kSlowpathCase>
          case_blocks;
      for (size_t i = 0; i < feedback_cases.size() + kSlowpathCase; i++) {
        case_blocks.push_back(__ NewBlock());
      }
      TSBlock* merge = __ NewBlock();
      __ Goto(case_blocks[0]);

      bool use_deopt_slowpath = deopts_enabled_;
      for (size_t i = 0; i < feedback_cases.size(); i++) {
        __ Bind(case_blocks[i]);
        InliningTree* tree = feedback_cases[i];
        if (!tree || !tree->is_inlined()) {
          // Fall through to the next case.
          __ Goto(case_blocks[i + 1]);
          // Do not use the deopt slowpath if we decided to not inline (at
          // least) one call target. Otherwise, this could lead to a deopt loop.
          use_deopt_slowpath = false;
          continue;
        }
        uint32_t inlined_index = tree->function_index();
        DCHECK(!decoder->module_->function_is_shared(inlined_index));
        V<Object> inlined_func_ref =
            __ LoadFixedArrayElement(func_refs, inlined_index);

        bool is_last_feedback_case = (i == feedback_cases.size() - 1);
        if (use_deopt_slowpath && is_last_feedback_case) {
          if (inlining_decisions_
                  ->has_non_inlineable_targets()[feedback_slot_]) {
            if (v8_flags.trace_wasm_inlining) {
              PrintF(
                  "[function %d%s: Not emitting deopt slow-path for "
                  "call_ref #%d as feedback contains non-inlineable "
                  "targets]\n",
                  func_index_, mode_ == kRegular ? "" : " (inlined)",
                  feedback_slot_);
            }
            use_deopt_slowpath = false;
          }
        }
        bool emit_deopt = use_deopt_slowpath && is_last_feedback_case;
        if (emit_deopt) {
          V<FrameState> frame_state =
              CreateFrameState(decoder, sig, &func_ref, args);
          if (frame_state.valid()) {
            DeoptIfNot(decoder, __ TaggedEqual(func_ref.op, inlined_func_ref),
                       frame_state);
          } else {
            emit_deopt = false;
            use_deopt_slowpath = false;
          }
        }
        if (!emit_deopt) {
          TSBlock* inline_block = __ NewBlock();
          BranchHint hint =
              is_last_feedback_case ? BranchHint::kTrue : BranchHint::kNone;
          __ Branch({__ TaggedEqual(func_ref.op, inlined_func_ref), hint},
                    inline_block, case_blocks[i + 1]);
          __ Bind(inline_block);
        }

        SmallZoneVector<Value, 4> direct_returns(return_count, decoder->zone_);
        if (v8_flags.trace_wasm_inlining) {
          PrintF(
              "[function %d%s: Speculatively inlining call_ref #%d, case #%zu, "
              "to function %d]\n",
              func_index_, mode_ == kRegular ? "" : " (inlined)",
              feedback_slot_, i, inlined_index);
        }
        InlineWasmCall(decoder, inlined_index, sig, static_cast<uint32_t>(i),
                       false, args, direct_returns.data());

        if (__ current_block() != nullptr) {
          // Only add phi inputs and a Goto to {merge} if the current_block is
          // not nullptr. If the current_block is nullptr, it means that the
          // inlined body unconditionally exits early (likely an unconditional
          // trap or throw).
          for (size_t ret = 0; ret < direct_returns.size(); ret++) {
            case_returns[ret].push_back(direct_returns[ret].op);
          }
          __ Goto(merge);
        }
      }

      if (!use_deopt_slowpath) {
        TSBlock* no_inline_block = case_blocks.back();
        __ Bind(no_inline_block);
        auto [target, implicit_arg] =
            BuildFunctionReferenceTargetAndImplicitArg(
                func_ref.op, func_ref.type, signature_hash);
        SmallZoneVector<Value, 4> ref_returns(return_count, decoder->zone_);
        BuildWasmCall(decoder, sig, target, implicit_arg, args,
                      ref_returns.data());
        for (size_t ret = 0; ret < ref_returns.size(); ret++) {
          case_returns[ret].push_back(ref_returns[ret].op);
        }
        __ Goto(merge);
      }

      __ Bind(merge);
      for (size_t i = 0; i < case_returns.size(); i++) {
        returns[i].op = __ Phi(base::VectorOf(case_returns[i]),
                               RepresentationFor(sig->GetReturn(i)));
      }
    } else {
      auto [target, implicit_arg] = BuildFunctionReferenceTargetAndImplicitArg(
          func_ref.op, func_ref.type, signature_hash);
      BuildWasmCall(decoder, sig, target, implicit_arg, args, returns);
    }
  }

  void ReturnCallRef(FullDecoder* decoder, const Value& func_ref,
                     const FunctionSig* sig, const Value args[]) {
    feedback_slot_++;

#if V8_ENABLE_SANDBOX
    uint64_t signature_hash = SignatureHasher::Hash(sig);
#else
    uint64_t signature_hash = 0;
#endif  // V8_ENABLE_SANDBOX

    if (should_inline(decoder, feedback_slot_,
                      std::numeric_limits<int>::max())) {
      DCHECK(!shared_);
      constexpr bool kNotShared = false;
      V<FixedArray> func_refs = LOAD_IMMUTABLE_INSTANCE_FIELD(
          trusted_instance_data(kNotShared), FuncRefs,
          MemoryRepresentation::TaggedPointer());

      base::Vector<InliningTree*> feedback_cases =
          inlining_decisions_->function_calls()[feedback_slot_];
      constexpr int kSlowpathCase = 1;
      base::SmallVector<TSBlock*, wasm::kMaxPolymorphism + kSlowpathCase>
          case_blocks;

      for (size_t i = 0; i < feedback_cases.size() + kSlowpathCase; i++) {
        case_blocks.push_back(__ NewBlock());
      }
      __ Goto(case_blocks[0]);

      for (size_t i = 0; i < feedback_cases.size(); i++) {
        __ Bind(case_blocks[i]);
        InliningTree* tree = feedback_cases[i];
        if (!tree || !tree->is_inlined()) {
          // Fall through to the next case.
          __ Goto(case_blocks[i + 1]);
          continue;
        }
        uint32_t inlined_index = tree->function_index();
        DCHECK(!decoder->module_->function_is_shared(inlined_index));
        V<Object> inlined_func_ref =
            __ LoadFixedArrayElement(func_refs, inlined_index);

        TSBlock* inline_block = __ NewBlock();
        bool is_last_case = (i == feedback_cases.size() - 1);
        BranchHint hint = is_last_case ? BranchHint::kTrue : BranchHint::kNone;
        __ Branch({__ TaggedEqual(func_ref.op, inlined_func_ref), hint},
                  inline_block, case_blocks[i + 1]);
        __ Bind(inline_block);
        if (v8_flags.trace_wasm_inlining) {
          PrintF(
              "[function %d%s: Speculatively inlining return_call_ref #%d, "
              "case #%zu, to function %d]\n",
              func_index_, mode_ == kRegular ? "" : " (inlined)",
              feedback_slot_, i, inlined_index);
        }
        InlineWasmCall(decoder, inlined_index, sig, static_cast<uint32_t>(i),
                       true, args, nullptr);

        // An inlined tail call should still terminate execution.
        DCHECK_NULL(__ current_block());
      }

      TSBlock* no_inline_block = case_blocks.back();
      __ Bind(no_inline_block);
    }
    auto [target, implicit_arg] = BuildFunctionReferenceTargetAndImplicitArg(
        func_ref.op, func_ref.type, signature_hash);
    BuildWasmMaybeReturnCall(decoder, sig, target, implicit_arg, args);
  }

  void BrOnNull(FullDecoder* decoder, const Value& ref_object, uint32_t depth,
                bool pass_null_along_branch, Value* result_on_fallthrough) {
    result_on_fallthrough->op = ref_object.op;
    IF (UNLIKELY(__ IsNull(ref_object.op, ref_object.type))) {
      int drop_values = pass_null_along_branch ? 0 : 1;
      BrOrRet(decoder, depth, drop_values);
    }
  }

  void BrOnNonNull(FullDecoder* decoder, const Value& ref_object, Value* result,
                   uint32_t depth, bool /* drop_null_on_fallthrough */) {
    result->op = ref_object.op;
    IF_NOT (UNLIKELY(__ IsNull(ref_object.op, ref_object.type))) {
      BrOrRet(decoder, depth);
    }
  }

  void SimdOp(FullDecoder* decoder, WasmOpcode opcode, const Value* args,
              Value* result) {
    switch (opcode) {
#define HANDLE_BINARY_OPCODE(kind)                                            \
  case kExpr##kind:                                                           \
    result->op =                                                              \
        __ Simd128Binop(V<compiler::turboshaft::Simd128>::Cast(args[0].op
```