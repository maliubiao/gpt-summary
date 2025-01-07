Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code seems to be related to WebAssembly (Wasm) and string/array manipulation within the V8 JavaScript engine.

Here's a plan to address the request:

1. **Identify the main purpose of the code:** Look for keywords and function names that indicate the core functionalities. The code includes functions like `ArraySet`, `ArrayGet`, `ArrayFill`, `StringNewWtf8`, `StringEncodeWtf8`, etc. This suggests it's about interfacing Wasm with V8's internal representation of arrays and strings.
2. **List the identified functionalities:**  Create a bulleted list of the operations the code performs.
3. **Check for Torque specific syntax:** Look for the `.tq` file extension mentioned in the prompt. If the code used `.tq` syntax (which it doesn't), it would indicate a different code generation mechanism.
4. **Determine JavaScript relevance and provide examples:** Analyze if the operations have direct counterparts or relate to JavaScript features. If so, provide simple JavaScript code examples to illustrate the connection.
5. **Look for code logic and provide examples:**  Identify functions with conditional logic or loops. Provide hypothetical inputs and outputs to demonstrate the function's behavior. Focus on the `ArrayCopy` function as it has clear loop-based logic.
6. **Identify common programming errors:** Think about potential issues users might encounter when using related JavaScript or Wasm features. Examples could include out-of-bounds access or type errors.
7. **Summarize the functionality (as part 7/12):** Concisely describe the role of this specific code segment within the broader context of Wasm and V8.

**Step-by-step execution:**

1. **Main Purpose:** The code provides implementations for various Wasm instructions related to array and string manipulation, bridging the gap between the Wasm execution environment and V8's object model.

2. **Functionalities:**
    * Array manipulation: Getting, setting, filling, copying, and creating arrays.
    * String manipulation: Creating strings from different encodings (UTF-8, UTF-16), measuring string length, encoding strings, concatenating strings, comparing strings, checking for USV sequences, converting strings to byte arrays, getting code units and code points, and creating string iterators.
    * Reference operations: Testing and casting references.
    * I31 operations: Handling 31-bit integers.

3. **Torque Check:** The provided code is C++ (`.cc`), not Torque (`.tq`).

4. **JavaScript Relevance and Examples:**
    * **Array:**  Wasm array operations are directly related to JavaScript `Array` objects.
      ```javascript
      const arr = [1, 2, 3];
      const value = arr[0]; // ArrayGet equivalent
      arr[1] = 4;          // ArraySet equivalent
      arr.fill(0);        // ArrayFill equivalent
      const newArr = [...arr]; // ArrayCopy conceptually similar
      ```
    * **String:** Wasm string operations are related to JavaScript `String` objects.
      ```javascript
      const str = "hello";
      const len = str.length; // StringMeasure equivalent
      const charCode = str.charCodeAt(0); // StringViewWtf16GetCodeUnit equivalent
      const newStr = str + " world"; // StringConcat equivalent
      ```

5. **Code Logic and Examples (ArrayCopy):**
    * **Scenario 1 (forward copy):**
        * `src_array`: `[10, 20, 30]`
        * `dst_array`: `[0, 0, 0]`
        * `src_index`: 0
        * `dst_index`: 0
        * `length`: 3
        * `Output`: `dst_array` becomes `[10, 20, 30]`
    * **Scenario 2 (backward copy):**
        * `src_array`: `[10, 20, 30]`
        * `dst_array`: `[0, 0, 0]`
        * `src_index`: 2
        * `dst_index`: 2
        * `length`: 3
        * `Output`: `dst_array` becomes `[0, 0, 10]` (Note: potential overlap issues if src and dest are the same)

6. **Common Programming Errors:**
    * **Array:**
        * `Index out of bounds`: Trying to access an array element with an invalid index.
          ```javascript
          const arr = [1, 2, 3];
          console.log(arr[5]); // undefined, but in Wasm might lead to a trap
          ```
    * **String:**
        * `String index out of range`: Similar to array indexing.
          ```javascript
          const str = "hello";
          console.log(str.charCodeAt(10)); // NaN
          ```
    * **Type errors:** Passing the wrong type to a function. While less directly visible in this C++ code, the type checks imply potential errors if Wasm provides incorrect types.

7. **Summary (Part 7/12):** This part of the V8 source code for Turboshaft (the Wasm compiler) defines the interface and implementation for various WebAssembly instructions that deal with array and string manipulation. It handles operations like creating, accessing, and modifying array and string data, bridging the gap between Wasm's abstract memory model and V8's internal object representations. As part 7 of 12, it likely focuses on a specific subset of Wasm features, with other parts covering different aspects of the Wasm compilation and execution pipeline.
`v8/src/wasm/turboshaft-graph-interface.cc` 是 V8 引擎中 Turboshaft 编译器的图形接口实现。它提供了一组 C++ 函数，用于将 WebAssembly (Wasm) 的操作转换为 Turboshaft 图形表示。这个图形表示是 Turboshaft 编译器进行后续优化和代码生成的基础。

**功能归纳:**

这个文件的主要功能是**为 Turboshaft 编译器提供 Wasm 指令到 Turboshaft 图形节点的映射和实现**。 具体来说，它定义了如何将各种 Wasm 操作（如数组操作、字符串操作、引用操作、I31 操作等）转换为 Turboshaft 图中的相应节点。

**详细功能列表:**

* **数组操作:**
    * `ArrayGet`: 从数组中获取指定索引的元素。
    * `ArraySet`: 设置数组中指定索引的元素。
    * `ArrayLen`: 获取数组的长度。
    * `ArrayCopy`: 将数组的一部分复制到另一个数组。
    * `ArrayFill`: 用一个给定的值填充数组的指定范围。
    * `ArrayNewFixed`: 创建一个具有固定大小和初始元素的数组。
    * `ArrayNewSegment`: 基于数据段或元素段创建一个新的数组。
    * `ArrayInitSegment`: 将数据段或元素段的内容复制到数组中。
* **引用操作:**
    * `RefI31`: 将 32 位整数转换为 i31ref 类型。
    * `I31GetS`: 从 i31ref 类型中提取有符号的 31 位整数。
    * `I31GetU`: 从 i31ref 类型中提取无符号的 31 位整数。
    * `RefTest`: 检查一个对象是否是指定的引用类型。
    * `RefTestAbstract`: 检查一个对象是否是指定的堆类型。
    * `RefCast`: 将一个对象转换为指定的引用类型。
    * `RefCastAbstract`: 将一个对象转换为指定的堆类型。
    * `BrOnCast`: 如果类型转换成功则跳转，否则继续执行。
    * `BrOnCastAbstract`: 如果堆类型转换成功则跳转，否则继续执行。
    * `BrOnCastFail`: 如果类型转换失败则跳转，否则继续执行。
    * `BrOnCastFailAbstract`: 如果堆类型转换失败则跳转，否则继续执行。
* **字符串操作:**
    * `StringNewWtf8`: 从内存中的 UTF-8 编码数据创建字符串。
    * `StringNewWtf8Array`: 从字节数组创建 UTF-8 字符串。
    * `StringNewWtf16`: 从内存中的 UTF-16 编码数据创建字符串。
    * `StringNewWtf16Array`: 从 16 位整数数组创建 UTF-16 字符串。
    * `StringConst`: 创建一个常量字符串。
    * `StringMeasureWtf8`: 测量 UTF-8 字符串的字节长度或代码点长度。
    * `StringMeasureWtf16`: 测量 UTF-16 字符串的长度（以代码单元计）。
    * `StringEncodeWtf8`: 将字符串编码为 UTF-8 并存储到内存中。
    * `StringEncodeWtf8Array`: 将字符串编码为 UTF-8 并存储到字节数组中。
    * `StringEncodeWtf16`: 将字符串编码为 UTF-16 并存储到内存中。
    * `StringEncodeWtf16Array`: 将字符串编码为 UTF-16 并存储到 16 位整数数组中。
    * `StringConcat`: 连接两个字符串。
    * `StringEq`: 比较两个字符串是否相等。
    * `StringIsUSVSequence`: 检查字符串是否是 USV 序列。
    * `StringAsWtf8`: 将字符串转换为 UTF-8 字节数组。
    * `StringViewWtf8Advance`: 在 UTF-8 字符串视图中前进指定数量的字节。
    * `StringViewWtf8Encode`: 将 UTF-8 字符串视图的内容编码到内存中。
    * `StringViewWtf8Slice`: 从 UTF-8 字符串视图中提取子字符串。
    * `StringAsWtf16`: 将字符串转换为 UTF-16 数组。
    * `StringViewWtf16GetCodeUnit`: 获取 UTF-16 字符串视图中指定位置的代码单元。
    * `StringCodePointAt`: 获取字符串中指定位置的代码点。
    * `StringViewWtf16Encode`: 将 UTF-16 字符串视图的内容编码到内存中。
    * `StringViewWtf16Slice`: 从 UTF-16 字符串视图中提取子字符串。
    * `StringAsIter`: 将字符串转换为迭代器。

**关于文件类型:**

`v8/src/wasm/turboshaft-graph-interface.cc` 以 `.cc` 结尾，表明它是一个 **C++ 源文件**。因此，它不是一个 Torque 源文件。

**与 JavaScript 的关系和示例:**

这些 Wasm 操作在 JavaScript 中都有对应的功能：

* **数组操作:** Wasm 的数组操作直接对应于 JavaScript 的 `Array` 对象和其方法。
    ```javascript
    const arr = [1, 2, 3];
    const value = arr[0]; // 对应 Wasm 的 ArrayGet
    arr[1] = 4;          // 对应 Wasm 的 ArraySet
    const len = arr.length; // 对应 Wasm 的 ArrayLen
    const newArr = arr.slice(0, 2); // 对应 Wasm 的 ArrayCopy
    arr.fill(0);        // 对应 Wasm 的 ArrayFill
    ```
* **字符串操作:** Wasm 的字符串操作对应于 JavaScript 的 `String` 对象和其方法。
    ```javascript
    const str = "hello";
    const len = str.length; // 对应 Wasm 的 StringMeasureWtf16
    const charCode = str.charCodeAt(0); // 对应 Wasm 的 StringViewWtf16GetCodeUnit
    const newStr = str + " world"; // 对应 Wasm 的 StringConcat
    const isEqual = str === "hello"; // 对应 Wasm 的 StringEq
    const utf8Encoder = new TextEncoder();
    const utf8Bytes = utf8Encoder.encode(str); // 对应 Wasm 的 StringAsWtf8
    ```
* **引用操作:**  Wasm 的引用操作 (如 `instanceof` 等)  在 JavaScript 中也有类似的概念，但 Wasm 的引用类型系统更加精细。

**代码逻辑推理和示例 (ArrayCopy):**

让我们以 `ArrayCopy` 函数为例，进行代码逻辑推理。

**假设输入:**

* `src_array`: 一个包含 `[10, 20, 30, 40, 50]` 的 Wasm 数组。
* `dst_array`: 一个初始为空或包含其他数据的 Wasm 数组，例如 `[0, 0, 0, 0, 0]`。
* `src_index`:  `1`
* `dst_index`:  `2`
* `length`:    `3`
* `element_type`: 数组元素的类型 (例如，`i32`)。

**推断的执行过程:**

根据 `ArrayCopy` 函数中的 `IF (Uint32LessThan(dst_index.op, src_index.op))` 条件，如果目标索引小于源索引，则进行反向复制；否则进行正向复制。

在本例中，`dst_index (2)` 大于 `src_index (1)`，所以会进入 `ELSE` 分支，执行正向复制。

循环会执行 `length` (3) 次：

1. 从 `src_array` 的索引 `1` (值 `20`) 获取值，并设置到 `dst_array` 的索引 `2`。 `dst_array` 变为 `[0, 0, 20, 0, 0]`。
2. 从 `src_array` 的索引 `2` (值 `30`) 获取值，并设置到 `dst_array` 的索引 `3`。 `dst_array` 变为 `[0, 0, 20, 30, 0]`。
3. 从 `src_array` 的索引 `3` (值 `40`) 获取值，并设置到 `dst_array` 的索引 `4`。 `dst_array` 变为 `[0, 0, 20, 30, 40]`。

**预期输出:**

`dst_array` 的最终状态将是 `[0, 0, 20, 30, 40]`。

**用户常见的编程错误:**

在涉及到数组和字符串操作时，用户常犯的编程错误包括：

* **数组索引越界:** 尝试访问或修改数组中不存在的索引。
    ```javascript
    const arr = [1, 2, 3];
    console.log(arr[3]); // 错误：索引超出范围
    ```
* **字符串索引越界:** 尝试访问字符串中不存在的字符索引。
    ```javascript
    const str = "hello";
    console.log(str[5]); // 错误：索引超出范围
    ```
* **类型不匹配:** 将不兼容的类型赋值给数组元素或传递给字符串操作。
    ```javascript
    const arr = [1, 2, 3];
    arr[0] = "hello"; // 如果 Wasm 数组是 i32 类型，这将是一个类型错误
    ```
* **字符串编码问题:** 在处理不同编码的字符串时出现错误，例如将 UTF-8 字符串误认为 UTF-16。
* **长度计算错误:** 在进行复制或填充操作时，错误地计算长度，导致数据丢失或越界。

**总结 (作为第 7 部分):**

作为 12 个部分中的第 7 部分，`v8/src/wasm/turboshaft-graph-interface.cc` 专注于 **实现 Wasm 中关于数组、字符串和引用操作的指令到 Turboshaft 图的转换**。  它构建了 Wasm 代码到 Turboshaft 中间表示的关键部分，为后续的优化和代码生成奠定了基础。 考虑到它处理的是数组和字符串这类核心数据结构的操作，可以推测之前的几个部分可能涉及了更基础的 Wasm 指令（如算术运算、控制流等），而后续的部分可能会涉及更高级的特性（如函数调用、内存管理、多线程等）以及优化和代码生成过程。

Prompt: 
```
这是目录为v8/src/wasm/turboshaft-graph-interface.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/turboshaft-graph-interface.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共12部分，请归纳一下它的功能

"""
     __ ArraySet(dst_array, dst_index_loop, value, element_type);

            IF_NOT (__ Uint32LessThan(src_index.op, src_index_loop)) BREAK;

            src_index_loop = __ Word32Sub(src_index_loop, 1);
            dst_index_loop = __ Word32Sub(dst_index_loop, 1);
          }
        } ELSE {
          ScopedVar<Word32> src_index_loop(this, src_index.op);
          ScopedVar<Word32> dst_index_loop(this, dst_index.op);

          WHILE(__ Word32Constant(1)) {
            V<Any> value = __ ArrayGet(src_array, src_index_loop,
                                       src_imm.array_type, true);
            __ ArraySet(dst_array, dst_index_loop, value, element_type);

            IF_NOT (__ Uint32LessThan(src_index_loop, src_end_index)) BREAK;

            src_index_loop = __ Word32Add(src_index_loop, 1);
            dst_index_loop = __ Word32Add(dst_index_loop, 1);
          }
        }
      }
    }
  }

  void ArrayFill(FullDecoder* decoder, ArrayIndexImmediate& imm,
                 const Value& array, const Value& index, const Value& value,
                 const Value& length) {
    const bool emit_write_barrier =
        imm.array_type->element_type().is_reference();
    auto array_value = V<WasmArrayNullable>::Cast(array.op);
    V<WasmArray> array_not_null = BoundsCheckArrayWithLength(
        array_value, index.op, length.op,
        array.type.is_nullable() ? compiler::kWithNullCheck
                                 : compiler::kWithoutNullCheck);
    ArrayFillImpl(array_not_null, V<Word32>::Cast(index.op),
                  V<Any>::Cast(value.op), V<Word32>::Cast(length.op),
                  imm.array_type, emit_write_barrier);
  }

  void ArrayNewFixed(FullDecoder* decoder, const ArrayIndexImmediate& array_imm,
                     const IndexImmediate& length_imm, const Value elements[],
                     Value* result) {
    const wasm::ArrayType* type = array_imm.array_type;
    wasm::ValueType element_type = type->element_type();
    int element_count = length_imm.index;
    // Initialize the array header.
    bool shared = decoder->module_->type(array_imm.index).is_shared;
    V<Map> rtt = __ RttCanon(managed_object_maps(shared), array_imm.index);
    V<WasmArray> array = __ WasmAllocateArray(rtt, element_count, type);
    // Initialize all elements.
    for (int i = 0; i < element_count; i++) {
      __ ArraySet(array, __ Word32Constant(i), elements[i].op, element_type);
    }
    result->op = array;
  }

  void ArrayNewSegment(FullDecoder* decoder,
                       const ArrayIndexImmediate& array_imm,
                       const IndexImmediate& segment_imm, const Value& offset,
                       const Value& length, Value* result) {
    bool is_element = array_imm.array_type->element_type().is_reference();
    // TODO(14616): Data segments aren't available during streaming compilation.
    // Discussion: github.com/WebAssembly/shared-everything-threads/issues/83
    bool segment_is_shared =
        decoder->enabled_.has_shared() &&
        (is_element
             ? decoder->module_->elem_segments[segment_imm.index].shared
             : decoder->module_->data_segments[segment_imm.index].shared);
    // TODO(14616): Add DCHECK that array sharedness is equal to `shared`?
    V<WasmArray> result_value =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmArrayNewSegment>(
            decoder,
            {__ Word32Constant(segment_imm.index), offset.op, length.op,
             __ SmiConstant(Smi::FromInt(is_element ? 1 : 0)),
             __ SmiConstant(Smi::FromInt(!shared_ && segment_is_shared)),
             __ RttCanon(managed_object_maps(segment_is_shared),
                         array_imm.index)});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void ArrayInitSegment(FullDecoder* decoder,
                        const ArrayIndexImmediate& array_imm,
                        const IndexImmediate& segment_imm, const Value& array,
                        const Value& array_index, const Value& segment_offset,
                        const Value& length) {
    bool is_element = array_imm.array_type->element_type().is_reference();
    // TODO(14616): Segments aren't available during streaming compilation.
    bool segment_is_shared =
        decoder->enabled_.has_shared() &&
        (is_element
             ? decoder->module_->elem_segments[segment_imm.index].shared
             : decoder->module_->data_segments[segment_imm.index].shared);
    // TODO(14616): Is this too restrictive?
    DCHECK_EQ(segment_is_shared,
              decoder->module_->type(array_imm.index).is_shared);
    CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmArrayInitSegment>(
        decoder,
        {array_index.op, segment_offset.op, length.op,
         __ SmiConstant(Smi::FromInt(segment_imm.index)),
         __ SmiConstant(Smi::FromInt(is_element ? 1 : 0)),
         __ SmiConstant(Smi::FromInt((!shared_ && segment_is_shared) ? 1 : 0)),
         array.op});
  }

  void RefI31(FullDecoder* decoder, const Value& input, Value* result) {
    if constexpr (SmiValuesAre31Bits()) {
      V<Word32> shifted =
          __ Word32ShiftLeft(input.op, kSmiTagSize + kSmiShiftSize);
      if constexpr (Is64()) {
        // The uppermost bits don't matter.
        result->op = __ BitcastWord32ToWord64(shifted);
      } else {
        result->op = shifted;
      }
    } else {
      // Set the topmost bit to sign-extend the second bit. This way,
      // interpretation in JS (if this value escapes there) will be the same as
      // i31.get_s.
      V<WordPtr> input_wordptr = __ ChangeUint32ToUintPtr(input.op);
      result->op = __ WordPtrShiftRightArithmetic(
          __ WordPtrShiftLeft(input_wordptr, kSmiShiftSize + kSmiTagSize + 1),
          1);
    }
    result->op = __ AnnotateWasmType(__ BitcastWordPtrToSmi(result->op),
                                     kWasmI31Ref.AsNonNull());
  }

  void I31GetS(FullDecoder* decoder, const Value& input, Value* result) {
    V<Object> input_non_null = NullCheck(input);
    if constexpr (SmiValuesAre31Bits()) {
      result->op = __ Word32ShiftRightArithmeticShiftOutZeros(
          __ TruncateWordPtrToWord32(__ BitcastTaggedToWordPtr(input_non_null)),
          kSmiTagSize + kSmiShiftSize);
    } else {
      // Topmost bit is already sign-extended.
      result->op = __ TruncateWordPtrToWord32(
          __ WordPtrShiftRightArithmeticShiftOutZeros(
              __ BitcastTaggedToWordPtr(input_non_null),
              kSmiTagSize + kSmiShiftSize));
    }
  }

  void I31GetU(FullDecoder* decoder, const Value& input, Value* result) {
    V<Object> input_non_null = NullCheck(input);
    if constexpr (SmiValuesAre31Bits()) {
      result->op = __ Word32ShiftRightLogical(
          __ TruncateWordPtrToWord32(__ BitcastTaggedToWordPtr(input_non_null)),
          kSmiTagSize + kSmiShiftSize);
    } else {
      // Topmost bit is sign-extended, remove it.
      result->op = __ TruncateWordPtrToWord32(__ WordPtrShiftRightLogical(
          __ WordPtrShiftLeft(__ BitcastTaggedToWordPtr(input_non_null), 1),
          kSmiTagSize + kSmiShiftSize + 1));
    }
  }

  void RefTest(FullDecoder* decoder, ModuleTypeIndex ref_index,
               const Value& object, Value* result, bool null_succeeds) {
    bool shared = decoder->module_->type(ref_index).is_shared;
    V<Map> rtt = __ RttCanon(managed_object_maps(shared), ref_index);
    compiler::WasmTypeCheckConfig config{
        object.type, ValueType::RefMaybeNull(
                         ref_index, null_succeeds ? kNullable : kNonNullable)};
    result->op = __ WasmTypeCheck(object.op, rtt, config);
  }

  void RefTestAbstract(FullDecoder* decoder, const Value& object, HeapType type,
                       Value* result, bool null_succeeds) {
    compiler::WasmTypeCheckConfig config{
        object.type, ValueType::RefMaybeNull(
                         type, null_succeeds ? kNullable : kNonNullable)};
    V<Map> rtt = OpIndex::Invalid();
    result->op = __ WasmTypeCheck(object.op, rtt, config);
  }

  void RefCast(FullDecoder* decoder, ModuleTypeIndex ref_index,
               const Value& object, Value* result, bool null_succeeds) {
    if (v8_flags.experimental_wasm_assume_ref_cast_succeeds) {
      // TODO(14108): Implement type guards.
      Forward(decoder, object, result);
      return;
    }
    bool shared = decoder->module_->type(ref_index).is_shared;
    V<Map> rtt = __ RttCanon(managed_object_maps(shared), ref_index);
    DCHECK_EQ(result->type.is_nullable(), null_succeeds);
    compiler::WasmTypeCheckConfig config{object.type, result->type};
    result->op = __ WasmTypeCast(object.op, rtt, config);
  }

  void RefCastAbstract(FullDecoder* decoder, const Value& object, HeapType type,
                       Value* result, bool null_succeeds) {
    if (v8_flags.experimental_wasm_assume_ref_cast_succeeds) {
      // TODO(14108): Implement type guards.
      Forward(decoder, object, result);
      return;
    }
    // TODO(jkummerow): {type} is redundant.
    DCHECK_IMPLIES(null_succeeds, result->type.is_nullable());
    DCHECK_EQ(type, result->type.heap_type());
    compiler::WasmTypeCheckConfig config{
        object.type, ValueType::RefMaybeNull(
                         type, null_succeeds ? kNullable : kNonNullable)};
    V<Map> rtt = OpIndex::Invalid();
    result->op = __ WasmTypeCast(object.op, rtt, config);
  }

  void BrOnCast(FullDecoder* decoder, ModuleTypeIndex ref_index,
                const Value& object, Value* value_on_branch, uint32_t br_depth,
                bool null_succeeds) {
    bool shared = decoder->module_->type(ref_index).is_shared;
    V<Map> rtt = __ RttCanon(managed_object_maps(shared), ref_index);
    compiler::WasmTypeCheckConfig config{
        object.type, ValueType::RefMaybeNull(
                         ref_index, null_succeeds ? kNullable : kNonNullable)};
    return BrOnCastImpl(decoder, rtt, config, object, value_on_branch, br_depth,
                        null_succeeds);
  }

  void BrOnCastAbstract(FullDecoder* decoder, const Value& object,
                        HeapType type, Value* value_on_branch,
                        uint32_t br_depth, bool null_succeeds) {
    V<Map> rtt = OpIndex::Invalid();
    compiler::WasmTypeCheckConfig config{
        object.type, ValueType::RefMaybeNull(
                         type, null_succeeds ? kNullable : kNonNullable)};
    return BrOnCastImpl(decoder, rtt, config, object, value_on_branch, br_depth,
                        null_succeeds);
  }

  void BrOnCastFail(FullDecoder* decoder, ModuleTypeIndex ref_index,
                    const Value& object, Value* value_on_fallthrough,
                    uint32_t br_depth, bool null_succeeds) {
    bool shared = decoder->module_->type(ref_index).is_shared;
    V<Map> rtt = __ RttCanon(managed_object_maps(shared), ref_index);
    compiler::WasmTypeCheckConfig config{
        object.type, ValueType::RefMaybeNull(
                         ref_index, null_succeeds ? kNullable : kNonNullable)};
    return BrOnCastFailImpl(decoder, rtt, config, object, value_on_fallthrough,
                            br_depth, null_succeeds);
  }

  void BrOnCastFailAbstract(FullDecoder* decoder, const Value& object,
                            HeapType type, Value* value_on_fallthrough,
                            uint32_t br_depth, bool null_succeeds) {
    V<Map> rtt = OpIndex::Invalid();
    compiler::WasmTypeCheckConfig config{
        object.type, ValueType::RefMaybeNull(
                         type, null_succeeds ? kNullable : kNonNullable)};
    return BrOnCastFailImpl(decoder, rtt, config, object, value_on_fallthrough,
                            br_depth, null_succeeds);
  }

  void StringNewWtf8(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                     const unibrow::Utf8Variant variant, const Value& offset,
                     const Value& size, Value* result) {
    V<Word32> memory = __ Word32Constant(imm.index);
    V<Smi> variant_smi =
        __ SmiConstant(Smi::FromInt(static_cast<int>(variant)));
    V<WordPtr> index =
        MemoryAddressToUintPtrOrOOBTrap(imm.memory->address_type, offset.op);
    V<WasmStringRefNullable> result_value =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmStringNewWtf8>(
            decoder, {index, size.op, memory, variant_smi});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  // TODO(jkummerow): This check would be more elegant if we made
  // {ArrayNewSegment} a high-level node that's lowered later.
  // Returns the call on success, nullptr otherwise (like `TryCast`).
  const CallOp* IsArrayNewSegment(V<Object> array) {
    DCHECK_IMPLIES(!array.valid(), __ generating_unreachable_operations());
    if (__ generating_unreachable_operations()) return nullptr;
    if (const WasmTypeAnnotationOp* annotation =
            __ output_graph().Get(array).TryCast<WasmTypeAnnotationOp>()) {
      array = annotation->value();
    }
    if (const DidntThrowOp* didnt_throw =
            __ output_graph().Get(array).TryCast<DidntThrowOp>()) {
      array = didnt_throw->throwing_operation();
    }
    const CallOp* call = __ output_graph().Get(array).TryCast<CallOp>();
    if (call == nullptr) return nullptr;
    uint64_t stub_id{};
    if (!OperationMatcher(__ output_graph())
             .MatchWasmStubCallConstant(call->callee(), &stub_id)) {
      return nullptr;
    }
    DCHECK_LT(stub_id, static_cast<uint64_t>(Builtin::kFirstBytecodeHandler));
    if (stub_id == static_cast<uint64_t>(Builtin::kWasmArrayNewSegment)) {
      return call;
    }
    return nullptr;
  }

  V<HeapObject> StringNewWtf8ArrayImpl(FullDecoder* decoder,
                                       const unibrow::Utf8Variant variant,
                                       const Value& array, const Value& start,
                                       const Value& end,
                                       ValueType result_type) {
    // Special case: shortcut a sequence "array from data segment" + "string
    // from wtf8 array" to directly create a string from the segment.
    V<internal::UnionOf<String, WasmNull, Null>> call;
    if (const CallOp* array_new = IsArrayNewSegment(array.op)) {
      // We can only pass 3 untagged parameters to the builtin (on 32-bit
      // platforms). The segment index is easy to tag: if it validated, it must
      // be in Smi range.
      OpIndex segment_index = array_new->input(1);
      int32_t index_val;
      OperationMatcher(__ output_graph())
          .MatchIntegralWord32Constant(segment_index, &index_val);
      V<Smi> index_smi = __ SmiConstant(Smi::FromInt(index_val));
      // Arbitrary choice for the second tagged parameter: the segment offset.
      OpIndex segment_offset = array_new->input(2);
      __ TrapIfNot(
          __ Uint32LessThan(segment_offset, __ Word32Constant(Smi::kMaxValue)),
          OpIndex::Invalid(), TrapId::kTrapDataSegmentOutOfBounds);
      V<Smi> offset_smi = __ TagSmi(segment_offset);
      OpIndex segment_length = array_new->input(3);
      V<Smi> variant_smi =
          __ SmiConstant(Smi::FromInt(static_cast<int32_t>(variant)));
      call = CallBuiltinThroughJumptable<
          BuiltinCallDescriptor::WasmStringFromDataSegment>(
          decoder, {segment_length, start.op, end.op, index_smi, offset_smi,
                    variant_smi});
    } else {
      // Regular path if the shortcut wasn't taken.
      call = CallBuiltinThroughJumptable<
          BuiltinCallDescriptor::WasmStringNewWtf8Array>(
          decoder,
          {start.op, end.op, V<WasmArray>::Cast(NullCheck(array)),
           __ SmiConstant(Smi::FromInt(static_cast<int32_t>(variant)))});
    }
    DCHECK_IMPLIES(variant == unibrow::Utf8Variant::kUtf8NoTrap,
                   result_type.is_nullable());
    // The builtin returns a WasmNull for kUtf8NoTrap, so nullable values in
    // combination with extern strings are not supported.
    DCHECK_NE(result_type, wasm::kWasmExternRef);
    return AnnotateAsString(call, result_type);
  }

  void StringNewWtf8Array(FullDecoder* decoder,
                          const unibrow::Utf8Variant variant,
                          const Value& array, const Value& start,
                          const Value& end, Value* result) {
    result->op = StringNewWtf8ArrayImpl(decoder, variant, array, start, end,
                                        result->type);
  }

  void StringNewWtf16(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                      const Value& offset, const Value& size, Value* result) {
    V<WordPtr> index =
        MemoryAddressToUintPtrOrOOBTrap(imm.memory->address_type, offset.op);
    V<String> result_value =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmStringNewWtf16>(
            decoder, {__ Word32Constant(imm.index), index, size.op});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void StringNewWtf16Array(FullDecoder* decoder, const Value& array,
                           const Value& start, const Value& end,
                           Value* result) {
    V<String> result_value = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringNewWtf16Array>(
        decoder, {V<WasmArray>::Cast(NullCheck(array)), start.op, end.op});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void StringConst(FullDecoder* decoder, const StringConstImmediate& imm,
                   Value* result) {
    V<String> result_value =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmStringConst>(
            decoder, {__ Word32Constant(imm.index)});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void StringMeasureWtf8(FullDecoder* decoder,
                         const unibrow::Utf8Variant variant, const Value& str,
                         Value* result) {
    result->op = StringMeasureWtf8Impl(decoder, variant,
                                       V<String>::Cast(NullCheck(str)));
  }

  OpIndex StringMeasureWtf8Impl(FullDecoder* decoder,
                                const unibrow::Utf8Variant variant,
                                V<String> string) {
    switch (variant) {
      case unibrow::Utf8Variant::kUtf8:
        return CallBuiltinThroughJumptable<
            BuiltinCallDescriptor::WasmStringMeasureUtf8>(decoder, {string});
      case unibrow::Utf8Variant::kLossyUtf8:
      case unibrow::Utf8Variant::kWtf8:
        return CallBuiltinThroughJumptable<
            BuiltinCallDescriptor::WasmStringMeasureWtf8>(decoder, {string});
      case unibrow::Utf8Variant::kUtf8NoTrap:
        UNREACHABLE();
    }
  }

  V<Word32> LoadStringLength(V<Object> string) {
    return __ template LoadField<Word32>(
        string, compiler::AccessBuilder::ForStringLength());
  }

  void StringMeasureWtf16(FullDecoder* decoder, const Value& str,
                          Value* result) {
    result->op = LoadStringLength(NullCheck(str));
  }

  void StringEncodeWtf8(FullDecoder* decoder,
                        const MemoryIndexImmediate& memory,
                        const unibrow::Utf8Variant variant, const Value& str,
                        const Value& offset, Value* result) {
    V<WordPtr> address =
        MemoryAddressToUintPtrOrOOBTrap(memory.memory->address_type, offset.op);
    V<Word32> mem_index = __ Word32Constant(memory.index);
    V<Word32> utf8 = __ Word32Constant(static_cast<int32_t>(variant));
    result->op = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringEncodeWtf8>(
        decoder, {address, mem_index, utf8, V<String>::Cast(NullCheck(str))});
  }

  void StringEncodeWtf8Array(FullDecoder* decoder,
                             const unibrow::Utf8Variant variant,
                             const Value& str, const Value& array,
                             const Value& start, Value* result) {
    result->op = StringEncodeWtf8ArrayImpl(
        decoder, variant, V<String>::Cast(NullCheck(str)),
        V<WasmArray>::Cast(NullCheck(array)), start.op);
  }

  OpIndex StringEncodeWtf8ArrayImpl(FullDecoder* decoder,
                                    const unibrow::Utf8Variant variant,
                                    V<String> str, V<WasmArray> array,
                                    V<Word32> start) {
    V<Smi> utf8 = __ SmiConstant(Smi::FromInt(static_cast<int32_t>(variant)));
    return CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringEncodeWtf8Array>(
        decoder, {str, array, start, utf8});
  }

  void StringEncodeWtf16(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                         const Value& str, const Value& offset, Value* result) {
    V<WordPtr> address =
        MemoryAddressToUintPtrOrOOBTrap(imm.memory->address_type, offset.op);
    V<Word32> mem_index = __ Word32Constant(static_cast<int32_t>(imm.index));
    result->op = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringEncodeWtf16>(
        decoder, {V<String>::Cast(NullCheck(str)), address, mem_index});
  }

  void StringEncodeWtf16Array(FullDecoder* decoder, const Value& str,
                              const Value& array, const Value& start,
                              Value* result) {
    result->op = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringEncodeWtf16Array>(
        decoder, {V<String>::Cast(NullCheck(str)),
                  V<WasmArray>::Cast(NullCheck(array)), start.op});
  }

  void StringConcat(FullDecoder* decoder, const Value& head, const Value& tail,
                    Value* result) {
    V<NativeContext> native_context = instance_cache_.native_context();
    V<String> result_value =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::StringAdd_CheckNone>(
            decoder, native_context,
            {V<String>::Cast(NullCheck(head)),
             V<String>::Cast(NullCheck(tail))});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  V<Word32> StringEqImpl(FullDecoder* decoder, V<String> a, V<String> b,
                         ValueType a_type, ValueType b_type) {
    Label<Word32> done(&asm_);
    // Covers "identical string pointer" and "both are null" cases.
    GOTO_IF(__ TaggedEqual(a, b), done, __ Word32Constant(1));
    if (a_type.is_nullable()) {
      GOTO_IF(__ IsNull(a, a_type), done, __ Word32Constant(0));
    }
    if (b_type.is_nullable()) {
      GOTO_IF(__ IsNull(b, b_type), done, __ Word32Constant(0));
    }
    // TODO(jkummerow): Call Builtin::kStringEqual directly.
    GOTO(done,
         CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmStringEqual>(
             decoder, {a, b}));
    BIND(done, eq_result);
    return eq_result;
  }

  void StringEq(FullDecoder* decoder, const Value& a, const Value& b,
                Value* result) {
    result->op = StringEqImpl(decoder, a.op, b.op, a.type, b.type);
  }

  void StringIsUSVSequence(FullDecoder* decoder, const Value& str,
                           Value* result) {
    result->op = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringIsUSVSequence>(
        decoder, {V<String>::Cast(NullCheck(str))});
  }

  void StringAsWtf8(FullDecoder* decoder, const Value& str, Value* result) {
    V<ByteArray> result_value =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmStringAsWtf8>(
            decoder, {V<String>::Cast(NullCheck(str))});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void StringViewWtf8Advance(FullDecoder* decoder, const Value& view,
                             const Value& pos, const Value& bytes,
                             Value* result) {
    result->op = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringViewWtf8Advance>(
        decoder, {V<ByteArray>::Cast(NullCheck(view)), pos.op, bytes.op});
  }

  void StringViewWtf8Encode(FullDecoder* decoder,
                            const MemoryIndexImmediate& memory,
                            const unibrow::Utf8Variant variant,
                            const Value& view, const Value& addr,
                            const Value& pos, const Value& bytes,
                            Value* next_pos, Value* bytes_written) {
    V<WordPtr> address =
        MemoryAddressToUintPtrOrOOBTrap(memory.memory->address_type, addr.op);
    V<Smi> mem_index = __ SmiConstant(Smi::FromInt(memory.index));
    V<Smi> utf8 = __ SmiConstant(Smi::FromInt(static_cast<int32_t>(variant)));
    OpIndex result = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringViewWtf8Encode>(
        decoder, {address, pos.op, bytes.op,
                  V<ByteArray>::Cast(NullCheck(view)), mem_index, utf8});
    next_pos->op = __ Projection(result, 0, RepresentationFor(next_pos->type));
    bytes_written->op =
        __ Projection(result, 1, RepresentationFor(bytes_written->type));
  }

  void StringViewWtf8Slice(FullDecoder* decoder, const Value& view,
                           const Value& start, const Value& end,
                           Value* result) {
    V<String> result_value = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringViewWtf8Slice>(
        decoder, {V<ByteArray>::Cast(NullCheck(view)), start.op, end.op});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void StringAsWtf16(FullDecoder* decoder, const Value& str, Value* result) {
    result->op = __ StringAsWtf16(V<String>::Cast(NullCheck(str)));
  }

  V<Word32> GetCodeUnitImpl(FullDecoder* decoder, V<String> string,
                            V<Word32> offset) {
    auto prepare = __ StringPrepareForGetCodeUnit(string);
    V<Object> base = __ template Projection<0>(prepare);
    V<WordPtr> base_offset = __ template Projection<1>(prepare);
    V<Word32> charwidth_shift = __ template Projection<2>(prepare);

    // Bounds check.
    V<Word32> length = LoadStringLength(string);
    __ TrapIfNot(__ Uint32LessThan(offset, length),
                 TrapId::kTrapStringOffsetOutOfBounds);

    Label<> onebyte(&asm_);
    Label<> bailout(&asm_);
    Label<Word32> done(&asm_);
    GOTO_IF(UNLIKELY(__ Word32Equal(charwidth_shift,
                                    compiler::kCharWidthBailoutSentinel)),
            bailout);
    GOTO_IF(__ Word32Equal(charwidth_shift, 0), onebyte);

    // Two-byte.
    V<WordPtr> object_offset = __ WordPtrAdd(
        __ WordPtrMul(__ ChangeInt32ToIntPtr(offset), 2), base_offset);
    // Bitcast the tagged to a wordptr as the offset already contains the
    // kHeapObjectTag handling. Furthermore, in case of external strings the
    // tagged value is a smi 0, which doesn't really encode a tagged load.
    V<WordPtr> base_ptr = __ BitcastTaggedToWordPtr(base);
    V<Word32> result_value =
        __ Load(base_ptr, object_offset, LoadOp::Kind::RawAligned().Immutable(),
                MemoryRepresentation::Uint16());
    GOTO(done, result_value);

    // One-byte.
    BIND(onebyte);
    object_offset = __ WordPtrAdd(__ ChangeInt32ToIntPtr(offset), base_offset);
    // Bitcast the tagged to a wordptr as the offset already contains the
    // kHeapObjectTag handling. Furthermore, in case of external strings the
    // tagged value is a smi 0, which doesn't really encode a tagged load.
    base_ptr = __ BitcastTaggedToWordPtr(base);
    result_value =
        __ Load(base_ptr, object_offset, LoadOp::Kind::RawAligned().Immutable(),
                MemoryRepresentation::Uint8());
    GOTO(done, result_value);

    BIND(bailout);
    GOTO(done, CallBuiltinThroughJumptable<
                   BuiltinCallDescriptor::WasmStringViewWtf16GetCodeUnit>(
                   decoder, {string, offset}));

    BIND(done, final_result);
    // Make sure the original string is kept alive as long as we're operating
    // on pointers extracted from it (otherwise e.g. external strings' resources
    // might get freed prematurely).
    __ Retain(string);
    return final_result;
  }

  void StringViewWtf16GetCodeUnit(FullDecoder* decoder, const Value& view,
                                  const Value& pos, Value* result) {
    result->op =
        GetCodeUnitImpl(decoder, V<String>::Cast(NullCheck(view)), pos.op);
  }

  V<Word32> StringCodePointAt(FullDecoder* decoder, V<String> string,
                              V<Word32> offset) {
    auto prepare = __ StringPrepareForGetCodeUnit(string);
    V<Object> base = __ template Projection<0>(prepare);
    V<WordPtr> base_offset = __ template Projection<1>(prepare);
    V<Word32> charwidth_shift = __ template Projection<2>(prepare);

    // Bounds check.
    V<Word32> length = LoadStringLength(string);
    __ TrapIfNot(__ Uint32LessThan(offset, length),
                 TrapId::kTrapStringOffsetOutOfBounds);

    Label<> onebyte(&asm_);
    Label<> bailout(&asm_);
    Label<Word32> done(&asm_);
    GOTO_IF(
        __ Word32Equal(charwidth_shift, compiler::kCharWidthBailoutSentinel),
        bailout);
    GOTO_IF(__ Word32Equal(charwidth_shift, 0), onebyte);

    // Two-byte.
    V<WordPtr> object_offset = __ WordPtrAdd(
        __ WordPtrMul(__ ChangeInt32ToIntPtr(offset), 2), base_offset);
    // Bitcast the tagged to a wordptr as the offset already contains the
    // kHeapObjectTag handling. Furthermore, in case of external strings the
    // tagged value is a smi 0, which doesn't really encode a tagged load.
    V<WordPtr> base_ptr = __ BitcastTaggedToWordPtr(base);
    V<Word32> lead =
        __ Load(base_ptr, object_offset, LoadOp::Kind::RawAligned().Immutable(),
                MemoryRepresentation::Uint16());
    V<Word32> is_lead_surrogate =
        __ Word32Equal(__ Word32BitwiseAnd(lead, 0xFC00), 0xD800);
    GOTO_IF_NOT(is_lead_surrogate, done, lead);
    V<Word32> trail_offset = __ Word32Add(offset, 1);
    GOTO_IF_NOT(__ Uint32LessThan(trail_offset, length), done, lead);
    V<Word32> trail = __ Load(
        base_ptr, __ WordPtrAdd(object_offset, __ IntPtrConstant(2)),
        LoadOp::Kind::RawAligned().Immutable(), MemoryRepresentation::Uint16());
    V<Word32> is_trail_surrogate =
        __ Word32Equal(__ Word32BitwiseAnd(trail, 0xFC00), 0xDC00);
    GOTO_IF_NOT(is_trail_surrogate, done, lead);
    V<Word32> surrogate_bias =
        __ Word32Constant(0x10000 - (0xD800 << 10) - 0xDC00);
    V<Word32> result = __ Word32Add(__ Word32ShiftLeft(lead, 10),
                                    __ Word32Add(trail, surrogate_bias));
    GOTO(done, result);

    // One-byte.
    BIND(onebyte);
    object_offset = __ WordPtrAdd(__ ChangeInt32ToIntPtr(offset), base_offset);
    // Bitcast the tagged to a wordptr as the offset already contains the
    // kHeapObjectTag handling. Furthermore, in case of external strings the
    // tagged value is a smi 0, which doesn't really encode a tagged load.
    base_ptr = __ BitcastTaggedToWordPtr(base);
    result =
        __ Load(base_ptr, object_offset, LoadOp::Kind::RawAligned().Immutable(),
                MemoryRepresentation::Uint8());
    GOTO(done, result);

    BIND(bailout);
    GOTO(done, CallBuiltinThroughJumptable<
                   BuiltinCallDescriptor::WasmStringCodePointAt>(
                   decoder, {string, offset}));

    BIND(done, final_result);
    // Make sure the original string is kept alive as long as we're operating
    // on pointers extracted from it (otherwise e.g. external strings' resources
    // might get freed prematurely).
    __ Retain(string);
    return final_result;
  }

  void StringViewWtf16Encode(FullDecoder* decoder,
                             const MemoryIndexImmediate& imm, const Value& view,
                             const Value& offset, const Value& pos,
                             const Value& codeunits, Value* result) {
    V<String> string = V<String>::Cast(NullCheck(view));
    V<WordPtr> address =
        MemoryAddressToUintPtrOrOOBTrap(imm.memory->address_type, offset.op);
    V<Smi> mem_index = __ SmiConstant(Smi::FromInt(imm.index));
    result->op = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringViewWtf16Encode>(
        decoder, {address, pos.op, codeunits.op, string, mem_index});
  }

  void StringViewWtf16Slice(FullDecoder* decoder, const Value& view,
                            const Value& start, const Value& end,
                            Value* result) {
    V<String> string = V<String>::Cast(NullCheck(view));
    V<String> result_value = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringViewWtf16Slice>(
        decoder, {string, start.op, end.op});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void StringAsIter(FullDecoder* decoder, const Value& str, Value* result) {
    V<String> string 
"""


```