Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/wasm/function-body-decoder-impl.h`. The snippet appears to be part of a WebAssembly decoder, specifically handling various WebAssembly instructions related to **garbage collection (GC)** and **string manipulation**.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Functionality:** The code is a `switch` statement handling different `case`s, each corresponding to a specific WebAssembly opcode. The prefix `kExpr` strongly suggests these are WebAssembly instruction opcodes. The instructions themselves (e.g., `kExprArrayInitElem`, `kExprArrayGetS`, `kExprRefCast`, `kExprStringNewUtf8`) point to GC features (arrays, references) and string operations.

2. **Categorize the Instructions:**  Group the instructions by their general purpose. This helps in summarizing the overall functionality. The main categories are:
    * **Array Instructions:**  Operations like initialization, getting/setting elements, getting length, copying, filling, and creating fixed-size arrays.
    * **Reference Instructions:** Operations like creating `i31` references, casting references (with and without null handling), and testing reference types.
    * **Branch on Cast Instructions:** Conditional branching based on successful or failed type casts.
    * **String Instructions:** Creating, measuring, and encoding strings (various UTF-8 and UTF-16 variants).
    * **`anyref`/`externref` Conversion:** Converting between these reference types.

3. **Analyze Individual Instructions:** For each instruction, understand its purpose based on its name and the code within the `case`. Pay attention to:
    * **Immediates:**  The `ArrayIndexImmediate`, `HeapTypeImmediate`, `IndexImmediate`, `MemoryIndexImmediate`, and `StringConstImmediate` classes suggest that many instructions take additional immediate operands after the opcode.
    * **Stack Manipulation:**  The `Pop()` and `Push()` functions indicate how the instruction interacts with the WebAssembly stack, consuming input values and producing output values.
    * **Validation:** The `Validate()` calls indicate type checking and other validation steps to ensure the correctness of the WebAssembly code.
    * **Interface Calls:** The `CALL_INTERFACE_IF_OK_AND_REACHABLE()` macro likely invokes a lower-level implementation of the instruction.
    * **Error Handling:** `this->DecodeError()` is used for reporting invalid or unsupported WebAssembly code.

4. **Address Specific Instructions:**
    * **`array.init_elem`:**  Initializes an array element from an element segment. Crucially, it enforces that the array is mutable and has a reference type.
    * **`array.get_s` / `array.get_u`:**  Signed and unsigned access to *packed* array elements.
    * **`array.get`:** Access to array elements that are *not* packed.
    * **`array.set`:**  Setting an array element, requiring the array to be mutable.
    * **`array.len`:** Gets the length of an array.
    * **`array.copy`:** Copies elements from one array to another, with type compatibility checks.
    * **`array.fill`:** Fills an array with a specific value.
    * **`array.new_fixed`:** Creates a new fixed-size array.
    * **`ref.i31`:** Creates a reference to an `i31` value.
    * **`i31.get_s` / `i31.get_u`:** Signed and unsigned access to the `i31` value within an `i31` reference.
    * **`ref.cast` / `ref.cast_null`:**  Casting references, with `ref.cast_null` succeeding even if the cast fails (resulting in a null reference). The code includes important validation about type hierarchy and string views.
    * **`ref.test` / `ref.test_null`:** Checking if a reference is of a specific type, with `ref.test_null` also checking for null.
    * **`ref.cast_nop`:** A non-standard, experimental instruction for performance experiments, essentially a no-op cast.
    * **`br_on_cast` / `br_on_cast_fail`:** Conditional branching based on the success or failure of a cast. The logic handles stack manipulation and potential reachability changes.
    * **String instructions:**  Cover creating strings from UTF-8/UTF-16 data in memory or arrays, measuring string length, and encoding strings into memory or arrays. The code distinguishes between trapping and non-trapping (returning null) versions for invalid UTF-8.

5. **Consider the ".tq" suffix:** The prompt explicitly asks about the `.tq` suffix. Explain that it signifies a Torque source file in V8.

6. **Javascript Relationship:**  Think about how these WebAssembly features relate to JavaScript. Arrays in WebAssembly are similar to typed arrays in JavaScript. String manipulation is a core part of JavaScript. Reference types in WebAssembly are related to JavaScript's object model, although the mapping isn't always direct. Provide simple JavaScript examples to illustrate the concepts.

7. **Code Logic Inference (Hypothetical Input/Output):**  For a few representative instructions, provide examples of input values on the stack and the expected output after the instruction executes. This helps illustrate the data flow.

8. **Common Programming Errors:** Think about typical mistakes developers might make when using these WebAssembly features, such as type mismatches, trying to modify immutable arrays, or incorrect memory access.

9. **Summarize the Functionality:**  Combine the individual instruction analyses into a concise summary of the code's overall purpose. Emphasize the GC and string manipulation aspects.

10. **Address the "Part 7 of 9" Instruction:**  Acknowledge that this is part of a larger decoder and that this specific part focuses on GC and string-related instructions.

By following these steps, we can generate a comprehensive and accurate explanation of the provided C++ code snippet. The key is to break down the code into smaller, understandable pieces and then synthesize the information into a cohesive overview.
这是一个V8源代码文件，路径为 `v8/src/wasm/function-body-decoder-impl.h`。根据您的描述，我们来分析一下它的功能。

**核心功能归纳 (基于提供的代码片段):**

这个代码片段是 WebAssembly 函数体解码器实现的一部分，专门负责解码和处理与 **垃圾回收 (GC)** 和 **字符串操作** 相关的 WebAssembly 指令。

**具体功能分解:**

1. **解码 GC 相关指令:** 代码中包含多个 `case` 分支，对应不同的 WebAssembly GC 指令 (以 `kExpr` 开头)。这些指令包括：
    * **数组操作:**
        * `kExprArrayNew`: 创建一个新数组。
        * `kExprArrayNewDefault`: 创建一个使用默认值初始化的新数组。
        * `kExprArrayInitStatic`: 使用静态数据初始化数组。
        * `kExprArrayInitElem`: 使用元素段的数据初始化数组。
        * `kExprArrayGetS`/`kExprArrayGetU`: 获取有符号/无符号 packed 数组元素。
        * `kExprArrayGet`: 获取非 packed 数组元素。
        * `kExprArraySet`: 设置数组元素。
        * `kExprArrayLen`: 获取数组长度。
        * `kExprArrayCopy`: 复制数组的一部分到另一个数组。
        * `kExprArrayFill`: 使用特定值填充数组。
        * `kExprArrayNewFixed`: 创建一个固定长度的数组。
    * **引用操作:**
        * `kExprRefI31`: 创建一个 i31 类型的引用。
        * `kExprI31GetS`/`kExprI31GetU`: 获取有符号/无符号 i31 引用中的值。
        * `kExprRefCast`/`kExprRefCastNull`: 将引用转换为特定类型 (`kExprRefCastNull` 在转换失败时返回 null)。
        * `kExprRefTest`/`kExprRefTestNull`: 测试引用是否属于特定类型 (`kExprRefTestNull` 同时检查是否为 null)。
        * `kExprRefCastNop`:  一个临时的非标准指令，用于性能实验，相当于一个空操作的类型转换。
        * `kExprBrOnCast`/`kExprBrOnCastFail`: 基于类型转换结果进行分支跳转。
        * `kExprAnyConvertExtern`: 将 `externref` 转换为 `anyref`。
        * `kExprExternConvertAny`: 将 `anyref` 转换为 `externref`。

2. **解码字符串相关指令:** 代码还处理与字符串操作相关的指令：
    * `kExprStringNewUtf8`/`kExprStringNewUtf8Try`/`kExprStringNewLossyUtf8`/`kExprStringNewWtf8`: 从 UTF-8 字节序列创建字符串 (不同变体处理错误的方式不同)。
    * `kExprStringNewWtf16`: 从 UTF-16 字节序列创建字符串。
    * `kExprStringConst`: 创建一个字符串常量。
    * `kExprStringMeasureUtf8`/`kExprStringMeasureWtf8`/`kExprStringMeasureWtf16`:  测量不同编码字符串的长度。
    * `kExprStringEncodeUtf8`/`kExprStringEncodeLossyUtf8`/`kExprStringEncodeWtf8`/`kExprStringEncodeWtf16`: 将字符串编码为不同格式的字节序列。
    * `kExprStringViewWtf8Encode`: 将 UTF-8 字符串视图编码到内存中。
    * `kExprStringNewWtf8Array`: 从 UTF-8 字节数组创建字符串。
    * `kExprStringEncodeWtf8Array`: 将字符串编码到 UTF-8 字节数组中。

3. **指令参数解析:**  代码中使用类似 `ArrayIndexImmediate`, `HeapTypeImmediate`, `IndexImmediate`, `MemoryIndexImmediate`, `StringConstImmediate` 等类来解析指令的操作数 (immediate values)。这些类负责从字节流中读取并验证操作数。

4. **类型检查和验证:** 在解码过程中，代码会进行类型检查 (`VALIDATE`, `IsSubtypeOf`)，确保操作的类型安全。例如，在数组操作中，会检查数组的 mutability 和元素类型。在引用转换中，会检查类型之间的继承关系。

5. **堆栈操作:** 代码使用 `Pop()` 从操作数栈中弹出值，使用 `Push()` 将结果值压入栈中。这反映了 WebAssembly 的基于栈的执行模型。

6. **接口调用:** `CALL_INTERFACE_IF_OK_AND_REACHABLE` 宏用于调用实际执行这些指令的底层接口。

7. **错误处理:**  `this->DecodeError()` 用于在解码过程中遇到错误时报告错误信息。

**关于 `.tq` 结尾:**

如果 `v8/src/wasm/function-body-decoder-impl.h` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码** 文件。 Torque 是 V8 用来生成高效的 JavaScript 和 WebAssembly 代码的领域特定语言。虽然这个文件实际上是 `.h` 结尾的 C++ 头文件，但理解 `.tq` 的含义也很重要。

**与 JavaScript 的关系 (举例):**

这些 WebAssembly 的 GC 和字符串操作功能与 JavaScript 的对象和字符串处理密切相关。例如：

* **WebAssembly 数组** 可以看作是 JavaScript 中 `TypedArray` 的底层实现或者类似的概念。

```javascript
// JavaScript TypedArray
const wasmArrayLike = new Int32Array(10);
wasmArrayLike[0] = 10;
const firstElement = wasmArrayLike[0];
const arrayLength = wasmArrayLike.length;

// 对应的 WebAssembly 操作 (概念上)
// (假设存在这样的 WASM API 或等价操作)
// array.set i32_array 0 i32.const 10
// array.get_s i32_array 0
// array.len i32_array
```

* **WebAssembly 字符串操作** 类似于 JavaScript 中 `String` 对象的方法。

```javascript
// JavaScript 字符串操作
const jsString = "Hello";
const length = jsString.length;
const charCode = jsString.charCodeAt(0);

// 对应的 WebAssembly 操作 (概念上)
// string.measure_utf16 string_ref
// string.encode_utf16 string_ref ...
```

* **WebAssembly 引用类型** 与 JavaScript 的对象引用类似，`anyref` 可以持有任何 JavaScript 值 (包括对象)。

```javascript
// JavaScript 对象
const jsObject = { value: 1 };
const anotherObject = jsObject; // 引用传递

// 对应的 WebAssembly 操作 (概念上)
// (假设存在这样的 WASM API 或等价操作)
// local.get some_anyref  // 假设 some_anyref 持有对一个 WASM 对象的引用
// ref.test some_anyref some_wasm_class // 检查类型
```

**代码逻辑推理 (假设输入与输出):**

假设我们遇到 `kExprArrayGetS` 指令，并且栈顶有两个值：

* 栈顶 (0):  `i32.const 5`  (数组索引)
* 栈顶 (1):  一个对 `i32_array` 类型的数组的引用 (假设数组内容为 `[10, 20, 30, 40, 50, 60, ...]`)

**输入:**  数组引用，索引 `5`

**输出:**  `i32.const 60` (索引为 5 的有符号整数值)

**用户常见的编程错误 (举例):**

* **类型不匹配:** 尝试将一个非引用类型的值传递给需要引用类型的指令，或者在数组操作中使用错误的元素类型。例如，尝试将一个 `i32` 值赋给一个 `ref` 类型的数组元素。
* **访问越界:** 尝试访问数组的非法索引 (小于 0 或大于等于数组长度)。WebAssembly 的内存安全机制通常会捕获这类错误。
* **尝试修改不可变数组:**  对使用 `array.new_fixed` 创建的不可变数组进行 `array.set` 操作。
* **引用类型转换错误:**  使用 `ref.cast` 尝试将一个不兼容类型的引用转换为另一个类型，导致转换失败 (除非使用 `ref.cast_null`)。
* **字符串编码/解码错误:**  在 UTF-8 字符串操作中处理无效的 UTF-8 字节序列，可能导致程序崩溃或产生意外结果 (取决于使用的字符串指令变体)。

**功能归纳 (作为第 7 部分，共 9 部分):**

作为解码器的第七部分，这个代码片段专注于处理 WebAssembly 规范中与 **垃圾回收机制引入的对象 (数组和引用)** 和 **字符串操作** 相关的指令。  在整个解码流程中，这一部分负责将这些高级的、与内存管理和数据结构相关的操作从字节码形式转换为内部表示，以便后续的编译和执行。之前的或后续的部分可能负责处理例如控制流、算术运算、内存访问等其他类型的指令。这部分的处理标志着解码器开始处理更复杂的、面向对象的 WebAssembly 特性。

### 提示词
```
这是目录为v8/src/wasm/function-body-decoder-impl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/function-body-decoder-impl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共9部分，请归纳一下它的功能
```

### 源代码
```c
n opcode_length + array_imm.length + data_segment.length;
      }
      case kExprArrayInitElem: {
        NON_CONST_ONLY
        // TODO(14616): Add check that array sharedness == segment sharedness?
        ArrayIndexImmediate array_imm(this, this->pc_ + opcode_length,
                                      validate);
        if (!this->Validate(this->pc_ + opcode_length, array_imm)) return 0;
        if (!array_imm.array_type->mutability()) {
          this->DecodeError(
              "array.init_elem can only be used with mutable arrays, found "
              "array type #%d instead",
              array_imm.index);
          return 0;
        }
        ValueType element_type = array_imm.array_type->element_type();
        if (element_type.is_numeric()) {
          this->DecodeError(
              "array.init_elem can only be used with reference-type arrays, "
              "found array type #%d instead",
              array_imm.index);
          return 0;
        }
        const uint8_t* elem_index_pc =
            this->pc_ + opcode_length + array_imm.length;
        IndexImmediate elem_segment(this, elem_index_pc, "element segment",
                                    validate);
        if (!this->ValidateElementSegment(elem_index_pc, elem_segment)) {
          return 0;
        }
        ValueType segment_type =
            this->module_->elem_segments[elem_segment.index].type;
        if (!VALIDATE(IsSubtypeOf(segment_type, element_type, this->module_))) {
          this->DecodeError(
              "array.init_elem: segment type %s is not a subtype of array "
              "element type %s",
              segment_type.name().c_str(), element_type.name().c_str());
          return 0;
        }

        auto [array, array_index, elem_offset, length] = Pop(
            ValueType::RefNull(array_imm.index), kWasmI32, kWasmI32, kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(ArrayInitSegment, array_imm,
                                           elem_segment, array, array_index,
                                           elem_offset, length);
        return opcode_length + array_imm.length + elem_segment.length;
      }
      case kExprArrayGetS:
      case kExprArrayGetU: {
        NON_CONST_ONLY
        ArrayIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        if (!VALIDATE(imm.array_type->element_type().is_packed())) {
          this->DecodeError(
              "%s: Immediate array type %d has non-packed type %s. Use "
              "array.get instead.",
              WasmOpcodes::OpcodeName(opcode), imm.index,
              imm.array_type->element_type().name().c_str());
          return 0;
        }
        auto [array_obj, index] = Pop(ValueType::RefNull(imm.index), kWasmI32);
        Value* value = Push(imm.array_type->element_type().Unpacked());
        CALL_INTERFACE_IF_OK_AND_REACHABLE(ArrayGet, array_obj, imm, index,
                                           opcode == kExprArrayGetS, value);
        return opcode_length + imm.length;
      }
      case kExprArrayGet: {
        NON_CONST_ONLY
        ArrayIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        if (!VALIDATE(!imm.array_type->element_type().is_packed())) {
          this->DecodeError(
              "array.get: Immediate array type %d has packed type %s. Use "
              "array.get_s or array.get_u instead.",
              imm.index, imm.array_type->element_type().name().c_str());
          return 0;
        }
        auto [array_obj, index] = Pop(ValueType::RefNull(imm.index), kWasmI32);
        Value* value = Push(imm.array_type->element_type());
        CALL_INTERFACE_IF_OK_AND_REACHABLE(ArrayGet, array_obj, imm, index,
                                           true, value);
        return opcode_length + imm.length;
      }
      case kExprArraySet: {
        NON_CONST_ONLY
        ArrayIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        if (!VALIDATE(imm.array_type->mutability())) {
          this->DecodeError("array.set: immediate array type %d is immutable",
                            imm.index);
          return 0;
        }
        auto [array_obj, index, value] =
            Pop(ValueType::RefNull(imm.index), kWasmI32,
                imm.array_type->element_type().Unpacked());
        CALL_INTERFACE_IF_OK_AND_REACHABLE(ArraySet, array_obj, imm, index,
                                           value);
        return opcode_length + imm.length;
      }
      case kExprArrayLen: {
        NON_CONST_ONLY
        Value array_obj = Pop(kWasmArrayRef);
        Value* value = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(ArrayLen, array_obj, value);
        return opcode_length;
      }
      case kExprArrayCopy: {
        NON_CONST_ONLY
        ArrayIndexImmediate dst_imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, dst_imm)) return 0;
        if (!VALIDATE(dst_imm.array_type->mutability())) {
          this->DecodeError(
              "array.copy: immediate destination array type #%d is immutable",
              dst_imm.index);
          return 0;
        }
        ArrayIndexImmediate src_imm(
            this, this->pc_ + opcode_length + dst_imm.length, validate);
        if (!this->Validate(this->pc_ + opcode_length + dst_imm.length,
                            src_imm)) {
          return 0;
        }
        if (!IsSubtypeOf(src_imm.array_type->element_type(),
                         dst_imm.array_type->element_type(), this->module_)) {
          this->DecodeError(
              "array.copy: source array's #%d element type is not a subtype of "
              "destination array's #%d element type",
              src_imm.index, dst_imm.index);
          return 0;
        }
        auto [dst, dst_index, src, src_index, length] =
            Pop(ValueType::RefNull(dst_imm.index), kWasmI32,
                ValueType::RefNull(src_imm.index), kWasmI32, kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(ArrayCopy, dst, dst_index, src,
                                           src_index, src_imm, length);
        return opcode_length + dst_imm.length + src_imm.length;
      }
      case kExprArrayFill: {
        NON_CONST_ONLY
        ArrayIndexImmediate array_imm(this, this->pc_ + opcode_length,
                                      validate);
        if (!this->Validate(this->pc_ + opcode_length, array_imm)) return 0;
        if (!VALIDATE(array_imm.array_type->mutability())) {
          this->DecodeError("array.init: immediate array type #%d is immutable",
                            array_imm.index);
          return 0;
        }

        auto [array, offset, value, length] =
            Pop(ValueType::RefNull(array_imm.index), kWasmI32,
                array_imm.array_type->element_type().Unpacked(), kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(ArrayFill, array_imm, array, offset,
                                           value, length);
        return opcode_length + array_imm.length;
      }
      case kExprArrayNewFixed: {
        ArrayIndexImmediate array_imm(this, this->pc_ + opcode_length,
                                      validate);
        if (!this->Validate(this->pc_ + opcode_length, array_imm)) return 0;
        IndexImmediate length_imm(this,
                                  this->pc_ + opcode_length + array_imm.length,
                                  "array.new_fixed length", validate);
        uint32_t elem_count = length_imm.index;
        if (!VALIDATE(elem_count <= kV8MaxWasmArrayNewFixedLength)) {
          this->DecodeError(
              "Requested length %u for array.new_fixed too large, maximum is "
              "%zu",
              length_imm.index, kV8MaxWasmArrayNewFixedLength);
          return 0;
        }
        ValueType element_type = array_imm.array_type->element_type();
        std::vector<ValueType> element_types(elem_count,
                                             element_type.Unpacked());
        FunctionSig element_sig(0, elem_count, element_types.data());
        PoppedArgVector elements = PopArgs(&element_sig);
        Value* result = Push(ValueType::Ref(array_imm.index));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(ArrayNewFixed, array_imm, length_imm,
                                           elements.data(), result);
        return opcode_length + array_imm.length + length_imm.length;
      }
      case kExprRefI31: {
        Value input = Pop(kWasmI32);
        Value* value = Push(ValueType::Ref(HeapType::kI31));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(RefI31, input, value);
        return opcode_length;
      }
      case kExprI31GetS: {
        NON_CONST_ONLY
        Value i31 = Pop(kWasmI31Ref);
        Value* value = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(I31GetS, i31, value);
        return opcode_length;
      }
      case kExprI31GetU: {
        NON_CONST_ONLY
        Value i31 = Pop(kWasmI31Ref);
        Value* value = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(I31GetU, i31, value);
        return opcode_length;
      }
      case kExprRefCast:
      case kExprRefCastNull: {
        NON_CONST_ONLY
        HeapTypeImmediate imm(this->enabled_, this, this->pc_ + opcode_length,
                              validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        opcode_length += imm.length;

        Value obj = Pop();

        HeapType target_type = imm.type;

        if (!VALIDATE((obj.type.is_object_reference() &&
                       IsSameTypeHierarchy(obj.type.heap_type(), target_type,
                                           this->module_)) ||
                      obj.type.is_bottom())) {
          this->DecodeError(
              obj.pc(),
              "Invalid types for %s: %s of type %s has to "
              "be in the same reference type hierarchy as (ref %s)",
              WasmOpcodes::OpcodeName(opcode), SafeOpcodeNameAt(obj.pc()),
              obj.type.name().c_str(), target_type.name().c_str());
          return 0;
        }
        if (!VALIDATE(!target_type.is_string_view())) {
          // TODO(12868): This reflects the current state of discussion at
          // https://github.com/WebAssembly/stringref/issues/40
          // It is suboptimal because it allows classifying a stringview_wtf16
          // as a stringref. This would be solved by making the views types
          // that aren't subtypes of anyref, which is one of the possible
          // resolutions of that discussion.
          this->DecodeError(
              this->pc_,
              "Invalid type for %s: string views are not classifiable",
              WasmOpcodes::OpcodeName(opcode));
          return 0;
        }

        bool null_succeeds = opcode == kExprRefCastNull;
        Value* value = Push(ValueType::RefMaybeNull(
            target_type, null_succeeds ? kNullable : kNonNullable));
        if (current_code_reachable_and_ok_) {
          // This logic ensures that code generation can assume that functions
          // can only be cast to function types, and data objects to data types.
          if (V8_UNLIKELY(TypeCheckAlwaysSucceeds(obj, target_type))) {
            if (obj.type.is_nullable() && !null_succeeds) {
              CALL_INTERFACE(AssertNotNullTypecheck, obj, value);
            } else {
              CALL_INTERFACE(Forward, obj, value);
            }
          } else if (V8_UNLIKELY(TypeCheckAlwaysFails(obj, target_type,
                                                      null_succeeds))) {
            // Unrelated types. The only way this will not trap is if the object
            // is null.
            if (obj.type.is_nullable() && null_succeeds) {
              CALL_INTERFACE(AssertNullTypecheck, obj, value);
            } else {
              CALL_INTERFACE(Trap, TrapReason::kTrapIllegalCast);
              // We know that the following code is not reachable, but according
              // to the spec it technically is. Set it to spec-only reachable.
              SetSucceedingCodeDynamicallyUnreachable();
            }
          } else {
            if (target_type.is_index()) {
              CALL_INTERFACE(RefCast, target_type.ref_index(), obj, value,
                             null_succeeds);
            } else {
              CALL_INTERFACE(RefCastAbstract, obj, target_type, value,
                             null_succeeds);
            }
          }
        }
        return opcode_length;
      }
      case kExprRefTestNull:
      case kExprRefTest: {
        NON_CONST_ONLY
        HeapTypeImmediate imm(this->enabled_, this, this->pc_ + opcode_length,
                              validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        opcode_length += imm.length;

        Value obj = Pop();
        HeapType target_type = imm.type;
        Value* result = Push(kWasmI32);

        if (!VALIDATE((obj.type.is_object_reference() &&
                       IsSameTypeHierarchy(obj.type.heap_type(), target_type,
                                           this->module_)) ||
                      obj.type.is_bottom())) {
          this->DecodeError(
              obj.pc(),
              "Invalid types for %s: %s of type %s has to "
              "be in the same reference type hierarchy as (ref %s)",
              WasmOpcodes::OpcodeName(opcode), SafeOpcodeNameAt(obj.pc()),
              obj.type.name().c_str(), target_type.name().c_str());
          return 0;
        }
        if (!VALIDATE(!target_type.is_string_view())) {
          // TODO(12868): This reflects the current state of discussion at
          // https://github.com/WebAssembly/stringref/issues/40
          // It is suboptimal because it allows classifying a stringview_wtf16
          // as a stringref. This would be solved by making the views types
          // that aren't subtypes of anyref, which is one of the possible
          // resolutions of that discussion.
          this->DecodeError(
              this->pc_,
              "Invalid type for %s: string views are not classifiable",
              WasmOpcodes::OpcodeName(opcode));
          return 0;
        }
        bool null_succeeds = opcode == kExprRefTestNull;
        if (V8_LIKELY(current_code_reachable_and_ok_)) {
          // This logic ensures that code generation can assume that functions
          // can only be cast to function types, and data objects to data types.
          if (V8_UNLIKELY(TypeCheckAlwaysSucceeds(obj, target_type))) {
            // Type checking can still fail for null.
            if (obj.type.is_nullable() && !null_succeeds) {
              // We abuse ref.as_non_null, which isn't otherwise used as a unary
              // operator, as a sentinel for the negation of ref.is_null.
              CALL_INTERFACE(UnOp, kExprRefAsNonNull, obj, result);
            } else {
              CALL_INTERFACE(Drop);
              CALL_INTERFACE(I32Const, result, 1);
            }
          } else if (V8_UNLIKELY(TypeCheckAlwaysFails(obj, target_type,
                                                      null_succeeds))) {
            CALL_INTERFACE(Drop);
            CALL_INTERFACE(I32Const, result, 0);
          } else {
            if (imm.type.is_index()) {
              CALL_INTERFACE(RefTest, imm.type.ref_index(), obj, result,
                             null_succeeds);
            } else {
              CALL_INTERFACE(RefTestAbstract, obj, target_type, result,
                             null_succeeds);
            }
          }
        }
        return opcode_length;
      }
      case kExprRefCastNop: {
        NON_CONST_ONLY
        // Temporary non-standard instruction, for performance experiments.
        if (!VALIDATE(this->enabled_.has_ref_cast_nop())) {
          this->DecodeError(
              "Invalid opcode 0xfb4c (enable with "
              "--experimental-wasm-ref-cast-nop)");
          return 0;
        }
        HeapTypeImmediate imm(this->enabled_, this, this->pc_ + opcode_length,
                              validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        opcode_length += imm.length;
        HeapType target_type = imm.type;
        Value obj = Pop();
        if (!VALIDATE((obj.type.is_object_reference() &&
                       IsSameTypeHierarchy(obj.type.heap_type(), target_type,
                                           this->module_)) ||
                      obj.type.is_bottom())) {
          this->DecodeError(
              obj.pc(),
              "Invalid types for %s: %s of type %s has to "
              "be in the same reference type hierarchy as (ref %s)",
              WasmOpcodes::OpcodeName(opcode), SafeOpcodeNameAt(obj.pc()),
              obj.type.name().c_str(), target_type.name().c_str());
          return 0;
        }
        Value* value = Push(ValueType::Ref(target_type));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(Forward, obj, value);
        return opcode_length;
      }
      case kExprBrOnCast:
      case kExprBrOnCastFail: {
        NON_CONST_ONLY
        uint32_t pc_offset = opcode_length;
        BrOnCastImmediate flags_imm(this, this->pc_ + pc_offset, validate);
        pc_offset += flags_imm.length;
        return ParseBrOnCast(opcode, pc_offset, flags_imm.flags);
      }
      case kExprAnyConvertExtern: {
        Value extern_val = Pop(kWasmExternRef);
        ValueType intern_type = ValueType::RefMaybeNull(
            HeapType::kAny, Nullability(extern_val.type.is_nullable()));
        Value* intern_val = Push(intern_type);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(UnOp, kExprAnyConvertExtern,
                                           extern_val, intern_val);
        return opcode_length;
      }
      case kExprExternConvertAny: {
        Value val = Pop(kWasmAnyRef);
        ValueType extern_type = ValueType::RefMaybeNull(
            HeapType::kExtern, Nullability(val.type.is_nullable()));
        Value* extern_val = Push(extern_type);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(UnOp, kExprExternConvertAny, val,
                                           extern_val);
        return opcode_length;
      }
      default:
        this->DecodeError("invalid gc opcode: %x", opcode);
        return 0;
    }
  }

  enum class WasmArrayAccess { kRead, kWrite };

  int ParseBrOnCast(WasmOpcode opcode, uint32_t opcode_length,
                    BrOnCastFlags flags) {
    BranchDepthImmediate branch_depth(this, this->pc_ + opcode_length,
                                      validate);
    if (!this->Validate(this->pc_ + opcode_length, branch_depth,
                        control_.size())) {
      return 0;
    }
    uint32_t pc_offset = opcode_length + branch_depth.length;

    Value obj = Pop();

    HeapTypeImmediate src_imm(this->enabled_, this, this->pc_ + pc_offset,
                              validate);
    if (!this->Validate(this->pc_ + pc_offset, src_imm)) return 0;
    pc_offset += src_imm.length;
    ValueType src_type = ValueType::RefMaybeNull(
        src_imm.type, flags.src_is_null ? kNullable : kNonNullable);
    ValidateStackValue(0, obj, src_type);

    HeapTypeImmediate target_imm(this->enabled_, this, this->pc_ + pc_offset,
                                 validate);
    if (!this->Validate(this->pc_ + pc_offset, target_imm)) return 0;
    pc_offset += target_imm.length;
    bool null_succeeds = flags.res_is_null;
    ValueType target_type = ValueType::RefMaybeNull(
        target_imm.type, null_succeeds ? kNullable : kNonNullable);

    if (!VALIDATE(IsSubtypeOf(target_type, src_type, this->module_))) {
      this->DecodeError("invalid types for %s: %s is not a subtype of %s",
                        WasmOpcodes::OpcodeName(opcode),
                        target_type.name().c_str(), src_type.name().c_str());
      return 0;
    }

    if (!VALIDATE(
            (obj.type.is_object_reference() &&
             IsSameTypeHierarchy(obj.type.heap_type(), target_type.heap_type(),
                                 this->module_)) ||
            obj.type.is_bottom())) {
      this->DecodeError(obj.pc(),
                        "invalid types for %s: %s of type %s has to "
                        "be in the same reference type hierarchy as %s",
                        WasmOpcodes::OpcodeName(opcode),
                        SafeOpcodeNameAt(obj.pc()), obj.type.name().c_str(),
                        target_type.name().c_str());
      return 0;
    }

    Control* c = control_at(branch_depth.depth);
    if (c->br_merge()->arity == 0) {
      this->DecodeError("%s must target a branch of arity at least 1",
                        WasmOpcodes::OpcodeName(opcode));
      return 0;
    }

    if (opcode == kExprBrOnCast) {
      Value* value_on_branch = Push(target_type);
      if (!VALIDATE(
              (TypeCheckBranch<PushBranchValues::kYes, RewriteStackTypes::kYes>(
                  c)))) {
        return 0;
      }
      if (V8_LIKELY(current_code_reachable_and_ok_)) {
        // This logic ensures that code generation can assume that functions
        // can only be cast to function types, and data objects to data types.
        if (V8_UNLIKELY(
                TypeCheckAlwaysSucceeds(obj, target_type.heap_type()))) {
          // The branch will still not be taken on null if not
          // {null_succeeds}.
          if (obj.type.is_nullable() && !null_succeeds) {
            CALL_INTERFACE(BrOnNonNull, obj, value_on_branch,
                           branch_depth.depth, false);
          } else {
            CALL_INTERFACE(Forward, obj, value_on_branch);
            CALL_INTERFACE(BrOrRet, branch_depth.depth);
            // We know that the following code is not reachable, but according
            // to the spec it technically is. Set it to spec-only reachable.
            SetSucceedingCodeDynamicallyUnreachable();
          }
          c->br_merge()->reached = true;
        } else if (V8_LIKELY(!TypeCheckAlwaysFails(obj, target_type.heap_type(),
                                                   null_succeeds))) {
          if (target_imm.type.is_index()) {
            CALL_INTERFACE(BrOnCast, target_imm.type.ref_index(), obj,
                           value_on_branch, branch_depth.depth, null_succeeds);
          } else {
            CALL_INTERFACE(BrOnCastAbstract, obj, target_type.heap_type(),
                           value_on_branch, branch_depth.depth, null_succeeds);
          }
          c->br_merge()->reached = true;
        }
      }

      Drop(*value_on_branch);
      Push(obj);  // Restore stack state on fallthrough.
      // The fallthrough type is the source type as specified in the br_on_cast
      // instruction. This can be a super type of the stack value. Furthermore
      // nullability gets refined to non-nullable if the cast target is
      // nullable, meaning the branch will be taken on null.
      DCHECK(!src_type.heap_type().is_bottom());
      bool fallthrough_nullable = flags.src_is_null && !flags.res_is_null;
      stack_value(1)->type = ValueType::RefMaybeNull(
          src_type.heap_type(),
          fallthrough_nullable ? kNullable : kNonNullable);
      CALL_INTERFACE_IF_OK_AND_REACHABLE(Forward, obj, stack_value(1));
      return pc_offset;

    } else {
      DCHECK_EQ(opcode, kExprBrOnCastFail);
      // The branch type is set based on the source type immediate (independent
      // of the actual stack value). If the target type is nullable, the branch
      // type is non-nullable.
      Push(flags.res_is_null ? src_type.AsNonNull() : src_type);
      CALL_INTERFACE_IF_OK_AND_REACHABLE(Forward, obj, stack_value(1));

      if (!VALIDATE(
              (TypeCheckBranch<PushBranchValues::kYes, RewriteStackTypes::kYes>(
                  c)))) {
        return 0;
      }

      Value result_on_fallthrough = CreateValue(target_type);
      if (V8_LIKELY(current_code_reachable_and_ok_)) {
        // This logic ensures that code generation can assume that functions
        // can only be cast between compatible types.
        if (V8_UNLIKELY(TypeCheckAlwaysFails(obj, target_type.heap_type(),
                                             null_succeeds))) {
          // The types are incompatible (i.e. neither of the two types is a
          // subtype of the other). Always branch.
          CALL_INTERFACE(Forward, obj, stack_value(1));
          CALL_INTERFACE(BrOrRet, branch_depth.depth);
          // We know that the following code is not reachable, but according
          // to the spec it technically is. Set it to spec-only reachable.
          SetSucceedingCodeDynamicallyUnreachable();
          c->br_merge()->reached = true;
        } else if (V8_UNLIKELY(
                       TypeCheckAlwaysSucceeds(obj, target_type.heap_type()))) {
          // The branch can still be taken on null.
          if (obj.type.is_nullable() && !null_succeeds) {
            CALL_INTERFACE(BrOnNull, obj, branch_depth.depth, true,
                           &result_on_fallthrough);
            c->br_merge()->reached = true;
          } else {
            // Otherwise, the type check always succeeds. Do not branch. Also,
            // make sure the object remains on the stack.
            result_on_fallthrough = obj;
          }
        } else {
          if (target_imm.type.is_index()) {
            CALL_INTERFACE(BrOnCastFail, target_imm.type.ref_index(), obj,
                           &result_on_fallthrough, branch_depth.depth,
                           null_succeeds);
          } else {
            CALL_INTERFACE(BrOnCastFailAbstract, obj, target_type.heap_type(),
                           &result_on_fallthrough, branch_depth.depth,
                           null_succeeds);
          }
          c->br_merge()->reached = true;
        }
      }
      // Make sure the correct value is on the stack state on fallthrough.
      Drop(obj);
      Push(result_on_fallthrough);
      return pc_offset;
    }
  }

  int DecodeStringNewWtf8(unibrow::Utf8Variant variant,
                          uint32_t opcode_length) {
    NON_CONST_ONLY
    bool null_on_invalid = variant == unibrow::Utf8Variant::kUtf8NoTrap;
    MemoryIndexImmediate imm(this, this->pc_ + opcode_length, validate);
    if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
    ValueType addr_type = MemoryAddressType(imm.memory);
    auto [offset, size] = Pop(addr_type, kWasmI32);
    Value* result = Push(ValueType::RefMaybeNull(
        HeapType::kString, null_on_invalid ? kNullable : kNonNullable));
    CALL_INTERFACE_IF_OK_AND_REACHABLE(StringNewWtf8, imm, variant, offset,
                                       size, result);
    return opcode_length + imm.length;
  }

  int DecodeStringMeasureWtf8(unibrow::Utf8Variant variant,
                              uint32_t opcode_length) {
    NON_CONST_ONLY
    Value str = Pop(kWasmStringRef);
    Value* result = Push(kWasmI32);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(StringMeasureWtf8, variant, str, result);
    return opcode_length;
  }

  int DecodeStringEncodeWtf8(unibrow::Utf8Variant variant,
                             uint32_t opcode_length) {
    NON_CONST_ONLY
    MemoryIndexImmediate imm(this, this->pc_ + opcode_length, validate);
    if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
    ValueType addr_type = MemoryAddressType(imm.memory);
    auto [str, addr] = Pop(kWasmStringRef, addr_type);
    Value* result = Push(kWasmI32);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(StringEncodeWtf8, imm, variant, str,
                                       addr, result);
    return opcode_length + imm.length;
  }

  int DecodeStringViewWtf8Encode(unibrow::Utf8Variant variant,
                                 uint32_t opcode_length) {
    NON_CONST_ONLY
    MemoryIndexImmediate imm(this, this->pc_ + opcode_length, validate);
    if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
    ValueType addr_type = MemoryAddressType(imm.memory);
    auto [view, addr, pos, bytes] =
        Pop(kWasmStringViewWtf8, addr_type, kWasmI32, kWasmI32);
    Value* next_pos = Push(kWasmI32);
    Value* bytes_out = Push(kWasmI32);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewWtf8Encode, imm, variant, view,
                                       addr, pos, bytes, next_pos, bytes_out);
    return opcode_length + imm.length;
  }

  int DecodeStringNewWtf8Array(unibrow::Utf8Variant variant,
                               uint32_t opcode_length) {
    NON_CONST_ONLY
    Value end = Pop(2, kWasmI32);
    Value start = Pop(1, kWasmI32);
    Value array = PopPackedArray(0, kWasmI8, WasmArrayAccess::kRead);
    bool null_on_invalid = variant == unibrow::Utf8Variant::kUtf8NoTrap;
    Value* result = Push(ValueType::RefMaybeNull(
        HeapType::kString, null_on_invalid ? kNullable : kNonNullable));
    CALL_INTERFACE_IF_OK_AND_REACHABLE(StringNewWtf8Array, variant, array,
                                       start, end, result);
    return opcode_length;
  }

  int DecodeStringEncodeWtf8Array(unibrow::Utf8Variant variant,
                                  uint32_t opcode_length) {
    NON_CONST_ONLY
    Value start = Pop(2, kWasmI32);
    Value array = PopPackedArray(1, kWasmI8, WasmArrayAccess::kWrite);
    Value str = Pop(0, kWasmStringRef);
    Value* result = Push(kWasmI32);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(StringEncodeWtf8Array, variant, str,
                                       array, start, result);
    return opcode_length;
  }

  int DecodeStringRefOpcode(WasmOpcode opcode, uint32_t opcode_length) {
    // Fast check for out-of-range opcodes (only allow 0xfbXX).
    // This might help the big switch below.
    if (!VALIDATE((opcode >> 8) == kGCPrefix)) {
      this->DecodeError("invalid stringref opcode: %x", opcode);
      return 0;
    }

    switch (opcode) {
      case kExprStringNewUtf8:
        return DecodeStringNewWtf8(unibrow::Utf8Variant::kUtf8, opcode_length);
      case kExprStringNewUtf8Try:
        return DecodeStringNewWtf8(unibrow::Utf8Variant::kUtf8NoTrap,
                                   opcode_length);
      case kExprStringNewLossyUtf8:
        return DecodeStringNewWtf8(unibrow::Utf8Variant::kLossyUtf8,
                                   opcode_length);
      case kExprStringNewWtf8:
        return DecodeStringNewWtf8(unibrow::Utf8Variant::kWtf8, opcode_length);
      case kExprStringNewWtf16: {
        NON_CONST_ONLY
        MemoryIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        ValueType addr_type = MemoryAddressType(imm.memory);
        auto [offset, size] = Pop(addr_type, kWasmI32);
        Value* result = Push(kWasmRefString);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringNewWtf16, imm, offset, size,
                                           result);
        return opcode_length + imm.length;
      }
      case kExprStringConst: {
        StringConstImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        Value* result = Push(kWasmRefString);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringConst, imm, result);
        return opcode_length + imm.length;
      }
      case kExprStringMeasureUtf8:
        return DecodeStringMeasureWtf8(unibrow::Utf8Variant::kUtf8,
                                       opcode_length);
      case kExprStringMeasureWtf8:
        return DecodeStringMeasureWtf8(unibrow::Utf8Variant::kWtf8,
                                       opcode_length);
      case kExprStringMeasureWtf16: {
        NON_CONST_ONLY
        Value str = Pop(kWasmStringRef);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringMeasureWtf16, str, result);
        return opcode_length;
      }
      case kExprStringEncodeUtf8:
        return DecodeStringEncodeWtf8(unibrow::Utf8Variant::kUtf8,
                                      opcode_length);
      case kExprStringEncodeLossyUtf8:
        return DecodeStringEncodeWtf8(unibrow::Utf8Variant::kLossyUtf8,
                                      opcode_length);
      case kExprStringEncodeWtf8:
        return DecodeStringEncodeWtf8(unibrow::Utf8Variant::kWtf8,
                                      opcode_length);
      case kExprStringEncodeWtf16: {
        NON_CONST_ONLY
        MemoryIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        ValueTy
```