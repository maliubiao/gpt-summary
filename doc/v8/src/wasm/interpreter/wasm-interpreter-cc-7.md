Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/interpreter/wasm-interpreter.cc`. I need to identify the key operations performed by each `INSTRUCTION_HANDLER_FUNC`. Specifically, I should look for actions like reading from or writing to memory (stack, struct fields, array elements), function calls, conditional branching, and object creation.

The prompt also asks for specific conditions:
1. **List functionality:** Summarize what the code does.
2. **.tq check:** Determine if the file *could* be a Torque file based on the name, even though the provided snippet is C++.
3. **JavaScript relation:** If there's a connection to JavaScript functionality, illustrate with an example.
4. **Code logic inference:** Provide hypothetical inputs and outputs for some functions.
5. **Common programming errors:** Point out potential pitfalls users might encounter.
6. **Part number:** Acknowledge this is part 8 of 15.
7. **Overall function:**  Provide a concise summary of the entire snippet's purpose.

Based on the function names and the operations within each function, it appears this code implements the execution logic for various WebAssembly instructions within the V8 interpreter. It handles operations related to:

- **Reference Types:**  Casting, calling references.
- **Structs:** Creating new structs (with and without default values), getting and setting struct fields.
- **Arrays:** Creating new arrays (with initial values, default values, from segments), getting and setting array elements, getting array length, copying array segments, filling arrays.
- **Data and Element Segments:** Initializing array data from segments.

I need to go through each `INSTRUCTION_HANDLER_FUNC` and concisely describe its operation.

For the JavaScript relation, I can consider how these Wasm instructions might be represented or used in JavaScript when interacting with WebAssembly modules.

For code logic inference, I can pick a simple function like `s2s_ArrayLen` and show an example of stack input and the resulting output.

Common programming errors will likely revolve around null dereferences, out-of-bounds accesses (for arrays and segments), and type casting issues.
这是目录为 `v8/src/wasm/interpreter/wasm-interpreter.cc` 的一个 V8 源代码片段，它定义了 WebAssembly 解释器中用于处理特定 WebAssembly 指令的函数。

以下是代码片段中各个函数的功能列表：

* **`s2s_BranchOnCastFail`**:  处理类型转换失败时的分支。它从栈中弹出引用和类型信息，如果引用到指定类型的转换失败（并且不允许空引用成功转换），则跳转到指定的偏移量。
* **`s2s_CallRef`**: 处理通过引用进行的函数调用。它从栈中弹出要调用的函数引用，并从指令流中读取签名索引、栈位置等信息，然后调用 `wasm_runtime->ExecuteCallRef` 来执行调用。如果函数引用为空，则会触发陷阱。
* **`s2s_ReturnCallRef`**: 处理尾调用优化的通过引用进行的函数调用。它执行与 `s2s_CallRef` 类似的操作，但会先调整栈帧，模拟尾调用的行为。
* **`s2s_StructNew`**:  处理创建新的结构体实例。它从栈中弹出字段值，并调用 `wasm_runtime->StructNewUninitialized` 创建一个未初始化的结构体，然后将栈中的值写入结构体的各个字段。
* **`s2s_StructNewDefault`**: 处理创建新的结构体实例并使用默认值初始化。它调用 `wasm_runtime->StructNewUninitialized` 创建一个未初始化的结构体，然后用字段类型的默认值初始化结构体的各个字段。
* **`s2s_StructGet` 系列 (e.g., `s2s_I8SStructGet`, `s2s_RefStructGet`)**: 处理获取结构体字段的值。它们从栈中弹出结构体引用，读取字段偏移量，然后从结构体内存中读取指定类型的值并压入栈中。如果结构体引用为空，则会触发陷阱。
* **`s2s_StructSet` 系列 (e.g., `s2s_I8StructSet`, `s2s_RefStructSet`)**: 处理设置结构体字段的值。它们从栈中弹出要设置的值和结构体引用，读取字段偏移量，然后将值写入结构体的指定字段。如果结构体引用为空，则会触发陷阱。
* **`s2s_ArrayNew` 系列 (e.g., `s2s_I8ArrayNew`, `s2s_RefArrayNew`)**: 处理创建新的数组实例并用给定值初始化所有元素。它从栈中弹出数组长度和初始值，调用 `wasm_runtime->ArrayNewUninitialized` 创建未初始化的数组，然后将初始值写入数组的每个元素。
* **`s2s_ArrayNewFixed`**: 处理创建新的数组实例并使用栈中的固定数量的值进行初始化。它从指令流中读取数组长度，调用 `wasm_runtime->ArrayNewUninitialized` 创建未初始化的数组，然后从栈中弹出对应数量的值并写入数组元素。
* **`s2s_ArrayNewDefault`**: 处理创建新的数组实例并使用默认值初始化所有元素。它从栈中弹出数组长度，调用 `wasm_runtime->ArrayNewUninitialized` 创建未初始化的数组，然后使用数组元素类型的默认值初始化数组的每个元素。
* **`s2s_ArrayNewSegment` 系列 (`s2s_ArrayNewData`, `s2s_ArrayNewElem`)**: 处理基于数据段或元素段创建新的数组实例。它从栈中弹出长度和偏移量，并调用 `wasm_runtime->WasmArrayNewSegment` 来创建和初始化数组。
* **`s2s_ArrayInitSegment` 系列 (`s2s_ArrayInitData`, `s2s_ArrayInitElem`)**: 处理使用数据段或元素段的数据初始化现有数组的指定部分。它从栈中弹出大小、源偏移量、目标偏移量和数组引用，并调用 `wasm_runtime->WasmArrayInitSegment` 执行初始化。
* **`s2s_ArrayLen`**: 处理获取数组的长度。它从栈中弹出数组引用，然后将数组的长度压入栈中。如果数组引用为空，则会触发陷阱。
* **`s2s_ArrayCopy`**: 处理复制数组的一部分到另一个数组。它从栈中弹出源数组、源偏移量、目标数组、目标偏移量和复制大小，并调用 `wasm_runtime->WasmArrayCopy` 执行复制。
* **`s2s_ArrayGet` 系列 (e.g., `s2s_I8SArrayGet`, `s2s_RefArrayGet`)**: 处理获取数组元素的值。它们从栈中弹出数组索引和数组引用，然后从数组内存中读取指定索引的值并压入栈中。如果数组引用为空或索引越界，则会触发陷阱。
* **`s2s_ArraySet` 系列 (e.g., `s2s_I8ArraySet`, `s2s_RefArraySet`)**: 处理设置数组元素的值。它们从栈中弹出要设置的值、数组索引和数组引用，然后将值写入数组的指定索引位置。如果数组引用为空或索引越界，则会触发陷阱。
* **`s2s_ArrayFill` 系列 (e.g., `s2s_I8ArrayFill`, `s2s_RefArrayFill`)**: 处理用给定的值填充数组的指定范围。它从栈中弹出填充大小、填充值、偏移量和数组引用，然后将该值写入数组的指定范围内的每个元素。
* **`s2s_RefI31`**:  处理将一个 i32 值转换为 i31ref 类型。

**如果 `v8/src/wasm/interpreter/wasm-interpreter.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**

然而，提供的代码片段是 C++ 代码，以 `.cc` 结尾，因此它不是 Torque 源代码。Torque 用于定义 V8 内部的内置函数和类型，它会生成 C++ 代码。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明**

这些函数直接对应于 WebAssembly 的指令，而 WebAssembly 可以在 JavaScript 环境中运行。  例如，`s2s_StructNew` 对应于 WebAssembly 的 `struct.new` 指令，`s2s_ArrayGet` 对应于 `array.get` 指令。

假设我们有一个 WebAssembly 模块定义了一个结构体类型和一个函数来创建和访问该结构体：

```wat
(module
  (type $struct_type (struct (field i32)))
  (func $create_struct (result (ref $struct_type))
    i32.const 10
    struct.new $struct_type
  )
  (func $get_field (param $s (ref $struct_type)) (result i32)
    local.get $s
    i32.const 0
    struct.get_at $struct_type 0
  )
  (export "create_struct" (func $create_struct))
  (export "get_field" (func $get_field))
)
```

在 JavaScript 中，我们可以加载并使用这个 WebAssembly 模块：

```javascript
async function runWasm() {
  const response = await fetch('module.wasm'); // 假设 module.wasm 是上面的 wasm 代码编译后的文件
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  const createStruct = instance.exports.create_struct;
  const getField = instance.exports.get_field;

  const myStructRef = createStruct(); // 这会对应执行 wasm-interpreter.cc 中的 s2s_StructNew
  const fieldValue = getField(myStructRef); // 这会对应执行 wasm-interpreter.cc 中的 s2s_I32StructGet

  console.log(fieldValue); // 输出 10
}

runWasm();
```

在这个例子中，当 JavaScript 调用 `createStruct()` 时，WebAssembly 解释器会执行相应的 `struct.new` 指令，这会调用 `s2s_StructNew` 函数。同样，调用 `getField(myStructRef)` 会执行 `struct.get_at` 指令，从而调用 `s2s_I32StructGet`。

**如果有代码逻辑推理，请给出假设输入与输出**

以 `s2s_ArrayLen` 函数为例：

**假设输入：**

*   栈顶：一个指向 WasmArray 对象的引用，假设该数组的长度为 5。
*   `sp` 指针指向栈顶。

**代码逻辑：**

1. `pop<WasmRef>(sp, code, wasm_runtime)` 从栈顶弹出一个 `WasmRef`，该引用指向一个 WasmArray 对象。
2. `wasm_runtime->IsRefNull(array_obj)` 检查该引用是否为空。
3. `Cast<WasmArray>(*array_obj)` 将引用转换为 `WasmArray` 对象。
4. `array->length()` 获取数组的长度。
5. `push<int32_t>(sp, code, wasm_runtime, array->length())` 将数组的长度 (5) 压入栈顶。

**输出：**

*   栈顶：整数值 `5`。
*   `sp` 指针已更新，指向新的栈顶位置。

**如果涉及用户常见的编程错误，请举例说明**

许多函数中都检查了空引用 (`wasm_runtime->IsRefNull`)，这对应于用户在 WebAssembly 中常见的 **空指针解引用** 错误。例如，在 JavaScript 中与 WebAssembly 交互时，如果 WebAssembly 函数返回了一个空引用，而 JavaScript 代码没有正确处理，并尝试访问该引用的属性或调用其方法，就会导致错误。

另一个常见的错误是 **数组越界访问**。例如，`s2s_ArrayGet` 函数在访问数组元素之前会检查索引是否越界 (`index >= array->length()`)。如果 WebAssembly 代码尝试访问超出数组边界的索引，就会触发陷阱。在 JavaScript 中，这可能发生在传递错误的索引给导出的 WebAssembly 函数时。

例如，以下 WebAssembly 代码可能导致数组越界错误：

```wat
(module
  (memory (export "mem") 1)
  (data (i32.const 0) "\01\02\03\04\05")
  (func (export "get_element") (param $index i32) (result i32)
    (i32.load (i32.add (i32.const 0) (local.get $index)))
  )
)
```

在 JavaScript 中调用这个函数并传递一个超出数据段大小的索引：

```javascript
async function runWasm() {
  const response = await fetch('module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  const getElement = instance.exports.get_element;
  const value = getElement(10); // 尝试访问索引 10，超出数据段大小

  console.log(value); // 这很可能会导致一个错误
}

runWasm();
```

**这是第 8 部分，共 15 部分，请归纳一下它的功能**

作为第 8 部分，此代码片段主要负责 **实现 WebAssembly 解释器中与引用类型、结构体和数组操作相关的指令处理逻辑**。它涵盖了结构体和数组的创建、字段和元素的访问与修改、数组的复制和填充等操作。这些功能是 WebAssembly 内存模型和类型系统的重要组成部分，为 WebAssembly 模块提供了操作复杂数据结构的能力。

总而言之，此代码片段是 V8 的 WebAssembly 解释器核心执行引擎的一部分，负责将 WebAssembly 的高级指令转换为底层的操作，使得 WebAssembly 代码能够在 V8 引擎中执行。

### 提示词
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
;
  }

  NextOp();
}

/*
 * Notice that in s2s_BranchOnCastFail the branch happens when the condition is
 * false, not true, as follows:
 *
 *   > s2s_BranchOnCastFail
 *       i32: null_succeeds
 *       i32: target_type HeapType representation
 *       pop - ref
 *       i32: ref value_tye
 *       push - ref
 *       branch_offset (if CAST SUCCEEDS) --+
 *   > s2s_CopySlot                         |
 *       ....                               |
 *   > s2s_Branch (gets here if CAST FAILS) |
 *       branch_offset                      |
 *   > (next instruction) <-----------------+
 */
INSTRUCTION_HANDLER_FUNC s2s_BranchOnCastFail(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  bool null_succeeds = ReadI32(code);
  HeapType target_type(ReadI32(code));

  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
  const uint32_t ref_bitfield = ReadI32(code);
  ValueType ref_type = ValueType::FromRawBitField(ref_bitfield);
  push<WasmRef>(sp, code, wasm_runtime, ref);
  int32_t branch_offset = ReadI32(code);

  if (DoRefCast(ref, ref_type, target_type, null_succeeds, wasm_runtime)) {
    // If condition is true, jump to the 'true' branch.
    code += (branch_offset - kCodeOffsetSize);
  }

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_CallRef(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  WasmRef func_ref = pop<WasmRef>(sp, code, wasm_runtime);
  uint32_t sig_index = ReadI32(code);
  uint32_t stack_pos = ReadI32(code);
  uint32_t slot_offset = ReadI32(code);
  uint32_t ref_stack_fp_offset = ReadI32(code);
  uint32_t return_slot_offset = 0;
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution) {
    return_slot_offset = ReadI32(code);
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  if (V8_UNLIKELY(wasm_runtime->IsRefNull(func_ref))) {
    TRAP(TrapReason::kTrapNullDereference)
  }

  // This can trap.
  wasm_runtime->ExecuteCallRef(code, func_ref, sig_index, stack_pos, sp,
                               ref_stack_fp_offset, slot_offset,
                               return_slot_offset, false);
  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_ReturnCallRef(const uint8_t* code, uint32_t* sp,
                                           WasmInterpreterRuntime* wasm_runtime,
                                           int64_t r0, double fp0) {
  uint32_t rets_size = ReadI32(code);
  uint32_t args_size = ReadI32(code);
  uint32_t rets_refs = ReadI32(code);
  uint32_t args_refs = ReadI32(code);

  WasmRef func_ref = pop<WasmRef>(sp, code, wasm_runtime);
  uint32_t sig_index = ReadI32(code);
  uint32_t stack_pos = ReadI32(code);
  uint32_t slot_offset = ReadI32(code);
  uint32_t ref_stack_fp_offset = ReadI32(code);
  uint32_t return_slot_offset = 0;
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution) {
    return_slot_offset = ReadI32(code);
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  if (V8_UNLIKELY(wasm_runtime->IsRefNull(func_ref))) {
    TRAP(TrapReason::kTrapNullDereference)
  }

  // Moves back the stack frame to the caller stack frame.
  wasm_runtime->UnwindCurrentStackFrame(sp, slot_offset, rets_size, args_size,
                                        rets_refs, args_refs,
                                        ref_stack_fp_offset);

  // TODO(paolosev@microsoft.com) - This calls adds a new C++ stack frame, which
  // is not ideal in a tail-call.
  wasm_runtime->ExecuteCallRef(code, func_ref, sig_index, stack_pos, sp, 0, 0,
                               return_slot_offset, true);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_StructNew(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  uint32_t index = ReadI32(code);
  std::pair<Handle<WasmStruct>, const StructType*> struct_new_result =
      wasm_runtime->StructNewUninitialized(index);
  Handle<Object> struct_obj = struct_new_result.first;
  const StructType* struct_type = struct_new_result.second;

  {
    // The new struct is uninitialized, which means GC might fail until
    // initialization.
    DisallowHeapAllocation no_gc;

    for (uint32_t i = struct_type->field_count(); i > 0;) {
      i--;
      int offset = StructFieldOffset(struct_type, i);
      Address field_addr = (*struct_obj).ptr() + offset;

      ValueKind kind = struct_type->field(i).kind();
      switch (kind) {
        case kI8:
          *reinterpret_cast<int8_t*>(field_addr) =
              pop<int32_t>(sp, code, wasm_runtime);
          break;
        case kI16:
          base::WriteUnalignedValue<int16_t>(
              field_addr, pop<int32_t>(sp, code, wasm_runtime));
          break;
        case kI32:
          base::WriteUnalignedValue<int32_t>(
              field_addr, pop<int32_t>(sp, code, wasm_runtime));
          break;
        case kI64:
          base::WriteUnalignedValue<int64_t>(
              field_addr, pop<int64_t>(sp, code, wasm_runtime));
          break;
        case kF32:
          base::WriteUnalignedValue<float>(field_addr,
                                           pop<float>(sp, code, wasm_runtime));
          break;
        case kF64:
          base::WriteUnalignedValue<double>(
              field_addr, pop<double>(sp, code, wasm_runtime));
          break;
        case kS128:
          base::WriteUnalignedValue<Simd128>(
              field_addr, pop<Simd128>(sp, code, wasm_runtime));
          break;
        case kRef:
        case kRefNull: {
          WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
          base::WriteUnalignedValue<Tagged_t>(
              field_addr,
              V8HeapCompressionScheme::CompressObject((*ref).ptr()));
          break;
        }
        default:
          UNREACHABLE();
      }
    }
  }

  push<WasmRef>(sp, code, wasm_runtime, struct_obj);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_StructNewDefault(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t index = ReadI32(code);
  std::pair<Handle<WasmStruct>, const StructType*> struct_new_result =
      wasm_runtime->StructNewUninitialized(index);
  Handle<Object> struct_obj = struct_new_result.first;
  const StructType* struct_type = struct_new_result.second;

  {
    // The new struct is uninitialized, which means GC might fail until
    // initialization.
    DisallowHeapAllocation no_gc;

    for (uint32_t i = struct_type->field_count(); i > 0;) {
      i--;
      int offset = StructFieldOffset(struct_type, i);
      Address field_addr = (*struct_obj).ptr() + offset;

      const ValueType value_type = struct_type->field(i);
      const ValueKind kind = value_type.kind();
      switch (kind) {
        case kI8:
          *reinterpret_cast<int8_t*>(field_addr) = int8_t{};
          break;
        case kI16:
          base::WriteUnalignedValue<int16_t>(field_addr, int16_t{});
          break;
        case kI32:
          base::WriteUnalignedValue<int32_t>(field_addr, int32_t{});
          break;
        case kI64:
          base::WriteUnalignedValue<int64_t>(field_addr, int64_t{});
          break;
        case kF32:
          base::WriteUnalignedValue<float>(field_addr, float{});
          break;
        case kF64:
          base::WriteUnalignedValue<double>(field_addr, double{});
          break;
        case kS128:
          base::WriteUnalignedValue<Simd128>(field_addr, Simd128{});
          break;
        case kRef:
        case kRefNull:
          base::WriteUnalignedValue<Tagged_t>(
              field_addr, static_cast<Tagged_t>(
                              wasm_runtime->GetNullValue(value_type).ptr()));
          break;
        default:
          UNREACHABLE();
      }
    }
  }

  push<WasmRef>(sp, code, wasm_runtime, struct_obj);

  NextOp();
}

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_StructGet(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  WasmRef struct_obj = pop<WasmRef>(sp, code, wasm_runtime);

  if (V8_UNLIKELY(wasm_runtime->IsRefNull(struct_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  int offset = ReadI32(code);
  Address field_addr = (*struct_obj).ptr() + offset;
  push<T>(sp, code, wasm_runtime, base::ReadUnalignedValue<U>(field_addr));

  NextOp();
}
static auto s2s_I8SStructGet = s2s_StructGet<int32_t, int8_t>;
static auto s2s_I8UStructGet = s2s_StructGet<uint32_t, uint8_t>;
static auto s2s_I16SStructGet = s2s_StructGet<int32_t, int16_t>;
static auto s2s_I16UStructGet = s2s_StructGet<uint32_t, uint16_t>;
static auto s2s_I32StructGet = s2s_StructGet<int32_t>;
static auto s2s_I64StructGet = s2s_StructGet<int64_t>;
static auto s2s_F32StructGet = s2s_StructGet<float>;
static auto s2s_F64StructGet = s2s_StructGet<double>;
static auto s2s_S128StructGet = s2s_StructGet<Simd128>;

INSTRUCTION_HANDLER_FUNC s2s_RefStructGet(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  WasmRef struct_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(struct_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  int offset = ReadI32(code);
  Address field_addr = (*struct_obj).ptr() + offset;
  // DrumBrake expects pointer compression.
  Tagged_t ref_tagged = base::ReadUnalignedValue<uint32_t>(field_addr);
  Isolate* isolate = wasm_runtime->GetIsolate();
  Tagged<Object> ref_uncompressed(
      V8HeapCompressionScheme::DecompressTagged(isolate, ref_tagged));
  WasmRef ref_handle = handle(ref_uncompressed, isolate);
  push<WasmRef>(sp, code, wasm_runtime, ref_handle);

  NextOp();
}

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_StructSet(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  int offset = ReadI32(code);
  T value = pop<T>(sp, code, wasm_runtime);
  WasmRef struct_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(struct_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  Address field_addr = (*struct_obj).ptr() + offset;
  base::WriteUnalignedValue<U>(field_addr, value);

  NextOp();
}
static auto s2s_I8StructSet = s2s_StructSet<int32_t, int8_t>;
static auto s2s_I16StructSet = s2s_StructSet<int32_t, int16_t>;
static auto s2s_I32StructSet = s2s_StructSet<int32_t>;
static auto s2s_I64StructSet = s2s_StructSet<int64_t>;
static auto s2s_F32StructSet = s2s_StructSet<float>;
static auto s2s_F64StructSet = s2s_StructSet<double>;
static auto s2s_S128StructSet = s2s_StructSet<Simd128>;

INSTRUCTION_HANDLER_FUNC s2s_RefStructSet(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  int offset = ReadI32(code);
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
  WasmRef struct_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(struct_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  Address field_addr = (*struct_obj).ptr() + offset;
  base::WriteUnalignedValue<Tagged_t>(
      field_addr, V8HeapCompressionScheme::CompressObject((*ref).ptr()));

  NextOp();
}

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_ArrayNew(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  const uint32_t array_index = ReadI32(code);
  const uint32_t elem_count = pop<int32_t>(sp, code, wasm_runtime);
  const T value = pop<T>(sp, code, wasm_runtime);

  std::pair<Handle<WasmArray>, const ArrayType*> array_new_result =
      wasm_runtime->ArrayNewUninitialized(elem_count, array_index);
  Handle<WasmArray> array = array_new_result.first;
  if (V8_UNLIKELY(array.is_null())) {
    TRAP(TrapReason::kTrapArrayTooLarge)
  }

  {
    // The new array is uninitialized, which means GC might fail until
    // initialization.
    DisallowHeapAllocation no_gc;

    const ArrayType* array_type = array_new_result.second;
    const ValueKind kind = array_type->element_type().kind();
    const uint32_t element_size = value_kind_size(kind);
    DCHECK_EQ(element_size, sizeof(U));

    Address element_addr = array->ElementAddress(0);
    for (uint32_t i = 0; i < elem_count; i++) {
      base::WriteUnalignedValue<U>(element_addr, value);
      element_addr += element_size;
    }
  }

  push<WasmRef>(sp, code, wasm_runtime, array);

  NextOp();
}
static auto s2s_I8ArrayNew = s2s_ArrayNew<int32_t, int8_t>;
static auto s2s_I16ArrayNew = s2s_ArrayNew<int32_t, int16_t>;
static auto s2s_I32ArrayNew = s2s_ArrayNew<int32_t>;
static auto s2s_I64ArrayNew = s2s_ArrayNew<int64_t>;
static auto s2s_F32ArrayNew = s2s_ArrayNew<float>;
static auto s2s_F64ArrayNew = s2s_ArrayNew<double>;
static auto s2s_S128ArrayNew = s2s_ArrayNew<Simd128>;

INSTRUCTION_HANDLER_FUNC s2s_RefArrayNew(const uint8_t* code, uint32_t* sp,
                                         WasmInterpreterRuntime* wasm_runtime,
                                         int64_t r0, double fp0) {
  const uint32_t array_index = ReadI32(code);
  const uint32_t elem_count = pop<int32_t>(sp, code, wasm_runtime);
  const WasmRef value = pop<WasmRef>(sp, code, wasm_runtime);

  std::pair<Handle<WasmArray>, const ArrayType*> array_new_result =
      wasm_runtime->ArrayNewUninitialized(elem_count, array_index);
  Handle<WasmArray> array = array_new_result.first;
  if (V8_UNLIKELY(array.is_null())) {
    TRAP(TrapReason::kTrapArrayTooLarge)
  }

#if DEBUG
  const ArrayType* array_type = array_new_result.second;
  DCHECK_EQ(value_kind_size(array_type->element_type().kind()),
            sizeof(Tagged_t));
#endif

  {
    // The new array is uninitialized, which means GC might fail until
    // initialization.
    DisallowHeapAllocation no_gc;

    Address element_addr = array->ElementAddress(0);
    for (uint32_t i = 0; i < elem_count; i++) {
      base::WriteUnalignedValue<Tagged_t>(
          element_addr,
          V8HeapCompressionScheme::CompressObject((*value).ptr()));
      element_addr += sizeof(Tagged_t);
    }
  }

  push<WasmRef>(sp, code, wasm_runtime, array);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_ArrayNewFixed(const uint8_t* code, uint32_t* sp,
                                           WasmInterpreterRuntime* wasm_runtime,
                                           int64_t r0, double fp0) {
  const uint32_t array_index = ReadI32(code);
  const uint32_t elem_count = ReadI32(code);

  std::pair<Handle<WasmArray>, const ArrayType*> array_new_result =
      wasm_runtime->ArrayNewUninitialized(elem_count, array_index);
  Handle<WasmArray> array = array_new_result.first;
  if (V8_UNLIKELY(array.is_null())) {
    TRAP(TrapReason::kTrapArrayTooLarge)
  }

  {
    // The new array is uninitialized, which means GC might fail until
    // initialization.
    DisallowHeapAllocation no_gc;

    if (elem_count > 0) {
      const ArrayType* array_type = array_new_result.second;
      const ValueKind kind = array_type->element_type().kind();
      const uint32_t element_size = value_kind_size(kind);

      Address element_addr = array->ElementAddress(elem_count - 1);
      for (uint32_t i = 0; i < elem_count; i++) {
        switch (kind) {
          case kI8:
            *reinterpret_cast<int8_t*>(element_addr) =
                pop<int32_t>(sp, code, wasm_runtime);
            break;
          case kI16:
            base::WriteUnalignedValue<int16_t>(
                element_addr, pop<int32_t>(sp, code, wasm_runtime));
            break;
          case kI32:
            base::WriteUnalignedValue<int32_t>(
                element_addr, pop<int32_t>(sp, code, wasm_runtime));
            break;
          case kI64:
            base::WriteUnalignedValue<int64_t>(
                element_addr, pop<int64_t>(sp, code, wasm_runtime));
            break;
          case kF32:
            base::WriteUnalignedValue<float>(
                element_addr, pop<float>(sp, code, wasm_runtime));
            break;
          case kF64:
            base::WriteUnalignedValue<double>(
                element_addr, pop<double>(sp, code, wasm_runtime));
            break;
          case kS128:
            base::WriteUnalignedValue<Simd128>(
                element_addr, pop<Simd128>(sp, code, wasm_runtime));
            break;
          case kRef:
          case kRefNull: {
            WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
            base::WriteUnalignedValue<Tagged_t>(
                element_addr,
                V8HeapCompressionScheme::CompressObject((*ref).ptr()));
            break;
          }
          default:
            UNREACHABLE();
        }
        element_addr -= element_size;
      }
    }
  }

  push<WasmRef>(sp, code, wasm_runtime, array);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC
s2s_ArrayNewDefault(const uint8_t* code, uint32_t* sp,
                    WasmInterpreterRuntime* wasm_runtime, int64_t r0,
                    double fp0) {
  const uint32_t array_index = ReadI32(code);
  const uint32_t elem_count = pop<int32_t>(sp, code, wasm_runtime);

  std::pair<Handle<WasmArray>, const ArrayType*> array_new_result =
      wasm_runtime->ArrayNewUninitialized(elem_count, array_index);
  Handle<WasmArray> array = array_new_result.first;
  if (V8_UNLIKELY(array.is_null())) {
    TRAP(TrapReason::kTrapArrayTooLarge)
  }

  {
    // The new array is uninitialized, which means GC might fail until
    // initialization.
    DisallowHeapAllocation no_gc;

    const ArrayType* array_type = array_new_result.second;
    const ValueType element_type = array_type->element_type();
    const ValueKind kind = element_type.kind();
    const uint32_t element_size = value_kind_size(kind);

    Address element_addr = array->ElementAddress(0);
    for (uint32_t i = 0; i < elem_count; i++) {
      switch (kind) {
        case kI8:
          *reinterpret_cast<int8_t*>(element_addr) = int8_t{};
          break;
        case kI16:
          base::WriteUnalignedValue<int16_t>(element_addr, int16_t{});
          break;
        case kI32:
          base::WriteUnalignedValue<int32_t>(element_addr, int32_t{});
          break;
        case kI64:
          base::WriteUnalignedValue<int64_t>(element_addr, int64_t{});
          break;
        case kF32:
          base::WriteUnalignedValue<float>(element_addr, float{});
          break;
        case kF64:
          base::WriteUnalignedValue<double>(element_addr, double{});
          break;
        case kS128:
          base::WriteUnalignedValue<Simd128>(element_addr, Simd128{});
          break;
        case kRef:
        case kRefNull:
          base::WriteUnalignedValue<Tagged_t>(
              element_addr,
              static_cast<Tagged_t>(
                  wasm_runtime->GetNullValue(element_type).ptr()));
          break;
        default:
          UNREACHABLE();
      }
      element_addr += element_size;
    }
  }

  push<WasmRef>(sp, code, wasm_runtime, array);

  NextOp();
}

template <TrapReason OutOfBoundsError>
INSTRUCTION_HANDLER_FUNC s2s_ArrayNewSegment(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  const uint32_t array_index = ReadI32(code);
  // TODO(paolosev@microsoft.com): already validated?
  if (V8_UNLIKELY(!Smi::IsValid(array_index))) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  const uint32_t data_index = ReadI32(code);
  // TODO(paolosev@microsoft.com): already validated?
  if (V8_UNLIKELY(!Smi::IsValid(data_index))) {
    TRAP(OutOfBoundsError)
  }

  uint32_t length = pop<int32_t>(sp, code, wasm_runtime);
  uint32_t offset = pop<int32_t>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(!Smi::IsValid(offset))) {
    TRAP(OutOfBoundsError)
  }
  if (V8_UNLIKELY(length >= static_cast<uint32_t>(WasmArray::MaxLength(
                                wasm_runtime->GetArrayType(array_index))))) {
    TRAP(TrapReason::kTrapArrayTooLarge)
  }

  WasmRef result = wasm_runtime->WasmArrayNewSegment(array_index, data_index,
                                                     offset, length);
  if (V8_UNLIKELY(result.is_null())) {
    wasm::TrapReason reason = WasmInterpreterThread::GetRuntimeLastWasmError(
        wasm_runtime->GetIsolate());
    INLINED_TRAP(reason)
  }
  push<WasmRef>(sp, code, wasm_runtime, result);

  NextOp();
}
// The instructions array.new_data and array.new_elem have the same
// implementation after validation. The only difference is that array.init_elem
// is used with arrays that contain elements of reference types, and
// array.init_data with arrays that contain elements of numeric types.
static auto s2s_ArrayNewData = s2s_ArrayNewSegment<kTrapDataSegmentOutOfBounds>;
static auto s2s_ArrayNewElem =
    s2s_ArrayNewSegment<kTrapElementSegmentOutOfBounds>;

template <bool init_data>
INSTRUCTION_HANDLER_FUNC s2s_ArrayInitSegment(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  const uint32_t array_index = ReadI32(code);
  // TODO(paolosev@microsoft.com): already validated?
  if (V8_UNLIKELY(!Smi::IsValid(array_index))) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  const uint32_t data_index = ReadI32(code);
  // TODO(paolosev@microsoft.com): already validated?
  if (V8_UNLIKELY(!Smi::IsValid(data_index))) {
    TRAP(TrapReason::kTrapElementSegmentOutOfBounds)
  }

  uint32_t size = pop<int32_t>(sp, code, wasm_runtime);
  uint32_t src_offset = pop<int32_t>(sp, code, wasm_runtime);
  uint32_t dest_offset = pop<int32_t>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(!Smi::IsValid(size)) || !Smi::IsValid(dest_offset)) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }
  if (V8_UNLIKELY(!Smi::IsValid(src_offset))) {
    TrapReason reason = init_data ? TrapReason::kTrapDataSegmentOutOfBounds
                                  : TrapReason::kTrapElementSegmentOutOfBounds;
    INLINED_TRAP(reason);
  }

  WasmRef array = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(array))) {
    TRAP(TrapReason::kTrapNullDereference)
  }

  bool ok = wasm_runtime->WasmArrayInitSegment(data_index, array, dest_offset,
                                               src_offset, size);
  if (V8_UNLIKELY(!ok)) {
    TrapReason reason = WasmInterpreterThread::GetRuntimeLastWasmError(
        wasm_runtime->GetIsolate());
    INLINED_TRAP(reason)
  }

  NextOp();
}
// The instructions array.init_data and array.init_elem have the same
// implementation after validation. The only difference is that array.init_elem
// is used with arrays that contain elements of reference types, and
// array.init_data with arrays that contain elements of numeric types.
static auto s2s_ArrayInitData = s2s_ArrayInitSegment<true>;
static auto s2s_ArrayInitElem = s2s_ArrayInitSegment<false>;

INSTRUCTION_HANDLER_FUNC s2s_ArrayLen(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  WasmRef array_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(array_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  DCHECK(IsWasmArray(*array_obj));

  Tagged<WasmArray> array = Cast<WasmArray>(*array_obj);
  push<int32_t>(sp, code, wasm_runtime, array->length());

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_ArrayCopy(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  const uint32_t dest_array_index = ReadI32(code);
  const uint32_t src_array_index = ReadI32(code);
  // TODO(paolosev@microsoft.com): already validated?
  if (V8_UNLIKELY(!Smi::IsValid(dest_array_index) ||
                  !Smi::IsValid(src_array_index))) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  uint32_t size = pop<int32_t>(sp, code, wasm_runtime);
  uint32_t src_offset = pop<int32_t>(sp, code, wasm_runtime);
  WasmRef src_array = pop<WasmRef>(sp, code, wasm_runtime);
  uint32_t dest_offset = pop<int32_t>(sp, code, wasm_runtime);
  WasmRef dest_array = pop<WasmRef>(sp, code, wasm_runtime);

  if (V8_UNLIKELY(!Smi::IsValid(src_offset)) || !Smi::IsValid(dest_offset)) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  } else if (V8_UNLIKELY(wasm_runtime->IsRefNull(dest_array))) {
    TRAP(TrapReason::kTrapNullDereference)
  } else if (V8_UNLIKELY(dest_offset + size >
                         Cast<WasmArray>(*dest_array)->length())) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  } else if (V8_UNLIKELY(wasm_runtime->IsRefNull(src_array))) {
    TRAP(TrapReason::kTrapNullDereference)
  } else if (V8_UNLIKELY(src_offset + size >
                         Cast<WasmArray>(*src_array)->length())) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  bool ok = true;
  if (size > 0) {
    ok = wasm_runtime->WasmArrayCopy(dest_array, dest_offset, src_array,
                                     src_offset, size);
  }

  if (V8_UNLIKELY(!ok)) {
    wasm::TrapReason reason = WasmInterpreterThread::GetRuntimeLastWasmError(
        wasm_runtime->GetIsolate());
    INLINED_TRAP(reason)
  }

  NextOp();
}

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_ArrayGet(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  uint32_t index = pop<uint32_t>(sp, code, wasm_runtime);
  WasmRef array_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(array_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  DCHECK(IsWasmArray(*array_obj));

  Tagged<WasmArray> array = Cast<WasmArray>(*array_obj);
  if (V8_UNLIKELY(index >= array->length())) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  Address element_addr = array->ElementAddress(index);
  push<T>(sp, code, wasm_runtime, base::ReadUnalignedValue<U>(element_addr));

  NextOp();
}
static auto s2s_I8SArrayGet = s2s_ArrayGet<int32_t, int8_t>;
static auto s2s_I8UArrayGet = s2s_ArrayGet<uint32_t, uint8_t>;
static auto s2s_I16SArrayGet = s2s_ArrayGet<int32_t, int16_t>;
static auto s2s_I16UArrayGet = s2s_ArrayGet<uint32_t, uint16_t>;
static auto s2s_I32ArrayGet = s2s_ArrayGet<int32_t>;
static auto s2s_I64ArrayGet = s2s_ArrayGet<int64_t>;
static auto s2s_F32ArrayGet = s2s_ArrayGet<float>;
static auto s2s_F64ArrayGet = s2s_ArrayGet<double>;
static auto s2s_S128ArrayGet = s2s_ArrayGet<Simd128>;

INSTRUCTION_HANDLER_FUNC s2s_RefArrayGet(const uint8_t* code, uint32_t* sp,
                                         WasmInterpreterRuntime* wasm_runtime,
                                         int64_t r0, double fp0) {
  uint32_t index = pop<uint32_t>(sp, code, wasm_runtime);
  WasmRef array_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(array_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  DCHECK(IsWasmArray(*array_obj));

  Tagged<WasmArray> array = Cast<WasmArray>(*array_obj);
  if (V8_UNLIKELY(index >= array->length())) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  push<WasmRef>(sp, code, wasm_runtime,
                wasm_runtime->GetWasmArrayRefElement(array, index));

  NextOp();
}

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_ArraySet(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  const T value = pop<T>(sp, code, wasm_runtime);
  const uint32_t index = pop<uint32_t>(sp, code, wasm_runtime);
  WasmRef array_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(array_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  DCHECK(IsWasmArray(*array_obj));

  Tagged<WasmArray> array = Cast<WasmArray>(*array_obj);
  if (V8_UNLIKELY(index >= array->length())) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  Address element_addr = array->ElementAddress(index);
  base::WriteUnalignedValue<U>(element_addr, value);

  NextOp();
}
static auto s2s_I8ArraySet = s2s_ArraySet<int32_t, int8_t>;
static auto s2s_I16ArraySet = s2s_ArraySet<int32_t, int16_t>;
static auto s2s_I32ArraySet = s2s_ArraySet<int32_t>;
static auto s2s_I64ArraySet = s2s_ArraySet<int64_t>;
static auto s2s_F32ArraySet = s2s_ArraySet<float>;
static auto s2s_F64ArraySet = s2s_ArraySet<double>;
static auto s2s_S128ArraySet = s2s_ArraySet<Simd128>;

INSTRUCTION_HANDLER_FUNC s2s_RefArraySet(const uint8_t* code, uint32_t* sp,
                                         WasmInterpreterRuntime* wasm_runtime,
                                         int64_t r0, double fp0) {
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
  const uint32_t index = pop<uint32_t>(sp, code, wasm_runtime);
  WasmRef array_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(array_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  DCHECK(IsWasmArray(*array_obj));

  Tagged<WasmArray> array = Cast<WasmArray>(*array_obj);
  if (V8_UNLIKELY(index >= array->length())) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  Address element_addr = array->ElementAddress(index);
  base::WriteUnalignedValue<Tagged_t>(
      element_addr, V8HeapCompressionScheme::CompressObject((*ref).ptr()));

  NextOp();
}

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_ArrayFill(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  uint32_t size = pop<uint32_t>(sp, code, wasm_runtime);
  T value = pop<U>(sp, code, wasm_runtime);
  uint32_t offset = pop<uint32_t>(sp, code, wasm_runtime);

  WasmRef array_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(array_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  DCHECK(IsWasmArray(*array_obj));

  Tagged<WasmArray> array = Cast<WasmArray>(*array_obj);
  if (V8_UNLIKELY(static_cast<uint64_t>(offset) + size > array->length())) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  Address element_addr = array->ElementAddress(offset);
  for (uint32_t i = 0; i < size; i++) {
    base::WriteUnalignedValue<T>(element_addr, value);
    element_addr += sizeof(T);
  }

  NextOp();
}
static auto s2s_I8ArrayFill = s2s_ArrayFill<int8_t, int32_t>;
static auto s2s_I16ArrayFill = s2s_ArrayFill<int16_t, int32_t>;
static auto s2s_I32ArrayFill = s2s_ArrayFill<int32_t>;
static auto s2s_I64ArrayFill = s2s_ArrayFill<int64_t>;
static auto s2s_F32ArrayFill = s2s_ArrayFill<float>;
static auto s2s_F64ArrayFill = s2s_ArrayFill<double>;
static auto s2s_S128ArrayFill = s2s_ArrayFill<Simd128>;

INSTRUCTION_HANDLER_FUNC s2s_RefArrayFill(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  // DrumBrake currently only works with pointer compression.
  static_assert(COMPRESS_POINTERS_BOOL);

  uint32_t size = pop<uint32_t>(sp, code, wasm_runtime);
  WasmRef value = pop<WasmRef>(sp, code, wasm_runtime);
  Tagged<Object> tagged_value = *value;
  uint32_t offset = pop<uint32_t>(sp, code, wasm_runtime);

  WasmRef array_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(array_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  DCHECK(IsWasmArray(*array_obj));

  Tagged<WasmArray> array = Cast<WasmArray>(*array_obj);
  if (V8_UNLIKELY(static_cast<uint64_t>(offset) + size > array->length())) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  Address element_addr = array->ElementAddress(offset);
  for (uint32_t i = 0; i < size; i++) {
    // Only stores the lower 32-bit.
    base::WriteUnalignedValue<Tagged_t>(
        element_addr, static_cast<Tagged_t>(tagged_value.ptr()));
    element_addr += kTaggedSize;
  }

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_RefI31(const uint8_t* code, uint32_t* sp,
                                    WasmInterpreterRuntime* wasm_runtime,
                                    int64_t r0, double fp0) {
  uint32_t value = pop<int32_t>(sp, code, wasm_runtime);

  // Trunc
```