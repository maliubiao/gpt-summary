Response:
Let's break down the thought process for analyzing this V8 code snippet.

1. **Initial Scan and High-Level Understanding:**  The first step is a quick read-through to grasp the general purpose. Keywords like `MemoryAddressToUintPtrOrOOBTrap`, `ChangeUint31ToSmi`, `BuildLoadWasmCodeEntrypointViaCodePointer`, `UnpackWasmException`, `AsmjsStoreMem`, `BoundsCheckArray`, `BrOnCastImpl`, `ArrayNewImpl`, `StructNewImpl`, `InlineWasmCall`, etc., immediately suggest operations related to WebAssembly (Wasm) and its interaction with the underlying system. The file name `turboshaft-graph-interface.cc` reinforces this, pointing towards the Turboshaft compiler pipeline within V8. The presence of `FullDecoder` as an argument to many functions further suggests this code is involved in processing or interpreting Wasm bytecode.

2. **Identifying Key Functional Areas:** After the initial scan, we can start grouping related functions and identify the major functionalities. The functions seem to fall into several categories:

    * **Address Manipulation:**  Functions like `MemOrTableAddressToUintPtrOrOOBTrap`, `MemoryAddressToUintPtrOrOOBTrap`, `TableAddressToUintPtrOrOOBTrap`, `ChangeUint31ToSmi`, `ChangeSmiToUint32` are clearly dealing with converting between different types of addresses and integers, including handling potential out-of-bounds access.

    * **Exception Handling:**  `BuildEncodeException32BitValue`, `BuildDecodeException32BitValue`, `BuildDecodeException64BitValue`, `UnpackWasmException`, `ThrowRef` are directly related to Wasm exception processing.

    * **Memory Access (Wasm and Asm.js):** `AsmjsStoreMem`, `AsmjsLoadMem` handle memory operations specifically for Asm.js, while others like `StoreInInt64StackSlot` are more general.

    * **Array and Struct Operations:** `BoundsCheckArray`, `BoundsCheckArrayWithLength`, `ArrayNewImpl`, `ArrayFillImpl`, `StructNewImpl`, `StructSet` deal with creating, accessing, and manipulating Wasm arrays and structs.

    * **Type Casting and Checks:** `BrOnCastImpl`, `BrOnCastFailImpl`, `WasmTypeCheck` are involved in handling Wasm's type system, particularly during casting operations.

    * **Function Calls and Inlining:**  `BuildLoadWasmCodeEntrypointViaCodePointer`, `InlineWasmCall`, `BuildWasmMaybeReturnCall`, `BuildWasmCall` are core to managing function calls within the Wasm environment, including the complex process of inlining.

    * **Utility Functions:**  Functions like `IsSimd128ZeroConstant`, `InlineTargetIsTypeCompatible`, `GetTrapIdForTrap`, and the `WasmPositionToOpIndex`/`OpIndexToSourcePosition` pair provide supporting functionalities.

3. **Analyzing Specific Functions and Code Snippets:**  Now, we delve into the details of individual functions. For example, the `MemOrTableAddressToUintPtrOrOOBTrap` function's logic with `AddressType::kI32` and the 64-bit check is important. The bit manipulation in `ChangeUint31ToSmi` and `ChangeSmiToUint32` relates to V8's Smi (small integer) representation. The `BuildLoadWasmCodeEntrypointViaCodePointer` function with the `#ifdef V8_ENABLE_SANDBOX` highlights a security-related mechanism. The `UnpackWasmException` function's switch statement clearly shows how different Wasm value types are extracted from the exception object.

4. **Considering Edge Cases and Potential Errors:**  As we analyze, we should consider potential issues. The "OOBTrap" functions immediately bring up the concept of out-of-bounds errors. The Asm.js memory access functions have comments about alignment and bounds checking. The `BoundsCheckArray` functions explicitly mention skipping checks in experimental modes. The inlining logic has comments about shared modules and validation.

5. **Connecting to JavaScript (If Applicable):**  The prompt specifically asks for JavaScript examples. We need to think about how the Wasm features being implemented here would be exposed or interact with JavaScript. For instance, Wasm memory access corresponds to `WebAssembly.Memory`, exceptions to `try...catch` blocks with Wasm exceptions, arrays to `WebAssembly.Array`, and structs to `WebAssembly.Struct`.

6. **Inferring Data Structures and Concepts:**  The code uses types like `V<Word>`, `V<Word32>`, `V<Smi>`, `V<FixedArray>`, `V<WasmArray>`, `V<WasmStruct>`, `OpIndex`. We can infer that `V<>` is likely a template for representing values within the Turboshaft graph, and these specific instantiations represent different data types used in Wasm and V8's internal representation. Concepts like `TrapId`, `AddressType`, `MemoryRepresentation`, `BuiltinCallDescriptor`, `FullDecoder`, `InstanceCache`, `InliningTree`, and `BlockPhis` emerge as important components of the Wasm compilation and execution process.

7. **Synthesizing the Information:** Finally, we synthesize all the gathered information into a structured summary, addressing each point of the prompt. We list the functionalities, explain the `.tq` check, provide JavaScript examples, illustrate code logic with input/output, highlight common programming errors, and summarize the overall purpose of the file within the context of Turboshaft and Wasm compilation. The fact that this is "part 11 of 12" suggests it's a component nearing the end of a larger process, likely focusing on the final stages of code generation or integration within the Turboshaft pipeline.

8. **Refinement and Iteration:**  The initial analysis might not be perfect. We might need to go back and re-examine certain functions or code sections if our understanding is incomplete or inconsistent. For example, the inlining logic is quite complex and might require multiple passes to fully grasp. We also double-check if we've addressed all parts of the prompt.
好的，根据你提供的代码片段，让我们来分析一下 `v8/src/wasm/turboshaft-graph-interface.cc` 的功能。

**功能列举:**

这个代码文件定义了一个用于在 Turboshaft 编译器的图形表示中构建 WebAssembly (Wasm) 操作的接口。它提供了一系列方法，用于执行各种 Wasm 特有的操作，包括但不限于：

1. **内存和表操作:**
   - 计算内存和表的有效地址，并处理越界陷阱 (`MemOrTableAddressToUintPtrOrOOBTrap`, `MemoryAddressToUintPtrOrOOBTrap`, `TableAddressToUintPtrOrOOBTrap`).
   - 将索引转换为指针 (`ChangeUint32ToUintPtr`).

2. **Smi（小整数）转换:**
   - 在无符号 31 位整数和 Smi 之间进行转换 (`ChangeUint31ToSmi`, `ChangeSmiToUint32`). 这与 V8 内部对小整数的优化表示有关。

3. **加载 Wasm 代码入口点:**
   -  通过代码指针句柄构建加载 Wasm 代码入口点的操作 (`BuildLoadWasmCodeEntrypointViaCodePointer`)。这部分代码在启用了沙箱模式时使用。

4. **异常处理:**
   - 对 32 位和 64 位异常值进行编码和解码，用于在 Wasm 和 JavaScript 之间传递异常信息 (`BuildEncodeException32BitValue`, `BuildDecodeException32BitValue`, `BuildDecodeException64BitValue`).
   - 解包 Wasm 异常 (`UnpackWasmException`)，将异常对象中的值提取出来。
   - 抛出引用类型的异常 (`ThrowRef`).

5. **Asm.js 互操作:**
   - 提供与 Asm.js 内存操作相关的指令 (`AsmjsStoreMem`, `AsmjsLoadMem`)，需要注意 Asm.js 不支持非对齐访问。

6. **数组操作:**
   - 进行数组的边界检查 (`BoundsCheckArray`, `BoundsCheckArrayWithLength`).
   - 创建新的数组并初始化元素 (`ArrayNewImpl`).
   - 填充数组元素 (`ArrayFillImpl`).

7. **结构体操作:**
   - 创建新的结构体并设置字段值 (`StructNewImpl`).

8. **类型转换和检查:**
   - 实现带分支的类型转换操作 (`BrOnCastImpl`, `BrOnCastFailImpl`)，用于安全地将对象转换为特定类型。

9. **内联 Wasm 调用:**
   -  支持内联 Wasm 函数调用 (`InlineWasmCall`)，这是一种性能优化手段，将目标函数的代码插入到调用者中。

10. **辅助工具函数:**
    - 判断 SIMD128 常量是否为零 (`IsSimd128ZeroConstant`).
    - 检查内联目标是否类型兼容 (`InlineTargetIsTypeCompatible`).
    - 获取 Wasm 陷阱原因对应的 `TrapId` (`GetTrapIdForTrap`).
    - 在 `OpIndex` 中编码和解码 Wasm 代码位置和内联 ID (`WasmPositionToOpIndex`, `OpIndexToSourcePosition`).
    - 获取分支提示 (`GetBranchHint`).

**关于文件后缀和 Torque:**

如果 `v8/src/wasm/turboshaft-graph-interface.cc` 的文件后缀是 `.tq`，那么它才是一个 V8 Torque 源代码。当前的 `.cc` 后缀表明它是 C++ 代码。Torque 是一种 V8 自研的类型化的中间语言，用于生成高效的 C++ 代码。

**与 JavaScript 的关系 (举例):**

这个文件中的功能是 Wasm 虚拟机实现的底层部分，JavaScript 通过 `WebAssembly` API 与 Wasm 进行交互。

例如，Wasm 代码中如果发生了越界内存访问，`MemOrTableAddressToUintPtrOrOOBTrap` 等函数会生成相应的陷阱操作。在 JavaScript 层面，这可能会导致一个 `WebAssembly.RuntimeError` 被抛出：

```javascript
const memory = new WebAssembly.Memory({ initial: 1 });
const buffer = new Uint8Array(memory.buffer);

try {
  // 尝试访问超出内存范围的地址
  buffer[65536] = 10;
} catch (e) {
  console.error("捕获到 WebAssembly 运行时错误:", e); // 可能输出: RangeError: Index out of bounds
}
```

再例如，Wasm 的异常处理机制与 JavaScript 的 `try...catch` 块相对应。`UnpackWasmException` 等函数负责在 Wasm 抛出异常时，将异常信息传递给 JavaScript。

```javascript
// 假设有一个导出的 Wasm 函数会抛出异常
const instance = await WebAssembly.instantiateStreaming(fetch('module.wasm'));
const wasmFunc = instance.exports.throwingFunction;

try {
  wasmFunc();
} catch (e) {
  console.error("捕获到 Wasm 异常:", e);
  // 这里的 e 可能是一个包含 Wasm 异常信息的对象
}
```

**代码逻辑推理 (假设输入与输出):**

假设我们调用 `MemOrTableAddressToUintPtrOrOOBTrap` 函数，其 `address_type` 为 `AddressType::kI32`，`index` 是一个 `V<Word32>` 类型的操作数，代表值 `1024`。

**假设输入:**
- `address_type`: `AddressType::kI32`
- `index`:  表示值 `1024` 的 `V<Word32>` 操作数

**预期输出:**
- 返回一个 `V<WordPtr>` 操作数，其值是指向内存地址 `1024` 的指针（经过适当的转换，例如左移）。如果 `index` 超出内存或表的大小，则会生成一个陷阱操作。

**用户常见的编程错误 (举例):**

1. **内存越界访问:**  这是 Wasm 中最常见的错误之一。例如，在 JavaScript 中创建了一个 `WebAssembly.Memory`，但在 Wasm 代码中访问了超出其分配范围的地址。Turboshaft 生成的代码会包含边界检查，但如果检查失败，就会导致陷阱。

   ```c++
   // Wasm 代码 (伪代码)
   (memory.store i32 offset: (i32.const 1000000) value: (i32.const 10))
   ```

   如果 `memory` 的大小不足以容纳偏移量 `1000000` 的写入，就会触发内存越界陷阱。

2. **类型错误:**  在进行类型转换时，如果没有进行正确的类型检查，可能会导致类型错误。例如，尝试将一个不兼容的对象强制转换为特定的 Wasm 引用类型。`BrOnCastImpl` 和 `BrOnCastFailImpl` 等函数旨在帮助安全地处理这些转换，但如果 Wasm 代码逻辑不正确，仍然可能出错。

   ```c++
   // Wasm 代码 (伪代码)
   (local.get $obj)
   (br_on_cast $rtt_subtype 0 (local.get $obj)) // 尝试将 $obj 转换为 $rtt_subtype
   ;; 如果转换失败，会继续执行这里的代码，可能导致类型错误
   ```

**功能归纳 (作为第 11 部分，共 12 部分):**

作为 Turboshaft 编译流程的第 11 部分，`v8/src/wasm/turboshaft-graph-interface.cc` 的主要功能是 **提供构建 Wasm 虚拟机操作的最终接口**。 在编译的这个阶段，Turboshaft 已经完成了对 Wasm 代码的分析和优化，现在需要将抽象的 Wasm 指令转换为具体的、可以在目标架构上执行的操作。

这个文件定义了用于表示这些操作的图形节点，并提供了创建这些节点的工具。它封装了与内存访问、类型转换、异常处理、函数调用等相关的底层细节，使得编译器的后续阶段（例如代码生成）可以基于这些图形表示生成最终的机器码。

考虑到这是倒数第二个部分，可以推测第 12 部分很可能涉及 **将 Turboshaft 图形表示转换为实际的机器码**，或者进行最后的代码优化和布局。 这个文件是连接 Wasm 语义和底层机器指令的关键桥梁。

Prompt: 
```
这是目录为v8/src/wasm/turboshaft-graph-interface.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/turboshaft-graph-interface.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第11部分，共12部分，请归纳一下它的功能

"""
 can cause the high
    // word of what's supposed to be an i32 to be non-zero).
    if (address_type == AddressType::kI32) {
      return __ ChangeUint32ToUintPtr(V<Word32>::Cast(index));
    }
    if constexpr (Is64()) {
      return V<WordPtr>::Cast(index);
    }
    __ TrapIf(__ TruncateWord64ToWord32(
                  __ Word64ShiftRightLogical(V<Word64>::Cast(index), 32)),
              OpIndex::Invalid(), trap_reason);
    return V<WordPtr>::Cast(__ TruncateWord64ToWord32(V<Word64>::Cast(index)));
  }

  V<WordPtr> MemoryAddressToUintPtrOrOOBTrap(AddressType address_type,
                                             V<Word> index) {
    return MemOrTableAddressToUintPtrOrOOBTrap(address_type, index,
                                               TrapId::kTrapMemOutOfBounds);
  }

  V<WordPtr> TableAddressToUintPtrOrOOBTrap(AddressType address_type,
                                            V<Word> index) {
    return MemOrTableAddressToUintPtrOrOOBTrap(address_type, index,
                                               TrapId::kTrapTableOutOfBounds);
  }

  V<Smi> ChangeUint31ToSmi(V<Word32> value) {
    if constexpr (COMPRESS_POINTERS_BOOL) {
      return V<Smi>::Cast(
          __ Word32ShiftLeft(value, kSmiShiftSize + kSmiTagSize));
    } else {
      return V<Smi>::Cast(__ WordPtrShiftLeft(__ ChangeUint32ToUintPtr(value),
                                              kSmiShiftSize + kSmiTagSize));
    }
  }

  V<Word32> ChangeSmiToUint32(V<Smi> value) {
    if constexpr (COMPRESS_POINTERS_BOOL) {
      return __ Word32ShiftRightLogical(V<Word32>::Cast(value),
                                        kSmiShiftSize + kSmiTagSize);
    } else {
      return __ TruncateWordPtrToWord32(__ WordPtrShiftRightLogical(
          V<WordPtr>::Cast(value), kSmiShiftSize + kSmiTagSize));
    }
  }

  V<WordPtr> BuildLoadWasmCodeEntrypointViaCodePointer(V<Word32> handle) {
#ifdef V8_ENABLE_SANDBOX
    V<Word32> index =
        __ Word32ShiftRightLogical(handle, kCodePointerHandleShift);
    V<WordPtr> offset = __ ChangeUint32ToUintPtr(
        __ Word32ShiftLeft(index, kCodePointerTableEntrySizeLog2));
    V<WordPtr> table =
        __ ExternalConstant(ExternalReference::code_pointer_table_address());
    V<WordPtr> entry = __ Load(table, offset, LoadOp::Kind::RawAligned(),
                               MemoryRepresentation::UintPtr());
    return __ Word64BitwiseXor(entry, __ UintPtrConstant(kWasmEntrypointTag));
#else
    UNREACHABLE();
#endif
  }

  void BuildEncodeException32BitValue(V<FixedArray> values_array,
                                      uint32_t index, V<Word32> value) {
    V<Smi> upper_half =
        ChangeUint31ToSmi(__ Word32ShiftRightLogical(value, 16));
    __ StoreFixedArrayElement(values_array, index, upper_half,
                              compiler::kNoWriteBarrier);
    V<Smi> lower_half = ChangeUint31ToSmi(__ Word32BitwiseAnd(value, 0xffffu));
    __ StoreFixedArrayElement(values_array, index + 1, lower_half,
                              compiler::kNoWriteBarrier);
  }

  V<Word32> BuildDecodeException32BitValue(V<FixedArray> exception_values_array,
                                           int index) {
    V<Word32> upper_half = __ Word32ShiftLeft(
        ChangeSmiToUint32(V<Smi>::Cast(
            __ LoadFixedArrayElement(exception_values_array, index))),
        16);
    V<Word32> lower_half = ChangeSmiToUint32(V<Smi>::Cast(
        __ LoadFixedArrayElement(exception_values_array, index + 1)));
    return __ Word32BitwiseOr(upper_half, lower_half);
  }

  V<Word64> BuildDecodeException64BitValue(V<FixedArray> exception_values_array,
                                           int index) {
    V<Word64> upper_half = __ Word64ShiftLeft(
        __ ChangeUint32ToUint64(
            BuildDecodeException32BitValue(exception_values_array, index)),
        32);
    V<Word64> lower_half = __ ChangeUint32ToUint64(
        BuildDecodeException32BitValue(exception_values_array, index + 2));
    return __ Word64BitwiseOr(upper_half, lower_half);
  }

  void UnpackWasmException(FullDecoder* decoder, V<Object> exception,
                           base::Vector<Value> values) {
    V<FixedArray> exception_values_array = V<FixedArray>::Cast(
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmGetOwnProperty>(
            decoder, instance_cache_.native_context(),
            {exception, LOAD_ROOT(wasm_exception_values_symbol)}));

    int index = 0;
    for (Value& value : values) {
      switch (value.type.kind()) {
        case kI32:
          value.op =
              BuildDecodeException32BitValue(exception_values_array, index);
          index += 2;
          break;
        case kI64:
          value.op =
              BuildDecodeException64BitValue(exception_values_array, index);
          index += 4;
          break;
        case kF32:
          value.op = __ BitcastWord32ToFloat32(
              BuildDecodeException32BitValue(exception_values_array, index));
          index += 2;
          break;
        case kF64:
          value.op = __ BitcastWord64ToFloat64(
              BuildDecodeException64BitValue(exception_values_array, index));
          index += 4;
          break;
        case kS128: {
          V<compiler::turboshaft::Simd128> value_s128;
          value_s128 = __ Simd128Splat(
              BuildDecodeException32BitValue(exception_values_array, index),
              compiler::turboshaft::Simd128SplatOp::Kind::kI32x4);
          index += 2;
          using Kind = compiler::turboshaft::Simd128ReplaceLaneOp::Kind;
          value_s128 = __ Simd128ReplaceLane(
              value_s128,
              BuildDecodeException32BitValue(exception_values_array, index),
              Kind::kI32x4, 1);
          index += 2;
          value_s128 = __ Simd128ReplaceLane(
              value_s128,
              BuildDecodeException32BitValue(exception_values_array, index),
              Kind::kI32x4, 2);
          index += 2;
          value.op = __ Simd128ReplaceLane(
              value_s128,
              BuildDecodeException32BitValue(exception_values_array, index),
              Kind::kI32x4, 3);
          index += 2;
          break;
        }
        case kRtt:
        case kRef:
        case kRefNull:
          value.op = __ LoadFixedArrayElement(exception_values_array, index);
          index++;
          break;
        case kI8:
        case kI16:
        case kF16:
        case kVoid:
        case kTop:
        case kBottom:
          UNREACHABLE();
      }
    }
  }

  void ThrowRef(FullDecoder* decoder, OpIndex exn) {
    CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmThrowRef>(
        decoder, {exn}, CheckForException::kCatchInThisFrame);
    __ Unreachable();
  }

  void AsmjsStoreMem(V<Word32> index, OpIndex value,
                     MemoryRepresentation repr) {
    // Since asmjs does not support unaligned accesses, we can bounds-check
    // ignoring the access size.
    // Technically, we should do a signed 32-to-ptr extension here. However,
    // that is an explicit instruction, whereas unsigned extension is implicit.
    // Since the difference is only observable for memories larger than 2 GiB,
    // and since we disallow such memories, we can use unsigned extension.
    V<WordPtr> index_ptr = __ ChangeUint32ToUintPtr(index);
    IF (LIKELY(__ UintPtrLessThan(index_ptr, MemSize(0)))) {
      __ Store(MemStart(0), index_ptr, value, StoreOp::Kind::RawAligned(), repr,
               compiler::kNoWriteBarrier, 0);
    }
  }

  OpIndex AsmjsLoadMem(V<Word32> index, MemoryRepresentation repr) {
    // Since asmjs does not support unaligned accesses, we can bounds-check
    // ignoring the access size.
    Variable result = __ NewVariable(repr.ToRegisterRepresentation());

    // Technically, we should do a signed 32-to-ptr extension here. However,
    // that is an explicit instruction, whereas unsigned extension is implicit.
    // Since the difference is only observable for memories larger than 2 GiB,
    // and since we disallow such memories, we can use unsigned extension.
    V<WordPtr> index_ptr = __ ChangeUint32ToUintPtr(index);
    IF (LIKELY(__ UintPtrLessThan(index_ptr, MemSize(0)))) {
      __ SetVariable(result, __ Load(MemStart(0), index_ptr,
                                     LoadOp::Kind::RawAligned(), repr));
    } ELSE {
      switch (repr) {
        case MemoryRepresentation::Int8():
        case MemoryRepresentation::Int16():
        case MemoryRepresentation::Int32():
        case MemoryRepresentation::Uint8():
        case MemoryRepresentation::Uint16():
        case MemoryRepresentation::Uint32():
          __ SetVariable(result, __ Word32Constant(0));
          break;
        case MemoryRepresentation::Float32():
          __ SetVariable(result, __ Float32Constant(
                                     std::numeric_limits<float>::quiet_NaN()));
          break;
        case MemoryRepresentation::Float64():
          __ SetVariable(result, __ Float64Constant(
                                     std::numeric_limits<double>::quiet_NaN()));
          break;
        default:
          UNREACHABLE();
      }
    }

    OpIndex result_op = __ GetVariable(result);
    __ SetVariable(result, OpIndex::Invalid());
    return result_op;
  }

  void BoundsCheckArray(V<WasmArrayNullable> array, V<Word32> index,
                        ValueType array_type) {
    if (V8_UNLIKELY(v8_flags.experimental_wasm_skip_bounds_checks)) {
      if (array_type.is_nullable()) {
        __ AssertNotNull(array, array_type, TrapId::kTrapNullDereference);
      }
    } else {
      OpIndex length = __ ArrayLength(array, array_type.is_nullable()
                                                 ? compiler::kWithNullCheck
                                                 : compiler::kWithoutNullCheck);
      __ TrapIfNot(__ Uint32LessThan(index, length),
                   TrapId::kTrapArrayOutOfBounds);
    }
  }

  V<WasmArray> BoundsCheckArrayWithLength(V<WasmArrayNullable> array,
                                          V<Word32> index, V<Word32> length,
                                          compiler::CheckForNull null_check) {
    if (V8_UNLIKELY(v8_flags.experimental_wasm_skip_bounds_checks)) {
      return V<WasmArray>::Cast(array);
    }
    V<Word32> array_length = __ ArrayLength(array, null_check);
    V<Word32> range_end = __ Word32Add(index, length);
    V<Word32> range_valid = __ Word32BitwiseAnd(
        // OOB if (index + length > array.len).
        __ Uint32LessThanOrEqual(range_end, array_length),
        // OOB if (index + length) overflows.
        __ Uint32LessThanOrEqual(index, range_end));
    __ TrapIfNot(range_valid, TrapId::kTrapArrayOutOfBounds);
    // The array is now guaranteed to be non-null.
    return V<WasmArray>::Cast(array);
  }

  void BrOnCastImpl(FullDecoder* decoder, V<Map> rtt,
                    compiler::WasmTypeCheckConfig config, const Value& object,
                    Value* value_on_branch, uint32_t br_depth,
                    bool null_succeeds) {
    OpIndex cast_succeeds = __ WasmTypeCheck(object.op, rtt, config);
    IF (cast_succeeds) {
      // Narrow type for the successful cast target branch.
      Forward(decoder, object, value_on_branch);
      BrOrRet(decoder, br_depth);
    }
    // Note: Differently to below for br_on_cast_fail, we do not Forward
    // the value here to perform a TypeGuard. It can't be done here due to
    // asymmetric decoder code. A Forward here would be popped from the stack
    // and ignored by the decoder. Therefore the decoder has to call Forward
    // itself.
  }

  void BrOnCastFailImpl(FullDecoder* decoder, V<Map> rtt,
                        compiler::WasmTypeCheckConfig config,
                        const Value& object, Value* value_on_fallthrough,
                        uint32_t br_depth, bool null_succeeds) {
    OpIndex cast_succeeds = __ WasmTypeCheck(object.op, rtt, config);
    IF (__ Word32Equal(cast_succeeds, 0)) {
      // It is necessary in case of {null_succeeds} to forward the value.
      // This will add a TypeGuard to the non-null type (as in this case the
      // object is non-nullable).
      Forward(decoder, object, decoder->stack_value(1));
      BrOrRet(decoder, br_depth);
    }
    // Narrow type for the successful cast fallthrough branch.
    value_on_fallthrough->op =
        __ AnnotateWasmType(V<Object>::Cast(object.op), config.to);
  }

  V<HeapObject> ArrayNewImpl(FullDecoder* decoder, ModuleTypeIndex index,
                             const ArrayType* array_type, V<Word32> length,
                             V<Any> initial_value) {
    // Initialize the array header.
    bool shared = decoder->module_->type(index).is_shared;
    V<Map> rtt = __ RttCanon(managed_object_maps(shared), index);
    V<WasmArray> array = __ WasmAllocateArray(rtt, length, array_type);
    // Initialize the elements.
    ArrayFillImpl(array, __ Word32Constant(0), initial_value, length,
                  array_type, false);
    return array;
  }

  V<WasmStruct> StructNewImpl(FullDecoder* decoder,
                              const StructIndexImmediate& imm, OpIndex args[]) {
    bool shared = decoder->module_->type(imm.index).is_shared;
    V<Map> rtt = __ RttCanon(managed_object_maps(shared), imm.index);

    V<WasmStruct> struct_value = __ WasmAllocateStruct(rtt, imm.struct_type);
    for (uint32_t i = 0; i < imm.struct_type->field_count(); ++i) {
      __ StructSet(struct_value, args[i], imm.struct_type, imm.index, i,
                   compiler::kWithoutNullCheck);
    }
    // If this assert fails then initialization of padding field might be
    // necessary.
    static_assert(Heap::kMinObjectSizeInTaggedWords == 2 &&
                      WasmStruct::kHeaderSize == 2 * kTaggedSize,
                  "empty struct might require initialization of padding field");
    return struct_value;
  }

  bool IsSimd128ZeroConstant(OpIndex op) {
    DCHECK_IMPLIES(!op.valid(), __ generating_unreachable_operations());
    if (__ generating_unreachable_operations()) return false;
    const Simd128ConstantOp* s128_op =
        __ output_graph().Get(op).TryCast<Simd128ConstantOp>();
    return s128_op && s128_op->IsZero();
  }

  void ArrayFillImpl(V<WasmArray> array, V<Word32> index, V<Any> value,
                     OpIndex length, const wasm::ArrayType* type,
                     bool emit_write_barrier) {
    wasm::ValueType element_type = type->element_type();

    // Initialize the array. Use an external function for large arrays with
    // null/number initializer. Use a loop for small arrays and reference arrays
    // with a non-null initial value.
    Label<> done(&asm_);

    // The builtin cannot handle s128 values other than 0.
    if (!(element_type == wasm::kWasmS128 && !IsSimd128ZeroConstant(value))) {
      constexpr uint32_t kArrayNewMinimumSizeForMemSet = 16;
      IF_NOT (__ Uint32LessThan(
                  length, __ Word32Constant(kArrayNewMinimumSizeForMemSet))) {
        OpIndex stack_slot = StoreInInt64StackSlot(value, element_type);
        MachineType arg_types[]{
            MachineType::TaggedPointer(), MachineType::Uint32(),
            MachineType::Uint32(),        MachineType::Uint32(),
            MachineType::Uint32(),        MachineType::Pointer()};
        MachineSignature sig(0, 6, arg_types);
        CallC(&sig, ExternalReference::wasm_array_fill(),
              {array, index, length,
               __ Word32Constant(emit_write_barrier ? 1 : 0),
               __ Word32Constant(element_type.raw_bit_field()), stack_slot});
        GOTO(done);
      }
    }

    ScopedVar<Word32> current_index(this, index);

    WHILE(__ Uint32LessThan(current_index, __ Word32Add(index, length))) {
      __ ArraySet(array, current_index, value, type->element_type());
      current_index = __ Word32Add(current_index, 1);
    }

    GOTO(done);

    BIND(done);
  }

  V<WordPtr> StoreInInt64StackSlot(OpIndex value, wasm::ValueType type) {
    OpIndex value_int64;
    switch (type.kind()) {
      case wasm::kI32:
      case wasm::kI8:
      case wasm::kI16:
        value_int64 = __ ChangeInt32ToInt64(value);
        break;
      case wasm::kI64:
        value_int64 = value;
        break;
      case wasm::kS128:
        // We can only get here if {value} is the constant 0.
        DCHECK(__ output_graph().Get(value).Cast<Simd128ConstantOp>().IsZero());
        value_int64 = __ Word64Constant(uint64_t{0});
        break;
      case wasm::kF32:
        value_int64 = __ ChangeUint32ToUint64(__ BitcastFloat32ToWord32(value));
        break;
      case wasm::kF64:
        value_int64 = __ BitcastFloat64ToWord64(value);
        break;
      case wasm::kRefNull:
      case wasm::kRef:
        value_int64 = kTaggedSize == 4 ? __ ChangeInt32ToInt64(value) : value;
        break;
      case wasm::kF16:
        UNIMPLEMENTED();
      case wasm::kRtt:
      case wasm::kVoid:
      case kTop:
      case wasm::kBottom:
        UNREACHABLE();
    }

    MemoryRepresentation int64_rep = MemoryRepresentation::Int64();
    V<WordPtr> stack_slot =
        __ StackSlot(int64_rep.SizeInBytes(), int64_rep.SizeInBytes());
    __ Store(stack_slot, value_int64, StoreOp::Kind::RawAligned(), int64_rep,
             compiler::WriteBarrierKind::kNoWriteBarrier);
    return stack_slot;
  }

  bool InlineTargetIsTypeCompatible(const WasmModule* module,
                                    const FunctionSig* sig,
                                    const FunctionSig* inlinee) {
    if (sig->parameter_count() != inlinee->parameter_count()) return false;
    if (sig->return_count() != inlinee->return_count()) return false;
    for (size_t i = 0; i < sig->return_count(); ++i) {
      if (!IsSubtypeOf(inlinee->GetReturn(i), sig->GetReturn(i), module))
        return false;
    }
    for (size_t i = 0; i < sig->parameter_count(); ++i) {
      if (!IsSubtypeOf(sig->GetParam(i), inlinee->GetParam(i), module))
        return false;
    }
    return true;
  }

  void InlineWasmCall(FullDecoder* decoder, uint32_t func_index,
                      const FunctionSig* sig, uint32_t feedback_case,
                      bool is_tail_call, const Value args[], Value returns[]) {
    DCHECK_IMPLIES(is_tail_call, returns == nullptr);
    const WasmFunction& inlinee = decoder->module_->functions[func_index];
    // In a corrupted sandbox, we can't trust the collected feedback.
    SBXCHECK(InlineTargetIsTypeCompatible(decoder->module_, sig, inlinee.sig));

    SmallZoneVector<OpIndex, 16> inlinee_args(
        inlinee.sig->parameter_count() + 1, decoder->zone_);
    bool inlinee_is_shared = decoder->module_->function_is_shared(func_index);
    inlinee_args[0] = trusted_instance_data(inlinee_is_shared);
    for (size_t i = 0; i < inlinee.sig->parameter_count(); i++) {
      inlinee_args[i + 1] = args[i].op;
    }

    base::Vector<const uint8_t> function_bytes =
        wire_bytes_->GetCode(inlinee.code);

    const wasm::FunctionBody inlinee_body{
        inlinee.sig, inlinee.code.offset(), function_bytes.begin(),
        function_bytes.end(), inlinee_is_shared};

    // If the inlinee was not validated before, do that now.
    if (V8_UNLIKELY(!decoder->module_->function_was_validated(func_index))) {
      if (ValidateFunctionBody(decoder->zone_, decoder->enabled_,
                               decoder->module_, decoder->detected_,
                               inlinee_body)
              .failed()) {
        // At this point we cannot easily raise a compilation error any more.
        // Since this situation is highly unlikely though, we just ignore this
        // inlinee, emit a regular call, and move on. The same validation error
        // will be triggered again when actually compiling the invalid function.
        V<WordPtr> callee =
            __ RelocatableConstant(func_index, RelocInfo::WASM_CALL);
        if (is_tail_call) {
          BuildWasmMaybeReturnCall(
              decoder, sig, callee,
              trusted_instance_data(
                  decoder->module_->function_is_shared(func_index)),
              args);
        } else {
          BuildWasmCall(decoder, sig, callee,
                        trusted_instance_data(
                            decoder->module_->function_is_shared(func_index)),
                        args, returns);
        }
        return;
      }
      decoder->module_->set_function_validated(func_index);
    }

    BlockPhis fresh_return_phis(decoder->zone_);

    Mode inlinee_mode;
    TSBlock* callee_catch_block = nullptr;
    TSBlock* callee_return_block;
    BlockPhis* inlinee_return_phis;

    if (is_tail_call) {
      if (mode_ == kInlinedTailCall || mode_ == kRegular) {
        inlinee_mode = kInlinedTailCall;
        callee_return_block = nullptr;
        inlinee_return_phis = nullptr;
      } else {
        // A tail call inlined inside a regular call inherits its settings,
        // as any `return` statement returns to the nearest non-tail caller.
        inlinee_mode = mode_;
        callee_return_block = return_block_;
        inlinee_return_phis = return_phis_;
        if (mode_ == kInlinedWithCatch) {
          callee_catch_block = return_catch_block_;
        }
      }
    } else {
      // Regular call (i.e. not a tail call).
      if (mode_ == kInlinedWithCatch || decoder->current_catch() != -1) {
        inlinee_mode = kInlinedWithCatch;
        // TODO(14108): If this is a nested inlining, can we forward the
        // caller's catch block instead?
        callee_catch_block = __ NewBlock();
      } else {
        inlinee_mode = kInlinedUnhandled;
      }
      callee_return_block = __ NewBlock();
      inlinee_return_phis = &fresh_return_phis;
    }

    OptionalV<FrameState> frame_state;
    if (deopts_enabled_) {
      frame_state = is_tail_call
                        ? parent_frame_state_
                        : CreateFrameState(decoder, sig, /*funcref*/ nullptr,
                                           /*args*/ nullptr);
    }

    WasmFullDecoder<TurboshaftGraphBuildingInterface::ValidationTag,
                    TurboshaftGraphBuildingInterface>
        inlinee_decoder(decoder->zone_, decoder->module_, decoder->enabled_,
                        decoder->detected_, inlinee_body, decoder->zone_, env_,
                        asm_, inlinee_mode, instance_cache_, assumptions_,
                        inlining_positions_, func_index, inlinee_is_shared,
                        wire_bytes_, base::VectorOf(inlinee_args),
                        callee_return_block, inlinee_return_phis,
                        callee_catch_block, is_tail_call, frame_state);
    SourcePosition call_position =
        SourcePosition(decoder->position(), inlining_id_ == kNoInliningId
                                                ? SourcePosition::kNotInlined
                                                : inlining_id_);
    inlining_positions_->push_back(
        {static_cast<int>(func_index), is_tail_call, call_position});
    inlinee_decoder.interface().set_inlining_id(
        static_cast<uint8_t>(inlining_positions_->size() - 1));
    inlinee_decoder.interface().set_parent_position(call_position);
    // Explicitly disable deopts if it has already been disabled for this
    // function.
    if (!deopts_enabled_) {
      inlinee_decoder.interface().disable_deopts();
    }
    if (v8_flags.liftoff) {
      if (inlining_decisions_ && inlining_decisions_->feedback_found()) {
        inlinee_decoder.interface().set_inlining_decisions(
            inlining_decisions_
                ->function_calls()[feedback_slot_][feedback_case]);
      }
    } else {
      no_liftoff_inlining_budget_ -= inlinee.code.length();
      inlinee_decoder.interface().set_no_liftoff_inlining_budget(
          no_liftoff_inlining_budget_);
    }
    inlinee_decoder.Decode();
    // The function was already validated above.
    DCHECK(inlinee_decoder.ok());

    DCHECK_IMPLIES(!is_tail_call && inlinee_mode == kInlinedWithCatch,
                   inlinee_return_phis != nullptr);

    if (!is_tail_call && inlinee_mode == kInlinedWithCatch &&
        !inlinee_return_phis->incoming_exceptions().empty()) {
      // We need to handle exceptions in the inlined call.
      __ Bind(callee_catch_block);
      OpIndex exception =
          MaybePhi(inlinee_return_phis->incoming_exceptions(), kWasmExternRef);
      bool handled_in_this_frame = decoder->current_catch() != -1;
      TSBlock* catch_block;
      if (handled_in_this_frame) {
        Control* current_catch =
            decoder->control_at(decoder->control_depth_of_current_catch());
        catch_block = current_catch->false_or_loop_or_catch_block;
        // The exceptional operation could have modified memory size; we need
        // to reload the memory context into the exceptional control path.
        instance_cache_.ReloadCachedMemory();
        SetupControlFlowEdge(decoder, catch_block, 0, exception);
      } else {
        DCHECK_EQ(mode_, kInlinedWithCatch);
        catch_block = return_catch_block_;
        if (exception.valid()) return_phis_->AddIncomingException(exception);
        // Reloading the InstanceCache will happen when {return_exception_phis_}
        // are retrieved.
      }
      __ Goto(catch_block);
    }

    if (!is_tail_call) {
      __ Bind(callee_return_block);
      BlockPhis* return_phis = inlinee_decoder.interface().return_phis();
      size_t return_count = inlinee.sig->return_count();
      for (size_t i = 0; i < return_count; i++) {
        returns[i].op =
            MaybePhi(return_phis->phi_inputs(i), return_phis->phi_type(i));
      }
    }

    if (!v8_flags.liftoff) {
      set_no_liftoff_inlining_budget(
          inlinee_decoder.interface().no_liftoff_inlining_budget());
    }
  }

  TrapId GetTrapIdForTrap(wasm::TrapReason reason) {
    switch (reason) {
#define TRAPREASON_TO_TRAPID(name)                                 \
  case wasm::k##name:                                              \
    static_assert(static_cast<int>(TrapId::k##name) ==             \
                      static_cast<int>(Builtin::kThrowWasm##name), \
                  "trap id mismatch");                             \
    return TrapId::k##name;
      FOREACH_WASM_TRAPREASON(TRAPREASON_TO_TRAPID)
#undef TRAPREASON_TO_TRAPID
      default:
        UNREACHABLE();
    }
  }

  // We need this shift so that resulting OpIndex offsets are multiples of
  // `sizeof(OperationStorageSlot)`.
  static constexpr int kPositionFieldShift = 3;
  static_assert(sizeof(compiler::turboshaft::OperationStorageSlot) ==
                1 << kPositionFieldShift);
  static constexpr int kPositionFieldSize = 23;
  static_assert(kV8MaxWasmFunctionSize < (1 << kPositionFieldSize));
  static constexpr int kInliningIdFieldSize = 6;
  static constexpr uint8_t kNoInliningId = 63;
  static_assert((1 << kInliningIdFieldSize) - 1 == kNoInliningId);
  // We need to assign inlining_ids to inlined nodes.
  static_assert(kNoInliningId > InliningTree::kMaxInlinedCount);

  // We encode the wasm code position and the inlining index in an OpIndex
  // stored in the output graph's node origins.
  using PositionField =
      base::BitField<WasmCodePosition, kPositionFieldShift, kPositionFieldSize>;
  using InliningIdField = PositionField::Next<uint8_t, kInliningIdFieldSize>;

  OpIndex WasmPositionToOpIndex(WasmCodePosition position, int inlining_id) {
    return OpIndex::FromOffset(PositionField::encode(position) |
                               InliningIdField::encode(inlining_id));
  }

  SourcePosition OpIndexToSourcePosition(OpIndex index) {
    DCHECK(index.valid());
    uint8_t inlining_id = InliningIdField::decode(index.offset());
    return SourcePosition(PositionField::decode(index.offset()),
                          inlining_id == kNoInliningId
                              ? SourcePosition::kNotInlined
                              : inlining_id);
  }

  BranchHint GetBranchHint(FullDecoder* decoder) {
    WasmBranchHint hint =
        branch_hints_ ? branch_hints_->GetHintFor(decoder->pc_relative_offset())
                      : WasmBranchHint::kNoHint;
    switch (hint) {
      case WasmBranchHint::kNoHint:
        return BranchHint::kNone;
      case WasmBranchHint::kUnlikely:
        return BranchHint::kFalse;
      case WasmBranchHint::kLikely:
        return BranchHint::kTrue;
    }
  }

 private:
  bool should_inline(FullDecoder* decoder, int feedback_slot, int size) {
    if (!v8_flags.wasm_inlining) return false;
    // TODO(42204563,41480394,335082212): Do not inline if the current function
    // is shared (which also implies the target cannot be shared either).
    if (shared_) return false;

    // Configuration without Liftoff and feedback, e.g., for testing.
    if (!v8_flags.liftoff) {
      return size < no_liftoff_inlining_budget_ &&
             // In a production configuration, `InliningTree` decides what to
             // (not) inline, e.g., asm.js functions or to not exceed
             // `kMaxInlinedCount`. But without Liftoff, we need to "manually"
             // comply with these constraints here.
             !is_asmjs_module(decoder->module_) &&
             inlining_positions_->size() < InliningTree::kMaxInlinedCount;
    }

    // Default, production configuration: Liftoff collects feedback, which
    // decides whether we inline:
    if (inlining_decisions_ && inlining_decisions_->feedback_found()) {
      DCHECK_GT(inlining_decisions_->function_calls().size(), feedback_slot);
      // We should inline if at least one case for this feedback slot needs
      // to be inlined.
      for (InliningTree* tree :
           inlining_decisions_->function_calls()[feedback_slot]) {
        if (tree && tree->is_inlined()) {
          DCHECK(!decoder->module_->function_is_shared(tree->function_index()));
          return true;
        }
      }
      return false;
    }
    return false;
  }

  void set_inlining_decisions(InliningTree* inlining_decisions) {
    inlining_decisions_ = inlining_decisions;
  }

  BlockPhis* return_phis() { return return_phis_; }
  void set_inlining_id(uint8_t inlining_id) {
    DCHECK_NE(inlining_id, kNoInliningId);
    inlining_id_ = inlining_id;
  }
  void set_parent_position(SourcePosition position) {
    parent_position_ = position;
  }
  int no_liftoff_inlining_budget() { return no_liftoff_inlining_budget_; }
  void set_no_liftoff_inlining_budget(int no_liftoff_inlining_budget) {
    no_liftoff_inlining_budget_ = no_liftoff_inlining_budget;
  }

  void disable_deopts() { deopts_enabled_ = false; }

  V<WasmTrustedInstanceData> trusted_instance_data(bool element_is_shared) {
    DCHECK_IMPLIES(shared_, element_is_shared);
    return (element_is_shared && !shared_)
               ? LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(
                     instance_cache_.trusted_instance_data(), SharedPart,
                     WasmTrustedInstanceData)
               : instance_cache_.trusted_instance_data();
  }

  V<FixedArray> managed_object_maps(bool type_is_shared) {
    DCHECK_IMPLIES(shared_, type_is_shared);
    if (type_is_shared && !shared_) {
      V<WasmTrustedInstanceData> shared_instance = trusted_instance_data(true);
      return LOAD_IMMUTABLE_INSTANCE_FIELD(
          shared_instance, ManagedObjectMaps,
          MemoryRepresentation::TaggedPointer());
    } else {
      return instance_cache_.managed_object_maps();
    }
  }

 private:
  Mode mode_;
  ZoneAbslFlatHashMap<TSBlock*, BlockPhis> block_phis_;
  CompilationEnv* env_;
  // Only used for "top-level" instantiations, not for inlining.
  std::unique_ptr<InstanceCache> owned_instance_cache_;

  // The instance cache to use (may be owned or passed in).
  InstanceCache& instance_cache_;

  AssumptionsJournal* assumptions_;
  ZoneVector<WasmInliningPosition>* inlining_positions_;
  uint8_t inlining_id_ = kNoInliningId;
  ZoneVector<OpIndex> ssa_env_;
  compiler::NullCheckStrategy null_check_strategy_ =
      trap_handler::IsTrapHandlerEnabled() && V8_STATIC_ROOTS_BOOL
          ? compiler::NullCheckStrategy::kTrapHandler
          : compiler::NullCheckStrategy::kExplicit;
  int func_index_;
  bool shared_;
  const WireBytesStorage* wire_bytes_;
  const BranchHintMap* branch_hints_ = nullptr;
  InliningTree* inlining_decisions_ = nullptr;
  int feedback_slot_ = -1;
  // Inlining budget in case of --no-liftoff.
  int no_liftoff_inlining_budget_ = 0;
  uint32_t liftoff_frame_size_ =
      FunctionTypeFeedback::kUninitializedLiftoffFrameSize;

  /* Used for inlining modes */
  // Contains real parameters for this inlined function, including the instance.
  // Used only in StartFunction();
  base::Vector<OpIndex> real_parameters_;
  // The bl
"""


```