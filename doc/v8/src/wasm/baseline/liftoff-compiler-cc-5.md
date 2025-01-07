Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/baseline/liftoff-compiler.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The code deals with WebAssembly (Wasm) compilation using Liftoff, V8's baseline compiler. The filename `liftoff-compiler.cc` reinforces this. The functions within the snippet are clearly related to specific Wasm operations.

2. **Analyze Individual Functions:** Go through each function and determine its purpose:
    * `MemorySize`:  Calculates the current size of a Wasm memory. It handles both single and multi-memory scenarios.
    * `MemoryGrow`:  Implements the Wasm `memory.grow` instruction, attempting to increase the memory size. It involves runtime calls and handles potential failures.
    * `GetStackValueTypesForDebugging`:  Fetches the types of values currently on the Wasm stack, specifically for debugging purposes.
    * `GetCurrentDebugSideTableEntries`:  Collects information about the current state of the Wasm stack and registers for debugging. This is used for generating debug information.
    * `RegisterDebugSideTableEntry` and `RegisterOOLDebugSideTableEntry`:  Functions for recording debugging information related to specific points in the generated code, particularly around function calls.
    * `CallDirect`, `CallIndirect`, `CallRef`, `ReturnCall`, `ReturnCallIndirect`, `ReturnCallRef`: These functions handle different types of Wasm function calls (direct, indirect, reference, and their tail-call equivalents).
    * `BrOnNull` and `BrOnNonNull`: Implement branching based on whether a reference is null or not null.
    * Template functions like `EmitTerOp`, `EmitSimdShiftOp`, `EmitSimdFloatRoundingOpWithCFallback`, `EmitSimdFloatBinOpWithCFallback`, `EmitSimdFmaOp`, `EmitSimdFmaOpWithCFallback`: These are helper functions for generating code for various SIMD (Single Instruction, Multiple Data) operations. They handle register allocation and potential fallbacks to C++ implementations.
    * `SimdOp`:  A large function that dispatches to the specific SIMD operation implementations based on the `opcode`. It contains a `switch` statement covering many different SIMD instructions.

3. **Look for Keywords and Patterns:**
    * "Memory":  Indicates operations related to Wasm memory.
    * "Call":  Signals function call handling.
    * "BrOnNull", "BrOnNonNull":  Clearly related to conditional branching.
    * "Simd":  Points to SIMD instruction implementations.
    * "DebugSideTable":  Indicates functionality related to debugging information generation.
    * "Emit":  Suggests code generation.
    * "PushRegister", "PopToRegister":  Operations related to managing the Wasm stack.
    * "Runtime call", "Builtin": Indicates interactions with V8's runtime system.

4. **Infer High-Level Functionality:** Based on the individual function analysis, group them into broader categories:
    * **Memory Management:** `MemorySize`, `MemoryGrow`.
    * **Debugging Support:** `GetStackValueTypesForDebugging`, `GetCurrentDebugSideTableEntries`, `RegisterDebugSideTableEntry`, `RegisterOOLDebugSideTableEntry`.
    * **Function Calls:** `CallDirect`, `CallIndirect`, `CallRef`, `ReturnCall`, `ReturnCallIndirect`, `ReturnCallRef`.
    * **Control Flow:** `BrOnNull`, `BrOnNonNull`.
    * **SIMD Operations:** The numerous `Emit...` and `SimdOp` functions.

5. **Address Specific Questions:**
    * **`.tq` extension:** The code is C++, so it's not a Torque file.
    * **Relationship to JavaScript:** Wasm allows JavaScript to execute computationally intensive tasks more efficiently. The memory management functions (`MemorySize`, `MemoryGrow`) directly relate to how Wasm memory, accessible from JavaScript, is handled. SIMD operations can also significantly speed up JavaScript code through Wasm.
    * **Code Logic Inference (with examples):**
        * `MemorySize`: Assume a Wasm memory with index 0 has a current size of 65536 bytes (64KB). The function would convert this to 16 pages (65536 / 4096).
        * `MemoryGrow`: If the current memory size is 16 pages and a `memory.grow(10)` is called, the function attempts to increase the size by 10 pages. The output would be the old size (16) if successful, or -1 if it fails.
    * **Common Programming Errors:**  Incorrect memory access bounds, especially when growing memory.
    * **Overall Functionality:** Synthesize the individual functionalities into a concise summary.

6. **Structure the Answer:** Organize the findings clearly, addressing each part of the user's request. Use headings and bullet points for readability.

7. **Review and Refine:** Check for accuracy and clarity. Ensure the language is appropriate and avoids overly technical jargon where possible. For example, explaining "Liftoff" as V8's baseline compiler provides context. Make sure to explicitly state that the provided code is C++ and not Torque.

By following these steps, we can generate a comprehensive and accurate answer to the user's request.
好的，让我们来分析一下这段 v8 源代码 `v8/src/wasm/baseline/liftoff-compiler.cc` 的功能。

**功能列举:**

这段代码是 V8 的 Liftoff 编译器的一部分，负责将 WebAssembly (Wasm) 代码快速编译成机器码。从提供的代码片段来看，它主要涉及以下功能：

1. **内存操作:**
   - `MemorySize`: 获取当前 WebAssembly 实例的内存大小（以页为单位）。它支持单内存和多内存的情况。
   - `MemoryGrow`: 实现 `memory.grow` 指令，尝试增加 WebAssembly 实例的内存大小。它会调用内置的运行时函数 `kWasmMemoryGrow`。

2. **调试支持:**
   - `GetStackValueTypesForDebugging`:  在调试模式下，获取当前 WebAssembly 栈中值的类型信息。
   - `GetCurrentDebugSideTableEntries`:  在调试模式下，记录当前执行点的栈和寄存器状态，用于生成调试边表（Debug Side Table）。
   - `RegisterDebugSideTableEntry`:  为即将进行的运行时调用注册调试边表条目。
   - `RegisterOOLDebugSideTableEntry`:  为不在线（Out-Of-Line）的代码生成注册调试边表条目。

3. **函数调用:**
   - `CallDirect`: 处理直接函数调用。
   - `CallIndirect`: 处理间接函数调用。
   - `CallRef`: 处理引用调用。
   - `ReturnCall`: 处理尾调用优化的直接函数调用。
   - `ReturnCallIndirect`: 处理尾调用优化的间接函数调用。
   - `ReturnCallRef`: 处理尾调用优化的引用调用。

4. **控制流:**
   - `BrOnNull`: 如果引用为空则跳转。
   - `BrOnNonNull`: 如果引用不为空则跳转。

5. **SIMD (单指令多数据) 操作:**
   - 代码中包含大量的 `Emit...` 函数和 `SimdOp` 函数，这些函数负责生成各种 SIMD 指令的机器码，例如：
     - `EmitI8x16Swizzle`, `EmitI8x16RelaxedSwizzle`: 处理 8 位整数向量的混洗操作。
     - `EmitUnOp`, `EmitBinOp`, `EmitTerOp`:  用于生成一元、二元和三元 SIMD 操作的指令。
     - 各种 SIMD 的算术、比较、位运算、移位等操作（例如 `kExprI8x16Add`, `kExprF32x4Eq`, `kExprS128Not` 等）。
     - 这些 SIMD 操作支持多种数据类型，如 i8x16, i16x8, i32x4, i64x2, f32x4, f64x2。
     - 代码中还包含了针对某些 SIMD 操作的 C++ 回退（fallback）机制，例如 `EmitSimdFloatBinOpWithCFallback`，这通常用于处理硬件不支持的指令或者提供更优的实现。

**关于文件类型:**

`v8/src/wasm/baseline/liftoff-compiler.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**，而不是 Torque 文件（Torque 文件以 `.tq` 结尾）。

**与 JavaScript 的关系及示例:**

WebAssembly 旨在作为 JavaScript 的补充，提供接近原生的性能。这段代码的功能直接影响到 JavaScript 中 WebAssembly 模块的执行效率。

**JavaScript 示例：**

```javascript
// 假设我们有一个 WebAssembly 模块实例
const wasmInstance = await WebAssembly.instantiateStreaming(fetch('my_module.wasm'));
const wasmMemory = wasmInstance.instance.exports.memory;

// 获取当前内存大小（对应 LiftoffCompiler::MemorySize）
const currentMemorySize = wasmMemory.buffer.byteLength / 65536; // 65536 bytes per page
console.log("当前内存大小（页）:", currentMemorySize);

// 尝试增加内存（对应 LiftoffCompiler::MemoryGrow）
try {
  const oldSize = wasmMemory.grow(10); // 尝试增加 10 页
  console.log("内存增长成功，旧大小（页）:", oldSize);
  console.log("新的内存大小（页）:", wasmMemory.buffer.byteLength / 65536);
} catch (e) {
  console.error("内存增长失败:", e);
}

// 调用 WebAssembly 导出的函数（对应 LiftoffCompiler::CallDirect 等）
const result = wasmInstance.instance.exports.add(5, 3);
console.log("Wasm 函数调用结果:", result);

// 使用 SIMD 操作 (如果 WebAssembly 模块中包含 SIMD 指令)
// 这部分在 JavaScript 中更抽象，但 LiftoffCompiler 负责编译这些指令
```

**代码逻辑推理 (假设输入与输出):**

**假设输入 `MemorySize`:** `imm.memory->index = 0` (访问第一个内存)，并且该内存当前大小为 65536 字节。

**输出 `MemorySize`:**  `mem_size` 寄存器将包含 `16` (65536 / 4096，其中 4096 是 Wasm 页的大小)。

**假设输入 `MemoryGrow`:** `imm.memory->index = 0`，当前内存大小为 10 页，`value` (要增长的页数) 为 5。

**输出 `MemoryGrow`:** 如果增长成功，运行时函数将返回旧的内存大小 `10`，该值将被放入 `result` 寄存器并最终推入栈中。如果增长失败（例如，超过最大内存），则可能返回 `-1`。

**用户常见的编程错误:**

1. **内存访问越界:** 在 JavaScript 中操作 `wasmMemory.buffer` 时，如果索引超出当前内存大小，会导致错误。Liftoff 编译器生成的代码会进行一些边界检查，但错误的 Wasm 代码仍然可能导致问题。
2. **`memory.grow` 期望的返回值理解错误:**  `memory.grow` 返回的是增长前的内存大小，而不是增长后的。
3. **SIMD 操作的数据类型不匹配:**  在 Wasm 中使用 SIMD 指令时，操作数的数据类型必须匹配。例如，尝试对 `i8x16` 向量进行浮点运算会导致错误。
4. **不检查 `memory.grow` 的返回值:**  在调用 `memory.grow` 后，没有检查返回值是否为 `-1`，就认为内存增长成功并进行后续操作，这可能导致程序崩溃或产生未定义的行为。

**第 6 部分功能归纳:**

作为 Liftoff 编译器的第 6 部分，这段代码主要负责以下核心功能：

* **处理内存相关的 WebAssembly 指令**，包括获取内存大小和增长内存。
* **提供必要的调试支持**，以便开发者可以理解和调试 Liftoff 生成的代码。
* **实现各种函数调用机制**，使得 WebAssembly 模块可以调用其他函数。
* **支持基于引用是否为空的条件跳转**。
* **专注于生成高效的 SIMD 指令代码**，以提升 WebAssembly 模块在处理向量化计算时的性能。这部分占据了代码的主要篇幅，涵盖了大量的 SIMD 操作。

总的来说，这段代码是 Liftoff 编译器将 WebAssembly 代码转换为机器码的关键组成部分，特别是对于内存管理、函数调用、控制流以及利用 SIMD 指令进行性能优化方面。

Prompt: 
```
这是目录为v8/src/wasm/baseline/liftoff-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/liftoff-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共13部分，请归纳一下它的功能

"""
ryIndexImmediate& imm,
                          Value* /* result */) {
    LiftoffRegList pinned;
    LiftoffRegister mem_size = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    if (imm.memory->index == 0) {
      LOAD_INSTANCE_FIELD(mem_size.gp(), Memory0Size, kSystemPointerSize,
                          pinned);
    } else {
      LOAD_PROTECTED_PTR_INSTANCE_FIELD(mem_size.gp(), MemoryBasesAndSizes,
                                        pinned);
      int buffer_offset =
          wasm::ObjectAccess::ToTagged(OFFSET_OF_DATA_START(ByteArray)) +
          kSystemPointerSize * (imm.memory->index * 2 + 1);
      __ LoadFullPointer(mem_size.gp(), mem_size.gp(), buffer_offset);
    }
    // Convert bytes to pages.
    __ emit_ptrsize_shri(mem_size.gp(), mem_size.gp(), kWasmPageSizeLog2);
    if (imm.memory->is_memory64() && kNeedI64RegPair) {
      LiftoffRegister high_word =
          __ GetUnusedRegister(kGpReg, LiftoffRegList{mem_size});
      // The high word is always 0 on 32-bit systems.
      __ LoadConstant(high_word, WasmValue{uint32_t{0}});
      mem_size = LiftoffRegister::ForPair(mem_size.gp(), high_word.gp());
    }
    __ PushRegister(imm.memory->is_memory64() ? kI64 : kI32, mem_size);
  }

  void MemoryGrow(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                  const Value& value, Value* result_val) {
    // Pop the input, then spill all cache registers to make the runtime call.
    LiftoffRegList pinned;
    LiftoffRegister num_pages = pinned.set(__ PopToRegister());
    __ SpillAllRegisters();

    LiftoffRegister result = pinned.set(__ GetUnusedRegister(kGpReg, pinned));

    Label done;

    if (imm.memory->is_memory64()) {
      // If the high word is not 0, this will always fail (would grow by
      // >=256TB). The int32_t value will be sign-extended below.
      __ LoadConstant(result, WasmValue(int32_t{-1}));
      if (kNeedI64RegPair) {
        FREEZE_STATE(all_spilled_anyway);
        __ emit_cond_jump(kNotEqual, &done, kI32, num_pages.high_gp(), no_reg,
                          all_spilled_anyway);
        num_pages = num_pages.low();
      } else {
        LiftoffRegister high_word = __ GetUnusedRegister(kGpReg, pinned);
        __ emit_i64_shri(high_word, num_pages, 32);
        FREEZE_STATE(all_spilled_anyway);
        __ emit_cond_jump(kNotEqual, &done, kI32, high_word.gp(), no_reg,
                          all_spilled_anyway);
      }
    }

    WasmMemoryGrowDescriptor descriptor;
    DCHECK_EQ(0, descriptor.GetStackParameterCount());
    DCHECK_EQ(2, descriptor.GetRegisterParameterCount());
    DCHECK_EQ(machine_type(kI32), descriptor.GetParameterType(0));
    DCHECK_EQ(machine_type(kI32), descriptor.GetParameterType(1));

    Register num_pages_param_reg = descriptor.GetRegisterParameter(1);
    if (num_pages.gp() != num_pages_param_reg) {
      __ Move(num_pages_param_reg, num_pages.gp(), kI32);
    }

    // Load the constant after potentially moving the {num_pages} register to
    // avoid overwriting it.
    Register mem_index_param_reg = descriptor.GetRegisterParameter(0);
    __ LoadConstant(LiftoffRegister{mem_index_param_reg},
                    WasmValue(imm.memory->index));

    __ CallBuiltin(Builtin::kWasmMemoryGrow);
    DefineSafepoint();
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    if (kReturnRegister0 != result.gp()) {
      __ Move(result.gp(), kReturnRegister0, kI32);
    }

    __ bind(&done);

    if (imm.memory->is_memory64()) {
      LiftoffRegister result64 = result;
      if (kNeedI64RegPair) result64 = __ GetUnusedRegister(kGpRegPair, pinned);
      __ emit_type_conversion(kExprI64SConvertI32, result64, result, nullptr);
      __ PushRegister(kI64, result64);
    } else {
      __ PushRegister(kI32, result);
    }
  }

  base::OwnedVector<ValueType> GetStackValueTypesForDebugging(
      FullDecoder* decoder) {
    DCHECK(for_debugging_);
    auto stack_value_types =
        base::OwnedVector<ValueType>::NewForOverwrite(decoder->stack_size());

    int depth = 0;
    for (ValueType& type : base::Reversed(stack_value_types)) {
      type = decoder->stack_value(++depth)->type;
    }
    return stack_value_types;
  }

  base::OwnedVector<DebugSideTable::Entry::Value>
  GetCurrentDebugSideTableEntries(
      FullDecoder* decoder,
      DebugSideTableBuilder::AssumeSpilling assume_spilling) {
    auto& stack_state = __ cache_state()->stack_state;

#ifdef DEBUG
    // For value types, we use the cached {stack_value_types_for_debugging_}
    // vector (gathered in {NextInstruction}). This still includes call
    // arguments, which Liftoff has already popped at this point. Hence the size
    // of this vector can be larger than the Liftoff stack size. Just ignore
    // that and use the lower part only.
    size_t expected_value_stack_size =
        stack_state.size() - num_exceptions_ - __ num_locals();
    DCHECK_LE(expected_value_stack_size,
              stack_value_types_for_debugging_.size());
#endif

    auto values =
        base::OwnedVector<DebugSideTable::Entry::Value>::NewForOverwrite(
            stack_state.size());

    int index = 0;
    ValueType* stack_value_type_ptr = stack_value_types_for_debugging_.begin();
    // Iterate the operand stack control block by control block, so that we can
    // handle the implicit exception value for try blocks.
    for (int j = decoder->control_depth() - 1; j >= 0; j--) {
      Control* control = decoder->control_at(j);
      Control* next_control = j > 0 ? decoder->control_at(j - 1) : nullptr;
      int end_index = next_control
                          ? next_control->stack_depth + __ num_locals() +
                                next_control->num_exceptions
                          : __ cache_state()->stack_height();
      bool exception_on_stack =
          control->is_try_catch() || control->is_try_catchall();
      for (; index < end_index; ++index) {
        const LiftoffVarState& slot = stack_state[index];
        DebugSideTable::Entry::Value& value = values[index];
        value.module = decoder->module_;
        value.index = index;
        if (exception_on_stack) {
          value.type = ValueType::Ref(HeapType::kAny);
          exception_on_stack = false;
        } else if (index < static_cast<int>(__ num_locals())) {
          value.type = decoder->local_type(index);
        } else {
          DCHECK_LT(stack_value_type_ptr,
                    stack_value_types_for_debugging_.end());
          value.type = *stack_value_type_ptr++;
        }
        DCHECK(CompatibleStackSlotTypes(slot.kind(), value.type.kind()));
        switch (slot.loc()) {
          case kIntConst:
            value.storage = DebugSideTable::Entry::kConstant;
            value.i32_const = slot.i32_const();
            break;
          case kRegister:
            DCHECK_NE(DebugSideTableBuilder::kDidSpill, assume_spilling);
            if (assume_spilling == DebugSideTableBuilder::kAllowRegisters) {
              value.storage = DebugSideTable::Entry::kRegister;
              value.reg_code = slot.reg().liftoff_code();
              break;
            }
            DCHECK_EQ(DebugSideTableBuilder::kAssumeSpilling, assume_spilling);
            [[fallthrough]];
          case kStack:
            value.storage = DebugSideTable::Entry::kStack;
            value.stack_offset = slot.offset();
            break;
        }
      }
    }
    DCHECK_EQ(values.size(), index);
    DCHECK_EQ(
        stack_value_types_for_debugging_.data() + expected_value_stack_size,
        stack_value_type_ptr);
    return values;
  }

  // Call this after emitting a runtime call that can show up in a stack trace
  // (e.g. because it can trap).
  void RegisterDebugSideTableEntry(
      FullDecoder* decoder,
      DebugSideTableBuilder::AssumeSpilling assume_spilling) {
    if (V8_LIKELY(!debug_sidetable_builder_)) return;
    debug_sidetable_builder_->NewEntry(
        __ pc_offset(),
        GetCurrentDebugSideTableEntries(decoder, assume_spilling).as_vector());
  }

  DebugSideTableBuilder::EntryBuilder* RegisterOOLDebugSideTableEntry(
      FullDecoder* decoder) {
    if (V8_LIKELY(!debug_sidetable_builder_)) return nullptr;
    return debug_sidetable_builder_->NewOOLEntry(
        GetCurrentDebugSideTableEntries(decoder,
                                        DebugSideTableBuilder::kAssumeSpilling)
            .as_vector());
  }

  void CallDirect(FullDecoder* decoder, const CallFunctionImmediate& imm,
                  const Value args[], Value[]) {
    CallDirect(decoder, imm, args, nullptr, CallJumpMode::kCall);
  }

  void CallIndirect(FullDecoder* decoder, const Value& index_val,
                    const CallIndirectImmediate& imm, const Value args[],
                    Value returns[]) {
    CallIndirectImpl(decoder, imm, CallJumpMode::kCall);
  }

  void CallRef(FullDecoder* decoder, const Value& func_ref,
               const FunctionSig* sig, const Value args[], Value returns[]) {
    CallRefImpl(decoder, func_ref.type, sig, CallJumpMode::kCall);
  }

  void ReturnCall(FullDecoder* decoder, const CallFunctionImmediate& imm,
                  const Value args[]) {
    TierupCheckOnTailCall(decoder);
    CallDirect(decoder, imm, args, nullptr, CallJumpMode::kTailCall);
  }

  void ReturnCallIndirect(FullDecoder* decoder, const Value& index_val,
                          const CallIndirectImmediate& imm,
                          const Value args[]) {
    TierupCheckOnTailCall(decoder);
    CallIndirectImpl(decoder, imm, CallJumpMode::kTailCall);
  }

  void ReturnCallRef(FullDecoder* decoder, const Value& func_ref,
                     const FunctionSig* sig, const Value args[]) {
    TierupCheckOnTailCall(decoder);
    CallRefImpl(decoder, func_ref.type, sig, CallJumpMode::kTailCall);
  }

  void BrOnNull(FullDecoder* decoder, const Value& ref_object, uint32_t depth,
                bool pass_null_along_branch,
                Value* /* result_on_fallthrough */) {
    // Avoid having sequences of branches do duplicate work.
    if (depth != decoder->control_depth() - 1) {
      __ PrepareForBranch(decoder->control_at(depth)->br_merge()->arity, {});
    }

    Label cont_false;
    LiftoffRegList pinned;
    LiftoffRegister ref =
        pinned.set(pass_null_along_branch ? __ PeekToRegister(0, pinned)
                                          : __ PopToRegister(pinned));
    Register null = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    LoadNullValueForCompare(null, pinned, ref_object.type);
    {
      FREEZE_STATE(frozen);
      __ emit_cond_jump(kNotEqual, &cont_false, ref_object.type.kind(),
                        ref.gp(), null, frozen);
      BrOrRet(decoder, depth);
    }
    __ bind(&cont_false);
    if (!pass_null_along_branch) {
      // We popped the value earlier, must push it back now.
      __ PushRegister(kRef, ref);
    }
  }

  void BrOnNonNull(FullDecoder* decoder, const Value& ref_object,
                   Value* /* result */, uint32_t depth,
                   bool drop_null_on_fallthrough) {
    // Avoid having sequences of branches do duplicate work.
    if (depth != decoder->control_depth() - 1) {
      __ PrepareForBranch(decoder->control_at(depth)->br_merge()->arity, {});
    }

    Label cont_false;
    LiftoffRegList pinned;
    LiftoffRegister ref = pinned.set(__ PeekToRegister(0, pinned));

    Register null = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    LoadNullValueForCompare(null, pinned, ref_object.type);
    {
      FREEZE_STATE(frozen);
      __ emit_cond_jump(kEqual, &cont_false, ref_object.type.kind(), ref.gp(),
                        null, frozen);

      BrOrRet(decoder, depth);
    }
    // Drop the reference if we are not branching.
    if (drop_null_on_fallthrough) __ DropValues(1);
    __ bind(&cont_false);
  }

  template <ValueKind src_kind, ValueKind result_kind,
            ValueKind result_lane_kind = kVoid, typename EmitFn,
            typename... ExtraArgs>
  void EmitTerOp(EmitFn fn, LiftoffRegister dst, LiftoffRegister src1,
                 LiftoffRegister src2, LiftoffRegister src3,
                 ExtraArgs... extra_args) {
    CallEmitFn(fn, dst, src1, src2, src3, extra_args...);
    if (V8_UNLIKELY(nondeterminism_)) {
      LiftoffRegList pinned{dst};
      if (result_kind == ValueKind::kF32 || result_kind == ValueKind::kF64) {
        CheckNan(dst, pinned, result_kind);
      } else if (result_kind == ValueKind::kS128 &&
                 (result_lane_kind == kF32 || result_lane_kind == kF64)) {
        CheckS128Nan(dst, LiftoffRegList{src1, src2, src3, dst},
                     result_lane_kind);
      }
    }
    __ PushRegister(result_kind, dst);
  }

  template <ValueKind src_kind, ValueKind result_kind,
            ValueKind result_lane_kind = kVoid, typename EmitFn>
  void EmitTerOp(EmitFn fn) {
    LiftoffRegister src3 = __ PopToRegister();
    LiftoffRegister src2 = __ PopToRegister(LiftoffRegList{src3});
    LiftoffRegister src1 = __ PopToRegister(LiftoffRegList{src3, src2});
    static constexpr RegClass result_rc = reg_class_for(result_kind);
    // Reusing src1 and src2 will complicate codegen for select for some
    // backend, so we allow only reusing src3 (the mask), and pin src1 and src2.
    // Additionally, only reuse src3 if it does not alias src1/src2,
    // otherwise dst will also alias it src1/src2.
    LiftoffRegister dst =
        (src2 == src3 || src1 == src3)
            ? __ GetUnusedRegister(result_rc, LiftoffRegList{src1, src2})
            : __ GetUnusedRegister(result_rc, {src3},
                                   LiftoffRegList{src1, src2});
    EmitTerOp<src_kind, result_kind, result_lane_kind, EmitFn>(fn, dst, src1,
                                                               src2, src3);
  }

  void EmitRelaxedLaneSelect(int lane_width) {
    DCHECK(lane_width == 8 || lane_width == 32 || lane_width == 64);
#if defined(V8_TARGET_ARCH_IA32) || defined(V8_TARGET_ARCH_X64)
    if (!CpuFeatures::IsSupported(AVX)) {
#if defined(V8_TARGET_ARCH_IA32)
      // On ia32 xmm0 is not a cached register.
      LiftoffRegister mask = LiftoffRegister::from_uncached(xmm0);
#else
      LiftoffRegister mask(xmm0);
#endif
      __ PopToFixedRegister(mask);
      LiftoffRegister src2 = __ PopToModifiableRegister(LiftoffRegList{mask});
      LiftoffRegister src1 = __ PopToRegister(LiftoffRegList{src2, mask});
      EmitTerOp<kS128, kS128>(&LiftoffAssembler::emit_s128_relaxed_laneselect,
                              src2, src1, src2, mask, lane_width);
      return;
    }
#endif
    LiftoffRegList pinned;
    LiftoffRegister mask = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister src2 = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister src1 = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister dst =
        __ GetUnusedRegister(reg_class_for(kS128), {}, pinned);
    EmitTerOp<kS128, kS128>(&LiftoffAssembler::emit_s128_relaxed_laneselect,
                            dst, src1, src2, mask, lane_width);
  }

  template <typename EmitFn, typename EmitFnImm>
  void EmitSimdShiftOp(EmitFn fn, EmitFnImm fnImm) {
    static constexpr RegClass result_rc = reg_class_for(kS128);

    VarState rhs_slot = __ cache_state()->stack_state.back();
    // Check if the RHS is an immediate.
    if (rhs_slot.is_const()) {
      __ cache_state()->stack_state.pop_back();
      int32_t imm = rhs_slot.i32_const();

      LiftoffRegister operand = __ PopToRegister();
      LiftoffRegister dst = __ GetUnusedRegister(result_rc, {operand}, {});

      CallEmitFn(fnImm, dst, operand, imm);
      __ PushRegister(kS128, dst);
    } else {
      LiftoffRegister count = __ PopToRegister();
      LiftoffRegister operand = __ PopToRegister();
      LiftoffRegister dst = __ GetUnusedRegister(result_rc, {operand}, {});

      CallEmitFn(fn, dst, operand, count);
      __ PushRegister(kS128, dst);
    }
  }

  template <ValueKind result_lane_kind>
  void EmitSimdFloatRoundingOpWithCFallback(
      bool (LiftoffAssembler::*emit_fn)(LiftoffRegister, LiftoffRegister),
      ExternalReference (*ext_ref)()) {
    static constexpr RegClass rc = reg_class_for(kS128);
    LiftoffRegister src = __ PopToRegister();
    LiftoffRegister dst = __ GetUnusedRegister(rc, {src}, {});
    if (!(asm_.*emit_fn)(dst, src)) {
      // Return v128 via stack for ARM.
      GenerateCCallWithStackBuffer(&dst, kVoid, kS128,
                                   {VarState{kS128, src, 0}}, ext_ref());
    }
    if (V8_UNLIKELY(nondeterminism_)) {
      LiftoffRegList pinned{dst};
      CheckS128Nan(dst, pinned, result_lane_kind);
    }
    __ PushRegister(kS128, dst);
  }

  template <ValueKind result_lane_kind, bool swap_lhs_rhs = false>
  void EmitSimdFloatBinOpWithCFallback(
      bool (LiftoffAssembler::*emit_fn)(LiftoffRegister, LiftoffRegister,
                                        LiftoffRegister),
      ExternalReference (*ext_ref)()) {
    static constexpr RegClass rc = reg_class_for(kS128);
    LiftoffRegister src2 = __ PopToRegister();
    LiftoffRegister src1 = __ PopToRegister(LiftoffRegList{src2});
    LiftoffRegister dst = __ GetUnusedRegister(rc, {src1, src2}, {});

    if (swap_lhs_rhs) std::swap(src1, src2);

    if (!(asm_.*emit_fn)(dst, src1, src2)) {
      // Return v128 via stack for ARM.
      GenerateCCallWithStackBuffer(
          &dst, kVoid, kS128,
          {VarState{kS128, src1, 0}, VarState{kS128, src2, 0}}, ext_ref());
    }
    if (V8_UNLIKELY(nondeterminism_)) {
      LiftoffRegList pinned{dst};
      CheckS128Nan(dst, pinned, result_lane_kind);
    }
    __ PushRegister(kS128, dst);
  }

  template <ValueKind result_lane_kind, typename EmitFn>
  void EmitSimdFmaOp(EmitFn emit_fn) {
    LiftoffRegList pinned;
    LiftoffRegister src3 = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister src2 = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister src1 = pinned.set(__ PopToRegister(pinned));
    RegClass dst_rc = reg_class_for(kS128);
    LiftoffRegister dst = __ GetUnusedRegister(dst_rc, {});
    (asm_.*emit_fn)(dst, src1, src2, src3);
    if (V8_UNLIKELY(nondeterminism_)) {
      LiftoffRegList pinned{dst};
      CheckS128Nan(dst, pinned, result_lane_kind);
    }
    __ PushRegister(kS128, dst);
  }

  template <ValueKind result_lane_kind, typename EmitFn>
  void EmitSimdFmaOpWithCFallback(EmitFn emit_fn,
                                  ExternalReference (*ext_ref)()) {
    LiftoffRegList pinned;
    LiftoffRegister src3 = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister src2 = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister src1 = pinned.set(__ PopToRegister(pinned));
    static constexpr RegClass dst_rc = reg_class_for(kS128);
    LiftoffRegister dst = __ GetUnusedRegister(dst_rc, {});
    if (!(asm_.*emit_fn)(dst, src1, src2, src3)) {
      // Return v128 via stack for ARM.
      GenerateCCallWithStackBuffer(
          &dst, kVoid, kS128,
          {VarState{kS128, src1, 0}, VarState{kS128, src2, 0},
           VarState{kS128, src3, 0}},
          ext_ref());
    }
    if (V8_UNLIKELY(nondeterminism_)) {
      LiftoffRegList pinned{dst};
      CheckS128Nan(dst, pinned, result_lane_kind);
    }
    __ PushRegister(kS128, dst);
  }

  void SimdOp(FullDecoder* decoder, WasmOpcode opcode, const Value* /* args */,
              Value* /* result */) {
    CHECK(CpuFeatures::SupportsWasmSimd128());
    switch (opcode) {
      case wasm::kExprI8x16Swizzle:
        return EmitI8x16Swizzle(false);
      case wasm::kExprI8x16RelaxedSwizzle:
        return EmitI8x16Swizzle(true);
      case wasm::kExprI8x16Popcnt:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_popcnt);
      case wasm::kExprI8x16Splat:
        return EmitUnOp<kI32, kS128>(&LiftoffAssembler::emit_i8x16_splat);
      case wasm::kExprI16x8Splat:
        return EmitUnOp<kI32, kS128>(&LiftoffAssembler::emit_i16x8_splat);
      case wasm::kExprI32x4Splat:
        return EmitUnOp<kI32, kS128>(&LiftoffAssembler::emit_i32x4_splat);
      case wasm::kExprI64x2Splat:
        return EmitUnOp<kI64, kS128>(&LiftoffAssembler::emit_i64x2_splat);
      case wasm::kExprF16x8Splat: {
        auto emit_with_c_fallback = [this](LiftoffRegister dst,
                                           LiftoffRegister src) {
          if (asm_.emit_f16x8_splat(dst, src)) return;
          LiftoffRegister value = __ GetUnusedRegister(kGpReg, {});
          auto conv_ref = ExternalReference::wasm_float32_to_float16();
          GenerateCCallWithStackBuffer(&value, kVoid, kI16,
                                       {VarState{kF32, src, 0}}, conv_ref);
          __ emit_i16x8_splat(dst, value);
        };
        return EmitUnOp<kF32, kS128>(emit_with_c_fallback);
      }
      case wasm::kExprF32x4Splat:
        return EmitUnOp<kF32, kS128, kF32>(&LiftoffAssembler::emit_f32x4_splat);
      case wasm::kExprF64x2Splat:
        return EmitUnOp<kF64, kS128, kF64>(&LiftoffAssembler::emit_f64x2_splat);
      case wasm::kExprI8x16Eq:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_eq);
      case wasm::kExprI8x16Ne:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_ne);
      case wasm::kExprI8x16LtS:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i8x16_gt_s);
      case wasm::kExprI8x16LtU:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i8x16_gt_u);
      case wasm::kExprI8x16GtS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_gt_s);
      case wasm::kExprI8x16GtU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_gt_u);
      case wasm::kExprI8x16LeS:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i8x16_ge_s);
      case wasm::kExprI8x16LeU:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i8x16_ge_u);
      case wasm::kExprI8x16GeS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_ge_s);
      case wasm::kExprI8x16GeU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_ge_u);
      case wasm::kExprI16x8Eq:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_eq);
      case wasm::kExprI16x8Ne:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_ne);
      case wasm::kExprI16x8LtS:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i16x8_gt_s);
      case wasm::kExprI16x8LtU:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i16x8_gt_u);
      case wasm::kExprI16x8GtS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_gt_s);
      case wasm::kExprI16x8GtU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_gt_u);
      case wasm::kExprI16x8LeS:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i16x8_ge_s);
      case wasm::kExprI16x8LeU:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i16x8_ge_u);
      case wasm::kExprI16x8GeS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_ge_s);
      case wasm::kExprI16x8GeU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_ge_u);
      case wasm::kExprI32x4Eq:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_eq);
      case wasm::kExprI32x4Ne:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_ne);
      case wasm::kExprI32x4LtS:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i32x4_gt_s);
      case wasm::kExprI32x4LtU:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i32x4_gt_u);
      case wasm::kExprI32x4GtS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_gt_s);
      case wasm::kExprI32x4GtU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_gt_u);
      case wasm::kExprI32x4LeS:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i32x4_ge_s);
      case wasm::kExprI32x4LeU:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i32x4_ge_u);
      case wasm::kExprI32x4GeS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_ge_s);
      case wasm::kExprI32x4GeU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_ge_u);
      case wasm::kExprI64x2Eq:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i64x2_eq);
      case wasm::kExprI64x2Ne:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i64x2_ne);
      case wasm::kExprI64x2LtS:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i64x2_gt_s);
      case wasm::kExprI64x2GtS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i64x2_gt_s);
      case wasm::kExprI64x2LeS:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i64x2_ge_s);
      case wasm::kExprI64x2GeS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i64x2_ge_s);
      case wasm::kExprF16x8Eq:
        return EmitSimdFloatBinOpWithCFallback<kI16>(
            &LiftoffAssembler::emit_f16x8_eq, ExternalReference::wasm_f16x8_eq);
      case wasm::kExprF16x8Ne:
        return EmitSimdFloatBinOpWithCFallback<kI16>(
            &LiftoffAssembler::emit_f16x8_ne, ExternalReference::wasm_f16x8_ne);
      case wasm::kExprF16x8Lt:
        return EmitSimdFloatBinOpWithCFallback<kI16>(
            &LiftoffAssembler::emit_f16x8_lt, ExternalReference::wasm_f16x8_lt);
      case wasm::kExprF16x8Gt:
        return EmitSimdFloatBinOpWithCFallback<kI16, true>(
            &LiftoffAssembler::emit_f16x8_lt, ExternalReference::wasm_f16x8_lt);
      case wasm::kExprF16x8Le:
        return EmitSimdFloatBinOpWithCFallback<kI16>(
            &LiftoffAssembler::emit_f16x8_le, ExternalReference::wasm_f16x8_le);
      case wasm::kExprF16x8Ge:
        return EmitSimdFloatBinOpWithCFallback<kI16, true>(
            &LiftoffAssembler::emit_f16x8_le, ExternalReference::wasm_f16x8_le);
      case wasm::kExprF32x4Eq:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_f32x4_eq);
      case wasm::kExprF32x4Ne:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_f32x4_ne);
      case wasm::kExprF32x4Lt:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_f32x4_lt);
      case wasm::kExprF32x4Gt:
        return EmitBinOp<kS128, kS128, true>(&LiftoffAssembler::emit_f32x4_lt);
      case wasm::kExprF32x4Le:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_f32x4_le);
      case wasm::kExprF32x4Ge:
        return EmitBinOp<kS128, kS128, true>(&LiftoffAssembler::emit_f32x4_le);
      case wasm::kExprF64x2Eq:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_f64x2_eq);
      case wasm::kExprF64x2Ne:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_f64x2_ne);
      case wasm::kExprF64x2Lt:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_f64x2_lt);
      case wasm::kExprF64x2Gt:
        return EmitBinOp<kS128, kS128, true>(&LiftoffAssembler::emit_f64x2_lt);
      case wasm::kExprF64x2Le:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_f64x2_le);
      case wasm::kExprF64x2Ge:
        return EmitBinOp<kS128, kS128, true>(&LiftoffAssembler::emit_f64x2_le);
      case wasm::kExprS128Not:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_s128_not);
      case wasm::kExprS128And:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_s128_and);
      case wasm::kExprS128Or:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_s128_or);
      case wasm::kExprS128Xor:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_s128_xor);
      case wasm::kExprS128Select:
        return EmitTerOp<kS128, kS128>(&LiftoffAssembler::emit_s128_select);
      case wasm::kExprI8x16Neg:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_neg);
      case wasm::kExprV128AnyTrue:
        return EmitUnOp<kS128, kI32>(&LiftoffAssembler::emit_v128_anytrue);
      case wasm::kExprI8x16AllTrue:
        return EmitUnOp<kS128, kI32>(&LiftoffAssembler::emit_i8x16_alltrue);
      case wasm::kExprI8x16BitMask:
        return EmitUnOp<kS128, kI32>(&LiftoffAssembler::emit_i8x16_bitmask);
      case wasm::kExprI8x16Shl:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i8x16_shl,
                               &LiftoffAssembler::emit_i8x16_shli);
      case wasm::kExprI8x16ShrS:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i8x16_shr_s,
                               &LiftoffAssembler::emit_i8x16_shri_s);
      case wasm::kExprI8x16ShrU:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i8x16_shr_u,
                               &LiftoffAssembler::emit_i8x16_shri_u);
      case wasm::kExprI8x16Add:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_add);
      case wasm::kExprI8x16AddSatS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_add_sat_s);
      case wasm::kExprI8x16AddSatU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_add_sat_u);
      case wasm::kExprI8x16Sub:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_sub);
      case wasm::kExprI8x16SubSatS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_sub_sat_s);
      case wasm::kExprI8x16SubSatU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_sub_sat_u);
      case wasm::kExprI8x16MinS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_min_s);
      case wasm::kExprI8x16MinU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_min_u);
      case wasm::kExprI8x16MaxS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_max_s);
      case wasm::kExprI8x16MaxU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_max_u);
      case wasm::kExprI16x8Neg:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_neg);
      case wasm::kExprI16x8AllTrue:
        return EmitUnOp<kS128, kI32>(&LiftoffAssembler::emit_i16x8_alltrue);
      case wasm::kExprI16x8BitMask:
        return EmitUnOp<kS128, kI32>(&LiftoffAssembler::emit_i16x8_bitmask);
      case wasm::kExprI16x8Shl:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i16x8_shl,
                               &LiftoffAssembler::emit_i16x8_shli);
      case wasm::kExprI16x8ShrS:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i16x8_shr_s,
                               &LiftoffAssembler::emit_i16x8_shri_s);
      case wasm::kExprI16x8ShrU:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i16x8_shr_u,
                               &LiftoffAssembler::emit_i16x8_shri_u);
      case wasm::kExprI16x8Add:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_add);
      case wasm::kExprI16x8AddSatS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_add_sat_s);
      case wasm::kExprI16x8AddSatU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_add_sat_u);
      case wasm::kExprI16x8Sub:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_sub);
      case wasm::kExprI16x8SubSatS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_sub_sat_s);
      case wasm::kExprI16x8SubSatU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_sub_sat_u);
      case wasm::kExprI16x8Mul:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_mul);
      case wasm::kExprI16x8MinS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_min_s);
      case wasm::kExprI16x8MinU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_min_u);
      case wasm::kExprI16x8MaxS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_max_s);
      case wasm::kExprI16x8MaxU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_max_u);
      case wasm::kExprI16x8ExtAddPairwiseI8x16S:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_extadd_pairwise_i8x16_s);
      case wasm::kExprI16x8ExtAddPairwiseI8x16U:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_extadd_pairwise_i8x16_u);
      case wasm::kExprI16x8ExtMulLowI8x16S:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_extmul_low_i8x16_s);
      case wasm::kExprI16x8ExtMulLowI8x16U:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_extmul_low_i8x16_u);
      case wasm::kExprI16x8ExtMulHighI8x16S:
        return EmitB
"""


```