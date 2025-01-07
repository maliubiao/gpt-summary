Response:
The user wants me to analyze a C++ source code snippet from V8's Liftoff compiler.
Here's a breakdown of the thought process to address all the user's requests:

1. **Identify the Core Functionality:** The code snippet deals with storing and loading exception values in WebAssembly. It also includes functions for throwing and catching exceptions, as well as handling atomic operations.

2. **List the Functionalities:** Based on the identified core functionality, list the specific tasks performed by the provided code. This includes loading and storing different data types for exceptions, getting exception values, emitting landing pads for exception handling, throwing exceptions, and various atomic memory operations.

3. **Check for Torque Source:** The user asks if the file ends with `.tq`. Since the provided snippet is clearly C++ code and not Torque, the answer is no.

4. **Relate to JavaScript Functionality:**  WebAssembly exceptions are relatively new and directly interact with JavaScript's `try...catch` mechanism. When a WebAssembly function throws an exception, it can be caught in JavaScript. Provide a simple JavaScript example showing how to invoke a WebAssembly function that throws an exception and catch it. Explain that the specific details in the C++ code relate to *how* V8 handles the low-level storage and retrieval of exception data, which is an internal implementation detail not directly visible in the JavaScript API.

5. **Provide Code Logic Inference with Hypothetical Input/Output:** Select a relatively self-contained function for this. `StoreExceptionValue` seems like a good choice. Create a scenario:
    * **Input:** Assume storing an `i32` value. Specify the `ValueType`, the `values_array` register, the initial `index_in_array`, and an empty `LiftoffRegList`. Also assume a value to be stored is on the top of the Liftoff stack.
    * **Output:** Describe the actions the function will take: pop the value, call `Store32BitExceptionValue`, and increment the index. Note that the actual register values are implementation details and less important than the conceptual flow.

6. **Illustrate Common Programming Errors:** Focus on the usage of WebAssembly exceptions from the JavaScript side, as this is what a developer interacts with. A common error is trying to access exception details without checking if an exception was actually thrown. Provide a JavaScript example of this error and how to fix it.

7. **Summarize the Functionality (for this part):** Combine the identified functionalities from step 2 into a concise summary specifically for the provided code snippet. Emphasize the exception handling and atomic operations aspects.

8. **Consider the "Part 8 of 13" Context:** This implies that the `liftoff-compiler.cc` file is likely quite large and the provided snippet is only a section. Acknowledge this and frame the summary accordingly. Avoid making claims about the *entire* file's functionality.

**Self-Correction/Refinement:**

* **Initial Thought:** Directly link the C++ code to internal JavaScript exception handling details.
* **Correction:** While there's a connection, the C++ is about *implementation*. The JavaScript example should focus on the observable behavior (try/catch).

* **Initial Thought:**  Try to infer exact register usage in the input/output example.
* **Correction:** Focus on the *types* and the *flow* of data. Register allocation is dynamic and architecture-specific, making exact inference difficult and less useful.

* **Initial Thought:**  Provide a very technical example of a WebAssembly programming error.
* **Correction:** Choose a common and easily understandable error related to exception handling in JavaScript, as this is the relevant developer interaction point.

By following these steps and incorporating self-correction, the response addresses all parts of the user's request accurately and provides relevant information.
这是目录为 `v8/src/wasm/baseline/liftoff-compiler.cc` 的一个 V8 源代码片段。

**功能列举:**

该代码片段主要负责以下功能，都与 WebAssembly 异常处理和原子操作有关：

1. **存储异常值 (`StoreExceptionValue`)**:  将不同类型的 WebAssembly 值（例如 `i32`, `f32`, `i64`, `f64`, `s128`, 对象引用等）存储到用于传递异常信息的数组中。它会根据值的类型进行适当的处理，例如对浮点数进行重新解释为整数的处理，或者将 SIMD 值拆分成多个 32 位值存储。对于引用类型，会直接存储 tagged 指针。

2. **加载异常值 (`LoadExceptionValue`)**: 从用于传递异常信息的数组中加载不同类型的 WebAssembly 值。这个操作是 `StoreExceptionValue` 的逆操作，同样需要根据值的类型进行相应的处理，例如将整数重新解释为浮点数，或者将多个 32 位值组合成 SIMD 值。对于引用类型，会加载 tagged 指针。

3. **获取异常值 (`GetExceptionValues`)**:  从异常对象的特定属性（`kwasm_exception_values_symbol`）中获取存储异常值的数组，并根据异常标签的签名，依次加载所有异常参数的值到 Liftoff 的值栈中。

4. **发射着陆区 (`EmitLandingPad`)**:  生成异常处理的“着陆区”代码。当 WebAssembly 代码抛出异常时，执行流程会跳转到这个着陆区。代码会处理异常，将异常信息推送到栈上，并跳转到对应的 `catch` 代码块。

5. **抛出异常 (`Throw`)**:  生成用于抛出 WebAssembly 异常的代码。这包括：
    * 计算需要存储的异常值的大小。
    * 调用内置函数 `kWasmAllocateFixedArray` 分配一个固定大小的数组来存储异常值。
    * 将异常值从 Liftoff 的值栈弹出并存储到刚分配的数组中。
    * 加载异常标签 (tag)。
    * 调用内置函数 `kWasmThrow` 来实际抛出异常。
    * 记录调试信息。
    * 如果需要，生成着陆区代码。

6. **原子存储操作 (`AtomicStoreMem`)**: 实现 WebAssembly 的原子存储指令。它会从栈上弹出要存储的值和内存地址，进行边界检查，然后执行原子存储操作。

7. **原子加载操作 (`AtomicLoadMem`)**: 实现 WebAssembly 的原子加载指令。它会从栈上弹出内存地址，进行边界检查，然后执行原子加载操作，并将加载的值推送到栈上。

8. **原子二元操作 (`AtomicBinop`)**: 实现 WebAssembly 的原子二元运算指令（例如 `atomic.add`, `atomic.sub` 等）。它会从栈上弹出操作数和内存地址，进行边界检查，然后执行原子运算，并将结果推送到栈上。

9. **原子比较交换操作 (`AtomicCompareExchange`)**: 实现 WebAssembly 的原子比较交换指令。它会从栈上弹出新值、期望值和内存地址，进行边界检查，然后执行原子比较交换操作，并将结果（指示是否交换成功）推送到栈上。

10. **调用内置函数 (`CallBuiltin`)**:  封装了调用 V8 内置函数的逻辑，用于执行一些底层操作，例如分配数组、抛出异常等。

11. **原子等待 (`AtomicWait`)**: 实现 `atomic.wait` 指令，允许线程等待共享内存中的某个值变为特定值。

12. **原子通知 (`AtomicNotify`)**: 实现 `atomic.notify` 指令，允许线程唤醒等待在共享内存上的其他线程。

13. **原子栅栏 (`AtomicFence`)**: 实现 `atomic.fence` 指令，用于保证原子操作的顺序性。

14. **处理索引 (`PopIndexToVarState`, `CheckHighWordEmptyForTableType`)**:  用于处理内存访问和表访问的索引值，特别是针对 32 位和 64 位环境下的兼容性问题。

**它不是 Torque 源代码:**

`v8/src/wasm/baseline/liftoff-compiler.cc` 以 `.cc` 结尾，这表明它是一个 C++ 源代码文件，而不是以 `.tq` 结尾的 Torque 源代码文件。 Torque 是一种 V8 特有的用于生成高效 TurboFan 代码的领域特定语言。

**与 JavaScript 的功能关系 (WebAssembly 异常):**

WebAssembly 的异常处理机制与 JavaScript 的 `try...catch` 语句密切相关。当 WebAssembly 代码抛出一个异常时，这个异常可以被 JavaScript 的 `try...catch` 捕获。

```javascript
// 假设你已经加载了一个包含抛出异常的 WebAssembly 模块
const wasmInstance = // ... 你的 WebAssembly 实例 ...

// 假设 WebAssembly 模块导出了一个名为 'throw_exception' 的函数，它会抛出一个带有 i32 参数的异常。
try {
  wasmInstance.exports.throw_exception(123);
} catch (error) {
  console.error("捕获到 WebAssembly 异常:", error);
  // 'error' 对象可能包含有关异常的信息，具体取决于 V8 的实现
}
```

在这个 JavaScript 例子中，`liftoff-compiler.cc` 中的 `Throw` 函数所生成的代码负责创建异常对象，并将参数 `123` 存储到异常值数组中。当 WebAssembly 运行时执行到 `kWasmThrow` 时，会创建一个 JavaScript 异常对象，并将相关信息传递给 JavaScript 运行时，使得 `catch` 块能够捕获到这个异常。 `GetExceptionValues` 则是在 WebAssembly 的 `catch` 代码块中，负责将存储在异常对象中的值取出来。

**代码逻辑推理 (以 `StoreExceptionValue` 为例):**

**假设输入:**

* `type`:  `ValueType::ForInt32()` (表示要存储的是一个 32 位整数)
* `values_array`:  一个指向用于存储异常值的 `FixedArray` 的寄存器，假设为 `r10`。
* `index_in_array`: 指向当前数组索引的指针，假设其值为 `0`。
* `pinned`: 一个空的 `LiftoffRegList`。
* Liftoff 的值栈顶包含要存储的 32 位整数值，假设其位于寄存器 `r8`。

**输出:**

1. `PopToRegister` 将栈顶的值 (位于 `r8`) 弹出到 `value` 变量中。
2. 进入 `switch` 语句的 `kI32` 分支。
3. 调用 `Store32BitExceptionValue(r10, &index_in_array, r8, pinned)`。
4. `Store32BitExceptionValue` 函数会将 `r8` 中的 32 位整数值存储到 `r10` 指向的 `FixedArray` 的索引为 `0` 的位置。
5. `index_in_array` 的值会增加到 `1`。

**用户常见的编程错误 (与 WebAssembly 异常相关):**

```javascript
// 错误示例：假设 WebAssembly 抛出的异常带有参数，但 JavaScript 侧没有正确处理
const wasmInstance = // ... 你的 WebAssembly 实例 ...

try {
  wasmInstance.exports.throw_exception_with_arg(42);
} catch (error) {
  // 错误地认为 error 只是一个简单的字符串或 Error 对象
  console.log("捕获到异常，但不确定参数:", error.message || error);
}

// 正确示例：需要根据 WebAssembly 的异常定义来处理
const wasmInstance = // ... 你的 WebAssembly 实例 ...

try {
  wasmInstance.exports.throw_exception_with_arg(42);
} catch (error) {
  if (error instanceof WebAssembly.Exception) {
    console.log("捕获到 WebAssembly 异常，参数:", error.getArg(0));
  } else {
    console.error("捕获到非 WebAssembly 异常:", error);
  }
}
```

常见的错误是假设 WebAssembly 抛出的异常会像 JavaScript 异常一样直接携带信息。实际上，WebAssembly 异常需要通过特定的 API (例如 `WebAssembly.Exception`) 来访问其携带的参数。

**第 8 部分功能归纳:**

作为 Liftoff 编译器的第 8 部分，该代码片段主要负责 **WebAssembly 异常处理机制的底层实现** 以及 **原子内存操作的实现**。它包含了存储和加载异常值、生成异常处理代码、以及实现各种原子指令的逻辑。这些功能是使得 WebAssembly 能够与 JavaScript 的异常处理机制互操作，并支持多线程共享内存的关键组成部分。

Prompt: 
```
这是目录为v8/src/wasm/baseline/liftoff-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/liftoff-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共13部分，请归纳一下它的功能

"""
se {
      Load16BitExceptionValue(dst, values_array, index, pinned);
      __ emit_i64_shli(dst, dst, 48);
      LiftoffRegister tmp_reg =
          pinned.set(__ GetUnusedRegister(kGpReg, pinned));
      Load16BitExceptionValue(tmp_reg, values_array, index, pinned);
      __ emit_i64_shli(tmp_reg, tmp_reg, 32);
      __ emit_i64_or(dst, tmp_reg, dst);
      Load16BitExceptionValue(tmp_reg, values_array, index, pinned);
      __ emit_i64_shli(tmp_reg, tmp_reg, 16);
      __ emit_i64_or(dst, tmp_reg, dst);
      Load16BitExceptionValue(tmp_reg, values_array, index, pinned);
      __ emit_i64_or(dst, tmp_reg, dst);
    }
  }

  void StoreExceptionValue(ValueType type, Register values_array,
                           int* index_in_array, LiftoffRegList pinned) {
    LiftoffRegister value = pinned.set(__ PopToRegister(pinned));
    switch (type.kind()) {
      case kI32:
        Store32BitExceptionValue(values_array, index_in_array, value.gp(),
                                 pinned);
        break;
      case kF32: {
        LiftoffRegister gp_reg =
            pinned.set(__ GetUnusedRegister(kGpReg, pinned));
        __ emit_type_conversion(kExprI32ReinterpretF32, gp_reg, value, nullptr);
        Store32BitExceptionValue(values_array, index_in_array, gp_reg.gp(),
                                 pinned);
        break;
      }
      case kI64:
        Store64BitExceptionValue(values_array, index_in_array, value, pinned);
        break;
      case kF64: {
        LiftoffRegister tmp_reg =
            pinned.set(__ GetUnusedRegister(reg_class_for(kI64), pinned));
        __ emit_type_conversion(kExprI64ReinterpretF64, tmp_reg, value,
                                nullptr);
        Store64BitExceptionValue(values_array, index_in_array, tmp_reg, pinned);
        break;
      }
      case kS128: {
        LiftoffRegister tmp_reg =
            pinned.set(__ GetUnusedRegister(kGpReg, pinned));
        for (int i : {3, 2, 1, 0}) {
          __ emit_i32x4_extract_lane(tmp_reg, value, i);
          Store32BitExceptionValue(values_array, index_in_array, tmp_reg.gp(),
                                   pinned);
        }
        break;
      }
      case wasm::kRef:
      case wasm::kRefNull:
      case wasm::kRtt: {
        --(*index_in_array);
        __ StoreTaggedPointer(
            values_array, no_reg,
            wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(
                *index_in_array),
            value.gp(), pinned);
        break;
      }
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
      case wasm::kVoid:
      case wasm::kTop:
      case wasm::kBottom:
        UNREACHABLE();
    }
  }

  void LoadExceptionValue(ValueKind kind, LiftoffRegister values_array,
                          uint32_t* index, LiftoffRegList pinned) {
    RegClass rc = reg_class_for(kind);
    LiftoffRegister value = pinned.set(__ GetUnusedRegister(rc, pinned));
    switch (kind) {
      case kI32:
        Load32BitExceptionValue(value.gp(), values_array, index, pinned);
        break;
      case kF32: {
        LiftoffRegister tmp_reg =
            pinned.set(__ GetUnusedRegister(kGpReg, pinned));
        Load32BitExceptionValue(tmp_reg.gp(), values_array, index, pinned);
        __ emit_type_conversion(kExprF32ReinterpretI32, value, tmp_reg,
                                nullptr);
        break;
      }
      case kI64:
        Load64BitExceptionValue(value, values_array, index, pinned);
        break;
      case kF64: {
        RegClass rc_i64 = reg_class_for(kI64);
        LiftoffRegister tmp_reg =
            pinned.set(__ GetUnusedRegister(rc_i64, pinned));
        Load64BitExceptionValue(tmp_reg, values_array, index, pinned);
        __ emit_type_conversion(kExprF64ReinterpretI64, value, tmp_reg,
                                nullptr);
        break;
      }
      case kS128: {
        LiftoffRegister tmp_reg =
            pinned.set(__ GetUnusedRegister(kGpReg, pinned));
        Load32BitExceptionValue(tmp_reg.gp(), values_array, index, pinned);
        __ emit_i32x4_splat(value, tmp_reg);
        for (int lane : {1, 2, 3}) {
          Load32BitExceptionValue(tmp_reg.gp(), values_array, index, pinned);
          __ emit_i32x4_replace_lane(value, value, tmp_reg, lane);
        }
        break;
      }
      case wasm::kRef:
      case wasm::kRefNull:
      case wasm::kRtt: {
        __ LoadTaggedPointer(
            value.gp(), values_array.gp(), no_reg,
            wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(*index));
        (*index)++;
        break;
      }
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
      case wasm::kVoid:
      case wasm::kTop:
      case wasm::kBottom:
        UNREACHABLE();
    }
    __ PushRegister(kind, value);
  }

  void GetExceptionValues(FullDecoder* decoder, const VarState& exception_var,
                          const WasmTag* tag) {
    LiftoffRegList pinned;
    CODE_COMMENT("get exception values");
    LiftoffRegister values_array = GetExceptionProperty(
        exception_var, RootIndex::kwasm_exception_values_symbol);
    pinned.set(values_array);
    uint32_t index = 0;
    const WasmTagSig* sig = tag->sig;
    for (ValueType param : sig->parameters()) {
      LoadExceptionValue(param.kind(), values_array, &index, pinned);
    }
    DCHECK_EQ(index, WasmExceptionPackage::GetEncodedSize(tag));
  }

  void EmitLandingPad(FullDecoder* decoder, int handler_offset) {
    if (decoder->current_catch() == -1) return;
    MovableLabel handler{zone_};

    // If we return from the throwing code normally, just skip over the handler.
    Label skip_handler;
    __ emit_jump(&skip_handler);

    // Handler: merge into the catch state, and jump to the catch body.
    CODE_COMMENT("-- landing pad --");
    __ bind(handler.get());
    __ ExceptionHandler();
    __ PushException();
    handlers_.push_back({std::move(handler), handler_offset});
    Control* current_try =
        decoder->control_at(decoder->control_depth_of_current_catch());
    DCHECK_NOT_NULL(current_try->try_info);
    if (current_try->try_info->catch_reached) {
      __ MergeStackWith(current_try->try_info->catch_state, 1,
                        LiftoffAssembler::kForwardJump);
    } else {
      current_try->try_info->catch_state = __ MergeIntoNewState(
          __ num_locals(), 1,
          current_try->stack_depth + current_try->num_exceptions);
      current_try->try_info->catch_reached = true;
    }
    __ emit_jump(&current_try->try_info->catch_label);

    __ bind(&skip_handler);
    // Drop the exception.
    __ DropValues(1);
  }

  void Throw(FullDecoder* decoder, const TagIndexImmediate& imm,
             const Value* /* args */) {
    LiftoffRegList pinned;

    // Load the encoded size in a register for the builtin call.
    int encoded_size = WasmExceptionPackage::GetEncodedSize(imm.tag);
    LiftoffRegister encoded_size_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    __ LoadConstant(encoded_size_reg, WasmValue::ForUintPtr(encoded_size));

    // Call the WasmAllocateFixedArray builtin to create the values array.
    CallBuiltin(Builtin::kWasmAllocateFixedArray,
                MakeSig::Returns(kIntPtrKind).Params(kIntPtrKind),
                {VarState{kIntPtrKind, LiftoffRegister{encoded_size_reg}, 0}},
                decoder->position());
    MaybeOSR();

    // The FixedArray for the exception values is now in the first gp return
    // register.
    LiftoffRegister values_array{kReturnRegister0};
    pinned.set(values_array);

    // Now store the exception values in the FixedArray. Do this from last to
    // first value, such that we can just pop them from the value stack.
    CODE_COMMENT("fill values array");
    int index = encoded_size;
    auto* sig = imm.tag->sig;
    for (size_t param_idx = sig->parameter_count(); param_idx > 0;
         --param_idx) {
      ValueType type = sig->GetParam(param_idx - 1);
      StoreExceptionValue(type, values_array.gp(), &index, pinned);
    }
    DCHECK_EQ(0, index);

    // Load the exception tag.
    CODE_COMMENT("load exception tag");
    LiftoffRegister exception_tag =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LOAD_TAGGED_PTR_INSTANCE_FIELD(exception_tag.gp(), TagsTable, pinned);
    __ LoadTaggedPointer(
        exception_tag.gp(), exception_tag.gp(), no_reg,
        wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(imm.index));

    // Finally, call WasmThrow.
    CallBuiltin(Builtin::kWasmThrow, MakeSig::Params(kIntPtrKind, kIntPtrKind),
                {VarState{kIntPtrKind, exception_tag, 0},
                 VarState{kIntPtrKind, values_array, 0}},
                decoder->position());

    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    int pc_offset = __ pc_offset();
    MaybeOSR();
    EmitLandingPad(decoder, pc_offset);
  }

  void AtomicStoreMem(FullDecoder* decoder, StoreType type,
                      const MemoryAccessImmediate& imm) {
    LiftoffRegList pinned;
    LiftoffRegister value = pinned.set(__ PopToRegister());
    bool i64_offset = imm.memory->is_memory64();
    auto& index_slot = __ cache_state() -> stack_state.back();
    DCHECK_EQ(i64_offset ? kI64 : kI32, index_slot.kind());
    uintptr_t offset = imm.offset;
    LiftoffRegList outer_pinned;
    Register index = no_reg;

    if (IndexStaticallyInBoundsAndAligned(imm.memory, index_slot, type.size(),
                                          &offset)) {
      __ cache_state() -> stack_state.pop_back();  // Pop index.
      CODE_COMMENT("atomic store (constant offset)");
    } else {
      LiftoffRegister full_index = __ PopToRegister(pinned);
      index =
          BoundsCheckMem(decoder, imm.memory, type.size(), imm.offset,
                         full_index, pinned, kDoForceCheck, kCheckAlignment);
      pinned.set(index);
      CODE_COMMENT("atomic store");
    }
    Register addr = pinned.set(GetMemoryStart(imm.mem_index, pinned));
    if (V8_UNLIKELY(v8_flags.trace_wasm_memory) && index != no_reg) {
      outer_pinned.set(index);
    }
    __ AtomicStore(addr, index, offset, value, type, outer_pinned, i64_offset);
    if (V8_UNLIKELY(v8_flags.trace_wasm_memory)) {
      // TODO(14259): Implement memory tracing for multiple memories.
      CHECK_EQ(0, imm.memory->index);
      TraceMemoryOperation(true, type.mem_rep(), index, offset,
                           decoder->position());
    }
  }

  void AtomicLoadMem(FullDecoder* decoder, LoadType type,
                     const MemoryAccessImmediate& imm) {
    ValueKind kind = type.value_type().kind();
    bool i64_offset = imm.memory->is_memory64();
    auto& index_slot = __ cache_state() -> stack_state.back();
    DCHECK_EQ(i64_offset ? kI64 : kI32, index_slot.kind());
    uintptr_t offset = imm.offset;
    Register index = no_reg;
    LiftoffRegList pinned;

    if (IndexStaticallyInBoundsAndAligned(imm.memory, index_slot, type.size(),
                                          &offset)) {
      __ cache_state() -> stack_state.pop_back();  // Pop index.
      CODE_COMMENT("atomic load (constant offset)");
    } else {
      LiftoffRegister full_index = __ PopToRegister();
      index = BoundsCheckMem(decoder, imm.memory, type.size(), imm.offset,
                             full_index, {}, kDoForceCheck, kCheckAlignment);
      pinned.set(index);
      CODE_COMMENT("atomic load");
    }

    Register addr = pinned.set(GetMemoryStart(imm.mem_index, pinned));
    RegClass rc = reg_class_for(kind);
    LiftoffRegister value = pinned.set(__ GetUnusedRegister(rc, pinned));
    __ AtomicLoad(value, addr, index, offset, type, pinned, i64_offset);
    __ PushRegister(kind, value);

    if (V8_UNLIKELY(v8_flags.trace_wasm_memory)) {
      // TODO(14259): Implement memory tracing for multiple memories.
      CHECK_EQ(0, imm.memory->index);
      TraceMemoryOperation(false, type.mem_type().representation(), index,
                           offset, decoder->position());
    }
  }

  void AtomicBinop(FullDecoder* decoder, StoreType type,
                   const MemoryAccessImmediate& imm,
                   void (LiftoffAssembler::*emit_fn)(Register, Register,
                                                     uintptr_t, LiftoffRegister,
                                                     LiftoffRegister, StoreType,
                                                     bool)) {
    ValueKind result_kind = type.value_type().kind();
    LiftoffRegList pinned;
    LiftoffRegister value = pinned.set(__ PopToRegister());
#ifdef V8_TARGET_ARCH_IA32
    // We have to reuse the value register as the result register so that we
    // don't run out of registers on ia32. For this we use the value register as
    // the result register if it has no other uses. Otherwise we allocate a new
    // register and let go of the value register to get spilled.
    LiftoffRegister result = value;
    if (__ cache_state()->is_used(value)) {
      result = pinned.set(__ GetUnusedRegister(value.reg_class(), pinned));
      __ Move(result, value, result_kind);
      pinned.clear(value);
      value = result;
    }
#else
    LiftoffRegister result =
        pinned.set(__ GetUnusedRegister(value.reg_class(), pinned));
#endif
    auto& index_slot = __ cache_state() -> stack_state.back();
    uintptr_t offset = imm.offset;
    bool i64_offset = imm.memory->is_memory64();
    DCHECK_EQ(i64_offset ? kI64 : kI32, index_slot.kind());
    Register index = no_reg;

    if (IndexStaticallyInBoundsAndAligned(imm.memory, index_slot, type.size(),
                                          &offset)) {
      __ cache_state() -> stack_state.pop_back();  // Pop index.
      CODE_COMMENT("atomic binop (constant offset)");
    } else {
      LiftoffRegister full_index = __ PopToRegister(pinned);
      index =
          BoundsCheckMem(decoder, imm.memory, type.size(), imm.offset,
                         full_index, pinned, kDoForceCheck, kCheckAlignment);

      pinned.set(index);
      CODE_COMMENT("atomic binop");
    }

    Register addr = pinned.set(GetMemoryStart(imm.mem_index, pinned));
    (asm_.*emit_fn)(addr, index, offset, value, result, type, i64_offset);
    __ PushRegister(result_kind, result);
  }

  void AtomicCompareExchange(FullDecoder* decoder, StoreType type,
                             const MemoryAccessImmediate& imm) {
#ifdef V8_TARGET_ARCH_IA32
    // On ia32 we don't have enough registers to first pop all the values off
    // the stack and then start with the code generation. Instead we do the
    // complete address calculation first, so that the address only needs a
    // single register. Afterwards we load all remaining values into the
    // other registers.
    LiftoffRegister full_index = __ PeekToRegister(2, {});

    Register index =
        BoundsCheckMem(decoder, imm.memory, type.size(), imm.offset, full_index,
                       {}, kDoForceCheck, kCheckAlignment);
    LiftoffRegList pinned{index};

    uintptr_t offset = imm.offset;
    Register addr = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    if (imm.memory->index == 0) {
      LOAD_INSTANCE_FIELD(addr, Memory0Start, kSystemPointerSize, pinned);
    } else {
      LOAD_PROTECTED_PTR_INSTANCE_FIELD(addr, MemoryBasesAndSizes, pinned);
      int buffer_offset =
          wasm::ObjectAccess::ToTagged(OFFSET_OF_DATA_START(ByteArray)) +
          kSystemPointerSize * imm.memory->index * 2;
      __ LoadFullPointer(addr, addr, buffer_offset);
    }
    __ emit_i32_add(addr, addr, index);
    pinned.clear(LiftoffRegister(index));
    LiftoffRegister new_value = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister expected = pinned.set(__ PopToRegister(pinned));

    // Pop the index from the stack.
    bool i64_offset = imm.memory->is_memory64();
    DCHECK_EQ(i64_offset ? kI64 : kI32,
              __ cache_state()->stack_state.back().kind());
    __ DropValues(1);

    LiftoffRegister result = expected;
    if (__ cache_state()->is_used(result)) __ SpillRegister(result);

    // We already added the index to addr, so we can just pass no_reg to the
    // assembler now.
    __ AtomicCompareExchange(addr, no_reg, offset, expected, new_value, result,
                             type, i64_offset);
    __ PushRegister(type.value_type().kind(), result);
    return;
#else
    ValueKind result_kind = type.value_type().kind();
    LiftoffRegList pinned;
    LiftoffRegister new_value = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister expected = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister result =
        pinned.set(__ GetUnusedRegister(reg_class_for(result_kind), pinned));

    auto& index_slot = __ cache_state() -> stack_state.back();
    uintptr_t offset = imm.offset;
    bool i64_offset = imm.memory->is_memory64();
    DCHECK_EQ(i64_offset ? kI64 : kI32, index_slot.kind());
    Register index = no_reg;

    if (IndexStaticallyInBoundsAndAligned(imm.memory, index_slot, type.size(),
                                          &offset)) {
      __ cache_state() -> stack_state.pop_back();  // Pop index.
      CODE_COMMENT("atomic cmpxchg (constant offset)");
    } else {
      LiftoffRegister full_index = __ PopToRegister(pinned);
      index =
          BoundsCheckMem(decoder, imm.memory, type.size(), imm.offset,
                         full_index, pinned, kDoForceCheck, kCheckAlignment);
      pinned.set(index);
      CODE_COMMENT("atomic cmpxchg");
    }

    Register addr = pinned.set(GetMemoryStart(imm.mem_index, pinned));
    __ AtomicCompareExchange(addr, index, offset, expected, new_value, result,
                             type, i64_offset);
    __ PushRegister(result_kind, result);
#endif
  }

  void CallBuiltin(Builtin builtin, const ValueKindSig& sig,
                   std::initializer_list<VarState> params, int position) {
    SCOPED_CODE_COMMENT(
        (std::string{"Call builtin: "} + Builtins::name(builtin)));
    auto interface_descriptor = Builtins::CallInterfaceDescriptorFor(builtin);
    auto* call_descriptor = compiler::Linkage::GetStubCallDescriptor(
        zone_,                                          // zone
        interface_descriptor,                           // descriptor
        interface_descriptor.GetStackParameterCount(),  // stack parameter count
        compiler::CallDescriptor::kNoFlags,             // flags
        compiler::Operator::kNoProperties,              // properties
        StubCallMode::kCallWasmRuntimeStub);            // stub call mode

    __ PrepareBuiltinCall(&sig, call_descriptor, params);
    if (position != kNoSourcePosition) {
      source_position_table_builder_.AddPosition(
          __ pc_offset(), SourcePosition(position), true);
    }
    __ CallBuiltin(builtin);
    DefineSafepoint();
  }

  void AtomicWait(FullDecoder* decoder, ValueKind kind,
                  const MemoryAccessImmediate& imm) {
    FUZZER_HEAVY_INSTRUCTION;
    ValueKind index_kind;
    {
      LiftoffRegList pinned;
      LiftoffRegister full_index = __ PeekToRegister(2, pinned);

      Register index_reg =
          BoundsCheckMem(decoder, imm.memory, value_kind_size(kind), imm.offset,
                         full_index, pinned, kDoForceCheck, kCheckAlignment);
      pinned.set(index_reg);

      uintptr_t offset = imm.offset;
      Register index_plus_offset = index_reg;

      if (__ cache_state()->is_used(LiftoffRegister(index_reg))) {
        index_plus_offset =
            pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
        __ Move(index_plus_offset, index_reg, kIntPtrKind);
      }
      if (offset) {
        __ emit_ptrsize_addi(index_plus_offset, index_plus_offset, offset);
      }

      VarState& index = __ cache_state()->stack_state.end()[-3];

      // We replace the index on the value stack with the `index_plus_offset`
      // calculated above. Thereby the BigInt allocation below does not
      // overwrite the calculated value by accident.
      // The kind of `index_plus_offset has to be the same or smaller than the
      // original kind of `index`. The kind of index is kI32 for memory32, and
      // kI64 for memory64. On 64-bit platforms we can use in both cases the
      // kind of `index` also for `index_plus_offset`. Note that
      // `index_plus_offset` fits into a kI32 because we do a bounds check
      // first.
      // On 32-bit platforms, we have to use an kI32 also for memory64, because
      // `index_plus_offset` does not exist in a register pair.
      __ cache_state()->inc_used(LiftoffRegister(index_plus_offset));
      if (index.is_reg()) __ cache_state()->dec_used(index.reg());
      index_kind = index.kind() == kI32 ? kI32 : kIntPtrKind;

      index = VarState{index_kind, LiftoffRegister{index_plus_offset},
                       index.offset()};
    }
    {
      // Convert the top value of the stack (the timeout) from I64 to a BigInt,
      // which we can then pass to the atomic.wait builtin.
      VarState i64_timeout = __ cache_state()->stack_state.back();
      CallBuiltin(
          kNeedI64RegPair ? Builtin::kI32PairToBigInt : Builtin::kI64ToBigInt,
          MakeSig::Returns(kRef).Params(kI64), {i64_timeout},
          decoder->position());
      __ DropValues(1);
      // We put the result on the value stack so that it gets preserved across
      // a potential GC that may get triggered by the BigInt allocation below.
      __ PushRegister(kRef, LiftoffRegister(kReturnRegister0));
    }

    Register expected = no_reg;
    if (kind == kI32) {
      expected = __ PeekToRegister(1, {}).gp();
    } else {
      VarState i64_expected = __ cache_state()->stack_state.end()[-2];
      CallBuiltin(
          kNeedI64RegPair ? Builtin::kI32PairToBigInt : Builtin::kI64ToBigInt,
          MakeSig::Returns(kRef).Params(kI64), {i64_expected},
          decoder->position());
      expected = kReturnRegister0;
    }
    ValueKind expected_kind = kind == kI32 ? kI32 : kRef;

    VarState timeout = __ cache_state()->stack_state.end()[-1];
    VarState index = __ cache_state()->stack_state.end()[-3];

    auto target = kind == kI32 ? Builtin::kWasmI32AtomicWait
                               : Builtin::kWasmI64AtomicWait;

    // The type of {index} can either by i32 or intptr, depending on whether
    // memory32 or memory64 is used. This is okay because both values get passed
    // by register.
    CallBuiltin(target, MakeSig::Params(kI32, index_kind, expected_kind, kRef),
                {{kI32, static_cast<int32_t>(imm.memory->index), 0},
                 index,
                 {expected_kind, LiftoffRegister{expected}, 0},
                 timeout},
                decoder->position());
    // Pop parameters from the value stack.
    __ DropValues(3);

    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    __ PushRegister(kI32, LiftoffRegister(kReturnRegister0));
  }

  void AtomicNotify(FullDecoder* decoder, const MemoryAccessImmediate& imm) {
    LiftoffRegList pinned;
    LiftoffRegister num_waiters_to_wake = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister full_index = __ PopToRegister(pinned);
    Register index_reg =
        BoundsCheckMem(decoder, imm.memory, kInt32Size, imm.offset, full_index,
                       pinned, kDoForceCheck, kCheckAlignment);
    pinned.set(index_reg);

    uintptr_t offset = imm.offset;
    Register addr = index_reg;
    if (__ cache_state()->is_used(LiftoffRegister(index_reg))) {
      addr = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
      __ Move(addr, index_reg, kIntPtrKind);
    }
    if (offset) {
      __ emit_ptrsize_addi(addr, addr, offset);
    }

    Register mem_start = GetMemoryStart(imm.memory->index, pinned);
    __ emit_ptrsize_add(addr, addr, mem_start);

    LiftoffRegister result =
        GenerateCCall(kI32,
                      {{kIntPtrKind, LiftoffRegister{addr}, 0},
                       {kI32, num_waiters_to_wake, 0}},
                      ExternalReference::wasm_atomic_notify());

    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    __ PushRegister(kI32, result);
  }

#define ATOMIC_STORE_LIST(V)        \
  V(I32AtomicStore, kI32Store)      \
  V(I64AtomicStore, kI64Store)      \
  V(I32AtomicStore8U, kI32Store8)   \
  V(I32AtomicStore16U, kI32Store16) \
  V(I64AtomicStore8U, kI64Store8)   \
  V(I64AtomicStore16U, kI64Store16) \
  V(I64AtomicStore32U, kI64Store32)

#define ATOMIC_LOAD_LIST(V)        \
  V(I32AtomicLoad, kI32Load)       \
  V(I64AtomicLoad, kI64Load)       \
  V(I32AtomicLoad8U, kI32Load8U)   \
  V(I32AtomicLoad16U, kI32Load16U) \
  V(I64AtomicLoad8U, kI64Load8U)   \
  V(I64AtomicLoad16U, kI64Load16U) \
  V(I64AtomicLoad32U, kI64Load32U)

#define ATOMIC_BINOP_INSTRUCTION_LIST(V)         \
  V(Add, I32AtomicAdd, kI32Store)                \
  V(Add, I64AtomicAdd, kI64Store)                \
  V(Add, I32AtomicAdd8U, kI32Store8)             \
  V(Add, I32AtomicAdd16U, kI32Store16)           \
  V(Add, I64AtomicAdd8U, kI64Store8)             \
  V(Add, I64AtomicAdd16U, kI64Store16)           \
  V(Add, I64AtomicAdd32U, kI64Store32)           \
  V(Sub, I32AtomicSub, kI32Store)                \
  V(Sub, I64AtomicSub, kI64Store)                \
  V(Sub, I32AtomicSub8U, kI32Store8)             \
  V(Sub, I32AtomicSub16U, kI32Store16)           \
  V(Sub, I64AtomicSub8U, kI64Store8)             \
  V(Sub, I64AtomicSub16U, kI64Store16)           \
  V(Sub, I64AtomicSub32U, kI64Store32)           \
  V(And, I32AtomicAnd, kI32Store)                \
  V(And, I64AtomicAnd, kI64Store)                \
  V(And, I32AtomicAnd8U, kI32Store8)             \
  V(And, I32AtomicAnd16U, kI32Store16)           \
  V(And, I64AtomicAnd8U, kI64Store8)             \
  V(And, I64AtomicAnd16U, kI64Store16)           \
  V(And, I64AtomicAnd32U, kI64Store32)           \
  V(Or, I32AtomicOr, kI32Store)                  \
  V(Or, I64AtomicOr, kI64Store)                  \
  V(Or, I32AtomicOr8U, kI32Store8)               \
  V(Or, I32AtomicOr16U, kI32Store16)             \
  V(Or, I64AtomicOr8U, kI64Store8)               \
  V(Or, I64AtomicOr16U, kI64Store16)             \
  V(Or, I64AtomicOr32U, kI64Store32)             \
  V(Xor, I32AtomicXor, kI32Store)                \
  V(Xor, I64AtomicXor, kI64Store)                \
  V(Xor, I32AtomicXor8U, kI32Store8)             \
  V(Xor, I32AtomicXor16U, kI32Store16)           \
  V(Xor, I64AtomicXor8U, kI64Store8)             \
  V(Xor, I64AtomicXor16U, kI64Store16)           \
  V(Xor, I64AtomicXor32U, kI64Store32)           \
  V(Exchange, I32AtomicExchange, kI32Store)      \
  V(Exchange, I64AtomicExchange, kI64Store)      \
  V(Exchange, I32AtomicExchange8U, kI32Store8)   \
  V(Exchange, I32AtomicExchange16U, kI32Store16) \
  V(Exchange, I64AtomicExchange8U, kI64Store8)   \
  V(Exchange, I64AtomicExchange16U, kI64Store16) \
  V(Exchange, I64AtomicExchange32U, kI64Store32)

#define ATOMIC_COMPARE_EXCHANGE_LIST(V)       \
  V(I32AtomicCompareExchange, kI32Store)      \
  V(I64AtomicCompareExchange, kI64Store)      \
  V(I32AtomicCompareExchange8U, kI32Store8)   \
  V(I32AtomicCompareExchange16U, kI32Store16) \
  V(I64AtomicCompareExchange8U, kI64Store8)   \
  V(I64AtomicCompareExchange16U, kI64Store16) \
  V(I64AtomicCompareExchange32U, kI64Store32)

  void AtomicOp(FullDecoder* decoder, WasmOpcode opcode, const Value args[],
                const size_t argc, const MemoryAccessImmediate& imm,
                Value* result) {
    switch (opcode) {
#define ATOMIC_STORE_OP(name, type)                \
  case wasm::kExpr##name:                          \
    AtomicStoreMem(decoder, StoreType::type, imm); \
    break;

      ATOMIC_STORE_LIST(ATOMIC_STORE_OP)
#undef ATOMIC_STORE_OP

#define ATOMIC_LOAD_OP(name, type)               \
  case wasm::kExpr##name:                        \
    AtomicLoadMem(decoder, LoadType::type, imm); \
    break;

      ATOMIC_LOAD_LIST(ATOMIC_LOAD_OP)
#undef ATOMIC_LOAD_OP

#define ATOMIC_BINOP_OP(op, name, type)                                        \
  case wasm::kExpr##name:                                                      \
    AtomicBinop(decoder, StoreType::type, imm, &LiftoffAssembler::Atomic##op); \
    break;

      ATOMIC_BINOP_INSTRUCTION_LIST(ATOMIC_BINOP_OP)
#undef ATOMIC_BINOP_OP

#define ATOMIC_COMPARE_EXCHANGE_OP(name, type)            \
  case wasm::kExpr##name:                                 \
    AtomicCompareExchange(decoder, StoreType::type, imm); \
    break;

      ATOMIC_COMPARE_EXCHANGE_LIST(ATOMIC_COMPARE_EXCHANGE_OP)
#undef ATOMIC_COMPARE_EXCHANGE_OP

      case kExprI32AtomicWait:
        AtomicWait(decoder, kI32, imm);
        break;
      case kExprI64AtomicWait:
        AtomicWait(decoder, kI64, imm);
        break;
      case kExprAtomicNotify:
        AtomicNotify(decoder, imm);
        break;
      default:
        UNREACHABLE();
    }
  }

#undef ATOMIC_STORE_LIST
#undef ATOMIC_LOAD_LIST
#undef ATOMIC_BINOP_INSTRUCTION_LIST
#undef ATOMIC_COMPARE_EXCHANGE_LIST

  void AtomicFence(FullDecoder* decoder) { __ AtomicFence(); }

  // Pop a VarState and if needed transform it to an intptr.
  // When truncating from u64 to u32, the {*high_word} is updated to contain
  // the ORed combination of all high words.
  VarState PopIndexToVarState(Register* high_word, LiftoffRegList* pinned) {
    VarState slot = __ PopVarState();
    const bool is_64bit_value = slot.kind() == kI64;
    // For memory32 on a 32-bit system or memory64 on a 64-bit system, there is
    // nothing to do.
    if (Is64() == is_64bit_value) {
      if (slot.is_reg()) pinned->set(slot.reg());
      return slot;
    }

    // {kI64} constants will be stored as 32-bit integers in the {VarState} and
    // will be sign-extended later. Hence we can return constants if they are
    // positive (such that sign-extension and zero-extension are identical).
    if (slot.is_const() && (kIntPtrKind == kI32 || slot.i32_const() >= 0)) {
      return {kIntPtrKind, slot.i32_const(), 0};
    }

    // For memory32 on 64-bit hosts, zero-extend.
    if constexpr (Is64()) {
      DCHECK(!is_64bit_value);  // Handled above.
      LiftoffRegister reg = __ LoadToModifiableRegister(slot, *pinned);
      __ emit_u32_to_uintptr(reg.gp(), reg.gp());
      pinned->set(reg);
      return {kIntPtrKind, reg, 0};
    }

    // For memory64 on 32-bit systems, combine all high words for a zero-check
    // and only use the low words afterwards. This keeps the register pressure
    // managable.
    DCHECK(is_64bit_value && !Is64());  // Other cases are handled above.
    LiftoffRegister reg = __ LoadToRegister(slot, *pinned);
    pinned->set(reg.low());
    if (*high_word == no_reg) {
      // Choose a register to hold the (combination of) high word(s). It cannot
      // be one of the pinned registers, and it cannot be used in the value
      // stack.
      *high_word =
          !pinned->has(reg.high()) && __ cache_state()->is_free(reg.high())
              ? reg.high().gp()
              : __ GetUnusedRegister(kGpReg, *pinned).gp();
      pinned->set(*high_word);
      if (*high_word != reg.high_gp()) {
        __ Move(*high_word, reg.high_gp(), kI32);
      }
    } else if (*high_word != reg.high_gp()) {
      // Combine the new high word into existing high words.
      __ emit_i32_or(*high_word, *high_word, reg.high_gp());
    }
    return {kIntPtrKind, reg.low(), 0};
  }

  // This is a helper function that traps with TableOOB if any bit is set in
  // `high_word`. It is meant to be used after `PopIndexToVarState()` to check
  // if the conversion was valid.
  // Note that this is suboptimal as we add an OOL code for this special
  // condition, and there's also another conditional trap in the caller builtin.
  // However, it only applies for the rare case of 32-bit platforms with
  // table64.
  void CheckHighWordEmptyForTableType(FullDecoder* decoder,
                                      const Register high_word,
                                      LiftoffRegList* pinned) {
    if constexpr (Is64()) {
      DCHECK_EQ(no_reg, high_word);
      return;
    }
    if (high_word == no_reg) return;

    Label* trap_label =
        AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapTableOutOfBounds);
    FREEZE_STATE(trapping);
    __ emit_cond_jump(kNotZero, trap_label, kI32, high_word, no_reg, trapping);
    // Clearing `high_word` is safe because this never aliases with another
    // in-use register, see `PopIndexToVarState()`.
    pinned->clear(high_word);
  }

  // Same as {PopIndexToVarState}, but can take a VarState in the middle of the
  // stack without popping it.
  // For 64-bit values on 32-bit systems, the resulting VarState will contain a
  // single register whose value will be 
"""


```