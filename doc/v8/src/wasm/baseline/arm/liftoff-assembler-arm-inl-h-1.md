Response:
The user wants a summary of the functionality of the provided C++ code snippet. The snippet is part of the V8 JavaScript engine, specifically the Liftoff baseline compiler for the ARM architecture.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the file's purpose:** The filename `liftoff-assembler-arm-inl.h` strongly suggests this file contains inline implementations for the Liftoff assembler on ARM. Liftoff is a baseline compiler for WebAssembly in V8.

2. **Scan for key function names:** Look for prominent function names within the code. These often indicate core functionalities. Examples include:
    * `LoadTaggedPointer`, `StoreTaggedPointer`: Likely deals with tagged pointers (V8's representation of JavaScript values).
    * `LoadFullPointer`:  Probably loads a raw pointer.
    * `Load`, `Store`: Generic load and store operations.
    * `AtomicLoad`, `AtomicStore`, `AtomicAdd`, etc.: Indicate support for atomic operations.
    * `LoadCallerFrameSlot`, `StoreCallerFrameSlot`, `LoadReturnStackSlot`: Suggest interaction with the call stack and frame management.
    * `MoveStackValue`:  Moving data on the stack.
    * `Move`: Register-to-register moves.
    * `Spill`, `Fill`: Moving data between registers and the stack (spilling and filling).
    * `emit_i32_add`, `emit_i32_sub`, etc.:  Code generation for specific i32 operations.

3. **Group related functions:** Observe patterns and group functions with similar prefixes or purposes. For instance, all the `Atomic*` functions clearly relate to atomic memory operations. The `Load*` and `Store*` functions handle memory access.

4. **Infer functionality from function names and parameters:** Based on the names and parameters, infer the high-level functionality of each group. For example:
    * `Load/Store Tagged Pointers`: These probably deal with reading and writing JavaScript values in memory, handling tagging and potential write barriers.
    * `Load/Store Full Pointers`:  Likely simpler, direct memory access.
    * `Atomic Operations`: Implement thread-safe operations on memory locations.
    * `Stack Operations`: Manage data within the function's call frame and the return stack.
    * `Register Moves`: Copy data between registers.
    * `Spill/Fill`:  Handle register allocation by moving data to and from the stack when registers are needed.
    * `emit_*`: These functions are likely responsible for generating the actual ARM assembly instructions for basic arithmetic and logical operations.

5. **Note specific details and assertions:** Pay attention to `static_assert` statements, comments (though minimal in this snippet), and specific instruction names (`ldr`, `str`, `add`, `sub`, `vmov`, etc.). These can provide more precise insights. For example, the `static_assert(!V8_ENABLE_SANDBOX_BOOL)` suggests these protected load/store functions are related to security and memory isolation. The use of NEON instructions for floating-point stores implies optimization.

6. **Address the user's specific questions:**
    * **.tq extension:** The code doesn't end in `.tq`, so it's not Torque code.
    * **Relationship to JavaScript:**  The presence of `LoadTaggedPointer` and the overall context of V8 strongly indicate a connection to JavaScript. The code is generating low-level instructions to execute JavaScript/WebAssembly code.
    * **JavaScript example:**  Think of a simple JavaScript operation that would require memory access or arithmetic. `let x = obj.y + 1;` would involve loading the value of `obj.y`, adding 1, and storing the result back. This would likely involve some of the functions seen in the snippet.
    * **Code logic/input-output:** Choose a simple function like `LoadProtectedPointer`. The input is a destination register, a source address register, and an offset. The output is the value loaded from memory at the calculated address into the destination register.
    * **Common programming errors:** Focus on errors related to memory access, such as out-of-bounds access or incorrect pointer usage.
    * **Code style:**  Note the consistent use of `LiftoffAssembler` and the ARM assembly instruction mnemonics.

7. **Synthesize the summary:** Combine the observations and inferences into a concise summary that addresses the user's request. Organize the summary by grouping related functionalities.

8. **Refine and clarify:** Review the summary for clarity and accuracy. Ensure it addresses all parts of the user's prompt. For example, explicitly mention that this code is for the ARM architecture and part of the Liftoff compiler.

By following these steps, we can construct a comprehensive and accurate summary of the provided V8 source code snippet.
这是目录为`v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h` 的 V8 源代码的第二部分，它主要包含了 `LiftoffAssembler` 类中关于内存操作、原子操作以及一些辅助功能的内联实现，用于在 ARM 架构上为 WebAssembly 的 Liftoff 编译器生成汇编代码。

以下是该部分代码的功能归纳：

**1. 受保护和非受保护的内存加载和存储：**

* **`LoadTaggedPointer` 和 `StoreTaggedPointer`**:  处理 V8 中带标签指针的加载和存储。这些指针通常用于表示 JavaScript 对象和值。`StoreTaggedPointer` 还包含了写屏障的逻辑，用于垃圾回收器的正确性。
* **`LoadProtectedPointer`**:  加载受保护的指针（在没有沙箱的情况下，其行为与 `LoadTaggedPointer` 相同）。
* **`LoadFullPointer`**: 加载完整的、未加标签的指针。
* **`Load` 和 `Store`**:  通用的加载和存储操作，可以处理不同大小和类型的 WebAssembly 数据（i32, i64, f32, f64, s128）。`Store` 方法针对不同的数据类型使用了不同的 ARM 指令，例如 `strb` (byte), `strh` (half-word), `str` (word/double-word), `vst1` (NEON 寄存器存储)。

**2. 原子操作：**

该部分实现了 WebAssembly 的原子操作，确保在多线程环境中的数据一致性。

* **`AtomicLoad`**: 原子加载不同类型的 WebAssembly 值。对于 64 位加载，它使用 `ldrexd` 指令，确保 64 位值被原子地读取。
* **`AtomicStore`**: 原子存储不同类型的 WebAssembly 值。对于 64 位存储，它使用 `strexd` 指令。
* **`AtomicAdd`，`AtomicSub`，`AtomicAnd`，`AtomicOr`，`AtomicXor`，`AtomicExchange`**: 实现原子的加、减、与、或、异或和交换操作。这些操作使用了 ARM 的独占加载/存储指令 (`ldrex`, `strex`, `ldrexb`, `strexb`, `ldrexh`, `strexh`) 来实现原子性。对于 64 位操作，使用了 `ldrexd` 和 `strexd`。
* **`AtomicCompareExchange`**: 实现原子的比较并交换操作。类似于其他原子操作，它也使用了独占加载/存储指令。对于 64 位操作，使用了 `ldrexd` 和 `strexd`，并需要处理寄存器分配的特殊约束。
* **`AtomicFence`**:  插入内存屏障指令 (`dmb ISH`)，确保内存操作的顺序性。

**3. 栈帧和栈操作：**

* **`LoadCallerFrameSlot` 和 `StoreCallerFrameSlot`**: 加载和存储调用者栈帧中的槽位，用于访问传递给当前函数的参数或本地变量。
* **`LoadReturnStackSlot`**:  加载返回栈中的槽位。
* **`MoveStackValue`**: 在栈上的不同位置之间移动数据。

**4. 寄存器操作：**

* **`Move` (寄存器到寄存器)**:  在通用寄存器和浮点/SIMD 寄存器之间移动数据。
* **`Spill`**: 将寄存器的值保存到栈上。
* **`Fill`**: 将栈上的值加载到寄存器中。
* **`FillI64Half`**:  加载 64 位值的一半到寄存器。
* **`FillStackSlotsWithZero`**: 将栈上的指定区域填充为零。
* **`LoadSpillAddress`**:  加载栈上溢出位置的地址到寄存器。

**5. 基本的 i32 操作的汇编代码生成：**

该部分包含了一系列 `emit_i32_*` 函数，用于生成 i32 类型的基本算术和逻辑运算的 ARM 汇编指令，例如加法、减法、乘法、与、或、异或、移位等。

**关于用户提出的问题：**

* **`.tq` 结尾**:  这段代码没有以 `.tq` 结尾，因此它不是 V8 Torque 源代码。它是用 C++ 编写的。
* **与 JavaScript 的关系**: 这段代码是 V8 JavaScript 引擎的一部分，用于执行 WebAssembly 代码。当 JavaScript 调用 WebAssembly 模块时，或者 WebAssembly 模块内部执行计算时，Liftoff 编译器会使用此类生成底层的 ARM 汇编指令。

**JavaScript 例子 (说明内存加载和存储):**

```javascript
// 假设有一个 WebAssembly 模块实例
const wasmInstance = ...;
const linearMemory = wasmInstance.exports.memory;
const buffer = new Uint32Array(linearMemory.buffer);

// WebAssembly 代码中可能有类似的操作，由 Liftoff 编译成汇编指令
const offset = 10;
const valueToStore = 12345;

// 模拟 WebAssembly 存储操作，Liftoff 会将其编译成类似 Store 指令
buffer[offset] = valueToStore;

// 模拟 WebAssembly 加载操作，Liftoff 会将其编译成类似 Load 指令
const loadedValue = buffer[offset + 1];
```

在这个例子中，`buffer[offset] = valueToStore;`  在 WebAssembly 层面会对应一个存储操作，Liftoff 可能会将其编译成 `LiftoffAssembler::Store` 函数中的指令。同样，`const loadedValue = buffer[offset + 1];` 会对应一个加载操作。

**代码逻辑推理 (以 `LoadProtectedPointer` 为例):**

**假设输入:**

* `dst`: 寄存器 `r0` (目标寄存器)
* `src_addr`: 寄存器 `r1` (源地址寄存器，假设其值为内存地址 `0x1000`)
* `offset`: 整数偏移量 `8`

**输出:**

假设内存地址 `0x1008` 处存储的值是 `0xABCDEF00`。执行 `LoadProtectedPointer(r0, r1, 8)` 后，寄存器 `r0` 的值将会是 `0xABCDEF00`。

**常见的编程错误举例:**

* **内存越界访问:** 在 WebAssembly 中，尝试访问线性内存范围之外的地址会导致错误。Liftoff 生成的代码依赖于 WebAssembly 运行时的边界检查，但如果编译器的某些部分存在错误，可能会导致生成错误的地址计算，从而导致越界访问。例如，错误的偏移量计算可能导致 `Load` 或 `Store` 指令访问到不应该访问的内存。
* **类型不匹配的加载/存储:**  如果 WebAssembly 代码指示加载一个 i32 值，但实际内存位置存储的是一个 f64 值，则加载的结果将是未定义的。Liftoff 编译器需要正确地根据类型生成相应的加载和存储指令。

**总结:**

这部分 `liftoff-assembler-arm-inl.h` 代码的核心功能是为 ARM 架构上的 WebAssembly Liftoff 编译器提供了一组用于生成汇编代码的构建块，涵盖了基本的内存访问、原子操作、栈帧管理和基础的 i32 运算。它负责将 WebAssembly 的高级操作转化为可以在 ARM 处理器上执行的底层指令。

Prompt: 
```
这是目录为v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
fset_imm, LoadType::kI32Load, protected_load_pc,
                        needs_shift);
}

void LiftoffAssembler::LoadProtectedPointer(Register dst, Register src_addr,
                                            int32_t offset) {
  static_assert(!V8_ENABLE_SANDBOX_BOOL);
  LoadTaggedPointer(dst, src_addr, no_reg, offset);
}

void LiftoffAssembler::LoadFullPointer(Register dst, Register src_addr,
                                       int32_t offset_imm) {
  UseScratchRegisterScope temps(this);
  MemOperand src_op =
      liftoff::GetMemOp(this, &temps, src_addr, no_reg, offset_imm);
  ldr(dst, src_op);
}

void LiftoffAssembler::StoreTaggedPointer(Register dst_addr,
                                          Register offset_reg,
                                          int32_t offset_imm, Register src,
                                          LiftoffRegList pinned,
                                          uint32_t* protected_store_pc,
                                          SkipWriteBarrier skip_write_barrier) {
  static_assert(kTaggedSize == kInt32Size);
  UseScratchRegisterScope temps{this};
  Register actual_offset_reg = offset_reg;
  if (offset_reg != no_reg && offset_imm != 0) {
    if (cache_state()->is_used(LiftoffRegister(offset_reg))) {
      // The code below only needs a scratch register if the {MemOperand} given
      // to {str} has an offset outside the uint12 range. After doing the
      // addition below we will not pass an immediate offset to {str} though, so
      // we can use the scratch register here.
      actual_offset_reg = temps.Acquire();
    }
    add(actual_offset_reg, offset_reg, Operand(offset_imm));
  }
  MemOperand dst_op = actual_offset_reg == no_reg
                          ? MemOperand(dst_addr, offset_imm)
                          : MemOperand(dst_addr, actual_offset_reg);

  if (protected_store_pc) *protected_store_pc = pc_offset();

  str(src, dst_op);

  if (skip_write_barrier || v8_flags.disable_write_barriers) return;

  // The write barrier.
  Label exit;
  CheckPageFlag(dst_addr, MemoryChunk::kPointersFromHereAreInterestingMask,
                kZero, &exit);
  JumpIfSmi(src, &exit);
  CheckPageFlag(src, MemoryChunk::kPointersToHereAreInterestingMask, eq, &exit);
  CallRecordWriteStubSaveRegisters(
      dst_addr,
      actual_offset_reg == no_reg ? Operand(offset_imm)
                                  : Operand(actual_offset_reg),
      SaveFPRegsMode::kSave, StubCallMode::kCallWasmRuntimeStub);
  bind(&exit);
}

void LiftoffAssembler::Load(LiftoffRegister dst, Register src_addr,
                            Register offset_reg, uint32_t offset_imm,
                            LoadType type, uint32_t* protected_load_pc,
                            bool /* is_load_mem */, bool /* i64_offset */,
                            bool needs_shift) {
  // Offsets >=2GB are statically OOB on 32-bit systems.
  DCHECK_LE(offset_imm, std::numeric_limits<int32_t>::max());
  liftoff::LoadInternal(this, dst, src_addr, offset_reg,
                        static_cast<int32_t>(offset_imm), type,
                        protected_load_pc, needs_shift);
}

void LiftoffAssembler::Store(Register dst_addr, Register offset_reg,
                             uint32_t offset_imm, LiftoffRegister src,
                             StoreType type, LiftoffRegList pinned,
                             uint32_t* protected_store_pc,
                             bool /* is_store_mem */, bool /* i64_offset */) {
  // Offsets >=2GB are statically OOB on 32-bit systems.
  DCHECK_LE(offset_imm, std::numeric_limits<int32_t>::max());
  UseScratchRegisterScope temps{this};
  if (type.value() == StoreType::kF64Store) {
    Register actual_dst_addr = liftoff::CalculateActualAddress(
        this, &temps, dst_addr, offset_reg, offset_imm);
    // Armv6 is not supported so Neon can be used to avoid alignment issues.
    CpuFeatureScope scope(this, NEON);
    vst1(Neon64, NeonListOperand(src.fp()), NeonMemOperand(actual_dst_addr));
  } else if (type.value() == StoreType::kS128Store) {
    Register actual_dst_addr = liftoff::CalculateActualAddress(
        this, &temps, dst_addr, offset_reg, offset_imm);
    // Armv6 is not supported so Neon can be used to avoid alignment issues.
    CpuFeatureScope scope(this, NEON);
    vst1(Neon8, NeonListOperand(src.low_fp(), 2),
         NeonMemOperand(actual_dst_addr));
  } else if (type.value() == StoreType::kF32Store) {
    // TODO(arm): Use vst1 for f32 when implemented in simulator as used for
    // f64. It supports unaligned access.
    Register actual_dst_addr = liftoff::CalculateActualAddress(
        this, &temps, dst_addr, offset_reg, offset_imm);
    liftoff::CacheStatePreservingTempRegisters liftoff_temps{this, pinned};
    Register scratch =
        temps.CanAcquire() ? temps.Acquire() : liftoff_temps.Acquire();
    vmov(scratch, liftoff::GetFloatRegister(src.fp()));
    str(scratch, MemOperand(actual_dst_addr));
  } else {
    MemOperand dst_op =
        liftoff::GetMemOp(this, &temps, dst_addr, offset_reg, offset_imm);
    if (protected_store_pc) *protected_store_pc = pc_offset();
    switch (type.value()) {
      case StoreType::kI64Store8:
        src = src.low();
        [[fallthrough]];
      case StoreType::kI32Store8:
        strb(src.gp(), dst_op);
        break;
      case StoreType::kI64Store16:
        src = src.low();
        [[fallthrough]];
      case StoreType::kI32Store16:
        strh(src.gp(), dst_op);
        break;
      case StoreType::kI64Store32:
        src = src.low();
        [[fallthrough]];
      case StoreType::kI32Store:
        str(src.gp(), dst_op);
        break;
      case StoreType::kI64Store:
        str(src.low_gp(), dst_op);
        // GetMemOp may use a scratch register as the offset register, in which
        // case, calling GetMemOp again will fail due to the assembler having
        // ran out of scratch registers.
        if (temps.CanAcquire()) {
          dst_op = liftoff::GetMemOp(this, &temps, dst_addr, offset_reg,
                                     offset_imm + kSystemPointerSize);
        } else {
          add(dst_op.rm(), dst_op.rm(), Operand(kSystemPointerSize));
        }
        str(src.high_gp(), dst_op);
        break;
      default:
        UNREACHABLE();
    }
  }
}

namespace liftoff {
#define __ lasm->

inline void AtomicOp32(
    LiftoffAssembler* lasm, Register dst_addr, Register offset_reg,
    uint32_t offset_imm, LiftoffRegister value, LiftoffRegister result,
    LiftoffRegList pinned,
    void (Assembler::*load)(Register, Register, Condition),
    void (Assembler::*store)(Register, Register, Register, Condition),
    void (*op)(LiftoffAssembler*, Register, Register, Register)) {
  Register store_result = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();

  // Allocate an additional {temp} register to hold the result that should be
  // stored to memory. Note that {temp} and {store_result} are not allowed to be
  // the same register.
  Register temp = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();

  // {LiftoffCompiler::AtomicBinop} ensures that {result} is unique.
  DCHECK(result.gp() != value.gp() && result.gp() != dst_addr &&
         result.gp() != offset_reg);

  UseScratchRegisterScope temps(lasm);
  Register actual_addr = liftoff::CalculateActualAddress(
      lasm, &temps, dst_addr, offset_reg, offset_imm);

  __ dmb(ISH);
  Label retry;
  __ bind(&retry);
  (lasm->*load)(result.gp(), actual_addr, al);
  op(lasm, temp, result.gp(), value.gp());
  (lasm->*store)(store_result, temp, actual_addr, al);
  __ cmp(store_result, Operand(0));
  __ b(ne, &retry);
  __ dmb(ISH);
}

inline void Add(LiftoffAssembler* lasm, Register dst, Register lhs,
                Register rhs) {
  __ add(dst, lhs, rhs);
}

inline void Sub(LiftoffAssembler* lasm, Register dst, Register lhs,
                Register rhs) {
  __ sub(dst, lhs, rhs);
}

inline void And(LiftoffAssembler* lasm, Register dst, Register lhs,
                Register rhs) {
  __ and_(dst, lhs, rhs);
}

inline void Or(LiftoffAssembler* lasm, Register dst, Register lhs,
               Register rhs) {
  __ orr(dst, lhs, rhs);
}

inline void Xor(LiftoffAssembler* lasm, Register dst, Register lhs,
                Register rhs) {
  __ eor(dst, lhs, rhs);
}

inline void Exchange(LiftoffAssembler* lasm, Register dst, Register lhs,
                     Register rhs) {
  __ mov(dst, rhs);
}

inline void AtomicBinop32(LiftoffAssembler* lasm, Register dst_addr,
                          Register offset_reg, uint32_t offset_imm,
                          LiftoffRegister value, LiftoffRegister result,
                          StoreType type,
                          void (*op)(LiftoffAssembler*, Register, Register,
                                     Register)) {
  LiftoffRegList pinned{dst_addr, value, result};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  switch (type.value()) {
    case StoreType::kI64Store8:
      __ LoadConstant(result.high(), WasmValue(0));
      result = result.low();
      value = value.low();
      [[fallthrough]];
    case StoreType::kI32Store8:
      liftoff::AtomicOp32(lasm, dst_addr, offset_reg, offset_imm, value, result,
                          pinned, &Assembler::ldrexb, &Assembler::strexb, op);
      return;
    case StoreType::kI64Store16:
      __ LoadConstant(result.high(), WasmValue(0));
      result = result.low();
      value = value.low();
      [[fallthrough]];
    case StoreType::kI32Store16:
      liftoff::AtomicOp32(lasm, dst_addr, offset_reg, offset_imm, value, result,
                          pinned, &Assembler::ldrexh, &Assembler::strexh, op);
      return;
    case StoreType::kI64Store32:
      __ LoadConstant(result.high(), WasmValue(0));
      result = result.low();
      value = value.low();
      [[fallthrough]];
    case StoreType::kI32Store:
      liftoff::AtomicOp32(lasm, dst_addr, offset_reg, offset_imm, value, result,
                          pinned, &Assembler::ldrex, &Assembler::strex, op);
      return;
    default:
      UNREACHABLE();
  }
}

inline void AtomicOp64(LiftoffAssembler* lasm, Register dst_addr,
                       Register offset_reg, uint32_t offset_imm,
                       LiftoffRegister value,
                       std::optional<LiftoffRegister> result,
                       void (*op)(LiftoffAssembler*, LiftoffRegister,
                                  LiftoffRegister, LiftoffRegister)) {
  // strexd loads a 64 bit word into two registers. The first register needs
  // to have an even index, e.g. r8, the second register needs to be the one
  // with the next higher index, e.g. r9 if the first register is r8. In the
  // following code we use the fixed register pair r8/r9 to make the code here
  // simpler, even though other register pairs would also be possible.
  constexpr Register dst_low = r8;
  constexpr Register dst_high = r9;

  // Make sure {dst_low} and {dst_high} are not occupied by any other value.
  Register value_low = value.low_gp();
  Register value_high = value.high_gp();
  LiftoffRegList pinned{dst_low, dst_high};
  auto regs_to_check = {&dst_addr, &offset_reg, &value_low, &value_high};
  auto re_pin = [regs_to_check, &pinned] {
    for (auto* reg : regs_to_check) {
      if (*reg != no_reg) pinned.set(*reg);
    }
  };
  re_pin();
  __ ClearRegister(dst_low, regs_to_check, pinned);
  re_pin();
  __ ClearRegister(dst_high, regs_to_check, pinned);
  re_pin();

  // Make sure that {result}, if it exists, also does not overlap with
  // {dst_low} and {dst_high}. We don't have to transfer the value stored in
  // {result}.
  Register result_low = no_reg;
  Register result_high = no_reg;
  if (result.has_value()) {
    result_low = result.value().low_gp();
    if (pinned.has(result_low)) {
      result_low = __ GetUnusedRegister(kGpReg, pinned).gp();
    }
    pinned.set(result_low);

    result_high = result.value().high_gp();
    if (pinned.has(result_high)) {
      result_high = __ GetUnusedRegister(kGpReg, pinned).gp();
    }
    pinned.set(result_high);
  }

  Register store_result = __ GetUnusedRegister(kGpReg, pinned).gp();

  UseScratchRegisterScope temps(lasm);
  Register actual_addr = liftoff::CalculateActualAddress(
      lasm, &temps, dst_addr, offset_reg, offset_imm);

  __ dmb(ISH);
  Label retry;
  __ bind(&retry);
  // {ldrexd} is needed here so that the {strexd} instruction below can
  // succeed. We don't need the value we are reading. We use {dst_low} and
  // {dst_high} as the destination registers because {ldrexd} has the same
  // restrictions on registers as {strexd}, see the comment above.
  __ ldrexd(dst_low, dst_high, actual_addr);
  if (result.has_value()) {
    __ mov(result_low, dst_low);
    __ mov(result_high, dst_high);
  }
  op(lasm, LiftoffRegister::ForPair(dst_low, dst_high),
     LiftoffRegister::ForPair(dst_low, dst_high),
     LiftoffRegister::ForPair(value_low, value_high));
  __ strexd(store_result, dst_low, dst_high, actual_addr);
  __ cmp(store_result, Operand(0));
  __ b(ne, &retry);
  __ dmb(ISH);

  if (result.has_value()) {
    if (result_low != result.value().low_gp()) {
      __ mov(result.value().low_gp(), result_low);
    }
    if (result_high != result.value().high_gp()) {
      __ mov(result.value().high_gp(), result_high);
    }
  }
}

inline void I64Store(LiftoffAssembler* lasm, LiftoffRegister dst,
                     LiftoffRegister, LiftoffRegister src) {
  __ mov(dst.low_gp(), src.low_gp());
  __ mov(dst.high_gp(), src.high_gp());
}

#undef __
}  // namespace liftoff

void LiftoffAssembler::AtomicLoad(LiftoffRegister dst, Register src_addr,
                                  Register offset_reg, uint32_t offset_imm,
                                  LoadType type, LiftoffRegList /* pinned */,
                                  bool /* i64_offset */) {
  if (type.value() != LoadType::kI64Load) {
    Load(dst, src_addr, offset_reg, offset_imm, type, nullptr, true);
    dmb(ISH);
    return;
  }
  // ldrexd loads a 64 bit word into two registers. The first register needs to
  // have an even index, e.g. r8, the second register needs to be the one with
  // the next higher index, e.g. r9 if the first register is r8. In the
  // following code we use the fixed register pair r8/r9 to make the code here
  // simpler, even though other register pairs would also be possible.
  constexpr Register dst_low = r8;
  constexpr Register dst_high = r9;
  SpillRegisters(dst_low, dst_high);
  {
    UseScratchRegisterScope temps(this);
    Register actual_addr = liftoff::CalculateActualAddress(
        this, &temps, src_addr, offset_reg, offset_imm);
    ldrexd(dst_low, dst_high, actual_addr);
    dmb(ISH);
  }

  ParallelRegisterMove(
      {{dst, LiftoffRegister::ForPair(dst_low, dst_high), kI64}});
}

void LiftoffAssembler::AtomicStore(Register dst_addr, Register offset_reg,
                                   uint32_t offset_imm, LiftoffRegister src,
                                   StoreType type, LiftoffRegList pinned,
                                   bool /* i64_offset */) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicOp64(this, dst_addr, offset_reg, offset_imm, src, {},
                        liftoff::I64Store);
    return;
  }

  dmb(ISH);
  Store(dst_addr, offset_reg, offset_imm, src, type, pinned, nullptr, true);
  dmb(ISH);
  return;
}

void LiftoffAssembler::AtomicAdd(Register dst_addr, Register offset_reg,
                                 uint32_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool /* i64_offset */) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicOp64(this, dst_addr, offset_reg, offset_imm, value, {result},
                        liftoff::I64Binop<&Assembler::add, &Assembler::adc>);
    return;
  }
  liftoff::AtomicBinop32(this, dst_addr, offset_reg, offset_imm, value, result,
                         type, &liftoff::Add);
}

void LiftoffAssembler::AtomicSub(Register dst_addr, Register offset_reg,
                                 uint32_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool /* i64_offset */) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicOp64(this, dst_addr, offset_reg, offset_imm, value, {result},
                        liftoff::I64Binop<&Assembler::sub, &Assembler::sbc>);
    return;
  }
  liftoff::AtomicBinop32(this, dst_addr, offset_reg, offset_imm, value, result,
                         type, &liftoff::Sub);
}

void LiftoffAssembler::AtomicAnd(Register dst_addr, Register offset_reg,
                                 uint32_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool /* i64_offset */) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicOp64(this, dst_addr, offset_reg, offset_imm, value, {result},
                        liftoff::I64Binop<&Assembler::and_, &Assembler::and_>);
    return;
  }
  liftoff::AtomicBinop32(this, dst_addr, offset_reg, offset_imm, value, result,
                         type, &liftoff::And);
}

void LiftoffAssembler::AtomicOr(Register dst_addr, Register offset_reg,
                                uint32_t offset_imm, LiftoffRegister value,
                                LiftoffRegister result, StoreType type,
                                bool /* i64_offset */) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicOp64(this, dst_addr, offset_reg, offset_imm, value, {result},
                        liftoff::I64Binop<&Assembler::orr, &Assembler::orr>);
    return;
  }
  liftoff::AtomicBinop32(this, dst_addr, offset_reg, offset_imm, value, result,
                         type, &liftoff::Or);
}

void LiftoffAssembler::AtomicXor(Register dst_addr, Register offset_reg,
                                 uint32_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool /* i64_offset */) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicOp64(this, dst_addr, offset_reg, offset_imm, value, {result},
                        liftoff::I64Binop<&Assembler::eor, &Assembler::eor>);
    return;
  }
  liftoff::AtomicBinop32(this, dst_addr, offset_reg, offset_imm, value, result,
                         type, &liftoff::Xor);
}

void LiftoffAssembler::AtomicExchange(Register dst_addr, Register offset_reg,
                                      uint32_t offset_imm,
                                      LiftoffRegister value,
                                      LiftoffRegister result, StoreType type,
                                      bool /* i64_offset */) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicOp64(this, dst_addr, offset_reg, offset_imm, value, {result},
                        liftoff::I64Store);
    return;
  }
  liftoff::AtomicBinop32(this, dst_addr, offset_reg, offset_imm, value, result,
                         type, &liftoff::Exchange);
}

namespace liftoff {
#define __ lasm->

inline void AtomicI64CompareExchange(LiftoffAssembler* lasm,
                                     Register dst_addr_reg, Register offset_reg,
                                     uint32_t offset_imm,
                                     LiftoffRegister expected,
                                     LiftoffRegister new_value,
                                     LiftoffRegister result) {
  // To implement I64AtomicCompareExchange, we nearly need all registers, with
  // some registers having special constraints, e.g. like for {new_value} and
  // {result} the low-word register has to have an even register code, and the
  // high-word has to be in the next higher register. To avoid complicated
  // register allocation code here, we just assign fixed registers to all
  // values here, and then move all values into the correct register.
  Register dst_addr = r0;
  Register offset = r1;
  Register result_low = r4;
  Register result_high = r5;
  Register new_value_low = r2;
  Register new_value_high = r3;
  Register store_result = r6;
  Register expected_low = r8;
  Register expected_high = r9;

  // We spill all registers, so that we can re-assign them afterwards.
  __ SpillRegisters(dst_addr, offset, result_low, result_high, new_value_low,
                    new_value_high, store_result, expected_low, expected_high);

  __ ParallelRegisterMove(
      {{LiftoffRegister::ForPair(new_value_low, new_value_high), new_value,
        kI64},
       {LiftoffRegister::ForPair(expected_low, expected_high), expected, kI64},
       {dst_addr, dst_addr_reg, kI32},
       {offset, offset_reg != no_reg ? offset_reg : offset, kI32}});

  {
    UseScratchRegisterScope temps(lasm);
    [[maybe_unused]] Register temp = liftoff::CalculateActualAddress(
        lasm, &temps, dst_addr, offset_reg == no_reg ? no_reg : offset,
        offset_imm, dst_addr);
    // Make sure the actual address is stored in the right register.
    DCHECK_EQ(dst_addr, temp);
  }

  Label retry;
  Label done;
  __ dmb(ISH);
  __ bind(&retry);
  __ ldrexd(result_low, result_high, dst_addr);
  __ cmp(result_low, expected_low);
  __ b(ne, &done);
  __ cmp(result_high, expected_high);
  __ b(ne, &done);
  __ strexd(store_result, new_value_low, new_value_high, dst_addr);
  __ cmp(store_result, Operand(0));
  __ b(ne, &retry);
  __ dmb(ISH);
  __ bind(&done);

  __ ParallelRegisterMove(
      {{result, LiftoffRegister::ForPair(result_low, result_high), kI64}});
}
#undef __
}  // namespace liftoff

void LiftoffAssembler::AtomicCompareExchange(
    Register dst_addr, Register offset_reg, uint32_t offset_imm,
    LiftoffRegister expected, LiftoffRegister new_value, LiftoffRegister result,
    StoreType type, bool /* i64_offset */) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicI64CompareExchange(this, dst_addr, offset_reg, offset_imm,
                                      expected, new_value, result);
    return;
  }

  // The other versions of CompareExchange can share code, but need special load
  // and store instructions.
  void (Assembler::*load)(Register, Register, Condition) = nullptr;
  void (Assembler::*store)(Register, Register, Register, Condition) = nullptr;

  LiftoffRegList pinned{dst_addr};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  // We need to remember the high word of {result}, so we can set it to zero in
  // the end if necessary.
  Register result_high = no_reg;
  switch (type.value()) {
    case StoreType::kI64Store8:
      result_high = result.high_gp();
      result = result.low();
      new_value = new_value.low();
      expected = expected.low();
      [[fallthrough]];
    case StoreType::kI32Store8:
      load = &Assembler::ldrexb;
      store = &Assembler::strexb;
      // We have to clear the high bits of {expected}, as we can only do a
      // 32-bit comparison. If the {expected} register is used, we spill it
      // first.
      if (cache_state()->is_used(expected)) {
        SpillRegister(expected);
      }
      uxtb(expected.gp(), expected.gp());
      break;
    case StoreType::kI64Store16:
      result_high = result.high_gp();
      result = result.low();
      new_value = new_value.low();
      expected = expected.low();
      [[fallthrough]];
    case StoreType::kI32Store16:
      load = &Assembler::ldrexh;
      store = &Assembler::strexh;
      // We have to clear the high bits of {expected}, as we can only do a
      // 32-bit comparison. If the {expected} register is used, we spill it
      // first.
      if (cache_state()->is_used(expected)) {
        SpillRegister(expected);
      }
      uxth(expected.gp(), expected.gp());
      break;
    case StoreType::kI64Store32:
      result_high = result.high_gp();
      result = result.low();
      new_value = new_value.low();
      expected = expected.low();
      [[fallthrough]];
    case StoreType::kI32Store:
      load = &Assembler::ldrex;
      store = &Assembler::strex;
      break;
    default:
      UNREACHABLE();
  }
  pinned.set(new_value);
  pinned.set(expected);

  Register result_reg = result.gp();
  if (pinned.has(result)) {
    result_reg = GetUnusedRegister(kGpReg, pinned).gp();
  }
  pinned.set(LiftoffRegister(result));
  Register store_result = GetUnusedRegister(kGpReg, pinned).gp();

  UseScratchRegisterScope temps(this);
  Register actual_addr = liftoff::CalculateActualAddress(
      this, &temps, dst_addr, offset_reg, offset_imm);

  Label retry;
  Label done;
  dmb(ISH);
  bind(&retry);
  (this->*load)(result.gp(), actual_addr, al);
  cmp(result.gp(), expected.gp());
  b(ne, &done);
  (this->*store)(store_result, new_value.gp(), actual_addr, al);
  cmp(store_result, Operand(0));
  b(ne, &retry);
  dmb(ISH);
  bind(&done);

  if (result.gp() != result_reg) {
    mov(result.gp(), result_reg);
  }
  if (result_high != no_reg) {
    LoadConstant(LiftoffRegister(result_high), WasmValue(0));
  }
}

void LiftoffAssembler::AtomicFence() { dmb(ISH); }

void LiftoffAssembler::LoadCallerFrameSlot(LiftoffRegister dst,
                                           uint32_t caller_slot_idx,
                                           ValueKind kind) {
  MemOperand src(fp, (caller_slot_idx + 1) * kSystemPointerSize);
  liftoff::Load(this, dst, src, kind);
}

void LiftoffAssembler::StoreCallerFrameSlot(LiftoffRegister src,
                                            uint32_t caller_slot_idx,
                                            ValueKind kind,
                                            Register frame_pointer) {
  MemOperand dst(frame_pointer, (caller_slot_idx + 1) * kSystemPointerSize);
  liftoff::Store(this, src, dst, kind);
}

void LiftoffAssembler::LoadReturnStackSlot(LiftoffRegister dst, int offset,
                                           ValueKind kind) {
  MemOperand src(sp, offset);
  liftoff::Load(this, dst, src, kind);
}

void LiftoffAssembler::MoveStackValue(uint32_t dst_offset, uint32_t src_offset,
                                      ValueKind kind) {
  DCHECK_NE(dst_offset, src_offset);
  liftoff::CacheStatePreservingTempRegisters temps{this};
  Register scratch = temps.Acquire();
  const int kRegSize = 4;
  DCHECK_EQ(0, SlotSizeForType(kind) % kRegSize);
  int words = SlotSizeForType(kind) / kRegSize;
  if (src_offset < dst_offset) {
    do {
      ldr(scratch, liftoff::GetStackSlot(src_offset));
      str(scratch, liftoff::GetStackSlot(dst_offset));
      dst_offset -= kSystemPointerSize;
      src_offset -= kSystemPointerSize;
    } while (--words);
  } else {
    while (words--) {
      ldr(scratch, liftoff::GetStackSlot(src_offset - words * kRegSize));
      str(scratch, liftoff::GetStackSlot(dst_offset - words * kRegSize));
    }
  }
}

void LiftoffAssembler::Move(Register dst, Register src, ValueKind kind) {
  DCHECK_NE(dst, src);
  DCHECK(kind == kI32 || is_reference(kind));
  MacroAssembler::Move(dst, src);
}

void LiftoffAssembler::Move(DoubleRegister dst, DoubleRegister src,
                            ValueKind kind) {
  DCHECK_NE(dst, src);
  if (kind == kF32) {
    vmov(liftoff::GetFloatRegister(dst), liftoff::GetFloatRegister(src));
  } else if (kind == kF64) {
    vmov(dst, src);
  } else {
    DCHECK_EQ(kS128, kind);
    vmov(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(src));
  }
}

void LiftoffAssembler::Spill(int offset, LiftoffRegister reg, ValueKind kind) {
  // The {str} instruction needs a temp register when the immediate in the
  // provided MemOperand does not fit into 12 bits. This happens for large stack
  // frames. This DCHECK checks that the temp register is available when needed.
  DCHECK(UseScratchRegisterScope{this}.CanAcquire());
  DCHECK_LT(0, offset);
  RecordUsedSpillOffset(offset);
  MemOperand dst(fp, -offset);
  liftoff::Store(this, reg, dst, kind);
}

void LiftoffAssembler::Spill(int offset, WasmValue value) {
  RecordUsedSpillOffset(offset);
  MemOperand dst = liftoff::GetStackSlot(offset);
  UseScratchRegisterScope assembler_temps(this);
  liftoff::CacheStatePreservingTempRegisters liftoff_temps{this};
  Register src = no_reg;
  // The scratch register will be required by str if multiple instructions
  // are required to encode the offset, and so we cannot use it in that case.
  if (!ImmediateFitsAddrMode2Instruction(dst.offset())) {
    src = liftoff_temps.Acquire();
  } else {
    src = assembler_temps.Acquire();
  }
  switch (value.type().kind()) {
    case kI32:
      mov(src, Operand(value.to_i32()));
      str(src, dst);
      break;
    case kI64: {
      int32_t low_word = value.to_i64();
      mov(src, Operand(low_word));
      str(src, liftoff::GetHalfStackSlot(offset, kLowWord));
      int32_t high_word = value.to_i64() >> 32;
      mov(src, Operand(high_word));
      str(src, liftoff::GetHalfStackSlot(offset, kHighWord));
      break;
    }
    default:
      // We do not track f32 and f64 constants, hence they are unreachable.
      UNREACHABLE();
  }
}

void LiftoffAssembler::Fill(LiftoffRegister reg, int offset, ValueKind kind) {
  liftoff::Load(this, reg, liftoff::GetStackSlot(offset), kind);
}

void LiftoffAssembler::FillI64Half(Register reg, int offset, RegPairHalf half) {
  ldr(reg, liftoff::GetHalfStackSlot(offset, half));
}

void LiftoffAssembler::FillStackSlotsWithZero(int start, int size) {
  DCHECK_LT(0, size);
  DCHECK_EQ(0, size % 4);
  RecordUsedSpillOffset(start + size);

  // We need a zero reg. Always use r0 for that, and push it before to restore
  // its value afterwards.
  push(r0);
  mov(r0, Operand(0));

  if (size <= 36) {
    // Special straight-line code for up to 9 words. Generates one
    // instruction per word.
    for (int offset = 4; offset <= size; offset += 4) {
      str(r0, liftoff::GetHalfStackSlot(start + offset, kLowWord));
    }
  } else {
    // General case for bigger counts (9 instructions).
    // Use r1 for start address (inclusive), r2 for end address (exclusive).
    push(r1);
    push(r2);
    sub(r1, fp, Operand(start + size));
    sub(r2, fp, Operand(start));

    Label loop;
    bind(&loop);
    str(r0, MemOperand(r1, /* offset */ kSystemPointerSize, PostIndex));
    cmp(r1, r2);
    b(&loop, ne);

    pop(r2);
    pop(r1);
  }

  pop(r0);
}

void LiftoffAssembler::LoadSpillAddress(Register dst, int offset,
                                        ValueKind /* kind */) {
  sub(dst, fp, Operand(offset));
}

void LiftoffAssembler::emit_i32_add(Register dst, Register lhs, Register rhs) {
  add(dst, lhs, rhs);
}
void LiftoffAssembler::emit_i32_addi(Register dst, Register lhs, int32_t imm) {
  add(dst, lhs, Operand(imm));
}

void LiftoffAssembler::emit_i32_sub(Register dst, Register lhs, Register rhs) {
  sub(dst, lhs, rhs);
}
void LiftoffAssembler::emit_i32_subi(Register dst, Register lhs, int32_t imm) {
  sub(dst, lhs, Operand(imm));
}

void LiftoffAssembler::emit_i32_mul(Register dst, Register lhs, Register rhs) {
  mul(dst, lhs, rhs);
}
void LiftoffAssembler::emit_i32_muli(Register dst, Register lhs, int32_t imm) {
  if (base::bits::IsPowerOfTwo(imm)) {
    emit_i32_shli(dst, lhs, base::bits::WhichPowerOfTwo(imm));
    return;
  }
  UseScratchRegisterScope temps{this};
  Register scratch = temps.Acquire();
  mov(scratch, Operand{imm});
  mul(dst, lhs, scratch);
}

void LiftoffAssembler::emit_i32_and(Register dst, Register lhs, Register rhs) {
  and_(dst, lhs, rhs);
}
void LiftoffAssembler::emit_i32_andi(Register dst, Register lhs, int32_t imm) {
  and_(dst, lhs, Operand(imm));
}

void LiftoffAssembler::emit_i32_or(Register dst, Register lhs, Register rhs) {
  orr(dst, lhs, rhs);
}
void LiftoffAssembler::emit_i32_ori(Register dst, Register lhs, int32_t imm) {
  orr(dst, lhs, Operand(imm));
}

void LiftoffAssembler::emit_i32_xor(Register dst, Register lhs, Register rhs) {
  eor(dst, lhs, rhs);
}
void LiftoffAssembler::emit_i32_xori(Register dst, Register lhs, int32_t imm) {
  eor(dst, lhs, Operand(imm));
}

void LiftoffAssembler::emit_i32_shl(Register dst, Register src,
                                    Register amount) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  and_(scratch, amount, Operand(0x1f));
  lsl(dst, src, Operand(scratch));
}
void LiftoffAssembler::emit_i32_shli(Register dst, Register src,
                                     int32_t amount) {
  if (V8_LIKELY((amount & 31) != 0)) {
    lsl(dst, src, Operand(amount & 31));
  } else if (dst != src) {
    mov(dst, src);
  }
}

void LiftoffAssembler::emit_i32_sar(Register dst, Register src,
                                    Register amount) {
  UseScratchRegi
"""


```