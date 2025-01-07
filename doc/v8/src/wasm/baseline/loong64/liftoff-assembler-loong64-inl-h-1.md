Response:
The user wants a summary of the functionality of the provided C++ code snippet from `liftoff-assembler-loong64-inl.h`.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename suggests it's part of the Liftoff compiler for WebAssembly on the LoongArch64 architecture. The `-inl.h` suffix indicates inline function definitions, likely for performance. The functions manipulate registers and memory.

2. **Group related functionalities:**  The code contains macros and functions related to:
    * Atomic operations (exchange, compare-exchange, fence)
    * Stack manipulation (loading/storing caller frame slots, return stack slots, moving stack values)
    * Register movement (general purpose and floating point)
    * Stack spilling and filling
    * Integer arithmetic and bitwise operations (for both 32-bit and 64-bit integers)
    * Floating-point arithmetic operations
    * Type conversions between integers and floats
    * Potentially some helper functions (like `GetMemOp` and stack slot access, though not directly defined here).

3. **Analyze individual functions/macros:** Understand what each function or macro does at a high level. Keywords like `Atomic`, `Load`, `Store`, `Move`, `Spill`, `Fill`, `emit_i32`, `emit_i64`, `emit_f32`, `emit_f64`, `Convert` are clues.

4. **Consider the context:** This is *assembly* generation. The functions are emitting LoongArch64 assembly instructions. The `LiftoffAssembler` class likely provides an abstraction layer over raw assembly instructions.

5. **Relate to WebAssembly concepts:** Connect the functionalities to common WebAssembly operations (e.g., atomic operations, local variable access, arithmetic, type conversions).

6. **Address specific instructions:**
    * **`.tq` extension:**  The code is C++, so it's not Torque.
    * **JavaScript relationship:**  The generated assembly code will eventually execute when a WebAssembly module is run in a JavaScript environment.
    * **Code logic inference:**  Focus on the *purpose* of the code blocks rather than detailed low-level assembly logic unless specifically requested.
    * **Common programming errors:** Think about scenarios where these assembly operations could be involved in errors (e.g., race conditions with atomics, incorrect type conversions, stack overflows).

7. **Structure the summary:**  Organize the findings logically, perhaps grouping by the categories identified in step 2.

8. **Refine and iterate:** Ensure the summary is clear, concise, and accurate. Focus on the *what* and *why* rather than the *how* (the specific assembly instructions).
这是 `v8/src/wasm/baseline/loong64/liftoff-assembler-loong64-inl.h` 文件的第二部分代码，延续了第一部分的功能，主要负责定义了 `LiftoffAssembler` 类中与 **原子操作**、**栈操作**、**寄存器移动**、**栈数据的保存和恢复**、以及 **各种算术和类型转换指令的生成**相关的内联函数。 这些函数是为 LoongArch64 架构上的 WebAssembly Liftoff 编译器生成汇编代码的核心组成部分。

**归纳一下这部分代码的功能：**

1. **原子操作支持 (Atomic Operations):**
   - 提供了原子交换 (`AtomicExchange`) 和原子比较并交换 (`AtomicCompareExchange`) 的实现，确保在多线程环境下对共享内存的并发访问是安全的。
   - 定义了 `AtomicFence`，用于插入内存屏障，保证内存操作的顺序性。
   - 这些原子操作针对不同的数据类型和大小（例如，8位、16位、32位、64位整数）。

2. **栈操作 (Stack Operations):**
   - 实现了加载和存储调用者帧槽 (`LoadCallerFrameSlot`, `StoreCallerFrameSlot`)，用于访问调用栈上的数据。
   - 提供了加载返回栈槽 (`LoadReturnStackSlot`) 的功能，用于访问返回地址等信息。
   - 实现了在栈上移动数据 (`MoveStackValue`) 的功能，用于例如函数调用时参数的传递。

3. **寄存器移动 (Register Movement):**
   - 提供了在通用寄存器之间移动数据 (`Move`) 的功能。
   - 提供了在浮点寄存器之间移动数据 (`Move`) 的功能。

4. **栈数据保存和恢复 (Spilling and Filling):**
   - 实现了将寄存器中的值保存到栈上 (`Spill`) 的功能，用于寄存器不足时临时存储数据。
   - 实现了从栈上恢复数据到寄存器 (`Fill`) 的功能。
   - 提供了用零填充栈槽 (`FillStackSlotsWithZero`) 的功能，用于初始化局部变量。
   - 提供了加载栈上某个位置的地址 (`LoadSpillAddress`) 的功能。

5. **整数运算指令生成 (Integer Arithmetic Instructions):**
   - 提供了生成 64 位整数各种运算指令的函数，例如计算前导零 (`emit_i64_clz`)、尾随零 (`emit_i64_ctz`)、位计数 (`emit_i64_popcnt`)、加法 (`emit_i64_addi`, `emit_i64_add`)、乘法 (`emit_i64_mul`, `emit_i64_muli`)、除法 (`emit_i64_divs`, `emit_i64_divu`)、求余 (`emit_i64_rems`, `emit_i64_remu`)、位运算 (`emit_i64_and`, `emit_i64_or`, `emit_i64_xor`) 和移位操作 (`emit_i64_shl`, `emit_i64_sar`, `emit_i64_shr`)。
   - 提供了生成 32 位整数各种运算指令的函数，功能类似 64 位整数，例如加减乘除、位运算和移位。

6. **浮点运算指令生成 (Floating-Point Arithmetic Instructions):**
   - 提供了生成单精度 (`f32`) 和双精度 (`f64`) 浮点数的各种运算指令的函数，例如取负 (`emit_f32_neg`, `emit_f64_neg`)、最小值 (`emit_f32_min`, `emit_f64_min`)、最大值 (`emit_f32_max`, `emit_f64_max`)、符号复制 (`emit_f32_copysign`, `emit_f64_copysign`)、加减乘除、绝对值、取整 (ceil, floor, trunc, nearest int) 和平方根。

7. **类型转换指令生成 (Type Conversion Instructions):**
   - 提供了生成各种类型转换指令的函数，例如整数类型之间的转换 (`emit_u32_to_uintptr`, `clear_i32_upper_half`)，整数和浮点数之间的转换 (`emit_type_conversion`)，以及浮点数类型之间的转换。这些转换可能需要处理溢出和 NaN 等情况。

**关于你的问题：**

* **`.tq` 结尾:**  `v8/src/wasm/baseline/loong64/liftoff-assembler-loong64-inl.h` 是一个 C++ 头文件，以 `.h` 结尾，而不是 `.tq`。因此，它不是 V8 Torque 源代码。Torque 文件通常用于定义 V8 内部的 Builtins 函数。

* **与 JavaScript 的功能关系:** 这部分代码直接支持 WebAssembly 的执行，而 WebAssembly 经常在 JavaScript 环境中运行。当 JavaScript 调用编译后的 WebAssembly 代码时，Liftoff 编译器生成的这些汇编指令会被执行。

   **JavaScript 示例:**

   ```javascript
   const wasmCode = new Uint8Array([
     0, 97, 115, 109, 1, 0, 0, 0, 1, 7, 1, 96, 1, 127, 1, 127, 3, 2, 1, 0, 10,
     9, 1, 7, 0, 32, 0, 65, 1, 106, 11
   ]);
   const wasmModule = new WebAssembly.Module(wasmCode);
   const wasmInstance = new WebAssembly.Instance(wasmModule);
   console.log(wasmInstance.exports.add(1)); // 调用 WebAssembly 模块中的函数
   ```

   在这个例子中，当 `wasmInstance.exports.add(1)` 被调用时，如果 `add` 函数的实现是由 Liftoff 编译器编译的，那么 `liftoff-assembler-loong64-inl.h` 中定义的函数就会被用来生成实际的 LoongArch64 汇编指令，例如加法指令。

* **代码逻辑推理 (以原子交换为例):**

   **假设输入:**
   - `dst_addr`: 寄存器，存储目标内存地址。假设值为 `0x1000`.
   - `value`:  `LiftoffRegister`，包含要交换的新值。假设其通用寄存器值为 `0x5`.
   - `result`: `LiftoffRegister`，用于存储从内存中读取的旧值。
   - `type`: `StoreType::kI32Store` (32位整数交换).

   **输出:**
   - 生成的汇编代码将执行以下操作：
     1. 将目标地址 `0x1000` 的内容原子地加载到 `result` 寄存器。
     2. 将 `value` 寄存器中的值 `0x5` 原子地存储到目标地址 `0x1000`。

   **生成的汇编代码（简化示意）可能包含：**
   ```assembly
   // ... 前置操作，例如保存寄存器 ...
   ll_w  temp2, (temp0)    // 原子加载链接 (Load-Linked) 目标地址的值到 temp2
   move  result, temp2     // 将旧值存储到 result 寄存器
   move  temp2, value      // 将新值移动到 temp2
   sc_w  temp2, (temp0)    // 原子条件存储 (Store-Conditional) 新值到目标地址
   beqz  temp2, exchange   // 如果存储成功 (temp2 为 0)，则跳出循环
   b     exchange          // 如果存储失败，则重试
   // ... 后置操作 ...
   ```

* **用户常见的编程错误 (以原子操作为例):**

   ```c++
   // 错误示例：未正确处理原子操作的返回值
   int shared_value = 0;

   void thread1() {
     int old_value = shared_value;
     // ... 一些非原子操作 ...
     shared_value = old_value + 1; // 潜在的竞态条件
   }

   // 正确示例：使用原子操作
   std::atomic<int> shared_value(0);

   void thread2() {
     shared_value.fetch_add(1, std::memory_order_seq_cst);
   }
   ```

   **解释:**  在没有使用原子操作的情况下，多个线程同时修改 `shared_value` 可能会导致数据竞争和更新丢失。例如，线程 1 读取了 `shared_value` 的值，然后在进行一些非原子操作后尝试更新它。在这期间，另一个线程可能已经修改了 `shared_value`，导致线程 1 的更新覆盖了其他线程的修改。  `LiftoffAssembler::AtomicExchange` 和 `LiftoffAssembler::AtomicCompareExchange` 旨在帮助生成正确的原子操作指令，避免这类错误。

总而言之，这部分代码是 Liftoff 编译器在 LoongArch64 架构上生成高效、正确的 WebAssembly 代码的关键组成部分，涵盖了原子操作、栈管理、寄存器操作以及各种指令的生成。

Prompt: 
```
这是目录为v8/src/wasm/baseline/loong64/liftoff-assembler-loong64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/loong64/liftoff-assembler-loong64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
def ASSEMBLE_ATOMIC_BINOP_EXT
#undef ATOMIC_BINOP_CASE

#define ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(load_linked, store_conditional, \
                                             size, aligned)                  \
  do {                                                                       \
    Label exchange;                                                          \
    andi(temp1, temp0, aligned);                                             \
    Sub_d(temp0, temp0, Operand(temp1));                                     \
    slli_w(temp1, temp1, 3);                                                 \
    dbar(0);                                                                 \
    bind(&exchange);                                                         \
    load_linked(temp2, MemOperand(temp0, 0));                                \
    ExtractBits(result.gp(), temp2, temp1, size, false);                     \
    InsertBits(temp2, value.gp(), temp1, size);                              \
    store_conditional(temp2, MemOperand(temp0, 0));                          \
    BranchShort(&exchange, eq, temp2, Operand(zero_reg));                    \
    dbar(0);                                                                 \
  } while (0)

void LiftoffAssembler::AtomicExchange(Register dst_addr, Register offset_reg,
                                      uintptr_t offset_imm,
                                      LiftoffRegister value,
                                      LiftoffRegister result, StoreType type,
                                      bool i64_offset) {
  LiftoffRegList pinned{dst_addr, value, result};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  Register temp0 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  Register temp1 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  Register temp2 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  MemOperand dst_op =
      liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm, i64_offset);
  Add_d(temp0, dst_op.base(), dst_op.offset());
  switch (type.value()) {
    case StoreType::kI64Store8:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_d, Sc_d, 8, 7);
      break;
    case StoreType::kI32Store8:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, 8, 3);
      break;
    case StoreType::kI64Store16:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_d, Sc_d, 16, 7);
      break;
    case StoreType::kI32Store16:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, 16, 3);
      break;
    case StoreType::kI64Store32:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_d, Sc_d, 32, 7);
      break;
    case StoreType::kI32Store:
      amswap_db_w(result.gp(), value.gp(), temp0);
      break;
    case StoreType::kI64Store:
      amswap_db_d(result.gp(), value.gp(), temp0);
      break;
    default:
      UNREACHABLE();
  }
}
#undef ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT

#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(load_linked,       \
                                                 store_conditional) \
  do {                                                              \
    Label compareExchange;                                          \
    Label exit;                                                     \
    dbar(0);                                                        \
    bind(&compareExchange);                                         \
    load_linked(result.gp(), MemOperand(temp0, 0));                 \
    BranchShort(&exit, ne, expected.gp(), Operand(result.gp()));    \
    mov(temp2, new_value.gp());                                     \
    store_conditional(temp2, MemOperand(temp0, 0));                 \
    BranchShort(&compareExchange, eq, temp2, Operand(zero_reg));    \
    bind(&exit);                                                    \
    dbar(0);                                                        \
  } while (0)

#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(            \
    load_linked, store_conditional, size, aligned)               \
  do {                                                           \
    Label compareExchange;                                       \
    Label exit;                                                  \
    andi(temp1, temp0, aligned);                                 \
    Sub_d(temp0, temp0, Operand(temp1));                         \
    slli_w(temp1, temp1, 3);                                     \
    dbar(0);                                                     \
    bind(&compareExchange);                                      \
    load_linked(temp2, MemOperand(temp0, 0));                    \
    ExtractBits(result.gp(), temp2, temp1, size, false);         \
    ExtractBits(temp2, expected.gp(), zero_reg, size, false);    \
    BranchShort(&exit, ne, temp2, Operand(result.gp()));         \
    InsertBits(temp2, new_value.gp(), temp1, size);              \
    store_conditional(temp2, MemOperand(temp0, 0));              \
    BranchShort(&compareExchange, eq, temp2, Operand(zero_reg)); \
    bind(&exit);                                                 \
    dbar(0);                                                     \
  } while (0)

void LiftoffAssembler::AtomicCompareExchange(
    Register dst_addr, Register offset_reg, uintptr_t offset_imm,
    LiftoffRegister expected, LiftoffRegister new_value, LiftoffRegister result,
    StoreType type, bool i64_offset) {
  LiftoffRegList pinned{dst_addr, expected, new_value, result};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  Register temp0 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  Register temp1 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  Register temp2 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  MemOperand dst_op =
      liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm, i64_offset);
  Add_d(temp0, dst_op.base(), dst_op.offset());
  switch (type.value()) {
    case StoreType::kI64Store8:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_d, Sc_d, 8, 7);
      break;
    case StoreType::kI32Store8:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, 8, 3);
      break;
    case StoreType::kI64Store16:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_d, Sc_d, 16, 7);
      break;
    case StoreType::kI32Store16:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, 16, 3);
      break;
    case StoreType::kI64Store32:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_d, Sc_d, 32, 7);
      break;
    case StoreType::kI32Store:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(Ll_w, Sc_w);
      break;
    case StoreType::kI64Store:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(Ll_d, Sc_d);
      break;
    default:
      UNREACHABLE();
  }
}
#undef ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT

void LiftoffAssembler::AtomicFence() { dbar(0); }

void LiftoffAssembler::LoadCallerFrameSlot(LiftoffRegister dst,
                                           uint32_t caller_slot_idx,
                                           ValueKind kind) {
  MemOperand src(fp, kSystemPointerSize * (caller_slot_idx + 1));
  liftoff::Load(this, dst, src, kind);
}

void LiftoffAssembler::StoreCallerFrameSlot(LiftoffRegister src,
                                            uint32_t caller_slot_idx,
                                            ValueKind kind,
                                            Register frame_pointer) {
  int32_t offset = kSystemPointerSize * (caller_slot_idx + 1);
  liftoff::Store(this, frame_pointer, offset, src, kind);
}

void LiftoffAssembler::LoadReturnStackSlot(LiftoffRegister dst, int offset,
                                           ValueKind kind) {
  liftoff::Load(this, dst, MemOperand(sp, offset), kind);
}

void LiftoffAssembler::MoveStackValue(uint32_t dst_offset, uint32_t src_offset,
                                      ValueKind kind) {
  DCHECK_NE(dst_offset, src_offset);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();

  switch (kind) {
    case kI32:
    case kF32:
      Ld_w(scratch, liftoff::GetStackSlot(src_offset));
      St_w(scratch, liftoff::GetStackSlot(dst_offset));
      break;
    case kI64:
    case kRefNull:
    case kRef:
    case kRtt:
    case kF64:
      Ld_d(scratch, liftoff::GetStackSlot(src_offset));
      St_d(scratch, liftoff::GetStackSlot(dst_offset));
      break;
    case kS128:
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::Move(Register dst, Register src, ValueKind kind) {
  DCHECK_NE(dst, src);
  // TODO(ksreten): Handle different sizes here.
  MacroAssembler::Move(dst, src);
}

void LiftoffAssembler::Move(DoubleRegister dst, DoubleRegister src,
                            ValueKind kind) {
  DCHECK_NE(dst, src);
  if (kind != kS128) {
    MacroAssembler::Move(dst, src);
  } else {
    UNREACHABLE();
  }
}

void LiftoffAssembler::Spill(int offset, LiftoffRegister reg, ValueKind kind) {
  RecordUsedSpillOffset(offset);
  MemOperand dst = liftoff::GetStackSlot(offset);
  switch (kind) {
    case kI32:
      St_w(reg.gp(), dst);
      break;
    case kI64:
    case kRef:
    case kRefNull:
    case kRtt:
      St_d(reg.gp(), dst);
      break;
    case kF32:
      Fst_s(reg.fp(), dst);
      break;
    case kF64:
      MacroAssembler::Fst_d(reg.fp(), dst);
      break;
    case kS128:
      UNREACHABLE();
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::Spill(int offset, WasmValue value) {
  RecordUsedSpillOffset(offset);
  MemOperand dst = liftoff::GetStackSlot(offset);
  switch (value.type().kind()) {
    case kI32: {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      MacroAssembler::li(scratch, Operand(value.to_i32()));
      St_w(scratch, dst);
      break;
    }
    case kI64:
    case kRef:
    case kRefNull: {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      MacroAssembler::li(scratch, value.to_i64());
      St_d(scratch, dst);
      break;
    }
    default:
      // kWasmF32 and kWasmF64 are unreachable, since those
      // constants are not tracked.
      UNREACHABLE();
  }
}

void LiftoffAssembler::Fill(LiftoffRegister reg, int offset, ValueKind kind) {
  MemOperand src = liftoff::GetStackSlot(offset);
  switch (kind) {
    case kI32:
      Ld_w(reg.gp(), src);
      break;
    case kI64:
    case kRef:
    case kRefNull:
    // TODO(LOONG_dev): LOONG64 Check, MIPS64 dosn't need, ARM64/LOONG64 need?
    case kRtt:
      Ld_d(reg.gp(), src);
      break;
    case kF32:
      Fld_s(reg.fp(), src);
      break;
    case kF64:
      MacroAssembler::Fld_d(reg.fp(), src);
      break;
    case kS128:
      UNREACHABLE();
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::FillI64Half(Register, int offset, RegPairHalf) {
  UNREACHABLE();
}

void LiftoffAssembler::FillStackSlotsWithZero(int start, int size) {
  DCHECK_LT(0, size);
  RecordUsedSpillOffset(start + size);

  if (size <= 12 * kStackSlotSize) {
    // Special straight-line code for up to 12 slots. Generates one
    // instruction per slot (<= 12 instructions total).
    uint32_t remainder = size;
    for (; remainder >= kStackSlotSize; remainder -= kStackSlotSize) {
      St_d(zero_reg, liftoff::GetStackSlot(start + remainder));
    }
    DCHECK(remainder == 4 || remainder == 0);
    if (remainder) {
      St_w(zero_reg, liftoff::GetStackSlot(start + remainder));
    }
  } else {
    // General case for bigger counts (12 instructions).
    // Use a0 for start address (inclusive), a1 for end address (exclusive).
    Push(a1, a0);
    Add_d(a0, fp, Operand(-start - size));
    Add_d(a1, fp, Operand(-start));

    Label loop;
    bind(&loop);
    St_d(zero_reg, MemOperand(a0, 0));
    addi_d(a0, a0, kSystemPointerSize);
    BranchShort(&loop, ne, a0, Operand(a1));

    Pop(a1, a0);
  }
}

void LiftoffAssembler::LoadSpillAddress(Register dst, int offset,
                                        ValueKind /* kind */) {
  Sub_d(dst, fp, Operand(offset));
}

void LiftoffAssembler::emit_i64_clz(LiftoffRegister dst, LiftoffRegister src) {
  MacroAssembler::Clz_d(dst.gp(), src.gp());
}

void LiftoffAssembler::emit_i64_ctz(LiftoffRegister dst, LiftoffRegister src) {
  MacroAssembler::Ctz_d(dst.gp(), src.gp());
}

bool LiftoffAssembler::emit_i64_popcnt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  MacroAssembler::Popcnt_d(dst.gp(), src.gp());
  return true;
}

void LiftoffAssembler::IncrementSmi(LiftoffRegister dst, int offset) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  if (COMPRESS_POINTERS_BOOL) {
    DCHECK(SmiValuesAre31Bits());
    Ld_w(scratch, MemOperand(dst.gp(), offset));
    Add_w(scratch, scratch, Operand(Smi::FromInt(1)));
    St_w(scratch, MemOperand(dst.gp(), offset));
  } else {
    SmiUntag(scratch, MemOperand(dst.gp(), offset));
    Add_d(scratch, scratch, Operand(1));
    SmiTag(scratch);
    St_d(scratch, MemOperand(dst.gp(), offset));
  }
}

void LiftoffAssembler::emit_i32_mul(Register dst, Register lhs, Register rhs) {
  MacroAssembler::Mul_w(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_divs(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs, Operand(zero_reg));

  // Check if lhs == kMinInt and rhs == -1, since this case is unrepresentable.
  rotri_w(kScratchReg, lhs, 31);
  xori(kScratchReg, kScratchReg, 1);
  // If lhs == kMinInt, move rhs to kScratchReg.
  masknez(kScratchReg, rhs, kScratchReg);
  addi_w(kScratchReg, kScratchReg, 1);
  MacroAssembler::Branch(trap_div_unrepresentable, eq, kScratchReg,
                         Operand(zero_reg));

  MacroAssembler::Div_w(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_divu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs, Operand(zero_reg));
  MacroAssembler::Div_wu(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_rems(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs, Operand(zero_reg));
  MacroAssembler::Mod_w(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_remu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs, Operand(zero_reg));
  MacroAssembler::Mod_wu(dst, lhs, rhs);
}

#define I32_BINOP(name, instruction)                                 \
  void LiftoffAssembler::emit_i32_##name(Register dst, Register lhs, \
                                         Register rhs) {             \
    instruction(dst, lhs, rhs);                                      \
  }

// clang-format off
I32_BINOP(add, add_w)
I32_BINOP(sub, sub_w)
I32_BINOP(and, and_)
I32_BINOP(or, or_)
I32_BINOP(xor, xor_)
// clang-format on

#undef I32_BINOP

#define I32_BINOP_I(name, instruction)                                  \
  void LiftoffAssembler::emit_i32_##name##i(Register dst, Register lhs, \
                                            int32_t imm) {              \
    instruction(dst, lhs, Operand(imm));                                \
  }

// clang-format off
I32_BINOP_I(add, Add_w)
I32_BINOP_I(sub, Sub_w)
I32_BINOP_I(and, And)
I32_BINOP_I(or, Or)
I32_BINOP_I(xor, Xor)
// clang-format on

#undef I32_BINOP_I

void LiftoffAssembler::emit_i32_clz(Register dst, Register src) {
  MacroAssembler::Clz_w(dst, src);
}

void LiftoffAssembler::emit_i32_ctz(Register dst, Register src) {
  MacroAssembler::Ctz_w(dst, src);
}

bool LiftoffAssembler::emit_i32_popcnt(Register dst, Register src) {
  MacroAssembler::Popcnt_w(dst, src);
  return true;
}

#define I32_SHIFTOP(name, instruction)                               \
  void LiftoffAssembler::emit_i32_##name(Register dst, Register src, \
                                         Register amount) {          \
    instruction(dst, src, amount);                                   \
  }
#define I32_SHIFTOP_I(name, instruction, instruction1)                  \
  I32_SHIFTOP(name, instruction)                                        \
  void LiftoffAssembler::emit_i32_##name##i(Register dst, Register src, \
                                            int amount) {               \
    instruction1(dst, src, amount & 0x1f);                              \
  }

I32_SHIFTOP_I(shl, sll_w, slli_w)
I32_SHIFTOP_I(sar, sra_w, srai_w)
I32_SHIFTOP_I(shr, srl_w, srli_w)

#undef I32_SHIFTOP
#undef I32_SHIFTOP_I

void LiftoffAssembler::emit_i64_addi(LiftoffRegister dst, LiftoffRegister lhs,
                                     int64_t imm) {
  MacroAssembler::Add_d(dst.gp(), lhs.gp(), Operand(imm));
}

void LiftoffAssembler::emit_i64_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  MacroAssembler::Mul_d(dst.gp(), lhs.gp(), rhs.gp());
}

void LiftoffAssembler::emit_i64_muli(LiftoffRegister dst, LiftoffRegister lhs,
                                     int32_t imm) {
  if (base::bits::IsPowerOfTwo(imm)) {
    emit_i64_shli(dst, lhs, base::bits::WhichPowerOfTwo(imm));
    return;
  }
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  MacroAssembler::li(scratch, Operand(imm));
  MacroAssembler::Mul_d(dst.gp(), lhs.gp(), scratch);
}

bool LiftoffAssembler::emit_i64_divs(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs.gp(), Operand(zero_reg));

  // Check if lhs == MinInt64 and rhs == -1, since this case is unrepresentable.
  rotri_d(kScratchReg, lhs.gp(), 63);
  xori(kScratchReg, kScratchReg, 1);
  // If lhs == MinInt64, move rhs to kScratchReg.
  masknez(kScratchReg, rhs.gp(), kScratchReg);
  addi_d(kScratchReg, kScratchReg, 1);
  MacroAssembler::Branch(trap_div_unrepresentable, eq, kScratchReg,
                         Operand(zero_reg));

  MacroAssembler::Div_d(dst.gp(), lhs.gp(), rhs.gp());
  return true;
}

bool LiftoffAssembler::emit_i64_divu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs.gp(), Operand(zero_reg));
  MacroAssembler::Div_du(dst.gp(), lhs.gp(), rhs.gp());
  return true;
}

bool LiftoffAssembler::emit_i64_rems(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs.gp(), Operand(zero_reg));
  MacroAssembler::Mod_d(dst.gp(), lhs.gp(), rhs.gp());
  return true;
}

bool LiftoffAssembler::emit_i64_remu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs.gp(), Operand(zero_reg));
  MacroAssembler::Mod_du(dst.gp(), lhs.gp(), rhs.gp());
  return true;
}

#define I64_BINOP(name, instruction)                                   \
  void LiftoffAssembler::emit_i64_##name(                              \
      LiftoffRegister dst, LiftoffRegister lhs, LiftoffRegister rhs) { \
    instruction(dst.gp(), lhs.gp(), rhs.gp());                         \
  }

// clang-format off
I64_BINOP(add, Add_d)
I64_BINOP(sub, Sub_d)
I64_BINOP(and, and_)
I64_BINOP(or, or_)
I64_BINOP(xor, xor_)
// clang-format on

#undef I64_BINOP

#define I64_BINOP_I(name, instruction)                         \
  void LiftoffAssembler::emit_i64_##name##i(                   \
      LiftoffRegister dst, LiftoffRegister lhs, int32_t imm) { \
    instruction(dst.gp(), lhs.gp(), Operand(imm));             \
  }

// clang-format off
I64_BINOP_I(and, And)
I64_BINOP_I(or, Or)
I64_BINOP_I(xor, Xor)
// clang-format on

#undef I64_BINOP_I

#define I64_SHIFTOP(name, instruction)                             \
  void LiftoffAssembler::emit_i64_##name(                          \
      LiftoffRegister dst, LiftoffRegister src, Register amount) { \
    instruction(dst.gp(), src.gp(), amount);                       \
  }
#define I64_SHIFTOP_I(name, instruction, instructioni)                         \
  I64_SHIFTOP(name, instruction)                                               \
  void LiftoffAssembler::emit_i64_##name##i(LiftoffRegister dst,               \
                                            LiftoffRegister src, int amount) { \
    instructioni(dst.gp(), src.gp(), amount & 63);                             \
  }

I64_SHIFTOP_I(shl, sll_d, slli_d)
I64_SHIFTOP_I(sar, sra_d, srai_d)
I64_SHIFTOP_I(shr, srl_d, srli_d)

#undef I64_SHIFTOP
#undef I64_SHIFTOP_I

void LiftoffAssembler::emit_u32_to_uintptr(Register dst, Register src) {
  bstrpick_d(dst, src, 31, 0);
}

void LiftoffAssembler::clear_i32_upper_half(Register dst) {
  // Don't need to clear the upper halves of i32 values for sandbox on
  // LoongArch64, because we'll explicitly zero-extend their lower halves before
  // using them for memory accesses anyway.
}

void LiftoffAssembler::emit_f32_neg(DoubleRegister dst, DoubleRegister src) {
  MacroAssembler::Neg_s(dst, src);
}

void LiftoffAssembler::emit_f64_neg(DoubleRegister dst, DoubleRegister src) {
  MacroAssembler::Neg_d(dst, src);
}

void LiftoffAssembler::emit_f32_min(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Label ool, done;
  MacroAssembler::Float32Min(dst, lhs, rhs, &ool);
  Branch(&done);

  bind(&ool);
  MacroAssembler::Float32MinOutOfLine(dst, lhs, rhs);
  bind(&done);
}

void LiftoffAssembler::emit_f32_max(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Label ool, done;
  MacroAssembler::Float32Max(dst, lhs, rhs, &ool);
  Branch(&done);

  bind(&ool);
  MacroAssembler::Float32MaxOutOfLine(dst, lhs, rhs);
  bind(&done);
}

void LiftoffAssembler::emit_f32_copysign(DoubleRegister dst, DoubleRegister lhs,
                                         DoubleRegister rhs) {
  fcopysign_s(dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64_min(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Label ool, done;
  MacroAssembler::Float64Min(dst, lhs, rhs, &ool);
  Branch(&done);

  bind(&ool);
  MacroAssembler::Float64MinOutOfLine(dst, lhs, rhs);
  bind(&done);
}

void LiftoffAssembler::emit_f64_max(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Label ool, done;
  MacroAssembler::Float64Max(dst, lhs, rhs, &ool);
  Branch(&done);

  bind(&ool);
  MacroAssembler::Float64MaxOutOfLine(dst, lhs, rhs);
  bind(&done);
}

void LiftoffAssembler::emit_f64_copysign(DoubleRegister dst, DoubleRegister lhs,
                                         DoubleRegister rhs) {
  fcopysign_d(dst, lhs, rhs);
}

#define FP_BINOP(name, instruction)                                          \
  void LiftoffAssembler::emit_##name(DoubleRegister dst, DoubleRegister lhs, \
                                     DoubleRegister rhs) {                   \
    instruction(dst, lhs, rhs);                                              \
  }
#define FP_UNOP(name, instruction)                                             \
  void LiftoffAssembler::emit_##name(DoubleRegister dst, DoubleRegister src) { \
    instruction(dst, src);                                                     \
  }
#define FP_UNOP_RETURN_TRUE(name, instruction)                                 \
  bool LiftoffAssembler::emit_##name(DoubleRegister dst, DoubleRegister src) { \
    instruction(dst, src);                                                     \
    return true;                                                               \
  }

FP_BINOP(f32_add, fadd_s)
FP_BINOP(f32_sub, fsub_s)
FP_BINOP(f32_mul, fmul_s)
FP_BINOP(f32_div, fdiv_s)
FP_UNOP(f32_abs, fabs_s)
FP_UNOP_RETURN_TRUE(f32_ceil, Ceil_s)
FP_UNOP_RETURN_TRUE(f32_floor, Floor_s)
FP_UNOP_RETURN_TRUE(f32_trunc, Trunc_s)
FP_UNOP_RETURN_TRUE(f32_nearest_int, Round_s)
FP_UNOP(f32_sqrt, fsqrt_s)
FP_BINOP(f64_add, fadd_d)
FP_BINOP(f64_sub, fsub_d)
FP_BINOP(f64_mul, fmul_d)
FP_BINOP(f64_div, fdiv_d)
FP_UNOP(f64_abs, fabs_d)
FP_UNOP_RETURN_TRUE(f64_ceil, Ceil_d)
FP_UNOP_RETURN_TRUE(f64_floor, Floor_d)
FP_UNOP_RETURN_TRUE(f64_trunc, Trunc_d)
FP_UNOP_RETURN_TRUE(f64_nearest_int, Round_d)
FP_UNOP(f64_sqrt, fsqrt_d)

#undef FP_BINOP
#undef FP_UNOP
#undef FP_UNOP_RETURN_TRUE

bool LiftoffAssembler::emit_type_conversion(WasmOpcode opcode,
                                            LiftoffRegister dst,
                                            LiftoffRegister src, Label* trap) {
  switch (opcode) {
    case kExprI32ConvertI64:
      MacroAssembler::bstrpick_w(dst.gp(), src.gp(), 31, 0);
      return true;
    case kExprI32SConvertF32: {
      LiftoffRegister rounded = GetUnusedRegister(kFpReg, LiftoffRegList{src});
      LiftoffRegister converted_back =
          GetUnusedRegister(kFpReg, LiftoffRegList{src, rounded});

      // Real conversion.
      MacroAssembler::Trunc_s(rounded.fp(), src.fp());
      ftintrz_w_s(kScratchDoubleReg, rounded.fp());
      movfr2gr_s(dst.gp(), kScratchDoubleReg);
      // Avoid INT32_MAX as an overflow indicator and use INT32_MIN instead,
      // because INT32_MIN allows easier out-of-bounds detection.
      MacroAssembler::Add_w(kScratchReg, dst.gp(), 1);
      MacroAssembler::Slt(kScratchReg2, kScratchReg, dst.gp());
      MacroAssembler::Movn(dst.gp(), kScratchReg, kScratchReg2);

      // Checking if trap.
      movgr2fr_w(kScratchDoubleReg, dst.gp());
      ffint_s_w(converted_back.fp(), kScratchDoubleReg);
      MacroAssembler::CompareF32(rounded.fp(), converted_back.fp(), CEQ);
      MacroAssembler::BranchFalseF(trap);
      return true;
    }
    case kExprI32UConvertF32: {
      LiftoffRegister rounded = GetUnusedRegister(kFpReg, LiftoffRegList{src});
      LiftoffRegister converted_back =
          GetUnusedRegister(kFpReg, LiftoffRegList{src, rounded});

      // Real conversion.
      MacroAssembler::Trunc_s(rounded.fp(), src.fp());
      MacroAssembler::Ftintrz_uw_s(dst.gp(), rounded.fp(), kScratchDoubleReg);
      // Avoid UINT32_MAX as an overflow indicator and use 0 instead,
      // because 0 allows easier out-of-bounds detection.
      MacroAssembler::Add_w(kScratchReg, dst.gp(), 1);
      MacroAssembler::Movz(dst.gp(), zero_reg, kScratchReg);

      // Checking if trap.
      MacroAssembler::Ffint_d_uw(converted_back.fp(), dst.gp());
      fcvt_s_d(converted_back.fp(), converted_back.fp());
      MacroAssembler::CompareF32(rounded.fp(), converted_back.fp(), CEQ);
      MacroAssembler::BranchFalseF(trap);
      return true;
    }
    case kExprI32SConvertF64: {
      LiftoffRegister rounded = GetUnusedRegister(kFpReg, LiftoffRegList{src});
      LiftoffRegister converted_back =
          GetUnusedRegister(kFpReg, LiftoffRegList{src, rounded});

      // Real conversion.
      MacroAssembler::Trunc_d(rounded.fp(), src.fp());
      ftintrz_w_d(kScratchDoubleReg, rounded.fp());
      movfr2gr_s(dst.gp(), kScratchDoubleReg);

      // Checking if trap.
      ffint_d_w(converted_back.fp(), kScratchDoubleReg);
      MacroAssembler::CompareF64(rounded.fp(), converted_back.fp(), CEQ);
      MacroAssembler::BranchFalseF(trap);
      return true;
    }
    case kExprI32UConvertF64: {
      LiftoffRegister rounded = GetUnusedRegister(kFpReg, LiftoffRegList{src});
      LiftoffRegister converted_back =
          GetUnusedRegister(kFpReg, LiftoffRegList{src, rounded});

      // Real conversion.
      MacroAssembler::Trunc_d(rounded.fp(), src.fp());
      MacroAssembler::Ftintrz_uw_d(dst.gp(), rounded.fp(), kScratchDoubleReg);

      // Checking if trap.
      MacroAssembler::Ffint_d_uw(converted_back.fp(), dst.gp());
      MacroAssembler::CompareF64(rounded.fp(), converted_back.fp(), CEQ);
      MacroAssembler::BranchFalseF(trap);
      return true;
    }
    case kExprI32ReinterpretF32:
      MacroAssembler::FmoveLow(dst.gp(), src.fp());
      return true;
    case kExprI64SConvertI32:
      slli_w(dst.gp(), src.gp(), 0);
      return true;
    case kExprI64UConvertI32:
      MacroAssembler::bstrpick_d(dst.gp(), src.gp(), 31, 0);
      return true;
    case kExprI64SConvertF32: {
      LiftoffRegister rounded = GetUnusedRegister(kFpReg, LiftoffRegList{src});
      LiftoffRegister converted_back =
          GetUnusedRegister(kFpReg, LiftoffRegList{src, rounded});

      // Real conversion.
      MacroAssembler::Trunc_s(rounded.fp(), src.fp());
      ftintrz_l_s(kScratchDoubleReg, rounded.fp());
      movfr2gr_d(dst.gp(), kScratchDoubleReg);
      // Avoid INT64_MAX as an overflow indicator and use INT64_MIN instead,
      // because INT64_MIN allows easier out-of-bounds detection.
      MacroAssembler::Add_d(kScratchReg, dst.gp(), 1);
      MacroAssembler::Slt(kScratchReg2, kScratchReg, dst.gp());
      MacroAssembler::Movn(dst.gp(), kScratchReg, kScratchReg2);

      // Checking if trap.
      movgr2fr_d(kScratchDoubleReg, dst.gp());
      ffint_s_l(converted_back.fp(), kScratchDoubleReg);
      MacroAssembler::CompareF32(rounded.fp(), converted_back.fp(), CEQ);
      MacroAssembler::BranchFalseF(trap);
      return true;
    }
    case kExprI64UConvertF32: {
      // Real conversion.
      MacroAssembler::Ftintrz_ul_s(dst.gp(), src.fp(), kScratchDoubleReg,
                                   kScratchReg);

      // Checking if trap.
      MacroAssembler::Branch(trap, eq, kScratchReg, Operand(zero_reg));
      return true;
    }
    case kExprI64SConvertF64: {
      LiftoffRegister rounded = GetUnusedRegister(kFpReg, LiftoffRegList{src});
      LiftoffRegister converted_back =
          GetUnusedRegister(kFpReg, LiftoffRegList{src, rounded});

      // Real conversion.
      MacroAssembler::Trunc_d(rounded.fp(), src.fp());
      ftintrz_l_d(kScratchDoubleReg, rounded.fp());
      movfr2gr_d(dst.gp(), kScratchDoubleReg);
      // Avoid INT64_MAX as an overflow indicator and use INT64_MIN instead,
      // because INT64_MIN allows easier out-of-bounds detection.
      MacroAssembler::Add_d(kScratchReg, dst.gp(), 1);
      MacroAssembler::Slt(kScratchReg2, kScratchReg, dst.gp());
      MacroAssembler::Movn(dst.gp(), kScratchReg, kScratchReg2);

      // Checking if trap.
      movgr2fr_d(kScratchDoubleReg, dst.gp());
      ffint_d_l(converted_back.fp(), kScratchDoubleReg);
      MacroAssembler::CompareF64(rounded.fp(), converted_back.fp(), CEQ);
      MacroAssembler::BranchFalseF(trap);
      return true;
    }
    case kExprI64UConvertF64: {
      // Real conversion.
      MacroAssembler::Ftintrz_ul_d(dst.gp(), src.fp(), kScratchDoubleReg,
                                   kScratchReg);

      // Checking if trap.
      MacroAssembler::Branch(trap, eq, kScratchReg, Operand(zero_reg));
      return true;
    }
    case kExprI64ReinterpretF64:
      movfr2gr_d(dst.gp(), src.fp());
      return true;
    case kExprF32SConvertI32: {
      LiftoffRegister scratch = GetUnusedRegister(kFpReg, LiftoffRegList{dst});
      movgr2fr_w(scratch.fp(), src.gp());
      ffint_s_w(dst.fp(), scratch.fp());
      return true;
    }
    case kExprF32UConvertI32:
      MacroAssembler::Ffint_s_uw(dst.fp(), src.gp());
      return true;
    case kExprF32ConvertF64:
      fcvt_s_d(dst.fp(), src.fp());
      return true;
    case kExprF32ReinterpretI32:
      MacroAssembler::FmoveLow(dst.fp(), src.gp());
      return true;
    case kExprF64SConvertI32: {
      LiftoffRegister scratch = GetUnusedRegister(kFpReg, LiftoffRegList{dst});
      movgr2fr_w(scratch.fp(), src.gp());
      ffint_d_w(dst.fp(), scratch.fp());
      return true;
    }
    case kExprF64UConvertI32:
      MacroAssembler::Ffint_d_uw(dst.fp(), src.gp());
      return true;
    case kExprF64ConvertF32:
      fcvt_d_s(dst.fp(), src.fp());
      return true;
    case kExprF64ReinterpretI64:
      movgr2fr_d(dst.fp(), src.gp());
      return true;
    case kExprI32SConvertSatF32:
      ftintrz_w_s(kScratchDoubleReg, src.fp());
      movfr2gr_s(dst.gp(), kScratchDoubleReg);
      return true;
    case kExprI32UConvertSatF32: {
      Label isnan_or_lessthan_or_equal_zero;
      mov(dst.gp(), zero_reg);
      MacroAssembler::Move(kScratchDoubleReg, static_cast<float>(0.0));
      CompareF32
"""


```