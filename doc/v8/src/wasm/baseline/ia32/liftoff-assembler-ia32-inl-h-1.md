Response:
The user wants a summary of the functionality of the provided C++ code snippet from V8. The code is part of the `liftoff-assembler-ia32-inl.h` file, which suggests it's related to the Liftoff compiler for the IA32 architecture in V8.

Here's a breakdown of the thought process to achieve the requested summary:

1. **Identify the Core Functionality:** The code primarily deals with implementing atomic operations and arithmetic/bitwise operations for WebAssembly within the Liftoff compiler on IA32.

2. **Analyze the Structure:** The code is organized into several inline functions within the `liftoff` namespace and methods of the `LiftoffAssembler` class. The inline functions `AtomicBinop32`, `AtomicAddOrSubOrExchange32`, and `AtomicBinop64` handle the core logic of atomic operations. The `LiftoffAssembler` methods provide a higher-level interface to these operations.

3. **Categorize Operations:**
    * **Atomic Operations:** The code implements various atomic operations like `AtomicAdd`, `AtomicSub`, `AtomicAnd`, `AtomicOr`, `AtomicXor`, `AtomicExchange`, and `AtomicCompareExchange`. These functions handle both 32-bit and 64-bit operations.
    * **Stack Manipulation:** Functions like `LoadCallerFrameSlot`, `LoadReturnStackSlot`, `StoreCallerFrameSlot`, and `MoveStackValue` deal with accessing and moving data on the stack.
    * **Register Moves:**  `Move` functions are for moving data between registers (both general-purpose and floating-point).
    * **Spilling and Filling:** `Spill` and `Fill` functions manage moving data between registers and the stack (for saving and restoring register values).
    * **Arithmetic and Bitwise Operations:** A significant portion of the code implements standard arithmetic (add, subtract, multiply, divide, remainder) and bitwise (and, or, xor, shift) operations for 32-bit and 64-bit integers.

4. **Note Architecture-Specific Details:** The code is specifically for IA32. This is evident from the register names (eax, ebx, ecx, edx, esi, edi, ebp, esp), assembly instructions (`mov`, `add`, `sub`, `and`, `or`, `xor`, `cmpxchg`, `lock`, etc.), and the use of the root register (`kRootRegister == ebx`).

5. **Consider Edge Cases and Optimizations:** The code includes checks and special handling for:
    * Atomic operations requiring exclusive access using `lock` prefix and `cmpxchg`.
    * Handling the root register (`ebx`) in atomic operations.
    * Optimizations for small stack fills.
    * Special cases in division and remainder operations (division by zero, unrepresentable results).
    * Utilizing specific CPU features like `POPCNT` when available.

6. **Address Specific User Questions:**
    * **`.tq` extension:** The code snippet is C++, not Torque.
    * **JavaScript relationship:** Atomic operations can be related to JavaScript's SharedArrayBuffer and Atomics API, allowing concurrent access to shared memory. Standard arithmetic/bitwise operations have direct JavaScript equivalents.
    * **Code Logic and Examples:**  Provide simple examples to illustrate the functionality of atomic operations and basic arithmetic.
    * **Common Programming Errors:** Highlight issues related to incorrect usage of atomic operations (race conditions) and integer overflow/underflow.

7. **Synthesize the Summary:** Combine the above points into a concise description of the code's purpose and functionality. Emphasize the key areas and the IA32-specific nature.

8. **Review and Refine:** Ensure the summary is accurate, clear, and addresses all aspects of the user's request. For example, initially, I might focus heavily on atomic operations, but a review would prompt me to ensure the arithmetic/bitwise operations are also adequately covered. Also, check if all the decomposed instructions are covered in the summary.
v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h 文件是 V8 引擎中 Liftoff 编译器在 IA-32 架构下的汇编器内联实现头文件。它定义了一些内联函数，用于生成特定于 IA-32 架构的机器码指令，这些指令实现了 WebAssembly 的各种操作。

**功能归纳:**

这个代码片段主要定义了以下功能：

1. **原子操作的实现:**  提供了一系列用于实现 WebAssembly 原子操作的函数，包括 `AtomicAdd`, `AtomicSub`, `AtomicAnd`, `AtomicOr`, `AtomicXor`, `AtomicExchange`, 和 `AtomicCompareExchange`。这些操作保证了在多线程环境下的数据一致性。这些函数针对不同的数据类型大小（8位、16位、32位、64位）提供了不同的实现。

2. **栈操作:**  定义了用于加载和存储调用者帧槽 (`LoadCallerFrameSlot`, `StoreCallerFrameSlot`) 和返回栈槽 (`LoadReturnStackSlot`) 的函数，以及用于移动栈上值的函数 (`MoveStackValue`)。

3. **寄存器操作:** 提供了在寄存器之间移动数据的函数 (`Move`)，包括通用寄存器和浮点寄存器。

4. **溢出和填充:**  定义了将寄存器内容溢出到栈上 (`Spill`) 和从栈上填充到寄存器 (`Fill`) 的函数，用于管理寄存器的使用。

5. **用零填充栈空间:** 提供了 `FillStackSlotsWithZero` 函数，用于将指定的栈空间填充为零。

6. **加载栈地址:**  `LoadSpillAddress` 函数用于加载栈上指定位置的地址到寄存器。

7. **基本的 32 位整数运算:**  定义了各种 32 位整数的算术和位运算指令的生成函数，例如加法 (`emit_i32_add`, `emit_i32_addi`)，减法 (`emit_i32_sub`, `emit_i32_subi`)，乘法 (`emit_i32_mul`, `emit_i32_muli`)，除法 (`emit_i32_divs`, `emit_i32_divu`)，取余 (`emit_i32_rems`, `emit_i32_remu`)，位与 (`emit_i32_and`, `emit_i32_andi`)，位或 (`emit_i32_or`, `emit_i32_ori`)，位异或 (`emit_i32_xor`, `emit_i32_xori`)，左移 (`emit_i32_shl`, `emit_i32_shli`)，算术右移 (`emit_i32_sar`, `emit_i32_sari`)，逻辑右移 (`emit_i32_shr`, `emit_i32_shri`)，前导零计数 (`emit_i32_clz`)，尾部零计数 (`emit_i32_ctz`)，和人口计数 (`emit_i32_popcnt`)。

8. **基本的 64 位整数运算:** 定义了一些 64 位整数的算术运算指令的生成函数，例如加法 (`emit_i64_add`, `emit_i64_addi`)，减法 (`emit_i64_sub`) 和乘法 (`emit_i64_mul`)。  对于 64 位除法和取余，目前返回 `false`，表示可能尚未完全实现或使用了其他方式处理。

9. **内存屏障:**  提供了 `AtomicFence` 函数，用于插入内存屏障指令 (`mfence`)，确保内存操作的顺序性。

**关于文件类型和 JavaScript 关系:**

-  `v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h` 以 `.h` 结尾，这是一个 C++ 头文件的标准扩展名。因此，它是一个 **C++ 源代码文件**，而不是 Torque 源代码。

- 这个文件与 JavaScript 的功能有关系，因为它直接参与了 **WebAssembly 代码的编译和执行**。 Liftoff 是 V8 中用于快速启动 WebAssembly 代码的编译器。 当 JavaScript 代码调用 WebAssembly 模块时，Liftoff 编译器会使用这些汇编器指令将 WebAssembly 指令转换为 IA-32 架构的机器码，从而在 CPU 上执行。

**JavaScript 示例 (与原子操作相关):**

JavaScript 的 `SharedArrayBuffer` 和 `Atomics` API 允许在多个 Worker 之间共享内存并进行原子操作。  `liftoff-assembler-ia32-inl.h` 中定义的原子操作函数正是为了支持这些 JavaScript API 在底层硬件上的实现。

```javascript
// 创建一个共享的 Int32Array
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2);
const sharedArray = new Int32Array(sab);

// 在不同的 worker 中增加共享数组的第一个元素
// Worker 1
Atomics.add(sharedArray, 0, 1);

// Worker 2
Atomics.add(sharedArray, 0, 1);

console.log(sharedArray[0]); // 输出 2，保证了原子性
```

在这个例子中，`Atomics.add` 操作在底层就会使用类似 `liftoff-assembler-ia32-inl.h` 中定义的 `AtomicAdd` 函数来确保线程安全地增加共享内存中的值。

**代码逻辑推理和假设输入输出 (以 `AtomicAdd` 为例):**

假设 `AtomicAdd` 函数被调用，其目的是将 `value` 加到内存地址 `dst_addr + offset_reg + offset_imm` 处。

**假设输入:**

- `lasm`: `LiftoffAssembler` 的实例，用于生成汇编代码。
- `dst_addr`: 寄存器，包含目标内存地址的基址。 例如：`eax`
- `offset_reg`: 寄存器，包含偏移量。 例如：`ecx`
- `offset_imm`: 立即数偏移量。 例如：`4`
- `value`: `LiftoffRegister`，包含要添加的值。 假设是 32 位整数，存储在寄存器 `edx` 中。
- `result`: `LiftoffRegister`，用于存储操作前的原始值。 假设是寄存器 `esi`。
- `type`: `StoreType::kI32Store`，表示 32 位存储。

**代码逻辑:**

`AtomicAdd` 函数会生成如下 IA-32 汇编指令（简化）：

1. **使用循环和 `cmpxchg` 指令实现原子性:**  它会尝试原子地比较并交换内存中的值。
2. **加载原始值:** 将 `dst_addr + offset_reg + offset_imm` 处的值加载到 `eax` 寄存器（`cmpxchg` 指令的要求）。
3. **计算新值:** 将 `value` 寄存器 (`edx`) 的值与 `eax` 寄存器的值相加。
4. **原子比较和交换:** 使用 `lock cmpxchg [dst_addr + offset_reg + offset_imm], <new_value>` 指令尝试将内存中的值与 `eax` 比较，如果相等，则将内存中的值替换为 `<new_value>`。
5. **重试:** 如果比较失败（即在加载原始值到执行 `cmpxchg` 之间，内存中的值被其他线程修改了），则跳转回循环开始，重新加载并计算。
6. **存储结果:** 将原始值（在 `eax` 中）移动到 `result` 寄存器 (`esi`)。

**可能的输出（生成的汇编代码片段）:**

```assembly
retry_label:
  mov eax, [eax + ecx + 4]  ; 加载原始值
  mov ebx, edx             ; 将 value 移动到 ebx
  add ebx, eax             ; 计算新值
  lock cmpxchg [eax + ecx + 4], ebx ; 原子比较和交换
  jne retry_label           ; 如果比较失败，则重试
  mov esi, eax             ; 将原始值移动到 result 寄存器
```

**用户常见的编程错误 (与原子操作相关):**

1. **忘记使用原子操作:** 在多线程环境中修改共享变量时，如果没有使用原子操作，可能会导致数据竞争和不一致的结果。

   ```c++
   // 错误示例 (非原子操作)
   int shared_counter = 0;

   void increment_counter() {
     shared_counter++; // 在多线程环境下不安全
   }
   ```

2. **对不同大小的数据进行原子操作不当:** 原子操作通常针对特定的数据大小，如果操作的数据大小与原子操作指令不匹配，可能会导致未定义的行为。

3. **死锁和活锁:**  复杂的原子操作序列如果设计不当，可能会导致死锁（多个线程互相等待）或活锁（线程不断尝试但无法取得进展）。

4. **错误地理解内存顺序:** 原子操作有不同的内存顺序模型，错误地理解这些模型可能导致意想不到的结果。例如，松散（relaxed）顺序的原子操作可能不会立即对其他线程可见。

**总结:**

这个代码片段定义了 Liftoff 编译器在 IA-32 架构下生成 WebAssembly 代码所需的底层汇编指令，特别是针对原子操作和基本的整数运算。它直接关联着 JavaScript 中 WebAssembly 模块的执行性能和多线程能力。

### 提示词
```
这是目录为v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```c
case StoreType::kI64Store8: {
      __ xor_(eax, eax);
      __ mov_b(eax, dst_op);
      break;
    }
    case StoreType::kI32Store16:
    case StoreType::kI64Store16: {
      __ xor_(eax, eax);
      __ mov_w(eax, dst_op);
      break;
    }
    case StoreType::kI32Store:
    case StoreType::kI64Store32: {
      __ mov(eax, dst_op);
      break;
    }
    default:
      UNREACHABLE();
  }

  Label binop;
  __ bind(&binop);
  __ mov(scratch, eax);

  switch (op) {
    case kAnd: {
      __ and_(scratch, value_reg);
      break;
    }
    case kOr: {
      __ or_(scratch, value_reg);
      break;
    }
    case kXor: {
      __ xor_(scratch, value_reg);
      break;
    }
    default:
      UNREACHABLE();
  }

  __ lock();

  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8: {
      __ cmpxchg_b(dst_op, scratch);
      break;
    }
    case StoreType::kI32Store16:
    case StoreType::kI64Store16: {
      __ cmpxchg_w(dst_op, scratch);
      break;
    }
    case StoreType::kI32Store:
    case StoreType::kI64Store32: {
      __ cmpxchg(dst_op, scratch);
      break;
    }
    default:
      UNREACHABLE();
  }
  __ j(not_equal, &binop);

  if (is_byte_store) {
    __ pop(kRootRegister);
  }
  if (result_reg != eax) {
    __ mov(result_reg, eax);
  }
  if (is_64_bit_op) {
    __ xor_(result.high_gp(), result.high_gp());
  }
}

inline void AtomicBinop64(LiftoffAssembler* lasm, Binop op, Register dst_addr,
                          Register offset_reg, uint32_t offset_imm,
                          LiftoffRegister value, LiftoffRegister result) {
  // We need {ebx} here, which is the root register. As the root register it
  // needs special treatment. As we use {ebx} directly in the code below, we
  // have to make sure here that the root register is actually {ebx}.
  static_assert(kRootRegister == ebx,
                "The following code assumes that kRootRegister == ebx");
  __ push(ebx);

  // Store the value on the stack, so that we can use it for retries.
  __ AllocateStackSpace(8);
  Operand value_op_hi = Operand(esp, 0);
  Operand value_op_lo = Operand(esp, 4);
  __ mov(value_op_lo, value.low_gp());
  __ mov(value_op_hi, value.high_gp());

  // We want to use the compare-exchange instruction here. It uses registers
  // as follows: old-value = EDX:EAX; new-value = ECX:EBX.
  Register old_hi = edx;
  Register old_lo = eax;
  Register new_hi = ecx;
  Register new_lo = ebx;
  // Base and offset need separate registers that do not alias with the
  // ones above.
  Register base = esi;
  Register offset = edi;

  // Spill all these registers if they are still holding other values.
  __ SpillRegisters(old_hi, old_lo, new_hi, base, offset);
  if (offset_reg == no_reg) {
    if (dst_addr != base) __ mov(base, dst_addr);
    offset = no_reg;
  } else {
    // Potentially swap base and offset register to avoid unnecessary moves.
    if (dst_addr == offset || offset_reg == base) {
      std::swap(dst_addr, offset_reg);
    }
    __ ParallelRegisterMove(
        {{LiftoffRegister{base}, LiftoffRegister{dst_addr}, kI32},
         {LiftoffRegister{offset}, LiftoffRegister{offset_reg}, kI32}});
  }

  Operand dst_op_lo = liftoff::MemOperand(base, offset, offset_imm);
  Operand dst_op_hi = liftoff::MemOperand(base, offset, offset_imm + 4);

  // Load the old value from memory.
  __ mov(old_lo, dst_op_lo);
  __ mov(old_hi, dst_op_hi);
  Label retry;
  __ bind(&retry);
  __ mov(new_lo, old_lo);
  __ mov(new_hi, old_hi);
  switch (op) {
    case kAdd:
      __ add(new_lo, value_op_lo);
      __ adc(new_hi, value_op_hi);
      break;
    case kSub:
      __ sub(new_lo, value_op_lo);
      __ sbb(new_hi, value_op_hi);
      break;
    case kAnd:
      __ and_(new_lo, value_op_lo);
      __ and_(new_hi, value_op_hi);
      break;
    case kOr:
      __ or_(new_lo, value_op_lo);
      __ or_(new_hi, value_op_hi);
      break;
    case kXor:
      __ xor_(new_lo, value_op_lo);
      __ xor_(new_hi, value_op_hi);
      break;
    case kExchange:
      __ mov(new_lo, value_op_lo);
      __ mov(new_hi, value_op_hi);
      break;
  }
  __ lock();
  __ cmpxchg8b(dst_op_lo);
  __ j(not_equal, &retry);

  // Deallocate the stack space again.
  __ add(esp, Immediate(8));
  // Restore the root register, and we are done.
  __ pop(kRootRegister);

  // Move the result into the correct registers.
  __ ParallelRegisterMove(
      {{result, LiftoffRegister::ForPair(old_lo, old_hi), kI64}});
}

#undef __
}  // namespace liftoff

void LiftoffAssembler::AtomicAdd(Register dst_addr, Register offset_reg,
                                 uint32_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool /* i64_offset */) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicBinop64(this, liftoff::kAdd, dst_addr, offset_reg,
                           offset_imm, value, result);
    return;
  }

  liftoff::AtomicAddOrSubOrExchange32(this, liftoff::kAdd, dst_addr, offset_reg,
                                      offset_imm, value, result, type);
}

void LiftoffAssembler::AtomicSub(Register dst_addr, Register offset_reg,
                                 uint32_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool /* i64_offset */) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicBinop64(this, liftoff::kSub, dst_addr, offset_reg,
                           offset_imm, value, result);
    return;
  }
  liftoff::AtomicAddOrSubOrExchange32(this, liftoff::kSub, dst_addr, offset_reg,
                                      offset_imm, value, result, type);
}

void LiftoffAssembler::AtomicAnd(Register dst_addr, Register offset_reg,
                                 uint32_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool /* i64_offset */) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicBinop64(this, liftoff::kAnd, dst_addr, offset_reg,
                           offset_imm, value, result);
    return;
  }

  liftoff::AtomicBinop32(this, liftoff::kAnd, dst_addr, offset_reg, offset_imm,
                         value, result, type);
}

void LiftoffAssembler::AtomicOr(Register dst_addr, Register offset_reg,
                                uint32_t offset_imm, LiftoffRegister value,
                                LiftoffRegister result, StoreType type,
                                bool /* i64_offset */) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicBinop64(this, liftoff::kOr, dst_addr, offset_reg, offset_imm,
                           value, result);
    return;
  }

  liftoff::AtomicBinop32(this, liftoff::kOr, dst_addr, offset_reg, offset_imm,
                         value, result, type);
}

void LiftoffAssembler::AtomicXor(Register dst_addr, Register offset_reg,
                                 uint32_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool /* i64_offset */) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicBinop64(this, liftoff::kXor, dst_addr, offset_reg,
                           offset_imm, value, result);
    return;
  }

  liftoff::AtomicBinop32(this, liftoff::kXor, dst_addr, offset_reg, offset_imm,
                         value, result, type);
}

void LiftoffAssembler::AtomicExchange(Register dst_addr, Register offset_reg,
                                      uint32_t offset_imm,
                                      LiftoffRegister value,
                                      LiftoffRegister result, StoreType type,
                                      bool /* i64_offset */) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicBinop64(this, liftoff::kExchange, dst_addr, offset_reg,
                           offset_imm, value, result);
    return;
  }
  liftoff::AtomicAddOrSubOrExchange32(this, liftoff::kExchange, dst_addr,
                                      offset_reg, offset_imm, value, result,
                                      type);
}

void LiftoffAssembler::AtomicCompareExchange(
    Register dst_addr, Register offset_reg, uint32_t offset_imm,
    LiftoffRegister expected, LiftoffRegister new_value, LiftoffRegister result,
    StoreType type, bool /* i64_offset */) {
  // We expect that the offset has already been added to {dst_addr}, and no
  // {offset_reg} is provided. This is to save registers.
  DCHECK_EQ(offset_reg, no_reg);

  DCHECK_EQ(result, expected);

  if (type.value() != StoreType::kI64Store) {
    bool is_64_bit_op = type.value_type() == kWasmI64;

    Register value_reg = is_64_bit_op ? new_value.low_gp() : new_value.gp();
    Register expected_reg = is_64_bit_op ? expected.low_gp() : expected.gp();
    Register result_reg = expected_reg;

    // The cmpxchg instruction uses eax to store the old value of the
    // compare-exchange primitive. Therefore we have to spill the register and
    // move any use to another register.
    ClearRegister(eax, {&dst_addr, &value_reg},
                  LiftoffRegList{dst_addr, value_reg, expected_reg});
    if (expected_reg != eax) {
      mov(eax, expected_reg);
      expected_reg = eax;
    }

    bool is_byte_store = type.size() == 1;
    LiftoffRegList pinned{dst_addr, value_reg, expected_reg};

    // Ensure that {value_reg} is a valid register.
    if (is_byte_store && !liftoff::kByteRegs.has(value_reg)) {
      Register safe_value_reg =
          pinned.set(GetUnusedRegister(liftoff::kByteRegs.MaskOut(pinned)))
              .gp();
      mov(safe_value_reg, value_reg);
      value_reg = safe_value_reg;
      pinned.clear(LiftoffRegister(value_reg));
    }

    Operand dst_op = Operand(dst_addr, offset_imm);

    lock();
    switch (type.value()) {
      case StoreType::kI32Store8:
      case StoreType::kI64Store8: {
        cmpxchg_b(dst_op, value_reg);
        movzx_b(result_reg, eax);
        break;
      }
      case StoreType::kI32Store16:
      case StoreType::kI64Store16: {
        cmpxchg_w(dst_op, value_reg);
        movzx_w(result_reg, eax);
        break;
      }
      case StoreType::kI32Store:
      case StoreType::kI64Store32: {
        cmpxchg(dst_op, value_reg);
        if (result_reg != eax) {
          mov(result_reg, eax);
        }
        break;
      }
      default:
        UNREACHABLE();
    }
    if (is_64_bit_op) {
      xor_(result.high_gp(), result.high_gp());
    }
    return;
  }

  // The following code handles kExprI64AtomicCompareExchange.

  // We need {ebx} here, which is the root register. The root register it
  // needs special treatment. As we use {ebx} directly in the code below, we
  // have to make sure here that the root register is actually {ebx}.
  static_assert(kRootRegister == ebx,
                "The following code assumes that kRootRegister == ebx");
  push(kRootRegister);

  // The compare-exchange instruction uses registers as follows:
  // old-value = EDX:EAX; new-value = ECX:EBX.
  Register expected_hi = edx;
  Register expected_lo = eax;
  Register new_hi = ecx;
  Register new_lo = ebx;
  // The address needs a separate registers that does not alias with the
  // ones above.
  Register address = esi;

  // Spill all these registers if they are still holding other values.
  SpillRegisters(expected_hi, expected_lo, new_hi, address);

  // We have to set new_lo specially, because it's the root register. We do it
  // before setting all other registers so that the original value does not get
  // overwritten.
  mov(new_lo, new_value.low_gp());

  // Move all other values into the right register.
  ParallelRegisterMove(
      {{LiftoffRegister(address), LiftoffRegister(dst_addr), kI32},
       {LiftoffRegister::ForPair(expected_lo, expected_hi), expected, kI64},
       {LiftoffRegister(new_hi), new_value.high(), kI32}});

  Operand dst_op = Operand(address, offset_imm);

  lock();
  cmpxchg8b(dst_op);

  // Restore the root register, and we are done.
  pop(kRootRegister);

  // Move the result into the correct registers.
  ParallelRegisterMove(
      {{result, LiftoffRegister::ForPair(expected_lo, expected_hi), kI64}});
}

void LiftoffAssembler::AtomicFence() { mfence(); }

void LiftoffAssembler::LoadCallerFrameSlot(LiftoffRegister dst,
                                           uint32_t caller_slot_idx,
                                           ValueKind kind) {
  liftoff::Load(this, dst, ebp, kSystemPointerSize * (caller_slot_idx + 1),
                kind);
}

void LiftoffAssembler::LoadReturnStackSlot(LiftoffRegister reg, int offset,
                                           ValueKind kind) {
  liftoff::Load(this, reg, esp, offset, kind);
}

void LiftoffAssembler::StoreCallerFrameSlot(LiftoffRegister src,
                                            uint32_t caller_slot_idx,
                                            ValueKind kind,
                                            Register frame_pointer) {
  liftoff::Store(this, frame_pointer,
                 kSystemPointerSize * (caller_slot_idx + 1), src, kind);
}

void LiftoffAssembler::MoveStackValue(uint32_t dst_offset, uint32_t src_offset,
                                      ValueKind kind) {
  DCHECK_EQ(0, SlotSizeForType(kind) % kSystemPointerSize);
  int words = SlotSizeForType(kind) / kSystemPointerSize;
  DCHECK_LE(1, words);
  // Make sure we move the words in the correct order in case there is an
  // overlap between src and dst.
  if (src_offset < dst_offset) {
    do {
      liftoff::MoveStackValue(this, liftoff::GetStackSlot(src_offset),
                              liftoff::GetStackSlot(dst_offset));
      dst_offset -= kSystemPointerSize;
      src_offset -= kSystemPointerSize;
    } while (--words);
  } else {
    while (words--) {
      liftoff::MoveStackValue(
          this, liftoff::GetStackSlot(src_offset - words * kSystemPointerSize),
          liftoff::GetStackSlot(dst_offset - words * kSystemPointerSize));
    }
  }
}

void LiftoffAssembler::Move(Register dst, Register src, ValueKind kind) {
  DCHECK_NE(dst, src);
  DCHECK(kI32 == kind || is_reference(kind));
  mov(dst, src);
}

void LiftoffAssembler::Move(DoubleRegister dst, DoubleRegister src,
                            ValueKind kind) {
  DCHECK_NE(dst, src);
  if (kind == kF32) {
    movss(dst, src);
  } else if (kind == kF64) {
    movsd(dst, src);
  } else {
    DCHECK_EQ(kS128, kind);
    Movaps(dst, src);
  }
}

void LiftoffAssembler::Spill(int offset, LiftoffRegister reg, ValueKind kind) {
  RecordUsedSpillOffset(offset);
  Operand dst = liftoff::GetStackSlot(offset);
  switch (kind) {
    case kI32:
    case kRefNull:
    case kRef:
    case kRtt:
      mov(dst, reg.gp());
      break;
    case kI64:
      mov(liftoff::GetHalfStackSlot(offset, kLowWord), reg.low_gp());
      mov(liftoff::GetHalfStackSlot(offset, kHighWord), reg.high_gp());
      break;
    case kF32:
      movss(dst, reg.fp());
      break;
    case kF64:
      movsd(dst, reg.fp());
      break;
    case kS128:
      movdqu(dst, reg.fp());
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::Spill(int offset, WasmValue value) {
  RecordUsedSpillOffset(offset);
  Operand dst = liftoff::GetStackSlot(offset);
  switch (value.type().kind()) {
    case kI32:
      mov(dst, Immediate(value.to_i32()));
      break;
    case kI64: {
      int32_t low_word = value.to_i64();
      int32_t high_word = value.to_i64() >> 32;
      mov(liftoff::GetHalfStackSlot(offset, kLowWord), Immediate(low_word));
      mov(liftoff::GetHalfStackSlot(offset, kHighWord), Immediate(high_word));
      break;
    }
    default:
      // We do not track f32 and f64 constants, hence they are unreachable.
      UNREACHABLE();
  }
}

void LiftoffAssembler::Fill(LiftoffRegister reg, int offset, ValueKind kind) {
  liftoff::Load(this, reg, ebp, -offset, kind);
}

void LiftoffAssembler::FillI64Half(Register reg, int offset, RegPairHalf half) {
  mov(reg, liftoff::GetHalfStackSlot(offset, half));
}

void LiftoffAssembler::FillStackSlotsWithZero(int start, int size) {
  DCHECK_LT(0, size);
  DCHECK_EQ(0, size % 4);
  RecordUsedSpillOffset(start + size);

  if (size <= 12) {
    // Special straight-line code for up to three words (6-9 bytes per word:
    // C7 <1-4 bytes operand> <4 bytes imm>, makes 18-27 bytes total).
    for (int offset = 4; offset <= size; offset += 4) {
      mov(liftoff::GetHalfStackSlot(start + offset, kLowWord), Immediate(0));
    }
  } else {
    // General case for bigger counts.
    // This sequence takes 19-22 bytes (3 for pushes, 3-6 for lea, 2 for xor, 5
    // for mov, 3 for repstosq, 3 for pops).
    // Note: rep_stos fills ECX doublewords at [EDI] with EAX.
    push(eax);
    push(ecx);
    push(edi);
    lea(edi, liftoff::GetStackSlot(start + size));
    xor_(eax, eax);
    // Size is in bytes, convert to doublewords (4-bytes).
    mov(ecx, Immediate(size / 4));
    rep_stos();
    pop(edi);
    pop(ecx);
    pop(eax);
  }
}

void LiftoffAssembler::LoadSpillAddress(Register dst, int offset,
                                        ValueKind /* kind */) {
  lea(dst, liftoff::GetStackSlot(offset));
}

void LiftoffAssembler::emit_i32_add(Register dst, Register lhs, Register rhs) {
  if (lhs != dst) {
    lea(dst, Operand(lhs, rhs, times_1, 0));
  } else {
    add(dst, rhs);
  }
}

void LiftoffAssembler::emit_i32_addi(Register dst, Register lhs, int32_t imm) {
  if (lhs != dst) {
    lea(dst, Operand(lhs, imm));
  } else {
    add(dst, Immediate(imm));
  }
}

void LiftoffAssembler::emit_i32_sub(Register dst, Register lhs, Register rhs) {
  if (dst != rhs) {
    // Default path.
    if (dst != lhs) mov(dst, lhs);
    sub(dst, rhs);
  } else if (lhs == rhs) {
    // Degenerate case.
    xor_(dst, dst);
  } else {
    // Emit {dst = lhs + -rhs} if dst == rhs.
    neg(dst);
    add(dst, lhs);
  }
}

void LiftoffAssembler::emit_i32_subi(Register dst, Register lhs, int32_t imm) {
  if (dst != lhs) {
    // We'll have to implement an UB-safe version if we need this corner case.
    DCHECK_NE(imm, kMinInt);
    lea(dst, Operand(lhs, -imm));
  } else {
    sub(dst, Immediate(imm));
  }
}

namespace liftoff {
template <void (Assembler::*op)(Register, Register)>
void EmitCommutativeBinOp(LiftoffAssembler* assm, Register dst, Register lhs,
                          Register rhs) {
  if (dst == rhs) {
    (assm->*op)(dst, lhs);
  } else {
    if (dst != lhs) assm->mov(dst, lhs);
    (assm->*op)(dst, rhs);
  }
}

template <void (Assembler::*op)(Register, int32_t)>
void EmitCommutativeBinOpImm(LiftoffAssembler* assm, Register dst, Register lhs,
                             int32_t imm) {
  if (dst != lhs) assm->mov(dst, lhs);
  (assm->*op)(dst, imm);
}
}  // namespace liftoff

void LiftoffAssembler::emit_i32_mul(Register dst, Register lhs, Register rhs) {
  liftoff::EmitCommutativeBinOp<&Assembler::imul>(this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_muli(Register dst, Register lhs, int32_t imm) {
  if (base::bits::IsPowerOfTwo(imm)) {
    emit_i32_shli(dst, lhs, base::bits::WhichPowerOfTwo(imm));
  } else {
    imul(dst, lhs, imm);
  }
}

namespace liftoff {
enum class DivOrRem : uint8_t { kDiv, kRem };
template <bool is_signed, DivOrRem div_or_rem>
void EmitInt32DivOrRem(LiftoffAssembler* assm, Register dst, Register lhs,
                       Register rhs, Label* trap_div_by_zero,
                       Label* trap_div_unrepresentable) {
  constexpr bool needs_unrepresentable_check =
      is_signed && div_or_rem == DivOrRem::kDiv;
  constexpr bool special_case_minus_1 =
      is_signed && div_or_rem == DivOrRem::kRem;
  DCHECK_EQ(needs_unrepresentable_check, trap_div_unrepresentable != nullptr);

  // For division, the lhs is always taken from {edx:eax}. Thus, make sure that
  // these registers are unused. If {rhs} is stored in one of them, move it to
  // another temporary register.
  // Do all this before any branch, such that the code is executed
  // unconditionally, as the cache state will also be modified unconditionally.
  assm->SpillRegisters(eax, edx);
  if (rhs == eax || rhs == edx) {
    LiftoffRegList unavailable{eax, edx, lhs};
    Register tmp = assm->GetUnusedRegister(kGpReg, unavailable).gp();
    assm->mov(tmp, rhs);
    rhs = tmp;
  }

  // Check for division by zero.
  assm->test(rhs, rhs);
  assm->j(zero, trap_div_by_zero);

  Label done;
  if (needs_unrepresentable_check) {
    // Check for {kMinInt / -1}. This is unrepresentable.
    Label do_div;
    assm->cmp(rhs, -1);
    assm->j(not_equal, &do_div);
    assm->cmp(lhs, kMinInt);
    assm->j(equal, trap_div_unrepresentable);
    assm->bind(&do_div);
  } else if (special_case_minus_1) {
    // {lhs % -1} is always 0 (needs to be special cased because {kMinInt / -1}
    // cannot be computed).
    Label do_rem;
    assm->cmp(rhs, -1);
    assm->j(not_equal, &do_rem);
    assm->xor_(dst, dst);
    assm->jmp(&done);
    assm->bind(&do_rem);
  }

  // Now move {lhs} into {eax}, then zero-extend or sign-extend into {edx}, then
  // do the division.
  if (lhs != eax) assm->mov(eax, lhs);
  if (is_signed) {
    assm->cdq();
    assm->idiv(rhs);
  } else {
    assm->xor_(edx, edx);
    assm->div(rhs);
  }

  // Move back the result (in {eax} or {edx}) into the {dst} register.
  constexpr Register kResultReg = div_or_rem == DivOrRem::kDiv ? eax : edx;
  if (dst != kResultReg) assm->mov(dst, kResultReg);
  if (special_case_minus_1) assm->bind(&done);
}
}  // namespace liftoff

void LiftoffAssembler::emit_i32_divs(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  liftoff::EmitInt32DivOrRem<true, liftoff::DivOrRem::kDiv>(
      this, dst, lhs, rhs, trap_div_by_zero, trap_div_unrepresentable);
}

void LiftoffAssembler::emit_i32_divu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  liftoff::EmitInt32DivOrRem<false, liftoff::DivOrRem::kDiv>(
      this, dst, lhs, rhs, trap_div_by_zero, nullptr);
}

void LiftoffAssembler::emit_i32_rems(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  liftoff::EmitInt32DivOrRem<true, liftoff::DivOrRem::kRem>(
      this, dst, lhs, rhs, trap_div_by_zero, nullptr);
}

void LiftoffAssembler::emit_i32_remu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  liftoff::EmitInt32DivOrRem<false, liftoff::DivOrRem::kRem>(
      this, dst, lhs, rhs, trap_div_by_zero, nullptr);
}

void LiftoffAssembler::emit_i32_and(Register dst, Register lhs, Register rhs) {
  liftoff::EmitCommutativeBinOp<&Assembler::and_>(this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_andi(Register dst, Register lhs, int32_t imm) {
  liftoff::EmitCommutativeBinOpImm<&Assembler::and_>(this, dst, lhs, imm);
}

void LiftoffAssembler::emit_i32_or(Register dst, Register lhs, Register rhs) {
  liftoff::EmitCommutativeBinOp<&Assembler::or_>(this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_ori(Register dst, Register lhs, int32_t imm) {
  liftoff::EmitCommutativeBinOpImm<&Assembler::or_>(this, dst, lhs, imm);
}

void LiftoffAssembler::emit_i32_xor(Register dst, Register lhs, Register rhs) {
  liftoff::EmitCommutativeBinOp<&Assembler::xor_>(this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_xori(Register dst, Register lhs, int32_t imm) {
  liftoff::EmitCommutativeBinOpImm<&Assembler::xor_>(this, dst, lhs, imm);
}

namespace liftoff {
inline void EmitShiftOperation(LiftoffAssembler* assm, Register dst,
                               Register src, Register amount,
                               void (Assembler::*emit_shift)(Register)) {
  LiftoffRegList pinned{dst, src, amount};
  // If dst is ecx, compute into a tmp register first, then move to ecx.
  if (dst == ecx) {
    Register tmp = assm->GetUnusedRegister(kGpReg, pinned).gp();
    assm->mov(tmp, src);
    if (amount != ecx) assm->mov(ecx, amount);
    (assm->*emit_shift)(tmp);
    assm->mov(ecx, tmp);
    return;
  }

  // Move amount into ecx. If ecx is in use, move its content to a tmp register
  // first. If src is ecx, src is now the tmp register.
  Register tmp_reg = no_reg;
  if (amount != ecx) {
    if (assm->cache_state()->is_used(LiftoffRegister(ecx)) ||
        pinned.has(LiftoffRegister(ecx))) {
      tmp_reg = assm->GetUnusedRegister(kGpReg, pinned).gp();
      assm->mov(tmp_reg, ecx);
      if (src == ecx) src = tmp_reg;
    }
    assm->mov(ecx, amount);
  }

  // Do the actual shift.
  if (dst != src) assm->mov(dst, src);
  (assm->*emit_shift)(dst);

  // Restore ecx if needed.
  if (tmp_reg.is_valid()) assm->mov(ecx, tmp_reg);
}
}  // namespace liftoff

void LiftoffAssembler::emit_i32_shl(Register dst, Register src,
                                    Register amount) {
  liftoff::EmitShiftOperation(this, dst, src, amount, &Assembler::shl_cl);
}

void LiftoffAssembler::emit_i32_shli(Register dst, Register src,
                                     int32_t amount) {
  if (dst != src) mov(dst, src);
  shl(dst, amount & 31);
}

void LiftoffAssembler::emit_i32_sar(Register dst, Register src,
                                    Register amount) {
  liftoff::EmitShiftOperation(this, dst, src, amount, &Assembler::sar_cl);
}

void LiftoffAssembler::emit_i32_sari(Register dst, Register src,
                                     int32_t amount) {
  if (dst != src) mov(dst, src);
  sar(dst, amount & 31);
}

void LiftoffAssembler::emit_i32_shr(Register dst, Register src,
                                    Register amount) {
  liftoff::EmitShiftOperation(this, dst, src, amount, &Assembler::shr_cl);
}

void LiftoffAssembler::emit_i32_shri(Register dst, Register src,
                                     int32_t amount) {
  if (dst != src) mov(dst, src);
  shr(dst, amount & 31);
}

void LiftoffAssembler::emit_i32_clz(Register dst, Register src) {
  Lzcnt(dst, src);
}

void LiftoffAssembler::emit_i32_ctz(Register dst, Register src) {
  Tzcnt(dst, src);
}

bool LiftoffAssembler::emit_i32_popcnt(Register dst, Register src) {
  if (!CpuFeatures::IsSupported(POPCNT)) return false;
  CpuFeatureScope scope(this, POPCNT);
  popcnt(dst, src);
  return true;
}

namespace liftoff {
template <void (Assembler::*op)(Register, Register),
          void (Assembler::*op_with_carry)(Register, Register)>
inline void OpWithCarry(LiftoffAssembler* assm, LiftoffRegister dst,
                        LiftoffRegister lhs, LiftoffRegister rhs) {
  // First, compute the low half of the result, potentially into a temporary dst
  // register if {dst.low_gp()} equals {rhs.low_gp()} or any register we need to
  // keep alive for computing the upper half.
  LiftoffRegList keep_alive{lhs.high_gp(), rhs};
  Register dst_low = keep_alive.has(dst.low_gp())
                         ? assm->GetUnusedRegister(kGpReg, keep_alive).gp()
                         : dst.low_gp();

  if (dst_low != lhs.low_gp()) assm->mov(dst_low, lhs.low_gp());
  (assm->*op)(dst_low, rhs.low_gp());

  // Now compute the upper half, while keeping alive the previous result.
  keep_alive = LiftoffRegList{dst_low, rhs.high_gp()};
  Register dst_high = keep_alive.has(dst.high_gp())
                          ? assm->GetUnusedRegister(kGpReg, keep_alive).gp()
                          : dst.high_gp();

  if (dst_high != lhs.high_gp()) assm->mov(dst_high, lhs.high_gp());
  (assm->*op_with_carry)(dst_high, rhs.high_gp());

  // If necessary, move result into the right registers.
  LiftoffRegister tmp_result = LiftoffRegister::ForPair(dst_low, dst_high);
  if (tmp_result != dst) assm->Move(dst, tmp_result, kI64);
}

template <void (Assembler::*op)(Register, const Immediate&),
          void (Assembler::*op_with_carry)(Register, int32_t)>
inline void OpWithCarryI(LiftoffAssembler* assm, LiftoffRegister dst,
                         LiftoffRegister lhs, int64_t imm) {
  // The compiler allocated registers such that either {dst == lhs} or there is
  // no overlap between the two.
  DCHECK_NE(dst.low_gp(), lhs.high_gp());

  int32_t imm_low_word = static_cast<int32_t>(imm);
  int32_t imm_high_word = static_cast<int32_t>(imm >> 32);

  // First, compute the low half of the result.
  if (dst.low_gp() != lhs.low_gp()) assm->mov(dst.low_gp(), lhs.low_gp());
  (assm->*op)(dst.low_gp(), Immediate(imm_low_word));

  // Now compute the upper half.
  if (dst.high_gp() != lhs.high_gp()) assm->mov(dst.high_gp(), lhs.high_gp());
  (assm->*op_with_carry)(dst.high_gp(), imm_high_word);
}
}  // namespace liftoff

void LiftoffAssembler::emit_i64_add(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  liftoff::OpWithCarry<&Assembler::add, &Assembler::adc>(this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i64_addi(LiftoffRegister dst, LiftoffRegister lhs,
                                     int64_t imm) {
  liftoff::OpWithCarryI<&Assembler::add, &Assembler::adc>(this, dst, lhs, imm);
}

void LiftoffAssembler::emit_i64_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  liftoff::OpWithCarry<&Assembler::sub, &Assembler::sbb>(this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i64_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  // Idea:
  //        [           lhs_hi  |           lhs_lo  ] * [  rhs_hi  |  rhs_lo  ]
  //    =   [  lhs_hi * rhs_lo  |                   ]  (32 bit mul, shift 32)
  //      + [  lhs_lo * rhs_hi  |                   ]  (32 bit mul, shift 32)
  //      + [             lhs_lo * rhs_lo           ]  (32x32->64 mul, shift 0)

  // For simplicity, we move lhs and rhs into fixed registers.
  Register dst_hi = edx;
  Register dst_lo = eax;
  Register lhs_hi = ecx;
  Register lhs_lo = dst_lo;
  Register rhs_hi = dst_hi;
  Register rhs_lo = esi;

  // Spill all these registers if they are still holding other values.
  SpillRegisters(dst_hi, dst_lo, lhs_hi, rhs_lo);

  // Move lhs and rhs into the respective registers.
  ParallelRegisterMove({{LiftoffRegister::ForPair(lhs_lo, lhs_hi), lhs, kI64},
                        {LiftoffRegister::ForPair(rhs_lo, rhs_hi), rhs, kI64}});

  // First mul: lhs_hi' = lhs_hi * rhs_lo.
  imul(lhs_hi, rhs_lo);
  // Second mul: rhi_hi' = rhs_hi * lhs_lo.
  imul(rhs_hi, lhs_lo);
  // Add them: lhs_hi'' = lhs_hi' + rhs_hi' = lhs_hi * rhs_lo + rhs_hi * lhs_lo.
  add(lhs_hi, rhs_hi);
  // Third mul: edx:eax (dst_hi:dst_lo) = eax * esi (lhs_lo * rhs_lo).
  mul(rhs_lo);
  // Add lhs_hi'' to dst_hi.
  add(dst_hi, lhs_hi);

  // Finally, move back the temporary result to the actual dst register pair.
  LiftoffRegister dst_tmp = LiftoffRegister::ForPair(dst_lo, dst_hi);
  if (dst != dst_tmp) Move(dst, dst_tmp, kI64);
}

bool LiftoffAssembler::emit_i64_divs(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  return false;
}

bool LiftoffAssembler::emit_i64_divu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  return false;
}

bool LiftoffAssembler::emit_i64_rems(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  return false;
}

bool LiftoffAssembler::emit_i64_remu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  return false;
}

namespace liftoff {
inline bool PairContains(LiftoffRegister pair, Register reg) {
  return pair.low_gp() == reg || pair.high_gp() == reg;
}

inline LiftoffRegister ReplaceInPair(LiftoffRegister pair, Register old_reg,
                                     Register new_reg) {
  if (pair.low_gp() == old_reg) {
    return LiftoffRegister::ForPair(new_reg, pair.high_gp());
  }
  if (pair.high_gp() == old_reg) {
    return LiftoffRegister::ForPair(pair.low_gp(), new_reg);
  }
  return pair;
}

inline void Emit64BitShiftOperation(
    LiftoffAssembler* assm, LiftoffRegister dst, LiftoffRegister src,
    Register amount, void (MacroAssembler::*emit_shift)(Register, Register)) {
  // Temporary registers cannot overlap with {dst}.
  LiftoffRegList
```