Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code is part of the V8 JavaScript engine, specifically for the WebAssembly baseline compiler on the PowerPC architecture.

I need to analyze the code and identify the key operations and functionalities it implements. The code defines methods within the `LiftoffAssembler` class.

Here's a breakdown of the code's functions:

1. **Atomic Operations:** `AtomicCompareExchange` and `AtomicFence` suggest support for atomic memory operations, crucial for multi-threaded environments.
2. **Stack Frame Access:** `LoadCallerFrameSlot`, `StoreCallerFrameSlot`, and `LoadReturnStackSlot` indicate mechanisms for accessing data within the current and calling function's stack frames.
3. **Stack Manipulation:** `MoveStackValue`, `Spill`, `Fill`, and `FillStackSlotsWithZero` handle moving data to and from the stack, a common task in compilers.
4. **Register Moves:** `Move` functions for both general-purpose and floating-point registers.
5. **Address Calculation:** `LoadSpillAddress` calculates the memory address for stack slots.
6. **Unary Operations:** The `UNOP_LIST` macro defines a set of unary operations (e.g., absolute value, negation, square root, bitwise operations, sign extension) for both 32-bit and 64-bit integers and floating-point numbers. The `EMIT_UNOP_FUNCTION` macro generates the corresponding C++ methods.
7. **Binary Operations:** The `BINOP_LIST` macro defines a set of binary operations (e.g., addition, subtraction, multiplication, division, bitwise operations, shifts) for both 32-bit and 64-bit integers and floating-point numbers. The `EMIT_BINOP_FUNCTION` macro generates the corresponding C++ methods.
8. **Integer Division and Remainder:** Specific functions (`emit_i32_divs`, `emit_i32_divu`, `emit_i32_rems`, `emit_i32_remu`, `emit_i64_divs`, `emit_i64_divu`, `emit_i64_rems`, `emit_i64_remu`) handle signed and unsigned integer division and remainder operations, including checks for division by zero and overflow.
9. **Type Conversions:** The `emit_type_conversion` function implements various type conversion operations between integers and floating-point numbers. It also includes saturated conversions and reinterpret casts.
10. **Smi Operations:** `IncrementSmi` suggests handling of Small Integers (Smis), a common optimization in JavaScript engines.

The code appears to be providing a set of low-level building blocks for generating machine code for the WebAssembly baseline compiler on the PowerPC architecture. It handles data movement, arithmetic operations, and memory access.
这是 `v8/src/wasm/baseline/ppc/liftoff-assembler-ppc-inl.h` 文件的一部分代码，主要功能是为 Liftoff 编译器在 PowerPC 架构上提供汇编指令级别的支持，用于实现 WebAssembly 的各种操作。

**归纳一下它的功能：**

这段代码定义了 `LiftoffAssembler` 类的一些成员函数，这些函数封装了 PowerPC 架构的汇编指令，用于执行以下操作：

1. **原子操作:**  提供了原子比较并交换（`AtomicCompareExchange`）和原子栅栏（`AtomicFence`）操作，用于在多线程环境下安全地访问共享内存。
2. **栈帧操作:**  提供了加载和存储调用者栈帧槽（`LoadCallerFrameSlot`, `StoreCallerFrameSlot`）以及加载返回栈槽（`LoadReturnStackSlot`）的功能，用于访问函数调用时的参数和局部变量。
3. **栈值移动:** 提供了在栈上移动数据的功能（`MoveStackValue`）。
4. **寄存器操作:**  提供了在寄存器之间移动数据的功能（`Move`），包括通用寄存器和浮点寄存器。
5. **栈溢出和填充:** 提供了将寄存器中的值溢出到栈上（`Spill`）以及从栈上填充到寄存器（`Fill`）的功能，这是编译器管理寄存器使用的常见操作。
6. **栈空间填充:** 提供了用零值填充栈空间的功能（`FillStackSlotsWithZero`）。
7. **加载栈地址:** 提供了加载栈上特定偏移地址的功能（`LoadSpillAddress`）。
8. **一元运算:**  通过宏 `UNOP_LIST` 定义了一系列一元运算，例如取绝对值、取反、开方、取整（floor, ceil, trunc）、计算前导零/尾随零、符号扩展、计算 popcount 等，并为每种运算生成了对应的 `emit_` 函数。
9. **二元运算:** 通过宏 `BINOP_LIST` 定义了一系列二元运算，例如 copysign, min, max, 加减乘除、位运算（与、或、异或）、移位等，并为每种运算生成了对应的 `emit_` 函数。
10. **整数除法和取余:**  提供了带符号和无符号的整数除法（`emit_i32_divs`, `emit_i32_divu`, `emit_i64_divs`, `emit_i64_divu`）和取余（`emit_i32_rems`, `emit_i32_remu`, `emit_i64_rems`, `emit_i64_remu`）操作，并处理了除零错误和溢出情况。
11. **类型转换:**  提供了各种类型转换操作（`emit_type_conversion`），例如整数类型之间的转换、浮点数类型之间的转换、整数和浮点数之间的转换，包括饱和转换和重新解释转换。
12. **Smi 操作:** 提供了递增 Smi（Small Integer）的功能（`IncrementSmi`）。

**如果 `v8/src/wasm/baseline/ppc/liftoff-assembler-ppc-inl.h` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**  但实际上它以 `.h` 结尾，所以它是 C++ 头文件。 Torque 是一种 V8 内部使用的用于生成高效汇编代码的语言。

**它与 JavaScript 的功能有关系，** 因为 WebAssembly 是一种可以在 JavaScript 虚拟机中运行的代码格式。 Liftoff 编译器是 V8 执行 WebAssembly 代码的一种方式。这段代码负责将 WebAssembly 的操作翻译成底层的 PowerPC 汇编指令，使得 JavaScript 引擎能够执行 WebAssembly 代码。

**JavaScript 示例说明：**

虽然这段代码是底层的汇编生成代码，但其最终目的是为了支持 JavaScript 中使用的 WebAssembly 功能。 例如，WebAssembly 中的一个简单的加法操作，在 Liftoff 编译器的背后，可能会用到这段代码中的 `emit_i32_add` 函数。

```javascript
// JavaScript 中调用 WebAssembly 的示例
async function runWasm() {
  const response = await fetch('your_wasm_module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(buffer);
  const instance = module.instance;

  // 假设 WebAssembly 模块中有一个 add 函数，对应 wasm 指令 i32.add
  const result = instance.exports.add(5, 10);
  console.log(result); // 输出 15
}

runWasm();
```

在这个例子中，当 JavaScript 引擎执行 `instance.exports.add(5, 10)` 时，如果 `add` 函数是用 WebAssembly 的 `i32.add` 指令实现的，那么 Liftoff 编译器在编译这段 WebAssembly 代码时，就会使用到 `LiftoffAssembler::emit_i32_add` 这样的函数来生成 PowerPC 架构的加法指令。

**代码逻辑推理示例：**

假设输入：
- `dst_addr` (目标地址寄存器) = `r3`
- `offset_reg` (偏移寄存器) = `r4`
- `offset_imm` (立即数偏移) = `8`
- `expected` (期望值寄存器) = `r5`，值为 `10`
- `new_value` (新值寄存器) = `r6`，值为 `20`
- `result` (结果寄存器) = `r7`
- `type` = `StoreType::kI32Store`

输出（大致的汇编指令）：

```assembly
  // ... 省略一些前置处理 ...
  addi r0, r4, 8       // r0 = r4 + 8
  mr ip, r0            // ip = r0 (将计算后的偏移地址放入 ip 寄存器)
  // ...
  // 执行原子比较并交换，比较内存地址 [ip + r3] 的值是否为 r5，如果是则设置为 r6，并将原始值放入 r7
  lwarx r7, r3, ip     // Load Word And Reserve Indexed (用于原子操作)
  cmpw r7, r5          // 比较内存中的值和期望值
  bne fail             // 如果不相等，跳转到失败标签
  stwcx. r6, r3, ip    // Store Word Conditional Indexed (只有在条件满足时才存储)
  b ok                 // 跳转到成功标签
fail:
  // ... 处理失败情况 ...
ok:
  // ... 处理成功情况 ...
```

**用户常见的编程错误示例：**

在使用原子操作时，一个常见的编程错误是没有正确处理比较和交换失败的情况。例如，在 `AtomicCompareExchange` 中，如果内存中的值在读取后到写入前被其他线程修改，那么交换会失败。用户需要在一个循环中重试操作，直到成功。

```c++
// C++ 模拟原子操作的常见错误
#include <iostream>
#include <atomic>

int main() {
  std::atomic<int> value = 10;
  int expected = 5;
  int desired = 15;

  // 错误的用法：假设一次比较交换就能成功
  if (value.compare_exchange_strong(expected, desired)) {
    std::cout << "交换成功，新值为: " << value.load() << std::endl;
  } else {
    std::cout << "交换失败，当前值为: " << value.load() << std::endl;
    std::cout << "期望值需要更新为: " << expected << std::endl; // 忘记更新 expected
  }

  return 0;
}
```

在这个错误的例子中，如果 `value` 的值在 `compare_exchange_strong` 调用前已经被修改为不是 `5`，那么交换会失败。但是，`expected` 的值没有被更新为 `value` 的当前值，导致后续的重试（如果存在）可能会一直失败。正确的做法是在循环中更新 `expected` 的值。

这段代码是 V8 引擎中实现 WebAssembly 功能的关键组成部分，它将高级的 WebAssembly 指令转换为可以在 PowerPC 架构上执行的底层汇编代码。

Prompt: 
```
这是目录为v8/src/wasm/baseline/ppc/liftoff-assembler-ppc-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/ppc/liftoff-assembler-ppc-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
iftoffAssembler::AtomicCompareExchange(
    Register dst_addr, Register offset_reg, uintptr_t offset_imm,
    LiftoffRegister expected, LiftoffRegister new_value, LiftoffRegister result,
    StoreType type, bool i64_offset) {
  if (!i64_offset && offset_reg != no_reg) {
    ZeroExtWord32(ip, offset_reg);
    offset_reg = ip;
  }

  Register offset = r0;
  if (offset_imm != 0) {
    mov(offset, Operand(offset_imm));
    if (offset_reg != no_reg) add(offset, offset, offset_reg);
    mr(ip, offset);
    offset = ip;
  } else if (offset_reg != no_reg) {
    offset = offset_reg;
  }
  MemOperand dst = MemOperand(offset, dst_addr);
  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8: {
      MacroAssembler::AtomicCompareExchange<uint8_t>(
          dst, expected.gp(), new_value.gp(), result.gp(), r0);
      break;
    }
    case StoreType::kI32Store16:
    case StoreType::kI64Store16: {
      if (is_be) {
        Push(new_value.gp(), expected.gp());
        Register scratch = GetRegisterThatIsNotOneOf(
            new_value.gp(), expected.gp(), result.gp());
        push(scratch);
        ByteReverseU16(new_value.gp(), new_value.gp(), scratch);
        ByteReverseU16(expected.gp(), expected.gp(), scratch);
        pop(scratch);
        MacroAssembler::AtomicCompareExchange<uint16_t>(
            dst, expected.gp(), new_value.gp(), result.gp(), r0);
        ByteReverseU16(result.gp(), result.gp(), r0);
        Pop(new_value.gp(), expected.gp());
      } else {
        MacroAssembler::AtomicCompareExchange<uint16_t>(
            dst, expected.gp(), new_value.gp(), result.gp(), r0);
      }
      break;
    }
    case StoreType::kI32Store:
    case StoreType::kI64Store32: {
      if (is_be) {
        Push(new_value.gp(), expected.gp());
        Register scratch = GetRegisterThatIsNotOneOf(
            new_value.gp(), expected.gp(), result.gp());
        push(scratch);
        ByteReverseU32(new_value.gp(), new_value.gp(), scratch);
        ByteReverseU32(expected.gp(), expected.gp(), scratch);
        pop(scratch);
        MacroAssembler::AtomicCompareExchange<uint32_t>(
            dst, expected.gp(), new_value.gp(), result.gp(), r0);
        ByteReverseU32(result.gp(), result.gp(), r0);
        Pop(new_value.gp(), expected.gp());
      } else {
        MacroAssembler::AtomicCompareExchange<uint32_t>(
            dst, expected.gp(), new_value.gp(), result.gp(), r0);
      }
      break;
    }
    case StoreType::kI64Store: {
      if (is_be) {
        Push(new_value.gp(), expected.gp());
        ByteReverseU64(new_value.gp(), new_value.gp());
        ByteReverseU64(expected.gp(), expected.gp());
        MacroAssembler::AtomicCompareExchange<uint64_t>(
            dst, expected.gp(), new_value.gp(), result.gp(), r0);
        ByteReverseU64(result.gp(), result.gp());
        Pop(new_value.gp(), expected.gp());
      } else {
        MacroAssembler::AtomicCompareExchange<uint64_t>(
            dst, expected.gp(), new_value.gp(), result.gp(), r0);
      }
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicFence() { sync(); }

void LiftoffAssembler::LoadCallerFrameSlot(LiftoffRegister dst,
                                           uint32_t caller_slot_idx,
                                           ValueKind kind) {
  int32_t offset = (caller_slot_idx + 1) * kSystemPointerSize;
  switch (kind) {
    case kI32: {
#if defined(V8_TARGET_BIG_ENDIAN)
      LoadS32(dst.gp(), MemOperand(fp, offset + 4), r0);
      break;
#else
      LoadS32(dst.gp(), MemOperand(fp, offset), r0);
      break;
#endif
    }
    case kRef:
    case kRtt:
    case kRefNull:
    case kI64: {
      LoadU64(dst.gp(), MemOperand(fp, offset), r0);
      break;
    }
    case kF32: {
      LoadF32(dst.fp(), MemOperand(fp, offset), r0);
      break;
    }
    case kF64: {
      LoadF64(dst.fp(), MemOperand(fp, offset), r0);
      break;
    }
    case kS128: {
      LoadSimd128(dst.fp().toSimd(), MemOperand(fp, offset), r0);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::StoreCallerFrameSlot(LiftoffRegister src,
                                            uint32_t caller_slot_idx,
                                            ValueKind kind,
                                            Register frame_pointer) {
  int32_t offset = (caller_slot_idx + 1) * kSystemPointerSize;
  switch (kind) {
    case kI32: {
#if defined(V8_TARGET_BIG_ENDIAN)
      StoreU32(src.gp(), MemOperand(fp, offset + 4), r0);
      break;
#else
      StoreU32(src.gp(), MemOperand(fp, offset), r0);
      break;
#endif
    }
    case kRef:
    case kRtt:
    case kRefNull:
    case kI64: {
      StoreU64(src.gp(), MemOperand(fp, offset), r0);
      break;
    }
    case kF32: {
      StoreF32(src.fp(), MemOperand(fp, offset), r0);
      break;
    }
    case kF64: {
      StoreF64(src.fp(), MemOperand(fp, offset), r0);
      break;
    }
    case kS128: {
      StoreSimd128(src.fp().toSimd(), MemOperand(fp, offset), r0);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::LoadReturnStackSlot(LiftoffRegister dst, int offset,
                                           ValueKind kind) {
  switch (kind) {
    case kI32: {
#if defined(V8_TARGET_BIG_ENDIAN)
      LoadS32(dst.gp(), MemOperand(sp, offset + 4), r0);
      break;
#else
      LoadS32(dst.gp(), MemOperand(sp, offset), r0);
      break;
#endif
    }
    case kRef:
    case kRtt:
    case kRefNull:
    case kI64: {
      LoadU64(dst.gp(), MemOperand(sp, offset), r0);
      break;
    }
    case kF32: {
      LoadF32(dst.fp(), MemOperand(sp, offset), r0);
      break;
    }
    case kF64: {
      LoadF64(dst.fp(), MemOperand(sp, offset), r0);
      break;
    }
    case kS128: {
      LoadSimd128(dst.fp().toSimd(), MemOperand(sp, offset), r0);
      break;
    }
    default:
      UNREACHABLE();
  }
}

#ifdef V8_TARGET_BIG_ENDIAN
constexpr int stack_bias = -4;
#else
constexpr int stack_bias = 0;
#endif

void LiftoffAssembler::MoveStackValue(uint32_t dst_offset, uint32_t src_offset,
                                      ValueKind kind) {
  DCHECK_NE(dst_offset, src_offset);

  switch (kind) {
    case kI32:
    case kF32:
      LoadU32(ip, liftoff::GetStackSlot(src_offset + stack_bias), r0);
      StoreU32(ip, liftoff::GetStackSlot(dst_offset + stack_bias), r0);
      break;
    case kI64:
    case kRefNull:
    case kRef:
    case kRtt:
    case kF64:
      LoadU64(ip, liftoff::GetStackSlot(src_offset), r0);
      StoreU64(ip, liftoff::GetStackSlot(dst_offset), r0);
      break;
    case kS128:
      LoadSimd128(kScratchSimd128Reg, liftoff::GetStackSlot(src_offset), r0);
      StoreSimd128(kScratchSimd128Reg, liftoff::GetStackSlot(dst_offset), r0);
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::Move(Register dst, Register src, ValueKind kind) {
  mr(dst, src);
}

void LiftoffAssembler::Move(DoubleRegister dst, DoubleRegister src,
                            ValueKind kind) {
  if (kind == kF32 || kind == kF64) {
    fmr(dst, src);
  } else {
    DCHECK_EQ(kS128, kind);
    vor(dst.toSimd(), src.toSimd(), src.toSimd());
  }
}

void LiftoffAssembler::Spill(int offset, LiftoffRegister reg, ValueKind kind) {
  DCHECK_LT(0, offset);
  RecordUsedSpillOffset(offset);

  switch (kind) {
    case kI32:
      StoreU32(reg.gp(), liftoff::GetStackSlot(offset + stack_bias), r0);
      break;
    case kI64:
    case kRefNull:
    case kRef:
    case kRtt:
      StoreU64(reg.gp(), liftoff::GetStackSlot(offset), r0);
      break;
    case kF32:
      StoreF32(reg.fp(), liftoff::GetStackSlot(offset + stack_bias), r0);
      break;
    case kF64:
      StoreF64(reg.fp(), liftoff::GetStackSlot(offset), r0);
      break;
    case kS128: {
      StoreSimd128(reg.fp().toSimd(), liftoff::GetStackSlot(offset), r0);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::Spill(int offset, WasmValue value) {
  RecordUsedSpillOffset(offset);
  UseScratchRegisterScope temps(this);
  Register src = no_reg;
  src = ip;
  switch (value.type().kind()) {
    case kI32: {
      mov(src, Operand(value.to_i32()));
      StoreU32(src, liftoff::GetStackSlot(offset + stack_bias), r0);
      break;
    }
    case kI64: {
      mov(src, Operand(value.to_i64()));
      StoreU64(src, liftoff::GetStackSlot(offset), r0);
      break;
    }
    default:
      // We do not track f32 and f64 constants, hence they are unreachable.
      UNREACHABLE();
  }
}

void LiftoffAssembler::Fill(LiftoffRegister reg, int offset, ValueKind kind) {
  switch (kind) {
    case kI32:
      LoadS32(reg.gp(), liftoff::GetStackSlot(offset + stack_bias), r0);
      break;
    case kI64:
    case kRef:
    case kRefNull:
    case kRtt:
      LoadU64(reg.gp(), liftoff::GetStackSlot(offset), r0);
      break;
    case kF32:
      LoadF32(reg.fp(), liftoff::GetStackSlot(offset + stack_bias), r0);
      break;
    case kF64:
      LoadF64(reg.fp(), liftoff::GetStackSlot(offset), r0);
      break;
    case kS128: {
      LoadSimd128(reg.fp().toSimd(), liftoff::GetStackSlot(offset), r0);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::FillI64Half(Register, int offset, RegPairHalf) {
  bailout(kUnsupportedArchitecture, "FillI64Half");
}

void LiftoffAssembler::FillStackSlotsWithZero(int start, int size) {
  DCHECK_LT(0, size);
  DCHECK_EQ(0, size % 8);
  RecordUsedSpillOffset(start + size);

  // We need a zero reg. Always use r0 for that, and push it before to restore
  // its value afterwards.

  if (size <= 36) {
    // Special straight-line code for up to nine words. Generates one
    // instruction per word.
    mov(ip, Operand::Zero());
    uint32_t remainder = size;
    for (; remainder >= kStackSlotSize; remainder -= kStackSlotSize) {
      StoreU64(ip, liftoff::GetStackSlot(start + remainder), r0);
    }
    DCHECK(remainder == 4 || remainder == 0);
    if (remainder) {
      StoreU32(ip, liftoff::GetStackSlot(start + remainder), r0);
    }
  } else {
    Label loop;
    push(r4);

    mov(r4, Operand(size / kSystemPointerSize));
    mtctr(r4);

    SubS64(r4, fp, Operand(start + size + kSystemPointerSize), r0);
    mov(r0, Operand::Zero());

    bind(&loop);
    StoreU64WithUpdate(r0, MemOperand(r4, kSystemPointerSize));
    bdnz(&loop);

    pop(r4);
  }
}

void LiftoffAssembler::LoadSpillAddress(Register dst, int offset,
                                        ValueKind kind) {
  if (kind == kI32) offset = offset + stack_bias;
  SubS64(dst, fp, Operand(offset));
}

#define SIGN_EXT(r) extsw(r, r)
#define ROUND_F64_TO_F32(fpr) frsp(fpr, fpr)
#define INT32_AND_WITH_1F(x) Operand(x & 0x1f)
#define INT32_AND_WITH_3F(x) Operand(x & 0x3f)
#define REGISTER_AND_WITH_1F    \
  ([&](Register rhs) {          \
    andi(r0, rhs, Operand(31)); \
    return r0;                  \
  })

#define REGISTER_AND_WITH_3F    \
  ([&](Register rhs) {          \
    andi(r0, rhs, Operand(63)); \
    return r0;                  \
  })

#define LFR_TO_REG(reg) reg.gp()

// V(name, instr, dtype, stype, dcast, scast, rcast, return_val, return_type)
#define UNOP_LIST(V)                                                         \
  V(f32_abs, fabs, DoubleRegister, DoubleRegister, , , USE, , void)          \
  V(f32_neg, fneg, DoubleRegister, DoubleRegister, , , USE, , void)          \
  V(f32_sqrt, fsqrt, DoubleRegister, DoubleRegister, , , ROUND_F64_TO_F32, , \
    void)                                                                    \
  V(f32_floor, frim, DoubleRegister, DoubleRegister, , , ROUND_F64_TO_F32,   \
    true, bool)                                                              \
  V(f32_ceil, frip, DoubleRegister, DoubleRegister, , , ROUND_F64_TO_F32,    \
    true, bool)                                                              \
  V(f32_trunc, friz, DoubleRegister, DoubleRegister, , , ROUND_F64_TO_F32,   \
    true, bool)                                                              \
  V(f64_abs, fabs, DoubleRegister, DoubleRegister, , , USE, , void)          \
  V(f64_neg, fneg, DoubleRegister, DoubleRegister, , , USE, , void)          \
  V(f64_sqrt, fsqrt, DoubleRegister, DoubleRegister, , , USE, , void)        \
  V(f64_floor, frim, DoubleRegister, DoubleRegister, , , USE, true, bool)    \
  V(f64_ceil, frip, DoubleRegister, DoubleRegister, , , USE, true, bool)     \
  V(f64_trunc, friz, DoubleRegister, DoubleRegister, , , USE, true, bool)    \
  V(i32_clz, CountLeadingZerosU32, Register, Register, , , USE, , void)      \
  V(i32_ctz, CountTrailingZerosU32, Register, Register, , , USE, , void)     \
  V(i64_clz, CountLeadingZerosU64, LiftoffRegister, LiftoffRegister,         \
    LFR_TO_REG, LFR_TO_REG, USE, , void)                                     \
  V(i64_ctz, CountTrailingZerosU64, LiftoffRegister, LiftoffRegister,        \
    LFR_TO_REG, LFR_TO_REG, USE, , void)                                     \
  V(u32_to_uintptr, ZeroExtWord32, Register, Register, , , USE, , void)      \
  V(i32_signextend_i8, extsb, Register, Register, , , USE, , void)           \
  V(i32_signextend_i16, extsh, Register, Register, , , USE, , void)          \
  V(i64_signextend_i8, extsb, LiftoffRegister, LiftoffRegister, LFR_TO_REG,  \
    LFR_TO_REG, USE, , void)                                                 \
  V(i64_signextend_i16, extsh, LiftoffRegister, LiftoffRegister, LFR_TO_REG, \
    LFR_TO_REG, USE, , void)                                                 \
  V(i64_signextend_i32, extsw, LiftoffRegister, LiftoffRegister, LFR_TO_REG, \
    LFR_TO_REG, USE, , void)                                                 \
  V(i32_popcnt, Popcnt32, Register, Register, , , USE, true, bool)           \
  V(i64_popcnt, Popcnt64, LiftoffRegister, LiftoffRegister, LFR_TO_REG,      \
    LFR_TO_REG, USE, true, bool)

#define EMIT_UNOP_FUNCTION(name, instr, dtype, stype, dcast, scast, rcast, \
                           ret, return_type)                               \
  return_type LiftoffAssembler::emit_##name(dtype dst, stype src) {        \
    auto _dst = dcast(dst);                                                \
    auto _src = scast(src);                                                \
    instr(_dst, _src);                                                     \
    rcast(_dst);                                                           \
    return ret;                                                            \
  }
UNOP_LIST(EMIT_UNOP_FUNCTION)
#undef EMIT_UNOP_FUNCTION
#undef UNOP_LIST

// V(name, instr, dtype, stype1, stype2, dcast, scast1, scast2, rcast,
// return_val, return_type)
#define BINOP_LIST(V)                                                          \
  V(f32_copysign, CopySignF64, DoubleRegister, DoubleRegister, DoubleRegister, \
    , , , USE, , void)                                                         \
  V(f64_copysign, CopySignF64, DoubleRegister, DoubleRegister, DoubleRegister, \
    , , , USE, , void)                                                         \
  V(f32_min, MinF64, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(f32_max, MaxF64, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(f64_min, MinF64, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(f64_max, MaxF64, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(i64_sub, SubS64, LiftoffRegister, LiftoffRegister, LiftoffRegister,        \
    LFR_TO_REG, LFR_TO_REG, LFR_TO_REG, USE, , void)                           \
  V(i64_add, AddS64, LiftoffRegister, LiftoffRegister, LiftoffRegister,        \
    LFR_TO_REG, LFR_TO_REG, LFR_TO_REG, USE, , void)                           \
  V(i64_addi, AddS64, LiftoffRegister, LiftoffRegister, int64_t, LFR_TO_REG,   \
    LFR_TO_REG, Operand, USE, , void)                                          \
  V(i32_sub, SubS32, Register, Register, Register, , , , USE, , void)          \
  V(i32_add, AddS32, Register, Register, Register, , , , USE, , void)          \
  V(i32_addi, AddS32, Register, Register, int32_t, , , Operand, USE, , void)   \
  V(i32_subi, SubS32, Register, Register, int32_t, , , Operand, USE, , void)   \
  V(i32_mul, MulS32, Register, Register, Register, , , , USE, , void)          \
  V(i64_mul, MulS64, LiftoffRegister, LiftoffRegister, LiftoffRegister,        \
    LFR_TO_REG, LFR_TO_REG, LFR_TO_REG, USE, , void)                           \
  V(i32_andi, AndU32, Register, Register, int32_t, , , Operand, USE, , void)   \
  V(i32_ori, OrU32, Register, Register, int32_t, , , Operand, USE, , void)     \
  V(i32_xori, XorU32, Register, Register, int32_t, , , Operand, USE, , void)   \
  V(i32_and, AndU32, Register, Register, Register, , , , USE, , void)          \
  V(i32_or, OrU32, Register, Register, Register, , , , USE, , void)            \
  V(i32_xor, XorU32, Register, Register, Register, , , , USE, , void)          \
  V(i64_and, AndU64, LiftoffRegister, LiftoffRegister, LiftoffRegister,        \
    LFR_TO_REG, LFR_TO_REG, LFR_TO_REG, USE, , void)                           \
  V(i64_or, OrU64, LiftoffRegister, LiftoffRegister, LiftoffRegister,          \
    LFR_TO_REG, LFR_TO_REG, LFR_TO_REG, USE, , void)                           \
  V(i64_xor, XorU64, LiftoffRegister, LiftoffRegister, LiftoffRegister,        \
    LFR_TO_REG, LFR_TO_REG, LFR_TO_REG, USE, , void)                           \
  V(i64_andi, AndU64, LiftoffRegister, LiftoffRegister, int32_t, LFR_TO_REG,   \
    LFR_TO_REG, Operand, USE, , void)                                          \
  V(i64_ori, OrU64, LiftoffRegister, LiftoffRegister, int32_t, LFR_TO_REG,     \
    LFR_TO_REG, Operand, USE, , void)                                          \
  V(i64_xori, XorU64, LiftoffRegister, LiftoffRegister, int32_t, LFR_TO_REG,   \
    LFR_TO_REG, Operand, USE, , void)                                          \
  V(i32_shli, ShiftLeftU32, Register, Register, int32_t, , ,                   \
    INT32_AND_WITH_1F, USE, , void)                                            \
  V(i32_sari, ShiftRightS32, Register, Register, int32_t, , ,                  \
    INT32_AND_WITH_1F, USE, , void)                                            \
  V(i32_shri, ShiftRightU32, Register, Register, int32_t, , ,                  \
    INT32_AND_WITH_1F, USE, , void)                                            \
  V(i32_shl, ShiftLeftU32, Register, Register, Register, , ,                   \
    REGISTER_AND_WITH_1F, USE, , void)                                         \
  V(i32_sar, ShiftRightS32, Register, Register, Register, , ,                  \
    REGISTER_AND_WITH_1F, USE, , void)                                         \
  V(i32_shr, ShiftRightU32, Register, Register, Register, , ,                  \
    REGISTER_AND_WITH_1F, USE, , void)                                         \
  V(i64_shl, ShiftLeftU64, LiftoffRegister, LiftoffRegister, Register,         \
    LFR_TO_REG, LFR_TO_REG, REGISTER_AND_WITH_3F, USE, , void)                 \
  V(i64_sar, ShiftRightS64, LiftoffRegister, LiftoffRegister, Register,        \
    LFR_TO_REG, LFR_TO_REG, REGISTER_AND_WITH_3F, USE, , void)                 \
  V(i64_shr, ShiftRightU64, LiftoffRegister, LiftoffRegister, Register,        \
    LFR_TO_REG, LFR_TO_REG, REGISTER_AND_WITH_3F, USE, , void)                 \
  V(i64_shli, ShiftLeftU64, LiftoffRegister, LiftoffRegister, int32_t,         \
    LFR_TO_REG, LFR_TO_REG, INT32_AND_WITH_3F, USE, , void)                    \
  V(i64_sari, ShiftRightS64, LiftoffRegister, LiftoffRegister, int32_t,        \
    LFR_TO_REG, LFR_TO_REG, INT32_AND_WITH_3F, USE, , void)                    \
  V(i64_shri, ShiftRightU64, LiftoffRegister, LiftoffRegister, int32_t,        \
    LFR_TO_REG, LFR_TO_REG, INT32_AND_WITH_3F, USE, , void)                    \
  V(f64_add, AddF64, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(f64_sub, SubF64, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(f64_mul, MulF64, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(f64_div, DivF64, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(f32_add, AddF32, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(f32_sub, SubF32, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(f32_mul, MulF32, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(f32_div, DivF32, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)

#define EMIT_BINOP_FUNCTION(name, instr, dtype, stype1, stype2, dcast, scast1, \
                            scast2, rcast, ret, return_type)                   \
  return_type LiftoffAssembler::emit_##name(dtype dst, stype1 lhs,             \
                                            stype2 rhs) {                      \
    auto _dst = dcast(dst);                                                    \
    auto _lhs = scast1(lhs);                                                   \
    auto _rhs = scast2(rhs);                                                   \
    instr(_dst, _lhs, _rhs);                                                   \
    rcast(_dst);                                                               \
    return ret;                                                                \
  }

BINOP_LIST(EMIT_BINOP_FUNCTION)
#undef BINOP_LIST
#undef EMIT_BINOP_FUNCTION
#undef SIGN_EXT
#undef INT32_AND_WITH_1F
#undef REGISTER_AND_WITH_1F
#undef LFR_TO_REG

bool LiftoffAssembler::emit_f32_nearest_int(DoubleRegister dst,
                                            DoubleRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f64_nearest_int(DoubleRegister dst,
                                            DoubleRegister src) {
  return false;
}

void LiftoffAssembler::IncrementSmi(LiftoffRegister dst, int offset) {
  UseScratchRegisterScope temps(this);
  if (COMPRESS_POINTERS_BOOL) {
    DCHECK(SmiValuesAre31Bits());
    Register scratch = temps.Acquire();
    LoadS32(scratch, MemOperand(dst.gp(), offset), r0);
    AddS64(scratch, scratch, Operand(Smi::FromInt(1)));
    StoreU32(scratch, MemOperand(dst.gp(), offset), r0);
  } else {
    Register scratch = temps.Acquire();
    SmiUntag(scratch, MemOperand(dst.gp(), offset), LeaveRC, r0);
    AddS64(scratch, scratch, Operand(1));
    SmiTag(scratch);
    StoreU64(scratch, MemOperand(dst.gp(), offset), r0);
  }
}

void LiftoffAssembler::emit_i32_divs(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  Label cont;

  // Check for division by zero.
  CmpS32(rhs, Operand::Zero(), r0);
  b(eq, trap_div_by_zero);

  // Check for kMinInt / -1. This is unrepresentable.
  CmpS32(rhs, Operand(-1), r0);
  bne(&cont);
  CmpS32(lhs, Operand(kMinInt), r0);
  b(eq, trap_div_unrepresentable);

  bind(&cont);
  DivS32(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_divu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  CmpS32(rhs, Operand::Zero(), r0);
  beq(trap_div_by_zero);
  DivU32(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_rems(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  Label cont, done, trap_div_unrepresentable;
  // Check for division by zero.
  CmpS32(rhs, Operand::Zero(), r0);
  beq(trap_div_by_zero);

  // Check kMinInt/-1 case.
  CmpS32(rhs, Operand(-1), r0);
  bne(&cont);
  CmpS32(lhs, Operand(kMinInt), r0);
  beq(&trap_div_unrepresentable);

  // Continue noraml calculation.
  bind(&cont);
  ModS32(dst, lhs, rhs);
  bne(&done);

  // trap by kMinInt/-1 case.
  bind(&trap_div_unrepresentable);
  mov(dst, Operand(0));
  bind(&done);
}

void LiftoffAssembler::emit_i32_remu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  CmpS32(rhs, Operand::Zero(), r0);
  beq(trap_div_by_zero);
  ModU32(dst, lhs, rhs);
}

bool LiftoffAssembler::emit_i64_divs(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  constexpr int64_t kMinInt64 = static_cast<int64_t>(1) << 63;
  Label cont;
  // Check for division by zero.
  CmpS64(rhs.gp(), Operand::Zero(), r0);
  beq(trap_div_by_zero);

  // Check for kMinInt / -1. This is unrepresentable.
  CmpS64(rhs.gp(), Operand(-1), r0);
  bne(&cont);
  CmpS64(lhs.gp(), Operand(kMinInt64), r0);
  beq(trap_div_unrepresentable);

  bind(&cont);
  DivS64(dst.gp(), lhs.gp(), rhs.gp());
  return true;
}

bool LiftoffAssembler::emit_i64_divu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  CmpS64(rhs.gp(), Operand::Zero(), r0);
  beq(trap_div_by_zero);
  // Do div.
  DivU64(dst.gp(), lhs.gp(), rhs.gp());
  return true;
}

bool LiftoffAssembler::emit_i64_rems(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  constexpr int64_t kMinInt64 = static_cast<int64_t>(1) << 63;

  Label trap_div_unrepresentable;
  Label done;
  Label cont;

  // Check for division by zero.
  CmpS64(rhs.gp(), Operand::Zero(), r0);
  beq(trap_div_by_zero);

  // Check for kMinInt / -1. This is unrepresentable.
  CmpS64(rhs.gp(), Operand(-1), r0);
  bne(&cont);
  CmpS64(lhs.gp(), Operand(kMinInt64), r0);
  beq(&trap_div_unrepresentable);

  bind(&cont);
  ModS64(dst.gp(), lhs.gp(), rhs.gp());
  bne(&done);

  bind(&trap_div_unrepresentable);
  mov(dst.gp(), Operand(0));
  bind(&done);
  return true;
}

bool LiftoffAssembler::emit_i64_remu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  CmpS64(rhs.gp(), Operand::Zero(), r0);
  beq(trap_div_by_zero);
  ModU64(dst.gp(), lhs.gp(), rhs.gp());
  return true;
}

bool LiftoffAssembler::emit_type_conversion(WasmOpcode opcode,
                                            LiftoffRegister dst,
                                            LiftoffRegister src, Label* trap) {
  switch (opcode) {
    case kExprI32ConvertI64:
      extsw(dst.gp(), src.gp());
      return true;
    case kExprI64SConvertI32:
      extsw(dst.gp(), src.gp());
      return true;
    case kExprI64UConvertI32:
      ZeroExtWord32(dst.gp(), src.gp());
      return true;
    case kExprF32ConvertF64:
      frsp(dst.fp(), src.fp());
      return true;
    case kExprF64ConvertF32:
      fmr(dst.fp(), src.fp());
      return true;
    case kExprF32SConvertI32: {
      ConvertIntToFloat(src.gp(), dst.fp());
      return true;
    }
    case kExprF32UConvertI32: {
      ConvertUnsignedIntToFloat(src.gp(), dst.fp());
      return true;
    }
    case kExprF64SConvertI32: {
      ConvertIntToDouble(src.gp(), dst.fp());
      return true;
    }
    case kExprF64UConvertI32: {
      ConvertUnsignedIntToDouble(src.gp(), dst.fp());
      return true;
    }
    case kExprF64SConvertI64: {
      ConvertInt64ToDouble(src.gp(), dst.fp());
      return true;
    }
    case kExprF64UConvertI64: {
      ConvertUnsignedInt64ToDouble(src.gp(), dst.fp());
      return true;
    }
    case kExprF32SConvertI64: {
      ConvertInt64ToFloat(src.gp(), dst.fp());
      return true;
    }
    case kExprF32UConvertI64: {
      ConvertUnsignedInt64ToFloat(src.gp(), dst.fp());
      return true;
    }
    case kExprI32SConvertF64:
    case kExprI32SConvertF32: {
      LoadDoubleLiteral(kScratchDoubleReg, base::Double(0.0), r0);
      fcmpu(src.fp(), kScratchDoubleReg);
      bunordered(trap);

      mtfsb0(VXCVI);  // clear FPSCR:VXCVI bit
      fctiwz(kScratchDoubleReg, src.fp());
      MovDoubleLowToInt(dst.gp(), kScratchDoubleReg);
      mcrfs(cr7, VXCVI);
      boverflow(trap, cr7);
      return true;
    }
    case kExprI32UConvertF64:
    case kExprI32UConvertF32: {
      mtfsb0(VXCVI);  // clear FPSCR:VXCVI bit
      ConvertDoubleToUnsignedInt64(src.fp(), r0, kScratchDoubleReg,
                                   kRoundToZero);
      mcrfs(cr7, VXCVI);  // extract FPSCR field containing VXCVI into cr7
      boverflow(trap, cr7);
      ZeroExtWord32(dst.gp(), r0);
      CmpU64(dst.gp(), r0);
      bne(trap);
      return true;
    }
    case kExprI64SConvertF64:
    case kExprI64SConvertF32: {
      LoadDoubleLiteral(kScratchDoubleReg, base::Double(0.0), r0);
      fcmpu(src.fp(), kScratchDoubleReg);
      bunordered(trap);

      mtfsb0(VXCVI);  // clear FPSCR:VXCVI bit
      fctidz(kScratchDoubleReg, src.fp());
      MovDoubleToInt64(dst.gp(), kScratchDoubleReg);
      mcrfs(cr7, VXCVI);
      boverflow(trap, cr7);
      return true;
    }
    case kExprI64UConvertF64:
    case kExprI64UConvertF32: {
      LoadDoubleLiteral(kScratchDoubleReg, base::Double(0.0), r0);
      fcmpu(src.fp(), kScratchDoubleReg);
      bunordered(trap);

      mtfsb0(VXCVI);  // clear FPSCR:VXCVI bit
      fctiduz(kScratchDoubleReg, src.fp());
      MovDoubleToInt64(dst.gp(), kScratchDoubleReg);
      mcrfs(cr7, VXCVI);
      boverflow(trap, cr7);
      return true;
    }
    case kExprI32SConvertSatF64:
    case kExprI32SConvertSatF32: {
      Label done, src_is_nan;
      LoadDoubleLiteral(kScratchDoubleReg, base::Double(0.0), r0);
      fcmpu(src.fp(), kScratchDoubleReg);
      bunordered(&src_is_nan);

      mtfsb0(VXCVI);  // clear FPSCR:VXCVI bit
      fctiwz(kScratchDoubleReg, src.fp());
      MovDoubleLowToInt(dst.gp(), kScratchDoubleReg);
      b(&done);

      bind(&src_is_nan);
      mov(dst.gp(), Operand::Zero());

      bind(&done);
      return true;
    }
    case kExprI32UConvertSatF64:
    case kExprI32UConvertSatF32: {
      Label done, src_is_nan;
      LoadDoubleLiteral(kScratchDoubleReg, base::Double(0.0), r0);
      fcmpu(src.fp(), kScratchDoubleReg);
      bunordered(&src_is_nan);

      mtfsb0(VXCVI);  // clear FPSCR:VXCVI bit
      fctiwuz(kScratchDoubleReg, src.fp());
      MovDoubleLowToInt(dst.gp(), kScratchDoubleReg);
      b(&done);

      bind(&src_is_nan);
      mov(dst.gp(), Operand::Zero());

      bind(&done);
      return true;
    }
    case kExprI64SConvertSatF64:
    case kExprI64SConvertSatF32: {
      Label done, src_is_nan;
      LoadDoubleLiteral(kScratchDoubleReg, base::Double(0.0), r0);
      fcmpu(src.fp(), kScratchDoubleReg);
      bunordered(&src_is_nan);

      mtfsb0(VXCVI);  // clear FPSCR:VXCVI bit
      fctidz(kScratchDoubleReg, src.fp());
      MovDoubleToInt64(dst.gp(), kScratchDoubleReg);
      b(&done);

      bind(&src_is_nan);
      mov(dst.gp(), Operand::Zero());

      bind(&done);
      return true;
    }
    case kExprI64UConvertSatF64:
    case kExprI64UConvertSatF32: {
      Label done, src_is_nan;
      LoadDoubleLiteral(kScratchDoubleReg, base::Double(0.0), r0);
      fcmpu(src.fp(), kScratchDoubleReg);
      bunordered(&src_is_nan);

      mtfsb0(VXCVI);  // clear FPSCR:VXCVI bit
      fctiduz(kScratchDoubleReg, src.fp());
      MovDoubleToInt64(dst.gp(), kScratchDoubleReg);
      b(&done);

      bind(&src_is_nan);
      mov(dst.gp(), Operand::Zero());

      bind(&done);
      return true;
    }
    case kExprI32ReinterpretF32: {
      MovFloatToInt(dst.gp(), src.fp(), kScratchDoubleReg);
      return true;
    }
    case kExprI64ReinterpretF64: {
      MovDoubleToInt64(dst.gp(), src.fp());
      return true;
    }
    case kExprF32ReinterpretI32: {
      MovIntToFloat(dst.fp(), src.gp(), r0);
      return true;
    }
    case kExprF64ReinterpretI64: {
      MovInt64ToDouble(dst.fp(), src.gp());
      return true;
    }
    
"""


```