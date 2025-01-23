Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is from `v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h`. I need to go through the code and identify the different functionalities implemented. The instructions are mainly related to:

1. **Integer Arithmetic:** Division, Remainder calculations.
2. **Type Conversions:** Between integers and floating-point numbers of different sizes, including saturated conversions.
3. **Bitwise Operations:** Sign extension, clearing upper bits.
4. **Floating Point Operations:** Copy sign.
5. **Control Flow:** Jumps (conditional and unconditional).
6. **Comparisons:** Setting flags based on comparisons, setting a register based on a condition.
7. **Selection:** Conditional selection of values.
8. **Memory Access:** Loads and Stores with optional transformations (extend, zero-extend, splat), including lane access for SIMD.
9. **SIMD Operations:** Various operations on 128-bit vectors (i8x16, i32x4, f32x4, f64x2, i64x2), including swizzle, relaxed swizzle, truncations, lane selection, splat, extract/replace lane, arithmetic operations, comparisons, shifts, and logical operations.

I should also check if the file name suggests it's a Torque file (it's not, as it doesn't end with `.tq`). I also need to provide a Javascript example if the C++ code relates to Javascript functionality, give example inputs and outputs for logical code, and point out potential programming errors.

**Plan:**

1. Iterate through each function in the C++ code.
2. Describe the function's purpose.
3. Check for Javascript relevance and provide an example if applicable.
4. If there's logic, create a simple example with input and output.
5. Identify potential user errors related to the functionality.
6. Finally, summarize the overall functionality of the code.
这是`v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h` 文件中一部分代码片段的功能归纳：

**核心功能：**

这部分代码定义了 `LiftoffAssembler` 类的成员函数，这些函数封装了 ARM64 汇编指令，用于在 V8 的 Liftoff 编译器的基础上生成 ARM64 架构的机器码。 这些函数主要针对 WebAssembly (Wasm) 的操作，实现了 Wasm 指令到 ARM64 汇编指令的映射。

**具体功能点：**

*   **整数除法和求余 (emit\_i64\_divs, emit\_i64\_divu, emit\_i64\_rems, emit\_i64\_remu):**  实现了有符号和无符号 64 位整数的除法和求余运算，并包含了除零错误的陷阱处理。
*   **类型转换 (emit\_u32\_to\_uintptr, clear\_i32\_upper\_half, emit\_type\_conversion):** 提供了各种数据类型之间的转换，包括 32 位无符号整数到指针大小的转换，清除 32 位整数高位，以及 Wasm 定义的各种类型转换操作（例如，整数与浮点数之间的转换，不同大小整数之间的转换等）。 这些转换中也包含了对溢出和 NaN (Not a Number) 的检查，并跳转到相应的陷阱标签。
*   **浮点数符号复制 (emit\_f32\_copysign, emit\_f64\_copysign):**  将一个浮点数的符号复制到另一个浮点数。
*   **符号扩展 (emit\_i32\_signextend\_i8, emit\_i32\_signextend\_i16, emit\_i64\_signextend\_i8, emit\_i64\_signextend\_i16, emit\_i64\_signextend\_i32):**  将较小位宽的整数值进行符号扩展到更大的位宽。
*   **跳转 (emit\_jump, emit\_cond\_jump, emit\_i32\_cond\_jumpi, emit\_ptrsize\_cond\_jumpi):**  实现无条件跳转和基于各种条件的跳转。
*   **条件设置 (emit\_i32\_eqz, emit\_i32\_set\_cond, emit\_i64\_eqz, emit\_i64\_set\_cond, emit\_f32\_set\_cond, emit\_f64\_set\_cond):**  根据比较结果设置寄存器的值（通常为 0 或 1）。
*   **条件选择 (emit\_select):**  根据条件寄存器的值，选择两个源寄存器中的一个值写入目标寄存器。
*   **SMI 检查 (emit\_smi\_check):**  检查一个值是否是 Small Integer (SMI)，并根据结果跳转。
*   **加载和存储 (LoadTransform, LoadLane, StoreLane):**  从内存中加载数据到寄存器，或将寄存器中的数据存储到内存。`LoadTransform` 提供了加载时进行数据转换的功能（如符号扩展、零扩展或向量复制）。 `LoadLane` 和 `StoreLane` 用于 SIMD 寄存器中特定通道的加载和存储。
*   **SIMD 操作 (emit\_i8x16\_swizzle, emit\_i8x16\_relaxed\_swizzle, emit\_\*):** 提供了各种 SIMD (Single Instruction, Multiple Data) 指令的封装，用于操作 128 位的向量数据，包括通道混洗、浮点数截断、通道选择、以及浮点数和整数的算术、逻辑和比较运算。

**关于文件类型和 JavaScript 关系：**

*   文件名 `liftoff-assembler-arm64-inl.h` 以 `.h` 结尾，表明它是一个 C++ 头文件，而不是 Torque 文件。
*   这些底层汇编操作与 JavaScript 的执行密切相关。JavaScript 引擎需要将 JavaScript 代码（或 WebAssembly 代码）编译成机器码才能执行。Liftoff 编译器是 V8 中一个快速的 Wasm 基线编译器，它使用这些汇编指令来生成高效的机器码。

**JavaScript 举例说明：**

虽然这些代码直接操作的是底层的汇编指令，但它们最终服务于 JavaScript (或 WebAssembly) 的执行。例如，`emit_i64_divs` 函数用于实现 JavaScript 中对 BigInt 类型的除法运算，或者 WebAssembly 中的 `i64.div_s` 指令。

```javascript
// JavaScript 示例 (模拟可能用到 emit_i64_divs 的场景)
const a = 10n; // BigInt
const b = -3n;
const result = a / b;
console.log(result); // 输出 -3n

// WebAssembly 示例 (直接对应)
// 假设有如下 WebAssembly 代码片段
/*
  (module
    (func (export "div_s") (param i64 i64) (result i64)
      local.get 0
      local.get 1
      i64.div_s
    )
  )
*/
// 当执行这个 WebAssembly 函数时，V8 的 Liftoff 编译器会使用类似 emit_i64_divs 的函数
// 生成对应的 ARM64 除法指令。
```

**代码逻辑推理示例：**

以 `emit_i64_divs` 为例，假设输入：

*   `lhs_x` 寄存器 (被除数): 10 (0xA)
*   `rhs_x` 寄存器 (除数): 3 (0x3)
*   `dst_x` 寄存器 (目标寄存器，与 `lhs_x` 不相同)

输出：

*   `dst_x` 寄存器: 3 (商)
*   如果 `rhs_x` 为 0，则会跳转到 `trap_div_by_zero` 标签。
*   如果 `lhs_x` 是最小值 (-9223372036854775808) 且 `rhs_x` 是 -1，则会跳转到 `trap_div_unrepresentable` 标签。

**用户常见的编程错误举例：**

*   **除零错误：** 在使用除法指令时，如果除数为零，会导致程序崩溃或产生未定义的行为。`emit_i64_divs` 和 `emit_i64_divu` 中都包含了对除零情况的检查和跳转到陷阱的处理，但这依赖于编译器生成的代码正确设置了 `trap_div_by_zero` 标签。  用户在编写 WebAssembly 或使用 BigInt 时，需要注意避免除零错误。
    ```javascript
    // JavaScript 除零错误
    try {
      console.log(10n / 0n); // 抛出 RangeError: Division by zero
    } catch (e) {
      console.error(e);
    }

    // WebAssembly 除零错误 (会被 Liftoff 捕获并处理)
    ```
*   **类型转换溢出：** 在进行类型转换时，如果目标类型无法表示源类型的值，会导致数据丢失或产生错误的结果。 例如，将一个很大的浮点数转换为一个较小的整数类型。 `emit_type_conversion` 中的代码尝试检查一些溢出情况，但这并不能覆盖所有可能的溢出场景。 程序员需要了解类型转换的规则和潜在的溢出风险。
    ```javascript
    // JavaScript 类型转换溢出
    console.log(parseInt(999999999999999999999.9)); // 输出 999999999999999900000 (精度丢失)
    console.log(Int32Array.of(2**31)); // 抛出 RangeError: Value is out of bounds.
    ```

**总结：**

这段代码是 V8 引擎中 Liftoff 编译器针对 ARM64 架构的关键组成部分，它定义了将 WebAssembly 操作映射到 ARM64 汇编指令的各种函数。 这些函数涵盖了基本的算术运算、类型转换、控制流、比较操作、内存访问以及 SIMD 操作，为高效地执行 WebAssembly 代码提供了基础。 开发者在使用 JavaScript (特别是 BigInt) 或编写 WebAssembly 时，需要注意潜在的除零错误和类型转换溢出等问题，尽管 V8 引擎会在一定程度上处理这些错误。

### 提示词
```
这是目录为v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```c
iases(lhs_x) && !dst_x.Aliases(rhs_x);
  if (can_use_dst) {
    // Do div early.
    Sdiv(dst_x, lhs_x, rhs_x);
  }
  // Check for division by zero.
  Cbz(rhs_x, trap_div_by_zero);
  // Check for kMinInt / -1. This is unrepresentable.
  Cmp(rhs_x, -1);
  Ccmp(lhs_x, 1, NoFlag, eq);
  B(trap_div_unrepresentable, vs);
  if (!can_use_dst) {
    // Do div.
    Sdiv(dst_x, lhs_x, rhs_x);
  }
  return true;
}

bool LiftoffAssembler::emit_i64_divu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  // Check for division by zero.
  Cbz(rhs.gp().X(), trap_div_by_zero);
  // Do div.
  Udiv(dst.gp().X(), lhs.gp().X(), rhs.gp().X());
  return true;
}

bool LiftoffAssembler::emit_i64_rems(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  Register dst_x = dst.gp().X();
  Register lhs_x = lhs.gp().X();
  Register rhs_x = rhs.gp().X();
  // Do early div.
  // No need to check kMinInt / -1 because the result is kMinInt and then
  // kMinInt * -1 -> kMinInt. In this case, the Msub result is therefore 0.
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Sdiv(scratch, lhs_x, rhs_x);
  // Check for division by zero.
  Cbz(rhs_x, trap_div_by_zero);
  // Compute remainder.
  Msub(dst_x, scratch, rhs_x, lhs_x);
  return true;
}

bool LiftoffAssembler::emit_i64_remu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  Register dst_x = dst.gp().X();
  Register lhs_x = lhs.gp().X();
  Register rhs_x = rhs.gp().X();
  // Do early div.
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Udiv(scratch, lhs_x, rhs_x);
  // Check for division by zero.
  Cbz(rhs_x, trap_div_by_zero);
  // Compute remainder.
  Msub(dst_x, scratch, rhs_x, lhs_x);
  return true;
}

void LiftoffAssembler::emit_u32_to_uintptr(Register dst, Register src) {
  Uxtw(dst, src);
}

void LiftoffAssembler::clear_i32_upper_half(Register dst) { Uxtw(dst, dst); }

void LiftoffAssembler::emit_f32_copysign(DoubleRegister dst, DoubleRegister lhs,
                                         DoubleRegister rhs) {
  UseScratchRegisterScope temps(this);
  DoubleRegister scratch = temps.AcquireD();
  Ushr(scratch.V2S(), rhs.V2S(), 31);
  if (dst != lhs) {
    Fmov(dst.S(), lhs.S());
  }
  Sli(dst.V2S(), scratch.V2S(), 31);
}

void LiftoffAssembler::emit_f64_copysign(DoubleRegister dst, DoubleRegister lhs,
                                         DoubleRegister rhs) {
  UseScratchRegisterScope temps(this);
  DoubleRegister scratch = temps.AcquireD();
  Ushr(scratch.V1D(), rhs.V1D(), 63);
  if (dst != lhs) {
    Fmov(dst.D(), lhs.D());
  }
  Sli(dst.V1D(), scratch.V1D(), 63);
}

bool LiftoffAssembler::emit_type_conversion(WasmOpcode opcode,
                                            LiftoffRegister dst,
                                            LiftoffRegister src, Label* trap) {
  switch (opcode) {
    case kExprI32ConvertI64:
      Mov(dst.gp().W(), src.gp().W());
      return true;
    case kExprI32SConvertF32:
      Fcvtzs(dst.gp().W(), src.fp().S());  // f32 -> i32 round to zero.
      // Check underflow and NaN.
      Fcmp(src.fp().S(), static_cast<float>(INT32_MIN));
      // Check overflow.
      Ccmp(dst.gp().W(), -1, VFlag, ge);
      B(trap, vs);
      return true;
    case kExprI32UConvertF32:
      Fcvtzu(dst.gp().W(), src.fp().S());  // f32 -> i32 round to zero.
      // Check underflow and NaN.
      Fcmp(src.fp().S(), -1.0);
      // Check overflow.
      Ccmp(dst.gp().W(), -1, ZFlag, gt);
      B(trap, eq);
      return true;
    case kExprI32SConvertF64: {
      // INT32_MIN and INT32_MAX are valid results, we cannot test the result
      // to detect the overflows. We could have done two immediate floating
      // point comparisons but it would have generated two conditional branches.
      UseScratchRegisterScope temps(this);
      VRegister fp_ref = temps.AcquireD();
      VRegister fp_cmp = temps.AcquireD();
      Fcvtzs(dst.gp().W(), src.fp().D());  // f64 -> i32 round to zero.
      Frintz(fp_ref, src.fp().D());        // f64 -> f64 round to zero.
      Scvtf(fp_cmp, dst.gp().W());         // i32 -> f64.
      // If comparison fails, we have an overflow or a NaN.
      Fcmp(fp_cmp, fp_ref);
      B(trap, ne);
      return true;
    }
    case kExprI32UConvertF64: {
      // INT32_MAX is a valid result, we cannot test the result to detect the
      // overflows. We could have done two immediate floating point comparisons
      // but it would have generated two conditional branches.
      UseScratchRegisterScope temps(this);
      VRegister fp_ref = temps.AcquireD();
      VRegister fp_cmp = temps.AcquireD();
      Fcvtzu(dst.gp().W(), src.fp().D());  // f64 -> i32 round to zero.
      Frintz(fp_ref, src.fp().D());        // f64 -> f64 round to zero.
      Ucvtf(fp_cmp, dst.gp().W());         // i32 -> f64.
      // If comparison fails, we have an overflow or a NaN.
      Fcmp(fp_cmp, fp_ref);
      B(trap, ne);
      return true;
    }
    case kExprI32SConvertSatF32:
      Fcvtzs(dst.gp().W(), src.fp().S());
      return true;
    case kExprI32UConvertSatF32:
      Fcvtzu(dst.gp().W(), src.fp().S());
      return true;
    case kExprI32SConvertSatF64:
      Fcvtzs(dst.gp().W(), src.fp().D());
      return true;
    case kExprI32UConvertSatF64:
      Fcvtzu(dst.gp().W(), src.fp().D());
      return true;
    case kExprI64SConvertSatF32:
      Fcvtzs(dst.gp().X(), src.fp().S());
      return true;
    case kExprI64UConvertSatF32:
      Fcvtzu(dst.gp().X(), src.fp().S());
      return true;
    case kExprI64SConvertSatF64:
      Fcvtzs(dst.gp().X(), src.fp().D());
      return true;
    case kExprI64UConvertSatF64:
      Fcvtzu(dst.gp().X(), src.fp().D());
      return true;
    case kExprI32ReinterpretF32:
      Fmov(dst.gp().W(), src.fp().S());
      return true;
    case kExprI64SConvertI32:
      Sxtw(dst.gp().X(), src.gp().W());
      return true;
    case kExprI64SConvertF32:
      Fcvtzs(dst.gp().X(), src.fp().S());  // f32 -> i64 round to zero.
      // Check underflow and NaN.
      Fcmp(src.fp().S(), static_cast<float>(INT64_MIN));
      // Check overflow.
      Ccmp(dst.gp().X(), -1, VFlag, ge);
      B(trap, vs);
      return true;
    case kExprI64UConvertF32:
      Fcvtzu(dst.gp().X(), src.fp().S());  // f32 -> i64 round to zero.
      // Check underflow and NaN.
      Fcmp(src.fp().S(), -1.0);
      // Check overflow.
      Ccmp(dst.gp().X(), -1, ZFlag, gt);
      B(trap, eq);
      return true;
    case kExprI64SConvertF64:
      Fcvtzs(dst.gp().X(), src.fp().D());  // f64 -> i64 round to zero.
      // Check underflow and NaN.
      Fcmp(src.fp().D(), static_cast<float>(INT64_MIN));
      // Check overflow.
      Ccmp(dst.gp().X(), -1, VFlag, ge);
      B(trap, vs);
      return true;
    case kExprI64UConvertF64:
      Fcvtzu(dst.gp().X(), src.fp().D());  // f64 -> i64 round to zero.
      // Check underflow and NaN.
      Fcmp(src.fp().D(), -1.0);
      // Check overflow.
      Ccmp(dst.gp().X(), -1, ZFlag, gt);
      B(trap, eq);
      return true;
    case kExprI64UConvertI32:
      Mov(dst.gp().W(), src.gp().W());
      return true;
    case kExprI64ReinterpretF64:
      Fmov(dst.gp().X(), src.fp().D());
      return true;
    case kExprF32SConvertI32:
      Scvtf(dst.fp().S(), src.gp().W());
      return true;
    case kExprF32UConvertI32:
      Ucvtf(dst.fp().S(), src.gp().W());
      return true;
    case kExprF32SConvertI64:
      Scvtf(dst.fp().S(), src.gp().X());
      return true;
    case kExprF32UConvertI64:
      Ucvtf(dst.fp().S(), src.gp().X());
      return true;
    case kExprF32ConvertF64:
      Fcvt(dst.fp().S(), src.fp().D());
      return true;
    case kExprF32ReinterpretI32:
      Fmov(dst.fp().S(), src.gp().W());
      return true;
    case kExprF64SConvertI32:
      Scvtf(dst.fp().D(), src.gp().W());
      return true;
    case kExprF64UConvertI32:
      Ucvtf(dst.fp().D(), src.gp().W());
      return true;
    case kExprF64SConvertI64:
      Scvtf(dst.fp().D(), src.gp().X());
      return true;
    case kExprF64UConvertI64:
      Ucvtf(dst.fp().D(), src.gp().X());
      return true;
    case kExprF64ConvertF32:
      Fcvt(dst.fp().D(), src.fp().S());
      return true;
    case kExprF64ReinterpretI64:
      Fmov(dst.fp().D(), src.gp().X());
      return true;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::emit_i32_signextend_i8(Register dst, Register src) {
  sxtb(dst.W(), src.W());
}

void LiftoffAssembler::emit_i32_signextend_i16(Register dst, Register src) {
  sxth(dst.W(), src.W());
}

void LiftoffAssembler::emit_i64_signextend_i8(LiftoffRegister dst,
                                              LiftoffRegister src) {
  sxtb(dst.gp(), src.gp());
}

void LiftoffAssembler::emit_i64_signextend_i16(LiftoffRegister dst,
                                               LiftoffRegister src) {
  sxth(dst.gp(), src.gp());
}

void LiftoffAssembler::emit_i64_signextend_i32(LiftoffRegister dst,
                                               LiftoffRegister src) {
  sxtw(dst.gp(), src.gp());
}

void LiftoffAssembler::emit_jump(Label* label) { B(label); }

void LiftoffAssembler::emit_jump(Register target) { Br(target); }

void LiftoffAssembler::emit_cond_jump(Condition cond, Label* label,
                                      ValueKind kind, Register lhs,
                                      Register rhs,
                                      const FreezeCacheState& frozen) {
  switch (kind) {
    case kI32:
      if (rhs.is_valid()) {
        Cmp(lhs.W(), rhs.W());
      } else {
        Cmp(lhs.W(), wzr);
      }
      break;
    case kRef:
    case kRefNull:
    case kRtt:
      DCHECK(rhs.is_valid());
      DCHECK(cond == kEqual || cond == kNotEqual);
#if defined(V8_COMPRESS_POINTERS)
      Cmp(lhs.W(), rhs.W());
#else
      Cmp(lhs.X(), rhs.X());
#endif
      break;
    case kI64:
      if (rhs.is_valid()) {
        Cmp(lhs.X(), rhs.X());
      } else {
        Cmp(lhs.X(), xzr);
      }
      break;
    default:
      UNREACHABLE();
  }
  B(label, cond);
}

void LiftoffAssembler::emit_i32_cond_jumpi(Condition cond, Label* label,
                                           Register lhs, int32_t imm,
                                           const FreezeCacheState& frozen) {
  Cmp(lhs.W(), Operand(imm));
  B(label, cond);
}

void LiftoffAssembler::emit_ptrsize_cond_jumpi(Condition cond, Label* label,
                                               Register lhs, int32_t imm,
                                               const FreezeCacheState& frozen) {
  Cmp(lhs.X(), Operand(imm));
  B(label, cond);
}

void LiftoffAssembler::emit_i32_eqz(Register dst, Register src) {
  Cmp(src.W(), wzr);
  Cset(dst.W(), eq);
}

void LiftoffAssembler::emit_i32_set_cond(Condition cond, Register dst,
                                         Register lhs, Register rhs) {
  Cmp(lhs.W(), rhs.W());
  Cset(dst.W(), cond);
}

void LiftoffAssembler::emit_i64_eqz(Register dst, LiftoffRegister src) {
  Cmp(src.gp().X(), xzr);
  Cset(dst.W(), eq);
}

void LiftoffAssembler::emit_i64_set_cond(Condition cond, Register dst,
                                         LiftoffRegister lhs,
                                         LiftoffRegister rhs) {
  Cmp(lhs.gp().X(), rhs.gp().X());
  Cset(dst.W(), cond);
}

void LiftoffAssembler::emit_f32_set_cond(Condition cond, Register dst,
                                         DoubleRegister lhs,
                                         DoubleRegister rhs) {
  Fcmp(lhs.S(), rhs.S());
  Cset(dst.W(), cond);
  if (cond != ne) {
    // If V flag set, at least one of the arguments was a Nan -> false.
    Csel(dst.W(), wzr, dst.W(), vs);
  }
}

void LiftoffAssembler::emit_f64_set_cond(Condition cond, Register dst,
                                         DoubleRegister lhs,
                                         DoubleRegister rhs) {
  Fcmp(lhs.D(), rhs.D());
  Cset(dst.W(), cond);
  if (cond != ne) {
    // If V flag set, at least one of the arguments was a Nan -> false.
    Csel(dst.W(), wzr, dst.W(), vs);
  }
}

bool LiftoffAssembler::emit_select(LiftoffRegister dst, Register condition,
                                   LiftoffRegister true_value,
                                   LiftoffRegister false_value,
                                   ValueKind kind) {
  if (kind != kI32 && kind != kI64 && kind != kF32 && kind != kF64)
    return false;

  Cmp(condition.W(), wzr);
  switch (kind) {
    default:
      UNREACHABLE();
    case kI32:
      Csel(dst.gp().W(), true_value.gp().W(), false_value.gp().W(), ne);
      break;
    case kI64:
      Csel(dst.gp().X(), true_value.gp().X(), false_value.gp().X(), ne);
      break;
    case kF32:
      Fcsel(dst.fp().S(), true_value.fp().S(), false_value.fp().S(), ne);
      break;
    case kF64:
      Fcsel(dst.fp().D(), true_value.fp().D(), false_value.fp().D(), ne);
      break;
  }
  return true;
}

void LiftoffAssembler::emit_smi_check(Register obj, Label* target,
                                      SmiCheckMode mode,
                                      const FreezeCacheState& frozen) {
  Label* smi_label = mode == kJumpOnSmi ? target : nullptr;
  Label* not_smi_label = mode == kJumpOnNotSmi ? target : nullptr;
  JumpIfSmi(obj, smi_label, not_smi_label);
}

void LiftoffAssembler::LoadTransform(LiftoffRegister dst, Register src_addr,
                                     Register offset_reg, uintptr_t offset_imm,
                                     LoadType type,
                                     LoadTransformationKind transform,
                                     uint32_t* protected_load_pc) {
  UseScratchRegisterScope temps(this);
  MemOperand src_op =
      transform == LoadTransformationKind::kSplat
          ? MemOperand{liftoff::GetEffectiveAddress(this, &temps, src_addr,
                                                    offset_reg, offset_imm)}
          : liftoff::GetMemOp(this, &temps, src_addr, offset_reg, offset_imm);
  *protected_load_pc = pc_offset();
  MachineType memtype = type.mem_type();

  if (transform == LoadTransformationKind::kExtend) {
    if (memtype == MachineType::Int8()) {
      Ldr(dst.fp().D(), src_op);
      Sxtl(dst.fp().V8H(), dst.fp().V8B());
    } else if (memtype == MachineType::Uint8()) {
      Ldr(dst.fp().D(), src_op);
      Uxtl(dst.fp().V8H(), dst.fp().V8B());
    } else if (memtype == MachineType::Int16()) {
      Ldr(dst.fp().D(), src_op);
      Sxtl(dst.fp().V4S(), dst.fp().V4H());
    } else if (memtype == MachineType::Uint16()) {
      Ldr(dst.fp().D(), src_op);
      Uxtl(dst.fp().V4S(), dst.fp().V4H());
    } else if (memtype == MachineType::Int32()) {
      Ldr(dst.fp().D(), src_op);
      Sxtl(dst.fp().V2D(), dst.fp().V2S());
    } else if (memtype == MachineType::Uint32()) {
      Ldr(dst.fp().D(), src_op);
      Uxtl(dst.fp().V2D(), dst.fp().V2S());
    }
  } else if (transform == LoadTransformationKind::kZeroExtend) {
    if (memtype == MachineType::Int32()) {
      Ldr(dst.fp().S(), src_op);
    } else {
      DCHECK_EQ(MachineType::Int64(), memtype);
      Ldr(dst.fp().D(), src_op);
    }
  } else {
    DCHECK_EQ(LoadTransformationKind::kSplat, transform);
    if (memtype == MachineType::Int8()) {
      ld1r(dst.fp().V16B(), src_op);
    } else if (memtype == MachineType::Int16()) {
      ld1r(dst.fp().V8H(), src_op);
    } else if (memtype == MachineType::Int32()) {
      ld1r(dst.fp().V4S(), src_op);
    } else if (memtype == MachineType::Int64()) {
      ld1r(dst.fp().V2D(), src_op);
    }
  }
}

void LiftoffAssembler::LoadLane(LiftoffRegister dst, LiftoffRegister src,
                                Register addr, Register offset_reg,
                                uintptr_t offset_imm, LoadType type,
                                uint8_t laneidx, uint32_t* protected_load_pc,
                                bool i64_offset) {
  UseScratchRegisterScope temps(this);
  MemOperand src_op{liftoff::GetEffectiveAddress(this, &temps, addr, offset_reg,
                                                 offset_imm, i64_offset)};

  MachineType mem_type = type.mem_type();
  if (dst != src) {
    Mov(dst.fp().Q(), src.fp().Q());
  }

  *protected_load_pc = pc_offset();
  if (mem_type == MachineType::Int8()) {
    ld1(dst.fp().B(), laneidx, src_op);
  } else if (mem_type == MachineType::Int16()) {
    ld1(dst.fp().H(), laneidx, src_op);
  } else if (mem_type == MachineType::Int32()) {
    ld1(dst.fp().S(), laneidx, src_op);
  } else if (mem_type == MachineType::Int64()) {
    ld1(dst.fp().D(), laneidx, src_op);
  } else {
    UNREACHABLE();
  }
}

void LiftoffAssembler::StoreLane(Register dst, Register offset,
                                 uintptr_t offset_imm, LiftoffRegister src,
                                 StoreType type, uint8_t lane,
                                 uint32_t* protected_store_pc,
                                 bool i64_offset) {
  UseScratchRegisterScope temps(this);
  MemOperand dst_op{liftoff::GetEffectiveAddress(this, &temps, dst, offset,
                                                 offset_imm, i64_offset)};
  if (protected_store_pc) *protected_store_pc = pc_offset();

  MachineRepresentation rep = type.mem_rep();
  if (rep == MachineRepresentation::kWord8) {
    st1(src.fp().B(), lane, dst_op);
  } else if (rep == MachineRepresentation::kWord16) {
    st1(src.fp().H(), lane, dst_op);
  } else if (rep == MachineRepresentation::kWord32) {
    st1(src.fp().S(), lane, dst_op);
  } else {
    DCHECK_EQ(MachineRepresentation::kWord64, rep);
    st1(src.fp().D(), lane, dst_op);
  }
}

void LiftoffAssembler::emit_i8x16_swizzle(LiftoffRegister dst,
                                          LiftoffRegister lhs,
                                          LiftoffRegister rhs) {
  Tbl(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_i8x16_relaxed_swizzle(LiftoffRegister dst,
                                                  LiftoffRegister lhs,
                                                  LiftoffRegister rhs) {
  Tbl(dst.fp().V16B(), lhs.fp().V16B(), rhs.fp().V16B());
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f32x4_s(LiftoffRegister dst,
                                                        LiftoffRegister src) {
  Fcvtzs(dst.fp().V4S(), src.fp().V4S());
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f32x4_u(LiftoffRegister dst,
                                                        LiftoffRegister src) {
  Fcvtzu(dst.fp().V4S(), src.fp().V4S());
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f64x2_s_zero(
    LiftoffRegister dst, LiftoffRegister src) {
  Fcvtzs(dst.fp().V2D(), src.fp().V2D());
  Sqxtn(dst.fp().V2S(), dst.fp().V2D());
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f64x2_u_zero(
    LiftoffRegister dst, LiftoffRegister src) {
  Fcvtzu(dst.fp().V2D(), src.fp().V2D());
  Uqxtn(dst.fp().V2S(), dst.fp().V2D());
}

void LiftoffAssembler::emit_s128_relaxed_laneselect(LiftoffRegister dst,
                                                    LiftoffRegister src1,
                                                    LiftoffRegister src2,
                                                    LiftoffRegister mask,
                                                    int lane_width) {
  // ARM64 uses bytewise selection for all lane widths.
  emit_s128_select(dst, src1, src2, mask);
}

void LiftoffAssembler::emit_f64x2_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Dup(dst.fp().V2D(), src.fp().D(), 0);
}

void LiftoffAssembler::emit_f64x2_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  Mov(dst.fp().D(), lhs.fp().V2D(), imm_lane_idx);
}

void LiftoffAssembler::emit_f64x2_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  if (dst != src1) {
    Mov(dst.fp().V2D(), src1.fp().V2D());
  }
  Mov(dst.fp().V2D(), imm_lane_idx, src2.fp().V2D(), 0);
}

void LiftoffAssembler::emit_f64x2_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Fabs(dst.fp().V2D(), src.fp().V2D());
}

void LiftoffAssembler::emit_f64x2_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Fneg(dst.fp().V2D(), src.fp().V2D());
}

void LiftoffAssembler::emit_f64x2_sqrt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  Fsqrt(dst.fp().V2D(), src.fp().V2D());
}

bool LiftoffAssembler::emit_f64x2_ceil(LiftoffRegister dst,
                                       LiftoffRegister src) {
  Frintp(dst.fp().V2D(), src.fp().V2D());
  return true;
}

bool LiftoffAssembler::emit_f64x2_floor(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Frintm(dst.fp().V2D(), src.fp().V2D());
  return true;
}

bool LiftoffAssembler::emit_f64x2_trunc(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Frintz(dst.fp().V2D(), src.fp().V2D());
  return true;
}

bool LiftoffAssembler::emit_f64x2_nearest_int(LiftoffRegister dst,
                                              LiftoffRegister src) {
  Frintn(dst.fp().V2D(), src.fp().V2D());
  return true;
}

void LiftoffAssembler::emit_f64x2_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Fadd(dst.fp().V2D(), lhs.fp().V2D(), rhs.fp().V2D());
}

void LiftoffAssembler::emit_f64x2_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Fsub(dst.fp().V2D(), lhs.fp().V2D(), rhs.fp().V2D());
}

void LiftoffAssembler::emit_f64x2_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Fmul(dst.fp().V2D(), lhs.fp().V2D(), rhs.fp().V2D());
}

void LiftoffAssembler::emit_f64x2_div(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Fdiv(dst.fp().V2D(), lhs.fp().V2D(), rhs.fp().V2D());
}

void LiftoffAssembler::emit_f64x2_min(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Fmin(dst.fp().V2D(), lhs.fp().V2D(), rhs.fp().V2D());
}

void LiftoffAssembler::emit_f64x2_max(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Fmax(dst.fp().V2D(), lhs.fp().V2D(), rhs.fp().V2D());
}

void LiftoffAssembler::emit_f64x2_pmin(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  UseScratchRegisterScope temps(this);

  VRegister tmp = dst.fp();
  if (dst == lhs || dst == rhs) {
    tmp = temps.AcquireV(kFormat2D);
  }

  Fcmgt(tmp.V2D(), lhs.fp().V2D(), rhs.fp().V2D());
  Bsl(tmp.V16B(), rhs.fp().V16B(), lhs.fp().V16B());

  if (dst == lhs || dst == rhs) {
    Mov(dst.fp().V2D(), tmp);
  }
}

void LiftoffAssembler::emit_f64x2_pmax(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  UseScratchRegisterScope temps(this);

  VRegister tmp = dst.fp();
  if (dst == lhs || dst == rhs) {
    tmp = temps.AcquireV(kFormat2D);
  }

  Fcmgt(tmp.V2D(), rhs.fp().V2D(), lhs.fp().V2D());
  Bsl(tmp.V16B(), rhs.fp().V16B(), lhs.fp().V16B());

  if (dst == lhs || dst == rhs) {
    Mov(dst.fp().V2D(), tmp);
  }
}

void LiftoffAssembler::emit_f64x2_relaxed_min(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  Fmin(dst.fp().V2D(), lhs.fp().V2D(), rhs.fp().V2D());
}

void LiftoffAssembler::emit_f64x2_relaxed_max(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  Fmax(dst.fp().V2D(), lhs.fp().V2D(), rhs.fp().V2D());
}

void LiftoffAssembler::emit_f64x2_convert_low_i32x4_s(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  Sxtl(dst.fp().V2D(), src.fp().V2S());
  Scvtf(dst.fp().V2D(), dst.fp().V2D());
}

void LiftoffAssembler::emit_f64x2_convert_low_i32x4_u(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  Uxtl(dst.fp().V2D(), src.fp().V2S());
  Ucvtf(dst.fp().V2D(), dst.fp().V2D());
}

void LiftoffAssembler::emit_f64x2_promote_low_f32x4(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  Fcvtl(dst.fp().V2D(), src.fp().V2S());
}

void LiftoffAssembler::emit_f32x4_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Dup(dst.fp().V4S(), src.fp().S(), 0);
}

void LiftoffAssembler::emit_f32x4_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  Mov(dst.fp().S(), lhs.fp().V4S(), imm_lane_idx);
}

void LiftoffAssembler::emit_f32x4_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  if (dst != src1) {
    Mov(dst.fp().V4S(), src1.fp().V4S());
  }
  Mov(dst.fp().V4S(), imm_lane_idx, src2.fp().V4S(), 0);
}

void LiftoffAssembler::emit_f32x4_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Fabs(dst.fp().V4S(), src.fp().V4S());
}

void LiftoffAssembler::emit_f32x4_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Fneg(dst.fp().V4S(), src.fp().V4S());
}

void LiftoffAssembler::emit_f32x4_sqrt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  Fsqrt(dst.fp().V4S(), src.fp().V4S());
}

bool LiftoffAssembler::emit_f32x4_ceil(LiftoffRegister dst,
                                       LiftoffRegister src) {
  Frintp(dst.fp().V4S(), src.fp().V4S());
  return true;
}

bool LiftoffAssembler::emit_f32x4_floor(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Frintm(dst.fp().V4S(), src.fp().V4S());
  return true;
}

bool LiftoffAssembler::emit_f32x4_trunc(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Frintz(dst.fp().V4S(), src.fp().V4S());
  return true;
}

bool LiftoffAssembler::emit_f32x4_nearest_int(LiftoffRegister dst,
                                              LiftoffRegister src) {
  Frintn(dst.fp().V4S(), src.fp().V4S());
  return true;
}

void LiftoffAssembler::emit_f32x4_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Fadd(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_f32x4_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Fsub(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_f32x4_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Fmul(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_f32x4_div(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Fdiv(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_f32x4_min(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Fmin(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_f32x4_max(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Fmax(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_f32x4_relaxed_min(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  Fmin(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_f32x4_relaxed_max(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  Fmax(dst.fp().V4S(), lhs.fp().V4S(), rhs.fp().V4S());
}

void LiftoffAssembler::emit_f32x4_pmin(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  UseScratchRegisterScope temps(this);

  VRegister tmp = dst.fp();
  if (dst == lhs || dst == rhs) {
    tmp = temps.AcquireV(kFormat4S);
  }

  Fcmgt(tmp.V4S(), lhs.fp().V4S(), rhs.fp().V4S());
  Bsl(tmp.V16B(), rhs.fp().V16B(), lhs.fp().V16B());

  if (dst == lhs || dst == rhs) {
    Mov(dst.fp().V4S(), tmp);
  }
}

void LiftoffAssembler::emit_f32x4_pmax(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  UseScratchRegisterScope temps(this);

  VRegister tmp = dst.fp();
  if (dst == lhs || dst == rhs) {
    tmp = temps.AcquireV(kFormat4S);
  }

  Fcmgt(tmp.V4S(), rhs.fp().V4S(), lhs.fp().V4S());
  Bsl(tmp.V16B(), rhs.fp().V16B(), lhs.fp().V16B());

  if (dst == lhs || dst == rhs) {
    Mov(dst.fp().V4S(), tmp);
  }
}

void LiftoffAssembler::emit_i64x2_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Dup(dst.fp().V2D(), src.gp().X());
}

void LiftoffAssembler::emit_i64x2_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  Mov(dst.gp().X(), lhs.fp().V2D(), imm_lane_idx);
}

void LiftoffAssembler::emit_i64x2_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  if (dst != src1) {
    Mov(dst.fp().V2D(), src1.fp().V2D());
  }
  Mov(dst.fp().V2D(), imm_lane_idx, src2.gp().X());
}

void LiftoffAssembler::emit_i64x2_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Neg(dst.fp().V2D(), src.fp().V2D());
}

void LiftoffAssembler::emit_i64x2_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  I64x2AllTrue(dst.gp(), src.fp());
}

void LiftoffAssembler::emit_i64x2_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdShift<liftoff::ShiftDirection::kLeft>(
      this, dst.fp().V2D(), lhs.fp().V2D(), rhs.gp(), kFormat2D);
}

void LiftoffAssembler::emit_i64x2_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  Shl(dst.fp().V2D(), lhs.fp().V2D(), rhs & 63);
}

void LiftoffAssembler::emit_i64x2_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdShift<liftoff::ShiftDirection::kRight,
                         liftoff::ShiftSign::kSigned>(
      this, dst.fp().V2D(), lhs.fp().V2D(), rhs.gp(), kFormat2D);
}

void LiftoffAssembler::emit_i64x2_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  liftoff::EmitSimdShiftRightImmediate<kFormat2D, liftoff::ShiftSign::kSigned>(
      this, dst.fp().V2D(), lhs.fp().V2D(), rhs);
}

void LiftoffAssembler::emit_i64x2_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdShift<liftoff::ShiftDirection::kRight,
                         liftoff::ShiftSign::kUnsigned>(
      this, dst.fp().V2D(), lhs.fp().V2D(), rhs.gp(), kFormat2D);
}

void LiftoffAssembler::emit_i64x2_shri_u(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  liftoff::EmitSimdShiftRightImmediate<kFormat2D,
                                       liftoff::ShiftSign::kUnsigned>(
      this, dst.fp().V2D(), lhs.fp().V2D(), rhs);
}

void LiftoffAssembler::emit_i64x2_add(LiftoffRegister dst, LiftoffRegister l
```