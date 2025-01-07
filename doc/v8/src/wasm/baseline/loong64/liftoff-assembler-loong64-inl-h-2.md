Response:
The user wants to understand the functionality of a C++ header file `liftoff-assembler-loong64-inl.h` which is part of the V8 JavaScript engine, specifically the LoongArch 64-bit architecture implementation within the baseline compiler's liftoff tier.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The file is named `liftoff-assembler`, which immediately suggests it's responsible for generating machine code instructions. The `loong64` part specifies the target architecture. The `.inl.h` suffix usually indicates inline implementations of methods declared in a corresponding `.h` file. `liftoff` refers to a specific compilation tier in V8.

2. **Scan for key functionalities:** Read through the provided code snippets and identify the different kinds of operations being performed. Look for function names and the operations they perform. Categories that stand out are:
    * Type conversions (integer to float, float to integer)
    * Sign extension
    * Control flow (jumps, conditional jumps)
    * Comparisons (integer and floating-point)
    * Conditional assignment (select)
    * Smi checks (related to V8's small integer representation)
    * SIMD (Single Instruction, Multiple Data) operations

3. **Group related functionalities:**  Organize the identified operations into logical groups. This makes the explanation clearer. For example, group all the different integer-to-float and float-to-integer conversion functions together. Similarly, group the different SIMD operations.

4. **Infer the overall role:** Based on the identified functionalities, deduce the high-level purpose of the file. It's about providing low-level assembly primitives for the Liftoff compiler to generate machine code.

5. **Address specific user questions:**
    * **`.tq` extension:** Explain that this file is `.h` and therefore not a Torque file.
    * **Relationship to JavaScript:** Since this is part of V8, it's inherently related to JavaScript. Explain that these assembly instructions are the underlying implementation of JavaScript operations. Provide simple JavaScript examples that would trigger some of the listed operations (type conversions, comparisons, etc.).
    * **Code logic and examples:** For specific code blocks, provide concrete input and output examples. Focus on the integer/float conversion sections as they are relatively straightforward. Explain the conditional branching logic.
    * **Common programming errors:**  Think about how the described functionalities could lead to errors. Type conversion issues (overflow, precision loss) are common. Incorrect conditional logic leading to unexpected branches is another.
    * **Summarize the functionality:**  Provide a concise summary of the file's purpose.

6. **Handle SIMD:** Notice the large number of `bailout(kSimd, ...)` calls. Explain that this indicates that SIMD operations are declared but not fully implemented in this specific file, likely relying on other parts of the V8 codebase.

7. **Structure the answer:** Organize the information logically with clear headings and bullet points for readability. Start with the core purpose and then delve into specifics.

8. **Refine and clarify:** Review the generated answer for clarity, accuracy, and completeness. Ensure that the examples are easy to understand and directly relate to the described functionality. For instance, initially, I might have just listed the SIMD operations. Refining it means explaining the `bailout` calls and their significance.

By following these steps, we can arrive at a comprehensive and informative answer that addresses all aspects of the user's request.
目录 `v8/src/wasm/baseline/loong64/liftoff-assembler-loong64-inl.h` 是 V8 JavaScript 引擎中针对 LoongArch 64 位架构的 Liftoff 编译器的汇编器内联实现头文件。

**功能归纳:**

这个头文件定义了 `LiftoffAssembler` 类的内联方法，这些方法封装了 LoongArch64 汇编指令，用于在 Liftoff 编译过程中生成机器码。 Liftoff 编译器是 V8 中用于 WebAssembly 的一个快速的基线编译器。

**具体功能列举:**

1. **浮点数和整数之间的转换 (Saturation):**
   - `emit_i32_convert_sat_f32`, `emit_i32_convert_sat_f64`: 将单精度和双精度浮点数转换为有符号 32 位整数，如果超出范围则饱和到最小值或最大值。
   - `emit_i32_uconvert_sat_f32`, `emit_i32_uconvert_sat_f64`: 将单精度和双精度浮点数转换为无符号 32 位整数，如果超出范围则饱和到 0。
   - `emit_i64_convert_sat_f32`, `emit_i64_convert_sat_f64`: 将单精度和双精度浮点数转换为有符号 64 位整数，如果超出范围则饱和到最小值或最大值。
   - `emit_i64_uconvert_sat_f32`, `emit_i64_uconvert_sat_f64`: 将单精度和双精度浮点数转换为无符号 64 位整数，如果超出范围则饱和到 0。
   - 这些操作都使用了 LoongArch64 特定的指令 `ftintrz_w_s`, `ftintrz_uw_s`, `ftintrz_w_d`, `ftintrz_uw_d`, `ftintrz_l_s`, `ftintrz_ul_s`, `ftintrz_l_d`, `ftintrz_ul_d` 来进行截断转换。 饱和处理通过比较和条件跳转实现。

2. **符号扩展:**
   - `emit_i32_signextend_i8`, `emit_i32_signextend_i16`: 将 8 位或 16 位有符号整数扩展为 32 位有符号整数。
   - `emit_i64_signextend_i8`, `emit_i64_signextend_i16`, `emit_i64_signextend_i32`: 将 8 位、16 位或 32 位有符号整数扩展为 64 位有符号整数。
   - 使用了 LoongArch64 的 `ext_w_b` 和 `ext_w_h` 指令。

3. **跳转指令:**
   - `emit_jump(Label* label)`: 无条件跳转到指定标签。
   - `emit_jump(Register target)`:  跳转到寄存器中存储的地址。
   - `emit_cond_jump`: 根据条件跳转到指定标签，支持比较整数和引用类型。
   - `emit_i32_cond_jumpi`, `emit_ptrsize_cond_jumpi`: 根据条件跳转，比较 32 位整数或指针大小的值与立即数。

4. **条件设置指令:**
   - `emit_i32_eqz`:  如果 32 位寄存器为零，则将目标寄存器设置为 1，否则设置为 0。
   - `emit_i32_set_cond`:  根据条件比较两个 32 位寄存器，并将结果 (0 或 1) 存储到目标寄存器。
   - `emit_i64_eqz`:  如果 64 位寄存器为零，则将目标寄存器设置为 1，否则设置为 0。
   - `emit_i64_set_cond`:  根据条件比较两个 64 位寄存器，并将结果 (0 或 1) 存储到目标寄存器。

5. **浮点数条件设置指令:**
   - `emit_f32_set_cond`, `emit_f64_set_cond`: 根据条件比较两个单精度或双精度浮点数，并将结果 (0 或 1) 存储到目标寄存器。 特别处理了 NaN 的情况。

6. **选择指令 (select):**
   - `emit_select`:  根据条件选择两个寄存器中的一个值，但当前实现返回 `false`，表示未实现。

7. **Smi 检查:**
   - `emit_smi_check`:  检查寄存器中的值是否为 Smi (Small Integer)，并根据结果跳转。

8. **SIMD 指令:**
   - 包含了大量的 `bailout(kSimd, ...)` 调用，这表明该文件中声明了许多 SIMD (Single Instruction, Multiple Data) 操作的接口，但 **当前提供的代码片段中，这些 SIMD 指令的实现被标记为 "unimplemented" 或 "bailout"**。 这意味着这些操作可能在其他 V8 代码文件中实现，或者在 Liftoff 编译器中尚未完全支持。 涉及的 SIMD 操作包括加载、存储、shuffle、swizzle、算术运算、比较运算等，涵盖了 `i8x16`, `i16x8`, `i32x4`, `i64x2`, `f32x4`, `f64x2` 等不同的 SIMD 数据类型。

**关于 `.tq` 结尾:**

`v8/src/wasm/baseline/loong64/liftoff-assembler-loong64-inl.h`  以 `.h` 结尾，所以它是一个 **C++ 头文件**，而不是 V8 Torque 源代码。 Torque 文件的扩展名是 `.tq`。

**与 JavaScript 的关系:**

这个文件是 V8 引擎的一部分，因此与 JavaScript 的执行息息相关。当 JavaScript 代码中涉及到 WebAssembly 模块的执行时，V8 会使用 Liftoff 编译器将 WebAssembly 的字节码快速地编译成机器码。 `liftoff-assembler-loong64-inl.h` 中定义的汇编指令生成函数正是这个编译过程中的核心部分，它们负责生成能够在 LoongArch64 架构上运行的本地机器码。

**JavaScript 例子:**

虽然这个文件本身是 C++ 代码，但它最终会影响 JavaScript 的执行。 例如，WebAssembly 中的一个将浮点数转换为整数的操作，最终可能会由 `emit_i32_convert_sat_f32` 或类似的函数生成 LoongArch64 汇编指令来执行。

```javascript
// JavaScript 代码调用 WebAssembly 模块
async function runWasm() {
  const response = await fetch('my_wasm_module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  // 假设 WebAssembly 模块中有一个函数 convertFloatToInt
  const floatValue = 3.14;
  const intResult = instance.exports.convertFloatToInt(floatValue);
  console.log(intResult); // 输出可能是 3
}

runWasm();
```

在上面的例子中，如果 `convertFloatToInt` 函数的 WebAssembly 代码执行了一个浮点数到整数的转换，那么 Liftoff 编译器在编译这个 WebAssembly 模块时，可能会使用 `emit_i32_convert_sat_f32` (或其他类似的转换函数) 生成相应的 LoongArch64 汇编代码来完成这个转换操作。

**代码逻辑推理 (假设输入与输出):**

以 `emit_i32_convert_sat_f32` 为例：

**假设输入:**

- `src.fp()`: 一个包含浮点数值 `3.7` 的浮点寄存器。
- `dst.gp()`: 一个用于存储结果的通用寄存器。

**代码逻辑:**

1. 将浮点数与 `0.0` 进行比较 (CULE - 小于等于无符号)。
2. 如果浮点数小于等于 0，则跳转到 `isnan_or_lessthan_or_equal_zero` 标签。
3. 否则，使用 `Ftintrz_uw_s` 指令将浮点数截断转换为无符号 32 位整数，结果存储在 `dst.gp()` 中。
4. `isnan_or_lessthan_or_equal_zero` 标签目前是空的，所以会直接返回 `true`。  (注意：这部分代码可能需要结合上下文来理解完整的饱和逻辑，因为这里只处理了小于等于 0 的情况)

**可能的输出:**

- `dst.gp()` 中的值为 `3` (浮点数 `3.7` 被截断为整数)。

以 `emit_i32_uconvert_sat_f64` 为例：

**假设输入:**

- `src.fp()`: 一个包含浮点数值 `-1.5` 的浮点寄存器。
- `dst.gp()`: 一个用于存储结果的通用寄存器。

**代码逻辑:**

1. 将 `dst.gp()` 初始化为 `0`。
2. 将浮点寄存器 `kScratchDoubleReg` 设置为 `0.0`。
3. 将输入浮点数与 `0.0` 进行比较 (CULE - 小于等于无符号)。
4. 由于 `-1.5` 小于 `0.0`，条件成立，跳转到 `isnan_or_lessthan_or_equal_zero` 标签。
5. 在 `isnan_or_lessthan_or_equal_zero` 标签处，程序返回 `true`。

**可能的输出:**

- `dst.gp()` 中的值为 `0` (由于输入为负数，无符号转换饱和到 0)。

**用户常见的编程错误 (与转换相关):**

1. **浮点数到整数转换时的精度丢失:**

   ```javascript
   const floatValue = 3.999999;
   const intValue = parseInt(floatValue); // intValue 将是 3，丢失了小数部分
   ```

   在 WebAssembly 中，如果使用不带饱和的转换，超出范围的浮点数转换为整数可能会导致未定义的行为或截断到意外的值。 Liftoff 提供的饱和转换在超出范围时会提供更可预测的结果。

2. **将大浮点数转换为小整数类型时的溢出:**

   ```javascript
   const largeFloat = 2**32 + 10;
   const wasmMemory = new WebAssembly.Memory({ initial: 1 });
   const wasmModule = new WebAssembly.Module(Uint8Array.from([
       // ... (Wasm 代码，包含将浮点数转换为 i32 的操作)
   ]));
   const wasmInstance = new WebAssembly.Instance(wasmModule, { mem: wasmMemory });
   // 假设 wasmInstance.exports.convert(largeFloat) 将浮点数转换为 i32
   const intResult = wasmInstance.exports.convert(largeFloat);
   // intResult 的值取决于 Wasm 代码的具体实现，可能是一个被截断或溢出的值
   ```

   如果 WebAssembly 代码中使用了 `i32.trunc_sat_f64_s` 这样的指令，那么 `emit_i32_convert_sat_f64` 这样的函数生成的代码会确保结果饱和到 i32 的最小值或最大值，避免不可预测的行为。

**总结 (第 3 部分功能):**

这部分代码主要定义了 `LiftoffAssembler` 类中用于执行以下操作的内联方法：

- 将浮点数安全地转换为有符号和无符号的 32 位和 64 位整数，处理溢出和下溢通过饱和操作。
- 执行基本的符号扩展操作，将较小的整数类型扩展到较大的整数类型。
- 提供基本的控制流指令，如无条件跳转和条件跳转。
- 实现基于条件的寄存器值设置。
- 处理浮点数的条件比较和结果设置，并考虑了 NaN 的特殊情况。
- 声明了大量的 SIMD 操作接口，但当前代码片段中这些操作的实现是占位符或未实现。

总而言之，这部分代码是 Liftoff 编译器生成 LoongArch64 架构机器码的关键组成部分，专注于数值类型转换、基本控制流和条件操作。

Prompt: 
```
这是目录为v8/src/wasm/baseline/loong64/liftoff-assembler-loong64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/loong64/liftoff-assembler-loong64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
(src.fp(), kScratchDoubleReg, CULE);
      BranchTrueShortF(&isnan_or_lessthan_or_equal_zero);
      Ftintrz_uw_s(dst.gp(), src.fp(), kScratchDoubleReg);
      bind(&isnan_or_lessthan_or_equal_zero);
      return true;
    }
    case kExprI32SConvertSatF64:
      ftintrz_w_d(kScratchDoubleReg, src.fp());
      movfr2gr_s(dst.gp(), kScratchDoubleReg);
      return true;
    case kExprI32UConvertSatF64: {
      Label isnan_or_lessthan_or_equal_zero;
      mov(dst.gp(), zero_reg);
      MacroAssembler::Move(kScratchDoubleReg, static_cast<double>(0.0));
      CompareF64(src.fp(), kScratchDoubleReg, CULE);
      BranchTrueShortF(&isnan_or_lessthan_or_equal_zero);
      Ftintrz_uw_d(dst.gp(), src.fp(), kScratchDoubleReg);
      bind(&isnan_or_lessthan_or_equal_zero);
      return true;
    }
    case kExprI64SConvertSatF32:
      ftintrz_l_s(kScratchDoubleReg, src.fp());
      movfr2gr_d(dst.gp(), kScratchDoubleReg);
      return true;
    case kExprI64UConvertSatF32: {
      Label isnan_or_lessthan_or_equal_zero;
      mov(dst.gp(), zero_reg);
      MacroAssembler::Move(kScratchDoubleReg, static_cast<float>(0.0));
      CompareF32(src.fp(), kScratchDoubleReg, CULE);
      BranchTrueShortF(&isnan_or_lessthan_or_equal_zero);
      Ftintrz_ul_s(dst.gp(), src.fp(), kScratchDoubleReg);
      bind(&isnan_or_lessthan_or_equal_zero);
      return true;
    }
    case kExprI64SConvertSatF64:
      ftintrz_l_d(kScratchDoubleReg, src.fp());
      movfr2gr_d(dst.gp(), kScratchDoubleReg);
      return true;
    case kExprI64UConvertSatF64: {
      Label isnan_or_lessthan_or_equal_zero;
      mov(dst.gp(), zero_reg);
      MacroAssembler::Move(kScratchDoubleReg, static_cast<double>(0.0));
      CompareF64(src.fp(), kScratchDoubleReg, CULE);
      BranchTrueShortF(&isnan_or_lessthan_or_equal_zero);
      Ftintrz_ul_d(dst.gp(), src.fp(), kScratchDoubleReg);
      bind(&isnan_or_lessthan_or_equal_zero);
      return true;
    }
    default:
      return false;
  }
}

void LiftoffAssembler::emit_i32_signextend_i8(Register dst, Register src) {
  ext_w_b(dst, src);
}

void LiftoffAssembler::emit_i32_signextend_i16(Register dst, Register src) {
  ext_w_h(dst, src);
}

void LiftoffAssembler::emit_i64_signextend_i8(LiftoffRegister dst,
                                              LiftoffRegister src) {
  ext_w_b(dst.gp(), src.gp());
}

void LiftoffAssembler::emit_i64_signextend_i16(LiftoffRegister dst,
                                               LiftoffRegister src) {
  ext_w_h(dst.gp(), src.gp());
}

void LiftoffAssembler::emit_i64_signextend_i32(LiftoffRegister dst,
                                               LiftoffRegister src) {
  slli_w(dst.gp(), src.gp(), 0);
}

void LiftoffAssembler::emit_jump(Label* label) {
  MacroAssembler::Branch(label);
}

void LiftoffAssembler::emit_jump(Register target) {
  MacroAssembler::Jump(target);
}

void LiftoffAssembler::emit_cond_jump(Condition cond, Label* label,
                                      ValueKind kind, Register lhs,
                                      Register rhs,
                                      const FreezeCacheState& frozen) {
  if (rhs == no_reg) {
    if (kind == kI32) {
      UseScratchRegisterScope temps(this);
      Register scratch0 = temps.Acquire();
      slli_w(scratch0, lhs, 0);
      MacroAssembler::Branch(label, cond, scratch0, Operand(zero_reg));
    } else {
      DCHECK(kind == kI64);
      MacroAssembler::Branch(label, cond, lhs, Operand(zero_reg));
    }
  } else {
    if (kind == kI64) {
      MacroAssembler::Branch(label, cond, lhs, Operand(rhs));
    } else {
      DCHECK((kind == kI32) || (kind == kRtt) || (kind == kRef) ||
             (kind == kRefNull));
      MacroAssembler::CompareTaggedAndBranch(label, cond, lhs, Operand(rhs));
    }
  }
}

void LiftoffAssembler::emit_i32_cond_jumpi(Condition cond, Label* label,
                                           Register lhs, int32_t imm,
                                           const FreezeCacheState& frozen) {
  MacroAssembler::CompareTaggedAndBranch(label, cond, lhs, Operand(imm));
}

void LiftoffAssembler::emit_ptrsize_cond_jumpi(Condition cond, Label* label,
                                               Register lhs, int32_t imm,
                                               const FreezeCacheState& frozen) {
  MacroAssembler::Branch(label, cond, lhs, Operand(imm));
}

void LiftoffAssembler::emit_i32_eqz(Register dst, Register src) {
  slli_w(dst, src, 0);
  sltui(dst, dst, 1);
}

void LiftoffAssembler::emit_i32_set_cond(Condition cond, Register dst,
                                         Register lhs, Register rhs) {
  UseScratchRegisterScope temps(this);
  Register scratch0 = temps.Acquire();
  Register scratch1 = kScratchReg;

  slli_w(scratch0, lhs, 0);
  slli_w(scratch1, rhs, 0);

  CompareWord(cond, dst, scratch0, Operand(scratch1));
}

void LiftoffAssembler::emit_i64_eqz(Register dst, LiftoffRegister src) {
  sltui(dst, src.gp(), 1);
}

void LiftoffAssembler::emit_i64_set_cond(Condition cond, Register dst,
                                         LiftoffRegister lhs,
                                         LiftoffRegister rhs) {
  CompareWord(cond, dst, lhs.gp(), Operand(rhs.gp()));
}

namespace liftoff {

inline FPUCondition ConditionToConditionCmpFPU(Condition condition,
                                               bool* predicate) {
  switch (condition) {
    case kEqual:
      *predicate = true;
      return CEQ;
    case kNotEqual:
      *predicate = false;
      return CEQ;
    case kUnsignedLessThan:
      *predicate = true;
      return CLT;
    case kUnsignedGreaterThanEqual:
      *predicate = false;
      return CLT;
    case kUnsignedLessThanEqual:
      *predicate = true;
      return CLE;
    case kUnsignedGreaterThan:
      *predicate = false;
      return CLE;
    default:
      *predicate = true;
      break;
  }
  UNREACHABLE();
}

}  // namespace liftoff

void LiftoffAssembler::emit_f32_set_cond(Condition cond, Register dst,
                                         DoubleRegister lhs,
                                         DoubleRegister rhs) {
  Label not_nan, cont;
  MacroAssembler::CompareIsNanF32(lhs, rhs);
  MacroAssembler::BranchFalseF(&not_nan);
  // If one of the operands is NaN, return 1 for f32.ne, else 0.
  if (cond == ne) {
    MacroAssembler::li(dst, 1);
  } else {
    MacroAssembler::Move(dst, zero_reg);
  }
  MacroAssembler::Branch(&cont);

  bind(&not_nan);

  MacroAssembler::li(dst, 1);
  bool predicate;
  FPUCondition fcond = liftoff::ConditionToConditionCmpFPU(cond, &predicate);
  MacroAssembler::CompareF32(lhs, rhs, fcond);
  if (predicate) {
    MacroAssembler::LoadZeroIfNotFPUCondition(dst);
  } else {
    MacroAssembler::LoadZeroIfFPUCondition(dst);
  }

  bind(&cont);
}

void LiftoffAssembler::emit_f64_set_cond(Condition cond, Register dst,
                                         DoubleRegister lhs,
                                         DoubleRegister rhs) {
  Label not_nan, cont;
  MacroAssembler::CompareIsNanF64(lhs, rhs);
  MacroAssembler::BranchFalseF(&not_nan);
  // If one of the operands is NaN, return 1 for f64.ne, else 0.
  if (cond == ne) {
    MacroAssembler::li(dst, 1);
  } else {
    MacroAssembler::Move(dst, zero_reg);
  }
  MacroAssembler::Branch(&cont);

  bind(&not_nan);

  MacroAssembler::li(dst, 1);
  bool predicate;
  FPUCondition fcond = liftoff::ConditionToConditionCmpFPU(cond, &predicate);
  MacroAssembler::CompareF64(lhs, rhs, fcond);
  if (predicate) {
    MacroAssembler::LoadZeroIfNotFPUCondition(dst);
  } else {
    MacroAssembler::LoadZeroIfFPUCondition(dst);
  }

  bind(&cont);
}

bool LiftoffAssembler::emit_select(LiftoffRegister dst, Register condition,
                                   LiftoffRegister true_value,
                                   LiftoffRegister false_value,
                                   ValueKind kind) {
  return false;
}

void LiftoffAssembler::emit_smi_check(Register obj, Label* target,
                                      SmiCheckMode mode,
                                      const FreezeCacheState& frozen) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  And(scratch, obj, Operand(kSmiTagMask));
  Condition condition = mode == kJumpOnSmi ? eq : ne;
  Branch(target, condition, scratch, Operand(zero_reg));
}

void LiftoffAssembler::LoadTransform(LiftoffRegister dst, Register src_addr,
                                     Register offset_reg, uintptr_t offset_imm,
                                     LoadType type,
                                     LoadTransformationKind transform,
                                     uint32_t* protected_load_pc) {
  bailout(kSimd, "load extend and load splat unimplemented");
}

void LiftoffAssembler::LoadLane(LiftoffRegister dst, LiftoffRegister src,
                                Register addr, Register offset_reg,
                                uintptr_t offset_imm, LoadType type,
                                uint8_t laneidx, uint32_t* protected_load_pc,
                                bool i64_offset) {
  bailout(kSimd, "loadlane");
}

void LiftoffAssembler::StoreLane(Register dst, Register offset,
                                 uintptr_t offset_imm, LiftoffRegister src,
                                 StoreType type, uint8_t lane,
                                 uint32_t* protected_store_pc,
                                 bool i64_offset) {
  bailout(kSimd, "storelane");
}

void LiftoffAssembler::emit_i8x16_shuffle(LiftoffRegister dst,
                                          LiftoffRegister lhs,
                                          LiftoffRegister rhs,
                                          const uint8_t shuffle[16],
                                          bool is_swizzle) {
  bailout(kSimd, "emit_i8x16_shuffle");
}

void LiftoffAssembler::emit_i8x16_swizzle(LiftoffRegister dst,
                                          LiftoffRegister lhs,
                                          LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_swizzle");
}

void LiftoffAssembler::emit_i8x16_relaxed_swizzle(LiftoffRegister dst,
                                                  LiftoffRegister lhs,
                                                  LiftoffRegister rhs) {
  bailout(kRelaxedSimd, "emit_i8x16_relaxed_swizzle");
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f32x4_s(LiftoffRegister dst,
                                                        LiftoffRegister src) {
  bailout(kRelaxedSimd, "emit_i32x4_relaxed_trunc_f32x4_s");
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f32x4_u(LiftoffRegister dst,
                                                        LiftoffRegister src) {
  bailout(kRelaxedSimd, "emit_i32x4_relaxed_trunc_f32x4_u");
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f64x2_s_zero(
    LiftoffRegister dst, LiftoffRegister src) {
  bailout(kRelaxedSimd, "emit_i32x4_relaxed_trunc_f64x2_s_zero");
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f64x2_u_zero(
    LiftoffRegister dst, LiftoffRegister src) {
  bailout(kRelaxedSimd, "emit_i32x4_relaxed_trunc_f64x2_u_zero");
}

void LiftoffAssembler::emit_s128_relaxed_laneselect(LiftoffRegister dst,
                                                    LiftoffRegister src1,
                                                    LiftoffRegister src2,
                                                    LiftoffRegister mask,
                                                    int lane_width) {
  bailout(kRelaxedSimd, "emit_s128_relaxed_laneselect");
}

void LiftoffAssembler::emit_i8x16_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  bailout(kSimd, "emit_i8x16_splat");
}

void LiftoffAssembler::emit_i16x8_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  bailout(kSimd, "emit_i16x8_splat");
}

void LiftoffAssembler::emit_i32x4_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  bailout(kSimd, "emit_i32x4_splat");
}

void LiftoffAssembler::emit_i64x2_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  bailout(kSimd, "emit_i64x2_splat");
}

void LiftoffAssembler::emit_f32x4_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  bailout(kSimd, "emit_f32x4_splat");
}

void LiftoffAssembler::emit_f64x2_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  bailout(kSimd, "emit_f64x2_splat");
}

#define SIMD_BINOP(name1, name2)                                         \
  void LiftoffAssembler::emit_##name1##_extmul_low_##name2(              \
      LiftoffRegister dst, LiftoffRegister src1, LiftoffRegister src2) { \
    bailout(kSimd, "emit_" #name1 "_extmul_low_" #name2);                \
  }                                                                      \
  void LiftoffAssembler::emit_##name1##_extmul_high_##name2(             \
      LiftoffRegister dst, LiftoffRegister src1, LiftoffRegister src2) { \
    bailout(kSimd, "emit_" #name1 "_extmul_high_" #name2);               \
  }

SIMD_BINOP(i16x8, i8x16_s)
SIMD_BINOP(i16x8, i8x16_u)

SIMD_BINOP(i32x4, i16x8_s)
SIMD_BINOP(i32x4, i16x8_u)

SIMD_BINOP(i64x2, i32x4_s)
SIMD_BINOP(i64x2, i32x4_u)

#undef SIMD_BINOP

#define SIMD_BINOP(name1, name2)                                 \
  void LiftoffAssembler::emit_##name1##_extadd_pairwise_##name2( \
      LiftoffRegister dst, LiftoffRegister src) {                \
    bailout(kSimd, "emit_" #name1 "_extadd_pairwise_" #name2);   \
  }

SIMD_BINOP(i16x8, i8x16_s)
SIMD_BINOP(i16x8, i8x16_u)
SIMD_BINOP(i32x4, i16x8_s)
SIMD_BINOP(i32x4, i16x8_u)
#undef SIMD_BINOP

void LiftoffAssembler::emit_i16x8_q15mulr_sat_s(LiftoffRegister dst,
                                                LiftoffRegister src1,
                                                LiftoffRegister src2) {
  bailout(kSimd, "emit_i16x8_q15mulr_sat_s");
}

void LiftoffAssembler::emit_i16x8_relaxed_q15mulr_s(LiftoffRegister dst,
                                                    LiftoffRegister src1,
                                                    LiftoffRegister src2) {
  bailout(kRelaxedSimd, "emit_i16x8_relaxed_q15mulr_s");
}

void LiftoffAssembler::emit_i16x8_dot_i8x16_i7x16_s(LiftoffRegister dst,
                                                    LiftoffRegister lhs,
                                                    LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_dot_i8x16_i7x16_s");
}

void LiftoffAssembler::emit_i32x4_dot_i8x16_i7x16_add_s(LiftoffRegister dst,
                                                        LiftoffRegister lhs,
                                                        LiftoffRegister rhs,
                                                        LiftoffRegister acc) {
  bailout(kSimd, "emit_i32x4_dot_i8x16_i7x16_add_s");
}

void LiftoffAssembler::emit_i8x16_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_eq");
}

void LiftoffAssembler::emit_i8x16_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_ne");
}

void LiftoffAssembler::emit_i8x16_gt_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_gt_s");
}

void LiftoffAssembler::emit_i8x16_gt_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_gt_u");
}

void LiftoffAssembler::emit_i8x16_ge_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_ge_s");
}

void LiftoffAssembler::emit_i8x16_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_ge_u");
}

void LiftoffAssembler::emit_i16x8_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_eq");
}

void LiftoffAssembler::emit_i16x8_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_ne");
}

void LiftoffAssembler::emit_i16x8_gt_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_gt_s");
}

void LiftoffAssembler::emit_i16x8_gt_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_gt_u");
}

void LiftoffAssembler::emit_i16x8_ge_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_ge_s");
}

void LiftoffAssembler::emit_i16x8_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_ge_u");
}

void LiftoffAssembler::emit_i32x4_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  bailout(kSimd, "emit_i32x4_eq");
}

void LiftoffAssembler::emit_i32x4_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  bailout(kSimd, "emit_i32x4_ne");
}

void LiftoffAssembler::emit_i32x4_gt_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  bailout(kSimd, "emit_i32x4_gt_s");
}

void LiftoffAssembler::emit_i32x4_gt_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  bailout(kSimd, "emit_i32x4_gt_u");
}

void LiftoffAssembler::emit_i32x4_ge_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  bailout(kSimd, "emit_i32x4_ge_s");
}

void LiftoffAssembler::emit_i32x4_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  bailout(kSimd, "emit_i32x4_ge_u");
}

void LiftoffAssembler::emit_f32x4_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  bailout(kSimd, "emit_f32x4_eq");
}

void LiftoffAssembler::emit_f32x4_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  bailout(kSimd, "emit_f32x4_ne");
}

void LiftoffAssembler::emit_f32x4_lt(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  bailout(kSimd, "emit_f32x4_lt");
}

void LiftoffAssembler::emit_f32x4_le(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  bailout(kSimd, "emit_f32x4_le");
}

void LiftoffAssembler::emit_i64x2_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  bailout(kSimd, "emit_i64x2_eq");
}

void LiftoffAssembler::emit_i64x2_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  bailout(kSimd, "emit_i64x2_ne");
}

void LiftoffAssembler::emit_i64x2_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  bailout(kSimd, "emit_i64x2_abs");
}

void LiftoffAssembler::emit_f64x2_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  bailout(kSimd, "emit_f64x2_eq");
}

void LiftoffAssembler::emit_f64x2_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  bailout(kSimd, "emit_f64x2_ne");
}

void LiftoffAssembler::emit_f64x2_lt(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  bailout(kSimd, "emit_f64x2_lt");
}

void LiftoffAssembler::emit_f64x2_le(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  bailout(kSimd, "emit_f64x2_le");
}

void LiftoffAssembler::emit_s128_const(LiftoffRegister dst,
                                       const uint8_t imms[16]) {
  bailout(kSimd, "emit_s128_const");
}

void LiftoffAssembler::emit_s128_not(LiftoffRegister dst, LiftoffRegister src) {
  bailout(kSimd, "emit_s128_not");
}

void LiftoffAssembler::emit_s128_and(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  bailout(kSimd, "emit_s128_and");
}

void LiftoffAssembler::emit_s128_or(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  bailout(kSimd, "emit_s128_or");
}

void LiftoffAssembler::emit_s128_xor(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  bailout(kSimd, "emit_s128_xor");
}

void LiftoffAssembler::emit_s128_and_not(LiftoffRegister dst,
                                         LiftoffRegister lhs,
                                         LiftoffRegister rhs) {
  bailout(kSimd, "emit_s128_and_not");
}

void LiftoffAssembler::emit_s128_select(LiftoffRegister dst,
                                        LiftoffRegister src1,
                                        LiftoffRegister src2,
                                        LiftoffRegister mask) {
  bailout(kSimd, "emit_s128_select");
}

void LiftoffAssembler::emit_i8x16_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  bailout(kSimd, "emit_i8x16_neg");
}

void LiftoffAssembler::emit_v128_anytrue(LiftoffRegister dst,
                                         LiftoffRegister src) {
  bailout(kSimd, "emit_v128_anytrue");
}

void LiftoffAssembler::emit_i8x16_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  bailout(kSimd, "emit_i8x16_alltrue");
}

void LiftoffAssembler::emit_i8x16_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  bailout(kSimd, "emit_i8x16_bitmask");
}

void LiftoffAssembler::emit_i8x16_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_shl");
}

void LiftoffAssembler::emit_i8x16_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  bailout(kSimd, "emit_i8x16_shli");
}

void LiftoffAssembler::emit_i8x16_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_shr_s");
}

void LiftoffAssembler::emit_i8x16_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  bailout(kSimd, "emit_i8x16_shri_s");
}

void LiftoffAssembler::emit_i8x16_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_shr_u");
}

void LiftoffAssembler::emit_i8x16_shri_u(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  bailout(kSimd, "emit_i8x16_shri_u");
}

void LiftoffAssembler::emit_i8x16_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_add");
}

void LiftoffAssembler::emit_i8x16_add_sat_s(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_add_sat_s");
}

void LiftoffAssembler::emit_i8x16_add_sat_u(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_add_sat_u");
}

void LiftoffAssembler::emit_i8x16_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_sub");
}

void LiftoffAssembler::emit_i8x16_sub_sat_s(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_sub_sat_s");
}

void LiftoffAssembler::emit_i8x16_sub_sat_u(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_sub_sat_u");
}

void LiftoffAssembler::emit_i8x16_min_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_min_s");
}

void LiftoffAssembler::emit_i8x16_min_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_min_u");
}

void LiftoffAssembler::emit_i8x16_max_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_max_s");
}

void LiftoffAssembler::emit_i8x16_max_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  bailout(kSimd, "emit_i8x16_max_u");
}

void LiftoffAssembler::emit_i8x16_popcnt(LiftoffRegister dst,
                                         LiftoffRegister src) {
  bailout(kSimd, "emit_i8x16_popcnt");
}

void LiftoffAssembler::emit_i16x8_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  bailout(kSimd, "emit_i16x8_neg");
}

void LiftoffAssembler::emit_i16x8_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  bailout(kSimd, "emit_i16x8_alltrue");
}

void LiftoffAssembler::emit_i16x8_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  bailout(kSimd, "emit_i16x8_bitmask");
}

void LiftoffAssembler::emit_i16x8_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_shl");
}

void LiftoffAssembler::emit_i16x8_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  bailout(kSimd, "emit_i16x8_shli");
}

void LiftoffAssembler::emit_i16x8_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_shr_s");
}

void LiftoffAssembler::emit_i16x8_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  bailout(kSimd, "emit_i16x8_shri_s");
}

void LiftoffAssembler::emit_i16x8_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_shr_u");
}

void LiftoffAssembler::emit_i16x8_shri_u(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  bailout(kSimd, "emit_i16x8_shri_u");
}

void LiftoffAssembler::emit_i16x8_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_add");
}

void LiftoffAssembler::emit_i16x8_add_sat_s(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_add_sat_s");
}

void LiftoffAssembler::emit_i16x8_add_sat_u(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_add_sat_u");
}

void LiftoffAssembler::emit_i16x8_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_sub");
}

void LiftoffAssembler::emit_i16x8_sub_sat_s(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_sub_sat_s");
}

void LiftoffAssembler::emit_i16x8_sub_sat_u(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_sub_sat_u");
}

void LiftoffAssembler::emit_i16x8_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_mul");
}

void LiftoffAssembler::emit_i16x8_min_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_min_s");
}

void LiftoffAssembler::emit_i16x8_min_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_min_u");
}

void LiftoffAssembler::emit_i16x8_max_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_max_s");
}

void LiftoffAssembler::emit_i16x8_max_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_max_u");
}

void LiftoffAssembler::emit_i32x4_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  bailout(kSimd, "emit_i32x4_neg");
}

void LiftoffAssembler::emit_i32x4_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  bailout(kSimd, "emit_i32x4_alltrue");
}

void LiftoffAssembler::emit_i32x4_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  bailout(kSimd, "emit_i32x4_bitmask");
}

void LiftoffAssembler::emit_i32x4_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  bailout(kSimd, "emit_i32x4_shl");
}

void LiftoffAssembler::emit_i32x4_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  bailout(kSimd, "emit_i32x4_shli");
}

void LiftoffAssembler::emit_i32x4_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  bailout(kSimd, "emit_i32x4_shr_s");
}

void LiftoffAssembler::emit_i32x4_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  bailout(kSimd, "emit_i32x4_shri_s");
}

void LiftoffAssembler::emit_i32x4_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  bailout(kSimd, "emit_i32x4_shr_u");
}

void LiftoffAssembler::emit_i32x4_shri_u(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  bailout(kSimd, "emit_i32x4_shri_u");
}

void LiftoffAssembler::emit_i32x4_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  bailout(kSimd, "emit_i32x4_add");
}

void LiftoffAssembler::emit_i32x4_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  bailout(kSimd, "emit_i32x4_sub");
}

void LiftoffAssembler::emit_i32x4_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  bailout(kSimd, "emit_i32x4_mul");
}

void LiftoffAssembler::emit_i32x4_min_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  bailout(kSimd, "emit_i32x4_min_s");
}

void LiftoffAssembler::emit_i32x4_min_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  bailout(kSimd, "emit_i32x4_min_u");
}

void LiftoffAssembler::emit_i32x4_max_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  bailout(kSimd, "emit_i32x4_max_s");
}

void LiftoffAssembler::emit_i32x4_max_u(LiftoffRegister dst,
                                        Liftoff
"""


```