Response:
The user wants a summary of the provided C++ code snippet from V8.
The code defines a part of the `LiftoffAssembler` class for the s390 architecture, specifically focusing on handling different WebAssembly instructions.

Here's a breakdown of the request and how to address it:

1. **List the functionalities:**  The code primarily deals with emitting machine code for various WebAssembly operations, mainly related to type conversions, comparisons, conditional jumps, and SIMD operations.

2. **.tq extension:** Check if the filename ends with `.tq`. It doesn't. Therefore, it's not a Torque file.

3. **Relationship with Javascript:**  WebAssembly is designed to be a compilation target for languages like C++, Rust, and can be executed in Javascript environments. The code here helps V8 execute WebAssembly code efficiently. I need to provide a Javascript example where these WebAssembly operations might be involved.

4. **Code Logic Inference:** Choose a simple code block and trace its execution with example inputs and outputs. The integer-to-float conversions seem suitable.

5. **Common Programming Errors:** Identify potential pitfalls that arise from the operations described in the code, especially around type conversions and comparisons.

6. **Overall Functionality (Part 3 of 4):**  Synthesize the functionalities described in this specific part of the code snippet, keeping in mind it's a part of a larger system. This part seems heavily focused on conversions between integer and floating-point types and basic control flow.

**Mental Sandbox:**

* **Functionalities:**  I'll group the functionalities by the WebAssembly instruction they handle (e.g., `kExprI32SConvertSatF32`).
* **Javascript Example:** I can show a simple WebAssembly module in Javascript that uses type conversions.
* **Code Logic:**  Let's pick `kExprI32SConvertSatF32`. If the float is NaN, it outputs 0. Otherwise, it converts to an integer, rounding towards zero.
* **Programming Errors:**  Integer overflow during float-to-int conversion is a good example. Incorrectly comparing signed and unsigned values is another.
* **Part 3 Summary:** This section seems to cover type conversions (especially float/int), conditional branching, and some SIMD operations. It's a continuation of the assembler's instruction handling logic.
这是V8源代码文件 `v8/src/wasm/baseline/s390/liftoff-assembler-s390-inl.h` 的第三部分，主要功能是为 WebAssembly 的 Liftoff 编译器在 s390 架构上生成机器码，特别是针对各种类型转换、比较操作、条件跳转以及 SIMD (Single Instruction, Multiple Data) 操作。

**功能列举:**

1. **类型转换指令生成:**
   - 将浮点数 (f32, f64) 转换为有符号和无符号 32 位整数 (i32)，并处理饱和转换 (超出范围则截断到最小值或最大值) 和 NaN (Not a Number) 值。
   - 将浮点数 (f32, f64) 转换为有符号和无符号 64 位整数 (i64)，同样处理饱和转换和 NaN 值。
   - 将整数 (i32, i64) 转换为浮点数 (f32, f64)。
   - 对浮点数和整数进行 reinterpret 转换 (按位重新解释)。
   - 在 f32 和 f64 之间进行转换。

2. **跳转指令生成:**
   - 生成无条件跳转 (`emit_jump`) 到指定标签或寄存器指向的地址。
   - 生成条件跳转 (`emit_cond_jump`)，根据比较结果跳转到指定标签。支持比较不同类型的寄存器 (i32, i64, ref)。
   - 生成基于立即数的条件跳转 (`emit_i32_cond_jumpi`, `emit_ptrsize_cond_jumpi`)。

3. **比较指令生成:**
   - 生成判断 i32 是否为零的指令 (`emit_i32_eqz`)。
   - 生成根据比较结果设置 i32 寄存器值的指令 (`emit_i32_set_cond`)。
   - 生成判断 i64 是否为零的指令 (`emit_i64_eqz`)。
   - 生成根据比较结果设置 i64 寄存器值的指令 (`emit_i64_set_cond`)。
   - 生成根据浮点数比较结果设置 i32 寄存器值的指令 (`emit_f32_set_cond`, `emit_f64_set_cond`)。

4. **其他算术指令生成:**
   - 生成 i64 乘以立即数的指令 (`emit_i64_muli`)，对 2 的幂次方进行了优化。
   - 生成 SMI (Small Integer) 检查指令 (`emit_smi_check`)，用于判断一个寄存器是否包含 SMI。

5. **SIMD 指令生成:**
   - 提供了大量 SIMD 指令的生成函数，涵盖了各种 SIMD 数据类型 (f64x2, f32x4, i64x2, i32x4, i16x8, i8x16, s128) 的加减乘除、比较、位运算、移位、绝对值、取反、平方根、舍入、类型转换、车道 (lane) 操作 (提取和替换)、扩展乘法、全真判断、饱和加减、成对加法、融合乘加/减 (QFM) 以及 relaxed SIMD 操作。
   -  定义了宏来简化生成这些 SIMD 指令的代码。

6. **内存加载指令生成:**
   - 提供了 `LoadTransform` 函数，用于加载内存数据并进行转换 (例如符号扩展)。

**关于 .tq 结尾:**

`v8/src/wasm/baseline/s390/liftoff-assembler-s390-inl.h` 没有以 `.tq` 结尾，所以它不是一个 V8 Torque 源代码文件。Torque 文件通常用于定义 V8 的内置函数和类型系统。

**与 Javascript 的功能关系:**

这段代码是 V8 引擎执行 WebAssembly 代码的关键部分。当 Javascript 执行一个 WebAssembly 模块时，V8 的 Liftoff 编译器会使用 `LiftoffAssembler` 类将 WebAssembly 指令转换为目标架构 (这里是 s390) 的机器码。

**Javascript 示例:**

```javascript
const buffer = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0,  // Magic number and version
  5, 131, 128, 128, 128, 0, 1, 104, 0, 1, 127, // Type section (function type)
  3, 130, 128, 128, 128, 0, 1, 0, // Function section (function 0)
  10, 138, 128, 128, 128, 0, 1, 65, 0, 171, 3, 11 // Code section (function 0 body)
]);
const module = new WebAssembly.Module(buffer);
const instance = new WebAssembly.Instance(module);

// 假设 WebAssembly 代码 (buffer) 中的函数 0 进行了以下操作:
// 1. 将浮点数 10.5 转换为有符号 32 位整数。
// 2. 将结果返回。

// 当执行 instance.exports.exported_function() 时，
// V8 的 Liftoff 编译器会使用类似这段 C++ 代码生成 s390 的机器码来完成浮点数到整数的转换。
// 具体来说，可能会用到 kExprI32SConvertSatF64 对应的代码逻辑。
```

在这个例子中，`buffer` 代表了一个简单的 WebAssembly 模块，其中可能包含将浮点数转换为整数的操作。当 Javascript 执行这个模块时，V8 会使用 `LiftoffAssembler` 中的代码来生成实际的机器指令来完成这个转换。

**代码逻辑推理:**

以 `kExprI32SConvertSatF32` 为例：

**假设输入:**

- `src.fp()` (源浮点寄存器) 包含浮点数 `10.75`。
- `dst.gp()` (目标通用寄存器) 将存储转换后的整数。

**执行流程:**

1. `lzer(kScratchDoubleReg);`: 将一个临时双精度寄存器清零。
2. `cebr(src.fp(), kScratchDoubleReg);`: 将源浮点数与 0.0 进行比较。
3. `b(Condition(1), &src_is_nan);`: 如果源是 NaN (无序比较结果)，则跳转到 `src_is_nan` 标签。在这个例子中，10.75 不是 NaN，所以不会跳转。
4. `ConvertFloat32ToInt32(dst.gp(), src.fp(), kRoundToZero);`: 调用函数将源浮点数转换为有符号 32 位整数，采用向零舍入。10.75 向零舍入为 10。
5. `b(&done);`: 跳转到 `done` 标签。
6. `bind(&src_is_nan);`: (如果之前跳转到这里) 将目标寄存器设置为 0 (处理 NaN 的情况)。
7. `bind(&done);`: 标记代码执行完成。

**输出:**

- `dst.gp()` 包含整数值 `10`。

**假设输入 (NaN 情况):**

- `src.fp()` 包含 NaN。
- `dst.gp()` 将存储转换后的整数。

**执行流程:**

1. `lzer(kScratchDoubleReg);`
2. `cebr(src.fp(), kScratchDoubleReg);`
3. `b(Condition(1), &src_is_nan);`: 因为源是 NaN，所以跳转到 `src_is_nan` 标签。
4. `bind(&src_is_nan);`:
5. `lghi(dst.gp(), Operand::Zero());`: 将目标寄存器设置为 0。
6. `bind(&done);`:

**输出:**

- `dst.gp()` 包含整数值 `0`。

**用户常见的编程错误:**

1. **浮点数到整数的转换未考虑 NaN:** 程序员可能没有意识到浮点数可能为 NaN，导致在转换为整数时出现未定义的行为或错误的结果。V8 的代码通过显式检查 NaN 并将其转换为 0 来处理这种情况。

   ```javascript
   // Javascript 示例
   let floatValue = NaN;
   let intValue = parseInt(floatValue); // 结果是 NaN，可能不是期望的行为

   // WebAssembly 中，V8 会确保 NaN 被合理处理，例如转换为 0
   ```

2. **浮点数到整数的饱和转换理解不足:** 程序员可能不清楚饱和转换的含义，即当浮点数超出整数范围时，结果会被截断到该范围的最大或最小值。

   ```javascript
   // Javascript 示例
   let largeFloat = 2**31; // 超过了有符号 32 位整数的最大值
   let intValue = largeFloat; // Javascript 的转换可能不会饱和，而是溢出或得到其他非预期结果

   // WebAssembly 的饱和转换会确保结果停留在整数范围内
   ```

3. **有符号和无符号比较混淆:** 在进行条件跳转时，使用错误的比较类型 (有符号或无符号) 会导致程序逻辑错误。这段代码中根据 `is_signed(cond)` 来选择 `CmpS32` 或 `CmpU32` 等指令，确保了比较的正确性。

   ```c++
   // C++ 示例
   int32_t a = -1;
   uint32_t b = 1;
   if (a > b) { // 有符号比较为 false
       // ...
   }
   if (static_cast<uint32_t>(a) > b) { // 无符号比较为 true
       // ...
   }
   ```

**归纳其功能 (作为第 3 部分):**

作为 `v8/src/wasm/baseline/s390/liftoff-assembler-s390-inl.h` 的第三部分，这段代码主要负责为 WebAssembly 的 Liftoff 编译器在 s390 架构上生成用于**数据类型转换** (特别是浮点数和整数之间的转换，以及 reinterpret 转换)、**控制流** (无条件和条件跳转) 以及各种 **SIMD 操作** 的机器码。它处理了类型转换的边界情况，例如 NaN 和饱和转换，并为多种 SIMD 数据类型提供了丰富的指令支持。这部分代码是 Liftoff 编译器将高级 WebAssembly 指令转换为底层机器码的关键组成部分，确保了 WebAssembly 代码在 s390 架构上的高效执行。

Prompt: 
```
这是目录为v8/src/wasm/baseline/s390/liftoff-assembler-s390-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/s390/liftoff-assembler-s390-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
case kExprI32SConvertSatF32: {
      Label done, src_is_nan;
      lzer(kScratchDoubleReg);
      cebr(src.fp(), kScratchDoubleReg);
      b(Condition(1), &src_is_nan);

      // source is a finite number
      ConvertFloat32ToInt32(dst.gp(), src.fp(),
                            kRoundToZero);  // f32 -> i32 round to zero.
      b(&done);

      bind(&src_is_nan);
      lghi(dst.gp(), Operand::Zero());

      bind(&done);
      return true;
    }
    case kExprI32UConvertSatF32: {
      Label done, src_is_nan;
      lzer(kScratchDoubleReg);
      cebr(src.fp(), kScratchDoubleReg);
      b(Condition(1), &src_is_nan);

      // source is a finite number
      ConvertFloat32ToUnsignedInt32(dst.gp(), src.fp(), kRoundToZero);
      b(&done);

      bind(&src_is_nan);
      lghi(dst.gp(), Operand::Zero());

      bind(&done);
      return true;
    }
    case kExprI32SConvertSatF64: {
      Label done, src_is_nan;
      lzdr(kScratchDoubleReg, r0);
      cdbr(src.fp(), kScratchDoubleReg);
      b(Condition(1), &src_is_nan);

      ConvertDoubleToInt32(dst.gp(), src.fp());
      b(&done);

      bind(&src_is_nan);
      lghi(dst.gp(), Operand::Zero());

      bind(&done);
      return true;
    }
    case kExprI32UConvertSatF64: {
      Label done, src_is_nan;
      lzdr(kScratchDoubleReg, r0);
      cdbr(src.fp(), kScratchDoubleReg);
      b(Condition(1), &src_is_nan);

      ConvertDoubleToUnsignedInt32(dst.gp(), src.fp());
      b(&done);

      bind(&src_is_nan);
      lghi(dst.gp(), Operand::Zero());

      bind(&done);
      return true;
    }
    case kExprI32ReinterpretF32:
      lgdr(dst.gp(), src.fp());
      srlg(dst.gp(), dst.gp(), Operand(32));
      return true;
    case kExprI64SConvertI32:
      LoadS32(dst.gp(), src.gp());
      return true;
    case kExprI64UConvertI32:
      llgfr(dst.gp(), src.gp());
      return true;
    case kExprI64ReinterpretF64:
      lgdr(dst.gp(), src.fp());
      return true;
    case kExprF32SConvertI32: {
      ConvertIntToFloat(dst.fp(), src.gp());
      return true;
    }
    case kExprF32UConvertI32: {
      ConvertUnsignedIntToFloat(dst.fp(), src.gp());
      return true;
    }
    case kExprF32ConvertF64:
      ledbr(dst.fp(), src.fp());
      return true;
    case kExprF32ReinterpretI32: {
      sllg(r0, src.gp(), Operand(32));
      ldgr(dst.fp(), r0);
      return true;
    }
    case kExprF64SConvertI32: {
      ConvertIntToDouble(dst.fp(), src.gp());
      return true;
    }
    case kExprF64UConvertI32: {
      ConvertUnsignedIntToDouble(dst.fp(), src.gp());
      return true;
    }
    case kExprF64ConvertF32:
      ldebr(dst.fp(), src.fp());
      return true;
    case kExprF64ReinterpretI64:
      ldgr(dst.fp(), src.gp());
      return true;
    case kExprF64SConvertI64:
      ConvertInt64ToDouble(dst.fp(), src.gp());
      return true;
    case kExprF64UConvertI64:
      ConvertUnsignedInt64ToDouble(dst.fp(), src.gp());
      return true;
    case kExprI64SConvertF32: {
      ConvertFloat32ToInt64(dst.gp(), src.fp());  // f32 -> i64 round to zero.
      b(Condition(1), trap);
      return true;
    }
    case kExprI64UConvertF32: {
      ConvertFloat32ToUnsignedInt64(dst.gp(),
                                    src.fp());  // f32 -> i64 round to zero.
      b(Condition(1), trap);
      return true;
    }
    case kExprF32SConvertI64:
      ConvertInt64ToFloat(dst.fp(), src.gp());
      return true;
    case kExprF32UConvertI64:
      ConvertUnsignedInt64ToFloat(dst.fp(), src.gp());
      return true;
    case kExprI64SConvertF64: {
      ConvertDoubleToInt64(dst.gp(), src.fp());  // f64 -> i64 round to zero.
      b(Condition(1), trap);
      return true;
    }
    case kExprI64UConvertF64: {
      ConvertDoubleToUnsignedInt64(dst.gp(),
                                   src.fp());  // f64 -> i64 round to zero.
      b(Condition(1), trap);
      return true;
    }
    case kExprI64SConvertSatF32: {
      Label done, src_is_nan;
      lzer(kScratchDoubleReg);
      cebr(src.fp(), kScratchDoubleReg);
      b(Condition(1), &src_is_nan);

      // source is a finite number
      ConvertFloat32ToInt64(dst.gp(), src.fp());  // f32 -> i64 round to zero.
      b(&done);

      bind(&src_is_nan);
      lghi(dst.gp(), Operand::Zero());

      bind(&done);
      return true;
    }
    case kExprI64UConvertSatF32: {
      Label done, src_is_nan;
      lzer(kScratchDoubleReg);
      cebr(src.fp(), kScratchDoubleReg);
      b(Condition(1), &src_is_nan);

      // source is a finite number
      ConvertFloat32ToUnsignedInt64(dst.gp(),
                                    src.fp());  // f32 -> i64 round to zero.
      b(&done);

      bind(&src_is_nan);
      lghi(dst.gp(), Operand::Zero());

      bind(&done);
      return true;
    }
    case kExprI64SConvertSatF64: {
      Label done, src_is_nan;
      lzdr(kScratchDoubleReg, r0);
      cdbr(src.fp(), kScratchDoubleReg);
      b(Condition(1), &src_is_nan);

      ConvertDoubleToInt64(dst.gp(), src.fp());  // f64 -> i64 round to zero.
      b(&done);

      bind(&src_is_nan);
      lghi(dst.gp(), Operand::Zero());

      bind(&done);
      return true;
    }
    case kExprI64UConvertSatF64: {
      Label done, src_is_nan;
      lzdr(kScratchDoubleReg, r0);
      cdbr(src.fp(), kScratchDoubleReg);
      b(Condition(1), &src_is_nan);

      ConvertDoubleToUnsignedInt64(dst.gp(),
                                   src.fp());  // f64 -> i64 round to zero.
      b(&done);

      bind(&src_is_nan);
      lghi(dst.gp(), Operand::Zero());

      bind(&done);
      return true;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::emit_jump(Label* label) { b(al, label); }

void LiftoffAssembler::emit_jump(Register target) { Jump(target); }

void LiftoffAssembler::emit_cond_jump(Condition cond, Label* label,
                                      ValueKind kind, Register lhs,
                                      Register rhs,
                                      const FreezeCacheState& frozen) {
  bool use_signed = is_signed(cond);

  if (rhs != no_reg) {
    switch (kind) {
      case kI32:
        if (use_signed) {
          CmpS32(lhs, rhs);
        } else {
          CmpU32(lhs, rhs);
        }
        break;
      case kRef:
      case kRefNull:
      case kRtt:
        DCHECK(cond == kEqual || cond == kNotEqual);
#if defined(V8_COMPRESS_POINTERS)
        if (use_signed) {
          CmpS32(lhs, rhs);
        } else {
          CmpU32(lhs, rhs);
        }
#else
        if (use_signed) {
          CmpS64(lhs, rhs);
        } else {
          CmpU64(lhs, rhs);
        }
#endif
        break;
      case kI64:
        if (use_signed) {
          CmpS64(lhs, rhs);
        } else {
          CmpU64(lhs, rhs);
        }
        break;
      default:
        UNREACHABLE();
    }
  } else {
    DCHECK_EQ(kind, kI32);
    CHECK(use_signed);
    CmpS32(lhs, Operand::Zero());
  }

  b(to_condition(cond), label);
}

void LiftoffAssembler::emit_i32_cond_jumpi(Condition cond, Label* label,
                                           Register lhs, int32_t imm,
                                           const FreezeCacheState& frozen) {
  bool use_signed = is_signed(cond);
  if (use_signed) {
    CmpS32(lhs, Operand(imm));
  } else {
    CmpU32(lhs, Operand(imm));
  }
  b(to_condition(cond), label);
}

void LiftoffAssembler::emit_ptrsize_cond_jumpi(Condition cond, Label* label,
                                               Register lhs, int32_t imm,
                                               const FreezeCacheState& frozen) {
  bool use_signed = is_signed(cond);
  if (use_signed) {
    CmpS64(lhs, Operand(imm));
  } else {
    CmpU64(lhs, Operand(imm));
  }
  b(to_condition(cond), label);
}

#define EMIT_EQZ(test, src) \
  {                         \
    Label done;             \
    test(r0, src);          \
    mov(dst, Operand(1));   \
    beq(&done);             \
    mov(dst, Operand(0));   \
    bind(&done);            \
  }

void LiftoffAssembler::emit_i32_eqz(Register dst, Register src) {
  EMIT_EQZ(ltr, src);
}

#define EMIT_SET_CONDITION(dst, cond) \
  {                                   \
    Label done;                       \
    lghi(dst, Operand(1));            \
    b(cond, &done);                   \
    lghi(dst, Operand(0));            \
    bind(&done);                      \
  }

void LiftoffAssembler::emit_i32_set_cond(Condition cond, Register dst,
                                         Register lhs, Register rhs) {
  bool use_signed = is_signed(cond);
  if (use_signed) {
    CmpS32(lhs, rhs);
  } else {
    CmpU32(lhs, rhs);
  }

  EMIT_SET_CONDITION(dst, to_condition(cond));
}

void LiftoffAssembler::emit_i64_eqz(Register dst, LiftoffRegister src) {
  EMIT_EQZ(ltgr, src.gp());
}

void LiftoffAssembler::emit_i64_set_cond(Condition cond, Register dst,
                                         LiftoffRegister lhs,
                                         LiftoffRegister rhs) {
  bool use_signed = is_signed(cond);
  if (use_signed) {
    CmpS64(lhs.gp(), rhs.gp());
  } else {
    CmpU64(lhs.gp(), rhs.gp());
  }

  EMIT_SET_CONDITION(dst, to_condition(cond));
}

void LiftoffAssembler::emit_f32_set_cond(Condition cond, Register dst,
                                         DoubleRegister lhs,
                                         DoubleRegister rhs) {
  cebr(lhs, rhs);
  EMIT_SET_CONDITION(dst, to_condition(cond));
}

void LiftoffAssembler::emit_f64_set_cond(Condition cond, Register dst,
                                         DoubleRegister lhs,
                                         DoubleRegister rhs) {
  cdbr(lhs, rhs);
  EMIT_SET_CONDITION(dst, to_condition(cond));
}

void LiftoffAssembler::emit_i64_muli(LiftoffRegister dst, LiftoffRegister lhs,
                                     int32_t imm) {
  if (base::bits::IsPowerOfTwo(imm)) {
    emit_i64_shli(dst, lhs, base::bits::WhichPowerOfTwo(imm));
    return;
  }
  mov(r0, Operand(imm));
  MulS64(dst.gp(), lhs.gp(), r0);
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
  TestIfSmi(obj);
  Condition condition = mode == kJumpOnSmi ? eq : ne;
  b(condition, target);  // branch if SMI
}

void LiftoffAssembler::clear_i32_upper_half(Register dst) { LoadU32(dst, dst); }

#define SIMD_BINOP_RR_LIST(V)                        \
  V(f64x2_add, F64x2Add)                             \
  V(f64x2_sub, F64x2Sub)                             \
  V(f64x2_mul, F64x2Mul)                             \
  V(f64x2_div, F64x2Div)                             \
  V(f64x2_min, F64x2Min)                             \
  V(f64x2_max, F64x2Max)                             \
  V(f64x2_eq, F64x2Eq)                               \
  V(f64x2_ne, F64x2Ne)                               \
  V(f64x2_lt, F64x2Lt)                               \
  V(f64x2_le, F64x2Le)                               \
  V(f64x2_pmin, F64x2Pmin)                           \
  V(f64x2_pmax, F64x2Pmax)                           \
  V(f32x4_add, F32x4Add)                             \
  V(f32x4_sub, F32x4Sub)                             \
  V(f32x4_mul, F32x4Mul)                             \
  V(f32x4_div, F32x4Div)                             \
  V(f32x4_min, F32x4Min)                             \
  V(f32x4_max, F32x4Max)                             \
  V(f32x4_eq, F32x4Eq)                               \
  V(f32x4_ne, F32x4Ne)                               \
  V(f32x4_lt, F32x4Lt)                               \
  V(f32x4_le, F32x4Le)                               \
  V(f32x4_pmin, F32x4Pmin)                           \
  V(f32x4_pmax, F32x4Pmax)                           \
  V(i64x2_add, I64x2Add)                             \
  V(i64x2_sub, I64x2Sub)                             \
  V(i64x2_eq, I64x2Eq)                               \
  V(i64x2_ne, I64x2Ne)                               \
  V(i64x2_gt_s, I64x2GtS)                            \
  V(i64x2_ge_s, I64x2GeS)                            \
  V(i32x4_add, I32x4Add)                             \
  V(i32x4_sub, I32x4Sub)                             \
  V(i32x4_mul, I32x4Mul)                             \
  V(i32x4_eq, I32x4Eq)                               \
  V(i32x4_ne, I32x4Ne)                               \
  V(i32x4_gt_s, I32x4GtS)                            \
  V(i32x4_ge_s, I32x4GeS)                            \
  V(i32x4_gt_u, I32x4GtU)                            \
  V(i32x4_min_s, I32x4MinS)                          \
  V(i32x4_min_u, I32x4MinU)                          \
  V(i32x4_max_s, I32x4MaxS)                          \
  V(i32x4_max_u, I32x4MaxU)                          \
  V(i16x8_add, I16x8Add)                             \
  V(i16x8_sub, I16x8Sub)                             \
  V(i16x8_mul, I16x8Mul)                             \
  V(i16x8_eq, I16x8Eq)                               \
  V(i16x8_ne, I16x8Ne)                               \
  V(i16x8_gt_s, I16x8GtS)                            \
  V(i16x8_ge_s, I16x8GeS)                            \
  V(i16x8_gt_u, I16x8GtU)                            \
  V(i16x8_min_s, I16x8MinS)                          \
  V(i16x8_min_u, I16x8MinU)                          \
  V(i16x8_max_s, I16x8MaxS)                          \
  V(i16x8_max_u, I16x8MaxU)                          \
  V(i16x8_rounding_average_u, I16x8RoundingAverageU) \
  V(i8x16_add, I8x16Add)                             \
  V(i8x16_sub, I8x16Sub)                             \
  V(i8x16_eq, I8x16Eq)                               \
  V(i8x16_ne, I8x16Ne)                               \
  V(i8x16_gt_s, I8x16GtS)                            \
  V(i8x16_ge_s, I8x16GeS)                            \
  V(i8x16_gt_u, I8x16GtU)                            \
  V(i8x16_min_s, I8x16MinS)                          \
  V(i8x16_min_u, I8x16MinU)                          \
  V(i8x16_max_s, I8x16MaxS)                          \
  V(i8x16_max_u, I8x16MaxU)                          \
  V(i8x16_rounding_average_u, I8x16RoundingAverageU) \
  V(s128_and, S128And)                               \
  V(s128_or, S128Or)                                 \
  V(s128_xor, S128Xor)                               \
  V(s128_and_not, S128AndNot)

#define EMIT_SIMD_BINOP_RR(name, op)                                           \
  void LiftoffAssembler::emit_##name(LiftoffRegister dst, LiftoffRegister lhs, \
                                     LiftoffRegister rhs) {                    \
    op(dst.fp(), lhs.fp(), rhs.fp());                                          \
  }
SIMD_BINOP_RR_LIST(EMIT_SIMD_BINOP_RR)
#undef EMIT_SIMD_BINOP_RR
#undef SIMD_BINOP_RR_LIST

#define SIMD_SHIFT_RR_LIST(V) \
  V(i64x2_shl, I64x2Shl)      \
  V(i64x2_shr_s, I64x2ShrS)   \
  V(i64x2_shr_u, I64x2ShrU)   \
  V(i32x4_shl, I32x4Shl)      \
  V(i32x4_shr_s, I32x4ShrS)   \
  V(i32x4_shr_u, I32x4ShrU)   \
  V(i16x8_shl, I16x8Shl)      \
  V(i16x8_shr_s, I16x8ShrS)   \
  V(i16x8_shr_u, I16x8ShrU)   \
  V(i8x16_shl, I8x16Shl)      \
  V(i8x16_shr_s, I8x16ShrS)   \
  V(i8x16_shr_u, I8x16ShrU)

#define EMIT_SIMD_SHIFT_RR(name, op)                                           \
  void LiftoffAssembler::emit_##name(LiftoffRegister dst, LiftoffRegister lhs, \
                                     LiftoffRegister rhs) {                    \
    op(dst.fp(), lhs.fp(), rhs.gp(), kScratchDoubleReg);                       \
  }
SIMD_SHIFT_RR_LIST(EMIT_SIMD_SHIFT_RR)
#undef EMIT_SIMD_SHIFT_RR
#undef SIMD_SHIFT_RR_LIST

#define SIMD_SHIFT_RI_LIST(V) \
  V(i64x2_shli, I64x2Shl)     \
  V(i64x2_shri_s, I64x2ShrS)  \
  V(i64x2_shri_u, I64x2ShrU)  \
  V(i32x4_shli, I32x4Shl)     \
  V(i32x4_shri_s, I32x4ShrS)  \
  V(i32x4_shri_u, I32x4ShrU)  \
  V(i16x8_shli, I16x8Shl)     \
  V(i16x8_shri_s, I16x8ShrS)  \
  V(i16x8_shri_u, I16x8ShrU)  \
  V(i8x16_shli, I8x16Shl)     \
  V(i8x16_shri_s, I8x16ShrS)  \
  V(i8x16_shri_u, I8x16ShrU)

#define EMIT_SIMD_SHIFT_RI(name, op)                                           \
  void LiftoffAssembler::emit_##name(LiftoffRegister dst, LiftoffRegister lhs, \
                                     int32_t rhs) {                            \
    op(dst.fp(), lhs.fp(), Operand(rhs), r0, kScratchDoubleReg);               \
  }
SIMD_SHIFT_RI_LIST(EMIT_SIMD_SHIFT_RI)
#undef EMIT_SIMD_SHIFT_RI
#undef SIMD_SHIFT_RI_LIST

#define SIMD_UNOP_LIST(V)                                              \
  V(f64x2_splat, F64x2Splat, fp, fp, , void)                           \
  V(f64x2_abs, F64x2Abs, fp, fp, , void)                               \
  V(f64x2_neg, F64x2Neg, fp, fp, , void)                               \
  V(f64x2_sqrt, F64x2Sqrt, fp, fp, , void)                             \
  V(f64x2_ceil, F64x2Ceil, fp, fp, true, bool)                         \
  V(f64x2_floor, F64x2Floor, fp, fp, true, bool)                       \
  V(f64x2_trunc, F64x2Trunc, fp, fp, true, bool)                       \
  V(f64x2_nearest_int, F64x2NearestInt, fp, fp, true, bool)            \
  V(f64x2_convert_low_i32x4_s, F64x2ConvertLowI32x4S, fp, fp, , void)  \
  V(f64x2_convert_low_i32x4_u, F64x2ConvertLowI32x4U, fp, fp, , void)  \
  V(f32x4_abs, F32x4Abs, fp, fp, , void)                               \
  V(f32x4_splat, F32x4Splat, fp, fp, , void)                           \
  V(f32x4_neg, F32x4Neg, fp, fp, , void)                               \
  V(f32x4_sqrt, F32x4Sqrt, fp, fp, , void)                             \
  V(f32x4_ceil, F32x4Ceil, fp, fp, true, bool)                         \
  V(f32x4_floor, F32x4Floor, fp, fp, true, bool)                       \
  V(f32x4_trunc, F32x4Trunc, fp, fp, true, bool)                       \
  V(f32x4_nearest_int, F32x4NearestInt, fp, fp, true, bool)            \
  V(i64x2_abs, I64x2Abs, fp, fp, , void)                               \
  V(i64x2_splat, I64x2Splat, fp, gp, , void)                           \
  V(i64x2_neg, I64x2Neg, fp, fp, , void)                               \
  V(i64x2_sconvert_i32x4_low, I64x2SConvertI32x4Low, fp, fp, , void)   \
  V(i64x2_sconvert_i32x4_high, I64x2SConvertI32x4High, fp, fp, , void) \
  V(i64x2_uconvert_i32x4_low, I64x2UConvertI32x4Low, fp, fp, , void)   \
  V(i64x2_uconvert_i32x4_high, I64x2UConvertI32x4High, fp, fp, , void) \
  V(i32x4_abs, I32x4Abs, fp, fp, , void)                               \
  V(i32x4_neg, I32x4Neg, fp, fp, , void)                               \
  V(i32x4_splat, I32x4Splat, fp, gp, , void)                           \
  V(i32x4_sconvert_i16x8_low, I32x4SConvertI16x8Low, fp, fp, , void)   \
  V(i32x4_sconvert_i16x8_high, I32x4SConvertI16x8High, fp, fp, , void) \
  V(i32x4_uconvert_i16x8_low, I32x4UConvertI16x8Low, fp, fp, , void)   \
  V(i32x4_uconvert_i16x8_high, I32x4UConvertI16x8High, fp, fp, , void) \
  V(i16x8_abs, I16x8Abs, fp, fp, , void)                               \
  V(i16x8_neg, I16x8Neg, fp, fp, , void)                               \
  V(i16x8_splat, I16x8Splat, fp, gp, , void)                           \
  V(i16x8_sconvert_i8x16_low, I16x8SConvertI8x16Low, fp, fp, , void)   \
  V(i16x8_sconvert_i8x16_high, I16x8SConvertI8x16High, fp, fp, , void) \
  V(i16x8_uconvert_i8x16_low, I16x8UConvertI8x16Low, fp, fp, , void)   \
  V(i16x8_uconvert_i8x16_high, I16x8UConvertI8x16High, fp, fp, , void) \
  V(i8x16_abs, I8x16Abs, fp, fp, , void)                               \
  V(i8x16_neg, I8x16Neg, fp, fp, , void)                               \
  V(i8x16_splat, I8x16Splat, fp, gp, , void)                           \
  V(i8x16_popcnt, I8x16Popcnt, fp, fp, , void)                         \
  V(s128_not, S128Not, fp, fp, , void)

#define EMIT_SIMD_UNOP(name, op, dtype, stype, return_val, return_type) \
  return_type LiftoffAssembler::emit_##name(LiftoffRegister dst,        \
                                            LiftoffRegister src) {      \
    op(dst.dtype(), src.stype());                                       \
    return return_val;                                                  \
  }
SIMD_UNOP_LIST(EMIT_SIMD_UNOP)
#undef EMIT_SIMD_UNOP
#undef SIMD_UNOP_LIST

#define SIMD_EXTRACT_LANE_LIST(V)                \
  V(f64x2_extract_lane, F64x2ExtractLane, fp)    \
  V(f32x4_extract_lane, F32x4ExtractLane, fp)    \
  V(i64x2_extract_lane, I64x2ExtractLane, gp)    \
  V(i32x4_extract_lane, I32x4ExtractLane, gp)    \
  V(i16x8_extract_lane_u, I16x8ExtractLaneU, gp) \
  V(i16x8_extract_lane_s, I16x8ExtractLaneS, gp) \
  V(i8x16_extract_lane_u, I8x16ExtractLaneU, gp) \
  V(i8x16_extract_lane_s, I8x16ExtractLaneS, gp)

#define EMIT_SIMD_EXTRACT_LANE(name, op, dtype)                                \
  void LiftoffAssembler::emit_##name(LiftoffRegister dst, LiftoffRegister src, \
                                     uint8_t imm_lane_idx) {                   \
    op(dst.dtype(), src.fp(), imm_lane_idx, r0);                               \
  }
SIMD_EXTRACT_LANE_LIST(EMIT_SIMD_EXTRACT_LANE)
#undef EMIT_SIMD_EXTRACT_LANE
#undef SIMD_EXTRACT_LANE_LIST

#define SIMD_REPLACE_LANE_LIST(V)             \
  V(f64x2_replace_lane, F64x2ReplaceLane, fp) \
  V(f32x4_replace_lane, F32x4ReplaceLane, fp) \
  V(i64x2_replace_lane, I64x2ReplaceLane, gp) \
  V(i32x4_replace_lane, I32x4ReplaceLane, gp) \
  V(i16x8_replace_lane, I16x8ReplaceLane, gp) \
  V(i8x16_replace_lane, I8x16ReplaceLane, gp)

#define EMIT_SIMD_REPLACE_LANE(name, op, stype)                        \
  void LiftoffAssembler::emit_##name(                                  \
      LiftoffRegister dst, LiftoffRegister src1, LiftoffRegister src2, \
      uint8_t imm_lane_idx) {                                          \
    op(dst.fp(), src1.fp(), src2.stype(), imm_lane_idx, r0);           \
  }
SIMD_REPLACE_LANE_LIST(EMIT_SIMD_REPLACE_LANE)
#undef EMIT_SIMD_REPLACE_LANE
#undef SIMD_REPLACE_LANE_LIST

#define SIMD_EXT_MUL_LIST(V)                          \
  V(i64x2_extmul_low_i32x4_s, I64x2ExtMulLowI32x4S)   \
  V(i64x2_extmul_low_i32x4_u, I64x2ExtMulLowI32x4U)   \
  V(i64x2_extmul_high_i32x4_s, I64x2ExtMulHighI32x4S) \
  V(i64x2_extmul_high_i32x4_u, I64x2ExtMulHighI32x4U) \
  V(i32x4_extmul_low_i16x8_s, I32x4ExtMulLowI16x8S)   \
  V(i32x4_extmul_low_i16x8_u, I32x4ExtMulLowI16x8U)   \
  V(i32x4_extmul_high_i16x8_s, I32x4ExtMulHighI16x8S) \
  V(i32x4_extmul_high_i16x8_u, I32x4ExtMulHighI16x8U) \
  V(i16x8_extmul_low_i8x16_s, I16x8ExtMulLowI8x16S)   \
  V(i16x8_extmul_low_i8x16_u, I16x8ExtMulLowI8x16U)   \
  V(i16x8_extmul_high_i8x16_s, I16x8ExtMulHighI8x16S) \
  V(i16x8_extmul_high_i8x16_u, I16x8ExtMulHighI8x16U)

#define EMIT_SIMD_EXT_MUL(name, op)                                      \
  void LiftoffAssembler::emit_##name(                                    \
      LiftoffRegister dst, LiftoffRegister src1, LiftoffRegister src2) { \
    op(dst.fp(), src1.fp(), src2.fp(), kScratchDoubleReg);               \
  }
SIMD_EXT_MUL_LIST(EMIT_SIMD_EXT_MUL)
#undef EMIT_SIMD_EXT_MUL
#undef SIMD_EXT_MUL_LIST

#define SIMD_ALL_TRUE_LIST(V)    \
  V(i64x2_alltrue, I64x2AllTrue) \
  V(i32x4_alltrue, I32x4AllTrue) \
  V(i16x8_alltrue, I16x8AllTrue) \
  V(i8x16_alltrue, I8x16AllTrue)

#define EMIT_SIMD_ALL_TRUE(name, op)                        \
  void LiftoffAssembler::emit_##name(LiftoffRegister dst,   \
                                     LiftoffRegister src) { \
    op(dst.gp(), src.fp(), r0, kScratchDoubleReg);          \
  }
SIMD_ALL_TRUE_LIST(EMIT_SIMD_ALL_TRUE)
#undef EMIT_SIMD_ALL_TRUE
#undef SIMD_ALL_TRUE_LIST

#define SIMD_ADD_SUB_SAT_LIST(V)   \
  V(i16x8_add_sat_s, I16x8AddSatS) \
  V(i16x8_sub_sat_s, I16x8SubSatS) \
  V(i16x8_add_sat_u, I16x8AddSatU) \
  V(i16x8_sub_sat_u, I16x8SubSatU) \
  V(i8x16_add_sat_s, I8x16AddSatS) \
  V(i8x16_sub_sat_s, I8x16SubSatS) \
  V(i8x16_add_sat_u, I8x16AddSatU) \
  V(i8x16_sub_sat_u, I8x16SubSatU)

#define EMIT_SIMD_ADD_SUB_SAT(name, op)                                        \
  void LiftoffAssembler::emit_##name(LiftoffRegister dst, LiftoffRegister lhs, \
                                     LiftoffRegister rhs) {                    \
    Simd128Register src1 = lhs.fp();                                           \
    Simd128Register src2 = rhs.fp();                                           \
    Simd128Register dest = dst.fp();                                           \
    /* lhs and rhs are unique based on their selection under liftoff-compiler  \
     * `EmitBinOp`. */                                                         \
    /* Make sure dst and temp are also unique. */                              \
    if (dest == src1 || dest == src2) {                                        \
      dest = GetUnusedRegister(kFpReg, LiftoffRegList{src1, src2}).fp();       \
    }                                                                          \
    Simd128Register temp =                                                     \
        GetUnusedRegister(kFpReg, LiftoffRegList{dest, src1, src2}).fp();      \
    op(dest, src1, src2, kScratchDoubleReg, temp);                             \
    /* Original dst register needs to be populated. */                         \
    if (dest != dst.fp()) {                                                    \
      vlr(dst.fp(), dest, Condition(0), Condition(0), Condition(0));           \
    }                                                                          \
  }
SIMD_ADD_SUB_SAT_LIST(EMIT_SIMD_ADD_SUB_SAT)
#undef EMIT_SIMD_ADD_SUB_SAT
#undef SIMD_ADD_SUB_SAT_LIST

#define SIMD_EXT_ADD_PAIRWISE_LIST(V)                         \
  V(i32x4_extadd_pairwise_i16x8_s, I32x4ExtAddPairwiseI16x8S) \
  V(i32x4_extadd_pairwise_i16x8_u, I32x4ExtAddPairwiseI16x8U) \
  V(i16x8_extadd_pairwise_i8x16_s, I16x8ExtAddPairwiseI8x16S) \
  V(i16x8_extadd_pairwise_i8x16_u, I16x8ExtAddPairwiseI8x16U)

#define EMIT_SIMD_EXT_ADD_PAIRWISE(name, op)                         \
  void LiftoffAssembler::emit_##name(LiftoffRegister dst,            \
                                     LiftoffRegister src) {          \
    Simd128Register src1 = src.fp();                                 \
    Simd128Register dest = dst.fp();                                 \
    /* Make sure dst and temp are unique. */                         \
    if (dest == src1) {                                              \
      dest = GetUnusedRegister(kFpReg, LiftoffRegList{src1}).fp();   \
    }                                                                \
    Simd128Register temp =                                           \
        GetUnusedRegister(kFpReg, LiftoffRegList{dest, src1}).fp();  \
    op(dest, src1, kScratchDoubleReg, temp);                         \
    if (dest != dst.fp()) {                                          \
      vlr(dst.fp(), dest, Condition(0), Condition(0), Condition(0)); \
    }                                                                \
  }
SIMD_EXT_ADD_PAIRWISE_LIST(EMIT_SIMD_EXT_ADD_PAIRWISE)
#undef EMIT_SIMD_EXT_ADD_PAIRWISE
#undef SIMD_EXT_ADD_PAIRWISE_LIST

#define SIMD_QFM_LIST(V)   \
  V(f64x2_qfma, F64x2Qfma) \
  V(f64x2_qfms, F64x2Qfms) \
  V(f32x4_qfma, F32x4Qfma) \
  V(f32x4_qfms, F32x4Qfms)

#define EMIT_SIMD_QFM(name, op)                                        \
  void LiftoffAssembler::emit_##name(                                  \
      LiftoffRegister dst, LiftoffRegister src1, LiftoffRegister src2, \
      LiftoffRegister src3) {                                          \
    op(dst.fp(), src1.fp(), src2.fp(), src3.fp());                     \
  }
SIMD_QFM_LIST(EMIT_SIMD_QFM)
#undef EMIT_SIMD_QFM
#undef SIMD_QFM_LIST

#define SIMD_RELAXED_BINOP_LIST(V)        \
  V(i8x16_relaxed_swizzle, i8x16_swizzle) \
  V(f64x2_relaxed_min, f64x2_pmin)        \
  V(f64x2_relaxed_max, f64x2_pmax)        \
  V(f32x4_relaxed_min, f32x4_pmin)        \
  V(f32x4_relaxed_max, f32x4_pmax)        \
  V(i16x8_relaxed_q15mulr_s, i16x8_q15mulr_sat_s)

#define SIMD_VISIT_RELAXED_BINOP(name, op)                                     \
  void LiftoffAssembler::emit_##name(LiftoffRegister dst, LiftoffRegister lhs, \
                                     LiftoffRegister rhs) {                    \
    emit_##op(dst, lhs, rhs);                                                  \
  }
SIMD_RELAXED_BINOP_LIST(SIMD_VISIT_RELAXED_BINOP)
#undef SIMD_VISIT_RELAXED_BINOP
#undef SIMD_RELAXED_BINOP_LIST

#define SIMD_RELAXED_UNOP_LIST(V)                                   \
  V(i32x4_relaxed_trunc_f32x4_s, i32x4_sconvert_f32x4)              \
  V(i32x4_relaxed_trunc_f32x4_u, i32x4_uconvert_f32x4)              \
  V(i32x4_relaxed_trunc_f64x2_s_zero, i32x4_trunc_sat_f64x2_s_zero) \
  V(i32x4_relaxed_trunc_f64x2_u_zero, i32x4_trunc_sat_f64x2_u_zero)

#define SIMD_VISIT_RELAXED_UNOP(name, op)                   \
  void LiftoffAssembler::emit_##name(LiftoffRegister dst,   \
                                     LiftoffRegister src) { \
    emit_##op(dst, src);                                    \
  }
SIMD_RELAXED_UNOP_LIST(SIMD_VISIT_RELAXED_UNOP)
#undef SIMD_VISIT_RELAXED_UNOP
#undef SIMD_RELAXED_UNOP_LIST

#define F16_UNOP_LIST(V)     \
  V(f16x8_splat)             \
  V(f16x8_abs)               \
  V(f16x8_neg)               \
  V(f16x8_sqrt)              \
  V(f16x8_ceil)              \
  V(f16x8_floor)             \
  V(f16x8_trunc)             \
  V(f16x8_nearest_int)       \
  V(i16x8_sconvert_f16x8)    \
  V(i16x8_uconvert_f16x8)    \
  V(f16x8_sconvert_i16x8)    \
  V(f16x8_uconvert_i16x8)    \
  V(f16x8_demote_f32x4_zero) \
  V(f32x4_promote_low_f16x8) \
  V(f16x8_demote_f64x2_zero)

#define VISIT_F16_UNOP(name)                                \
  bool LiftoffAssembler::emit_##name(LiftoffRegister dst,   \
                                     LiftoffRegister src) { \
    return false;                                           \
  }
F16_UNOP_LIST(VISIT_F16_UNOP)
#undef VISIT_F16_UNOP
#undef F16_UNOP_LIST

#define F16_BINOP_LIST(V) \
  V(f16x8_eq)             \
  V(f16x8_ne)             \
  V(f16x8_lt)             \
  V(f16x8_le)             \
  V(f16x8_add)            \
  V(f16x8_sub)            \
  V(f16x8_mul)            \
  V(f16x8_div)            \
  V(f16x8_min)            \
  V(f16x8_max)            \
  V(f16x8_pmin)           \
  V(f16x8_pmax)

#define VISIT_F16_BINOP(name)                                                  \
  bool LiftoffAssembler::emit_##name(LiftoffRegister dst, LiftoffRegister lhs, \
                                     LiftoffRegister rhs) {                    \
    return false;                                                              \
  }
F16_BINOP_LIST(VISIT_F16_BINOP)
#undef VISIT_F16_BINOP
#undef F16_BINOP_LIST

bool LiftoffAssembler::supports_f16_mem_access() { return false; }

bool LiftoffAssembler::emit_f16x8_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_qfma(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_qfms(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  return false;
}

void LiftoffAssembler::LoadTransform(LiftoffRegister dst, Register src_addr,
                                     Register offset_reg, uintptr_t offset_imm,
                                     LoadType type,
                                     LoadTransformationKind transform,
                                     uint32_t* protected_load_pc) {
  if (!is_int20(offset_imm)) {
    mov(ip, Operand(offset_imm));
    if (offset_reg != no_reg) {
      AddS64(ip, offset_reg);
    }
    offset_reg = ip;
    offset_imm = 0;
  }
  MemOperand src_op =
      MemOperand(src_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm);
  *protected_load_pc = pc_offset();
  MachineType memtype = type.mem_type();
  if (transform == LoadTransformationKind::kExtend) {
    if (memtype == MachineType::Int8()) {
    
"""


```