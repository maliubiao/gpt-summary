Response:
My thought process to analyze the provided C++ code snippet and fulfill the request goes like this:

1. **Understand the Request:**  The user wants to know the functionality of the given C++ header file (`liftoff-assembler-riscv64-inl.h`), specifically focusing on its role in the V8 JavaScript engine, potential connections to JavaScript, code logic, common programming errors, and a general summary. It's also important to note the "part 2 of 3" instruction, indicating this is likely part of a larger file.

2. **Initial Code Scan and Keyword Identification:** I'll start by quickly reading through the code, looking for keywords and patterns that suggest its purpose. I see things like:
    * `LiftoffAssembler`: This strongly suggests assembly code generation, likely for a "liftoff" compiler (a fast, baseline compiler).
    * `riscv64`:  Indicates the target architecture is RISC-V 64-bit.
    * `MacroAssembler`: This is a V8 class for generating machine code.
    * Register names (e.g., `dst`, `src`, `a0`, `sp`, `fp`, `kScratchReg`):  Reinforces the assembly generation idea.
    * Wasm opcodes (e.g., `kExprI32ConvertI64`): Points to WebAssembly support.
    * Data types (e.g., `kI32`, `kF64`, `kS128`):  More evidence of handling WebAssembly types.
    * `emit_...`: Function names like `emit_i32_add`, `emit_f64_ceil` clearly indicate the emission of specific assembly instructions for various operations.
    * Memory operations (`Ld`, `Sd`, `Sw`, `Lb`, `Sb`): Confirm direct memory manipulation.
    * SIMD instructions (using `VU` and vector registers like `v0`, `kSimd128ScratchReg`): Shows support for SIMD (Single Instruction, Multiple Data) operations.
    * `CallC`, `ExternalReference`:  Suggests the ability to call C functions from the generated code.

3. **Core Functionality Deduction:** Based on the keywords and patterns, the primary function of this header file is to provide a high-level interface for generating RISC-V 64-bit assembly code, specifically within the context of V8's Liftoff compiler for WebAssembly. It abstracts away the low-level details of individual RISC-V instructions.

4. **Relationship to JavaScript:**  Since it's part of V8 and deals with WebAssembly, the connection to JavaScript is through the compilation process. JavaScript code can be compiled to WebAssembly, and this code assists in the *second* tier of compilation (Liftoff being a baseline compiler). It helps translate WebAssembly instructions into efficient machine code that can be executed by the CPU.

5. **Torque Consideration:** The prompt mentions `.tq` files and Torque. A quick search confirms that Torque is V8's custom language for generating C++ code for runtime functions. Since this file ends in `.h`, it's *not* a Torque file. This distinction is important to address.

6. **JavaScript Example (if applicable):** To illustrate the connection to JavaScript, a simple example would be a JavaScript function that gets compiled to WebAssembly and uses operations that this assembler handles. Arithmetic operations, memory access, and type conversions are good candidates.

7. **Code Logic and Examples:**  The `emit_...` functions represent the core logic. I'll pick a few representative examples and analyze them:
    * **Simple arithmetic:** `emit_i32_add` is straightforward addition. I can create a simple input/output scenario.
    * **More complex logic:** `emit_i32_divs` shows branching for division by zero and unrepresentable results. This allows me to create scenarios triggering these branches.
    * **Memory operations:** `FillStackSlotsWithZero` demonstrates efficient stack clearing. I can illustrate how different sizes are handled.
    * **SIMD:**  The `emit_i64x2_add` (though not shown in this snippet, based on naming conventions in the full file, this would likely exist) demonstrates SIMD operations. I can provide a conceptual example.

8. **Common Programming Errors:** Since this code deals with low-level operations, common errors in related contexts (like C/C++ or assembly programming) are relevant:
    * Integer overflow/underflow (especially with signed division).
    * Division by zero.
    * Incorrect memory access (out-of-bounds).
    * Type mismatch.

9. **Summarization (Part 2 Focus):** The request specifically asks for a summary of *this* part. Looking at the beginning and end of the snippet, I see it starts with loading values and goes through a significant number of arithmetic, bitwise, shift, comparison, and type conversion operations for both integer and floating-point values. It also covers some SIMD operations. Therefore, the summary should emphasize these aspects.

10. **Structure and Refinement:** Finally, I'll organize my findings into the requested categories: Functionality, Torque, JavaScript Relation, Code Logic Examples, Common Errors, and Summary. I'll ensure the language is clear, concise, and directly addresses the user's prompt. I'll double-check that the examples are relevant and easy to understand. I will also ensure that I correctly identified that the provided snippet is *not* a Torque file.
好的，让我们来分析一下 `v8/src/wasm/baseline/riscv/liftoff-assembler-riscv64-inl.h` 这个代码片段的功能。

**功能归纳:**

这段代码是 V8 JavaScript 引擎中，用于 RISC-V 64 位架构的 Liftoff 编译器（一个快速的 WebAssembly 基线编译器）的汇编器内联头文件。它定义了 `LiftoffAssembler` 类的一些成员函数，这些函数负责生成 RISC-V 64 位的机器码指令，以实现 WebAssembly 的各种操作。

具体来说，这段代码片段涵盖了以下功能：

* **加载数据:**  从内存或寄存器加载不同类型的 WebAssembly 数据 (i32, i64, f32, f64, s128) 到寄存器。
* **填充内存:** 将指定栈空间填充为零。针对小块内存和较大内存使用了不同的优化策略。
* **整数运算 (i64):**  实现了 i64 类型的位操作 (clz, ctz, popcnt)、乘法、除法 (有符号和无符号，并处理除零陷阱和不可表示的情况)、取余、加减、位与、位或、位异或、移位操作 (左移、算术右移、逻辑右移)。
* **整数运算 (i32):**  实现了 i32 类型的乘法、除法 (有符号和无符号，并处理除零陷阱和不可表示的情况)、取余、加减、位与、位或、位异或、移位操作。
* **浮点数运算:** 实现了 f64 类型的 ceil, floor, trunc, nearest int 等运算。
* **类型转换:**  实现了各种 WebAssembly 数据类型之间的转换，包括整数与浮点数之间的转换、整数的扩展和截断、浮点数的转换和重解释等。针对可能导致陷阱的转换，可以指定跳转标签。
* **SIMD 操作 (i64x2):**  实现了 SIMD 向量的元素提取、splat（将标量值复制到向量的所有元素）、替换 lane 等操作。
* **SIMD 操作 (f64x2):** 实现了 f64x2 的 min 和 max 操作，并考虑了 NaN 值。
* **SIMD 操作 (i32x4 和 i16x8 的扩展加法):** 实现了有符号和无符号的成对扩展加法操作。
* **跳转:**  实现了无条件跳转和条件跳转，包括基于整数值和特定条件的跳转。
* **条件设置:**  根据比较结果设置寄存器的值 (0 或 1)。
* **原子操作 (IncrementSmi):**  实现了对 Smi（Small Integer）类型的原子递增操作。
* **加载并转换:**  从内存加载数据并进行扩展 (符号扩展或零扩展) 或 splat 操作到 SIMD 寄存器。
* **加载/存储 Lane:**  从内存加载单个 lane 到 SIMD 寄存器或将 SIMD 寄存器的单个 lane 存储到内存。
* **调用 C 函数:**  提供了 `CallCWithStackBuffer` 和 `CallC` 函数，用于调用 C 函数，并处理参数传递和返回值。`CallCWithStackBuffer` 特别用于将参数放置在栈上缓冲区中传递。

**关于文件类型和 JavaScript 功能的关系:**

* **文件类型:**  `v8/src/wasm/baseline/riscv/liftoff-assembler-riscv64-inl.h` 以 `.h` 结尾，这表明它是一个 C++ 头文件，用于定义类的接口和内联函数。它**不是**以 `.tq` 结尾，因此不是 V8 Torque 源代码。

* **与 JavaScript 的功能关系:**  这段代码直接参与了将 WebAssembly 代码转换为可在 RISC-V 64 位架构上执行的机器码的过程。当 JavaScript 代码中调用 WebAssembly 模块时，V8 引擎会使用 Liftoff 编译器（或其他更高级的编译器）将 WebAssembly 指令翻译成机器码。`liftoff-assembler-riscv64-inl.h` 中定义的函数就是用来生成这些机器码指令的。

**JavaScript 示例 (概念性):**

虽然不能直接用 JavaScript 代码来展示这个 C++ 文件的功能，但可以展示一个最终会用到这些功能的 JavaScript + WebAssembly 的例子：

```javascript
// JavaScript 代码
async function runWasm() {
  const response = await fetch('my_wasm_module.wasm'); // 假设有一个 wasm 模块
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(buffer);
  const instance = module.instance;

  // 调用 wasm 模块中的函数
  const result = instance.exports.add(5, 10);
  console.log(result); // 输出 15
}

runWasm();
```

在这个例子中，`instance.exports.add(5, 10)` 调用了 WebAssembly 模块中的 `add` 函数。当 V8 引擎执行这个调用时，如果使用了 Liftoff 编译器，就会用到类似 `emit_i32_add` 这样的函数来生成 RISC-V 的加法指令。

**代码逻辑推理:**

以 `emit_i32_divs` (有符号整数除法) 为例：

**假设输入:**

* `dst`: 目标寄存器 (例如 `a0`)
* `lhs`: 被除数寄存器 (例如 `a1`)，值为 10
* `rhs`: 除数寄存器 (例如 `a2`)，值为 2
* `trap_div_by_zero`:  如果除数为零，跳转到此标签
* `trap_div_unrepresentable`: 如果发生溢出 (例如 `INT_MIN / -1`)，跳转到此标签

**输出:**

机器码指令序列，执行以下操作：

1. **检查除零:** 生成指令，如果 `rhs` (a2) 为零，则跳转到 `trap_div_by_zero` 标签。
2. **检查溢出:**
   * 将 `lhs` (a1) 与 `INT_MIN` 进行比较，结果存储在 `kScratchReg`。
   * 将 `rhs` (a2) 与 -1 进行比较，结果存储在 `kScratchReg2`。
   * 将 `kScratchReg` 和 `kScratchReg2` 相加。
   * 如果结果为零 (意味着 `lhs` 是 `INT_MIN` 且 `rhs` 是 -1)，则跳转到 `trap_div_unrepresentable` 标签。
3. **执行除法:** 如果没有发生除零或溢出，生成 RISC-V 的有符号整数除法指令，将结果存储在 `dst` (a0) 中。

**用户常见的编程错误举例:**

在使用 WebAssembly 或编写类似的底层代码时，常见的错误包括：

1. **除零错误:**  WebAssembly 中整数除零会导致陷阱。
   ```javascript
   // WebAssembly (Text Format)
   (module
     (func $divide (param $x i32) (param $y i32) (result i32)
       local.get $x
       local.get $y
       i32.div_s  ;; 有符号整数除法
     )
     (export "divide" (func $divide))
   )
   ```
   如果在 JavaScript 中调用这个 WebAssembly 模块的 `divide` 函数时，传入的除数为 0，就会触发一个错误。

2. **整数溢出:**  某些整数运算可能导致溢出，例如有符号整数除法的特殊情况 (`INT_MIN / -1`)。
   ```javascript
   // 假设 WebAssembly 模块中有类似的除法操作
   const result = instance.exports.divide(-2147483648, -1); // INT_MIN / -1
   // 这可能会导致不可预测的结果或陷阱，取决于编译器的处理方式。
   ```

3. **类型不匹配:**  尝试将一种类型的值错误地解释为另一种类型，例如将浮点数直接当做整数处理。 虽然 WebAssembly 有明确的类型系统，但在底层的汇编代码中，如果逻辑处理不当，可能会导致这类错误。

**总结 (针对第 2 部分):**

这段代码片段主要集中在实现 **基本的算术、逻辑、位运算、类型转换以及部分 SIMD 操作** 的 RISC-V 64 位机器码生成。它涵盖了 WebAssembly 中 i32、i64 和浮点数 (f32, f64) 的常见操作，以及一些 SIMD 指令的支持。此外，它还包含了内存操作（加载、存储、填充）以及调用 C 函数的机制。这段代码是 V8 引擎 Liftoff 编译器将 WebAssembly 代码转化为 RISC-V 架构可执行代码的关键组成部分。

### 提示词
```
这是目录为v8/src/wasm/baseline/riscv/liftoff-assembler-riscv64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/riscv/liftoff-assembler-riscv64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
break;
    case kF64:
      MacroAssembler::LoadDouble(reg.fp(), src);
      break;
    case kS128: {
      VU.set(kScratchReg, E8, m1);
      Register src_reg = src.offset() == 0 ? src.rm() : kScratchReg;
      if (src.offset() != 0) {
        MacroAssembler::Add64(src_reg, src.rm(), src.offset());
      }
      vl(reg.fp().toV(), src_reg, 0, E8);
      break;
    }
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
      Sd(zero_reg, liftoff::GetStackSlot(start + remainder));
    }
    DCHECK(remainder == 4 || remainder == 0);
    if (remainder) {
      Sw(zero_reg, liftoff::GetStackSlot(start + remainder));
    }
  } else {
    // General case for bigger counts (12 instructions).
    // Use a0 for start address (inclusive), a1 for end address (exclusive).
    Push(a1, a0);
    Add64(a0, fp, Operand(-start - size));
    Add64(a1, fp, Operand(-start));

    Label loop;
    bind(&loop);
    Sd(zero_reg, MemOperand(a0));
    addi(a0, a0, kSystemPointerSize);
    BranchShort(&loop, ne, a0, Operand(a1));

    Pop(a1, a0);
  }
}

void LiftoffAssembler::emit_i64_clz(LiftoffRegister dst, LiftoffRegister src) {
  MacroAssembler::Clz64(dst.gp(), src.gp());
}

void LiftoffAssembler::emit_i64_ctz(LiftoffRegister dst, LiftoffRegister src) {
  MacroAssembler::Ctz64(dst.gp(), src.gp());
}

bool LiftoffAssembler::emit_i64_popcnt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  MacroAssembler::Popcnt64(dst.gp(), src.gp(), kScratchReg);
  return true;
}

void LiftoffAssembler::emit_i32_mul(Register dst, Register lhs, Register rhs) {
  MacroAssembler::Mul32(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_divs(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs, Operand(zero_reg));

  // Check if lhs == kMinInt and rhs == -1, since this case is unrepresentable.
  MacroAssembler::CompareI(kScratchReg, lhs, Operand(kMinInt), ne);
  MacroAssembler::CompareI(kScratchReg2, rhs, Operand(-1), ne);
  add(kScratchReg, kScratchReg, kScratchReg2);
  MacroAssembler::Branch(trap_div_unrepresentable, eq, kScratchReg,
                         Operand(zero_reg));

  MacroAssembler::Div32(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_divu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs, Operand(zero_reg));
  MacroAssembler::Divu32(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_rems(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs, Operand(zero_reg));
  MacroAssembler::Mod32(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_remu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs, Operand(zero_reg));
  MacroAssembler::Modu32(dst, lhs, rhs);
}

#define I32_BINOP(name, instruction)                                 \
  void LiftoffAssembler::emit_i32_##name(Register dst, Register lhs, \
                                         Register rhs) {             \
    instruction(dst, lhs, rhs);                                      \
  }

// clang-format off
I32_BINOP(add, addw)
I32_BINOP(sub, subw)
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
I32_BINOP_I(add, Add32)
I32_BINOP_I(sub, Sub32)
I32_BINOP_I(and, And)
I32_BINOP_I(or, Or)
I32_BINOP_I(xor, Xor)
// clang-format on

#undef I32_BINOP_I

void LiftoffAssembler::emit_i32_clz(Register dst, Register src) {
  MacroAssembler::Clz32(dst, src);
}

void LiftoffAssembler::emit_i32_ctz(Register dst, Register src) {
  MacroAssembler::Ctz32(dst, src);
}

bool LiftoffAssembler::emit_i32_popcnt(Register dst, Register src) {
  MacroAssembler::Popcnt32(dst, src, kScratchReg);
  return true;
}

#define I32_SHIFTOP(name, instruction)                               \
  void LiftoffAssembler::emit_i32_##name(Register dst, Register src, \
                                         Register amount) {          \
    instruction(dst, src, amount);                                   \
  }
#define I32_SHIFTOP_I(name, instruction)                                \
  void LiftoffAssembler::emit_i32_##name##i(Register dst, Register src, \
                                            int amount) {               \
    instruction(dst, src, amount & 31);                                 \
  }

I32_SHIFTOP(shl, sllw)
I32_SHIFTOP(sar, sraw)
I32_SHIFTOP(shr, srlw)

I32_SHIFTOP_I(shl, slliw)
I32_SHIFTOP_I(sar, sraiw)
I32_SHIFTOP_I(shr, srliw)

#undef I32_SHIFTOP
#undef I32_SHIFTOP_I

void LiftoffAssembler::emit_i64_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  MacroAssembler::Mul64(dst.gp(), lhs.gp(), rhs.gp());
}

void LiftoffAssembler::emit_i64_muli(LiftoffRegister dst, LiftoffRegister lhs,
                                     int32_t imm) {
  if (base::bits::IsPowerOfTwo(imm)) {
    emit_i64_shli(dst, lhs, base::bits::WhichPowerOfTwo(imm));
    return;
  }
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, imm);
  Mul64(dst.gp(), lhs.gp(), scratch);
}

bool LiftoffAssembler::emit_i64_divs(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs.gp(), Operand(zero_reg));

  // Check if lhs == MinInt64 and rhs == -1, since this case is unrepresentable.
  MacroAssembler::CompareI(kScratchReg, lhs.gp(),
                           Operand(std::numeric_limits<int64_t>::min()), ne);
  MacroAssembler::CompareI(kScratchReg2, rhs.gp(), Operand(-1), ne);
  add(kScratchReg, kScratchReg, kScratchReg2);
  MacroAssembler::Branch(trap_div_unrepresentable, eq, kScratchReg,
                         Operand(zero_reg));

  MacroAssembler::Div64(dst.gp(), lhs.gp(), rhs.gp());
  return true;
}

bool LiftoffAssembler::emit_i64_divu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs.gp(), Operand(zero_reg));
  MacroAssembler::Divu64(dst.gp(), lhs.gp(), rhs.gp());
  return true;
}

bool LiftoffAssembler::emit_i64_rems(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs.gp(), Operand(zero_reg));
  MacroAssembler::Mod64(dst.gp(), lhs.gp(), rhs.gp());
  return true;
}

bool LiftoffAssembler::emit_i64_remu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs.gp(), Operand(zero_reg));
  MacroAssembler::Modu64(dst.gp(), lhs.gp(), rhs.gp());
  return true;
}

#define I64_BINOP(name, instruction)                                   \
  void LiftoffAssembler::emit_i64_##name(                              \
      LiftoffRegister dst, LiftoffRegister lhs, LiftoffRegister rhs) { \
    instruction(dst.gp(), lhs.gp(), rhs.gp());                         \
  }

// clang-format off
I64_BINOP(add, add)
I64_BINOP(sub, sub)
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

I64_SHIFTOP(shl, sll)
I64_SHIFTOP(sar, sra)
I64_SHIFTOP(shr, srl)
#undef I64_SHIFTOP

void LiftoffAssembler::emit_i64_shli(LiftoffRegister dst, LiftoffRegister src,
                                     int amount) {
  if (is_uint6(amount)) {
    slli(dst.gp(), src.gp(), amount);
  } else {
    li(kScratchReg, amount);
    sll(dst.gp(), src.gp(), kScratchReg);
  }
}

void LiftoffAssembler::emit_i64_sari(LiftoffRegister dst, LiftoffRegister src,
                                     int amount) {
  if (is_uint6(amount)) {
    srai(dst.gp(), src.gp(), amount);
  } else {
    li(kScratchReg, amount);
    sra(dst.gp(), src.gp(), kScratchReg);
  }
}

void LiftoffAssembler::emit_i64_shri(LiftoffRegister dst, LiftoffRegister src,
                                     int amount) {
  if (is_uint6(amount)) {
    srli(dst.gp(), src.gp(), amount);
  } else {
    li(kScratchReg, amount);
    srl(dst.gp(), src.gp(), kScratchReg);
  }
}

void LiftoffAssembler::emit_i64_addi(LiftoffRegister dst, LiftoffRegister lhs,
                                     int64_t imm) {
  MacroAssembler::Add64(dst.gp(), lhs.gp(), Operand(imm));
}
void LiftoffAssembler::emit_u32_to_uintptr(Register dst, Register src) {
  ZeroExtendWord(dst, src);
}

void LiftoffAssembler::clear_i32_upper_half(Register dst) {
  // Don't need to clear the upper halves of i32 values for sandbox on riscv64,
  // because we'll explicitly zero-extend their lower halves before using them
  // for memory accesses anyway.
}

#define FP_UNOP_RETURN_TRUE(name, instruction)                                 \
  bool LiftoffAssembler::emit_##name(DoubleRegister dst, DoubleRegister src) { \
    instruction(dst, src, kScratchDoubleReg);                                  \
    return true;                                                               \
  }

FP_UNOP_RETURN_TRUE(f64_ceil, Ceil_d_d)
FP_UNOP_RETURN_TRUE(f64_floor, Floor_d_d)
FP_UNOP_RETURN_TRUE(f64_trunc, Trunc_d_d)
FP_UNOP_RETURN_TRUE(f64_nearest_int, Round_d_d)

#undef FP_UNOP_RETURN_TRUE

bool LiftoffAssembler::emit_type_conversion(WasmOpcode opcode,
                                            LiftoffRegister dst,
                                            LiftoffRegister src, Label* trap) {
  switch (opcode) {
    case kExprI32ConvertI64:
      // According to WebAssembly spec, if I64 value does not fit the range of
      // I32, the value is undefined. Therefore, We use sign extension to
      // implement I64 to I32 truncation
      MacroAssembler::SignExtendWord(dst.gp(), src.gp());
      return true;
    case kExprI32SConvertF32:
    case kExprI32UConvertF32:
    case kExprI32SConvertF64:
    case kExprI32UConvertF64:
    case kExprI64SConvertF32:
    case kExprI64UConvertF32:
    case kExprI64SConvertF64:
    case kExprI64UConvertF64:
    case kExprF32ConvertF64: {
      // real conversion, if src is out-of-bound of target integer types,
      // kScratchReg is set to 0
      switch (opcode) {
        case kExprI32SConvertF32:
          Trunc_w_s(dst.gp(), src.fp(), kScratchReg);
          break;
        case kExprI32UConvertF32:
          Trunc_uw_s(dst.gp(), src.fp(), kScratchReg);
          break;
        case kExprI32SConvertF64:
          Trunc_w_d(dst.gp(), src.fp(), kScratchReg);
          break;
        case kExprI32UConvertF64:
          Trunc_uw_d(dst.gp(), src.fp(), kScratchReg);
          break;
        case kExprI64SConvertF32:
          Trunc_l_s(dst.gp(), src.fp(), kScratchReg);
          break;
        case kExprI64UConvertF32:
          Trunc_ul_s(dst.gp(), src.fp(), kScratchReg);
          break;
        case kExprI64SConvertF64:
          Trunc_l_d(dst.gp(), src.fp(), kScratchReg);
          break;
        case kExprI64UConvertF64:
          Trunc_ul_d(dst.gp(), src.fp(), kScratchReg);
          break;
        case kExprF32ConvertF64:
          fcvt_s_d(dst.fp(), src.fp());
          break;
        default:
          UNREACHABLE();
      }

      // Checking if trap.
      if (trap != nullptr) {
        MacroAssembler::Branch(trap, eq, kScratchReg, Operand(zero_reg));
      }

      return true;
    }
    case kExprI32ReinterpretF32:
      MacroAssembler::ExtractLowWordFromF64(dst.gp(), src.fp());
      return true;
    case kExprI64SConvertI32:
      MacroAssembler::SignExtendWord(dst.gp(), src.gp());
      return true;
    case kExprI64UConvertI32:
      MacroAssembler::ZeroExtendWord(dst.gp(), src.gp());
      return true;
    case kExprI64ReinterpretF64:
      fmv_x_d(dst.gp(), src.fp());
      return true;
    case kExprF32SConvertI32: {
      MacroAssembler::Cvt_s_w(dst.fp(), src.gp());
      return true;
    }
    case kExprF32UConvertI32:
      MacroAssembler::Cvt_s_uw(dst.fp(), src.gp());
      return true;
    case kExprF32ReinterpretI32:
      fmv_w_x(dst.fp(), src.gp());
      return true;
    case kExprF64SConvertI32: {
      MacroAssembler::Cvt_d_w(dst.fp(), src.gp());
      return true;
    }
    case kExprF64UConvertI32:
      MacroAssembler::Cvt_d_uw(dst.fp(), src.gp());
      return true;
    case kExprF64ConvertF32:
      fcvt_d_s(dst.fp(), src.fp());
      return true;
    case kExprF64ReinterpretI64:
      fmv_d_x(dst.fp(), src.gp());
      return true;
    case kExprI32SConvertSatF32: {
      fcvt_w_s(dst.gp(), src.fp(), RTZ);
      Clear_if_nan_s(dst.gp(), src.fp());
      return true;
    }
    case kExprI32UConvertSatF32: {
      fcvt_wu_s(dst.gp(), src.fp(), RTZ);
      Clear_if_nan_s(dst.gp(), src.fp());
      return true;
    }
    case kExprI32SConvertSatF64: {
      fcvt_w_d(dst.gp(), src.fp(), RTZ);
      Clear_if_nan_d(dst.gp(), src.fp());
      return true;
    }
    case kExprI32UConvertSatF64: {
      fcvt_wu_d(dst.gp(), src.fp(), RTZ);
      Clear_if_nan_d(dst.gp(), src.fp());
      return true;
    }
    case kExprI64SConvertSatF32: {
      fcvt_l_s(dst.gp(), src.fp(), RTZ);
      Clear_if_nan_s(dst.gp(), src.fp());
      return true;
    }
    case kExprI64UConvertSatF32: {
      fcvt_lu_s(dst.gp(), src.fp(), RTZ);
      Clear_if_nan_s(dst.gp(), src.fp());
      return true;
    }
    case kExprI64SConvertSatF64: {
      fcvt_l_d(dst.gp(), src.fp(), RTZ);
      Clear_if_nan_d(dst.gp(), src.fp());
      return true;
    }
    case kExprI64UConvertSatF64: {
      fcvt_lu_d(dst.gp(), src.fp(), RTZ);
      Clear_if_nan_d(dst.gp(), src.fp());
      return true;
    }
    default:
      return false;
  }
}

void LiftoffAssembler::emit_i64x2_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  VU.set(kScratchReg, E64, m1);
  vslidedown_vi(kSimd128ScratchReg, lhs.fp().toV(), imm_lane_idx);
  vmv_xs(dst.gp(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i32_signextend_i8(Register dst, Register src) {
  slliw(dst, src, 32 - 8);
  sraiw(dst, dst, 32 - 8);
}

void LiftoffAssembler::emit_i32_signextend_i16(Register dst, Register src) {
  slliw(dst, src, 32 - 16);
  sraiw(dst, dst, 32 - 16);
}

void LiftoffAssembler::emit_i64_signextend_i8(LiftoffRegister dst,
                                              LiftoffRegister src) {
  slli(dst.gp(), src.gp(), 64 - 8);
  srai(dst.gp(), dst.gp(), 64 - 8);
}

void LiftoffAssembler::emit_i64_signextend_i16(LiftoffRegister dst,
                                               LiftoffRegister src) {
  slli(dst.gp(), src.gp(), 64 - 16);
  srai(dst.gp(), dst.gp(), 64 - 16);
}

void LiftoffAssembler::emit_i64_signextend_i32(LiftoffRegister dst,
                                               LiftoffRegister src) {
  slli(dst.gp(), src.gp(), 64 - 32);
  srai(dst.gp(), dst.gp(), 64 - 32);
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
      slliw(scratch0, lhs, 0);
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
  MacroAssembler::slliw(dst, src, 0);
  MacroAssembler::Sltu(dst, src, 1);
}

void LiftoffAssembler::emit_i32_set_cond(Condition cond, Register dst,
                                         Register lhs, Register rhs) {
  UseScratchRegisterScope temps(this);
  Register scratch0 = temps.Acquire();
  Register scratch1 = kScratchReg;
  MacroAssembler::slliw(scratch0, lhs, 0);
  MacroAssembler::slliw(scratch1, rhs, 0);
  MacroAssembler::CompareI(dst, scratch0, Operand(scratch1), cond);
}

void LiftoffAssembler::emit_i64_eqz(Register dst, LiftoffRegister src) {
  MacroAssembler::Sltu(dst, src.gp(), 1);
}

void LiftoffAssembler::emit_i64_set_cond(Condition cond, Register dst,
                                         LiftoffRegister lhs,
                                         LiftoffRegister rhs) {
  MacroAssembler::CompareI(dst, lhs.gp(), Operand(rhs.gp()), cond);
}

void LiftoffAssembler::IncrementSmi(LiftoffRegister dst, int offset) {
  UseScratchRegisterScope temps(this);
  if (COMPRESS_POINTERS_BOOL) {
    DCHECK(SmiValuesAre31Bits());
    Register scratch = temps.Acquire();
    Lw(scratch, MemOperand(dst.gp(), offset));
    Add32(scratch, scratch, Operand(Smi::FromInt(1)));
    Sw(scratch, MemOperand(dst.gp(), offset));
  } else {
    Register scratch = temps.Acquire();
    SmiUntag(scratch, MemOperand(dst.gp(), offset));
    Add64(scratch, scratch, Operand(1));
    SmiTag(scratch);
    Sd(scratch, MemOperand(dst.gp(), offset));
  }
}

void LiftoffAssembler::LoadTransform(LiftoffRegister dst, Register src_addr,
                                     Register offset_reg, uintptr_t offset_imm,
                                     LoadType type,
                                     LoadTransformationKind transform,
                                     uint32_t* protected_load_pc) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  MemOperand src_op = liftoff::GetMemOp(this, src_addr, offset_reg, offset_imm);
  VRegister dst_v = dst.fp().toV();
  auto trapper = [protected_load_pc](int offset) {
    if (protected_load_pc) *protected_load_pc = static_cast<uint32_t>(offset);
  };
  MachineType memtype = type.mem_type();
  if (transform == LoadTransformationKind::kExtend) {
    Ld(scratch, src_op, trapper);
    if (memtype == MachineType::Int8()) {
      VU.set(kScratchReg, E64, m1);
      vmv_vx(kSimd128ScratchReg, scratch);
      VU.set(kScratchReg, E16, m1);
      vsext_vf2(dst_v, kSimd128ScratchReg);
    } else if (memtype == MachineType::Uint8()) {
      VU.set(kScratchReg, E64, m1);
      vmv_vx(kSimd128ScratchReg, scratch);
      VU.set(kScratchReg, E16, m1);
      vzext_vf2(dst_v, kSimd128ScratchReg);
    } else if (memtype == MachineType::Int16()) {
      VU.set(kScratchReg, E64, m1);
      vmv_vx(kSimd128ScratchReg, scratch);
      VU.set(kScratchReg, E32, m1);
      vsext_vf2(dst_v, kSimd128ScratchReg);
    } else if (memtype == MachineType::Uint16()) {
      VU.set(kScratchReg, E64, m1);
      vmv_vx(kSimd128ScratchReg, scratch);
      VU.set(kScratchReg, E32, m1);
      vzext_vf2(dst_v, kSimd128ScratchReg);
    } else if (memtype == MachineType::Int32()) {
      VU.set(kScratchReg, E64, m1);
      vmv_vx(kSimd128ScratchReg, scratch);
      vsext_vf2(dst_v, kSimd128ScratchReg);
    } else if (memtype == MachineType::Uint32()) {
      VU.set(kScratchReg, E64, m1);
      vmv_vx(kSimd128ScratchReg, scratch);
      vzext_vf2(dst_v, kSimd128ScratchReg);
    }
  } else if (transform == LoadTransformationKind::kZeroExtend) {
    vxor_vv(dst_v, dst_v, dst_v);
    if (memtype == MachineType::Int32()) {
      VU.set(kScratchReg, E32, m1);
      Lwu(scratch, src_op, trapper);
      vmv_sx(dst_v, scratch);
    } else {
      DCHECK_EQ(MachineType::Int64(), memtype);
      VU.set(kScratchReg, E64, m1);
      Ld(scratch, src_op, trapper);
      vmv_sx(dst_v, scratch);
    }
  } else {
    DCHECK_EQ(LoadTransformationKind::kSplat, transform);
    if (memtype == MachineType::Int8()) {
      VU.set(kScratchReg, E8, m1);
      Lb(scratch, src_op, trapper);
      vmv_vx(dst_v, scratch);
    } else if (memtype == MachineType::Int16()) {
      VU.set(kScratchReg, E16, m1);
      Lh(scratch, src_op, trapper);
      vmv_vx(dst_v, scratch);
    } else if (memtype == MachineType::Int32()) {
      VU.set(kScratchReg, E32, m1);
      Lw(scratch, src_op, trapper);
      vmv_vx(dst_v, scratch);
    } else if (memtype == MachineType::Int64()) {
      VU.set(kScratchReg, E64, m1);
      Ld(scratch, src_op, trapper);
      vmv_vx(dst_v, scratch);
    }
  }
  if (protected_load_pc) {
    DCHECK(InstructionAt(*protected_load_pc)->IsLoad());
  }
}

void LiftoffAssembler::LoadLane(LiftoffRegister dst, LiftoffRegister src,
                                Register addr, Register offset_reg,
                                uintptr_t offset_imm, LoadType type,
                                uint8_t laneidx, uint32_t* protected_load_pc,
                                bool i64_offset) {
  MemOperand src_op =
      liftoff::GetMemOp(this, addr, offset_reg, offset_imm, i64_offset);
  MachineType mem_type = type.mem_type();
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  auto trapper = [protected_load_pc](int offset) {
    if (protected_load_pc) *protected_load_pc = static_cast<uint32_t>(offset);
  };
  if (mem_type == MachineType::Int8()) {
    Lbu(scratch, src_op, trapper);
    VU.set(kScratchReg, E64, m1);
    li(kScratchReg, 0x1 << laneidx);
    vmv_sx(v0, kScratchReg);
    VU.set(kScratchReg, E8, m1);
    vmerge_vx(dst.fp().toV(), scratch, dst.fp().toV());
  } else if (mem_type == MachineType::Int16()) {
    Lhu(scratch, src_op, trapper);
    VU.set(kScratchReg, E16, m1);
    li(kScratchReg, 0x1 << laneidx);
    vmv_sx(v0, kScratchReg);
    vmerge_vx(dst.fp().toV(), scratch, dst.fp().toV());
  } else if (mem_type == MachineType::Int32()) {
    Lwu(scratch, src_op, trapper);
    VU.set(kScratchReg, E32, m1);
    li(kScratchReg, 0x1 << laneidx);
    vmv_sx(v0, kScratchReg);
    vmerge_vx(dst.fp().toV(), scratch, dst.fp().toV());
  } else if (mem_type == MachineType::Int64()) {
    Ld(scratch, src_op, trapper);
    VU.set(kScratchReg, E64, m1);
    li(kScratchReg, 0x1 << laneidx);
    vmv_sx(v0, kScratchReg);
    vmerge_vx(dst.fp().toV(), scratch, dst.fp().toV());
  } else {
    UNREACHABLE();
  }
  if (protected_load_pc) {
    DCHECK(InstructionAt(*protected_load_pc)->IsLoad());
  }
}

void LiftoffAssembler::StoreLane(Register dst, Register offset,
                                 uintptr_t offset_imm, LiftoffRegister src,
                                 StoreType type, uint8_t lane,
                                 uint32_t* protected_store_pc,
                                 bool i64_offset) {
  MemOperand dst_op =
      liftoff::GetMemOp(this, dst, offset, offset_imm, i64_offset);
  MachineRepresentation rep = type.mem_rep();
  auto trapper = [protected_store_pc](int offset) {
    if (protected_store_pc) *protected_store_pc = static_cast<uint32_t>(offset);
  };
  if (rep == MachineRepresentation::kWord8) {
    VU.set(kScratchReg, E8, m1);
    vslidedown_vi(kSimd128ScratchReg, src.fp().toV(), lane);
    vmv_xs(kScratchReg, kSimd128ScratchReg);
    Sb(kScratchReg, dst_op, trapper);
  } else if (rep == MachineRepresentation::kWord16) {
    VU.set(kScratchReg, E16, m1);
    vslidedown_vi(kSimd128ScratchReg, src.fp().toV(), lane);
    vmv_xs(kScratchReg, kSimd128ScratchReg);
    Sh(kScratchReg, dst_op, trapper);
  } else if (rep == MachineRepresentation::kWord32) {
    VU.set(kScratchReg, E32, m1);
    vslidedown_vi(kSimd128ScratchReg, src.fp().toV(), lane);
    vmv_xs(kScratchReg, kSimd128ScratchReg);
    Sw(kScratchReg, dst_op, trapper);
  } else {
    DCHECK_EQ(MachineRepresentation::kWord64, rep);
    VU.set(kScratchReg, E64, m1);
    vslidedown_vi(kSimd128ScratchReg, src.fp().toV(), lane);
    vmv_xs(kScratchReg, kSimd128ScratchReg);
    Sd(kScratchReg, dst_op, trapper);
  }
  if (protected_store_pc) {
    DCHECK(InstructionAt(*protected_store_pc)->IsStore());
  }
}

void LiftoffAssembler::emit_i64x2_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  VU.set(kScratchReg, E64, m1);
  vmv_vx(dst.fp().toV(), src.gp());
}

void LiftoffAssembler::emit_i64x2_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  VU.set(kScratchReg, E64, m1);
  li(kScratchReg, 0x1 << imm_lane_idx);
  vmv_sx(v0, kScratchReg);
  vmerge_vx(dst.fp().toV(), src2.gp(), src1.fp().toV());
}

void LiftoffAssembler::emit_f64x2_min(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  const int64_t kNaN = 0x7ff8000000000000L;
  vmfeq_vv(v0, lhs.fp().toV(), lhs.fp().toV());
  vmfeq_vv(kSimd128ScratchReg, rhs.fp().toV(), rhs.fp().toV());
  vand_vv(v0, v0, kSimd128ScratchReg);
  li(kScratchReg, kNaN);
  vmv_vx(kSimd128ScratchReg, kScratchReg);
  vfmin_vv(kSimd128ScratchReg, rhs.fp().toV(), lhs.fp().toV(), Mask);
  vmv_vv(dst.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_f64x2_max(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  VU.set(kScratchReg, E64, m1);
  const int64_t kNaN = 0x7ff8000000000000L;
  vmfeq_vv(v0, lhs.fp().toV(), lhs.fp().toV());
  vmfeq_vv(kSimd128ScratchReg, rhs.fp().toV(), rhs.fp().toV());
  vand_vv(v0, v0, kSimd128ScratchReg);
  li(kScratchReg, kNaN);
  vmv_vx(kSimd128ScratchReg, kScratchReg);
  vfmax_vv(kSimd128ScratchReg, rhs.fp().toV(), lhs.fp().toV(), Mask);
  vmv_vv(dst.fp().toV(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i32x4_extadd_pairwise_i16x8_s(LiftoffRegister dst,
                                                          LiftoffRegister src) {
  VU.set(kScratchReg, E64, m1);
  vmv_vi(kSimd128ScratchReg, -1);
  vmv_vi(kSimd128ScratchReg3, -1);
  li(kScratchReg, 0x0006000400020000);
  vmv_sx(kSimd128ScratchReg, kScratchReg);
  li(kScratchReg, 0x0007000500030001);
  vmv_sx(kSimd128ScratchReg3, kScratchReg);
  VU.set(kScratchReg, E16, m1);
  vrgather_vv(kSimd128ScratchReg2, src.fp().toV(), kSimd128ScratchReg);
  vrgather_vv(kSimd128ScratchReg, src.fp().toV(), kSimd128ScratchReg3);
  VU.set(kScratchReg, E16, mf2);
  vwadd_vv(dst.fp().toV(), kSimd128ScratchReg, kSimd128ScratchReg2);
}

void LiftoffAssembler::emit_i32x4_extadd_pairwise_i16x8_u(LiftoffRegister dst,
                                                          LiftoffRegister src) {
  VU.set(kScratchReg, E64, m1);
  vmv_vi(kSimd128ScratchReg, -1);
  vmv_vi(kSimd128ScratchReg3, -1);
  li(kScratchReg, 0x0006000400020000);
  vmv_sx(kSimd128ScratchReg, kScratchReg);
  li(kScratchReg, 0x0007000500030001);
  vmv_sx(kSimd128ScratchReg3, kScratchReg);
  VU.set(kScratchReg, E16, m1);
  vrgather_vv(kSimd128ScratchReg2, src.fp().toV(), kSimd128ScratchReg);
  vrgather_vv(kSimd128ScratchReg, src.fp().toV(), kSimd128ScratchReg3);
  VU.set(kScratchReg, E16, mf2);
  vwaddu_vv(dst.fp().toV(), kSimd128ScratchReg, kSimd128ScratchReg2);
}

void LiftoffAssembler::emit_i16x8_extadd_pairwise_i8x16_s(LiftoffRegister dst,
                                                          LiftoffRegister src) {
  VU.set(kScratchReg, E64, m1);
  vmv_vi(kSimd128ScratchReg, -1);
  vmv_vi(kSimd128ScratchReg3, -1);
  li(kScratchReg, 0x0E0C0A0806040200);
  vmv_sx(kSimd128ScratchReg, kScratchReg);
  li(kScratchReg, 0x0F0D0B0907050301);
  vmv_sx(kSimd128ScratchReg3, kScratchReg);
  VU.set(kScratchReg, E8, m1);
  vrgather_vv(kSimd128ScratchReg2, src.fp().toV(), kSimd128ScratchReg);
  vrgather_vv(kSimd128ScratchReg, src.fp().toV(), kSimd128ScratchReg3);
  VU.set(kScratchReg, E8, mf2);
  vwadd_vv(dst.fp().toV(), kSimd128ScratchReg, kSimd128ScratchReg2);
}

void LiftoffAssembler::emit_i16x8_extadd_pairwise_i8x16_u(LiftoffRegister dst,
                                                          LiftoffRegister src) {
  VU.set(kScratchReg, E64, m1);
  vmv_vi(kSimd128ScratchReg, -1);
  vmv_vi(kSimd128ScratchReg3, -1);
  li(kScratchReg, 0x0E0C0A0806040200);
  vmv_sx(kSimd128ScratchReg, kScratchReg);
  li(kScratchReg, 0x0F0D0B0907050301);
  vmv_sx(kSimd128ScratchReg3, kScratchReg);
  VU.set(kScratchReg, E8, m1);
  vrgather_vv(kSimd128ScratchReg2, src.fp().toV(), kSimd128ScratchReg);
  vrgather_vv(kSimd128ScratchReg, src.fp().toV(), kSimd128ScratchReg3);
  VU.set(kScratchReg, E8, mf2);
  vwaddu_vv(dst.fp().toV(), kSimd128ScratchReg, kSimd128ScratchReg2);
}

void LiftoffAssembler::CallCWithStackBuffer(
    const std::initializer_list<VarState> args, const LiftoffRegister* rets,
    ValueKind return_kind, ValueKind out_argument_kind, int stack_bytes,
    ExternalReference ext_ref) {
  AddWord(sp, sp, Operand(-stack_bytes));

  int arg_offset = 0;
  for (const VarState& arg : args) {
    liftoff::StoreToMemory(this, MemOperand{sp, arg_offset}, arg);
    arg_offset += value_kind_size(arg.kind());
  }
  DCHECK_LE(arg_offset, stack_bytes);

  // Pass a pointer to the buffer with the arguments to the C function.
  // On RISC-V, the first argument is passed in {a0}.
  constexpr Register kFirstArgReg = a0;
  mv(kFirstArgReg, sp);

  // Now call the C function.
  constexpr int kNumCCallArgs = 1;
  PrepareCallCFunction(kNumCCallArgs, kScratchReg);
  CallCFunction(ext_ref, kNumCCallArgs);

  // Move return value to the right register.
  const LiftoffRegister* next_result_reg = rets;
  if (return_kind != kVoid) {
    constexpr Register kReturnReg = a0;
    if (kReturnReg != next_result_reg->gp()) {
      Move(*next_result_reg, LiftoffRegister(kReturnReg), return_kind);
    }
    ++next_result_reg;
  }

  // Load potential output value from the buffer on the stack.
  if (out_argument_kind != kVoid) {
    liftoff::Load(this, *next_result_reg, MemOperand(sp, 0), out_argument_kind);
  }

  AddWord(sp, sp, Operand(stack_bytes));
}

void LiftoffAssembler::CallC(const std::initializer_list<VarState> args_list,
                             ExternalReference ext_ref) {
  c
```