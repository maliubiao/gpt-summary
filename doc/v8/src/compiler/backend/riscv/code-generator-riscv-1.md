Response: The user wants to understand the functionality of the provided C++ code snippet, which is a part of a larger file (`code-generator-riscv.cc`). This specific part seems to handle the generation of RISC-V assembly instructions based on higher-level intermediate representation (IR) instructions.

Here's a breakdown of the thought process to arrive at the summarized functionality:

1. **Identify the Core Function:** The code is within a `switch` statement that operates on `i.opcode()`. This suggests that the code is handling different types of operations or instructions. Each `case` corresponds to a specific operation.

2. **Recognize the Context:** The file name `code-generator-riscv.cc` strongly indicates that this code is responsible for generating RISC-V assembly code. The `__` prefix before many function calls (like `__ Add`, `__ fadd_d`, `__ Lw`) is a common convention in V8 for the assembler interface.

3. **Analyze Individual Cases:** Examine the code within each `case`. Notice a pattern:
    * It takes input operands (registers, immediates, memory locations) from the `i` object (presumably an `Instruction` object).
    * It calls assembler functions (prefixed with `__`) to emit the corresponding RISC-V instructions.
    * It often manipulates registers (general-purpose and floating-point).

4. **Group Similar Cases:** Observe groups of cases that perform related operations:
    * Integer arithmetic (`kRiscvAdd`, `kRiscvSub`, etc.)
    * Floating-point arithmetic (`kRiscvAddD`, `kRiscvSubD`, etc.)
    * Memory access (`kRiscvLw`, `kRiscvSw`, `kRiscvLoadFloat`, etc.)
    * Conversions between data types (`kRiscvCvtSD`, `kRiscvCvtDW`, etc.)
    * Bitwise operations (`kRiscvAnd`, `kRiscvOr`, etc.)
    * Stack manipulation (`kRiscvPush`, `kRiscvPop`, `kRiscvStackClaim`)
    * Atomic operations (`kAtomicLoadInt8`, `kAtomicStoreWord32`, etc.)
    * SIMD/Vector operations (starting with `kRiscvRvvSt`, `kRiscvS128Zero`, etc.) - the presence of `VU` suggests Vector Unit instructions.

5. **Infer Overall Functionality:** Based on the analysis of individual cases and their groupings, conclude that this part of the code generator translates high-level operations into concrete RISC-V machine instructions. It handles a wide variety of operations, including arithmetic, logical, memory access, type conversion, and atomic operations. The latter part clearly deals with SIMD instructions, suggesting support for vectorized computations.

6. **Identify Connections to JavaScript (if any):** Consider how these operations relate to JavaScript.
    * **Arithmetic and Logical Operations:**  JavaScript has operators like `+`, `-`, `*`, `/`, `&`, `|`, `^`, which would be implemented using corresponding machine instructions.
    * **Floating-point Numbers:** JavaScript's `Number` type is typically represented as a double-precision floating-point number. The floating-point instructions are crucial for handling these.
    * **Memory Access:**  JavaScript objects and arrays are stored in memory. The load and store instructions are essential for accessing and modifying JavaScript data.
    * **Type Conversions:** JavaScript often performs implicit type conversions. The conversion instructions facilitate these.
    * **Atomic Operations:**  While not directly exposed in standard JavaScript, atomic operations are relevant in concurrent programming scenarios (e.g., using SharedArrayBuffer and Atomics).
    * **SIMD:**  JavaScript has a WebAssembly SIMD API, and the presence of these instructions indicates support for optimizing such code.

7. **Construct JavaScript Examples:**  Create simple JavaScript code snippets that would likely result in the generation of some of the handled RISC-V instructions. Focus on basic arithmetic, memory access, and type conversions.

8. **Refine the Summary:** Organize the findings into a clear and concise summary, highlighting the core functionality and its relation to JavaScript. Mention the different categories of operations handled by this code.

9. **Review and Iterate:**  Read through the summary and examples to ensure clarity, accuracy, and completeness. Make any necessary adjustments to improve the explanation. For example, explicitly mentioning WebAssembly's SIMD support provides a clearer context for the vector instructions. Also, adding a note about the `trapper` argument helps to understand potential safety mechanisms in memory access.
这是一个C++源代码文件的片段，属于V8 JavaScript引擎中RISC-V架构的代码生成器。

**功能归纳:**

这段代码的主要功能是**将高级的、平台无关的中间代码 (Instruction) 翻译成具体的RISC-V汇编指令**。它是一个大型 `switch` 语句的一部分，这个 `switch` 语句基于 `i.opcode()` 来处理不同的中间代码操作码。

具体来说，这段代码负责处理以下类型的操作：

* **整数运算:**  加法、减法、乘法、除法、取模、位运算 (与、或、异或、移位)、符号扩展等。
* **浮点数运算:**  加法、减法、乘法、除法、取模、绝对值、取反、平方根、最大值、最小值以及各种舍入操作 (向下取整、向上取整、四舍五入到偶数、截断取整)。
* **浮点数类型转换:**  单精度到双精度、双精度到单精度、整数到浮点数、浮点数到整数的转换（包括各种舍入模式）。
* **位操作和类型转换 (位模式不变):**  在整数和浮点数之间进行位模式的转换。
* **内存访问:**  加载 (load) 和存储 (store) 不同大小的数据 (字节、半字、字、双字) 到内存，包括有符号和无符号的加载，以及浮点数的加载和存储。
* **栈操作:**  压栈 (push)、弹栈 (pop，通过调整栈指针实现)、栈空间申请 (stack claim)、存储到栈槽 (store to stack slot)。
* **字节序转换:**  字节交换 (byte swap)。
* **原子操作:**  加载 (load)、存储 (store)、交换 (exchange)、比较并交换 (compare and exchange) 不同大小的整数值，用于并发编程。
* **断言:**  检查条件是否成立，不成立则触发中止。
* **压缩和解压缩Tagged值 (RISC-V64特有):**  处理V8中Tagged指针的压缩和解压缩操作。
* **加载和存储沙箱指针 (RISC-V64特有):**  处理沙箱环境下的指针加载和存储。
* **向量 (SIMD) 操作 (以 `kRiscvRvv` 和 `kRiscvS128` 开头的指令):**  包括向量的加载和存储、创建全零或全一向量、选择、非运算、常量加载、gather、slide down、车道提取和替换、移位、绝对值、类型转换、算术运算、比较运算、归约运算、shuffle、popcount 等等。

**与JavaScript的关系和JavaScript示例:**

这段代码是V8引擎的一部分，V8负责执行JavaScript代码。当V8编译JavaScript代码时，它会将JavaScript代码转换成中间代码，然后由代码生成器将中间代码翻译成目标架构（这里是RISC-V）的机器码。

因此，这段C++代码的功能直接影响JavaScript代码的执行效率和正确性。

以下是一些JavaScript示例，它们的操作可能会涉及到这段C++代码中实现的一些RISC-V指令：

**1. 算术运算和浮点数运算:**

```javascript
let a = 10;
let b = 5;
let sum = a + b; // 可能会用到 kRiscvAdd

let x = 3.14;
let y = 2.71;
let product = x * y; // 可能会用到 kRiscvMulD

let z = Math.sqrt(x); // 可能会用到 kRiscvSqrtD
```

**2. 类型转换:**

```javascript
let numStr = "123";
let num = parseInt(numStr); // 可能会用到浮点数到整数的转换指令 (如果内部先转成浮点数)

let floatNum = 42.5;
let intNum = floatNum | 0; // 位运算也可能触发浮点数到整数的转换指令 (截断)
```

**3. 内存访问 (JavaScript中的数组和对象属性访问):**

```javascript
let arr = [1, 2, 3];
let first = arr[0]; // 可能会用到 kRiscvLw 来加载数组元素

let obj = { value: 100 };
let val = obj.value; // 可能会用到 kRiscvLw 来加载对象属性值
```

**4. 原子操作 (在使用 SharedArrayBuffer 和 Atomics 时):**

```javascript
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const view = new Int32Array(sab);
Atomics.add(view, 0, 5); // 可能会用到 kAtomicAddWord32 等原子操作指令
```

**5. SIMD 操作 (WebAssembly SIMD API):**

```javascript
// 需要在WebAssembly 环境中使用
// 假设已经有 wasm 代码使用 SIMD 指令
const a = wasmModule.exports.simd_function(); // wasm 的 SIMD 函数可能会映射到 kRiscvS128Add 等指令
```

**总结:**

这段C++代码是V8引擎将JavaScript代码高效地执行在RISC-V架构上的关键组成部分。它负责将抽象的计算操作转化为底层的机器指令，涵盖了JavaScript中常见的算术运算、类型转换、内存访问以及一些高级特性（如原子操作和SIMD）。理解这段代码的功能有助于深入了解JavaScript引擎的内部工作原理。

Prompt: 
```
这是目录为v8/src/compiler/backend/riscv/code-generator-riscv.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
imm, kScratchReg, kScratchReg2);
      }
    } break;
    case kRiscvSarPair: {
      Register second_output =
          instr->OutputCount() >= 2 ? i.OutputRegister(1) : i.TempRegister(0);
      if (instr->InputAt(2)->IsRegister()) {
        __ SarPair(i.OutputRegister(0), second_output, i.InputRegister(0),
                   i.InputRegister(1), i.InputRegister(2), kScratchReg,
                   kScratchReg2);
      } else {
        uint32_t imm = i.InputOperand(2).immediate();
        __ SarPair(i.OutputRegister(0), second_output, i.InputRegister(0),
                   i.InputRegister(1), imm, kScratchReg, kScratchReg2);
      }
    } break;
#endif
    case kRiscvAddD:
      // TODO(plind): add special case: combine mult & add.
      __ fadd_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kRiscvSubD:
      __ fsub_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kRiscvMulD:
      // TODO(plind): add special case: right op is -1.0, see arm port.
      __ fmul_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kRiscvDivD:
      __ fdiv_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kRiscvModD: {
      // TODO(bmeurer): We should really get rid of this special instruction,
      // and generate a CallAddress instruction instead.
      FrameScope scope(masm(), StackFrame::MANUAL);
      __ PrepareCallCFunction(0, 2, kScratchReg);
      __ MovToFloatParameters(i.InputDoubleRegister(0),
                              i.InputDoubleRegister(1));
      __ CallCFunction(ExternalReference::mod_two_doubles_operation(), 0, 2);
      // Move the result in the double result register.
      __ MovFromFloatResult(i.OutputDoubleRegister());
      break;
    }
    case kRiscvAbsD:
      __ fabs_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kRiscvNegD:
      __ Neg_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kRiscvSqrtD: {
      __ fsqrt_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kRiscvMaxD:
      __ fmax_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kRiscvMinD:
      __ fmin_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
#if V8_TARGET_ARCH_RISCV64
    case kRiscvFloat64RoundDown: {
      __ Floor_d_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                   kScratchDoubleReg);
      break;
    }
    case kRiscvFloat64RoundTruncate: {
      __ Trunc_d_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                   kScratchDoubleReg);
      break;
    }
    case kRiscvFloat64RoundUp: {
      __ Ceil_d_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                  kScratchDoubleReg);
      break;
    }
    case kRiscvFloat64RoundTiesEven: {
      __ Round_d_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                   kScratchDoubleReg);
      break;
    }
#endif
    case kRiscvFloat32RoundDown: {
      __ Floor_s_s(i.OutputSingleRegister(), i.InputSingleRegister(0),
                   kScratchDoubleReg);
      break;
    }
    case kRiscvFloat32RoundTruncate: {
      __ Trunc_s_s(i.OutputSingleRegister(), i.InputSingleRegister(0),
                   kScratchDoubleReg);
      break;
    }
    case kRiscvFloat32RoundUp: {
      __ Ceil_s_s(i.OutputSingleRegister(), i.InputSingleRegister(0),
                  kScratchDoubleReg);
      break;
    }
    case kRiscvFloat32RoundTiesEven: {
      __ Round_s_s(i.OutputSingleRegister(), i.InputSingleRegister(0),
                   kScratchDoubleReg);
      break;
    }
    case kRiscvFloat32Max: {
      __ Float32Max(i.OutputSingleRegister(), i.InputSingleRegister(0),
                    i.InputSingleRegister(1));
      break;
    }
    case kRiscvFloat64Max: {
      __ Float64Max(i.OutputSingleRegister(), i.InputSingleRegister(0),
                    i.InputSingleRegister(1));
      break;
    }
    case kRiscvFloat32Min: {
      __ Float32Min(i.OutputSingleRegister(), i.InputSingleRegister(0),
                    i.InputSingleRegister(1));
      break;
    }
    case kRiscvFloat64Min: {
      __ Float64Min(i.OutputSingleRegister(), i.InputSingleRegister(0),
                    i.InputSingleRegister(1));
      break;
    }
    case kRiscvFloat64SilenceNaN:
      __ FPUCanonicalizeNaN(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kRiscvCvtSD: {
      Label done;
      __ feq_d(kScratchReg, i.InputDoubleRegister(0), i.InputDoubleRegister(0));
#if V8_TARGET_ARCH_RISCV64
      __ fmv_x_d(kScratchReg2, i.InputDoubleRegister(0));
#elif V8_TARGET_ARCH_RISCV32
      __ StoreDouble(i.InputDoubleRegister(0),
                     MemOperand(sp, -kDoubleSize));  // store whole 64 bit
#endif
      __ fcvt_s_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      __ Branch(&done, ne, kScratchReg, Operand(zero_reg));
#if V8_TARGET_ARCH_RISCV64
      __ And(kScratchReg2, kScratchReg2, Operand(0x8000000000000000));
      __ srai(kScratchReg2, kScratchReg2, 32);
      __ fmv_d_x(kScratchDoubleReg, kScratchReg2);
#elif V8_TARGET_ARCH_RISCV32
      __ Lw(kScratchReg2,
            MemOperand(sp,
                       -kDoubleSize /
                           2));  // only load the high half to get the sign bit
      __ fmv_w_x(kScratchDoubleReg, kScratchReg2);
#endif
      __ fsgnj_s(i.OutputDoubleRegister(), i.OutputDoubleRegister(),
                 kScratchDoubleReg);
      __ bind(&done);
      break;
    }
    case kRiscvCvtDS: {
      Label done;
      __ feq_s(kScratchReg, i.InputDoubleRegister(0), i.InputDoubleRegister(0));
#if V8_TARGET_ARCH_RISCV64
      __ fmv_x_d(kScratchReg2, i.InputDoubleRegister(0));
#elif V8_TARGET_ARCH_RISCV32
      __ StoreFloat(i.InputDoubleRegister(0), MemOperand(sp, -kFloatSize));
#endif
      __ fcvt_d_s(i.OutputDoubleRegister(), i.InputSingleRegister(0));
      __ Branch(&done, ne, kScratchReg, Operand(zero_reg));
#if V8_TARGET_ARCH_RISCV64
      __ And(kScratchReg2, kScratchReg2, Operand(0x80000000));
      __ slli(kScratchReg2, kScratchReg2, 32);
      __ fmv_d_x(kScratchDoubleReg, kScratchReg2);
#elif V8_TARGET_ARCH_RISCV32
      __ Lw(kScratchReg2, MemOperand(sp, -kFloatSize));
      __ fcvt_d_w(kScratchDoubleReg, kScratchReg2);
#endif
      __ fsgnj_d(i.OutputDoubleRegister(), i.OutputDoubleRegister(),
                 kScratchDoubleReg);
      __ bind(&done);
      break;
    }
    case kRiscvCvtDW: {
      __ fcvt_d_w(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
    case kRiscvCvtSW: {
      __ fcvt_s_w(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
    case kRiscvCvtSUw: {
      __ Cvt_s_uw(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
#if V8_TARGET_ARCH_RISCV64
    case kRiscvCvtSL: {
      __ fcvt_s_l(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
    case kRiscvCvtDL: {
      __ fcvt_d_l(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
    case kRiscvCvtDUl: {
      __ Cvt_d_ul(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
    case kRiscvCvtSUl: {
      __ Cvt_s_ul(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
#endif
    case kRiscvCvtDUw: {
      __ Cvt_d_uw(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
    case kRiscvFloorWD: {
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      __ Floor_w_d(i.OutputRegister(), i.InputDoubleRegister(0), result);
      break;
    }
    case kRiscvCeilWD: {
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      __ Ceil_w_d(i.OutputRegister(), i.InputDoubleRegister(0), result);
      break;
    }
    case kRiscvRoundWD: {
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      __ Round_w_d(i.OutputRegister(), i.InputDoubleRegister(0), result);
      break;
    }
    case kRiscvTruncWD: {
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      __ Trunc_w_d(i.OutputRegister(), i.InputDoubleRegister(0), result);
      break;
    }
    case kRiscvFloorWS: {
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      __ Floor_w_s(i.OutputRegister(), i.InputDoubleRegister(0), result);
      break;
    }
    case kRiscvCeilWS: {
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      __ Ceil_w_s(i.OutputRegister(), i.InputDoubleRegister(0), result);
      break;
    }
    case kRiscvRoundWS: {
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      __ Round_w_s(i.OutputRegister(), i.InputDoubleRegister(0), result);
      break;
    }
    case kRiscvTruncWS: {
      Label done;
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      bool set_overflow_to_min_i32 = MiscField::decode(instr->opcode());
      __ Trunc_w_s(i.OutputRegister(), i.InputDoubleRegister(0), result);

      // On RISCV, if the input value exceeds INT32_MAX, the result of fcvt
      // is INT32_MAX. Note that, since INT32_MAX means the lower 31-bits are
      // all 1s, INT32_MAX cannot be represented precisely as a float, so an
      // fcvt result of INT32_MAX always indicate overflow.
      //
      // In wasm_compiler, to detect overflow in converting a FP value, fval, to
      // integer, V8 checks whether I2F(F2I(fval)) equals fval. However, if fval
      // == INT32_MAX+1, the value of I2F(F2I(fval)) happens to be fval. So,
      // INT32_MAX is not a good value to indicate overflow. Instead, we will
      // use INT32_MIN as the converted result of an out-of-range FP value,
      // exploiting the fact that INT32_MAX+1 is INT32_MIN.
      //
      // If the result of conversion overflow, the result will be set to
      // INT32_MIN. Here we detect overflow by testing whether output + 1 <
      // output (i.e., kScratchReg  < output)
      if (set_overflow_to_min_i32) {
        __ Add32(kScratchReg, i.OutputRegister(), 1);
        __ BranchShort(&done, lt, i.OutputRegister(), Operand(kScratchReg));
        __ Move(i.OutputRegister(), kScratchReg);
        __ bind(&done);
      }
      break;
    }
#if V8_TARGET_ARCH_RISCV64
    case kRiscvTruncLS: {
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      __ Trunc_l_s(i.OutputRegister(), i.InputDoubleRegister(0), result);
      break;
    }
    case kRiscvTruncLD: {
      Label done;
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      bool set_overflow_to_min_i64 = MiscField::decode(instr->opcode());
      __ Trunc_l_d(i.OutputRegister(), i.InputDoubleRegister(0), result);
      if (set_overflow_to_min_i64) {
        __ AddWord(kScratchReg, i.OutputRegister(), 1);
        __ BranchShort(&done, lt, i.OutputRegister(), Operand(kScratchReg));
        __ Move(i.OutputRegister(), kScratchReg);
        __ bind(&done);
      }
      break;
    }
#endif
    case kRiscvTruncUwD: {
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      __ Trunc_uw_d(i.OutputRegister(), i.InputDoubleRegister(0), result);
      break;
    }
    case kRiscvTruncUwS: {
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      bool set_overflow_to_min_u32 = MiscField::decode(instr->opcode());
      __ Trunc_uw_s(i.OutputRegister(), i.InputDoubleRegister(0), result);

      // On RISCV, if the input value exceeds UINT32_MAX, the result of fcvt
      // is UINT32_MAX. Note that, since UINT32_MAX means all 32-bits are 1s,
      // UINT32_MAX cannot be represented precisely as float, so an fcvt result
      // of UINT32_MAX always indicates overflow.
      //
      // In wasm_compiler.cc, to detect overflow in converting a FP value, fval,
      // to integer, V8 checks whether I2F(F2I(fval)) equals fval. However, if
      // fval == UINT32_MAX+1, the value of I2F(F2I(fval)) happens to be fval.
      // So, UINT32_MAX is not a good value to indicate overflow. Instead, we
      // will use 0 as the converted result of an out-of-range FP value,
      // exploiting the fact that UINT32_MAX+1 is 0.
      if (set_overflow_to_min_u32) {
        __ Add32(kScratchReg, i.OutputRegister(), 1);
        // Set ouput to zero if result overflows (i.e., UINT32_MAX)
        __ LoadZeroIfConditionZero(i.OutputRegister(), kScratchReg);
      }
      break;
    }
#if V8_TARGET_ARCH_RISCV64
    case kRiscvTruncUlS: {
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      __ Trunc_ul_s(i.OutputRegister(), i.InputDoubleRegister(0), result);
      break;
    }
    case kRiscvTruncUlD: {
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      __ Trunc_ul_d(i.OutputRegister(0), i.InputDoubleRegister(0), result);
      break;
    }
    case kRiscvBitcastDL:
      __ fmv_x_d(i.OutputRegister(), i.InputDoubleRegister(0));
      break;
    case kRiscvBitcastLD:
      __ fmv_d_x(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
#endif
    case kRiscvBitcastInt32ToFloat32:
      __ fmv_w_x(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kRiscvBitcastFloat32ToInt32:
      __ fmv_x_w(i.OutputRegister(), i.InputDoubleRegister(0));
      break;
    case kRiscvFloat64ExtractLowWord32:
      __ ExtractLowWordFromF64(i.OutputRegister(), i.InputDoubleRegister(0));
      break;
    case kRiscvFloat64ExtractHighWord32:
      __ ExtractHighWordFromF64(i.OutputRegister(), i.InputDoubleRegister(0));
      break;
    case kRiscvFloat64InsertLowWord32:
      __ InsertLowWordF64(i.OutputDoubleRegister(), i.InputRegister(1));
      break;
    case kRiscvFloat64InsertHighWord32:
      __ InsertHighWordF64(i.OutputDoubleRegister(), i.InputRegister(1));
      break;
      // ... more basic instructions ...

    case kRiscvSignExtendByte:
      __ SignExtendByte(i.OutputRegister(), i.InputRegister(0));
      break;
    case kRiscvSignExtendShort:
      __ SignExtendShort(i.OutputRegister(), i.InputRegister(0));
      break;
    case kRiscvLbu:
      __ Lbu(i.OutputRegister(), i.MemoryOperand(), trapper);
      break;
    case kRiscvLb:
      __ Lb(i.OutputRegister(), i.MemoryOperand(), trapper);
      break;
    case kRiscvSb:
      __ Sb(i.InputOrZeroRegister(0), i.MemoryOperand(1), trapper);
      break;
    case kRiscvLhu:
      __ Lhu(i.OutputRegister(), i.MemoryOperand(), trapper);
      break;
    case kRiscvUlhu:
      __ Ulhu(i.OutputRegister(), i.MemoryOperand());
      break;
    case kRiscvLh:
      __ Lh(i.OutputRegister(), i.MemoryOperand(), trapper);
      break;
    case kRiscvUlh:
      __ Ulh(i.OutputRegister(), i.MemoryOperand());
      break;
    case kRiscvSh:
      __ Sh(i.InputOrZeroRegister(0), i.MemoryOperand(1), trapper);
      break;
    case kRiscvUsh:
      __ Ush(i.InputOrZeroRegister(2), i.MemoryOperand());
      break;
    case kRiscvLw:
      __ Lw(i.OutputRegister(), i.MemoryOperand(), trapper);
      break;
    case kRiscvUlw:
      __ Ulw(i.OutputRegister(), i.MemoryOperand());
      break;
#if V8_TARGET_ARCH_RISCV64
    case kRiscvLwu:
      __ Lwu(i.OutputRegister(), i.MemoryOperand(), trapper);
      break;
    case kRiscvUlwu:
      __ Ulwu(i.OutputRegister(), i.MemoryOperand());
      break;
    case kRiscvLd:
      __ Ld(i.OutputRegister(), i.MemoryOperand(), trapper);
      break;
    case kRiscvUld:
      __ Uld(i.OutputRegister(), i.MemoryOperand());
      break;
    case kRiscvSd:
      __ Sd(i.InputOrZeroRegister(0), i.MemoryOperand(1), trapper);
      break;
    case kRiscvUsd:
      __ Usd(i.InputOrZeroRegister(2), i.MemoryOperand());
      break;
#endif
    case kRiscvSw:
      __ Sw(i.InputOrZeroRegister(0), i.MemoryOperand(1), trapper);
      break;
    case kRiscvUsw:
      __ Usw(i.InputOrZeroRegister(2), i.MemoryOperand());
      break;
    case kRiscvLoadFloat: {
      __ LoadFloat(i.OutputSingleRegister(), i.MemoryOperand(), trapper);
      break;
    }
    case kRiscvULoadFloat: {
      __ ULoadFloat(i.OutputSingleRegister(), i.MemoryOperand(), kScratchReg);
      break;
    }
    case kRiscvStoreFloat: {
      MemOperand operand = i.MemoryOperand(1);
      FPURegister ft = i.InputOrZeroSingleRegister(0);
      if (ft == kSingleRegZero && !__ IsSingleZeroRegSet()) {
        __ LoadFPRImmediate(kSingleRegZero, 0.0f);
      }
      __ StoreFloat(ft, operand, trapper);
      break;
    }
    case kRiscvUStoreFloat: {
      size_t index = 0;
      MemOperand operand = i.MemoryOperand(&index);
      FPURegister ft = i.InputOrZeroSingleRegister(index);
      if (ft == kSingleRegZero && !__ IsSingleZeroRegSet()) {
        __ LoadFPRImmediate(kSingleRegZero, 0.0f);
      }
      __ UStoreFloat(ft, operand, kScratchReg);
      break;
    }
    case kRiscvLoadDouble:
      __ LoadDouble(i.OutputDoubleRegister(), i.MemoryOperand(), trapper);
      break;
    case kRiscvULoadDouble:
      __ ULoadDouble(i.OutputDoubleRegister(), i.MemoryOperand(), kScratchReg);
      break;
    case kRiscvStoreDouble: {
      FPURegister ft = i.InputOrZeroDoubleRegister(0);
      if (ft == kDoubleRegZero && !__ IsDoubleZeroRegSet()) {
        __ LoadFPRImmediate(kDoubleRegZero, 0.0);
      }
      __ StoreDouble(ft, i.MemoryOperand(1), trapper);
      break;
    }
    case kRiscvUStoreDouble: {
      FPURegister ft = i.InputOrZeroDoubleRegister(2);
      if (ft == kDoubleRegZero && !__ IsDoubleZeroRegSet()) {
        __ LoadFPRImmediate(kDoubleRegZero, 0.0);
      }
      __ UStoreDouble(ft, i.MemoryOperand(), kScratchReg);
      break;
    }
    case kRiscvSync: {
      __ sync();
      break;
    }
    case kRiscvPush:
      if (instr->InputAt(0)->IsFPRegister()) {
        __ StoreDouble(i.InputDoubleRegister(0), MemOperand(sp, -kDoubleSize));
        __ Sub32(sp, sp, Operand(kDoubleSize));
        frame_access_state()->IncreaseSPDelta(kDoubleSize / kSystemPointerSize);
      } else {
        __ Push(i.InputOrZeroRegister(0));
        frame_access_state()->IncreaseSPDelta(1);
      }
      break;
    case kRiscvPeek: {
      int reverse_slot = i.InputInt32(0);
      int offset =
          FrameSlotToFPOffset(frame()->GetTotalFrameSlotCount() - reverse_slot);
      if (instr->OutputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->OutputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ LoadDouble(i.OutputDoubleRegister(), MemOperand(fp, offset));
        } else {
          DCHECK_EQ(op->representation(), MachineRepresentation::kFloat32);
          __ LoadFloat(
              i.OutputSingleRegister(0),
              MemOperand(fp, offset + kLessSignificantWordInDoublewordOffset));
        }
      } else {
        __ LoadWord(i.OutputRegister(0), MemOperand(fp, offset));
      }
      break;
    }
    case kRiscvStackClaim: {
      __ SubWord(sp, sp, Operand(i.InputInt32(0)));
      frame_access_state()->IncreaseSPDelta(i.InputInt32(0) /
                                            kSystemPointerSize);
      break;
    }
    case kRiscvStoreToStackSlot: {
      if (instr->InputAt(0)->IsFPRegister()) {
        if (instr->InputAt(0)->IsSimd128Register()) {
          Register dst = sp;
          if (i.InputInt32(1) != 0) {
            dst = kScratchReg2;
            __ AddWord(kScratchReg2, sp, Operand(i.InputInt32(1)));
          }
          __ VU.set(kScratchReg, E8, m1);
          __ vs(i.InputSimd128Register(0), dst, 0, E8);
        } else {
#if V8_TARGET_ARCH_RISCV64
          __ StoreDouble(i.InputDoubleRegister(0),
                         MemOperand(sp, i.InputInt32(1)));
#elif V8_TARGET_ARCH_RISCV32
          if (instr->InputAt(0)->IsDoubleRegister()) {
            __ StoreDouble(i.InputDoubleRegister(0),
                           MemOperand(sp, i.InputInt32(1)));
          } else if (instr->InputAt(0)->IsFloatRegister()) {
            __ StoreFloat(i.InputSingleRegister(0),
                          MemOperand(sp, i.InputInt32(1)));
          }
#endif
        }
      } else {
        __ StoreWord(i.InputOrZeroRegister(0), MemOperand(sp, i.InputInt32(1)));
      }
      break;
    }
#if V8_TARGET_ARCH_RISCV64
    case kRiscvByteSwap64: {
      __ ByteSwap(i.OutputRegister(0), i.InputRegister(0), 8, kScratchReg);
      break;
    }
#endif
    case kRiscvByteSwap32: {
      __ ByteSwap(i.OutputRegister(0), i.InputRegister(0), 4, kScratchReg);
      break;
    }
    case kAtomicLoadInt8:
#if V8_TARGET_ARCH_RISCV64
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
#endif
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Lb);
      break;
    case kAtomicLoadUint8:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Lbu);
      break;
    case kAtomicLoadInt16:
#if V8_TARGET_ARCH_RISCV64
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
#endif
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Lh);
      break;
    case kAtomicLoadUint16:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Lhu);
      break;
    case kAtomicLoadWord32:
#if V8_TARGET_ARCH_RISCV64
      if (AtomicWidthField::decode(opcode) == AtomicWidth::kWord64) {
        ASSEMBLE_ATOMIC_LOAD_INTEGER(Lwu);
        break;
      }
#endif  // V8_TARGET_ARCH_RISCV64
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Lw);
      break;
#if V8_TARGET_ARCH_RISCV64
    case kRiscvWord64AtomicLoadUint64:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ld);
      break;
    case kRiscvWord64AtomicStoreWord64:
      ASSEMBLE_ATOMIC_STORE_INTEGER(Sd);
      break;
#endif
    case kAtomicStoreWord8:
      ASSEMBLE_ATOMIC_STORE_INTEGER(Sb);
      break;
    case kAtomicStoreWord16:
      ASSEMBLE_ATOMIC_STORE_INTEGER(Sh);
      break;
    case kAtomicStoreWord32:
      ASSEMBLE_ATOMIC_STORE_INTEGER(Sw);
      break;
#if V8_TARGET_ARCH_RISCV32
    case kRiscvWord32AtomicPairLoad: {
      FrameScope scope(masm(), StackFrame::MANUAL);
      __ AddWord(a0, i.InputRegister(0), i.InputRegister(1));
      __ PushCallerSaved(SaveFPRegsMode::kIgnore, a0, a1);
      __ PrepareCallCFunction(1, 0, kScratchReg);
      __ CallCFunction(ExternalReference::atomic_pair_load_function(), 1, 0);
      __ PopCallerSaved(SaveFPRegsMode::kIgnore, a0, a1);
      break;
    }
    case kRiscvWord32AtomicPairStore: {
      FrameScope scope(masm(), StackFrame::MANUAL);
      __ AddWord(a0, i.InputRegister(0), i.InputRegister(1));
      __ PushCallerSaved(SaveFPRegsMode::kIgnore);
      __ PrepareCallCFunction(3, 0, kScratchReg);
      __ CallCFunction(ExternalReference::atomic_pair_store_function(), 3, 0);
      __ PopCallerSaved(SaveFPRegsMode::kIgnore);
      break;
    }
#define ATOMIC64_BINOP_ARITH_CASE(op, instr, external) \
  case kRiscvWord32AtomicPair##op:                     \
    ASSEMBLE_ATOMIC64_ARITH_BINOP(instr, external);    \
    break;
      ATOMIC64_BINOP_ARITH_CASE(Add, AddPair, atomic_pair_add_function)
      ATOMIC64_BINOP_ARITH_CASE(Sub, SubPair, atomic_pair_sub_function)
#undef ATOMIC64_BINOP_ARITH_CASE
#define ATOMIC64_BINOP_LOGIC_CASE(op, instr, external) \
  case kRiscvWord32AtomicPair##op:                     \
    ASSEMBLE_ATOMIC64_LOGIC_BINOP(instr, external);    \
    break;
      ATOMIC64_BINOP_LOGIC_CASE(And, AndPair, atomic_pair_and_function)
      ATOMIC64_BINOP_LOGIC_CASE(Or, OrPair, atomic_pair_or_function)
      ATOMIC64_BINOP_LOGIC_CASE(Xor, XorPair, atomic_pair_xor_function)
    case kRiscvWord32AtomicPairExchange: {
      FrameScope scope(masm(), StackFrame::MANUAL);
      __ PushCallerSaved(SaveFPRegsMode::kIgnore, a0, a1);
      __ PrepareCallCFunction(3, 0, kScratchReg);
      __ AddWord(a0, i.InputRegister(0), i.InputRegister(1));
      __ CallCFunction(ExternalReference::atomic_pair_exchange_function(), 3,
                       0);
      __ PopCallerSaved(SaveFPRegsMode::kIgnore, a0, a1);
      break;
    }
    case kRiscvWord32AtomicPairCompareExchange: {
      FrameScope scope(masm(), StackFrame::MANUAL);
      __ PushCallerSaved(SaveFPRegsMode::kIgnore, a0, a1);
      __ PrepareCallCFunction(5, 0, kScratchReg);
      __ add(a0, i.InputRegister(0), i.InputRegister(1));
      __ CallCFunction(
          ExternalReference::atomic_pair_compare_exchange_function(), 5, 0);
      __ PopCallerSaved(SaveFPRegsMode::kIgnore, a0, a1);
      break;
    }
#endif
    case kAtomicExchangeInt8:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll, Sc, true, 8, 32);
      break;
    case kAtomicExchangeUint8:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll, Sc, false, 8, 32);
          break;
        case AtomicWidth::kWord64:
#if V8_TARGET_ARCH_RISCV64
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Lld, Scd, false, 8, 64);
          break;
#endif
        default:
          UNREACHABLE();
      }
      break;
    case kAtomicExchangeInt16:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll, Sc, true, 16, 32);
      break;
    case kAtomicExchangeUint16:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll, Sc, false, 16, 32);
          break;
#if V8_TARGET_ARCH_RISCV64
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Lld, Scd, false, 16, 64);
          break;
#endif
        default:
          UNREACHABLE();
      }
      break;
    case kAtomicExchangeWord32:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(Ll, Sc);
          break;
#if V8_TARGET_ARCH_RISCV64
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Lld, Scd, false, 32, 64);
          break;
#endif
        default:
          UNREACHABLE();
      }
      break;
#if V8_TARGET_ARCH_RISCV64
    case kRiscvWord64AtomicExchangeUint64:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(Lld, Scd);
      break;
#endif
    case kAtomicCompareExchangeInt8:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll, Sc, true, 8, 32);
      break;
    case kAtomicCompareExchangeUint8:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll, Sc, false, 8, 32);
          break;
#if V8_TARGET_ARCH_RISCV64
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Lld, Scd, false, 8, 64);
          break;
#endif
        default:
          UNREACHABLE();
      }
      break;
    case kAtomicCompareExchangeInt16:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll, Sc, true, 16, 32);
      break;
    case kAtomicCompareExchangeUint16:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll, Sc, false, 16, 32);
          break;
#if V8_TARGET_ARCH_RISCV64
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Lld, Scd, false, 16, 64);
          break;
#endif
        default:
          UNREACHABLE();
      }
      break;
    case kAtomicCompareExchangeWord32:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ Sll32(i.InputRegister(2), i.InputRegister(2), 0);
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(Ll, Sc);
          break;
#if V8_TARGET_ARCH_RISCV64
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Lld, Scd, false, 32, 64);
          break;
#endif
        default:
          UNREACHABLE();
      }
      break;
#if V8_TARGET_ARCH_RISCV64
    case kRiscvWord64AtomicCompareExchangeUint64:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(Lld, Scd);
      break;
#define ATOMIC_BINOP_CASE(op, inst32, inst64)                          \
  case kAtomic##op##Int8:                                              \
    DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32); \
    ASSEMBLE_ATOMIC_BINOP_EXT(Ll, Sc, true, 8, inst32, 32);            \
    break;                                                             \
  case kAtomic##op##Uint8:                                             \
    switch (AtomicWidthField::decode(opcode)) {                        \
      case AtomicWidth::kWord32:                                       \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll, Sc, false, 8, inst32, 32);       \
        break;                                                         \
      case AtomicWidth::kWord64:                                       \
        ASSEMBLE_ATOMIC_BINOP_EXT(Lld, Scd, false, 8, inst64, 64);     \
        break;                                                         \
    }                                                                  \
    break;                                                             \
  case kAtomic##op##Int16:                                             \
    DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32); \
    ASSEMBLE_ATOMIC_BINOP_EXT(Ll, Sc, true, 16, inst32, 32);           \
    break;                                                             \
  case kAtomic##op##Uint16:                                            \
    switch (AtomicWidthField::decode(opcode)) {                        \
      case AtomicWidth::kWord32:                                       \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll, Sc, false, 16, inst32, 32);      \
        break;                                                         \
      case AtomicWidth::kWord64:                                       \
        ASSEMBLE_ATOMIC_BINOP_EXT(Lld, Scd, false, 16, inst64, 64);    \
        break;                                                         \
    }                                                                  \
    break;                                                             \
  case kAtomic##op##Word32:                                            \
    switch (AtomicWidthField::decode(opcode)) {                        \
      case AtomicWidth::kWord32:                                       \
        ASSEMBLE_ATOMIC_BINOP(Ll, Sc, inst32);                         \
        break;                                                         \
      case AtomicWidth::kWord64:                                       \
        ASSEMBLE_ATOMIC_BINOP_EXT(Lld, Scd, false, 32, inst64, 64);    \
        break;                                                         \
    }                                                                  \
    break;                                                             \
  case kRiscvWord64Atomic##op##Uint64:                                 \
    ASSEMBLE_ATOMIC_BINOP(Lld, Scd, inst64);                           \
    break;
      ATOMIC_BINOP_CASE(Add, Add32, AddWord)
      ATOMIC_BINOP_CASE(Sub, Sub32, Sub64)
      ATOMIC_BINOP_CASE(And, And, And)
      ATOMIC_BINOP_CASE(Or, Or, Or)
      ATOMIC_BINOP_CASE(Xor, Xor, Xor)
#undef ATOMIC_BINOP_CASE
#elif V8_TARGET_ARCH_RISCV32
#define ATOMIC_BINOP_CASE(op, inst32, inst64, amoinst32)                   \
  case kAtomic##op##Int8:                                                  \
    ASSEMBLE_ATOMIC_BINOP_EXT(Ll, Sc, true, 8, inst32, 32);                \
    break;                                                                 \
  case kAtomic##op##Uint8:                                                 \
    ASSEMBLE_ATOMIC_BINOP_EXT(Ll, Sc, false, 8, inst32, 32);               \
    break;                                                                 \
  case kAtomic##op##Int16:                                                 \
    ASSEMBLE_ATOMIC_BINOP_EXT(Ll, Sc, true, 16, inst32, 32);               \
    break;                                                                 \
  case kAtomic##op##Uint16:                                                \
    ASSEMBLE_ATOMIC_BINOP_EXT(Ll, Sc, false, 16, inst32, 32);              \
    break;                                                                 \
  case kAtomic##op##Word32:                                                \
    __ AddWord(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1)); \
    __ amoinst32(true, true, i.OutputRegister(0), i.TempRegister(0),       \
                 i.InputRegister(2));                                      \
    break;
      ATOMIC_BINOP_CASE(Add, Add32, Add64, amoadd_w)  // todo: delete 64
      ATOMIC_BINOP_CASE(Sub, Sub32, Sub64, Amosub_w)  // todo: delete 64
      ATOMIC_BINOP_CASE(And, And, And, amoand_w)
      ATOMIC_BINOP_CASE(Or, Or, Or, amoor_w)
      ATOMIC_BINOP_CASE(Xor, Xor, Xor, amoxor_w)
#undef ATOMIC_BINOP_CASE
#endif
    case kRiscvAssertEqual:
      __ Assert(eq, static_cast<AbortReason>(i.InputOperand(2).immediate()),
                i.InputRegister(0), Operand(i.InputRegister(1)));
      break;
#if V8_TARGET_ARCH_RISCV64
    case kRiscvStoreCompressTagged: {
      MemOperand mem = i.MemoryOperand(1);
      __ StoreTaggedField(i.InputOrZeroRegister(0), mem);
      break;
    }
    case kRiscvLoadDecompressTaggedSigned: {
      CHECK(instr->HasOutput());
      Register result = i.OutputRegister();
      MemOperand operand = i.MemoryOperand();
      __ DecompressTaggedSigned(result, operand);
      break;
    }
    case kRiscvLoadDecompressTagged: {
      CHECK(instr->HasOutput());
      Register result = i.OutputRegister();
      MemOperand operand = i.MemoryOperand();
      __ DecompressTagged(result, operand);
      break;
    }
    case kRiscvLoadDecodeSandboxedPointer:
      __ LoadSandboxedPointerField(i.OutputRegister(), i.MemoryOperand());
      break;
    case kRiscvStoreEncodeSandboxedPointer: {
      MemOperand mem = i.MemoryOperand(1);
      __ StoreSandboxedPointerField(i.InputOrZeroRegister(0), mem);
      break;
    }
    case kRiscvStoreIndirectPointer: {
      MemOperand mem = i.MemoryOperand(1);
      __ StoreIndirectPointerField(i.InputOrZeroRegister(0), mem);
      break;
    }
    case kRiscvAtomicLoadDecompressTaggedSigned:
      __ AtomicDecompressTaggedSigned(i.OutputRegister(), i.MemoryOperand());
      break;
    case kRiscvAtomicLoadDecompressTagged:
      __ AtomicDecompressTagged(i.OutputRegister(), i.MemoryOperand());
      break;
    case kRiscvAtomicStoreCompressTagged: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      __ AtomicStoreTaggedField(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kRiscvLoadDecompressProtected: {
      __ DecompressProtected(i.OutputRegister(), i.MemoryOperand(), trapper);
      break;
    }
#endif
    case kRiscvRvvSt: {
      (__ VU).set(kScratchReg, VSew::E8, Vlmul::m1);
      auto memOperand = i.MemoryOperand(1);
      Register dst = memOperand.offset() == 0 ? memOperand.rm() : kScratchReg;
      if (memOperand.offset() != 0) {
        __ AddWord(dst, memOperand.rm(), memOperand.offset());
      }
      trapper(__ pc_offset());
      __ vs(i.InputSimd128Register(0), dst, 0, VSew::E8);
      break;
    }
    case kRiscvRvvLd: {
      (__ VU).set(kScratchReg, VSew::E8, Vlmul::m1);
      Register src = i.MemoryOperand().offset() == 0 ? i.MemoryOperand().rm()
                                                     : kScratchReg;
      if (i.MemoryOperand().offset() != 0) {
        __ AddWord(src, i.MemoryOperand().rm(), i.MemoryOperand().offset());
      }
      trapper(__ pc_offset());
      __ vl(i.OutputSimd128Register(), src, 0, VSew::E8);
      break;
    }
    case kRiscvS128Zero: {
      Simd128Register dst = i.OutputSimd128Register();
      __ VU.set(kScratchReg, E8, m1);
      __ vmv_vx(dst, zero_reg);
      break;
    }
    case kRiscvS128Load32Zero: {
      Simd128Register dst = i.OutputSimd128Register();
      __ VU.set(kScratchReg, E32, m1);
      __ Load32U(kScratchReg, i.MemoryOperand(), trapper);
      __ vmv_sx(dst, kScratchReg);
      break;
    }
    case kRiscvS128Load64Zero: {
      Simd128Register dst = i.OutputSimd128Register();
      __ VU.set(kScratchReg, E64, m1);
#if V8_TARGET_ARCH_RISCV64
      __ LoadWord(kScratchReg, i.MemoryOperand(), trapper);
      __ vmv_sx(dst, kScratchReg);
#elif V8_TARGET_ARCH_RISCV32
      __ LoadDouble(kScratchDoubleReg, i.MemoryOperand(), trapper);
      __ vfmv_sf(dst, kScratchDoubleReg);
#endif
      break;
    }
    case kRiscvS128LoadLane: {
      Simd128Register dst = i.OutputSimd128Register();
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      auto sz = LaneSizeField::decode(opcode);
      __ LoadLane(sz, dst, i.InputUint8(1), i.MemoryOperand(2), trapper);
      break;
    }
    case kRiscvS128StoreLane: {
      Simd128Register src = i.InputSimd128Register(0);
      DCHECK_EQ(src, i.InputSimd128Register(0));
      auto sz = LaneSizeField::decode(opcode);
      __ StoreLane(sz, src, i.InputUint8(1), i.MemoryOperand(2), trapper);
      break;
    }
    case kRiscvS128Load64ExtendS: {
      __ VU.set(kScratchReg, E64, m1);
#if V8_TARGET_ARCH_RISCV64
      __ LoadWord(kScratchReg, i.MemoryOperand(), trapper);
      __ vmv_vx(kSimd128ScratchReg, kScratchReg);
#elif V8_TARGET_ARCH_RISCV32
      __ LoadDouble(kScratchDoubleReg, i.MemoryOperand(), trapper);
      __ vfmv_vf(kSimd128ScratchReg, kScratchDoubleReg);
#endif
      __ VU.set(kScratchReg, i.InputInt8(2), m1);
      __ vsext_vf2(i.OutputSimd128Register(), kSimd128ScratchReg);
      break;
    }
    case kRiscvS128Load64ExtendU: {
      __ VU.set(kScratchReg, E64, m1);
#if V8_TARGET_ARCH_RISCV64
      __ LoadWord(kScratchReg, i.MemoryOperand(), trapper);
      __ vmv_vx(kSimd128ScratchReg, kScratchReg);
#elif V8_TARGET_ARCH_RISCV32
      __ LoadDouble(kScratchDoubleReg, i.MemoryOperand(), trapper);
      __ vfmv_vf(kSimd128ScratchReg, kScratchDoubleReg);
#endif
      __ VU.set(kScratchReg, i.InputInt8(2), m1);
      __ vzext_vf2(i.OutputSimd128Register(), kSimd128ScratchReg);
      break;
    }
    case kRiscvS128LoadSplat: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      switch (i.InputInt8(2)) {
        case E8:
          __ Lb(kScratchReg, i.MemoryOperand(), trapper);
          __ vmv_vx(i.OutputSimd128Register(), kScratchReg);
          break;
        case E16:
          __ Lh(kScratchReg, i.MemoryOperand(), trapper);
          __ vmv_vx(i.OutputSimd128Register(), kScratchReg);
          break;
        case E32:
          __ Lw(kScratchReg, i.MemoryOperand(), trapper);
          __ vmv_vx(i.OutputSimd128Register(), kScratchReg);
          break;
        case E64:
#if V8_TARGET_ARCH_RISCV64
          __ LoadWord(kScratchReg, i.MemoryOperand(), trapper);
          __ vmv_vx(i.OutputSimd128Register(), kScratchReg);
#elif V8_TARGET_ARCH_RISCV32
          __ LoadDouble(kScratchDoubleReg, i.MemoryOperand(), trapper);
          __ vfmv_vf(i.OutputSimd128Register(), kScratchDoubleReg);
#endif
          break;
        default:
          UNREACHABLE();
      }
      break;
    }
    case kRiscvS128AllOnes: {
      __ VU.set(kScratchReg, E8, m1);
      __ vmv_vx(i.OutputSimd128Register(), zero_reg);
      __ vnot_vv(i.OutputSimd128Register(), i.OutputSimd128Register());
      break;
    }
    case kRiscvS128Select: {
      __ VU.set(kScratchReg, E8, m1);
      __ vand_vv(kSimd128ScratchReg, i.InputSimd128Register(1),
                 i.InputSimd128Register(0));
      __ vnot_vv(kSimd128ScratchReg2, i.InputSimd128Register(0));
      __ vand_vv(kSimd128ScratchReg2, i.InputSimd128Register(2),
                 kSimd128ScratchReg2);
      __ vor_vv(i.OutputSimd128Register(), kSimd128ScratchReg,
                kSimd128ScratchReg2);
      break;
    }
    case kRiscvVnot: {
      (__ VU).set(kScratchReg, VSew::E8, Vlmul::m1);
      __ vnot_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvS128Const: {
      Simd128Register dst = i.OutputSimd128Register();
      uint8_t imm[16];
      *reinterpret_cast<uint64_t*>(imm) =
          make_uint64(i.InputUint32(1), i.InputUint32(0));
      *(reinterpret_cast<uint64_t*>(imm) + 1) =
          make_uint64(i.InputUint32(3), i.InputUint32(2));
      __ WasmRvvS128const(dst, imm);
      break;
    }
    case kRiscvVrgather: {
      Simd128Register index = i.InputSimd128Register(0);
      if (!(instr->InputAt(1)->IsImmediate())) {
        index = i.InputSimd128Register(1);
      } else {
#if V8_TARGET_ARCH_RISCV64
        __ VU.set(kScratchReg, E64, m1);
        __ li(kScratchReg, i.InputInt64(1));
        __ vmv_vi(kSimd128ScratchReg3, -1);
        __ vmv_sx(kSimd128ScratchReg3, kScratchReg);
        index = kSimd128ScratchReg3;
#elif V8_TARGET_ARCH_RISCV32
        int64_t intput_int64 = i.InputInt64(1);
        int32_t input_int32[2];
        memcpy(input_int32, &intput_int64, sizeof(intput_int64));
        __ VU.set(kScratchReg, E32, m1);
        __ li(kScratchReg, input_int32[1]);
        __ vmv_vx(kSimd128ScratchReg3, kScratchReg);
        __ li(kScratchReg, input_int32[0]);
        __ vmv_sx(kSimd128ScratchReg3, kScratchReg);
        index = kSimd128ScratchReg3;
#endif
      }
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      if (i.OutputSimd128Register() == i.InputSimd128Register(0)) {
        __ vrgather_vv(kSimd128ScratchReg, i.InputSimd128Register(0), index);
        __ vmv_vv(i.OutputSimd128Register(), kSimd128ScratchReg);
      } else {
        __ vrgather_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                       index);
      }
      break;
    }
    case kRiscvVslidedown: {
      __ VU.set(kScratchReg, i.InputInt8(2), i.InputInt8(3));
      if (instr->InputAt(1)->IsImmediate()) {
        DCHECK(is_uint5(i.InputInt32(1)));
        __ vslidedown_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                         i.InputInt5(1));
      } else {
        __ vslidedown_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                         i.InputRegister(1));
      }
      break;
    }
    case kRiscvI8x16ExtractLaneU: {
      __ VU.set(kScratchReg, E8, m1);
      __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0),
                       i.InputInt8(1));
      __ vmv_xs(i.OutputRegister(), kSimd128ScratchReg);
      __ slli(i.OutputRegister(), i.OutputRegister(), sizeof(void*) * 8 - 8);
      __ srli(i.OutputRegister(), i.OutputRegister(), sizeof(void*) * 8 - 8);
      break;
    }
    case kRiscvI8x16ExtractLaneS: {
      __ VU.set(kScratchReg, E8, m1);
      __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0),
                       i.InputInt8(1));
      __ vmv_xs(i.OutputRegister(), kSimd128ScratchReg);
      break;
    }
    case kRiscvI16x8ExtractLaneU: {
      __ VU.set(kScratchReg, E16, m1);
      __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0),
                       i.InputInt8(1));
      __ vmv_xs(i.OutputRegister(), kSimd128ScratchReg);
      __ slli(i.OutputRegister(), i.OutputRegister(), sizeof(void*) * 8 - 16);
      __ srli(i.OutputRegister(), i.OutputRegister(), sizeof(void*) * 8 - 16);
      break;
    }
    case kRiscvI16x8ExtractLaneS: {
      __ VU.set(kScratchReg, E16, m1);
      __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0),
                       i.InputInt8(1));
      __ vmv_xs(i.OutputRegister(), kSimd128ScratchReg);
      break;
    }
    case kRiscvI8x16ShrU: {
      __ VU.set(kScratchReg, E8, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ andi(i.InputRegister(1), i.InputRegister(1), 8 - 1);
        __ vsrl_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        __ vsrl_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputInt5(1) % 8);
      }
      break;
    }
    case kRiscvI16x8ShrU: {
      __ VU.set(kScratchReg, E16, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ andi(i.InputRegister(1), i.InputRegister(1), 16 - 1);
        __ vsrl_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        __ vsrl_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputInt5(1) % 16);
      }
      break;
    }
    case kRiscvI32x4TruncSatF64x2SZero: {
      __ VU.set(kScratchReg, E64, m1);
      __ vmv_vx(kSimd128ScratchReg, zero_reg);
      __ vmfeq_vv(v0, i.InputSimd128Register(0), i.InputSimd128Register(0));
      __ vmv_vv(kSimd128ScratchReg3, i.InputSimd128Register(0));
      __ VU.set(kScratchReg, E32, m1);
      __ VU.set(FPURoundingMode::RTZ);
      __ vfncvt_x_f_w(kSimd128ScratchReg, kSimd128ScratchReg3, MaskType::Mask);
      __ vmv_vv(i.OutputSimd128Register(), kSimd128ScratchReg);
      break;
    }
    case kRiscvI32x4TruncSatF64x2UZero: {
      __ VU.set(kScratchReg, E64, m1);
      __ vmv_vx(kSimd128ScratchReg, zero_reg);
      __ vmfeq_vv(v0, i.InputSimd128Register(0), i.InputSimd128Register(0));
      __ vmv_vv(kSimd128ScratchReg3, i.InputSimd128Register(0));
      __ VU.set(kScratchReg, E32, m1);
      __ VU.set(FPURoundingMode::RTZ);
      __ vfncvt_xu_f_w(kSimd128ScratchReg, kSimd128ScratchReg3, MaskType::Mask);
      __ vmv_vv(i.OutputSimd128Register(), kSimd128ScratchReg);
      break;
    }
    case kRiscvI32x4ShrU: {
      __ VU.set(kScratchReg, E32, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsrl_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        __ vsrl_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputInt5(1) % 32);
      }
      break;
    }
    case kRiscvI64x2ShrU: {
      __ VU.set(kScratchReg, E64, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsrl_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        if (is_uint5(i.InputInt6(1) % 64)) {
          __ vsrl_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputInt6(1) % 64);
        } else {
          __ li(kScratchReg, i.InputInt6(1) % 64);
          __ vsrl_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     kScratchReg);
        }
      }
      break;
    }
    case kRiscvI8x16ShrS: {
      __ VU.set(kScratchReg, E8, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsra_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        __ vsra_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputInt5(1) % 8);
      }
      break;
    }
    case kRiscvI16x8ShrS: {
      __ VU.set(kScratchReg, E16, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsra_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        __ vsra_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputInt5(1) % 16);
      }
      break;
    }
    case kRiscvI32x4ShrS: {
      __ VU.set(kScratchReg, E32, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsra_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        __ vsra_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputInt5(1) % 32);
      }
      break;
    }
    case kRiscvI64x2ShrS: {
      __ VU.set(kScratchReg, E64, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsra_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        if (is_uint5(i.InputInt6(1) % 64)) {
          __ vsra_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputInt6(1) % 64);
        } else {
          __ li(kScratchReg, i.InputInt6(1) % 64);
          __ vsra_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     kScratchReg);
        }
      }
      break;
    }
    case kRiscvI32x4ExtractLane: {
      __ WasmRvvExtractLane(i.OutputRegister(), i.InputSimd128Register(0),
                            i.InputInt8(1), E32, m1);
      break;
    }
    case kRiscvVAbs: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      __ vmv_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      __ vmslt_vx(v0, i.InputSimd128Register(0), zero_reg);
      __ vneg_vv(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 MaskType::Mask);
      break;
    }
#if V8_TARGET_ARCH_RISCV64
    case kRiscvI64x2ExtractLane: {
      __ WasmRvvExtractLane(i.OutputRegister(), i.InputSimd128Register(0),
                            i.InputInt8(1), E64, m1);
      break;
    }
#elif V8_TARGET_ARCH_RISCV32
    case kRiscvI64x2ExtractLane: {
      uint8_t imm_lane_idx = i.InputInt8(1);
      __ VU.set(kScratchReg, E32, m1);
      __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0),
                       (imm_lane_idx << 0x1) + 1);
      __ vmv_xs(i.OutputRegister(1), kSimd128ScratchReg);
      __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0),
                       (imm_lane_idx << 0x1));
      __ vmv_xs(i.OutputRegister(0), kSimd128ScratchReg);
      break;
    }
#endif
    case kRiscvI8x16Shl: {
      __ VU.set(kScratchReg, E8, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsll_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        __ vsll_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputInt5(1) % 8);
      }
      break;
    }
    case kRiscvI16x8Shl: {
      __ VU.set(kScratchReg, E16, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsll_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        __ vsll_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputInt5(1) % 16);
      }
      break;
    }
    case kRiscvI32x4Shl: {
      __ VU.set(kScratchReg, E32, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsll_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        __ vsll_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputInt5(1) % 32);
      }
      break;
    }
    case kRiscvI64x2Shl: {
      __ VU.set(kScratchReg, E64, m1);
      if (instr->InputAt(1)->IsRegister()) {
        __ vsll_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputRegister(1));
      } else {
        if (is_int5(i.InputInt6(1) % 64)) {
          __ vsll_vi(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputInt6(1) % 64);
        } else {
          __ li(kScratchReg, i.InputInt6(1) % 64);
          __ vsll_vx(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     kScratchReg);
        }
      }
      break;
    }
    case kRiscvI8x16ReplaceLane: {
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register dst = i.OutputSimd128Register();
      __ VU.set(kScratchReg, E64, m1);
      __ li(kScratchReg, 0x1 << i.InputInt8(1));
      __ vmv_sx(v0, kScratchReg);
      __ VU.set(kScratchReg, E8, m1);
      __ vmerge_vx(dst, i.InputRegister(2), src);
      break;
    }
    case kRiscvI16x8ReplaceLane: {
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register dst = i.OutputSimd128Register();
      __ VU.set(kScratchReg, E16, m1);
      __ li(kScratchReg, 0x1 << i.InputInt8(1));
      __ vmv_sx(v0, kScratchReg);
      __ vmerge_vx(dst, i.InputRegister(2), src);
      break;
    }
#if V8_TARGET_ARCH_RISCV64
    case kRiscvI64x2ReplaceLane: {
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register dst = i.OutputSimd128Register();
      __ VU.set(kScratchReg, E64, m1);
      __ li(kScratchReg, 0x1 << i.InputInt8(1));
      __ vmv_sx(v0, kScratchReg);
      __ vmerge_vx(dst, i.InputRegister(2), src);
      break;
    }
#elif V8_TARGET_ARCH_RISCV32
    case kRiscvI64x2ReplaceLaneI32Pair: {
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register dst = i.OutputSimd128Register();
      Register int64_low = i.InputRegister(2);
      Register int64_high = i.InputRegister(3);
      __ VU.set(kScratchReg, E32, m1);
      __ vmv_vx(kSimd128ScratchReg, int64_high);
      __ vmv_sx(kSimd128ScratchReg, int64_low);
      __ VU.set(kScratchReg, E64, m1);
      __ li(kScratchReg, 0x1 << i.InputInt8(1));
      __ vmv_sx(v0, kScratchReg);
      __ vfmv_fs(kScratchDoubleReg, kSimd128ScratchReg);
      __ vfmerge_vf(dst, kScratchDoubleReg, src);
      break;
    }
#endif
    case kRiscvI32x4ReplaceLane: {
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register dst = i.OutputSimd128Register();
      __ VU.set(kScratchReg, E32, m1);
      __ li(kScratchReg, 0x1 << i.InputInt8(1));
      __ vmv_sx(v0, kScratchReg);
      __ vmerge_vx(dst, i.InputRegister(2), src);
      break;
    }
    case kRiscvV128AnyTrue: {
      __ VU.set(kScratchReg, E8, m1);
      Register dst = i.OutputRegister();
      Label t;
      __ vmv_sx(kSimd128ScratchReg, zero_reg);
      __ vredmaxu_vs(kSimd128ScratchReg, i.InputSimd128Register(0),
                     kSimd128ScratchReg);
      __ vmv_xs(dst, kSimd128ScratchReg);
      __ beq(dst, zero_reg, &t);
      __ li(dst, 1);
      __ bind(&t);
      break;
    }
    case kRiscvVAllTrue: {
      __ VU.set(kScratchReg, i.InputInt8(1), i.InputInt8(2));
      Register dst = i.OutputRegister();
      Label notalltrue;
      __ vmv_vi(kSimd128ScratchReg, -1);
      __ vredminu_vs(kSimd128ScratchReg, i.InputSimd128Register(0),
                     kSimd128ScratchReg);
      __ vmv_xs(dst, kSimd128ScratchReg);
      __ beqz(dst, &notalltrue);
      __ li(dst, 1);
      __ bind(&notalltrue);
      break;
    }
    case kRiscvI8x16Shuffle: {
      VRegister dst = i.OutputSimd128Register(),
                src0 = i.InputSimd128Register(0),
                src1 = i.InputSimd128Register(1);

#if V8_TARGET_ARCH_RISCV64
      int64_t imm1 = make_uint64(i.InputInt32(3), i.InputInt32(2));
      int64_t imm2 = make_uint64(i.InputInt32(5), i.InputInt32(4));
      __ VU.set(kScratchReg, VSew::E64, Vlmul::m1);
      __ li(kScratchReg, imm2);
      __ vmv_sx(kSimd128ScratchReg2, kScratchReg);
      __ vslideup_vi(kSimd128ScratchReg, kSimd128ScratchReg2, 1);
      __ li(kScratchReg, imm1);
      __ vmv_sx(kSimd128ScratchReg, kScratchReg);
#elif V8_TARGET_ARCH_RISCV32
      __ VU.set(kScratchReg, VSew::E32, Vlmul::m1);
      __ li(kScratchReg, i.InputInt32(5));
      __ vmv_vx(kSimd128ScratchReg2, kScratchReg);
      __ li(kScratchReg, i.InputInt32(4));
      __ vmv_sx(kSimd128ScratchReg2, kScratchReg);
      __ li(kScratchReg, i.InputInt32(3));
      __ vmv_vx(kSimd128ScratchReg, kScratchReg);
      __ li(kScratchReg, i.InputInt32(2));
      __ vmv_sx(kSimd128ScratchReg, kScratchReg);
      __ vslideup_vi(kSimd128ScratchReg, kSimd128ScratchReg2, 2);
#endif

      __ VU.set(kScratchReg, E8, m1);
      if (dst == src0) {
        __ vmv_vv(kSimd128ScratchReg2, src0);
        src0 = kSimd128ScratchReg2;
      } else if (dst == src1) {
        __ vmv_vv(kSimd128ScratchReg2, src1);
        src1 = kSimd128ScratchReg2;
      }
      __ vrgather_vv(dst, src0, kSimd128ScratchReg);
      __ vadd_vi(kSimd128ScratchReg, kSimd128ScratchReg, -16);
      __ vrgather_vv(kSimd128ScratchReg3, src1, kSimd128ScratchReg);
      __ vor_vv(dst, dst, kSimd128ScratchReg3);
      break;
    }
    case kRiscvI8x16Popcnt: {
      VRegister dst = i.OutputSimd128Register(),
                src = i.InputSimd128Register(0);
      Label t;

      __ VU.set(kScratchReg, E8, m1);
      __ vmv_vv(kSimd128ScratchReg, src);
      __ vmv_vv(dst, kSimd128RegZero);

      __ bind(&t);
      __ vmsne_vv(v0, kSimd128ScratchReg, kSimd128RegZero);
      __ vadd_vi(dst, dst, 1, Mask);
      __ vadd_vi(kSimd128ScratchReg2, kSimd128ScratchReg, -1, Mask);
      __ vand_vv(kSimd128ScratchReg, kSimd128ScratchReg, kSimd128ScratchReg2);
      // kScratchReg = -1 if kSimd128ScratchReg == 0 i.e. no active element
      __ vfirst_m(kScratchReg, kSimd128ScratchReg);
      __ bgez(kScratchReg, &t);
      break;
    }
    case kRiscvF64x2NearestInt: {
      __ Round_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kScratchReg, kSimd128ScratchReg);
      break;
    }
    case kRiscvF64x2Trunc: {
      __ Trunc_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kScratchReg, kSimd128ScratchReg);
      break;
    }
    case kRiscvF64x2Sqrt: {
      __ VU.set(kScratchReg, E64, m1);
      __ vfsqrt_v(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvF64x2Abs: {
      __ VU.set(kScratchReg, VSew::E64, Vlmul::m1);
      __ vfabs_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvF64x2Ceil: {
      __ Ceil_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                kScratchReg, kSimd128ScratchReg);
      break;
    }
    case kRiscvF64x2Floor: {
      __ Floor_d(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kScratchReg, kSimd128ScratchReg);
      break;
    }
    case kRiscvF64x2ReplaceLane: {
      __ VU.set(kScratchReg, E64, m1);
      __ li(kScratchReg, 0x1 << i.InputInt8(1));
      __ vmv_sx(v0, kScratchReg);
      __ vfmerge_vf(i.OutputSimd128Register(), i.InputSingleRegister(2),
                    i.InputSimd128Register(0));
      break;
    }
    case kRiscvF64x2Pmax: {
      __ VU.set(kScratchReg, E64, m1);
      __ vmflt_vv(v0, i.InputSimd128Register(0), i.InputSimd128Register(1));
      __ vmerge_vv(i.OutputSimd128Register(), i.InputSimd128Register(1),
                   i.InputSimd128Register(0));
      break;
    }
    case kRiscvF64x2Pmin: {
      __ VU.set(kScratchReg, E64, m1);
      __ vmflt_vv(v0, i.InputSimd128Register(1), i.InputSimd128Register(0));
      __ vmerge_vv(i.OutputSimd128Register(), i.InputSimd128Register(1),
                   i.InputSimd128Register(0));
      break;
    }
    case kRiscvF64x2ExtractLane: {
      __ VU.set(kScratchReg, E64, m1);
      if (is_uint5(i.InputInt8(1))) {
        __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0),
                         i.InputInt8(1));
      } else {
        __ li(kScratchReg, i.InputInt8(1));
        __ vslidedown_vx(kSimd128ScratchReg, i.InputSimd128Register(0),
                         kScratchReg);
      }
      __ vfmv_fs(i.OutputDoubleRegister(), kSimd128ScratchReg);
      break;
    }
    case kRiscvF64x2PromoteLowF32x4: {
      __ VU.set(kScratchReg, E32, mf2);
      if (i.OutputSimd128Register() != i.InputSimd128Register(0)) {
        __ vfwcvt_f_f_v(i.OutputSimd128Register(), i.InputSimd128Register(0));
      } else {
        __ vfwcvt_f_f_v(kSimd128ScratchReg3, i.InputSimd128Register(0));
        __ VU.set(kScratchReg, E64, m1);
        __ vmv_vv(i.OutputSimd128Register(), kSimd128ScratchReg3);
      }
      break;
    }
    case kRiscvF64x2ConvertLowI32x4S: {
      __ VU.set(kScratchReg, E32, mf2);
      if (i.OutputSimd128Register() != i.InputSimd128Register(0)) {
        __ vfwcvt_f_x_v(i.OutputSimd128Register(), i.InputSimd128Register(0));
      } else {
        __ vfwcvt_f_x_v(kSimd128ScratchReg3, i.InputSimd128Register(0));
        __ VU.set(kScratchReg, E64, m1);
        __ vmv_vv(i.OutputSimd128Register(), kSimd128ScratchReg3);
      }
      break;
    }
    case kRiscvF64x2ConvertLowI32x4U: {
      __ VU.set(kScratchReg, E32, mf2);
      if (i.OutputSimd128Register() != i.InputSimd128Register(0)) {
        __ vfwcvt_f_xu_v(i.OutputSimd128Register(), i.InputSimd128Register(0));
      } else {
        __ vfwcvt_f_xu_v(kSimd128ScratchReg3, i.InputSimd128Register(0));
        __ VU.set(kScratchReg, E64, m1);
        __ vmv_vv(i.OutputSimd128Register(), kSimd128ScratchReg3);
      }
      break;
    }
    case kRiscvF64x2Qfma: {
      __ VU.set(kScratchReg, E64, m1);
      __ vfmadd_vv(i.InputSimd128Register(0), i.InputSimd128Register(1),
                   i.InputSimd128Register(2));
      __ vmv_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvF64x2Qfms: {
      __ VU.set(kScratchReg, E64, m1);
      __ vfnmsub_vv(i.InputSimd128Register(0), i.InputSimd128Register(1),
                    i.InputSimd128Register(2));
      __ vmv_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvF32x4ExtractLane: {
      __ VU.set(kScratchReg, E32, m1);
      __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0),
                       i.InputInt8(1));
      __ vfmv_fs(i.OutputDoubleRegister(), kSimd128ScratchReg);
      break;
    }
    case kRiscvF32x4Trunc: {
      __ Trunc_f(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kScratchReg, kSimd128ScratchReg);
      break;
    }
    case kRiscvF32x4NearestInt: {
      __ Round_f(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kScratchReg, kSimd128ScratchReg);
      break;
    }
    case kRiscvF32x4DemoteF64x2Zero: {
      __ VU.set(kScratchReg, E32, mf2);
      __ vfncvt_f_f_w(i.OutputSimd128Register(), i.InputSimd128Register(0));
      __ VU.set(kScratchReg, E32, m1);
      __ vmv_vi(v0, 12);
      __ vmerge_vx(i.OutputSimd128Register(), zero_reg,
                   i.OutputSimd128Register());
      break;
    }
    case kRiscvF32x4Abs: {
      __ VU.set(kScratchReg, VSew::E32, Vlmul::m1);
      __ vfabs_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvF32x4Ceil: {
      __ Ceil_f(i.OutputSimd128Register(), i.InputSimd128Register(0),
                kScratchReg, kSimd128ScratchReg);
      break;
    }
    case kRiscvF32x4Floor: {
      __ Floor_f(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 kScratchReg, kSimd128ScratchReg);
      break;
    }
    case kRiscvF32x4UConvertI32x4: {
      __ VU.set(kScratchReg, E32, m1);
      __ VU.set(FPURoundingMode::RTZ);
      __ vfcvt_f_xu_v(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvF32x4SConvertI32x4: {
      __ VU.set(kScratchReg, E32, m1);
      __ VU.set(FPURoundingMode::RTZ);
      __ vfcvt_f_x_v(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvF32x4ReplaceLane: {
      __ VU.set(kScratchReg, E32, m1);
      __ li(kScratchReg, 0x1 << i.InputInt8(1));
      __ vmv_sx(v0, kScratchReg);
      __ fmv_x_w(kScratchReg, i.InputSingleRegister(2));
      __ vmerge_vx(i.OutputSimd128Register(), kScratchReg,
                   i.InputSimd128Register(0));
      break;
    }
    case kRiscvF32x4Pmax: {
      __ VU.set(kScratchReg, E32, m1);
      __ vmflt_vv(v0, i.InputSimd128Register(0), i.InputSimd128Register(1));
      __ vmerge_vv(i.OutputSimd128Register(), i.InputSimd128Register(1),
                   i.InputSimd128Register(0));
      break;
    }
    case kRiscvF32x4Pmin: {
      __ VU.set(kScratchReg, E32, m1);
      __ vmflt_vv(v0, i.InputSimd128Register(1), i.InputSimd128Register(0));
      __ vmerge_vv(i.OutputSimd128Register(), i.InputSimd128Register(1),
                   i.InputSimd128Register(0));
      break;
    }
    case kRiscvF32x4Sqrt: {
      __ VU.set(kScratchReg, E32, m1);
      __ vfsqrt_v(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvF32x4Qfma: {
      __ VU.set(kScratchReg, E32, m1);
      __ vfmadd_vv(i.InputSimd128Register(0), i.InputSimd128Register(1),
                   i.InputSimd128Register(2));
      __ vmv_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvF32x4Qfms: {
      __ VU.set(kScratchReg, E32, m1);
      __ vfnmsub_vv(i.InputSimd128Register(0), i.InputSimd128Register(1),
                    i.InputSimd128Register(2));
      __ vmv_vv(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kRiscvI64x2SConvertI32x4Low: {
      __ VU.set(kScratchReg, E64, m1);
      __ vmv_vv(kSimd128ScratchReg, i.InputSimd128Register(0));
      __ vsext_vf2(i.OutputSimd128Register(), kSimd128ScratchReg);

      break;
    }
    case kRiscvI64x2SConvertI32x4High: {
      __ VU.set(kScratchReg, E32, m1);
      __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0), 2);
      __ VU.set(kScratchReg, E64, m1);
      __ vsext_vf2(i.OutputSimd128Register(), kSimd128ScratchReg);
      break;
    }
    case kRiscvI64x2UConvertI32x4Low: {
      __ VU.set(kScratchReg, E64, m1);
      __ vmv_vv(kSimd128ScratchReg, i.InputSimd128Register(0));
      __ vzext_vf2(i.OutputSimd128Register(), kSimd128ScratchReg);
      break;
    }
    case kRiscvI64x2UConvertI32x4High: {
      __ VU.set(kScratchReg, E32, m1);
      __ vslidedown_vi(kSimd128ScratchReg, i.InputSimd128Register(0), 2);
      __ VU.set(kScratchReg, E64, m1);
      __ vzext_vf2(i.OutputSimd128Register(), kSimd128ScratchReg);
      break;
  
"""


```