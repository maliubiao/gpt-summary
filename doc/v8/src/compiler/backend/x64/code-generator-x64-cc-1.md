Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/backend/x64/code-generator-x64.cc`.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the File's Role:** The file name suggests it's responsible for generating x64 assembly code within the V8 compiler's backend. Specifically, it's a `CodeGenerator`.

2. **Analyze the Code Snippet:**  The snippet consists primarily of C++ macros (`#define`). These macros seem to encapsulate common assembly instruction patterns. Keywords like `ASSEMBLE_COMPARE`, `ASSEMBLE_TEST`, `ASSEMBLE_MOVX`, `ASSEMBLE_SSE_BINOP`, `ASSEMBLE_SIMD_BINOP`, etc., are strong indicators of this.

3. **Categorize the Macros:**  Group the macros based on the type of assembly instructions they represent. This helps in creating a structured summary.
    * **Basic Operations:**  Compare, test, move, multiply, shift.
    * **Floating-Point (SSE/AVX):** Binary and unary operations.
    * **SIMD (Single Instruction, Multiple Data):**  Various operations on SIMD registers (128-bit and 256-bit).
    * **Atomic Operations:** Operations ensuring atomicity (using `lock` prefix).
    * **Tail Call Handling:**  Macros and functions related to optimizing function calls.
    * **Stack Management:** Functions like `AssembleDeconstructFrame`.
    * **Helper Functions:**  Functions for setting up immediate values in registers.
    * **Checks:** Functions for verifying register contents.

4. **Infer Functionality from Macros:**  Each macro suggests a code generation pattern for a specific category of operations. For example, `ASSEMBLE_COMPARE` handles the generation of `cmp` instructions with different operand types (memory, immediate, register). `ASSEMBLE_SSE_BINOP` deals with SSE floating-point binary operations.

5. **Connect to V8's Purpose:**  Recognize that this code is part of a JavaScript engine. The generated assembly code is used to execute JavaScript code efficiently. This leads to understanding that the macros facilitate the translation of higher-level V8 intermediate representations (like the `Instruction` class being used) into low-level machine code.

6. **Address Specific Questions:**
    * **`.tq` extension:** Explain that this file is `.cc`, not `.tq`, and that `.tq` signifies Torque code (a V8 domain-specific language).
    * **Relationship to JavaScript:** Explain that this is *how* JavaScript is executed—the compiled code runs on the CPU. Provide simple JavaScript examples that would lead to the execution of these assembly instructions (e.g., arithmetic operations, comparisons, function calls).
    * **Code Logic Reasoning:** For the provided macros, illustrate with a concrete example (e.g., the `ASSEMBLE_COMPARE` macro with specific input types) to show how it translates to assembly.
    * **Common Programming Errors:**  Think about common JavaScript errors that might relate to the underlying assembly, such as type errors leading to unexpected behavior in comparisons or arithmetic. Also, consider errors related to incorrect function calls.

7. **Structure the Summary:**  Organize the findings into clear sections addressing the user's requests. Use bullet points and descriptive language.

8. **Refine and Edit:** Ensure the summary is concise, accurate, and easy to understand. Double-check the explanations and examples. For instance, initially, I might have just listed the macro names. Refining involves explaining *what* each category of macros does in terms of code generation.

By following these steps, the goal is to produce a comprehensive yet understandable summary of the provided code snippet's role within the V8 JavaScript engine.
这是 `v8/src/compiler/backend/x64/code-generator-x64.cc` 文件的第二部分代码，它主要定义了一些 C++ 宏，这些宏用于简化在 x64 架构上生成汇编代码的过程。这些宏针对不同的指令类型，例如比较、测试、移动、算术运算、SIMD 指令等，封装了生成相应汇编代码的逻辑。

**功能归纳:**

这部分代码的主要功能是定义了一系列 C++ 宏，作为生成 x64 汇编指令的便捷工具。这些宏可以根据不同的输入类型（寄存器、立即数、内存操作数）和指令特性，自动生成相应的汇编代码。

**详细功能列表:**

* **指令生成宏:**  定义了用于生成各种 x64 汇编指令的宏，例如：
    * **`ASSEMBLE_COMPARE`:** 生成比较指令 (`cmp`) 或测试指令 (`test`)，可以处理立即数、寄存器和内存操作数。
    * **`ASSEMBLE_TEST`:** 生成测试指令 (`test`)，可以处理立即数、寄存器和内存操作数。
    * **`ASSEMBLE_MULT`:** 生成乘法指令 (`imul`)，可以将结果存储到指定的输出寄存器。
    * **`ASSEMBLE_SHIFT`:** 生成移位指令 (`shl`, `shr`, `sar`)，可以处理立即数和寄存器作为移位量。
    * **`ASSEMBLE_MOVX`:** 生成数据移动指令 (`mov`)，可以从内存或寄存器移动数据到寄存器。
    * **`ASSEMBLE_SSE_BINOP`:** 生成 SSE (Streaming SIMD Extensions) 浮点二元运算指令，例如加法、减法等。
    * **`ASSEMBLE_SSE_UNOP`:** 生成 SSE 浮点一元运算指令，例如取负、绝对值等。
    * **`ASSEMBLE_AVX_BINOP`:** 生成 AVX (Advanced Vector Extensions) 浮点二元运算指令。
    * **`ASSEMBLE_IEEE754_BINOP` 和 `ASSEMBLE_IEEE754_UNOP`:**  用于调用 C 函数来实现 IEEE 754 标准的浮点运算。
    * **`ASSEMBLE_ATOMIC_BINOP` 和 `ASSEMBLE_ATOMIC64_BINOP`:** 生成原子操作指令，用于在多线程环境中保证操作的原子性。
    * **`ASSEMBLE_SIMD_BINOP`:** 生成 SIMD (Single Instruction, Multiple Data) 向量二元运算指令。
    * **`ASSEMBLE_SIMD_F16x8_BINOP` 和 `ASSEMBLE_SIMD_F16x8_RELOP`:** 生成针对半精度浮点数（F16）的 SIMD 运算指令。
    * **`ASSEMBLE_SIMD256_BINOP`:** 生成 256 位 SIMD 向量二元运算指令。
    * **`ASSEMBLE_SIMD_INSTR` 和 `ASSEMBLE_SIMD_IMM_INSTR`:** 生成更通用的 SIMD 指令，可以处理不同的操作数类型。
    * **`ASSEMBLE_SIMD_PUNPCK_SHUFFLE` 和 `ASSEMBLE_SIMD_IMM_SHUFFLE`:** 生成 SIMD 数据重排指令。
    * **`ASSEMBLE_SIMD_ALL_TRUE`:** 生成检查 SIMD 向量所有元素是否都为真的指令。
    * **`ASSEMBLE_SIMD_SHIFT` 和 `ASSEMBLE_SIMD256_SHIFT`:** 生成 SIMD 向量移位指令。
    * **`ASSEMBLE_PINSR`:** 生成 SIMD 插入指令。
    * **`ASSEMBLE_SEQ_CST_STORE`:** 生成具有顺序一致性内存模型的存储指令。

* **辅助函数和宏:**
    * **`AdjustStackPointerForTailCall`:**  调整栈指针以支持尾调用优化。
    * **`SetupSimdImmediateInRegister` 和 `SetupSimd256ImmediateInRegister`:** 将立即数加载到 SIMD 寄存器中。
    * **`AssembleDeconstructFrame` 和 `AssemblePrepareTailCall`:** 处理函数调用帧的构建和销毁，以及尾调用准备。
    * **代码校验相关:** `AssembleCodeStartRegisterCheck` 和 `AssembleDispatchHandleRegisterCheck` 用于在运行时检查代码起始地址和分发句柄的正确性。
    * **`BailoutIfDeoptimized`:**  在代码被反优化后跳转到相应的处理逻辑。
    * **`ShouldClearOutputRegisterBeforeInstruction`:**  判断在执行指令前是否需要清除输出寄存器。
    * **`AssemblePlaceHolderForLazyDeopt`:**  为延迟反优化插入占位符。

**关于文件扩展名和 Torque:**

`v8/src/compiler/backend/x64/code-generator-x64.cc` 的文件扩展名是 `.cc`，这表明它是一个 C++ 源文件。如果文件以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码。Torque 是一种 V8 特有的领域特定语言，用于定义内置函数的实现。

**与 JavaScript 的关系 (举例说明):**

这些宏生成的汇编代码是 JavaScript 代码在 x64 架构上执行的底层指令。例如，一个简单的 JavaScript 加法运算 `a + b` 可能会涉及到使用 `ASSEMBLE_COMPARE` 宏来比较数值大小，或者使用 `ASSEMBLE_SSE_BINOP` 或 `ASSEMBLE_AVX_BINOP` 宏来执行浮点数加法（如果 `a` 和 `b` 是浮点数），或者使用更基础的算术指令（如果 `a` 和 `b` 是整数）。

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 3); // 整数加法
let floatResult = add(2.5, 1.5); // 浮点数加法
let compareResult = (result > 10); // 比较运算
```

当 V8 编译这段 JavaScript 代码时，`code-generator-x64.cc` 中的代码会被调用，并使用这些宏来生成相应的 x64 汇编指令来实现加法和比较操作。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个指令 `instr`，它代表一个整数比较操作，并且：

* `HasAddressingMode(instr)` 返回 `false`。
* `HasImmediateInput(instr, 1)` 返回 `true`，且 `i.InputImmediate(1)` 的值为立即数 `10`。
* `HasRegisterInput(instr, 0)` 返回 `true`，且 `i.InputRegister(0)` 返回寄存器 `rax`。

那么，执行 `ASSEMBLE_COMPARE(cmpq, testq)` 宏将会生成以下汇编代码：

```assembly
cmpq rax, 10
```

**用户常见的编程错误 (举例说明):**

在 JavaScript 中，一些常见的编程错误可能最终导致生成的汇编代码执行不符合预期：

1. **类型错误导致的意外比较:**  例如，比较一个字符串和一个数字，可能会导致 V8 执行字符串到数字的转换，如果转换失败，比较结果可能出乎意料。这会影响到 `ASSEMBLE_COMPARE` 生成的比较指令的行为。

   ```javascript
   let a = "5";
   let b = 5;
   if (a > b) { // 字符串 "5" 会被转换为数字 5 进行比较
     console.log("a is greater than b");
   } else {
     console.log("a is not greater than b");
   }
   ```

2. **浮点数精度问题:**  浮点数运算可能存在精度损失，导致比较结果不符合直觉。这会影响到 `ASSEMBLE_SSE_BINOP` 或 `ASSEMBLE_AVX_BINOP` 生成的浮点运算指令的结果。

   ```javascript
   let x = 0.1 + 0.2;
   if (x === 0.3) { // 结果可能为 false，因为浮点数运算存在精度问题
     console.log("x is exactly 0.3");
   } else {
     console.log("x is not exactly 0.3");
   }
   ```

3. **未定义行为导致的崩溃:**  某些操作，例如访问超出数组边界的元素，在底层可能导致访问无效内存地址，最终导致程序崩溃。虽然这更多是运行时错误，但底层的汇编代码没有进行充分的边界检查就可能触发这类问题。

总之，这部分代码是 V8 引擎中用于将高级抽象操作转化为实际机器码的关键组成部分，它通过宏的方式提高了代码生成效率和可读性。

### 提示词
```
这是目录为v8/src/compiler/backend/x64/code-generator-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/x64/code-generator-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
\
    }                                                            \
  } while (false)

#define ASSEMBLE_COMPARE(cmp_instr, test_instr)                    \
  do {                                                             \
    if (HasAddressingMode(instr)) {                                \
      size_t index = 0;                                            \
      Operand left = i.MemoryOperand(&index);                      \
      if (HasImmediateInput(instr, index)) {                       \
        __ cmp_instr(left, i.InputImmediate(index));               \
      } else {                                                     \
        __ cmp_instr(left, i.InputRegister(index));                \
      }                                                            \
    } else {                                                       \
      if (HasImmediateInput(instr, 1)) {                           \
        Immediate right = i.InputImmediate(1);                     \
        if (HasRegisterInput(instr, 0)) {                          \
          if (right.value() == 0) {                                \
            __ test_instr(i.InputRegister(0), i.InputRegister(0)); \
          } else {                                                 \
            __ cmp_instr(i.InputRegister(0), right);               \
          }                                                        \
        } else {                                                   \
          __ cmp_instr(i.InputOperand(0), right);                  \
        }                                                          \
      } else {                                                     \
        if (HasRegisterInput(instr, 1)) {                          \
          __ cmp_instr(i.InputRegister(0), i.InputRegister(1));    \
        } else {                                                   \
          __ cmp_instr(i.InputRegister(0), i.InputOperand(1));     \
        }                                                          \
      }                                                            \
    }                                                              \
  } while (false)

#define ASSEMBLE_TEST(asm_instr)                                 \
  do {                                                           \
    if (HasAddressingMode(instr)) {                              \
      size_t index = 0;                                          \
      Operand left = i.MemoryOperand(&index);                    \
      if (HasImmediateInput(instr, index)) {                     \
        __ asm_instr(left, i.InputImmediate(index));             \
      } else {                                                   \
        __ asm_instr(left, i.InputRegister(index));              \
      }                                                          \
    } else {                                                     \
      if (HasImmediateInput(instr, 1)) {                         \
        if (HasRegisterInput(instr, 0)) {                        \
          __ asm_instr(i.InputRegister(0), i.InputImmediate(1)); \
        } else {                                                 \
          __ asm_instr(i.InputOperand(0), i.InputImmediate(1));  \
        }                                                        \
      } else {                                                   \
        if (HasRegisterInput(instr, 1)) {                        \
          __ asm_instr(i.InputRegister(0), i.InputRegister(1));  \
        } else {                                                 \
          __ asm_instr(i.InputRegister(0), i.InputOperand(1));   \
        }                                                        \
      }                                                          \
    }                                                            \
  } while (false)

#define ASSEMBLE_MULT(asm_instr)                              \
  do {                                                        \
    if (HasImmediateInput(instr, 1)) {                        \
      if (HasRegisterInput(instr, 0)) {                       \
        __ asm_instr(i.OutputRegister(), i.InputRegister(0),  \
                     i.InputImmediate(1));                    \
      } else {                                                \
        __ asm_instr(i.OutputRegister(), i.InputOperand(0),   \
                     i.InputImmediate(1));                    \
      }                                                       \
    } else {                                                  \
      if (HasRegisterInput(instr, 1)) {                       \
        __ asm_instr(i.OutputRegister(), i.InputRegister(1)); \
      } else {                                                \
        __ asm_instr(i.OutputRegister(), i.InputOperand(1));  \
      }                                                       \
    }                                                         \
  } while (false)

#define ASSEMBLE_SHIFT(asm_instr, width)                                   \
  do {                                                                     \
    if (HasImmediateInput(instr, 1)) {                                     \
      if (instr->Output()->IsRegister()) {                                 \
        __ asm_instr(i.OutputRegister(), Immediate(i.InputInt##width(1))); \
      } else {                                                             \
        __ asm_instr(i.OutputOperand(), Immediate(i.InputInt##width(1)));  \
      }                                                                    \
    } else {                                                               \
      if (instr->Output()->IsRegister()) {                                 \
        __ asm_instr##_cl(i.OutputRegister());                             \
      } else {                                                             \
        __ asm_instr##_cl(i.OutputOperand());                              \
      }                                                                    \
    }                                                                      \
  } while (false)

#define ASSEMBLE_MOVX(asm_instr)                            \
  do {                                                      \
    if (HasAddressingMode(instr)) {                         \
      __ asm_instr(i.OutputRegister(), i.MemoryOperand());  \
    } else if (HasRegisterInput(instr, 0)) {                \
      __ asm_instr(i.OutputRegister(), i.InputRegister(0)); \
    } else {                                                \
      __ asm_instr(i.OutputRegister(), i.InputOperand(0));  \
    }                                                       \
  } while (false)

#define ASSEMBLE_SSE_BINOP(asm_instr)                                     \
  do {                                                                    \
    if (HasAddressingMode(instr)) {                                       \
      size_t index = 1;                                                   \
      Operand right = i.MemoryOperand(&index);                            \
      __ asm_instr(i.InputDoubleRegister(0), right);                      \
    } else {                                                              \
      if (instr->InputAt(1)->IsFPRegister()) {                            \
        __ asm_instr(i.InputDoubleRegister(0), i.InputDoubleRegister(1)); \
      } else {                                                            \
        __ asm_instr(i.InputDoubleRegister(0), i.InputOperand(1));        \
      }                                                                   \
    }                                                                     \
  } while (false)

#define ASSEMBLE_SSE_UNOP(asm_instr)                                    \
  do {                                                                  \
    if (instr->InputAt(0)->IsFPRegister()) {                            \
      __ asm_instr(i.OutputDoubleRegister(), i.InputDoubleRegister(0)); \
    } else {                                                            \
      __ asm_instr(i.OutputDoubleRegister(), i.InputOperand(0));        \
    }                                                                   \
  } while (false)

#define ASSEMBLE_AVX_BINOP(asm_instr)                                          \
  do {                                                                         \
    CpuFeatureScope avx_scope(masm(), AVX);                                    \
    if (HasAddressingMode(instr)) {                                            \
      size_t index = 1;                                                        \
      Operand right = i.MemoryOperand(&index);                                 \
      __ asm_instr(i.OutputDoubleRegister(), i.InputDoubleRegister(0), right); \
    } else {                                                                   \
      if (instr->InputAt(1)->IsFPRegister()) {                                 \
        __ asm_instr(i.OutputDoubleRegister(), i.InputDoubleRegister(0),       \
                     i.InputDoubleRegister(1));                                \
      } else {                                                                 \
        __ asm_instr(i.OutputDoubleRegister(), i.InputDoubleRegister(0),       \
                     i.InputOperand(1));                                       \
      }                                                                        \
    }                                                                          \
  } while (false)

#define ASSEMBLE_IEEE754_BINOP(name)                                     \
  do {                                                                   \
    __ PrepareCallCFunction(2);                                          \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 2); \
  } while (false)

#define ASSEMBLE_IEEE754_UNOP(name)                                      \
  do {                                                                   \
    __ PrepareCallCFunction(1);                                          \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 1); \
  } while (false)

#define ASSEMBLE_ATOMIC_BINOP(bin_inst, mov_inst, cmpxchg_inst)          \
  do {                                                                   \
    Label binop;                                                         \
    __ bind(&binop);                                                     \
    RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset()); \
    __ mov_inst(rax, i.MemoryOperand(1));                                \
    __ movl(i.TempRegister(0), rax);                                     \
    __ bin_inst(i.TempRegister(0), i.InputRegister(0));                  \
    __ lock();                                                           \
    __ cmpxchg_inst(i.MemoryOperand(1), i.TempRegister(0));              \
    __ j(not_equal, &binop);                                             \
  } while (false)

#define ASSEMBLE_ATOMIC64_BINOP(bin_inst, mov_inst, cmpxchg_inst)        \
  do {                                                                   \
    Label binop;                                                         \
    __ bind(&binop);                                                     \
    RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset()); \
    __ mov_inst(rax, i.MemoryOperand(1));                                \
    __ movq(i.TempRegister(0), rax);                                     \
    __ bin_inst(i.TempRegister(0), i.InputRegister(0));                  \
    __ lock();                                                           \
    __ cmpxchg_inst(i.MemoryOperand(1), i.TempRegister(0));              \
    __ j(not_equal, &binop);                                             \
  } while (false)

// Handles both SSE and AVX codegen. For SSE we use DefineSameAsFirst, so the
// dst and first src will be the same. For AVX we don't restrict it that way, so
// we will omit unnecessary moves.
#define ASSEMBLE_SIMD_BINOP(opcode)                                      \
  do {                                                                   \
    if (CpuFeatures::IsSupported(AVX)) {                                 \
      CpuFeatureScope avx_scope(masm(), AVX);                            \
      __ v##opcode(i.OutputSimd128Register(), i.InputSimd128Register(0), \
                   i.InputSimd128Register(1));                           \
    } else {                                                             \
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));   \
      __ opcode(i.OutputSimd128Register(), i.InputSimd128Register(1));   \
    }                                                                    \
  } while (false)

#define ASSEMBLE_SIMD_F16x8_BINOP(instr)              \
  do {                                                \
    CpuFeatureScope f16c_scope(masm(), F16C);         \
    CpuFeatureScope avx_scope(masm(), AVX);           \
    YMMRegister tmp1 = i.TempSimd256Register(0);      \
    YMMRegister tmp2 = i.TempSimd256Register(1);      \
    __ vcvtph2ps(tmp1, i.InputSimd128Register(0));    \
    __ vcvtph2ps(tmp2, i.InputSimd128Register(1));    \
    __ instr(tmp2, tmp1, tmp2);                       \
    __ vcvtps2ph(i.OutputSimd128Register(), tmp2, 0); \
  } while (false)

#define ASSEMBLE_SIMD_F16x8_RELOP(instr)                 \
  do {                                                   \
    CpuFeatureScope f16c_scope(masm(), F16C);            \
    CpuFeatureScope avx_scope(masm(), AVX);              \
    YMMRegister tmp1 = i.TempSimd256Register(0);         \
    YMMRegister tmp2 = i.TempSimd256Register(1);         \
    __ vcvtph2ps(tmp1, i.InputSimd128Register(0));       \
    __ vcvtph2ps(tmp2, i.InputSimd128Register(1));       \
    __ instr(tmp2, tmp1, tmp2);                          \
    __ vpackssdw(i.OutputSimd128Register(), tmp2, tmp2); \
  } while (false)

#define ASSEMBLE_SIMD256_BINOP(opcode, cpu_feature)                    \
  do {                                                                 \
    CpuFeatureScope avx_scope(masm(), cpu_feature);                    \
    __ v##opcode(i.OutputSimd256Register(), i.InputSimd256Register(0), \
                 i.InputSimd256Register(1));                           \
  } while (false)

#define ASSEMBLE_SIMD_INSTR(opcode, dst_operand, index)      \
  do {                                                       \
    if (instr->InputAt(index)->IsSimd128Register()) {        \
      __ opcode(dst_operand, i.InputSimd128Register(index)); \
    } else {                                                 \
      __ opcode(dst_operand, i.InputOperand(index));         \
    }                                                        \
  } while (false)

#define ASSEMBLE_SIMD_IMM_INSTR(opcode, dst_operand, index, imm)  \
  do {                                                            \
    if (instr->InputAt(index)->IsSimd128Register()) {             \
      __ opcode(dst_operand, i.InputSimd128Register(index), imm); \
    } else {                                                      \
      __ opcode(dst_operand, i.InputOperand(index), imm);         \
    }                                                             \
  } while (false)

#define ASSEMBLE_SIMD_PUNPCK_SHUFFLE(opcode)                    \
  do {                                                          \
    XMMRegister dst = i.OutputSimd128Register();                \
    uint8_t input_index = instr->InputCount() == 2 ? 1 : 0;     \
    if (CpuFeatures::IsSupported(AVX)) {                        \
      CpuFeatureScope avx_scope(masm(), AVX);                   \
      DCHECK(instr->InputAt(input_index)->IsSimd128Register()); \
      __ v##opcode(dst, i.InputSimd128Register(0),              \
                   i.InputSimd128Register(input_index));        \
    } else {                                                    \
      DCHECK_EQ(dst, i.InputSimd128Register(0));                \
      ASSEMBLE_SIMD_INSTR(opcode, dst, input_index);            \
    }                                                           \
  } while (false)

#define ASSEMBLE_SIMD_IMM_SHUFFLE(opcode, imm)                \
  do {                                                        \
    XMMRegister dst = i.OutputSimd128Register();              \
    XMMRegister src = i.InputSimd128Register(0);              \
    if (CpuFeatures::IsSupported(AVX)) {                      \
      CpuFeatureScope avx_scope(masm(), AVX);                 \
      DCHECK(instr->InputAt(1)->IsSimd128Register());         \
      __ v##opcode(dst, src, i.InputSimd128Register(1), imm); \
    } else {                                                  \
      DCHECK_EQ(dst, src);                                    \
      if (instr->InputAt(1)->IsSimd128Register()) {           \
        __ opcode(dst, i.InputSimd128Register(1), imm);       \
      } else {                                                \
        __ opcode(dst, i.InputOperand(1), imm);               \
      }                                                       \
    }                                                         \
  } while (false)

#define ASSEMBLE_SIMD_ALL_TRUE(opcode)                       \
  do {                                                       \
    Register dst = i.OutputRegister();                       \
    __ xorq(dst, dst);                                       \
    __ Pxor(kScratchDoubleReg, kScratchDoubleReg);           \
    __ opcode(kScratchDoubleReg, i.InputSimd128Register(0)); \
    __ Ptest(kScratchDoubleReg, kScratchDoubleReg);          \
    __ setcc(equal, dst);                                    \
  } while (false)

// This macro will directly emit the opcode if the shift is an immediate - the
// shift value will be taken modulo 2^width. Otherwise, it will emit code to
// perform the modulus operation.
#define ASSEMBLE_SIMD_SHIFT(opcode, width)                               \
  do {                                                                   \
    XMMRegister dst = i.OutputSimd128Register();                         \
    if (HasImmediateInput(instr, 1)) {                                   \
      if (CpuFeatures::IsSupported(AVX)) {                               \
        CpuFeatureScope avx_scope(masm(), AVX);                          \
        __ v##opcode(dst, i.InputSimd128Register(0),                     \
                     uint8_t{i.InputInt##width(1)});                     \
      } else {                                                           \
        DCHECK_EQ(dst, i.InputSimd128Register(0));                       \
        __ opcode(dst, uint8_t{i.InputInt##width(1)});                   \
      }                                                                  \
    } else {                                                             \
      constexpr int mask = (1 << width) - 1;                             \
      __ movq(kScratchRegister, i.InputRegister(1));                     \
      __ andq(kScratchRegister, Immediate(mask));                        \
      __ Movq(kScratchDoubleReg, kScratchRegister);                      \
      if (CpuFeatures::IsSupported(AVX)) {                               \
        CpuFeatureScope avx_scope(masm(), AVX);                          \
        __ v##opcode(dst, i.InputSimd128Register(0), kScratchDoubleReg); \
      } else {                                                           \
        DCHECK_EQ(dst, i.InputSimd128Register(0));                       \
        __ opcode(dst, kScratchDoubleReg);                               \
      }                                                                  \
    }                                                                    \
  } while (false)

#define ASSEMBLE_SIMD256_SHIFT(opcode, width)                \
  do {                                                       \
    CpuFeatureScope avx_scope(masm(), AVX2);                 \
    YMMRegister src = i.InputSimd256Register(0);             \
    YMMRegister dst = i.OutputSimd256Register();             \
    if (HasImmediateInput(instr, 1)) {                       \
      __ v##opcode(dst, src, uint8_t{i.InputInt##width(1)}); \
    } else {                                                 \
      constexpr int mask = (1 << width) - 1;                 \
      __ movq(kScratchRegister, i.InputRegister(1));         \
      __ andq(kScratchRegister, Immediate(mask));            \
      __ Movq(kScratchDoubleReg, kScratchRegister);          \
      __ v##opcode(dst, src, kScratchDoubleReg);             \
    }                                                        \
  } while (false)

#define ASSEMBLE_PINSR(ASM_INSTR)                                        \
  do {                                                                   \
    XMMRegister dst = i.OutputSimd128Register();                         \
    XMMRegister src = i.InputSimd128Register(0);                         \
    uint8_t laneidx = i.InputUint8(1);                                   \
    uint32_t load_offset;                                                \
    if (HasAddressingMode(instr)) {                                      \
      __ ASM_INSTR(dst, src, i.MemoryOperand(2), laneidx, &load_offset); \
    } else if (instr->InputAt(2)->IsFPRegister()) {                      \
      __ Movq(kScratchRegister, i.InputDoubleRegister(2));               \
      __ ASM_INSTR(dst, src, kScratchRegister, laneidx, &load_offset);   \
    } else if (instr->InputAt(2)->IsRegister()) {                        \
      __ ASM_INSTR(dst, src, i.InputRegister(2), laneidx, &load_offset); \
    } else {                                                             \
      __ ASM_INSTR(dst, src, i.InputOperand(2), laneidx, &load_offset);  \
    }                                                                    \
    RecordTrapInfoIfNeeded(zone(), this, opcode, instr, load_offset);    \
  } while (false)

#define ASSEMBLE_SEQ_CST_STORE(rep)                                            \
  do {                                                                         \
    Register value = i.InputRegister(0);                                       \
    Operand operand = i.MemoryOperand(1);                                      \
    EmitTSANAwareStore<std::memory_order_seq_cst>(                             \
        zone(), this, masm(), operand, value, i, DetermineStubCallMode(), rep, \
        instr);                                                                \
  } while (false)

void CodeGenerator::AssembleDeconstructFrame() {
  unwinding_info_writer_.MarkFrameDeconstructed(__ pc_offset());
  __ movq(rsp, rbp);
  __ popq(rbp);
}

void CodeGenerator::AssemblePrepareTailCall() {
  if (frame_access_state()->has_frame()) {
    __ movq(rbp, MemOperand(rbp, 0));
  }
  frame_access_state()->SetFrameAccessToSP();
}

namespace {

void AdjustStackPointerForTailCall(Instruction* instr,
                                   MacroAssembler* assembler, Linkage* linkage,
                                   OptimizedCompilationInfo* info,
                                   FrameAccessState* state,
                                   int new_slot_above_sp,
                                   bool allow_shrinkage = true) {
  int stack_slot_delta;
  if (instr->HasCallDescriptorFlag(CallDescriptor::kIsTailCallForTierUp)) {
    // For this special tail-call mode, the callee has the same arguments and
    // linkage as the caller, and arguments adapter frames must be preserved.
    // Thus we simply have reset the stack pointer register to its original
    // value before frame construction.
    // See also: AssembleConstructFrame.
    DCHECK(!info->is_osr());
    DCHECK(linkage->GetIncomingDescriptor()->CalleeSavedRegisters().is_empty());
    DCHECK(
        linkage->GetIncomingDescriptor()->CalleeSavedFPRegisters().is_empty());
    DCHECK_EQ(state->frame()->GetReturnSlotCount(), 0);
    stack_slot_delta = (state->frame()->GetTotalFrameSlotCount() -
                        kReturnAddressStackSlotCount) *
                       -1;
    DCHECK_LE(stack_slot_delta, 0);
  } else {
    int current_sp_offset = state->GetSPToFPSlotCount() +
                            StandardFrameConstants::kFixedSlotCountAboveFp;
    stack_slot_delta = new_slot_above_sp - current_sp_offset;
  }

  if (stack_slot_delta > 0) {
    assembler->AllocateStackSpace(stack_slot_delta * kSystemPointerSize);
    state->IncreaseSPDelta(stack_slot_delta);
  } else if (allow_shrinkage && stack_slot_delta < 0) {
    assembler->addq(rsp, Immediate(-stack_slot_delta * kSystemPointerSize));
    state->IncreaseSPDelta(stack_slot_delta);
  }
}

void SetupSimdImmediateInRegister(MacroAssembler* assembler, uint32_t* imms,
                                  XMMRegister reg) {
  assembler->Move(reg, make_uint64(imms[3], imms[2]),
                  make_uint64(imms[1], imms[0]));
}

void SetupSimd256ImmediateInRegister(MacroAssembler* assembler, uint32_t* imms,
                                     YMMRegister reg, XMMRegister scratch) {
  bool is_splat = std::all_of(imms, imms + kSimd256Size,
                              [imms](uint32_t v) { return v == imms[0]; });
  if (is_splat) {
    assembler->Move(scratch, imms[0]);
    CpuFeatureScope avx_scope(assembler, AVX2);
    assembler->vpbroadcastd(reg, scratch);
  } else {
    assembler->Move(reg, make_uint64(imms[3], imms[2]),
                    make_uint64(imms[1], imms[0]));
    assembler->Move(scratch, make_uint64(imms[7], imms[6]),
                    make_uint64(imms[5], imms[4]));
    CpuFeatureScope avx_scope(assembler, AVX2);
    assembler->vinserti128(reg, reg, scratch, uint8_t{1});
  }
}

}  // namespace

void CodeGenerator::AssembleTailCallBeforeGap(Instruction* instr,
                                              int first_unused_slot_offset) {
  CodeGenerator::PushTypeFlags flags(kImmediatePush | kScalarPush);
  ZoneVector<MoveOperands*> pushes(zone());
  GetPushCompatibleMoves(instr, flags, &pushes);

  if (!pushes.empty() &&
      (LocationOperand::cast(pushes.back()->destination()).index() + 1 ==
       first_unused_slot_offset)) {
    DCHECK(!instr->HasCallDescriptorFlag(CallDescriptor::kIsTailCallForTierUp));
    X64OperandConverter g(this, instr);
    for (auto move : pushes) {
      LocationOperand destination_location(
          LocationOperand::cast(move->destination()));
      InstructionOperand source(move->source());
      AdjustStackPointerForTailCall(instr, masm(), linkage(), info(),
                                    frame_access_state(),
                                    destination_location.index());
      if (source.IsStackSlot()) {
        LocationOperand source_location(LocationOperand::cast(source));
        __ Push(g.SlotToOperand(source_location.index()));
      } else if (source.IsRegister()) {
        LocationOperand source_location(LocationOperand::cast(source));
        __ Push(source_location.GetRegister());
      } else if (source.IsImmediate()) {
        __ Push(Immediate(ImmediateOperand::cast(source).inline_int32_value()));
      } else {
        // Pushes of non-scalar data types is not supported.
        UNIMPLEMENTED();
      }
      frame_access_state()->IncreaseSPDelta(1);
      move->Eliminate();
    }
  }
  AdjustStackPointerForTailCall(instr, masm(), linkage(), info(),
                                frame_access_state(), first_unused_slot_offset,
                                false);
}

void CodeGenerator::AssembleTailCallAfterGap(Instruction* instr,
                                             int first_unused_slot_offset) {
  AdjustStackPointerForTailCall(instr, masm(), linkage(), info(),
                                frame_access_state(), first_unused_slot_offset);
}

// Check that {kJavaScriptCallCodeStartRegister} is correct.
void CodeGenerator::AssembleCodeStartRegisterCheck() {
  __ ComputeCodeStartAddress(rbx);
  __ cmpq(rbx, kJavaScriptCallCodeStartRegister);
  __ Assert(equal, AbortReason::kWrongFunctionCodeStart);
}

#ifdef V8_ENABLE_LEAPTIERING
// Check that {kJavaScriptCallDispatchHandleRegister} is correct.
void CodeGenerator::AssembleDispatchHandleRegisterCheck() {
  DCHECK(linkage()->GetIncomingDescriptor()->IsJSFunctionCall());

  // We currently don't check this for JS builtins as those are sometimes
  // called directly (e.g. from other builtins) and not through the dispatch
  // table. This is fine as builtin functions don't use the dispatch handle,
  // but we could enable this check in the future if we make sure to pass the
  // kInvalidDispatchHandle whenever we do a direct call to a JS builtin.
  if (Builtins::IsBuiltinId(info()->builtin())) {
    return;
  }

  // For now, we only ensure that the register references a valid dispatch
  // entry with the correct parameter count. In the future, we may also be able
  // to check that the entry points back to this code.
  __ LoadParameterCountFromJSDispatchTable(
      rbx, kJavaScriptCallDispatchHandleRegister);
  __ cmpl(rbx, Immediate(parameter_count_));
  __ Assert(equal, AbortReason::kWrongFunctionDispatchHandle);
}
#endif  // V8_ENABLE_LEAPTIERING

void CodeGenerator::BailoutIfDeoptimized() { __ BailoutIfDeoptimized(rbx); }

bool ShouldClearOutputRegisterBeforeInstruction(CodeGenerator* g,
                                                Instruction* instr) {
  X64OperandConverter i(g, instr);
  FlagsMode mode = FlagsModeField::decode(instr->opcode());
  if (mode == kFlags_set) {
    FlagsCondition condition = FlagsConditionField::decode(instr->opcode());
    if (condition != kUnorderedEqual && condition != kUnorderedNotEqual) {
      Register reg = i.OutputRegister(instr->OutputCount() - 1);
      // Do not clear output register when it is also input register.
      for (size_t index = 0; index < instr->InputCount(); ++index) {
        if (HasRegisterInput(instr, index) && reg == i.InputRegister(index))
          return false;
      }
      return true;
    }
  }
  return false;
}

void CodeGenerator::AssemblePlaceHolderForLazyDeopt(Instruction* instr) {
  if (info()->shadow_stack_compliant_lazy_deopt() &&
      instr->HasCallDescriptorFlag(CallDescriptor::kNeedsFrameState)) {
    __ Nop(MacroAssembler::kIntraSegmentJmpInstrSize);
  }
}

// Assembles an instruction after register allocation, producing machine code.
CodeGenerator::CodeGenResult CodeGenerator::AssembleArchInstruction(
    Instruction* instr) {
  X64OperandConverter i(this, instr);
  InstructionCode opcode = instr->opcode();
  ArchOpcode arch_opcode = ArchOpcodeField::decode(opcode);
  if (ShouldClearOutputRegisterBeforeInstruction(this, instr)) {
    // Transform setcc + movzxbl into xorl + setcc to avoid register stall and
    // encode one byte shorter.
    Register reg = i.OutputRegister(instr->OutputCount() - 1);
    __ xorl(reg, reg);
  }
  switch (arch_opcode) {
    case kX64TraceInstruction: {
      __ emit_trace_instruction(i.InputImmediate(0));
      break;
    }
    case kArchCallCodeObject: {
      if (HasImmediateInput(instr, 0)) {
        Handle<Code> code = i.InputCode(0);
        __ Call(code, RelocInfo::CODE_TARGET);
      } else {
        Register reg = i.InputRegister(0);
        CodeEntrypointTag tag =
            i.InputCodeEntrypointTag(instr->CodeEnrypointTagInputIndex());
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ LoadCodeInstructionStart(reg, reg, tag);
        __ call(reg);
      }
      RecordCallPosition(instr);
      AssemblePlaceHolderForLazyDeopt(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchCallBuiltinPointer: {
      DCHECK(!HasImmediateInput(instr, 0));
      Register builtin_index = i.InputRegister(0);
      __ CallBuiltinByIndex(builtin_index);
      RecordCallPosition(instr);
      AssemblePlaceHolderForLazyDeopt(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
#if V8_ENABLE_WEBASSEMBLY
    case kArchCallWasmFunction: {
      if (HasImmediateInput(instr, 0)) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt64());
        if (DetermineStubCallMode() == StubCallMode::kCallWasmRuntimeStub) {
          __ near_call(wasm_code, constant.rmode());
        } else {
          __ Call(wasm_code, constant.rmode());
        }
      } else {
        __ call(i.InputRegister(0));
      }
      RecordCallPosition(instr);
      AssemblePlaceHolderFo
```