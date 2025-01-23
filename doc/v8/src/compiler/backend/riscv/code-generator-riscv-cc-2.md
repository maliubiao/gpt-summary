Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/backend/riscv/code-generator-riscv.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Functionality:** The code snippet is a `switch` statement within a larger function (likely `AssembleInstruction`). It dispatches based on the `opcode` of an instruction (`i->opcode()`). Each `case` handles a specific RISC-V instruction or a higher-level operation that translates into a sequence of RISC-V instructions.

2. **Categorize the Operations:** Group similar functionalities to provide a clearer summary. Looking at the cases, obvious categories emerge:
    * Integer arithmetic and logical operations (like `kRiscvAdd`, `kRiscvAnd`, `kRiscvSarPair`).
    * Floating-point arithmetic operations (`kRiscvAddD`, `kRiscvSqrtD`).
    * Floating-point conversions (`kRiscvCvtSD`, `kRiscvFloorWD`).
    * Memory access operations (loads and stores: `kRiscvLbu`, `kRiscvSw`, `kRiscvLoadFloat`).
    * Stack manipulation (`kRiscvPush`, `kRiscvStackClaim`).
    * Atomic operations (`kAtomicLoadInt8`, `kAtomicExchangeWord32`).
    * Bit manipulation (`kRiscvBitcastDL`, `kRiscvByteSwap32`).

3. **Analyze Individual Cases:** For each case, understand what RISC-V assembly instruction(s) are being emitted using the `__` prefixed functions (e.g., `__ AddWord`, `__ fadd_d`, `__ Lw`). Recognize patterns like the use of `kScratchReg` and `kScratchDoubleReg` for temporary values.

4. **Address Specific Instructions:**  Some cases are more complex and require closer examination:
    * `kRiscvModD`:  It involves a C function call, indicating that the modulo operation for doubles isn't a direct RISC-V instruction.
    * Rounding operations (`kRiscvFloat64RoundDown`):  These use specific RISC-V rounding instructions.
    * Conversions with potential overflow handling (`kRiscvTruncWS`, `kRiscvTruncLD`, `kRiscvTruncUwS`): These have logic to detect and handle overflow cases, often setting the result to a minimum or maximum value.
    * Atomic operations: Recognize the use of `ASSEMBLE_ATOMIC_*` macros, which encapsulate sequences of load-reserved and store-conditional instructions to ensure atomicity.

5. **Check for .tq Extension:** The prompt specifically asks about the `.tq` extension. Based on common V8 practices,  `.tq` files are associated with Torque, a V8-specific language for generating compiler code. The provided snippet is C++, so the answer is that it's not a Torque file.

6. **Identify JavaScript Relevance:**  The operations performed in this code (arithmetic, memory access, etc.) are fundamental to JavaScript execution. Provide a simple JavaScript example that would involve these kinds of low-level operations during compilation and execution (e.g., basic arithmetic and variable assignment).

7. **Code Logic Inference:**  Choose an interesting case with some conditional logic. The overflow handling in `kRiscvTruncWS` is a good example. Create hypothetical input and output scenarios to illustrate the overflow behavior.

8. **Common Programming Errors:** Relate the operations to common programming errors. Integer overflow (demonstrated in the `kRiscvTruncWS` example) and incorrect memory access are good candidates.

9. **Synthesize the Summary:** Combine the categorized functionalities and specific observations into a concise summary. Emphasize that this code is part of the code generation process, translating higher-level IR into RISC-V assembly.

10. **Review and Refine:** Ensure the answer is clear, accurate, and addresses all parts of the prompt. Check for any technical inaccuracies or ambiguities. For instance, clarify the role of the `trapper` argument in memory access instructions.

By following these steps, the detailed and informative response can be generated, covering all the specific requirements of the user's prompt.
好的，根据您提供的代码片段，这是 `v8/src/compiler/backend/riscv/code-generator-riscv.cc` 文件的**第三部分**内容，它主要负责将 V8 的中间表示（IR）指令转换为 RISC-V 汇编代码。

以下是这段代码片段功能的归纳：

**主要功能：实现各种 RISC-V 特定指令的代码生成**

这段代码的核心是一个 `switch` 语句，根据不同的 `opcode` (操作码) 来生成相应的 RISC-V 汇编指令。  涵盖了以下几大类操作：

1. **双精度浮点运算:**  实现了加 (`kRiscvAddD`)、减 (`kRiscvSubD`)、乘 (`kRiscvMulD`)、除 (`kRiscvDivD`)、取模 (`kRiscvModD`)、绝对值 (`kRiscvAbsD`)、取反 (`kRiscvNegD`)、平方根 (`kRiscvSqrtD`)、最大值 (`kRiscvMaxD`)、最小值 (`kRiscvMinD`) 等双精度浮点运算指令的生成。  `kRiscvModD`  使用了 C 函数调用来实现。

2. **浮点数舍入:**  实现了将双精度浮点数向不同方向舍入的指令，包括向下取整 (`kRiscvFloat64RoundDown`)、向零取整 (`kRiscvFloat64RoundTruncate`)、向上取整 (`kRiscvFloat64RoundUp`)、向偶数舍入 (`kRiscvFloat64RoundTiesEven`)，以及单精度浮点数的类似操作 (`kRiscvFloat32RoundDown` 等)。

3. **浮点数比较和 NaN 处理:**  实现了浮点数的最大值 (`kRiscvFloat64Max`, `kRiscvFloat32Max`)、最小值 (`kRiscvFloat64Min`, `kRiscvFloat32Min`) 操作，以及将 NaN 值规范化的操作 (`kRiscvFloat64SilenceNaN`)。

4. **浮点数类型转换:**  实现了各种浮点数类型之间的转换，例如双精度转单精度 (`kRiscvCvtSD`)、单精度转双精度 (`kRiscvCvtDS`)，以及浮点数与整数之间的转换 (`kRiscvCvtDW`, `kRiscvFloorWD` 等)。  在浮点数转整数的指令中，还包含对溢出情况的处理。

5. **浮点数位操作:**  实现了浮点数的位操作，例如将双精度浮点数的位表示转换为长整型 (`kRiscvBitcastDL`)，反之亦然 (`kRiscvBitcastLD`)。

6. **浮点数的组成和分解:** 提供了提取双精度浮点数的低 32 位 (`kRiscvFloat64ExtractLowWord32`) 和高 32 位 (`kRiscvFloat64ExtractHighWord32`)，以及用给定的 32 位值插入到双精度浮点数的低位 (`kRiscvFloat64InsertLowWord32`) 和高位 (`kRiscvFloat64InsertHighWord32`) 的功能。

7. **符号扩展:** 实现了将字节 (`kRiscvSignExtendByte`) 和短整型 (`kRiscvSignExtendShort`) 进行符号扩展的指令。

8. **内存访问 (Load/Store):** 实现了从内存加载和存储各种大小的数据，包括字节 (`kRiscvLbu`, `kRiscvLb`, `kRiscvSb`)、半字 (`kRiscvLhu`, `kRiscvLh`, `kRiscvSh`)、字 (`kRiscvLw`, `kRiscvSw`)、双字 (`kRiscvLd`, `kRiscvSd`，仅限 RISC-V 64 位架构) 以及浮点数 (`kRiscvLoadFloat`, `kRiscvStoreFloat`, `kRiscvLoadDouble`, `kRiscvStoreDouble`)。  还包括了未对齐的内存访问 (`kRiscvUlhu`, `kRiscvUlw` 等)。

9. **栈操作:** 实现了压栈 (`kRiscvPush`)、窥视栈顶元素 (`kRiscvPeek`)、栈空间申请 (`kRiscvStackClaim`) 和存储数据到栈槽 (`kRiscvStoreToStackSlot`) 的操作。

10. **字节序转换:** 提供了字节交换的指令，用于处理不同字节序之间的数据转换 (`kRiscvByteSwap64`, `kRiscvByteSwap32`)。

11. **原子操作:** 实现了各种原子加载 (`kAtomicLoadInt8`, `kAtomicLoadUint8` 等)、原子存储 (`kAtomicStoreWord8`, `kAtomicStoreWord16` 等)、原子交换 (`kAtomicExchangeInt8`, `kAtomicExchangeUint8` 等) 和原子比较交换 (`kAtomicCompareExchangeInt8`, `kAtomicCompareExchangeUint8` 等) 操作。  对于 RISC-V 32 位架构，还包含了 64 位原子对操作 (`kRiscvWord32AtomicPairLoad`, `kRiscvWord32AtomicPairStore` 等)，这些操作通常通过调用 C 函数来实现。

**关于文件类型和 JavaScript 关系：**

* **文件类型:**  `v8/src/compiler/backend/riscv/code-generator-riscv.cc` 以 `.cc` 结尾，这是一个标准的 C++ 源文件扩展名。因此，它不是 V8 Torque 源代码。

* **与 JavaScript 的关系:**  这段代码直接参与了 JavaScript 代码的编译和执行过程。当 V8 编译 JavaScript 代码时，它会将 JavaScript 翻译成中间表示 (IR)，然后 `code-generator-riscv.cc` 的功能就是将这些 IR 指令转换成可以在 RISC-V 架构上执行的机器码。

**JavaScript 示例:**

以下 JavaScript 代码的执行会涉及到这段 C++ 代码的功能：

```javascript
let a = 1.5;
let b = 2.7;
let sum = a + b;
let roundedSum = Math.floor(sum);
let intValue = roundedSum | 0; // 将浮点数转换为 32 位整数

let arr = new Float64Array(1);
arr[0] = sum;
let lowBits = arr[0]; // 这里会涉及浮点数的内存表示

let counter = 0;
Atomics.add(new Int32Array(new SharedArrayBuffer(4)), 0, 1); // 原子操作
```

在这个例子中：

* `a + b` 会使用浮点加法运算，对应 `kRiscvAddD`。
* `Math.floor(sum)` 会使用浮点数向下取整，对应 `kRiscvFloat64RoundDown`。
* `roundedSum | 0` 会将浮点数转换为整数，可能对应 `kRiscvFloorWD` 或类似的转换指令。
* `arr[0] = sum` 会将双精度浮点数存储到内存，对应 `kRiscvStoreDouble`。
* `Atomics.add` 会使用原子加法操作，对应 `kAtomicAddWord32` 或类似的指令。

**代码逻辑推理 (以 `kRiscvTruncWS` 为例):**

**假设输入:**

* `instr` 指向一个 `kRiscvTruncWS` 指令。
* `i.InputDoubleRegister(0)` 包含一个单精度浮点数，例如 `3.7`。
* `instr->OutputCount() > 1` 为 `false`，意味着只需要一个输出寄存器。

**预期输出:**

* 生成的 RISC-V 汇编代码会将 `3.7` 向零取整，并将结果 `3` 存储到 `i.OutputRegister()` 指定的寄存器中。

**假设输入（溢出情况）:**

* `instr` 指向一个 `kRiscvTruncWS` 指令，且 `MiscField::decode(instr->opcode())` 为 `true` (表示溢出时设置为 `INT32_MIN`)。
* `i.InputDoubleRegister(0)` 包含一个单精度浮点数，例如 `2147483648.0` (大于 `INT32_MAX`)。

**预期输出:**

* 生成的 RISC-V 汇编代码会将 `2147483648.0` 尝试转换为整数。由于溢出，并且设置了溢出处理，最终会将 `INT32_MIN` 的值存储到 `i.OutputRegister()` 指定的寄存器中。

**用户常见的编程错误:**

这段代码生成的指令与用户在 JavaScript 中可能犯的错误密切相关：

1. **浮点数精度问题:**  用户可能会期望浮点运算得到精确的结果，但由于浮点数的表示方式，可能会出现精度丢失。例如，对两个看起来很简单的浮点数进行加法，其二进制表示可能导致精度损失。 这与 `kRiscvAddD` 等浮点运算指令有关。

   ```javascript
   let x = 0.1 + 0.2;
   console.log(x === 0.3); // 输出 false
   ```

2. **整数溢出:**  在进行浮点数到整数的转换时，如果浮点数的值超出了整数类型的表示范围，就会发生溢出。这段代码中 `kRiscvTruncWS` 等指令的处理就与此相关。

   ```javascript
   let floatValue = 2147483648.0;
   let intValue = floatValue | 0; // 可能会得到意外的结果，取决于实现
   ```

3. **未对齐的内存访问:**  尽管这段代码包含了处理未对齐内存访问的指令 (`kRiscvUlhu` 等)，但在某些情况下，用户直接操作内存缓冲区时，如果地址未对齐，可能会导致错误。  现代 JavaScript 引擎通常会处理这种情况，但理解底层原理很重要。

4. **原子操作使用不当:**  在多线程或共享内存的场景下，如果原子操作使用不当，可能导致数据竞争和程序错误。例如，忘记使用原子操作来更新共享变量。 这与 `kAtomicAddWord32` 等原子操作指令有关。

   ```javascript
   // 多线程场景
   let counter = 0;
   // 两个线程同时执行 incrementCounter
   function incrementCounter() {
     counter++; // 非原子操作，可能导致数据竞争
   }

   function incrementCounterAtomic() {
     Atomics.add(sharedArray, 0, 1); // 原子操作，保证线程安全
   }
   ```

**总结：**

这段代码是 V8 引擎中 RISC-V 架构代码生成器的核心部分，负责将高级的中间表示指令转换为底层的 RISC-V 汇编指令。它涵盖了各种算术运算、类型转换、内存访问和原子操作，是 JavaScript 代码在 RISC-V 架构上高效执行的关键组成部分。 这部分代码的正确性和效率直接影响着 JavaScript 程序的性能。

### 提示词
```
这是目录为v8/src/compiler/backend/riscv/code-generator-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/riscv/code-generator-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
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
```