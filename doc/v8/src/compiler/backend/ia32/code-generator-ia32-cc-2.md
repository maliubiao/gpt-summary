Response:
My thought process to answer the request goes like this:

1. **Understand the Core Request:** The primary goal is to analyze a code snippet from `v8/src/compiler/backend/ia32/code-generator-ia32.cc` and explain its functionality. The request also includes several specific constraints, such as checking for `.tq` extension, relating to JavaScript, providing examples, and summarizing the functionality for this specific part (part 3 of 6).

2. **Initial Scan for Keywords and Patterns:** I quickly scan the code for recognizable IA-32 assembly instructions (like `mov`, `push`, `add`, `sub`, `xor`, `cmp`, and the SIMD instructions like `paddd`, `pslld`, etc.) and patterns within the `switch` statement. The `case` labels starting with `kIA32` and `kSSE`/`kAVX` immediately tell me this code is handling instruction generation for different IA-32 instruction set extensions.

3. **Identify the Overall Structure:** The code is clearly within a `switch` statement operating on the opcode of an instruction (`instr->opcode()`). This suggests it's a dispatch mechanism where different code blocks handle different types of instructions. The `__` prefix before assembly instructions indicates that it's using some kind of assembler helper or macro system (likely within V8's codebase).

4. **Analyze Individual Cases (Focus on Representative Examples):**  I don't need to understand every single case in detail at this stage. Instead, I'll pick a few representative examples from different categories:
    * **Stack Manipulation (`kIA32Push`, `kIA32Poke`, `kIA32Peek`):** These cases deal with moving data to and from the stack. They demonstrate how the code interacts with memory locations relative to the stack pointer (`esp`) and frame pointer (`ebp`).
    * **Floating-Point SIMD (`kIA32F64x2Splat`, `kIA32F64x2Add`, etc.):**  These show how the code generates instructions for operating on double-precision floating-point numbers in SIMD registers.
    * **Integer SIMD (`kIA32I64x2Abs`, `kIA32I32x4Add`, etc.):** Similar to floating-point, these handle integer SIMD operations.
    * **Conversions (`kIA32F32x4SConvertI32x4`, `kIA32I32x4UConvertF32x4`):** These deal with converting between different data types (float to integer, signed to unsigned).
    * **Conditional Operations (`kIA32F64x2Eq`, `kIA32I32x4GtS`):** These show how comparisons are implemented in SIMD.
    * **Instructions with CPU Feature Checks (`kIA32Insertps`, `kSSEI32x4UConvertF32x4`, `kAVXI32x4UConvertF32x4`):**  These highlight how the code adapts to different CPU capabilities (SSE, AVX).

5. **Infer High-Level Functionality:** Based on the types of instructions being generated, I can infer the overall functionality of this code: it's responsible for translating higher-level intermediate representation (likely from V8's compiler pipeline) into actual IA-32 machine code. It specifically handles a variety of operations, including:
    * Stack management
    * Basic arithmetic and logical operations
    * Floating-point and integer SIMD operations
    * Data type conversions
    * Comparisons
    * Conditional moves/selections (implicitly through comparison results)

6. **Address the Specific Constraints:**
    * **`.tq` Extension:** The code snippet is C++, not Torque, so this part is straightforward.
    * **Relationship to JavaScript:**  Since V8 executes JavaScript, this code directly implements the low-level operations that make JavaScript features possible (e.g., array manipulation, numerical calculations, etc.). I need to come up with JavaScript examples that would trigger these kinds of low-level operations.
    * **Code Logic and Examples:** For cases like stack manipulation, I can create simple scenarios of function calls and local variable allocation to illustrate the stack operations. For SIMD, array operations or vector calculations in JavaScript serve as good examples. I need to provide both the conceptual operation and the potential underlying assembly.
    * **Common Programming Errors:**  Think about errors related to data types (e.g., mixing floats and integers incorrectly), stack overflows (though less directly related to *this specific code* but conceptually linked to stack operations), and incorrect assumptions about data layout in memory.
    * **Part 3 Summary:**  Focus on the categories of instructions covered in this particular snippet. It seems to heavily emphasize stack operations and SIMD instructions.

7. **Structure the Answer:**  Organize the information logically, starting with the high-level summary and then going into details for each constraint. Use clear headings and examples. Make sure to address each part of the original request.

8. **Refine and Review:**  Read through the answer to ensure accuracy, clarity, and completeness. Double-check the assembly instructions and their meanings. Make sure the JavaScript examples are relevant and easy to understand. Ensure the summary accurately reflects the content of the provided code. For instance, initially, I might just say "handles SIMD", but I should refine it to specify "handles various SIMD operations for both floating-point and integer data types."

By following these steps, I can systematically analyze the code snippet and generate a comprehensive and accurate answer that addresses all the requirements of the prompt.
```
这是目录为v8/src/compiler/backend/ia32/code-generator-ia32.cc的一个v8源代码， 请列举一下它的功能,
如果v8/src/compiler/backend/ia32/code-generator-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

**功能归纳 (针对提供的代码片段):**

这段代码是 V8 JavaScript 引擎中 IA-32 架构的代码生成器的一部分，负责将中间表示 (IR) 的指令转换为具体的 IA-32 汇编代码。 这部分代码主要处理以下功能：

1. **栈操作:**
   - `kIA32Push`: 将数据压入栈中，根据数据类型（普通寄存器、浮点数栈槽、双精度栈槽、SIMD栈槽）选择不同的汇编指令和栈空间分配方式。
   - `kIA32Poke`: 将数据写入栈中的指定偏移位置。
   - `kIA32Peek`: 从栈中的指定偏移位置读取数据到寄存器（通用寄存器或浮点寄存器）。

2. **SIMD (单指令多数据流) 浮点数操作:**
   - `kIA32F64x2Splat`: 将一个双精度浮点数复制到 SIMD 寄存器的所有通道。
   - `kIA32F64x2ExtractLane`: 从 SIMD 寄存器中提取指定通道的双精度浮点数。
   - `kIA32F64x2ReplaceLane`: 将 SIMD 寄存器中指定通道的双精度浮点数替换为另一个双精度浮点数。
   - `kIA32F64x2Sqrt`, `kIA32F64x2Add`, `kIA32F64x2Sub`, `kIA32F64x2Mul`, `kIA32F64x2Div`:  双精度浮点数的 SIMD 算术运算。
   - `kIA32F64x2Min`, `kIA32F64x2Max`:  双精度浮点数的 SIMD 最小值和最大值运算。
   - `kIA32F64x2Eq`, `kIA32F64x2Ne`, `kIA32F64x2Lt`, `kIA32F64x2Le`: 双精度浮点数的 SIMD 比较运算。
   - `kIA32F64x2Qfma`, `kIA32F64x2Qfms`: 双精度浮点数的 SIMD 融合乘加/减运算。
   - `kIA32Minpd`, `kIA32Maxpd`:  双精度浮点数的 SIMD 最小值和最大值运算 (另一种指令)。
   - `kIA32F64x2Round`: 双精度浮点数的 SIMD 舍入运算。
   - `kIA32F64x2PromoteLowF32x4`: 将低 32 位浮点数扩展为双精度浮点数。
   - `kIA32F32x4DemoteF64x2Zero`: 将双精度浮点数降级为单精度浮点数。
   - `kIA32I32x4TruncSatF64x2SZero`, `kIA32I32x4TruncSatF64x2UZero`: 将双精度浮点数截断为有符号/无符号 32 位整数。
   - `kIA32F64x2ConvertLowI32x4S`, `kIA32F64x2ConvertLowI32x4U`: 将 32 位有符号/无符号整数转换为双精度浮点数。
   - 以及其他 `F64x2...` 开头的指令，都是针对双精度浮点数的 SIMD 操作。

3. **SIMD 整数操作:**
   - `kIA32I64x2ExtMulLowI32x4S`, `kIA32I64x2ExtMulHighI32x4S`, `kIA32I64x2ExtMulLowI32x4U`, `kIA32I64x2ExtMulHighI32x4U`: 64 位整数 SIMD 扩展乘法。
   - `kIA32I32x4ExtMulLowI16x8S`, `kIA32I32x4ExtMulHighI16x8S`, `kIA32I32x4ExtMulLowI16x8U`, `kIA32I32x4ExtMulHighI16x8U`: 32 位整数 SIMD 扩展乘法。
   - `kIA32I16x8ExtMulLowI8x16S`, `kIA32I16x8ExtMulHighI8x16S`, `kIA32I16x8ExtMulLowI8x16U`, `kIA32I16x8ExtMulHighI8x16U`: 16 位整数 SIMD 扩展乘法。
   - `kIA32I64x2SplatI32Pair`: 将一对 32 位整数组合成 64 位整数并复制到 SIMD 寄存器。
   - `kIA32I64x2ReplaceLaneI32Pair`: 替换 SIMD 寄存器中指定的 64 位整数通道。
   - `kIA32I64x2Abs`, `kIA32I64x2Neg`, `kIA32I64x2Shl`, `kIA32I64x2ShrS`, `kIA32I64x2Add`, `kIA32I64x2Sub`, `kIA32I64x2Mul`, `kIA32I64x2ShrU`: 64 位整数 SIMD 算术和位运算。
   - `kIA32I64x2BitMask`: 从 SIMD 寄存器中提取位掩码。
   - `kIA32I64x2Eq`, `kIA32I64x2Ne`, `kIA32I64x2GtS`, `kIA32I64x2GeS`: 64 位整数 SIMD 比较运算。
   - `kIA32I64x2SConvertI32x4Low`, `kIA32I64x2SConvertI32x4High`, `kIA32I64x2UConvertI32x4Low`, `kIA32I64x2UConvertI32x4High`: 将 32 位整数转换为 64 位整数。
   - `kIA32I32x4ExtAddPairwiseI16x8S`, `kIA32I32x4ExtAddPairwiseI16x8U`, `kIA32I16x8ExtAddPairwiseI8x16S`, `kIA32I16x8ExtAddPairwiseI8x16U`:  SIMD 成对加法。
   - `kIA32I16x8Q15MulRSatS`, `kIA32I16x8RelaxedQ15MulRS`:  SIMD 饱和乘法。
   - `kIA32I16x8DotI8x16I7x16S`, `kIA32I32x4DotI8x16I7x16AddS`: SIMD 点积运算。
   - 以及其他 `I64x2...`, `I32x4...`, `I16x8...` 开头的指令，都是针对不同位宽整数的 SIMD 操作。

4. **SIMD 单精度浮点数操作:**
   - `kIA32F32x4Splat`: 将一个单精度浮点数复制到 SIMD 寄存器的所有通道。
   - `kIA32F32x4ExtractLane`: 从 SIMD 寄存器中提取指定通道的单精度浮点数。
   - `kIA32Insertps`: 向 SIMD 寄存器中插入一个单精度浮点数。
   - `kIA32F32x4SConvertI32x4`, `kIA32F32x4UConvertI32x4`: 将 32 位整数转换为单精度浮点数。
   - `kIA32F32x4Sqrt`, `kIA32F32x4Add`, `kIA32F32x4Sub`, `kIA32F32x4Mul`, `kIA32F32x4Div`: 单精度浮点数的 SIMD 算术运算。
   - `kIA32F32x4Min`, `kIA32F32x4Max`: 单精度浮点数的 SIMD 最小值和最大值运算。
   - `kIA32F32x4Eq`, `kIA32F32x4Ne`, `kIA32F32x4Lt`, `kIA32F32x4Le`: 单精度浮点数的 SIMD 比较运算。
   - `kIA32F32x4Qfma`, `kIA32F32x4Qfms`: 单精度浮点数的 SIMD 融合乘加/减运算。
   - `kIA32Minps`, `kIA32Maxps`: 单精度浮点数的 SIMD 最小值和最大值运算 (另一种指令)。
   - `kIA32F32x4Round`: 单精度浮点数的 SIMD 舍入运算。

5. **SIMD 整数操作 (续):**
   - `kIA32I32x4Splat`: 将一个 32 位整数复制到 SIMD 寄存器的所有通道。
   - `kIA32I32x4ExtractLane`: 从 SIMD 寄存器中提取指定通道的 32 位整数。
   - `kIA32I32x4SConvertF32x4`: 将单精度浮点数转换为 32 位有符号整数。
   - `kIA32I32x4SConvertI16x8Low`, `kIA32I32x4SConvertI16x8High`: 将 16 位整数转换为 32 位有符号整数。
   - `kIA32I32x4Neg`, `kIA32I32x4Shl`, `kIA32I32x4ShrS`, `kIA32I32x4Add`, `kIA32I32x4Sub`, `kIA32I32x4Mul`, `kIA32I32x4MinS`, `kIA32I32x4MaxS`, `kIA32I32x4Eq`, `kIA32I32x4Ne`, `kIA32I32x4GtS`, `kIA32I32x4GeS`: 32 位整数 SIMD 算术、位运算和比较运算。
   - `kSSEI32x4UConvertF32x4`, `kAVXI32x4UConvertF32x4`: 将单精度浮点数转换为 32 位无符号整数 (有 SSE 和 AVX 版本)。
   - `kIA32I32x4UConvertI16x8Low`, `kIA32I32x4UConvertI16x8High`: 将 16 位整数转换为 32 位无符号整数。
   - `kIA32I32x4ShrU`, `kIA32I32x4MinU`, `kIA32I32x4MaxU`: 32 位整数 SIMD 无符号右移、最小值和最大值运算。
   - `kSSEI32x4GtU`, `kAVXI32x4GtU`, `kSSEI32x4GeU`, `kAVXI32x4GeU`: 32 位整数 SIMD 无符号比较运算 (有 SSE 和 AVX 版本)。
   - `kIA32I32x4Abs`, `kIA32I32x4BitMask`, `kIA32I32x4DotI16x8S`: 32 位整数 SIMD 绝对值、位掩码和点积运算。

6. **SIMD 16 位整数操作:**
   - `kIA32I16x8Splat`: 将一个 16 位整数复制到 SIMD 寄存器的所有通道。
   - `kIA32I16x8ExtractLaneS`: 从 SIMD 寄存器中提取指定通道的 16 位有符号整数。
   - `kIA32I16x8SConvertI8x16Low`, `kIA32I16x8SConvertI8x16High`: 将 8 位整数转换为 16 位有符号整数。
   - `kIA32I16x8Neg`, `kIA32I16x8Shl`, `kIA32I16x8ShrS`, `kIA32I16x8SConvertI32x4`, `kIA32I16x8Add`, `kIA32I16x8AddSatS`, `kIA32I16x8Sub`, `kIA32I16x8SubSatS`, `kIA32I16x8Mul`, `kIA32I16x8MinS`, `kIA32I16x8MaxS`, `kIA32I16x8Eq`, `kSSEI16x8Ne`, `kAVXI16x8Ne`, `kIA32I16x8GtS`, `kSSEI16x8GeS`, `kAVXI16x8GeS`: 16 位整数 SIMD 算术、位运算、转换和比较运算 (有 SSE 和 AVX 版本)。
   - `kIA32I16x8UConvertI8x16Low`, `kIA32I16x8UConvertI8x16High`, `kIA32I16x8ShrU`, `kIA32I16x8UConvertI32x4`, `kIA32I16x8AddSatU`, `kIA32I16x8SubSatU`, `kIA32I16x8MinU`, `kIA32I16x8MaxU`, `kSSEI16x8GtU`, `kAVXI16x8GtU`, `kSSEI16x8GeU`, `kAVXI16x8GeU`: 16 位整数 SIMD 无符号操作 (有 SSE 和 AVX 版本)。

**关于代码的特性：**

- **IA-32 特定:** 代码中使用了 IA-32 架构的汇编指令，例如 `mov`, `push`, `add`, `sub`, 以及各种 SIMD 指令 (如 `movsd`, `addpd`, `paddd`, `pslld` 等)。
- **V8 内部接口:** 代码中使用了 V8 提供的宏和辅助函数（以 `__` 开头），例如 `__ AllocateStackSpace`, `__ push`, `__ mov` 等，这些是 V8 内部用于生成汇编代码的抽象层。
- **指令处理:** 通过 `switch` 语句处理不同的 IR 指令 (`instr->opcode()`)，并为每种指令生成相应的汇编代码。
- **寄存器和内存操作:** 代码涉及到寄存器的分配和使用（例如 `i.OutputRegister()`, `i.InputRegister()`, `kScratchDoubleReg`）以及内存操作（例如 `Operand(esp, 0)`, `Operand(ebp, offset)`）。
- **SIMD 支持:**  大量的代码处理 SIMD 指令，涵盖了浮点数和整数的各种操作，这表明 V8 引擎在 IA-32 架构上对 SIMD 进行了广泛的优化。
- **CPU 特性检测:**  可以看到代码中有使用 `CpuFeatures::IsSupported(AVX)` 来判断 CPU 是否支持 AVX 指令集，并根据支持情况生成不同的代码，这体现了 V8 对不同 CPU 架构和特性的适配能力。

**如果 `v8/src/compiler/backend/ia32/code-generator-ia32.cc` 以 `.tq` 结尾：**

那么它将是一个用 V8 的 Torque 语言编写的源代码。Torque 是一种用于定义 V8 内部运行时代码和编译器内置函数的领域特定语言。它允许以更高级、更类型安全的方式描述底层的操作，然后 Torque 编译器会将其转换为 C++ 代码。 然而，实际情况是 `code-generator-ia32.cc` 是 C++ 文件。

**与 JavaScript 的关系以及 JavaScript 示例：**

这段代码直接负责将 JavaScript 代码编译成 IA-32 机器码。 每当 JavaScript 代码执行到需要进行底层操作（例如数学运算、数组操作、类型转换等）时，V8 的编译器就会调用类似这样的代码来生成相应的机器指令。

以下是一些 JavaScript 示例，它们可能会触发这段代码中处理的某些操作：

1. **栈操作:**
   ```javascript
   function foo(a, b) {
     let sum = a + b;
     return sum;
   }
   foo(1, 2);
   ```
   在这个例子中，函数 `foo` 的参数 `a` 和 `b` 以及局部变量 `sum` 可能会被分配到栈上，涉及到 `kIA32Push` 和 `kIA32Poke` 类似的操作。 函数返回时，可能涉及到从栈上弹出数据。

2. **SIMD 浮点数操作:**
   ```javascript
   let arr1 = new Float64Array([1.0, 2.0]);
   let arr2 = new Float64Array([3.0, 4.0]);
   let result = new Float64Array(2);
   for (let i = 0; i < arr1.length; i++) {
     result[i] = Math.sqrt(arr1[i]) + arr2[i] * 2;
   }
   ```
   这段代码对 `Float64Array` 进行操作，V8 可能会利用 SIMD 指令来加速这些操作，例如 `kIA32F64x2Sqrt`, `kIA32F64x2Add`, `kIA32F64x2Mul` 等。

3. **SIMD 整数操作:**
   ```javascript
   let arr1 = new Int32Array([1, 2, 3, 4]);
   let arr2 = new Int32Array([5, 6, 7, 8]);
   let result = new Int32Array(4);
   for (let i = 0; i < arr1.length; i++) {
     result[i] = arr1[i] * arr2[i] + 10;
   }
   ```
   类似地，对 `Int32Array` 的操作也可能使用 SIMD 指令，例如 `kIA32I32x4Mul`, `kIA32I32x4Add`。

**代码逻辑推理和假设输入输出：**

以 `case kIA32Push:` 为例：

**假设输入：** 一个 IR 指令 `instr`，其 `opcode()` 为 `kIA32Push`，并且 `instr->InputAt(1)` 指向一个表示浮点数栈槽的 `LocationOperand`。`stack_decrement` 的值为 16 (假设需要分配 16 字节的空间)。

**代码逻辑推理：**

1. 进入 `case kIA32Push:` 分支。
2. 检查 `input->IsFloatStackSlot()` 为真。
3. 调用 `__ AllocateStackSpace(16 - 4)`，即分配 12 字节的栈空间 (减去一个 `kSystemPointerSize`)。
4. 执行 `__ push(i.InputOperand(1))`，将 `instr` 的第二个输入操作数（表示要压入栈的浮点数）的值压入栈顶。
5. 调用 `frame_access_state()->IncreaseSPDelta(slots)`，其中 `slots` 为 1，表示栈指针增加了 1 个槽位（即 `kSystemPointerSize`）。

**假设输出：** 生成的汇编代码会将栈指针 `esp` 减去 12，并将指定的浮点数值压入当前的栈顶位置。栈指针的偏移量会更新。

**用户常见的编程错误：**

虽然这段代码是 V8 内部的代码生成器，但用户在编写 JavaScript 时的错误会影响到生成的机器码。以下是一些可能相关的错误：

1. **类型不匹配导致的转换开销:**  如果 JavaScript 代码中频繁进行不同类型之间的运算（例如，整数和浮点数混合运算），编译器可能需要生成额外的转换指令，这可能会降低性能。

   ```javascript
   let a = 10; // 整数
   let b = 3.14; // 浮点数
   let c = a + b; // 整数需要转换为浮点数才能相加
   ```

2. **过度使用非类型化数组:**  虽然 JavaScript 的灵活性很高，但如果性能是关键，过度使用普通的 `Array` 可能会导致 V8 无法进行有效的优化，包括 SIMD 优化。使用类型化数组（如 `Float64Array`, `Int32Array`）可以提供更多类型信息，帮助 V8 生成更高效的 SIMD 代码。

3. **在循环中进行不必要的操作:**  例如，在循环中重复计算不变量，这会导致生成冗余的机器码。V8 的优化编译器会尝试识别并优化这些情况，但最好还是避免：

   ```javascript
   let arr = new Array(1000);
   for (let i = 0; i < arr.length; i++) {
     arr[i] = Math.sqrt(2) * i; // Math.sqrt(2) 可以放在循环外部计算
   }
   ```

**总结一下它的功能 (针对提供的代码片段):**

这段 `code-generator-ia32.cc` 的代码片段是 V8 引擎在 IA-32 架构上生成机器码的核心部分，专门负责处理栈操作以及大量的 SIMD 浮点数和整数运算指令。它根据不同的 IR 指令生成相应的 IA-32 汇编代码，包括针对不同数据类型和 SIMD 操作的优化指令。代码中还考虑了 CPU 特性，以便在支持 AVX 等指令集的处理器上生成更高效的代码。 这部分代码的功能对于 V8 引擎在 IA-32 架构上执行 JavaScript 代码的性能至关重要，尤其是在处理需要大量数值计算或数据并行处理的场景下。

### 提示词
```
这是目录为v8/src/compiler/backend/ia32/code-generator-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/ia32/code-generator-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
ckSlot() || input->IsFloatStackSlot()) {
          __ AllocateStackSpace(stack_decrement - kSystemPointerSize);
          __ push(i.InputOperand(1));
        } else if (input->IsDoubleStackSlot()) {
          DCHECK_GE(stack_decrement, kDoubleSize);
          __ Movsd(kScratchDoubleReg, i.InputOperand(1));
          __ AllocateStackSpace(stack_decrement);
          __ Movsd(Operand(esp, 0), kScratchDoubleReg);
        } else {
          DCHECK(input->IsSimd128StackSlot());
          DCHECK_GE(stack_decrement, kSimd128Size);
          // TODO(bbudge) Use Movaps when slots are aligned.
          __ Movups(kScratchDoubleReg, i.InputOperand(1));
          __ AllocateStackSpace(stack_decrement);
          __ Movups(Operand(esp, 0), kScratchDoubleReg);
        }
      }
      frame_access_state()->IncreaseSPDelta(slots);
      break;
    }
    case kIA32Poke: {
      int slot = MiscField::decode(instr->opcode());
      if (HasImmediateInput(instr, 0)) {
        __ mov(Operand(esp, slot * kSystemPointerSize), i.InputImmediate(0));
      } else {
        __ mov(Operand(esp, slot * kSystemPointerSize), i.InputRegister(0));
      }
      break;
    }
    case kIA32Peek: {
      int reverse_slot = i.InputInt32(0);
      int offset =
          FrameSlotToFPOffset(frame()->GetTotalFrameSlotCount() - reverse_slot);
      if (instr->OutputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->OutputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ Movsd(i.OutputDoubleRegister(), Operand(ebp, offset));
        } else if (op->representation() == MachineRepresentation::kFloat32) {
          __ Movss(i.OutputFloatRegister(), Operand(ebp, offset));
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
          __ Movdqu(i.OutputSimd128Register(), Operand(ebp, offset));
        }
      } else {
        __ mov(i.OutputRegister(), Operand(ebp, offset));
      }
      break;
    }
    case kIA32F64x2Splat: {
      __ Movddup(i.OutputSimd128Register(), i.InputDoubleRegister(0));
      break;
    }
    case kIA32F64x2ExtractLane: {
      __ F64x2ExtractLane(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                          i.InputUint8(1));
      break;
    }
    case kIA32F64x2ReplaceLane: {
      __ F64x2ReplaceLane(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          i.InputDoubleRegister(2), i.InputInt8(1));
      break;
    }
    case kIA32F64x2Sqrt: {
      __ Sqrtpd(i.OutputSimd128Register(), i.InputOperand(0));
      break;
    }
    case kIA32F64x2Add: {
      __ Addpd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputOperand(1));
      break;
    }
    case kIA32F64x2Sub: {
      __ Subpd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputOperand(1));
      break;
    }
    case kIA32F64x2Mul: {
      __ Mulpd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputOperand(1));
      break;
    }
    case kIA32F64x2Div: {
      __ Divpd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputOperand(1));
      break;
    }
    case kIA32F64x2Min: {
      __ F64x2Min(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kIA32F64x2Max: {
      __ F64x2Max(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kIA32F64x2Eq: {
      __ Cmpeqpd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32F64x2Ne: {
      __ Cmpneqpd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputOperand(1));
      break;
    }
    case kIA32F64x2Lt: {
      __ Cmpltpd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32F64x2Le: {
      __ Cmplepd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32F64x2Qfma: {
      __ F64x2Qfma(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1), i.InputSimd128Register(2),
                   kScratchDoubleReg);
      break;
    }
    case kIA32F64x2Qfms: {
      __ F64x2Qfms(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1), i.InputSimd128Register(2),
                   kScratchDoubleReg);
      break;
    }
    case kIA32Minpd: {
      __ Minpd(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kIA32Maxpd: {
      __ Maxpd(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kIA32F64x2Round: {
      RoundingMode const mode =
          static_cast<RoundingMode>(MiscField::decode(instr->opcode()));
      __ Roundpd(i.OutputSimd128Register(), i.InputDoubleRegister(0), mode);
      break;
    }
    case kIA32F64x2PromoteLowF32x4: {
      if (HasAddressingMode(instr)) {
        __ Cvtps2pd(i.OutputSimd128Register(), i.MemoryOperand());
      } else {
        __ Cvtps2pd(i.OutputSimd128Register(), i.InputSimd128Register(0));
      }
      break;
    }
    case kIA32F32x4DemoteF64x2Zero: {
      __ Cvtpd2ps(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kIA32I32x4TruncSatF64x2SZero: {
      __ I32x4TruncSatF64x2SZero(i.OutputSimd128Register(),
                                 i.InputSimd128Register(0), kScratchDoubleReg,
                                 i.TempRegister(0));
      break;
    }
    case kIA32I32x4TruncSatF64x2UZero: {
      __ I32x4TruncSatF64x2UZero(i.OutputSimd128Register(),
                                 i.InputSimd128Register(0), kScratchDoubleReg,
                                 i.TempRegister(0));
      break;
    }
    case kIA32F64x2ConvertLowI32x4S: {
      __ Cvtdq2pd(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kIA32F64x2ConvertLowI32x4U: {
      __ F64x2ConvertLowI32x4U(i.OutputSimd128Register(),
                               i.InputSimd128Register(0), i.TempRegister(0));
      break;
    }
    case kIA32I64x2ExtMulLowI32x4S: {
      __ I64x2ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/true, /*is_signed=*/true);
      break;
    }
    case kIA32I64x2ExtMulHighI32x4S: {
      __ I64x2ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/false, /*is_signed=*/true);
      break;
    }
    case kIA32I64x2ExtMulLowI32x4U: {
      __ I64x2ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/true, /*is_signed=*/false);
      break;
    }
    case kIA32I64x2ExtMulHighI32x4U: {
      __ I64x2ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/false, /*is_signed=*/false);
      break;
    }
    case kIA32I32x4ExtMulLowI16x8S: {
      __ I32x4ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/true, /*is_signed=*/true);
      break;
    }
    case kIA32I32x4ExtMulHighI16x8S: {
      __ I32x4ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/false, /*is_signed=*/true);
      break;
    }
    case kIA32I32x4ExtMulLowI16x8U: {
      __ I32x4ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/true, /*is_signed=*/false);
      break;
    }
    case kIA32I32x4ExtMulHighI16x8U: {
      __ I32x4ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/false, /*is_signed=*/false);
      break;
    }
    case kIA32I16x8ExtMulLowI8x16S: {
      __ I16x8ExtMulLow(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), kScratchDoubleReg,
                        /*is_signed=*/true);
      break;
    }
    case kIA32I16x8ExtMulHighI8x16S: {
      __ I16x8ExtMulHighS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kIA32I16x8ExtMulLowI8x16U: {
      __ I16x8ExtMulLow(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), kScratchDoubleReg,
                        /*is_signed=*/false);
      break;
    }
    case kIA32I16x8ExtMulHighI8x16U: {
      __ I16x8ExtMulHighU(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kIA32I64x2SplatI32Pair: {
      XMMRegister dst = i.OutputSimd128Register();
      __ Pinsrd(dst, i.InputRegister(0), 0);
      __ Pinsrd(dst, i.InputOperand(1), 1);
      __ Pshufd(dst, dst, uint8_t{0x44});
      break;
    }
    case kIA32I64x2ReplaceLaneI32Pair: {
      int8_t lane = i.InputInt8(1);
      __ Pinsrd(i.OutputSimd128Register(), i.InputOperand(2), lane * 2);
      __ Pinsrd(i.OutputSimd128Register(), i.InputOperand(3), lane * 2 + 1);
      break;
    }
    case kIA32I64x2Abs: {
      __ I64x2Abs(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  kScratchDoubleReg);
      break;
    }
    case kIA32I64x2Neg: {
      __ I64x2Neg(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  kScratchDoubleReg);
      break;
    }
    case kIA32I64x2Shl: {
      ASSEMBLE_SIMD_SHIFT(Psllq, 6);
      break;
    }
    case kIA32I64x2ShrS: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src = i.InputSimd128Register(0);
      if (HasImmediateInput(instr, 1)) {
        __ I64x2ShrS(dst, src, i.InputInt6(1), kScratchDoubleReg);
      } else {
        __ I64x2ShrS(dst, src, i.InputRegister(1), kScratchDoubleReg,
                     i.TempSimd128Register(0), i.TempRegister(1));
      }
      break;
    }
    case kIA32I64x2Add: {
      __ Paddq(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32I64x2Sub: {
      __ Psubq(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32I64x2Mul: {
      __ I64x2Mul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), i.TempSimd128Register(0),
                  i.TempSimd128Register(1));
      break;
    }
    case kIA32I64x2ShrU: {
      ASSEMBLE_SIMD_SHIFT(Psrlq, 6);
      break;
    }
    case kIA32I64x2BitMask: {
      __ Movmskpd(i.OutputRegister(), i.InputSimd128Register(0));
      break;
    }
    case kIA32I64x2Eq: {
      __ Pcmpeqq(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32I64x2Ne: {
      __ Pcmpeqq(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      __ Pcmpeqq(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      __ Pxor(i.OutputSimd128Register(), kScratchDoubleReg);
      break;
    }
    case kIA32I64x2GtS: {
      __ I64x2GtS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kIA32I64x2GeS: {
      __ I64x2GeS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kIA32I64x2SConvertI32x4Low: {
      __ Pmovsxdq(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kIA32I64x2SConvertI32x4High: {
      __ I64x2SConvertI32x4High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0));
      break;
    }
    case kIA32I64x2UConvertI32x4Low: {
      __ Pmovzxdq(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kIA32I64x2UConvertI32x4High: {
      __ I64x2UConvertI32x4High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0), kScratchDoubleReg);
      break;
    }
    case kIA32I32x4ExtAddPairwiseI16x8S: {
      __ I32x4ExtAddPairwiseI16x8S(i.OutputSimd128Register(),
                                   i.InputSimd128Register(0),
                                   i.TempRegister(0));
      break;
    }
    case kIA32I32x4ExtAddPairwiseI16x8U: {
      __ I32x4ExtAddPairwiseI16x8U(i.OutputSimd128Register(),
                                   i.InputSimd128Register(0),
                                   kScratchDoubleReg);
      break;
    }
    case kIA32I16x8ExtAddPairwiseI8x16S: {
      __ I16x8ExtAddPairwiseI8x16S(i.OutputSimd128Register(),
                                   i.InputSimd128Register(0), kScratchDoubleReg,
                                   i.TempRegister(0));
      break;
    }
    case kIA32I16x8ExtAddPairwiseI8x16U: {
      __ I16x8ExtAddPairwiseI8x16U(i.OutputSimd128Register(),
                                   i.InputSimd128Register(0),
                                   i.TempRegister(0));
      break;
    }
    case kIA32I16x8Q15MulRSatS: {
      __ I16x8Q15MulRSatS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kIA32I16x8RelaxedQ15MulRS: {
      __ Pmulhrsw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kIA32I16x8DotI8x16I7x16S: {
      __ I16x8DotI8x16I7x16S(i.OutputSimd128Register(),
                             i.InputSimd128Register(0),
                             i.InputSimd128Register(1));
      break;
    }
    case kIA32I32x4DotI8x16I7x16AddS: {
      __ I32x4DotI8x16I7x16AddS(
          i.OutputSimd128Register(), i.InputSimd128Register(0),
          i.InputSimd128Register(1), i.InputSimd128Register(2),
          kScratchDoubleReg, i.TempSimd128Register(0));
      break;
    }
    case kIA32F32x4Splat: {
      __ F32x4Splat(i.OutputSimd128Register(), i.InputDoubleRegister(0));
      break;
    }
    case kIA32F32x4ExtractLane: {
      __ F32x4ExtractLane(i.OutputFloatRegister(), i.InputSimd128Register(0),
                          i.InputUint8(1));
      break;
    }
    case kIA32Insertps: {
      if (CpuFeatures::IsSupported(AVX)) {
        CpuFeatureScope avx_scope(masm(), AVX);
        __ vinsertps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputOperand(2), i.InputInt8(1) << 4);
      } else {
        DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
        CpuFeatureScope sse_scope(masm(), SSE4_1);
        __ insertps(i.OutputSimd128Register(), i.InputOperand(2),
                    i.InputInt8(1) << 4);
      }
      break;
    }
    case kIA32F32x4SConvertI32x4: {
      __ Cvtdq2ps(i.OutputSimd128Register(), i.InputOperand(0));
      break;
    }
    case kIA32F32x4UConvertI32x4: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src = i.InputSimd128Register(0);
      __ Pxor(kScratchDoubleReg, kScratchDoubleReg);      // zeros
      __ Pblendw(kScratchDoubleReg, src, uint8_t{0x55});  // get lo 16 bits
      __ Psubd(dst, src, kScratchDoubleReg);              // get hi 16 bits
      __ Cvtdq2ps(kScratchDoubleReg, kScratchDoubleReg);  // convert lo exactly
      __ Psrld(dst, dst, uint8_t{1});  // divide by 2 to get in unsigned range
      __ Cvtdq2ps(dst, dst);    // convert hi exactly
      __ Addps(dst, dst, dst);  // double hi, exactly
      __ Addps(dst, dst, kScratchDoubleReg);  // add hi and lo, may round.
      break;
    }
    case kIA32F32x4Sqrt: {
      __ Sqrtps(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kIA32F32x4Add: {
      __ Addps(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    };
    case kIA32F32x4Sub: {
      __ Subps(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32F32x4Mul: {
      __ Mulps(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32F32x4Div: {
      __ Divps(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32F32x4Min: {
      __ F32x4Min(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kIA32F32x4Max: {
      __ F32x4Max(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kIA32F32x4Eq: {
      __ Cmpeqps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32F32x4Ne: {
      __ Cmpneqps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputOperand(1));
      break;
    }
    case kIA32F32x4Lt: {
      __ Cmpltps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32F32x4Le: {
      __ Cmpleps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32F32x4Qfma: {
      __ F32x4Qfma(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1), i.InputSimd128Register(2),
                   kScratchDoubleReg);
      break;
    }
    case kIA32F32x4Qfms: {
      __ F32x4Qfms(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   i.InputSimd128Register(1), i.InputSimd128Register(2),
                   kScratchDoubleReg);
      break;
    }
    case kIA32Minps: {
      __ Minps(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kIA32Maxps: {
      __ Maxps(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputSimd128Register(1));
      break;
    }
    case kIA32F32x4Round: {
      RoundingMode const mode =
          static_cast<RoundingMode>(MiscField::decode(instr->opcode()));
      __ Roundps(i.OutputSimd128Register(), i.InputDoubleRegister(0), mode);
      break;
    }
    case kIA32I32x4Splat: {
      XMMRegister dst = i.OutputSimd128Register();
      __ Movd(dst, i.InputOperand(0));
      __ Pshufd(dst, dst, uint8_t{0x0});
      break;
    }
    case kIA32I32x4ExtractLane: {
      __ Pextrd(i.OutputRegister(), i.InputSimd128Register(0), i.InputInt8(1));
      break;
    }
    case kIA32I32x4SConvertF32x4: {
      __ I32x4SConvertF32x4(i.OutputSimd128Register(),
                            i.InputSimd128Register(0), kScratchDoubleReg,
                            i.TempRegister(0));
      break;
    }
    case kIA32I32x4SConvertI16x8Low: {
      __ Pmovsxwd(i.OutputSimd128Register(), i.InputOperand(0));
      break;
    }
    case kIA32I32x4SConvertI16x8High: {
      __ I32x4SConvertI16x8High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0));
      break;
    }
    case kIA32I32x4Neg: {
      XMMRegister dst = i.OutputSimd128Register();
      Operand src = i.InputOperand(0);
      if (src.is_reg(dst)) {
        __ Pcmpeqd(kScratchDoubleReg, kScratchDoubleReg);
        __ Psignd(dst, kScratchDoubleReg);
      } else {
        __ Pxor(dst, dst);
        __ Psubd(dst, src);
      }
      break;
    }
    case kIA32I32x4Shl: {
      ASSEMBLE_SIMD_SHIFT(Pslld, 5);
      break;
    }
    case kIA32I32x4ShrS: {
      ASSEMBLE_SIMD_SHIFT(Psrad, 5);
      break;
    }
    case kIA32I32x4Add: {
      __ Paddd(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32I32x4Sub: {
      __ Psubd(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32I32x4Mul: {
      __ Pmulld(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I32x4MinS: {
      __ Pminsd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I32x4MaxS: {
      __ Pmaxsd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I32x4Eq: {
      __ Pcmpeqd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32I32x4Ne: {
      __ Pcmpeqd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      __ Pcmpeqd(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      __ Pxor(i.OutputSimd128Register(), i.OutputSimd128Register(),
              kScratchDoubleReg);
      break;
    }
    case kIA32I32x4GtS: {
      __ Pcmpgtd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32I32x4GeS: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src1 = i.InputSimd128Register(0);
      XMMRegister src2 = i.InputSimd128Register(1);
      if (CpuFeatures::IsSupported(AVX)) {
        CpuFeatureScope avx_scope(masm(), AVX);
        __ vpminsd(kScratchDoubleReg, src1, src2);
        __ vpcmpeqd(dst, kScratchDoubleReg, src2);
      } else {
        DCHECK_EQ(dst, src1);
        CpuFeatureScope sse_scope(masm(), SSE4_1);
        __ pminsd(dst, src2);
        __ pcmpeqd(dst, src2);
      }
      break;
    }
    case kSSEI32x4UConvertF32x4: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      CpuFeatureScope sse_scope(masm(), SSE4_1);
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister tmp = i.TempSimd128Register(0);
      XMMRegister tmp2 = i.TempSimd128Register(1);
      __ I32x4TruncF32x4U(dst, dst, tmp, tmp2);
      break;
    }
    case kAVXI32x4UConvertF32x4: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister tmp = i.TempSimd128Register(0);
      // NAN->0, negative->0
      __ vpxor(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      __ vmaxps(dst, dst, kScratchDoubleReg);
      // scratch: float representation of max_signed
      __ vpcmpeqd(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      __ vpsrld(kScratchDoubleReg, kScratchDoubleReg, 1);  // 0x7fffffff
      __ vcvtdq2ps(kScratchDoubleReg, kScratchDoubleReg);  // 0x4f000000
      // tmp: convert (src-max_signed).
      // Positive overflow lanes -> 0x7FFFFFFF
      // Negative lanes -> 0
      __ vsubps(tmp, dst, kScratchDoubleReg);
      __ vcmpleps(kScratchDoubleReg, kScratchDoubleReg, tmp);
      __ vcvttps2dq(tmp, tmp);
      __ vpxor(tmp, tmp, kScratchDoubleReg);
      __ vpxor(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      __ vpmaxsd(tmp, tmp, kScratchDoubleReg);
      // convert. Overflow lanes above max_signed will be 0x80000000
      __ vcvttps2dq(dst, dst);
      // Add (src-max_signed) for overflow lanes.
      __ vpaddd(dst, dst, tmp);
      break;
    }
    case kIA32I32x4UConvertI16x8Low: {
      __ Pmovzxwd(i.OutputSimd128Register(), i.InputOperand(0));
      break;
    }
    case kIA32I32x4UConvertI16x8High: {
      __ I32x4UConvertI16x8High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0), kScratchDoubleReg);
      break;
    }
    case kIA32I32x4ShrU: {
      ASSEMBLE_SIMD_SHIFT(Psrld, 5);
      break;
    }
    case kIA32I32x4MinU: {
      __ Pminud(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I32x4MaxU: {
      __ Pmaxud(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kSSEI32x4GtU: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      CpuFeatureScope sse_scope(masm(), SSE4_1);
      XMMRegister dst = i.OutputSimd128Register();
      Operand src = i.InputOperand(1);
      __ pmaxud(dst, src);
      __ pcmpeqd(dst, src);
      __ pcmpeqd(kScratchDoubleReg, kScratchDoubleReg);
      __ xorps(dst, kScratchDoubleReg);
      break;
    }
    case kAVXI32x4GtU: {
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src1 = i.InputSimd128Register(0);
      Operand src2 = i.InputOperand(1);
      __ vpmaxud(kScratchDoubleReg, src1, src2);
      __ vpcmpeqd(dst, kScratchDoubleReg, src2);
      __ vpcmpeqd(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      __ vpxor(dst, dst, kScratchDoubleReg);
      break;
    }
    case kSSEI32x4GeU: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      CpuFeatureScope sse_scope(masm(), SSE4_1);
      XMMRegister dst = i.OutputSimd128Register();
      Operand src = i.InputOperand(1);
      __ pminud(dst, src);
      __ pcmpeqd(dst, src);
      break;
    }
    case kAVXI32x4GeU: {
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister src1 = i.InputSimd128Register(0);
      Operand src2 = i.InputOperand(1);
      __ vpminud(kScratchDoubleReg, src1, src2);
      __ vpcmpeqd(i.OutputSimd128Register(), kScratchDoubleReg, src2);
      break;
    }
    case kIA32I32x4Abs: {
      __ Pabsd(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kIA32I32x4BitMask: {
      __ Movmskps(i.OutputRegister(), i.InputSimd128Register(0));
      break;
    }
    case kIA32I32x4DotI16x8S: {
      __ Pmaddwd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32I16x8Splat: {
      if (instr->InputAt(0)->IsRegister()) {
        __ I16x8Splat(i.OutputSimd128Register(), i.InputRegister(0));
      } else {
        __ I16x8Splat(i.OutputSimd128Register(), i.InputOperand(0));
      }
      break;
    }
    case kIA32I16x8ExtractLaneS: {
      Register dst = i.OutputRegister();
      __ Pextrw(dst, i.InputSimd128Register(0), i.InputUint8(1));
      __ movsx_w(dst, dst);
      break;
    }
    case kIA32I16x8SConvertI8x16Low: {
      __ Pmovsxbw(i.OutputSimd128Register(), i.InputOperand(0));
      break;
    }
    case kIA32I16x8SConvertI8x16High: {
      __ I16x8SConvertI8x16High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0));
      break;
    }
    case kIA32I16x8Neg: {
      XMMRegister dst = i.OutputSimd128Register();
      Operand src = i.InputOperand(0);
      if (src.is_reg(dst)) {
        __ Pcmpeqd(kScratchDoubleReg, kScratchDoubleReg);
        __ Psignw(dst, kScratchDoubleReg);
      } else {
        __ Pxor(dst, dst);
        __ Psubw(dst, src);
      }
      break;
    }
    case kIA32I16x8Shl: {
      ASSEMBLE_SIMD_SHIFT(Psllw, 4);
      break;
    }
    case kIA32I16x8ShrS: {
      ASSEMBLE_SIMD_SHIFT(Psraw, 4);
      break;
    }
    case kIA32I16x8SConvertI32x4: {
      __ Packssdw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputOperand(1));
      break;
    }
    case kIA32I16x8Add: {
      __ Paddw(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32I16x8AddSatS: {
      __ Paddsw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I16x8Sub: {
      __ Psubw(i.OutputSimd128Register(), i.InputSimd128Register(0),
               i.InputOperand(1));
      break;
    }
    case kIA32I16x8SubSatS: {
      __ Psubsw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I16x8Mul: {
      __ Pmullw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I16x8MinS: {
      __ Pminsw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I16x8MaxS: {
      __ Pmaxsw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I16x8Eq: {
      __ Pcmpeqw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kSSEI16x8Ne: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      __ pcmpeqw(i.OutputSimd128Register(), i.InputOperand(1));
      __ pcmpeqw(kScratchDoubleReg, kScratchDoubleReg);
      __ xorps(i.OutputSimd128Register(), kScratchDoubleReg);
      break;
    }
    case kAVXI16x8Ne: {
      CpuFeatureScope avx_scope(masm(), AVX);
      __ vpcmpeqw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputOperand(1));
      __ vpcmpeqw(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      __ vpxor(i.OutputSimd128Register(), i.OutputSimd128Register(),
               kScratchDoubleReg);
      break;
    }
    case kIA32I16x8GtS: {
      __ Pcmpgtw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kSSEI16x8GeS: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      XMMRegister dst = i.OutputSimd128Register();
      Operand src = i.InputOperand(1);
      __ pminsw(dst, src);
      __ pcmpeqw(dst, src);
      break;
    }
    case kAVXI16x8GeS: {
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister src1 = i.InputSimd128Register(0);
      Operand src2 = i.InputOperand(1);
      __ vpminsw(kScratchDoubleReg, src1, src2);
      __ vpcmpeqw(i.OutputSimd128Register(), kScratchDoubleReg, src2);
      break;
    }
    case kIA32I16x8UConvertI8x16Low: {
      __ Pmovzxbw(i.OutputSimd128Register(), i.InputOperand(0));
      break;
    }
    case kIA32I16x8UConvertI8x16High: {
      __ I16x8UConvertI8x16High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0), kScratchDoubleReg);
      break;
    }
    case kIA32I16x8ShrU: {
      ASSEMBLE_SIMD_SHIFT(Psrlw, 4);
      break;
    }
    case kIA32I16x8UConvertI32x4: {
      __ Packusdw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kIA32I16x8AddSatU: {
      __ Paddusw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32I16x8SubSatU: {
      __ Psubusw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputOperand(1));
      break;
    }
    case kIA32I16x8MinU: {
      __ Pminuw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kIA32I16x8MaxU: {
      __ Pmaxuw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                i.InputOperand(1));
      break;
    }
    case kSSEI16x8GtU: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      CpuFeatureScope sse_scope(masm(), SSE4_1);
      XMMRegister dst = i.OutputSimd128Register();
      Operand src = i.InputOperand(1);
      __ pmaxuw(dst, src);
      __ pcmpeqw(dst, src);
      __ pcmpeqw(kScratchDoubleReg, kScratchDoubleReg);
      __ xorps(dst, kScratchDoubleReg);
      break;
    }
    case kAVXI16x8GtU: {
      CpuFeatureScope avx_scope(masm(), AVX);
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src1 = i.InputSimd128Register(0);
      Operand src2 = i.InputOperand(1);
      __ vpmaxuw(kScratchDoubleReg, src1, src2);
      __ vpcmpeqw(dst, kScratchDoubleReg, src2);
      __ vpcmpeqw(kScratchDoubleReg, kScratchDoubleReg, kScratchDoubleReg);
      __ vpxor(dst, dst, kScratchDoubleReg);
      break;
    }
    case kSSEI16x8GeU: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      CpuFeatureScope sse_scope(m
```