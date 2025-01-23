Response:
Let's break down the thought process for answering the request about `instruction-selector.cc`.

**1. Understanding the Core Request:**

The fundamental goal is to explain the functionality of the `instruction-selector.cc` file in the V8 JavaScript engine, based on the provided code snippet and some guiding questions.

**2. Initial Analysis of the Code Snippet:**

The snippet consists of a large `switch` statement. The `case` labels within the `switch` are `IrOpcode::k...`, indicating that this code is processing intermediate representation (IR) opcodes. Each case calls a `Visit...` function. Crucially, most of the cases related to `I...`, `F...`, and `S...` followed by numbers like `128`, `256`, and operation names like `Add`, `Sub`, `Mul`, `Min`, `Max`, etc. This strongly suggests the code is dealing with Single Instruction, Multiple Data (SIMD) operations.

**3. Connecting to V8 and Compilation:**

Knowing this is V8 source code, and the file is in `src/compiler/backend/`,  it's reasonable to infer this file is part of the code generation process. The compiler takes the high-level JavaScript code, converts it to an intermediate representation (IR), and then needs to translate that IR into machine-specific instructions. The "instruction selector" part of the filename is a strong clue about its purpose.

**4. Formulating the Main Functionality:**

Based on the `switch` statement and the file's location, the primary function is to take IR nodes (representing operations) and select the appropriate machine instructions to perform those operations. This involves understanding the IR opcode and potentially the target architecture.

**5. Addressing the ".tq" Question:**

The request specifically asks about the `.tq` extension. Knowing that Torque is V8's internal language for defining built-in functions and some compiler phases, we can confidently say that if the file ended in `.tq`, it would be a Torque file. Since it ends in `.cc`, it's C++.

**6. Connecting to JavaScript and Providing Examples:**

The core functionality revolves around SIMD operations. Modern JavaScript has a WebAssembly (Wasm) integration, and Wasm supports SIMD. Therefore, the operations seen in the code likely map to Wasm SIMD instructions. A simple JavaScript/Wasm example demonstrating a SIMD addition is the most effective way to illustrate the connection. Choosing `Int32x4` is a good starting point as it's a commonly understood SIMD type.

**7. Addressing Code Logic and Hypothetical Input/Output:**

The code doesn't directly implement complex logic *within this snippet*. It's a dispatch mechanism. The *real* logic is inside the `Visit...` functions. Therefore, the "code logic" here is the mapping from IR opcode to the corresponding `Visit` call. A hypothetical input would be an IR node with a specific opcode (e.g., `IrOpcode::kI32x4Add`), and the output would be a call to the corresponding `VisitI32x4Add` function.

**8. Identifying Common Programming Errors:**

Since this code deals with low-level optimizations and instruction selection, common *user* programming errors are less directly relevant. However, if we think about the *intent* of these SIMD operations (performance), a common mistake would be using scalar operations when SIMD would be much faster. Another error could be incorrect data type handling when working with SIMD.

**9. Considering the "Part 6 of 8" Information:**

This suggests there are other parts to the compilation process. Instruction selection is a crucial *middle* stage. Before this, there's likely IR generation and optimization. After this, there will be instruction scheduling, register allocation, and final code emission.

**10. Synthesizing the Summary:**

The summary should concisely reiterate the main function: instruction selection for specific operations (primarily SIMD), as part of the backend compilation pipeline. Mentioning the translation from IR to machine code is key.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file handles all instructions. **Correction:** The code snippet heavily emphasizes SIMD, so it's likely a specialized part of the instruction selection process.
* **Initial thought:**  Provide very low-level assembly examples. **Correction:**  A higher-level JavaScript/Wasm example is more accessible and directly answers the "relationship to JavaScript" question.
* **Initial thought:**  Focus on potential errors in the V8 compiler itself. **Correction:**  The request asked about *user* errors, so relating it to suboptimal use of JavaScript/Wasm features is more appropriate.

By following this structured approach, analyzing the provided code, and addressing each point in the request systematically, we arrive at the comprehensive and accurate answer.
好的，让我们根据您提供的代码片段来分析 `v8/src/compiler/backend/instruction-selector.cc` 的功能。

**1. 功能列举:**

从提供的代码片段来看，`instruction-selector.cc` 的主要功能是：

* **指令选择 (Instruction Selection):** 这是一个编译器后端的重要组成部分，其核心任务是将中间表示 (Intermediate Representation, IR) 的操作 (nodes) 转换为目标架构 (例如 x64) 的具体机器指令。
* **处理 SIMD (单指令多数据) 操作:**  代码片段中大量的 `IrOpcode::kI...`, `IrOpcode::kF...`, `IrOpcode::kS...` 前缀的操作，以及 `Simd128`, `Simd256` 的标记，都表明这个文件专注于处理 SIMD 指令。这些指令允许一次执行多个数据元素的相同操作，从而提高性能。
* **映射 IR 操作到具体的 Visit 函数:**  对于每一种 IR 操作码 (例如 `kI32x4Add` 表示 4 个 32 位整数的 SIMD 加法)，都有一个对应的 `Visit...` 函数 (例如 `VisitI32x4Add`) 来处理，并选择合适的机器指令。
* **区分数据类型:**  代码根据不同的数据类型 (例如 i8, i16, i32, f32, f64) 和 SIMD 向量的宽度 (128 位或 256 位) 来进行指令选择。
* **处理不同的 SIMD 操作类型:**  支持各种 SIMD 操作，包括算术运算 (加、减、乘、除)、比较运算 (等于、不等于、大于、小于)、位运算 (与、或、异或)、类型转换、数据提取和替换、以及一些特殊的 SIMD 操作 (如点积、饱和运算、平均值)。
* **标记操作的输出类型:**  `MarkAsSimd128(node)`, `MarkAsWord32(node)`, `MarkAsFloat32(node)`, `MarkAsSimd256(node)` 等函数用于标记当前 IR 节点的输出结果类型，这有助于后续的指令选择和优化。
* **支持 WebAssembly SIMD:**  代码中涉及到许多 WebAssembly SIMD 指令 (例如 `relaxedMin`, `relaxedMax`, `qfma`, `qfms`)，表明该文件也负责处理 WebAssembly 中的 SIMD 操作。
* **支持 SIMD256 (AVX-512):**  在 `#if defined(V8_TARGET_ARCH_X64) && defined(V8_ENABLE_WASM_SIMD256_REVEC)` 条件下的代码表明，该文件还支持 256 位的 SIMD 指令集 (通常与 AVX-512 相关)。
* **处理 Turboshaft IR (可能):**  代码片段中也包含一个 `InstructionSelectorT<TurboshaftAdapter>::VisitNode` 的模板特化，这可能表明该文件也能够处理 V8 新的编译器管道 Turboshaft 生成的 IR。

**2. 关于 .tq 结尾:**

您是对的，如果 `v8/src/compiler/backend/instruction-selector.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。Torque 是 V8 内部使用的一种领域特定语言，用于更安全、更易于维护地编写 V8 的内置函数和一些编译器代码。然而，根据您提供的文件名，它是 `.cc` 结尾，因此是标准的 **C++ 源代码**文件。

**3. 与 JavaScript 的关系及示例:**

`instruction-selector.cc` 的功能直接关系到 JavaScript 的性能，尤其是在处理需要大量并行计算的任务时。JavaScript 通过 WebAssembly 的 SIMD 支持，可以利用这些底层的 SIMD 指令。

**JavaScript 示例 (使用 WebAssembly):**

```javascript
// 假设我们有一个 WebAssembly 模块，其中定义了一个 SIMD 加法函数
const wasmCode = `
  (module
    (type $t0 (func (param i32 i32 i32 i32) (result i32 i32 i32 i32)))
    (func $add_i32x4 (export "add_i32x4") (param $p0 i32 $p1 i32) (result v128)
      local.get $p0
      local.get $p1
      i32x4.add
    )
    (memory $memory 1)
    (export "memory" (memory $memory))
  )
`;

const wasmBytes = new Uint8Array(Buffer.from(wasmCode, "utf8")).buffer;

WebAssembly.instantiate(wasmBytes).then(wasmModule => {
  const { add_i32x4, memory } = wasmModule.instance.exports;
  const i32Array = new Int32Array(memory.buffer);

  // 初始化两个 i32x4 向量的数据
  i32Array[0] = 1;
  i32Array[1] = 2;
  i32Array[2] = 3;
  i32Array[3] = 4;

  i32Array[4] = 5;
  i32Array[5] = 6;
  i32Array[6] = 7;
  i32Array[7] = 8;

  // 调用 WebAssembly 函数进行 SIMD 加法
  const resultVectorPtr = add_i32x4(0, 4); // 假设结果存储在内存的某个位置

  // (在实际的 WebAssembly 代码中，你需要知道如何访问结果向量)
  // 这里仅为示意，假设结果向量覆盖了第二个输入向量的位置
  console.log(i32Array.slice(4, 8)); // 输出类似 [6, 8, 10, 12] 的结果
});
```

在这个例子中，当 JavaScript 调用 WebAssembly 的 `add_i32x4` 函数时，V8 的 `instruction-selector.cc` 会将 WebAssembly 的 `i32x4.add` 操作映射到目标架构上高效的 SIMD 加法指令。

**4. 代码逻辑推理 (假设输入与输出):**

**假设输入:** 一个 IR 节点，其操作码为 `IrOpcode::kI16x8Mul`，表示对两个包含 8 个 16 位整数的 SIMD 向量进行乘法运算。

**假设输出:**  `instruction-selector.cc` (更具体地说是 `VisitI16x8Mul` 函数) 会选择合适的机器指令来执行这个操作。在 x64 架构上，这可能会被映射到 `pmullw` (Packed Multiply Low Words) 指令。同时，`MarkAsSimd128(node)` 会将该节点的输出标记为 128 位的 SIMD 类型。

**5. 涉及用户常见的编程错误:**

虽然 `instruction-selector.cc` 是 V8 内部的实现，但它所处理的 SIMD 操作与用户编写的 JavaScript 代码密切相关。用户在使用 WebAssembly SIMD 时，可能会犯以下错误：

* **数据类型不匹配:**  例如，尝试将浮点数 SIMD 向量与整数 SIMD 向量进行操作，而没有进行显式的类型转换。

  ```javascript
  // 假设在 WebAssembly 中定义了 i32x4 和 f32x4 类型的变量
  // 错误示例：尝试直接相加不同类型的 SIMD 向量
  // i32x4.add(f32x4_variable); // 这会导致类型错误
  ```

* **向量长度不匹配:**  尝试对不同长度的 SIMD 向量进行操作，这通常是不允许的。

  ```javascript
  // 假设在 WebAssembly 中定义了 i32x4 和 i32x2 类型的变量
  // 错误示例：尝试将不同长度的 SIMD 向量相加
  // i32x4.add(i32x2_variable); // 这通常是不允许的
  ```

* **未充分利用 SIMD 的并行性:**  在可以进行 SIMD 操作的场景下，仍然使用标量操作，导致性能下降。

  ```javascript
  // 低效的 JavaScript 代码示例 (可以被 SIMD 优化)
  const arr1 = [1, 2, 3, 4];
  const arr2 = [5, 6, 7, 8];
  const result = [];
  for (let i = 0; i < arr1.length; i++) {
    result.push(arr1[i] + arr2[i]);
  }

  // 更高效的方式是使用 WebAssembly SIMD
  ```

* **对齐问题 (在某些底层场景):**  虽然 JavaScript 抽象了内存管理，但在一些更底层的 WebAssembly SIMD 操作中，数据的内存对齐可能会影响性能，甚至导致错误。

**6. 功能归纳 (第 6 部分，共 8 部分):**

作为编译过程的第 6 部分 (假设总共 8 个主要阶段)，`v8/src/compiler/backend/instruction-selector.cc` 的主要功能是 **将编译器后端生成的中间表示 (特别是 SIMD 相关的操作) 转换为目标机器架构的具体指令**。它是连接高层抽象的 IR 和底层硬件指令的关键桥梁，专注于为 SIMD 操作选择最优的机器指令，以提高 JavaScript (特别是通过 WebAssembly) 的执行性能。在这个阶段，编译器已经进行了类型分析、优化等前期工作，现在需要将逻辑操作映射到实际的硬件指令序列。后续的阶段可能会包括指令调度、寄存器分配和最终的代码生成。

### 提示词
```
这是目录为v8/src/compiler/backend/instruction-selector.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/instruction-selector.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
MarkAsSimd128(node), VisitI16x8SubSatS(node);
    case IrOpcode::kI16x8Mul:
      return MarkAsSimd128(node), VisitI16x8Mul(node);
    case IrOpcode::kI16x8MinS:
      return MarkAsSimd128(node), VisitI16x8MinS(node);
    case IrOpcode::kI16x8MaxS:
      return MarkAsSimd128(node), VisitI16x8MaxS(node);
    case IrOpcode::kI16x8Eq:
      return MarkAsSimd128(node), VisitI16x8Eq(node);
    case IrOpcode::kI16x8Ne:
      return MarkAsSimd128(node), VisitI16x8Ne(node);
    case IrOpcode::kI16x8GtS:
      return MarkAsSimd128(node), VisitI16x8GtS(node);
    case IrOpcode::kI16x8GeS:
      return MarkAsSimd128(node), VisitI16x8GeS(node);
    case IrOpcode::kI16x8UConvertI8x16Low:
      return MarkAsSimd128(node), VisitI16x8UConvertI8x16Low(node);
    case IrOpcode::kI16x8UConvertI8x16High:
      return MarkAsSimd128(node), VisitI16x8UConvertI8x16High(node);
    case IrOpcode::kI16x8ShrU:
      return MarkAsSimd128(node), VisitI16x8ShrU(node);
    case IrOpcode::kI16x8UConvertI32x4:
      return MarkAsSimd128(node), VisitI16x8UConvertI32x4(node);
    case IrOpcode::kI16x8AddSatU:
      return MarkAsSimd128(node), VisitI16x8AddSatU(node);
    case IrOpcode::kI16x8SubSatU:
      return MarkAsSimd128(node), VisitI16x8SubSatU(node);
    case IrOpcode::kI16x8MinU:
      return MarkAsSimd128(node), VisitI16x8MinU(node);
    case IrOpcode::kI16x8MaxU:
      return MarkAsSimd128(node), VisitI16x8MaxU(node);
    case IrOpcode::kI16x8GtU:
      return MarkAsSimd128(node), VisitI16x8GtU(node);
    case IrOpcode::kI16x8GeU:
      return MarkAsSimd128(node), VisitI16x8GeU(node);
    case IrOpcode::kI16x8RoundingAverageU:
      return MarkAsSimd128(node), VisitI16x8RoundingAverageU(node);
    case IrOpcode::kI16x8Q15MulRSatS:
      return MarkAsSimd128(node), VisitI16x8Q15MulRSatS(node);
    case IrOpcode::kI16x8Abs:
      return MarkAsSimd128(node), VisitI16x8Abs(node);
    case IrOpcode::kI16x8BitMask:
      return MarkAsWord32(node), VisitI16x8BitMask(node);
    case IrOpcode::kI16x8ExtMulLowI8x16S:
      return MarkAsSimd128(node), VisitI16x8ExtMulLowI8x16S(node);
    case IrOpcode::kI16x8ExtMulHighI8x16S:
      return MarkAsSimd128(node), VisitI16x8ExtMulHighI8x16S(node);
    case IrOpcode::kI16x8ExtMulLowI8x16U:
      return MarkAsSimd128(node), VisitI16x8ExtMulLowI8x16U(node);
    case IrOpcode::kI16x8ExtMulHighI8x16U:
      return MarkAsSimd128(node), VisitI16x8ExtMulHighI8x16U(node);
    case IrOpcode::kI16x8ExtAddPairwiseI8x16S:
      return MarkAsSimd128(node), VisitI16x8ExtAddPairwiseI8x16S(node);
    case IrOpcode::kI16x8ExtAddPairwiseI8x16U:
      return MarkAsSimd128(node), VisitI16x8ExtAddPairwiseI8x16U(node);
    case IrOpcode::kI8x16Splat:
      return MarkAsSimd128(node), VisitI8x16Splat(node);
    case IrOpcode::kI8x16ExtractLaneU:
      return MarkAsWord32(node), VisitI8x16ExtractLaneU(node);
    case IrOpcode::kI8x16ExtractLaneS:
      return MarkAsWord32(node), VisitI8x16ExtractLaneS(node);
    case IrOpcode::kI8x16ReplaceLane:
      return MarkAsSimd128(node), VisitI8x16ReplaceLane(node);
    case IrOpcode::kI8x16Neg:
      return MarkAsSimd128(node), VisitI8x16Neg(node);
    case IrOpcode::kI8x16Shl:
      return MarkAsSimd128(node), VisitI8x16Shl(node);
    case IrOpcode::kI8x16ShrS:
      return MarkAsSimd128(node), VisitI8x16ShrS(node);
    case IrOpcode::kI8x16SConvertI16x8:
      return MarkAsSimd128(node), VisitI8x16SConvertI16x8(node);
    case IrOpcode::kI8x16Add:
      return MarkAsSimd128(node), VisitI8x16Add(node);
    case IrOpcode::kI8x16AddSatS:
      return MarkAsSimd128(node), VisitI8x16AddSatS(node);
    case IrOpcode::kI8x16Sub:
      return MarkAsSimd128(node), VisitI8x16Sub(node);
    case IrOpcode::kI8x16SubSatS:
      return MarkAsSimd128(node), VisitI8x16SubSatS(node);
    case IrOpcode::kI8x16MinS:
      return MarkAsSimd128(node), VisitI8x16MinS(node);
    case IrOpcode::kI8x16MaxS:
      return MarkAsSimd128(node), VisitI8x16MaxS(node);
    case IrOpcode::kI8x16Eq:
      return MarkAsSimd128(node), VisitI8x16Eq(node);
    case IrOpcode::kI8x16Ne:
      return MarkAsSimd128(node), VisitI8x16Ne(node);
    case IrOpcode::kI8x16GtS:
      return MarkAsSimd128(node), VisitI8x16GtS(node);
    case IrOpcode::kI8x16GeS:
      return MarkAsSimd128(node), VisitI8x16GeS(node);
    case IrOpcode::kI8x16ShrU:
      return MarkAsSimd128(node), VisitI8x16ShrU(node);
    case IrOpcode::kI8x16UConvertI16x8:
      return MarkAsSimd128(node), VisitI8x16UConvertI16x8(node);
    case IrOpcode::kI8x16AddSatU:
      return MarkAsSimd128(node), VisitI8x16AddSatU(node);
    case IrOpcode::kI8x16SubSatU:
      return MarkAsSimd128(node), VisitI8x16SubSatU(node);
    case IrOpcode::kI8x16MinU:
      return MarkAsSimd128(node), VisitI8x16MinU(node);
    case IrOpcode::kI8x16MaxU:
      return MarkAsSimd128(node), VisitI8x16MaxU(node);
    case IrOpcode::kI8x16GtU:
      return MarkAsSimd128(node), VisitI8x16GtU(node);
    case IrOpcode::kI8x16GeU:
      return MarkAsSimd128(node), VisitI8x16GeU(node);
    case IrOpcode::kI8x16RoundingAverageU:
      return MarkAsSimd128(node), VisitI8x16RoundingAverageU(node);
    case IrOpcode::kI8x16Popcnt:
      return MarkAsSimd128(node), VisitI8x16Popcnt(node);
    case IrOpcode::kI8x16Abs:
      return MarkAsSimd128(node), VisitI8x16Abs(node);
    case IrOpcode::kI8x16BitMask:
      return MarkAsWord32(node), VisitI8x16BitMask(node);
    case IrOpcode::kS128Const:
      return MarkAsSimd128(node), VisitS128Const(node);
    case IrOpcode::kS128Zero:
      return MarkAsSimd128(node), VisitS128Zero(node);
    case IrOpcode::kS128And:
      return MarkAsSimd128(node), VisitS128And(node);
    case IrOpcode::kS128Or:
      return MarkAsSimd128(node), VisitS128Or(node);
    case IrOpcode::kS128Xor:
      return MarkAsSimd128(node), VisitS128Xor(node);
    case IrOpcode::kS128Not:
      return MarkAsSimd128(node), VisitS128Not(node);
    case IrOpcode::kS128Select:
      return MarkAsSimd128(node), VisitS128Select(node);
    case IrOpcode::kS128AndNot:
      return MarkAsSimd128(node), VisitS128AndNot(node);
    case IrOpcode::kI8x16Swizzle:
      return MarkAsSimd128(node), VisitI8x16Swizzle(node);
    case IrOpcode::kI8x16Shuffle:
      return MarkAsSimd128(node), VisitI8x16Shuffle(node);
    case IrOpcode::kV128AnyTrue:
      return MarkAsWord32(node), VisitV128AnyTrue(node);
    case IrOpcode::kI64x2AllTrue:
      return MarkAsWord32(node), VisitI64x2AllTrue(node);
    case IrOpcode::kI32x4AllTrue:
      return MarkAsWord32(node), VisitI32x4AllTrue(node);
    case IrOpcode::kI16x8AllTrue:
      return MarkAsWord32(node), VisitI16x8AllTrue(node);
    case IrOpcode::kI8x16AllTrue:
      return MarkAsWord32(node), VisitI8x16AllTrue(node);
    case IrOpcode::kI8x16RelaxedLaneSelect:
      return MarkAsSimd128(node), VisitI8x16RelaxedLaneSelect(node);
    case IrOpcode::kI16x8RelaxedLaneSelect:
      return MarkAsSimd128(node), VisitI16x8RelaxedLaneSelect(node);
    case IrOpcode::kI32x4RelaxedLaneSelect:
      return MarkAsSimd128(node), VisitI32x4RelaxedLaneSelect(node);
    case IrOpcode::kI64x2RelaxedLaneSelect:
      return MarkAsSimd128(node), VisitI64x2RelaxedLaneSelect(node);
    case IrOpcode::kF32x4RelaxedMin:
      return MarkAsSimd128(node), VisitF32x4RelaxedMin(node);
    case IrOpcode::kF32x4RelaxedMax:
      return MarkAsSimd128(node), VisitF32x4RelaxedMax(node);
    case IrOpcode::kF64x2RelaxedMin:
      return MarkAsSimd128(node), VisitF64x2RelaxedMin(node);
    case IrOpcode::kF64x2RelaxedMax:
      return MarkAsSimd128(node), VisitF64x2RelaxedMax(node);
    case IrOpcode::kI32x4RelaxedTruncF64x2SZero:
      return MarkAsSimd128(node), VisitI32x4RelaxedTruncF64x2SZero(node);
    case IrOpcode::kI32x4RelaxedTruncF64x2UZero:
      return MarkAsSimd128(node), VisitI32x4RelaxedTruncF64x2UZero(node);
    case IrOpcode::kI32x4RelaxedTruncF32x4S:
      return MarkAsSimd128(node), VisitI32x4RelaxedTruncF32x4S(node);
    case IrOpcode::kI32x4RelaxedTruncF32x4U:
      return MarkAsSimd128(node), VisitI32x4RelaxedTruncF32x4U(node);
    case IrOpcode::kI16x8RelaxedQ15MulRS:
      return MarkAsSimd128(node), VisitI16x8RelaxedQ15MulRS(node);
    case IrOpcode::kI16x8DotI8x16I7x16S:
      return MarkAsSimd128(node), VisitI16x8DotI8x16I7x16S(node);
    case IrOpcode::kI32x4DotI8x16I7x16AddS:
      return MarkAsSimd128(node), VisitI32x4DotI8x16I7x16AddS(node);
    case IrOpcode::kF16x8Splat:
      return MarkAsSimd128(node), VisitF16x8Splat(node);
    case IrOpcode::kF16x8ExtractLane:
      return MarkAsFloat32(node), VisitF16x8ExtractLane(node);
    case IrOpcode::kF16x8ReplaceLane:
      return MarkAsSimd128(node), VisitF16x8ReplaceLane(node);
    case IrOpcode::kF16x8Abs:
      return MarkAsSimd128(node), VisitF16x8Abs(node);
    case IrOpcode::kF16x8Neg:
      return MarkAsSimd128(node), VisitF16x8Neg(node);
    case IrOpcode::kF16x8Sqrt:
      return MarkAsSimd128(node), VisitF16x8Sqrt(node);
    case IrOpcode::kF16x8Ceil:
      return MarkAsSimd128(node), VisitF16x8Ceil(node);
    case IrOpcode::kF16x8Floor:
      return MarkAsSimd128(node), VisitF16x8Floor(node);
    case IrOpcode::kF16x8Trunc:
      return MarkAsSimd128(node), VisitF16x8Trunc(node);
    case IrOpcode::kF16x8NearestInt:
      return MarkAsSimd128(node), VisitF16x8NearestInt(node);
    case IrOpcode::kF16x8Add:
      return MarkAsSimd128(node), VisitF16x8Add(node);
    case IrOpcode::kF16x8Sub:
      return MarkAsSimd128(node), VisitF16x8Sub(node);
    case IrOpcode::kF16x8Mul:
      return MarkAsSimd128(node), VisitF16x8Mul(node);
    case IrOpcode::kF16x8Div:
      return MarkAsSimd128(node), VisitF16x8Div(node);
    case IrOpcode::kF16x8Min:
      return MarkAsSimd128(node), VisitF16x8Min(node);
    case IrOpcode::kF16x8Max:
      return MarkAsSimd128(node), VisitF16x8Max(node);
    case IrOpcode::kF16x8Pmin:
      return MarkAsSimd128(node), VisitF16x8Pmin(node);
    case IrOpcode::kF16x8Pmax:
      return MarkAsSimd128(node), VisitF16x8Pmax(node);
    case IrOpcode::kF16x8Eq:
      return MarkAsSimd128(node), VisitF16x8Eq(node);
    case IrOpcode::kF16x8Ne:
      return MarkAsSimd128(node), VisitF16x8Ne(node);
    case IrOpcode::kF16x8Lt:
      return MarkAsSimd128(node), VisitF16x8Lt(node);
    case IrOpcode::kF16x8Le:
      return MarkAsSimd128(node), VisitF16x8Le(node);
    case IrOpcode::kF16x8SConvertI16x8:
      return MarkAsSimd128(node), VisitF16x8SConvertI16x8(node);
    case IrOpcode::kF16x8UConvertI16x8:
      return MarkAsSimd128(node), VisitF16x8UConvertI16x8(node);
    case IrOpcode::kI16x8UConvertF16x8:
      return MarkAsSimd128(node), VisitI16x8UConvertF16x8(node);
    case IrOpcode::kI16x8SConvertF16x8:
      return MarkAsSimd128(node), VisitI16x8SConvertF16x8(node);
    case IrOpcode::kF16x8DemoteF32x4Zero:
      return MarkAsSimd128(node), VisitF16x8DemoteF32x4Zero(node);
    case IrOpcode::kF16x8DemoteF64x2Zero:
      return MarkAsSimd128(node), VisitF16x8DemoteF64x2Zero(node);
    case IrOpcode::kF32x4PromoteLowF16x8:
      return MarkAsSimd128(node), VisitF32x4PromoteLowF16x8(node);
    case IrOpcode::kF16x8Qfma:
      return MarkAsSimd128(node), VisitF16x8Qfma(node);
    case IrOpcode::kF16x8Qfms:
      return MarkAsSimd128(node), VisitF16x8Qfms(node);

      // SIMD256
#if defined(V8_TARGET_ARCH_X64) && defined(V8_ENABLE_WASM_SIMD256_REVEC)
    case IrOpcode::kF64x4Min:
      return MarkAsSimd256(node), VisitF64x4Min(node);
    case IrOpcode::kF64x4Max:
      return MarkAsSimd256(node), VisitF64x4Max(node);
    case IrOpcode::kF64x4Add:
      return MarkAsSimd256(node), VisitF64x4Add(node);
    case IrOpcode::kF32x8Add:
      return MarkAsSimd256(node), VisitF32x8Add(node);
    case IrOpcode::kI64x4Add:
      return MarkAsSimd256(node), VisitI64x4Add(node);
    case IrOpcode::kI32x8Add:
      return MarkAsSimd256(node), VisitI32x8Add(node);
    case IrOpcode::kI16x16Add:
      return MarkAsSimd256(node), VisitI16x16Add(node);
    case IrOpcode::kI8x32Add:
      return MarkAsSimd256(node), VisitI8x32Add(node);
    case IrOpcode::kF64x4Sub:
      return MarkAsSimd256(node), VisitF64x4Sub(node);
    case IrOpcode::kF32x8Sub:
      return MarkAsSimd256(node), VisitF32x8Sub(node);
    case IrOpcode::kF32x8Min:
      return MarkAsSimd256(node), VisitF32x8Min(node);
    case IrOpcode::kF32x8Max:
      return MarkAsSimd256(node), VisitF32x8Max(node);
    case IrOpcode::kI64x4Ne:
      return MarkAsSimd256(node), VisitI64x4Ne(node);
    case IrOpcode::kI64x4GeS:
      return MarkAsSimd256(node), VisitI64x4GeS(node);
    case IrOpcode::kI32x8Ne:
      return MarkAsSimd256(node), VisitI32x8Ne(node);
    case IrOpcode::kI32x8GtU:
      return MarkAsSimd256(node), VisitI32x8GtU(node);
    case IrOpcode::kI32x8GeS:
      return MarkAsSimd256(node), VisitI32x8GeS(node);
    case IrOpcode::kI32x8GeU:
      return MarkAsSimd256(node), VisitI32x8GeU(node);
    case IrOpcode::kI16x16Ne:
      return MarkAsSimd256(node), VisitI16x16Ne(node);
    case IrOpcode::kI16x16GtU:
      return MarkAsSimd256(node), VisitI16x16GtU(node);
    case IrOpcode::kI16x16GeS:
      return MarkAsSimd256(node), VisitI16x16GeS(node);
    case IrOpcode::kI16x16GeU:
      return MarkAsSimd256(node), VisitI16x16GeU(node);
    case IrOpcode::kI8x32Ne:
      return MarkAsSimd256(node), VisitI8x32Ne(node);
    case IrOpcode::kI8x32GtU:
      return MarkAsSimd256(node), VisitI8x32GtU(node);
    case IrOpcode::kI8x32GeS:
      return MarkAsSimd256(node), VisitI8x32GeS(node);
    case IrOpcode::kI8x32GeU:
      return MarkAsSimd256(node), VisitI8x32GeU(node);
    case IrOpcode::kI64x4Sub:
      return MarkAsSimd256(node), VisitI64x4Sub(node);
    case IrOpcode::kI32x8Sub:
      return MarkAsSimd256(node), VisitI32x8Sub(node);
    case IrOpcode::kI16x16Sub:
      return MarkAsSimd256(node), VisitI16x16Sub(node);
    case IrOpcode::kI8x32Sub:
      return MarkAsSimd256(node), VisitI8x32Sub(node);
    case IrOpcode::kF64x4Mul:
      return MarkAsSimd256(node), VisitF64x4Mul(node);
    case IrOpcode::kF32x8Mul:
      return MarkAsSimd256(node), VisitF32x8Mul(node);
    case IrOpcode::kI64x4Mul:
      return MarkAsSimd256(node), VisitI64x4Mul(node);
    case IrOpcode::kI32x8Mul:
      return MarkAsSimd256(node), VisitI32x8Mul(node);
    case IrOpcode::kI16x16Mul:
      return MarkAsSimd256(node), VisitI16x16Mul(node);
    case IrOpcode::kF32x8Div:
      return MarkAsSimd256(node), VisitF32x8Div(node);
    case IrOpcode::kF64x4Div:
      return MarkAsSimd256(node), VisitF64x4Div(node);
    case IrOpcode::kI16x16AddSatS:
      return MarkAsSimd256(node), VisitI16x16AddSatS(node);
    case IrOpcode::kI8x32AddSatS:
      return MarkAsSimd256(node), VisitI8x32AddSatS(node);
    case IrOpcode::kI16x16AddSatU:
      return MarkAsSimd256(node), VisitI16x16AddSatU(node);
    case IrOpcode::kI8x32AddSatU:
      return MarkAsSimd256(node), VisitI8x32AddSatU(node);
    case IrOpcode::kI16x16SubSatS:
      return MarkAsSimd256(node), VisitI16x16SubSatS(node);
    case IrOpcode::kI8x32SubSatS:
      return MarkAsSimd256(node), VisitI8x32SubSatS(node);
    case IrOpcode::kI16x16SubSatU:
      return MarkAsSimd256(node), VisitI16x16SubSatU(node);
    case IrOpcode::kI8x32SubSatU:
      return MarkAsSimd256(node), VisitI8x32SubSatU(node);
    case IrOpcode::kI32x8SConvertF32x8:
      return MarkAsSimd256(node), VisitI32x8SConvertF32x8(node);
    case IrOpcode::kI32x8UConvertF32x8:
      return MarkAsSimd256(node), VisitI32x8UConvertF32x8(node);
    case IrOpcode::kF64x4ConvertI32x4S:
      return MarkAsSimd256(node), VisitF64x4ConvertI32x4S(node);
    case IrOpcode::kF32x8SConvertI32x8:
      return MarkAsSimd256(node), VisitF32x8SConvertI32x8(node);
    case IrOpcode::kF32x8UConvertI32x8:
      return MarkAsSimd256(node), VisitF32x8UConvertI32x8(node);
    case IrOpcode::kF32x4DemoteF64x4:
      return MarkAsSimd256(node), VisitF32x4DemoteF64x4(node);
    case IrOpcode::kI64x4SConvertI32x4:
      return MarkAsSimd256(node), VisitI64x4SConvertI32x4(node);
    case IrOpcode::kI64x4UConvertI32x4:
      return MarkAsSimd256(node), VisitI64x4UConvertI32x4(node);
    case IrOpcode::kI32x8SConvertI16x8:
      return MarkAsSimd256(node), VisitI32x8SConvertI16x8(node);
    case IrOpcode::kI32x8UConvertI16x8:
      return MarkAsSimd256(node), VisitI32x8UConvertI16x8(node);
    case IrOpcode::kI16x16SConvertI8x16:
      return MarkAsSimd256(node), VisitI16x16SConvertI8x16(node);
    case IrOpcode::kI16x16UConvertI8x16:
      return MarkAsSimd256(node), VisitI16x16UConvertI8x16(node);
    case IrOpcode::kI16x16SConvertI32x8:
      return MarkAsSimd256(node), VisitI16x16SConvertI32x8(node);
    case IrOpcode::kI16x16UConvertI32x8:
      return MarkAsSimd256(node), VisitI16x16UConvertI32x8(node);
    case IrOpcode::kI8x32SConvertI16x16:
      return MarkAsSimd256(node), VisitI8x32SConvertI16x16(node);
    case IrOpcode::kI8x32UConvertI16x16:
      return MarkAsSimd256(node), VisitI8x32UConvertI16x16(node);
    case IrOpcode::kF32x8Abs:
      return MarkAsSimd256(node), VisitF32x8Abs(node);
    case IrOpcode::kF64x4Abs:
      return MarkAsSimd256(node), VisitF64x4Abs(node);
    case IrOpcode::kF32x8Neg:
      return MarkAsSimd256(node), VisitF32x8Neg(node);
    case IrOpcode::kF64x4Neg:
      return MarkAsSimd256(node), VisitF64x4Neg(node);
    case IrOpcode::kF32x8Sqrt:
      return MarkAsSimd256(node), VisitF32x8Sqrt(node);
    case IrOpcode::kF64x4Sqrt:
      return MarkAsSimd256(node), VisitF64x4Sqrt(node);
    case IrOpcode::kI32x8Abs:
      return MarkAsSimd256(node), VisitI32x8Abs(node);
    case IrOpcode::kI32x8Neg:
      return MarkAsSimd256(node), VisitI32x8Neg(node);
    case IrOpcode::kI16x16Abs:
      return MarkAsSimd256(node), VisitI16x16Abs(node);
    case IrOpcode::kI16x16Neg:
      return MarkAsSimd256(node), VisitI16x16Neg(node);
    case IrOpcode::kI8x32Abs:
      return MarkAsSimd256(node), VisitI8x32Abs(node);
    case IrOpcode::kI8x32Neg:
      return MarkAsSimd256(node), VisitI8x32Neg(node);
    case IrOpcode::kI64x4Shl:
      return MarkAsSimd256(node), VisitI64x4Shl(node);
    case IrOpcode::kI64x4ShrU:
      return MarkAsSimd256(node), VisitI64x4ShrU(node);
    case IrOpcode::kI32x8Shl:
      return MarkAsSimd256(node), VisitI32x8Shl(node);
    case IrOpcode::kI32x8ShrS:
      return MarkAsSimd256(node), VisitI32x8ShrS(node);
    case IrOpcode::kI32x8ShrU:
      return MarkAsSimd256(node), VisitI32x8ShrU(node);
    case IrOpcode::kI16x16Shl:
      return MarkAsSimd256(node), VisitI16x16Shl(node);
    case IrOpcode::kI16x16ShrS:
      return MarkAsSimd256(node), VisitI16x16ShrS(node);
    case IrOpcode::kI16x16ShrU:
      return MarkAsSimd256(node), VisitI16x16ShrU(node);
    case IrOpcode::kI32x8DotI16x16S:
      return MarkAsSimd256(node), VisitI32x8DotI16x16S(node);
    case IrOpcode::kI16x16RoundingAverageU:
      return MarkAsSimd256(node), VisitI16x16RoundingAverageU(node);
    case IrOpcode::kI8x32RoundingAverageU:
      return MarkAsSimd256(node), VisitI8x32RoundingAverageU(node);
    case IrOpcode::kS256Const:
      return MarkAsSimd256(node), VisitS256Const(node);
    case IrOpcode::kS256Zero:
      return MarkAsSimd256(node), VisitS256Zero(node);
    case IrOpcode::kS256And:
      return MarkAsSimd256(node), VisitS256And(node);
    case IrOpcode::kS256Or:
      return MarkAsSimd256(node), VisitS256Or(node);
    case IrOpcode::kS256Xor:
      return MarkAsSimd256(node), VisitS256Xor(node);
    case IrOpcode::kS256Not:
      return MarkAsSimd256(node), VisitS256Not(node);
    case IrOpcode::kS256Select:
      return MarkAsSimd256(node), VisitS256Select(node);
    case IrOpcode::kS256AndNot:
      return MarkAsSimd256(node), VisitS256AndNot(node);
    case IrOpcode::kF32x8Eq:
      return MarkAsSimd256(node), VisitF32x8Eq(node);
    case IrOpcode::kF64x4Eq:
      return MarkAsSimd256(node), VisitF64x4Eq(node);
    case IrOpcode::kI64x4Eq:
      return MarkAsSimd256(node), VisitI64x4Eq(node);
    case IrOpcode::kI32x8Eq:
      return MarkAsSimd256(node), VisitI32x8Eq(node);
    case IrOpcode::kI16x16Eq:
      return MarkAsSimd256(node), VisitI16x16Eq(node);
    case IrOpcode::kI8x32Eq:
      return MarkAsSimd256(node), VisitI8x32Eq(node);
    case IrOpcode::kF32x8Ne:
      return MarkAsSimd256(node), VisitF32x8Ne(node);
    case IrOpcode::kF64x4Ne:
      return MarkAsSimd256(node), VisitF64x4Ne(node);
    case IrOpcode::kI64x4GtS:
      return MarkAsSimd256(node), VisitI64x4GtS(node);
    case IrOpcode::kI32x8GtS:
      return MarkAsSimd256(node), VisitI32x8GtS(node);
    case IrOpcode::kI16x16GtS:
      return MarkAsSimd256(node), VisitI16x16GtS(node);
    case IrOpcode::kI8x32GtS:
      return MarkAsSimd256(node), VisitI8x32GtS(node);
    case IrOpcode::kF64x4Lt:
      return MarkAsSimd256(node), VisitF64x4Lt(node);
    case IrOpcode::kF32x8Lt:
      return MarkAsSimd256(node), VisitF32x8Lt(node);
    case IrOpcode::kF64x4Le:
      return MarkAsSimd256(node), VisitF64x4Le(node);
    case IrOpcode::kF32x8Le:
      return MarkAsSimd256(node), VisitF32x8Le(node);
    case IrOpcode::kI32x8MinS:
      return MarkAsSimd256(node), VisitI32x8MinS(node);
    case IrOpcode::kI16x16MinS:
      return MarkAsSimd256(node), VisitI16x16MinS(node);
    case IrOpcode::kI8x32MinS:
      return MarkAsSimd256(node), VisitI8x32MinS(node);
    case IrOpcode::kI32x8MinU:
      return MarkAsSimd256(node), VisitI32x8MinU(node);
    case IrOpcode::kI16x16MinU:
      return MarkAsSimd256(node), VisitI16x16MinU(node);
    case IrOpcode::kI8x32MinU:
      return MarkAsSimd256(node), VisitI8x32MinU(node);
    case IrOpcode::kI32x8MaxS:
      return MarkAsSimd256(node), VisitI32x8MaxS(node);
    case IrOpcode::kI16x16MaxS:
      return MarkAsSimd256(node), VisitI16x16MaxS(node);
    case IrOpcode::kI8x32MaxS:
      return MarkAsSimd256(node), VisitI8x32MaxS(node);
    case IrOpcode::kI32x8MaxU:
      return MarkAsSimd256(node), VisitI32x8MaxU(node);
    case IrOpcode::kI16x16MaxU:
      return MarkAsSimd256(node), VisitI16x16MaxU(node);
    case IrOpcode::kI8x32MaxU:
      return MarkAsSimd256(node), VisitI8x32MaxU(node);
    case IrOpcode::kI64x4Splat:
      return MarkAsSimd256(node), VisitI64x4Splat(node);
    case IrOpcode::kI32x8Splat:
      return MarkAsSimd256(node), VisitI32x8Splat(node);
    case IrOpcode::kI16x16Splat:
      return MarkAsSimd256(node), VisitI16x16Splat(node);
    case IrOpcode::kI8x32Splat:
      return MarkAsSimd256(node), VisitI8x32Splat(node);
    case IrOpcode::kF32x8Splat:
      return MarkAsSimd256(node), VisitF32x8Splat(node);
    case IrOpcode::kF64x4Splat:
      return MarkAsSimd256(node), VisitF64x4Splat(node);
    case IrOpcode::kI64x4ExtMulI32x4S:
      return MarkAsSimd256(node), VisitI64x4ExtMulI32x4S(node);
    case IrOpcode::kI64x4ExtMulI32x4U:
      return MarkAsSimd256(node), VisitI64x4ExtMulI32x4U(node);
    case IrOpcode::kI32x8ExtMulI16x8S:
      return MarkAsSimd256(node), VisitI32x8ExtMulI16x8S(node);
    case IrOpcode::kI32x8ExtMulI16x8U:
      return MarkAsSimd256(node), VisitI32x8ExtMulI16x8U(node);
    case IrOpcode::kI16x16ExtMulI8x16S:
      return MarkAsSimd256(node), VisitI16x16ExtMulI8x16S(node);
    case IrOpcode::kI16x16ExtMulI8x16U:
      return MarkAsSimd256(node), VisitI16x16ExtMulI8x16U(node);
    case IrOpcode::kI32x8ExtAddPairwiseI16x16S:
      return MarkAsSimd256(node), VisitI32x8ExtAddPairwiseI16x16S(node);
    case IrOpcode::kI32x8ExtAddPairwiseI16x16U:
      return MarkAsSimd256(node), VisitI32x8ExtAddPairwiseI16x16U(node);
    case IrOpcode::kI16x16ExtAddPairwiseI8x32S:
      return MarkAsSimd256(node), VisitI16x16ExtAddPairwiseI8x32S(node);
    case IrOpcode::kI16x16ExtAddPairwiseI8x32U:
      return MarkAsSimd256(node), VisitI16x16ExtAddPairwiseI8x32U(node);
    case IrOpcode::kF32x8Pmin:
      return MarkAsSimd256(node), VisitF32x8Pmin(node);
    case IrOpcode::kF32x8Pmax:
      return MarkAsSimd256(node), VisitF32x8Pmax(node);
    case IrOpcode::kF64x4Pmin:
      return MarkAsSimd256(node), VisitF64x4Pmin(node);
    case IrOpcode::kF64x4Pmax:
      return MarkAsSimd256(node), VisitF64x4Pmax(node);
    case IrOpcode::kI8x32Shuffle:
      return MarkAsSimd256(node), VisitI8x32Shuffle(node);
    case IrOpcode::kExtractF128:
      return MarkAsSimd128(node), VisitExtractF128(node);
    case IrOpcode::kF32x8Qfma:
      return MarkAsSimd256(node), VisitF32x8Qfma(node);
    case IrOpcode::kF32x8Qfms:
      return MarkAsSimd256(node), VisitF32x8Qfms(node);
    case IrOpcode::kF64x4Qfma:
      return MarkAsSimd256(node), VisitF64x4Qfma(node);
    case IrOpcode::kF64x4Qfms:
      return MarkAsSimd256(node), VisitF64x4Qfms(node);
    case IrOpcode::kI64x4RelaxedLaneSelect:
      return MarkAsSimd256(node), VisitI64x4RelaxedLaneSelect(node);
    case IrOpcode::kI32x8RelaxedLaneSelect:
      return MarkAsSimd256(node), VisitI32x8RelaxedLaneSelect(node);
    case IrOpcode::kI16x16RelaxedLaneSelect:
      return MarkAsSimd256(node), VisitI16x16RelaxedLaneSelect(node);
    case IrOpcode::kI8x32RelaxedLaneSelect:
      return MarkAsSimd256(node), VisitI8x32RelaxedLaneSelect(node);
    case IrOpcode::kI32x8DotI8x32I7x32AddS:
      return MarkAsSimd256(node), VisitI32x8DotI8x32I7x32AddS(node);
    case IrOpcode::kI16x16DotI8x32I7x32S:
      return MarkAsSimd256(node), VisitI16x16DotI8x32I7x32S(node);
    case IrOpcode::kF32x8RelaxedMin:
      return MarkAsSimd256(node), VisitF32x8RelaxedMin(node);
    case IrOpcode::kF32x8RelaxedMax:
      return MarkAsSimd256(node), VisitF32x8RelaxedMax(node);
    case IrOpcode::kF64x4RelaxedMin:
      return MarkAsSimd256(node), VisitF64x4RelaxedMin(node);
    case IrOpcode::kF64x4RelaxedMax:
      return MarkAsSimd256(node), VisitF64x4RelaxedMax(node);
    case IrOpcode::kI32x8RelaxedTruncF32x8S:
      return MarkAsSimd256(node), VisitI32x8RelaxedTruncF32x8S(node);
    case IrOpcode::kI32x8RelaxedTruncF32x8U:
      return MarkAsSimd256(node), VisitI32x8RelaxedTruncF32x8U(node);
#endif  // V8_TARGET_ARCH_X64 && V8_ENABLE_WASM_SIMD256_REVEC
#endif  // V8_ENABLE_WEBASSEMBLY
    default:
      FATAL("Unexpected operator #%d:%s @ node #%d", node->opcode(),
            node->op()->mnemonic(), node->id());
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitNode(
    turboshaft::OpIndex node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  tick_counter_->TickAndMaybeEnterSafepoint();
  const turboshaft::Operation& op = this->Get(node);
  using Opcode = turboshaft::Opcode;
  using Rep = turboshaft::RegisterRepresentation;
  switch (op.opcode) {
    case Opcode::kBranch:
    case Opcode::kGoto:
    case Opcode::kReturn:
    case Opcode::kTailCall:
    case Opcode::kUnreachable:
    case Opcode::kDeoptimize:
    case Opcode::kSwitch:
    case Opcode::kCheckException:
      // Those are already handled in VisitControl.
      DCHECK(op.IsBlockTerminator());
      break;
    case Opcode::kParameter: {
      // Parameters should always be scheduled to the first block.
      DCHECK_EQ(this->rpo_number(this->block(schedule(), node)).ToInt(), 0);
      MachineType type = linkage()->GetParameterType(
          op.Cast<turboshaft::ParameterOp>().parameter_index);
      MarkAsRepresentation(type.representation(), node);
      return VisitParameter(node);
    }
    case Opcode::kChange: {
      const turboshaft::ChangeOp& change = op.Cast<turboshaft::ChangeOp>();
      MarkAsRepresentation(change.to.machine_representation(), node);
      switch (change.kind) {
        case ChangeOp::Kind::kFloatConversion:
          if (change.from == Rep::Float64()) {
            DCHECK_EQ(change.to, Rep::Float32());
            return VisitTruncateFloat64ToFloat32(node);
          } else {
            DCHECK_EQ(change.from, Rep::Float32());
            DCHECK_EQ(change.to, Rep::Float64());
            return VisitChangeFloat32ToFloat64(node);
          }
        case ChangeOp::Kind::kSignedFloatTruncateOverflowToMin:
        case ChangeOp::Kind::kUnsignedFloatTruncateOverflowToMin: {
          using A = ChangeOp::Assumption;
          bool is_signed =
              change.kind == ChangeOp::Kind::kSignedFloatTruncateOverflowToMin;
          switch (multi(change.from, change.to, is_signed, change.assumption)) {
            case multi(Rep::Float32(), Rep::Word32(), true, A::kNoOverflow):
            case multi(Rep::Float32(), Rep::Word32(), true, A::kNoAssumption):
              return VisitTruncateFloat32ToInt32(node);
            case multi(Rep::Float32(), Rep::Word32(), false, A::kNoOverflow):
            case multi(Rep::Float32(), Rep::Word32(), false, A::kNoAssumption):
              return VisitTruncateFloat32ToUint32(node);
            case multi(Rep::Float64(), Rep::Word32(), true, A::kReversible):
              return VisitChangeFloat64ToInt32(node);
            case multi(Rep::Float64(), Rep::Word32(), false, A::kReversible):
              return VisitChangeFloat64ToUint32(node);
            case multi(Rep::Float64(), Rep::Word32(), true, A::kNoOverflow):
              return VisitRoundFloat64ToInt32(node);
            case multi(Rep::Float64(), Rep::Word32(), false, A::kNoAssumption):
            case multi(Rep::Float64(), Rep::Word32(), false, A::kNoOverflow):
              return VisitTruncateFloat64ToUint32(node);
            case multi(Rep::Float64(), Rep::Word64(), true, A::kReversible):
              return VisitChangeFloat64ToInt64(node);
            case multi(Rep::Float64(), Rep::Word64(), false, A::kReversible):
              return VisitChangeFloat64ToUint64(node);
            case multi(Rep::Float64(), Rep::Word64(), true, A::kNoOverflow):
            case multi(Rep::Float64(), Rep::Word64(), true, A::kNoAssumption):
              return VisitTruncateFloat64ToInt64(node);
            default:
              // Invalid combination.
              UNREACHABLE();
          }

          UNREACHABLE();
        }
        case ChangeOp::Kind::kJSFloatTruncate:
          DCHECK_EQ(change.from, Rep::Float64());
          DCHECK_EQ(change.to, Rep::Word32());
          return VisitTruncateFloat64ToWord32(node);
        case ChangeOp::Kind::kJSFloat16TruncateWithBitcast:
          DCHECK_EQ(Rep::Float64(), change.from);
          DCHECK_EQ(Rep::Word32(), change.to);
          return VisitTruncateFloat64ToFloat16RawBits(node);
        case ChangeOp::Kind::kSignedToFloat:
          if (change.from == Rep::Word32()) {
            if (change.to == Rep::Float32()) {
              return VisitRoundInt32ToFloat32(node);
            } else {
              DCHECK_EQ(change.to, Rep::Float64());
              DCHECK_EQ(change.assumption, ChangeOp::Assumption::kNoAssumption);
              return VisitChangeInt32ToFloat64(node);
            }
          } else {
            DCHECK_EQ(change.from, Rep::Word64());
            if (change.to == Rep::Float32()) {
              return VisitRoundInt64ToFloat32(node);
            } else {
              DCHECK_EQ(change.to, Rep::Float64());
              if (change.assumption == ChangeOp::Assumption::kReversible) {
                return VisitChangeInt64ToFloat64(node);
              } else {
                return VisitRoundInt64ToFloat64(node);
              }
            }
          }
          UNREACHABLE();
        case ChangeOp::Kind::kUnsignedToFloat:
          switch (multi(change.from, change.to)) {
            case multi(Rep::Word32(), Rep::Float32()):
              return VisitRoundUint32ToFloat32(node);
            case multi(Rep::Word32(), Rep::Float64()):
              return VisitChangeUint32ToFloat64(node);
            case multi(Rep::Word64(), Rep::Float32()):
              return VisitRoundUint64ToFloat32(node);
            case multi(Rep::Word64(), Rep::Float64()):
              return VisitRoundUint64ToFloat64(node);
            default:
              UNREACHABLE();
          }
        case ChangeOp::Kind::kExtractHighHalf:
          DCHECK_EQ(change.from, Rep::Float64());
          DCHECK_EQ(change.to, Rep::Word32());
          return VisitFloat64ExtractHighWord32(node);
        case ChangeOp::Kind::kExtractLowHalf:
          DCHECK_EQ(change.from, Rep::Float64());
          DCHECK_EQ(change.to, Rep::Word32());
          return VisitFloat64ExtractLowWord32(node);
        case ChangeOp::Kind::kZeroExtend:
          DCHECK_EQ(change.from, Rep::Word32());
          DCHECK_EQ(change.to, Rep::Word64());
          return VisitChangeUint32ToUint64(node);
        case ChangeOp::Kind::kSignExtend:
          DCHECK_EQ(change.from, Rep::Word32());
          DCHECK_EQ(change.to, Rep::Word64());
          return VisitChangeInt32ToInt64(node);
        case ChangeOp::Kind::kTruncate:
          DCHECK_EQ(change.from, Rep::Word64());
          DCHECK_EQ(change.to, Rep::Word32());
          MarkAsWord32(node);
          return VisitTruncateInt64ToInt32(node);
        case ChangeOp::Kind::kBitcast:
          switch (multi(change.from, change.to)) {
```