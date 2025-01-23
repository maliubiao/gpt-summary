Response:
The user wants to understand the functionality of the provided C++ header file snippet. This file seems to define an enumeration of opcodes used in the V8 compiler.

Here's a breakdown of how to approach the prompt:

1. **Identify the core purpose:** The code defines macros (`IF_WASM`, `MACHINE_SIMD256_OP_LIST`, `VALUE_OP_LIST`, `ALL_OP_LIST`) and an enum `IrOpcode::Value`. The core purpose is to list and categorize opcodes.

2. **Explain the structure:** Describe how the macros are used to conditionally include opcodes based on `IF_WASM`. Explain that the `IrOpcode::Value` enum lists all the opcodes.

3. **Analyze the opcode categories:**  Notice the different `_OP_LIST` macros (WASM, SIMD, MACHINE, COMMON, JS, CONTROL). Explain these categories and what they likely represent.

4. **Address the `.tq` question:** Explain that if the filename ended in `.tq`, it would be a Torque file, but since it's `.h`, it's a C++ header.

5. **Relate to JavaScript (if applicable):**  Look for opcodes with `JS` prefixes. These are directly related to JavaScript operations. Provide JavaScript examples for some common JS opcodes (like addition, property access).

6. **Code logic reasoning:** The code is primarily a declaration, not executable logic. However, the `Is*Opcode` methods implement logic to check the category of an opcode. Provide an example of how these methods work with an assumed input and output.

7. **Common programming errors:** This file itself doesn't directly expose users to errors. However, knowing the opcodes helps understand compiler errors or performance issues related to specific operations. Give an example related to incorrect type usage leading to inefficient opcodes.

8. **Summarize the functionality:**  Concise recap of the file's role in defining and categorizing compiler operations.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 如果v8/src/compiler/opcodes.h以.tq结尾，那它是个v8 torque源代码: Yes
* 如果它与javascript的功能有关系，请用javascript举例说明: Yes
* 如果有代码逻辑推理，请给出假设输入与输出: Yes
* 如果涉及用户常见的编程错误，请举例说明: Yes
* 这是第2部分，共2部分，请归纳一下它的功能: Yes

Confidence Score: 5/5

**Mental Sandbox Simulation:**

* Imagine trying to use these opcodes directly in JavaScript - it's not possible, they are internal compiler concepts.
* Think about the compilation process - this header is crucial for the compiler to understand and generate machine code.
* Consider the different categories of opcodes - how does this structure help in organizing the compiler's work?

By following these steps, the response should accurately and comprehensively address the user's request.
这是v8源代码文件 `v8/src/compiler/opcodes.h` 的第二部分，延续了第一部分定义 V8 编译器中使用的各种操作码（opcodes）。

**功能归纳:**

总的来说，`v8/src/compiler/opcodes.h` 文件的主要功能是**定义了 V8 编译器中间表示（Intermediate Representation, IR）中使用的所有操作码。** 这些操作码代表了编译器在优化和生成机器码过程中可以执行的各种操作。

具体到你提供的这段代码，它主要定义了与 **WebAssembly (Wasm) SIMD (Single Instruction, Multiple Data)** 相关的操作码，以及一些用于 **AVX (Advanced Vector Extensions)** 指令集的 SIMD256 操作码。

**详细功能列表:**

1. **WebAssembly SIMD 操作码:**
   -  这段代码大量使用了 `IF_WASM(V, Op)` 宏，这表明其定义的主要是 WebAssembly 的 SIMD 指令。
   -  这些操作码覆盖了各种 SIMD 数据类型的操作，例如：
      - `F64x2`: 包含两个 64 位浮点数的向量。
      - `F32x4`: 包含四个 32 位浮点数的向量。
      - `F16x8`: 包含八个 16 位浮点数的向量。
      - `I64x2`: 包含两个 64 位整数的向量。
      - `I32x4`: 包含四个 32 位整数的向量。
      - `I16x8`: 包含八个 16 位整数的向量。
      - `I8x16`: 包含十六个 8 位整数的向量。
   -  针对每种 SIMD 数据类型，定义了各种操作，例如：
      - **算术运算:** `Add`, `Sub`, `Mul`, `Div`
      - **比较运算:** `Eq`, `Ne`, `Lt`, `Le`, `Gt`, `Ge`
      - **位运算:** `Shl`, `ShrS`, `ShrU`, `And`, `Or`, `Xor`, `Not`, `AndNot`
      - **转换运算:**  例如 `ConvertLowI32x4S` (将 `I32x4` 的低位转换为 `F64x2`)，`SConvertI32x4` (将 `I32x4` 转换为 `F32x4`)
      - **其他操作:** 例如 `Abs` (绝对值), `Neg` (取反), `Sqrt` (平方根), `Min`, `Max`, `Splat` (将标量值复制到向量的所有通道), `ExtractLane` (提取向量中的一个元素), `ReplaceLane` (替换向量中的一个元素), `Shuffle` (重排向量元素)
      - **特殊操作:** 例如 `Qfma` (Fused Multiply-Add), `Pmin` (Pairwise Minimum),  `DotI16x8S` (点积)
      - **Relaxed 操作:** 带有 `Relaxed` 前缀的操作，通常用于一些允许精度损失或有特定平台优化的变体。

2. **SIMD256 操作码 (AVX):**
   -  `MACHINE_SIMD256_OP_LIST(V)` 定义了针对支持 AVX 指令集的架构的 256 位 SIMD 操作码。
   -  这些操作码类似于 SIMD128，但处理的数据宽度更大，例如：
      - `F64x4`: 包含四个 64 位浮点数的向量。
      - `F32x8`: 包含八个 32 位浮点数的向量。
      - `I64x4`: 包含四个 64 位整数的向量。
      - `I32x8`: 包含八个 32 位整数的向量。
      - `I16x16`: 包含十六个 16 位整数的向量。
      - `I8x32`: 包含三十二个 8 位整数的向量。
   -  同样包含了算术、比较、位运算、转换和其他操作。

**如果 `v8/src/compiler/opcodes.h` 以 `.tq` 结尾:**

如果 `v8/src/compiler/opcodes.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 使用的一种领域特定语言（DSL），用于定义运行时函数的实现，特别是那些需要高性能和底层控制的操作。在这种情况下，这个 `.tq` 文件可能会定义生成或处理这些操作码的 Torque 代码。

**与 JavaScript 的关系 (通过 WebAssembly):**

这段代码中定义的操作码主要与 **WebAssembly** 相关，而不是直接对应于标准的 JavaScript 语法。然而，JavaScript 可以通过 WebAssembly 来间接地利用这些 SIMD 功能。

**JavaScript 示例 (展示如何触发 WebAssembly SIMD 操作):**

```javascript
// 假设你有一个编译好的 WebAssembly 模块，其中使用了 SIMD 指令
const wasmCode = await fetch('my_simd_module.wasm');
const wasmInstance = await WebAssembly.instantiateStreaming(wasmCode);

// 假设 WebAssembly 模块导出了一个函数 `vectorAdd`，
// 它接受两个 Float32x4 类型的参数并返回一个 Float32x4

const a = new Float32Array([1, 2, 3, 4]);
const b = new Float32Array([5, 6, 7, 8]);

const vectorA = Float32x4.fromArray(a);
const vectorB = Float32x4.fromArray(b);

const resultVector = wasmInstance.exports.vectorAdd(vectorA, vectorB);

const resultArray = Float32x4.toArray(resultVector);
console.log(resultArray); // 输出类似 [6, 8, 10, 12]
```

在这个例子中，JavaScript 代码创建了 `Float32x4` 类型的数组，并将它们传递给 WebAssembly 模块中的 `vectorAdd` 函数。`vectorAdd` 函数的实现很可能会利用你在 `opcodes.h` 中看到的类似 `F32x4Add` 的操作码。

**代码逻辑推理:**

这段代码主要是**声明式**的，定义了枚举值。代码逻辑推理更多体现在如何使用这些定义。例如，`IsSimd128Opcode` 函数会检查给定的 `Value` 是否在 `MACHINE_SIMD128_OP_LIST` 中定义。

**假设输入与输出 (针对 `IsSimd128Opcode`):**

**假设输入:** `IrOpcode::Value::kF32x4Add`

**预期输出:** `true` (因为 `F32x4Add` 在 `MACHINE_SIMD128_OP_LIST` 中定义)

**假设输入:** `IrOpcode::Value::kJSAdd`

**预期输出:** `false` (因为 `kJSAdd` 是一个 JavaScript 操作码，不在 `MACHINE_SIMD128_OP_LIST` 中)

**涉及用户常见的编程错误:**

虽然用户不会直接编写这些操作码，但理解这些操作码有助于理解与 WebAssembly SIMD 相关的错误。

**示例错误:**

1. **类型不匹配:** 在 WebAssembly 中，SIMD 操作对数据类型非常敏感。如果 JavaScript 代码传递给 WebAssembly 函数的数组类型与 WebAssembly 期望的类型不匹配，可能会导致错误或性能问题。例如，将 `Float64Array` 传递给期望 `Float32x4` 的函数。

2. **通道数量错误:** SIMD 操作依赖于固定数量的通道。尝试对通道数量不匹配的向量进行操作会导致错误。

3. **未启用 SIMD 支持:** 在某些环境中，可能需要显式启用 WebAssembly SIMD 支持。如果未启用，使用了 SIMD 指令的 WebAssembly 模块可能无法正确运行。

**总结 (第二部分功能):**

这部分 `v8/src/compiler/opcodes.h` 的主要功能是定义了 V8 编译器中用于表示 **WebAssembly SIMD 操作** 以及 **部分 AVX SIMD256 操作** 的操作码。这些操作码是编译器理解和优化 WebAssembly SIMD 代码的关键。虽然 JavaScript 开发者不会直接使用这些操作码，但理解它们有助于理解 WebAssembly SIMD 的工作原理以及可能出现的错误。

### 提示词
```
这是目录为v8/src/compiler/opcodes.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/opcodes.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
\
  IF_WASM(V, F64x2Pmin)                   \
  IF_WASM(V, F64x2Pmax)                   \
  IF_WASM(V, F64x2Ceil)                   \
  IF_WASM(V, F64x2Floor)                  \
  IF_WASM(V, F64x2Trunc)                  \
  IF_WASM(V, F64x2NearestInt)             \
  IF_WASM(V, F64x2ConvertLowI32x4S)       \
  IF_WASM(V, F64x2ConvertLowI32x4U)       \
  IF_WASM(V, F64x2PromoteLowF32x4)        \
  IF_WASM(V, F32x4Splat)                  \
  IF_WASM(V, F32x4ExtractLane)            \
  IF_WASM(V, F32x4ReplaceLane)            \
  IF_WASM(V, F32x4SConvertI32x4)          \
  IF_WASM(V, F32x4UConvertI32x4)          \
  IF_WASM(V, F32x4Abs)                    \
  IF_WASM(V, F32x4Neg)                    \
  IF_WASM(V, F32x4Sqrt)                   \
  IF_WASM(V, F32x4Add)                    \
  IF_WASM(V, F32x4Sub)                    \
  IF_WASM(V, F32x4Mul)                    \
  IF_WASM(V, F32x4Div)                    \
  IF_WASM(V, F32x4Min)                    \
  IF_WASM(V, F32x4Max)                    \
  IF_WASM(V, F32x4Eq)                     \
  IF_WASM(V, F32x4Ne)                     \
  IF_WASM(V, F32x4Lt)                     \
  IF_WASM(V, F32x4Le)                     \
  IF_WASM(V, F32x4Gt)                     \
  IF_WASM(V, F32x4Ge)                     \
  IF_WASM(V, F32x4Qfma)                   \
  IF_WASM(V, F32x4Qfms)                   \
  IF_WASM(V, F32x4Pmin)                   \
  IF_WASM(V, F32x4Pmax)                   \
  IF_WASM(V, F32x4Ceil)                   \
  IF_WASM(V, F32x4Floor)                  \
  IF_WASM(V, F32x4Trunc)                  \
  IF_WASM(V, F32x4NearestInt)             \
  IF_WASM(V, F32x4DemoteF64x2Zero)        \
  IF_WASM(V, F16x8Splat)                  \
  IF_WASM(V, F16x8ExtractLane)            \
  IF_WASM(V, F16x8ReplaceLane)            \
  IF_WASM(V, F16x8Abs)                    \
  IF_WASM(V, F16x8Neg)                    \
  IF_WASM(V, F16x8Sqrt)                   \
  IF_WASM(V, F16x8Ceil)                   \
  IF_WASM(V, F16x8Floor)                  \
  IF_WASM(V, F16x8Trunc)                  \
  IF_WASM(V, F16x8NearestInt)             \
  IF_WASM(V, F16x8Add)                    \
  IF_WASM(V, F16x8Sub)                    \
  IF_WASM(V, F16x8Mul)                    \
  IF_WASM(V, F16x8Div)                    \
  IF_WASM(V, F16x8Min)                    \
  IF_WASM(V, F16x8Max)                    \
  IF_WASM(V, F16x8Pmin)                   \
  IF_WASM(V, F16x8Pmax)                   \
  IF_WASM(V, F16x8Eq)                     \
  IF_WASM(V, F16x8Ne)                     \
  IF_WASM(V, F16x8Lt)                     \
  IF_WASM(V, F16x8Le)                     \
  IF_WASM(V, F16x8Gt)                     \
  IF_WASM(V, F16x8Ge)                     \
  IF_WASM(V, I16x8SConvertF16x8)          \
  IF_WASM(V, I16x8UConvertF16x8)          \
  IF_WASM(V, F16x8SConvertI16x8)          \
  IF_WASM(V, F16x8UConvertI16x8)          \
  IF_WASM(V, F16x8DemoteF32x4Zero)        \
  IF_WASM(V, F16x8DemoteF64x2Zero)        \
  IF_WASM(V, F32x4PromoteLowF16x8)        \
  IF_WASM(V, F16x8Qfma)                   \
  IF_WASM(V, F16x8Qfms)                   \
  IF_WASM(V, I64x2Splat)                  \
  IF_WASM(V, I64x2SplatI32Pair)           \
  IF_WASM(V, I64x2ExtractLane)            \
  IF_WASM(V, I64x2ReplaceLane)            \
  IF_WASM(V, I64x2ReplaceLaneI32Pair)     \
  IF_WASM(V, I64x2Abs)                    \
  IF_WASM(V, I64x2Neg)                    \
  IF_WASM(V, I64x2SConvertI32x4Low)       \
  IF_WASM(V, I64x2SConvertI32x4High)      \
  IF_WASM(V, I64x2UConvertI32x4Low)       \
  IF_WASM(V, I64x2UConvertI32x4High)      \
  IF_WASM(V, I64x2BitMask)                \
  IF_WASM(V, I64x2Shl)                    \
  IF_WASM(V, I64x2ShrS)                   \
  IF_WASM(V, I64x2Add)                    \
  IF_WASM(V, I64x2Sub)                    \
  IF_WASM(V, I64x2Mul)                    \
  IF_WASM(V, I64x2Eq)                     \
  IF_WASM(V, I64x2Ne)                     \
  IF_WASM(V, I64x2GtS)                    \
  IF_WASM(V, I64x2GeS)                    \
  IF_WASM(V, I64x2ShrU)                   \
  IF_WASM(V, I64x2ExtMulLowI32x4S)        \
  IF_WASM(V, I64x2ExtMulHighI32x4S)       \
  IF_WASM(V, I64x2ExtMulLowI32x4U)        \
  IF_WASM(V, I64x2ExtMulHighI32x4U)       \
  IF_WASM(V, I32x4Splat)                  \
  IF_WASM(V, I32x4ExtractLane)            \
  IF_WASM(V, I32x4ReplaceLane)            \
  IF_WASM(V, I32x4SConvertF32x4)          \
  IF_WASM(V, I32x4SConvertI16x8Low)       \
  IF_WASM(V, I32x4SConvertI16x8High)      \
  IF_WASM(V, I32x4Neg)                    \
  IF_WASM(V, I32x4Shl)                    \
  IF_WASM(V, I32x4ShrS)                   \
  IF_WASM(V, I32x4Add)                    \
  IF_WASM(V, I32x4Sub)                    \
  IF_WASM(V, I32x4Mul)                    \
  IF_WASM(V, I32x4MinS)                   \
  IF_WASM(V, I32x4MaxS)                   \
  IF_WASM(V, I32x4Eq)                     \
  IF_WASM(V, I32x4Ne)                     \
  IF_WASM(V, I32x4LtS)                    \
  IF_WASM(V, I32x4LeS)                    \
  IF_WASM(V, I32x4GtS)                    \
  IF_WASM(V, I32x4GeS)                    \
  IF_WASM(V, I32x4UConvertF32x4)          \
  IF_WASM(V, I32x4UConvertI16x8Low)       \
  IF_WASM(V, I32x4UConvertI16x8High)      \
  IF_WASM(V, I32x4ShrU)                   \
  IF_WASM(V, I32x4MinU)                   \
  IF_WASM(V, I32x4MaxU)                   \
  IF_WASM(V, I32x4LtU)                    \
  IF_WASM(V, I32x4LeU)                    \
  IF_WASM(V, I32x4GtU)                    \
  IF_WASM(V, I32x4GeU)                    \
  IF_WASM(V, I32x4Abs)                    \
  IF_WASM(V, I32x4BitMask)                \
  IF_WASM(V, I32x4DotI16x8S)              \
  IF_WASM(V, I32x4ExtMulLowI16x8S)        \
  IF_WASM(V, I32x4ExtMulHighI16x8S)       \
  IF_WASM(V, I32x4ExtMulLowI16x8U)        \
  IF_WASM(V, I32x4ExtMulHighI16x8U)       \
  IF_WASM(V, I32x4ExtAddPairwiseI16x8S)   \
  IF_WASM(V, I32x4ExtAddPairwiseI16x8U)   \
  IF_WASM(V, I32x4TruncSatF64x2SZero)     \
  IF_WASM(V, I32x4TruncSatF64x2UZero)     \
  IF_WASM(V, I16x8Splat)                  \
  IF_WASM(V, I16x8ExtractLaneU)           \
  IF_WASM(V, I16x8ExtractLaneS)           \
  IF_WASM(V, I16x8ReplaceLane)            \
  IF_WASM(V, I16x8SConvertI8x16Low)       \
  IF_WASM(V, I16x8SConvertI8x16High)      \
  IF_WASM(V, I16x8Neg)                    \
  IF_WASM(V, I16x8Shl)                    \
  IF_WASM(V, I16x8ShrS)                   \
  IF_WASM(V, I16x8SConvertI32x4)          \
  IF_WASM(V, I16x8Add)                    \
  IF_WASM(V, I16x8AddSatS)                \
  IF_WASM(V, I16x8Sub)                    \
  IF_WASM(V, I16x8SubSatS)                \
  IF_WASM(V, I16x8Mul)                    \
  IF_WASM(V, I16x8MinS)                   \
  IF_WASM(V, I16x8MaxS)                   \
  IF_WASM(V, I16x8Eq)                     \
  IF_WASM(V, I16x8Ne)                     \
  IF_WASM(V, I16x8LtS)                    \
  IF_WASM(V, I16x8LeS)                    \
  IF_WASM(V, I16x8GtS)                    \
  IF_WASM(V, I16x8GeS)                    \
  IF_WASM(V, I16x8UConvertI8x16Low)       \
  IF_WASM(V, I16x8UConvertI8x16High)      \
  IF_WASM(V, I16x8ShrU)                   \
  IF_WASM(V, I16x8UConvertI32x4)          \
  IF_WASM(V, I16x8AddSatU)                \
  IF_WASM(V, I16x8SubSatU)                \
  IF_WASM(V, I16x8MinU)                   \
  IF_WASM(V, I16x8MaxU)                   \
  IF_WASM(V, I16x8LtU)                    \
  IF_WASM(V, I16x8LeU)                    \
  IF_WASM(V, I16x8GtU)                    \
  IF_WASM(V, I16x8GeU)                    \
  IF_WASM(V, I16x8RoundingAverageU)       \
  IF_WASM(V, I16x8Q15MulRSatS)            \
  IF_WASM(V, I16x8Abs)                    \
  IF_WASM(V, I16x8BitMask)                \
  IF_WASM(V, I16x8ExtMulLowI8x16S)        \
  IF_WASM(V, I16x8ExtMulHighI8x16S)       \
  IF_WASM(V, I16x8ExtMulLowI8x16U)        \
  IF_WASM(V, I16x8ExtMulHighI8x16U)       \
  IF_WASM(V, I16x8ExtAddPairwiseI8x16S)   \
  IF_WASM(V, I16x8ExtAddPairwiseI8x16U)   \
  V(I8x16Splat)                           \
  IF_WASM(V, I8x16ExtractLaneU)           \
  IF_WASM(V, I8x16ExtractLaneS)           \
  IF_WASM(V, I8x16ReplaceLane)            \
  IF_WASM(V, I8x16SConvertI16x8)          \
  IF_WASM(V, I8x16Neg)                    \
  IF_WASM(V, I8x16Shl)                    \
  IF_WASM(V, I8x16ShrS)                   \
  IF_WASM(V, I8x16Add)                    \
  IF_WASM(V, I8x16AddSatS)                \
  IF_WASM(V, I8x16Sub)                    \
  IF_WASM(V, I8x16SubSatS)                \
  IF_WASM(V, I8x16MinS)                   \
  IF_WASM(V, I8x16MaxS)                   \
  V(I8x16Eq)                              \
  IF_WASM(V, I8x16Ne)                     \
  IF_WASM(V, I8x16LtS)                    \
  IF_WASM(V, I8x16LeS)                    \
  IF_WASM(V, I8x16GtS)                    \
  IF_WASM(V, I8x16GeS)                    \
  IF_WASM(V, I8x16UConvertI16x8)          \
  IF_WASM(V, I8x16AddSatU)                \
  IF_WASM(V, I8x16SubSatU)                \
  IF_WASM(V, I8x16ShrU)                   \
  IF_WASM(V, I8x16MinU)                   \
  IF_WASM(V, I8x16MaxU)                   \
  IF_WASM(V, I8x16LtU)                    \
  IF_WASM(V, I8x16LeU)                    \
  IF_WASM(V, I8x16GtU)                    \
  IF_WASM(V, I8x16GeU)                    \
  IF_WASM(V, I8x16RoundingAverageU)       \
  IF_WASM(V, I8x16Popcnt)                 \
  IF_WASM(V, I8x16Abs)                    \
  V(I8x16BitMask)                         \
  IF_WASM(V, S128Zero)                    \
  IF_WASM(V, S128Const)                   \
  IF_WASM(V, S128Not)                     \
  IF_WASM(V, S128And)                     \
  IF_WASM(V, S128Or)                      \
  IF_WASM(V, S128Xor)                     \
  IF_WASM(V, S128Select)                  \
  IF_WASM(V, S128AndNot)                  \
  IF_WASM(V, I8x16Swizzle)                \
  IF_WASM(V, I8x16RelaxedLaneSelect)      \
  IF_WASM(V, I16x8RelaxedLaneSelect)      \
  IF_WASM(V, I32x4RelaxedLaneSelect)      \
  IF_WASM(V, I64x2RelaxedLaneSelect)      \
  IF_WASM(V, F32x4RelaxedMin)             \
  IF_WASM(V, F32x4RelaxedMax)             \
  IF_WASM(V, F64x2RelaxedMin)             \
  IF_WASM(V, F64x2RelaxedMax)             \
  IF_WASM(V, I32x4RelaxedTruncF32x4S)     \
  IF_WASM(V, I32x4RelaxedTruncF32x4U)     \
  IF_WASM(V, I32x4RelaxedTruncF64x2SZero) \
  IF_WASM(V, I32x4RelaxedTruncF64x2UZero) \
  IF_WASM(V, I16x8RelaxedQ15MulRS)        \
  IF_WASM(V, I16x8DotI8x16I7x16S)         \
  IF_WASM(V, I32x4DotI8x16I7x16AddS)      \
  IF_WASM(V, I8x16AddReduce)              \
  IF_WASM(V, I16x8AddReduce)              \
  IF_WASM(V, I32x4AddReduce)              \
  IF_WASM(V, I64x2AddReduce)              \
  IF_WASM(V, F32x4AddReduce)              \
  IF_WASM(V, F64x2AddReduce)              \
  IF_WASM(V, I8x16Shuffle)                \
  IF_WASM(V, V128AnyTrue)                 \
  IF_WASM(V, I64x2AllTrue)                \
  IF_WASM(V, I32x4AllTrue)                \
  IF_WASM(V, I16x8AllTrue)                \
  IF_WASM(V, I8x16AllTrue)                \
  IF_WASM(V, LoadTransform)               \
  IF_WASM(V, LoadLane)                    \
  IF_WASM(V, StoreLane)

// SIMD256 for AVX
#define MACHINE_SIMD256_OP_LIST(V) \
  V(F64x4Min)                      \
  V(F64x4Max)                      \
  V(F64x4Add)                      \
  V(F64x4Abs)                      \
  V(F64x4Neg)                      \
  V(F64x4Sqrt)                     \
  V(F32x8Add)                      \
  V(I64x4Add)                      \
  V(I32x8Add)                      \
  V(I16x16Add)                     \
  V(I8x32Add)                      \
  V(F64x4Sub)                      \
  V(F32x8Sub)                      \
  V(I64x4Sub)                      \
  V(I32x8Sub)                      \
  V(I16x16Sub)                     \
  V(I8x32Sub)                      \
  V(F64x4Mul)                      \
  V(F32x8Mul)                      \
  V(I64x4Mul)                      \
  V(I32x8Mul)                      \
  V(I16x16Mul)                     \
  V(F64x4Div)                      \
  V(F32x8Div)                      \
  V(I16x16AddSatS)                 \
  V(I8x32AddSatS)                  \
  V(I16x16AddSatU)                 \
  V(I8x32AddSatU)                  \
  V(I16x16SubSatS)                 \
  V(I8x32SubSatS)                  \
  V(I16x16SubSatU)                 \
  V(I8x32SubSatU)                  \
  V(F32x8Pmin)                     \
  V(F32x8Pmax)                     \
  V(F32x8Eq)                       \
  V(F64x4Eq)                       \
  V(I64x4Eq)                       \
  V(I32x8Eq)                       \
  V(I16x16Eq)                      \
  V(I8x32Eq)                       \
  V(F32x8Ne)                       \
  V(F64x4Ne)                       \
  V(I64x4GtS)                      \
  V(I32x8GtS)                      \
  V(I16x16GtS)                     \
  V(I8x32GtS)                      \
  V(F64x4Lt)                       \
  V(F32x8Lt)                       \
  V(F64x4Le)                       \
  V(F32x8Le)                       \
  V(I32x8MinS)                     \
  V(I16x16MinS)                    \
  V(I8x32MinS)                     \
  V(I32x8MinU)                     \
  V(I16x16MinU)                    \
  V(I8x32MinU)                     \
  V(I32x8MaxS)                     \
  V(I16x16MaxS)                    \
  V(I8x32MaxS)                     \
  V(I32x8MaxU)                     \
  V(I16x16MaxU)                    \
  V(I8x32MaxU)                     \
  V(F32x8Min)                      \
  V(F32x8Max)                      \
  V(I64x4Ne)                       \
  V(I64x4GeS)                      \
  V(I32x8Ne)                       \
  V(I32x8GtU)                      \
  V(I32x8GeS)                      \
  V(I32x8GeU)                      \
  V(I16x16Ne)                      \
  V(I16x16GtU)                     \
  V(I16x16GeS)                     \
  V(I16x16GeU)                     \
  V(I8x32Ne)                       \
  V(I8x32GtU)                      \
  V(I8x32GeS)                      \
  V(I8x32GeU)                      \
  V(I32x8SConvertF32x8)            \
  V(I32x8UConvertF32x8)            \
  V(F64x4ConvertI32x4S)            \
  V(F32x8SConvertI32x8)            \
  V(F32x8UConvertI32x8)            \
  V(F32x4DemoteF64x4)              \
  V(I64x4SConvertI32x4)            \
  V(I64x4UConvertI32x4)            \
  V(I32x8SConvertI16x8)            \
  V(I32x8UConvertI16x8)            \
  V(I16x16SConvertI8x16)           \
  V(I16x16UConvertI8x16)           \
  V(I16x16SConvertI32x8)           \
  V(I16x16UConvertI32x8)           \
  V(I8x32SConvertI16x16)           \
  V(I8x32UConvertI16x16)           \
  V(F32x8Abs)                      \
  V(F32x8Neg)                      \
  V(F32x8Sqrt)                     \
  V(I32x8Abs)                      \
  V(I32x8Neg)                      \
  V(I16x16Abs)                     \
  V(I16x16Neg)                     \
  V(I8x32Abs)                      \
  V(I8x32Neg)                      \
  V(I64x4Shl)                      \
  V(I64x4ShrU)                     \
  V(I32x8Shl)                      \
  V(I32x8ShrS)                     \
  V(I32x8ShrU)                     \
  V(I16x16Shl)                     \
  V(I16x16ShrS)                    \
  V(I16x16ShrU)                    \
  V(I32x8DotI16x16S)               \
  V(I16x16RoundingAverageU)        \
  V(I8x32RoundingAverageU)         \
  V(I64x4ExtMulI32x4S)             \
  V(I64x4ExtMulI32x4U)             \
  V(I32x8ExtMulI16x8S)             \
  V(I32x8ExtMulI16x8U)             \
  V(I16x16ExtMulI8x16S)            \
  V(I16x16ExtMulI8x16U)            \
  V(I32x8ExtAddPairwiseI16x16S)    \
  V(I32x8ExtAddPairwiseI16x16U)    \
  V(I16x16ExtAddPairwiseI8x32S)    \
  V(I16x16ExtAddPairwiseI8x32U)    \
  V(ExtractF128)                   \
  V(S256Const)                     \
  V(S256Zero)                      \
  V(S256Not)                       \
  V(S256And)                       \
  V(S256Or)                        \
  V(S256Xor)                       \
  V(S256Select)                    \
  V(S256AndNot)                    \
  V(I64x4Splat)                    \
  V(I32x8Splat)                    \
  V(I16x16Splat)                   \
  V(I8x32Splat)                    \
  V(F64x4Pmin)                     \
  V(F64x4Pmax)                     \
  V(F64x4Splat)                    \
  V(F32x8Splat)                    \
  V(I8x32Shuffle)                  \
  V(F32x8Qfma)                     \
  V(F32x8Qfms)                     \
  V(F64x4Qfma)                     \
  V(F64x4Qfms)                     \
  V(I64x4RelaxedLaneSelect)        \
  V(I32x8RelaxedLaneSelect)        \
  V(I16x16RelaxedLaneSelect)       \
  V(I8x32RelaxedLaneSelect)        \
  V(I32x8DotI8x32I7x32AddS)        \
  V(I16x16DotI8x32I7x32S)          \
  V(F32x8RelaxedMin)               \
  V(F32x8RelaxedMax)               \
  V(F64x4RelaxedMin)               \
  V(F64x4RelaxedMax)               \
  V(I32x8RelaxedTruncF32x8S)       \
  V(I32x8RelaxedTruncF32x8U)

#define VALUE_OP_LIST(V)              \
  COMMON_OP_LIST(V)                   \
  SIMPLIFIED_OP_LIST(V)               \
  MACHINE_OP_LIST(V)                  \
  MACHINE_SIMD128_OP_LIST(V)          \
  IF_WASM(MACHINE_SIMD256_OP_LIST, V) \
  JS_OP_LIST(V)

// The combination of all operators at all levels and the common operators.
#define ALL_OP_LIST(V) \
  CONTROL_OP_LIST(V)   \
  VALUE_OP_LIST(V)

namespace v8 {
namespace internal {
namespace compiler {

// Declare an enumeration with all the opcodes at all levels so that they
// can be globally, uniquely numbered.
class V8_EXPORT_PRIVATE IrOpcode {
 public:
  enum Value {
#define DECLARE_OPCODE(x, ...) k##x,
    ALL_OP_LIST(DECLARE_OPCODE)
#undef DECLARE_OPCODE
        kLast = -1
#define COUNT_OPCODE(...) +1
                ALL_OP_LIST(COUNT_OPCODE)
#undef COUNT_OPCODE
  };

  // Returns the mnemonic name of an opcode.
  static char const* Mnemonic(Value value);

  // Returns true if opcode for common operator.
  static bool IsCommonOpcode(Value value) {
    return kStart <= value && value <= kStaticAssert;
  }

  // Returns true if opcode for control operator.
  static bool IsControlOpcode(Value value) {
    return kStart <= value && value <= kEnd;
  }

  // Returns true if opcode for JavaScript operator.
  static bool IsJsOpcode(Value value) {
    return kJSEqual <= value && value <= kJSDebugger;
  }

  // Returns true if opcode for machine operator.
  static bool IsMachineOpcode(Value value) {
    return kWord32Clz <= value && value <= kTraceInstruction;
  }

  // Returns true iff opcode is a machine-level constant.
  static bool IsMachineConstantOpcode(Value value) {
    switch (value) {
#define CASE(name) \
  case k##name:    \
    return true;
      MACHINE_LEVEL_CONSTANT_OP_LIST(CASE)
#undef CASE
      default:
        return false;
    }
  }

  // Returns true if opcode for constant operator.
  static bool IsConstantOpcode(Value value) {
#define CASE(Name) \
  case k##Name:    \
    return true;
    switch (value) {
      CONSTANT_OP_LIST(CASE);
      default:
        return false;
    }
#undef CASE
    UNREACHABLE();
  }

  static bool IsPhiOpcode(Value value) {
    return value == kPhi || value == kEffectPhi;
  }

  static bool IsMergeOpcode(Value value) {
    return value == kMerge || value == kLoop;
  }

  static bool IsIfProjectionOpcode(Value value) {
    return kIfTrue <= value && value <= kIfDefault;
  }

  // Returns true if opcode terminates control flow in a graph (i.e.
  // respective nodes are expected to have control uses by the graphs {End}
  // node only).
  static bool IsGraphTerminator(Value value) {
    return value == kDeoptimize || value == kReturn || value == kTailCall ||
           value == kTerminate || value == kThrow;
  }

  // Returns true if opcode can be inlined.
  static bool IsInlineeOpcode(Value value) {
    return value == kJSConstruct || value == kJSCall;
  }

  // Returns true if opcode for comparison operator.
  static bool IsComparisonOpcode(Value value) {
#define CASE(Name, ...) \
  case k##Name:         \
    return true;
    switch (value) {
      JS_COMPARE_BINOP_LIST(CASE);
      SIMPLIFIED_COMPARE_BINOP_LIST(CASE);
      MACHINE_COMPARE_BINOP_LIST(CASE);
      default:
        return false;
    }
#undef CASE
    UNREACHABLE();
  }

  static bool IsContextChainExtendingOpcode(Value value) {
    return kJSCreateFunctionContext <= value && value <= kJSCreateBlockContext;
  }

  // These opcode take the feedback vector as an input, and implement
  // feedback-collecting logic in generic lowering.
  static bool IsFeedbackCollectingOpcode(Value value) {
#define CASE(Name, ...) \
  case k##Name:         \
    return true;
    switch (value) {
      JS_ARITH_BINOP_LIST(CASE)
      JS_ARITH_UNOP_LIST(CASE)
      JS_BITWISE_BINOP_LIST(CASE)
      JS_BITWISE_UNOP_LIST(CASE)
      JS_COMPARE_BINOP_LIST(CASE)
      case kJSCall:
      case kJSCallWithArrayLike:
      case kJSCallWithSpread:
      case kJSCloneObject:
      case kJSConstruct:
      case kJSConstructWithArrayLike:
      case kJSConstructWithSpread:
      case kJSCreateEmptyLiteralArray:
      case kJSCreateLiteralArray:
      case kJSCreateLiteralObject:
      case kJSCreateLiteralRegExp:
      case kJSDefineKeyedOwnProperty:
      case kJSForInNext:
      case kJSForInPrepare:
      case kJSGetIterator:
      case kJSGetTemplateObject:
      case kJSHasProperty:
      case kJSInstanceOf:
      case kJSLoadGlobal:
      case kJSLoadNamed:
      case kJSLoadNamedFromSuper:
      case kJSLoadProperty:
      case kJSDefineKeyedOwnPropertyInLiteral:
      case kJSStoreGlobal:
      case kJSStoreInArrayLiteral:
      case kJSSetNamedProperty:
      case kJSDefineNamedOwnProperty:
      case kJSSetKeyedProperty:
        return true;
      default:
        return false;
    }
#undef CASE
    UNREACHABLE();
  }

  static bool IsFeedbackCollectingOpcode(int16_t value) {
    DCHECK(0 <= value && value <= kLast);
    return IsFeedbackCollectingOpcode(static_cast<IrOpcode::Value>(value));
  }

  static bool isAtomicOpOpcode(Value value) {
    switch (value) {
    #define CASE(Name, ...) \
      case k##Name:         \
        return true;
      MACHINE_ATOMIC_OP_LIST(CASE)
      default:
        return false;
    #undef CASE
    }
    UNREACHABLE();
  }

#if V8_ENABLE_WEBASSEMBLY
  static bool IsSimd128Opcode(Value value) {
#define CASE(Name, ...) case k##Name:
    switch (value) {
      MACHINE_SIMD128_OP_LIST(CASE)
      return true;
      default:
        return false;
    }
#undef CASE
    UNREACHABLE();
  }
#endif  // V8_ENABLE_WEBASSEMBLY
};

V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream&, IrOpcode::Value);

}  // namespace compiler
}  // namespace internal
}  // namespace v8

#endif  // V8_COMPILER_OPCODES_H_
```