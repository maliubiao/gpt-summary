Response:
Let's break down the thought process for analyzing this V8 code snippet.

**1. Initial Scan and Keyword Recognition:**

The first step is a quick scan for keywords and patterns. Things that immediately jump out:

* `#define`:  This strongly suggests macro definitions, used for code generation or abstraction.
* `SIMD_`:  This prefix is a huge clue that the code deals with Single Instruction, Multiple Data operations, likely related to vector processing and performance optimizations for parallel computations.
* `Visit...`:  This pattern is very common in compiler infrastructure. It suggests a visitor pattern, where different node types in an intermediate representation of code are handled by specific `Visit` methods.
* `InstructionSelectorT`: This confirms the code is part of the instruction selection phase of a compiler, where high-level operations are translated into machine-specific instructions.
* `x64`:  This explicitly targets the x64 architecture.
* `kV128`, `kV256`, `kL8`, `kL16`, `kL32`, `kL64`:  These look like constants representing vector lengths and lane sizes, further reinforcing the SIMD theme.
* `Emit`:  A very common compiler term indicating the generation of the actual machine instructions.
* `TurbofanAdapter`, `TurboshaftAdapter`: These are likely different compiler pipelines or backends within V8. The code is templated to work with both.

**2. Understanding the Macros:**

The core of this code snippet revolves around the `#define` macros. The key is to understand what each macro does. Let's take `SIMD_BINOP_SSE_AVX_LIST(V)` as an example.

* **Purpose:** It defines a *list* of SIMD binary operations.
* **Mechanism:** It takes a macro `V` as an argument. Inside the definition, it *calls* this macro `V` repeatedly with specific operation names (like `F64x2Add`, `F32x4Add`) and corresponding internal operation codes (`FAdd`).
* **Implication:** This is a code generation technique. Instead of writing the same `Visit` function for each binary operation, they define a generic structure and use a macro to populate it. This reduces code duplication and makes it easier to add new operations.

**3. Connecting Macros to `Visit` Functions:**

The next step is to see how these macros are used. The pattern `VISIT_SIMD_BINOP(Opcode)` shows how the macro expands into `Visit` functions.

* **Example:** When `SIMD_BINOP_SSE_AVX_LIST(VISIT_SIMD_BINOP)` is invoked,  `VISIT_SIMD_BINOP(F64x2Add)` will be generated, and so on. This means there's a `VisitF64x2Add` function, a `VisitF32x4Add` function, etc.

**4. Analyzing the `Visit` Functions:**

Now, let's look at the structure of a typical `Visit` function, like `VisitF64x2Add`.

* **Operand Generation:** `X64OperandGeneratorT<Adapter> g(this);`  This creates an object to help manage operands (registers, memory locations, immediates) for the x64 architecture.
* **Input Access:** `this->input_at(node, 0)`, `this->input_at(node, 1)`, or the turboshaft equivalents like `op.input()`. This retrieves the operands of the current node in the intermediate representation.
* **Instruction Emission:** `Emit(kX64FAdd, ...)`  This is the crucial step where the x64 `FAdd` instruction is generated, along with its operands. The `kX64FAdd` likely represents an internal identifier for the floating-point addition instruction.
* **Register Allocation:** `g.DefineAsRegister(node)` specifies that the result of the operation should be placed in a register. `g.DefineSameAsFirst(node)` is an optimization where the output register is the same as the first input register, potentially saving a move instruction.
* **Immediate Handling:** The code often checks `g.CanBeImmediate(...)` to see if an operand is a constant value that can be directly embedded in the instruction.

**5. Understanding SIMD Concepts:**

The presence of different vector lengths (`kV128`, `kV256`) and lane sizes (`kL8`, `kL16`, etc.) is fundamental to SIMD.

* **Vector Length:** How many data elements are processed in parallel.
* **Lane Size:** The size of each individual data element within the vector (e.g., 32-bit integer, 64-bit float).

The macro names (e.g., `I32x4Add`) clearly indicate the data type (`I` for integer, `F` for float), the lane size (32-bit), and the number of lanes (4).

**6. Distinguishing Turbofan and Turboshaft:**

The code uses templates (`template <typename Adapter>`) and conditional compilation (`if constexpr (Adapter::IsTurboshaft)`) to support different V8 compiler pipelines. The core logic is similar, but the way they access the intermediate representation (`node`) differs.

**7. Identifying Potential Errors and JavaScript Relevance:**

By examining the SIMD operations (addition, subtraction, comparison, etc.), we can see the connection to JavaScript's SIMD API (`Float32x4`, `Int32x4`, etc.). Common programming errors would involve:

* **Incorrect Lane/Vector Sizes:** Trying to operate on vectors with incompatible dimensions.
* **Type Mismatches:**  Performing operations on vectors with the wrong data types.
* **Out-of-Bounds Lane Access:** Trying to extract or replace a lane that doesn't exist.

**8. Synthesizing the Functionality:**

Putting it all together, the code's primary function is instruction selection for SIMD operations on the x64 architecture within the V8 JavaScript engine. It takes high-level SIMD operations from the compiler's intermediate representation and translates them into specific x64 machine instructions, optimizing for different vector lengths and data types, and supporting both Turbofan and Turboshaft compiler pipelines.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Maybe these macros are just for defining constants."  **Correction:**  Realized they are more about *code generation* due to the way they call the `V` macro.
* **Initial thought:** "The `Visit` functions are all doing very different things." **Correction:**  Observed the common pattern of operand generation, input access, and instruction emission, indicating a systematic approach.
* **Initial thought:** "The `Adapter` template is just for different data types." **Correction:** Recognized it's about different compiler pipelines, as the code access to the IR is different.

By following these steps of scanning, keyword analysis, macro decomposition, and understanding the underlying concepts, a clear picture of the code's functionality emerges.
好的，让我们来分析一下这段 C++ 代码（`v8/src/compiler/backend/x64/instruction-selector-x64.cc` 的一部分）。

**功能概括**

这段代码是 V8 JavaScript 引擎中，针对 x64 架构的**指令选择器（Instruction Selector）**的一部分。它的主要功能是将中间表示（IR - Intermediate Representation）中的 SIMD (Single Instruction, Multiple Data) 操作，转换为具体的 x64 汇编指令。

**详细功能分解**

1. **SIMD 指令集的支持:** 代码中定义了大量的宏（例如 `SIMD_BINOP_SSE_AVX_LIST`, `SIMD_UNOP_LIST` 等），这些宏列举了各种 SIMD 指令。这些指令涵盖了不同数据类型（如浮点数、整数）、不同向量长度（128 位、256 位）和不同操作（加法、减法、比较、逻辑运算等）。这表明该文件负责处理 JavaScript 中 SIMD API 对应的底层指令生成。

2. **指令选择逻辑:** 代码中的 `Visit...` 函数（例如 `VisitF64x2Add`, `VisitI32x4Splat`）是指令选择器的核心。每个 `Visit` 函数对应处理一种特定的 IR 节点（代表一个 SIMD 操作）。在这些函数内部，代码会：
   - **获取操作数:**  通过 `this->input_at(node, ...)` 或 Turboshaft 的方式获取当前操作的输入操作数。
   - **生成 x64 指令:** 调用 `Emit` 函数，并传入相应的 x64 指令助记符（例如 `kX64FAdd`, `kX64ISplat`）以及操作数。
   - **处理不同的指令变体:**  根据 AVX (Advanced Vector Extensions) 指令集是否支持，可能会生成不同的指令，以利用更高级的特性提升性能。例如，对于某些二元操作，在支持 AVX 的情况下，可能会使用不修改源操作数的指令。
   - **处理立即数:**  代码会检查操作数是否可以是立即数（编译时常量），并据此选择更优的指令形式。

3. **针对不同编译管道的支持:** 代码使用了模板 `template <typename Adapter>`，并区分了 `TurbofanAdapter` 和 `TurboshaftAdapter`。这表明 V8 内部可能存在不同的编译器管道（Turbofan 和较新的 Turboshaft）。这段代码需要兼容这两种管道，针对不同的管道可能需要采用不同的方式获取 IR 节点的信息。

4. **常量优化:**  例如，`VisitS128Const` 函数会对 128 位常量的特殊情况进行优化。如果常量全为零或全为一，则会使用特定的指令 (`kX64SZero`, `kX64SAllOnes`)，而不是通用的常量加载指令。`Visit...Splat` 系列函数也会对 splat 操作的零常量进行优化。

5. **Lane 操作支持:**  代码中包含了对 SIMD 向量中特定通道（lane）进行操作的指令选择，例如 `VisitF64x2ExtractLane`, `VisitI32x4ReplaceLane`。

**关于文件后缀和 Torque**

你提供的代码片段是以 `.cc` 结尾的，这意味着它是标准的 C++ 源代码文件。如果 `v8/src/compiler/backend/x64/instruction-selector-x64.cc` 以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。Torque 是 V8 自己设计的一种用于编写高性能运行时代码的语言，它类似于 TypeScript，可以编译成 C++。

**与 JavaScript 功能的关系**

这段代码直接关系到 JavaScript 中 **SIMD API** 的性能。当你在 JavaScript 中使用 `Float32x4`, `Int32x4`, `Float64x2` 等类型进行向量化计算时，V8 引擎会将其编译成中间表示，然后由指令选择器将这些中间表示转换成 x64 架构的 SIMD 汇编指令 (例如 SSE, AVX)。

**JavaScript 示例**

```javascript
// 创建两个 Float32x4 类型的 SIMD 向量
const a = Float32x4(1.0, 2.0, 3.0, 4.0);
const b = Float32x4(5.0, 6.0, 7.0, 8.0);

// 执行加法操作
const sum = a.add(b); // 对应代码中的 VisitF32x4Add

// 执行乘法操作
const product = a.mul(b); // 对应代码中的 VisitF32x4Mul

// 提取第一个通道的值
const firstLane = a.x; // 对应代码中的 VisitF32x4ExtractLane

console.log(sum);      // Float32x4: [6, 8, 10, 12]
console.log(product);  // Float32x4: [5, 12, 21, 32]
console.log(firstLane); // 1
```

当 V8 执行这段 JavaScript 代码时，`instruction-selector-x64.cc` 中的代码会被调用，将 `a.add(b)` 这样的操作转换成相应的 x64 加法指令（例如 `paddd` 或 `vaddps`），以实现高效的向量化运算。

**代码逻辑推理和假设输入输出**

假设有一个 IR 节点代表 `Float32x4` 类型的加法操作，输入操作数分别是两个寄存器（例如，分别存储了向量 `[1.0, 2.0, 3.0, 4.0]` 和 `[5.0, 6.0, 7.0, 8.0]`）。

**假设输入（IR 节点）：**

- 操作类型: `Float32x4Add`
- 输入 0: 寄存器 R1 (包含 `[1.0, 2.0, 3.0, 4.0]`)
- 输入 1: 寄存器 R2 (包含 `[5.0, 6.0, 7.0, 8.0]`)

**可能输出（x64 汇编指令）：**

```assembly
vaddps xmm0, xmm1, xmm2  ; 如果支持 AVX，且定义输出寄存器为 xmm0，输入寄存器为 xmm1, xmm2
```

或者，如果不支持 AVX：

```assembly
movaps xmm0, xmm1        ; 将第一个输入复制到输出寄存器
addps xmm0, xmm2         ; 将第二个输入加到输出寄存器
```

**用户常见的编程错误**

1. **类型不匹配:**  尝试对不同类型的 SIMD 向量进行操作，例如将 `Float32x4` 和 `Int32x4` 相加。V8 的类型检查会在早期发现这类错误，但理解底层的指令选择有助于理解为什么这种操作是非法的。

   ```javascript
   const floatVec = Float32x4(1, 2, 3, 4);
   const intVec = Int32x4(5, 6, 7, 8);
   // 错误：不能直接将 Float32x4 和 Int32x4 相加
   // const result = floatVec.add(intVec);
   ```

2. **向量长度不匹配:**  虽然这段代码主要关注向量操作，但在涉及混合标量和向量操作时，可能会出现概念上的混淆。例如，尝试将一个标量直接加到一个 SIMD 向量的所有通道上，需要使用 `splat` 操作先将标量扩展成向量。

   ```javascript
   const vec = Float32x4(1, 2, 3, 4);
   const scalar = 10;
   // 错误：不能直接将标量加到向量
   // const result = vec.add(scalar);

   // 正确的做法是先将标量扩展成向量
   const scalarVec = Float32x4.splat(scalar);
   const result = vec.add(scalarVec);
   ```

3. **误解 Lane 操作:**  不正确地使用 `extractLane` 或 `replaceLane`，例如访问超出向量边界的 Lane 索引。

   ```javascript
   const vec = Float32x4(1, 2, 3, 4);
   // 错误：Float32x4 只有 4 个 Lane，索引从 0 到 3
   // const value = vec.extractLane(4);
   ```

**第 8 部分，共 10 部分的功能归纳**

作为第 8 部分，并且代码内容主要集中在 SIMD 指令的选择上，我们可以推断这一部分主要负责处理 V8 编译器后端中，将 **SIMD 相关的中间表示转换为 x64 架构的具体机器指令** 的任务。它确保了 JavaScript 中 SIMD API 的高效执行。之前的章节可能涉及了更通用的指令选择或其他后端处理，而后续章节可能涉及代码的最终生成、优化或其他架构的支持。

总而言之，`v8/src/compiler/backend/x64/instruction-selector-x64.cc` 的这一部分是 V8 引擎中至关重要的组件，它直接影响了 JavaScript 中 SIMD 代码的执行效率，体现了 V8 在性能优化方面的努力。

### 提示词
```
这是目录为v8/src/compiler/backend/x64/instruction-selector-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/x64/instruction-selector-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
, FNe, kL32, kV128)                              \
  V(F32x8Ne, FNe, kL32, kV256)                              \
  V(F64x4Ne, FNe, kL64, kV256)                              \
  V(I32x4GtS, IGtS, kL32, kV128)                            \
  V(I16x8GtS, IGtS, kL16, kV128)                            \
  V(I8x16GtS, IGtS, kL8, kV128)                             \
  V(I8x32GtS, IGtS, kL8, kV256)                             \
  V(I16x16GtS, IGtS, kL16, kV256)                           \
  V(I32x8GtS, IGtS, kL32, kV256)                            \
  V(I64x4GtS, IGtS, kL64, kV256)                            \
  V(F64x2Lt, FLt, kL64, kV128)                              \
  V(F32x4Lt, FLt, kL32, kV128)                              \
  V(F64x4Lt, FLt, kL64, kV256)                              \
  V(F32x8Lt, FLt, kL32, kV256)                              \
  V(F64x2Le, FLe, kL64, kV128)                              \
  V(F32x4Le, FLe, kL32, kV128)                              \
  V(F64x4Le, FLe, kL64, kV256)                              \
  V(F32x8Le, FLe, kL32, kV256)                              \
  V(I32x4MinS, IMinS, kL32, kV128)                          \
  V(I16x8MinS, IMinS, kL16, kV128)                          \
  V(I8x16MinS, IMinS, kL8, kV128)                           \
  V(I32x4MinU, IMinU, kL32, kV128)                          \
  V(I16x8MinU, IMinU, kL16, kV128)                          \
  V(I8x16MinU, IMinU, kL8, kV128)                           \
  V(I32x4MaxS, IMaxS, kL32, kV128)                          \
  V(I16x8MaxS, IMaxS, kL16, kV128)                          \
  V(I8x16MaxS, IMaxS, kL8, kV128)                           \
  V(I32x4MaxU, IMaxU, kL32, kV128)                          \
  V(I16x8MaxU, IMaxU, kL16, kV128)                          \
  V(I8x16MaxU, IMaxU, kL8, kV128)                           \
  V(I32x8MinS, IMinS, kL32, kV256)                          \
  V(I16x16MinS, IMinS, kL16, kV256)                         \
  V(I8x32MinS, IMinS, kL8, kV256)                           \
  V(I32x8MinU, IMinU, kL32, kV256)                          \
  V(I16x16MinU, IMinU, kL16, kV256)                         \
  V(I8x32MinU, IMinU, kL8, kV256)                           \
  V(I32x8MaxS, IMaxS, kL32, kV256)                          \
  V(I16x16MaxS, IMaxS, kL16, kV256)                         \
  V(I8x32MaxS, IMaxS, kL8, kV256)                           \
  V(I32x8MaxU, IMaxU, kL32, kV256)                          \
  V(I16x16MaxU, IMaxU, kL16, kV256)                         \
  V(I8x32MaxU, IMaxU, kL8, kV256)                           \
  V(I16x8RoundingAverageU, IRoundingAverageU, kL16, kV128)  \
  V(I16x16RoundingAverageU, IRoundingAverageU, kL16, kV256) \
  V(I8x16RoundingAverageU, IRoundingAverageU, kL8, kV128)   \
  V(I8x32RoundingAverageU, IRoundingAverageU, kL8, kV256)   \
  V(S128And, SAnd, kL8, kV128)                              \
  V(S256And, SAnd, kL8, kV256)                              \
  V(S128Or, SOr, kL8, kV128)                                \
  V(S256Or, SOr, kL8, kV256)                                \
  V(S128Xor, SXor, kL8, kV128)                              \
  V(S256Xor, SXor, kL8, kV256)

#define SIMD_F16x8_BINOP_LIST(V) \
  V(F16x8Add, FAdd)              \
  V(F16x8Sub, FSub)              \
  V(F16x8Mul, FMul)              \
  V(F16x8Div, FDiv)              \
  V(F16x8Min, FMin)              \
  V(F16x8Max, FMax)              \
  V(F16x8Eq, FEq)                \
  V(F16x8Ne, FNe)                \
  V(F16x8Lt, FLt)                \
  V(F16x8Le, FLe)

#define SIMD_BINOP_LANE_SIZE_VECTOR_LENGTH_LIST(V) \
  V(F64x2Min, FMin, kL64, kV128)                   \
  V(F32x4Min, FMin, kL32, kV128)                   \
  V(F64x4Min, FMin, kL64, kV256)                   \
  V(F32x8Min, FMin, kL32, kV256)                   \
  V(F64x2Max, FMax, kL64, kV128)                   \
  V(F32x4Max, FMax, kL32, kV128)                   \
  V(F64x4Max, FMax, kL64, kV256)                   \
  V(F32x8Max, FMax, kL32, kV256)                   \
  V(I64x2Ne, INe, kL64, kV128)                     \
  V(I32x4Ne, INe, kL32, kV128)                     \
  V(I16x8Ne, INe, kL16, kV128)                     \
  V(I8x16Ne, INe, kL8, kV128)                      \
  V(I64x4Ne, INe, kL64, kV256)                     \
  V(I32x8Ne, INe, kL32, kV256)                     \
  V(I16x16Ne, INe, kL16, kV256)                    \
  V(I8x32Ne, INe, kL8, kV256)                      \
  V(I32x4GtU, IGtU, kL32, kV128)                   \
  V(I16x8GtU, IGtU, kL16, kV128)                   \
  V(I8x16GtU, IGtU, kL8, kV128)                    \
  V(I32x8GtU, IGtU, kL32, kV256)                   \
  V(I16x16GtU, IGtU, kL16, kV256)                  \
  V(I8x32GtU, IGtU, kL8, kV256)                    \
  V(I32x4GeS, IGeS, kL32, kV128)                   \
  V(I16x8GeS, IGeS, kL16, kV128)                   \
  V(I8x16GeS, IGeS, kL8, kV128)                    \
  V(I32x8GeS, IGeS, kL32, kV256)                   \
  V(I16x16GeS, IGeS, kL16, kV256)                  \
  V(I8x32GeS, IGeS, kL8, kV256)                    \
  V(I32x4GeU, IGeU, kL32, kV128)                   \
  V(I16x8GeU, IGeU, kL16, kV128)                   \
  V(I8x16GeU, IGeU, kL8, kV128)                    \
  V(I32x8GeU, IGeU, kL32, kV256)                   \
  V(I16x16GeU, IGeU, kL16, kV256)                  \
  V(I8x32GeU, IGeU, kL8, kV256)

#define SIMD_UNOP_LIST(V)   \
  V(F64x2ConvertLowI32x4S)  \
  V(F64x4ConvertI32x4S)     \
  V(F32x4SConvertI32x4)     \
  V(F32x8SConvertI32x8)     \
  V(F32x4DemoteF64x2Zero)   \
  V(F32x4DemoteF64x4)       \
  V(I16x8SConvertF16x8)     \
  V(I16x8UConvertF16x8)     \
  V(F16x8SConvertI16x8)     \
  V(F16x8UConvertI16x8)     \
  V(F16x8DemoteF32x4Zero)   \
  V(F32x4PromoteLowF16x8)   \
  V(I64x2SConvertI32x4Low)  \
  V(I64x2SConvertI32x4High) \
  V(I64x4SConvertI32x4)     \
  V(I64x2UConvertI32x4Low)  \
  V(I64x2UConvertI32x4High) \
  V(I64x4UConvertI32x4)     \
  V(I32x4SConvertI16x8Low)  \
  V(I32x4SConvertI16x8High) \
  V(I32x8SConvertI16x8)     \
  V(I32x4UConvertI16x8Low)  \
  V(I32x4UConvertI16x8High) \
  V(I32x8UConvertI16x8)     \
  V(I16x8SConvertI8x16Low)  \
  V(I16x8SConvertI8x16High) \
  V(I16x16SConvertI8x16)    \
  V(I16x8UConvertI8x16Low)  \
  V(I16x8UConvertI8x16High) \
  V(I16x16UConvertI8x16)

#define SIMD_UNOP_LANE_SIZE_VECTOR_LENGTH_LIST(V) \
  V(F32x4Abs, FAbs, kL32, kV128)                  \
  V(I32x4Abs, IAbs, kL32, kV128)                  \
  V(F16x8Abs, FAbs, kL16, kV128)                  \
  V(I16x8Abs, IAbs, kL16, kV128)                  \
  V(I8x16Abs, IAbs, kL8, kV128)                   \
  V(F32x4Neg, FNeg, kL32, kV128)                  \
  V(I32x4Neg, INeg, kL32, kV128)                  \
  V(F16x8Neg, FNeg, kL16, kV128)                  \
  V(I16x8Neg, INeg, kL16, kV128)                  \
  V(I8x16Neg, INeg, kL8, kV128)                   \
  V(F64x2Sqrt, FSqrt, kL64, kV128)                \
  V(F32x4Sqrt, FSqrt, kL32, kV128)                \
  V(F16x8Sqrt, FSqrt, kL16, kV128)                \
  V(I64x2BitMask, IBitMask, kL64, kV128)          \
  V(I32x4BitMask, IBitMask, kL32, kV128)          \
  V(I16x8BitMask, IBitMask, kL16, kV128)          \
  V(I8x16BitMask, IBitMask, kL8, kV128)           \
  V(I64x2AllTrue, IAllTrue, kL64, kV128)          \
  V(I32x4AllTrue, IAllTrue, kL32, kV128)          \
  V(I16x8AllTrue, IAllTrue, kL16, kV128)          \
  V(I8x16AllTrue, IAllTrue, kL8, kV128)           \
  V(S128Not, SNot, kL8, kV128)                    \
  V(F64x4Abs, FAbs, kL64, kV256)                  \
  V(F32x8Abs, FAbs, kL32, kV256)                  \
  V(I32x8Abs, IAbs, kL32, kV256)                  \
  V(I16x16Abs, IAbs, kL16, kV256)                 \
  V(I8x32Abs, IAbs, kL8, kV256)                   \
  V(F64x4Neg, FNeg, kL64, kV256)                  \
  V(F32x8Neg, FNeg, kL32, kV256)                  \
  V(I32x8Neg, INeg, kL32, kV256)                  \
  V(I16x16Neg, INeg, kL16, kV256)                 \
  V(I8x32Neg, INeg, kL8, kV256)                   \
  V(F64x4Sqrt, FSqrt, kL64, kV256)                \
  V(F32x8Sqrt, FSqrt, kL32, kV256)                \
  V(S256Not, SNot, kL8, kV256)

#define SIMD_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES(V) \
  V(I64x2Shl, IShl, kL64, kV128)                      \
  V(I32x4Shl, IShl, kL32, kV128)                      \
  V(I16x8Shl, IShl, kL16, kV128)                      \
  V(I32x4ShrS, IShrS, kL32, kV128)                    \
  V(I16x8ShrS, IShrS, kL16, kV128)                    \
  V(I64x2ShrU, IShrU, kL64, kV128)                    \
  V(I32x4ShrU, IShrU, kL32, kV128)                    \
  V(I16x8ShrU, IShrU, kL16, kV128)                    \
  V(I64x4Shl, IShl, kL64, kV256)                      \
  V(I32x8Shl, IShl, kL32, kV256)                      \
  V(I16x16Shl, IShl, kL16, kV256)                     \
  V(I32x8ShrS, IShrS, kL32, kV256)                    \
  V(I16x16ShrS, IShrS, kL16, kV256)                   \
  V(I64x4ShrU, IShrU, kL64, kV256)                    \
  V(I32x8ShrU, IShrU, kL32, kV256)                    \
  V(I16x16ShrU, IShrU, kL16, kV256)

#define SIMD_NARROW_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES(V) \
  V(I8x16Shl, IShl, kL8, kV128)                              \
  V(I8x16ShrS, IShrS, kL8, kV128)                            \
  V(I8x16ShrU, IShrU, kL8, kV128)

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Const(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  static const int kUint32Immediates = kSimd128Size / sizeof(uint32_t);
  uint32_t val[kUint32Immediates];
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128ConstantOp& constant =
        this->Get(node).template Cast<turboshaft::Simd128ConstantOp>();
    memcpy(val, constant.value, kSimd128Size);
  } else {
    memcpy(val, S128ImmediateParameterOf(node->op()).data(), kSimd128Size);
  }
  // If all bytes are zeros or ones, avoid emitting code for generic constants
  bool all_zeros = !(val[0] || val[1] || val[2] || val[3]);
  bool all_ones = val[0] == UINT32_MAX && val[1] == UINT32_MAX &&
                  val[2] == UINT32_MAX && val[3] == UINT32_MAX;
  InstructionOperand dst = g.DefineAsRegister(node);
  if (all_zeros) {
    Emit(kX64SZero | VectorLengthField::encode(kV128), dst);
  } else if (all_ones) {
    Emit(kX64SAllOnes | VectorLengthField::encode(kV128), dst);
  } else {
    Emit(kX64S128Const, dst, g.UseImmediate(val[0]), g.UseImmediate(val[1]),
         g.UseImmediate(val[2]), g.UseImmediate(val[3]));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Zero(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  Emit(kX64SZero | VectorLengthField::encode(kV128), g.DefineAsRegister(node));
}
// Name, LaneSize, VectorLength
#define SIMD_INT_TYPES_FOR_SPLAT(V) \
  V(I64x2, kL64, kV128)             \
  V(I32x4, kL32, kV128)             \
  V(I16x8, kL16, kV128)             \
  V(I8x16, kL8, kV128)              \
  V(I64x4, kL64, kV256)             \
  V(I32x8, kL32, kV256)             \
  V(I16x16, kL16, kV256)            \
  V(I8x32, kL8, kV256)

// Splat with an optimization for const 0.
#define VISIT_INT_SIMD_SPLAT(Type, LaneSize, VectorLength)                   \
  template <typename Adapter>                                                \
  void InstructionSelectorT<Adapter>::Visit##Type##Splat(node_t node) {      \
    X64OperandGeneratorT<Adapter> g(this);                                   \
    DCHECK_EQ(this->value_input_count(node), 1);                             \
    node_t input = this->input_at(node, 0);                                  \
    if (g.CanBeImmediate(input) && g.GetImmediateIntegerValue(input) == 0) { \
      Emit(kX64SZero | VectorLengthField::encode(VectorLength),              \
           g.DefineAsRegister(node));                                        \
    } else {                                                                 \
      Emit(kX64ISplat | LaneSizeField::encode(LaneSize) |                    \
               VectorLengthField::encode(VectorLength),                      \
           g.DefineAsRegister(node), g.Use(input));                          \
    }                                                                        \
  }
SIMD_INT_TYPES_FOR_SPLAT(VISIT_INT_SIMD_SPLAT)
#undef VISIT_INT_SIMD_SPLAT
#undef SIMD_INT_TYPES_FOR_SPLAT

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Splat(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64FSplat | LaneSizeField::encode(kL64) |
           VectorLengthField::encode(kV128),
       g.DefineAsRegister(node), g.Use(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Splat(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64FSplat | LaneSizeField::encode(kL32) |
           VectorLengthField::encode(kV128),
       g.DefineAsRegister(node), g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8Splat(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64FSplat | LaneSizeField::encode(kL16) |
           VectorLengthField::encode(kV128),
       g.DefineAsRegister(node), g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x4Splat(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64FSplat | LaneSizeField::encode(kL64) |
           VectorLengthField::encode(kV256),
       g.DefineAsRegister(node), g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x8Splat(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64FSplat | LaneSizeField::encode(kL32) |
           VectorLengthField::encode(kV256),
       g.DefineAsRegister(node), g.UseRegister(this->input_at(node, 0)));
}

#define SIMD_VISIT_EXTRACT_LANE(IF, Type, Sign, LaneSize, VectorLength)        \
  template <>                                                                  \
  void InstructionSelectorT<TurbofanAdapter>::Visit##Type##ExtractLane##Sign(  \
      node_t node) {                                                           \
    X64OperandGeneratorT<TurbofanAdapter> g(this);                             \
    int32_t lane = OpParameter<int32_t>(node->op());                           \
    Emit(kX64##IF##ExtractLane##Sign | LaneSizeField::encode(LaneSize) |       \
             VectorLengthField::encode(VectorLength),                          \
         g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)),            \
         g.UseImmediate(lane));                                                \
  }                                                                            \
  template <>                                                                  \
  void                                                                         \
      InstructionSelectorT<TurboshaftAdapter>::Visit##Type##ExtractLane##Sign( \
          node_t node) {                                                       \
    X64OperandGeneratorT<TurboshaftAdapter> g(this);                           \
    const turboshaft::Simd128ExtractLaneOp& op =                               \
        this->Get(node).template Cast<turboshaft::Simd128ExtractLaneOp>();     \
    int32_t lane = op.lane;                                                    \
    Emit(kX64##IF##ExtractLane##Sign | LaneSizeField::encode(LaneSize) |       \
             VectorLengthField::encode(VectorLength),                          \
         g.DefineAsRegister(node), g.UseRegister(op.input()),                  \
         g.UseImmediate(lane));                                                \
  }

SIMD_VISIT_EXTRACT_LANE(F, F64x2, , kL64, kV128)
SIMD_VISIT_EXTRACT_LANE(F, F32x4, , kL32, kV128)
SIMD_VISIT_EXTRACT_LANE(F, F16x8, , kL16, kV128)
SIMD_VISIT_EXTRACT_LANE(I, I64x2, , kL64, kV128)
SIMD_VISIT_EXTRACT_LANE(I, I32x4, , kL32, kV128)
SIMD_VISIT_EXTRACT_LANE(I, I16x8, S, kL16, kV128)
SIMD_VISIT_EXTRACT_LANE(I, I8x16, S, kL8, kV128)
#undef SIMD_VISIT_EXTRACT_LANE

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ExtractLaneU(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128ExtractLaneOp& op =
        this->Get(node).template Cast<turboshaft::Simd128ExtractLaneOp>();
    Emit(kX64Pextrw, g.DefineAsRegister(node), g.UseRegister(op.input()),
         g.UseImmediate(static_cast<int32_t>(op.lane)));

  } else {
    int32_t lane = OpParameter<int32_t>(node->op());
    Emit(kX64Pextrw, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)),
         g.UseImmediate(lane));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16ExtractLaneU(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128ExtractLaneOp& op =
        this->Get(node).template Cast<turboshaft::Simd128ExtractLaneOp>();
    Emit(kX64Pextrb, g.DefineAsRegister(node), g.UseRegister(op.input()),
         g.UseImmediate(op.lane));

  } else {
    int32_t lane = OpParameter<int32_t>(node->op());
    Emit(kX64Pextrb, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)),
         g.UseImmediate(lane));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8ReplaceLane(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    auto& op =
        this->Get(node).template Cast<turboshaft::Simd128ReplaceLaneOp>();
    Emit(kX64FReplaceLane | LaneSizeField::encode(kL16) |
             VectorLengthField::encode(kV128),
         g.DefineSameAsFirst(node), g.UseRegister(op.into()),
         g.UseImmediate(op.lane), g.Use(op.new_lane()));

  } else {
    int32_t lane = OpParameter<int32_t>(node->op());
    Emit(kX64FReplaceLane | LaneSizeField::encode(kL16) |
             VectorLengthField::encode(kV128),
         g.DefineSameAsFirst(node), g.UseRegister(node->InputAt(0)),
         g.UseImmediate(lane), g.Use(node->InputAt(1)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4ReplaceLane(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128ReplaceLaneOp& op =
        this->Get(node).template Cast<turboshaft::Simd128ReplaceLaneOp>();
    Emit(kX64FReplaceLane | LaneSizeField::encode(kL32) |
             VectorLengthField::encode(kV128),
         g.DefineSameAsFirst(node), g.UseRegister(op.into()),
         g.UseImmediate(op.lane), g.Use(op.new_lane()));

  } else {
    int32_t lane = OpParameter<int32_t>(node->op());
    Emit(kX64FReplaceLane | LaneSizeField::encode(kL32) |
             VectorLengthField::encode(kV128),
         g.DefineSameAsFirst(node), g.UseRegister(node->InputAt(0)),
         g.UseImmediate(lane), g.Use(node->InputAt(1)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2ReplaceLane(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  // When no-AVX, define dst == src to save a move.
  InstructionOperand dst =
      IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node);
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128ReplaceLaneOp& op =
        this->Get(node).template Cast<turboshaft::Simd128ReplaceLaneOp>();
    Emit(kX64FReplaceLane | LaneSizeField::encode(kL64) |
             VectorLengthField::encode(kV128),
         dst, g.UseRegister(op.into()), g.UseImmediate(op.lane),
         g.UseRegister(op.new_lane()));

  } else {
    int32_t lane = OpParameter<int32_t>(node->op());
    Emit(kX64FReplaceLane | LaneSizeField::encode(kL64) |
             VectorLengthField::encode(kV128),
         dst, g.UseRegister(node->InputAt(0)), g.UseImmediate(lane),
         g.UseRegister(node->InputAt(1)));
  }
}

#define VISIT_SIMD_REPLACE_LANE(TYPE, OPCODE)                                 \
  template <typename Adapter>                                                 \
  void InstructionSelectorT<Adapter>::Visit##TYPE##ReplaceLane(node_t node) { \
    X64OperandGeneratorT<Adapter> g(this);                                    \
    if constexpr (Adapter::IsTurboshaft) {                                    \
      const turboshaft::Simd128ReplaceLaneOp& op =                            \
          this->Get(node).template Cast<turboshaft::Simd128ReplaceLaneOp>();  \
      Emit(OPCODE, g.DefineAsRegister(node), g.UseRegister(op.into()),        \
           g.UseImmediate(op.lane), g.Use(op.new_lane()));                    \
    } else {                                                                  \
      int32_t lane = OpParameter<int32_t>(node->op());                        \
      Emit(OPCODE, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)), \
           g.UseImmediate(lane), g.Use(node->InputAt(1)));                    \
    }                                                                         \
  }

#define SIMD_TYPES_FOR_REPLACE_LANE(V) \
  V(I64x2, kX64Pinsrq)                 \
  V(I32x4, kX64Pinsrd)                 \
  V(I16x8, kX64Pinsrw)                 \
  V(I8x16, kX64Pinsrb)

SIMD_TYPES_FOR_REPLACE_LANE(VISIT_SIMD_REPLACE_LANE)
#undef SIMD_TYPES_FOR_REPLACE_LANE
#undef VISIT_SIMD_REPLACE_LANE

#define VISIT_SIMD_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES(                  \
    Name, Opcode, LaneSize, VectorLength)                                  \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) {           \
    X64OperandGeneratorT<Adapter> g(this);                                 \
    DCHECK_EQ(this->value_input_count(node), 2);                           \
    InstructionOperand dst = IsSupported(AVX) ? g.DefineAsRegister(node)   \
                                              : g.DefineSameAsFirst(node); \
    if (g.CanBeImmediate(this->input_at(node, 1))) {                       \
      Emit(kX64##Opcode | LaneSizeField::encode(LaneSize) |                \
               VectorLengthField::encode(VectorLength),                    \
           dst, g.UseRegister(this->input_at(node, 0)),                    \
           g.UseImmediate(this->input_at(node, 1)));                       \
    } else {                                                               \
      Emit(kX64##Opcode | LaneSizeField::encode(LaneSize) |                \
               VectorLengthField::encode(VectorLength),                    \
           dst, g.UseRegister(this->input_at(node, 0)),                    \
           g.UseRegister(this->input_at(node, 1)));                        \
    }                                                                      \
  }
SIMD_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES(
    VISIT_SIMD_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES)

#undef VISIT_SIMD_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES
#undef SIMD_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES

#define VISIT_SIMD_NARROW_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES(            \
    Name, Opcode, LaneSize, VectorLength)                                   \
  template <typename Adapter>                                               \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) {            \
    X64OperandGeneratorT<Adapter> g(this);                                  \
    DCHECK_EQ(this->value_input_count(node), 2);                            \
    InstructionOperand output =                                             \
        IsSupported(AVX) ? g.UseRegister(node) : g.DefineSameAsFirst(node); \
    if (g.CanBeImmediate(this->input_at(node, 1))) {                        \
      Emit(kX64##Opcode | LaneSizeField::encode(LaneSize) |                 \
               VectorLengthField::encode(VectorLength),                     \
           output, g.UseRegister(this->input_at(node, 0)),                  \
           g.UseImmediate(this->input_at(node, 1)));                        \
    } else {                                                                \
      InstructionOperand temps[] = {g.TempSimd128Register()};               \
      Emit(kX64##Opcode | LaneSizeField::encode(LaneSize) |                 \
               VectorLengthField::encode(VectorLength),                     \
           output, g.UseUniqueRegister(this->input_at(node, 0)),            \
           g.UseUniqueRegister(this->input_at(node, 1)), arraysize(temps),  \
           temps);                                                          \
    }                                                                       \
  }
SIMD_NARROW_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES(
    VISIT_SIMD_NARROW_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES)
#undef VISIT_SIMD_NARROW_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES
#undef SIMD_NARROW_SHIFT_LANE_SIZE_VECTOR_LENGTH_OPCODES

#define VISIT_SIMD_UNOP(Opcode)                                    \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    X64OperandGeneratorT<Adapter> g(this);                         \
    DCHECK_EQ(this->value_input_count(node), 1);                   \
    Emit(kX64##Opcode, g.DefineAsRegister(node),                   \
         g.UseRegister(this->input_at(node, 0)));                  \
  }
SIMD_UNOP_LIST(VISIT_SIMD_UNOP)
#undef VISIT_SIMD_UNOP
#undef SIMD_UNOP_LIST

#define VISIT_SIMD_UNOP_LANE_SIZE_VECTOR_LENGTH(Name, Opcode, LaneSize,     \
                                                VectorLength)               \
  template <typename Adapter>                                               \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) {            \
    X64OperandGeneratorT<Adapter> g(this);                                  \
    DCHECK_EQ(this->value_input_count(node), 1);                            \
    Emit(kX64##Opcode | LaneSizeField::encode(LaneSize) |                   \
             VectorLengthField::encode(VectorLength),                       \
         g.DefineAsRegister(node), g.UseRegister(this->input_at(node, 0))); \
  }

SIMD_UNOP_LANE_SIZE_VECTOR_LENGTH_LIST(VISIT_SIMD_UNOP_LANE_SIZE_VECTOR_LENGTH)

#undef VISIT_SIMD_UNOP_LANE_SIZE_VECTOR_LENGTH
#undef SIMD_UNOP_LANE_SIZE_VECTOR_LENGTH_LIST

#define VISIT_SIMD_BINOP_LANE_SIZE_VECTOR_LENGTH(Name, Opcode, LaneSize,    \
                                                 VectorLength)              \
  template <typename Adapter>                                               \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) {            \
    X64OperandGeneratorT<Adapter> g(this);                                  \
    DCHECK_EQ(this->value_input_count(node), 2);                            \
    Emit(kX64##Opcode | LaneSizeField::encode(LaneSize) |                   \
             VectorLengthField::encode(VectorLength),                       \
         g.DefineSameAsFirst(node), g.UseRegister(this->input_at(node, 0)), \
         g.UseRegister(this->input_at(node, 1)));                           \
  }

SIMD_BINOP_LANE_SIZE_VECTOR_LENGTH_LIST(
    VISIT_SIMD_BINOP_LANE_SIZE_VECTOR_LENGTH)

#undef VISIT_SIMD_BINOP_LANE_SIZE_VECTOR_LENGTH
#undef SIMD_BINOP_LANE_SIZE_VECTOR_LENGTH_LIST

#define VISIT_SIMD_BINOP(Opcode)                                   \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    X64OperandGeneratorT<Adapter> g(this);                         \
    DCHECK_EQ(this->value_input_count(node), 2);                   \
    if (IsSupported(AVX)) {                                        \
      Emit(kX64##Opcode, g.DefineAsRegister(node),                 \
           g.UseRegister(this->input_at(node, 0)),                 \
           g.UseRegister(this->input_at(node, 1)));                \
    } else {                                                       \
      Emit(kX64##Opcode, g.DefineSameAsFirst(node),                \
           g.UseRegister(this->input_at(node, 0)),                 \
           g.UseRegister(this->input_at(node, 1)));                \
    }                                                              \
  }

SIMD_BINOP_SSE_AVX_LIST(VISIT_SIMD_BINOP)
#undef VISIT_SIMD_BINOP
#undef SIMD_BINOP_SSE_AVX_LIST

#define VISIT_SIMD_BINOP_LANE_SIZE_VECTOR_LENGTH(Name, Opcode, LaneSize,      \
                                                 VectorLength)                \
  template <typename Adapter>                                                 \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) {              \
    X64OperandGeneratorT<Adapter> g(this);                                    \
    DCHECK_EQ(this->value_input_count(node), 2);                              \
    if (IsSupported(AVX)) {                                                   \
      Emit(kX64##Opcode | LaneSizeField::encode(LaneSize) |                   \
               VectorLengthField::encode(VectorLength),                       \
           g.DefineAsRegister(node), g.UseRegister(this->input_at(node, 0)),  \
           g.UseRegister(this->input_at(node, 1)));                           \
    } else {                                                                  \
      Emit(kX64##Opcode | LaneSizeField::encode(LaneSize) |                   \
               VectorLengthField::encode(VectorLength),                       \
           g.DefineSameAsFirst(node), g.UseRegister(this->input_at(node, 0)), \
           g.UseRegister(this->input_at(node, 1)));                           \
    }                                                                         \
  }

SIMD_BINOP_SSE_AVX_LANE_SIZE_VECTOR_LENGTH_LIST(
    VISIT_SIMD_BINOP_LANE_SIZE_VECTOR_LENGTH)
#undef VISIT_SIMD_BINOP_LANE_SIZE_VECTOR_LENGTH
#undef SIMD_BINOP_SSE_AVX_LANE_SIZE_VECTOR_LENGTH_LIST

#define VISIT_SIMD_F16x8_BINOP(Name, Opcode)                               \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) {           \
    X64OperandGeneratorT<Adapter> g(this);                                 \
    DCHECK_EQ(this->value_input_count(node), 2);                           \
    InstructionOperand temps[] = {g.TempSimd256Register(),                 \
                                  g.TempSimd256Register()};                \
    size_t temp_count = arraysize(temps);                                  \
    Emit(kX64##Opcode | LaneSizeField::encode(kL16) |                      \
             VectorLengthField::encode(kV128),                             \
         g.DefineAsRegister(node),                                         \
         g.UseUniqueRegister(this->input_at(node, 0)),                     \
         g.UseUniqueRegister(this->input_at(node, 1)), temp_count, temps); \
  }

SIMD_F16x8_BINOP_LIST(VISIT_SIMD_F16x8_BINOP)
#undef VISIT_SIMD_F16x8_BINOP
#undef SIMD_F16x8_BINOP_LIST

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitV128AnyTrue(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64V128AnyTrue, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)));
}

namespace {

static bool IsV128ZeroConst(InstructionSelectorT<TurbofanAdapter>* selector,
                            Node* node) {
  if (node->opcode() == IrOpcode::kS128Zero) {
    return true;
  }
  // If the node is a V128 const, check all the elements
  auto m = V128ConstMatcher(node);
  if (m.HasResolvedValue()) {
    auto imms = m.ResolvedValue().immediate();
    return std::all_of(imms.begin(), imms.end(), [](auto i) { return i == 0; });
  }
  return false;
}

static bool IsV128ZeroConst(InstructionSelectorT<TurboshaftAdapter>* selector,
                            turboshaft::OpIndex node) {
  const turboshaft::Operation& op = selector->Get(node);
  if (auto constant = op.TryCast<turboshaft::Simd128ConstantOp>()) {
    return constant->IsZero();
  }
  return false;
}

static bool MatchSimd128Constant(
    InstructionSelectorT<TurbofanAdapter>* selector, Node* node,
    std::array<uint8_t, kSimd128Size>* constant) {
  DCHECK_NOT_NULL(constant);
  auto m = V128ConstMatcher(node);
  if (m.HasResolvedValue()) {
    // If the indices vector is a const, check if they are in range, or if the
    // top bit is set, then we can avoid th
```