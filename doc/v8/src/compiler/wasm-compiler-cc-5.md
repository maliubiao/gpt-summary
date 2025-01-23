Response:
Let's break down the thought process for analyzing this V8 code snippet.

**1. Initial Understanding and Context:**

* **File Location:** The first crucial piece of information is `v8/src/compiler/wasm-compiler.cc`. This tells us we're dealing with the WebAssembly compiler within the V8 JavaScript engine. This immediately suggests the code is responsible for translating WebAssembly bytecode into machine code.
* **Filename Extension:** The prompt specifically mentions checking for `.tq`. Since it's `.cc`, we know it's standard C++ code, not Torque (V8's domain-specific language for built-ins). This eliminates one potential source of complexity.
* **Section Number:**  "Part 6 of 12" indicates this is a component of a larger file, likely focusing on a specific stage or aspect of the WebAssembly compilation process.

**2. High-Level Code Overview (Skimming):**

* **Class Name:** The presence of `WasmGraphBuilder` strongly suggests this code is involved in building an intermediate representation of the WebAssembly code, likely a graph-based representation suitable for further optimization and code generation.
* **Key Concepts:**  Terms like `Signature`, `MachineRepresentation`, `LowerInt64`, `BigInt`, `Builtin`, `SimdOp`, and various WASM opcode names jump out. These provide clues about the functionalities being implemented:
    * **Signatures:**  Dealing with function types and their parameters.
    * **MachineRepresentation:**  Mapping WASM types to low-level machine types (e.g., 32-bit vs. 64-bit integers, tagged values).
    * **Lowering:**  Transforming higher-level operations into lower-level machine instructions.
    * **BigInt:** Handling 64-bit integers in JavaScript.
    * **Builtin:** Calling pre-compiled V8 functions.
    * **SimdOp:** Implementing SIMD (Single Instruction, Multiple Data) operations for performance.
    * **WASM Opcodes:**  Directly implementing the behavior of WebAssembly instructions.

**3. Function-by-Function Analysis (More Detailed):**

* **`CreateMachineSignature`:**  Clearly converts WASM function signatures to machine-level signatures, handling the difference between tagged JavaScript values and raw WASM types. The template indicates it works for both standard and canonical WASM value types.
* **`LowerInt64`:**  Focuses on handling 64-bit integers, especially on 32-bit architectures. It uses an `Int64Lowering` helper class, suggesting a separate module for this complex task.
* **`BuildChangeInt64ToBigInt`:**  Demonstrates how 64-bit WASM integers are converted to JavaScript `BigInt` objects, using either a direct conversion on 64-bit systems or a pair of 32-bit words on 32-bit systems.
* **`SetSourcePosition`:**  Relates nodes in the intermediate representation back to their original source code location in the WASM module. This is important for debugging and profiling.
* **`S128Zero`:** Creates a zero-initialized 128-bit SIMD vector.
* **`SimdOp`:**  A large switch statement that implements a wide range of WASM SIMD operations. It maps WASM opcodes to corresponding machine instructions or potentially calls helper functions (like `BuildF64x2Ceil`). The `has_simd_` flag suggests tracking whether SIMD instructions are used.

**4. Identifying Relationships with JavaScript:**

* The `CreateMachineSignature` function handles the case where parameters come from JavaScript, explicitly tagging them.
* `BuildChangeInt64ToBigInt` directly addresses the interaction between WASM's 64-bit integers and JavaScript's `BigInt` type.

**5. Code Logic and Potential Issues:**

* **`LowerInt64`:** The logic is architecture-dependent. A potential issue is performance overhead on 32-bit systems due to the need to manipulate two 32-bit registers for a single 64-bit value.
* **`BuildChangeInt64ToBigInt`:**  The branching logic based on `mcgraph()->machine()->Is64()` is correct but highlights the platform dependency. A potential issue could arise if the `Builtin::kI64ToBigInt` or `Builtin::kI32PairToBigInt` implementations have bugs.
* **`SimdOp`:** The sheer number of cases makes this function complex and prone to errors if any mapping between WASM opcode and machine instruction is incorrect. The "Architecture support" comments highlight the need for fallback implementations when certain hardware instructions are not available.

**6. User Programming Errors (related to JavaScript interaction):**

* **Incorrect Type Handling (for I64):**  JavaScript users might not realize that WASM `i64` values are represented as `BigInt` in JavaScript. Trying to treat them as standard JavaScript numbers will lead to errors or incorrect results.
* **SIMD Usage:**  While not directly a *programming* error in JavaScript, if a WASM module heavily relies on SIMD instructions not well-supported by the user's browser/platform, performance might be suboptimal.

**7. Synthesizing the Summary:**

Based on the analysis, the key functionalities revolve around:

* **Signature Conversion:** Translating WASM function signatures to machine-level signatures, considering JavaScript interop.
* **64-bit Integer Handling:**  Managing 64-bit integer values, especially for JavaScript interaction and on 32-bit architectures.
* **SIMD Operation Implementation:** Providing the underlying machine instructions for a wide variety of WASM SIMD operations.
* **Source Code Mapping:**  Linking the generated code back to the original WASM source for debugging.

**Self-Correction/Refinement during the process:**

* Initially, I might have just focused on the `SimdOp` function due to its size. However, recognizing the importance of `LowerInt64` and the signature handling is crucial for a complete understanding.
* The prompt explicitly asked about `.tq`, so confirming it's `.cc` is a key step to avoid misinterpreting the code as Torque.
*  Remembering the context of "compiler" is essential. The code isn't *executing* WASM; it's *translating* it.

By following this systematic approach, moving from high-level understanding to detailed analysis, and considering the specific questions in the prompt, we can effectively analyze and summarize the functionality of this V8 code snippet.
好的，让我们来分析一下这段 `v8/src/compiler/wasm-compiler.cc` 代码片段的功能。

**功能概括:**

这段代码是 V8 引擎中 WebAssembly (Wasm) 编译器的一部分，主要负责 **构建和操作中间表示（IR）图**，以便将 Wasm 代码转换为机器码。更具体地说，这段代码专注于以下几个核心功能：

1. **处理函数签名 (Signatures):**  创建和转换函数签名，以适应不同的调用场景，特别是从 JavaScript 调用 Wasm 函数的情况。
2. **处理 64 位整数 (Int64):** 针对不同的架构（32 位和 64 位），提供降低 64 位整数操作复杂性的机制，并处理 Wasm 的 64 位整数与 JavaScript 的 `BigInt` 之间的转换。
3. **支持 SIMD 指令 (SIMD Operations):**  为大量的 Wasm SIMD (Single Instruction, Multiple Data) 操作生成相应的中间表示节点。
4. **设置源码位置 (Source Position):**  记录中间表示图中节点对应的 Wasm 源码位置，用于调试和错误报告。

**详细功能分解:**

1. **处理函数签名 (Signatures):**
   - `CreateMachineSignature`: 这个模板函数负责根据 Wasm 的值类型签名 (`Signature<wasm::ValueType>`) 或规范值类型签名 (`Signature<wasm::CanonicalValueType>`) 创建机器表示签名 (`Signature<MachineRepresentation>`)。
   - **JavaScript 关系:** 当 Wasm 函数被 JavaScript 调用时，参数需要以 V8 的 tagged value 形式传递。即使 Wasm 签名声明参数是 I64，JavaScript 也会提供一个 `BigInt` 对象，而不是两个 32 位参数。这段代码确保了在这些情况下，参数的机器表示被设置为 `kTagged`。

   ```javascript
   // 假设有一个 Wasm 函数接受一个 i64 类型的参数
   // 并且 JavaScript 调用了这个函数
   const wasmModule = // ... 加载的 Wasm 模块
   const wasmInstance = // ... Wasm 实例
   const wasmFunction = wasmInstance.exports.myFunction;

   const bigIntValue = 123456789012345n; // JavaScript BigInt
   wasmFunction(bigIntValue); // 调用 Wasm 函数
   ```
   在 V8 内部，`CreateMachineSignature` 会识别出这是从 JavaScript 发起的调用，并将对应的参数类型设置为 `kTagged` 以处理 `BigInt`。

2. **处理 64 位整数 (Int64):**
   - `LowerInt64`: 这个函数负责降低 64 位整数操作的复杂性，特别是在 32 位架构上。在 32 位架构上，64 位整数需要用两个 32 位寄存器来表示。`Int64Lowering` 类会进行相应的转换。
   - `BuildChangeInt64ToBigInt`:  这个函数用于将 Wasm 的 64 位整数转换为 JavaScript 的 `BigInt` 对象。在 64 位架构上，可以直接调用内置函数 `Builtin::kI64ToBigInt`；在 32 位架构上，则需要将 64 位整数拆分成高低 32 位，然后调用 `Builtin::kI32PairToBigInt` 来创建 `BigInt`。

   **假设输入与输出 (BuildChangeInt64ToBigInt):**
   - **假设输入 (64 位架构):** `input` 是一个表示 64 位整数的中间表示节点。
   - **输出 (64 位架构):** 一个表示 JavaScript `BigInt` 对象的中间表示节点。
   - **假设输入 (32 位架构):** `input` 是一个表示 64 位整数的中间表示节点。
   - **输出 (32 位架构):** 一个表示 JavaScript `BigInt` 对象的中间表示节点，其内部是由 `low_word` 和 `high_word` 两个 32 位值构成的。

   **用户常见的编程错误 (与 JavaScript 关系):**
   ```javascript
   // 错误示例：尝试将 Wasm 的 i64 直接作为 JavaScript Number 使用
   const wasmModule = // ... 加载的 Wasm 模块
   const wasmInstance = // ... Wasm 实例
   const getI64Function = wasmInstance.exports.getI64;

   const i64Value = getI64Function(); // 假设 Wasm 函数返回一个 i64
   console.log(i64Value + 1); // 错误！i64Value 是一个 BigInt，不能直接与 Number 相加
   console.log(i64Value + 1n); // 正确：与 BigInt 相加
   ```
   用户需要注意，Wasm 的 `i64` 类型在 JavaScript 中会被转换为 `BigInt`，需要使用 `BigInt` 的操作方式。

3. **支持 SIMD 指令 (SIMD Operations):**
   - `S128Zero`: 创建一个表示 128 位零向量的中间表示节点。
   - `SimdOp`:  这是一个大型的 `switch` 语句，针对各种 Wasm SIMD 操作码 (`wasm::WasmOpcode`)，创建相应的机器指令节点。例如，`wasm::kExprF64x2Add` 会创建一个 `mcgraph()->machine()->F64x2Add()` 节点。
   - `has_simd_`:  这个成员变量用于标记是否在当前的编译过程中使用了 SIMD 指令。
   - 针对一些没有硬件直接支持的 SIMD 操作，代码中会调用 `BuildF64x2Ceil` 等辅助函数来实现。

4. **设置源码位置 (Source Position):**
   - `SetSourcePosition`:  将中间表示图中的节点与 Wasm 源码中的特定位置 (`wasm::WasmCodePosition`) 关联起来。这对于调试器定位错误和性能分析工具追踪代码执行非常重要。

**代码逻辑推理示例 (SimdOp - wasm::kExprF64x2Add):**

- **假设输入:**
    - `opcode` 是 `wasm::kExprF64x2Add`，表示双精度浮点数 2x128 位向量加法。
    - `inputs` 是一个包含两个节点的数组，`inputs[0]` 和 `inputs[1]` 分别表示两个要相加的 128 位向量。
- **输出:**
    - 一个新的中间表示节点，该节点表示执行 `F64x2Add` 操作，并将 `inputs[0]` 和 `inputs[1]` 作为其输入。这个节点类型由 `mcgraph()->machine()->F64x2Add()` 决定，它代表了目标架构上的相应机器指令。

**归纳其功能 (作为第 6 部分):**

这段 `wasm-compiler.cc` 代码片段在 WebAssembly 编译流程中扮演着关键的 **中间层角色**。它负责：

- **桥接 Wasm 语义和底层机器指令:**  将 Wasm 的高级概念（如函数签名、64 位整数、SIMD 操作）转换为更接近目标机器的中间表示形式。
- **处理平台差异:**  通过条件判断和不同的处理方式，来适应不同的 CPU 架构（例如，如何处理 64 位整数在 32 位系统上的表示）。
- **为后续优化和代码生成做准备:**  构建的中间表示图是后续优化器进行各种优化的基础，最终会被代码生成器转换为实际的机器码。

作为第 6 部分，它很可能位于 Wasm 编译流程中 **将 Wasm 字节码初步转换为中间表示的关键阶段**。之前的阶段可能负责解析 Wasm 字节码，而后续阶段则会进行更深入的优化和最终的代码生成。这段代码确保了从 Wasm 语义到机器指令转换的正确性和效率。

### 提示词
```
这是目录为v8/src/compiler/wasm-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/wasm-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
S) {
      // Parameters coming from JavaScript are always tagged values. Especially
      // when the signature says that it's an I64 value, then a BigInt object is
      // provided by JavaScript, and not two 32-bit parameters.
      builder.AddParam(MachineRepresentation::kTagged);
    } else {
      builder.AddParam(param.machine_representation());
    }
  }
  return builder.Get();
}

template Signature<MachineRepresentation>* CreateMachineSignature(
    Zone*, const Signature<wasm::ValueType>*, wasm::CallOrigin);
template Signature<MachineRepresentation>* CreateMachineSignature(
    Zone*, const Signature<wasm::CanonicalValueType>*, wasm::CallOrigin);

void WasmGraphBuilder::LowerInt64(Signature<MachineRepresentation>* sig) {
  if (mcgraph()->machine()->Is64()) return;
  Int64Lowering r(mcgraph()->graph(), mcgraph()->machine(), mcgraph()->common(),
                  gasm_->simplified(), mcgraph()->zone(), sig);
  r.LowerGraph();
}

void WasmGraphBuilder::LowerInt64(wasm::CallOrigin origin) {
  Signature<MachineRepresentation>* machine_sig =
      function_sig_ != nullptr
          ? CreateMachineSignature(mcgraph()->zone(), function_sig_, origin)
          : CreateMachineSignature(mcgraph()->zone(), wrapper_sig_, origin);
  LowerInt64(machine_sig);
}

Node* WasmGraphBuilder::BuildChangeInt64ToBigInt(Node* input,
                                                 StubCallMode stub_mode) {
  if (mcgraph()->machine()->Is64()) {
    return gasm_->CallBuiltin(Builtin::kI64ToBigInt, Operator::kEliminatable,
                              input);
  } else {
    Node* low_word = gasm_->TruncateInt64ToInt32(input);
    Node* high_word = gasm_->TruncateInt64ToInt32(
        gasm_->Word64Shr(input, gasm_->Int32Constant(32)));
    return gasm_->CallBuiltin(Builtin::kI32PairToBigInt,
                              Operator::kEliminatable, low_word, high_word);
  }
}

void WasmGraphBuilder::SetSourcePosition(Node* node,
                                         wasm::WasmCodePosition position) {
  DCHECK_NE(position, wasm::kNoCodePosition);
  if (source_position_table_) {
    source_position_table_->SetSourcePosition(
        node, SourcePosition(position, inlining_id_));
  }
}

Node* WasmGraphBuilder::S128Zero() {
  has_simd_ = true;
  return graph()->NewNode(mcgraph()->machine()->S128Zero());
}

Node* WasmGraphBuilder::SimdOp(wasm::WasmOpcode opcode, Node* const* inputs) {
  has_simd_ = true;
  switch (opcode) {
    case wasm::kExprF64x2Splat:
      return graph()->NewNode(mcgraph()->machine()->F64x2Splat(), inputs[0]);
    case wasm::kExprF64x2Abs:
      return graph()->NewNode(mcgraph()->machine()->F64x2Abs(), inputs[0]);
    case wasm::kExprF64x2Neg:
      return graph()->NewNode(mcgraph()->machine()->F64x2Neg(), inputs[0]);
    case wasm::kExprF64x2Sqrt:
      return graph()->NewNode(mcgraph()->machine()->F64x2Sqrt(), inputs[0]);
    case wasm::kExprF64x2Add:
      return graph()->NewNode(mcgraph()->machine()->F64x2Add(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Sub:
      return graph()->NewNode(mcgraph()->machine()->F64x2Sub(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Mul:
      return graph()->NewNode(mcgraph()->machine()->F64x2Mul(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Div:
      return graph()->NewNode(mcgraph()->machine()->F64x2Div(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Min:
      return graph()->NewNode(mcgraph()->machine()->F64x2Min(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Max:
      return graph()->NewNode(mcgraph()->machine()->F64x2Max(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Eq:
      return graph()->NewNode(mcgraph()->machine()->F64x2Eq(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Ne:
      return graph()->NewNode(mcgraph()->machine()->F64x2Ne(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Lt:
      return graph()->NewNode(mcgraph()->machine()->F64x2Lt(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Le:
      return graph()->NewNode(mcgraph()->machine()->F64x2Le(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Gt:
      return graph()->NewNode(mcgraph()->machine()->F64x2Lt(), inputs[1],
                              inputs[0]);
    case wasm::kExprF64x2Ge:
      return graph()->NewNode(mcgraph()->machine()->F64x2Le(), inputs[1],
                              inputs[0]);
    case wasm::kExprF64x2Qfma:
      return graph()->NewNode(mcgraph()->machine()->F64x2Qfma(), inputs[0],
                              inputs[1], inputs[2]);
    case wasm::kExprF64x2Qfms:
      return graph()->NewNode(mcgraph()->machine()->F64x2Qfms(), inputs[0],
                              inputs[1], inputs[2]);
    case wasm::kExprF64x2Pmin:
      return graph()->NewNode(mcgraph()->machine()->F64x2Pmin(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Pmax:
      return graph()->NewNode(mcgraph()->machine()->F64x2Pmax(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Ceil:
      // Architecture support for F64x2Ceil and Float64RoundUp is the same.
      if (!mcgraph()->machine()->Float64RoundUp().IsSupported())
        return BuildF64x2Ceil(inputs[0]);
      return graph()->NewNode(mcgraph()->machine()->F64x2Ceil(), inputs[0]);
    case wasm::kExprF64x2Floor:
      // Architecture support for F64x2Floor and Float64RoundDown is the same.
      if (!mcgraph()->machine()->Float64RoundDown().IsSupported())
        return BuildF64x2Floor(inputs[0]);
      return graph()->NewNode(mcgraph()->machine()->F64x2Floor(), inputs[0]);
    case wasm::kExprF64x2Trunc:
      // Architecture support for F64x2Trunc and Float64RoundTruncate is the
      // same.
      if (!mcgraph()->machine()->Float64RoundTruncate().IsSupported())
        return BuildF64x2Trunc(inputs[0]);
      return graph()->NewNode(mcgraph()->machine()->F64x2Trunc(), inputs[0]);
    case wasm::kExprF64x2NearestInt:
      // Architecture support for F64x2NearestInt and Float64RoundTiesEven is
      // the same.
      if (!mcgraph()->machine()->Float64RoundTiesEven().IsSupported())
        return BuildF64x2NearestInt(inputs[0]);
      return graph()->NewNode(mcgraph()->machine()->F64x2NearestInt(),
                              inputs[0]);
    case wasm::kExprF64x2ConvertLowI32x4S:
      return graph()->NewNode(mcgraph()->machine()->F64x2ConvertLowI32x4S(),
                              inputs[0]);
    case wasm::kExprF64x2ConvertLowI32x4U:
      return graph()->NewNode(mcgraph()->machine()->F64x2ConvertLowI32x4U(),
                              inputs[0]);
    case wasm::kExprF64x2PromoteLowF32x4:
      return graph()->NewNode(mcgraph()->machine()->F64x2PromoteLowF32x4(),
                              inputs[0]);
    case wasm::kExprF32x4Splat:
      return graph()->NewNode(mcgraph()->machine()->F32x4Splat(), inputs[0]);
    case wasm::kExprF32x4SConvertI32x4:
      return graph()->NewNode(mcgraph()->machine()->F32x4SConvertI32x4(),
                              inputs[0]);
    case wasm::kExprF32x4UConvertI32x4:
      return graph()->NewNode(mcgraph()->machine()->F32x4UConvertI32x4(),
                              inputs[0]);
    case wasm::kExprF32x4Abs:
      return graph()->NewNode(mcgraph()->machine()->F32x4Abs(), inputs[0]);
    case wasm::kExprF32x4Neg:
      return graph()->NewNode(mcgraph()->machine()->F32x4Neg(), inputs[0]);
    case wasm::kExprF32x4Sqrt:
      return graph()->NewNode(mcgraph()->machine()->F32x4Sqrt(), inputs[0]);
    case wasm::kExprF32x4Add:
      return graph()->NewNode(mcgraph()->machine()->F32x4Add(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Sub:
      return graph()->NewNode(mcgraph()->machine()->F32x4Sub(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Mul:
      return graph()->NewNode(mcgraph()->machine()->F32x4Mul(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Div:
      return graph()->NewNode(mcgraph()->machine()->F32x4Div(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Min:
      return graph()->NewNode(mcgraph()->machine()->F32x4Min(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Max:
      return graph()->NewNode(mcgraph()->machine()->F32x4Max(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Eq:
      return graph()->NewNode(mcgraph()->machine()->F32x4Eq(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Ne:
      return graph()->NewNode(mcgraph()->machine()->F32x4Ne(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Lt:
      return graph()->NewNode(mcgraph()->machine()->F32x4Lt(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Le:
      return graph()->NewNode(mcgraph()->machine()->F32x4Le(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Gt:
      return graph()->NewNode(mcgraph()->machine()->F32x4Lt(), inputs[1],
                              inputs[0]);
    case wasm::kExprF32x4Ge:
      return graph()->NewNode(mcgraph()->machine()->F32x4Le(), inputs[1],
                              inputs[0]);
    case wasm::kExprF32x4Qfma:
      return graph()->NewNode(mcgraph()->machine()->F32x4Qfma(), inputs[0],
                              inputs[1], inputs[2]);
    case wasm::kExprF32x4Qfms:
      return graph()->NewNode(mcgraph()->machine()->F32x4Qfms(), inputs[0],
                              inputs[1], inputs[2]);
    case wasm::kExprF32x4Pmin:
      return graph()->NewNode(mcgraph()->machine()->F32x4Pmin(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Pmax:
      return graph()->NewNode(mcgraph()->machine()->F32x4Pmax(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Ceil:
      // Architecture support for F32x4Ceil and Float32RoundUp is the same.
      if (!mcgraph()->machine()->Float32RoundUp().IsSupported())
        return BuildF32x4Ceil(inputs[0]);
      return graph()->NewNode(mcgraph()->machine()->F32x4Ceil(), inputs[0]);
    case wasm::kExprF32x4Floor:
      // Architecture support for F32x4Floor and Float32RoundDown is the same.
      if (!mcgraph()->machine()->Float32RoundDown().IsSupported())
        return BuildF32x4Floor(inputs[0]);
      return graph()->NewNode(mcgraph()->machine()->F32x4Floor(), inputs[0]);
    case wasm::kExprF32x4Trunc:
      // Architecture support for F32x4Trunc and Float32RoundTruncate is the
      // same.
      if (!mcgraph()->machine()->Float32RoundTruncate().IsSupported())
        return BuildF32x4Trunc(inputs[0]);
      return graph()->NewNode(mcgraph()->machine()->F32x4Trunc(), inputs[0]);
    case wasm::kExprF32x4NearestInt:
      // Architecture support for F32x4NearestInt and Float32RoundTiesEven is
      // the same.
      if (!mcgraph()->machine()->Float32RoundTiesEven().IsSupported())
        return BuildF32x4NearestInt(inputs[0]);
      return graph()->NewNode(mcgraph()->machine()->F32x4NearestInt(),
                              inputs[0]);
    case wasm::kExprF32x4DemoteF64x2Zero:
      return graph()->NewNode(mcgraph()->machine()->F32x4DemoteF64x2Zero(),
                              inputs[0]);
    case wasm::kExprI64x2Splat:
      return graph()->NewNode(mcgraph()->machine()->I64x2Splat(), inputs[0]);
    case wasm::kExprI64x2Abs:
      return graph()->NewNode(mcgraph()->machine()->I64x2Abs(), inputs[0]);
    case wasm::kExprI64x2Neg:
      return graph()->NewNode(mcgraph()->machine()->I64x2Neg(), inputs[0]);
    case wasm::kExprI64x2SConvertI32x4Low:
      return graph()->NewNode(mcgraph()->machine()->I64x2SConvertI32x4Low(),
                              inputs[0]);
    case wasm::kExprI64x2SConvertI32x4High:
      return graph()->NewNode(mcgraph()->machine()->I64x2SConvertI32x4High(),
                              inputs[0]);
    case wasm::kExprI64x2UConvertI32x4Low:
      return graph()->NewNode(mcgraph()->machine()->I64x2UConvertI32x4Low(),
                              inputs[0]);
    case wasm::kExprI64x2UConvertI32x4High:
      return graph()->NewNode(mcgraph()->machine()->I64x2UConvertI32x4High(),
                              inputs[0]);
    case wasm::kExprI64x2BitMask:
      return graph()->NewNode(mcgraph()->machine()->I64x2BitMask(), inputs[0]);
    case wasm::kExprI64x2Shl:
      return graph()->NewNode(mcgraph()->machine()->I64x2Shl(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2ShrS:
      return graph()->NewNode(mcgraph()->machine()->I64x2ShrS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2Add:
      return graph()->NewNode(mcgraph()->machine()->I64x2Add(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2Sub:
      return graph()->NewNode(mcgraph()->machine()->I64x2Sub(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2Mul:
      return graph()->NewNode(mcgraph()->machine()->I64x2Mul(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2Eq:
      return graph()->NewNode(mcgraph()->machine()->I64x2Eq(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2Ne:
      return graph()->NewNode(mcgraph()->machine()->I64x2Ne(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2LtS:
      return graph()->NewNode(mcgraph()->machine()->I64x2GtS(), inputs[1],
                              inputs[0]);
    case wasm::kExprI64x2LeS:
      return graph()->NewNode(mcgraph()->machine()->I64x2GeS(), inputs[1],
                              inputs[0]);
    case wasm::kExprI64x2GtS:
      return graph()->NewNode(mcgraph()->machine()->I64x2GtS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2GeS:
      return graph()->NewNode(mcgraph()->machine()->I64x2GeS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2ShrU:
      return graph()->NewNode(mcgraph()->machine()->I64x2ShrU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2ExtMulLowI32x4S:
      return graph()->NewNode(mcgraph()->machine()->I64x2ExtMulLowI32x4S(),
                              inputs[0], inputs[1]);
    case wasm::kExprI64x2ExtMulHighI32x4S:
      return graph()->NewNode(mcgraph()->machine()->I64x2ExtMulHighI32x4S(),
                              inputs[0], inputs[1]);
    case wasm::kExprI64x2ExtMulLowI32x4U:
      return graph()->NewNode(mcgraph()->machine()->I64x2ExtMulLowI32x4U(),
                              inputs[0], inputs[1]);
    case wasm::kExprI64x2ExtMulHighI32x4U:
      return graph()->NewNode(mcgraph()->machine()->I64x2ExtMulHighI32x4U(),
                              inputs[0], inputs[1]);
    case wasm::kExprI32x4Splat:
      return graph()->NewNode(mcgraph()->machine()->I32x4Splat(), inputs[0]);
    case wasm::kExprI32x4SConvertF32x4:
      return graph()->NewNode(mcgraph()->machine()->I32x4SConvertF32x4(),
                              inputs[0]);
    case wasm::kExprI32x4UConvertF32x4:
      return graph()->NewNode(mcgraph()->machine()->I32x4UConvertF32x4(),
                              inputs[0]);
    case wasm::kExprI32x4SConvertI16x8Low:
      return graph()->NewNode(mcgraph()->machine()->I32x4SConvertI16x8Low(),
                              inputs[0]);
    case wasm::kExprI32x4SConvertI16x8High:
      return graph()->NewNode(mcgraph()->machine()->I32x4SConvertI16x8High(),
                              inputs[0]);
    case wasm::kExprI32x4Neg:
      return graph()->NewNode(mcgraph()->machine()->I32x4Neg(), inputs[0]);
    case wasm::kExprI32x4Shl:
      return graph()->NewNode(mcgraph()->machine()->I32x4Shl(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4ShrS:
      return graph()->NewNode(mcgraph()->machine()->I32x4ShrS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4Add:
      return graph()->NewNode(mcgraph()->machine()->I32x4Add(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4Sub:
      return graph()->NewNode(mcgraph()->machine()->I32x4Sub(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4Mul:
      return graph()->NewNode(mcgraph()->machine()->I32x4Mul(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4MinS:
      return graph()->NewNode(mcgraph()->machine()->I32x4MinS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4MaxS:
      return graph()->NewNode(mcgraph()->machine()->I32x4MaxS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4Eq:
      return graph()->NewNode(mcgraph()->machine()->I32x4Eq(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4Ne:
      return graph()->NewNode(mcgraph()->machine()->I32x4Ne(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4LtS:
      return graph()->NewNode(mcgraph()->machine()->I32x4GtS(), inputs[1],
                              inputs[0]);
    case wasm::kExprI32x4LeS:
      return graph()->NewNode(mcgraph()->machine()->I32x4GeS(), inputs[1],
                              inputs[0]);
    case wasm::kExprI32x4GtS:
      return graph()->NewNode(mcgraph()->machine()->I32x4GtS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4GeS:
      return graph()->NewNode(mcgraph()->machine()->I32x4GeS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4UConvertI16x8Low:
      return graph()->NewNode(mcgraph()->machine()->I32x4UConvertI16x8Low(),
                              inputs[0]);
    case wasm::kExprI32x4UConvertI16x8High:
      return graph()->NewNode(mcgraph()->machine()->I32x4UConvertI16x8High(),
                              inputs[0]);
    case wasm::kExprI32x4ShrU:
      return graph()->NewNode(mcgraph()->machine()->I32x4ShrU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4MinU:
      return graph()->NewNode(mcgraph()->machine()->I32x4MinU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4MaxU:
      return graph()->NewNode(mcgraph()->machine()->I32x4MaxU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4LtU:
      return graph()->NewNode(mcgraph()->machine()->I32x4GtU(), inputs[1],
                              inputs[0]);
    case wasm::kExprI32x4LeU:
      return graph()->NewNode(mcgraph()->machine()->I32x4GeU(), inputs[1],
                              inputs[0]);
    case wasm::kExprI32x4GtU:
      return graph()->NewNode(mcgraph()->machine()->I32x4GtU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4GeU:
      return graph()->NewNode(mcgraph()->machine()->I32x4GeU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4Abs:
      return graph()->NewNode(mcgraph()->machine()->I32x4Abs(), inputs[0]);
    case wasm::kExprI32x4BitMask:
      return graph()->NewNode(mcgraph()->machine()->I32x4BitMask(), inputs[0]);
    case wasm::kExprI32x4DotI16x8S:
      return graph()->NewNode(mcgraph()->machine()->I32x4DotI16x8S(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4ExtMulLowI16x8S:
      return graph()->NewNode(mcgraph()->machine()->I32x4ExtMulLowI16x8S(),
                              inputs[0], inputs[1]);
    case wasm::kExprI32x4ExtMulHighI16x8S:
      return graph()->NewNode(mcgraph()->machine()->I32x4ExtMulHighI16x8S(),
                              inputs[0], inputs[1]);
    case wasm::kExprI32x4ExtMulLowI16x8U:
      return graph()->NewNode(mcgraph()->machine()->I32x4ExtMulLowI16x8U(),
                              inputs[0], inputs[1]);
    case wasm::kExprI32x4ExtMulHighI16x8U:
      return graph()->NewNode(mcgraph()->machine()->I32x4ExtMulHighI16x8U(),
                              inputs[0], inputs[1]);
    case wasm::kExprI32x4ExtAddPairwiseI16x8S:
      return graph()->NewNode(mcgraph()->machine()->I32x4ExtAddPairwiseI16x8S(),
                              inputs[0]);
    case wasm::kExprI32x4ExtAddPairwiseI16x8U:
      return graph()->NewNode(mcgraph()->machine()->I32x4ExtAddPairwiseI16x8U(),
                              inputs[0]);
    case wasm::kExprI32x4TruncSatF64x2SZero:
      return graph()->NewNode(mcgraph()->machine()->I32x4TruncSatF64x2SZero(),
                              inputs[0]);
    case wasm::kExprI32x4TruncSatF64x2UZero:
      return graph()->NewNode(mcgraph()->machine()->I32x4TruncSatF64x2UZero(),
                              inputs[0]);
    case wasm::kExprI16x8Splat:
      return graph()->NewNode(mcgraph()->machine()->I16x8Splat(), inputs[0]);
    case wasm::kExprI16x8SConvertI8x16Low:
      return graph()->NewNode(mcgraph()->machine()->I16x8SConvertI8x16Low(),
                              inputs[0]);
    case wasm::kExprI16x8SConvertI8x16High:
      return graph()->NewNode(mcgraph()->machine()->I16x8SConvertI8x16High(),
                              inputs[0]);
    case wasm::kExprI16x8Shl:
      return graph()->NewNode(mcgraph()->machine()->I16x8Shl(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8ShrS:
      return graph()->NewNode(mcgraph()->machine()->I16x8ShrS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8Neg:
      return graph()->NewNode(mcgraph()->machine()->I16x8Neg(), inputs[0]);
    case wasm::kExprI16x8SConvertI32x4:
      return graph()->NewNode(mcgraph()->machine()->I16x8SConvertI32x4(),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8Add:
      return graph()->NewNode(mcgraph()->machine()->I16x8Add(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8AddSatS:
      return graph()->NewNode(mcgraph()->machine()->I16x8AddSatS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8Sub:
      return graph()->NewNode(mcgraph()->machine()->I16x8Sub(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8SubSatS:
      return graph()->NewNode(mcgraph()->machine()->I16x8SubSatS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8Mul:
      return graph()->NewNode(mcgraph()->machine()->I16x8Mul(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8MinS:
      return graph()->NewNode(mcgraph()->machine()->I16x8MinS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8MaxS:
      return graph()->NewNode(mcgraph()->machine()->I16x8MaxS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8Eq:
      return graph()->NewNode(mcgraph()->machine()->I16x8Eq(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8Ne:
      return graph()->NewNode(mcgraph()->machine()->I16x8Ne(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8LtS:
      return graph()->NewNode(mcgraph()->machine()->I16x8GtS(), inputs[1],
                              inputs[0]);
    case wasm::kExprI16x8LeS:
      return graph()->NewNode(mcgraph()->machine()->I16x8GeS(), inputs[1],
                              inputs[0]);
    case wasm::kExprI16x8GtS:
      return graph()->NewNode(mcgraph()->machine()->I16x8GtS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8GeS:
      return graph()->NewNode(mcgraph()->machine()->I16x8GeS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8UConvertI8x16Low:
      return graph()->NewNode(mcgraph()->machine()->I16x8UConvertI8x16Low(),
                              inputs[0]);
    case wasm::kExprI16x8UConvertI8x16High:
      return graph()->NewNode(mcgraph()->machine()->I16x8UConvertI8x16High(),
                              inputs[0]);
    case wasm::kExprI16x8UConvertI32x4:
      return graph()->NewNode(mcgraph()->machine()->I16x8UConvertI32x4(),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8ShrU:
      return graph()->NewNode(mcgraph()->machine()->I16x8ShrU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8AddSatU:
      return graph()->NewNode(mcgraph()->machine()->I16x8AddSatU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8SubSatU:
      return graph()->NewNode(mcgraph()->machine()->I16x8SubSatU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8MinU:
      return graph()->NewNode(mcgraph()->machine()->I16x8MinU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8MaxU:
      return graph()->NewNode(mcgraph()->machine()->I16x8MaxU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8LtU:
      return graph()->NewNode(mcgraph()->machine()->I16x8GtU(), inputs[1],
                              inputs[0]);
    case wasm::kExprI16x8LeU:
      return graph()->NewNode(mcgraph()->machine()->I16x8GeU(), inputs[1],
                              inputs[0]);
    case wasm::kExprI16x8GtU:
      return graph()->NewNode(mcgraph()->machine()->I16x8GtU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8GeU:
      return graph()->NewNode(mcgraph()->machine()->I16x8GeU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8RoundingAverageU:
      return graph()->NewNode(mcgraph()->machine()->I16x8RoundingAverageU(),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8Q15MulRSatS:
      return graph()->NewNode(mcgraph()->machine()->I16x8Q15MulRSatS(),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8RelaxedQ15MulRS:
      return graph()->NewNode(mcgraph()->machine()->I16x8RelaxedQ15MulRS(),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8DotI8x16I7x16S:
      return graph()->NewNode(mcgraph()->machine()->I16x8DotI8x16I7x16S(),
                              inputs[0], inputs[1]);
    case wasm::kExprI32x4DotI8x16I7x16AddS:
      return graph()->NewNode(mcgraph()->machine()->I32x4DotI8x16I7x16AddS(),
                              inputs[0], inputs[1], inputs[2]);
    case wasm::kExprI16x8Abs:
      return graph()->NewNode(mcgraph()->machine()->I16x8Abs(), inputs[0]);
    case wasm::kExprI16x8BitMask:
      return graph()->NewNode(mcgraph()->machine()->I16x8BitMask(), inputs[0]);
    case wasm::kExprI16x8ExtMulLowI8x16S:
      return graph()->NewNode(mcgraph()->machine()->I16x8ExtMulLowI8x16S(),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8ExtMulHighI8x16S:
      return graph()->NewNode(mcgraph()->machine()->I16x8ExtMulHighI8x16S(),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8ExtMulLowI8x16U:
      return graph()->NewNode(mcgraph()->machine()->I16x8ExtMulLowI8x16U(),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8ExtMulHighI8x16U:
      return graph()->NewNode(mcgraph()->machine()->I16x8ExtMulHighI8x16U(),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8ExtAddPairwiseI8x16S:
      return graph()->NewNode(mcgraph()->machine()->I16x8ExtAddPairwiseI8x16S(),
                              inputs[0]);
    case wasm::kExprI16x8ExtAddPairwiseI8x16U:
      return graph()->NewNode(mcgraph()->machine()->I16x8ExtAddPairwiseI8x16U(),
                              inputs[0]);
    case wasm::kExprI8x16Splat:
      return graph()->NewNode(mcgraph()->machine()->I8x16Splat(), inputs[0]);
    case wasm::kExprI8x16Neg:
      return graph()->NewNode(mcgraph()->machine()->I8x16Neg(), inputs[0]);
    case wasm::kExprI8x16Shl:
      return graph()->NewNode(mcgraph()->machine()->I8x16Shl(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16ShrS:
      return graph()->NewNode(mcgraph()->machine()->I8x16ShrS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16SConvertI16x8:
      return graph()->NewNode(mcgraph()->machine()->I8x16SConvertI16x8(),
                              inputs[0], inputs[1]);
    case wasm::kExprI8x16Add:
      return graph()->NewNode(mcgraph()->machine()->I8x16Add(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16AddSatS:
      return graph()->NewNode(mcgraph()->machine()->I8x16AddSatS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16Sub:
      return graph()->NewNode(mcgraph()->machine()->I8x16Sub(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16SubSatS:
      return graph()->NewNode(mcgraph()->machine()->I8x16SubSatS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16MinS:
      return graph()->NewNode(mcgraph()->machine()->I8x16MinS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16MaxS:
      return graph()->NewNode(mcgraph()->machine()->I8x16MaxS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16Eq:
      return graph()->NewNode(mcgraph()->machine()->I8x16Eq(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16Ne:
      return graph()->NewNode(mcgraph()->machine()->I8x16Ne(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16LtS:
      return graph()->NewNode(mcgraph()->machine()->I8x16GtS(), inputs[1],
                              inputs[0]);
    case wasm::kExprI8x16LeS:
      return graph()->NewNode(mcgraph()->machine()->I8x16GeS(), inputs[1],
                              inputs[0]);
    case wasm::kExprI8x16GtS:
      return graph()->NewNode(mcgraph()->machine()->I8x16GtS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16GeS:
      return graph()->NewNode(mcgraph()->machine()->I8x16GeS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16ShrU:
      return graph()->NewNode(mcgraph()->machine()->I8x16ShrU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16UConvertI16x8:
      return graph()->NewNode(mcgraph()->machine()->I8x16UConvertI16x8(),
                              inputs[0], inputs[1]);
    case wasm::kExprI8x16AddSatU:
      return graph()->NewNode(mcgraph()->machine()->I8x16AddSatU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16SubSatU:
      return graph()->NewNode(mcgraph()->machine()->I8x16SubSatU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16MinU:
      return graph()->NewNode(mcgraph()->machine()->I8x16MinU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16MaxU:
      return graph()->NewNode(mcgraph()->machine()->I8x16MaxU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16LtU:
      return graph()->NewNode(mcgraph()->machine()->I8x16GtU(), inputs[1],
                              inputs[0]);
    case wasm::kExprI8x16LeU:
      return graph()->NewNode(mcgraph()->machine()->I8x16GeU(), inputs[1],
                              inputs[0]);
    case wasm::kExprI8x16GtU:
      return graph()->NewNode(mcgraph()->machine()->I8x16GtU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16GeU:
      return graph()->NewNode(mcgraph()->machine()->I8x16GeU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16RoundingAverageU:
      return graph()->NewNode(mcgraph()->machine()->I8x16RoundingAverageU(),
                              inputs[0], inputs[1]);
    case wasm::kExprI8x16Popcnt:
      return graph()->NewNode(mcgraph()->machine()->I8x16Popcnt(), inputs[0]);
    case wasm::kExprI8x16Abs:
      return graph()->NewNode(mcgraph()->machine()->I8x16Abs(), inputs[0]);
    case wasm::kExprI8x16BitMask:
      return graph()->NewNode(mcgraph()->machine()->I8x16BitMask(), inputs[0]);
    case wasm::kExprS128And:
      return graph()->NewNode(mcgraph()->machine()->S128And(), inputs[0],
                              inputs[1]);
    case wasm::kExprS128Or:
      return graph()->NewNode(mcgraph()->machine()->S128Or(), inputs[0],
                              inputs[1]);
    case wasm::kExprS128Xor:
      return graph()->NewNode(mcgraph()->machine()->S128Xor(), inputs[0],
                              inputs[1]);
    case wasm::kExprS128Not:
```