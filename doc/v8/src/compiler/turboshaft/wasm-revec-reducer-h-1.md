Response:
The user wants a summary of the C++ code provided, specifically focusing on its functionality within the V8 JavaScript engine. Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The filename `wasm-revec-reducer.h` and the presence of terms like `Simd128`, `Simd256`, `PackNode`, and `RevectorizedNode` strongly suggest this code is about optimizing WebAssembly SIMD (Single Instruction, Multiple Data) operations. The "reducer" part implies it's transforming or simplifying the representation of these operations.

2. **Look for key classes and methods:** The code defines a class `WasmRevecReducer`. The template method `REDUCE_INPUT_GRAPH` is central, as is `FixLoopPhi`. These are the primary actions the reducer performs.

3. **Analyze `REDUCE_INPUT_GRAPH` specializations:**  Notice the various overloads of `REDUCE_INPUT_GRAPH` for different SIMD operations (`Simd128Unary`, `Simd128Binop`, etc.). This tells us the reducer handles specific types of SIMD instructions. The logic within these methods often checks for `PackNode` and attempts to create corresponding `Simd256` operations. This confirms the goal is to combine 128-bit SIMD operations into 256-bit ones for better performance.

4. **Understand `PackNode` and `RevectorizedNode`:** The code frequently interacts with `PackNode` and checks `RevectorizedNode`. A `PackNode` seems to represent a group of related 128-bit SIMD operations that *can* be combined. `RevectorizedNode` likely stores the resulting 256-bit operation after the reduction.

5. **Focus on the "revectorization" concept:** The core function seems to be "revectorization" – taking multiple 128-bit SIMD operations and representing them as fewer 256-bit operations. This is a common optimization technique for SIMD code.

6. **Examine `FixLoopPhi`:** This method deals with `PhiOp` nodes within loops. The special handling for `RegisterRepresentation::Simd128()` indicates that loop variables using SIMD are also being optimized, likely related to the revectorization process.

7. **Look for connections to JavaScript:**  While the code itself is C++, the context is WebAssembly in V8. WebAssembly executes JavaScript. Therefore, these SIMD optimizations directly benefit JavaScript code that utilizes WebAssembly with SIMD features.

8. **Consider potential user errors:** While this code is an internal compiler optimization, a user might write WebAssembly code that *could* benefit from this optimization. A common pattern might involve performing similar operations on adjacent data elements using 128-bit SIMD. The reducer aims to automatically improve such patterns.

9. **Address the ".tq" question:** The prompt asks about ".tq" files. The code explicitly checks if the filename ends with ".tq" to determine if it's a Torque file. Since it doesn't, it's not.

10. **Structure the answer:** Organize the findings into logical sections:
    * Core functionality (revectorization).
    * Handling specific SIMD operations.
    * Loop optimization.
    * Relationship to JavaScript (via WebAssembly).
    * No Torque.
    * Code logic explanation (using a simple example).
    * Potential user errors (related to inefficient SIMD usage).

11. **Provide a concrete code logic example:** Create a simple JavaScript/WebAssembly scenario that illustrates the potential transformation from two 128-bit additions to one 256-bit addition. This makes the optimization more tangible.

12. **Illustrate potential user errors:**  Give an example of how a user might write less optimal SIMD code that the reducer could potentially improve.

13. **Refine and review:** Ensure the language is clear, concise, and accurately reflects the code's purpose. Double-check for any inconsistencies or misunderstandings. For example, initially, I might focus too much on the individual operation types. The core takeaway is the *grouping* and *widening* of SIMD operations.
这是一个V8源代码文件，位于 `v8/src/compiler/turboshaft/` 目录下，名为 `wasm-revec-reducer.h`。从文件名来看，它很可能与 WebAssembly 的“revectorization”有关，并且是一个“reducer”，意味着它在编译过程中对代码进行转换或优化。

**功能归纳：**

`WasmRevecReducer` 的主要功能是**将 WebAssembly 中针对 128 位 SIMD (Single Instruction, Multiple Data) 操作的指令，尝试合并或转换为 256 位的 SIMD 操作，以提高性能。** 这个过程被称为 "revectorization"。

具体来说，它会分析 WebAssembly 的中间表示 (可能是 Turboshaft 图)，寻找可以进行合并的 128 位 SIMD 操作对，并将它们替换为等效的 256 位 SIMD 操作。这可以减少指令的数量，并充分利用现代处理器提供的更宽的 SIMD 寄存器。

**详细功能点：**

1. **识别可合并的 SIMD 操作：**  通过 `WasmRevecAnalyzer` 来分析代码，识别可以“打包”在一起的 128 位 SIMD 操作。这些操作通常是针对相邻数据进行的类似操作。`PackNode` 结构似乎用于表示这些可以打包的操作集合。

2. **创建 256 位 SIMD 操作：** 对于识别出的可合并操作，`WasmRevecReducer` 会创建相应的 256 位 SIMD 操作，例如将两个 `Simd128Binop` 操作合并为一个 `Simd256Binop` 操作。代码中存在许多 `REDUCE_INPUT_GRAPH` 的特化版本，分别处理不同的 128 位 SIMD 指令类型（例如 `Simd128Unary`, `Simd128Binop`, `Simd128Shift` 等）。

3. **处理 `PackNode`：**  代码中多次提到 `PackNode`，包括 `ForcePackNode` 和 `IntersectPackNode`。这些似乎是用于辅助 revectorization 的中间结构，用于指示哪些 128 位操作应该被视为一个整体进行转换。

4. **处理循环中的 Phi 节点：**  `FixLoopPhi` 方法专门处理循环中的 `PhiOp` 节点，特别是当它们涉及 128 位 SIMD 类型时。这表明 revectorization 也需要考虑循环结构，以确保转换的正确性。

5. **处理 Load 和 Shuffle 操作的特殊情况：**  可以看到对于 `Simd128Shuffle` 和涉及内存加载的操作有特殊的处理逻辑，这可能因为这些操作的 revectorization 需要更复杂的转换策略。例如，可以将两个相邻的 128 位加载操作转换为一个 256 位的加载操作，然后再进行后续的 SIMD 计算。

6. **维护新旧图的映射：**  在转换过程中，需要维护原始的 128 位 SIMD 操作与新创建的 256 位 SIMD 操作之间的映射关系。

**关于文件类型：**

根据您的描述，如果 `v8/src/compiler/turboshaft/wasm-revec-reducer.h` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。然而，目前它以 `.h` 结尾，**所以它是一个 C++ 头文件**。 Torque 是一种 V8 使用的用于定义运行时内置函数的领域特定语言，它会被编译成 C++ 代码。

**与 JavaScript 的关系：**

`WasmRevecReducer` 通过优化 WebAssembly 代码来间接影响 JavaScript 的性能。当 JavaScript 代码执行 WebAssembly 模块，并且该模块使用了 SIMD 指令时，`WasmRevecReducer` 的优化可以提高这些 SIMD 操作的执行效率，从而提升整体 JavaScript 应用的性能。

**JavaScript 示例 (概念性):**

虽然 `WasmRevecReducer` 是 C++ 代码，但其优化的对象是 WebAssembly 代码。以下是一个概念性的 JavaScript 例子，展示了在 WebAssembly 中可能被 revectorization 优化的 SIMD 操作模式：

```javascript
// 假设这是 WebAssembly 代码的抽象表示
function wasm_simd_operation(a_low, a_high, b_low, b_high) {
  // 假设 a_low, a_high, b_low, b_high 是 i32x4 类型的 SIMD 值 (128位)
  let result_low = a_low.add(b_low);
  let result_high = a_high.add(b_high);
  return [result_low, result_high];
}

// 在 revectorization 之后，上面的操作可能会被优化为类似这样：
function wasm_simd_operation_optimized(a, b) {
  // 假设 a 和 b 是 i32x8 类型的 SIMD 值 (256位)
  let result = a.add(b);
  return result;
}

// JavaScript 调用 WebAssembly
const wasmInstance = // ... 加载和实例化 WebAssembly 模块
const array1 = new Int32Array([1, 2, 3, 4]);
const array2 = new Int32Array([5, 6, 7, 8]);
const array3 = new Int32Array([9, 10, 11, 12]);
const array4 = new Int32Array([13, 14, 15, 16]);

// 模拟 WebAssembly SIMD 操作 (需要实际的 WebAssembly SIMD API)
// const result = wasmInstance.exports.wasm_simd_operation(array1, array2, array3, array4);
```

在这个例子中，如果 WebAssembly 代码对两个相邻的 128 位 SIMD 值执行相同的加法操作，`WasmRevecReducer` 可能会将这两个 128 位加法合并为一个 256 位的加法。

**代码逻辑推理 (假设输入与输出):**

**假设输入 (在 Turboshaft 图中):**

两个相邻的 `Simd128Binop` 节点，都执行加法操作，操作数来自相邻的内存位置或寄存器。

*   `op1`: `Simd128Binop(kind=Add, left=value1_low, right=value2_low)`
*   `op2`: `Simd128Binop(kind=Add, left=value1_high, right=value2_high)`

**假设输出 (经过 revectorization):**

一个新的 `Simd256Binop` 节点，执行 256 位加法操作。

*   `op_merged`: `Simd256Binop(kind=Add, left=value1_merged, right=value2_merged)`

其中 `value1_merged` 和 `value2_merged` 是将 `value1_low` 和 `value1_high` 以及 `value2_low` 和 `value2_high` 合并而成的 256 位 SIMD 值。可能还会涉及到一些 `SimdPack128To256` 或类似的指令来创建这些合并后的值。

**涉及用户常见的编程错误 (在 WebAssembly 中):**

虽然 `WasmRevecReducer` 是一个编译器优化，但了解其工作原理可以帮助开发者编写更易于优化的 WebAssembly 代码。一个常见的“错误”或者说低效的模式是**手动地对数据的不同部分进行独立的 SIMD 操作，而不是利用更宽的 SIMD 指令一次性处理更多数据。**

**例子：**

假设开发者需要对一个包含 8 个 32 位整数的数组进行加法操作，他们可能会写成两个独立的 128 位 SIMD 加法：

```c++
// 假设这是 WebAssembly C API 的伪代码
v128_t a_low = wasm_v128_load(ptr + 0);  // 加载前 4 个整数
v128_t b_low = wasm_v128_load(ptr + 16);
v128_t result_low = wasm_f32x4_add(a_low, b_low);
wasm_v128_store(ptr + 32, result_low);

v128_t a_high = wasm_v128_load(ptr + 4 * 4); // 加载后 4 个整数
v128_t b_high = wasm_v128_load(ptr + 4 * 4 + 16);
v128_t result_high = wasm_f32x4_add(a_high, b_high);
wasm_v128_store(ptr + 4 * 4 + 32, result_high);
```

`WasmRevecReducer` 的目标就是将这种模式识别出来，并将其转换为一个更高效的 256 位 SIMD 加法操作，如果目标架构支持的话：

```c++
// 优化后的 WebAssembly 代码 (概念)
v256_t a_merged = wasm_v256_load(ptr + 0); // 一次加载 8 个整数
v256_t b_merged = wasm_v256_load(ptr + 32);
v256_t result_merged = wasm_f64x4_add(a_merged, b_merged); // 使用 256 位加法
wasm_v256_store(ptr + 64, result_merged);
```

**第2部分功能归纳：**

这部分代码主要包含了 `REDUCE_INPUT_GRAPH` 方法针对各种具体 SIMD 指令类型的实现逻辑，以及一些辅助方法。

*   **针对特定 SIMD 指令的 revectorization 逻辑：**  例如 `REDUCE_INPUT_GRAPH(Simd128Unary)`, `REDUCE_INPUT_GRAPH(Simd128Binop)`, `REDUCE_INPUT_GRAPH(Simd128Shift)`, `REDUCE_INPUT_GRAPH(Simd128Ternary)`, `REDUCE_INPUT_GRAPH(Simd128Splat)`, `REDUCE_INPUT_GRAPH(Simd128Shuffle)`, `REDUCE_INPUT_GRAPH(Simd128ReplaceLane)` 等方法，分别处理不同类型的 128 位 SIMD 指令。它们的核心逻辑是检查是否存在可以合并的相邻操作，并创建相应的 256 位 SIMD 指令。
*   **处理 `ForcePackNode` 和 `IntersectPackNode`：**  这两种 `PackNode` 类型似乎代表了不同的 revectorization 策略或场景。`ForcePackNode` 可能指示强制将某些 128 位操作打包在一起，而 `IntersectPackNode` 可能涉及更复杂的依赖关系分析。
*   **`ReduceInputsOfOp` 方法：**  这个方法用于递归地处理一个操作的输入，确保在处理当前操作之前，其所有相关的输入操作都已经被处理过。
*   **`GetExtractOpIfNeeded` 方法：**  这个方法可能用于处理当一个 256 位 SIMD 操作的结果需要被拆分成两个 128 位部分使用的情况。
*   **辅助的静态方法 (`GetSimd256UnaryKind`, `GetSimd256BinOpKind` 等)：**  这些方法用于将 128 位 SIMD 指令的种类映射到对应的 256 位 SIMD 指令种类。

**总而言之，这部分代码是 `WasmRevecReducer` 的核心实现，负责识别和执行从 128 位 SIMD 操作到 256 位 SIMD 操作的转换过程，从而优化 WebAssembly 代码的性能。**

### 提示词
```
这是目录为v8/src/compiler/turboshaft/wasm-revec-reducer.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/wasm-revec-reducer.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
lse {
          return extract_op_index;
        }
      }
    }

    // no_change
    return Adapter::ReduceInputGraphPhi(ig_index, phi);
  }

  void FixLoopPhi(const PhiOp& input_phi, OpIndex output_index,
                  Block* output_graph_loop) {
    if (input_phi.rep == RegisterRepresentation::Simd128()) {
      OpIndex phi_index = __ input_graph().Index(input_phi);
      DCHECK(phi_index.valid());
      if (auto* pnode = analyzer_.GetPackNode(phi_index)) {
        auto pending_index = pnode->RevectorizedNode();
        DCHECK(pending_index.valid());
        if (pending_index.valid() &&
            output_graph_loop->Contains(pending_index)) {
          // Need skip replaced op
          if (auto* pending_phi = __ output_graph()
                                      .Get(pending_index)
                                      .template TryCast<PendingLoopPhiOp>()) {
            __ output_graph().template Replace<PhiOp>(
                pending_index,
                base::VectorOf({pending_phi -> first(),
                                analyzer_.GetReducedInput(pnode, 1)}),
                RegisterRepresentation::Simd256());
            return;
          }
        }
      }
    }

    return Adapter::FixLoopPhi(input_phi, output_index, output_graph_loop);
  }

  V<Simd128> REDUCE_INPUT_GRAPH(Simd128Unary)(V<Simd128> ig_index,
                                              const Simd128UnaryOp& unary) {
    auto pnode = analyzer_.GetPackNode(ig_index);
    if (pnode && pnode->IsDefaultPackNode()) {
      V<Simd256> og_index = pnode->RevectorizedNode();
      // Skip revectorized node.
      if (!og_index.valid()) {
        V<Simd256> input = analyzer_.GetReducedInput(pnode);
        if (!input.valid()) {
          V<Simd128> input = __ MapToNewGraph(unary.input());
          og_index = __ Simd256Unary(input, GetSimd256UnaryKind(unary.kind));
        } else {
          og_index = __ Simd256Unary(input, GetSimd256UnaryKind(unary.kind));
        }
        pnode->SetRevectorizedNode(og_index);
      }
      return GetExtractOpIfNeeded(pnode, ig_index, og_index);
    }
    return Adapter::ReduceInputGraphSimd128Unary(ig_index, unary);
  }

  V<Simd128> REDUCE_INPUT_GRAPH(Simd128Binop)(V<Simd128> ig_index,
                                              const Simd128BinopOp& op) {
    auto pnode = analyzer_.GetPackNode(ig_index);
    if (pnode && pnode->IsDefaultPackNode()) {
      V<Simd256> og_index = pnode->RevectorizedNode();
      // Skip revectorized node.
      if (!og_index.valid()) {
        if (pnode->GetOperandsSize() < 2) {
          V<Simd128> left = __ MapToNewGraph(op.left());
          V<Simd128> right = __ MapToNewGraph(op.right());
          og_index = __ Simd256Binop(left, right, GetSimd256BinOpKind(op.kind));
        } else {
          V<Simd256> left = analyzer_.GetReducedInput(pnode, 0);
          V<Simd256> right = analyzer_.GetReducedInput(pnode, 1);
          og_index = __ Simd256Binop(left, right, GetSimd256BinOpKind(op.kind));
        }
        pnode->SetRevectorizedNode(og_index);
      }
      return GetExtractOpIfNeeded(pnode, ig_index, og_index);
    }

    return Adapter::ReduceInputGraphSimd128Binop(ig_index, op);
  }

  V<Simd128> REDUCE_INPUT_GRAPH(Simd128Shift)(V<Simd128> ig_index,
                                              const Simd128ShiftOp& op) {
    if (auto pnode = analyzer_.GetPackNode(ig_index)) {
      V<Simd256> og_index = pnode->RevectorizedNode();
      // Skip revectorized node.
      if (!og_index.valid()) {
        V<Simd256> input = analyzer_.GetReducedInput(pnode);
        DCHECK(input.valid());
        V<Word32> shift = __ MapToNewGraph(op.shift());
        og_index =
            __ Simd256Shift(input, shift, GetSimd256ShiftOpKind(op.kind));
        pnode->SetRevectorizedNode(og_index);
      }
      return GetExtractOpIfNeeded(pnode, ig_index, og_index);
    }

    // no_change
    return Adapter::ReduceInputGraphSimd128Shift(ig_index, op);
  }

  V<Simd128> REDUCE_INPUT_GRAPH(Simd128Ternary)(
      V<Simd128> ig_index, const Simd128TernaryOp& ternary) {
    if (auto pnode = analyzer_.GetPackNode(ig_index)) {
      V<Simd256> og_index = pnode->RevectorizedNode();
      // Skip revectorized node.
      if (!og_index.valid()) {
        V<Simd256> first = analyzer_.GetReducedInput(pnode, 0);
        V<Simd256> second = analyzer_.GetReducedInput(pnode, 1);
        V<Simd256> third = analyzer_.GetReducedInput(pnode, 2);

        og_index = __ Simd256Ternary(first, second, third,
                                     GetSimd256TernaryKind(ternary.kind));

        pnode->SetRevectorizedNode(og_index);
      }

      return GetExtractOpIfNeeded(pnode, ig_index, og_index);
    }
    return Adapter::ReduceInputGraphSimd128Ternary(ig_index, ternary);
  }

  V<Simd128> REDUCE_INPUT_GRAPH(Simd128Splat)(V<Simd128> ig_index,
                                              const Simd128SplatOp& op) {
    if (auto pnode = analyzer_.GetPackNode(ig_index)) {
      V<Simd256> og_index = pnode->RevectorizedNode();
      // Skip revectorized node.
      if (!og_index.valid()) {
        og_index = __ Simd256Splat(__ MapToNewGraph(op.input()),
                                   Get256SplatOpKindFrom128(op.kind));

        pnode->SetRevectorizedNode(og_index);
      }
      return GetExtractOpIfNeeded(pnode, ig_index, og_index);
    }

    return Adapter::ReduceInputGraphSimd128Splat(ig_index, op);
  }

  V<Simd128> REDUCE_INPUT_GRAPH(Simd128Shuffle)(V<Simd128> ig_index,
                                                const Simd128ShuffleOp& op) {
    if (auto p = analyzer_.GetPackNode(ig_index)) {
      ShufflePackNode* pnode = p->AsShufflePackNode();
      V<Simd256> og_index = pnode->RevectorizedNode();
      // Skip revectorized node.
      if (!og_index.valid()) {
        const ShufflePackNode::SpecificInfo::Kind kind = pnode->info().kind();
        switch (kind) {
          case ShufflePackNode::SpecificInfo::Kind::kS256Load32Transform:
          case ShufflePackNode::SpecificInfo::Kind::kS256Load64Transform: {
            const bool is_32 =
                kind ==
                ShufflePackNode::SpecificInfo::Kind::kS256Load32Transform;

            const OpIndex load_index =
                op.input(pnode->info().splat_index() >> (is_32 ? 2 : 1));
            const LoadOp& load =
                __ input_graph().Get(load_index).template Cast<LoadOp>();

            const int bytes_per_lane = is_32 ? 4 : 8;
            const int splat_index =
                pnode->info().splat_index() * bytes_per_lane;
            const int offset = splat_index + load.offset;

            V<WordPtr> base = __ WordPtrAdd(__ MapToNewGraph(load.base()),
                                            __ IntPtrConstant(offset));

            V<WordPtr> index = load.index().has_value()
                                   ? __ MapToNewGraph(load.index().value())
                                   : __ IntPtrConstant(0);

            const Simd256LoadTransformOp::TransformKind transform_kind =
                is_32 ? Simd256LoadTransformOp::TransformKind::k32Splat
                      : Simd256LoadTransformOp::TransformKind::k64Splat;
            og_index = __ Simd256LoadTransform(base, index, load.kind,
                                               transform_kind, 0);
            pnode->SetRevectorizedNode(og_index);
            break;
          }
          case ShufflePackNode::SpecificInfo::Kind::kS256Load8x8U: {
            const Simd128ShuffleOp& op0 =
                __ input_graph()
                    .Get(pnode -> nodes()[0])
                    .template Cast<Simd128ShuffleOp>();

            V<Simd128> load_transform_idx =
                __ input_graph()
                        .Get(op0.left())
                        .template Is<Simd128LoadTransformOp>()
                    ? op0.left()
                    : op0.right();
            const Simd128LoadTransformOp& load_transform =
                __ input_graph()
                    .Get(load_transform_idx)
                    .template Cast<Simd128LoadTransformOp>();
            DCHECK_EQ(load_transform.transform_kind,
                      Simd128LoadTransformOp::TransformKind::k64Zero);
            V<WordPtr> base = __ MapToNewGraph(load_transform.base());
            V<WordPtr> index = __ MapToNewGraph(load_transform.index());
            og_index = __ Simd256LoadTransform(
                base, index, load_transform.load_kind,
                Simd256LoadTransformOp::TransformKind::k8x8U,
                load_transform.offset);
            pnode->SetRevectorizedNode(og_index);
            break;
          }
#ifdef V8_TARGET_ARCH_X64
          case ShufflePackNode::SpecificInfo::Kind::kShufd: {
            V<Simd256> og_left = analyzer_.GetReducedInput(pnode, 0);
            DCHECK_EQ(og_left, analyzer_.GetReducedInput(pnode, 1));
            og_index = __ Simd256Shufd(og_left, pnode->info().shufd_control());
            pnode->SetRevectorizedNode(og_index);
            break;
          }
          case ShufflePackNode::SpecificInfo::Kind::kShufps: {
            V<Simd256> og_left = analyzer_.GetReducedInput(pnode, 0);
            V<Simd256> og_right = analyzer_.GetReducedInput(pnode, 1);
            og_index = __ Simd256Shufps(og_left, og_right,
                                        pnode->info().shufps_control());
            pnode->SetRevectorizedNode(og_index);
            break;
          }
          case ShufflePackNode::SpecificInfo::Kind::kS32x8UnpackLow: {
            V<Simd256> og_left = analyzer_.GetReducedInput(pnode, 0);
            V<Simd256> og_right = analyzer_.GetReducedInput(pnode, 1);
            og_index = __ Simd256Unpack(og_left, og_right,
                                        Simd256UnpackOp::Kind::k32x8Low);
            pnode->SetRevectorizedNode(og_index);
            break;
          }
          case ShufflePackNode::SpecificInfo::Kind::kS32x8UnpackHigh: {
            V<Simd256> og_left = analyzer_.GetReducedInput(pnode, 0);
            V<Simd256> og_right = analyzer_.GetReducedInput(pnode, 1);
            og_index = __ Simd256Unpack(og_left, og_right,
                                        Simd256UnpackOp::Kind::k32x8High);
            pnode->SetRevectorizedNode(og_index);
            break;
          }
#endif  // V8_TARGET_ARCH_X64
          default:
            UNREACHABLE();
        }
      }
      return GetExtractOpIfNeeded(pnode, ig_index, og_index);
    }

    return Adapter::ReduceInputGraphSimd128Shuffle(ig_index, op);
  }

  OpIndex REDUCE_INPUT_GRAPH(Simd128ReplaceLane)(
      OpIndex ig_index, const Simd128ReplaceLaneOp& replace) {
    PackNode* pnode = analyzer_.GetPackNode(ig_index);
    if (pnode && pnode->IsBundlePackNode()) {
      V<Simd256> og_index = pnode->RevectorizedNode();
      // Don't reduce revectorized node.
      if (!og_index.valid()) {
        const BundlePackNode* bundle_pnode = pnode->AsBundlePackNode();
        V<Simd128> base_index = __ MapToNewGraph(bundle_pnode->base());
        V<Simd128> i16x8_index = base_index;
        V<Simd256> i32x8_index;
        if (bundle_pnode->is_sign_extract()) {
          if (bundle_pnode->lane_size() == 1) {
            if (bundle_pnode->offset() == 0) {
              i16x8_index = __ Simd128Unary(
                  base_index, Simd128UnaryOp::Kind::kI16x8SConvertI8x16Low);
            } else {
              DCHECK_EQ(bundle_pnode->offset(), 8);
              i16x8_index = __ Simd128Unary(
                  base_index, Simd128UnaryOp::Kind::kI16x8SConvertI8x16High);
            }
          }
          i32x8_index = __ Simd256Unary(
              i16x8_index, Simd256UnaryOp::Kind::kI32x8SConvertI16x8);
        } else {
          if (bundle_pnode->lane_size() == 1) {
            if (bundle_pnode->offset() == 0) {
              i16x8_index = __ Simd128Unary(
                  base_index, Simd128UnaryOp::Kind::kI16x8UConvertI8x16Low);
            } else {
              DCHECK_EQ(bundle_pnode->offset(), 8);
              i16x8_index = __ Simd128Unary(
                  base_index, Simd128UnaryOp::Kind::kI16x8UConvertI8x16High);
            }
          }
          i32x8_index = __ Simd256Unary(
              i16x8_index, Simd256UnaryOp::Kind::kI32x8UConvertI16x8);
        }

        if (bundle_pnode->is_sign_convert()) {
          og_index = __ Simd256Unary(i32x8_index,
                                     Simd256UnaryOp::Kind::kF32x8SConvertI32x8);
        } else {
          og_index = __ Simd256Unary(i32x8_index,
                                     Simd256UnaryOp::Kind::kF32x8UConvertI32x8);
        }

        pnode->SetRevectorizedNode(og_index);
      }
      return GetExtractOpIfNeeded(pnode, ig_index, og_index);
    }
    // no_change
    return Adapter::ReduceInputGraphSimd128ReplaceLane(ig_index, replace);
  }

  void ReduceInputsOfOp(OpIndex cur_index, OpIndex op_index) {
    // Reduce all the operations of op_index's input tree, which should be
    // bigger than the cur_index. The traversal is done in a DFS manner
    // to make sure all inputs are emitted before the use.
    const Block* current_input_block = Asm().current_input_block();
    std::stack<OpIndex> inputs;
    ZoneUnorderedSet<OpIndex> visited(Asm().phase_zone());
    inputs.push(op_index);

    while (!inputs.empty()) {
      OpIndex idx = inputs.top();
      if (visited.find(idx) != visited.end()) {
        inputs.pop();
        continue;
      }

      const Operation& op = __ input_graph().Get(idx);
      bool has_unvisited_inputs = false;
      for (OpIndex input : op.inputs()) {
        if (input > cur_index && visited.find(input) == visited.end()) {
          inputs.push(input);
          has_unvisited_inputs = true;
        }
      }

      if (!has_unvisited_inputs) {
        inputs.pop();
        visited.insert(idx);

        // op_index will be reduced later.
        if (idx == op_index) continue;

        DCHECK(!Asm().input_graph().Get(idx).template Is<PhiOp>());
        Asm().template VisitOpAndUpdateMapping<false>(idx, current_input_block);
      }
    }
  }

  template <typename Op, typename Continuation>
  void ReduceForceOrIntersectPackNode(PackNode* pnode, const OpIndex ig_index,
                                      OpIndex* og_index) {
    std::array<OpIndex, 2> v;
    DCHECK_EQ(pnode->nodes().size(), 2);
    // The operation order in pnode is determined by the store or reduce
    // seed when build the SLPTree. It is not quaranteed to align with
    // the visiting order in each basic block from input graph. E.g. we
    // can have a block including {a1, a2, b1, b2} operations, and the
    // SLPTree can be pnode1: (a2, a1), pnode2: (b1, b2) if a2 is input
    // of b1, and a1 is input of b2.
    for (int i = 0; i < static_cast<int>(pnode->nodes().size()); i++) {
      OpIndex cur_index = pnode->nodes()[i];
      if ((*og_index).valid() && cur_index == ig_index) {
        v[i] = *og_index;
      } else {
        // The current index maybe already reduced by the IntersectPackNode.
        v[i] = __ template MapToNewGraph<true>(cur_index);
      }

      if (v[i].valid()) continue;

      if (cur_index != ig_index) {
        ReduceInputsOfOp(ig_index, cur_index);
      }
      const Op& op = Asm().input_graph().Get(cur_index).template Cast<Op>();
      v[i] = Continuation{this}.ReduceInputGraph(cur_index, op);

      if (cur_index == ig_index) {
        *og_index = v[i];
      } else {
        // We have to create the mapping as cur_index may exist in other
        // IntersectPackNode and reduce again.
        __ CreateOldToNewMapping(cur_index, v[i]);
      }
    }

    OpIndex revec_index = __ SimdPack128To256(v[0], v[1]);
    pnode->SetRevectorizedNode(revec_index);
  }

  template <typename Op, typename Continuation>
  OpIndex ReduceInputGraphOperation(OpIndex ig_index, const Op& op) {
    OpIndex og_index;
    // Reduce ForcePackNode
    if (PackNode* p = analyzer_.GetPackNode(ig_index);
        p && p->IsForcePackNode()) {
      // Handle force packing nodes.
      ForcePackNode* pnode = p->AsForcePackNode();
      if (!pnode->RevectorizedNode().valid()) {
        switch (pnode->force_pack_type()) {
          case ForcePackNode::kSplat: {
            // The og_index maybe already reduced by the IntersectPackNode.
            OpIndex reduced_index = __ template MapToNewGraph<true>(ig_index);
            if (!reduced_index.valid()) {
              og_index = reduced_index =
                  Continuation{this}.ReduceInputGraph(ig_index, op);
            }
            OpIndex revec_index =
                __ SimdPack128To256(reduced_index, reduced_index);
            pnode->SetRevectorizedNode(revec_index);
            break;
          }
          case ForcePackNode::kGeneral: {
            ReduceForceOrIntersectPackNode<Op, Continuation>(pnode, ig_index,
                                                             &og_index);
            break;
          }
        }
      }
    }

    // Reduce IntersectPackNode
    if (auto intersect_packnodes = analyzer_.GetIntersectPackNodes(ig_index)) {
      for (PackNode* pnode : *intersect_packnodes) {
        if (!(pnode->RevectorizedNode()).valid()) {
          ReduceForceOrIntersectPackNode<Op, Continuation>(pnode, ig_index,
                                                           &og_index);
        }
      }
    }

    if (og_index.valid()) {
      return og_index;
    }

    if (__ template MapToNewGraph<true>(ig_index).valid()) {
      // The op is already emitted during emitting force pack right node input
      // trees.
      return OpIndex::Invalid();
    }

    return Continuation{this}.ReduceInputGraph(ig_index, op);
  }

 private:
  static Simd256UnaryOp::Kind GetSimd256UnaryKind(
      Simd128UnaryOp::Kind simd128_kind) {
    switch (simd128_kind) {
#define UNOP_KIND_MAPPING(from, to)   \
  case Simd128UnaryOp::Kind::k##from: \
    return Simd256UnaryOp::Kind::k##to;
      SIMD256_UNARY_SIMPLE_OP(UNOP_KIND_MAPPING)
#undef UNOP_KIND_MAPPING

#define SIGN_EXTENSION_UNOP_KIND_MAPPING(from_1, to, from_2) \
  case Simd128UnaryOp::Kind::k##from_1:                      \
    return Simd256UnaryOp::Kind::k##to;                      \
  case Simd128UnaryOp::Kind::k##from_2:                      \
    return Simd256UnaryOp::Kind::k##to;
      SIMD256_UNARY_SIGN_EXTENSION_OP(SIGN_EXTENSION_UNOP_KIND_MAPPING)
#undef SIGN_EXTENSION_UNOP_KIND_MAPPING
      default:
        UNIMPLEMENTED();
    }
  }

  static Simd256BinopOp::Kind GetSimd256BinOpKind(Simd128BinopOp::Kind kind) {
    switch (kind) {
#define BINOP_KIND_MAPPING(from, to)  \
  case Simd128BinopOp::Kind::k##from: \
    return Simd256BinopOp::Kind::k##to;
      SIMD256_BINOP_SIMPLE_OP(BINOP_KIND_MAPPING)
#undef BINOP_KIND_MAPPING

#define SIGN_EXTENSION_BINOP_KIND_MAPPING(from_1, to, from_2) \
  case Simd128BinopOp::Kind::k##from_1:                       \
    return Simd256BinopOp::Kind::k##to;                       \
  case Simd128BinopOp::Kind::k##from_2:                       \
    return Simd256BinopOp::Kind::k##to;
      SIMD256_BINOP_SIGN_EXTENSION_OP(SIGN_EXTENSION_BINOP_KIND_MAPPING)
#undef SIGN_EXTENSION_UNOP_KIND_MAPPING
      default:
        UNIMPLEMENTED();
    }
  }

  static Simd256ShiftOp::Kind GetSimd256ShiftOpKind(Simd128ShiftOp::Kind kind) {
    switch (kind) {
#define SHIFT_KIND_MAPPING(from, to)  \
  case Simd128ShiftOp::Kind::k##from: \
    return Simd256ShiftOp::Kind::k##to;
      SIMD256_SHIFT_OP(SHIFT_KIND_MAPPING)
#undef SHIFT_KIND_MAPPING
      default:
        UNIMPLEMENTED();
    }
  }

  static Simd256TernaryOp::Kind GetSimd256TernaryKind(
      Simd128TernaryOp::Kind simd128_kind) {
    switch (simd128_kind) {
#define TERNARY_KIND_MAPPING(from, to)  \
  case Simd128TernaryOp::Kind::k##from: \
    return Simd256TernaryOp::Kind::k##to;
      SIMD256_TERNARY_OP(TERNARY_KIND_MAPPING)
#undef TERNARY_KIND_MAPPING
      default:
        UNIMPLEMENTED();
    }
  }

  static Simd256LoadTransformOp::TransformKind Get256LoadTransformKindFrom128(
      Simd128LoadTransformOp::TransformKind simd128_kind) {
    switch (simd128_kind) {
#define TRANSFORM_KIND_MAPPING(from, to)               \
  case Simd128LoadTransformOp::TransformKind::k##from: \
    return Simd256LoadTransformOp::TransformKind::k##to;
      SIMD256_LOADTRANSFORM_OP(TRANSFORM_KIND_MAPPING)
#undef TRANSFORM_KIND_MAPPING
      default:
        UNREACHABLE();
    }
  }

  static Simd256SplatOp::Kind Get256SplatOpKindFrom128(
      Simd128SplatOp::Kind kind) {
    switch (kind) {
#define SPLAT_KIND_MAPPING(from, to)  \
  case Simd128SplatOp::Kind::k##from: \
    return Simd256SplatOp::Kind::k##to;
      SIMD256_SPLAT_OP(SPLAT_KIND_MAPPING)
      default:
        UNREACHABLE();
    }
  }

  const wasm::WasmModule* module_ = __ data() -> wasm_module();
  WasmRevecAnalyzer analyzer_ = *__ data() -> wasm_revec_analyzer();
};

#include "src/compiler/turboshaft/undef-assembler-macros.inc"

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_COMPILER_TURBOSHAFT_WASM_REVEC_REDUCER_H_
```