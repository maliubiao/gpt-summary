Response:
Let's break down the thought process for analyzing this C++ header file and generating the requested information.

**1. Initial Scan and High-Level Understanding:**

* **Keywords:** Immediately, I look for keywords related to data structures (`ZoneVector`, `GrowingOpIndexSidetable`, `base::iterator_range`), memory management (`graph_zone_`), operations (`Operation`, `OpIndex`), and control flow (`Block`). The namespace `v8::internal::compiler::turboshaft` strongly suggests this is part of the Turboshaft compiler within V8.
* **File Name:** `graph.h` clearly indicates this file defines the core representation of a computation graph.
* **Purpose:** The class `Graph` is central. It seems to hold operations, blocks, and related metadata. This is the core data structure for representing the program being compiled.

**2. Deeper Dive into `Graph` Class Members:**

I'll go through the member variables and methods, trying to understand their purpose:

* **`operations_`:**  A `GrowingOpIndexSidetable` strongly suggests a dynamically sized array-like structure storing `Operation` objects. This is likely *the* store of individual instructions in the graph.
* **`bound_blocks_`, `all_blocks_`, `next_block_`:** These appear to manage the control flow blocks. The distinction between `bound_blocks_` and `all_blocks_` needs further investigation, but the comments suggest `all_blocks_` provides pointer stability.
* **`op_to_block_`:**  Maps `OpIndex` to `BlockIndex`. This is crucial for determining which block an operation belongs to.
* **`graph_zone_`:**  A `Zone*` implies custom memory management within this graph. V8 uses Zones for efficient allocation and deallocation of related objects.
* **`source_positions_`, `operation_origins_`, `operation_types_`:**  These `GrowingOpIndexSidetable`s store auxiliary information about operations – where they came from in the source, their original index, and their type.
* **`dominator_tree_depth_`:**  Relates to compiler optimizations that rely on understanding the control flow structure.
* **`companion_`:**  The concept of a "companion graph" is interesting. The `SwapWithCompanion` method suggests this is used for multi-pass compilation or analysis.
* **Methods like `NewOperation`, `NewBlock`, `Bind`, `Finalize`:** These are the core building blocks for constructing the graph.
* **Methods related to blocks (`blocks`, `IsLoopBackedge`, `ReorderBlocks`):**  These manipulate and query the block structure.
* **Debug-related members (`block_type_refinement_`, `generation_`, `IsCreatedFromTurbofan`):** Useful for development and debugging the compiler.
* **Phase-specific data (`loop_unrolling_analyzer_`, `stack_checks_to_remove_`):**  These are temporary data used during specific compiler optimization phases.

**3. Answering the Specific Questions:**

* **Functionality:** Based on the above analysis, I can list the core functionalities: creating and managing operations and blocks, tracking control flow, storing metadata, supporting multi-pass compilation, and providing utilities for analysis and optimization.
* **`.tq` Extension:** The code explicitly checks for this. If `graph.h` were `graph.tq`, it would be a Torque source file.
* **JavaScript Relation:** I need to find concepts in this C++ code that directly correspond to JavaScript. Control flow (if/else, loops) is a key area. Operations like arithmetic, function calls, and comparisons also have JavaScript equivalents. I'll construct simple JavaScript examples and map them to the underlying graph concepts.
* **Code Logic Inference:** The `IsLoopBackedge` function provides a clear example. I can create a hypothetical graph structure and trace the logic. Dominator tree calculation is more complex but can be mentioned conceptually.
* **Common Programming Errors:**  The focus on memory management and correct graph construction suggests potential errors like using invalid `OpIndex` values or creating inconsistent graph structures.
* **Summarization (Part 2):**  This section requires synthesizing the information from the previous steps and focusing on the overarching purpose of the `graph.h` file.

**4. Refinement and Examples:**

* **JavaScript Examples:**  Keep them simple and clearly illustrate the connection to the graph. Focus on the control flow and basic operations.
* **Code Logic Example:** Choose a manageable example like `IsLoopBackedge`. Provide a clear input (a `GotoOp` and the graph) and expected output (true/false).
* **Common Errors:**  Focus on errors that a developer *implementing* or *manipulating* the graph might make, not general JavaScript errors.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe `all_blocks_` stores all blocks, and `bound_blocks_` only stores the ones that are part of the finalized graph structure.
* **Correction based on comments:**  The comments indicate `all_blocks_` is for pointer stability. `bound_blocks_` seems to be the main collection of blocks in the current graph structure.
* **Initial thought:** Focus heavily on individual operations.
* **Correction:**  Recognize the importance of control flow blocks and how they structure the operations. The interaction between operations and blocks is key.
* **Initial thought:**  Provide very technical explanations of every detail.
* **Correction:**  Balance technical accuracy with clarity for someone who might not be a V8 internals expert. Use simpler language where possible.

By following this structured approach, I can systematically analyze the C++ header file and generate a comprehensive and accurate answer to the prompt. The process involves understanding the purpose, dissecting the components, connecting them to relevant concepts, and generating clear examples.
## 功能列表 (功能归纳在最后)

这个头文件 `v8/src/compiler/turboshaft/graph.h` 定义了 Turboshaft 编译器的核心数据结构：`Graph` 类。它用于表示程序执行的控制流图和数据流图。以下是它的主要功能：

1. **表示控制流图 (CFG):**
   - **`Block` 类:** 代表控制流图中的基本块，包含一系列的操作。
   - **`bound_blocks_`:** 一个 `ZoneVector`，存储了图中已绑定的 `Block` 指针，表示当前图中的所有有效基本块。
   - **`all_blocks_` 和 `next_block_`:**  用于高效分配和管理 `Block` 对象，提供指针稳定性。
   - **`NewBlock()`:** 创建新的 `Block` 对象。
   - **`Bind()`:** 将操作添加到指定的 `Block` 中，并更新操作到块的映射 (`op_to_block_`)。
   - **`FinalizeBlock()`:** 完成对一个 `Block` 的构建。
   - **`GotoOp` 和 `IsLoopBackedge()`:** 用于表示和判断控制流转移，特别是循环的后沿边。
   - **`ReorderBlocks()`:** 允许重新排列基本块的顺序，这在某些优化阶段很有用。
   - **支配树相关 (`ComputeDominator()`):** 提供计算和存储基本块之间支配关系的功能，用于后续的优化。

2. **表示数据流图 (DFG):**
   - **`Operation` 类 (在其他文件中定义，但通过 `Graph` 管理):** 代表程序执行的各种操作 (例如，加法、乘法、函数调用等)。
   - **`operations_`:** 一个 `OperationBuffer`，存储图中的所有 `Operation` 对象。
   - **`NewOperation()`:** 创建新的 `Operation` 对象，并添加到图中。
   - **`Get()`:**  通过 `OpIndex` 获取 `Operation` 对象。
   - **`inputs()`:**  获取操作的输入操作。
   - **`IncrementInputUses()` 和 `DecrementInputUses()`:** 跟踪操作的被使用次数。
   - **`operation_origins_`:**  记录操作的原始来源 `OpIndex`，可能用于调试或回溯。
   - **`operation_types_`:** 存储每个操作的类型信息。

3. **操作索引和块索引管理:**
   - **`OpIndex`:** 用于唯一标识图中的每个 `Operation`。
   - **`BlockIndex`:** 用于唯一标识图中的每个 `Block`。
   - **`op_to_block_`:**  将 `OpIndex` 映射到所属的 `BlockIndex`。
   - **`IsValid()`:** 检查 `OpIndex` 是否有效。

4. **元数据存储:**
   - **`source_positions_`:**  存储每个操作对应的源代码位置信息，用于调试和错误报告。
   - **调试信息 (`block_type_refinement_`, `generation_`, `IsCreatedFromTurbofan()`):**  在 DEBUG 模式下存储额外的调试信息，例如块的类型细化信息和图的生成信息。

5. **支持图的转换和优化:**
   - **`companion_` 和 `GetOrCreateCompanion()`:**  支持创建和获取一个“伴随图”，用于多趟编译或分析。
   - **`SwapWithCompanion()`:** 将当前图与它的伴随图交换内容，用于在编译的不同阶段之间传递数据。
   - **特定阶段的数据存储 (`loop_unrolling_analyzer_`, `stack_checks_to_remove_`):**  为特定的优化阶段存储临时数据。

6. **迭代器支持:**
   - **`operations()`:**  提供迭代器以遍历块中的操作。
   - **`blocks()`:** 提供迭代器以遍历图中的所有块。
   - **`PredecessorIterator`:** 用于遍历块的前驱。

## 功能归纳

总而言之，`v8/src/compiler/turboshaft/graph.h` 定义了 Turboshaft 编译器用于表示和操作程序中间表示的核心数据结构 `Graph`。它提供了创建、连接、查询和修改控制流图和数据流图的工具，并包含用于存储元数据、支持图转换和优化的机制。

## 关于 .tq 结尾

如果 `v8/src/compiler/turboshaft/graph.h` 以 `.tq` 结尾，那么它将是 **V8 Torque 源代码**。 Torque 是 V8 用于定义运行时内置函数和编译器内部操作的一种领域特定语言。

## 与 JavaScript 的关系 (及示例)

`Graph` 类以及它所表示的控制流和数据流图，直接对应着 JavaScript 代码的执行流程和数据操作。编译器会将 JavaScript 代码转换为这种中间表示，以便进行分析、优化和最终的代码生成。

**JavaScript 示例:**

```javascript
function add(a, b) {
  if (a > 0) {
    return a + b;
  } else {
    return b;
  }
}

let result = add(5, 2);
```

**在 `Graph` 中的表示 (概念性):**

- **块 (Blocks):**
    - **入口块:**  包含 `add` 函数的开始。
    - **条件块:**  包含 `a > 0` 的比较操作。
    - **Then 块:**  包含 `return a + b` 的操作。
    - **Else 块:**  包含 `return b` 的操作。
    - **出口块:** `add` 函数的结束。
- **操作 (Operations):**
    - **LoadLocal:** 加载局部变量 `a` 和 `b`。
    - **GreaterThan:**  执行 `a > 0` 的比较。
    - **Branch:** 根据比较结果跳转到 Then 块或 Else 块。
    - **Add:** 执行 `a + b` 的加法。
    - **Return:** 返回值。
    - **Constant:** 表示常量值 (例如 `0`, `5`, `2`)。
    - **Call:** 调用 `add` 函数。
    - **StoreGlobal:** 将结果存储到全局变量 `result`。

**对应关系:**

- JavaScript 的控制流语句 (`if`, `else`) 会被转换为图中的基本块和控制流转移操作 (`Branch`, `GotoOp`)。
- JavaScript 的表达式 (`a + b`, `a > 0`) 会被转换为图中的算术运算操作 (`Add`) 和比较运算操作 (`GreaterThan`)。
- JavaScript 的变量访问会转换为图中的加载和存储操作 (`LoadLocal`, `StoreGlobal`)。
- JavaScript 的函数调用会转换为图中的调用操作 (`Call`).

## 代码逻辑推理 (假设输入与输出)

**假设输入:** 考虑一个简单的 JavaScript `if` 语句：

```javascript
function test(x) {
  if (x > 10) {
    return true;
  } else {
    return false;
  }
}
```

**在 `Graph` 中构建后，当执行到 `IsLoopBackedge()` 时:**

**假设场景:**  我们有一个 `GotoOp` 操作，其 `destination` 指向一个块 `B1`，该块 `B1` 的起始操作索引小于或等于 `GotoOp` 自身的索引。

**输入:**
- `op`: 一个 `GotoOp` 对象，其 `destination` 指向块 `B1`。
- `op.destination->begin()`: 块 `B1` 的起始操作索引，例如 `OpIndex(5)`.
- `Index(op)`:  `GotoOp` 自身的索引，例如 `OpIndex(10)`.

**代码逻辑:**
`IsLoopBackedge(op)` 函数会执行以下操作：
1. `DCHECK(op.destination->IsBound());`: 确保目标块已绑定 (有效)。
2. `return op.destination->begin() <= Index(op);`: 比较目标块的起始索引和 `GotoOp` 的索引。

**输出:**
在这种情况下，`5 <= 10` 为真，因此 `IsLoopBackedge()` 将返回 `true`。这表示该 `GotoOp` 构成一个循环的后沿边。

**另一种场景 (非循环后沿边):**

**输入:**
- `op`: 一个 `GotoOp` 对象，其 `destination` 指向块 `B2`。
- `op.destination->begin()`: 块 `B2` 的起始操作索引，例如 `OpIndex(15)`.
- `Index(op)`:  `GotoOp` 自身的索引，例如 `OpIndex(10)`.

**输出:**
在这种情况下，`15 <= 10` 为假，因此 `IsLoopBackedge()` 将返回 `false`。这表示该 `GotoOp` 不是循环的后沿边，可能只是一个普通的控制流转移。

## 用户常见的编程错误 (涉及 `Graph` 的使用)

直接操作 `v8/src/compiler/turboshaft/graph.h` 中定义的 `Graph` 类通常是 V8 编译器内部开发人员的任务，普通 JavaScript 开发者不会直接接触到它。然而，如果开发者需要扩展或修改 Turboshaft 编译器，可能会遇到以下编程错误：

1. **使用无效的 `OpIndex` 或 `BlockIndex`:**
   - **示例:**  尝试访问一个已删除或尚未创建的操作或块。
   - **后果:**  可能导致程序崩溃或产生未定义的行为。
   - **C++ 代码示例 (假设错误):**
     ```c++
     Graph* graph = ...;
     OpIndex invalid_index(999); // 假设图中没有这个索引
     const Operation& op = graph->Get(invalid_index); // 错误：访问无效索引
     ```

2. **在块绑定后尝试修改块结构:**
   - **示例:**  在 `FinalizeBlock()` 被调用后，尝试向块中添加新的操作或修改其控制流转移。
   - **后果:**  可能破坏图的完整性，导致后续的分析或优化出错。
   - **C++ 代码示例 (假设错误):**
     ```c++
     Graph* graph = ...;
     Block* block = graph->NewBlock();
     // 添加一些操作到 block
     graph->FinalizeBlock(block);
     Operation* new_op = graph->NewOperation(...);
     graph->Bind(new_op, block); // 错误：在 finalize 后尝试绑定
     ```

3. **不正确地更新操作的使用计数:**
   - **示例:**  在替换或删除一个操作时，忘记更新其输入操作的使用计数。
   - **后果:**  可能导致垃圾回收或后续优化阶段出现问题，因为引用计数不准确。
   - **C++ 代码示例 (假设错误):**
     ```c++
     Graph* graph = ...;
     OpIndex op_index = ...;
     Operation& op_to_replace = graph->Get(op_index);
     OpIndex input_index = *op_to_replace.inputs().begin();
     // ... 创建 replacement_op ...
     // 假设直接替换操作，但忘记更新输入的使用计数
     graph->operations_[op_index] = replacement_op;
     ```

4. **在不适当的时候调用 `SwapWithCompanion()`:**
   - **示例:**  在某些编译阶段中间，假设某些数据结构的状态是特定的，但由于错误的 `SwapWithCompanion()` 调用，状态被意外更改。
   - **后果:**  可能导致编译过程中的逻辑错误。

5. **内存管理错误 (虽然 `Zone` 有助于减轻这个问题):**
   - **示例:**  手动分配了内存，但忘记释放，或者尝试访问已释放的内存。
   - **后果:**  内存泄漏或程序崩溃。

这些错误通常需要在对 V8 编译器内部结构和 Turboshaft 的工作原理有深入了解的情况下才能避免。`DCHECK` 宏在开发和调试过程中可以帮助检测这些错误。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/graph.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/graph.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
bound_blocks_.size())};
  }
  base::iterator_range<base::DerefPtrIterator<const Block>> blocks() const {
    return {base::DerefPtrIterator<const Block>(bound_blocks_.data()),
            base::DerefPtrIterator<const Block>(bound_blocks_.data() +
                                                bound_blocks_.size())};
  }
  const ZoneVector<Block*>& blocks_vector() const { return bound_blocks_; }

  bool IsLoopBackedge(const GotoOp& op) const {
    DCHECK(op.destination->IsBound());
    return op.destination->begin() <= Index(op);
  }

  bool IsValid(OpIndex i) const { return i < next_operation_index(); }

  const GrowingOpIndexSidetable<SourcePosition>& source_positions() const {
    return source_positions_;
  }
  GrowingOpIndexSidetable<SourcePosition>& source_positions() {
    return source_positions_;
  }

  const GrowingOpIndexSidetable<OpIndex>& operation_origins() const {
    return operation_origins_;
  }
  GrowingOpIndexSidetable<OpIndex>& operation_origins() {
    return operation_origins_;
  }

  uint32_t DominatorTreeDepth() const { return dominator_tree_depth_; }

  const GrowingOpIndexSidetable<Type>& operation_types() const {
    return operation_types_;
  }
  GrowingOpIndexSidetable<Type>& operation_types() { return operation_types_; }
#ifdef DEBUG
  // Store refined types per block here for --trace-turbo printing.
  // TODO(nicohartmann@): Remove this once we have a proper way to print
  // type information inside the reducers.
  using TypeRefinements = std::vector<std::pair<OpIndex, Type>>;
  const GrowingBlockSidetable<TypeRefinements>& block_type_refinement() const {
    return block_type_refinement_;
  }
  GrowingBlockSidetable<TypeRefinements>& block_type_refinement() {
    return block_type_refinement_;
  }
#endif  // DEBUG

  void ReorderBlocks(base::Vector<uint32_t> permutation) {
    DCHECK_EQ(permutation.size(), bound_blocks_.size());
    block_permutation_.resize(bound_blocks_.size());
    std::swap(block_permutation_, bound_blocks_);

    for (size_t i = 0; i < permutation.size(); ++i) {
      DCHECK_LE(0, permutation[i]);
      DCHECK_LT(permutation[i], block_permutation_.size());
      bound_blocks_[i] = block_permutation_[permutation[i]];
      bound_blocks_[i]->index_ = BlockIndex(static_cast<uint32_t>(i));
    }
  }

  Graph& GetOrCreateCompanion() {
    if (!companion_) {
      companion_ = graph_zone_->New<Graph>(graph_zone_, operations_.size());
#ifdef DEBUG
      companion_->generation_ = generation_ + 1;
      if (IsCreatedFromTurbofan()) companion_->SetCreatedFromTurbofan();
#endif  // DEBUG
    }
    return *companion_;
  }

  // Swap the graph with its companion graph to turn the output of one phase
  // into the input of the next phase.
  void SwapWithCompanion() {
    Graph& companion = GetOrCreateCompanion();
    std::swap(operations_, companion.operations_);
    std::swap(bound_blocks_, companion.bound_blocks_);
    std::swap(all_blocks_, companion.all_blocks_);
    std::swap(next_block_, companion.next_block_);
    std::swap(block_permutation_, companion.block_permutation_);
    std::swap(graph_zone_, companion.graph_zone_);
    op_to_block_.SwapData(companion.op_to_block_);
    source_positions_.SwapData(companion.source_positions_);
    operation_origins_.SwapData(companion.operation_origins_);
    operation_types_.SwapData(companion.operation_types_);
#ifdef DEBUG
    std::swap(block_type_refinement_, companion.block_type_refinement_);
    // Update generation index.
    DCHECK_EQ(generation_ + 1, companion.generation_);
    generation_ = companion.generation_++;
#endif  // DEBUG
    // Reseting phase-specific fields.
    loop_unrolling_analyzer_ = nullptr;
    stack_checks_to_remove_.clear();
  }

#ifdef DEBUG
  size_t generation() const { return generation_; }
  int generation_mod2() const { return generation_ % 2; }

  bool BelongsToThisGraph(OpIndex idx) const {
    return idx.generation_mod2() == generation_mod2();
  }

  void SetCreatedFromTurbofan() { graph_created_from_turbofan_ = true; }
  bool IsCreatedFromTurbofan() const { return graph_created_from_turbofan_; }
#endif  // DEBUG

  void set_loop_unrolling_analyzer(
      LoopUnrollingAnalyzer* loop_unrolling_analyzer) {
    DCHECK_NULL(loop_unrolling_analyzer_);
    loop_unrolling_analyzer_ = loop_unrolling_analyzer;
  }
  void clear_loop_unrolling_analyzer() { loop_unrolling_analyzer_ = nullptr; }
  LoopUnrollingAnalyzer* loop_unrolling_analyzer() const {
    DCHECK_NOT_NULL(loop_unrolling_analyzer_);
    return loop_unrolling_analyzer_;
  }
#ifdef DEBUG
  bool has_loop_unrolling_analyzer() const {
    return loop_unrolling_analyzer_ != nullptr;
  }
#endif

  void clear_stack_checks_to_remove() { stack_checks_to_remove_.clear(); }
  ZoneAbslFlatHashSet<uint32_t>& stack_checks_to_remove() {
    return stack_checks_to_remove_;
  }
  const ZoneAbslFlatHashSet<uint32_t>& stack_checks_to_remove() const {
    return stack_checks_to_remove_;
  }

 private:
  bool InputsValid(const Operation& op) const {
    for (OpIndex i : op.inputs()) {
      if (!IsValid(i)) return false;
    }
    return true;
  }

  template <class Op>
  void IncrementInputUses(const Op& op) {
    for (OpIndex input : op.inputs()) {
      // Tuples should never be used as input, except in other tuples (which is
      // used for instance in Int64Lowering::LowerCall).
      DCHECK_IMPLIES(Get(input).Is<TupleOp>(), op.template Is<TupleOp>());
      Get(input).saturated_use_count.Incr();
    }
  }

  template <class Op>
  void DecrementInputUses(const Op& op) {
    for (OpIndex input : op.inputs()) {
      // Tuples should never be used as input, except in other tuples (which is
      // used for instance in Int64Lowering::LowerCall).
      DCHECK_IMPLIES(Get(input).Is<TupleOp>(), op.template Is<TupleOp>());
      Get(input).saturated_use_count.Decr();
    }
  }

  // Allocates pointer-stable storage for new blocks, and pushes the pointers
  // to that storage to `bound_blocks_`. Initialization of the blocks is defered
  // to when they are actually constructed in `NewBlocks`.
  V8_NOINLINE V8_PRESERVE_MOST void AllocateNewBlocks() {
    constexpr size_t kMinCapacity = 32;
    size_t next_capacity = std::max(kMinCapacity, all_blocks_.size() * 2);
    size_t new_block_count = next_capacity - all_blocks_.size();
    DCHECK_GT(new_block_count, 0);
    base::Vector<Block> block_storage =
        graph_zone_->AllocateVector<Block>(new_block_count);
    base::Vector<Block*> new_all_blocks =
        graph_zone_->AllocateVector<Block*>(next_capacity);
    DCHECK_EQ(new_all_blocks.size(), all_blocks_.size() + new_block_count);
    std::copy(all_blocks_.begin(), all_blocks_.end(), new_all_blocks.begin());
    Block** insert_begin = new_all_blocks.begin() + all_blocks_.size();
    DCHECK_EQ(insert_begin + new_block_count, new_all_blocks.end());
    for (size_t i = 0; i < new_block_count; ++i) {
      insert_begin[i] = &block_storage[i];
    }
    base::Vector<Block*> old_all_blocks = all_blocks_;
    all_blocks_ = new_all_blocks;
    if (!old_all_blocks.empty()) {
      graph_zone_->DeleteArray(old_all_blocks.data(), old_all_blocks.length());
    }

    // Eventually most new blocks will be bound anyway, so pre-allocate as well.
    DCHECK_LE(bound_blocks_.size(), all_blocks_.size());
    bound_blocks_.reserve(all_blocks_.size());
  }

  OperationBuffer operations_;
  ZoneVector<Block*> bound_blocks_;
  // The next two fields essentially form a `ZoneVector` but with pointer
  // stability for the `Block` elements. That is, `all_blocks_` contains
  // pointers to (potentially non-contiguous) Zone-allocated `Block`s.
  // Each pointer in `all_blocks_` points to already allocated space, but they
  // are only properly value-initialized up to index `next_block_`.
  base::Vector<Block*> all_blocks_;
  size_t next_block_ = 0;
  GrowingOpIndexSidetable<BlockIndex> op_to_block_;
  // When `ReorderBlocks` is called, `block_permutation_` contains the original
  // order of blocks in order to provide a proper OpIndex->Block mapping for
  // `BlockOf`. In non-reordered graphs, this vector is empty.
  ZoneVector<Block*> block_permutation_;
  Zone* graph_zone_;
  GrowingOpIndexSidetable<SourcePosition> source_positions_;
  GrowingOpIndexSidetable<OpIndex> operation_origins_;
  uint32_t dominator_tree_depth_ = 0;
  GrowingOpIndexSidetable<Type> operation_types_;
#ifdef DEBUG
  GrowingBlockSidetable<TypeRefinements> block_type_refinement_;
  bool graph_created_from_turbofan_ = false;
#endif

  Graph* companion_ = nullptr;
#ifdef DEBUG
  size_t generation_ = 1;
#endif  // DEBUG

  // Phase specific data.
  // For some reducers/phases, we use the graph to pass data around. These data
  // should always be invalidated at the end of the graph copy.

  LoopUnrollingAnalyzer* loop_unrolling_analyzer_ = nullptr;

  // {stack_checks_to_remove_} contains the BlockIndex of loop headers whose
  // stack checks should be removed.
  // TODO(dmercadier): using the Zone for a resizable structure is not great
  // (because it tends to waste memory), but using a newed/malloced structure in
  // the Graph means that we have to remember to delete/free it, which isn't
  // convenient, because Zone memory typically isn't manually deleted (and the
  // Graph thus isn't). Still, it's probably not a big deal, because
  // {stack_checks_to_remove_} should never contain more than a handful of
  // items, and thus shouldn't waste too much memory.
  ZoneAbslFlatHashSet<uint32_t> stack_checks_to_remove_;
};

V8_INLINE OperationStorageSlot* AllocateOpStorage(Graph* graph,
                                                  size_t slot_count) {
  return graph->Allocate(slot_count);
}

V8_INLINE const Operation& Get(const Graph& graph, OpIndex index) {
  return graph.Get(index);
}

V8_INLINE const Operation& Block::FirstOperation(const Graph& graph) const {
  DCHECK_EQ(graph_generation_, graph.generation());
  DCHECK(begin_.valid());
  DCHECK(end_.valid());
  return graph.Get(begin_);
}

V8_INLINE const Operation& Block::LastOperation(const Graph& graph) const {
  DCHECK_EQ(graph_generation_, graph.generation());
  return graph.Get(graph.PreviousIndex(end()));
}

V8_INLINE Operation& Block::LastOperation(Graph& graph) const {
  DCHECK_EQ(graph_generation_, graph.generation());
  return graph.Get(graph.PreviousIndex(end()));
}

V8_INLINE bool Block::HasPhis(const Graph& graph) const {
  // TODO(dmercadier): consider re-introducing the invariant that Phis are
  // always at the begining of a block to speed up such functions. Currently,
  // in practice, Phis do not appear after the first non-FrameState non-Constant
  // operation, but this is not enforced.
  DCHECK_EQ(graph_generation_, graph.generation());
  for (const auto& op : graph.operations(*this)) {
    if (op.Is<PhiOp>()) return true;
  }
  return false;
}

struct PrintAsBlockHeader {
  const Block& block;
  BlockIndex block_id;

  explicit PrintAsBlockHeader(const Block& block)
      : block(block), block_id(block.index()) {}
  PrintAsBlockHeader(const Block& block, BlockIndex block_id)
      : block(block), block_id(block_id) {}
};
V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           PrintAsBlockHeader block);
V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           const Graph& graph);
V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           const Block::Kind& kind);

inline uint32_t Block::ComputeDominator() {
  if (V8_UNLIKELY(LastPredecessor() == nullptr)) {
    // If the block has no predecessors, then it's the start block. We create a
    // jmp_ edge to itself, so that the SetDominator algorithm does not need a
    // special case for when the start block is reached.
    SetAsDominatorRoot();
  } else {
    // If the block has one or more predecessors, the dominator is the lowest
    // common ancestor (LCA) of all of the predecessors.

    // Note that for BranchTarget, there is a single predecessor. This doesn't
    // change the logic: the loop won't be entered, and the first (and only)
    // predecessor is set as the dominator.
    // Similarly, since we compute dominators on the fly, when we reach a
    // kLoopHeader, we haven't visited its body yet, and it should only have one
    // predecessor (the backedge is not here yet), which is its dominator.
    DCHECK_IMPLIES(kind_ == Block::Kind::kLoopHeader, PredecessorCount() == 1);

    Block* dominator = LastPredecessor();
    for (Block* pred = dominator->NeighboringPredecessor(); pred != nullptr;
         pred = pred->NeighboringPredecessor()) {
      dominator = dominator->GetCommonDominator(pred);
    }
    SetDominator(dominator);
  }
  DCHECK_NE(jmp_, nullptr);
  DCHECK_IMPLIES(nxt_ == nullptr, LastPredecessor() == nullptr);
  DCHECK_IMPLIES(len_ == 0, LastPredecessor() == nullptr);
  return Depth();
}

template <class Derived>
inline void RandomAccessStackDominatorNode<Derived>::SetAsDominatorRoot() {
  jmp_ = static_cast<Derived*>(this);
  nxt_ = nullptr;
  len_ = 0;
  jmp_len_ = 0;
}

template <class Derived>
inline void RandomAccessStackDominatorNode<Derived>::SetDominator(
    Derived* dominator) {
  DCHECK_NOT_NULL(dominator);
  DCHECK_NULL(static_cast<Block*>(this)->neighboring_child_);
  DCHECK_NULL(static_cast<Block*>(this)->last_child_);
  // Determining the jmp pointer
  Derived* t = dominator->jmp_;
  if (dominator->len_ - t->len_ == t->len_ - t->jmp_len_) {
    t = t->jmp_;
  } else {
    t = dominator;
  }
  // Initializing fields
  nxt_ = dominator;
  jmp_ = t;
  len_ = dominator->len_ + 1;
  jmp_len_ = jmp_->len_;
  dominator->AddChild(static_cast<Derived*>(this));
}

template <class Derived>
inline Derived* RandomAccessStackDominatorNode<Derived>::GetCommonDominator(
    RandomAccessStackDominatorNode<Derived>* other) const {
  const RandomAccessStackDominatorNode* a = this;
  const RandomAccessStackDominatorNode* b = other;
  if (b->len_ > a->len_) {
    // Swapping |a| and |b| so that |a| always has a greater length.
    std::swap(a, b);
  }
  DCHECK_GE(a->len_, 0);
  DCHECK_GE(b->len_, 0);

  // Going up the dominators of |a| in order to reach the level of |b|.
  while (a->len_ != b->len_) {
    DCHECK_GE(a->len_, 0);
    if (a->jmp_len_ >= b->len_) {
      a = a->jmp_;
    } else {
      a = a->nxt_;
    }
  }

  // Going up the dominators of |a| and |b| simultaneously until |a| == |b|
  while (a != b) {
    DCHECK_EQ(a->len_, b->len_);
    DCHECK_GE(a->len_, 0);
    if (a->jmp_ == b->jmp_) {
      // We found a common dominator, but we actually want to find the smallest
      // one, so we go down in the current subtree.
      a = a->nxt_;
      b = b->nxt_;
    } else {
      a = a->jmp_;
      b = b->jmp_;
    }
  }

  return static_cast<Derived*>(
      const_cast<RandomAccessStackDominatorNode<Derived>*>(a));
}

}  // namespace v8::internal::compiler::turboshaft

// MSVC needs this definition to know how to deal with the PredecessorIterator.
template <>
class std::iterator_traits<
    v8::internal::compiler::turboshaft::PredecessorIterator> {
 public:
  using iterator_category = std::forward_iterator_tag;
};

#endif  // V8_COMPILER_TURBOSHAFT_GRAPH_H_
```