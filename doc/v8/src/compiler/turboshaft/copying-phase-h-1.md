Response:
The user wants a summary of the functionality of the C++ header file `v8/src/compiler/turboshaft/copying-phase.h`. I need to analyze the code and identify its main purposes and components.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The filename "copying-phase.h" strongly suggests that this code is responsible for copying parts of a graph, likely for optimization or transformation purposes within the Turboshaft compiler. The presence of "Assembler" related functions and the concept of "old graph" and "new graph" reinforces this.

2. **Analyze Key Classes and Methods:**
    * `CopyingPhaseImpl` and `CopyingPhase`: These seem to be the main entry points for running the copying process. They take input graph data and use `TSAssembler`.
    * `CopyingPhaseVisitor`: This class is central to the copying logic. It iterates through the input graph and builds a new one. Key methods within this class are:
        * `VisitBlock()`: Processes individual blocks of the graph.
        * `VisitOp()`: Processes individual operations within a block.
        * `AssembleOutputGraph...()`: A family of methods responsible for translating operations from the old graph to the new graph. These handle different operation types like `Goto`, `Branch`, `Phi`, `Call`, etc.
        * `MapToNewGraph()`:  Crucial for translating references (like block indices and operation indices) from the old graph to the new graph.
        * `CreateOldToNewMapping()`: Records the translation between old and new graph elements.
        * `FixLoopPhis()`:  Handles the specific case of Phi nodes in loops.
    * `TSAssembler`:  This likely provides the interface for building the new graph. It handles the actual creation of new operations and connections.
    * Data structures like `op_mapping_`, `block_mapping_`, `old_opindex_to_variables`: These store the mappings between elements of the old and new graphs, including potential variable assignments.

3. **Identify Key Concepts:**
    * **Graph Copying:** The fundamental operation.
    * **Old Graph vs. New Graph:** The code clearly distinguishes between the original graph and the newly constructed copy.
    * **Assembler:**  The tool used to build the new graph.
    * **Mapping:** The process of translating references from the old graph to the new graph.
    * **Reducers:** The template parameters suggest that the copying phase works in conjunction with other optimization passes (reducers).
    * **Inlining and Cloning:** Techniques used for optimization, particularly for blocks.
    * **Loop Handling:** Special consideration for loops, especially Phi nodes.
    * **Exception Handling:**  The `CheckExceptionOp` and related methods indicate support for handling exceptions during compilation.
    * **Variables:** The use of `MaybeVariable` and related methods suggests a mechanism for tracking and potentially reusing intermediate values.

4. **Connect the Concepts to Functionality:** The `CopyingPhaseVisitor` iterates through the input graph. For each block and operation, it uses the `AssembleOutputGraph...` methods and the `TSAssembler` to create corresponding elements in the new graph. The `MapToNewGraph` and mapping data structures ensure that references are correctly translated. The handling of loops, inlining, and cloning suggests that the copying process is not a simple duplication but involves transformations and optimizations.

5. **Address Specific Requirements:**
    * **`.tq` extension:**  The code itself doesn't suggest a `.tq` extension. It's a C++ header file. This needs to be stated.
    * **JavaScript Relationship:**  Since this is part of the V8 compiler, it directly impacts how JavaScript code is compiled and optimized. A simple example would be demonstrating how a function call might be represented in the intermediate graph.
    * **Code Logic/Input-Output:**  Focus on a key function like `AssembleOutputGraphBranch`. Provide a simple scenario of an `if` statement in the input graph and how it would be translated in the output graph.
    * **Common Programming Errors:** Think about scenarios where graph transformations might introduce errors or unexpected behavior if not handled correctly. Incorrectly mapping variables or not handling control flow properly could be examples.

6. **Structure the Answer:** Organize the information logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the core components and their roles.
    * Address the specific points raised in the prompt (Torque, JavaScript, logic, errors).
    * Finally, provide a concise summary of the overall functionality in the second part of the answer.

7. **Refine and Elaborate:** Ensure clarity and provide sufficient detail without being overly technical. For example, when explaining `MapToNewGraph`, mention the different types of mappings it handles. When discussing reducers, explain their general role in optimization.
```cpp
ndex())) {
      OpIndex index = Asm().output_graph().Index(op);
      const char* prefix;
      if (index == new_index) {
        prefix = "╰─>";
        before_arrow = false;
      } else if (before_arrow) {
        prefix = "│  ";
      } else {
        prefix = "   ";
      }
      std::cout << prefix << " n" << index.id() << ": "
                << PaddingSpace{5 - CountDecimalDigits(index.id())}
                << OperationPrintStyle{Asm().output_graph().Get(index), "#n"}
                << "\n";
      if (op.IsBlockTerminator() && Asm().current_block() &&
          Asm().current_block() != current_block) {
        current_block = &Asm().output_graph().Get(
            BlockIndex(current_block->index().id() + 1));
        std::cout << "new " << PrintAsBlockHeader{*current_block} << "\n";
      }
    }
    std::cout << "\n";
  }
  void TraceBlockFinished() { std::cout << "\n"; }

  // These functions take an operation from the old graph and use the assembler
  // to emit a corresponding operation in the new graph, translating inputs and
  // blocks accordingly.
  V8_INLINE OpIndex AssembleOutputGraphGoto(const GotoOp& op) {
    Block* destination = MapToNewGraph(op.destination);
    if (op.is_backedge) {
      DCHECK(destination->IsBound());
      DCHECK(destination->IsLoop());
      FixLoopPhis(op.destination);
    }
    // It is important that we first fix loop phis and then reduce the `Goto`,
    // because reducing the `Goto` can have side effects, in particular, it can
    // modify affect the SnapshotTable of `VariableReducer`, which is also used
    // by `FixLoopPhis()`.
    Asm().ReduceGoto(destination, op.is_backedge);
    return OpIndex::Invalid();
  }
  V8_INLINE OpIndex AssembleOutputGraphBranch(const BranchOp& op) {
    Block* if_true = MapToNewGraph(op.if_true);
    Block* if_false = MapToNewGraph(op.if_false);
    return Asm().ReduceBranch(MapToNewGraph(op.condition()), if_true, if_false,
                              op.hint);
  }
  OpIndex AssembleOutputGraphSwitch(const SwitchOp& op) {
    base::SmallVector<SwitchOp::Case, 16> cases;
    for (SwitchOp::Case c : op.cases) {
      cases.emplace_back(c.value, MapToNewGraph(c.destination), c.hint);
    }
    return Asm().ReduceSwitch(
        MapToNewGraph(op.input()),
        Asm().graph_zone()->CloneVector(base::VectorOf(cases)),
        MapToNewGraph(op.default_case), op.default_hint);
  }
  OpIndex AssembleOutputGraphPhi(const PhiOp& op) {
    return ResolvePhi(
        op,
        [this](OpIndex ind, int predecessor_index, int old_index = 0) {
          return MapToNewGraph(ind, predecessor_index);
        },
        op.rep);
  }
  OpIndex AssembleOutputGraphPendingLoopPhi(const PendingLoopPhiOp& op) {
    UNREACHABLE();
  }
  V8_INLINE OpIndex AssembleOutputGraphFrameState(const FrameStateOp& op) {
    auto inputs = MapToNewGraph<32>(op.inputs());
    return Asm().ReduceFrameState(base::VectorOf(inputs), op.inlined, op.data);
  }
  OpIndex AssembleOutputGraphCall(const CallOp& op) {
    OpIndex callee = MapToNewGraph(op.callee());
    OptionalOpIndex frame_state = MapToNewGraph(op.frame_state());
    auto arguments = MapToNewGraph<16>(op.arguments());
    return Asm().ReduceCall(callee, frame_state, base::VectorOf(arguments),
                            op.descriptor, op.Effects());
  }
  OpIndex AssembleOutputGraphDidntThrow(const DidntThrowOp& op) {
    const Operation& throwing_operation =
        Asm().input_graph().Get(op.throwing_operation());
    OpIndex result;
    switch (throwing_operation.opcode) {
#define CASE(Name)                                                     \
  case Opcode::k##Name:                                                \
    result = Asm().ReduceInputGraph##Name(                             \
        op.throwing_operation(), throwing_operation.Cast<Name##Op>()); \
    break;
      TURBOSHAFT_THROWING_OPERATIONS_LIST(CASE)
#undef CASE
      default:
        UNREACHABLE();
    }
    return result;
  }

  V<None> AssembleOutputGraphCheckException(const CheckExceptionOp& op) {
    Graph::OpIndexIterator it(op.didnt_throw_block->begin(),
                              &Asm().input_graph());
    Graph::OpIndexIterator end(op.didnt_throw_block->end(),
                               &Asm().input_graph());
    // To translate `CheckException` to the new graph, we reduce the throwing
    // operation (actually it's `DidntThrow` operation, but that triggers the
    // actual reduction) with a catch scope. If the reduction replaces the
    // throwing operation with other throwing operations, all of them will be
    // connected to the provided catch block. The reduction should automatically
    // bind a block that represents non-throwing control flow of the original
    // operation, so we can inline the rest of the `didnt_throw` block.
    {
      CatchScope scope(Asm(), MapToNewGraph(op.catch_block));
      DCHECK(Asm().input_graph().Get(*it).template Is<DidntThrowOp>());
      if (!Asm().InlineOp(*it, op.didnt_throw_block)) {
        return V<None>::Invalid();
      }
      ++it;
    }
    for (; it != end; ++it) {
      // Using `InlineOp` requires that the inlined operation is not emitted
      // multiple times. This is the case here because we just removed the
      // single predecessor of `didnt_throw_block`.
      if (!Asm().InlineOp(*it, op.didnt_throw_block)) {
        break;
      }
    }
    return V<None>::Invalid();
  }

  void CreateOldToNewMapping(OpIndex old_index, OpIndex new_index) {
    DCHECK(old_index.valid());
    DCHECK(Asm().input_graph().BelongsToThisGraph(old_index));
    DCHECK_IMPLIES(new_index.valid(),
                   Asm().output_graph().BelongsToThisGraph(new_index));

    if (current_block_needs_variables_) {
      MaybeVariable var = GetVariableFor(old_index);
      if (!var.has_value()) {
        MaybeRegisterRepresentation rep =
            Asm().input_graph().Get(old_index).outputs_rep().size() == 1
                ? static_cast<const MaybeRegisterRepresentation&>(
                      Asm().input_graph().Get(old_index).outputs_rep()[0])
                : MaybeRegisterRepresentation::None();
        var = Asm().NewLoopInvariantVariable(rep);
        SetVariableFor(old_index, *var);
      }
      Asm().SetVariable(*var, new_index);
      return;
    }

    DCHECK(!op_mapping_[old_index].valid());
    op_mapping_[old_index] = new_index;
  }

  MaybeVariable GetVariableFor(OpIndex old_index) const {
    return old_opindex_to_variables[old_index];
  }

  void SetVariableFor(OpIndex old_index, MaybeVariable var) {
    DCHECK(!old_opindex_to_variables[old_index].has_value());
    old_opindex_to_variables[old_index] = var;
  }

  void FixLoopPhis(Block* input_graph_loop) {
    DCHECK(input_graph_loop->IsLoop());
    Block* output_graph_loop = MapToNewGraph(input_graph_loop);
    DCHECK(output_graph_loop->IsLoop());
    for (const Operation& op : Asm().input_graph().operations(
             input_graph_loop->begin(), input_graph_loop->end())) {
      if (auto* input_phi = op.TryCast<PhiOp>()) {
        OpIndex phi_index =
            MapToNewGraph<true>(Asm().input_graph().Index(*input_phi));
        if (!phi_index.valid() || !output_graph_loop->Contains(phi_index)) {
          // Unused phis are skipped, so they are not be mapped to anything in
          // the new graph. If the phi is reduced to an operation from a
          // different block, then there is no loop phi in the current loop
          // header to take care of.
          continue;
        }
        Asm().FixLoopPhi(*input_phi, phi_index, output_graph_loop);
      }
    }
  }

  Graph& input_graph_;
  OptimizedCompilationInfo* info_ = Asm().data()->info();
  TickCounter* const tick_counter_ = info_ ? &info_->tick_counter() : nullptr;

  const Block* current_input_block_;

  // Mappings from old OpIndices to new OpIndices.
  FixedOpIndexSidetable<OpIndex> op_mapping_;

  // Mappings from old blocks to new blocks.
  FixedBlockSidetable<Block*> block_mapping_;

  // {current_block_needs_variables_} is set to true if the current block should
  // use Variables to map old to new OpIndex rather than just {op_mapping}. This
  // is typically the case when the block has been cloned.
  bool current_block_needs_variables_ = false;

  // When {turn_loop_without_backedge_into_merge_} is true (the default), when
  // processing an input block that ended with a loop backedge but doesn't
  // anymore, the loop header is turned into a regular merge. This can be turned
  // off when unrolling a loop for instance.
  bool turn_loop_without_backedge_into_merge_ = true;

  // Set of Blocks for which Variables should be used rather than
  // {op_mapping}.
  BitVector blocks_needing_variables_;

  // Mapping from old OpIndex to Variables.
  FixedOpIndexSidetable<MaybeVariable> old_opindex_to_variables;

  // When the last operation of a Block is a Goto to a Block with a single
  // predecessor, we always inline the destination into the current block. To
  // avoid making this process recursive (which could lead to stack overflows),
  // we set the variable {block_to_inline_now_} instead. Right after we're done
  // visiting a Block, the function ProcessWaitingCloningAndInlining will inline
  // {block_to_inline_now_} (if it's set) in a non-recursive way.
  Block* block_to_inline_now_ = nullptr;

  // When a Reducer wants to clone a block (for instance,
  // BranchEliminationReducer, in order to remove Phis or to replace a Branch by
  // a Goto), this block is not cloned right away, in order to avoid recursion
  // (which could lead to stack overflows). Instead, we add this block to
  // {blocks_to_clone_}. Right after we're done visiting a Block, the function
  // ProcessWaitingCloningAndInlining will actually clone the blocks in
  // {blocks_to_clone_} in a non-recursive way.
  struct BlockToClone {
    const Block* input_block;
    int added_block_phi_input;
    Block* new_output_block;
  };
  ZoneVector<BlockToClone> blocks_to_clone_;

#ifdef DEBUG
  // Recursively inlining blocks is still allowed (mainly for
  // LoopUnrollingReducer), but it shouldn't be actually recursive. This is
  // checked by the {is_in_recursive_inlining_}, which is set to true while
  // recursively inlining a block. Trying to inline a block while
  // {is_in_recursive_inlining_} is true will lead to a DCHECK failure.
  bool is_in_recursive_inlining_ = false;
#endif
};

template <template <class> class... Reducers>
class TSAssembler;

template <template <class> class... Reducers>
class CopyingPhaseImpl {
 public:
  static void Run(PipelineData* data, Graph& input_graph, Zone* phase_zone,
                  bool trace_reductions = false) {
    TSAssembler<GraphVisitor, Reducers...> phase(
        data, input_graph, input_graph.GetOrCreateCompanion(), phase_zone);
#ifdef DEBUG
    if (trace_reductions) {
      phase.template VisitGraph<true>();
    } else {
      phase.template VisitGraph<false>();
    }
#else
    phase.template VisitGraph<false>();
#endif  // DEBUG
  }
};

template <template <typename> typename... Reducers>
class CopyingPhase {
 public:
  static void Run(PipelineData* data, Zone* phase_zone) {
    Graph& input_graph = data->graph();
    CopyingPhaseImpl<Reducers...>::Run(
        data, input_graph, phase_zone,
        data->info()->turboshaft_trace_reduction());
  }
};

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_COMPILER_TURBOSHAFT_COPYING_PHASE_H_
```

## 功能列举

`v8/src/compiler/turboshaft/copying-phase.h` 定义了 Turboshaft 编译器的复制阶段，其主要功能是：

1. **图的复制 (Graph Copying):**  它负责将一个现有的图（`input_graph`）复制到一个新的图（`output_graph`）。这个过程不仅仅是简单的复制，还涉及到节点的转换和连接。

2. **操作的组装 (Operation Assembly):** 它提供了一系列 `AssembleOutputGraph...` 函数，用于将旧图中的各种操作（如 `Goto`, `Branch`, `Phi`, `Call` 等）转换并添加到新图中。

3. **块的映射 (Block Mapping):**  它维护了旧图的块到新图的块的映射关系 (`block_mapping_`)，确保控制流在复制后仍然正确。

4. **操作的映射 (Operation Mapping):** 它也维护了旧图的操作到新图的操作的映射关系 (`op_mapping_`)，用于跟踪操作的对应关系。

5. **Phi 节点的处理 (Phi Node Handling):** 特别处理了 Phi 节点，尤其是在循环中，通过 `FixLoopPhis` 确保循环的 Phi 节点在新的图中正确连接。

6. **内联和克隆 (Inlining and Cloning):**  支持将块内联到当前块中，以及克隆块并在稍后处理，以避免递归调用。这在优化过程中非常有用。

7. **变量管理 (Variable Management):**  使用 `MaybeVariable` 来管理在复制过程中可能需要的临时变量，尤其是在克隆块时。

8. **异常处理 (Exception Handling):** 包含了处理异常控制流的逻辑，例如 `AssembleOutputGraphCheckException`，用于处理 `try...catch` 结构。

9. **Reducer 集成 (Reducer Integration):**  作为一个编译管道的一部分，它与 Reducer 集成，Reducer 负责对图进行各种优化。

## 关于 .tq 扩展名

如果 `v8/src/compiler/turboshaft/copying-phase.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。 Torque 是一种用于 V8 内部实现的领域特定语言，用于生成高效的 C++ 代码。 然而，根据你提供的文件内容，它是一个 **C++ 头文件** (`.h`)，而不是 Torque 文件。

## 与 JavaScript 的关系

`v8/src/compiler/turboshaft/copying-phase.h` 中实现的功能是 JavaScript 代码编译和优化的核心部分。当 V8 执行 JavaScript 代码时，它会将其转换为中间表示（例如，Turboshaft 的图表示），然后进行各种优化。复制阶段是其中一个重要的环节，用于创建图的副本，以便在不影响原始图的情况下进行进一步的转换和优化。

**JavaScript 示例：**

考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  if (a > 0) {
    return a + b;
  } else {
    return b;
  }
}
```

当 V8 编译这个函数时，Turboshaft 会创建一个表示该函数的图。复制阶段可能会被用来创建一个该图的副本，以便进行诸如分支消除之类的优化。例如，如果编译器可以静态地知道 `a` 总是大于 0，那么 `if` 语句的 `else` 分支可能被消除。

## 代码逻辑推理

**假设输入：** 一个表示以下 JavaScript 代码片段的 Turboshaft 图：

```javascript
let x = 10;
if (x > 5) {
  x = x + 1;
}
return x;
```

该图可能包含以下关键块和操作（简化表示）：

* **Block 1 (Start):** 定义了 `x = 10`。
* **Operation 1:**  比较 `x > 5`。
* **Block 2 (If True):** `x = x + 1`。
* **Block 3 (If False):** （空操作，因为条件总是真）
* **Block 4 (Merge):** 合并 `If True` 和 `If False` 的控制流。
* **Operation 2:** 返回 `x`。

**`CopyingPhase` 的处理：**

当 `CopyingPhase` 处理这个图时，它会创建一个新的图，并逐个复制块和操作。

1. **复制 Block 1:**  在新图中创建一个对应的新块，并复制定义 `x = 10` 的操作。
2. **复制 Operation 1 (比较):** 在新图中创建一个对应的比较操作。
3. **复制 Block 2 (If True):** 在新图中创建一个对应的新块，并复制 `x = x + 1` 的操作。
4. **复制 Block 3 (If False):** 在新图中创建一个对应的新块（可能是空的）。
5. **复制 Block 4 (Merge):** 在新图中创建一个对应的新合并块。
6. **复制 Operation 2 (返回):** 在新图中创建一个返回操作。

**假设输出：**  `CopyingPhase` 创建的新图会与原始图结构相似，但是所有的块和操作都是新创建的实例，并且它们的索引和引用会被更新以指向新图中的元素。例如，旧图中的 Block 1 可能对应新图中的 Block 5，旧图中的 Operation 1 可能对应新图中的 Operation 15，以此类推。`op_mapping_` 和 `block_mapping_` 会记录这些映射关系。

**潜在的优化：**  如果某个 Reducer 在复制之前或之后运行，例如 "分支消除器"，并且它可以确定 `x > 5` 总是为真，那么新图可能被优化为直接执行 `If True` 分支，而跳过 `If False` 分支和合并块。

## 用户常见的编程错误

虽然 `copying-phase.h` 是编译器内部的实现，用户不会直接编写这里的代码，但是理解其背后的原理可以帮助理解一些与性能相关的 JavaScript 编程错误：

1. **过度使用条件语句：**  像示例中的 `if` 语句一样，过多的条件分支可能会导致编译器生成更复杂的控制流图。如果这些分支是可以预测的，编译器可能会优化它们。但是，不可预测的分支可能会导致性能下降，因为 CPU 的分支预测器可能会失效。

   ```javascript
   function process(value) {
     if (value === 1) {
       // ...
     } else if (value === 2) {
       // ...
     } else if (value === 3) {
       // ...
     } // 更多不可预测的条件
   }
   ```

2. **在循环中进行不必要的操作：**  如果循环体过于复杂或包含可以移出循环的不变操作，编译器可能需要创建和复制更复杂的图结构，这可能会影响性能。

   ```javascript
   function loop(arr) {
     for (let i = 0; i < arr.length; i++) {
       const constant = Date.now(); // 每次循环都调用，但值不变
       console.log(arr[i] + constant);
     }
   }
   ```

3. **编写难以预测的代码：**  编译器优化依赖于能够分析和理解代码的行为。编写过于动态或难以静态分析的代码可能会阻止编译器进行有效的优化，例如内联和分支消除。

   ```javascript
   function dynamicDispatch(obj) {
     const methodName = 'doSomething';
     obj[methodName](); // 编译器难以预测实际调用的方法
   }
   ```

## 功能归纳 (第 2 部分)

总而言之，`v8/src/compiler/turboshaft/copying-phase.h` 定义了 Turboshaft 编译器的核心组件，负责将程序代码的中间表示（图）从一种形式复制到另一种形式。这个复制过程是编译器进行各种优化的基础，它不仅复制了图的结构和操作，还维护了新旧图之间的映射关系，并处理了诸如循环、异常和内联等复杂情况。`CopyingPhase` 的目标是创建一个新的、可能经过修改或优化的图，以便后续的编译阶段可以继续处理。它在 V8 优化 JavaScript 代码的过程中扮演着至关重要的角色。

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/copying-phase.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/copying-phase.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
ndex())) {
      OpIndex index = Asm().output_graph().Index(op);
      const char* prefix;
      if (index == new_index) {
        prefix = "╰─>";
        before_arrow = false;
      } else if (before_arrow) {
        prefix = "│  ";
      } else {
        prefix = "   ";
      }
      std::cout << prefix << " n" << index.id() << ": "
                << PaddingSpace{5 - CountDecimalDigits(index.id())}
                << OperationPrintStyle{Asm().output_graph().Get(index), "#n"}
                << "\n";
      if (op.IsBlockTerminator() && Asm().current_block() &&
          Asm().current_block() != current_block) {
        current_block = &Asm().output_graph().Get(
            BlockIndex(current_block->index().id() + 1));
        std::cout << "new " << PrintAsBlockHeader{*current_block} << "\n";
      }
    }
    std::cout << "\n";
  }
  void TraceBlockFinished() { std::cout << "\n"; }

  // These functions take an operation from the old graph and use the assembler
  // to emit a corresponding operation in the new graph, translating inputs and
  // blocks accordingly.
  V8_INLINE OpIndex AssembleOutputGraphGoto(const GotoOp& op) {
    Block* destination = MapToNewGraph(op.destination);
    if (op.is_backedge) {
      DCHECK(destination->IsBound());
      DCHECK(destination->IsLoop());
      FixLoopPhis(op.destination);
    }
    // It is important that we first fix loop phis and then reduce the `Goto`,
    // because reducing the `Goto` can have side effects, in particular, it can
    // modify affect the SnapshotTable of `VariableReducer`, which is also used
    // by `FixLoopPhis()`.
    Asm().ReduceGoto(destination, op.is_backedge);
    return OpIndex::Invalid();
  }
  V8_INLINE OpIndex AssembleOutputGraphBranch(const BranchOp& op) {
    Block* if_true = MapToNewGraph(op.if_true);
    Block* if_false = MapToNewGraph(op.if_false);
    return Asm().ReduceBranch(MapToNewGraph(op.condition()), if_true, if_false,
                              op.hint);
  }
  OpIndex AssembleOutputGraphSwitch(const SwitchOp& op) {
    base::SmallVector<SwitchOp::Case, 16> cases;
    for (SwitchOp::Case c : op.cases) {
      cases.emplace_back(c.value, MapToNewGraph(c.destination), c.hint);
    }
    return Asm().ReduceSwitch(
        MapToNewGraph(op.input()),
        Asm().graph_zone()->CloneVector(base::VectorOf(cases)),
        MapToNewGraph(op.default_case), op.default_hint);
  }
  OpIndex AssembleOutputGraphPhi(const PhiOp& op) {
    return ResolvePhi(
        op,
        [this](OpIndex ind, int predecessor_index, int old_index = 0) {
          return MapToNewGraph(ind, predecessor_index);
        },
        op.rep);
  }
  OpIndex AssembleOutputGraphPendingLoopPhi(const PendingLoopPhiOp& op) {
    UNREACHABLE();
  }
  V8_INLINE OpIndex AssembleOutputGraphFrameState(const FrameStateOp& op) {
    auto inputs = MapToNewGraph<32>(op.inputs());
    return Asm().ReduceFrameState(base::VectorOf(inputs), op.inlined, op.data);
  }
  OpIndex AssembleOutputGraphCall(const CallOp& op) {
    OpIndex callee = MapToNewGraph(op.callee());
    OptionalOpIndex frame_state = MapToNewGraph(op.frame_state());
    auto arguments = MapToNewGraph<16>(op.arguments());
    return Asm().ReduceCall(callee, frame_state, base::VectorOf(arguments),
                            op.descriptor, op.Effects());
  }
  OpIndex AssembleOutputGraphDidntThrow(const DidntThrowOp& op) {
    const Operation& throwing_operation =
        Asm().input_graph().Get(op.throwing_operation());
    OpIndex result;
    switch (throwing_operation.opcode) {
#define CASE(Name)                                                     \
  case Opcode::k##Name:                                                \
    result = Asm().ReduceInputGraph##Name(                             \
        op.throwing_operation(), throwing_operation.Cast<Name##Op>()); \
    break;
      TURBOSHAFT_THROWING_OPERATIONS_LIST(CASE)
#undef CASE
      default:
        UNREACHABLE();
    }
    return result;
  }

  V<None> AssembleOutputGraphCheckException(const CheckExceptionOp& op) {
    Graph::OpIndexIterator it(op.didnt_throw_block->begin(),
                              &Asm().input_graph());
    Graph::OpIndexIterator end(op.didnt_throw_block->end(),
                               &Asm().input_graph());
    // To translate `CheckException` to the new graph, we reduce the throwing
    // operation (actually it's `DidntThrow` operation, but that triggers the
    // actual reduction) with a catch scope. If the reduction replaces the
    // throwing operation with other throwing operations, all of them will be
    // connected to the provided catch block. The reduction should automatically
    // bind a block that represents non-throwing control flow of the original
    // operation, so we can inline the rest of the `didnt_throw` block.
    {
      CatchScope scope(Asm(), MapToNewGraph(op.catch_block));
      DCHECK(Asm().input_graph().Get(*it).template Is<DidntThrowOp>());
      if (!Asm().InlineOp(*it, op.didnt_throw_block)) {
        return V<None>::Invalid();
      }
      ++it;
    }
    for (; it != end; ++it) {
      // Using `InlineOp` requires that the inlined operation is not emitted
      // multiple times. This is the case here because we just removed the
      // single predecessor of `didnt_throw_block`.
      if (!Asm().InlineOp(*it, op.didnt_throw_block)) {
        break;
      }
    }
    return V<None>::Invalid();
  }

  void CreateOldToNewMapping(OpIndex old_index, OpIndex new_index) {
    DCHECK(old_index.valid());
    DCHECK(Asm().input_graph().BelongsToThisGraph(old_index));
    DCHECK_IMPLIES(new_index.valid(),
                   Asm().output_graph().BelongsToThisGraph(new_index));

    if (current_block_needs_variables_) {
      MaybeVariable var = GetVariableFor(old_index);
      if (!var.has_value()) {
        MaybeRegisterRepresentation rep =
            Asm().input_graph().Get(old_index).outputs_rep().size() == 1
                ? static_cast<const MaybeRegisterRepresentation&>(
                      Asm().input_graph().Get(old_index).outputs_rep()[0])
                : MaybeRegisterRepresentation::None();
        var = Asm().NewLoopInvariantVariable(rep);
        SetVariableFor(old_index, *var);
      }
      Asm().SetVariable(*var, new_index);
      return;
    }

    DCHECK(!op_mapping_[old_index].valid());
    op_mapping_[old_index] = new_index;
  }

  MaybeVariable GetVariableFor(OpIndex old_index) const {
    return old_opindex_to_variables[old_index];
  }

  void SetVariableFor(OpIndex old_index, MaybeVariable var) {
    DCHECK(!old_opindex_to_variables[old_index].has_value());
    old_opindex_to_variables[old_index] = var;
  }

  void FixLoopPhis(Block* input_graph_loop) {
    DCHECK(input_graph_loop->IsLoop());
    Block* output_graph_loop = MapToNewGraph(input_graph_loop);
    DCHECK(output_graph_loop->IsLoop());
    for (const Operation& op : Asm().input_graph().operations(
             input_graph_loop->begin(), input_graph_loop->end())) {
      if (auto* input_phi = op.TryCast<PhiOp>()) {
        OpIndex phi_index =
            MapToNewGraph<true>(Asm().input_graph().Index(*input_phi));
        if (!phi_index.valid() || !output_graph_loop->Contains(phi_index)) {
          // Unused phis are skipped, so they are not be mapped to anything in
          // the new graph. If the phi is reduced to an operation from a
          // different block, then there is no loop phi in the current loop
          // header to take care of.
          continue;
        }
        Asm().FixLoopPhi(*input_phi, phi_index, output_graph_loop);
      }
    }
  }

  Graph& input_graph_;
  OptimizedCompilationInfo* info_ = Asm().data()->info();
  TickCounter* const tick_counter_ = info_ ? &info_->tick_counter() : nullptr;

  const Block* current_input_block_;

  // Mappings from old OpIndices to new OpIndices.
  FixedOpIndexSidetable<OpIndex> op_mapping_;

  // Mappings from old blocks to new blocks.
  FixedBlockSidetable<Block*> block_mapping_;

  // {current_block_needs_variables_} is set to true if the current block should
  // use Variables to map old to new OpIndex rather than just {op_mapping}. This
  // is typically the case when the block has been cloned.
  bool current_block_needs_variables_ = false;

  // When {turn_loop_without_backedge_into_merge_} is true (the default), when
  // processing an input block that ended with a loop backedge but doesn't
  // anymore, the loop header is turned into a regular merge. This can be turned
  // off when unrolling a loop for instance.
  bool turn_loop_without_backedge_into_merge_ = true;

  // Set of Blocks for which Variables should be used rather than
  // {op_mapping}.
  BitVector blocks_needing_variables_;

  // Mapping from old OpIndex to Variables.
  FixedOpIndexSidetable<MaybeVariable> old_opindex_to_variables;

  // When the last operation of a Block is a Goto to a Block with a single
  // predecessor, we always inline the destination into the current block. To
  // avoid making this process recursive (which could lead to stack overflows),
  // we set the variable {block_to_inline_now_} instead. Right after we're done
  // visiting a Block, the function ProcessWaitingCloningAndInlining will inline
  // {block_to_inline_now_} (if it's set) in a non-recursive way.
  Block* block_to_inline_now_ = nullptr;

  // When a Reducer wants to clone a block (for instance,
  // BranchEliminationReducer, in order to remove Phis or to replace a Branch by
  // a Goto), this block is not cloned right away, in order to avoid recursion
  // (which could lead to stack overflows). Instead, we add this block to
  // {blocks_to_clone_}. Right after we're done visiting a Block, the function
  // ProcessWaitingCloningAndInlining will actually clone the blocks in
  // {blocks_to_clone_} in a non-recursive way.
  struct BlockToClone {
    const Block* input_block;
    int added_block_phi_input;
    Block* new_output_block;
  };
  ZoneVector<BlockToClone> blocks_to_clone_;

#ifdef DEBUG
  // Recursively inlining blocks is still allowed (mainly for
  // LoopUnrollingReducer), but it shouldn't be actually recursive. This is
  // checked by the {is_in_recursive_inlining_}, which is set to true while
  // recursively inlining a block. Trying to inline a block while
  // {is_in_recursive_inlining_} is true will lead to a DCHECK failure.
  bool is_in_recursive_inlining_ = false;
#endif
};

template <template <class> class... Reducers>
class TSAssembler;

template <template <class> class... Reducers>
class CopyingPhaseImpl {
 public:
  static void Run(PipelineData* data, Graph& input_graph, Zone* phase_zone,
                  bool trace_reductions = false) {
    TSAssembler<GraphVisitor, Reducers...> phase(
        data, input_graph, input_graph.GetOrCreateCompanion(), phase_zone);
#ifdef DEBUG
    if (trace_reductions) {
      phase.template VisitGraph<true>();
    } else {
      phase.template VisitGraph<false>();
    }
#else
    phase.template VisitGraph<false>();
#endif  // DEBUG
  }
};

template <template <typename> typename... Reducers>
class CopyingPhase {
 public:
  static void Run(PipelineData* data, Zone* phase_zone) {
    Graph& input_graph = data->graph();
    CopyingPhaseImpl<Reducers...>::Run(
        data, input_graph, phase_zone,
        data->info()->turboshaft_trace_reduction());
  }
};

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_COMPILER_TURBOSHAFT_COPYING_PHASE_H_

"""


```