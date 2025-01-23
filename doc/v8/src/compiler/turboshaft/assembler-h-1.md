Response:
The user wants to understand the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine's Turboshaft compiler. They have also specified some constraints on the explanation:
1. **List the functionalities:**  Identify what the code does.
2. **Torque source:** Check if the file might be a Torque file (indicated by a `.tq` extension).
3. **JavaScript relation:** If it relates to JavaScript, provide a JavaScript example.
4. **Code logic inference:** For logical parts, provide hypothetical input and output.
5. **Common programming errors:** Point out potential user errors.
6. **Part of a larger set:** This is part 2 of 8, so summarize its contribution within the broader context (though the other parts are not available).

Let's break down the code:

- **Reducer Stack:** The code defines a series of template classes (e.g., `NextReducer`, `TSReducerBase`, `ReducerBaseForwarder`, `GenericReducerBase`). This structure suggests a "reducer stack" pattern, where each class adds or modifies behavior.
- **Turboshaft Operations:**  The code uses terms like `OpIndex`, `Operation`, `PhiOp`, `GotoOp`, `BranchOp`, `SwitchOp`, `CallOp`, etc. These are likely representations of the intermediate operations in the Turboshaft compiler.
- **Code Generation:** The `Emit` method in `TSReducerBase` seems responsible for adding these operations to a graph.
- **Control Flow:**  `GenericReducerBase` handles control flow operations like `Goto`, `Branch`, `Switch`, and loops.
- **Error Handling:** The `CatchBlockBegin` and `CheckException` operations indicate support for exception handling.
- **Data Types:**  The use of `V<T>` suggests a value representation, possibly with metadata. `RegisterRepresentation` hints at how values are represented in registers.
- **Generic Nature:** The extensive use of templates suggests this code is designed to be generic and reusable for different types of operations and representations.

**Plan:**

1. **High-level Functionality:** Summarize the core purpose of this code: defining a framework for building compiler intermediate representations.
2. **Individual Component Functions:** Briefly describe what each major class (`NextReducer`, `TSReducerBase`, etc.) contributes.
3. **Torque Check:** Verify if the filename convention indicates a Torque file.
4. **JavaScript Relation:** Connect the concepts (like function calls, control flow, exception handling) to their JavaScript equivalents.
5. **Code Logic Example:** Choose a simpler logic block (like the `WrapInTupleIfNeeded` function or a basic `Emit` call) and illustrate its behavior with hypothetical inputs.
6. **Common Errors:**  Think about common mistakes related to control flow, incorrect operation usage, or type mismatches based on the code structure.
7. **Part Summary:** Emphasize that this part focuses on the foundational elements of code generation and control flow within the Turboshaft pipeline.
这是一个V8 Turboshaft编译器的源代码文件，定义了构建编译器中间表示（IR）的框架。它通过一系列的模板类来实现，形成一个“reducer”栈，每个reducer负责处理特定类型的操作。

**功能列举：**

1. **定义 Reducer 接口:**  代码定义了一系列的模板类，例如 `NextReducer`, `TSReducerBase`, `ReducerBaseForwarder`, `GenericReducerBase` 等。这些类构成了一个责任链模式的结构，被称为 "reducer 栈"。每个 reducer 负责处理特定类型的操作或提供特定的功能。
2. **Turboshaft 操作的发射 (Emission):**  `TSReducerBase` 类中的 `Emit` 方法负责将 Turboshaft 的操作（例如 `PhiOp`, `GotoOp`, `BranchOp` 等）添加到输出图 (output graph) 中。这相当于在编译过程中构建抽象语法树或中间表示。
3. **控制流处理:** `GenericReducerBase` 类处理控制流相关的操作，例如 `Goto` (跳转), `Branch` (分支), `Switch` (开关语句)。它还负责维护基本块 (Block) 之间的前驱关系，并调用 Assembler 来保持图的 split-edge 形式。
4. **异常处理:** 代码中出现了 `CatchBlockBegin` 和 `CheckException` 相关的操作，表明这个框架支持异常处理的构建。
5. **操作的泛型处理:**  通过模板，这些 reducer 可以处理各种不同类型的操作，增加了代码的灵活性和可复用性。
6. **PHI 节点的处理:** 代码包含了对 `PhiOp` (PHI 节点) 的特殊处理，这在静态单赋值 (SSA) 形式的 IR 中用于合并来自不同控制流路径的值。
7. **Loop 的处理:** 代码中出现了 `PendingLoopPhiOp`，表明它支持循环结构的构建。
8. **数据类型的抽象:** 代码中使用 `V<Any>`, `V<Word32>`, `V<Object>` 等模板化的类型来表示值，这可能是一种对编译器内部值表示的抽象。
9. **操作的元数据:**  代码中涉及到 `OpEffects`，这可能用于描述操作的副作用。

**Torque 源代码判断:**

v8/src/compiler/turboshaft/assembler.h 以 `.h` 结尾，因此它不是一个以 `.tq` 结尾的 V8 Torque 源代码。它是一个 C++ 头文件。

**与 JavaScript 的功能关系以及 JavaScript 示例：**

这段代码是 V8 引擎 Turboshaft 编译器的核心组成部分，它负责将 JavaScript 代码转换成更底层的机器码。它与 JavaScript 的以下功能密切相关：

* **控制流语句 (if/else, loops, switch):** `GenericReducerBase` 中的 `REDUCE(Branch)`, `REDUCE(Switch)`, `REDUCE(Goto)` 等方法直接对应 JavaScript 中的 `if`, `else`, `for`, `while`, `switch` 等控制流语句的编译过程。

   ```javascript
   // JavaScript 示例
   function foo(x) {
     if (x > 10) {
       return x + 1;
     } else {
       return x - 1;
     }
   }
   ```

   在 Turboshaft 编译 `foo` 函数时，`REDUCE(Branch)` 可能会被用来表示 `if (x > 10)` 的分支逻辑，生成两个不同的代码路径。

* **函数调用:** `REDUCE(Call)` 方法处理 JavaScript 函数的调用。

   ```javascript
   // JavaScript 示例
   function bar(a, b) {
     return a * b;
   }

   function baz(c) {
     return bar(c, 5);
   }
   ```

   当编译 `baz` 函数调用 `bar` 时，`REDUCE(Call)` 会被调用，用于生成表示函数调用操作的 IR 节点。

* **异常处理 (try/catch):** `REDUCE(CatchBlockBegin)` 和 `REDUCE(CheckException)` 与 JavaScript 的 `try...catch` 语句相关。

   ```javascript
   // JavaScript 示例
   function handleException() {
     try {
       throw new Error("Something went wrong");
     } catch (e) {
       console.error("Caught an error:", e);
     }
   }
   ```

   在编译 `handleException` 函数时，`REDUCE(CatchBlockBegin)` 会标记 `catch` 代码块的开始，而 `REDUCE(CheckException)` 会在 `try` 代码块中可能抛出异常的地方生成检查异常的操作。

**代码逻辑推理 - 假设输入与输出：**

假设我们正在编译一个简单的 `if` 语句：

```javascript
// 假设的 JavaScript 代码
function testIf(y) {
  if (y > 0) {
    return 1;
  } else {
    return 0;
  }
}
```

当 Turboshaft 编译到 `if (y > 0)` 时，可能会调用 `GenericReducerBase::REDUCE(Branch)`。

**假设输入：**

* `condition`:  表示 `y > 0` 比较结果的 `OpIndex`。假设其 ID 为 10。
* `if_true`: 指向 `return 1;` 代码块的 `Block*` 指针。假设其索引为 B2。
* `if_false`: 指向 `return 0;` 代码块的 `Block*` 指针。假设其索引为 B3。
* `hint`: 可能是一个 `BranchHint`，指示分支预测的信息。

**预期输出：**

`REDUCE(Branch)` 方法会：

1. 调用 `Base::ReduceBranch` (即 `ReducerBaseForwarder::ReduceBranch`)，最终调用 `TSReducerBase::Emit<BranchOp>`，创建一个 `BranchOp` 并添加到输出图中。新创建的 `BranchOp` 的 `OpIndex` 将被返回。 假设其 ID 为 15。
2. 调用 `Asm().AddPredecessor(saved_current_block, if_true, true)`，将当前基本块添加到 `if_true` 代码块 (B2) 的前驱列表中。
3. 调用 `Asm().AddPredecessor(saved_current_block, if_false, true)`，将当前基本块添加到 `if_false` 代码块 (B3) 的前驱列表中。

因此，假设的输出是 `OpIndex`，其 ID 为 15，并且内部输出图会记录下这个分支操作以及基本块之间的连接关系。

**涉及用户常见的编程错误：**

虽然这段代码是编译器内部的，但它反映了 JavaScript 程序员可能犯的错误，例如：

* **无限循环:** 如果编译器生成了错误的 `Goto` 指令，可能会导致程序陷入无限循环。这在 JavaScript 中可能由错误的循环条件或缺少终止条件引起。
* **未捕获的异常:** `CheckException` 的存在表明 JavaScript 中可能抛出未捕获的异常，这段编译器代码负责处理这种控制流。
* **类型错误:** 尽管这段代码没有直接处理 JavaScript 的类型，但编译器需要确保操作的类型一致性。JavaScript 中的类型错误可能会导致编译失败或生成错误的代码。
* **逻辑错误导致错误的控制流:**  `Branch` 和 `Switch` 操作处理控制流，如果 JavaScript 代码中的逻辑有误，编译器会按照错误的逻辑生成代码。

**第2部分的功能归纳：**

作为第2部分，这段代码主要负责构建 Turboshaft 编译器的中间表示 (IR) 的核心框架。它定义了：

* **Reducer 栈的基础结构:**  通过模板类定义了处理编译过程的不同阶段的机制。
* **Turboshaft 操作的发射机制:** 提供了向 IR 图中添加各种操作的方法。
* **基本的控制流操作处理:** 实现了 `Goto`, `Branch`, `Switch` 等控制流语句的编译逻辑。
* **异常处理的基础支持:** 包含了处理 `try...catch` 语句的关键组件。

总而言之，这段代码是 Turboshaft 编译器进行代码生成和控制流建模的关键基础设施，为后续的优化和代码生成阶段奠定了基础。它抽象了底层的操作细节，使得编译器能够以一种结构化的方式处理 JavaScript 代码。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/assembler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/assembler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共8部分，请归纳一下它的功能
```

### 源代码
```c
t Next::CatchBlockBegin is
    // indeed a CatchBlockBegin (which means that the .Cast<> of the generic
    // ReduceOperation could fail on CatchBlockBegin).
    return Next::ReduceCatchBlockBegin();
  }

  template <Opcode opcode, typename Continuation, typename... Args>
  OpIndex ReduceOperation(Args... args) {
    OpIndex new_idx = Continuation{this}.Reduce(args...);
    const Operation& op = Asm().output_graph().Get(new_idx);
    if constexpr (MayThrow(opcode)) {
      // Operations that can throw are lowered to an Op+DidntThrow, and what we
      // get from Next::Reduce is the DidntThrow.
      return WrapInTupleIfNeeded(op.Cast<DidntThrowOp>(), new_idx);
    }
    return WrapInTupleIfNeeded(op.Cast<typename Continuation::Op>(), new_idx);
  }

 private:
  template <class Op>
  V<Any> WrapInTupleIfNeeded(const Op& op, V<Any> idx) {
    if (op.outputs_rep().size() > 1) {
      base::SmallVector<V<Any>, 8> projections;
      auto reps = op.outputs_rep();
      for (int i = 0; i < static_cast<int>(reps.size()); i++) {
        projections.push_back(Asm().Projection(idx, i, reps[i]));
      }
      return Asm().Tuple(base::VectorOf(projections));
    }
    return idx;
  }
};

// This reducer takes care of emitting Turboshaft operations. Ideally, the rest
// of the Assembler stack would be generic, and only TSReducerBase (and
// TurboshaftAssemblerOpInterface) would be Turboshaft-specific.
// TODO(dmercadier): this is currently not quite at the very bottom of the stack
// but actually before ReducerBase and ReducerBaseForwarder. This doesn't
// matter, because Emit should be unique on the reducer stack, but still, it
// would be nice to have the TSReducerBase at the very bottom of the stack.
template <class Next>
class TSReducerBase : public Next {
 public:
  static constexpr bool kIsBottomOfStack = true;
  TURBOSHAFT_REDUCER_GENERIC_BOILERPLATE(TSReducerBase)
  using node_t = OpIndex;
  using block_t = Block;

  template <class Op, class... Args>
  OpIndex Emit(Args... args) {
    static_assert((std::is_base_of<Operation, Op>::value));
    static_assert(!(std::is_same<Op, Operation>::value));
    DCHECK_NOT_NULL(Asm().current_block());
    OpIndex result = Asm().output_graph().next_operation_index();
    Op& op = Asm().output_graph().template Add<Op>(args...);
    Asm().output_graph().operation_origins()[result] =
        Asm().current_operation_origin();
#ifdef DEBUG
    if (v8_flags.turboshaft_trace_intermediate_reductions) {
      std::cout << std::setw(Asm().intermediate_tracing_depth()) << ' ' << "["
                << ReducerName() << "]: emitted " << op << "\n";
    }
    op_to_block_[result] = Asm().current_block();
    DCHECK(ValidInputs(result));
#endif  // DEBUG
    if (op.IsBlockTerminator()) Asm().FinalizeBlock();
    return result;
  }

 private:
#ifdef DEBUG
  GrowingOpIndexSidetable<Block*> op_to_block_{Asm().phase_zone(),
                                               &Asm().output_graph()};

  bool ValidInputs(OpIndex op_idx) {
    const Operation& op = Asm().output_graph().Get(op_idx);
    if (auto* phi = op.TryCast<PhiOp>()) {
      auto pred_blocks = Asm().current_block()->Predecessors();
      for (size_t i = 0; i < phi->input_count; ++i) {
        Block* input_block = op_to_block_[phi->input(i)];
        Block* pred_block = pred_blocks[i];
        if (input_block->GetCommonDominator(pred_block) != input_block) {
          std::cerr << "Input #" << phi->input(i).id()
                    << " does not dominate predecessor B"
                    << pred_block->index().id() << ".\n";
          std::cerr << op_idx.id() << ": " << op << "\n";
          return false;
        }
      }
    } else {
      for (OpIndex input : op.inputs()) {
        Block* input_block = op_to_block_[input];
        if (input_block->GetCommonDominator(Asm().current_block()) !=
            input_block) {
          std::cerr << "Input #" << input.id()
                    << " does not dominate its use.\n";
          std::cerr << op_idx.id() << ": " << op << "\n";
          return false;
        }
      }
    }
    return true;
  }
#endif  // DEBUG
};

namespace detail {
template <typename T>
inline T&& MakeShadowy(T&& value) {
  static_assert(!std::is_same_v<std::remove_reference_t<T>, OpIndex>);
  return std::forward<T>(value);
}
inline ShadowyOpIndex MakeShadowy(OpIndex value) {
  return ShadowyOpIndex{value};
}
template <typename T>
inline ShadowyOpIndex MakeShadowy(V<T> value) {
  return ShadowyOpIndex{value};
}
inline ShadowyOpIndexVectorWrapper MakeShadowy(
    base::Vector<const OpIndex> value) {
  return ShadowyOpIndexVectorWrapper{value};
}
template <typename T>
inline ShadowyOpIndexVectorWrapper MakeShadowy(base::Vector<const V<T>> value) {
  return ShadowyOpIndexVectorWrapper{value};
}
}  // namespace detail

// This empty base-class is used to provide default-implementations of plain
// methods emitting operations.
template <class Next>
class ReducerBaseForwarder : public Next {
 public:
  TURBOSHAFT_REDUCER_BOILERPLATE(ReducerBaseForwarder)

#define EMIT_OP(Name)                                                         \
  OpIndex ReduceInputGraph##Name(OpIndex ig_index, const Name##Op& op) {      \
    return this->Asm().AssembleOutputGraph##Name(op);                         \
  }                                                                           \
  template <class... Args>                                                    \
  OpIndex Reduce##Name(Args... args) {                                        \
    return this->Asm().template Emit<Name##Op>(detail::MakeShadowy(args)...); \
  }
  TURBOSHAFT_OPERATION_LIST(EMIT_OP)
#undef EMIT_OP
};

// GenericReducerBase provides default implementations of Branch-related
// Operations (Goto, Branch, Switch, CheckException), and takes care of updating
// Block predecessors (and calls the Assembler to maintain split-edge form).
// ReducerBase is always added by Assembler at the bottom of the reducer stack.
template <class Next>
class GenericReducerBase : public ReducerBaseForwarder<Next> {
 public:
  TURBOSHAFT_REDUCER_BOILERPLATE(GenericReducerBase)

  using Base = ReducerBaseForwarder<Next>;

  void Bind(Block* block) {}

  // CanAutoInlineBlocksWithSinglePredecessor is used to control whether the
  // CopyingPhase is allowed to automatically inline blocks with a single
  // predecessor or not.
  bool CanAutoInlineBlocksWithSinglePredecessor() const { return true; }

  void Analyze() {}

#ifdef DEBUG
  void Verify(OpIndex old_index, OpIndex new_index) {}
#endif  // DEBUG

  void RemoveLast(OpIndex index_of_last_operation) {
    Asm().output_graph().RemoveLast();
  }

  void FixLoopPhi(const PhiOp& input_phi, OpIndex output_index,
                  Block* output_graph_loop) {
    if (!Asm()
             .output_graph()
             .Get(output_index)
             .template Is<PendingLoopPhiOp>()) {
      return;
    }
    DCHECK(output_graph_loop->Contains(output_index));
    auto& pending_phi = Asm()
                            .output_graph()
                            .Get(output_index)
                            .template Cast<PendingLoopPhiOp>();
#ifdef DEBUG
    DCHECK_EQ(pending_phi.rep, input_phi.rep);
    // The 1st input of the PendingLoopPhi should be the same as the original
    // Phi, except for peeled loops (where it's the same as the 2nd input when
    // computed with the VariableReducer Snapshot right before the loop was
    // emitted).
    DCHECK_IMPLIES(
        pending_phi.first() != Asm().MapToNewGraph(input_phi.input(0)),
        output_graph_loop->has_peeled_iteration());
#endif
    Asm().output_graph().template Replace<PhiOp>(
        output_index,
        base::VectorOf<OpIndex>(
            {pending_phi.first(), Asm().MapToNewGraph(input_phi.input(1))}),
        input_phi.rep);
  }

  OpIndex REDUCE(Phi)(base::Vector<const OpIndex> inputs,
                      RegisterRepresentation rep) {
    DCHECK(Asm().current_block()->IsMerge() &&
           inputs.size() == Asm().current_block()->Predecessors().size());
    return Base::ReducePhi(inputs, rep);
  }

  OpIndex REDUCE(PendingLoopPhi)(OpIndex first, RegisterRepresentation rep) {
    DCHECK(Asm().current_block()->IsLoop());
    return Base::ReducePendingLoopPhi(first, rep);
  }

  V<None> REDUCE(Goto)(Block* destination, bool is_backedge) {
    // Calling Base::Goto will call Emit<Goto>, which will call FinalizeBlock,
    // which will reset {current_block_}. We thus save {current_block_} before
    // calling Base::Goto, as we'll need it for AddPredecessor. Note also that
    // AddPredecessor might introduce some new blocks/operations if it needs to
    // split an edge, which means that it has to run after Base::Goto
    // (otherwise, the current Goto could be inserted in the wrong block).
    Block* saved_current_block = Asm().current_block();
    V<None> new_opindex = Base::ReduceGoto(destination, is_backedge);
    Asm().AddPredecessor(saved_current_block, destination, false);
    return new_opindex;
  }

  OpIndex REDUCE(Branch)(OpIndex condition, Block* if_true, Block* if_false,
                         BranchHint hint) {
    // There should never be a good reason to generate a Branch where both the
    // {if_true} and {if_false} are the same Block. If we ever decide to lift
    // this condition, then AddPredecessor and SplitEdge should be updated
    // accordingly.
    DCHECK_NE(if_true, if_false);
    Block* saved_current_block = Asm().current_block();
    OpIndex new_opindex =
        Base::ReduceBranch(condition, if_true, if_false, hint);
    Asm().AddPredecessor(saved_current_block, if_true, true);
    Asm().AddPredecessor(saved_current_block, if_false, true);
    return new_opindex;
  }

  V<Object> REDUCE(CatchBlockBegin)() {
    Block* current_block = Asm().current_block();
    if (current_block->IsBranchTarget()) {
      DCHECK_EQ(current_block->PredecessorCount(), 1);
      DCHECK_EQ(current_block->LastPredecessor()
                    ->LastOperation(Asm().output_graph())
                    .template Cast<CheckExceptionOp>()
                    .catch_block,
                current_block);
      return Base::ReduceCatchBlockBegin();
    }
    // We are trying to emit a CatchBlockBegin into a block that used to be the
    // catch_block successor but got edge-splitted into a merge. Therefore, we
    // need to emit a phi now and can rely on the predecessors all having a
    // ReduceCatchBlockBegin and nothing else.
    DCHECK(current_block->IsMerge());
    base::SmallVector<OpIndex, 8> phi_inputs;
    for (Block* predecessor : current_block->Predecessors()) {
      V<Object> catch_begin = predecessor->begin();
      DCHECK(Asm().Get(catch_begin).template Is<CatchBlockBeginOp>());
      phi_inputs.push_back(catch_begin);
    }
    return Asm().Phi(base::VectorOf(phi_inputs),
                     RegisterRepresentation::Tagged());
  }

  V<None> REDUCE(Switch)(V<Word32> input, base::Vector<SwitchOp::Case> cases,
                         Block* default_case, BranchHint default_hint) {
#ifdef DEBUG
    // Making sure that all cases and {default_case} are different. If we ever
    // decide to lift this condition, then AddPredecessor and SplitEdge should
    // be updated accordingly.
    std::unordered_set<Block*> seen;
    seen.insert(default_case);
    for (auto switch_case : cases) {
      DCHECK_EQ(seen.count(switch_case.destination), 0);
      seen.insert(switch_case.destination);
    }
#endif
    Block* saved_current_block = Asm().current_block();
    V<None> new_opindex =
        Base::ReduceSwitch(input, cases, default_case, default_hint);
    for (SwitchOp::Case c : cases) {
      Asm().AddPredecessor(saved_current_block, c.destination, true);
    }
    Asm().AddPredecessor(saved_current_block, default_case, true);
    return new_opindex;
  }

  V<Any> REDUCE(Call)(V<CallTarget> callee,
                      OptionalV<turboshaft::FrameState> frame_state,
                      base::Vector<const OpIndex> arguments,
                      const TSCallDescriptor* descriptor, OpEffects effects) {
    V<Any> raw_call =
        Base::ReduceCall(callee, frame_state, arguments, descriptor, effects);
    bool has_catch_block = false;
    if (descriptor->can_throw == CanThrow::kYes) {
      // TODO(nicohartmann@): Unfortunately, we have many descriptors where
      // effects are not set consistently with {can_throw}. We should fix those
      // and reenable this DCHECK.
      // DCHECK(effects.is_required_when_unused());
      effects = effects.RequiredWhenUnused();
      has_catch_block = CatchIfInCatchScope(raw_call);
    }
    return ReduceDidntThrow(raw_call, has_catch_block, &descriptor->out_reps,
                            effects);
  }

  OpIndex REDUCE(FastApiCall)(
      V<FrameState> frame_state, V<Object> data_argument, V<Context> context,
      base::Vector<const OpIndex> arguments,
      const FastApiCallParameters* parameters,
      base::Vector<const RegisterRepresentation> out_reps) {
    OpIndex raw_call = Base::ReduceFastApiCall(
        frame_state, data_argument, context, arguments, parameters, out_reps);
    bool has_catch_block = CatchIfInCatchScope(raw_call);
    return ReduceDidntThrow(raw_call, has_catch_block,
                            &Asm()
                                 .output_graph()
                                 .Get(raw_call)
                                 .template Cast<FastApiCallOp>()
                                 .out_reps,
                            OpEffects().CanCallAnything());
  }

#define REDUCE_THROWING_OP(Name)                                             \
  template <typename... Args>                                                \
  V<Any> Reduce##Name(Args... args) {                                        \
    OpIndex raw_op_index = Base::Reduce##Name(args...);                      \
    bool has_catch_block = CatchIfInCatchScope(raw_op_index);                \
    const Name##Op& raw_op =                                                 \
        Asm().output_graph().Get(raw_op_index).template Cast<Name##Op>();    \
    return ReduceDidntThrow(raw_op_index, has_catch_block, &raw_op.kOutReps, \
                            raw_op.Effects());                               \
  }
  TURBOSHAFT_THROWING_STATIC_OUTPUTS_OPERATIONS_LIST(REDUCE_THROWING_OP)
#undef REDUCE_THROWING_OP

 private:
  // These reduce functions are private, as they should only be emitted
  // automatically by `CatchIfInCatchScope` and `DoNotCatch` defined below and
  // never explicitly.
  using Base::ReduceDidntThrow;
  V<None> REDUCE(CheckException)(V<Any> throwing_operation, Block* successor,
                                 Block* catch_block) {
    // {successor} and {catch_block} should never be the same.  AddPredecessor
    // and SplitEdge rely on this.
    DCHECK_NE(successor, catch_block);
    Block* saved_current_block = Asm().current_block();
    V<None> new_opindex =
        Base::ReduceCheckException(throwing_operation, successor, catch_block);
    Asm().AddPredecessor(saved_current_block, successor, true);
    Asm().AddPredecessor(saved_current_block, catch_block, true);
    return new_opindex;
  }

  bool CatchIfInCatchScope(OpIndex throwing_operation) {
    if (Asm().current_catch_block()) {
      Block* successor = Asm().NewBlock();
      ReduceCheckException(throwing_operation, successor,
                           Asm().current_catch_block());
      Asm().BindReachable(successor);
      return true;
    }
    return false;
  }
};

namespace detail {

template <typename LoopLabel, typename Iterable, typename Iterator,
          typename ValueTuple, size_t... Indices>
auto BuildResultTupleImpl(bool bound, Iterable&& iterable,
                          LoopLabel&& loop_header, Label<> loop_exit,
                          Iterator current_iterator, ValueTuple current_values,
                          std::index_sequence<Indices...>) {
  return std::make_tuple(bound, std::forward<Iterable>(iterable),
                         std::forward<LoopLabel>(loop_header),
                         std::move(loop_exit), current_iterator,
                         std::get<Indices>(current_values)...);
}

template <typename LoopLabel, typename Iterable, typename Iterator,
          typename Value>
auto BuildResultTuple(bool bound, Iterable&& iterable, LoopLabel&& loop_header,
                      Label<> loop_exit, Iterator current_iterator,
                      Value current_value) {
  return std::make_tuple(bound, std::forward<Iterable>(iterable),
                         std::forward<LoopLabel>(loop_header),
                         std::move(loop_exit), current_iterator, current_value);
}

template <typename LoopLabel, typename Iterable, typename Iterator,
          typename... Values>
auto BuildResultTuple(bool bound, Iterable&& iterable, LoopLabel&& loop_header,
                      Label<> loop_exit, Iterator current_iterator,
                      std::tuple<Values...> current_values) {
  static_assert(std::tuple_size_v<Iterator> == sizeof...(Values));
  return BuildResultTupleImpl(bound, std::forward<Iterable>(iterable),
                              std::forward<LoopLabel>(loop_header),
                              std::move(loop_exit), std::move(current_iterator),
                              std::move(current_values),
                              std::make_index_sequence<sizeof...(Values)>{});
}

}  // namespace detail

template <typename Assembler>
class GenericAssemblerOpInterface {
 public:
  using assembler_t = Assembler;
  using block_t = Block;
  assembler_t& Asm() { return *static_cast<assembler_t*>(this); }

  // These methods are used by the assembler macros (BIND, BIND_LOOP, GOTO,
  // GOTO_IF).
  template <typename L>
  auto ControlFlowHelper_Bind(L& label)
      -> base::prepend_tuple_type<bool, typename L::values_t> {
    // LoopLabels need to be bound with `BIND_LOOP` instead of `BIND`.
    static_assert(!L::is_loop);
    return label.Bind(Asm());
  }

  template <typename L>
  auto ControlFlowHelper_BindLoop(L& label)
      -> base::prepend_tuple_type<bool, typename L::values_t> {
    // Only LoopLabels can be bound with `BIND_LOOP`. Otherwise use `BIND`.
    static_assert(L::is_loop);
    return label.BindLoop(Asm());
  }

  template <typename L>
  void ControlFlowHelper_EndLoop(L& label) {
    static_assert(L::is_loop);
    label.EndLoop(Asm());
  }

  template <ForeachIterable<assembler_t> It>
  auto ControlFlowHelper_Foreach(It iterable) {
    // We need to take ownership over the `iterable` instance as we need to make
    // sure that the `ControlFlowHelper_Foreach` and
    // `ControlFlowHelper_EndForeachLoop` functions operate on the same object.
    // This can potentially involve copying the `iterable` if it is not moved to
    // the `FOREACH` macro. `ForeachIterable`s should be cheap to copy and they
    // MUST NOT emit any code in their constructors/destructors.
#ifdef DEBUG
    OpIndex next_index = Asm().output_graph().next_operation_index();
    {
      It temp_copy = iterable;
      USE(temp_copy);
    }
    // Make sure we have not emitted any operations.
    DCHECK_EQ(next_index, Asm().output_graph().next_operation_index());
#endif

    LoopLabelFor<typename It::iterator_type> loop_header(this);
    Label<> loop_exit(this);

    typename It::iterator_type begin = iterable.Begin(Asm());

    ControlFlowHelper_Goto(loop_header, {begin});

    auto bound_and_current_iterator = loop_header.BindLoop(Asm());
    auto [bound] = base::tuple_head<1>(bound_and_current_iterator);
    auto current_iterator = detail::unwrap_unary_tuple(
        base::tuple_drop<1>(bound_and_current_iterator));
    OptionalV<Word32> is_end = iterable.IsEnd(Asm(), current_iterator);
    if (is_end.has_value()) {
      ControlFlowHelper_GotoIf(is_end.value(), loop_exit, {});
    }

    typename It::value_type current_value =
        iterable.Dereference(Asm(), current_iterator);

    return detail::BuildResultTuple(
        bound, std::move(iterable), std::move(loop_header),
        std::move(loop_exit), current_iterator, current_value);
  }

  template <ForeachIterable<assembler_t> It>
  void ControlFlowHelper_EndForeachLoop(
      It iterable, LoopLabelFor<typename It::iterator_type>& header_label,
      Label<>& exit_label, typename It::iterator_type current_iterator) {
    typename It::iterator_type next_iterator =
        iterable.Advance(Asm(), current_iterator);
    ControlFlowHelper_Goto(header_label, {next_iterator});
    ControlFlowHelper_EndLoop(header_label);
    ControlFlowHelper_Bind(exit_label);
  }

  std::tuple<bool, LoopLabel<>, Label<>> ControlFlowHelper_While(
      std::function<V<Word32>()> cond_builder) {
    LoopLabel<> loop_header(this);
    Label<> loop_exit(this);

    ControlFlowHelper_Goto(loop_header, {});

    auto [bound] = loop_header.BindLoop(Asm());
    V<Word32> cond = cond_builder();
    ControlFlowHelper_GotoIfNot(cond, loop_exit, {});

    return std::make_tuple(bound, std::move(loop_header), std::move(loop_exit));
  }

  template <typename L1, typename L2>
  void ControlFlowHelper_EndWhileLoop(L1& header_label, L2& exit_label) {
    static_assert(L1::is_loop);
    static_assert(!L2::is_loop);
    ControlFlowHelper_Goto(header_label, {});
    ControlFlowHelper_EndLoop(header_label);
    ControlFlowHelper_Bind(exit_label);
  }

  template <typename L>
  void ControlFlowHelper_Goto(L& label,
                              const typename L::const_or_values_t& values) {
    auto resolved_values = detail::ResolveAll(Asm(), values);
    label.Goto(Asm(), resolved_values);
  }

  template <typename L>
  void ControlFlowHelper_GotoIf(ConditionWithHint condition, L& label,
                                const typename L::const_or_values_t& values) {
    auto resolved_values = detail::ResolveAll(Asm(), values);
    label.GotoIf(Asm(), condition.condition(), condition.hint(),
                 resolved_values);
  }

  template <typename L>
  void ControlFlowHelper_GotoIfNot(
      ConditionWithHint condition, L& label,
      const typename L::const_or_values_t& values) {
    auto resolved_values = detail::ResolveAll(Asm(), values);
    label.GotoIfNot(Asm(), condition.condition(), condition.hint(),
                    resolved_values);
  }

  struct ControlFlowHelper_IfState {
    block_t* else_block;
    block_t* end_block;
  };

  bool ControlFlowHelper_BindIf(ConditionWithHint condition,
                                ControlFlowHelper_IfState* state) {
    block_t* then_block = Asm().NewBlock();
    state->else_block = Asm().NewBlock();
    state->end_block = Asm().NewBlock();
    Asm().Branch(condition, then_block, state->else_block);
    return Asm().Bind(then_block);
  }

  bool ControlFlowHelper_BindIfNot(ConditionWithHint condition,
                                   ControlFlowHelper_IfState* state) {
    block_t* then_block = Asm().NewBlock();
    state->else_block = Asm().NewBlock();
    state->end_block = Asm().NewBlock();
    Asm().Branch(condition, state->else_block, then_block);
    return Asm().Bind(then_block);
  }

  bool ControlFlowHelper_BindElse(ControlFlowHelper_IfState* state) {
    block_t* else_block = state->else_block;
    state->else_block = nullptr;
    return Asm().Bind(else_block);
  }

  void ControlFlowHelper_FinishIfBlock(ControlFlowHelper_IfState* state) {
    if (Asm().current_block() == nullptr) return;
    Asm().Goto(state->end_block);
  }

  void ControlFlowHelper_EndIf(ControlFlowHelper_IfState* state) {
    if (state->else_block) {
      if (Asm().Bind(state->else_block)) {
        Asm().Goto(state->end_block);
      }
    }
    Asm().Bind(state->end_block);
  }
};

template <typename Assembler>
class TurboshaftAssemblerOpInterface
    : public GenericAssemblerOpInterface<Assembler> {
 public:
  using GenericAssemblerOpInterface<Assembler>::Asm;

  template <typename... Args>
  explicit TurboshaftAssemblerOpInterface(Args... args)
      : GenericAssemblerOpInterface<Assembler>(args...),
        matcher_(Asm().output_graph()) {}

  const OperationMatcher& matcher() const { return matcher_; }

  // Methods to be used by the reducers to reducer operations with the whole
  // reducer stack.

  V<Word32> Word32SignHint(V<Word32> input, Word32SignHintOp::Sign sign) {
    return ReduceIfReachableWord32SignHint(input, sign);
  }

  V<Word32> Word32SignHintUnsigned(V<Word32> input) {
    return Word32SignHint(input, Word32SignHintOp::Sign::kUnsigned);
  }
  V<Word32> Word32SignHintSigned(V<Word32> input) {
    return Word32SignHint(input, Word32SignHintOp::Sign::kSigned);
  }

  V<Object> GenericBinop(V<Object> left, V<Object> right,
                         V<turboshaft::FrameState> frame_state,
                         V<Context> context, GenericBinopOp::Kind kind,
                         LazyDeoptOnThrow lazy_deopt_on_throw) {
    return ReduceIfReachableGenericBinop(left, right, frame_state, context,
                                         kind, lazy_deopt_on_throw);
  }
#define DECL_GENERIC_BINOP(Name)                                              \
  V<Object> Generic##Name(                                                    \
      V<Object> left, V<Object> right, V<turboshaft::FrameState> frame_state, \
      V<Context> context, LazyDeoptOnThrow lazy_deopt_on_throw) {             \
    return GenericBinop(left, right, frame_state, context,                    \
                        GenericBinopOp::Kind::k##Name, lazy_deopt_on_throw);  \
  }
  GENERIC_BINOP_LIST(DECL_GENERIC_BINOP)
#undef DECL_GENERIC_BINOP

  V<Object> GenericUnop(V<Object> input, V<turboshaft::FrameState> frame_state,
                        V<Context> context, GenericUnopOp::Kind kind,
                        LazyDeoptOnThrow lazy_deopt_on_throw) {
    return ReduceIfReachableGenericUnop(input, frame_state, context, kind,
                                        lazy_deopt_on_throw);
  }
#define DECL_GENERIC_UNOP(Name)                                            \
  V<Object> Generic##Name(                                                 \
      V<Object> input, V<turboshaft::FrameState> frame_state,              \
      V<Context> context, LazyDeoptOnThrow lazy_deopt_on_throw) {          \
    return GenericUnop(input, frame_state, context,                        \
                       GenericUnopOp::Kind::k##Name, lazy_deopt_on_throw); \
  }
  GENERIC_UNOP_LIST(DECL_GENERIC_UNOP)
#undef DECL_GENERIC_UNOP

  V<Object> ToNumberOrNumeric(V<Object> input,
                              V<turboshaft::FrameState> frame_state,
                              V<Context> context, Object::Conversion kind,
                              LazyDeoptOnThrow lazy_deopt_on_throw) {
    return ReduceIfReachableToNumberOrNumeric(input, frame_state, context, kind,
                                              lazy_deopt_on_throw);
  }
  V<Object> ToNumber(V<Object> input, V<turboshaft::FrameState> frame_state,
                     V<Context> context, LazyDeoptOnThrow lazy_deopt_on_throw) {
    return ToNumberOrNumeric(input, frame_state, context,
                             Object::Conversion::kToNumber,
                             lazy_deopt_on_throw);
  }
  V<Object> ToNumeric(V<Object> input, V<turboshaft::FrameState> frame_state,
                      V<Context> context,
                      LazyDeoptOnThrow lazy_deopt_on_throw) {
    return ToNumberOrNumeric(input, frame_state, context,
                             Object::Conversion::kToNumeric,
                             lazy_deopt_on_throw);
  }

#define DECL_MULTI_REP_BINOP(name, operation, rep_type, kind)               \
  OpIndex name(OpIndex left, OpIndex right, rep_type rep) {                 \
    return ReduceIfReachable##operation(left, right,                        \
                                        operation##Op::Kind::k##kind, rep); \
  }

#define DECL_MULTI_REP_BINOP_V(name, operation, kind, tag)                  \
  V<tag> name(V<tag> left, V<tag> right, v_traits<tag>::rep_type rep) {     \
    return ReduceIfReachable##operation(left, right,                        \
                                        operation##Op::Kind::k##kind, rep); \
  }

#define DECL_SINGLE_REP_BINOP_V(name, operation, kind, tag)            \
  V<tag> name(ConstOrV<tag> left, ConstOrV<tag> right) {               \
    return ReduceIfReachable##operation(resolve(left), resolve(right), \
                                        operation##Op::Kind::k##kind,  \
                                        V<tag>::rep);                  \
  }
  DECL_MULTI_REP_BINOP_V(WordAdd, WordBinop, Add, Word)
  DECL_SINGLE_REP_BINOP_V(Word32Add, WordBinop, Add, Word32)
  DECL_SINGLE_REP_BINOP_V(Word64Add, WordBinop, Add, Word64)
  DECL_SINGLE_REP_BINOP_V(WordPtrAdd, WordBinop, Add, WordPtr)

  DECL_MULTI_REP_BINOP_V(WordMul, WordBinop, Mul, Word)
  DECL_SINGLE_REP_BINOP_V(Word32Mul, WordBinop, Mul, Word32)
  DECL_SINGLE_REP_BINOP_V(Word64Mul, WordBinop, Mul, Word64)
  DECL_SINGLE_REP_BINOP_V(WordPtrMul, WordBinop, Mul, WordPtr)

  DECL_MULTI_REP_BINOP_V(WordBitwiseAnd, WordBinop, BitwiseAnd, Word)
  DECL_SINGLE_REP_BINOP_V(Word32BitwiseAnd, WordBinop, BitwiseAnd, Word32)
  DECL_SINGLE_REP_BINOP_V(Word64BitwiseAnd, WordBinop, BitwiseAnd, Word64)
  DECL_SINGLE_REP_BINOP_V(WordPtrBitwiseAnd, WordBinop, BitwiseAnd, WordPtr)

  DECL_MULTI_REP_BINOP_V(WordBitwiseOr, WordBinop, BitwiseOr, Word)
  DECL_SINGLE_REP_BINOP_V(Word32BitwiseOr, WordBinop, BitwiseOr, Word32)
  DECL_SINGLE_REP_BINOP_V(Word64BitwiseOr, WordBinop, BitwiseOr, Word64)
  DECL_SINGLE_REP_BINOP_V(WordPtrBitwiseOr, WordBinop, BitwiseOr, WordPtr)

  DECL_MULTI_REP_BINOP_V(WordBitwiseXor, WordBinop, BitwiseXor, Word)
  DECL_SINGLE_REP_BINOP_V(Word32BitwiseXor, WordBinop, BitwiseXor, Word32)
  DECL_SINGLE_REP_BINOP_V(Word64BitwiseXor, WordBinop, BitwiseXor, Word64)

  DECL_MULTI_REP_BINOP_V(WordSub, WordBinop, Sub, Word)
  DECL_SINGLE_REP_BINOP_V(Word32Sub, WordBinop, Sub, Word32)
  DECL_SINGLE_REP_BINOP_V(Word64Sub, WordBinop, Sub, Word64)
  DECL_SINGLE_REP_BINOP_V(WordPtrSub, WordBinop, Sub, WordPtr)

  DECL_MULTI_REP_BINOP_V(IntDiv, WordBinop, SignedDiv, Word)
  DECL_SINGLE_REP_BINOP_V(Int32Div, WordBinop, SignedDiv, Word32)
  DECL_SINGLE_REP_BINOP_V(Int64Div, WordBinop, SignedDiv, Word64)
  DECL_MULTI_REP_BINOP_V(UintDiv, WordBinop, UnsignedDiv, Word)
  DECL_SINGLE_REP_BINOP_V(Uint32Div, WordBinop, UnsignedDiv, Word32)
  DECL_SINGLE_REP_BINOP_V(Uint64Div, WordBinop, UnsignedDiv, Word64)
  DECL_MULTI_REP_BINOP_V(IntMod, WordBinop, SignedMod, Word)
  DECL_SINGLE_REP_BINOP_V(Int32Mod, WordBinop, SignedMod, Word32)
  DECL_SINGLE_REP_BINOP_V(Int64Mod, WordBinop, SignedMod, Word64)
  DECL_MULTI_REP_BINOP_V(UintMod, WordBinop, UnsignedMod, Word)
  DECL_SINGLE_REP_BINOP_V(Uint32Mod, WordBinop, UnsignedMod, Word32)
  DECL_SINGLE_REP_BINOP_V(Uint64Mod, WordBinop, UnsignedMod, Word64)
  DECL_MULTI_REP_BINOP_V(IntMulOverflownBits, WordBinop, SignedMulOverflownBits,
                         Word)
  DECL_SINGLE_REP_BINOP_V(Int32MulOverflownBits, WordBinop,
                          SignedMulOverflownBits, Word32)
  DECL_SINGLE_REP_BINOP_V(Int64MulOverflownBits, WordBinop,
                          SignedMulOverflownBits, Word64)
  DECL_MULTI_REP_BINOP_V(UintMulOverflownBits, WordBinop,
                         UnsignedMulOverflownBits, Word)
  DECL_SINGLE_REP_BINOP_V(Uint32MulOverflownBits, WordBinop,
                          UnsignedMulOverflownBits, Word32)
  DECL_SINGLE_REP_BINOP_V(Uint64MulOverflownBits, WordBinop,
                          UnsignedMulOverflownBits, Word64)

  V<Word32> Word32BitwiseNot(ConstOrV<Word32> input) {
    return Word32BitwiseXor(input, static_cast<uint32_t>(-1));
  }

  V<Word> WordBinop(V<Word> left, V<Word> right, WordBinopOp::Kind kind,
                    WordRepresentation rep) {
    return ReduceIfReachableWordBinop(left, right, kind, rep);
  }
  V<turboshaft::Tuple<Word, Word32>> OverflowCheckedBinop(
      V<Word> left, V<Word> right, OverflowCheckedBinopOp::Kind kind,
      WordRepresentation rep) {
    return ReduceIfReachableOverflowCheckedBinop(left, right, kind, rep);
  }

#define DECL_MULTI_REP_CHECK_BINOP_V(name, operation, kind, tag)            \
  V<turboshaft::Tuple<tag, Word32>> name(V<tag> left, V<tag> right,         \
                                         v_traits<tag>::rep_type rep) {     \
    return ReduceIfReachable##operation(left, right,                        \
                                        operation##Op::Kind::k##kind, rep); \
  }
#define DECL_SINGLE_REP_CHECK_BINOP_V(name, operation, kind, tag)      \
  V<turboshaft::Tuple<tag, Word32>> name(ConstOrV<tag> left,           \
                                         ConstOrV<tag> right) {        \
    re
```