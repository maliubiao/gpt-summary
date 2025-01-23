Response:
Let's break down the thought process to analyze the provided C++ header file.

**1. Initial Scan and High-Level Understanding:**

* **File Name and Path:** `v8/src/compiler/turboshaft/type-inference-reducer.h`. This immediately tells us it's part of the Turboshaft compiler in V8 and focuses on type inference. The `.h` extension confirms it's a header file, likely defining a class or set of related functions.
* **Copyright and License:** Standard V8 boilerplate, indicating open-source and licensing terms.
* **Includes:** A quick scan of the `#include` directives reveals dependencies on core V8 components (`base/logging.h`, `base/vector.h`), Turboshaft infrastructure (`assembler.h`, `operations.h`, `representations.h`, etc.), and specifically type inference related headers (`type-inference-analysis.h`, `typer.h`, `types.h`). This reinforces the file's purpose.
* **Namespace:** `v8::internal::compiler::turboshaft`. Clearly places this code within the Turboshaft compiler's internal implementation.

**2. Core Class Identification and Purpose:**

* The central element is the `TypeInferenceReducer` class template. The comments immediately highlight its main function: "the central component to infer types for Turboshaft graphs."
* **Reducer Pattern:** The class name ends in "Reducer" and it inherits from `UniformReducerAdapter`. This strongly suggests it's part of a compilation pipeline that uses a reducer pattern, transforming the compiler's intermediate representation (the "graph").

**3. Key Features and Options:**

* **Input and Output Graph Typing:** The `TypeInferenceReducerArgs` struct defines two key enums: `InputGraphTyping` and `OutputGraphTyping`. The comments clearly explain the different levels of type inference applied to the input and output graphs. This is a crucial aspect of the reducer's flexibility.
* **`Analyze()` Method:**  This method seems to be the entry point for the type inference process. It handles different scenarios based on the `InputGraphTyping` setting, potentially running a full fixpoint analysis.
* **`ReduceOperation()` and `ReduceInputGraphOperation()`:** These are typical method names for reducers. They indicate how the reducer processes individual operations within the graph, potentially creating new operations or updating existing ones. The type inference logic is clearly integrated within these methods.
* **`Bind()` Method:** This suggests block-level processing in the graph. The comments about sealing blocks and merging information from predecessors are important for understanding how type information propagates through the control flow graph.
* **`RefineTypesAfterBranch()`:**  This specifically handles type refinement after conditional branches, a common optimization in compilers.
* **`GetType()` and `SetType()`:** These are fundamental for accessing and updating type information associated with operations.
* **`PendingLoopPhi` and `Phi` Reduction:** These methods handle the special case of Phi nodes, which are essential for representing values that merge at control flow joins, especially in loops.
* **Various `REDUCE` Macros:** These are clearly macros used to simplify the implementation of the reducer for different operation types.

**4. Relationship to JavaScript (If Any):**

* The comment mentions that if the file ended in `.tq`, it would be Torque code. Since it's `.h`, it's C++. However, the core purpose of type inference is directly related to understanding JavaScript's dynamic typing. The reducer is figuring out the possible types of variables and expressions *as they are used in the generated compiler IR*, even though JavaScript itself doesn't have explicit static types in the same way.

**5. Code Logic and Inference Examples:**

* **Phi Nodes:** The logic for `REDUCE(Phi)` demonstrates the core concept of finding the least upper bound (union) of the types of the incoming values. This is a standard approach in static analysis for handling control flow merges.
* **Constant Propagation:**  `REDUCE(Constant)` shows how the type of a constant value is directly determined.
* **Binary Operations:** `REDUCE(WordBinop)` and `REDUCE(FloatBinop)` illustrate how the types of operands influence the resulting type, taking into account the specific operation and representation.
* **`CheckTurboshaftTypeOf`:** This is related to runtime type checks potentially inserted by the compiler. The reducer handles cases where the type check is known to succeed or fail based on the inferred type.
* **Branch Refinement:**  The `RefineTypesAfterBranch` logic is a form of control-flow sensitive type analysis. If a branch condition implies a certain type, that information can be used to refine types within the branch's target block.

**6. Common Programming Errors:**

* The `CheckTurboshaftTypeOf` section hints at a potential error: a type check failing after it supposedly passed in a previous phase. This could indicate inconsistencies or bugs in the compiler's type inference or optimization passes. It's not a direct user programming error, but a compiler implementation issue.

**7. Assumptions and Potential Issues:**

* **Soundness of Type System:** The effectiveness of this reducer depends on the soundness and expressiveness of the underlying type system used by Turboshaft.
* **Complexity of Analysis:** Precise type inference, especially with control flow, can be computationally expensive. The different `InputGraphTyping` options likely represent trade-offs between precision and performance.
* **Integration with Other Passes:** This reducer is part of a larger compilation pipeline. Its correctness depends on the information provided by preceding passes and the expectations of subsequent passes.

By following this detailed analysis process, we can gain a comprehensive understanding of the `TypeInferenceReducer` and its role in the V8 Turboshaft compiler. The focus on examining the code structure, comments, key methods, and their interactions is crucial for deciphering complex software components.
This header file, `v8/src/compiler/turboshaft/type-inference-reducer.h`, defines a **type inference reducer** for the Turboshaft compiler in V8. Let's break down its functionality:

**Core Functionality:**

The primary goal of `TypeInferenceReducer` is to **infer and propagate type information** for operations within the Turboshaft intermediate representation (IR) graph. This process helps the compiler:

1. **Optimize code:**  Knowing the types of values allows for more aggressive optimizations, such as using specialized instructions or eliminating unnecessary checks.
2. **Verify code:** Type information can be used to detect potential errors or inconsistencies in the generated code.
3. **Inform later compilation stages:** Subsequent compiler passes can leverage the inferred type information for further transformations and code generation.

**Key Features and Options:**

* **Reducer in a Pipeline:** The class is implemented as a `UniformReducerAdapter`, indicating it's part of a compilation pipeline where reducers transform the graph in stages. This specific reducer is intended to be the *last* one in the stack.
* **Input and Output Graph Typing Options:** The `TypeInferenceReducerArgs` struct defines how type inference is handled for both the input and output graphs:
    * **Input Graph Typing:**
        * `kNone`: No type information is assumed for the input graph.
        * `kPrecise`: A full, fixpoint type analysis is performed on the input graph to determine the most accurate types.
    * **Output Graph Typing:**
        * `kNone`: No types will be assigned to the operations in the output graph.
        * `kPreserveFromInputGraph`: Types from the input graph are reused for corresponding operations in the output graph where possible. New operations remain untyped.
        * `kRefineFromInputGraph`:  Types from the input graph are used to provide a starting point. The reducer then infers types for new operations and refines existing types in the output graph, aiming for greater precision.
* **Type Storage:** It uses a `SnapshotTable<Type>` (`table_t`) to store the inferred types associated with operations. This table supports taking snapshots, which is useful for handling control flow and merging type information at join points.
* **Block-Based Processing:** The `Bind(Block* new_block)` method suggests the reducer processes the graph block by block, merging type information from predecessor blocks.
* **Handling of Different Operations:** The code includes `REDUCE` methods for various Turboshaft operations (e.g., `PendingLoopPhi`, `Phi`, `Constant`, `Comparison`, `WordBinop`, `FloatBinop`, `CheckTurboshaftTypeOf`). Each `REDUCE` method implements the type inference logic specific to that operation.
* **Branch Refinement:** The `RefineTypesAfterBranch` method demonstrates how type information can be refined based on the outcome of a conditional branch. For example, if a branch checks if a value is a number, the "then" branch can assume the value is indeed a number.
* **Tracing and Debugging:**  The code includes tracing statements (`TURBOSHAFT_TRACE_TYPING_OK`, `TURBOSHAFT_TRACE_TYPING_FAIL`) that are likely used for debugging and understanding the type inference process.

**If `v8/src/compiler/turboshaft/type-inference-reducer.h` ended in `.tq`:**

If the file ended in `.tq`, it would indeed be a **Torque source file**. Torque is V8's domain-specific language for writing low-level compiler code. Torque code is statically typed and generates C++ code.

**Relationship to JavaScript and Examples:**

While this C++ code doesn't directly execute JavaScript, its purpose is to analyze and optimize code *generated* from JavaScript. Type inference in Turboshaft is crucial for making JavaScript execution faster.

Here's how the concepts relate to JavaScript with examples:

**Example 1: Basic Type Inference**

```javascript
function add(x, y) {
  return x + y;
}

add(5, 10); // Likely infers that x and y are numbers, result is a number.
add("hello", " world"); // Likely infers that x and y are strings, result is a string.
```

The `TypeInferenceReducer` would analyze the generated Turboshaft IR for the `add` function. Based on the operations and how `x` and `y` are used with the `+` operator, it would try to infer their types. In the first call, it might infer `x` and `y` are likely `Number`. In the second call, it might infer they are `String`.

**Example 2: Branch Refinement**

```javascript
function processValue(value) {
  if (typeof value === 'number') {
    console.log(value * 2); // Inside this block, value is known to be a number.
  } else {
    console.log(value.toUpperCase()); // Inside this block, value is likely a string (or something with toUpperCase).
  }
}

processValue(5);
processValue("test");
```

The `RefineTypesAfterBranch` logic would come into play here. When the `if (typeof value === 'number')` branch is analyzed:

* **"Then" branch:** The reducer can refine the type of `value` within the `console.log(value * 2)` block to be `Number`. This allows for optimizations knowing that a numeric multiplication can be performed.
* **"Else" branch:** The reducer can infer that `value` is likely a `String` (or a type with a `toUpperCase` method) in the `console.log(value.toUpperCase())` block.

**Code Logic Inference (Hypothetical):**

Let's consider the `REDUCE(WordBinop)` method:

**Hypothetical Input (Turboshaft IR):**

```
%1 = LoadRegister(...)  // Loads some value into a register
%2 = Constant(5)       // Constant value 5
%3 = WordBinop(%1, %2, Add, Int32) // Add operation
```

**Assumptions:**

* The `LoadRegister` operation (represented by `%1`) has been previously inferred to have the type `Int32`.
* The `Constant` operation (`%2`) has the type `Int32`.
* The `WordBinop` operation with the `Add` kind and `Int32` representation performs integer addition.

**Output (Inferred Type):**

The `REDUCE(WordBinop)` method would likely infer that the result of the `WordBinop` operation (`%3`) also has the type `Int32`.

**Logic:**  If you add two integers, the result is generally an integer (within the bounds of the representation).

**Common Programming Errors (and how type inference helps):**

Type inference in the compiler helps *detect* potential issues, even if the JavaScript code itself doesn't have explicit types.

**Example:**

```javascript
function greet(name) {
  return "Hello, " + name.toUpperCase();
}

greet(123); // This will cause a runtime error in JavaScript.
```

Even though JavaScript is dynamically typed, the `TypeInferenceReducer` might infer that `name` in the `toUpperCase()` call is expected to be a `String` (or something with a `toUpperCase` method). If the compiler sees a call like `greet(123)`, where `123` is clearly a `Number`, the type inference might flag a potential type mismatch or generate code that includes a runtime check to handle this case gracefully. This doesn't necessarily prevent the error at compile time like a statically typed language, but it allows the compiler to generate more efficient or safer code.

**In summary, `v8/src/compiler/turboshaft/type-inference-reducer.h` is a crucial component of V8's Turboshaft compiler responsible for understanding the types of values during compilation. This information is vital for optimization, verification, and informing later stages of the compilation process, ultimately contributing to faster and more reliable JavaScript execution.**

### 提示词
```
这是目录为v8/src/compiler/turboshaft/type-inference-reducer.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/type-inference-reducer.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_TURBOSHAFT_TYPE_INFERENCE_REDUCER_H_
#define V8_COMPILER_TURBOSHAFT_TYPE_INFERENCE_REDUCER_H_

#include <limits>
#include <optional>

#include "src/base/logging.h"
#include "src/base/vector.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/copying-phase.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/compiler/turboshaft/sidetable.h"
#include "src/compiler/turboshaft/snapshot-table.h"
#include "src/compiler/turboshaft/tracing.h"
#include "src/compiler/turboshaft/type-inference-analysis.h"
#include "src/compiler/turboshaft/typer.h"
#include "src/compiler/turboshaft/types.h"
#include "src/compiler/turboshaft/uniform-reducer-adapter.h"

namespace v8::internal::compiler::turboshaft {

#include "src/compiler/turboshaft/define-assembler-macros.inc"

template <typename Op>
V8_INLINE bool CanBeTyped(const Op& operation) {
  return operation.outputs_rep().size() > 0;
}

struct TypeInferenceReducerArgs
    : base::ContextualClass<TypeInferenceReducerArgs> {
  enum class InputGraphTyping {
    kNone,     // Do not compute types for the input graph.
    kPrecise,  // Run a complete fixpoint analysis on the input graph.
  };
  enum class OutputGraphTyping {
    kNone,                    // Do not compute types for the output graph.
    kPreserveFromInputGraph,  // Reuse types of the input graph where
                              // possible.
    kRefineFromInputGraph,  // Reuse types of the input graph and compute types
                            // for new nodes and more precise types where
                            // possible.
  };
  InputGraphTyping input_graph_typing;
  OutputGraphTyping output_graph_typing;

  TypeInferenceReducerArgs(InputGraphTyping input_graph_typing,
                           OutputGraphTyping output_graph_typing)
      : input_graph_typing(input_graph_typing),
        output_graph_typing(output_graph_typing) {}
};

// TypeInferenceReducer is the central component to infer types for Turboshaft
// graphs. It comes with different options for how the input and output graph
// should be typed:
//
// - InputGraphTyping::kNone: No types are computed for the input graph.
// - InputGraphTyping::kPrecise: We run a full fixpoint analysis on the input
// graph to infer the most precise types possible (see TypeInferenceAnalysis).
//
// - OutputGraphTyping::kNone: No types will be set for the output graph.
// - OutputGraphTyping::kPreserveFromInputGraph: Types from the input graph will
// be preserved for the output graph. Where this is not possible (e.g. new
// operations introduced during lowering), the output operation will be untyped.
// - OutputGraphTyping::kRefineFromInputGraph: Types from the input graph will
// be used where they provide additional precision (e.g loop phis). For new
// operations, the reducer reruns the typer to make sure that the output graph
// is fully typed.
//
// NOTE: The TypeInferenceReducer has to be the last reducer in the stack!
template <class Next>
class TypeInferenceReducer
    : public UniformReducerAdapter<TypeInferenceReducer, Next> {
  static_assert(next_is_bottom_of_assembler_stack<Next>::value);
  using table_t = SnapshotTable<Type>;

 public:
  TURBOSHAFT_REDUCER_BOILERPLATE(TypeInference)

  using Adapter = UniformReducerAdapter<TypeInferenceReducer, Next>;
  using Args = TypeInferenceReducerArgs;

  TypeInferenceReducer() {
    // It is not reasonable to try to reuse input graph types if there are none.
    DCHECK_IMPLIES(args_.output_graph_typing ==
                       Args::OutputGraphTyping::kPreserveFromInputGraph,
                   args_.input_graph_typing != Args::InputGraphTyping::kNone);
  }

  void Analyze() {
    if (args_.input_graph_typing == Args::InputGraphTyping::kPrecise) {
#ifdef DEBUG
      GrowingBlockSidetable<std::vector<std::pair<OpIndex, Type>>>
          block_refinements(Asm().input_graph().block_count(), {},
                            Asm().phase_zone());
      input_graph_types_ = analyzer_.Run(&block_refinements);
      Tracing::Get().PrintPerBlockData(
          "Type Refinements", Asm().input_graph(),
          [&](std::ostream& stream, const turboshaft::Graph& graph,
              turboshaft::BlockIndex index) -> bool {
            const std::vector<std::pair<turboshaft::OpIndex, turboshaft::Type>>&
                refinements = block_refinements[index];
            if (refinements.empty()) return false;
            stream << "\\n";
            for (const auto& [op, type] : refinements) {
              stream << op << " : " << type << "\\n";
            }
            return true;
          });
#else
      input_graph_types_ = analyzer_.Run(nullptr);
#endif  // DEBUG
      Tracing::Get().PrintPerOperationData(
          "Types", Asm().input_graph(),
          [&](std::ostream& stream, const turboshaft::Graph& graph,
              turboshaft::OpIndex index) -> bool {
            turboshaft::Type type = input_graph_types_[index];
            if (!type.IsInvalid() && !type.IsNone()) {
              type.PrintTo(stream);
              return true;
            }
            return false;
          });
    }
    Next::Analyze();
  }

  Type GetInputGraphType(OpIndex ig_index) {
    return input_graph_types_[ig_index];
  }

  Type GetOutputGraphType(OpIndex og_index) { return GetType(og_index); }

  template <Opcode opcode, typename Continuation, typename... Ts>
  OpIndex ReduceOperation(Ts... args) {
    OpIndex index = Continuation{this}.Reduce(args...);
    if (!NeedsTyping(index)) return index;

    const Operation& op = Asm().output_graph().Get(index);
    if (CanBeTyped(op)) {
      Type type = Typer::TypeForRepresentation(
          Asm().output_graph().Get(index).outputs_rep(), Asm().graph_zone());
      SetType(index, type, true);
    }
    return index;
  }

  template <typename Op, typename Continuation>
  OpIndex ReduceInputGraphOperation(OpIndex ig_index, const Op& operation) {
    OpIndex og_index = Continuation{this}.ReduceInputGraph(ig_index, operation);
    if (!og_index.valid()) return og_index;
    if (args_.output_graph_typing == Args::OutputGraphTyping::kNone) {
      return og_index;
    }
    if (!CanBeTyped(operation)) return og_index;

    Type ig_type = GetInputGraphType(ig_index);
    DCHECK_IMPLIES(args_.input_graph_typing != Args::InputGraphTyping::kNone,
                   !ig_type.IsInvalid());
    if (!ig_type.IsInvalid()) {
      Type og_type = GetType(og_index);
      // If the type we have from the input graph is more precise, we keep it.
      if (og_type.IsInvalid() ||
          (ig_type.IsSubtypeOf(og_type) && !og_type.IsSubtypeOf(ig_type))) {
        RefineTypeFromInputGraph(og_index, og_type, ig_type);
      }
    }
    return og_index;
  }

  void Bind(Block* new_block) {
    Next::Bind(new_block);

    // Seal the current block first.
    if (table_.IsSealed()) {
      DCHECK_NULL(current_block_);
    } else {
      // If we bind a new block while the previous one is still unsealed, we
      // finalize it.
      DCHECK_NOT_NULL(current_block_);
      DCHECK(current_block_->index().valid());
      block_to_snapshot_mapping_[current_block_->index()] = table_.Seal();
      current_block_ = nullptr;
    }

    // Collect the snapshots of all predecessors.
    {
      predecessors_.clear();
      for (const Block* pred : new_block->PredecessorsIterable()) {
        std::optional<table_t::Snapshot> pred_snapshot =
            block_to_snapshot_mapping_[pred->index()];
        DCHECK(pred_snapshot.has_value());
        predecessors_.push_back(pred_snapshot.value());
      }
      std::reverse(predecessors_.begin(), predecessors_.end());
    }

    // Start a new snapshot for this block by merging information from
    // predecessors.
    {
      auto MergeTypes = [&](table_t::Key,
                            base::Vector<const Type> predecessors) -> Type {
        DCHECK_GT(predecessors.size(), 0);
        Type result_type = predecessors[0];
        for (size_t i = 1; i < predecessors.size(); ++i) {
          result_type = Type::LeastUpperBound(result_type, predecessors[i],
                                              Asm().graph_zone());
        }
        return result_type;
      };

      table_.StartNewSnapshot(base::VectorOf(predecessors_), MergeTypes);
    }

    // Check if the predecessor is a branch that allows us to refine a few
    // types.
    if (args_.output_graph_typing ==
        Args::OutputGraphTyping::kRefineFromInputGraph) {
      if (new_block->PredecessorCount() == 1) {
        Block* predecessor = new_block->LastPredecessor();
        const Operation& terminator =
            predecessor->LastOperation(Asm().output_graph());
        if (const BranchOp* branch = terminator.TryCast<BranchOp>()) {
          DCHECK(branch->if_true == new_block || branch->if_false == new_block);
          RefineTypesAfterBranch(branch, new_block,
                                 branch->if_true == new_block);
        }
      }
    }
    current_block_ = new_block;
  }

  void RefineTypesAfterBranch(const BranchOp* branch, Block* new_block,
                              bool then_branch) {
    const std::string branch_str = branch->ToString().substr(0, 40);
    USE(branch_str);
    TURBOSHAFT_TRACE_TYPING_OK("Br   %3d:%-40s\n",
                               Asm().output_graph().Index(*branch).id(),
                               branch_str.c_str());

    Typer::BranchRefinements refinements(
        [this](OpIndex index) { return GetType(index); },
        [&](OpIndex index, const Type& refined_type) {
          RefineOperationType(new_block, index, refined_type,
                              then_branch ? 'T' : 'F');
        });

    // Inspect branch condition.
    const Operation& condition = Asm().output_graph().Get(branch->condition());
    refinements.RefineTypes(condition, then_branch, Asm().graph_zone());
  }

  void RefineOperationType(Block* new_block, OpIndex op, const Type& type,
                           char case_for_tracing) {
    DCHECK(op.valid());
    DCHECK(!type.IsInvalid());

    TURBOSHAFT_TRACE_TYPING_OK(
        "  %c: %3d:%-40s ~~> %s\n", case_for_tracing, op.id(),
        Asm().output_graph().Get(op).ToString().substr(0, 40).c_str(),
        type.ToString().c_str());

    auto key_opt = op_to_key_mapping_[op];
    // We might not have a key for this value, because we are running in a mode
    // where we don't type all operations.
    if (key_opt.has_value()) {
      table_.Set(*key_opt, type);

#ifdef DEBUG
      std::vector<std::pair<OpIndex, Type>>& refinement =
          Asm().output_graph().block_type_refinement()[new_block->index()];
      refinement.push_back(std::make_pair(op, type));
#endif

      // TODO(nicohartmann@): One could push the refined type deeper into the
      // operations.
    }
  }

  OpIndex REDUCE(PendingLoopPhi)(OpIndex first, RegisterRepresentation rep) {
    OpIndex index = Next::ReducePendingLoopPhi(first, rep);
    if (!NeedsTyping(index)) return index;

    // There is not much we can do for pending loop phis, because we don't know
    // the type of the backedge yet, so we have to assume maximal type. If we
    // run with a typed input graph, we can refine this type using the input
    // graph's type (see ReduceInputGraphOperation).
    SetType(index, Typer::TypeForRepresentation(rep));
    return index;
  }

  OpIndex REDUCE(Phi)(base::Vector<const OpIndex> inputs,
                      RegisterRepresentation rep) {
    OpIndex index = Next::ReducePhi(inputs, rep);
    if (!NeedsTyping(index)) return index;

    Type type = Type::None();
    for (const OpIndex input : inputs) {
      type = Type::LeastUpperBound(type, GetType(input), Asm().graph_zone());
    }
    SetType(index, type);
    return index;
  }

  OpIndex REDUCE(Constant)(ConstantOp::Kind kind, ConstantOp::Storage value) {
    OpIndex index = Next::ReduceConstant(kind, value);
    if (!NeedsTyping(index)) return index;

    Type type = Typer::TypeConstant(kind, value);
    SetType(index, type);
    return index;
  }

  V<Word32> REDUCE(Comparison)(V<Any> left, V<Any> right,
                               ComparisonOp::Kind kind,
                               RegisterRepresentation rep) {
    OpIndex index = Next::ReduceComparison(left, right, kind, rep);
    if (!NeedsTyping(index)) return index;

    Type type = Typer::TypeComparison(GetType(left), GetType(right), rep, kind,
                                      Asm().graph_zone());
    SetType(index, type);
    return index;
  }

  V<Any> REDUCE(Projection)(V<Any> input, uint16_t idx,
                            RegisterRepresentation rep) {
    V<Any> index = Next::ReduceProjection(input, idx, rep);
    if (!NeedsTyping(index)) return index;

    Type type = Typer::TypeProjection(GetType(input), idx);
    SetType(index, type);
    return index;
  }

  V<Word> REDUCE(WordBinop)(V<Word> left, V<Word> right, WordBinopOp::Kind kind,
                            WordRepresentation rep) {
    V<Word> index = Next::ReduceWordBinop(left, right, kind, rep);
    if (!NeedsTyping(index)) return index;

    Type type = Typer::TypeWordBinop(GetType(left), GetType(right), kind, rep,
                                     Asm().graph_zone());
    SetType(index, type);
    return index;
  }

  OpIndex REDUCE(OverflowCheckedBinop)(V<Word> left, V<Word> right,
                                       OverflowCheckedBinopOp::Kind kind,
                                       WordRepresentation rep) {
    OpIndex index = Next::ReduceOverflowCheckedBinop(left, right, kind, rep);
    if (!NeedsTyping(index)) return index;

    Type type = Typer::TypeOverflowCheckedBinop(GetType(left), GetType(right),
                                                kind, rep, Asm().graph_zone());
    SetType(index, type);
    return index;
  }

  V<Float> REDUCE(FloatBinop)(V<Float> left, V<Float> right,
                              FloatBinopOp::Kind kind,
                              FloatRepresentation rep) {
    V<Float> index = Next::ReduceFloatBinop(left, right, kind, rep);
    if (!NeedsTyping(index)) return index;

    Type type = Typer::TypeFloatBinop(GetType(left), GetType(right), kind, rep,
                                      Asm().graph_zone());
    SetType(index, type);
    return index;
  }

  OpIndex REDUCE(CheckTurboshaftTypeOf)(OpIndex input,
                                        RegisterRepresentation rep, Type type,
                                        bool successful) {
    Type input_type = GetType(input);
    if (input_type.IsSubtypeOf(type)) {
      OpIndex index = Next::ReduceCheckTurboshaftTypeOf(input, rep, type, true);
      TURBOSHAFT_TRACE_TYPING_OK(
          "CTOF %3d:%-40s\n  P: %3d:%-40s ~~> %s\n", index.id(),
          Asm().output_graph().Get(index).ToString().substr(0, 40).c_str(),
          input.id(),
          Asm().output_graph().Get(input).ToString().substr(0, 40).c_str(),
          input_type.ToString().c_str());
      return index;
    }
    if (successful) {
      FATAL(
          "Checking type %s of operation %d:%s failed after it passed in a "
          "previous phase",
          type.ToString().c_str(), input.id(),
          Asm().output_graph().Get(input).ToString().c_str());
    }
    OpIndex index =
        Next::ReduceCheckTurboshaftTypeOf(input, rep, type, successful);
    TURBOSHAFT_TRACE_TYPING_FAIL(
        "CTOF %3d:%-40s\n  F: %3d:%-40s ~~> %s\n", index.id(),
        Asm().output_graph().Get(index).ToString().substr(0, 40).c_str(),
        input.id(),
        Asm().output_graph().Get(input).ToString().substr(0, 40).c_str(),
        input_type.ToString().c_str());
    return index;
  }

  void RemoveLast(OpIndex index_of_last_operation) {
    if (op_to_key_mapping_[index_of_last_operation]) {
      op_to_key_mapping_[index_of_last_operation] = std::nullopt;
      TURBOSHAFT_TRACE_TYPING_OK(
          "REM  %3d:%-40s %-40s\n", index_of_last_operation.id(),
          Asm()
              .output_graph()
              .Get(index_of_last_operation)
              .ToString()
              .substr(0, 40)
              .c_str(),
          GetType(index_of_last_operation).ToString().substr(0, 40).c_str());
      output_graph_types_[index_of_last_operation] = Type::Invalid();
    }
    Next::RemoveLast(index_of_last_operation);
  }

 private:
  void RefineTypeFromInputGraph(OpIndex index, const Type& og_type,
                                const Type& ig_type) {
    // Refinement should happen when we just lowered the corresponding
    // operation, so we should be at the point where the operation is defined
    // (e.g. not in a refinement after a branch). So the current block must
    // contain the operation.
    DCHECK(!ig_type.IsInvalid());

    TURBOSHAFT_TRACE_TYPING_OK(
        "Refi %3d:%-40s\n  I:     %-40s ~~> %-40s\n", index.id(),
        Asm().output_graph().Get(index).ToString().substr(0, 40).c_str(),
        (og_type.IsInvalid() ? "invalid" : og_type.ToString().c_str()),
        ig_type.ToString().c_str());

    RefineOperationType(Asm().current_block(), index, ig_type, 'I');
  }

  Type GetTypeOrInvalid(OpIndex index) {
    if (auto key = op_to_key_mapping_[index]) return table_.Get(*key);
    return Type::Invalid();
  }

  Type GetTupleType(const TupleOp& tuple) {
    base::SmallVector<Type, 4> tuple_types;
    for (OpIndex input : tuple.inputs()) {
      tuple_types.push_back(GetType(input));
    }
    return TupleType::Tuple(base::VectorOf(tuple_types), Asm().graph_zone());
  }

  Type GetType(OpIndex index) {
    Type type = GetTypeOrInvalid(index);
    if (type.IsInvalid()) {
      const Operation& op = Asm().output_graph().Get(index);
      if (op.Is<TupleOp>()) {
        return GetTupleType(op.Cast<TupleOp>());
      } else {
        return Typer::TypeForRepresentation(op.outputs_rep(),
                                            Asm().graph_zone());
      }
    }
    return type;
  }

  void SetType(OpIndex index, const Type& result_type,
               bool is_fallback_for_unsupported_operation = false) {
    DCHECK(!result_type.IsInvalid());

    if (auto key_opt = op_to_key_mapping_[index]) {
      table_.Set(*key_opt, result_type);
      DCHECK(result_type.IsSubtypeOf(output_graph_types_[index]));
      output_graph_types_[index] = result_type;
      DCHECK(!output_graph_types_[index].IsInvalid());
    } else {
      auto key = table_.NewKey(Type::None());
      op_to_key_mapping_[index] = key;
      table_.Set(key, result_type);
      output_graph_types_[index] = result_type;
    }

    if (!is_fallback_for_unsupported_operation) {
      TURBOSHAFT_TRACE_TYPING_OK(
          "Type %3d:%-40s ==> %s\n", index.id(),
          Asm().output_graph().Get(index).ToString().substr(0, 40).c_str(),
          result_type.ToString().c_str());
    } else {
      // TODO(nicohartmann@): Remove the fallback case once all operations are
      // supported.
      TURBOSHAFT_TRACE_TYPING_FAIL(
          "TODO %3d:%-40s ==> %s\n", index.id(),
          Asm().output_graph().Get(index).ToString().substr(0, 40).c_str(),
          result_type.ToString().c_str());
    }
  }

// Verification is more difficult, now that the output graph uses types from the
// input graph. It is generally not possible to verify that the output graph's
// type is a subtype of the input graph's type, because the typer might not
// support a precise typing of the operations after the lowering.
// TODO(nicohartmann@): Evaluate new strategies for verification.
#if 0
#ifdef DEBUG
  void Verify(OpIndex input_index, OpIndex output_index) {
    DCHECK(input_index.valid());
    DCHECK(output_index.valid());

    const auto& input_type = Asm().input_graph().operation_types()[input_index];
    const auto& output_type = types_[output_index];

    if (input_type.IsInvalid()) return;
    DCHECK(!output_type.IsInvalid());

    const bool is_okay = output_type.IsSubtypeOf(input_type);

    TURBOSHAFT_TRACE_TYPING(
        "\033[%s %3d:%-40s %-40s\n     %3d:%-40s %-40s\033[0m\n",
        is_okay ? "32mOK  " : "31mFAIL", input_index.id(),
        Asm().input_graph().Get(input_index).ToString().substr(0, 40).c_str(),
        input_type.ToString().substr(0, 40).c_str(), output_index.id(),
        Asm().output_graph().Get(output_index).ToString().substr(0, 40).c_str(),
        output_type.ToString().substr(0, 40).c_str());

    if (V8_UNLIKELY(!is_okay)) {
      FATAL(
          "\033[%s %3d:%-40s %-40s\n     %3d:%-40s %-40s\033[0m\n",
          is_okay ? "32mOK  " : "31mFAIL", input_index.id(),
          Asm().input_graph().Get(input_index).ToString().substr(0, 40).c_str(),
          input_type.ToString().substr(0, 40).c_str(), output_index.id(),
          Asm()
              .output_graph()
              .Get(output_index)
              .ToString()
              .substr(0, 40)
              .c_str(),
          output_type.ToString().substr(0, 40).c_str());
    }
  }
#endif
#endif

  bool NeedsTyping(OpIndex index) const {
    return index.valid() && args_.output_graph_typing ==
                                Args::OutputGraphTyping::kRefineFromInputGraph;
  }

  TypeInferenceReducerArgs args_{TypeInferenceReducerArgs::Get()};
  GrowingOpIndexSidetable<Type> input_graph_types_{Asm().graph_zone(),
                                                   &Asm().input_graph()};
  GrowingOpIndexSidetable<Type>& output_graph_types_{
      Asm().output_graph().operation_types()};
  table_t table_{Asm().phase_zone()};
  const Block* current_block_ = nullptr;
  GrowingOpIndexSidetable<std::optional<table_t::Key>> op_to_key_mapping_{
      Asm().phase_zone(), &Asm().output_graph()};
  GrowingBlockSidetable<std::optional<table_t::Snapshot>>
      block_to_snapshot_mapping_{Asm().input_graph().block_count(),
                                 std::nullopt, Asm().phase_zone()};
  // {predecessors_} is used during merging, but we use an instance variable for
  // it, in order to save memory and not reallocate it for each merge.
  ZoneVector<table_t::Snapshot> predecessors_{Asm().phase_zone()};
  TypeInferenceAnalysis analyzer_{Asm().modifiable_input_graph(),
                                  Asm().phase_zone()};
};

#include "src/compiler/turboshaft/undef-assembler-macros.inc"

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_COMPILER_TURBOSHAFT_TYPE_INFERENCE_REDUCER_H_
```