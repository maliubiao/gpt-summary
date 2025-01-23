Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

**1. Initial Skim and Keyword Identification:**

* First, I'd quickly skim the code, looking for recognizable keywords and patterns. Things like `Phi`, `ValueRepresentation`, `Tagged`, `Untagging`, `Convert`, `Hoist`, `Loop`, `Block`, `Node`, `Smi`, `Float64`, `Int32`, etc., immediately jump out. The file name itself, `maglev-phi-representation-selector.cc`, is a huge clue.

**2. Understanding the Core Goal (Based on the File Name and Keywords):**

* The name strongly suggests this code is about *selecting* the best *representation* for `Phi` nodes within the Maglev compiler. The presence of "untagging" indicates a focus on optimizing by removing type tags when safe and beneficial.

**3. Dissecting Key Sections:**

* **`PreProcessBasicBlock`:** This function iterates through the `Phi` nodes in a basic block and calls `ProcessPhi`. This suggests `ProcessPhi` is the core logic for deciding on the representation of each Phi. The "retry" mechanism hints that the decision for one Phi might influence another.

* **`ProcessPhi`:** This is the heart of the logic. I'd pay close attention to:
    * The initial check `node->value_representation() != ValueRepresentation::kTagged`. This indicates it only processes Phis that haven't been processed yet.
    * The handling of `exception_phi`.
    * The `input_reprs` calculation: How it determines the possible representations based on the inputs.
    * The handling of `Constant`, `SmiConstant`, and conversion nodes.
    * The special handling of loop phis and hoisting.
    * The `use_reprs` calculation: How the uses of the Phi influence the decision.
    * The logic around `intersection` of `possible_inputs` and `allowed_inputs_for_uses`. This is the crucial decision-making part.
    * The calls to `ConvertTaggedPhiTo`.

* **`ConvertTaggedPhiTo`:** This function changes the representation of a Phi and handles updating its inputs (potentially inserting conversions). The different cases (SmiConstant, Constant, conversions, other Phis, hoisting) are important to understand.

* **Helper Functions (e.g., `EnsurePhiTagged`, `GetOpcodeForConversion`):** These support the main logic by ensuring tagged values where needed and determining the appropriate conversion opcodes.

* **`UpdateNodePhiInput` (overloads):**  These functions deal with the consequences of a Phi's representation changing. They ensure that nodes using the Phi are updated correctly, potentially adding tagging operations or changing the node's opcode.

* **`FixLoopPhisBackedge`:** This handles specific adjustments needed for loop phis after their representations have been decided.

**4. Identifying the "Why": Optimization**

* The recurring themes of "untagging" and "hoisting" strongly point to performance optimization. Removing tags reduces overhead, and hoisting moves untagging operations to less frequently executed code (like loop prologues).

**5. Connecting to JavaScript (The "How"):**

*  The key connection is that JavaScript is dynamically typed. V8 needs to figure out the underlying types at runtime. `Phi` nodes in the intermediate representation represent values whose type might not be known statically.
* Untagging is about removing the "tag" that indicates the type of a JavaScript value (e.g., whether a number is a Smi or a HeapNumber). This allows for more efficient operations if the type is known or can be inferred.
* Loops are prime candidates for optimization. If V8 can determine that a value within a loop is always a number, it can use untagged arithmetic.

**6. Crafting the JavaScript Example:**

* The example needs to demonstrate a situation where V8 would benefit from untagging a Phi node. A simple loop where a variable is likely to hold a number is a good starting point.
* I'd start with a tagged version (performing operations directly on `y`).
* Then, I'd show how V8 *could* optimize this by untagging `y` inside the loop, performing the addition as an integer operation, and then potentially retagging if needed later. This illustrates the core idea of the C++ code.

**7. Refining the Summary and Example:**

* Ensure the summary is concise and focuses on the main functionalities.
* Make sure the JavaScript example is clear, easy to understand, and directly relates to the C++ concepts (Phi nodes, untagging).
* Use clear language and avoid overly technical jargon where possible. Explain terms like "Phi nodes" briefly.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "Is this about type inference?"  ->  **Correction:**  It's related, but more about *representation selection* based on inference and usage.
* **Considering details:**  "Why the retry mechanism in `PreProcessBasicBlock`?" -> **Answer:**  Because the representation of one Phi might depend on another.
* **JavaScript clarity:** "Is the JavaScript example too simple?" -> **Consideration:** Simplicity is good for illustrating the core concept. Adding too much complexity might obscure the connection.

By following these steps, combining code analysis with an understanding of compiler optimization techniques, I can effectively summarize the C++ code and provide a relevant JavaScript example.
这个C++源代码文件 `maglev-phi-representation-selector.cc` 的主要功能是 **在V8的Maglev编译器中，为Phi节点选择最佳的值表示形式 (ValueRepresentation)**。  更具体地说，它的核心目标是 **尽可能地将Phi节点的值表示从 `kTagged`（带标签的JavaScript值）转换为更底层的、未装箱的表示形式，例如 `kInt32` 或 `kFloat64`，以提高性能**。这个过程被称为 **Phi节点的解标签 (Untagging)**。

**以下是其功能的详细归纳：**

1. **Phi节点表示形式优化:** 该文件的核心职责是优化Phi节点的表示。Phi节点是编译器IR中用于合并来自不同执行路径的值的节点。最初，所有Phi节点都被表示为 `kTagged`，这意味着它们可以存储任何JavaScript值。

2. **解标签 (Untagging):**  该文件试图将Phi节点的表示形式更改为更具体的未装箱类型，例如 `kInt32` (32位整数) 或 `kFloat64` (64位浮点数)。这样做的好处是，后续使用这些Phi节点的操作可以直接在未装箱的值上进行，避免了昂贵的装箱和拆箱操作，从而提高性能。

3. **基于输入和用途的决策:**  `MaglevPhiRepresentationSelector` 分析了Phi节点的 **输入 (inputs)** 和 **用途 (uses)** 来决定是否以及如何进行解标签。
    * **输入分析:** 它检查Phi节点的输入值的表示形式。如果所有输入都可能是整数，那么Phi节点可以被解标签为 `kInt32`。类似地，如果所有输入都可能是浮点数，则可以解标签为 `kFloat64`。
    * **用途分析:** 它还检查Phi节点在后续代码中的使用方式。如果Phi节点只被用作整数操作的输入，那么解标签为 `kInt32` 是安全的。

4. **类型提升 (Widening):**  在解标签过程中，允许进行类型提升。例如，如果Phi节点的输入既有 `kInt32` 也有 `kFloat64`，那么该Phi节点可能会被解标签为 `kFloat64`，因为浮点数可以表示所有整数。但反过来是不允许的，以避免精度损失。

5. **插入转换 (Conversions):** 如果一个Phi节点被解标签，那么它的输入可能仍然是 `kTagged` 的。在这种情况下，编译器会插入显式的 **解标签操作 (Untagging Operations)**，例如 `CheckedSmiUntag` 或 `CheckedNumberOrOddballToFloat64`，将输入值转换为目标表示形式。

6. **处理循环 (Loops):** 该文件特别关注循环中的Phi节点。它尝试将解标签操作 **提升 (Hoist)** 到循环入口之前，这样解标签操作只需要执行一次，而不是在每次循环迭代中都执行。这对于性能至关重要。

7. **处理控制流 (Control Flow):**  `MaglevPhiRepresentationSelector` 考虑了控制流的影响，确保在所有可能的执行路径中，Phi节点的值都具有一致的表示形式。

8. **更新节点输入 (Updating Node Inputs):** 当Phi节点的表示形式发生改变时，需要更新使用该Phi节点的所有其他节点的输入。如果一个节点期望一个 `kTagged` 值，但Phi节点被解标签为 `kInt32`，则可能需要插入一个 **重新标签操作 (Retagging Operation)**，例如 `Int32ToNumber`。

9. **处理不同类型的Phi节点:** 文件中包含了对不同类型Phi节点（例如异常Phi节点、循环Phi节点）的特殊处理逻辑。

**与 JavaScript 功能的关系和示例:**

`maglev-phi-representation-selector.cc` 的功能与 JavaScript 的动态类型特性密切相关。JavaScript 变量在运行时可以存储不同类型的值。当 V8 编译 JavaScript 代码时，它需要处理这种动态性。Phi 节点的存在就是为了处理由于控制流而可能具有不同类型或表示形式的值。

解标签优化直接影响 JavaScript 代码的执行效率，特别是涉及到数值计算的场景。

**JavaScript 示例:**

```javascript
function add(a, b, condition) {
  let x;
  if (condition) {
    x = a; // 假设 'a' 是一个小的整数 (Smi)
  } else {
    x = b; // 假设 'b' 是一个浮点数
  }
  return x + 1;
}

// 多次调用 add 函数，让 V8 进行优化
add(1, 2.5, true);
add(5, 10.8, false);
add(10, 3.14, true);
```

**在 Maglev 编译器的视角下，上面的 JavaScript 代码会发生什么：**

1. **Phi 节点生成:** 在编译 `add` 函数时，对于变量 `x`，编译器会创建一个 Phi 节点，因为它在不同的控制流路径 (`if` 和 `else` 分支) 中被赋值。

2. **初始表示:**  最初，`x` 的 Phi 节点会被表示为 `kTagged`，因为 `a` 可能是整数，而 `b` 是浮点数，JavaScript 变量可以存储不同类型的值。

3. **解标签分析:** `maglev-phi-representation-selector.cc` 中的代码会分析 `x` 的 Phi 节点的输入 (`a` 和 `b`) 和用途 (`x + 1`)。

4. **可能的解标签:**
   * 如果 V8 能够通过类型反馈或其他分析确定 `a` 总是小的整数 (Smi) 而 `b` 总是浮点数，那么 `x` 的 Phi 节点可能会被解标签为 `kFloat64`，因为浮点数可以安全地表示整数。
   * 在解标签的过程中，编译器可能会在 `if` 分支中插入一个将 `a` 从 `kTagged` (Smi) 转换为 `kFloat64` 的操作，而在 `else` 分支中 `b` 已经是浮点数，则不需要转换。

5. **优化加法操作:** 一旦 `x` 的 Phi 节点被解标签为 `kFloat64`，那么 `x + 1` 的加法操作就可以直接在未装箱的浮点数上进行，避免了检查标签和进行类型转换的开销。

**总结:**

`maglev-phi-representation-selector.cc` 是 Maglev 编译器中一个关键的优化组件。它通过智能地选择 Phi 节点的表示形式，特别是通过解标签，显著提高了 JavaScript 代码的执行效率，尤其是在涉及数值运算的场景中。它体现了 V8 如何在动态类型的 JavaScript 环境中进行静态分析和优化，以达到接近静态类型语言的性能。

### 提示词
```
这是目录为v8/src/maglev/maglev-phi-representation-selector.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/maglev/maglev-phi-representation-selector.h"

#include <optional>

#include "src/base/enum-set.h"
#include "src/base/logging.h"
#include "src/base/small-vector.h"
#include "src/compiler/turboshaft/utils.h"
#include "src/flags/flags.h"
#include "src/handles/handles-inl.h"
#include "src/maglev/maglev-graph-processor.h"
#include "src/maglev/maglev-ir-inl.h"
#include "src/maglev/maglev-ir.h"

namespace v8 {
namespace internal {
namespace maglev {

#define TRACE_UNTAGGING(...)                      \
  do {                                            \
    if (v8_flags.trace_maglev_phi_untagging) {    \
      StdoutStream{} << __VA_ARGS__ << std::endl; \
    }                                             \
  } while (false)

BlockProcessResult MaglevPhiRepresentationSelector::PreProcessBasicBlock(
    BasicBlock* block) {
  PreparePhiTaggings(current_block_, block);
  current_block_ = block;

  if (block->has_phi()) {
    auto& phis = *block->phis();

    auto first_retry = phis.begin();
    auto end_retry = first_retry;
    bool any_change = false;

    for (auto it = phis.begin(); it != phis.end(); ++it) {
      Phi* phi = *it;
      switch (ProcessPhi(phi)) {
        case ProcessPhiResult::kNone:
          break;
        case ProcessPhiResult::kChanged:
          any_change = true;
          break;
        case ProcessPhiResult::kRetryOnChange:
          if (end_retry == first_retry) {
            first_retry = it;
          }
          end_retry = it;
          ++end_retry;
          break;
      }
    }
    // Give it one more shot in case an earlier phi has a later one as input.
    if (any_change) {
      for (auto it = first_retry; it != end_retry; ++it) {
        ProcessPhi(*it);
      }
    }
  }

  return BlockProcessResult::kContinue;
}

bool MaglevPhiRepresentationSelector::CanHoistUntaggingTo(BasicBlock* block) {
  if (block->successors().size() != 1) return false;
  BasicBlock* next = block->successors()[0];
  // To be able to hoist above resumable loops we would have to be able to
  // convert during resumption.
  return !next->state()->is_resumable_loop();
}

MaglevPhiRepresentationSelector::ProcessPhiResult
MaglevPhiRepresentationSelector::ProcessPhi(Phi* node) {
  if (node->value_representation() != ValueRepresentation::kTagged) {
    return ProcessPhiResult::kNone;
  }

  if (node->is_exception_phi()) {
    // Exception phis have no inputs (or, at least, none accessible through
    // `node->input(...)`), so we don't know if the inputs could be untagged or
    // not, so we just keep those Phis tagged.
    return ProcessPhiResult::kNone;
  }

  TRACE_UNTAGGING(
      "Considering for untagging: " << PrintNodeLabel(graph_labeller(), node));

  // {input_mask} represents the ValueRepresentation that {node} could have,
  // based on the ValueRepresentation of its inputs.
  ValueRepresentationSet input_reprs;
  HoistTypeList hoist_untagging;
  hoist_untagging.resize_and_init(node->input_count(), HoistType::kNone);

  bool has_tagged_phi_input = false;
  for (int i = 0; i < node->input_count(); i++) {
    ValueNode* input = node->input(i).node();
    if (input->Is<SmiConstant>()) {
      // Could be any representation. We treat such inputs as Int32, since we
      // later allow ourselves to promote Int32 to Float64 if needed (but we
      // never downgrade Float64 to Int32, as it could cause deopt loops).
      input_reprs.Add(ValueRepresentation::kInt32);
    } else if (Constant* constant = input->TryCast<Constant>()) {
      if (constant->object().IsHeapNumber()) {
        input_reprs.Add(ValueRepresentation::kFloat64);
      } else {
        // Not a Constant that we can untag.
        // TODO(leszeks): Consider treating 'undefined' as a potential
        // HoleyFloat64.
        input_reprs.RemoveAll();
        break;
      }
    } else if (input->properties().is_conversion()) {
      DCHECK_EQ(input->input_count(), 1);
      // The graph builder tags all Phi inputs, so this conversion should
      // produce a tagged value.
      DCHECK_EQ(input->value_representation(), ValueRepresentation::kTagged);
      // If we want to untag {node}, then we'll drop the conversion and use its
      // input instead.
      input_reprs.Add(
          input->input(0).node()->properties().value_representation());
    } else if (Phi* input_phi = input->TryCast<Phi>()) {
      if (input_phi->value_representation() != ValueRepresentation::kTagged) {
        input_reprs.Add(input_phi->value_representation());
      } else {
        // An untagged phi is an input of the current phi.
        if (node->is_backedge_offset(i) &&
            node->merge_state()->is_loop_with_peeled_iteration()) {
          // This is the backedge of a loop that has a peeled iteration. We
          // ignore it and speculatively assume that it will be the same as the
          // 1st input.
          DCHECK_EQ(node->input_count(), 2);
          DCHECK_EQ(i, 1);
          break;
        }
        has_tagged_phi_input = true;
        input_reprs.RemoveAll();
        break;
      }
    } else {
      // This is the case where we don't have an existing conversion to attach
      // the untagging to. In the general case we give up, however in the
      // special case of the value originating from the loop entry branch, we
      // can try to hoist untagging out of the loop.
      if (builder_->graph()->is_osr() &&
          v8_flags.maglev_hoist_osr_value_phi_untagging &&
          input->Is<InitialValue>() &&
          CanHoistUntaggingTo(*builder_->graph()->begin())) {
        hoist_untagging[i] = HoistType::kPrologue;
        continue;
      }
      if (node->is_loop_phi() && !node->is_backedge_offset(i)) {
        BasicBlock* pred = node->merge_state()->predecessor_at(i);
        if (CanHoistUntaggingTo(pred)) {
          auto static_type = StaticTypeForNode(
              builder_->broker(), builder_->local_isolate(), input);
          if (NodeTypeIs(static_type, NodeType::kSmi)) {
            input_reprs.Add(ValueRepresentation::kInt32);
            hoist_untagging[i] = HoistType::kLoopEntryUnchecked;
            continue;
          }
          if (NodeTypeIs(static_type, NodeType::kNumber)) {
            input_reprs.Add(ValueRepresentation::kFloat64);
            hoist_untagging[i] = HoistType::kLoopEntryUnchecked;
            continue;
          }

          // TODO(olivf): Unless we untag OSR values, speculatively untagging
          // could end us in deopt loops. To enable this by default we need to
          // add some feedback to be able to back off. Or, ideally find the
          // respective checked conversion from within the loop to wire up the
          // feedback collection.
          if (v8_flags.maglev_speculative_hoist_phi_untagging) {
            // TODO(olivf): Currently there is no hard guarantee that the phi
            // merge state has a checkpointed jump.
            if (pred->control_node()->Is<CheckpointedJump>()) {
              DCHECK(!node->merge_state()->is_resumable_loop());
              hoist_untagging[i] = HoistType::kLoopEntry;
              continue;
            }
          }
        }
      }

      // This input is tagged, didn't require a tagging operation to be
      // tagged and we decided not to hosit; we won't untag {node}.
      // TODO(dmercadier): this is a bit suboptimal, because some nodes start
      // tagged, and later become untagged (parameters for instance). Such nodes
      // will have their untagged alternative passed to {node} without any
      // explicit conversion, and we thus won't untag {node} even though we
      // could have.
      input_reprs.RemoveAll();
      break;
    }
  }
  ProcessPhiResult default_result = has_tagged_phi_input
                                        ? ProcessPhiResult::kRetryOnChange
                                        : ProcessPhiResult::kNone;

  UseRepresentationSet use_reprs;
  if (node->is_loop_phi() && !node->get_same_loop_uses_repr_hints().empty()) {
    // {node} is a loop phi that has uses inside the loop; we will tag/untag
    // based on those uses, ignoring uses after the loop.
    use_reprs = node->get_same_loop_uses_repr_hints();
  } else {
    use_reprs = node->get_uses_repr_hints();
  }

  TRACE_UNTAGGING("  + use_reprs  : " << use_reprs);
  TRACE_UNTAGGING("  + input_reprs: " << input_reprs);

  if (use_reprs.contains(UseRepresentation::kTagged) ||
      use_reprs.contains(UseRepresentation::kUint32) || use_reprs.empty()) {
    // We don't untag phis that are used as tagged (because we'd have to retag
    // them later). We also ignore phis that are used as Uint32, because this is
    // a fairly rare case and supporting it doesn't improve performance all that
    // much but will increase code complexity.
    // TODO(dmercadier): consider taking into account where those Tagged uses
    // are: Tagged uses outside of a loop or for a Return could probably be
    // ignored.
    TRACE_UNTAGGING("  => Leaving tagged [incompatible uses]");
    EnsurePhiInputsTagged(node);
    return default_result;
  }

  if (input_reprs.contains(ValueRepresentation::kTagged) ||
      input_reprs.contains(ValueRepresentation::kUint32) ||
      input_reprs.empty()) {
    TRACE_UNTAGGING("  => Leaving tagged [tagged or uint32 inputs]");
    EnsurePhiInputsTagged(node);
    return default_result;
  }

  // Only allowed to have Int32, Float64 and HoleyFloat64 inputs from here.
  DCHECK_EQ(input_reprs -
                ValueRepresentationSet({ValueRepresentation::kInt32,
                                        ValueRepresentation::kFloat64,
                                        ValueRepresentation::kHoleyFloat64}),
            ValueRepresentationSet());

  DCHECK_EQ(
      use_reprs - UseRepresentationSet({UseRepresentation::kInt32,
                                        UseRepresentation::kTruncatedInt32,
                                        UseRepresentation::kFloat64,
                                        UseRepresentation::kHoleyFloat64}),
      UseRepresentationSet());

  // The rules for untagging are that we can only widen input representations,
  // i.e. promote Int32 -> Float64 -> HoleyFloat64.
  //
  // Inputs can always be used as more generic uses, and tighter uses always
  // block more generic inputs. So, we can find the minimum generic use and
  // maximum generic input, extend inputs upwards, uses downwards, and convert
  // to the least generic use in the intersection.
  //
  // Of interest is the fact that we don't want to insert conversions which
  // reduce genericity, e.g. Float64->Int32 conversions, since they could deopt
  // and lead to deopt loops. The above logic ensures that if a Phi has Float64
  // inputs and Int32 uses, we simply don't untag it.
  //
  // TODO(leszeks): The above logic could be implemented with bit magic if the
  // representations were contiguous.

  ValueRepresentationSet possible_inputs;
  if (input_reprs.contains(ValueRepresentation::kHoleyFloat64)) {
    possible_inputs = {ValueRepresentation::kHoleyFloat64};
  } else if (input_reprs.contains(ValueRepresentation::kFloat64)) {
    possible_inputs = {ValueRepresentation::kFloat64,
                       ValueRepresentation::kHoleyFloat64};
  } else {
    DCHECK(input_reprs.contains_only(ValueRepresentation::kInt32));
    possible_inputs = {ValueRepresentation::kInt32,
                       ValueRepresentation::kFloat64,
                       ValueRepresentation::kHoleyFloat64};
  }

  ValueRepresentationSet allowed_inputs_for_uses;
  if (use_reprs.contains(UseRepresentation::kInt32)) {
    allowed_inputs_for_uses = {ValueRepresentation::kInt32};
  } else if (use_reprs.contains(UseRepresentation::kFloat64)) {
    allowed_inputs_for_uses = {ValueRepresentation::kInt32,
                               ValueRepresentation::kFloat64};
  } else {
    DCHECK(!use_reprs.empty() &&
           use_reprs.is_subset_of({UseRepresentation::kHoleyFloat64,
                                   UseRepresentation::kTruncatedInt32}));
    allowed_inputs_for_uses = {ValueRepresentation::kInt32,
                               ValueRepresentation::kFloat64,
                               ValueRepresentation::kHoleyFloat64};
  }

  // When hoisting we must ensure that we don't turn a tagged flowing into
  // CheckedSmiUntag into a float64. This would cause us to loose the smi check
  // which in turn can invalidate assumptions on aliasing values.
  if (hoist_untagging.size() && node->uses_require_31_bit_value()) {
    allowed_inputs_for_uses.Remove(
        {ValueRepresentation::kFloat64, ValueRepresentation::kHoleyFloat64});
  }

  auto intersection = possible_inputs & allowed_inputs_for_uses;

  TRACE_UNTAGGING("  + intersection reprs: " << intersection);
  if (intersection.contains(ValueRepresentation::kInt32)) {
    TRACE_UNTAGGING("  => Untagging to Int32");
    ConvertTaggedPhiTo(node, ValueRepresentation::kInt32, hoist_untagging);
    return ProcessPhiResult::kChanged;
  } else if (intersection.contains(ValueRepresentation::kFloat64)) {
    TRACE_UNTAGGING("  => Untagging to kFloat64");
    ConvertTaggedPhiTo(node, ValueRepresentation::kFloat64, hoist_untagging);
    return ProcessPhiResult::kChanged;
  } else if (intersection.contains(ValueRepresentation::kHoleyFloat64)) {
    TRACE_UNTAGGING("  => Untagging to HoleyFloat64");
    ConvertTaggedPhiTo(node, ValueRepresentation::kHoleyFloat64,
                       hoist_untagging);
    return ProcessPhiResult::kChanged;
  }

  DCHECK(intersection.empty());
  // We don't untag the Phi.
  TRACE_UNTAGGING("  => Leaving tagged [incompatible inputs/uses]");
  EnsurePhiInputsTagged(node);
  return default_result;
}

void MaglevPhiRepresentationSelector::EnsurePhiInputsTagged(Phi* phi) {
  // Since we are untagging some Phis, it's possible that one of the inputs of
  // {phi} is an untagged Phi. However, if this function is called, then we've
  // decided that {phi} is going to stay tagged, and thus, all of its inputs
  // should be tagged. We'll thus insert tagging operation on the untagged phi
  // inputs of {phi}.

  for (int i = 0; i < phi->input_count(); i++) {
    ValueNode* input = phi->input(i).node();
    if (Phi* phi_input = input->TryCast<Phi>()) {
      phi->change_input(
          i, EnsurePhiTagged(phi_input, phi->predecessor_at(i),
                             NewNodePosition::kEndOfBlock, nullptr, i));
    } else {
      // Inputs of Phis that aren't Phi should always be tagged (except for the
      // phis untagged by this class, but {phi} isn't one of them).
      DCHECK(input->is_tagged());
    }
  }
}

namespace {

Opcode GetOpcodeForConversion(ValueRepresentation from, ValueRepresentation to,
                              bool truncating) {
  DCHECK_NE(from, ValueRepresentation::kTagged);
  DCHECK_NE(to, ValueRepresentation::kTagged);

  switch (from) {
    case ValueRepresentation::kInt32:
      switch (to) {
        case ValueRepresentation::kUint32:
          return Opcode::kCheckedInt32ToUint32;
        case ValueRepresentation::kFloat64:
        case ValueRepresentation::kHoleyFloat64:
          return Opcode::kChangeInt32ToFloat64;

        case ValueRepresentation::kInt32:
        case ValueRepresentation::kTagged:
        case ValueRepresentation::kIntPtr:
          UNREACHABLE();
      }
    case ValueRepresentation::kUint32:
      switch (to) {
        case ValueRepresentation::kInt32:
          return Opcode::kCheckedUint32ToInt32;

        case ValueRepresentation::kFloat64:
        case ValueRepresentation::kHoleyFloat64:
          return Opcode::kChangeUint32ToFloat64;

        case ValueRepresentation::kUint32:
        case ValueRepresentation::kTagged:
        case ValueRepresentation::kIntPtr:
          UNREACHABLE();
      }
    case ValueRepresentation::kFloat64:
      switch (to) {
        case ValueRepresentation::kInt32:
          if (truncating) {
            return Opcode::kTruncateFloat64ToInt32;
          }
          return Opcode::kCheckedTruncateFloat64ToInt32;
        case ValueRepresentation::kUint32:
          // The graph builder never inserts Tagged->Uint32 conversions, so we
          // don't have to handle this case.
          UNREACHABLE();
        case ValueRepresentation::kHoleyFloat64:
          return Opcode::kIdentity;

        case ValueRepresentation::kFloat64:
        case ValueRepresentation::kTagged:
        case ValueRepresentation::kIntPtr:
          UNREACHABLE();
      }
    case ValueRepresentation::kHoleyFloat64:
      switch (to) {
        case ValueRepresentation::kInt32:
          // Holes are NaNs, so we can truncate them to int32 same as real NaNs.
          if (truncating) {
            return Opcode::kTruncateFloat64ToInt32;
          }
          return Opcode::kCheckedTruncateFloat64ToInt32;
        case ValueRepresentation::kUint32:
          // The graph builder never inserts Tagged->Uint32 conversions, so we
          // don't have to handle this case.
          UNREACHABLE();
        case ValueRepresentation::kFloat64:
          return Opcode::kHoleyFloat64ToMaybeNanFloat64;

        case ValueRepresentation::kHoleyFloat64:
        case ValueRepresentation::kTagged:
        case ValueRepresentation::kIntPtr:
          UNREACHABLE();
      }

    case ValueRepresentation::kTagged:
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
  }
  UNREACHABLE();
}

}  // namespace

void MaglevPhiRepresentationSelector::ConvertTaggedPhiTo(
    Phi* phi, ValueRepresentation repr, const HoistTypeList& hoist_untagging) {
  // We currently only support Int32, Float64, and HoleyFloat64 untagged phis.
  DCHECK(repr == ValueRepresentation::kInt32 ||
         repr == ValueRepresentation::kFloat64 ||
         repr == ValueRepresentation::kHoleyFloat64);
  phi->change_representation(repr);
  // Re-initialise register data, since we might have changed from integer
  // registers to floating registers.
  phi->InitializeRegisterData();

  for (int i = 0; i < phi->input_count(); i++) {
    ValueNode* input = phi->input(i).node();
#define TRACE_INPUT_LABEL \
  "    @ Input " << i << " (" << PrintNodeLabel(graph_labeller(), input) << ")"

    if (input->Is<SmiConstant>()) {
      switch (repr) {
        case ValueRepresentation::kInt32:
          TRACE_UNTAGGING(TRACE_INPUT_LABEL << ": Making Int32 instead of Smi");
          phi->change_input(i,
                            builder_->GetInt32Constant(
                                input->Cast<SmiConstant>()->value().value()));
          break;
        case ValueRepresentation::kFloat64:
        case ValueRepresentation::kHoleyFloat64:
          TRACE_UNTAGGING(TRACE_INPUT_LABEL
                          << ": Making Float64 instead of Smi");
          phi->change_input(i,
                            builder_->GetFloat64Constant(
                                input->Cast<SmiConstant>()->value().value()));
          break;
        case ValueRepresentation::kUint32:
          UNIMPLEMENTED();
        default:
          UNREACHABLE();
      }
    } else if (Constant* constant = input->TryCast<Constant>()) {
      TRACE_UNTAGGING(TRACE_INPUT_LABEL
                      << ": Making Float64 instead of Constant");
      DCHECK(constant->object().IsHeapNumber());
      DCHECK(repr == ValueRepresentation::kFloat64 ||
             repr == ValueRepresentation::kHoleyFloat64);
      phi->change_input(i, builder_->GetFloat64Constant(
                               constant->object().AsHeapNumber().value()));
    } else if (input->properties().is_conversion()) {
      // Unwrapping the conversion.
      DCHECK_EQ(input->value_representation(), ValueRepresentation::kTagged);
      // Needs to insert a new conversion.
      ValueNode* bypassed_input = input->input(0).node();
      ValueRepresentation from_repr = bypassed_input->value_representation();
      ValueNode* new_input;
      if (from_repr == repr) {
        TRACE_UNTAGGING(TRACE_INPUT_LABEL << ": Bypassing conversion");
        new_input = bypassed_input;
      } else {
        Opcode conv_opcode =
            GetOpcodeForConversion(from_repr, repr, /*truncating*/ false);
        switch (conv_opcode) {
          case Opcode::kChangeInt32ToFloat64: {
            TRACE_UNTAGGING(
                TRACE_INPUT_LABEL
                << ": Replacing old conversion with a ChangeInt32ToFloat64");
            ValueNode* new_node = NodeBase::New<ChangeInt32ToFloat64>(
                builder_->zone(), {input->input(0).node()});
            new_input = AddNodeAtBlockEnd(new_node, phi->predecessor_at(i));
            break;
          }
          case Opcode::kIdentity:
            TRACE_UNTAGGING(TRACE_INPUT_LABEL << ": Bypassing conversion");
            new_input = bypassed_input;
            break;
          default:
            UNREACHABLE();
        }
      }
      phi->change_input(i, new_input);
    } else if (Phi* input_phi = input->TryCast<Phi>()) {
      ValueRepresentation from_repr = input_phi->value_representation();
      if (from_repr == ValueRepresentation::kTagged) {
        // We allow speculative untagging of the backedge for loop phis from
        // loops that have been peeled.
        // This can lead to deopt loops (eg, if after the last iteration of a
        // loop, a loop Phi has a specific representation that it never has in
        // the loop), but this case should (hopefully) be rare.

        // We know that we are on the backedge input of a peeled loop, because
        // if it wasn't the case, then Process(Phi*) would not have decided to
        // untag this Phi, and this function would not have been called (because
        // except for backedges of peeled loops, tagged inputs prevent phi
        // untagging).
        DCHECK(phi->merge_state()->is_loop_with_peeled_iteration());
        DCHECK(phi->is_backedge_offset(i));

        DeoptFrame* deopt_frame = phi->merge_state()->backedge_deopt_frame();
        switch (repr) {
          case ValueRepresentation::kInt32: {
            phi->change_input(
                i, AddNodeAtBlockEnd(NodeBase::New<CheckedSmiUntag>(
                                         builder_->zone(), {input_phi}),
                                     phi->predecessor_at(i), deopt_frame));
            break;
          }
          case ValueRepresentation::kFloat64: {
            phi->change_input(
                i, AddNodeAtBlockEnd(
                       NodeBase::New<CheckedNumberOrOddballToFloat64>(
                           builder_->zone(), {input_phi},
                           TaggedToFloat64ConversionType::kOnlyNumber),
                       phi->predecessor_at(i), deopt_frame));
            break;
          }
          case ValueRepresentation::kHoleyFloat64: {
            phi->change_input(
                i, AddNodeAtBlockEnd(
                       NodeBase::New<CheckedNumberOrOddballToHoleyFloat64>(
                           builder_->zone(), {input_phi},
                           TaggedToFloat64ConversionType::kNumberOrOddball),
                       phi->predecessor_at(i), deopt_frame));
            break;
          }
          case ValueRepresentation::kTagged:
          case ValueRepresentation::kIntPtr:
          case ValueRepresentation::kUint32:
            UNREACHABLE();
        }
        TRACE_UNTAGGING(TRACE_INPUT_LABEL
                        << ": Eagerly untagging Phi on backedge");
      } else if (from_repr != repr &&
                 from_repr == ValueRepresentation::kInt32) {
        // We allow widening of Int32 inputs to Float64, which can lead to the
        // current Phi having a Float64 representation but having some Int32
        // inputs, which will require an Int32ToFloat64 conversion.
        DCHECK(repr == ValueRepresentation::kFloat64 ||
               repr == ValueRepresentation::kHoleyFloat64);
        phi->change_input(i,
                          AddNodeAtBlockEnd(NodeBase::New<ChangeInt32ToFloat64>(
                                                builder_->zone(), {input_phi}),
                                            phi->predecessor_at(i)));
        TRACE_UNTAGGING(
            TRACE_INPUT_LABEL
            << ": Converting phi input with a ChangeInt32ToFloat64");
      } else {
        // We allow Float64 to silently be used as HoleyFloat64.
        DCHECK_IMPLIES(from_repr != repr,
                       from_repr == ValueRepresentation::kFloat64 &&
                           repr == ValueRepresentation::kHoleyFloat64);
        TRACE_UNTAGGING(TRACE_INPUT_LABEL
                        << ": Keeping untagged Phi input as-is");
      }
    } else if (hoist_untagging[i] != HoistType::kNone) {
      CHECK_EQ(input->value_representation(), ValueRepresentation::kTagged);
      BasicBlock* block;
      DeoptFrame* deopt_frame;
      auto GetDeoptFrame = [](BasicBlock* block) {
        return &block->control_node()
                    ->Cast<CheckpointedJump>()
                    ->eager_deopt_info()
                    ->top_frame();
      };
      switch (hoist_untagging[i]) {
        case HoistType::kLoopEntryUnchecked:
          block = phi->merge_state()->predecessor_at(i);
          deopt_frame = nullptr;
          break;
        case HoistType::kLoopEntry:
          block = phi->merge_state()->predecessor_at(i);
          deopt_frame = GetDeoptFrame(block);
          break;
        case HoistType::kPrologue:
          block = *builder_->graph()->begin();
          deopt_frame = GetDeoptFrame(block);
          break;
        case HoistType::kNone:
          UNREACHABLE();
      }
      // Ensure the hoisted value is actually live at the hoist location.
      CHECK(input->Is<InitialValue>() ||
            (phi->is_loop_phi() && !phi->is_backedge_offset(i)));
      ValueNode* untagged;
      switch (repr) {
        case ValueRepresentation::kInt32:
          if (!deopt_frame) {
            DCHECK(
                NodeTypeIs(StaticTypeForNode(builder_->broker(),
                                             builder_->local_isolate(), input),
                           NodeType::kSmi));
            untagged = AddNodeAtBlockEnd(
                NodeBase::New<UnsafeSmiUntag>(builder_->zone(), {input}),
                block);

          } else {
            untagged = AddNodeAtBlockEnd(
                NodeBase::New<CheckedNumberOrOddballToFloat64>(
                    builder_->zone(), {input},
                    TaggedToFloat64ConversionType::kOnlyNumber),
                block, deopt_frame);
            untagged =
                AddNodeAtBlockEnd(NodeBase::New<CheckedTruncateFloat64ToInt32>(
                                      builder_->zone(), {untagged}),
                                  block, deopt_frame);
          }
          break;
        case ValueRepresentation::kFloat64:
        case ValueRepresentation::kHoleyFloat64:
          if (!deopt_frame) {
            DCHECK(
                NodeTypeIs(StaticTypeForNode(builder_->broker(),
                                             builder_->local_isolate(), input),
                           NodeType::kNumber));
            untagged = AddNodeAtBlockEnd(
                NodeBase::New<UncheckedNumberOrOddballToFloat64>(
                    builder_->zone(), {input},
                    TaggedToFloat64ConversionType::kOnlyNumber),
                block);
          } else {
            DCHECK(!phi->uses_require_31_bit_value());
            untagged = AddNodeAtBlockEnd(
                NodeBase::New<CheckedNumberOrOddballToFloat64>(
                    builder_->zone(), {input},
                    TaggedToFloat64ConversionType::kOnlyNumber),
                block, deopt_frame);
            if (repr != ValueRepresentation::kHoleyFloat64) {
              untagged =
                  AddNodeAtBlockEnd(NodeBase::New<CheckedHoleyFloat64ToFloat64>(
                                        builder_->zone(), {untagged}),
                                    block, deopt_frame);
            }
          }
          break;
        case ValueRepresentation::kTagged:
        case ValueRepresentation::kUint32:
        case ValueRepresentation::kIntPtr:
          UNREACHABLE();
      }
      phi->change_input(i, untagged);
    } else {
      TRACE_UNTAGGING(TRACE_INPUT_LABEL << ": Invalid input for untagged phi");
      UNREACHABLE();
    }
  }
}

bool MaglevPhiRepresentationSelector::IsUntagging(Opcode op) {
  switch (op) {
    case Opcode::kCheckedSmiUntag:
    case Opcode::kUnsafeSmiUntag:
    case Opcode::kCheckedObjectToIndex:
    case Opcode::kCheckedTruncateNumberOrOddballToInt32:
    case Opcode::kTruncateNumberOrOddballToInt32:
    case Opcode::kCheckedNumberOrOddballToFloat64:
    case Opcode::kUncheckedNumberOrOddballToFloat64:
    case Opcode::kCheckedNumberOrOddballToHoleyFloat64:
      return true;
    default:
      return false;
  }
}

void MaglevPhiRepresentationSelector::UpdateUntaggingOfPhi(
    Phi* phi, ValueNode* old_untagging) {
  DCHECK_EQ(old_untagging->input_count(), 1);
  DCHECK(old_untagging->input(0).node()->Is<Phi>());

  ValueRepresentation from_repr =
      old_untagging->input(0).node()->value_representation();
  ValueRepresentation to_repr = old_untagging->value_representation();

  // Since initially Phis are tagged, it would make not sense for
  // {old_conversion} to convert a Phi to a Tagged value.
  DCHECK_NE(to_repr, ValueRepresentation::kTagged);
  // The graph builder never inserts Tagged->Uint32 conversions (and thus, we
  // don't handle them in GetOpcodeForCheckedConversion).
  DCHECK_NE(to_repr, ValueRepresentation::kUint32);

  if (from_repr == ValueRepresentation::kTagged) {
    // The Phi hasn't been untagged, so we leave the conversion as it is.
    return;
  }

  if (from_repr == to_repr) {
    if (from_repr == ValueRepresentation::kInt32) {
      if (phi->uses_require_31_bit_value() &&
          old_untagging->Is<CheckedSmiUntag>()) {
        old_untagging->OverwriteWith<CheckedSmiSizedInt32>();
        return;
      }
    }
    old_untagging->OverwriteWith<Identity>();
    return;
  }

  if (old_untagging->Is<UnsafeSmiUntag>()) {
    // UnsafeSmiTag are only inserted when the node is a known Smi. If the
    // current phi has a Float64/Uint32 representation, then we can safely
    // truncate it to Int32, because we know that the Float64/Uint32 fits in a
    // Smi, and therefore in an Int32.
    if (from_repr == ValueRepresentation::kFloat64 ||
        from_repr == ValueRepresentation::kHoleyFloat64) {
      old_untagging->OverwriteWith<UnsafeTruncateFloat64ToInt32>();
    } else if (from_repr == ValueRepresentation::kUint32) {
      old_untagging->OverwriteWith<UnsafeTruncateUint32ToInt32>();
    } else {
      DCHECK_EQ(from_repr, ValueRepresentation::kInt32);
      old_untagging->OverwriteWith<Identity>();
    }
    return;
  }

  // The graph builder inserts 3 kind of Tagged->Int32 conversions that can have
  // heap number as input: CheckedTruncateNumberToInt32, which truncates its
  // input (and deopts if it's not a HeapNumber), TruncateNumberToInt32, which
  // truncates its input (assuming that it's indeed a HeapNumber) and
  // CheckedSmiTag, which deopts on non-smi inputs. The first 2 cannot deopt if
  // we have Float64 phi and will happily truncate it, but the 3rd one should
  // deopt if it cannot be converted without loss of precision.
  bool conversion_is_truncating_float64 =
      old_untagging->Is<CheckedTruncateNumberOrOddballToInt32>() ||
      old_untagging->Is<TruncateNumberOrOddballToInt32>();

  Opcode needed_conversion = GetOpcodeForConversion(
      from_repr, to_repr, conversion_is_truncating_float64);

  if (CheckedNumberOrOddballToFloat64* number_untagging =
          old_untagging->TryCast<CheckedNumberOrOddballToFloat64>()) {
    if (from_repr == ValueRepresentation::kHoleyFloat64 &&
        number_untagging->conversion_type() !=
            TaggedToFloat64ConversionType::kNumberOrOddball) {
      // {phi} is a HoleyFloat64 (and thus, it could be a hole), but the
      // original untagging did not allow holes.
      needed_conversion = Opcode::kCheckedHoleyFloat64ToFloat64;
    }
  }

  if (needed_conversion != old_untagging->opcode()) {
    old_untagging->OverwriteWith(needed_conversion);
  }
}

ProcessResult MaglevPhiRepresentationSelector::UpdateNodePhiInput(
    CheckSmi* node, Phi* phi, int input_index, const ProcessingState* state) {
  DCHECK_EQ(input_index, 0);

  switch (phi->value_representation()) {
    case ValueRepresentation::kTagged:
      return ProcessResult::kContinue;

    case ValueRepresentation::kInt32:
      if (!SmiValuesAre32Bits()) {
        node->OverwriteWith<CheckInt32IsSmi>();
        return ProcessResult::kContinue;
      } else {
        return ProcessResult::kRemove;
      }

    case ValueRepresentation::kFloat64:
    case ValueRepresentation::kHoleyFloat64:
      node->OverwriteWith<CheckHoleyFloat64IsSmi>();
      return ProcessResult::kContinue;

    case ValueRepresentation::kUint32:
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
  }
}

ProcessResult MaglevPhiRepresentationSelector::UpdateNodePhiInput(
    CheckNumber* node, Phi* phi, int input_index,
    const ProcessingState* state) {
  if (phi->value_representation() != ValueRepresentation::kTagged) {
    // The phi was untagged, so we know that it's a number. We thus remove this
    // CheckNumber from the graph.
    return ProcessResult::kRemove;
  }
  return UpdateNodePhiInput(static_cast<NodeBase*>(node), phi, input_index,
                            state);
}

// If the input of a StoreTaggedFieldNoWriteBarrier was a Phi that got
// untagged, then we need to retag it, and we might need to actually use a write
// barrier.
ProcessResult MaglevPhiRepresentationSelector::UpdateNodePhiInput(
    StoreTaggedFieldNoWriteBarrier* node, Phi* phi, int input_index,
    const ProcessingState* state) {
  if (input_index == StoreTaggedFieldNoWriteBarrier::kObjectIndex) {
    // The 1st input of a Store should usually not be untagged. However, it is
    // possible to write `let x = a ? 4 : 2; x.c = 10`, which will produce a
    // store whose receiver could be an untagged Phi. So, for such cases, we use
    // the generic UpdateNodePhiInput method to tag `phi` if needed.
    return UpdateNodePhiInput(static_cast<NodeBase*>(node), phi, input_index,
                              state);
  }
  DCHECK_EQ(input_index, StoreTaggedFieldNoWriteBarrier::kValueIndex);

  if (phi->value_representation() != ValueRepresentation::kTagged) {
    // We need to tag {phi}. However, this could turn it into a HeapObject
    // rather than a Smi (either because {phi} is a Float64 phi, or because it's
    // an Int32/Uint32 phi that doesn't fit on 31 bits), so we need the write
    // barrier.
    node->change_input(
        input_index,
        EnsurePhiTagged(phi, current_block_,
                        NewNodePosition::kBeforeCurrentNode, state));
    static_assert(StoreTaggedFieldNoWriteBarrier::kObjectIndex ==
                  StoreTaggedFieldWithWriteBarrier::kObjectIndex);
    static_assert(StoreTaggedFieldNoWriteBarrier::kValueIndex ==
                  StoreTaggedFieldWithWriteBarrier::kValueIndex);
    node->OverwriteWith<StoreTaggedFieldWithWriteBarrier>();
  }

  return ProcessResult::kContinue;
}

// If the input of a StoreFixedArrayElementNoWriteBarrier was a Phi that got
// untagged, then we need to retag it, and we might need to actually use a write
// barrier.
ProcessResult MaglevPhiRepresentationSelector::UpdateNodePhiInput(
    StoreFixedArrayElementNoWriteBarrier* node, Phi* phi, int input_index,
    const ProcessingState* state) {
  if (input_index != StoreFixedArrayElementNoWriteBarrier::kValueIndex) {
    return UpdateNodePhiInput(static_cast<NodeBase*>(node), phi, input_index,
                              state);
  }

  if (phi->value_representation() != ValueRepresentation::kTagged) {
    // We need to tag {phi}. However, this could turn it into a HeapObject
    // rather than a Smi (either because {phi} is a Float64 phi, or because it's
    // an Int32/Uint32 phi that doesn't fit on 31 bits), so we need the write
    // barrier.
    node->change_input(
        input_index,
        EnsurePhiTagged(phi, current_block_,
                        NewNodePosition::kBeforeCurrentNode, state));
    static_assert(StoreFixedArrayElementNoWriteBarrier::kElementsIndex ==
                  StoreFixedArrayElementWithWriteBarrier::kElementsIndex);
    static_assert(StoreFixedArrayElementNoWriteBarrier::kIndexIndex ==
                  StoreFixedArrayElementWithWriteBarrier::kIndexIndex);
    static_assert(StoreFixedArrayElementNoWriteBarrier::kValueIndex ==
                  StoreFixedArrayElementWithWriteBarrier::kValueIndex);
    node->OverwriteWith<StoreFixedArrayElementWithWriteBarrier>();
  }

  return ProcessResult::kContinue;
}

// When a BranchIfToBooleanTrue has an untagged Int32/Float64 Phi as input, we
// convert it to a BranchIfInt32ToBooleanTrue/BranchIfFloat6ToBooleanTrue to
// avoid retagging the Phi.
ProcessResult MaglevPhiRepresentationSelector::UpdateNodePhiInput(
    BranchIfToBooleanTrue* node, Phi* phi, int input_index,
    const ProcessingState* state) {
  DCHECK_EQ(input_index, 0);

  switch (phi->value_representation()) {
    case ValueRepresentation::kInt32:
      node->OverwriteWith<BranchIfInt32ToBooleanTrue>();
      return ProcessResult::kContinue;

    case ValueRepresentation::kFloat64:
    case ValueRepresentation::kHoleyFloat64:
      node->OverwriteWith<BranchIfFloat64ToBooleanTrue>();
      return ProcessResult::kContinue;

    case ValueRepresentation::kTagged:
      return ProcessResult::kContinue;

    case ValueRepresentation::kUint32:
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
  }
}

// {node} was using {phi} without any untagging, which means that it was using
// {phi} as a tagged value, so, if we've untagged {phi}, we need to re-tag it
// for {node}.
ProcessResult MaglevPhiRepresentationSelector::UpdateNodePhiInput(
    NodeBase* node, Phi* phi, int input_index, const ProcessingState* state) {
  if (node->properties().is_conversion()) {
    // {node} can't be an Untagging if we reached this point (because
    // UpdateNodePhiInput is not called on untagging nodes).
    DCHECK(!IsUntagging(node->opcode()));
    // So, {node} has to be a conversion that takes an input an untagged node,
    // and this input happens to be {phi}, which means that {node} is aware that
    // {phi} isn't tagged. This means that {node} was inserted during the
    // current phase. In this case, we don't do anything.
    DCHECK_NE(phi->value_representation(), ValueRepresentation::kTagged);
    DCHECK_NE(new_nodes_.find(node), new_nodes_.end());
  } else {
    node->change_input(
        input_index,
        EnsurePhiTagged(phi, current_block_,
                        NewNodePosition::kBeforeCurrentNode, state));
  }
  return ProcessResult::kContinue;
}

ValueNode* MaglevPhiRepresentationSelector::EnsurePhiTagged(
    Phi* phi, BasicBlock* block, NewNodePosition pos,
    const ProcessingState* state, std::optional<int> predecessor_index) {
  DCHECK_IMPLIES(state == nullptr, pos == NewNodePosition::kEndOfBlock);

  if (phi->value_representation() == ValueRepresentation::kTagged) {
    return phi;
  }

  // Try to find an existing Tagged conversion for {phi} in {phi_taggings_}.
  if (phi->has_key()) {
    if (predecessor_index.has_value()) {
      if (ValueNode* tagging = phi_taggings_.GetPredecessorValue(
              phi->key(), predecessor_index.value())) {
        return tagging;
      }
    } else {
      if (ValueNode* tagging = phi_taggings_.Get(phi->key())) {
        return tagging;
      }
    }
  }

  // We didn't already Tag {phi} on the current path; creating this tagging now.
  ValueNode* tagged = nullptr;
  switch (phi->value_representation()) {
    case ValueRepresentation::kFloat64:
      // It's important to use kCanonicalizeSmi for Float64ToTagged, as
      // otherwise, we could end up storing HeapNumbers in Smi fields.
      tagged = AddNode(NodeBase::New<Float64ToTagged>(
                           builder_->zone(), {phi},
                           Float64ToTagged::ConversionMode::kCanonicalizeSmi),
                       block, pos, state);
      break;
    case ValueRepresentation::kHoleyFloat64:
      // It's important to use kCanonicalizeSmi for HoleyFloat64ToTagged, as
      // otherwise, we could end up storing HeapNumbers in Smi fields.
      tagged =
          AddNode(NodeBase::New<HoleyFloat64ToTagged>(
                      builder_->zone(), {phi},
                      HoleyFloat64ToTagged::ConversionMode::kCanonicalizeSmi),
                  block, pos, state);
      break;
    case ValueRepresentation::kInt32:
      tagged = AddNode(NodeBase::New<Int32ToNumber>(builder_->zone(), {phi}),
                       block, pos, state);
      break;
    case ValueRepresentation::kUint32:
      tagged = AddNode(NodeBase::New<Uint32ToNumber>(builder_->zone(), {phi}),
                       block, pos, state);
      break;
    case ValueRepresentation::kTagged:
      // Already handled at the begining of this function.
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
  }

  if (predecessor_index.has_value()) {
    // We inserted the new tagging node in a predecessor of the current block,
    // so we shouldn't update the snapshot table for the current block (and we
    // can't update it for the predecessor either since its snapshot is sealed).
    DCHECK_IMPLIES(block == current_block_,
                   block->is_loop() && block->successors().size() == 1 &&
                       block->successors().at(0) == block);
    return tagged;
  }

  if (phi->has_key()) {
    // The Key already existed, but wasn't set on the current path.
    phi_taggings_.Set(phi->key(), tagged);
  } else {
    // The Key didn't already exist, so we create it now.
    auto key = phi_taggings_.NewKey();
    phi->set_key(key);
    phi_taggings_.Set(key, tagged);
  }
  return tagged;
}

void MaglevPhiRepresentationSelector::FixLoopPhisBackedge(BasicBlock* block) {
  // TODO(dmercadier): it would be interesting to compute a fix point for loop
  // phis, or at least to go over the loop header twice.
  if (!block->has_phi()) return;
  for (Phi* phi : *block->phis()) {
    int last_input_idx = phi->input_count() - 1;
    ValueNode* backedge = phi->input(last_input_idx).node();
    if (phi->value_representation() == ValueRepresentation::kTagged) {
      // If the backedge is a Phi that was untagged, but {phi} is tagged, then
      // we need to retag the backedge.

      // Identity nodes are used to replace outdated untagging nodes after a phi
      // has been untagged. Here, since the backedge was initially tagged, it
      // couldn't have been such an untagging node, so it shouldn't be an
      // Identity node now.
      DCHECK(!backedge->Is<Identity>());

      if (backedge->value_representation() != ValueRepresentation::kTagged) {
        // Since all Phi inputs are initially tagged, the fact that the backedge
        // is not tagged means that it's a Phi that we recently untagged.
        DCHECK(backedge->Is<Phi>());
        phi->change_input(
            last_input_idx,
            EnsurePhiTagged(backedge->Cast<Phi>(), current_block_,
                            NewNodePosition::kEndOfBlock, /*state*/ nullptr));
      }
    } else {
      // If {phi} was untagged and its backedge became Identity, then we need to
      // unwrap it.
      DCHECK_NE(phi->value_representation(), ValueRepresentation::kTagged);
      if (backedge->Is<Identity>()) {
        // {backedge} should have the same representation as {phi}, although if
        // {phi} has HoleyFloat64 representation, the backedge is allowed to
        // have Float64 representation rather than HoleyFloat64.
        DCHECK((backedge->input(0).node()->value_representation() ==
                phi->value_representation()) ||
               (backedge->input(0).node()->value_representation() ==
                    ValueRepresentation::kFloat64 &&
                phi->value_representation() ==
                    ValueRepresentation::kHoleyFloat64));
        phi->change_input(last_input_idx, backedge->input(0).node());
      }
    }
  }
}

template <typename DeoptInfoT>
void MaglevPhiRepresentationSelector::BypassIdentities(DeoptInfoT* deopt_info) {
  detail::DeepForEachInputRemovingIdentities(
      deopt_info, [&](ValueNode* node, InputLocation* input) {});
}

template void MaglevPhiRepresentationSelector::BypassIdentities<EagerDeoptInfo>(
    EagerDeoptInfo*);
template void MaglevPhiRepresentationSelector::BypassIdentities<LazyDeoptInfo>(
    LazyDeoptInfo*);

ValueNode* MaglevPhiRepresentationSelector::AddNodeAtBlockEnd(
    ValueNode* node, BasicBlock* block, DeoptFrame* deopt_frame) {
  return AddNode(node, block, NewNodePosition::kEndOfBlock, nullptr,
                 deopt_frame);
}

ValueNode* MaglevPhiRepresentationSelector::AddNode(
    ValueNode* node, BasicBlock* block, NewNodePosition pos,
    const ProcessingState* state, DeoptFrame* deopt_frame) {
  if (node->properties().can_eager_deopt()) {
    DCHECK_NOT_NULL(deopt_frame);
    node->SetEagerDeoptInfo(builder_->zone(), *deopt_frame);
  }

  if (pos == NewNodePosition::kBeforeCurrentNode) {
    DCHECK_EQ(block, current_block_);
    DCHECK_NOT_NULL(state);
    state->node_it()->InsertBefore(node);
  } else {
    block->nodes().Add(node);
  }

  RegisterNewNode(node);
  return node;
}

void MaglevPhiRepresentationSelector::RegisterNewNode(ValueNode* node) {
  if (builder_->has_graph_labeller()) {
    builder_->graph_labeller()->RegisterNode(node);
  }
#ifdef DEBUG
  new_nodes_.insert(node);
#endif
}

void MaglevPhiRepresentationSelector::PreparePhiTaggings(
    BasicBlock* old_block, const BasicBlock* new_block) {
  // Sealing and saving current snapshot
  if (phi_taggings_.IsSealed()) {
    phi_taggings_.StartNewSnapshot();
    return;
  }
  old_block->SetSnapshot(phi_taggings_.Seal());

  // Setting up new snapshot
  predecessors_.clear();

  if (!new_block->is_merge_block()) {
    BasicBlock* pred = new_block->predecessor();
    predecessors_.push_back(pred->snapshot());
  } else {
    int skip_backedge = new_block->is_loop();
    for (int i = 0; i < new_block->predecessor_count() - skip_backedge; i++) {
      BasicBlock* pred = new_block->predecessor_at(i);
      predecessors_.push_back(pred->snapshot());
    }
  }

  auto merge_taggings =
      [&](Key key, base::Vector<ValueNode* const> predecessors) -> ValueNode* {
    for (ValueNode* node : predecessors) {
      if (node == nullptr) {
        // There is a predecessor that doesn't have this Tagging, so we'll
        // return nullptr, and if we need it in the future, we'll have to
        // recreate it. An alternative would be to eagerly insert this Tagging
        // in all of the other predecesors, but it's possible that it's not used
        // anymore or not on all future path, so this could also introduce
        // unnecessary tagging.
        return static_cast<Phi*>(nullptr);
      }
    }

    // Only merge blocks should require Phis.
    DCHECK(new_block->is_merge_block());

    // We create a Phi to merge all of the existing taggings.
    int predecessor_count = new_block->predecessor_count();
    Phi* phi = Node::New<Phi>(builder_->zone(), predecessor_count,
                              new_block->state(), interpreter::Register());
    for (int i = 0; static_cast<size_t>(i) < predecessors.size(); i++) {
      phi->set_input(i, predecessors[i]);
    }
    if (predecessors.size() != static_cast<size_t>(predecessor_count)) {
      // The backedge is omitted from {predecessors}. With set the Phi as its
      // own backedge.
      DCHECK(new_block->is_loop());
      phi->set_input(predecessor_count - 1, phi);
    }
    RegisterNewNode(phi);
    new_block->AddPhi(phi);

    return phi;
  };

  phi_taggings_.StartNewSnapshot(base::VectorOf(predecessors_), merge_taggings);
}

}  // namespace maglev
}  // namespace internal
}  // namespace v8
```