Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/maglev/maglev-phi-representation-selector.cc`.

Here's a breakdown of the thinking process to answer the user's request:

1. **Identify the Core Purpose:** The file name `maglev-phi-representation-selector.cc` strongly suggests that this code is responsible for selecting the optimal data representation for Phi nodes within the Maglev compiler. Phi nodes represent the merging of values from different control flow paths.

2. **Analyze the `PreProcessBasicBlock` Function:** This function is the entry point for processing each basic block. It iterates through the Phi nodes within a block and calls `ProcessPhi` for each. The "retry" mechanism suggests that the representation selection might be iterative, as the best representation for one Phi might depend on the representation of others.

3. **Deep Dive into `ProcessPhi`:** This is the heart of the representation selection logic. The code checks the current representation of the Phi and attempts to "untag" it (change it from a generic "tagged" representation to a more specific one like `int32` or `float64`).

4. **Understand Untagging Conditions:** The code carefully examines the inputs and uses of a Phi node to determine if untagging is possible and beneficial. Key factors considered:
    * **Input Representations:**  If all inputs can be represented as a specific unboxed type (e.g., `SmiConstant` implies `int32`).
    * **Use Representations:** How the Phi node's value is used later in the code. If it's only used in operations that require integers, it's safe to untag to `int32`.
    * **Conversions:**  If inputs are already being converted, the code might bypass or adjust these conversions.
    * **Loop Considerations:** Special handling for Phi nodes in loops, particularly for back edges and peeled iterations. The code attempts to "hoist" untagging operations out of loops for performance.

5. **Trace Logging:** The `#define TRACE_UNTAGGING` macro indicates that this code is crucial for performance and debugging. It allows developers to track the untagging decisions being made.

6. **`ConvertTaggedPhiTo` Function:**  This function performs the actual untagging of a Phi node. It changes the Phi's representation and updates its inputs, potentially inserting or modifying conversion nodes.

7. **`EnsurePhiInputsTagged` Function:**  The counterpart to untagging. If a Phi remains tagged, this function ensures that its untagged Phi inputs are explicitly tagged.

8. **`GetOpcodeForConversion` Function:** This helper function determines the appropriate low-level operation (opcode) for converting between different data representations.

9. **`IsUntagging` Function:** A simple helper to check if a given opcode represents an untagging operation.

10. **`UpdateUntaggingOfPhi` Function:** This function seems to refine existing untagging operations based on changes in the Phi's representation.

11. **`UpdateNodePhiInput` Function:** This function deals with specific node types (like `CheckSmi`) and adjusts their inputs based on the Phi's representation. The snippet provided is incomplete, but its purpose is evident.

12. **Relate to JavaScript:**  Think about how JavaScript's dynamic typing translates to the need for these optimizations. JavaScript variables can hold values of different types. Maglev, as a compiler for V8, tries to optimize by inferring and using more specific representations when possible. Untagging is about moving away from the generic "tagged" representation.

13. **Identify Potential Programming Errors:**  Consider scenarios where incorrect representation choices or missing conversions could lead to runtime errors or deoptimizations.

14. **Structure the Answer:** Organize the findings into clear sections addressing the user's specific questions:
    * Functionality overview
    * Torque source check
    * JavaScript relevance with examples
    * Code logic reasoning (with assumptions and outputs)
    * Common programming errors
    * Summary of functionality.

15. **Refine and Elaborate:**  Add details and explanations to make the answer comprehensive and easy to understand for someone familiar with compiler concepts but possibly not the specifics of V8's Maglev. For example, explain the concept of "tagged" and "untagged" representations.
```cpp
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
                NodeBase::New
Prompt: 
```
这是目录为v8/src/maglev/maglev-phi-representation-selector.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-phi-representation-selector.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
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
        node->
"""


```