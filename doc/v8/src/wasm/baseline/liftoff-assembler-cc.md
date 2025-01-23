Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/wasm/baseline/liftoff-assembler.cc`.

Here's a breakdown of the thought process to address the request:

1. **Identify the Core Functionality:**  The filename "liftoff-assembler.cc" strongly suggests that this code is related to assembling WebAssembly code using the Liftoff compiler within V8. The presence of classes like `LiftoffAssembler`, `CacheState`, and `ParallelMove` reinforces this.

2. **Analyze Key Classes and Methods:**
    * **`LiftoffAssembler`:** The central class likely responsible for emitting machine code instructions. Look for methods that manipulate the stack, registers, and memory.
    * **`CacheState`:**  This seems to manage the state of values (locals, stack slots, constants) during code generation, including their location (register or stack).
    * **`ParallelMove`:**  Likely handles efficient movement of data between registers and stack locations, especially when multiple moves are needed simultaneously.
    * **`MergeIntoNewState`:**  This function seems crucial for managing the state of the stack and registers during control flow merges (e.g., at the target of a branch). It aims to create a consistent target state.
    * **`MergeStackWith` and `MergeFullStackWith`:** These functions probably handle merging the state when jumping to a different point in the code, ensuring data is in the correct locations.
    * **`Spill`:**  The mechanism for moving a value from a register to the stack.
    * **`LoadToRegister`:**  The mechanism for moving a value from the stack to a register.
    * **`PrepareCall` and `PrepareBuiltinCall`:** Functions involved in setting up the stack and registers before making a function call (either to a WebAssembly function or a built-in V8 function).

3. **Infer High-Level Functionality:** Based on the classes and methods, the code appears to be responsible for:
    * **Register Allocation and Management:** Keeping track of which registers are in use and allocating free registers.
    * **Stack Management:** Allocating and managing the WebAssembly stack frame.
    * **Data Movement:** Moving data between registers, stack slots, and constants.
    * **State Merging:**  Ensuring consistency of the stack and register state at control flow merge points.
    * **Function Call Setup:** Preparing the stack and registers according to the calling convention before making function calls.
    * **Safepoint Definition:**  Generating information needed by the garbage collector to locate live objects during execution.

4. **Address Specific Questions:**

    * **`.tq` Extension:** The code clearly includes `#include` directives for C++ headers (`.h`). Therefore, it's C++ and not Torque.
    * **Relationship to JavaScript:**  While not directly JavaScript code, this code is a crucial part of V8's WebAssembly execution pipeline. It's the layer that translates the WebAssembly bytecode into actual machine instructions that the CPU can execute. The interaction happens when JavaScript calls WebAssembly functions or vice versa.
    * **Code Logic Inference:** Focus on the `MergeIntoNewState` function as it demonstrates complex logic for managing state. Think about different scenarios (keeping stack slots, turning them into registers, handling constants) and how the function aims to create a consistent target state. Consider edge cases and the purpose of parameters like `allow_constants` and `reuse_registers`.
    * **Common Programming Errors:**  Relate this to the context of a compiler or runtime. Common errors could involve incorrect register usage, stack corruption, or inconsistencies in the managed state. Think about the consequences of these errors (e.g., wrong results, crashes).

5. **Structure the Output:** Organize the information clearly, starting with a summary of the main functionality. Then, address each of the user's specific points. Use clear and concise language. For the JavaScript example, illustrate how it triggers the use of this C++ code. For the code logic, provide a clear scenario with inputs and expected outputs. For common errors, give relatable examples.

6. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check if all aspects of the prompt have been addressed.

Self-Correction/Refinement during the thought process:

* Initially, I might have focused too much on the individual assembly instructions. However, the code is higher-level than that; it's managing the *state* used for generating instructions. Shifting focus to state management (registers and stack) is key.
* Recognizing that this is *Liftoff* assembler is important. Liftoff is a fast, single-pass compiler, which explains the need for efficient state management and data movement.
* The connection to garbage collection via safepoints is a vital aspect of any language runtime and should be included.
* When considering common programming errors, think from the perspective of a *compiler developer* rather than a general application developer. The errors are about managing the internal state correctly during compilation.

By following these steps, the detailed and informative answer provided in the initial example can be constructed.
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/baseline/liftoff-assembler.h"

#include <optional>
#include <sstream>

#include "src/base/platform/memory.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/compiler/linkage.h"
#include "src/compiler/wasm-compiler.h"
#include "src/utils/ostreams.h"
#include "src/wasm/baseline/liftoff-assembler-inl.h"
#include "src/wasm/baseline/liftoff-register.h"
#include "src/wasm/baseline/parallel-move-inl.h"
#include "src/wasm/object-access.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-opcodes.h"

namespace v8::internal::wasm {

using VarState = LiftoffAssembler::VarState;
using ValueKindSig = LiftoffAssembler::ValueKindSig;

constexpr ValueKind LiftoffAssembler::kIntPtrKind;
constexpr ValueKind LiftoffAssembler::kSmiKind;

namespace {

class RegisterReuseMap {
 public:
  void Add(LiftoffRegister src, LiftoffRegister dst) {
    if ([[maybe_unused]] auto previous = Lookup(src)) {
      DCHECK_EQ(previous, dst);
      return;
    }
    map_.emplace_back(src);
    map_.emplace_back(dst);
  }

  std::optional<LiftoffRegister> Lookup(LiftoffRegister src) {
    for (auto it = map_.begin(), end = map_.end(); it != end; it += 2) {
      if (it->is_gp_pair() == src.is_gp_pair() &&
          it->is_fp_pair() == src.is_fp_pair() && *it == src)
        return *(it + 1);
    }
    return {};
  }

 private:
  // {map_} holds pairs of <src, dst>.
  base::SmallVector<LiftoffRegister, 8> map_;
};

enum MergeKeepStackSlots : bool {
  kKeepStackSlots = true,
  kTurnStackSlotsIntoRegisters = false
};
enum MergeAllowConstants : bool {
  kConstantsAllowed = true,
  kConstantsNotAllowed = false
};
enum MergeAllowRegisters : bool {
  kRegistersAllowed = true,
  kRegistersNotAllowed = false
};
enum ReuseRegisters : bool {
  kReuseRegisters = true,
  kNoReuseRegisters = false
};
// {InitMergeRegion} is a helper used by {MergeIntoNewState} to initialize
// a part of the target stack ([target, target+count]) from [source,
// source+count]. The parameters specify how to initialize the part. The goal is
// to set up the region such that later merges (via {MergeStackWith} /
// {MergeFullStackWith} can successfully transfer their values to this new
// state.
void InitMergeRegion(LiftoffAssembler::CacheState* target_state,
                     const VarState* source, VarState* target, uint32_t count,
                     MergeKeepStackSlots keep_stack_slots,
                     MergeAllowConstants allow_constants,
                     MergeAllowRegisters allow_registers,
                     ReuseRegisters reuse_registers, LiftoffRegList used_regs,
                     int new_stack_offset, ParallelMove& parallel_move) {
  RegisterReuseMap register_reuse_map;
  for (const VarState* source_end = source + count; source < source_end;
       ++source, ++target) {
    if (source->is_stack() && keep_stack_slots) {
      *target = *source;
      // If {new_stack_offset} is set, we want to recompute stack offsets for
      // the region we are initializing such that they are contiguous. If
      // {new_stack_offset} is zero (which is an illegal stack offset), we just
      // keep the source offsets.
      if (new_stack_offset) {
        new_stack_offset =
            LiftoffAssembler::NextSpillOffset(source->kind(), new_stack_offset);
        if (new_stack_offset != source->offset()) {
          target->set_offset(new_stack_offset);
          parallel_move.TransferToStack(new_stack_offset, *source);
        }
      }
      continue;
    }
    if (source->is_const() && allow_constants) {
      *target = *source;
      DCHECK(!new_stack_offset);
      continue;
    }
    std::optional<LiftoffRegister> reg;
    bool needs_reg_transfer = true;
    if (allow_registers) {
      // First try: Keep the same register, if it's free.
      if (source->is_reg() && target_state->is_free(source->reg())) {
        reg = source->reg();
        needs_reg_transfer = false;
      }
      // Second try: Use the same register we used before (if we reuse
      // registers).
      if (!reg && reuse_registers) {
        reg = register_reuse_map.Lookup(source->reg());
      }
      // Third try: Use any free register.
      RegClass rc = reg_class_for(source->kind());
      if (!reg && target_state->has_unused_register(rc, used_regs)) {
        reg = target_state->unused_register(rc, used_regs);
      }
    }
    // See above: Recompute the stack offset if requested.
    int target_offset = source->offset();
    if (new_stack_offset) {
      new_stack_offset =
          LiftoffAssembler::NextSpillOffset(source->kind(), new_stack_offset);
      target_offset = new_stack_offset;
    }
    if (reg) {
      if (needs_reg_transfer) parallel_move.LoadIntoRegister(*reg, *source);
      if (reuse_registers) register_reuse_map.Add(source->reg(), *reg);
      target_state->inc_used(*reg);
      *target = VarState(source->kind(), *reg, target_offset);
    } else {
      // No free register; make this a stack slot.
      *target = VarState(source->kind(), target_offset);
      parallel_move.TransferToStack(target_offset, *source);
    }
  }
}

}  // namespace

LiftoffAssembler::CacheState LiftoffAssembler::MergeIntoNewState(
    uint32_t num_locals, uint32_t arity, uint32_t stack_depth) {
  CacheState target{zone()};

  // The source state looks like this:
  // |------locals------|---(stack prefix)---|--(discarded)--|----merge----|
  //  <-- num_locals --> <-- stack_depth  -->                 <-- arity -->
  //
  // We compute the following target state from it:
  // |------locals------|---(stack prefix)----|----merge----|
  //  <-- num_locals --> <-- stack_depth   --> <-- arity -->
  //
  // The target state will have dropped the "(discarded)" region, and the
  // "locals" and "merge" regions have been modified to avoid any constants and
  // avoid duplicate register uses. This ensures that later merges can
  // successfully transfer into the target state.
  // The "stack prefix" region will be identical for any source that merges into
  // that state.

  if (cache_state_.cached_instance_data != no_reg) {
    target.SetInstanceCacheRegister(cache_state_.cached_instance_data);
  }

  DCHECK_EQ(cache_state_.cached_mem_start == no_reg,
            cache_state_.cached_mem_index == CacheState::kNoCachedMemIndex);
  if (cache_state_.cached_mem_start != no_reg) {
    target.SetMemStartCacheRegister(cache_state_.cached_mem_start,
                                    cache_state_.cached_mem_index);
  }

  uint32_t target_height = num_locals + stack_depth + arity;

  target.stack_state.resize_no_init(target_height);

  const VarState* source_begin = cache_state_.stack_state.data();
  VarState* target_begin = target.stack_state.data();

  // Compute the starts of the different regions, for source and target (see
  // pictograms above).
  const VarState* locals_source = source_begin;
  const VarState* stack_prefix_source = source_begin + num_locals;
  const VarState* discarded_source = stack_prefix_source + stack_depth;
  const VarState* merge_source = cache_state_.stack_state.end() - arity;
  VarState* locals_target = target_begin;
  VarState* stack_prefix_target = target_begin + num_locals;
  VarState* merge_target = target_begin + num_locals + stack_depth;

  // Try to keep locals and the merge region in their registers. Registers used
  // multiple times need to be copied to another free register. Compute the list
  // of used registers.
  LiftoffRegList used_regs;
  for (auto& src : base::VectorOf(locals_source, num_locals)) {
    if (src.is_reg()) used_regs.set(src.reg());
  }
  // If there is more than one operand in the merge region, a stack-to-stack
  // move can interfere with a register reload, which would not be handled
  // correctly by the ParallelMove. To avoid this, spill all registers in
  // this region.
  MergeAllowRegisters allow_registers =
      arity <= 1 ? kRegistersAllowed : kRegistersNotAllowed;
  if (allow_registers) {
    for (auto& src : base::VectorOf(merge_source, arity)) {
      if (src.is_reg()) used_regs.set(src.reg());
    }
  }

  ParallelMove parallel_move{this};

  // The merge region is often empty, hence check for this before doing any
  // work (even though not needed for correctness).
  if (arity) {
    // Initialize the merge region. If this region moves, try to turn stack
    // slots into registers since we need to load the value anyways.
    MergeKeepStackSlots keep_merge_stack_slots =
        target_height == cache_state_.stack_height()
            ? kKeepStackSlots
            : kTurnStackSlotsIntoRegisters;
    // Shift spill offsets down to keep slots contiguous. We place the merge
    // region right after the "stack prefix", if it exists.
    int merge_region_stack_offset = discarded_source == source_begin
                                        ? StaticStackFrameSize()
                                        : discarded_source[-1].offset();
    InitMergeRegion(&target, merge_source, merge_target, arity,
                    keep_merge_stack_slots, kConstantsNotAllowed,
                    allow_registers, kNoReuseRegisters, used_regs,
                    merge_region_stack_offset, parallel_move);
  }

  // Initialize the locals region. Here, stack slots stay stack slots (because
  // they do not move). Try to keep register in registers, but avoid duplicates.
  if (num_locals) {
    InitMergeRegion(&target, locals_source, locals_target, num_locals,
                    kKeepStackSlots, kConstantsNotAllowed, kRegistersAllowed,
                    kNoReuseRegisters, used_regs, 0, parallel_move);
  }
  // Consistency check: All the {used_regs} are really in use now.
  DCHECK_EQ(used_regs, target.used_registers & used_regs);

  // Last, initialize the "stack prefix" region. Here, constants are allowed,
  // but registers which are already used for the merge region or locals must be
  // moved to other registers or spilled. If a register appears twice in the
  // source region, ensure to use the same register twice in the target region.
  if (stack_depth) {
    InitMergeRegion(&target, stack_prefix_source, stack_prefix_target,
                    stack_depth, kKeepStackSlots, kConstantsAllowed,
                    kRegistersAllowed, kReuseRegisters, used_regs, 0,
                    parallel_move);
  }

  return target;
}

void LiftoffAssembler::CacheState::Steal(CacheState& source) {
  // Just use the move assignment operator.
  *this = std::move(source);
}

void LiftoffAssembler::CacheState::Split(const CacheState& source) {
  // Call the private copy assignment operator.
  *this = source;
}

namespace {
int GetSafepointIndexForStackSlot(const VarState& slot) {
  // index = 0 is for the stack slot at 'fp + kFixedFrameSizeAboveFp -
  // kSystemPointerSize', the location of the current stack slot is 'fp -
  // slot.offset()'. The index we need is therefore '(fp +
  // kFixedFrameSizeAboveFp - kSystemPointerSize) - (fp - slot.offset())' =
  // 'slot.offset() + kFixedFrameSizeAboveFp - kSystemPointerSize'.
  // Concretely, the index of the first stack slot is '4'.
  return (slot.offset() + StandardFrameConstants::kFixedFrameSizeAboveFp -
          kSystemPointerSize) /
         kSystemPointerSize;
}
}  // namespace

void LiftoffAssembler::CacheState::GetTaggedSlotsForOOLCode(
    ZoneVector<int>* slots, LiftoffRegList* spills,
    SpillLocation spill_location) {
  for (const auto& slot : stack_state) {
    if (!is_reference(slot.kind())) continue;

    if (spill_location == SpillLocation::kTopOfStack && slot.is_reg()) {
      // Registers get spilled just before the call to the runtime. In {spills}
      // we store which of the spilled registers contain references, so that we
      // can add the spill slots to the safepoint.
      spills->set(slot.reg());
      continue;
    }
    DCHECK_IMPLIES(slot.is_reg(), spill_location == SpillLocation::kStackSlots);

    slots->push_back(GetSafepointIndexForStackSlot(slot));
  }
}

void LiftoffAssembler::CacheState::DefineSafepoint(
    SafepointTableBuilder::Safepoint& safepoint) {
  // Go in reversed order to set the higher bits first; this avoids cost for
  // growing the underlying bitvector.
  for (const auto& slot : base::Reversed(stack_state)) {
    if (is_reference(slot.kind())) {
      // TODO(v8:14422): References that are not on the stack now will get lost
      // at the moment. Once v8:14422 is resolved, this `continue` should be
      // revisited and potentially updated to a DCHECK.
      if (!slot.is_stack()) continue;
      safepoint.DefineTaggedStackSlot(GetSafepointIndexForStackSlot(slot));
    }
  }
}

void LiftoffAssembler::CacheState::DefineSafepointWithCalleeSavedRegisters(
    SafepointTableBuilder::Safepoint& safepoint) {
  for (const auto& slot : stack_state) {
    if (!is_reference(slot.kind())) continue;
    if (slot.is_stack()) {
      safepoint.DefineTaggedStackSlot(GetSafepointIndexForStackSlot(slot));
    } else {
      DCHECK(slot.is_reg());
      safepoint.DefineTaggedRegister(slot.reg().gp().code());
    }
  }
  if (cached_instance_data != no_reg) {
    safepoint.DefineTaggedRegister(cached_instance_data.code());

### 提示词
```
这是目录为v8/src/wasm/baseline/liftoff-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/liftoff-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/baseline/liftoff-assembler.h"

#include <optional>
#include <sstream>

#include "src/base/platform/memory.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/compiler/linkage.h"
#include "src/compiler/wasm-compiler.h"
#include "src/utils/ostreams.h"
#include "src/wasm/baseline/liftoff-assembler-inl.h"
#include "src/wasm/baseline/liftoff-register.h"
#include "src/wasm/baseline/parallel-move-inl.h"
#include "src/wasm/object-access.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-opcodes.h"

namespace v8::internal::wasm {

using VarState = LiftoffAssembler::VarState;
using ValueKindSig = LiftoffAssembler::ValueKindSig;

constexpr ValueKind LiftoffAssembler::kIntPtrKind;
constexpr ValueKind LiftoffAssembler::kSmiKind;

namespace {

class RegisterReuseMap {
 public:
  void Add(LiftoffRegister src, LiftoffRegister dst) {
    if ([[maybe_unused]] auto previous = Lookup(src)) {
      DCHECK_EQ(previous, dst);
      return;
    }
    map_.emplace_back(src);
    map_.emplace_back(dst);
  }

  std::optional<LiftoffRegister> Lookup(LiftoffRegister src) {
    for (auto it = map_.begin(), end = map_.end(); it != end; it += 2) {
      if (it->is_gp_pair() == src.is_gp_pair() &&
          it->is_fp_pair() == src.is_fp_pair() && *it == src)
        return *(it + 1);
    }
    return {};
  }

 private:
  // {map_} holds pairs of <src, dst>.
  base::SmallVector<LiftoffRegister, 8> map_;
};

enum MergeKeepStackSlots : bool {
  kKeepStackSlots = true,
  kTurnStackSlotsIntoRegisters = false
};
enum MergeAllowConstants : bool {
  kConstantsAllowed = true,
  kConstantsNotAllowed = false
};
enum MergeAllowRegisters : bool {
  kRegistersAllowed = true,
  kRegistersNotAllowed = false
};
enum ReuseRegisters : bool {
  kReuseRegisters = true,
  kNoReuseRegisters = false
};
// {InitMergeRegion} is a helper used by {MergeIntoNewState} to initialize
// a part of the target stack ([target, target+count]) from [source,
// source+count]. The parameters specify how to initialize the part. The goal is
// to set up the region such that later merges (via {MergeStackWith} /
// {MergeFullStackWith} can successfully transfer their values to this new
// state.
void InitMergeRegion(LiftoffAssembler::CacheState* target_state,
                     const VarState* source, VarState* target, uint32_t count,
                     MergeKeepStackSlots keep_stack_slots,
                     MergeAllowConstants allow_constants,
                     MergeAllowRegisters allow_registers,
                     ReuseRegisters reuse_registers, LiftoffRegList used_regs,
                     int new_stack_offset, ParallelMove& parallel_move) {
  RegisterReuseMap register_reuse_map;
  for (const VarState* source_end = source + count; source < source_end;
       ++source, ++target) {
    if (source->is_stack() && keep_stack_slots) {
      *target = *source;
      // If {new_stack_offset} is set, we want to recompute stack offsets for
      // the region we are initializing such that they are contiguous. If
      // {new_stack_offset} is zero (which is an illegal stack offset), we just
      // keep the source offsets.
      if (new_stack_offset) {
        new_stack_offset =
            LiftoffAssembler::NextSpillOffset(source->kind(), new_stack_offset);
        if (new_stack_offset != source->offset()) {
          target->set_offset(new_stack_offset);
          parallel_move.TransferToStack(new_stack_offset, *source);
        }
      }
      continue;
    }
    if (source->is_const() && allow_constants) {
      *target = *source;
      DCHECK(!new_stack_offset);
      continue;
    }
    std::optional<LiftoffRegister> reg;
    bool needs_reg_transfer = true;
    if (allow_registers) {
      // First try: Keep the same register, if it's free.
      if (source->is_reg() && target_state->is_free(source->reg())) {
        reg = source->reg();
        needs_reg_transfer = false;
      }
      // Second try: Use the same register we used before (if we reuse
      // registers).
      if (!reg && reuse_registers) {
        reg = register_reuse_map.Lookup(source->reg());
      }
      // Third try: Use any free register.
      RegClass rc = reg_class_for(source->kind());
      if (!reg && target_state->has_unused_register(rc, used_regs)) {
        reg = target_state->unused_register(rc, used_regs);
      }
    }
    // See above: Recompute the stack offset if requested.
    int target_offset = source->offset();
    if (new_stack_offset) {
      new_stack_offset =
          LiftoffAssembler::NextSpillOffset(source->kind(), new_stack_offset);
      target_offset = new_stack_offset;
    }
    if (reg) {
      if (needs_reg_transfer) parallel_move.LoadIntoRegister(*reg, *source);
      if (reuse_registers) register_reuse_map.Add(source->reg(), *reg);
      target_state->inc_used(*reg);
      *target = VarState(source->kind(), *reg, target_offset);
    } else {
      // No free register; make this a stack slot.
      *target = VarState(source->kind(), target_offset);
      parallel_move.TransferToStack(target_offset, *source);
    }
  }
}

}  // namespace

LiftoffAssembler::CacheState LiftoffAssembler::MergeIntoNewState(
    uint32_t num_locals, uint32_t arity, uint32_t stack_depth) {
  CacheState target{zone()};

  // The source state looks like this:
  // |------locals------|---(stack prefix)---|--(discarded)--|----merge----|
  //  <-- num_locals --> <-- stack_depth  -->                 <-- arity -->
  //
  // We compute the following target state from it:
  // |------locals------|---(stack prefix)----|----merge----|
  //  <-- num_locals --> <-- stack_depth   --> <-- arity -->
  //
  // The target state will have dropped the "(discarded)" region, and the
  // "locals" and "merge" regions have been modified to avoid any constants and
  // avoid duplicate register uses. This ensures that later merges can
  // successfully transfer into the target state.
  // The "stack prefix" region will be identical for any source that merges into
  // that state.

  if (cache_state_.cached_instance_data != no_reg) {
    target.SetInstanceCacheRegister(cache_state_.cached_instance_data);
  }

  DCHECK_EQ(cache_state_.cached_mem_start == no_reg,
            cache_state_.cached_mem_index == CacheState::kNoCachedMemIndex);
  if (cache_state_.cached_mem_start != no_reg) {
    target.SetMemStartCacheRegister(cache_state_.cached_mem_start,
                                    cache_state_.cached_mem_index);
  }

  uint32_t target_height = num_locals + stack_depth + arity;

  target.stack_state.resize_no_init(target_height);

  const VarState* source_begin = cache_state_.stack_state.data();
  VarState* target_begin = target.stack_state.data();

  // Compute the starts of the different regions, for source and target (see
  // pictograms above).
  const VarState* locals_source = source_begin;
  const VarState* stack_prefix_source = source_begin + num_locals;
  const VarState* discarded_source = stack_prefix_source + stack_depth;
  const VarState* merge_source = cache_state_.stack_state.end() - arity;
  VarState* locals_target = target_begin;
  VarState* stack_prefix_target = target_begin + num_locals;
  VarState* merge_target = target_begin + num_locals + stack_depth;

  // Try to keep locals and the merge region in their registers. Registers used
  // multiple times need to be copied to another free register. Compute the list
  // of used registers.
  LiftoffRegList used_regs;
  for (auto& src : base::VectorOf(locals_source, num_locals)) {
    if (src.is_reg()) used_regs.set(src.reg());
  }
  // If there is more than one operand in the merge region, a stack-to-stack
  // move can interfere with a register reload, which would not be handled
  // correctly by the ParallelMove. To avoid this, spill all registers in
  // this region.
  MergeAllowRegisters allow_registers =
      arity <= 1 ? kRegistersAllowed : kRegistersNotAllowed;
  if (allow_registers) {
    for (auto& src : base::VectorOf(merge_source, arity)) {
      if (src.is_reg()) used_regs.set(src.reg());
    }
  }

  ParallelMove parallel_move{this};

  // The merge region is often empty, hence check for this before doing any
  // work (even though not needed for correctness).
  if (arity) {
    // Initialize the merge region. If this region moves, try to turn stack
    // slots into registers since we need to load the value anyways.
    MergeKeepStackSlots keep_merge_stack_slots =
        target_height == cache_state_.stack_height()
            ? kKeepStackSlots
            : kTurnStackSlotsIntoRegisters;
    // Shift spill offsets down to keep slots contiguous. We place the merge
    // region right after the "stack prefix", if it exists.
    int merge_region_stack_offset = discarded_source == source_begin
                                        ? StaticStackFrameSize()
                                        : discarded_source[-1].offset();
    InitMergeRegion(&target, merge_source, merge_target, arity,
                    keep_merge_stack_slots, kConstantsNotAllowed,
                    allow_registers, kNoReuseRegisters, used_regs,
                    merge_region_stack_offset, parallel_move);
  }

  // Initialize the locals region. Here, stack slots stay stack slots (because
  // they do not move). Try to keep register in registers, but avoid duplicates.
  if (num_locals) {
    InitMergeRegion(&target, locals_source, locals_target, num_locals,
                    kKeepStackSlots, kConstantsNotAllowed, kRegistersAllowed,
                    kNoReuseRegisters, used_regs, 0, parallel_move);
  }
  // Consistency check: All the {used_regs} are really in use now.
  DCHECK_EQ(used_regs, target.used_registers & used_regs);

  // Last, initialize the "stack prefix" region. Here, constants are allowed,
  // but registers which are already used for the merge region or locals must be
  // moved to other registers or spilled. If a register appears twice in the
  // source region, ensure to use the same register twice in the target region.
  if (stack_depth) {
    InitMergeRegion(&target, stack_prefix_source, stack_prefix_target,
                    stack_depth, kKeepStackSlots, kConstantsAllowed,
                    kRegistersAllowed, kReuseRegisters, used_regs, 0,
                    parallel_move);
  }

  return target;
}

void LiftoffAssembler::CacheState::Steal(CacheState& source) {
  // Just use the move assignment operator.
  *this = std::move(source);
}

void LiftoffAssembler::CacheState::Split(const CacheState& source) {
  // Call the private copy assignment operator.
  *this = source;
}

namespace {
int GetSafepointIndexForStackSlot(const VarState& slot) {
  // index = 0 is for the stack slot at 'fp + kFixedFrameSizeAboveFp -
  // kSystemPointerSize', the location of the current stack slot is 'fp -
  // slot.offset()'. The index we need is therefore '(fp +
  // kFixedFrameSizeAboveFp - kSystemPointerSize) - (fp - slot.offset())' =
  // 'slot.offset() + kFixedFrameSizeAboveFp - kSystemPointerSize'.
  // Concretely, the index of the first stack slot is '4'.
  return (slot.offset() + StandardFrameConstants::kFixedFrameSizeAboveFp -
          kSystemPointerSize) /
         kSystemPointerSize;
}
}  // namespace

void LiftoffAssembler::CacheState::GetTaggedSlotsForOOLCode(
    ZoneVector<int>* slots, LiftoffRegList* spills,
    SpillLocation spill_location) {
  for (const auto& slot : stack_state) {
    if (!is_reference(slot.kind())) continue;

    if (spill_location == SpillLocation::kTopOfStack && slot.is_reg()) {
      // Registers get spilled just before the call to the runtime. In {spills}
      // we store which of the spilled registers contain references, so that we
      // can add the spill slots to the safepoint.
      spills->set(slot.reg());
      continue;
    }
    DCHECK_IMPLIES(slot.is_reg(), spill_location == SpillLocation::kStackSlots);

    slots->push_back(GetSafepointIndexForStackSlot(slot));
  }
}

void LiftoffAssembler::CacheState::DefineSafepoint(
    SafepointTableBuilder::Safepoint& safepoint) {
  // Go in reversed order to set the higher bits first; this avoids cost for
  // growing the underlying bitvector.
  for (const auto& slot : base::Reversed(stack_state)) {
    if (is_reference(slot.kind())) {
      // TODO(v8:14422): References that are not on the stack now will get lost
      // at the moment. Once v8:14422 is resolved, this `continue` should be
      // revisited and potentially updated to a DCHECK.
      if (!slot.is_stack()) continue;
      safepoint.DefineTaggedStackSlot(GetSafepointIndexForStackSlot(slot));
    }
  }
}

void LiftoffAssembler::CacheState::DefineSafepointWithCalleeSavedRegisters(
    SafepointTableBuilder::Safepoint& safepoint) {
  for (const auto& slot : stack_state) {
    if (!is_reference(slot.kind())) continue;
    if (slot.is_stack()) {
      safepoint.DefineTaggedStackSlot(GetSafepointIndexForStackSlot(slot));
    } else {
      DCHECK(slot.is_reg());
      safepoint.DefineTaggedRegister(slot.reg().gp().code());
    }
  }
  if (cached_instance_data != no_reg) {
    safepoint.DefineTaggedRegister(cached_instance_data.code());
  }
}

int LiftoffAssembler::GetTotalFrameSlotCountForGC() const {
  // The GC does not care about the actual number of spill slots, just about
  // the number of references that could be there in the spilling area. Note
  // that the offset of the first spill slot is kSystemPointerSize and not
  // '0'. Therefore we don't have to add '+1' here.
  return (max_used_spill_offset_ +
          StandardFrameConstants::kFixedFrameSizeAboveFp +
          ool_spill_space_size_) /
         kSystemPointerSize;
}

int LiftoffAssembler::OolSpillCount() const {
  return ool_spill_space_size_ / kSystemPointerSize;
}

namespace {

AssemblerOptions DefaultLiftoffOptions() {
  return AssemblerOptions{
      .is_wasm = true,
  };
}

}  // namespace

LiftoffAssembler::LiftoffAssembler(Zone* zone,
                                   std::unique_ptr<AssemblerBuffer> buffer)
    : MacroAssembler(zone, DefaultLiftoffOptions(), CodeObjectRequired::kNo,
                     std::move(buffer)),
      cache_state_(zone) {
  set_abort_hard(true);  // Avoid calls to Abort.
}

LiftoffAssembler::~LiftoffAssembler() {
  if (num_locals_ > kInlineLocalKinds) {
    base::Free(more_local_kinds_);
  }
}

LiftoffRegister LiftoffAssembler::LoadToRegister_Slow(VarState slot,
                                                      LiftoffRegList pinned) {
  DCHECK(!slot.is_reg());
  LiftoffRegister reg = GetUnusedRegister(reg_class_for(slot.kind()), pinned);
  LoadToFixedRegister(slot, reg);
  return reg;
}

LiftoffRegister LiftoffAssembler::LoadI64HalfIntoRegister(
    VarState slot, RegPairHalf half, LiftoffRegList pinned) {
  if (slot.is_reg()) {
    return half == kLowWord ? slot.reg().low() : slot.reg().high();
  }
  LiftoffRegister dst = GetUnusedRegister(kGpReg, pinned);
  if (slot.is_stack()) {
    FillI64Half(dst.gp(), slot.offset(), half);
    return dst;
  }
  DCHECK(slot.is_const());
  int32_t half_word =
      static_cast<int32_t>(half == kLowWord ? slot.constant().to_i64()
                                            : slot.constant().to_i64() >> 32);
  LoadConstant(dst, WasmValue(half_word));
  return dst;
}

void LiftoffAssembler::DropExceptionValueAtOffset(int offset) {
  auto* dropped = cache_state_.stack_state.begin() + offset;
  if (dropped->is_reg()) {
    cache_state_.dec_used(dropped->reg());
  }
  // Compute the stack offset that the remaining slots are based on.
  int stack_offset =
      offset == 0 ? StaticStackFrameSize() : dropped[-1].offset();
  // Move remaining slots down.
  for (VarState *slot = dropped, *end = cache_state_.stack_state.end() - 1;
       slot != end; ++slot) {
    *slot = *(slot + 1);
    stack_offset = NextSpillOffset(slot->kind(), stack_offset);
    // Padding could cause some spill offsets to remain the same.
    if (slot->offset() != stack_offset) {
      if (slot->is_stack()) {
        MoveStackValue(stack_offset, slot->offset(), slot->kind());
      }
      slot->set_offset(stack_offset);
    }
  }
  cache_state_.stack_state.pop_back();
}

void LiftoffAssembler::SpillLoopArgs(int num) {
  for (VarState& slot :
       base::VectorOf(cache_state_.stack_state.end() - num, num)) {
    Spill(&slot);
  }
}

void LiftoffAssembler::PrepareForBranch(uint32_t arity, LiftoffRegList pinned) {
  VarState* stack_base = cache_state_.stack_state.data();
  for (auto slots :
       {base::VectorOf(stack_base + cache_state_.stack_state.size() - arity,
                       arity),
        base::VectorOf(stack_base, num_locals())}) {
    for (VarState& slot : slots) {
      if (slot.is_reg()) {
        // Registers used more than once can't be used for merges.
        if (cache_state_.get_use_count(slot.reg()) > 1) {
          RegClass rc = reg_class_for(slot.kind());
          if (cache_state_.has_unused_register(rc, pinned)) {
            LiftoffRegister dst_reg = cache_state_.unused_register(rc, pinned);
            Move(dst_reg, slot.reg(), slot.kind());
            cache_state_.inc_used(dst_reg);
            cache_state_.dec_used(slot.reg());
            slot.MakeRegister(dst_reg);
          } else {
            Spill(slot.offset(), slot.reg(), slot.kind());
            cache_state_.dec_used(slot.reg());
            slot.MakeStack();
          }
        }
        continue;
      }
      // Materialize constants.
      if (!slot.is_const()) continue;
      RegClass rc = reg_class_for(slot.kind());
      if (cache_state_.has_unused_register(rc, pinned)) {
        LiftoffRegister reg = cache_state_.unused_register(rc, pinned);
        LoadConstant(reg, slot.constant());
        cache_state_.inc_used(reg);
        slot.MakeRegister(reg);
      } else {
        Spill(slot.offset(), slot.constant());
        slot.MakeStack();
      }
    }
  }
}

#ifdef DEBUG
namespace {
bool SlotInterference(const VarState& a, const VarState& b) {
  return a.is_stack() && b.is_stack() &&
         b.offset() > a.offset() - value_kind_size(a.kind()) &&
         b.offset() - value_kind_size(b.kind()) < a.offset();
}

bool SlotInterference(const VarState& a, base::Vector<const VarState> v) {
  // Check the first 16 entries in {v}, then increase the step size to avoid
  // quadratic runtime on huge stacks. This logic checks 41 of the first 100
  // slots, 77 of the first 1000 and 115 of the first 10000.
  for (size_t idx = 0, end = v.size(); idx < end; idx += 1 + idx / 16) {
    if (SlotInterference(a, v[idx])) return true;
  }
  return false;
}
}  // namespace
#endif

void LiftoffAssembler::MergeFullStackWith(CacheState& target) {
  DCHECK_EQ(cache_state_.stack_height(), target.stack_height());
  // TODO(clemensb): Reuse the same ParallelMove object to save some
  // allocations.
  ParallelMove parallel_move{this};
  for (uint32_t i = 0, e = cache_state_.stack_height(); i < e; ++i) {
    parallel_move.Transfer(target.stack_state[i], cache_state_.stack_state[i]);
    DCHECK(!SlotInterference(target.stack_state[i],
                             base::VectorOf(cache_state_.stack_state) + i + 1));
  }

  // Full stack merging is only done for forward jumps, so we can just clear the
  // cache registers at the target in case of mismatch.
  if (cache_state_.cached_instance_data != target.cached_instance_data) {
    target.ClearCachedInstanceRegister();
  }
  if (cache_state_.cached_mem_index != target.cached_mem_index ||
      cache_state_.cached_mem_start != target.cached_mem_start) {
    target.ClearCachedMemStartRegister();
  }
}

void LiftoffAssembler::MergeStackWith(CacheState& target, uint32_t arity,
                                      JumpDirection jump_direction) {
  // Before: ----------------|----- (discarded) ----|--- arity ---|
  //                         ^target_stack_height   ^stack_base   ^stack_height
  // After:  ----|-- arity --|
  //             ^           ^target_stack_height
  //             ^target_stack_base
  uint32_t stack_height = cache_state_.stack_height();
  uint32_t target_stack_height = target.stack_height();
  DCHECK_LE(target_stack_height, stack_height);
  DCHECK_LE(arity, target_stack_height);
  uint32_t stack_base = stack_height - arity;
  uint32_t target_stack_base = target_stack_height - arity;
  ParallelMove parallel_move{this};
  for (uint32_t i = 0; i < target_stack_base; ++i) {
    parallel_move.Transfer(target.stack_state[i], cache_state_.stack_state[i]);
    DCHECK(!SlotInterference(
        target.stack_state[i],
        base::VectorOf(cache_state_.stack_state.data() + i + 1,
                       target_stack_base - i - 1)));
    DCHECK(!SlotInterference(
        target.stack_state[i],
        base::VectorOf(cache_state_.stack_state.data() + stack_base, arity)));
  }
  for (uint32_t i = 0; i < arity; ++i) {
    parallel_move.Transfer(target.stack_state[target_stack_base + i],
                           cache_state_.stack_state[stack_base + i]);
    DCHECK(!SlotInterference(
        target.stack_state[target_stack_base + i],
        base::VectorOf(cache_state_.stack_state.data() + stack_base + i + 1,
                       arity - i - 1)));
  }

  // Check whether the cached instance and/or memory start need to be moved to
  // another register. Register moves are executed as part of the
  // {ParallelMove}. Remember whether the register content has to be
  // reloaded after executing the stack parallel_move.
  bool reload_instance_data = false;
  // If the instance cache registers match, or the destination has no instance
  // cache register, nothing needs to be done.
  if (cache_state_.cached_instance_data != target.cached_instance_data &&
      target.cached_instance_data != no_reg) {
    // On forward jumps, just reset the cached register in the target state.
    if (jump_direction == kForwardJump) {
      target.ClearCachedInstanceRegister();
    } else if (cache_state_.cached_instance_data != no_reg) {
      // If the source has the instance cached but in the wrong register,
      // execute a register move as part of the stack transfer.
      parallel_move.MoveRegister(
          LiftoffRegister{target.cached_instance_data},
          LiftoffRegister{cache_state_.cached_instance_data}, kIntPtrKind);
    } else {
      // Otherwise (the source state has no cached instance), we reload later.
      reload_instance_data = true;
    }
  }

  bool reload_mem_start = false;
  // If the cached memory start registers match, or the destination has no cache
  // register, nothing needs to be done.
  DCHECK_EQ(target.cached_mem_start == no_reg,
            target.cached_mem_index == CacheState::kNoCachedMemIndex);
  if ((cache_state_.cached_mem_start != target.cached_mem_start ||
       cache_state_.cached_mem_index != target.cached_mem_index) &&
      target.cached_mem_start != no_reg) {
    // On forward jumps, just reset the cached register in the target state.
    if (jump_direction == kForwardJump) {
      target.ClearCachedMemStartRegister();
    } else if (cache_state_.cached_mem_index == target.cached_mem_index) {
      DCHECK_NE(no_reg, cache_state_.cached_mem_start);
      // If the source has the content but in the wrong register, execute a
      // register move as part of the stack transfer.
      parallel_move.MoveRegister(LiftoffRegister{target.cached_mem_start},
                                 LiftoffRegister{cache_state_.cached_mem_start},
                                 kIntPtrKind);
    } else {
      // Otherwise (the source state has no cached content), we reload later.
      reload_mem_start = true;
    }
  }

  // Now execute stack transfers and register moves/loads.
  parallel_move.Execute();

  if (reload_instance_data) {
    LoadInstanceDataFromFrame(target.cached_instance_data);
  }
  if (reload_mem_start) {
    // {target.cached_instance_data} already got restored above, so we can use
    // it if it exists.
    Register instance_data = target.cached_instance_data;
    if (instance_data == no_reg) {
      // We don't have the instance data available yet. Store it into the target
      // mem_start, so that we can load the mem0_start from there.
      instance_data = target.cached_mem_start;
      LoadInstanceDataFromFrame(instance_data);
    }
    if (target.cached_mem_index == 0) {
      LoadFromInstance(
          target.cached_mem_start, instance_data,
          ObjectAccess::ToTagged(WasmTrustedInstanceData::kMemory0StartOffset),
          sizeof(size_t));
    } else {
      LoadProtectedPointer(
          target.cached_mem_start, instance_data,
          ObjectAccess::ToTagged(
              WasmTrustedInstanceData::kProtectedMemoryBasesAndSizesOffset));
      int buffer_offset =
          wasm::ObjectAccess::ToTagged(OFFSET_OF_DATA_START(ByteArray)) +
          kSystemPointerSize * target.cached_mem_index * 2;
      LoadFullPointer(target.cached_mem_start, target.cached_mem_start,
                      buffer_offset);
    }
  }
}

void LiftoffAssembler::Spill(VarState* slot) {
  switch (slot->loc()) {
    case VarState::kStack:
      return;
    case VarState::kRegister:
      Spill(slot->offset(), slot->reg(), slot->kind());
      cache_state_.dec_used(slot->reg());
      break;
    case VarState::kIntConst:
      Spill(slot->offset(), slot->constant());
      break;
  }
  slot->MakeStack();
}

void LiftoffAssembler::SpillLocals() {
  for (VarState& local_slot :
       base::VectorOf(cache_state_.stack_state.data(), num_locals_)) {
    Spill(&local_slot);
  }
}

void LiftoffAssembler::SpillAllRegisters() {
  for (VarState& slot : cache_state_.stack_state) {
    if (!slot.is_reg()) continue;
    Spill(slot.offset(), slot.reg(), slot.kind());
    slot.MakeStack();
  }
  cache_state_.ClearAllCacheRegisters();
  cache_state_.reset_used_registers();
}

void LiftoffAssembler::ClearRegister(
    Register reg, std::initializer_list<Register*> possible_uses,
    LiftoffRegList pinned) {
  if (reg == cache_state()->cached_instance_data) {
    cache_state()->ClearCachedInstanceRegister();
    // We can return immediately. The instance is only used to load information
    // at the beginning of an instruction when values don't have to be in
    // specific registers yet. Therefore the instance should never be one of the
    // {possible_uses}.
#ifdef DEBUG
    for (Register* use : possible_uses) DCHECK_NE(reg, *use);
#endif
    return;
  } else if (reg == cache_state()->cached_mem_start) {
    cache_state()->ClearCachedMemStartRegister();
    // The memory start may be among the {possible_uses}, e.g. for an atomic
    // compare exchange. Therefore it is necessary to iterate over the
    // {possible_uses} below, and we cannot return early.
  } else if (cache_state()->is_used(LiftoffRegister(reg))) {
    SpillRegister(LiftoffRegister(reg));
  }
  Register replacement = no_reg;
  for (Register* use : possible_uses) {
    if (reg != *use) continue;
    if (replacement == no_reg) {
      replacement = GetUnusedRegister(kGpReg, pinned).gp();
      Move(replacement, reg, kIntPtrKind);
    }
    // We cannot leave this loop early. There may be multiple uses of {reg}.
    *use = replacement;
  }
}

namespace {
void PrepareStackTransfers(const ValueKindSig* sig,
                           compiler::CallDescriptor* call_descriptor,
                           const VarState* slots,
                           LiftoffStackSlots* stack_slots,
                           ParallelMove* parallel_move,
                           LiftoffRegList* param_regs) {
  // Process parameters backwards, to reduce the amount of Slot sorting for
  // the most common case - a normal Wasm Call. Slots will be mostly unsorted
  // in the Builtin call case.
  uint32_t call_desc_input_idx =
      static_cast<uint32_t>(call_descriptor->InputCount());
  uint32_t num_params = static_cast<uint32_t>(sig->parameter_count());
  for (uint32_t i = num_params; i > 0; --i) {
    const uint32_t param = i - 1;
    ValueKind kind = sig->GetParam(param);
    const bool is_gp_pair = kNeedI64RegPair && kind == kI64;
    const int num_lowered_params = is_gp_pair ? 2 : 1;
    const VarState& slot = slots[param];
    DCHECK(CompatibleStackSlotTypes(slot.kind(), kind));
    // Process both halfs of a register pair separately, because they are passed
    // as separate parameters. One or both of them could end up on the stack.
    for (int lowered_idx = 0; lowered_idx < num_lowered_params; ++lowered_idx) {
      const RegPairHalf half =
          is_gp_pair && lowered_idx == 0 ? kHighWord : kLowWord;
      --call_desc_input_idx;
      LinkageLocation loc =
          call_descriptor->GetInputLocation(call_desc_input_idx);
      if (loc.IsRegister()) {
        DCHECK(!loc.IsAnyRegister());
        RegClass rc = is_gp_pair ? kGpReg : reg_class_for(kind);
        int reg_code = loc.AsRegister();
        LiftoffRegister reg =
            LiftoffRegister::from_external_code(rc, kind, reg_code);
        param_regs->set(reg);
        if (is_gp_pair) {
          parallel_move->LoadI64HalfIntoRegister(reg, slot, half);
        } else {
          parallel_move->LoadIntoRegister(reg, slot);
        }
      } else {
        DCHECK(loc.IsCallerFrameSlot());
        int param_offset = -loc.GetLocation() - 1;
        stack_slots->Add(slot, slot.offset(), half, param_offset);
      }
    }
  }
}

}  // namespace

void LiftoffAssembler::PrepareBuiltinCall(
    const ValueKindSig* sig, compiler::CallDescriptor* call_descriptor,
    std::initializer_list<VarState> params) {
  LiftoffStackSlots stack_slots{this};
  ParallelMove parallel_move{this};
  LiftoffRegList param_regs;
  PrepareStackTransfers(sig, call_descriptor, params.begin(), &stack_slots,
                        &parallel_move, &param_regs);
  SpillAllRegisters();
  int param_slots = static_cast<int>(call_descriptor->ParameterSlotCount());
  if (param_slots > 0) {
    stack_slots.Construct(param_slots);
  }
  // Execute the stack transfers before filling the instance register.
  parallel_move.Execute();

  // Reset register use counters.
  cache_state_.reset_used_registers();
}

void LiftoffAssembler::PrepareCall(const ValueKindSig* sig,
                                   compiler::CallDescriptor* call_descriptor,
                                   Register* target,
                                   Register target_instance_data) {
  uint32_t num_params = static_cast<uint32_t>(sig->parameter_count());

  LiftoffStackSlots stack_slots{this};
  ParallelMove parallel_move{this};
  LiftoffRegList param_regs;

  // Move the target instance (if supplied) into the correct instance register.
  Register instance_reg = wasm::kGpParamRegisters[0];
  // Check that the call descriptor agrees. Input 0 is the call target, 1 is the
  // instance.
  DCHECK_EQ(
      instance_reg,
      Register::from_code(call_descriptor->GetInputLocation(1).AsRegister()));
  param_regs.set(instance_reg);
  if (target_instance_data == no_reg) {
    target_instance_data = cache_state_.cached_instance_data;
  }
  if (target_instance_data != no_reg && target_instance_data != instance_reg) {
    parallel_move.MoveRegister(LiftoffRegister(instance_reg),
                               LiftoffRegister(target_instance_data),
                               kIntPtrKind);
  }

  int param_slots = static_cast<int>(call_descriptor->ParameterSlotCount());
  if (num_params) {
    uint32_t param_base = cache_state_.stack_height() - num_params;
    PrepareStackTransfers(sig, call_descriptor,
                          &cache_state_.stack_state[param_base], &stack_slots,
                          &parallel_move, &param_regs);
  }

  // If the target register overlaps with a parameter register, then move the
  // target to another free register, or spill to the stack.
  if (target && param_regs.has(LiftoffRegister(*target))) {
    // Try to find another free register.
    LiftoffRegList free_regs = kGpCacheRegList.MaskOut(param_regs);
    if (!free_regs.is_empty()) {
      LiftoffRegister new_target = free_regs.GetFirstRegSet();
      parallel_move.MoveRegister(new_target, LiftoffRegister(*target),
                                 kIntPtrKind);
      *target = new_target.gp();
    } else {
      stack_slots.Add(VarState(kIntPtrKind, LiftoffRegister(*target), 0),
                      param_slots);
      param_slots++;
      *target = no_reg;
    }
  }

  // After figuring out all register and stack moves, drop the parameter slots
  // from the stack.
  DropValues(num_params);

  // Spill all remaining cache slots.
  cache_state_.ClearAllCacheRegisters();
  // Iterate backwards, spilling r
```