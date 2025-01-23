Response: The user is asking for a summary of the functionality of the C++ source code file `v8/src/compiler/backend/register-allocator.cc`. This is the third part of a four-part series, suggesting a more detailed breakdown is expected. The code snippet provided focuses on specific aspects of register allocation within the V8 JavaScript engine.

Here's a breakdown of the thought process to summarize the functionality based on the code:

1. **Identify the Core Task:** The code is part of a register allocator. Register allocation is about assigning physical registers to virtual registers (live ranges) to optimize code execution.

2. **Analyze Key Data Structures:** The code uses several custom data structures:
    * `Vote`:  Used for deciding which registers to keep live across control flow merges. It tracks the count and which registers were used in predecessors.
    * `TopLevelLiveRangeComparator`:  Used for sorting `TopLevelLiveRange` objects, likely by their virtual register number.
    * `RangeVoteMap`: A map to store votes for live ranges. The `SmallZoneMap` suggests optimization for small maps.
    * `RangeRegisterSmallMap`:  A map associating live ranges with their assigned registers.

3. **Examine Key Functions and Methods:**
    * `ComputeStateFromManyPredecessors`: This function seems crucial for handling control flow merges. It determines which registers should remain live based on the registers used in the preceding blocks. The `Vote` structure is central here.
    * `ConsiderBlockForControlFlow`:  Determines if a predecessor block should be considered when making register allocation decisions at a merge point. Back edges and transitions across deferred/non-deferred code are considered.
    * `UpdateDeferredFixedRanges`:  Manages the activation and deactivation of fixed registers in deferred (e.g., exception handling) code. This is important for correctness when dealing with registers that have special meanings.
    * `BlockIsDeferredOrImmediatePredecessorIsNotDeferred`, `HasNonDeferredPredecessor`: Helper functions related to identifying deferred blocks.
    * `AllocateRegisters`: The main function for performing register allocation. It iterates through live ranges, manages active and inactive sets, and calls `ProcessCurrentRange`.
    * `SetLiveRangeAssignedRegister`, `AddToActive`, `AddToInactive`, `AddToUnhandled`: Functions for managing the state of live ranges during allocation.
    * `ForwardStateTo`:  Updates the active and inactive sets of live ranges based on the current position in the code.
    * `FindFreeRegistersForRange`: Determines which registers are available for a given live range. It considers both active and inactive ranges and potential aliasing.
    * `ProcessCurrentRange`:  The core logic for allocating a register to a specific live range. It attempts to use hints, then free registers, and finally might need to spill other ranges.
    * `TryAllocatePreferredReg`, `TryAllocateFreeReg`, `AllocateBlockedReg`: Strategies for allocating registers.
    * `PickRegisterThatIsAvailableLongest`:  A heuristic for choosing the best free register.
    * `SplitAndSpillIntersecting`:  Handles conflicts by spilling intersecting live ranges.
    * `TryReuseSpillForPhi`: An optimization to reuse spill slots for Phi nodes.
    * `SpillAfter`, `SpillBetween`, `SpillBetweenUntil`: Functions for spilling live ranges.
    * `OperandAssigner::DecideSpillingMode`, `OperandAssigner::AssignSpillSlots`, `OperandAssigner::CommitAssignment`:  Functions related to assigning spill slots and committing the register allocation decisions.
    * `ReferenceMapPopulator::PopulateReferenceMaps`:  Handles the generation of reference maps for garbage collection.

4. **Identify Key Concepts:**
    * **Live Ranges:** The intervals during which a virtual register holds a value.
    * **Active/Inactive Live Ranges:**  The allocator maintains sets of active (currently using a register) and inactive (holding a register but not currently in use) live ranges.
    * **Unhandled Live Ranges:** Live ranges that haven't been assigned a register yet.
    * **Spilling:**  Moving the value of a register to memory to free up the register.
    * **Deferred Code:** Code that is not executed in the normal control flow (e.g., exception handlers).
    * **Control Flow Merges:** Points in the code where multiple execution paths converge.
    * **Register Hints:** Preferences for which register should be used for a live range.
    * **Register Aliasing:**  When different register types can overlap (e.g., parts of a floating-point register might overlap with integer registers).
    * **Phi Nodes:** Instructions that merge values from different control flow paths.
    * **Reference Maps:** Data structures used by the garbage collector to track pointers in registers and on the stack.
    * **Spill Slots:** Memory locations used for storing spilled register values.
    * **Live Range Bundles:** Groups of live ranges that should ideally be assigned to the same register or spill slot.

5. **Structure the Summary:**  Organize the identified functionalities into logical groups. Since this is part 3 of 4, focus on the aspects covered in this particular code snippet.

6. **Relate to JavaScript (If Applicable):**  The register allocator directly impacts the performance of JavaScript code. Good register allocation minimizes the need to move data between registers and memory, leading to faster execution. Provide a simple JavaScript example where register allocation would be crucial (e.g., a loop with many variable accesses).

7. **Refine and Clarify:** Ensure the language is clear and concise, and explain any technical terms that might not be immediately obvious.

By following these steps, a comprehensive summary of the code's functionality can be generated. The focus remains on register allocation strategies, handling control flow, managing deferred code, and integrating with other V8 components like garbage collection.
这个C++源代码文件是V8 JavaScript引擎的**线性扫描寄存器分配器**的一部分，专注于在代码编译的后端阶段，为**多个控制流路径汇聚点**的虚拟寄存器（live ranges）选择合适的物理寄存器。

具体来说，这部分代码主要负责处理以下功能：

**1. 基于控制流的寄存器分配决策：**

* **`ComputeStateFromManyPredecessors(InstructionBlock* current_block, RangeRegisterSmallMap& to_be_live)`:**  这是核心函数，用于处理当多个代码块（例如，`if-else`语句或`switch`语句的不同分支）汇聚到一个新的代码块时，如何决定哪些虚拟寄存器应该继续分配到物理寄存器中。
* 它通过**投票机制**来实现：
    * 遍历当前代码块的所有**有效前驱块**（考虑了循环回边和跨越 deferred/non-deferred 代码块的边界）。
    * 对于每个前驱块，检查其在块结尾处哪些虚拟寄存器被分配了物理寄存器。
    * 使用 `Vote` 结构体来记录每个虚拟寄存器在前驱块中被分配到的次数以及分配到的具体物理寄存器。
    * 选择在前驱块中被分配次数超过半数（majority）的虚拟寄存器，并尝试为其分配在前驱块中最常分配的物理寄存器。
    * 如果存在物理寄存器冲突，则选择其他可用的物理寄存器。
* **`ConsiderBlockForControlFlow(InstructionBlock* current_block, RpoNumber predecessor)`:**  判断一个前驱块是否应该被纳入控制流影响的考虑范围。它会忽略循环回边和从 deferred 代码块到 non-deferred 代码块的跳转。

**2. 处理Deferred代码块中的寄存器：**

* **`UpdateDeferredFixedRanges(SpillMode spill_mode, InstructionBlock* block)`:**  处理 deferred 代码块（例如，异常处理代码块）中固定的物理寄存器。
    * 当进入 deferred 代码块时 (`spill_mode == SpillMode::kSpillDeferred`)，它将这些固定的物理寄存器添加到 `inactive_live_ranges` 中，意味着这些寄存器在该 deferred 代码块中被占用。
    * 当离开 deferred 代码块时，它将这些固定的物理寄存器从 `inactive_live_ranges` 中移除。
    * 在添加 inactive 寄存器时，会检查是否与其他 active 或 inactive 的 live range 冲突，如果冲突，会拆分这些 live range 并将其添加到未处理的队列中，以便重新分配。
* **`BlockIsDeferredOrImmediatePredecessorIsNotDeferred(const InstructionBlock* block)` 和 `HasNonDeferredPredecessor(InstructionBlock* block)`:**  辅助函数，用于判断代码块是否是 deferred 的，或者是否有 non-deferred 的前驱块。

**3. 主要的寄存器分配循环：**

* **`AllocateRegisters()`:**  这是主要的寄存器分配函数。
    * 初始化未处理、活跃和不活跃的 live range 集合。
    * 将由内存操作数定义的 live range 进行拆分和溢出（spill）。
    * 将需要分配物理寄存器的 live range 添加到 `unhandled_live_ranges` 队列中。
    * 将 non-deferred 的固定 live range 添加到 `inactive_live_ranges` 中。
    * 进入一个循环，直到所有 live range 都被处理完或遍历完所有代码块边界。
    * **处理块边界：** 当跨越代码块边界时，会保存当前的溢出状态，并根据控制流信息（通过 `ComputeStateFromManyPredecessors` 或简单地从前驱块继承状态）更新活跃和不活跃的 live range 集合。
    * **处理单个 live range：** 从 `unhandled_live_ranges` 中取出一个 live range，并调用 `ProcessCurrentRange` 函数为其分配物理寄存器。

**4. Live Range 状态管理：**

* **`SetLiveRangeAssignedRegister(LiveRange* range, int reg)`:** 设置 live range 分配到的物理寄存器。
* **`AddToActive(LiveRange* range)`:** 将 live range 添加到活跃集合中。
* **`AddToInactive(LiveRange* range)`:** 将 live range 添加到不活跃集合中。
* **`AddToUnhandled(LiveRange* range)`:** 将 live range 添加到未处理集合中。
* **`ActiveToHandled`，`ActiveToInactive`，`InactiveToHandled`，`InactiveToActive`:**  在不同状态之间移动 live range 的辅助函数。
* **`ForwardStateTo(LifetimePosition position)`:**  根据当前的执行位置，更新活跃和不活跃的 live range 集合。

**5. 寻找空闲寄存器：**

* **`FindFreeRegistersForRange(LiveRange* range, base::Vector<LifetimePosition> positions)`:**  找出哪些物理寄存器在给定 live range 的生命周期内是空闲的。它会考虑活跃和不活跃的 live range，以及寄存器别名的情况。

**6. 分配策略：**

* **`ProcessCurrentRange(LiveRange* current, SpillMode spill_mode)`:**  为当前的 live range 分配物理寄存器。
    * 首先尝试分配**首选寄存器**（hint）。
    * 如果首选寄存器不可用，则尝试分配**空闲寄存器**。
    * 如果没有空闲寄存器，则需要**溢出（spill）**其他的 live range 来释放寄存器。
* **`TryAllocatePreferredReg`，`TryAllocateFreeReg`，`AllocateBlockedReg`:**  具体的分配策略。
* **`PickRegisterThatIsAvailableLongest`:**  选择一个空闲时间最长的寄存器。
* **`SplitAndSpillIntersecting`:**  当分配物理寄存器发生冲突时，拆分并溢出与其他 live range 相交的部分。
* **`TryReuseSpillForPhi`:**  尝试为 Phi 节点复用之前溢出的内存位置。
* **`SpillAfter`，`SpillBetween`，`SpillBetweenUntil`:**  执行溢出操作的函数。

**7. 操作数分配和提交:**

* **`OperandAssigner::DecideSpillingMode()`，`OperandAssigner::AssignSpillSlots()`，`OperandAssigner::CommitAssignment()`:**  负责决定溢出模式、分配溢出槽位，并将最终的寄存器分配结果提交到指令操作数中。

**8. 引用映射填充:**

* **`ReferenceMapPopulator::PopulateReferenceMaps()`:**  负责填充引用映射（Reference Maps），用于垃圾回收器跟踪栈和寄存器中的对象引用。

**与 JavaScript 的关系和示例:**

寄存器分配是 V8 优化 JavaScript 代码执行的关键步骤。它直接影响生成的机器码的性能。

**JavaScript 示例:**

```javascript
function foo(a, b, c) {
  let sum = a + b;
  let product = sum * c;
  let result = product - a;
  return result;
}
```

在这个简单的 JavaScript 函数中，变量 `a`、`b`、`c`、`sum`、`product` 和 `result` 都对应着虚拟寄存器。寄存器分配器的任务就是尽可能将这些虚拟寄存器分配到物理寄存器中，以避免频繁地在寄存器和内存之间移动数据。

* 当执行 `let sum = a + b;` 时，寄存器分配器会尝试将 `a` 和 `b` 的值分别加载到两个物理寄存器中，然后执行加法运算并将结果存储到另一个物理寄存器中（分配给 `sum`）。
* 同样，在 `let product = sum * c;` 时，会尝试将 `sum` 和 `c` 的值放入物理寄存器进行乘法运算。
* 在控制流复杂的情况下，例如 `if-else` 语句，`ComputeStateFromManyPredecessors` 这样的函数就会发挥作用，确保在不同分支汇聚时，仍然需要的变量能够继续保存在寄存器中，避免不必要的加载和存储。

**总结来说，这部分代码实现了线性扫描寄存器分配算法中的关键环节，特别是处理控制流合并点和 deferred 代码块的寄存器分配，旨在提高 V8 生成的机器码的执行效率。**

### 提示词
```
这是目录为v8/src/compiler/backend/register-allocator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
s[RegisterConfiguration::kMaxRegisters];
    explicit Vote(int reg) : count(1), used_registers{0} {
      used_registers[reg] = 1;
    }
  };
  struct TopLevelLiveRangeComparator {
    bool operator()(const TopLevelLiveRange* lhs,
                    const TopLevelLiveRange* rhs) const {
      return lhs->vreg() < rhs->vreg();
    }
  };
  // Typically this map is very small, e.g., on JetStream2 it has at most 3
  // elements ~80% of the time and at most 8 elements ~94% of the time.
  // Thus use a `SmallZoneMap` to avoid allocations and because linear search
  // in an array is faster than map lookup for such small sizes.
  // We don't want too many inline elements though since `Vote` is pretty large.
  using RangeVoteMap =
      SmallZoneMap<TopLevelLiveRange*, Vote, 16, TopLevelLiveRangeComparator>;
  static_assert(sizeof(RangeVoteMap) < 4096, "too large stack allocation");
  RangeVoteMap counts(data()->allocation_zone());

  int deferred_blocks = 0;
  for (RpoNumber pred : current_block->predecessors()) {
    if (!ConsiderBlockForControlFlow(current_block, pred)) {
      // Back edges of a loop count as deferred here too.
      deferred_blocks++;
      continue;
    }
    const auto& pred_state = data()->GetSpillState(pred);
    for (LiveRange* range : pred_state) {
      // We might have spilled the register backwards, so the range we
      // stored might have lost its register. Ignore those.
      if (!range->HasRegisterAssigned()) continue;
      TopLevelLiveRange* toplevel = range->TopLevel();
      auto [it, inserted] =
          counts.try_emplace(toplevel, range->assigned_register());
      if (!inserted) {
        it->second.count++;
        it->second.used_registers[range->assigned_register()]++;
      }
    }
  }

  // Choose the live ranges from the majority.
  const size_t majority =
      (current_block->PredecessorCount() + 2 - deferred_blocks) / 2;
  bool taken_registers[RegisterConfiguration::kMaxRegisters] = {false};
  DCHECK(to_be_live.empty());
  auto assign_to_live = [this, majority, &counts](
                            std::function<bool(TopLevelLiveRange*)> filter,
                            RangeRegisterSmallMap& to_be_live,
                            bool* taken_registers) {
    bool check_aliasing =
        kFPAliasing == AliasingKind::kCombine && check_fp_aliasing();
    for (const auto& val : counts) {
      if (!filter(val.first)) continue;
      if (val.second.count >= majority) {
        int register_max = 0;
        int reg = kUnassignedRegister;
        bool conflict = false;
        int num_regs = num_registers();
        int num_codes = num_allocatable_registers();
        const int* codes = allocatable_register_codes();
        MachineRepresentation rep = val.first->representation();
        if (check_aliasing && (rep == MachineRepresentation::kFloat32 ||
                               rep == MachineRepresentation::kSimd128 ||
                               rep == MachineRepresentation::kSimd256))
          GetFPRegisterSet(rep, &num_regs, &num_codes, &codes);
        for (int idx = 0; idx < num_regs; idx++) {
          int uses = val.second.used_registers[idx];
          if (uses == 0) continue;
          if (uses > register_max || (conflict && uses == register_max)) {
            reg = idx;
            register_max = uses;
            conflict = check_aliasing ? CheckConflict(rep, reg, to_be_live)
                                      : taken_registers[reg];
          }
        }
        if (conflict) {
          reg = kUnassignedRegister;
        } else if (!check_aliasing) {
          taken_registers[reg] = true;
        }
        TRACE("Reset %d as live due vote %zu in %s\n", val.first->vreg(),
              val.second.count, RegisterName(reg));
        auto [_, inserted] = to_be_live.emplace(val.first, reg);
        DCHECK(inserted);
        USE(inserted);
      }
    }
  };
  // First round, process fixed registers, as these have precedence.
  // There is only one fixed range per register, so we cannot have
  // conflicts.
  assign_to_live([](TopLevelLiveRange* r) { return r->IsFixed(); }, to_be_live,
                 taken_registers);
  // Second round, process the rest.
  assign_to_live([](TopLevelLiveRange* r) { return !r->IsFixed(); }, to_be_live,
                 taken_registers);
}

bool LinearScanAllocator::ConsiderBlockForControlFlow(
    InstructionBlock* current_block, RpoNumber predecessor) {
  // We ignore predecessors on back edges when looking for control flow effects,
  // as those lie in the future of allocation and we have no data yet. Also,
  // deferred bocks are ignored on deferred to non-deferred boundaries, as we do
  // not want them to influence allocation of non deferred code.
  return (predecessor < current_block->rpo_number()) &&
         (current_block->IsDeferred() ||
          !code()->InstructionBlockAt(predecessor)->IsDeferred());
}

void LinearScanAllocator::UpdateDeferredFixedRanges(SpillMode spill_mode,
                                                    InstructionBlock* block) {
  if (spill_mode == SpillMode::kSpillDeferred) {
    LifetimePosition max = LifetimePosition::InstructionFromInstructionIndex(
        LastDeferredInstructionIndex(block));
    // Adds range back to inactive, resolving resulting conflicts.
    auto add_to_inactive = [this, max](LiveRange* range) {
      AddToInactive(range);
      // Splits other if it conflicts with range. Other is placed in unhandled
      // for later reallocation.
      auto split_conflicting = [this, max](LiveRange* range, LiveRange* other,
                                           std::function<void(LiveRange*)>
                                               update_caches) {
        if (other->TopLevel()->IsFixed()) return;
        int reg = range->assigned_register();
        if (kFPAliasing != AliasingKind::kCombine || !check_fp_aliasing()) {
          if (other->assigned_register() != reg) {
            return;
          }
        } else {
          if (!data()->config()->AreAliases(range->representation(), reg,
                                            other->representation(),
                                            other->assigned_register())) {
            return;
          }
        }
        // The inactive range might conflict, so check whether we need to
        // split and spill. We can look for the first intersection, as there
        // cannot be any intersections in the past, as those would have been a
        // conflict then.
        LifetimePosition next_start = range->FirstIntersection(other);
        if (!next_start.IsValid() || (next_start > max)) {
          // There is no conflict or the conflict is outside of the current
          // stretch of deferred code. In either case we can ignore the
          // inactive range.
          return;
        }
        // They overlap. So we need to split active and reschedule it
        // for allocation.
        TRACE("Resolving conflict of %d with deferred fixed for register %s\n",
              other->TopLevel()->vreg(),
              RegisterName(other->assigned_register()));
        LiveRange* split_off =
            other->SplitAt(next_start, data()->allocation_zone());
        // Try to get the same register after the deferred block.
        split_off->set_controlflow_hint(other->assigned_register());
        DCHECK_NE(split_off, other);
        AddToUnhandled(split_off);
        update_caches(other);
      };
      // Now check for conflicts in active and inactive ranges. We might have
      // conflicts in inactive, as we do not do this check on every block
      // boundary but only on deferred/non-deferred changes but inactive
      // live ranges might become live on any block boundary.
      for (auto active : active_live_ranges()) {
        split_conflicting(range, active, [this](LiveRange* updated) {
          next_active_ranges_change_ =
              std::min(updated->End(), next_active_ranges_change_);
        });
      }
      for (int reg = 0; reg < num_registers(); ++reg) {
        if ((kFPAliasing != AliasingKind::kCombine || !check_fp_aliasing()) &&
            reg != range->assigned_register()) {
          continue;
        }
        SlowDCheckInactiveLiveRangesIsSorted(reg);
        for (auto inactive : inactive_live_ranges(reg)) {
          if (inactive->NextStart() > max) break;
          split_conflicting(range, inactive, [this](LiveRange* updated) {
            next_inactive_ranges_change_ =
                std::min(updated->End(), next_inactive_ranges_change_);
          });
        }
      }
    };
    if (mode() == RegisterKind::kGeneral) {
      for (TopLevelLiveRange* current : data()->fixed_live_ranges()) {
        if (current != nullptr) {
          if (current->IsDeferredFixed()) {
            add_to_inactive(current);
          }
        }
      }
    } else if (mode() == RegisterKind::kDouble) {
      for (TopLevelLiveRange* current : data()->fixed_double_live_ranges()) {
        if (current != nullptr) {
          if (current->IsDeferredFixed()) {
            add_to_inactive(current);
          }
        }
      }
      if (kFPAliasing == AliasingKind::kCombine && check_fp_aliasing()) {
        for (TopLevelLiveRange* current : data()->fixed_float_live_ranges()) {
          if (current != nullptr) {
            if (current->IsDeferredFixed()) {
              add_to_inactive(current);
            }
          }
        }
        for (TopLevelLiveRange* current : data()->fixed_simd128_live_ranges()) {
          if (current != nullptr) {
            if (current->IsDeferredFixed()) {
              add_to_inactive(current);
            }
          }
        }
      }
    } else {
      DCHECK_EQ(mode(), RegisterKind::kSimd128);
      for (TopLevelLiveRange* current : data()->fixed_simd128_live_ranges()) {
        if (current != nullptr) {
          if (current->IsDeferredFixed()) {
            add_to_inactive(current);
          }
        }
      }
    }
  } else {
    // Remove all ranges.
    for (int reg = 0; reg < num_registers(); ++reg) {
      for (auto it = inactive_live_ranges(reg).begin();
           it != inactive_live_ranges(reg).end();) {
        if ((*it)->TopLevel()->IsDeferredFixed()) {
          it = inactive_live_ranges(reg).erase(it);
        } else {
          ++it;
        }
      }
    }
  }
}

bool LinearScanAllocator::BlockIsDeferredOrImmediatePredecessorIsNotDeferred(
    const InstructionBlock* block) {
  if (block->IsDeferred()) return true;
  if (block->PredecessorCount() == 0) return true;
  bool pred_is_deferred = false;
  for (auto pred : block->predecessors()) {
    if (pred.IsNext(block->rpo_number())) {
      pred_is_deferred = code()->InstructionBlockAt(pred)->IsDeferred();
      break;
    }
  }
  return !pred_is_deferred;
}

bool LinearScanAllocator::HasNonDeferredPredecessor(InstructionBlock* block) {
  for (auto pred : block->predecessors()) {
    InstructionBlock* pred_block = code()->InstructionBlockAt(pred);
    if (!pred_block->IsDeferred()) return true;
  }
  return false;
}

void LinearScanAllocator::AllocateRegisters() {
  DCHECK(unhandled_live_ranges().empty());
  DCHECK(active_live_ranges().empty());
  for (int reg = 0; reg < num_registers(); ++reg) {
    DCHECK(inactive_live_ranges(reg).empty());
  }

  SplitAndSpillRangesDefinedByMemoryOperand();
  data()->ResetSpillState();

  if (v8_flags.trace_turbo_alloc) {
    PrintRangeOverview();
  }

  const size_t live_ranges_size = data()->live_ranges().size();
  for (TopLevelLiveRange* range : data()->live_ranges()) {
    CHECK_EQ(live_ranges_size,
             data()->live_ranges().size());  // TODO(neis): crbug.com/831822
    if (!CanProcessRange(range)) continue;
    for (LiveRange* to_add = range; to_add != nullptr;
         to_add = to_add->next()) {
      if (!to_add->spilled()) {
        AddToUnhandled(to_add);
      }
    }
  }

  if (mode() == RegisterKind::kGeneral) {
    for (TopLevelLiveRange* current : data()->fixed_live_ranges()) {
      if (current != nullptr) {
        if (current->IsDeferredFixed()) continue;
        AddToInactive(current);
      }
    }
  } else if (mode() == RegisterKind::kDouble) {
    for (TopLevelLiveRange* current : data()->fixed_double_live_ranges()) {
      if (current != nullptr) {
        if (current->IsDeferredFixed()) continue;
        AddToInactive(current);
      }
    }
    if (kFPAliasing == AliasingKind::kCombine && check_fp_aliasing()) {
      for (TopLevelLiveRange* current : data()->fixed_float_live_ranges()) {
        if (current != nullptr) {
          if (current->IsDeferredFixed()) continue;
          AddToInactive(current);
        }
      }
      for (TopLevelLiveRange* current : data()->fixed_simd128_live_ranges()) {
        if (current != nullptr) {
          if (current->IsDeferredFixed()) continue;
          AddToInactive(current);
        }
      }
    }
  } else {
    DCHECK(mode() == RegisterKind::kSimd128);
    for (TopLevelLiveRange* current : data()->fixed_simd128_live_ranges()) {
      if (current != nullptr) {
        if (current->IsDeferredFixed()) continue;
        AddToInactive(current);
      }
    }
  }

  RpoNumber last_block = RpoNumber::FromInt(0);
  RpoNumber max_blocks =
      RpoNumber::FromInt(code()->InstructionBlockCount() - 1);
  LifetimePosition next_block_boundary =
      LifetimePosition::InstructionFromInstructionIndex(
          data()
              ->code()
              ->InstructionBlockAt(last_block)
              ->last_instruction_index())
          .NextFullStart();
  SpillMode spill_mode = SpillMode::kSpillAtDefinition;

  // Process all ranges. We also need to ensure that we have seen all block
  // boundaries. Linear scan might have assigned and spilled ranges before
  // reaching the last block and hence we would ignore control flow effects for
  // those. Not only does this produce a potentially bad assignment, it also
  // breaks with the invariant that we undo spills that happen in deferred code
  // when crossing a deferred/non-deferred boundary.
  while (!unhandled_live_ranges().empty() || last_block < max_blocks) {
    data()->tick_counter()->TickAndMaybeEnterSafepoint();
    LiveRange* current = unhandled_live_ranges().empty()
                             ? nullptr
                             : *unhandled_live_ranges().begin();
    LifetimePosition position =
        current ? current->Start() : next_block_boundary;
#ifdef DEBUG
    allocation_finger_ = position;
#endif
    // Check whether we just moved across a block boundary. This will trigger
    // for the first range that is past the current boundary.
    if (position >= next_block_boundary) {
      TRACE("Processing boundary at %d leaving %d\n",
            next_block_boundary.value(), last_block.ToInt());

      // Forward state to before block boundary
      LifetimePosition end_of_block = next_block_boundary.PrevStart().End();
      ForwardStateTo(end_of_block);

      // Remember this state.
      InstructionBlock* current_block = data()->code()->GetInstructionBlock(
          next_block_boundary.ToInstructionIndex());

      // Store current spill state (as the state at end of block). For
      // simplicity, we store the active ranges, e.g., the live ranges that
      // are not spilled.
      data()->RememberSpillState(last_block, active_live_ranges());

      // Only reset the state if this was not a direct fallthrough. Otherwise
      // control flow resolution will get confused (it does not expect changes
      // across fallthrough edges.).
      bool fallthrough =
          (current_block->PredecessorCount() == 1) &&
          current_block->predecessors()[0].IsNext(current_block->rpo_number());

      // When crossing a deferred/non-deferred boundary, we have to load or
      // remove the deferred fixed ranges from inactive.
      if ((spill_mode == SpillMode::kSpillDeferred) !=
          current_block->IsDeferred()) {
        // Update spill mode.
        spill_mode = current_block->IsDeferred()
                         ? SpillMode::kSpillDeferred
                         : SpillMode::kSpillAtDefinition;

        ForwardStateTo(next_block_boundary);

#ifdef DEBUG
        // Allow allocation at current position.
        allocation_finger_ = next_block_boundary;
#endif
        UpdateDeferredFixedRanges(spill_mode, current_block);
      }

      // Allocation relies on the fact that each non-deferred block has at
      // least one non-deferred predecessor. Check this invariant here.
      DCHECK_IMPLIES(!current_block->IsDeferred(),
                     HasNonDeferredPredecessor(current_block));

      if (!fallthrough) {
#ifdef DEBUG
        // Allow allocation at current position.
        allocation_finger_ = next_block_boundary;
#endif

        // We are currently at next_block_boundary - 1. Move the state to the
        // actual block boundary position. In particular, we have to
        // reactivate inactive ranges so that they get rescheduled for
        // allocation if they were not live at the predecessors.
        ForwardStateTo(next_block_boundary);

        RangeRegisterSmallMap to_be_live(allocation_zone());

        // If we end up deciding to use the state of the immediate
        // predecessor, it is better not to perform a change. It would lead to
        // the same outcome anyway.
        // This may never happen on boundaries between deferred and
        // non-deferred code, as we rely on explicit respill to ensure we
        // spill at definition.
        bool no_change_required = false;

        auto pick_state_from = [this, current_block](
                                   RpoNumber pred,
                                   RangeRegisterSmallMap& to_be_live) -> bool {
          TRACE("Using information from B%d\n", pred.ToInt());
          // If this is a fall-through that is not across a deferred
          // boundary, there is nothing to do.
          bool is_noop = pred.IsNext(current_block->rpo_number());
          if (!is_noop) {
            auto& spill_state = data()->GetSpillState(pred);
            TRACE("Not a fallthrough. Adding %zu elements...\n",
                  spill_state.size());
            LifetimePosition pred_end =
                LifetimePosition::GapFromInstructionIndex(
                    this->code()->InstructionBlockAt(pred)->code_end());
            DCHECK(to_be_live.empty());
            for (const auto range : spill_state) {
              // Filter out ranges that were split or had their register
              // stolen by backwards working spill heuristics. These have
              // been spilled after the fact, so ignore them.
              if (range->End() < pred_end || !range->HasRegisterAssigned())
                continue;
              auto [_, inserted] = to_be_live.emplace(
                  range->TopLevel(), range->assigned_register());
              DCHECK(inserted);
              USE(inserted);
            }
          }
          return is_noop;
        };

        // Multiple cases here:
        // 1) We have a single predecessor => this is a control flow split, so
        //     just restore the predecessor state.
        // 2) We have two predecessors => this is a conditional, so break ties
        //     based on what to do based on forward uses, trying to benefit
        //     the same branch if in doubt (make one path fast).
        // 3) We have many predecessors => this is a switch. Compute union
        //     based on majority, break ties by looking forward.
        if (current_block->PredecessorCount() == 1) {
          TRACE("Single predecessor for B%d\n",
                current_block->rpo_number().ToInt());
          no_change_required =
              pick_state_from(current_block->predecessors()[0], to_be_live);
        } else if (current_block->PredecessorCount() == 2) {
          TRACE("Two predecessors for B%d\n",
                current_block->rpo_number().ToInt());
          // If one of the branches does not contribute any information,
          // e.g. because it is deferred or a back edge, we can short cut
          // here right away.
          RpoNumber chosen_predecessor = RpoNumber::Invalid();
          if (!ConsiderBlockForControlFlow(current_block,
                                           current_block->predecessors()[0])) {
            chosen_predecessor = current_block->predecessors()[1];
          } else if (!ConsiderBlockForControlFlow(
                         current_block, current_block->predecessors()[1])) {
            chosen_predecessor = current_block->predecessors()[0];
          } else {
            chosen_predecessor = ChooseOneOfTwoPredecessorStates(
                current_block, next_block_boundary);
          }
          no_change_required = pick_state_from(chosen_predecessor, to_be_live);

        } else {
          // Merge at the end of, e.g., a switch.
          ComputeStateFromManyPredecessors(current_block, to_be_live);
        }

        if (!no_change_required) {
          SpillNotLiveRanges(to_be_live, next_block_boundary, spill_mode);
          ReloadLiveRanges(to_be_live, next_block_boundary);
        }
      }
      // Update block information
      last_block = current_block->rpo_number();
      next_block_boundary = LifetimePosition::InstructionFromInstructionIndex(
                                current_block->last_instruction_index())
                                .NextFullStart();

      // We might have created new unhandled live ranges, so cycle around the
      // loop to make sure we pick the top most range in unhandled for
      // processing.
      continue;
    }

    DCHECK_NOT_NULL(current);

    TRACE("Processing interval %d:%d start=%d\n", current->TopLevel()->vreg(),
          current->relative_id(), position.value());

    // Now we can erase current, as we are sure to process it.
    unhandled_live_ranges().erase(unhandled_live_ranges().begin());

    if (current->IsTopLevel() && TryReuseSpillForPhi(current->TopLevel()))
      continue;

    ForwardStateTo(position);

    DCHECK(!current->HasRegisterAssigned() && !current->spilled());

    ProcessCurrentRange(current, spill_mode);
  }

  if (v8_flags.trace_turbo_alloc) {
    PrintRangeOverview();
  }
}

void LinearScanAllocator::SetLiveRangeAssignedRegister(LiveRange* range,
                                                       int reg) {
  data()->MarkAllocated(range->representation(), reg);
  range->set_assigned_register(reg);
  range->SetUseHints(reg);
  range->UpdateBundleRegister(reg);
  if (range->IsTopLevel() && range->TopLevel()->is_phi()) {
    data()->GetPhiMapValueFor(range->TopLevel())->set_assigned_register(reg);
  }
}

void LinearScanAllocator::AddToActive(LiveRange* range) {
  TRACE("Add live range %d:%d in %s to active\n", range->TopLevel()->vreg(),
        range->relative_id(), RegisterName(range->assigned_register()));
  active_live_ranges().push_back(range);
  next_active_ranges_change_ =
      std::min(next_active_ranges_change_, range->NextEndAfter(range->Start()));
}

void LinearScanAllocator::AddToInactive(LiveRange* range) {
  TRACE("Add live range %d:%d to inactive\n", range->TopLevel()->vreg(),
        range->relative_id());
  next_inactive_ranges_change_ = std::min(
      next_inactive_ranges_change_, range->NextStartAfter(range->Start()));
  DCHECK(range->HasRegisterAssigned());
  // Keep `inactive_live_ranges` sorted.
  inactive_live_ranges(range->assigned_register())
      .insert(std::upper_bound(
                  inactive_live_ranges(range->assigned_register()).begin(),
                  inactive_live_ranges(range->assigned_register()).end(), range,
                  InactiveLiveRangeOrdering()),
              1, range);
}

void LinearScanAllocator::AddToUnhandled(LiveRange* range) {
  if (range == nullptr || range->IsEmpty()) return;
  DCHECK(!range->HasRegisterAssigned() && !range->spilled());
  DCHECK(allocation_finger_ <= range->Start());

  TRACE("Add live range %d:%d to unhandled\n", range->TopLevel()->vreg(),
        range->relative_id());
  unhandled_live_ranges().insert(range);
}

ZoneVector<LiveRange*>::iterator LinearScanAllocator::ActiveToHandled(
    const ZoneVector<LiveRange*>::iterator it) {
  TRACE("Moving live range %d:%d from active to handled\n",
        (*it)->TopLevel()->vreg(), (*it)->relative_id());
  return active_live_ranges().erase(it);
}

ZoneVector<LiveRange*>::iterator LinearScanAllocator::ActiveToInactive(
    const ZoneVector<LiveRange*>::iterator it, LifetimePosition position) {
  LiveRange* range = *it;
  TRACE("Moving live range %d:%d from active to inactive\n",
        (range)->TopLevel()->vreg(), range->relative_id());
  LifetimePosition next_active = range->NextStartAfter(position);
  next_inactive_ranges_change_ =
      std::min(next_inactive_ranges_change_, next_active);
  DCHECK(range->HasRegisterAssigned());
  // Keep `inactive_live_ranges` sorted.
  inactive_live_ranges(range->assigned_register())
      .insert(std::upper_bound(
                  inactive_live_ranges(range->assigned_register()).begin(),
                  inactive_live_ranges(range->assigned_register()).end(), range,
                  InactiveLiveRangeOrdering()),
              1, range);
  return active_live_ranges().erase(it);
}

LinearScanAllocator::InactiveLiveRangeQueue::iterator
LinearScanAllocator::InactiveToHandled(InactiveLiveRangeQueue::iterator it) {
  LiveRange* range = *it;
  TRACE("Moving live range %d:%d from inactive to handled\n",
        range->TopLevel()->vreg(), range->relative_id());
  int reg = range->assigned_register();
  // This must keep the order of `inactive_live_ranges` intact since one of its
  // callers `SplitAndSpillIntersecting` relies on it being sorted.
  return inactive_live_ranges(reg).erase(it);
}

LinearScanAllocator::InactiveLiveRangeQueue::iterator
LinearScanAllocator::InactiveToActive(InactiveLiveRangeQueue::iterator it,
                                      LifetimePosition position) {
  LiveRange* range = *it;
  active_live_ranges().push_back(range);
  TRACE("Moving live range %d:%d from inactive to active\n",
        range->TopLevel()->vreg(), range->relative_id());
  next_active_ranges_change_ =
      std::min(next_active_ranges_change_, range->NextEndAfter(position));
  int reg = range->assigned_register();
  // Remove the element without copying O(n) subsequent elements.
  // The order of `inactive_live_ranges` is established afterwards by sorting in
  // `ForwardStateTo`, which is the only caller.
  std::swap(*it, inactive_live_ranges(reg).back());
  inactive_live_ranges(reg).pop_back();
  return it;
}

void LinearScanAllocator::ForwardStateTo(LifetimePosition position) {
  if (position >= next_active_ranges_change_) {
    next_active_ranges_change_ = LifetimePosition::MaxPosition();
    for (auto it = active_live_ranges().begin();
         it != active_live_ranges().end();) {
      LiveRange* cur_active = *it;
      if (cur_active->End() <= position) {
        it = ActiveToHandled(it);
      } else if (!cur_active->Covers(position)) {
        it = ActiveToInactive(it, position);
      } else {
        next_active_ranges_change_ = std::min(
            next_active_ranges_change_, cur_active->NextEndAfter(position));
        ++it;
      }
    }
  }

  if (position >= next_inactive_ranges_change_) {
    next_inactive_ranges_change_ = LifetimePosition::MaxPosition();
    for (int reg = 0; reg < num_registers(); ++reg) {
      for (auto it = inactive_live_ranges(reg).begin();
           it != inactive_live_ranges(reg).end();) {
        LiveRange* cur_inactive = *it;
        if (cur_inactive->End() <= position) {
          it = InactiveToHandled(it);
        } else if (cur_inactive->Covers(position)) {
          it = InactiveToActive(it, position);
        } else {
          next_inactive_ranges_change_ = std::min(
              next_inactive_ranges_change_,
              // This modifies `cur_inactive.next_start_` and thus
              // invalidates the ordering of `inactive_live_ranges(reg)`.
              cur_inactive->NextStartAfter(position));
          ++it;
        }
      }
      std::sort(inactive_live_ranges(reg).begin(),
                inactive_live_ranges(reg).end(), InactiveLiveRangeOrdering());
    }
  }

  for (int reg = 0; reg < num_registers(); ++reg) {
    SlowDCheckInactiveLiveRangesIsSorted(reg);
  }
}

int LinearScanAllocator::LastDeferredInstructionIndex(InstructionBlock* start) {
  DCHECK(start->IsDeferred());
  RpoNumber last_block =
      RpoNumber::FromInt(code()->InstructionBlockCount() - 1);
  while ((start->rpo_number() < last_block)) {
    InstructionBlock* next =
        code()->InstructionBlockAt(start->rpo_number().Next());
    if (!next->IsDeferred()) break;
    start = next;
  }
  return start->last_instruction_index();
}

void LinearScanAllocator::GetFPRegisterSet(MachineRepresentation rep,
                                           int* num_regs, int* num_codes,
                                           const int** codes) const {
  DCHECK_EQ(kFPAliasing, AliasingKind::kCombine);
  if (rep == MachineRepresentation::kFloat32) {
    *num_regs = data()->config()->num_float_registers();
    *num_codes = data()->config()->num_allocatable_float_registers();
    *codes = data()->config()->allocatable_float_codes();
  } else if (rep == MachineRepresentation::kSimd128) {
    *num_regs = data()->config()->num_simd128_registers();
    *num_codes = data()->config()->num_allocatable_simd128_registers();
    *codes = data()->config()->allocatable_simd128_codes();
  } else if (rep == MachineRepresentation::kSimd256) {
    *num_regs = data()->config()->num_simd256_registers();
    *num_codes = data()->config()->num_allocatable_simd256_registers();
    *codes = data()->config()->allocatable_simd256_codes();
  } else {
    UNREACHABLE();
  }
}

void LinearScanAllocator::GetSIMD128RegisterSet(int* num_regs, int* num_codes,
                                                const int** codes) const {
  DCHECK_EQ(kFPAliasing, AliasingKind::kIndependent);

  *num_regs = data()->config()->num_simd128_registers();
  *num_codes = data()->config()->num_allocatable_simd128_registers();
  *codes = data()->config()->allocatable_simd128_codes();
}

void LinearScanAllocator::FindFreeRegistersForRange(
    LiveRange* range, base::Vector<LifetimePosition> positions) {
  int num_regs = num_registers();
  int num_codes = num_allocatable_registers();
  const int* codes = allocatable_register_codes();
  MachineRepresentation rep = range->representation();
  if (kFPAliasing == AliasingKind::kCombine &&
      (rep == MachineRepresentation::kFloat32 ||
       rep == MachineRepresentation::kSimd128)) {
    GetFPRegisterSet(rep, &num_regs, &num_codes, &codes);
  } else if (kFPAliasing == AliasingKind::kIndependent &&
             (rep == MachineRepresentation::kSimd128)) {
    GetSIMD128RegisterSet(&num_regs, &num_codes, &codes);
  }
  DCHECK_GE(positions.length(), num_regs);

  for (int i = 0; i < num_regs; ++i) {
    positions[i] = LifetimePosition::MaxPosition();
  }

  for (LiveRange* cur_active : active_live_ranges()) {
    int cur_reg = cur_active->assigned_register();
    if (kFPAliasing != AliasingKind::kCombine || !check_fp_aliasing()) {
      positions[cur_reg] = LifetimePosition::GapFromInstructionIndex(0);
      TRACE("Register %s is free until pos %d (1) due to %d\n",
            RegisterName(cur_reg),
            LifetimePosition::GapFromInstructionIndex(0).value(),
            cur_active->TopLevel()->vreg());
    } else {
      int alias_base_index = -1;
      int aliases = data()->config()->GetAliases(
          cur_active->representation(), cur_reg, rep, &alias_base_index);
      DCHECK(aliases > 0 || (aliases == 0 && alias_base_index == -1));
      while (aliases--) {
        int aliased_reg = alias_base_index + aliases;
        positions[aliased_reg] = LifetimePosition::GapFromInstructionIndex(0);
      }
    }
  }

  for (int cur_reg = 0; cur_reg < num_regs; ++cur_reg) {
    SlowDCheckInactiveLiveRangesIsSorted(cur_reg);
    for (LiveRange* cur_inactive : inactive_live_ranges(cur_reg)) {
      DCHECK_GT(cur_inactive->End(), range->Start());
      DCHECK_EQ(cur_inactive->assigned_register(), cur_reg);
      // No need to carry out intersections, when this register won't be
      // interesting to this range anyway.
      // TODO(mtrofin): extend to aliased ranges, too.
      if ((kFPAliasing != AliasingKind::kCombine || !check_fp_aliasing()) &&
          (positions[cur_reg] <= cur_inactive->NextStart() ||
           range->End() <= cur_inactive->NextStart())) {
        break;
      }
      LifetimePosition next_intersection =
          cur_inactive->FirstIntersection(range);
      if (!next_intersection.IsValid()) continue;
      if (kFPAliasing != AliasingKind::kCombine || !check_fp_aliasing()) {
        positions[cur_reg] = std::min(positions[cur_reg], next_intersection);
        TRACE("Register %s is free until pos %d (2)\n", RegisterName(cur_reg),
              positions[cur_reg].value());
      } else {
        int alias_base_index = -1;
        int aliases = data()->config()->GetAliases(
            cur_inactive->representation(), cur_reg, rep, &alias_base_index);
        DCHECK(aliases > 0 || (aliases == 0 && alias_base_index == -1));
        while (aliases--) {
          int aliased_reg = alias_base_index + aliases;
          positions[aliased_reg] =
              std::min(positions[aliased_reg], next_intersection);
        }
      }
    }
  }
}

// High-level register allocation summary:
//
// We attempt to first allocate the preferred (hint) register. If that is not
// possible, we find a register that's free, and allocate that. If that's not
// possible, we search for a register to steal from a range that was allocated.
// The goal is to optimize for throughput by avoiding register-to-memory moves,
// which are expensive.
void LinearScanAllocator::ProcessCurrentRange(LiveRange* current,
                                              SpillMode spill_mode) {
  base::EmbeddedVector<LifetimePosition, RegisterConfiguration::kMaxRegisters>
      free_until_pos;
  FindFreeRegistersForRange(current, free_until_pos);
  if (!TryAllocatePreferredReg(current, free_until_pos)) {
    if (!TryAllocateFreeReg(current, free_until_pos)) {
      AllocateBlockedReg(current, spill_mode);
    }
  }
  if (current->HasRegisterAssigned()) {
    AddToActive(current);
  }
}

bool LinearScanAllocator::TryAllocatePreferredReg(
    LiveRange* current, base::Vector<const LifetimePosition> free_until_pos) {
  int hint_register;
  if (current->RegisterFromControlFlow(&hint_register) ||
      current->RegisterFromFirstHint(&hint_register) ||
      current->RegisterFromBundle(&hint_register)) {
    TRACE(
        "Found reg hint %s (free until [%d) for live range %d:%d (end %d[).\n",
        RegisterName(hint_register), free_until_pos[hint_register].value(),
        current->TopLevel()->vreg(), current->relative_id(),
        current->End().value());

    // The desired register is free until the end of the current live range.
    if (free_until_pos[hint_register] >= current->End()) {
      TRACE("Assigning preferred reg %s to live range %d:%d\n",
            RegisterName(hint_register), current->TopLevel()->vreg(),
            current->relative_id());
      SetLiveRangeAssignedRegister(current, hint_register);
      return true;
    }
  }
  return false;
}

int LinearScanAllocator::PickRegisterThatIsAvailableLongest(
    LiveRange* current, int hint_reg,
    base::Vector<const LifetimePosition> free_until_pos) {
  int num_regs = 0;  // used only for the call to GetFPRegisterSet.
  int num_codes = num_allocatable_registers();
  const int* codes = allocatable_register_codes();
  MachineRepresentation rep = current->representation();
  if (kFPAliasing == AliasingKind::kCombine &&
      (rep == MachineRepresentation::kFloat32 ||
       rep == MachineRepresentation::kSimd128)) {
    GetFPRegisterSet(rep, &num_regs, &num_codes, &codes);
  } else if (kFPAliasing == AliasingKind::kIndependent &&
             (rep == MachineRepresentation::kSimd128)) {
    GetSIMD128RegisterSet(&num_regs, &num_codes, &codes);
  }

  DCHECK_GE(free_until_pos.length(), num_codes);

  // Find the register which stays free for the longest time. Check for
  // the hinted register first, as we might want to use that one. Only
  // count full instructions for free ranges, as an instruction's internal
  // positions do not help but might shadow a hinted register. This is
  // typically the case for function calls, where all registered are
  // cloberred after the call except for the argument registers, which are
  // set before the call. Hence, the argument registers always get ignored,
  // as their available time is shorter.
  int reg = (hint_reg == kUnassignedRegister) ? codes[0] : hint_reg;
  int current_free = free_until_pos[reg].ToInstructionIndex();
  for (int i = 0; i < num_codes; ++i) {
    int code = codes[i];
    // Prefer registers that have no fixed uses to avoid blocking later hints.
    // We use the first register that has no fixed uses to ensure we use
    // byte addressable registers in ia32 first.
    int candidate_free = free_until_pos[code].ToInstructionIndex();
    TRACE("Register %s in free until %d\n", RegisterName(code), candidate_free);
    if ((candidate_free > current_free) ||
        (candidate_free == current_free && reg != hint_reg &&
         (data()->HasFixedUse(current->representation(), reg) &&
          !data()->HasFixedUse(current->representation(), code)))) {
      reg = code;
      current_free = candidate_free;
    }
  }

  return reg;
}

bool LinearScanAllocator::TryAllocateFreeReg(
    LiveRange* current, base::Vector<const LifetimePosition> free_until_pos) {
  // Compute register hint, if such exists.
  int hint_reg = kUnassignedRegister;
  current->RegisterFromControlFlow(&hint_reg) ||
      current->RegisterFromFirstHint(&hint_reg) ||
      current->RegisterFromBundle(&hint_reg);

  int reg =
      PickRegisterThatIsAvailableLongest(current, hint_reg, free_until_pos);

  LifetimePosition pos = free_until_pos[reg];

  if (pos <= current->Start()) {
    // All registers are blocked.
    return false;
  }

  if (pos < current->End()) {
    // Register reg is available at the range start but becomes blocked before
    // the range end. Split current before the position where it becomes
    // blocked. Shift the split position to the last gap position. This is to
    // ensure that if a connecting move is needed, that move coincides with the
    // start of the range that it defines. See crbug.com/1182985.
    LifetimePosition gap_pos =
        pos.IsGapPosition() ? pos : pos.FullStart().End();
    if (gap_pos <= current->Start()) return false;
    LiveRange* tail = SplitRangeAt(current, gap_pos);
    AddToUnhandled(tail);

    // Try to allocate preferred register once more.
    if (TryAllocatePreferredReg(current, free_until_pos)) return true;
  }

  // Register reg is available at the range start and is free until the range
  // end.
  DCHECK_GE(pos, current->End());
  TRACE("Assigning free reg %s to live range %d:%d\n", RegisterName(reg),
        current->TopLevel()->vreg(), current->relative_id());
  SetLiveRangeAssignedRegister(current, reg);

  return true;
}

void LinearScanAllocator::AllocateBlockedReg(LiveRange* current,
                                             SpillMode spill_mode) {
  UsePosition* register_use = current->NextRegisterPosition(current->Start());
  if (register_use == nullptr) {
    // There is no use in the current live range that requires a register.
    // We can just spill it.
    LiveRange* begin_spill = nullptr;
    LifetimePosition spill_pos = FindOptimalSpillingPos(
        current, current->Start(), spill_mode, &begin_spill);
    MaybeSpillPreviousRanges(begin_spill, spill_pos, current);
    Spill(current, spill_mode);
    return;
  }

  MachineRepresentation rep = current->representation();

  // use_pos keeps track of positions a register/alias is used at.
  // block_pos keeps track of positions where a register/alias is blocked
  // from.
  base::EmbeddedVector<LifetimePosition, RegisterConfiguration::kMaxRegisters>
      use_pos(LifetimePosition::MaxPosition());
  base::EmbeddedVector<LifetimePosition, RegisterConfiguration::kMaxRegisters>
      block_pos(LifetimePosition::MaxPosition());

  for (LiveRange* range : active_live_ranges()) {
    int cur_reg = range->assigned_register();
    bool is_fixed_or_cant_spill =
        range->TopLevel()->IsFixed() || !range->CanBeSpilled(current->Start());
    if (kFPAliasing != AliasingKind::kCombine || !check_fp_aliasing()) {
      if (is_fixed_or_cant_spill) {
        block_pos[cur_reg] = use_pos[cur_reg] =
            LifetimePosition::GapFromInstructionIndex(0);
      } else {
        DCHECK_NE(LifetimePosition::GapFromInstructionIndex(0),
                  block_pos[cur_reg]);
        use_pos[cur_reg] =
            range->NextLifetimePositionRegisterIsBeneficial(current->Start());
      }
    } else {
      int alias_base_index = -1;
      int aliases = data()->config()->GetAliases(
          range->representation(), cur_reg, rep, &alias_base_index);
      DCHECK(aliases > 0 || (aliases == 0 && alias_base_index == -1));
      while (aliases--) {
        int aliased_reg = alias_base_index + aliases;
        if (is_fixed_or_cant_spill) {
          block_pos[aliased_reg] = use_pos[aliased_reg] =
              LifetimePosition::GapFromInstructionIndex(0);
        } else {
          use_pos[aliased_reg] =
              std::min(block_pos[aliased_reg],
                       range->NextLifetimePositionRegisterIsBeneficial(
                           current->Start()));
        }
      }
    }
  }

  for (int cur_reg = 0; cur_reg < num_registers(); ++cur_reg) {
    SlowDCheckInactiveLiveRangesIsSorted(cur_reg);
    for (LiveRange* range : inactive_live_ranges(cur_reg)) {
      DCHECK(range->End() > current->Start());
      DCHECK_EQ(range->assigned_register(), cur_reg);
      bool is_fixed = range->TopLevel()->IsFixed();

      // Don't perform costly intersections if they are guaranteed to not update
      // block_pos or use_pos.
      // TODO(mtrofin): extend to aliased ranges, too.
      if ((kFPAliasing != AliasingKind::kCombine || !check_fp_aliasing())) {
        DCHECK_LE(use_pos[cur_reg], block_pos[cur_reg]);
        if (block_pos[cur_reg] <= range->NextStart()) break;
        if (!is_fixed && use_pos[cur_reg] <= range->NextStart()) continue;
      }

      LifetimePosition next_intersection = range->FirstIntersection(current);
      if (!next_intersection.IsValid()) continue;

      if (kFPAliasing != AliasingKind::kCombine || !check_fp_aliasing()) {
        if (is_fixed) {
          block_pos[cur_reg] = std::min(block_pos[cur_reg], next_intersection);
          use_pos[cur_reg] = std::min(block_pos[cur_reg], use_pos[cur_reg]);
        } else {
          use_pos[cur_reg] = std::min(use_pos[cur_reg], next_intersection);
        }
      } else {
        int alias_base_index = -1;
        int aliases = data()->config()->GetAliases(
            range->representation(), cur_reg, rep, &alias_base_index);
        DCHECK(aliases > 0 || (aliases == 0 && alias_base_index == -1));
        while (aliases--) {
          int aliased_reg = alias_base_index + aliases;
          if (is_fixed) {
            block_pos[aliased_reg] =
                std::min(block_pos[aliased_reg], next_intersection);
            use_pos[aliased_reg] =
                std::min(block_pos[aliased_reg], use_pos[aliased_reg]);
          } else {
            use_pos[aliased_reg] =
                std::min(use_pos[aliased_reg], next_intersection);
          }
        }
      }
    }
  }

  // Compute register hint if it exists.
  int hint_reg = kUnassignedRegister;
  current->RegisterFromControlFlow(&hint_reg) ||
      register_use->HintRegister(&hint_reg) ||
      current->RegisterFromBundle(&hint_reg);
  int reg = PickRegisterThatIsAvailableLongest(current, hint_reg, use_pos);

  if (use_pos[reg] < register_use->pos()) {
    // If there is a gap position before the next register use, we can
    // spill until there. The gap position will then fit the fill move.
    if (LifetimePosition::ExistsGapPositionBetween(current->Start(),
                                                   register_use->pos())) {
      SpillBetween(current, current->Start(), register_use->pos(), spill_mode);
      return;
    }
  }

  // When in deferred spilling mode avoid stealing registers beyond the current
  // deferred region. This is required as we otherwise might spill an inactive
  // range with a start outside of deferred code and that would not be reloaded.
  LifetimePosition new_end = current->End();
  if (spill_mode == SpillMode::kSpillDeferred) {
    InstructionBlock* deferred_block =
        code()->GetInstructionBlock(current->Start().ToInstructionIndex());
    new_end =
        std::min(new_end, LifetimePosition::GapFromInstructionIndex(
                              LastDeferredInstructionIndex(deferred_block)));
  }

  // We couldn't spill until the next register use. Split before the register
  // is blocked, if applicable.
  if (block_pos[reg] < new_end) {
    // Register becomes blocked before the current range end. Split before that
    // position.
    new_end = block_pos[reg].Start();
  }

  // If there is no register available at all, we can only spill this range.
  // Happens for instance on entry to deferred code where registers might
  // become blocked yet we aim to reload ranges.
  if (new_end == current->Start()) {
    SpillBetween(current, new_end, register_use->pos(), spill_mode);
    return;
  }

  // Split at the new end if we found one.
  if (new_end != current->End()) {
    LiveRange* tail = SplitBetween(current, current->Start(), new_end);
    AddToUnhandled(tail);
  }

  // Register reg is not blocked for the whole range.
  DCHECK(block_pos[reg] >= current->End());
  TRACE("Assigning blocked reg %s to live range %d:%d\n", RegisterName(reg),
        current->TopLevel()->vreg(), current->relative_id());
  SetLiveRangeAssignedRegister(current, reg);

  // This register was not free. Thus we need to find and spill
  // parts of active and inactive live regions that use the same register
  // at the same lifetime positions as current.
  SplitAndSpillIntersecting(current, spill_mode);
}

void LinearScanAllocator::SplitAndSpillIntersecting(LiveRange* current,
                                                    SpillMode spill_mode) {
  DCHECK(current->HasRegisterAssigned());
  int reg = current->assigned_register();
  LifetimePosition split_pos = current->Start();
  for (auto it = active_live_ranges().begin();
       it != active_live_ranges().end();) {
    LiveRange* range = *it;
    if (kFPAliasing != AliasingKind::kCombine || !check_fp_aliasing()) {
      if (range->assigned_register() != reg) {
        ++it;
        continue;
      }
    } else {
      if (!data()->config()->AreAliases(current->representation(), reg,
                                        range->representation(),
                                        range->assigned_register())) {
        ++it;
        continue;
      }
    }

    UsePosition* next_pos = range->NextRegisterPosition(current->Start());
    LiveRange* begin_spill = nullptr;
    LifetimePosition spill_pos =
        FindOptimalSpillingPos(range, split_pos, spill_mode, &begin_spill);
    MaybeSpillPreviousRanges(begin_spill, spill_pos, range);
    if (next_pos == nullptr) {
      SpillAfter(range, spill_pos, spill_mode);
    } else {
      // When spilling between spill_pos and next_pos ensure that the range
      // remains spilled at least until the start of the current live range.
      // This guarantees that we will not introduce new unhandled ranges that
      // start before the current range as this violates allocation invariants
      // and will lead to an inconsistent state of active and inactive
      // live-ranges: ranges are allocated in order of their start positions,
      // ranges are retired from active/inactive when the start of the
      // current live-range is larger than their end.
      DCHECK(LifetimePosition::ExistsGapPositionBetween(current->Start(),
                                                        next_pos->pos()));
      SpillBetweenUntil(range, spill_pos, current->Start(), next_pos->pos(),
                        spill_mode);
    }
    it = ActiveToHandled(it);
  }

  for (int cur_reg = 0; cur_reg < num_registers(); ++cur_reg) {
    if (kFPAliasing != AliasingKind::kCombine || !check_fp_aliasing()) {
      if (cur_reg != reg) continue;
    }
    SlowDCheckInactiveLiveRangesIsSorted(cur_reg);
    for (auto it = inactive_live_ranges(cur_reg).begin();
         it != inactive_live_ranges(cur_reg).end();) {
      LiveRange* range = *it;
      if (kFPAliasing == AliasingKind::kCombine && check_fp_aliasing() &&
          !data()->config()->AreAliases(current->representation(), reg,
                                        range->representation(), cur_reg)) {
        ++it;
        continue;
      }
      DCHECK(range->End() > current->Start());
      if (range->TopLevel()->IsFixed()) {
        ++it;
        continue;
      }

      LifetimePosition next_intersection = range->FirstIntersection(current);
      if (next_intersection.IsValid()) {
        UsePosition* next_pos = range->NextRegisterPosition(current->Start());
        if (next_pos == nullptr) {
          SpillAfter(range, split_pos, spill_mode);
        } else {
          next_intersection = std::min(next_intersection, next_pos->pos());
          SpillBetween(range, split_pos, next_intersection, spill_mode);
        }
        it = InactiveToHandled(it);
      } else {
        ++it;
      }
    }
  }
}

bool LinearScanAllocator::TryReuseSpillForPhi(TopLevelLiveRange* range) {
  if (!range->is_phi()) return false;

  DCHECK(!range->HasSpillOperand());
  // Check how many operands belong to the same bundle as the output.
  LiveRangeBundle* out_bundle = range->get_bundle();
  RegisterAllocationData::PhiMapValue* phi_map_value =
      data()->GetPhiMapValueFor(range);
  const PhiInstruction* phi = phi_map_value->phi();
  const InstructionBlock* block = phi_map_value->block();
  // Count the number of spilled operands.
  size_t spilled_count = 0;
  for (size_t i = 0; i < phi->operands().size(); i++) {
    int op = phi->operands()[i];
    TopLevelLiveRange* op_range = data()->GetLiveRangeFor(op);
    if (!op_range->HasSpillRange() || op_range->get_bundle() != out_bundle)
      continue;
    const InstructionBlock* pred =
        code()->InstructionBlockAt(block->predecessors()[i]);
    LifetimePosition pred_end =
        LifetimePosition::InstructionFromInstructionIndex(
            pred->last_instruction_index());
    LiveRange* op_range_child = op_range->GetChildCovers(pred_end);
    if (op_range_child != nullptr && op_range_child->spilled()) {
      spilled_count++;
    }
  }

  // Only continue if more than half of the operands are spilled to the same
  // slot (because part of same bundle).
  if (spilled_count * 2 <= phi->operands().size()) {
    return false;
  }

  // If the range does not need register soon, spill it to the merged
  // spill range.
  LifetimePosition next_pos = range->Start();
  if (next_pos.IsGapPosition()) next_pos = next_pos.NextStart();
  UsePosition* pos = range->NextUsePositionRegisterIsBeneficial(next_pos);
  if (pos == nullptr) {
    Spill(range, SpillMode::kSpillAtDefinition);
    return true;
  } else if (pos->pos() > range->Start().NextStart()) {
    SpillBetween(range, range->Start(), pos->pos(),
                 SpillMode::kSpillAtDefinition);
    return true;
  }
  return false;
}

void LinearScanAllocator::SpillAfter(LiveRange* range, LifetimePosition pos,
                                     SpillMode spill_mode) {
  LiveRange* second_part = SplitRangeAt(range, pos);
  Spill(second_part, spill_mode);
}

void LinearScanAllocator::SpillBetween(LiveRange* range, LifetimePosition start,
                                       LifetimePosition end,
                                       SpillMode spill_mode) {
  SpillBetweenUntil(range, start, start, end, spill_mode);
}

void LinearScanAllocator::SpillBetweenUntil(LiveRange* range,
                                            LifetimePosition start,
                                            LifetimePosition until,
                                            LifetimePosition end,
                                            SpillMode spill_mode) {
  CHECK(start < end);
  LiveRange* second_part = SplitRangeAt(range, start);

  if (second_part->Start() < end) {
    // The split result intersects with [start, end[.
    // Split it at position between ]start+1, end[, spill the middle part
    // and put the rest to unhandled.

    // Make sure that the third part always starts after the start of the
    // second part, as that likely is the current position of the register
    // allocator and we cannot add ranges to unhandled that start before
    // the current position.
    LifetimePosition split_start = std::max(second_part->Start().End(), until);

    // If end is an actual use (which it typically is) we have to split
    // so that there is a gap before so that we have space for moving the
    // value into its position.
    // However, if we have no choice, split right where asked.
    LifetimePosition third_part_end =
        std::max(split_start, end.PrevStart().End());
    // Instead of spliting right after or even before the block boundary,
    // split on the boumndary to avoid extra moves.
    if (data()->IsBlockBoundary(end.Start())) {
      third_part_end = std::max(split_start, end.Start());
    }

    LiveRange* third_part =
        SplitBetween(second_part, split_start, third_part_end);
    if (GetInstructionBlock(data()->code(), second_part->Start())
            ->IsDeferred()) {
      // Try to use the same register as before.
      TRACE("Setting control flow hint for %d:%d to %s\n",
            third_part->TopLevel()->vreg(), third_part->relative_id(),
            RegisterName(range->controlflow_hint()));
      third_part->set_controlflow_hint(range->controlflow_hint());
    }

    AddToUnhandled(third_part);
    // This can happen, even if we checked for start < end above, as we fiddle
    // with the end location. However, we are guaranteed to be after or at
    // until, so this is fine.
    if (third_part != second_part) {
      Spill(second_part, spill_mode);
    }
  } else {
    // The split result does not intersect with [start, end[.
    // Nothing to spill. Just put it to unhandled as whole.
    AddToUnhandled(second_part);
  }
}

OperandAssigner::OperandAssigner(RegisterAllocationData* data) : data_(data) {}

void OperandAssigner::DecideSpillingMode() {
  for (auto range : data()->live_ranges()) {
    data()->tick_counter()->TickAndMaybeEnterSafepoint();
    DCHECK_NOT_NULL(range);
    if (range->IsSpilledOnlyInDeferredBlocks(data())) {
      // If the range is spilled only in deferred blocks and starts in
      // a non-deferred block, we transition its representation here so
      // that the LiveRangeConnector processes them correctly. If,
      // however, they start in a deferred block, we uograde them to
      // spill at definition, as that definition is in a deferred block
      // anyway. While this is an optimization, the code in LiveRangeConnector
      // relies on it!
      if (GetInstructionBlock(data()->code(), range->Start())->IsDeferred()) {
        TRACE("Live range %d is spilled and alive in deferred code only\n",
              range->vreg());
        range->TransitionRangeToSpillAtDefinition();
      } else {
        TRACE("Live range %d is spilled deferred code only but alive outside\n",
              range->vreg());
        range->TransitionRangeToDeferredSpill(data()->allocation_zone());
      }
    }
  }
}

void OperandAssigner::AssignSpillSlots() {
  ZoneVector<SpillRange*> spill_ranges(data()->allocation_zone());
  for (const TopLevelLiveRange* range : data()->live_ranges()) {
    DCHECK_NOT_NULL(range);
    if (range->HasSpillRange()) {
      DCHECK_NOT_NULL(range->GetSpillRange());
      spill_ranges.push_back(range->GetSpillRange());
    }
  }
  // At this point, the `SpillRange`s for all `TopLevelLiveRange`s should be
  // unique, since none have been merged yet.
  DCHECK_EQ(spill_ranges.size(),
            std::set(spill_ranges.begin(), spill_ranges.end()).size());

  // Merge all `SpillRange`s that belong to the same `LiveRangeBundle`.
  for (const TopLevelLiveRange* range : data()->live_ranges()) {
    data()->tick_counter()->TickAndMaybeEnterSafepoint();
    DCHECK_NOT_NULL(range);
    if (range->get_bundle() != nullptr) {
      range->get_bundle()->MergeSpillRangesAndClear();
    }
  }

  // Now merge *all* disjoint, non-empty `SpillRange`s.
  // Formerly, this merging was O(n^2) in the number of `SpillRange`s, which
  // then dominated compile time (>40%) for some pathological cases,
  // e.g., https://crbug.com/v8/14133.
  // Now, we allow only `kMaxRetries` unsuccessful merges with directly
  // following `SpillRange`s. After each `kMaxRetries`, we exponentially
  // increase the stride, which limits the inner loop to O(log n) and thus
  // the overall merging to O(n * log n).

  // The merging above may have left some `SpillRange`s empty, remove them.
  SpillRange** end_nonempty =
      std::remove_if(spill_ranges.begin(), spill_ranges.end(),
                     [](const SpillRange* range) { return range->IsEmpty(); });
  for (SpillRange** range_it = spill_ranges.begin(); range_it < end_nonempty;
       ++range_it) {
    data()->tick_counter()->TickAndMaybeEnterSafepoint();
    SpillRange* range = *range_it;
    DCHECK(!range->IsEmpty());
    constexpr size_t kMaxRetries = 1000;
    size_t retries = kMaxRetries;
    size_t stride = 1;
    for (SpillRange** other_it = range_it + 1; other_it < end_nonempty;
         other_it += stride) {
      SpillRange* other = *other_it;
      DCHECK(!other->IsEmpty());
      if (range->TryMerge(other)) {
        DCHECK(other->IsEmpty());
        std::iter_swap(other_it, --end_nonempty);
      } else if (--retries == 0) {
        retries = kMaxRetries;
        stride *= 2;
      }
    }
  }
  spill_ranges.erase(end_nonempty, spill_ranges.end());

  // Allocate slots for the merged spill ranges.
  for (SpillRange* range : spill_ranges) {
    data()->tick_counter()->TickAndMaybeEnterSafepoint();
    DCHECK(!range->IsEmpty());
    if (!range->HasSlot()) {
      // Allocate a new operand referring to the spill slot, aligned to the
      // operand size.
      int width = range->byte_width();
      int index = data()->frame()->AllocateSpillSlot(width, width);
      range->set_assigned_slot(index);
    }
  }
}

void OperandAssigner::CommitAssignment() {
  const size_t live_ranges_size = data()->live_ranges().size();
  for (TopLevelLiveRange* top_range : data()->live_ranges()) {
    data()->tick_counter()->TickAndMaybeEnterSafepoint();
    CHECK_EQ(live_ranges_size,
             data()->live_ranges().size());  // TODO(neis): crbug.com/831822
    DCHECK_NOT_NULL(top_range);
    if (top_range->IsEmpty()) continue;
    InstructionOperand spill_operand;
    if (top_range->HasSpillOperand()) {
      auto it = data()->slot_for_const_range().find(top_range);
      if (it != data()->slot_for_const_range().end()) {
        spill_operand = *it->second;
      } else {
        spill_operand = *top_range->GetSpillOperand();
      }
    } else if (top_range->HasSpillRange()) {
      spill_operand = top_range->GetSpillRangeOperand();
    }
    if (top_range->is_phi()) {
      data()->GetPhiMapValueFor(top_range)->CommitAssignment(
          top_range->GetAssignedOperand());
    }
    for (LiveRange* range = top_range; range != nullptr;
         range = range->next()) {
      InstructionOperand assigned = range->GetAssignedOperand();
      DCHECK(!assigned.IsUnallocated());
      range->ConvertUsesToOperand(assigned, spill_operand);
    }

    if (!spill_operand.IsInvalid()) {
      // If this top level range has a child spilled in a deferred block, we use
      // the range and control flow connection mechanism instead of spilling at
      // definition. Refer to the ConnectLiveRanges and ResolveControlFlow
      // phases. Normally, when we spill at definition, we do not insert a
      // connecting move when a successor child range is spilled - because the
      // spilled range picks up its value from the slot which was assigned at
      // definition. For ranges that are determined to spill only in deferred
      // blocks, we let ConnectLiveRanges and ResolveControlFlow find the blocks
      // where a spill operand is expected, and then finalize by inserting the
      // spills in the deferred blocks dominators.
      if (!top_range->IsSpilledOnlyInDeferredBlocks(data()) &&
          !top_range->HasGeneralSpillRange()) {
        // Spill at definition if the range isn't spilled in a way that will be
        // handled later.
        top_range->FilterSpillMoves(data(), spill_operand);
        top_range->CommitSpillMoves(data(), spill_operand);
      }
    }
  }
}

ReferenceMapPopulator::ReferenceMapPopulator(RegisterAllocationData* data)
    : data_(data) {}

bool ReferenceMapPopulator::SafePointsAreInOrder() const {
  int safe_point = 0;
  for (ReferenceMap* map : *data()->code()->reference_maps()) {
    if (safe_point > map->instruction_position()) return false;
    safe_point = map->instruction_position();
  }
  return true;
}

void ReferenceMapPopulator::PopulateReferenceMaps() {
  DCHECK(SafePointsAreInOrder());
  // Map all delayed references.
  for (RegisterAllocationData::DelayedReference& delayed_reference :
       data()->delayed_references()) {
    delayed_reference.map->RecordReference(
        AllocatedOperand::cast(*delayed_reference.operand));
  }
  // Iterate over all safe point positions and record a pointer
  // for all spilled live ranges at this point.
  int last_range_start = 0;
  const ReferenceMaps* reference_maps = data()->code()->reference_maps();
  ReferenceMaps::const_iterator first_it = reference_maps->begin();
  const size_t live_ranges_size = data()->live_ranges().size();
  // Select subset of `TopLevelLiveRange`s to process, sort them by their start.
  ZoneVector<TopLevelLiveRange*> candidate_ranges(data()->allocation_zone());
  candidate_ranges.reserve(data()->live_ranges().size());
  for (TopLevelLiveRange* range : data()->live_ranges()) {
    CHECK_EQ(live_ranges_size,
             data()->live_ranges().size());  // TODO(neis): crbug.com/831822
    DCHECK_NOT_NULL(range);
    // Skip non-reference values.
    if (!data()->code()->IsReference(range->vreg())) continue;
    // Skip empty live ranges.
    if (range->IsEmpty()) continue;
    if (range->has_preassigned_slot()) continue;
    candidate_ranges.push_back(range);
  }
  std::sort(candidate_ranges.begin(), candidate_ranges.end(),
            LiveRangeOrdering());
  for (TopLevelLiveRange* range : candidate_ranges) {
    // Find the extent of the range and its children.
    int start = range->Start().ToInstructionIndex();
    int end = range->Children().back()->End().ToInstructionIndex();

    // Ranges should be sorted, so that the first reference map in the current
    // live range has to be after {first_it}.
    DCHECK_LE(last_range_start, start);
    last_range_start = start;
    USE(last_range_start);

    // Step across all the safe points that are before the start of this range,
    // recording how far we step in order to save doing this for the next range.
    for (; first_it != reference_maps->end(); ++first_it) {
      ReferenceMap* map = *first_it;
      if (map->instruction_position() >= start) break;
    }

    InstructionOperand spill_operand;
    if (((range->HasSpillOperand() &&
          !range->GetSpillOperand()->IsConstant()) ||
         range->HasSpillRange())) {
      if (range->HasSpillOperand()) {
        spill_operand = *range->GetSpillOperand();
      } else {
        spill_operand = range->GetSpillRangeOperand();
      }
      DCHECK(spill_operand.IsStackSlot());
      DCHECK(CanBeTaggedOrCompressedPointer(
          AllocatedOperand::cast(spill_operand).representation()));
    }

    LiveRange* cur = nullptr;
    // Step through the safe points to see whether they are in the range.
    for (auto it = first_it; it != reference_maps->end(); ++it) {
      ReferenceMap* map = *it;
      int safe_point = map->instruction_position();

      // The safe points are sorted so we can stop searching here.
      if (safe_point - 1 > end) break;

      // Advance to the next active range that covers the current
      // safe point position.
      LifetimePosition safe_point_pos =
          LifetimePosition::InstructionFromInstructionIndex(safe_point);

      // Search for the child range (cur) that covers safe_point_pos. If we
      // don't find it before the children pass safe_point_pos, keep cur at
      // the last child, because the next safe_point_pos may be covered by cur.
      // This may happen if cur has more than one interval, and the current
      // safe_point_pos is in between intervals.
      // For that reason, cur may be at most the last child.
      // Use binary search for the first iteration, then linear search after.
      bool found = false;
      if (cur == nullptr) {
        cur = range->GetChildCovers(
```