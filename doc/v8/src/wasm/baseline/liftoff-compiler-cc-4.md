Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/baseline/liftoff-compiler.cc`.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The file name and the presence of terms like `compiler`, `assembler`, `wasm` suggest it's about compiling WebAssembly code. `liftoff` likely refers to a specific compilation strategy (likely a fast, baseline compiler).

2. **Analyze key methods:**  Look for methods with names that indicate actions or operations. Examples in the snippet:
    * `Select`:  Likely related to conditional value selection.
    * `BrImpl`, `BrOrRet`, `BrIf`, `BrTable`:  Clearly about branching and control flow.
    * `LoadMem`, `StoreMem`, `LoadLane`, `StoreLane`: Operations on memory.
    * `BoundsCheckMem`, `AlignmentCheckMem`: Memory access validation.
    * `ReturnImpl`: Function return.
    * `TierupCheck`:  Potentially related to optimizing compilation over time.

3. **Infer functionality from method logic:**  Examine the code within the methods to understand what they do. For instance:
    * `Select` has logic for conditional moves, with a fallback to conditional jumps if direct selection isn't possible.
    * The `Br*` methods manipulate labels and stack states, indicating how control flow is managed.
    * The memory access methods involve bounds checking, alignment checking, loading/storing values, and potentially triggering traps for out-of-bounds accesses.

4. **Relate to WebAssembly concepts:** Connect the observed functionality to WebAssembly instructions and features. For example, `BrIf` corresponds to the `br_if` instruction, `LoadMem` to memory load instructions, and so on.

5. **Address specific requests:**
    * **`.tq` extension:** Check if the filename ends with `.tq`. In this case, it doesn't.
    * **JavaScript relation:** If the functionality relates to JavaScript, provide a JavaScript example. WebAssembly interacts closely with JavaScript, so things like memory access and function calls will have parallels.
    * **Logic inference:**  For methods with clear logic, provide input and output examples. `Select` is a good candidate for this.
    * **Common errors:**  Think about common mistakes developers make with WebAssembly, such as out-of-bounds memory access.
    * **Part number:** Acknowledge the "part 5 of 13" information.

6. **Synthesize a summary:** Combine the findings into a concise description of the file's purpose and key functionalities.

**Self-Correction/Refinement during the thought process:**

* Initially, I might focus too much on low-level details. The request is for a *functional* summary, so I need to abstract away some of the implementation specifics.
* I need to ensure I'm answering all parts of the user's request, including the questions about `.tq`, JavaScript, logic inference, and common errors.
* The "归纳一下它的功能" strongly suggests a summarization, so the output should be focused and high-level.

By following these steps, I can generate a comprehensive and accurate summary of the `liftoff-compiler.cc` file's functionality.
这是V8 JavaScript引擎中Liftoff编译器的一部分，负责将WebAssembly (Wasm) 代码快速编译为机器码。由于这是第5部分，我们可以推断前面部分可能处理了初始化、解码等任务，而后续部分会涉及更多指令和优化。

**以下是 `v8/src/wasm/baseline/liftoff-compiler.cc` 代码片段的主要功能归纳：**

1. **条件选择 (Select):**  实现了 WebAssembly 的 `select` 指令。它基于一个条件值，选择两个输入值中的一个作为输出。如果目标寄存器和其中一个输入值相同，则尝试直接进行条件移动。否则，使用分支指令实现条件选择。

2. **无条件跳转 (BrImpl):**  处理 WebAssembly 的 `br` (branch) 指令，用于无条件跳转到指定的控制结构（例如，块的末尾或循环的开始）。它涉及到合并栈状态，并可能包含动态分层编译的检查 (`dynamic_tiering()`)，以便在循环等热点代码中触发更优化的编译。

3. **条件跳转 (BrIf):** 处理 WebAssembly 的 `br_if` (branch if) 指令，根据条件值的真假决定是否跳转。如果条件为假，则继续执行后续代码。

4. **分支表 (BrTable):** 处理 WebAssembly 的 `br_table` 指令，根据索引值跳转到一组目标标签中的一个。它通过递归地生成条件分支来实现，类似于构建一个决策树。

5. **Else 块处理 (Else):** 处理 WebAssembly `if-else` 结构中的 `else` 块。它负责合并栈状态，并跳转到 `if` 块的结束标签。

6. **生成陷阱代码 (AddOutOfLineTrap):**  当需要触发 WebAssembly 陷阱（例如，内存越界访问）时，生成跳转到预定义的陷阱处理代码的指令。这在调试模式下会保存寄存器状态以便检查。

7. **内存访问边界检查 (BoundsCheckMem):**  在执行内存加载或存储操作之前，检查访问的索引是否在内存边界内。它支持不同的边界检查策略，包括使用硬件陷阱处理程序。

8. **内存访问对齐检查 (AlignmentCheckMem):**  检查内存访问是否符合数据类型的对齐要求。如果未对齐，则生成一个陷阱。

9. **跟踪内存操作 (TraceMemoryOperation):**  （在启用了 `trace_wasm_memory` 标志的情况下）在内存加载或存储操作前后插入对运行时函数的调用，用于记录内存访问信息，用于调试和分析。

10. **静态边界检查优化 (IndexStaticallyInBounds):**  尝试在编译时确定内存访问是否在边界内。如果索引是一个常量，并且偏移加上索引在有效范围内，则可以避免运行时的边界检查。

11. **获取内存起始地址 (GetMemoryStart):**  获取指定内存实例的起始地址。它会尝试缓存内存起始地址以提高效率。

12. **加载内存 (LoadMem):**  处理 WebAssembly 的内存加载指令，从指定的内存地址加载值到寄存器。它包括边界检查和可选的内存跟踪。

13. **向量加载转换 (LoadTransform):** 处理需要进行转换的向量加载指令，例如零扩展或符号扩展。

14. **向量加载通道 (LoadLane):** 处理加载向量中特定通道的指令。

15. **存储到内存 (StoreMem):** 处理 WebAssembly 的内存存储指令，将寄存器中的值存储到指定的内存地址。它包括边界检查和可选的内存跟踪。

16. **向量存储通道 (StoreLane):** 处理将向量中特定通道存储到内存的指令。

**关于其他问题的回答:**

* **`.tq` 结尾：**  代码片段的文件名是 `liftoff-compiler.cc`，没有 `.tq` 结尾，所以它不是 Torque 源代码。

* **与 JavaScript 功能的关系：**  WebAssembly 模块通常在 JavaScript 环境中运行，并且可以与 JavaScript 代码进行交互。内存访问是其中一个关键的交互点。

   ```javascript
   // 假设一个 WebAssembly 模块实例名为 'wasmInstance'，并且它导出了一个名为 'memory' 的 Memory 对象

   // 创建一个 Uint8Array 视图来访问 WebAssembly 的线性内存
   const memoryBuffer = wasmInstance.exports.memory.buffer;
   const memoryView = new Uint8Array(memoryBuffer);

   // 假设 WebAssembly 代码中有一个加载 i32 类型的操作，地址偏移为 10
   const offset = 10;
   // 在 JavaScript 中模拟从 WebAssembly 内存中加载 i32 (4个字节)
   const loadedValue = memoryView[offset] |
                       (memoryView[offset + 1] << 8) |
                       (memoryView[offset + 2] << 16) |
                       (memoryView[offset + 3] << 24);

   console.log("从 WebAssembly 内存加载的值:", loadedValue);

   // 假设 WebAssembly 代码中有一个存储 i32 类型的操作，地址偏移为 20，存储值为 12345
   const storeOffset = 20;
   const valueToStore = 12345;
   // 在 JavaScript 中模拟向 WebAssembly 内存中存储 i32
   memoryView[storeOffset] = valueToStore & 0xFF;
   memoryView[storeOffset + 1] = (valueToStore >> 8) & 0xFF;
   memoryView[storeOffset + 2] = (valueToStore >> 16) & 0xFF;
   memoryView[storeOffset + 3] = (valueToStore >> 24) & 0xFF;

   console.log("已将值存储到 WebAssembly 内存");
   ```

* **代码逻辑推理 (Select):**

   **假设输入：**
   * `dst` 寄存器：R1
   * `condition` 寄存器：R2 (值为 1，表示真)
   * `true_value` 寄存器：R3 (值为 10)
   * `false_value` 寄存器：R4 (值为 20)
   * `kind`：kI32

   **预期输出：**
   由于 `condition` (R2) 的值为真，`dst` 寄存器 (R1) 的值将被设置为 `true_value` (R3) 的值，即 10。如果 `dst` 和 `true_value` 不是同一个寄存器，则会执行一个移动操作。

* **用户常见的编程错误：**

   **内存越界访问：**  这是 WebAssembly 中常见的错误。例如，尝试访问超出分配的内存范围的地址。

   ```c++
   // WebAssembly 代码 (示意)
   void store_at_invalid_address(int index, int value) {
     // 假设内存大小为 100，但 index 可能很大
     memory[index] = value; // 如果 index >= 100，则会发生内存越界
   }
   ```

   在 `liftoff-compiler.cc` 中，`BoundsCheckMem` 函数就是为了防止这种错误而存在的。如果检测到越界访问，它会生成陷阱代码。

**总结:**

这段代码是 V8 中 Liftoff 编译器的核心部分，负责将 WebAssembly 的控制流指令（如分支）和内存访问指令编译成机器码，并确保内存访问的安全性。它还包含了一些与性能相关的优化，例如动态分层编译的检查。

Prompt: 
```
这是目录为v8/src/wasm/baseline/liftoff-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/liftoff-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共13部分，请归纳一下它的功能

"""
ue, false_value}, {});
    if (!__ emit_select(dst, condition, true_value, false_value, kind)) {
      FREEZE_STATE(frozen);
      // Emit generic code (using branches) instead.
      Label cont;
      Label case_false;
      __ emit_cond_jump(kEqual, &case_false, kI32, condition, no_reg, frozen);
      if (dst != true_value) __ Move(dst, true_value, kind);
      __ emit_jump(&cont);

      __ bind(&case_false);
      if (dst != false_value) __ Move(dst, false_value, kind);
      __ bind(&cont);
    }
    __ PushRegister(kind, dst);
  }

  void BrImpl(FullDecoder* decoder, Control* target) {
    if (dynamic_tiering()) {
      if (target->is_loop()) {
        DCHECK(target->label.get()->is_bound());
        int jump_distance = __ pc_offset() - target->label.get()->pos();
        TierupCheck(decoder, decoder->position(), jump_distance);
      } else {
        // To estimate time spent in this function more accurately, we could
        // increment the tiering budget on forward jumps. However, we don't
        // know the jump distance yet; using a blanket value has been tried
        // and found to not make a difference.
      }
    }
    if (target->br_merge()->reached) {
      __ MergeStackWith(target->label_state, target->br_merge()->arity,
                        target->is_loop() ? LiftoffAssembler::kBackwardJump
                                          : LiftoffAssembler::kForwardJump);
    } else {
      target->label_state =
          __ MergeIntoNewState(__ num_locals(), target->br_merge()->arity,
                               target->stack_depth + target->num_exceptions);
    }
    __ jmp(target->label.get());
  }

  bool NeedsTierupCheck(FullDecoder* decoder, uint32_t br_depth) {
    if (!dynamic_tiering()) return false;
    return br_depth == decoder->control_depth() - 1 ||
           decoder->control_at(br_depth)->is_loop();
  }

  void BrOrRet(FullDecoder* decoder, uint32_t depth) {
    if (depth == decoder->control_depth() - 1) {
      ReturnImpl(decoder);
    } else {
      BrImpl(decoder, decoder->control_at(depth));
    }
  }

  void BrIf(FullDecoder* decoder, const Value& /* cond */, uint32_t depth) {
    // Avoid having sequences of branches do duplicate work.
    if (depth != decoder->control_depth() - 1) {
      __ PrepareForBranch(decoder->control_at(depth)->br_merge()->arity, {});
    }

    Label cont_false;

    // Test the condition on the value stack, jump to {cont_false} if zero.
    std::optional<FreezeCacheState> frozen;
    JumpIfFalse(decoder, &cont_false, frozen);

    BrOrRet(decoder, depth);

    __ bind(&cont_false);
  }

  // Generate a branch table case, potentially reusing previously generated
  // stack transfer code.
  void GenerateBrCase(FullDecoder* decoder, uint32_t br_depth,
                      ZoneMap<uint32_t, MovableLabel>* br_targets) {
    auto [iterator, is_new_target] = br_targets->emplace(br_depth, zone_);
    Label* label = iterator->second.get();
    DCHECK_EQ(is_new_target, !label->is_bound());
    if (is_new_target) {
      __ bind(label);
      BrOrRet(decoder, br_depth);
    } else {
      __ jmp(label);
    }
  }

  // Generate a branch table for input in [min, max).
  // TODO(wasm): Generate a real branch table (like TF TableSwitch).
  void GenerateBrTable(FullDecoder* decoder, LiftoffRegister value,
                       uint32_t min, uint32_t max,
                       BranchTableIterator<ValidationTag>* table_iterator,
                       ZoneMap<uint32_t, MovableLabel>* br_targets,
                       const FreezeCacheState& frozen) {
    DCHECK_LT(min, max);
    // Check base case.
    if (max == min + 1) {
      DCHECK_EQ(min, table_iterator->cur_index());
      GenerateBrCase(decoder, table_iterator->next(), br_targets);
      return;
    }

    uint32_t split = min + (max - min) / 2;
    Label upper_half;
    __ emit_i32_cond_jumpi(kUnsignedGreaterThanEqual, &upper_half, value.gp(),
                           split, frozen);
    // Emit br table for lower half:
    GenerateBrTable(decoder, value, min, split, table_iterator, br_targets,
                    frozen);
    __ bind(&upper_half);
    // table_iterator will trigger a DCHECK if we don't stop decoding now.
    if (did_bailout()) return;
    // Emit br table for upper half:
    GenerateBrTable(decoder, value, split, max, table_iterator, br_targets,
                    frozen);
  }

  void BrTable(FullDecoder* decoder, const BranchTableImmediate& imm,
               const Value& key) {
    LiftoffRegList pinned;
    LiftoffRegister value = pinned.set(__ PopToRegister());

    {
      // All targets must have the same arity (checked by validation), so
      // we can just sample any of them to find that arity.
      auto [sample_depth, unused_length] =
          decoder->read_u32v<Decoder::NoValidationTag>(imm.table,
                                                       "first depth");
      __ PrepareForBranch(decoder->control_at(sample_depth)->br_merge()->arity,
                          pinned);
    }

    BranchTableIterator<ValidationTag> table_iterator{decoder, imm};
    ZoneMap<uint32_t, MovableLabel> br_targets{zone_};

    if (imm.table_count > 0) {
      FREEZE_STATE(frozen);
      Label case_default;
      __ emit_i32_cond_jumpi(kUnsignedGreaterThanEqual, &case_default,
                             value.gp(), imm.table_count, frozen);

      GenerateBrTable(decoder, value, 0, imm.table_count, &table_iterator,
                      &br_targets, frozen);

      __ bind(&case_default);
      // table_iterator will trigger a DCHECK if we don't stop decoding now.
      if (did_bailout()) return;
    }

    // Generate the default case.
    GenerateBrCase(decoder, table_iterator.next(), &br_targets);
    DCHECK(!table_iterator.has_next());
  }

  void Else(FullDecoder* decoder, Control* c) {
    if (c->reachable()) {
      if (c->end_merge.reached) {
        __ MergeFullStackWith(c->label_state);
      } else {
        c->label_state =
            __ MergeIntoNewState(__ num_locals(), c->end_merge.arity,
                                 c->stack_depth + c->num_exceptions);
      }
      __ emit_jump(c->label.get());
    }
    __ bind(c->else_state->label.get());
    __ cache_state()->Steal(c->else_state->state);
  }

  SpilledRegistersForInspection* GetSpilledRegistersForInspection() {
    DCHECK(for_debugging_);
    // If we are generating debugging code, we really need to spill all
    // registers to make them inspectable when stopping at the trap.
    auto* spilled = zone_->New<SpilledRegistersForInspection>(zone_);
    for (uint32_t i = 0, e = __ cache_state()->stack_height(); i < e; ++i) {
      auto& slot = __ cache_state()->stack_state[i];
      if (!slot.is_reg()) continue;
      spilled->entries.push_back(SpilledRegistersForInspection::Entry{
          slot.offset(), slot.reg(), slot.kind()});
      __ RecordUsedSpillOffset(slot.offset());
    }
    return spilled;
  }

  Label* AddOutOfLineTrap(FullDecoder* decoder, Builtin builtin) {
    DCHECK(v8_flags.wasm_bounds_checks);
    OutOfLineSafepointInfo* safepoint_info = nullptr;
    // Execution does not return after a trap. Therefore we don't have to define
    // a safepoint for traps that would preserve references on the stack.
    // However, if this is debug code, then we have to preserve the references
    // so that they can be inspected.
    if (V8_UNLIKELY(for_debugging_)) {
      safepoint_info = zone_->New<OutOfLineSafepointInfo>(zone_);
      __ cache_state()->GetTaggedSlotsForOOLCode(
          &safepoint_info->slots, &safepoint_info->spills,
          LiftoffAssembler::CacheState::SpillLocation::kStackSlots);
    }
    out_of_line_code_.push_back(OutOfLineCode::Trap(
        zone_, builtin, decoder->position(),
        V8_UNLIKELY(for_debugging_) ? GetSpilledRegistersForInspection()
                                    : nullptr,
        safepoint_info, RegisterOOLDebugSideTableEntry(decoder)));
    return out_of_line_code_.back().label.get();
  }

  enum ForceCheck : bool { kDoForceCheck = true, kDontForceCheck = false };
  enum AlignmentCheck : bool {
    kCheckAlignment = true,
    kDontCheckAlignment = false
  };

  // Returns the GP {index} register holding the ptrsized index.
  // Note that the {index} will typically not be pinned, but the returned
  // register will be pinned by the caller. This avoids one pinned register if
  // {full_index} is a pair.
  Register BoundsCheckMem(FullDecoder* decoder, const WasmMemory* memory,
                          uint32_t access_size, uint64_t offset,
                          LiftoffRegister index, LiftoffRegList pinned,
                          ForceCheck force_check,
                          AlignmentCheck check_alignment) {
    // The decoder ensures that the access is not statically OOB.
    DCHECK(base::IsInBounds<uintptr_t>(offset, access_size,
                                       memory->max_memory_size));

    wasm::BoundsCheckStrategy bounds_checks = memory->bounds_checks;

    // After bounds checking, we know that the index must be ptrsize, hence only
    // look at the lower word on 32-bit systems (the high word is bounds-checked
    // further down).
    Register index_ptrsize =
        kNeedI64RegPair && index.is_gp_pair() ? index.low_gp() : index.gp();

    if (check_alignment) {
      AlignmentCheckMem(decoder, access_size, offset, index_ptrsize,
                        pinned | LiftoffRegList{index});
    }

    // Without bounds checks (testing only), just return the ptrsize index.
    if (V8_UNLIKELY(bounds_checks == kNoBoundsChecks)) {
      return index_ptrsize;
    }

    // We already checked that an access at `offset` is within max memory size.
    uintptr_t end_offset = offset + access_size - 1u;
    DCHECK_LT(end_offset, memory->max_memory_size);

    // Early return for trap handler.
    bool use_trap_handler = !force_check && bounds_checks == kTrapHandler;
    bool need_ool_code = !use_trap_handler || memory->is_memory64();
    Label* trap_label =
        need_ool_code
            ? AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapMemOutOfBounds)
            : nullptr;

    DCHECK_IMPLIES(
        memory->is_memory64() && !v8_flags.wasm_memory64_trap_handling,
        bounds_checks == kExplicitBoundsChecks);
#if V8_TRAP_HANDLER_SUPPORTED
    if (use_trap_handler) {
#if V8_TARGET_ARCH_ARM64 || V8_TARGET_ARCH_X64
      if (memory->is_memory64()) {
        SCOPED_CODE_COMMENT("bounds check memory");
        // Bounds check `index` against `max_mem_size - end_offset`, such that
        // at runtime `index + end_offset` will be < `max_mem_size`, where the
        // trap handler can handle out-of-bound accesses.
        __ set_trap_on_oob_mem64(
            index_ptrsize, memory->max_memory_size - end_offset, trap_label);
      }
#else
      CHECK(!memory->is_memory64());
#endif  // V8_TARGET_ARCH_ARM64 || V8_TARGET_ARCH_X64

      // With trap handlers we should not have a register pair as input (we
      // would only return the lower half).
      DCHECK(index.is_gp());
      return index_ptrsize;
    }
#else
    CHECK(!use_trap_handler);
#endif  // V8_TRAP_HANDLER_SUPPORTED

    SCOPED_CODE_COMMENT("bounds check memory");

    // Convert the index to ptrsize, bounds-checking the high word on 32-bit
    // systems for memory64.
    if (!memory->is_memory64()) {
      __ emit_u32_to_uintptr(index_ptrsize, index_ptrsize);
    } else if (kSystemPointerSize == kInt32Size) {
      DCHECK_GE(kMaxUInt32, memory->max_memory_size);
      FREEZE_STATE(trapping);
      __ emit_cond_jump(kNotZero, trap_label, kI32, index.high_gp(), no_reg,
                        trapping);
    }

    pinned.set(index_ptrsize);
    LiftoffRegister end_offset_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LiftoffRegister mem_size = __ GetUnusedRegister(kGpReg, pinned);
    // TODO(13957): Clamp the loaded memory size to a safe value.
    if (memory->index == 0) {
      LOAD_INSTANCE_FIELD(mem_size.gp(), Memory0Size, kSystemPointerSize,
                          pinned);
    } else {
      LOAD_PROTECTED_PTR_INSTANCE_FIELD(mem_size.gp(), MemoryBasesAndSizes,
                                        pinned);
      int buffer_offset =
          wasm::ObjectAccess::ToTagged(OFFSET_OF_DATA_START(ByteArray)) +
          kSystemPointerSize * (memory->index * 2 + 1);
      __ LoadFullPointer(mem_size.gp(), mem_size.gp(), buffer_offset);
    }

    __ LoadConstant(end_offset_reg, WasmValue::ForUintPtr(end_offset));

    FREEZE_STATE(trapping);
    // If the end offset is larger than the smallest memory, dynamically check
    // the end offset against the actual memory size, which is not known at
    // compile time. Otherwise, only one check is required (see below).
    if (end_offset > memory->min_memory_size) {
      __ emit_cond_jump(kUnsignedGreaterThanEqual, trap_label, kIntPtrKind,
                        end_offset_reg.gp(), mem_size.gp(), trapping);
    }

    // Just reuse the end_offset register for computing the effective size
    // (which is >= 0 because of the check above).
    LiftoffRegister effective_size_reg = end_offset_reg;
    __ emit_ptrsize_sub(effective_size_reg.gp(), mem_size.gp(),
                        end_offset_reg.gp());

    __ emit_cond_jump(kUnsignedGreaterThanEqual, trap_label, kIntPtrKind,
                      index_ptrsize, effective_size_reg.gp(), trapping);
    return index_ptrsize;
  }

  void AlignmentCheckMem(FullDecoder* decoder, uint32_t access_size,
                         uintptr_t offset, Register index,
                         LiftoffRegList pinned) {
    DCHECK_NE(0, access_size);
    // For access_size 1 there is no minimum alignment.
    if (access_size == 1) return;
    SCOPED_CODE_COMMENT("alignment check");
    Label* trap_label =
        AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapUnalignedAccess);
    Register address = __ GetUnusedRegister(kGpReg, pinned).gp();

    FREEZE_STATE(trapping);
    const uint32_t align_mask = access_size - 1;
    if ((offset & align_mask) == 0) {
      // If {offset} is aligned, we can produce faster code.

      // TODO(ahaas): On Intel, the "test" instruction implicitly computes the
      // AND of two operands. We could introduce a new variant of
      // {emit_cond_jump} to use the "test" instruction without the "and" here.
      // Then we can also avoid using the temp register here.
      __ emit_i32_andi(address, index, align_mask);
      __ emit_cond_jump(kNotEqual, trap_label, kI32, address, no_reg, trapping);
    } else {
      // For alignment checks we only look at the lower 32-bits in {offset}.
      __ emit_i32_addi(address, index, static_cast<uint32_t>(offset));
      __ emit_i32_andi(address, address, align_mask);
      __ emit_cond_jump(kNotEqual, trap_label, kI32, address, no_reg, trapping);
    }
  }

  void TraceMemoryOperation(bool is_store, MachineRepresentation rep,
                            Register index, uintptr_t offset,
                            WasmCodePosition position) {
    // Before making the runtime call, spill all cache registers.
    __ SpillAllRegisters();

    LiftoffRegList pinned;
    if (index != no_reg) pinned.set(index);
    // Get one register for computing the effective offset (offset + index).
    LiftoffRegister effective_offset =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    // TODO(14259): Support multiple memories.
    const WasmMemory* memory = env_->module->memories.data();
    if (memory->is_memory64() && !kNeedI64RegPair) {
      __ LoadConstant(effective_offset,
                      WasmValue(static_cast<uint64_t>(offset)));
      if (index != no_reg) {
        __ emit_i64_add(effective_offset, effective_offset,
                        LiftoffRegister(index));
      }
    } else {
      // The offset is actually a 32-bits number when 'kNeedI64RegPair'
      // is true, so we just do 32-bits operations on it under memory64.
      DCHECK_GE(kMaxUInt32, offset);
      __ LoadConstant(effective_offset,
                      WasmValue(static_cast<uint32_t>(offset)));
      if (index != no_reg) {
        __ emit_i32_add(effective_offset.gp(), effective_offset.gp(), index);
      }
    }

    // Get a register to hold the stack slot for MemoryTracingInfo.
    LiftoffRegister info = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    // Allocate stack slot for MemoryTracingInfo.
    __ AllocateStackSlot(info.gp(), sizeof(MemoryTracingInfo));

    // Reuse the {effective_offset} register for all information to be stored in
    // the MemoryTracingInfo struct.
    LiftoffRegister data = effective_offset;

    // Now store all information into the MemoryTracingInfo struct.
    if (kSystemPointerSize == 8 && !memory->is_memory64()) {
      // Zero-extend the effective offset to u64.
      CHECK(__ emit_type_conversion(kExprI64UConvertI32, data, effective_offset,
                                    nullptr));
    }
    __ Store(
        info.gp(), no_reg, offsetof(MemoryTracingInfo, offset), data,
        kSystemPointerSize == 8 ? StoreType::kI64Store : StoreType::kI32Store,
        pinned);
    __ LoadConstant(data, WasmValue(is_store ? 1 : 0));
    __ Store(info.gp(), no_reg, offsetof(MemoryTracingInfo, is_store), data,
             StoreType::kI32Store8, pinned);
    __ LoadConstant(data, WasmValue(static_cast<int>(rep)));
    __ Store(info.gp(), no_reg, offsetof(MemoryTracingInfo, mem_rep), data,
             StoreType::kI32Store8, pinned);

    WasmTraceMemoryDescriptor descriptor;
    DCHECK_EQ(0, descriptor.GetStackParameterCount());
    DCHECK_EQ(1, descriptor.GetRegisterParameterCount());
    Register param_reg = descriptor.GetRegisterParameter(0);
    if (info.gp() != param_reg) {
      __ Move(param_reg, info.gp(), kIntPtrKind);
    }

    source_position_table_builder_.AddPosition(__ pc_offset(),
                                               SourcePosition(position), false);
    __ CallBuiltin(Builtin::kWasmTraceMemory);
    DefineSafepoint();

    __ DeallocateStackSlot(sizeof(MemoryTracingInfo));
  }

  bool IndexStaticallyInBounds(const WasmMemory* memory,
                               const VarState& index_slot, int access_size,
                               uintptr_t* offset) {
    if (!index_slot.is_const()) return false;

    // memory64: Sign-extend to restore the original index value.
    // memory32: Zero-extend the 32 bit value.
    const uintptr_t index =
        memory->is_memory64()
            ? static_cast<uintptr_t>(intptr_t{index_slot.i32_const()})
            : uintptr_t{static_cast<uint32_t>(index_slot.i32_const())};
    const uintptr_t effective_offset = index + *offset;

    if (effective_offset < index  // overflow
        || !base::IsInBounds<uintptr_t>(effective_offset, access_size,
                                        memory->min_memory_size)) {
      return false;
    }

    *offset = effective_offset;
    return true;
  }

  bool IndexStaticallyInBoundsAndAligned(const WasmMemory* memory,
                                         const VarState& index_slot,
                                         int access_size, uintptr_t* offset) {
    uintptr_t new_offset = *offset;
    if (IndexStaticallyInBounds(memory, index_slot, access_size, &new_offset) &&
        IsAligned(new_offset, access_size)) {
      *offset = new_offset;
      return true;
    }
    return false;
  }

  V8_INLINE Register GetMemoryStart(int memory_index, LiftoffRegList pinned) {
    if (memory_index == __ cache_state()->cached_mem_index) {
      Register memory_start = __ cache_state()->cached_mem_start;
      DCHECK_NE(no_reg, memory_start);
      return memory_start;
    }
    return GetMemoryStart_Slow(memory_index, pinned);
  }

  V8_NOINLINE V8_PRESERVE_MOST Register
  GetMemoryStart_Slow(int memory_index, LiftoffRegList pinned) {
    // This method should only be called if we cannot use the cached memory
    // start.
    DCHECK_NE(memory_index, __ cache_state()->cached_mem_index);
    __ cache_state()->ClearCachedMemStartRegister();
    SCOPED_CODE_COMMENT("load memory start");
    Register memory_start = __ GetUnusedRegister(kGpReg, pinned).gp();
    if (memory_index == 0) {
      LOAD_INSTANCE_FIELD(memory_start, Memory0Start, kSystemPointerSize,
                          pinned);
    } else {
      LOAD_PROTECTED_PTR_INSTANCE_FIELD(memory_start, MemoryBasesAndSizes,
                                        pinned);
      int buffer_offset = wasm::ObjectAccess::ToTagged(
          TrustedFixedAddressArray::OffsetOfElementAt(memory_index * 2));
      __ LoadFullPointer(memory_start, memory_start, buffer_offset);
    }
    __ cache_state()->SetMemStartCacheRegister(memory_start, memory_index);
    return memory_start;
  }

  void LoadMem(FullDecoder* decoder, LoadType type,
               const MemoryAccessImmediate& imm, const Value& index_val,
               Value* result) {
    DCHECK_EQ(type.value_type().kind(), result->type.kind());
    bool needs_f16_to_f32_conv = false;
    if (type.value() == LoadType::kF32LoadF16 &&
        !asm_.supports_f16_mem_access()) {
      needs_f16_to_f32_conv = true;
      type = LoadType::kI32Load16U;
    }
    ValueKind kind = type.value_type().kind();
    if (!CheckSupportedType(decoder, kind, "load")) return;

    uintptr_t offset = imm.offset;
    Register index = no_reg;
    RegClass rc = reg_class_for(kind);

    // Only look at the slot, do not pop it yet (will happen in PopToRegister
    // below, if this is not a statically-in-bounds index).
    auto& index_slot = __ cache_state()->stack_state.back();
    DCHECK_EQ(index_val.type.kind(), index_slot.kind());
    bool i64_offset = imm.memory->is_memory64();
    DCHECK_EQ(i64_offset ? kI64 : kI32, index_slot.kind());
    if (IndexStaticallyInBounds(imm.memory, index_slot, type.size(), &offset)) {
      __ cache_state()->stack_state.pop_back();
      SCOPED_CODE_COMMENT("load from memory (constant offset)");
      LiftoffRegList pinned;
      Register mem = pinned.set(GetMemoryStart(imm.memory->index, pinned));
      LiftoffRegister value = pinned.set(__ GetUnusedRegister(rc, pinned));
      __ Load(value, mem, no_reg, offset, type, nullptr, true, i64_offset);
      if (needs_f16_to_f32_conv) {
        LiftoffRegister dst = __ GetUnusedRegister(kFpReg, {});
        auto conv_ref = ExternalReference::wasm_float16_to_float32();
        GenerateCCallWithStackBuffer(&dst, kVoid, kF32,
                                     {VarState{kI16, value, 0}}, conv_ref);
        __ PushRegister(kF32, dst);
      } else {
        __ PushRegister(kind, value);
      }
    } else {
      LiftoffRegister full_index = __ PopToRegister();
      index =
          BoundsCheckMem(decoder, imm.memory, type.size(), offset, full_index,
                         {}, kDontForceCheck, kDontCheckAlignment);

      SCOPED_CODE_COMMENT("load from memory");
      LiftoffRegList pinned{index};

      // Load the memory start address only now to reduce register pressure
      // (important on ia32).
      Register mem = pinned.set(GetMemoryStart(imm.memory->index, pinned));
      LiftoffRegister value = pinned.set(__ GetUnusedRegister(rc, pinned));

      uint32_t protected_load_pc = 0;
      __ Load(value, mem, index, offset, type, &protected_load_pc, true,
              i64_offset);
      if (imm.memory->bounds_checks == kTrapHandler) {
        RegisterProtectedInstruction(decoder, protected_load_pc);
      }
      if (needs_f16_to_f32_conv) {
        LiftoffRegister dst = __ GetUnusedRegister(kFpReg, {});
        auto conv_ref = ExternalReference::wasm_float16_to_float32();
        GenerateCCallWithStackBuffer(&dst, kVoid, kF32,
                                     {VarState{kI16, value, 0}}, conv_ref);
        __ PushRegister(kF32, dst);
      } else {
        __ PushRegister(kind, value);
      }
    }

    if (V8_UNLIKELY(v8_flags.trace_wasm_memory)) {
      // TODO(14259): Implement memory tracing for multiple memories.
      CHECK_EQ(0, imm.memory->index);
      TraceMemoryOperation(false, type.mem_type().representation(), index,
                           offset, decoder->position());
    }
  }

  void LoadTransform(FullDecoder* decoder, LoadType type,
                     LoadTransformationKind transform,
                     const MemoryAccessImmediate& imm, const Value& index_val,
                     Value* result) {
    CHECK(CheckSupportedType(decoder, kS128, "LoadTransform"));

    LiftoffRegister full_index = __ PopToRegister();
    // For load splats and load zero, LoadType is the size of the load, and for
    // load extends, LoadType is the size of the lane, and it always loads 8
    // bytes.
    uint32_t access_size =
        transform == LoadTransformationKind::kExtend ? 8 : type.size();
    Register index =
        BoundsCheckMem(decoder, imm.memory, access_size, imm.offset, full_index,
                       {}, kDontForceCheck, kDontCheckAlignment);

    uintptr_t offset = imm.offset;
    LiftoffRegList pinned{index};
    CODE_COMMENT("load with transformation");
    Register addr = GetMemoryStart(imm.mem_index, pinned);
    LiftoffRegister value = __ GetUnusedRegister(reg_class_for(kS128), {});
    uint32_t protected_load_pc = 0;
    __ LoadTransform(value, addr, index, offset, type, transform,
                     &protected_load_pc);

    if (imm.memory->bounds_checks == kTrapHandler) {
      protected_instructions_.emplace_back(
          trap_handler::ProtectedInstructionData{protected_load_pc});
      source_position_table_builder_.AddPosition(
          protected_load_pc, SourcePosition(decoder->position()), true);
      if (for_debugging_) {
        DefineSafepoint(protected_load_pc);
      }
    }
    __ PushRegister(kS128, value);

    if (V8_UNLIKELY(v8_flags.trace_wasm_memory)) {
      // TODO(14259): Implement memory tracing for multiple memories.
      CHECK_EQ(0, imm.memory->index);
      // Again load extend is different.
      MachineRepresentation mem_rep =
          transform == LoadTransformationKind::kExtend
              ? MachineRepresentation::kWord64
              : type.mem_type().representation();
      TraceMemoryOperation(false, mem_rep, index, offset, decoder->position());
    }
  }

  void LoadLane(FullDecoder* decoder, LoadType type, const Value& _value,
                const Value& _index, const MemoryAccessImmediate& imm,
                const uint8_t laneidx, Value* _result) {
    if (!CheckSupportedType(decoder, kS128, "LoadLane")) {
      return;
    }

    LiftoffRegList pinned;
    LiftoffRegister value = pinned.set(__ PopToRegister());
    LiftoffRegister full_index = __ PopToRegister();
    Register index =
        BoundsCheckMem(decoder, imm.memory, type.size(), imm.offset, full_index,
                       pinned, kDontForceCheck, kDontCheckAlignment);

    bool i64_offset = imm.memory->is_memory64();
    DCHECK_EQ(i64_offset ? kI64 : kI32, _index.type.kind());

    uintptr_t offset = imm.offset;
    pinned.set(index);
    CODE_COMMENT("load lane");
    Register addr = GetMemoryStart(imm.mem_index, pinned);
    LiftoffRegister result = __ GetUnusedRegister(reg_class_for(kS128), {});
    uint32_t protected_load_pc = 0;
    __ LoadLane(result, value, addr, index, offset, type, laneidx,
                &protected_load_pc, i64_offset);
    if (imm.memory->bounds_checks == kTrapHandler) {
      protected_instructions_.emplace_back(
          trap_handler::ProtectedInstructionData{protected_load_pc});
      source_position_table_builder_.AddPosition(
          protected_load_pc, SourcePosition(decoder->position()), true);
      if (for_debugging_) {
        DefineSafepoint(protected_load_pc);
      }
    }

    __ PushRegister(kS128, result);

    if (V8_UNLIKELY(v8_flags.trace_wasm_memory)) {
      // TODO(14259): Implement memory tracing for multiple memories.
      CHECK_EQ(0, imm.memory->index);
      TraceMemoryOperation(false, type.mem_type().representation(), index,
                           offset, decoder->position());
    }
  }

  void StoreMem(FullDecoder* decoder, StoreType type,
                const MemoryAccessImmediate& imm, const Value& index_val,
                const Value& value_val) {
    ValueKind kind = type.value_type().kind();
    DCHECK_EQ(kind, value_val.type.kind());
    if (!CheckSupportedType(decoder, kind, "store")) return;

    LiftoffRegList pinned;
    LiftoffRegister value = pinned.set(__ PopToRegister());

    if (type.value() == StoreType::kF32StoreF16 &&
        !asm_.supports_f16_mem_access()) {
      type = StoreType::kI32Store16;
      // {value} is always a float, so can't alias with {i16}.
      DCHECK_EQ(kF32, kind);
      LiftoffRegister i16 = pinned.set(__ GetUnusedRegister(kGpReg, {}));
      auto conv_ref = ExternalReference::wasm_float32_to_float16();
      GenerateCCallWithStackBuffer(&i16, kVoid, kI16,
                                   {VarState{kF32, value, 0}}, conv_ref);
      value = i16;
    }

    uintptr_t offset = imm.offset;
    Register index = no_reg;

    auto& index_slot = __ cache_state()->stack_state.back();
    DCHECK_EQ(index_val.type.kind(), index_slot.kind());
    bool i64_offset = imm.memory->is_memory64();
    DCHECK_EQ(i64_offset ? kI64 : kI32, index_val.type.kind());
    if (IndexStaticallyInBounds(imm.memory, index_slot, type.size(), &offset)) {
      __ cache_state()->stack_state.pop_back();
      SCOPED_CODE_COMMENT("store to memory (constant offset)");
      Register mem = pinned.set(GetMemoryStart(imm.memory->index, pinned));
      __ Store(mem, no_reg, offset, value, type, pinned, nullptr, true,
               i64_offset);
    } else {
      LiftoffRegister full_index = __ PopToRegister(pinned);
      ForceCheck force_check =
          kPartialOOBWritesAreNoops ? kDontForceCheck : kDoForceCheck;
      index =
          BoundsCheckMem(decoder, imm.memory, type.size(), imm.offset,
                         full_index, pinned, force_check, kDontCheckAlignment);

      pinned.set(index);
      SCOPED_CODE_COMMENT("store to memory");
      uint32_t protected_store_pc = 0;
      // Load the memory start address only now to reduce register pressure
      // (important on ia32).
      Register mem = pinned.set(GetMemoryStart(imm.memory->index, pinned));
      LiftoffRegList outer_pinned;
      if (V8_UNLIKELY(v8_flags.trace_wasm_memory)) outer_pinned.set(index);
      __ Store(mem, index, offset, value, type, outer_pinned,
               &protected_store_pc, true, i64_offset);
      if (imm.memory->bounds_checks == kTrapHandler) {
        RegisterProtectedInstruction(decoder, protected_store_pc);
      }
    }

    if (V8_UNLIKELY(v8_flags.trace_wasm_memory)) {
      // TODO(14259): Implement memory tracing for multiple memories.
      CHECK_EQ(0, imm.memory->index);
      TraceMemoryOperation(true, type.mem_rep(), index, offset,
                           decoder->position());
    }
  }

  void StoreLane(FullDecoder* decoder, StoreType type,
                 const MemoryAccessImmediate& imm, const Value& _index,
                 const Value& _value, const uint8_t lane) {
    if (!CheckSupportedType(decoder, kS128, "StoreLane")) return;
    LiftoffRegList pinned;
    LiftoffRegister value = pinned.set(__ PopToRegister());
    LiftoffRegister full_index = __ PopToRegister(pinned);
    ForceCheck force_check =
        kPartialOOBWritesAreNoops ? kDontForceCheck : kDoForceCheck;
    Register index =
        BoundsCheckMem(decoder, imm.memory, type.size(), imm.offset, full_index,
                       pinned, force_check, kDontCheckAlignment);

    bool i64_offset = imm.memory->is_memory64();
    DCHECK_EQ(i64_offset ? kI64 : kI32, _index.type.kind());

    uintptr_t offset = imm.offset;
    pinned.set(index);
    CODE_COMMENT("store lane to memory");
    Register addr = pinned.set(GetMemoryStart(imm.mem_index, pinned));
    uint32_t protected_store_pc = 0;
    __ StoreLane(addr, index, offset, value, type, lane, &protected_store_pc,
                 i64_offset);
    if (imm.memory->bounds_checks == kTrapHandler) {
      protected_instructions_.emplace_back(
          trap_handler::ProtectedInstructionData{protected_store_pc});
      source_position_table_builder_.AddPosition(
          protected_store_pc, SourcePosition(decoder->position()), true);
      if (for_debugging_) {
        DefineSafepoint(protected_store_pc);
      }
    }
    if (V8_UNLIKELY(v8_flags.trace_wasm_memory)) {
      // TODO(14259): Implement memory tracing for multiple memories.
      CHECK_EQ(0, imm.memory->index);
      TraceMemoryOperation(true, type.mem_rep(), index, offset,
                           decoder->position());
    }
  }

  void CurrentMemoryPages(FullDecoder* /* decoder */,
                          const Memo
"""


```