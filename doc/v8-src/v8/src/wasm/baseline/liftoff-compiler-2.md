Response: The user wants a summary of the C++ code in `v8/src/wasm/baseline/liftoff-compiler.cc`, specifically focusing on its functionality and relationship to JavaScript. This is the third of a seven-part summary.

My plan is to:

1. **Identify the core purpose of this code snippet.** Based on the naming conventions (`BrImpl`, `BrIf`, `BrTable`, `LoadMem`, `StoreMem`, `SimdOp`), it appears to be responsible for generating machine code for specific WebAssembly instructions related to control flow (branches) and memory access (loads, stores, SIMD operations).

2. **Explain the general mechanism.** Liftoff is a baseline compiler, meaning it generates relatively simple and fast code. This snippet likely translates Wasm instructions into corresponding machine code instructions.

3. **Find connections to JavaScript.**  WebAssembly is designed to be integrated with JavaScript. The operations in this code snippet directly correspond to actions that can be triggered from JavaScript when running a WebAssembly module.

4. **Provide JavaScript examples.** For the identified connections, I will provide simple JavaScript code that would lead to the execution of the corresponding WebAssembly instructions and thus involve this C++ code.
这个C++代码片段主要负责 **为 WebAssembly 的控制流指令（如 `br`, `br_if`, `br_table`）和内存访问指令（如 `load`, `store`）以及 SIMD 指令生成机器码**。

由于 Liftoff 是一个基线编译器，它会为这些 WebAssembly 指令生成相对简单直接的机器码，目标是快速生成可执行代码。

**它与 JavaScript 的功能有很强的关系**。当 JavaScript 执行一个 WebAssembly 模块时，如果使用的是 Liftoff 编译器，那么执行到相应的 WebAssembly 指令时，就会调用这段 C++ 代码来生成底层的机器码。

以下是一些 JavaScript 例子，说明了这些指令的触发方式：

**1. 控制流指令 (`br`, `br_if`, `br_table`)**

```javascript
// 假设我们有一个 WebAssembly 模块 instance
const instance = ...;
const wasmMemory = new WebAssembly.Memory({ initial: 1 });

// 模块内部的代码可能包含如下的控制流结构

// (func $my_func (local $i i32)
//   (block $my_block
//     (br_if $my_block (i32.ne (local.get $i) (i32.const 10)))
//     (return)
//   )
//   (br 0) ; 跳转到最外层的 block (也就是函数末尾)
// )

// 在 JavaScript 中调用这个函数
instance.exports.my_func(5); // 这可能导致 br_if 指令不满足条件，继续执行
instance.exports.my_func(10); // 这可能导致 br_if 指令满足条件，执行 return
```

在这个例子中，`br_if` 指令会根据条件跳转到 `$my_block` 的开头，或者继续执行 `return` 语句。`br 0` 指令会无条件跳转到函数的末尾。当 JavaScript 调用 `instance.exports.my_func` 时，WebAssembly 虚拟机执行到这些指令时，`liftoff-compiler.cc` 中的 `BrIf` 和 `BrImpl` 等方法会被调用。

**2. 内存访问指令 (`load`, `store`)**

```javascript
// 假设我们有一个 WebAssembly 模块 instance 和 memory
const instance = ...;
const wasmMemory = new WebAssembly.Memory({ initial: 1 });
const buffer = new Uint8Array(wasmMemory.buffer);

// 模块内部的代码可能包含如下的内存访问

// (func $store_value (param $index i32) (param $value i32)
//   (i32.store (local.get $index) (local.get $value))
// )

// (func $load_value (param $index i32) (result i32)
//   (i32.load (local.get $index))
// )

// 在 JavaScript 中调用这些函数来操作 WebAssembly 的内存
instance.exports.store_value(10, 42); // 调用 i32.store， liftoff-compiler.cc 中的 StoreMem 会被调用
console.log(instance.exports.load_value(10)); // 调用 i32.load， liftoff-compiler.cc 中的 LoadMem 会被调用
console.log(buffer[10]); // 可以看到内存已经被修改
```

在这个例子中，`i32.store` 指令会将 `$value` 存储到内存地址 `$index` 处，而 `i32.load` 指令会从内存地址 `$index` 处加载一个 32 位整数。当 JavaScript 调用 `instance.exports.store_value` 和 `instance.exports.load_value` 时，`liftoff-compiler.cc` 中的 `StoreMem` 和 `LoadMem` 方法会被调用，生成相应的机器码来执行内存的读写操作。

**3. SIMD 指令**

```javascript
// 需要启用 SIMD 支持的 WebAssembly 模块
// 模块内部的代码可能包含 SIMD 操作

// (func $add_vectors (param $a v128) (param $b v128) (result v128)
//   (v128.add $a $b)
// )

// 在 JavaScript 中创建 TypedArray 并将其转换为 v128
const a = new Uint32Array([1, 2, 3, 4]);
const b = new Uint32Array([5, 6, 7, 8]);
const a_v128 = new Uint8Array(a.buffer);
const b_v128 = new Uint8Array(b.buffer);

// 调用 WebAssembly 函数
const result_v128 = instance.exports.add_vectors(a_v128, b_v128); // 调用 v128.add， liftoff-compiler.cc 中的 SimdOp 会被调用

// 将结果 v128 转换回 TypedArray
const result_array = new Uint32Array(result_v128.buffer);
console.log(result_array); // 输出 [6, 8, 10, 12]
```

在这个例子中，`v128.add` 指令会将两个 128 位的向量相加。当 JavaScript 调用 `instance.exports.add_vectors` 时，`liftoff-compiler.cc` 中的 `SimdOp` 方法会被调用，为 `v128.add` 指令生成相应的 SIMD 机器码。

总而言之，这个 C++ 代码片段是 WebAssembly 执行引擎的核心组成部分，它负责将高层的 WebAssembly 指令翻译成可以直接在硬件上执行的机器码，从而使得 JavaScript 能够执行 WebAssembly 模块的功能。

Prompt: 
```
这是目录为v8/src/wasm/baseline/liftoff-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共7部分，请归纳一下它的功能

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
                          const MemoryIndexImmediate& imm,
                          Value* /* result */) {
    LiftoffRegList pinned;
    LiftoffRegister mem_size = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    if (imm.memory->index == 0) {
      LOAD_INSTANCE_FIELD(mem_size.gp(), Memory0Size, kSystemPointerSize,
                          pinned);
    } else {
      LOAD_PROTECTED_PTR_INSTANCE_FIELD(mem_size.gp(), MemoryBasesAndSizes,
                                        pinned);
      int buffer_offset =
          wasm::ObjectAccess::ToTagged(OFFSET_OF_DATA_START(ByteArray)) +
          kSystemPointerSize * (imm.memory->index * 2 + 1);
      __ LoadFullPointer(mem_size.gp(), mem_size.gp(), buffer_offset);
    }
    // Convert bytes to pages.
    __ emit_ptrsize_shri(mem_size.gp(), mem_size.gp(), kWasmPageSizeLog2);
    if (imm.memory->is_memory64() && kNeedI64RegPair) {
      LiftoffRegister high_word =
          __ GetUnusedRegister(kGpReg, LiftoffRegList{mem_size});
      // The high word is always 0 on 32-bit systems.
      __ LoadConstant(high_word, WasmValue{uint32_t{0}});
      mem_size = LiftoffRegister::ForPair(mem_size.gp(), high_word.gp());
    }
    __ PushRegister(imm.memory->is_memory64() ? kI64 : kI32, mem_size);
  }

  void MemoryGrow(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                  const Value& value, Value* result_val) {
    // Pop the input, then spill all cache registers to make the runtime call.
    LiftoffRegList pinned;
    LiftoffRegister num_pages = pinned.set(__ PopToRegister());
    __ SpillAllRegisters();

    LiftoffRegister result = pinned.set(__ GetUnusedRegister(kGpReg, pinned));

    Label done;

    if (imm.memory->is_memory64()) {
      // If the high word is not 0, this will always fail (would grow by
      // >=256TB). The int32_t value will be sign-extended below.
      __ LoadConstant(result, WasmValue(int32_t{-1}));
      if (kNeedI64RegPair) {
        FREEZE_STATE(all_spilled_anyway);
        __ emit_cond_jump(kNotEqual, &done, kI32, num_pages.high_gp(), no_reg,
                          all_spilled_anyway);
        num_pages = num_pages.low();
      } else {
        LiftoffRegister high_word = __ GetUnusedRegister(kGpReg, pinned);
        __ emit_i64_shri(high_word, num_pages, 32);
        FREEZE_STATE(all_spilled_anyway);
        __ emit_cond_jump(kNotEqual, &done, kI32, high_word.gp(), no_reg,
                          all_spilled_anyway);
      }
    }

    WasmMemoryGrowDescriptor descriptor;
    DCHECK_EQ(0, descriptor.GetStackParameterCount());
    DCHECK_EQ(2, descriptor.GetRegisterParameterCount());
    DCHECK_EQ(machine_type(kI32), descriptor.GetParameterType(0));
    DCHECK_EQ(machine_type(kI32), descriptor.GetParameterType(1));

    Register num_pages_param_reg = descriptor.GetRegisterParameter(1);
    if (num_pages.gp() != num_pages_param_reg) {
      __ Move(num_pages_param_reg, num_pages.gp(), kI32);
    }

    // Load the constant after potentially moving the {num_pages} register to
    // avoid overwriting it.
    Register mem_index_param_reg = descriptor.GetRegisterParameter(0);
    __ LoadConstant(LiftoffRegister{mem_index_param_reg},
                    WasmValue(imm.memory->index));

    __ CallBuiltin(Builtin::kWasmMemoryGrow);
    DefineSafepoint();
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    if (kReturnRegister0 != result.gp()) {
      __ Move(result.gp(), kReturnRegister0, kI32);
    }

    __ bind(&done);

    if (imm.memory->is_memory64()) {
      LiftoffRegister result64 = result;
      if (kNeedI64RegPair) result64 = __ GetUnusedRegister(kGpRegPair, pinned);
      __ emit_type_conversion(kExprI64SConvertI32, result64, result, nullptr);
      __ PushRegister(kI64, result64);
    } else {
      __ PushRegister(kI32, result);
    }
  }

  base::OwnedVector<ValueType> GetStackValueTypesForDebugging(
      FullDecoder* decoder) {
    DCHECK(for_debugging_);
    auto stack_value_types =
        base::OwnedVector<ValueType>::NewForOverwrite(decoder->stack_size());

    int depth = 0;
    for (ValueType& type : base::Reversed(stack_value_types)) {
      type = decoder->stack_value(++depth)->type;
    }
    return stack_value_types;
  }

  base::OwnedVector<DebugSideTable::Entry::Value>
  GetCurrentDebugSideTableEntries(
      FullDecoder* decoder,
      DebugSideTableBuilder::AssumeSpilling assume_spilling) {
    auto& stack_state = __ cache_state()->stack_state;

#ifdef DEBUG
    // For value types, we use the cached {stack_value_types_for_debugging_}
    // vector (gathered in {NextInstruction}). This still includes call
    // arguments, which Liftoff has already popped at this point. Hence the size
    // of this vector can be larger than the Liftoff stack size. Just ignore
    // that and use the lower part only.
    size_t expected_value_stack_size =
        stack_state.size() - num_exceptions_ - __ num_locals();
    DCHECK_LE(expected_value_stack_size,
              stack_value_types_for_debugging_.size());
#endif

    auto values =
        base::OwnedVector<DebugSideTable::Entry::Value>::NewForOverwrite(
            stack_state.size());

    int index = 0;
    ValueType* stack_value_type_ptr = stack_value_types_for_debugging_.begin();
    // Iterate the operand stack control block by control block, so that we can
    // handle the implicit exception value for try blocks.
    for (int j = decoder->control_depth() - 1; j >= 0; j--) {
      Control* control = decoder->control_at(j);
      Control* next_control = j > 0 ? decoder->control_at(j - 1) : nullptr;
      int end_index = next_control
                          ? next_control->stack_depth + __ num_locals() +
                                next_control->num_exceptions
                          : __ cache_state()->stack_height();
      bool exception_on_stack =
          control->is_try_catch() || control->is_try_catchall();
      for (; index < end_index; ++index) {
        const LiftoffVarState& slot = stack_state[index];
        DebugSideTable::Entry::Value& value = values[index];
        value.module = decoder->module_;
        value.index = index;
        if (exception_on_stack) {
          value.type = ValueType::Ref(HeapType::kAny);
          exception_on_stack = false;
        } else if (index < static_cast<int>(__ num_locals())) {
          value.type = decoder->local_type(index);
        } else {
          DCHECK_LT(stack_value_type_ptr,
                    stack_value_types_for_debugging_.end());
          value.type = *stack_value_type_ptr++;
        }
        DCHECK(CompatibleStackSlotTypes(slot.kind(), value.type.kind()));
        switch (slot.loc()) {
          case kIntConst:
            value.storage = DebugSideTable::Entry::kConstant;
            value.i32_const = slot.i32_const();
            break;
          case kRegister:
            DCHECK_NE(DebugSideTableBuilder::kDidSpill, assume_spilling);
            if (assume_spilling == DebugSideTableBuilder::kAllowRegisters) {
              value.storage = DebugSideTable::Entry::kRegister;
              value.reg_code = slot.reg().liftoff_code();
              break;
            }
            DCHECK_EQ(DebugSideTableBuilder::kAssumeSpilling, assume_spilling);
            [[fallthrough]];
          case kStack:
            value.storage = DebugSideTable::Entry::kStack;
            value.stack_offset = slot.offset();
            break;
        }
      }
    }
    DCHECK_EQ(values.size(), index);
    DCHECK_EQ(
        stack_value_types_for_debugging_.data() + expected_value_stack_size,
        stack_value_type_ptr);
    return values;
  }

  // Call this after emitting a runtime call that can show up in a stack trace
  // (e.g. because it can trap).
  void RegisterDebugSideTableEntry(
      FullDecoder* decoder,
      DebugSideTableBuilder::AssumeSpilling assume_spilling) {
    if (V8_LIKELY(!debug_sidetable_builder_)) return;
    debug_sidetable_builder_->NewEntry(
        __ pc_offset(),
        GetCurrentDebugSideTableEntries(decoder, assume_spilling).as_vector());
  }

  DebugSideTableBuilder::EntryBuilder* RegisterOOLDebugSideTableEntry(
      FullDecoder* decoder) {
    if (V8_LIKELY(!debug_sidetable_builder_)) return nullptr;
    return debug_sidetable_builder_->NewOOLEntry(
        GetCurrentDebugSideTableEntries(decoder,
                                        DebugSideTableBuilder::kAssumeSpilling)
            .as_vector());
  }

  void CallDirect(FullDecoder* decoder, const CallFunctionImmediate& imm,
                  const Value args[], Value[]) {
    CallDirect(decoder, imm, args, nullptr, CallJumpMode::kCall);
  }

  void CallIndirect(FullDecoder* decoder, const Value& index_val,
                    const CallIndirectImmediate& imm, const Value args[],
                    Value returns[]) {
    CallIndirectImpl(decoder, imm, CallJumpMode::kCall);
  }

  void CallRef(FullDecoder* decoder, const Value& func_ref,
               const FunctionSig* sig, const Value args[], Value returns[]) {
    CallRefImpl(decoder, func_ref.type, sig, CallJumpMode::kCall);
  }

  void ReturnCall(FullDecoder* decoder, const CallFunctionImmediate& imm,
                  const Value args[]) {
    TierupCheckOnTailCall(decoder);
    CallDirect(decoder, imm, args, nullptr, CallJumpMode::kTailCall);
  }

  void ReturnCallIndirect(FullDecoder* decoder, const Value& index_val,
                          const CallIndirectImmediate& imm,
                          const Value args[]) {
    TierupCheckOnTailCall(decoder);
    CallIndirectImpl(decoder, imm, CallJumpMode::kTailCall);
  }

  void ReturnCallRef(FullDecoder* decoder, const Value& func_ref,
                     const FunctionSig* sig, const Value args[]) {
    TierupCheckOnTailCall(decoder);
    CallRefImpl(decoder, func_ref.type, sig, CallJumpMode::kTailCall);
  }

  void BrOnNull(FullDecoder* decoder, const Value& ref_object, uint32_t depth,
                bool pass_null_along_branch,
                Value* /* result_on_fallthrough */) {
    // Avoid having sequences of branches do duplicate work.
    if (depth != decoder->control_depth() - 1) {
      __ PrepareForBranch(decoder->control_at(depth)->br_merge()->arity, {});
    }

    Label cont_false;
    LiftoffRegList pinned;
    LiftoffRegister ref =
        pinned.set(pass_null_along_branch ? __ PeekToRegister(0, pinned)
                                          : __ PopToRegister(pinned));
    Register null = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    LoadNullValueForCompare(null, pinned, ref_object.type);
    {
      FREEZE_STATE(frozen);
      __ emit_cond_jump(kNotEqual, &cont_false, ref_object.type.kind(),
                        ref.gp(), null, frozen);
      BrOrRet(decoder, depth);
    }
    __ bind(&cont_false);
    if (!pass_null_along_branch) {
      // We popped the value earlier, must push it back now.
      __ PushRegister(kRef, ref);
    }
  }

  void BrOnNonNull(FullDecoder* decoder, const Value& ref_object,
                   Value* /* result */, uint32_t depth,
                   bool drop_null_on_fallthrough) {
    // Avoid having sequences of branches do duplicate work.
    if (depth != decoder->control_depth() - 1) {
      __ PrepareForBranch(decoder->control_at(depth)->br_merge()->arity, {});
    }

    Label cont_false;
    LiftoffRegList pinned;
    LiftoffRegister ref = pinned.set(__ PeekToRegister(0, pinned));

    Register null = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    LoadNullValueForCompare(null, pinned, ref_object.type);
    {
      FREEZE_STATE(frozen);
      __ emit_cond_jump(kEqual, &cont_false, ref_object.type.kind(), ref.gp(),
                        null, frozen);

      BrOrRet(decoder, depth);
    }
    // Drop the reference if we are not branching.
    if (drop_null_on_fallthrough) __ DropValues(1);
    __ bind(&cont_false);
  }

  template <ValueKind src_kind, ValueKind result_kind,
            ValueKind result_lane_kind = kVoid, typename EmitFn,
            typename... ExtraArgs>
  void EmitTerOp(EmitFn fn, LiftoffRegister dst, LiftoffRegister src1,
                 LiftoffRegister src2, LiftoffRegister src3,
                 ExtraArgs... extra_args) {
    CallEmitFn(fn, dst, src1, src2, src3, extra_args...);
    if (V8_UNLIKELY(nondeterminism_)) {
      LiftoffRegList pinned{dst};
      if (result_kind == ValueKind::kF32 || result_kind == ValueKind::kF64) {
        CheckNan(dst, pinned, result_kind);
      } else if (result_kind == ValueKind::kS128 &&
                 (result_lane_kind == kF32 || result_lane_kind == kF64)) {
        CheckS128Nan(dst, LiftoffRegList{src1, src2, src3, dst},
                     result_lane_kind);
      }
    }
    __ PushRegister(result_kind, dst);
  }

  template <ValueKind src_kind, ValueKind result_kind,
            ValueKind result_lane_kind = kVoid, typename EmitFn>
  void EmitTerOp(EmitFn fn) {
    LiftoffRegister src3 = __ PopToRegister();
    LiftoffRegister src2 = __ PopToRegister(LiftoffRegList{src3});
    LiftoffRegister src1 = __ PopToRegister(LiftoffRegList{src3, src2});
    static constexpr RegClass result_rc = reg_class_for(result_kind);
    // Reusing src1 and src2 will complicate codegen for select for some
    // backend, so we allow only reusing src3 (the mask), and pin src1 and src2.
    // Additionally, only reuse src3 if it does not alias src1/src2,
    // otherwise dst will also alias it src1/src2.
    LiftoffRegister dst =
        (src2 == src3 || src1 == src3)
            ? __ GetUnusedRegister(result_rc, LiftoffRegList{src1, src2})
            : __ GetUnusedRegister(result_rc, {src3},
                                   LiftoffRegList{src1, src2});
    EmitTerOp<src_kind, result_kind, result_lane_kind, EmitFn>(fn, dst, src1,
                                                               src2, src3);
  }

  void EmitRelaxedLaneSelect(int lane_width) {
    DCHECK(lane_width == 8 || lane_width == 32 || lane_width == 64);
#if defined(V8_TARGET_ARCH_IA32) || defined(V8_TARGET_ARCH_X64)
    if (!CpuFeatures::IsSupported(AVX)) {
#if defined(V8_TARGET_ARCH_IA32)
      // On ia32 xmm0 is not a cached register.
      LiftoffRegister mask = LiftoffRegister::from_uncached(xmm0);
#else
      LiftoffRegister mask(xmm0);
#endif
      __ PopToFixedRegister(mask);
      LiftoffRegister src2 = __ PopToModifiableRegister(LiftoffRegList{mask});
      LiftoffRegister src1 = __ PopToRegister(LiftoffRegList{src2, mask});
      EmitTerOp<kS128, kS128>(&LiftoffAssembler::emit_s128_relaxed_laneselect,
                              src2, src1, src2, mask, lane_width);
      return;
    }
#endif
    LiftoffRegList pinned;
    LiftoffRegister mask = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister src2 = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister src1 = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister dst =
        __ GetUnusedRegister(reg_class_for(kS128), {}, pinned);
    EmitTerOp<kS128, kS128>(&LiftoffAssembler::emit_s128_relaxed_laneselect,
                            dst, src1, src2, mask, lane_width);
  }

  template <typename EmitFn, typename EmitFnImm>
  void EmitSimdShiftOp(EmitFn fn, EmitFnImm fnImm) {
    static constexpr RegClass result_rc = reg_class_for(kS128);

    VarState rhs_slot = __ cache_state()->stack_state.back();
    // Check if the RHS is an immediate.
    if (rhs_slot.is_const()) {
      __ cache_state()->stack_state.pop_back();
      int32_t imm = rhs_slot.i32_const();

      LiftoffRegister operand = __ PopToRegister();
      LiftoffRegister dst = __ GetUnusedRegister(result_rc, {operand}, {});

      CallEmitFn(fnImm, dst, operand, imm);
      __ PushRegister(kS128, dst);
    } else {
      LiftoffRegister count = __ PopToRegister();
      LiftoffRegister operand = __ PopToRegister();
      LiftoffRegister dst = __ GetUnusedRegister(result_rc, {operand}, {});

      CallEmitFn(fn, dst, operand, count);
      __ PushRegister(kS128, dst);
    }
  }

  template <ValueKind result_lane_kind>
  void EmitSimdFloatRoundingOpWithCFallback(
      bool (LiftoffAssembler::*emit_fn)(LiftoffRegister, LiftoffRegister),
      ExternalReference (*ext_ref)()) {
    static constexpr RegClass rc = reg_class_for(kS128);
    LiftoffRegister src = __ PopToRegister();
    LiftoffRegister dst = __ GetUnusedRegister(rc, {src}, {});
    if (!(asm_.*emit_fn)(dst, src)) {
      // Return v128 via stack for ARM.
      GenerateCCallWithStackBuffer(&dst, kVoid, kS128,
                                   {VarState{kS128, src, 0}}, ext_ref());
    }
    if (V8_UNLIKELY(nondeterminism_)) {
      LiftoffRegList pinned{dst};
      CheckS128Nan(dst, pinned, result_lane_kind);
    }
    __ PushRegister(kS128, dst);
  }

  template <ValueKind result_lane_kind, bool swap_lhs_rhs = false>
  void EmitSimdFloatBinOpWithCFallback(
      bool (LiftoffAssembler::*emit_fn)(LiftoffRegister, LiftoffRegister,
                                        LiftoffRegister),
      ExternalReference (*ext_ref)()) {
    static constexpr RegClass rc = reg_class_for(kS128);
    LiftoffRegister src2 = __ PopToRegister();
    LiftoffRegister src1 = __ PopToRegister(LiftoffRegList{src2});
    LiftoffRegister dst = __ GetUnusedRegister(rc, {src1, src2}, {});

    if (swap_lhs_rhs) std::swap(src1, src2);

    if (!(asm_.*emit_fn)(dst, src1, src2)) {
      // Return v128 via stack for ARM.
      GenerateCCallWithStackBuffer(
          &dst, kVoid, kS128,
          {VarState{kS128, src1, 0}, VarState{kS128, src2, 0}}, ext_ref());
    }
    if (V8_UNLIKELY(nondeterminism_)) {
      LiftoffRegList pinned{dst};
      CheckS128Nan(dst, pinned, result_lane_kind);
    }
    __ PushRegister(kS128, dst);
  }

  template <ValueKind result_lane_kind, typename EmitFn>
  void EmitSimdFmaOp(EmitFn emit_fn) {
    LiftoffRegList pinned;
    LiftoffRegister src3 = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister src2 = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister src1 = pinned.set(__ PopToRegister(pinned));
    RegClass dst_rc = reg_class_for(kS128);
    LiftoffRegister dst = __ GetUnusedRegister(dst_rc, {});
    (asm_.*emit_fn)(dst, src1, src2, src3);
    if (V8_UNLIKELY(nondeterminism_)) {
      LiftoffRegList pinned{dst};
      CheckS128Nan(dst, pinned, result_lane_kind);
    }
    __ PushRegister(kS128, dst);
  }

  template <ValueKind result_lane_kind, typename EmitFn>
  void EmitSimdFmaOpWithCFallback(EmitFn emit_fn,
                                  ExternalReference (*ext_ref)()) {
    LiftoffRegList pinned;
    LiftoffRegister src3 = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister src2 = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister src1 = pinned.set(__ PopToRegister(pinned));
    static constexpr RegClass dst_rc = reg_class_for(kS128);
    LiftoffRegister dst = __ GetUnusedRegister(dst_rc, {});
    if (!(asm_.*emit_fn)(dst, src1, src2, src3)) {
      // Return v128 via stack for ARM.
      GenerateCCallWithStackBuffer(
          &dst, kVoid, kS128,
          {VarState{kS128, src1, 0}, VarState{kS128, src2, 0},
           VarState{kS128, src3, 0}},
          ext_ref());
    }
    if (V8_UNLIKELY(nondeterminism_)) {
      LiftoffRegList pinned{dst};
      CheckS128Nan(dst, pinned, result_lane_kind);
    }
    __ PushRegister(kS128, dst);
  }

  void SimdOp(FullDecoder* decoder, WasmOpcode opcode, const Value* /* args */,
              Value* /* result */) {
    CHECK(CpuFeatures::SupportsWasmSimd128());
    switch (opcode) {
      case wasm::kExprI8x16Swizzle:
        return EmitI8x16Swizzle(false);
      case wasm::kExprI8x16RelaxedSwizzle:
        return EmitI8x16Swizzle(true);
      case wasm::kExprI8x16Popcnt:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_popcnt);
      case wasm::kExprI8x16Splat:
        return EmitUnOp<kI32, kS128>(&LiftoffAssembler::emit_i8x16_splat);
      case wasm::kExprI16x8Splat:
        return EmitUnOp<kI32, kS128>(&LiftoffAssembler::emit_i16x8_splat);
      case wasm::kExprI32x4Splat:
        return EmitUnOp<kI32, kS128>(&LiftoffAssembler::emit_i32x4_splat);
      case wasm::kExprI64x2Splat:
        return EmitUnOp<kI64, kS128>(&LiftoffAssembler::emit_i64x2_splat);
      case wasm::kExprF16x8Splat: {
        auto emit_with_c_fallback = [this](LiftoffRegister dst,
                                           LiftoffRegister src) {
          if (asm_.emit_f16x8_splat(dst, src)) return;
          LiftoffRegister value = __ GetUnusedRegister(kGpReg, {});
          auto conv_ref = ExternalReference::wasm_float32_to_float16();
          GenerateCCallWithStackBuffer(&value, kVoid, kI16,
                                       {VarState{kF32, src, 0}}, conv_ref);
          __ emit_i16x8_splat(dst, value);
        };
        return EmitUnOp<kF32, kS128>(emit_with_c_fallback);
      }
      case wasm::kExprF32x4Splat:
        return EmitUnOp<kF32, kS128, kF32>(&LiftoffAssembler::emit_f32x4_splat);
      case wasm::kExprF64x2Splat:
        return EmitUnOp<kF64, kS128, kF64>(&LiftoffAssembler::emit_f64x2_splat);
      case wasm::kExprI8x16Eq:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_eq);
      case wasm::kExprI8x16Ne:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_ne);
      case wasm::kExprI8x16LtS:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i8x16_gt_s);
      case wasm::kExprI8x16LtU:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i8x16_gt_u);
      case wasm::kExprI8x16GtS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_gt_s);
      case wasm::kExprI8x16GtU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_gt_u);
      case wasm::kExprI8x16LeS:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i8x16_ge_s);
      case wasm::kExprI8x16LeU:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i8x16_ge_u);
      case wasm::kExprI8x16GeS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_ge_s);
      case wasm::kExprI8x16GeU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_ge_u);
      case wasm::kExprI16x8Eq:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_eq);
      case wasm::kExprI16x8Ne:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_ne);
      case wasm::kExprI16x8LtS:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i16x8_gt_s);
      case wasm::kExprI16x8LtU:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i16x8_gt_u);
      case wasm::kExprI16x8GtS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_gt_s);
      case wasm::kExprI16x8GtU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_gt_u);
      case wasm::kExprI16x8LeS:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i16x8_ge_s);
      case wasm::kExprI16x8LeU:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i16x8_ge_u);
      case wasm::kExprI16x8GeS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_ge_s);
      case wasm::kExprI16x8GeU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_ge_u);
      case wasm::kExprI32x4Eq:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_eq);
      case wasm::kExprI32x4Ne:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_ne);
      case wasm::kExprI32x4LtS:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i32x4_gt_s);
      case wasm::kExprI32x4LtU:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i32x4_gt_u);
      case wasm::kExprI32x4GtS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_gt_s);
      case wasm::kExprI32x4GtU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_gt_u);
      case wasm::kExprI32x4LeS:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i32x4_ge_s);
      case wasm::kExprI32x4LeU:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i32x4_ge_u);
      case wasm::kExprI32x4GeS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_ge_s);
      case wasm::kExprI32x4GeU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_ge_u);
      case wasm::kExprI64x2Eq:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i64x2_eq);
      case wasm::kExprI64x2Ne:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i64x2_ne);
      case wasm::kExprI64x2LtS:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i64x2_gt_s);
      case wasm::kExprI64x2GtS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i64x2_gt_s);
      case wasm::kExprI64x2LeS:
        return EmitBinOp<kS128, kS128, true>(
            &LiftoffAssembler::emit_i64x2_ge_s);
      case wasm::kExprI64x2GeS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i64x2_ge_s);
      case wasm::kExprF16x8Eq:
        return EmitSimdFloatBinOpWithCFallback<kI16>(
            &LiftoffAssembler::emit_f16x8_eq, ExternalReference::wasm_f16x8_eq);
      case wasm::kExprF16x8Ne:
        return EmitSimdFloatBinOpWithCFallback<kI16>(
            &LiftoffAssembler::emit_f16x8_ne, ExternalReference::wasm_f16x8_ne);
      case wasm::kExprF16x8Lt:
        return EmitSimdFloatBinOpWithCFallback<kI16>(
            &LiftoffAssembler::emit_f16x8_lt, ExternalReference::wasm_f16x8_lt);
      case wasm::kExprF16x8Gt:
        return EmitSimdFloatBinOpWithCFallback<kI16, true>(
            &LiftoffAssembler::emit_f16x8_lt, ExternalReference::wasm_f16x8_lt);
      case wasm::kExprF16x8Le:
        return EmitSimdFloatBinOpWithCFallback<kI16>(
            &LiftoffAssembler::emit_f16x8_le, ExternalReference::wasm_f16x8_le);
      case wasm::kExprF16x8Ge:
        return EmitSimdFloatBinOpWithCFallback<kI16, true>(
            &LiftoffAssembler::emit_f16x8_le, ExternalReference::wasm_f16x8_le);
      case wasm::kExprF32x4Eq:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_f32x4_eq);
      case wasm::kExprF32x4Ne:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_f32x4_ne);
      case wasm::kExprF32x4Lt:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_f32x4_lt);
      case wasm::kExprF32x4Gt:
        return EmitBinOp<kS128, kS128, true>(&LiftoffAssembler::emit_f32x4_lt);
      case wasm::kExprF32x4Le:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_f32x4_le);
      case wasm::kExprF32x4Ge:
        return EmitBinOp<kS128, kS128, true>(&LiftoffAssembler::emit_f32x4_le);
      case wasm::kExprF64x2Eq:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_f64x2_eq);
      case wasm::kExprF64x2Ne:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_f64x2_ne);
      case wasm::kExprF64x2Lt:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_f64x2_lt);
      case wasm::kExprF64x2Gt:
        return EmitBinOp<kS128, kS128, true>(&LiftoffAssembler::emit_f64x2_lt);
      case wasm::kExprF64x2Le:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_f64x2_le);
      case wasm::kExprF64x2Ge:
        return EmitBinOp<kS128, kS128, true>(&LiftoffAssembler::emit_f64x2_le);
      case wasm::kExprS128Not:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_s128_not);
      case wasm::kExprS128And:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_s128_and);
      case wasm::kExprS128Or:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_s128_or);
      case wasm::kExprS128Xor:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_s128_xor);
      case wasm::kExprS128Select:
        return EmitTerOp<kS128, kS128>(&LiftoffAssembler::emit_s128_select);
      case wasm::kExprI8x16Neg:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_neg);
      case wasm::kExprV128AnyTrue:
        return EmitUnOp<kS128, kI32>(&LiftoffAssembler::emit_v128_anytrue);
      case wasm::kExprI8x16AllTrue:
        return EmitUnOp<kS128, kI32>(&LiftoffAssembler::emit_i8x16_alltrue);
      case wasm::kExprI8x16BitMask:
        return EmitUnOp<kS128, kI32>(&LiftoffAssembler::emit_i8x16_bitmask);
      case wasm::kExprI8x16Shl:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i8x16_shl,
                               &LiftoffAssembler::emit_i8x16_shli);
      case wasm::kExprI8x16ShrS:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i8x16_shr_s,
                               &LiftoffAssembler::emit_i8x16_shri_s);
      case wasm::kExprI8x16ShrU:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i8x16_shr_u,
                               &LiftoffAssembler::emit_i8x16_shri_u);
      case wasm::kExprI8x16Add:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_add);
      case wasm::kExprI8x16AddSatS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_add_sat_s);
      case wasm::kExprI8x16AddSatU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_add_sat_u);
      case wasm::kExprI8x16Sub:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_sub);
      case wasm::kExprI8x16SubSatS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_sub_sat_s);
      case wasm::kExprI8x16SubSatU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_sub_sat_u);
      case wasm::kExprI8x16MinS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_min_s);
      case wasm::kExprI8x16MinU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_min_u);
      case wasm::kExprI8x16MaxS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_max_s);
      case wasm::kExprI8x16MaxU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_max_u);
      case wasm::kExprI16x8Neg:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_neg);
      case wasm::kExprI16x8AllTrue:
        return EmitUnOp<kS128, kI32>(&LiftoffAssembler::emit_i16x8_alltrue);
      case wasm::kExprI16x8BitMask:
        return EmitUnOp<kS128, kI32>(&LiftoffAssembler::emit_i16x8_bitmask);
      case wasm::kExprI16x8Shl:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i16x8_shl,
                               &LiftoffAssembler::emit_i16x8_shli);
      case wasm::kExprI16x8ShrS:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i16x8_shr_s,
                               &LiftoffAssembler::emit_i16x8_shri_s);
      case wasm::kExprI16x8ShrU:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i16x8_shr_u,
                               &LiftoffAssembler::emit_i16x8_shri_u);
      case wasm::kExprI16x8Add:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_add);
      case wasm::kExprI16x8AddSatS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_add_sat_s);
      case wasm::kExprI16x8AddSatU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_add_sat_u);
      case wasm::kExprI16x8Sub:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_sub);
      case wasm::kExprI16x8SubSatS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_sub_sat_s);
      case wasm::kExprI16x8SubSatU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_sub_sat_u);
      case wasm::kExprI16x8Mul:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_mul);
      case wasm::kExprI16x8MinS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_min_s);
      case wasm::kExprI16x8MinU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_min_u);
      case wasm::kExprI16x8MaxS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_max_s);
      case wasm::kExprI16x8MaxU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_max_u);
      case wasm::kExprI16x8ExtAddPairwiseI8x16S:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_extadd_pairwise_i8x16_s);
      case wasm::kExprI16x8ExtAddPairwiseI8x16U:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_extadd_pairwise_i8x16_u);
      case wasm::kExprI16x8ExtMulLowI8x16S:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_extmul_low_i8x16_s);
      case wasm::kExprI16x8ExtMulLowI8x16U:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_extmul_low_i8x16_u);
      case wasm::kExprI16x8ExtMulHighI8x16S:
        return EmitB
"""


```