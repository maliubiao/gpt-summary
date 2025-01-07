Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/wasm-compiler.cc`.

Here's a breakdown of how to approach this:

1. **Identify the Class:** The code is part of the `WasmGraphBuilder` class. This immediately suggests it's involved in building a graph representation of WebAssembly code.

2. **Analyze Method Names:**  The method names are very descriptive and provide clues about their purpose. Look for patterns and groupings. For example, methods starting with `BuildI32`, `BuildI64` likely deal with integer operations. Methods with `Call`, `ReturnCall` are related to function calls.

3. **Examine Key Operations:**  Focus on the core actions performed within the methods. Are they performing arithmetic, comparisons, memory access, control flow manipulations (branches, merges)?

4. **Look for External Dependencies:**  The code interacts with `mcgraph()` (likely a `MachineGraphBuilder`), `gasm_` (likely a `CodeAssembler`), and uses concepts like `Node`, `MachineRepresentation`, `MachineType`, `ExternalReference`, `TrapReason`, `CallDescriptor`. These hint at the underlying graph representation and low-level code generation aspects.

5. **Connect to WebAssembly Concepts:**  Relate the methods and operations to standard WebAssembly instructions and features (e.g., `i32.div_s`, `i64.rem_u`, function calls, table calls, memory access).

6. **Address Specific User Queries:**
    * **Torque:** Check the file extension.
    * **JavaScript Relationship:** Look for operations that have direct counterparts in JavaScript or influence how JavaScript interacts with WebAssembly.
    * **Logic Inference:** Identify methods that perform conditional logic or calculations and describe potential inputs and outputs.
    * **Common Errors:** Consider potential issues related to the operations performed, such as division by zero or out-of-bounds access.
    * **Part of a Larger Whole:** Recognize that this is one component of a larger compilation pipeline.

7. **Structure the Summary:** Organize the findings logically, grouping related functionalities together. Start with a high-level overview and then delve into more specific details.

**Self-Correction/Refinement during thought process:**

* Initially, I might focus too much on individual low-level operations. It's important to step back and see the bigger picture – this code is about translating WebAssembly semantics into a lower-level graph representation.
*  I need to be careful not to make assumptions about the exact implementation details of `mcgraph()` and `gasm_` without more context. Focus on the observable behavior.
* When providing JavaScript examples, ensure they illustrate the *high-level* functionality and not necessarily the exact low-level implementation.
*  For logic inference, keep the examples simple and focused on demonstrating the conditional behavior.
* When discussing common errors, relate them to typical programming mistakes that could lead to the specific WebAssembly traps or behaviors being handled in the code.

By following this process, I can create a comprehensive and accurate summary of the `wasm-compiler.cc` code snippet.
```cpp
ght, Int32Constant(0)), BranchHint::kFalse);
  z.Chain(control());

  return z.Phi(MachineRepresentation::kWord32, Int32Constant(0),
               graph()->NewNode(mcgraph()->machine()->Uint32Div(), left, right,
                                z.if_false));
}

Node* WasmGraphBuilder::BuildI32AsmjsRemU(Node* left, Node* right) {
  // asm.js semantics return 0 on divide or mod by zero.
  // Explicit check for x % 0.
  Diamond z(graph(), mcgraph()->common(),
            gasm_->Word32Equal(right, Int32Constant(0)), BranchHint::kFalse);
  z.Chain(control());

  Node* rem = graph()->NewNode(mcgraph()->machine()->Uint32Mod(), left, right,
                               z.if_false);
  return z.Phi(MachineRepresentation::kWord32, Int32Constant(0), rem);
}

Node* WasmGraphBuilder::BuildI64DivS(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  if (mcgraph()->machine()->Is32()) {
    return BuildDiv64Call(left, right, ExternalReference::wasm_int64_div(),
                          MachineType::Int64(), wasm::kTrapDivByZero, position);
  }
  ZeroCheck64(wasm::kTrapDivByZero, right, position);
  Node* previous_effect = effect();
  auto [denom_is_m1, denom_is_not_m1] =
      BranchExpectFalse(gasm_->Word64Equal(right, Int64Constant(-1)));
  SetControl(denom_is_m1);
  TrapIfEq64(wasm::kTrapDivUnrepresentable, left,
             std::numeric_limits<int64_t>::min(), position);
  Node* merge = Merge(control(), denom_is_not_m1);
  SetEffectControl(graph()->NewNode(mcgraph()->common()->EffectPhi(2), effect(),
                                    previous_effect, merge),
                   merge);
  return gasm_->Int64Div(left, right);
}

Node* WasmGraphBuilder::BuildI64RemS(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  if (mcgraph()->machine()->Is32()) {
    return BuildDiv64Call(left, right, ExternalReference::wasm_int64_mod(),
                          MachineType::Int64(), wasm::kTrapRemByZero, position);
  }
  ZeroCheck64(wasm::kTrapRemByZero, right, position);
  Diamond d(mcgraph()->graph(), mcgraph()->common(),
            gasm_->Word64Equal(right, Int64Constant(-1)));

  d.Chain(control());

  Node* rem = graph()->NewNode(mcgraph()->machine()->Int64Mod(), left, right,
                               d.if_false);

  return d.Phi(MachineRepresentation::kWord64, Int64Constant(0), rem);
}

Node* WasmGraphBuilder::BuildI64DivU(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  if (mcgraph()->machine()->Is32()) {
    return BuildDiv64Call(left, right, ExternalReference::wasm_uint64_div(),
                          MachineType::Int64(), wasm::kTrapDivByZero, position);
  }
  ZeroCheck64(wasm::kTrapDivByZero, right, position);
  return gasm_->Uint64Div(left, right);
}
Node* WasmGraphBuilder::BuildI64RemU(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  if (mcgraph()->machine()->Is32()) {
    return BuildDiv64Call(left, right, ExternalReference::wasm_uint64_mod(),
                          MachineType::Int64(), wasm::kTrapRemByZero, position);
  }
  ZeroCheck64(wasm::kTrapRemByZero, right, position);
  return gasm_->Uint64Mod(left, right);
}

Node* WasmGraphBuilder::BuildDiv64Call(Node* left, Node* right,
                                       ExternalReference ref,
                                       MachineType result_type,
                                       wasm::TrapReason trap_zero,
                                       wasm::WasmCodePosition position) {
  Node* stack_slot =
      StoreArgsInStackSlot({{MachineRepresentation::kWord64, left},
                            {MachineRepresentation::kWord64, right}});

  MachineType sig_types[] = {MachineType::Int32(), MachineType::Pointer()};
  MachineSignature sig(1, 1, sig_types);

  Node* function = gasm_->ExternalConstant(ref);
  Node* call = BuildCCall(&sig, function, stack_slot);

  ZeroCheck32(trap_zero, call, position);
  TrapIfEq32(wasm::kTrapDivUnrepresentable, call, -1, position);
  return gasm_->Load(result_type, stack_slot, 0);
}

Node* WasmGraphBuilder::IsNull(Node* object, wasm::ValueType type) {
  // This version is for Wasm functions (i.e. not wrappers):
  // - they use module-specific types
  // - they go through a lowering phase later
  // Both points are different in wrappers, see
  // WasmWrapperGraphBuilder::IsNull().
  DCHECK_EQ(parameter_mode_, kInstanceParameterMode);
  return gasm_->IsNull(object, type);
}

template <typename... Args>
Node* WasmGraphBuilder::BuildCCall(MachineSignature* sig, Node* function,
                                   Args... args) {
  DCHECK_LE(sig->return_count(), 1);
  DCHECK_EQ(sizeof...(args), sig->parameter_count());
  Node* call_args[] = {function, args..., effect(), control()};

  auto call_descriptor =
      Linkage::GetSimplifiedCDescriptor(mcgraph()->zone(), sig);

  return gasm_->Call(call_descriptor, arraysize(call_args), call_args);
}

Node* WasmGraphBuilder::BuildCallNode(size_t param_count,
                                      base::Vector<Node*> args,
                                      wasm::WasmCodePosition position,
                                      Node* implicit_first_arg,
                                      const Operator* op, Node* frame_state) {
  needs_stack_check_ = true;
  const size_t has_frame_state = frame_state != nullptr ? 1 : 0;
  const size_t extra = 3;  // instance_node, effect, and control.
  const size_t count = 1 + param_count + extra + has_frame_state;

  // Reallocate the buffer to make space for extra inputs.
  base::SmallVector<Node*, 16 + extra> inputs(count);
  DCHECK_EQ(1 + param_count, args.size());

  // Make room for the first argument at index 1, just after code.
  inputs[0] = args[0];  // code
  inputs[1] = implicit_first_arg;
  if (param_count > 0) {
    memcpy(&inputs[2], &args[1], param_count * sizeof(Node*));
  }

  // Add effect and control inputs.
  if (has_frame_state != 0) inputs[param_count + 2] = frame_state;
  inputs[param_count + has_frame_state + 2] = effect();
  inputs[param_count + has_frame_state + 3] = control();

  Node* call = graph()->NewNode(op, static_cast<int>(count), inputs.begin());
  // Return calls have no effect output. Other calls are the new effect node.
  if (op->EffectOutputCount() > 0) SetEffect(call);
  DCHECK(position == wasm::kNoCodePosition || position > 0);
  if (position > 0) SetSourcePosition(call, position);

  return call;
}

template <typename T>
Node* WasmGraphBuilder::BuildWasmCall(const Signature<T>* sig,
                                      base::Vector<Node*> args,
                                      base::Vector<Node*> rets,
                                      wasm::WasmCodePosition position,
                                      Node* implicit_first_arg,
                                      Node* frame_state) {
  CallDescriptor* call_descriptor = GetWasmCallDescriptor(
      mcgraph()->zone(), sig, kWasmFunction, frame_state != nullptr);
  const Operator* op = mcgraph()->common()->Call(call_descriptor);
  Node* call = BuildCallNode(sig->parameter_count(), args, position,
                             implicit_first_arg, op, frame_state);
  // TODO(manoskouk): These assume the call has control and effect outputs.
  DCHECK_GT(op->ControlOutputCount(), 0);
  DCHECK_GT(op->EffectOutputCount(), 0);
  SetEffectControl(call);

  size_t ret_count = sig->return_count();
  if (ret_count == 0) return call;  // No return value.

  DCHECK_EQ(ret_count, rets.size());
  if (ret_count == 1) {
    // Only a single return value.
    rets[0] = call;
  } else {
    // Create projections for all return values.
    for (size_t i = 0; i < ret_count; i++) {
      rets[i] = graph()->NewNode(mcgraph()->common()->Projection(i), call,
                                 graph()->start());
    }
  }
  return call;
}

Node* WasmGraphBuilder::BuildWasmReturnCall(const wasm::FunctionSig* sig,
                                            base::Vector<Node*> args,
                                            wasm::WasmCodePosition position,
                                            Node* implicit_first_arg) {
  CallDescriptor* call_descriptor =
      GetWasmCallDescriptor(mcgraph()->zone(), sig);
  const Operator* op = mcgraph()->common()->TailCall(call_descriptor);
  Node* call = BuildCallNode(sig->parameter_count(), args, position,
                             implicit_first_arg, op);

  // TODO(manoskouk): If we have kNoThrow calls, do not merge them to end.
  DCHECK_GT(call->op()->ControlOutputCount(), 0);
  gasm_->MergeControlToEnd(call);

  return call;
}

Node* WasmGraphBuilder::BuildImportCall(const wasm::FunctionSig* sig,
                                        base::Vector<Node*> args,
                                        base::Vector<Node*> rets,
                                        wasm::WasmCodePosition position,
                                        int func_index,
                                        IsReturnCall continuation) {
  return BuildImportCall(sig, args, rets, position,
                         gasm_->Uint32Constant(func_index), continuation);
}

Node* WasmGraphBuilder::BuildImportCall(
    const wasm::FunctionSig* sig, base::Vector<Node*> args,
    base::Vector<Node*> rets, wasm::WasmCodePosition position, Node* func_index,
    IsReturnCall continuation, Node* frame_state) {
  // Load the imported function refs array from the instance.
  Node* dispatch_table =
      LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(DispatchTableForImports);
  // Access fixed array at {header_size - tag + func_index * kTaggedSize}.
  Node* func_index_intptr = gasm_->BuildChangeUint32ToUintPtr(func_index);
  Node* dispatch_table_entry_offset = gasm_->IntMul(
      func_index_intptr, gasm_->IntPtrConstant(WasmDispatchTable::kEntrySize));
  Node* implicit_arg = gasm_->LoadProtectedPointerFromObject(
      dispatch_table,
      gasm_->IntAdd(dispatch_table_entry_offset,
                    gasm_->IntPtrConstant(wasm::ObjectAccess::ToTagged(
                        WasmDispatchTable::kEntriesOffset +
                        WasmDispatchTable::kImplicitArgBias))));

  Node* target = gasm_->LoadFromObject(
      MachineType::WasmCodePointer(), dispatch_table,
      gasm_->IntAdd(dispatch_table_entry_offset,
                    gasm_->IntPtrConstant(wasm::ObjectAccess::ToTagged(
                        WasmDispatchTable::kEntriesOffset +
                        WasmDispatchTable::kTargetBias))));

  args[0] = target;

  switch (continuation) {
    case kCallContinues:
      return BuildWasmCall(sig, args, rets, position, implicit_arg,
                           frame_state);
    case kReturnCall:
      DCHECK(rets.empty());
      return BuildWasmReturnCall(sig, args, position, implicit_arg);
  }
}

Node* WasmGraphBuilder::CallDirect(uint32_t index, base::Vector<Node*> args,
                                   base::Vector<Node*> rets,
                                   wasm::WasmCodePosition position) {
  DCHECK_NULL(args[0]);
  const wasm::FunctionSig* sig = env_->module->functions[index].sig;

  if (env_ && index < env_->module->num_imported_functions) {
    // Call to an imported function.
    return BuildImportCall(sig, args, rets, position, index, kCallContinues);
  }

  // A direct call to a wasm function defined in this module.
  // Just encode the function index. This will be patched at instantiation.
  Address code = static_cast<Address>(index);
  args[0] = mcgraph()->RelocatableIntPtrConstant(code, RelocInfo::WASM_CALL);

  return BuildWasmCall(sig, args, rets, position, GetInstanceData());
}

Node* WasmGraphBuilder::CallIndirect(uint32_t table_index,
                                     wasm::ModuleTypeIndex sig_index,
                                     base::Vector<Node*> args,
                                     base::Vector<Node*> rets,
                                     wasm::WasmCodePosition position) {
  return BuildIndirectCall(table_index, sig_index, args, rets, position,
                           kCallContinues);
}

Node* WasmGraphBuilder::BuildIndirectCall(uint32_t table_index,
                                          wasm::ModuleTypeIndex sig_index,
                                          base::Vector<Node*> args,
                                          base::Vector<Node*> rets,
                                          wasm::WasmCodePosition position,
                                          IsReturnCall continuation) {
  DCHECK_NOT_NULL(args[0]);
  DCHECK_NOT_NULL(env_);

  // Load the dispatch table.
  Node* dispatch_table;
  if (table_index == 0) {
    dispatch_table = LOAD_PROTECTED_INSTANCE_FIELD(DispatchTable0);
  } else {
    Node* dispatch_tables =
        LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(DispatchTables);
    dispatch_table = gasm_->LoadProtectedPointerFromObject(
        dispatch_tables,
        wasm::ObjectAccess::ToTagged(
            ProtectedFixedArray::OffsetOfElementAt(table_index)));
  }

  // Bounds check the index.
  Node* index = args[0];
  const wasm::WasmTable& table = env_->module->tables[table_index];
  TableTypeToUintPtrOrOOBTrap(table.address_type, {&index}, position);
  const bool needs_dynamic_size =
      !table.has_maximum_size || table.maximum_size != table.initial_size;
  Node* table_size =
      needs_dynamic_size
          ? gasm_->LoadFromObject(
                MachineType::Int32(), dispatch_table,
                wasm::ObjectAccess::ToTagged(WasmDispatchTable::kLengthOffset))
          : Int32Constant(table.initial_size);
  Node* in_bounds = Is64() ? gasm_->Uint64LessThan(
                                 index, gasm_->ChangeUint32ToUint64(table_size))
                           : gasm_->Uint32LessThan(index, table_size);
  TrapIfFalse(wasm::kTrapTableOutOfBounds, in_bounds, position);

  wasm::ValueType table_type = env_->module->tables[table_index].type;
  bool needs_type_check = !wasm::EquivalentTypes(
      table_type.AsNonNull(), wasm::ValueType::Ref(sig_index), env_->module,
      env_->module);
  bool needs_null_check = table_type.is_nullable();

  Node* dispatch_table_entry_offset = gasm_->IntAdd(
      gasm_->IntPtrConstant(
          wasm::ObjectAccess::ToTagged(WasmDispatchTable::kEntriesOffset)),
      gasm_->IntMul(index,
                    gasm_->IntPtrConstant(WasmDispatchTable::kEntrySize)));

  // Skip check if table type matches declared signature.
  if (needs_type_check) {
    // Embed the expected signature ID as a relocatable constant.
    wasm::CanonicalTypeIndex canonical_sig_id =
        env_->module->canonical_sig_id(sig_index);
    Node* expected_sig_id = mcgraph()->RelocatableInt32Constant(
        canonical_sig_id.index, RelocInfo::WASM_CANONICAL_SIG_ID);

    Node* loaded_sig = gasm_->LoadFromObject(
        MachineType::Int32(), dispatch_table,
        gasm_->IntAdd(dispatch_table_entry_offset,
                      gasm_->IntPtrConstant(WasmDispatchTable::kSigBias)));
    Node* sig_match = gasm_->Word32Equal(loaded_sig, expected_sig_id);

    if (!env_->module->type(sig_index).is_final) {
      // Do a full subtyping check.
      auto end_label = gasm_->MakeLabel();
      gasm_->GotoIf(sig_match, &end_label);

      // Trap on null element.
      if (needs_null_check) {
        TrapIfTrue(wasm::kTrapFuncSigMismatch,
                   gasm_->Word32Equal(loaded_sig, Int32Constant(-1)), position);
      }

      Node* formal_rtt = RttCanon(sig_index);
      int rtt_depth = wasm::GetSubtypingDepth(env_->module, sig_index);
      DCHECK_GE(rtt_depth, 0);

      // Since we have the canonical index of the real rtt, we have to load it
      // from the isolate rtt-array (which is canonically indexed). Since this
      // reference is weak, we have to promote it to a strong reference.
      // Note: The reference cannot have been cleared: Since the loaded_sig
      // corresponds to a function of the same canonical type, that function
      // will have kept the type alive.
      Node* rtts = LOAD_MUTABLE_ROOT(WasmCanonicalRtts, wasm_canonical_rtts);
      Node* real_rtt =
          gasm_->WordAnd(gasm_->LoadWeakFixedArrayElement(rtts, loaded_sig),
                         gasm_->IntPtrConstant(~kWeakHeapObjectMask));
      Node* type_info = gasm_->LoadWasmTypeInfo(real_rtt);

      // If the depth of the rtt is known to be less than the minimum supertype
      // array length, we can access the supertype without bounds-checking the
      // supertype array.
      if (static_cast<uint32_t>(rtt_depth) >=
          wasm::kMinimumSupertypeArraySize) {
        Node* supertypes_length =
            gasm_->BuildChangeSmiToIntPtr(gasm_->LoadImmutableFromObject(
                MachineType::TaggedSigned(), type_info,
                wasm::ObjectAccess::ToTagged(
                    WasmTypeInfo::kSupertypesLengthOffset)));
        TrapIfFalse(wasm::kTrapFuncSigMismatch,
                    gasm_->UintLessThan(gasm_->IntPtrConstant(rtt_depth),
                                        supertypes_length),
                    position);
      }

      Node* maybe_match = gasm_->LoadImmutableFromObject(
          MachineType::TaggedPointer(), type_info,
          wasm::ObjectAccess::ToTagged(WasmTypeInfo::kSupertypesOffset +
                                       kTaggedSize * rtt_depth));
      TrapIfFalse(wasm::kTrapFuncSigMismatch,
                  gasm_->TaggedEqual(maybe_match, formal_rtt), position);
      gasm_->Goto(&end_label);

      gasm_->Bind(&end_label);
    } else {
      // In absence of subtyping, we just need to check for type equality.
      TrapIfFalse(wasm::kTrapFuncSigMismatch, sig_match, position);
    }
  } else if (needs_null_check) {
    Node* loaded_sig = gasm_->LoadFromObject(
        MachineType::Int32(), dispatch_table,
        gasm_->IntAdd(dispatch_table_entry_offset,
                      gasm_->IntPtrConstant(WasmDispatchTable::kSigBias)));
    TrapIfTrue(wasm::kTrapFuncSigMismatch,
               gasm_->Word32Equal(loaded_sig, Int32Constant(-1)), position);
  }

  Node* implicit_arg = gasm_->LoadProtectedPointerFromObject(
      dispatch_table, gasm_->IntAdd(dispatch_table_entry_offset,
                                    gasm_->IntPtrConstant(
                                        WasmDispatchTable::kImplicitArgBias)));

  Node* target = gasm_->LoadFromObject(
      MachineType::WasmCodePointer(), dispatch_table,
      gasm_->IntAdd(dispatch_table_entry_offset,
                    gasm_->IntPtrConstant(WasmDispatchTable::kTargetBias)));
  args[0] = target;

  const wasm::FunctionSig* sig = env_->module->signature(sig_index);

  switch (continuation) {
    case kCallContinues:
      return BuildWasmCall(sig, args, rets, position, implicit_arg);
    case kReturnCall:
      return BuildWasmReturnCall(sig, args, position, implicit_arg);
  }
}

Node* WasmGraphBuilder::BuildLoadCallTargetFromExportedFunctionData(
    Node* function_data) {
  Node* internal = gasm_->LoadProtectedPointerFromObject(
      function_data, wasm::ObjectAccess::ToTagged(
                         WasmExportedFunctionData::kProtectedInternalOffset));
  return gasm_->LoadFromObject(
      MachineType::WasmCodePointer(), internal,
      wasm::ObjectAccess::ToTagged(WasmInternalFunction::kCallTargetOffset));
}

// TODO(9495): Support CAPI function refs.
Node* WasmGraphBuilder::BuildCallRef(const wasm::FunctionSig* sig,
                                     base::Vector<Node*> args,
                                     base::Vector<Node*> rets,
                                     CheckForNull null_check,
                                     IsReturnCall continuation,
                                     wasm::WasmCodePosition position) {
  Node* func_ref = args[0];
  if (null_check == kWithNullCheck &&
      null_check_strategy_ == NullCheckStrategy::kExplicit) {
    func_ref =
        AssertNotNull(func_ref, wasm::kWasmFuncRef /* good enough */, position);
  }

  Node* internal_function;
  if (null_check == kWithNullCheck &&
      null_check_strategy_ == NullCheckStrategy::kTrapHandler) {
    // TODO(14564): Move WasmInternalFunction to trusted space and make
    // this a load of a trusted (immutable) pointer.
    Node* load;
    std::tie(load, internal_function) =
        gasm_->LoadTrustedPointerFromObjectTrapOnNull(
            func_ref,
            wasm::ObjectAccess::ToTagged(WasmFuncRef::kTrustedInternalOffset),
            kWasmInternalFunctionIndirectPointerTag);
    SetSourcePosition(load, position);
  } else {
    internal_function = gasm_->LoadTrustedPointerFromObject(
        func_ref,
        wasm::ObjectAccess::ToTagged(WasmFuncRef::kTrustedInternalOffset),
        kWasmInternalFunctionIndirectPointerTag);
  }

  Node* implicit_arg = gasm_->LoadImmutableProtectedPointerFromObject(
      internal_function,
      wasm::ObjectAccess::ToTagged(
          WasmInternalFunction::kProtectedImplicitArgOffset));
  Node* target = gasm_->LoadFromObject(
      MachineType::WasmCodePointer(), internal_function,
      wasm::ObjectAccess::ToTagged(WasmInternalFunction::kCallTargetOffset));

  args[0] = target;

  Node* call = continuation == kCallContinues
                   ? BuildWasmCall(sig, args, rets, position, implicit_arg)
                   : BuildWasmReturnCall(sig, args, position, implicit_arg);
  return call;
}

void WasmGraphBuilder::CompareToFuncRefAtIndex(Node* func_ref,
                                               uint32_t function_index,
                                               Node** success_control,
                                               Node** failure_control,
                                               bool is_last_case) {
  // Since we are comparing to a function reference, it is guaranteed that
  // instance->wasm_internal_functions() has been initialized.
  Node* func_refs = gasm_->LoadImmutable(
      MachineType::TaggedPointer(), GetInstanceData(),
      wasm::ObjectAccess::ToTagged(WasmTrustedInstanceData::kFuncRefsOffset));
  // We cannot use an immutable load here, since function references are
  // initialized lazily: Calling {RefFunc()} between two invocations of this
  // function may initialize the function, i.e. mutate the object we are
  // loading.
  Node* function_ref_at_index = gasm_->LoadFixedArrayElement(
      func_refs, gasm_->IntPtrConstant(function_index),
      MachineType::AnyTagged());
  BranchHint hint = is_last_case ? BranchHint::kTrue : BranchHint::kNone;
  gasm_->Branch(gasm_->TaggedEqual(function_ref_at_index, func_ref),
                success_control, failure_control, hint);
}

Node* WasmGraphBuilder::CallRef(const wasm::FunctionSig* sig,
                                base::Vector<Node*> args,
                                base::Vector<Node*> rets,
                                CheckForNull null_check,
                                wasm::WasmCodePosition position) {
  return BuildCallRef(sig, args, rets, null_check, IsReturnCall::kCallContinues,
                      position);
}

Node* WasmGraphBuilder::ReturnCallRef(const wasm::FunctionSig* sig,
                                      base::Vector<Node*> args,
                                      CheckForNull null_check,
                                      wasm::WasmCodePosition position) {
  return BuildCallRef(sig, args, {}, null_check, IsReturnCall::kReturnCall,
                      position);
}

Node* WasmGraphBuilder::ReturnCall(uint32_t index, base::Vector<Node*> args,
                                   wasm::WasmCodePosition position) {
  DCHECK_NULL(args[0]);
  const wasm::FunctionSig* sig = env_->module->functions[index].sig;

  if (env_ && index < env_->module->num_imported_functions) {
    // Return Call to an imported function.
    return BuildImportCall(sig, args, {}, position, index, kReturnCall);
  }

  // A direct tail call to a wasm function defined in this module.
  // Just encode the function index. This will be patched during code
  // generation.
  Address code = static_cast<Address>(index);
  args[0] = mcgraph()->RelocatableIntPtrConstant(code, RelocInfo::WASM_CALL);

  return BuildWasmReturnCall(sig, args, position, GetInstanceData());
}

Node* WasmGraphBuilder::ReturnCallIndirect(uint32_t table_index,
                                           wasm::ModuleTypeIndex sig_index,
                                           base::Vector<Node*> args,
                                           wasm::WasmCodePosition position) {
  return BuildIndirectCall(table_index, sig_index, args, {}, position,
                           kReturnCall);
}

std::tuple<Node*, Node*> WasmGraphBuilder::BrOnNull(Node* ref_object,
                                                    wasm::ValueType type) {
  return BranchExpectFalse(IsNull(ref_object, type));
}

Node* WasmGraphBuilder::BuildI32Rol(Node* left, Node* right) {
  // Implement Rol by Ror since TurboFan does not have Rol opcode.
  // TODO(weiliang): support Word32Rol opcode in TurboFan.
  Int32Matcher m(right);
  if (m.HasResolvedValue()) {
    return Binop(wasm::kExprI32Ror, left,
                 Int32Constant(32 - (m.ResolvedValue() & 0x1F)));
  } else {
    return Binop(wasm::kExprI32Ror, left,
                 Binop(wasm::kExprI32Sub, Int32Constant(32), right));
  }
}

Node* WasmGraphBuilder::BuildI64Rol(Node* left, Node* right) {
  // Implement Rol by Ror since TurboFan does not have Rol opcode.
  // TODO(weiliang): support Word64Rol opcode in TurboFan.
  Int64Matcher m(right);
  Node* inv_right = m.HasResolvedValue()
                        ? Int64Constant(64 - (m.ResolvedValue() & 0x3F))
                        : Binop(wasm::kExprI64Sub, Int64Constant(64), right);
  return Binop(wasm::kExprI64Ror, left, inv_right);
}

Node* WasmGraphBuilder::Invert(Node* node) {
  return Unop(wasm::kExprI32Eqz, node);
}

void WasmGraphBuilder::InitInstanceCache(
    WasmInstanceCacheNodes* instance_cache) {
  // We handle caching of the instance cache nodes manually, and we may reload
  // them in contexts where load elimination would eliminate the reload.
  // Therefore, we use plain Load nodes which are not subject to load
  // elimination.

  // Only cache memory start and size if there is a memory (the nodes would be
  // dead otherwise, but we can avoid creating them in the first place).
  if (!has_cached_memory()) return;

  instance_cache->mem_start = LoadMemStart(cached_memory_index_);

  // TODO(13957): Clamp the loaded memory size to a safe value.
  instance_cache->mem_size = LoadMemSize(cached_memory_index_);
}

void WasmGraphBuilder::PrepareInstanceCacheForLoop(
    WasmInstanceCacheNodes* instance_cache, Node* control) {
  if (!has_cached_memory()) return;
  for (auto field : WasmInstanceCacheNodes::kFields) {
    instance_cache->*field = graph()->NewNode(
        mcgraph()->common()->Phi(MachineType::PointerRepresentation(), 1),
        instance_cache->*field, control);
  }
}

void WasmGraphBuilder::NewInstanceCacheMerge(WasmInstanceCacheNodes* to,
                                             WasmInstanceCacheNodes* from,
                                             Node* merge) {
  for (auto field : WasmInstanceCacheNodes::kFields) {
Prompt: 
```
这是目录为v8/src/compiler/wasm-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/wasm-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共12部分，请归纳一下它的功能

"""
ght, Int32Constant(0)), BranchHint::kFalse);
  z.Chain(control());

  return z.Phi(MachineRepresentation::kWord32, Int32Constant(0),
               graph()->NewNode(mcgraph()->machine()->Uint32Div(), left, right,
                                z.if_false));
}

Node* WasmGraphBuilder::BuildI32AsmjsRemU(Node* left, Node* right) {
  // asm.js semantics return 0 on divide or mod by zero.
  // Explicit check for x % 0.
  Diamond z(graph(), mcgraph()->common(),
            gasm_->Word32Equal(right, Int32Constant(0)), BranchHint::kFalse);
  z.Chain(control());

  Node* rem = graph()->NewNode(mcgraph()->machine()->Uint32Mod(), left, right,
                               z.if_false);
  return z.Phi(MachineRepresentation::kWord32, Int32Constant(0), rem);
}

Node* WasmGraphBuilder::BuildI64DivS(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  if (mcgraph()->machine()->Is32()) {
    return BuildDiv64Call(left, right, ExternalReference::wasm_int64_div(),
                          MachineType::Int64(), wasm::kTrapDivByZero, position);
  }
  ZeroCheck64(wasm::kTrapDivByZero, right, position);
  Node* previous_effect = effect();
  auto [denom_is_m1, denom_is_not_m1] =
      BranchExpectFalse(gasm_->Word64Equal(right, Int64Constant(-1)));
  SetControl(denom_is_m1);
  TrapIfEq64(wasm::kTrapDivUnrepresentable, left,
             std::numeric_limits<int64_t>::min(), position);
  Node* merge = Merge(control(), denom_is_not_m1);
  SetEffectControl(graph()->NewNode(mcgraph()->common()->EffectPhi(2), effect(),
                                    previous_effect, merge),
                   merge);
  return gasm_->Int64Div(left, right);
}

Node* WasmGraphBuilder::BuildI64RemS(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  if (mcgraph()->machine()->Is32()) {
    return BuildDiv64Call(left, right, ExternalReference::wasm_int64_mod(),
                          MachineType::Int64(), wasm::kTrapRemByZero, position);
  }
  ZeroCheck64(wasm::kTrapRemByZero, right, position);
  Diamond d(mcgraph()->graph(), mcgraph()->common(),
            gasm_->Word64Equal(right, Int64Constant(-1)));

  d.Chain(control());

  Node* rem = graph()->NewNode(mcgraph()->machine()->Int64Mod(), left, right,
                               d.if_false);

  return d.Phi(MachineRepresentation::kWord64, Int64Constant(0), rem);
}

Node* WasmGraphBuilder::BuildI64DivU(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  if (mcgraph()->machine()->Is32()) {
    return BuildDiv64Call(left, right, ExternalReference::wasm_uint64_div(),
                          MachineType::Int64(), wasm::kTrapDivByZero, position);
  }
  ZeroCheck64(wasm::kTrapDivByZero, right, position);
  return gasm_->Uint64Div(left, right);
}
Node* WasmGraphBuilder::BuildI64RemU(Node* left, Node* right,
                                     wasm::WasmCodePosition position) {
  if (mcgraph()->machine()->Is32()) {
    return BuildDiv64Call(left, right, ExternalReference::wasm_uint64_mod(),
                          MachineType::Int64(), wasm::kTrapRemByZero, position);
  }
  ZeroCheck64(wasm::kTrapRemByZero, right, position);
  return gasm_->Uint64Mod(left, right);
}

Node* WasmGraphBuilder::BuildDiv64Call(Node* left, Node* right,
                                       ExternalReference ref,
                                       MachineType result_type,
                                       wasm::TrapReason trap_zero,
                                       wasm::WasmCodePosition position) {
  Node* stack_slot =
      StoreArgsInStackSlot({{MachineRepresentation::kWord64, left},
                            {MachineRepresentation::kWord64, right}});

  MachineType sig_types[] = {MachineType::Int32(), MachineType::Pointer()};
  MachineSignature sig(1, 1, sig_types);

  Node* function = gasm_->ExternalConstant(ref);
  Node* call = BuildCCall(&sig, function, stack_slot);

  ZeroCheck32(trap_zero, call, position);
  TrapIfEq32(wasm::kTrapDivUnrepresentable, call, -1, position);
  return gasm_->Load(result_type, stack_slot, 0);
}

Node* WasmGraphBuilder::IsNull(Node* object, wasm::ValueType type) {
  // This version is for Wasm functions (i.e. not wrappers):
  // - they use module-specific types
  // - they go through a lowering phase later
  // Both points are different in wrappers, see
  // WasmWrapperGraphBuilder::IsNull().
  DCHECK_EQ(parameter_mode_, kInstanceParameterMode);
  return gasm_->IsNull(object, type);
}

template <typename... Args>
Node* WasmGraphBuilder::BuildCCall(MachineSignature* sig, Node* function,
                                   Args... args) {
  DCHECK_LE(sig->return_count(), 1);
  DCHECK_EQ(sizeof...(args), sig->parameter_count());
  Node* call_args[] = {function, args..., effect(), control()};

  auto call_descriptor =
      Linkage::GetSimplifiedCDescriptor(mcgraph()->zone(), sig);

  return gasm_->Call(call_descriptor, arraysize(call_args), call_args);
}

Node* WasmGraphBuilder::BuildCallNode(size_t param_count,
                                      base::Vector<Node*> args,
                                      wasm::WasmCodePosition position,
                                      Node* implicit_first_arg,
                                      const Operator* op, Node* frame_state) {
  needs_stack_check_ = true;
  const size_t has_frame_state = frame_state != nullptr ? 1 : 0;
  const size_t extra = 3;  // instance_node, effect, and control.
  const size_t count = 1 + param_count + extra + has_frame_state;

  // Reallocate the buffer to make space for extra inputs.
  base::SmallVector<Node*, 16 + extra> inputs(count);
  DCHECK_EQ(1 + param_count, args.size());

  // Make room for the first argument at index 1, just after code.
  inputs[0] = args[0];  // code
  inputs[1] = implicit_first_arg;
  if (param_count > 0) {
    memcpy(&inputs[2], &args[1], param_count * sizeof(Node*));
  }

  // Add effect and control inputs.
  if (has_frame_state != 0) inputs[param_count + 2] = frame_state;
  inputs[param_count + has_frame_state + 2] = effect();
  inputs[param_count + has_frame_state + 3] = control();

  Node* call = graph()->NewNode(op, static_cast<int>(count), inputs.begin());
  // Return calls have no effect output. Other calls are the new effect node.
  if (op->EffectOutputCount() > 0) SetEffect(call);
  DCHECK(position == wasm::kNoCodePosition || position > 0);
  if (position > 0) SetSourcePosition(call, position);

  return call;
}

template <typename T>
Node* WasmGraphBuilder::BuildWasmCall(const Signature<T>* sig,
                                      base::Vector<Node*> args,
                                      base::Vector<Node*> rets,
                                      wasm::WasmCodePosition position,
                                      Node* implicit_first_arg,
                                      Node* frame_state) {
  CallDescriptor* call_descriptor = GetWasmCallDescriptor(
      mcgraph()->zone(), sig, kWasmFunction, frame_state != nullptr);
  const Operator* op = mcgraph()->common()->Call(call_descriptor);
  Node* call = BuildCallNode(sig->parameter_count(), args, position,
                             implicit_first_arg, op, frame_state);
  // TODO(manoskouk): These assume the call has control and effect outputs.
  DCHECK_GT(op->ControlOutputCount(), 0);
  DCHECK_GT(op->EffectOutputCount(), 0);
  SetEffectControl(call);

  size_t ret_count = sig->return_count();
  if (ret_count == 0) return call;  // No return value.

  DCHECK_EQ(ret_count, rets.size());
  if (ret_count == 1) {
    // Only a single return value.
    rets[0] = call;
  } else {
    // Create projections for all return values.
    for (size_t i = 0; i < ret_count; i++) {
      rets[i] = graph()->NewNode(mcgraph()->common()->Projection(i), call,
                                 graph()->start());
    }
  }
  return call;
}

Node* WasmGraphBuilder::BuildWasmReturnCall(const wasm::FunctionSig* sig,
                                            base::Vector<Node*> args,
                                            wasm::WasmCodePosition position,
                                            Node* implicit_first_arg) {
  CallDescriptor* call_descriptor =
      GetWasmCallDescriptor(mcgraph()->zone(), sig);
  const Operator* op = mcgraph()->common()->TailCall(call_descriptor);
  Node* call = BuildCallNode(sig->parameter_count(), args, position,
                             implicit_first_arg, op);

  // TODO(manoskouk): If we have kNoThrow calls, do not merge them to end.
  DCHECK_GT(call->op()->ControlOutputCount(), 0);
  gasm_->MergeControlToEnd(call);

  return call;
}

Node* WasmGraphBuilder::BuildImportCall(const wasm::FunctionSig* sig,
                                        base::Vector<Node*> args,
                                        base::Vector<Node*> rets,
                                        wasm::WasmCodePosition position,
                                        int func_index,
                                        IsReturnCall continuation) {
  return BuildImportCall(sig, args, rets, position,
                         gasm_->Uint32Constant(func_index), continuation);
}

Node* WasmGraphBuilder::BuildImportCall(
    const wasm::FunctionSig* sig, base::Vector<Node*> args,
    base::Vector<Node*> rets, wasm::WasmCodePosition position, Node* func_index,
    IsReturnCall continuation, Node* frame_state) {
  // Load the imported function refs array from the instance.
  Node* dispatch_table =
      LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(DispatchTableForImports);
  // Access fixed array at {header_size - tag + func_index * kTaggedSize}.
  Node* func_index_intptr = gasm_->BuildChangeUint32ToUintPtr(func_index);
  Node* dispatch_table_entry_offset = gasm_->IntMul(
      func_index_intptr, gasm_->IntPtrConstant(WasmDispatchTable::kEntrySize));
  Node* implicit_arg = gasm_->LoadProtectedPointerFromObject(
      dispatch_table,
      gasm_->IntAdd(dispatch_table_entry_offset,
                    gasm_->IntPtrConstant(wasm::ObjectAccess::ToTagged(
                        WasmDispatchTable::kEntriesOffset +
                        WasmDispatchTable::kImplicitArgBias))));

  Node* target = gasm_->LoadFromObject(
      MachineType::WasmCodePointer(), dispatch_table,
      gasm_->IntAdd(dispatch_table_entry_offset,
                    gasm_->IntPtrConstant(wasm::ObjectAccess::ToTagged(
                        WasmDispatchTable::kEntriesOffset +
                        WasmDispatchTable::kTargetBias))));

  args[0] = target;

  switch (continuation) {
    case kCallContinues:
      return BuildWasmCall(sig, args, rets, position, implicit_arg,
                           frame_state);
    case kReturnCall:
      DCHECK(rets.empty());
      return BuildWasmReturnCall(sig, args, position, implicit_arg);
  }
}

Node* WasmGraphBuilder::CallDirect(uint32_t index, base::Vector<Node*> args,
                                   base::Vector<Node*> rets,
                                   wasm::WasmCodePosition position) {
  DCHECK_NULL(args[0]);
  const wasm::FunctionSig* sig = env_->module->functions[index].sig;

  if (env_ && index < env_->module->num_imported_functions) {
    // Call to an imported function.
    return BuildImportCall(sig, args, rets, position, index, kCallContinues);
  }

  // A direct call to a wasm function defined in this module.
  // Just encode the function index. This will be patched at instantiation.
  Address code = static_cast<Address>(index);
  args[0] = mcgraph()->RelocatableIntPtrConstant(code, RelocInfo::WASM_CALL);

  return BuildWasmCall(sig, args, rets, position, GetInstanceData());
}

Node* WasmGraphBuilder::CallIndirect(uint32_t table_index,
                                     wasm::ModuleTypeIndex sig_index,
                                     base::Vector<Node*> args,
                                     base::Vector<Node*> rets,
                                     wasm::WasmCodePosition position) {
  return BuildIndirectCall(table_index, sig_index, args, rets, position,
                           kCallContinues);
}

Node* WasmGraphBuilder::BuildIndirectCall(uint32_t table_index,
                                          wasm::ModuleTypeIndex sig_index,
                                          base::Vector<Node*> args,
                                          base::Vector<Node*> rets,
                                          wasm::WasmCodePosition position,
                                          IsReturnCall continuation) {
  DCHECK_NOT_NULL(args[0]);
  DCHECK_NOT_NULL(env_);

  // Load the dispatch table.
  Node* dispatch_table;
  if (table_index == 0) {
    dispatch_table = LOAD_PROTECTED_INSTANCE_FIELD(DispatchTable0);
  } else {
    Node* dispatch_tables =
        LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(DispatchTables);
    dispatch_table = gasm_->LoadProtectedPointerFromObject(
        dispatch_tables,
        wasm::ObjectAccess::ToTagged(
            ProtectedFixedArray::OffsetOfElementAt(table_index)));
  }

  // Bounds check the index.
  Node* index = args[0];
  const wasm::WasmTable& table = env_->module->tables[table_index];
  TableTypeToUintPtrOrOOBTrap(table.address_type, {&index}, position);
  const bool needs_dynamic_size =
      !table.has_maximum_size || table.maximum_size != table.initial_size;
  Node* table_size =
      needs_dynamic_size
          ? gasm_->LoadFromObject(
                MachineType::Int32(), dispatch_table,
                wasm::ObjectAccess::ToTagged(WasmDispatchTable::kLengthOffset))
          : Int32Constant(table.initial_size);
  Node* in_bounds = Is64() ? gasm_->Uint64LessThan(
                                 index, gasm_->ChangeUint32ToUint64(table_size))
                           : gasm_->Uint32LessThan(index, table_size);
  TrapIfFalse(wasm::kTrapTableOutOfBounds, in_bounds, position);

  wasm::ValueType table_type = env_->module->tables[table_index].type;
  bool needs_type_check = !wasm::EquivalentTypes(
      table_type.AsNonNull(), wasm::ValueType::Ref(sig_index), env_->module,
      env_->module);
  bool needs_null_check = table_type.is_nullable();

  Node* dispatch_table_entry_offset = gasm_->IntAdd(
      gasm_->IntPtrConstant(
          wasm::ObjectAccess::ToTagged(WasmDispatchTable::kEntriesOffset)),
      gasm_->IntMul(index,
                    gasm_->IntPtrConstant(WasmDispatchTable::kEntrySize)));

  // Skip check if table type matches declared signature.
  if (needs_type_check) {
    // Embed the expected signature ID as a relocatable constant.
    wasm::CanonicalTypeIndex canonical_sig_id =
        env_->module->canonical_sig_id(sig_index);
    Node* expected_sig_id = mcgraph()->RelocatableInt32Constant(
        canonical_sig_id.index, RelocInfo::WASM_CANONICAL_SIG_ID);

    Node* loaded_sig = gasm_->LoadFromObject(
        MachineType::Int32(), dispatch_table,
        gasm_->IntAdd(dispatch_table_entry_offset,
                      gasm_->IntPtrConstant(WasmDispatchTable::kSigBias)));
    Node* sig_match = gasm_->Word32Equal(loaded_sig, expected_sig_id);

    if (!env_->module->type(sig_index).is_final) {
      // Do a full subtyping check.
      auto end_label = gasm_->MakeLabel();
      gasm_->GotoIf(sig_match, &end_label);

      // Trap on null element.
      if (needs_null_check) {
        TrapIfTrue(wasm::kTrapFuncSigMismatch,
                   gasm_->Word32Equal(loaded_sig, Int32Constant(-1)), position);
      }

      Node* formal_rtt = RttCanon(sig_index);
      int rtt_depth = wasm::GetSubtypingDepth(env_->module, sig_index);
      DCHECK_GE(rtt_depth, 0);

      // Since we have the canonical index of the real rtt, we have to load it
      // from the isolate rtt-array (which is canonically indexed). Since this
      // reference is weak, we have to promote it to a strong reference.
      // Note: The reference cannot have been cleared: Since the loaded_sig
      // corresponds to a function of the same canonical type, that function
      // will have kept the type alive.
      Node* rtts = LOAD_MUTABLE_ROOT(WasmCanonicalRtts, wasm_canonical_rtts);
      Node* real_rtt =
          gasm_->WordAnd(gasm_->LoadWeakFixedArrayElement(rtts, loaded_sig),
                         gasm_->IntPtrConstant(~kWeakHeapObjectMask));
      Node* type_info = gasm_->LoadWasmTypeInfo(real_rtt);

      // If the depth of the rtt is known to be less than the minimum supertype
      // array length, we can access the supertype without bounds-checking the
      // supertype array.
      if (static_cast<uint32_t>(rtt_depth) >=
          wasm::kMinimumSupertypeArraySize) {
        Node* supertypes_length =
            gasm_->BuildChangeSmiToIntPtr(gasm_->LoadImmutableFromObject(
                MachineType::TaggedSigned(), type_info,
                wasm::ObjectAccess::ToTagged(
                    WasmTypeInfo::kSupertypesLengthOffset)));
        TrapIfFalse(wasm::kTrapFuncSigMismatch,
                    gasm_->UintLessThan(gasm_->IntPtrConstant(rtt_depth),
                                        supertypes_length),
                    position);
      }

      Node* maybe_match = gasm_->LoadImmutableFromObject(
          MachineType::TaggedPointer(), type_info,
          wasm::ObjectAccess::ToTagged(WasmTypeInfo::kSupertypesOffset +
                                       kTaggedSize * rtt_depth));
      TrapIfFalse(wasm::kTrapFuncSigMismatch,
                  gasm_->TaggedEqual(maybe_match, formal_rtt), position);
      gasm_->Goto(&end_label);

      gasm_->Bind(&end_label);
    } else {
      // In absence of subtyping, we just need to check for type equality.
      TrapIfFalse(wasm::kTrapFuncSigMismatch, sig_match, position);
    }
  } else if (needs_null_check) {
    Node* loaded_sig = gasm_->LoadFromObject(
        MachineType::Int32(), dispatch_table,
        gasm_->IntAdd(dispatch_table_entry_offset,
                      gasm_->IntPtrConstant(WasmDispatchTable::kSigBias)));
    TrapIfTrue(wasm::kTrapFuncSigMismatch,
               gasm_->Word32Equal(loaded_sig, Int32Constant(-1)), position);
  }

  Node* implicit_arg = gasm_->LoadProtectedPointerFromObject(
      dispatch_table, gasm_->IntAdd(dispatch_table_entry_offset,
                                    gasm_->IntPtrConstant(
                                        WasmDispatchTable::kImplicitArgBias)));

  Node* target = gasm_->LoadFromObject(
      MachineType::WasmCodePointer(), dispatch_table,
      gasm_->IntAdd(dispatch_table_entry_offset,
                    gasm_->IntPtrConstant(WasmDispatchTable::kTargetBias)));
  args[0] = target;

  const wasm::FunctionSig* sig = env_->module->signature(sig_index);

  switch (continuation) {
    case kCallContinues:
      return BuildWasmCall(sig, args, rets, position, implicit_arg);
    case kReturnCall:
      return BuildWasmReturnCall(sig, args, position, implicit_arg);
  }
}

Node* WasmGraphBuilder::BuildLoadCallTargetFromExportedFunctionData(
    Node* function_data) {
  Node* internal = gasm_->LoadProtectedPointerFromObject(
      function_data, wasm::ObjectAccess::ToTagged(
                         WasmExportedFunctionData::kProtectedInternalOffset));
  return gasm_->LoadFromObject(
      MachineType::WasmCodePointer(), internal,
      wasm::ObjectAccess::ToTagged(WasmInternalFunction::kCallTargetOffset));
}

// TODO(9495): Support CAPI function refs.
Node* WasmGraphBuilder::BuildCallRef(const wasm::FunctionSig* sig,
                                     base::Vector<Node*> args,
                                     base::Vector<Node*> rets,
                                     CheckForNull null_check,
                                     IsReturnCall continuation,
                                     wasm::WasmCodePosition position) {
  Node* func_ref = args[0];
  if (null_check == kWithNullCheck &&
      null_check_strategy_ == NullCheckStrategy::kExplicit) {
    func_ref =
        AssertNotNull(func_ref, wasm::kWasmFuncRef /* good enough */, position);
  }

  Node* internal_function;
  if (null_check == kWithNullCheck &&
      null_check_strategy_ == NullCheckStrategy::kTrapHandler) {
    // TODO(14564): Move WasmInternalFunction to trusted space and make
    // this a load of a trusted (immutable) pointer.
    Node* load;
    std::tie(load, internal_function) =
        gasm_->LoadTrustedPointerFromObjectTrapOnNull(
            func_ref,
            wasm::ObjectAccess::ToTagged(WasmFuncRef::kTrustedInternalOffset),
            kWasmInternalFunctionIndirectPointerTag);
    SetSourcePosition(load, position);
  } else {
    internal_function = gasm_->LoadTrustedPointerFromObject(
        func_ref,
        wasm::ObjectAccess::ToTagged(WasmFuncRef::kTrustedInternalOffset),
        kWasmInternalFunctionIndirectPointerTag);
  }

  Node* implicit_arg = gasm_->LoadImmutableProtectedPointerFromObject(
      internal_function,
      wasm::ObjectAccess::ToTagged(
          WasmInternalFunction::kProtectedImplicitArgOffset));
  Node* target = gasm_->LoadFromObject(
      MachineType::WasmCodePointer(), internal_function,
      wasm::ObjectAccess::ToTagged(WasmInternalFunction::kCallTargetOffset));

  args[0] = target;

  Node* call = continuation == kCallContinues
                   ? BuildWasmCall(sig, args, rets, position, implicit_arg)
                   : BuildWasmReturnCall(sig, args, position, implicit_arg);
  return call;
}

void WasmGraphBuilder::CompareToFuncRefAtIndex(Node* func_ref,
                                               uint32_t function_index,
                                               Node** success_control,
                                               Node** failure_control,
                                               bool is_last_case) {
  // Since we are comparing to a function reference, it is guaranteed that
  // instance->wasm_internal_functions() has been initialized.
  Node* func_refs = gasm_->LoadImmutable(
      MachineType::TaggedPointer(), GetInstanceData(),
      wasm::ObjectAccess::ToTagged(WasmTrustedInstanceData::kFuncRefsOffset));
  // We cannot use an immutable load here, since function references are
  // initialized lazily: Calling {RefFunc()} between two invocations of this
  // function may initialize the function, i.e. mutate the object we are
  // loading.
  Node* function_ref_at_index = gasm_->LoadFixedArrayElement(
      func_refs, gasm_->IntPtrConstant(function_index),
      MachineType::AnyTagged());
  BranchHint hint = is_last_case ? BranchHint::kTrue : BranchHint::kNone;
  gasm_->Branch(gasm_->TaggedEqual(function_ref_at_index, func_ref),
                success_control, failure_control, hint);
}

Node* WasmGraphBuilder::CallRef(const wasm::FunctionSig* sig,
                                base::Vector<Node*> args,
                                base::Vector<Node*> rets,
                                CheckForNull null_check,
                                wasm::WasmCodePosition position) {
  return BuildCallRef(sig, args, rets, null_check, IsReturnCall::kCallContinues,
                      position);
}

Node* WasmGraphBuilder::ReturnCallRef(const wasm::FunctionSig* sig,
                                      base::Vector<Node*> args,
                                      CheckForNull null_check,
                                      wasm::WasmCodePosition position) {
  return BuildCallRef(sig, args, {}, null_check, IsReturnCall::kReturnCall,
                      position);
}

Node* WasmGraphBuilder::ReturnCall(uint32_t index, base::Vector<Node*> args,
                                   wasm::WasmCodePosition position) {
  DCHECK_NULL(args[0]);
  const wasm::FunctionSig* sig = env_->module->functions[index].sig;

  if (env_ && index < env_->module->num_imported_functions) {
    // Return Call to an imported function.
    return BuildImportCall(sig, args, {}, position, index, kReturnCall);
  }

  // A direct tail call to a wasm function defined in this module.
  // Just encode the function index. This will be patched during code
  // generation.
  Address code = static_cast<Address>(index);
  args[0] = mcgraph()->RelocatableIntPtrConstant(code, RelocInfo::WASM_CALL);

  return BuildWasmReturnCall(sig, args, position, GetInstanceData());
}

Node* WasmGraphBuilder::ReturnCallIndirect(uint32_t table_index,
                                           wasm::ModuleTypeIndex sig_index,
                                           base::Vector<Node*> args,
                                           wasm::WasmCodePosition position) {
  return BuildIndirectCall(table_index, sig_index, args, {}, position,
                           kReturnCall);
}

std::tuple<Node*, Node*> WasmGraphBuilder::BrOnNull(Node* ref_object,
                                                    wasm::ValueType type) {
  return BranchExpectFalse(IsNull(ref_object, type));
}

Node* WasmGraphBuilder::BuildI32Rol(Node* left, Node* right) {
  // Implement Rol by Ror since TurboFan does not have Rol opcode.
  // TODO(weiliang): support Word32Rol opcode in TurboFan.
  Int32Matcher m(right);
  if (m.HasResolvedValue()) {
    return Binop(wasm::kExprI32Ror, left,
                 Int32Constant(32 - (m.ResolvedValue() & 0x1F)));
  } else {
    return Binop(wasm::kExprI32Ror, left,
                 Binop(wasm::kExprI32Sub, Int32Constant(32), right));
  }
}

Node* WasmGraphBuilder::BuildI64Rol(Node* left, Node* right) {
  // Implement Rol by Ror since TurboFan does not have Rol opcode.
  // TODO(weiliang): support Word64Rol opcode in TurboFan.
  Int64Matcher m(right);
  Node* inv_right = m.HasResolvedValue()
                        ? Int64Constant(64 - (m.ResolvedValue() & 0x3F))
                        : Binop(wasm::kExprI64Sub, Int64Constant(64), right);
  return Binop(wasm::kExprI64Ror, left, inv_right);
}

Node* WasmGraphBuilder::Invert(Node* node) {
  return Unop(wasm::kExprI32Eqz, node);
}

void WasmGraphBuilder::InitInstanceCache(
    WasmInstanceCacheNodes* instance_cache) {
  // We handle caching of the instance cache nodes manually, and we may reload
  // them in contexts where load elimination would eliminate the reload.
  // Therefore, we use plain Load nodes which are not subject to load
  // elimination.

  // Only cache memory start and size if there is a memory (the nodes would be
  // dead otherwise, but we can avoid creating them in the first place).
  if (!has_cached_memory()) return;

  instance_cache->mem_start = LoadMemStart(cached_memory_index_);

  // TODO(13957): Clamp the loaded memory size to a safe value.
  instance_cache->mem_size = LoadMemSize(cached_memory_index_);
}

void WasmGraphBuilder::PrepareInstanceCacheForLoop(
    WasmInstanceCacheNodes* instance_cache, Node* control) {
  if (!has_cached_memory()) return;
  for (auto field : WasmInstanceCacheNodes::kFields) {
    instance_cache->*field = graph()->NewNode(
        mcgraph()->common()->Phi(MachineType::PointerRepresentation(), 1),
        instance_cache->*field, control);
  }
}

void WasmGraphBuilder::NewInstanceCacheMerge(WasmInstanceCacheNodes* to,
                                             WasmInstanceCacheNodes* from,
                                             Node* merge) {
  for (auto field : WasmInstanceCacheNodes::kFields) {
    if (to->*field == from->*field) continue;
    Node* vals[] = {to->*field, from->*field, merge};
    to->*field = graph()->NewNode(
        mcgraph()->common()->Phi(MachineType::PointerRepresentation(), 2), 3,
        vals);
  }
}

void WasmGraphBuilder::MergeInstanceCacheInto(WasmInstanceCacheNodes* to,
                                              WasmInstanceCacheNodes* from,
                                              Node* merge) {
  if (!has_cached_memory()) {
    // Instance cache nodes should be nullptr then.
    DCHECK(to->mem_start == nullptr && to->mem_size == nullptr &&
           from->mem_start == nullptr && from->mem_size == nullptr);
    return;
  }

  for (auto field : WasmInstanceCacheNodes::kFields) {
    to->*field = CreateOrMergeIntoPhi(MachineType::PointerRepresentation(),
                                      merge, to->*field, from->*field);
  }
}

Node* WasmGraphBuilder::CreateOrMergeIntoPhi(MachineRepresentation rep,
                                             Node* merge, Node* tnode,
                                             Node* fnode) {
  if (IsPhiWithMerge(tnode, merge)) {
    AppendToPhi(tnode, fnode);
  } else if (tnode != fnode) {
    // Note that it is not safe to use {Buffer} here since this method is used
    // via {CheckForException} while the {Buffer} is in use by another method.
    uint32_t count = merge->InputCount();
    // + 1 for the merge node.
    base::SmallVector<Node*, 9> inputs(count + 1);
    for (uint32_t j = 0; j < count - 1; j++) inputs[j] = tnode;
    inputs[count - 1] = fnode;
    inputs[count] = merge;
    tnode = graph()->NewNode(mcgraph()->common()->Phi(rep, count), count + 1,
                             inputs.begin());
  }
  return tnode;
}

Node* WasmGraphBuilder::CreateOrMergeIntoEffectPhi(Node* merge, Node* tnode,
                                                   Node* fnode) {
  if (IsPhiWithMerge(tnode, merge)) {
    AppendToPhi(tnode, fnode);
  } else if (tnode != fnode) {
    // Note that it is not safe to use {Buffer} here since this method is used
    // via {CheckForException} while the {Buffer} is in use by another method.
    uint32_t count = merge->InputCount();
    // + 1 for the merge node.
    base::SmallVector<Node*, 9> inputs(count + 1);
    for (uint32_t j = 0; j < count - 1; j++) {
      inputs[j] = tnode;
    }
    inputs[count - 1] = fnode;
    inputs[count] = merge;
    tnode = graph()->NewNode(mcgraph()->common()->EffectPhi(count), count + 1,
                             inputs.begin());
  }
  return tnode;
}

Node* WasmGraphBuilder::effect() { return gasm_->effect(); }

Node* WasmGraphBuilder::control() { return gasm_->control(); }

Node* WasmGraphBuilder::SetEffect(Node* node) {
  SetEffectControl(node, control());
  return node;
}

Node* WasmGraphBuilder::SetControl(Node* node) {
  SetEffectControl(effect(), node);
  return node;
}

void WasmGraphBuilder::SetEffectControl(Node* effect, Node* control) {
  gasm_->InitializeEffectControl(effect, control);
}

Node* WasmGraphBuilder::MemStart(uint32_t mem_index) {
  DCHECK_NOT_NULL(instance_cache_);
  V8_ASSUME(cached_memory_index_ == kNoCachedMemoryIndex ||
            cached_memory_index_ >= 0);
  if (mem_index == static_cast<uint32_t>(cached_memory_index_)) {
    return instance_cache_->mem_start;
  }
  return LoadMemStart(mem_index);
}

Node* WasmGraphBuilder::MemSize(uint32_t mem_index) {
  DCHECK_NOT_NULL(instance_cache_);
  V8_ASSUME(cached_memory_index_ == kNoCachedMemoryIndex ||
            cached_memory_index_ >= 0);
  if (mem_index == static_cast<uint32_t>(cached_memory_index_)) {
    return instance_cache_->mem_size;
  }

  return LoadMemSize(mem_index);
}

Node* WasmGraphBuilder::LoadMemStart(uint32_t mem_index) {
  if (mem_index == 0) {
    return LOAD_INSTANCE_FIELD_NO_ELIMINATION(Memory0Start,
                                              MachineType::Pointer());
  }
  Node* memory_bases_and_sizes =
      LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(MemoryBasesAndSizes);
  // Use {LoadByteArrayElement} even though it's a trusted array; their layout
  // is the same.
  static_assert(FixedAddressArray::OffsetOfElementAt(0) ==
                TrustedFixedAddressArray::OffsetOfElementAt(0));
  return gasm_->LoadByteArrayElement(memory_bases_and_sizes,
                                     gasm_->IntPtrConstant(2 * mem_index),
                                     MachineType::Pointer());
}

Node* WasmGraphBuilder::LoadMemSize(uint32_t mem_index) {
  wasm::ValueType mem_type = env_->module->memories[mem_index].is_memory64()
                                 ? wasm::kWasmI64
                                 : wasm::kWasmI32;
  if (mem_index == 0) {
    return SetType(
        LOAD_INSTANCE_FIELD_NO_ELIMINATION(Memory0Size, MachineType::UintPtr()),
        mem_type);
  }
  Node* memory_bases_and_sizes =
      LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(MemoryBasesAndSizes);
  // Use {LoadByteArrayElement} even though it's a trusted array; their layout
  // is the same.
  static_assert(FixedAddressArray::OffsetOfElementAt(0) ==
                TrustedFixedAddressArray::OffsetOfElementAt(0));
  return SetType(
      gasm_->LoadByteArrayElement(memory_bases_and_sizes,
                                  gasm_->IntPtrConstant(2 * mem_index + 1),
                                  MachineType::UintPtr()),
      mem_type);
}

Node* WasmGraphBuilder::MemBuffer(uint32_t mem_index, uintptr_t offset) {
  Node* mem_start = MemStart(mem_index);
  if (offset == 0) return mem_start;
  return gasm_->IntAdd(mem_start, gasm_->UintPtrConstant(
"""


```