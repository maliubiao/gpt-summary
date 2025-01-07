Response:
The user wants a summary of the provided C++ code snippet from `v8/src/compiler/turboshaft/maglev-graph-building-phase.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Functionality:** The code consists of multiple `Process` methods, each handling a specific `maglev::` node type. This suggests the file's primary function is to translate or process nodes from a Maglev graph into something else (likely a Turboshaft graph or intermediate representation). The file name itself, "maglev-graph-building-phase.cc", strongly reinforces this idea.

2. **Examine Individual `Process` Methods:**  Go through each `Process` method and understand its purpose. Look for patterns:
    * **`SetMap(node, ...)`:**  This appears frequently, suggesting a mapping or transformation of some kind.
    * **`__` prefix:**  Methods like `__ Return`, `__ Deoptimize`, `__ LoadMapField` indicate interactions with an underlying code generation or runtime interface (likely the Turboshaft assembler).
    * **`GET_FRAME_STATE_MAYBE_ABORT`:** This clearly deals with deoptimization and frame state management.
    * **Builtin calls:**  `GENERATE_AND_MAP_BUILTIN_CALL` signifies invoking built-in JavaScript functions.
    * **Generator specific methods:** `__ GeneratorStore`, `__ LoadTaggedField` point to handling generator functions.
    * **Control flow:** `IF`, `GOTO_IF`, `GOTO`, `BIND` are standard assembly-level control flow operations.
    * **`UNREACHABLE()`:** This indicates code paths that should not be executed under normal circumstances, often related to Maglev-specific nodes not used when targeting Turboshaft.

3. **Infer Overall Purpose:** Based on the individual `Process` methods, the file seems to be responsible for:
    * **Translating Maglev nodes into Turboshaft instructions or operations.**  This is the most prominent function.
    * **Handling deoptimization scenarios.**
    * **Managing frame states.**
    * **Interfacing with built-in JavaScript functions.**
    * **Supporting generator functions.**
    * **Dealing with different data types (Smi, HeapNumber, etc.).**

4. **Address Specific Questions:**
    * **File Extension:** The code is `.cc`, so it's C++ and not Torque.
    * **Relationship to JavaScript:** Many of the operations directly relate to JavaScript concepts: numbers, objects, built-in functions, generators, deoptimization (which happens during runtime when assumptions are violated). Provide concrete JavaScript examples that would trigger the corresponding Maglev nodes. For example, `parseFloat("1.5")` for `Float64ToUint8Clamped` after a conversion.
    * **Code Logic and Input/Output:** For `CheckedNumberToUint8Clamped`, provide a clear example of input (a number-like value) and potential output (clamped integer) along with deoptimization scenarios.
    * **Common Programming Errors:**  Highlight type errors that would lead to deoptimization. Trying to clamp a non-numeric value is a good example.

5. **Synthesize a Summary:** Combine the understanding of individual methods and the inferred overall purpose into a concise summary. Emphasize the translation role, handling of deoptimization, and the interaction with the Turboshaft assembler. Mention the handling of different Maglev node types.

6. **Review and Refine:** Check for clarity, accuracy, and completeness. Ensure the JavaScript examples are relevant and easy to understand. Make sure the summary accurately reflects the code's functionality. Since this is part 7 of 9, explicitly state that this part focuses on translating specific Maglev operations.
```cpp
maglev::ProcessResult Process(maglev::Float64ToUint8Clamped* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, Float64ToUint8Clamped(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckedNumberToUint8Clamped* node,
                                const maglev::ProcessingState& state) {
    ScopedVar<Word32, AssemblerT> result(this);
    V<Object> value = Map(node->input());
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    IF (__ IsSmi(value)) {
      result = Int32ToUint8Clamped(__ UntagSmi(V<Smi>::Cast(value)));
    } ELSE {
      V<i::Map> map = __ LoadMapField(value);
      __ DeoptimizeIfNot(
          __ TaggedEqual(map,
                         __ HeapConstant(local_factory_->heap_number_map())),
          frame_state, DeoptimizeReason::kNotAHeapNumber,
          node->eager_deopt_info()->feedback_to_update());
      result = Float64ToUint8Clamped(
          __ LoadHeapNumberValue(V<HeapNumber>::Cast(value)));
    }
    RETURN_IF_UNREACHABLE();
    SetMap(node, result);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::ToObject* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
    OpIndex arguments[] = {Map(node->value_input()), Map(node->context())};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kToObject, frame_state,
                                  base::VectorOf(arguments));

    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Return* node,
                                const maglev::ProcessingState& state) {
    __ Return(Map(node->value_input()));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Deopt* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ Deoptimize(frame_state, node->reason(),
                  node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::SetPendingMessage* node,
                                const maglev::ProcessingState& state) {
    V<WordPtr> message_address = __ ExternalConstant(
        ExternalReference::address_of_pending_message(isolate_));
    V<Object> old_message = __ LoadMessage(message_address);
    __ StoreMessage(message_address, Map(node->value()));
    SetMap(node, old_message);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::GeneratorStore* node,
                                const maglev::ProcessingState& state) {
    base::SmallVector<OpIndex, 32> parameters_and_registers;
    int num_parameters_and_registers = node->num_parameters_and_registers();
    for (int i = 0; i < num_parameters_and_registers; i++) {
      parameters_and_registers.push_back(
          Map(node->parameters_and_registers(i)));
    }
    __ GeneratorStore(Map(node->context_input()), Map(node->generator_input()),
                      parameters_and_registers, node->suspend_id(),
                      node->bytecode_offset());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::GeneratorRestoreRegister* node,
                                const maglev::ProcessingState& state) {
    V<FixedArray> array = Map(node->array_input());
    V<Object> result =
        __ LoadTaggedField(array, FixedArray::OffsetOfElementAt(node->index()));
    __ Store(array, Map(node->stale_input()), StoreOp::Kind::TaggedBase(),
             MemoryRepresentation::TaggedSigned(),
             WriteBarrierKind::kNoWriteBarrier,
             FixedArray::OffsetOfElementAt(node->index()));

    SetMap(node, result);

    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Abort* node,
                                const maglev::ProcessingState& state) {
    __ RuntimeAbort(node->reason());
    // TODO(dmercadier): remove this `Unreachable` once RuntimeAbort is marked
    // as a block terminator.
    __ Unreachable();
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Identity* node,
                                const maglev::ProcessingState&) {
    SetMap(node, Map(node->input(0)));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Dead*, const maglev::ProcessingState&) {
    // Nothing to do; `Dead` is in Maglev to kill a node when removing it
    // directly from the graph is not possible.
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::DebugBreak*,
                                const maglev::ProcessingState&) {
    __ DebugBreak();
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::GapMove*,
                                const maglev::ProcessingState&) {
    // GapMove nodes are created by Maglev's register allocator, which
    // doesn't run when using Maglev as a frontend for Turboshaft.
    UNREACHABLE();
  }
  maglev::ProcessResult Process(maglev::ConstantGapMove*,
                                const maglev::ProcessingState&) {
    // ConstantGapMove nodes are created by Maglev's register allocator, which
    // doesn't run when using Maglev as a frontend for Turboshaft.
    UNREACHABLE();
  }

  maglev::ProcessResult Process(maglev::VirtualObject*,
                                const maglev::ProcessingState&) {
    // VirtualObjects should never be part of the Maglev graph.
    UNREACHABLE();
  }

  maglev::ProcessResult Process(maglev::GetSecondReturnedValue* node,
                                const maglev::ProcessingState& state) {
    DCHECK(second_return_value_.valid());
    SetMap(node, second_return_value_);

#ifdef DEBUG
    second_return_value_ = V<Object>::Invalid();
#endif

    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::TryOnStackReplacement*,
                                const maglev::ProcessingState&) {
    // Turboshaft is the top tier compiler, so we never need to OSR from it.
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::ReduceInterruptBudgetForReturn*,
                                const maglev::ProcessingState&) {
    // No need to update the interrupt budget once we reach Turboshaft.
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::ReduceInterruptBudgetForLoop* node,
                                const maglev::ProcessingState&) {
    // ReduceInterruptBudgetForLoop nodes are not emitted by Maglev when it is
    // used as a frontend for Turboshaft.
    UNREACHABLE();
  }
  maglev::ProcessResult Process(maglev::HandleNoHeapWritesInterrupt* node,
                                const maglev::ProcessingState&) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
    __ JSLoopStackCheck(native_context(), frame_state);
    return maglev::ProcessResult::kContinue;
  }

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  maglev::ProcessResult Process(
      maglev::GetContinuationPreservedEmbedderData* node,
      const maglev::ProcessingState&) {
    V<Object> data = __ GetContinuationPreservedEmbedderData();
    SetMap(node, data);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(
      maglev::SetContinuationPreservedEmbedderData* node,
      const maglev::ProcessingState&) {
    V<Object> data = Map(node->input(0));
    __ SetContinuationPreservedEmbedderData(data);
    return maglev::ProcessResult::kContinue;
  }
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

  maglev::ProcessResult Process(maglev::AssertInt32* node,
                                const maglev::ProcessingState&) {
    bool negate_result = false;
    V<Word32> cmp = ConvertInt32Compare(node->left_input(), node->right_input(),
                                        node->condition(), &negate_result);
    Label<> abort(this);
    Label<> end(this);
    if (negate_result) {
      GOTO_IF(cmp, abort);
    } else {
      GOTO_IF_NOT(cmp, abort);
    }
    GOTO(end);

    BIND(abort);
    __ RuntimeAbort(node->reason());
    __ Unreachable();

    BIND(end);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::CallSelf*,
                                const maglev::ProcessingState&) {
    // CallSelf nodes are only created when Maglev is the top-tier compiler
    // (which can't be the case here, since we're currently compiling for
    // Turboshaft).
    UNREACHABLE();
  }

  // Nodes unused by maglev but still existing.
  maglev::ProcessResult Process(maglev::ExternalConstant*,
                                const maglev::ProcessingState&) {
    UNREACHABLE();
  }
  maglev::ProcessResult Process(maglev::CallCPPBuiltin*,
                                const maglev::ProcessingState&) {
    UNREACHABLE();
  }
  maglev::ProcessResult Process(maglev::UnsafeTruncateUint32ToInt32*,
                                const maglev::ProcessingState&) {
    UNREACHABLE();
  }
  maglev::ProcessResult Process(maglev::UnsafeTruncateFloat64ToInt32*,
                                const maglev::ProcessingState&) {
    UNREACHABLE();
  }
  maglev::ProcessResult Process(maglev::BranchIfTypeOf*,
                                const maglev::ProcessingState&) {
    UNREACHABLE();
  }

  AssemblerT& Asm() { return assembler_; }
  Zone* temp_zone() { return temp_zone_; }
  Zone* graph_zone() { return Asm().output_graph().graph_zone(); }

 private:
  OptionalV<FrameState> BuildFrameState(
      maglev::EagerDeoptInfo* eager_deopt_info) {
    deduplicator_.Reset();
    // Eager deopts don't have a result location/size.
    const interpreter::Register result_location =
        interpreter::Register::invalid_value();
    const int result_size = 0;
    const maglev::VirtualObject::List& virtual_objects =
        maglev::GetVirtualObjects(eager_deopt_info->top_frame());

    switch (eager_deopt_info->top_frame().type()) {
      case maglev::DeoptFrame::FrameType::kInterpretedFrame:
        return BuildFrameState(eager_deopt_info->top_frame().as_interpreted(),
                               virtual_objects, result_location, result_size);
      case maglev::DeoptFrame::FrameType::kBuiltinContinuationFrame:
        return BuildFrameState(
            eager_deopt_info->top_frame().as_builtin_continuation(),
            virtual_objects);
      case maglev::DeoptFrame::FrameType::kInlinedArgumentsFrame:
      case maglev::DeoptFrame::FrameType::kConstructInvokeStubFrame:
        UNIMPLEMENTED();
    }
  }

  OptionalV<FrameState> BuildFrameState(
      maglev::LazyDeoptInfo* lazy_deopt_info) {
    deduplicator_.Reset();
    const maglev::VirtualObject::List& virtual_objects =
        maglev::GetVirtualObjects(lazy_deopt_info->top_frame());
    switch (lazy_deopt_info->top_frame().type()) {
      case maglev::DeoptFrame::FrameType::kInterpretedFrame:
        return BuildFrameState(
            lazy_deopt_info->top_frame().as_interpreted(), virtual_objects,
            lazy_deopt_info->result_location(), lazy_deopt_info->result_size());
      case maglev::DeoptFrame::FrameType::kConstructInvokeStubFrame:
        return BuildFrameState(lazy_deopt_info->top_frame().as_construct_stub(),
                               virtual_objects);

      case maglev::DeoptFrame::FrameType::kBuiltinContinuationFrame:
        return BuildFrameState(
            lazy_deopt_info->top_frame().as_builtin_continuation(),
            virtual_objects);

      case maglev::DeoptFrame::FrameType::kInlinedArgumentsFrame:
        UNIMPLEMENTED();
    }
  }

  OptionalV<FrameState> BuildParentFrameState(
      maglev::DeoptFrame& frame,
      const maglev::VirtualObject::List& virtual_objects) {
    // Only the topmost frame should have a valid result_location and
    // result_size. One reason for this is that, in Maglev, the PokeAt is not an
    // attribute of the DeoptFrame but rather of the LazyDeoptInfo (to which the
    // topmost frame is attached).
    const interpreter::Register result_location =
        interpreter::Register::invalid_value();
    const int result_size = 0;

    switch (frame.type()) {
      case maglev::DeoptFrame::FrameType::kInterpretedFrame:
        return BuildFrameState(frame.as_interpreted(), virtual_objects,
                               result_location, result_size);
      case maglev::DeoptFrame::FrameType::kConstructInvokeStubFrame:
        return BuildFrameState(frame.as_construct_stub(), virtual_objects);
      case maglev::DeoptFrame::FrameType::kInlinedArgumentsFrame:
        return BuildFrameState(frame.as_inlined_arguments(), virtual_objects);
      case maglev::DeoptFrame::FrameType::kBuiltinContinuationFrame:
        return BuildFrameState(frame.as_builtin_continuation(),
                               virtual_objects);
    }
  }

  OptionalV<FrameState> BuildFrameState(
      maglev::ConstructInvokeStubDeoptFrame& frame,
      const maglev::VirtualObject::List& virtual_objects) {
    FrameStateData::Builder builder;
    if (frame.parent() != nullptr) {
      OptionalV<FrameState> parent_frame =
          BuildParentFrameState(*frame.parent(), virtual_objects);
      if (!parent_frame.has_value()) return OptionalV<FrameState>::Nullopt();
      builder.AddParentFrameState(parent_frame.value());
    }

    // Closure
    // TODO(dmercadier): ConstructInvokeStub frames don't have a Closure input,
    // but the instruction selector assumes that they do and that it should be
    // skipped. We thus use SmiConstant(0) as a fake Closure input here, but it
    // would be nicer to fix the instruction selector to not require this input
    // at all for such frames.
    V<Any> fake_closure_input = __ SmiConstant(0);
    builder.AddInput(MachineType::AnyTagged(), fake_closure_input);

    // Parameters
    AddDeoptInput(builder, virtual_objects, frame.receiver());

    // Context
    AddDeoptInput(builder, virtual_objects, frame.context());

    if (builder.Inputs().size() >
        std::numeric_limits<decltype(Operation::input_count)>::max() - 1) {
      *bailout_ = BailoutReason::kTooManyArguments;
      return OptionalV<FrameState>::Nullopt();
    }

    const FrameStateInfo* frame_state_info = MakeFrameStateInfo(frame);
    return __ FrameState(
        builder.Inputs(), builder.inlined(),
        builder.AllocateFrameStateData(*frame_state_info, graph_zone()));
  }

  OptionalV<FrameState> BuildFrameState(
      maglev::InlinedArgumentsDeoptFrame& frame,
      const maglev::VirtualObject::List& virtual_objects) {
    FrameStateData::Builder builder;
    if (frame.parent() != nullptr) {
      OptionalV<FrameState> parent_frame =
          BuildParentFrameState(*frame.parent(), virtual_objects);
      if (!parent_frame.has_value()) return OptionalV<FrameState>::Nullopt();
      builder.AddParentFrameState(parent_frame.value());
    }

    // Closure
    AddDeoptInput(builder, virtual_objects, frame.closure());

    // Parameters
    for (const maglev::ValueNode* arg : frame.arguments()) {
      AddDeoptInput(builder, virtual_objects, arg);
    }

    // Context
    // TODO(dmercadier): InlinedExtraArguments frames don't have a Context
    // input, but the instruction selector assumes that they do and that it
    // should be skipped. We thus use SmiConstant(0) as a fake Context input
    // here, but it would be nicer to fix the instruction selector to not
    // require this input at all for such frames.
    V<Any> fake_context_input = __ SmiConstant(0);
    builder.AddInput(MachineType::AnyTagged(), fake_context_input);

    if (builder.Inputs().size() >
        std::numeric_limits<decltype(Operation::input_count)>::max() - 1) {
      *bailout_ = BailoutReason::kTooManyArguments;
      return OptionalV<FrameState>::Nullopt();
    }

    const FrameStateInfo* frame_state_info = MakeFrameStateInfo(frame);
    return __ FrameState(
        builder.Inputs(), builder.inlined(),
        builder.AllocateFrameStateData(*frame_state_info, graph_zone()));
  }

  OptionalV<FrameState> BuildFrameState(
      maglev::BuiltinContinuationDeoptFrame& frame,
      const maglev::VirtualObject::List& virtual_objects) {
    FrameStateData::Builder builder;
    if (frame.parent() != nullptr) {
      OptionalV<FrameState> parent_frame =
          BuildParentFrameState(*frame.parent(), virtual_objects);
      if (!parent_frame.has_value()) return OptionalV<FrameState>::Nullopt();
      builder.AddParentFrameState(parent_frame.value());
    }

    // Closure
    if (frame.is_javascript()) {
      builder.AddInput(MachineType::AnyTagged(),
                       __ HeapConstant(frame.javascript_target().object()));
    } else {
      builder.AddUnusedRegister();
    }

    // Parameters
    for (maglev::ValueNode* param : frame.parameters()) {
      AddDeoptInput(builder, virtual_objects, param);
    }

    // Extra fixed JS frame parameters. These are at the end since JS builtins
    // push their parameters in reverse order.
    constexpr int kExtraFixedJSFrameParameters =
        V8_ENABLE_LEAPTIERING_BOOL ? 4 : 3;
    if (frame.is_javascript()) {
      DCHECK_EQ(Builtins::CallInterfaceDescriptorFor(frame.builtin_id())
                    .GetRegisterParameterCount(),
                kExtraFixedJSFrameParameters);
      static_assert(kExtraFixedJSFrameParameters ==
                    3 + (V8_ENABLE_LEAPTIERING_BOOL ? 1 : 0));
      // kJavaScriptCallTargetRegister
      builder.AddInput(MachineType::AnyTagged(),
                       __ HeapConstant(frame.javascript_target().object()));
      // kJavaScriptCallNewTargetRegister
      builder.AddInput(MachineType::AnyTagged(),
                       __ HeapConstant(local_factory_->undefined_value()));
      // kJavaScriptCallArgCountRegister
      builder.AddInput(
          MachineType::AnyTagged(),
          __ SmiConstant(Smi::FromInt(
              Builtins::GetStackParameterCount(frame.builtin_id()))));
#ifdef V8_ENABLE_LEAPTIERING
      // kJavaScriptCallDispatchHandleRegister
      builder.AddInput(MachineType::AnyTagged(),
                       __ SmiConstant(Smi::FromInt(kInvalidDispatchHandle)));
#endif
    }

    // Context
    AddDeoptInput(builder, virtual_objects, frame.context());

    if (builder.Inputs().size() >
        std::numeric_limits<decltype(Operation::input_count)>::max() - 1) {
      *bailout_ = BailoutReason::kTooManyArguments;
      return OptionalV<FrameState>::Nullopt();
    }

    const FrameStateInfo* frame_state_info = MakeFrameStateInfo(frame);
    return __ FrameState(
        builder.Inputs(), builder.inlined(),
        builder.AllocateFrameStateData(*frame_state_info, graph_zone()));
  }

  OptionalV<FrameState> BuildFrameState(
      maglev::InterpretedDeoptFrame& frame,
      const maglev::VirtualObject::List& virtual_objects,
      interpreter::Register result_location, int result_size) {
    DCHECK_EQ(result_size != 0, result_location.is_valid());
    FrameStateData::Builder builder;

    if (frame.parent() != nullptr) {
      OptionalV<FrameState> parent_frame =
          BuildParentFrameState(*frame.parent(), virtual_objects);
      if (!parent_frame.has_value()) return OptionalV<FrameState>::Nullopt();
      builder.AddParentFrameState(parent_frame.value());
    }

    // Closure
    AddDeoptInput(builder, virtual_objects, frame.closure());

    // Parameters
    frame.frame_state()->ForEachParameter(
        frame.unit(), [&](maglev::ValueNode* value, interpreter::Register reg) {
          AddDeoptInput(builder, virtual_objects, value, reg, result_location,
                        result_size);
        });

    // Context
    AddDeoptInput(builder, virtual_objects,
                  frame.frame_state()->context(frame.unit()));

    // Locals
    // ForEachLocal in Maglev skips over dead registers, but we still need to
    // call AddUnusedRegister on the Turboshaft FrameStateData Builder.
    // {local_index} is used to keep track of such unused registers.
    // Among the variables not included in ForEachLocal is the Accumulator (but
    // this is fine since there is an entry in the state specifically for the
    // accumulator later).
    int local_index = 0;
    frame.frame_state()->ForEachLocal(
        frame.unit(), [&](maglev::ValueNode* value, interpreter::Register reg) {
          while (local_index < reg.index()) {
            builder.AddUnusedRegister();
            local_index++;
          }
          AddDeoptInput(builder, virtual_objects, value, reg, result_location,
                        result_size);
          local_index++;
        });
    for (; local_index < frame.unit().register_count(); local_index++) {
      builder.AddUnusedRegister();
    }

    // Accumulator
    if (frame.frame_state()->liveness()->AccumulatorIsLive()) {
      AddDeoptInput(builder, virtual_objects,
                    frame.frame_state()->accumulator(frame.unit()),
                    interpreter::Register::virtual_accumulator(),
                    result_location, result_size);
    } else {
      builder.AddUnusedRegister();
    }

    OutputFrameStateCombine combine =
        ComputeCombine(frame, result_location, result_size);

    if (builder.Inputs().size() >
        std::numeric_limits<decltype(Operation::input_count)>::max() - 1) {
      *bailout_ = BailoutReason::kTooManyArguments;
      return OptionalV<FrameState>::Nullopt();
    }

    const FrameStateInfo* frame_state_info = MakeFrameStateInfo(frame, combine);
    return __ FrameState(
        builder.Inputs(), builder.inlined(),
        builder.AllocateFrameStateData(*frame_state_info, graph_zone()));
  }

  void AddDeoptInput(FrameStateData::Builder& builder,
                     const maglev::VirtualObject::List& virtual_objects,
                     const maglev::ValueNode* node) {
    if (const maglev::InlinedAllocation* alloc =
            node->TryCast<maglev::InlinedAllocation>()) {
      DCHECK(alloc->HasBeenAnalysed());
      if (alloc->HasBeenElided()) {
        AddVirtualObjectInput(builder, virtual_objects,
                              virtual_objects.FindAllocatedWith(alloc));
        return;
      }
    }
    if (const maglev::Identity* ident_obj = node->TryCast<maglev::Identity>()) {
      // The value_representation of Identity nodes is always Tagged rather than
      // the actual value_representation of their input. We thus bypass identity
      // nodes manually here to get to correct value_representation and thus the
      // correct MachineType.
      node = ident_obj->input(0).node();
      // Identity nodes should not have Identity as input.
      DCHECK(!node->Is<maglev::Identity>());
    }
    builder.AddInput(MachineTypeFor(node->value_representation()), Map(node));
  }

  void AddDeoptInput(FrameStateData::Builder& builder,
                     const maglev::VirtualObject::List& virtual_objects,
                     const maglev::ValueNode* node, interpreter::Register reg,
                     interpreter::Register result_location, int result_size) {
    if (result_location.is_valid() && maglev::LazyDeoptInfo::InReturnValues(
                                          reg, result_location, result_size)) {
      builder.AddUnusedRegister();
    } else {
      AddDeoptInput(builder, virtual_objects, node);
    }
  }

  void AddVirtualObjectInput(FrameStateData::Builder& builder,
                             const maglev::VirtualObject::List& virtual_objects,
                             const maglev::VirtualObject* vobj) {
    if (vobj->type() == maglev::VirtualObject::kHeapNumber) {
      // We need to add HeapNumbers as dematerialized HeapNumbers (rather than
      // simply NumberConstant), because they could be mutable HeapNumber
      // fields, in which case we don't want GVN to merge them.
      constexpr int kNumberOfField = 2;  // map + value
      builder.AddDematerializedObject(deduplicator_.CreateFreshId().id,
                                      kNumberOfField);
      builder.AddInput(MachineType::AnyTagged(),
                       __ HeapConstant(local_factory_->heap_number_map()));
      builder.AddInput(MachineType::Float64(),
                       __ Float64Constant(vobj->number()));
      return;
    }

    Deduplicator::DuplicatedId dup_id = deduplicator_.GetDuplicatedId(vobj);
    if (dup_id.duplicated) {
      builder.AddDematerializedObjectReference(dup_id.id);
      return;
    }
    if (vobj->type() == maglev::VirtualObject::kFixedDoubleArray) {
      constexpr int kMapAndLengthFieldCount = 2;
      uint32_t length = vobj->double_elements_length();
      uint32_t field_count = length + kMapAndLengthFieldCount;
      builder.AddDematerializedObject(dup_id.id, field_count);
      builder.AddInput(
          MachineType::AnyTagged(),
          __ HeapConstantNoHole(local_factory_->fixed_double_array_map()));
      builder.AddInput(MachineType::AnyTagged(),
                       __ SmiConstant(Smi::FromInt(length)));
      FixedDoubleArrayRef elements = vobj->double_elements();
      for (uint32_t i = 0; i < length; i++) {
        i::Float64 value = elements.GetFromImmutableFixedDoubleArray(i);
        if (value.is_hole_nan()) {
          builder.AddInput(
              MachineType::AnyTagged(),
              __ HeapConstantHole(local_factory_->the_hole_value()));
        } else {
          builder.AddInput(MachineType::AnyTagged(),
                           __ NumberConstant(value.get_scalar()));
        }
      }
      return;
    }

    DCHECK_EQ(vobj->type(), maglev::VirtualObject::kDefault);
    constexpr int kMapFieldCount = 1;
    uint32_t field_count = vobj->slot_count() + kMapFieldCount;
    builder.AddDematerializedObject(dup_id.id, field_count);
    builder.AddInput(MachineType::AnyTagged(),
                     __ HeapConstantNoHole(vobj->map().object()));
    for (uint32_t i = 0; i < vobj->slot_count(); i++) {
      AddVirtualObjectNestedValue(builder, virtual_objects,
                                  vobj->get_by_index(i));
    }
  }

  void AddVirtualObjectNestedValue(
      FrameStateData::Builder& builder,
      const maglev::VirtualObject::List& virtual_objects,
      const maglev::ValueNode* value) {
    if (maglev::IsConstantNode(value->opcode())) {
      switch (value->opcode()) {
        case maglev::Opcode::kConstant:
          builder.AddInput(
              MachineType::AnyTagged(),
              __ HeapConstant(value->Cast<maglev::Constant>()->ref().object()));
          break;

        case maglev::Opcode::kFloat64Constant:
          builder.AddInput(
              MachineType::AnyTagged(),
              __ NumberConstant(value->Cast<maglev::Float64Constant>()
                                    ->value()
                                    .get_scalar()));
          break;

        case maglev::Opcode::kInt32Constant:
          builder.AddInput(
              MachineType::AnyTagged(),
              __ NumberConstant(value->Cast<maglev::Int32Constant>()->value()));
          break;

        case maglev::Opcode::kUint32Constant:
          builder.AddInput(MachineType::AnyTagged(),
                           __ Number
Prompt: 
```
这是目录为v8/src/compiler/turboshaft/maglev-graph-building-phase.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/maglev-graph-building-phase.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共9部分，请归纳一下它的功能

"""
aglev::ProcessResult Process(maglev::Float64ToUint8Clamped* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, Float64ToUint8Clamped(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckedNumberToUint8Clamped* node,
                                const maglev::ProcessingState& state) {
    ScopedVar<Word32, AssemblerT> result(this);
    V<Object> value = Map(node->input());
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    IF (__ IsSmi(value)) {
      result = Int32ToUint8Clamped(__ UntagSmi(V<Smi>::Cast(value)));
    } ELSE {
      V<i::Map> map = __ LoadMapField(value);
      __ DeoptimizeIfNot(
          __ TaggedEqual(map,
                         __ HeapConstant(local_factory_->heap_number_map())),
          frame_state, DeoptimizeReason::kNotAHeapNumber,
          node->eager_deopt_info()->feedback_to_update());
      result = Float64ToUint8Clamped(
          __ LoadHeapNumberValue(V<HeapNumber>::Cast(value)));
    }
    RETURN_IF_UNREACHABLE();
    SetMap(node, result);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::ToObject* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
    OpIndex arguments[] = {Map(node->value_input()), Map(node->context())};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kToObject, frame_state,
                                  base::VectorOf(arguments));

    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Return* node,
                                const maglev::ProcessingState& state) {
    __ Return(Map(node->value_input()));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Deopt* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ Deoptimize(frame_state, node->reason(),
                  node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::SetPendingMessage* node,
                                const maglev::ProcessingState& state) {
    V<WordPtr> message_address = __ ExternalConstant(
        ExternalReference::address_of_pending_message(isolate_));
    V<Object> old_message = __ LoadMessage(message_address);
    __ StoreMessage(message_address, Map(node->value()));
    SetMap(node, old_message);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::GeneratorStore* node,
                                const maglev::ProcessingState& state) {
    base::SmallVector<OpIndex, 32> parameters_and_registers;
    int num_parameters_and_registers = node->num_parameters_and_registers();
    for (int i = 0; i < num_parameters_and_registers; i++) {
      parameters_and_registers.push_back(
          Map(node->parameters_and_registers(i)));
    }
    __ GeneratorStore(Map(node->context_input()), Map(node->generator_input()),
                      parameters_and_registers, node->suspend_id(),
                      node->bytecode_offset());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::GeneratorRestoreRegister* node,
                                const maglev::ProcessingState& state) {
    V<FixedArray> array = Map(node->array_input());
    V<Object> result =
        __ LoadTaggedField(array, FixedArray::OffsetOfElementAt(node->index()));
    __ Store(array, Map(node->stale_input()), StoreOp::Kind::TaggedBase(),
             MemoryRepresentation::TaggedSigned(),
             WriteBarrierKind::kNoWriteBarrier,
             FixedArray::OffsetOfElementAt(node->index()));

    SetMap(node, result);

    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Abort* node,
                                const maglev::ProcessingState& state) {
    __ RuntimeAbort(node->reason());
    // TODO(dmercadier): remove this `Unreachable` once RuntimeAbort is marked
    // as a block terminator.
    __ Unreachable();
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Identity* node,
                                const maglev::ProcessingState&) {
    SetMap(node, Map(node->input(0)));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Dead*, const maglev::ProcessingState&) {
    // Nothing to do; `Dead` is in Maglev to kill a node when removing it
    // directly from the graph is not possible.
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::DebugBreak*,
                                const maglev::ProcessingState&) {
    __ DebugBreak();
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::GapMove*,
                                const maglev::ProcessingState&) {
    // GapMove nodes are created by Maglev's register allocator, which
    // doesn't run when using Maglev as a frontend for Turboshaft.
    UNREACHABLE();
  }
  maglev::ProcessResult Process(maglev::ConstantGapMove*,
                                const maglev::ProcessingState&) {
    // ConstantGapMove nodes are created by Maglev's register allocator, which
    // doesn't run when using Maglev as a frontend for Turboshaft.
    UNREACHABLE();
  }

  maglev::ProcessResult Process(maglev::VirtualObject*,
                                const maglev::ProcessingState&) {
    // VirtualObjects should never be part of the Maglev graph.
    UNREACHABLE();
  }

  maglev::ProcessResult Process(maglev::GetSecondReturnedValue* node,
                                const maglev::ProcessingState& state) {
    DCHECK(second_return_value_.valid());
    SetMap(node, second_return_value_);

#ifdef DEBUG
    second_return_value_ = V<Object>::Invalid();
#endif

    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::TryOnStackReplacement*,
                                const maglev::ProcessingState&) {
    // Turboshaft is the top tier compiler, so we never need to OSR from it.
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::ReduceInterruptBudgetForReturn*,
                                const maglev::ProcessingState&) {
    // No need to update the interrupt budget once we reach Turboshaft.
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::ReduceInterruptBudgetForLoop* node,
                                const maglev::ProcessingState&) {
    // ReduceInterruptBudgetForLoop nodes are not emitted by Maglev when it is
    // used as a frontend for Turboshaft.
    UNREACHABLE();
  }
  maglev::ProcessResult Process(maglev::HandleNoHeapWritesInterrupt* node,
                                const maglev::ProcessingState&) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
    __ JSLoopStackCheck(native_context(), frame_state);
    return maglev::ProcessResult::kContinue;
  }

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  maglev::ProcessResult Process(
      maglev::GetContinuationPreservedEmbedderData* node,
      const maglev::ProcessingState&) {
    V<Object> data = __ GetContinuationPreservedEmbedderData();
    SetMap(node, data);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(
      maglev::SetContinuationPreservedEmbedderData* node,
      const maglev::ProcessingState&) {
    V<Object> data = Map(node->input(0));
    __ SetContinuationPreservedEmbedderData(data);
    return maglev::ProcessResult::kContinue;
  }
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

  maglev::ProcessResult Process(maglev::AssertInt32* node,
                                const maglev::ProcessingState&) {
    bool negate_result = false;
    V<Word32> cmp = ConvertInt32Compare(node->left_input(), node->right_input(),
                                        node->condition(), &negate_result);
    Label<> abort(this);
    Label<> end(this);
    if (negate_result) {
      GOTO_IF(cmp, abort);
    } else {
      GOTO_IF_NOT(cmp, abort);
    }
    GOTO(end);

    BIND(abort);
    __ RuntimeAbort(node->reason());
    __ Unreachable();

    BIND(end);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::CallSelf*,
                                const maglev::ProcessingState&) {
    // CallSelf nodes are only created when Maglev is the top-tier compiler
    // (which can't be the case here, since we're currently compiling for
    // Turboshaft).
    UNREACHABLE();
  }

  // Nodes unused by maglev but still existing.
  maglev::ProcessResult Process(maglev::ExternalConstant*,
                                const maglev::ProcessingState&) {
    UNREACHABLE();
  }
  maglev::ProcessResult Process(maglev::CallCPPBuiltin*,
                                const maglev::ProcessingState&) {
    UNREACHABLE();
  }
  maglev::ProcessResult Process(maglev::UnsafeTruncateUint32ToInt32*,
                                const maglev::ProcessingState&) {
    UNREACHABLE();
  }
  maglev::ProcessResult Process(maglev::UnsafeTruncateFloat64ToInt32*,
                                const maglev::ProcessingState&) {
    UNREACHABLE();
  }
  maglev::ProcessResult Process(maglev::BranchIfTypeOf*,
                                const maglev::ProcessingState&) {
    UNREACHABLE();
  }

  AssemblerT& Asm() { return assembler_; }
  Zone* temp_zone() { return temp_zone_; }
  Zone* graph_zone() { return Asm().output_graph().graph_zone(); }

 private:
  OptionalV<FrameState> BuildFrameState(
      maglev::EagerDeoptInfo* eager_deopt_info) {
    deduplicator_.Reset();
    // Eager deopts don't have a result location/size.
    const interpreter::Register result_location =
        interpreter::Register::invalid_value();
    const int result_size = 0;
    const maglev::VirtualObject::List& virtual_objects =
        maglev::GetVirtualObjects(eager_deopt_info->top_frame());

    switch (eager_deopt_info->top_frame().type()) {
      case maglev::DeoptFrame::FrameType::kInterpretedFrame:
        return BuildFrameState(eager_deopt_info->top_frame().as_interpreted(),
                               virtual_objects, result_location, result_size);
      case maglev::DeoptFrame::FrameType::kBuiltinContinuationFrame:
        return BuildFrameState(
            eager_deopt_info->top_frame().as_builtin_continuation(),
            virtual_objects);
      case maglev::DeoptFrame::FrameType::kInlinedArgumentsFrame:
      case maglev::DeoptFrame::FrameType::kConstructInvokeStubFrame:
        UNIMPLEMENTED();
    }
  }

  OptionalV<FrameState> BuildFrameState(
      maglev::LazyDeoptInfo* lazy_deopt_info) {
    deduplicator_.Reset();
    const maglev::VirtualObject::List& virtual_objects =
        maglev::GetVirtualObjects(lazy_deopt_info->top_frame());
    switch (lazy_deopt_info->top_frame().type()) {
      case maglev::DeoptFrame::FrameType::kInterpretedFrame:
        return BuildFrameState(
            lazy_deopt_info->top_frame().as_interpreted(), virtual_objects,
            lazy_deopt_info->result_location(), lazy_deopt_info->result_size());
      case maglev::DeoptFrame::FrameType::kConstructInvokeStubFrame:
        return BuildFrameState(lazy_deopt_info->top_frame().as_construct_stub(),
                               virtual_objects);

      case maglev::DeoptFrame::FrameType::kBuiltinContinuationFrame:
        return BuildFrameState(
            lazy_deopt_info->top_frame().as_builtin_continuation(),
            virtual_objects);

      case maglev::DeoptFrame::FrameType::kInlinedArgumentsFrame:
        UNIMPLEMENTED();
    }
  }

  OptionalV<FrameState> BuildParentFrameState(
      maglev::DeoptFrame& frame,
      const maglev::VirtualObject::List& virtual_objects) {
    // Only the topmost frame should have a valid result_location and
    // result_size. One reason for this is that, in Maglev, the PokeAt is not an
    // attribute of the DeoptFrame but rather of the LazyDeoptInfo (to which the
    // topmost frame is attached).
    const interpreter::Register result_location =
        interpreter::Register::invalid_value();
    const int result_size = 0;

    switch (frame.type()) {
      case maglev::DeoptFrame::FrameType::kInterpretedFrame:
        return BuildFrameState(frame.as_interpreted(), virtual_objects,
                               result_location, result_size);
      case maglev::DeoptFrame::FrameType::kConstructInvokeStubFrame:
        return BuildFrameState(frame.as_construct_stub(), virtual_objects);
      case maglev::DeoptFrame::FrameType::kInlinedArgumentsFrame:
        return BuildFrameState(frame.as_inlined_arguments(), virtual_objects);
      case maglev::DeoptFrame::FrameType::kBuiltinContinuationFrame:
        return BuildFrameState(frame.as_builtin_continuation(),
                               virtual_objects);
    }
  }

  OptionalV<FrameState> BuildFrameState(
      maglev::ConstructInvokeStubDeoptFrame& frame,
      const maglev::VirtualObject::List& virtual_objects) {
    FrameStateData::Builder builder;
    if (frame.parent() != nullptr) {
      OptionalV<FrameState> parent_frame =
          BuildParentFrameState(*frame.parent(), virtual_objects);
      if (!parent_frame.has_value()) return OptionalV<FrameState>::Nullopt();
      builder.AddParentFrameState(parent_frame.value());
    }

    // Closure
    // TODO(dmercadier): ConstructInvokeStub frames don't have a Closure input,
    // but the instruction selector assumes that they do and that it should be
    // skipped. We thus use SmiConstant(0) as a fake Closure input here, but it
    // would be nicer to fix the instruction selector to not require this input
    // at all for such frames.
    V<Any> fake_closure_input = __ SmiConstant(0);
    builder.AddInput(MachineType::AnyTagged(), fake_closure_input);

    // Parameters
    AddDeoptInput(builder, virtual_objects, frame.receiver());

    // Context
    AddDeoptInput(builder, virtual_objects, frame.context());

    if (builder.Inputs().size() >
        std::numeric_limits<decltype(Operation::input_count)>::max() - 1) {
      *bailout_ = BailoutReason::kTooManyArguments;
      return OptionalV<FrameState>::Nullopt();
    }

    const FrameStateInfo* frame_state_info = MakeFrameStateInfo(frame);
    return __ FrameState(
        builder.Inputs(), builder.inlined(),
        builder.AllocateFrameStateData(*frame_state_info, graph_zone()));
  }

  OptionalV<FrameState> BuildFrameState(
      maglev::InlinedArgumentsDeoptFrame& frame,
      const maglev::VirtualObject::List& virtual_objects) {
    FrameStateData::Builder builder;
    if (frame.parent() != nullptr) {
      OptionalV<FrameState> parent_frame =
          BuildParentFrameState(*frame.parent(), virtual_objects);
      if (!parent_frame.has_value()) return OptionalV<FrameState>::Nullopt();
      builder.AddParentFrameState(parent_frame.value());
    }

    // Closure
    AddDeoptInput(builder, virtual_objects, frame.closure());

    // Parameters
    for (const maglev::ValueNode* arg : frame.arguments()) {
      AddDeoptInput(builder, virtual_objects, arg);
    }

    // Context
    // TODO(dmercadier): InlinedExtraArguments frames don't have a Context
    // input, but the instruction selector assumes that they do and that it
    // should be skipped. We thus use SmiConstant(0) as a fake Context input
    // here, but it would be nicer to fix the instruction selector to not
    // require this input at all for such frames.
    V<Any> fake_context_input = __ SmiConstant(0);
    builder.AddInput(MachineType::AnyTagged(), fake_context_input);

    if (builder.Inputs().size() >
        std::numeric_limits<decltype(Operation::input_count)>::max() - 1) {
      *bailout_ = BailoutReason::kTooManyArguments;
      return OptionalV<FrameState>::Nullopt();
    }

    const FrameStateInfo* frame_state_info = MakeFrameStateInfo(frame);
    return __ FrameState(
        builder.Inputs(), builder.inlined(),
        builder.AllocateFrameStateData(*frame_state_info, graph_zone()));
  }

  OptionalV<FrameState> BuildFrameState(
      maglev::BuiltinContinuationDeoptFrame& frame,
      const maglev::VirtualObject::List& virtual_objects) {
    FrameStateData::Builder builder;
    if (frame.parent() != nullptr) {
      OptionalV<FrameState> parent_frame =
          BuildParentFrameState(*frame.parent(), virtual_objects);
      if (!parent_frame.has_value()) return OptionalV<FrameState>::Nullopt();
      builder.AddParentFrameState(parent_frame.value());
    }

    // Closure
    if (frame.is_javascript()) {
      builder.AddInput(MachineType::AnyTagged(),
                       __ HeapConstant(frame.javascript_target().object()));
    } else {
      builder.AddUnusedRegister();
    }

    // Parameters
    for (maglev::ValueNode* param : frame.parameters()) {
      AddDeoptInput(builder, virtual_objects, param);
    }

    // Extra fixed JS frame parameters. These are at the end since JS builtins
    // push their parameters in reverse order.
    constexpr int kExtraFixedJSFrameParameters =
        V8_ENABLE_LEAPTIERING_BOOL ? 4 : 3;
    if (frame.is_javascript()) {
      DCHECK_EQ(Builtins::CallInterfaceDescriptorFor(frame.builtin_id())
                    .GetRegisterParameterCount(),
                kExtraFixedJSFrameParameters);
      static_assert(kExtraFixedJSFrameParameters ==
                    3 + (V8_ENABLE_LEAPTIERING_BOOL ? 1 : 0));
      // kJavaScriptCallTargetRegister
      builder.AddInput(MachineType::AnyTagged(),
                       __ HeapConstant(frame.javascript_target().object()));
      // kJavaScriptCallNewTargetRegister
      builder.AddInput(MachineType::AnyTagged(),
                       __ HeapConstant(local_factory_->undefined_value()));
      // kJavaScriptCallArgCountRegister
      builder.AddInput(
          MachineType::AnyTagged(),
          __ SmiConstant(Smi::FromInt(
              Builtins::GetStackParameterCount(frame.builtin_id()))));
#ifdef V8_ENABLE_LEAPTIERING
      // kJavaScriptCallDispatchHandleRegister
      builder.AddInput(MachineType::AnyTagged(),
                       __ SmiConstant(Smi::FromInt(kInvalidDispatchHandle)));
#endif
    }

    // Context
    AddDeoptInput(builder, virtual_objects, frame.context());

    if (builder.Inputs().size() >
        std::numeric_limits<decltype(Operation::input_count)>::max() - 1) {
      *bailout_ = BailoutReason::kTooManyArguments;
      return OptionalV<FrameState>::Nullopt();
    }

    const FrameStateInfo* frame_state_info = MakeFrameStateInfo(frame);
    return __ FrameState(
        builder.Inputs(), builder.inlined(),
        builder.AllocateFrameStateData(*frame_state_info, graph_zone()));
  }

  OptionalV<FrameState> BuildFrameState(
      maglev::InterpretedDeoptFrame& frame,
      const maglev::VirtualObject::List& virtual_objects,
      interpreter::Register result_location, int result_size) {
    DCHECK_EQ(result_size != 0, result_location.is_valid());
    FrameStateData::Builder builder;

    if (frame.parent() != nullptr) {
      OptionalV<FrameState> parent_frame =
          BuildParentFrameState(*frame.parent(), virtual_objects);
      if (!parent_frame.has_value()) return OptionalV<FrameState>::Nullopt();
      builder.AddParentFrameState(parent_frame.value());
    }

    // Closure
    AddDeoptInput(builder, virtual_objects, frame.closure());

    // Parameters
    frame.frame_state()->ForEachParameter(
        frame.unit(), [&](maglev::ValueNode* value, interpreter::Register reg) {
          AddDeoptInput(builder, virtual_objects, value, reg, result_location,
                        result_size);
        });

    // Context
    AddDeoptInput(builder, virtual_objects,
                  frame.frame_state()->context(frame.unit()));

    // Locals
    // ForEachLocal in Maglev skips over dead registers, but we still need to
    // call AddUnusedRegister on the Turboshaft FrameStateData Builder.
    // {local_index} is used to keep track of such unused registers.
    // Among the variables not included in ForEachLocal is the Accumulator (but
    // this is fine since there is an entry in the state specifically for the
    // accumulator later).
    int local_index = 0;
    frame.frame_state()->ForEachLocal(
        frame.unit(), [&](maglev::ValueNode* value, interpreter::Register reg) {
          while (local_index < reg.index()) {
            builder.AddUnusedRegister();
            local_index++;
          }
          AddDeoptInput(builder, virtual_objects, value, reg, result_location,
                        result_size);
          local_index++;
        });
    for (; local_index < frame.unit().register_count(); local_index++) {
      builder.AddUnusedRegister();
    }

    // Accumulator
    if (frame.frame_state()->liveness()->AccumulatorIsLive()) {
      AddDeoptInput(builder, virtual_objects,
                    frame.frame_state()->accumulator(frame.unit()),
                    interpreter::Register::virtual_accumulator(),
                    result_location, result_size);
    } else {
      builder.AddUnusedRegister();
    }

    OutputFrameStateCombine combine =
        ComputeCombine(frame, result_location, result_size);

    if (builder.Inputs().size() >
        std::numeric_limits<decltype(Operation::input_count)>::max() - 1) {
      *bailout_ = BailoutReason::kTooManyArguments;
      return OptionalV<FrameState>::Nullopt();
    }

    const FrameStateInfo* frame_state_info = MakeFrameStateInfo(frame, combine);
    return __ FrameState(
        builder.Inputs(), builder.inlined(),
        builder.AllocateFrameStateData(*frame_state_info, graph_zone()));
  }

  void AddDeoptInput(FrameStateData::Builder& builder,
                     const maglev::VirtualObject::List& virtual_objects,
                     const maglev::ValueNode* node) {
    if (const maglev::InlinedAllocation* alloc =
            node->TryCast<maglev::InlinedAllocation>()) {
      DCHECK(alloc->HasBeenAnalysed());
      if (alloc->HasBeenElided()) {
        AddVirtualObjectInput(builder, virtual_objects,
                              virtual_objects.FindAllocatedWith(alloc));
        return;
      }
    }
    if (const maglev::Identity* ident_obj = node->TryCast<maglev::Identity>()) {
      // The value_representation of Identity nodes is always Tagged rather than
      // the actual value_representation of their input. We thus bypass identity
      // nodes manually here to get to correct value_representation and thus the
      // correct MachineType.
      node = ident_obj->input(0).node();
      // Identity nodes should not have Identity as input.
      DCHECK(!node->Is<maglev::Identity>());
    }
    builder.AddInput(MachineTypeFor(node->value_representation()), Map(node));
  }

  void AddDeoptInput(FrameStateData::Builder& builder,
                     const maglev::VirtualObject::List& virtual_objects,
                     const maglev::ValueNode* node, interpreter::Register reg,
                     interpreter::Register result_location, int result_size) {
    if (result_location.is_valid() && maglev::LazyDeoptInfo::InReturnValues(
                                          reg, result_location, result_size)) {
      builder.AddUnusedRegister();
    } else {
      AddDeoptInput(builder, virtual_objects, node);
    }
  }

  void AddVirtualObjectInput(FrameStateData::Builder& builder,
                             const maglev::VirtualObject::List& virtual_objects,
                             const maglev::VirtualObject* vobj) {
    if (vobj->type() == maglev::VirtualObject::kHeapNumber) {
      // We need to add HeapNumbers as dematerialized HeapNumbers (rather than
      // simply NumberConstant), because they could be mutable HeapNumber
      // fields, in which case we don't want GVN to merge them.
      constexpr int kNumberOfField = 2;  // map + value
      builder.AddDematerializedObject(deduplicator_.CreateFreshId().id,
                                      kNumberOfField);
      builder.AddInput(MachineType::AnyTagged(),
                       __ HeapConstant(local_factory_->heap_number_map()));
      builder.AddInput(MachineType::Float64(),
                       __ Float64Constant(vobj->number()));
      return;
    }

    Deduplicator::DuplicatedId dup_id = deduplicator_.GetDuplicatedId(vobj);
    if (dup_id.duplicated) {
      builder.AddDematerializedObjectReference(dup_id.id);
      return;
    }
    if (vobj->type() == maglev::VirtualObject::kFixedDoubleArray) {
      constexpr int kMapAndLengthFieldCount = 2;
      uint32_t length = vobj->double_elements_length();
      uint32_t field_count = length + kMapAndLengthFieldCount;
      builder.AddDematerializedObject(dup_id.id, field_count);
      builder.AddInput(
          MachineType::AnyTagged(),
          __ HeapConstantNoHole(local_factory_->fixed_double_array_map()));
      builder.AddInput(MachineType::AnyTagged(),
                       __ SmiConstant(Smi::FromInt(length)));
      FixedDoubleArrayRef elements = vobj->double_elements();
      for (uint32_t i = 0; i < length; i++) {
        i::Float64 value = elements.GetFromImmutableFixedDoubleArray(i);
        if (value.is_hole_nan()) {
          builder.AddInput(
              MachineType::AnyTagged(),
              __ HeapConstantHole(local_factory_->the_hole_value()));
        } else {
          builder.AddInput(MachineType::AnyTagged(),
                           __ NumberConstant(value.get_scalar()));
        }
      }
      return;
    }

    DCHECK_EQ(vobj->type(), maglev::VirtualObject::kDefault);
    constexpr int kMapFieldCount = 1;
    uint32_t field_count = vobj->slot_count() + kMapFieldCount;
    builder.AddDematerializedObject(dup_id.id, field_count);
    builder.AddInput(MachineType::AnyTagged(),
                     __ HeapConstantNoHole(vobj->map().object()));
    for (uint32_t i = 0; i < vobj->slot_count(); i++) {
      AddVirtualObjectNestedValue(builder, virtual_objects,
                                  vobj->get_by_index(i));
    }
  }

  void AddVirtualObjectNestedValue(
      FrameStateData::Builder& builder,
      const maglev::VirtualObject::List& virtual_objects,
      const maglev::ValueNode* value) {
    if (maglev::IsConstantNode(value->opcode())) {
      switch (value->opcode()) {
        case maglev::Opcode::kConstant:
          builder.AddInput(
              MachineType::AnyTagged(),
              __ HeapConstant(value->Cast<maglev::Constant>()->ref().object()));
          break;

        case maglev::Opcode::kFloat64Constant:
          builder.AddInput(
              MachineType::AnyTagged(),
              __ NumberConstant(value->Cast<maglev::Float64Constant>()
                                    ->value()
                                    .get_scalar()));
          break;

        case maglev::Opcode::kInt32Constant:
          builder.AddInput(
              MachineType::AnyTagged(),
              __ NumberConstant(value->Cast<maglev::Int32Constant>()->value()));
          break;

        case maglev::Opcode::kUint32Constant:
          builder.AddInput(MachineType::AnyTagged(),
                           __ NumberConstant(
                               value->Cast<maglev::Uint32Constant>()->value()));
          break;

        case maglev::Opcode::kRootConstant:
          builder.AddInput(
              MachineType::AnyTagged(),
              (__ HeapConstant(Cast<HeapObject>(isolate_->root_handle(
                  value->Cast<maglev::RootConstant>()->index())))));
          break;

        case maglev::Opcode::kSmiConstant:
          builder.AddInput(
              MachineType::AnyTagged(),
              __ SmiConstant(value->Cast<maglev::SmiConstant>()->value()));
          break;

        case maglev::Opcode::kTrustedConstant:
          builder.AddInput(
              MachineType::AnyTagged(),
              __ TrustedHeapConstant(
                  value->Cast<maglev::TrustedConstant>()->object().object()));
          break;

        case maglev::Opcode::kTaggedIndexConstant:
        case maglev::Opcode::kExternalConstant:
        default:
          UNREACHABLE();
      }
      return;
    }

    // Special nodes.
    switch (value->opcode()) {
      case maglev::Opcode::kArgumentsElements:
        builder.AddArgumentsElements(
            value->Cast<maglev::ArgumentsElements>()->type());
        break;
      case maglev::Opcode::kArgumentsLength:
        builder.AddArgumentsLength();
        break;
      case maglev::Opcode::kRestLength:
        builder.AddRestLength();
        break;
      case maglev::Opcode::kVirtualObject:
        UNREACHABLE();
      default:
        AddDeoptInput(builder, virtual_objects, value);
        break;
    }
  }

  class Deduplicator {
   public:
    struct DuplicatedId {
      uint32_t id;
      bool duplicated;
    };
    DuplicatedId GetDuplicatedId(const maglev::VirtualObject* object) {
      // TODO(dmercadier): do better than a linear search here.
      for (uint32_t idx = 0; idx < object_ids_.size(); idx++) {
        if (object_ids_[idx] == object) {
          return {idx, true};
        }
      }
      object_ids_.push_back(object);
      return {next_id_++, false};
    }

    DuplicatedId CreateFreshId() { return {next_id_++, false}; }

    void Reset() {
      object_ids_.clear();
      next_id_ = 0;
    }

    static const uint32_t kNotDuplicated = -1;

   private:
    std::vector<const maglev::VirtualObject*> object_ids_{10};
    uint32_t next_id_ = 0;
  };

  OutputFrameStateCombine ComputeCombine(maglev::InterpretedDeoptFrame& frame,
                                         interpreter::Register result_location,
                                         int result_size) {
    if (result_size == 0) {
      return OutputFrameStateCombine::Ignore();
    }
    return OutputFrameStateCombine::PokeAt(
        frame.ComputeReturnOffset(result_location, result_size));
  }

  const FrameStateInfo* MakeFrameStateInfo(
      maglev::InterpretedDeoptFrame& maglev_frame,
      OutputFrameStateCombine combine) {
    FrameStateType type = FrameStateType::kUnoptimizedFunction;
    uint16_t parameter_count = maglev_frame.unit().parameter_count();
    uint16_t max_arguments = maglev_frame.unit().max_arguments();
    int local_count = maglev_frame.unit().register_count();
    Handle<SharedFunctionInfo> shared_info =
        maglev_frame.unit().shared_function_info().object();
    Handle<BytecodeArray> bytecode_array =
        maglev_frame.unit().bytecode().object();
    FrameStateFunctionInfo* info = graph_zone()->New<FrameStateFunctionInfo>(
        type, parameter_count, max_arguments, local_count, shared_info,
        bytecode_array);

    return graph_zone()->New<FrameStateInfo>(maglev_frame.bytecode_position(),
                                             combine, info);
  }

  const FrameStateInfo* MakeFrameStateInfo(
      maglev::InlinedArgumentsDeoptFrame& maglev_frame) {
    FrameStateType type = FrameStateType::kInlinedExtraArguments;
    uint16_t parameter_count =
        static_cast<uint16_t>(maglev_frame.arguments().size());
    uint16_t max_arguments = 0;
    int local_count = 0;
    Handle<SharedFunctionInfo> shared_info =
        maglev_frame.unit().shared_function_info().object();
    FrameStateFunctionInfo* info = graph_zone()->New<FrameStateFunctionInfo>(
        type, parameter_count, max_arguments, local_count, shared_info,
        kNullMaybeHandle);

    return graph_zone()->New<FrameStateInfo>(maglev_frame.bytecode_position(),
                                             OutputFrameStateCombine::Ignore(),
                                             info);
  }

  const FrameStateInfo* MakeFrameStateInfo(
      maglev::ConstructInvokeStubDeoptFrame& maglev_frame) {
    FrameStateType type = FrameStateType::kConstructInvokeStub;
    Handle<SharedFunctionInfo> shared_info =
        maglev_frame.unit().shared_function_info().object();
    constexpr uint16_t kParameterCount = 1;  // Only 1 parameter: the receiver.
    constexpr uint16_t kMaxArguments = 0;
    constexpr int kLocalCount = 0;
    FrameStateFunctionInfo* info = graph_zone()->New<FrameStateFunctionInfo>(
        type, kParameterCount, kMaxArguments, kLocalCount, shared_info,
        kNullMaybeHandle);

    return graph_zone()->New<FrameStateInfo>(
        BytecodeOffset::None(), OutputFrameStateCombine::Ignore(), info);
  }

  const FrameStateInfo* MakeFrameStateInfo(
      maglev::BuiltinContinuationDeoptFrame& maglev_frame) {
    FrameStateType type = maglev_frame.is_javas
"""


```