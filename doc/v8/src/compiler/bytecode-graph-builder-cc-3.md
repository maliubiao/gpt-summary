Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/bytecode-graph-builder.cc`. They have several specific questions:

1. **Main Functionality:** What does this code do?
2. **Torque Source:** Is it a Torque file (indicated by a `.tq` extension)?
3. **JavaScript Relation:** If it relates to JavaScript, provide a JavaScript example.
4. **Code Logic and Inference:**  If there's logical deduction, provide example inputs and outputs.
5. **Common Programming Errors:**  Point out potential user errors related to this code.
6. **Summary of Functionality (Part 4/6):**  Summarize the specific functions in this snippet, considering it's part 4 of a larger piece.

**Plan:**

1. **Analyze the code:**  Identify the core actions performed by each function in the provided snippet.
2. **Address .tq question:** Check for any indications of Torque usage (though the file extension in the prompt suggests it's not).
3. **JavaScript Relation:**  Focus on identifying bytecode instructions that directly correspond to JavaScript operations and provide illustrative JavaScript code.
4. **Code Logic and Inference:** Where applicable, devise simple scenarios to demonstrate the input and output of specific functions.
5. **Common Errors:**  Think about typical mistakes developers might make that would interact with the functionalities exposed here.
6. **Summarize:** Condense the identified functionalities into a concise summary for this specific part of the code.
```c++
)->CreateArrayFromIterable(),
                           environment()->LookupAccumulator());
  environment()->BindAccumulator(iterable, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitCreateObjectLiteral() {
  ObjectBoilerplateDescriptionRef constant_properties =
      MakeRefForConstantForIndexOperand<ObjectBoilerplateDescription>(0);
  int const slot_id = bytecode_iterator().GetIndexOperand(1);
  FeedbackSource pair = CreateFeedbackSource(slot_id);
  int bytecode_flags = bytecode_iterator().GetFlag8Operand(2);
  int literal_flags =
      interpreter::CreateObjectLiteralFlags::FlagsBits::decode(bytecode_flags);
  int number_of_properties = constant_properties.boilerplate_properties_count();
  static_assert(JSCreateLiteralObjectNode::FeedbackVectorIndex() == 0);
  const Operator* op = javascript()->CreateLiteralObject(
      constant_properties, pair, literal_flags, number_of_properties);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* literal = NewNode(op, feedback_vector_node());
  environment()->BindAccumulator(literal, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitCreateEmptyObjectLiteral() {
  Node* literal = NewNode(javascript()->CreateEmptyLiteralObject());
  environment()->BindAccumulator(literal);
}

void BytecodeGraphBuilder::VisitCloneObject() {
  PrepareEagerCheckpoint();
  Node* source =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  int flags = bytecode_iterator().GetFlag8Operand(1);
  int slot = bytecode_iterator().GetIndexOperand(2);
  const Operator* op =
      javascript()->CloneObject(CreateFeedbackSource(slot), flags);
  static_assert(JSCloneObjectNode::SourceIndex() == 0);
  static_assert(JSCloneObjectNode::FeedbackVectorIndex() == 1);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* value = NewNode(op, source, feedback_vector_node());
  environment()->BindAccumulator(value, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitGetTemplateObject() {
  FeedbackSource source =
      CreateFeedbackSource(bytecode_iterator().GetIndexOperand(1));
  TemplateObjectDescriptionRef description =
      MakeRefForConstantForIndexOperand<TemplateObjectDescription>(0);
  static_assert(JSGetTemplateObjectNode::FeedbackVectorIndex() == 0);
  const Operator* op =
      javascript()->GetTemplateObject(description, shared_info(), source);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* template_object = NewNode(op, feedback_vector_node());
  environment()->BindAccumulator(template_object);
}

Node* const* BytecodeGraphBuilder::GetCallArgumentsFromRegisters(
    Node* callee, Node* receiver, interpreter::Register first_arg,
    int arg_count) {
  const int arity = JSCallNode::ArityForArgc(arg_count);
  Node** all = local_zone()->AllocateArray<Node*>(static_cast<size_t>(arity));
  int cursor = 0;

  static_assert(JSCallNode::TargetIndex() == 0);
  static_assert(JSCallNode::ReceiverIndex() == 1);
  static_assert(JSCallNode::FirstArgumentIndex() == 2);
  static_assert(JSCallNode::kFeedbackVectorIsLastInput);

  all[cursor++] = callee;
  all[cursor++] = receiver;

  // The function arguments are in consecutive registers.
  const int arg_base = first_arg.index();
  for (int i = 0; i < arg_count; ++i) {
    all[cursor++] =
        environment()->LookupRegister(interpreter::Register(arg_base + i));
  }

  all[cursor++] = feedback_vector_node();

  DCHECK_EQ(cursor, arity);
  return all;
}

void BytecodeGraphBuilder::BuildCall(ConvertReceiverMode receiver_mode,
                                     Node* const* args, size_t arg_count,
                                     int slot_id) {
  DCHECK_EQ(interpreter::Bytecodes::GetReceiverMode(
                bytecode_iterator().current_bytecode()),
            receiver_mode);
  PrepareEagerCheckpoint();

  FeedbackSource feedback = CreateFeedbackSource(slot_id);
  CallFrequency frequency = ComputeCallFrequency(slot_id);
  SpeculationMode speculation_mode = GetSpeculationMode(slot_id);
  CallFeedbackRelation call_feedback_relation =
      ComputeCallFeedbackRelation(slot_id);
  const Operator* op =
      javascript()->Call(arg_count, frequency, feedback, receiver_mode,
                         speculation_mode, call_feedback_relation);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));

  JSTypeHintLowering::LoweringResult lowering = TryBuildSimplifiedCall(
      op, args, static_cast<int>(arg_count), feedback.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    node = MakeNode(op, static_cast<int>(arg_count), args);
  }
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

Node* const* BytecodeGraphBuilder::ProcessCallVarArgs(
    ConvertReceiverMode receiver_mode, Node* callee,
    interpreter::Register first_reg, int arg_count) {
  DCHECK_GE(arg_count, 0);
  Node* receiver_node;
  interpreter::Register first_arg;

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    // The receiver is implicit (and undefined), the arguments are in
    // consecutive registers.
    receiver_node = jsgraph()->UndefinedConstant();
    first_arg = first_reg;
  } else {
    // The receiver is the first register, followed by the arguments in the
    // consecutive registers.
    receiver_node = environment()->LookupRegister(first_reg);
    first_arg = interpreter::Register(first_reg.index() + 1);
  }

  Node* const* call_args = GetCallArgumentsFromRegisters(callee, receiver_node,
                                                         first_arg, arg_count);
  return call_args;
}

void BytecodeGraphBuilder::BuildCallVarArgs(ConvertReceiverMode receiver_mode) {
  DCHECK_EQ(interpreter::Bytecodes::GetReceiverMode(
                bytecode_iterator().current_bytecode()),
            receiver_mode);
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  interpreter::Register first_reg = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);
  int const slot_id = bytecode_iterator().GetIndexOperand(3);

  int arg_count = receiver_mode == ConvertReceiverMode::kNullOrUndefined
                      ? static_cast<int>(reg_count)
                      : static_cast<int>(reg_count) - 1;
  Node* const* call_args =
      ProcessCallVarArgs(receiver_mode, callee, first_reg, arg_count);
  BuildCall(receiver_mode, call_args, JSCallNode::ArityForArgc(arg_count),
            slot_id);
}

void BytecodeGraphBuilder::VisitCallAnyReceiver() {
  BuildCallVarArgs(ConvertReceiverMode::kAny);
}

void BytecodeGraphBuilder::VisitCallProperty() {
  BuildCallVarArgs(ConvertReceiverMode::kNotNullOrUndefined);
}

void BytecodeGraphBuilder::VisitCallProperty0() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  int const slot_id = bytecode_iterator().GetIndexOperand(2);
  BuildCall(ConvertReceiverMode::kNotNullOrUndefined,
            {callee, receiver, feedback_vector_node()}, slot_id);
}

void BytecodeGraphBuilder::VisitCallProperty1() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  Node* arg0 =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(2));
  int const slot_id = bytecode_iterator().GetIndexOperand(3);
  BuildCall(ConvertReceiverMode::kNotNullOrUndefined,
            {callee, receiver, arg0, feedback_vector_node()}, slot_id);
}

void BytecodeGraphBuilder::VisitCallProperty2() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  Node* arg0 =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(2));
  Node* arg1 =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(3));
  int const slot_id = bytecode_iterator().GetIndexOperand(4);
  BuildCall(ConvertReceiverMode::kNotNullOrUndefined,
            {callee, receiver, arg0, arg1, feedback_vector_node()}, slot_id);
}

void BytecodeGraphBuilder::VisitCallUndefinedReceiver() {
  BuildCallVarArgs(ConvertReceiverMode::kNullOrUndefined);
}

void BytecodeGraphBuilder::VisitCallUndefinedReceiver0() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver = jsgraph()->UndefinedConstant();
  int const slot_id = bytecode_iterator().GetIndexOperand(1);
  BuildCall(ConvertReceiverMode::kNullOrUndefined,
            {callee, receiver, feedback_vector_node()}, slot_id);
}

void BytecodeGraphBuilder::VisitCallUndefinedReceiver1() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver = jsgraph()->UndefinedConstant();
  Node* arg0 =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  int const slot_id = bytecode_iterator().GetIndexOperand(2);
  BuildCall(ConvertReceiverMode::kNullOrUndefined,
            {callee, receiver, arg0, feedback_vector_node()}, slot_id);
}

void BytecodeGraphBuilder::VisitCallUndefinedReceiver2() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver = jsgraph()->UndefinedConstant();
  Node* arg0 =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  Node* arg1 =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(2));
  int const slot_id = bytecode_iterator().GetIndexOperand(3);
  BuildCall(ConvertReceiverMode::kNullOrUndefined,
            {callee, receiver, arg0, arg1, feedback_vector_node()}, slot_id);
}

void BytecodeGraphBuilder::VisitCallWithSpread() {
  PrepareEagerCheckpoint();
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  interpreter::Register receiver = bytecode_iterator().GetRegisterOperand(1);
  Node* receiver_node = environment()->LookupRegister(receiver);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);
  interpreter::Register first_arg = interpreter::Register(receiver.index() + 1);
  int arg_count = static_cast<int>(reg_count) - 1;
  Node* const* args = GetCallArgumentsFromRegisters(callee, receiver_node,
                                                    first_arg, arg_count);
  int const slot_id = bytecode_iterator().GetIndexOperand(3);
  FeedbackSource feedback = CreateFeedbackSource(slot_id);
  CallFrequency frequency = ComputeCallFrequency(slot_id);
  SpeculationMode speculation_mode = GetSpeculationMode(slot_id);
  const Operator* op = javascript()->CallWithSpread(
      JSCallWithSpreadNode::ArityForArgc(arg_count), frequency, feedback,
      speculation_mode);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));

  JSTypeHintLowering::LoweringResult lowering = TryBuildSimplifiedCall(
      op, args, static_cast<int>(arg_count), feedback.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    node = MakeNode(op, JSCallWithSpreadNode::ArityForArgc(arg_count), args);
  }
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitCallJSRuntime() {
  PrepareEagerCheckpoint();
  Node* callee = BuildLoadNativeContextField(
      bytecode_iterator().GetNativeContextIndexOperand(0));
  interpreter::Register first_reg = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);
  int arg_count = static_cast<int>(reg_count);
  int arity = JSCallNode::ArityForArgc(arg_count);

  const Operator* call = javascript()->Call(arity);
  Node* const* call_args = ProcessCallVarArgs(
      ConvertReceiverMode::kNullOrUndefined, callee, first_reg, arg_count);
  Node* value = MakeNode(call, arity, call_args);
  environment()->BindAccumulator(value, Environment::kAttachFrameState);
}

Node* BytecodeGraphBuilder::ProcessCallRuntimeArguments(
    const Operator* call_runtime_op, interpreter::Register receiver,
    size_t reg_count) {
  int arg_count = static_cast<int>(reg_count);
  // arity is args.
  int arity = arg_count;
  Node** all = local_zone()->AllocateArray<Node*>(static_cast<size_t>(arity));
  int first_arg_index = receiver.index();
  for (int i = 0; i < static_cast<int>(reg_count); ++i) {
    all[i] = environment()->LookupRegister(
        interpreter::Register(first_arg_index + i));
  }
  Node* value = MakeNode(call_runtime_op, arity, all);
  return value;
}

void BytecodeGraphBuilder::VisitCallRuntime() {
  PrepareEagerCheckpoint();
  Runtime::FunctionId function_id = bytecode_iterator().GetRuntimeIdOperand(0);
  interpreter::Register receiver = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);

  // Handle %ObserveNode here (rather than in JSIntrinsicLowering) to observe
  // the node as early as possible.
  if (function_id == Runtime::FunctionId::kObserveNode) {
    DCHECK_EQ(1, reg_count);
    Node* value = environment()->LookupRegister(receiver);
    observe_node_info_.StartObserving(value);
    environment()->BindAccumulator(value);
  } else {
    // Create node to perform the runtime call.
    const Operator* call = javascript()->CallRuntime(function_id, reg_count);
    Node* value = ProcessCallRuntimeArguments(call, receiver, reg_count);
    environment()->BindAccumulator(value, Environment::kAttachFrameState);

    // Connect to the end if {function_id} is non-returning.
    if (Runtime::IsNonReturning(function_id)) {
      // TODO(7099): Investigate if we need LoopExit node here.
      Node* control = NewNode(common()->Throw());
      MergeControlToLeaveFunction(control);
    }
  }
}

void BytecodeGraphBuilder::VisitCallRuntimeForPair() {
  PrepareEagerCheckpoint();
  Runtime::FunctionId functionId = bytecode_iterator().GetRuntimeIdOperand(0);
  interpreter::Register receiver = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);
  interpreter::Register first_return =
      bytecode_iterator().GetRegisterOperand(3);

  // Create node to perform the runtime call.
  const Operator* call = javascript()->CallRuntime(functionId, reg_count);
  Node* return_pair = ProcessCallRuntimeArguments(call, receiver, reg_count);
  environment()->BindRegistersToProjections(first_return, return_pair,
                                            Environment::kAttachFrameState);
}

Node* const* BytecodeGraphBuilder::GetConstructArgumentsFromRegister(
    Node* target, Node* new_target, interpreter::Register first_arg,
    int arg_count) {
  const int arity = JSConstructNode::ArityForArgc(arg_count);
  Node** all = local_zone()->AllocateArray<Node*>(static_cast<size_t>(arity));
  int cursor = 0;

  static_assert(JSConstructNode::TargetIndex() == 0);
  static_assert(JSConstructNode::NewTargetIndex() == 1);
  static_assert(JSConstructNode::FirstArgumentIndex() == 2);
  static_assert(JSConstructNode::kFeedbackVectorIsLastInput);

  all[cursor++] = target;
  all[cursor++] = new_target;

  // The function arguments are in consecutive registers.
  int arg_base = first_arg.index();
  for (int i = 0; i < arg_count; ++i) {
    all[cursor++] =
        environment()->LookupRegister(interpreter::Register(arg_base + i));
  }

  all[cursor++] = feedback_vector_node();

  DCHECK_EQ(cursor, arity);
  return all;
}

void BytecodeGraphBuilder::VisitConstruct() {
  PrepareEagerCheckpoint();
  interpreter::Register callee_reg = bytecode_iterator().GetRegisterOperand(0);
  interpreter::Register first_reg = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);
  int const slot_id = bytecode_iterator().GetIndexOperand(3);
  FeedbackSource feedback = CreateFeedbackSource(slot_id);

  Node* new_target = environment()->LookupAccumulator();
  Node* callee = environment()->LookupRegister(callee_reg);

  CallFrequency frequency = ComputeCallFrequency(slot_id);
  const uint32_t arg_count = static_cast<uint32_t>(reg_count);
  const uint32_t arity = JSConstructNode::ArityForArgc(arg_count);
  const Operator* op = javascript()->Construct(arity, frequency, feedback);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* const* args = GetConstructArgumentsFromRegister(callee, new_target,
                                                        first_reg, arg_count);
  JSTypeHintLowering::LoweringResult lowering = TryBuildSimplifiedConstruct(
      op, args, static_cast<int>(arg_count), feedback.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    node = MakeNode(op, arity, args);
  }
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitConstructWithSpread() {
  PrepareEagerCheckpoint();
  interpreter::Register callee_reg = bytecode_iterator().GetRegisterOperand(0);
  interpreter::Register first_reg = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);
  int const slot_id = bytecode_iterator().GetIndexOperand(3);
  FeedbackSource feedback = CreateFeedbackSource(slot_id);

  Node* new_target = environment()->LookupAccumulator();
  Node* callee = environment()->LookupRegister(callee_reg);

  CallFrequency frequency = ComputeCallFrequency(slot_id);
  const uint32_t arg_count = static_cast<uint32_t>(reg_count);
  const uint32_t arity = JSConstructNode::ArityForArgc(arg_count);
  const Operator* op =
      javascript()->ConstructWithSpread(arity, frequency, feedback);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* const* args = GetConstructArgumentsFromRegister(callee, new_target,
                                                        first_reg, arg_count);
  JSTypeHintLowering::LoweringResult lowering = TryBuildSimplifiedConstruct(
      op, args, static_cast<int>(arg_count), feedback.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    node = MakeNode(op, arity, args);
  }
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitConstructForwardAllArgs() {
  PrepareEagerCheckpoint();
  interpreter::Register callee_reg = bytecode_iterator().GetRegisterOperand(0);
  int const slot_id = bytecode_iterator().GetIndexOperand(1);
  FeedbackSource feedback = CreateFeedbackSource(slot_id);
  Node* new_target = environment()->LookupAccumulator();
  Node* callee = environment()->LookupRegister(callee_reg);
  CallFrequency frequency = ComputeCallFrequency(slot_id);

  // Use 0 as a fake argument count.
  //
  // This op will be later reduced to either a builtin call (in the case of not
  // being inlined) or a normal JSConstruct with the inlined arguments
  // forwarded.
  constexpr int arg_count = 0;
  const int arity = JSConstructForwardAllArgsNode::ArityForArgc(arg_count);
  Node** construct_args =
      local_zone()->AllocateArray<Node*>(static_cast<size_t>(arity));
  static_assert(JSConstructForwardAllArgsNode::TargetIndex() == 0);
  static_assert(JSConstructForwardAllArgsNode::NewTargetIndex() == 1);
  static_assert(JSConstructNode::kFeedbackVectorIsLastInput);
  DCHECK_LT(JSConstructForwardAllArgsNode::NewTargetIndex(), arity);
  int cursor = 0;
  construct_args[cursor++] = callee;
  construct_args[cursor++] = new_target;
  construct_args[cursor++] = feedback_vector_node();

  const Operator* op =
      javascript()->ConstructForwardAllArgs(frequency, feedback);
  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedConstruct(op, construct_args, arg_count, feedback.slot);
  if (lowering.IsExit()) return;

  Node* node;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    node = MakeNode(op, arity, construct_args);
  }

  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitInvokeIntrinsic() {
  PrepareEagerCheckpoint();
  Runtime::FunctionId functionId = bytecode_iterator().GetIntrinsicIdOperand(0);
  interpreter::Register receiver = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);

  // Create node to perform the runtime call. Turbofan will take care of the
  // lowering.
  const Operator* call = javascript()->CallRuntime(functionId, reg_count);
  Node* value = ProcessCallRuntimeArguments(call, receiver, reg_count);
  environment()->BindAccumulator(value, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitThrow() {
  BuildLoopExitsForFunctionExit(bytecode_analysis().GetInLivenessFor(
      bytecode_iterator().current_offset()));
  Node* value = environment()->LookupAccumulator();
  Node* call = NewNode(javascript()->CallRuntime(Runtime::kThrow), value);
  environment()->BindAccumulator(call, Environment::kAttachFrameState);
  Node* control = NewNode(common()->Throw());
  MergeControlToLeaveFunction(control);
}

void BytecodeGraphBuilder::VisitAbort() {
  BuildLoopExitsForFunctionExit(bytecode_analysis().GetInLivenessFor(
      bytecode_iterator().current_offset()));
  AbortReason reason =
      static_cast<AbortReason>(bytecode_iterator().GetIndexOperand(0));
  NewNode(simplified()->RuntimeAbort(reason));
  Node* control = NewNode(common()->Throw());
  MergeControlToLeaveFunction(control);
}

void BytecodeGraphBuilder::VisitReThrow() {
  BuildLoopExitsForFunctionExit(bytecode_analysis().GetInLivenessFor(
      bytecode_iterator().current_offset()));
  Node* value = environment()->LookupAccumulator();
  NewNode(javascript()->CallRuntime(Runtime::kReThrow), value);
  Node* control = NewNode(common()->Throw());
  MergeControlToLeaveFunction(control);
}

void BytecodeGraphBuilder::BuildHoleCheckAndThrow(
    Node* condition, Runtime::FunctionId runtime_id, Node* name) {
  Node* accumulator = environment()->LookupAccumulator();
  NewBranch(condition, BranchHint::kFalse);
  {
    SubEnvironment sub_environment(this);

    NewIfTrue();
    BuildLoopExitsForFunctionExit(bytecode_analysis().GetInLivenessFor(
        bytecode_iterator().current_offset()));
    Node* node;
    const Operator* op = javascript()->CallRuntime(runtime_id);
    if (runtime_id == Runtime::kThrowAccessedUninitializedVariable) {
      DCHECK_NOT_NULL(name);
      node = NewNode(op, name);
    } else {
      DCHECK(runtime_id == Runtime::kThrowSuperAlreadyCalledError ||
             runtime_id == Runtime::kThrowSuperNotCalled);
      node = NewNode(op);
    }
    environment()->RecordAfterState(node, Environment::kAttachFrameState);
    Node* control = NewNode(common()->Throw());
    MergeControlToLeaveFunction(control);
  }
  NewIfFalse();
  environment()->BindAccumulator(accumulator);
}

void BytecodeGraphBuilder::VisitThrowReferenceErrorIfHole() {
  Node* accumulator = environment()->LookupAccumulator();
  Node* check_for_hole = NewNode(simplified()->ReferenceEqual(), accumulator,
                                 jsgraph()->TheHoleConstant());
  Node* name =
      jsgraph()->ConstantNoHole(MakeRefForConstantForIndexOperand(0), broker());
  BuildHoleCheckAndThrow(check_for_hole,
                         Runtime::kThrowAccessedUninitializedVariable, name);
}

void BytecodeGraphBuilder::VisitThrowSuperNotCalledIfHole() {
  Node* accumulator = environment()->LookupAccumulator();
  Node* check_for_hole = NewNode(simplified()->ReferenceEqual(), accumulator,
                                 jsgraph()->TheHoleConstant());
  BuildHoleCheckAndThrow(check_for_hole, Runtime::kThrowSuperNotCalled);
}

void BytecodeGraphBuilder::VisitThrowSuperAlreadyCalledIfNotHole() {
  Node* accumulator = environment()->LookupAccumulator();
  Node* check_for_hole = NewNode(simplified()->ReferenceEqual(), accumulator,
                                 jsgraph()->TheHoleConstant());
  Node* check_for_not_hole =
      NewNode(simplified()->BooleanNot(), check_for_hole);
  BuildHoleCheckAndThrow(check_for_not_hole,
                         Runtime::kThrowSuperAlreadyCalledError);
}

void BytecodeGraphBuilder::VisitThrowIfNotSuperConstructor() {
  Node* constructor =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* check_is_constructor =
      NewNode(simplified()->ObjectIsConstructor(), constructor);
  NewBranch(check_is_constructor, BranchHint::kTrue);
  {
    SubEnvironment sub_environment(this);
    NewIfFalse();
    BuildLoopExitsForFunctionExit(bytecode_analysis().GetInLivenessFor(
        bytecode_iterator().current_offset()));
    Node* node =
        NewNode(javascript()->CallRuntime(Runtime::kThrowNotSuperConstructor),
                constructor, GetFunctionClosure());
    environment()->RecordAfterState(node, Environment::kAttachFrameState);
    Node* control = NewNode(common()->Throw());
    MergeControlToLeaveFunction(control);
  }
  NewIfTrue();

  constructor = NewNode(common()->TypeGuard(Type::Callable()), constructor);
  environment()->BindRegister(bytecode_iterator().GetRegisterOperand(0),
                              constructor);
}

void BytecodeGraphBuilder::BuildUnaryOp(const Operator* op) {
  DCHECK(JSOperator::IsUnaryWithFeedback(op->opcode()));
  PrepareEagerCheckpoint();
  Node* operand = environment()->LookupAccumulator();

  FeedbackSlot slot =
      bytecode_iterator().GetSlotOperand(kUnaryOperationHintIndex);
  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedUnaryOp(op, operand, slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
    node = NewNode(op, operand, feedback_vector_node());
  }

  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::BuildBinaryOp(const Operator* op) {
  DCHECK(JSOperator::IsBinaryWithFeedback(op->opcode()));
  PrepareEagerCheckpoint();
  Node* left =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* right = environment()->LookupAccumulator();

  FeedbackSlot slot =
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex);
  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedBinaryOp(op, left, right, slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
    node = NewNode(op, left, right, feedback_vector_node());
  }

  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

// Helper function to create for-in mode from the recorded type feedback.
ForInMode BytecodeGraphBuilder::GetForInMode(FeedbackSlot slot) {
  FeedbackSource source(feedback_vector(), slot);
  switch (broker()->GetFeedbackForForIn(source)) {
    case ForInHint::kNone:
    case ForInHint::kEnumCacheKeysAndIndices:
      return ForInMode::kUseEnumCacheKeysAndIndices;
    case ForInHint::kEnumCacheKeys:
      return ForInMode::kUseEnumCacheKeys;
    case ForInHint::kAny:
      return ForInMode::kGeneric;
  }
  UNREACHABLE();
}

CallFrequency BytecodeGraphBuilder::ComputeCallFrequency(int slot_id) const {
  if (invocation_frequency_.IsUnknown()) return CallFrequency();
  FeedbackSlot slot = FeedbackVector::ToSlot(slot_id);
  FeedbackSource source(feedback_vector(), slot);
  ProcessedFeedback const& feedback = broker()->GetFeedbackForCall(source);
  float feedback_frequency =
      feedback.IsInsufficient() ? 0.0f : feedback.AsCall().frequency();
  if (feedback_frequency == 0.0f) {  // Prevent multiplying zero and infinity.
    return CallFrequency(0.0f);
  } else {
    return CallFrequency(feedback_frequency * invocation_frequency_.value());
  }
}

SpeculationMode BytecodeGraphBuilder::GetSpeculationMode(int slot_id) const {
  FeedbackSlot slot = FeedbackVector::ToSlot(slot_id);
  FeedbackSource source(feedback_vector(), slot);
  ProcessedFeedback const& feedback = broker()->GetFeedbackForCall(source);
  return feedback.IsInsufficient() ? SpeculationMode::kDisallowSpeculation
                                   : feedback.AsCall().speculation_mode();
}

CallFeedback
### 提示词
```
这是目录为v8/src/compiler/bytecode-graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/bytecode-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
)->CreateArrayFromIterable(),
                           environment()->LookupAccumulator());
  environment()->BindAccumulator(iterable, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitCreateObjectLiteral() {
  ObjectBoilerplateDescriptionRef constant_properties =
      MakeRefForConstantForIndexOperand<ObjectBoilerplateDescription>(0);
  int const slot_id = bytecode_iterator().GetIndexOperand(1);
  FeedbackSource pair = CreateFeedbackSource(slot_id);
  int bytecode_flags = bytecode_iterator().GetFlag8Operand(2);
  int literal_flags =
      interpreter::CreateObjectLiteralFlags::FlagsBits::decode(bytecode_flags);
  int number_of_properties = constant_properties.boilerplate_properties_count();
  static_assert(JSCreateLiteralObjectNode::FeedbackVectorIndex() == 0);
  const Operator* op = javascript()->CreateLiteralObject(
      constant_properties, pair, literal_flags, number_of_properties);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* literal = NewNode(op, feedback_vector_node());
  environment()->BindAccumulator(literal, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitCreateEmptyObjectLiteral() {
  Node* literal = NewNode(javascript()->CreateEmptyLiteralObject());
  environment()->BindAccumulator(literal);
}

void BytecodeGraphBuilder::VisitCloneObject() {
  PrepareEagerCheckpoint();
  Node* source =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  int flags = bytecode_iterator().GetFlag8Operand(1);
  int slot = bytecode_iterator().GetIndexOperand(2);
  const Operator* op =
      javascript()->CloneObject(CreateFeedbackSource(slot), flags);
  static_assert(JSCloneObjectNode::SourceIndex() == 0);
  static_assert(JSCloneObjectNode::FeedbackVectorIndex() == 1);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* value = NewNode(op, source, feedback_vector_node());
  environment()->BindAccumulator(value, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitGetTemplateObject() {
  FeedbackSource source =
      CreateFeedbackSource(bytecode_iterator().GetIndexOperand(1));
  TemplateObjectDescriptionRef description =
      MakeRefForConstantForIndexOperand<TemplateObjectDescription>(0);
  static_assert(JSGetTemplateObjectNode::FeedbackVectorIndex() == 0);
  const Operator* op =
      javascript()->GetTemplateObject(description, shared_info(), source);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* template_object = NewNode(op, feedback_vector_node());
  environment()->BindAccumulator(template_object);
}

Node* const* BytecodeGraphBuilder::GetCallArgumentsFromRegisters(
    Node* callee, Node* receiver, interpreter::Register first_arg,
    int arg_count) {
  const int arity = JSCallNode::ArityForArgc(arg_count);
  Node** all = local_zone()->AllocateArray<Node*>(static_cast<size_t>(arity));
  int cursor = 0;

  static_assert(JSCallNode::TargetIndex() == 0);
  static_assert(JSCallNode::ReceiverIndex() == 1);
  static_assert(JSCallNode::FirstArgumentIndex() == 2);
  static_assert(JSCallNode::kFeedbackVectorIsLastInput);

  all[cursor++] = callee;
  all[cursor++] = receiver;

  // The function arguments are in consecutive registers.
  const int arg_base = first_arg.index();
  for (int i = 0; i < arg_count; ++i) {
    all[cursor++] =
        environment()->LookupRegister(interpreter::Register(arg_base + i));
  }

  all[cursor++] = feedback_vector_node();

  DCHECK_EQ(cursor, arity);
  return all;
}

void BytecodeGraphBuilder::BuildCall(ConvertReceiverMode receiver_mode,
                                     Node* const* args, size_t arg_count,
                                     int slot_id) {
  DCHECK_EQ(interpreter::Bytecodes::GetReceiverMode(
                bytecode_iterator().current_bytecode()),
            receiver_mode);
  PrepareEagerCheckpoint();

  FeedbackSource feedback = CreateFeedbackSource(slot_id);
  CallFrequency frequency = ComputeCallFrequency(slot_id);
  SpeculationMode speculation_mode = GetSpeculationMode(slot_id);
  CallFeedbackRelation call_feedback_relation =
      ComputeCallFeedbackRelation(slot_id);
  const Operator* op =
      javascript()->Call(arg_count, frequency, feedback, receiver_mode,
                         speculation_mode, call_feedback_relation);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));

  JSTypeHintLowering::LoweringResult lowering = TryBuildSimplifiedCall(
      op, args, static_cast<int>(arg_count), feedback.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    node = MakeNode(op, static_cast<int>(arg_count), args);
  }
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

Node* const* BytecodeGraphBuilder::ProcessCallVarArgs(
    ConvertReceiverMode receiver_mode, Node* callee,
    interpreter::Register first_reg, int arg_count) {
  DCHECK_GE(arg_count, 0);
  Node* receiver_node;
  interpreter::Register first_arg;

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    // The receiver is implicit (and undefined), the arguments are in
    // consecutive registers.
    receiver_node = jsgraph()->UndefinedConstant();
    first_arg = first_reg;
  } else {
    // The receiver is the first register, followed by the arguments in the
    // consecutive registers.
    receiver_node = environment()->LookupRegister(first_reg);
    first_arg = interpreter::Register(first_reg.index() + 1);
  }

  Node* const* call_args = GetCallArgumentsFromRegisters(callee, receiver_node,
                                                         first_arg, arg_count);
  return call_args;
}

void BytecodeGraphBuilder::BuildCallVarArgs(ConvertReceiverMode receiver_mode) {
  DCHECK_EQ(interpreter::Bytecodes::GetReceiverMode(
                bytecode_iterator().current_bytecode()),
            receiver_mode);
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  interpreter::Register first_reg = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);
  int const slot_id = bytecode_iterator().GetIndexOperand(3);

  int arg_count = receiver_mode == ConvertReceiverMode::kNullOrUndefined
                      ? static_cast<int>(reg_count)
                      : static_cast<int>(reg_count) - 1;
  Node* const* call_args =
      ProcessCallVarArgs(receiver_mode, callee, first_reg, arg_count);
  BuildCall(receiver_mode, call_args, JSCallNode::ArityForArgc(arg_count),
            slot_id);
}

void BytecodeGraphBuilder::VisitCallAnyReceiver() {
  BuildCallVarArgs(ConvertReceiverMode::kAny);
}

void BytecodeGraphBuilder::VisitCallProperty() {
  BuildCallVarArgs(ConvertReceiverMode::kNotNullOrUndefined);
}

void BytecodeGraphBuilder::VisitCallProperty0() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  int const slot_id = bytecode_iterator().GetIndexOperand(2);
  BuildCall(ConvertReceiverMode::kNotNullOrUndefined,
            {callee, receiver, feedback_vector_node()}, slot_id);
}

void BytecodeGraphBuilder::VisitCallProperty1() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  Node* arg0 =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(2));
  int const slot_id = bytecode_iterator().GetIndexOperand(3);
  BuildCall(ConvertReceiverMode::kNotNullOrUndefined,
            {callee, receiver, arg0, feedback_vector_node()}, slot_id);
}

void BytecodeGraphBuilder::VisitCallProperty2() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  Node* arg0 =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(2));
  Node* arg1 =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(3));
  int const slot_id = bytecode_iterator().GetIndexOperand(4);
  BuildCall(ConvertReceiverMode::kNotNullOrUndefined,
            {callee, receiver, arg0, arg1, feedback_vector_node()}, slot_id);
}

void BytecodeGraphBuilder::VisitCallUndefinedReceiver() {
  BuildCallVarArgs(ConvertReceiverMode::kNullOrUndefined);
}

void BytecodeGraphBuilder::VisitCallUndefinedReceiver0() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver = jsgraph()->UndefinedConstant();
  int const slot_id = bytecode_iterator().GetIndexOperand(1);
  BuildCall(ConvertReceiverMode::kNullOrUndefined,
            {callee, receiver, feedback_vector_node()}, slot_id);
}

void BytecodeGraphBuilder::VisitCallUndefinedReceiver1() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver = jsgraph()->UndefinedConstant();
  Node* arg0 =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  int const slot_id = bytecode_iterator().GetIndexOperand(2);
  BuildCall(ConvertReceiverMode::kNullOrUndefined,
            {callee, receiver, arg0, feedback_vector_node()}, slot_id);
}

void BytecodeGraphBuilder::VisitCallUndefinedReceiver2() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver = jsgraph()->UndefinedConstant();
  Node* arg0 =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  Node* arg1 =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(2));
  int const slot_id = bytecode_iterator().GetIndexOperand(3);
  BuildCall(ConvertReceiverMode::kNullOrUndefined,
            {callee, receiver, arg0, arg1, feedback_vector_node()}, slot_id);
}

void BytecodeGraphBuilder::VisitCallWithSpread() {
  PrepareEagerCheckpoint();
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  interpreter::Register receiver = bytecode_iterator().GetRegisterOperand(1);
  Node* receiver_node = environment()->LookupRegister(receiver);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);
  interpreter::Register first_arg = interpreter::Register(receiver.index() + 1);
  int arg_count = static_cast<int>(reg_count) - 1;
  Node* const* args = GetCallArgumentsFromRegisters(callee, receiver_node,
                                                    first_arg, arg_count);
  int const slot_id = bytecode_iterator().GetIndexOperand(3);
  FeedbackSource feedback = CreateFeedbackSource(slot_id);
  CallFrequency frequency = ComputeCallFrequency(slot_id);
  SpeculationMode speculation_mode = GetSpeculationMode(slot_id);
  const Operator* op = javascript()->CallWithSpread(
      JSCallWithSpreadNode::ArityForArgc(arg_count), frequency, feedback,
      speculation_mode);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));

  JSTypeHintLowering::LoweringResult lowering = TryBuildSimplifiedCall(
      op, args, static_cast<int>(arg_count), feedback.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    node = MakeNode(op, JSCallWithSpreadNode::ArityForArgc(arg_count), args);
  }
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitCallJSRuntime() {
  PrepareEagerCheckpoint();
  Node* callee = BuildLoadNativeContextField(
      bytecode_iterator().GetNativeContextIndexOperand(0));
  interpreter::Register first_reg = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);
  int arg_count = static_cast<int>(reg_count);
  int arity = JSCallNode::ArityForArgc(arg_count);

  const Operator* call = javascript()->Call(arity);
  Node* const* call_args = ProcessCallVarArgs(
      ConvertReceiverMode::kNullOrUndefined, callee, first_reg, arg_count);
  Node* value = MakeNode(call, arity, call_args);
  environment()->BindAccumulator(value, Environment::kAttachFrameState);
}

Node* BytecodeGraphBuilder::ProcessCallRuntimeArguments(
    const Operator* call_runtime_op, interpreter::Register receiver,
    size_t reg_count) {
  int arg_count = static_cast<int>(reg_count);
  // arity is args.
  int arity = arg_count;
  Node** all = local_zone()->AllocateArray<Node*>(static_cast<size_t>(arity));
  int first_arg_index = receiver.index();
  for (int i = 0; i < static_cast<int>(reg_count); ++i) {
    all[i] = environment()->LookupRegister(
        interpreter::Register(first_arg_index + i));
  }
  Node* value = MakeNode(call_runtime_op, arity, all);
  return value;
}

void BytecodeGraphBuilder::VisitCallRuntime() {
  PrepareEagerCheckpoint();
  Runtime::FunctionId function_id = bytecode_iterator().GetRuntimeIdOperand(0);
  interpreter::Register receiver = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);

  // Handle %ObserveNode here (rather than in JSIntrinsicLowering) to observe
  // the node as early as possible.
  if (function_id == Runtime::FunctionId::kObserveNode) {
    DCHECK_EQ(1, reg_count);
    Node* value = environment()->LookupRegister(receiver);
    observe_node_info_.StartObserving(value);
    environment()->BindAccumulator(value);
  } else {
    // Create node to perform the runtime call.
    const Operator* call = javascript()->CallRuntime(function_id, reg_count);
    Node* value = ProcessCallRuntimeArguments(call, receiver, reg_count);
    environment()->BindAccumulator(value, Environment::kAttachFrameState);

    // Connect to the end if {function_id} is non-returning.
    if (Runtime::IsNonReturning(function_id)) {
      // TODO(7099): Investigate if we need LoopExit node here.
      Node* control = NewNode(common()->Throw());
      MergeControlToLeaveFunction(control);
    }
  }
}

void BytecodeGraphBuilder::VisitCallRuntimeForPair() {
  PrepareEagerCheckpoint();
  Runtime::FunctionId functionId = bytecode_iterator().GetRuntimeIdOperand(0);
  interpreter::Register receiver = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);
  interpreter::Register first_return =
      bytecode_iterator().GetRegisterOperand(3);

  // Create node to perform the runtime call.
  const Operator* call = javascript()->CallRuntime(functionId, reg_count);
  Node* return_pair = ProcessCallRuntimeArguments(call, receiver, reg_count);
  environment()->BindRegistersToProjections(first_return, return_pair,
                                            Environment::kAttachFrameState);
}

Node* const* BytecodeGraphBuilder::GetConstructArgumentsFromRegister(
    Node* target, Node* new_target, interpreter::Register first_arg,
    int arg_count) {
  const int arity = JSConstructNode::ArityForArgc(arg_count);
  Node** all = local_zone()->AllocateArray<Node*>(static_cast<size_t>(arity));
  int cursor = 0;

  static_assert(JSConstructNode::TargetIndex() == 0);
  static_assert(JSConstructNode::NewTargetIndex() == 1);
  static_assert(JSConstructNode::FirstArgumentIndex() == 2);
  static_assert(JSConstructNode::kFeedbackVectorIsLastInput);

  all[cursor++] = target;
  all[cursor++] = new_target;

  // The function arguments are in consecutive registers.
  int arg_base = first_arg.index();
  for (int i = 0; i < arg_count; ++i) {
    all[cursor++] =
        environment()->LookupRegister(interpreter::Register(arg_base + i));
  }

  all[cursor++] = feedback_vector_node();

  DCHECK_EQ(cursor, arity);
  return all;
}

void BytecodeGraphBuilder::VisitConstruct() {
  PrepareEagerCheckpoint();
  interpreter::Register callee_reg = bytecode_iterator().GetRegisterOperand(0);
  interpreter::Register first_reg = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);
  int const slot_id = bytecode_iterator().GetIndexOperand(3);
  FeedbackSource feedback = CreateFeedbackSource(slot_id);

  Node* new_target = environment()->LookupAccumulator();
  Node* callee = environment()->LookupRegister(callee_reg);

  CallFrequency frequency = ComputeCallFrequency(slot_id);
  const uint32_t arg_count = static_cast<uint32_t>(reg_count);
  const uint32_t arity = JSConstructNode::ArityForArgc(arg_count);
  const Operator* op = javascript()->Construct(arity, frequency, feedback);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* const* args = GetConstructArgumentsFromRegister(callee, new_target,
                                                        first_reg, arg_count);
  JSTypeHintLowering::LoweringResult lowering = TryBuildSimplifiedConstruct(
      op, args, static_cast<int>(arg_count), feedback.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    node = MakeNode(op, arity, args);
  }
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitConstructWithSpread() {
  PrepareEagerCheckpoint();
  interpreter::Register callee_reg = bytecode_iterator().GetRegisterOperand(0);
  interpreter::Register first_reg = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);
  int const slot_id = bytecode_iterator().GetIndexOperand(3);
  FeedbackSource feedback = CreateFeedbackSource(slot_id);

  Node* new_target = environment()->LookupAccumulator();
  Node* callee = environment()->LookupRegister(callee_reg);

  CallFrequency frequency = ComputeCallFrequency(slot_id);
  const uint32_t arg_count = static_cast<uint32_t>(reg_count);
  const uint32_t arity = JSConstructNode::ArityForArgc(arg_count);
  const Operator* op =
      javascript()->ConstructWithSpread(arity, frequency, feedback);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* const* args = GetConstructArgumentsFromRegister(callee, new_target,
                                                        first_reg, arg_count);
  JSTypeHintLowering::LoweringResult lowering = TryBuildSimplifiedConstruct(
      op, args, static_cast<int>(arg_count), feedback.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    node = MakeNode(op, arity, args);
  }
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitConstructForwardAllArgs() {
  PrepareEagerCheckpoint();
  interpreter::Register callee_reg = bytecode_iterator().GetRegisterOperand(0);
  int const slot_id = bytecode_iterator().GetIndexOperand(1);
  FeedbackSource feedback = CreateFeedbackSource(slot_id);
  Node* new_target = environment()->LookupAccumulator();
  Node* callee = environment()->LookupRegister(callee_reg);
  CallFrequency frequency = ComputeCallFrequency(slot_id);

  // Use 0 as a fake argument count.
  //
  // This op will be later reduced to either a builtin call (in the case of not
  // being inlined) or a normal JSConstruct with the inlined arguments
  // forwarded.
  constexpr int arg_count = 0;
  const int arity = JSConstructForwardAllArgsNode::ArityForArgc(arg_count);
  Node** construct_args =
      local_zone()->AllocateArray<Node*>(static_cast<size_t>(arity));
  static_assert(JSConstructForwardAllArgsNode::TargetIndex() == 0);
  static_assert(JSConstructForwardAllArgsNode::NewTargetIndex() == 1);
  static_assert(JSConstructNode::kFeedbackVectorIsLastInput);
  DCHECK_LT(JSConstructForwardAllArgsNode::NewTargetIndex(), arity);
  int cursor = 0;
  construct_args[cursor++] = callee;
  construct_args[cursor++] = new_target;
  construct_args[cursor++] = feedback_vector_node();

  const Operator* op =
      javascript()->ConstructForwardAllArgs(frequency, feedback);
  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedConstruct(op, construct_args, arg_count, feedback.slot);
  if (lowering.IsExit()) return;

  Node* node;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    node = MakeNode(op, arity, construct_args);
  }

  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitInvokeIntrinsic() {
  PrepareEagerCheckpoint();
  Runtime::FunctionId functionId = bytecode_iterator().GetIntrinsicIdOperand(0);
  interpreter::Register receiver = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);

  // Create node to perform the runtime call. Turbofan will take care of the
  // lowering.
  const Operator* call = javascript()->CallRuntime(functionId, reg_count);
  Node* value = ProcessCallRuntimeArguments(call, receiver, reg_count);
  environment()->BindAccumulator(value, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitThrow() {
  BuildLoopExitsForFunctionExit(bytecode_analysis().GetInLivenessFor(
      bytecode_iterator().current_offset()));
  Node* value = environment()->LookupAccumulator();
  Node* call = NewNode(javascript()->CallRuntime(Runtime::kThrow), value);
  environment()->BindAccumulator(call, Environment::kAttachFrameState);
  Node* control = NewNode(common()->Throw());
  MergeControlToLeaveFunction(control);
}

void BytecodeGraphBuilder::VisitAbort() {
  BuildLoopExitsForFunctionExit(bytecode_analysis().GetInLivenessFor(
      bytecode_iterator().current_offset()));
  AbortReason reason =
      static_cast<AbortReason>(bytecode_iterator().GetIndexOperand(0));
  NewNode(simplified()->RuntimeAbort(reason));
  Node* control = NewNode(common()->Throw());
  MergeControlToLeaveFunction(control);
}

void BytecodeGraphBuilder::VisitReThrow() {
  BuildLoopExitsForFunctionExit(bytecode_analysis().GetInLivenessFor(
      bytecode_iterator().current_offset()));
  Node* value = environment()->LookupAccumulator();
  NewNode(javascript()->CallRuntime(Runtime::kReThrow), value);
  Node* control = NewNode(common()->Throw());
  MergeControlToLeaveFunction(control);
}

void BytecodeGraphBuilder::BuildHoleCheckAndThrow(
    Node* condition, Runtime::FunctionId runtime_id, Node* name) {
  Node* accumulator = environment()->LookupAccumulator();
  NewBranch(condition, BranchHint::kFalse);
  {
    SubEnvironment sub_environment(this);

    NewIfTrue();
    BuildLoopExitsForFunctionExit(bytecode_analysis().GetInLivenessFor(
        bytecode_iterator().current_offset()));
    Node* node;
    const Operator* op = javascript()->CallRuntime(runtime_id);
    if (runtime_id == Runtime::kThrowAccessedUninitializedVariable) {
      DCHECK_NOT_NULL(name);
      node = NewNode(op, name);
    } else {
      DCHECK(runtime_id == Runtime::kThrowSuperAlreadyCalledError ||
             runtime_id == Runtime::kThrowSuperNotCalled);
      node = NewNode(op);
    }
    environment()->RecordAfterState(node, Environment::kAttachFrameState);
    Node* control = NewNode(common()->Throw());
    MergeControlToLeaveFunction(control);
  }
  NewIfFalse();
  environment()->BindAccumulator(accumulator);
}

void BytecodeGraphBuilder::VisitThrowReferenceErrorIfHole() {
  Node* accumulator = environment()->LookupAccumulator();
  Node* check_for_hole = NewNode(simplified()->ReferenceEqual(), accumulator,
                                 jsgraph()->TheHoleConstant());
  Node* name =
      jsgraph()->ConstantNoHole(MakeRefForConstantForIndexOperand(0), broker());
  BuildHoleCheckAndThrow(check_for_hole,
                         Runtime::kThrowAccessedUninitializedVariable, name);
}

void BytecodeGraphBuilder::VisitThrowSuperNotCalledIfHole() {
  Node* accumulator = environment()->LookupAccumulator();
  Node* check_for_hole = NewNode(simplified()->ReferenceEqual(), accumulator,
                                 jsgraph()->TheHoleConstant());
  BuildHoleCheckAndThrow(check_for_hole, Runtime::kThrowSuperNotCalled);
}

void BytecodeGraphBuilder::VisitThrowSuperAlreadyCalledIfNotHole() {
  Node* accumulator = environment()->LookupAccumulator();
  Node* check_for_hole = NewNode(simplified()->ReferenceEqual(), accumulator,
                                 jsgraph()->TheHoleConstant());
  Node* check_for_not_hole =
      NewNode(simplified()->BooleanNot(), check_for_hole);
  BuildHoleCheckAndThrow(check_for_not_hole,
                         Runtime::kThrowSuperAlreadyCalledError);
}

void BytecodeGraphBuilder::VisitThrowIfNotSuperConstructor() {
  Node* constructor =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* check_is_constructor =
      NewNode(simplified()->ObjectIsConstructor(), constructor);
  NewBranch(check_is_constructor, BranchHint::kTrue);
  {
    SubEnvironment sub_environment(this);
    NewIfFalse();
    BuildLoopExitsForFunctionExit(bytecode_analysis().GetInLivenessFor(
        bytecode_iterator().current_offset()));
    Node* node =
        NewNode(javascript()->CallRuntime(Runtime::kThrowNotSuperConstructor),
                constructor, GetFunctionClosure());
    environment()->RecordAfterState(node, Environment::kAttachFrameState);
    Node* control = NewNode(common()->Throw());
    MergeControlToLeaveFunction(control);
  }
  NewIfTrue();

  constructor = NewNode(common()->TypeGuard(Type::Callable()), constructor);
  environment()->BindRegister(bytecode_iterator().GetRegisterOperand(0),
                              constructor);
}

void BytecodeGraphBuilder::BuildUnaryOp(const Operator* op) {
  DCHECK(JSOperator::IsUnaryWithFeedback(op->opcode()));
  PrepareEagerCheckpoint();
  Node* operand = environment()->LookupAccumulator();

  FeedbackSlot slot =
      bytecode_iterator().GetSlotOperand(kUnaryOperationHintIndex);
  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedUnaryOp(op, operand, slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
    node = NewNode(op, operand, feedback_vector_node());
  }

  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::BuildBinaryOp(const Operator* op) {
  DCHECK(JSOperator::IsBinaryWithFeedback(op->opcode()));
  PrepareEagerCheckpoint();
  Node* left =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* right = environment()->LookupAccumulator();

  FeedbackSlot slot =
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex);
  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedBinaryOp(op, left, right, slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
    node = NewNode(op, left, right, feedback_vector_node());
  }

  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

// Helper function to create for-in mode from the recorded type feedback.
ForInMode BytecodeGraphBuilder::GetForInMode(FeedbackSlot slot) {
  FeedbackSource source(feedback_vector(), slot);
  switch (broker()->GetFeedbackForForIn(source)) {
    case ForInHint::kNone:
    case ForInHint::kEnumCacheKeysAndIndices:
      return ForInMode::kUseEnumCacheKeysAndIndices;
    case ForInHint::kEnumCacheKeys:
      return ForInMode::kUseEnumCacheKeys;
    case ForInHint::kAny:
      return ForInMode::kGeneric;
  }
  UNREACHABLE();
}

CallFrequency BytecodeGraphBuilder::ComputeCallFrequency(int slot_id) const {
  if (invocation_frequency_.IsUnknown()) return CallFrequency();
  FeedbackSlot slot = FeedbackVector::ToSlot(slot_id);
  FeedbackSource source(feedback_vector(), slot);
  ProcessedFeedback const& feedback = broker()->GetFeedbackForCall(source);
  float feedback_frequency =
      feedback.IsInsufficient() ? 0.0f : feedback.AsCall().frequency();
  if (feedback_frequency == 0.0f) {  // Prevent multiplying zero and infinity.
    return CallFrequency(0.0f);
  } else {
    return CallFrequency(feedback_frequency * invocation_frequency_.value());
  }
}

SpeculationMode BytecodeGraphBuilder::GetSpeculationMode(int slot_id) const {
  FeedbackSlot slot = FeedbackVector::ToSlot(slot_id);
  FeedbackSource source(feedback_vector(), slot);
  ProcessedFeedback const& feedback = broker()->GetFeedbackForCall(source);
  return feedback.IsInsufficient() ? SpeculationMode::kDisallowSpeculation
                                   : feedback.AsCall().speculation_mode();
}

CallFeedbackRelation BytecodeGraphBuilder::ComputeCallFeedbackRelation(
    int slot_id) const {
  FeedbackSlot slot = FeedbackVector::ToSlot(slot_id);
  FeedbackSource source(feedback_vector(), slot);
  ProcessedFeedback const& feedback = broker()->GetFeedbackForCall(source);
  if (feedback.IsInsufficient()) return CallFeedbackRelation::kUnrelated;
  CallFeedbackContent call_feedback_content =
      feedback.AsCall().call_feedback_content();
  return call_feedback_content == CallFeedbackContent::kTarget
             ? CallFeedbackRelation::kTarget
             : CallFeedbackRelation::kReceiver;
}

void BytecodeGraphBuilder::VisitBitwiseNot() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kUnaryOperationHintIndex));
  BuildUnaryOp(javascript()->BitwiseNot(feedback));
}

void BytecodeGraphBuilder::VisitDec() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kUnaryOperationHintIndex));
  BuildUnaryOp(javascript()->Decrement(feedback));
}

void BytecodeGraphBuilder::VisitInc() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kUnaryOperationHintIndex));
  BuildUnaryOp(javascript()->Increment(feedback));
}

void BytecodeGraphBuilder::VisitNegate() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kUnaryOperationHintIndex));
  BuildUnaryOp(javascript()->Negate(feedback));
}

void BytecodeGraphBuilder::VisitAdd() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->Add(feedback));
}

void BytecodeGraphBuilder::VisitSub() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->Subtract(feedback));
}

void BytecodeGraphBuilder::VisitMul() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->Multiply(feedback));
}

void BytecodeGraphBuilder::VisitDiv() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->Divide(feedback));
}

void BytecodeGraphBuilder::VisitMod() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->Modulus(feedback));
}

void BytecodeGraphBuilder::VisitExp() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->Exponentiate(feedback));
}

void BytecodeGraphBuilder::VisitBitwiseOr() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->BitwiseOr(feedback));
}

void BytecodeGraphBuilder::VisitBitwiseXor() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->BitwiseXor(feedback));
}

void BytecodeGraphBuilder::VisitBitwiseAnd() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->BitwiseAnd(feedback));
}

void BytecodeGraphBuilder::VisitShiftLeft() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->ShiftLeft(feedback));
}

void BytecodeGraphBuilder::VisitShiftRight() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javas
```