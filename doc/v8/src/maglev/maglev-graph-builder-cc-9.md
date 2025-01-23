Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/maglev/maglev-graph-builder.cc`. They are specifically interested in:

1. **Listing the functionalities** of the code.
2. **Checking if it's Torque code:** This can be done by looking for the `.tq` extension.
3. **Relating it to JavaScript:** If applicable, provide JavaScript examples.
4. **Illustrating code logic:** Provide example inputs and outputs.
5. **Highlighting common programming errors:** Give examples of errors related to the code.
6. **Summarizing the overall functionality** as part 10 of 18.

Let's break down the code snippet section by section and identify its purpose.

**Code Analysis:**

* **`VisitTypeOf`:**  This function appears to handle the `typeof` operator in JavaScript. It checks the type of a value and sets the accumulator accordingly. It handles `callable` types specifically.
* **`VisitDeletePropertyStrict` & `VisitDeletePropertySloppy`:** These functions handle the `delete` operator in JavaScript, distinguishing between strict and sloppy mode. They create a `DeleteProperty` node in the Maglev graph.
* **`VisitGetSuperConstructor`:** This function retrieves the constructor of the superclass. It attempts to optimize by checking for stable maps.
* **`HasValidInitialMap`:** This helper function checks if a `new_target` function has a valid initial map that matches the constructor.
* **`TryBuildFindNonDefaultConstructorOrConstruct`:** This function tries to optimize the process of finding a non-default constructor or constructing an object. It handles cases where the constructor is a default derived or base constructor. It involves checks for class fields and private methods.
* **`VisitFindNonDefaultConstructorOrConstruct`:** This function calls `TryBuildFindNonDefaultConstructorOrConstruct` or falls back to a builtin call.
* **`BuildInlined`:** This function handles the inlining of function calls. It sets up the arguments and context for the inlined function and builds its body.
* **`ShouldInlineCall`:** This function determines whether a function call should be inlined based on various criteria like bytecode size, call frequency, and inlining depth.
* **`TryBuildInlinedCall`:** This function attempts to inline a function call. It creates a new compilation unit and graph builder for the inlined function.
* **`TryReduceArrayIsArray`:** This function tries to optimize the `Array.isArray()` call. It checks the type of the argument and uses known map information.
* **`TryReduceArrayForEach`:** This function attempts to optimize the `Array.prototype.forEach()` method by inlining its execution. It involves checks for fast array iteration, elements kind, and dependencies. It uses a sub-graph builder to handle the loop.
* **`TryReduceArrayIteratorPrototypeNext`:** This function tries to optimize the `next()` method of an array iterator. It handles fast array iteration and loads elements based on the elements kind. It also uses a sub-graph builder.

**Overall Functionality:**

The code snippet focuses on building the Maglev graph for various JavaScript operations, including:

* **Type checks:**  Handling the `typeof` operator.
* **Property deletion:** Implementing the `delete` operator.
* **Constructor retrieval:**  Getting the super constructor.
* **Object construction:** Optimizing the process of finding and calling constructors, especially for inheritance.
* **Function inlining:** Determining when and how to inline function calls for performance.
* **Array methods:** Optimizing calls to `Array.isArray()`, `Array.prototype.forEach()`, and array iterator methods.

Now, let's formulate the response based on these observations.
```cpp
void MaglevGraphBuilder::VisitTypeOf() {
  ValueNode* value = GetAccumulator();
  switch (value->type()) {
    case NodeType::kHeapConstant: {
      compiler::HeapObjectRef ref =
          value->Cast<HeapConstant>()->value().AsHeapObject();
      if (ref.is_callable()) {
        SetAccumulator(GetRootConstant(RootIndex::kfunction_string));
        return;
      }
      if (ref.is_undetectable()) {
        SetAccumulator(GetRootConstant(RootIndex::kUndefinedValue));
        return;
      }
      break;
    }
    case NodeType::kBoolean:
      SetAccumulator(GetRootConstant(RootIndex::kboolean_string));
      return;
    case NodeType::kNumber:
      SetAccumulator(GetRootConstant(RootIndex::knumber_string));
      return;
    case NodeType::kString:
      SetAccumulator(GetRootConstant(RootIndex::kstring_string));
      return;
    case NodeType::kSymbol:
      SetAccumulator(GetRootConstant(RootIndex::ksymbol_string));
      return;
    case NodeType::kNull:
      SetAccumulator(GetRootConstant(RootIndex::kobject_string));
      return;
    case NodeType::kUndefined:
      SetAccumulator(GetRootConstant(RootIndex::kundefined_string));
      return;
    case NodeType::kBigInt:
      SetAccumulator(GetRootConstant(RootIndex::kbigint_string));
      return;
    case NodeType::kJSReceiver:
      // typeof callables is "function", others are "object".
      // TODO(leszeks): Use CheckMaps to refine the type.
      if (CheckType(GetType(value)));
      EnsureType(value, NodeType::kCallable);
      SetAccumulator(GetRootConstant(RootIndex::kfunction_string));
      return;
    default:
      break;
  }

  SetAccumulator(BuildCallBuiltin<Builtin::kTypeof>({GetTaggedValue(value)}));
}

void MaglevGraphBuilder::VisitDeletePropertyStrict() {
  ValueNode* object = LoadRegister(0);
  ValueNode* key = GetAccumulator();
  ValueNode* context = GetContext();
  SetAccumulator(AddNewNode<DeleteProperty>({context, object, key},
                                            LanguageMode::kStrict));
}

void MaglevGraphBuilder::VisitDeletePropertySloppy() {
  ValueNode* object = LoadRegister(0);
  ValueNode* key = GetAccumulator();
  ValueNode* context = GetContext();
  SetAccumulator(AddNewNode<DeleteProperty>({context, object, key},
                                            LanguageMode::kSloppy));
}

void MaglevGraphBuilder::VisitGetSuperConstructor() {
  ValueNode* active_function = GetAccumulator();
  // TODO(victorgomes): Maybe BuildLoadTaggedField should support constants
  // instead.
  if (compiler::OptionalHeapObjectRef constant =
          TryGetConstant(active_function)) {
    compiler::MapRef map = constant->map(broker());
    if (map.is_stable()) {
      broker()->dependencies()->DependOnStableMap(map);
      ValueNode* map_proto = GetConstant(map.prototype(broker()));
      StoreRegister(iterator_.GetRegisterOperand(0), map_proto);
      return;
    }
  }
  ValueNode* map =
      BuildLoadTaggedField(active_function, HeapObject::kMapOffset);
  ValueNode* map_proto = BuildLoadTaggedField(map, Map::kPrototypeOffset);
  StoreRegister(iterator_.GetRegisterOperand(0), map_proto);
}

bool MaglevGraphBuilder::HasValidInitialMap(
    compiler::JSFunctionRef new_target, compiler::JSFunctionRef constructor) {
  if (!new_target.map(broker()).has_prototype_slot()) return false;
  if (!new_target.has_initial_map(broker())) return false;
  compiler::MapRef initial_map = new_target.initial_map(broker());
  return initial_map.GetConstructor(broker()).equals(constructor);
}

bool MaglevGraphBuilder::TryBuildFindNonDefaultConstructorOrConstruct(
    ValueNode* this_function, ValueNode* new_target,
    std::pair<interpreter::Register, interpreter::Register> result) {
  // See also:
  // JSNativeContextSpecialization::ReduceJSFindNonDefaultConstructorOrConstruct

  compiler::OptionalHeapObjectRef maybe_constant =
      TryGetConstant(this_function);
  if (!maybe_constant) return false;

  compiler::MapRef function_map = maybe_constant->map(broker());
  compiler::HeapObjectRef current = function_map.prototype(broker());

  // TODO(v8:13091): Don't produce incomplete stack traces when debug is active.
  // We already deopt when a breakpoint is set. But it would be even nicer to
  // avoid producting incomplete stack traces when when debug is active, even if
  // there are no breakpoints - then a user inspecting stack traces via Dev
  // Tools would always see the full stack trace.

  while (true) {
    if (!current.IsJSFunction()) return false;
    compiler::JSFunctionRef current_function = current.AsJSFunction();

    // If there are class fields, bail out. TODO(v8:13091): Handle them here.
    if (current_function.shared(broker())
            .requires_instance_members_initializer()) {
      return false;
    }

    // If there are private methods, bail out. TODO(v8:13091): Handle them here.
    if (current_function.context(broker())
            .scope_info(broker())
            .ClassScopeHasPrivateBrand()) {
      return false;
    }

    FunctionKind kind = current_function.shared(broker()).kind();
    if (kind != FunctionKind::kDefaultDerivedConstructor) {
      // The hierarchy walk will end here; this is the last change to bail out
      // before creating new nodes.
      if (!broker()->dependencies()->DependOnArrayIteratorProtector()) {
        return false;
      }

      compiler::OptionalHeapObjectRef new_target_function =
          TryGetConstant(new_target);
      if (kind == FunctionKind::kDefaultBaseConstructor) {
        // Store the result register first, so that a lazy deopt in
        // `FastNewObject` writes `true` to this register.
        StoreRegister(result.first, GetBooleanConstant(true));

        ValueNode* object;
        if (new_target_function && new_target_function->IsJSFunction() &&
            HasValidInitialMap(new_target_function->AsJSFunction(),
                               current_function)) {
          object = BuildInlinedAllocation(
              CreateJSConstructor(new_target_function->AsJSFunction()),
              AllocationType::kYoung);
          ClearCurrentAllocationBlock();
        } else {
          object = BuildCallBuiltin<Builtin::kFastNewObject>(
              {GetConstant(current_function), GetTaggedValue(new_target)});
          // We've already stored "true" into result.first, so a deopt here just
          // has to store result.second. Also mark result.first as being used,
          // since the lazy deopt frame won't have marked it since it used to be
          // a result register.
          AddDeoptUse(current_interpreter_frame_.get(result.first));
          object->lazy_deopt_info()->UpdateResultLocation(result.second, 1);
        }
        StoreRegister(result.second, object);
      } else {
        StoreRegister(result.first, GetBooleanConstant(false));
        StoreRegister(result.second, GetConstant(current));
      }

      broker()->dependencies()->DependOnStablePrototypeChain(
          function_map, WhereToStart::kStartAtReceiver, current_function);
      return true;
    }

    // Keep walking up the class tree.
    current = current_function.map(broker()).prototype(broker());
  }
}

void MaglevGraphBuilder::VisitFindNonDefaultConstructorOrConstruct() {
  ValueNode* this_function = LoadRegister(0);
  ValueNode* new_target = LoadRegister(1);

  auto register_pair = iterator_.GetRegisterPairOperand(2);

  if (TryBuildFindNonDefaultConstructorOrConstruct(this_function, new_target,
                                                   register_pair)) {
    return;
  }

  CallBuiltin* result =
      BuildCallBuiltin<Builtin::kFindNonDefaultConstructorOrConstruct>(
          {GetTaggedValue(this_function), GetTaggedValue(new_target)});
  StoreRegisterPair(register_pair, result);
}

namespace {
void ForceEscapeIfAllocation(ValueNode* value) {
  if (InlinedAllocation* alloc = value->TryCast<InlinedAllocation>()) {
    alloc->ForceEscaping();
  }
}
}  // namespace

ReduceResult MaglevGraphBuilder::BuildInlined(ValueNode* context,
                                              ValueNode* function,
                                              ValueNode* new_target,
                                              const CallArguments& args) {
  DCHECK(is_inline());

  // Manually create the prologue of the inner function graph, so that we
  // can manually set up the arguments.
  DCHECK_NOT_NULL(current_block_);

  // Set receiver.
  ValueNode* receiver =
      GetConvertReceiver(compilation_unit_->shared_function_info(), args);
  SetArgument(0, receiver);

  // The inlined function could call a builtin that iterates the frame, the
  // receiver needs to have been materialized.
  // TODO(victorgomes): Can we relax this requirement? Maybe we can allocate the
  // object lazily? This is also only required if the inlined function is not a
  // leaf (ie. it calls other functions).
  ForceEscapeIfAllocation(receiver);

  // Set remaining arguments.
  RootConstant* undefined_constant =
      GetRootConstant(RootIndex::kUndefinedValue);
  int arg_count = static_cast<int>(args.count());
  int formal_parameter_count = compilation_unit_->parameter_count() - 1;
  for (int i = 0; i < formal_parameter_count; i++) {
    ValueNode* arg_value = args[i];
    if (arg_value == nullptr) arg_value = undefined_constant;
    SetArgument(i + 1, arg_value);
  }

  // Save all arguments if we have a mismatch between arguments count and
  // parameter count.
  inlined_arguments_ = zone()->AllocateVector<ValueNode*>(arg_count + 1);
  inlined_arguments_[0] = receiver;
  for (int i = 0; i < arg_count; i++) {
    inlined_arguments_[i + 1] = args[i];
  }

  inlined_new_target_ = new_target;

  BuildRegisterFrameInitialization(context, function, new_target);
  BuildMergeStates();
  EndPrologue();
  in_prologue_ = false;

  // Build the inlined function body.
  BuildBody();

  // All returns in the inlined body jump to a merge point one past the bytecode
  // length (i.e. at offset bytecode.length()). If there isn't one already,
  // create a block at this fake offset and have it jump out of the inlined
  // function, into a new block that we create which resumes execution of the
  // outer function.
  if (!current_block_) {
    // If we don't have a merge state at the inline_exit_offset, then there is
    // no control flow that reaches the end of the inlined function, either
    // because of infinite loops or deopts
    if (merge_states_[inline_exit_offset()] == nullptr) {
      return ReduceResult::DoneWithAbort();
    }

    ProcessMergePoint(inline_exit_offset(), /*preserve_kna*/ false);
    StartNewBlock(inline_exit_offset(), /*predecessor*/ nullptr);
  }

  // Pull the returned accumulator value out of the inlined function's final
  // merged return state.
  return current_interpreter_frame_.accumulator();
}

#define TRACE_INLINING(...)                       \
  do {                                            \
    if (v8_flags.trace_maglev_inlining)           \
      StdoutStream{} << __VA_ARGS__ << std::endl; \
  } while (false)

#define TRACE_CANNOT_INLINE(...) \
  TRACE_INLINING("  cannot inline " << shared << ": " << __VA_ARGS__)

bool MaglevGraphBuilder::ShouldInlineCall(
    compiler::SharedFunctionInfoRef shared,
    compiler::OptionalFeedbackVectorRef feedback_vector, float call_frequency) {
  if (graph()->total_inlined_bytecode_size() >
      v8_flags.max_maglev_inlined_bytecode_size_cumulative) {
    compilation_unit_->info()->set_could_not_inline_all_candidates();
    TRACE_CANNOT_INLINE("maximum inlined bytecode size");
    return false;
  }
  if (!feedback_vector) {
    // TODO(verwaest): Soft deopt instead?
    TRACE_CANNOT_INLINE("it has not been compiled/run with feedback yet");
    return false;
  }
  // TODO(olivf): This is a temporary stopgap to prevent infinite recursion when
  // inlining, because we currently excempt small functions from some of the
  // negative heuristics. We should refactor these heuristics and make sure they
  // make sense in the presence of (mutually) recursive inlining. Please do
  // *not* return true before this check.
  if (inlining_depth() > v8_flags.max_maglev_hard_inline_depth) {
    TRACE_CANNOT_INLINE("inlining depth ("
                        << inlining_depth() << ") >= hard-max-depth ("
                        << v8_flags.max_maglev_hard_inline_depth << ")");
    return false;
  }
  if (compilation_unit_->shared_function_info().equals(shared)) {
    TRACE_CANNOT_INLINE("direct recursion");
    return false;
  }
  SharedFunctionInfo::Inlineability inlineability =
      shared.GetInlineability(broker());
  if (inlineability != SharedFunctionInfo::Inlineability::kIsInlineable) {
    TRACE_CANNOT_INLINE(inlineability);
    return false;
  }
  // TODO(victorgomes): Support NewTarget/RegisterInput in inlined functions.
  compiler::BytecodeArrayRef bytecode = shared.GetBytecodeArray(broker());
  if (bytecode.incoming_new_target_or_generator_register().is_valid()) {
    TRACE_CANNOT_INLINE("use unsupported NewTargetOrGenerator register");
    return false;
  }
  if (call_frequency < v8_flags.min_maglev_inlining_frequency) {
    TRACE_CANNOT_INLINE("call frequency ("
                        << call_frequency << ") < minimum threshold ("
                        << v8_flags.min_maglev_inlining_frequency << ")");
    return false;
  }
  if (bytecode.length() < v8_flags.max_maglev_inlined_bytecode_size_small) {
    TRACE_INLINING("  inlining "
                   << shared
                   << ": small function, skipping max-size and max-depth");
    return true;
  }
  if (bytecode.length() > v8_flags.max_maglev_inlined_bytecode_size) {
    TRACE_CANNOT_INLINE("big function, size ("
                        << bytecode.length() << ") >= max-size ("
                        << v8_flags.max_maglev_inlined_bytecode_size << ")");
    return false;
  }
  if (inlining_depth() > v8_flags.max_maglev_inline_depth) {
    TRACE_CANNOT_INLINE("inlining depth ("
                        << inlining_depth() << ") >= max-depth ("
                        << v8_flags.max_maglev_inline_depth << ")");
    return false;
  }
  TRACE_INLINING("  inlining " << shared);
  if (v8_flags.trace_maglev_inlining_verbose) {
    BytecodeArray::Disassemble(bytecode.object(), std::cout);
    i::Print(*feedback_vector->object(), std::cout);
  }
  graph()->add_inlined_bytecode_size(bytecode.length());
  return true;
}

ReduceResult MaglevGraphBuilder::TryBuildInlinedCall(
    ValueNode* context, ValueNode* function, ValueNode* new_target,
    compiler::SharedFunctionInfoRef shared,
    compiler::OptionalFeedbackVectorRef feedback_vector, CallArguments& args,
    const compiler::FeedbackSource& feedback_source) {
  DCHECK_EQ(args.mode(), CallArguments::kDefault);
  float feedback_frequency = 0.0f;
  if (feedback_source.IsValid()) {
    compiler::ProcessedFeedback const& feedback =
        broker()->GetFeedbackForCall(feedback_source);
    feedback_frequency =
        feedback.IsInsufficient() ? 0.0f : feedback.AsCall().frequency();
  }
  float call_frequency = feedback_frequency * call_frequency_;
  if (!ShouldInlineCall(shared, feedback_vector, call_frequency)) {
    return ReduceResult::Fail();
  }

  compiler::BytecodeArrayRef bytecode = shared.GetBytecodeArray(broker());

  if (v8_flags.maglev_print_inlined &&
      TopLevelFunctionPassMaglevPrintFilter() &&
      (v8_flags.print_maglev_code || v8_flags.print_maglev_graph ||
       v8_flags.print_maglev_graphs)) {
    std::cout << "== Inlining " << Brief(*shared.object()) << std::endl;
    BytecodeArray::Disassemble(bytecode.object(), std::cout);
    if (v8_flags.maglev_print_feedback) {
      i::Print(*feedback_vector->object(), std::cout);
    }
  } else if (v8_flags.trace_maglev_graph_building) {
    std::cout << "== Inlining " << shared.object() << std::endl;
  }

  graph()->inlined_functions().push_back(
      OptimizedCompilationInfo::InlinedFunctionHolder(
          shared.object(), bytecode.object(), current_source_position_));
  if (feedback_vector->object()->invocation_count_before_stable(kRelaxedLoad) >
      v8_flags.invocation_count_for_early_optimization) {
    compilation_unit_->info()->set_could_not_inline_all_candidates();
  }
  int inlining_id = static_cast<int>(graph()->inlined_functions().size() - 1);

  // Create a new compilation unit and graph builder for the inlined
  // function.
  MaglevCompilationUnit* inner_unit = MaglevCompilationUnit::NewInner(
      zone(), compilation_unit_, shared, feedback_vector.value());
  MaglevGraphBuilder inner_graph_builder(
      local_isolate_, inner_unit, graph_, call_frequency,
      BytecodeOffset(iterator_.current_offset()), IsInsideLoop(), inlining_id,
      this);

  // Merge catch block state if needed.
  CatchBlockDetails catch_block = GetCurrentTryCatchBlock();
  if (catch_block.ref && catch_block.state->exception_handler_was_used()) {
    // Merge the current state into the handler state.
    catch_block.state->MergeThrow(
        GetCurrentCatchBlockGraphBuilder(), catch_block.unit,
        *current_interpreter_frame_.known_node_aspects(),
        current_interpreter_frame_.virtual_objects());
  }

  // Propagate catch block.
  inner_graph_builder.parent_catch_ = catch_block;
  inner_graph_builder.parent_catch_deopt_frame_distance_ =
      1 + (IsInsideTryBlock() ? 0 : parent_catch_deopt_frame_distance_);

  // Set the inner graph builder to build in the current block.
  inner_graph_builder.current_block_ = current_block_;

  ReduceResult result =
      inner_graph_builder.BuildInlined(context, function, new_target, args);
  if (result.IsDoneWithAbort()) {
    DCHECK_NULL(inner_graph_builder.current_block_);
    current_block_ = nullptr;
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "== Finished inlining (abort) " << shared.object()
                << std::endl;
    }
    return ReduceResult::DoneWithAbort();
  }

  // Propagate KnownNodeAspects back to the caller.
  current_interpreter_frame_.set_known_node_aspects(
      inner_graph_builder.current_interpreter_frame_.known_node_aspects());
  unobserved_context_slot_stores_ =
      inner_graph_builder.unobserved_context_slot_stores_;

  // Propagate virtual object lists back to the caller.
  current_interpreter_frame_.set_virtual_objects(
      inner_graph_builder.current_interpreter_frame_.virtual_objects());

  DCHECK(result.IsDoneWithValue());
  // Resume execution using the final block of the inner builder.
  current_block_ = inner_graph_builder.current_block_;

  if (v8_flags.trace_maglev_graph_building) {
    std::cout << "== Finished inlining " << shared.object() << std::endl;
  }
  return result;
}

namespace {

bool CanInlineArrayIteratingBuiltin(compiler::JSHeapBroker* broker,
                                    const PossibleMaps& maps,
                                    ElementsKind* kind_return) {
  DCHECK_NE(0, maps.size());
  *kind_return = maps.at(0).elements_kind();
  for (compiler::MapRef map : maps) {
    if (!map.supports_fast_array_iteration(broker) ||
        !UnionElementsKindUptoSize(kind_return, map.elements_kind())) {
      return false;
    }
  }
  return true;
}

}  // namespace

ReduceResult MaglevGraphBuilder::TryReduceArrayIsArray(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() == 0) return GetBooleanConstant(false);

  ValueNode* node = args[0];

  if (CheckType(node, NodeType::kJSArray)) {
    return GetBooleanConstant(true);
  }

  auto node_info = known_node_aspects().TryGetInfoFor(node);
  if (node_info && node_info->possible_maps_are_known()) {
    bool has_array_map = false;
    bool has_proxy_map = false;
    bool has_other_map = false;
    for (compiler::MapRef map : node_info->possible_maps()) {
      InstanceType type = map.instance_type();
      if (InstanceTypeChecker::IsJSArray(type)) {
        has_array_map = true;
      } else if (InstanceTypeChecker::IsJSProxy(type)) {
        has_proxy_map = true;
      } else {
        has_other_map = true;
      }
    }
    if ((has_array_map ^ has_other_map) && !has_proxy_map) {
      if (has_array_map) node_info->CombineType(NodeType::kJSArray);
      return GetBooleanConstant(has_array_map);
    }
  }

  // TODO(verwaest): Add a node that checks the instance type.
  return ReduceResult::Fail();
}

ReduceResult MaglevGraphBuilder::TryReduceArrayForEach(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }

  ValueNode* receiver = args.receiver();
  if (!receiver) return ReduceResult::Fail();

  if (args.count() < 1) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.forEach - not enough "
                   "arguments"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  auto node_info = known_node_aspects().TryGetInfoFor(receiver);
  if (!node_info || !node_info->possible_maps_are_known()) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.forEach - receiver "
                   "map is unknown"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  ElementsKind elements_kind;
  if (!CanInlineArrayIteratingBuiltin(broker(), node_info->possible_maps(),
                                      &elements_kind)) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.forEach - doesn't "
                   "support fast array iteration or incompatible maps"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  // TODO(leszeks): May only be needed for holey elements kinds.
  if (!broker()->dependencies()->DependOnNoElementsProtector()) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.forEach - invalidated "
                   "no elements protector"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  ValueNode* callback = args[0];
  if (!callback->is_tagged()) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.forEach - callback is "
                   "untagged value"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  ValueNode* this_arg =
      args.count() > 1 ? args[1] : GetRootConstant(RootIndex::kUndefinedValue);

  ValueNode* original_length = BuildLoadJSArrayLength(receiver);

  // Elide the callable check if the node is known callable.
  EnsureType(callback, NodeType::kCallable, [&](NodeType old_type) {
    // ThrowIfNotCallable is wrapped in a lazy_deopt_scope to make sure the
    // exception has the right call stack.
    DeoptFrameScope lazy_deopt_scope(
        this, Builtin::kArrayForEachLoopLazyDeoptContinuation, target,
        base::VectorOf<ValueNode*>({receiver, callback, this_arg,
                                    GetSmiConstant(0), original_length}));
    AddNewNode<ThrowIfNotCallable>({callback});
  });

  ValueNode* original_length_int32 = GetInt32(original_length);

  // Remember the receiver map set before entering the loop the call.
  bool receiver_maps_were_unstable = node_info->possible_maps_are_unstable();
  PossibleMaps receiver_maps_before_loop(node_info->possible_maps());

  // Create a sub graph builder with two variable (index and length)
  MaglevSubGraphBuilder sub_builder(this, 2);
  MaglevSubGraphBuilder::Variable var_index(0);
  MaglevSubGraphBuilder::Variable var_length(1);

  MaglevSubGraphBuilder::Label loop_end(&sub_builder, 1);

  // ```
  // index = 0
  // bind loop_header
  // ```
  sub_builder.set(var_index, GetSmiConstant(0));
  sub_builder.set(var_length, original_length);
  MaglevSubGraphBuilder::LoopLabel loop_header =
      sub_builder.BeginLoop({&var_index, &var_length});

  // Reset known state that is cleared by BeginLoop, but is known to be true on
  // the first iteration, and will be re-checked at the end of the loop.

  // Reset the known receiver maps if necessary.
  if (receiver_maps_were_unstable) {
    node_info->SetPossibleMaps(receiver_maps_before_loop,
                               receiver_maps_were_unstable,
                               // Node type is monotonic, no need to reset it.
                               NodeType::kUnknown, broker());
    known_node_aspects().any_map_for_any_node_is_unstable = true;
  } else {
    DCHECK_EQ(node_info->possible_maps().size(),
              receiver_maps_before_loop.size());
  }
  // Reset the cached loaded array length to the length var.
  RecordKnownProperty(receiver, broker()->length_string(),
                      sub_builder.get(var_length), false,
                      compiler::AccessMode::kLoad);

  // ```
  // if (index_int32 < length_int32)
  //   fallthrough
  // else
  //   goto end
  // ```
  Phi* index_tagged = sub_builder.get(var_index)->Cast<Phi>();
  EnsureType(index_tagged, NodeType::kSmi);
  ValueNode* index_int32 = GetInt32(index_tagged);

  sub_builder.GotoIfFalse<BranchIfInt32Compare>(
      &loop_end, {index_int32, original_length_int32}, Operation::kLessThan);

  // ```
  // next_index = index + 1
  // ```
  ValueNode* next_index_int32 = nullptr;
  {
    // Eager deopt scope for index increment overflow.
    // TODO(pthier): In practice this increment can never overflow, as the max
    // possible array length is less than int32 max value. Add a new
    // Int32Increment that asserts no overflow instead of deopting.
    DeoptFrameScope eager_deopt_scope(
        this, Builtin::kArrayForEachLoopEagerDeoptContinuation, target,
        base::VectorOf<ValueNode*>(
            {receiver, callback, this_arg, index_int32, original_length}));
    next_index_int32 = AddNewNode<Int32IncrementWithOverflow>({index_int32});
    EnsureType(next_index_int32, NodeType::kSmi);
  }
  // TODO(leszeks): Assert Smi.

  // ```
  // element = array.elements[index]
  // ```
  ValueNode* elements = BuildLoadElements(receiver);
  ValueNode* element;
  if (IsDoubleElementsKind(elements_kind)) {
    element = BuildLoadFixedDoubleArrayElement(elements, index_int32);
  } else {
    element = BuildLoadFixedArrayElement(elements, index_int32);
  }

  std::optional<MaglevSub
### 提示词
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第10部分，共18部分，请归纳一下它的功能
```

### 源代码
```cpp
ckType(GetType(value)));
      EnsureType(value, NodeType::kCallable);
      SetAccumulator(GetRootConstant(RootIndex::kfunction_string));
      return;
    default:
      break;
  }

  SetAccumulator(BuildCallBuiltin<Builtin::kTypeof>({GetTaggedValue(value)}));
}

void MaglevGraphBuilder::VisitDeletePropertyStrict() {
  ValueNode* object = LoadRegister(0);
  ValueNode* key = GetAccumulator();
  ValueNode* context = GetContext();
  SetAccumulator(AddNewNode<DeleteProperty>({context, object, key},
                                            LanguageMode::kStrict));
}

void MaglevGraphBuilder::VisitDeletePropertySloppy() {
  ValueNode* object = LoadRegister(0);
  ValueNode* key = GetAccumulator();
  ValueNode* context = GetContext();
  SetAccumulator(AddNewNode<DeleteProperty>({context, object, key},
                                            LanguageMode::kSloppy));
}

void MaglevGraphBuilder::VisitGetSuperConstructor() {
  ValueNode* active_function = GetAccumulator();
  // TODO(victorgomes): Maybe BuildLoadTaggedField should support constants
  // instead.
  if (compiler::OptionalHeapObjectRef constant =
          TryGetConstant(active_function)) {
    compiler::MapRef map = constant->map(broker());
    if (map.is_stable()) {
      broker()->dependencies()->DependOnStableMap(map);
      ValueNode* map_proto = GetConstant(map.prototype(broker()));
      StoreRegister(iterator_.GetRegisterOperand(0), map_proto);
      return;
    }
  }
  ValueNode* map =
      BuildLoadTaggedField(active_function, HeapObject::kMapOffset);
  ValueNode* map_proto = BuildLoadTaggedField(map, Map::kPrototypeOffset);
  StoreRegister(iterator_.GetRegisterOperand(0), map_proto);
}

bool MaglevGraphBuilder::HasValidInitialMap(
    compiler::JSFunctionRef new_target, compiler::JSFunctionRef constructor) {
  if (!new_target.map(broker()).has_prototype_slot()) return false;
  if (!new_target.has_initial_map(broker())) return false;
  compiler::MapRef initial_map = new_target.initial_map(broker());
  return initial_map.GetConstructor(broker()).equals(constructor);
}

bool MaglevGraphBuilder::TryBuildFindNonDefaultConstructorOrConstruct(
    ValueNode* this_function, ValueNode* new_target,
    std::pair<interpreter::Register, interpreter::Register> result) {
  // See also:
  // JSNativeContextSpecialization::ReduceJSFindNonDefaultConstructorOrConstruct

  compiler::OptionalHeapObjectRef maybe_constant =
      TryGetConstant(this_function);
  if (!maybe_constant) return false;

  compiler::MapRef function_map = maybe_constant->map(broker());
  compiler::HeapObjectRef current = function_map.prototype(broker());

  // TODO(v8:13091): Don't produce incomplete stack traces when debug is active.
  // We already deopt when a breakpoint is set. But it would be even nicer to
  // avoid producting incomplete stack traces when when debug is active, even if
  // there are no breakpoints - then a user inspecting stack traces via Dev
  // Tools would always see the full stack trace.

  while (true) {
    if (!current.IsJSFunction()) return false;
    compiler::JSFunctionRef current_function = current.AsJSFunction();

    // If there are class fields, bail out. TODO(v8:13091): Handle them here.
    if (current_function.shared(broker())
            .requires_instance_members_initializer()) {
      return false;
    }

    // If there are private methods, bail out. TODO(v8:13091): Handle them here.
    if (current_function.context(broker())
            .scope_info(broker())
            .ClassScopeHasPrivateBrand()) {
      return false;
    }

    FunctionKind kind = current_function.shared(broker()).kind();
    if (kind != FunctionKind::kDefaultDerivedConstructor) {
      // The hierarchy walk will end here; this is the last change to bail out
      // before creating new nodes.
      if (!broker()->dependencies()->DependOnArrayIteratorProtector()) {
        return false;
      }

      compiler::OptionalHeapObjectRef new_target_function =
          TryGetConstant(new_target);
      if (kind == FunctionKind::kDefaultBaseConstructor) {
        // Store the result register first, so that a lazy deopt in
        // `FastNewObject` writes `true` to this register.
        StoreRegister(result.first, GetBooleanConstant(true));

        ValueNode* object;
        if (new_target_function && new_target_function->IsJSFunction() &&
            HasValidInitialMap(new_target_function->AsJSFunction(),
                               current_function)) {
          object = BuildInlinedAllocation(
              CreateJSConstructor(new_target_function->AsJSFunction()),
              AllocationType::kYoung);
          ClearCurrentAllocationBlock();
        } else {
          object = BuildCallBuiltin<Builtin::kFastNewObject>(
              {GetConstant(current_function), GetTaggedValue(new_target)});
          // We've already stored "true" into result.first, so a deopt here just
          // has to store result.second. Also mark result.first as being used,
          // since the lazy deopt frame won't have marked it since it used to be
          // a result register.
          AddDeoptUse(current_interpreter_frame_.get(result.first));
          object->lazy_deopt_info()->UpdateResultLocation(result.second, 1);
        }
        StoreRegister(result.second, object);
      } else {
        StoreRegister(result.first, GetBooleanConstant(false));
        StoreRegister(result.second, GetConstant(current));
      }

      broker()->dependencies()->DependOnStablePrototypeChain(
          function_map, WhereToStart::kStartAtReceiver, current_function);
      return true;
    }

    // Keep walking up the class tree.
    current = current_function.map(broker()).prototype(broker());
  }
}

void MaglevGraphBuilder::VisitFindNonDefaultConstructorOrConstruct() {
  ValueNode* this_function = LoadRegister(0);
  ValueNode* new_target = LoadRegister(1);

  auto register_pair = iterator_.GetRegisterPairOperand(2);

  if (TryBuildFindNonDefaultConstructorOrConstruct(this_function, new_target,
                                                   register_pair)) {
    return;
  }

  CallBuiltin* result =
      BuildCallBuiltin<Builtin::kFindNonDefaultConstructorOrConstruct>(
          {GetTaggedValue(this_function), GetTaggedValue(new_target)});
  StoreRegisterPair(register_pair, result);
}

namespace {
void ForceEscapeIfAllocation(ValueNode* value) {
  if (InlinedAllocation* alloc = value->TryCast<InlinedAllocation>()) {
    alloc->ForceEscaping();
  }
}
}  // namespace

ReduceResult MaglevGraphBuilder::BuildInlined(ValueNode* context,
                                              ValueNode* function,
                                              ValueNode* new_target,
                                              const CallArguments& args) {
  DCHECK(is_inline());

  // Manually create the prologue of the inner function graph, so that we
  // can manually set up the arguments.
  DCHECK_NOT_NULL(current_block_);

  // Set receiver.
  ValueNode* receiver =
      GetConvertReceiver(compilation_unit_->shared_function_info(), args);
  SetArgument(0, receiver);

  // The inlined function could call a builtin that iterates the frame, the
  // receiver needs to have been materialized.
  // TODO(victorgomes): Can we relax this requirement? Maybe we can allocate the
  // object lazily? This is also only required if the inlined function is not a
  // leaf (ie. it calls other functions).
  ForceEscapeIfAllocation(receiver);

  // Set remaining arguments.
  RootConstant* undefined_constant =
      GetRootConstant(RootIndex::kUndefinedValue);
  int arg_count = static_cast<int>(args.count());
  int formal_parameter_count = compilation_unit_->parameter_count() - 1;
  for (int i = 0; i < formal_parameter_count; i++) {
    ValueNode* arg_value = args[i];
    if (arg_value == nullptr) arg_value = undefined_constant;
    SetArgument(i + 1, arg_value);
  }

  // Save all arguments if we have a mismatch between arguments count and
  // parameter count.
  inlined_arguments_ = zone()->AllocateVector<ValueNode*>(arg_count + 1);
  inlined_arguments_[0] = receiver;
  for (int i = 0; i < arg_count; i++) {
    inlined_arguments_[i + 1] = args[i];
  }

  inlined_new_target_ = new_target;

  BuildRegisterFrameInitialization(context, function, new_target);
  BuildMergeStates();
  EndPrologue();
  in_prologue_ = false;

  // Build the inlined function body.
  BuildBody();

  // All returns in the inlined body jump to a merge point one past the bytecode
  // length (i.e. at offset bytecode.length()). If there isn't one already,
  // create a block at this fake offset and have it jump out of the inlined
  // function, into a new block that we create which resumes execution of the
  // outer function.
  if (!current_block_) {
    // If we don't have a merge state at the inline_exit_offset, then there is
    // no control flow that reaches the end of the inlined function, either
    // because of infinite loops or deopts
    if (merge_states_[inline_exit_offset()] == nullptr) {
      return ReduceResult::DoneWithAbort();
    }

    ProcessMergePoint(inline_exit_offset(), /*preserve_kna*/ false);
    StartNewBlock(inline_exit_offset(), /*predecessor*/ nullptr);
  }

  // Pull the returned accumulator value out of the inlined function's final
  // merged return state.
  return current_interpreter_frame_.accumulator();
}

#define TRACE_INLINING(...)                       \
  do {                                            \
    if (v8_flags.trace_maglev_inlining)           \
      StdoutStream{} << __VA_ARGS__ << std::endl; \
  } while (false)

#define TRACE_CANNOT_INLINE(...) \
  TRACE_INLINING("  cannot inline " << shared << ": " << __VA_ARGS__)

bool MaglevGraphBuilder::ShouldInlineCall(
    compiler::SharedFunctionInfoRef shared,
    compiler::OptionalFeedbackVectorRef feedback_vector, float call_frequency) {
  if (graph()->total_inlined_bytecode_size() >
      v8_flags.max_maglev_inlined_bytecode_size_cumulative) {
    compilation_unit_->info()->set_could_not_inline_all_candidates();
    TRACE_CANNOT_INLINE("maximum inlined bytecode size");
    return false;
  }
  if (!feedback_vector) {
    // TODO(verwaest): Soft deopt instead?
    TRACE_CANNOT_INLINE("it has not been compiled/run with feedback yet");
    return false;
  }
  // TODO(olivf): This is a temporary stopgap to prevent infinite recursion when
  // inlining, because we currently excempt small functions from some of the
  // negative heuristics. We should refactor these heuristics and make sure they
  // make sense in the presence of (mutually) recursive inlining. Please do
  // *not* return true before this check.
  if (inlining_depth() > v8_flags.max_maglev_hard_inline_depth) {
    TRACE_CANNOT_INLINE("inlining depth ("
                        << inlining_depth() << ") >= hard-max-depth ("
                        << v8_flags.max_maglev_hard_inline_depth << ")");
    return false;
  }
  if (compilation_unit_->shared_function_info().equals(shared)) {
    TRACE_CANNOT_INLINE("direct recursion");
    return false;
  }
  SharedFunctionInfo::Inlineability inlineability =
      shared.GetInlineability(broker());
  if (inlineability != SharedFunctionInfo::Inlineability::kIsInlineable) {
    TRACE_CANNOT_INLINE(inlineability);
    return false;
  }
  // TODO(victorgomes): Support NewTarget/RegisterInput in inlined functions.
  compiler::BytecodeArrayRef bytecode = shared.GetBytecodeArray(broker());
  if (bytecode.incoming_new_target_or_generator_register().is_valid()) {
    TRACE_CANNOT_INLINE("use unsupported NewTargetOrGenerator register");
    return false;
  }
  if (call_frequency < v8_flags.min_maglev_inlining_frequency) {
    TRACE_CANNOT_INLINE("call frequency ("
                        << call_frequency << ") < minimum threshold ("
                        << v8_flags.min_maglev_inlining_frequency << ")");
    return false;
  }
  if (bytecode.length() < v8_flags.max_maglev_inlined_bytecode_size_small) {
    TRACE_INLINING("  inlining "
                   << shared
                   << ": small function, skipping max-size and max-depth");
    return true;
  }
  if (bytecode.length() > v8_flags.max_maglev_inlined_bytecode_size) {
    TRACE_CANNOT_INLINE("big function, size ("
                        << bytecode.length() << ") >= max-size ("
                        << v8_flags.max_maglev_inlined_bytecode_size << ")");
    return false;
  }
  if (inlining_depth() > v8_flags.max_maglev_inline_depth) {
    TRACE_CANNOT_INLINE("inlining depth ("
                        << inlining_depth() << ") >= max-depth ("
                        << v8_flags.max_maglev_inline_depth << ")");
    return false;
  }
  TRACE_INLINING("  inlining " << shared);
  if (v8_flags.trace_maglev_inlining_verbose) {
    BytecodeArray::Disassemble(bytecode.object(), std::cout);
    i::Print(*feedback_vector->object(), std::cout);
  }
  graph()->add_inlined_bytecode_size(bytecode.length());
  return true;
}

ReduceResult MaglevGraphBuilder::TryBuildInlinedCall(
    ValueNode* context, ValueNode* function, ValueNode* new_target,
    compiler::SharedFunctionInfoRef shared,
    compiler::OptionalFeedbackVectorRef feedback_vector, CallArguments& args,
    const compiler::FeedbackSource& feedback_source) {
  DCHECK_EQ(args.mode(), CallArguments::kDefault);
  float feedback_frequency = 0.0f;
  if (feedback_source.IsValid()) {
    compiler::ProcessedFeedback const& feedback =
        broker()->GetFeedbackForCall(feedback_source);
    feedback_frequency =
        feedback.IsInsufficient() ? 0.0f : feedback.AsCall().frequency();
  }
  float call_frequency = feedback_frequency * call_frequency_;
  if (!ShouldInlineCall(shared, feedback_vector, call_frequency)) {
    return ReduceResult::Fail();
  }

  compiler::BytecodeArrayRef bytecode = shared.GetBytecodeArray(broker());

  if (v8_flags.maglev_print_inlined &&
      TopLevelFunctionPassMaglevPrintFilter() &&
      (v8_flags.print_maglev_code || v8_flags.print_maglev_graph ||
       v8_flags.print_maglev_graphs)) {
    std::cout << "== Inlining " << Brief(*shared.object()) << std::endl;
    BytecodeArray::Disassemble(bytecode.object(), std::cout);
    if (v8_flags.maglev_print_feedback) {
      i::Print(*feedback_vector->object(), std::cout);
    }
  } else if (v8_flags.trace_maglev_graph_building) {
    std::cout << "== Inlining " << shared.object() << std::endl;
  }

  graph()->inlined_functions().push_back(
      OptimizedCompilationInfo::InlinedFunctionHolder(
          shared.object(), bytecode.object(), current_source_position_));
  if (feedback_vector->object()->invocation_count_before_stable(kRelaxedLoad) >
      v8_flags.invocation_count_for_early_optimization) {
    compilation_unit_->info()->set_could_not_inline_all_candidates();
  }
  int inlining_id = static_cast<int>(graph()->inlined_functions().size() - 1);

  // Create a new compilation unit and graph builder for the inlined
  // function.
  MaglevCompilationUnit* inner_unit = MaglevCompilationUnit::NewInner(
      zone(), compilation_unit_, shared, feedback_vector.value());
  MaglevGraphBuilder inner_graph_builder(
      local_isolate_, inner_unit, graph_, call_frequency,
      BytecodeOffset(iterator_.current_offset()), IsInsideLoop(), inlining_id,
      this);

  // Merge catch block state if needed.
  CatchBlockDetails catch_block = GetCurrentTryCatchBlock();
  if (catch_block.ref && catch_block.state->exception_handler_was_used()) {
    // Merge the current state into the handler state.
    catch_block.state->MergeThrow(
        GetCurrentCatchBlockGraphBuilder(), catch_block.unit,
        *current_interpreter_frame_.known_node_aspects(),
        current_interpreter_frame_.virtual_objects());
  }

  // Propagate catch block.
  inner_graph_builder.parent_catch_ = catch_block;
  inner_graph_builder.parent_catch_deopt_frame_distance_ =
      1 + (IsInsideTryBlock() ? 0 : parent_catch_deopt_frame_distance_);

  // Set the inner graph builder to build in the current block.
  inner_graph_builder.current_block_ = current_block_;

  ReduceResult result =
      inner_graph_builder.BuildInlined(context, function, new_target, args);
  if (result.IsDoneWithAbort()) {
    DCHECK_NULL(inner_graph_builder.current_block_);
    current_block_ = nullptr;
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "== Finished inlining (abort) " << shared.object()
                << std::endl;
    }
    return ReduceResult::DoneWithAbort();
  }

  // Propagate KnownNodeAspects back to the caller.
  current_interpreter_frame_.set_known_node_aspects(
      inner_graph_builder.current_interpreter_frame_.known_node_aspects());
  unobserved_context_slot_stores_ =
      inner_graph_builder.unobserved_context_slot_stores_;

  // Propagate virtual object lists back to the caller.
  current_interpreter_frame_.set_virtual_objects(
      inner_graph_builder.current_interpreter_frame_.virtual_objects());

  DCHECK(result.IsDoneWithValue());
  // Resume execution using the final block of the inner builder.
  current_block_ = inner_graph_builder.current_block_;

  if (v8_flags.trace_maglev_graph_building) {
    std::cout << "== Finished inlining " << shared.object() << std::endl;
  }
  return result;
}

namespace {

bool CanInlineArrayIteratingBuiltin(compiler::JSHeapBroker* broker,
                                    const PossibleMaps& maps,
                                    ElementsKind* kind_return) {
  DCHECK_NE(0, maps.size());
  *kind_return = maps.at(0).elements_kind();
  for (compiler::MapRef map : maps) {
    if (!map.supports_fast_array_iteration(broker) ||
        !UnionElementsKindUptoSize(kind_return, map.elements_kind())) {
      return false;
    }
  }
  return true;
}

}  // namespace

ReduceResult MaglevGraphBuilder::TryReduceArrayIsArray(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() == 0) return GetBooleanConstant(false);

  ValueNode* node = args[0];

  if (CheckType(node, NodeType::kJSArray)) {
    return GetBooleanConstant(true);
  }

  auto node_info = known_node_aspects().TryGetInfoFor(node);
  if (node_info && node_info->possible_maps_are_known()) {
    bool has_array_map = false;
    bool has_proxy_map = false;
    bool has_other_map = false;
    for (compiler::MapRef map : node_info->possible_maps()) {
      InstanceType type = map.instance_type();
      if (InstanceTypeChecker::IsJSArray(type)) {
        has_array_map = true;
      } else if (InstanceTypeChecker::IsJSProxy(type)) {
        has_proxy_map = true;
      } else {
        has_other_map = true;
      }
    }
    if ((has_array_map ^ has_other_map) && !has_proxy_map) {
      if (has_array_map) node_info->CombineType(NodeType::kJSArray);
      return GetBooleanConstant(has_array_map);
    }
  }

  // TODO(verwaest): Add a node that checks the instance type.
  return ReduceResult::Fail();
}

ReduceResult MaglevGraphBuilder::TryReduceArrayForEach(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }

  ValueNode* receiver = args.receiver();
  if (!receiver) return ReduceResult::Fail();

  if (args.count() < 1) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.forEach - not enough "
                   "arguments"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  auto node_info = known_node_aspects().TryGetInfoFor(receiver);
  if (!node_info || !node_info->possible_maps_are_known()) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.forEach - receiver "
                   "map is unknown"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  ElementsKind elements_kind;
  if (!CanInlineArrayIteratingBuiltin(broker(), node_info->possible_maps(),
                                      &elements_kind)) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.forEach - doesn't "
                   "support fast array iteration or incompatible maps"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  // TODO(leszeks): May only be needed for holey elements kinds.
  if (!broker()->dependencies()->DependOnNoElementsProtector()) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.forEach - invalidated "
                   "no elements protector"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  ValueNode* callback = args[0];
  if (!callback->is_tagged()) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.forEach - callback is "
                   "untagged value"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  ValueNode* this_arg =
      args.count() > 1 ? args[1] : GetRootConstant(RootIndex::kUndefinedValue);

  ValueNode* original_length = BuildLoadJSArrayLength(receiver);

  // Elide the callable check if the node is known callable.
  EnsureType(callback, NodeType::kCallable, [&](NodeType old_type) {
    // ThrowIfNotCallable is wrapped in a lazy_deopt_scope to make sure the
    // exception has the right call stack.
    DeoptFrameScope lazy_deopt_scope(
        this, Builtin::kArrayForEachLoopLazyDeoptContinuation, target,
        base::VectorOf<ValueNode*>({receiver, callback, this_arg,
                                    GetSmiConstant(0), original_length}));
    AddNewNode<ThrowIfNotCallable>({callback});
  });

  ValueNode* original_length_int32 = GetInt32(original_length);

  // Remember the receiver map set before entering the loop the call.
  bool receiver_maps_were_unstable = node_info->possible_maps_are_unstable();
  PossibleMaps receiver_maps_before_loop(node_info->possible_maps());

  // Create a sub graph builder with two variable (index and length)
  MaglevSubGraphBuilder sub_builder(this, 2);
  MaglevSubGraphBuilder::Variable var_index(0);
  MaglevSubGraphBuilder::Variable var_length(1);

  MaglevSubGraphBuilder::Label loop_end(&sub_builder, 1);

  // ```
  // index = 0
  // bind loop_header
  // ```
  sub_builder.set(var_index, GetSmiConstant(0));
  sub_builder.set(var_length, original_length);
  MaglevSubGraphBuilder::LoopLabel loop_header =
      sub_builder.BeginLoop({&var_index, &var_length});

  // Reset known state that is cleared by BeginLoop, but is known to be true on
  // the first iteration, and will be re-checked at the end of the loop.

  // Reset the known receiver maps if necessary.
  if (receiver_maps_were_unstable) {
    node_info->SetPossibleMaps(receiver_maps_before_loop,
                               receiver_maps_were_unstable,
                               // Node type is monotonic, no need to reset it.
                               NodeType::kUnknown, broker());
    known_node_aspects().any_map_for_any_node_is_unstable = true;
  } else {
    DCHECK_EQ(node_info->possible_maps().size(),
              receiver_maps_before_loop.size());
  }
  // Reset the cached loaded array length to the length var.
  RecordKnownProperty(receiver, broker()->length_string(),
                      sub_builder.get(var_length), false,
                      compiler::AccessMode::kLoad);

  // ```
  // if (index_int32 < length_int32)
  //   fallthrough
  // else
  //   goto end
  // ```
  Phi* index_tagged = sub_builder.get(var_index)->Cast<Phi>();
  EnsureType(index_tagged, NodeType::kSmi);
  ValueNode* index_int32 = GetInt32(index_tagged);

  sub_builder.GotoIfFalse<BranchIfInt32Compare>(
      &loop_end, {index_int32, original_length_int32}, Operation::kLessThan);

  // ```
  // next_index = index + 1
  // ```
  ValueNode* next_index_int32 = nullptr;
  {
    // Eager deopt scope for index increment overflow.
    // TODO(pthier): In practice this increment can never overflow, as the max
    // possible array length is less than int32 max value. Add a new
    // Int32Increment that asserts no overflow instead of deopting.
    DeoptFrameScope eager_deopt_scope(
        this, Builtin::kArrayForEachLoopEagerDeoptContinuation, target,
        base::VectorOf<ValueNode*>(
            {receiver, callback, this_arg, index_int32, original_length}));
    next_index_int32 = AddNewNode<Int32IncrementWithOverflow>({index_int32});
    EnsureType(next_index_int32, NodeType::kSmi);
  }
  // TODO(leszeks): Assert Smi.

  // ```
  // element = array.elements[index]
  // ```
  ValueNode* elements = BuildLoadElements(receiver);
  ValueNode* element;
  if (IsDoubleElementsKind(elements_kind)) {
    element = BuildLoadFixedDoubleArrayElement(elements, index_int32);
  } else {
    element = BuildLoadFixedArrayElement(elements, index_int32);
  }

  std::optional<MaglevSubGraphBuilder::Label> skip_call;
  if (IsHoleyElementsKind(elements_kind)) {
    // ```
    // if (element is hole) goto skip_call
    // ```
    skip_call.emplace(
        &sub_builder, 2,
        std::initializer_list<MaglevSubGraphBuilder::Variable*>{&var_length});
    if (elements_kind == HOLEY_DOUBLE_ELEMENTS) {
      sub_builder.GotoIfTrue<BranchIfFloat64IsHole>(&*skip_call, {element});
    } else {
      sub_builder.GotoIfTrue<BranchIfRootConstant>(&*skip_call, {element},
                                                   RootIndex::kTheHoleValue);
    }
  }

  // ```
  // callback(this_arg, element, array)
  // ```
  ReduceResult result;
  {
    DeoptFrameScope lazy_deopt_scope(
        this, Builtin::kArrayForEachLoopLazyDeoptContinuation, target,
        base::VectorOf<ValueNode*>(
            {receiver, callback, this_arg, next_index_int32, original_length}));

    CallArguments call_args =
        args.count() < 2
            ? CallArguments(ConvertReceiverMode::kNullOrUndefined,
                            {element, index_tagged, receiver})
            : CallArguments(ConvertReceiverMode::kAny,
                            {this_arg, element, index_tagged, receiver});

    SaveCallSpeculationScope saved(this);
    result = ReduceCall(callback, call_args, saved.value());
  }

  // ```
  // index = next_index
  // jump loop_header
  // ```
  DCHECK_IMPLIES(result.IsDoneWithAbort(), current_block_ == nullptr);

  // No need to finish the loop if this code is unreachable.
  if (!result.IsDoneWithAbort()) {
    // If any of the receiver's maps were unstable maps, we have to re-check the
    // maps on each iteration, in case the callback changed them. That said, we
    // know that the maps are valid on the first iteration, so we can rotate the
    // check to _after_ the callback, and then elide it if the receiver maps are
    // still known to be valid (i.e. the known maps after the call are contained
    // inside the known maps before the call).
    bool recheck_maps_after_call = receiver_maps_were_unstable;
    if (recheck_maps_after_call) {
      // No need to recheck maps if there are known maps...
      if (auto receiver_info_after_call =
              known_node_aspects().TryGetInfoFor(receiver)) {
        // ... and those known maps are equal to, or a subset of, the maps
        // before the call.
        if (receiver_info_after_call &&
            receiver_info_after_call->possible_maps_are_known()) {
          recheck_maps_after_call = !receiver_maps_before_loop.contains(
              receiver_info_after_call->possible_maps());
        }
      }
    }

    // Make sure to finish the loop if we eager deopt in the map check or index
    // check.
    DeoptFrameScope eager_deopt_scope(
        this, Builtin::kArrayForEachLoopEagerDeoptContinuation, target,
        base::VectorOf<ValueNode*>(
            {receiver, callback, this_arg, next_index_int32, original_length}));

    if (recheck_maps_after_call) {
      // Build the CheckMap manually, since we're doing it with already known
      // maps rather than feedback, and we don't need to update known node
      // aspects or types since we're at the end of the loop anyway.
      bool emit_check_with_migration = std::any_of(
          receiver_maps_before_loop.begin(), receiver_maps_before_loop.end(),
          [](compiler::MapRef map) { return map.is_migration_target(); });
      if (emit_check_with_migration) {
        AddNewNode<CheckMapsWithMigration>({receiver},
                                           receiver_maps_before_loop,
                                           CheckType::kOmitHeapObjectCheck);
      } else {
        AddNewNode<CheckMaps>({receiver}, receiver_maps_before_loop,
                              CheckType::kOmitHeapObjectCheck);
      }
    }

    // Check if the index is still in bounds, in case the callback changed the
    // length.
    ValueNode* current_length = BuildLoadJSArrayLength(receiver);
    sub_builder.set(var_length, current_length);

    // Reference compare the loaded length against the original length. If this
    // is the same value node, then we didn't have any side effects and didn't
    // clear the cached length.
    if (current_length != original_length) {
      RETURN_IF_ABORT(
          TryBuildCheckInt32Condition(original_length_int32, current_length,
                                      AssertCondition::kUnsignedLessThanEqual,
                                      DeoptimizeReason::kArrayLengthChanged));
    }
  }

  if (skip_call.has_value()) {
    sub_builder.GotoOrTrim(&*skip_call);
    sub_builder.Bind(&*skip_call);
  }

  sub_builder.set(var_index, next_index_int32);
  sub_builder.EndLoop(&loop_header);

  // ```
  // bind end
  // ```
  sub_builder.Bind(&loop_end);

  return GetRootConstant(RootIndex::kUndefinedValue);
}

ReduceResult MaglevGraphBuilder::TryReduceArrayIteratorPrototypeNext(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }

  ValueNode* receiver = args.receiver();
  if (!receiver) return ReduceResult::Fail();

  if (!receiver->Is<InlinedAllocation>()) return ReduceResult::Fail();
  VirtualObject* iterator = receiver->Cast<InlinedAllocation>()->object();
  if (!iterator->map().IsJSArrayIteratorMap()) {
    FAIL("iterator is not a JS array iterator object");
  }

  ValueNode* iterated_object =
      iterator->get(JSArrayIterator::kIteratedObjectOffset);
  ElementsKind elements_kind;
  base::SmallVector<compiler::MapRef, 4> maps;
  if (iterated_object->Is<InlinedAllocation>()) {
    VirtualObject* array = iterated_object->Cast<InlinedAllocation>()->object();
    // TODO(victorgomes): Remove this once we track changes in the inlined
    // allocated object.
    if (iterated_object->Cast<InlinedAllocation>()->IsEscaping()) {
      FAIL("allocation is escaping, map could have been changed");
    }
    // TODO(victorgomes): This effectively disable the optimization for `for-of`
    // loops. We need to figure it out a way to re-enable this.
    if (IsInsideLoop()) {
      FAIL("we're inside a loop, iterated object map could change");
    }
    auto map = array->map();
    if (!map.supports_fast_array_iteration(broker())) {
      FAIL("no fast array iteration support");
    }
    elements_kind = map.elements_kind();
    maps.push_back(map);
  } else {
    auto node_info = known_node_aspects().TryGetInfoFor(iterated_object);
    if (!node_info || !node_info->possible_maps_are_known()) {
      FAIL("iterated object is unknown");
    }
    if (!CanInlineArrayIteratingBuiltin(broker(), node_info->possible_maps(),
                                        &elements_kind)) {
      FAIL("no fast array iteration support or incompatible maps");
    }
    for (auto map : node_info->possible_maps()) {
      maps.push_back(map);
    }
  }

  // TODO(victorgomes): Support typed arrays.
  if (IsTypedArrayElementsKind(elements_kind)) {
    FAIL("no typed arrays support");
  }

  if (IsHoleyElementsKind(elements_kind) &&
      !broker()->dependencies()->DependOnNoElementsProtector()) {
    FAIL("no elements protector");
  }

  // Load the [[NextIndex]] from the {iterator}.
  // We can assume index and length fit in Uint32.
  ValueNode* index =
      BuildLoadTaggedField(receiver, JSArrayIterator::kNextIndexOffset);
  ValueNode* uint32_index;
  GET_VALUE_OR_ABORT(uint32_index, GetUint32ElementIndex(index));
  ValueNode* uint32_length;
  GET_VALUE_OR_ABORT(uint32_length,
                     GetUint32ElementIndex(BuildLoadJSArrayLength(
                         iterated_object, IsFastElementsKind(elements_kind)
                                              ? NodeType::kSmi
                                              : NodeType::kNumber)));

  // Check next index is below length
  MaglevSubGraphBuilder subgraph(this, 2);
  MaglevSubGraphBuilder::Variable is_done(0);
  MaglevSubGraphBuilder::Variable ret_value(1)
```