Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/maglev/maglev-graph-builder.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The filename `maglev-graph-builder.cc` strongly suggests this code is responsible for building the Maglev graph, an intermediate representation in the V8 JavaScript engine.

2. **Analyze the function names:**  The code is full of functions starting with `TryReduce...`. This immediately points to a pattern of "reduction," where the graph builder attempts to simplify or optimize certain operations. The specific names (e.g., `TryReduceFunctionPrototypeHasInstance`, `TryReduceObjectPrototypeHasOwnProperty`, `TryReduceMathRound`, `TryReduceArrayConstructor`) indicate that the builder is handling calls to various JavaScript built-in functions and methods.

3. **Look for patterns in the `TryReduce` functions:**  Most of these functions follow a similar structure:
    * They take a `compiler::JSFunctionRef target` (the function being called) and `CallArguments& args`.
    * They perform checks on the arguments (e.g., number of arguments, types of arguments, receiver).
    * If the checks pass and the operation can be optimized, they build a specific Maglev node (e.g., `AddNewNode<ConvertHoleToUndefined>`, `AddNewNode<CheckDynamicValue>`, `GetRootConstant`).
    * If the optimization cannot be performed, they often return `ReduceResult::Fail()`.

4. **Identify other key functions:**  Functions like `BuildGenericCall`, `BuildCallSelf`, `TryBuildCallKnownJSFunction`, `TryBuildCallKnownApiFunction`, `BuildCheckValue`, `BuildConvertHoleToUndefined`, and `BuildCheckNotHole` are crucial for understanding the overall graph building process. These indicate how different types of function calls are handled and how type checks and conversions are integrated into the graph.

5. **Connect the functionality to JavaScript:** The names of the `TryReduce` functions directly correspond to common JavaScript methods and constructors. This confirms that the code is indeed related to how V8 optimizes JavaScript execution.

6. **Identify potential user errors:** Based on the argument checks within the `TryReduce` functions, common errors like calling built-in functions with the wrong number or type of arguments are evident.

7. **Address the ".tq" question:**  The prompt explicitly asks about `.tq` files. This is a simple conditional check based on the file extension.

8. **Summarize the functionality:** Based on the above analysis, formulate a concise summary that highlights the core responsibilities of the code: optimization of built-in calls, handling different call types, performing type checks and conversions, and building the Maglev graph.

9. **Provide a JavaScript example:** Choose a simple example that demonstrates one of the optimized built-in calls, like `Array.prototype.pop()`.

10. **Construct a code logic example:** Select a function with clear input and output based on its logic. `TryReduceObjectPrototypeHasOwnProperty` when the receiver is a constant and the property is known is a good candidate.

11. **Illustrate a common programming error:**  Provide a JavaScript example that would cause one of the `TryReduce` functions to fail its checks, such as calling `Math.round()` without any arguments.

12. **Incorporate the "Part 12 of 18" information:** Acknowledge this context in the summary, indicating that this is a part of a larger graph building process.

By following these steps, a comprehensive and accurate answer can be generated that addresses all aspects of the user's request.
```cpp
ewNode<ConvertHoleToUndefined>({value});
    }
    sub_graph.set(var_value, value);
    return ReduceResult::Done();
  };

  RETURN_IF_ABORT(BuildJSArrayBuiltinMapSwitchOnElementsKind(
      receiver, map_kinds, sub_graph, do_return, unique_kind_count,
      index_to_elements_kind, build_array_pop));

  sub_graph.Bind(&empty_array);
  sub_graph.set(var_new_array_length, GetSmiConstant(0));
  sub_graph.set(var_value, GetRootConstant(RootIndex::kUndefinedValue));
  sub_graph.Goto(&*do_return);

  sub_graph.Bind(&*do_return);
  RecordKnownProperty(receiver, broker()->length_string(),
                      sub_graph.get(var_new_array_length), false,
                      compiler::AccessMode::kStore);
  return sub_graph.get(var_value);
}

ReduceResult MaglevGraphBuilder::TryReduceFunctionPrototypeHasInstance(
    compiler::JSFunctionRef target, CallArguments& args) {
  // We can't reduce Function#hasInstance when there is no receiver function.
  if (args.receiver_mode() == ConvertReceiverMode::kNullOrUndefined) {
    return ReduceResult::Fail();
  }
  if (args.count() != 1) {
    return ReduceResult::Fail();
  }
  compiler::OptionalHeapObjectRef maybe_receiver_constant =
      TryGetConstant(args.receiver());
  if (!maybe_receiver_constant) {
    return ReduceResult::Fail();
  }
  compiler::HeapObjectRef receiver_object = maybe_receiver_constant.value();
  if (!receiver_object.IsJSObject() ||
      !receiver_object.map(broker()).is_callable()) {
    return ReduceResult::Fail();
  }
  return BuildOrdinaryHasInstance(args[0], receiver_object.AsJSObject(),
                                  nullptr);
}

ReduceResult MaglevGraphBuilder::TryReduceObjectPrototypeHasOwnProperty(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  if (args.receiver_mode() == ConvertReceiverMode::kNullOrUndefined) {
    return ReduceResult::Fail();
  }

  // We can constant-fold the {receiver.hasOwnProperty(name)} builtin call to
  // the {True} node in this case:

  //   for (name in receiver) {
  //     if (receiver.hasOwnProperty(name)) {
  //        ...
  //     }
  //   }

  if (args.count() != 1 || args[0] != current_for_in_state.key) {
    return ReduceResult::Fail();
  }
  ValueNode* receiver = args.receiver();
  if (receiver == current_for_in_state.receiver) {
    if (current_for_in_state.receiver_needs_map_check) {
      auto* receiver_map =
          BuildLoadTaggedField(receiver, HeapObject::kMapOffset);
      AddNewNode<CheckDynamicValue>(
          {receiver_map, current_for_in_state.cache_type});
      current_for_in_state.receiver_needs_map_check = false;
    }
    return GetRootConstant(RootIndex::kTrueValue);
  }

  // We can also optimize for this case below:

  // receiver(is a heap constant with fast map)
  //  ^
  //  |    object(all keys are enumerable)
  //  |      ^
  //  |      |
  //  |   JSForInNext
  //  |      ^
  //  +----+ |
  //       | |
  //  JSCall[hasOwnProperty]

  // We can replace the {JSCall} with several internalized string
  // comparisons.

  compiler::OptionalMapRef maybe_receiver_map;
  compiler::OptionalHeapObjectRef receiver_ref = TryGetConstant(receiver);
  if (receiver_ref.has_value()) {
    compiler::HeapObjectRef receiver_object = receiver_ref.value();
    compiler::MapRef receiver_map = receiver_object.map(broker());
    maybe_receiver_map = receiver_map;
  } else {
    NodeInfo* known_info = GetOrCreateInfoFor(receiver);
    if (known_info->possible_maps_are_known()) {
      compiler::ZoneRefSet<Map> possible_maps = known_info->possible_maps();
      if (possible_maps.size() == 1) {
        compiler::MapRef receiver_map = *(possible_maps.begin());
        maybe_receiver_map = receiver_map;
      }
    }
  }
  if (!maybe_receiver_map.has_value()) {
    return ReduceResult::Fail();
  }

  compiler::MapRef receiver_map = maybe_receiver_map.value();
  InstanceType instance_type = receiver_map.instance_type();
  int const nof = receiver_map.NumberOfOwnDescriptors();
  // We set a heuristic value to limit the compare instructions number.
  if (nof > 4 || IsSpecialReceiverInstanceType(instance_type) ||
      receiver_map.is_dictionary_map()) {
    return ReduceResult::Fail();
  }
  RETURN_IF_ABORT(BuildCheckMaps(receiver, base::VectorOf({receiver_map})));
  //  Replace builtin call with several internalized string comparisons.
  MaglevSubGraphBuilder sub_graph(this, 1);
  MaglevSubGraphBuilder::Variable var_result(0);
  MaglevSubGraphBuilder::Label done(
      &sub_graph, nof + 1,
      std::initializer_list<MaglevSubGraphBuilder::Variable*>{&var_result});
  const compiler::DescriptorArrayRef descriptor_array =
      receiver_map.instance_descriptors(broker());
  for (InternalIndex key_index : InternalIndex::Range(nof)) {
    compiler::NameRef receiver_key =
        descriptor_array.GetPropertyKey(broker(), key_index);
    ValueNode* lhs = GetConstant(receiver_key);
    sub_graph.set(var_result, GetRootConstant(RootIndex::kTrueValue));
    sub_graph.GotoIfTrue<BranchIfReferenceEqual>(&done, {lhs, args[0]});
  }
  sub_graph.set(var_result, GetRootConstant(RootIndex::kFalseValue));
  sub_graph.Goto(&done);
  sub_graph.Bind(&done);
  return sub_graph.get(var_result);
}

ReduceResult MaglevGraphBuilder::TryReduceGetProto(ValueNode* object) {
  NodeInfo* info = known_node_aspects().TryGetInfoFor(object);
  if (!info || !info->possible_maps_are_known()) {
    return ReduceResult::Fail();
  }
  auto& possible_maps = info->possible_maps();
  if (possible_maps.is_empty()) {
    return ReduceResult::DoneWithAbort();
  }
  auto it = possible_maps.begin();
  compiler::MapRef map = *it;
  if (IsSpecialReceiverInstanceType(map.instance_type())) {
    return ReduceResult::Fail();
  }
  DCHECK(!map.IsPrimitiveMap() && map.IsJSReceiverMap());
  compiler::HeapObjectRef proto = map.prototype(broker());
  ++it;
  for (; it != possible_maps.end(); ++it) {
    map = *it;
    if (IsSpecialReceiverInstanceType(map.instance_type()) ||
        !proto.equals(map.prototype(broker()))) {
      return ReduceResult::Fail();
    }
    DCHECK(!map.IsPrimitiveMap() && map.IsJSReceiverMap());
  }
  return GetConstant(proto);
}

ReduceResult MaglevGraphBuilder::TryReduceObjectPrototypeGetProto(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() != 0) {
    return ReduceResult::Fail();
  }
  return TryReduceGetProto(args.receiver());
}

ReduceResult MaglevGraphBuilder::TryReduceObjectGetPrototypeOf(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() != 1) {
    return ReduceResult::Fail();
  }
  return TryReduceGetProto(args[0]);
}

ReduceResult MaglevGraphBuilder::TryReduceReflectGetPrototypeOf(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryReduceObjectGetPrototypeOf(target, args);
}

ReduceResult MaglevGraphBuilder::TryReduceMathRound(
    compiler::JSFunctionRef target, CallArguments& args) {
  return DoTryReduceMathRound(args, Float64Round::Kind::kNearest);
}

ReduceResult MaglevGraphBuilder::TryReduceNumberParseInt(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() == 0) {
    return GetRootConstant(RootIndex::kNanValue);
  }
  if (args.count() != 1) {
    if (RootConstant* c = args[1]->TryCast<RootConstant>()) {
      if (c->index() != RootIndex::kUndefinedValue) {
        return ReduceResult::Fail();
      }
    } else if (SmiConstant* c = args[1]->TryCast<SmiConstant>()) {
      if (c->value().value() != 10 && c->value().value() != 0) {
        return ReduceResult::Fail();
      }
    } else {
      return ReduceResult::Fail();
    }
  }

  ValueNode* arg = args[0];

  switch (arg->value_representation()) {
    case ValueRepresentation::kUint32:
    case ValueRepresentation::kInt32:
      return arg;
    case ValueRepresentation::kTagged:
      switch (CheckTypes(arg, {NodeType::kSmi})) {
        case NodeType::kSmi:
          return arg;
        default:
          // TODO(verwaest): Support actually parsing strings, converting
          // doubles to ints, ...
          return ReduceResult::Fail();
      }
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
    case ValueRepresentation::kFloat64:
    case ValueRepresentation::kHoleyFloat64:
      return ReduceResult::Fail();
  }
}

ReduceResult MaglevGraphBuilder::TryReduceMathAbs(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() == 0) {
    return GetRootConstant(RootIndex::kNanValue);
  }
  ValueNode* arg = args[0];

  switch (arg->value_representation()) {
    case ValueRepresentation::kUint32:
      return arg;
    case ValueRepresentation::kInt32:
      if (!CanSpeculateCall()) {
        return ReduceResult::Fail();
      }
      return AddNewNode<Int32AbsWithOverflow>({arg});
    case ValueRepresentation::kTagged:
      switch (CheckTypes(arg, {NodeType::kSmi, NodeType::kNumberOrOddball})) {
        case NodeType::kSmi:
          if (!CanSpeculateCall()) return ReduceResult::Fail();
          return AddNewNode<Int32AbsWithOverflow>({arg});
        case NodeType::kNumberOrOddball:
          return AddNewNode<Float64Abs>({GetHoleyFloat64ForToNumber(
              arg, ToNumberHint::kAssumeNumberOrOddball)});
        // TODO(verwaest): Add support for ToNumberOrNumeric and deopt.
        default:
          break;
      }
      break;
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
    case ValueRepresentation::kFloat64:
    case ValueRepresentation::kHoleyFloat64:
      return AddNewNode<Float64Abs>({arg});
  }
  return ReduceResult::Fail();
}

ReduceResult MaglevGraphBuilder::TryReduceMathFloor(
    compiler::JSFunctionRef target, CallArguments& args) {
  return DoTryReduceMathRound(args, Float64Round::Kind::kFloor);
}

ReduceResult MaglevGraphBuilder::TryReduceMathCeil(
    compiler::JSFunctionRef target, CallArguments& args) {
  return DoTryReduceMathRound(args, Float64Round::Kind::kCeil);
}

ReduceResult MaglevGraphBuilder::DoTryReduceMathRound(CallArguments& args,
                                                      Float64Round::Kind kind) {
  if (args.count() == 0) {
    return GetRootConstant(RootIndex::kNanValue);
  }
  ValueNode* arg = args[0];
  auto arg_repr = arg->value_representation();
  if (arg_repr == ValueRepresentation::kInt32 ||
      arg_repr == ValueRepresentation::kUint32) {
    return arg;
  }
  if (CheckType(arg, NodeType::kSmi)) return arg;
  if (!IsSupported(CpuOperation::kFloat64Round)) {
    return ReduceResult::Fail();
  }
  if (arg_repr == ValueRepresentation::kFloat64 ||
      arg_repr == ValueRepresentation::kHoleyFloat64) {
    return AddNewNode<Float64Round>({arg}, kind);
  }
  DCHECK_EQ(arg_repr, ValueRepresentation::kTagged);
  if (CheckType(arg, NodeType::kNumberOrOddball)) {
    return AddNewNode<Float64Round>(
        {GetHoleyFloat64ForToNumber(arg, ToNumberHint::kAssumeNumberOrOddball)},
        kind);
  }
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  DeoptFrameScope continuation_scope(this, Float64Round::continuation(kind));
  ToNumberOrNumeric* conversion =
      AddNewNode<ToNumberOrNumeric>({arg}, Object::Conversion::kToNumber);
  ValueNode* float64_value = AddNewNode<UncheckedNumberOrOddballToFloat64>(
      {conversion}, TaggedToFloat64ConversionType::kOnlyNumber);
  return AddNewNode<Float64Round>({float64_value}, kind);
}

ReduceResult MaglevGraphBuilder::TryReduceArrayConstructor(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryReduceConstructArrayConstructor(target, args);
}

ReduceResult MaglevGraphBuilder::TryReduceStringConstructor(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() == 0) {
    return GetRootConstant(RootIndex::kempty_string);
  }

  return BuildToString(args[0], ToString::kConvertSymbol);
}

ReduceResult MaglevGraphBuilder::TryReduceMathPow(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() < 2) {
    // For < 2 args, we'll be calculating Math.Pow(arg[0], undefined), which is
    // ToNumber(arg[0]) ** NaN == NaN. So we can just return NaN.
    // However, if there is a single argument and it's tagged, we have to call
    // ToNumber on it before returning NaN, for side effects. This call could
    // lazy deopt, which would mean we'd need a continuation to actually set
    // the NaN return value... it's easier to just bail out, this should be
    // an uncommon case anyway.
    if (args.count() == 1 && args[0]->properties().is_tagged()) {
      return ReduceResult::Fail();
    }
    return GetRootConstant(RootIndex::kNanValue);
  }
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  // If both arguments are tagged, it is cheaper to call Math.Pow builtin,
  // instead of Float64Exponentiate, since we are still making a call and we
  // don't need to unbox both inputs. See https://crbug.com/1393643.
  if (args[0]->properties().is_tagged() && args[1]->properties().is_tagged()) {
    // The Math.pow call will be created in CallKnownJSFunction reduction.
    return ReduceResult::Fail();
  }
  ValueNode* left =
      GetHoleyFloat64ForToNumber(args[0], ToNumberHint::kAssumeNumber);
  ValueNode* right =
      GetHoleyFloat64ForToNumber(args[1], ToNumberHint::kAssumeNumber);
  return AddNewNode<Float64Exponentiate>({left, right});
}

#define MATH_UNARY_IEEE_BUILTIN_REDUCER(MathName, ExtName, EnumName)          \
  ReduceResult MaglevGraphBuilder::TryReduce##MathName(                       \
      compiler::JSFunctionRef target, CallArguments& args) {                  \
    if (args.count() < 1) {                                                   \
      return GetRootConstant(RootIndex::kNanValue);                           \
    }                                                                         \
    if (!CanSpeculateCall()) {                                                \
      ValueRepresentation rep = args[0]->properties().value_representation(); \
      if (rep == ValueRepresentation::kTagged ||                              \
          rep == ValueRepresentation::kHoleyFloat64) {                        \
        return ReduceResult::Fail();                                          \
      }                                                                       \
    }                                                                         \
    ValueNode* value =                                                        \
        GetFloat64ForToNumber(args[0], ToNumberHint::kAssumeNumber);          \
    return AddNewNode<Float64Ieee754Unary>(                                   \
        {value}, Float64Ieee754Unary::Ieee754Function::k##EnumName);          \
  }

IEEE_754_UNARY_LIST(MATH_UNARY_IEEE_BUILTIN_REDUCER)
#undef MATH_UNARY_IEEE_BUILTIN_REDUCER

ReduceResult MaglevGraphBuilder::TryReduceBuiltin(
    compiler::JSFunctionRef target, compiler::SharedFunctionInfoRef shared,
    CallArguments& args, const compiler::FeedbackSource& feedback_source) {
  if (args.mode() != CallArguments::kDefault) {
    // TODO(victorgomes): Maybe inline the spread stub? Or call known function
    // directly if arguments list is an array.
    return ReduceResult::Fail();
  }
  SaveCallSpeculationScope speculate(this, feedback_source);
  if (!shared.HasBuiltinId()) {
    return ReduceResult::Fail();
  }
  if (v8_flags.trace_maglev_graph_building) {
    std::cout << "  ! Trying to reduce builtin "
              << Builtins::name(shared.builtin_id()) << std::endl;
  }
  switch (shared.builtin_id()) {
#define CASE(Name, ...)  \
  case Builtin::k##Name: \
    return TryReduce##Name(target, args);
    MAGLEV_REDUCED_BUILTIN(CASE)
#undef CASE
    default:
      // TODO(v8:7700): Inline more builtins.
      return ReduceResult::Fail();
  }
}

ValueNode* MaglevGraphBuilder::GetConvertReceiver(
    compiler::SharedFunctionInfoRef shared, const CallArguments& args) {
  if (shared.native() || shared.language_mode() == LanguageMode::kStrict) {
    if (args.receiver_mode() == ConvertReceiverMode::kNullOrUndefined) {
      return GetRootConstant(RootIndex::kUndefinedValue);
    } else {
      return args.receiver();
    }
  }
  if (args.receiver_mode() == ConvertReceiverMode::kNullOrUndefined) {
    return GetConstant(
        broker()->target_native_context().global_proxy_object(broker()));
  }
  ValueNode* receiver = args.receiver();
  if (CheckType(receiver, NodeType::kJSReceiver)) return receiver;
  if (compiler::OptionalHeapObjectRef maybe_constant =
          TryGetConstant(receiver)) {
    compiler::HeapObjectRef constant = maybe_constant.value();
    if (constant.IsNullOrUndefined()) {
      return GetConstant(
          broker()->target_native_context().global_proxy_object(broker()));
    }
  }
  return AddNewNode<ConvertReceiver>(
      {receiver}, broker()->target_native_context(), args.receiver_mode());
}

template <typename CallNode, typename... Args>
CallNode* MaglevGraphBuilder::AddNewCallNode(const CallArguments& args,
                                             Args&&... extra_args) {
  size_t input_count = args.count_with_receiver() + CallNode::kFixedInputCount;
  return AddNewNode<CallNode>(
      input_count,
      [&](CallNode* call) {
        int arg_index = 0;
        call->set_arg(arg_index++,
                      GetTaggedValue(GetValueOrUndefined(args.receiver())));
        for (size_t i = 0; i < args.count(); ++i) {
          call->set_arg(arg_index++, GetTaggedValue(args[i]));
        }
      },
      std::forward<Args>(extra_args)...);
}

ValueNode* MaglevGraphBuilder::BuildGenericCall(ValueNode* target,
                                                Call::TargetType target_type,
                                                const CallArguments& args) {
  // TODO(victorgomes): We do not collect call feedback from optimized/inlined
  // calls. In order to be consistent, we don't pass the feedback_source to the
  // IR, so that we avoid collecting for generic calls as well. We might want to
  // revisit this in the future.
  switch (args.mode()) {
    case CallArguments::kDefault:
      return AddNewCallNode<Call>(args, args.receiver_mode(), target_type,
                                  GetTaggedValue(target),
                                  GetTaggedValue(GetContext()));
    case CallArguments::kWithSpread:
      DCHECK_EQ(args.receiver_mode(), ConvertReceiverMode::kAny);
      return AddNewCallNode<CallWithSpread>(args, GetTaggedValue(target),
                                            GetTaggedValue(GetContext()));
    case CallArguments::kWithArrayLike:
      DCHECK_EQ(args.receiver_mode(), ConvertReceiverMode::kAny);
      // We don't use AddNewCallNode here, because the number of required
      // arguments is known statically.
      return AddNewNode<CallWithArrayLike>(
          {target, GetValueOrUndefined(args.receiver()), args[0],
           GetContext()});
  }
}

ValueNode* MaglevGraphBuilder::BuildCallSelf(
    ValueNode* context, ValueNode* function, ValueNode* new_target,
    compiler::SharedFunctionInfoRef shared, CallArguments& args) {
  ValueNode* receiver = GetConvertReceiver(shared, args);
  size_t input_count = args.count() + CallSelf::kFixedInputCount;
  graph()->set_has_recursive_calls(true);
  return AddNewNode<CallSelf>(
      input_count,
      [&](CallSelf* call) {
        for (int i = 0; i < static_cast<int>(args.count()); i++) {
          call->set_arg(i, GetTaggedValue(args[i]));
        }
      },
      shared, GetTaggedValue(function), GetTaggedValue(context),
      GetTaggedValue(receiver), GetTaggedValue(new_target));
}

bool MaglevGraphBuilder::TargetIsCurrentCompilingUnit(
    compiler::JSFunctionRef target) {
  if (compilation_unit_->info()->specialize_to_function_context()) {
    return target.object().equals(
        compilation_unit_->info()->toplevel_function());
  }
  return target.object()->shared() ==
         compilation_unit_->info()->toplevel_function()->shared();
}

ReduceResult MaglevGraphBuilder::ReduceCallForApiFunction(
    compiler::FunctionTemplateInfoRef api_callback,
    compiler::OptionalSharedFunctionInfoRef maybe_shared,
    compiler::OptionalJSObjectRef api_holder, CallArguments& args) {
  if (args.mode() != CallArguments::kDefault) {
    // TODO(victorgomes): Maybe inline the spread stub? Or call known function
    // directly if arguments list is an array.
    return ReduceResult::Fail();
  }
  // Check if the function has an associated C++ code to execute.
  compiler::OptionalObjectRef maybe_callback_data =
      api_callback.callback_data(broker());
  if (!maybe_callback_data.has_value()) {
    // TODO(ishell): consider generating "return undefined" for empty function
    // instead of failing.
    return ReduceResult::Fail();
  }

  size_t input_count = args.count() + CallKnownApiFunction::kFixedInputCount;
  ValueNode* receiver;
  if (maybe_shared.has_value()) {
    receiver = GetConvertReceiver(maybe_shared.value(), args);
  } else {
    receiver = args.receiver();
    CHECK_NOT_NULL(receiver);
  }

  CallKnownApiFunction::Mode mode =
      broker()->dependencies()->DependOnNoProfilingProtector()
          ? (v8_flags.maglev_inline_api_calls
                 ? CallKnownApiFunction::kNoProfilingInlined
                 : CallKnownApiFunction::kNoProfiling)
          : CallKnownApiFunction::kGeneric;

  return AddNewNode<CallKnownApiFunction>(
      input_count,
      [&](CallKnownApiFunction* call) {
        for (int i = 0; i < static_cast<int>(args.count()); i++) {
          call->set_arg(i, GetTaggedValue(args[i]));
        }
      },
      mode, api_callback, api_holder, GetTaggedValue(GetContext()),
      GetTaggedValue(receiver));
}

ReduceResult MaglevGraphBuilder::TryBuildCallKnownApiFunction(
    compiler::JSFunctionRef function, compiler::SharedFunctionInfoRef shared,
    CallArguments& args) {
  compiler::OptionalFunctionTemplateInfoRef maybe_function_template_info =
      shared.function_template_info(broker());
  if (!maybe_function_template_info.has_value()) {
    // Not an Api function.
    return ReduceResult::Fail();
  }

  // See if we can optimize this API call.
  compiler::FunctionTemplateInfoRef function_template_info =
      maybe_function_template_info.value();

  compiler::HolderLookupResult api_holder;
  if (function_template_info.accept_any_receiver() &&
      function_template_info.is_signature_undefined(broker())) {
    // We might be able to optimize the API call depending on the
    // {function_template_info}.
    // If the API function accepts any kind of {receiver}, we only need to
    // ensure that the {receiver} is actually a JSReceiver at this point,
    // and also pass that as the {holder}. There are two independent bits
    // here:
    //
    //  a. When the "accept any receiver" bit is set, it means we don't
    //     need to perform access checks, even if the {receiver}'s map
    //     has the "needs access check" bit set.
    //  b. When the {function_template_info} has no signature, we don't
    //     need to do the compatible receiver check, since all receivers
    //     are considered compatible at that point, and the {receiver}
    //     will be pass as the {holder}.

    api_holder =
        compiler::HolderLookupResult{CallOptimization::kHolderIsReceiver};
  } else {
    // Try to infer API holder from the known aspects of the {receiver}.
    api_holder =
        TryInferApiHolderValue(function_template_info, args.receiver());
  }

  switch (api_holder.lookup) {
    case CallOptimization::kHolderIsReceiver:
    case CallOptimization::kHolderFound:
      return ReduceCallForApiFunction(function_template_info, shared,
                                      api_holder.holder, args);

    case CallOptimization::kHolderNotFound:
      break;
  }

  // We don't have enough information to eliminate the access check
  // and/or the compatible receiver check, so use the generic builtin
  // that does those checks dynamically. This is still significantly
  // faster than the generic call sequence.
  Builtin builtin_name;
  // TODO(ishell): create no-profiling versions of kCallFunctionTemplate
  // builtins and use them here based on DependOnNoProfilingProtector()
  // dependency state.
  if (function_template_info.accept_any_receiver()) {
    DCHECK(!function_template_info.is_signature_undefined(broker()));
    builtin_name = Builtin::kCallFunctionTemplate_CheckCompatibleReceiver;
  } else if (function_template_info.is_signature_undefined(broker())) {
    builtin_name = Builtin::kCallFunctionTemplate_CheckAccess;
  } else {
    builtin_name =
        Builtin::kCallFunctionTemplate_CheckAccessAndCompatibleReceiver;
  }

  // The CallFunctionTemplate builtin requires the {receiver} to be
  // an actual JSReceiver, so make sure we do the proper conversion
  // first if necessary.
  ValueNode* receiver = GetConvertReceiver(shared, args);
  int kContext = 1;
  int kFunctionTemplateInfo = 1;
  int kArgc = 1;
  return AddNewNode<CallBuiltin>(
      kFunctionTemplateInfo + kArgc + kContext + args.count_with_receiver(),
      [&](CallBuiltin* call_builtin) {
        int arg_index = 0;
        call_builtin->set_arg(arg_index++, GetConstant(function_template_info));
        call_builtin->set_arg(
            arg_index++,
            GetInt32Constant(JSParameterCount(static_cast<int>(args.count()))));

        call_builtin->set_arg(arg_index++, GetTaggedValue(receiver));
        for (int i = 0; i < static_cast<int>(args.count()); i++) {
          call_builtin->set_arg(arg_index++, GetTaggedValue(args[i]));
        }
      },
      builtin_name, GetTaggedValue(GetContext()));
}

ReduceResult MaglevGraphBuilder::TryBuildCallKnownJSFunction(
    compiler::JSFunctionRef function, ValueNode* new_target,
    CallArguments& args, const compiler::FeedbackSource& feedback_source) {
  // Don't inline CallFunction stub across native contexts.
  if (function.native_context(broker()) != broker()->target_native_context()) {
    return ReduceResult::Fail();
  }
  compiler::SharedFunctionInfoRef shared = function.shared(broker());
  RETURN_IF_DONE(TryBuildCallKnownApiFunction(function, shared, args));

  ValueNode* closure = GetConstant(function);
  compiler::ContextRef context = function
Prompt: 
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第12部分，共18部分，请归纳一下它的功能

"""
ewNode<ConvertHoleToUndefined>({value});
    }
    sub_graph.set(var_value, value);
    return ReduceResult::Done();
  };

  RETURN_IF_ABORT(BuildJSArrayBuiltinMapSwitchOnElementsKind(
      receiver, map_kinds, sub_graph, do_return, unique_kind_count,
      index_to_elements_kind, build_array_pop));

  sub_graph.Bind(&empty_array);
  sub_graph.set(var_new_array_length, GetSmiConstant(0));
  sub_graph.set(var_value, GetRootConstant(RootIndex::kUndefinedValue));
  sub_graph.Goto(&*do_return);

  sub_graph.Bind(&*do_return);
  RecordKnownProperty(receiver, broker()->length_string(),
                      sub_graph.get(var_new_array_length), false,
                      compiler::AccessMode::kStore);
  return sub_graph.get(var_value);
}

ReduceResult MaglevGraphBuilder::TryReduceFunctionPrototypeHasInstance(
    compiler::JSFunctionRef target, CallArguments& args) {
  // We can't reduce Function#hasInstance when there is no receiver function.
  if (args.receiver_mode() == ConvertReceiverMode::kNullOrUndefined) {
    return ReduceResult::Fail();
  }
  if (args.count() != 1) {
    return ReduceResult::Fail();
  }
  compiler::OptionalHeapObjectRef maybe_receiver_constant =
      TryGetConstant(args.receiver());
  if (!maybe_receiver_constant) {
    return ReduceResult::Fail();
  }
  compiler::HeapObjectRef receiver_object = maybe_receiver_constant.value();
  if (!receiver_object.IsJSObject() ||
      !receiver_object.map(broker()).is_callable()) {
    return ReduceResult::Fail();
  }
  return BuildOrdinaryHasInstance(args[0], receiver_object.AsJSObject(),
                                  nullptr);
}

ReduceResult MaglevGraphBuilder::TryReduceObjectPrototypeHasOwnProperty(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  if (args.receiver_mode() == ConvertReceiverMode::kNullOrUndefined) {
    return ReduceResult::Fail();
  }

  // We can constant-fold the {receiver.hasOwnProperty(name)} builtin call to
  // the {True} node in this case:

  //   for (name in receiver) {
  //     if (receiver.hasOwnProperty(name)) {
  //        ...
  //     }
  //   }

  if (args.count() != 1 || args[0] != current_for_in_state.key) {
    return ReduceResult::Fail();
  }
  ValueNode* receiver = args.receiver();
  if (receiver == current_for_in_state.receiver) {
    if (current_for_in_state.receiver_needs_map_check) {
      auto* receiver_map =
          BuildLoadTaggedField(receiver, HeapObject::kMapOffset);
      AddNewNode<CheckDynamicValue>(
          {receiver_map, current_for_in_state.cache_type});
      current_for_in_state.receiver_needs_map_check = false;
    }
    return GetRootConstant(RootIndex::kTrueValue);
  }

  // We can also optimize for this case below:

  // receiver(is a heap constant with fast map)
  //  ^
  //  |    object(all keys are enumerable)
  //  |      ^
  //  |      |
  //  |   JSForInNext
  //  |      ^
  //  +----+ |
  //       | |
  //  JSCall[hasOwnProperty]

  // We can replace the {JSCall} with several internalized string
  // comparisons.

  compiler::OptionalMapRef maybe_receiver_map;
  compiler::OptionalHeapObjectRef receiver_ref = TryGetConstant(receiver);
  if (receiver_ref.has_value()) {
    compiler::HeapObjectRef receiver_object = receiver_ref.value();
    compiler::MapRef receiver_map = receiver_object.map(broker());
    maybe_receiver_map = receiver_map;
  } else {
    NodeInfo* known_info = GetOrCreateInfoFor(receiver);
    if (known_info->possible_maps_are_known()) {
      compiler::ZoneRefSet<Map> possible_maps = known_info->possible_maps();
      if (possible_maps.size() == 1) {
        compiler::MapRef receiver_map = *(possible_maps.begin());
        maybe_receiver_map = receiver_map;
      }
    }
  }
  if (!maybe_receiver_map.has_value()) {
    return ReduceResult::Fail();
  }

  compiler::MapRef receiver_map = maybe_receiver_map.value();
  InstanceType instance_type = receiver_map.instance_type();
  int const nof = receiver_map.NumberOfOwnDescriptors();
  // We set a heuristic value to limit the compare instructions number.
  if (nof > 4 || IsSpecialReceiverInstanceType(instance_type) ||
      receiver_map.is_dictionary_map()) {
    return ReduceResult::Fail();
  }
  RETURN_IF_ABORT(BuildCheckMaps(receiver, base::VectorOf({receiver_map})));
  //  Replace builtin call with several internalized string comparisons.
  MaglevSubGraphBuilder sub_graph(this, 1);
  MaglevSubGraphBuilder::Variable var_result(0);
  MaglevSubGraphBuilder::Label done(
      &sub_graph, nof + 1,
      std::initializer_list<MaglevSubGraphBuilder::Variable*>{&var_result});
  const compiler::DescriptorArrayRef descriptor_array =
      receiver_map.instance_descriptors(broker());
  for (InternalIndex key_index : InternalIndex::Range(nof)) {
    compiler::NameRef receiver_key =
        descriptor_array.GetPropertyKey(broker(), key_index);
    ValueNode* lhs = GetConstant(receiver_key);
    sub_graph.set(var_result, GetRootConstant(RootIndex::kTrueValue));
    sub_graph.GotoIfTrue<BranchIfReferenceEqual>(&done, {lhs, args[0]});
  }
  sub_graph.set(var_result, GetRootConstant(RootIndex::kFalseValue));
  sub_graph.Goto(&done);
  sub_graph.Bind(&done);
  return sub_graph.get(var_result);
}

ReduceResult MaglevGraphBuilder::TryReduceGetProto(ValueNode* object) {
  NodeInfo* info = known_node_aspects().TryGetInfoFor(object);
  if (!info || !info->possible_maps_are_known()) {
    return ReduceResult::Fail();
  }
  auto& possible_maps = info->possible_maps();
  if (possible_maps.is_empty()) {
    return ReduceResult::DoneWithAbort();
  }
  auto it = possible_maps.begin();
  compiler::MapRef map = *it;
  if (IsSpecialReceiverInstanceType(map.instance_type())) {
    return ReduceResult::Fail();
  }
  DCHECK(!map.IsPrimitiveMap() && map.IsJSReceiverMap());
  compiler::HeapObjectRef proto = map.prototype(broker());
  ++it;
  for (; it != possible_maps.end(); ++it) {
    map = *it;
    if (IsSpecialReceiverInstanceType(map.instance_type()) ||
        !proto.equals(map.prototype(broker()))) {
      return ReduceResult::Fail();
    }
    DCHECK(!map.IsPrimitiveMap() && map.IsJSReceiverMap());
  }
  return GetConstant(proto);
}

ReduceResult MaglevGraphBuilder::TryReduceObjectPrototypeGetProto(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() != 0) {
    return ReduceResult::Fail();
  }
  return TryReduceGetProto(args.receiver());
}

ReduceResult MaglevGraphBuilder::TryReduceObjectGetPrototypeOf(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() != 1) {
    return ReduceResult::Fail();
  }
  return TryReduceGetProto(args[0]);
}

ReduceResult MaglevGraphBuilder::TryReduceReflectGetPrototypeOf(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryReduceObjectGetPrototypeOf(target, args);
}

ReduceResult MaglevGraphBuilder::TryReduceMathRound(
    compiler::JSFunctionRef target, CallArguments& args) {
  return DoTryReduceMathRound(args, Float64Round::Kind::kNearest);
}

ReduceResult MaglevGraphBuilder::TryReduceNumberParseInt(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() == 0) {
    return GetRootConstant(RootIndex::kNanValue);
  }
  if (args.count() != 1) {
    if (RootConstant* c = args[1]->TryCast<RootConstant>()) {
      if (c->index() != RootIndex::kUndefinedValue) {
        return ReduceResult::Fail();
      }
    } else if (SmiConstant* c = args[1]->TryCast<SmiConstant>()) {
      if (c->value().value() != 10 && c->value().value() != 0) {
        return ReduceResult::Fail();
      }
    } else {
      return ReduceResult::Fail();
    }
  }

  ValueNode* arg = args[0];

  switch (arg->value_representation()) {
    case ValueRepresentation::kUint32:
    case ValueRepresentation::kInt32:
      return arg;
    case ValueRepresentation::kTagged:
      switch (CheckTypes(arg, {NodeType::kSmi})) {
        case NodeType::kSmi:
          return arg;
        default:
          // TODO(verwaest): Support actually parsing strings, converting
          // doubles to ints, ...
          return ReduceResult::Fail();
      }
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
    case ValueRepresentation::kFloat64:
    case ValueRepresentation::kHoleyFloat64:
      return ReduceResult::Fail();
  }
}

ReduceResult MaglevGraphBuilder::TryReduceMathAbs(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() == 0) {
    return GetRootConstant(RootIndex::kNanValue);
  }
  ValueNode* arg = args[0];

  switch (arg->value_representation()) {
    case ValueRepresentation::kUint32:
      return arg;
    case ValueRepresentation::kInt32:
      if (!CanSpeculateCall()) {
        return ReduceResult::Fail();
      }
      return AddNewNode<Int32AbsWithOverflow>({arg});
    case ValueRepresentation::kTagged:
      switch (CheckTypes(arg, {NodeType::kSmi, NodeType::kNumberOrOddball})) {
        case NodeType::kSmi:
          if (!CanSpeculateCall()) return ReduceResult::Fail();
          return AddNewNode<Int32AbsWithOverflow>({arg});
        case NodeType::kNumberOrOddball:
          return AddNewNode<Float64Abs>({GetHoleyFloat64ForToNumber(
              arg, ToNumberHint::kAssumeNumberOrOddball)});
        // TODO(verwaest): Add support for ToNumberOrNumeric and deopt.
        default:
          break;
      }
      break;
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
    case ValueRepresentation::kFloat64:
    case ValueRepresentation::kHoleyFloat64:
      return AddNewNode<Float64Abs>({arg});
  }
  return ReduceResult::Fail();
}

ReduceResult MaglevGraphBuilder::TryReduceMathFloor(
    compiler::JSFunctionRef target, CallArguments& args) {
  return DoTryReduceMathRound(args, Float64Round::Kind::kFloor);
}

ReduceResult MaglevGraphBuilder::TryReduceMathCeil(
    compiler::JSFunctionRef target, CallArguments& args) {
  return DoTryReduceMathRound(args, Float64Round::Kind::kCeil);
}

ReduceResult MaglevGraphBuilder::DoTryReduceMathRound(CallArguments& args,
                                                      Float64Round::Kind kind) {
  if (args.count() == 0) {
    return GetRootConstant(RootIndex::kNanValue);
  }
  ValueNode* arg = args[0];
  auto arg_repr = arg->value_representation();
  if (arg_repr == ValueRepresentation::kInt32 ||
      arg_repr == ValueRepresentation::kUint32) {
    return arg;
  }
  if (CheckType(arg, NodeType::kSmi)) return arg;
  if (!IsSupported(CpuOperation::kFloat64Round)) {
    return ReduceResult::Fail();
  }
  if (arg_repr == ValueRepresentation::kFloat64 ||
      arg_repr == ValueRepresentation::kHoleyFloat64) {
    return AddNewNode<Float64Round>({arg}, kind);
  }
  DCHECK_EQ(arg_repr, ValueRepresentation::kTagged);
  if (CheckType(arg, NodeType::kNumberOrOddball)) {
    return AddNewNode<Float64Round>(
        {GetHoleyFloat64ForToNumber(arg, ToNumberHint::kAssumeNumberOrOddball)},
        kind);
  }
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  DeoptFrameScope continuation_scope(this, Float64Round::continuation(kind));
  ToNumberOrNumeric* conversion =
      AddNewNode<ToNumberOrNumeric>({arg}, Object::Conversion::kToNumber);
  ValueNode* float64_value = AddNewNode<UncheckedNumberOrOddballToFloat64>(
      {conversion}, TaggedToFloat64ConversionType::kOnlyNumber);
  return AddNewNode<Float64Round>({float64_value}, kind);
}

ReduceResult MaglevGraphBuilder::TryReduceArrayConstructor(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryReduceConstructArrayConstructor(target, args);
}

ReduceResult MaglevGraphBuilder::TryReduceStringConstructor(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() == 0) {
    return GetRootConstant(RootIndex::kempty_string);
  }

  return BuildToString(args[0], ToString::kConvertSymbol);
}

ReduceResult MaglevGraphBuilder::TryReduceMathPow(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() < 2) {
    // For < 2 args, we'll be calculating Math.Pow(arg[0], undefined), which is
    // ToNumber(arg[0]) ** NaN == NaN. So we can just return NaN.
    // However, if there is a single argument and it's tagged, we have to call
    // ToNumber on it before returning NaN, for side effects. This call could
    // lazy deopt, which would mean we'd need a continuation to actually set
    // the NaN return value... it's easier to just bail out, this should be
    // an uncommon case anyway.
    if (args.count() == 1 && args[0]->properties().is_tagged()) {
      return ReduceResult::Fail();
    }
    return GetRootConstant(RootIndex::kNanValue);
  }
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  // If both arguments are tagged, it is cheaper to call Math.Pow builtin,
  // instead of Float64Exponentiate, since we are still making a call and we
  // don't need to unbox both inputs. See https://crbug.com/1393643.
  if (args[0]->properties().is_tagged() && args[1]->properties().is_tagged()) {
    // The Math.pow call will be created in CallKnownJSFunction reduction.
    return ReduceResult::Fail();
  }
  ValueNode* left =
      GetHoleyFloat64ForToNumber(args[0], ToNumberHint::kAssumeNumber);
  ValueNode* right =
      GetHoleyFloat64ForToNumber(args[1], ToNumberHint::kAssumeNumber);
  return AddNewNode<Float64Exponentiate>({left, right});
}

#define MATH_UNARY_IEEE_BUILTIN_REDUCER(MathName, ExtName, EnumName)          \
  ReduceResult MaglevGraphBuilder::TryReduce##MathName(                       \
      compiler::JSFunctionRef target, CallArguments& args) {                  \
    if (args.count() < 1) {                                                   \
      return GetRootConstant(RootIndex::kNanValue);                           \
    }                                                                         \
    if (!CanSpeculateCall()) {                                                \
      ValueRepresentation rep = args[0]->properties().value_representation(); \
      if (rep == ValueRepresentation::kTagged ||                              \
          rep == ValueRepresentation::kHoleyFloat64) {                        \
        return ReduceResult::Fail();                                          \
      }                                                                       \
    }                                                                         \
    ValueNode* value =                                                        \
        GetFloat64ForToNumber(args[0], ToNumberHint::kAssumeNumber);          \
    return AddNewNode<Float64Ieee754Unary>(                                   \
        {value}, Float64Ieee754Unary::Ieee754Function::k##EnumName);          \
  }

IEEE_754_UNARY_LIST(MATH_UNARY_IEEE_BUILTIN_REDUCER)
#undef MATH_UNARY_IEEE_BUILTIN_REDUCER

ReduceResult MaglevGraphBuilder::TryReduceBuiltin(
    compiler::JSFunctionRef target, compiler::SharedFunctionInfoRef shared,
    CallArguments& args, const compiler::FeedbackSource& feedback_source) {
  if (args.mode() != CallArguments::kDefault) {
    // TODO(victorgomes): Maybe inline the spread stub? Or call known function
    // directly if arguments list is an array.
    return ReduceResult::Fail();
  }
  SaveCallSpeculationScope speculate(this, feedback_source);
  if (!shared.HasBuiltinId()) {
    return ReduceResult::Fail();
  }
  if (v8_flags.trace_maglev_graph_building) {
    std::cout << "  ! Trying to reduce builtin "
              << Builtins::name(shared.builtin_id()) << std::endl;
  }
  switch (shared.builtin_id()) {
#define CASE(Name, ...)  \
  case Builtin::k##Name: \
    return TryReduce##Name(target, args);
    MAGLEV_REDUCED_BUILTIN(CASE)
#undef CASE
    default:
      // TODO(v8:7700): Inline more builtins.
      return ReduceResult::Fail();
  }
}

ValueNode* MaglevGraphBuilder::GetConvertReceiver(
    compiler::SharedFunctionInfoRef shared, const CallArguments& args) {
  if (shared.native() || shared.language_mode() == LanguageMode::kStrict) {
    if (args.receiver_mode() == ConvertReceiverMode::kNullOrUndefined) {
      return GetRootConstant(RootIndex::kUndefinedValue);
    } else {
      return args.receiver();
    }
  }
  if (args.receiver_mode() == ConvertReceiverMode::kNullOrUndefined) {
    return GetConstant(
        broker()->target_native_context().global_proxy_object(broker()));
  }
  ValueNode* receiver = args.receiver();
  if (CheckType(receiver, NodeType::kJSReceiver)) return receiver;
  if (compiler::OptionalHeapObjectRef maybe_constant =
          TryGetConstant(receiver)) {
    compiler::HeapObjectRef constant = maybe_constant.value();
    if (constant.IsNullOrUndefined()) {
      return GetConstant(
          broker()->target_native_context().global_proxy_object(broker()));
    }
  }
  return AddNewNode<ConvertReceiver>(
      {receiver}, broker()->target_native_context(), args.receiver_mode());
}

template <typename CallNode, typename... Args>
CallNode* MaglevGraphBuilder::AddNewCallNode(const CallArguments& args,
                                             Args&&... extra_args) {
  size_t input_count = args.count_with_receiver() + CallNode::kFixedInputCount;
  return AddNewNode<CallNode>(
      input_count,
      [&](CallNode* call) {
        int arg_index = 0;
        call->set_arg(arg_index++,
                      GetTaggedValue(GetValueOrUndefined(args.receiver())));
        for (size_t i = 0; i < args.count(); ++i) {
          call->set_arg(arg_index++, GetTaggedValue(args[i]));
        }
      },
      std::forward<Args>(extra_args)...);
}

ValueNode* MaglevGraphBuilder::BuildGenericCall(ValueNode* target,
                                                Call::TargetType target_type,
                                                const CallArguments& args) {
  // TODO(victorgomes): We do not collect call feedback from optimized/inlined
  // calls. In order to be consistent, we don't pass the feedback_source to the
  // IR, so that we avoid collecting for generic calls as well. We might want to
  // revisit this in the future.
  switch (args.mode()) {
    case CallArguments::kDefault:
      return AddNewCallNode<Call>(args, args.receiver_mode(), target_type,
                                  GetTaggedValue(target),
                                  GetTaggedValue(GetContext()));
    case CallArguments::kWithSpread:
      DCHECK_EQ(args.receiver_mode(), ConvertReceiverMode::kAny);
      return AddNewCallNode<CallWithSpread>(args, GetTaggedValue(target),
                                            GetTaggedValue(GetContext()));
    case CallArguments::kWithArrayLike:
      DCHECK_EQ(args.receiver_mode(), ConvertReceiverMode::kAny);
      // We don't use AddNewCallNode here, because the number of required
      // arguments is known statically.
      return AddNewNode<CallWithArrayLike>(
          {target, GetValueOrUndefined(args.receiver()), args[0],
           GetContext()});
  }
}

ValueNode* MaglevGraphBuilder::BuildCallSelf(
    ValueNode* context, ValueNode* function, ValueNode* new_target,
    compiler::SharedFunctionInfoRef shared, CallArguments& args) {
  ValueNode* receiver = GetConvertReceiver(shared, args);
  size_t input_count = args.count() + CallSelf::kFixedInputCount;
  graph()->set_has_recursive_calls(true);
  return AddNewNode<CallSelf>(
      input_count,
      [&](CallSelf* call) {
        for (int i = 0; i < static_cast<int>(args.count()); i++) {
          call->set_arg(i, GetTaggedValue(args[i]));
        }
      },
      shared, GetTaggedValue(function), GetTaggedValue(context),
      GetTaggedValue(receiver), GetTaggedValue(new_target));
}

bool MaglevGraphBuilder::TargetIsCurrentCompilingUnit(
    compiler::JSFunctionRef target) {
  if (compilation_unit_->info()->specialize_to_function_context()) {
    return target.object().equals(
        compilation_unit_->info()->toplevel_function());
  }
  return target.object()->shared() ==
         compilation_unit_->info()->toplevel_function()->shared();
}

ReduceResult MaglevGraphBuilder::ReduceCallForApiFunction(
    compiler::FunctionTemplateInfoRef api_callback,
    compiler::OptionalSharedFunctionInfoRef maybe_shared,
    compiler::OptionalJSObjectRef api_holder, CallArguments& args) {
  if (args.mode() != CallArguments::kDefault) {
    // TODO(victorgomes): Maybe inline the spread stub? Or call known function
    // directly if arguments list is an array.
    return ReduceResult::Fail();
  }
  // Check if the function has an associated C++ code to execute.
  compiler::OptionalObjectRef maybe_callback_data =
      api_callback.callback_data(broker());
  if (!maybe_callback_data.has_value()) {
    // TODO(ishell): consider generating "return undefined" for empty function
    // instead of failing.
    return ReduceResult::Fail();
  }

  size_t input_count = args.count() + CallKnownApiFunction::kFixedInputCount;
  ValueNode* receiver;
  if (maybe_shared.has_value()) {
    receiver = GetConvertReceiver(maybe_shared.value(), args);
  } else {
    receiver = args.receiver();
    CHECK_NOT_NULL(receiver);
  }

  CallKnownApiFunction::Mode mode =
      broker()->dependencies()->DependOnNoProfilingProtector()
          ? (v8_flags.maglev_inline_api_calls
                 ? CallKnownApiFunction::kNoProfilingInlined
                 : CallKnownApiFunction::kNoProfiling)
          : CallKnownApiFunction::kGeneric;

  return AddNewNode<CallKnownApiFunction>(
      input_count,
      [&](CallKnownApiFunction* call) {
        for (int i = 0; i < static_cast<int>(args.count()); i++) {
          call->set_arg(i, GetTaggedValue(args[i]));
        }
      },
      mode, api_callback, api_holder, GetTaggedValue(GetContext()),
      GetTaggedValue(receiver));
}

ReduceResult MaglevGraphBuilder::TryBuildCallKnownApiFunction(
    compiler::JSFunctionRef function, compiler::SharedFunctionInfoRef shared,
    CallArguments& args) {
  compiler::OptionalFunctionTemplateInfoRef maybe_function_template_info =
      shared.function_template_info(broker());
  if (!maybe_function_template_info.has_value()) {
    // Not an Api function.
    return ReduceResult::Fail();
  }

  // See if we can optimize this API call.
  compiler::FunctionTemplateInfoRef function_template_info =
      maybe_function_template_info.value();

  compiler::HolderLookupResult api_holder;
  if (function_template_info.accept_any_receiver() &&
      function_template_info.is_signature_undefined(broker())) {
    // We might be able to optimize the API call depending on the
    // {function_template_info}.
    // If the API function accepts any kind of {receiver}, we only need to
    // ensure that the {receiver} is actually a JSReceiver at this point,
    // and also pass that as the {holder}. There are two independent bits
    // here:
    //
    //  a. When the "accept any receiver" bit is set, it means we don't
    //     need to perform access checks, even if the {receiver}'s map
    //     has the "needs access check" bit set.
    //  b. When the {function_template_info} has no signature, we don't
    //     need to do the compatible receiver check, since all receivers
    //     are considered compatible at that point, and the {receiver}
    //     will be pass as the {holder}.

    api_holder =
        compiler::HolderLookupResult{CallOptimization::kHolderIsReceiver};
  } else {
    // Try to infer API holder from the known aspects of the {receiver}.
    api_holder =
        TryInferApiHolderValue(function_template_info, args.receiver());
  }

  switch (api_holder.lookup) {
    case CallOptimization::kHolderIsReceiver:
    case CallOptimization::kHolderFound:
      return ReduceCallForApiFunction(function_template_info, shared,
                                      api_holder.holder, args);

    case CallOptimization::kHolderNotFound:
      break;
  }

  // We don't have enough information to eliminate the access check
  // and/or the compatible receiver check, so use the generic builtin
  // that does those checks dynamically. This is still significantly
  // faster than the generic call sequence.
  Builtin builtin_name;
  // TODO(ishell): create no-profiling versions of kCallFunctionTemplate
  // builtins and use them here based on DependOnNoProfilingProtector()
  // dependency state.
  if (function_template_info.accept_any_receiver()) {
    DCHECK(!function_template_info.is_signature_undefined(broker()));
    builtin_name = Builtin::kCallFunctionTemplate_CheckCompatibleReceiver;
  } else if (function_template_info.is_signature_undefined(broker())) {
    builtin_name = Builtin::kCallFunctionTemplate_CheckAccess;
  } else {
    builtin_name =
        Builtin::kCallFunctionTemplate_CheckAccessAndCompatibleReceiver;
  }

  // The CallFunctionTemplate builtin requires the {receiver} to be
  // an actual JSReceiver, so make sure we do the proper conversion
  // first if necessary.
  ValueNode* receiver = GetConvertReceiver(shared, args);
  int kContext = 1;
  int kFunctionTemplateInfo = 1;
  int kArgc = 1;
  return AddNewNode<CallBuiltin>(
      kFunctionTemplateInfo + kArgc + kContext + args.count_with_receiver(),
      [&](CallBuiltin* call_builtin) {
        int arg_index = 0;
        call_builtin->set_arg(arg_index++, GetConstant(function_template_info));
        call_builtin->set_arg(
            arg_index++,
            GetInt32Constant(JSParameterCount(static_cast<int>(args.count()))));

        call_builtin->set_arg(arg_index++, GetTaggedValue(receiver));
        for (int i = 0; i < static_cast<int>(args.count()); i++) {
          call_builtin->set_arg(arg_index++, GetTaggedValue(args[i]));
        }
      },
      builtin_name, GetTaggedValue(GetContext()));
}

ReduceResult MaglevGraphBuilder::TryBuildCallKnownJSFunction(
    compiler::JSFunctionRef function, ValueNode* new_target,
    CallArguments& args, const compiler::FeedbackSource& feedback_source) {
  // Don't inline CallFunction stub across native contexts.
  if (function.native_context(broker()) != broker()->target_native_context()) {
    return ReduceResult::Fail();
  }
  compiler::SharedFunctionInfoRef shared = function.shared(broker());
  RETURN_IF_DONE(TryBuildCallKnownApiFunction(function, shared, args));

  ValueNode* closure = GetConstant(function);
  compiler::ContextRef context = function.context(broker());
  ValueNode* context_node = GetConstant(context);
  ReduceResult res;
  if (MaglevIsTopTier() && TargetIsCurrentCompilingUnit(function) &&
      !graph_->is_osr()) {
    res = BuildCallSelf(context_node, closure, new_target, shared, args);
  } else {
    res = TryBuildCallKnownJSFunction(context_node, closure, new_target, shared,
                                      function.feedback_vector(broker()), args,
                                      feedback_source);
  }
  return res;
}

ReduceResult MaglevGraphBuilder::TryBuildCallKnownJSFunction(
    ValueNode* context, ValueNode* function, ValueNode* new_target,
    compiler::SharedFunctionInfoRef shared,
    compiler::OptionalFeedbackVectorRef feedback_vector, CallArguments& args,
    const compiler::FeedbackSource& feedback_source) {
  if (v8_flags.maglev_inlining) {
    RETURN_IF_DONE(TryBuildInlinedCall(context, function, new_target, shared,
                                       feedback_vector, args, feedback_source));
  }
  ValueNode* receiver = GetConvertReceiver(shared, args);
  size_t input_count = args.count() + CallKnownJSFunction::kFixedInputCount;
  return AddNewNode<CallKnownJSFunction>(
      input_count,
      [&](CallKnownJSFunction* call) {
        for (int i = 0; i < static_cast<int>(args.count()); i++) {
          call->set_arg(i, GetTaggedValue(args[i]));
        }
      },
      shared, GetTaggedValue(function), GetTaggedValue(context),
      GetTaggedValue(receiver), GetTaggedValue(new_target));
}

ReduceResult MaglevGraphBuilder::BuildCheckValue(ValueNode* node,
                                                 compiler::HeapObjectRef ref) {
  DCHECK(!ref.IsSmi());
  DCHECK(!ref.IsHeapNumber());

  if (compiler::OptionalHeapObjectRef maybe_constant = TryGetConstant(node)) {
    if (maybe_constant.value().equals(ref)) {
      return ReduceResult::Done();
    }
    return EmitUnconditionalDeopt(DeoptimizeReason::kUnknown);
  }
  if (ref.IsString()) {
    DCHECK(ref.IsInternalizedString());
    AddNewNode<CheckValueEqualsString>({node}, ref.AsInternalizedString());
    SetKnownValue(node, ref, NodeType::kString);
  } else {
    AddNewNode<CheckValue>({node}, ref);
    SetKnownValue(node, ref, StaticTypeForConstant(broker(), ref));
  }

  return ReduceResult::Done();
}

ReduceResult MaglevGraphBuilder::BuildCheckValue(ValueNode* node,
                                                 compiler::ObjectRef ref) {
  if (ref.IsHeapObject() && !ref.IsHeapNumber()) {
    return BuildCheckValue(node, ref.AsHeapObject());
  }
  if (ref.IsSmi()) {
    int ref_value = ref.AsSmi();
    if (IsConstantNode(node->opcode())) {
      if (node->Is<SmiConstant>() &&
          node->Cast<SmiConstant>()->value().value() == ref_value) {
        return ReduceResult::Done();
      }
      if (node->Is<Int32Constant>() &&
          node->Cast<Int32Constant>()->value() == ref_value) {
        return ReduceResult::Done();
      }
      return EmitUnconditionalDeopt(DeoptimizeReason::kUnknown);
    }
    AddNewNode<CheckValueEqualsInt32>({node}, ref_value);
  } else {
    DCHECK(ref.IsHeapNumber());
    Float64 ref_value = Float64::FromBits(ref.AsHeapNumber().value_as_bits());
    DCHECK(!ref_value.is_hole_nan());
    if (node->Is<Float64Constant>()) {
      Float64 f64 = node->Cast<Float64Constant>()->value();
      DCHECK(!f64.is_hole_nan());
      if (f64 == ref_value) {
        return ReduceResult::Done();
      }
      return EmitUnconditionalDeopt(DeoptimizeReason::kUnknown);
    } else if (compiler::OptionalHeapObjectRef constant =
                   TryGetConstant(node)) {
      if (constant.value().IsHeapNumber()) {
        Float64 f64 =
            Float64::FromBits(constant.value().AsHeapNumber().value_as_bits());
        DCHECK(!f64.is_hole_nan());
        if (f64 == ref_value) {
          return ReduceResult::Done();
        }
      }
      return EmitUnconditionalDeopt(DeoptimizeReason::kUnknown);
    }
    if (ref_value.is_nan()) {
      AddNewNode<CheckFloat64IsNan>({node});
    } else {
      AddNewNode<CheckValueEqualsFloat64>({node}, ref_value);
    }
  }
  SetKnownValue(node, ref, NodeType::kNumber);
  return ReduceResult::Done();
}

ValueNode* MaglevGraphBuilder::BuildConvertHoleToUndefined(ValueNode* node) {
  if (!node->is_tagged()) return node;
  compiler::OptionalHeapObjectRef maybe_constant = TryGetConstant(node);
  if (maybe_constant) {
    return maybe_constant.value().IsTheHole()
               ? GetRootConstant(RootIndex::kUndefinedValue)
               : node;
  }
  return AddNewNode<ConvertHoleToUndefined>({node});
}

ReduceResult MaglevGraphBuilder::BuildCheckNotHole(ValueNode* node) {
  if (!node->is_tagged()) return ReduceResult::Done();
  compiler::OptionalHeapObjectRef maybe_constant = TryGetConstant(node);
  if (maybe_constant) {
    if (maybe_constant.value().IsTheHole()) {
      return EmitUnconditionalDeopt(DeoptimizeReason::kHole);
    }
    return ReduceResult::Done();
  }
  AddNewNode<CheckNotHole>({node});
  return ReduceResult::Done();
}

ReduceResult MaglevGraphBuilder::ReduceCallForConstant(
    compiler::JSFunctionRef target, CallArguments& args,
    const compiler::FeedbackSource& feedback_source) {
  if (args.mode() != CallArguments::kDefault) {
    // TODO(victorgomes): Maybe inline the spread stub? Or call known function
    // directly if arguments list is an array.
    return ReduceResult::Fail();
  }
  compiler::SharedFunctionInfoRef shared = target.shared(broker());
  ValueNode* target_node = GetConstant(target);
  // Do not reduce calls to functions with break points.
  if (!shared.HasBreakInfo(broker())) {
    if (IsClassConstructor(shared.kind())) {
      // If we have a class constructor, we should raise an exception.
      return BuildCallRuntime(Runtime::kThrowConstructorNonCallableError,
                              {target_node});
    }
    DCHECK(IsCallable(*target.object()));
    RETURN_IF_DONE(TryReduceBuiltin(target, shared, args, feedback_source));
    RETURN_IF_DONE(TryBuildCallKnownJSFunction(
        target, GetRootConstant(RootIndex::kUndefinedValue), args,
        feedback_source));
  }
  return BuildGenericCall(target_node, Call::TargetType::kJSFunction, args);
}

compiler::HolderLookupResult MaglevGraphBuilder::TryInferApiHolderValue(
    compiler::FunctionTemplateInfoRef function_template_info,
    ValueNode* receiver) {
  const compiler::HolderLookupResult not_found;

  auto receiver_info = known_node_aspects().TryGetInfoFor(receiver);
  if (!receiver_info || !receiv
"""


```