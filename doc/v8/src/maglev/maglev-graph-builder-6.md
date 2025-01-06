Response: The user wants a summary of the C++ source code file `v8/src/maglev/maglev-graph-builder.cc`.
This is part 7 of a 9-part series, suggesting the file implements a portion of a larger system. Given the file path, it's likely related to the Maglev compiler in V8, specifically the part that builds the graph representation of the code.

The code snippets heavily feature:
- **`MaglevGraphBuilder` class:**  This is the central class and likely contains the logic for converting bytecode into a graph.
- **`Reduce...` methods:** These functions seem to be involved in optimizing or simplifying certain operations during graph construction.
- **`Build...` methods:**  These functions appear to create nodes in the graph.
- **`Visit...` methods:**  These likely correspond to handling different bytecode instructions.
- **`CallArguments`:** A class for managing arguments for function calls and constructions.
- **`FeedbackSlot` and `FeedbackSource`:**  Mechanisms for utilizing type feedback to optimize code.
- **`VirtualObject` and `InlinedAllocation`:**  Representing object creation and allocation within the graph.
- **Handling of different call types:** Regular calls, calls with spread syntax, constructor calls.
- **Type checks and conversions:**  `BuildCheckValue`, `BuildToBoolean`, `BuildToString`, `BuildToNumberOrToNumeric`.
- **Optimization for known functions and constructors:**  Special handling for `Array`, `Object`, and other built-in functions.
- **Optimization of `instanceof` operator.**
- **Handling of iterators and generators.**
- **Intrinsic function calls.**

Considering it's part 7 of 9, it likely handles a specific set of operations or a particular stage of graph construction. Given the content, this part appears to focus on **function calls, constructor calls, type conversions, and optimizations related to these operations.**

As for the relationship with JavaScript, the code is clearly implementing the behavior of JavaScript constructs within the Maglev compiler. The `Visit...` methods are directly tied to JavaScript bytecode instructions. The optimizations and special handling target specific JavaScript built-in functions and operators.

**Hypothesized Functionality:**

This part of `maglev-graph-builder.cc` is responsible for:

1. **Translating JavaScript function calls and constructor calls from bytecode into the Maglev graph representation.** This includes different call patterns like regular calls, calls with spread syntax, and calls to known functions/constructors.
2. **Applying optimizations to function and constructor calls based on type feedback.** This involves checking types and potentially inlining or specializing calls.
3. **Handling JavaScript's `instanceof` operator**, including optimizations based on the structure of the constructor function.
4. **Implementing various type conversion operations** like `ToBoolean`, `ToString`, `ToNumber`, and `ToNumeric` within the graph.
5. **Handling calls to JavaScript built-in functions and intrinsics**, potentially with specialized logic for common cases like `Array` and `Object` constructors.
6. **Dealing with JavaScript's iterator and generator objects**.

**JavaScript Examples:**

Here are some JavaScript examples that would likely be handled by this part of the code:

- **Function Calls:**
  ```javascript
  function foo(a, b) { return a + b; }
  foo(1, 2);
  ```

- **Constructor Calls:**
  ```javascript
  const arr = new Array(5);
  const obj = new Object();
  ```

- **Calls with Spread:**
  ```javascript
  function bar(x, y, z) {}
  const args = [1, 2];
  bar(0, ...args);
  ```

- **`instanceof` operator:**
  ```javascript
  const arr = [];
  arr instanceof Array; // true
  ```

- **Type Conversions:**
  ```javascript
  if (0) {} // ToBoolean
  const str = 123 + ""; // ToString
  const num = +"456"; // ToNumber
  ```

- **Iterator/Generator usage:**
  ```javascript
  function* gen() { yield 1; }
  const it = gen();
  ```

- **Intrinsic functions (examples, not directly callable in JS):**  Operations like copying object properties.

This part of the `MaglevGraphBuilder` plays a crucial role in transforming high-level JavaScript code into an optimized intermediate representation for execution.
This section of the `maglev-graph-builder.cc` file focuses on **building and optimizing call operations within the Maglev graph.** It handles various types of calls, including regular function calls, constructor calls, calls with spread syntax, and calls to built-in functions and runtime functions. It leverages type feedback to make informed decisions about how to represent these operations in the graph, aiming for efficiency.

Here's a breakdown of its key functionalities:

**1. Handling Regular Function Calls (`VisitCall...`)**:

* **`BuildCallWithFeedback`**: This is the central function for building call nodes. It retrieves type feedback associated with the call site and uses it to potentially optimize the call.
* **Optimizations based on Feedback**:
    * If the feedback indicates a specific target function, it attempts to directly call that function (`ReduceCallForTarget`).
    * It handles the `Function.prototype.apply` case, trying to optimize it when the receiver and arguments are known or can be inferred.
* **Handling Calls to Known Functions**:  It tries to optimize calls to known JSFunctions (`ReduceCallForConstant`).
* **Handling Calls to New Closures**:  It optimizes calls to newly created closures (`ReduceCallForNewClosure`), especially for non-constructor functions.
* **Handling Calls with Array-like Arguments**: It deals with scenarios where arguments are passed as array-like objects (like `arguments`), attempting to forward them efficiently (`ReduceCallWithArrayLike`, `ReduceCallWithArrayLikeForArgumentsObject`).
* **Generic Call**: If no specific optimization applies, it creates a generic call node (`BuildGenericCall`).

**2. Handling Constructor Calls (`VisitConstruct...`)**:

* **`BuildConstruct`**:  Similar to `BuildCallWithFeedback`, this function handles building constructor call nodes, utilizing type feedback.
* **Optimizations based on Feedback**:
    * It specifically optimizes calls to the `Array` constructor based on allocation site feedback (`TryReduceConstructArrayConstructor`).
    * It attempts to optimize calls to other known constructors (`TryReduceConstructBuiltin`).
    * It handles generic constructor calls, potentially inlining object allocation (`TryReduceConstructGeneric`).
* **Handling `new.target`**: It correctly handles the `new.target` meta-property in constructor calls.
* **Handling Constructor Calls with Spread**:  It supports constructor calls using the spread syntax (`VisitConstructWithSpread`).

**3. Optimizations based on Type Information and Feedback**:

* **Type Checks**:  It inserts explicit type checks (`BuildCheckValue`, `BuildCheckMaps`, `BuildCheckSmi`, `CheckNumber`) based on feedback to ensure assumptions made during optimization are valid.
* **Inlining**:  It attempts to inline calls to known functions and constructors when beneficial.
* **Specialized Call Nodes**: It uses specialized call nodes like `CallForwardVarargs` for optimized argument forwarding.

**4. Handling Intrinsic Functions (`VisitInvokeIntrinsic`, `VisitIntrinsic...`)**:

* It provides specific handlers for various built-in intrinsic functions, often involving direct calls to optimized runtime functions or inlined operations. Examples include operations on iterators, async functions, and object property manipulation.

**5. Implementing Type Conversions (`VisitTo...`, `BuildTo...`)**:

* It implements the logic for various JavaScript type conversion operations like `ToBoolean`, `ToName`, `ToNumber`, `ToNumeric`, and `ToObject`, potentially using optimized graph nodes based on the input value's type.

**6. Implementing the `instanceof` Operator (`VisitTestInstanceOf`)**:

* **`TryBuildFastInstanceOf`**: It attempts to optimize the `instanceof` operator based on the constructor's structure and type feedback, potentially using `BuildHasInPrototypeChain` for faster checks.
* **`BuildOrdinaryHasInstance`**:  Handles the default behavior of `instanceof`.

**7. Implementing the `in` Operator (`VisitTestIn`)**:

* It uses the `KeyedHasIC` built-in for checking if a property exists in an object.

**8. Supporting Async Functions and Generators**:

* It includes specific logic for handling the creation and manipulation of async function and generator objects.

**Relation to JavaScript Functionality:**

This code directly implements the semantics of various JavaScript operations. For example:

* When JavaScript code calls a function, the corresponding `VisitCall...` method will be executed, and this code will build the appropriate graph representation for that call.
* When a `new` keyword is used in JavaScript, the `VisitConstruct...` methods are involved in creating the graph nodes for object instantiation.
* JavaScript's type conversion rules (e.g., how `if (0)` evaluates to false) are implemented in the `BuildToBoolean` function.
* The `instanceof` operator's behavior is precisely defined by the logic in `BuildOrdinaryHasInstance` and its optimizations.

**JavaScript Examples:**

```javascript
// Function Call (would trigger VisitCallUndefinedReceiver1 or similar)
function greet(name) {
  console.log("Hello, " + name);
}
greet("World");

// Constructor Call (would trigger VisitConstruct)
const now = new Date();

// instanceof Operator (would trigger VisitTestInstanceOf)
const arr = [];
arr instanceof Array; // true

// Type Conversion (would trigger VisitToBoolean)
if (0) {
  // This won't execute
}

// Intrinsic function equivalent (not directly callable, but implemented here)
const obj = { a: 1, b: 2 };
const copy = Object.assign({}, obj);

// Async function (would involve VisitIntrinsicAsyncFunction...)
async function myFunction() {
  await somePromise;
  return "Done";
}
```

**In summary, this part of `maglev-graph-builder.cc` is a critical component responsible for translating JavaScript's dynamic call semantics, constructor behavior, type conversions, and specific operators into the static structure of the Maglev graph, applying optimizations wherever possible based on runtime feedback.** It bridges the gap between the JavaScript language and the compiler's internal representation.

Prompt: 
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第7部分，共9部分，请归纳一下它的功能

"""
er_info->possible_maps_are_known()) {
    // No info about receiver, can't infer API holder.
    return not_found;
  }
  DCHECK(!receiver_info->possible_maps().is_empty());
  compiler::MapRef first_receiver_map = receiver_info->possible_maps()[0];

  // See if we can constant-fold the compatible receiver checks.
  compiler::HolderLookupResult api_holder =
      function_template_info.LookupHolderOfExpectedType(broker(),
                                                        first_receiver_map);
  if (api_holder.lookup == CallOptimization::kHolderNotFound) {
    // Can't infer API holder.
    return not_found;
  }

  // Check that all {receiver_maps} are actually JSReceiver maps and
  // that the {function_template_info} accepts them without access
  // checks (even if "access check needed" is set for {receiver}).
  //
  // API holder might be a receivers's hidden prototype (i.e. the receiver is
  // a global proxy), so in this case the map check or stability dependency on
  // the receiver guard us from detaching a global object from global proxy.
  CHECK(first_receiver_map.IsJSReceiverMap());
  CHECK(!first_receiver_map.is_access_check_needed() ||
        function_template_info.accept_any_receiver());

  for (compiler::MapRef receiver_map : receiver_info->possible_maps()) {
    compiler::HolderLookupResult holder_i =
        function_template_info.LookupHolderOfExpectedType(broker(),
                                                          receiver_map);

    if (api_holder.lookup != holder_i.lookup) {
      // Different API holders, dynamic lookup is required.
      return not_found;
    }
    DCHECK(holder_i.lookup == CallOptimization::kHolderFound ||
           holder_i.lookup == CallOptimization::kHolderIsReceiver);
    if (holder_i.lookup == CallOptimization::kHolderFound) {
      DCHECK(api_holder.holder.has_value() && holder_i.holder.has_value());
      if (!api_holder.holder->equals(*holder_i.holder)) {
        // Different API holders, dynamic lookup is required.
        return not_found;
      }
    }

    CHECK(receiver_map.IsJSReceiverMap());
    CHECK(!receiver_map.is_access_check_needed() ||
          function_template_info.accept_any_receiver());
  }
  return api_holder;
}

ReduceResult MaglevGraphBuilder::ReduceCallForTarget(
    ValueNode* target_node, compiler::JSFunctionRef target, CallArguments& args,
    const compiler::FeedbackSource& feedback_source) {
  RETURN_IF_ABORT(BuildCheckValue(target_node, target));
  return ReduceCallForConstant(target, args, feedback_source);
}

ReduceResult MaglevGraphBuilder::ReduceCallForNewClosure(
    ValueNode* target_node, ValueNode* target_context,
    compiler::SharedFunctionInfoRef shared,
    compiler::OptionalFeedbackVectorRef feedback_vector, CallArguments& args,
    const compiler::FeedbackSource& feedback_source) {
  // Do not reduce calls to functions with break points.
  if (args.mode() != CallArguments::kDefault) {
    // TODO(victorgomes): Maybe inline the spread stub? Or call known function
    // directly if arguments list is an array.
    return ReduceResult::Fail();
  }
  if (!shared.HasBreakInfo(broker())) {
    if (IsClassConstructor(shared.kind())) {
      // If we have a class constructor, we should raise an exception.
      return BuildCallRuntime(Runtime::kThrowConstructorNonCallableError,
                              {target_node});
    }
    RETURN_IF_DONE(TryBuildCallKnownJSFunction(
        target_context, target_node,
        GetRootConstant(RootIndex::kUndefinedValue), shared, feedback_vector,
        args, feedback_source));
  }
  return BuildGenericCall(target_node, Call::TargetType::kJSFunction, args);
}

ReduceResult MaglevGraphBuilder::ReduceFunctionPrototypeApplyCallWithReceiver(
    compiler::OptionalHeapObjectRef maybe_receiver, CallArguments& args,
    const compiler::FeedbackSource& feedback_source) {
  if (args.mode() != CallArguments::kDefault) return ReduceResult::Fail();

  ValueNode* function = GetValueOrUndefined(args.receiver());
  if (maybe_receiver.has_value()) {
    RETURN_IF_ABORT(BuildCheckValue(function, maybe_receiver.value()));
    function = GetConstant(maybe_receiver.value());
  }

  SaveCallSpeculationScope saved(this);
  if (args.count() == 0) {
    CallArguments empty_args(ConvertReceiverMode::kNullOrUndefined);
    return ReduceCall(function, empty_args, feedback_source);
  }
  auto build_call_only_with_new_receiver = [&] {
    CallArguments new_args(ConvertReceiverMode::kAny, {args[0]});
    return ReduceCall(function, new_args, feedback_source);
  };
  if (args.count() == 1 || IsNullValue(args[1]) || IsUndefinedValue(args[1])) {
    return build_call_only_with_new_receiver();
  }
  auto build_call_with_array_like = [&] {
    CallArguments new_args(ConvertReceiverMode::kAny, {args[0], args[1]},
                           CallArguments::kWithArrayLike);
    return ReduceCallWithArrayLike(function, new_args, feedback_source);
  };
  if (!MayBeNullOrUndefined(args[1])) {
    return build_call_with_array_like();
  }
  return SelectReduction(
      [&](auto& builder) {
        return BuildBranchIfUndefinedOrNull(builder, args[1]);
      },
      build_call_only_with_new_receiver, build_call_with_array_like);
}

void MaglevGraphBuilder::BuildCallWithFeedback(
    ValueNode* target_node, CallArguments& args,
    const compiler::FeedbackSource& feedback_source) {
  const compiler::ProcessedFeedback& processed_feedback =
      broker()->GetFeedbackForCall(feedback_source);
  if (processed_feedback.IsInsufficient()) {
    RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
        DeoptimizeReason::kInsufficientTypeFeedbackForCall));
  }

  DCHECK_EQ(processed_feedback.kind(), compiler::ProcessedFeedback::kCall);
  const compiler::CallFeedback& call_feedback = processed_feedback.AsCall();

  if (call_feedback.target().has_value() &&
      call_feedback.target()->IsJSFunction()) {
    CallFeedbackContent content = call_feedback.call_feedback_content();
    compiler::JSFunctionRef feedback_target =
        call_feedback.target()->AsJSFunction();
    if (content == CallFeedbackContent::kReceiver) {
      compiler::NativeContextRef native_context =
          broker()->target_native_context();
      compiler::JSFunctionRef apply_function =
          native_context.function_prototype_apply(broker());
      RETURN_VOID_IF_ABORT(BuildCheckValue(target_node, apply_function));
      PROCESS_AND_RETURN_IF_DONE(ReduceFunctionPrototypeApplyCallWithReceiver(
                                     feedback_target, args, feedback_source),
                                 SetAccumulator);
      feedback_target = apply_function;
    } else {
      DCHECK_EQ(CallFeedbackContent::kTarget, content);
    }
    RETURN_VOID_IF_ABORT(BuildCheckValue(target_node, feedback_target));
  }

  PROCESS_AND_RETURN_IF_DONE(ReduceCall(target_node, args, feedback_source),
                             SetAccumulator);
}

ReduceResult MaglevGraphBuilder::ReduceCallWithArrayLikeForArgumentsObject(
    ValueNode* target_node, CallArguments& args,
    VirtualObject* arguments_object,
    const compiler::FeedbackSource& feedback_source) {
  DCHECK_EQ(args.mode(), CallArguments::kWithArrayLike);
  DCHECK(arguments_object->map().IsJSArgumentsObjectMap() ||
         arguments_object->map().IsJSArrayMap());
  args.PopArrayLikeArgument();
  ValueNode* elements_value =
      arguments_object->get(JSArgumentsObject::kElementsOffset);
  if (elements_value->Is<ArgumentsElements>()) {
    Call::TargetType target_type = Call::TargetType::kAny;
    // TODO(victorgomes): Add JSFunction node type in KNA and use the info here.
    if (compiler::OptionalHeapObjectRef maybe_constant =
            TryGetConstant(target_node)) {
      if (maybe_constant->IsJSFunction()) {
        compiler::SharedFunctionInfoRef shared =
            maybe_constant->AsJSFunction().shared(broker());
        if (!IsClassConstructor(shared.kind())) {
          target_type = Call::TargetType::kJSFunction;
        }
      }
    }
    int start_index = 0;
    if (elements_value->Cast<ArgumentsElements>()->type() ==
        CreateArgumentsType::kRestParameter) {
      start_index =
          elements_value->Cast<ArgumentsElements>()->formal_parameter_count();
    }
    return AddNewCallNode<CallForwardVarargs>(args, GetTaggedValue(target_node),
                                              GetTaggedValue(GetContext()),
                                              start_index, target_type);
  }

  if (elements_value->Is<RootConstant>()) {
    // It is a RootConstant, Elements can only be the empty fixed array.
    DCHECK_EQ(elements_value->Cast<RootConstant>()->index(),
              RootIndex::kEmptyFixedArray);
    CallArguments new_args(ConvertReceiverMode::kAny, {args.receiver()});
    return ReduceCall(target_node, new_args, feedback_source);
  }

  if (Constant* constant_value = elements_value->TryCast<Constant>()) {
    DCHECK(constant_value->object().IsFixedArray());
    compiler::FixedArrayRef elements = constant_value->object().AsFixedArray();
    base::SmallVector<ValueNode*, 8> arg_list;
    DCHECK_NOT_NULL(args.receiver());
    arg_list.push_back(args.receiver());
    for (int i = 0; i < static_cast<int>(args.count()); i++) {
      arg_list.push_back(args[i]);
    }
    for (uint32_t i = 0; i < elements.length(); i++) {
      arg_list.push_back(GetConstant(*elements.TryGet(broker(), i)));
    }
    CallArguments new_args(ConvertReceiverMode::kAny, std::move(arg_list));
    return ReduceCall(target_node, new_args, feedback_source);
  }

  DCHECK(elements_value->Is<InlinedAllocation>());
  InlinedAllocation* allocation = elements_value->Cast<InlinedAllocation>();
  VirtualObject* elements = allocation->object();

  base::SmallVector<ValueNode*, 8> arg_list;
  DCHECK_NOT_NULL(args.receiver());
  arg_list.push_back(args.receiver());
  for (int i = 0; i < static_cast<int>(args.count()); i++) {
    arg_list.push_back(args[i]);
  }
  DCHECK(elements->get(offsetof(FixedArray, length_))->Is<Int32Constant>());
  int length = elements->get(offsetof(FixedArray, length_))
                   ->Cast<Int32Constant>()
                   ->value();
  for (int i = 0; i < length; i++) {
    arg_list.push_back(elements->get(FixedArray::OffsetOfElementAt(i)));
  }
  CallArguments new_args(ConvertReceiverMode::kAny, std::move(arg_list));
  return ReduceCall(target_node, new_args, feedback_source);
}

namespace {
bool IsSloppyMappedArgumentsObject(compiler::JSHeapBroker* broker,
                                   compiler::MapRef map) {
  return broker->target_native_context()
      .fast_aliased_arguments_map(broker)
      .equals(map);
}
}  // namespace

std::optional<VirtualObject*>
MaglevGraphBuilder::TryGetNonEscapingArgumentsObject(ValueNode* value) {
  if (!value->Is<InlinedAllocation>()) return {};
  InlinedAllocation* alloc = value->Cast<InlinedAllocation>();
  // Although the arguments object has not been changed so far, since it is not
  // escaping, it could be modified after this bytecode if it is inside a loop.
  if (IsInsideLoop()) {
    if (!is_loop_effect_tracking() ||
        !loop_effects_->allocations.contains(alloc)) {
      return {};
    }
  }
  // TODO(victorgomes): We can probably loosen the IsNotEscaping requirement if
  // we keep track of the arguments object changes so far.
  if (alloc->IsEscaping()) return {};
  VirtualObject* object = alloc->object();
  // TODO(victorgomes): Support simple JSArray forwarding.
  compiler::MapRef map = object->map();
  // It is a rest parameter, if it is an array with ArgumentsElements node as
  // the elements array.
  if (map.IsJSArrayMap() && object->get(JSArgumentsObject::kElementsOffset)
                                ->Is<ArgumentsElements>()) {
    return object;
  }
  // TODO(victorgomes): We can loosen the IsSloppyMappedArgumentsObject
  // requirement if there is no stores to  the mapped arguments.
  if (map.IsJSArgumentsObjectMap() &&
      !IsSloppyMappedArgumentsObject(broker(), map)) {
    return object;
  }
  return {};
}

ReduceResult MaglevGraphBuilder::ReduceCallWithArrayLike(
    ValueNode* target_node, CallArguments& args,
    const compiler::FeedbackSource& feedback_source) {
  DCHECK_EQ(args.mode(), CallArguments::kWithArrayLike);

  // TODO(victorgomes): Add the case for JSArrays and Rest parameter.
  if (std::optional<VirtualObject*> arguments_object =
          TryGetNonEscapingArgumentsObject(args.array_like_argument())) {
    RETURN_IF_DONE(ReduceCallWithArrayLikeForArgumentsObject(
        target_node, args, *arguments_object, feedback_source));
  }

  // On fallthrough, create a generic call.
  return BuildGenericCall(target_node, Call::TargetType::kAny, args);
}

ReduceResult MaglevGraphBuilder::ReduceCall(
    ValueNode* target_node, CallArguments& args,
    const compiler::FeedbackSource& feedback_source) {
  if (compiler::OptionalHeapObjectRef maybe_constant =
          TryGetConstant(target_node)) {
    if (maybe_constant->IsJSFunction()) {
      ReduceResult result = ReduceCallForTarget(
          target_node, maybe_constant->AsJSFunction(), args, feedback_source);
      RETURN_IF_DONE(result);
    }
  }

  // If the implementation here becomes more complex, we could probably
  // deduplicate the code for FastCreateClosure and CreateClosure by using
  // templates or giving them a shared base class.
  if (FastCreateClosure* create_closure =
          target_node->TryCast<FastCreateClosure>()) {
    ReduceResult result = ReduceCallForNewClosure(
        create_closure, create_closure->context().node(),
        create_closure->shared_function_info(),
        create_closure->feedback_cell().feedback_vector(broker()), args,
        feedback_source);
    RETURN_IF_DONE(result);
  } else if (CreateClosure* create_closure =
                 target_node->TryCast<CreateClosure>()) {
    ReduceResult result = ReduceCallForNewClosure(
        create_closure, create_closure->context().node(),
        create_closure->shared_function_info(),
        create_closure->feedback_cell().feedback_vector(broker()), args,
        feedback_source);
    RETURN_IF_DONE(result);
  }

  // On fallthrough, create a generic call.
  return BuildGenericCall(target_node, Call::TargetType::kAny, args);
}

void MaglevGraphBuilder::BuildCallFromRegisterList(
    ConvertReceiverMode receiver_mode) {
  ValueNode* target = LoadRegister(0);
  interpreter::RegisterList reg_list = iterator_.GetRegisterListOperand(1);
  FeedbackSlot slot = GetSlotOperand(3);
  compiler::FeedbackSource feedback_source(feedback(), slot);
  CallArguments args(receiver_mode, reg_list, current_interpreter_frame_);
  BuildCallWithFeedback(target, args, feedback_source);
}

void MaglevGraphBuilder::BuildCallFromRegisters(
    int arg_count, ConvertReceiverMode receiver_mode) {
  ValueNode* target = LoadRegister(0);
  const int receiver_count =
      (receiver_mode == ConvertReceiverMode::kNullOrUndefined) ? 0 : 1;
  const int reg_count = arg_count + receiver_count;
  FeedbackSlot slot = GetSlotOperand(reg_count + 1);
  compiler::FeedbackSource feedback_source(feedback(), slot);
  switch (reg_count) {
    case 0: {
      DCHECK_EQ(receiver_mode, ConvertReceiverMode::kNullOrUndefined);
      CallArguments args(receiver_mode);
      BuildCallWithFeedback(target, args, feedback_source);
      break;
    }
    case 1: {
      CallArguments args(receiver_mode, {LoadRegister(1)});
      BuildCallWithFeedback(target, args, feedback_source);
      break;
    }
    case 2: {
      CallArguments args(receiver_mode, {LoadRegister(1), LoadRegister(2)});
      BuildCallWithFeedback(target, args, feedback_source);
      break;
    }
    case 3: {
      CallArguments args(receiver_mode,
                         {LoadRegister(1), LoadRegister(2), LoadRegister(3)});
      BuildCallWithFeedback(target, args, feedback_source);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void MaglevGraphBuilder::VisitCallAnyReceiver() {
  BuildCallFromRegisterList(ConvertReceiverMode::kAny);
}
void MaglevGraphBuilder::VisitCallProperty() {
  BuildCallFromRegisterList(ConvertReceiverMode::kNotNullOrUndefined);
}
void MaglevGraphBuilder::VisitCallProperty0() {
  BuildCallFromRegisters(0, ConvertReceiverMode::kNotNullOrUndefined);
}
void MaglevGraphBuilder::VisitCallProperty1() {
  BuildCallFromRegisters(1, ConvertReceiverMode::kNotNullOrUndefined);
}
void MaglevGraphBuilder::VisitCallProperty2() {
  BuildCallFromRegisters(2, ConvertReceiverMode::kNotNullOrUndefined);
}
void MaglevGraphBuilder::VisitCallUndefinedReceiver() {
  BuildCallFromRegisterList(ConvertReceiverMode::kNullOrUndefined);
}
void MaglevGraphBuilder::VisitCallUndefinedReceiver0() {
  BuildCallFromRegisters(0, ConvertReceiverMode::kNullOrUndefined);
}
void MaglevGraphBuilder::VisitCallUndefinedReceiver1() {
  BuildCallFromRegisters(1, ConvertReceiverMode::kNullOrUndefined);
}
void MaglevGraphBuilder::VisitCallUndefinedReceiver2() {
  BuildCallFromRegisters(2, ConvertReceiverMode::kNullOrUndefined);
}

void MaglevGraphBuilder::VisitCallWithSpread() {
  ValueNode* function = LoadRegister(0);
  interpreter::RegisterList reglist = iterator_.GetRegisterListOperand(1);
  FeedbackSlot slot = GetSlotOperand(3);
  compiler::FeedbackSource feedback_source(feedback(), slot);
  CallArguments args(ConvertReceiverMode::kAny, reglist,
                     current_interpreter_frame_, CallArguments::kWithSpread);
  BuildCallWithFeedback(function, args, feedback_source);
}

void MaglevGraphBuilder::VisitCallRuntime() {
  Runtime::FunctionId function_id = iterator_.GetRuntimeIdOperand(0);
  interpreter::RegisterList args = iterator_.GetRegisterListOperand(1);
  ValueNode* context = GetContext();
  size_t input_count = args.register_count() + CallRuntime::kFixedInputCount;
  CallRuntime* call_runtime = AddNewNode<CallRuntime>(
      input_count,
      [&](CallRuntime* call_runtime) {
        for (int i = 0; i < args.register_count(); ++i) {
          call_runtime->set_arg(i, GetTaggedValue(args[i]));
        }
      },
      function_id, context);
  SetAccumulator(call_runtime);

  if (RuntimeFunctionCanThrow(function_id)) {
    RETURN_VOID_IF_DONE(BuildAbort(AbortReason::kUnexpectedReturnFromThrow));
    UNREACHABLE();
  }
}

void MaglevGraphBuilder::VisitCallJSRuntime() {
  // Get the function to call from the native context.
  compiler::NativeContextRef native_context = broker()->target_native_context();
  ValueNode* context = GetConstant(native_context);
  uint32_t slot = iterator_.GetNativeContextIndexOperand(0);
  ValueNode* callee =
      LoadAndCacheContextSlot(context, slot, kMutable, ContextKind::kDefault);
  // Call the function.
  interpreter::RegisterList reglist = iterator_.GetRegisterListOperand(1);
  CallArguments args(ConvertReceiverMode::kNullOrUndefined, reglist,
                     current_interpreter_frame_);
  SetAccumulator(BuildGenericCall(callee, Call::TargetType::kJSFunction, args));
}

void MaglevGraphBuilder::VisitCallRuntimeForPair() {
  Runtime::FunctionId function_id = iterator_.GetRuntimeIdOperand(0);
  interpreter::RegisterList args = iterator_.GetRegisterListOperand(1);
  ValueNode* context = GetContext();

  size_t input_count = args.register_count() + CallRuntime::kFixedInputCount;
  CallRuntime* call_runtime = AddNewNode<CallRuntime>(
      input_count,
      [&](CallRuntime* call_runtime) {
        for (int i = 0; i < args.register_count(); ++i) {
          call_runtime->set_arg(i, GetTaggedValue(args[i]));
        }
      },
      function_id, context);
  auto result = iterator_.GetRegisterPairOperand(3);
  StoreRegisterPair(result, call_runtime);
}

void MaglevGraphBuilder::VisitInvokeIntrinsic() {
  // InvokeIntrinsic <function_id> <first_arg> <arg_count>
  Runtime::FunctionId intrinsic_id = iterator_.GetIntrinsicIdOperand(0);
  interpreter::RegisterList args = iterator_.GetRegisterListOperand(1);
  switch (intrinsic_id) {
#define CASE(Name, _, arg_count)                                         \
  case Runtime::kInline##Name:                                           \
    DCHECK_IMPLIES(arg_count != -1, arg_count == args.register_count()); \
    VisitIntrinsic##Name(args);                                          \
    break;
    INTRINSICS_LIST(CASE)
#undef CASE
    default:
      UNREACHABLE();
  }
}

void MaglevGraphBuilder::VisitIntrinsicCopyDataProperties(
    interpreter::RegisterList args) {
  DCHECK_EQ(args.register_count(), 2);
  SetAccumulator(BuildCallBuiltin<Builtin::kCopyDataProperties>(
      {GetTaggedValue(args[0]), GetTaggedValue(args[1])}));
}

void MaglevGraphBuilder::
    VisitIntrinsicCopyDataPropertiesWithExcludedPropertiesOnStack(
        interpreter::RegisterList args) {
  SmiConstant* excluded_property_count =
      GetSmiConstant(args.register_count() - 1);
  int kContext = 1;
  int kExcludedPropertyCount = 1;
  CallBuiltin* call_builtin = AddNewNode<CallBuiltin>(
      args.register_count() + kContext + kExcludedPropertyCount,
      [&](CallBuiltin* call_builtin) {
        int arg_index = 0;
        call_builtin->set_arg(arg_index++, GetTaggedValue(args[0]));
        call_builtin->set_arg(arg_index++, excluded_property_count);
        for (int i = 1; i < args.register_count(); i++) {
          call_builtin->set_arg(arg_index++, GetTaggedValue(args[i]));
        }
      },
      Builtin::kCopyDataPropertiesWithExcludedProperties,
      GetTaggedValue(GetContext()));
  SetAccumulator(call_builtin);
}

void MaglevGraphBuilder::VisitIntrinsicCreateIterResultObject(
    interpreter::RegisterList args) {
  DCHECK_EQ(args.register_count(), 2);
  ValueNode* value = current_interpreter_frame_.get(args[0]);
  ValueNode* done = current_interpreter_frame_.get(args[1]);
  compiler::MapRef map =
      broker()->target_native_context().iterator_result_map(broker());
  VirtualObject* iter_result = CreateJSIteratorResult(map, value, done);
  ValueNode* allocation =
      BuildInlinedAllocation(iter_result, AllocationType::kYoung);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the
  // next side effect clear it.
  ClearCurrentAllocationBlock();
  SetAccumulator(allocation);
}

void MaglevGraphBuilder::VisitIntrinsicCreateAsyncFromSyncIterator(
    interpreter::RegisterList args) {
  DCHECK_EQ(args.register_count(), 1);
  SetAccumulator(
      BuildCallBuiltin<Builtin::kCreateAsyncFromSyncIteratorBaseline>(
          {GetTaggedValue(args[0])}));
}

void MaglevGraphBuilder::VisitIntrinsicCreateJSGeneratorObject(
    interpreter::RegisterList args) {
  DCHECK_EQ(args.register_count(), 2);
  ValueNode* closure = current_interpreter_frame_.get(args[0]);
  ValueNode* receiver = current_interpreter_frame_.get(args[1]);
  PROCESS_AND_RETURN_IF_DONE(
      TryBuildAndAllocateJSGeneratorObject(closure, receiver), SetAccumulator);
  SetAccumulator(BuildCallBuiltin<Builtin::kCreateGeneratorObject>(
      {GetTaggedValue(closure), GetTaggedValue(receiver)}));
}

void MaglevGraphBuilder::VisitIntrinsicGeneratorGetResumeMode(
    interpreter::RegisterList args) {
  DCHECK_EQ(args.register_count(), 1);
  ValueNode* generator = current_interpreter_frame_.get(args[0]);
  SetAccumulator(
      BuildLoadTaggedField(generator, JSGeneratorObject::kResumeModeOffset));
}

void MaglevGraphBuilder::VisitIntrinsicGeneratorClose(
    interpreter::RegisterList args) {
  DCHECK_EQ(args.register_count(), 1);
  ValueNode* generator = current_interpreter_frame_.get(args[0]);
  ValueNode* value = GetSmiConstant(JSGeneratorObject::kGeneratorClosed);
  BuildStoreTaggedFieldNoWriteBarrier(generator, value,
                                      JSGeneratorObject::kContinuationOffset,
                                      StoreTaggedMode::kDefault);
  SetAccumulator(GetRootConstant(RootIndex::kUndefinedValue));
}

void MaglevGraphBuilder::VisitIntrinsicGetImportMetaObject(
    interpreter::RegisterList args) {
  DCHECK_EQ(args.register_count(), 0);
  SetAccumulator(BuildCallRuntime(Runtime::kGetImportMetaObject, {}).value());
}

void MaglevGraphBuilder::VisitIntrinsicAsyncFunctionAwait(
    interpreter::RegisterList args) {
  DCHECK_EQ(args.register_count(), 2);
  SetAccumulator(BuildCallBuiltin<Builtin::kAsyncFunctionAwait>(
      {GetTaggedValue(args[0]), GetTaggedValue(args[1])}));
}

void MaglevGraphBuilder::VisitIntrinsicAsyncFunctionEnter(
    interpreter::RegisterList args) {
  DCHECK_EQ(args.register_count(), 2);
  SetAccumulator(BuildCallBuiltin<Builtin::kAsyncFunctionEnter>(
      {GetTaggedValue(args[0]), GetTaggedValue(args[1])}));
}

void MaglevGraphBuilder::VisitIntrinsicAsyncFunctionReject(
    interpreter::RegisterList args) {
  DCHECK_EQ(args.register_count(), 2);
  SetAccumulator(BuildCallBuiltin<Builtin::kAsyncFunctionReject>(
      {GetTaggedValue(args[0]), GetTaggedValue(args[1])}));
}

void MaglevGraphBuilder::VisitIntrinsicAsyncFunctionResolve(
    interpreter::RegisterList args) {
  DCHECK_EQ(args.register_count(), 2);
  SetAccumulator(BuildCallBuiltin<Builtin::kAsyncFunctionResolve>(
      {GetTaggedValue(args[0]), GetTaggedValue(args[1])}));
}

void MaglevGraphBuilder::VisitIntrinsicAsyncGeneratorAwait(
    interpreter::RegisterList args) {
  DCHECK_EQ(args.register_count(), 2);
  SetAccumulator(BuildCallBuiltin<Builtin::kAsyncGeneratorAwait>(
      {GetTaggedValue(args[0]), GetTaggedValue(args[1])}));
}

void MaglevGraphBuilder::VisitIntrinsicAsyncGeneratorReject(
    interpreter::RegisterList args) {
  DCHECK_EQ(args.register_count(), 2);
  SetAccumulator(BuildCallBuiltin<Builtin::kAsyncGeneratorReject>(
      {GetTaggedValue(args[0]), GetTaggedValue(args[1])}));
}

void MaglevGraphBuilder::VisitIntrinsicAsyncGeneratorResolve(
    interpreter::RegisterList args) {
  DCHECK_EQ(args.register_count(), 3);
  SetAccumulator(BuildCallBuiltin<Builtin::kAsyncGeneratorResolve>(
      {GetTaggedValue(args[0]), GetTaggedValue(args[1]),
       GetTaggedValue(args[2])}));
}

void MaglevGraphBuilder::VisitIntrinsicAsyncGeneratorYieldWithAwait(
    interpreter::RegisterList args) {
  DCHECK_EQ(args.register_count(), 2);
  SetAccumulator(BuildCallBuiltin<Builtin::kAsyncGeneratorYieldWithAwait>(
      {GetTaggedValue(args[0]), GetTaggedValue(args[1])}));
}

ValueNode* MaglevGraphBuilder::BuildGenericConstruct(
    ValueNode* target, ValueNode* new_target, ValueNode* context,
    const CallArguments& args,
    const compiler::FeedbackSource& feedback_source) {
  size_t input_count = args.count_with_receiver() + Construct::kFixedInputCount;
  DCHECK_EQ(args.receiver_mode(), ConvertReceiverMode::kNullOrUndefined);
  return AddNewNode<Construct>(
      input_count,
      [&](Construct* construct) {
        int arg_index = 0;
        // Add undefined receiver.
        construct->set_arg(arg_index++,
                           GetRootConstant(RootIndex::kUndefinedValue));
        for (size_t i = 0; i < args.count(); i++) {
          construct->set_arg(arg_index++, GetTaggedValue(args[i]));
        }
      },
      feedback_source, GetTaggedValue(target), GetTaggedValue(new_target),
      GetTaggedValue(context));
}

ValueNode* MaglevGraphBuilder::BuildAndAllocateKeyValueArray(ValueNode* key,
                                                             ValueNode* value) {
  VirtualObject* elements = CreateFixedArray(broker()->fixed_array_map(), 2);
  elements->set(FixedArray::OffsetOfElementAt(0), key);
  elements->set(FixedArray::OffsetOfElementAt(1), value);
  compiler::MapRef map =
      broker()->target_native_context().js_array_packed_elements_map(broker());
  VirtualObject* array =
      CreateJSArray(map, map.instance_size(), GetInt32Constant(2));
  array->set(JSArray::kElementsOffset, elements);
  ValueNode* allocation = BuildInlinedAllocation(array, AllocationType::kYoung);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the
  // next side effect clear it.
  ClearCurrentAllocationBlock();
  return allocation;
}

ValueNode* MaglevGraphBuilder::BuildAndAllocateJSArray(
    compiler::MapRef map, ValueNode* length, ValueNode* elements,
    const compiler::SlackTrackingPrediction& slack_tracking_prediction,
    AllocationType allocation_type) {
  VirtualObject* array =
      CreateJSArray(map, slack_tracking_prediction.instance_size(), length);
  array->set(JSArray::kElementsOffset, elements);
  for (int i = 0; i < slack_tracking_prediction.inobject_property_count();
       i++) {
    array->set(map.GetInObjectPropertyOffset(i),
               GetRootConstant(RootIndex::kUndefinedValue));
  }
  ValueNode* allocation = BuildInlinedAllocation(array, allocation_type);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the
  // next side effect clear it.
  ClearCurrentAllocationBlock();
  return allocation;
}

ValueNode* MaglevGraphBuilder::BuildAndAllocateJSArrayIterator(
    ValueNode* array, IterationKind iteration_kind) {
  compiler::MapRef map =
      broker()->target_native_context().initial_array_iterator_map(broker());
  VirtualObject* iterator = CreateJSArrayIterator(map, array, iteration_kind);
  ValueNode* allocation =
      BuildInlinedAllocation(iterator, AllocationType::kYoung);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the
  // next side effect clear it.
  ClearCurrentAllocationBlock();
  return allocation;
}

ReduceResult MaglevGraphBuilder::TryBuildAndAllocateJSGeneratorObject(
    ValueNode* closure, ValueNode* receiver) {
  compiler::OptionalHeapObjectRef maybe_constant = TryGetConstant(closure);
  if (!maybe_constant.has_value()) return ReduceResult::Fail();
  if (!maybe_constant->IsJSFunction()) return ReduceResult::Fail();
  compiler::JSFunctionRef function = maybe_constant->AsJSFunction();
  if (!function.has_initial_map(broker())) return ReduceResult::Fail();

  // Create the register file.
  compiler::SharedFunctionInfoRef shared = function.shared(broker());
  DCHECK(shared.HasBytecodeArray());
  compiler::BytecodeArrayRef bytecode_array = shared.GetBytecodeArray(broker());
  int parameter_count_no_receiver = bytecode_array.parameter_count() - 1;
  int length = parameter_count_no_receiver + bytecode_array.register_count();
  if (FixedArray::SizeFor(length) > kMaxRegularHeapObjectSize) {
    return ReduceResult::Fail();
  }
  auto undefined = GetRootConstant(RootIndex::kUndefinedValue);
  VirtualObject* register_file =
      CreateFixedArray(broker()->fixed_array_map(), length);
  for (int i = 0; i < length; i++) {
    register_file->set(FixedArray::OffsetOfElementAt(i), undefined);
  }

  // Create the JS[Async]GeneratorObject instance.
  compiler::SlackTrackingPrediction slack_tracking_prediction =
      broker()->dependencies()->DependOnInitialMapInstanceSizePrediction(
          function);
  compiler::MapRef initial_map = function.initial_map(broker());
  VirtualObject* generator = CreateJSGeneratorObject(
      initial_map, slack_tracking_prediction.instance_size(), GetContext(),
      closure, receiver, register_file);

  // Handle in-object properties.
  for (int i = 0; i < slack_tracking_prediction.inobject_property_count();
       i++) {
    generator->set(initial_map.GetInObjectPropertyOffset(i), undefined);
  }

  ValueNode* allocation =
      BuildInlinedAllocation(generator, AllocationType::kYoung);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the
  // next side effect clear it.
  ClearCurrentAllocationBlock();
  return allocation;
}

namespace {

compiler::OptionalMapRef GetArrayConstructorInitialMap(
    compiler::JSHeapBroker* broker, compiler::JSFunctionRef array_function,
    ElementsKind elements_kind, size_t argc, std::optional<int> maybe_length) {
  compiler::MapRef initial_map = array_function.initial_map(broker);
  if (argc == 1 && (!maybe_length.has_value() || *maybe_length > 0)) {
    // Constructing an Array via new Array(N) where N is an unsigned
    // integer, always creates a holey backing store.
    elements_kind = GetHoleyElementsKind(elements_kind);
  }
  return initial_map.AsElementsKind(broker, elements_kind);
}

}  // namespace

ValueNode* MaglevGraphBuilder::BuildElementsArray(int length) {
  if (length == 0) {
    return GetRootConstant(RootIndex::kEmptyFixedArray);
  }
  VirtualObject* elements =
      CreateFixedArray(broker()->fixed_array_map(), length);
  auto hole = GetRootConstant(RootIndex::kTheHoleValue);
  for (int i = 0; i < length; i++) {
    elements->set(FixedArray::OffsetOfElementAt(i), hole);
  }
  return elements;
}

ReduceResult MaglevGraphBuilder::TryReduceConstructArrayConstructor(
    compiler::JSFunctionRef array_function, CallArguments& args,
    compiler::OptionalAllocationSiteRef maybe_allocation_site) {
  ElementsKind elements_kind =
      maybe_allocation_site.has_value()
          ? maybe_allocation_site->GetElementsKind()
          : array_function.initial_map(broker()).elements_kind();
  // TODO(victorgomes): Support double elements array.
  if (IsDoubleElementsKind(elements_kind)) return ReduceResult::Fail();
  DCHECK(IsFastElementsKind(elements_kind));

  std::optional<int> maybe_length;
  if (args.count() == 1) {
    maybe_length = TryGetInt32Constant(args[0]);
  }
  compiler::OptionalMapRef maybe_initial_map = GetArrayConstructorInitialMap(
      broker(), array_function, elements_kind, args.count(), maybe_length);
  if (!maybe_initial_map.has_value()) return ReduceResult::Fail();
  compiler::MapRef initial_map = maybe_initial_map.value();
  compiler::SlackTrackingPrediction slack_tracking_prediction =
      broker()->dependencies()->DependOnInitialMapInstanceSizePrediction(
          array_function);

  // Tells whether we are protected by either the {site} or a
  // protector cell to do certain speculative optimizations.
  bool can_inline_call = false;
  AllocationType allocation_type = AllocationType::kYoung;

  if (maybe_allocation_site) {
    can_inline_call = maybe_allocation_site->CanInlineCall();
    allocation_type =
        broker()->dependencies()->DependOnPretenureMode(*maybe_allocation_site);
    broker()->dependencies()->DependOnElementsKind(*maybe_allocation_site);
  } else {
    compiler::PropertyCellRef array_constructor_protector = MakeRef(
        broker(), local_isolate()->factory()->array_constructor_protector());
    array_constructor_protector.CacheAsProtector(broker());
    can_inline_call = array_constructor_protector.value(broker()).AsSmi() ==
                      Protectors::kProtectorValid;
  }

  if (args.count() == 0) {
    return BuildAndAllocateJSArray(
        initial_map, GetSmiConstant(0),
        BuildElementsArray(JSArray::kPreallocatedArrayElements),
        slack_tracking_prediction, allocation_type);
  }

  if (maybe_length.has_value() && *maybe_length >= 0 &&
      *maybe_length < JSArray::kInitialMaxFastElementArray) {
    return BuildAndAllocateJSArray(initial_map, GetSmiConstant(*maybe_length),
                                   BuildElementsArray(*maybe_length),
                                   slack_tracking_prediction, allocation_type);
  }

  // TODO(victorgomes): If we know the argument cannot be a number, we should
  // allocate an array with one element.
  // We don't know anything about the length, so we rely on the allocation
  // site to avoid deopt loops.
  if (args.count() == 1 && can_inline_call) {
    return SelectReduction(
        [&](auto& builder) {
          return BuildBranchIfInt32Compare(builder,
                                           Operation::kGreaterThanOrEqual,
                                           args[0], GetInt32Constant(0));
        },
        [&] {
          ValueNode* elements =
              AddNewNode<AllocateElementsArray>({args[0]}, allocation_type);
          return BuildAndAllocateJSArray(initial_map, args[0], elements,
                                         slack_tracking_prediction,
                                         allocation_type);
        },
        [&] {
          ValueNode* error = GetSmiConstant(
              static_cast<int>(MessageTemplate::kInvalidArrayLength));
          return BuildCallRuntime(Runtime::kThrowRangeError, {error});
        });
  }

  // TODO(victorgomes): Support the constructor with argument count larger
  // than 1.
  return ReduceResult::Fail();
}

ReduceResult MaglevGraphBuilder::TryReduceConstructBuiltin(
    compiler::JSFunctionRef builtin,
    compiler::SharedFunctionInfoRef shared_function_info, ValueNode* target,
    CallArguments& args) {
  // TODO(victorgomes): specialize more known constants builtin targets.
  switch (shared_function_info.builtin_id()) {
    case Builtin::kArrayConstructor: {
      RETURN_IF_DONE(TryReduceConstructArrayConstructor(builtin, args));
      break;
    }
    case Builtin::kObjectConstructor: {
      // If no value is passed, we can immediately lower to a simple
      // constructor.
      if (args.count() == 0) {
        RETURN_IF_ABORT(BuildCheckValue(target, builtin));
        ValueNode* result = BuildInlinedAllocation(CreateJSConstructor(builtin),
                                                   AllocationType::kYoung);
        // TODO(leszeks): Don't eagerly clear the raw allocation, have the
        // next side effect clear it.
        ClearCurrentAllocationBlock();
        return result;
      }
      break;
    }
    default:
      break;
  }
  return ReduceResult::Fail();
}

ReduceResult MaglevGraphBuilder::TryReduceConstructGeneric(
    compiler::JSFunctionRef function,
    compiler::SharedFunctionInfoRef shared_function_info, ValueNode* target,
    ValueNode* new_target, CallArguments& args,
    compiler::FeedbackSource& feedback_source) {
  RETURN_IF_ABORT(BuildCheckValue(target, function));

  int construct_arg_count = static_cast<int>(args.count());
  base::Vector<ValueNode*> construct_arguments_without_receiver =
      zone()->AllocateVector<ValueNode*>(construct_arg_count);
  for (int i = 0; i < construct_arg_count; i++) {
    construct_arguments_without_receiver[i] = args[i];
  }

  if (IsDerivedConstructor(shared_function_info.kind())) {
    ValueNode* implicit_receiver = GetRootConstant(RootIndex::kTheHoleValue);
    args.set_receiver(implicit_receiver);
    ValueNode* call_result;
    {
      DeoptFrameScope construct(this, implicit_receiver);
      ReduceResult result = TryBuildCallKnownJSFunction(function, new_target,
                                                        args, feedback_source);
      RETURN_IF_ABORT(result);
      call_result = result.value();
    }
    if (CheckType(call_result, NodeType::kJSReceiver)) return call_result;
    ValueNode* constant_node;
    if (compiler::OptionalHeapObjectRef maybe_constant =
            TryGetConstant(call_result, &constant_node)) {
      compiler::HeapObjectRef constant = maybe_constant.value();
      if (constant.IsJSReceiver()) return constant_node;
    }
    if (!call_result->properties().is_tagged()) {
      return BuildCallRuntime(Runtime::kThrowConstructorReturnedNonObject, {});
    }
    return AddNewNode<CheckDerivedConstructResult>({call_result});
  }

  // We do not create a construct stub lazy deopt frame, since
  // FastNewObject cannot fail if target is a JSFunction.
  ValueNode* implicit_receiver = nullptr;
  if (function.has_initial_map(broker())) {
    compiler::MapRef map = function.initial_map(broker());
    if (map.GetConstructor(broker()).equals(function)) {
      implicit_receiver = BuildInlinedAllocation(CreateJSConstructor(function),
                                                 AllocationType::kYoung);
      // TODO(leszeks): Don't eagerly clear the raw allocation, have the
      // next side effect clear it.
      ClearCurrentAllocationBlock();
    }
  }
  if (implicit_receiver == nullptr) {
    implicit_receiver = BuildCallBuiltin<Builtin::kFastNewObject>(
        {GetTaggedValue(target), GetTaggedValue(new_target)});
  }
  EnsureType(implicit_receiver, NodeType::kJSReceiver);

  args.set_receiver(implicit_receiver);
  ValueNode* call_result;
  {
    DeoptFrameScope construct(this, implicit_receiver);
    ReduceResult result = TryBuildCallKnownJSFunction(function, new_target,
                                                      args, feedback_source);
    RETURN_IF_ABORT(result);
    call_result = result.value();
  }
  if (CheckType(call_result, NodeType::kJSReceiver)) return call_result;
  if (!call_result->properties().is_tagged()) return implicit_receiver;
  ValueNode* constant_node;
  if (compiler::OptionalHeapObjectRef maybe_constant =
          TryGetConstant(call_result, &constant_node)) {
    compiler::HeapObjectRef constant = maybe_constant.value();
    DCHECK(CheckType(implicit_receiver, NodeType::kJSReceiver));
    if (constant.IsJSReceiver()) return constant_node;
    return implicit_receiver;
  }
  return AddNewNode<CheckConstructResult>({call_result, implicit_receiver});
}

ReduceResult MaglevGraphBuilder::TryReduceConstruct(
    compiler::HeapObjectRef feedback_target, ValueNode* target,
    ValueNode* new_target, CallArguments& args,
    compiler::FeedbackSource& feedback_source) {
  DCHECK(!feedback_target.IsAllocationSite());
  if (!feedback_target.map(broker()).is_constructor()) {
    // TODO(victorgomes): Deal the case where target is not a constructor.
    return ReduceResult::Fail();
  }

  if (target != new_target) return ReduceResult::Fail();

  // TODO(v8:7700): Add fast paths for other callables.
  if (!feedback_target.IsJSFunction()) return ReduceResult::Fail();
  compiler::JSFunctionRef function = feedback_target.AsJSFunction();

  // Do not inline constructors with break points.
  compiler::SharedFunctionInfoRef shared_function_info =
      function.shared(broker());
  if (shared_function_info.HasBreakInfo(broker())) {
    return ReduceResult::Fail();
  }

  // Do not inline cross natives context.
  if (function.native_context(broker()) != broker()->target_native_context()) {
    return ReduceResult::Fail();
  }

  if (args.mode() != CallArguments::kDefault) {
    // TODO(victorgomes): Maybe inline the spread stub? Or call known
    // function directly if arguments list is an array.
    return ReduceResult::Fail();
  }

  if (shared_function_info.HasBuiltinId()) {
    RETURN_IF_DONE(TryReduceConstructBuiltin(function, shared_function_info,
                                             target, args));
  }

  if (shared_function_info.construct_as_builtin()) {
    // TODO(victorgomes): Inline JSBuiltinsConstructStub.
    return ReduceResult::Fail();
  }

  return TryReduceConstructGeneric(function, shared_function_info, target,
                                   new_target, args, feedback_source);
}

void MaglevGraphBuilder::BuildConstruct(
    ValueNode* target, ValueNode* new_target, CallArguments& args,
    compiler::FeedbackSource& feedback_source) {
  compiler::ProcessedFeedback const& processed_feedback =
      broker()->GetFeedbackForCall(feedback_source);
  if (processed_feedback.IsInsufficient()) {
    RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
        DeoptimizeReason::kInsufficientTypeFeedbackForConstruct));
  }

  DCHECK_EQ(processed_feedback.kind(), compiler::ProcessedFeedback::kCall);
  compiler::OptionalHeapObjectRef feedback_target =
      processed_feedback.AsCall().target();
  if (feedback_target.has_value() && feedback_target->IsAllocationSite()) {
    // The feedback is an AllocationSite, which means we have called the
    // Array function and collected transition (and pretenuring) feedback
    // for the resulting arrays.
    compiler::JSFunctionRef array_function =
        broker()->target_native_context().array_function(broker());
    RETURN_VOID_IF_ABORT(BuildCheckValue(target, array_function));
    PROCESS_AND_RETURN_IF_DONE(
        TryReduceConstructArrayConstructor(array_function, args,
                                           feedback_target->AsAllocationSite()),
        SetAccumulator);
  } else {
    if (feedback_target.has_value()) {
      PROCESS_AND_RETURN_IF_DONE(
          TryReduceConstruct(feedback_target.value(), target, new_target, args,
                             feedback_source),
          SetAccumulator);
    }
    if (compiler::OptionalHeapObjectRef maybe_constant =
            TryGetConstant(target)) {
      PROCESS_AND_RETURN_IF_DONE(
          TryReduceConstruct(maybe_constant.value(), target, new_target, args,
                             feedback_source),
          SetAccumulator);
    }
  }
  ValueNode* context = GetContext();
  SetAccumulator(BuildGenericConstruct(target, new_target, context, args,
                                       feedback_source));
}

void MaglevGraphBuilder::VisitConstruct() {
  ValueNode* new_target = GetAccumulator();
  ValueNode* target = LoadRegister(0);
  interpreter::RegisterList reg_list = iterator_.GetRegisterListOperand(1);
  FeedbackSlot slot = GetSlotOperand(3);
  compiler::FeedbackSource feedback_source{feedback(), slot};
  CallArguments args(ConvertReceiverMode::kNullOrUndefined, reg_list,
                     current_interpreter_frame_);
  BuildConstruct(target, new_target, args, feedback_source);
}

void MaglevGraphBuilder::VisitConstructWithSpread() {
  ValueNode* new_target = GetAccumulator();
  ValueNode* constructor = LoadRegister(0);
  interpreter::RegisterList args = iterator_.GetRegisterListOperand(1);
  ValueNode* context = GetContext();
  FeedbackSlot slot = GetSlotOperand(3);
  compiler::FeedbackSource feedback_source(feedback(), slot);

  int kReceiver = 1;
  size_t input_count =
      args.register_count() + kReceiver + ConstructWithSpread::kFixedInputCount;
  ConstructWithSpread* construct = AddNewNode<ConstructWithSpread>(
      input_count,
      [&](ConstructWithSpread* construct) {
        int arg_index = 0;
        // Add undefined receiver.
        construct->set_arg(arg_index++,
                           GetRootConstant(RootIndex::kUndefinedValue));
        for (int i = 0; i < args.register_count(); i++) {
          construct->set_arg(arg_index++, GetTaggedValue(args[i]));
        }
      },
      feedback_source, GetTaggedValue(constructor), GetTaggedValue(new_target),
      GetTaggedValue(context));
  SetAccumulator(construct);
}

void MaglevGraphBuilder::VisitConstructForwardAllArgs() {
  ValueNode* new_target = GetAccumulator();
  ValueNode* target = LoadRegister(0);
  FeedbackSlot slot = GetSlotOperand(1);
  compiler::FeedbackSource feedback_source{feedback(), slot};

  if (is_inline()) {
    base::SmallVector<ValueNode*, 8> forwarded_args(argument_count());
    for (int i = 1 /* skip receiver */; i < argument_count(); ++i) {
      forwarded_args[i] = GetInlinedArgument(i);
    }
    CallArguments args(ConvertReceiverMode::kNullOrUndefined,
                       std::move(forwarded_args));
    BuildConstruct(target, new_target, args, feedback_source);
  } else {
    // TODO(syg): Add ConstructForwardAllArgs reductions and support inlining.
    SetAccumulator(
        BuildCallBuiltin<Builtin::kConstructForwardAllArgs_WithFeedback>(
            {GetTaggedValue(target), GetTaggedValue(new_target)},
            feedback_source));
  }
}

void MaglevGraphBuilder::VisitTestEqual() {
  VisitCompareOperation<Operation::kEqual>();
}
void MaglevGraphBuilder::VisitTestEqualStrict() {
  VisitCompareOperation<Operation::kStrictEqual>();
}
void MaglevGraphBuilder::VisitTestLessThan() {
  VisitCompareOperation<Operation::kLessThan>();
}
void MaglevGraphBuilder::VisitTestLessThanOrEqual() {
  VisitCompareOperation<Operation::kLessThanOrEqual>();
}
void MaglevGraphBuilder::VisitTestGreaterThan() {
  VisitCompareOperation<Operation::kGreaterThan>();
}
void MaglevGraphBuilder::VisitTestGreaterThanOrEqual() {
  VisitCompareOperation<Operation::kGreaterThanOrEqual>();
}

MaglevGraphBuilder::InferHasInPrototypeChainResult
MaglevGraphBuilder::InferHasInPrototypeChain(
    ValueNode* receiver, compiler::HeapObjectRef prototype) {
  auto node_info = known_node_aspects().TryGetInfoFor(receiver);
  // If the map set is not found, then we don't know anything about the map of
  // the receiver, so bail.
  if (!node_info || !node_info->possible_maps_are_known()) {
    return kMayBeInPrototypeChain;
  }

  // If the set of possible maps is empty, then there's no possible map for this
  // receiver, therefore this path is unreachable at runtime. We're unlikely to
  // ever hit this case, BuildCheckMaps should already unconditionally deopt,
  // but check it in case another checking operation fails to statically
  // unconditionally deopt.
  if (node_info->possible_maps().is_empty()) {
    // TODO(leszeks): Add an unreachable assert here.
    return kIsNotInPrototypeChain;
  }

  ZoneVector<compiler::MapRef> receiver_map_refs(zone());

  // Try to determine either that all of the {receiver_maps} have the given
  // {prototype} in their chain, or that none do. If we can't tell, return
  // kMayBeInPrototypeChain.
  bool all = true;
  bool none = true;
  for (compiler::MapRef map : node_info->possible_maps()) {
    receiver_map_refs.push_back(map);
    while (true) {
      if (IsSpecialReceiverInstanceType(map.instance_type())) {
        return kMayBeInPrototypeChain;
      }
      if (!map.IsJSObjectMap()) {
        all = false;
        break;
      }
      compiler::HeapObjectRef map_prototype = map.prototype(broker());
      if (map_prototype.equals(prototype)) {
        none = false;
        break;
      }
      map = map_prototype.map(broker());
      // TODO(v8:11457) Support dictionary mode protoypes here.
      if (!map.is_stable() || map.is_dictionary_map()) {
        return kMayBeInPrototypeChain;
      }
      if (map.oddball_type(broker()) == compiler::OddballType::kNull) {
        all = false;
        break;
      }
    }
  }
  DCHECK(!receiver_map_refs.empty());
  DCHECK_IMPLIES(all, !none);
  if (!all && !none) return kMayBeInPrototypeChain;

  {
    compiler::OptionalJSObjectRef last_prototype;
    if (all) {
      // We don't need to protect the full chain if we found the prototype, we
      // can stop at {prototype}.  In fact we could stop at the one before
      // {prototype} but since we're dealing with multiple receiver maps this
      // might be a different object each time, so it's much simpler to include
      // {prototype}. That does, however, mean that we must check {prototype}'s
      // map stability.
      if (!prototype.IsJSObject() || !prototype.map(broker()).is_stable()) {
        return kMayBeInPrototypeChain;
      }
      last_prototype = prototype.AsJSObject();
    }
    broker()->dependencies()->DependOnStablePrototypeChains(
        receiver_map_refs, kStartAtPrototype, last_prototype);
  }

  DCHECK_EQ(all, !none);
  return all ? kIsInPrototypeChain : kIsNotInPrototypeChain;
}

ReduceResult MaglevGraphBuilder::TryBuildFastHasInPrototypeChain(
    ValueNode* object, compiler::HeapObjectRef prototype) {
  auto in_prototype_chain = InferHasInPrototypeChain(object, prototype);
  if (in_prototype_chain == kMayBeInPrototypeChain) return ReduceResult::Fail();

  return GetBooleanConstant(in_prototype_chain == kIsInPrototypeChain);
}

ReduceResult MaglevGraphBuilder::BuildHasInPrototypeChain(
    ValueNode* object, compiler::HeapObjectRef prototype) {
  RETURN_IF_DONE(TryBuildFastHasInPrototypeChain(object, prototype));
  return AddNewNode<HasInPrototypeChain>({object}, prototype);
}

ReduceResult MaglevGraphBuilder::TryBuildFastOrdinaryHasInstance(
    ValueNode* object, compiler::JSObjectRef callable,
    ValueNode* callable_node_if_not_constant) {
  const bool is_constant = callable_node_if_not_constant == nullptr;
  if (!is_constant) return ReduceResult::Fail();

  if (callable.IsJSBoundFunction()) {
    // OrdinaryHasInstance on bound functions turns into a recursive
    // invocation of the instanceof operator again.
    compiler::JSBoundFunctionRef function = callable.AsJSBoundFunction();
    compiler::JSReceiverRef bound_target_function =
        function.bound_target_function(broker());

    if (bound_target_function.IsJSObject()) {
      RETURN_IF_DONE(TryBuildFastInstanceOf(
          object, bound_target_function.AsJSObject(), nullptr));
    }

    // If we can't build a fast instance-of, build a slow one with the
    // partial optimisation of using the bound target function constant.
    return BuildCallBuiltin<Builtin::kInstanceOf>(
        {GetTaggedValue(object), GetConstant(bound_target_function)});
  }

  if (callable.IsJSFunction()) {
    // Optimize if we currently know the "prototype" property.
    compiler::JSFunctionRef function = callable.AsJSFunction();

    // TODO(v8:7700): Remove the has_prototype_slot condition once the broker
    // is always enabled.
    if (!function.map(broker()).has_prototype_slot() ||
        !function.has_instance_prototype(broker()) ||
        function.PrototypeRequiresRuntimeLookup(broker())) {
      return ReduceResult::Fail();
    }

    compiler::HeapObjectRef prototype =
        broker()->dependencies()->DependOnPrototypeProperty(function);
    return BuildHasInPrototypeChain(object, prototype);
  }

  return ReduceResult::Fail();
}

ReduceResult MaglevGraphBuilder::BuildOrdinaryHasInstance(
    ValueNode* object, compiler::JSObjectRef callable,
    ValueNode* callable_node_if_not_constant) {
  RETURN_IF_DONE(TryBuildFastOrdinaryHasInstance(
      object, callable, callable_node_if_not_constant));

  return BuildCallBuiltin<Builtin::kOrdinaryHasInstance>(
      {callable_node_if_not_constant
           ? GetTaggedValue(callable_node_if_not_constant)
           : GetConstant(callable),
       GetTaggedValue(object)});
}

ReduceResult MaglevGraphBuilder::TryBuildFastInstanceOf(
    ValueNode* object, compiler::JSObjectRef callable,
    ValueNode* callable_node_if_not_constant) {
  compiler::MapRef receiver_map = callable.map(broker());
  compiler::NameRef name = broker()->has_instance_symbol();
  compiler::PropertyAccessInfo access_info = broker()->GetPropertyAccessInfo(
      receiver_map, name, compiler::AccessMode::kLoad);

  // TODO(v8:11457) Support dictionary mode holders here.
  if (access_info.IsInvalid() || access_info.HasDictionaryHolder()) {
    return ReduceResult::Fail();
  }
  access_info.RecordDependencies(broker()->dependencies());

  if (access_info.IsNotFound()) {
    // If there's no @@hasInstance handler, the OrdinaryHasInstance operation
    // takes over, but that requires the constructor to be callable.
    if (!receiver_map.is_callable()) {
      return ReduceResult::Fail();
    }

    broker()->dependencies()->DependOnStablePrototypeChains(
        access_info.lookup_start_object_maps(), kStartAtPrototype);

    // Monomorphic property access.
    if (callable_node_if_not_constant) {
      RETURN_IF_ABORT(BuildCheckMaps(
          callable_node_if_not_constant,
          base::VectorOf(access_info.lookup_start_object_maps())));
    } else {
      // Even if we have a constant receiver, we still have to make sure its
      // map is correct, in case it migrates.
      if (receiver_map.is_stable()) {
        broker()->dependencies()->DependOnStableMap(receiver_map);
      } else {
        RETURN_IF_ABORT(BuildCheckMaps(
            GetConstant(callable),
            base::VectorOf(access_info.lookup_start_object_maps())));
      }
    }

    return BuildOrdinaryHasInstance(object, callable,
                                    callable_node_if_not_constant);
  }

  if (access_info.IsFastDataConstant()) {
    compiler::OptionalJSObjectRef holder = access_info.holder();
    bool found_on_proto = holder.has_value();
    compiler::JSObjectRef holder_ref =
        found_on_proto ? holder.value() : callable;
    if (access_info.field_representation().IsDouble()) {
      return ReduceResult::Fail();
    }
    compiler::OptionalObjectRef has_instance_field =
        holder_ref.GetOwnFastConstantDataProperty(
            broker(), access_info.field_representation(),
            access_info.field_index(), broker()->dependencies());
    if (!has_instance_field.has_value() ||
        !has_instance_field->IsHeapObject() ||
        !has_instance_field->AsHeapObject().map(broker()).is_callable()) {
      return ReduceResult::Fail();
    }

    if (found_on_proto) {
      broker()->dependencies()->DependOnStablePrototypeChains(
          access_info.lookup_start_object_maps(), kStartAtPrototype,
          holder.value());
    }

    ValueNode* callable_node;
    if (callable_node_if_not_constant) {
      // Check that {callable_node_if_not_constant} is actually {callable}.
      RETURN_IF_ABORT(BuildCheckValue(callable_node_if_not_constant, callable));
      callable_node = callable_node_if_not_constant;
    } else {
      callable_node = GetConstant(callable);
    }
    RETURN_IF_ABORT(BuildCheckMaps(
        callable_node, base::VectorOf(access_info.lookup_start_object_maps())));

    // Special case the common case, where @@hasInstance is
    // Function.p.hasInstance. In this case we don't need to call ToBoolean (or
    // use the continuation), since OrdinaryHasInstance is guaranteed to return
    // a boolean.
    if (has_instance_field->IsJSFunction()) {
      compiler::SharedFunctionInfoRef shared =
          has_instance_field->AsJSFunction().shared(broker());
      if (shared.HasBuiltinId() &&
          shared.builtin_id() == Builtin::kFunctionPrototypeHasInstance) {
        return BuildOrdinaryHasInstance(object, callable,
                                        callable_node_if_not_constant);
      }
    }

    // Call @@hasInstance
    CallArguments args(ConvertReceiverMode::kNotNullOrUndefined,
                       {callable_node, object});
    ValueNode* call_result;
    {
      // Make sure that a lazy deopt after the @@hasInstance call also performs
      // ToBoolean before returning to the interpreter.
      DeoptFrameScope continuation_scope(
          this, Builtin::kToBooleanLazyDeoptContinuation);

      if (has_instance_field->IsJSFunction()) {
        SaveCallSpeculationScope saved(this);
        GET_VALUE_OR_ABORT(
            call_result,
            ReduceCallForConstant(has_instance_field->AsJSFunction(), args));
      } else {
        call_result = BuildGenericCall(GetConstant(*has_instance_field),
                                       Call::TargetType::kAny, args);
      }
      // TODO(victorgomes): Propagate the case if we need to soft deopt.
    }

    return BuildToBoolean(call_result);
  }

  return ReduceResult::Fail();
}

template <bool flip>
ValueNode* MaglevGraphBuilder::BuildToBoolean(ValueNode* value) {
  if (IsConstantNode(value->opcode())) {
    return GetBooleanConstant(FromConstantToBool(local_isolate(), value) ^
                              flip);
  }

  switch (value->value_representation()) {
    case ValueRepresentation::kFloat64:
    case ValueRepresentation::kHoleyFloat64:
      // The ToBoolean of both the_hole and NaN is false, so we can use the
      // same operation for HoleyFloat64 and Float64.
      return AddNewNode<Float64ToBoolean>({value}, flip);

    case ValueRepresentation::kUint32:
      // Uint32 has the same logic as Int32 when converting ToBoolean, namely
      // comparison against zero, so we can cast it and ignore the signedness.
      value = AddNewNode<TruncateUint32ToInt32>({value});
      [[fallthrough]];
    case ValueRepresentation::kInt32:
      return AddNewNode<Int32ToBoolean>({value}, flip);

    case ValueRepresentation::kIntPtr:
      UNREACHABLE();

    case ValueRepresentation::kTagged:
      break;
  }

  NodeInfo* node_info = known_node_aspects().TryGetInfoFor(value);
  if (node_info) {
    if (ValueNode* as_int32 = node_info->alternative().int32()) {
      return AddNewNode<Int32ToBoolean>({as_int32}, flip);
    }
    if (ValueNode* as_float64 = node_info->alternative().float64()) {
      return AddNewNode<Float64ToBoolean>({as_float64}, flip);
    }
  }

  NodeType value_type;
  if (CheckType(value, NodeType::kJSReceiver, &value_type)) {
    ValueNode* result = BuildTestUndetectable(value);
    // TODO(victorgomes): Check if it is worth to create
    // TestUndetectableLogicalNot or to remove ToBooleanLogicalNot, since we
    // already optimize LogicalNots by swapping the branches.
    if constexpr (!flip) {
      result = BuildLogicalNot(result);
    }
    return result;
  }
  ValueNode* falsy_value = nullptr;
  if (CheckType(value, NodeType::kString)) {
    falsy_value = GetRootConstant(RootIndex::kempty_string);
  } else if (CheckType(value, NodeType::kSmi)) {
    falsy_value = GetSmiConstant(0);
  }
  if (falsy_value != nullptr) {
    return AddNewNode<std::conditional_t<flip, TaggedEqual, TaggedNotEqual>>(
        {value, falsy_value});
  }
  if (CheckType(value, NodeType::kBoolean)) {
    if constexpr (flip) {
      value = BuildLogicalNot(value);
    }
    return value;
  }
  return AddNewNode<std::conditional_t<flip, ToBooleanLogicalNot, ToBoolean>>(
      {value}, GetCheckType(value_type));
}

ReduceResult MaglevGraphBuilder::TryBuildFastInstanceOfWithFeedback(
    ValueNode* object, ValueNode* callable,
    compiler::FeedbackSource feedback_source) {
  compiler::ProcessedFeedback const& feedback =
      broker()->GetFeedbackForInstanceOf(feedback_source);

  if (feedback.IsInsufficient()) {
    return EmitUnconditionalDeopt(
        DeoptimizeReason::kInsufficientTypeFeedbackForInstanceOf);
  }

  // Check if the right hand side is a known receiver, or
  // we have feedback from the InstanceOfIC.
  compiler::OptionalHeapObjectRef maybe_constant;
  if ((maybe_constant = TryGetConstant(callable)) &&
      maybe_constant.value().IsJSObject()) {
    compiler::JSObjectRef callable_ref = maybe_constant.value().AsJSObject();
    return TryBuildFastInstanceOf(object, callable_ref, nullptr);
  }
  if (feedback_source.IsValid()) {
    compiler::OptionalJSObjectRef callable_from_feedback =
        feedback.AsInstanceOf().value();
    if (callable_from_feedback) {
      return TryBuildFastInstanceOf(object, *callable_from_feedback, callable);
    }
  }
  return ReduceResult::Fail();
}

void MaglevGraphBuilder::VisitTestInstanceOf() {
  // TestInstanceOf <src> <feedback_slot>
  ValueNode* object = LoadRegister(0);
  ValueNode* callable = GetAccumulator();
  FeedbackSlot slot = GetSlotOperand(1);
  compiler::FeedbackSource feedback_source{feedback(), slot};

  ReduceResult result =
      TryBuildFastInstanceOfWithFeedback(object, callable, feedback_source);
  PROCESS_AND_RETURN_IF_DONE(result, SetAccumulator);

  ValueNode* context = GetContext();
  SetAccumulator(
      AddNewNode<TestInstanceOf>({context, object, callable}, feedback_source));
}

void MaglevGraphBuilder::VisitTestIn() {
  // TestIn <src> <feedback_slot>
  ValueNode* object = GetAccumulator();
  ValueNode* name = LoadRegister(0);
  FeedbackSlot slot = GetSlotOperand(1);
  compiler::FeedbackSource feedback_source{feedback(), slot};

  // TODO(victorgomes): Create fast path using feedback.
  USE(feedback_source);

  SetAccumulator(BuildCallBuiltin<Builtin::kKeyedHasIC>(
      {GetTaggedValue(object), GetTaggedValue(name)}, feedback_source));
}

void MaglevGraphBuilder::VisitToName() {
  // ToObject <dst>
  if (!CheckType(GetAccumulator(), NodeType::kName)) {
    SetAccumulator(AddNewNode<ToName>({GetContext(), GetAccumulator()}));
  }
}

ValueNode* MaglevGraphBuilder::BuildToString(ValueNode* value,
                                             ToString::ConversionMode mode) {
  if (CheckType(value, NodeType::kString)) return value;
  // TODO(victorgomes): Add fast path for constant primitives.
  if (CheckType(value, NodeType::kNumber)) {
    // TODO(verwaest): Float64ToString if float.
    return AddNewNode<NumberToString>({value});
  }
  return AddNewNode<ToString>({GetContext(), value}, mode);
}

void MaglevGraphBuilder::BuildToNumberOrToNumeric(Object::Conversion mode) {
  ValueNode* value = GetAccumulator();
  switch (value->value_representation()) {
    case ValueRepresentation::kInt32:
    case ValueRepresentation::kUint32:
    case ValueRepresentation::kFloat64:
      return;

    case ValueRepresentation::kHoleyFloat64: {
      SetAccumulator(AddNewNode<HoleyFloat64ToMaybeNanFloat64>({value}));
      return;
    }

    case ValueRepresentation::kTagged:
      // We'll insert the required checks depending on the feedback.
      break;

    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
  }

  FeedbackSlot slot = GetSlotOperand(0);
  switch (broker()->GetFeedbackForBinaryOperation(
      compiler::FeedbackSource(feedback(), slot))) {
    case BinaryOperationHint::kSignedSmall:
      RETURN_VOID_IF_ABORT(BuildCheckSmi(value));
      break;
    case BinaryOperationHint::kSignedSmallInputs:
      UNREACHABLE();
    case BinaryOperationHint::kNumber:
    case BinaryOperationHint::kBigInt:
    case BinaryOperationHint::kBigInt64:
      if (mode == Object::Conversion::kToNumber &&
          EnsureType(value, NodeType::kNumber)) {
        return;
      }
      AddNewNode<CheckNumber>({value}, mode);
      break;
    case BinaryOperationHint::kNone:
    // TODO(leszeks): Faster ToNumber for kNumberOrOddball
    case BinaryOperationHint::kNumberOrOddball:
    case BinaryOperationHint::kString:
    case BinaryOperationHint::kStringOrStringWrapper:
    case BinaryOperationHint::kAny:
      if (CheckType(value, NodeType::kNumber)) return;
      SetAccumulator(AddNewNode<ToNumberOrNumeric>({value}, mode));
      break;
  }
}

void MaglevGraphBuilder::VisitToNumber() {
  BuildToNumberOrToNumeric(Object::Conversion::kToNumber);
}
void MaglevGraphBuilder::VisitToNumeric() {
  BuildToNumberOrToNumeric(Object::Conversion::kToNumeric);
}

void MaglevGraphBuilder::VisitToObject() {
  // ToObject <dst>
  ValueNode* value = GetAccumulator();
  interpreter::Reg
"""


```