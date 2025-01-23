Response:
The user wants a summary of the functionality of the `v8/src/maglev/maglev-graph-builder.cc` file, specifically focusing on the provided code snippet (part 14 of 18).

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core function:** The code snippet primarily deals with the `MaglevGraphBuilder` class and its methods for generating Maglev graph nodes. The key methods seem to be related to handling constructor calls (`TryReduceConstruct`, `BuildConstruct`, `VisitConstruct`), instanceof checks (`TryBuildFastInstanceOf`, `BuildOrdinaryHasInstance`, `VisitTestInstanceOf`), and type conversions (`BuildToBoolean`, `BuildToString`, `BuildToNumberOrToNumeric`).

2. **Analyze specific code blocks:**
    * **`TryReduceConstructArrayConstructor`:** This function attempts to optimize the construction of arrays. It checks for various scenarios like zero arguments, a single constant numeric argument, and uses allocation sites for optimization. It also handles cases where inlining is possible.
    * **`TryReduceConstructBuiltin`:**  Handles construction of built-in objects like `Array` and `Object`. The `Object` constructor optimization for zero arguments is notable.
    * **`TryReduceConstructGeneric`:** Deals with general constructor calls, including derived classes and allocation strategies. It shows the handling of implicit receivers and potential deoptimization points.
    * **`BuildConstruct`:**  This is the main entry point for handling `construct` bytecode. It uses feedback to optimize the construction process, potentially calling the specialized `TryReduceConstruct` functions.
    * **`VisitConstruct` and related `VisitConstructWithSpread`, `VisitConstructForwardAllArgs`:** These methods handle the different bytecode instructions related to constructor calls.
    * **`VisitTestEqual` family:** These are simple wrappers around a generic comparison function.
    * **`InferHasInPrototypeChain`:**  This function tries to statically determine if an object is in a given prototype chain. It uses known map information and dependencies.
    * **`TryBuildFastHasInPrototypeChain` and `BuildHasInPrototypeChain`:**  Functions to optimize the `in` operator by checking the prototype chain.
    * **`TryBuildFastOrdinaryHasInstance` and `BuildOrdinaryHasInstance`:**  Functions related to the `instanceof` operator, handling bound functions and prototype lookups.
    * **`TryBuildFastInstanceOf`:**  Further optimization for `instanceof` by checking for `@@hasInstance` method.
    * **`BuildToBoolean`:**  Handles the conversion of various types to boolean, with optimizations for constants and specific types.
    * **`TryBuildFastInstanceOfWithFeedback` and `VisitTestInstanceOf`:** Handle `instanceof` with feedback for optimization.
    * **`VisitTestIn`:** Handles the `in` operator, using `KeyedHasIC`.
    * **`VisitToName`:** Converts a value to a name (if it's not already).
    * **`BuildToString`:**  Converts a value to a string, with special handling for numbers.
    * **`BuildToNumberOrToNumeric` and related `VisitToNumber`, `VisitToNumeric`:** Handle the conversion of values to numbers.

3. **Identify key concepts and patterns:**
    * **Optimization through feedback:** The code heavily relies on type feedback to specialize and optimize operations.
    * **Inlining:**  The code attempts to inline common operations like constructor calls and property accesses.
    * **Deoptimization:** Mechanisms are in place to deoptimize when assumptions are violated.
    * **Handling different object types:** The code distinguishes between various JavaScript object types (arrays, functions, built-ins, etc.) for optimization.
    * **Prototype chain checks:**  Several functions focus on efficiently checking the prototype chain.
    * **Type conversions:**  Explicit type conversion functions are present.

4. **Connect to JavaScript functionality:** For each major function or concept, think about the corresponding JavaScript operation.
    * `TryReduceConstruct*`:  `new Array()`, `new Object()`, `new MyClass()`
    * `VisitTestInstanceOf`: `instanceof` operator
    * `BuildToBoolean`:  Implicit boolean conversions in `if` statements, logical operators, etc.
    * `BuildToString`:  String concatenation, `String()` constructor, `object.toString()`
    * `BuildToNumber`:  Arithmetic operations, `Number()` constructor

5. **Illustrate with JavaScript examples:** Create simple, clear JavaScript examples to demonstrate the functionality being discussed.

6. **Identify potential programming errors:** Think about common mistakes developers make related to the covered areas.
    * Incorrectly assuming array lengths.
    * Confusing `==` and `===`.
    * Misunderstanding how `instanceof` works with custom prototypes.
    * Not considering the implicit type coercion in JavaScript.

7. **Structure the answer:** Organize the information logically with clear headings and bullet points for readability.

8. **Address specific instructions:** Ensure all parts of the prompt are addressed, including the `.tq` check and the section number.

9. **Refine and review:** Read through the answer to ensure accuracy, clarity, and completeness. Check for any ambiguity or missing information. For instance, initially, I might focus too much on the C++ code. The review step would prompt me to emphasize the *JavaScript functionality* more directly. Also, explicitly state when a function might fail and what that implies in terms of fallback behavior.
`v8/src/maglev/maglev-graph-builder.cc` 是 V8 引擎中 Maglev 优化编译器的核心组件之一，负责将字节码（bytecode）转换为 Maglev 图（Maglev Graph）。Maglev 图是一种中间表示形式，更适合进行进一步的优化和代码生成。

**根据提供的代码片段，这个部分的主要功能集中在处理对象的构造函数调用 (`Construct`) 和类型检查 (`instanceof`, `in`)，以及一些类型转换操作。**

**功能归纳:**

1. **处理 `Array` 构造函数调用 (`TryReduceConstructArrayConstructor`):**
   - 尝试优化 `Array` 构造函数的调用，特别是针对常见的场景。
   - **零参数构造：** 创建一个空数组。
   - **单参数构造：**
     - 如果参数是数字常量，并且在合理范围内，则创建一个具有该长度的数组。
     - 如果参数是动态的，则根据分配站点的信息进行优化，例如内联分配。
     - 如果参数是负数或超出范围，则抛出 `RangeError`。
   - 依赖于分配站点（AllocationSite）的信息进行优化，例如内联调用和预分配。
   - 使用保护器（Protector）来判断是否可以进行某些投机优化。
   - **目前不支持双精度浮点数数组的优化。**
   - **目前不支持多参数的 `Array` 构造函数的优化。**

2. **处理其他内置构造函数调用 (`TryReduceConstructBuiltin`):**
   - 目前只特别处理了 `Object` 构造函数。
   - **零参数 `Object` 构造：** 可以直接内联为一个简单的对象分配。

3. **处理通用的构造函数调用 (`TryReduceConstructGeneric`):**
   - 对于派生类构造函数，会处理 `super()` 调用并检查返回结果。
   - 对于非派生类构造函数，可能会内联对象分配（如果构造函数具有初始 Map 且与自身相等）。
   - 如果不能内联分配，则会调用内置函数 `FastNewObject` 来创建对象。
   - 都会尝试调用构造函数本身，并检查其返回值是否为对象。

4. **主要的构造函数处理入口 (`BuildConstruct`):**
   - 接收构造函数的目标对象 (`target`)、`new.target` 和参数。
   - 利用类型反馈信息 (`FeedbackSource`) 来进行优化。
   - 如果有分配站点反馈，并且目标是 `Array` 构造函数，则调用 `TryReduceConstructArrayConstructor`。
   - 否则，尝试调用 `TryReduceConstruct` 来处理其他构造函数。
   - 如果所有优化都失败，则调用通用的 `BuildGenericConstruct`。

5. **处理 `construct` 相关的字节码指令 (`VisitConstruct`, `VisitConstructWithSpread`, `VisitConstructForwardAllArgs`):**
   - 从解释器帧中提取必要的信息（目标对象、参数、反馈槽）。
   - 调用 `BuildConstruct` 来构建构造函数调用的 Maglev 图节点。
   - `VisitConstructWithSpread` 处理带有展开运算符 (`...`) 的构造函数调用。
   - `VisitConstructForwardAllArgs` 处理转发所有参数的构造函数调用。

6. **处理比较操作 (`VisitTestEqual`, `VisitTestEqualStrict`, etc.):**
   - 这些函数是简单地调用通用的比较操作处理函数。

7. **处理 `instanceof` 操作 (`InferHasInPrototypeChain`, `TryBuildFastHasInPrototypeChain`, `BuildHasInPrototypeChain`, `TryBuildFastOrdinaryHasInstance`, `BuildOrdinaryHasInstance`, `TryBuildFastInstanceOf`, `TryBuildFastInstanceOfWithFeedback`, `VisitTestInstanceOf`):**
   - **`InferHasInPrototypeChain`:**  尝试静态推断一个对象是否在给定原型的原型链上。
   - **快速路径优化：** 尝试通过已知的类型信息和反馈信息来快速判断 `instanceof` 的结果，避免昂贵的运行时查找。
   - **普通路径：** 如果无法进行快速判断，则会生成调用内置函数 `OrdinaryHasInstance` 或 `HasInPrototypeChain` 的节点。
   - **处理 `@@hasInstance` 方法：** 如果对象具有 `@@hasInstance` 方法，则会尝试调用该方法。
   - **利用类型反馈：** `TryBuildFastInstanceOfWithFeedback` 使用 `InstanceOfIC` 的反馈信息来优化。

8. **处理 `in` 操作 (`VisitTestIn`):**
   - 调用内置函数 `KeyedHasIC` 来检查对象是否具有某个属性。

9. **类型转换操作 (`VisitToName`, `BuildToString`, `BuildToNumberOrToNumeric`, `VisitToNumber`, `VisitToNumeric`, `VisitToObject`):**
   - **`VisitToName`:** 将值转换为 Name 类型 (Symbol 或 String)。
   - **`BuildToString`:** 将值转换为字符串，针对数字类型有特殊优化。
   - **`BuildToNumberOrToNumeric`:** 将值转换为数字类型，根据反馈信息插入类型检查。
   - **`VisitToNumber` 和 `VisitToNumeric`:** 处理将值转换为 Number 或 Numeric 类型的字节码指令。
   - **`BuildToBoolean`:** 将值转换为布尔值，针对常量和特定类型有优化。

**如果 `v8/src/maglev/maglev-graph-builder.cc` 以 `.tq` 结尾，那它是个 v8 Torque 源代码。** 然而，根据你提供的文件名，它是 `.cc` 文件，所以是 C++ 源代码。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这个文件中的代码直接对应着 JavaScript 的语言特性，例如：

* **对象创建:** `new Array(10)`, `new Object()`, `new MyClass()`
* **类型检查:** `value instanceof Array`, `"length" in myArray`
* **类型转换:**
    ```javascript
    let num = 10;
    let str = String(num); // 对应 BuildToString
    let bool = Boolean(0); // 对应 BuildToBoolean
    let obj = {};
    let prim = 1;
    console.log(prim.toString()); // 间接涉及到 BuildToString
    ```

**代码逻辑推理 (假设输入与输出):**

**假设输入:**  `Array` 构造函数调用，参数为一个数字常量 `5`。

**`TryReduceConstructArrayConstructor` 的流程:**

1. `args.count() == 1` 为真。
2. `TryGetInt32Constant(args[0])` 返回 `std::optional<int>{5}`。
3. `GetArrayConstructorInitialMap` 获取初始 Map。
4. `*maybe_length >= 0 && *maybe_length < JSArray::kInitialMaxFastElementArray` 为真 (假设 5 小于最大值)。
5. `BuildElementsArray(5)` 创建一个可以容纳 5 个元素的数组的表示。
6. `BuildAndAllocateJSArray` 创建一个表示数组分配和初始化的 Maglev 图节点，其中长度为 5。

**输出:**  一个表示分配长度为 5 的快速数组的 Maglev 图节点。

**用户常见的编程错误:**

1. **误解 `Array` 构造函数的单参数行为:**
   ```javascript
   let arr1 = new Array(3); // 创建一个长度为 3 的空数组
   let arr2 = new Array("3"); // 创建一个包含一个字符串 "3" 的数组
   ```
   Maglev 需要处理这种参数类型差异。

2. **在 `instanceof` 中使用非构造函数:**
   ```javascript
   let obj = {};
   obj instanceof 10; // TypeError
   ```
   Maglev 可能会在早期尝试优化 `instanceof` 操作，需要处理这种错误情况。

3. **对 `null` 或 `undefined` 使用属性访问或 `in` 操作:**
   ```javascript
   let obj = null;
   "property" in obj; // TypeError
   ```
   Maglev 需要确保在进行这些操作之前进行必要的类型检查。

**总结（第 14 部分的功能）:**

这个代码片段主要负责 Maglev 编译器中处理对象构造函数调用、类型检查（特别是 `instanceof` 和 `in` 操作）以及基本的类型转换。它试图通过类型反馈和内联等技术来优化这些操作，提高 JavaScript 代码的执行效率。对于 `Array` 构造函数，有较为详细的优化逻辑，涵盖了常见的用法。对于其他构造函数和类型检查，也存在快速路径优化尝试。总的来说，这部分代码是 Maglev 编译器在构建执行图时处理对象创建和类型相关操作的关键组成部分。

### 提示词
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第14部分，共18部分，请归纳一下它的功能
```

### 源代码
```cpp
ents_kind();
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
```