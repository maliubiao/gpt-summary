Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/js-call-reducer.cc`. I need to analyze the code and provide a summary of its purpose within the V8 JavaScript engine's Turbofan compiler.

Here's a breakdown of the steps to address the user's request:

1. **Identify the file's role:** Based on the filename `js-call-reducer.cc`, it seems responsible for optimizing JavaScript call operations during the compilation process. The term "reducer" suggests it's involved in simplifying or transforming the call nodes in the intermediate representation (IR).

2. **Analyze the provided code blocks:**
    * The first block handles calls to function templates. It checks the receiver and signature, potentially converting the receiver to a JSReceiver. It uses different builtins (`CallFunctionTemplate_CheckCompatibleReceiver`, `CallFunctionTemplate_CheckAccess`, etc.) depending on the template's properties.
    * The second block deals with API calls associated with function templates. It checks for a C++ callback and generates either a fast API call or a slow call to the `CallApiCallback` builtin.
    * The third block contains helper functions like `IsSafeArgumentsElements`, `IsCallOrConstructWithArrayLike`, and `IsCallOrConstructWithSpread`, which are used to identify specific patterns in the IR related to call and construct operations with array-like objects or spread syntax.
    * The fourth block includes `ConvertHoleToUndefined`, a utility for handling potentially missing elements in sparse arrays.
    * The fifth block, `CheckIfConstructor`, ensures that `new` is used with a constructor. It inserts checks and handles potential exceptions.
    * The sixth block, starting with `ShouldUseCallICFeedback`, seems to determine if CallIC feedback (information gathered during runtime about call sites) can be used for optimization.
    * The seventh block, `CheckArrayLength`, generates code to verify that the length of an array hasn't changed.
    * The eighth block, `ReduceCallOrConstructWithArrayLikeOrSpreadOfCreateArguments`, handles optimization when `...arguments` or `apply` is used with the `arguments` object. It aims to directly insert the arguments into the call.
    * The ninth block, `ReduceCallOrConstructWithArrayLikeOrSpread`, is a more general handler for optimizing calls with array-like or spread arguments, including array literals.
    * The tenth block, `IsBuiltinOrApiFunction`, checks if a function is a builtin or has an associated API function.
    * The final block, `ReduceJSCall`, is the core function for optimizing regular JavaScript calls. It handles calls to known functions (including bound functions and closures) and uses feedback from CallIC to potentially specialize the call.

3. **Relate to JavaScript functionality:** The code directly relates to how JavaScript functions are called and constructed, including scenarios with `apply`, spread syntax, and the `arguments` object.

4. **Identify potential programming errors:** The `CheckIfConstructor` function directly addresses the common error of calling a non-constructor function with `new`.

5. **Consider the "part 6 of 12" context:** This suggests that `js-call-reducer.cc` is a significant part of the compiler's optimization pipeline, and this snippet likely represents a subset of its responsibilities.

6. **Formulate the summary:** Combine the above observations into a concise description of the code's functionality.
`v8/src/compiler/js-call-reducer.cc` 是 V8 Turbofan 编译器的一部分，它的主要功能是 **优化 JavaScript 函数调用 (JSCall) 和构造函数调用 (JSConstruct) 操作**。它通过分析调用点的上下文、目标函数的信息以及运行时反馈，尝试将这些调用操作替换为更高效的、特定的操作序列，从而提高代码的执行效率。

由于文件以 `.cc` 结尾，因此它是 **C++ 源代码**，而不是 Torque 源代码。

**以下是代码片段中涉及的具体功能和概念的详细解释：**

**1. 函数模板调用优化 (Function Template Calls):**

* 当调用的目标是一个函数模板时，这段代码会根据函数模板的属性（例如是否接受任意接收者、是否有签名）选择合适的内置函数来处理调用 (`Builtin::kCallFunctionTemplate_CheckCompatibleReceiver`, `Builtin::kCallFunctionTemplate_CheckAccess`, 等)。
* 它确保 `receiver` 被正确转换为 `JSReceiver`，如果需要的话。
* 它使用 `CallFunctionTemplate` 内置函数来执行调用，并更新 IR 节点的操作码和输入。

**JavaScript 示例:**

```javascript
function MyTemplate() {}
MyTemplate.prototype.foo = function() {};

let obj = {};
let instance = new MyTemplate();

// 调用函数模板，可能需要检查接收者是否兼容
MyTemplate.call(obj);
MyTemplate.call(instance);
```

**假设输入与输出:**

* **假设输入:** 一个表示 `MyTemplate.call(obj)` 的 JSCall IR 节点，其中 `MyTemplate` 是一个函数模板，`obj` 是接收者。
* **输出:**  该 JSCall 节点被修改为调用 `Builtin::kCallFunctionTemplate_CheckAccess`，并且 `receiver` 输入被转换为 `JSReceiver`。

**2. API 回调优化 (API Callback Optimization):**

* 如果函数模板关联了 C++ 代码（通过 `callback_data`），这段代码会尝试优化 API 调用。
* 它首先尝试使用快速 API 调用 (`FastApiCallFunction`)，如果目标地址存在，则生成一个快速调用的子图。
* 如果快速调用不可行，则会生成一个慢速调用，使用 `CallApiCallback` 内置函数。
* 它会创建内联 API 函数的帧状态 (`CreateInlinedApiFunctionFrameState`)。

**JavaScript 示例:**

```javascript
// 假设有一个通过 C++ API 创建的函数模板
function nativeFunction() {
  // 这里的代码实际上由 C++ 实现
}

nativeFunction();
```

**假设输入与输出:**

* **假设输入:** 一个表示 `nativeFunction()` 的 JSCall IR 节点，其中 `nativeFunction` 是一个与 C++ 回调关联的函数模板。
* **输出:** 该 JSCall 节点被修改为调用 `Builtin::kCallApiCallbackOptimized` 或 `Builtin::kCallApiCallbackOptimizedNoProfiling`，并包含必要的参数，例如函数引用和帧状态。

**3. 关于 `arguments` 对象的优化:**

* `IsSafeArgumentsElements` 函数检查 `arguments` 对象的元素是否被安全地访问（例如，仅通过 `LoadField` 或 `LoadElement`）。
* 代码会尝试优化使用 `...arguments` 或 `apply` 调用函数的情况，如果参数列表来源于 `JSCreateArguments` 节点，它可以直接将参数插入到调用中，避免创建临时的数组。

**JavaScript 示例:**

```javascript
function foo(a, b, c) {
  bar.apply(null, arguments); // 或者 bar(...arguments);
}

function bar(x, y, z) {
  console.log(x, y, z);
}

foo(1, 2, 3);
```

**假设输入与输出:**

* **假设输入:** 一个表示 `bar.apply(null, arguments)` 的 JSCallWithArrayLike IR 节点，其中 `arguments` 是一个 `JSCreateArguments` 节点。
* **输出:** 该 JSCallWithArrayLike 节点被转换为一个普通的 JSCall 节点，并将 `arguments` 对象中的元素作为独立的参数插入到调用中。

**4. 类型检查和去优化 (Type Checks and Deoptimization):**

* `CheckIfConstructor` 函数用于检查 `new` 操作符的目标是否是一个构造函数，如果不是，则抛出 `TypeError`。
* 代码中使用了 `CheckIf` 节点，用于在某些条件不满足时触发去优化，例如数组长度改变 (`DeoptimizeReason::kArrayLengthChanged`) 或调用目标错误 (`DeoptimizeReason::kWrongCallTarget`)。

**JavaScript 示例 (导致 `TypeError`):**

```javascript
function foo() {}
let obj = new foo(); // 合法

let notConstructor = {};
let error = new notConstructor(); // TypeError: notConstructor is not a constructor
```

**5. CallIC 反馈 (CallIC Feedback):**

* `ShouldUseCallICFeedback` 函数判断是否应该使用 CallIC (Inline Cache) 的运行时反馈信息来优化调用。
* 代码会根据 CallIC 的反馈信息，尝试将调用目标绑定到特定的函数或闭包，并进行相应的优化。

**6. 数组长度检查 (Array Length Check):**

* `CheckArrayLength` 函数用于生成代码来检查数组的长度是否与预期值一致，这在优化涉及到数组操作的调用时很有用。

**7. 对内置函数和 API 函数的识别 (Builtin and API Function Recognition):**

* `IsBuiltinOrApiFunction` 函数用于判断一个函数是否是 V8 的内置函数或者关联了 C++ API 函数。

**8. 常量目标调用优化 (Constant Target Call Optimization):**

* `ReduceJSCall` 函数会尝试优化调用目标是常量的情况，例如直接调用一个已知的函数或绑定函数。
* 对于绑定函数，它可以将绑定参数内联到调用中。
* 对于闭包，它可以根据闭包的 SharedFunctionInfo 进行优化。

**9. 对 `JSCallWithArrayLike` 和 `JSCallWithSpread` 的优化:**

* 代码尝试优化使用 `apply` 或 spread 语法调用函数的情况，特别是当 spread 的对象是数组字面量或 `arguments` 对象时，它可以将数组元素直接展开为函数参数。

**用户常见的编程错误:**

* **将非构造函数作为构造函数调用:**  `CheckIfConstructor` 函数处理这种情况。
  ```javascript
  function notAConstructor() {}
  new notAConstructor(); // TypeError
  ```
* **假设数组长度不变:** 在某些优化中，代码会假设数组的长度在特定操作之间不会改变，如果实际发生改变，会导致去优化。
  ```javascript
  function processArray(arr) {
    // 假设 arr.length 不变
    for (let i = 0; i < arr.length; i++) {
      // ...
    }
  }

  let myArray = [1, 2, 3];
  processArray(myArray);
  myArray.push(4); // 改变了数组长度，可能导致之前的优化失效
  processArray(myArray);
  ```

**归纳一下它的功能 (第 6 部分，共 12 部分):**

作为编译器优化管道的第 6 部分，这段代码主要负责 **针对 JavaScript 函数调用进行特定的优化**。它专注于以下几个方面：

* **处理函数模板的调用，** 确保接收者和参数的正确性，并选择合适的内置函数。
* **优化与 C++ API 关联的函数的调用，**  尝试快速调用或使用慢速调用机制。
* **优化使用 `arguments` 对象或 spread 语法进行的函数调用，**  尝试将参数直接内联到调用中。
* **执行必要的类型检查，** 例如确保 `new` 操作符的目标是构造函数，并在条件不满足时触发去优化。
* **利用 CallIC 的运行时反馈信息，**  将调用目标绑定到具体函数或闭包。
* **优化调用目标为常量的情况，** 包括直接调用已知函数、绑定函数和闭包。
* **优化使用数组字面量作为 `apply` 或 spread 参数的调用。**

总而言之，这段代码的核心目标是 **识别和转换低效的通用函数调用模式为更高效的、特定的操作序列**，从而提高 JavaScript 代码的执行速度。它涉及到对函数模板、API 调用、`arguments` 对象、spread 语法以及运行时反馈的精细处理和优化。

### 提示词
```
这是目录为v8/src/compiler/js-call-reducer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-call-reducer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
plate_info.accept_any_receiver()) {
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
      receiver = holder = effect = graph()->NewNode(
          simplified()->ConvertReceiver(p.convert_mode()), receiver,
          jsgraph()->ConstantNoHole(native_context(), broker()), global_proxy,
          effect, control);

      Callable callable = Builtins::CallableFor(isolate(), builtin_name);
      auto call_descriptor = Linkage::GetStubCallDescriptor(
          graph()->zone(), callable.descriptor(),
          argc + 1 /* implicit receiver */, CallDescriptor::kNeedsFrameState);
      node->RemoveInput(n.FeedbackVectorIndex());
      node->InsertInput(graph()->zone(), 0,
                        jsgraph()->HeapConstantNoHole(callable.code()));
      node->ReplaceInput(
          1, jsgraph()->ConstantNoHole(function_template_info, broker()));
      node->InsertInput(graph()->zone(), 2,
                        jsgraph()->Int32Constant(JSParameterCount(argc)));
      node->ReplaceInput(3, receiver);       // Update receiver input.
      node->ReplaceInput(6 + argc, effect);  // Update effect input.
      NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
      return Changed(node);
    }
  }

  // TODO(turbofan): Consider introducing a JSCallApiCallback operator for
  // this and lower it during JSGenericLowering, and unify this with the
  // JSNativeContextSpecialization::InlineApiCall method a bit.
  compiler::OptionalObjectRef maybe_callback_data =
      function_template_info.callback_data(broker());
  // Check if the function has an associated C++ code to execute.
  if (!maybe_callback_data.has_value()) {
    // TODO(ishell): consider generating "return undefined" for empty function
    // instead of failing.
    TRACE_BROKER_MISSING(broker(), "call code for function template info "
                                       << function_template_info);
    return NoChange();
  }

  // Handles overloaded functions.
  FastApiCallFunction c_function =
      GetFastApiCallTarget(broker(), function_template_info, argc);

  if (c_function.address) {
    FastApiCallReducerAssembler a(this, node, function_template_info,
                                  c_function, receiver, holder, shared, target,
                                  argc, effect);
    Node* fast_call_subgraph = a.ReduceFastApiCall();

    return Replace(fast_call_subgraph);
  }

  // Slow call

  bool no_profiling = broker()->dependencies()->DependOnNoProfilingProtector();
  Callable call_api_callback = Builtins::CallableFor(
      isolate(), no_profiling ? Builtin::kCallApiCallbackOptimizedNoProfiling
                              : Builtin::kCallApiCallbackOptimized);
  CallInterfaceDescriptor cid = call_api_callback.descriptor();
  auto call_descriptor =
      Linkage::GetStubCallDescriptor(graph()->zone(), cid, argc + 1 /*
     implicit receiver */, CallDescriptor::kNeedsFrameState);
  ApiFunction api_function(function_template_info.callback(broker()));
  ExternalReference function_reference = ExternalReference::Create(
      &api_function, ExternalReference::DIRECT_API_CALL);

  Node* continuation_frame_state = CreateInlinedApiFunctionFrameState(
      jsgraph(), shared, target, context, receiver, frame_state);

  node->RemoveInput(n.FeedbackVectorIndex());
  node->InsertInput(graph()->zone(), 0,
                    jsgraph()->HeapConstantNoHole(call_api_callback.code()));
  node->ReplaceInput(1, jsgraph()->ExternalConstant(function_reference));
  node->InsertInput(graph()->zone(), 2, jsgraph()->ConstantNoHole(argc));
  node->InsertInput(
      graph()->zone(), 3,
      jsgraph()->HeapConstantNoHole(function_template_info.object()));
  node->InsertInput(graph()->zone(), 4, holder);
  node->ReplaceInput(5, receiver);  // Update receiver input.
  // 6 + argc is context input.
  node->ReplaceInput(6 + argc + 1, continuation_frame_state);
  node->ReplaceInput(6 + argc + 2, effect);
  NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
  return Changed(node);
}

namespace {

// Check whether elements aren't mutated; we play it extremely safe here by
// explicitly checking that {node} is only used by {LoadField} or
// {LoadElement}.
bool IsSafeArgumentsElements(Node* node) {
  for (Edge const edge : node->use_edges()) {
    if (!NodeProperties::IsValueEdge(edge)) continue;
    if (edge.from()->opcode() != IrOpcode::kLoadField &&
        edge.from()->opcode() != IrOpcode::kLoadElement) {
      return false;
    }
  }
  return true;
}

#ifdef DEBUG
bool IsCallOrConstructWithArrayLike(Node* node) {
  return node->opcode() == IrOpcode::kJSCallWithArrayLike ||
         node->opcode() == IrOpcode::kJSConstructWithArrayLike;
}
#endif

bool IsCallOrConstructWithSpread(Node* node) {
  return node->opcode() == IrOpcode::kJSCallWithSpread ||
         node->opcode() == IrOpcode::kJSConstructWithSpread;
}

bool IsCallWithArrayLikeOrSpread(Node* node) {
  return node->opcode() == IrOpcode::kJSCallWithArrayLike ||
         node->opcode() == IrOpcode::kJSCallWithSpread;
}

}  // namespace

Node* JSCallReducer::ConvertHoleToUndefined(Node* value, ElementsKind kind) {
  DCHECK(IsHoleyElementsKind(kind));
  if (kind == HOLEY_DOUBLE_ELEMENTS) {
    return graph()->NewNode(simplified()->ChangeFloat64HoleToTagged(), value);
  }
  return graph()->NewNode(simplified()->ConvertTaggedHoleToUndefined(), value);
}

void JSCallReducer::CheckIfConstructor(Node* construct) {
  JSConstructNode n(construct);
  Node* new_target = n.new_target();
  Control control = n.control();

  Node* check =
      graph()->NewNode(simplified()->ObjectIsConstructor(), new_target);
  Node* check_branch =
      graph()->NewNode(common()->Branch(BranchHint::kTrue), check, control);
  Node* check_fail = graph()->NewNode(common()->IfFalse(), check_branch);
  Node* check_throw = check_fail = graph()->NewNode(
      javascript()->CallRuntime(Runtime::kThrowTypeError, 2),
      jsgraph()->ConstantNoHole(
          static_cast<int>(MessageTemplate::kNotConstructor)),
      new_target, n.context(), n.frame_state(), n.effect(), check_fail);
  control = graph()->NewNode(common()->IfTrue(), check_branch);
  NodeProperties::ReplaceControlInput(construct, control);

  // Rewire potential exception edges.
  Node* on_exception = nullptr;
  if (NodeProperties::IsExceptionalCall(construct, &on_exception)) {
    // Create appropriate {IfException}  and {IfSuccess} nodes.
    Node* if_exception =
        graph()->NewNode(common()->IfException(), check_throw, check_fail);
    check_fail = graph()->NewNode(common()->IfSuccess(), check_fail);

    // Join the exception edges.
    Node* merge =
        graph()->NewNode(common()->Merge(2), if_exception, on_exception);
    Node* ephi = graph()->NewNode(common()->EffectPhi(2), if_exception,
                                  on_exception, merge);
    Node* phi =
        graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                         if_exception, on_exception, merge);
    ReplaceWithValue(on_exception, phi, ephi, merge);
    merge->ReplaceInput(1, on_exception);
    ephi->ReplaceInput(1, on_exception);
    phi->ReplaceInput(1, on_exception);
  }

  // The above %ThrowTypeError runtime call is an unconditional throw,
  // making it impossible to return a successful completion in this case. We
  // simply connect the successful completion to the graph end.
  Node* throw_node =
      graph()->NewNode(common()->Throw(), check_throw, check_fail);
  MergeControlToEnd(graph(), common(), throw_node);
}

namespace {

bool ShouldUseCallICFeedback(Node* node) {
  HeapObjectMatcher m(node);
  if (m.HasResolvedValue() || m.IsCheckClosure() || m.IsJSCreateClosure()) {
    // Don't use CallIC feedback when we know the function
    // being called, i.e. either know the closure itself or
    // at least the SharedFunctionInfo.
    return false;
  } else if (m.IsPhi()) {
    // Protect against endless loops here.
    Node* control = NodeProperties::GetControlInput(node);
    if (control->opcode() == IrOpcode::kLoop ||
        control->opcode() == IrOpcode::kDead)
      return false;
    // Check if {node} is a Phi of nodes which shouldn't
    // use CallIC feedback (not looking through loops).
    int const value_input_count = m.node()->op()->ValueInputCount();
    for (int n = 0; n < value_input_count; ++n) {
      if (ShouldUseCallICFeedback(node->InputAt(n))) return true;
    }
    return false;
  }
  return true;
}

}  // namespace

Node* JSCallReducer::CheckArrayLength(Node* array, ElementsKind elements_kind,
                                      uint32_t array_length,
                                      const FeedbackSource& feedback_source,
                                      Effect effect, Control control) {
  Node* length = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSArrayLength(elements_kind)),
      array, effect, control);
  Node* check = graph()->NewNode(simplified()->NumberEqual(), length,
                                 jsgraph()->ConstantNoHole(array_length));
  return graph()->NewNode(
      simplified()->CheckIf(DeoptimizeReason::kArrayLengthChanged,
                            feedback_source),
      check, effect, control);
}

Reduction
JSCallReducer::ReduceCallOrConstructWithArrayLikeOrSpreadOfCreateArguments(
    Node* node, Node* arguments_list, int arraylike_or_spread_index,
    CallFrequency const& frequency, FeedbackSource const& feedback,
    SpeculationMode speculation_mode, CallFeedbackRelation feedback_relation) {
  DCHECK_EQ(arguments_list->opcode(), IrOpcode::kJSCreateArguments);

  // Check if {node} is the only value user of {arguments_list} (except for
  // value uses in frame states). If not, we give up for now.
  for (Edge edge : arguments_list->use_edges()) {
    if (!NodeProperties::IsValueEdge(edge)) continue;
    Node* const user = edge.from();
    switch (user->opcode()) {
      case IrOpcode::kCheckMaps:
      case IrOpcode::kFrameState:
      case IrOpcode::kStateValues:
      case IrOpcode::kReferenceEqual:
      case IrOpcode::kReturn:
        // Ignore safe uses that definitely don't mess with the arguments.
        continue;
      case IrOpcode::kLoadField: {
        DCHECK_EQ(arguments_list, user->InputAt(0));
        FieldAccess const& access = FieldAccessOf(user->op());
        if (access.offset == JSArray::kLengthOffset) {
          // Ignore uses for arguments#length.
          static_assert(
              static_cast<int>(JSArray::kLengthOffset) ==
              static_cast<int>(JSStrictArgumentsObject::kLengthOffset));
          static_assert(
              static_cast<int>(JSArray::kLengthOffset) ==
              static_cast<int>(JSSloppyArgumentsObject::kLengthOffset));
          continue;
        } else if (access.offset == JSObject::kElementsOffset) {
          // Ignore safe uses for arguments#elements.
          if (IsSafeArgumentsElements(user)) continue;
        }
        break;
      }
      case IrOpcode::kJSCallWithArrayLike: {
        // Ignore uses as argumentsList input to calls with array like.
        JSCallWithArrayLikeNode n(user);
        if (edge.index() == n.ArgumentIndex(0)) continue;
        break;
      }
      case IrOpcode::kJSConstructWithArrayLike: {
        // Ignore uses as argumentsList input to calls with array like.
        JSConstructWithArrayLikeNode n(user);
        if (edge.index() == n.ArgumentIndex(0)) continue;
        break;
      }
      case IrOpcode::kJSCallWithSpread: {
        // Ignore uses as spread input to calls with spread.
        JSCallWithSpreadNode n(user);
        if (edge.index() == n.LastArgumentIndex()) continue;
        break;
      }
      case IrOpcode::kJSConstructWithSpread: {
        // Ignore uses as spread input to construct with spread.
        JSConstructWithSpreadNode n(user);
        if (edge.index() == n.LastArgumentIndex()) continue;
        break;
      }
      default:
        break;
    }
    // We cannot currently reduce the {node} to something better than what
    // it already is, but we might be able to do something about the {node}
    // later, so put it on the waitlist and try again during finalization.
    waitlist_.insert(node);
    return NoChange();
  }

  // Get to the actual frame state from which to extract the arguments;
  // we can only optimize this in case the {node} was already inlined into
  // some other function (and same for the {arguments_list}).
  CreateArgumentsType const type = CreateArgumentsTypeOf(arguments_list->op());
  FrameState frame_state =
      FrameState{NodeProperties::GetFrameStateInput(arguments_list)};

  int formal_parameter_count;
  {
    Handle<SharedFunctionInfo> shared;
    if (!frame_state.frame_state_info().shared_info().ToHandle(&shared)) {
      return NoChange();
    }
    formal_parameter_count =
        MakeRef(broker(), shared)
            .internal_formal_parameter_count_without_receiver();
  }

  if (type == CreateArgumentsType::kMappedArguments) {
    // Mapped arguments (sloppy mode) that are aliased can only be handled
    // here if there's no side-effect between the {node} and the {arg_array}.
    // TODO(turbofan): Further relax this constraint.
    if (formal_parameter_count != 0) {
      Node* effect = NodeProperties::GetEffectInput(node);
      if (!NodeProperties::NoObservableSideEffectBetween(effect,
                                                         arguments_list)) {
        return NoChange();
      }
    }
  }

  // For call/construct with spread, we need to also install a code
  // dependency on the array iterator lookup protector cell to ensure
  // that no one messed with the %ArrayIteratorPrototype%.next method.
  if (IsCallOrConstructWithSpread(node)) {
    if (!dependencies()->DependOnArrayIteratorProtector()) return NoChange();
  }

  // Remove the {arguments_list} input from the {node}.
  node->RemoveInput(arraylike_or_spread_index);

  // The index of the first relevant parameter. Only non-zero when looking at
  // rest parameters, in which case it is set to the index of the first rest
  // parameter.
  const int start_index = (type == CreateArgumentsType::kRestParameter)
                              ? formal_parameter_count
                              : 0;

  // After removing the arraylike or spread object, the argument count is:
  int argc =
      arraylike_or_spread_index - JSCallOrConstructNode::FirstArgumentIndex();
  // Check if are spreading to inlined arguments or to the arguments of
  // the outermost function.
  if (frame_state.outer_frame_state()->opcode() != IrOpcode::kFrameState) {
    Operator const* op;
    if (IsCallWithArrayLikeOrSpread(node)) {
      static constexpr int kTargetAndReceiver = 2;
      op = javascript()->CallForwardVarargs(argc + kTargetAndReceiver,
                                            start_index);
    } else {
      static constexpr int kTargetAndNewTarget = 2;
      op = javascript()->ConstructForwardVarargs(argc + kTargetAndNewTarget,
                                                 start_index);
    }
    node->RemoveInput(JSCallOrConstructNode::FeedbackVectorIndexForArgc(argc));
    NodeProperties::ChangeOp(node, op);
    return Changed(node);
  }
  // Get to the actual frame state from which to extract the arguments;
  // we can only optimize this in case the {node} was already inlined into
  // some other function (and same for the {arg_array}).
  FrameState outer_state{frame_state.outer_frame_state()};
  FrameStateInfo outer_info = outer_state.frame_state_info();
  if (outer_info.type() == FrameStateType::kInlinedExtraArguments) {
    // Need to take the parameters from the inlined extra arguments frame state.
    frame_state = outer_state;
  }
  // Add the actual parameters to the {node}, skipping the receiver.
  StateValuesAccess parameters_access(frame_state.parameters());
  for (auto it = parameters_access.begin_without_receiver_and_skip(start_index);
       !it.done(); ++it) {
    DCHECK_NOT_NULL(it.node());
    node->InsertInput(graph()->zone(),
                      JSCallOrConstructNode::ArgumentIndex(argc++), it.node());
  }

  if (IsCallWithArrayLikeOrSpread(node)) {
    NodeProperties::ChangeOp(
        node, javascript()->Call(JSCallNode::ArityForArgc(argc), frequency,
                                 feedback, ConvertReceiverMode::kAny,
                                 speculation_mode, feedback_relation));
    return Changed(node).FollowedBy(ReduceJSCall(node));
  } else {
    NodeProperties::ChangeOp(
        node, javascript()->Construct(JSConstructNode::ArityForArgc(argc),
                                      frequency, feedback));

    // Check whether the given new target value is a constructor function. The
    // replacement {JSConstruct} operator only checks the passed target value
    // but relies on the new target value to be implicitly valid.
    CheckIfConstructor(node);
    return Changed(node).FollowedBy(ReduceJSConstruct(node));
  }
}

Reduction JSCallReducer::ReduceCallOrConstructWithArrayLikeOrSpread(
    Node* node, int argument_count, int arraylike_or_spread_index,
    CallFrequency const& frequency, FeedbackSource const& feedback_source,
    SpeculationMode speculation_mode, CallFeedbackRelation feedback_relation,
    Node* target, Effect effect, Control control) {
  DCHECK(IsCallOrConstructWithArrayLike(node) ||
         IsCallOrConstructWithSpread(node));
  DCHECK_IMPLIES(speculation_mode == SpeculationMode::kAllowSpeculation,
                 feedback_source.IsValid());

  Node* arguments_list =
      NodeProperties::GetValueInput(node, arraylike_or_spread_index);

  if (arguments_list->opcode() == IrOpcode::kJSCreateArguments) {
    return ReduceCallOrConstructWithArrayLikeOrSpreadOfCreateArguments(
        node, arguments_list, arraylike_or_spread_index, frequency,
        feedback_source, speculation_mode, feedback_relation);
  }

  if (!v8_flags.turbo_optimize_apply) return NoChange();

  // Optimization of construct nodes not supported yet.
  if (!IsCallWithArrayLikeOrSpread(node)) return NoChange();

  // Avoid deoptimization loops.
  if (speculation_mode != SpeculationMode::kAllowSpeculation) return NoChange();

  // Only optimize with array literals.
  if (arguments_list->opcode() != IrOpcode::kJSCreateLiteralArray &&
      arguments_list->opcode() != IrOpcode::kJSCreateEmptyLiteralArray) {
    return NoChange();
  }

  // For call/construct with spread, we need to also install a code
  // dependency on the array iterator lookup protector cell to ensure
  // that no one messed with the %ArrayIteratorPrototype%.next method.
  if (IsCallOrConstructWithSpread(node)) {
    if (!dependencies()->DependOnArrayIteratorProtector()) return NoChange();
  }

  if (arguments_list->opcode() == IrOpcode::kJSCreateEmptyLiteralArray) {
    if (generated_calls_with_array_like_or_spread_.count(node)) {
      return NoChange();  // Avoid infinite recursion.
    }
    JSCallReducerAssembler a(this, node);
    Node* subgraph = a.ReduceJSCallWithArrayLikeOrSpreadOfEmpty(
        &generated_calls_with_array_like_or_spread_);
    return ReplaceWithSubgraph(&a, subgraph);
  }

  DCHECK_EQ(arguments_list->opcode(), IrOpcode::kJSCreateLiteralArray);
  int new_argument_count;

  // Find array length and elements' kind from the feedback's allocation
  // site's boilerplate JSArray.
  JSCreateLiteralOpNode args_node(arguments_list);
  CreateLiteralParameters const& args_params = args_node.Parameters();
  const FeedbackSource& array_feedback = args_params.feedback();
  const ProcessedFeedback& feedback =
      broker()->GetFeedbackForArrayOrObjectLiteral(array_feedback);
  if (feedback.IsInsufficient()) return NoChange();

  AllocationSiteRef site = feedback.AsLiteral().value();
  if (!site.boilerplate(broker()).has_value()) return NoChange();

  JSArrayRef boilerplate_array = site.boilerplate(broker())->AsJSArray();
  int const array_length =
      boilerplate_array.GetBoilerplateLength(broker()).AsSmi();

  // We'll replace the arguments_list input with {array_length} element loads.
  new_argument_count = argument_count - 1 + array_length;

  // Do not optimize calls with a large number of arguments.
  // Arbitrarily sets the limit to 32 arguments.
  const int kMaxArityForOptimizedFunctionApply = 32;
  if (new_argument_count > kMaxArityForOptimizedFunctionApply) {
    return NoChange();
  }

  // Determine the array's map.
  MapRef array_map = boilerplate_array.map(broker());
  if (!array_map.supports_fast_array_iteration(broker())) {
    return NoChange();
  }

  // Check and depend on NoElementsProtector.
  if (!dependencies()->DependOnNoElementsProtector()) {
    return NoChange();
  }

  // Remove the {arguments_list} node which will be replaced by a sequence of
  // LoadElement nodes.
  node->RemoveInput(arraylike_or_spread_index);

  // Speculate on that array's map is still equal to the dynamic map of
  // arguments_list; generate a map check.
  effect = graph()->NewNode(
      simplified()->CheckMaps(CheckMapsFlag::kNone, ZoneRefSet<Map>(array_map),
                              feedback_source),
      arguments_list, effect, control);

  // Speculate on that array's length being equal to the dynamic length of
  // arguments_list; generate a deopt check.
  ElementsKind elements_kind = array_map.elements_kind();
  effect = CheckArrayLength(arguments_list, elements_kind, array_length,
                            feedback_source, effect, control);

  // Generate N element loads to replace the {arguments_list} node with a set
  // of arguments loaded from it.
  Node* elements = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSObjectElements()),
      arguments_list, effect, control);
  for (int i = 0; i < array_length; i++) {
    // Load the i-th element from the array.
    Node* index = jsgraph()->ConstantNoHole(i);
    Node* load = effect = graph()->NewNode(
        simplified()->LoadElement(
            AccessBuilder::ForFixedArrayElement(elements_kind)),
        elements, index, effect, control);

    // In "holey" arrays some arguments might be missing and we pass
    // 'undefined' instead.
    if (IsHoleyElementsKind(elements_kind)) {
      load = ConvertHoleToUndefined(load, elements_kind);
    }

    node->InsertInput(graph()->zone(), arraylike_or_spread_index + i, load);
  }

  NodeProperties::ChangeOp(
      node,
      javascript()->Call(JSCallNode::ArityForArgc(new_argument_count),
                         frequency, feedback_source, ConvertReceiverMode::kAny,
                         speculation_mode, CallFeedbackRelation::kUnrelated));
  NodeProperties::ReplaceEffectInput(node, effect);
  return Changed(node).FollowedBy(ReduceJSCall(node));
}

bool JSCallReducer::IsBuiltinOrApiFunction(JSFunctionRef function) const {
  // TODO(neis): Add a way to check if function template info isn't serialized
  // and add a warning in such cases. Currently we can't tell if function
  // template info doesn't exist or wasn't serialized.
  return function.shared(broker()).HasBuiltinId() ||
         function.shared(broker()).function_template_info(broker()).has_value();
}

Reduction JSCallReducer::ReduceJSCall(Node* node) {
  if (broker()->StackHasOverflowed()) return NoChange();

  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  Node* target = n.target();
  Effect effect = n.effect();
  Control control = n.control();
  int arity = p.arity_without_implicit_args();

  // Try to specialize JSCall {node}s with constant {target}s.
  HeapObjectMatcher m(target);
  if (m.HasResolvedValue()) {
    ObjectRef target_ref = m.Ref(broker());
    if (target_ref.IsJSFunction()) {
      JSFunctionRef function = target_ref.AsJSFunction();

      // Don't inline cross native context.
      if (!function.native_context(broker()).equals(native_context())) {
        return NoChange();
      }

      return ReduceJSCall(node, function.shared(broker()));
    } else if (target_ref.IsJSBoundFunction()) {
      JSBoundFunctionRef function = target_ref.AsJSBoundFunction();
      ObjectRef bound_this = function.bound_this(broker());
      ConvertReceiverMode const convert_mode =
          bound_this.IsNullOrUndefined()
              ? ConvertReceiverMode::kNullOrUndefined
              : ConvertReceiverMode::kNotNullOrUndefined;

      // TODO(jgruber): Inline this block below once TryGet is guaranteed to
      // succeed.
      FixedArrayRef bound_arguments = function.bound_arguments(broker());
      const uint32_t bound_arguments_length = bound_arguments.length();
      static constexpr int kInlineSize = 16;  // Arbitrary.
      base::SmallVector<Node*, kInlineSize> args;
      for (uint32_t i = 0; i < bound_arguments_length; ++i) {
        OptionalObjectRef maybe_arg = bound_arguments.TryGet(broker(), i);
        if (!maybe_arg.has_value()) {
          TRACE_BROKER_MISSING(broker(), "bound argument");
          return NoChange();
        }
        args.emplace_back(
            jsgraph()->ConstantNoHole(maybe_arg.value(), broker()));
      }

      // Patch {node} to use [[BoundTargetFunction]] and [[BoundThis]].
      NodeProperties::ReplaceValueInput(
          node,
          jsgraph()->ConstantNoHole(function.bound_target_function(broker()),
                                    broker()),
          JSCallNode::TargetIndex());
      NodeProperties::ReplaceValueInput(
          node, jsgraph()->ConstantNoHole(bound_this, broker()),
          JSCallNode::ReceiverIndex());

      // Insert the [[BoundArguments]] for {node}.
      for (uint32_t i = 0; i < bound_arguments_length; ++i) {
        node->InsertInput(graph()->zone(), i + 2, args[i]);
        arity++;
      }

      NodeProperties::ChangeOp(
          node,
          javascript()->Call(JSCallNode::ArityForArgc(arity), p.frequency(),
                             p.feedback(), convert_mode, p.speculation_mode(),
                             CallFeedbackRelation::kUnrelated));

      // Try to further reduce the JSCall {node}.
      return Changed(node).FollowedBy(ReduceJSCall(node));
    }

    // Don't mess with other {node}s that have a constant {target}.
    // TODO(bmeurer): Also support proxies here.
    return NoChange();
  }

  // If {target} is the result of a JSCreateClosure operation, we can
  // just immediately try to inline based on the SharedFunctionInfo,
  // since TurboFan generally doesn't inline cross-context, and hence
  // the {target} must have the same native context as the call site.
  // Same if the {target} is the result of a CheckClosure operation.
  if (target->opcode() == IrOpcode::kJSCreateClosure) {
    CreateClosureParameters const& params =
        JSCreateClosureNode{target}.Parameters();
    return ReduceJSCall(node, params.shared_info());
  } else if (target->opcode() == IrOpcode::kCheckClosure) {
    FeedbackCellRef cell = MakeRef(broker(), FeedbackCellOf(target->op()));
    OptionalSharedFunctionInfoRef shared = cell.shared_function_info(broker());
    if (!shared.has_value()) {
      TRACE_BROKER_MISSING(broker(), "Unable to reduce JSCall. FeedbackCell "
                                         << cell << " has no FeedbackVector");
      return NoChange();
    }
    return ReduceJSCall(node, *shared);
  }

  // If {target} is the result of a JSCreateBoundFunction operation,
  // we can just fold the construction and call the bound target
  // function directly instead.
  if (target->opcode() == IrOpcode::kJSCreateBoundFunction) {
    Node* bound_target_function = NodeProperties::GetValueInput(target, 0);
    Node* bound_this = NodeProperties::GetValueInput(target, 1);
    uint32_t const bound_arguments_length =
        static_cast<int>(CreateBoundFunctionParametersOf(target->op()).arity());

    // Patch the {node} to use [[BoundTargetFunction]] and [[BoundThis]].
    NodeProperties::ReplaceValueInput(node, bound_target_function,
                                      n.TargetIndex());
    NodeProperties::ReplaceValueInput(node, bound_this, n.ReceiverIndex());

    // Insert the [[BoundArguments]] for {node}.
    for (uint32_t i = 0; i < bound_arguments_length; ++i) {
      Node* value = NodeProperties::GetValueInput(target, 2 + i);
      node->InsertInput(graph()->zone(), n.ArgumentIndex(i), value);
      arity++;
    }

    // Update the JSCall operator on {node}.
    ConvertReceiverMode const convert_mode =
        NodeProperties::CanBeNullOrUndefined(broker(), bound_this, effect)
            ? ConvertReceiverMode::kAny
            : ConvertReceiverMode::kNotNullOrUndefined;
    NodeProperties::ChangeOp(
        node,
        javascript()->Call(JSCallNode::ArityForArgc(arity), p.frequency(),
                           p.feedback(), convert_mode, p.speculation_mode(),
                           CallFeedbackRelation::kUnrelated));

    // Try to further reduce the JSCall {node}.
    return Changed(node).FollowedBy(ReduceJSCall(node));
  }

  if (!ShouldUseCallICFeedback(target) ||
      p.feedback_relation() == CallFeedbackRelation::kUnrelated ||
      !p.feedback().IsValid()) {
    return NoChange();
  }

  ProcessedFeedback const& feedback =
      broker()->GetFeedbackForCall(p.feedback());
  if (feedback.IsInsufficient()) {
    return ReduceForInsufficientFeedback(
        node, DeoptimizeReason::kInsufficientTypeFeedbackForCall);
  }

  OptionalHeapObjectRef feedback_target;
  if (p.feedback_relation() == CallFeedbackRelation::kTarget) {
    feedback_target = feedback.AsCall().target();
  } else {
    DCHECK_EQ(p.feedback_relation(), CallFeedbackRelation::kReceiver);
    feedback_target = native_context().function_prototype_apply(broker());
  }

  if (feedback_target.has_value() &&
      feedback_target->map(broker()).is_callable()) {
    Node* target_function =
        jsgraph()->ConstantNoHole(*feedback_target, broker());

    // Check that the {target} is still the {target_function}.
    Node* check = graph()->NewNode(simplified()->ReferenceEqual(), target,
                                   target_function);
    effect = graph()->NewNode(
        simplified()->CheckIf(DeoptimizeReason::kWrongCallTarget), check,
        effect, control);

    // Specialize the JSCall node to the {target_function}.
    NodeProperties::ReplaceValueInput(node, target_function, n.TargetIndex());
    NodeProperties::ReplaceEffectInput(node, effect);

    // Try to further reduce the JSCall {node}.
    return Changed(node).FollowedBy(ReduceJSCall(node));
  } else if (feedback_target.has_value() && feedback_target->IsFeedbackCell()) {
    FeedbackCellRef feedback_cell = feedback_target.value().AsFeedbackCell();
    // TODO(neis): This check seems unnecessary.
    if (feedback_cell.feedback_vector(broker()).has_value()) {
      // Check that {target} is a closure with given {feedback_cell},
      // which uniquely identifies a given function inside a native context.
      Node* target_closure = effect =
          graph()->NewNode(simplified()->CheckClosure(feedback_cell.object()),
                           target, effect, control);

      // Specialize the JSCall node to the {target_closure}.
      NodeProperties::ReplaceValueInput(node, target_closure, n.TargetIndex());
      NodeProperties::ReplaceEffectInput(node, effect);

      // Try to further reduce the JSCall {node}.
      return Changed(node).FollowedBy(ReduceJSCall(node));
    }
  }
  return NoChange();
}

Reduction JSCallReducer::ReduceJSCall(Node* node,
                                      SharedFunctionInfoRef shared) {
  JSCallNode n(node);
  Node* target = n.target();

  // Do not reduce calls to functions with break points.
  // If this state changes during background compilation, the compilation
  // job will be aborted from the main thread (see
  // Debug::PrepareFunctionForDebugExecution()).
  if (shared.HasBreakInfo(broker())) return NoChange();

  // Class constructors are callable, but [[Call]] will raise an exception.
  // See ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList ).
  if (IsClassConstructor(shared.kind())) {
    NodeProperties::ReplaceValueInputs(node, target);
    NodeProperties::ChangeOp(
        node, javascript()->CallRuntime(
                  Runtime::kThrowConstructorNonCallableError, 1));
    return Changed(node);
  }
```