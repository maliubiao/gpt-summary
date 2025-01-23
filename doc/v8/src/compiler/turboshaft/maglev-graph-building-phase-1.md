Response: The user wants to understand the functionality of the C++ code in `v8/src/compiler/turboshaft/maglev-graph-building-phase.cc`. This is the second part of a five-part code snippet.

The core task of this file is to translate Maglev nodes (an intermediate representation of JavaScript code) into Turboshaft nodes (another lower-level IR used in V8's compiler). This involves generating machine code instructions or abstractions of them.

Here's a breakdown of the code and its relation to JavaScript:

1. **Processing Maglev Nodes:** The code defines `Process` methods for various `maglev::` node types. Each `Process` method handles the translation of a specific Maglev operation.

2. **Generating Turboshaft Operations:**  Inside the `Process` methods, the code uses the `__` object (likely an instance of a class providing an interface to the Turboshaft builder) to generate Turboshaft operations. These operations represent low-level actions like calling built-in functions, loading/storing data, performing checks, etc.

3. **JavaScript Semantics:** Many of the `Process` methods directly correspond to JavaScript language features and built-in functions. For example:
    - `maglev::CallBuiltin` and `maglev::CallRuntime` handle calling JavaScript functions (built-in or user-defined).
    - `maglev::ThrowReferenceErrorIfHole`, `maglev::ThrowIfNotSuperConstructor`, etc., handle JavaScript's error handling and constructor behavior.
    - `maglev::CreateFunctionContext`, `maglev::FastCreateClosure`, `maglev::CreateClosure` handle the creation of function scopes and closures.
    - `maglev::CallWithArrayLike`, `maglev::CallWithSpread`, `maglev::CallForwardVarargs` deal with different ways of calling functions with arguments.
    - `maglev::Construct`, `maglev::ConstructWithSpread` handle the `new` operator in JavaScript.
    - `maglev::SetKeyedGeneric`, `maglev::GetKeyedGeneric`, `maglev::SetNamedGeneric`, `maglev::LoadNamedGeneric`, etc., handle property access and modification.
    - `maglev::LoadGlobal`, `maglev::StoreGlobal` deal with accessing and modifying global variables.
    - `maglev::CreateShallowObjectLiteral`, `maglev::CreateShallowArrayLiteral`, `maglev::CreateObjectLiteral`, `maglev::CreateArrayLiteral` handle the creation of objects and arrays.
    - `maglev::TestInstanceOf` handles the `instanceof` operator.
    - `maglev::DeleteProperty` handles the `delete` operator.
    - `maglev::ToString`, `maglev::NumberToString` handle type conversions.
    - `maglev::ArgumentsLength`, `maglev::ArgumentsElements`, `maglev::RestLength` deal with function arguments.
    - `maglev::CheckSmi`, `maglev::CheckNumber`, `maglev::CheckHeapObject`, `maglev::CheckMaps`, etc., handle runtime type checks and optimizations.
    - `maglev::StringConcat`, `maglev::StringEqual`, `maglev::StringLength`, `maglev::StringAt` deal with string operations.

4. **Feedback and Optimization:**  Nodes like `maglev::CallBuiltin`, `maglev::GetKeyedGeneric`, and `maglev::SetKeyedGeneric` often involve feedback slots and vectors. These are mechanisms for collecting runtime information about the types and behavior of objects, which the compiler uses to optimize subsequent executions.

5. **Deoptimization:**  The `GET_FRAME_STATE_MAYBE_ABORT` macro and `__ DeoptimizeIf`/`__ DeoptimizeIfNot` operations are related to deoptimization. If runtime assumptions made by the compiler are violated (e.g., an object's type is not what was expected), the code deoptimizes, falling back to a less optimized version of the code.

**JavaScript Examples:**

Let's illustrate with the `Process(maglev::CallBuiltin* node, ...)` method:

This method handles calls to built-in JavaScript functions like `Math.abs`, `Array.push`, etc.

```javascript
// Example JavaScript code that might lead to a maglev::CallBuiltin node:
function myFunction(arr) {
  arr.push(5); // Calling the built-in Array.push method
  return Math.abs(-10); // Calling the built-in Math.abs method
}
```

When the V8 compiler processes this JavaScript code with Maglev, the call to `arr.push(5)` and `Math.abs(-10)` would be represented as `maglev::CallBuiltin` nodes. The `Process` method in the C++ code would then generate the corresponding Turboshaft instructions to perform these built-in function calls. This involves:

- Identifying the built-in function (`Builtin::kArrayPush`, `Builtin::kMathAbs`).
- Gathering the arguments (`arr`, `5` for `push`; `-10` for `abs`).
- Potentially including feedback information for optimization.
- Generating a `__ CallBuiltin` Turboshaft operation.

Similarly, the `Process(maglev::StringConcat* node, ...)` method handles string concatenation:

```javascript
// Example JavaScript code:
let str1 = "hello";
let str2 = " world";
let result = str1 + str2; // String concatenation
```

The `str1 + str2` operation would be represented by a `maglev::StringConcat` node. The corresponding `Process` method would generate Turboshaft instructions to perform the string concatenation using the `__ StringConcat` operation.

**In summary, this part of the `maglev-graph-building-phase.cc` file is responsible for translating high-level Maglev IR nodes, which represent JavaScript operations, into lower-level Turboshaft IR nodes, getting the V8 compiler closer to generating machine code.** The code handles a wide variety of JavaScript language features and built-in functions. The presence of feedback mechanisms and deoptimization logic highlights V8's dynamic optimization strategy.

这是 `v8/src/compiler/turboshaft/maglev-graph-building-phase.cc` 文件的第 2 部分，它主要负责将 **Maglev 图中的节点转换为 Turboshaft 图中的节点**。  简单来说，它将 Maglev 这一中间表示形式转换为更底层的、更接近机器码的 Turboshaft 表示形式。

**核心功能：**

- **处理 Maglev 节点：**  该部分代码包含了大量的 `Process` 函数，每个函数对应处理一种特定的 Maglev 节点类型 (例如 `maglev::CallBuiltin`, `maglev::CallRuntime`, `maglev::LoadNamedGeneric` 等)。
- **生成 Turboshaft 操作：**  在每个 `Process` 函数内部，代码会根据 Maglev 节点的语义，生成相应的 Turboshaft 操作。这些操作通常是对底层操作的抽象，例如函数调用、内存访问、类型检查等。
- **处理 JavaScript 语义：**  这些 `Process` 函数的实现逻辑紧密围绕着 JavaScript 的语言特性和内置函数的行为。例如，处理 `maglev::CallBuiltin` 节点时，会考虑内置函数的调用约定、参数传递方式以及可能的反馈信息。处理属性访问节点时，会考虑原型链查找、访问器属性等。
- **支持优化和去优化：** 代码中包含了对反馈信息（feedback slot, feedback vector）的处理，这些信息用于优化代码执行。同时，也包含了去优化 (deoptimization) 的逻辑，当运行时类型或假设与编译时的预测不符时，会触发去优化，回到更安全的执行路径。
- **处理异常和错误：**  代码中包含对可能抛出异常的操作的处理，例如 `ThrowingScope` 的使用，以及对特定错误情况的检查和处理，例如 `maglev::ThrowReferenceErrorIfHole`。

**与 JavaScript 功能的关系以及 JavaScript 示例：**

这个文件的核心作用是将高层次的 JavaScript 操作转换为可以在 V8 虚拟机上执行的低层次操作。  每一个 `Process` 函数都对应着一个或一组 JavaScript 的概念或操作。

**以下是一些 JavaScript 示例以及它们如何与这段代码相关联：**

1. **函数调用 (`maglev::CallBuiltin`, `maglev::CallRuntime`)：**

   ```javascript
   Math.abs(-5);  // 调用内置函数
   function myFunc(a, b) { return a + b; }
   myFunc(1, 2);   // 调用用户定义的函数
   ```

   当 Maglev 遇到这些函数调用时，会创建 `maglev::CallBuiltin` (对于内置函数) 或 `maglev::CallRuntime` (对于其他函数) 节点。 这部分代码的 `Process` 函数会将这些节点转换为 Turboshaft 的调用指令，并处理参数传递、返回值等。

2. **属性访问 (`maglev::GetKeyedGeneric`, `maglev::LoadNamedGeneric`)：**

   ```javascript
   const obj = { x: 10 };
   console.log(obj.x);   // 命名属性访问
   const arr = [1, 2, 3];
   console.log(arr[1]);  // 索引属性访问
   ```

   Maglev 会为属性访问生成 `maglev::GetKeyedGeneric` (索引属性) 或 `maglev::LoadNamedGeneric` (命名属性) 节点。 代码中的 `Process` 函数会生成 Turboshaft 指令来执行实际的内存读取操作，并可能利用反馈信息进行优化。

3. **对象和数组字面量 (`maglev::CreateShallowObjectLiteral`, `maglev::CreateShallowArrayLiteral`)：**

   ```javascript
   const obj = { a: 1, b: 2 };
   const arr = [1, 'hello', true];
   ```

   这些字面量的创建会对应 `maglev::CreateShallowObjectLiteral` 和 `maglev::CreateShallowArrayLiteral` 节点。  `Process` 函数会生成 Turboshaft 指令来分配内存并初始化对象或数组。

4. **类型检查 (`maglev::CheckSmi`, `maglev::CheckNumber`, `maglev::CheckMaps`)：**

   ```javascript
   function add(a, b) {
       if (typeof a === 'number' && typeof b === 'number') {
           return a + b;
       }
       return NaN;
   }
   ```

   V8 在执行过程中会进行类型检查以进行优化。 `maglev::CheckSmi`, `maglev::CheckNumber`, `maglev::CheckMaps` 等节点就代表了这些类型检查。 `Process` 函数会将这些节点转换为 Turboshaft 的条件分支或去优化指令。

5. **字符串操作 (`maglev::StringConcat`, `maglev::StringLength`)：**

   ```javascript
   const greeting = "Hello, " + "world!";
   console.log(greeting.length);
   ```

   字符串拼接和长度获取会对应 `maglev::StringConcat` 和 `maglev::StringLength` 节点。 `Process` 函数会生成相应的 Turboshaft 指令来执行这些字符串操作。

**总结：**

这部分代码是 V8 编译器 Maglev 到 Turboshaft 转换的关键环节。 它负责理解 Maglev 图中每个节点的含义，并将其翻译成更底层的、更适合机器执行的 Turboshaft 操作。  这直接关系到 JavaScript 代码的执行效率和性能。  通过处理各种 Maglev 节点，这段代码确保了 JavaScript 的语义在 Turboshaft 阶段得到正确的表达。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/maglev-graph-building-phase.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```
t_info());

    base::SmallVector<OpIndex, 16> arguments;
    for (int i = 0; i < node->InputCountWithoutContext(); i++) {
      arguments.push_back(Map(node->input(i)));
    }

    if (node->has_feedback()) {
      V<Any> feedback_slot;
      switch (node->slot_type()) {
        case maglev::CallBuiltin::kTaggedIndex:
          feedback_slot = __ TaggedIndexConstant(node->feedback().index());
          break;
        case maglev::CallBuiltin::kSmi:
          feedback_slot = __ WordPtrConstant(node->feedback().index());
          break;
      }
      arguments.push_back(feedback_slot);
      arguments.push_back(__ HeapConstant(node->feedback().vector));
    }

    auto descriptor = Builtins::CallInterfaceDescriptorFor(node->builtin());
    if (descriptor.HasContextParameter()) {
      arguments.push_back(Map(node->context_input()));
    }

    int stack_arg_count =
        node->InputCountWithoutContext() - node->InputsInRegisterCount();
    if (node->has_feedback()) {
      // We might need to take the feedback slot and vector into account for
      // {stack_arg_count}. There are three possibilities:
      // 1. Feedback slot and vector are in register.
      // 2. Feedback slot is in register and vector is on stack.
      // 3. Feedback slot and vector are on stack.
      int slot_index = node->InputCountWithoutContext();
      int vector_index = slot_index + 1;
      if (vector_index < descriptor.GetRegisterParameterCount()) {
        // stack_arg_count is already correct.
      } else if (vector_index == descriptor.GetRegisterParameterCount()) {
        // feedback vector is on the stack
        stack_arg_count += 1;
      } else {
        // feedback slot and vector on the stack
        stack_arg_count += 2;
      }
    }

    BAILOUT_IF_TOO_MANY_ARGUMENTS_FOR_CALL(arguments.size());
    V<Any> call_idx =
        GenerateBuiltinCall(node, node->builtin(), frame_state,
                            base::VectorOf(arguments), stack_arg_count);
    SetMapMaybeMultiReturn(node, call_idx);

    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CallRuntime* node,
                                const maglev::ProcessingState& state) {
    ThrowingScope throwing_scope(this, node);
    LazyDeoptOnThrow lazy_deopt_on_throw = ShouldLazyDeoptOnThrow(node);

    auto c_entry_stub = __ CEntryStubConstant(isolate_, node->ReturnCount());

    CallDescriptor* call_descriptor = Linkage::GetRuntimeCallDescriptor(
        graph_zone(), node->function_id(), node->num_args(),
        Operator::kNoProperties, CallDescriptor::kNeedsFrameState,
        lazy_deopt_on_throw);

    base::SmallVector<OpIndex, 16> arguments;
    for (int i = 0; i < node->num_args(); i++) {
      arguments.push_back(Map(node->arg(i)));
    }

    arguments.push_back(
        __ ExternalConstant(ExternalReference::Create(node->function_id())));
    arguments.push_back(__ Word32Constant(node->num_args()));

    arguments.push_back(Map(node->context()));

    OptionalV<FrameState> frame_state = OptionalV<FrameState>::Nullopt();
    if (call_descriptor->NeedsFrameState()) {
      GET_FRAME_STATE_MAYBE_ABORT(frame_state_value, node->lazy_deopt_info());
      frame_state = frame_state_value;
    }
    DCHECK_IMPLIES(lazy_deopt_on_throw == LazyDeoptOnThrow::kYes,
                   frame_state.has_value());

    BAILOUT_IF_TOO_MANY_ARGUMENTS_FOR_CALL(arguments.size());
    V<Any> call_idx =
        __ Call(c_entry_stub, frame_state, base::VectorOf(arguments),
                TSCallDescriptor::Create(call_descriptor, CanThrow::kYes,
                                         lazy_deopt_on_throw, graph_zone()));
    SetMapMaybeMultiReturn(node, call_idx);

    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::ThrowReferenceErrorIfHole* node,
                                const maglev::ProcessingState& state) {
    ThrowingScope throwing_scope(this, node);

    IF (UNLIKELY(RootEqual(node->value(), RootIndex::kTheHoleValue))) {
      GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
      __ CallRuntime_ThrowAccessedUninitializedVariable(
          isolate_, frame_state, native_context(), ShouldLazyDeoptOnThrow(node),
          __ HeapConstant(node->name().object()));
      // TODO(dmercadier): use RuntimeAbort here instead of Unreachable.
      // However, before doing so, RuntimeAbort should be changed so that 1)
      // it's a block terminator and 2) it doesn't call the runtime when
      // v8_flags.trap_on_abort is true.
      __ Unreachable();
    }
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::ThrowIfNotSuperConstructor* node,
                                const maglev::ProcessingState& state) {
    ThrowingScope throwing_scope(this, node);

    V<HeapObject> constructor = Map(node->constructor());
    V<i::Map> map = __ LoadMapField(constructor);
    static_assert(Map::kBitFieldOffsetEnd + 1 - Map::kBitFieldOffset == 1);
    V<Word32> bitfield =
        __ template LoadField<Word32>(map, AccessBuilder::ForMapBitField());
    IF_NOT (LIKELY(__ Word32BitwiseAnd(bitfield,
                                       Map::Bits1::IsConstructorBit::kMask))) {
      GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
      __ CallRuntime_ThrowNotSuperConstructor(
          isolate_, frame_state, native_context(), ShouldLazyDeoptOnThrow(node),
          constructor, Map(node->function()));
      // TODO(dmercadier): use RuntimeAbort here instead of Unreachable.
      // However, before doing so, RuntimeAbort should be changed so that 1)
      // it's a block terminator and 2) it doesn't call the runtime when
      // v8_flags.trap_on_abort is true.
      __ Unreachable();
    }

    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::ThrowSuperAlreadyCalledIfNotHole* node,
                                const maglev::ProcessingState& state) {
    ThrowingScope throwing_scope(this, node);

    IF_NOT (LIKELY(__ RootEqual(Map(node->value()), RootIndex::kTheHoleValue,
                                isolate_))) {
      GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
      __ CallRuntime_ThrowSuperAlreadyCalledError(isolate_, frame_state,
                                                  native_context(),
                                                  ShouldLazyDeoptOnThrow(node));
      // TODO(dmercadier): use RuntimeAbort here instead of Unreachable.
      // However, before doing so, RuntimeAbort should be changed so that 1)
      // it's a block terminator and 2) it doesn't call the runtime when
      // v8_flags.trap_on_abort is true.
      __ Unreachable();
    }

    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::ThrowSuperNotCalledIfHole* node,
                                const maglev::ProcessingState& state) {
    ThrowingScope throwing_scope(this, node);

    IF (UNLIKELY(__ RootEqual(Map(node->value()), RootIndex::kTheHoleValue,
                              isolate_))) {
      GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
      __ CallRuntime_ThrowSuperNotCalled(isolate_, frame_state,
                                         native_context(),
                                         ShouldLazyDeoptOnThrow(node));
      // TODO(dmercadier): use RuntimeAbort here instead of Unreachable.
      // However, before doing so, RuntimeAbort should be changed so that 1)
      // it's a block terminator and 2) it doesn't call the runtime when
      // v8_flags.trap_on_abort is true.
      __ Unreachable();
    }

    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::ThrowIfNotCallable* node,
                                const maglev::ProcessingState& state) {
    ThrowingScope throwing_scope(this, node);

    V<Object> value = Map(node->value());

    IF_NOT (LIKELY(__ ObjectIsCallable(value))) {
      GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
      __ CallRuntime_ThrowCalledNonCallable(
          isolate_, frame_state, native_context(), ShouldLazyDeoptOnThrow(node),
          value);
      // TODO(dmercadier): use RuntimeAbort here instead of Unreachable.
      // However, before doing so, RuntimeAbort should be changed so that 1)
      // it's a block terminator and 2) it doesn't call the runtime when
      // v8_flags.trap_on_abort is true.
      __ Unreachable();
    }

    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::CreateFunctionContext* node,
                                const maglev::ProcessingState& state) {
    ThrowingScope throwing_scope(this, node);

    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
    V<Context> context = Map(node->context());
    V<ScopeInfo> scope_info = __ HeapConstant(node->scope_info().object());
    if (node->scope_type() == FUNCTION_SCOPE) {
      SetMap(node, __ CallBuiltin_FastNewFunctionContextFunction(
                       isolate_, frame_state, context, scope_info,
                       node->slot_count(), ShouldLazyDeoptOnThrow(node)));
    } else {
      DCHECK_EQ(node->scope_type(), EVAL_SCOPE);
      SetMap(node, __ CallBuiltin_FastNewFunctionContextEval(
                       isolate_, frame_state, context, scope_info,
                       node->slot_count(), ShouldLazyDeoptOnThrow(node)));
    }
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::FastCreateClosure* node,
                                const maglev::ProcessingState& state) {
    NoThrowingScopeRequired no_throws(node);

    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
    V<Context> context = Map(node->context());
    V<SharedFunctionInfo> shared_function_info =
        __ HeapConstant(node->shared_function_info().object());
    V<FeedbackCell> feedback_cell =
        __ HeapConstant(node->feedback_cell().object());

    SetMap(node,
           __ CallBuiltin_FastNewClosure(isolate_, frame_state, context,
                                         shared_function_info, feedback_cell));

    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CreateClosure* node,
                                const maglev::ProcessingState& state) {
    NoThrowingScopeRequired no_throws(node);

    V<Context> context = Map(node->context());
    V<SharedFunctionInfo> shared_function_info =
        __ HeapConstant(node->shared_function_info().object());
    V<FeedbackCell> feedback_cell =
        __ HeapConstant(node->feedback_cell().object());

    V<JSFunction> closure;
    if (node->pretenured()) {
      closure = __ CallRuntime_NewClosure_Tenured(
          isolate_, context, shared_function_info, feedback_cell);
    } else {
      closure = __ CallRuntime_NewClosure(isolate_, context,
                                          shared_function_info, feedback_cell);
    }

    SetMap(node, closure);

    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::CallWithArrayLike* node,
                                const maglev::ProcessingState& state) {
    ThrowingScope throwing_scope(this, node);

    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
    V<Context> context = Map(node->context());
    V<Object> function = Map(node->function());
    V<Object> receiver = Map(node->receiver());
    V<Object> arguments_list = Map(node->arguments_list());

    SetMap(node, __ CallBuiltin_CallWithArrayLike(
                     isolate_, graph_zone(), frame_state, context, receiver,
                     function, arguments_list, ShouldLazyDeoptOnThrow(node)));

    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::CallWithSpread* node,
                                const maglev::ProcessingState& state) {
    ThrowingScope throwing_scope(this, node);

    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
    V<Context> context = Map(node->context());
    V<Object> function = Map(node->function());
    V<Object> spread = Map(node->spread());

    base::SmallVector<V<Object>, 16> arguments_no_spread;
    for (auto arg : node->args_no_spread()) {
      arguments_no_spread.push_back(Map(arg));
    }

    SetMap(node, __ CallBuiltin_CallWithSpread(
                     isolate_, graph_zone(), frame_state, context, function,
                     node->num_args_no_spread(), spread,
                     base::VectorOf(arguments_no_spread),
                     ShouldLazyDeoptOnThrow(node)));

    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::CallForwardVarargs* node,
                                const maglev::ProcessingState& state) {
    ThrowingScope throwing_scope(this, node);

    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
    V<JSFunction> function = Map(node->function());
    V<Context> context = Map(node->context());

    base::SmallVector<V<Object>, 16> arguments;
    for (auto arg : node->args()) {
      arguments.push_back(Map(arg));
    }
    DCHECK_EQ(node->num_args(), arguments.size());

    Builtin builtin;
    switch (node->target_type()) {
      case maglev::Call::TargetType::kJSFunction:
        builtin = Builtin::kCallFunctionForwardVarargs;
        break;
      case maglev::Call::TargetType::kAny:
        builtin = Builtin::kCallForwardVarargs;
        break;
    }
    V<Object> call = __ CallBuiltin_CallForwardVarargs(
        isolate_, graph_zone(), builtin, frame_state, context, function,
        node->num_args(), node->start_index(), base::VectorOf(arguments),
        ShouldLazyDeoptOnThrow(node));

    SetMap(node, call);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Construct* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
    base::SmallVector<OpIndex, 16> arguments;

    arguments.push_back(Map(node->function()));
    arguments.push_back(Map(node->new_target()));
    arguments.push_back(__ Word32Constant(node->num_args()));

    for (auto arg : node->args()) {
      arguments.push_back(Map(arg));
    }

    arguments.push_back(Map(node->context()));

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kConstruct, frame_state,
                                  base::VectorOf(arguments), node->num_args());

    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::ConstructWithSpread* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    base::SmallVector<OpIndex, 16> arguments;
    arguments.push_back(Map(node->function()));
    arguments.push_back(Map(node->new_target()));
    arguments.push_back(__ Word32Constant(node->num_args_no_spread()));
    arguments.push_back(Map(node->spread()));

    for (auto arg : node->args_no_spread()) {
      arguments.push_back(Map(arg));
    }

    arguments.push_back(Map(node->context()));

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kConstructWithSpread,
                                  frame_state, base::VectorOf(arguments),
                                  node->num_args_no_spread());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckConstructResult* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ CheckConstructResult(Map(node->construct_result_input()),
                                         Map(node->implicit_receiver_input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckDerivedConstructResult* node,
                                const maglev::ProcessingState& state) {
    ThrowingScope throwing_scope(this, node);
    V<Object> construct_result = Map(node->construct_result_input());
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
    __ CheckDerivedConstructResult(construct_result, frame_state,
                                   native_context(),
                                   ShouldLazyDeoptOnThrow(node));
    SetMap(node, construct_result);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::SetKeyedGeneric* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {Map(node->object_input()),
                           Map(node->key_input()),
                           Map(node->value_input()),
                           __ TaggedIndexConstant(node->feedback().index()),
                           __ HeapConstant(node->feedback().vector),
                           Map(node->context())};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kKeyedStoreIC, frame_state,
                                  base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::GetKeyedGeneric* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {Map(node->object_input()), Map(node->key_input()),
                           __ TaggedIndexConstant(node->feedback().index()),
                           __ HeapConstant(node->feedback().vector),
                           Map(node->context())};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kKeyedLoadIC, frame_state,
                                  base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::SetNamedGeneric* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {Map(node->object_input()),
                           __ HeapConstant(node->name().object()),
                           Map(node->value_input()),
                           __ TaggedIndexConstant(node->feedback().index()),
                           __ HeapConstant(node->feedback().vector),
                           Map(node->context())};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kStoreIC, frame_state,
                                  base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::LoadNamedGeneric* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {
        Map(node->object_input()), __ HeapConstant(node->name().object()),
        __ TaggedIndexConstant(node->feedback().index()),
        __ HeapConstant(node->feedback().vector), Map(node->context())};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kLoadIC, frame_state,
                                  base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::LoadNamedFromSuperGeneric* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {Map(node->receiver()),
                           Map(node->lookup_start_object()),
                           __ HeapConstant(node->name().object()),
                           __ TaggedIndexConstant(node->feedback().index()),
                           __ HeapConstant(node->feedback().vector),
                           Map(node->context())};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kLoadSuperIC, frame_state,
                                  base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::LoadGlobal* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {__ HeapConstant(node->name().object()),
                           __ TaggedIndexConstant(node->feedback().index()),
                           __ HeapConstant(node->feedback().vector),
                           Map(node->context())};

    Builtin builtin;
    switch (node->typeof_mode()) {
      case TypeofMode::kInside:
        builtin = Builtin::kLoadGlobalICInsideTypeof;
        break;
      case TypeofMode::kNotInside:
        builtin = Builtin::kLoadGlobalIC;
        break;
    }

    GENERATE_AND_MAP_BUILTIN_CALL(node, builtin, frame_state,
                                  base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::StoreGlobal* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {
        __ HeapConstant(node->name().object()), Map(node->value()),
        __ TaggedIndexConstant(node->feedback().index()),
        __ HeapConstant(node->feedback().vector), Map(node->context())};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kStoreGlobalIC, frame_state,
                                  base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::DefineKeyedOwnGeneric* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {Map(node->object_input()),
                           Map(node->key_input()),
                           Map(node->value_input()),
                           Map(node->flags_input()),
                           __ TaggedIndexConstant(node->feedback().index()),
                           __ HeapConstant(node->feedback().vector),
                           Map(node->context())};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kDefineKeyedOwnIC, frame_state,
                                  base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::DefineNamedOwnGeneric* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {Map(node->object_input()),
                           __ HeapConstant(node->name().object()),
                           Map(node->value_input()),
                           __ TaggedIndexConstant(node->feedback().index()),
                           __ HeapConstant(node->feedback().vector),
                           Map(node->context())};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kDefineNamedOwnIC, frame_state,
                                  base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::GetIterator* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {
        Map(node->receiver()), __ TaggedIndexConstant(node->load_slot()),
        __ TaggedIndexConstant(node->call_slot()),
        __ HeapConstant(node->feedback()), Map(node->context())};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kGetIteratorWithFeedback,
                                  frame_state, base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::CreateShallowObjectLiteral* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {
        __ HeapConstant(node->feedback().vector),
        __ TaggedIndexConstant(node->feedback().index()),
        __ HeapConstant(node->boilerplate_descriptor().object()),
        __ SmiConstant(Smi::FromInt(node->flags())), native_context()};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kCreateShallowObjectLiteral,
                                  frame_state, base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::CreateShallowArrayLiteral* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {__ HeapConstant(node->feedback().vector),
                           __ TaggedIndexConstant(node->feedback().index()),
                           __ HeapConstant(node->constant_elements().object()),
                           __ SmiConstant(Smi::FromInt(node->flags())),
                           native_context()};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kCreateShallowArrayLiteral,
                                  frame_state, base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::StoreInArrayLiteralGeneric* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {Map(node->object_input()),
                           Map(node->name_input()),
                           Map(node->value_input()),
                           __ TaggedIndexConstant(node->feedback().index()),
                           __ HeapConstant(node->feedback().vector),
                           native_context()};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kStoreInArrayLiteralIC,
                                  frame_state, base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::TestInstanceOf* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {Map(node->object()), Map(node->callable()),
                           Map(node->context())};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kInstanceOf, frame_state,
                                  base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::DeleteProperty* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {
        Map(node->object()), Map(node->key()),
        __ SmiConstant(Smi::FromInt(static_cast<int>(node->mode()))),
        Map(node->context())};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kDeleteProperty, frame_state,
                                  base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::ToName* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {Map(node->value_input()), Map(node->context())};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kToName, frame_state,
                                  base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::CreateRegExpLiteral* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {__ HeapConstant(node->feedback().vector),
                           __ TaggedIndexConstant(node->feedback().index()),
                           __ HeapConstant(node->pattern().object()),
                           __ SmiConstant(Smi::FromInt(node->flags())),
                           native_context()};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kCreateRegExpLiteral,
                                  frame_state, base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::GetTemplateObject* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {
        __ HeapConstant(node->shared_function_info().object()),
        Map(node->description()), __ WordPtrConstant(node->feedback().index()),
        __ HeapConstant(node->feedback().vector), native_context()};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kGetTemplateObject,
                                  frame_state, base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::CreateObjectLiteral* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {
        __ HeapConstant(node->feedback().vector),
        __ TaggedIndexConstant(node->feedback().index()),
        __ HeapConstant(node->boilerplate_descriptor().object()),
        __ SmiConstant(Smi::FromInt(node->flags())), native_context()};

    GENERATE_AND_MAP_BUILTIN_CALL(node,
                                  Builtin::kCreateObjectFromSlowBoilerplate,
                                  frame_state, base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::CreateArrayLiteral* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {__ HeapConstant(node->feedback().vector),
                           __ TaggedIndexConstant(node->feedback().index()),
                           __ HeapConstant(node->constant_elements().object()),
                           __ SmiConstant(Smi::FromInt(node->flags())),
                           native_context()};

    GENERATE_AND_MAP_BUILTIN_CALL(node,
                                  Builtin::kCreateArrayFromSlowBoilerplate,
                                  frame_state, base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::ForInPrepare* node,
                                const maglev::ProcessingState& state) {
    OpIndex arguments[] = {Map(node->enumerator()),
                           __ TaggedIndexConstant(node->feedback().index()),
                           __ HeapConstant(node->feedback().vector),
                           Map(node->context())};

    V<Any> call =
        GenerateBuiltinCall(node, Builtin::kForInPrepare,
                            OptionalV<turboshaft::FrameState>::Nullopt(),
                            base::VectorOf(arguments));
    SetMap(node, __ Projection(call, 0, RegisterRepresentation::Tagged()));
    second_return_value_ = V<Object>::Cast(
        __ Projection(call, 1, RegisterRepresentation::Tagged()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::ForInNext* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    OpIndex arguments[] = {__ WordPtrConstant(node->feedback().index()),
                           Map(node->receiver()),
                           Map(node->cache_array()),
                           Map(node->cache_type()),
                           Map(node->cache_index()),
                           __ HeapConstant(node->feedback().vector),
                           Map(node->context())};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kForInNext, frame_state,
                                  base::VectorOf(arguments));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::CheckSmi* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ DeoptimizeIfNot(__ ObjectIsSmi(Map(node->receiver_input())), frame_state,
                       DeoptimizeReason::kNotASmi,
                       node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckInt32IsSmi* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    DeoptIfInt32IsNotSmi(node->input(), frame_state,
                         node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckUint32IsSmi* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ DeoptimizeIfNot(__ Uint32LessThan(Map(node->input()), Smi::kMaxValue),
                       frame_state, DeoptimizeReason::kNotASmi,
                       node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckHoleyFloat64IsSmi* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    V<Word32> w32 = __ ChangeFloat64ToInt32OrDeopt(
        Map(node->input()), frame_state,
        CheckForMinusZeroMode::kCheckForMinusZero,
        node->eager_deopt_info()->feedback_to_update());
    if (!SmiValuesAre32Bits()) {
      DeoptIfInt32IsNotSmi(w32, frame_state,
                           node->eager_deopt_info()->feedback_to_update());
    }
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckNumber* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    V<Object> input = Map(node->receiver_input());
    V<Word32> check;
    if (node->mode() == Object::Conversion::kToNumeric) {
      check = __ ObjectIsNumberOrBigInt(input);
    } else {
      DCHECK_EQ(node->mode(), Object::Conversion::kToNumber);
      check = __ ObjectIsNumber(input);
    }
    __ DeoptimizeIfNot(check, frame_state, DeoptimizeReason::kNotANumber,
                       node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckHeapObject* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ DeoptimizeIf(__ ObjectIsSmi(Map(node->receiver_input())), frame_state,
                    DeoptimizeReason::kSmi,
                    node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckFloat64IsNan* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ DeoptimizeIfNot(__ Float64IsNaN(Map(node->target_input())), frame_state,
                       DeoptimizeReason::kWrongValue,
                       node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }
  void CheckMaps(V<Object> receiver_input, V<FrameState> frame_state,
                 OptionalV<Map> map, const FeedbackSource& feedback,
                 const compiler::ZoneRefSet<Map>& maps, bool check_heap_object,
                 bool try_migrate) {
    Label<> done(this);
    if (check_heap_object) {
      OpIndex is_smi = __ IsSmi(receiver_input);
      if (AnyMapIsHeapNumber(maps)) {
        // Smis count as matching the HeapNumber map, so we're done.
        GOTO_IF(is_smi, done);
      } else {
        __ DeoptimizeIf(is_smi, frame_state, DeoptimizeReason::kWrongMap,
                        feedback);
      }
    }

    bool has_migration_targets = false;
    if (try_migrate) {
      for (MapRef map : maps) {
        if (map.object()->is_migration_target()) {
          has_migration_targets = true;
          break;
        }
      }
    }

    __ CheckMaps(V<HeapObject>::Cast(receiver_input), frame_state, map, maps,
                 has_migration_targets ? CheckMapsFlag::kTryMigrateInstance
                                       : CheckMapsFlag::kNone,
                 feedback);

    if (done.has_incoming_jump()) {
      GOTO(done);
      BIND(done);
    }
  }
  maglev::ProcessResult Process(maglev::CheckMaps* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    CheckMaps(Map(node->receiver_input()), frame_state, {},
              node->eager_deopt_info()->feedback_to_update(),
              node->maps().Clone(graph_zone()),
              node->check_type() == maglev::CheckType::kCheckHeapObject,
              /* try_migrate */ false);
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckMapsWithAlreadyLoadedMap* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    CheckMaps(Map(node->object_input()), frame_state, Map(node->map_input()),
              node->eager_deopt_info()->feedback_to_update(),
              node->maps().Clone(graph_zone()), /*check_heap_object*/ false,
              /* try_migrate */ false);
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckMapsWithMigration* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    CheckMaps(Map(node->receiver_input()), frame_state, {},
              node->eager_deopt_info()->feedback_to_update(),
              node->maps().Clone(graph_zone()),
              node->check_type() == maglev::CheckType::kCheckHeapObject,
              /* try_migrate */ true);
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::MigrateMapIfNeeded* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    SetMap(node,
           __ MigrateMapIfNeeded(
               Map(node->object_input()), Map(node->map_input()), frame_state,
               node->eager_deopt_info()->feedback_to_update()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckValue* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ DeoptimizeIfNot(__ TaggedEqual(Map(node->target_input()),
                                      __ HeapConstant(node->value().object())),
                       frame_state, DeoptimizeReason::kWrongValue,
                       node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckValueEqualsInt32* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ DeoptimizeIfNot(__ Word32Equal(Map(node->target_input()), node->value()),
                       frame_state, DeoptimizeReason::kWrongValue,
                       node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckValueEqualsFloat64* node,
                                const maglev::ProcessingState& state) {
    DCHECK(!std::isnan(node->value()));
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ DeoptimizeIfNot(
        __ Float64Equal(Map(node->target_input()), node->value()), frame_state,
        DeoptimizeReason::kWrongValue,
        node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckString* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    ObjectIsOp::InputAssumptions input_assumptions =
        node->check_type() == maglev::CheckType::kCheckHeapObject
            ? ObjectIsOp::InputAssumptions::kNone
            : ObjectIsOp::InputAssumptions::kHeapObject;
    V<Word32> check = __ ObjectIs(Map(node->receiver_input()),
                                  ObjectIsOp::Kind::kString, input_assumptions);
    __ DeoptimizeIfNot(check, frame_state, DeoptimizeReason::kNotAString,
                       node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckStringOrStringWrapper* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    ObjectIsOp::InputAssumptions input_assumptions =
        node->check_type() == maglev::CheckType::kCheckHeapObject
            ? ObjectIsOp::InputAssumptions::kNone
            : ObjectIsOp::InputAssumptions::kHeapObject;
    V<Word32> check = __ ObjectIs(Map(node->receiver_input()),
                                  ObjectIsOp::Kind::kStringOrStringWrapper,
                                  input_assumptions);
    __ DeoptimizeIfNot(check, frame_state,
                       DeoptimizeReason::kNotAStringOrStringWrapper,
                       node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckSymbol* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    ObjectIsOp::InputAssumptions input_assumptions =
        node->check_type() == maglev::CheckType::kCheckHeapObject
            ? ObjectIsOp::InputAssumptions::kNone
            : ObjectIsOp::InputAssumptions::kHeapObject;
    V<Word32> check = __ ObjectIs(Map(node->receiver_input()),
                                  ObjectIsOp::Kind::kSymbol, input_assumptions);
    __ DeoptimizeIfNot(check, frame_state, DeoptimizeReason::kNotASymbol,
                       node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckInstanceType* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ CheckInstanceType(
        Map(node->receiver_input()), frame_state,
        node->eager_deopt_info()->feedback_to_update(),
        node->first_instance_type(), node->last_instance_type(),
        node->check_type() != maglev::CheckType::kOmitHeapObjectCheck);

    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckDynamicValue* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ DeoptimizeIfNot(
        __ TaggedEqual(Map(node->first_input()), Map(node->second_input())),
        frame_state, DeoptimizeReason::kWrongValue,
        node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckedSmiSizedInt32* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    DeoptIfInt32IsNotSmi(node->input(), frame_state,
                         node->eager_deopt_info()->feedback_to_update());
    SetMap(node, Map(node->input()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckNotHole* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ DeoptimizeIf(RootEqual(node->object_input(), RootIndex::kTheHoleValue),
                    frame_state, DeoptimizeReason::kHole,
                    node->eager_deopt_info()->feedback_to_update());
    SetMap(node, Map(node->object_input()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckInt32Condition* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    bool negate_result = false;
    V<Word32> cmp = ConvertInt32Compare(node->left_input(), node->right_input(),
                                        node->condition(), &negate_result);
    if (negate_result) {
      __ DeoptimizeIf(cmp, frame_state, node->reason(),
                      node->eager_deopt_info()->feedback_to_update());
    } else {
      __ DeoptimizeIfNot(cmp, frame_state, node->reason(),
                         node->eager_deopt_info()->feedback_to_update());
    }
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::AllocationBlock* node,
                                const maglev::ProcessingState& state) {
    DCHECK(
        node->is_used());  // Should have been dead-code eliminated otherwise.
    int size = 0;
    for (auto alloc : node->allocation_list()) {
      if (!alloc->HasBeenAnalysed() || alloc->HasEscaped()) {
        alloc->set_offset(size);
        size += alloc->size();
      }
    }
    node->set_size(size);
    SetMap(node, __ FinishInitialization(
                     __ Allocate<HeapObject>(size, node->allocation_type())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::InlinedAllocation* node,
                                const maglev::ProcessingState& state) {
    DCHECK(node->HasBeenAnalysed() &&
           node->HasEscaped());  // Would have been removed otherwise.
    V<HeapObject> alloc = Map(node->allocation_block());
    SetMap(node, __ BitcastWordPtrToHeapObject(__ WordPtrAdd(
                     __ BitcastHeapObjectToWordPtr(alloc), node->offset())));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::EnsureWritableFastElements* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ EnsureWritableFastElements(Map(node->object_input()),
                                               Map(node->elements_input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::MaybeGrowFastElements* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    GrowFastElementsMode mode =
        IsDoubleElementsKind(node->elements_kind())
            ? GrowFastElementsMode::kDoubleElements
            : GrowFastElementsMode::kSmiOrObjectElements;
    SetMap(node, __ MaybeGrowFastElements(
                     Map(node->object_input()), Map(node->elements_input()),
                     Map(node->index_input()),
                     Map(node->elements_length_input()), frame_state, mode,
                     node->eager_deopt_info()->feedback_to_update()));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::ExtendPropertiesBackingStore* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    SetMap(node, __ ExtendPropertiesBackingStore(
                     Map(node->property_array_input()),
                     Map(node->object_input()), node->old_length(), frame_state,
                     node->eager_deopt_info()->feedback_to_update()));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::TransitionElementsKindOrCheckMap* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ TransitionElementsKindOrCheckMap(
        Map(node->object_input()), Map(node->map_input()), frame_state,
        node->transition_sources(), node->transition_target(),
        node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::TransitionElementsKind* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ TransitionMultipleElementsKind(
                     Map(node->object_input()), Map(node->map_input()),
                     node->transition_sources(), node->transition_target()));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::HasInPrototypeChain* node,
                                const maglev::ProcessingState& state) {
    ThrowingScope throwing_scope(this, node);

    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
    SetMap(node, __ HasInPrototypeChain(Map(node->object()), node->prototype(),
                                        frame_state, native_context(),
                                        ShouldLazyDeoptOnThrow(node)));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::UpdateJSArrayLength* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ UpdateJSArrayLength(Map(node->length_input()),
                                        Map(node->object_input()),
                                        Map(node->index_input())));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::AllocateElementsArray* node,
                                const maglev::ProcessingState& state) {
    V<Word32> length = Map(node->length_input());
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    // Note that {length} cannot be negative (Maglev inserts a check before
    // AllocateElementsArray to ensure this).
    __ DeoptimizeIfNot(
        __ Uint32LessThan(length, JSArray::kInitialMaxFastElementArray),
        frame_state, DeoptimizeReason::kGreaterThanMaxFastElementArray,
        node->eager_deopt_info()->feedback_to_update());
    RETURN_IF_UNREACHABLE();

    SetMap(node,
           __ NewArray(__ ChangeUint32ToUintPtr(length),
                       NewArrayOp::Kind::kObject, node->allocation_type()));
    return maglev::ProcessResult::kContinue;
  }

  template <typename Node>
  maglev::ProcessResult StringConcatHelper(Node* node, V<String> left,
                                           V<String> right) {
    // When coming from Turbofan, StringConcat is always guarded by a check that
    // the length is less than String::kMaxLength, which prevents StringConcat
    // from ever throwing (and as a consequence of this, it does not need a
    // Context input). This is not the case for Maglev. To mimic Turbofan's
    // behavior, we thus insert here a length check.
    // TODO(dmercadier): I'm not convinced that these checks make a lot of
    // sense, since they make the graph bigger, and throwing before the builtin
    // call to StringConcat isn't super important since throwing is not supposed
    // to be fast. We should consider just calling the builtin and letting it
    // throw. With LazyDeopOnThrow, this is currently a bit verbose to
    // implement, so we should first find a way to have this LazyDeoptOnThrow
    // without adding a member to all throwing operations (like adding
    // LazyDeoptOnThrow in FrameStateOp).
    ThrowingScope throwing_scope(this, node);

    V<Word32> left_len = __ StringLength(left);
    V<Word32> right_len = __ StringLength(right);

    V<Tuple<Word32, Word32>> len_and_ovf =
        __ Int32AddCheckOverflow(left_len, right_len);
    V<Word32> len = __ Projection<0>(len_and_ovf);
    V<Word32> ovf = __ Projection<1>(len_and_ovf);

    Label<> throw_invalid_length(this);
    Label<> done(this);

    GOTO_IF(UNLIKELY(ovf), throw_invalid_length);
    GOTO_IF(LIKELY(__ Uint32LessThanOrEqual(len, String::kMaxLength)), done);

    GOTO(throw_invalid_length);
    BIND(throw_invalid_length);
    {
      GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
      __ CallRuntime_ThrowInvalidStringLength(isolate_, frame_state,
                                              native_context(),
                                              ShouldLazyDeoptOnThrow(node));
      // We should not return from Throw.
      __ Unreachable();
    }

    BIND(done);
    SetMap(node, __ StringConcat(__ TagSmi(len), left, right));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::StringConcat* node,
                                const maglev::ProcessingState& state) {
    V<String> left = Map(node->lhs());
    V<String> right = Map(node->rhs());
    return StringConcatHelper(node, left, right);
  }
  maglev::ProcessResult Process(maglev::StringWrapperConcat* node,
                                const maglev::ProcessingState& state) {
    V<HeapObject> left_string_or_wrapper = Map(node->lhs());
    V<HeapObject> right_string_or_wrapper = Map(node->rhs());

    ScopedVar<String, AssemblerT> left(this);
    ScopedVar<String, AssemblerT> right(this);
    IF (__ ObjectIsString(left_string_or_wrapper)) {
      left = V<String>::Cast(left_string_or_wrapper);
    } ELSE {
      left = V<String>::Cast(__ LoadTaggedField(
          V<JSPrimitiveWrapper>::Cast(left_string_or_wrapper),
          JSPrimitiveWrapper::kValueOffset));
    }
    IF (__ ObjectIsString(right_string_or_wrapper)) {
      right = V<String>::Cast(right_string_or_wrapper);
    } ELSE {
      right = V<String>::Cast(__ LoadTaggedField(
          V<JSPrimitiveWrapper>::Cast(right_string_or_wrapper),
          JSPrimitiveWrapper::kValueOffset));
    }

    return StringConcatHelper(node, left, right);
  }
  maglev::ProcessResult Process(maglev::StringEqual* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ StringEqual(Map(node->lhs()), Map(node->rhs())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::StringLength* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ StringLength(Map(node->object_input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::StringAt* node,
                                const maglev::ProcessingState& state) {
    V<Word32> char_code =
        __ StringCharCodeAt(Map(node->string_input()),
                            __ ChangeUint32ToUintPtr(Map(node->index_input())));
    SetMap(node, __ ConvertCharCodeToString(char_code));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckedInternalizedString* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    SetMap(node, __ CheckedInternalizedString(
                     Map(node->object_input()), frame_state,
                     node->check_type() == maglev::CheckType::kCheckHeapObject,
                     node->eager_deopt_info()->feedback_to_update()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckValueEqualsString* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ CheckValueEqualsString(Map(node->target_input()), node->value(),
                              frame_state,
                              node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::BuiltinStringFromCharCode* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ ConvertCharCodeToString(Map(node->code_input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(
      maglev::BuiltinStringPrototypeCharCodeOrCodePointAt* node,
      const maglev::ProcessingState& state) {
    if (node->mode() == maglev::BuiltinStringPrototypeCharCodeOrCodePointAt::
                            Mode::kCharCodeAt) {
      SetMap(node, __ StringCharCodeAt(
                       Map(node->string_input()),
                       __ ChangeUint32ToUintPtr(Map(node->index_input()))));
    } else {
      DCHECK_EQ(node->mode(),
                maglev::BuiltinStringPrototypeCharCodeOrCodePointAt::Mode::
                    kCodePointAt);
      SetMap(node, __ StringCodePointAt(
                       Map(node->string_input()),
                       __ ChangeUint32ToUintPtr(Map(node->index_input()))));
    }
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::ToString* node,
                                const maglev::ProcessingState& state) {
    ThrowingScope throwing_scope(this, node);

    Label<String> done(this);

    V<Object> value = Map(node->value_input());
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    GOTO_IF(__ ObjectIsString(value), done, V<String>::Cast(value));

    IF_NOT (__ IsSmi(value)) {
      if (node->mode() == maglev::ToString::ConversionMode::kConvertSymbol) {
        V<i::Map> map = __ LoadMapField(value);
        V<Word32> instance_type = __ LoadInstanceTypeField(map);
        IF (__ Word32Equal(instance_type, SYMBOL_TYPE)) {
          GOTO(done, __ CallRuntime_SymbolDescriptiveString(
                         isolate_, frame_state, Map(node->context()),
                         V<Symbol>::Cast(value), ShouldLazyDeoptOnThrow(node)));
        }
      }
    }

    GOTO(done,
         __ CallBuiltin_ToString(isolate_, frame_state, Map(node->context()),
                                 value, ShouldLazyDeoptOnThrow(node)));

    BIND(done, result);
    SetMap(node, result);
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::NumberToString* node,
                                const maglev::ProcessingState& state) {
    NoThrowingScopeRequired no_throws(node);

    SetMap(node,
           __ CallBuiltin_NumberToString(isolate_, Map(node->value_input())));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::ArgumentsLength* node,
                                const maglev::ProcessingState& state) {
    // TODO(dmercadier): ArgumentsLength in Maglev returns a raw Word32, while
    // in Turboshaft, it returns a Smi. We thus untag this Smi here to match
    // Maglev's behavior, but it would be more efficient to change Turboshaft's
    // ArgumentsLength operation to return a raw Word32 as well.
    SetMap(node, __ UntagSmi(__ ArgumentsLength()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::ArgumentsElements* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ NewArgumentsElements(Map(node->arguments_count_input()),
                                         node->type(),
                                         node->formal_parameter_count()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::RestLength* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ RestLength(node->formal_parameter_count()));
    return maglev::ProcessResult::kContinue;
  }

  template <typename T>
  maglev::ProcessResult Process(maglev::AbstractLoadTaggedField<T>* node,
                                const maglev::ProcessingState& state) {
    V<Object> value =
        __ LoadTaggedField(Map(node->object_input()), node->offset());
    SetMap(node, value);

    if (generator_analyzer_.has_header_bypasses() &&
        maglev_generator_context_node_ == nullptr &&
        node->object_input().node()->template Is<maglev::RegisterInput>() &&
        node->offset() == JSGeneratorObject::kContextOffset) {
      // This is loading the context of a generator for the 1st time. We save it
      // in {generator_context_} for later use.
      __ SetVariable(generator_context_, value);
      maglev_generator_context_node_ = node;
    }

    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(
      maglev::LoadTaggedFieldForScriptContextSlot* node,
      const maglev::ProcessingState& state) {
    V<Context> script_context = V<Context>::Cast(Map(node->context()));
    V<Object> value = __ LoadTaggedField(script_context, node->offset());
    ScopedVar<Object, AssemblerT> result(this, value);
    IF_NOT (__ IsSmi(value)) {
      V<i::Map> value_map = __ LoadMapField(value);
      IF (UNLIKELY(__ TaggedEqual(
              value_map, __ HeapConstant(local_factory_->heap_number_map())))) {
        V<HeapNumber> heap_number = V<HeapNumber>::Cast(value);
        result = __ LoadHeapNumberFromScriptContext(script_context,
                                                    node->index(), heap_number);
      }
    }
    SetMap(node, result);
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::LoadDoubleField* node,
                                const maglev::ProcessingState& state) {
    V<HeapNumber> field = __ LoadTaggedField<HeapNumber>(
        Map(node->object_input()), node->offset());
    SetMap(node, __ LoadHeapNumberValue(field));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::LoadFixedArrayElement* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ LoadFixedArrayElement(
                     Map(node->elements_input()),
                     __ ChangeInt32ToIntPtr(Map(node->index_input()))));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::LoadFixedDoubleArrayElement* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ LoadFixedDoubleArrayElement(
                     Map(node->elements_input()),
                     __ ChangeInt32ToIntPtr(Map(node->index_input()))));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::LoadHoleyFixedDoubleArrayElement* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ LoadFixedDoubleArrayElement(
                     Map(node->elements_input()),
                     __ ChangeInt32ToIntPtr(Map(node->index_input()))));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(
      maglev::LoadHoleyFixedDoubleArrayElementCheckedNotHole* node,
      const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    V<Float64> result = __ LoadFixedDoubleArrayElement(
        Map(node->elements_input()),
        __ ChangeInt32ToIntPtr(Map(node->index_input())));
    __ DeoptimizeIf(__ Float64IsHole(result), frame_state,
                    DeoptimizeReason::kHole,
                    node->eager_deopt_info()->feedback_to_update());
    SetMap(node, result);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::StoreTaggedFieldNoWriteBarrier* node,
                                const maglev::ProcessingState& state) {
    __ Store(Map(node->object_input()), Map(node->value_input()),
             StoreOp::Kind::TaggedBase(), MemoryRepresentation::AnyTagged(),
             WriteBarrierKind::kNoWriteBarrier, node->offset(),
             node->initializing_or_transitioning());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::StoreTaggedFieldWithWriteBarrier* node,
                                const maglev::ProcessingState& state) {
    __ Store(Map(node->object_input()), Map(node->value_input()),
             StoreOp::Kind::TaggedBase(), MemoryRepresentation::AnyTagged(),
             WriteBarrierKind::kFullWriteBarrier, node->offset(),
             node->initializing_or_transitioning());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(
      maglev::StoreScriptContextSlotWithWriteBarrier* node,
      const maglev::ProcessingState& state) {
    Label<> done(this);
    V<Context> context = V<i::Context>::Cast(Map(node->context_input()));
    V<Object> new_value = Map(node->new_value_input());
    V<Object> old_value = __ LoadTaggedField(context, node->offset());
    IF_NOT (__ TaggedEqual(old_value, new_value)) {
      V<Object> side_data =
          __ LoadScriptContextSideData(context, node->index());
      IF_NOT (UNLIKELY(__ TaggedEqual(
                  side_data,
                  __ SmiConstant(ContextSidePropertyCell::Other())))) {
        GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
        __ StoreScriptContextSlowPath(
            context, old_value, new_value, side_data, frame_state,
            node->eager_deopt_info()->feedback_to_update(), done);
      }
      __ Store(context, new_value, StoreOp::Kind::TaggedBase(),
```