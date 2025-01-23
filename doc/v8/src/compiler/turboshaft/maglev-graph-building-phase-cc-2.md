Response:
The user wants to understand the functionality of the provided C++ code snippet from V8's `maglev-graph-building-phase.cc` file. The code seems to be processing different types of Maglev nodes and generating corresponding low-level code (likely TurboShaft IR).

Here's a breakdown of the thought process to address the user's request:

1. **Identify the core task:** The code iterates through various `maglev::*` node types and performs actions based on the node type. The primary action seems to involve generating calls to built-in functions or runtime functions.

2. **Analyze the `Process` methods:**  Each `Process` method handles a specific Maglev node type (e.g., `maglev::CallBuiltin`, `maglev::CallRuntime`, `maglev::ThrowReferenceErrorIfHole`). This suggests the file is responsible for translating high-level Maglev operations into lower-level instructions.

3. **Look for common patterns:**  Several `Process` methods follow a similar structure:
    * Get inputs from the Maglev node using `node->input(i)` or similar.
    * Create a vector of arguments (`arguments`).
    * Potentially add feedback vector and slot.
    * Add the context.
    * Call `GenerateBuiltinCall` or `__ Call`.
    * Map the result using `SetMap` or `SetMapMaybeMultiReturn`.
    * Handle potential exceptions using `ThrowingScope`.
    * Implement eager or lazy deoptimization checks.

4. **Focus on key function calls:**  `GenerateBuiltinCall` and `__ Call` are crucial. `GenerateBuiltinCall` likely creates a call to a built-in V8 function, while `__ Call` appears to handle calls to runtime functions or C++ stubs.

5. **Infer the file's role:** Based on the node processing and the generation of function calls, the file's main function is to translate the Maglev graph into a lower-level representation suitable for code generation. It acts as a bridge between the high-level Maglev IR and the more concrete TurboShaft IR.

6. **Address specific user questions:**

    * **Functionality:** List the types of Maglev nodes being processed and the general action taken for each (e.g., calling a built-in, calling a runtime function, performing a check, etc.).
    * **`.tq` extension:** Explicitly state that the file is C++ and not Torque based on the `.cc` extension.
    * **Relationship to JavaScript:**  Provide examples of JavaScript code that would lead to the execution of some of the processed Maglev nodes (e.g., function calls, property access, object/array literals, `instanceof`, `delete`).
    * **Code logic inference:** For a simple case like `maglev::ThrowReferenceErrorIfHole`, explain the conditional logic and the bailout mechanism. Provide a simple input and expected outcome.
    * **Common programming errors:** Connect some of the processed nodes to common JavaScript errors (e.g., accessing an uninitialized variable, calling a non-callable object, type errors in constructors).
    * **Part 3 of 9:**  Acknowledge this information but note that the functionality is independent of the partitioning.
    * **Summarize the functionality:**  Provide a concise summary highlighting the translation of Maglev nodes into lower-level calls and the inclusion of deoptimization checks.

7. **Refine and structure the answer:** Organize the information logically, using clear headings and bullet points. Ensure the JavaScript examples are clear and directly related to the processed nodes. Double-check the code snippets and explanations for accuracy.

**(Self-correction during the process):** Initially, I might have focused too much on the specific built-in functions being called. However, the user's request is about the *overall functionality* of the file. Therefore, it's more important to emphasize the *process* of translating Maglev nodes into calls and the handling of deoptimization, rather than memorizing every single built-in. Also, providing a good range of JavaScript examples is key to illustrating the connection between the C++ code and the user's programming experience.
这是 V8 源代码文件 `v8/src/compiler/turboshaft/maglev-graph-building-phase.cc` 的第三部分，主要负责将 Maglev 图中的节点转换为 TurboShaft 图中的相应操作。这个阶段是 Maglev 编译器的核心部分，它将高级的、更接近 JavaScript 语义的 Maglev 图转换为更底层的、更适合代码生成的 TurboShaft 图。

**功能归纳 (第 3 部分):**

这部分代码主要处理以下类型的 Maglev 节点，并将它们转换为 TurboShaft 图中的操作，通常涉及调用内置函数或运行时函数：

* **函数调用:**  `maglev::CallBuiltin`, `maglev::CallRuntime`, `maglev::CallWithArrayLike`, `maglev::CallWithSpread`, `maglev::CallForwardVarargs`：处理不同类型的函数调用，包括调用内置函数和运行时函数，并考虑了参数传递、上下文和可能的反馈信息。
* **异常处理 (抛出错误):** `maglev::ThrowReferenceErrorIfHole`, `maglev::ThrowIfNotSuperConstructor`, `maglev::ThrowSuperAlreadyCalledIfNotHole`, `maglev::ThrowSuperNotCalledIfHole`, `maglev::ThrowIfNotCallable`：处理各种需要抛出 JavaScript 错误的场景。
* **闭包和上下文创建:** `maglev::CreateFunctionContext`, `maglev::FastCreateClosure`, `maglev::CreateClosure`：处理函数上下文和闭包的创建。
* **构造函数调用:** `maglev::Construct`, `maglev::ConstructWithSpread`, `maglev::CheckConstructResult`, `maglev::CheckDerivedConstructResult`：处理构造函数的调用和结果检查。
* **属性访问 (读写):** `maglev::SetKeyedGeneric`, `maglev::GetKeyedGeneric`, `maglev::SetNamedGeneric`, `maglev::LoadNamedGeneric`, `maglev::LoadNamedFromSuperGeneric`：处理对象属性的读取和写入，包括普通属性和原型链上的属性。
* **全局变量访问:** `maglev::LoadGlobal`, `maglev::StoreGlobal`：处理全局变量的读取和写入。
* **属性定义:** `maglev::DefineKeyedOwnGeneric`, `maglev::DefineNamedOwnGeneric`：处理对象自身属性的定义。
* **迭代器:** `maglev::GetIterator`, `maglev::ForInPrepare`, `maglev::ForInNext`：处理迭代器的获取和 `for...in` 循环。
* **字面量创建:** `maglev::CreateShallowObjectLiteral`, `maglev::CreateShallowArrayLiteral`, `maglev::CreateObjectLiteral`, `maglev::CreateArrayLiteral`：处理对象和数组字面量的创建。
* **其他操作:** `maglev::StoreInArrayLiteralGeneric`, `maglev::TestInstanceOf`, `maglev::DeleteProperty`, `maglev::ToName`, `maglev::CreateRegExpLiteral`, `maglev::GetTemplateObject`：处理数组字面量赋值、`instanceof` 运算符、属性删除、类型转换和正则表达式字面量等。
* **类型检查:** `maglev::CheckSmi`, `maglev::CheckInt32IsSmi`：进行类型检查，如果不符合预期则触发反优化。

**关于文件类型:**

`v8/src/compiler/turboshaft/maglev-graph-building-phase.cc` 以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。

**与 JavaScript 的关系及示例:**

这个文件中的代码负责将各种 JavaScript 操作转换为底层的机器指令。以下是一些 JavaScript 示例以及它们可能触发的代码逻辑：

1. **函数调用:**

   ```javascript
   function foo(a, b) {
     return a + b;
   }
   foo(1, 2); // 可能触发 Process(maglev::CallBuiltin*) 或 Process(maglev::CallRuntime*)
   ```
   Maglev 会根据 `foo` 的具体类型 (例如，是否是内置函数) 选择合适的 `Process` 方法来处理这个调用。

2. **属性访问:**

   ```javascript
   const obj = { x: 10 };
   console.log(obj.x); // 可能触发 Process(maglev::LoadNamedGeneric*)
   obj.y = 20;        // 可能触发 Process(maglev::SetNamedGeneric*)
   ```
   Maglev 会分析属性访问操作，并生成相应的 TurboShaft 代码来读取或写入属性。

3. **对象字面量:**

   ```javascript
   const point = { x: 1, y: 2 }; // 可能触发 Process(maglev::CreateShallowObjectLiteral*) 或 Process(maglev::CreateObjectLiteral*)
   ```
   Maglev 会根据对象的复杂程度和优化情况选择合适的节点来创建对象。

4. **构造函数:**

   ```javascript
   class MyClass {}
   new MyClass(); // 可能触发 Process(maglev::Construct*)
   ```
   Maglev 会处理构造函数的调用过程。

5. **`instanceof` 运算符:**

   ```javascript
   const arr = [];
   arr instanceof Array; // 可能触发 Process(maglev::TestInstanceOf*)
   ```
   Maglev 会生成代码来检查对象的原型链。

6. **`for...in` 循环:**

   ```javascript
   const obj = { a: 1, b: 2 };
   for (let key in obj) {
     console.log(key); // 可能触发 Process(maglev::ForInPrepare*) 和 Process(maglev::ForInNext*)
   }
   ```
   Maglev 会处理 `for...in` 循环的枚举过程。

**代码逻辑推理与假设输入输出:**

以 `Process(maglev::ThrowReferenceErrorIfHole* node, ...)` 为例：

**假设输入:** 一个 `maglev::ThrowReferenceErrorIfHole` 节点，其中 `node->value()` 代表一个变量的值，`node->name()` 代表变量名。

**代码逻辑:**

```c++
IF (UNLIKELY(RootEqual(node->value(), RootIndex::kTheHoleValue))) {
  // 如果变量的值是 Hole，表示访问了未初始化的变量
  GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
  __ CallRuntime_ThrowAccessedUninitializedVariable(
      isolate_, frame_state, native_context(), ShouldLazyDeoptOnThrow(node),
      __ HeapConstant(node->name().object()));
  __ Unreachable();
}
return maglev::ProcessResult::kContinue;
```

**假设输入:** 假设 `node->value()` 返回一个表示 `the hole` 的值 (这是 V8 中表示未初始化变量的值)。 `node->name()` 返回一个字符串 "x"。

**输出:** 代码会执行 `__ CallRuntime_ThrowAccessedUninitializedVariable`，调用运行时函数来抛出一个 "ReferenceError: Cannot access 'x' before initialization" 类型的错误。 `__ Unreachable()` 表示之后的代码不会被执行，因为已经抛出了异常。

**如果 `node->value()` 不是 `the hole`，则该 `Process` 方法会直接返回 `maglev::ProcessResult::kContinue`，表示没有错误发生，继续处理下一个节点。**

**用户常见的编程错误:**

这个文件处理的节点很多都与用户常见的编程错误有关：

* **访问未初始化的变量:**  `maglev::ThrowReferenceErrorIfHole` 对应于访问了 `let` 或 `const` 声明但未赋值的变量。

   ```javascript
   let x;
   console.log(x); // ReferenceError: Cannot access 'x' before initialization
   ```

* **调用非函数:** `maglev::ThrowIfNotCallable` 对应于尝试调用一个非函数类型的对象。

   ```javascript
   const notAFunction = 10;
   notAFunction(); // TypeError: notAFunction is not a function
   ```

* **`super` 关键字使用错误:** `maglev::ThrowIfNotSuperConstructor`, `maglev::ThrowSuperAlreadyCalledIfNotHole`, `maglev::ThrowSuperNotCalledIfHole` 对应于在派生类的构造函数中不正确地使用 `super` 关键字。

   ```javascript
   class Parent {}
   class Child extends Parent {
     constructor() {
       // console.log(this); // ReferenceError: Must call super constructor in derived class before accessing 'this' or returning from derived constructor
       super();
     }
   }
   new Child();
   ```

**总结 (针对第 3 部分):**

`v8/src/compiler/turboshaft/maglev-graph-building-phase.cc` 的第 3 部分专注于将与函数调用、异常处理、闭包创建、构造函数、属性访问、全局变量、属性定义、迭代器、字面量创建以及其他一些关键的 JavaScript 语义相关的 Maglev 图节点转换为 TurboShaft 图中的低级操作。这部分代码是 Maglev 编译器将高级抽象的 JavaScript 代码转化为可执行机器代码的关键步骤。它还处理了与常见 JavaScript 运行时错误相关的逻辑，确保在编译过程中能够识别和处理这些错误。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/maglev-graph-building-phase.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/maglev-graph-building-phase.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
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
                         node->eager_
```