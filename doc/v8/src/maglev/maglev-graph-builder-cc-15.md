Response:
Let's break down the thought process for analyzing this V8 source code snippet.

1. **Understand the Goal:** The primary goal is to understand the functionality of the provided C++ code snippet within the `v8/src/maglev/maglev-graph-builder.cc` file. The prompt also provides some helpful constraints and specific questions to address.

2. **Initial Scan and Keyword Spotting:**  Quickly read through the code, looking for recurring keywords and patterns. Some immediately stand out:

    * `MaglevGraphBuilder`: This strongly suggests the code is part of the Maglev compiler in V8 and is responsible for building a graph representation of the code.
    * `Build...`:  Functions like `BuildInlinedArgumentsElements`, `BuildInlinedAllocation`, `BuildCallBuiltin`, etc., indicate the creation of graph nodes representing different operations.
    * `CreateArgumentsObject`, `CreateObjectLiteral`, `CreateClosure`, `CreateContext`: These suggest the code is involved in creating various JavaScript objects and execution contexts.
    * `Visit...`: Functions like `VisitCreateObjectLiteral`, `VisitCreateClosure`, etc., point to a visitor pattern, where the code handles different bytecode instructions.
    * `Jump`, `JumpLoop`, `BranchIf...`: These indicate control flow within the generated graph.
    * `FeedbackSlot`, `compiler::...`:  These suggest interaction with V8's feedback system for optimization.
    * `is_inline()`: This implies different code paths based on whether a function is being inlined.
    * `arguments`, `rest parameter`:  These relate to how function arguments are handled in JavaScript.
    * `AllocationType`: This suggests memory management and object allocation.
    * `MergePointInterpreterFrameState`: This points to how the graph builder manages the state of the JavaScript interpreter's stack frames.
    * `PeelLoop`: This is a specific optimization technique for loops.

3. **Focus on Key Functions:**  Based on the initial scan, focus on the most prominent functions:

    * `BuildVirtualArgumentsObject`: This function seems central to how the `arguments` object is created, with different cases for sloppy, strict, and rest parameters.
    * `TryBuildFastCreateObjectOrArrayLiteral`: This suggests an optimization path for creating object and array literals.
    * The `Visit...` functions:  Each of these handles a specific bytecode instruction related to object creation, closures, contexts, and control flow.
    * `PeelLoop` and `BuildLoopForPeeling`: These are clearly related to loop optimization.

4. **Analyze Function Logic (with specific examples in mind):**  For each key function, try to understand its internal logic. Think about how this would translate to JavaScript behavior.

    * **`BuildVirtualArgumentsObject`:** Notice the different `CreateArgumentsType` cases.
        * **Sloppy:** Handles the historical `arguments` object with potential aliasing. The code differentiates between cases with and without parameter names. This leads to the JavaScript example about accessing named parameters vs. extra arguments.
        * **Unmapped:**  Represents the `arguments` object in strict mode, where there's no aliasing. This is a simpler case.
        * **Rest Parameter:** Handles the `...args` syntax, creating an array of the remaining arguments.
    * **`TryBuildFastCreateObjectOrArrayLiteral`:**  This suggests an optimization for simple object/array literals based on feedback. If the boilerplate is simple enough, it can be created quickly. The lack of a successful fast path leads to the fallback in `VisitCreateObjectLiteral`.
    * **`VisitCreateObjectLiteral`:** This shows the different ways object literals are created, including a fast path and a slower path using builtins. The example demonstrates basic object literal creation.
    * **`VisitCreateClosure`:**  This highlights the creation of function closures, with a fast path for simple cases.
    * **`VisitCreateContext` functions:** These demonstrate how different types of execution contexts are created (block, catch, function, eval, with). While providing direct JavaScript examples for all is harder, understanding the *purpose* of each context type (e.g., `catch` for error handling, `with` for the `with` statement) is important.
    * **`PeelLoop`:** Understand that loop peeling is about unrolling the first few iterations of a loop to potentially improve performance. The code manages the state for these peeled iterations.

5. **Relate to JavaScript Concepts:**  Continuously connect the C++ code back to familiar JavaScript concepts. How does the creation of a `VirtualArgumentsObject` relate to the `arguments` keyword in JavaScript? How does `CreateClosure` relate to the concept of closures in JavaScript?

6. **Address Specific Questions:**  Go back to the prompt and address each question directly:

    * **Functionality:** Summarize the overall purpose of the code.
    * **`.tq` extension:** Explain that it's not a Torque file.
    * **JavaScript relationship:** Provide concrete JavaScript examples for relevant functionalities.
    * **Code logic推理 (Reasoning):** If there are conditional branches or different code paths based on input, provide hypothetical inputs and outputs to illustrate the flow. For example, the different cases in `BuildVirtualArgumentsObject`.
    * **User programming errors:** Think about common mistakes related to the functionalities. For example, misunderstanding the behavior of the `arguments` object in sloppy mode.
    * **归纳功能 (Summary):**  Provide a concise summary of the code's role.

7. **Structure the Answer:** Organize the findings in a clear and logical way, addressing each point in the prompt. Use headings and bullet points for readability.

8. **Refine and Review:**  Read through the answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or missing information. For instance, initially, I might not have explicitly connected the `VisitCreateContext` functions to the different types of JavaScript scopes. Reviewing helps to make these connections. Also, double-check the provided JavaScript examples for correctness.

By following this iterative process of scanning, focusing, analyzing, connecting to JavaScript, and addressing specific questions, a comprehensive understanding of the provided V8 source code can be achieved.
好的，让我们来分析一下 `v8/src/maglev/maglev-graph-builder.cc` 的这个代码片段的功能。

**功能归纳:**

这段代码是 V8 的 Maglev 优化编译器中的一部分，主要负责在构建程序执行图（Maglev Graph）时处理与创建 JavaScript 对象、函数闭包、执行上下文以及函数参数相关的操作。 它根据不同的 JavaScript 语法和语义，生成相应的图节点，以便后续的优化和代码生成。 特别是，它对常见的对象和数组字面量创建进行了优化，并处理了不同类型的 `arguments` 对象。

**具体功能分解:**

1. **创建 `arguments` 对象:**
   -  `BuildVirtualArgumentsObject<type>()`:  根据 `CreateArgumentsType` 的不同值（`kMappedArguments`, `kUnmappedArguments`, `kRestParameter`），生成不同类型的 `arguments` 对象的虚拟表示。
   -  **`kMappedArguments` (Sloppy 模式):** 处理函数中使用了命名参数，并且可能存在 `arguments` 对象与命名参数别名的情况。  区分了内联（`is_inline()`）和非内联的情况。
   -  **`kUnmappedArguments` (Strict 模式):** 处理严格模式下的 `arguments` 对象，不存在别名。
   -  **`kRestParameter` (剩余参数):** 处理 `...args` 语法创建的参数数组。
   -  `BuildAndAllocateArgumentsObject<type>()`: 在堆上分配创建的 `arguments` 对象。

2. **快速创建对象和数组字面量:**
   - `TryBuildFastCreateObjectOrArrayLiteral(const compiler::LiteralFeedback& feedback)`:  尝试根据编译器的反馈信息，快速地内联分配和初始化对象或数组字面量。如果字面量结构简单且反馈信息充分，则可以避免调用运行时的慢速路径。

3. **创建对象字面量:**
   - `VisitCreateObjectLiteral()`: 处理 `CreateObjectLiteral` 字节码，根据反馈信息尝试快速创建，否则调用内置函数或运行时函数来创建对象。
   - `VisitCreateEmptyObjectLiteral()`: 处理创建空对象字面量的字节码，直接内联分配。
   - `VisitCloneObject()`: 处理克隆对象的字节码，调用内置函数 `kCloneObjectIC`。

4. **创建模板对象 (用于模板字面量):**
   - `VisitGetTemplateObject()`: 处理获取模板对象的字节码，从缓存或通过创建新的模板对象。

5. **创建闭包 (函数):**
   - `VisitCreateClosure()`: 处理创建函数闭包的字节码，根据标志位选择快速创建或普通创建方式。

6. **创建执行上下文:**
   - `TryBuildInlinedAllocatedContext()`: 尝试内联分配上下文。
   - `VisitCreateBlockContext()`: 处理创建块级作用域上下文的字节码。
   - `VisitCreateCatchContext()`: 处理 `try...catch` 语句创建的 catch 块上下文。
   - `VisitCreateFunctionContext()`: 处理创建函数执行上下文的字节码。
   - `VisitCreateEvalContext()`: 处理 `eval()` 调用创建的上下文。
   - `VisitCreateWithContext()`: 处理 `with` 语句创建的上下文。

7. **处理不同类型的 `arguments` 对象 (字节码处理):**
   - `VisitCreateMappedArguments()`: 处理 `CreateMappedArguments` 字节码。
   - `VisitCreateUnmappedArguments()`: 处理 `CreateUnmappedArguments` 字节码。
   - `VisitCreateRestParameter()`: 处理 `CreateRestParameter` 字节码。

8. **循环展开 (Loop Peeling):**
   - `PeelLoop()`:  实现循环展开优化，将循环的开头几次迭代展开，以减少循环开销并可能进行更积极的优化。
   - `BuildLoopForPeeling()`: 构建展开后的循环迭代。

9. **OSR 前奏分析:**
   - `OsrAnalyzePrequel()`:  在 On-Stack Replacement (OSR) 的入口点之前，分析代码以收集必要的信息。

10. **循环效果跟踪:**
    - `BeginLoopEffects()`, `EndLoopEffects()`: 用于跟踪循环对程序状态的影响，以便进行更精确的优化。

11. **处理跳转指令:**
    - `VisitJumpLoop()`: 处理循环跳转指令。
    - `VisitJump()`，`VisitJumpConstant()` 等：处理各种无条件和条件跳转指令，并维护图的连接和帧状态。
    - `MergeIntoFrameState()`:  在跳转目标处合并解释器帧状态。
    - `MergeDeadIntoFrameState()`:  处理不可达代码的帧状态合并。

12. **分支指令的构建:**
    - `BuildBranchIfReferenceEqual()`: 构建检查引用相等的条件分支节点。
    - `MarkBranchDeadAndJumpIfNeeded()`:  标记死分支并根据条件进行跳转。
    - `BuildBranchIfRootConstant()`: 构建与根常量比较的条件分支节点。

**与 JavaScript 功能的关系及示例:**

1. **`arguments` 对象:**

   ```javascript
   function sloppyFunction(a, b) {
     console.log(arguments[0]); // 可能输出 a 的值
     arguments[0] = 10;
     console.log(a);        // 在非严格模式下，可能输出 10 (别名)
     console.log(arguments);
   }

   function strictFunction(a, b) {
     'use strict';
     console.log(arguments[0]); // 输出传入的第一个参数
     arguments[0] = 10;
     console.log(a);        // 输出传入的 a 的值，不受 arguments 修改的影响
     console.log(arguments);
   }

   function restParameterFunction(...args) {
     console.log(args); // 输出一个包含所有传入参数的数组
   }

   sloppyFunction(1, 2);
   strictFunction(3, 4);
   restParameterFunction(5, 6, 7);
   ```

2. **对象和数组字面量:**

   ```javascript
   const obj = { x: 1, y: 2 }; // CreateObjectLiteral
   const arr = [1, 2, 3];     // TryBuildFastCreateObjectOrArrayLiteral (可能)
   const emptyObj = {};       // VisitCreateEmptyObjectLiteral
   ```

3. **函数闭包:**

   ```javascript
   function outer() {
     const x = 10;
     function inner() {
       console.log(x); // inner 函数闭包引用了 outer 的变量 x
     }
     return inner; // VisitCreateClosure 创建 inner 的闭包
   }

   const closure = outer();
   closure();
   ```

4. **执行上下文:**

   ```javascript
   let globalVar = 5; // 全局上下文

   function myFunction() { // 函数上下文
     let localVar = 10;
     console.log(globalVar);

     if (true) { // 块级上下文
       let blockVar = 15;
       console.log(blockVar);
     }

     try {
       throw new Error("oops");
     } catch (e) { // Catch 上下文
       console.error(e);
     }
   }

   function withStatement() {
     const obj = { a: 1, b: 2 };
     with (obj) { // With 上下文 (不推荐使用)
       console.log(a + b);
     }
   }

   myFunction();
   withStatement();
   ```

5. **剩余参数:**  如上面的 `restParameterFunction` 示例。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**  一个调用了 `sloppyFunction(1, 2)` 的 JavaScript 代码片段。

**`BuildVirtualArgumentsObject<kMappedArguments>` 的可能执行路径:**

- `parameter_count_without_receiver()` 为 2 (`a`, `b`)。
- `argument_count_without_receiver()` 为 2 (`1`, `2`)。
- 因为参数数量不为零，进入 `else` 分支。
- 假设是非内联情况 (`!is_inline()`)。
- 创建 `ArgumentsLength` 节点。
- 创建 `ArgumentsElements` 节点，类型为 `kMappedArguments`，参数数量为 2。
- 创建 `MappedArgumentsElements` 的虚拟对象。
- 循环设置映射关系，将 `arguments[0]` 和 `arguments[1]` 映射到对应的上下文参数索引。
- 创建 `ArgumentsObject` 节点，使用 `fast_aliased_arguments_map`。

**输出:**  生成 Maglev 图中表示 `arguments` 对象的节点，该节点会引用一个映射的元素存储，其中前两个元素与函数的参数 `a` 和 `b` 关联。

**用户常见的编程错误:**

1. **混淆 `arguments` 对象的行为:**  在非严格模式下，修改 `arguments` 对象的元素会影响到对应的命名参数，反之亦然。这可能会导致意外的行为，尤其是在不熟悉这种特性的开发者中。

   ```javascript
   function example(a) {
     arguments[0] = 100;
     console.log(a); // 在非严格模式下可能输出 100
   }
   example(50);
   ```

2. **在严格模式下错误地假设 `arguments` 的别名行为:**  严格模式下的 `arguments` 对象不会与命名参数产生别名，修改 `arguments` 不会影响命名参数的值。

   ```javascript
   function strictExample(a) {
     'use strict';
     arguments[0] = 100;
     console.log(a); // 始终输出传入的原始值
   }
   strictExample(50);
   ```

3. **过度依赖 `arguments` 对象:**  在现代 JavaScript 中，剩余参数 (`...args`) 提供了更清晰和灵活的方式来处理函数参数。过度使用 `arguments` 可能导致代码可读性下降。

4. **在箭头函数中使用 `arguments`:** 箭头函数没有自己的 `arguments` 对象，它会从最近的非箭头父作用域中捕获 `arguments`。这可能导致混淆。

**关于文件后缀 `.tq`:**

你提到 "如果 `v8/src/maglev/maglev-graph-builder.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码"。这是一个重要的区分。

- **`.cc` 文件:**  表示 C++ 源代码文件。你提供的代码是 C++ 代码。
- **`.tq` 文件:** 表示 Torque 源代码文件。Torque 是 V8 用于定义内置函数和运行时函数的领域特定语言。

因此，`v8/src/maglev/maglev-graph-builder.cc` 不是 Torque 文件，它是用 C++ 编写的。

**总结:**

`v8/src/maglev/maglev-graph-builder.cc` 的这一部分是 Maglev 编译器构建执行图的关键组件，它负责将 JavaScript 的对象创建、函数调用、上下文管理和参数处理等操作转换为图中的节点表示，并针对常见的字面量创建和 `arguments` 对象进行了优化。理解这部分代码有助于深入了解 V8 编译器的内部工作原理。

### 提示词
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第16部分，共18部分，请归纳一下它的功能
```

### 源代码
```cpp
parameter_count_without_receiver() == 0) {
        // If there is no aliasing, the arguments object elements are not
        // special in any way, we can just return an unmapped backing store.
        if (is_inline()) {
          int length = argument_count_without_receiver();
          ValueNode* elements = BuildInlinedArgumentsElements(0, length);
          return CreateArgumentsObject(
              broker()->target_native_context().sloppy_arguments_map(broker()),
              GetInt32Constant(length), elements, GetClosure());
        } else {
          ArgumentsLength* length = AddNewNode<ArgumentsLength>({});
          EnsureType(length, NodeType::kSmi);
          ArgumentsElements* elements = AddNewNode<ArgumentsElements>(
              {length}, CreateArgumentsType::kUnmappedArguments,
              parameter_count_without_receiver());
          return CreateArgumentsObject(
              broker()->target_native_context().sloppy_arguments_map(broker()),
              length, elements, GetClosure());
        }
      } else {
        // If the parameter count is zero, we should have used the unmapped
        // backing store.
        int param_count = parameter_count_without_receiver();
        DCHECK_GT(param_count, 0);
        DCHECK(CanAllocateSloppyArgumentElements());
        int param_idx_in_ctxt = compilation_unit_->shared_function_info()
                                    .context_parameters_start() +
                                param_count - 1;
        // The {unmapped_elements} correspond to the extra arguments
        // (overapplication) that do not need be "mapped" to the actual
        // arguments. Mapped arguments are accessed via the context, whereas
        // unmapped arguments are simply accessed via this fixed array. See
        // SloppyArgumentsElements in src/object/arguments.h.
        if (is_inline()) {
          int length = argument_count_without_receiver();
          int mapped_count = std::min(param_count, length);
          ValueNode* unmapped_elements =
              BuildInlinedUnmappedArgumentsElements(mapped_count);
          VirtualObject* elements = CreateMappedArgumentsElements(
              broker()->sloppy_arguments_elements_map(), mapped_count,
              GetContext(), unmapped_elements);
          for (int i = 0; i < mapped_count; i++, param_idx_in_ctxt--) {
            elements->set(SloppyArgumentsElements::OffsetOfElementAt(i),
                          GetInt32Constant(param_idx_in_ctxt));
          }
          return CreateArgumentsObject(
              broker()->target_native_context().fast_aliased_arguments_map(
                  broker()),
              GetInt32Constant(length), elements, GetClosure());
        } else {
          ArgumentsLength* length = AddNewNode<ArgumentsLength>({});
          EnsureType(length, NodeType::kSmi);
          ArgumentsElements* unmapped_elements = AddNewNode<ArgumentsElements>(
              {length}, CreateArgumentsType::kMappedArguments, param_count);
          VirtualObject* elements = CreateMappedArgumentsElements(
              broker()->sloppy_arguments_elements_map(), param_count,
              GetContext(), unmapped_elements);
          ValueNode* the_hole_value = GetConstant(broker()->the_hole_value());
          for (int i = 0; i < param_count; i++, param_idx_in_ctxt--) {
            ValueNode* value = Select(
                [&](auto& builder) {
                  return BuildBranchIfInt32Compare(builder,
                                                   Operation::kLessThan,
                                                   GetInt32Constant(i), length);
                },
                [&] { return GetSmiConstant(param_idx_in_ctxt); },
                [&] { return the_hole_value; });
            elements->set(SloppyArgumentsElements::OffsetOfElementAt(i), value);
          }
          return CreateArgumentsObject(
              broker()->target_native_context().fast_aliased_arguments_map(
                  broker()),
              length, elements, GetClosure());
        }
      }
    case CreateArgumentsType::kUnmappedArguments:
      if (is_inline()) {
        int length = argument_count_without_receiver();
        ValueNode* elements = BuildInlinedArgumentsElements(0, length);
        return CreateArgumentsObject(
            broker()->target_native_context().strict_arguments_map(broker()),
            GetInt32Constant(length), elements);
      } else {
        ArgumentsLength* length = AddNewNode<ArgumentsLength>({});
        EnsureType(length, NodeType::kSmi);
        ArgumentsElements* elements = AddNewNode<ArgumentsElements>(
            {length}, CreateArgumentsType::kUnmappedArguments,
            parameter_count_without_receiver());
        return CreateArgumentsObject(
            broker()->target_native_context().strict_arguments_map(broker()),
            length, elements);
      }
    case CreateArgumentsType::kRestParameter:
      if (is_inline()) {
        int start_index = parameter_count_without_receiver();
        int length =
            std::max(0, argument_count_without_receiver() - start_index);
        ValueNode* elements =
            BuildInlinedArgumentsElements(start_index, length);
        return CreateArgumentsObject(
            broker()->target_native_context().js_array_packed_elements_map(
                broker()),
            GetInt32Constant(length), elements);
      } else {
        ArgumentsLength* length = AddNewNode<ArgumentsLength>({});
        EnsureType(length, NodeType::kSmi);
        ArgumentsElements* elements = AddNewNode<ArgumentsElements>(
            {length}, CreateArgumentsType::kRestParameter,
            parameter_count_without_receiver());
        RestLength* rest_length =
            AddNewNode<RestLength>({}, parameter_count_without_receiver());
        return CreateArgumentsObject(
            broker()->target_native_context().js_array_packed_elements_map(
                broker()),
            rest_length, elements);
      }
  }
}

template <CreateArgumentsType type>
ValueNode* MaglevGraphBuilder::BuildAndAllocateArgumentsObject() {
  auto arguments = BuildVirtualArgumentsObject<type>();
  ValueNode* allocation =
      BuildInlinedAllocation(arguments, AllocationType::kYoung);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the next side
  // effect clear it.
  ClearCurrentAllocationBlock();
  return allocation;
}

ReduceResult MaglevGraphBuilder::TryBuildFastCreateObjectOrArrayLiteral(
    const compiler::LiteralFeedback& feedback) {
  compiler::AllocationSiteRef site = feedback.value();
  if (!site.boilerplate(broker()).has_value()) return ReduceResult::Fail();
  AllocationType allocation_type =
      broker()->dependencies()->DependOnPretenureMode(site);

  // First try to extract out the shape and values of the boilerplate, bailing
  // out on complex boilerplates.
  int max_properties = compiler::kMaxFastLiteralProperties;
  std::optional<VirtualObject*> maybe_value = TryReadBoilerplateForFastLiteral(
      *site.boilerplate(broker()), allocation_type,
      compiler::kMaxFastLiteralDepth, &max_properties);
  if (!maybe_value.has_value()) return ReduceResult::Fail();

  // Then, use the collected information to actually create nodes in the graph.
  // TODO(leszeks): Add support for unwinding graph modifications, so that we
  // can get rid of this two pass approach.
  broker()->dependencies()->DependOnElementsKinds(site);
  ReduceResult result = BuildInlinedAllocation(*maybe_value, allocation_type);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the next side
  // effect clear it.
  ClearCurrentAllocationBlock();
  return result;
}

void MaglevGraphBuilder::VisitCreateObjectLiteral() {
  compiler::ObjectBoilerplateDescriptionRef boilerplate_desc =
      GetRefOperand<ObjectBoilerplateDescription>(0);
  FeedbackSlot slot_index = GetSlotOperand(1);
  int bytecode_flags = GetFlag8Operand(2);
  int literal_flags =
      interpreter::CreateObjectLiteralFlags::FlagsBits::decode(bytecode_flags);
  compiler::FeedbackSource feedback_source(feedback(), slot_index);

  compiler::ProcessedFeedback const& processed_feedback =
      broker()->GetFeedbackForArrayOrObjectLiteral(feedback_source);
  if (processed_feedback.IsInsufficient()) {
    RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
        DeoptimizeReason::kInsufficientTypeFeedbackForObjectLiteral));
  }

  ReduceResult result =
      TryBuildFastCreateObjectOrArrayLiteral(processed_feedback.AsLiteral());
  PROCESS_AND_RETURN_IF_DONE(result, SetAccumulator);

  if (interpreter::CreateObjectLiteralFlags::FastCloneSupportedBit::decode(
          bytecode_flags)) {
    // TODO(victorgomes): CreateShallowObjectLiteral should not need the
    // boilerplate descriptor. However the current builtin checks that the
    // feedback exists and fallsback to CreateObjectLiteral if it doesn't.
    SetAccumulator(AddNewNode<CreateShallowObjectLiteral>(
        {}, boilerplate_desc, feedback_source, literal_flags));
  } else {
    SetAccumulator(AddNewNode<CreateObjectLiteral>(
        {}, boilerplate_desc, feedback_source, literal_flags));
  }
}

void MaglevGraphBuilder::VisitCreateEmptyObjectLiteral() {
  compiler::NativeContextRef native_context = broker()->target_native_context();
  compiler::MapRef map =
      native_context.object_function(broker()).initial_map(broker());
  DCHECK(!map.is_dictionary_map());
  DCHECK(!map.IsInobjectSlackTrackingInProgress());
  SetAccumulator(
      BuildInlinedAllocation(CreateJSObject(map), AllocationType::kYoung));
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the next side
  // effect clear it.
  ClearCurrentAllocationBlock();
}

void MaglevGraphBuilder::VisitCloneObject() {
  // CloneObject <source_idx> <flags> <feedback_slot>
  ValueNode* source = LoadRegister(0);
  ValueNode* flags =
      GetSmiConstant(interpreter::CreateObjectLiteralFlags::FlagsBits::decode(
          GetFlag8Operand(1)));
  FeedbackSlot slot = GetSlotOperand(2);
  compiler::FeedbackSource feedback_source{feedback(), slot};
  SetAccumulator(BuildCallBuiltin<Builtin::kCloneObjectIC>(
      {GetTaggedValue(source), flags}, feedback_source));
}

void MaglevGraphBuilder::VisitGetTemplateObject() {
  // GetTemplateObject <descriptor_idx> <literal_idx>
  compiler::SharedFunctionInfoRef shared_function_info =
      compilation_unit_->shared_function_info();
  ValueNode* description = GetConstant(GetRefOperand<HeapObject>(0));
  FeedbackSlot slot = GetSlotOperand(1);
  compiler::FeedbackSource feedback_source{feedback(), slot};

  const compiler::ProcessedFeedback& feedback =
      broker()->GetFeedbackForTemplateObject(feedback_source);
  if (feedback.IsInsufficient()) {
    return SetAccumulator(AddNewNode<GetTemplateObject>(
        {description}, shared_function_info, feedback_source));
  }
  compiler::JSArrayRef template_object = feedback.AsTemplateObject().value();
  SetAccumulator(GetConstant(template_object));
}

void MaglevGraphBuilder::VisitCreateClosure() {
  compiler::SharedFunctionInfoRef shared_function_info =
      GetRefOperand<SharedFunctionInfo>(0);
  compiler::FeedbackCellRef feedback_cell =
      feedback().GetClosureFeedbackCell(broker(), iterator_.GetIndexOperand(1));
  uint32_t flags = GetFlag8Operand(2);

  if (interpreter::CreateClosureFlags::FastNewClosureBit::decode(flags)) {
    SetAccumulator(AddNewNode<FastCreateClosure>(
        {GetContext()}, shared_function_info, feedback_cell));
  } else {
    bool pretenured =
        interpreter::CreateClosureFlags::PretenuredBit::decode(flags);
    SetAccumulator(AddNewNode<CreateClosure>(
        {GetContext()}, shared_function_info, feedback_cell, pretenured));
  }
}

ReduceResult MaglevGraphBuilder::TryBuildInlinedAllocatedContext(
    compiler::MapRef map, compiler::ScopeInfoRef scope, int context_length) {
  const int kContextAllocationLimit = 16;
  if (context_length > kContextAllocationLimit) {
    return ReduceResult::Fail();
  }
  DCHECK_GE(context_length, Context::MIN_CONTEXT_SLOTS);
  auto context = CreateContext(map, context_length, scope, GetContext());
  ValueNode* result = BuildInlinedAllocation(context, AllocationType::kYoung);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the next side
  // effect clear it.
  ClearCurrentAllocationBlock();
  return result;
}

void MaglevGraphBuilder::VisitCreateBlockContext() {
  // CreateBlockContext <scope_info_idx>
  compiler::ScopeInfoRef scope_info = GetRefOperand<ScopeInfo>(0);
  compiler::MapRef map =
      broker()->target_native_context().block_context_map(broker());

  auto done = [&](ValueNode* res) {
    graph()->record_scope_info(res, scope_info);
    SetAccumulator(res);
  };

  PROCESS_AND_RETURN_IF_DONE(TryBuildInlinedAllocatedContext(
                                 map, scope_info, scope_info.ContextLength()),
                             done);
  // Fallback.
  done(BuildCallRuntime(Runtime::kPushBlockContext, {GetConstant(scope_info)})
           .value());
}

void MaglevGraphBuilder::VisitCreateCatchContext() {
  // CreateCatchContext <exception> <scope_info_idx>
  ValueNode* exception = LoadRegister(0);
  compiler::ScopeInfoRef scope_info = GetRefOperand<ScopeInfo>(1);
  auto context = CreateContext(
      broker()->target_native_context().catch_context_map(broker()),
      Context::MIN_CONTEXT_EXTENDED_SLOTS, scope_info, GetContext(), exception);
  SetAccumulator(BuildInlinedAllocation(context, AllocationType::kYoung));
  graph()->record_scope_info(GetAccumulator(), scope_info);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the next side
  // effect clear it.
  ClearCurrentAllocationBlock();
}

void MaglevGraphBuilder::VisitCreateFunctionContext() {
  compiler::ScopeInfoRef info = GetRefOperand<ScopeInfo>(0);
  uint32_t slot_count = iterator_.GetUnsignedImmediateOperand(1);
  compiler::MapRef map =
      broker()->target_native_context().function_context_map(broker());

  auto done = [&](ValueNode* res) {
    graph()->record_scope_info(res, info);
    SetAccumulator(res);
  };

  PROCESS_AND_RETURN_IF_DONE(
      TryBuildInlinedAllocatedContext(map, info,
                                      slot_count + Context::MIN_CONTEXT_SLOTS),
      done);
  // Fallback.
  done(AddNewNode<CreateFunctionContext>({GetContext()}, info, slot_count,
                                         ScopeType::FUNCTION_SCOPE));
}

void MaglevGraphBuilder::VisitCreateEvalContext() {
  compiler::ScopeInfoRef info = GetRefOperand<ScopeInfo>(0);
  uint32_t slot_count = iterator_.GetUnsignedImmediateOperand(1);
  compiler::MapRef map =
      broker()->target_native_context().eval_context_map(broker());

  auto done = [&](ValueNode* res) {
    graph()->record_scope_info(res, info);
    SetAccumulator(res);
  };

  PROCESS_AND_RETURN_IF_DONE(
      TryBuildInlinedAllocatedContext(map, info,
                                      slot_count + Context::MIN_CONTEXT_SLOTS),
      done);
  if (slot_count <= static_cast<uint32_t>(
                        ConstructorBuiltins::MaximumFunctionContextSlots())) {
    done(AddNewNode<CreateFunctionContext>({GetContext()}, info, slot_count,
                                           ScopeType::EVAL_SCOPE));
  } else {
    done(BuildCallRuntime(Runtime::kNewFunctionContext, {GetConstant(info)})
             .value());
  }
}

void MaglevGraphBuilder::VisitCreateWithContext() {
  // CreateWithContext <register> <scope_info_idx>
  ValueNode* object = LoadRegister(0);
  compiler::ScopeInfoRef scope_info = GetRefOperand<ScopeInfo>(1);
  auto context = CreateContext(
      broker()->target_native_context().with_context_map(broker()),
      Context::MIN_CONTEXT_EXTENDED_SLOTS, scope_info, GetContext(), object);
  SetAccumulator(BuildInlinedAllocation(context, AllocationType::kYoung));
  graph()->record_scope_info(GetAccumulator(), scope_info);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the next side
  // effect clear it.
  ClearCurrentAllocationBlock();
}

bool MaglevGraphBuilder::CanAllocateSloppyArgumentElements() {
  return SloppyArgumentsElements::SizeFor(parameter_count()) <=
         kMaxRegularHeapObjectSize;
}

bool MaglevGraphBuilder::CanAllocateInlinedArgumentElements() {
  DCHECK(is_inline());
  return FixedArray::SizeFor(argument_count_without_receiver()) <=
         kMaxRegularHeapObjectSize;
}

void MaglevGraphBuilder::VisitCreateMappedArguments() {
  compiler::SharedFunctionInfoRef shared =
      compilation_unit_->shared_function_info();
  if (!shared.object()->has_duplicate_parameters()) {
    if (((is_inline() && CanAllocateInlinedArgumentElements()) ||
         (!is_inline() && CanAllocateSloppyArgumentElements()))) {
      SetAccumulator(BuildAndAllocateArgumentsObject<
                     CreateArgumentsType::kMappedArguments>());
      return;
    } else if (!is_inline()) {
      SetAccumulator(
          BuildCallBuiltin<Builtin::kFastNewSloppyArguments>({GetClosure()}));
      return;
    }
  }
  // Generic fallback.
  SetAccumulator(
      BuildCallRuntime(Runtime::kNewSloppyArguments, {GetClosure()}).value());
}

void MaglevGraphBuilder::VisitCreateUnmappedArguments() {
  if (!is_inline() || CanAllocateInlinedArgumentElements()) {
    SetAccumulator(BuildAndAllocateArgumentsObject<
                   CreateArgumentsType::kUnmappedArguments>());
    return;
  }
  // Generic fallback.
  SetAccumulator(
      BuildCallRuntime(Runtime::kNewStrictArguments, {GetClosure()}).value());
}

void MaglevGraphBuilder::VisitCreateRestParameter() {
  if (!is_inline() || CanAllocateInlinedArgumentElements()) {
    SetAccumulator(
        BuildAndAllocateArgumentsObject<CreateArgumentsType::kRestParameter>());
    return;
  }
  // Generic fallback.
  SetAccumulator(
      BuildCallRuntime(Runtime::kNewRestParameter, {GetClosure()}).value());
}

void MaglevGraphBuilder::PeelLoop() {
  int loop_header = iterator_.current_offset();
  DCHECK(loop_headers_to_peel_.Contains(loop_header));
  DCHECK(!in_peeled_iteration());
  peeled_iteration_count_ = v8_flags.maglev_optimistic_peeled_loops ? 2 : 1;
  any_peeled_loop_ = true;
  allow_loop_peeling_ = false;

  if (v8_flags.trace_maglev_graph_building) {
    std::cout << "  * Begin loop peeling...." << std::endl;
  }

  while (in_peeled_iteration()) {
    BuildLoopForPeeling();
  }
  // Emit the actual (not peeled) loop if needed.
  if (loop_header == iterator_.current_offset()) {
    BuildLoopForPeeling();
  }
  allow_loop_peeling_ = true;
}

void MaglevGraphBuilder::BuildLoopForPeeling() {
  int loop_header = iterator_.current_offset();
  DCHECK(loop_headers_to_peel_.Contains(loop_header));

  // Since peeled loops do not start with a loop merge state, we need to
  // explicitly enter e loop effect tracking scope for the peeled iteration.
  bool track_peeled_effects =
      v8_flags.maglev_optimistic_peeled_loops && peeled_iteration_count_ == 2;
  if (track_peeled_effects) {
    BeginLoopEffects(loop_header);
  }

#ifdef DEBUG
  bool was_in_peeled_iteration = in_peeled_iteration();
#endif  // DEBUG

  while (iterator_.current_bytecode() != interpreter::Bytecode::kJumpLoop) {
    local_isolate_->heap()->Safepoint();
    VisitSingleBytecode();
    iterator_.Advance();
  }

  VisitSingleBytecode();  // VisitJumpLoop

  DCHECK_EQ(was_in_peeled_iteration, in_peeled_iteration());
  if (!in_peeled_iteration()) {
    return;
  }

  // In case the peeled iteration was mergeable (see TryMergeLoop) or the
  // JumpLoop was dead, we are done.
  if (!current_block_) {
    decremented_predecessor_offsets_.clear();
    KillPeeledLoopTargets(peeled_iteration_count_);
    peeled_iteration_count_ = 0;
    if (track_peeled_effects) {
      EndLoopEffects(loop_header);
    }
    return;
  }

  peeled_iteration_count_--;

  // After processing the peeled iteration and reaching the `JumpLoop`, we
  // re-process the loop body. For this, we need to reset the graph building
  // state roughly as if we didn't process it yet.

  // Reset position in exception handler table to before the loop.
  HandlerTable table(*bytecode().object());
  while (next_handler_table_index_ > 0) {
    next_handler_table_index_--;
    int start = table.GetRangeStart(next_handler_table_index_);
    if (start < loop_header) break;
  }

  // Re-create catch handler merge states.
  for (int offset = loop_header; offset <= iterator_.current_offset();
       ++offset) {
    if (auto& merge_state = merge_states_[offset]) {
      if (merge_state->is_exception_handler()) {
        merge_state = MergePointInterpreterFrameState::NewForCatchBlock(
            *compilation_unit_, merge_state->frame_state().liveness(), offset,
            merge_state->exception_handler_was_used(),
            merge_state->catch_block_context_register(), graph_);
      } else {
        // We only peel innermost loops.
        DCHECK(!merge_state->is_loop());
        merge_state = nullptr;
      }
    }
    new (&jump_targets_[offset]) BasicBlockRef();
  }

  // Reset predecessors as if the loop body had not been visited.
  for (int offset : decremented_predecessor_offsets_) {
    DCHECK_GE(offset, loop_header);
    if (offset <= iterator_.current_offset()) {
      UpdatePredecessorCount(offset, 1);
    }
  }
  decremented_predecessor_offsets_.clear();

  DCHECK(current_block_);
  // After resetting, the actual loop header always has exactly 2
  // predecessors: the two copies of `JumpLoop`.
  InitializePredecessorCount(loop_header, 2);
  merge_states_[loop_header] = MergePointInterpreterFrameState::NewForLoop(
      current_interpreter_frame_, *compilation_unit_, loop_header, 2,
      GetInLivenessFor(loop_header),
      &bytecode_analysis_.GetLoopInfoFor(loop_header),
      /* has_been_peeled */ true);

  BasicBlock* block = FinishBlock<Jump>({}, &jump_targets_[loop_header]);
  // If we ever want more peelings, we should ensure that only the last one
  // creates a loop header.
  DCHECK_LE(peeled_iteration_count_, 1);
  DCHECK_IMPLIES(in_peeled_iteration(),
                 v8_flags.maglev_optimistic_peeled_loops);
  merge_states_[loop_header]->InitializeLoop(
      this, *compilation_unit_, current_interpreter_frame_, block,
      in_peeled_iteration(), loop_effects_);

  if (track_peeled_effects) {
    EndLoopEffects(loop_header);
  }
  DCHECK_NE(iterator_.current_offset(), loop_header);
  iterator_.SetOffset(loop_header);
}

void MaglevGraphBuilder::OsrAnalyzePrequel() {
  DCHECK_EQ(compilation_unit_->info()->toplevel_compilation_unit(),
            compilation_unit_);

  // TODO(olivf) We might want to start collecting known_node_aspects_ here.
  for (iterator_.SetOffset(0); iterator_.current_offset() != entrypoint_;
       iterator_.Advance()) {
    switch (iterator_.current_bytecode()) {
      case interpreter::Bytecode::kPushContext: {
        graph()->record_scope_info(GetContext(), {});
        // Nothing left to analyze...
        return;
      }
      default:
        continue;
    }
  }
}

void MaglevGraphBuilder::BeginLoopEffects(int loop_header) {
  loop_effects_stack_.push_back(zone()->New<LoopEffects>(loop_header, zone()));
  loop_effects_ = loop_effects_stack_.back();
}

void MaglevGraphBuilder::EndLoopEffects(int loop_header) {
  DCHECK_EQ(loop_effects_, loop_effects_stack_.back());
  DCHECK_EQ(loop_effects_->loop_header, loop_header);
  // TODO(olivf): Update merge states dominated by the loop header with
  // information we know to be unaffected by the loop.
  if (merge_states_[loop_header] && merge_states_[loop_header]->is_loop()) {
    merge_states_[loop_header]->set_loop_effects(loop_effects_);
  }
  if (loop_effects_stack_.size() > 1) {
    LoopEffects* inner_effects = loop_effects_;
    loop_effects_ = *(loop_effects_stack_.end() - 2);
    loop_effects_->Merge(inner_effects);
  } else {
    loop_effects_ = nullptr;
  }
  loop_effects_stack_.pop_back();
}

void MaglevGraphBuilder::VisitJumpLoop() {
  const uint32_t relative_jump_bytecode_offset =
      iterator_.GetUnsignedImmediateOperand(0);
  const int32_t loop_offset = iterator_.GetImmediateOperand(1);
  const FeedbackSlot feedback_slot = iterator_.GetSlotOperand(2);
  int target = iterator_.GetJumpTargetOffset();

  if (ShouldEmitInterruptBudgetChecks()) {
    int reduction = relative_jump_bytecode_offset *
                    v8_flags.osr_from_maglev_interrupt_scale_factor;
    AddNewNode<ReduceInterruptBudgetForLoop>({}, reduction > 0 ? reduction : 1);
  } else {
    AddNewNode<HandleNoHeapWritesInterrupt>({});
  }

  if (ShouldEmitOsrInterruptBudgetChecks()) {
    AddNewNode<TryOnStackReplacement>(
        {GetClosure()}, loop_offset, feedback_slot,
        BytecodeOffset(iterator_.current_offset()), compilation_unit_);
  }

  bool is_peeled_loop = loop_headers_to_peel_.Contains(target);
  auto FinishLoopBlock = [&]() {
    return FinishBlock<JumpLoop>({}, jump_targets_[target].block_ptr());
  };
  if (is_peeled_loop && in_peeled_iteration()) {
    ClobberAccumulator();
    if (in_optimistic_peeling_iteration()) {
      // Let's see if we can finish this loop without peeling it.
      if (!merge_states_[target]->TryMergeLoop(this, current_interpreter_frame_,
                                               FinishLoopBlock)) {
        merge_states_[target]->MergeDeadLoop(*compilation_unit());
      }
      if (is_loop_effect_tracking_enabled()) {
        EndLoopEffects(target);
      }
    }
  } else {
    BasicBlock* block = FinishLoopBlock();
    merge_states_[target]->MergeLoop(this, current_interpreter_frame_, block);
    block->set_predecessor_id(merge_states_[target]->predecessor_count() - 1);
    if (is_peeled_loop) {
      DCHECK(!in_peeled_iteration());
    }
    if (is_loop_effect_tracking_enabled()) {
      EndLoopEffects(target);
    }
  }
}
void MaglevGraphBuilder::VisitJump() {
  BasicBlock* block =
      FinishBlock<Jump>({}, &jump_targets_[iterator_.GetJumpTargetOffset()]);
  MergeIntoFrameState(block, iterator_.GetJumpTargetOffset());
  DCHECK_EQ(current_block_, nullptr);
  DCHECK_LT(next_offset(), bytecode().length());
}
void MaglevGraphBuilder::VisitJumpConstant() { VisitJump(); }
void MaglevGraphBuilder::VisitJumpIfNullConstant() { VisitJumpIfNull(); }
void MaglevGraphBuilder::VisitJumpIfNotNullConstant() { VisitJumpIfNotNull(); }
void MaglevGraphBuilder::VisitJumpIfUndefinedConstant() {
  VisitJumpIfUndefined();
}
void MaglevGraphBuilder::VisitJumpIfNotUndefinedConstant() {
  VisitJumpIfNotUndefined();
}
void MaglevGraphBuilder::VisitJumpIfUndefinedOrNullConstant() {
  VisitJumpIfUndefinedOrNull();
}
void MaglevGraphBuilder::VisitJumpIfTrueConstant() { VisitJumpIfTrue(); }
void MaglevGraphBuilder::VisitJumpIfFalseConstant() { VisitJumpIfFalse(); }
void MaglevGraphBuilder::VisitJumpIfJSReceiverConstant() {
  VisitJumpIfJSReceiver();
}
void MaglevGraphBuilder::VisitJumpIfForInDoneConstant() {
  VisitJumpIfForInDone();
}
void MaglevGraphBuilder::VisitJumpIfToBooleanTrueConstant() {
  VisitJumpIfToBooleanTrue();
}
void MaglevGraphBuilder::VisitJumpIfToBooleanFalseConstant() {
  VisitJumpIfToBooleanFalse();
}

void MaglevGraphBuilder::MergeIntoFrameState(BasicBlock* predecessor,
                                             int target) {
  if (merge_states_[target] == nullptr) {
    bool jumping_to_peeled_iteration = bytecode_analysis().IsLoopHeader(target);
    DCHECK_EQ(jumping_to_peeled_iteration,
              loop_headers_to_peel_.Contains(target));
    const compiler::BytecodeLivenessState* liveness = GetInLivenessFor(target);
    if (jumping_to_peeled_iteration) {
      // The peeled iteration is missing the backedge.
      DecrementDeadPredecessorAndAccountForPeeling(target);
    }
    // If there's no target frame state, allocate a new one.
    merge_states_[target] = MergePointInterpreterFrameState::New(
        *compilation_unit_, current_interpreter_frame_, target,
        predecessor_count(target), predecessor, liveness);
  } else {
    // If there already is a frame state, merge.
    merge_states_[target]->Merge(this, current_interpreter_frame_, predecessor);
  }
}

void MaglevGraphBuilder::MergeDeadIntoFrameState(int target) {
  // If there already is a frame state, merge.
  if (merge_states_[target]) {
    DCHECK_EQ(merge_states_[target]->predecessor_count(),
              predecessor_count(target));
    merge_states_[target]->MergeDead(*compilation_unit_);
    // If this merge is the last one which kills a loop merge, remove that
    // merge state.
    if (merge_states_[target]->is_unreachable_loop()) {
      if (v8_flags.trace_maglev_graph_building) {
        std::cout << "! Killing loop merge state at @" << target << std::endl;
      }
      merge_states_[target] = nullptr;
    }
  }
  // If there is no merge state yet, don't create one, but just reduce the
  // number of possible predecessors to zero.
  DecrementDeadPredecessorAndAccountForPeeling(target);
}

void MaglevGraphBuilder::MergeDeadLoopIntoFrameState(int target) {
  // Check if the Loop entry is dead already (e.g. an outer loop from OSR).
  if (V8_UNLIKELY(!merge_states_[target]) && predecessor_count(target) == 0) {
    static_assert(kLoopsMustBeEnteredThroughHeader);
    return;
  }
  // If there already is a frame state, merge.
  if (V8_LIKELY(merge_states_[target])) {
    DCHECK_EQ(merge_states_[target]->predecessor_count(),
              predecessor_count(target));
    if (is_loop_effect_tracking_enabled() &&
        !merge_states_[target]->is_unreachable_loop()) {
      EndLoopEffects(target);
    }
    merge_states_[target]->MergeDeadLoop(*compilation_unit_);
  }
  // If there is no merge state yet, don't create one, but just reduce the
  // number of possible predecessors to zero.
  DecrementDeadPredecessorAndAccountForPeeling(target);
}

void MaglevGraphBuilder::MergeIntoInlinedReturnFrameState(
    BasicBlock* predecessor) {
  int target = inline_exit_offset();
  if (merge_states_[target] == nullptr) {
    // All returns should have the same liveness, which is that only the
    // accumulator is live.
    const compiler::BytecodeLivenessState* liveness = GetInLiveness();
    DCHECK(liveness->AccumulatorIsLive());
    DCHECK_EQ(liveness->live_value_count(), 1);

    // If there's no target frame state, allocate a new one.
    merge_states_[target] = MergePointInterpreterFrameState::New(
        *compilation_unit_, current_interpreter_frame_, target,
        predecessor_count(target), predecessor, liveness);
  } else {
    // Again, all returns should have the same liveness, so double check this.
    DCHECK(GetInLiveness()->Equals(
        *merge_states_[target]->frame_state().liveness()));
    merge_states_[target]->Merge(this, current_interpreter_frame_, predecessor);
  }
}

MaglevGraphBuilder::BranchResult
MaglevGraphBuilder::BuildBranchIfReferenceEqual(BranchBuilder& builder,
                                                ValueNode* lhs,
                                                ValueNode* rhs) {
  if (RootConstant* root_constant = rhs->TryCast<RootConstant>()) {
    return builder.Build<BranchIfRootConstant>({lhs}, root_constant->index());
  }
  if (RootConstant* root_constant = lhs->TryCast<RootConstant>()) {
    return builder.Build<BranchIfRootConstant>({rhs}, root_constant->index());
  }
  if (InlinedAllocation* alloc_lhs = lhs->TryCast<InlinedAllocation>()) {
    if (InlinedAllocation* alloc_rhs = rhs->TryCast<InlinedAllocation>()) {
      return builder.FromBool(alloc_lhs == alloc_rhs);
    }
  }

  return builder.Build<BranchIfReferenceEqual>({lhs, rhs});
}

void MaglevGraphBuilder::MarkBranchDeadAndJumpIfNeeded(bool is_jump_taken) {
  int jump_offset = iterator_.GetJumpTargetOffset();
  if (is_jump_taken) {
    BasicBlock* block = FinishBlock<Jump>({}, &jump_targets_[jump_offset]);
    MergeDeadIntoFrameState(next_offset());
    MergeIntoFrameState(block, jump_offset);
  } else {
    MergeDeadIntoFrameState(jump_offset);
  }
}

#ifdef DEBUG
namespace {
bool IsNumberRootConstant(RootIndex root_index) {
  switch (root_index) {
#define CASE(type, name, label) case RootIndex::k##label:
    SMI_ROOT_LIST(CASE)
    STRONG_READ_ONLY_HEAP_NUMBER_ROOT_LIST(CASE)
    return true;
    default:
      return false;
  }
#undef CASE
}
}  // namespace
#endif

MaglevGraphBuilder::BranchResult MaglevGraphBuilder::BuildBranchIfRootConstant(
    BranchBuilder& builder, ValueNode* node, RootIndex root_index) {
  // We assume that Maglev never emits a comparison to a root number.
  DCHECK(!IsNumberRootConstant(root_index));

  // If the node we're checking is in the accumulator, swap it in the branch
  // with the checked value. Cache whether we want to swap, since after we've
  // swapped the accumulator isn't the original node anymore.
  BranchBuilder::PatchAccumulatorInBranchScope scope(builder, node, root_index
```