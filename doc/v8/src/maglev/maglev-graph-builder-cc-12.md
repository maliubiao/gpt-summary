Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/maglev/maglev-graph-builder.cc`.

Here's a plan to address the request:

1. **High-level overview:**  Identify the primary purpose of this code based on the file name and the content. It seems to be related to building a graph for the Maglev compiler in V8, specifically handling function calls and related operations.
2. **Function-by-function analysis:** Go through each function in the snippet and describe its individual role.
3. **Relationship to JavaScript:**  Explain how the operations performed in the C++ code relate to JavaScript concepts like function calls, `apply`, `call`, `new`, and array construction. Provide JavaScript examples.
4. **Code logic reasoning:** For functions with conditional logic, construct hypothetical input and output scenarios.
5. **Common programming errors:** Identify potential JavaScript errors that the code might be designed to handle or optimize.
6. **File purpose summary:** Based on the analysis, provide a concise summary of the file's overall function within the Maglev compiler.
7. **Address the ".tq" check:** Explicitly mention that this is not a Torque file.
8. **Address the part number:** Acknowledge that this is part 13 of 18.
目录 `v8/src/maglev/maglev-graph-builder.cc` 的主要功能是构建用于 V8 Maglev 编译器的图结构。 这个图表示了 JavaScript 代码的执行流程， Maglev 编译器会基于这个图生成优化的机器码。

以下是代码片段中各个函数的功能的详细说明：

1. **`TryInferApiHolderOfExpectedType`**:
   - **功能**: 尝试推断给定函数模板期望的 API 持有者（API Holder）。API 持有者通常是与 JavaScript 对象关联的 C++ 对象。
   - **输入**:
     - `function_template_info`:  关于函数模板的信息。
     - `receiver_info`: 关于接收者（`this`）的信息。
   - **输出**:
     - `api_holder`: 如果能够成功推断出唯一的 API 持有者，则返回该持有者的信息。
     - `not_found`: 如果无法推断或者存在多个可能的 API 持有者，则返回 `not_found`。
   - **代码逻辑推理**:
     - 检查是否已知接收者的所有可能 Map (对象结构)。如果未知，则无法推断 API 持有者。
     - 获取第一个可能的接收者 Map。
     - 使用 `LookupHolderOfExpectedType` 查找与该接收者 Map 兼容的 API 持有者。如果找不到，则无法推断。
     - 遍历所有可能的接收者 Map，并检查它们是否都指向同一个 API 持有者。如果有不同的 API 持有者，则需要动态查找。
     - 检查接收者 Map 是否是 `JSReceiverMap`，并且函数模板是否接受它们而不需要访问检查。
   - **假设输入与输出**:
     - **假设输入**: `function_template_info` 代表一个绑定到特定 C++ 类的 JavaScript 函数， `receiver_info` 表示接收者对象总是该 C++ 类的实例。
     - **预期输出**: 返回该 C++ 类的 API 持有者信息。
     - **假设输入**: `function_template_info` 代表一个普通的 JavaScript 函数， `receiver_info` 可能指向不同类型的对象。
     - **预期输出**: 返回 `not_found`。

2. **`ReduceCallForTarget`**:
   - **功能**:  为已知目标（`target`）的函数调用构建图节点。
   - **输入**:
     - `target_node`:  表示目标函数的节点。
     - `target`:  目标函数的 `JSFunctionRef`。
     - `args`:  函数调用的参数。
     - `feedback_source`:  反馈信息的来源。
   - **输出**:  `ReduceResult`，指示构建操作的结果。
   - **代码逻辑推理**:
     - 首先使用 `BuildCheckValue` 检查 `target_node` 的值是否与已知的 `target` 相符。
     - 然后调用 `ReduceCallForConstant` 处理常量目标的调用。

3. **`ReduceCallForNewClosure`**:
   - **功能**: 为创建新闭包的函数调用构建图节点（例如，调用 `Function` 构造函数或定义一个函数）。
   - **输入**:
     - `target_node`: 表示目标（通常是 `Function` 构造函数或一个函数表达式）的节点。
     - `target_context`:  目标函数的上下文。
     - `shared`:  目标函数的 `SharedFunctionInfoRef`。
     - `feedback_vector`:  反馈向量。
     - `args`: 函数调用的参数。
     - `feedback_source`: 反馈信息的来源。
   - **输出**: `ReduceResult`。
   - **代码逻辑推理**:
     - 如果调用模式不是默认模式（例如，带有断点），则不进行简化。
     - 如果 `shared` 函数信息中没有断点信息，并且是类构造函数，则抛出异常。
     - 尝试使用 `TryBuildCallKnownJSFunction` 构建已知 JS 函数的调用。
     - 如果以上都不满足，则构建一个通用的函数调用 (`BuildGenericCall`)。

4. **`ReduceFunctionPrototypeApplyCallWithReceiver`**:
   - **功能**: 处理 `Function.prototype.apply` 的调用。
   - **输入**:
     - `maybe_receiver`:  显式指定的接收者（通过 `apply` 的第一个参数）。
     - `args`:  `apply` 调用的参数。
     - `feedback_source`: 反馈信息的来源。
   - **输出**: `ReduceResult`。
   - **代码逻辑推理**:
     - 如果调用模式不是默认模式，则返回失败。
     - 获取被调用的函数。
     - 如果有显式指定的接收者，则检查该接收者是否与期望的值匹配。
     - 根据 `apply` 的参数数量和类型，选择不同的调用路径：
       - 没有参数：直接调用函数，接收者为 `null` 或 `undefined`。
       - 一个参数：调用函数，第一个参数作为新的接收者。
       - 两个或更多参数：
         - 如果第二个参数是 `null` 或 `undefined`，则像一个参数的情况一样处理。
         - 否则，将第二个参数视为类数组对象，并使用 `ReduceCallWithArrayLike` 处理。

   - **JavaScript 示例**:
     ```javascript
     function myFunc(a, b) {
       console.log(this, a, b);
     }

     let obj = { name: 'test' };

     // 没有参数
     myFunc.apply(obj); // 输出: { name: 'test' } undefined undefined

     // 一个参数
     myFunc.apply(obj, [1]); // 输出: { name: 'test' } 1 undefined

     // 两个参数
     myFunc.apply(obj, [1, 2]); // 输出: { name: 'test' } 1 2

     // 第二个参数为 null 或 undefined
     myFunc.apply(obj, null); // 输出: null undefined undefined
     myFunc.apply(obj, undefined); // 输出: undefined undefined undefined

     // 第二个参数为类数组对象
     myFunc.apply(obj, { 0: 1, 1: 2, length: 2 }); // 模拟 ReduceCallWithArrayLike
     ```

5. **`BuildCallWithFeedback`**:
   - **功能**: 构建带有类型反馈信息的函数调用节点。
   - **输入**:
     - `target_node`:  表示目标函数的节点。
     - `args`:  函数调用的参数。
     - `feedback_source`:  反馈信息的来源。
   - **输出**: 无返回值 (void)，但会构建图节点。
   - **代码逻辑推理**:
     - 从反馈源获取处理过的反馈信息。
     - 如果反馈信息不足，则发出取消优化的信号。
     - 如果目标有类型反馈，并且是 `JSFunction`，则根据反馈内容（接收者或目标）进行特殊处理，例如，对于 `apply` 调用，可能会调用 `ReduceFunctionPrototypeApplyCallWithReceiver`。
     - 最后调用 `ReduceCall` 来构建实际的调用节点。

6. **`ReduceCallWithArrayLikeForArgumentsObject`**:
   - **功能**:  当使用类数组参数对象（例如 `arguments`）调用函数时，尝试进行优化。
   - **输入**:
     - `target_node`: 表示目标函数的节点。
     - `args`: 函数调用的参数，其模式为 `kWithArrayLike`。
     - `arguments_object`:  表示 `arguments` 对象的 `VirtualObject`。
     - `feedback_source`: 反馈信息的来源。
   - **输出**: `ReduceResult`。
   - **代码逻辑推理**:
     - 检查参数对象是真正的 `arguments` 对象还是数组。
     - 获取 `arguments` 对象的元素。
     - 如果元素是一个 `ArgumentsElements` 节点，则创建一个 `CallForwardVarargs` 节点，用于转发可变数量的参数。
     - 如果元素是 `RootConstant` (空数组)，则直接使用空参数列表调用函数。
     - 如果元素是常量 `FixedArray`，则将数组中的元素作为额外的参数添加到调用中。
     - 如果元素是一个内联分配的数组，则提取数组中的元素作为额外的参数。

7. **`TryGetNonEscapingArgumentsObject`**:
   - **功能**: 尝试获取一个非逃逸的 `arguments` 对象。非逃逸意味着该对象不会被传递到外部作用域，因此可以进行某些优化。
   - **输入**:  一个 `ValueNode`，可能表示一个 `arguments` 对象。
   - **输出**:  如果找到非逃逸的 `arguments` 对象，则返回 `VirtualObject*`，否则返回 `std::optional<VirtualObject*>`。
   - **代码逻辑推理**:
     - 检查该值是否是一个内联分配。
     - 检查是否在循环内，如果是在循环内，需要额外的检查确保该分配在循环中没有被修改。
     - 检查该分配是否逃逸。
     - 检查该对象是否是 `JSArgumentsObjectMap` 或 `JSArrayMap` (用于 rest 参数)。
     - 对于 `JSArgumentsObjectMap`，还需要检查它是否是松散映射的 arguments 对象。

8. **`ReduceCallWithArrayLike`**:
   - **功能**: 处理使用类数组对象（例如 `arguments` 或具有 `length` 属性的对象）的函数调用。
   - **输入**:
     - `target_node`: 表示目标函数的节点。
     - `args`: 函数调用的参数，其模式为 `kWithArrayLike`。
     - `feedback_source`: 反馈信息的来源。
   - **输出**: `ReduceResult`。
   - **代码逻辑推理**:
     - 尝试获取非逃逸的 `arguments` 对象，并调用 `ReduceCallWithArrayLikeForArgumentsObject` 进行优化。
     - 如果失败，则构建一个通用的函数调用。

9. **`ReduceCall`**:
   - **功能**:  处理一般的函数调用。
   - **输入**:
     - `target_node`: 表示目标函数的节点。
     - `args`: 函数调用的参数。
     - `feedback_source`: 反馈信息的来源。
   - **输出**: `ReduceResult`。
   - **代码逻辑推理**:
     - 如果目标是一个常量 `JSFunction`，则调用 `ReduceCallForTarget`。
     - 如果目标是一个 `FastCreateClosure` 或 `CreateClosure` 节点（用于创建闭包），则调用 `ReduceCallForNewClosure`。
     - 否则，构建一个通用的函数调用。

10. **`BuildCallFromRegisterList`**:
    - **功能**: 从寄存器列表中构建函数调用。
    - **输入**: `receiver_mode`，指定接收者处理方式。
    - **代码逻辑**: 从指定的寄存器加载目标函数和参数，并调用 `BuildCallWithFeedback`。

11. **`BuildCallFromRegisters`**:
    - **功能**: 从一组连续的寄存器中构建函数调用。
    - **输入**: `arg_count` (参数数量) 和 `receiver_mode`。
    - **代码逻辑**: 从指定的寄存器加载目标函数和参数，并根据参数数量调用 `BuildCallWithFeedback`。

12. **`VisitCallAnyReceiver`**, **`VisitCallProperty`** 等一系列 `VisitCall...` 函数:
    - **功能**:  对应于不同的字节码指令，用于构建不同类型的函数调用。它们会调用 `BuildCallFromRegisterList` 或 `BuildCallFromRegisters` 并传递相应的参数。例如，`VisitCallProperty` 用于处理属性上的调用（例如 `obj.method()`）。

13. **`VisitCallWithSpread`**:
    - **功能**: 处理带有展开运算符 (`...`) 的函数调用。
    - **代码逻辑**: 从寄存器中加载函数和参数，并设置 `CallArguments` 的模式为 `kWithSpread`，然后调用 `BuildCallWithFeedback`。

    - **JavaScript 示例**:
      ```javascript
      function myFunc(a, b, c) {
        console.log(a, b, c);
      }

      let arr = [1, 2];
      myFunc(...arr, 3); // 输出: 1 2 3
      ```

14. **`VisitCallRuntime`**:
    - **功能**:  构建对 V8 运行时函数的调用。
    - **输入**:  运行时函数 ID 和参数寄存器列表。
    - **代码逻辑**: 创建 `CallRuntime` 节点，并将参数从寄存器复制到节点中。

    - **JavaScript 示例**:  虽然不能直接调用这些运行时函数，但它们是 V8 实现 JavaScript 某些特性的基础，例如 `Object.keys()` 可能会在内部调用一个运行时函数。

15. **`VisitCallJSRuntime`**:
    - **功能**:  调用存储在原生上下文中的 JavaScript 运行时函数。
    - **代码逻辑**: 加载上下文槽中的函数，并使用 `BuildGenericCall` 构建调用。

16. **`VisitCallRuntimeForPair`**:
    - **功能**:  调用返回一对值的运行时函数。
    - **代码逻辑**: 类似于 `VisitCallRuntime`，但会将结果存储到寄存器对中。

17. **`VisitInvokeIntrinsic`**:
    - **功能**:  调用内置函数（intrinsics）。
    - **代码逻辑**:  根据内置函数 ID 调用相应的 `VisitIntrinsic...` 函数。

18. **`VisitIntrinsicCopyDataProperties`**, **`VisitIntrinsicCreateIterResultObject`** 等一系列 `VisitIntrinsic...` 函数:
    - **功能**:  处理特定的内置函数调用，通常会直接构建相应的节点（例如 `CallBuiltin`）。

    - **JavaScript 示例 (对应 `VisitIntrinsicCreateIterResultObject`)**:
      ```javascript
      function createIterResult(value, done) {
        return { value: value, done: done };
      }
      ```

19. **`BuildGenericConstruct`**:
    - **功能**:  构建通用的 `new` 调用（构造函数调用）。
    - **输入**: 目标构造函数、`new.target`、上下文和参数。
    - **代码逻辑**: 创建 `Construct` 节点，并将参数复制到节点中。

    - **JavaScript 示例**:
      ```javascript
      class MyClass {}
      new MyClass();
      ```

20. **`BuildAndAllocateKeyValueArray`**:
    - **功能**:  创建一个包含键值对的数组。
    - **代码逻辑**: 创建一个固定数组来存储键值，然后创建一个 `JSArray` 对象来包装它。

    - **JavaScript 示例**:  内部用于创建类似 `[key, value]` 的结构。

21. **`BuildAndAllocateJSArray`**:
    - **功能**:  创建一个 `JSArray` 对象。
    - **代码逻辑**:  创建 `JSArray` 对象的虚拟表示，设置长度和元素。

    - **JavaScript 示例**:
      ```javascript
      new Array(5); // 创建一个长度为 5 的数组
      [1, 2, 3];    // 创建一个包含元素的数组
      ```

22. **`BuildAndAllocateJSArrayIterator`**:
    - **功能**:  创建一个数组迭代器对象。
    - **代码逻辑**: 创建 `JSArrayIterator` 对象的虚拟表示。

    - **JavaScript 示例**:
      ```javascript
      const arr = [1, 2, 3];
      const iterator = arr[Symbol.iterator]();
      ```

23. **`TryBuildAndAllocateJSGeneratorObject`**:
    - **功能**:  尝试创建并分配一个生成器对象。
    - **代码逻辑**:  如果可以确定闭包是常量，则尝试内联分配生成器对象。

    - **JavaScript 示例**:
      ```javascript
      function* myGenerator() {
        yield 1;
        yield 2;
      }
      const gen = myGenerator();
      ```

24. **`BuildElementsArray`**:
    - **功能**: 创建一个填充了空洞（`the hole`）的元素数组。
    - **代码逻辑**: 创建一个指定长度的 `FixedArray` 并用 `the hole` 填充。

    - **JavaScript 示例**:  这在创建稀疏数组时内部使用。

25. **`TryReduceConstructArrayConstructor`**:
    - **功能**:  尝试优化 `Array` 构造函数的调用。
    - **代码逻辑**:  根据参数和分配站点的反馈信息，尝试创建特定类型的数组。

    - **JavaScript 示例**:
      ```javascript
      new Array(10);       // 可能创建空洞数组
      new Array(1, 2, 3);  // 创建包含元素的数组
      ```

**关于 `.tq` 结尾**:

`v8/src/maglev/maglev-graph-builder.cc` 以 `.cc` 结尾，这意味着它是一个 **C++ 源代码文件**，而不是 Torque (`.tq`) 文件。Torque 是一种 V8 用于定义运行时函数的领域特定语言。

**归纳一下它的功能 (第 13 部分，共 18 部分)**:

作为 Maglev 图构建过程的一部分，这个代码片段专注于 **处理和优化函数调用以及与函数调用相关的操作**。它负责：

- **识别不同类型的函数调用**: 常规调用、`apply`、`call`、`new` 调用、运行时函数调用、内置函数调用等。
- **利用类型反馈信息**:  根据类型反馈优化函数调用，例如，检查接收者的类型。
- **处理参数**: 包括展开运算符、类数组对象 (`arguments`) 等。
- **创建特定类型的对象**:  例如，数组、迭代器、生成器对象。
- **进行内联优化**:  在可能的情况下，直接构建对象而不是调用运行时函数。

由于这是第 13 部分，可以推断出前面的部分可能负责图构建的初始化、基本节点的创建等，而后面的部分可能涉及图的最终化、优化和代码生成。这个部分专注于函数调用的具体构建逻辑，是连接抽象语法树和最终机器码的关键环节。

**用户常见的编程错误 (可能相关的)**:

虽然 `maglev-graph-builder.cc` 本身不直接处理用户代码的错误，但它尝试优化和处理与以下常见 JavaScript 编程模式相关的操作，这些模式可能导致性能问题或意外行为：

1. **过度使用 `apply` 或 `call`**:  虽然这些方法很灵活，但在某些情况下可能影响性能。Maglev 尝试优化这些调用。
2. **使用 `arguments` 对象**:  `arguments` 对象的一些特性（例如，在非严格模式下的映射）可能导致性能问题。Maglev 尝试对非逃逸的 `arguments` 对象进行优化。
3. **构造大型稀疏数组**:  使用 `new Array(largeNumber)` 创建大型稀疏数组可能会有性能影响，Maglev 在创建这些数组时会考虑空洞。
4. **不必要的函数调用**:  Maglev 的目标之一是减少不必要的函数调用开销，例如，通过内联内置函数。
5. **对 `Array` 构造函数的不当使用**: 例如，使用单个数字参数调用 `Array` 构造函数创建稀疏数组，这可能不是用户的预期。
6. **Generator 和 Async 函数的性能**: Maglev 尝试优化生成器和异步函数的创建和执行。

### 提示词
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第13部分，共18部分，请归纳一下它的功能
```

### 源代码
```cpp
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
          : array_function.initial_map(broker()).elem
```