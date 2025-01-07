Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/bytecode-graph-builder.cc`. They also have specific constraints:

1. **List Functionality:** Describe what the code does.
2. **Torque Source Check:** Determine if the file would be a Torque source if its extension was `.tq`.
3. **Javascript Relation:** If the code relates to Javascript functionality, provide a Javascript example.
4. **Logic Inference:** If there's logical deduction, give an example with inputs and outputs.
5. **Common Errors:**  If the code relates to common programming errors, illustrate with an example.
6. **Part of a Whole:** Note that this is part 3 of 6 and summarize its role within the larger context.

**Mental Walkthrough:**

* **Identify Core Purpose:** The code consists of various `Visit` methods, suggesting it processes bytecode instructions. Each `Visit` method seems to correspond to a specific bytecode operation (e.g., `VisitLdaGlobal`, `VisitStaGlobal`). The overall goal appears to be translating bytecode into an intermediate representation (IR) for further compilation.

* **Check for `.tq` nature:**  The code is C++, not Torque. Torque uses a different syntax and is generally used for defining built-in functions and types.

* **Relate to Javascript:** The bytecode instructions clearly map to Javascript operations. For example, `LdaGlobal` loads a global variable, and `StaGlobal` stores a global variable. Think of corresponding Javascript code.

* **Look for Logic:**  Some methods involve conditional logic (e.g., checking for context extensions in `CheckContextExtensions`). These are opportunities for input/output examples.

* **Consider Error Scenarios:** Instructions related to global variable access or property access could potentially lead to runtime errors in Javascript (e.g., `ReferenceError`).

* **Contextualize:**  The `BytecodeGraphBuilder` is part of the compiler pipeline. It takes bytecode as input and generates a graph representation. This is an intermediate step before further optimizations and code generation.

**Constraint Checklist & Confidence Score:**

1. List functionality: Yes
2. Torque source check: Yes
3. Javascript relation: Yes
4. Logic inference: Yes
5. Common errors: Yes
6. Part of a whole: Yes

Confidence Score: 5/5 - I'm confident I can address all constraints.

**Pre-computation/Pre-analysis:**

* **Javascript Examples:** Need to formulate simple Javascript snippets that trigger the corresponding bytecode instructions.
* **Logic Example:**  For `CheckContextExtensions`, consider a scenario with nested scopes and a variable in an outer scope.
* **Error Example:**  Demonstrate accessing an undeclared global variable.

**Structure the Response:**

Start with the overall functionality. Then address each constraint point by point, providing explanations and examples. Finally, summarize the role of this part within the larger compilation process.
这是 V8 源代码文件 `v8/src/compiler/bytecode-graph-builder.cc` 的一部分，负责将字节码指令转换为中间表示（IR）图，以便后续的优化和代码生成。 这是该文件处理加载和存储全局变量、上下文变量、属性以及创建闭包和上下文等字节码指令的部分。

**功能列举:**

这个代码片段主要负责以下功能：

1. **加载全局变量 (`VisitLdaGlobal`, `VisitLdaGlobalInsideTypeof`, `VisitLdaLookupGlobalSlot`, `VisitLdaLookupGlobalSlotInsideTypeof`):**  处理从全局作用域加载变量的字节码指令。区分在 `typeof` 运算符内部和外部的加载，并处理需要进行作用域查找的情况。
2. **存储全局变量 (`VisitStaGlobal`):** 处理将值存储到全局作用域的字节码指令。
3. **数组字面量操作 (`VisitStaInArrayLiteral`, `VisitDefineKeyedOwnPropertyInLiteral`):** 处理在数组字面量中存储元素和定义自有属性的字节码指令。
4. **上下文变量操作 (`VisitLdaContextSlot`, `VisitLdaScriptContextSlot`, `VisitLdaImmutableContextSlot`, `VisitLdaCurrentContextSlot`, `VisitLdaCurrentScriptContextSlot`, `VisitLdaImmutableCurrentContextSlot`, `VisitStaContextSlot`, `VisitStaCurrentContextSlot`, `VisitStaScriptContextSlot`, `VisitStaCurrentScriptContextSlot`):** 处理加载和存储上下文变量的字节码指令。区分不同类型的上下文（例如，脚本上下文）和不同的作用域深度。
5. **作用域查找 (`VisitLdaLookupSlot`, `VisitLdaLookupSlotInsideTypeof`, `BuildLdaLookupContextSlot`, `BuildLdaLookupGlobalSlot`):** 处理需要进行作用域链查找来加载变量的字节码指令。区分在 `typeof` 运算符内部和外部的查找，并处理需要检查上下文扩展的情况。
6. **存储作用域查找结果 (`VisitStaLookupSlot`):** 处理存储作用域查找结果的字节码指令。
7. **属性操作 (`VisitGetNamedProperty`, `VisitGetNamedPropertyFromSuper`, `VisitGetKeyedProperty`, `VisitGetEnumeratedKeyedProperty`, `VisitSetNamedProperty`, `VisitDefineNamedOwnProperty`, `VisitSetKeyedProperty`, `VisitDefineKeyedOwnProperty`):** 处理加载和存储对象属性的字节码指令，包括命名属性和键值属性。也处理从 `super` 加载属性的情况。
8. **模块变量操作 (`VisitLdaModuleVariable`, `VisitStaModuleVariable`):** 处理加载和存储模块作用域变量的字节码指令。
9. **上下文管理 (`VisitPushContext`, `VisitPopContext`):** 处理压入和弹出执行上下文的字节码指令。
10. **闭包创建 (`VisitCreateClosure`):** 处理创建闭包的字节码指令。
11. **上下文创建 (`VisitCreateBlockContext`, `VisitCreateFunctionContext`, `VisitCreateEvalContext`, `VisitCreateCatchContext`, `VisitCreateWithContext`):** 处理创建不同类型上下文的字节码指令。
12. **arguments 对象创建 (`VisitCreateMappedArguments`, `VisitCreateUnmappedArguments`, `VisitCreateRestParameter`):** 处理创建 `arguments` 对象的字节码指令。
13. **字面量创建 (`VisitCreateRegExpLiteral`, `VisitCreateArrayLiteral`, `VisitCreateEmptyArrayLiteral`, `VisitCreateArrayFromIterable`):** 处理创建正则表达式、数组等字面量的字节码指令。

**关于 `.tq` 扩展名:**

如果 `v8/src/compiler/bytecode-graph-builder.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。 Torque 是一种 V8 自研的类型化的中间语言，用于定义内置函数和运行时库。 这个文件目前是 C++ 代码，负责将字节码转换为更底层的 IR 图。

**与 Javascript 的关系及示例:**

这些代码片段直接对应于 JavaScript 的各种操作。以下是一些示例：

* **`VisitLdaGlobal('console')` 对应于 JavaScript:**
  ```javascript
  console;
  ```
  这里假设全局作用域中存在名为 `console` 的变量。

* **`VisitStaGlobal('myVar')` 对应于 JavaScript:**
  ```javascript
  myVar = value; // 假设 value 已经存在
  ```
  这里将 `value` 赋值给全局变量 `myVar`。

* **`VisitLdaContextSlot(0, 1)` 对应于 JavaScript:**
  ```javascript
  function outer() {
    let localVar = 10;
    function inner() {
      console.log(localVar); // 访问外层函数的局部变量
    }
    return inner;
  }
  const myInnerFunc = outer();
  myInnerFunc();
  ```
  `LdaContextSlot` 用于访问闭包中捕获的变量。在这个例子中，`inner` 函数通过上下文槽访问 `outer` 函数的 `localVar`。

* **`VisitSetNamedProperty()` 对应于 JavaScript:**
  ```javascript
  const obj = {};
  obj.propertyName = value;
  ```
  将 `value` 赋值给对象 `obj` 的 `propertyName` 属性。

**代码逻辑推理示例:**

假设输入的字节码指令是 `LdaContextSlot [r0], [1], [0]`， 并且：

* `r0` 寄存器指向当前的上下文对象。
* 索引操作数 `[1]` 表示要加载的槽位在上下文中的偏移量为 1。
* 立即数操作数 `[0]` 可能表示作用域深度（在这里是当前作用域）。

**假设输入:**

* 当前上下文对象（`r0` 的值）是一个包含多个变量的 JavaScript 函数上下文。
* 上下文对象的第 1 个槽位存储着一个值为字符串 "hello" 的局部变量。

**输出:**

* `VisitLdaContextSlot` 方法会创建一个加载上下文槽位的 IR 节点。
* 该节点会从 `r0` 指向的上下文中加载偏移量为 1 的值。
* 最终，累加器（accumulator）会被绑定到表示字符串 "hello" 的 IR 节点。

**用户常见的编程错误示例:**

* **`VisitLdaGlobal` 但变量未声明:** 如果 JavaScript 代码中尝试访问一个未声明的全局变量，例如：
  ```javascript
  console.log(undeclaredVariable);
  ```
  在编译过程中，`VisitLdaGlobal('undeclaredVariable')` 会被处理。然而，在运行时，由于 `undeclaredVariable` 不存在于全局作用域中，将会抛出 `ReferenceError`。

* **`VisitStaGlobal` 在严格模式下给未声明的变量赋值:** 在非严格模式下，给未声明的变量赋值会隐式地创建全局变量。但在严格模式下，这样做会抛出 `ReferenceError`。例如：
  ```javascript
  "use strict";
  undeclaredVariable = 10; // 会抛出 ReferenceError
  ```
  相应的 `VisitStaGlobal('undeclaredVariable')` 在运行时会导致错误。

**功能归纳 (第 3 部分):**

作为 `BytecodeGraphBuilder` 的一部分，这部分代码专注于将涉及 **变量访问（全局和局部/上下文）、属性操作以及基本对象和上下文创建** 的字节码指令转换为中间表示图。 它处理了从作用域加载和存储值、访问对象属性、以及建立程序执行所需的基本结构（如闭包和上下文）。 这部分是连接字节码指令和更底层的编译器 IR 之间的关键桥梁。

Prompt: 
```
这是目录为v8/src/compiler/bytecode-graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/bytecode-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
adGlobal(name, feedback_slot_index, TypeofMode::kNotInside);
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitLdaGlobalInsideTypeof() {
  PrepareEagerCheckpoint();
  NameRef name = MakeRefForConstantForIndexOperand<Name>(0);
  uint32_t feedback_slot_index = bytecode_iterator().GetIndexOperand(1);
  Node* node = BuildLoadGlobal(name, feedback_slot_index, TypeofMode::kInside);
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitStaGlobal() {
  PrepareEagerCheckpoint();
  NameRef name = MakeRefForConstantForIndexOperand<Name>(0);
  FeedbackSource feedback =
      CreateFeedbackSource(bytecode_iterator().GetIndexOperand(1));
  Node* value = environment()->LookupAccumulator();

  LanguageMode language_mode =
      GetLanguageModeFromSlotKind(broker()->GetFeedbackSlotKind(feedback));
  const Operator* op = javascript()->StoreGlobal(language_mode, name, feedback);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* node = NewNode(op, value, feedback_vector_node());
  environment()->RecordAfterState(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitStaInArrayLiteral() {
  PrepareEagerCheckpoint();
  Node* value = environment()->LookupAccumulator();
  Node* array =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* index =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  FeedbackSource feedback =
      CreateFeedbackSource(bytecode_iterator().GetIndexOperand(2));
  const Operator* op = javascript()->StoreInArrayLiteral(feedback);

  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedStoreKeyed(op, array, index, value, feedback.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
    node = NewNode(op, array, index, value, feedback_vector_node());
  }

  environment()->RecordAfterState(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitDefineKeyedOwnPropertyInLiteral() {
  PrepareEagerCheckpoint();

  Node* object =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* name =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  Node* value = environment()->LookupAccumulator();
  int flags = bytecode_iterator().GetFlag8Operand(2);
  FeedbackSource feedback =
      CreateFeedbackSource(bytecode_iterator().GetIndexOperand(3));
  const Operator* op = javascript()->DefineKeyedOwnPropertyInLiteral(feedback);

  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedStoreKeyed(op, object, name, value, feedback.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
    node = NewNode(op, object, name, value, jsgraph()->ConstantNoHole(flags),
                   feedback_vector_node());
  }

  environment()->RecordAfterState(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitLdaContextSlot() {
  const Operator* op = javascript()->LoadContext(
      bytecode_iterator().GetUnsignedImmediateOperand(2),
      bytecode_iterator().GetIndexOperand(1), false);
  Node* node = NewNode(op);
  Node* context =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  NodeProperties::ReplaceContextInput(node, context);
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaScriptContextSlot() {
  const Operator* op = javascript()->LoadScriptContext(
      bytecode_iterator().GetUnsignedImmediateOperand(2),
      bytecode_iterator().GetIndexOperand(1));
  Node* node = NewNode(op);
  Node* context =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  NodeProperties::ReplaceContextInput(node, context);
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaImmutableContextSlot() {
  const Operator* op = javascript()->LoadContext(
      bytecode_iterator().GetUnsignedImmediateOperand(2),
      bytecode_iterator().GetIndexOperand(1), true);
  Node* node = NewNode(op);
  Node* context =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  NodeProperties::ReplaceContextInput(node, context);
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaCurrentContextSlot() {
  const Operator* op = javascript()->LoadContext(
      0, bytecode_iterator().GetIndexOperand(0), false);
  Node* node = NewNode(op);
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaCurrentScriptContextSlot() {
  const Operator* op = javascript()->LoadScriptContext(
      0, bytecode_iterator().GetIndexOperand(0));
  Node* node = NewNode(op);
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaImmutableCurrentContextSlot() {
  const Operator* op = javascript()->LoadContext(
      0, bytecode_iterator().GetIndexOperand(0), true);
  Node* node = NewNode(op);
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitStaContextSlot() {
  const Operator* op = javascript()->StoreContext(
      bytecode_iterator().GetUnsignedImmediateOperand(2),
      bytecode_iterator().GetIndexOperand(1));
  Node* value = environment()->LookupAccumulator();
  Node* node = NewNode(op, value);
  Node* context =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  NodeProperties::ReplaceContextInput(node, context);
}

void BytecodeGraphBuilder::VisitStaCurrentContextSlot() {
  const Operator* op =
      javascript()->StoreContext(0, bytecode_iterator().GetIndexOperand(0));
  Node* value = environment()->LookupAccumulator();
  NewNode(op, value);
}

void BytecodeGraphBuilder::VisitStaScriptContextSlot() {
  PrepareEagerCheckpoint();
  const Operator* op = javascript()->StoreScriptContext(
      bytecode_iterator().GetUnsignedImmediateOperand(2),
      bytecode_iterator().GetIndexOperand(1));
  Node* value = environment()->LookupAccumulator();
  Node* node = NewNode(op, value);
  Node* context =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  NodeProperties::ReplaceContextInput(node, context);
}

void BytecodeGraphBuilder::VisitStaCurrentScriptContextSlot() {
  PrepareEagerCheckpoint();
  const Operator* op = javascript()->StoreScriptContext(
      0, bytecode_iterator().GetIndexOperand(0));
  Node* value = environment()->LookupAccumulator();
  NewNode(op, value);
}

void BytecodeGraphBuilder::BuildLdaLookupSlot(TypeofMode typeof_mode) {
  PrepareEagerCheckpoint();
  Node* name =
      jsgraph()->ConstantNoHole(MakeRefForConstantForIndexOperand(0), broker());
  const Operator* op =
      javascript()->CallRuntime(typeof_mode == TypeofMode::kNotInside
                                    ? Runtime::kLoadLookupSlot
                                    : Runtime::kLoadLookupSlotInsideTypeof);
  Node* value = NewNode(op, name);
  environment()->BindAccumulator(value, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitLdaLookupSlot() {
  BuildLdaLookupSlot(TypeofMode::kNotInside);
}

void BytecodeGraphBuilder::VisitLdaLookupSlotInsideTypeof() {
  BuildLdaLookupSlot(TypeofMode::kInside);
}

BytecodeGraphBuilder::Environment*
BytecodeGraphBuilder::CheckContextExtensionAtDepth(
    Environment* slow_environment, uint32_t depth) {
  Node* extension_slot = NewNode(
      javascript()->LoadContext(depth, Context::EXTENSION_INDEX, false));
  Node* check_no_extension =
      NewNode(simplified()->ReferenceEqual(), extension_slot,
              jsgraph()->UndefinedConstant());
  NewBranch(check_no_extension);
  {
    SubEnvironment sub_environment(this);
    NewIfFalse();
    // If there is an extension, merge into the slow path.
    if (slow_environment == nullptr) {
      slow_environment = environment();
      NewMerge();
    } else {
      slow_environment->Merge(environment(),
                              bytecode_analysis().GetInLivenessFor(
                                  bytecode_iterator().current_offset()));
    }
  }
  NewIfTrue();
  // Do nothing on if there is no extension, eventually falling through to
  // the fast path.
  DCHECK_NOT_NULL(slow_environment);
  return slow_environment;
}

OptionalScopeInfoRef BytecodeGraphBuilder::TryGetScopeInfo() {
  Node* context = environment()->Context();
  switch (context->opcode()) {
    case IrOpcode::kJSCreateFunctionContext:
      return CreateFunctionContextParametersOf(context->op()).scope_info();
    case IrOpcode::kJSCreateBlockContext:
    case IrOpcode::kJSCreateCatchContext:
    case IrOpcode::kJSCreateWithContext:
      return ScopeInfoOf(context->op());
    case IrOpcode::kParameter: {
      ScopeInfoRef scope_info = shared_info_.scope_info(broker());
      if (scope_info.HasOuterScopeInfo()) {
        scope_info = scope_info.OuterScopeInfo(broker());
      }
      return scope_info;
    }
    default:
      return std::nullopt;
  }
}

BytecodeGraphBuilder::Environment* BytecodeGraphBuilder::CheckContextExtensions(
    uint32_t depth) {
  OptionalScopeInfoRef maybe_scope_info = TryGetScopeInfo();
  if (!maybe_scope_info.has_value()) {
    return CheckContextExtensionsSlowPath(depth);
  }

  ScopeInfoRef scope_info = maybe_scope_info.value();
  // We only need to check up to the last-but-one depth, because an eval
  // in the same scope as the variable itself has no way of shadowing it.
  Environment* slow_environment = nullptr;
  for (uint32_t d = 0; d < depth; d++) {
    // Const tracking let data is stored in the extension slot of a
    // ScriptContext - however, it's unrelated to the sloppy eval variable
    // extension. We should never iterate through a ScriptContext here.
    DCHECK_NE(scope_info.scope_type(), ScopeType::SCRIPT_SCOPE);
    DCHECK_NE(scope_info.scope_type(), ScopeType::REPL_MODE_SCOPE);

    if (scope_info.HasContextExtensionSlot() &&
        !broker()->dependencies()->DependOnEmptyContextExtension(scope_info)) {
      // Using EmptyContextExtension dependency is not possible for this
      // scope_info, so generate dynamic checks.
      slow_environment = CheckContextExtensionAtDepth(slow_environment, d);
    }
    DCHECK_IMPLIES(!scope_info.HasOuterScopeInfo(), d + 1 == depth);
    if (scope_info.HasOuterScopeInfo()) {
      scope_info = scope_info.OuterScopeInfo(broker());
    }
  }

  // There should have been at least one slow path generated, otherwise we
  // could have already skipped the lookup in the bytecode. The only exception
  // is if we replaced all the dynamic checks with code dependencies.
  DCHECK_IMPLIES(!v8_flags.empty_context_extension_dep,
                 slow_environment != nullptr);
  return slow_environment;
}

BytecodeGraphBuilder::Environment*
BytecodeGraphBuilder::CheckContextExtensionsSlowPath(uint32_t depth) {
  // Output environment where the context has an extension
  Environment* slow_environment = nullptr;

  // We only need to check up to the last-but-one depth, because an eval
  // in the same scope as the variable itself has no way of shadowing it.
  for (uint32_t d = 0; d < depth; d++) {
    Node* has_extension = NewNode(javascript()->HasContextExtension(d));

    Environment* undefined_extension_env;
    NewBranch(has_extension);
    {
      SubEnvironment sub_environment(this);
      NewIfTrue();
      slow_environment = CheckContextExtensionAtDepth(slow_environment, d);
      undefined_extension_env = environment();
    }
    NewIfFalse();
    environment()->Merge(undefined_extension_env,
                         bytecode_analysis().GetInLivenessFor(
                             bytecode_iterator().current_offset()));
    mark_as_needing_eager_checkpoint(true);
    // Do nothing on if there is no extension, eventually falling through to
    // the fast path.
  }

  // There should have been at least one slow path generated, otherwise we could
  // have already skipped the lookup in the bytecode.
  DCHECK_NOT_NULL(slow_environment);
  return slow_environment;
}

void BytecodeGraphBuilder::BuildLdaLookupContextSlot(TypeofMode typeof_mode) {
  uint32_t depth = bytecode_iterator().GetUnsignedImmediateOperand(2);

  // Check if any context in the depth has an extension.
  Environment* slow_environment = CheckContextExtensions(depth);

  // Fast path, do a context load.
  {
    uint32_t slot_index = bytecode_iterator().GetIndexOperand(1);

    // TODO(victorgomes): Emit LoadScriptContext if ContextKind::kScriptContext.
    const Operator* op = javascript()->LoadContext(depth, slot_index, false);
    environment()->BindAccumulator(NewNode(op));
  }
  if (!slow_environment) {
    // The slow path was fully replaced by a set of compilation dependencies.
    return;
  }

  // Add a merge to the fast environment.
  NewMerge();
  Environment* fast_environment = environment();

  // Slow path, do a runtime load lookup.
  set_environment(slow_environment);
  {
    Node* name = jsgraph()->ConstantNoHole(MakeRefForConstantForIndexOperand(0),
                                           broker());

    const Operator* op =
        javascript()->CallRuntime(typeof_mode == TypeofMode::kNotInside
                                      ? Runtime::kLoadLookupSlot
                                      : Runtime::kLoadLookupSlotInsideTypeof);
    Node* value = NewNode(op, name);
    environment()->BindAccumulator(value, Environment::kAttachFrameState);
  }

  fast_environment->Merge(environment(),
                          bytecode_analysis().GetOutLivenessFor(
                              bytecode_iterator().current_offset()));
  set_environment(fast_environment);
  mark_as_needing_eager_checkpoint(true);
}

void BytecodeGraphBuilder::VisitLdaLookupContextSlot() {
  BuildLdaLookupContextSlot(TypeofMode::kNotInside);
}

void BytecodeGraphBuilder::VisitLdaLookupScriptContextSlot() {
  BuildLdaLookupContextSlot(TypeofMode::kNotInside);
}

void BytecodeGraphBuilder::VisitLdaLookupContextSlotInsideTypeof() {
  BuildLdaLookupContextSlot(TypeofMode::kInside);
}

void BytecodeGraphBuilder::VisitLdaLookupScriptContextSlotInsideTypeof() {
  BuildLdaLookupContextSlot(TypeofMode::kInside);
}

void BytecodeGraphBuilder::BuildLdaLookupGlobalSlot(TypeofMode typeof_mode) {
  uint32_t depth = bytecode_iterator().GetUnsignedImmediateOperand(2);

  // Check if any context in the depth has an extension.
  Environment* slow_environment = CheckContextExtensions(depth);

  // Fast path, do a global load.
  {
    PrepareEagerCheckpoint();
    NameRef name = MakeRefForConstantForIndexOperand<Name>(0);
    uint32_t feedback_slot_index = bytecode_iterator().GetIndexOperand(1);
    Node* node = BuildLoadGlobal(name, feedback_slot_index, typeof_mode);
    environment()->BindAccumulator(node, Environment::kAttachFrameState);
  }
  if (!slow_environment) {
    // The slow path was fully replaced by a set of compilation dependencies.
    return;
  }

  // Add a merge to the fast environment.
  NewMerge();
  Environment* fast_environment = environment();

  // Slow path, do a runtime load lookup.
  set_environment(slow_environment);
  {
    Node* name = jsgraph()->ConstantNoHole(
        MakeRefForConstantForIndexOperand<Name>(0), broker());

    const Operator* op =
        javascript()->CallRuntime(typeof_mode == TypeofMode::kNotInside
                                      ? Runtime::kLoadLookupSlot
                                      : Runtime::kLoadLookupSlotInsideTypeof);
    Node* value = NewNode(op, name);
    environment()->BindAccumulator(value, Environment::kAttachFrameState);
  }

  fast_environment->Merge(environment(),
                          bytecode_analysis().GetOutLivenessFor(
                              bytecode_iterator().current_offset()));
  set_environment(fast_environment);
  mark_as_needing_eager_checkpoint(true);
}

void BytecodeGraphBuilder::VisitLdaLookupGlobalSlot() {
  BuildLdaLookupGlobalSlot(TypeofMode::kNotInside);
}

void BytecodeGraphBuilder::VisitLdaLookupGlobalSlotInsideTypeof() {
  BuildLdaLookupGlobalSlot(TypeofMode::kInside);
}

void BytecodeGraphBuilder::VisitStaLookupSlot() {
  PrepareEagerCheckpoint();
  Node* value = environment()->LookupAccumulator();
  Node* name =
      jsgraph()->ConstantNoHole(MakeRefForConstantForIndexOperand(0), broker());
  int bytecode_flags = bytecode_iterator().GetFlag8Operand(1);
  LanguageMode language_mode = static_cast<LanguageMode>(
      interpreter::StoreLookupSlotFlags::LanguageModeBit::decode(
          bytecode_flags));
  LookupHoistingMode lookup_hoisting_mode = static_cast<LookupHoistingMode>(
      interpreter::StoreLookupSlotFlags::LookupHoistingModeBit::decode(
          bytecode_flags));
  DCHECK_IMPLIES(lookup_hoisting_mode == LookupHoistingMode::kLegacySloppy,
                 is_sloppy(language_mode));
  const Operator* op = javascript()->CallRuntime(
      is_strict(language_mode)
          ? Runtime::kStoreLookupSlot_Strict
          : lookup_hoisting_mode == LookupHoistingMode::kLegacySloppy
                ? Runtime::kStoreLookupSlot_SloppyHoisting
                : Runtime::kStoreLookupSlot_Sloppy);
  Node* store = NewNode(op, name, value);
  environment()->BindAccumulator(store, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitGetNamedProperty() {
  PrepareEagerCheckpoint();
  Node* object =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  NameRef name = MakeRefForConstantForIndexOperand<Name>(1);
  FeedbackSource feedback =
      CreateFeedbackSource(bytecode_iterator().GetIndexOperand(2));
  const Operator* op = javascript()->LoadNamed(name, feedback);

  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedLoadNamed(op, feedback.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
    node = NewNode(op, object, feedback_vector_node());
  }
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitGetNamedPropertyFromSuper() {
  PrepareEagerCheckpoint();
  Node* receiver =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* home_object = environment()->LookupAccumulator();
  NameRef name = MakeRefForConstantForIndexOperand<Name>(1);

  FeedbackSource feedback =
      CreateFeedbackSource(bytecode_iterator().GetIndexOperand(2));
  const Operator* op = javascript()->LoadNamedFromSuper(name, feedback);

  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedLoadNamed(op, feedback.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
    node = NewNode(op, receiver, home_object, feedback_vector_node());
  }
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitGetKeyedProperty() {
  PrepareEagerCheckpoint();
  Node* key = environment()->LookupAccumulator();
  Node* object =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  FeedbackSource feedback =
      CreateFeedbackSource(bytecode_iterator().GetIndexOperand(1));
  const Operator* op = javascript()->LoadProperty(feedback);

  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedLoadKeyed(op, object, key, feedback.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    static_assert(JSLoadPropertyNode::ObjectIndex() == 0);
    static_assert(JSLoadPropertyNode::KeyIndex() == 1);
    static_assert(JSLoadPropertyNode::FeedbackVectorIndex() == 2);
    DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
    node = NewNode(op, object, key, feedback_vector_node());
  }
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitGetEnumeratedKeyedProperty() {
  // GetEnumeratedKeyedProperty <object> <enum_index> <cache_type> <slot>
  PrepareEagerCheckpoint();
  Node* key = environment()->LookupAccumulator();
  Node* object =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  FeedbackSource feedback =
      CreateFeedbackSource(bytecode_iterator().GetIndexOperand(3));
  const Operator* op = javascript()->LoadProperty(feedback);

  static_assert(JSLoadPropertyNode::ObjectIndex() == 0);
  static_assert(JSLoadPropertyNode::KeyIndex() == 1);
  static_assert(JSLoadPropertyNode::FeedbackVectorIndex() == 2);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* node = NewNode(op, object, key, feedback_vector_node());
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::BuildNamedStore(NamedStoreMode store_mode) {
  PrepareEagerCheckpoint();
  Node* value = environment()->LookupAccumulator();
  Node* object =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  NameRef name = MakeRefForConstantForIndexOperand<Name>(1);
  FeedbackSource feedback =
      CreateFeedbackSource(bytecode_iterator().GetIndexOperand(2));

  const Operator* op;
  if (store_mode == NamedStoreMode::kDefineOwn) {
    DCHECK_EQ(FeedbackSlotKind::kDefineNamedOwn,
              broker()->GetFeedbackSlotKind(feedback));

    op = javascript()->DefineNamedOwnProperty(name, feedback);
  } else {
    DCHECK_EQ(NamedStoreMode::kSet, store_mode);
    LanguageMode language_mode =
        GetLanguageModeFromSlotKind(broker()->GetFeedbackSlotKind(feedback));
    op = javascript()->SetNamedProperty(language_mode, name, feedback);
  }

  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedStoreNamed(op, object, value, feedback.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
    node = NewNode(op, object, value, feedback_vector_node());
  }
  environment()->RecordAfterState(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitSetNamedProperty() {
  BuildNamedStore(NamedStoreMode::kSet);
}

void BytecodeGraphBuilder::VisitDefineNamedOwnProperty() {
  BuildNamedStore(NamedStoreMode::kDefineOwn);
}

void BytecodeGraphBuilder::VisitSetKeyedProperty() {
  PrepareEagerCheckpoint();
  Node* value = environment()->LookupAccumulator();
  Node* object =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* key =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  FeedbackSource source =
      CreateFeedbackSource(bytecode_iterator().GetIndexOperand(2));
  LanguageMode language_mode =
      GetLanguageModeFromSlotKind(broker()->GetFeedbackSlotKind(source));
  const Operator* op = javascript()->SetKeyedProperty(language_mode, source);

  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedStoreKeyed(op, object, key, value, source.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    static_assert(JSSetKeyedPropertyNode::ObjectIndex() == 0);
    static_assert(JSSetKeyedPropertyNode::KeyIndex() == 1);
    static_assert(JSSetKeyedPropertyNode::ValueIndex() == 2);
    static_assert(JSSetKeyedPropertyNode::FeedbackVectorIndex() == 3);
    DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
    node = NewNode(op, object, key, value, feedback_vector_node());
  }

  environment()->RecordAfterState(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitDefineKeyedOwnProperty() {
  PrepareEagerCheckpoint();
  Node* value = environment()->LookupAccumulator();
  Node* object =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* key =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  int flags = bytecode_iterator().GetFlag8Operand(2);
  FeedbackSource source =
      CreateFeedbackSource(bytecode_iterator().GetIndexOperand(3));
  LanguageMode language_mode =
      GetLanguageModeFromSlotKind(broker()->GetFeedbackSlotKind(source));

  const Operator* op =
      javascript()->DefineKeyedOwnProperty(language_mode, source);

  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedStoreKeyed(op, object, key, value, source.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    static_assert(JSDefineKeyedOwnPropertyNode::ObjectIndex() == 0);
    static_assert(JSDefineKeyedOwnPropertyNode::KeyIndex() == 1);
    static_assert(JSDefineKeyedOwnPropertyNode::ValueIndex() == 2);
    static_assert(JSDefineKeyedOwnPropertyNode::FlagsIndex() == 3);
    static_assert(JSDefineKeyedOwnPropertyNode::FeedbackVectorIndex() == 4);
    DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
    node = NewNode(op, object, key, value, jsgraph()->ConstantNoHole(flags),
                   feedback_vector_node());
  }

  environment()->RecordAfterState(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitLdaModuleVariable() {
  int32_t cell_index = bytecode_iterator().GetImmediateOperand(0);
  uint32_t depth = bytecode_iterator().GetUnsignedImmediateOperand(1);
  Node* module =
      NewNode(javascript()->LoadContext(depth, Context::EXTENSION_INDEX, true));
  Node* value = NewNode(javascript()->LoadModule(cell_index), module);
  environment()->BindAccumulator(value);
}

void BytecodeGraphBuilder::VisitStaModuleVariable() {
  int32_t cell_index = bytecode_iterator().GetImmediateOperand(0);
  uint32_t depth = bytecode_iterator().GetUnsignedImmediateOperand(1);
  Node* module =
      NewNode(javascript()->LoadContext(depth, Context::EXTENSION_INDEX, true));
  Node* value = environment()->LookupAccumulator();
  NewNode(javascript()->StoreModule(cell_index), module, value);
}

void BytecodeGraphBuilder::VisitPushContext() {
  Node* new_context = environment()->LookupAccumulator();
  environment()->BindRegister(bytecode_iterator().GetRegisterOperand(0),
                              environment()->Context());
  environment()->SetContext(new_context);
}

void BytecodeGraphBuilder::VisitPopContext() {
  Node* context =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  environment()->SetContext(context);
}

void BytecodeGraphBuilder::VisitCreateClosure() {
  SharedFunctionInfoRef shared_info =
      MakeRefForConstantForIndexOperand<SharedFunctionInfo>(0);
  AllocationType allocation =
      interpreter::CreateClosureFlags::PretenuredBit::decode(
          bytecode_iterator().GetFlag8Operand(2))
          ? AllocationType::kOld
          : AllocationType::kYoung;
  CodeRef compile_lazy =
      MakeRef(broker(), *BUILTIN_CODE(jsgraph()->isolate(), CompileLazy));
  const Operator* op =
      javascript()->CreateClosure(shared_info, compile_lazy, allocation);
  Node* closure = NewNode(
      op, BuildLoadFeedbackCell(bytecode_iterator().GetIndexOperand(1)));
  environment()->BindAccumulator(closure);
}

void BytecodeGraphBuilder::VisitCreateBlockContext() {
  ScopeInfoRef scope_info = MakeRefForConstantForIndexOperand<ScopeInfo>(0);
  const Operator* op = javascript()->CreateBlockContext(scope_info);
  Node* context = NewNode(op);
  environment()->BindAccumulator(context);
}

void BytecodeGraphBuilder::VisitCreateFunctionContext() {
  ScopeInfoRef scope_info = MakeRefForConstantForIndexOperand<ScopeInfo>(0);
  uint32_t slots = bytecode_iterator().GetUnsignedImmediateOperand(1);
  const Operator* op =
      javascript()->CreateFunctionContext(scope_info, slots, FUNCTION_SCOPE);
  Node* context = NewNode(op);
  environment()->BindAccumulator(context);
}

void BytecodeGraphBuilder::VisitCreateEvalContext() {
  ScopeInfoRef scope_info = MakeRefForConstantForIndexOperand<ScopeInfo>(0);
  uint32_t slots = bytecode_iterator().GetUnsignedImmediateOperand(1);
  const Operator* op =
      javascript()->CreateFunctionContext(scope_info, slots, EVAL_SCOPE);
  Node* context = NewNode(op);
  environment()->BindAccumulator(context);
}

void BytecodeGraphBuilder::VisitCreateCatchContext() {
  interpreter::Register reg = bytecode_iterator().GetRegisterOperand(0);
  Node* exception = environment()->LookupRegister(reg);
  ScopeInfoRef scope_info = MakeRefForConstantForIndexOperand<ScopeInfo>(1);

  const Operator* op = javascript()->CreateCatchContext(scope_info);
  Node* context = NewNode(op, exception);
  environment()->BindAccumulator(context);
}

void BytecodeGraphBuilder::VisitCreateWithContext() {
  Node* object =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  ScopeInfoRef scope_info = MakeRefForConstantForIndexOperand<ScopeInfo>(1);

  const Operator* op = javascript()->CreateWithContext(scope_info);
  Node* context = NewNode(op, object);
  environment()->BindAccumulator(context);
}

void BytecodeGraphBuilder::BuildCreateArguments(CreateArgumentsType type) {
  const Operator* op = javascript()->CreateArguments(type);
  Node* object = NewNode(op, GetFunctionClosure());
  environment()->BindAccumulator(object, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitCreateMappedArguments() {
  BuildCreateArguments(CreateArgumentsType::kMappedArguments);
}

void BytecodeGraphBuilder::VisitCreateUnmappedArguments() {
  BuildCreateArguments(CreateArgumentsType::kUnmappedArguments);
}

void BytecodeGraphBuilder::VisitCreateRestParameter() {
  BuildCreateArguments(CreateArgumentsType::kRestParameter);
}

void BytecodeGraphBuilder::VisitCreateRegExpLiteral() {
  StringRef constant_pattern = MakeRefForConstantForIndexOperand<String>(0);
  int const slot_id = bytecode_iterator().GetIndexOperand(1);
  FeedbackSource pair = CreateFeedbackSource(slot_id);
  int literal_flags = bytecode_iterator().GetFlag16Operand(2);
  static_assert(JSCreateLiteralRegExpNode::FeedbackVectorIndex() == 0);
  const Operator* op =
      javascript()->CreateLiteralRegExp(constant_pattern, pair, literal_flags);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* literal = NewNode(op, feedback_vector_node());
  environment()->BindAccumulator(literal, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitCreateArrayLiteral() {
  ArrayBoilerplateDescriptionRef array_boilerplate_description =
      MakeRefForConstantForIndexOperand<ArrayBoilerplateDescription>(0);
  int const slot_id = bytecode_iterator().GetIndexOperand(1);
  FeedbackSource pair = CreateFeedbackSource(slot_id);
  int bytecode_flags = bytecode_iterator().GetFlag8Operand(2);
  int literal_flags =
      interpreter::CreateArrayLiteralFlags::FlagsBits::decode(bytecode_flags);
  // Disable allocation site mementos. Only unoptimized code will collect
  // feedback about allocation site. Once the code is optimized we expect the
  // data to converge. So, we disable allocation site mementos in optimized
  // code. We can revisit this when we have data to the contrary.
  literal_flags |= ArrayLiteral::kDisableMementos;
  int number_of_elements =
      array_boilerplate_description.constants_elements_length();
  static_assert(JSCreateLiteralArrayNode::FeedbackVectorIndex() == 0);
  const Operator* op = javascript()->CreateLiteralArray(
      array_boilerplate_description, pair, literal_flags, number_of_elements);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* literal = NewNode(op, feedback_vector_node());
  environment()->BindAccumulator(literal, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitCreateEmptyArrayLiteral() {
  int const slot_id = bytecode_iterator().GetIndexOperand(0);
  FeedbackSource pair = CreateFeedbackSource(slot_id);
  const Operator* op = javascript()->CreateEmptyLiteralArray(pair);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* literal = NewNode(op, feedback_vector_node());
  environment()->BindAccumulator(literal);
}

void BytecodeGraphBuilder::VisitCreateArrayFromIterable() {
  Node* iterable = NewNode(javascript(
"""


```