Response: The user wants a summary of the C++ source code file `v8/src/compiler/bytecode-graph-builder.cc`, specifically the functionality described in the provided snippet (which is the second part of three). The summary should also include a JavaScript example if the C++ code relates to JavaScript functionality.

My plan is to:

1. **Analyze the provided C++ code:** Go through each function (e.g., `VisitLdaGlobal`, `VisitStaGlobal`, `VisitGetNamedProperty`, `VisitCallAnyReceiver`, etc.) and understand its purpose based on its name and the operations it performs. Look for patterns and common themes.
2. **Identify JavaScript connections:** Determine how the C++ code relates to JavaScript concepts and operations. Keywords like "LoadGlobal", "StoreGlobal", "NamedProperty", "Call", "Construct", "Context", "Scope", etc., strongly suggest a connection to JavaScript semantics.
3. **Summarize the functionality:** Based on the analysis, provide a concise description of the overall purpose of this code snippet.
4. **Create JavaScript examples:** For key functionalities, provide simple JavaScript code snippets that illustrate the corresponding actions being performed by the C++ code.
这是 `v8/src/compiler/bytecode-graph-builder.cc` 源代码文件的第二部分，它主要负责将 JavaScript 字节码指令转换为 **TurboFan 图（中间表示）** 的节点。这个过程是 V8 编译优化的关键步骤，它将相对底层的字节码转换为更适合进行高级优化的图结构。

**核心功能归纳:**

* **加载和存储全局变量:**  处理 `LdaGlobal` 和 `StaGlobal` 指令，生成加载和存储全局变量的图节点。 这包括处理 `typeof` 运算符在全局变量上的特殊情况。
* **处理数组和对象字面量:**  处理在数组和对象字面量中进行元素定义和赋值的操作，如 `StaInArrayLiteral` 和 `DefineKeyedOwnPropertyInLiteral`。
* **上下文 (Context) 操作:** 处理与 JavaScript 上下文相关的操作，如加载和存储上下文槽 (`LdaContextSlot`, `StaContextSlot`)，这涉及到作用域链的查找。
* **变量查找 (Lookup):** 处理变量查找操作，包括在当前作用域和外层作用域中查找变量 (`LdaLookupSlot`, `LdaLookupContextSlot`, `LdaLookupGlobalSlot`)。这部分代码还涉及到对 `eval` 引入的上下文扩展进行检查，以确保变量查找的正确性。
* **属性访问:** 处理属性的读取 (`GetNamedProperty`, `GetKeyedProperty`) 和写入 (`SetNamedProperty`, `SetKeyedProperty`) 操作。
* **模块变量:**  处理模块级别的变量加载和存储 (`LdaModuleVariable`, `StaModuleVariable`)。
* **上下文切换:**  处理 `PushContext` 和 `PopContext` 指令，用于切换当前的执行上下文。
* **闭包创建:**  处理 `CreateClosure` 指令，创建闭包对象。
* **上下文创建:**  处理创建不同类型的上下文，如块级上下文 (`CreateBlockContext`)、函数上下文 (`CreateFunctionContext`)、 `eval` 上下文 (`CreateEvalContext`)、`catch` 上下文 (`CreateCatchContext`) 和 `with` 上下文 (`CreateWithContext`)。
* **arguments 对象创建:** 处理创建 `arguments` 对象的指令 (`CreateMappedArguments`, `CreateUnmappedArguments`, `CreateRestParameter`)。
* **字面量创建:** 处理创建正则表达式字面量 (`CreateRegExpLiteral`)、数组字面量 (`CreateArrayLiteral`, `CreateEmptyArrayLiteral`) 和对象字面量 (`CreateObjectLiteral`, `CreateEmptyObjectLiteral`) 的指令。
* **对象克隆:** 处理 `CloneObject` 指令，用于创建对象的浅拷贝。
* **模板对象:** 处理 `GetTemplateObject` 指令，用于获取模板字面量的模板对象。
* **函数调用:** 处理各种函数调用指令，包括普通函数调用 (`CallAnyReceiver`, `CallProperty`, `CallUndefinedReceiver`)、带 `spread` 语法的调用 (`CallWithSpread`) 和调用运行时函数 (`CallJSRuntime`, `CallRuntime`, `CallRuntimeForPair`)。
* **构造函数调用:** 处理 `new` 运算符的构造函数调用 (`Construct`, `ConstructWithSpread`, `ConstructForwardAllArgs`)。
* **内置函数调用:** 处理调用内置函数的指令 (`InvokeIntrinsic`)。
* **异常处理:** 处理 `throw` 和 `rethrow` 异常的指令，以及在访问未初始化变量时抛出错误的指令 (`ThrowReferenceErrorIfHole`, `ThrowSuperNotCalledIfHole`, `ThrowSuperAlreadyCalledIfNotHole`)。
* **类型检查:** 处理类型检查相关的指令，例如 `ThrowIfNotSuperConstructor`，用于确保 `super` 只能在构造函数中调用。
* **一元和二元运算符:**  为各种一元运算符 (`BitwiseNot`, `Dec`, `Inc`, `Negate`) 和二元运算符 (`Add`, `Sub`, `Mul`, `Div`, `Mod`, `Exp`, `BitwiseOr`, `BitwiseXor`, `BitwiseAnd`, `ShiftLeft`, `ShiftRight`) 生成相应的图节点。 这部分代码会利用类型反馈信息进行优化。
* **For-In 循环:**  提供获取 `for-in` 循环模式的方法，根据类型反馈进行优化。
* **调用频率和推测模式:**  计算函数调用的频率和推测模式，用于后续的优化决策。

**与 JavaScript 的关系及 JavaScript 示例:**

这部分 C++ 代码直接对应着 JavaScript 的各种语法结构和操作。每条字节码指令都旨在表示一个特定的 JavaScript 行为。

**示例 1: 加载全局变量 (`LdaGlobal`)**

```c++
void BytecodeGraphBuilder::VisitLdaGlobal(TypeofMode typeof_mode) {
  PrepareEagerCheckpoint();
  NameRef name = MakeRefForConstantForIndexOperand<Name>(0);
  uint32_t feedback_slot_index = bytecode_iterator().GetIndexOperand(1);
  Node* node = BuildLoadGlobal(name, feedback_slot_index, typeof_mode);
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}
```

**对应的 JavaScript 例子:**

```javascript
console.log(globalVariable); // 假设 globalVariable 是一个全局变量
```

当 V8 执行这段 JavaScript 代码时，会生成 `LdaGlobal` 字节码指令来加载 `globalVariable`。 上面的 C++ 代码负责将这个字节码指令转换为 TurboFan 图中的一个“加载全局变量”的节点。

**示例 2: 存储全局变量 (`StaGlobal`)**

```c++
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
```

**对应的 JavaScript 例子:**

```javascript
globalVariable = 10;
```

这段 JavaScript 代码会生成 `StaGlobal` 字节码指令来存储值 `10` 到全局变量 `globalVariable`。 相应的 C++ 代码会生成一个“存储全局变量”的图节点。

**示例 3: 函数调用 (`VisitCallProperty0`)**

```c++
void BytecodeGraphBuilder::VisitCallProperty0() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  int const slot_id = bytecode_iterator().GetIndexOperand(2);
  BuildCall(ConvertReceiverMode::kNotNullOrUndefined,
            {callee, receiver, feedback_vector_node()}, slot_id);
}
```

**对应的 JavaScript 例子:**

```javascript
object.method(); // 假设 object 有一个名为 method 的方法
```

这会生成 `CallProperty0` 字节码指令，表示调用 `object` 上的 `method` 函数（没有参数）。 C++ 代码会生成一个“函数调用”的图节点。

**总结:**

这部分 `bytecode-graph-builder.cc` 代码是连接 JavaScript 字节码和 TurboFan 优化器的桥梁。 它将各种 JavaScript 操作转化为图节点，为后续的类型推断、内联优化等高级优化奠定了基础。 理解这部分代码有助于深入了解 V8 引擎是如何将 JavaScript 代码编译和优化的。

Prompt: 
```
这是目录为v8/src/compiler/bytecode-graph-builder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

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
  Node* iterable = NewNode(javascript()->CreateArrayFromIterable(),
                           environment()->LookupAccumulator());
  environment()->BindAccumulator(iterable, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitCreateObjectLiteral() {
  ObjectBoilerplateDescriptionRef constant_properties =
      MakeRefForConstantForIndexOperand<ObjectBoilerplateDescription>(0);
  int const slot_id = bytecode_iterator().GetIndexOperand(1);
  FeedbackSource pair = CreateFeedbackSource(slot_id);
  int bytecode_flags = bytecode_iterator().GetFlag8Operand(2);
  int literal_flags =
      interpreter::CreateObjectLiteralFlags::FlagsBits::decode(bytecode_flags);
  int number_of_properties = constant_properties.boilerplate_properties_count();
  static_assert(JSCreateLiteralObjectNode::FeedbackVectorIndex() == 0);
  const Operator* op = javascript()->CreateLiteralObject(
      constant_properties, pair, literal_flags, number_of_properties);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* literal = NewNode(op, feedback_vector_node());
  environment()->BindAccumulator(literal, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitCreateEmptyObjectLiteral() {
  Node* literal = NewNode(javascript()->CreateEmptyLiteralObject());
  environment()->BindAccumulator(literal);
}

void BytecodeGraphBuilder::VisitCloneObject() {
  PrepareEagerCheckpoint();
  Node* source =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  int flags = bytecode_iterator().GetFlag8Operand(1);
  int slot = bytecode_iterator().GetIndexOperand(2);
  const Operator* op =
      javascript()->CloneObject(CreateFeedbackSource(slot), flags);
  static_assert(JSCloneObjectNode::SourceIndex() == 0);
  static_assert(JSCloneObjectNode::FeedbackVectorIndex() == 1);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* value = NewNode(op, source, feedback_vector_node());
  environment()->BindAccumulator(value, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitGetTemplateObject() {
  FeedbackSource source =
      CreateFeedbackSource(bytecode_iterator().GetIndexOperand(1));
  TemplateObjectDescriptionRef description =
      MakeRefForConstantForIndexOperand<TemplateObjectDescription>(0);
  static_assert(JSGetTemplateObjectNode::FeedbackVectorIndex() == 0);
  const Operator* op =
      javascript()->GetTemplateObject(description, shared_info(), source);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* template_object = NewNode(op, feedback_vector_node());
  environment()->BindAccumulator(template_object);
}

Node* const* BytecodeGraphBuilder::GetCallArgumentsFromRegisters(
    Node* callee, Node* receiver, interpreter::Register first_arg,
    int arg_count) {
  const int arity = JSCallNode::ArityForArgc(arg_count);
  Node** all = local_zone()->AllocateArray<Node*>(static_cast<size_t>(arity));
  int cursor = 0;

  static_assert(JSCallNode::TargetIndex() == 0);
  static_assert(JSCallNode::ReceiverIndex() == 1);
  static_assert(JSCallNode::FirstArgumentIndex() == 2);
  static_assert(JSCallNode::kFeedbackVectorIsLastInput);

  all[cursor++] = callee;
  all[cursor++] = receiver;

  // The function arguments are in consecutive registers.
  const int arg_base = first_arg.index();
  for (int i = 0; i < arg_count; ++i) {
    all[cursor++] =
        environment()->LookupRegister(interpreter::Register(arg_base + i));
  }

  all[cursor++] = feedback_vector_node();

  DCHECK_EQ(cursor, arity);
  return all;
}

void BytecodeGraphBuilder::BuildCall(ConvertReceiverMode receiver_mode,
                                     Node* const* args, size_t arg_count,
                                     int slot_id) {
  DCHECK_EQ(interpreter::Bytecodes::GetReceiverMode(
                bytecode_iterator().current_bytecode()),
            receiver_mode);
  PrepareEagerCheckpoint();

  FeedbackSource feedback = CreateFeedbackSource(slot_id);
  CallFrequency frequency = ComputeCallFrequency(slot_id);
  SpeculationMode speculation_mode = GetSpeculationMode(slot_id);
  CallFeedbackRelation call_feedback_relation =
      ComputeCallFeedbackRelation(slot_id);
  const Operator* op =
      javascript()->Call(arg_count, frequency, feedback, receiver_mode,
                         speculation_mode, call_feedback_relation);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));

  JSTypeHintLowering::LoweringResult lowering = TryBuildSimplifiedCall(
      op, args, static_cast<int>(arg_count), feedback.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    node = MakeNode(op, static_cast<int>(arg_count), args);
  }
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

Node* const* BytecodeGraphBuilder::ProcessCallVarArgs(
    ConvertReceiverMode receiver_mode, Node* callee,
    interpreter::Register first_reg, int arg_count) {
  DCHECK_GE(arg_count, 0);
  Node* receiver_node;
  interpreter::Register first_arg;

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    // The receiver is implicit (and undefined), the arguments are in
    // consecutive registers.
    receiver_node = jsgraph()->UndefinedConstant();
    first_arg = first_reg;
  } else {
    // The receiver is the first register, followed by the arguments in the
    // consecutive registers.
    receiver_node = environment()->LookupRegister(first_reg);
    first_arg = interpreter::Register(first_reg.index() + 1);
  }

  Node* const* call_args = GetCallArgumentsFromRegisters(callee, receiver_node,
                                                         first_arg, arg_count);
  return call_args;
}

void BytecodeGraphBuilder::BuildCallVarArgs(ConvertReceiverMode receiver_mode) {
  DCHECK_EQ(interpreter::Bytecodes::GetReceiverMode(
                bytecode_iterator().current_bytecode()),
            receiver_mode);
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  interpreter::Register first_reg = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);
  int const slot_id = bytecode_iterator().GetIndexOperand(3);

  int arg_count = receiver_mode == ConvertReceiverMode::kNullOrUndefined
                      ? static_cast<int>(reg_count)
                      : static_cast<int>(reg_count) - 1;
  Node* const* call_args =
      ProcessCallVarArgs(receiver_mode, callee, first_reg, arg_count);
  BuildCall(receiver_mode, call_args, JSCallNode::ArityForArgc(arg_count),
            slot_id);
}

void BytecodeGraphBuilder::VisitCallAnyReceiver() {
  BuildCallVarArgs(ConvertReceiverMode::kAny);
}

void BytecodeGraphBuilder::VisitCallProperty() {
  BuildCallVarArgs(ConvertReceiverMode::kNotNullOrUndefined);
}

void BytecodeGraphBuilder::VisitCallProperty0() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  int const slot_id = bytecode_iterator().GetIndexOperand(2);
  BuildCall(ConvertReceiverMode::kNotNullOrUndefined,
            {callee, receiver, feedback_vector_node()}, slot_id);
}

void BytecodeGraphBuilder::VisitCallProperty1() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  Node* arg0 =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(2));
  int const slot_id = bytecode_iterator().GetIndexOperand(3);
  BuildCall(ConvertReceiverMode::kNotNullOrUndefined,
            {callee, receiver, arg0, feedback_vector_node()}, slot_id);
}

void BytecodeGraphBuilder::VisitCallProperty2() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  Node* arg0 =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(2));
  Node* arg1 =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(3));
  int const slot_id = bytecode_iterator().GetIndexOperand(4);
  BuildCall(ConvertReceiverMode::kNotNullOrUndefined,
            {callee, receiver, arg0, arg1, feedback_vector_node()}, slot_id);
}

void BytecodeGraphBuilder::VisitCallUndefinedReceiver() {
  BuildCallVarArgs(ConvertReceiverMode::kNullOrUndefined);
}

void BytecodeGraphBuilder::VisitCallUndefinedReceiver0() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver = jsgraph()->UndefinedConstant();
  int const slot_id = bytecode_iterator().GetIndexOperand(1);
  BuildCall(ConvertReceiverMode::kNullOrUndefined,
            {callee, receiver, feedback_vector_node()}, slot_id);
}

void BytecodeGraphBuilder::VisitCallUndefinedReceiver1() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver = jsgraph()->UndefinedConstant();
  Node* arg0 =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  int const slot_id = bytecode_iterator().GetIndexOperand(2);
  BuildCall(ConvertReceiverMode::kNullOrUndefined,
            {callee, receiver, arg0, feedback_vector_node()}, slot_id);
}

void BytecodeGraphBuilder::VisitCallUndefinedReceiver2() {
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* receiver = jsgraph()->UndefinedConstant();
  Node* arg0 =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  Node* arg1 =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(2));
  int const slot_id = bytecode_iterator().GetIndexOperand(3);
  BuildCall(ConvertReceiverMode::kNullOrUndefined,
            {callee, receiver, arg0, arg1, feedback_vector_node()}, slot_id);
}

void BytecodeGraphBuilder::VisitCallWithSpread() {
  PrepareEagerCheckpoint();
  Node* callee =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  interpreter::Register receiver = bytecode_iterator().GetRegisterOperand(1);
  Node* receiver_node = environment()->LookupRegister(receiver);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);
  interpreter::Register first_arg = interpreter::Register(receiver.index() + 1);
  int arg_count = static_cast<int>(reg_count) - 1;
  Node* const* args = GetCallArgumentsFromRegisters(callee, receiver_node,
                                                    first_arg, arg_count);
  int const slot_id = bytecode_iterator().GetIndexOperand(3);
  FeedbackSource feedback = CreateFeedbackSource(slot_id);
  CallFrequency frequency = ComputeCallFrequency(slot_id);
  SpeculationMode speculation_mode = GetSpeculationMode(slot_id);
  const Operator* op = javascript()->CallWithSpread(
      JSCallWithSpreadNode::ArityForArgc(arg_count), frequency, feedback,
      speculation_mode);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));

  JSTypeHintLowering::LoweringResult lowering = TryBuildSimplifiedCall(
      op, args, static_cast<int>(arg_count), feedback.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    node = MakeNode(op, JSCallWithSpreadNode::ArityForArgc(arg_count), args);
  }
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitCallJSRuntime() {
  PrepareEagerCheckpoint();
  Node* callee = BuildLoadNativeContextField(
      bytecode_iterator().GetNativeContextIndexOperand(0));
  interpreter::Register first_reg = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);
  int arg_count = static_cast<int>(reg_count);
  int arity = JSCallNode::ArityForArgc(arg_count);

  const Operator* call = javascript()->Call(arity);
  Node* const* call_args = ProcessCallVarArgs(
      ConvertReceiverMode::kNullOrUndefined, callee, first_reg, arg_count);
  Node* value = MakeNode(call, arity, call_args);
  environment()->BindAccumulator(value, Environment::kAttachFrameState);
}

Node* BytecodeGraphBuilder::ProcessCallRuntimeArguments(
    const Operator* call_runtime_op, interpreter::Register receiver,
    size_t reg_count) {
  int arg_count = static_cast<int>(reg_count);
  // arity is args.
  int arity = arg_count;
  Node** all = local_zone()->AllocateArray<Node*>(static_cast<size_t>(arity));
  int first_arg_index = receiver.index();
  for (int i = 0; i < static_cast<int>(reg_count); ++i) {
    all[i] = environment()->LookupRegister(
        interpreter::Register(first_arg_index + i));
  }
  Node* value = MakeNode(call_runtime_op, arity, all);
  return value;
}

void BytecodeGraphBuilder::VisitCallRuntime() {
  PrepareEagerCheckpoint();
  Runtime::FunctionId function_id = bytecode_iterator().GetRuntimeIdOperand(0);
  interpreter::Register receiver = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);

  // Handle %ObserveNode here (rather than in JSIntrinsicLowering) to observe
  // the node as early as possible.
  if (function_id == Runtime::FunctionId::kObserveNode) {
    DCHECK_EQ(1, reg_count);
    Node* value = environment()->LookupRegister(receiver);
    observe_node_info_.StartObserving(value);
    environment()->BindAccumulator(value);
  } else {
    // Create node to perform the runtime call.
    const Operator* call = javascript()->CallRuntime(function_id, reg_count);
    Node* value = ProcessCallRuntimeArguments(call, receiver, reg_count);
    environment()->BindAccumulator(value, Environment::kAttachFrameState);

    // Connect to the end if {function_id} is non-returning.
    if (Runtime::IsNonReturning(function_id)) {
      // TODO(7099): Investigate if we need LoopExit node here.
      Node* control = NewNode(common()->Throw());
      MergeControlToLeaveFunction(control);
    }
  }
}

void BytecodeGraphBuilder::VisitCallRuntimeForPair() {
  PrepareEagerCheckpoint();
  Runtime::FunctionId functionId = bytecode_iterator().GetRuntimeIdOperand(0);
  interpreter::Register receiver = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);
  interpreter::Register first_return =
      bytecode_iterator().GetRegisterOperand(3);

  // Create node to perform the runtime call.
  const Operator* call = javascript()->CallRuntime(functionId, reg_count);
  Node* return_pair = ProcessCallRuntimeArguments(call, receiver, reg_count);
  environment()->BindRegistersToProjections(first_return, return_pair,
                                            Environment::kAttachFrameState);
}

Node* const* BytecodeGraphBuilder::GetConstructArgumentsFromRegister(
    Node* target, Node* new_target, interpreter::Register first_arg,
    int arg_count) {
  const int arity = JSConstructNode::ArityForArgc(arg_count);
  Node** all = local_zone()->AllocateArray<Node*>(static_cast<size_t>(arity));
  int cursor = 0;

  static_assert(JSConstructNode::TargetIndex() == 0);
  static_assert(JSConstructNode::NewTargetIndex() == 1);
  static_assert(JSConstructNode::FirstArgumentIndex() == 2);
  static_assert(JSConstructNode::kFeedbackVectorIsLastInput);

  all[cursor++] = target;
  all[cursor++] = new_target;

  // The function arguments are in consecutive registers.
  int arg_base = first_arg.index();
  for (int i = 0; i < arg_count; ++i) {
    all[cursor++] =
        environment()->LookupRegister(interpreter::Register(arg_base + i));
  }

  all[cursor++] = feedback_vector_node();

  DCHECK_EQ(cursor, arity);
  return all;
}

void BytecodeGraphBuilder::VisitConstruct() {
  PrepareEagerCheckpoint();
  interpreter::Register callee_reg = bytecode_iterator().GetRegisterOperand(0);
  interpreter::Register first_reg = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);
  int const slot_id = bytecode_iterator().GetIndexOperand(3);
  FeedbackSource feedback = CreateFeedbackSource(slot_id);

  Node* new_target = environment()->LookupAccumulator();
  Node* callee = environment()->LookupRegister(callee_reg);

  CallFrequency frequency = ComputeCallFrequency(slot_id);
  const uint32_t arg_count = static_cast<uint32_t>(reg_count);
  const uint32_t arity = JSConstructNode::ArityForArgc(arg_count);
  const Operator* op = javascript()->Construct(arity, frequency, feedback);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* const* args = GetConstructArgumentsFromRegister(callee, new_target,
                                                        first_reg, arg_count);
  JSTypeHintLowering::LoweringResult lowering = TryBuildSimplifiedConstruct(
      op, args, static_cast<int>(arg_count), feedback.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    node = MakeNode(op, arity, args);
  }
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitConstructWithSpread() {
  PrepareEagerCheckpoint();
  interpreter::Register callee_reg = bytecode_iterator().GetRegisterOperand(0);
  interpreter::Register first_reg = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);
  int const slot_id = bytecode_iterator().GetIndexOperand(3);
  FeedbackSource feedback = CreateFeedbackSource(slot_id);

  Node* new_target = environment()->LookupAccumulator();
  Node* callee = environment()->LookupRegister(callee_reg);

  CallFrequency frequency = ComputeCallFrequency(slot_id);
  const uint32_t arg_count = static_cast<uint32_t>(reg_count);
  const uint32_t arity = JSConstructNode::ArityForArgc(arg_count);
  const Operator* op =
      javascript()->ConstructWithSpread(arity, frequency, feedback);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* const* args = GetConstructArgumentsFromRegister(callee, new_target,
                                                        first_reg, arg_count);
  JSTypeHintLowering::LoweringResult lowering = TryBuildSimplifiedConstruct(
      op, args, static_cast<int>(arg_count), feedback.slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    node = MakeNode(op, arity, args);
  }
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitConstructForwardAllArgs() {
  PrepareEagerCheckpoint();
  interpreter::Register callee_reg = bytecode_iterator().GetRegisterOperand(0);
  int const slot_id = bytecode_iterator().GetIndexOperand(1);
  FeedbackSource feedback = CreateFeedbackSource(slot_id);
  Node* new_target = environment()->LookupAccumulator();
  Node* callee = environment()->LookupRegister(callee_reg);
  CallFrequency frequency = ComputeCallFrequency(slot_id);

  // Use 0 as a fake argument count.
  //
  // This op will be later reduced to either a builtin call (in the case of not
  // being inlined) or a normal JSConstruct with the inlined arguments
  // forwarded.
  constexpr int arg_count = 0;
  const int arity = JSConstructForwardAllArgsNode::ArityForArgc(arg_count);
  Node** construct_args =
      local_zone()->AllocateArray<Node*>(static_cast<size_t>(arity));
  static_assert(JSConstructForwardAllArgsNode::TargetIndex() == 0);
  static_assert(JSConstructForwardAllArgsNode::NewTargetIndex() == 1);
  static_assert(JSConstructNode::kFeedbackVectorIsLastInput);
  DCHECK_LT(JSConstructForwardAllArgsNode::NewTargetIndex(), arity);
  int cursor = 0;
  construct_args[cursor++] = callee;
  construct_args[cursor++] = new_target;
  construct_args[cursor++] = feedback_vector_node();

  const Operator* op =
      javascript()->ConstructForwardAllArgs(frequency, feedback);
  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedConstruct(op, construct_args, arg_count, feedback.slot);
  if (lowering.IsExit()) return;

  Node* node;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    node = MakeNode(op, arity, construct_args);
  }

  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitInvokeIntrinsic() {
  PrepareEagerCheckpoint();
  Runtime::FunctionId functionId = bytecode_iterator().GetIntrinsicIdOperand(0);
  interpreter::Register receiver = bytecode_iterator().GetRegisterOperand(1);
  size_t reg_count = bytecode_iterator().GetRegisterCountOperand(2);

  // Create node to perform the runtime call. Turbofan will take care of the
  // lowering.
  const Operator* call = javascript()->CallRuntime(functionId, reg_count);
  Node* value = ProcessCallRuntimeArguments(call, receiver, reg_count);
  environment()->BindAccumulator(value, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitThrow() {
  BuildLoopExitsForFunctionExit(bytecode_analysis().GetInLivenessFor(
      bytecode_iterator().current_offset()));
  Node* value = environment()->LookupAccumulator();
  Node* call = NewNode(javascript()->CallRuntime(Runtime::kThrow), value);
  environment()->BindAccumulator(call, Environment::kAttachFrameState);
  Node* control = NewNode(common()->Throw());
  MergeControlToLeaveFunction(control);
}

void BytecodeGraphBuilder::VisitAbort() {
  BuildLoopExitsForFunctionExit(bytecode_analysis().GetInLivenessFor(
      bytecode_iterator().current_offset()));
  AbortReason reason =
      static_cast<AbortReason>(bytecode_iterator().GetIndexOperand(0));
  NewNode(simplified()->RuntimeAbort(reason));
  Node* control = NewNode(common()->Throw());
  MergeControlToLeaveFunction(control);
}

void BytecodeGraphBuilder::VisitReThrow() {
  BuildLoopExitsForFunctionExit(bytecode_analysis().GetInLivenessFor(
      bytecode_iterator().current_offset()));
  Node* value = environment()->LookupAccumulator();
  NewNode(javascript()->CallRuntime(Runtime::kReThrow), value);
  Node* control = NewNode(common()->Throw());
  MergeControlToLeaveFunction(control);
}

void BytecodeGraphBuilder::BuildHoleCheckAndThrow(
    Node* condition, Runtime::FunctionId runtime_id, Node* name) {
  Node* accumulator = environment()->LookupAccumulator();
  NewBranch(condition, BranchHint::kFalse);
  {
    SubEnvironment sub_environment(this);

    NewIfTrue();
    BuildLoopExitsForFunctionExit(bytecode_analysis().GetInLivenessFor(
        bytecode_iterator().current_offset()));
    Node* node;
    const Operator* op = javascript()->CallRuntime(runtime_id);
    if (runtime_id == Runtime::kThrowAccessedUninitializedVariable) {
      DCHECK_NOT_NULL(name);
      node = NewNode(op, name);
    } else {
      DCHECK(runtime_id == Runtime::kThrowSuperAlreadyCalledError ||
             runtime_id == Runtime::kThrowSuperNotCalled);
      node = NewNode(op);
    }
    environment()->RecordAfterState(node, Environment::kAttachFrameState);
    Node* control = NewNode(common()->Throw());
    MergeControlToLeaveFunction(control);
  }
  NewIfFalse();
  environment()->BindAccumulator(accumulator);
}

void BytecodeGraphBuilder::VisitThrowReferenceErrorIfHole() {
  Node* accumulator = environment()->LookupAccumulator();
  Node* check_for_hole = NewNode(simplified()->ReferenceEqual(), accumulator,
                                 jsgraph()->TheHoleConstant());
  Node* name =
      jsgraph()->ConstantNoHole(MakeRefForConstantForIndexOperand(0), broker());
  BuildHoleCheckAndThrow(check_for_hole,
                         Runtime::kThrowAccessedUninitializedVariable, name);
}

void BytecodeGraphBuilder::VisitThrowSuperNotCalledIfHole() {
  Node* accumulator = environment()->LookupAccumulator();
  Node* check_for_hole = NewNode(simplified()->ReferenceEqual(), accumulator,
                                 jsgraph()->TheHoleConstant());
  BuildHoleCheckAndThrow(check_for_hole, Runtime::kThrowSuperNotCalled);
}

void BytecodeGraphBuilder::VisitThrowSuperAlreadyCalledIfNotHole() {
  Node* accumulator = environment()->LookupAccumulator();
  Node* check_for_hole = NewNode(simplified()->ReferenceEqual(), accumulator,
                                 jsgraph()->TheHoleConstant());
  Node* check_for_not_hole =
      NewNode(simplified()->BooleanNot(), check_for_hole);
  BuildHoleCheckAndThrow(check_for_not_hole,
                         Runtime::kThrowSuperAlreadyCalledError);
}

void BytecodeGraphBuilder::VisitThrowIfNotSuperConstructor() {
  Node* constructor =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* check_is_constructor =
      NewNode(simplified()->ObjectIsConstructor(), constructor);
  NewBranch(check_is_constructor, BranchHint::kTrue);
  {
    SubEnvironment sub_environment(this);
    NewIfFalse();
    BuildLoopExitsForFunctionExit(bytecode_analysis().GetInLivenessFor(
        bytecode_iterator().current_offset()));
    Node* node =
        NewNode(javascript()->CallRuntime(Runtime::kThrowNotSuperConstructor),
                constructor, GetFunctionClosure());
    environment()->RecordAfterState(node, Environment::kAttachFrameState);
    Node* control = NewNode(common()->Throw());
    MergeControlToLeaveFunction(control);
  }
  NewIfTrue();

  constructor = NewNode(common()->TypeGuard(Type::Callable()), constructor);
  environment()->BindRegister(bytecode_iterator().GetRegisterOperand(0),
                              constructor);
}

void BytecodeGraphBuilder::BuildUnaryOp(const Operator* op) {
  DCHECK(JSOperator::IsUnaryWithFeedback(op->opcode()));
  PrepareEagerCheckpoint();
  Node* operand = environment()->LookupAccumulator();

  FeedbackSlot slot =
      bytecode_iterator().GetSlotOperand(kUnaryOperationHintIndex);
  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedUnaryOp(op, operand, slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
    node = NewNode(op, operand, feedback_vector_node());
  }

  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::BuildBinaryOp(const Operator* op) {
  DCHECK(JSOperator::IsBinaryWithFeedback(op->opcode()));
  PrepareEagerCheckpoint();
  Node* left =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* right = environment()->LookupAccumulator();

  FeedbackSlot slot =
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex);
  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedBinaryOp(op, left, right, slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
    node = NewNode(op, left, right, feedback_vector_node());
  }

  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

// Helper function to create for-in mode from the recorded type feedback.
ForInMode BytecodeGraphBuilder::GetForInMode(FeedbackSlot slot) {
  FeedbackSource source(feedback_vector(), slot);
  switch (broker()->GetFeedbackForForIn(source)) {
    case ForInHint::kNone:
    case ForInHint::kEnumCacheKeysAndIndices:
      return ForInMode::kUseEnumCacheKeysAndIndices;
    case ForInHint::kEnumCacheKeys:
      return ForInMode::kUseEnumCacheKeys;
    case ForInHint::kAny:
      return ForInMode::kGeneric;
  }
  UNREACHABLE();
}

CallFrequency BytecodeGraphBuilder::ComputeCallFrequency(int slot_id) const {
  if (invocation_frequency_.IsUnknown()) return CallFrequency();
  FeedbackSlot slot = FeedbackVector::ToSlot(slot_id);
  FeedbackSource source(feedback_vector(), slot);
  ProcessedFeedback const& feedback = broker()->GetFeedbackForCall(source);
  float feedback_frequency =
      feedback.IsInsufficient() ? 0.0f : feedback.AsCall().frequency();
  if (feedback_frequency == 0.0f) {  // Prevent multiplying zero and infinity.
    return CallFrequency(0.0f);
  } else {
    return CallFrequency(feedback_frequency * invocation_frequency_.value());
  }
}

SpeculationMode BytecodeGraphBuilder::GetSpeculationMode(int slot_id) const {
  FeedbackSlot slot = FeedbackVector::ToSlot(slot_id);
  FeedbackSource source(feedback_vector(), slot);
  ProcessedFeedback const& feedback = broker()->GetFeedbackForCall(source);
  return feedback.IsInsufficient() ? SpeculationMode::kDisallowSpeculation
                                   : feedback.AsCall().speculation_mode();
}

CallFeedbackRelation BytecodeGraphBuilder::ComputeCallFeedbackRelation(
    int slot_id) const {
  FeedbackSlot slot = FeedbackVector::ToSlot(slot_id);
  FeedbackSource source(feedback_vector(), slot);
  ProcessedFeedback const& feedback = broker()->GetFeedbackForCall(source);
  if (feedback.IsInsufficient()) return CallFeedbackRelation::kUnrelated;
  CallFeedbackContent call_feedback_content =
      feedback.AsCall().call_feedback_content();
  return call_feedback_content == CallFeedbackContent::kTarget
             ? CallFeedbackRelation::kTarget
             : CallFeedbackRelation::kReceiver;
}

void BytecodeGraphBuilder::VisitBitwiseNot() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kUnaryOperationHintIndex));
  BuildUnaryOp(javascript()->BitwiseNot(feedback));
}

void BytecodeGraphBuilder::VisitDec() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kUnaryOperationHintIndex));
  BuildUnaryOp(javascript()->Decrement(feedback));
}

void BytecodeGraphBuilder::VisitInc() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kUnaryOperationHintIndex));
  BuildUnaryOp(javascript()->Increment(feedback));
}

void BytecodeGraphBuilder::VisitNegate() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kUnaryOperationHintIndex));
  BuildUnaryOp(javascript()->Negate(feedback));
}

void BytecodeGraphBuilder::VisitAdd() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->Add(feedback));
}

void BytecodeGraphBuilder::VisitSub() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->Subtract(feedback));
}

void BytecodeGraphBuilder::VisitMul() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->Multiply(feedback));
}

void BytecodeGraphBuilder::VisitDiv() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->Divide(feedback));
}

void BytecodeGraphBuilder::VisitMod() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->Modulus(feedback));
}

void BytecodeGraphBuilder::VisitExp() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->Exponentiate(feedback));
}

void BytecodeGraphBuilder::VisitBitwiseOr() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->BitwiseOr(feedback));
}

void BytecodeGraphBuilder::VisitBitwiseXor() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->BitwiseXor(feedback));
}

void BytecodeGraphBuilder::VisitBitwiseAnd() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->BitwiseAnd(feedback));
}

void BytecodeGraphBuilder::VisitShiftLeft() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->ShiftLeft(feedback));
}

void BytecodeGraphBuilder::VisitShiftRight() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javas
"""


```