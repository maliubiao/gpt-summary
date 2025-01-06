Response: The user has provided the second part of a C++ source code file (`v8/src/compiler/js-typed-lowering.cc`) and is asking for a summary of its functionality. They also want to understand its relationship with JavaScript, illustrated with JavaScript examples if applicable.

**High-Level Plan:**

1. **Analyze the C++ code:** Read through the provided code snippets and identify the main functions (methods) and their purpose. Focus on the actions performed within each function, especially concerning V8's internal representations and operations.
2. **Identify core functionalities:** Group related functions to determine the overall capabilities of this part of the file.
3. **Relate to JavaScript:**  Connect the identified C++ functionalities to corresponding JavaScript concepts or operations. Think about how these low-level operations enable or optimize JavaScript behavior.
4. **Provide JavaScript examples:** For relevant functionalities, create simple JavaScript code snippets that demonstrate the behavior being implemented in the C++ code.
5. **Structure the summary:** Organize the findings into a clear and concise explanation, addressing the user's request for a functional summary and its relation to JavaScript.

**Detailed Breakdown of the Code:**

* **`ReduceJSStoreContext(Node* node)` and `ReduceJSStoreScriptContext(Node* node)`:** These functions handle storing values into context variables. They involve traversing the context chain and potentially dealing with different types of context slots (mutable, constant, heap numbers).
* **`BuildGetModuleCell(Node* node)`:** This function retrieves the "cell" associated with a module variable. This cell holds the actual value of the module's export or import.
* **`ReduceJSLoadModule(Node* node)` and `ReduceJSStoreModule(Node* node)`:** These functions load and store values from module variables, utilizing the `BuildGetModuleCell` function.
* **`ReduceBuiltin(...)`:** This function appears to optimize calls to built-in JavaScript functions by directly calling the C++ implementation (CEntry).
* **`ReduceJSConstructForwardVarargs(Node* node)` and `ReduceJSConstruct(Node* node)`:** These functions handle the `new` operator in JavaScript (constructor calls). They optimize calls to known constructors.
* **`ReduceJSCallForwardVarargs(Node* node)` and `ReduceJSCall(Node* node)`:** These functions handle regular function calls in JavaScript, including optimizations for known functions and built-ins.
* **`ReduceJSForInNext(Node* node)` and `ReduceJSForInPrepare(Node* node)`:** These functions implement the logic for the `for...in` loop in JavaScript, dealing with iterating over object properties.
* **`ReduceJSLoadMessage(Node* node)` and `ReduceJSStoreMessage(Node* node)`:** These seem to handle storing and retrieving pending exception messages within the V8 engine.
* **`ReduceJSGeneratorStore(Node* node)`, `ReduceJSGeneratorRestoreContinuation(Node* node)`, `ReduceJSGeneratorRestoreContext(Node* node)`, `ReduceJSGeneratorRestoreRegister(Node* node)`, `ReduceJSGeneratorRestoreInputOrDebugPos(Node* node)`:** These functions are related to the implementation of JavaScript generators (functions with `yield`). They handle storing and restoring the state of a generator.
* **`ReduceObjectIsArray(Node* node)`:** This function implements the `Array.isArray()` check in JavaScript, optimizing for known array types.
* **`ReduceJSParseInt(Node* node)`:** This function optimizes calls to `parseInt()` when the input is already a safe integer.
* **`ReduceJSResolvePromise(Node* node)`:** This function optimizes promise resolution when the resolved value is a primitive.
* **`Reduce(Node* node)`:** This is a central dispatch function that calls the appropriate `Reduce` function based on the `IrOpcode` of the input `node`. This suggests this file is part of a larger reduction or optimization pipeline.
* **Helper functions:** Functions like `factory()`, `graph()`, `dependencies()`, `isolate()`, `javascript()`, `common()`, `simplified()` provide access to V8's internal components.

**Connecting to JavaScript:**

The core theme of this part of the file is the optimization and lowering of JavaScript operations to simpler, lower-level operations within V8's compiler. This involves:

* **Context management:** Handling variable access in different scopes.
* **Module loading:** Implementing the import/export mechanism.
* **Function calls:** Optimizing calls to built-in functions and regular JavaScript functions.
* **Constructor calls:** Optimizing the creation of new objects.
* **Iteration:** Implementing the `for...in` loop.
* **Error handling:** Managing exceptions.
* **Asynchronous programming:** Supporting generators and promises.
* **Type checking:** Implementing built-in type checking functions like `Array.isArray()`.
* **Type conversion:** Optimizing type conversion functions like `parseInt()`.

**JavaScript Examples:**

I will provide examples for the most relevant functionalities.

**Self-Correction/Refinement:**

Initially, I might focus too much on the individual low-level operations. I need to synthesize these individual actions into a higher-level understanding of what the file achieves in the context of JavaScript execution. Also, ensuring the JavaScript examples clearly illustrate the C++ code's purpose is crucial. I should prioritize examples that are easy to understand and directly relate to the optimizations being performed.
这是 C++ 源代码文件 `v8/src/compiler/js-typed-lowering.cc` 的第二部分，它延续了第一部分的功能，主要负责将 **类型化的 JavaScript 抽象语法树节点（JSAST nodes）** 降低（lowering）到更底层的、更接近机器指令的 **简化节点（Simplified nodes）**。 这个过程是 V8 编译器优化管道中的一个关键步骤，它利用类型信息来执行更高效的操作。

延续第一部分的分析，这部分代码继续处理各种 JavaScript 语言结构，并将其转换为更底层的操作。以下是这部分代码的主要功能归纳：

**核心功能：类型化 JavaScript 节点的降级**

这部分代码的核心目标仍然是将高级的、类型化的 JavaScript 操作转化为更底层的、更易于优化的操作。它针对特定的 JavaScript 语法结构，根据已知的类型信息，选择更优的实现方式。

**具体处理的 JavaScript 功能（延续第一部分）：**

* **上下文变量的存储 (Store Context Variables):**
    * `ReduceJSStoreContext`:  处理向上下文中存储变量的操作，涉及遍历上下文链。
    * `ReduceJSStoreScriptContext`: 处理向脚本上下文中存储变量的操作，并考虑了变量的可变性（`const` 等）。

* **模块加载和存储 (Module Load and Store):**
    * `BuildGetModuleCell`:  构建获取模块单元（Module Cell）的节点，模块单元存储了模块的导出或导入变量的值。
    * `ReduceJSLoadModule`:  处理加载模块变量的操作。
    * `ReduceJSStoreModule`: 处理存储模块变量的操作。

* **内置函数的优化调用 (Optimized Built-in Function Calls):**
    * `ReduceBuiltin`:  对于已知的内置函数，直接调用其 C++ 实现 (CEntry)，避免了间接的 JavaScript 调用开销。

* **构造函数调用优化 (Constructor Call Optimization):**
    * `ReduceJSConstructForwardVarargs`: 优化使用 `...arguments` 转发参数的构造函数调用。
    * `ReduceJSConstruct`:  优化构造函数调用，特别是对于已知的构造函数，直接调用其构造存根 (construct stub)。

* **普通函数调用优化 (Regular Function Call Optimization):**
    * `ReduceJSCallForwardVarargs`: 优化使用 `...arguments` 转发参数的函数调用。
    * `ReduceJSCall`: 优化普通函数调用，对于已知函数，可能直接调用其代码对象或内置实现。

* **`for...in` 循环的优化 (Optimization of `for...in` Loops):**
    * `ReduceJSForInNext`: 处理 `for...in` 循环的下一次迭代，利用缓存和类型信息进行优化。
    * `ReduceJSForInPrepare`: 处理 `for...in` 循环的准备阶段，例如获取枚举器。

* **错误消息处理 (Error Message Handling):**
    * `ReduceJSLoadMessage`: 加载待处理的错误消息。
    * `ReduceJSStoreMessage`: 存储待处理的错误消息。

* **生成器 (Generators) 的状态管理 (State Management for Generators):**
    * `ReduceJSGeneratorStore`: 存储生成器的状态（上下文、延续、寄存器值等）。
    * `ReduceJSGeneratorRestoreContinuation`: 恢复生成器的延续点。
    * `ReduceJSGeneratorRestoreContext`: 恢复生成器的上下文。
    * `ReduceJSGeneratorRestoreRegister`: 恢复生成器的寄存器值。
    * `ReduceJSGeneratorRestoreInputOrDebugPos`: 恢复生成器的输入或调试位置。

* **类型检查内置函数的优化 (Optimization of Type Checking Built-in Functions):**
    * `ReduceObjectIsArray`: 优化 `Array.isArray()` 的调用，根据类型信息进行常量折叠或更高效的实现。

* **类型转换内置函数的优化 (Optimization of Type Conversion Built-in Functions):**
    * `ReduceJSParseInt`: 优化 `parseInt()` 的调用，特别是当输入已经是安全整数时。

* **Promise 相关的优化 (Promise Related Optimization):**
    * `ReduceJSResolvePromise`: 优化 Promise 的解析过程，特别是当解析值为原始类型时。

* **中央降级调度器 (Central Lowering Dispatcher):**
    * `Reduce(Node* node)`:  这是一个中心函数，根据输入的 JSAST 节点的类型 (`IrOpcode`)，分发到相应的 `Reduce` 函数进行降级处理。

**与 JavaScript 的关系及示例：**

这部分代码直接影响 JavaScript 代码的执行效率。它通过在编译时利用类型信息，将一些高级的 JavaScript 操作转换为更底层的、更快速的实现。

**示例 1：优化内置函数调用 (`ReduceBuiltin`)**

```javascript
// JavaScript 代码
Math.abs(-5); // 调用内置函数 Math.abs
```

在编译过程中，`ReduceBuiltin` 函数可能会识别出 `Math.abs` 是一个内置函数，并将其直接替换为对 V8 内部 C++ 实现的调用，而不是通过通常的 JavaScript 函数调用流程。这避免了查找函数对象、设置调用栈等开销。

**示例 2：优化构造函数调用 (`ReduceJSConstruct`)**

```javascript
// JavaScript 代码
const arr = new Array(10); // 调用 Array 构造函数
```

如果编译器已知 `Array` 是内置的构造函数，`ReduceJSConstruct` 可能会直接生成创建固定大小数组的底层操作，而不是通用的对象构造流程。

**示例 3：优化 `Array.isArray()` (`ReduceObjectIsArray`)**

```javascript
// JavaScript 代码
function isItArray(obj) {
  return Array.isArray(obj);
}

isItArray([1, 2, 3]); // true
isItArray({ key: 'value' }); // false
```

`ReduceObjectIsArray` 会根据 `obj` 的类型进行优化。如果编译器可以确定 `obj` 一定是数组，则会将 `Array.isArray(obj)` 替换为 `true` 常量。如果确定不是数组，则替换为 `false`。如果类型不确定，则会生成更底层的类型检查代码，但也会尝试进行一些优化，例如直接检查实例类型。

**示例 4：优化 `parseInt()` (`ReduceJSParseInt`)**

```javascript
// JavaScript 代码
const num = parseInt("123", 10); // 将字符串转换为整数
```

如果编译器可以确定传入 `parseInt` 的第一个参数已经是数字类型，并且第二个参数是 10 或未指定（默认为 10），`ReduceJSParseInt` 可能会直接使用该数字，而跳过字符串解析的步骤。

**总结:**

`v8/src/compiler/js-typed-lowering.cc` 的第二部分延续了其核心职责，即利用类型信息将 JavaScript 代码降低到更底层的表示，以便进行更有效的机器代码生成和执行。它覆盖了 JavaScript 语言的多种关键特性，并通过针对性的优化，显著提升了 JavaScript 代码的运行效率。这部分代码与 JavaScript 的关系非常紧密，它的工作直接决定了 JavaScript 代码最终的执行性能。

Prompt: 
```
这是目录为v8/src/compiler/js-typed-lowering.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
text);
  }

  TNode<Object> value = gasm.LoadField<Object>(
      AccessBuilder::ForContextSlot(access.index()), context);
  TNode<Object> result =
      gasm.SelectIf<Object>(gasm.ObjectIsSmi(value))
          .Then([&] { return value; })
          .Else([&] {
            TNode<Map> value_map =
                gasm.LoadMap(TNode<HeapObject>::UncheckedCast(value));
            return gasm.SelectIf<Object>(gasm.IsHeapNumberMap(value_map))
                .Then([&] {
                  size_t side_data_index =
                      access.index() - Context::MIN_CONTEXT_EXTENDED_SLOTS;
                  TNode<FixedArray> side_data = gasm.LoadField<FixedArray>(
                      AccessBuilder::ForContextSlot(
                          Context::CONTEXT_SIDE_TABLE_PROPERTY_INDEX),
                      context);
                  TNode<Object> data = gasm.LoadField<Object>(
                      AccessBuilder::ForFixedArraySlot(side_data_index),
                      side_data);
                  TNode<Object> property =
                      gasm.SelectIf<Object>(gasm.ObjectIsSmi(data))
                          .Then([&] { return data; })
                          .Else([&] {
                            return gasm.LoadField<Object>(
                                AccessBuilder::ForContextSideProperty(),
                                TNode<HeapObject>::UncheckedCast(data));
                          })
                          .Value();
                  return gasm
                      .SelectIf<Object>(gasm.ReferenceEqual(
                          property,
                          TNode<Object>::UncheckedCast(gasm.SmiConstant(
                              ContextSidePropertyCell::kMutableHeapNumber))))
                      .Then([&] {
                        Node* number = gasm.LoadHeapNumberValue(value);
                        // Allocate a new HeapNumber.
                        AllocationBuilder a(jsgraph(), broker(), gasm.effect(),
                                            gasm.control());
                        a.Allocate(sizeof(HeapNumber), AllocationType::kYoung,
                                   Type::OtherInternal());
                        a.Store(AccessBuilder::ForMap(),
                                broker()->heap_number_map());
                        a.Store(AccessBuilder::ForHeapNumberValue(), number);
                        Node* new_heap_number = a.Finish();
                        gasm.UpdateEffectControlWith(new_heap_number);
                        return TNode<Object>::UncheckedCast(new_heap_number);
                      })
                      .Else([&] { return value; })
                      .Value();
                })
                .Else([&] { return value; })
                .ExpectFalse()
                .Value();
          })
          .Value();

  ReplaceWithValue(node, result, gasm.effect(), gasm.control());
  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSStoreContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSStoreContext, node->opcode());
  ContextAccess const& access = ContextAccessOf(node->op());
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* context = NodeProperties::GetContextInput(node);
  Node* control = graph()->start();
  Node* value = NodeProperties::GetValueInput(node, 0);
  for (size_t i = 0; i < access.depth(); ++i) {
    context = effect = graph()->NewNode(
        simplified()->LoadField(
            AccessBuilder::ForContextSlotKnownPointer(Context::PREVIOUS_INDEX)),
        context, effect, control);
  }
  node->ReplaceInput(0, context);
  node->ReplaceInput(1, value);
  node->ReplaceInput(2, effect);
  NodeProperties::ChangeOp(
      node,
      simplified()->StoreField(AccessBuilder::ForContextSlot(access.index())));
  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSStoreScriptContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSStoreScriptContext, node->opcode());
  ContextAccess const& access = ContextAccessOf(node->op());
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  JSGraphAssembler gasm(broker(), jsgraph(), jsgraph()->zone(),
                        BranchSemantics::kJS);
  gasm.InitializeEffectControl(effect, control);

  TNode<Context> context =
      TNode<Context>::UncheckedCast(NodeProperties::GetContextInput(node));
  for (size_t i = 0; i < access.depth(); ++i) {
    context = gasm.LoadField<Context>(
        AccessBuilder::ForContextSlotKnownPointer(Context::PREVIOUS_INDEX),
        context);
  }

  TNode<Object> old_value = gasm.LoadField<Object>(
      AccessBuilder::ForContextSlot(access.index()), context);
  TNode<Object> new_value =
      TNode<Object>::UncheckedCast(NodeProperties::GetValueInput(node, 0));

  gasm.IfNot(gasm.ReferenceEqual(old_value, new_value)).Then([&] {
    size_t side_data_index =
        access.index() - Context::MIN_CONTEXT_EXTENDED_SLOTS;
    TNode<FixedArray> side_data = gasm.LoadField<FixedArray>(
        AccessBuilder::ForContextSlot(
            Context::CONTEXT_SIDE_TABLE_PROPERTY_INDEX),
        context);
    TNode<Object> data = gasm.LoadField<Object>(
        AccessBuilder::ForFixedArraySlot(side_data_index), side_data);

    TNode<Boolean> is_other = gasm.ReferenceEqual(
        data, TNode<Object>::UncheckedCast(
                  gasm.SmiConstant(ContextSidePropertyCell::kOther)));
    gasm.If(is_other)
        .Then([&] {
          gasm.StoreField(AccessBuilder::ForContextSlot(access.index()),
                          context, new_value);
        })
        .Else([&] {
          gasm.CheckIf(gasm.BooleanNot(gasm.IsUndefined(data)),
                       DeoptimizeReason::kWrongValue);
          TNode<Object> property =
              gasm.SelectIf<Object>(gasm.ObjectIsSmi(data))
                  .Then([&] { return data; })
                  .Else([&] {
                    return gasm.LoadField<Object>(
                        AccessBuilder::ForContextSideProperty(),
                        TNode<HeapObject>::UncheckedCast(data));
                  })
                  .Value();
          TNode<Boolean> is_const = gasm.ReferenceEqual(
              property, TNode<Object>::UncheckedCast(
                            gasm.SmiConstant(ContextSidePropertyCell::kConst)));
          gasm.CheckIf(gasm.BooleanNot(is_const),
                       DeoptimizeReason::kWrongValue);
          if (v8_flags.script_context_mutable_heap_number) {
            TNode<Boolean> is_smi_marker = gasm.ReferenceEqual(
                property, TNode<Object>::UncheckedCast(
                              gasm.SmiConstant(ContextSidePropertyCell::kSmi)));
            gasm.If(is_smi_marker)
                .Then([&] {
                  Node* smi_value = gasm.CheckSmi(new_value);
                  gasm.StoreField(
                      AccessBuilder::ForContextSlotSmi(access.index()), context,
                      smi_value);
                })
                .Else([&] {
                  // It must be a mutable heap number in this case.
                  Node* number_value = gasm.CheckNumber(new_value);
                  gasm.StoreField(AccessBuilder::ForHeapNumberValue(),
                                  old_value, number_value);
                });
          } else {
            gasm.StoreField(AccessBuilder::ForContextSlot(access.index()),
                            context, new_value);
          }
        })
        .ExpectTrue();
  });
  ReplaceWithValue(node, gasm.effect(), gasm.effect(), gasm.control());
  return Changed(node);
}

Node* JSTypedLowering::BuildGetModuleCell(Node* node) {
  DCHECK(node->opcode() == IrOpcode::kJSLoadModule ||
         node->opcode() == IrOpcode::kJSStoreModule);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  int32_t cell_index = OpParameter<int32_t>(node->op());
  Node* module = NodeProperties::GetValueInput(node, 0);
  Type module_type = NodeProperties::GetType(module);

  if (module_type.IsHeapConstant()) {
    SourceTextModuleRef module_constant =
        module_type.AsHeapConstant()->Ref().AsSourceTextModule();
    OptionalCellRef cell_constant =
        module_constant.GetCell(broker(), cell_index);
    if (cell_constant.has_value())
      return jsgraph()->ConstantNoHole(*cell_constant, broker());
  }

  FieldAccess field_access;
  int index;
  if (SourceTextModuleDescriptor::GetCellIndexKind(cell_index) ==
      SourceTextModuleDescriptor::kExport) {
    field_access = AccessBuilder::ForModuleRegularExports();
    index = cell_index - 1;
  } else {
    DCHECK_EQ(SourceTextModuleDescriptor::GetCellIndexKind(cell_index),
              SourceTextModuleDescriptor::kImport);
    field_access = AccessBuilder::ForModuleRegularImports();
    index = -cell_index - 1;
  }
  Node* array = effect = graph()->NewNode(simplified()->LoadField(field_access),
                                          module, effect, control);
  return graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForFixedArraySlot(index)), array,
      effect, control);
}

Reduction JSTypedLowering::ReduceJSLoadModule(Node* node) {
  DCHECK_EQ(IrOpcode::kJSLoadModule, node->opcode());
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  Node* cell = BuildGetModuleCell(node);
  if (cell->op()->EffectOutputCount() > 0) effect = cell;
  Node* value = effect =
      graph()->NewNode(simplified()->LoadField(AccessBuilder::ForCellValue()),
                       cell, effect, control);

  ReplaceWithValue(node, value, effect, control);
  return Changed(value);
}

Reduction JSTypedLowering::ReduceJSStoreModule(Node* node) {
  DCHECK_EQ(IrOpcode::kJSStoreModule, node->opcode());
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* value = NodeProperties::GetValueInput(node, 1);
  DCHECK_EQ(SourceTextModuleDescriptor::GetCellIndexKind(
                OpParameter<int32_t>(node->op())),
            SourceTextModuleDescriptor::kExport);

  Node* cell = BuildGetModuleCell(node);
  if (cell->op()->EffectOutputCount() > 0) effect = cell;
  effect =
      graph()->NewNode(simplified()->StoreField(AccessBuilder::ForCellValue()),
                       cell, value, effect, control);

  ReplaceWithValue(node, effect, effect, control);
  return Changed(value);
}

namespace {

void ReduceBuiltin(JSGraph* jsgraph, Node* node, Builtin builtin, int arity,
                   CallDescriptor::Flags flags) {
  // Patch {node} to a direct CEntry call.
  // ----------- A r g u m e n t s -----------
  // -- 0: CEntry
  // --- Stack args ---
  // -- 1: new_target
  // -- 2: target
  // -- 3: argc, including the receiver and implicit args (Smi)
  // -- 4: padding
  // -- 5: receiver
  // -- [6, 6 + n[: the n actual arguments passed to the builtin
  // --- Register args ---
  // -- 6 + n: the C entry point
  // -- 6 + n + 1: argc (Int32)
  // -----------------------------------

  // The logic contained here is mirrored in Builtins::Generate_Adaptor.
  // Keep these in sync.

  Node* target = node->InputAt(JSCallOrConstructNode::TargetIndex());

  // Unify representations between construct and call nodes. For construct
  // nodes, the receiver is undefined. For call nodes, the new_target is
  // undefined.
  Node* new_target;
  Zone* zone = jsgraph->zone();
  if (node->opcode() == IrOpcode::kJSConstruct) {
    static_assert(JSCallNode::ReceiverIndex() ==
                  JSConstructNode::NewTargetIndex());
    new_target = JSConstructNode{node}.new_target();
    node->ReplaceInput(JSConstructNode::NewTargetIndex(),
                       jsgraph->UndefinedConstant());
    node->RemoveInput(JSConstructNode{node}.FeedbackVectorIndex());
  } else {
    new_target = jsgraph->UndefinedConstant();
    node->RemoveInput(JSCallNode{node}.FeedbackVectorIndex());
  }

  // CPP builtins are implemented in C++, and we can inline it.
  // CPP builtins create a builtin exit frame.
  DCHECK(Builtins::IsCpp(builtin));
  const bool has_builtin_exit_frame = true;

  Node* stub =
      jsgraph->CEntryStubConstant(1, ArgvMode::kStack, has_builtin_exit_frame);
  node->ReplaceInput(0, stub);

  const int argc = arity + BuiltinArguments::kNumExtraArgsWithReceiver;
  Node* argc_node = jsgraph->ConstantNoHole(argc);

  static const int kStub = 1;
  static_assert(BuiltinArguments::kNewTargetIndex == 0);
  static_assert(BuiltinArguments::kTargetIndex == 1);
  static_assert(BuiltinArguments::kArgcIndex == 2);
  static_assert(BuiltinArguments::kPaddingIndex == 3);
  node->InsertInput(zone, 1, new_target);
  node->InsertInput(zone, 2, target);
  node->InsertInput(zone, 3, argc_node);
  node->InsertInput(zone, 4, jsgraph->PaddingConstant());
  int cursor = arity + kStub + BuiltinArguments::kNumExtraArgsWithReceiver;

  Address entry = Builtins::CppEntryOf(builtin);
  ExternalReference entry_ref = ExternalReference::Create(entry);
  Node* entry_node = jsgraph->ExternalConstant(entry_ref);

  node->InsertInput(zone, cursor++, entry_node);
  node->InsertInput(zone, cursor++, argc_node);

  static const int kReturnCount = 1;
  const char* debug_name = Builtins::name(builtin);
  Operator::Properties properties = node->op()->properties();
  auto call_descriptor = Linkage::GetCEntryStubCallDescriptor(
      zone, kReturnCount, argc, debug_name, properties, flags,
      StackArgumentOrder::kJS);

  NodeProperties::ChangeOp(node, jsgraph->common()->Call(call_descriptor));
}
}  // namespace

Reduction JSTypedLowering::ReduceJSConstructForwardVarargs(Node* node) {
  DCHECK_EQ(IrOpcode::kJSConstructForwardVarargs, node->opcode());
  ConstructForwardVarargsParameters p =
      ConstructForwardVarargsParametersOf(node->op());
  DCHECK_LE(2u, p.arity());
  int const arity = static_cast<int>(p.arity() - 2);
  int const start_index = static_cast<int>(p.start_index());
  Node* target = NodeProperties::GetValueInput(node, 0);
  Type target_type = NodeProperties::GetType(target);

  // Check if {target} is a JSFunction.
  if (target_type.IsHeapConstant() &&
      target_type.AsHeapConstant()->Ref().IsJSFunction()) {
    // Only optimize [[Construct]] here if {function} is a Constructor.
    JSFunctionRef function = target_type.AsHeapConstant()->Ref().AsJSFunction();
    if (!function.map(broker()).is_constructor()) return NoChange();
    // Patch {node} to an indirect call via ConstructFunctionForwardVarargs.
    Callable callable = CodeFactory::ConstructFunctionForwardVarargs(isolate());
    node->InsertInput(graph()->zone(), 0,
                      jsgraph()->HeapConstantNoHole(callable.code()));
    node->InsertInput(graph()->zone(), 3,
                      jsgraph()->ConstantNoHole(JSParameterCount(arity)));
    node->InsertInput(graph()->zone(), 4,
                      jsgraph()->ConstantNoHole(start_index));
    node->InsertInput(graph()->zone(), 5, jsgraph()->UndefinedConstant());
    NodeProperties::ChangeOp(
        node, common()->Call(Linkage::GetStubCallDescriptor(
                  graph()->zone(), callable.descriptor(), arity + 1,
                  CallDescriptor::kNeedsFrameState)));
    return Changed(node);
  }

  return NoChange();
}

Reduction JSTypedLowering::ReduceJSConstruct(Node* node) {
  JSConstructNode n(node);
  ConstructParameters const& p = n.Parameters();
  int const arity = p.arity_without_implicit_args();
  Node* target = n.target();
  Type target_type = NodeProperties::GetType(target);

  // Check if {target} is a known JSFunction.
  if (target_type.IsHeapConstant() &&
      target_type.AsHeapConstant()->Ref().IsJSFunction()) {
    JSFunctionRef function = target_type.AsHeapConstant()->Ref().AsJSFunction();

    // Only optimize [[Construct]] here if {function} is a Constructor.
    if (!function.map(broker()).is_constructor()) return NoChange();

    // Patch {node} to an indirect call via the {function}s construct stub.
    Callable callable = Builtins::CallableFor(
        isolate(), function.shared(broker()).construct_as_builtin()
                       ? Builtin::kJSBuiltinsConstructStub
                       : Builtin::kJSConstructStubGeneric);
    static_assert(JSConstructNode::TargetIndex() == 0);
    static_assert(JSConstructNode::NewTargetIndex() == 1);
    node->RemoveInput(n.FeedbackVectorIndex());
    node->InsertInput(graph()->zone(), 0,
                      jsgraph()->HeapConstantNoHole(callable.code()));
    node->InsertInput(graph()->zone(), 3,
                      jsgraph()->ConstantNoHole(JSParameterCount(arity)));
    node->InsertInput(graph()->zone(), 4, jsgraph()->UndefinedConstant());
    NodeProperties::ChangeOp(
        node, common()->Call(Linkage::GetStubCallDescriptor(
                  graph()->zone(), callable.descriptor(), 1 + arity,
                  CallDescriptor::kNeedsFrameState)));
    return Changed(node);
  }

  return NoChange();
}

Reduction JSTypedLowering::ReduceJSCallForwardVarargs(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCallForwardVarargs, node->opcode());
  CallForwardVarargsParameters p = CallForwardVarargsParametersOf(node->op());
  DCHECK_LE(2u, p.arity());
  int const arity = static_cast<int>(p.arity() - 2);
  int const start_index = static_cast<int>(p.start_index());
  Node* target = NodeProperties::GetValueInput(node, 0);
  Type target_type = NodeProperties::GetType(target);

  // Check if {target} is a directly callable JSFunction.
  if (target_type.Is(Type::CallableFunction())) {
    // Compute flags for the call.
    CallDescriptor::Flags flags = CallDescriptor::kNeedsFrameState;
    // Patch {node} to an indirect call via CallFunctionForwardVarargs.
    Callable callable = CodeFactory::CallFunctionForwardVarargs(isolate());
    node->InsertInput(graph()->zone(), 0,
                      jsgraph()->HeapConstantNoHole(callable.code()));
    node->InsertInput(graph()->zone(), 2,
                      jsgraph()->ConstantNoHole(JSParameterCount(arity)));
    node->InsertInput(graph()->zone(), 3,
                      jsgraph()->ConstantNoHole(start_index));
    NodeProperties::ChangeOp(
        node, common()->Call(Linkage::GetStubCallDescriptor(
                  graph()->zone(), callable.descriptor(), arity + 1, flags)));
    return Changed(node);
  }

  return NoChange();
}

Reduction JSTypedLowering::ReduceJSCall(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  int arity = p.arity_without_implicit_args();
  ConvertReceiverMode convert_mode = p.convert_mode();
  Node* target = n.target();
  Type target_type = NodeProperties::GetType(target);
  Node* receiver = n.receiver();
  Type receiver_type = NodeProperties::GetType(receiver);
  Effect effect = n.effect();
  Control control = n.control();

  // Try to infer receiver {convert_mode} from {receiver} type.
  if (receiver_type.Is(Type::NullOrUndefined())) {
    convert_mode = ConvertReceiverMode::kNullOrUndefined;
  } else if (!receiver_type.Maybe(Type::NullOrUndefined())) {
    convert_mode = ConvertReceiverMode::kNotNullOrUndefined;
  }

  // Check if we know the SharedFunctionInfo of {target}.
  OptionalJSFunctionRef function;
  OptionalSharedFunctionInfoRef shared;

  if (target_type.IsHeapConstant() &&
      target_type.AsHeapConstant()->Ref().IsJSFunction()) {
    function = target_type.AsHeapConstant()->Ref().AsJSFunction();
    shared = function->shared(broker());
  } else if (target->opcode() == IrOpcode::kJSCreateClosure) {
    CreateClosureParameters const& ccp =
        JSCreateClosureNode{target}.Parameters();
    shared = ccp.shared_info();
  } else if (target->opcode() == IrOpcode::kCheckClosure) {
    FeedbackCellRef cell = MakeRef(broker(), FeedbackCellOf(target->op()));
    shared = cell.shared_function_info(broker());
  }

  if (shared.has_value()) {
    // Do not inline the call if we need to check whether to break at entry.
    // If this state changes during background compilation, the compilation
    // job will be aborted from the main thread (see
    // Debug::PrepareFunctionForDebugExecution()).
    if (shared->HasBreakInfo(broker())) return NoChange();

    // Class constructors are callable, but [[Call]] will raise an exception.
    // See ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList ).
    // We need to check here in addition to JSCallReducer for Realms.
    // TODO(pthier): Consolidate all the class constructor checks.
    if (IsClassConstructor(shared->kind())) return NoChange();

    // Check if we need to convert the {receiver}, but bailout if it would
    // require data from a foreign native context.
    if (is_sloppy(shared->language_mode()) && !shared->native() &&
        !receiver_type.Is(Type::Receiver())) {
      if (!function.has_value() || !function->native_context(broker()).equals(
                                       broker()->target_native_context())) {
        return NoChange();
      }
      NativeContextRef native_context = function->native_context(broker());
      Node* global_proxy = jsgraph()->ConstantNoHole(
          native_context.global_proxy_object(broker()), broker());
      receiver = effect = graph()->NewNode(
          simplified()->ConvertReceiver(convert_mode), receiver,
          jsgraph()->ConstantNoHole(native_context, broker()), global_proxy,
          effect, control);
      NodeProperties::ReplaceValueInput(node, receiver, 1);
    }

    // Load the context from the {target}.
    Node* context = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSFunctionContext()), target,
        effect, control);
    NodeProperties::ReplaceContextInput(node, context);

    // Update the effect dependency for the {node}.
    NodeProperties::ReplaceEffectInput(node, effect);

    // Compute flags for the call.
    CallDescriptor::Flags flags = CallDescriptor::kNeedsFrameState;
    Node* new_target = jsgraph()->UndefinedConstant();

    int formal_count =
        shared->internal_formal_parameter_count_without_receiver();
    if (formal_count > arity) {
      node->RemoveInput(n.FeedbackVectorIndex());
      // Underapplication. Massage the arguments to match the expected number of
      // arguments.
      for (int i = arity; i < formal_count; i++) {
        node->InsertInput(graph()->zone(), arity + 2,
                          jsgraph()->UndefinedConstant());
      }

      // Patch {node} to a direct call.
      node->InsertInput(graph()->zone(), formal_count + 2, new_target);
      node->InsertInput(graph()->zone(), formal_count + 3,
                        jsgraph()->ConstantNoHole(JSParameterCount(arity)));
#ifdef V8_ENABLE_LEAPTIERING
      node->InsertInput(graph()->zone(), formal_count + 4,
                        jsgraph()->ConstantNoHole(kPlaceholderDispatchHandle));
#endif
      NodeProperties::ChangeOp(node,
                               common()->Call(Linkage::GetJSCallDescriptor(
                                   graph()->zone(), false, 1 + formal_count,
                                   flags | CallDescriptor::kCanUseRoots)));
    } else if (shared->HasBuiltinId() &&
               Builtins::IsCpp(shared->builtin_id())) {
      // Patch {node} to a direct CEntry call.
      ReduceBuiltin(jsgraph(), node, shared->builtin_id(), arity, flags);
    } else if (shared->HasBuiltinId()) {
      DCHECK(Builtins::HasJSLinkage(shared->builtin_id()));
      // Patch {node} to a direct code object call.
      Callable callable =
          Builtins::CallableFor(isolate(), shared->builtin_id());

      const CallInterfaceDescriptor& descriptor = callable.descriptor();
      auto call_descriptor = Linkage::GetStubCallDescriptor(
          graph()->zone(), descriptor, 1 + arity, flags);
      Node* stub_code = jsgraph()->HeapConstantNoHole(callable.code());
      node->RemoveInput(n.FeedbackVectorIndex());
      node->InsertInput(graph()->zone(), 0, stub_code);  // Code object.
      node->InsertInput(graph()->zone(), 2, new_target);
      node->InsertInput(graph()->zone(), 3,
                        jsgraph()->ConstantNoHole(JSParameterCount(arity)));
#ifdef V8_ENABLE_LEAPTIERING
      node->InsertInput(graph()->zone(), 4,
                        jsgraph()->ConstantNoHole(kPlaceholderDispatchHandle));
#endif
      NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
    } else {
      // Patch {node} to a direct call.
      node->RemoveInput(n.FeedbackVectorIndex());
      node->InsertInput(graph()->zone(), arity + 2, new_target);
      node->InsertInput(graph()->zone(), arity + 3,
                        jsgraph()->ConstantNoHole(JSParameterCount(arity)));
#ifdef V8_ENABLE_LEAPTIERING
      node->InsertInput(graph()->zone(), arity + 4,
                        jsgraph()->ConstantNoHole(kPlaceholderDispatchHandle));
#endif
      NodeProperties::ChangeOp(node,
                               common()->Call(Linkage::GetJSCallDescriptor(
                                   graph()->zone(), false, 1 + arity,
                                   flags | CallDescriptor::kCanUseRoots)));
    }
    return Changed(node);
  }

  // Check if {target} is a directly callable JSFunction.
  if (target_type.Is(Type::CallableFunction())) {
    // The node will change operators, remove the feedback vector.
    node->RemoveInput(n.FeedbackVectorIndex());
    // Compute flags for the call.
    CallDescriptor::Flags flags = CallDescriptor::kNeedsFrameState;
    // Patch {node} to an indirect call via the CallFunction builtin.
    Callable callable = CodeFactory::CallFunction(isolate(), convert_mode);
    node->InsertInput(graph()->zone(), 0,
                      jsgraph()->HeapConstantNoHole(callable.code()));
    node->InsertInput(graph()->zone(), 2,
                      jsgraph()->ConstantNoHole(JSParameterCount(arity)));
    NodeProperties::ChangeOp(
        node, common()->Call(Linkage::GetStubCallDescriptor(
                  graph()->zone(), callable.descriptor(), 1 + arity, flags)));
    return Changed(node);
  }

  // Maybe we did at least learn something about the {receiver}.
  if (p.convert_mode() != convert_mode) {
    NodeProperties::ChangeOp(
        node,
        javascript()->Call(p.arity(), p.frequency(), p.feedback(), convert_mode,
                           p.speculation_mode(), p.feedback_relation()));
    return Changed(node);
  }

  return NoChange();
}

Reduction JSTypedLowering::ReduceJSForInNext(Node* node) {
  JSForInNextNode n(node);
  Node* receiver = n.receiver();
  Node* cache_array = n.cache_array();
  Node* cache_type = n.cache_type();
  Node* index = n.index();
  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Effect effect = n.effect();
  Control control = n.control();

  // Load the map of the {receiver}.
  Node* receiver_map = effect =
      graph()->NewNode(simplified()->LoadField(AccessBuilder::ForMap()),
                       receiver, effect, control);

  switch (n.Parameters().mode()) {
    case ForInMode::kUseEnumCacheKeys:
    case ForInMode::kUseEnumCacheKeysAndIndices: {
      // Ensure that the expected map still matches that of the {receiver}.
      Node* check = graph()->NewNode(simplified()->ReferenceEqual(),
                                     receiver_map, cache_type);
      effect =
          graph()->NewNode(simplified()->CheckIf(DeoptimizeReason::kWrongMap),
                           check, effect, control);

      // Since the change to LoadElement() below is effectful, we connect
      // node to all effect uses.
      ReplaceWithValue(node, node, node, control);

      // Morph the {node} into a LoadElement.
      node->ReplaceInput(0, cache_array);
      node->ReplaceInput(1, index);
      node->ReplaceInput(2, effect);
      node->ReplaceInput(3, control);
      node->TrimInputCount(4);
      ElementAccess access =
          AccessBuilder::ForJSForInCacheArrayElement(n.Parameters().mode());
      NodeProperties::ChangeOp(node, simplified()->LoadElement(access));
      NodeProperties::SetType(node, access.type);
      break;
    }
    case ForInMode::kGeneric: {
      // Load the next {key} from the {cache_array}.
      Node* key = effect = graph()->NewNode(
          simplified()->LoadElement(AccessBuilder::ForJSForInCacheArrayElement(
              n.Parameters().mode())),
          cache_array, index, effect, control);

      // Check if the expected map still matches that of the {receiver}.
      Node* check = graph()->NewNode(simplified()->ReferenceEqual(),
                                     receiver_map, cache_type);
      Node* branch =
          graph()->NewNode(common()->Branch(BranchHint::kTrue), check, control);

      Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
      Node* etrue;
      Node* vtrue;
      {
        // Don't need filtering since expected map still matches that of the
        // {receiver}.
        etrue = effect;
        vtrue = key;
      }

      Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
      Node* efalse;
      Node* vfalse;
      {
        // Filter the {key} to check if it's still a valid property of the
        // {receiver} (does the ToName conversion implicitly).
        Callable const callable =
            Builtins::CallableFor(isolate(), Builtin::kForInFilter);
        auto call_descriptor = Linkage::GetStubCallDescriptor(
            graph()->zone(), callable.descriptor(),
            callable.descriptor().GetStackParameterCount(),
            CallDescriptor::kNeedsFrameState);
        vfalse = efalse = if_false = graph()->NewNode(
            common()->Call(call_descriptor),
            jsgraph()->HeapConstantNoHole(callable.code()), key, receiver,
            context, frame_state, effect, if_false);
        NodeProperties::SetType(
            vfalse,
            Type::Union(Type::String(), Type::Undefined(), graph()->zone()));

        // Update potential {IfException} uses of {node} to point to the above
        // ForInFilter stub call node instead.
        Node* if_exception = nullptr;
        if (NodeProperties::IsExceptionalCall(node, &if_exception)) {
          if_false = graph()->NewNode(common()->IfSuccess(), vfalse);
          NodeProperties::ReplaceControlInput(if_exception, vfalse);
          NodeProperties::ReplaceEffectInput(if_exception, efalse);
          Revisit(if_exception);
        }
      }

      control = graph()->NewNode(common()->Merge(2), if_true, if_false);
      effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
      ReplaceWithValue(node, node, effect, control);

      // Morph the {node} into a Phi.
      node->ReplaceInput(0, vtrue);
      node->ReplaceInput(1, vfalse);
      node->ReplaceInput(2, control);
      node->TrimInputCount(3);
      NodeProperties::ChangeOp(
          node, common()->Phi(MachineRepresentation::kTagged, 2));
    }
  }

  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSForInPrepare(Node* node) {
  JSForInPrepareNode n(node);
  Node* enumerator = n.enumerator();
  Effect effect = n.effect();
  Control control = n.control();
  Node* cache_type = enumerator;
  Node* cache_array = nullptr;
  Node* cache_length = nullptr;

  switch (n.Parameters().mode()) {
    case ForInMode::kUseEnumCacheKeys:
    case ForInMode::kUseEnumCacheKeysAndIndices: {
      // Check that the {enumerator} is a Map.
      // The direct IsMap check requires reading of an instance type, so we
      // compare its map against fixed_array_map instead (by definition,
      // the {enumerator} is either the receiver's Map or a FixedArray).
      Node* check_for_fixed_array = effect =
          graph()->NewNode(simplified()->CompareMaps(
                               ZoneRefSet<Map>(broker()->fixed_array_map())),
                           enumerator, effect, control);
      Node* check_for_not_fixed_array =
          graph()->NewNode(simplified()->BooleanNot(), check_for_fixed_array);
      effect =
          graph()->NewNode(simplified()->CheckIf(DeoptimizeReason::kWrongMap),
                           check_for_not_fixed_array, effect, control);

      // Load the enum cache from the {enumerator} map.
      Node* descriptor_array = effect = graph()->NewNode(
          simplified()->LoadField(AccessBuilder::ForMapDescriptors()),
          enumerator, effect, control);
      Node* enum_cache = effect = graph()->NewNode(
          simplified()->LoadField(AccessBuilder::ForDescriptorArrayEnumCache()),
          descriptor_array, effect, control);
      cache_array = effect = graph()->NewNode(
          simplified()->LoadField(AccessBuilder::ForEnumCacheKeys()),
          enum_cache, effect, control);

      // Load the enum length of the {enumerator} map.
      Node* bit_field3 = effect = graph()->NewNode(
          simplified()->LoadField(AccessBuilder::ForMapBitField3()), enumerator,
          effect, control);
      static_assert(Map::Bits3::EnumLengthBits::kShift == 0);
      cache_length = graph()->NewNode(
          simplified()->NumberBitwiseAnd(), bit_field3,
          jsgraph()->ConstantNoHole(Map::Bits3::EnumLengthBits::kMask));
      break;
    }
    case ForInMode::kGeneric: {
      // Check if the {enumerator} is a Map or a FixedArray.
      // The direct IsMap check requires reading of an instance type, so we
      // compare against fixed array map instead (by definition,
      // the {enumerator} is either the receiver's Map or a FixedArray).
      Node* check = effect =
          graph()->NewNode(simplified()->CompareMaps(
                               ZoneRefSet<Map>(broker()->fixed_array_map())),
                           enumerator, effect, control);
      Node* branch = graph()->NewNode(common()->Branch(BranchHint::kFalse),
                                      check, control);

      Node* if_map = graph()->NewNode(common()->IfFalse(), branch);
      Node* etrue = effect;
      Node* cache_array_true;
      Node* cache_length_true;
      {
        // Load the enum cache from the {enumerator} map.
        Node* descriptor_array = etrue = graph()->NewNode(
            simplified()->LoadField(AccessBuilder::ForMapDescriptors()),
            enumerator, etrue, if_map);
        Node* enum_cache = etrue =
            graph()->NewNode(simplified()->LoadField(
                                 AccessBuilder::ForDescriptorArrayEnumCache()),
                             descriptor_array, etrue, if_map);
        cache_array_true = etrue = graph()->NewNode(
            simplified()->LoadField(AccessBuilder::ForEnumCacheKeys()),
            enum_cache, etrue, if_map);

        // Load the enum length of the {enumerator} map.
        Node* bit_field3 = etrue = graph()->NewNode(
            simplified()->LoadField(AccessBuilder::ForMapBitField3()),
            enumerator, etrue, if_map);
        static_assert(Map::Bits3::EnumLengthBits::kShift == 0);
        cache_length_true = graph()->NewNode(
            simplified()->NumberBitwiseAnd(), bit_field3,
            jsgraph()->ConstantNoHole(Map::Bits3::EnumLengthBits::kMask));
      }

      Node* if_fixed_array = graph()->NewNode(common()->IfTrue(), branch);
      Node* efalse = effect;
      Node* cache_array_false;
      Node* cache_length_false;
      {
        // The {enumerator} is the FixedArray with the keys to iterate.
        cache_array_false = enumerator;
        cache_length_false = efalse = graph()->NewNode(
            simplified()->LoadField(AccessBuilder::ForFixedArrayLength()),
            cache_array_false, efalse, if_fixed_array);
      }

      // Rewrite the uses of the {node}.
      control = graph()->NewNode(common()->Merge(2), if_map, if_fixed_array);
      effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
      cache_array =
          graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                           cache_array_true, cache_array_false, control);
      cache_length =
          graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                           cache_length_true, cache_length_false, control);
      break;
    }
  }

  // Update the uses of {node}.
  for (Edge edge : node->use_edges()) {
    Node* const user = edge.from();
    if (NodeProperties::IsEffectEdge(edge)) {
      edge.UpdateTo(effect);
      Revisit(user);
    } else if (NodeProperties::IsControlEdge(edge)) {
      edge.UpdateTo(control);
      Revisit(user);
    } else {
      DCHECK(NodeProperties::IsValueEdge(edge));
      switch (ProjectionIndexOf(user->op())) {
        case 0:
          Replace(user, cache_type);
          break;
        case 1:
          Replace(user, cache_array);
          break;
        case 2:
          Replace(user, cache_length);
          break;
        default:
          UNREACHABLE();
      }
    }
  }
  node->Kill();
  return Replace(effect);
}

Reduction JSTypedLowering::ReduceJSLoadMessage(Node* node) {
  DCHECK_EQ(IrOpcode::kJSLoadMessage, node->opcode());
  ExternalReference const ref =
      ExternalReference::address_of_pending_message(isolate());
  node->ReplaceInput(0, jsgraph()->ExternalConstant(ref));
  NodeProperties::ChangeOp(node, simplified()->LoadMessage());
  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSStoreMessage(Node* node) {
  DCHECK_EQ(IrOpcode::kJSStoreMessage, node->opcode());
  ExternalReference const ref =
      ExternalReference::address_of_pending_message(isolate());
  Node* value = NodeProperties::GetValueInput(node, 0);
  node->ReplaceInput(0, jsgraph()->ExternalConstant(ref));
  node->ReplaceInput(1, value);
  NodeProperties::ChangeOp(node, simplified()->StoreMessage());
  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSGeneratorStore(Node* node) {
  DCHECK_EQ(IrOpcode::kJSGeneratorStore, node->opcode());
  Node* generator = NodeProperties::GetValueInput(node, 0);
  Node* continuation = NodeProperties::GetValueInput(node, 1);
  Node* offset = NodeProperties::GetValueInput(node, 2);
  Node* context = NodeProperties::GetContextInput(node);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  int value_count = GeneratorStoreValueCountOf(node->op());

  FieldAccess array_field =
      AccessBuilder::ForJSGeneratorObjectParametersAndRegisters();
  FieldAccess context_field = AccessBuilder::ForJSGeneratorObjectContext();
  FieldAccess continuation_field =
      AccessBuilder::ForJSGeneratorObjectContinuation();
  FieldAccess input_or_debug_pos_field =
      AccessBuilder::ForJSGeneratorObjectInputOrDebugPos();

  Node* array = effect = graph()->NewNode(simplified()->LoadField(array_field),
                                          generator, effect, control);

  for (int i = 0; i < value_count; ++i) {
    Node* value = NodeProperties::GetValueInput(node, 3 + i);
    if (value != jsgraph()->OptimizedOutConstant()) {
      effect = graph()->NewNode(
          simplified()->StoreField(AccessBuilder::ForFixedArraySlot(i)), array,
          value, effect, control);
    }
  }

  effect = graph()->NewNode(simplified()->StoreField(context_field), generator,
                            context, effect, control);
  effect = graph()->NewNode(simplified()->StoreField(continuation_field),
                            generator, continuation, effect, control);
  effect = graph()->NewNode(simplified()->StoreField(input_or_debug_pos_field),
                            generator, offset, effect, control);

  ReplaceWithValue(node, effect, effect, control);
  return Changed(effect);
}

Reduction JSTypedLowering::ReduceJSGeneratorRestoreContinuation(Node* node) {
  DCHECK_EQ(IrOpcode::kJSGeneratorRestoreContinuation, node->opcode());
  Node* generator = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  FieldAccess continuation_field =
      AccessBuilder::ForJSGeneratorObjectContinuation();

  Node* continuation = effect = graph()->NewNode(
      simplified()->LoadField(continuation_field), generator, effect, control);
  Node* executing =
      jsgraph()->ConstantNoHole(JSGeneratorObject::kGeneratorExecuting);
  effect = graph()->NewNode(simplified()->StoreField(continuation_field),
                            generator, executing, effect, control);

  ReplaceWithValue(node, continuation, effect, control);
  return Changed(continuation);
}

Reduction JSTypedLowering::ReduceJSGeneratorRestoreContext(Node* node) {
  DCHECK_EQ(IrOpcode::kJSGeneratorRestoreContext, node->opcode());

  const Operator* new_op =
      simplified()->LoadField(AccessBuilder::ForJSGeneratorObjectContext());

  // Mutate the node in-place.
  DCHECK(OperatorProperties::HasContextInput(node->op()));
  DCHECK(!OperatorProperties::HasContextInput(new_op));
  node->RemoveInput(NodeProperties::FirstContextIndex(node));

  NodeProperties::ChangeOp(node, new_op);
  return Changed(node);
}

Reduction JSTypedLowering::ReduceJSGeneratorRestoreRegister(Node* node) {
  DCHECK_EQ(IrOpcode::kJSGeneratorRestoreRegister, node->opcode());
  Node* generator = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  int index = RestoreRegisterIndexOf(node->op());

  FieldAccess array_field =
      AccessBuilder::ForJSGeneratorObjectParametersAndRegisters();
  FieldAccess element_field = AccessBuilder::ForFixedArraySlot(index);

  Node* array = effect = graph()->NewNode(simplified()->LoadField(array_field),
                                          generator, effect, control);
  Node* element = effect = graph()->NewNode(
      simplified()->LoadField(element_field), array, effect, control);
  Node* stale = jsgraph()->StaleRegisterConstant();
  effect = graph()->NewNode(simplified()->StoreField(element_field), array,
                            stale, effect, control);

  ReplaceWithValue(node, element, effect, control);
  return Changed(element);
}

Reduction JSTypedLowering::ReduceJSGeneratorRestoreInputOrDebugPos(Node* node) {
  DCHECK_EQ(IrOpcode::kJSGeneratorRestoreInputOrDebugPos, node->opcode());

  FieldAccess input_or_debug_pos_field =
      AccessBuilder::ForJSGeneratorObjectInputOrDebugPos();
  const Operator* new_op = simplified()->LoadField(input_or_debug_pos_field);

  // Mutate the node in-place.
  DCHECK(OperatorProperties::HasContextInput(node->op()));
  DCHECK(!OperatorProperties::HasContextInput(new_op));
  node->RemoveInput(NodeProperties::FirstContextIndex(node));

  NodeProperties::ChangeOp(node, new_op);
  return Changed(node);
}

Reduction JSTypedLowering::ReduceObjectIsArray(Node* node) {
  Node* value = NodeProperties::GetValueInput(node, 0);
  Type value_type = NodeProperties::GetType(value);
  Node* context = NodeProperties::GetContextInput(node);
  Node* frame_state = NodeProperties::GetFrameStateInput(node);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // Constant-fold based on {value} type.
  if (value_type.Is(Type::Array())) {
    value = jsgraph()->TrueConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  } else if (!value_type.Maybe(Type::ArrayOrProxy())) {
    value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }

  int count = 0;
  Node* values[5];
  Node* effects[5];
  Node* controls[4];

  // Check if the {value} is a Smi.
  Node* check = graph()->NewNode(simplified()->ObjectIsSmi(), value);
  control =
      graph()->NewNode(common()->Branch(BranchHint::kFalse), check, control);

  // The {value} is a Smi.
  controls[count] = graph()->NewNode(common()->IfTrue(), control);
  effects[count] = effect;
  values[count] = jsgraph()->FalseConstant();
  count++;

  control = graph()->NewNode(common()->IfFalse(), control);

  // Load the {value}s instance type.
  Node* value_map = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMap()), value, effect, control);
  Node* value_instance_type = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMapInstanceType()), value_map,
      effect, control);

  // Check if the {value} is a JSArray.
  check = graph()->NewNode(simplified()->NumberEqual(), value_instance_type,
                           jsgraph()->ConstantNoHole(JS_ARRAY_TYPE));
  control = graph()->NewNode(common()->Branch(), check, control);

  // The {value} is a JSArray.
  controls[count] = graph()->NewNode(common()->IfTrue(), control);
  effects[count] = effect;
  values[count] = jsgraph()->TrueConstant();
  count++;

  control = graph()->NewNode(common()->IfFalse(), control);

  // Check if the {value} is a JSProxy.
  check = graph()->NewNode(simplified()->NumberEqual(), value_instance_type,
                           jsgraph()->ConstantNoHole(JS_PROXY_TYPE));
  control =
      graph()->NewNode(common()->Branch(BranchHint::kFalse), check, control);

  // The {value} is neither a JSArray nor a JSProxy.
  controls[count] = graph()->NewNode(common()->IfFalse(), control);
  effects[count] = effect;
  values[count] = jsgraph()->FalseConstant();
  count++;

  control = graph()->NewNode(common()->IfTrue(), control);

  // Let the %ArrayIsArray runtime function deal with the JSProxy {value}.
  value = effect = control =
      graph()->NewNode(javascript()->CallRuntime(Runtime::kArrayIsArray), value,
                       context, frame_state, effect, control);
  NodeProperties::SetType(value, Type::Boolean());

  // Update potential {IfException} uses of {node} to point to the above
  // %ArrayIsArray runtime call node instead.
  Node* on_exception = nullptr;
  if (NodeProperties::IsExceptionalCall(node, &on_exception)) {
    NodeProperties::ReplaceControlInput(on_exception, control);
    NodeProperties::ReplaceEffectInput(on_exception, effect);
    control = graph()->NewNode(common()->IfSuccess(), control);
    Revisit(on_exception);
  }

  // The {value} is neither a JSArray nor a JSProxy.
  controls[count] = control;
  effects[count] = effect;
  values[count] = value;
  count++;

  control = graph()->NewNode(common()->Merge(count), count, controls);
  effects[count] = control;
  values[count] = control;
  effect = graph()->NewNode(common()->EffectPhi(count), count + 1, effects);
  value = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, count),
                           count + 1, values);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSTypedLowering::ReduceJSParseInt(Node* node) {
  Node* value = NodeProperties::GetValueInput(node, 0);
  Type value_type = NodeProperties::GetType(value);
  Node* radix = NodeProperties::GetValueInput(node, 1);
  Type radix_type = NodeProperties::GetType(radix);
  // We need kTenOrUndefined and kZeroOrUndefined because
  // the type representing {0,10} would become the range 1-10.
  if (value_type.Is(type_cache_->kSafeInteger) &&
      (radix_type.Is(type_cache_->kTenOrUndefined) ||
       radix_type.Is(type_cache_->kZeroOrUndefined))) {
    // Number.parseInt(a:safe-integer) -> a
    // Number.parseInt(a:safe-integer,b:#0\/undefined) -> a
    // Number.parseInt(a:safe-integer,b:#10\/undefined) -> a
    ReplaceWithValue(node, value);
    return Replace(value);
  }
  return NoChange();
}

Reduction JSTypedLowering::ReduceJSResolvePromise(Node* node) {
  DCHECK_EQ(IrOpcode::kJSResolvePromise, node->opcode());
  Node* resolution = NodeProperties::GetValueInput(node, 1);
  Type resolution_type = NodeProperties::GetType(resolution);
  // We can strength-reduce JSResolvePromise to JSFulfillPromise
  // if the {resolution} is known to be a primitive, as in that
  // case we don't perform the implicit chaining (via "then").
  if (resolution_type.Is(Type::Primitive())) {
    // JSResolvePromise(p,v:primitive) -> JSFulfillPromise(p,v)
    node->RemoveInput(3);  // frame state
    NodeProperties::ChangeOp(node, javascript()->FulfillPromise());
    return Changed(node);
  }
  return NoChange();
}

Reduction JSTypedLowering::Reduce(Node* node) {
  switch (node->opcode()) {
    case IrOpcode::kJSEqual:
      return ReduceJSEqual(node);
    case IrOpcode::kJSStrictEqual:
      return ReduceJSStrictEqual(node);
    case IrOpcode::kJSLessThan:         // fall through
    case IrOpcode::kJSGreaterThan:      // fall through
    case IrOpcode::kJSLessThanOrEqual:  // fall through
    case IrOpcode::kJSGreaterThanOrEqual:
      return ReduceJSComparison(node);
    case IrOpcode::kJSBitwiseOr:
    case IrOpcode::kJSBitwiseXor:
    case IrOpcode::kJSBitwiseAnd:
      return ReduceInt32Binop(node);
    case IrOpcode::kJSShiftLeft:
    case IrOpcode::kJSShiftRight:
      return ReduceUI32Shift(node, kSigned);
    case IrOpcode::kJSShiftRightLogical:
      return ReduceUI32Shift(node, kUnsigned);
    case IrOpcode::kJSAdd:
      return ReduceJSAdd(node);
    case IrOpcode::kJSSubtract:
    case IrOpcode::kJSMultiply:
    case IrOpcode::kJSDivide:
    case IrOpcode::kJSModulus:
    case IrOpcode::kJSExponentiate:
      return ReduceNumberBinop(node);
    case IrOpcode::kJSBitwiseNot:
      return ReduceJSBitwiseNot(node);
    case IrOpcode::kJSDecrement:
      return ReduceJSDecrement(node);
    case IrOpcode::kJSIncrement:
      return ReduceJSIncrement(node);
    case IrOpcode::kJSNegate:
      return ReduceJSNegate(node);
    case IrOpcode::kJSHasInPrototypeChain:
      return ReduceJSHasInPrototypeChain(node);
    case IrOpcode::kJSOrdinaryHasInstance:
      return ReduceJSOrdinaryHasInstance(node);
    case IrOpcode::kJSToLength:
      return ReduceJSToLength(node);
    case IrOpcode::kJSToName:
      return ReduceJSToName(node);
    case IrOpcode::kJSToNumber:
    case IrOpcode::kJSToNumberConvertBigInt:
      return ReduceJSToNumber(node);
    case IrOpcode::kJSToBigInt:
      return ReduceJSToBigInt(node);
    case IrOpcode::kJSToBigIntConvertNumber:
      return ReduceJSToBigIntConvertNumber(node);
    case IrOpcode::kJSToNumeric:
      return ReduceJSToNumeric(node);
    case IrOpcode::kJSToString:
      return ReduceJSToString(node);
    case IrOpcode::kJSToObject:
      return ReduceJSToObject(node);
    case IrOpcode::kJSLoadNamed:
      return ReduceJSLoadNamed(node);
    case IrOpcode::kJSLoadContext:
      return ReduceJSLoadContext(node);
    case IrOpcode::kJSLoadScriptContext:
      return ReduceJSLoadScriptContext(node);
    case IrOpcode::kJSStoreContext:
      return ReduceJSStoreContext(node);
    case IrOpcode::kJSStoreScriptContext:
      return ReduceJSStoreScriptContext(node);
    case IrOpcode::kJSLoadModule:
      return ReduceJSLoadModule(node);
    case IrOpcode::kJSStoreModule:
      return ReduceJSStoreModule(node);
    case IrOpcode::kJSConstructForwardVarargs:
      return ReduceJSConstructForwardVarargs(node);
    case IrOpcode::kJSConstruct:
      return ReduceJSConstruct(node);
    case IrOpcode::kJSCallForwardVarargs:
      return ReduceJSCallForwardVarargs(node);
    case IrOpcode::kJSCall:
      return ReduceJSCall(node);
    case IrOpcode::kJSForInPrepare:
      return ReduceJSForInPrepare(node);
    case IrOpcode::kJSForInNext:
      return ReduceJSForInNext(node);
    case IrOpcode::kJSHasContextExtension:
      return ReduceJSHasContextExtension(node);
    case IrOpcode::kJSLoadMessage:
      return ReduceJSLoadMessage(node);
    case IrOpcode::kJSStoreMessage:
      return ReduceJSStoreMessage(node);
    case IrOpcode::kJSGeneratorStore:
      return ReduceJSGeneratorStore(node);
    case IrOpcode::kJSGeneratorRestoreContinuation:
      return ReduceJSGeneratorRestoreContinuation(node);
    case IrOpcode::kJSGeneratorRestoreContext:
      return ReduceJSGeneratorRestoreContext(node);
    case IrOpcode::kJSGeneratorRestoreRegister:
      return ReduceJSGeneratorRestoreRegister(node);
    case IrOpcode::kJSGeneratorRestoreInputOrDebugPos:
      return ReduceJSGeneratorRestoreInputOrDebugPos(node);
    case IrOpcode::kJSObjectIsArray:
      return ReduceObjectIsArray(node);
    case IrOpcode::kJSParseInt:
      return ReduceJSParseInt(node);
    case IrOpcode::kJSResolvePromise:
      return ReduceJSResolvePromise(node);
    default:
      break;
  }
  return NoChange();
}

Factory* JSTypedLowering::factory() const { return jsgraph()->factory(); }

Graph* JSTypedLowering::graph() const { return jsgraph()->graph(); }

CompilationDependencies* JSTypedLowering::dependencies() const {
  return broker()->dependencies();
}

Isolate* JSTypedLowering::isolate() const { return jsgraph()->isolate(); }

JSOperatorBuilder* JSTypedLowering::javascript() const {
  return jsgraph()->javascript();
}

CommonOperatorBuilder* JSTypedLowering::common() const {
  return jsgraph()->common();
}

SimplifiedOperatorBuilder* JSTypedLowering::simplified() const {
  return jsgraph()->simplified();
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```