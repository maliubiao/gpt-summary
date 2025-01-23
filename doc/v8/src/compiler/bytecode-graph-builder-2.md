Response: Let's break down the thought process for summarizing the C++ code.

1. **Understand the Goal:** The request asks for a functional summary of a specific C++ file (`bytecode-graph-builder.cc`) within the V8 JavaScript engine. It emphasizes the relationship to JavaScript and requires a JavaScript example. The "part 3 of 3" suggests we should assume context from previous parts but focus on the provided snippet.

2. **Initial Scan and Keyword Identification:** Quickly read through the code, looking for recurring patterns, class names, and function names. Keywords that jump out are:

    * `BytecodeGraphBuilder` (the central class)
    * `Visit...` (many functions starting with `Visit`)
    * `Build...` (many functions starting with `Build`)
    * `environment()` (suggests state management)
    * `jsgraph()` (interaction with the V8 graph representation)
    * `simplified()` and `javascript()` (accessing different operation sets)
    * `FeedbackSource`, `FeedbackSlot` (related to performance optimization)
    * `NewNode()` (node creation in the graph)
    * `Jump...`, `Switch...` (control flow)
    * `ToBoolean`, `ToNumber`, etc. (type conversions)
    * `SuspendGenerator`, `ResumeGenerator` (generator function handling)
    * `TryBuildSimplified...` (optimization attempts)

3. **Identify Core Functionality:** The names `BytecodeGraphBuilder` and the `Visit...` pattern strongly suggest this class *processes bytecode instructions*. The `Build...` pattern likely involves *constructing something* based on those instructions. The presence of `jsgraph()` points to building a graph representation of the code.

4. **Infer the Purpose of `Visit...` Functions:**  The numerous `Visit` functions, each corresponding to a specific bytecode like `VisitAdd`, `VisitLoadGlobal`, etc. (based on common bytecode operation names), strongly indicate that these functions handle the logic for *translating each bytecode instruction into a graph representation*.

5. **Infer the Purpose of `Build...` Functions:**  The `Build` functions often seem to be helper functions called by the `Visit` functions. They encapsulate common logic for building specific graph structures, like `BuildBinaryOp` for binary operations or `BuildCall` for function calls.

6. **Recognize the Role of `environment()`:**  The `environment()` calls likely manage the *state* during the graph construction process. This includes things like:

    * Keeping track of the current accumulator value.
    * Mapping registers to their corresponding graph nodes.
    * Managing control flow and effect dependencies.

7. **Understand `jsgraph()`, `simplified()`, and `javascript()`:** These appear to be interfaces for creating different kinds of nodes in the graph. `simplified()` probably refers to the *simplified* intermediate representation (IR) used by V8 for optimizations. `javascript()` likely represents *higher-level* JavaScript operations that might later be lowered to the simplified IR.

8. **Grasp the Significance of Feedback:** The `FeedbackSource` and `FeedbackSlot` elements are clearly related to *performance optimization*. They suggest that the graph builder incorporates information gathered during runtime (feedback) to generate more efficient code.

9. **Connect to JavaScript:** Now, think about how these C++ constructs relate to JavaScript features:

    * **Bytecode:** JavaScript code is compiled into bytecode. This builder processes that bytecode.
    * **Graph Representation:**  This is the internal representation V8 uses for optimizing and executing JavaScript.
    * **`VisitAdd`, `VisitSubtract`, etc.:** These directly correspond to JavaScript operators (`+`, `-`, etc.).
    * **`VisitLoadGlobal`, `VisitLoadProperty`:** These relate to accessing variables and object properties in JavaScript.
    * **`VisitCall`, `VisitConstruct`:** These correspond to function calls and the `new` operator in JavaScript.
    * **Type Conversions:**  JavaScript's dynamic typing requires implicit type conversions (e.g., `+` with a number and a string). The `ToBoolean`, `ToNumber`, etc., functions handle these.
    * **Control Flow:** `if`, `else`, `for`, `while` in JavaScript are implemented using jumps and conditional branches in bytecode, which are handled by the `Jump...` and `Switch...` functions.
    * **Generator Functions:** The `async`/`await` and generator function features in JavaScript have specific bytecode instructions (`SuspendGenerator`, `ResumeGenerator`) that this builder handles.

10. **Formulate the Summary:**  Combine the observations into a concise summary, highlighting the core function and its relation to JavaScript. Use clear and accessible language.

11. **Create the JavaScript Example:** Choose a simple JavaScript snippet that demonstrates the concepts being handled by the `bytecode-graph-builder`. Focus on operations that have corresponding `Visit` functions (like addition, variable access).

12. **Review and Refine:** Read through the summary and example to ensure they are accurate, clear, and address all parts of the request. Ensure the connection between the C++ code and the JavaScript example is evident. For instance, explicitly state which JavaScript operation corresponds to which `Visit` function.

By following these steps, we can systematically analyze the C++ code and arrive at a comprehensive and informative summary that connects it to the relevant JavaScript concepts. The key is to understand the naming conventions, the overall architecture of a compiler, and how different internal components relate to the user-facing language features.
好的，让我们来归纳一下这段C++代码的功能。

这是 `v8/src/compiler/bytecode-graph-builder.cc` 文件的第三部分，延续了前两部分的功能，其核心职责是将 **字节码 (bytecode)** 转换为 **图 (graph)** 的中间表示，用于后续的优化和代码生成。这个图是由 V8 的涡轮增压编译器 (TurboFan) 使用的。

**本部分代码的主要功能集中在处理各种 JavaScript 的操作和控制流，将它们转化为图节点。**  具体来说，它实现了 `BytecodeGraphBuilder` 类的各种 `Visit...` 方法，这些方法对应着不同的字节码指令。

**核心功能点：**

1. **处理二元运算和位运算：**
   - 实现了 `VisitAdd`, `VisitSub`, `VisitMul`, `VisitDiv`, `VisitMod`, `VisitExp`, `VisitBitwiseOr`, `VisitBitwiseXor`, `VisitBitwiseAnd`, `VisitShiftLeft`, `VisitShiftRight`, `VisitShiftRightLogical` 等方法，处理 JavaScript 中的加减乘除、取模、指数、位运算等操作。
   - 区分了普通二元运算和与立即数 (Smi) 进行的二元运算 (`VisitAddSmi` 等)。
   - 利用 `FeedbackSource` 和 `FeedbackSlot` 来收集类型信息，以便进行优化。

2. **处理逻辑运算：**
   - 实现了 `VisitLogicalNot` 和 `VisitToBooleanLogicalNot`，处理逻辑非运算。

3. **处理 `typeof` 运算符：**
   - 实现了 `VisitTypeOf`，将 `typeof` 操作转换为图节点。

4. **处理 `delete` 运算符：**
   - 实现了 `VisitDeletePropertyStrict` 和 `VisitDeletePropertySloppy`，处理严格模式和非严格模式下的 `delete` 操作。

5. **处理 `super` 关键字：**
   - 实现了 `VisitGetSuperConstructor` 和 `VisitFindNonDefaultConstructorOrConstruct`，用于处理 `super` 关键字相关的操作。

6. **处理比较运算：**
   - 实现了 `VisitTestEqual`, `VisitTestEqualStrict`, `VisitTestLessThan`, `VisitTestGreaterThan`, `VisitTestLessThanOrEqual`, `VisitTestGreaterThanOrEqual`, `VisitTestReferenceEqual`, `VisitTestIn`, `VisitTestInstanceOf`, `VisitTestUndetectable`, `VisitTestNull`, `VisitTestUndefined`, `VisitTestTypeOf` 等方法，处理各种比较运算。

7. **处理类型转换：**
   - 实现了 `VisitToName`, `VisitToObject`, `VisitToString`, `VisitToBoolean`, `VisitToNumber`, `VisitToNumeric` 等方法，处理 JavaScript 中的类型转换操作。

8. **处理控制流：**
   - 实现了各种 `VisitJump...` 方法，例如 `VisitJump`, `VisitJumpIfTrue`, `VisitJumpIfFalse`, `VisitJumpIfToBooleanTrue`, `VisitJumpIfToBooleanFalse`, `VisitJumpIfJSReceiver`, `VisitJumpIfForInDone`, `VisitJumpIfNull`, `VisitJumpIfUndefined` 等，将字节码的跳转指令转换为图的控制流结构。
   - 实现了 `VisitSwitchOnSmiNoFeedback`，处理基于Smi的 `switch` 语句。
   - 实现了 `VisitJumpLoop`，处理循环跳转。

9. **处理函数返回和调试：**
   - 实现了 `VisitReturn`，处理函数返回。
   - 实现了 `VisitDebugger`，处理 `debugger` 语句。

10. **处理代码覆盖率：**
    - 实现了 `VisitIncBlockCounter`，用于增加代码块的执行计数器，用于代码覆盖率分析。

11. **处理 `for...in` 循环：**
    - 实现了 `VisitForInEnumerate`, `VisitForInPrepare`, `VisitForInNext`, `VisitForInStep`，处理 `for...in` 循环的各个阶段。

12. **处理迭代器：**
    - 实现了 `VisitGetIterator`，获取对象的迭代器。

13. **处理生成器函数 (Generator Functions)：**
    - 实现了 `VisitSuspendGenerator` 和 `VisitResumeGenerator`，处理生成器函数的挂起和恢复状态。
    - 实现了 `VisitSwitchOnGeneratorState`，根据生成器状态进行跳转。

14. **辅助方法和数据结构：**
    - 提供了 `BuildBinaryOp`, `BuildBinaryOpWithImmediate`, `BuildCompareOp`, `BuildDelete`, `BuildCastOperator` 等辅助方法，用于简化图节点的创建过程。
    - 使用了 `Environment` 类来管理当前代码块的上下文信息，包括累加器、寄存器等。
    - 使用了 `JSTypeHintLowering` 类来尝试进行基于类型反馈的优化。
    - 维护了 `merge_environments_` 和 `exception_handlers_` 等数据结构来处理控制流合并和异常处理。

**与 JavaScript 功能的关系以及 JavaScript 示例：**

这段 C++ 代码直接对应着 JavaScript 的各种语法结构和操作。每当 V8 执行 JavaScript 代码时，会先将其编译成字节码，然后 `BytecodeGraphBuilder` 就负责将这些字节码翻译成更底层的图表示，以便进行进一步的优化和生成机器码。

**JavaScript 示例：**

```javascript
function example(a, b) {
  let sum = a + b; // 对应 VisitAdd 字节码
  if (sum > 10) { // 对应 VisitTestGreaterThan 和 VisitJumpIfFalse 字节码
    return true;  // 对应 VisitReturn 字节码
  } else {
    console.log("Sum is not greater than 10");
    return false; // 对应 VisitReturn 字节码
  }
}

let result = example(5, 7);
```

在这个简单的 JavaScript 例子中：

- `a + b` 这个加法运算会对应到 `BytecodeGraphBuilder::VisitAdd` 方法。
- `sum > 10` 这个比较运算会对应到 `BytecodeGraphBuilder::VisitTestGreaterThan` 方法。
- `if (sum > 10)` 这个条件判断会涉及到 `BytecodeGraphBuilder::VisitJumpIfFalse` 方法，根据比较结果进行跳转。
- `return true;` 和 `return false;` 会对应到 `BytecodeGraphBuilder::VisitReturn` 方法。

**总结来说， `v8/src/compiler/bytecode-graph-builder.cc` 的这一部分是 V8 编译器中至关重要的一个环节，它充当了字节码到图表示的桥梁，使得 JavaScript 代码能够被高效地编译和执行。** 它的每一个 `Visit...` 方法都与特定的 JavaScript 语法或操作息息相关。

### 提示词
```
这是目录为v8/src/compiler/bytecode-graph-builder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```
cript()->ShiftRight(feedback));
}

void BytecodeGraphBuilder::VisitShiftRightLogical() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationHintIndex));
  BuildBinaryOp(javascript()->ShiftRightLogical(feedback));
}

void BytecodeGraphBuilder::BuildBinaryOpWithImmediate(const Operator* op) {
  DCHECK(JSOperator::IsBinaryWithFeedback(op->opcode()));
  PrepareEagerCheckpoint();
  Node* left = environment()->LookupAccumulator();
  Node* right =
      jsgraph()->ConstantNoHole(bytecode_iterator().GetImmediateOperand(0));

  FeedbackSlot slot =
      bytecode_iterator().GetSlotOperand(kBinaryOperationSmiHintIndex);
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

void BytecodeGraphBuilder::VisitAddSmi() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationSmiHintIndex));
  BuildBinaryOpWithImmediate(javascript()->Add(feedback));
}

void BytecodeGraphBuilder::VisitSubSmi() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationSmiHintIndex));
  BuildBinaryOpWithImmediate(javascript()->Subtract(feedback));
}

void BytecodeGraphBuilder::VisitMulSmi() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationSmiHintIndex));
  BuildBinaryOpWithImmediate(javascript()->Multiply(feedback));
}

void BytecodeGraphBuilder::VisitDivSmi() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationSmiHintIndex));
  BuildBinaryOpWithImmediate(javascript()->Divide(feedback));
}

void BytecodeGraphBuilder::VisitModSmi() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationSmiHintIndex));
  BuildBinaryOpWithImmediate(javascript()->Modulus(feedback));
}

void BytecodeGraphBuilder::VisitExpSmi() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationSmiHintIndex));
  BuildBinaryOpWithImmediate(javascript()->Exponentiate(feedback));
}

void BytecodeGraphBuilder::VisitBitwiseOrSmi() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationSmiHintIndex));
  BuildBinaryOpWithImmediate(javascript()->BitwiseOr(feedback));
}

void BytecodeGraphBuilder::VisitBitwiseXorSmi() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationSmiHintIndex));
  BuildBinaryOpWithImmediate(javascript()->BitwiseXor(feedback));
}

void BytecodeGraphBuilder::VisitBitwiseAndSmi() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationSmiHintIndex));
  BuildBinaryOpWithImmediate(javascript()->BitwiseAnd(feedback));
}

void BytecodeGraphBuilder::VisitShiftLeftSmi() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationSmiHintIndex));
  BuildBinaryOpWithImmediate(javascript()->ShiftLeft(feedback));
}

void BytecodeGraphBuilder::VisitShiftRightSmi() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationSmiHintIndex));
  BuildBinaryOpWithImmediate(javascript()->ShiftRight(feedback));
}

void BytecodeGraphBuilder::VisitShiftRightLogicalSmi() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kBinaryOperationSmiHintIndex));
  BuildBinaryOpWithImmediate(javascript()->ShiftRightLogical(feedback));
}

void BytecodeGraphBuilder::VisitLogicalNot() {
  Node* value = environment()->LookupAccumulator();
  Node* node = NewNode(simplified()->BooleanNot(), value);
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitToBooleanLogicalNot() {
  Node* value =
      NewNode(simplified()->ToBoolean(), environment()->LookupAccumulator());
  Node* node = NewNode(simplified()->BooleanNot(), value);
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitTypeOf() {
  PrepareEagerCheckpoint();
  Node* operand = environment()->LookupAccumulator();

  FeedbackSlot slot = bytecode_iterator().GetSlotOperand(0);
  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedUnaryOp(simplified()->TypeOf(), operand, slot);
  if (lowering.IsExit()) return;

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    node = NewNode(simplified()->TypeOf(), environment()->LookupAccumulator());
  }

  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::BuildDelete(LanguageMode language_mode) {
  PrepareEagerCheckpoint();
  Node* key = environment()->LookupAccumulator();
  Node* object =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* mode = jsgraph()->ConstantNoHole(static_cast<int32_t>(language_mode));
  Node* node = NewNode(javascript()->DeleteProperty(), object, key, mode);
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitDeletePropertyStrict() {
  BuildDelete(LanguageMode::kStrict);
}

void BytecodeGraphBuilder::VisitDeletePropertySloppy() {
  BuildDelete(LanguageMode::kSloppy);
}

void BytecodeGraphBuilder::VisitGetSuperConstructor() {
  Node* node = NewNode(javascript()->GetSuperConstructor(),
                       environment()->LookupAccumulator());
  environment()->BindRegister(bytecode_iterator().GetRegisterOperand(0), node,
                              Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitFindNonDefaultConstructorOrConstruct() {
  Node* this_function =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* new_target =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));

  Node* node = NewNode(javascript()->FindNonDefaultConstructorOrConstruct(),
                       this_function, new_target);

  // The outputs of the JSFindNonDefaultConstructor node are [boolean_thing,
  // object_thing]. In some cases we reduce it to JSCreate, which has only one
  // output, [object_thing], and we also fix the poke location in that case.
  // Here we hard-wire the FrameState for [boolean_thing] to be `true`, which is
  // the correct value in the case where JSFindNonDefaultConstructor is reduced
  // to JSCreate.
  environment()->BindRegister(bytecode_iterator().GetRegisterOperand(2),
                              jsgraph()->TrueConstant());
  environment()->BindRegistersToProjections(
      bytecode_iterator().GetRegisterOperand(2), node,
      Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::BuildCompareOp(const Operator* op) {
  DCHECK(JSOperator::IsBinaryWithFeedback(op->opcode()));
  PrepareEagerCheckpoint();
  Node* left =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* right = environment()->LookupAccumulator();

  FeedbackSlot slot = bytecode_iterator().GetSlotOperand(1);
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

void BytecodeGraphBuilder::VisitTestEqual() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kCompareOperationHintIndex));
  BuildCompareOp(javascript()->Equal(feedback));
}

void BytecodeGraphBuilder::VisitTestEqualStrict() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kCompareOperationHintIndex));
  BuildCompareOp(javascript()->StrictEqual(feedback));
}

void BytecodeGraphBuilder::VisitTestLessThan() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kCompareOperationHintIndex));
  BuildCompareOp(javascript()->LessThan(feedback));
}

void BytecodeGraphBuilder::VisitTestGreaterThan() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kCompareOperationHintIndex));
  BuildCompareOp(javascript()->GreaterThan(feedback));
}

void BytecodeGraphBuilder::VisitTestLessThanOrEqual() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kCompareOperationHintIndex));
  BuildCompareOp(javascript()->LessThanOrEqual(feedback));
}

void BytecodeGraphBuilder::VisitTestGreaterThanOrEqual() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kCompareOperationHintIndex));
  BuildCompareOp(javascript()->GreaterThanOrEqual(feedback));
}

void BytecodeGraphBuilder::VisitTestReferenceEqual() {
  Node* left =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* right = environment()->LookupAccumulator();
  Node* result = NewNode(simplified()->ReferenceEqual(), left, right);
  environment()->BindAccumulator(result);
}

void BytecodeGraphBuilder::VisitTestIn() {
  PrepareEagerCheckpoint();
  Node* object = environment()->LookupAccumulator();
  Node* key =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  FeedbackSource feedback =
      CreateFeedbackSource(bytecode_iterator().GetIndexOperand(1));
  static_assert(JSHasPropertyNode::ObjectIndex() == 0);
  static_assert(JSHasPropertyNode::KeyIndex() == 1);
  static_assert(JSHasPropertyNode::FeedbackVectorIndex() == 2);
  const Operator* op = javascript()->HasProperty(feedback);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* node = NewNode(op, object, key, feedback_vector_node());
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitTestInstanceOf() {
  FeedbackSource feedback = CreateFeedbackSource(
      bytecode_iterator().GetSlotOperand(kCompareOperationHintIndex));
  BuildCompareOp(javascript()->InstanceOf(feedback));
}

void BytecodeGraphBuilder::VisitTestUndetectable() {
  Node* object = environment()->LookupAccumulator();
  Node* node = NewNode(jsgraph()->simplified()->ObjectIsUndetectable(), object);
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitTestNull() {
  Node* object = environment()->LookupAccumulator();
  Node* result = NewNode(simplified()->ReferenceEqual(), object,
                         jsgraph()->NullConstant());
  environment()->BindAccumulator(result);
}

void BytecodeGraphBuilder::VisitTestUndefined() {
  Node* object = environment()->LookupAccumulator();
  Node* result = NewNode(simplified()->ReferenceEqual(), object,
                         jsgraph()->UndefinedConstant());
  environment()->BindAccumulator(result);
}

void BytecodeGraphBuilder::VisitTestTypeOf() {
  Node* object = environment()->LookupAccumulator();
  auto literal_flag = interpreter::TestTypeOfFlags::Decode(
      bytecode_iterator().GetFlag8Operand(0));
  Node* result;
  switch (literal_flag) {
    case interpreter::TestTypeOfFlags::LiteralFlag::kNumber:
      result = NewNode(simplified()->ObjectIsNumber(), object);
      break;
    case interpreter::TestTypeOfFlags::LiteralFlag::kString:
      result = NewNode(simplified()->ObjectIsString(), object);
      break;
    case interpreter::TestTypeOfFlags::LiteralFlag::kSymbol:
      result = NewNode(simplified()->ObjectIsSymbol(), object);
      break;
    case interpreter::TestTypeOfFlags::LiteralFlag::kBigInt:
      result = NewNode(simplified()->ObjectIsBigInt(), object);
      break;
    case interpreter::TestTypeOfFlags::LiteralFlag::kBoolean:
      result = NewNode(common()->Select(MachineRepresentation::kTagged),
                       NewNode(simplified()->ReferenceEqual(), object,
                               jsgraph()->TrueConstant()),
                       jsgraph()->TrueConstant(),
                       NewNode(simplified()->ReferenceEqual(), object,
                               jsgraph()->FalseConstant()));
      break;
    case interpreter::TestTypeOfFlags::LiteralFlag::kUndefined:
      result = graph()->NewNode(
          common()->Select(MachineRepresentation::kTagged),
          graph()->NewNode(simplified()->ReferenceEqual(), object,
                           jsgraph()->NullConstant()),
          jsgraph()->FalseConstant(),
          graph()->NewNode(simplified()->ObjectIsUndetectable(), object));
      break;
    case interpreter::TestTypeOfFlags::LiteralFlag::kFunction:
      result =
          graph()->NewNode(simplified()->ObjectIsDetectableCallable(), object);
      break;
    case interpreter::TestTypeOfFlags::LiteralFlag::kObject:
      result = graph()->NewNode(
          common()->Select(MachineRepresentation::kTagged),
          graph()->NewNode(simplified()->ObjectIsNonCallable(), object),
          jsgraph()->TrueConstant(),
          graph()->NewNode(simplified()->ReferenceEqual(), object,
                           jsgraph()->NullConstant()));
      break;
    case interpreter::TestTypeOfFlags::LiteralFlag::kOther:
      UNREACHABLE();  // Should never be emitted.
  }
  environment()->BindAccumulator(result);
}

void BytecodeGraphBuilder::BuildCastOperator(const Operator* js_op) {
  Node* value = NewNode(js_op, environment()->LookupAccumulator());
  environment()->BindRegister(bytecode_iterator().GetRegisterOperand(0), value,
                              Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitToName() {
  Node* value =
      NewNode(javascript()->ToName(), environment()->LookupAccumulator());
  environment()->BindAccumulator(value, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitToObject() {
  BuildCastOperator(javascript()->ToObject());
}

void BytecodeGraphBuilder::VisitToString() {
  Node* value =
      NewNode(javascript()->ToString(), environment()->LookupAccumulator());
  environment()->BindAccumulator(value, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitToBoolean() {
  Node* value =
      NewNode(simplified()->ToBoolean(), environment()->LookupAccumulator());
  environment()->BindAccumulator(value, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitToNumber() {
  PrepareEagerCheckpoint();
  Node* object = environment()->LookupAccumulator();

  FeedbackSlot slot = bytecode_iterator().GetSlotOperand(0);
  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedToNumber(object, slot);

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    node = NewNode(javascript()->ToNumber(), object);
  }

  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitToNumeric() {
  PrepareEagerCheckpoint();
  Node* object = environment()->LookupAccumulator();

  // If we have some kind of Number feedback, we do the same lowering as for
  // ToNumber.
  FeedbackSlot slot = bytecode_iterator().GetSlotOperand(0);
  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedToNumber(object, slot);

  Node* node = nullptr;
  if (lowering.IsSideEffectFree()) {
    node = lowering.value();
  } else {
    DCHECK(!lowering.Changed());
    node = NewNode(javascript()->ToNumeric(), object);
  }

  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitJump() { BuildJump(); }

void BytecodeGraphBuilder::VisitJumpConstant() { BuildJump(); }

void BytecodeGraphBuilder::VisitJumpIfTrue() { BuildJumpIfTrue(); }

void BytecodeGraphBuilder::VisitJumpIfTrueConstant() { BuildJumpIfTrue(); }

void BytecodeGraphBuilder::VisitJumpIfFalse() { BuildJumpIfFalse(); }

void BytecodeGraphBuilder::VisitJumpIfFalseConstant() { BuildJumpIfFalse(); }

void BytecodeGraphBuilder::VisitJumpIfToBooleanTrue() {
  BuildJumpIfToBooleanTrue();
}

void BytecodeGraphBuilder::VisitJumpIfToBooleanTrueConstant() {
  BuildJumpIfToBooleanTrue();
}

void BytecodeGraphBuilder::VisitJumpIfToBooleanFalse() {
  BuildJumpIfToBooleanFalse();
}

void BytecodeGraphBuilder::VisitJumpIfToBooleanFalseConstant() {
  BuildJumpIfToBooleanFalse();
}

void BytecodeGraphBuilder::VisitJumpIfJSReceiver() { BuildJumpIfJSReceiver(); }

void BytecodeGraphBuilder::VisitJumpIfJSReceiverConstant() {
  BuildJumpIfJSReceiver();
}

void BytecodeGraphBuilder::VisitJumpIfForInDone() { BuildJumpIfForInDone(); }

void BytecodeGraphBuilder::VisitJumpIfForInDoneConstant() {
  BuildJumpIfForInDone();
}

void BytecodeGraphBuilder::VisitJumpIfNull() {
  BuildJumpIfEqual(jsgraph()->NullConstant());
}

void BytecodeGraphBuilder::VisitJumpIfNullConstant() {
  BuildJumpIfEqual(jsgraph()->NullConstant());
}

void BytecodeGraphBuilder::VisitJumpIfNotNull() {
  BuildJumpIfNotEqual(jsgraph()->NullConstant());
}

void BytecodeGraphBuilder::VisitJumpIfNotNullConstant() {
  BuildJumpIfNotEqual(jsgraph()->NullConstant());
}

void BytecodeGraphBuilder::VisitJumpIfUndefined() {
  BuildJumpIfEqual(jsgraph()->UndefinedConstant());
}

void BytecodeGraphBuilder::VisitJumpIfUndefinedConstant() {
  BuildJumpIfEqual(jsgraph()->UndefinedConstant());
}

void BytecodeGraphBuilder::VisitJumpIfNotUndefined() {
  BuildJumpIfNotEqual(jsgraph()->UndefinedConstant());
}

void BytecodeGraphBuilder::VisitJumpIfNotUndefinedConstant() {
  BuildJumpIfNotEqual(jsgraph()->UndefinedConstant());
}

void BytecodeGraphBuilder::VisitJumpIfUndefinedOrNull() {
  BuildJumpIfEqual(jsgraph()->UndefinedConstant());
  BuildJumpIfEqual(jsgraph()->NullConstant());
}

void BytecodeGraphBuilder::VisitJumpIfUndefinedOrNullConstant() {
  BuildJumpIfEqual(jsgraph()->UndefinedConstant());
  BuildJumpIfEqual(jsgraph()->NullConstant());
}

void BytecodeGraphBuilder::VisitJumpLoop() {
  BuildIterationBodyStackCheck();
  BuildJump();
}

void BytecodeGraphBuilder::BuildSwitchOnSmi(Node* condition) {
  interpreter::JumpTableTargetOffsets offsets =
      bytecode_iterator().GetJumpTableTargetOffsets();

  NewSwitch(condition, offsets.size() + 1);
  for (interpreter::JumpTableTargetOffset entry : offsets) {
    SubEnvironment sub_environment(this);
    NewIfValue(entry.case_value);
    MergeIntoSuccessorEnvironment(entry.target_offset);
  }
  NewIfDefault();
}

void BytecodeGraphBuilder::VisitSwitchOnSmiNoFeedback() {
  PrepareEagerCheckpoint();

  Node* acc = environment()->LookupAccumulator();
  Node* acc_smi = NewNode(simplified()->CheckSmi(FeedbackSource()), acc);
  BuildSwitchOnSmi(acc_smi);
}

void BytecodeGraphBuilder::VisitSetPendingMessage() {
  Node* previous_message = NewNode(javascript()->LoadMessage());
  NewNode(javascript()->StoreMessage(), environment()->LookupAccumulator());
  environment()->BindAccumulator(previous_message);
}

void BytecodeGraphBuilder::BuildReturn(const BytecodeLivenessState* liveness) {
  BuildLoopExitsForFunctionExit(liveness);
  Node* pop_node = jsgraph()->ZeroConstant();
  Node* control =
      NewNode(common()->Return(), pop_node, environment()->LookupAccumulator());
  MergeControlToLeaveFunction(control);
}

void BytecodeGraphBuilder::VisitReturn() {
  BuildReturn(bytecode_analysis().GetInLivenessFor(
      bytecode_iterator().current_offset()));
}

void BytecodeGraphBuilder::VisitDebugger() {
  PrepareEagerCheckpoint();
  Node* call = NewNode(javascript()->Debugger());
  environment()->RecordAfterState(call, Environment::kAttachFrameState);
}

// We cannot create a graph from the debugger copy of the bytecode array.
#define DEBUG_BREAK(Name, ...) \
  void BytecodeGraphBuilder::Visit##Name() { UNREACHABLE(); }
DEBUG_BREAK_BYTECODE_LIST(DEBUG_BREAK)
#undef DEBUG_BREAK

void BytecodeGraphBuilder::VisitIncBlockCounter() {
  Node* closure = GetFunctionClosure();
  Node* coverage_array_slot =
      jsgraph()->ConstantNoHole(bytecode_iterator().GetIndexOperand(0));

  // Lowered by js-intrinsic-lowering to call Builtin::kIncBlockCounter.
  const Operator* op =
      javascript()->CallRuntime(Runtime::kInlineIncBlockCounter);

  NewNode(op, closure, coverage_array_slot);
}

void BytecodeGraphBuilder::VisitForInEnumerate() {
  Node* receiver =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* enumerator = NewNode(javascript()->ForInEnumerate(), receiver);
  environment()->BindAccumulator(enumerator, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitForInPrepare() {
  PrepareEagerCheckpoint();
  Node* enumerator = environment()->LookupAccumulator();

  FeedbackSlot slot = bytecode_iterator().GetSlotOperand(1);
  JSTypeHintLowering::LoweringResult lowering =
      TryBuildSimplifiedForInPrepare(enumerator, slot);
  if (lowering.IsExit()) return;
  DCHECK(!lowering.Changed());
  FeedbackSource feedback = CreateFeedbackSource(slot);
  Node* node = NewNode(javascript()->ForInPrepare(GetForInMode(slot), feedback),
                       enumerator, feedback_vector_node());
  environment()->BindRegistersToProjections(
      bytecode_iterator().GetRegisterOperand(0), node);
}

void BytecodeGraphBuilder::VisitForInNext() {
  PrepareEagerCheckpoint();
  Node* receiver =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  Node* index =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  int catch_reg_pair_index = bytecode_iterator().GetRegisterOperand(2).index();
  Node* cache_type = environment()->LookupRegister(
      interpreter::Register(catch_reg_pair_index));
  Node* cache_array = environment()->LookupRegister(
      interpreter::Register(catch_reg_pair_index + 1));

  // We need to rename the {index} here, as in case of OSR we lose the
  // information that the {index} is always a valid unsigned Smi value.
  index = NewNode(common()->TypeGuard(Type::UnsignedSmall()), index);

  FeedbackSlot slot = bytecode_iterator().GetSlotOperand(3);
  JSTypeHintLowering::LoweringResult lowering = TryBuildSimplifiedForInNext(
      receiver, cache_array, cache_type, index, slot);
  if (lowering.IsExit()) return;

  DCHECK(!lowering.Changed());
  FeedbackSource feedback = CreateFeedbackSource(slot);
  Node* node =
      NewNode(javascript()->ForInNext(GetForInMode(slot), feedback), receiver,
              cache_array, cache_type, index, feedback_vector_node());
  environment()->BindAccumulator(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitForInStep() {
  PrepareEagerCheckpoint();
  interpreter::Register index_reg = bytecode_iterator().GetRegisterOperand(0);
  Node* index = environment()->LookupRegister(index_reg);
  index = NewNode(simplified()->SpeculativeSafeIntegerAdd(
                      NumberOperationHint::kSignedSmall),
                  index, jsgraph()->OneConstant());
  environment()->BindRegister(index_reg, index, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitGetIterator() {
  PrepareEagerCheckpoint();
  Node* receiver =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  FeedbackSource load_feedback =
      CreateFeedbackSource(bytecode_iterator().GetIndexOperand(1));
  FeedbackSource call_feedback =
      CreateFeedbackSource(bytecode_iterator().GetIndexOperand(2));
  const Operator* op = javascript()->GetIterator(load_feedback, call_feedback);

  JSTypeHintLowering::LoweringResult lowering = TryBuildSimplifiedGetIterator(
      op, receiver, load_feedback.slot, call_feedback.slot);
  if (lowering.IsExit()) return;

  DCHECK(!lowering.Changed());
  static_assert(JSGetIteratorNode::ReceiverIndex() == 0);
  static_assert(JSGetIteratorNode::FeedbackVectorIndex() == 1);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  Node* iterator = NewNode(op, receiver, feedback_vector_node());
  environment()->BindAccumulator(iterator, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::VisitSuspendGenerator() {
  Node* generator = environment()->LookupRegister(
      bytecode_iterator().GetRegisterOperand(0));
  interpreter::Register first_reg = bytecode_iterator().GetRegisterOperand(1);
  // We assume we are storing a range starting from index 0.
  CHECK_EQ(0, first_reg.index());
  int register_count =
      static_cast<int>(bytecode_iterator().GetRegisterCountOperand(2));
  int parameter_count_without_receiver = bytecode_array().parameter_count() - 1;

  Node* suspend_id = jsgraph()->SmiConstant(
      bytecode_iterator().GetUnsignedImmediateOperand(3));

  // The offsets used by the bytecode iterator are relative to a different base
  // than what is used in the interpreter, hence the addition.
  Node* offset =
      jsgraph()->ConstantNoHole(bytecode_iterator().current_offset() +
                                (BytecodeArray::kHeaderSize - kHeapObjectTag));

  const BytecodeLivenessState* liveness = bytecode_analysis().GetInLivenessFor(
      bytecode_iterator().current_offset());

  // Maybe overallocate the value list since we don't know how many registers
  // are live.
  // TODO(leszeks): We could get this count from liveness rather than the
  // register list.
  int value_input_count = 3 + parameter_count_without_receiver + register_count;

  Node** value_inputs = local_zone()->AllocateArray<Node*>(value_input_count);
  value_inputs[0] = generator;
  value_inputs[1] = suspend_id;
  value_inputs[2] = offset;

  int count_written = 0;
  // Store the parameters.
  for (int i = 0; i < parameter_count_without_receiver; i++) {
    value_inputs[3 + count_written++] =
        environment()->LookupRegister(bytecode_iterator().GetParameter(i));
  }

  // Store the registers.
  for (int i = 0; i < register_count; ++i) {
    if (liveness == nullptr || liveness->RegisterIsLive(i)) {
      int index_in_parameters_and_registers =
          parameter_count_without_receiver + i;
      while (count_written < index_in_parameters_and_registers) {
        value_inputs[3 + count_written++] = jsgraph()->OptimizedOutConstant();
      }
      value_inputs[3 + count_written++] =
          environment()->LookupRegister(interpreter::Register(i));
      DCHECK_EQ(count_written, index_in_parameters_and_registers + 1);
    }
  }

  // Use the actual written count rather than the register count to create the
  // node.
  MakeNode(javascript()->GeneratorStore(count_written), 3 + count_written,
           value_inputs, false);

  // TODO(leszeks): This over-approximates the liveness at exit, only the
  // accumulator should be live by this point.
  BuildReturn(bytecode_analysis().GetInLivenessFor(
      bytecode_iterator().current_offset()));
}

void BytecodeGraphBuilder::BuildSwitchOnGeneratorState(
    const ZoneVector<ResumeJumpTarget>& resume_jump_targets,
    bool allow_fallthrough_on_executing) {
  Node* generator_state = environment()->LookupGeneratorState();

  int extra_cases = allow_fallthrough_on_executing ? 2 : 1;
  NewSwitch(generator_state,
            static_cast<int>(resume_jump_targets.size() + extra_cases));
  for (const ResumeJumpTarget& target : resume_jump_targets) {
    SubEnvironment sub_environment(this);
    NewIfValue(target.suspend_id());
    if (target.is_leaf()) {
      // Mark that we are resuming executing.
      environment()->BindGeneratorState(
          jsgraph()->SmiConstant(JSGeneratorObject::kGeneratorExecuting));
    }
    // Jump to the target offset, whether it's a loop header or the resume.
    MergeIntoSuccessorEnvironment(target.target_offset());
  }

  {
    SubEnvironment sub_environment(this);
    // We should never hit the default case (assuming generator state cannot be
    // corrupted), so abort if we do.
    // TODO(leszeks): Maybe only check this in debug mode, and otherwise use
    // the default to represent one of the cases above/fallthrough below?
    NewIfDefault();
    NewNode(simplified()->RuntimeAbort(AbortReason::kInvalidJumpTableIndex));
    // TODO(7099): Investigate if we need LoopExit here.
    Node* control = NewNode(common()->Throw());
    MergeControlToLeaveFunction(control);
  }

  if (allow_fallthrough_on_executing) {
    // If we are executing (rather than resuming), and we allow it, just fall
    // through to the actual loop body.
    NewIfValue(JSGeneratorObject::kGeneratorExecuting);
  } else {
    // Otherwise, this environment is dead.
    set_environment(nullptr);
  }
}

void BytecodeGraphBuilder::VisitSwitchOnGeneratorState() {
  Node* generator =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));

  Node* generator_is_undefined =
      NewNode(simplified()->ReferenceEqual(), generator,
              jsgraph()->UndefinedConstant());

  NewBranch(generator_is_undefined);
  {
    SubEnvironment resume_env(this);
    NewIfFalse();

    Node* generator_state =
        NewNode(javascript()->GeneratorRestoreContinuation(), generator);
    environment()->BindGeneratorState(generator_state);

    Node* generator_context =
        NewNode(javascript()->GeneratorRestoreContext(), generator);
    environment()->SetContext(generator_context);

    BuildSwitchOnGeneratorState(bytecode_analysis().resume_jump_targets(),
                                false);
  }

  // Fallthrough for the first-call case.
  NewIfTrue();
}

void BytecodeGraphBuilder::VisitResumeGenerator() {
  Node* generator =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  interpreter::Register first_reg = bytecode_iterator().GetRegisterOperand(1);
  // We assume we are restoring registers starting fromm index 0.
  CHECK_EQ(0, first_reg.index());

  const BytecodeLivenessState* liveness = bytecode_analysis().GetOutLivenessFor(
      bytecode_iterator().current_offset());

  int parameter_count_without_receiver = bytecode_array().parameter_count() - 1;

  // Mapping between registers and array indices must match that used in
  // InterpreterAssembler::ExportParametersAndRegisterFile.
  for (int i = 0; i < environment()->register_count(); ++i) {
    if (liveness == nullptr || liveness->RegisterIsLive(i)) {
      Node* value = NewNode(javascript()->GeneratorRestoreRegister(
                                parameter_count_without_receiver + i),
                            generator);
      environment()->BindRegister(interpreter::Register(i), value);
    }
  }

  // Update the accumulator with the generator's input_or_debug_pos.
  Node* input_or_debug_pos =
      NewNode(javascript()->GeneratorRestoreInputOrDebugPos(), generator);
  environment()->BindAccumulator(input_or_debug_pos);
}

void BytecodeGraphBuilder::VisitWide() {
  // Consumed by the BytecodeArrayIterator.
  UNREACHABLE();
}

void BytecodeGraphBuilder::VisitExtraWide() {
  // Consumed by the BytecodeArrayIterator.
  UNREACHABLE();
}

void BytecodeGraphBuilder::VisitIllegal() {
  // Not emitted in valid bytecode.
  UNREACHABLE();
}

void BytecodeGraphBuilder::SwitchToMergeEnvironment(int current_offset) {
  auto it = merge_environments_.find(current_offset);
  if (it != merge_environments_.end()) {
    mark_as_needing_eager_checkpoint(true);
    if (environment() != nullptr) {
      it->second->Merge(environment(),
                        bytecode_analysis().GetInLivenessFor(current_offset));
    }
    set_environment(it->second);
  }
}

void BytecodeGraphBuilder::BuildLoopHeaderEnvironment(int current_offset) {
  if (bytecode_analysis().IsLoopHeader(current_offset)) {
    mark_as_needing_eager_checkpoint(true);
    const LoopInfo& loop_info =
        bytecode_analysis().GetLoopInfoFor(current_offset);
    const BytecodeLivenessState* liveness =
        bytecode_analysis().GetInLivenessFor(current_offset);

    const auto& resume_jump_targets = loop_info.resume_jump_targets();
    bool generate_suspend_switch = !resume_jump_targets.empty();

    // Add loop header.
    environment()->PrepareForLoop(loop_info.assignments(), liveness);

    // Store a copy of the environment so we can connect merged back edge inputs
    // to the loop header.
    merge_environments_[current_offset] = environment()->Copy();

    // If this loop contains resumes, create a new switch just after the loop
    // for those resumes.
    if (generate_suspend_switch) {
      BuildSwitchOnGeneratorState(loop_info.resume_jump_targets(), true);

      // TODO(leszeks): At this point we know we are executing rather than
      // resuming, so we should be able to prune off the phis in the environment
      // related to the resume path.

      // Set the generator state to a known constant.
      environment()->BindGeneratorState(
          jsgraph()->SmiConstant(JSGeneratorObject::kGeneratorExecuting));
    }
  }
}

void BytecodeGraphBuilder::MergeIntoSuccessorEnvironment(int target_offset) {
  BuildLoopExitsForBranch(target_offset);
  Environment*& merge_environment = merge_environments_[target_offset];

  if (merge_environment == nullptr) {
    // Append merge nodes to the environment. We may merge here with another
    // environment. So add a place holder for merge nodes. We may add redundant
    // but will be eliminated in a later pass.
    NewMerge();
    merge_environment = environment();
  } else {
    // Merge any values which are live coming into the successor.
    merge_environment->Merge(
        environment(), bytecode_analysis().GetInLivenessFor(target_offset));
  }
  set_environment(nullptr);
}

void BytecodeGraphBuilder::MergeControlToLeaveFunction(Node* exit) {
  exit_controls_.push_back(exit);
  set_environment(nullptr);
}

void BytecodeGraphBuilder::BuildLoopExitsForBranch(int target_offset) {
  int origin_offset = bytecode_iterator().current_offset();
  // Only build loop exits for forward edges.
  if (target_offset > origin_offset) {
    BuildLoopExitsUntilLoop(
        bytecode_analysis().GetLoopOffsetFor(target_offset),
        bytecode_analysis().GetInLivenessFor(target_offset));
  }
}

void BytecodeGraphBuilder::BuildLoopExitsUntilLoop(
    int loop_offset, const BytecodeLivenessState* liveness) {
  int origin_offset = bytecode_iterator().current_offset();
  int current_loop = bytecode_analysis().GetLoopOffsetFor(origin_offset);
  // The limit_offset is the stop offset for building loop exists, used for OSR.
  // It prevents the creations of loopexits for loops which do not exist.
  loop_offset = std::max(loop_offset, currently_peeled_loop_offset_);

  while (loop_offset < current_loop) {
    Node* loop_node = merge_environments_[current_loop]->GetControlDependency();
    const LoopInfo& loop_info =
        bytecode_analysis().GetLoopInfoFor(current_loop);
    environment()->PrepareForLoopExit(loop_node, loop_info.assignments(),
                                      liveness);
    current_loop = loop_info.parent_offset();
  }
}

void BytecodeGraphBuilder::BuildLoopExitsForFunctionExit(
    const BytecodeLivenessState* liveness) {
  BuildLoopExitsUntilLoop(-1, liveness);
}

void BytecodeGraphBuilder::BuildJump() {
  MergeIntoSuccessorEnvironment(bytecode_iterator().GetJumpTargetOffset());
}

void BytecodeGraphBuilder::BuildJumpIf(Node* condition) {
  NewBranch(condition, BranchHint::kNone);
  {
    SubEnvironment sub_environment(this);
    NewIfTrue();
    MergeIntoSuccessorEnvironment(bytecode_iterator().GetJumpTargetOffset());
  }
  NewIfFalse();
}

void BytecodeGraphBuilder::BuildJumpIfNot(Node* condition) {
  NewBranch(condition, BranchHint::kNone);
  {
    SubEnvironment sub_environment(this);
    NewIfFalse();
    MergeIntoSuccessorEnvironment(bytecode_iterator().GetJumpTargetOffset());
  }
  NewIfTrue();
}

void BytecodeGraphBuilder::BuildJumpIfEqual(Node* comperand) {
  Node* accumulator = environment()->LookupAccumulator();
  Node* condition =
      NewNode(simplified()->ReferenceEqual(), accumulator, comperand);
  BuildJumpIf(condition);
}

void BytecodeGraphBuilder::BuildJumpIfNotEqual(Node* comperand) {
  Node* accumulator = environment()->LookupAccumulator();
  Node* condition =
      NewNode(simplified()->ReferenceEqual(), accumulator, comperand);
  BuildJumpIfNot(condition);
}

void BytecodeGraphBuilder::BuildJumpIfFalse() {
  NewBranch(environment()->LookupAccumulator(), BranchHint::kNone);
  {
    SubEnvironment sub_environment(this);
    NewIfFalse();
    environment()->BindAccumulator(jsgraph()->FalseConstant());
    MergeIntoSuccessorEnvironment(bytecode_iterator().GetJumpTargetOffset());
  }
  NewIfTrue();
  environment()->BindAccumulator(jsgraph()->TrueConstant());
}

void BytecodeGraphBuilder::BuildJumpIfTrue() {
  NewBranch(environment()->LookupAccumulator(), BranchHint::kNone);
  {
    SubEnvironment sub_environment(this);
    NewIfTrue();
    environment()->BindAccumulator(jsgraph()->TrueConstant());
    MergeIntoSuccessorEnvironment(bytecode_iterator().GetJumpTargetOffset());
  }
  NewIfFalse();
  environment()->BindAccumulator(jsgraph()->FalseConstant());
}

void BytecodeGraphBuilder::BuildJumpIfToBooleanTrue() {
  Node* accumulator = environment()->LookupAccumulator();
  Node* condition = NewNode(simplified()->ToBoolean(), accumulator);
  BuildJumpIf(condition);
}

void BytecodeGraphBuilder::BuildJumpIfToBooleanFalse() {
  Node* accumulator = environment()->LookupAccumulator();
  Node* condition = NewNode(simplified()->ToBoolean(), accumulator);
  BuildJumpIfNot(condition);
}

void BytecodeGraphBuilder::BuildJumpIfNotHole() {
  Node* accumulator = environment()->LookupAccumulator();
  Node* condition = NewNode(simplified()->ReferenceEqual(), accumulator,
                            jsgraph()->TheHoleConstant());
  BuildJumpIfNot(condition);
}

void BytecodeGraphBuilder::BuildJumpIfJSReceiver() {
  Node* accumulator = environment()->LookupAccumulator();
  Node* condition = NewNode(simplified()->ObjectIsReceiver(), accumulator);
  BuildJumpIf(condition);
}

void BytecodeGraphBuilder::BuildJumpIfForInDone() {
  // There's an eager checkpoint here for the speculative comparison, but it can
  // never actually deopt because these are known to be Smi.
  PrepareEagerCheckpoint();
  Node* index =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(1));
  Node* cache_length =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(2));
  Node* condition = NewNode(
      simplified()->SpeculativeNumberEqual(NumberOperationHint::kSignedSmall),
      index, cache_length);
  BuildJumpIf(condition);
}

JSTypeHintLowering::LoweringResult
BytecodeGraphBuilder::TryBuildSimplifiedUnaryOp(const Operator* op,
                                                Node* operand,
                                                FeedbackSlot slot) {
  Node* effect = environment()->GetEffectDependency();
  Node* control = environment()->GetControlDependency();
  JSTypeHintLowering::LoweringResult result =
      type_hint_lowering().ReduceUnaryOperation(op, operand, effect, control,
                                                slot);
  ApplyEarlyReduction(result);
  return result;
}

JSTypeHintLowering::LoweringResult
BytecodeGraphBuilder::TryBuildSimplifiedBinaryOp(const Operator* op, Node* left,
                                                 Node* right,
                                                 FeedbackSlot slot) {
  Node* effect = environment()->GetEffectDependency();
  Node* control = environment()->GetControlDependency();
  JSTypeHintLowering::LoweringResult result =
      type_hint_lowering().ReduceBinaryOperation(op, left, right, effect,
                                                 control, slot);
  ApplyEarlyReduction(result);
  return result;
}

JSTypeHintLowering::LoweringResult
BytecodeGraphBuilder::TryBuildSimplifiedForInNext(Node* receiver,
                                                  Node* cache_array,
                                                  Node* cache_type, Node* index,
                                                  FeedbackSlot slot) {
  Node* effect = environment()->GetEffectDependency();
  Node* control = environment()->GetControlDependency();
  JSTypeHintLowering::LoweringResult result =
      type_hint_lowering().ReduceForInNextOperation(
          receiver, cache_array, cache_type, index, effect, control, slot);
  ApplyEarlyReduction(result);
  return result;
}

JSTypeHintLowering::LoweringResult
BytecodeGraphBuilder::TryBuildSimplifiedForInPrepare(Node* enumerator,
                                                     FeedbackSlot slot) {
  Node* effect = environment()->GetEffectDependency();
  Node* control = environment()->GetControlDependency();
  JSTypeHintLowering::LoweringResult result =
      type_hint_lowering().ReduceForInPrepareOperation(enumerator, effect,
                                                       control, slot);
  ApplyEarlyReduction(result);
  return result;
}

JSTypeHintLowering::LoweringResult
BytecodeGraphBuilder::TryBuildSimplifiedToNumber(Node* value,
                                                 FeedbackSlot slot) {
  Node* effect = environment()->GetEffectDependency();
  Node* control = environment()->GetControlDependency();
  JSTypeHintLowering::LoweringResult result =
      type_hint_lowering().ReduceToNumberOperation(value, effect, control,
                                                   slot);
  ApplyEarlyReduction(result);
  return result;
}

JSTypeHintLowering::LoweringResult BytecodeGraphBuilder::TryBuildSimplifiedCall(
    const Operator* op, Node* const* args, int arg_count, FeedbackSlot slot) {
  Node* effect = environment()->GetEffectDependency();
  Node* control = environment()->GetControlDependency();
  JSTypeHintLowering::LoweringResult result =
      type_hint_lowering().ReduceCallOperation(op, args, arg_count, effect,
                                               control, slot);
  ApplyEarlyReduction(result);
  return result;
}

JSTypeHintLowering::LoweringResult
BytecodeGraphBuilder::TryBuildSimplifiedConstruct(const Operator* op,
                                                  Node* const* args,
                                                  int arg_count,
                                                  FeedbackSlot slot) {
  Node* effect = environment()->GetEffectDependency();
  Node* control = environment()->GetControlDependency();
  JSTypeHintLowering::LoweringResult result =
      type_hint_lowering().ReduceConstructOperation(op, args, arg_count, effect,
                                                    control, slot);
  ApplyEarlyReduction(result);
  return result;
}

JSTypeHintLowering::LoweringResult
BytecodeGraphBuilder::TryBuildSimplifiedGetIterator(const Operator* op,
                                                    Node* receiver,
                                                    FeedbackSlot load_slot,
                                                    FeedbackSlot call_slot) {
  Node* effect = environment()->GetEffectDependency();
  Node* control = environment()->GetControlDependency();
  JSTypeHintLowering::LoweringResult early_reduction =
      type_hint_lowering().ReduceGetIteratorOperation(
          op, receiver, effect, control, load_slot, call_slot);
  ApplyEarlyReduction(early_reduction);
  return early_reduction;
}

JSTypeHintLowering::LoweringResult
BytecodeGraphBuilder::TryBuildSimplifiedLoadNamed(const Operator* op,
                                                  FeedbackSlot slot) {
  Node* effect = environment()->GetEffectDependency();
  Node* control = environment()->GetControlDependency();
  JSTypeHintLowering::LoweringResult early_reduction =
      type_hint_lowering().ReduceLoadNamedOperation(op, effect, control, slot);
  ApplyEarlyReduction(early_reduction);
  return early_reduction;
}

JSTypeHintLowering::LoweringResult
BytecodeGraphBuilder::TryBuildSimplifiedLoadKeyed(const Operator* op,
                                                  Node* receiver, Node* key,
                                                  FeedbackSlot slot) {
  Node* effect = environment()->GetEffectDependency();
  Node* control = environment()->GetControlDependency();
  JSTypeHintLowering::LoweringResult result =
      type_hint_lowering().ReduceLoadKeyedOperation(op, receiver, key, effect,
                                                    control, slot);
  ApplyEarlyReduction(result);
  return result;
}

JSTypeHintLowering::LoweringResult
BytecodeGraphBuilder::TryBuildSimplifiedStoreNamed(const Operator* op,
                                                   Node* receiver, Node* value,
                                                   FeedbackSlot slot) {
  Node* effect = environment()->GetEffectDependency();
  Node* control = environment()->GetControlDependency();
  JSTypeHintLowering::LoweringResult result =
      type_hint_lowering().ReduceStoreNamedOperation(op, receiver, value,
                                                     effect, control, slot);
  ApplyEarlyReduction(result);
  return result;
}

JSTypeHintLowering::LoweringResult
BytecodeGraphBuilder::TryBuildSimplifiedStoreKeyed(const Operator* op,
                                                   Node* receiver, Node* key,
                                                   Node* value,
                                                   FeedbackSlot slot) {
  Node* effect = environment()->GetEffectDependency();
  Node* control = environment()->GetControlDependency();
  JSTypeHintLowering::LoweringResult result =
      type_hint_lowering().ReduceStoreKeyedOperation(op, receiver, key, value,
                                                     effect, control, slot);
  ApplyEarlyReduction(result);
  return result;
}

void BytecodeGraphBuilder::ApplyEarlyReduction(
    JSTypeHintLowering::LoweringResult reduction) {
  if (reduction.IsExit()) {
    MergeControlToLeaveFunction(reduction.control());
  } else if (reduction.IsSideEffectFree()) {
    environment()->UpdateEffectDependency(reduction.effect());
    environment()->UpdateControlDependency(reduction.control());
  } else {
    DCHECK(!reduction.Changed());
    // At the moment, we assume side-effect free reduction. To support
    // side-effects, we would have to invalidate the eager checkpoint,
    // so that deoptimization does not repeat the side effect.
  }
}

Node** BytecodeGraphBuilder::EnsureInputBufferSize(int size) {
  if (size > input_buffer_size_) {
    size = size + kInputBufferSizeIncrement + input_buffer_size_;
    input_buffer_ = local_zone()->AllocateArray<Node*>(size);
    input_buffer_size_ = size;
  }
  return input_buffer_;
}

void BytecodeGraphBuilder::ExitThenEnterExceptionHandlers(int current_offset) {
  DisallowGarbageCollection no_gc;
  HandlerTable table(bytecode_array().handler_table_address(),
                     bytecode_array().handler_table_size(),
                     HandlerTable::kRangeBasedEncoding);

  // Potentially exit exception handlers.
  while (!exception_handlers_.empty()) {
    int current_end = exception_handlers_.top().end_offset_;
    if (current_offset < current_end) break;  // Still covered by range.
    exception_handlers_.pop();
  }

  // Potentially enter exception handlers.
  int num_entries = table.NumberOfRangeEntries();
  while (current_exception_handler_ < num_entries) {
    int next_start = table.GetRangeStart(current_exception_handler_);
    if (current_offset < next_start) break;  // Not yet covered by range.
    int next_end = table.GetRangeEnd(current_exception_handler_);
    int next_handler = table.GetRangeHandler(current_exception_handler_);
    int context_register = table.GetRangeData(current_exception_handler_);
    exception_handlers_.push(
        {next_start, next_end, next_handler, context_register});
    current_exception_handler_++;
  }
}

Node* BytecodeGraphBuilder::MakeNode(const Operator* op, int value_input_count,
                                     Node* const* value_inputs,
                                     bool incomplete) {
  DCHECK_EQ(op->ValueInputCount(), value_input_count);
  // Parameter nodes must be created through GetParameter.
  DCHECK_IMPLIES(
      op->opcode() == IrOpcode::kParameter,
      (nullptr == cached_parameters_[static_cast<std::size_t>(
                      ParameterIndexOf(op) - ParameterInfo::kMinIndex)]));

  bool has_context = OperatorProperties::HasContextInput(op);
  bool has_frame_state = OperatorProperties::HasFrameStateInput(op);
  bool has_control = op->ControlInputCount() == 1;
  bool has_effect = op->EffectInputCount() == 1;

  DCHECK_LT(op->ControlInputCount(), 2);
  DCHECK_LT(op->EffectInputCount(), 2);

  Node* result = nullptr;
  if (!has_context && !has_frame_state && !has_control && !has_effect) {
    result = graph()->NewNode(op, value_input_count, value_inputs, incomplete);
  } else {
    bool inside_handler = !exception_handlers_.empty();
    int input_count_with_deps = value_input_count;
    if (has_context) ++input_count_with_deps;
    if (has_frame_state) ++input_count_with_deps;
    if (has_control) ++input_count_with_deps;
    if (has_effect) ++input_count_with_deps;
    Node** buffer = EnsureInputBufferSize(input_count_with_deps);
    if (value_input_count > 0) {
      memcpy(buffer, value_inputs, kSystemPointerSize * value_input_count);
    }
    Node** current_input = buffer + value_input_count;
    if (has_context) {
      *current_input++ = OperatorProperties::NeedsExactContext(op)
                             ? environment()->Context()
                             : native_context_node();
    }
    if (has_frame_state) {
      // The frame state will be inserted later. Here we misuse the {Dead} node
      // as a sentinel to be later overwritten with the real frame state by the
      // calls to {PrepareFrameState} within individual visitor methods.
      *current_input++ = jsgraph()->Dead();
    }
    if (has_effect) {
      *current_input++ = environment()->GetEffectDependency();
    }
    if (has_control) {
      *current_input++ = environment()->GetControlDependency();
    }
    result = graph()->NewNode(op, input_count_with_deps, buffer, incomplete);
    // Update the current control dependency for control-producing nodes.
    if (result->op()->ControlOutputCount() > 0) {
      environment()->UpdateControlDependency(result);
    }
    // Update the current effect dependency for effect-producing nodes.
    if (result->op()->EffectOutputCount() > 0) {
      environment()->UpdateEffectDependency(result);
    }
    // Add implicit exception continuation for throwing nodes.
    if (!result->op()->HasProperty(Operator::kNoThrow) && inside_handler) {
      int handler_offset = exception_handlers_.top().handler_offset_;
      int context_index = exception_handlers_.top().context_register_;
      interpreter::Register context_register(context_index);
      Environment* success_env = environment()->Copy();
      const Operator* if_exception = common()->IfException();
      Node* effect = environment()->GetEffectDependency();
      Node* on_exception = graph()->NewNode(if_exception, effect, result);
      Node* context = environment()->LookupRegister(context_register);
      environment()->UpdateControlDependency(on_exception);
      environment()->UpdateEffectDependency(on_exception);
      environment()->BindAccumulator(on_exception);
      environment()->SetContext(context);
      MergeIntoSuccessorEnvironment(handler_offset);
      set_environment(success_env);
    }
    // Add implicit success continuation for throwing nodes.
    if (!result->op()->HasProperty(Operator::kNoThrow) && inside_handler) {
      const Operator* if_success = common()->IfSuccess();
      Node* on_success = graph()->NewNode(if_success, result);
      environment()->UpdateControlDependency(on_success);
    }
    // Ensure checkpoints are created after operations with side-effects.
    if (has_effect && !result->op()->HasProperty(Operator::kNoWrite)) {
      mark_as_needing_eager_checkpoint(true);
    }
  }

  return result;
}


Node* BytecodeGraphBuilder::NewPhi(int count, Node* input, Node* control) {
  const Operator* phi_op = common()->Phi(MachineRepresentation::kTagged, count);
  Node** buffer = EnsureInputBufferSize(count + 1);
  MemsetPointer(buffer, input, count);
  buffer[count] = control;
  return graph()->NewNode(phi_op, count + 1, buffer, true);
}

Node* BytecodeGraphBuilder::NewEffectPhi(int count, Node* input,
                                         Node* control) {
  const Operator* phi_op = common()->EffectPhi(count);
  Node** buffer = EnsureInputBufferSize(count + 1);
  MemsetPointer(buffer, input, count);
  buffer[count] = control;
  return graph()->NewNode(phi_op, count + 1, buffer, true);
}


Node* BytecodeGraphBuilder::MergeControl(Node* control, Node* other) {
  int inputs = control->op()->ControlInputCount() + 1;
  if (control->opcode() == IrOpcode::kLoop) {
    // Control node for loop exists, add input.
    const Operator* op = common()->Loop(inputs);
    control->AppendInput(graph_zone(), other);
    NodeProperties::ChangeOp(control, op);
  } else if (control->opcode() == IrOpcode::kMerge) {
    // Control node for merge exists, add input.
    const Operator* op = common()->Merge(inputs);
    control->AppendInput(graph_zone(), other);
    NodeProperties::ChangeOp(control, op);
  } else {
    // Control node is a singleton, introduce a merge.
    const Operator* op = common()->Merge(inputs);
    Node* merge_inputs[] = {control, other};
    control = graph()->NewNode(op, arraysize(merge_inputs), merge_inputs, true);
  }
  return control;
}

Node* BytecodeGraphBuilder::MergeEffect(Node* value, Node* other,
                                        Node* control) {
  int inputs = control->op()->ControlInputCount();
  if (value->opcode() == IrOpcode::kEffectPhi &&
      NodeProperties::GetControlInput(value) == control) {
    // Phi already exists, add input.
    value->InsertInput(graph_zone(), inputs - 1, other);
    NodeProperties::ChangeOp(value, common()->EffectPhi(inputs));
  } else if (value != other) {
    // Phi does not exist yet, introduce one.
    value = NewEffectPhi(inputs, value, control);
    value->ReplaceInput(inputs - 1, other);
  }
  return value;
}

Node* BytecodeGraphBuilder::MergeValue(Node* value, Node* other,
                                       Node* control) {
  int inputs = control->op()->ControlInputCount();
  if (value->opcode() == IrOpcode::kPhi &&
      NodeProperties::GetControlInput(value) == control) {
    // Phi already exists, add input.
    value->InsertInput(graph_zone(), inputs - 1, other);
    NodeProperties::ChangeOp(
        value, common()->Phi(MachineRepresentation::kTagged, inputs));
  } else if (value != other) {
    // Phi does not exist yet, introduce one.
    value = NewPhi(inputs, value, control);
    value->ReplaceInput(inputs - 1, other);
  }
  return value;
}

void BytecodeGraphBuilder::UpdateSourceAndBytecodePosition(int offset) {
  if (node_origins_) {
    node_origins_->SetCurrentBytecodePosition(offset);
  }
  if (source_position_iterator().done()) return;
  if (source_position_iterator().code_offset() == offset) {
    source_positions_->SetCurrentPosition(SourcePosition(
        source_position_iterator().source_position().ScriptOffset(),
        start_position_.InliningId()));
    source_position_iterator().Advance();
  } else {
    DCHECK_GT(source_position_iterator().code_offset(), offset);
  }
}

void BuildGraphFromBytecode(
    JSHeapBroker* broker, Zone* local_zone, SharedFunctionInfoRef shared_info,
    BytecodeArrayRef bytecode, FeedbackCellRef feedback_cell,
    BytecodeOffset osr_offset, JSGraph* jsgraph,
    CallFrequency const& invocation_frequency,
    SourcePositionTable* source_positions, NodeOriginTable* node_origins,
    int inlining_id, CodeKind code_kind, BytecodeGraphBuilderFlags flags,
    TickCounter* tick_counter, ObserveNodeInfo const& observe_node_info) {
  BytecodeGraphBuilder builder(
      broker, local_zone, broker->target_native_context(), shared_info,
      bytecode, feedback_cell, osr_offset, jsgraph, invocation_frequency,
      source_positions, node_origins, inlining_id, code_kind, flags,
      tick_counter, observe_node_info);
  builder.CreateGraph();
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```