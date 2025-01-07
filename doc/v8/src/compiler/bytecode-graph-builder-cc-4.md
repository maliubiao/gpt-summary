Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/bytecode-graph-builder.cc`. I need to analyze the code and extract its main purpose.

The code consists of a class `BytecodeGraphBuilder` with methods like `VisitAdd`, `VisitSub`, `VisitLoadGlobal`, etc. These methods correspond to different bytecode instructions. Each method seems to translate a bytecode instruction into a graph representation used by the V8 compiler.

Therefore, the primary function of `bytecode-graph-builder.cc` is to translate bytecode instructions into an intermediate representation suitable for further optimization and code generation within the V8 compiler.

Regarding the user's specific requests:

1. **Functionality List:** Enumerate the actions performed by the code.
2. **Torque Source:** Check if the filename ends with `.tq`.
3. **JavaScript Relation:**  If the functionality relates to JavaScript, provide an example.
4. **Code Logic Reasoning:** If there's logical deduction based on input, provide an example.
5. **Common Programming Errors:** If the code relates to preventing user errors, provide examples.
6. **Overall Functionality (This Part):** Summarize the actions within the provided snippet.

Let's go through each point.
```
这是目录为v8/src/compiler/bytecode-graph-builder.cc的一个v8源代码， 请列举一下它的功能,
如果v8/src/compiler/bytecode-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

根据提供的代码片段，`v8/src/compiler/bytecode-graph-builder.cc` 的主要功能是 **将 V8 的字节码指令转换为中间表示 (IR) 图**，以便后续的编译器优化和代码生成。

**功能列表:**

* **处理算术运算字节码:**  例如 `VisitAdd`, `VisitSub`, `VisitMul`, `VisitDiv`, `VisitMod`, `VisitExp`, `VisitAddSmi` 等，负责将加减乘除、取模、幂运算等字节码转换为相应的 IR 节点。
* **处理位运算字节码:** 例如 `VisitBitwiseOr`, `VisitBitwiseXor`, `VisitBitwiseAnd`, `VisitShiftLeft`, `VisitShiftRight`, `VisitShiftRightLogical` 以及它们的 Smi 版本，负责将位运算字节码转换为 IR 节点。
* **处理逻辑运算字节码:** 例如 `VisitLogicalNot`, `VisitToBooleanLogicalNot`，负责将逻辑非运算转换为 IR 节点。
* **处理类型判断字节码:** 例如 `VisitTypeOf`，负责将 `typeof` 运算符转换为 IR 节点。
* **处理属性删除字节码:** 例如 `VisitDeletePropertyStrict`, `VisitDeletePropertySloppy`，负责将 `delete` 操作符转换为 IR 节点。
* **处理 `super` 关键字相关字节码:** 例如 `VisitGetSuperConstructor`, `VisitFindNonDefaultConstructorOrConstruct`，负责将 `super` 相关的操作转换为 IR 节点。
* **处理比较运算字节码:** 例如 `VisitTestEqual`, `VisitTestEqualStrict`, `VisitTestLessThan`, `VisitTestGreaterThan` 等，负责将各种比较运算符转换为 IR 节点。
* **处理 `in` 和 `instanceof` 运算符字节码:** 例如 `VisitTestIn`, `VisitTestInstanceOf`，负责将 `in` 和 `instanceof` 运算符转换为 IR 节点。
* **处理类型测试字节码:** 例如 `VisitTestUndetectable`, `VisitTestNull`, `VisitTestUndefined`, `VisitTestTypeOf`，负责将各种类型测试转换为 IR 节点。
* **处理类型转换字节码:** 例如 `VisitToName`, `VisitToObject`, `VisitToString`, `VisitToBoolean`, `VisitToNumber`, `VisitToNumeric`，负责将类型转换操作转换为 IR 节点。
* **处理跳转字节码:** 例如 `VisitJump`, `VisitJumpIfTrue`, `VisitJumpIfFalse` 等，负责将各种跳转指令转换为 IR 控制流节点。
* **处理 `switch` 语句字节码:** 例如 `VisitSwitchOnSmiNoFeedback`，负责将 `switch` 语句转换为 IR 结构。
* **处理异常相关字节码:** 例如 `VisitSetPendingMessage`，用于设置待处理的消息。
* **处理 `return` 语句字节码:** `VisitReturn`，负责将 `return` 语句转换为 IR 节点。
* **处理 `debugger` 语句字节码:** `VisitDebugger`，负责处理 `debugger` 语句。
* **处理代码覆盖率相关字节码:** `VisitIncBlockCounter`，用于增加代码块的执行计数。
* **处理 `for...in` 循环相关字节码:** 例如 `VisitForInEnumerate`, `VisitForInPrepare`, `VisitForInNext`, `VisitForInStep`，负责将 `for...in` 循环的各个步骤转换为 IR 节点。
* **处理迭代器相关字节码:** `VisitGetIterator`，负责获取迭代器。
* **处理生成器函数相关字节码:** 例如 `VisitSuspendGenerator`, `VisitSwitchOnGeneratorState`, `VisitResumeGenerator`，负责处理生成器函数的挂起和恢复状态。
* **处理宽字节码指令:** `VisitWide`, `VisitExtraWide`，虽然代码中标记为 `UNREACHABLE()`，但它们是处理 V8 中操作数较多的字节码指令的前缀。
* **处理非法字节码指令:** `VisitIllegal`，标记为 `UNREACHABLE()`，表示不应该出现。
* **维护和切换环境:** `SwitchToMergeEnvironment`, `BuildLoopHeaderEnvironment`，负责管理和切换代码生成过程中的环境信息。

**关于文件扩展名:**

如果 `v8/src/compiler/bytecode-graph-builder.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码。但根据提供的文件名，它是 `.cc` 文件，因此是 C++ 源代码。

**与 JavaScript 功能的关系和示例:**

这个 C++ 文件直接负责将 JavaScript 代码编译成机器码过程中的一个重要环节。它将 JavaScript 编译产生的字节码转换为更底层的图表示。以下是一些 JavaScript 示例，以及 `bytecode-graph-builder.cc` 如何处理与之相关的字节码：

* **算术运算:**
   ```javascript
   let a = 10;
   let b = 5;
   let sum = a + b; // 对应 VisitAdd 相关的字节码
   let product = a * b; // 对应 VisitMul 相关的字节码
   ```

* **逻辑运算:**
   ```javascript
   let flag = true;
   let notFlag = !flag; // 对应 VisitLogicalNot 相关的字节码
   ```

* **类型判断:**
   ```javascript
   let value = "hello";
   console.log(typeof value); // 对应 VisitTypeOf 相关的字节码
   ```

* **属性删除:**
   ```javascript
   const obj = { name: "Alice", age: 30 };
   delete obj.age; // 对应 VisitDeletePropertyStrict 或 VisitDeletePropertySloppy 相关的字节码
   ```

* **比较运算:**
   ```javascript
   let x = 5;
   let y = 10;
   if (x < y) { // 对应 VisitTestLessThan 相关的字节码
       console.log("x is less than y");
   }
   ```

* **类型转换:**
   ```javascript
   let numStr = "42";
   let num = Number(numStr); // 对应 VisitToNumber 相关的字节码
   let boolValue = !!num; // 对应 VisitToBoolean 相关的字节码
   ```

* **`for...in` 循环:**
   ```javascript
   const obj = { a: 1, b: 2, c: 3 };
   for (let key in obj) { // 对应 VisitForInEnumerate, VisitForInNext 等相关的字节码
       console.log(key);
   }
   ```

* **生成器函数:**
   ```javascript
   function* myGenerator() {
       yield 1;
       yield 2;
   }
   const gen = myGenerator(); // 对应 VisitSwitchOnGeneratorState, VisitSuspendGenerator, VisitResumeGenerator 等相关的字节码
   ```

**代码逻辑推理的假设输入与输出:**

假设输入的字节码是执行 `let sum = a + b;` 的指令序列，其中 `a` 和 `b` 分别存储在特定的寄存器中。

* **假设输入 (字节码):**  LOAD_REGISTER r0, [location of a], LOAD_REGISTER r1, [location of b], ADD r2, r0, r1, STORE_REGISTER [location of sum], r2
* **输出 (部分 IR 图):** 会生成表示加载 `a` 和 `b` 的节点，一个表示加法运算的节点，并将结果存储到 `sum` 的位置的节点。具体 IR 结构会比较复杂，涉及到操作数、反馈槽等信息，但核心是构建一个代表加法操作的图节点。

**用户常见的编程错误示例 (虽然此代码主要处理编译过程，但其影响最终会体现在运行时行为):**

此代码本身不直接处理用户编程错误，但它正确地构建 IR 图是确保 JavaScript 代码按预期运行的关键。如果 `bytecode-graph-builder.cc` 中的逻辑有误，可能会导致生成的代码行为异常，例如：

* **类型转换错误:**  如果 `VisitToNumber` 的实现不正确，可能会导致本应转换为数字的值转换失败，或者得到错误的结果，例如 `Number("abc")` 应该返回 `NaN`。
* **运算符优先级错误:** 如果二元运算符的 IR 构建顺序不正确，可能会导致计算结果错误，例如 `2 + 3 * 4` 应该先算乘法。
* **作用域错误:** 虽然作用域主要由其他编译阶段处理，但如果变量加载的 IR 构建错误，可能会导致访问到错误作用域的变量。

**当前代码片段的功能归纳 (第 5 部分):**

这部分代码主要负责将 **各种 JavaScript 的二元和一元运算、类型转换、类型判断、属性删除、比较运算、`in` 和 `instanceof` 运算符、`super` 关键字相关操作，以及部分控制流跳转** 的字节码指令转换为对应的中间表示 (IR) 图节点。它涵盖了 JavaScript 语言中很多基础的操作和运算符，是构建程序逻辑图的关键部分。特别需要注意的是，这段代码还处理了与 Smi (小整数) 相关的优化版本指令，例如 `VisitAddSmi` 等，这体现了 V8 对常见数据类型的优化处理。此外，还涉及到与生成器函数和 `for...in` 循环相关的字节码处理。

Prompt: 
```
这是目录为v8/src/compiler/bytecode-graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/bytecode-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能

"""
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
      BuildSwitchOnGeneratorState(loop_info.resume_ju
"""


```