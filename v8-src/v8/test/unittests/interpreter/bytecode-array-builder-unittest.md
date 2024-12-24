Response: Let's break down the thought process for analyzing this C++ unittest file and generating the JavaScript example.

**1. Understanding the Goal:**

The request asks for a summary of the C++ file's functionality and, if related to JavaScript, a JavaScript example. This means we need to understand what the C++ code *does* and how it relates to JavaScript's execution.

**2. Initial Scan and Keywords:**

The first step is to quickly scan the code for keywords and recognizable patterns. Things that jump out are:

* `#include "src/interpreter/bytecode-array-builder.h"`: This is the core component being tested. The name suggests it's responsible for building bytecode arrays.
* `namespace v8::internal::interpreter`: This clearly indicates the code belongs to V8's interpreter.
* `class BytecodeArrayBuilderTest`: This confirms it's a unit test for `BytecodeArrayBuilder`.
* `TEST_F(...)`:  These are the individual test cases.
* Bytecode names (e.g., `LoadLiteral`, `StoreAccumulatorInRegister`, `JumpIfNull`, `CallProperty`): These are instructions for the V8 interpreter.
* JavaScript-related terms (e.g., `CreateArguments`, `LoadGlobal`, `LoadNamedProperty`, `CallAnyReceiver`, `Construct`, `this`, `typeof`, `instanceof`, `in`, `delete`, `try...catch`, `for...in`, `async function`):  These strongly suggest a connection to JavaScript semantics.

**3. Deeper Dive into Test Cases:**

Next, we need to examine the individual test cases to understand what aspects of `BytecodeArrayBuilder` are being verified. We look for patterns in how the builder is used and what assertions are made.

* **`AllBytecodesGenerated`**: This test seems to systematically generate *all* possible bytecodes. This is crucial for understanding the full capabilities of the builder. We see various bytecode emission methods being called.
* **`FrameSizesLookGood`**: This verifies that the builder correctly calculates the size of the execution frame based on the number of local variables and temporary registers.
* **`RegisterValues`**: This checks the basic functionality of register management.
* **`Parameters`**: This relates to how function parameters are handled.
* **`Constants`**: This checks how the builder manages and deduplicates constants.
* **`ForwardJumps` and `BackwardJumps`**: These test the logic for generating jump instructions with correct offsets, both forward and backward in the bytecode.
* **`SmallSwitch` and `WideSwitch`**: These test the generation of `switch` statement bytecode, ensuring it handles both small and large jump tables.

**4. Identifying Core Functionality:**

From examining the test cases, the core function of `BytecodeArrayBuilder` becomes clear:

* **Building Bytecode:** Its primary responsibility is to generate the sequence of bytecode instructions that the V8 interpreter will execute.
* **Managing Registers:** It allocates and manages registers for storing intermediate values.
* **Handling Constants:** It stores and deduplicates constants used in the code.
* **Generating Control Flow:** It creates bytecode for conditional jumps, loops, and `switch` statements.
* **Representing JavaScript Semantics:**  The names of the bytecodes and the test scenarios directly map to JavaScript language features.

**5. Connecting to JavaScript:**

The presence of JavaScript-related terms in the bytecode names and the test scenarios strongly indicates a direct relationship. The C++ code is testing the *compilation* process from JavaScript code into V8 bytecode. Each bytecode represents a low-level operation needed to execute JavaScript.

**6. Crafting the JavaScript Example:**

Now, the goal is to create a simple JavaScript example that would, when compiled by V8, likely generate some of the bytecodes tested in the C++ file. We want to pick features that are explicitly tested:

* **Variables:**  `let x = 10;` would likely involve `LoadLiteral` and storing to a register.
* **Basic Operations:** `x + 5;` would involve a binary operation bytecode.
* **Function Calls:** `console.log(x);` would involve property access and a function call bytecode.
* **Conditional Logic:** `if (x > 0) { ... }` would involve comparison and jump bytecodes.

The example should be concise and illustrate the connection without being overly complex.

**7. Explaining the Connection:**

The final step is to clearly explain how the C++ code and the JavaScript example relate. Emphasize that the C++ code is *testing the compiler* and that the bytecodes it generates are the internal representation of the JavaScript code. Mentioning the interpreter's role in executing the bytecode completes the picture.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the C++ code is just manipulating bytecode for some internal V8 purpose.
* **Correction:**  The presence of so many JavaScript-specific keywords and test cases directly mirroring JavaScript syntax strongly suggests it's about compiling JavaScript.
* **Initial thought on JS example:** Create a very complex example to cover more bytecodes.
* **Refinement:**  A simpler, more focused example is better for illustrating the core connection clearly. It should highlight the most common and easily understood JavaScript features.
* **Initial explanation:**  Focus heavily on the technical details of bytecode.
* **Refinement:**  Start with a high-level explanation of compilation and interpretation, then introduce bytecode as the intermediary. This makes it more accessible.

By following these steps of scanning, deep diving, identifying core functionality, connecting to the target language, crafting an example, and explaining the relationship, we can effectively analyze the C++ unittest file and provide a helpful and understandable answer.
这个C++源代码文件 `bytecode-array-builder-unittest.cc` 是 V8 JavaScript 引擎的一部分，其主要功能是**测试 `BytecodeArrayBuilder` 类**。`BytecodeArrayBuilder` 的作用是**构建用于执行 JavaScript 代码的字节码数组 (BytecodeArray)**。

更具体地说，这个单元测试文件验证了 `BytecodeArrayBuilder` 能够正确生成各种不同的字节码指令，并且生成的字节码数组的结构（例如，帧大小、常量池）是正确的。

**与 JavaScript 的关系：**

`BytecodeArrayBuilder` 是 V8 引擎将 JavaScript 源代码编译成可执行代码的关键部分。当 V8 编译 JavaScript 代码时，它会经历一个将抽象语法树 (AST) 转换为字节码的过程。 `BytecodeArrayBuilder` 就是负责执行这个转换并生成最终的字节码数组。这个字节码数组随后会被 V8 的解释器 (Ignition) 或即时编译器 (TurboFan) 执行。

**JavaScript 举例说明:**

假设我们有以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  let sum = a + b;
  console.log(sum);
  return sum;
}

add(5, 3);
```

当 V8 编译这段 JavaScript 代码时，`BytecodeArrayBuilder` 可能会生成类似于以下的字节码指令序列（这只是一个简化的示例，实际的字节码会更复杂）：

* **`CreateArguments`**: 为 `add` 函数创建 arguments 对象。
* **`Ldar arg0`**: 将参数 `a` 加载到累加器。
* **`Ldar arg1`**: 将参数 `b` 加载到累加器。
* **`BinaryOperation Add`**: 执行加法操作。
* **`Star local0`**: 将结果存储到局部变量 `sum`。
* **`LoadGlobal [console]`**: 加载全局对象 `console`。
* **`LoadNamedProperty [log]`**: 加载 `console` 对象的 `log` 属性。
* **`Ldar local0`**: 将局部变量 `sum` 加载到累加器。
* **`CallProperty 1`**: 调用 `console.log` 函数，并传递一个参数。
* **`Ldar local0`**: 将局部变量 `sum` 加载到累加器。
* **`Return`**: 返回累加器中的值。
* **`LoadGlobal [add]`**: 加载全局对象 `add` (实际上在函数定义时已经处理)。
* **`LdaSmi 5`**: 加载小整数常量 5。
* **`LdaSmi 3`**: 加载小整数常量 3。
* **`CallUndefinedReceiver 2`**: 调用 `add` 函数，并传递两个参数。

**`bytecode-array-builder-unittest.cc` 的作用就是确保 `BytecodeArrayBuilder` 能够正确生成上述类似的各种字节码指令**，例如：

* `builder.LoadLiteral(Smi::zero())`:  对应 JavaScript 中的常量加载 (例如 `LdaSmi 5`)。
* `builder.BinaryOperation(Token::kAdd, reg, 1)`: 对应 JavaScript 中的加法运算 (`BinaryOperation Add`)。
* `builder.CallProperty(reg, reg_list, 1)`: 对应 JavaScript 中的方法调用 (`CallProperty 1`)。
* `builder.JumpIfNull(&after_loop)`: 对应 JavaScript 中的条件判断和控制流 (`if` 语句等)。
* `builder.CreateClosure(0, 1, static_cast<int>(AllocationType::kYoung))`: 对应 JavaScript 中创建闭包。

**总结:**

`bytecode-array-builder-unittest.cc` 是一个测试文件，用于验证 V8 引擎中负责将 JavaScript 代码编译成字节码的 `BytecodeArrayBuilder` 类的正确性。它通过模拟生成各种字节码指令的场景来确保编译过程的可靠性，这直接关系到 JavaScript 代码的执行效率和正确性。 开发者会编写这样的单元测试来保证 V8 引擎的核心组件能够按照预期工作。

Prompt: 
```
这是目录为v8/test/unittests/interpreter/bytecode-array-builder-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/interpreter/bytecode-array-builder.h"

#include <limits>

#include "src/ast/scopes.h"
#include "src/common/globals.h"
#include "src/init/v8.h"
#include "src/interpreter/bytecode-array-iterator.h"
#include "src/interpreter/bytecode-jump-table.h"
#include "src/interpreter/bytecode-label.h"
#include "src/interpreter/bytecode-register-allocator.h"
#include "src/numbers/hash-seed-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/smi.h"
#include "test/common/flag-utils.h"
#include "test/unittests/interpreter/bytecode-utils.h"
#include "test/unittests/test-utils.h"

namespace v8 {
namespace internal {
namespace interpreter {

class BytecodeArrayBuilderTest : public TestWithIsolateAndZone {
 public:
  BytecodeArrayBuilderTest() = default;
  ~BytecodeArrayBuilderTest() override = default;
};

using ToBooleanMode = BytecodeArrayBuilder::ToBooleanMode;

TEST_F(BytecodeArrayBuilderTest, AllBytecodesGenerated) {
  FlagScope<bool> const_tracking_let(&i::v8_flags.const_tracking_let, true);
  FlagScope<bool> script_context_mutable_heap_number(
      &i::v8_flags.script_context_mutable_heap_number, true);

  FeedbackVectorSpec feedback_spec(zone());
  BytecodeArrayBuilder builder(zone(), 1, 131, &feedback_spec);
  Factory* factory = isolate()->factory();
  AstValueFactory ast_factory(zone(), isolate()->ast_string_constants(),
                              HashSeed(isolate()));
  DeclarationScope scope(zone(), &ast_factory);

  Handle<ScopeInfo> scope_info =
      factory->NewScopeInfo(ScopeInfo::kVariablePartIndex);
  int flags = ScopeInfo::IsEmptyBit::encode(true);
  scope_info->set_flags(flags, kRelaxedStore);
  scope_info->set_context_local_count(0);
  scope_info->set_parameter_count(0);
  scope_info->set_position_info_start(0);
  scope_info->set_position_info_end(0);
  scope.SetScriptScopeInfo(scope_info);

  CHECK_EQ(builder.locals_count(), 131);
  CHECK_EQ(builder.fixed_register_count(), 131);

  Register reg(0);
  Register other(reg.index() + 1);
  Register wide(128);
  RegisterList empty;
  RegisterList single = BytecodeUtils::NewRegisterList(0, 1);
  RegisterList pair = BytecodeUtils::NewRegisterList(0, 2);
  RegisterList triple = BytecodeUtils::NewRegisterList(0, 3);
  RegisterList reg_list = BytecodeUtils::NewRegisterList(0, 10);

  // Emit argument creation operations.
  builder.CreateArguments(CreateArgumentsType::kMappedArguments)
      .CreateArguments(CreateArgumentsType::kUnmappedArguments)
      .CreateArguments(CreateArgumentsType::kRestParameter);

  // Emit constant loads.
  builder.LoadLiteral(Smi::zero())
      .StoreAccumulatorInRegister(reg)
      .LoadLiteral(Smi::FromInt(8))
      .CompareOperation(Token::kEq, reg,
                        1)  // Prevent peephole optimization
                            // LdaSmi, Star -> LdrSmi.
      .StoreAccumulatorInRegister(reg)
      .LoadLiteral(Smi::FromInt(10000000))
      .StoreAccumulatorInRegister(reg)
      .LoadLiteral(ast_factory.GetOneByteString("A constant"))
      .StoreAccumulatorInRegister(reg)
      .LoadUndefined()
      .StoreAccumulatorInRegister(reg)
      .LoadNull()
      .StoreAccumulatorInRegister(reg)
      .LoadTheHole()
      .StoreAccumulatorInRegister(reg)
      .LoadTrue()
      .StoreAccumulatorInRegister(reg)
      .LoadFalse()
      .StoreAccumulatorInRegister(wide);

  // Emit Ldar and Star taking care to foil the register optimizer.
  builder.LoadAccumulatorWithRegister(other)
      .BinaryOperation(Token::kAdd, reg, 1)
      .StoreAccumulatorInRegister(reg)
      .LoadNull();

  // The above had a lot of Star0, but we must also emit the rest of
  // the short-star codes.
  for (int i = 1; i < 16; ++i) {
    builder.StoreAccumulatorInRegister(Register(i));
  }

  // Emit register-register transfer.
  builder.MoveRegister(reg, other);
  builder.MoveRegister(reg, wide);

  FeedbackSlot load_global_slot =
      feedback_spec.AddLoadGlobalICSlot(TypeofMode::kNotInside);
  FeedbackSlot load_global_typeof_slot =
      feedback_spec.AddLoadGlobalICSlot(TypeofMode::kInside);
  FeedbackSlot sloppy_store_global_slot =
      feedback_spec.AddStoreGlobalICSlot(LanguageMode::kSloppy);
  FeedbackSlot load_slot = feedback_spec.AddLoadICSlot();
  FeedbackSlot call_slot = feedback_spec.AddCallICSlot();
  FeedbackSlot keyed_load_slot = feedback_spec.AddKeyedLoadICSlot();
  FeedbackSlot sloppy_store_slot =
      feedback_spec.AddStoreICSlot(LanguageMode::kSloppy);
  FeedbackSlot strict_store_slot =
      feedback_spec.AddStoreICSlot(LanguageMode::kStrict);
  FeedbackSlot sloppy_keyed_store_slot =
      feedback_spec.AddKeyedStoreICSlot(LanguageMode::kSloppy);
  FeedbackSlot strict_keyed_store_slot =
      feedback_spec.AddKeyedStoreICSlot(LanguageMode::kStrict);
  FeedbackSlot define_named_own_slot = feedback_spec.AddDefineNamedOwnICSlot();
  FeedbackSlot store_array_element_slot =
      feedback_spec.AddStoreInArrayLiteralICSlot();

  // Emit global load / store operations.
  const AstRawString* name = ast_factory.GetOneByteString("var_name");
  builder.LoadGlobal(name, load_global_slot.ToInt(), TypeofMode::kNotInside)
      .LoadGlobal(name, load_global_typeof_slot.ToInt(), TypeofMode::kInside)
      .StoreGlobal(name, sloppy_store_global_slot.ToInt());

  // Emit context operations.
  Variable var1(&scope, name, VariableMode::kVar, VariableKind::NORMAL_VARIABLE,
                InitializationFlag::kCreatedInitialized);
  var1.AllocateTo(VariableLocation::CONTEXT, 1);
  Variable var2(&scope, name, VariableMode::kVar, VariableKind::NORMAL_VARIABLE,
                InitializationFlag::kCreatedInitialized);
  var2.AllocateTo(VariableLocation::CONTEXT, 1);
  Variable var3(&scope, name, VariableMode::kVar, VariableKind::NORMAL_VARIABLE,
                InitializationFlag::kCreatedInitialized);
  var3.AllocateTo(VariableLocation::CONTEXT, 3);

  // Emit context operations which operate on the script context.
  builder.PushContext(reg)
      .PopContext(reg)
      .LoadContextSlot(reg, &var1, 0, BytecodeArrayBuilder::kMutableSlot)
      .StoreContextSlot(reg, &var1, 0)
      .LoadContextSlot(reg, &var2, 0, BytecodeArrayBuilder::kImmutableSlot)
      .StoreContextSlot(reg, &var3, 0);

  // Emit context operations which operate on the local context.
  builder
      .LoadContextSlot(Register::current_context(), &var1, 0,
                       BytecodeArrayBuilder::kMutableSlot)
      .StoreContextSlot(Register::current_context(), &var1, 0)
      .LoadContextSlot(Register::current_context(), &var2, 0,
                       BytecodeArrayBuilder::kImmutableSlot)
      .StoreContextSlot(Register::current_context(), &var3, 0)
      .LoadContextSlot(Register::current_context(), &var1, 0,
                       BytecodeArrayBuilder::kMutableSlot);

  // Emit context operations.
  DeclarationScope fun_scope(zone(), ScopeType::FUNCTION_SCOPE, &ast_factory,
                             scope_info);
  Variable fun_var1(&fun_scope, name, VariableMode::kVar,
                    VariableKind::NORMAL_VARIABLE,
                    InitializationFlag::kCreatedInitialized);
  fun_var1.AllocateTo(VariableLocation::CONTEXT, 1);
  Variable fun_var2(&fun_scope, name, VariableMode::kVar,
                    VariableKind::NORMAL_VARIABLE,
                    InitializationFlag::kCreatedInitialized);
  fun_var2.AllocateTo(VariableLocation::CONTEXT, 1);
  Variable fun_var3(&fun_scope, name, VariableMode::kVar,
                    VariableKind::NORMAL_VARIABLE,
                    InitializationFlag::kCreatedInitialized);
  fun_var3.AllocateTo(VariableLocation::CONTEXT, 3);
  builder.CreateFunctionContext(&fun_scope, 3)
      .StoreAccumulatorInRegister(reg)
      .LoadContextSlot(reg, &fun_var1, 0, BytecodeArrayBuilder::kMutableSlot)
      .StoreContextSlot(reg, &fun_var1, 0)
      .LoadContextSlot(reg, &fun_var2, 0, BytecodeArrayBuilder::kImmutableSlot)
      .StoreContextSlot(reg, &fun_var3, 0)
      .PushContext(reg)
      .LoadContextSlot(Register::current_context(), &fun_var1, 0,
                       BytecodeArrayBuilder::kMutableSlot)
      .StoreContextSlot(Register::current_context(), &fun_var1, 0)
      .LoadContextSlot(Register::current_context(), &fun_var2, 0,
                       BytecodeArrayBuilder::kImmutableSlot)
      .StoreContextSlot(Register::current_context(), &fun_var3, 0)
      .PopContext(reg);

  // Emit load / store property operations.
  builder.LoadNamedProperty(reg, name, load_slot.ToInt())
      .LoadNamedPropertyFromSuper(reg, name, load_slot.ToInt())
      .LoadKeyedProperty(reg, keyed_load_slot.ToInt())
      .LoadEnumeratedKeyedProperty(reg, reg, reg, keyed_load_slot.ToInt())
      .SetNamedProperty(reg, name, sloppy_store_slot.ToInt(),
                        LanguageMode::kSloppy)
      .SetKeyedProperty(reg, reg, sloppy_keyed_store_slot.ToInt(),
                        LanguageMode::kSloppy)
      .SetNamedProperty(reg, name, strict_store_slot.ToInt(),
                        LanguageMode::kStrict)
      .SetKeyedProperty(reg, reg, strict_keyed_store_slot.ToInt(),
                        LanguageMode::kStrict)
      .DefineNamedOwnProperty(reg, name, define_named_own_slot.ToInt())
      .DefineKeyedOwnProperty(reg, reg, DefineKeyedOwnPropertyFlag::kNoFlags,
                              define_named_own_slot.ToInt())
      .StoreInArrayLiteral(reg, reg, store_array_element_slot.ToInt());

  // Emit Iterator-protocol operations
  builder.GetIterator(reg, load_slot.ToInt(), call_slot.ToInt());

  // Emit load / store lookup slots.
  builder.LoadLookupSlot(name, TypeofMode::kNotInside)
      .LoadLookupSlot(name, TypeofMode::kInside)
      .StoreLookupSlot(name, LanguageMode::kSloppy, LookupHoistingMode::kNormal)
      .StoreLookupSlot(name, LanguageMode::kSloppy,
                       LookupHoistingMode::kLegacySloppy)
      .StoreLookupSlot(name, LanguageMode::kStrict,
                       LookupHoistingMode::kNormal);

  // Emit load / store lookup slots with context fast paths.
  builder
      .LoadLookupContextSlot(name, TypeofMode::kNotInside,
                             ContextKind::kDefault, 1, 0)
      .LoadLookupContextSlot(name, TypeofMode::kInside, ContextKind::kDefault,
                             1, 0)
      .LoadLookupContextSlot(name, TypeofMode::kNotInside,
                             ContextKind::kScriptContext, 1, 0)
      .LoadLookupContextSlot(name, TypeofMode::kInside,
                             ContextKind::kScriptContext, 1, 0);

  // Emit load / store lookup slots with global fast paths.
  builder.LoadLookupGlobalSlot(name, TypeofMode::kNotInside, 1, 0)
      .LoadLookupGlobalSlot(name, TypeofMode::kInside, 1, 0);

  // Emit closure operations.
  builder.CreateClosure(0, 1, static_cast<int>(AllocationType::kYoung));

  // Emit create context operation.
  builder.CreateBlockContext(&scope);
  builder.CreateCatchContext(reg, &scope);
  builder.CreateFunctionContext(&scope, 1);
  builder.CreateEvalContext(&scope, 1);
  builder.CreateWithContext(reg, &scope);

  // Emit literal creation operations.
  builder.CreateRegExpLiteral(ast_factory.GetOneByteString("a"), 0, 0);
  builder.CreateArrayLiteral(0, 0, 0);
  builder.CreateObjectLiteral(0, 0, 0);

  // Emit tagged template operations.
  builder.GetTemplateObject(0, 0);

  // Call operations.
  builder.CallAnyReceiver(reg, reg_list, 1)
      .CallProperty(reg, reg_list, 1)
      .CallProperty(reg, single, 1)
      .CallProperty(reg, pair, 1)
      .CallProperty(reg, triple, 1)
      .CallUndefinedReceiver(reg, reg_list, 1)
      .CallUndefinedReceiver(reg, empty, 1)
      .CallUndefinedReceiver(reg, single, 1)
      .CallUndefinedReceiver(reg, pair, 1)
      .CallRuntime(Runtime::kIsArray, reg)
      .CallRuntimeForPair(Runtime::kLoadLookupSlotForCall, reg_list, pair)
      .CallJSRuntime(Context::PROMISE_THEN_INDEX, reg_list)
      .CallWithSpread(reg, reg_list, 1);

  // Emit binary operator invocations.
  builder.BinaryOperation(Token::kAdd, reg, 1)
      .BinaryOperation(Token::kSub, reg, 2)
      .BinaryOperation(Token::kMul, reg, 3)
      .BinaryOperation(Token::kDiv, reg, 4)
      .BinaryOperation(Token::kMod, reg, 5)
      .BinaryOperation(Token::kExp, reg, 6);

  // Emit bitwise operator invocations
  builder.BinaryOperation(Token::kBitOr, reg, 6)
      .BinaryOperation(Token::kBitXor, reg, 7)
      .BinaryOperation(Token::kBitAnd, reg, 8);

  // Emit shift operator invocations
  builder.BinaryOperation(Token::kShl, reg, 9)
      .BinaryOperation(Token::kSar, reg, 10)
      .BinaryOperation(Token::kShr, reg, 11);

  // Emit Smi binary operations.
  builder.BinaryOperationSmiLiteral(Token::kAdd, Smi::FromInt(42), 2)
      .BinaryOperationSmiLiteral(Token::kSub, Smi::FromInt(42), 2)
      .BinaryOperationSmiLiteral(Token::kMul, Smi::FromInt(42), 2)
      .BinaryOperationSmiLiteral(Token::kDiv, Smi::FromInt(42), 2)
      .BinaryOperationSmiLiteral(Token::kMod, Smi::FromInt(42), 2)
      .BinaryOperationSmiLiteral(Token::kExp, Smi::FromInt(42), 2)
      .BinaryOperationSmiLiteral(Token::kBitOr, Smi::FromInt(42), 2)
      .BinaryOperationSmiLiteral(Token::kBitXor, Smi::FromInt(42), 2)
      .BinaryOperationSmiLiteral(Token::kBitAnd, Smi::FromInt(42), 2)
      .BinaryOperationSmiLiteral(Token::kShl, Smi::FromInt(42), 2)
      .BinaryOperationSmiLiteral(Token::kSar, Smi::FromInt(42), 2)
      .BinaryOperationSmiLiteral(Token::kShr, Smi::FromInt(42), 2);

  // Emit unary and count operator invocations.
  builder.UnaryOperation(Token::kInc, 1)
      .UnaryOperation(Token::kDec, 1)
      .UnaryOperation(Token::kAdd, 1)
      .UnaryOperation(Token::kSub, 1)
      .UnaryOperation(Token::kBitNot, 1);

  // Emit unary operator invocations.
  builder.LogicalNot(ToBooleanMode::kConvertToBoolean)
      .LogicalNot(ToBooleanMode::kAlreadyBoolean)
      .TypeOf(1);

  // Emit delete
  builder.Delete(reg, LanguageMode::kSloppy).Delete(reg, LanguageMode::kStrict);

  // Emit construct.
  builder.Construct(reg, reg_list, 1)
      .ConstructWithSpread(reg, reg_list, 1)
      .ConstructForwardAllArgs(reg, 1);

  // Emit test operator invocations.
  builder.CompareOperation(Token::kEq, reg, 1)
      .CompareOperation(Token::kEqStrict, reg, 2)
      .CompareOperation(Token::kLessThan, reg, 3)
      .CompareOperation(Token::kGreaterThan, reg, 4)
      .CompareOperation(Token::kLessThanEq, reg, 5)
      .CompareOperation(Token::kGreaterThanEq, reg, 6)
      .CompareTypeOf(TestTypeOfFlags::LiteralFlag::kNumber)
      .CompareOperation(Token::kInstanceOf, reg, 7)
      .CompareOperation(Token::kIn, reg, 8)
      .CompareReference(reg)
      .CompareUndetectable()
      .CompareUndefined()
      .CompareNull();

  // Emit conversion operator invocations.
  builder.ToNumber(1).ToNumeric(1).ToObject(reg).ToName().ToString().ToBoolean(
      ToBooleanMode::kConvertToBoolean);

  // Emit GetSuperConstructor.
  builder.GetSuperConstructor(reg);

  // Constructor check for GetSuperConstructor.
  builder.ThrowIfNotSuperConstructor(reg);

  // Hole checks.
  builder.ThrowReferenceErrorIfHole(name)
      .ThrowSuperAlreadyCalledIfNotHole()
      .ThrowSuperNotCalledIfHole();

  // Short jumps with Imm8 operands
  {
    BytecodeLoopHeader loop_header;
    BytecodeLabel after_jump1, after_jump2, after_jump3, after_jump4,
        after_jump5, after_jump6, after_jump7, after_jump8, after_jump9,
        after_jump10, after_jump11, after_jump12, after_loop;
    builder.JumpIfNull(&after_loop)
        .Bind(&loop_header)
        .Jump(&after_jump1)
        .Bind(&after_jump1)
        .JumpIfNull(&after_jump2)
        .Bind(&after_jump2)
        .JumpIfNotNull(&after_jump3)
        .Bind(&after_jump3)
        .JumpIfUndefined(&after_jump4)
        .Bind(&after_jump4)
        .JumpIfNotUndefined(&after_jump5)
        .Bind(&after_jump5)
        .JumpIfUndefinedOrNull(&after_jump6)
        .Bind(&after_jump6)
        .JumpIfJSReceiver(&after_jump7)
        .Bind(&after_jump7)
        .JumpIfForInDone(&after_jump8, reg, reg)
        .Bind(&after_jump8)
        .JumpIfTrue(ToBooleanMode::kConvertToBoolean, &after_jump9)
        .Bind(&after_jump9)
        .JumpIfTrue(ToBooleanMode::kAlreadyBoolean, &after_jump10)
        .Bind(&after_jump10)
        .JumpIfFalse(ToBooleanMode::kConvertToBoolean, &after_jump11)
        .Bind(&after_jump11)
        .JumpIfFalse(ToBooleanMode::kAlreadyBoolean, &after_jump12)
        .Bind(&after_jump12)
        .JumpLoop(&loop_header, 0, 0, 0)
        .Bind(&after_loop);
  }

  BytecodeLabel end[12];
  {
    // Longer jumps with constant operands
    BytecodeLabel after_jump;
    builder.JumpIfNull(&after_jump)
        .Jump(&end[0])
        .Bind(&after_jump)
        .JumpIfTrue(ToBooleanMode::kConvertToBoolean, &end[1])
        .JumpIfTrue(ToBooleanMode::kAlreadyBoolean, &end[2])
        .JumpIfFalse(ToBooleanMode::kConvertToBoolean, &end[3])
        .JumpIfFalse(ToBooleanMode::kAlreadyBoolean, &end[4])
        .JumpIfNull(&end[5])
        .JumpIfNotNull(&end[6])
        .JumpIfUndefined(&end[7])
        .JumpIfNotUndefined(&end[8])
        .JumpIfUndefinedOrNull(&end[9])
        .LoadLiteral(ast_factory.prototype_string())
        .JumpIfJSReceiver(&end[10])
        .JumpIfForInDone(&end[11], reg, reg);
  }

  // Emit Smi table switch bytecode.
  BytecodeJumpTable* jump_table = builder.AllocateJumpTable(1, 0);
  builder.SwitchOnSmiNoFeedback(jump_table).Bind(jump_table, 0);

  // Emit set pending message bytecode.
  builder.SetPendingMessage();

  // Emit throw and re-throw in it's own basic block so that the rest of the
  // code isn't omitted due to being dead.
  BytecodeLabel after_throw, after_rethrow;
  builder.JumpIfNull(&after_throw).Throw().Bind(&after_throw);
  builder.JumpIfNull(&after_rethrow).ReThrow().Bind(&after_rethrow);

  builder.ForInEnumerate(reg)
      .ForInPrepare(triple, 1)
      .ForInNext(reg, reg, pair, 1)
      .ForInStep(reg);

  // Wide constant pool loads
  for (int i = 0; i < 256; i++) {
    // Emit junk in constant pool to force wide constant pool index.
    builder.LoadLiteral(2.5321 + i);
  }
  builder.LoadLiteral(Smi::FromInt(20000000));
  const AstRawString* wide_name = ast_factory.GetOneByteString("var_wide_name");

  builder.DefineKeyedOwnPropertyInLiteral(
      reg, reg, DefineKeyedOwnPropertyInLiteralFlag::kNoFlags, 0);

  // Emit wide context operations.
  Variable var(&scope, name, VariableMode::kVar, VariableKind::NORMAL_VARIABLE,
               InitializationFlag::kCreatedInitialized);
  var.AllocateTo(VariableLocation::CONTEXT, 1024);

  builder.LoadContextSlot(reg, &var, 0, BytecodeArrayBuilder::kMutableSlot)
      .StoreContextSlot(reg, &var, 0);

  // Emit wide load / store lookup slots.
  builder.LoadLookupSlot(wide_name, TypeofMode::kNotInside)
      .LoadLookupSlot(wide_name, TypeofMode::kInside)
      .StoreLookupSlot(wide_name, LanguageMode::kSloppy,
                       LookupHoistingMode::kNormal)
      .StoreLookupSlot(wide_name, LanguageMode::kSloppy,
                       LookupHoistingMode::kLegacySloppy)
      .StoreLookupSlot(wide_name, LanguageMode::kStrict,
                       LookupHoistingMode::kNormal);

  // CreateClosureWide
  builder.CreateClosure(1000, 321, static_cast<int>(AllocationType::kYoung));

  // Emit wide variant of literal creation operations.
  builder
      .CreateRegExpLiteral(ast_factory.GetOneByteString("wide_literal"), 0, 0)
      .CreateArrayLiteral(0, 0, 0)
      .CreateEmptyArrayLiteral(0)
      .CreateArrayFromIterable()
      .CreateObjectLiteral(0, 0, 0)
      .CreateEmptyObjectLiteral()
      .CloneObject(reg, 0, 0);

  // Emit load and store operations for module variables.
  builder.LoadModuleVariable(-1, 42)
      .LoadModuleVariable(0, 42)
      .LoadModuleVariable(1, 42)
      .StoreModuleVariable(-1, 42)
      .StoreModuleVariable(0, 42)
      .StoreModuleVariable(1, 42);

  // Emit generator operations.
  {
    // We have to skip over suspend because it returns and marks the remaining
    // bytecode dead.
    BytecodeLabel after_suspend;
    builder.JumpIfTrue(ToBooleanMode::kAlreadyBoolean, &after_suspend)
        .SuspendGenerator(reg, reg_list, 0)
        .Bind(&after_suspend)
        .ResumeGenerator(reg, reg_list);
  }
  BytecodeJumpTable* gen_jump_table = builder.AllocateJumpTable(1, 0);
  builder.SwitchOnGeneratorState(reg, gen_jump_table).Bind(gen_jump_table, 0);

  // Intrinsics handled by the interpreter.
  builder.CallRuntime(Runtime::kInlineAsyncFunctionReject, reg_list);

  // Emit debugger bytecode.
  builder.Debugger();

  // Emit abort bytecode.
  BytecodeLabel after_abort;
  builder.JumpIfNull(&after_abort)
      .Abort(AbortReason::kOperandIsASmi)
      .Bind(&after_abort);

  // Insert dummy ops to force longer jumps.
  for (int i = 0; i < 256; i++) {
    builder.Debugger();
  }

  // Emit block counter increments.
  builder.IncBlockCounter(0);

  // Bind labels for long jumps at the very end.
  for (size_t i = 0; i < arraysize(end); i++) {
    builder.Bind(&end[i]);
  }

  // Return must be the last instruction.
  builder.Return();

  // Generate BytecodeArray.
  ast_factory.Internalize(isolate());
  DirectHandle<BytecodeArray> the_array = builder.ToBytecodeArray(isolate());
  CHECK_EQ(the_array->frame_size(),
           builder.total_register_count() * kSystemPointerSize);

  // Build scorecard of bytecodes encountered in the BytecodeArray.
  std::vector<int> scorecard(Bytecodes::ToByte(Bytecode::kLast) + 1);

  Bytecode final_bytecode = Bytecode::kLdaZero;
  int i = 0;
  while (i < the_array->length()) {
    uint8_t code = the_array->get(i);
    scorecard[code] += 1;
    final_bytecode = Bytecodes::FromByte(code);
    OperandScale operand_scale = OperandScale::kSingle;
    int prefix_offset = 0;
    if (Bytecodes::IsPrefixScalingBytecode(final_bytecode)) {
      operand_scale = Bytecodes::PrefixBytecodeToOperandScale(final_bytecode);
      prefix_offset = 1;
      code = the_array->get(i + 1);
      scorecard[code] += 1;
      final_bytecode = Bytecodes::FromByte(code);
    }
    i += prefix_offset + Bytecodes::Size(final_bytecode, operand_scale);
  }

  // Insert entry for illegal bytecode as this is never willingly emitted.
  scorecard[Bytecodes::ToByte(Bytecode::kIllegal)] = 1;

  // This bytecode is too inconvenient to test manually.
  scorecard[Bytecodes::ToByte(
      Bytecode::kFindNonDefaultConstructorOrConstruct)] = 1;

  // Check return occurs at the end and only once in the BytecodeArray.
  CHECK_EQ(final_bytecode, Bytecode::kReturn);
  CHECK_EQ(scorecard[Bytecodes::ToByte(final_bytecode)], 1);

#define CHECK_BYTECODE_PRESENT(Name, ...)                                \
  /* Check Bytecode is marked in scorecard, unless it's a debug break */ \
  if (!Bytecodes::IsDebugBreak(Bytecode::k##Name)) {                     \
    EXPECT_GE(scorecard[Bytecodes::ToByte(Bytecode::k##Name)], 1);       \
  }
  BYTECODE_LIST(CHECK_BYTECODE_PRESENT, CHECK_BYTECODE_PRESENT)
#undef CHECK_BYTECODE_PRESENT
}

TEST_F(BytecodeArrayBuilderTest, FrameSizesLookGood) {
  for (int locals = 0; locals < 5; locals++) {
    for (int temps = 0; temps < 3; temps++) {
      BytecodeArrayBuilder builder(zone(), 1, locals);
      BytecodeRegisterAllocator* allocator(builder.register_allocator());
      for (int i = 0; i < locals; i++) {
        builder.LoadLiteral(Smi::zero());
        builder.StoreAccumulatorInRegister(Register(i));
      }
      for (int i = 0; i < temps; i++) {
        Register temp = allocator->NewRegister();
        builder.LoadLiteral(Smi::zero());
        builder.StoreAccumulatorInRegister(temp);
        // Ensure temporaries are used so not optimized away by the
        // register optimizer.
        builder.ToName().StoreAccumulatorInRegister(temp);
      }
      builder.Return();

      DirectHandle<BytecodeArray> the_array =
          builder.ToBytecodeArray(isolate());
      int total_registers = locals + temps;
      CHECK_EQ(the_array->frame_size(), total_registers * kSystemPointerSize);
    }
  }
}

TEST_F(BytecodeArrayBuilderTest, RegisterValues) {
  int index = 1;

  Register the_register(index);
  CHECK_EQ(the_register.index(), index);

  int actual_operand = the_register.ToOperand();
  int actual_index = Register::FromOperand(actual_operand).index();
  CHECK_EQ(actual_index, index);
}

TEST_F(BytecodeArrayBuilderTest, Parameters) {
  BytecodeArrayBuilder builder(zone(), 10, 0);

  Register receiver(builder.Receiver());
  Register param8(builder.Parameter(8));
  CHECK_EQ(receiver.index() - param8.index(), 9);
}

TEST_F(BytecodeArrayBuilderTest, Constants) {
  BytecodeArrayBuilder builder(zone(), 1, 0);
  AstValueFactory ast_factory(zone(), isolate()->ast_string_constants(),
                              HashSeed(isolate()));

  double heap_num_1 = 3.14;
  double heap_num_2 = 5.2;
  double nan = std::numeric_limits<double>::quiet_NaN();
  const AstRawString* string = ast_factory.GetOneByteString("foo");
  const AstRawString* string_copy = ast_factory.GetOneByteString("foo");

  builder.LoadLiteral(heap_num_1)
      .LoadLiteral(heap_num_2)
      .LoadLiteral(string)
      .LoadLiteral(heap_num_1)
      .LoadLiteral(heap_num_1)
      .LoadLiteral(nan)
      .LoadLiteral(string_copy)
      .LoadLiteral(heap_num_2)
      .LoadLiteral(nan)
      .Return();

  ast_factory.Internalize(isolate());
  DirectHandle<BytecodeArray> array = builder.ToBytecodeArray(isolate());
  // Should only have one entry for each identical constant.
  EXPECT_EQ(4, array->constant_pool()->length());
}

TEST_F(BytecodeArrayBuilderTest, ForwardJumps) {
  static const int kFarJumpDistance = 256 + 20;

  BytecodeArrayBuilder builder(zone(), 1, 1);

  Register reg(0);
  BytecodeLabel far0, far1, far2, far3, far4;
  BytecodeLabel near0, near1, near2, near3, near4;
  BytecodeLabel after_jump_near0, after_jump_far0;

  builder.JumpIfNull(&after_jump_near0)
      .Jump(&near0)
      .Bind(&after_jump_near0)
      .CompareOperation(Token::kEq, reg, 1)
      .JumpIfTrue(ToBooleanMode::kAlreadyBoolean, &near1)
      .CompareOperation(Token::kEq, reg, 2)
      .JumpIfFalse(ToBooleanMode::kAlreadyBoolean, &near2)
      .BinaryOperation(Token::kAdd, reg, 1)
      .JumpIfTrue(ToBooleanMode::kConvertToBoolean, &near3)
      .BinaryOperation(Token::kAdd, reg, 2)
      .JumpIfFalse(ToBooleanMode::kConvertToBoolean, &near4)
      .Bind(&near0)
      .Bind(&near1)
      .Bind(&near2)
      .Bind(&near3)
      .Bind(&near4)
      .JumpIfNull(&after_jump_far0)
      .Jump(&far0)
      .Bind(&after_jump_far0)
      .CompareOperation(Token::kEq, reg, 3)
      .JumpIfTrue(ToBooleanMode::kAlreadyBoolean, &far1)
      .CompareOperation(Token::kEq, reg, 4)
      .JumpIfFalse(ToBooleanMode::kAlreadyBoolean, &far2)
      .BinaryOperation(Token::kAdd, reg, 3)
      .JumpIfTrue(ToBooleanMode::kConvertToBoolean, &far3)
      .BinaryOperation(Token::kAdd, reg, 4)
      .JumpIfFalse(ToBooleanMode::kConvertToBoolean, &far4);
  for (int i = 0; i < kFarJumpDistance - 22; i++) {
    builder.Debugger();
  }
  builder.Bind(&far0).Bind(&far1).Bind(&far2).Bind(&far3).Bind(&far4);
  builder.Return();

  Handle<BytecodeArray> array = builder.ToBytecodeArray(isolate());
  DCHECK_EQ(array->length(), 48 + kFarJumpDistance - 22 + 1);

  BytecodeArrayIterator iterator(array);

  // Ignore JumpIfNull operation.
  iterator.Advance();

  CHECK_EQ(iterator.current_bytecode(), Bytecode::kJump);
  CHECK_EQ(iterator.GetUnsignedImmediateOperand(0), 22);
  iterator.Advance();

  // Ignore compare operation.
  iterator.Advance();

  CHECK_EQ(iterator.current_bytecode(), Bytecode::kJumpIfTrue);
  CHECK_EQ(iterator.GetUnsignedImmediateOperand(0), 17);
  iterator.Advance();

  // Ignore compare operation.
  iterator.Advance();

  CHECK_EQ(iterator.current_bytecode(), Bytecode::kJumpIfFalse);
  CHECK_EQ(iterator.GetUnsignedImmediateOperand(0), 12);
  iterator.Advance();

  // Ignore add operation.
  iterator.Advance();

  CHECK_EQ(iterator.current_bytecode(), Bytecode::kJumpIfToBooleanTrue);
  CHECK_EQ(iterator.GetUnsignedImmediateOperand(0), 7);
  iterator.Advance();

  // Ignore add operation.
  iterator.Advance();

  CHECK_EQ(iterator.current_bytecode(), Bytecode::kJumpIfToBooleanFalse);
  CHECK_EQ(iterator.GetUnsignedImmediateOperand(0), 2);
  iterator.Advance();

  // Ignore JumpIfNull operation.
  iterator.Advance();

  CHECK_EQ(iterator.current_bytecode(), Bytecode::kJumpConstant);
  CHECK_EQ(*(iterator.GetConstantForIndexOperand(0, isolate())),
           Smi::FromInt(kFarJumpDistance));
  iterator.Advance();

  // Ignore compare operation.
  iterator.Advance();

  CHECK_EQ(iterator.current_bytecode(), Bytecode::kJumpIfTrueConstant);
  CHECK_EQ(*(iterator.GetConstantForIndexOperand(0, isolate())),
           Smi::FromInt(kFarJumpDistance - 5));
  iterator.Advance();

  // Ignore compare operation.
  iterator.Advance();

  CHECK_EQ(iterator.current_bytecode(), Bytecode::kJumpIfFalseConstant);
  CHECK_EQ(*(iterator.GetConstantForIndexOperand(0, isolate())),
           Smi::FromInt(kFarJumpDistance - 10));
  iterator.Advance();

  // Ignore add operation.
  iterator.Advance();

  CHECK_EQ(iterator.current_bytecode(), Bytecode::kJumpIfToBooleanTrueConstant);
  CHECK_EQ(*(iterator.GetConstantForIndexOperand(0, isolate())),
           Smi::FromInt(kFarJumpDistance - 15));
  iterator.Advance();

  // Ignore add operation.
  iterator.Advance();

  CHECK_EQ(iterator.current_bytecode(),
           Bytecode::kJumpIfToBooleanFalseConstant);
  CHECK_EQ(*(iterator.GetConstantForIndexOperand(0, isolate())),
           Smi::FromInt(kFarJumpDistance - 20));
  iterator.Advance();
}

TEST_F(BytecodeArrayBuilderTest, BackwardJumps) {
  BytecodeArrayBuilder builder(zone(), 1, 1);

  BytecodeLabel end;
  builder.JumpIfNull(&end);

  BytecodeLabel after_loop;
  // Conditional jump to force the code after the JumpLoop to be live.
  // Technically this jump is illegal because it's jumping into the middle of
  // the subsequent loops, but that's ok for this unit test.
  BytecodeLoopHeader loop_header;
  builder.JumpIfNull(&after_loop)
      .Bind(&loop_header)
      .JumpLoop(&loop_header, 0, 0, 0)
      .Bind(&after_loop);
  for (int i = 0; i < 42; i++) {
    BytecodeLabel also_after_loop;
    // Conditional jump to force the code after the JumpLoop to be live.
    builder.JumpIfNull(&also_after_loop)
        .JumpLoop(&loop_header, 0, 0, 0)
        .Bind(&also_after_loop);
  }

  // Add padding to force wide backwards jumps.
  for (int i = 0; i < 256; i++) {
    builder.Debugger();
  }

  builder.JumpLoop(&loop_header, 0, 0, 0);
  builder.Bind(&end);
  builder.Return();

  Handle<BytecodeArray> array = builder.ToBytecodeArray(isolate());
  BytecodeArrayIterator iterator(array);
  // Ignore the JumpIfNull to the end
  iterator.Advance();
  // Ignore the JumpIfNull to after the first JumpLoop
  iterator.Advance();
  CHECK_EQ(iterator.current_bytecode(), Bytecode::kJumpLoop);
  CHECK_EQ(iterator.GetUnsignedImmediateOperand(0), 0);
  iterator.Advance();
  for (unsigned i = 0; i < 42; i++) {
    // Ignore the JumpIfNull to after the JumpLoop
    iterator.Advance();

    CHECK_EQ(iterator.current_bytecode(), Bytecode::kJumpLoop);
    CHECK_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
    // offset of 6 (because kJumpLoop takes three immediate operands and
    // JumpIfNull takes 1)
    CHECK_EQ(Bytecodes::NumberOfOperands(Bytecode::kJumpLoop), 3);
    CHECK_EQ(iterator.GetUnsignedImmediateOperand(0), i * 6 + 6);
    iterator.Advance();
  }
  // Check padding to force wide backwards jumps.
  for (int i = 0; i < 256; i++) {
    CHECK_EQ(iterator.current_bytecode(), Bytecode::kDebugger);
    iterator.Advance();
  }
  CHECK_EQ(iterator.current_bytecode(), Bytecode::kJumpLoop);
  CHECK_EQ(iterator.current_operand_scale(), OperandScale::kDouble);
  CHECK_EQ(iterator.GetUnsignedImmediateOperand(0), 42 * 6 + 1 + 256 + 4);
  iterator.Advance();
  CHECK_EQ(iterator.current_bytecode(), Bytecode::kReturn);
  iterator.Advance();
  CHECK(iterator.done());
}

TEST_F(BytecodeArrayBuilderTest, SmallSwitch) {
  BytecodeArrayBuilder builder(zone(), 1, 1);

  // Small jump table that fits into the single-size constant pool
  int small_jump_table_size = 5;
  int small_jump_table_base = -2;
  BytecodeJumpTable* small_jump_table =
      builder.AllocateJumpTable(small_jump_table_size, small_jump_table_base);

  builder.LoadLiteral(Smi::FromInt(7)).SwitchOnSmiNoFeedback(small_jump_table);
  for (int i = 0; i < small_jump_table_size; i++) {
    builder.Bind(small_jump_table, small_jump_table_base + i).Debugger();
  }
  builder.Return();

  Handle<BytecodeArray> array = builder.ToBytecodeArray(isolate());
  BytecodeArrayIterator iterator(array);

  CHECK_EQ(iterator.current_bytecode(), Bytecode::kLdaSmi);
  iterator.Advance();

  CHECK_EQ(iterator.current_bytecode(), Bytecode::kSwitchOnSmiNoFeedback);
  CHECK_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  {
    int i = 0;
    int switch_end =
        iterator.current_offset() + iterator.current_bytecode_size();

    for (JumpTableTargetOffset entry : iterator.GetJumpTableTargetOffsets()) {
      CHECK_EQ(entry.case_value, small_jump_table_base + i);
      CHECK_EQ(entry.target_offset, switch_end + i);

      i++;
    }
    CHECK_EQ(i, small_jump_table_size);
  }
  iterator.Advance();

  for (int i = 0; i < small_jump_table_size; i++) {
    CHECK_EQ(iterator.current_bytecode(), Bytecode::kDebugger);
    iterator.Advance();
  }

  CHECK_EQ(iterator.current_bytecode(), Bytecode::kReturn);
  iterator.Advance();
  CHECK(iterator.done());
}

TEST_F(BytecodeArrayBuilderTest, WideSwitch) {
  BytecodeArrayBuilder builder(zone(), 1, 1);

  // Large jump table that requires a wide Switch bytecode.
  int large_jump_table_size = 256;
  int large_jump_table_base = -10;
  BytecodeJumpTable* large_jump_table =
      builder.AllocateJumpTable(large_jump_table_size, large_jump_table_base);

  builder.LoadLiteral(Smi::FromInt(7)).SwitchOnSmiNoFeedback(large_jump_table);
  for (int i = 0; i < large_jump_table_size; i++) {
    builder.Bind(large_jump_table, large_jump_table_base + i).Debugger();
  }
  builder.Return();

  Handle<BytecodeArray> array = builder.ToBytecodeArray(isolate());
  BytecodeArrayIterator iterator(array);

  CHECK_EQ(iterator.current_bytecode(), Bytecode::kLdaSmi);
  iterator.Advance();

  CHECK_EQ(iterator.current_bytecode(), Bytecode::kSwitchOnSmiNoFeedback);
  CHECK_EQ(iterator.current_operand_scale(), OperandScale::kDouble);
  {
    int i = 0;
    int switch_end =
        iterator.current_offset() + iterator.current_bytecode_size();

    for (JumpTableTargetOffset entry : iterator.GetJumpTableTargetOffsets()) {
      CHECK_EQ(entry.case_value, large_jump_table_base + i);
      CHECK_EQ(entry.target_offset, switch_end + i);

      i++;
    }
    CHECK_EQ(i, large_jump_table_size);
  }
  iterator.Advance();

  for (int i = 0; i < large_jump_table_size; i++) {
    CHECK_EQ(iterator.current_bytecode(), Bytecode::kDebugger);
    iterator.Advance();
  }

  CHECK_EQ(iterator.current_bytecode(), Bytecode::kReturn);
  iterator.Advance();
  CHECK(iterator.done());
}

}  // namespace interpreter
}  // namespace internal
}  // namespace v8

"""

```