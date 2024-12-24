Response: Let's break down the thought process for analyzing this C++ code and explaining its function in relation to JavaScript.

1. **Understand the Core Goal:** The filename `bytecode-array-random-iterator-unittest.cc` immediately suggests the code is a *unit test* for something called `BytecodeArrayRandomIterator`. The "unittest" part is key. Unit tests verify the correct behavior of individual components.

2. **Identify the Target Class:** The central class being tested is `BytecodeArrayRandomIterator`. The test file will contain methods and assertions that exercise its functionality.

3. **Examine the Test Structure:** The code uses the Google Test framework (`TEST_F`). Each `TEST_F` function focuses on a specific aspect of the iterator's behavior. Looking at the test names provides clues:
    * `InvalidBeforeStart`: Checks what happens before the beginning.
    * `InvalidAfterEnd`: Checks what happens after the end.
    * `AccessesFirst`: Verifies accessing the first element.
    * `AccessesLast`: Verifies accessing the last element.
    * `RandomAccessValid`: Tests jumping to arbitrary positions.
    * `IteratesBytecodeArray`: Tests forward iteration.
    * `IteratesBytecodeArrayBackwards`: Tests backward iteration.

4. **Analyze the Setup within Each Test:**  Each test function follows a similar pattern:
    * **`BytecodeArrayBuilder builder(...)`:**  A `BytecodeArrayBuilder` is used to create a `BytecodeArray`. This tells us the iterator works on `BytecodeArray` objects. The builder is populated with various bytecode instructions.
    * **`BytecodeArrayRandomIterator iterator(bytecodeArray, zone());`:** An instance of the iterator is created, associated with the generated `bytecodeArray`.
    * **Iterator Manipulation (`GoToStart`, `GoToEnd`, `GoToIndex`, `++`, `--`):** The tests use the iterator's methods to move through the bytecode array.
    * **Assertions (`ASSERT_TRUE`, `ASSERT_FALSE`, `EXPECT_EQ`):** These are the core of the unit test. They verify that the iterator is behaving as expected (e.g., `IsValid()` returns the correct boolean, `current_bytecode()` returns the expected instruction, operand values are correct).

5. **Identify Key Iterator Methods:** From the test code, we can infer the important methods of `BytecodeArrayRandomIterator`:
    * `IsValid()`: Checks if the iterator is currently pointing to a valid bytecode.
    * `GoToStart()`: Moves the iterator to the beginning.
    * `GoToEnd()`: Moves the iterator to the end.
    * `GoToIndex(int index)`: Moves the iterator to a specific bytecode index.
    * `operator++()`: Moves the iterator to the next bytecode.
    * `operator--()`: Moves the iterator to the previous bytecode.
    * `current_bytecode()`: Returns the current bytecode instruction.
    * `current_index()`: Returns the index of the current bytecode.
    * `current_offset()`: Returns the byte offset of the current bytecode within the array.
    * `current_operand_scale()`: Returns the operand scale of the current bytecode.
    * `GetConstantForIndexOperand(int operand_index, Isolate* isolate())`: Gets a constant operand.
    * `GetRegisterOperand(int operand_index)`: Gets a register operand.
    * `GetRegisterOperandRange(int operand_index)`: Gets the range of registers for an operand.
    * `GetImmediateOperand(int operand_index)`: Gets an immediate operand value.
    * `GetRuntimeIdOperand(int operand_index)`: Gets a runtime function ID operand.
    * `GetIndexOperand(int operand_index)`: Gets an index operand.
    * `GetRegisterCountOperand(int operand_index)`: Gets the count of registers for an operand.

6. **Connect to JavaScript:** The crucial link is the mention of "bytecode."  JavaScript engines, like V8, compile JavaScript code into bytecode for efficient execution within their virtual machines. The `BytecodeArray` is a representation of this compiled JavaScript code. The `BytecodeArrayRandomIterator` is a tool to navigate and examine this internal representation.

7. **Illustrate with a JavaScript Example:**  To make the connection clear, a simple JavaScript function is needed. The goal is to show how a basic JavaScript construct translates into bytecode that the iterator would operate on. A simple function with a variable assignment and addition is sufficient.

8. **Explain the Relationship:**  Explicitly state that the C++ code is a *testing tool* for V8's internal workings. It's not directly accessible to JavaScript developers. However, the *behavior* it tests (iterating through bytecode) is directly related to how V8 executes JavaScript code.

9. **Refine and Organize:**  Structure the explanation logically, starting with the core function, detailing the test cases, listing the key methods, establishing the JavaScript link, providing an example, and summarizing the overall purpose. Use clear and concise language. Ensure the JavaScript example is easy to understand.

Self-Correction/Refinement during the process:

* **Initial thought:** Focus heavily on the C++ syntax. **Correction:** Shift focus to the *purpose* of the code and how it relates to JavaScript's execution model. The specific C++ details are less important for someone primarily interested in the JavaScript connection.
* **Initial explanation of "bytecode":**  Might be too technical. **Correction:** Simplify the explanation to "low-level instructions" understood by the JavaScript engine.
* **JavaScript example:** Initially considered a more complex example. **Correction:** Opted for a simpler example to clearly demonstrate the concept without unnecessary complexity.
* **Clarity of the "testing" aspect:** Initially might not have emphasized enough that this is *test* code. **Correction:** Make it very clear that this is a tool for V8 developers to ensure the iterator works correctly, not a component directly used in JavaScript code.
这个C++源代码文件 `bytecode-array-random-iterator-unittest.cc` 的功能是**测试 `BytecodeArrayRandomIterator` 类**的正确性。`BytecodeArrayRandomIterator` 是 V8 JavaScript 引擎内部用于遍历字节码数组（BytecodeArray）的迭代器。这个迭代器允许以任意顺序访问字节码数组中的指令，而不仅仅是顺序访问。

具体来说，这个测试文件包含了多个单元测试用例，用来验证 `BytecodeArrayRandomIterator` 的以下行为：

* **边界条件处理:**
    * 测试在开始位置之前（`InvalidBeforeStart`）和结束位置之后（`InvalidAfterEnd`）访问迭代器是否会使其失效。
* **基本访问:**
    * 测试能否正确访问字节码数组的第一个元素（`AccessesFirst`）和最后一个元素（`AccessesLast`）。
* **随机访问:**
    * 测试能否通过索引随机访问字节码数组中的任意有效位置（`RandomAccessValid`），并能正确获取当前字节码、索引、偏移量和操作数等信息。
* **正向迭代:**
    * 测试能否通过 `++` 操作符正向遍历整个字节码数组（`IteratesBytecodeArray`），并能正确获取每个字节码的信息。
* **反向迭代:**
    * 测试能否通过 `--` 操作符反向遍历整个字节码数组（`IteratesBytecodeArrayBackwards`），并能正确获取每个字节码的信息。

**与 JavaScript 的功能关系:**

这个 C++ 文件直接关联到 V8 JavaScript 引擎的**解释器（Interpreter）**部分。当 JavaScript 代码被执行时，V8 会将其编译成一种中间表示形式，即字节码（Bytecode）。`BytecodeArray` 就是存储这些字节码指令的数组。

`BytecodeArrayRandomIterator` 作为一个内部工具，主要用于 V8 引擎的开发和调试。它可以帮助开发者检查和分析生成的字节码，例如：

* **调试器:**  当你在 JavaScript 代码中设置断点时，V8 内部可能会使用类似的迭代器来定位和执行相应的字节码指令。
* **代码优化:**  V8 团队可以利用这种迭代器来分析字节码的结构，从而进行更深入的优化。
* **测试框架:**  正如这个测试文件本身所展示的，这种迭代器对于测试字节码生成和解释的正确性至关重要。

**JavaScript 示例 (概念性，无法直接操作):**

虽然 JavaScript 代码无法直接操作 `BytecodeArray` 或 `BytecodeArrayRandomIterator`，但我们可以用一个简单的 JavaScript 函数来理解字节码的概念以及迭代器可能访问的内容。

```javascript
function add(a, b) {
  const sum = a + b;
  return sum;
}

add(5, 3);
```

当 V8 执行这段代码时，它可能会生成类似于以下的字节码指令序列（这只是一个简化的例子，实际的字节码会更复杂）：

1. `Ldar a`  // 将参数 'a' 加载到累加器
2. `Add r1`  // 将寄存器 r1（存储 'b'）的值加到累加器
3. `Star r2` // 将累加器的值存储到寄存器 r2 (对应 'sum')
4. `Ldar r2` // 将寄存器 r2 的值加载到累加器
5. `Return`  // 返回累加器的值

`BytecodeArrayRandomIterator` 的作用就是能够遍历这个字节码数组，并能够获取每个指令的信息，例如：

* `current_bytecode()` 可能返回 `Bytecode::kLdar`, `Bytecode::kAdd` 等枚举值，表示当前指令的类型。
* `current_operand()` 可能返回操作数的信息，例如对于 `Add r1`，操作数就是寄存器 `r1`。

**总结:**

`bytecode-array-random-iterator-unittest.cc` 是 V8 引擎内部用于测试字节码数组随机迭代器功能的 C++ 文件。虽然 JavaScript 开发者无法直接使用这个迭代器，但理解它的功能有助于理解 JavaScript 代码在 V8 引擎内部是如何被编译和执行的。它体现了 V8 内部对字节码进行操作和分析的需求，这是实现高性能 JavaScript 执行的关键部分。

Prompt: 
```
这是目录为v8/test/unittests/interpreter/bytecode-array-random-iterator-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/init/v8.h"

#include "src/interpreter/bytecode-array-builder.h"
#include "src/interpreter/bytecode-array-random-iterator.h"
#include "src/numbers/hash-seed-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/smi.h"
#include "test/unittests/interpreter/bytecode-utils.h"
#include "test/unittests/test-utils.h"

namespace v8 {
namespace internal {
namespace interpreter {

class BytecodeArrayRandomIteratorTest : public TestWithIsolateAndZone {
 public:
  BytecodeArrayRandomIteratorTest() = default;
  ~BytecodeArrayRandomIteratorTest() override = default;
};

TEST_F(BytecodeArrayRandomIteratorTest, InvalidBeforeStart) {
  // Use a builder to create an array with containing multiple bytecodes
  // with 0, 1 and 2 operands.
  FeedbackVectorSpec feedback_spec(zone());
  BytecodeArrayBuilder builder(zone(), 3, 3, &feedback_spec);
  AstValueFactory ast_factory(zone(), isolate()->ast_string_constants(),
                              HashSeed(isolate()));
  double heap_num_0 = 2.718;
  double heap_num_1 = 2.0 * Smi::kMaxValue;
  Tagged<Smi> zero = Smi::zero();
  Tagged<Smi> smi_0 = Smi::FromInt(64);
  Tagged<Smi> smi_1 = Smi::FromInt(-65536);
  Register reg_0(0);
  Register reg_1(1);
  RegisterList pair = BytecodeUtils::NewRegisterList(0, 2);
  RegisterList triple = BytecodeUtils::NewRegisterList(0, 3);
  Register param = Register::FromParameterIndex(2);
  const AstRawString* name = ast_factory.GetOneByteString("abc");
  uint32_t feedback_slot = feedback_spec.AddLoadICSlot().ToInt();

  builder.LoadLiteral(heap_num_0)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(heap_num_1)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(zero)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(smi_0)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(smi_1)
      .StoreAccumulatorInRegister(reg_1)
      .LoadAccumulatorWithRegister(reg_0)
      .BinaryOperation(Token::kAdd, reg_0, 2)
      .StoreAccumulatorInRegister(reg_1)
      .LoadNamedProperty(reg_1, name, feedback_slot)
      .BinaryOperation(Token::kAdd, reg_0, 3)
      .StoreAccumulatorInRegister(param)
      .CallRuntimeForPair(Runtime::kLoadLookupSlotForCall, param, pair)
      .ForInPrepare(triple, feedback_slot)
      .CallRuntime(Runtime::kLoadIC_Miss, reg_0)
      .Debugger()
      .Return();

  ast_factory.Internalize(isolate());
  Handle<BytecodeArray> bytecodeArray = builder.ToBytecodeArray(isolate());
  BytecodeArrayRandomIterator iterator(bytecodeArray, zone());

  iterator.GoToStart();
  ASSERT_TRUE(iterator.IsValid());
  --iterator;
  ASSERT_FALSE(iterator.IsValid());
}

TEST_F(BytecodeArrayRandomIteratorTest, InvalidAfterEnd) {
  // Use a builder to create an array with containing multiple bytecodes
  // with 0, 1 and 2 operands.
  FeedbackVectorSpec feedback_spec(zone());
  BytecodeArrayBuilder builder(zone(), 3, 3, &feedback_spec);
  AstValueFactory ast_factory(zone(), isolate()->ast_string_constants(),
                              HashSeed(isolate()));
  double heap_num_0 = 2.718;
  double heap_num_1 = 2.0 * Smi::kMaxValue;
  Tagged<Smi> zero = Smi::zero();
  Tagged<Smi> smi_0 = Smi::FromInt(64);
  Tagged<Smi> smi_1 = Smi::FromInt(-65536);
  Register reg_0(0);
  Register reg_1(1);
  RegisterList pair = BytecodeUtils::NewRegisterList(0, 2);
  RegisterList triple = BytecodeUtils::NewRegisterList(0, 3);
  Register param = Register::FromParameterIndex(2);
  const AstRawString* name = ast_factory.GetOneByteString("abc");
  uint32_t feedback_slot = feedback_spec.AddLoadICSlot().ToInt();

  builder.LoadLiteral(heap_num_0)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(heap_num_1)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(zero)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(smi_0)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(smi_1)
      .StoreAccumulatorInRegister(reg_1)
      .LoadAccumulatorWithRegister(reg_0)
      .BinaryOperation(Token::kAdd, reg_0, 2)
      .StoreAccumulatorInRegister(reg_1)
      .LoadNamedProperty(reg_1, name, feedback_slot)
      .BinaryOperation(Token::kAdd, reg_0, 3)
      .StoreAccumulatorInRegister(param)
      .CallRuntimeForPair(Runtime::kLoadLookupSlotForCall, param, pair)
      .ForInPrepare(triple, feedback_slot)
      .CallRuntime(Runtime::kLoadIC_Miss, reg_0)
      .Debugger()
      .Return();

  ast_factory.Internalize(isolate());
  Handle<BytecodeArray> bytecodeArray = builder.ToBytecodeArray(isolate());
  BytecodeArrayRandomIterator iterator(bytecodeArray, zone());

  iterator.GoToEnd();
  ASSERT_TRUE(iterator.IsValid());
  ++iterator;
  ASSERT_FALSE(iterator.IsValid());
}

TEST_F(BytecodeArrayRandomIteratorTest, AccessesFirst) {
  // Use a builder to create an array with containing multiple bytecodes
  // with 0, 1 and 2 operands.
  FeedbackVectorSpec feedback_spec(zone());
  BytecodeArrayBuilder builder(zone(), 3, 3, &feedback_spec);
  AstValueFactory ast_factory(zone(), isolate()->ast_string_constants(),
                              HashSeed(isolate()));
  double heap_num_0 = 2.718;
  double heap_num_1 = 2.0 * Smi::kMaxValue;
  Tagged<Smi> zero = Smi::zero();
  Tagged<Smi> smi_0 = Smi::FromInt(64);
  Tagged<Smi> smi_1 = Smi::FromInt(-65536);
  Register reg_0(0);
  Register reg_1(1);
  RegisterList pair = BytecodeUtils::NewRegisterList(0, 2);
  RegisterList triple = BytecodeUtils::NewRegisterList(0, 3);
  Register param = Register::FromParameterIndex(2);
  const AstRawString* name = ast_factory.GetOneByteString("abc");
  uint32_t feedback_slot = feedback_spec.AddLoadICSlot().ToInt();

  builder.LoadLiteral(heap_num_0)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(heap_num_1)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(zero)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(smi_0)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(smi_1)
      .StoreAccumulatorInRegister(reg_1)
      .LoadAccumulatorWithRegister(reg_0)
      .BinaryOperation(Token::kAdd, reg_0, 2)
      .StoreAccumulatorInRegister(reg_1)
      .LoadNamedProperty(reg_1, name, feedback_slot)
      .BinaryOperation(Token::kAdd, reg_0, 3)
      .StoreAccumulatorInRegister(param)
      .CallRuntimeForPair(Runtime::kLoadLookupSlotForCall, param, pair)
      .ForInPrepare(triple, feedback_slot)
      .CallRuntime(Runtime::kLoadIC_Miss, reg_0)
      .Debugger()
      .Return();

  ast_factory.Internalize(isolate());
  Handle<BytecodeArray> bytecodeArray = builder.ToBytecodeArray(isolate());
  BytecodeArrayRandomIterator iterator(bytecodeArray, zone());

  iterator.GoToStart();

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kLdaConstant);
  EXPECT_EQ(iterator.current_index(), 0);
  EXPECT_EQ(iterator.current_offset(), 0);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(
      Object::NumberValue(*iterator.GetConstantForIndexOperand(0, isolate())),
      heap_num_0);
  ASSERT_TRUE(iterator.IsValid());
}

TEST_F(BytecodeArrayRandomIteratorTest, AccessesLast) {
  // Use a builder to create an array with containing multiple bytecodes
  // with 0, 1 and 2 operands.
  FeedbackVectorSpec feedback_spec(zone());
  BytecodeArrayBuilder builder(zone(), 3, 3, &feedback_spec);
  AstValueFactory ast_factory(zone(), isolate()->ast_string_constants(),
                              HashSeed(isolate()));
  double heap_num_0 = 2.718;
  double heap_num_1 = 2.0 * Smi::kMaxValue;
  Tagged<Smi> zero = Smi::zero();
  Tagged<Smi> smi_0 = Smi::FromInt(64);
  Tagged<Smi> smi_1 = Smi::FromInt(-65536);
  Register reg_0(0);
  Register reg_1(1);
  RegisterList pair = BytecodeUtils::NewRegisterList(0, 2);
  RegisterList triple = BytecodeUtils::NewRegisterList(0, 3);
  Register param = Register::FromParameterIndex(2);
  const AstRawString* name = ast_factory.GetOneByteString("abc");
  uint32_t feedback_slot = feedback_spec.AddLoadICSlot().ToInt();

  builder.LoadLiteral(heap_num_0)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(heap_num_1)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(zero)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(smi_0)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(smi_1)
      .StoreAccumulatorInRegister(reg_1)
      .LoadAccumulatorWithRegister(reg_0)
      .BinaryOperation(Token::kAdd, reg_0, 2)
      .StoreAccumulatorInRegister(reg_1)
      .LoadNamedProperty(reg_1, name, feedback_slot)
      .BinaryOperation(Token::kAdd, reg_0, 3)
      .StoreAccumulatorInRegister(param)
      .CallRuntimeForPair(Runtime::kLoadLookupSlotForCall, param, pair)
      .ForInPrepare(triple, feedback_slot)
      .CallRuntime(Runtime::kLoadIC_Miss, reg_0)
      .Debugger()
      .Return();

  ast_factory.Internalize(isolate());
  Handle<BytecodeArray> bytecodeArray = builder.ToBytecodeArray(isolate());
  BytecodeArrayRandomIterator iterator(bytecodeArray, zone());

  iterator.GoToEnd();

  int offset = bytecodeArray->length() -
               Bytecodes::Size(Bytecode::kReturn, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kReturn);
  EXPECT_EQ(iterator.current_index(), 20);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  ASSERT_TRUE(iterator.IsValid());
}

TEST_F(BytecodeArrayRandomIteratorTest, RandomAccessValid) {
  // Use a builder to create an array with containing multiple bytecodes
  // with 0, 1 and 2 operands.
  FeedbackVectorSpec feedback_spec(zone());
  BytecodeArrayBuilder builder(zone(), 3, 17, &feedback_spec);
  AstValueFactory ast_factory(zone(), isolate()->ast_string_constants(),
                              HashSeed(isolate()));
  double heap_num_0 = 2.718;
  double heap_num_1 = 2.0 * Smi::kMaxValue;
  Tagged<Smi> zero = Smi::zero();
  Tagged<Smi> smi_0 = Smi::FromInt(64);
  Tagged<Smi> smi_1 = Smi::FromInt(-65536);
  Register reg_0(0);
  Register reg_16(16);  // Something not eligible for short Star.
  RegisterList pair = BytecodeUtils::NewRegisterList(0, 2);
  RegisterList triple = BytecodeUtils::NewRegisterList(0, 3);
  Register param = Register::FromParameterIndex(2);
  const AstRawString* name = ast_factory.GetOneByteString("abc");
  uint32_t name_index = 2;
  uint32_t feedback_slot = feedback_spec.AddLoadICSlot().ToInt();

  builder.LoadLiteral(heap_num_0)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(heap_num_1)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(zero)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(smi_0)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(smi_1)
      .StoreAccumulatorInRegister(reg_16)
      .LoadAccumulatorWithRegister(reg_0)
      .BinaryOperation(Token::kAdd, reg_0, 2)
      .StoreAccumulatorInRegister(reg_16)
      .LoadNamedProperty(reg_16, name, feedback_slot)
      .BinaryOperation(Token::kAdd, reg_0, 3)
      .StoreAccumulatorInRegister(param)
      .CallRuntimeForPair(Runtime::kLoadLookupSlotForCall, param, pair)
      .ForInPrepare(triple, feedback_slot)
      .CallRuntime(Runtime::kLoadIC_Miss, reg_0)
      .Debugger()
      .Return();

  // Test iterator sees the expected output from the builder.
  ast_factory.Internalize(isolate());
  BytecodeArrayRandomIterator iterator(builder.ToBytecodeArray(isolate()),
                                       zone());
  const int kPrefixByteSize = 1;
  int offset = 0;

  iterator.GoToIndex(11);
  offset = Bytecodes::Size(Bytecode::kLdaConstant, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kLdaConstant, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kLdaZero, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kLdaSmi, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kLdaSmi, OperandScale::kQuadruple) +
            kPrefixByteSize;
  offset += Bytecodes::Size(Bytecode::kStar, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kLdar, OperandScale::kSingle);

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kAdd);
  EXPECT_EQ(iterator.current_index(), 11);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), reg_0.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(0), 1);
  ASSERT_TRUE(iterator.IsValid());

  iterator.GoToIndex(2);
  offset = Bytecodes::Size(Bytecode::kLdaConstant, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kLdaConstant);
  EXPECT_EQ(iterator.current_index(), 2);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(
      Object::NumberValue(*iterator.GetConstantForIndexOperand(0, isolate())),
      heap_num_1);
  ASSERT_TRUE(iterator.IsValid());

  iterator.GoToIndex(16);
  offset = Bytecodes::Size(Bytecode::kLdaConstant, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kLdaConstant, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kLdaZero, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kLdaSmi, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kLdaSmi, OperandScale::kQuadruple) +
            kPrefixByteSize;
  offset += Bytecodes::Size(Bytecode::kStar, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kLdar, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kAdd, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kStar, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kGetNamedProperty, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kAdd, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kStar, OperandScale::kSingle);

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kCallRuntimeForPair);
  EXPECT_EQ(iterator.current_index(), 16);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRuntimeIdOperand(0), Runtime::kLoadLookupSlotForCall);
  EXPECT_EQ(iterator.GetRegisterOperand(1).index(), param.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(1), 1);
  EXPECT_EQ(iterator.GetRegisterCountOperand(2), 1u);
  EXPECT_EQ(iterator.GetRegisterOperand(3).index(), reg_0.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(3), 2);
  ASSERT_TRUE(iterator.IsValid());

  iterator -= 3;
  offset -= Bytecodes::Size(Bytecode::kStar, OperandScale::kSingle);
  offset -= Bytecodes::Size(Bytecode::kAdd, OperandScale::kSingle);
  offset -= Bytecodes::Size(Bytecode::kGetNamedProperty, OperandScale::kSingle);

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kGetNamedProperty);
  EXPECT_EQ(iterator.current_index(), 13);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), reg_16.index());
  EXPECT_EQ(iterator.GetIndexOperand(1), name_index);
  EXPECT_EQ(iterator.GetIndexOperand(2), feedback_slot);
  ASSERT_TRUE(iterator.IsValid());

  iterator += 2;
  offset += Bytecodes::Size(Bytecode::kGetNamedProperty, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kAdd, OperandScale::kSingle);

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kStar);
  EXPECT_EQ(iterator.current_index(), 15);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), param.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(0), 1);
  ASSERT_TRUE(iterator.IsValid());

  iterator.GoToIndex(20);
  offset = Bytecodes::Size(Bytecode::kLdaConstant, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kLdaConstant, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kLdaZero, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kLdaSmi, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kLdaSmi, OperandScale::kQuadruple) +
            kPrefixByteSize;
  offset += Bytecodes::Size(Bytecode::kStar, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kLdar, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kAdd, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kStar, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kGetNamedProperty, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kAdd, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kStar, OperandScale::kSingle);
  offset +=
      Bytecodes::Size(Bytecode::kCallRuntimeForPair, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kForInPrepare, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kCallRuntime, OperandScale::kSingle);
  offset += Bytecodes::Size(Bytecode::kDebugger, OperandScale::kSingle);

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kReturn);
  EXPECT_EQ(iterator.current_index(), 20);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  ASSERT_TRUE(iterator.IsValid());

  iterator.GoToIndex(22);
  EXPECT_FALSE(iterator.IsValid());

  iterator.GoToIndex(-5);
  EXPECT_FALSE(iterator.IsValid());
}

TEST_F(BytecodeArrayRandomIteratorTest, IteratesBytecodeArray) {
  // Use a builder to create an array with containing multiple bytecodes
  // with 0, 1 and 2 operands.
  FeedbackVectorSpec feedback_spec(zone());
  BytecodeArrayBuilder builder(zone(), 3, 17, &feedback_spec);
  AstValueFactory ast_factory(zone(), isolate()->ast_string_constants(),
                              HashSeed(isolate()));
  double heap_num_0 = 2.718;
  double heap_num_1 = 2.0 * Smi::kMaxValue;
  Tagged<Smi> zero = Smi::zero();
  Tagged<Smi> smi_0 = Smi::FromInt(64);
  Tagged<Smi> smi_1 = Smi::FromInt(-65536);
  Register reg_0(0);
  Register reg_16(16);  // Something not eligible for short Star.
  RegisterList pair = BytecodeUtils::NewRegisterList(0, 2);
  RegisterList triple = BytecodeUtils::NewRegisterList(0, 3);
  Register param = Register::FromParameterIndex(2);
  const AstRawString* name = ast_factory.GetOneByteString("abc");
  uint32_t name_index = 2;
  uint32_t feedback_slot = feedback_spec.AddLoadICSlot().ToInt();

  builder.LoadLiteral(heap_num_0)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(heap_num_1)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(zero)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(smi_0)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(smi_1)
      .StoreAccumulatorInRegister(reg_16)
      .LoadAccumulatorWithRegister(reg_0)
      .BinaryOperation(Token::kAdd, reg_0, 2)
      .StoreAccumulatorInRegister(reg_16)
      .LoadNamedProperty(reg_16, name, feedback_slot)
      .BinaryOperation(Token::kAdd, reg_0, 3)
      .StoreAccumulatorInRegister(param)
      .CallRuntimeForPair(Runtime::kLoadLookupSlotForCall, param, pair)
      .ForInPrepare(triple, feedback_slot)
      .CallRuntime(Runtime::kLoadIC_Miss, reg_0)
      .Debugger()
      .Return();

  // Test iterator sees the expected output from the builder.
  ast_factory.Internalize(isolate());
  BytecodeArrayRandomIterator iterator(builder.ToBytecodeArray(isolate()),
                                       zone());
  const int kPrefixByteSize = 1;
  int offset = 0;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kLdaConstant);
  EXPECT_EQ(iterator.current_index(), 0);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(
      Object::NumberValue(*iterator.GetConstantForIndexOperand(0, isolate())),
      heap_num_0);
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kLdaConstant, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kStar0);
  EXPECT_EQ(iterator.current_index(), 1);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kLdaConstant);
  EXPECT_EQ(iterator.current_index(), 2);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(
      Object::NumberValue(*iterator.GetConstantForIndexOperand(0, isolate())),
      heap_num_1);
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kLdaConstant, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kStar0);
  EXPECT_EQ(iterator.current_index(), 3);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kLdaZero);
  EXPECT_EQ(iterator.current_index(), 4);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kLdaZero, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kStar0);
  EXPECT_EQ(iterator.current_index(), 5);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kLdaSmi);
  EXPECT_EQ(iterator.current_index(), 6);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(Smi::FromInt(iterator.GetImmediateOperand(0)), smi_0);
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kLdaSmi, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kStar0);
  EXPECT_EQ(iterator.current_index(), 7);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kLdaSmi);
  EXPECT_EQ(iterator.current_index(), 8);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kQuadruple);
  EXPECT_EQ(Smi::FromInt(iterator.GetImmediateOperand(0)), smi_1);
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kLdaSmi, OperandScale::kQuadruple) +
            kPrefixByteSize;
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kStar);
  EXPECT_EQ(iterator.current_index(), 9);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), reg_16.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(0), 1);
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kStar, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kLdar);
  EXPECT_EQ(iterator.current_index(), 10);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), reg_0.index());
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kLdar, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kAdd);
  EXPECT_EQ(iterator.current_index(), 11);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), reg_0.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(0), 1);
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kAdd, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kStar);
  EXPECT_EQ(iterator.current_index(), 12);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), reg_16.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(0), 1);
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kStar, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kGetNamedProperty);
  EXPECT_EQ(iterator.current_index(), 13);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), reg_16.index());
  EXPECT_EQ(iterator.GetIndexOperand(1), name_index);
  EXPECT_EQ(iterator.GetIndexOperand(2), feedback_slot);
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kGetNamedProperty, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kAdd);
  EXPECT_EQ(iterator.current_index(), 14);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), reg_0.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(0), 1);
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kAdd, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kStar);
  EXPECT_EQ(iterator.current_index(), 15);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), param.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(0), 1);
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kStar, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kCallRuntimeForPair);
  EXPECT_EQ(iterator.current_index(), 16);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRuntimeIdOperand(0), Runtime::kLoadLookupSlotForCall);
  EXPECT_EQ(iterator.GetRegisterOperand(1).index(), param.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(1), 1);
  EXPECT_EQ(iterator.GetRegisterCountOperand(2), 1u);
  EXPECT_EQ(iterator.GetRegisterOperand(3).index(), reg_0.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(3), 2);
  ASSERT_TRUE(iterator.IsValid());
  offset +=
      Bytecodes::Size(Bytecode::kCallRuntimeForPair, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kForInPrepare);
  EXPECT_EQ(iterator.current_index(), 17);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), reg_0.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(0), 3);
  EXPECT_EQ(iterator.GetIndexOperand(1), feedback_slot);
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kForInPrepare, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kCallRuntime);
  EXPECT_EQ(iterator.current_index(), 18);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRuntimeIdOperand(0), Runtime::kLoadIC_Miss);
  EXPECT_EQ(iterator.GetRegisterOperand(1).index(), reg_0.index());
  EXPECT_EQ(iterator.GetRegisterCountOperand(2), 1u);
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kCallRuntime, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kDebugger);
  EXPECT_EQ(iterator.current_index(), 19);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  ASSERT_TRUE(iterator.IsValid());
  offset += Bytecodes::Size(Bytecode::kDebugger, OperandScale::kSingle);
  ++iterator;

  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kReturn);
  EXPECT_EQ(iterator.current_index(), 20);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  ASSERT_TRUE(iterator.IsValid());
  ++iterator;
  ASSERT_TRUE(!iterator.IsValid());
}

TEST_F(BytecodeArrayRandomIteratorTest, IteratesBytecodeArrayBackwards) {
  // Use a builder to create an array with containing multiple bytecodes
  // with 0, 1 and 2 operands.
  FeedbackVectorSpec feedback_spec(zone());
  BytecodeArrayBuilder builder(zone(), 3, 17, &feedback_spec);
  AstValueFactory ast_factory(zone(), isolate()->ast_string_constants(),
                              HashSeed(isolate()));
  double heap_num_0 = 2.718;
  double heap_num_1 = 2.0 * Smi::kMaxValue;
  Tagged<Smi> zero = Smi::zero();
  Tagged<Smi> smi_0 = Smi::FromInt(64);
  Tagged<Smi> smi_1 = Smi::FromInt(-65536);
  Register reg_0(0);
  Register reg_16(16);  // Something not eligible for short Star.
  RegisterList pair = BytecodeUtils::NewRegisterList(0, 2);
  RegisterList triple = BytecodeUtils::NewRegisterList(0, 3);
  Register param = Register::FromParameterIndex(2);
  const AstRawString* name = ast_factory.GetOneByteString("abc");
  uint32_t name_index = 2;
  uint32_t feedback_slot = feedback_spec.AddLoadICSlot().ToInt();

  builder.LoadLiteral(heap_num_0)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(heap_num_1)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(zero)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(smi_0)
      .StoreAccumulatorInRegister(reg_0)
      .LoadLiteral(smi_1)
      .StoreAccumulatorInRegister(reg_16)
      .LoadAccumulatorWithRegister(reg_0)
      .BinaryOperation(Token::kAdd, reg_0, 2)
      .StoreAccumulatorInRegister(reg_16)
      .LoadNamedProperty(reg_16, name, feedback_slot)
      .BinaryOperation(Token::kAdd, reg_0, 3)
      .StoreAccumulatorInRegister(param)
      .CallRuntimeForPair(Runtime::kLoadLookupSlotForCall, param, pair)
      .ForInPrepare(triple, feedback_slot)
      .CallRuntime(Runtime::kLoadIC_Miss, reg_0)
      .Debugger()
      .Return();

  // Test iterator sees the expected output from the builder.
  ast_factory.Internalize(isolate());
  Handle<BytecodeArray> bytecodeArray = builder.ToBytecodeArray(isolate());
  BytecodeArrayRandomIterator iterator(bytecodeArray, zone());
  const int kPrefixByteSize = 1;
  int offset = bytecodeArray->length();

  iterator.GoToEnd();

  offset -= Bytecodes::Size(Bytecode::kReturn, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kReturn);
  EXPECT_EQ(iterator.current_index(), 20);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kDebugger, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kDebugger);
  EXPECT_EQ(iterator.current_index(), 19);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kCallRuntime, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kCallRuntime);
  EXPECT_EQ(iterator.current_index(), 18);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRuntimeIdOperand(0), Runtime::kLoadIC_Miss);
  EXPECT_EQ(iterator.GetRegisterOperand(1).index(), reg_0.index());
  EXPECT_EQ(iterator.GetRegisterCountOperand(2), 1u);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kForInPrepare, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kForInPrepare);
  EXPECT_EQ(iterator.current_index(), 17);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), reg_0.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(0), 3);
  EXPECT_EQ(iterator.GetIndexOperand(1), feedback_slot);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -=
      Bytecodes::Size(Bytecode::kCallRuntimeForPair, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kCallRuntimeForPair);
  EXPECT_EQ(iterator.current_index(), 16);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRuntimeIdOperand(0), Runtime::kLoadLookupSlotForCall);
  EXPECT_EQ(iterator.GetRegisterOperand(1).index(), param.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(1), 1);
  EXPECT_EQ(iterator.GetRegisterCountOperand(2), 1u);
  EXPECT_EQ(iterator.GetRegisterOperand(3).index(), reg_0.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(3), 2);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kStar, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kStar);
  EXPECT_EQ(iterator.current_index(), 15);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), param.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(0), 1);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kAdd, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kAdd);
  EXPECT_EQ(iterator.current_index(), 14);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), reg_0.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(0), 1);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kGetNamedProperty, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kGetNamedProperty);
  EXPECT_EQ(iterator.current_index(), 13);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), reg_16.index());
  EXPECT_EQ(iterator.GetIndexOperand(1), name_index);
  EXPECT_EQ(iterator.GetIndexOperand(2), feedback_slot);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kStar, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kStar);
  EXPECT_EQ(iterator.current_index(), 12);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), reg_16.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(0), 1);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kAdd, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kAdd);
  EXPECT_EQ(iterator.current_index(), 11);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), reg_0.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(0), 1);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kLdar, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kLdar);
  EXPECT_EQ(iterator.current_index(), 10);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), reg_0.index());
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kStar, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kStar);
  EXPECT_EQ(iterator.current_index(), 9);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(iterator.GetRegisterOperand(0).index(), reg_16.index());
  EXPECT_EQ(iterator.GetRegisterOperandRange(0), 1);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kLdaSmi, OperandScale::kQuadruple) +
            kPrefixByteSize;
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kLdaSmi);
  EXPECT_EQ(iterator.current_index(), 8);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kQuadruple);
  EXPECT_EQ(Smi::FromInt(iterator.GetImmediateOperand(0)), smi_1);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kStar0);
  EXPECT_EQ(iterator.current_index(), 7);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kLdaSmi, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kLdaSmi);
  EXPECT_EQ(iterator.current_index(), 6);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(Smi::FromInt(iterator.GetImmediateOperand(0)), smi_0);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kStar0);
  EXPECT_EQ(iterator.current_index(), 5);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kLdaZero, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kLdaZero);
  EXPECT_EQ(iterator.current_index(), 4);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kStar0);
  EXPECT_EQ(iterator.current_index(), 3);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kLdaConstant, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kLdaConstant);
  EXPECT_EQ(iterator.current_index(), 2);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(
      Object::NumberValue(*iterator.GetConstantForIndexOperand(0, isolate())),
      heap_num_1);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kStar0, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kStar0);
  EXPECT_EQ(iterator.current_index(), 1);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;

  offset -= Bytecodes::Size(Bytecode::kLdaConstant, OperandScale::kSingle);
  EXPECT_EQ(iterator.current_bytecode(), Bytecode::kLdaConstant);
  EXPECT_EQ(iterator.current_index(), 0);
  EXPECT_EQ(iterator.current_offset(), offset);
  EXPECT_EQ(iterator.current_operand_scale(), OperandScale::kSingle);
  EXPECT_EQ(
      Object::NumberValue(*iterator.GetConstantForIndexOperand(0, isolate())),
      heap_num_0);
  ASSERT_TRUE(iterator.IsValid());
  --iterator;
  ASSERT_FALSE(iterator.IsValid());
}

}  // namespace interpreter
}  // namespace internal
}  // namespace v8

"""

```