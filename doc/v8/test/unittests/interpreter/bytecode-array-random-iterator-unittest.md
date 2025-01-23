Response:
The user wants to understand the functionality of the C++ code provided. The code is a unit test for a class called `BytecodeArrayRandomIterator`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core subject:** The filename and the class name `BytecodeArrayRandomIteratorTest` clearly indicate that this code tests the `BytecodeArrayRandomIterator` class.

2. **Determine the purpose of the tested class:**  The name `BytecodeArrayRandomIterator` suggests that it's an iterator that can move through a `BytecodeArray` in a potentially non-sequential way (random access).

3. **Analyze the test cases:**  Each `TEST_F` function focuses on a specific aspect of the iterator's functionality:
    * `InvalidBeforeStart`: Checks behavior when going before the beginning.
    * `InvalidAfterEnd`: Checks behavior when going after the end.
    * `AccessesFirst`: Verifies accessing the first element.
    * `AccessesLast`: Verifies accessing the last element.
    * `RandomAccessValid`: Checks moving to specific indices.
    * `IteratesBytecodeArray`: Tests forward iteration.
    * `IteratesBytecodeArrayBackwards`: Tests backward iteration.

4. **Infer the class's responsibilities based on the tests:** From the tests, we can deduce the following functionalities of `BytecodeArrayRandomIterator`:
    * Moving to the start and end of a `BytecodeArray`.
    * Moving to a specific index within the `BytecodeArray`.
    * Iterating forward and backward through the `BytecodeArray`.
    * Checking if the iterator is currently valid (within the bounds of the array).
    * Accessing information about the current bytecode, such as its opcode, index, offset, and operands.

5. **Check for Torque usage:** The prompt mentions checking for `.tq` extension. The provided code is `.cc`, so it's standard C++, not Torque.

6. **Consider JavaScript relevance:** The code interacts with bytecodes, which are the low-level instructions executed by the V8 JavaScript engine. Therefore, it directly relates to how JavaScript code is executed internally. We need to provide a simple JavaScript example that would result in the kind of bytecode manipulation demonstrated in the C++ tests (e.g., loading literals, storing to registers, performing arithmetic operations, accessing properties).

7. **Look for code logic and potential inputs/outputs:**  The tests themselves demonstrate the logic. The "input" is a constructed `BytecodeArray`, and the "output" is the iterator's state (current bytecode, index, offset, validity) after performing various operations. We can pick a simple test case like `AccessesFirst` and detail its input (the constructed bytecode array) and expected output (iterator pointing to the first instruction with specific properties).

8. **Identify common programming errors:** The "InvalidBeforeStart" and "InvalidAfterEnd" tests directly point to potential errors: going out of bounds when iterating. We need to illustrate this with a JavaScript example of iterating past the beginning or end of an array, which is a common mistake.

9. **Synthesize the summary:**  Combine the findings from the previous steps into a concise summary of the file's purpose.

10. **Structure the answer:** Organize the information logically with clear headings for each aspect (functionality, Torque, JavaScript relation, logic, errors, summary). Use examples to illustrate the points.
好的，这是对提供的 C++ 源代码文件 `v8/test/unittests/interpreter/bytecode-array-random-iterator-unittest.cc` 的功能归纳：

**功能归纳:**

该 C++ 代码文件是一个单元测试文件，专门用于测试 `v8` JavaScript 引擎中 `interpreter` 组件下的 `BytecodeArrayRandomIterator` 类的功能。

`BytecodeArrayRandomIterator` 类的主要作用是提供一种在字节码数组 (`BytecodeArray`) 中进行随机访问和迭代的能力。与普通的顺序迭代器不同，`BytecodeArrayRandomIterator` 允许以非线性的方式移动到数组中的任意位置，并访问该位置的字节码信息。

**具体测试的功能点包括：**

* **边界检查:**
    * 测试当迭代器试图移动到字节码数组开始之前 (`InvalidBeforeStart`) 或结束之后 (`InvalidAfterEnd`) 的行为，验证其是否能正确地标记为无效状态。
* **首尾访问:**
    * 测试迭代器能否正确地移动到字节码数组的第一个元素 (`AccessesFirst`) 和最后一个元素 (`AccessesLast`)，并能正确访问这些元素的字节码信息 (例如，操作码 `bytecode`、索引 `index`、偏移量 `offset`、操作数缩放 `operand_scale` 以及操作数本身)。
* **随机访问:**
    * 测试迭代器能否通过 `GoToIndex()` 方法准确地移动到字节码数组的指定索引位置 (`RandomAccessValid`)，并能正确访问该位置的字节码信息。同时测试了超出有效索引范围的情况。
* **正向迭代:**
    * 测试迭代器能否通过 `++` 运算符正确地在字节码数组中向前迭代 (`IteratesBytecodeArray`)，并能依次访问每个字节码的详细信息。
* **反向迭代:**
    * 测试迭代器能否通过 `--` 运算符正确地在字节码数组中向后迭代 (`IteratesBytecodeArrayBackwards`)，并能依次访问每个字节码的详细信息。

**关于文件类型和 JavaScript 关联:**

* **文件类型:** 该文件以 `.cc` 结尾，表明它是一个标准的 C++ 源代码文件，而不是以 `.tq` 结尾的 V8 Torque 源代码。
* **JavaScript 关联:**  `BytecodeArray` 存储的是 JavaScript 代码编译后生成的字节码指令。`BytecodeArrayRandomIterator` 用于分析和操作这些字节码。因此，该文件与 JavaScript 的功能有直接关系，因为它测试了 V8 引擎如何处理和遍历 JavaScript 代码的底层表示形式。

**JavaScript 示例:**

虽然我们不能直接用 JavaScript 操作 `BytecodeArray` 或 `BytecodeArrayRandomIterator`，但我们可以举一个简单的 JavaScript 例子，说明最终会生成类似的字节码并被该迭代器处理：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10);
```

这段简单的 JavaScript 代码在 V8 引擎中会被编译成一系列的字节码指令，例如：加载常量、加载参数、执行加法运算、返回结果等。 `BytecodeArrayRandomIterator` 的作用就是能遍历和分析这些底层的字节码指令。

**代码逻辑推理与假设输入/输出 (以 `AccessesFirst` 测试为例):**

**假设输入:**

1. `BytecodeArrayBuilder` 构建了一个包含多个字节码指令的 `BytecodeArray`，其中第一个指令是 `LoadLiteral(heap_num_0)`，对应的字节码是 `Bytecode::kLdaConstant`。
2. `heap_num_0` 的值为 2.718。

**代码逻辑:**

1. `iterator.GoToStart();`  将迭代器移动到字节码数组的起始位置。

**预期输出:**

1. `iterator.current_bytecode()` 应该返回 `Bytecode::kLdaConstant`。
2. `iterator.current_index()` 应该返回 `0` (第一个指令的索引)。
3. `iterator.current_offset()` 应该返回 `0` (第一个指令的起始偏移量)。
4. `iterator.current_operand_scale()` 应该返回 `OperandScale::kSingle`。
5. `Object::NumberValue(*iterator.GetConstantForIndexOperand(0, isolate()))` 应该返回 2.718 (第一个操作数是常量 `heap_num_0`)。
6. `iterator.IsValid()` 应该返回 `true` (迭代器在有效范围内)。

**用户常见的编程错误 (与迭代器相关):**

涉及到迭代器，用户常见的编程错误包括：

1. **越界访问:** 在循环中使用迭代器时，没有正确检查迭代器是否到达数组的末尾或开始之前，导致访问无效内存。

    ```javascript
    const arr = [1, 2, 3];
    // 错误示例：循环条件可能导致越界访问
    for (let i = 0; i <= arr.length; i++) {
      console.log(arr[i]); // 当 i 等于 arr.length 时会出错
    }
    ```

2. **迭代器失效:** 在迭代过程中修改了被迭代的集合，可能导致迭代器失效。虽然 `BytecodeArray` 在创建后通常不会被修改，但在其他使用迭代器的场景中 это распространенная ошибка.

    ```javascript
    const arr = [1, 2, 3];
    for (const item of arr) {
      if (item === 2) {
        arr.splice(1, 1); // 从数组中移除元素，可能导致迭代器失效
      }
      console.log(item);
    }
    ```

**总结:**

`v8/test/unittests/interpreter/bytecode-array-random-iterator-unittest.cc` 这个单元测试文件的主要功能是全面测试 `BytecodeArrayRandomIterator` 类的各种操作，包括边界检查、首尾访问、随机访问以及正向和反向迭代，以确保该类能够正确可靠地在字节码数组中移动和访问字节码信息。这对于 V8 引擎的解释器正确执行 JavaScript 代码至关重要。

### 提示词
```
这是目录为v8/test/unittests/interpreter/bytecode-array-random-iterator-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/interpreter/bytecode-array-random-iterator-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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
  EXPECT_EQ(iterator.current_op
```