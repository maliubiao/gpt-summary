Response: Let's break down the thought process for analyzing the C++ unittest file and generating the summary and JavaScript examples.

1. **Understand the Goal:** The request is to understand the purpose of the C++ file `bytecode-array-writer-unittest.cc`, summarize its functionality, and connect it to JavaScript using examples if applicable.

2. **Identify the Core Subject:** The filename itself is a huge clue: `bytecode-array-writer-unittest`. This immediately tells us the code is about testing a `BytecodeArrayWriter`. The `unittest` suffix confirms it's a unit testing file.

3. **Examine the Includes:**  The `#include` directives provide context:
    * `src/init/v8.h`:  Indicates interaction with the V8 JavaScript engine.
    * `src/api/api.h`:  Likely involves V8's public API, though less directly relevant to the core functionality being tested.
    * `src/codegen/source-position-table.h`: Points to source code location tracking, crucial for debugging and error reporting.
    * `src/execution/isolate.h`:  References the V8 isolate, a fundamental concept for separate execution environments.
    * `src/heap/factory.h`: Deals with object creation in V8's heap.
    * `src/interpreter/bytecode-array-writer.h`: The star of the show – the class being tested.
    * `src/interpreter/bytecode-label.h`, `bytecode-node.h`, `bytecode-register.h`, `bytecode-source-info.h`:  These are the building blocks of the bytecode representation.
    * `src/interpreter/constant-array-builder.h`:  Handles constants within the bytecode.
    * `src/utils/utils.h`:  General utility functions.
    * `src/objects/objects-inl.h`:  Internal V8 object representations.
    * `test/unittests/interpreter/bytecode-utils.h`, `test/unittests/test-utils.h`: Standard testing infrastructure.

4. **Analyze the Class Structure:** The `BytecodeArrayWriterUnittest` class is the central testing fixture. Key observations:
    * It inherits from `TestWithIsolateAndZone`, suggesting it sets up a V8 environment for testing.
    * It has members like `constant_array_builder_` and `bytecode_array_writer_`, confirming the focus on `BytecodeArrayWriter`.
    * The `Write` methods are clearly designed to add bytecode instructions with varying numbers of operands and source information.
    * The `WriteJump` and `WriteJumpLoop` methods handle control flow instructions.
    * The `writer()`, `bytecodes()`, and `source_position_table_builder()` methods provide access to internal state for verification.

5. **Understand the Test Cases:**  The `TEST_F` macros define individual test cases:
    * `SimpleExample`: A basic test to write a few instructions and verify the resulting bytecode and source positions.
    * `ComplexExample`: A more involved scenario with jumps and loops to test more complex bytecode sequences.
    * `ElideNoneffectfulBytecodes`: Tests the optimization of removing unnecessary bytecode instructions.
    * `DeadcodeElimination`: Tests the removal of unreachable code.

6. **Connect to JavaScript (The "Aha!" Moment):** The key insight is that this C++ code is *internal* to the V8 engine. It's about how JavaScript code is *compiled* and *represented* inside the engine. The "bytecode" being manipulated is the low-level instructions that V8's interpreter (Ignition) executes.

7. **Formulate the Summary:** Based on the analysis, the core function is clear: testing the `BytecodeArrayWriter`. Its role is to take individual bytecode instructions and their operands and assemble them into a linear array of bytes, along with metadata like source code positions. This representation is the intermediate form between parsing JavaScript and actual execution.

8. **Generate JavaScript Examples:** This requires thinking about JavaScript code snippets that would *result* in the kinds of bytecode operations being tested. The C++ code uses mnemonics like `LdaSmi` (Load Small Integer), `Star` (Store to Register), `Ldar` (Load from Register), `Add`, `JumpIfUndefined`, etc. We need to come up with JavaScript that would generate these instructions.

    * **Simple Assignment:** `let x = 127;` would likely involve loading a small integer (`LdaSmi`) and storing it (`Star`).
    * **Arithmetic:** `x + y;` would use arithmetic bytecodes like `Add`.
    * **Control Flow:** `if (condition) { ... }` would generate conditional jump instructions (`JumpIfFalse`, `JumpIfTrue`). Loops (`for`, `while`) would involve loop-related bytecodes (`JumpLoop`).
    * **Object/Property Access:**  Accessing properties (`obj.prop`) would involve bytecodes for loading and storing object properties.
    * **Function Calls:** Function calls would use bytecodes for setting up stack frames and executing the function's bytecode.

9. **Refine the Examples:** Ensure the JavaScript examples are clear, concise, and directly related to the bytecode concepts being tested. It's important to explain the *connection* – how the JavaScript code *leads to* the underlying bytecode.

10. **Review and Iterate:** Read through the summary and examples to ensure they are accurate, easy to understand, and effectively answer the prompt. For instance, initially, I might have just listed bytecode names without explaining their purpose. The iteration would involve adding the explanations and connecting them more explicitly to JavaScript concepts. Similarly, I might initially choose overly complex JavaScript examples. The iteration would simplify them to highlight the core bytecode being demonstrated.
这个C++源代码文件 `bytecode-array-writer-unittest.cc` 的主要功能是**测试 V8 JavaScript 引擎中用于生成字节码数组的 `BytecodeArrayWriter` 类**。

更具体地说，这个单元测试文件包含了多个测试用例，用于验证 `BytecodeArrayWriter` 类的各种功能，包括：

1. **写入不同的字节码指令:** 测试可以正确地将各种字节码指令（如 `LdaSmi`, `Star`, `Ldar`, `Return`, `Add`, `JumpIfUndefined` 等）及其操作数写入到字节码数组中。
2. **处理不同数量的操作数:** 测试可以正确处理不同操作数数量的字节码指令（从零个到多个）。
3. **写入跳转指令:** 测试可以正确地写入跳转指令，并解析和链接到 `BytecodeLabel` 定义的位置。
4. **写入循环跳转指令:** 测试可以正确地写入循环跳转指令，并处理与 `BytecodeLoopHeader` 相关的信息。
5. **记录源代码位置信息:** 测试可以正确地记录每个字节码指令对应的源代码位置，并将这些信息存储在 `SourcePositionTable` 中，用于调试和错误报告。
6. **优化和死代码消除:** 测试在开启相关优化标志时，`BytecodeArrayWriter` 是否能够消除无副作用的字节码以及死代码。
7. **生成最终的字节码数组:** 测试 `BytecodeArrayWriter` 可以正确地将写入的字节码和元数据（如常量池和源代码位置表）转换为最终的 `BytecodeArray` 对象。

**与 JavaScript 的关系 (以及示例说明):**

这个 C++ 文件直接关系到 JavaScript 的执行过程。V8 引擎在解析 JavaScript 代码后，会将其转换为一种中间表示形式，即字节码 (bytecode)。`BytecodeArrayWriter` 类负责将这些字节码指令组织成一个可执行的数组。这个字节码数组随后会被 V8 的解释器 (Ignition) 或即时编译器 (TurboFan) 执行。

**JavaScript 示例:**

以下是一些 JavaScript 代码片段，以及它们可能生成的（简化的）字节码指令，来说明 `BytecodeArrayWriter` 在幕后做的事情：

**示例 1: 简单的赋值和返回**

```javascript
function foo() {
  let x = 127;
  return x;
}
```

`BytecodeArrayWriter` 可能会生成如下的字节码 (简化表示)：

```
// ... 函数入口 ...
LdaSmi 127       // 将小整数 127 加载到累加器
Star r0          // 将累加器的值存储到寄存器 r0
Ldar r0          // 将寄存器 r0 的值加载到累加器
Return           // 返回累加器的值
```

在这个例子中，`LdaSmi` 对应加载一个小的整数常量，`Star` 对应将值存储到一个寄存器，`Ldar` 对应从寄存器加载值，`Return` 对应函数返回。

**示例 2: 条件语句**

```javascript
function bar(a) {
  if (a > 10) {
    return true;
  } else {
    return false;
  }
}
```

`BytecodeArrayWriter` 可能会生成如下的字节码 (简化表示)：

```
// ... 函数入口 ...
Ldar arg0         // 加载参数 a 到累加器
LdaSmi 10         // 加载小整数 10 到寄存器
GreaterThan       // 比较累加器和寄存器中的值
JumpIfTrue label1 // 如果比较结果为真，跳转到 label1
LdaFalse          // 加载 false 到累加器
Jump label2       // 跳转到 label2
label1:
LdaTrue           // 加载 true 到累加器
label2:
Return            // 返回累加器的值
```

在这个例子中，`GreaterThan` 对应大于比较操作，`JumpIfTrue` 和 `Jump` 对应条件跳转和无条件跳转，`LdaTrue` 和 `LdaFalse` 对应加载布尔值常量。

**示例 3: 循环语句**

```javascript
function baz() {
  let sum = 0;
  for (let i = 0; i < 5; i++) {
    sum += i;
  }
  return sum;
}
```

`BytecodeArrayWriter` 可能会生成如下的字节码 (简化表示)：

```
// ... 函数入口 ...
LdaZero         // 加载 0 到累加器
Star r0          // 将累加器的值存储到寄存器 r0 (sum)
LdaZero         // 加载 0 到累加器
Star r1          // 将累加器的值存储到寄存器 r1 (i)
loop_start:
Ldar r1          // 加载寄存器 r1 的值到累加器
LdaSmi 5         // 加载小整数 5 到寄存器
LessThan         // 比较累加器和寄存器中的值
JumpIfFalse loop_end // 如果比较结果为假，跳转到 loop_end
Ldar r0          // 加载寄存器 r0 的值到累加器
Ldar r1          // 加载寄存器 r1 的值到累加器
Add             // 将累加器和寄存器中的值相加
Star r0          // 将累加器的值存储到寄存器 r0
Ldar r1          // 加载寄存器 r1 的值到累加器
LdaSmi 1         // 加载小整数 1 到寄存器
Add             // 将累加器和寄存器中的值相加
Star r1          // 将累加器的值存储到寄存器 r1
Jump loop_start  // 跳转到 loop_start
loop_end:
Ldar r0          // 加载寄存器 r0 的值到累加器
Return            // 返回累加器的值
```

在这个例子中，可以看到用于循环控制的比较 (`LessThan`) 和跳转指令 (`JumpIfFalse`, `Jump`)。

**总结:**

`bytecode-array-writer-unittest.cc` 这个文件是 V8 引擎内部测试基础设施的一部分，用于确保 `BytecodeArrayWriter` 能够正确地生成用于执行 JavaScript 代码的字节码。它验证了字节码生成的各个方面，从简单的指令写入到复杂的控制流和优化处理。理解这个文件的作用有助于深入了解 V8 引擎是如何将 JavaScript 代码转化为可执行的指令的。

Prompt: 
```
这是目录为v8/test/unittests/interpreter/bytecode-array-writer-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/init/v8.h"

#include "src/api/api.h"
#include "src/codegen/source-position-table.h"
#include "src/execution/isolate.h"
#include "src/heap/factory.h"
#include "src/interpreter/bytecode-array-writer.h"
#include "src/interpreter/bytecode-label.h"
#include "src/interpreter/bytecode-node.h"
#include "src/interpreter/bytecode-register.h"
#include "src/interpreter/bytecode-source-info.h"
#include "src/interpreter/constant-array-builder.h"
#include "src/utils/utils.h"
#include "src/objects/objects-inl.h"
#include "test/unittests/interpreter/bytecode-utils.h"
#include "test/unittests/test-utils.h"

namespace v8 {
namespace internal {
namespace interpreter {
namespace bytecode_array_writer_unittest {

#define B(Name) static_cast<uint8_t>(Bytecode::k##Name)
#define R(i) static_cast<uint32_t>(Register(i).ToOperand())

class BytecodeArrayWriterUnittest : public TestWithIsolateAndZone {
 public:
  BytecodeArrayWriterUnittest()
      : constant_array_builder_(zone()),
        bytecode_array_writer_(
            zone(), &constant_array_builder_,
            SourcePositionTableBuilder::RECORD_SOURCE_POSITIONS) {}
  ~BytecodeArrayWriterUnittest() override = default;

  void Write(Bytecode bytecode, BytecodeSourceInfo info = BytecodeSourceInfo());
  void Write(Bytecode bytecode, uint32_t operand0,
             BytecodeSourceInfo info = BytecodeSourceInfo());
  void Write(Bytecode bytecode, uint32_t operand0, uint32_t operand1,
             BytecodeSourceInfo info = BytecodeSourceInfo());
  void Write(Bytecode bytecode, uint32_t operand0, uint32_t operand1,
             uint32_t operand2, BytecodeSourceInfo info = BytecodeSourceInfo());
  void Write(Bytecode bytecode, uint32_t operand0, uint32_t operand1,
             uint32_t operand2, uint32_t operand3,
             BytecodeSourceInfo info = BytecodeSourceInfo());

  void WriteJump(Bytecode bytecode, BytecodeLabel* label,
                 BytecodeSourceInfo info = BytecodeSourceInfo());
  void WriteJump(Bytecode bytecode, BytecodeLabel* label, uint32_t operand1,
                 uint32_t operand2,
                 BytecodeSourceInfo info = BytecodeSourceInfo());
  void WriteJumpLoop(Bytecode bytecode, BytecodeLoopHeader* loop_header,
                     int depth, int feedback_index,
                     BytecodeSourceInfo info = BytecodeSourceInfo());

  BytecodeArrayWriter* writer() { return &bytecode_array_writer_; }
  ZoneVector<unsigned char>* bytecodes() { return writer()->bytecodes(); }
  SourcePositionTableBuilder* source_position_table_builder() {
    return writer()->source_position_table_builder();
  }

 private:
  ConstantArrayBuilder constant_array_builder_;
  BytecodeArrayWriter bytecode_array_writer_;
};

void BytecodeArrayWriterUnittest::Write(Bytecode bytecode,
                                        BytecodeSourceInfo info) {
  BytecodeNode node(bytecode, info);
  writer()->Write(&node);
}

void BytecodeArrayWriterUnittest::Write(Bytecode bytecode, uint32_t operand0,
                                        BytecodeSourceInfo info) {
  BytecodeNode node(bytecode, operand0, info);
  writer()->Write(&node);
}

void BytecodeArrayWriterUnittest::Write(Bytecode bytecode, uint32_t operand0,
                                        uint32_t operand1,
                                        BytecodeSourceInfo info) {
  BytecodeNode node(bytecode, operand0, operand1, info);
  writer()->Write(&node);
}

void BytecodeArrayWriterUnittest::Write(Bytecode bytecode, uint32_t operand0,
                                        uint32_t operand1, uint32_t operand2,
                                        BytecodeSourceInfo info) {
  BytecodeNode node(bytecode, operand0, operand1, operand2, info);
  writer()->Write(&node);
}

void BytecodeArrayWriterUnittest::Write(Bytecode bytecode, uint32_t operand0,
                                        uint32_t operand1, uint32_t operand2,
                                        uint32_t operand3,
                                        BytecodeSourceInfo info) {
  BytecodeNode node(bytecode, operand0, operand1, operand2, operand3, info);
  writer()->Write(&node);
}

void BytecodeArrayWriterUnittest::WriteJump(Bytecode bytecode,
                                            BytecodeLabel* label,
                                            BytecodeSourceInfo info) {
  BytecodeNode node(bytecode, 0, info);
  writer()->WriteJump(&node, label);
}

void BytecodeArrayWriterUnittest::WriteJump(Bytecode bytecode,
                                            BytecodeLabel* label,
                                            uint32_t operand1,
                                            uint32_t operand2,
                                            BytecodeSourceInfo info) {
  BytecodeNode node(bytecode, 0, operand1, operand2, info);
  writer()->WriteJump(&node, label);
}

void BytecodeArrayWriterUnittest::WriteJumpLoop(Bytecode bytecode,
                                                BytecodeLoopHeader* loop_header,
                                                int depth, int feedback_index,
                                                BytecodeSourceInfo info) {
  BytecodeNode node(bytecode, 0, depth, feedback_index, info);
  writer()->WriteJumpLoop(&node, loop_header);
}

TEST_F(BytecodeArrayWriterUnittest, SimpleExample) {
  CHECK_EQ(bytecodes()->size(), 0u);

  Write(Bytecode::kLdaSmi, 127, {55, true});
  CHECK_EQ(bytecodes()->size(), 2u);

  Write(Bytecode::kStar, Register(20).ToOperand());
  CHECK_EQ(bytecodes()->size(), 4u);

  Write(Bytecode::kLdar, Register(200).ToOperand());
  CHECK_EQ(bytecodes()->size(), 8u);

  Write(Bytecode::kReturn, {70, true});
  CHECK_EQ(bytecodes()->size(), 9u);

  static const uint8_t expected_bytes[] = {
      // clang-format off
      /*  0 55 S> */ B(LdaSmi), U8(127),
      /*  2       */ B(Star), R8(20),
      /*  4       */ B(Wide), B(Ldar), R16(200),
      /*  8 70 S> */ B(Return),
      // clang-format on
  };
  CHECK_EQ(bytecodes()->size(), arraysize(expected_bytes));
  for (size_t i = 0; i < arraysize(expected_bytes); ++i) {
    CHECK_EQ(bytecodes()->at(i), expected_bytes[i]);
  }

  DirectHandle<BytecodeArray> bytecode_array = writer()->ToBytecodeArray(
      isolate(), 0, 0, 0, factory()->empty_trusted_byte_array());
  bytecode_array->set_source_position_table(
      *writer()->ToSourcePositionTable(isolate()), kReleaseStore);
  CHECK_EQ(bytecodes()->size(), arraysize(expected_bytes));

  PositionTableEntry expected_positions[] = {{0, 55, true}, {8, 70, true}};
  SourcePositionTableIterator source_iterator(
      bytecode_array->SourcePositionTable());
  for (size_t i = 0; i < arraysize(expected_positions); ++i) {
    const PositionTableEntry& expected = expected_positions[i];
    CHECK_EQ(source_iterator.code_offset(), expected.code_offset);
    CHECK_EQ(source_iterator.source_position().ScriptOffset(),
             expected.source_position);
    CHECK_EQ(source_iterator.is_statement(), expected.is_statement);
    source_iterator.Advance();
  }
  CHECK(source_iterator.done());
}

TEST_F(BytecodeArrayWriterUnittest, ComplexExample) {
  static const uint8_t expected_bytes[] = {
      // clang-format off
      /*  0 42 S> */ B(LdaConstant), U8(0),
      /*  2 42 E> */ B(Add), R8(1), U8(1),
      /*  4 68 S> */ B(JumpIfUndefined), U8(36),
      /*  6       */ B(JumpIfNull), U8(34),
      /*  8       */ B(ToObject), R8(3),
      /* 10       */ B(ForInPrepare), R8(3), U8(4),
      /* 13       */ B(LdaZero),
      /* 14       */ B(Star), R8(7),
      /* 16 63 S> */ B(JumpIfForInDone), U8(24), R8(7), R8(6),
      /* 21       */ B(ForInNext), R8(3), R8(7), R8(4), U8(1),
      /* 26       */ B(JumpIfUndefined), U8(9),
      /* 28       */ B(Star), R8(0),
      /* 30       */ B(Ldar), R8(0),
      /* 32       */ B(Star), R8(2),
      /* 34 85 S> */ B(Return),
      /* 35       */ B(ForInStep), R8(7),
      /* 39       */ B(JumpLoop), U8(20), U8(0), U8(0),
      /* 43       */ B(LdaUndefined),
      /* 44 85 S> */ B(Return),
      // clang-format on
  };

  static const PositionTableEntry expected_positions[] = {
      {0, 42, true},  {2, 42, false}, {5, 68, true},
      {17, 63, true}, {34, 85, true}, {42, 85, true}};

  BytecodeLoopHeader loop_header;
  BytecodeLabel jump_for_in, jump_end_1, jump_end_2, jump_end_3;

  Write(Bytecode::kLdaConstant, U8(0), {42, true});
  Write(Bytecode::kAdd, R(1), U8(1), {42, false});
  WriteJump(Bytecode::kJumpIfUndefined, &jump_end_1, {68, true});
  WriteJump(Bytecode::kJumpIfNull, &jump_end_2);
  Write(Bytecode::kToObject, R(3));
  Write(Bytecode::kForInPrepare, R(3), U8(4));
  Write(Bytecode::kLdaZero);
  Write(Bytecode::kStar, R(7));
  writer()->BindLoopHeader(&loop_header);
  WriteJump(Bytecode::kJumpIfForInDone, &jump_end_3, R(7), R(6), {63, true});
  Write(Bytecode::kForInNext, R(3), R(7), R(4), U8(1));
  WriteJump(Bytecode::kJumpIfUndefined, &jump_for_in);
  Write(Bytecode::kStar, R(0));
  Write(Bytecode::kLdar, R(0));
  Write(Bytecode::kStar, R(2));
  Write(Bytecode::kReturn, {85, true});
  writer()->BindLabel(&jump_for_in);
  Write(Bytecode::kForInStep, R(7));
  WriteJumpLoop(Bytecode::kJumpLoop, &loop_header, 0, 0);
  writer()->BindLabel(&jump_end_1);
  writer()->BindLabel(&jump_end_2);
  writer()->BindLabel(&jump_end_3);
  Write(Bytecode::kLdaUndefined);
  Write(Bytecode::kReturn, {85, true});

  CHECK_EQ(bytecodes()->size(), arraysize(expected_bytes));
  for (size_t i = 0; i < arraysize(expected_bytes); ++i) {
    CHECK_EQ(static_cast<int>(bytecodes()->at(i)),
             static_cast<int>(expected_bytes[i]));
  }

  DirectHandle<BytecodeArray> bytecode_array = writer()->ToBytecodeArray(
      isolate(), 0, 0, 0, factory()->empty_trusted_byte_array());
  bytecode_array->set_source_position_table(
      *writer()->ToSourcePositionTable(isolate()), kReleaseStore);
  SourcePositionTableIterator source_iterator(
      bytecode_array->SourcePositionTable());
  for (size_t i = 0; i < arraysize(expected_positions); ++i) {
    const PositionTableEntry& expected = expected_positions[i];
    CHECK_EQ(source_iterator.code_offset(), expected.code_offset);
    CHECK_EQ(source_iterator.source_position().ScriptOffset(),
             expected.source_position);
    CHECK_EQ(source_iterator.is_statement(), expected.is_statement);
    source_iterator.Advance();
  }
  CHECK(source_iterator.done());
}

TEST_F(BytecodeArrayWriterUnittest, ElideNoneffectfulBytecodes) {
  if (!i::v8_flags.ignition_elide_noneffectful_bytecodes) return;

  static const uint8_t expected_bytes[] = {
      // clang-format off
      /*  0  55 S> */ B(Ldar), R8(20),
      /*  2        */ B(Star), R8(20),
      /*  4        */ B(CreateMappedArguments),
      /*  5  60 S> */ B(LdaSmi), U8(127),
      /*  7  70 S> */ B(Ldar), R8(20),
      /*  9 75 S> */ B(Return),
      // clang-format on
  };

  static const PositionTableEntry expected_positions[] = {
      {0, 55, true}, {5, 60, false}, {7, 70, true}, {9, 75, true}};

  Write(Bytecode::kLdaSmi, 127, {55, true});  // Should be elided.
  Write(Bytecode::kLdar, Register(20).ToOperand());
  Write(Bytecode::kStar, Register(20).ToOperand());
  Write(Bytecode::kLdar, Register(20).ToOperand());  // Should be elided.
  Write(Bytecode::kCreateMappedArguments);
  Write(Bytecode::kLdaSmi, 127, {60, false});  // Not elided due to source info.
  Write(Bytecode::kLdar, Register(20).ToOperand(), {70, true});
  Write(Bytecode::kReturn, {75, true});

  CHECK_EQ(bytecodes()->size(), arraysize(expected_bytes));
  for (size_t i = 0; i < arraysize(expected_bytes); ++i) {
    CHECK_EQ(static_cast<int>(bytecodes()->at(i)),
             static_cast<int>(expected_bytes[i]));
  }

  DirectHandle<BytecodeArray> bytecode_array = writer()->ToBytecodeArray(
      isolate(), 0, 0, 0, factory()->empty_trusted_byte_array());
  bytecode_array->set_source_position_table(
      *writer()->ToSourcePositionTable(isolate()), kReleaseStore);
  SourcePositionTableIterator source_iterator(
      bytecode_array->SourcePositionTable());
  for (size_t i = 0; i < arraysize(expected_positions); ++i) {
    const PositionTableEntry& expected = expected_positions[i];
    CHECK_EQ(source_iterator.code_offset(), expected.code_offset);
    CHECK_EQ(source_iterator.source_position().ScriptOffset(),
             expected.source_position);
    CHECK_EQ(source_iterator.is_statement(), expected.is_statement);
    source_iterator.Advance();
  }
  CHECK(source_iterator.done());
}

TEST_F(BytecodeArrayWriterUnittest, DeadcodeElimination) {
  static const uint8_t expected_bytes[] = {
      // clang-format off
      /*  0  55 S> */ B(LdaSmi), U8(127),
      /*  2        */ B(Jump), U8(2),
      /*  4  65 S> */ B(LdaSmi), U8(127),
      /*  6        */ B(JumpIfFalse), U8(3),
      /*  8  75 S> */ B(Return),
      /*  9       */ B(JumpIfFalse), U8(3),
      /*  11       */ B(Throw),
      /*  12       */ B(JumpIfFalse), U8(3),
      /*  14       */ B(ReThrow),
      /*  15       */ B(Return),
      // clang-format on
  };

  static const PositionTableEntry expected_positions[] = {
      {0, 55, true}, {4, 65, true}, {8, 75, true}};

  BytecodeLabel after_jump, after_conditional_jump, after_return, after_throw,
      after_rethrow;

  Write(Bytecode::kLdaSmi, 127, {55, true});
  WriteJump(Bytecode::kJump, &after_jump);
  Write(Bytecode::kLdaSmi, 127);                               // Dead code.
  WriteJump(Bytecode::kJumpIfFalse, &after_conditional_jump);  // Dead code.
  writer()->BindLabel(&after_jump);
  // We would bind the after_conditional_jump label here, but the jump to it is
  // dead.
  CHECK(!after_conditional_jump.has_referrer_jump());
  Write(Bytecode::kLdaSmi, 127, {65, true});
  WriteJump(Bytecode::kJumpIfFalse, &after_return);
  Write(Bytecode::kReturn, {75, true});
  Write(Bytecode::kLdaSmi, 127, {100, true});  // Dead code.
  writer()->BindLabel(&after_return);
  WriteJump(Bytecode::kJumpIfFalse, &after_throw);
  Write(Bytecode::kThrow);
  Write(Bytecode::kLdaSmi, 127);  // Dead code.
  writer()->BindLabel(&after_throw);
  WriteJump(Bytecode::kJumpIfFalse, &after_rethrow);
  Write(Bytecode::kReThrow);
  Write(Bytecode::kLdaSmi, 127);  // Dead code.
  writer()->BindLabel(&after_rethrow);
  Write(Bytecode::kReturn);

  CHECK_EQ(bytecodes()->size(), arraysize(expected_bytes));
  for (size_t i = 0; i < arraysize(expected_bytes); ++i) {
    CHECK_EQ(static_cast<int>(bytecodes()->at(i)),
             static_cast<int>(expected_bytes[i]));
  }

  DirectHandle<BytecodeArray> bytecode_array = writer()->ToBytecodeArray(
      isolate(), 0, 0, 0, factory()->empty_trusted_byte_array());
  bytecode_array->set_source_position_table(
      *writer()->ToSourcePositionTable(isolate()), kReleaseStore);
  SourcePositionTableIterator source_iterator(
      bytecode_array->SourcePositionTable());
  for (size_t i = 0; i < arraysize(expected_positions); ++i) {
    const PositionTableEntry& expected = expected_positions[i];
    CHECK_EQ(source_iterator.code_offset(), expected.code_offset);
    CHECK_EQ(source_iterator.source_position().ScriptOffset(),
             expected.source_position);
    CHECK_EQ(source_iterator.is_statement(), expected.is_statement);
    source_iterator.Advance();
  }
  CHECK(source_iterator.done());
}

#undef B
#undef R

}  // namespace bytecode_array_writer_unittest
}  // namespace interpreter
}  // namespace internal
}  // namespace v8

"""

```