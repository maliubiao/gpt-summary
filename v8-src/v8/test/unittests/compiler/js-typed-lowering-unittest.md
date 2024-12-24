Response: Let's break down the thought process for analyzing this C++ code and summarizing its functionality, particularly focusing on the connection to JavaScript.

1. **Understand the Goal:** The primary request is to understand the *purpose* of this C++ file. It's located within the V8 project, specifically in a `compiler` and `unittests` directory. This strongly suggests it's a testing file for compiler functionality.

2. **Identify Key Components:** Scan the code for important classes, functions, and namespaces.
    * `v8::internal::compiler`:  This namespace confirms it's related to the V8 compiler.
    * `JSTypedLowering`: The class name itself is very informative. "Typed Lowering" implies a process of converting higher-level, potentially type-agnostic operations into lower-level, type-specific instructions. The "JS" prefix indicates a connection to JavaScript.
    * `JSTypedLoweringTest`:  The `Test` suffix clearly marks this as a unit test class.
    * `Reduce(Node* node)`: This function is central to the testing process. It takes a `Node` (likely representing an operation in the compiler's intermediate representation) and seems to apply some kind of transformation.
    * `JSOperatorBuilder`, `MachineOperatorBuilder`, `SimplifiedOperatorBuilder`: These seem to be helpers for creating different types of operations within the compiler's graph representation.
    * `TEST_F(...)`: These are the individual test cases. The names of the test cases (e.g., `JSToNameWithString`, `JSToNumberWithPlainPrimitive`) are crucial for understanding what specific compiler transformations are being tested.

3. **Focus on the `Reduce` Function:** This function is the core of the tests. It sets up the necessary components for the `JSTypedLowering` class and then calls `reducer.Reduce(node)`. This confirms that the tests are about verifying the behavior of the `JSTypedLowering::Reduce` method.

4. **Analyze the Test Cases:**  Examine the structure of each test case. They generally follow a pattern:
    * Create input `Node`s representing JavaScript operations (using `javascript()->...`).
    * Call the `Reduce` function.
    * Use `ASSERT_TRUE(r.Changed())` or `ASSERT_FALSE(r.Changed())` to check if a transformation occurred.
    * Use `EXPECT_EQ` or `EXPECT_THAT` to assert the result of the transformation. The `Is...` functions (like `IsPlainPrimitiveToNumber`, `IsStringConcat`) provide hints about the expected low-level operations.

5. **Connect Test Cases to JavaScript Concepts:**  This is where the connection to JavaScript becomes clear. The test case names and the `javascript()->...` calls directly correspond to JavaScript operations:
    * `JSToName`:  JavaScript's abstract operation of converting a value to a name (string or symbol).
    * `JSToNumber`: JavaScript's `Number()` conversion.
    * `JSToObject`: JavaScript's `Object()` conversion.
    * `JSToString`: JavaScript's `String()` conversion.
    * `JSStrictEqual`: JavaScript's `===` operator.
    * `JSShiftLeft`, `JSShiftRight`, `JSShiftRightLogical`: JavaScript's bitwise shift operators (`<<`, `>>`, `>>>`).
    * `JSLoadContext`, `JSStoreContext`: Operations related to accessing and modifying variables in JavaScript's scope (lexical environments).
    * `JSLoadNamed`: Accessing properties of JavaScript objects (e.g., `string.length`).
    * `JSAdd`: JavaScript's `+` operator (specifically string concatenation in one case).

6. **Infer the Role of `JSTypedLowering`:** Based on the test cases, the `JSTypedLowering` class seems to be responsible for:
    * **Type-Specific Optimizations:**  When the input type is known, it replaces generic JavaScript operations with more efficient, lower-level machine or simplified operations. For example, `JSToName` becomes a no-op for strings and symbols. `JSToNumber` becomes `PlainPrimitiveToNumber` for primitive types. `JSStrictEqual` can be optimized to `ReferenceEqual` for unique types.
    * **Handling Specific Cases:**  It handles specific JavaScript behaviors, like converting booleans to strings (`"true"`/`"false"`) in `JSToString`.
    * **Lowering to Machine Operations:**  Many tests show JavaScript operations being replaced with machine-level operations (e.g., bitwise shifts).

7. **Construct the Summary:** Combine the observations into a coherent description.
    * Start with the basic function: unit testing.
    * Identify the class under test: `JSTypedLowering`.
    * Explain the purpose of `JSTypedLowering`: optimizing JavaScript operations based on type information during compilation.
    * Provide concrete examples from the test cases, mapping the JavaScript operation to the optimized C++ equivalent.
    * Illustrate with JavaScript examples to make the connection clear.

8. **Refine and Organize:** Ensure the summary is clear, concise, and well-organized. Use headings or bullet points to separate different aspects of the functionality. Double-check for accuracy and clarity in the JavaScript examples. For instance, explicitly mentioning the string concatenation aspect of `JSAdd` is important.

Self-Correction Example During the Process:

* **Initial thought:** "This file seems to be testing basic JavaScript functionality."
* **Correction:** "While it *relates* to JavaScript functionality, it's specifically testing the *compiler's optimization* of those operations, not the fundamental behavior itself. The focus is on *how* V8 transforms the JavaScript code internally."  This leads to a more accurate description of the file's purpose.

By following these steps, we can systematically analyze the C++ code and generate a comprehensive and accurate summary that highlights its function and its relationship to JavaScript.
这个C++源代码文件 `v8/test/unittests/compiler/js-typed-lowering-unittest.cc` 是 V8 JavaScript 引擎的一部分，它的主要功能是**测试编译器中 `JSTypedLowering` 阶段的正确性**。

**`JSTypedLowering` 的功能：**

`JSTypedLowering` 是 V8 编译器中的一个关键阶段，它的目标是将高级的、类型不确定的 JavaScript 抽象操作（例如 `JSAdd`, `JSToNumber` 等）转换成更低级的、类型化的机器操作或简化的操作。这个过程会利用类型反馈信息（如果有）来做出更优化的决策。简单来说，它负责根据变量的类型信息，将通用的 JavaScript 操作转换成更具体的、更高效的底层实现。

**文件内容归纳：**

这个单元测试文件包含了多个测试用例（通过 `TEST_F` 宏定义），每个测试用例针对 `JSTypedLowering` 阶段对特定的 JavaScript 操作的处理进行验证。  主要测试了以下 JavaScript 操作的 lowering 过程：

* **类型转换操作:**
    * `JSToName`: 测试将值转换为名称（字符串或 Symbol）的操作。
    * `JSToNumber`: 测试将值转换为数字的操作。
    * `JSToObject`: 测试将值转换为对象的操作。
    * `JSToString`: 测试将值转换为字符串的操作。
* **比较操作:**
    * `JSStrictEqual`: 测试严格相等 (`===`) 比较操作。
* **位运算操作:**
    * `JSShiftLeft`: 测试左移 (`<<`) 操作。
    * `JSShiftRight`: 测试算术右移 (`>>`) 操作。
    * `JSShiftRightLogical`: 测试无符号右移 (`>>>`) 操作。
* **上下文操作:**
    * `JSLoadContext`: 测试加载上下文变量的操作。
    * `JSStoreContext`: 测试存储上下文变量的操作。
* **属性访问:**
    * `JSLoadNamed`: 测试访问命名属性的操作 (例如字符串的 `length` 属性)。
* **算术运算:**
    * `JSAdd`: 测试加法 (`+`) 操作，特别是字符串连接的情况。

**与 JavaScript 功能的关系及示例：**

这个测试文件直接验证了 V8 编译器如何处理各种 JavaScript 语言结构。  `JSTypedLowering` 的目标就是优化这些操作，使其在底层能够更高效地执行。

以下是一些测试用例对应的 JavaScript 功能示例：

1. **`JSToNameWithString` 和 `JSToNameWithSymbol`:**
   - **JavaScript:**  在需要字符串或 Symbol 的地方使用任何值时，JavaScript 引擎会尝试将其转换为字符串或 Symbol。例如：
     ```javascript
     const obj = { toString: () => 'my object' };
     console.log('Prefix ' + obj); // obj 会被转换为字符串 "my object"
     const sym = Symbol('mySymbol');
     console.log(sym.description); // sym 本身就是一个 Symbol，不需要转换
     ```
   - 这个测试验证了当输入已经是字符串或 Symbol 时，`JSTypedLowering` 不会进行多余的操作。

2. **`JSToNumberWithPlainPrimitive`:**
   - **JavaScript:** 使用 `Number()` 函数或进行涉及数字的运算时，非数字类型的值会被转换为数字。
     ```javascript
     console.log(Number('123')); // 输出 123
     console.log(10 + '5');     // '5' 会被转换为数字 5，然后进行加法运算 (这里需要注意 JavaScript 的 + 运算符的重载)
     console.log(10 + +'5');    // 使用一元加号将 '5' 显式转换为数字
     ```
   - 这个测试验证了当输入是原始类型时，`JSTypedLowering` 会将其转换为数字类型。

3. **`JSToObjectWithAny` 和 `JSToObjectWithReceiver`:**
   - **JavaScript:** 使用 `Object()` 函数可以将原始类型的值转换为对应的包装对象，而对象类型的值保持不变。
     ```javascript
     console.log(typeof Object(10));      // 输出 "object"
     console.log(typeof Object('hello'));  // 输出 "object"
     const arr = [1, 2, 3];
     console.log(Object(arr) === arr);   // 输出 true，对象类型不变
     ```
   - 这些测试验证了 `JSTypedLowering` 如何处理不同类型的输入进行对象转换。

4. **`JSToStringWithBoolean`:**
   - **JavaScript:** 将布尔值转换为字符串时，`true` 变为 `"true"`，`false` 变为 `"false"`。
     ```javascript
     console.log(String(true));  // 输出 "true"
     console.log(String(false)); // 输出 "false"
     ```
   - 这个测试验证了 `JSTypedLowering` 会将布尔值转换为对应的字符串常量。

5. **`JSStrictEqualWithUnique`:**
   - **JavaScript:** 严格相等 (`===`) 运算符比较值和类型。对于对象来说，比较的是引用。
     ```javascript
     const obj1 = {};
     const obj2 = {};
     console.log(obj1 === obj2); // 输出 false (不同的对象引用)
     const obj3 = obj1;
     console.log(obj1 === obj3); // 输出 true (相同的对象引用)
     ```
   - 这个测试验证了当比较的类型是唯一（例如 Symbol）时，`JSTypedLowering` 可以直接使用引用相等性进行优化。

6. **`JSShiftLeftWithSigned32AndConstant` 等位运算测试:**
   - **JavaScript:** JavaScript 中的位运算符会将操作数转换为 32 位整数进行运算。
     ```javascript
     console.log(10 << 2);  // 左移 2 位，相当于乘以 4，输出 40
     console.log(-8 >> 1); // 算术右移 1 位，保留符号，输出 -4
     console.log(16 >>> 2); // 无符号右移 2 位，输出 4
     ```
   - 这些测试验证了 `JSTypedLowering` 如何将 JavaScript 的位运算操作降低到更底层的机器位运算指令。

7. **`JSLoadContext` 和 `JSStoreContext`:**
   - **JavaScript:**  涉及访问和修改作用域中的变量。
     ```javascript
     function outer() {
       let x = 10;
       function inner() {
         console.log(x); // 访问外部作用域的变量 x
         x = 20;         // 修改外部作用域的变量 x
       }
       inner();
     }
     outer();
     ```
   - 这些测试验证了 `JSTypedLowering` 如何处理访问和修改不同作用域层次上的变量。

8. **`JSLoadNamedStringLength`:**
   - **JavaScript:** 访问字符串的 `length` 属性。
     ```javascript
     const str = "hello";
     console.log(str.length); // 输出 5
     ```
   - 这个测试验证了 `JSTypedLowering` 会将访问字符串 `length` 属性的操作优化为直接获取字符串长度的指令。

9. **`JSAddWithString`:**
   - **JavaScript:**  当 `+` 运算符的操作数中至少有一个是字符串时，执行字符串连接。
     ```javascript
     console.log("hello" + " world"); // 输出 "hello world"
     console.log(10 + " apples");   // 输出 "10 apples" (数字 10 被转换为字符串)
     ```
   - 这个测试验证了 `JSTypedLowering` 会将字符串连接操作转换为专门的字符串连接指令。

**总结:**

总而言之，`v8/test/unittests/compiler/js-typed-lowering-unittest.cc` 文件通过一系列单元测试，确保 V8 编译器中的 `JSTypedLowering` 阶段能够正确地将各种 JavaScript 操作转换为更底层的表示形式，从而提高代码的执行效率。每个测试用例都针对特定的 JavaScript 语法或操作，验证了类型推断和 lowering 过程的正确性。

Prompt: 
```
这是目录为v8/test/unittests/compiler/js-typed-lowering-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/js-typed-lowering.h"

#include "src/compiler/access-builder.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/js-operator.h"
#include "src/compiler/machine-operator.h"
#include "src/execution/isolate-inl.h"
#include "test/unittests/compiler/graph-unittest.h"
#include "test/unittests/compiler/node-test-utils.h"
#include "testing/gmock-support.h"

using testing::_;
using testing::BitEq;
using testing::IsNaN;


namespace v8 {
namespace internal {
namespace compiler {

namespace {

const size_t kIndices[] = {0, 1, 42, 100, 1024};

Type const kJSTypes[] = {Type::Undefined(), Type::Null(),   Type::Boolean(),
                         Type::Number(),    Type::String(), Type::Object()};

}  // namespace


class JSTypedLoweringTest : public TypedGraphTest {
 public:
  JSTypedLoweringTest()
      : TypedGraphTest(3), javascript_(zone()), deps_(broker(), zone()) {}
  ~JSTypedLoweringTest() override = default;

 protected:
  Reduction Reduce(Node* node) {
    MachineOperatorBuilder machine(zone());
    SimplifiedOperatorBuilder simplified(zone());
    JSGraph jsgraph(isolate(), graph(), common(), javascript(), &simplified,
                    &machine);
    GraphReducer graph_reducer(zone(), graph(), tick_counter(), broker());
    JSTypedLowering reducer(&graph_reducer, &jsgraph, broker(), zone());
    return reducer.Reduce(node);
  }

  JSOperatorBuilder* javascript() { return &javascript_; }

 private:
  JSOperatorBuilder javascript_;
  CompilationDependencies deps_;
};



// -----------------------------------------------------------------------------
// JSToName

TEST_F(JSTypedLoweringTest, JSToNameWithString) {
  Node* const input = Parameter(Type::String(), 0);
  Node* const context = Parameter(Type::Any(), 1);
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  Reduction r = Reduce(graph()->NewNode(javascript()->ToName(), input, context,
                                        EmptyFrameState(), effect, control));
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(input, r.replacement());
}

TEST_F(JSTypedLoweringTest, JSToNameWithSymbol) {
  Node* const input = Parameter(Type::Symbol(), 0);
  Node* const context = Parameter(Type::Any(), 1);
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  Reduction r = Reduce(graph()->NewNode(javascript()->ToName(), input, context,
                                        EmptyFrameState(), effect, control));
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(input, r.replacement());
}

TEST_F(JSTypedLoweringTest, JSToNameWithAny) {
  Node* const input = Parameter(Type::Any(), 0);
  Node* const context = Parameter(Type::Any(), 1);
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  Reduction r = Reduce(graph()->NewNode(javascript()->ToName(), input, context,
                                        EmptyFrameState(), effect, control));
  ASSERT_FALSE(r.Changed());
}

// -----------------------------------------------------------------------------
// JSToNumber

TEST_F(JSTypedLoweringTest, JSToNumberWithPlainPrimitive) {
  Node* const input = Parameter(Type::PlainPrimitive(), 0);
  Node* const context = Parameter(Type::Any(), 1);
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  Reduction r =
      Reduce(graph()->NewNode(javascript()->ToNumber(), input, context,
                              EmptyFrameState(), effect, control));
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsPlainPrimitiveToNumber(input));
}


// -----------------------------------------------------------------------------
// JSToObject


TEST_F(JSTypedLoweringTest, JSToObjectWithAny) {
  Node* const input = Parameter(Type::Any(), 0);
  Node* const context = Parameter(Type::Any(), 1);
  Node* const frame_state = EmptyFrameState();
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  Reduction r = Reduce(graph()->NewNode(javascript()->ToObject(), input,
                                        context, frame_state, effect, control));
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsPhi(MachineRepresentation::kTagged, _, _, _));
}


TEST_F(JSTypedLoweringTest, JSToObjectWithReceiver) {
  Node* const input = Parameter(Type::Receiver(), 0);
  Node* const context = Parameter(Type::Any(), 1);
  Node* const frame_state = EmptyFrameState();
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  Reduction r = Reduce(graph()->NewNode(javascript()->ToObject(), input,
                                        context, frame_state, effect, control));
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(input, r.replacement());
}


// -----------------------------------------------------------------------------
// JSToString


TEST_F(JSTypedLoweringTest, JSToStringWithBoolean) {
  Node* const input = Parameter(Type::Boolean(), 0);
  Node* const context = Parameter(Type::Any(), 1);
  Node* const frame_state = EmptyFrameState();
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  Reduction r = Reduce(graph()->NewNode(javascript()->ToString(), input,
                                        context, frame_state, effect, control));
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(),
              IsSelect(MachineRepresentation::kTagged, input,
                       IsHeapConstant(factory()->true_string()),
                       IsHeapConstant(factory()->false_string())));
}


// -----------------------------------------------------------------------------
// JSStrictEqual

namespace {

FeedbackSource FeedbackSourceWithOneBinarySlot(JSTypedLoweringTest* R) {
  return FeedbackSource{
      FeedbackVector::NewWithOneBinarySlotForTesting(R->zone(), R->isolate()),
      FeedbackSlot{0}};
}

FeedbackSource FeedbackSourceWithOneCompareSlot(JSTypedLoweringTest* R) {
  return FeedbackSource{
      FeedbackVector::NewWithOneCompareSlotForTesting(R->zone(), R->isolate()),
      FeedbackSlot{0}};
}

}  // namespace

TEST_F(JSTypedLoweringTest, JSStrictEqualWithTheHole) {
  Node* const the_hole = HeapConstantHole(factory()->the_hole_value());
  Node* const feedback = UndefinedConstant();
  Node* const context = UndefinedConstant();
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  TRACED_FOREACH(Type, type, kJSTypes) {
    Node* const lhs = Parameter(type);
    Reduction r = Reduce(graph()->NewNode(
        javascript()->StrictEqual(FeedbackSourceWithOneCompareSlot(this)), lhs,
        the_hole, feedback, context, effect, control));
    ASSERT_FALSE(r.Changed());
  }
}


TEST_F(JSTypedLoweringTest, JSStrictEqualWithUnique) {
  Node* const lhs = Parameter(Type::Unique(), 0);
  Node* const rhs = Parameter(Type::Unique(), 1);
  Node* const feedback = UndefinedConstant();
  Node* const context = Parameter(Type::Any(), 2);
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  Reduction r = Reduce(graph()->NewNode(
      javascript()->StrictEqual(FeedbackSourceWithOneCompareSlot(this)), lhs,
      rhs, feedback, context, effect, control));
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsReferenceEqual(lhs, rhs));
}


// -----------------------------------------------------------------------------
// JSShiftLeft

TEST_F(JSTypedLoweringTest, JSShiftLeftWithSigned32AndConstant) {
  Node* const lhs = Parameter(Type::Signed32());
  Node* const feedback = UndefinedConstant();
  Node* const context = UndefinedConstant();
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  TRACED_FORRANGE(double, rhs, 0, 31) {
    Reduction r = Reduce(graph()->NewNode(
        javascript()->ShiftLeft(FeedbackSourceWithOneBinarySlot(this)), lhs,
        NumberConstant(rhs), feedback, context, EmptyFrameState(), effect,
        control));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsNumberShiftLeft(lhs, IsNumberConstant(BitEq(rhs))));
  }
}

TEST_F(JSTypedLoweringTest, JSShiftLeftWithSigned32AndUnsigned32) {
  Node* const lhs = Parameter(Type::Signed32());
  Node* const rhs = Parameter(Type::Unsigned32());
  Node* const feedback = UndefinedConstant();
  Node* const context = UndefinedConstant();
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  Reduction r = Reduce(graph()->NewNode(
      javascript()->ShiftLeft(FeedbackSourceWithOneBinarySlot(this)), lhs, rhs,
      feedback, context, EmptyFrameState(), effect, control));
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsNumberShiftLeft(lhs, rhs));
}


// -----------------------------------------------------------------------------
// JSShiftRight


TEST_F(JSTypedLoweringTest, JSShiftRightWithSigned32AndConstant) {
  Node* const lhs = Parameter(Type::Signed32());
  Node* const feedback = UndefinedConstant();
  Node* const context = UndefinedConstant();
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  TRACED_FORRANGE(double, rhs, 0, 31) {
    Reduction r = Reduce(graph()->NewNode(
        javascript()->ShiftRight(FeedbackSourceWithOneBinarySlot(this)), lhs,
        NumberConstant(rhs), feedback, context, EmptyFrameState(), effect,
        control));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsNumberShiftRight(lhs, IsNumberConstant(BitEq(rhs))));
  }
}


TEST_F(JSTypedLoweringTest, JSShiftRightWithSigned32AndUnsigned32) {
  Node* const lhs = Parameter(Type::Signed32());
  Node* const rhs = Parameter(Type::Unsigned32());
  Node* const feedback = UndefinedConstant();
  Node* const context = UndefinedConstant();
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  Reduction r = Reduce(graph()->NewNode(
      javascript()->ShiftRight(FeedbackSourceWithOneBinarySlot(this)), lhs, rhs,
      feedback, context, EmptyFrameState(), effect, control));
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsNumberShiftRight(lhs, rhs));
}


// -----------------------------------------------------------------------------
// JSShiftRightLogical


TEST_F(JSTypedLoweringTest,
                   JSShiftRightLogicalWithUnsigned32AndConstant) {
  Node* const lhs = Parameter(Type::Unsigned32());
  Node* const feedback = UndefinedConstant();
  Node* const context = UndefinedConstant();
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  TRACED_FORRANGE(double, rhs, 0, 31) {
    Reduction r = Reduce(graph()->NewNode(
        javascript()->ShiftRightLogical(FeedbackSourceWithOneBinarySlot(this)),
        lhs, NumberConstant(rhs), feedback, context, EmptyFrameState(), effect,
        control));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsNumberShiftRightLogical(lhs, IsNumberConstant(BitEq(rhs))));
  }
}


TEST_F(JSTypedLoweringTest, JSShiftRightLogicalWithUnsigned32AndUnsigned32) {
  Node* const lhs = Parameter(Type::Unsigned32());
  Node* const rhs = Parameter(Type::Unsigned32());
  Node* const feedback = UndefinedConstant();
  Node* const context = UndefinedConstant();
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  Reduction r = Reduce(graph()->NewNode(
      javascript()->ShiftRightLogical(FeedbackSourceWithOneBinarySlot(this)),
      lhs, rhs, feedback, context, EmptyFrameState(), effect, control));
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsNumberShiftRightLogical(lhs, rhs));
}


// -----------------------------------------------------------------------------
// JSLoadContext


TEST_F(JSTypedLoweringTest, JSLoadContext) {
  Node* const context = Parameter(Type::Any());
  Node* const effect = graph()->start();
  static bool kBooleans[] = {false, true};
  TRACED_FOREACH(size_t, index, kIndices) {
    TRACED_FOREACH(bool, immutable, kBooleans) {
      Reduction const r1 = Reduce(graph()->NewNode(
          javascript()->LoadContext(0, index, immutable), context, effect));
      ASSERT_TRUE(r1.Changed());
      EXPECT_THAT(r1.replacement(),
                  IsLoadField(AccessBuilder::ForContextSlot(index), context,
                              effect, graph()->start()));

      Reduction const r2 = Reduce(graph()->NewNode(
          javascript()->LoadContext(1, index, immutable), context, effect));
      ASSERT_TRUE(r2.Changed());
      EXPECT_THAT(
          r2.replacement(),
          IsLoadField(AccessBuilder::ForContextSlot(index),
                      IsLoadField(AccessBuilder::ForContextSlotKnownPointer(
                                      Context::PREVIOUS_INDEX),
                                  context, effect, graph()->start()),
                      _, graph()->start()));
    }
  }
}


// -----------------------------------------------------------------------------
// JSStoreContext


TEST_F(JSTypedLoweringTest, JSStoreContext) {
  Node* const context = Parameter(Type::Any());
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  TRACED_FOREACH(size_t, index, kIndices) {
    TRACED_FOREACH(Type, type, kJSTypes) {
      Node* const value = Parameter(type);

      Reduction const r1 =
          Reduce(graph()->NewNode(javascript()->StoreContext(0, index), value,
                                  context, effect, control));
      ASSERT_TRUE(r1.Changed());
      EXPECT_THAT(r1.replacement(),
                  IsStoreField(AccessBuilder::ForContextSlot(index), context,
                               value, effect, control));

      Reduction const r2 =
          Reduce(graph()->NewNode(javascript()->StoreContext(1, index), value,
                                  context, effect, control));
      ASSERT_TRUE(r2.Changed());
      EXPECT_THAT(
          r2.replacement(),
          IsStoreField(AccessBuilder::ForContextSlot(index),
                       IsLoadField(AccessBuilder::ForContextSlotKnownPointer(
                                       Context::PREVIOUS_INDEX),
                                   context, effect, graph()->start()),
                       value, _, control));
    }
  }
}


// -----------------------------------------------------------------------------
// JSLoadNamed


TEST_F(JSTypedLoweringTest, JSLoadNamedStringLength) {
  NameRef name = broker()->length_string();
  Node* const receiver = Parameter(Type::String(), 0);
  Node* const feedback = UndefinedConstant();
  Node* const context = UndefinedConstant();
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  Reduction const r = Reduce(graph()->NewNode(
      javascript()->LoadNamed(name, FeedbackSource{}), receiver, feedback,
      context, EmptyFrameState(), effect, control));
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsStringLength(receiver));
}


// -----------------------------------------------------------------------------
// JSAdd


TEST_F(JSTypedLoweringTest, JSAddWithString) {
  Node* lhs = Parameter(Type::String(), 0);
  Node* rhs = Parameter(Type::String(), 1);
  Node* const feedback = UndefinedConstant();
  Node* context = Parameter(Type::Any(), 2);
  Node* frame_state = EmptyFrameState();
  Node* effect = graph()->start();
  Node* control = graph()->start();
  Reduction r = Reduce(graph()->NewNode(
      javascript()->Add(FeedbackSourceWithOneBinarySlot(this)), lhs, rhs,
      feedback, context, frame_state, effect, control));
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsStringConcat(_, lhs, rhs));
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```