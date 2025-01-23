Response:
Let's break down the thought process for analyzing this C++ unit test file.

**1. Initial Understanding - The Big Picture**

The file name `js-typed-lowering-unittest.cc` immediately gives a strong hint. "unittest" means it's testing specific units of code. "compiler" tells us it's related to the V8 JavaScript engine's compilation process. "js-typed-lowering" is the core: it tests the "typed lowering" phase of the compiler.

* **Key Concept:** Typed lowering is a compiler optimization step where abstract JavaScript operations are converted into more concrete, machine-understandable instructions based on type information.

**2. Scanning for Key Elements**

Now, let's look for structural elements and keywords within the code:

* **Headers:**  `#include` directives indicate dependencies. `js-typed-lowering.h` confirms the tested component. Others like `compiler/js-graph.h`, `compiler/js-operator.h`, `compiler/machine-operator.h` point to the compiler infrastructure. `test/unittests/compiler/graph-unittest.h` and `test/unittests/compiler/node-test-utils.h` are standard testing utilities.

* **Namespaces:** `v8::internal::compiler` tells us the code's organizational context within the V8 project.

* **Test Fixture:** The `JSTypedLoweringTest` class, inheriting from `TypedGraphTest`, is the foundation of the tests. The constructor and `Reduce` method are crucial.

* **`Reduce` Method:** This is the heart of the testing. It takes a `Node` (representing an operation in the compiler's intermediate representation) and uses the `JSTypedLowering` class to perform the lowering. The return value `Reduction` signifies if a transformation occurred.

* **`TEST_F` Macros:** These define individual test cases within the `JSTypedLoweringTest` fixture. Each test targets a specific JavaScript operation (e.g., `JSToName`, `JSToNumber`, `JSStrictEqual`).

* **Assertions (`ASSERT_TRUE`, `ASSERT_FALSE`, `EXPECT_EQ`, `EXPECT_THAT`):**  These are standard Google Test macros used to verify the expected outcomes of the lowering process. `EXPECT_THAT` often uses custom matchers (like `IsPlainPrimitiveToNumber`, `IsReferenceEqual`) defined in the test infrastructure.

* **Node Creation:**  Code like `graph()->NewNode(javascript()->ToName(), ...)` shows how JavaScript operations are represented as nodes in the compiler's graph.

* **Parameters and Constants:**  The tests often create input `Node`s representing parameters (with specific types) or constants.

* **Type System:**  The use of `Type::String()`, `Type::Number()`, etc., is central to the concept of typed lowering.

**3. Analyzing Individual Tests (Pattern Recognition)**

As we examine the `TEST_F` blocks, a pattern emerges:

1. **Set up:** Create input `Node`s representing the operands and context of a JavaScript operation.
2. **Execution:** Call the `Reduce` method with the `Node` representing the JavaScript operation.
3. **Verification:** Use assertions to check if a reduction occurred (`ASSERT_TRUE(r.Changed())` or `ASSERT_FALSE(r.Changed())`) and the nature of the replacement `Node` (using `EXPECT_EQ` or `EXPECT_THAT`).

**4. Inferring Functionality from Tests**

By looking at the names of the tests and the assertions, we can deduce the functionality being tested:

* **`JSToName`:** Tests how the `ToName` operation is lowered for different input types (String, Symbol, Any). It seems for String and Symbol, the input remains the same.
* **`JSToNumber`:** Checks how `ToNumber` is lowered for plain primitives. The test asserts that it's replaced with a `PlainPrimitiveToNumber` operation.
* **`JSToObject`:** Verifies the lowering of `ToObject` for `Any` and `Receiver` types. For `Receiver`, it remains the same; for `Any`, it's converted to a `Phi` node (related to control flow merging).
* **`JSToString`:**  Tests the lowering of `ToString` for Booleans, showing it's converted to a selection based on the boolean value.
* **`JSStrictEqual`:**  Focuses on how strict equality (`===`) is lowered, particularly with `the_hole` and unique objects. For unique objects, it's lowered to a reference equality check.
* **`JSShiftLeft`, `JSShiftRight`, `JSShiftRightLogical`:** Tests the lowering of bitwise shift operations with different operand types (Signed32, Unsigned32, constants). They are lowered to machine-level shift operations.
* **`JSLoadContext`, `JSStoreContext`:** Checks how accessing variables in different scopes (context) is lowered to memory load and store operations.
* **`JSLoadNamed`:** Tests how accessing properties by name (e.g., `string.length`) is lowered. For `string.length`, it's lowered to a specific `StringLength` operation.
* **`JSAdd`:**  Specifically tests string concatenation when using the `+` operator with strings.

**5. Connecting to JavaScript (If Applicable)**

For each test, if it relates to a JavaScript feature, we can create a JavaScript example:

* **`JSToName`:** `String(x)` or `Symbol(x)`
* **`JSToNumber`:** `Number(x)` or `+x`
* **`JSToObject`:** `Object(x)`
* **`JSToString`:** `String(x)` or `x.toString()`
* **`JSStrictEqual`:** `x === y`
* **`JSShiftLeft`:** `x << y`
* **`JSLoadContext` / `JSStoreContext`:**  Accessing variables in different scopes.
* **`JSLoadNamed`:** `object.property`
* **`JSAdd` (with strings):** `"hello" + "world"`

**6. Identifying Potential Programming Errors**

Looking at the lowering transformations can sometimes highlight potential JavaScript pitfalls:

* **Implicit Type Conversions:**  Operations like `JSToNumber`, `JSToString`, and `JSToObject` demonstrate how JavaScript implicitly converts types. This can sometimes lead to unexpected behavior if the programmer doesn't understand the conversion rules. For example, using `+` with a number and a string will result in string concatenation.
* **Strict Equality:** The `JSStrictEqual` tests highlight the difference between `==` and `===`. `===` avoids implicit type coercion, which can prevent subtle bugs.

**7. Considering `.tq` Files (If the Check Were True)**

The prompt includes a conditional check for `.tq` files. Torque is V8's type definition language. If the file ended in `.tq`, it would contain type definitions and potentially code for built-in functions, not unit tests for the compiler's lowering phase.

By following these steps, we can systematically analyze the C++ unit test file and extract the requested information. The key is to understand the purpose of unit tests in a compiler and then examine the structure and content of the tests to infer the functionality being verified.
## 功能列举

`v8/test/unittests/compiler/js-typed-lowering-unittest.cc` 文件是一个 **V8 JavaScript 引擎** 中 **编译器** 的 **类型化降低（Typed Lowering）** 阶段的 **单元测试** 文件。

它的主要功能是：

1. **测试 `JSTypedLowering` 类的功能:**  `JSTypedLowering` 是编译器中的一个组件，它的作用是根据 JavaScript 代码中节点的类型信息，将高级的、抽象的 JavaScript 操作（例如 `JSAdd`, `JSToNumber` 等）转换为更低级的、更接近机器指令的操作（例如 `NumberAdd`, `PlainPrimitiveToNumber` 等）。这个过程被称为“类型化降低”。

2. **验证特定 JavaScript 操作的降低结果:**  该文件中的每个 `TEST_F` 宏定义了一个具体的测试用例，用于测试特定的 JavaScript 操作在经过 `JSTypedLowering` 处理后，是否被正确地降低成了预期的底层操作。

3. **模拟不同的输入类型:** 测试用例会创建具有不同类型信息的输入节点（例如 `Type::String()`, `Type::Number()`, `Type::Any()` 等），以验证 `JSTypedLowering` 在处理不同类型输入时的行为是否正确。

4. **使用断言进行验证:**  每个测试用例都使用断言宏（例如 `ASSERT_TRUE`, `EXPECT_EQ`, `EXPECT_THAT`）来检查降低的结果是否符合预期。例如，它会检查降低是否发生了 (`r.Changed()`) 以及替换后的节点类型和输入是否正确。

**总结来说，这个文件的目的是确保编译器的类型化降低阶段能够正确地将 JavaScript 代码转换为更底层的表示形式，这是编译器优化的关键步骤。**

## 关于 `.tq` 结尾

如果 `v8/test/unittests/compiler/js-typed-lowering-unittest.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque** 源代码文件。 Torque 是一种 V8 自定义的类型定义和代码生成语言，常用于定义 V8 的内置函数和运行时代码。

在这种情况下，它将 **不会** 是一个单元测试文件，而是 **定义类型和生成代码** 的文件，与当前的 `.cc` 文件功能截然不同。

## 与 JavaScript 功能的关系及举例

该文件测试的 `JSTypedLowering` 阶段直接关系到各种 JavaScript 操作的执行效率和底层实现。  以下是一些测试用例对应的 JavaScript 功能和例子：

* **`JSToName`:**  对应 JavaScript 中将值转换为字符串或 Symbol 的操作，例如：
   ```javascript
   String(123); // 将数字转换为字符串
   Symbol('mySymbol'); // 创建一个 Symbol
   ```
   该测试用例验证了当输入已经是 String 或 Symbol 时，`JSToName` 是否进行了正确的处理（没有不必要的转换）。

* **`JSToNumber`:** 对应 JavaScript 中将值转换为数字的操作，例如：
   ```javascript
   Number("123"); // 将字符串转换为数字
   +"456";       // 一元加号运算符也会将值转换为数字
   ```
   该测试用例验证了当输入是基本类型时，`JSToNumber` 能否正确地降低为 `PlainPrimitiveToNumber` 操作。

* **`JSToObject`:** 对应 JavaScript 中将值转换为对象的操作，例如：
   ```javascript
   Object(123);    // 将数字包装成 Number 对象
   Object("abc");   // 将字符串包装成 String 对象
   Object(null);   // 返回全局对象
   Object(undefined); // 返回全局对象
   ```
   该测试用例验证了对于 `Receiver` 类型（例如对象），`JSToObject` 是否能正确处理而不进行额外的转换。

* **`JSToString`:** 对应 JavaScript 中将值转换为字符串的操作，例如：
   ```javascript
   String(true); // 将布尔值转换为字符串 "true"
   123 + "";     // 通过与空字符串连接将数字转换为字符串
   ```
   该测试用例验证了将布尔值转换为字符串时，`JSTypedLowering` 能否生成正确的选择节点，根据布尔值选择 `"true"` 或 `"false"`。

* **`JSStrictEqual`:** 对应 JavaScript 中的严格相等运算符 `===`，例如：
   ```javascript
   123 === 123;    // true
   "abc" === "abc"; // true
   1 === "1";      // false (类型不同)
   ```
   该测试用例验证了当比较的对象是唯一的（Unique）时，`JSStrictEqual` 能否降低为引用相等比较。

* **`JSShiftLeft`，`JSShiftRight`，`JSShiftRightLogical`:** 对应 JavaScript 中的位移运算符 `<<`, `>>`, `>>>`，例如：
   ```javascript
   10 << 2;  // 左移，结果为 40
   -16 >> 2; // 右移，结果为 -4
   -16 >>> 2; // 无符号右移，结果为 1073741820
   ```
   这些测试用例验证了当操作数为 `Signed32` 或 `Unsigned32` 类型时，位移操作能否正确降低为底层的位移指令。

* **`JSLoadContext`，`JSStoreContext`:** 对应 JavaScript 中访问和修改作用域链中的变量，例如：
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
   这些测试用例验证了 `JSLoadContext` 和 `JSStoreContext` 能否正确地降低为从上下文（作用域链）加载和存储值的操作。

* **`JSLoadNamed`:** 对应 JavaScript 中访问对象的属性，例如：
   ```javascript
   const obj = { name: "John", age: 30 };
   console.log(obj.name); // 访问 name 属性
   console.log("hello".length); // 访问字符串的 length 属性
   ```
   该测试用例验证了访问字符串的 `length` 属性时，`JSLoadNamed` 能否正确降低为获取字符串长度的操作。

* **`JSAdd`:** 对应 JavaScript 中的加法运算符 `+`，既可以用于数字相加，也可以用于字符串拼接，例如：
   ```javascript
   5 + 3;       // 数字相加
   "hello" + " world"; // 字符串拼接
   ```
   该测试用例验证了当操作数为字符串时，`JSAdd` 能否正确降低为字符串拼接操作。

## 代码逻辑推理 (假设输入与输出)

以下以 `JSToNumberWithPlainPrimitive` 测试用例为例进行代码逻辑推理：

**假设输入：**

* `input` 节点表示一个类型为 `Type::PlainPrimitive()` 的参数，例如，它可以代表一个已知是数字或布尔值的变量。
* 其他节点 `context`, `effect`, `control` 代表执行上下文、副作用和控制流。

**代码逻辑：**

1. `Reduce` 函数被调用，传入表示 `javascript()->ToNumber()` 操作的节点，以及其输入 `input` 和其他上下文信息。
2. `JSTypedLowering` 的 `Reduce` 方法会分析 `ToNumber` 操作和输入 `input` 的类型。
3. 因为 `input` 的类型是 `Type::PlainPrimitive()`，`JSTypedLowering` 会判断这是一个可以直接转换为数字的基本类型。
4. 因此，`ToNumber` 操作会被降低为 `IsPlainPrimitiveToNumber(input)`，这是一个更底层的操作，直接将基本类型转换为数字。

**预期输出：**

* `r.Changed()` 为 `true`，表示发生了降低。
* `r.replacement()` 指向一个新的节点，该节点是通过 `IsPlainPrimitiveToNumber(input)` 构建的，它代表了将基本类型转换为数字的底层操作，并且输入仍然是原来的 `input` 节点。

## 用户常见的编程错误举例

`js-typed-lowering-unittest.cc` 中的测试用例及其对应的 JavaScript 功能，可以帮助我们理解一些常见的编程错误：

1. **类型转换错误 (与 `JSToNumber`, `JSToString`, `JSToObject` 相关):**  程序员可能没有意识到 JavaScript 会进行隐式的类型转换，导致意想不到的结果。

   ```javascript
   console.log(5 + "3"); // 输出 "53"，字符串拼接，而不是数字加法

   if ("0") { // 字符串 "0" 在布尔上下文中被认为是 true
     console.log("This will print");
   }

   const obj = {};
   console.log(obj.toString()); // 输出 "[object Object]"，而不是程序员期望的更有意义的字符串表示
   ```

2. **误用相等运算符 (与 `JSStrictEqual` 相关):** 使用非严格相等 `==` 时，JavaScript 会进行类型转换，可能导致不符合预期的比较结果。

   ```javascript
   console.log(1 == "1");  // 输出 true，因为会进行类型转换
   console.log(1 === "1"); // 输出 false，类型不同
   ```

3. **位运算的理解不足 (与 `JSShiftLeft`, `JSShiftRight`, `JSShiftRightLogical` 相关):**  程序员可能不清楚位运算的细节，例如有符号右移和无符号右移的区别，导致计算错误。

   ```javascript
   console.log(-16 >> 2);  // 输出 -4
   console.log(-16 >>> 2); // 输出 1073741820，结果大相径庭
   ```

4. **作用域理解错误 (与 `JSLoadContext`, `JSStoreContext` 相关):**  在闭包中访问或修改外部作用域的变量时，如果理解不透彻，可能会导致变量的值不符合预期。

   ```javascript
   function createCounter() {
     let count = 0;
     return function() {
       count++;
       
### 提示词
```
这是目录为v8/test/unittests/compiler/js-typed-lowering-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/js-typed-lowering-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```