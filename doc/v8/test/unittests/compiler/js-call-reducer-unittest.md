Response:
Let's break down the thought process for analyzing the given C++ code snippet.

1. **Understanding the Core Task:** The request asks for the functionality of `v8/test/unittests/compiler/js-call-reducer-unittest.cc`. The `.cc` extension strongly suggests C++ source code, and the name itself ("js-call-reducer-unittest") gives a significant clue about its purpose: testing a component called "JSCallReducer."

2. **Initial Code Scan - Identifying Key Elements:**  A quick scan reveals:
    * Standard C++ includes (`<cctype>`).
    * V8 specific includes (`"src/..."`). These are the most important parts. They tell us what V8 components are being used. Specifically, look for:
        * `js-call-reducer.h`: This is likely the header file for the class being tested.
        * `compiler/`: This confirms it's part of the compiler infrastructure.
        * `test/unittests/`:  Clearly indicates it's a unit test.
        * `graph-unittest.h`, `node-test-utils.h`:  These suggest the tests involve manipulating and checking the compiler's intermediate representation (the "graph" of operations).
    * A C++ namespace structure (`namespace v8 { namespace internal { namespace compiler { ... }}}`).
    * A test fixture class `JSCallReducerTest` inheriting from `TypedGraphTest`. This is the standard Google Test setup.
    * A `Reduce` method. This is a strong indicator of what the `JSCallReducer` does - it "reduces" or simplifies nodes in the graph.
    * Helper methods like `GlobalFunction`, `MathFunction`, `StringFunction`, `NumberFunction`. These seem designed to easily create nodes representing calls to global functions or methods of built-in objects.
    * `TEST_F` macros. These are the individual test cases. Their names provide hints about what specific scenarios are being tested (e.g., `PromiseConstructorNoArgs`, `MathUnaryWithNumber`).

3. **Focusing on `JSCallReducer`:** The core of the file is about testing `JSCallReducer`. The `Reduce` method is central. It takes a `Node*` (a node in the compiler graph) as input and returns a `Reduction`. This confirms the reducer's role in transforming nodes.

4. **Analyzing Test Cases:**  Examine the individual `TEST_F` blocks. Notice the patterns:
    * Setting up input nodes (representing function calls, constructors, etc.) using the helper functions.
    * Calling the `Reduce` method on these nodes.
    * Assertions (using `ASSERT_TRUE`, `ASSERT_FALSE`, `EXPECT_THAT`) to check the outcome of the reduction. The `EXPECT_THAT` often compares the opcode of the resulting node to an expected value.

5. **Inferring Functionality from Test Cases:** This is the crucial step. By looking at what's being tested, we can infer the `JSCallReducer`'s capabilities:
    * **Promise Constructor Optimization:** Tests like `PromiseConstructorNoArgs`, `PromiseConstructorSubclass`, `PromiseConstructorBasic`, `PromiseConstructorWithHook` suggest the reducer tries to optimize calls to the `Promise` constructor. The "WithHook" test hints at handling cases where optimizations might be invalidated.
    * **Math Function Optimization:** Tests like `MathUnaryWithNumber`, `MathBinaryWithNumber`, `MathClz32WithUnsigned32`, `MathMinWithNoArguments`, `MathMaxWithTwoArguments` clearly show the reducer's ability to simplify calls to various `Math` object methods (e.g., `Math.abs`, `Math.pow`, `Math.min`, `Math.max`). It often replaces these calls with more efficient lower-level operations.
    * **String Function Optimization:** The `StringFromSingleCharCodeWithNumber` test indicates optimization for `String.fromCharCode`.
    * **Number Function Optimization:**  Tests for `Number.isFinite`, `Number.isInteger`, `Number.isNaN`, `Number.isSafeInteger`, and `Number.parseInt` suggest the reducer optimizes calls to these methods.
    * **Global Function Optimization:** Tests for `isFinite` and `isNaN` (global functions) indicate similar optimizations.

6. **Considering Potential .tq Files:** The request mentions `.tq` files (Torque). Since no `.tq` file is provided, the answer correctly states that the current file is C++ and not Torque. It's important to understand that Torque is a language used within V8 for defining built-in functions and can sometimes be related to the optimizations performed by components like `JSCallReducer`.

7. **Connecting to JavaScript:** The request asks for JavaScript examples. This involves taking the C++ test cases and showing the equivalent JavaScript code that would trigger the optimizations being tested. For example, the `MathUnaryWithNumber` test in C++ corresponds to calling `Math.abs()`, `Math.sin()`, etc., in JavaScript.

8. **Inferring Logic and Assumptions:** For code logic, the reducer likely checks the function being called (e.g., `Math.abs`), the types of the arguments, and potentially some internal V8 state (like the promise hook protector). The assumptions are that the input graph represents a JavaScript program and the goal is to optimize it.

9. **Identifying Common Programming Errors:**  Relate the optimizations to potential programmer mistakes. For instance, inefficiently calling `Math.min` or `Math.max` with many arguments could be something the reducer handles by generating more optimal code.

10. **Structuring the Answer:** Organize the findings logically:
    * Start with a high-level summary of the file's purpose.
    * List the key functionalities based on the test cases.
    * Address the `.tq` file question.
    * Provide relevant JavaScript examples.
    * Explain the underlying logic and assumptions.
    * Give examples of common programming errors that these optimizations address.

By following these steps, we can thoroughly analyze the C++ code and provide a comprehensive answer to the request. The key is to combine code inspection with an understanding of V8's architecture and the purpose of compiler optimizations.
`v8/test/unittests/compiler/js-call-reducer-unittest.cc` 是一个 V8 引擎的 C++ 源代码文件，它的主要功能是 **测试 `JSCallReducer` 组件**。

`JSCallReducer` 是 V8 编译器中的一个重要组成部分，它的职责是 **在编译过程中对 JavaScript 函数调用进行优化和简化**。这个 unittest 文件通过创建各种 JavaScript 函数调用场景，并使用 `JSCallReducer` 对这些调用进行处理，然后断言处理结果是否符合预期，以此来验证 `JSCallReducer` 的功能是否正常。

**以下是该文件测试的一些主要功能点：**

1. **Promise 构造函数的优化:**
   - 测试 `new Promise()` 的不同调用方式（无参数，有参数，子类化等），验证 `JSCallReducer` 是否能正确识别并进行优化。

   ```javascript
   // Promise 构造函数的基本调用
   new Promise((resolve, reject) => {
     // ...
   });

   // Promise 构造函数无参数调用 (尽管实际意义不大)
   new Promise();

   // Promise 子类的构造
   class MyPromise extends Promise {}
   new MyPromise(() => {});
   ```

2. **Math 对象方法的优化:**
   - 测试 `Math.abs`, `Math.acos`, `Math.sin`, `Math.min`, `Math.max`, `Math.clz32`, `Math.imul` 等各种 `Math` 对象的方法调用，验证 `JSCallReducer` 是否能将其替换为更高效的底层操作。

   ```javascript
   // Math 对象的单参数方法
   Math.abs(-5);
   Math.sin(0);

   // Math 对象的双参数方法
   Math.pow(2, 3);
   Math.min(10, 5);

   // Math.clz32 (Count Leading Zeroes in 32-bit Integer)
   Math.clz32(8); // 二进制表示 000...01000，前导零有 32 - 4 = 28 个

   // Math.imul (带符号的 32 位整数乘法)
   Math.imul(2, 3);
   ```

3. **String 对象方法的优化:**
   - 测试 `String.fromCharCode` 方法的调用，验证 `JSCallReducer` 是否能将其优化为直接创建单字符字符串的操作。

   ```javascript
   // String.fromCharCode
   String.fromCharCode(65); // 输出 "A"
   ```

4. **Number 对象方法的优化:**
   - 测试 `Number.isFinite`, `Number.isInteger`, `Number.isNaN`, `Number.isSafeInteger`, `Number.parseInt` 等方法的调用，验证 `JSCallReducer` 是否能将其替换为更高效的检查或转换操作。

   ```javascript
   // Number.isFinite
   Number.isFinite(10);   // true
   Number.isFinite(Infinity); // false

   // Number.isInteger
   Number.isInteger(5);    // true
   Number.isInteger(5.1);  // false

   // Number.isNaN
   Number.isNaN(NaN);     // true
   Number.isNaN(10);      // false

   // Number.isSafeInteger
   Number.isSafeInteger(Math.pow(2, 53) - 1); // true
   Number.isSafeInteger(Math.pow(2, 53));     // false

   // Number.parseInt
   Number.parseInt("10");   // 10
   Number.parseInt("10.5"); // 10
   ```

5. **全局函数的优化:**
   - 测试全局函数 `isFinite`, `isNaN` 的调用，验证 `JSCallReducer` 是否能将其优化为更底层的数字检查操作。

   ```javascript
   // 全局 isFinite
   isFinite(10);   // true
   isFinite(Infinity); // false

   // 全局 isNaN
   isNaN(NaN);     // true
   isNaN(10);      // false
   ```

**关于 `.tq` 文件:**

如果 `v8/test/unittests/compiler/js-call-reducer-unittest.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是一种 V8 内部使用的领域特定语言，用于定义内置函数和运行时代码。  然而，根据你提供的文件名，它以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**。

**代码逻辑推理与假设输入输出:**

让我们以 `Math.abs` 的测试为例：

**假设输入:**  一个表示 `Math.abs(x)` 调用的编译器节点，其中 `x` 的类型可以是 `Type::Any()`（表示类型未知），也可以是更具体的数字类型。

**代码逻辑推理:** `JSCallReducer` 会识别出这是一个对 `Math.abs` 的调用。如果参数 `x` 可以被推断为数字类型，`JSCallReducer` 会尝试将其替换为一个底层的 `NumberAbs` 操作，这是一个更直接、更高效的计算绝对值的操作。

**预期输出:**  `Reduce` 方法会返回一个 `Reduction` 对象，其中包含一个新的节点，该节点表示 `NumberAbs(ToNumber(x))`。这里 `ToNumber(x)` 表示将 `x` 转换为数字的操作，如果 `x` 已经是数字类型，则可能是一个空操作。

**示例：`TEST_F(JSCallReducerTest, MathUnaryWithNumber)` 中的 `Math.abs` 测试**

- **输入 (C++ 表示):** 一个 `javascript()->Call()` 节点，其目标是 `MathFunction("abs")`，参数是 `p0` (类型为 `Type::Any()`)。
- **`JSCallReducer` 的处理:** `Reduce` 方法被调用。
- **输出 (C++ 表示):**  `r.replacement()` 会是一个表示 `NumberAbs(SpeculativeToNumber(p0))` 的节点。 `SpeculativeToNumber` 意味着在运行时可能会进行类型检查和转换。

**用户常见的编程错误示例:**

`JSCallReducer` 的优化有时可以减轻某些常见的编程错误带来的性能影响。例如：

1. **不必要的函数调用:** 用户可能会在性能敏感的代码中直接调用 `Math.min` 或 `Math.max`，即使参数已经是数字类型。`JSCallReducer` 可以将这些调用优化为更底层的比较操作。

   ```javascript
   let a = 10;
   let b = 5;
   let minVal = Math.min(a, b); // JSCallReducer 可以将其优化为简单的比较操作
   ```

2. **类型不确定导致的性能损耗:** JavaScript 是一门动态类型语言，如果不进行类型推断，很多操作都需要进行运行时类型检查。`JSCallReducer` 可以根据已有的类型信息进行优化，例如，如果知道传递给 `Math.abs` 的参数总是数字，就可以避免不必要的类型检查。

3. **对某些内置函数的低效使用:**  例如，在旧版本的 JavaScript 中，可能需要手动进行一些数字检查。现在，`Number.isFinite`, `Number.isInteger` 等方法提供了更清晰和高效的方式，`JSCallReducer` 可以确保这些方法调用被高效地执行。

**总结:**

`v8/test/unittests/compiler/js-call-reducer-unittest.cc` 是一个关键的测试文件，它确保了 V8 编译器中的 `JSCallReducer` 组件能够正确地识别和优化各种 JavaScript 函数调用，从而提高 JavaScript 代码的执行效率。它通过模拟不同的调用场景并验证优化结果来保证 `JSCallReducer` 的功能稳定可靠。

### 提示词
```
这是目录为v8/test/unittests/compiler/js-call-reducer-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/js-call-reducer-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cctype>

#include "src/codegen/tick-counter.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/feedback-source.h"
#include "src/compiler/js-call-reducer.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/simplified-operator.h"
#include "src/execution/isolate.h"
#include "src/execution/protectors.h"
#include "src/heap/factory.h"
#include "src/objects/feedback-vector.h"
#include "test/unittests/compiler/graph-unittest.h"
#include "test/unittests/compiler/node-test-utils.h"

namespace v8 {
namespace internal {
namespace compiler {

class JSCallReducerTest : public TypedGraphTest {
 public:
  JSCallReducerTest()
      : TypedGraphTest(3), javascript_(zone()), deps_(broker(), zone()) {
  }
  ~JSCallReducerTest() override = default;

 protected:
  Reduction Reduce(Node* node) {
    MachineOperatorBuilder machine(zone());
    SimplifiedOperatorBuilder simplified(zone());
    JSGraph jsgraph(isolate(), graph(), common(), javascript(), &simplified,
                    &machine);
    GraphReducer graph_reducer(zone(), graph(), tick_counter(), broker());
    JSCallReducer reducer(&graph_reducer, &jsgraph, broker(), zone(),
                          JSCallReducer::kNoFlags);
    return reducer.Reduce(node);
  }

  JSOperatorBuilder* javascript() { return &javascript_; }

  Node* GlobalFunction(const char* name) {
    Handle<JSFunction> f = Cast<JSFunction>(
        Object::GetProperty(
            isolate(), isolate()->global_object(),
            isolate()->factory()->NewStringFromAsciiChecked(name))
            .ToHandleChecked());
    return HeapConstantNoHole(CanonicalHandle(f));
  }

  Node* MathFunction(const std::string& name) {
    Handle<JSAny> m =
        Cast<JSAny>(JSObject::GetProperty(
                        isolate(), isolate()->global_object(),
                        isolate()->factory()->NewStringFromAsciiChecked("Math"))
                        .ToHandleChecked());
    Handle<JSFunction> f = Cast<JSFunction>(
        Object::GetProperty(
            isolate(), m,
            isolate()->factory()->NewStringFromAsciiChecked(name.c_str()))
            .ToHandleChecked());
    return HeapConstantNoHole(CanonicalHandle(f));
  }

  Node* StringFunction(const char* name) {
    Handle<JSAny> m = Cast<JSAny>(
        JSObject::GetProperty(
            isolate(), isolate()->global_object(),
            isolate()->factory()->NewStringFromAsciiChecked("String"))
            .ToHandleChecked());
    Handle<JSFunction> f = Cast<JSFunction>(
        Object::GetProperty(
            isolate(), m, isolate()->factory()->NewStringFromAsciiChecked(name))
            .ToHandleChecked());
    return HeapConstantNoHole(CanonicalHandle(f));
  }

  Node* NumberFunction(const char* name) {
    Handle<JSAny> m = Cast<JSAny>(
        JSObject::GetProperty(
            isolate(), isolate()->global_object(),
            isolate()->factory()->NewStringFromAsciiChecked("Number"))
            .ToHandleChecked());
    Handle<JSFunction> f = Cast<JSFunction>(
        Object::GetProperty(
            isolate(), m, isolate()->factory()->NewStringFromAsciiChecked(name))
            .ToHandleChecked());
    return HeapConstantNoHole(CanonicalHandle(f));
  }

  std::string op_name_for(const char* fnc) {
    std::string string_fnc(fnc);
    char initial = std::toupper(fnc[0]);
    return std::string("Number") + initial +
           string_fnc.substr(1, std::string::npos);
  }

  const Operator* Call(int arity) {
    FeedbackVectorSpec spec(zone());
    spec.AddCallICSlot();
    Handle<FeedbackVector> vector =
        FeedbackVector::NewForTesting(isolate(), &spec);
    FeedbackSource feedback(vector, FeedbackSlot(0));
    return javascript()->Call(JSCallNode::ArityForArgc(arity), CallFrequency(),
                              feedback, ConvertReceiverMode::kAny,
                              SpeculationMode::kAllowSpeculation,
                              CallFeedbackRelation::kTarget);
  }

  Node* DummyFrameState() {
    return graph()->NewNode(
        common()->FrameState(BytecodeOffset{42},
                             OutputFrameStateCombine::Ignore(), nullptr),
        graph()->start(), graph()->start(), graph()->start(), graph()->start(),
        graph()->start(), graph()->start());
  }

 private:
  JSOperatorBuilder javascript_;
  CompilationDependencies deps_;
};

TEST_F(JSCallReducerTest, PromiseConstructorNoArgs) {
  Node* promise =
      HeapConstantNoHole(CanonicalHandle(native_context()->promise_function()));
  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* feedback = UndefinedConstant();

  Node* construct = graph()->NewNode(
      javascript()->Construct(JSConstructNode::ArityForArgc(0)), promise,
      promise, feedback, context, frame_state, effect, control);

  Reduction r = Reduce(construct);

  ASSERT_FALSE(r.Changed());
}

TEST_F(JSCallReducerTest, PromiseConstructorSubclass) {
  Node* promise =
      HeapConstantNoHole(CanonicalHandle(native_context()->promise_function()));
  Node* new_target =
      HeapConstantNoHole(CanonicalHandle(native_context()->array_function()));
  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* feedback = UndefinedConstant();

  Node* executor = UndefinedConstant();
  Node* construct = graph()->NewNode(
      javascript()->Construct(JSConstructNode::ArityForArgc(1)), promise,
      new_target, executor, feedback, context, frame_state, effect, control);

  Reduction r = Reduce(construct);

  ASSERT_FALSE(r.Changed());
}

TEST_F(JSCallReducerTest, PromiseConstructorBasic) {
  Node* promise =
      HeapConstantNoHole(CanonicalHandle(native_context()->promise_function()));
  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* feedback = UndefinedConstant();

  Node* executor = UndefinedConstant();
  Node* construct = graph()->NewNode(
      javascript()->Construct(JSConstructNode::ArityForArgc(1)), promise,
      promise, executor, feedback, context, frame_state, effect, control);

  Reduction r = Reduce(construct);
  ASSERT_TRUE(r.Changed());
}

// Exactly the same as PromiseConstructorBasic which expects a reduction,
// except that we invalidate the protector cell.
TEST_F(JSCallReducerTest, PromiseConstructorWithHook) {
  Node* promise =
      HeapConstantNoHole(CanonicalHandle(native_context()->promise_function()));
  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* feedback = UndefinedConstant();

  Node* executor = UndefinedConstant();
  Node* construct = graph()->NewNode(
      javascript()->Construct(JSConstructNode::ArityForArgc(1)), promise,
      promise, executor, feedback, context, frame_state, effect, control);

  Protectors::InvalidatePromiseHook(isolate());

  Reduction r = Reduce(construct);

  ASSERT_FALSE(r.Changed());
}

// -----------------------------------------------------------------------------
// Math unaries

namespace {

const char* kMathUnaries[] = {
    "abs",  "acos",  "acosh", "asin", "asinh", "atan",  "cbrt",
    "ceil", "cos",   "cosh",  "exp",  "expm1", "floor", "fround",
    "log",  "log1p", "log10", "log2", "round", "sign",  "sin",
    "sinh", "sqrt",  "tan",   "tanh", "trunc"};

}  // namespace

TEST_F(JSCallReducerTest, MathUnaryWithNumber) {
  TRACED_FOREACH(const char*, fnc, kMathUnaries) {
    Node* effect = graph()->start();
    Node* control = graph()->start();
    Node* context = UndefinedConstant();
    Node* frame_state = DummyFrameState();
    Node* jsfunction = MathFunction(fnc);
    Node* p0 = Parameter(Type::Any(), 0);
    Node* feedback = UndefinedConstant();
    Node* call =
        graph()->NewNode(Call(1), jsfunction, UndefinedConstant(), p0, feedback,
                         context, frame_state, effect, control);
    Reduction r = Reduce(call);
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(std::string(IrOpcode::Mnemonic(r.replacement()->opcode())),
                op_name_for(fnc));
  }
}

// -----------------------------------------------------------------------------
// Math binaries

namespace {

const char* kMathBinaries[] = {"atan2", "pow"};

}  // namespace

TEST_F(JSCallReducerTest, MathBinaryWithNumber) {
  TRACED_FOREACH(const char*, fnc, kMathBinaries) {
    Node* jsfunction = MathFunction(fnc);

    Node* effect = graph()->start();
    Node* control = graph()->start();
    Node* context = UndefinedConstant();
    Node* frame_state = DummyFrameState();
    Node* p0 = Parameter(Type::Any(), 0);
    Node* p1 = Parameter(Type::Any(), 0);
    Node* feedback = UndefinedConstant();
    Node* call =
        graph()->NewNode(Call(2), jsfunction, UndefinedConstant(), p0, p1,
                         feedback, context, frame_state, effect, control);
    Reduction r = Reduce(call);

    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(std::string(IrOpcode::Mnemonic(r.replacement()->opcode())),
                op_name_for(fnc));
  }
}

// -----------------------------------------------------------------------------
// Math.clz32

TEST_F(JSCallReducerTest, MathClz32WithUnsigned32) {
  Node* jsfunction = MathFunction("clz32");
  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();

  Node* p0 = Parameter(Type::Unsigned32(), 0);
  Node* feedback = UndefinedConstant();
  Node* call =
      graph()->NewNode(Call(1), jsfunction, UndefinedConstant(), p0, feedback,
                       context, frame_state, effect, control);
  Reduction r = Reduce(call);

  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(),
              IsNumberClz32(IsNumberToUint32(IsSpeculativeToNumber(p0))));
}

TEST_F(JSCallReducerTest, MathClz32WithUnsigned32NoArg) {
  Node* jsfunction = MathFunction("clz32");
  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();

  Node* feedback = UndefinedConstant();
  Node* call =
      graph()->NewNode(Call(0), jsfunction, UndefinedConstant(), feedback,
                       context, frame_state, effect, control);
  Reduction r = Reduce(call);

  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsNumberConstant(32));
}

// -----------------------------------------------------------------------------
// Math.imul

TEST_F(JSCallReducerTest, MathImulWithUnsigned32) {
  Node* jsfunction = MathFunction("imul");

  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* p0 = Parameter(Type::Unsigned32(), 0);
  Node* p1 = Parameter(Type::Unsigned32(), 1);
  Node* feedback = UndefinedConstant();
  Node* call =
      graph()->NewNode(Call(2), jsfunction, UndefinedConstant(), p0, p1,
                       feedback, context, frame_state, effect, control);
  Reduction r = Reduce(call);

  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(std::string(IrOpcode::Mnemonic(r.replacement()->opcode())),
              op_name_for("imul"));
}

// -----------------------------------------------------------------------------
// Math.min

TEST_F(JSCallReducerTest, MathMinWithNoArguments) {
  Node* jsfunction = MathFunction("min");
  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* feedback = UndefinedConstant();
  Node* call =
      graph()->NewNode(Call(0), jsfunction, UndefinedConstant(), feedback,
                       context, frame_state, effect, control);
  Reduction r = Reduce(call);

  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsNumberConstant(V8_INFINITY));
}

TEST_F(JSCallReducerTest, MathMinWithNumber) {
  Node* jsfunction = MathFunction("min");
  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* p0 = Parameter(Type::Any(), 0);
  Node* feedback = UndefinedConstant();
  Node* call =
      graph()->NewNode(Call(1), jsfunction, UndefinedConstant(), p0, feedback,
                       context, frame_state, effect, control);
  Reduction r = Reduce(call);

  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsSpeculativeToNumber(p0));
}

TEST_F(JSCallReducerTest, MathMinWithTwoArguments) {
  Node* jsfunction = MathFunction("min");
  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* p0 = Parameter(Type::Any(), 0);
  Node* p1 = Parameter(Type::Any(), 1);
  Node* feedback = UndefinedConstant();
  Node* call =
      graph()->NewNode(Call(2), jsfunction, UndefinedConstant(), p0, p1,
                       feedback, context, frame_state, effect, control);
  Reduction r = Reduce(call);

  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsNumberMin(IsSpeculativeToNumber(p0),
                                           IsSpeculativeToNumber(p1)));
}

// -----------------------------------------------------------------------------
// Math.max

TEST_F(JSCallReducerTest, MathMaxWithNoArguments) {
  Node* jsfunction = MathFunction("max");

  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* feedback = UndefinedConstant();
  Node* call =
      graph()->NewNode(Call(0), jsfunction, UndefinedConstant(), feedback,
                       context, frame_state, effect, control);
  Reduction r = Reduce(call);

  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsNumberConstant(-V8_INFINITY));
}

TEST_F(JSCallReducerTest, MathMaxWithNumber) {
  Node* jsfunction = MathFunction("max");
  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* p0 = Parameter(Type::Any(), 0);
  Node* feedback = UndefinedConstant();
  Node* call =
      graph()->NewNode(Call(1), jsfunction, UndefinedConstant(), p0, feedback,
                       context, frame_state, effect, control);
  Reduction r = Reduce(call);

  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsSpeculativeToNumber(p0));
}

TEST_F(JSCallReducerTest, MathMaxWithTwoArguments) {
  Node* jsfunction = MathFunction("max");

  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* p0 = Parameter(Type::Any(), 0);
  Node* p1 = Parameter(Type::Any(), 1);
  Node* feedback = UndefinedConstant();
  Node* call =
      graph()->NewNode(Call(2), jsfunction, UndefinedConstant(), p0, p1,
                       feedback, context, frame_state, effect, control);
  Reduction r = Reduce(call);

  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsNumberMax(IsSpeculativeToNumber(p0),
                                           IsSpeculativeToNumber(p1)));
}

// -----------------------------------------------------------------------------
// String.fromCharCode

TEST_F(JSCallReducerTest, StringFromSingleCharCodeWithNumber) {
  Node* function = StringFunction("fromCharCode");

  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* p0 = Parameter(Type::Any(), 0);
  Node* feedback = UndefinedConstant();
  Node* call =
      graph()->NewNode(Call(1), function, UndefinedConstant(), p0, feedback,
                       context, frame_state, effect, control);
  Reduction r = Reduce(call);

  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(),
              IsStringFromSingleCharCode(IsSpeculativeToNumber(p0)));
}

TEST_F(JSCallReducerTest, StringFromSingleCharCodeWithPlainPrimitive) {
  Node* function = StringFunction("fromCharCode");

  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* p0 = Parameter(Type::PlainPrimitive(), 0);
  Node* feedback = UndefinedConstant();
  Node* call =
      graph()->NewNode(Call(1), function, UndefinedConstant(), p0, feedback,
                       context, frame_state, effect, control);
  Reduction r = Reduce(call);

  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(),
              IsStringFromSingleCharCode(IsSpeculativeToNumber(p0)));
}

// -----------------------------------------------------------------------------
// Number.isFinite

TEST_F(JSCallReducerTest, NumberIsFinite) {
  Node* function = NumberFunction("isFinite");

  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* p0 = Parameter(Type::Any(), 0);
  Node* feedback = UndefinedConstant();
  Node* call =
      graph()->NewNode(Call(1), function, UndefinedConstant(), p0, feedback,
                       context, frame_state, effect, control);
  Reduction r = Reduce(call);

  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsObjectIsFiniteNumber(p0));
}

// -----------------------------------------------------------------------------
// Number.isInteger

TEST_F(JSCallReducerTest, NumberIsIntegerWithNumber) {
  Node* function = NumberFunction("isInteger");

  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* p0 = Parameter(Type::Any(), 0);
  Node* feedback = UndefinedConstant();
  Node* call =
      graph()->NewNode(Call(1), function, UndefinedConstant(), p0, feedback,
                       context, frame_state, effect, control);
  Reduction r = Reduce(call);

  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsObjectIsInteger(p0));
}

// -----------------------------------------------------------------------------
// Number.isNaN

TEST_F(JSCallReducerTest, NumberIsNaNWithNumber) {
  Node* function = NumberFunction("isNaN");

  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* p0 = Parameter(Type::Any(), 0);
  Node* feedback = UndefinedConstant();
  Node* call =
      graph()->NewNode(Call(1), function, UndefinedConstant(), p0, feedback,
                       context, frame_state, effect, control);
  Reduction r = Reduce(call);

  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsObjectIsNaN(p0));
}

// -----------------------------------------------------------------------------
// Number.isSafeInteger

TEST_F(JSCallReducerTest, NumberIsSafeIntegerWithIntegral32) {
  Node* function = NumberFunction("isSafeInteger");

  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* p0 = Parameter(Type::Any(), 0);
  Node* feedback = UndefinedConstant();
  Node* call =
      graph()->NewNode(Call(1), function, UndefinedConstant(), p0, feedback,
                       context, frame_state, effect, control);
  Reduction r = Reduce(call);

  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsObjectIsSafeInteger(p0));
}

// -----------------------------------------------------------------------------
// isFinite

TEST_F(JSCallReducerTest, GlobalIsFiniteWithNumber) {
  Node* function = GlobalFunction("isFinite");

  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* p0 = Parameter(Type::Any(), 0);
  Node* feedback = UndefinedConstant();
  Node* call =
      graph()->NewNode(Call(1), function, UndefinedConstant(), p0, feedback,
                       context, frame_state, effect, control);
  Reduction r = Reduce(call);

  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsNumberIsFinite(IsSpeculativeToNumber(p0)));
}

// -----------------------------------------------------------------------------
// isNaN

TEST_F(JSCallReducerTest, GlobalIsNaN) {
  Node* function = GlobalFunction("isNaN");

  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* p0 = Parameter(Type::Any(), 0);
  Node* feedback = UndefinedConstant();
  Node* call =
      graph()->NewNode(Call(1), function, UndefinedConstant(), p0, feedback,
                       context, frame_state, effect, control);
  Reduction r = Reduce(call);

  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsNumberIsNaN(IsSpeculativeToNumber(p0)));
}

// -----------------------------------------------------------------------------
// Number.parseInt

TEST_F(JSCallReducerTest, NumberParseInt) {
  Node* function = NumberFunction("parseInt");

  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* context = UndefinedConstant();
  Node* frame_state = DummyFrameState();
  Node* p0 = Parameter(Type::Any(), 0);
  Node* p1 = Parameter(Type::Any(), 1);
  Node* feedback = UndefinedConstant();
  Node* call =
      graph()->NewNode(Call(2), function, UndefinedConstant(), p0, p1, feedback,
                       context, frame_state, effect, control);
  Reduction r = Reduce(call);

  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsJSParseInt(p0, p1));
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```