Response: Let's break down the thought process for analyzing the C++ code and generating the summary and JavaScript examples.

1. **Understanding the Goal:** The request asks for a summary of the C++ code's functionality and to illustrate its connection to JavaScript using examples. This means we need to figure out *what* the C++ code does in the context of V8 and how that relates to observable JavaScript behavior.

2. **Initial Scan for Keywords:**  Looking at the `#include` directives and class names immediately gives clues.
    * `"src/compiler/js-call-reducer.h"`:  The core component is a "JSCallReducer."  "Reducer" suggests optimization or simplification. "JSCall" likely refers to JavaScript function calls.
    * `"src/compiler/js-graph.h"`: This implies the code operates on an intermediate representation of JavaScript code (the "graph").
    * `"test/unittests/compiler/"`: This confirms it's a unit test, verifying the `JSCallReducer`'s behavior.
    * Keywords like `Math`, `String`, `Number`, `Promise` appear in the test names, hinting at the JavaScript built-in objects being targeted.

3. **Identifying the Core Functionality:**  The `Reduce(Node* node)` method is the key. It takes a `Node` (part of the graph) and returns a `Reduction`. The setup within `Reduce` creates the environment needed for the reduction process (JSGraph, GraphReducer, JSCallReducer). This confirms the initial guess that the code optimizes JavaScript calls.

4. **Examining the Test Cases:**  The `TEST_F` macros define individual test cases. Analyzing these reveals the specific scenarios the `JSCallReducer` handles. Look for patterns:
    * **`PromiseConstructor...`:**  These tests check how `new Promise(...)` calls are optimized. The "Basic" case shows a reduction occurs, while "Subclass" and "NoArgs" might not. The "WithHook" case introduces the idea of invalidating protectors.
    * **`MathUnaryWithNumber`, `MathBinaryWithNumber`:** These focus on calls to `Math` object methods (e.g., `Math.abs()`, `Math.pow()`). The tests assert that these calls are "reduced," meaning they're replaced with more efficient low-level operations.
    * **`Math.clz32`, `Math.imul`, `Math.min`, `Math.max`:** These are specific `Math` methods with their own tests, likely due to special optimization rules.
    * **`String.fromCharCode`, `Number.isFinite`, `Number.isInteger`, `Number.isNaN`, `Number.isSafeInteger`, `isFinite`, `isNaN`, `Number.parseInt`:**  These cover optimizations for methods on the `String` and `Number` constructors and global functions.

5. **Connecting C++ to JavaScript:**  For each test case, try to think of the equivalent JavaScript code that would lead to the tested scenario. For example:
    * `PromiseConstructorBasic`: `new Promise(() => {})`
    * `MathUnaryWithNumber`: `Math.abs(5)`, `Math.sin(x)`
    * `StringFromSingleCharCodeWithNumber`: `String.fromCharCode(65)`
    * `NumberIsFinite`: `Number.isFinite(42)` or `Number.isFinite("hello")`
    * `isFinite`: `isFinite(42)`

6. **Inferring the Reduction Logic:**  While the C++ code details the implementation, the test assertions (`ASSERT_TRUE(r.Changed())`, `EXPECT_THAT(...)`) give hints about *what* the reduction does. For instance, when `Math.abs(x)` is called, the reducer likely replaces the call with a more direct operation for calculating the absolute value.

7. **Formulating the Summary:**  Combine the observations:
    * The file tests the `JSCallReducer`.
    * The `JSCallReducer` optimizes JavaScript function calls during compilation.
    * It focuses on built-in functions like `Promise` constructor, `Math` methods, `String` methods, `Number` methods, and global functions.
    * The optimization involves replacing these calls with more efficient internal operations.

8. **Creating JavaScript Examples:** Based on the test names and the understanding of the reductions, create concise JavaScript code snippets that demonstrate the functionality being tested. The examples should directly correspond to the scenarios in the C++ tests.

9. **Review and Refine:** Read through the summary and examples to ensure clarity, accuracy, and completeness. Make sure the connection between the C++ code and the JavaScript examples is clear. For example, explicitly mention that the reducer aims to optimize these JavaScript calls.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This seems like a lot of low-level compiler stuff."  **Correction:** While it *is* low-level, the tests are specifically targeting observable JavaScript behavior, so the connection is there.
* **Stuck on a specific test:** If a test case is unclear, look at the specific operators being used (`javascript()->Construct`, `Call`) and try to map them back to JavaScript syntax.
* **Overly detailed explanation:** Avoid going into the nitty-gritty of the C++ implementation. Focus on the *what* and *why* of the reductions from a JavaScript perspective.

By following these steps, combining code analysis with an understanding of JavaScript semantics and compiler optimization principles, you can effectively summarize the functionality of the C++ code and illustrate its connection to JavaScript.
这个C++源代码文件 `v8/test/unittests/compiler/js-call-reducer-unittest.cc` 是V8 JavaScript引擎中 **编译器 (compiler)** 部分的 **JSCallReducer** 组件的 **单元测试 (unittest)** 文件。

**功能归纳:**

该文件的主要功能是测试 `JSCallReducer` 类的各种优化能力。 `JSCallReducer` 的作用是在 V8 编译 JavaScript 代码的过程中，**识别并优化特定的 JavaScript 函数调用**，将其替换为更高效的内部操作或者内置函数。  这些优化可以提高 JavaScript 代码的执行效率。

**更具体地说，该文件测试了 `JSCallReducer` 如何优化以下类型的 JavaScript 函数调用：**

* **`Promise` 构造函数:**  测试了 `new Promise(...)` 调用的不同场景，例如无参数、有参数、作为子类调用等，以及在某些特定条件下的优化。
* **`Math` 对象的方法:**  测试了 `Math.abs()`, `Math.acos()`, `Math.sin()`, `Math.pow()`, `Math.min()`, `Math.max()`, `Math.clz32()`, `Math.imul()` 等数学函数的调用优化。
* **`String` 对象的方法:**  测试了 `String.fromCharCode()` 的调用优化。
* **`Number` 对象的方法:**  测试了 `Number.isFinite()`, `Number.isInteger()`, `Number.isNaN()`, `Number.isSafeInteger()`, `Number.parseInt()` 的调用优化。
* **全局函数:** 测试了 `isFinite()`, `isNaN()` 全局函数的调用优化。

**与 JavaScript 功能的关系及举例说明:**

`JSCallReducer` 的优化直接影响着 JavaScript 代码的执行效率。 它通过识别特定的 JavaScript 调用模式，并将其转换为 V8 内部更高效的实现，从而提升性能。

以下是一些 JavaScript 示例，对应于该 C++ 单元测试文件测试的优化：

**1. `Promise` 构造函数优化:**

```javascript
// 对应 C++ 中的 TEST_F(JSCallReducerTest, PromiseConstructorBasic)
const p = new Promise((resolve, reject) => {
  // ...
});
```

V8 的 `JSCallReducer` 可以识别这种标准的 `Promise` 构造，并可能将其替换为更直接的 Promise 创建逻辑，避免额外的函数调用开销。

**2. `Math` 对象方法优化:**

```javascript
// 对应 C++ 中的 TEST_F(JSCallReducerTest, MathUnaryWithNumber) (例如 Math.abs)
const absValue = Math.abs(-5); // JSCallReducer 可能将其优化为直接的绝对值计算
const sineValue = Math.sin(0.5); // JSCallReducer 可能将其优化为调用内置的 sin 函数

// 对应 C++ 中的 TEST_F(JSCallReducerTest, MathBinaryWithNumber) (例如 Math.pow)
const powerValue = Math.pow(2, 3); // JSCallReducer 可能将其优化为内置的幂运算
```

`JSCallReducer` 可以将对 `Math` 对象某些已知方法的调用，替换为更底层的、针对数字类型优化的指令，避免通用的函数调用开销。

**3. `String.fromCharCode` 优化:**

```javascript
// 对应 C++ 中的 TEST_F(JSCallReducerTest, StringFromSingleCharCodeWithNumber)
const char = String.fromCharCode(65); // JSCallReducer 可能将其优化为直接创建单字符字符串
```

对于 `String.fromCharCode` 这种特定模式，`JSCallReducer` 可以直接生成创建单字符字符串的操作，而无需完整的函数调用流程。

**4. `Number.isFinite` 等类型检查优化:**

```javascript
// 对应 C++ 中的 TEST_F(JSCallReducerTest, NumberIsFinite)
const isNumFinite = Number.isFinite(10); // JSCallReducer 可能将其优化为直接的数字类型检查

// 对应 C++ 中的 TEST_F(JSCallReducerTest, GlobalIsFiniteWithNumber)
const isGloballyFinite = isFinite(0); // JSCallReducer 可能将其优化为直接的数字类型检查
```

对于 `Number.isFinite`, `Number.isNaN` 等类型检查方法，`JSCallReducer` 可以直接生成相应的类型检查指令，避免函数调用的开销。

**总结:**

`v8/test/unittests/compiler/js-call-reducer-unittest.cc` 文件通过一系列单元测试，验证了 V8 编译器中的 `JSCallReducer` 组件能够有效地识别和优化特定的 JavaScript 函数调用模式，从而提高 JavaScript 代码的执行效率。 这些优化涉及到 `Promise` 构造、`Math` 对象方法、`String` 对象方法、`Number` 对象方法以及全局函数等多个方面。 了解这些优化有助于开发者理解 V8 如何提升性能，并在编写 JavaScript 代码时考虑这些优化点。

Prompt: 
```
这是目录为v8/test/unittests/compiler/js-call-reducer-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```