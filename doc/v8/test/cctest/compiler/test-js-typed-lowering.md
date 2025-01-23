Response:
Let's break down the thought process for analyzing this C++ code snippet.

**1. Initial Understanding - Context is Key:**

The first thing to recognize is the file path: `v8/test/cctest/compiler/test-js-typed-lowering.cc`. This immediately tells us a lot:

* **`v8`:** This is part of the V8 JavaScript engine.
* **`test`:** It's a test file, not core engine code.
* **`cctest`:** This likely indicates a specific testing framework used within V8.
* **`compiler`:**  This is related to the compilation pipeline of V8.
* **`test-js-typed-lowering.cc`:** The core subject – testing the "JS Typed Lowering" phase.

**2. Deciphering "JS Typed Lowering":**

Now, we need to understand what "JS Typed Lowering" does. Based on the name, we can infer:

* **"JS":** It operates on JavaScript-related concepts.
* **"Typed":** It likely deals with type information associated with JavaScript values.
* **"Lowering":**  This implies transforming higher-level representations into lower-level ones. In compiler terms, this usually means moving from more abstract operations to more concrete machine-like instructions.

Combining this, we can hypothesize that "JS Typed Lowering" is a compilation phase in V8 that takes JavaScript code (represented in some intermediate form) and, using type information, transforms it into a lower-level representation suitable for code generation.

**3. Examining the Code - High-Level Structure:**

Next, scan the code for key elements:

* **Includes:**  Notice headers like `src/compiler/...`, `src/codegen/...`, `src/objects/...`, and test-related headers. This confirms our initial context about compilation and testing.
* **Namespace:** The code is within `v8::internal::compiler`, reinforcing the compiler context.
* **Class `JSTypedLoweringTester`:** This is clearly the core testing class. It inherits from testing base classes and sets up the necessary infrastructure for creating and manipulating compiler IR (Intermediate Representation) graphs.
* **Member Variables:**  Observe variables like `graph`, `typer`, `javascript`, `simplified`, `machine`, `common`. These represent different components of the Turbofan compiler, particularly the graph representation and operator builders for different levels of abstraction.
* **Helper Functions:** Functions like `Parameter`, `UndefinedConstant`, `Binop`, `Unop`, `reduce`, `CheckBinop`, `CheckNumberConstant`, etc., are designed to simplify the creation of IR nodes and assertions about the results of the lowering process.
* **Test Functions:** Functions starting with `TEST(...)` are the actual test cases. They use the `JSTypedLoweringTester` to set up scenarios and verify the behavior of the `JSTypedLowering` phase.
* **Data Structures:** Arrays like `kStringTypes`, `kInt32Types`, `kNumberTypes` define sets of types used in the tests.

**4. Understanding the Test Logic:**

Focus on what the test cases are doing:

* They create IR nodes representing JavaScript operations (like addition, subtraction, comparisons, type conversions).
* They use the `reduce` method, which internally calls the `JSTypedLowering` pass.
* They then use `Check...` functions to assert that the lowered IR has the expected structure (e.g., using specific machine or simplified operators) and properties.

**5. Connecting to JavaScript:**

Now, think about how the tested operations relate to JavaScript:

* **`StringBinops`:** Tests how string concatenation (`+`) is lowered.
* **`AddNumber1`, `NumberBinops`:** Tests how arithmetic operations on numbers are lowered.
* **`Int32BitwiseShifts`, `Int32BitwiseBinops`:** Tests lowering of bitwise operations, highlighting the importance of integer types.
* **`JSToNumber*`, `JSToString*`:** Tests how explicit and implicit type conversions (like `Number(x)` or string concatenation with a non-string) are handled.
* **`StringComparison`, `NumberComparison`, `MixedComparison1`:** Tests how comparison operators (`<`, `>`, `==`, `===`) are lowered based on the types of the operands.
* **`EqualityForNumbers`, `StrictEqualityForRefEqualTypes`, `StringEquality`:** Focuses on the different lowering strategies for equality comparisons based on operand types.

**6. Identifying Key Functionality:**

Based on the tests, we can summarize the core functionality being tested:

* **Type-based Lowering:** The tests demonstrate how the `JSTypedLowering` phase uses type information to choose more efficient lower-level operations. For example, adding two known numbers becomes a `NumberAdd` instruction, while adding strings becomes `StringConcat`.
* **Specialization:** Operations are specialized based on the types of the operands.
* **Optimization:**  The lowering phase aims to optimize code by choosing the most appropriate lower-level representation.
* **Handling Type Conversions:** Tests cover how explicit and implicit type conversions are handled and potentially optimized.

**7. Addressing Specific Questions:**

* **`.tq` extension:** The code is `.cc`, so it's C++, not Torque.
* **Relationship to JavaScript:**  The tests directly correspond to common JavaScript operations. The examples in the prompt illustrate this.
* **Code Logic Inference:** The tests provide input (IR nodes representing JavaScript operations with specific types) and expected output (the lowered IR). For instance, adding two `Type::Number()` nodes should result in a `kNumberAdd` operation.
* **Common Programming Errors:** While the tests themselves don't directly *demonstrate* user errors, they indirectly relate to them. For example, the tests around type conversions highlight potential unexpected behavior if a user doesn't understand JavaScript's implicit type coercion rules (e.g., the difference between `+` for numbers and strings).
* **归纳功能 (Summarize Functionality):** This brings us back to the core idea of type-based lowering and optimization within the V8 compiler.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe it's just about replacing JS operators with simplified ones.
* **Correction:**  It's more than just simple replacement. It's about *intelligent* replacement based on type information, leading to more efficient code.
* **Initial thought:** The tests are just checking for specific opcodes.
* **Correction:** They also verify the connections between nodes (inputs), the preservation or modification of effect chains, and the types of the resulting nodes.

By following this structured approach, combining code analysis with knowledge of compiler principles and JavaScript semantics, we can arrive at a comprehensive understanding of the code's functionality and its role within the V8 JavaScript engine.
This C++ code snippet is a part of the V8 JavaScript engine's testing framework. Specifically, it's testing the functionality of the `JSTypedLowering` compiler pass.

Here's a breakdown of its functions:

**Core Functionality:**

The primary function of `v8/test/cctest/compiler/test-js-typed-lowering.cc` is to **test the `JSTypedLowering` compiler phase in V8**. This phase is responsible for:

* **Lowering JavaScript operators to more specific, typed operations:** Based on the type information available for the operands, `JSTypedLowering` replaces generic JavaScript operators (like `JSAdd`, `JSLessThan`, `JSToNumber`) with their more concrete counterparts (like `NumberAdd`, `NumberLessThan`, `PlainPrimitiveToNumber`). This allows the compiler to generate more efficient machine code.
* **Performing type-based optimizations:** By understanding the types involved, the lowering phase can perform optimizations, such as directly using primitive operations on numbers instead of going through generic object handling.
* **Removing unnecessary type conversions:** If the types are already compatible, explicit type conversion nodes (like `JSToNumber` or `JSToString`) might be removed.

**Structure of the Test File:**

The file sets up a series of unit tests within the `TEST(...)` macros. Each test case focuses on a specific aspect of the `JSTypedLowering` pass, typically involving:

1. **Setting up a test environment:**  Creating a `JSTypedLoweringTester` instance, which provides helpers for building compiler graphs.
2. **Creating input nodes:**  Constructing nodes representing JavaScript operations (e.g., addition, comparison, type conversion) with specific input types.
3. **Running the `JSTypedLowering` pass:**  Calling the `reduce()` method, which triggers the lowering process on the input node.
4. **Asserting the output:**  Using `CHECK_EQ` and other assertion macros to verify that the lowered node has the expected opcode and inputs. This confirms that the `JSTypedLowering` pass has transformed the node as expected based on the input types.

**Relationship to JavaScript and Examples:**

Yes, this code is directly related to how JavaScript code is compiled and optimized in V8. Here are some examples based on the tests in the file:

* **String Concatenation:**
   ```javascript
   let a = "hello";
   let b = "world";
   let c = a + b; // This JavaScript '+' operation
   ```
   The `TEST(StringBinops)` test checks that when the `JSTypedLowering` phase encounters a `JSAdd` operation where both operands are known to be strings, it's lowered to a `StringConcat` operation.

* **Number Addition:**
   ```javascript
   let x = 5;
   let y = 10;
   let z = x + y; // This JavaScript '+' operation
   ```
   The `TEST(AddNumber1)` and `TEST(NumberBinops)` tests verify that when adding two numbers, the `JSAdd` operation is lowered to a more efficient `NumberAdd` operation.

* **Type Conversion (`ToNumber`):**
   ```javascript
   let str = "42";
   let num = Number(str); // Explicit type conversion
   let sum = num + 1;    // Implicit type conversion might occur
   ```
   The `TEST(JSToNumber1)` and related tests check how the `JSTypedLowering` phase handles `JSToNumber` operations. If the input is already a number, the `JSToNumber` might be removed. If the input is a known primitive type (like `undefined` or `null`), it might be lowered to a `NumberConstant`.

* **Type Conversion (`ToString`):**
   ```javascript
   let num = 123;
   let str = String(num); // Explicit type conversion
   let combined = "" + num; // Implicit type conversion
   ```
   The `TEST(JSToString1)` tests how `JSTypedLowering` handles `JSToString`. For numbers, it's lowered to `NumberToString`. For strings, it might be a no-op.

* **Comparisons:**
   ```javascript
   let a = 5;
   let b = "10";
   let less = a < b; // Comparison between a number and a string
   let str1 = "apple";
   let str2 = "banana";
   let isBefore = str1 < str2; // Comparison between strings
   ```
   The `TEST(StringComparison)`, `TEST(NumberComparison)`, and `TEST(MixedComparison1)` tests demonstrate how comparisons are lowered based on the types of the operands. Comparing two numbers might be lowered to `NumberLessThan`, while comparing two strings might be lowered to `StringLessThan`.

**Code Logic Inference (Hypothetical Example):**

**Assumption:**  The `reduce()` function in `JSTypedLoweringTester` correctly simulates the `JSTypedLowering` pass.

**Hypothetical Input:** A `JSAdd` node with two input nodes of `Type::Number()`.

```c++
// Inside a TEST function:
JSTypedLoweringTester R;
Node* left = R.Parameter(Type::Number(), 0);
Node* right = R.Parameter(Type::Number(), 1);
Node* add = R.Binop(R.javascript.Add(FeedbackSourceWithOneBinarySlot(&R)), left, right);
```

**Expected Output:** The `reduce(add)` call should return a node with the opcode `IrOpcode::kNumberAdd` and the original `left` and `right` nodes as its inputs (potentially in a different order depending on the implementation details).

```c++
Node* lowered_add = R.reduce(add);
R.CheckBinop(IrOpcode::kNumberAdd, lowered_add);
CHECK_EQ(left, lowered_add->InputAt(0)); // Or InputAt(1), order might vary
CHECK_EQ(right, lowered_add->InputAt(1)); // Or InputAt(0)
```

**User Common Programming Errors (Indirectly Related):**

While this test code doesn't directly show user errors, it tests the compiler's behavior in scenarios that arise from user code. For example:

* **Type Mismatches in Operations:** A common error is trying to perform arithmetic operations on non-numeric types. The tests for `JSToNumber` and mixed-type comparisons show how the compiler handles these situations, often involving implicit type conversions. Understanding this behavior is crucial for avoiding unexpected results.
* **Incorrect Assumptions about Type Coercion:** JavaScript's type coercion rules can be subtle. The tests for `JSToString` illustrate how different types are converted to strings, which is important for understanding the outcome of string concatenation or explicit `String()` calls.

**归纳一下它的功能 (Summarize its function):**

In summary, `v8/test/cctest/compiler/test-js-typed-lowering.cc` is a crucial part of V8's testing infrastructure. Its primary function is to **rigorously verify the correctness and effectiveness of the `JSTypedLowering` compiler phase**. This phase plays a vital role in optimizing JavaScript code by leveraging type information to replace generic JavaScript operations with more efficient, type-specific lower-level operations. The tests cover various JavaScript operators and type conversion scenarios, ensuring that the compiler correctly transforms the intermediate representation of the code for optimal performance.

### 提示词
```
这是目录为v8/test/cctest/compiler/test-js-typed-lowering.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/test-js-typed-lowering.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/tick-counter.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/js-typed-lowering.h"
#include "src/compiler/machine-operator.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/opcodes.h"
#include "src/compiler/operator-properties.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/turbofan-typer.h"
#include "src/execution/isolate.h"
#include "src/heap/factory-inl.h"
#include "src/objects/objects.h"
#include "test/cctest/cctest.h"
#include "test/cctest/compiler/js-heap-broker-base.h"

namespace v8 {
namespace internal {
namespace compiler {

class JSTypedLoweringTester : public HandleAndZoneScope,
                              public JSHeapBrokerTestBase {
 public:
  explicit JSTypedLoweringTester(int num_parameters = 0)
      : HandleAndZoneScope(kCompressGraphZone),
        JSHeapBrokerTestBase(main_isolate(), main_zone()),
        isolate(main_isolate()),
        binop(nullptr),
        unop(nullptr),
        javascript(main_zone()),
        machine(main_zone()),
        simplified(main_zone()),
        common(main_zone()),
        graph(main_zone()),
        typer(broker(), Typer::kNoFlags, &graph, &tick_counter),
        context_node(nullptr),
        deps(broker(), main_zone()) {
    graph.SetStart(graph.NewNode(common.Start(num_parameters)));
    graph.SetEnd(graph.NewNode(common.End(1), graph.start()));
    typer.Run();
  }

  Isolate* isolate;
  TickCounter tick_counter;
  const Operator* binop;
  const Operator* unop;
  JSOperatorBuilder javascript;
  MachineOperatorBuilder machine;
  SimplifiedOperatorBuilder simplified;
  CommonOperatorBuilder common;
  Graph graph;
  Typer typer;
  Node* context_node;
  CompilationDependencies deps;

  Node* Parameter(Type t, int32_t index = 0) {
    Node* n = graph.NewNode(common.Parameter(index), graph.start());
    NodeProperties::SetType(n, t);
    return n;
  }

  Node* UndefinedConstant() {
    Handle<HeapObject> value = isolate->factory()->undefined_value();
    return graph.NewNode(common.HeapConstant(value));
  }

  Node* HeapConstantNoHole(Handle<HeapObject> constant) {
    return graph.NewNode(common.HeapConstant(constant));
  }

  Node* EmptyFrameState(Node* context) {
    Node* parameters =
        graph.NewNode(common.StateValues(0, SparseInputMask::Dense()));
    Node* locals =
        graph.NewNode(common.StateValues(0, SparseInputMask::Dense()));
    Node* stack =
        graph.NewNode(common.StateValues(0, SparseInputMask::Dense()));

    Node* state_node = graph.NewNode(
        common.FrameState(BytecodeOffset::None(),
                          OutputFrameStateCombine::Ignore(), nullptr),
        parameters, locals, stack, context, UndefinedConstant(), graph.start());

    return state_node;
  }

  Node* reduce(Node* node) {
    JSGraph jsgraph(main_isolate(), &graph, &common, &javascript, &simplified,
                    &machine);
    GraphReducer graph_reducer(main_zone(), &graph, &tick_counter, broker());
    JSTypedLowering reducer(&graph_reducer, &jsgraph, broker(), main_zone());
    Reduction reduction = reducer.Reduce(node);
    if (reduction.Changed()) return reduction.replacement();
    return node;
  }

  Node* start() { return graph.start(); }

  Node* context() {
    if (context_node == nullptr) {
      context_node = graph.NewNode(common.Parameter(-1), graph.start());
    }
    return context_node;
  }

  Node* control() { return start(); }

  void CheckBinop(IrOpcode::Value expected, Node* node) {
    CHECK_EQ(expected, node->opcode());
  }

  void CheckBinop(const Operator* expected, Node* node) {
    CHECK_EQ(expected->opcode(), node->op()->opcode());
  }

  Node* ReduceUnop(const Operator* op, Type input_type) {
    return reduce(Unop(op, Parameter(input_type)));
  }

  Node* ReduceBinop(const Operator* op, Type left_type, Type right_type) {
    return reduce(Binop(op, Parameter(left_type, 0), Parameter(right_type, 1)));
  }

  Node* Binop(const Operator* op, Node* left, Node* right) {
    // JS binops also require context, effect, and control
    std::vector<Node*> inputs;
    inputs.push_back(left);
    inputs.push_back(right);
    if (JSOperator::IsBinaryWithFeedback(op->opcode())) {
      inputs.push_back(UndefinedConstant());  // Feedback vector.
    }
    if (OperatorProperties::HasContextInput(op)) {
      inputs.push_back(context());
    }
    for (int i = 0; i < OperatorProperties::GetFrameStateInputCount(op); i++) {
      inputs.push_back(EmptyFrameState(context()));
    }
    if (op->EffectInputCount() > 0) {
      inputs.push_back(start());
    }
    if (op->ControlInputCount() > 0) {
      inputs.push_back(control());
    }
    return graph.NewNode(op, static_cast<int>(inputs.size()),
                         &(inputs.front()));
  }

  Node* Unop(const Operator* op, Node* input) {
    DCHECK(!JSOperator::IsUnaryWithFeedback(op->opcode()));
    // JS unops also require context, effect, and control
    if (OperatorProperties::GetFrameStateInputCount(op) > 0) {
      CHECK_EQ(1, OperatorProperties::GetFrameStateInputCount(op));
      return graph.NewNode(op, input, context(), EmptyFrameState(context()),
                           start(), control());
    } else {
      return graph.NewNode(op, input, context(), start(), control());
    }
  }

  Node* UseForEffect(Node* node) {
    Node* merge = graph.NewNode(common.Merge(1), start());
    return graph.NewNode(common.EffectPhi(1), node, merge);
  }

  void CheckEffectInput(Node* effect, Node* use) {
    CHECK_EQ(effect, NodeProperties::GetEffectInput(use));
  }

  void CheckNumberConstant(double expected, Node* result) {
    CHECK_EQ(IrOpcode::kNumberConstant, result->opcode());
    CHECK_EQ(expected, OpParameter<double>(result->op()));
  }

  void CheckNaN(Node* result) {
    CHECK_EQ(IrOpcode::kNumberConstant, result->opcode());
    double value = OpParameter<double>(result->op());
    CHECK(std::isnan(value));
  }

  void CheckTrue(Node* result) {
    CheckHandle(isolate->factory()->true_value(), result);
  }

  void CheckFalse(Node* result) {
    CheckHandle(isolate->factory()->false_value(), result);
  }

  void CheckHandle(DirectHandle<HeapObject> expected, Node* result) {
    CHECK_EQ(IrOpcode::kHeapConstant, result->opcode());
    DirectHandle<HeapObject> value = HeapConstantOf(result->op());
    CHECK_EQ(*expected, *value);
  }
};

static Type kStringTypes[] = {Type::InternalizedString(), Type::String()};

static Type kInt32Types[] = {Type::UnsignedSmall(), Type::Negative32(),
                             Type::Unsigned31(),    Type::SignedSmall(),
                             Type::Signed32(),      Type::Unsigned32(),
                             Type::Integral32()};

static Type kNumberTypes[] = {
    Type::UnsignedSmall(), Type::Negative32(),  Type::Unsigned31(),
    Type::SignedSmall(),   Type::Signed32(),    Type::Unsigned32(),
    Type::Integral32(),    Type::MinusZero(),   Type::NaN(),
    Type::OrderedNumber(), Type::PlainNumber(), Type::Number()};

static Type I32Type(bool is_signed) {
  return is_signed ? Type::Signed32() : Type::Unsigned32();
}


static IrOpcode::Value NumberToI32(bool is_signed) {
  return is_signed ? IrOpcode::kNumberToInt32 : IrOpcode::kNumberToUint32;
}

namespace {

FeedbackSource FeedbackSourceWithOneBinarySlot(JSTypedLoweringTester* R) {
  return FeedbackSource{FeedbackVector::NewWithOneBinarySlotForTesting(
                            R->main_zone(), R->main_isolate()),
                        FeedbackSlot{0}};
}

FeedbackSource FeedbackSourceWithOneCompareSlot(JSTypedLoweringTester* R) {
  return FeedbackSource{FeedbackVector::NewWithOneCompareSlotForTesting(
                            R->main_zone(), R->main_isolate()),
                        FeedbackSlot{0}};
}

}  // namespace

TEST(StringBinops) {
  JSTypedLoweringTester R;

  for (size_t i = 0; i < arraysize(kStringTypes); ++i) {
    Node* p0 = R.Parameter(kStringTypes[i], 0);

    for (size_t j = 0; j < arraysize(kStringTypes); ++j) {
      Node* p1 = R.Parameter(kStringTypes[j], 1);

      Node* add = R.Binop(R.javascript.Add(FeedbackSourceWithOneBinarySlot(&R)),
                          p0, p1);
      Node* r = R.reduce(add);

      R.CheckBinop(IrOpcode::kStringConcat, r);
      CHECK_EQ(p0, r->InputAt(1));
      CHECK_EQ(p1, r->InputAt(2));
    }
  }
}

TEST(AddNumber1) {
  JSTypedLoweringTester R;
  for (size_t i = 0; i < arraysize(kNumberTypes); ++i) {
    Node* p0 = R.Parameter(kNumberTypes[i], 0);
    Node* p1 = R.Parameter(kNumberTypes[i], 1);
    Node* add =
        R.Binop(R.javascript.Add(FeedbackSourceWithOneBinarySlot(&R)), p0, p1);
    Node* r = R.reduce(add);

    R.CheckBinop(IrOpcode::kNumberAdd, r);
    CHECK_EQ(p0, r->InputAt(0));
    CHECK_EQ(p1, r->InputAt(1));
  }
}

TEST(NumberBinops) {
  JSTypedLoweringTester R;
  FeedbackSource feedback_source = FeedbackSourceWithOneBinarySlot(&R);
  const Operator* ops[] = {
      R.javascript.Add(feedback_source),      R.simplified.NumberAdd(),
      R.javascript.Subtract(feedback_source), R.simplified.NumberSubtract(),
      R.javascript.Multiply(feedback_source), R.simplified.NumberMultiply(),
      R.javascript.Divide(feedback_source),   R.simplified.NumberDivide(),
      R.javascript.Modulus(feedback_source),  R.simplified.NumberModulus(),
  };

  for (size_t i = 0; i < arraysize(kNumberTypes); ++i) {
    Node* p0 = R.Parameter(kNumberTypes[i], 0);

    for (size_t j = 0; j < arraysize(kNumberTypes); ++j) {
      Node* p1 = R.Parameter(kNumberTypes[j], 1);

      for (size_t k = 0; k < arraysize(ops); k += 2) {
        Node* add = R.Binop(ops[k], p0, p1);
        Node* r = R.reduce(add);

        R.CheckBinop(ops[k + 1], r);
        CHECK_EQ(p0, r->InputAt(0));
        CHECK_EQ(p1, r->InputAt(1));
      }
    }
  }
}


static void CheckToI32(Node* old_input, Node* new_input, bool is_signed) {
  Type old_type = NodeProperties::GetType(old_input);
  Type new_type = NodeProperties::GetType(new_input);
  Type expected_type = I32Type(is_signed);
  CHECK(new_type.Is(expected_type));
  if (old_type.Is(expected_type)) {
    CHECK_EQ(old_input, new_input);
  } else if (new_input->opcode() == IrOpcode::kNumberConstant) {
    double v = OpParameter<double>(new_input->op());
    double e = static_cast<double>(is_signed ? FastD2I(v) : FastD2UI(v));
    CHECK_EQ(e, v);
  }
}


// A helper class for testing lowering of bitwise shift operators.
class JSBitwiseShiftTypedLoweringTester : public JSTypedLoweringTester {
 public:
  JSBitwiseShiftTypedLoweringTester() : JSTypedLoweringTester() {
    int i = 0;
    FeedbackSource feedback_source = FeedbackSourceWithOneBinarySlot(this);
    set(i++, javascript.ShiftLeft(feedback_source), true);
    set(i++, simplified.NumberShiftLeft(), false);
    set(i++, javascript.ShiftRight(feedback_source), true);
    set(i++, simplified.NumberShiftRight(), false);
    set(i++, javascript.ShiftRightLogical(feedback_source), false);
    set(i++, simplified.NumberShiftRightLogical(), false);
  }
  static const int kNumberOps = 6;
  const Operator* ops[kNumberOps];
  bool signedness[kNumberOps];

 private:
  void set(int idx, const Operator* op, bool s) {
    ops[idx] = op;
    signedness[idx] = s;
  }
};


TEST(Int32BitwiseShifts) {
  JSBitwiseShiftTypedLoweringTester R;

  Type types[] = {
      Type::SignedSmall(), Type::UnsignedSmall(), Type::Negative32(),
      Type::Unsigned31(),  Type::Unsigned32(),    Type::Signed32(),
      Type::MinusZero(),   Type::NaN(),           Type::Undefined(),
      Type::Null(),        Type::Boolean(),       Type::Number(),
      Type::PlainNumber(), Type::String()};

  for (size_t i = 0; i < arraysize(types); ++i) {
    Node* p0 = R.Parameter(types[i], 0);

    for (size_t j = 0; j < arraysize(types); ++j) {
      Node* p1 = R.Parameter(types[j], 1);

      for (int k = 0; k < R.kNumberOps; k += 2) {
        Node* add = R.Binop(R.ops[k], p0, p1);
        Node* r = R.reduce(add);

        R.CheckBinop(R.ops[k + 1], r);
        Node* r0 = r->InputAt(0);
        Node* r1 = r->InputAt(1);

        CheckToI32(p0, r0, R.signedness[k]);
        CheckToI32(p1, r1, false);
      }
    }
  }
}


// A helper class for testing lowering of bitwise operators.
class JSBitwiseTypedLoweringTester : public JSTypedLoweringTester {
 public:
  JSBitwiseTypedLoweringTester() : JSTypedLoweringTester() {
    int i = 0;
    FeedbackSource feedback_source = FeedbackSourceWithOneBinarySlot(this);
    set(i++, javascript.BitwiseOr(feedback_source), true);
    set(i++, simplified.NumberBitwiseOr(), true);
    set(i++, javascript.BitwiseXor(feedback_source), true);
    set(i++, simplified.NumberBitwiseXor(), true);
    set(i++, javascript.BitwiseAnd(feedback_source), true);
    set(i++, simplified.NumberBitwiseAnd(), true);
  }
  static const int kNumberOps = 6;
  const Operator* ops[kNumberOps];
  bool signedness[kNumberOps];

 private:
  void set(int idx, const Operator* op, bool s) {
    ops[idx] = op;
    signedness[idx] = s;
  }
};


TEST(Int32BitwiseBinops) {
  JSBitwiseTypedLoweringTester R;

  Type types[] = {
      Type::SignedSmall(),   Type::UnsignedSmall(), Type::Unsigned32(),
      Type::Signed32(),      Type::MinusZero(),     Type::NaN(),
      Type::OrderedNumber(), Type::PlainNumber(),   Type::Undefined(),
      Type::Null(),          Type::Boolean(),       Type::Number(),
      Type::String()};

  for (size_t i = 0; i < arraysize(types); ++i) {
    Node* p0 = R.Parameter(types[i], 0);

    for (size_t j = 0; j < arraysize(types); ++j) {
      Node* p1 = R.Parameter(types[j], 1);

      for (int k = 0; k < R.kNumberOps; k += 2) {
        Node* add = R.Binop(R.ops[k], p0, p1);
        Node* r = R.reduce(add);

        R.CheckBinop(R.ops[k + 1], r);

        CheckToI32(p0, r->InputAt(0), R.signedness[k]);
        CheckToI32(p1, r->InputAt(1), R.signedness[k + 1]);
      }
    }
  }
}


TEST(JSToNumber1) {
  JSTypedLoweringTester R;
  const Operator* ton = R.javascript.ToNumber();

  for (size_t i = 0; i < arraysize(kNumberTypes); i++) {  // ToNumber(number)
    Node* r = R.ReduceUnop(ton, kNumberTypes[i]);
    CHECK_EQ(IrOpcode::kParameter, r->opcode());
  }

  {  // ToNumber(undefined)
    Node* r = R.ReduceUnop(ton, Type::Undefined());
    R.CheckNaN(r);
  }

  {  // ToNumber(null)
    Node* r = R.ReduceUnop(ton, Type::Null());
    R.CheckNumberConstant(0.0, r);
  }
}


TEST(JSToNumber_replacement) {
  JSTypedLoweringTester R;

  Type types[] = {Type::Null(), Type::Undefined(), Type::Number()};

  for (size_t i = 0; i < arraysize(types); i++) {
    Node* n = R.Parameter(types[i]);
    Node* c =
        R.graph.NewNode(R.javascript.ToNumber(), n, R.context(),
                        R.EmptyFrameState(R.context()), R.start(), R.start());
    Node* effect_use = R.UseForEffect(c);
    Node* add = R.graph.NewNode(R.simplified.ReferenceEqual(), n, c);

    R.CheckEffectInput(c, effect_use);
    Node* r = R.reduce(c);

    if (types[i].Is(Type::Number())) {
      CHECK_EQ(n, r);
    } else {
      CHECK_EQ(IrOpcode::kNumberConstant, r->opcode());
    }

    CHECK_EQ(n, add->InputAt(0));
    CHECK_EQ(r, add->InputAt(1));
    R.CheckEffectInput(R.start(), effect_use);
  }
}


TEST(JSToNumberOfConstant) {
  JSTypedLoweringTester R;

  const Operator* ops[] = {R.common.NumberConstant(0),
                           R.common.NumberConstant(-1),
                           R.common.NumberConstant(0.1)};

  for (size_t i = 0; i < arraysize(ops); i++) {
    Node* n = R.graph.NewNode(ops[i]);
    Node* convert = R.Unop(R.javascript.ToNumber(), n);
    Node* r = R.reduce(convert);
    // Note that either outcome below is correct. It only depends on whether
    // the types of constants are eagerly computed or only computed by the
    // typing pass.
    if (NodeProperties::GetType(n).Is(Type::Number())) {
      // If number constants are eagerly typed, then reduction should
      // remove the ToNumber.
      CHECK_EQ(n, r);
    } else {
      // Otherwise, type-based lowering should only look at the type, and
      // *not* try to constant fold.
      CHECK_EQ(convert, r);
    }
  }
}


TEST(JSToNumberOfNumberOrOtherPrimitive) {
  JSTypedLoweringTester R;
  Type others[] = {Type::Undefined(), Type::Null(), Type::Boolean(),
                   Type::String()};

  for (size_t i = 0; i < arraysize(others); i++) {
    Type t = Type::Union(Type::Number(), others[i], R.main_zone());
    Node* r = R.ReduceUnop(R.javascript.ToNumber(), t);
    CHECK_EQ(IrOpcode::kPlainPrimitiveToNumber, r->opcode());
  }
}


TEST(JSToString1) {
  JSTypedLoweringTester R;

  for (size_t i = 0; i < arraysize(kStringTypes); i++) {
    Node* r = R.ReduceUnop(R.javascript.ToString(), kStringTypes[i]);
    CHECK_EQ(IrOpcode::kParameter, r->opcode());
  }

  const Operator* op = R.javascript.ToString();

  {  // ToString(undefined) => "undefined"
    Node* r = R.ReduceUnop(op, Type::Undefined());
    R.CheckHandle(R.isolate->factory()->undefined_string(), r);
  }

  {  // ToString(null) => "null"
    Node* r = R.ReduceUnop(op, Type::Null());
    R.CheckHandle(R.isolate->factory()->null_string(), r);
  }

  {  // ToString(boolean)
    Node* r = R.ReduceUnop(op, Type::Boolean());
    CHECK_EQ(IrOpcode::kSelect, r->opcode());
  }

  {  // ToString(number)
    Node* r = R.ReduceUnop(op, Type::Number());
    CHECK_EQ(IrOpcode::kNumberToString, r->opcode());
  }

  {  // ToString(string)
    Node* r = R.ReduceUnop(op, Type::String());
    CHECK_EQ(IrOpcode::kParameter, r->opcode());  // No-op
  }

  {  // ToString(object)
    Node* r = R.ReduceUnop(op, Type::Object());
    CHECK_EQ(IrOpcode::kJSToString, r->opcode());  // No reduction.
  }
}


TEST(JSToString_replacement) {
  JSTypedLoweringTester R;

  Type types[] = {Type::Null(), Type::Undefined(), Type::String()};

  for (size_t i = 0; i < arraysize(types); i++) {
    Node* n = R.Parameter(types[i]);
    Node* c =
        R.graph.NewNode(R.javascript.ToString(), n, R.context(),
                        R.EmptyFrameState(R.context()), R.start(), R.start());
    Node* effect_use = R.UseForEffect(c);
    Node* add = R.graph.NewNode(R.simplified.ReferenceEqual(), n, c);

    R.CheckEffectInput(c, effect_use);
    Node* r = R.reduce(c);

    if (types[i].Is(Type::String())) {
      CHECK_EQ(n, r);
    } else {
      CHECK_EQ(IrOpcode::kHeapConstant, r->opcode());
    }

    CHECK_EQ(n, add->InputAt(0));
    CHECK_EQ(r, add->InputAt(1));
    R.CheckEffectInput(R.start(), effect_use);
  }
}

TEST(StringComparison) {
  JSTypedLoweringTester R;
  FeedbackSource feedback_source = FeedbackSourceWithOneCompareSlot(&R);

  const Operator* ops[] = {R.javascript.LessThan(feedback_source),
                           R.simplified.StringLessThan(),
                           R.javascript.LessThanOrEqual(feedback_source),
                           R.simplified.StringLessThanOrEqual(),
                           R.javascript.GreaterThan(feedback_source),
                           R.simplified.StringLessThan(),
                           R.javascript.GreaterThanOrEqual(feedback_source),
                           R.simplified.StringLessThanOrEqual()};

  for (size_t i = 0; i < arraysize(kStringTypes); i++) {
    Node* p0 = R.Parameter(kStringTypes[i], 0);
    for (size_t j = 0; j < arraysize(kStringTypes); j++) {
      Node* p1 = R.Parameter(kStringTypes[j], 1);

      for (size_t k = 0; k < arraysize(ops); k += 2) {
        Node* cmp = R.Binop(ops[k], p0, p1);
        Node* r = R.reduce(cmp);

        R.CheckBinop(ops[k + 1], r);
        if (k >= 4) {
          // GreaterThan and GreaterThanOrEqual commute the inputs
          // and use the LessThan and LessThanOrEqual operators.
          CHECK_EQ(p1, r->InputAt(0));
          CHECK_EQ(p0, r->InputAt(1));
        } else {
          CHECK_EQ(p0, r->InputAt(0));
          CHECK_EQ(p1, r->InputAt(1));
        }
      }
    }
  }
}


static void CheckIsConvertedToNumber(Node* val, Node* converted) {
  if (NodeProperties::GetType(val).Is(Type::Number())) {
    CHECK_EQ(val, converted);
  } else {
    if (converted->opcode() == IrOpcode::kNumberConstant) return;
    CHECK(IrOpcode::kJSToNumber == converted->opcode() ||
          IrOpcode::kJSToNumberConvertBigInt == converted->opcode());
    CHECK_EQ(val, converted->InputAt(0));
  }
}

TEST(NumberComparison) {
  JSTypedLoweringTester R;
  FeedbackSource feedback_source = FeedbackSourceWithOneCompareSlot(&R);

  const Operator* ops[] = {R.javascript.LessThan(feedback_source),
                           R.simplified.NumberLessThan(),
                           R.javascript.LessThanOrEqual(feedback_source),
                           R.simplified.NumberLessThanOrEqual(),
                           R.javascript.GreaterThan(feedback_source),
                           R.simplified.NumberLessThan(),
                           R.javascript.GreaterThanOrEqual(feedback_source),
                           R.simplified.NumberLessThanOrEqual()};

  Node* const p0 = R.Parameter(Type::Number(), 0);
  Node* const p1 = R.Parameter(Type::Number(), 1);

  for (size_t k = 0; k < arraysize(ops); k += 2) {
    Node* cmp = R.Binop(ops[k], p0, p1);
    Node* r = R.reduce(cmp);

    R.CheckBinop(ops[k + 1], r);
    if (k >= 4) {
      // GreaterThan and GreaterThanOrEqual commute the inputs
      // and use the LessThan and LessThanOrEqual operators.
      CheckIsConvertedToNumber(p1, r->InputAt(0));
      CheckIsConvertedToNumber(p0, r->InputAt(1));
    } else {
      CheckIsConvertedToNumber(p0, r->InputAt(0));
      CheckIsConvertedToNumber(p1, r->InputAt(1));
    }
  }
}

TEST(MixedComparison1) {
  JSTypedLoweringTester R;
  FeedbackSource feedback_source = FeedbackSourceWithOneCompareSlot(&R);

  Type types[] = {Type::Number(), Type::String(),
                  Type::Union(Type::Number(), Type::String(), R.main_zone())};

  for (size_t i = 0; i < arraysize(types); i++) {
    Node* p0 = R.Parameter(types[i], 0);

    for (size_t j = 0; j < arraysize(types); j++) {
      Node* p1 = R.Parameter(types[j], 1);
      {
        const Operator* less_than = R.javascript.LessThan(feedback_source);
        Node* cmp = R.Binop(less_than, p0, p1);
        Node* r = R.reduce(cmp);
        if (types[i].Is(Type::String()) && types[j].Is(Type::String())) {
          R.CheckBinop(R.simplified.StringLessThan(), r);
        } else if ((types[i].Is(Type::Number()) &&
                    types[j].Is(Type::Number())) ||
                   (!types[i].Maybe(Type::String()) ||
                    !types[j].Maybe(Type::String()))) {
          R.CheckBinop(R.simplified.NumberLessThan(), r);
        } else {
          // No reduction of mixed types.
          CHECK_EQ(r->op(), less_than);
        }
      }
    }
  }
}

TEST(RemoveToNumberEffects) {
  JSTypedLoweringTester R;

  FeedbackSource feedback_source = FeedbackSourceWithOneBinarySlot(&R);
  Node* feedback = R.UndefinedConstant();
  Node* effect_use = nullptr;
  Node* zero = R.graph.NewNode(R.common.NumberConstant(0));
  for (int i = 0; i < 10; i++) {
    Node* p0 = R.Parameter(Type::Number());
    Node* ton = R.Unop(R.javascript.ToNumber(), p0);
    Node* frame_state = R.EmptyFrameState(R.context());
    effect_use = nullptr;

    switch (i) {
      case 0:
        CHECK_EQ(1, OperatorProperties::GetFrameStateInputCount(
                        R.javascript.ToNumber()));
        effect_use = R.graph.NewNode(R.javascript.ToNumber(), p0, R.context(),
                                     frame_state, ton, R.start());
        break;
      case 1:
        CHECK_EQ(1, OperatorProperties::GetFrameStateInputCount(
                        R.javascript.ToNumber()));
        effect_use = R.graph.NewNode(R.javascript.ToNumber(), ton, R.context(),
                                     frame_state, ton, R.start());
        break;
      case 2:
        effect_use = R.graph.NewNode(R.common.EffectPhi(1), ton, R.start());
        break;
      case 3:
        effect_use =
            R.graph.NewNode(R.javascript.Add(feedback_source), ton, ton,
                            feedback, R.context(), frame_state, ton, R.start());
        break;
      case 4:
        effect_use =
            R.graph.NewNode(R.javascript.Add(feedback_source), p0, p0, feedback,
                            R.context(), frame_state, ton, R.start());
        break;
      case 5:
        effect_use =
            R.graph.NewNode(R.common.Return(), zero, p0, ton, R.start());
        break;
      case 6:
        effect_use =
            R.graph.NewNode(R.common.Return(), zero, ton, ton, R.start());
    }

    R.CheckEffectInput(R.start(), ton);
    if (effect_use != nullptr) R.CheckEffectInput(ton, effect_use);

    Node* r = R.reduce(ton);
    CHECK_EQ(p0, r);
    CHECK_NE(R.start(), r);

    if (effect_use != nullptr) {
      R.CheckEffectInput(R.start(), effect_use);
      // Check that value uses of ToNumber() do not go to start().
      for (int j = 0; j < effect_use->op()->ValueInputCount(); j++) {
        CHECK_NE(R.start(), effect_use->InputAt(j));
      }
    }
  }

  CHECK(!effect_use);  // should have done all cases above.
}


// Helper class for testing the reduction of a single binop.
class BinopEffectsTester {
 public:
  BinopEffectsTester(const Operator* op, Type t0, Type t1)
      : R(0),
        p0(R.Parameter(t0, 0)),
        p1(R.Parameter(t1, 1)),
        binop(R.Binop(op, p0, p1)),
        effect_use(R.graph.NewNode(R.common.EffectPhi(1), binop, R.start())) {
    // Effects should be ordered start -> binop -> effect_use
    R.CheckEffectInput(R.start(), binop);
    R.CheckEffectInput(binop, effect_use);
    result = R.reduce(binop);
  }

  JSTypedLoweringTester R;
  Node* p0;
  Node* p1;
  Node* binop;
  Node* effect_use;
  Node* result;

  void CheckEffectsRemoved() { R.CheckEffectInput(R.start(), effect_use); }

  void CheckEffectOrdering(Node* n0) {
    R.CheckEffectInput(R.start(), n0);
    R.CheckEffectInput(n0, effect_use);
  }

  void CheckEffectOrdering(Node* n0, Node* n1) {
    R.CheckEffectInput(R.start(), n0);
    R.CheckEffectInput(n0, n1);
    R.CheckEffectInput(n1, effect_use);
  }

  Node* CheckConvertedInput(IrOpcode::Value opcode, int which, bool effects) {
    return CheckConverted(opcode, result->InputAt(which), effects);
  }

  Node* CheckConverted(IrOpcode::Value opcode, Node* node, bool effects) {
    CHECK_EQ(opcode, node->opcode());
    if (effects) {
      CHECK_LT(0, node->op()->EffectInputCount());
    } else {
      CHECK_EQ(0, node->op()->EffectInputCount());
    }
    return node;
  }

  Node* CheckNoOp(int which) {
    CHECK_EQ(which == 0 ? p0 : p1, result->InputAt(which));
    return result->InputAt(which);
  }
};


// Helper function for strict and non-strict equality reductions.
void CheckEqualityReduction(JSTypedLoweringTester* R, bool strict, Node* l,
                            Node* r, IrOpcode::Value expected) {
  FeedbackSource feedback_source = FeedbackSourceWithOneCompareSlot(R);
  for (int j = 0; j < 2; j++) {
    Node* p0 = j == 0 ? l : r;
    Node* p1 = j == 1 ? l : r;

    {
      const Operator* op = strict ? R->javascript.StrictEqual(feedback_source)
                                  : R->javascript.Equal(feedback_source);
      Node* eq = R->Binop(op, p0, p1);
      Node* reduced = R->reduce(eq);
      R->CheckBinop(expected, reduced);
    }
  }
}


TEST(EqualityForNumbers) {
  JSTypedLoweringTester R;

  Type simple_number_types[] = {Type::UnsignedSmall(), Type::SignedSmall(),
                                Type::Signed32(), Type::Unsigned32(),
                                Type::Number()};

  for (size_t i = 0; i < arraysize(simple_number_types); ++i) {
    Node* p0 = R.Parameter(simple_number_types[i], 0);

    for (size_t j = 0; j < arraysize(simple_number_types); ++j) {
      Node* p1 = R.Parameter(simple_number_types[j], 1);

      CheckEqualityReduction(&R, true, p0, p1, IrOpcode::kNumberEqual);
      CheckEqualityReduction(&R, false, p0, p1, IrOpcode::kNumberEqual);
    }
  }
}


TEST(StrictEqualityForRefEqualTypes) {
  JSTypedLoweringTester R;

  Type types[] = {Type::Undefined(), Type::Null(), Type::Boolean(),
                  Type::Object(), Type::Receiver()};

  Node* p0 = R.Parameter(Type::Any());
  for (size_t i = 0; i < arraysize(types); i++) {
    Node* p1 = R.Parameter(types[i]);
    CheckEqualityReduction(&R, true, p0, p1, IrOpcode::kReferenceEqual);
  }
}

TEST(StrictEqualityForUnique) {
  JSTypedLoweringTester R;

  Node* p0 = R.Parameter(Type::Unique());
  Node* p1 = R.Parameter(Type::Unique());
  CheckEqualityReduction(&R, true, p0, p1, IrOpcode::kReferenceEqual);
  CheckEqualityReduction(&R, true, p1, p0, IrOpcode::kReferenceEqual);
}

TEST(StringEquality) {
  JSTypedLoweringTester R;
  Node* p0 = R.Parameter(Type::String());
  Node* p1 = R.Parameter(Type::String());

  CheckEqualityReduction(&R, true, p0, p1, IrOpcode::kStringEqual);
  CheckEqualityReduction(&R, false, p0, p1, IrOpcode::kStringEqual);
}

TEST(RemovePureNumberBinopEffects) {
  JSTypedLoweringTester R;
  FeedbackSource binary_source = FeedbackSourceWithOneBinarySlot(&R);
  FeedbackSource compare_source = FeedbackSourceWithOneCompareSlot(&R);

  const Operator* ops[] = {
      R.javascript.Equal(compare_source),
      R.simplified.NumberEqual(),
      R.javascript.Add(binary_source),
      R.simplified.NumberAdd(),
      R.javascript.Subtract(binary_source),
      R.simplified.NumberSubtract(),
      R.javascript.Multiply(binary_source),
      R.simplified.NumberMultiply(),
      R.javascript.Divide(binary_source),
      R.simplified.NumberDivide(),
      R.javascript.Modulus(binary_source),
      R.simplified.NumberModulus(),
      R.javascript.LessThan(compare_source),
      R.simplified.NumberLessThan(),
      R.javascript.LessThanOrEqual(compare_source),
      R.simplified.NumberLessThanOrEqual(),
  };

  for (size_t j = 0; j < arraysize(ops); j += 2) {
    BinopEffectsTester B(ops[j], Type::Number(), Type::Number());
    CHECK_EQ(ops[j + 1]->opcode(), B.result->op()->opcode());

    B.R.CheckBinop(B.result->opcode(), B.result);

    B.CheckNoOp(0);
    B.CheckNoOp(1);

    B.CheckEffectsRemoved();
  }
}

TEST(Int32BinopEffects) {
  JSBitwiseTypedLoweringTester R;
  for (int j = 0; j < R.kNumberOps; j += 2) {
    bool signed_left = R.signedness[j], signed_right = R.signedness[j + 1];
    BinopEffectsTester B(R.ops[j], I32Type(signed_left), I32Type(signed_right));
    CHECK_EQ(R.ops[j + 1]->opcode(), B.result->op()->opcode());

    B.R.CheckBinop(B.result->opcode(), B.result);

    B.CheckNoOp(0);
    B.CheckNoOp(1);

    B.CheckEffectsRemoved();
  }

  for (int j = 0; j < R.kNumberOps; j += 2) {
    bool signed_left = R.signedness[j], signed_right = R.signedness[j + 1];
    BinopEffectsTester B(R.ops[j], Type::Number(), Type::Number());
    CHECK_EQ(R.ops[j + 1]->opcode(), B.result->op()->opcode());

    B.R.CheckBinop(B.result->opcode(), B.result);

    B.CheckConvertedInput(NumberToI32(signed_left), 0, false);
    B.CheckConvertedInput(NumberToI32(signed_right), 1, false);

    B.CheckEffectsRemoved();
  }

  for (int j = 0; j < R.kNumberOps; j += 2) {
    bool signed_left = R.signedness[j];
    BinopEffectsTester B(R.ops[j], Type::Number(), Type::Boolean());

    B.R.CheckBinop(B.result->opcode(), B.result);

    B.CheckConvertedInput(NumberToI32(signed_left), 0, false);
    B.CheckConvertedInput(IrOpcode::kPlainPrimitiveToNumber, 1, false);

    B.CheckEffectsRemoved();
  }

  for (int j = 0; j < R.kNumberOps; j += 2) {
    bool signed_right = R.signedness[j + 1];
    BinopEffectsTester B(R.ops[j], Type::Boolean(), Type::Number());

    B.R.CheckBinop(B.result->opcode(), B.result);

    B.CheckConvertedInput(IrOpcode::kPlainPrimitiveToNumber, 0, false);
    B.CheckConvertedInput(NumberToI32(signed_right), 1, false);

    B.CheckEffectsRemoved();
  }

  for (int j = 0; j < R.kNumberOps; j += 2) {
    BinopEffectsTester B(R.ops[j], Type::Boolean(), Type::Boolean());

    B.R.CheckBinop(B.result->opcode(), B.result);

    B.CheckConvertedInput(IrOpcode::kPlainPrimitiveToNumber, 0, false);
    B.CheckConvertedInput(IrOpcode::kPlainPrimitiveToNumber, 1, false);

    B.CheckEffectsRemoved();
  }
}

TEST(Int32AddNarrowing) {
  {
    JSBitwiseTypedLoweringTester R;

    for (int o = 0; o < R.kNumberOps; o += 2) {
      for (size_t i = 0; i < arraysize(kInt32Types); i++) {
        Node* n0 = R.Parameter(kInt32Types[i]);
        for (size_t j = 0; j < arraysize(kInt32Types); j++) {
          Node* n1 = R.Parameter(kInt32Types[j]);
          Node* one = R.graph.NewNode(R.
```