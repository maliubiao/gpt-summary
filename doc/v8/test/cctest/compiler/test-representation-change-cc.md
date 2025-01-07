Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request asks for a functional summary of the C++ code, along with explanations, JavaScript analogies (if applicable), logic inference examples, and common programming errors related to its purpose.

2. **Initial Scan and Keywords:** Quickly skim the code, looking for keywords and patterns that reveal the core functionality. Keywords like "RepresentationChanger," "MachineRepresentation," "Type," "GetRepresentationFor," "Check...", "Constant," and "TEST" are strong indicators. The file path also gives a hint: `v8/test/cctest/compiler/test-representation-change.cc`. This immediately suggests it's a *test* file for a compiler component related to *representation changes*.

3. **Identify the Core Class:** The class `RepresentationChangerTester` is central. Its members (`changer_`, `jsgraph_`, `broker()`) point to interactions with the V8 compiler infrastructure. The inheritance (`HandleAndZoneScope`, `GraphAndBuilders`, `JSHeapBrokerTestBase`) reinforces that this is a testing setup.

4. **Analyze the Tester Class Methods:**
    * **Constructor:** Sets up the testing environment, creating a graph, JSGraph, and the `RepresentationChanger`.
    * **`Check...Constant` methods:** These are helper functions to verify that a node in the graph represents a specific constant value of a given type (Int32, Int64, Float64, etc.). This confirms the code is about manipulating and verifying data representations.
    * **`Parameter`:** Creates a parameter node, likely used as input to representation changes.
    * **`Return`:** Creates a return node, acting as a consumer of the potentially changed representation.
    * **`CheckTypeError`:**  Specifically tests for scenarios that *should* result in a type error during representation change.
    * **`CheckNop`:** Tests cases where the representation remains the same (a "no-operation").

5. **Focus on `RepresentationChanger::GetRepresentationFor`:** This is the crucial method being tested. The test cases call this function with various `MachineRepresentation` (like `kTagged`, `kFloat64`, `kWord32`), `Type` (like `Signed32`, `Unsigned32`, `Number`), and `UseInfo`. This confirms the function's role in converting between different data representations while considering type information and how the result will be used.

6. **Examine the Test Cases (TEST blocks):** The `TEST` blocks reveal specific scenarios being tested. Notice the patterns:
    * **Constant Conversions:** Tests like `BoolToBit_constant`, `ToTagged_constant`, `ToFloat64_constant`, `ToInt32_constant`, etc., check how constant values are converted between representations.
    * **General Conversions (`CheckChange`, `CheckTwoChanges`):** These tests use the `Parameter` and `Return` methods to simulate a data flow and check if `GetRepresentationFor` inserts the correct conversion operations (like `ChangeInt32ToInt64`, `TruncateFloat64ToInt32`).
    * **Specific Scenarios:** Tests like `Word64`, `SingleChanges`, `SignednessInWord32`, `MinusZeroCheck`, `Nops`, and `TypeErrors` target particular aspects of representation changes and potential issues.

7. **Connect to Compiler Concepts:**  Realize that "representation change" is a core compiler optimization technique. Compilers need to efficiently convert data between different internal formats (e.g., integers, floats, pointers) based on the operations being performed. This test suite ensures the `RepresentationChanger` component does this correctly.

8. **Relate to JavaScript (if possible):** While the code is C++, the concept of type conversion is fundamental in JavaScript. Think about implicit and explicit conversions (e.g., `Number("10")`, `10 + ""`). This leads to the JavaScript examples provided in the intended answer.

9. **Consider Logic Inference:** The `CheckChange` and `CheckTwoChanges` functions with their assertions demonstrate logic inference. You provide an input representation and type, a target representation, and the test verifies that the correct conversion *operation* is inserted into the graph. The assumptions here are that the input graph and types are set up correctly.

10. **Think about Common Programming Errors:**  Given the focus on representation changes, common errors in programming involve incorrect type conversions, leading to unexpected results, loss of precision, or runtime errors. This leads to examples like mixing integer and floating-point types without explicit conversion or assuming a value fits within a specific representation's limits.

11. **Structure the Answer:** Organize the findings into logical sections: Functionality, Torque connection, JavaScript relation, Logic Inference, and Common Errors. Provide clear explanations and concrete examples for each point.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Is this about JavaScript's dynamic typing?  **Correction:** While related to types, it's more about the *compiler's internal representation* of those types.
* **Realization:** The `UseInfo` parameter in `GetRepresentationFor` is important. It indicates *how* the result will be used, which can influence the necessary conversion.
* **Clarification:** Distinguish between implicit and explicit conversions in the JavaScript examples.
* **Emphasis:** Highlight that the C++ code is a *test* for the `RepresentationChanger` component, not the component itself.

By following these steps, iterating through the code, and connecting it to compiler concepts and JavaScript analogies, we arrive at a comprehensive understanding of the C++ file's purpose and its implications.
这个C++源代码文件 `v8/test/cctest/compiler/test-representation-change.cc` 的主要功能是**测试 V8 编译器中 `RepresentationChanger` 类的功能**。`RepresentationChanger` 负责在编译过程中，根据操作的需求以及值的类型，插入必要的节点来改变值的机器表示形式（Machine Representation）。

以下是该文件的详细功能列表：

**1. 测试 `RepresentationChanger` 的基本转换功能:**

   - **布尔值到比特 (BoolToBit):**  测试将 JavaScript 的 `true` 和 `false` 常量转换为机器比特表示 (0 或 1)。
   - **到 Tagged (ToTagged):** 测试将不同机器表示的常量值（例如 `float64`, `int32`, `uint32`）转换为 V8 的 `Tagged` 表示形式（可以包含数字、对象等）。
   - **到 Float64 (ToFloat64):** 测试将不同机器表示的常量值转换为 `float64` 的机器表示。
   - **到 Float32 (ToFloat32):** 测试将不同机器表示的常量值转换为 `float32` 的机器表示。
   - **到 Int32 (ToInt32):** 测试将不同机器表示的常量值转换为 `int32` 的机器表示。
   - **到 Uint32 (ToUint32):** 测试将不同机器表示的常量值转换为 `uint32` 的机器表示。
   - **到 Int64 (ToInt64):** 测试将不同机器表示的常量值转换为 `int64` 的机器表示。

**2. 测试通用的表示形式转换 (Generic Representation Changes):**

   - 使用 `CheckChange` 和 `CheckTwoChanges` 宏来测试在给定输入表示形式、类型和目标表示形式的情况下，`RepresentationChanger` 是否插入了预期的转换操作（例如 `kChangeInt32ToInt64`, `kTruncateFloat64ToInt32` 等）。
   - 测试了各种不同机器表示之间的转换，包括 `Word64`, `Tagged`, `Float32` 等。
   - 涵盖了带符号和无符号整数之间的转换，以及浮点数和整数之间的转换。

**3. 测试符号扩展和零扩展 (Signedness in Word32):**

   - 测试在 32 位机器字 (Word32) 的表示形式中，如何处理有符号和无符号数之间的转换。

**4. 测试负零检查 (MinusZeroCheck):**

   - 测试在将浮点数转换为整数时，如何处理负零的情况。这对于某些需要区分正零和负零的操作很重要。

**5. 测试无操作 (Nops):**

   - 测试在源表示形式和目标表示形式相同时，`RepresentationChanger` 不会插入任何额外的转换操作。

**6. 测试类型错误 (TypeErrors):**

   - 测试在进行不安全的或不允许的表示形式转换时，`RepresentationChanger` 是否能够正确识别并标记为类型错误。

**如果 `v8/test/cctest/compiler/test-representation-change.cc` 以 `.tq` 结尾:**

   那么它将是一个 **V8 Torque 源代码**文件。Torque 是一种用于编写 V8 内部函数的领域特定语言。这个文件会定义一些用 Torque 编写的测试，这些测试会更底层地验证类型转换和表示形式变更的逻辑。

**与 JavaScript 功能的关系 (JavaScript Examples):**

`RepresentationChanger` 的工作直接影响 JavaScript 代码的执行效率和正确性。JavaScript 是一种动态类型语言，运行时会进行大量的类型转换。`RepresentationChanger` 的正确性保证了这些转换在编译后的代码中能够高效且正确地执行。

以下是一些与 `RepresentationChanger` 功能相关的 JavaScript 例子：

```javascript
// 示例 1: 数字类型转换
let a = 10;        // 内部可能表示为 int32
let b = a + 0.5;   // '+' 操作可能导致 a 被转换为 float64

// 示例 2: 布尔类型转换
let c = true;      // 内部表示为某种布尔值
let d = c ? 1 : 0; // 条件表达式可能导致 c 被转换为数字

// 示例 3: 强制类型转换
let e = "5";
let f = parseInt(e); // parseInt 显式地将字符串转换为整数

// 示例 4: 比较操作
let g = 5;
let h = "5";
if (g == h) {       // '==' 可能会导致类型转换
  console.log("相等");
}
```

在编译这些 JavaScript 代码时，`RepresentationChanger` 会根据操作符和变量的类型信息，插入必要的转换节点，将值转换为操作所需的机器表示形式。例如，在示例 1 中，当 `a` (可能是 `int32`) 与 `0.5` (肯定是 `float64`) 相加时，`RepresentationChanger` 可能会插入一个节点将 `a` 的表示形式转换为 `float64`。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下代码片段，并且 `RepresentationChanger` 正在处理变量 `x` 的表示形式转换：

**假设输入:**

- `x` 是一个节点，表示一个 JavaScript 变量，其机器表示形式是 `MachineRepresentation::kTagged`。
- `x` 的类型信息是 `Type::Signed32()`，意味着编译器推断 `x` 的值很可能是一个有符号的 32 位整数。
- 我们需要将 `x` 的表示形式转换为 `MachineRepresentation::kWord32`，以便进行一些底层的位操作。

**预期输出:**

`RepresentationChanger` 会插入一个 `IrOpcode::kChangeTaggedToInt32` 节点。这个节点会将 `Tagged` 表示的整数值转换为 `Word32` 的机器表示。

**假设输入:**

- `y` 是一个节点，表示一个 JavaScript 变量，其机器表示形式是 `MachineRepresentation::kFloat64`。
- `y` 的类型信息是 `Type::Number()`。
- 我们需要将 `y` 的表示形式转换为 `MachineRepresentation::kWord32`，并且知道它的值应该在 `int32` 的范围内。

**预期输出:**

`RepresentationChanger` 可能会插入一个 `IrOpcode::kCheckedFloat64ToInt32` 节点。这是一个受检查的转换，它会在运行时检查浮点数是否可以安全地转换为 32 位整数。

**涉及用户常见的编程错误 (Examples):**

`RepresentationChanger` 试图处理 JavaScript 中各种隐式和显式类型转换。用户常见的编程错误与类型转换密切相关：

1. **隐式类型转换导致意外结果:**

   ```javascript
   let strNum = "10";
   let num = 5;
   let result = strNum + num; // 错误地将数字与字符串连接
   console.log(result); // 输出 "105"，而不是 15
   ```

   在这种情况下，JavaScript 的 `+` 运算符会优先进行字符串连接，导致 `num` 被隐式转换为字符串。`RepresentationChanger` 在编译时需要处理这种隐式转换。

2. **精度丢失:**

   ```javascript
   let bigInt = 9007199254740992; // 大于 JavaScript Number 的安全整数范围
   let num = bigInt;
   console.log(num); // 输出 9007199254740992，但内部可能损失精度

   let floatNum = 1.1;
   let intNum = parseInt(floatNum); // 显式转换为整数，丢失小数部分
   console.log(intNum); // 输出 1
   ```

   将大整数赋值给 `Number` 类型变量时，或者将浮点数转换为整数时，可能会发生精度丢失。`RepresentationChanger` 需要根据目标表示形式处理这种潜在的精度损失。

3. **不正确的类型假设:**

   ```javascript
   function processNumber(input) {
     // 假设 input 是一个数字
     let squared = input * input;
     return squared;
   }

   let value = "5";
   let result = processNumber(value); // 传入字符串，可能导致错误
   console.log(result); // 输出 NaN (Not a Number)
   ```

   如果函数或操作依赖于特定的数据类型，但实际传入了不同类型的值，就会导致错误。`RepresentationChanger` 在编译时会根据类型信息进行转换，但如果类型信息不准确或存在运行时类型错误，仍然可能出现问题。

4. **位操作的类型错误:**

   ```javascript
   let num = 5.5;
   let shifted = num << 2; // 对浮点数进行位移操作，结果可能不符合预期
   console.log(shifted); // 输出 20，因为浮点数会被转换为整数
   ```

   位操作通常应用于整数。对其他类型的值进行位操作可能会导致隐式类型转换，从而产生意想不到的结果。

总而言之，`v8/test/cctest/compiler/test-representation-change.cc` 是一个关键的测试文件，用于确保 V8 编译器能够正确地处理各种类型转换和表示形式变更，这对于 JavaScript 代码的正确高效执行至关重要。它通过各种测试用例验证了 `RepresentationChanger` 类的功能，涵盖了常量转换、通用转换、符号扩展、负零处理、无操作和类型错误等多个方面。

Prompt: 
```
这是目录为v8/test/cctest/compiler/test-representation-change.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/test-representation-change.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>

#include "src/compiler/access-info.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/representation-change.h"
#include "src/compiler/type-cache.h"
#include "src/objects/objects-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/compiler/codegen-tester.h"
#include "test/cctest/compiler/graph-and-builders.h"
#include "test/cctest/compiler/js-heap-broker-base.h"
#include "test/common/value-helper.h"

namespace v8 {
namespace internal {
namespace compiler {

class RepresentationChangerTester : public HandleAndZoneScope,
                                    public GraphAndBuilders,
                                    public JSHeapBrokerTestBase {
 public:
  explicit RepresentationChangerTester(int num_parameters = 0)
      : HandleAndZoneScope(kCompressGraphZone),
        GraphAndBuilders(main_zone()),
        JSHeapBrokerTestBase(main_isolate(), main_zone()),
        javascript_(main_zone()),
        jsgraph_(main_isolate(), main_graph_, &main_common_, &javascript_,
                 &main_simplified_, &main_machine_),
        changer_(&jsgraph_, broker(), nullptr) {
    Node* s = graph()->NewNode(common()->Start(num_parameters));
    graph()->SetStart(s);
  }

  JSOperatorBuilder javascript_;
  JSGraph jsgraph_;
  RepresentationChanger changer_;

  Isolate* isolate() { return main_isolate(); }
  Graph* graph() { return main_graph_; }
  CommonOperatorBuilder* common() { return &main_common_; }
  JSGraph* jsgraph() { return &jsgraph_; }
  RepresentationChanger* changer() { return &changer_; }

  // TODO(titzer): use ValueChecker / ValueUtil
  void CheckInt32Constant(Node* n, int32_t expected) {
    Int32Matcher m(n);
    CHECK(m.HasResolvedValue());
    CHECK_EQ(expected, m.ResolvedValue());
  }

  void CheckInt64Constant(Node* n, int64_t expected) {
    Int64Matcher m(n);
    CHECK(m.HasResolvedValue());
    CHECK_EQ(expected, m.ResolvedValue());
  }

  void CheckUint32Constant(Node* n, uint32_t expected) {
    Uint32Matcher m(n);
    CHECK(m.HasResolvedValue());
    CHECK_EQ(static_cast<int>(expected), static_cast<int>(m.ResolvedValue()));
  }

  void CheckFloat64Constant(Node* n, double expected) {
    Float64Matcher m(n);
    CHECK(m.HasResolvedValue());
    CHECK_DOUBLE_EQ(expected, m.ResolvedValue());
  }

  void CheckFloat32Constant(Node* n, float expected) {
    CHECK_EQ(IrOpcode::kFloat32Constant, n->opcode());
    float fval = OpParameter<float>(n->op());
    CHECK_FLOAT_EQ(expected, fval);
  }

  void CheckHeapConstant(Node* n, Tagged<HeapObject> expected) {
    HeapObjectMatcher m(n);
    CHECK(m.HasResolvedValue());
    CHECK_EQ(expected, *m.ResolvedValue());
  }

  void CheckNumberConstant(Node* n, double expected) {
    NumberMatcher m(n);
    CHECK_EQ(IrOpcode::kNumberConstant, n->opcode());
    CHECK(m.HasResolvedValue());
    CHECK_DOUBLE_EQ(expected, m.ResolvedValue());
  }

  Node* Parameter(int index = 0) {
    Node* n = graph()->NewNode(common()->Parameter(index), graph()->start());
    NodeProperties::SetType(n, Type::Any());
    return n;
  }

  Node* Return(Node* input) {
    Node* n = graph()->NewNode(common()->Return(), jsgraph()->Int32Constant(0),
                               input, graph()->start(), graph()->start());
    return n;
  }

  void CheckTypeError(MachineRepresentation from, Type from_type,
                      MachineRepresentation to) {
    changer()->testing_type_errors_ = true;
    changer()->type_error_ = false;
    Node* n = Parameter(0);
    Node* use = Return(n);
    Node* c = changer()->GetRepresentationFor(n, from, from_type, use,
                                              UseInfo(to, Truncation::None()));
    CHECK(changer()->type_error_);
    CHECK_EQ(n, c);
  }

  void CheckNop(MachineRepresentation from, Type from_type,
                MachineRepresentation to) {
    Node* n = Parameter(0);
    Node* use = Return(n);
    Node* c = changer()->GetRepresentationFor(n, from, from_type, use,
                                              UseInfo(to, Truncation::None()));
    CHECK_EQ(n, c);
  }
};

const MachineType kMachineTypes[] = {
    MachineType::Float32(), MachineType::Float64(),  MachineType::Int8(),
    MachineType::Uint8(),   MachineType::Int16(),    MachineType::Uint16(),
    MachineType::Int32(),   MachineType::Uint32(),   MachineType::Int64(),
    MachineType::Uint64(),  MachineType::AnyTagged()};

TEST(BoolToBit_constant) {
  RepresentationChangerTester r;

  Node* true_node = r.jsgraph()->TrueConstant();
  Node* true_use = r.Return(true_node);
  Node* true_bit = r.changer()->GetRepresentationFor(
      true_node, MachineRepresentation::kTagged, Type::None(), true_use,
      UseInfo(MachineRepresentation::kBit, Truncation::None()));
  r.CheckInt32Constant(true_bit, 1);

  Node* false_node = r.jsgraph()->FalseConstant();
  Node* false_use = r.Return(false_node);
  Node* false_bit = r.changer()->GetRepresentationFor(
      false_node, MachineRepresentation::kTagged, Type::None(), false_use,
      UseInfo(MachineRepresentation::kBit, Truncation::None()));
  r.CheckInt32Constant(false_bit, 0);
}

TEST(ToTagged_constant) {
  RepresentationChangerTester r;

  for (double i : ValueHelper::float64_vector()) {
    Node* n = r.jsgraph()->ConstantNoHole(i);
    Node* use = r.Return(n);
    Node* c = r.changer()->GetRepresentationFor(
        n, MachineRepresentation::kFloat64, Type::None(), use,
        UseInfo(MachineRepresentation::kTagged, Truncation::None()));
    r.CheckNumberConstant(c, i);
  }

  for (int i : ValueHelper::int32_vector()) {
    Node* n = r.jsgraph()->ConstantNoHole(i);
    Node* use = r.Return(n);
    Node* c = r.changer()->GetRepresentationFor(
        n, MachineRepresentation::kWord32, Type::Signed32(), use,
        UseInfo(MachineRepresentation::kTagged, Truncation::None()));
    r.CheckNumberConstant(c, i);
  }

  for (uint32_t i : ValueHelper::uint32_vector()) {
    Node* n = r.jsgraph()->ConstantNoHole(i);
    Node* use = r.Return(n);
    Node* c = r.changer()->GetRepresentationFor(
        n, MachineRepresentation::kWord32, Type::Unsigned32(), use,
        UseInfo(MachineRepresentation::kTagged, Truncation::None()));
    r.CheckNumberConstant(c, i);
  }
}

TEST(ToFloat64_constant) {
  RepresentationChangerTester r;

  for (double i : ValueHelper::float64_vector()) {
    Node* n = r.jsgraph()->ConstantNoHole(i);
    Node* use = r.Return(n);
    Node* c = r.changer()->GetRepresentationFor(
        n, MachineRepresentation::kTagged, Type::None(), use,
        UseInfo(MachineRepresentation::kFloat64, Truncation::None()));
    r.CheckFloat64Constant(c, i);
  }

  for (int i : ValueHelper::int32_vector()) {
    Node* n = r.jsgraph()->ConstantNoHole(i);
    Node* use = r.Return(n);
    Node* c = r.changer()->GetRepresentationFor(
        n, MachineRepresentation::kWord32, Type::Signed32(), use,
        UseInfo(MachineRepresentation::kFloat64, Truncation::None()));
    r.CheckFloat64Constant(c, i);
  }

  for (uint32_t i : ValueHelper::uint32_vector()) {
    Node* n = r.jsgraph()->ConstantNoHole(i);
    Node* use = r.Return(n);
    Node* c = r.changer()->GetRepresentationFor(
        n, MachineRepresentation::kWord32, Type::Unsigned32(), use,
        UseInfo(MachineRepresentation::kFloat64, Truncation::None()));
    r.CheckFloat64Constant(c, i);
  }

  {
    Node* n = r.jsgraph()->ConstantNoHole(0);
    Node* use = r.Return(n);
    Node* c = r.changer()->GetRepresentationFor(
        n, MachineRepresentation::kWord64, Type::Range(0, 0, r.zone()), use,
        UseInfo(MachineRepresentation::kFloat64, Truncation::None()));
    r.CheckFloat64Constant(c, 0);
  }
}


static bool IsFloat32Int32(int32_t val) {
  return val >= -(1 << 23) && val <= (1 << 23);
}


static bool IsFloat32Uint32(uint32_t val) { return val <= (1 << 23); }


TEST(ToFloat32_constant) {
  RepresentationChangerTester r;

  for (double i : ValueHelper::float32_vector()) {
    Node* n = r.jsgraph()->ConstantNoHole(i);
    Node* use = r.Return(n);
    Node* c = r.changer()->GetRepresentationFor(
        n, MachineRepresentation::kTagged, Type::None(), use,
        UseInfo(MachineRepresentation::kFloat32, Truncation::None()));
    r.CheckFloat32Constant(c, i);
  }

  for (int i : ValueHelper::int32_vector()) {
    if (!IsFloat32Int32(i)) continue;
    Node* n = r.jsgraph()->ConstantNoHole(i);
    Node* use = r.Return(n);
    Node* c = r.changer()->GetRepresentationFor(
        n, MachineRepresentation::kWord32, Type::Signed32(), use,
        UseInfo(MachineRepresentation::kFloat32, Truncation::None()));
    r.CheckFloat32Constant(c, static_cast<float>(i));
  }

  for (uint32_t i : ValueHelper::uint32_vector()) {
    if (!IsFloat32Uint32(i)) continue;
    Node* n = r.jsgraph()->ConstantNoHole(i);
    Node* use = r.Return(n);
    Node* c = r.changer()->GetRepresentationFor(
        n, MachineRepresentation::kWord32, Type::Unsigned32(), use,
        UseInfo(MachineRepresentation::kFloat32, Truncation::None()));
    r.CheckFloat32Constant(c, static_cast<float>(i));
  }
}

TEST(ToInt32_constant) {
  RepresentationChangerTester r;
  {
    FOR_INT32_INPUTS(i) {
      const double value = static_cast<double>(i);
      Node* n = r.jsgraph()->ConstantNoHole(value);
      NodeProperties::SetType(n, Type::Constant(value, r.zone()));
      Node* use = r.Return(n);
      Node* c = r.changer()->GetRepresentationFor(
          n, MachineRepresentation::kTagged, Type::Signed32(), use,
          UseInfo(MachineRepresentation::kWord32, Truncation::None()));
      r.CheckInt32Constant(c, i);
    }
  }
}

TEST(ToUint32_constant) {
  RepresentationChangerTester r;
  FOR_UINT32_INPUTS(i) {
    const double value = static_cast<double>(i);
    Node* n = r.jsgraph()->ConstantNoHole(value);
    NodeProperties::SetType(n, Type::Constant(value, r.zone()));
    Node* use = r.Return(n);
    Node* c = r.changer()->GetRepresentationFor(
        n, MachineRepresentation::kTagged, Type::Unsigned32(), use,
        UseInfo(MachineRepresentation::kWord32, Truncation::None()));
    r.CheckUint32Constant(c, i);
  }
}

TEST(ToInt64_constant) {
  RepresentationChangerTester r;
  FOR_INT32_INPUTS(i) {
    const double value = static_cast<double>(i);
    Node* n = r.jsgraph()->ConstantNoHole(value);
    NodeProperties::SetType(n, Type::Constant(value, r.zone()));
    Node* use = r.Return(n);
    Node* c = r.changer()->GetRepresentationFor(
        n, MachineRepresentation::kTagged, TypeCache::Get()->kSafeInteger, use,
        UseInfo(MachineRepresentation::kWord64, Truncation::None()));
    r.CheckInt64Constant(c, i);
  }
}

static void CheckChange(IrOpcode::Value expected, MachineRepresentation from,
                        Type from_type, UseInfo use_info) {
  RepresentationChangerTester r;

  Node* n = r.Parameter();
  Node* use = r.Return(n);
  Node* c =
      r.changer()->GetRepresentationFor(n, from, from_type, use, use_info);

  CHECK_NE(c, n);
  CHECK_EQ(expected, c->opcode());
  CHECK_EQ(n, c->InputAt(0));

  if (expected == IrOpcode::kCheckedFloat64ToInt32 ||
      expected == IrOpcode::kCheckedFloat64ToInt64) {
    CheckForMinusZeroMode mode =
        from_type.Maybe(Type::MinusZero())
            ? use_info.minus_zero_check()
            : CheckForMinusZeroMode::kDontCheckForMinusZero;
    CHECK_EQ(mode, CheckMinusZeroParametersOf(c->op()).mode());
  }
}

static void CheckChange(IrOpcode::Value expected, MachineRepresentation from,
                        Type from_type, MachineRepresentation to) {
  CheckChange(expected, from, from_type, UseInfo(to, Truncation::Any()));
}

static void CheckTwoChanges(IrOpcode::Value expected2,
                            IrOpcode::Value expected1,
                            MachineRepresentation from, Type from_type,
                            MachineRepresentation to, UseInfo use_info) {
  RepresentationChangerTester r;

  Node* n = r.Parameter();
  Node* use = r.Return(n);
  Node* c1 =
      r.changer()->GetRepresentationFor(n, from, from_type, use, use_info);

  CHECK_NE(c1, n);
  CHECK_EQ(expected1, c1->opcode());
  Node* c2 = c1->InputAt(0);
  CHECK_NE(c2, n);
  CHECK_EQ(expected2, c2->opcode());
  CHECK_EQ(n, c2->InputAt(0));
}

static void CheckTwoChanges(IrOpcode::Value expected2,
                            IrOpcode::Value expected1,
                            MachineRepresentation from, Type from_type,
                            MachineRepresentation to) {
  CheckTwoChanges(expected2, expected1, from, from_type, to,
                  UseInfo(to, Truncation::None()));
}

static void CheckChange(IrOpcode::Value expected, MachineRepresentation from,
                        Type from_type, MachineRepresentation to,
                        UseInfo use_info) {
  RepresentationChangerTester r;

  Node* n = r.Parameter();
  Node* use = r.Return(n);
  Node* c =
      r.changer()->GetRepresentationFor(n, from, from_type, use, use_info);

  CHECK_NE(c, n);
  CHECK_EQ(expected, c->opcode());
  CHECK_EQ(n, c->InputAt(0));
}

TEST(Word64) {
  CheckChange(IrOpcode::kChangeInt32ToInt64, MachineRepresentation::kWord8,
              TypeCache::Get()->kInt8, MachineRepresentation::kWord64);
  CheckChange(IrOpcode::kChangeUint32ToUint64, MachineRepresentation::kWord8,
              TypeCache::Get()->kUint8, MachineRepresentation::kWord64);
  CheckChange(IrOpcode::kChangeInt32ToInt64, MachineRepresentation::kWord16,
              TypeCache::Get()->kInt16, MachineRepresentation::kWord64);
  CheckChange(IrOpcode::kChangeUint32ToUint64, MachineRepresentation::kWord16,
              TypeCache::Get()->kUint16, MachineRepresentation::kWord64);
  CheckChange(IrOpcode::kChangeInt32ToInt64, MachineRepresentation::kWord32,
              Type::Signed32(), MachineRepresentation::kWord64);
  CheckChange(
      IrOpcode::kChangeInt32ToInt64, MachineRepresentation::kWord32,
      Type::Signed32OrMinusZero(), MachineRepresentation::kWord64,
      UseInfo(MachineRepresentation::kWord64, Truncation::Any(kIdentifyZeros)));
  CheckChange(IrOpcode::kChangeUint32ToUint64, MachineRepresentation::kWord32,
              Type::Unsigned32(), MachineRepresentation::kWord64);
  CheckChange(
      IrOpcode::kChangeUint32ToUint64, MachineRepresentation::kWord32,
      Type::Unsigned32OrMinusZero(), MachineRepresentation::kWord64,
      UseInfo(MachineRepresentation::kWord64, Truncation::Any(kIdentifyZeros)));

  CheckChange(IrOpcode::kTruncateInt64ToInt32, MachineRepresentation::kWord64,
              Type::Signed32(), MachineRepresentation::kWord32);
  CheckChange(IrOpcode::kTruncateInt64ToInt32, MachineRepresentation::kWord64,
              Type::Unsigned32(), MachineRepresentation::kWord32);
  CheckChange(IrOpcode::kTruncateInt64ToInt32, MachineRepresentation::kWord64,
              TypeCache::Get()->kSafeInteger, MachineRepresentation::kWord32,
              UseInfo::TruncatingWord32());
  CheckChange(
      IrOpcode::kCheckedInt64ToInt32, MachineRepresentation::kWord64,
      TypeCache::Get()->kSafeInteger, MachineRepresentation::kWord32,
      UseInfo::CheckedSigned32AsWord32(kIdentifyZeros, FeedbackSource()));
  CheckChange(
      IrOpcode::kCheckedUint64ToInt32, MachineRepresentation::kWord64,
      TypeCache::Get()->kPositiveSafeInteger, MachineRepresentation::kWord32,
      UseInfo::CheckedSigned32AsWord32(kIdentifyZeros, FeedbackSource()));

  CheckChange(IrOpcode::kChangeFloat64ToInt64, MachineRepresentation::kFloat64,
              Type::Signed32(), MachineRepresentation::kWord64);
  CheckChange(IrOpcode::kChangeFloat64ToInt64, MachineRepresentation::kFloat64,
              Type::Unsigned32(), MachineRepresentation::kWord64);
  CheckChange(IrOpcode::kChangeFloat64ToInt64, MachineRepresentation::kFloat64,
              TypeCache::Get()->kSafeInteger, MachineRepresentation::kWord64);
  CheckChange(IrOpcode::kChangeFloat64ToInt64, MachineRepresentation::kFloat64,
              TypeCache::Get()->kDoubleRepresentableInt64,
              MachineRepresentation::kWord64);
  CheckChange(IrOpcode::kChangeFloat64ToUint64, MachineRepresentation::kFloat64,
              TypeCache::Get()->kDoubleRepresentableUint64,
              MachineRepresentation::kWord64);
  CheckChange(
      IrOpcode::kCheckedFloat64ToInt64, MachineRepresentation::kFloat64,
      Type::Number(), MachineRepresentation::kWord64,
      UseInfo::CheckedSigned64AsWord64(kIdentifyZeros, FeedbackSource()));

  CheckChange(IrOpcode::kChangeInt64ToFloat64, MachineRepresentation::kWord64,
              Type::Signed32(), MachineRepresentation::kFloat64);
  CheckChange(IrOpcode::kChangeInt64ToFloat64, MachineRepresentation::kWord64,
              Type::Unsigned32(), MachineRepresentation::kFloat64);
  CheckChange(IrOpcode::kChangeInt64ToFloat64, MachineRepresentation::kWord64,
              TypeCache::Get()->kSafeInteger, MachineRepresentation::kFloat64);

  CheckTwoChanges(IrOpcode::kChangeFloat32ToFloat64,
                  IrOpcode::kChangeFloat64ToInt64,
                  MachineRepresentation::kFloat32, Type::Signed32(),
                  MachineRepresentation::kWord64);
  CheckTwoChanges(IrOpcode::kChangeFloat32ToFloat64,
                  IrOpcode::kChangeFloat64ToInt64,
                  MachineRepresentation::kFloat32, Type::Unsigned32(),
                  MachineRepresentation::kWord64);
  CheckTwoChanges(IrOpcode::kChangeFloat32ToFloat64,
                  IrOpcode::kChangeFloat64ToInt64,
                  MachineRepresentation::kFloat32,
                  TypeCache::Get()->kDoubleRepresentableInt64,
                  MachineRepresentation::kWord64);
  CheckTwoChanges(IrOpcode::kChangeFloat32ToFloat64,
                  IrOpcode::kChangeFloat64ToUint64,
                  MachineRepresentation::kFloat32,
                  TypeCache::Get()->kDoubleRepresentableUint64,
                  MachineRepresentation::kWord64);
  CheckTwoChanges(
      IrOpcode::kChangeFloat32ToFloat64, IrOpcode::kCheckedFloat64ToInt64,
      MachineRepresentation::kFloat32, Type::Number(),
      MachineRepresentation::kWord64,
      UseInfo::CheckedSigned64AsWord64(kIdentifyZeros, FeedbackSource()));

  CheckTwoChanges(IrOpcode::kChangeInt64ToFloat64,
                  IrOpcode::kTruncateFloat64ToFloat32,
                  MachineRepresentation::kWord64, Type::Signed32(),
                  MachineRepresentation::kFloat32);

  CheckChange(IrOpcode::kChangeTaggedToInt64, MachineRepresentation::kTagged,
              Type::Signed32(), MachineRepresentation::kWord64);
  CheckChange(IrOpcode::kChangeTaggedToInt64, MachineRepresentation::kTagged,
              Type::Unsigned32(), MachineRepresentation::kWord64);
  CheckChange(IrOpcode::kChangeTaggedToInt64, MachineRepresentation::kTagged,
              TypeCache::Get()->kSafeInteger, MachineRepresentation::kWord64);
  CheckChange(IrOpcode::kChangeTaggedToInt64, MachineRepresentation::kTagged,
              TypeCache::Get()->kDoubleRepresentableInt64,
              MachineRepresentation::kWord64);
  CheckChange(IrOpcode::kChangeTaggedSignedToInt64,
              MachineRepresentation::kTaggedSigned, Type::SignedSmall(),
              MachineRepresentation::kWord64);
  CheckChange(
      IrOpcode::kCheckedTaggedToInt64, MachineRepresentation::kTagged,
      Type::Number(), MachineRepresentation::kWord64,
      UseInfo::CheckedSigned64AsWord64(kIdentifyZeros, FeedbackSource()));
  CheckChange(
      IrOpcode::kCheckedTaggedToInt64, MachineRepresentation::kTaggedPointer,
      Type::Number(), MachineRepresentation::kWord64,
      UseInfo::CheckedSigned64AsWord64(kIdentifyZeros, FeedbackSource()));

  CheckTwoChanges(IrOpcode::kTruncateInt64ToInt32,
                  IrOpcode::kChangeInt31ToTaggedSigned,
                  MachineRepresentation::kWord64, Type::Signed31(),
                  MachineRepresentation::kTagged);
  CheckTwoChanges(IrOpcode::kTruncateInt64ToInt32,
                  IrOpcode::kChangeInt32ToTagged,
                  MachineRepresentation::kWord64, Type::Signed32(),
                  MachineRepresentation::kTagged);
  CheckTwoChanges(IrOpcode::kTruncateInt64ToInt32,
                  IrOpcode::kChangeUint32ToTagged,
                  MachineRepresentation::kWord64, Type::Unsigned32(),
                  MachineRepresentation::kTagged);
  CheckChange(IrOpcode::kChangeInt64ToTagged, MachineRepresentation::kWord64,
              TypeCache::Get()->kSafeInteger, MachineRepresentation::kTagged);
  CheckChange(IrOpcode::kChangeUint64ToTagged, MachineRepresentation::kWord64,
              TypeCache::Get()->kPositiveSafeInteger,
              MachineRepresentation::kTagged);

  CheckTwoChanges(IrOpcode::kTruncateInt64ToInt32,
                  IrOpcode::kChangeInt31ToTaggedSigned,
                  MachineRepresentation::kWord64, Type::Signed31(),
                  MachineRepresentation::kTaggedSigned);
  if (SmiValuesAre32Bits()) {
    CheckTwoChanges(IrOpcode::kTruncateInt64ToInt32,
                    IrOpcode::kChangeInt32ToTagged,
                    MachineRepresentation::kWord64, Type::Signed32(),
                    MachineRepresentation::kTaggedSigned);
  }
  CheckChange(IrOpcode::kCheckedInt64ToTaggedSigned,
              MachineRepresentation::kWord64, TypeCache::Get()->kSafeInteger,
              MachineRepresentation::kTaggedSigned,
              UseInfo::CheckedSignedSmallAsTaggedSigned(FeedbackSource()));
  CheckChange(IrOpcode::kCheckedUint64ToTaggedSigned,
              MachineRepresentation::kWord64,
              TypeCache::Get()->kPositiveSafeInteger,
              MachineRepresentation::kTaggedSigned,
              UseInfo::CheckedSignedSmallAsTaggedSigned(FeedbackSource()));

  CheckTwoChanges(
      IrOpcode::kChangeInt64ToFloat64, IrOpcode::kChangeFloat64ToTaggedPointer,
      MachineRepresentation::kWord64, TypeCache::Get()->kSafeInteger,
      MachineRepresentation::kTaggedPointer);
}

TEST(SingleChanges) {
  CheckChange(IrOpcode::kChangeTaggedToBit, MachineRepresentation::kTagged,
              Type::Boolean(), MachineRepresentation::kBit);
  CheckChange(IrOpcode::kChangeBitToTagged, MachineRepresentation::kBit,
              Type::Boolean(), MachineRepresentation::kTagged);

  CheckChange(IrOpcode::kChangeInt31ToTaggedSigned,
              MachineRepresentation::kWord32, Type::Signed31(),
              MachineRepresentation::kTagged);
  CheckChange(IrOpcode::kChangeInt32ToTagged, MachineRepresentation::kWord32,
              Type::Signed32(), MachineRepresentation::kTagged);
  CheckChange(IrOpcode::kChangeUint32ToTagged, MachineRepresentation::kWord32,
              Type::Unsigned32(), MachineRepresentation::kTagged);
  CheckChange(IrOpcode::kChangeFloat64ToTagged, MachineRepresentation::kFloat64,
              Type::Number(), MachineRepresentation::kTagged);
  CheckTwoChanges(IrOpcode::kChangeFloat64ToInt32,
                  IrOpcode::kChangeInt31ToTaggedSigned,
                  MachineRepresentation::kFloat64, Type::Signed31(),
                  MachineRepresentation::kTagged);
  CheckTwoChanges(IrOpcode::kChangeFloat64ToInt32,
                  IrOpcode::kChangeInt32ToTagged,
                  MachineRepresentation::kFloat64, Type::Signed32(),
                  MachineRepresentation::kTagged);
  CheckTwoChanges(IrOpcode::kChangeFloat64ToUint32,
                  IrOpcode::kChangeUint32ToTagged,
                  MachineRepresentation::kFloat64, Type::Unsigned32(),
                  MachineRepresentation::kTagged);

  CheckChange(IrOpcode::kChangeTaggedToInt32, MachineRepresentation::kTagged,
              Type::Signed32(), MachineRepresentation::kWord32);
  CheckChange(IrOpcode::kChangeTaggedToUint32, MachineRepresentation::kTagged,
              Type::Unsigned32(), MachineRepresentation::kWord32);
  CheckChange(IrOpcode::kChangeTaggedToFloat64, MachineRepresentation::kTagged,
              Type::Number(), MachineRepresentation::kFloat64);
  CheckChange(IrOpcode::kTruncateTaggedToFloat64,
              MachineRepresentation::kTagged, Type::NumberOrUndefined(),
              UseInfo(MachineRepresentation::kFloat64,
                      Truncation::OddballAndBigIntToNumber()));
  CheckChange(IrOpcode::kChangeTaggedToFloat64, MachineRepresentation::kTagged,
              Type::Signed31(), MachineRepresentation::kFloat64);

  // Int32,Uint32 <-> Float64 are actually machine conversions.
  CheckChange(IrOpcode::kChangeInt32ToFloat64, MachineRepresentation::kWord32,
              Type::Signed32(), MachineRepresentation::kFloat64);
  CheckChange(IrOpcode::kChangeInt32ToFloat64, MachineRepresentation::kWord32,
              Type::Signed32OrMinusZero(), MachineRepresentation::kFloat64,
              UseInfo(MachineRepresentation::kFloat64,
                      Truncation::Any(kIdentifyZeros)));
  CheckChange(IrOpcode::kChangeUint32ToFloat64, MachineRepresentation::kWord32,
              Type::Unsigned32(), MachineRepresentation::kFloat64);
  CheckChange(IrOpcode::kChangeFloat64ToInt32, MachineRepresentation::kFloat64,
              Type::Signed32(), MachineRepresentation::kWord32);
  CheckChange(IrOpcode::kChangeFloat64ToUint32, MachineRepresentation::kFloat64,
              Type::Unsigned32(), MachineRepresentation::kWord32);

  CheckChange(IrOpcode::kTruncateFloat64ToFloat32,
              MachineRepresentation::kFloat64, Type::Number(),
              MachineRepresentation::kFloat32);

  // Int32,Uint32 <-> Float32 require two changes.
  CheckTwoChanges(IrOpcode::kChangeInt32ToFloat64,
                  IrOpcode::kTruncateFloat64ToFloat32,
                  MachineRepresentation::kWord32, Type::Signed32(),
                  MachineRepresentation::kFloat32);
  CheckTwoChanges(IrOpcode::kChangeUint32ToFloat64,
                  IrOpcode::kTruncateFloat64ToFloat32,
                  MachineRepresentation::kWord32, Type::Unsigned32(),
                  MachineRepresentation::kFloat32);
  CheckTwoChanges(IrOpcode::kChangeFloat32ToFloat64,
                  IrOpcode::kChangeFloat64ToInt32,
                  MachineRepresentation::kFloat32, Type::Signed32(),
                  MachineRepresentation::kWord32);
  CheckTwoChanges(IrOpcode::kChangeFloat32ToFloat64,
                  IrOpcode::kChangeFloat64ToUint32,
                  MachineRepresentation::kFloat32, Type::Unsigned32(),
                  MachineRepresentation::kWord32);

  // Float32 <-> Tagged require two changes.
  CheckTwoChanges(IrOpcode::kChangeFloat32ToFloat64,
                  IrOpcode::kChangeFloat64ToTagged,
                  MachineRepresentation::kFloat32, Type::Number(),
                  MachineRepresentation::kTagged);
  CheckTwoChanges(IrOpcode::kChangeTaggedToFloat64,
                  IrOpcode::kTruncateFloat64ToFloat32,
                  MachineRepresentation::kTagged, Type::Number(),
                  MachineRepresentation::kFloat32);
}


TEST(SignednessInWord32) {
  RepresentationChangerTester r;

  CheckChange(IrOpcode::kChangeTaggedToInt32, MachineRepresentation::kTagged,
              Type::Signed32(), MachineRepresentation::kWord32);
  CheckChange(IrOpcode::kChangeTaggedToUint32, MachineRepresentation::kTagged,
              Type::Unsigned32(), MachineRepresentation::kWord32);
  CheckChange(IrOpcode::kChangeInt32ToFloat64, MachineRepresentation::kWord32,
              Type::Signed32(), MachineRepresentation::kFloat64);
  CheckChange(IrOpcode::kChangeFloat64ToInt32, MachineRepresentation::kFloat64,
              Type::Signed32(), MachineRepresentation::kWord32);
  CheckChange(IrOpcode::kTruncateFloat64ToWord32,
              MachineRepresentation::kFloat64, Type::Number(),
              MachineRepresentation::kWord32,
              UseInfo(MachineRepresentation::kWord32, Truncation::Word32()));
  CheckChange(IrOpcode::kCheckedTruncateTaggedToWord32,
              MachineRepresentation::kTagged, Type::NonInternal(),
              MachineRepresentation::kWord32,
              UseInfo::CheckedNumberOrOddballAsWord32(FeedbackSource()));

  CheckTwoChanges(IrOpcode::kChangeInt32ToFloat64,
                  IrOpcode::kTruncateFloat64ToFloat32,
                  MachineRepresentation::kWord32, Type::Signed32(),
                  MachineRepresentation::kFloat32);
  CheckTwoChanges(IrOpcode::kChangeFloat32ToFloat64,
                  IrOpcode::kTruncateFloat64ToWord32,
                  MachineRepresentation::kFloat32, Type::Number(),
                  MachineRepresentation::kWord32);

  CheckChange(
      IrOpcode::kCheckedUint32ToInt32, MachineRepresentation::kWord32,
      Type::Unsigned32(),
      UseInfo::CheckedSigned32AsWord32(kIdentifyZeros, FeedbackSource()));
}

static void TestMinusZeroCheck(IrOpcode::Value expected, Type from_type) {
  RepresentationChangerTester r;

  CheckChange(
      expected, MachineRepresentation::kFloat64, from_type,
      UseInfo::CheckedSignedSmallAsWord32(kDistinguishZeros, FeedbackSource()));

  CheckChange(
      expected, MachineRepresentation::kFloat64, from_type,
      UseInfo::CheckedSignedSmallAsWord32(kIdentifyZeros, FeedbackSource()));

  CheckChange(
      expected, MachineRepresentation::kFloat64, from_type,
      UseInfo::CheckedSigned32AsWord32(kDistinguishZeros, FeedbackSource()));

  CheckChange(
      expected, MachineRepresentation::kFloat64, from_type,
      UseInfo::CheckedSigned32AsWord32(kDistinguishZeros, FeedbackSource()));
}

TEST(MinusZeroCheck) {
  TestMinusZeroCheck(IrOpcode::kCheckedFloat64ToInt32, Type::NumberOrOddball());
  // PlainNumber cannot be minus zero so the minus zero check should be
  // eliminated.
  TestMinusZeroCheck(IrOpcode::kCheckedFloat64ToInt32, Type::PlainNumber());
}

TEST(Nops) {
  RepresentationChangerTester r;

  // X -> X is always a nop for any single representation X.
  for (size_t i = 0; i < arraysize(kMachineTypes); i++) {
    r.CheckNop(kMachineTypes[i].representation(), Type::Number(),
               kMachineTypes[i].representation());
  }

  // 32-bit floats.
  r.CheckNop(MachineRepresentation::kFloat32, Type::Number(),
             MachineRepresentation::kFloat32);

  // 32-bit words can be used as smaller word sizes and vice versa, because
  // loads from memory implicitly sign or zero extend the value to the
  // full machine word size, and stores implicitly truncate.
  r.CheckNop(MachineRepresentation::kWord32, Type::Signed32(),
             MachineRepresentation::kWord8);
  r.CheckNop(MachineRepresentation::kWord32, Type::Signed32(),
             MachineRepresentation::kWord16);
  r.CheckNop(MachineRepresentation::kWord32, Type::Signed32(),
             MachineRepresentation::kWord32);
  r.CheckNop(MachineRepresentation::kWord8, Type::Signed32(),
             MachineRepresentation::kWord32);
  r.CheckNop(MachineRepresentation::kWord16, Type::Signed32(),
             MachineRepresentation::kWord32);

  // kRepBit (result of comparison) is implicitly a wordish thing.
  r.CheckNop(MachineRepresentation::kBit, Type::Boolean(),
             MachineRepresentation::kWord8);
  r.CheckNop(MachineRepresentation::kBit, Type::Boolean(),
             MachineRepresentation::kWord16);
  r.CheckNop(MachineRepresentation::kBit, Type::Boolean(),
             MachineRepresentation::kWord32);
}


TEST(TypeErrors) {
  RepresentationChangerTester r;

  // Floats cannot be implicitly converted to/from comparison conditions.
  r.CheckTypeError(MachineRepresentation::kBit, Type::Number(),
                   MachineRepresentation::kFloat32);
  r.CheckTypeError(MachineRepresentation::kBit, Type::Boolean(),
                   MachineRepresentation::kFloat32);

  // Word64 is internal and shouldn't be implicitly converted.
  r.CheckTypeError(MachineRepresentation::kWord64, Type::Internal(),
                   MachineRepresentation::kTagged);
  r.CheckTypeError(MachineRepresentation::kTagged, Type::Number(),
                   MachineRepresentation::kWord64);
  r.CheckTypeError(MachineRepresentation::kTagged, Type::Boolean(),
                   MachineRepresentation::kWord64);
  r.CheckTypeError(MachineRepresentation::kWord64, Type::Internal(),
                   MachineRepresentation::kWord32);
  r.CheckTypeError(MachineRepresentation::kWord32, Type::Number(),
                   MachineRepresentation::kWord64);
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```