Response: Let's break down the thought process for analyzing this C++ unittest file.

1. **Understand the Goal:** The core task is to understand the purpose of `machine-operator-unittest.cc`. The name itself gives a strong clue: it's testing machine operators. "Unittest" signifies it's testing individual units of functionality.

2. **Identify Key Components:** Scan the file for significant keywords and structures. Immediately, these jump out:
    * `#include` directives:  These tell us what other parts of the V8 codebase are involved. `src/compiler/machine-operator.h`, `src/compiler/opcodes.h`, `src/compiler/operator.h`, and `src/compiler/operator-properties.h` are crucial. They indicate this file is testing the `MachineOperator` class and related compiler concepts. `test/unittests/test-utils.h` is standard for V8 unit tests.
    * `namespace` declarations:  These define the organizational context. We're in `v8::internal::compiler::machine_operator_unittest`.
    * `template` and `class` declarations:  These define the test structure. `MachineOperatorTestWithParam` suggests parameterized testing.
    * `TEST_P` and `TEST_F` macros: These are Google Test framework macros, indicating individual test cases. `TEST_P` means parameterized tests, while `TEST_F` are standard tests within a fixture.
    * `EXPECT_EQ`: Another Google Test macro, used for assertions (checking if values are equal).
    * Constant arrays like `kMachineReps`, `kMachineTypesForAccess`, `kRepresentationsForStore`:  These likely define the sets of parameters used in the parameterized tests.
    * Structs like `PureOperator` and `OptionalOperatorEntry`: These appear to define test data for different types of operators.

3. **Focus on the Core Functionality:** The core entity being tested is the `MachineOperator`. What does a `MachineOperator` do?  Based on the names of the tests and the included headers, it seems to represent low-level operations (loads, stores, arithmetic, bitwise operations, etc.) that the compiler uses. The "machine" part suggests these operations are close to the underlying hardware or the target architecture's instruction set.

4. **Analyze Test Categories:**  Notice the clear sections in the code: "Load operator," "Store operator," "Pure operators," "Optional operators," and "Pseudo operators." This is a good organizational structure and helps understand the testing scope.

5. **Understand Parameterized Testing:**  The `MachineOperatorTestWithParam` template and the `INSTANTIATE_TEST_SUITE_P` calls are key. They indicate that the same test logic (`InstancesAreGloballyShared`, `NumberOfInputsAndOutputs`, etc.) is run multiple times with different combinations of `MachineRepresentation` and other relevant parameters. This is a powerful way to test different scenarios.

6. **Examine Individual Test Cases:**
    * **Load/Store Tests:** These tests check if `Load` and `Store` operators are created correctly, if they are shared instances (for efficiency), and if they have the correct number of inputs and outputs. The parameters like `LoadRepresentation` and `StoreRepresentation` are important for defining the data type and access characteristics.
    * **Pure Operator Tests:**  These tests iterate through a list of "pure" operators (operators without side effects, like addition or bitwise AND). The tests verify that the same operator instance is returned regardless of the `MachineRepresentation` and that the input/output counts are correct.
    * **Optional Operator Tests:**  Similar to pure operators, but these operators might not be available in all configurations (hence "optional"). The tests check if the operators are supported based on a flag.
    * **Pseudo Operator Tests:** These tests verify that certain "generic" operators (like `WordAnd`) map to the correct architecture-specific operators (like `Word32And` or `Word64And`) based on the word size.

7. **Connect to JavaScript (if applicable):** This is where the connection to the high-level language comes in. Think about what these low-level machine operations are *for*. They are the building blocks that the V8 compiler uses to implement JavaScript's semantics. A `Load` operator corresponds to reading a value from memory (accessing a variable, object property, array element). A `Store` operator corresponds to writing to memory (assigning a value). Arithmetic and bitwise operators directly implement JavaScript's operators. Type conversions (like `ChangeFloat64ToInt32`) are necessary for JavaScript's dynamic typing.

8. **Formulate the Summary:** Based on the analysis, construct a summary that covers the following:
    * **Primary Function:** Testing the `MachineOperator` class.
    * **Scope:**  Testing various types of machine operators (load, store, arithmetic, etc.).
    * **Methodology:** Using Google Test, including parameterized tests.
    * **Key Aspects Tested:**  Operator creation, sharing, input/output counts, opcodes, parameters, optional operator support, pseudo-operator mapping.
    * **Connection to JavaScript:** Explain how these low-level operators implement JavaScript functionality, providing concrete examples.

9. **Refine and Organize:**  Ensure the summary is clear, concise, and well-organized. Use bullet points or numbered lists for clarity. Provide the JavaScript examples to make the connection concrete.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This just tests the C++ implementation details."
* **Correction:** "While it tests C++ details, these details are crucial for how JavaScript is executed. Need to connect it back to JavaScript concepts."
* **Initial thought:** "The parameters are just random types."
* **Correction:** "The parameters represent different data types and memory access modes, which are fundamental to how the compiler works with JavaScript values."
* **Make sure the JavaScript examples are accurate and relevant to the tested operators.** For example, showing how `+` might involve an `Int32Add` or `Float64Add` operator.

By following this systematic approach, you can effectively analyze and understand the purpose and functionality of a complex C++ source file like the one provided.
这个C++源代码文件 `machine-operator-unittest.cc` 的主要功能是**测试 V8 JavaScript 引擎中 `compiler` 模块的 `MachineOperator` 类及其相关功能。**

具体来说，它通过编写单元测试来验证以下内容：

1. **`MachineOperator` 对象的创建和共享:**  测试不同 `MachineOperatorBuilder` 创建的相同类型的操作符实例是否是全局共享的，以确保效率。
2. **操作符的输入和输出数量:** 验证每个 `MachineOperator`（例如 `Load`, `Store`, `Word32And` 等）定义了正确的输入（值输入、效果输入、控制输入）和输出（值输出、效果输出、控制输出）数量。
3. **操作符的 `IrOpcode`:** 检查每个 `MachineOperator` 是否关联了正确的中间表示操作码 (Intermediate Representation Opcode)。
4. **操作符的参数:** 验证 `Load` 和 `Store` 操作符的参数（例如，加载或存储的数据类型 `LoadRepresentation` 和 `StoreRepresentation`）是否正确。
5. **纯操作符 (Pure Operators):** 测试不产生副作用的算术、逻辑和位运算等操作符的创建和属性，例如 `Word32And`, `Int32Add`, `Float64Sqrt` 等。
6. **可选操作符 (Optional Operators):**  测试一些根据特定标志位才启用的操作符，例如浮点数的舍入操作和选择操作。
7. **伪操作符 (Pseudo Operators):**  测试一些更通用的操作符（例如 `WordAnd`, `IntAdd`），它们会根据目标机器的字长 (32位或64位) 自动映射到具体的机器操作符（例如 `Word32And` 或 `Word64And`）。

**与 JavaScript 的关系以及 JavaScript 举例说明:**

`MachineOperator` 类在 V8 编译器的代码生成阶段扮演着至关重要的角色。当 V8 编译 JavaScript 代码时，它会将高级的 JavaScript 语义转换为一系列底层的机器操作。 `MachineOperator` 就代表了这些底层的操作，例如：

* **内存访问:**  `Load` 操作符对应于从内存中读取数据，`Store` 操作符对应于向内存中写入数据。
* **算术运算:**  `Int32Add`, `Float64Mul` 等操作符对应于加法、乘法等数学运算。
* **位运算:**  `Word32And`, `Word64Or` 等操作符对应于按位与、按位或等操作。
* **类型转换:** `ChangeFloat64ToInt32` 等操作符对应于 JavaScript 中不同数据类型之间的转换。

**JavaScript 举例:**

考虑以下简单的 JavaScript 代码：

```javascript
let x = 10;
let y = 20;
let sum = x + y;
let isGreaterThan = x > 5;
let result = sum & 0xFF;
```

当 V8 编译这段代码时，可能会生成如下与 `MachineOperator` 相关的操作：

1. **`let x = 10;` 和 `let y = 20;`**: 这可能涉及到将常量值 10 和 20 存储到内存中，可以使用 `Store` 操作符。
2. **`let sum = x + y;`**:  这会生成一个加法操作。 由于 `x` 和 `y` 在 JavaScript 中是数字，V8 可能会将其编译为 `Int32Add` (如果确定是整数) 或 `Float64Add` (如果涉及浮点数) 操作符。
3. **`let isGreaterThan = x > 5;`**:  这会生成一个比较操作。 V8 可能会使用 `Int32LessThan` 或 `Float64LessThan` 操作符来比较 `x` 和 5。
4. **`let result = sum & 0xFF;`**: 这会生成一个按位与操作。 V8 可能会使用 `Word32And` 操作符来执行按位与运算。

**更具体的 JavaScript 例子与 `Load` 和 `Store`:**

```javascript
let obj = { a: 5 };
let value = obj.a; // Load 操作
obj.a = 10;       // Store 操作
```

* 当执行 `let value = obj.a;` 时，V8 需要从 `obj` 对象的内存中读取 `a` 属性的值。 这会对应到一个 `Load` 操作符，其参数会指定要加载的内存地址和数据类型。
* 当执行 `obj.a = 10;` 时，V8 需要将值 10 写入到 `obj` 对象中 `a` 属性对应的内存位置。 这会对应到一个 `Store` 操作符，其参数会指定要存储的内存地址、要存储的值以及数据类型。

**总结:**

`machine-operator-unittest.cc` 文件通过单元测试确保 V8 编译器中用于表示底层机器操作的 `MachineOperator` 类能够正确创建、配置和使用。这些底层的机器操作是 V8 将 JavaScript 代码转换为可执行机器码的关键组成部分，直接影响着 JavaScript 代码的执行效率和正确性。 这个测试文件对于保证 V8 编译器的质量至关重要。

Prompt: 
```
这是目录为v8/test/unittests/compiler/machine-operator-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/machine-operator.h"
#include "src/compiler/opcodes.h"
#include "src/compiler/operator.h"
#include "src/compiler/operator-properties.h"
#include "test/unittests/test-utils.h"

namespace v8 {
namespace internal {
namespace compiler {
namespace machine_operator_unittest {

template <typename T>
class MachineOperatorTestWithParam
    : public TestWithZone,
      public ::testing::WithParamInterface<
          ::testing::tuple<MachineRepresentation, T> > {
 protected:
  MachineRepresentation representation() const {
    return ::testing::get<0>(B::GetParam());
  }
  const T& GetParam() const { return ::testing::get<1>(B::GetParam()); }

 private:
  using B = ::testing::WithParamInterface<
      ::testing::tuple<MachineRepresentation, T> >;
};


const MachineRepresentation kMachineReps[] = {MachineRepresentation::kWord32,
                                              MachineRepresentation::kWord64};


const MachineType kMachineTypesForAccess[] = {
    MachineType::Float32(), MachineType::Float64(),  MachineType::Int8(),
    MachineType::Uint8(),   MachineType::Int16(),    MachineType::Uint16(),
    MachineType::Int32(),   MachineType::Uint32(),   MachineType::Int64(),
    MachineType::Uint64(),  MachineType::AnyTagged()};


const MachineRepresentation kRepresentationsForStore[] = {
    MachineRepresentation::kFloat32, MachineRepresentation::kFloat64,
    MachineRepresentation::kWord8,   MachineRepresentation::kWord16,
    MachineRepresentation::kWord32,  MachineRepresentation::kWord64,
    MachineRepresentation::kTagged};


// -----------------------------------------------------------------------------
// Load operator.

using MachineLoadOperatorTest =
    MachineOperatorTestWithParam<LoadRepresentation>;

TEST_P(MachineLoadOperatorTest, InstancesAreGloballyShared) {
  MachineOperatorBuilder machine1(zone(), representation());
  MachineOperatorBuilder machine2(zone(), representation());
  EXPECT_EQ(machine1.Load(GetParam()), machine2.Load(GetParam()));
}


TEST_P(MachineLoadOperatorTest, NumberOfInputsAndOutputs) {
  MachineOperatorBuilder machine(zone(), representation());
  const Operator* op = machine.Load(GetParam());

  EXPECT_EQ(2, op->ValueInputCount());
  EXPECT_EQ(1, op->EffectInputCount());
  EXPECT_EQ(1, op->ControlInputCount());
  EXPECT_EQ(4, OperatorProperties::GetTotalInputCount(op));

  EXPECT_EQ(1, op->ValueOutputCount());
  EXPECT_EQ(1, op->EffectOutputCount());
  EXPECT_EQ(0, op->ControlOutputCount());
}


TEST_P(MachineLoadOperatorTest, OpcodeIsCorrect) {
  MachineOperatorBuilder machine(zone(), representation());
  EXPECT_EQ(IrOpcode::kLoad, machine.Load(GetParam())->opcode());
}


TEST_P(MachineLoadOperatorTest, ParameterIsCorrect) {
  MachineOperatorBuilder machine(zone(), representation());
  EXPECT_EQ(GetParam(), LoadRepresentationOf(machine.Load(GetParam())));
}

INSTANTIATE_TEST_SUITE_P(
    MachineOperatorTest, MachineLoadOperatorTest,
    ::testing::Combine(::testing::ValuesIn(kMachineReps),
                       ::testing::ValuesIn(kMachineTypesForAccess)));

// -----------------------------------------------------------------------------
// Store operator.


class MachineStoreOperatorTest
    : public MachineOperatorTestWithParam<
          ::testing::tuple<MachineRepresentation, WriteBarrierKind> > {
 protected:
  StoreRepresentation GetParam() const {
    return StoreRepresentation(
        ::testing::get<0>(
            MachineOperatorTestWithParam< ::testing::tuple<
                MachineRepresentation, WriteBarrierKind> >::GetParam()),
        ::testing::get<1>(
            MachineOperatorTestWithParam< ::testing::tuple<
                MachineRepresentation, WriteBarrierKind> >::GetParam()));
  }
};


TEST_P(MachineStoreOperatorTest, InstancesAreGloballyShared) {
  MachineOperatorBuilder machine1(zone(), representation());
  MachineOperatorBuilder machine2(zone(), representation());
  EXPECT_EQ(machine1.Store(GetParam()), machine2.Store(GetParam()));
}


TEST_P(MachineStoreOperatorTest, NumberOfInputsAndOutputs) {
  MachineOperatorBuilder machine(zone(), representation());
  const Operator* op = machine.Store(GetParam());

  EXPECT_EQ(3, op->ValueInputCount());
  EXPECT_EQ(1, op->EffectInputCount());
  EXPECT_EQ(1, op->ControlInputCount());
  EXPECT_EQ(5, OperatorProperties::GetTotalInputCount(op));

  EXPECT_EQ(0, op->ValueOutputCount());
  EXPECT_EQ(1, op->EffectOutputCount());
  EXPECT_EQ(0, op->ControlOutputCount());
}


TEST_P(MachineStoreOperatorTest, OpcodeIsCorrect) {
  MachineOperatorBuilder machine(zone(), representation());
  EXPECT_EQ(IrOpcode::kStore, machine.Store(GetParam())->opcode());
}


TEST_P(MachineStoreOperatorTest, ParameterIsCorrect) {
  MachineOperatorBuilder machine(zone(), representation());
  EXPECT_EQ(GetParam(), StoreRepresentationOf(machine.Store(GetParam())));
}

INSTANTIATE_TEST_SUITE_P(
    MachineOperatorTest, MachineStoreOperatorTest,
    ::testing::Combine(
        ::testing::ValuesIn(kMachineReps),
        ::testing::Combine(::testing::ValuesIn(kRepresentationsForStore),
                           ::testing::Values(kNoWriteBarrier,
                                             kFullWriteBarrier))));

// -----------------------------------------------------------------------------
// Pure operators.

struct PureOperator {
  const Operator* (MachineOperatorBuilder::*constructor)();
  char const* const constructor_name;
  int value_input_count;
  int control_input_count;
  int value_output_count;
};


std::ostream& operator<<(std::ostream& os, PureOperator const& pop) {
  return os << pop.constructor_name;
}

const PureOperator kPureOperators[] = {
#define PURE(Name, value_input_count, control_input_count, value_output_count) \
  {                                                                            \
    &MachineOperatorBuilder::Name, #Name, value_input_count,                   \
        control_input_count, value_output_count                                \
  }
    PURE(Word32And, 2, 0, 1),                 // --
    PURE(Word32Or, 2, 0, 1),                  // --
    PURE(Word32Xor, 2, 0, 1),                 // --
    PURE(Word32Shl, 2, 0, 1),                 // --
    PURE(Word32Shr, 2, 0, 1),                 // --
    PURE(Word32Sar, 2, 0, 1),                 // --
    PURE(Word32Ror, 2, 0, 1),                 // --
    PURE(Word32Equal, 2, 0, 1),               // --
    PURE(Word32Clz, 1, 0, 1),                 // --
    PURE(Word64And, 2, 0, 1),                 // --
    PURE(Word64Or, 2, 0, 1),                  // --
    PURE(Word64Xor, 2, 0, 1),                 // --
    PURE(Word64Shl, 2, 0, 1),                 // --
    PURE(Word64Shr, 2, 0, 1),                 // --
    PURE(Word64Sar, 2, 0, 1),                 // --
    PURE(Word64Ror, 2, 0, 1),                 // --
    PURE(Word64RorLowerable, 2, 1, 1),        // --
    PURE(Word64Equal, 2, 0, 1),               // --
    PURE(Int32Add, 2, 0, 1),                  // --
    PURE(Int32Sub, 2, 0, 1),                  // --
    PURE(Int32Mul, 2, 0, 1),                  // --
    PURE(Int32MulHigh, 2, 0, 1),              // --
    PURE(Int32Div, 2, 1, 1),                  // --
    PURE(Uint32Div, 2, 1, 1),                 // --
    PURE(Int32Mod, 2, 1, 1),                  // --
    PURE(Uint32Mod, 2, 1, 1),                 // --
    PURE(Int32LessThan, 2, 0, 1),             // --
    PURE(Int32LessThanOrEqual, 2, 0, 1),      // --
    PURE(Uint32LessThan, 2, 0, 1),            // --
    PURE(Uint32LessThanOrEqual, 2, 0, 1),     // --
    PURE(Int64Add, 2, 0, 1),                  // --
    PURE(Int64Sub, 2, 0, 1),                  // --
    PURE(Int64Mul, 2, 0, 1),                  // --
    PURE(Int64Div, 2, 1, 1),                  // --
    PURE(Uint64Div, 2, 1, 1),                 // --
    PURE(Int64Mod, 2, 1, 1),                  // --
    PURE(Uint64Mod, 2, 1, 1),                 // --
    PURE(Int64LessThan, 2, 0, 1),             // --
    PURE(Int64LessThanOrEqual, 2, 0, 1),      // --
    PURE(Uint64LessThan, 2, 0, 1),            // --
    PURE(Uint64LessThanOrEqual, 2, 0, 1),     // --
    PURE(ChangeFloat32ToFloat64, 1, 0, 1),    // --
    PURE(ChangeFloat64ToInt32, 1, 0, 1),      // --
    PURE(ChangeFloat64ToUint32, 1, 0, 1),     // --
    PURE(ChangeInt32ToInt64, 1, 0, 1),        // --
    PURE(ChangeUint32ToFloat64, 1, 0, 1),     // --
    PURE(ChangeUint32ToUint64, 1, 0, 1),      // --
    PURE(TruncateFloat64ToFloat32, 1, 0, 1),  // --
    PURE(TruncateInt64ToInt32, 1, 0, 1),      // --
    PURE(Float32Abs, 1, 0, 1),                // --
    PURE(Float32Add, 2, 0, 1),                // --
    PURE(Float32Sub, 2, 0, 1),                // --
    PURE(Float32Mul, 2, 0, 1),                // --
    PURE(Float32Div, 2, 0, 1),                // --
    PURE(Float32Sqrt, 1, 0, 1),               // --
    PURE(Float32Equal, 2, 0, 1),              // --
    PURE(Float32LessThan, 2, 0, 1),           // --
    PURE(Float32LessThanOrEqual, 2, 0, 1),    // --
    PURE(Float32Neg, 1, 0, 1),                // --
    PURE(Float64Abs, 1, 0, 1),                // --
    PURE(Float64Add, 2, 0, 1),                // --
    PURE(Float64Sub, 2, 0, 1),                // --
    PURE(Float64Mul, 2, 0, 1),                // --
    PURE(Float64Div, 2, 0, 1),                // --
    PURE(Float64Mod, 2, 0, 1),                // --
    PURE(Float64Sqrt, 1, 0, 1),               // --
    PURE(Float64Max, 2, 0, 1),                // --
    PURE(Float64Min, 2, 0, 1),                // --
    PURE(Float64Equal, 2, 0, 1),              // --
    PURE(Float64LessThan, 2, 0, 1),           // --
    PURE(Float64LessThanOrEqual, 2, 0, 1),    // --
    PURE(Float64ExtractLowWord32, 1, 0, 1),   // --
    PURE(Float64ExtractHighWord32, 1, 0, 1),  // --
    PURE(Float64InsertLowWord32, 2, 0, 1),    // --
    PURE(Float64InsertHighWord32, 2, 0, 1),   // --
    PURE(Float64Neg, 1, 0, 1),                // --
#undef PURE
};

class MachinePureOperatorTest : public TestWithZone {
 protected:
  MachineRepresentation word_type() {
    return MachineType::PointerRepresentation();
  }
};


TEST_F(MachinePureOperatorTest, PureOperators) {
  TRACED_FOREACH(MachineRepresentation, machine_rep1, kMachineReps) {
    MachineOperatorBuilder machine1(zone(), machine_rep1);
    TRACED_FOREACH(MachineRepresentation, machine_rep2, kMachineReps) {
      MachineOperatorBuilder machine2(zone(), machine_rep2);
      TRACED_FOREACH(PureOperator, pop, kPureOperators) {
        const Operator* op1 = (machine1.*pop.constructor)();
        const Operator* op2 = (machine2.*pop.constructor)();
        EXPECT_EQ(op1, op2);
        EXPECT_EQ(pop.value_input_count, op1->ValueInputCount());
        EXPECT_EQ(pop.control_input_count, op1->ControlInputCount());
        EXPECT_EQ(pop.value_output_count, op1->ValueOutputCount());
      }
    }
  }
}


// Optional operators.

struct OptionalOperatorEntry {
  const OptionalOperator (MachineOperatorBuilder::*constructor)();
  MachineOperatorBuilder::Flag enabling_flag;
  char const* const constructor_name;
  int value_input_count;
  int control_input_count;
  int value_output_count;
};


std::ostream& operator<<(std::ostream& os, OptionalOperatorEntry const& pop) {
  return os << pop.constructor_name;
}

const OptionalOperatorEntry kOptionalOperators[] = {
#define OPTIONAL_ENTRY(Name, value_input_count, control_input_count,       \
                       value_output_count)                                 \
  {                                                                        \
    &MachineOperatorBuilder::Name, MachineOperatorBuilder::k##Name, #Name, \
        value_input_count, control_input_count, value_output_count         \
  }
    OPTIONAL_ENTRY(Float64RoundDown, 1, 0, 1),      // --
    OPTIONAL_ENTRY(Float64RoundTruncate, 1, 0, 1),  // --
    OPTIONAL_ENTRY(Float64RoundTiesAway, 1, 0, 1),  // --
    OPTIONAL_ENTRY(Float64Select, 3, 0, 1),         // --
    OPTIONAL_ENTRY(Float32Select, 3, 0, 1),         // --
    OPTIONAL_ENTRY(Word32Select, 3, 0, 1),          // --
    OPTIONAL_ENTRY(Word64Select, 3, 0, 1),          // --
#undef OPTIONAL_ENTRY
};


class MachineOptionalOperatorTest : public TestWithZone {
 protected:
  MachineRepresentation word_rep() {
    return MachineType::PointerRepresentation();
  }
};


TEST_F(MachineOptionalOperatorTest, OptionalOperators) {
  TRACED_FOREACH(OptionalOperatorEntry, pop, kOptionalOperators) {
    TRACED_FOREACH(MachineRepresentation, machine_rep1, kMachineReps) {
      MachineOperatorBuilder machine1(zone(), machine_rep1, pop.enabling_flag);
      TRACED_FOREACH(MachineRepresentation, machine_rep2, kMachineReps) {
        MachineOperatorBuilder machine2(zone(), machine_rep2,
                                        pop.enabling_flag);
        const Operator* op1 = (machine1.*pop.constructor)().op();
        const Operator* op2 = (machine2.*pop.constructor)().op();
        EXPECT_EQ(op1, op2);
        EXPECT_EQ(pop.value_input_count, op1->ValueInputCount());
        EXPECT_EQ(pop.control_input_count, op1->ControlInputCount());
        EXPECT_EQ(pop.value_output_count, op1->ValueOutputCount());

        MachineOperatorBuilder machine3(zone(), word_rep());
        EXPECT_TRUE((machine1.*pop.constructor)().IsSupported());
        EXPECT_FALSE((machine3.*pop.constructor)().IsSupported());
      }
    }
  }
}


// -----------------------------------------------------------------------------
// Pseudo operators.

using MachineOperatorTest = TestWithZone;

TEST_F(MachineOperatorTest, PseudoOperatorsWhenWordSizeIs32Bit) {
  MachineOperatorBuilder machine(zone(), MachineRepresentation::kWord32);
  EXPECT_EQ(machine.Word32And(), machine.WordAnd());
  EXPECT_EQ(machine.Word32Or(), machine.WordOr());
  EXPECT_EQ(machine.Word32Xor(), machine.WordXor());
  EXPECT_EQ(machine.Word32Shl(), machine.WordShl());
  EXPECT_EQ(machine.Word32Shr(), machine.WordShr());
  EXPECT_EQ(machine.Word32Sar(), machine.WordSar());
  EXPECT_EQ(machine.Word32Ror(), machine.WordRor());
  EXPECT_EQ(machine.Word32Equal(), machine.WordEqual());
  EXPECT_EQ(machine.Int32Add(), machine.IntAdd());
  EXPECT_EQ(machine.Int32Sub(), machine.IntSub());
  EXPECT_EQ(machine.Int32Mul(), machine.IntMul());
  EXPECT_EQ(machine.Int32Div(), machine.IntDiv());
  EXPECT_EQ(machine.Uint32Div(), machine.UintDiv());
  EXPECT_EQ(machine.Int32Mod(), machine.IntMod());
  EXPECT_EQ(machine.Uint32Mod(), machine.UintMod());
  EXPECT_EQ(machine.Int32LessThan(), machine.IntLessThan());
  EXPECT_EQ(machine.Int32LessThanOrEqual(), machine.IntLessThanOrEqual());
}


TEST_F(MachineOperatorTest, PseudoOperatorsWhenWordSizeIs64Bit) {
  MachineOperatorBuilder machine(zone(), MachineRepresentation::kWord64);
  EXPECT_EQ(machine.Word64And(), machine.WordAnd());
  EXPECT_EQ(machine.Word64Or(), machine.WordOr());
  EXPECT_EQ(machine.Word64Xor(), machine.WordXor());
  EXPECT_EQ(machine.Word64Shl(), machine.WordShl());
  EXPECT_EQ(machine.Word64Shr(), machine.WordShr());
  EXPECT_EQ(machine.Word64Sar(), machine.WordSar());
  EXPECT_EQ(machine.Word64Ror(), machine.WordRor());
  EXPECT_EQ(machine.Word64Equal(), machine.WordEqual());
  EXPECT_EQ(machine.Int64Add(), machine.IntAdd());
  EXPECT_EQ(machine.Int64Sub(), machine.IntSub());
  EXPECT_EQ(machine.Int64Mul(), machine.IntMul());
  EXPECT_EQ(machine.Int64Div(), machine.IntDiv());
  EXPECT_EQ(machine.Uint64Div(), machine.UintDiv());
  EXPECT_EQ(machine.Int64Mod(), machine.IntMod());
  EXPECT_EQ(machine.Uint64Mod(), machine.UintMod());
  EXPECT_EQ(machine.Int64LessThan(), machine.IntLessThan());
  EXPECT_EQ(machine.Int64LessThanOrEqual(), machine.IntLessThanOrEqual());
}

}  // namespace machine_operator_unittest
}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```