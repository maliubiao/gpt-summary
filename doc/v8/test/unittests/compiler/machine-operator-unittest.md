Response:
Let's break down the thought process for analyzing the C++ unit test file.

1. **Understand the Goal:** The core goal of a unit test is to verify the behavior of a specific unit of code in isolation. In this case, the unit is the `MachineOperatorBuilder` class and its ability to create and manage machine-level operators.

2. **Identify the Subject Under Test:** The file name `machine-operator-unittest.cc` and the inclusion of `"src/compiler/machine-operator.h"` immediately point to the `MachineOperatorBuilder` class as the central focus.

3. **Recognize the Testing Framework:**  The presence of `#include "test/unittests/test-utils.h"` and constructs like `TEST_P`, `TEST_F`, `EXPECT_EQ` indicate the use of a testing framework, likely Google Test, common in C++ projects.

4. **Analyze the Test Structure:**  The code is organized into several test suites or groups, indicated by `TEST_P` and `TEST_F`. Each test suite focuses on a specific category of machine operators (Load, Store, Pure, Optional, Pseudo).

5. **Examine Individual Tests:** For each test, ask:
    * **What is being tested?**  The test name and the assertions within the test provide clues. For instance, `InstancesAreGloballyShared` suggests testing the singleton-like behavior of operator creation. `NumberOfInputsAndOutputs` checks the expected number of inputs and outputs for an operator. `OpcodeIsCorrect` verifies the assigned opcode. `ParameterIsCorrect` checks operator-specific parameters.
    * **How is it being tested?** The tests generally follow a pattern:
        1. Create one or more `MachineOperatorBuilder` instances.
        2. Use the builder to create specific operators (e.g., `machine.Load()`, `machine.Store()`).
        3. Use `EXPECT_EQ` or similar assertions to compare the created operator's properties (e.g., its pointer, opcode, parameters) with expected values.
    * **Are there parameterized tests?** `TEST_P` indicates parameterized tests. This means the same test logic is executed with different input values. The `INSTANTIATE_TEST_SUITE_P` macro defines the sets of parameters to use. This is very useful for testing different data types and configurations.

6. **Identify Key Concepts:**  As you analyze the tests, note the key concepts being exercised:
    * **Machine Operators:**  The fundamental building blocks of the intermediate representation in the V8 compiler. Examples include Load, Store, arithmetic operations, bitwise operations, floating-point operations, etc.
    * **MachineRepresentation:**  The underlying data type of values the operators work with (e.g., `kWord32`, `kWord64`, `kFloat32`, `kFloat64`).
    * **LoadRepresentation/StoreRepresentation:**  Specific details for load and store operations, including the memory access type and write barrier kind.
    * **Opcodes:** Unique identifiers for each type of machine operator.
    * **Operator Properties:**  Information about the operator, such as the number of inputs and outputs.
    * **Pure Operators:** Operators without side effects.
    * **Optional Operators:** Operators that might not be supported on all architectures or require specific flags.
    * **Pseudo Operators:**  Higher-level operators that map to specific word-size-dependent operators.
    * **Write Barriers:** Mechanisms to ensure garbage collection correctness when storing object pointers.

7. **Consider the Absence of Torque:** The prompt specifically mentions checking if the file ends with `.tq`. Since it ends with `.cc`, it's a C++ file, not a Torque file. Therefore, we don't need to delve into Torque-specific aspects.

8. **Relate to JavaScript (if applicable):**  The prompt asks about the relationship to JavaScript. While this file *doesn't directly contain JavaScript*, it tests the *machine-level operations* that the V8 compiler ultimately generates when compiling JavaScript code. Think about common JavaScript operations and how they might map to machine instructions:
    * Variable access (`let x = obj.prop;`) -> `Load` operator.
    * Variable assignment (`obj.prop = value;`) -> `Store` operator.
    * Arithmetic operations (`a + b`) -> `Int32Add`, `Float64Add`, etc.
    * Bitwise operations (`a & b`) -> `Word32And`, `Word64And`.
    * Comparisons (`a < b`) -> `Int32LessThan`, `Float64LessThan`.

9. **Think about Potential Programming Errors:** Unit tests often reveal common programming errors. In this context, the tests highlight the importance of:
    * **Correctly specifying data types:** Using the right `MachineRepresentation` is crucial for correct code generation.
    * **Understanding memory access:** `Load` and `Store` operators need to handle different data sizes and potentially write barriers.
    * **Choosing the appropriate operator:**  Using a bitwise AND when you need addition would be a programming error.
    * **Considering platform differences:** Optional operators highlight that certain operations might not be available everywhere.

10. **Synthesize the Information:**  Finally, organize the findings into a clear and concise summary that addresses all the points raised in the prompt: functionality, Torque check, JavaScript relationship, logic/I/O examples, and common errors.

By following this structured approach, you can effectively analyze C++ unit tests and understand their purpose and implications, even without being deeply familiar with the specific codebase.
`v8/test/unittests/compiler/machine-operator-unittest.cc` 是 V8 JavaScript 引擎中用于测试 `MachineOperatorBuilder` 类的单元测试文件。`MachineOperatorBuilder` 类负责创建和管理表示底层机器指令的操作符，这些操作符是 V8 编译器中间表示（IR）的一部分。

**功能列表:**

1. **测试 Load 操作符:**
   - 验证 `MachineOperatorBuilder::Load()` 方法创建的 Load 操作符实例是全局共享的（单例模式）。
   - 检查 Load 操作符的输入和输出数量是否正确（2个值输入：地址和偏移，1个效果输入：内存状态，1个控制输入：控制流；1个值输出：加载的值，1个效果输出：更新后的内存状态，0个控制输出）。
   - 验证 Load 操作符的 `IrOpcode` 是 `kLoad`。
   - 检查 Load 操作符的参数（`LoadRepresentation`，包含数据类型）是否正确。

2. **测试 Store 操作符:**
   - 验证 `MachineOperatorBuilder::Store()` 方法创建的 Store 操作符实例是全局共享的。
   - 检查 Store 操作符的输入和输出数量是否正确（3个值输入：地址，偏移，要存储的值，1个效果输入，1个控制输入；0个值输出，1个效果输出，0个控制输出）。
   - 验证 Store 操作符的 `IrOpcode` 是 `kStore`。
   - 检查 Store 操作符的参数（`StoreRepresentation`，包含数据类型和是否需要写屏障）是否正确。

3. **测试 Pure 操作符 (无副作用的操作符):**
   - 遍历一系列无副作用的机器操作符（例如：`Word32And`，`Int32Add`，`Float64Sqrt` 等）。
   - 验证对于相同的操作符，无论 `MachineOperatorBuilder` 的机器表示类型如何，创建的实例都是相同的。
   - 检查每个 Pure 操作符的输入和输出数量是否符合预期。

4. **测试 Optional 操作符 (可选的操作符):**
   - 遍历一系列可选的机器操作符（例如：`Float64RoundDown`，`Float64Select` 等）。
   - 验证对于相同的操作符和启用的标志，无论 `MachineOperatorBuilder` 的机器表示类型如何，创建的实例都是相同的。
   - 检查每个 Optional 操作符的输入和输出数量是否符合预期。
   - 检查 `IsSupported()` 方法是否根据 `MachineOperatorBuilder` 的配置正确返回。

5. **测试 Pseudo 操作符 (伪操作符):**
   - 验证在 32 位机器表示下，`WordAnd()` 等伪操作符会返回对应的 32 位操作符（例如 `Word32And()`）。
   - 验证在 64 位机器表示下，`WordAnd()` 等伪操作符会返回对应的 64 位操作符（例如 `Word64And()`）。
   - 这部分测试了根据目标架构字长选择合适操作符的功能。

**关于文件扩展名和 Torque:**

该文件以 `.cc` 结尾，表示它是一个 C++ 源文件。如果它以 `.tq` 结尾，那它才是一个 V8 Torque 源代码。因此，这个文件不是 Torque 代码。

**与 JavaScript 的关系:**

`v8/test/unittests/compiler/machine-operator-unittest.cc` 测试的是 V8 编译器中低级别的机器操作符。这些操作符是 JavaScript 代码编译成机器码过程中的一个重要中间步骤。

**JavaScript 示例说明:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它可以帮助理解 JavaScript 代码最终如何被转换为机器指令。例如：

```javascript
let a = 10;
let b = 20;
let sum = a + b; // JavaScript 加法操作
```

在 V8 编译器的某个阶段，`a + b` 这个 JavaScript 加法操作可能会被转换为一个 `Int32Add`（如果 `a` 和 `b` 被推断为 32 位整数）或者 `Float64Add`（如果 `a` 和 `b` 被推断为浮点数）的机器操作符。这个测试文件就是用来验证 `MachineOperatorBuilder` 能否正确地创建这些底层的操作符。

再比如，JavaScript 的对象属性访问：

```javascript
const obj = { x: 5 };
let value = obj.x; // JavaScript 属性读取
```

这个属性读取操作在编译器层面可能会被转换成一个 `Load` 操作符，用于从 `obj` 对象在内存中的位置加载 `x` 的值。

**代码逻辑推理 (假设输入与输出):**

假设我们测试 `Int32Add` 操作符：

**假设输入:**

- `MachineRepresentation`: `kWord32` (表示 32 位字长)
- 调用 `MachineOperatorBuilder::Int32Add()`

**预期输出:**

- 返回一个指向 `Operator` 实例的指针。
- 该 `Operator` 实例的 `opcode()` 方法返回 `IrOpcode::kInt32Add`。
- 该 `Operator` 实例的 `ValueInputCount()` 返回 `2`。
- 该 `Operator` 实例的 `ControlInputCount()` 返回 `0`。
- 该 `Operator` 实例的 `ValueOutputCount()` 返回 `1`。

**用户常见的编程错误举例:**

虽然这个测试文件针对的是编译器内部的组件，但理解这些底层操作符可以帮助开发者避免一些性能问题或理解 JavaScript 引擎的行为。 与这些测试相关的常见编程错误可能发生在编写编译器代码时，例如：

1. **错误地指定 `MachineRepresentation`:**  如果编译器错误地将一个浮点数操作使用了整数操作符，或者使用了错误的字长，会导致计算错误。 例如，本应该使用 `Float64Add` 却使用了 `Int32Add`。
2. **Load 和 Store 操作中使用了错误的偏移或地址:**  这会导致读取或写入错误的内存位置，可能导致程序崩溃或数据损坏。 例如，尝试加载超出数组边界的元素。
3. **没有正确处理可选操作符的支持情况:**  如果在不支持特定指令集的平台上使用了可选操作符，可能会导致运行时错误。

总而言之，`v8/test/unittests/compiler/machine-operator-unittest.cc` 是 V8 编译器中一个关键的测试文件，它确保了 `MachineOperatorBuilder` 能够正确地创建和管理用于表示底层机器指令的操作符，这对于将 JavaScript 代码高效可靠地编译成机器码至关重要。

### 提示词
```
这是目录为v8/test/unittests/compiler/machine-operator-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/machine-operator-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
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
```