Response:
Let's break down the thought process to analyze the given C++ header file.

1. **Identify the Core Purpose:** The filename `turboshaft-instruction-selector-unittest.h` immediately suggests this is a unit test header file related to the "instruction selector" within the "turboshaft" compiler component of V8. The `.h` confirms it's a header, likely defining classes and structures for these tests.

2. **Examine Includes:**  The `#include` directives reveal dependencies:
    * Standard Library (`<deque>`, `<set>`, `<type_traits>`): Basic data structures and type utilities.
    * V8 Specific Headers:  These are crucial for understanding the context. Key ones include:
        * `src/base/utils/random-number-generator.h`:  Indicates the tests might involve randomness.
        * `src/common/globals.h`, `src/compiler/globals.h`:  Fundamental V8 definitions.
        * `src/compiler/backend/instruction-selector.h`:  Confirms the focus on instruction selection.
        * `src/compiler/turboshaft/...`: A whole suite of headers under the `turboshaft` namespace, hinting at the components involved (assembler, graph, reducers, operations, representations, phase).
        * `test/unittests/test-utils.h`:  Standard V8 unit testing utilities.

3. **Namespace Exploration:** The code is within `namespace v8::internal::compiler::turboshaft`. This pinpoints the exact location of these tests within the V8 codebase.

4. **Conditional Compilation:**  The `#if V8_ENABLE_WEBASSEMBLY` block is significant. It suggests that certain features and operations are specific to WebAssembly. This means the instruction selector being tested needs to handle both standard JavaScript and WebAssembly scenarios.

5. **Macro Definitions (BINOP_LIST, UNOP_LIST):** These macros are used to define lists of binary and unary operations. The naming convention (`Word32Add`, `Float64Div`, `ChangeInt32ToFloat64`, etc.) strongly suggests these are low-level operations that the instruction selector deals with. The presence of `SIMD_BINOP_LIST` within `BINOP_LIST` further ties into the WebAssembly SIMD support.

6. **Enums (TSBinop, TSUnop):** These enums, using the macros defined earlier, create a type-safe way to represent the binary and unary operations within the test framework. The `k` prefix for each enum member is a common C++ convention for constants.

7. **The Core Test Class (`TurboshaftInstructionSelectorTest`):** This is the heart of the file.
    * **Inheritance:** It inherits from `TestWithNativeContextAndZone`, a standard V8 testing base class, providing a testing environment with a V8 isolate and memory management.
    * **`SetUp()` and `TearDown()`:** Standard test fixture setup and cleanup methods. They initialize and destroy `PipelineData`, a crucial structure for the Turboshaft compiler pipeline.
    * **`data()` and `rng()`:** Accessors for the `PipelineData` and the random number generator.
    * **`StreamBuilder` Class:** This nested class is an *internal DSL (Domain Specific Language)* for constructing sequences of Turboshaft operations. It provides a fluent interface for emitting operations (`Emit()`), defining parameters, and building the instruction stream (`Build()`). The various constructors allow for setting up different call descriptor signatures. The `MakeSimpleCallDescriptor` functions are for creating simplified call scenarios for testing.
    * **`Stream` Class:** This nested class represents the result of the instruction selection process. It holds the generated `Instruction` objects and provides methods for inspecting them (checking operand types, extracting constant values, etc.). The internal data structures like `constants_`, `doubles_`, and `references_` are used to track the properties of the generated instructions.

8. **Focus on Instruction Selection:**  The names of classes (`TurboshaftInstructionSelectorTest`, `StreamBuilder`, `Stream`), the included headers (`instruction-selector.h`), and the types of operations being tested (arithmetic, bitwise, comparisons, SIMD) all point towards the core functionality being tested: verifying that the Turboshaft instruction selector correctly translates high-level operations into low-level machine instructions.

9. **Relationship to JavaScript (Speculation based on context):** While the code itself is C++, the *purpose* is to test a component of the JavaScript engine (V8). The instruction selector is responsible for generating machine code that will eventually execute JavaScript. The test cases likely cover scenarios that arise from compiling various JavaScript constructs. *Without specific examples in this header*, we can only infer the connection.

10. **Code Logic Inference (High-Level):** The `StreamBuilder` allows constructing a "program" using Turboshaft operations. The `Build()` method then invokes the instruction selector (implicitly). The `Stream` class allows verification that the *output* of the instruction selector (the generated instructions) matches expectations. The tests would likely involve building a sequence of operations using `StreamBuilder` and then asserting properties of the resulting `Stream`.

11. **Common Programming Errors (Hypothetical):**  Since this is a test file, the focus is on *finding* errors in the instruction selector. Common errors might include:
    * **Incorrect instruction selection:** Choosing the wrong machine instruction for a given Turboshaft operation.
    * **Incorrect operand generation:**  Generating operands with the wrong types or values.
    * **Missing edge cases:** Failing to handle specific combinations of inputs or CPU features.
    * **Incorrect handling of WebAssembly specifics:** Errors in SIMD instruction selection or memory access.

By systematically examining these elements, we can arrive at a comprehensive understanding of the header file's role and functionality within the V8 project.
这个头文件 `v8/test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.h` 是 V8 JavaScript 引擎中 Turboshaft 编译器的指令选择器（instruction selector）的单元测试框架的定义。

**主要功能:**

1. **定义测试基础设施:** 它定义了一个名为 `TurboshaftInstructionSelectorTest` 的 C++ 类，这个类继承自 `TestWithNativeContextAndZone`，这是一个 V8 提供的用于编写单元测试的基类。这个基类提供了 V8 运行时的环境，例如 Isolate 和 Zone（用于内存管理）。

2. **提供构建 Turboshaft 操作序列的工具:**  它定义了一个嵌套类 `StreamBuilder`，用于方便地构建 Turboshaft 中间表示（IR）的操作序列。这个类提供了类似于汇编器的接口，允许测试用例以编程方式创建各种 Turboshaft 操作，例如算术运算、位运算、比较运算、类型转换等。

3. **模拟指令选择过程:** `StreamBuilder` 最终会调用指令选择器，将构建的 Turboshaft 操作序列转换成目标架构的机器指令。虽然这个头文件本身不包含指令选择的实现，但它是测试指令选择器功能的关键入口。

4. **提供检查生成指令的工具:** 它定义了另一个嵌套类 `Stream`，用于存储和检查指令选择器生成的机器指令。`Stream` 类提供了方法来访问生成的指令，并检查其属性，例如操作码、操作数类型和值等。

5. **支持测试不同 CPU 特性下的指令选择:** `StreamBuilder` 允许指定要启用的 CPU 特性（通过 `CpuFeature` 枚举），以便测试指令选择器在不同硬件能力下的行为。这对于测试诸如 SIMD 指令的支持非常重要。

6. **支持 WebAssembly 指令的测试:**  通过条件编译 (`#if V8_ENABLE_WEBASSEMBLY`)，这个头文件包含了针对 WebAssembly SIMD 指令的定义和辅助函数，表明它也用于测试 WebAssembly 代码的指令选择。

**关于文件扩展名 `.tq`:**

这个头文件的扩展名是 `.h`，而不是 `.tq`。如果一个 V8 源代码文件以 `.tq` 结尾，那么它是一个 **Torque** 源代码文件。Torque 是 V8 用来定义内置函数和运行时函数的领域特定语言。

**与 JavaScript 的关系:**

指令选择器是编译器后端的一部分，它的主要任务是将高级的中间表示转换成目标机器的低级指令。在 V8 中，当 JavaScript 代码被编译时，Turboshaft 编译器会生成中间表示，然后指令选择器会根据目标架构（例如 x64、ARM）选择合适的机器指令。

**JavaScript 举例说明:**

虽然这个头文件是 C++ 代码，用于测试编译器的内部机制，但它可以用来测试编译以下 JavaScript 代码时指令选择器的行为：

```javascript
function add(a, b) {
  return a + b;
}

function compare(x, y) {
  return x < y;
}

function bitwiseAnd(m, n) {
  return m & n;
}
```

例如，一个测试用例可能会使用 `StreamBuilder` 构建表示 `a + b` 的 Turboshaft 操作，然后检查指令选择器是否为目标架构生成了正确的加法指令。

**代码逻辑推理 (假设输入与输出):**

假设我们使用 `StreamBuilder` 构建了一个简单的加法操作：

```c++
StreamBuilder builder(this, MachineType::Int32());
auto param0 = builder.Parameter(0, MachineType::Int32());
auto param1 = builder.Parameter(1, MachineType::Int32());
auto add_op = builder.Emit(TSBinop::kWord32Add, param0, param1);
builder.Return(add_op);
Stream stream = builder.Build();
```

**假设输入:**  `StreamBuilder` 构建了一个表示两个 32 位整数相加的 Turboshaft 操作序列。

**预期输出:** `Stream` 对象将包含一个或多个机器指令，具体取决于目标架构。在 x64 架构上，可能包含一个 `add` 指令。`Stream` 对象的方法可以用来验证是否存在 `add` 指令，并且其操作数指向正确的寄存器或内存位置。

**用户常见的编程错误 (以及如何通过测试发现):**

这个测试框架主要用于发现 **编译器自身的错误**，而不是用户 JavaScript 代码的错误。但是，编译器的错误可能会导致用户代码在运行时出现意想不到的行为或性能问题。以下是一些指令选择器可能出现的错误，这个测试框架可以帮助发现：

1. **选择了错误的指令:** 例如，对于无符号整数加法，错误地选择了有符号整数加法指令。测试可以构建一个无符号加法的场景，并验证生成的指令是否正确。

2. **操作数处理错误:**  例如，指令的操作数类型不匹配，或者使用了错误的寄存器分配策略。测试可以创建需要特定操作数类型的操作，并检查指令选择器是否正确处理。

3. **遗漏了某些 CPU 特性的优化:**  例如，在支持 AVX 指令的 CPU 上，对于某些操作没有使用 AVX 指令进行优化。测试可以针对特定的 CPU 特性构建场景，并验证是否生成了优化的指令。

4. **处理边界情况或溢出时的错误:** 例如，对于可能溢出的整数运算，没有正确生成溢出检查的代码。测试可以构造导致溢出的输入，并验证是否生成了必要的溢出处理指令。

**总结:**

`v8/test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.h` 是一个关键的头文件，它为 V8 引擎中 Turboshaft 编译器的指令选择器提供了强大的单元测试框架。它允许开发者以编程方式构建 Turboshaft 操作序列，模拟指令选择过程，并验证生成的机器指令是否符合预期，从而确保编译器的正确性和性能。

Prompt: 
```
这是目录为v8/test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.h的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_UNITTESTS_COMPILER_INSTRUCTION_SELECTOR_UNITTEST_H_
#define V8_UNITTESTS_COMPILER_INSTRUCTION_SELECTOR_UNITTEST_H_

#include <deque>
#include <set>
#include <type_traits>

#include "src/base/utils/random-number-generator.h"
#include "src/common/globals.h"
#include "src/compiler/backend/instruction-selector.h"
#include "src/compiler/globals.h"
#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/index.h"
#include "src/compiler/turboshaft/instruction-selection-normalization-reducer.h"
#include "src/compiler/turboshaft/load-store-simplification-reducer.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/phase.h"
#include "src/compiler/turboshaft/representations.h"
#include "test/unittests/test-utils.h"

namespace v8::internal::compiler::turboshaft {

#if V8_ENABLE_WEBASSEMBLY
#define SIMD_BINOP_LIST(V)          \
  FOREACH_SIMD_128_BINARY_OPCODE(V) \
  FOREACH_SIMD_128_SHIFT_OPCODE(V)
#else
#define SIMD_BINOP_LIST(V)
#endif  // V8_ENABLE_WEBASSEMBLY

#define BINOP_LIST(V)           \
  SIMD_BINOP_LIST(V)            \
  V(Word32BitwiseAnd)           \
  V(Word64BitwiseAnd)           \
  V(Word32BitwiseOr)            \
  V(Word64BitwiseOr)            \
  V(Word32BitwiseXor)           \
  V(Word64BitwiseXor)           \
  V(Word32Add)                  \
  V(Word64Add)                  \
  V(Word32Sub)                  \
  V(Word64Sub)                  \
  V(Word32Mul)                  \
  V(Word64Mul)                  \
  V(Int32MulOverflownBits)      \
  V(Int64MulOverflownBits)      \
  V(Int32Div)                   \
  V(Int64Div)                   \
  V(Int32Mod)                   \
  V(Int64Mod)                   \
  V(Uint32MulOverflownBits)     \
  V(Uint64MulOverflownBits)     \
  V(Uint32Div)                  \
  V(Uint64Div)                  \
  V(Uint32Mod)                  \
  V(Uint64Mod)                  \
  V(Word32ShiftLeft)            \
  V(Word64ShiftLeft)            \
  V(Word32ShiftRightLogical)    \
  V(Word64ShiftRightLogical)    \
  V(Word32ShiftRightArithmetic) \
  V(Word64ShiftRightArithmetic) \
  V(Word32RotateRight)          \
  V(Word64RotateRight)          \
  V(Int32AddCheckOverflow)      \
  V(Int64AddCheckOverflow)      \
  V(Int32SubCheckOverflow)      \
  V(Int64SubCheckOverflow)      \
  V(Word32Equal)                \
  V(Word64Equal)                \
  V(Word32NotEqual)             \
  V(Word64NotEqual)             \
  V(Int32LessThan)              \
  V(Int32LessThanOrEqual)       \
  V(Uint32LessThan)             \
  V(Uint32LessThanOrEqual)      \
  V(Int32GreaterThanOrEqual)    \
  V(Int32GreaterThan)           \
  V(Uint32GreaterThanOrEqual)   \
  V(Uint32GreaterThan)          \
  V(Int64LessThan)              \
  V(Int64LessThanOrEqual)       \
  V(Uint64LessThan)             \
  V(Uint64LessThanOrEqual)      \
  V(Int64GreaterThanOrEqual)    \
  V(Int64GreaterThan)           \
  V(Uint64GreaterThanOrEqual)   \
  V(Uint64GreaterThan)          \
  V(Float64Add)                 \
  V(Float64Sub)                 \
  V(Float64Mul)                 \
  V(Float64Div)                 \
  V(Float64Equal)               \
  V(Float64LessThan)            \
  V(Float64LessThanOrEqual)     \
  V(Float32Equal)               \
  V(Float32LessThan)            \
  V(Float32LessThanOrEqual)

#define UNOP_LIST(V)          \
  V(ChangeFloat32ToFloat64)   \
  V(TruncateFloat64ToFloat32) \
  V(ChangeInt32ToInt64)       \
  V(ChangeUint32ToUint64)     \
  V(TruncateWord64ToWord32)   \
  V(ChangeInt32ToFloat64)     \
  V(ChangeUint32ToFloat64)    \
  V(ReversibleFloat64ToInt32) \
  V(ReversibleFloat64ToUint32)

#define DECL(Op) k##Op,

enum class TSBinop { BINOP_LIST(DECL) };
enum class TSUnop { UNOP_LIST(DECL) };

#undef DECL

class TurboshaftInstructionSelectorTest : public TestWithNativeContextAndZone {
 public:
  using BaseAssembler = TSAssembler<LoadStoreSimplificationReducer,
                                    InstructionSelectionNormalizationReducer>;

  TurboshaftInstructionSelectorTest();
  ~TurboshaftInstructionSelectorTest() override;

  ZoneStats zone_stats_{this->zone()->allocator()};

  void SetUp() override {
    pipeline_data_ = std::make_unique<PipelineData>(
        &zone_stats_, TurboshaftPipelineKind::kJS, isolate_, nullptr,
        AssemblerOptions::Default(isolate_));
    pipeline_data_->InitializeGraphComponent(nullptr);
  }
  void TearDown() override { pipeline_data_.reset(); }

  PipelineData* data() { return pipeline_data_.get(); }
  base::RandomNumberGenerator* rng() { return &rng_; }

  class Stream;

  enum StreamBuilderMode {
    kAllInstructions,
    kTargetInstructions,
    kAllExceptNopInstructions
  };

  class StreamBuilder final : public BaseAssembler {
   public:
    StreamBuilder(TurboshaftInstructionSelectorTest* test,
                  MachineType return_type)
        : BaseAssembler(test->data(), test->graph(), test->graph(),
                        test->zone()),
          test_(test),
          call_descriptor_(MakeCallDescriptor(test->zone(), return_type)) {
      Init();
    }

    StreamBuilder(TurboshaftInstructionSelectorTest* test,
                  MachineType return_type, MachineType parameter0_type)
        : BaseAssembler(test->data(), test->graph(), test->graph(),
                        test->zone()),
          test_(test),
          call_descriptor_(
              MakeCallDescriptor(test->zone(), return_type, parameter0_type)) {
      Init();
    }

    StreamBuilder(TurboshaftInstructionSelectorTest* test,
                  MachineType return_type, MachineType parameter0_type,
                  MachineType parameter1_type)
        : BaseAssembler(test->data(), test->graph(), test->graph(),
                        test->zone()),
          test_(test),
          call_descriptor_(MakeCallDescriptor(
              test->zone(), return_type, parameter0_type, parameter1_type)) {
      Init();
    }

    StreamBuilder(TurboshaftInstructionSelectorTest* test,
                  MachineType return_type, MachineType parameter0_type,
                  MachineType parameter1_type, MachineType parameter2_type)
        : BaseAssembler(test->data(), test->graph(), test->graph(),
                        test->zone()),
          test_(test),
          call_descriptor_(MakeCallDescriptor(test->zone(), return_type,
                                              parameter0_type, parameter1_type,
                                              parameter2_type)) {
      Init();
    }

    Stream Build(CpuFeature feature) {
      return Build(InstructionSelector::Features(feature));
    }
    Stream Build(CpuFeature feature1, CpuFeature feature2) {
      return Build(InstructionSelector::Features(feature1, feature2));
    }
    Stream Build(StreamBuilderMode mode = kTargetInstructions) {
      return Build(InstructionSelector::Features(), mode);
    }
    Stream Build(InstructionSelector::Features features,
                 StreamBuilderMode mode = kTargetInstructions,
                 InstructionSelector::SourcePositionMode source_position_mode =
                     InstructionSelector::kAllSourcePositions);

    const FrameStateFunctionInfo* GetFrameStateFunctionInfo(
        uint16_t parameter_count, int local_count);

    // Create a simple call descriptor for testing.
    static CallDescriptor* MakeSimpleCallDescriptor(Zone* zone,
                                                    MachineSignature* msig) {
      LocationSignature::Builder locations(zone, msig->return_count(),
                                           msig->parameter_count());

      // Add return location(s).
      const int return_count = static_cast<int>(msig->return_count());
      for (int i = 0; i < return_count; i++) {
        locations.AddReturn(
            LinkageLocation::ForCallerFrameSlot(-1 - i, msig->GetReturn(i)));
      }

      // Just put all parameters on the stack.
      const int parameter_count = static_cast<int>(msig->parameter_count());
      unsigned slot_index = -1;
      for (int i = 0; i < parameter_count; i++) {
        locations.AddParam(
            LinkageLocation::ForCallerFrameSlot(slot_index, msig->GetParam(i)));

        // Slots are kSystemPointerSize sized. This reserves enough for space
        // for types that might be bigger, eg. Simd128.
        slot_index -=
            std::max(1, ElementSizeInBytes(msig->GetParam(i).representation()) /
                            kSystemPointerSize);
      }

      const RegList kCalleeSaveRegisters;
      const DoubleRegList kCalleeSaveFPRegisters;

      MachineType target_type = MachineType::Pointer();
      LinkageLocation target_loc = LinkageLocation::ForAnyRegister();

      return zone->New<CallDescriptor>(  // --
          CallDescriptor::kCallAddress,  // kind
          kDefaultCodeEntrypointTag,     // tag
          target_type,                   // target MachineType
          target_loc,                    // target location
          locations.Get(),               // location_sig
          0,                             // stack_parameter_count
          Operator::kNoProperties,       // properties
          kCalleeSaveRegisters,          // callee-saved registers
          kCalleeSaveFPRegisters,        // callee-saved fp regs
          CallDescriptor::kCanUseRoots,  // flags
          "iselect-test-call");
    }

    static const TSCallDescriptor* MakeSimpleTSCallDescriptor(
        Zone* zone, MachineSignature* msig) {
      return TSCallDescriptor::Create(MakeSimpleCallDescriptor(zone, msig),
                                      CanThrow::kYes, LazyDeoptOnThrow::kNo,
                                      zone);
    }

    CallDescriptor* call_descriptor() { return call_descriptor_; }

    OpIndex Emit(TSUnop op, OpIndex input) {
      switch (op) {
#define CASE(Op)      \
  case TSUnop::k##Op: \
    return Op(input);
        UNOP_LIST(CASE)
#undef CASE
      }
    }

    OpIndex Emit(TSBinop op, OpIndex left, OpIndex right) {
      switch (op) {
#define CASE(Op)       \
  case TSBinop::k##Op: \
    return Op(left, right);
        BINOP_LIST(CASE)
#undef CASE
      }
    }

    template <typename T>
    V<T> Emit(TSBinop op, OpIndex left, OpIndex right) {
      OpIndex result = Emit(op, left, right);
      DCHECK_EQ(Get(result).outputs_rep().size(), 1);
      DCHECK_EQ(Get(result).outputs_rep()[0], v_traits<T>::rep);
      return V<T>::Cast(result);
    }

    // Some helpers to have the same interface as the Turbofan instruction
    // selector test had.
    V<Word32> Int32Constant(int32_t c) { return Word32Constant(c); }
    V<Word64> Int64Constant(int64_t c) { return Word64Constant(c); }
    V<Word32> Word32BinaryNot(V<Word32> a) { return Word32Equal(a, 0); }
    V<Word32> Word32BitwiseNot(V<Word32> a) { return Word32BitwiseXor(a, -1); }
    V<Word64> Word64BitwiseNot(V<Word64> a) { return Word64BitwiseXor(a, -1); }
    V<Word32> Word32NotEqual(V<Word32> a, V<Word32> b) {
      return Word32BinaryNot(Word32Equal(a, b));
    }
    V<Word32> Word64NotEqual(V<Word64> a, V<Word64> b) {
      return Word32BinaryNot(Word64Equal(a, b));
    }
    V<Word32> Int32GreaterThanOrEqual(V<Word32> a, V<Word32> b) {
      return Int32LessThanOrEqual(b, a);
    }
    V<Word32> Uint32GreaterThanOrEqual(V<Word32> a, V<Word32> b) {
      return Uint32LessThanOrEqual(b, a);
    }
    V<Word32> Int32GreaterThan(V<Word32> a, V<Word32> b) {
      return Int32LessThan(b, a);
    }
    V<Word32> Uint32GreaterThan(V<Word32> a, V<Word32> b) {
      return Uint32LessThan(b, a);
    }
    V<Word32> Int64GreaterThanOrEqual(V<Word64> a, V<Word64> b) {
      return Int64LessThanOrEqual(b, a);
    }
    V<Word32> Uint64GreaterThanOrEqual(V<Word64> a, V<Word64> b) {
      return Uint64LessThanOrEqual(b, a);
    }
    V<Word32> Int64GreaterThan(V<Word64> a, V<Word64> b) {
      return Int64LessThan(b, a);
    }
    V<Word32> Uint64GreaterThan(V<Word64> a, V<Word64> b) {
      return Uint64LessThan(b, a);
    }
    OpIndex Parameter(int index) {
      return Assembler::Parameter(
          index, RegisterRepresentation::FromMachineType(
                     call_descriptor()->GetParameterType(index)));
    }
    OpIndex Parameter(int index, RegisterRepresentation rep) {
      return Assembler::Parameter(index, rep);
    }
    template <typename T>
    V<T> Parameter(int index) {
      RegisterRepresentation rep = RegisterRepresentation::FromMachineType(
          call_descriptor()->GetParameterType(index));
      DCHECK_EQ(rep, v_traits<T>::rep);
      return Assembler::Parameter(index, rep);
    }
    using Assembler::Phi;
    template <typename... Args,
              typename = std::enable_if_t<
                  (true && ... && std::is_convertible_v<Args, OpIndex>)>>
    OpIndex Phi(MachineRepresentation rep, Args... inputs) {
      return Phi({inputs...},
                 RegisterRepresentation::FromMachineRepresentation(rep));
    }
    using Assembler::Load;
    OpIndex Load(MachineType type, OpIndex base, OpIndex index) {
      MemoryRepresentation mem_rep =
          MemoryRepresentation::FromMachineType(type);
      return Load(base, index, LoadOp::Kind::RawAligned(), mem_rep,
                  mem_rep.ToRegisterRepresentation());
    }
    OpIndex Load(MachineType type, OpIndex base) {
      MemoryRepresentation mem_rep =
          MemoryRepresentation::FromMachineType(type);
      return Load(base, LoadOp::Kind::RawAligned(), mem_rep);
    }
    OpIndex LoadImmutable(MachineType type, OpIndex base, OpIndex index) {
      MemoryRepresentation mem_rep =
          MemoryRepresentation::FromMachineType(type);
      return Load(base, index, LoadOp::Kind::RawAligned().Immutable(), mem_rep);
    }
    using Assembler::Store;
    void Store(MachineRepresentation rep, OpIndex base, OpIndex index,
               OpIndex value, WriteBarrierKind write_barrier) {
      MemoryRepresentation mem_rep =
          MemoryRepresentation::FromMachineRepresentation(rep);
      Store(base, index, value, StoreOp::Kind::RawAligned(), mem_rep,
            write_barrier);
    }
    using Assembler::Projection;
    OpIndex Projection(OpIndex input, int index) {
      const Operation& input_op = output_graph().Get(input);
      if (const TupleOp* tuple = input_op.TryCast<TupleOp>()) {
        DCHECK_LT(index, tuple->input_count);
        return tuple->input(index);
      }
      DCHECK_LT(index, input_op.outputs_rep().size());
      return Projection(input, index, input_op.outputs_rep()[index]);
    }
    V<Undefined> UndefinedConstant() {
      return HeapConstant(test_->isolate_->factory()->undefined_value());
    }

#ifdef V8_ENABLE_WEBASSEMBLY

#define DECL_SPLAT(Name)                                       \
  V<Simd128> Name##Splat(OpIndex input) {                      \
    return Simd128Splat(input, Simd128SplatOp::Kind::k##Name); \
  }
    FOREACH_SIMD_128_SPLAT_OPCODE(DECL_SPLAT)
#undef DECL_SPLAT

#define DECL_SIMD128_BINOP(Name)                                     \
  V<Simd128> Name(V<Simd128> left, V<Simd128> right) {               \
    return Simd128Binop(left, right, Simd128BinopOp::Kind::k##Name); \
  }
    FOREACH_SIMD_128_BINARY_OPCODE(DECL_SIMD128_BINOP)
#undef DECL_SIMD128_BINOP

#define DECL_SIMD128_UNOP(Name)                                \
  V<Simd128> Name(V<Simd128> input) {                          \
    return Simd128Unary(input, Simd128UnaryOp::Kind::k##Name); \
  }
    FOREACH_SIMD_128_UNARY_OPCODE(DECL_SIMD128_UNOP)
#undef DECL_SIMD128_UNOP

#define DECL_SIMD128_EXTRACT_LANE(Name, Suffix, Type)                 \
  V<Type> Name##Suffix##ExtractLane(V<Simd128> input, uint8_t lane) { \
    return V<Type>::Cast(Simd128ExtractLane(                          \
        input, Simd128ExtractLaneOp::Kind::k##Name##Suffix, lane));   \
  }
    DECL_SIMD128_EXTRACT_LANE(I8x16, S, Word32)
    DECL_SIMD128_EXTRACT_LANE(I8x16, U, Word32)
    DECL_SIMD128_EXTRACT_LANE(I16x8, S, Word32)
    DECL_SIMD128_EXTRACT_LANE(I16x8, U, Word32)
    DECL_SIMD128_EXTRACT_LANE(I32x4, , Word32)
    DECL_SIMD128_EXTRACT_LANE(I64x2, , Word64)
    DECL_SIMD128_EXTRACT_LANE(F32x4, , Float32)
    DECL_SIMD128_EXTRACT_LANE(F64x2, , Float64)
#undef DECL_SIMD128_EXTRACT_LANE

#define DECL_SIMD128_REDUCE(Name)                                           \
  V<Simd128> Name##AddReduce(V<Simd128> input) {                            \
    return Simd128Reduce(input, Simd128ReduceOp::Kind::k##Name##AddReduce); \
  }
    DECL_SIMD128_REDUCE(I8x16)
    DECL_SIMD128_REDUCE(I16x8)
    DECL_SIMD128_REDUCE(I32x4)
    DECL_SIMD128_REDUCE(I64x2)
    DECL_SIMD128_REDUCE(F32x4)
    DECL_SIMD128_REDUCE(F64x2)
#undef DECL_SIMD128_REDUCE

#define DECL_SIMD128_SHIFT(Name)                                      \
  V<Simd128> Name(V<Simd128> input, V<Word32> shift) {                \
    return Simd128Shift(input, shift, Simd128ShiftOp::Kind::k##Name); \
  }
    FOREACH_SIMD_128_SHIFT_OPCODE(DECL_SIMD128_SHIFT)
#undef DECL_SIMD128_SHIFT

#endif  // V8_ENABLE_WEBASSEMBLY

   private:
    template <typename... ParamT>
    CallDescriptor* MakeCallDescriptor(Zone* zone, MachineType return_type,
                                       ParamT... parameter_type) {
      MachineSignature::Builder builder(zone, 1, sizeof...(ParamT));
      builder.AddReturn(return_type);
      (builder.AddParam(parameter_type), ...);
      return MakeSimpleCallDescriptor(zone, builder.Get());
    }

    void Init() {
      // We reset the graph since the StreamBuilder is meant to create a new
      // fresh graph.
      test_->graph().Reset();

      // We bind a block right at the start so that test can start emitting
      // operations without always needing to bind a block first.
      Block* start_block = NewBlock();
      Bind(start_block);
    }

    TurboshaftInstructionSelectorTest* test_;
    CallDescriptor* call_descriptor_;
  };

  class Stream final {
   public:
    size_t size() const { return instructions_.size(); }
    const Instruction* operator[](size_t index) const {
      EXPECT_LT(index, size());
      return instructions_[index];
    }

    bool IsDouble(const InstructionOperand* operand) const {
      return IsDouble(ToVreg(operand));
    }

    bool IsDouble(OpIndex index) const { return IsDouble(ToVreg(index)); }

    bool IsInteger(const InstructionOperand* operand) const {
      return IsInteger(ToVreg(operand));
    }

    bool IsInteger(OpIndex index) const { return IsInteger(ToVreg(index)); }

    bool IsReference(const InstructionOperand* operand) const {
      return IsReference(ToVreg(operand));
    }

    bool IsReference(OpIndex index) const { return IsReference(ToVreg(index)); }

    float ToFloat32(const InstructionOperand* operand) const {
      return ToConstant(operand).ToFloat32();
    }

    double ToFloat64(const InstructionOperand* operand) const {
      return ToConstant(operand).ToFloat64().value();
    }

    int32_t ToInt32(const InstructionOperand* operand) const {
      return ToConstant(operand).ToInt32();
    }

    int64_t ToInt64(const InstructionOperand* operand) const {
      return ToConstant(operand).ToInt64();
    }

    Handle<HeapObject> ToHeapObject(const InstructionOperand* operand) const {
      return ToConstant(operand).ToHeapObject();
    }

    int ToVreg(const InstructionOperand* operand) const {
      if (operand->IsConstant()) {
        return ConstantOperand::cast(operand)->virtual_register();
      }
      EXPECT_EQ(InstructionOperand::UNALLOCATED, operand->kind());
      return UnallocatedOperand::cast(operand)->virtual_register();
    }

    int ToVreg(OpIndex index) const;

    bool IsFixed(const InstructionOperand* operand, Register reg) const;
    bool IsSameAsFirst(const InstructionOperand* operand) const;
    bool IsSameAsInput(const InstructionOperand* operand,
                       int input_index) const;
    bool IsUsedAtStart(const InstructionOperand* operand) const;

    FrameStateDescriptor* GetFrameStateDescriptor(int deoptimization_id) {
      EXPECT_LT(deoptimization_id, GetFrameStateDescriptorCount());
      return deoptimization_entries_[deoptimization_id];
    }

    int GetFrameStateDescriptorCount() {
      return static_cast<int>(deoptimization_entries_.size());
    }

   private:
    bool IsDouble(int virtual_register) const {
      return doubles_.find(virtual_register) != doubles_.end();
    }

    bool IsInteger(int virtual_register) const {
      return !IsDouble(virtual_register) && !IsReference(virtual_register);
    }

    bool IsReference(int virtual_register) const {
      return references_.find(virtual_register) != references_.end();
    }

    Constant ToConstant(const InstructionOperand* operand) const {
      ConstantMap::const_iterator i;
      if (operand->IsConstant()) {
        i = constants_.find(ConstantOperand::cast(operand)->virtual_register());
        EXPECT_EQ(ConstantOperand::cast(operand)->virtual_register(), i->first);
        EXPECT_FALSE(constants_.end() == i);
      } else {
        EXPECT_EQ(InstructionOperand::IMMEDIATE, operand->kind());
        auto imm = ImmediateOperand::cast(operand);
        if (imm->type() == ImmediateOperand::INLINE_INT32) {
          return Constant(imm->inline_int32_value());
        } else if (imm->type() == ImmediateOperand::INLINE_INT64) {
          return Constant(imm->inline_int64_value());
        }
        i = immediates_.find(imm->indexed_value());
        EXPECT_EQ(imm->indexed_value(), i->first);
        EXPECT_FALSE(immediates_.end() == i);
      }
      return i->second;
    }

    friend class StreamBuilder;

    using ConstantMap = std::map<int, Constant>;
    using VirtualRegisters = std::map<uint32_t, int>;

    ConstantMap constants_;
    ConstantMap immediates_;
    std::deque<Instruction*> instructions_;
    std::set<int> doubles_;
    std::set<int> references_;
    VirtualRegisters virtual_registers_;
    std::deque<FrameStateDescriptor*> deoptimization_entries_;
  };

  base::RandomNumberGenerator rng_;

  Graph& graph() { return pipeline_data_->graph(); }

  Isolate* isolate_ = this->isolate();

  std::unique_ptr<turboshaft::PipelineData> pipeline_data_;
};

template <typename T>
class TurboshaftInstructionSelectorTestWithParam
    : public TurboshaftInstructionSelectorTest,
      public ::testing::WithParamInterface<T> {};

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_UNITTESTS_COMPILER_INSTRUCTION_SELECTOR_UNITTEST_H_

"""

```