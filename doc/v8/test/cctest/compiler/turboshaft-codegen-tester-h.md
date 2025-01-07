Response:
Let's break down the thought process to analyze the provided C++ header file.

1. **Understand the Goal:** The request asks for the *functionality* of the header file `v8/test/cctest/compiler/turboshaft-codegen-tester.h`. This means understanding its purpose and how it's used within the V8 project.

2. **Initial Scan for Keywords and Structure:**  Quickly scan the file for prominent keywords and structural elements. Things that immediately stand out:
    * `#ifndef`, `#define`, `#include`: Standard C++ header guard. Confirms it's a header file.
    * `namespace v8::internal::compiler::turboshaft`:  Indicates this code belongs to the Turboshaft compiler pipeline within V8.
    * `class DataHolder`, `class RawMachineAssemblerTester`, `class BufferedRawMachineAssemblerTester`:  These are the main classes, suggesting the core functionality revolves around creating and manipulating some form of "assembler" or code generation.
    * `template`:  Heavy use of templates implies genericity and the ability to work with different data types.
    * `GenerateCode`, `GetCode`, `Call`: Methods suggesting the ability to generate and execute code.
    * `CheckNumber`, `CheckString`: Methods for verifying the output of the generated code.
    * `TurboshaftBinop`, `TurboshaftComparison`: Enums listing different kinds of binary operations and comparisons, hinting at testing specific compiler functionalities.
    * `BinopTester`, `IntBinopWrapper`, `CompareWrapper`, `BinopGen`, `Int32BinopInputShapeTester`: More classes related to testing binary operations, suggesting a focus on testing these specific instructions.

3. **Focus on Key Classes and their Responsibilities:**

    * **`DataHolder`:**  The name suggests it holds essential data needed for code generation. Looking at its members: `Isolate`, `Zone`, `OptimizedCompilationInfo`, `PipelineData`, `CallDescriptor`. These are all core V8 compiler concepts. It seems `DataHolder` sets up the basic environment required for Turboshaft code generation within a test. The comment about `turboshaft_instruction_selection` is a vital clue about its purpose.

    * **`RawMachineAssemblerTester`:** This class inherits from `DataHolder` and other utility classes (`HandleAndZoneScope`, `CallHelper`). The name "AssemblerTester" strongly suggests it's used to build and test machine code sequences. It has methods for emitting instructions (`Parameter`, `PointerConstant`, `Load`, `Store`, `Int32GreaterThan`, etc.) and for generating/retrieving the resulting code (`GenerateCode`, `GetCode`). The `Call` method indicates it can execute the generated code.

    * **`BufferedRawMachineAssemblerTester`:** This appears to be a specialization of `RawMachineAssemblerTester`. The "Buffered" part and the comments about passing pointers to parameters and storing return values suggest it handles cases where parameters or return values are larger than what can be directly passed through registers, likely for 64-bit values or more complex data structures.

    * **`BinopTester` and related classes (`Int32BinopTester`, `Float64BinopTester`, etc.):** These classes are clearly designed for testing binary operations. They manage input values, execute the generated code, and compare the result with the expected outcome. The template parameter `use_result_buffer` distinguishes between returning values directly in registers and storing them in memory.

    * **`IntBinopWrapper` and `CompareWrapper`:** These are helper classes to encapsulate different binary operations and comparisons. They provide a way to generate the corresponding Turboshaft IR nodes and evaluate the operation in C++.

    * **`BinopGen` and `Int32BinopInputShapeTester`:** These are designed for more systematic testing of binary operations, exploring various input combinations and ensuring correctness.

4. **Infer Functionality from Usage Patterns:** Notice the pattern in the `RawMachineAssemblerTester`: setting up parameters, emitting operations, then calling `GenerateCode` and `Call`. This suggests a workflow for testing individual code snippets. The `CheckNumber` and `CheckString` methods confirm the intent is to verify the output of these snippets.

5. **Address Specific Questions in the Prompt:**

    * **List the functionality:**  Synthesize the observations from the previous steps into a concise summary of the header's purpose.
    * **`.tq` extension:** Check the file extension. It's `.h`, so it's not Torque.
    * **Relationship to JavaScript:**  The header is part of the *compiler* (Turboshaft). Compilers translate source code (like JavaScript) into machine code. Therefore, this header is indirectly related to JavaScript by helping test the code generation process for JavaScript. Provide a simple JavaScript example whose compiled output could be tested using these tools.
    * **Code logic and assumptions:**  Focus on the `BinopTester` and its related classes. Illustrate how a test case might be structured, providing example inputs and expected outputs for a basic operation like addition.
    * **Common programming errors:**  Consider the context of compiler testing. Common errors would involve incorrect code generation, leading to wrong results. Provide examples related to integer overflow or incorrect type handling that these tests might catch.

6. **Refine and Organize:** Structure the answer logically, starting with a high-level summary and then going into more detail about the individual components. Use clear headings and bullet points for readability.

7. **Review and Verify:** Read through the generated answer to ensure it's accurate, comprehensive, and addresses all aspects of the prompt. Double-check the example code and explanations.

By following these steps, you can systematically analyze a complex piece of code like this header file and understand its purpose and functionality within a larger project like V8. The key is to break it down into smaller, manageable parts and look for patterns and relationships between them.
这个头文件 `v8/test/cctest/compiler/turboshaft-codegen-tester.h` 的主要功能是为 V8 的 **Turboshaft 编译器** 提供一个 **测试框架**，用于生成和测试低级机器代码。它允许开发者编写 C++ 测试用例，这些用例能够构建 Turboshaft 的中间表示（IR），并将其编译成实际的机器码，然后执行并验证结果。

让我们更详细地分解其功能：

**核心功能：**

1. **简化 Turboshaft 代码生成测试:**  该头文件提供了一组工具类，例如 `RawMachineAssemblerTester` 和 `BufferedRawMachineAssemblerTester`， 这些类封装了 Turboshaft 代码生成所需的复杂步骤，例如创建 `Isolate`、`Zone`、`OptimizedCompilationInfo`、`PipelineData` 和 `CallDescriptor` 等。 这使得编写测试用例更加简洁和方便。

2. **构建 Turboshaft IR:**  `RawMachineAssemblerTester` 类继承自 `TSAssembler`，提供了一系列方法（例如 `Parameter`, `Int32Add`, `Load`, `Store`, `Return` 等）来直接构建 Turboshaft 的指令序列。 这些方法对应于 Turboshaft IR 中的各种操作。

3. **生成机器代码:**  通过调用 `GenerateCode()` 或 `GetCode()` 方法，测试框架能够将构建的 Turboshaft IR 转换成可执行的机器代码。  这依赖于 V8 编译管道的 `Pipeline::GenerateTurboshaftCodeForTesting` 函数。

4. **执行生成的代码:**  `RawMachineAssemblerTester` 继承自 `CallHelper`，提供了 `Call()` 方法来执行生成的机器代码。 这允许测试用例运行生成的代码并获取其返回值。

5. **验证结果:**  提供了 `CheckNumber()` 和 `CheckString()` 等方法，用于断言执行生成的代码后得到的结果是否符合预期。

6. **支持不同类型的操作和数据:**  通过模板类和方法重载，该框架支持测试各种数据类型（例如 `int32_t`, `int64_t`, `float`, `double`, Tagged 对象等）和操作（例如算术运算、位运算、比较运算等）。  `BinopTester` 及其子类是专门为测试二元运算设计的。

**关于文件扩展名和 Torque:**

`v8/test/cctest/compiler/turboshaft-codegen-tester.h` 以 `.h` 结尾，这表明它是一个 C++ 头文件，而不是 Torque 源文件。 Torque 源文件通常以 `.tq` 结尾。  因此，这个文件不是 Torque 代码。

**与 JavaScript 功能的关系:**

虽然这个头文件本身是用 C++ 编写的，并且位于 V8 编译器的测试目录下，但它的最终目的是 **测试 V8 如何将 JavaScript 代码编译成高效的机器代码**。  Turboshaft 是 V8 的下一代优化编译器，这个测试框架用于验证 Turboshaft 生成的机器码是否正确地实现了 JavaScript 的语义。

**JavaScript 示例:**

假设我们要测试 Turboshaft 编译器如何处理简单的 JavaScript 加法运算。

```javascript
function add(a, b) {
  return a + b;
}
```

`v8/test/cctest/compiler/turboshaft-codegen-tester.h` 中的测试用例可能会构建 Turboshaft IR 来表示这个 `add` 函数的加法操作，然后生成机器代码并执行，以确保对于不同的输入 `a` 和 `b`，返回的结果是正确的。

**代码逻辑推理和假设输入输出:**

让我们以 `Int32BinopTester` 和 `IntBinopWrapper` 为例，测试一个简单的 32 位整数加法：

**假设输入:**

* `Int32BinopTester` 用于测试两个 `int32_t` 类型的参数的二元运算。
* 使用 `IntBinopWrapper` 创建一个加法操作节点 (`TurboshaftBinop::kWord32Add`).
* 传入的两个参数分别为 `a = 5` 和 `b = 10`。

**代码逻辑:**

1. `RawMachineAssemblerTester` 会创建一个表示函数的 Turboshaft IR 图。
2. 使用 `Parameter()` 方法创建表示输入参数 `a` 和 `b` 的节点。
3. 使用 `IntBinopWrapper` 的 `MakeNode()` 方法创建一个加法操作节点，将 `a` 和 `b` 的参数节点作为输入。
4. 使用 `Return()` 方法将加法操作的结果作为函数的返回值。
5. `Call()` 方法会执行生成的机器代码。

**预期输出:**

由于执行的是 32 位整数加法 `5 + 10`，预期的返回值是 `15`。

**用户常见的编程错误:**

使用这个测试框架可以帮助发现 V8 编译器中的各种错误，其中一些可能与用户常见的编程错误相关，例如：

1. **整数溢出:**  如果 Turboshaft 编译器在处理可能导致整数溢出的 JavaScript 代码时生成了错误的机器码，测试用例可以捕获到这一点。

   ```javascript
   function overflow() {
     return 2147483647 + 1; // 32位有符号整数的最大值加 1
   }
   ```

   测试用例可能会检查生成的代码是否正确处理了溢出，例如，结果是否被正确地截断或转换为浮点数（取决于 JavaScript 的语义）。

2. **类型错误:** JavaScript 是一种动态类型语言，编译器需要处理不同类型的操作。 如果 Turboshaft 在处理类型转换或运算符重载时生成了错误的代码，测试用例可以检测到。

   ```javascript
   function typeError(a) {
     return a + "hello"; // 数字和字符串的相加
   }
   ```

   测试用例可能会验证生成的代码是否正确地将数字转换为字符串并进行拼接。

3. **位运算错误:**  对于位运算，确保生成的机器码执行了正确的位操作非常重要。

   ```javascript
   function bitwiseAnd(a, b) {
     return a & b;
   }
   ```

   测试用例会使用各种输入值来验证按位与运算的结果是否正确。

4. **浮点数精度问题:**  测试框架可以帮助确保 Turboshaft 编译器在处理浮点数运算时不会引入不必要的精度损失或产生错误的舍入结果。

   ```javascript
   function floatAdd(a, b) {
     return 0.1 + 0.2;
   }
   ```

   测试用例会检查结果是否接近预期的浮点数值。

**总结:**

`v8/test/cctest/compiler/turboshaft-codegen-tester.h` 是 V8 中一个关键的测试基础设施，专门用于验证 Turboshaft 编译器的代码生成质量。 它允许开发者以编程方式构建、编译和执行低级代码片段，并断言其行为是否符合预期，从而帮助确保 V8 能够正确高效地执行 JavaScript 代码。

Prompt: 
```
这是目录为v8/test/cctest/compiler/turboshaft-codegen-tester.h的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/turboshaft-codegen-tester.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CCTEST_COMPILER_TURBOSHAFT_CODEGEN_TESTER_H_
#define V8_CCTEST_COMPILER_TURBOSHAFT_CODEGEN_TESTER_H_

#include "src/codegen/assembler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/common/globals.h"
#include "src/compiler/backend/instruction-selector.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/linkage.h"
#include "src/compiler/pipeline-data-inl.h"
#include "src/compiler/pipeline.h"
#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/instruction-selection-phase.h"
#include "src/compiler/turboshaft/load-store-simplification-reducer.h"
#include "src/compiler/turboshaft/phase.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/compiler/zone-stats.h"
#include "src/objects/code-inl.h"
#include "test/cctest/cctest.h"
#include "test/common/call-tester.h"

namespace v8::internal::compiler::turboshaft {

using BaseAssembler = TSAssembler<LoadStoreSimplificationReducer>;

class DataHolder {
 public:
  template <typename... ParamMachTypes>
  DataHolder(Isolate* isolate, Zone* zone, MachineType return_type,
             ParamMachTypes... p)
      : isolate_(isolate),
        graph_zone_(zone),
        info_(zone->New<OptimizedCompilationInfo>(base::ArrayVector("testing"),
                                                  zone, CodeKind::FOR_TESTING)),
        zone_stats_(isolate->allocator()),
        ts_pipeline_data_(&zone_stats_, turboshaft::TurboshaftPipelineKind::kJS,
                          isolate, info_, AssemblerOptions::Default(isolate)),
        descriptor_(Linkage::GetSimplifiedCDescriptor(
            zone, CSignature::New(zone, return_type, p...),
            CallDescriptor::kInitializeRootRegister)) {
    // TODO(dmercadier): remove once turboshaft_instruction_selection is the
    // default. We currently set it manually so that
    // LoadStoreSimplificationReducer triggers lowering of Stores/Loads (and
    // anyways, these tests always go through GenerateTurboshaftCodeForTesting,
    // which uses the Turboshaft instruction selector without even checking
    // v8_flags.turboshaft_instruction_selection).
    v8_flags.turboshaft_instruction_selection = true;
    ts_pipeline_data_.InitializeGraphComponent(nullptr);
  }

  PipelineData& ts_pipeline_data() { return ts_pipeline_data_; }

  Isolate* isolate() { return isolate_; }
  Zone* zone() { return graph_zone_; }
  Graph& graph() { return ts_pipeline_data_.graph(); }
  CallDescriptor* call_descriptor() { return descriptor_; }
  OptimizedCompilationInfo* info() { return info_; }

 private:
  Isolate* isolate_;
  Zone* graph_zone_;
  OptimizedCompilationInfo* info_;
  // zone_stats_ must be destroyed after pipeline_data_, so it's declared
  // before.
  ZoneStats zone_stats_;
  turboshaft::PipelineData ts_pipeline_data_;
  CallDescriptor* descriptor_;
};

template <typename ReturnType>
class RawMachineAssemblerTester : public HandleAndZoneScope,
                                  public CallHelper<ReturnType>,
                                  public DataHolder,
                                  public BaseAssembler {
 public:
  template <typename... ParamMachTypes>
  explicit RawMachineAssemblerTester(ParamMachTypes... p)
      : HandleAndZoneScope(kCompressGraphZone),
        CallHelper<ReturnType>(
            main_isolate(),
            CSignature::New(main_zone(), MachineTypeForC<ReturnType>(), p...)),
        DataHolder(main_isolate(), main_zone(), MachineTypeForC<ReturnType>(),
                   p...),
        BaseAssembler(&DataHolder::ts_pipeline_data(), graph(), graph(),
                      zone()) {
    Init();
  }

  template <typename... ParamMachTypes>
  RawMachineAssemblerTester(CodeKind kind, ParamMachTypes... p)
      : HandleAndZoneScope(kCompressGraphZone),
        CallHelper<ReturnType>(
            main_isolate(),
            CSignature::New(main_zone(), MachineTypeForC<ReturnType>(), p...)),
        DataHolder(main_isolate(), main_zone(), MachineTypeForC<ReturnType>(),
                   p...),
        BaseAssembler(&DataHolder::ts_pipeline_data(), graph(), graph(),
                      zone()),
        kind_(kind) {
    Init();
  }

  ~RawMachineAssemblerTester() override = default;

  void CheckNumber(double expected, Tagged<Object> number) {
    CHECK(Object::SameValue(*this->isolate()->factory()->NewNumber(expected),
                            number));
  }

  void CheckString(const char* expected, Tagged<Object> string) {
    CHECK(Object::SameValue(
        *this->isolate()->factory()->InternalizeUtf8String(expected), string));
  }

  void GenerateCode() { Generate(); }

  Handle<Code> GetCode() {
    Generate();
    return code_.ToHandleChecked();
  }

  using CallHelper<ReturnType>::Call;
  using Assembler::Call;

  // A few Assembler helpers.
  using Assembler::Parameter;
  OpIndex Parameter(int i) {
    return Parameter(i, RegisterRepresentation::FromMachineType(
                            call_descriptor()->GetParameterType(i)));
  }

  OpIndex PointerConstant(void* value) {
    return IntPtrConstant(reinterpret_cast<intptr_t>(value));
  }

  using Assembler::Load;
  OpIndex LoadFromPointer(void* address, MachineType type, int32_t offset = 0) {
    return Load(PointerConstant(address), LoadOp::Kind::RawAligned(),
                MemoryRepresentation::FromMachineType(type), offset);
  }
  OpIndex Load(MachineType type, OpIndex base) {
    MemoryRepresentation mem_rep = MemoryRepresentation::FromMachineType(type);
    return Load(base, LoadOp::Kind::RawAligned(), mem_rep);
  }

  using Assembler::Store;
  void StoreToPointer(void* address, MachineRepresentation rep, OpIndex value) {
    // Otherwise, we can use an offset instead of an Index.
    return Store(PointerConstant(address), value, StoreOp::Kind::RawAligned(),
                 MemoryRepresentation::FromMachineRepresentation(rep),
                 WriteBarrierKind::kNoWriteBarrier);
  }
  void Store(MachineRepresentation rep, OpIndex base, OpIndex value,
             WriteBarrierKind write_barrier) {
    MemoryRepresentation mem_rep =
        MemoryRepresentation::FromMachineRepresentation(rep);
    Store(base, value, StoreOp::Kind::RawAligned(), mem_rep, write_barrier);
  }

  V<Word32> Int32GreaterThan(V<Word32> a, V<Word32> b) {
    return Int32LessThan(b, a);
  }
  V<Word32> Int32GreaterThanOrEqual(V<Word32> a, V<Word32> b) {
    return Int32LessThanOrEqual(b, a);
  }
  V<Word32> Uint32GreaterThan(V<Word32> a, V<Word32> b) {
    return Uint32LessThan(b, a);
  }
  V<Word32> Uint32GreaterThanOrEqual(V<Word32> a, V<Word32> b) {
    return Uint32LessThanOrEqual(b, a);
  }

 protected:
  Address Generate() override {
    if (code_.is_null()) {
      code_ = Pipeline::GenerateTurboshaftCodeForTesting(call_descriptor(),
                                                         &ts_pipeline_data());
    }
    return code_.ToHandleChecked()->instruction_start();
  }

 private:
  void Init() {
    // We bind a block right at the start so that the test can start emitting
    // operations without always needing to bind a block first.
    Block* start_block = NewBlock();
    Bind(start_block);

    // We emit the parameters now so that they appear at the begining of the
    // graph (because the register allocator doesn't like it when Parameters are
    // not in the 1st block). Subsequent calls to `m.Parameter()` will reuse the
    // Parameters created here, thanks to Turboshaft's parameter cache (see
    // TurboshaftAssemblerOpInterface::Parameter).
    for (size_t i = 0; i < call_descriptor()->ParameterCount(); i++) {
      Parameter(static_cast<int>(i));
    }
  }

  CodeKind kind_ = CodeKind::FOR_TESTING;
  MaybeHandle<Code> code_;
};

template <typename ReturnType>
class BufferedRawMachineAssemblerTester
    : public RawMachineAssemblerTester<int32_t> {
 public:
  template <typename... ParamMachTypes>
  explicit BufferedRawMachineAssemblerTester(ParamMachTypes... p)
      : RawMachineAssemblerTester<int32_t>(
            MachineType::Pointer(), ((void)p, MachineType::Pointer())...),
        test_graph_signature_(
            CSignature::New(this->main_zone(), MachineType::Int32(), p...)) {
    static_assert(sizeof...(p) <= arraysize(parameter_nodes_),
                  "increase parameter_nodes_ array");
    std::array<MachineType, sizeof...(p)> p_arr{{p...}};
    for (size_t i = 0; i < p_arr.size(); ++i) {
      parameter_nodes_[i] = Load(
          p_arr[i], RawMachineAssemblerTester::Parameter(static_cast<int>(i)));
    }
    return_param_ = RawMachineAssemblerTester::Parameter(sizeof...(p));
  }

  Address Generate() override { return RawMachineAssemblerTester::Generate(); }

  // The BufferedRawMachineAssemblerTester does not pass parameters directly
  // to the constructed IR graph. Instead it passes a pointer to the parameter
  // to the IR graph, and adds Load nodes to the IR graph to load the
  // parameters from memory. Thereby it is possible to pass 64 bit parameters
  // to the IR graph.
  OpIndex Parameter(size_t index) {
    CHECK_GT(arraysize(parameter_nodes_), index);
    return parameter_nodes_[index];
  }

  // The BufferedRawMachineAssemblerTester adds a Store node to the IR graph
  // to store the graph's return value in memory. The memory address for the
  // Store node is provided as a parameter. By storing the return value in
  // memory it is possible to return 64 bit values.
  void Return(OpIndex input) {
    if (COMPRESS_POINTERS_BOOL && MachineTypeForC<ReturnType>().IsTagged()) {
      // Since we are returning values via storing to off-heap location
      // generate full-word store here.
      Store(MachineType::PointerRepresentation(), return_param_,
            BitcastTaggedToWordPtr(input), kNoWriteBarrier);

    } else {
      Store(MachineTypeForC<ReturnType>().representation(), return_param_,
            input, kNoWriteBarrier);
    }
    BaseAssembler::Return(Word32Constant(1234));
  }

  template <typename... Params>
  ReturnType Call(Params... p) {
    uintptr_t zap_data[] = {kZapValue, kZapValue};
    ReturnType return_value;
    static_assert(sizeof(return_value) <= sizeof(zap_data));
    MemCopy(&return_value, &zap_data, sizeof(return_value));
    CSignature::VerifyParams<Params...>(test_graph_signature_);
    CallHelper<int32_t>::Call(reinterpret_cast<void*>(&p)...,
                              reinterpret_cast<void*>(&return_value));
    return return_value;
  }

 private:
  CSignature* test_graph_signature_;
  OpIndex parameter_nodes_[4];
  OpIndex return_param_;
};

template <>
class BufferedRawMachineAssemblerTester<void>
    : public RawMachineAssemblerTester<void> {
 public:
  template <typename... ParamMachTypes>
  explicit BufferedRawMachineAssemblerTester(ParamMachTypes... p)
      : RawMachineAssemblerTester<void>(((void)p, MachineType::Pointer())...),
        test_graph_signature_(
            CSignature::New(RawMachineAssemblerTester<void>::main_zone(),
                            MachineType::None(), p...)) {
    static_assert(sizeof...(p) <= arraysize(parameter_nodes_),
                  "increase parameter_nodes_ array");
    std::array<MachineType, sizeof...(p)> p_arr{{p...}};
    for (size_t i = 0; i < p_arr.size(); ++i) {
      parameter_nodes_[i] = Load(p_arr[i], Parameter(i));
    }
  }

  Address Generate() override { return RawMachineAssemblerTester::Generate(); }

  // The BufferedRawMachineAssemblerTester does not pass parameters directly
  // to the constructed IR graph. Instead it passes a pointer to the parameter
  // to the IR graph, and adds Load nodes to the IR graph to load the
  // parameters from memory. Thereby it is possible to pass 64 bit parameters
  // to the IR graph.
  OpIndex Parameter(size_t index) {
    CHECK_GT(arraysize(parameter_nodes_), index);
    return parameter_nodes_[index];
  }

  template <typename... Params>
  void Call(Params... p) {
    CSignature::VerifyParams<Params...>(test_graph_signature_);
    CallHelper<void>::Call(reinterpret_cast<void*>(&p)...);
  }

 private:
  CSignature* test_graph_signature_;
  OpIndex parameter_nodes_[4];
};

static const bool USE_RESULT_BUFFER = true;
static const bool USE_RETURN_REGISTER = false;
static const int32_t CHECK_VALUE = 0x99BEEDCE;

// TODO(titzer): use the C-style calling convention, or any register-based
// calling convention for binop tests.
template <typename CType, bool use_result_buffer>
class BinopTester {
 public:
  explicit BinopTester(RawMachineAssemblerTester<int32_t>* tester,
                       MachineType type)
      : T(tester),
        param0(T->LoadFromPointer(&p0, type)),
        param1(T->LoadFromPointer(&p1, type)),
        type(type),
        p0(static_cast<CType>(0)),
        p1(static_cast<CType>(0)),
        result(static_cast<CType>(0)) {}

  RawMachineAssemblerTester<int32_t>* T;
  OpIndex param0;
  OpIndex param1;

  CType call(CType a0, CType a1) {
    p0 = a0;
    p1 = a1;
    if (use_result_buffer) {
      CHECK_EQ(CHECK_VALUE, T->Call());
      return result;
    } else {
      return static_cast<CType>(T->Call());
    }
  }

  void AddReturn(OpIndex val) {
    if (use_result_buffer) {
      T->Store(type.representation(), T->PointerConstant(&result),
               T->Word32Constant(0), val, kNoWriteBarrier);
      T->Return(T->Word32Constant(CHECK_VALUE));
    } else {
      T->Return(val);
    }
  }

  template <typename Ci, typename Cj, typename Fn>
  void Run(const Ci& ci, const Cj& cj, const Fn& fn) {
    typename Ci::const_iterator i;
    typename Cj::const_iterator j;
    for (i = ci.begin(); i != ci.end(); ++i) {
      for (j = cj.begin(); j != cj.end(); ++j) {
        CHECK_EQ(fn(*i, *j), this->call(*i, *j));
      }
    }
  }

 protected:
  MachineType type;
  CType p0;
  CType p1;
  CType result;
};

// A helper class for testing code sequences that take two int parameters and
// return an int value.
class Int32BinopTester : public BinopTester<int32_t, USE_RETURN_REGISTER> {
 public:
  explicit Int32BinopTester(RawMachineAssemblerTester<int32_t>* tester)
      : BinopTester<int32_t, USE_RETURN_REGISTER>(tester,
                                                  MachineType::Int32()) {}
};

// A helper class for testing code sequences that take two int parameters and
// return an int value.
class Int64BinopTester : public BinopTester<int64_t, USE_RETURN_REGISTER> {
 public:
  explicit Int64BinopTester(RawMachineAssemblerTester<int32_t>* tester)
      : BinopTester<int64_t, USE_RETURN_REGISTER>(tester,
                                                  MachineType::Int64()) {}
};

// A helper class for testing code sequences that take two uint parameters and
// return an uint value.
class Uint32BinopTester : public BinopTester<uint32_t, USE_RETURN_REGISTER> {
 public:
  explicit Uint32BinopTester(RawMachineAssemblerTester<int32_t>* tester)
      : BinopTester<uint32_t, USE_RETURN_REGISTER>(tester,
                                                   MachineType::Uint32()) {}

  uint32_t call(uint32_t a0, uint32_t a1) {
    p0 = a0;
    p1 = a1;
    return static_cast<uint32_t>(T->Call());
  }
};

// A helper class for testing code sequences that take two float parameters and
// return a float value.
class Float32BinopTester : public BinopTester<float, USE_RESULT_BUFFER> {
 public:
  explicit Float32BinopTester(RawMachineAssemblerTester<int32_t>* tester)
      : BinopTester<float, USE_RESULT_BUFFER>(tester, MachineType::Float32()) {}
};

// A helper class for testing code sequences that take two double parameters and
// return a double value.
class Float64BinopTester : public BinopTester<double, USE_RESULT_BUFFER> {
 public:
  explicit Float64BinopTester(RawMachineAssemblerTester<int32_t>* tester)
      : BinopTester<double, USE_RESULT_BUFFER>(tester, MachineType::Float64()) {
  }
};

// A helper class for testing code sequences that take two pointer parameters
// and return a pointer value.
// TODO(titzer): pick word size of pointers based on V8_TARGET.
template <typename Type>
class PointerBinopTester : public BinopTester<Type, USE_RETURN_REGISTER> {
 public:
  explicit PointerBinopTester(RawMachineAssemblerTester<int32_t>* tester)
      : BinopTester<Type, USE_RETURN_REGISTER>(tester, MachineType::Pointer()) {
  }
};

// A helper class for testing code sequences that take two tagged parameters and
// return a tagged value.
template <typename Type>
class TaggedBinopTester : public BinopTester<Type, USE_RETURN_REGISTER> {
 public:
  explicit TaggedBinopTester(RawMachineAssemblerTester<int32_t>* tester)
      : BinopTester<Type, USE_RETURN_REGISTER>(tester,
                                               MachineType::AnyTagged()) {}
};

#define BINOP_LIST(V) \
  V(Word32Add)        \
  V(Word32Sub)        \
  V(Word32Mul)        \
  V(Word32BitwiseAnd) \
  V(Word32BitwiseOr)  \
  V(Word32BitwiseXor) \
  V(Word64Add)        \
  V(Word64Sub)        \
  V(Word64Mul)        \
  V(Word64BitwiseAnd) \
  V(Word64BitwiseOr)  \
  V(Word64BitwiseXor)

enum class TurboshaftBinop {
#define DEF(kind) k##kind,
  BINOP_LIST(DEF)
#undef DEF
};

// A helper class for integer binary operations. Wraps a machine opcode and
// provides evaluation routines and the operators.
template <typename T>
class IntBinopWrapper {
 public:
  explicit IntBinopWrapper(TurboshaftBinop op) : op(op) {}

  OpIndex MakeNode(BaseAssembler& m, OpIndex a, OpIndex b) {
    return MakeNode(&m, a, b);
  }

  OpIndex MakeNode(BaseAssembler* m, OpIndex a, OpIndex b) {
    switch (op) {
#define CASE(kind)               \
  case TurboshaftBinop::k##kind: \
    return m->kind(a, b);
      BINOP_LIST(CASE)
#undef CASE
    }
  }

  T eval(T a, T b) const {
    switch (op) {
      case TurboshaftBinop::kWord32Add:
      case TurboshaftBinop::kWord64Add:
        return a + b;
      case TurboshaftBinop::kWord32Sub:
      case TurboshaftBinop::kWord64Sub:
        return a - b;
      case TurboshaftBinop::kWord32Mul:
      case TurboshaftBinop::kWord64Mul:
        return a * b;
      case TurboshaftBinop::kWord32BitwiseAnd:
      case TurboshaftBinop::kWord64BitwiseAnd:
        return a & b;
      case TurboshaftBinop::kWord32BitwiseOr:
      case TurboshaftBinop::kWord64BitwiseOr:
        return a | b;
      case TurboshaftBinop::kWord32BitwiseXor:
      case TurboshaftBinop::kWord64BitwiseXor:
        return a ^ b;
    }
  }
  TurboshaftBinop op;
};

#define COMPARE_LIST(V)    \
  V(Word32Equal)           \
  V(Int32LessThan)         \
  V(Int32LessThanOrEqual)  \
  V(Uint32LessThan)        \
  V(Uint32LessThanOrEqual) \
  V(Word64Equal)           \
  V(Int64LessThan)         \
  V(Int64LessThanOrEqual)  \
  V(Uint64LessThan)        \
  V(Uint64LessThanOrEqual) \
  V(Float64Equal)          \
  V(Float64LessThan)       \
  V(Float64LessThanOrEqual)

enum class TurboshaftComparison {
#define DEF(kind) k##kind,
  COMPARE_LIST(DEF)
#undef DEF
};

// A helper class for testing compares. Wraps a machine opcode and provides
// evaluation routines and the operators.
class CompareWrapper {
 public:
  explicit CompareWrapper(TurboshaftComparison op) : op(op) {}

  V<Word32> MakeNode(BaseAssembler& m, OpIndex a, OpIndex b) {
    return MakeNode(&m, a, b);
  }
  V<Word32> MakeNode(BaseAssembler* m, OpIndex a, OpIndex b) {
    switch (op) {
#define CASE(kind)                    \
  case TurboshaftComparison::k##kind: \
    return m->kind(a, b);
      COMPARE_LIST(CASE)
#undef CASE
    }
  }

  bool Int32Compare(int32_t a, int32_t b) const {
    switch (op) {
      case TurboshaftComparison::kWord32Equal:
        return a == b;
      case TurboshaftComparison::kInt32LessThan:
        return a < b;
      case TurboshaftComparison::kInt32LessThanOrEqual:
        return a <= b;
      case TurboshaftComparison::kUint32LessThan:
        return static_cast<uint32_t>(a) < static_cast<uint32_t>(b);
      case TurboshaftComparison::kUint32LessThanOrEqual:
        return static_cast<uint32_t>(a) <= static_cast<uint32_t>(b);
      default:
        UNREACHABLE();
    }
  }

  bool Int64Compare(int64_t a, int64_t b) const {
    switch (op) {
      case TurboshaftComparison::kWord64Equal:
        return a == b;
      case TurboshaftComparison::kInt64LessThan:
        return a < b;
      case TurboshaftComparison::kInt64LessThanOrEqual:
        return a <= b;
      case TurboshaftComparison::kUint64LessThan:
        return static_cast<uint64_t>(a) < static_cast<uint64_t>(b);
      case TurboshaftComparison::kUint64LessThanOrEqual:
        return static_cast<uint64_t>(a) <= static_cast<uint64_t>(b);
      default:
        UNREACHABLE();
    }
  }

  bool Float64Compare(double a, double b) const {
    switch (op) {
      case TurboshaftComparison::kFloat64Equal:
        return a == b;
      case TurboshaftComparison::kFloat64LessThan:
        return a < b;
      case TurboshaftComparison::kFloat64LessThanOrEqual:
        return a <= b;
      default:
        UNREACHABLE();
    }
  }

  TurboshaftComparison op;
};

// A small closure class to generate code for a function of two inputs that
// produces a single output so that it can be used in many different contexts.
// The {expected()} method should compute the expected output for a given
// pair of inputs.
template <typename T>
class BinopGen {
 public:
  virtual void gen(RawMachineAssemblerTester<int32_t>* m, OpIndex a,
                   OpIndex b) = 0;
  virtual T expected(T a, T b) = 0;
  virtual ~BinopGen() = default;
};

// A helper class to generate various combination of input shape combinations
// and run the generated code to ensure it produces the correct results.
class Int32BinopInputShapeTester {
 public:
  explicit Int32BinopInputShapeTester(BinopGen<int32_t>* g)
      : gen(g), input_a(0), input_b(0) {}

  void TestAllInputShapes();

 private:
  BinopGen<int32_t>* gen;
  int32_t input_a;
  int32_t input_b;

  void Run(RawMachineAssemblerTester<int32_t>* m);
  void RunLeft(RawMachineAssemblerTester<int32_t>* m);
  void RunRight(RawMachineAssemblerTester<int32_t>* m);
};

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_CCTEST_COMPILER_TURBOSHAFT_CODEGEN_TESTER_H_

"""

```