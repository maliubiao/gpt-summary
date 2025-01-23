Response:
Let's break down the thought process for analyzing the `codegen-tester.h` file.

1. **Understand the Goal:** The primary request is to understand the *functionality* of this header file within the V8 project. The prompt also gives hints about Torque files and JavaScript relevance, which might or might not be applicable.

2. **Initial Scan and Key Includes:** Quickly read through the code, paying attention to `#include` statements and namespace declarations.

   *  `#include "src/codegen/assembler.h"` and `#include "src/compiler/raw-machine-assembler.h"`: Immediately suggests this file is related to code generation at a low level, likely dealing with machine instructions or an abstraction over them. The "assembler" keyword is a strong indicator.
   *  `#include "src/compiler/backend/instruction-selector.h"` and `#include "src/compiler/pipeline.h"`: Confirms involvement in the compilation pipeline, specifically the backend stages where higher-level code is translated to machine instructions.
   *  `#include "src/objects/code-inl.h"`: Points to the representation of compiled code within V8.
   *  `#include "test/cctest/cctest.h"`:  Crucially reveals this is part of the *testing* infrastructure (`cctest`). This means its purpose is to facilitate testing of code generation components.
   *  `#include "test/common/call-tester.h"`: Another testing-related include, suggesting the ability to call generated code.

3. **Identify Core Classes:** Look for the main class definitions.

   *  `RawMachineAssemblerTester`: This is the central class. Its inheritance (`HandleAndZoneScope`, `CallHelper`, `RawMachineAssembler`) tells us a lot:
      * `HandleAndZoneScope`: Manages memory allocation within a specific scope, common in V8.
      * `CallHelper`: Provides mechanisms to call generated code.
      * `RawMachineAssembler`:  Confirms the low-level code generation aspect.
   *  `BufferedRawMachineAssemblerTester`:  Inherits from the previous class and appears to add buffering or indirection for parameters and return values. This is likely to handle cases where direct parameter passing is insufficient (e.g., for larger data types).
   *  `BinopTester`, `Int32BinopTester`, etc.:  These are clearly helper classes designed for testing binary operations. The template parameters and naming conventions (`Int32`, `Float64`) indicate they are specialized for different data types.
   *  `IntBinopWrapper`, `CompareWrapper`: These seem to encapsulate specific machine instructions (opcodes) and provide a way to execute and verify them.
   *  `BinopGen`, `Int32BinopInputShapeTester`:  More sophisticated testing utilities for generating different input combinations and verifying the correctness of binary operations.

4. **Analyze `RawMachineAssemblerTester`:**

   *  The constructor takes `ParamMachTypes`, hinting at the ability to create test functions with different parameter types.
   *  `CheckNumber`, `CheckString`:  Verification functions to compare the results of generated code against expected values.
   *  `GenerateCode`, `GetCode`: Methods to trigger code generation and retrieve the resulting `Code` object.
   *  The `Generate()` method itself uses `Pipeline::GenerateCodeForTesting`, strongly reinforcing the testing context.

5. **Analyze `BufferedRawMachineAssemblerTester`:**

   *  The constructor's parameter handling with `Load` nodes clarifies its purpose: to handle parameter passing indirectly, potentially for wider data types.
   *  The `Return` method stores the result in memory, further supporting the idea of handling return values that might not fit in a register.
   *  The `Call` method shows how to execute the generated code with specific input parameters.

6. **Analyze the `BinopTester` Hierarchy:**

   *  The base `BinopTester` handles the general setup for binary operation testing.
   *  The derived classes (`Int32BinopTester`, etc.) specialize it for specific data types.
   *  The `call` and `AddReturn` methods manage the execution and result handling.
   *  The `Run` method iterates through test value combinations.

7. **Analyze `IntBinopWrapper` and `CompareWrapper`:**

   *  These classes map symbolic opcodes (like `IrOpcode::kInt32Add`) to actual machine instructions.
   *  They provide `eval` methods (or similar logic in `CompareWrapper`) to calculate the expected result of the operation.

8. **Address the Specific Questions in the Prompt:**

   * **Functionality:**  Summarize the findings from the class analysis. Emphasize the testing purpose, the ability to generate and execute low-level code, and the helper classes for specific scenarios (binary operations, different data types).
   * **Torque:** Look for `.tq` extensions (none present). State that it's not a Torque file.
   * **JavaScript Relation:** Consider how this relates to JavaScript execution. Explain that it's indirectly related by testing the compiler components that translate JavaScript to machine code. Provide a simple JavaScript example and explain how the concepts in the header file are relevant *during compilation* of that code.
   * **Code Logic Reasoning (Assumptions and Outputs):**  Pick a simple example, like `Int32BinopTester` and an addition operation. Provide concrete input values and the expected output.
   * **Common Programming Errors:**  Think about what could go wrong when writing low-level code or when using these testers. Examples include incorrect data types, register mismatches (though less direct here since it's a tester), and memory errors (more relevant in raw assembler but can be conceptualized).

9. **Structure and Refine:** Organize the information logically with clear headings. Ensure the explanation is easy to understand, even for someone not intimately familiar with the V8 codebase. Use code snippets from the header file to illustrate points.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the `RawMachineAssembler` itself. Recognizing the testing context (`cctest`) is crucial.
* I needed to be careful not to overstate the direct connection to JavaScript. The file is about *testing the compiler*, not directly about JavaScript execution.
* When explaining the "code logic reasoning," it's important to choose a simple and illustrative example. Overly complex scenarios can be confusing.
*  I needed to explicitly address each point raised in the initial prompt.

By following this structured approach, breaking down the code into manageable parts, and considering the specific questions, I can arrive at a comprehensive and accurate understanding of the `codegen-tester.h` file.
This header file, `v8/test/cctest/compiler/codegen-tester.h`, provides a set of C++ template classes and utilities designed for **testing the code generation phase of the V8 JavaScript engine's compiler**. It allows developers to write focused tests that generate and execute small snippets of machine code, verifying the correctness of the compiler's backend.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Raw Machine Code Generation:** The central class, `RawMachineAssemblerTester`, inherits from `RawMachineAssembler`. This allows tests to construct a directed acyclic graph (DAG) representing low-level machine operations. It provides an interface to build these graphs using methods like `AddNode`, `Parameter`, `Return`, etc., mimicking the actions of a machine code assembler.

2. **Code Compilation and Execution:**  The `GenerateCode()` or `GetCode()` methods trigger the compilation pipeline for the constructed graph. This takes the low-level representation and generates actual executable machine code. The `CallHelper` base class provides the machinery to execute this generated code within the testing environment.

3. **Parameter Passing and Result Handling:** The testers allow defining the signature of the generated code (parameter types and return type). They handle passing arguments to the generated code and retrieving the returned value. The `BufferedRawMachineAssemblerTester` provides a mechanism for passing and returning larger values (like 64-bit integers or doubles) by passing pointers to memory locations.

4. **Verification:**  The `CheckNumber` and `CheckString` methods provide simple ways to assert that the generated code produces the expected results.

5. **Testing Binary Operations:**  The `BinopTester` and its specialized subclasses (`Int32BinopTester`, `Float64BinopTester`, etc.) offer a convenient framework for testing binary operations. They automate the process of setting up test cases with different input values and verifying the output.

6. **Abstraction over Machine Instructions:** Classes like `IntBinopWrapper` and `CompareWrapper` encapsulate specific machine opcodes. This allows tests to be written in terms of logical operations (e.g., addition, subtraction, comparison) rather than directly manipulating machine instructions.

**Is it a Torque file?**

No, `v8/test/cctest/compiler/codegen-tester.h` does **not** end with `.tq`. Therefore, it is **not** a V8 Torque source code file. Torque files are typically used to define built-in functions and runtime stubs in a higher-level language that is then compiled to C++.

**Relationship with JavaScript:**

While this header file doesn't directly involve JavaScript syntax, it is **fundamentally related to JavaScript functionality**. The code generated and tested using these classes is the underlying machine code that executes JavaScript code.

**Example:** Imagine a simple JavaScript addition:

```javascript
function add(a, b) {
  return a + b;
}
```

The V8 compiler will eventually translate this JavaScript function into a sequence of machine instructions. The `codegen-tester.h` framework allows developers to write tests that specifically target the code generation for this kind of addition.

**JavaScript Example Connection (Conceptual):**

A test using `codegen-tester.h` might look something like this (simplified pseudo-code):

```c++
TEST(Int32Addition) {
  RawMachineAssemblerTester<int32_t> tester; // Create a tester for a function returning an int32_t
  Node* param0 = tester.Parameter(0);
  Node* param1 = tester.Parameter(1);
  Node* sum = tester.Int32Add(param0, param1); // Generate an Int32 addition instruction
  tester.Return(sum); // Return the result

  // Execute the generated code with inputs 5 and 10
  int32_t result = tester.Call<int32_t>(5, 10);
  ASSERT_EQ(15, result); // Verify the result
}
```

This C++ test, using the classes from `codegen-tester.h`, directly tests the machine code generated for the JavaScript `a + b` operation.

**Code Logic Reasoning (Assumption and Output):**

Let's consider the `Int32BinopTester`.

**Assumption:** We are testing the `Int32Add` operation.

**Input:**  Let's assume we set `p0` (the first parameter) to `5` and `p1` (the second parameter) to `10`.

**Code Logic within the Tester (Simplified):**

The `Int32BinopTester` would internally:

1. Load the values from the memory locations pointed to by `&p0` and `&p1`.
2. Generate a machine instruction for `Int32Add` using these loaded values as operands.
3. Execute the generated code.
4. Return the result of the addition.

**Output:** The `call` method of `Int32BinopTester` would return `15`.

**User-Specific Programming Errors:**

While users don't directly write code in `codegen-tester.h`, using it effectively requires understanding low-level concepts. Common errors when writing tests using this framework include:

1. **Incorrect Machine Types:**  Specifying the wrong `MachineType` for parameters or return values can lead to misinterpretations of data and incorrect code generation. For example, treating a 64-bit integer as a 32-bit integer.

   ```c++
   // Error: Assuming a 64-bit value fits in an Int32
   RawMachineAssemblerTester<int32_t> tester;
   int64_t large_value = 0x1234567890ABCDEF;
   // ... pass large_value to the generated code ...
   ```

2. **Mismatched Parameter Counts/Types in `Call`:**  The `Call` method needs to be invoked with arguments that match the signature defined in the tester. Providing the wrong number or type of arguments will lead to errors.

   ```c++
   RawMachineAssemblerTester<int32_t, int32_t> tester; // Function takes two int32_t
   // ... generate code that uses two parameters ...

   // Error: Providing only one argument
   tester.Call<int32_t>(5);
   ```

3. **Incorrectly Handling Return Values (especially for `BufferedRawMachineAssemblerTester`):**  When using `BufferedRawMachineAssemblerTester` for larger return values, forgetting to retrieve the value from the memory location where it was stored will result in incorrect test results.

4. **Logical Errors in Graph Construction:**  Building the low-level graph incorrectly (e.g., using the wrong opcode, connecting nodes in the wrong order) will lead to the generation of incorrect machine code.

5. **Forgetting to `Return`:**  Every generated code snippet needs a `Return` node to specify the value to be returned. Omitting this will likely lead to undefined behavior.

In summary, `v8/test/cctest/compiler/codegen-tester.h` is a crucial part of V8's testing infrastructure, providing tools to rigorously verify the correctness of the code generation process, which is essential for ensuring the performance and reliability of JavaScript execution.

### 提示词
```
这是目录为v8/test/cctest/compiler/codegen-tester.h的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/codegen-tester.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CCTEST_COMPILER_CODEGEN_TESTER_H_
#define V8_CCTEST_COMPILER_CODEGEN_TESTER_H_

#include "src/codegen/assembler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/compiler/backend/instruction-selector.h"
#include "src/compiler/pipeline.h"
#include "src/compiler/raw-machine-assembler.h"
#include "src/objects/code-inl.h"
#include "test/cctest/cctest.h"
#include "test/common/call-tester.h"

namespace v8 {
namespace internal {
namespace compiler {

template <typename ReturnType>
class RawMachineAssemblerTester : public HandleAndZoneScope,
                                  public CallHelper<ReturnType>,
                                  public RawMachineAssembler {
 public:
  template <typename... ParamMachTypes>
  explicit RawMachineAssemblerTester(ParamMachTypes... p)
      : HandleAndZoneScope(kCompressGraphZone),
        CallHelper<ReturnType>(
            main_isolate(),
            CSignature::New(main_zone(), MachineTypeForC<ReturnType>(), p...)),
        RawMachineAssembler(
            main_isolate(), main_zone()->template New<Graph>(main_zone()),
            Linkage::GetSimplifiedCDescriptor(
                main_zone(),
                CSignature::New(main_zone(), MachineTypeForC<ReturnType>(),
                                p...),
                CallDescriptor::kInitializeRootRegister),
            MachineType::PointerRepresentation(),
            InstructionSelector::SupportedMachineOperatorFlags(),
            InstructionSelector::AlignmentRequirements()) {}

  template <typename... ParamMachTypes>
  RawMachineAssemblerTester(CodeKind kind, ParamMachTypes... p)
      : HandleAndZoneScope(kCompressGraphZone),
        CallHelper<ReturnType>(
            main_isolate(),
            CSignature::New(main_zone(), MachineTypeForC<ReturnType>(), p...)),
        RawMachineAssembler(
            main_isolate(), main_zone()->template New<Graph>(main_zone()),
            Linkage::GetSimplifiedCDescriptor(
                main_zone(),
                CSignature::New(main_zone(), MachineTypeForC<ReturnType>(),
                                p...),
                CallDescriptor::kInitializeRootRegister),
            MachineType::PointerRepresentation(),
            InstructionSelector::SupportedMachineOperatorFlags(),
            InstructionSelector::AlignmentRequirements()),
        kind_(kind) {}

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

 protected:
  Address Generate() override {
    if (code_.is_null()) {
      Schedule* schedule = ExportForTest();
      OptimizedCompilationInfo info(base::ArrayVector("testing"), main_zone(),
                                    kind_);
      code_ = Pipeline::GenerateCodeForTesting(
          &info, main_isolate(), call_descriptor(), graph(),
          AssemblerOptions::Default(main_isolate()), schedule);
    }
    return code_.ToHandleChecked()->instruction_start();
  }

 private:
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
            CSignature::New(this->main_zone(), MachineType::Int32(), p...)),
        return_parameter_index_(sizeof...(p)) {
    static_assert(sizeof...(p) <= arraysize(parameter_nodes_),
                  "increase parameter_nodes_ array");
    std::array<MachineType, sizeof...(p)> p_arr{{p...}};
    for (size_t i = 0; i < p_arr.size(); ++i) {
      parameter_nodes_[i] = Load(p_arr[i], RawMachineAssembler::Parameter(i));
    }
  }

  Address Generate() override { return RawMachineAssemblerTester::Generate(); }

  // The BufferedRawMachineAssemblerTester does not pass parameters directly
  // to the constructed IR graph. Instead it passes a pointer to the parameter
  // to the IR graph, and adds Load nodes to the IR graph to load the
  // parameters from memory. Thereby it is possible to pass 64 bit parameters
  // to the IR graph.
  Node* Parameter(size_t index) {
    CHECK_GT(arraysize(parameter_nodes_), index);
    return parameter_nodes_[index];
  }

  // The BufferedRawMachineAssemblerTester adds a Store node to the IR graph
  // to store the graph's return value in memory. The memory address for the
  // Store node is provided as a parameter. By storing the return value in
  // memory it is possible to return 64 bit values.
  void Return(Node* input) {
    if (COMPRESS_POINTERS_BOOL && MachineTypeForC<ReturnType>().IsTagged()) {
      // Since we are returning values via storing to off-heap location
      // generate full-word store here.
      Store(MachineType::PointerRepresentation(),
            RawMachineAssembler::Parameter(return_parameter_index_),
            BitcastTaggedToWord(input), kNoWriteBarrier);

    } else {
      Store(MachineTypeForC<ReturnType>().representation(),
            RawMachineAssembler::Parameter(return_parameter_index_), input,
            kNoWriteBarrier);
    }
    RawMachineAssembler::Return(Int32Constant(1234));
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
  Node* parameter_nodes_[4];
  uint32_t return_parameter_index_;
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
      parameter_nodes_[i] = Load(p_arr[i], RawMachineAssembler::Parameter(i));
    }
  }

  Address Generate() override { return RawMachineAssemblerTester::Generate(); }

  // The BufferedRawMachineAssemblerTester does not pass parameters directly
  // to the constructed IR graph. Instead it passes a pointer to the parameter
  // to the IR graph, and adds Load nodes to the IR graph to load the
  // parameters from memory. Thereby it is possible to pass 64 bit parameters
  // to the IR graph.
  Node* Parameter(size_t index) {
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
  Node* parameter_nodes_[4];
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
  Node* param0;
  Node* param1;

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

  void AddReturn(Node* val) {
    if (use_result_buffer) {
      T->Store(type.representation(), T->PointerConstant(&result),
               T->Int32Constant(0), val, kNoWriteBarrier);
      T->Return(T->Int32Constant(CHECK_VALUE));
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

// A helper class for integer binary operations. Wraps a machine opcode and
// provides evaluation routines and the operators.
template <typename T>
class IntBinopWrapper {
 public:
  explicit IntBinopWrapper(IrOpcode::Value op) : opcode(op) {}

  const Operator* op(MachineOperatorBuilder* machine) const {
    switch (opcode) {
      case IrOpcode::kInt32Add:
        return machine->Int32Add();
      case IrOpcode::kInt32Sub:
        return machine->Int32Sub();
      case IrOpcode::kInt32Mul:
        return machine->Int32Mul();
      case IrOpcode::kWord32And:
        return machine->Word32And();
      case IrOpcode::kWord32Or:
        return machine->Word32Or();
      case IrOpcode::kWord32Xor:
        return machine->Word32Xor();
      case IrOpcode::kInt64Add:
        return machine->Int64Add();
      case IrOpcode::kInt64Sub:
        return machine->Int64Sub();
      case IrOpcode::kInt64Mul:
        return machine->Int64Mul();
      case IrOpcode::kWord64And:
        return machine->Word64And();
      case IrOpcode::kWord64Or:
        return machine->Word64Or();
      case IrOpcode::kWord64Xor:
        return machine->Word64Xor();
      default:
        UNREACHABLE();
    }
  }

  T eval(T a, T b) const {
    switch (opcode) {
      case IrOpcode::kInt32Add:
      case IrOpcode::kInt64Add:
        return a + b;
      case IrOpcode::kInt32Sub:
      case IrOpcode::kInt64Sub:
        return a - b;
      case IrOpcode::kInt32Mul:
      case IrOpcode::kInt64Mul:
        return a * b;
      case IrOpcode::kWord32And:
      case IrOpcode::kWord64And:
        return a & b;
      case IrOpcode::kWord32Or:
      case IrOpcode::kWord64Or:
        return a | b;
      case IrOpcode::kWord32Xor:
      case IrOpcode::kWord64Xor:
        return a ^ b;
      default:
        UNREACHABLE();
    }
  }
  IrOpcode::Value opcode;
};

// A helper class for testing compares. Wraps a machine opcode and provides
// evaluation routines and the operators.
class CompareWrapper {
 public:
  explicit CompareWrapper(IrOpcode::Value op) : opcode(op) {}

  Node* MakeNode(RawMachineAssemblerTester<int32_t>* m, Node* a,
                 Node* b) const {
    return m->AddNode(op(m->machine()), a, b);
  }

  const Operator* op(MachineOperatorBuilder* machine) const {
    switch (opcode) {
      case IrOpcode::kWord32Equal:
        return machine->Word32Equal();
      case IrOpcode::kInt32LessThan:
        return machine->Int32LessThan();
      case IrOpcode::kInt32LessThanOrEqual:
        return machine->Int32LessThanOrEqual();
      case IrOpcode::kUint32LessThan:
        return machine->Uint32LessThan();
      case IrOpcode::kUint32LessThanOrEqual:
        return machine->Uint32LessThanOrEqual();
      case IrOpcode::kWord64Equal:
        return machine->Word64Equal();
      case IrOpcode::kInt64LessThan:
        return machine->Int64LessThan();
      case IrOpcode::kInt64LessThanOrEqual:
        return machine->Int64LessThanOrEqual();
      case IrOpcode::kUint64LessThan:
        return machine->Uint64LessThan();
      case IrOpcode::kUint64LessThanOrEqual:
        return machine->Uint64LessThanOrEqual();
      case IrOpcode::kFloat64Equal:
        return machine->Float64Equal();
      case IrOpcode::kFloat64LessThan:
        return machine->Float64LessThan();
      case IrOpcode::kFloat64LessThanOrEqual:
        return machine->Float64LessThanOrEqual();
      default:
        UNREACHABLE();
    }
  }

  bool Int32Compare(int32_t a, int32_t b) const {
    switch (opcode) {
      case IrOpcode::kWord32Equal:
        return a == b;
      case IrOpcode::kInt32LessThan:
        return a < b;
      case IrOpcode::kInt32LessThanOrEqual:
        return a <= b;
      case IrOpcode::kUint32LessThan:
        return static_cast<uint32_t>(a) < static_cast<uint32_t>(b);
      case IrOpcode::kUint32LessThanOrEqual:
        return static_cast<uint32_t>(a) <= static_cast<uint32_t>(b);
      default:
        UNREACHABLE();
    }
  }

  bool Int64Compare(int64_t a, int64_t b) const {
    switch (opcode) {
      case IrOpcode::kWord64Equal:
        return a == b;
      case IrOpcode::kInt64LessThan:
        return a < b;
      case IrOpcode::kInt64LessThanOrEqual:
        return a <= b;
      case IrOpcode::kUint64LessThan:
        return static_cast<uint64_t>(a) < static_cast<uint64_t>(b);
      case IrOpcode::kUint64LessThanOrEqual:
        return static_cast<uint64_t>(a) <= static_cast<uint64_t>(b);
      default:
        UNREACHABLE();
    }
  }

  bool Float64Compare(double a, double b) const {
    switch (opcode) {
      case IrOpcode::kFloat64Equal:
        return a == b;
      case IrOpcode::kFloat64LessThan:
        return a < b;
      case IrOpcode::kFloat64LessThanOrEqual:
        return a <= b;
      default:
        UNREACHABLE();
    }
  }

  IrOpcode::Value opcode;
};

// A small closure class to generate code for a function of two inputs that
// produces a single output so that it can be used in many different contexts.
// The {expected()} method should compute the expected output for a given
// pair of inputs.
template <typename T>
class BinopGen {
 public:
  virtual void gen(RawMachineAssemblerTester<int32_t>* m, Node* a, Node* b) = 0;
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
}  // namespace compiler
}  // namespace internal
}  // namespace v8

#endif  // V8_CCTEST_COMPILER_CODEGEN_TESTER_H_
```