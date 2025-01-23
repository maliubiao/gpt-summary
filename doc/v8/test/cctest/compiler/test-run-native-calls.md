Response:
Let's break down the thought process for analyzing this C++ code snippet.

**1. Initial Scan and Keywords:**

The first thing I do is a quick scan for recognizable keywords and patterns. I see:

* `#include`:  Indicates C++ header files, likely defining data structures and functions used in the code. The included headers like `assembler.h`, `linkage.h`, `objects-inl.h`, `wasm/wasm-linkage.h`, and `test/cctest/` strongly suggest this is part of the V8 JavaScript engine's testing framework, specifically related to the compiler.
* `namespace v8 { namespace internal { namespace compiler { namespace test_run_native_calls {`:  This confirms the location within V8's codebase and the specific purpose: testing native calls within the compiler.
* `using float32 = float; using float64 = double;`:  Type aliases for clarity.
* Classes like `Pairs`, `RegisterPairs`, `Float32RegisterPairs`, `Float64RegisterPairs`, `Allocator`, `RegisterConfig`, `ArgsBuffer`, `Computer`: These are the core building blocks of the test framework.
* Functions like `CompileGraph`, `WrapWithCFunction`, `Run`, `Build_...`, `Compute_...`, `Test_...`:  These are the actions performed within the tests.
* Macros like `TEST`, `FOR_INT32_INPUTS`: These are part of the testing framework (`cctest`).
* Comments like `// Picks a representative pair of integers...`, `// Helper for allocating...`, `// Build the add function.`: These provide high-level explanations of the code's intent.

**2. Identifying Core Functionality - Focus on the Classes:**

The class definitions are crucial. I analyze each one to understand its role:

* **`Pairs` and its specializations (`RegisterPairs`, `Float32RegisterPairs`, `Float64RegisterPairs`):**  These classes are clearly about generating pairs of values, likely for testing combinations of registers. The `Next()` method is key here. The specialization tells me they're dealing with general-purpose registers and floating-point registers.
* **`Allocator`:**  This class manages the allocation of registers and stack slots for function parameters and return values. The `Next()` method is about deciding where to place the next parameter/return. The internal `wasm::LinkageAllocator` hints at a connection to WebAssembly.
* **`RegisterConfig`:**  This class seems to tie `Allocator` instances together for parameters and return values, and it's responsible for creating `CallDescriptor` objects. The `Create()` method is the central action.
* **`ArgsBuffer`:**  This class is designed to hold and manipulate arguments for function calls. The `Mutate()` method suggests it's generating different sets of inputs for testing. The template nature indicates it works with different data types.
* **`Computer`:**  This class encapsulates the process of compiling and running code snippets. The `Run()` method orchestrates the entire testing process, compiling a graph, wrapping it, and running it with different input values.

**3. Tracing the Test Flow - Following the `TEST` Macros:**

The `TEST` macros are where the actual tests are defined. I pick a representative test, like `TEST(Run_Int32Sub_all_allocatable_pairs_0)`, and follow its execution path:

* It calls `Test_RunInt32SubWithRet(0)`.
* `Test_RunInt32SubWithRet` creates `RegisterPairs` to iterate through register pairs.
* Inside the loop, it creates `Allocator` instances for parameters and return values, then `RegisterConfig`.
* It calls `TestInt32Sub` with a generated `CallDescriptor`.
* `TestInt32Sub` defines a simple graph that performs integer subtraction.
* It uses `CompileGraph` to compile the graph into executable code.
* It wraps the compiled code with `WrapWithCFunction`.
* It uses `CodeRunner` to execute the wrapped code with various input values.

This trace helps understand the overall structure: generate test cases (register combinations), define a computation, compile it, and run it with various inputs.

**4. Identifying Potential Relationships with JavaScript:**

The presence of "native calls" in the filename and the use of `CallDescriptor` and the compiler infrastructure strongly suggest a connection to how JavaScript calls native (C++) functions. I look for evidence of interaction:

* The `WrapWithCFunction` clearly takes compiled code and creates a wrapper, likely to make it callable from a higher level. While the example doesn't *directly* show a JavaScript call, it's the underlying mechanism that allows JavaScript to invoke these compiled C++ functions. I would then hypothesize that similar mechanisms are used when JavaScript calls built-in functions or performs operations that are optimized and potentially offloaded to native code.

**5. Considering Potential Errors:**

Based on the operations being tested (arithmetic, data copying, function calls with specific register assignments), I can think about common errors:

* **Incorrect register allocation:** If the `Allocator` or `RegisterConfig` doesn't correctly assign registers, the compiled code might read or write to the wrong locations.
* **Type mismatches:** If the `MachineType` used in the `CallDescriptor` doesn't match the actual data type, it could lead to crashes or incorrect results.
* **Stack overflow/underflow:** Incorrect calculation of stack frame size in the `Allocator` could lead to stack corruption.
* **Off-by-one errors in loops:**  When iterating through parameters or registers.
* **Incorrect handling of floating-point numbers:**  Especially NaN values, which the code explicitly deals with in `ArgsBuffer`.

**6. Structuring the Answer:**

Finally, I organize my findings into the requested categories:

* **Functionality:** Summarize the overall purpose of the code – testing the V8 compiler's ability to handle native function calls. Mention the key aspects being tested (register allocation, different data types, stack parameters).
* **Torque:**  Address the `.tq` filename check explicitly.
* **JavaScript Relation:** Explain the connection to native calls and provide a simple JavaScript example that would conceptually trigger such a mechanism.
* **Code Logic Inference:**  Choose a simple test case (like `TestInt32Sub`) and explain the input, processing, and output.
* **Common Programming Errors:**  List the potential errors I identified.
* **Summary:** Provide a concise overview of the code's purpose.

This iterative process of scanning, analyzing classes and functions, tracing execution, and making connections allows for a comprehensive understanding of the code's functionality and its place within the larger V8 project.
好的，让我们来分析一下 `v8/test/cctest/compiler/test-run-native-calls.cc` 这个 V8 源代码文件的功能。

**1. 文件名和路径的含义：**

* `v8`:  表明这是 V8 JavaScript 引擎的源代码。
* `test`:  说明这是一个测试相关的目录。
* `cctest`:  表示这是 Chromium 风格的 C++ 测试（通常用于 V8 的单元测试）。
* `compiler`:  指明这个测试与 V8 的编译器组件有关。
* `test-run-native-calls.cc`:  文件名明确地暗示了这个测试的目标是 **运行原生（C++）函数调用**。

**2. 主要功能归纳：**

这个 C++ 源代码文件的主要功能是 **测试 V8 编译器生成能够正确调用原生 C++ 函数的代码的能力**。它通过以下方式来实现：

* **定义和配置原生函数调用：**  文件中定义了一些辅助类（如 `Pairs`, `RegisterPairs`, `Allocator`, `RegisterConfig`, `ArgsBuffer`）来方便地配置原生函数的调用约定，包括参数类型、返回值类型、寄存器分配等。
* **构建调用原生函数的 V8 IR (中间表示)：**  使用 V8 编译器提供的 API（如 `RawMachineAssembler`, `GraphAndBuilders`）来构建表示原生函数调用的中间表示图。这个图描述了如何准备参数、执行调用以及处理返回值。
* **编译 IR 为机器码：**  利用 V8 的编译管道将构建的 IR 图编译成实际的机器码。
* **执行编译后的代码并验证结果：**  运行生成的机器码，调用预先定义好的原生 C++ 函数，并将调用的结果与预期值进行比较，从而验证编译器生成的代码是否正确。

**3. 关于文件扩展名和 Torque：**

如果 `v8/test/cctest/compiler/test-run-native-calls.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是 V8 用来定义内置函数和运行时函数的 DSL (领域特定语言)。由于当前的文件名是 `.cc`，所以它是一个标准的 C++ 文件。

**4. 与 JavaScript 的功能关系和 JavaScript 示例：**

`test-run-native-calls.cc` 测试的是 V8 引擎中一个核心机制：如何从 JavaScript 代码中调用原生（C++）函数。这种机制是 V8 实现内置函数（如 `Math.sin`, `Array.push` 等）和提供扩展能力的关键。

**JavaScript 示例：**

```javascript
// 假设在 V8 内部，有一个原生 C++ 函数叫做 "nativeAdd"
// 它的作用是将两个整数相加

// 在 JavaScript 中调用这个原生函数（这只是一个概念性的例子，
// 实际的 V8 内置函数调用会有更复杂的绑定机制）
function jsAdd(a, b) {
  // V8 编译器会将这里的调用转换为对 "nativeAdd" 的调用
  return nativeAdd(a, b);
}

let result = jsAdd(5, 3);
console.log(result); // 输出 8
```

在这个例子中，当 JavaScript 代码调用 `jsAdd(5, 3)` 时，V8 的编译器需要生成能够正确调用底层原生 C++ 函数 `nativeAdd` 的机器码。`test-run-native-calls.cc` 中的测试就是为了确保编译器在处理这类原生函数调用时不会出错。

**5. 代码逻辑推理和假设输入输出：**

让我们以文件中的 `TestInt32Sub` 函数为例进行逻辑推理：

**假设输入：**

* 两个 32 位整数，例如 `i = 10` 和 `j = 5`。

**代码逻辑：**

1. `TestInt32Sub` 函数首先构建一个 V8 IR 图，该图表示一个简单的整数减法操作，将两个参数 `p0` 和 `p1` 相减。
2. 然后，它将这个 IR 图编译成机器码。
3. `WrapWithCFunction`  将编译后的代码包装成一个可以通过 C++ 函数指针调用的形式。
4. `CodeRunner` 用于执行这个包装后的代码。
5. 在 `FOR_INT32_INPUTS` 循环中，`runnable.Call(i, j)` 会实际执行编译后的减法操作。

**预期输出：**

* 对于输入 `i = 10` 和 `j = 5`，预期的结果是 `10 - 5 = 5`。`CHECK_EQ(expected, result)` 宏会验证实际的运行结果是否与预期值相等。

**6. 涉及用户常见的编程错误：**

虽然这个测试文件主要是测试编译器，但它间接反映了用户在编写与原生代码交互的 JavaScript 代码时可能遇到的错误：

* **类型不匹配：** 如果 JavaScript 传递给原生函数的参数类型与原生函数期望的类型不符，会导致错误或未定义的行为。例如，原生函数期望一个整数，但 JavaScript 传递了一个字符串。
* **参数数量不匹配：**  如果 JavaScript 调用原生函数时传递的参数数量与原生函数定义的参数数量不一致，也会导致错误。
* **内存管理错误：** 如果原生函数需要访问或修改 JavaScript 对象的内存，但没有正确地处理 V8 的垃圾回收机制，可能会导致内存泄漏或访问已释放的内存。
* **ABI (Application Binary Interface) 不兼容：**  在更复杂的场景下，如果原生代码的编译方式与 V8 期望的 ABI 不兼容，可能会导致调用失败。

**示例说明类型不匹配的编程错误（JavaScript）：**

```javascript
// 假设有一个原生函数 nativeSquareRoot(number: number): number;

function calculateSquareRoot(input) {
  // 用户可能错误地将字符串传递给期望数字的原生函数
  return nativeSquareRoot(input);
}

let result = calculateSquareRoot("abc"); // 这很可能导致原生函数出错
```

**总结：**

`v8/test/cctest/compiler/test-run-native-calls.cc` 的主要功能是 **验证 V8 编译器能够正确地生成用于调用原生 C++ 函数的机器码**。它通过构建和编译模拟原生函数调用的 IR 图，并执行生成的代码来确保编译器在处理不同参数类型、返回值类型和寄存器分配的情况下都能产生正确的代码。这个测试对于保证 V8 引擎的稳定性和正确性，以及支持高效的内置函数和扩展功能至关重要。

### 提示词
```
这是目录为v8/test/cctest/compiler/test-run-native-calls.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/test-run-native-calls.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include "src/base/overflowing-math.h"
#include "src/codegen/assembler.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/register-configuration.h"
#include "src/compiler/linkage.h"
#include "src/compiler/raw-machine-assembler.h"
#include "src/objects/objects-inl.h"
#include "src/wasm/wasm-linkage.h"
#include "test/cctest/cctest.h"
#include "test/cctest/compiler/codegen-tester.h"
#include "test/cctest/compiler/graph-and-builders.h"
#include "test/common/value-helper.h"

namespace v8 {
namespace internal {
namespace compiler {
namespace test_run_native_calls {

namespace {
using float32 = float;
using float64 = double;

// Picks a representative pair of integers from the given range.
// If there are less than {max_pairs} possible pairs, do them all, otherwise try
// to select a representative set.
class Pairs {
 public:
  Pairs(int max_pairs, int range, const int* codes)
      : range_(range),
        codes_(codes),
        max_pairs_(std::min(max_pairs, range_ * range_)),
        counter_(0) {}

  bool More() { return counter_ < max_pairs_; }

  void Next(int* r0, int* r1, bool same_is_ok) {
    do {
      // Find the next pair.
      if (exhaustive()) {
        *r0 = codes_[counter_ % range_];
        *r1 = codes_[counter_ / range_];
      } else {
        // Try each integer at least once for both r0 and r1.
        int index = counter_ / 2;
        if (counter_ & 1) {
          *r0 = codes_[index % range_];
          *r1 = codes_[index / range_];
        } else {
          *r1 = codes_[index % range_];
          *r0 = codes_[index / range_];
        }
      }
      counter_++;
      if ((same_is_ok) || (*r0 != *r1)) break;
      if (counter_ == max_pairs_) {
        // For the last hurrah, reg#0 with reg#n-1
        *r0 = codes_[0];
        *r1 = codes_[range_ - 1];
        break;
      }
    } while (true);
  }

 private:
  int range_;
  const int* codes_;
  int max_pairs_;
  int counter_;
  bool exhaustive() { return max_pairs_ == (range_ * range_); }
};


// Pairs of general purpose registers.
class RegisterPairs : public Pairs {
 public:
  RegisterPairs()
      : Pairs(100, GetRegConfig()->num_allocatable_general_registers(),
              GetRegConfig()->allocatable_general_codes()) {}
};

// Pairs of float registers.
class Float32RegisterPairs : public Pairs {
 public:
  Float32RegisterPairs()
      : Pairs(100, GetRegConfig()->num_allocatable_float_registers(),
              GetRegConfig()->allocatable_float_codes()) {}
};


// Pairs of double registers.
class Float64RegisterPairs : public Pairs {
 public:
  Float64RegisterPairs()
      : Pairs(100, GetRegConfig()->num_allocatable_double_registers(),
              GetRegConfig()->allocatable_double_codes()) {}
};


// Helper for allocating either an GP or FP reg, or the next stack slot.
class Allocator {
 public:
  Allocator(int* gp, int gpc, int* fp, int fpc) : stack_offset_(0) {
    for (int i = 0; i < gpc; ++i) {
      gp_.push_back(Register::from_code(gp[i]));
    }
    for (int i = 0; i < fpc; ++i) {
      fp_.push_back(DoubleRegister::from_code(fp[i]));
    }
    Reset();
  }

  int stack_offset() const { return stack_offset_; }

  LinkageLocation Next(MachineType type) {
    if (IsFloatingPoint(type.representation())) {
      // Allocate a floating point register/stack location.
      if (reg_allocator_->CanAllocateFP(type.representation())) {
        int code = reg_allocator_->NextFpReg(type.representation());
        return LinkageLocation::ForRegister(code, type);
      } else {
        int offset = -1 - stack_offset_;
        stack_offset_ += StackWords(type);
        return LinkageLocation::ForCallerFrameSlot(offset, type);
      }
    } else {
      // Allocate a general purpose register/stack location.
      if (reg_allocator_->CanAllocateGP()) {
        int code = reg_allocator_->NextGpReg();
        return LinkageLocation::ForRegister(code, type);
      } else {
        int offset = -1 - stack_offset_;
        stack_offset_ += StackWords(type);
        return LinkageLocation::ForCallerFrameSlot(offset, type);
      }
    }
  }
  int StackWords(MachineType type) {
    int size = 1 << ElementSizeLog2Of(type.representation());
    return size <= kSystemPointerSize ? 1 : size / kSystemPointerSize;
  }
  void Reset() {
    stack_offset_ = 0;
    reg_allocator_.reset(
        new wasm::LinkageAllocator(gp_.data(), static_cast<int>(gp_.size()),
                                   fp_.data(), static_cast<int>(fp_.size())));
  }

 private:
  std::vector<Register> gp_;
  std::vector<DoubleRegister> fp_;
  std::unique_ptr<wasm::LinkageAllocator> reg_allocator_;
  int stack_offset_;
};


class RegisterConfig {
 public:
  RegisterConfig(Allocator& p, Allocator& r) : params(p), rets(r) {}

  CallDescriptor* Create(Zone* zone, MachineSignature* msig) {
    rets.Reset();
    params.Reset();

    LocationSignature::Builder locations(zone, msig->return_count(),
                                         msig->parameter_count());
    // Add return location(s).
    const int return_count = static_cast<int>(locations.return_count_);
    for (int i = 0; i < return_count; i++) {
      locations.AddReturn(rets.Next(msig->GetReturn(i)));
    }

    // Add register and/or stack parameter(s).
    const int parameter_count = static_cast<int>(msig->parameter_count());
    for (int i = 0; i < parameter_count; i++) {
      locations.AddParam(params.Next(msig->GetParam(i)));
    }

    const RegList kCalleeSaveRegisters;
    const DoubleRegList kCalleeSaveFPRegisters;

    MachineType target_type = MachineType::AnyTagged();
    LinkageLocation target_loc = LinkageLocation::ForAnyRegister();
    int stack_param_count = params.stack_offset();
    return zone->New<CallDescriptor>(       // --
        CallDescriptor::kCallCodeObject,    // kind
        kDefaultCodeEntrypointTag,          // tag
        target_type,                        // target MachineType
        target_loc,                         // target location
        locations.Get(),                    // location_sig
        stack_param_count,                  // stack_parameter_count
        compiler::Operator::kNoProperties,  // properties
        kCalleeSaveRegisters,               // callee-saved registers
        kCalleeSaveFPRegisters,             // callee-saved fp regs
        CallDescriptor::kNoFlags,           // flags
        "c-call");
  }

 private:
  Allocator& params;
  Allocator& rets;
};

const int kMaxParamCount = 64;

MachineType kIntTypes[kMaxParamCount + 1] = {
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32(), MachineType::Int32(),
    MachineType::Int32(), MachineType::Int32()};


// For making uniform int32 signatures shorter.
class Int32Signature : public MachineSignature {
 public:
  explicit Int32Signature(int param_count)
      : MachineSignature(1, param_count, kIntTypes) {
    CHECK_GE(kMaxParamCount, param_count);
  }
};

Handle<Code> CompileGraph(const char* name, CallDescriptor* call_descriptor,
                          Graph* graph, Schedule* schedule = nullptr) {
  Isolate* isolate = CcTest::InitIsolateOnce();
  OptimizedCompilationInfo info(base::ArrayVector("testing"), graph->zone(),
                                CodeKind::FOR_TESTING);
  Handle<Code> code = Pipeline::GenerateCodeForTesting(
                          &info, isolate, call_descriptor, graph,
                          AssemblerOptions::Default(isolate), schedule)
                          .ToHandleChecked();
#ifdef ENABLE_DISASSEMBLER
  if (v8_flags.print_opt_code) {
    StdoutStream os;
    code->Disassemble(name, os, isolate);
  }
#endif
  return code;
}

Handle<Code> WrapWithCFunction(Isolate* isolate, Handle<Code> inner,
                               CallDescriptor* call_descriptor) {
  Zone zone(isolate->allocator(), ZONE_NAME, kCompressGraphZone);
  int param_count = static_cast<int>(call_descriptor->ParameterCount());
  GraphAndBuilders caller(&zone);
  {
    GraphAndBuilders& b = caller;
    Node* start = b.graph()->NewNode(b.common()->Start(param_count + 3));
    b.graph()->SetStart(start);
    Node* target = b.graph()->NewNode(b.common()->HeapConstant(inner));

    // Add arguments to the call.
    Node** args = zone.AllocateArray<Node*>(param_count + 3);
    int index = 0;
    args[index++] = target;
    for (int i = 0; i < param_count; i++) {
      args[index] = b.graph()->NewNode(b.common()->Parameter(i), start);
      index++;
    }
    args[index++] = start;  // effect.
    args[index++] = start;  // control.

    // Build the call and return nodes.
    Node* call = b.graph()->NewNode(b.common()->Call(call_descriptor),
                                    param_count + 3, args);
    Node* zero = b.graph()->NewNode(b.common()->Int32Constant(0));
    Node* ret =
        b.graph()->NewNode(b.common()->Return(), zero, call, call, start);
    b.graph()->SetEnd(ret);
  }

  MachineSignature* msig = call_descriptor->GetMachineSignature(&zone);
  CallDescriptor* cdesc = Linkage::GetSimplifiedCDescriptor(&zone, msig);

  return CompileGraph("wrapper", cdesc, caller.graph());
}

template <typename CType>
class ArgsBuffer {
 public:
  static const int kMaxParamCount = 64;

  explicit ArgsBuffer(int count, int seed = 1) : count_(count), seed_(seed) {
    // initialize the buffer with "seed 0"
    seed_ = 0;
    Mutate();
    seed_ = seed;
  }

  class Sig : public MachineSignature {
   public:
    explicit Sig(int param_count)
        : MachineSignature(1, param_count, MachTypes()) {
      CHECK_GE(kMaxParamCount, param_count);
    }
  };

  static MachineType* MachTypes() {
    MachineType t = MachineTypeForC<CType>();
    static MachineType kTypes[kMaxParamCount + 1] = {
        t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t,
        t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t,
        t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t};
    return kTypes;
  }

  Node* MakeConstant(RawMachineAssembler* raw, int32_t value) {
    return raw->Int32Constant(value);
  }

  Node* MakeConstant(RawMachineAssembler* raw, int64_t value) {
    return raw->Int64Constant(value);
  }

  Node* MakeConstant(RawMachineAssembler* raw, float32 value) {
    return raw->Float32Constant(value);
  }

  Node* MakeConstant(RawMachineAssembler* raw, float64 value) {
    return raw->Float64Constant(value);
  }

  Node* LoadInput(RawMachineAssembler* raw, Node* base, int index) {
    Node* offset = raw->Int32Constant(index * sizeof(CType));
    return raw->Load(MachineTypeForC<CType>(), base, offset);
  }

  Node* StoreOutput(RawMachineAssembler* raw, Node* value) {
    Node* base = raw->PointerConstant(&output);
    Node* offset = raw->Int32Constant(0);
    return raw->Store(MachineTypeForC<CType>().representation(), base, offset,
                      value, kNoWriteBarrier);
  }

  // Computes the next set of inputs by updating the {input} array.
  void Mutate();

  void Reset() { memset(input, 0, sizeof(input)); }

  int count_;
  int seed_;
  CType input[kMaxParamCount];
  CType output;
};


template <>
void ArgsBuffer<int32_t>::Mutate() {
  uint32_t base = 1111111111u * seed_;
  for (int j = 0; j < count_ && j < kMaxParamCount; j++) {
    input[j] = static_cast<int32_t>(256 + base + j + seed_ * 13);
  }
  output = -1;
  seed_++;
}


template <>
void ArgsBuffer<int64_t>::Mutate() {
  uint64_t base = 11111111111111111ull * seed_;
  for (int j = 0; j < count_ && j < kMaxParamCount; j++) {
    input[j] = static_cast<int64_t>(256 + base + j + seed_ * 13);
  }
  output = -1;
  seed_++;
}


template <>
void ArgsBuffer<float32>::Mutate() {
  float64 base = -33.25 * seed_;
  for (int j = 0; j < count_ && j < kMaxParamCount; j++) {
    input[j] = 256 + base + j + seed_ * 13;
  }
  output = std::numeric_limits<float32>::quiet_NaN();
  seed_++;
}


template <>
void ArgsBuffer<float64>::Mutate() {
  float64 base = -111.25 * seed_;
  for (int j = 0; j < count_ && j < kMaxParamCount; j++) {
    input[j] = 256 + base + j + seed_ * 13;
  }
  output = std::numeric_limits<float64>::quiet_NaN();
  seed_++;
}

int ParamCount(CallDescriptor* call_descriptor) {
  return static_cast<int>(call_descriptor->ParameterCount());
}


template <typename CType>
class Computer {
 public:
  static void Run(CallDescriptor* desc,
                  void (*build)(CallDescriptor*, RawMachineAssembler*),
                  CType (*compute)(CallDescriptor*, CType* inputs),
                  int seed = 1) {
    int num_params = ParamCount(desc);
    CHECK_LE(num_params, kMaxParamCount);
    Isolate* isolate = CcTest::InitIsolateOnce();
    HandleScope scope(isolate);
    Handle<Code> inner;
    {
      // Build the graph for the computation.
      Zone zone(isolate->allocator(), ZONE_NAME, kCompressGraphZone);
      Graph graph(&zone);
      RawMachineAssembler raw(isolate, &graph, desc);
      build(desc, &raw);
      inner = CompileGraph("Compute", desc, &graph, raw.ExportForTest());
    }

    CSignatureOf<int32_t> csig;
    ArgsBuffer<CType> io(num_params, seed);

    {
      // constant mode.
      DirectHandle<Code> wrapper;
      {
        // Wrap the above code with a callable function that passes constants.
        Zone zone(isolate->allocator(), ZONE_NAME, kCompressGraphZone);
        Graph graph(&zone);
        CallDescriptor* cdesc = Linkage::GetSimplifiedCDescriptor(&zone, &csig);
        RawMachineAssembler raw(isolate, &graph, cdesc);
        Node* target = raw.HeapConstant(inner);
        Node** inputs = zone.AllocateArray<Node*>(num_params + 1);
        int input_count = 0;
        inputs[input_count++] = target;
        for (int i = 0; i < num_params; i++) {
          inputs[input_count++] = io.MakeConstant(&raw, io.input[i]);
        }

        Node* call = raw.CallN(desc, input_count, inputs);
        Node* store = io.StoreOutput(&raw, call);
        USE(store);
        raw.Return(raw.Int32Constant(seed));
        wrapper = CompileGraph("Compute-wrapper-const", cdesc, &graph,
                               raw.ExportForTest());
      }

      CodeRunner<int32_t> runnable(isolate, wrapper, &csig);

      // Run the code, checking it against the reference.
      CType expected = compute(desc, io.input);
      int32_t check_seed = runnable.Call();
      CHECK_EQ(seed, check_seed);
      CHECK_EQ(expected, io.output);
    }

    {
      // buffer mode.
      DirectHandle<Code> wrapper;
      {
        // Wrap the above code with a callable function that loads from {input}.
        Zone zone(isolate->allocator(), ZONE_NAME, kCompressGraphZone);
        Graph graph(&zone);
        CallDescriptor* cdesc = Linkage::GetSimplifiedCDescriptor(&zone, &csig);
        RawMachineAssembler raw(isolate, &graph, cdesc);
        Node* base = raw.PointerConstant(io.input);
        Node* target = raw.HeapConstant(inner);
        Node** inputs = zone.AllocateArray<Node*>(kMaxParamCount + 1);
        int input_count = 0;
        inputs[input_count++] = target;
        for (int i = 0; i < num_params; i++) {
          inputs[input_count++] = io.LoadInput(&raw, base, i);
        }

        Node* call = raw.CallN(desc, input_count, inputs);
        Node* store = io.StoreOutput(&raw, call);
        USE(store);
        raw.Return(raw.Int32Constant(seed));
        wrapper =
            CompileGraph("Compute-wrapper", cdesc, &graph, raw.ExportForTest());
      }

      CodeRunner<int32_t> runnable(isolate, wrapper, &csig);

      // Run the code, checking it against the reference.
      for (int i = 0; i < 5; i++) {
        CType expected = compute(desc, io.input);
        int32_t check_seed = runnable.Call();
        CHECK_EQ(seed, check_seed);
        CHECK_EQ(expected, io.output);
        io.Mutate();
      }
    }
  }
};

}  // namespace


static void TestInt32Sub(CallDescriptor* desc) {
  Isolate* isolate = CcTest::InitIsolateOnce();
  HandleScope scope(isolate);
  Zone zone(isolate->allocator(), ZONE_NAME, kCompressGraphZone);
  GraphAndBuilders inner(&zone);
  {
    // Build the add function.
    GraphAndBuilders& b = inner;
    Node* start = b.graph()->NewNode(b.common()->Start(5));
    b.graph()->SetStart(start);
    Node* p0 = b.graph()->NewNode(b.common()->Parameter(0), start);
    Node* p1 = b.graph()->NewNode(b.common()->Parameter(1), start);
    Node* add = b.graph()->NewNode(b.machine()->Int32Sub(), p0, p1);
    Node* zero = b.graph()->NewNode(b.common()->Int32Constant(0));
    Node* ret =
        b.graph()->NewNode(b.common()->Return(), zero, add, start, start);
    b.graph()->SetEnd(ret);
  }

  Handle<Code> inner_code = CompileGraph("Int32Sub", desc, inner.graph());
  DirectHandle<Code> wrapper = WrapWithCFunction(isolate, inner_code, desc);
  MachineSignature* msig = desc->GetMachineSignature(&zone);
  CodeRunner<int32_t> runnable(isolate, wrapper,
                               CSignature::FromMachine(&zone, msig));

  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected = static_cast<int32_t>(static_cast<uint32_t>(i) -
                                              static_cast<uint32_t>(j));
      int32_t result = runnable.Call(i, j);
      CHECK_EQ(expected, result);
    }
  }
}


static void CopyTwentyInt32(CallDescriptor* desc) {
  const int kNumParams = 20;
  int32_t input[kNumParams];
  int32_t output[kNumParams];
  Isolate* isolate = CcTest::InitIsolateOnce();
  HandleScope scope(isolate);
  Handle<Code> inner;
  {
    // Writes all parameters into the output buffer.
    Zone zone(isolate->allocator(), ZONE_NAME, kCompressGraphZone);
    Graph graph(&zone);
    RawMachineAssembler raw(isolate, &graph, desc);
    Node* base = raw.PointerConstant(output);
    for (int i = 0; i < kNumParams; i++) {
      Node* offset = raw.Int32Constant(i * sizeof(int32_t));
      raw.Store(MachineRepresentation::kWord32, base, offset, raw.Parameter(i),
                kNoWriteBarrier);
    }
    raw.Return(raw.Int32Constant(42));
    inner = CompileGraph("CopyTwentyInt32", desc, &graph, raw.ExportForTest());
  }

  CSignatureOf<int32_t> csig;
  DirectHandle<Code> wrapper;
  {
    // Loads parameters from the input buffer and calls the above code.
    Zone zone(isolate->allocator(), ZONE_NAME, kCompressGraphZone);
    Graph graph(&zone);
    CallDescriptor* cdesc = Linkage::GetSimplifiedCDescriptor(&zone, &csig);
    RawMachineAssembler raw(isolate, &graph, cdesc);
    Node* base = raw.PointerConstant(input);
    Node* target = raw.HeapConstant(inner);
    Node** inputs = zone.AllocateArray<Node*>(JSParameterCount(kNumParams));
    int input_count = 0;
    inputs[input_count++] = target;
    for (int i = 0; i < kNumParams; i++) {
      Node* offset = raw.Int32Constant(i * sizeof(int32_t));
      inputs[input_count++] = raw.Load(MachineType::Int32(), base, offset);
    }

    Node* call = raw.CallN(desc, input_count, inputs);
    raw.Return(call);
    wrapper = CompileGraph("CopyTwentyInt32-wrapper", cdesc, &graph,
                           raw.ExportForTest());
  }

  CodeRunner<int32_t> runnable(isolate, wrapper, &csig);

  // Run the code, checking it correctly implements the memcpy.
  for (int i = 0; i < 5; i++) {
    uint32_t base = 1111111111u * i;
    for (int j = 0; j < kNumParams; j++) {
      input[j] = static_cast<int32_t>(base + 13 * j);
    }

    memset(output, 0, sizeof(output));
    CHECK_EQ(42, runnable.Call());

    for (int j = 0; j < kNumParams; j++) {
      CHECK_EQ(input[j], output[j]);
    }
  }
}


static void Test_RunInt32SubWithRet(int retreg) {
  Int32Signature sig(2);
  v8::internal::AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);
  RegisterPairs pairs;
  while (pairs.More()) {
    int parray[2];
    int rarray[] = {retreg};
    pairs.Next(&parray[0], &parray[1], false);
    Allocator params(parray, 2, nullptr, 0);
    Allocator rets(rarray, 1, nullptr, 0);
    RegisterConfig config(params, rets);
    TestInt32Sub(config.Create(&zone, &sig));
  }
}


// Separate tests for parallelization.
#define TEST_INT32_SUB_WITH_RET(x)                     \
  TEST(Run_Int32Sub_all_allocatable_pairs_##x) {       \
    if (x < Register::kNumRegisters &&                 \
        GetRegConfig()->IsAllocatableGeneralCode(x)) { \
      Test_RunInt32SubWithRet(x);                      \
    }                                                  \
  }

TEST_INT32_SUB_WITH_RET(0)
TEST_INT32_SUB_WITH_RET(1)
TEST_INT32_SUB_WITH_RET(2)
TEST_INT32_SUB_WITH_RET(3)
TEST_INT32_SUB_WITH_RET(4)
TEST_INT32_SUB_WITH_RET(5)
TEST_INT32_SUB_WITH_RET(6)
TEST_INT32_SUB_WITH_RET(7)
TEST_INT32_SUB_WITH_RET(8)
TEST_INT32_SUB_WITH_RET(9)
TEST_INT32_SUB_WITH_RET(10)
TEST_INT32_SUB_WITH_RET(11)
TEST_INT32_SUB_WITH_RET(12)
TEST_INT32_SUB_WITH_RET(13)
TEST_INT32_SUB_WITH_RET(14)
TEST_INT32_SUB_WITH_RET(15)
TEST_INT32_SUB_WITH_RET(16)
TEST_INT32_SUB_WITH_RET(17)
TEST_INT32_SUB_WITH_RET(18)
TEST_INT32_SUB_WITH_RET(19)


TEST(Run_Int32Sub_all_allocatable_single) {
  Int32Signature sig(2);
  RegisterPairs pairs;
  while (pairs.More()) {
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    int parray[1];
    int rarray[1];
    pairs.Next(&rarray[0], &parray[0], true);
    Allocator params(parray, 1, nullptr, 0);
    Allocator rets(rarray, 1, nullptr, 0);
    RegisterConfig config(params, rets);
    TestInt32Sub(config.Create(&zone, &sig));
  }
}


TEST(Run_CopyTwentyInt32_all_allocatable_pairs) {
  Int32Signature sig(20);
  RegisterPairs pairs;
  while (pairs.More()) {
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    int parray[2];
    int rarray[] = {GetRegConfig()->GetAllocatableGeneralCode(0)};
    pairs.Next(&parray[0], &parray[1], false);
    Allocator params(parray, 2, nullptr, 0);
    Allocator rets(rarray, 1, nullptr, 0);
    RegisterConfig config(params, rets);
    CopyTwentyInt32(config.Create(&zone, &sig));
  }
}

template <typename CType>
static void Run_Computation(
    CallDescriptor* desc, void (*build)(CallDescriptor*, RawMachineAssembler*),
    CType (*compute)(CallDescriptor*, CType* inputs), int seed = 1) {
  Computer<CType>::Run(desc, build, compute, seed);
}

static uint32_t coeff[] = {1,  2,  3,  5,  7,   11,  13,  17,  19, 23, 29,
                           31, 37, 41, 43, 47,  53,  59,  61,  67, 71, 73,
                           79, 83, 89, 97, 101, 103, 107, 109, 113};

static void Build_Int32_WeightedSum(CallDescriptor* desc,
                                    RawMachineAssembler* raw) {
  Node* result = raw->Int32Constant(0);
  for (int i = 0; i < ParamCount(desc); i++) {
    Node* term = raw->Int32Mul(raw->Parameter(i), raw->Int32Constant(coeff[i]));
    result = raw->Int32Add(result, term);
  }
  raw->Return(result);
}

static int32_t Compute_Int32_WeightedSum(CallDescriptor* desc, int32_t* input) {
  uint32_t result = 0;
  for (int i = 0; i < ParamCount(desc); i++) {
    result += static_cast<uint32_t>(input[i]) * coeff[i];
  }
  return static_cast<int32_t>(result);
}


static void Test_Int32_WeightedSum_of_size(int count) {
  Int32Signature sig(count);
  for (int p0 = 0; p0 < Register::kNumRegisters; p0++) {
    if (GetRegConfig()->IsAllocatableGeneralCode(p0)) {
      v8::internal::AccountingAllocator allocator;
      Zone zone(&allocator, ZONE_NAME);

      int parray[] = {p0};
      int rarray[] = {GetRegConfig()->GetAllocatableGeneralCode(0)};
      Allocator params(parray, 1, nullptr, 0);
      Allocator rets(rarray, 1, nullptr, 0);
      RegisterConfig config(params, rets);
      CallDescriptor* desc = config.Create(&zone, &sig);
      Run_Computation<int32_t>(desc, Build_Int32_WeightedSum,
                               Compute_Int32_WeightedSum, 257 + count);
    }
  }
}


// Separate tests for parallelization.
#define TEST_INT32_WEIGHTEDSUM(x) \
  TEST(Run_Int32_WeightedSum_##x) { Test_Int32_WeightedSum_of_size(x); }


TEST_INT32_WEIGHTEDSUM(1)
TEST_INT32_WEIGHTEDSUM(2)
TEST_INT32_WEIGHTEDSUM(3)
TEST_INT32_WEIGHTEDSUM(4)
TEST_INT32_WEIGHTEDSUM(5)
TEST_INT32_WEIGHTEDSUM(7)
TEST_INT32_WEIGHTEDSUM(9)
TEST_INT32_WEIGHTEDSUM(11)
TEST_INT32_WEIGHTEDSUM(17)
TEST_INT32_WEIGHTEDSUM(19)

template <int which>
static void Build_Select(CallDescriptor* desc, RawMachineAssembler* raw) {
  raw->Return(raw->Parameter(which));
}

template <typename CType, int which>
static CType Compute_Select(CallDescriptor* desc, CType* inputs) {
  return inputs[which];
}


template <typename CType, int which>
static void RunSelect(CallDescriptor* desc) {
  int count = ParamCount(desc);
  if (count <= which) return;
  Run_Computation<CType>(desc, Build_Select<which>,
                         Compute_Select<CType, which>,
                         1044 + which + 3 * sizeof(CType));
}


template <int which>
void Test_Int32_Select() {
  int parray[] = {GetRegConfig()->GetAllocatableGeneralCode(0)};
  int rarray[] = {GetRegConfig()->GetAllocatableGeneralCode(0)};
  Allocator params(parray, 1, nullptr, 0);
  Allocator rets(rarray, 1, nullptr, 0);
  RegisterConfig config(params, rets);

  v8::internal::AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);

  for (int i = which + 1; i <= 64; i++) {
    Int32Signature sig(i);
    CallDescriptor* desc = config.Create(&zone, &sig);
    RunSelect<int32_t, which>(desc);
  }
}


// Separate tests for parallelization.
#define TEST_INT32_SELECT(x) \
  TEST(Run_Int32_Select_##x) { Test_Int32_Select<x>(); }


TEST_INT32_SELECT(0)
TEST_INT32_SELECT(1)
TEST_INT32_SELECT(2)
TEST_INT32_SELECT(3)
TEST_INT32_SELECT(4)
TEST_INT32_SELECT(5)
TEST_INT32_SELECT(6)
TEST_INT32_SELECT(11)
TEST_INT32_SELECT(15)
TEST_INT32_SELECT(19)
TEST_INT32_SELECT(45)
TEST_INT32_SELECT(62)
TEST_INT32_SELECT(63)


TEST(Int64Select_registers) {
  if (GetRegConfig()->num_allocatable_general_registers() < 2) return;
  // TODO(titzer): int64 on 32-bit platforms
  if (kSystemPointerSize < 8) return;

  int rarray[] = {GetRegConfig()->GetAllocatableGeneralCode(0)};
  ArgsBuffer<int64_t>::Sig sig(2);

  RegisterPairs pairs;
  v8::internal::AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);
  while (pairs.More()) {
    int parray[2];
    pairs.Next(&parray[0], &parray[1], false);
    Allocator params(parray, 2, nullptr, 0);
    Allocator rets(rarray, 1, nullptr, 0);
    RegisterConfig config(params, rets);

    CallDescriptor* desc = config.Create(&zone, &sig);
    RunSelect<int64_t, 0>(desc);
    RunSelect<int64_t, 1>(desc);
  }
}


TEST(Float32Select_registers) {
  if (GetRegConfig()->num_allocatable_double_registers() < 2) {
    return;
  }

  int rarray[] = {GetRegConfig()->GetAllocatableFloatCode(0)};
  ArgsBuffer<float32>::Sig sig(2);

  Float32RegisterPairs pairs;
  v8::internal::AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);
  while (pairs.More()) {
    int parray[2];
    pairs.Next(&parray[0], &parray[1], false);
    Allocator params(nullptr, 0, parray, 2);
    Allocator rets(nullptr, 0, rarray, 1);
    RegisterConfig config(params, rets);

    CallDescriptor* desc = config.Create(&zone, &sig);
    RunSelect<float32, 0>(desc);
    RunSelect<float32, 1>(desc);
  }
}


TEST(Float64Select_registers) {
  if (GetRegConfig()->num_allocatable_double_registers() < 2) return;
  if (GetRegConfig()->num_allocatable_general_registers() < 2) return;
  int rarray[] = {GetRegConfig()->GetAllocatableDoubleCode(0)};
  ArgsBuffer<float64>::Sig sig(2);

  Float64RegisterPairs pairs;
  v8::internal::AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);
  while (pairs.More()) {
    int parray[2];
    pairs.Next(&parray[0], &parray[1], false);
    Allocator params(nullptr, 0, parray, 2);
    Allocator rets(nullptr, 0, rarray, 1);
    RegisterConfig config(params, rets);

    CallDescriptor* desc = config.Create(&zone, &sig);
    RunSelect<float64, 0>(desc);
    RunSelect<float64, 1>(desc);
  }
}


TEST(Float32Select_stack_params_return_reg) {
  int rarray[] = {GetRegConfig()->GetAllocatableFloatCode(0)};
  Allocator params(nullptr, 0, nullptr, 0);
  Allocator rets(nullptr, 0, rarray, 1);
  RegisterConfig config(params, rets);

  v8::internal::AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);
  for (int count = 1; count < 6; count++) {
    ArgsBuffer<float32>::Sig sig(count);
    CallDescriptor* desc = config.Create(&zone, &sig);
    RunSelect<float32, 0>(desc);
    RunSelect<float32, 1>(desc);
    RunSelect<float32, 2>(desc);
    RunSelect<float32, 3>(desc);
    RunSelect<float32, 4>(desc);
    RunSelect<float32, 5>(desc);
  }
}


TEST(Float64Select_stack_params_return_reg) {
  int rarray[] = {GetRegConfig()->GetAllocatableDoubleCode(0)};
  Allocator params(nullptr, 0, nullptr, 0);
  Allocator rets(nullptr, 0, rarray, 1);
  RegisterConfig config(params, rets);

  v8::internal::AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);
  for (int count = 1; count < 6; count++) {
    ArgsBuffer<float64>::Sig sig(count);
    CallDescriptor* desc = config.Create(&zone, &sig);
    RunSelect<float64, 0>(desc);
    RunSelect<float64, 1>(desc);
    RunSelect<float64, 2>(desc);
    RunSelect<float64, 3>(desc);
    RunSelect<float64, 4>(desc);
    RunSelect<float64, 5>(desc);
  }
}

template <typename CType, int which>
static void Build_Select_With_Call(CallDescriptor* desc,
                                   RawMachineAssembler* raw) {
  Handle<Code> inner;
  int num_params = ParamCount(desc);
  CHECK_LE(num_params, kMaxParamCount);
  {
    Isolate* isolate = CcTest::InitIsolateOnce();
    // Build the actual select.
    Zone zone(isolate->allocator(), ZONE_NAME, kCompressGraphZone);
    Graph graph(&zone);
    RawMachineAssembler r(isolate, &graph, desc);
    r.Return(r.Parameter(which));
    inner = CompileGraph("Select-indirection", desc, &graph, r.ExportForTest());
    CHECK(!inner.is_null());
    CHECK(IsCode(*inner));
  }

  {
    // Build a call to the function that does the select.
    Node* target = raw->HeapConstant(inner);
    Node** inputs = raw->zone()->AllocateArray<Node*>(num_params + 1);
    int input_count = 0;
    inputs[input_count++] = target;
    for (int i = 0; i < num_params; i++) {
      inputs[input_count++] = raw->Parameter(i);
    }

    Node* call = raw->CallN(desc, input_count, inputs);
    raw->Return(call);
  }
}

TEST(Float64StackParamsToStackParams) {
  int rarray[] = {GetRegConfig()->GetAllocatableDoubleCode(0)};
  Allocator params(nullptr, 0, nullptr, 0);
  Allocator rets(nullptr, 0, rarray, 1);

  v8::internal::AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);
  ArgsBuffer<float64>::Sig sig(2);
  RegisterConfig config(params, rets);
  CallDescriptor* desc = config.Create(&zone, &sig);

  Run_Computation<float64>(desc, Build_Select_With_Call<float64, 0>,
                           Compute_Select<float64, 0>, 1098);

  Run_Computation<float64>(desc, Build_Select_With_Call<float64, 1>,
                           Compute_Select<float64, 1>, 1099);
}


void MixedParamTest(int start) {
  if (GetRegConfig()->num_double_registers() < 2) return;

// TODO(titzer): mix in 64-bit types on all platforms when supported.
#if V8_TARGET_ARCH_32_BIT
  static MachineType types[] = {
      MachineType::Int32(),   MachineType::Float32(), MachineType::Float64(),
      MachineType::Int32(),
```