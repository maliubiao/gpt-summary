Response:
Let's break down the request and the provided C++ code to construct the answer.

**1. Understanding the Goal:**

The primary goal is to analyze the `v8/src/compiler/linkage.cc` file and provide a comprehensive overview of its functionality. The prompt also includes specific constraints regarding Torque, JavaScript examples, logical reasoning, and common programming errors.

**2. Initial Scan and Key Concepts:**

A quick scan of the code reveals the following key concepts:

* **`CallDescriptor`:**  This appears to be the central data structure. It describes how functions are called, including information about parameters, return values, registers used, and stack layout.
* **`LinkageLocation`:**  Represents where data (parameters, return values) are located – either in registers or on the stack.
* **Machine Types (`MachineType`):**  Indicates the data type of values (e.g., tagged pointer, integer, floating-point).
* **Call Kinds (`CallDescriptor::Kind`):**  Different types of calls (JS functions, code objects, runtime functions, WASM functions).
* **Frame Management:**  The code deals with setting up and managing call frames.
* **Tail Calls:** Optimization technique where a function call is the last operation, allowing for stack frame reuse.
* **Runtime Functions:** Built-in functions of V8.
* **Stubs:** Small pieces of pre-compiled code used for specific tasks.
* **OSR (On-Stack Replacement):** Optimizing code while it's running.
* **WASM (WebAssembly):** Support for WebAssembly calls.

**3. Deconstructing the Code Functionality (Mental Outline):**

Based on the keywords and structure, I can infer the following functional areas:

* **`CallDescriptor` Creation:**  The code likely contains functions to create and configure `CallDescriptor` objects for various call scenarios (JS, runtime, stubs, WASM). Functions like `GetJSCallDescriptor`, `GetRuntimeCallDescriptor`, `GetStubCallDescriptor` confirm this.
* **`CallDescriptor` Analysis:** Methods within `CallDescriptor` (and potentially related functions) probably analyze and manipulate `CallDescriptor` properties (e.g., `GetOffsetToReturns`, `CanTailCall`).
* **Linkage Management:** The `Linkage` class itself likely helps determine the appropriate calling conventions based on the context (e.g., `ComputeIncoming`).
* **Parameter and Return Value Handling:**  The code deals with the locations and types of parameters and return values.
* **Stack Frame Layout:**  Calculations like `CalculateFixedFrameSize` suggest involvement in determining the size and structure of call frames.
* **WASM Specifics:**  The `#if V8_ENABLE_WEBASSEMBLY` blocks indicate specialized logic for WebAssembly calls.

**4. Answering the Specific Questions:**

* **Functionality:** Based on the above analysis, I can now list the key functionalities of the file.
* **Torque:** The file ends with `.cc`, not `.tq`, so it's not a Torque file.
* **JavaScript Relationship:** The concepts of function calls, parameters, return values, and the different call types are directly related to how JavaScript code is executed. I need to provide concrete JavaScript examples that map to these concepts (e.g., calling a regular function, calling a built-in function).
* **Logical Reasoning:** I can choose a function like `CanTailCall` and provide hypothetical `CallDescriptor` inputs to illustrate its behavior.
* **Common Programming Errors:**  Relate the concepts to common mistakes developers make (e.g., incorrect number of arguments, type mismatches, stack overflow due to lack of tail call optimization).

**5. Refining the JavaScript Examples:**

I need to ensure the JavaScript examples are clear and directly illustrate the C++ code's functionality. For example, when discussing `CallDescriptor::kCallJSFunction`, a simple JavaScript function call is appropriate. For built-ins, examples like `Math.sqrt()` would work.

**6. Constructing the Logical Reasoning Example:**

For `CanTailCall`, I need to create two `CallDescriptor` examples – one where a tail call is possible and another where it's not, based on the return value locations.

**7. Identifying Common Programming Errors:**

I should focus on errors that relate to the concepts in the C++ code, such as:

* Passing the wrong number of arguments.
* Type mismatches (though JavaScript is dynamically typed, internal conversions might be relevant).
* Understanding the implications of stack frame size (leading to stack overflows).

**8. Structuring the Output:**

I'll organize the answer according to the prompt's questions: functionality, Torque, JavaScript examples, logical reasoning, and common errors. Using clear headings and bullet points will improve readability.

**Self-Correction/Refinement during thought process:**

* **Initial thought:**  Focus heavily on low-level details of registers and stack offsets.
* **Correction:**  While important, the high-level concepts of describing function calls are more crucial for a general understanding. I should explain the *purpose* of these details rather than just listing them.
* **Initial thought:**  Provide overly complex JavaScript examples.
* **Correction:**  Keep the JavaScript examples simple and focused on illustrating the specific concept.
* **Initial thought:**  Get bogged down in the intricacies of WASM.
* **Correction:**  Acknowledge the WASM-related code but keep the primary focus on the core call descriptor and linkage concepts.

By following this structured thought process, I can generate a comprehensive and accurate answer that addresses all aspects of the prompt.好的，让我们来分析一下 `v8/src/compiler/linkage.cc` 这个 V8 源代码文件的功能。

**文件功能概述**

`v8/src/compiler/linkage.cc` 文件的主要职责是定义和管理 V8 编译器中函数调用相关的接口和数据结构，特别是 `CallDescriptor` 类。它描述了如何在不同的调用场景下（例如，调用 JavaScript 函数、内置函数、运行时函数、WebAssembly 函数等）进行参数传递、返回值处理以及管理调用栈帧。

更具体地说，这个文件提供了以下关键功能：

1. **定义 `CallDescriptor` 类:**  `CallDescriptor` 是一个核心的数据结构，它封装了关于函数调用的所有必要信息，包括：
    * **调用类型 (`Kind`):**  例如 `kCallJSFunction` (调用 JavaScript 函数), `kCallCodeObject` (调用代码对象), `kCallRuntime` (调用运行时函数) 等。
    * **目标 (`target`):**  被调用函数的地址或代码对象。
    * **参数 (`parameters`):**  参数的个数、类型以及它们在寄存器或栈上的位置 (`LinkageLocation`)。
    * **返回值 (`returns`):** 返回值的个数、类型以及它们在寄存器或栈上的位置。
    * **调用约定:**  如何传递参数 (寄存器、栈)、哪些寄存器需要保存等。
    * **调试信息:**  例如函数名称。
    * **栈帧信息:**  与栈帧布局相关的属性。

2. **提供创建 `CallDescriptor` 的方法:**  文件中包含了多个静态方法，用于根据不同的调用场景创建合适的 `CallDescriptor` 对象，例如：
    * `Linkage::GetJSCallDescriptor`:  用于创建调用 JavaScript 函数的描述符。
    * `Linkage::GetRuntimeCallDescriptor`: 用于创建调用 V8 运行时函数的描述符。
    * `Linkage::GetStubCallDescriptor`: 用于创建调用代码桩 (stubs) 的描述符。
    * `Linkage::ComputeIncoming`:  用于计算进入已编译代码的调用描述符。

3. **定义 `LinkageLocation` 类:**  `LinkageLocation` 描述了数据（例如参数或返回值）在机器中的位置，可以是：
    * **寄存器:**  指定具体的寄存器和数据类型。
    * **栈帧槽位:**  指定相对于栈帧指针的偏移量和数据类型。

4. **支持尾调用优化:**  `CallDescriptor::CanTailCall` 方法用于判断当前调用是否可以进行尾调用优化，这有助于减少栈的使用。

5. **处理 WebAssembly 调用:**  通过 `#if V8_ENABLE_WEBASSEMBLY` 宏，文件中包含了处理 WebAssembly 函数调用的特定逻辑和 `CallDescriptor` 类型。

6. **计算栈帧大小:**  `CallDescriptor::CalculateFixedFrameSize` 方法用于计算不同类型调用的固定栈帧大小。

**关于文件类型和 JavaScript 关系**

* **文件类型:**  `v8/src/compiler/linkage.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**。如果它以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。 Torque 是一种用于生成 V8 代码的领域特定语言。

* **与 JavaScript 的关系:**  `v8/src/compiler/linkage.cc` 与 JavaScript 的功能 **密切相关**。它定义了 V8 引擎在执行 JavaScript 代码时如何进行函数调用的底层机制。  每当 JavaScript 代码中发生函数调用时，V8 的编译器就需要根据被调用函数的类型和参数等信息，创建一个 `CallDescriptor` 对象，以便生成正确的机器码来完成调用。

**JavaScript 举例说明**

以下 JavaScript 示例展示了 `v8/src/compiler/linkage.cc` 中概念的应用：

```javascript
function add(a, b) {
  return a + b;
}

function outer(x) {
  return add(x, 5); // 这里会发生一个函数调用
}

outer(10); // 这里也会发生一个函数调用

Math.sqrt(9); // 调用内置函数
```

在这个例子中：

* 调用 `add(x, 5)` 和 `outer(10)` 会触发 V8 编译器生成代码，并创建 `CallDescriptor` 对象。对于 `add` 函数，`CallDescriptor` 会描述如何传递参数 `x` 和 `5`，以及如何获取返回值。`CallDescriptor` 的 `kind` 可能是 `kCallJSFunction`。
* 调用 `Math.sqrt(9)` 会调用一个内置函数。编译器会创建一个不同的 `CallDescriptor`，其 `kind` 可能是 `kCallBuiltinPointer` 或其他相关的类型。这个描述符会指定调用内置函数的特定方式。

**代码逻辑推理**

让我们以 `CallDescriptor::CanTailCall` 方法为例进行代码逻辑推理。

**假设输入:**

* `caller_descriptor`:  一个 `CallDescriptor` 对象，描述了调用者函数的调用约定和返回值处理。
* `callee_descriptor`: 一个 `CallDescriptor` 对象，描述了被调用者函数的调用约定和返回值处理。

**方法 `CanTailCall` 的逻辑 (简化):**

```c++
bool CallDescriptor::CanTailCall(const CallDescriptor* callee) const {
  if (ReturnCount() != callee->ReturnCount()) return false; // 返回值数量必须相同

  const int stack_returns_delta =
      GetOffsetToReturns() - callee->GetOffsetToReturns();

  for (size_t i = 0; i < ReturnCount(); ++i) {
    if (GetReturnLocation(i).IsCallerFrameSlot() &&
        callee->GetReturnLocation(i).IsCallerFrameSlot()) {
      // 如果调用者和被调用者的返回值都在栈上
      if (GetReturnLocation(i).AsCallerFrameSlot() + stack_returns_delta !=
          callee->GetReturnLocation(i).AsCallerFrameSlot()) {
        return false; // 返回值在栈上的位置需要匹配
      }
    } else if (!LinkageLocation::IsSameLocation(GetReturnLocation(i),
                                                callee->GetReturnLocation(i))) {
      return false; // 返回值不在栈上，则它们的位置必须完全相同（例如，在同一个寄存器）
    }
  }
  return true; // 所有条件都满足，可以进行尾调用
}
```

**假设输入实例:**

* **`caller_descriptor` (调用者):**  假设一个函数 `outer`，它有一个返回值，并且这个返回值被放置在调用者的栈帧的某个位置 (例如，`LinkageLocation::ForCallerFrameSlot(-1, ...)`)。
* **`callee_descriptor` (被调用者):** 假设函数 `add`，它也有一个返回值，并且这个返回值也被放置在调用者的栈帧的另一个位置 (例如，`LinkageLocation::ForCallerFrameSlot(-1 + delta, ...)`，其中 `delta` 是栈偏移)。

**输出:**

* 如果 `caller_descriptor->ReturnCount()` 等于 `callee_descriptor->ReturnCount()`，并且返回值都在栈上，且它们在栈上的相对位置 `stack_returns_delta` 与实际的偏移量一致，则 `CanTailCall` 返回 `true`，表示可以进行尾调用优化。
* 否则，`CanTailCall` 返回 `false`。

**用户常见的编程错误**

虽然 `v8/src/compiler/linkage.cc` 是 V8 引擎的内部实现，但它所处理的概念与用户编写 JavaScript 代码时可能遇到的错误有关：

1. **参数数量不匹配:**  在 JavaScript 中调用函数时，如果传递的参数数量与函数定义的不符，V8 引擎会抛出错误。`CallDescriptor` 中记录了参数的数量，这与 V8 运行时的参数检查有关。

   ```javascript
   function greet(name) {
     console.log("Hello, " + name);
   }

   greet(); // 错误：期望 1 个参数，但只传递了 0 个
   greet("Alice", "Bob"); // 错误：期望 1 个参数，但传递了 2 个
   ```

2. **返回值处理不当 (虽然不是直接错误):**  虽然 JavaScript 是动态类型的，但理解函数如何返回值以及返回值在哪里被使用对于编写高效的代码很重要。`CallDescriptor` 描述了返回值的类型和位置，这与 V8 引擎如何处理返回值相关。

3. **栈溢出 (间接相关):**  如果函数调用链过深，没有进行尾调用优化，可能会导致栈溢出。`CallDescriptor::CanTailCall` 的逻辑直接影响了尾调用优化是否能够进行。

   ```javascript
   function recursiveFunction(n) {
     if (n <= 0) {
       return 0;
     }
     return 1 + recursiveFunction(n - 1); // 如果没有尾调用优化，n 很大时会导致栈溢出
   }

   recursiveFunction(10000); // 可能导致栈溢出
   ```

**总结**

`v8/src/compiler/linkage.cc` 是 V8 编译器中一个至关重要的文件，它定义了函数调用的抽象和实现细节。理解 `CallDescriptor` 及其相关概念有助于深入理解 V8 引擎如何执行 JavaScript 代码以及如何进行性能优化。虽然开发者通常不需要直接修改这个文件，但其背后的原理与编写高效且健壮的 JavaScript 代码息息相关。

### 提示词
```
这是目录为v8/src/compiler/linkage.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/linkage.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/linkage.h"

#include "src/builtins/builtins-descriptors.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/compiler/frame.h"
#include "src/compiler/globals.h"
#include "src/compiler/osr.h"
#include "src/compiler/pipeline.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/compiler/wasm-compiler-definitions.h"
#endif

namespace v8 {
namespace internal {
namespace compiler {

namespace {

// Offsets from callee to caller frame, in slots.
constexpr int kFirstCallerSlotOffset = 1;
constexpr int kNoCallerSlotOffset = 0;

inline LinkageLocation regloc(Register reg, MachineType type) {
  return LinkageLocation::ForRegister(reg.code(), type);
}

inline LinkageLocation regloc(DoubleRegister reg, MachineType type) {
  return LinkageLocation::ForRegister(reg.code(), type);
}

}  // namespace


std::ostream& operator<<(std::ostream& os, const CallDescriptor::Kind& k) {
  switch (k) {
    case CallDescriptor::kCallCodeObject:
      os << "Code";
      break;
    case CallDescriptor::kCallJSFunction:
      os << "JS";
      break;
    case CallDescriptor::kCallAddress:
      os << "Addr";
      break;
#if V8_ENABLE_WEBASSEMBLY
    case CallDescriptor::kCallWasmCapiFunction:
      os << "WasmExit";
      break;
    case CallDescriptor::kCallWasmFunction:
      os << "WasmFunction";
      break;
    case CallDescriptor::kCallWasmImportWrapper:
      os << "WasmImportWrapper";
      break;
#endif  // V8_ENABLE_WEBASSEMBLY
    case CallDescriptor::kCallBuiltinPointer:
      os << "BuiltinPointer";
      break;
  }
  return os;
}


std::ostream& operator<<(std::ostream& os, const CallDescriptor& d) {
  // TODO(svenpanne) Output properties etc. and be less cryptic.
  return os << d.kind() << ":" << d.debug_name() << ":r" << d.ReturnCount()
            << "s" << d.ParameterSlotCount() << "i" << d.InputCount() << "f"
            << d.FrameStateCount();
}

MachineSignature* CallDescriptor::GetMachineSignature(Zone* zone) const {
  size_t param_count = ParameterCount();
  size_t return_count = ReturnCount();
  MachineType* types =
      zone->AllocateArray<MachineType>(param_count + return_count);
  int current = 0;
  for (size_t i = 0; i < return_count; ++i) {
    types[current++] = GetReturnType(i);
  }
  for (size_t i = 0; i < param_count; ++i) {
    types[current++] = GetParameterType(i);
  }
  return zone->New<MachineSignature>(return_count, param_count, types);
}

int CallDescriptor::GetStackParameterDelta(
    CallDescriptor const* tail_caller) const {
  // In the IsTailCallForTierUp case, the callee has
  // identical linkage and runtime arguments to the caller, thus the stack
  // parameter delta is 0. We don't explicitly pass the runtime arguments as
  // inputs to the TailCall node, since they already exist on the stack.
  if (IsTailCallForTierUp()) return 0;

  // Add padding if necessary before computing the stack parameter delta.
  int callee_slots_above_sp = AddArgumentPaddingSlots(GetOffsetToReturns());
  int tail_caller_slots_above_sp =
      AddArgumentPaddingSlots(tail_caller->GetOffsetToReturns());
  int stack_param_delta = callee_slots_above_sp - tail_caller_slots_above_sp;
  DCHECK(!ShouldPadArguments(stack_param_delta));
  return stack_param_delta;
}

int CallDescriptor::GetOffsetToFirstUnusedStackSlot() const {
  int offset = kFirstCallerSlotOffset;
  for (size_t i = 0; i < InputCount(); ++i) {
    LinkageLocation operand = GetInputLocation(i);
    if (!operand.IsRegister()) {
      DCHECK(operand.IsCallerFrameSlot());
      int slot_offset = -operand.GetLocation();
      offset = std::max(offset, slot_offset + operand.GetSizeInPointers());
    }
  }
  return offset;
}

int CallDescriptor::GetOffsetToReturns() const {
  // Find the return slot with the least offset relative to the callee.
  int offset = kNoCallerSlotOffset;
  for (size_t i = 0; i < ReturnCount(); ++i) {
    LinkageLocation operand = GetReturnLocation(i);
    if (!operand.IsRegister()) {
      DCHECK(operand.IsCallerFrameSlot());
      int slot_offset = -operand.GetLocation();
      offset = std::min(offset, slot_offset);
    }
  }
  // If there was a return slot, return the offset minus 1 slot.
  if (offset != kNoCallerSlotOffset) {
    return offset - 1;
  }

  // Otherwise, return the first slot after the parameters area, including
  // optional padding slots.
  int last_argument_slot = GetOffsetToFirstUnusedStackSlot() - 1;
  offset = AddArgumentPaddingSlots(last_argument_slot);

  DCHECK_IMPLIES(offset == 0, ParameterSlotCount() == 0);
  return offset;
}

uint32_t CallDescriptor::GetTaggedParameterSlots() const {
  uint32_t count = 0;
  uint32_t untagged_count = 0;
  uint32_t first_offset = kMaxInt;
  for (size_t i = 0; i < InputCount(); ++i) {
    LinkageLocation operand = GetInputLocation(i);
    if (!operand.IsRegister()) {
      if (operand.GetType().IsTagged()) {
        ++count;
        // Caller frame slots have negative indices and start at -1. Flip it
        // back to a positive offset (to be added to the frame's SP to find the
        // slot).
        int slot_offset = -operand.GetLocation() - 1;
        DCHECK_GE(slot_offset, 0);
        first_offset =
            std::min(first_offset, static_cast<uint32_t>(slot_offset));
      } else {
        untagged_count += operand.GetSizeInPointers();
      }
    }
  }
  if (count == 0) {
    // If we don't have any tagged parameter slots, still initialize the offset
    // to point past the untagged parameter slots, so that
    // offset + count == stack slot count.
    first_offset = untagged_count;
  }
  DCHECK(first_offset != kMaxInt);
  return (first_offset << 16) | (count & 0xFFFFu);
}

bool CallDescriptor::CanTailCall(const CallDescriptor* callee) const {
  if (ReturnCount() != callee->ReturnCount()) return false;
  const int stack_returns_delta =
      GetOffsetToReturns() - callee->GetOffsetToReturns();
  for (size_t i = 0; i < ReturnCount(); ++i) {
    if (GetReturnLocation(i).IsCallerFrameSlot() &&
        callee->GetReturnLocation(i).IsCallerFrameSlot()) {
      if (GetReturnLocation(i).AsCallerFrameSlot() + stack_returns_delta !=
          callee->GetReturnLocation(i).AsCallerFrameSlot()) {
        return false;
      }
    } else if (!LinkageLocation::IsSameLocation(GetReturnLocation(i),
                                                callee->GetReturnLocation(i))) {
      return false;
    }
  }
  return true;
}

// TODO(jkummerow, sigurds): Arguably frame size calculation should be
// keyed on code/frame type, not on CallDescriptor kind. Think about a
// good way to organize this logic.
int CallDescriptor::CalculateFixedFrameSize(CodeKind code_kind) const {
  switch (kind_) {
    case kCallJSFunction:
      return StandardFrameConstants::kFixedSlotCount;
    case kCallAddress:
#if V8_ENABLE_WEBASSEMBLY
      if (code_kind == CodeKind::C_WASM_ENTRY) {
        return CWasmEntryFrameConstants::kFixedSlotCount;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      return CommonFrameConstants::kFixedSlotCountAboveFp +
             CommonFrameConstants::kCPSlotCount;
    case kCallCodeObject:
    case kCallBuiltinPointer:
      return TypedFrameConstants::kFixedSlotCount;
#if V8_ENABLE_WEBASSEMBLY
    case kCallWasmFunction:
    case kCallWasmImportWrapper:
      return WasmFrameConstants::kFixedSlotCount;
    case kCallWasmCapiFunction:
      return WasmExitFrameConstants::kFixedSlotCount;
#endif  // V8_ENABLE_WEBASSEMBLY
  }
  UNREACHABLE();
}

EncodedCSignature CallDescriptor::ToEncodedCSignature() const {
  int parameter_count = static_cast<int>(ParameterCount());
  EncodedCSignature sig(parameter_count);
  CHECK_LT(parameter_count, EncodedCSignature::kInvalidParamCount);

  for (int i = 0; i < parameter_count; ++i) {
    if (IsFloatingPoint(GetParameterType(i).representation())) {
      sig.SetFloat(i);
    }
  }
  if (ReturnCount() > 0) {
    DCHECK_EQ(1, ReturnCount());
    if (IsFloatingPoint(GetReturnType(0).representation())) {
      if (GetReturnType(0).representation() ==
          MachineRepresentation::kFloat64) {
        sig.SetReturnFloat64();
      } else {
        sig.SetReturnFloat32();
      }
    }
  }
  return sig;
}

void CallDescriptor::ComputeParamCounts() const {
  gp_param_count_ = 0;
  fp_param_count_ = 0;
  for (size_t i = 0; i < ParameterCount(); ++i) {
    if (IsFloatingPoint(GetParameterType(i).representation())) {
      ++fp_param_count_.value();
    } else {
      ++gp_param_count_.value();
    }
  }
}

#if V8_ENABLE_WEBASSEMBLY
namespace {
CallDescriptor* ReplaceTypeInCallDescriptorWith(
    Zone* zone, const CallDescriptor* call_descriptor, size_t num_replacements,
    MachineType from, MachineType to) {
  // The last parameter may be the special callable parameter. In that case we
  // have to preserve it as the last parameter, i.e. we allocate it in the new
  // location signature again in the same register.
  bool extra_callable_param =
      (call_descriptor->GetInputLocation(call_descriptor->InputCount() - 1) ==
       LinkageLocation::ForRegister(kJSFunctionRegister.code(),
                                    MachineType::TaggedPointer()));

  size_t return_count = call_descriptor->ReturnCount();
  // To recover the function parameter count, disregard the instance parameter,
  // and the extra callable parameter if present.
  size_t parameter_count =
      call_descriptor->ParameterCount() - (extra_callable_param ? 2 : 1);

  // Precompute if the descriptor contains {from}.
  bool needs_change = false;
  for (size_t i = 0; !needs_change && i < return_count; i++) {
    needs_change = call_descriptor->GetReturnType(i) == from;
  }
  for (size_t i = 1; !needs_change && i < parameter_count + 1; i++) {
    needs_change = call_descriptor->GetParameterType(i) == from;
  }
  if (!needs_change) return const_cast<CallDescriptor*>(call_descriptor);

  std::vector<MachineType> reps;

  for (size_t i = 0, limit = return_count; i < limit; i++) {
    MachineType initial_type = call_descriptor->GetReturnType(i);
    if (initial_type == from) {
      for (size_t j = 0; j < num_replacements; j++) reps.push_back(to);
      return_count += num_replacements - 1;
    } else {
      reps.push_back(initial_type);
    }
  }

  // Disregard the instance (first) parameter.
  for (size_t i = 1, limit = parameter_count + 1; i < limit; i++) {
    MachineType initial_type = call_descriptor->GetParameterType(i);
    if (initial_type == from) {
      for (size_t j = 0; j < num_replacements; j++) reps.push_back(to);
      parameter_count += num_replacements - 1;
    } else {
      reps.push_back(initial_type);
    }
  }

  MachineSignature sig(return_count, parameter_count, reps.data());

  int parameter_slots;
  int return_slots;
  LocationSignature* location_sig = BuildLocations(
      zone, &sig, extra_callable_param, &parameter_slots, &return_slots);

  return zone->New<CallDescriptor>(               // --
      call_descriptor->kind(),                    // kind
      call_descriptor->tag(),                     // tag
      call_descriptor->GetInputType(0),           // target MachineType
      call_descriptor->GetInputLocation(0),       // target location
      location_sig,                               // location_sig
      parameter_slots,                            // parameter slot count
      call_descriptor->properties(),              // properties
      call_descriptor->CalleeSavedRegisters(),    // callee-saved registers
      call_descriptor->CalleeSavedFPRegisters(),  // callee-saved fp regs
      call_descriptor->flags(),                   // flags
      call_descriptor->debug_name(),              // debug name
      call_descriptor->GetStackArgumentOrder(),   // stack order
      call_descriptor->AllocatableRegisters(),    // allocatable registers
      return_slots);                              // return slot count
}
}  // namespace

CallDescriptor* GetI32WasmCallDescriptor(
    Zone* zone, const CallDescriptor* call_descriptor) {
  return ReplaceTypeInCallDescriptorWith(
      zone, call_descriptor, 2, MachineType::Int64(), MachineType::Int32());
}
#endif

CallDescriptor* Linkage::ComputeIncoming(Zone* zone,
                                         OptimizedCompilationInfo* info) {
#if V8_ENABLE_WEBASSEMBLY
  DCHECK(info->IsOptimizing() || info->IsWasm());
#else
  DCHECK(info->IsOptimizing());
#endif  // V8_ENABLE_WEBASSEMBLY
  if (!info->closure().is_null()) {
    // If we are compiling a JS function, use a JS call descriptor,
    // plus the receiver.
    DCHECK(info->has_bytecode_array());
    DCHECK_EQ(info->closure()
                  ->shared()
                  ->internal_formal_parameter_count_with_receiver(),
              info->bytecode_array()->parameter_count());
    return GetJSCallDescriptor(zone, info->is_osr(),
                               info->bytecode_array()->parameter_count(),
                               CallDescriptor::kCanUseRoots);
  }
  return nullptr;  // TODO(titzer): ?
}


// static
bool Linkage::NeedsFrameStateInput(Runtime::FunctionId function) {
  switch (function) {
    // Most runtime functions need a FrameState. A few chosen ones that we know
    // not to call into arbitrary JavaScript, not to throw, and not to lazily
    // deoptimize are allowlisted here and can be called without a FrameState.
    case Runtime::kAbort:
    case Runtime::kAllocateInOldGeneration:
    case Runtime::kCreateIterResultObject:
    case Runtime::kGrowableSharedArrayBufferByteLength:
    case Runtime::kIncBlockCounter:
    case Runtime::kNewClosure:
    case Runtime::kNewClosure_Tenured:
    case Runtime::kNewFunctionContext:
    case Runtime::kPushBlockContext:
    case Runtime::kPushCatchContext:
    case Runtime::kReThrow:
    case Runtime::kReThrowWithMessage:
    case Runtime::kStringEqual:
    case Runtime::kStringLessThan:
    case Runtime::kStringLessThanOrEqual:
    case Runtime::kStringGreaterThan:
    case Runtime::kStringGreaterThanOrEqual:
    case Runtime::kToFastProperties:  // TODO(conradw): Is it safe?
    case Runtime::kTraceEnter:
    case Runtime::kTraceExit:
      return false;

    // Some inline intrinsics are also safe to call without a FrameState.
    case Runtime::kInlineCreateIterResultObject:
    case Runtime::kInlineIncBlockCounter:
    case Runtime::kInlineGeneratorClose:
    case Runtime::kInlineGeneratorGetResumeMode:
    case Runtime::kInlineCreateJSGeneratorObject:
      return false;

    default:
      break;
  }

  // For safety, default to needing a FrameState unless allowlisted.
  return true;
}

CallDescriptor* Linkage::GetRuntimeCallDescriptor(
    Zone* zone, Runtime::FunctionId function_id, int js_parameter_count,
    Operator::Properties properties, CallDescriptor::Flags flags,
    LazyDeoptOnThrow lazy_deopt_on_throw) {
  const Runtime::Function* function = Runtime::FunctionForId(function_id);
  const int return_count = function->result_size;
  const char* debug_name = function->name;

  if (lazy_deopt_on_throw == LazyDeoptOnThrow::kNo &&
      !Linkage::NeedsFrameStateInput(function_id)) {
    flags = static_cast<CallDescriptor::Flags>(
        flags & ~CallDescriptor::kNeedsFrameState);
  }

  DCHECK_IMPLIES(lazy_deopt_on_throw == LazyDeoptOnThrow::kYes,
                 flags & CallDescriptor::kNeedsFrameState);

  return GetCEntryStubCallDescriptor(zone, return_count, js_parameter_count,
                                     debug_name, properties, flags);
}

CallDescriptor* Linkage::GetCEntryStubCallDescriptor(
    Zone* zone, int return_count, int js_parameter_count,
    const char* debug_name, Operator::Properties properties,
    CallDescriptor::Flags flags, StackArgumentOrder stack_order) {
  const size_t function_count = 1;
  const size_t num_args_count = 1;
  const size_t context_count = 1;
  const size_t parameter_count = function_count +
                                 static_cast<size_t>(js_parameter_count) +
                                 num_args_count + context_count;

  LocationSignature::Builder locations(zone, static_cast<size_t>(return_count),
                                       static_cast<size_t>(parameter_count));

  // Add returns.
  if (locations.return_count_ > 0) {
    locations.AddReturn(regloc(kReturnRegister0, MachineType::AnyTagged()));
  }
  if (locations.return_count_ > 1) {
    locations.AddReturn(regloc(kReturnRegister1, MachineType::AnyTagged()));
  }
  if (locations.return_count_ > 2) {
    locations.AddReturn(regloc(kReturnRegister2, MachineType::AnyTagged()));
  }

  // All parameters to the runtime call go on the stack.
  for (int i = 0; i < js_parameter_count; i++) {
    locations.AddParam(LinkageLocation::ForCallerFrameSlot(
        i - js_parameter_count, MachineType::AnyTagged()));
  }
  // Add runtime function itself.
  locations.AddParam(
      regloc(kRuntimeCallFunctionRegister, MachineType::Pointer()));

  // Add runtime call argument count.
  locations.AddParam(
      regloc(kRuntimeCallArgCountRegister, MachineType::Int32()));

  // Add context.
  locations.AddParam(regloc(kContextRegister, MachineType::AnyTagged()));

  // The target for runtime calls is a code object.
  MachineType target_type = MachineType::AnyTagged();
  LinkageLocation target_loc =
      LinkageLocation::ForAnyRegister(MachineType::AnyTagged());
  return zone->New<CallDescriptor>(     // --
      CallDescriptor::kCallCodeObject,  // kind
      kDefaultCodeEntrypointTag,        // tag
      target_type,                      // target MachineType
      target_loc,                       // target location
      locations.Get(),                  // location_sig
      js_parameter_count,               // stack_parameter_count
      properties,                       // properties
      kNoCalleeSaved,                   // callee-saved
      kNoCalleeSavedFp,                 // callee-saved fp
      flags,                            // flags
      debug_name,                       // debug name
      stack_order);                     // stack order
}

CallDescriptor* Linkage::GetJSCallDescriptor(Zone* zone, bool is_osr,
                                             int js_parameter_count,
                                             CallDescriptor::Flags flags,
                                             Operator::Properties properties) {
  const size_t return_count = 1;
  const size_t context_count = 1;
  const size_t new_target_count = 1;
  const size_t num_args_count = 1;
  const size_t dispatch_handle_count = V8_ENABLE_LEAPTIERING_BOOL ? 1 : 0;
  const size_t parameter_count = js_parameter_count + new_target_count +
                                 num_args_count + dispatch_handle_count +
                                 context_count;

  // The JSCallDescriptor must be compatible both with the interface descriptor
  // of JS builtins and with the general JS calling convention (as defined by
  // the JSTrampolineDescriptor). The JS builtin descriptors are already
  // statically asserted to be compatible with the JS calling convention, so
  // here we just ensure compatibility with the JS builtin descriptors.
  DCHECK_EQ(parameter_count, kJSBuiltinBaseParameterCount + js_parameter_count);

  LocationSignature::Builder locations(zone, return_count, parameter_count);

  // All JS calls have exactly one return value.
  locations.AddReturn(regloc(kReturnRegister0, MachineType::AnyTagged()));

  // All parameters to JS calls go on the stack.
  for (int i = 0; i < js_parameter_count; i++) {
    int spill_slot_index = -i - 1;
    locations.AddParam(LinkageLocation::ForCallerFrameSlot(
        spill_slot_index, MachineType::AnyTagged()));
  }

  // Add JavaScript call new target value.
  locations.AddParam(
      regloc(kJavaScriptCallNewTargetRegister, MachineType::AnyTagged()));

  // Add JavaScript call argument count.
  locations.AddParam(
      regloc(kJavaScriptCallArgCountRegister, MachineType::Int32()));

#ifdef V8_ENABLE_LEAPTIERING
  // Add dispatch handle.
  locations.AddParam(
      regloc(kJavaScriptCallDispatchHandleRegister, MachineType::Int32()));
#endif

  // Add context.
  locations.AddParam(regloc(kContextRegister, MachineType::AnyTagged()));

  // The target for JS function calls is the JSFunction object.
  MachineType target_type = MachineType::AnyTagged();
  // When entering into an OSR function from unoptimized code the JSFunction
  // is not in a register, but it is on the stack in the marker spill slot.
  // For kind == JSDescKind::kBuiltin, we should still use the regular
  // kJSFunctionRegister, so that frame attribution for stack traces works.
  LinkageLocation target_loc = is_osr
                                   ? LinkageLocation::ForSavedCallerFunction()
                                   : regloc(kJSFunctionRegister, target_type);
  CallDescriptor::Kind descriptor_kind = CallDescriptor::kCallJSFunction;
  return zone->New<CallDescriptor>(  // --
      descriptor_kind,               // kind
      kJSEntrypointTag,              // tag
      target_type,                   // target MachineType
      target_loc,                    // target location
      locations.Get(),               // location_sig
      js_parameter_count,            // stack_parameter_count
      properties,                    // properties
      kNoCalleeSaved,                // callee-saved
      kNoCalleeSavedFp,              // callee-saved fp
      flags,                         // flags
      "js-call");                    // debug name
}

// TODO(turbofan): cache call descriptors for code stub calls.
// TODO(jgruber): Clean up stack parameter count handling. The descriptor
// already knows the formal stack parameter count and ideally only additional
// stack parameters should be passed into this method. All call-sites should
// be audited for correctness (e.g. many used to assume a stack parameter count
// of 0).
CallDescriptor* Linkage::GetStubCallDescriptor(
    Zone* zone, const CallInterfaceDescriptor& descriptor,
    int stack_parameter_count, CallDescriptor::Flags flags,
    Operator::Properties properties, StubCallMode stub_mode) {
  const int register_parameter_count = descriptor.GetRegisterParameterCount();
  const int js_parameter_count =
      register_parameter_count + stack_parameter_count;
  const int context_count = descriptor.HasContextParameter() ? 1 : 0;
  const size_t parameter_count =
      static_cast<size_t>(js_parameter_count + context_count);

  DCHECK_GE(stack_parameter_count, descriptor.GetStackParameterCount());

  int return_count = descriptor.GetReturnCount();
  LocationSignature::Builder locations(zone, return_count, parameter_count);

  // Add returns.
  for (int i = 0; i < return_count; i++) {
    MachineType type = descriptor.GetReturnType(static_cast<int>(i));
    if (IsFloatingPoint(type.representation())) {
      DoubleRegister reg = descriptor.GetDoubleRegisterReturn(i);
      locations.AddReturn(regloc(reg, type));
    } else {
      Register reg = descriptor.GetRegisterReturn(i);
      locations.AddReturn(regloc(reg, type));
    }
  }

  // Add parameters in registers and on the stack.
  for (int i = 0; i < js_parameter_count; i++) {
    if (i < register_parameter_count) {
      // The first parameters go in registers.
      MachineType type = descriptor.GetParameterType(i);
      if (IsFloatingPoint(type.representation())) {
        DoubleRegister reg = descriptor.GetDoubleRegisterParameter(i);
        locations.AddParam(regloc(reg, type));
      } else {
        Register reg = descriptor.GetRegisterParameter(i);
        locations.AddParam(regloc(reg, type));
      }
    } else {
      // The rest of the parameters go on the stack.
      int stack_slot = i - register_parameter_count - stack_parameter_count;
      locations.AddParam(LinkageLocation::ForCallerFrameSlot(
          stack_slot, i < descriptor.GetParameterCount()
                          ? descriptor.GetParameterType(i)
                          : MachineType::AnyTagged()));
    }
  }

  // Add context.
  if (context_count) {
    locations.AddParam(regloc(kContextRegister, MachineType::AnyTagged()));
  }

  // The target for stub calls depends on the requested mode.
  CallDescriptor::Kind kind;
  MachineType target_type;
  switch (stub_mode) {
    case StubCallMode::kCallCodeObject:
      kind = CallDescriptor::kCallCodeObject;
      target_type = MachineType::AnyTagged();
      break;
#if V8_ENABLE_WEBASSEMBLY
    case StubCallMode::kCallWasmRuntimeStub:
      kind = CallDescriptor::kCallWasmFunction;
      target_type = MachineType::WasmCodePointer();
      break;
#endif  // V8_ENABLE_WEBASSEMBLY
    case StubCallMode::kCallBuiltinPointer:
      kind = CallDescriptor::kCallBuiltinPointer;
      target_type = MachineType::AnyTagged();
      break;
  }

  RegList allocatable_registers = descriptor.allocatable_registers();
  RegList callee_saved_registers = kNoCalleeSaved;
  if (descriptor.CalleeSaveRegisters()) {
    callee_saved_registers = allocatable_registers;
    DCHECK(!callee_saved_registers.is_empty());
  }
  LinkageLocation target_loc = LinkageLocation::ForAnyRegister(target_type);
  return zone->New<CallDescriptor>(          // --
      kind,                                  // kind
      descriptor.tag(),                      // tag
      target_type,                           // target MachineType
      target_loc,                            // target location
      locations.Get(),                       // location_sig
      stack_parameter_count,                 // stack_parameter_count
      properties,                            // properties
      callee_saved_registers,                // callee-saved registers
      kNoCalleeSavedFp,                      // callee-saved fp
      CallDescriptor::kCanUseRoots | flags,  // flags
      descriptor.DebugName(),                // debug name
      descriptor.GetStackArgumentOrder(),    // stack order
      allocatable_registers);
}

// static
CallDescriptor* Linkage::GetBytecodeDispatchCallDescriptor(
    Zone* zone, const CallInterfaceDescriptor& descriptor,
    int stack_parameter_count) {
  const int register_parameter_count = descriptor.GetRegisterParameterCount();
  const int parameter_count = register_parameter_count + stack_parameter_count;

  DCHECK_EQ(descriptor.GetReturnCount(), 1);
  LocationSignature::Builder locations(zone, 1, parameter_count);

  locations.AddReturn(regloc(kReturnRegister0, descriptor.GetReturnType(0)));

  // Add parameters in registers and on the stack.
  for (int i = 0; i < parameter_count; i++) {
    if (i < register_parameter_count) {
      // The first parameters go in registers.
      Register reg = descriptor.GetRegisterParameter(i);
      MachineType type = descriptor.GetParameterType(i);
      locations.AddParam(regloc(reg, type));
    } else {
      // The rest of the parameters go on the stack.
      int stack_slot = i - register_parameter_count - stack_parameter_count;
      locations.AddParam(LinkageLocation::ForCallerFrameSlot(
          stack_slot, MachineType::AnyTagged()));
    }
  }

  // The target for interpreter dispatches is a code entry address.
  MachineType target_type = MachineType::Pointer();
  LinkageLocation target_loc = LinkageLocation::ForAnyRegister(target_type);
  const CallDescriptor::Flags kFlags =
      CallDescriptor::kCanUseRoots | CallDescriptor::kFixedTargetRegister;
  return zone->New<CallDescriptor>(   // --
      CallDescriptor::kCallAddress,   // kind
      kBytecodeHandlerEntrypointTag,  // tag
      target_type,                    // target MachineType
      target_loc,                     // target location
      locations.Get(),                // location_sig
      stack_parameter_count,          // stack_parameter_count
      Operator::kNoProperties,        // properties
      kNoCalleeSaved,                 // callee-saved registers
      kNoCalleeSavedFp,               // callee-saved fp
      kFlags,                         // flags
      descriptor.DebugName());
}

LinkageLocation Linkage::GetOsrValueLocation(int index) const {
  CHECK(incoming_->IsJSFunctionCall());
  int parameter_count_with_receiver =
      static_cast<int>(incoming_->JSParameterCount());
  int first_stack_slot =
      OsrHelper::FirstStackSlotIndex(parameter_count_with_receiver - 1);

  if (index == kOsrContextSpillSlotIndex) {
    int context_index =
        Linkage::GetJSCallContextParamIndex(parameter_count_with_receiver);
    return GetParameterLocation(context_index);
  } else if (index >= first_stack_slot) {
    // Local variable stored in this (callee) stack.
    int spill_index =
        index - first_stack_slot + StandardFrameConstants::kFixedSlotCount;
    return LinkageLocation::ForCalleeFrameSlot(spill_index,
                                               MachineType::AnyTagged());
  } else {
    // Parameter. Use the assigned location from the incoming call descriptor.
    return GetParameterLocation(index);
  }
}

namespace {
inline bool IsTaggedReg(const LinkageLocation& loc, Register reg) {
  return loc.IsRegister() && loc.AsRegister() == reg.code() &&
         loc.GetType().representation() ==
             MachineRepresentation::kTaggedPointer;
}
}  // namespace

bool Linkage::ParameterHasSecondaryLocation(int index) const {
  // TODO(titzer): this should be configurable, not call-type specific.
  if (incoming_->IsJSFunctionCall()) {
    LinkageLocation loc = GetParameterLocation(index);
    return IsTaggedReg(loc, kJSFunctionRegister) ||
           IsTaggedReg(loc, kContextRegister);
  }
#if V8_ENABLE_WEBASSEMBLY
  if (incoming_->IsWasmFunctionCall()) {
    LinkageLocation loc = GetParameterLocation(index);
    return IsTaggedReg(loc, kWasmImplicitArgRegister);
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  return false;
}

LinkageLocation Linkage::GetParameterSecondaryLocation(int index) const {
  // TODO(titzer): these constants are necessary due to offset/slot# mismatch
  static const int kJSContextSlot = 2 + StandardFrameConstants::kCPSlotCount;
  static const int kJSFunctionSlot = 3 + StandardFrameConstants::kCPSlotCount;

  DCHECK(ParameterHasSecondaryLocation(index));
  LinkageLocation loc = GetParameterLocation(index);

  // TODO(titzer): this should be configurable, not call-type specific.
  if (incoming_->IsJSFunctionCall()) {
    if (IsTaggedReg(loc, kJSFunctionRegister)) {
      return LinkageLocation::ForCalleeFrameSlot(kJSFunctionSlot,
                                                 MachineType::AnyTagged());
    } else {
      DCHECK(IsTaggedReg(loc, kContextRegister));
      return LinkageLocation::ForCalleeFrameSlot(kJSContextSlot,
                                                 MachineType::AnyTagged());
    }
  }
#if V8_ENABLE_WEBASSEMBLY
  static const int kWasmInstanceDataSlot =
      3 + StandardFrameConstants::kCPSlotCount;
  if (incoming_->IsWasmFunctionCall()) {
    DCHECK(IsTaggedReg(loc, kWasmImplicitArgRegister));
    return LinkageLocation::ForCalleeFrameSlot(kWasmInstanceDataSlot,
                                               MachineType::AnyTagged());
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  UNREACHABLE();
}


}  // namespace compiler
}  // namespace internal
}  // namespace v8
```