Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The primary goal is to understand the functionality of the `linkage.cc` file within the V8 JavaScript engine's compiler and explain its relationship to JavaScript, providing a concrete example.

2. **Initial Skim for Keywords and Structure:**  I'd first quickly scan the code for important keywords and structural elements:
    * `#include`:  This tells me about dependencies. I see includes like `compiler/frame.h`, `codegen/assembler-inl.h`, `builtins/builtins-descriptors.h`, `compiler/osr.h`, suggesting this file deals with how function calls are set up and managed within the compiler. The `wasm` includes indicate WebAssembly support.
    * `namespace v8::internal::compiler`:  This clearly positions the code within the V8 compiler.
    * `class CallDescriptor`: This class appears central. I'd pay close attention to its methods.
    * `class Linkage`:  Another key class, likely related to `CallDescriptor`.
    * `enum CallDescriptor::Kind`: This suggests different types of function calls.
    * `std::ostream& operator<<`: Overloaded output operators hint at debugging and logging functionality.
    * Static methods like `Linkage::ComputeIncoming`, `Linkage::GetRuntimeCallDescriptor`, `Linkage::GetJSCallDescriptor`, `Linkage::GetStubCallDescriptor`: These are entry points for creating `CallDescriptor` objects for different scenarios.

3. **Focus on `CallDescriptor`:**  This class seems to be the core concept. I'd look at its methods:
    * `GetMachineSignature`:  Deals with function signatures (return types and parameter types).
    * `GetStackParameterDelta`, `GetOffsetToFirstUnusedStackSlot`, `GetOffsetToReturns`:  These methods relate to managing the call stack.
    * `CanTailCall`:  Indicates support for tail call optimization.
    * `CalculateFixedFrameSize`:  Determines the size of the stack frame for different call types.
    * `ToEncodedCSignature`: Likely for interoperability with C code.

4. **Focus on `Linkage`:**  This class seems to be the factory or manager for `CallDescriptor` objects. I'd look at its key static methods:
    * `ComputeIncoming`:  Determines the incoming call linkage for a compiled function.
    * `GetRuntimeCallDescriptor`, `GetJSCallDescriptor`, `GetStubCallDescriptor`, `GetBytecodeDispatchCallDescriptor`:  These methods create `CallDescriptor` instances for different call scenarios (runtime functions, JavaScript functions, stubs, bytecode dispatch).

5. **Infer Functionality -  Connecting the Dots:** Based on the methods and class names, I'd start forming a high-level understanding:
    * **Call Setup:** The code is about how the V8 compiler sets up function calls. This includes managing the stack, registers, and arguments.
    * **Different Call Types:**  The `CallDescriptor::Kind` enum shows that V8 handles different kinds of calls (JS functions, C functions, WebAssembly functions, built-ins).
    * **Optimization:** Features like tail call optimization (`CanTailCall`) and On-Stack Replacement (OSR, mentioned in `Linkage::ComputeIncoming` and `Linkage::GetOsrValueLocation`) suggest optimization is a key concern.
    * **Interoperability:** The WebAssembly and C function call types point to V8's ability to interact with code outside of JavaScript.
    * **Frame Management:**  Methods calculating frame sizes indicate the file's role in stack frame layout.

6. **Identify the Relationship to JavaScript:** The most direct connection is the `Linkage::GetJSCallDescriptor` method. This explicitly creates `CallDescriptor` objects for JavaScript function calls. The management of parameters and return values is crucial for correctly executing JavaScript functions. The concept of the "stack" is fundamental to how JavaScript function calls work.

7. **Develop a JavaScript Example:** To illustrate the connection, I'd think about a simple JavaScript function call and how the concepts in `linkage.cc` apply:
    * A basic function with parameters and a return value is a good starting point.
    *  The idea of passing arguments, the function's execution context, and the eventual return value are directly managed by the mechanisms described in the C++ code.
    * The example should highlight concepts like the stack, arguments, return values, and potentially the context (`this`).

8. **Refine the Summary:** Based on the analysis, I'd structure the summary to cover the key areas:
    * Core purpose (managing function call setup).
    * Key class (`CallDescriptor`).
    * Different call types.
    * Relationship to JavaScript (focus on `GetJSCallDescriptor`).
    * Mention of optimization and interoperability.

9. **Review and Iterate:** I'd reread the code and the generated summary to ensure accuracy and clarity. I would check if the JavaScript example effectively illustrates the concepts. For instance, I might initially forget to mention the context (`this`) in the JavaScript example and then add it upon review. I might also refine the language in the summary for better readability.

This structured approach, starting with a high-level overview and then drilling down into specific components, combined with the goal of connecting the C++ code to JavaScript functionality, allows for a comprehensive understanding and effective explanation.
这个C++源代码文件 `linkage.cc` 的主要功能是**定义和管理函数调用的链接 (linkage) 信息**，这是 V8 编译器中一个至关重要的部分。它定义了在编译后的代码中，如何调用不同的函数，包括 JavaScript 函数、C++ 内置函数（runtime functions）、以及 WebAssembly 函数等。

更具体地说，`linkage.cc` 做了以下几件事：

1. **定义了 `CallDescriptor` 类:**  这是核心类，用于描述一个函数调用的所有关键信息，例如：
    * **调用类型 (`CallDescriptor::Kind`)**:  指示被调用的函数是 JavaScript 函数、C++ 代码对象、C++ 函数地址、WebAssembly 函数等等。
    * **参数和返回值的位置 (`LinkageLocation`)**:  指定参数和返回值是存储在寄存器中还是栈上的特定位置。
    * **参数和返回值的类型 (`MachineType`)**:  描述参数和返回值的机器类型（例如，整数、浮点数、指针等）。
    * **栈参数数量 (`ParameterSlotCount`)**:  指定在栈上传递的参数数量。
    * **是否需要帧状态 (`kNeedsFrameState`)**:  指示调用是否需要保存当前的帧状态，用于调试和异常处理。
    * **调试名称 (`debug_name`)**:  用于调试和日志输出。

2. **提供了创建 `CallDescriptor` 对象的静态方法:** `Linkage` 类包含一系列静态方法，用于根据不同的调用场景创建合适的 `CallDescriptor` 对象：
    * **`ComputeIncoming`**:  计算正在编译的函数的入口调用描述符。
    * **`GetRuntimeCallDescriptor`**:  创建调用 C++ runtime 函数的描述符。
    * **`GetCEntryStubCallDescriptor`**:  创建调用 C++ 入口桩代码的描述符。
    * **`GetJSCallDescriptor`**:  创建调用 JavaScript 函数的描述符。
    * **`GetStubCallDescriptor`**:  创建调用代码桩 (stub) 的描述符，例如调用内置函数。
    * **`GetBytecodeDispatchCallDescriptor`**: 创建用于字节码分发的调用描述符。

3. **处理不同的调用约定:**  不同的函数调用类型可能使用不同的调用约定（例如，参数传递方式、返回值位置等）。`linkage.cc` 负责处理这些差异，确保编译器能够生成正确的调用代码。

4. **支持 WebAssembly 调用:**  文件中包含了对 WebAssembly 函数调用的特殊处理，例如 `kCallWasmFunction` 等 `CallDescriptor::Kind` 类型，以及创建 WebAssembly 调用描述符的方法。

5. **支持尾调用优化:**  `CanTailCall` 方法用于判断是否可以进行尾调用优化。

**它与 JavaScript 的功能关系密切。**  `linkage.cc` 中最重要的部分之一就是 **`Linkage::GetJSCallDescriptor` 方法**。这个方法负责创建描述 JavaScript 函数调用的 `CallDescriptor` 对象。当 V8 编译器需要编译一段包含函数调用的 JavaScript 代码时，它会使用 `GetJSCallDescriptor` 来确定如何设置这次调用，包括：

* **参数的传递方式**:  JavaScript 函数的参数通常通过栈传递。
* **`this` 值的传递**:  `this` 值也会作为参数传递。
* **上下文 (context) 的传递**:  JavaScript 的执行需要上下文信息。
* **返回值的处理**:  JavaScript 函数的返回值通常存储在特定的寄存器中。

**JavaScript 举例说明:**

假设有以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 3);
```

当 V8 编译器编译这段代码时，在编译 `add(5, 3)` 这个函数调用时，`Linkage::GetJSCallDescriptor` 方法会被调用，生成一个 `CallDescriptor` 对象，用于描述这次调用。这个 `CallDescriptor` 对象会包含以下信息（简化）：

* **`kind`**:  `CallDescriptor::kCallJSFunction`，表示这是一个 JavaScript 函数调用。
* **目标函数位置**:  指向 `add` 函数的代码对象。
* **参数位置**:  `a` (值 5) 和 `b` (值 3) 将会被放置在栈上的特定位置。
* **上下文位置**:  当前执行上下文的信息。
* **返回值位置**:  计算结果 (8) 将会被放置在特定的寄存器中，以便后续使用。

编译器会根据这个 `CallDescriptor` 对象生成相应的机器码，确保在运行时能够正确地调用 `add` 函数，传递参数，并获取返回值。

**更进一步的例子，涉及到 `this` 和上下文：**

```javascript
const obj = {
  value: 10,
  increment(amount) {
    this.value += amount;
    return this.value;
  }
};

let newValue = obj.increment(5);
```

当编译 `obj.increment(5)` 时，生成的 `CallDescriptor` 会包含如何传递 `obj` 作为 `this` 值的信息，以及如何传递当前的执行上下文。

**总结来说，`linkage.cc` 是 V8 编译器中负责规范和描述函数调用方式的关键组件。它定义了 `CallDescriptor` 类来表示调用的各种属性，并提供了创建不同类型调用描述符的方法，其中与 JavaScript 最直接相关的是 `GetJSCallDescriptor`，它确保了 JavaScript 函数能够被正确地调用和执行。**

Prompt: 
```
这是目录为v8/src/compiler/linkage.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```