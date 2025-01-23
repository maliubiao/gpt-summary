Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understanding the Goal:** The request asks for the functionality of `fast-api-calls.cc` and its relation to JavaScript, exemplified by a JavaScript snippet.

2. **Initial Scan and Keywords:**  I'll quickly scan the code for prominent keywords and patterns. I see:
    * `FastApiCall` (repeatedly)
    * `compiler` (part of the file path and namespace)
    * `CTypeInfo`
    * `Local`, `MaybeLocal` (handle types)
    * `v8` (namespace and mentions of V8 internals)
    * `JavaScript` (implied context)
    * `Build` (a key function)
    * `GetParameter`, `ConvertReturnValue`, `InitializeOptions`, `GenerateSlowApiCall` (functional interfaces)
    * `TypedArray` (related to `GetTypedArrayElementsKind`)
    * `CanOptimizeFastSignature` (suggests performance optimization)
    * Assembly-like code (`gasm()->`, `__ Store`, `__ Load`, `__ Call`)

3. **Inferring the Core Functionality:** The name `fast-api-calls` and the internal usage of "fast call" strongly suggest this code is about optimizing calls from JavaScript to C++ (or potentially other native code). The presence of `GenerateSlowApiCall` implies a fallback mechanism when the "fast path" isn't possible.

4. **Analyzing Key Sections:**

    * **Assertions:** The `ASSERT_TRIVIALLY_COPYABLE` lines are about ensuring efficient data passing, likely related to how arguments are passed between JavaScript and C++. This reinforces the idea of performance optimization.

    * **`GetTypedArrayElementsKind`:** This function maps C++ type information (`CTypeInfo::Type`) to JavaScript TypedArray element kinds (e.g., `UINT8_ELEMENTS`). This directly connects to how JavaScript TypedArrays are handled in the C++ layer.

    * **`CanOptimizeFastSignature`:** This function checks various conditions (architecture, floating-point parameters, argument counts) to determine if a "fast call" is feasible. This confirms the optimization focus. The `#ifdef` directives suggest platform-specific considerations.

    * **`FastApiCallBuilder` Class:** This class seems to orchestrate the process of building the fast API call. The constructor takes function pointers (`GetParameter`, etc.), suggesting a configurable or modular approach. The `Build` method is likely the main entry point.

    * **`WrapFastCall`:** This function seems to handle the actual generation of the assembly code for the fast call, including CPU profiling support.

    * **`PropagateException`:**  This clearly deals with propagating exceptions from the C++ side back to JavaScript.

    * **`Build` Method (within `FastApiCallBuilder`):** This method is the most complex. It appears to:
        * Determine if a fast path is possible.
        * Retrieve parameters from JavaScript.
        * Potentially allocate a stack slot for options.
        * Build a `CallDescriptor` for the C++ function.
        * Generate the assembly code for the fast call.
        * Check for exceptions after the call.
        * Handle the fallback to the "slow call" if errors occur.
        * Convert the C++ return value back to a JavaScript value.

5. **Identifying the JavaScript Connection:** The core connection is enabling efficient calls from JavaScript to native C++ functions. The `GetTypedArrayElementsKind` function provides a concrete example of how JavaScript data types (TypedArrays) are represented in the C++ code. The concepts of parameters and return values also directly relate to how JavaScript functions interact with native code.

6. **Formulating the Summary:** Based on the analysis, I can summarize the file's purpose as optimizing calls from JavaScript to C++ by generating specialized "fast paths."  The summary should mention the key components and their roles (checking signatures, building the call, handling errors, converting types).

7. **Creating the JavaScript Example:** To illustrate the connection, I need a JavaScript example that demonstrates how a native C++ function might be called. The example should cover:
    * Declaring a native function (using `dlsym` or a similar mechanism, although the actual linking isn't shown in the C++ code).
    * Passing parameters (including different data types).
    * Receiving a return value.
    * Ideally, an example involving TypedArrays to connect with `GetTypedArrayElementsKind`.

    A simple example could involve a function that adds two numbers. To make it more relevant to the V8 context, demonstrating interaction with TypedArrays or objects could be beneficial. The provided example of squaring elements in a TypedArray is a good choice because it links to the `GetTypedArrayElementsKind` function. It also shows passing data to the native function and receiving a result.

8. **Refining the Explanation:**  After drafting the summary and example, I'll review them for clarity and accuracy. I'll ensure the language is accessible and avoids unnecessary jargon. I'll also make sure the JavaScript example clearly shows the interaction with the C++ code's functionality. I should highlight that the C++ code is part of V8's *internal* mechanisms and is not directly exposed for typical JavaScript development.

This structured approach, starting with a high-level overview and then drilling down into specific code sections, helps to effectively analyze and understand the purpose of the C++ file and its relationship to JavaScript.
这个C++源代码文件 `fast-api-calls.cc` 的主要功能是**优化从 JavaScript 调用 C++ (Native) 函数的性能**。它旨在为特定的 C++ 函数生成更高效的调用路径，称为“快速 API 调用”。

以下是其功能的详细归纳：

**核心功能:**

1. **判断是否可以进行快速调用 (`CanOptimizeFastSignature`)**:  此函数检查给定的 C++ 函数签名 (`CFunctionInfo`) 是否满足可以进行快速调用的条件。这些条件可能包括：
    * 参数和返回值的类型是否是基本类型或 V8 内部可以高效处理的类型。
    * 架构特定的限制（例如，某些架构上对参数数量或浮点参数的支持）。
    * 某些编译选项的启用状态。
    * 是否需要特定的 CPU 特性（例如 SSE4.2）。

2. **构建快速调用 (`FastApiCallBuilder::Build`)**: 如果 C++ 函数满足快速调用的条件，这个方法会生成执行快速调用的代码。这涉及到：
    * **获取参数**:  从 JavaScript 传递过来的参数会被高效地提取出来。
    * **准备调用描述符 (`CallDescriptor`)**:  描述了如何调用 C++ 函数，包括参数和返回值的类型信息。
    * **生成机器码**:  使用 `GraphAssembler` 生成实际的机器指令来调用 C++ 函数。
    * **处理异常**:  在快速调用之后检查 C++ 函数是否抛出了异常，并将异常传播回 JavaScript。
    * **转换返回值 (`convert_return_value_`)**:  将 C++ 函数的返回值转换回 JavaScript 可以理解的值。

3. **处理慢速调用 (`generate_slow_api_call_`)**:  如果 C++ 函数不满足快速调用的条件，或者快速调用失败（例如，类型不匹配），代码会回退到传统的、更通用的 C++ 调用机制（慢速调用）。

4. **类型转换 (`GetTypedArrayElementsKind`)**:  此函数用于将 C++ 中的 `CTypeInfo::Type` 类型映射到 JavaScript 中 `TypedArray` 的元素类型 (例如 `UINT8_ELEMENTS`, `INT32_ELEMENTS`)。这对于在 C++ 函数中高效处理 JavaScript 的 `TypedArray` 对象非常重要。

5. **支持 `FastApiCallbackOptions`**:  对于某些需要额外选项的快速调用，代码会处理 `v8::FastApiCallbackOptions` 结构体，允许在调用 C++ 函数时传递额外的数据。

**与 JavaScript 的关系及示例:**

此代码直接影响 JavaScript 调用 C++ 函数的性能。当 JavaScript 代码调用一个通过 V8 的 Native API (例如 Node.js 的 Addon) 暴露的 C++ 函数时，V8 内部会尝试使用这里实现的快速调用优化。

**JavaScript 示例:**

假设我们有一个 Node.js C++ Addon，其中定义了一个 C++ 函数 `SquareArrayElements`，它接受一个 `Uint32Array` 并返回一个新的 `Uint32Array`，其中每个元素都是输入数组的平方。

**C++ (Addon 代码片段 - 简化示例):**

```c++
#include <node_api.h>
#include <vector>

napi_value SquareArrayElements(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

  if (argc < 1) {
    napi_throw_error(env, nullptr, "Wrong number of arguments");
    return nullptr;
  }

  bool is_typed_array;
  napi_is_typedarray(env, args[0], &is_typed_array);
  if (!is_typed_array) {
    napi_throw_type_error(env, nullptr, "Argument must be a Uint32Array");
    return nullptr;
  }

  napi_typedarray_type type;
  size_t byte_length;
  void* data;
  size_t length;
  napi_get_typedarray_info(env, args[0], &type, &byte_length, &data, &length);

  if (type != napi_uint32_array) {
    napi_throw_type_error(env, nullptr, "Argument must be a Uint32Array");
    return nullptr;
  }

  uint32_t* input_array = static_cast<uint32_t*>(data);
  std::vector<uint32_t> result_vector;
  result_vector.reserve(length);
  for (size_t i = 0; i < length; ++i) {
    result_vector.push_back(input_array[i] * input_array[i]);
  }

  napi_value result_array;
  napi_create_typed_array(env, napi_uint32_array, length, &result_array, nullptr);
  uint32_t* output_array;
  napi_get_typedarray_info(env, result_array, &type, &byte_length, (void**)&output_array, &length);

  for (size_t i = 0; i < length; ++i) {
    output_array[i] = result_vector[i];
  }

  return result_array;
}

napi_value Init(napi_env env, napi_value exports) {
  napi_value fn;
  napi_create_function(env, nullptr, 0, SquareArrayElements, nullptr, &fn);
  napi_set_named_property(env, exports, "squareArrayElements", fn);
  return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)
```

**JavaScript (调用 Addon):**

```javascript
const addon = require('./build/Release/my_addon'); // 假设你的 addon 编译后的路径

const inputArray = new Uint32Array([1, 2, 3, 4, 5]);
console.log("Input Array:", inputArray);

const squaredArray = addon.squareArrayElements(inputArray);
console.log("Squared Array:", squaredArray);
```

**`fast-api-calls.cc` 的作用:**

当 JavaScript 代码调用 `addon.squareArrayElements(inputArray)` 时，V8 的编译器会尝试优化这个调用。如果 `SquareArrayElements` 函数的签名和使用方式满足 `fast-api-calls.cc` 中 `CanOptimizeFastSignature` 的条件（例如，参数是 `Uint32Array`，返回值也是 `Uint32Array` 或可以高效转换的类型），V8 可能会使用这里生成的快速调用路径。

**快速调用的好处:**

* **减少开销**: 避免了标准 C++ 函数调用的一些通用性检查和转换步骤。
* **更直接的内存访问**:  对于 `TypedArray` 这样的数据结构，可以生成更直接的内存访问指令。
* **潜在的内联**:  在某些情况下，快速调用可能会更容易被内联，进一步提高性能。

总之，`v8/src/compiler/fast-api-calls.cc` 是 V8 引擎中一个关键的性能优化组件，它专注于使 JavaScript 调用 Native C++ 代码更加高效，特别是对于涉及到基本数据类型和 `TypedArray` 的场景。 它通过生成专门的、更精简的调用代码路径来实现这一点。

### 提示词
```
这是目录为v8/src/compiler/fast-api-calls.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/fast-api-calls.h"

#include "src/codegen/cpu-features.h"
#include "src/compiler/globals.h"

namespace v8 {

// Local handles should be trivially copyable so that the contained value can be
// efficiently passed by value in a register. This is important for two
// reasons: better performance and a simpler ABI for generated code and fast
// API calls.
ASSERT_TRIVIALLY_COPYABLE(api_internal::IndirectHandleBase);
#ifdef V8_ENABLE_DIRECT_HANDLE
ASSERT_TRIVIALLY_COPYABLE(api_internal::DirectHandleBase);
#endif
ASSERT_TRIVIALLY_COPYABLE(LocalBase<Object>);

#if !(defined(V8_ENABLE_LOCAL_OFF_STACK_CHECK) && V8_HAS_ATTRIBUTE_TRIVIAL_ABI)
// Direct local handles should be trivially copyable, for the same reasons as
// above. In debug builds, however, where we want to check that such handles are
// stack-allocated, we define a non-default copy constructor and destructor.
// This makes them non-trivially copyable. We only do it in builds where we can
// declare them as "trivial ABI", which guarantees that they can be efficiently
// passed by value in a register.
ASSERT_TRIVIALLY_COPYABLE(Local<Object>);
ASSERT_TRIVIALLY_COPYABLE(internal::LocalUnchecked<Object>);
ASSERT_TRIVIALLY_COPYABLE(MaybeLocal<Object>);
#endif

namespace internal {
namespace compiler {
namespace fast_api_call {

ElementsKind GetTypedArrayElementsKind(CTypeInfo::Type type) {
  switch (type) {
    case CTypeInfo::Type::kUint8:
      return UINT8_ELEMENTS;
    case CTypeInfo::Type::kInt32:
      return INT32_ELEMENTS;
    case CTypeInfo::Type::kUint32:
      return UINT32_ELEMENTS;
    case CTypeInfo::Type::kInt64:
      return BIGINT64_ELEMENTS;
    case CTypeInfo::Type::kUint64:
      return BIGUINT64_ELEMENTS;
    case CTypeInfo::Type::kFloat32:
      return FLOAT32_ELEMENTS;
    case CTypeInfo::Type::kFloat64:
      return FLOAT64_ELEMENTS;
    case CTypeInfo::Type::kVoid:
    case CTypeInfo::Type::kSeqOneByteString:
    case CTypeInfo::Type::kBool:
    case CTypeInfo::Type::kPointer:
    case CTypeInfo::Type::kV8Value:
    case CTypeInfo::Type::kApiObject:
    case CTypeInfo::Type::kAny:
      UNREACHABLE();
  }
}

bool CanOptimizeFastSignature(const CFunctionInfo* c_signature) {
  USE(c_signature);

#if defined(V8_OS_MACOS) && defined(V8_TARGET_ARCH_ARM64)
  // On MacArm64 hardware we don't support passing of arguments on the stack.
  if (c_signature->ArgumentCount() > 8) {
    return false;
  }
#endif  // defined(V8_OS_MACOS) && defined(V8_TARGET_ARCH_ARM64)

#ifndef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
  if (c_signature->ReturnInfo().GetType() == CTypeInfo::Type::kFloat32 ||
      c_signature->ReturnInfo().GetType() == CTypeInfo::Type::kFloat64) {
    return false;
  }
#endif

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  if (!v8_flags.fast_api_allow_float_in_sim &&
      (c_signature->ReturnInfo().GetType() == CTypeInfo::Type::kFloat32 ||
       c_signature->ReturnInfo().GetType() == CTypeInfo::Type::kFloat64)) {
    return false;
  }
#endif

#ifndef V8_TARGET_ARCH_64_BIT
  if (c_signature->ReturnInfo().GetType() == CTypeInfo::Type::kInt64 ||
      c_signature->ReturnInfo().GetType() == CTypeInfo::Type::kUint64) {
    return false;
  }
#endif

  for (unsigned int i = 0; i < c_signature->ArgumentCount(); ++i) {
    USE(i);

#ifdef V8_TARGET_ARCH_X64
    // Clamp lowering in EffectControlLinearizer uses rounding.
    uint8_t flags = uint8_t(c_signature->ArgumentInfo(i).GetFlags());
    if (flags & uint8_t(CTypeInfo::Flags::kClampBit)) {
      return CpuFeatures::IsSupported(SSE4_2);
    }
#endif  // V8_TARGET_ARCH_X64

#ifndef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
    if (c_signature->ArgumentInfo(i).GetType() == CTypeInfo::Type::kFloat32 ||
        c_signature->ArgumentInfo(i).GetType() == CTypeInfo::Type::kFloat64) {
      return false;
    }
#endif

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
    if (!v8_flags.fast_api_allow_float_in_sim &&
        (c_signature->ArgumentInfo(i).GetType() == CTypeInfo::Type::kFloat32 ||
         c_signature->ArgumentInfo(i).GetType() == CTypeInfo::Type::kFloat64)) {
      return false;
    }
#endif

#ifndef V8_TARGET_ARCH_64_BIT
    if (c_signature->ArgumentInfo(i).GetType() == CTypeInfo::Type::kInt64 ||
        c_signature->ArgumentInfo(i).GetType() == CTypeInfo::Type::kUint64) {
      return false;
    }
#endif
  }

  return true;
}

#define __ gasm()->

class FastApiCallBuilder {
 public:
  FastApiCallBuilder(Isolate* isolate, Graph* graph,
                     GraphAssembler* graph_assembler,
                     const GetParameter& get_parameter,
                     const ConvertReturnValue& convert_return_value,
                     const InitializeOptions& initialize_options,
                     const GenerateSlowApiCall& generate_slow_api_call)
      : isolate_(isolate),
        graph_(graph),
        graph_assembler_(graph_assembler),
        get_parameter_(get_parameter),
        convert_return_value_(convert_return_value),
        initialize_options_(initialize_options),
        generate_slow_api_call_(generate_slow_api_call) {}

  Node* Build(FastApiCallFunction c_function, Node* data_argument);

 private:
  Node* WrapFastCall(const CallDescriptor* call_descriptor, int inputs_size,
                     Node** inputs, Node* target,
                     const CFunctionInfo* c_signature, int c_arg_count,
                     Node* stack_slot);
  void PropagateException();

  Isolate* isolate() const { return isolate_; }
  Graph* graph() const { return graph_; }
  GraphAssembler* gasm() const { return graph_assembler_; }
  Isolate* isolate_;
  Graph* graph_;
  GraphAssembler* graph_assembler_;
  const GetParameter& get_parameter_;
  const ConvertReturnValue& convert_return_value_;
  const InitializeOptions& initialize_options_;
  const GenerateSlowApiCall& generate_slow_api_call_;
};

Node* FastApiCallBuilder::WrapFastCall(const CallDescriptor* call_descriptor,
                                       int inputs_size, Node** inputs,
                                       Node* target,
                                       const CFunctionInfo* c_signature,
                                       int c_arg_count, Node* stack_slot) {
  // CPU profiler support
  Node* target_address = __ IsolateField(IsolateFieldId::kFastApiCallTarget);
  __ Store(StoreRepresentation(MachineType::PointerRepresentation(),
                               kNoWriteBarrier),
           target_address, 0, __ BitcastTaggedToWord(target));

  // Update effect and control
  if (stack_slot != nullptr) {
    inputs[c_arg_count + 1] = stack_slot;
    inputs[c_arg_count + 2] = __ effect();
    inputs[c_arg_count + 3] = __ control();
  } else {
    inputs[c_arg_count + 1] = __ effect();
    inputs[c_arg_count + 2] = __ control();
  }

  // Create the fast call
  Node* call = __ Call(call_descriptor, inputs_size, inputs);

  // Reset the CPU profiler target address.
  __ Store(StoreRepresentation(MachineType::PointerRepresentation(),
                               kNoWriteBarrier),
           target_address, 0, __ IntPtrConstant(0));

  return call;
}

void FastApiCallBuilder::PropagateException() {
  Runtime::FunctionId fun_id = Runtime::FunctionId::kPropagateException;
  const Runtime::Function* fun = Runtime::FunctionForId(fun_id);
  auto call_descriptor = Linkage::GetRuntimeCallDescriptor(
      graph()->zone(), fun_id, fun->nargs, Operator::kNoProperties,
      CallDescriptor::kNoFlags);
  // The CEntryStub is loaded from the IsolateRoot so that generated code is
  // Isolate independent. At the moment this is only done for CEntryStub(1).
  Node* isolate_root = __ LoadRootRegister();
  DCHECK_EQ(1, fun->result_size);
  auto centry_id = Builtin::kWasmCEntry;
  int builtin_slot_offset = IsolateData::BuiltinSlotOffset(centry_id);
  Node* centry_stub =
      __ Load(MachineType::Pointer(), isolate_root, builtin_slot_offset);
  const int kInputCount = 6;
  Node* inputs[kInputCount];
  int count = 0;
  inputs[count++] = centry_stub;
  inputs[count++] = __ ExternalConstant(ExternalReference::Create(fun_id));
  inputs[count++] = __ Int32Constant(fun->nargs);
  inputs[count++] = __ IntPtrConstant(0);
  inputs[count++] = __ effect();
  inputs[count++] = __ control();
  DCHECK_EQ(kInputCount, count);

  __ Call(call_descriptor, count, inputs);
}

Node* FastApiCallBuilder::Build(FastApiCallFunction c_function,
                                Node* data_argument) {
  const CFunctionInfo* c_signature = c_function.signature;
  const int c_arg_count = c_signature->ArgumentCount();

  // Hint to fast path.
  auto if_success = __ MakeLabel();
  auto if_error = __ MakeDeferredLabel();

  // Generate fast call.

  const int kFastTargetAddressInputIndex = 0;
  const int kFastTargetAddressInputCount = 1;

  const int kEffectAndControlInputCount = 2;

  int extra_input_count =
      kEffectAndControlInputCount + (c_signature->HasOptions() ? 1 : 0);

  Node** const inputs = graph()->zone()->AllocateArray<Node*>(
      kFastTargetAddressInputCount + c_arg_count + extra_input_count);

  ExternalReference::Type ref_type = ExternalReference::FAST_C_CALL;

  // The inputs to {Call} node for the fast call look like:
  // [fast callee, receiver, ... C arguments, [optional Options], effect,
  //  control].
  //
  // The first input node represents the target address for the fast call.
  // If the function is not overloaded (c_functions.size() == 1) this is the
  // address associated to the first and only element in the c_functions vector.
  // If there are multiple overloads the value of this input will be set later
  // with a Phi node created by AdaptOverloadedFastCallArgument.
  inputs[kFastTargetAddressInputIndex] = __ ExternalConstant(
      ExternalReference::Create(c_function.address, ref_type));

  for (int i = 0; i < c_arg_count; ++i) {
    inputs[i + kFastTargetAddressInputCount] = get_parameter_(i, &if_error);
  }
  DCHECK_NOT_NULL(inputs[kFastTargetAddressInputIndex]);

  MachineSignature::Builder builder(
      graph()->zone(), 1, c_arg_count + (c_signature->HasOptions() ? 1 : 0));
  MachineType return_type =
      MachineType::TypeForCType(c_signature->ReturnInfo());
  builder.AddReturn(return_type);
  for (int i = 0; i < c_arg_count; ++i) {
    CTypeInfo type = c_signature->ArgumentInfo(i);
    MachineType machine_type =
        type.GetSequenceType() == CTypeInfo::SequenceType::kScalar
            ? MachineType::TypeForCType(type)
            : MachineType::AnyTagged();
    builder.AddParam(machine_type);
  }

  Node* stack_slot = nullptr;
  if (c_signature->HasOptions()) {
    const int kAlign = alignof(v8::FastApiCallbackOptions);
    const int kSize = sizeof(v8::FastApiCallbackOptions);
    // If this check fails, you've probably added new fields to
    // v8::FastApiCallbackOptions, which means you'll need to write code
    // that initializes and reads from them too.
    static_assert(kSize == sizeof(uintptr_t) * 2);
    stack_slot = __ StackSlot(kSize, kAlign);

    __ Store(StoreRepresentation(MachineType::PointerRepresentation(),
                                 kNoWriteBarrier),
             stack_slot,
             static_cast<int>(offsetof(v8::FastApiCallbackOptions, isolate)),
             __ ExternalConstant(ExternalReference::isolate_address()));

    Node* data_argument_to_pass = __ AdaptLocalArgument(data_argument);

    __ Store(StoreRepresentation(MachineType::PointerRepresentation(),
                                 kNoWriteBarrier),
             stack_slot,
             static_cast<int>(offsetof(v8::FastApiCallbackOptions, data)),
             data_argument_to_pass);

    initialize_options_(stack_slot);

    builder.AddParam(MachineType::Pointer());  // stack_slot
  }

  CallDescriptor* call_descriptor =
      Linkage::GetSimplifiedCDescriptor(graph()->zone(), builder.Get());

  Node* c_call_result =
      WrapFastCall(call_descriptor, c_arg_count + extra_input_count + 1, inputs,
                   inputs[0], c_signature, c_arg_count, stack_slot);

  Node* exception = __ Load(MachineType::IntPtr(),
                            __ ExternalConstant(ExternalReference::Create(
                                IsolateAddressId::kExceptionAddress, isolate_)),
                            0);

  Node* the_hole =
      __ Load(MachineType::IntPtr(), __ LoadRootRegister(),
              IsolateData::root_slot_offset(RootIndex::kTheHoleValue));

  auto throw_label = __ MakeDeferredLabel();
  auto done = __ MakeLabel();
  __ GotoIfNot(__ IntPtrEqual(exception, the_hole), &throw_label);
  __ Goto(&done);

  __ Bind(&throw_label);
  PropagateException();
  __ Unreachable();

  __ Bind(&done);
  Node* fast_call_result = convert_return_value_(c_signature, c_call_result);

  auto merge = __ MakeLabel(MachineRepresentation::kTagged);
  __ Goto(&if_success);

  // We need to generate a fallback (both fast and slow call) in case
  // the generated code might fail, in case e.g. a Smi was passed where
  // a JSObject was expected and an error must be thrown
  if (if_error.IsUsed()) {
    // Generate direct slow call.
    __ Bind(&if_error);
    {
      Node* slow_call_result = generate_slow_api_call_();
      __ Goto(&merge, slow_call_result);
    }
  }

  __ Bind(&if_success);
  __ Goto(&merge, fast_call_result);

  __ Bind(&merge);
  return merge.PhiAt(0);
}

#undef __

Node* BuildFastApiCall(Isolate* isolate, Graph* graph,
                       GraphAssembler* graph_assembler,
                       FastApiCallFunction c_function, Node* data_argument,
                       const GetParameter& get_parameter,
                       const ConvertReturnValue& convert_return_value,
                       const InitializeOptions& initialize_options,
                       const GenerateSlowApiCall& generate_slow_api_call) {
  FastApiCallBuilder builder(isolate, graph, graph_assembler, get_parameter,
                             convert_return_value, initialize_options,
                             generate_slow_api_call);
  return builder.Build(c_function, data_argument);
}

}  // namespace fast_api_call
}  // namespace compiler
}  // namespace internal
}  // namespace v8
```