Response:
Let's break down the thought process for analyzing the provided C++ header file.

1. **Initial Understanding of the Request:** The request asks for the functionality of a V8 source file, specifically focusing on its role in the compiler, its potential relation to JavaScript, and common programming errors it might help prevent or handle. It also mentions `.tq` files (Torque) which isn't applicable here but signals a need to look for code generation or lowering aspects.

2. **Identifying the File's Purpose (Header File Clues):** The file name `fast-api-call-lowering-reducer.h` is very informative.
    * `fast-api-call`:  This immediately suggests dealing with calls to C++ functions exposed to JavaScript (Fast API calls).
    * `lowering`: This strongly indicates a compiler optimization or transformation phase, converting a higher-level representation to a lower-level one closer to machine code.
    * `reducer`: In the context of compilers (especially Turboshaft, which is mentioned in the path), "reducer" often refers to a component that simplifies or rewrites the intermediate representation of the code.

3. **Analyzing the Includes:** The included headers provide further context:
    * `include/v8-fast-api-calls.h`:  Confirms the focus on Fast API calls.
    * `src/compiler/fast-api-calls.h`: More internal details about Fast API calls within the compiler.
    * `src/compiler/globals.h`: Basic compiler definitions.
    * `src/compiler/turboshaft/...`:  Confirms this is part of the Turboshaft compiler pipeline. The specific includes like `assembler.h`, `operations.h`, and `representations.h` point to code generation and manipulation of an intermediate representation.

4. **Examining the Class Structure:** The core of the file is the `FastApiCallLoweringReducer` class. The template structure `template <typename Next> class FastApiCallLoweringReducer : public Next` suggests a chain of responsibility or a pipeline pattern, where this reducer is one step.

5. **Focusing on the `REDUCE(FastApiCall)` Method:** This method is the heart of the reducer. Its name and signature are key:
    * `REDUCE(FastApiCall)`:  Indicates that this reducer handles `FastApiCall` operations in the intermediate representation.
    * Input parameters: `frame_state`, `data_argument`, `context`, `arguments`, `parameters`, `out_reps`. These suggest it's processing information about a call site, including arguments, context, and metadata about the target C++ function.
    * Return type: `OpIndex`. This likely represents an operation or a tuple of operations in the compiler's intermediate representation.

6. **Deconstructing the `REDUCE` Method's Logic:**
    * **Getting C++ function details:** It extracts the C++ function address (`c_function`) and signature (`c_signature`) from the `parameters`.
    * **Error Handling:** The `handle_error` label and the checks like `V8_LIKELY(!__ generating_unreachable_operations())` highlight the importance of handling potential mismatches between JavaScript and C++ types.
    * **Argument Adaptation (`AdaptFastCallArgument`):** This is a crucial part. It iterates through the arguments and calls `AdaptFastCallArgument`. This suggests type conversion or checking is happening to bridge the gap between JavaScript values and the expected C++ types. The `TryTruncateFloat64ToInt32` family of functions further reinforces this.
    * **Building the Call:** It constructs a `TSCallDescriptor` and then uses `WrapFastCall` to create the actual call operation in the intermediate representation.
    * **Exception Handling:** The code checks for exceptions after the C++ call using `IsolateAddressId::kExceptionAddress`.
    * **Return Value Handling (`ConvertReturnValue`):**  The `ConvertReturnValue` function handles converting the C++ return value back into a JavaScript-compatible value.
    * **Default Return Values:** The `DefaultReturnValue` function provides fallback values in case of errors.

7. **Analyzing Helper Methods:** The private helper methods provide more detail about the lowering process:
    * `Checked`:  Handles the result of "try" operations, branching to the error handler if needed.
    * `AdaptFastCallArgument`:  Performs the type adaptation for individual arguments. The switch statement and the checks for `kEnforceRangeBit`, `kClampBit`, and specific types (`kV8Value`, `kPointer`, `kSeqOneByteString`) are key to understanding the conversion logic.
    * `ClampFastCallArgument`: Implements clamping of values to specific ranges.
    * `DefaultReturnValue`: Provides default return values based on the C++ function's signature.
    * `ConvertReturnValue`: Converts the raw C++ return value to a JavaScript value.
    * `BuildAllocateJSExternalObject`: Handles the allocation of `JSExternalObject` for returning C++ pointers to JavaScript.
    * `WrapFastCall`:  Creates the actual call operation, including handling CPU profiler setup and context switching.

8. **Connecting to JavaScript:** The functionality is directly related to calling C++ functions from JavaScript using the Fast API. The type adaptation logic ensures that JavaScript values are correctly converted to the expected C++ types, and vice-versa for return values.

9. **Identifying Potential Programming Errors:** The code directly addresses potential type mismatches and range errors that can occur when calling C++ from JavaScript. For example, passing a floating-point number to a C++ function expecting an integer might lead to truncation or errors, which this code tries to handle gracefully. Passing incorrect object types (e.g., a plain object instead of a `JSArray`) is another area addressed by the checks in `AdaptFastCallArgument`.

10. **Constructing Examples and Explanations:** Based on the analysis, I would then construct JavaScript examples demonstrating how these Fast API calls might be used and the types of errors the reducer helps prevent. The code logic inference would involve tracing the execution flow through the `REDUCE` method with hypothetical inputs.

11. **Review and Refinement:** Finally, I'd review my analysis to ensure clarity, accuracy, and completeness, making sure I've addressed all aspects of the original request. For example, double-checking if the file is a `.tq` file (it's not) and explicitly stating that.
This header file, `v8/src/compiler/turboshaft/fast-api-call-lowering-reducer.h`, defines a **Turboshaft compiler phase** called `FastApiCallLoweringReducer`. Its primary function is to **lower (transform) high-level `FastApiCall` operations in the Turboshaft intermediate representation (IR) into lower-level operations** that can be more directly translated into machine code.

Here's a breakdown of its functionalities:

* **Lowering `FastApiCall` Operations:**  The core responsibility is to take a `FastApiCall` operation and convert it into a sequence of lower-level operations. This involves:
    * **Preparing Arguments:**  Adapting JavaScript values passed as arguments to the Fast API call to the expected C++ types. This might involve type conversions, checks, and potentially allocating stack space for passing complex types.
    * **Generating the Actual C++ Call:**  Creating the necessary IR instructions to perform the actual call to the C++ function. This involves setting up the call frame, passing arguments according to the calling convention, and invoking the function.
    * **Handling Return Values:** Converting the C++ return value back into a JavaScript-representable value. This might involve boxing primitive types into objects or creating specific JavaScript objects to represent C++ data structures.
    * **Error Handling:**  Inserting checks and conditional branches to handle potential errors during the Fast API call, such as type mismatches or exceptions thrown by the C++ function.

* **Type Adaptation:** A significant part of the lowering process is adapting JavaScript values to the types expected by the C++ function signature. The `AdaptFastCallArgument` method handles this, performing conversions and checks based on the `CTypeInfo` of the expected C++ argument. This includes:
    * **Scalar Types:** Handling conversions for integers (int32, uint32, int64, uint64), floats (float32, float64), booleans, and pointers. It can enforce ranges, clamp values, or perform direct type conversions.
    * **String Types:**  Specifically handling `SeqOneByteString` by creating a structure on the stack containing the data pointer and length.
    * **Object Types:** Checking for specific JavaScript object types like `JSArray` and potentially adapting them.
    * **External Objects:**  Handling pointers by ensuring they are `JSExternalObject` instances or null.

* **Generating Machine Code Constructs:** The reducer utilizes the Turboshaft `Assembler` to generate low-level operations like:
    * `ExternalConstant`: To represent the address of the C++ function.
    * `Call`: To generate the actual function call.
    * `StackSlot`: To allocate space on the stack for passing arguments or temporary values.
    * `StoreOffHeap`: To write data to memory locations.
    * `Load`: To read data from memory locations.
    * `TaggedEqual`, `ObjectIsSmi`, `Word32Equal`, etc.: For type checks and comparisons.
    * `GOTO`, `BIND`, `GOTO_IF`, etc.: For control flow.

* **Integration with Turboshaft Pipeline:**  As a "reducer," it fits into the Turboshaft compilation pipeline, taking higher-level IR as input and producing lower-level IR as output. The `<typename Next>` template parameter suggests a chain-of-responsibility pattern where this reducer operates before another phase (`Next`).

**Is it a Torque source file?**

No, the file `v8/src/compiler/turboshaft/fast-api-call-lowering-reducer.h` ends with `.h`, which signifies a **C++ header file**. Torque source files typically end with `.tq`.

**Relationship with Javascript and Javascript Example:**

This file is **directly related to JavaScript**. It deals with the mechanism of efficiently calling C++ functions from JavaScript code using the Fast API.

Here's a JavaScript example illustrating the concept:

```javascript
// Assume we have a C++ function registered as a Fast API call
// that takes an integer and returns its square.

// In C++ (simplified example):
// extern "C" int Square(int x) {
//   return x * x;
// }

// In JavaScript:
const fastApi = {
  square: (x) => %FastApiCall(0, null, fastApi.square, x) // Hypothetical %FastApiCall intrinsic
};

console.log(fastApi.square(5)); // This will execute the C++ Square function
```

In this example, when `fastApi.square(5)` is called, the JavaScript engine (V8) will recognize it as a Fast API call. The `FastApiCallLoweringReducer` will then be responsible for generating the low-level instructions to:

1. **Adapt the JavaScript integer `5`** to the C++ `int` type.
2. **Call the `Square` C++ function.**
3. **Adapt the C++ integer return value** back to a JavaScript number.

**Code Logic Inference with Hypothetical Input and Output:**

Let's consider a simplified scenario:

**Hypothetical Input (Turboshaft IR `FastApiCall` Operation):**

*   `frame_state`: Represents the current state of the execution stack.
*   `data_argument`:  Potentially some data passed along with the call (often null).
*   `context`: The current JavaScript context.
*   `arguments`: A vector containing the JavaScript value `5` (represented in Turboshaft IR).
*   `parameters`:  Information about the `Square` C++ function, including its address and signature (taking an `int32_t` and returning an `int32_t`).
*   `out_reps`: Information about the expected output representation.

**Processing within `FastApiCallLoweringReducer`:**

1. The `REDUCE(FastApiCall)` method is invoked.
2. It retrieves the C++ function address and signature from `parameters`.
3. `AdaptFastCallArgument` is called for the argument `5`. Since the C++ function expects an `int32_t`, and assuming the JavaScript value can be represented as such, it might generate a `ReversibleFloat64ToInt32` operation (if the JavaScript number is a float64 internally) or simply use the existing representation.
4. A `TSCallDescriptor` is created describing the call to the C++ function.
5. `WrapFastCall` generates the actual `Call` operation in the IR, passing the adapted argument.

**Hypothetical Output (Lowered Turboshaft IR):**

*   A sequence of operations including:
    *   Potentially `ReversibleFloat64ToInt32` for the argument `5`.
    *   `ExternalConstant` representing the address of the `Square` function.
    *   A `Call` operation with the `Square` function as the callee and the adapted argument.
    *   Potentially some operation to convert the `int32_t` return value back to a JavaScript number.

**User-Common Programming Errors and Examples:**

This code helps prevent errors related to **mismatched types between JavaScript and C++**. Here are some examples of programming errors this reducer helps manage:

1. **Incorrect Argument Types:**

    ```javascript
    // C++ function expects an integer
    const fastApi = {
      processInteger: (x) => %FastApiCall(0, null, fastApi.processInteger, x)
    };

    fastApi.processInteger("not an integer"); //  JavaScript doesn't have static typing
    ```

    The `FastApiCallLoweringReducer` will try to convert the string `"not an integer"` to an integer. Depending on the `CTypeInfo` and the flags, it might:

    *   **Throw an error:** If strict type checking is enforced.
    *   **Return a default value:** If the signature allows for it.
    *   **Perform a best-effort conversion:** Which might lead to unexpected results (e.g., `NaN`).

2. **Out-of-Range Values:**

    ```javascript
    // C++ function expects a uint8_t (0-255)
    const fastApi = {
      setByteValue: (value) => %FastApiCall(0, null, fastApi.setByteValue, value)
    };

    fastApi.setByteValue(300); //  Value exceeds the range of uint8_t
    ```

    If the `CTypeInfo` for the `setByteValue` function's argument has the `kEnforceRangeBit` set, the reducer will detect this out-of-range value and potentially:

    *   **Throw an error.**
    *   **Clamp the value** to the valid range (255 in this case) if the `kClampBit` is set.

3. **Passing Incorrect Object Types:**

    ```javascript
    // C++ function expects a JSArray
    const fastApi = {
      processArray: (arr) => %FastApiCall(0, null, fastApi.processArray, arr)
    };

    fastApi.processArray({ a: 1, b: 2 }); // Passing a plain object instead of an array
    ```

    The `AdaptFastCallArgument` method checks the type of the JavaScript value. If the C++ function expects a `JSArray`, the reducer will detect that a plain object is being passed and might:

    *   **Throw an error.**
    *   **Return a default value.**

In summary, `v8/src/compiler/turboshaft/fast-api-call-lowering-reducer.h` is a crucial component of the V8 Turboshaft compiler that bridges the gap between JavaScript and C++ when using the Fast API. It ensures that calls to C++ functions are performed efficiently and with proper type handling, preventing common programming errors related to type mismatches.

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/fast-api-call-lowering-reducer.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/fast-api-call-lowering-reducer.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_TURBOSHAFT_FAST_API_CALL_LOWERING_REDUCER_H_
#define V8_COMPILER_TURBOSHAFT_FAST_API_CALL_LOWERING_REDUCER_H_

#include "include/v8-fast-api-calls.h"
#include "src/compiler/fast-api-calls.h"
#include "src/compiler/globals.h"
#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/copying-phase.h"
#include "src/compiler/turboshaft/index.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/phase.h"
#include "src/compiler/turboshaft/representations.h"

namespace v8::internal::compiler::turboshaft {

#include "src/compiler/turboshaft/define-assembler-macros.inc"

template <typename Next>
class FastApiCallLoweringReducer : public Next {
 public:
  TURBOSHAFT_REDUCER_BOILERPLATE(FastApiCallLowering)

  OpIndex REDUCE(FastApiCall)(
      V<FrameState> frame_state, V<Object> data_argument, V<Context> context,
      base::Vector<const OpIndex> arguments,
      const FastApiCallParameters* parameters,
      base::Vector<const RegisterRepresentation> out_reps) {
    FastApiCallFunction c_function = parameters->c_function;
    const auto& c_signature = parameters->c_signature();
    const int c_arg_count = c_signature->ArgumentCount();
    DCHECK_EQ(c_arg_count, arguments.size());

    Label<> handle_error(this);
    Label<Word32> done(this);
    Variable result = __ NewVariable(RegisterRepresentation::FromCTypeInfo(
        c_signature->ReturnInfo(), c_signature->GetInt64Representation()));

    OpIndex callee = __ ExternalConstant(ExternalReference::Create(
        c_function.address, ExternalReference::FAST_C_CALL));

    base::SmallVector<OpIndex, 16> args;
    for (int i = 0; i < c_arg_count; ++i) {
        CTypeInfo type = c_signature->ArgumentInfo(i);
        args.push_back(AdaptFastCallArgument(arguments[i], type, handle_error));
    }

    // While adapting the arguments, we might have noticed an inconsistency that
    // lead to unconditionally jumping to {handle_error}. If this happens, then
    // we don't emit the call.
    if (V8_LIKELY(!__ generating_unreachable_operations())) {
      MachineSignature::Builder builder(
          __ graph_zone(), 1,
          c_arg_count + (c_signature->HasOptions() ? 1 : 0));

      builder.AddReturn(MachineType::TypeForCType(c_signature->ReturnInfo()));

      for (int i = 0; i < c_arg_count; ++i) {
        CTypeInfo type = c_signature->ArgumentInfo(i);
        MachineType machine_type =
            type.GetSequenceType() == CTypeInfo::SequenceType::kScalar
                ? MachineType::TypeForCType(type)
                : MachineType::AnyTagged();
        builder.AddParam(machine_type);
      }

      OpIndex stack_slot;
      if (c_signature->HasOptions()) {
        const int kAlign = alignof(v8::FastApiCallbackOptions);
        const int kSize = sizeof(v8::FastApiCallbackOptions);
        // If this check fails, you've probably added new fields to
        // v8::FastApiCallbackOptions, which means you'll need to write code
        // that initializes and reads from them too.
        static_assert(kSize == sizeof(uintptr_t) * 2);
        stack_slot = __ StackSlot(kSize, kAlign);

        // isolate
        __ StoreOffHeap(
            stack_slot,
            __ ExternalConstant(ExternalReference::isolate_address()),
            MemoryRepresentation::UintPtr(),
            offsetof(v8::FastApiCallbackOptions, isolate));
        // data = data_argument
        OpIndex data_argument_to_pass = __ AdaptLocalArgument(data_argument);
        __ StoreOffHeap(stack_slot, data_argument_to_pass,
                        MemoryRepresentation::UintPtr(),
                        offsetof(v8::FastApiCallbackOptions, data));

        args.push_back(stack_slot);
        builder.AddParam(MachineType::Pointer());
      }

      // Build the actual call.
      const TSCallDescriptor* call_descriptor = TSCallDescriptor::Create(
          Linkage::GetSimplifiedCDescriptor(__ graph_zone(), builder.Get(),
                                            CallDescriptor::kNeedsFrameState),
          CanThrow::kNo, LazyDeoptOnThrow::kNo, __ graph_zone());
      OpIndex c_call_result = WrapFastCall(call_descriptor, callee, frame_state,
                                           context, base::VectorOf(args));

      Label<> trigger_exception(this);

      V<Object> exception =
          __ Load(__ ExternalConstant(ExternalReference::Create(
                      IsolateAddressId::kExceptionAddress, isolate_)),
                  LoadOp::Kind::RawAligned(), MemoryRepresentation::UintPtr());
      GOTO_IF_NOT(LIKELY(__ TaggedEqual(
                      exception,
                      __ HeapConstant(isolate_->factory()->the_hole_value()))),
                  trigger_exception);

      V<Any> fast_call_result = ConvertReturnValue(c_signature, c_call_result);
      __ SetVariable(result, fast_call_result);

      GOTO(done, FastApiCallOp::kSuccessValue);
      BIND(trigger_exception);
      __ template CallRuntime<
          typename RuntimeCallDescriptor::PropagateException>(
          isolate_, frame_state, __ NoContextConstant(), LazyDeoptOnThrow::kNo,
          {});

      __ Unreachable();
    }

    if (BIND(handle_error)) {
      __ SetVariable(result, DefaultReturnValue(c_signature));
      // We pass Tagged<Smi>(0) as the value here, although this should never be
      // visible when calling code reacts to `kFailureValue` properly.
      GOTO(done, FastApiCallOp::kFailureValue);
    }

    BIND(done, state);
    return __ Tuple(state, __ GetVariable(result));
  }

 private:
  template <typename T>
  V<T> Checked(V<Tuple<T, Word32>> result, Label<>& otherwise) {
    V<Word32> result_state = __ template Projection<1>(result);
    GOTO_IF_NOT(__ Word32Equal(result_state, TryChangeOp::kSuccessValue),
                otherwise);
    return __ template Projection<0>(result);
  }

  OpIndex AdaptFastCallArgument(OpIndex argument, CTypeInfo arg_type,
                                Label<>& handle_error) {
    switch (arg_type.GetSequenceType()) {
      case CTypeInfo::SequenceType::kScalar: {
        uint8_t flags = static_cast<uint8_t>(arg_type.GetFlags());
        if (flags & static_cast<uint8_t>(CTypeInfo::Flags::kEnforceRangeBit)) {
          switch (arg_type.GetType()) {
            case CTypeInfo::Type::kInt32: {
              auto result = __ TryTruncateFloat64ToInt32(argument);
              return Checked(result, handle_error);
            }
            case CTypeInfo::Type::kUint32: {
              auto result = __ TryTruncateFloat64ToUint32(argument);
              return Checked(result, handle_error);
            }
            case CTypeInfo::Type::kInt64: {
              auto result = __ TryTruncateFloat64ToInt64(argument);
              return Checked(result, handle_error);
            }
            case CTypeInfo::Type::kUint64: {
              auto result = __ TryTruncateFloat64ToUint64(argument);
              return Checked(result, handle_error);
            }
            default: {
              GOTO(handle_error);
              return argument;
            }
          }
        } else if (flags & static_cast<uint8_t>(CTypeInfo::Flags::kClampBit)) {
          return ClampFastCallArgument(argument, arg_type.GetType());
        } else {
          switch (arg_type.GetType()) {
            case CTypeInfo::Type::kV8Value: {
              return __ AdaptLocalArgument(argument);
            }
            case CTypeInfo::Type::kFloat32: {
              return __ TruncateFloat64ToFloat32(argument);
            }
            case CTypeInfo::Type::kPointer: {
              // Check that the value is a HeapObject.
              GOTO_IF(__ ObjectIsSmi(argument), handle_error);
              Label<WordPtr> done(this);

              // Check if the value is null.
              GOTO_IF(UNLIKELY(__ TaggedEqual(
                          argument, __ HeapConstant(factory_->null_value()))),
                      done, 0);

              // Check that the value is a JSExternalObject.
              GOTO_IF_NOT(
                  __ TaggedEqual(__ LoadMapField(argument),
                                 __ HeapConstant(factory_->external_map())),
                  handle_error);

              GOTO(done, __ template LoadField<WordPtr>(
                             V<HeapObject>::Cast(argument),
                             AccessBuilder::ForJSExternalObjectValue()));

              BIND(done, result);
              return result;
            }
            case CTypeInfo::Type::kSeqOneByteString: {
              // Check that the value is a HeapObject.
              GOTO_IF(__ ObjectIsSmi(argument), handle_error);
              V<HeapObject> argument_obj = V<HeapObject>::Cast(argument);

              V<Map> map = __ LoadMapField(argument_obj);
              V<Word32> instance_type = __ LoadInstanceTypeField(map);

              V<Word32> encoding = __ Word32BitwiseAnd(
                  instance_type, kStringRepresentationAndEncodingMask);
              GOTO_IF_NOT(__ Word32Equal(encoding, kSeqOneByteStringTag),
                          handle_error);

              V<WordPtr> length_in_bytes = __ template LoadField<WordPtr>(
                  argument_obj, AccessBuilder::ForStringLength());
              V<WordPtr> data_ptr = __ GetElementStartPointer(
                  argument_obj, AccessBuilder::ForSeqOneByteStringCharacter());

              constexpr int kAlign = alignof(FastOneByteString);
              constexpr int kSize = sizeof(FastOneByteString);
              static_assert(kSize == sizeof(uintptr_t) + sizeof(size_t),
                            "The size of "
                            "FastOneByteString isn't equal to the sum of its "
                            "expected members.");
              OpIndex stack_slot = __ StackSlot(kSize, kAlign);
              __ StoreOffHeap(stack_slot, data_ptr,
                              MemoryRepresentation::UintPtr());
              __ StoreOffHeap(stack_slot, length_in_bytes,
                              MemoryRepresentation::Uint32(), sizeof(size_t));
              static_assert(sizeof(uintptr_t) == sizeof(size_t),
                            "The string length can't "
                            "fit the PointerRepresentation used to store it.");
              return stack_slot;
            }
            default: {
              return argument;
            }
          }
        }
      }
      case CTypeInfo::SequenceType::kIsSequence: {
        CHECK_EQ(arg_type.GetType(), CTypeInfo::Type::kVoid);

        // Check that the value is a HeapObject.
        GOTO_IF(__ ObjectIsSmi(argument), handle_error);

        // Check that the value is a JSArray.
        V<Map> map = __ LoadMapField(argument);
        V<Word32> instance_type = __ LoadInstanceTypeField(map);
        GOTO_IF_NOT(__ Word32Equal(instance_type, JS_ARRAY_TYPE), handle_error);

        return __ AdaptLocalArgument(argument);
      }
        START_ALLOW_USE_DEPRECATED()
      case CTypeInfo::SequenceType::kIsTypedArray:
        UNREACHABLE();
        END_ALLOW_USE_DEPRECATED()
      default: {
        UNREACHABLE();
      }
    }
  }

  OpIndex ClampFastCallArgument(V<Float64> argument,
                                CTypeInfo::Type scalar_type) {
    double min, max;
    switch (scalar_type) {
      case CTypeInfo::Type::kInt32:
        min = std::numeric_limits<int32_t>::min();
        max = std::numeric_limits<int32_t>::max();
        break;
      case CTypeInfo::Type::kUint32:
        min = 0;
        max = std::numeric_limits<uint32_t>::max();
        break;
      case CTypeInfo::Type::kInt64:
        min = kMinSafeInteger;
        max = kMaxSafeInteger;
        break;
      case CTypeInfo::Type::kUint64:
        min = 0;
        max = kMaxSafeInteger;
        break;
      default:
        UNREACHABLE();
    }

    V<Float64> clamped =
        __ Conditional(__ Float64LessThan(min, argument),
                       __ Conditional(__ Float64LessThan(argument, max),
                                      argument, __ Float64Constant(max)),
                       __ Float64Constant(min));

    Label<Float64> done(this);
    V<Float64> rounded = __ Float64RoundTiesEven(clamped);
    GOTO_IF(__ Float64IsNaN(rounded), done, 0.0);
    GOTO(done, rounded);

    BIND(done, rounded_result);
    switch (scalar_type) {
      case CTypeInfo::Type::kInt32:
        return __ ReversibleFloat64ToInt32(rounded_result);
      case CTypeInfo::Type::kUint32:
        return __ ReversibleFloat64ToUint32(rounded_result);
      case CTypeInfo::Type::kInt64:
        return __ ReversibleFloat64ToInt64(rounded_result);
      case CTypeInfo::Type::kUint64:
        return __ ReversibleFloat64ToUint64(rounded_result);
      default:
        UNREACHABLE();
    }
  }

  V<Any> DefaultReturnValue(const CFunctionInfo* c_signature) {
    switch (c_signature->ReturnInfo().GetType()) {
      case CTypeInfo::Type::kVoid:
        return __ HeapConstant(factory_->undefined_value());
      case CTypeInfo::Type::kBool:
      case CTypeInfo::Type::kInt32:
      case CTypeInfo::Type::kUint32:
        return __ Word32Constant(0);
      case CTypeInfo::Type::kInt64:
      case CTypeInfo::Type::kUint64: {
        CFunctionInfo::Int64Representation repr =
            c_signature->GetInt64Representation();
        if (repr == CFunctionInfo::Int64Representation::kBigInt) {
          return __ Word64Constant(int64_t{0});
        }
        DCHECK_EQ(repr, CFunctionInfo::Int64Representation::kNumber);
        return __ Float64Constant(0);
      }
      case CTypeInfo::Type::kFloat32:
        return __ Float32Constant(0);
      case CTypeInfo::Type::kFloat64:
        return __ Float64Constant(0);
      case CTypeInfo::Type::kPointer:
        return __ HeapConstant(factory_->undefined_value());
      case CTypeInfo::Type::kAny:
      case CTypeInfo::Type::kSeqOneByteString:
      case CTypeInfo::Type::kV8Value:
      case CTypeInfo::Type::kApiObject:
      case CTypeInfo::Type::kUint8:
        UNREACHABLE();
    }
  }

  V<Any> ConvertReturnValue(const CFunctionInfo* c_signature, OpIndex result) {
    switch (c_signature->ReturnInfo().GetType()) {
      case CTypeInfo::Type::kVoid:
        return __ HeapConstant(factory_->undefined_value());
      case CTypeInfo::Type::kBool:
        static_assert(sizeof(bool) == 1, "unsupported bool size");
        return __ Word32BitwiseAnd(result, __ Word32Constant(0xFF));
      case CTypeInfo::Type::kInt32:
      case CTypeInfo::Type::kUint32:
      case CTypeInfo::Type::kFloat32:
      case CTypeInfo::Type::kFloat64:
        return result;
      case CTypeInfo::Type::kInt64: {
        CFunctionInfo::Int64Representation repr =
            c_signature->GetInt64Representation();
        if (repr == CFunctionInfo::Int64Representation::kBigInt) {
          return result;
        }
        DCHECK_EQ(repr, CFunctionInfo::Int64Representation::kNumber);
        return __ ChangeInt64ToFloat64(result);
      }
      case CTypeInfo::Type::kUint64: {
        CFunctionInfo::Int64Representation repr =
            c_signature->GetInt64Representation();
        if (repr == CFunctionInfo::Int64Representation::kBigInt) {
          return result;
        }
        DCHECK_EQ(repr, CFunctionInfo::Int64Representation::kNumber);
        return __ ChangeUint64ToFloat64(result);
      }

      case CTypeInfo::Type::kPointer:
        return BuildAllocateJSExternalObject(result);
      case CTypeInfo::Type::kAny:
      case CTypeInfo::Type::kSeqOneByteString:
      case CTypeInfo::Type::kV8Value:
      case CTypeInfo::Type::kApiObject:
      case CTypeInfo::Type::kUint8:
        UNREACHABLE();
    }
  }

  V<HeapObject> BuildAllocateJSExternalObject(V<WordPtr> pointer) {
    Label<HeapObject> done(this);

    // Check if the pointer is a null pointer.
    GOTO_IF(__ WordPtrEqual(pointer, 0), done,
            __ HeapConstant(factory_->null_value()));

    Uninitialized<HeapObject> external =
        __ Allocate(JSExternalObject::kHeaderSize, AllocationType::kYoung);
    __ InitializeField(external, AccessBuilder::ForMap(),
                       __ HeapConstant(factory_->external_map()));
    V<FixedArray> empty_fixed_array =
        __ HeapConstant(factory_->empty_fixed_array());
    __ InitializeField(external, AccessBuilder::ForJSObjectPropertiesOrHash(),
                       empty_fixed_array);
    __ InitializeField(external, AccessBuilder::ForJSObjectElements(),
                       empty_fixed_array);

#ifdef V8_ENABLE_SANDBOX
    OpIndex isolate_ptr =
        __ ExternalConstant(ExternalReference::isolate_address());
    MachineSignature::Builder builder(__ graph_zone(), 1, 2);
    builder.AddReturn(MachineType::Uint32());
    builder.AddParam(MachineType::Pointer());
    builder.AddParam(MachineType::Pointer());
    OpIndex allocate_and_initialize_young_external_pointer_table_entry =
        __ ExternalConstant(
            ExternalReference::
                allocate_and_initialize_young_external_pointer_table_entry());
    auto call_descriptor =
        Linkage::GetSimplifiedCDescriptor(__ graph_zone(), builder.Get());
    OpIndex handle = __ Call(
        allocate_and_initialize_young_external_pointer_table_entry,
        {isolate_ptr, pointer},
        TSCallDescriptor::Create(call_descriptor, CanThrow::kNo,
                                 LazyDeoptOnThrow::kNo, __ graph_zone()));
    __ InitializeField(
        external, AccessBuilder::ForJSExternalObjectPointerHandle(), handle);
#else
    __ InitializeField(external, AccessBuilder::ForJSExternalObjectValue(),
                       pointer);
#endif  // V8_ENABLE_SANDBOX
    GOTO(done, __ FinishInitialization(std::move(external)));

    BIND(done, result);
    return result;
  }

  OpIndex WrapFastCall(const TSCallDescriptor* descriptor, OpIndex callee,
                       V<FrameState> frame_state, V<Context> context,
                       base::Vector<const OpIndex> arguments) {
    // CPU profiler support.
    OpIndex target_address =
        __ IsolateField(IsolateFieldId::kFastApiCallTarget);
    __ StoreOffHeap(target_address, __ BitcastHeapObjectToWordPtr(callee),
                    MemoryRepresentation::UintPtr());

    OpIndex context_address = __ ExternalConstant(
        ExternalReference::Create(IsolateAddressId::kContextAddress, isolate_));

    __ StoreOffHeap(context_address, __ BitcastHeapObjectToWordPtr(context),
                    MemoryRepresentation::UintPtr());

    // Create the fast call.
    OpIndex result = __ Call(callee, frame_state, arguments, descriptor);

    // Reset the CPU profiler target address.
    __ StoreOffHeap(target_address, __ IntPtrConstant(0),
                    MemoryRepresentation::UintPtr());

#if DEBUG
    // Reset the context again after the call, to make sure nobody is using the
    // leftover context in the isolate.
    __ StoreOffHeap(context_address,
                    __ WordPtrConstant(Context::kInvalidContext),
                    MemoryRepresentation::UintPtr());
#endif

    return result;
  }

  Isolate* isolate_ = __ data() -> isolate();
  Factory* factory_ = isolate_->factory();
};

#include "src/compiler/turboshaft/undef-assembler-macros.inc"

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_COMPILER_TURBOSHAFT_FAST_API_CALL_LOWERING_REDUCER_H_

"""

```