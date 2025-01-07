Response:
Let's break down the thought process to analyze the C++ header file `v8/src/compiler/linkage.h`.

1. **Understand the Goal:** The primary goal is to explain the functionality of this header file within the V8 JavaScript engine. The secondary goals are to identify if it's a Torque file (it's not), relate it to JavaScript, provide code logic examples, and highlight common programming errors.

2. **Initial Scan and Keywords:** Quickly scan the code for prominent keywords and structures. Things that jump out are:
    * `#ifndef`, `#define`, `#include`: Standard C++ header file guards and includes.
    * `namespace v8`, `namespace internal`, `namespace compiler`:  Namespace organization, indicating the file's place within the V8 structure.
    * `class V8_EXPORT_PRIVATE CallDescriptor`: This looks like a key class. The name suggests it describes how calls happen. `V8_EXPORT_PRIVATE` hints at internal use.
    * `enum Kind`:  Likely defines different types of calls. The values (`kCallCodeObject`, `kCallJSFunction`, etc.) provide strong hints.
    * `enum Flag`:  Looks like bit flags to modify call behavior. The names suggest control over frame setup, register usage, etc.
    * `class V8_EXPORT_PRIVATE Linkage`: Another important class. The name suggests how different parts of the compilation process are linked together.
    * Function names like `GetJSCallDescriptor`, `GetRuntimeCallDescriptor`, `GetParameterLocation`, `GetReturnLocation`: These point to the file's role in managing call setup.

3. **Focus on Key Classes:**  `CallDescriptor` and `Linkage` seem central. Let's analyze them in more detail.

    * **CallDescriptor:**
        * **Purpose:** The comments explicitly state it "Describes a call to various parts of the compiler." This is the core function.
        * **`Kind` enum:** The different kinds of calls are crucial. Understanding that calls can be to code objects, JS functions, C functions, WebAssembly functions, and builtins is fundamental.
        * **`Flag` enum:**  These flags modify the call's behavior. Examples like `kNeedsFrameState`, `kCallerSavedRegisters`, `kIsTailCallForTierUp` are important to understand the flexibility of the call mechanism.
        * **Member Variables:**  The member variables (`kind_`, `tag_`, `target_type_`, `target_loc_`, `location_sig_`, etc.) store information about the call's target, arguments, and return values. The types (like `MachineType`, `LinkageLocation`, `LocationSignature`) indicate interaction with lower-level code generation.
        * **Methods:**  Methods like `ParameterCount()`, `ReturnCount()`, `GetInputLocation()`, `GetReturnLocation()` expose the information stored in the object and allow access to details about the call's signature and locations.

    * **Linkage:**
        * **Purpose:** The comments state it "Defines the linkage for a compilation, including the calling conventions..." This means it bridges the abstract representation of a call with the concrete machine code implementation.
        * **Relationship with `CallDescriptor`:** It holds an `incoming_` `CallDescriptor`, which represents the calling convention *into* the current compilation unit.
        * **Static Methods:** The static methods (`ComputeIncoming`, `GetJSCallDescriptor`, `GetRuntimeCallDescriptor`, etc.) are factory methods for creating specific `CallDescriptor` instances for different scenarios. This highlights the different types of calls managed by the system.
        * **Instance Methods:**  Methods like `GetParameterLocation()` and `GetReturnLocation()` provide access to the input and output locations defined by the `incoming_` descriptor.

4. **Relate to JavaScript:**  Now, connect these C++ concepts back to JavaScript.

    * **`kCallJSFunction`:** This directly relates to calling JavaScript functions.
    * **Parameter Passing:**  The concepts of parameter slots, argument order, and register allocation directly influence how arguments are passed when calling JavaScript functions. Think about how JavaScript function calls work under the hood.
    * **`CallDescriptor` Flags:** Flags like `kNeedsFrameState` and `kCallerSavedRegisters` relate to the execution context of JavaScript code and the need to preserve state during calls.
    * **Runtime Functions:** `GetRuntimeCallDescriptor` connects to V8's built-in runtime functions that implement core JavaScript features.
    * **Builtins:** `kCallBuiltinPointer` relates to optimized, pre-compiled code for common JavaScript operations.

5. **JavaScript Examples:** Create simple JavaScript code snippets to illustrate the concepts. Calling a function, accessing arguments, and the existence of built-in functions are good starting points.

6. **Code Logic and Assumptions:**  Consider specific scenarios and how the `CallDescriptor` might be used. For example, imagine a call to a simple C function or a JavaScript function with a few arguments. What information would the `CallDescriptor` need to hold? What would be the input and output of the methods?  This helps to understand the data flow and the purpose of the different fields.

7. **Common Programming Errors:** Think about common mistakes that might arise from a misunderstanding of calling conventions or how parameters are passed. Incorrect argument counts or types are good examples.

8. **Torque Check:**  The presence of `.tq` file extensions is a simple check. The absence confirms it's a standard C++ header.

9. **Structure and Refine:**  Organize the information logically. Start with a high-level overview, then delve into the details of the key classes. Provide clear explanations and examples. Use formatting (like bullet points) to improve readability. Ensure the language is clear and avoids overly technical jargon where possible. Review and refine the explanation for clarity and accuracy. For instance, initially, I might have just listed the `Flag` enums, but realizing their significance in controlling call behavior led to explaining them in more detail. Similarly, the connection between `CallDescriptor` and different JavaScript call types needed to be explicitly made.
This C++ header file, `v8/src/compiler/linkage.h`, defines core data structures and functions related to **managing function calls within the V8 compiler**. It essentially describes *how* different parts of the V8 engine (and external code) interact through function calls at a low level.

Here's a breakdown of its functionalities:

**1. Defining `CallDescriptor`:**

*   The central piece of this header is the `CallDescriptor` class. It acts as a **blueprint for describing a function call**. It encapsulates all the necessary information about a call, such as:
    *   **`Kind`:** The type of call (e.g., calling a Code object, a JS function, a C function, a WebAssembly function, a built-in function).
    *   **Target Information:** The type and location of the function being called.
    *   **Signature:** The types and locations of parameters and return values.
    *   **Stack Layout:** Information about how parameters and return values are arranged on the stack.
    *   **Callee-Saved Registers:** Which registers the called function is responsible for preserving.
    *   **Flags:** Various options influencing the call's behavior (e.g., whether a frame needs to be set up, whether to initialize the root register, whether it's a tail call).

**2. Defining `Linkage`:**

*   The `Linkage` class represents the **calling convention** for a compilation unit. It describes how parameters are passed *into* the current function and how return values are passed *out*. It also provides methods for obtaining `CallDescriptor`s for making *outgoing* calls to various targets.
*   It uses the `CallDescriptor` to represent the incoming calling convention.
*   It provides static methods to create `CallDescriptor`s for different types of outgoing calls (JS functions, runtime functions, C entry points, stubs, bytecode dispatch).

**3. Abstraction over Architecture Differences:**

*   This header helps to abstract away architecture-specific details of function calling conventions. The `CallDescriptor` and `Linkage` classes provide a consistent interface that the compiler can use regardless of the underlying architecture (e.g., x64, ARM).

**4. Supporting Various Call Types:**

*   It explicitly defines different `Kind`s of calls, indicating the versatility of the V8 compiler in interacting with various code types (JavaScript, C++, WebAssembly, built-in functions).

**5. Optimizations and Flags:**

*   The `Flag` enum within `CallDescriptor` allows for fine-grained control over call behavior, enabling optimizations like tail calls and specifying register usage.

**If `v8/src/compiler/linkage.h` ended with `.tq`, it would be a V8 Torque source file.** Torque is a domain-specific language used within V8 to generate efficient C++ code for runtime functions and builtins. This particular file is a standard C++ header file.

**Relationship with JavaScript and JavaScript Examples:**

This header file is **fundamentally related to how JavaScript functions are called and executed** within V8. When you call a JavaScript function, the V8 compiler needs to generate machine code that adheres to a specific calling convention. The `CallDescriptor` and `Linkage` classes are crucial in defining and managing this convention.

Here are some JavaScript scenarios and how `linkage.h` is involved:

*   **Calling a regular JavaScript function:** When you call a JavaScript function like `myFunction(arg1, arg2)`, the compiler will use a `CallDescriptor` with `Kind::kCallJSFunction` to describe this call. This descriptor will specify where the function object is located, where the arguments (`arg1`, `arg2`) should be placed (registers or stack), and where the return value will be stored.

    ```javascript
    function myFunction(a, b) {
      return a + b;
    }

    let result = myFunction(5, 10);
    console.log(result); // Output: 15
    ```

*   **Calling a built-in JavaScript function:**  When you use built-in methods like `Array.push()` or `console.log()`, these calls are often handled by optimized, pre-compiled C++ code within V8. The compiler might use a `CallDescriptor` with `Kind::kCallBuiltinPointer` to invoke these builtins.

    ```javascript
    const myArray = [1, 2, 3];
    myArray.push(4);
    console.log(myArray); // Output: [1, 2, 3, 4]
    ```

*   **Interacting with WebAssembly:** If your JavaScript code calls a WebAssembly function, a `CallDescriptor` with `Kind::kCallWasmFunction` would be used to describe the call to the WebAssembly module.

    ```javascript
    // Assuming you have a WebAssembly module instance 'wasmInstance'
    const result = wasmInstance.exports.add(7, 8);
    console.log(result); // Output: 15 (if the WASM function adds two numbers)
    ```

*   **Tail Call Optimization:** The `kIsTailCallForTierUp` flag relates to a specific optimization where a function call is the very last operation in a function. This allows the compiler to potentially reuse the current stack frame, avoiding unnecessary overhead.

    ```javascript
    function factorial(n, accumulator = 1) {
      if (n <= 1) {
        return accumulator;
      }
      return factorial(n - 1, n * accumulator); // This is a tail call
    }

    console.log(factorial(5)); // Output: 120
    ```

**Code Logic Reasoning with Assumptions:**

Let's consider a simplified scenario: calling a JavaScript function with two integer arguments.

**Assumption:** We are on an architecture where the first two integer arguments are passed in registers `r0` and `r1`, and the return value is placed in register `r0`.

**Input:** A `CallDescriptor` object for a JavaScript function call (`Kind::kCallJSFunction`) with two parameters of `MachineType::Int32`.

**Expected Output (based on methods of `CallDescriptor`):**

*   `ParameterCount()`:  Returns `2`.
*   `GPParameterCount()`: Returns `2` (assuming both are general-purpose integers).
*   `GetInputLocation(1)`: Would likely return a `LinkageLocation` representing register `r0`.
*   `GetInputLocation(2)`: Would likely return a `LinkageLocation` representing register `r1`.
*   `GetReturnLocation(0)`: Would likely return a `LinkageLocation` representing register `r0`.
*   `GetParameterType(0)`: Returns `MachineType::Int32`.
*   `GetParameterType(1)`: Returns `MachineType::Int32`.

**Common Programming Errors (from a compiler perspective):**

While this header is for internal V8 use, understanding its concepts can help illustrate common programming errors that a compiler needs to handle:

*   **Incorrect Number of Arguments:** If the JavaScript code calls a function with the wrong number of arguments, the generated code (informed by the `CallDescriptor`) might try to read from invalid stack locations or registers. V8's runtime system will usually catch these errors.

    ```javascript
    function add(a, b) {
      return a + b;
    }

    // Error: Calling with too few arguments
    add(5); // Results in NaN (Not a Number) because 'b' is undefined.
    ```

*   **Type Mismatches:** If the JavaScript code passes arguments of the wrong type, the compiler might generate code assuming a certain data layout, leading to unexpected behavior or errors.

    ```javascript
    function greet(name) {
      return "Hello, " + name;
    }

    // Potential type mismatch: passing a number instead of a string
    console.log(greet(123)); // Output: Hello, 123 (JavaScript is very forgiving)
    ```

*   **Stack Overflow (related to recursion and frame setup):**  If a JavaScript function calls itself recursively too many times without a proper base case, it can lead to a stack overflow. The `CallDescriptor` and frame management mechanisms are involved in allocating space on the stack for each function call.

    ```javascript
    function recursiveFunction() {
      recursiveFunction(); // No base case, will cause a stack overflow
    }

    // This will eventually throw a "RangeError: Maximum call stack size exceeded"
    // recursiveFunction();
    ```

In summary, `v8/src/compiler/linkage.h` is a foundational header file in V8's compiler that defines how function calls are structured and managed at a low level. It provides the necessary abstractions and data structures to handle various types of calls within the V8 engine, ultimately enabling the execution of JavaScript code.

Prompt: 
```
这是目录为v8/src/compiler/linkage.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/linkage.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_LINKAGE_H_
#define V8_COMPILER_LINKAGE_H_

#include <optional>

#include "src/base/compiler-specific.h"
#include "src/base/flags.h"
#include "src/codegen/interface-descriptors.h"
#include "src/codegen/linkage-location.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/register.h"
#include "src/codegen/reglist.h"
#include "src/codegen/signature.h"
#include "src/common/globals.h"
#include "src/compiler/frame.h"
#include "src/compiler/globals.h"
#include "src/compiler/operator.h"
#include "src/execution/encoded-c-signature.h"
#include "src/runtime/runtime.h"
#include "src/zone/zone.h"

namespace v8 {
class CFunctionInfo;

namespace internal {

class CallInterfaceDescriptor;
class OptimizedCompilationInfo;

namespace compiler {

constexpr RegList kNoCalleeSaved;
constexpr DoubleRegList kNoCalleeSavedFp;

class OsrHelper;

// Describes a call to various parts of the compiler. Every call has the notion
// of a "target", which is the first input to the call.
class V8_EXPORT_PRIVATE CallDescriptor final
    : public NON_EXPORTED_BASE(ZoneObject) {
 public:
  // Describes the kind of this call, which determines the target.
  enum Kind {
    kCallCodeObject,         // target is a Code object
    kCallJSFunction,         // target is a JSFunction object
    kCallAddress,            // target is a machine pointer
#if V8_ENABLE_WEBASSEMBLY    // ↓ WebAssembly only
    kCallWasmCapiFunction,   // target is a Wasm C API function
    kCallWasmFunction,       // target is a wasm function
    kCallWasmImportWrapper,  // target is a wasm import wrapper
#endif                       // ↑ WebAssembly only
    kCallBuiltinPointer,     // target is a builtin pointer
  };

  // NOTE: The lowest 10 bits of the Flags field are encoded in InstructionCode
  // (for use in the code generator). All higher bits are lost.
  static constexpr int kFlagsBitsEncodedInInstructionCode = 10;
  enum Flag {
    kNoFlags = 0u,
    kNeedsFrameState = 1u << 0,
    kHasExceptionHandler = 1u << 1,
    kCanUseRoots = 1u << 2,
    // Causes the code generator to initialize the root register.
    kInitializeRootRegister = 1u << 3,
    // Does not ever try to allocate space on our heap.
    kNoAllocate = 1u << 4,
    // Use the kJavaScriptCallCodeStartRegister (fixed) register for the
    // indirect target address when calling.
    kFixedTargetRegister = 1u << 5,
    kCallerSavedRegisters = 1u << 6,
    // The kCallerSavedFPRegisters only matters (and set) when the more general
    // flag for kCallerSavedRegisters above is also set.
    kCallerSavedFPRegisters = 1u << 7,
    // Tail calls for tier up are special (in fact they are different enough
    // from normal tail calls to warrant a dedicated opcode; but they also have
    // enough similar aspects that reusing the TailCall opcode is pragmatic).
    // Specifically:
    //
    // 1. Caller and callee are both JS-linkage Code objects.
    // 2. JS runtime arguments are passed unchanged from caller to callee.
    // 3. JS runtime arguments are not attached as inputs to the TailCall node.
    // 4. Prior to the tail call, frame and register state is torn down to just
    //    before the caller frame was constructed.
    // 5. Unlike normal tail calls, inlined arguments frames (if present) are
    //    *not* torn down.
    //
    // In other words, behavior is identical to a jmp instruction prior caller
    // frame construction.
    kIsTailCallForTierUp = 1u << 8,

    // AIX has a function descriptor by default but it can be disabled for a
    // certain CFunction call (only used for Kind::kCallAddress).
    kNoFunctionDescriptor = 1u << 9,

    // Flags past here are *not* encoded in InstructionCode and are thus not
    // accessible from the code generator. See also
    // kFlagsBitsEncodedInInstructionCode.
  };
  using Flags = base::Flags<Flag>;

  CallDescriptor(Kind kind, CodeEntrypointTag tag, MachineType target_type,
                 LinkageLocation target_loc, LocationSignature* location_sig,
                 size_t param_slot_count, Operator::Properties properties,
                 RegList callee_saved_registers,
                 DoubleRegList callee_saved_fp_registers, Flags flags,
                 const char* debug_name = "",
                 StackArgumentOrder stack_order = StackArgumentOrder::kDefault,
                 const RegList allocatable_registers = {},
                 size_t return_slot_count = 0)
      : kind_(kind),
        tag_(tag),
        target_type_(target_type),
        target_loc_(target_loc),
        location_sig_(location_sig),
        param_slot_count_(param_slot_count),
        return_slot_count_(return_slot_count),
        properties_(properties),
        callee_saved_registers_(callee_saved_registers),
        callee_saved_fp_registers_(callee_saved_fp_registers),
        allocatable_registers_(allocatable_registers),
        flags_(flags),
        stack_order_(stack_order),
        debug_name_(debug_name) {}

  CallDescriptor(const CallDescriptor&) = delete;
  CallDescriptor& operator=(const CallDescriptor&) = delete;

  // Returns the kind of this call.
  Kind kind() const { return kind_; }

  // Returns the entrypoint tag for this call.
  CodeEntrypointTag tag() const { return tag_; }

  // Returns the entrypoint tag for this call, shifted to the right by
  // kCodeEntrypointTagShift so that it fits into a 32-bit immediate.
  uint32_t shifted_tag() const {
    static_assert(kCodeEntrypointTagShift >= 32);
    return tag_ >> kCodeEntrypointTagShift;
  }

  // Returns {true} if this descriptor is a call to a Code object.
  bool IsCodeObjectCall() const { return kind_ == kCallCodeObject; }

  // Returns {true} if this descriptor is a call to a C function.
  bool IsCFunctionCall() const { return kind_ == kCallAddress; }

  // Returns {true} if this descriptor is a call to a JSFunction.
  bool IsJSFunctionCall() const { return kind_ == kCallJSFunction; }

#if V8_ENABLE_WEBASSEMBLY
  // Returns {true} if this descriptor is a call to a WebAssembly function.
  bool IsWasmFunctionCall() const { return kind_ == kCallWasmFunction; }

  // Returns {true} if this descriptor is a call to a WebAssembly function.
  bool IsWasmImportWrapper() const { return kind_ == kCallWasmImportWrapper; }

  // Returns {true} if this descriptor is a call to a Wasm C API function.
  bool IsWasmCapiFunction() const { return kind_ == kCallWasmCapiFunction; }
#endif  // V8_ENABLE_WEBASSEMBLY

  bool IsBuiltinPointerCall() const { return kind_ == kCallBuiltinPointer; }

  bool RequiresFrameAsIncoming() const {
    if (IsCFunctionCall() || IsJSFunctionCall()) return true;
#if V8_ENABLE_WEBASSEMBLY
    if (IsWasmFunctionCall()) return true;
#endif  // V8_ENABLE_WEBASSEMBLY
    if (CalleeSavedRegisters() != kNoCalleeSaved) return true;
    return false;
  }

  bool RequiresEntrypointTagForCall() const { return IsCodeObjectCall(); }

  // The number of return values from this call.
  size_t ReturnCount() const { return location_sig_->return_count(); }

  // The number of C parameters to this call. The following invariant
  // should hold true:
  // ParameterCount() == GPParameterCount() + FPParameterCount()
  size_t ParameterCount() const { return location_sig_->parameter_count(); }

  // The number of general purpose C parameters to this call.
  size_t GPParameterCount() const {
    if (!gp_param_count_) {
      ComputeParamCounts();
    }
    return gp_param_count_.value();
  }

  // The number of floating point C parameters to this call.
  size_t FPParameterCount() const {
    if (!fp_param_count_) {
      ComputeParamCounts();
    }
    return fp_param_count_.value();
  }

  // The number of stack parameter slots to the call.
  size_t ParameterSlotCount() const { return param_slot_count_; }

  // The number of stack return value slots from the call.
  size_t ReturnSlotCount() const { return return_slot_count_; }

  // The number of parameters to the JS function call.
  size_t JSParameterCount() const {
    DCHECK(IsJSFunctionCall());
    return param_slot_count_;
  }

  int GetStackIndexFromSlot(int slot_index) const {
    switch (GetStackArgumentOrder()) {
      case StackArgumentOrder::kDefault:
        return -slot_index - 1;
      case StackArgumentOrder::kJS:
        return slot_index + static_cast<int>(ParameterSlotCount());
    }
  }

  // The total number of inputs to this call, which includes the target,
  // receiver, context, etc.
  // TODO(titzer): this should input the framestate input too.
  size_t InputCount() const { return 1 + location_sig_->parameter_count(); }

  size_t FrameStateCount() const { return NeedsFrameState() ? 1 : 0; }

  Flags flags() const { return flags_; }

  bool NeedsFrameState() const { return flags() & kNeedsFrameState; }
  bool InitializeRootRegister() const {
    return flags() & kInitializeRootRegister;
  }
  bool NeedsCallerSavedRegisters() const {
    return flags() & kCallerSavedRegisters;
  }
  bool NeedsCallerSavedFPRegisters() const {
    return flags() & kCallerSavedFPRegisters;
  }
  bool IsTailCallForTierUp() const { return flags() & kIsTailCallForTierUp; }
  bool NoFunctionDescriptor() const { return flags() & kNoFunctionDescriptor; }

  LinkageLocation GetReturnLocation(size_t index) const {
    return location_sig_->GetReturn(index);
  }

  LinkageLocation GetInputLocation(size_t index) const {
    if (index == 0) return target_loc_;
    return location_sig_->GetParam(index - 1);
  }

  MachineSignature* GetMachineSignature(Zone* zone) const;

  MachineType GetReturnType(size_t index) const {
    return location_sig_->GetReturn(index).GetType();
  }

  MachineType GetInputType(size_t index) const {
    if (index == 0) return target_type_;
    return location_sig_->GetParam(index - 1).GetType();
  }

  MachineType GetParameterType(size_t index) const {
    return location_sig_->GetParam(index).GetType();
  }

  StackArgumentOrder GetStackArgumentOrder() const { return stack_order_; }

  // Operator properties describe how this call can be optimized, if at all.
  Operator::Properties properties() const { return properties_; }

  // Get the callee-saved registers, if any, across this call.
  RegList CalleeSavedRegisters() const { return callee_saved_registers_; }

  // Get the callee-saved FP registers, if any, across this call.
  DoubleRegList CalleeSavedFPRegisters() const {
    return callee_saved_fp_registers_;
  }

  const char* debug_name() const { return debug_name_; }

  // Difference between the number of parameter slots of *this* and
  // *tail_caller* (callee minus caller).
  int GetStackParameterDelta(const CallDescriptor* tail_caller) const;

  // Returns the offset to the area below the parameter slots on the stack,
  // relative to callee slot 0, the return address. If there are no parameter
  // slots, returns +1.
  int GetOffsetToFirstUnusedStackSlot() const;

  // Returns the offset to the area above the return slots on the stack,
  // relative to callee slot 0, the return address. If there are no return
  // slots, returns the offset to the lowest slot of the parameter area.
  // If there are no parameter slots, returns 0.
  int GetOffsetToReturns() const;

  // Returns two 16-bit numbers packed together: (first slot << 16) | num_slots.
  uint32_t GetTaggedParameterSlots() const;

  bool CanTailCall(const CallDescriptor* callee) const;

  int CalculateFixedFrameSize(CodeKind code_kind) const;

  RegList AllocatableRegisters() const { return allocatable_registers_; }

  bool HasRestrictedAllocatableRegisters() const {
    return !allocatable_registers_.is_empty();
  }

  EncodedCSignature ToEncodedCSignature() const;

 private:
  void ComputeParamCounts() const;

  friend class Linkage;

  const Kind kind_;
  const CodeEntrypointTag tag_;
  const MachineType target_type_;
  const LinkageLocation target_loc_;
  const LocationSignature* const location_sig_;
  const size_t param_slot_count_;
  const size_t return_slot_count_;
  const Operator::Properties properties_;
  const RegList callee_saved_registers_;
  const DoubleRegList callee_saved_fp_registers_;
  // Non-zero value means restricting the set of allocatable registers for
  // register allocator to use.
  const RegList allocatable_registers_;
  const Flags flags_;
  const StackArgumentOrder stack_order_;
  const char* const debug_name_;

  mutable std::optional<size_t> gp_param_count_;
  mutable std::optional<size_t> fp_param_count_;
};

DEFINE_OPERATORS_FOR_FLAGS(CallDescriptor::Flags)

std::ostream& operator<<(std::ostream& os, const CallDescriptor& d);
V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           const CallDescriptor::Kind& k);

#if V8_ENABLE_WEBASSEMBLY
// Lowers a wasm CallDescriptor for 32 bit platforms by replacing i64 parameters
// and returns with two i32s each.
V8_EXPORT_PRIVATE CallDescriptor* GetI32WasmCallDescriptor(
    Zone* zone, const CallDescriptor* call_descriptor);
#endif

// Defines the linkage for a compilation, including the calling conventions
// for incoming parameters and return value(s) as well as the outgoing calling
// convention for any kind of call. Linkage is generally architecture-specific.
//
// Can be used to translate {arg_index} (i.e. index of the call node input) as
// well as {param_index} (i.e. as stored in parameter nodes) into an operator
// representing the architecture-specific location. The following call node
// layouts are supported (where {n} is the number of value inputs):
//
//                        #0          #1     #2     [...]             #n
// Call[CodeStub]         code,       arg 1, arg 2, [...],            context
// Call[JSFunction]       function,   rcvr,  arg 1, [...], new, #arg, context
// Call[Runtime]          CEntry,     arg 1, arg 2, [...], fun, #arg, context
// Call[BytecodeDispatch] address,    arg 1, arg 2, [...]
class V8_EXPORT_PRIVATE Linkage : public NON_EXPORTED_BASE(ZoneObject) {
 public:
  explicit Linkage(CallDescriptor* incoming) : incoming_(incoming) {}
  Linkage(const Linkage&) = delete;
  Linkage& operator=(const Linkage&) = delete;

  static CallDescriptor* ComputeIncoming(Zone* zone,
                                         OptimizedCompilationInfo* info);

  // The call descriptor for this compilation unit describes the locations
  // of incoming parameters and the outgoing return value(s).
  CallDescriptor* GetIncomingDescriptor() const { return incoming_; }
  // Calls to JSFunctions should never overwrite the {properties}, but calls to
  // known builtins might.
  static CallDescriptor* GetJSCallDescriptor(
      Zone* zone, bool is_osr, int parameter_count, CallDescriptor::Flags flags,
      Operator::Properties properties =
          Operator::kNoProperties /* use with care! */);

  static CallDescriptor* GetRuntimeCallDescriptor(
      Zone* zone, Runtime::FunctionId function, int js_parameter_count,
      Operator::Properties properties, CallDescriptor::Flags flags,
      LazyDeoptOnThrow lazy_deopt_on_throw = LazyDeoptOnThrow::kNo);

  static CallDescriptor* GetCEntryStubCallDescriptor(
      Zone* zone, int return_count, int js_parameter_count,
      const char* debug_name, Operator::Properties properties,
      CallDescriptor::Flags flags,
      StackArgumentOrder stack_order = StackArgumentOrder::kDefault);

  static CallDescriptor* GetStubCallDescriptor(
      Zone* zone, const CallInterfaceDescriptor& descriptor,
      int stack_parameter_count, CallDescriptor::Flags flags,
      Operator::Properties properties = Operator::kNoProperties,
      StubCallMode stub_mode = StubCallMode::kCallCodeObject);

  static CallDescriptor* GetBytecodeDispatchCallDescriptor(
      Zone* zone, const CallInterfaceDescriptor& descriptor,
      int stack_parameter_count);

  // Creates a call descriptor for simplified C calls that is appropriate
  // for the host platform. This simplified calling convention only supports
  // integers and pointers of one word size each, i.e. no floating point,
  // structs, pointers to members, etc.
  static CallDescriptor* GetSimplifiedCDescriptor(
      Zone* zone, const MachineSignature* sig,
      CallDescriptor::Flags flags = CallDescriptor::kNoFlags);

  // Get the location of an (incoming) parameter to this function.
  LinkageLocation GetParameterLocation(int index) const {
    return incoming_->GetInputLocation(index + 1);  // + 1 to skip target.
  }

  // Get the machine type of an (incoming) parameter to this function.
  MachineType GetParameterType(int index) const {
    return incoming_->GetInputType(index + 1);  // + 1 to skip target.
  }

  // Get the location where this function should place its return value.
  LinkageLocation GetReturnLocation(size_t index = 0) const {
    return incoming_->GetReturnLocation(index);
  }

  // Get the machine type of this function's return value.
  MachineType GetReturnType(size_t index = 0) const {
    return incoming_->GetReturnType(index);
  }

  bool ParameterHasSecondaryLocation(int index) const;
  LinkageLocation GetParameterSecondaryLocation(int index) const;

  static bool NeedsFrameStateInput(Runtime::FunctionId function);

  // Get the location where an incoming OSR value is stored.
  LinkageLocation GetOsrValueLocation(int index) const;

  // A special {Parameter} index for Stub Calls that represents context.
  static int GetStubCallContextParamIndex(int parameter_count) {
    return parameter_count + 0;
  }

  // A special {Parameter} index for JSCalls that represents the new target.
  static constexpr int GetJSCallNewTargetParamIndex(int parameter_count) {
    return parameter_count + 0;
  }

  // A special {Parameter} index for JSCalls that represents the argument count.
  static constexpr int GetJSCallArgCountParamIndex(int parameter_count) {
    return GetJSCallNewTargetParamIndex(parameter_count) + 1;
  }

#ifdef V8_ENABLE_LEAPTIERING
  // A special {Parameter} index for JSCalls that represents the dispatch
  // handle.
  static constexpr int GetJSCallDispatchHandleParamIndex(int parameter_count) {
    return GetJSCallArgCountParamIndex(parameter_count) + 1;
  }
#endif

  // A special {Parameter} index for JSCalls that represents the context.
  static constexpr int GetJSCallContextParamIndex(int parameter_count) {
#ifdef V8_ENABLE_LEAPTIERING
    return GetJSCallDispatchHandleParamIndex(parameter_count) + 1;
#else
    return GetJSCallArgCountParamIndex(parameter_count) + 1;
#endif
  }

  // A special {Parameter} index for JSCalls that represents the closure.
  static constexpr int kJSCallClosureParamIndex = kJSCallClosureParameterIndex;
  static_assert(kJSCallClosureParamIndex == -1);

  // A special {OsrValue} index to indicate the context spill slot.
  static const int kOsrContextSpillSlotIndex = -1;

  // A special {OsrValue} index to indicate the accumulator register.
  static const int kOsrAccumulatorRegisterIndex = -1;

 private:
  CallDescriptor* const incoming_;
};

}  // namespace compiler
}  // namespace internal
}  // namespace v8
#undef NO_INLINE_FOR_ARM64_MSVC

#endif  // V8_COMPILER_LINKAGE_H_

"""

```