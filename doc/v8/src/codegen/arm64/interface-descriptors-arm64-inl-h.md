Response:
My thought process to analyze the given C++ header file goes like this:

1. **Understand the Context:** The file is located in `v8/src/codegen/arm64/`. This immediately tells me it's related to V8's code generation for the ARM64 architecture. The filename `interface-descriptors-arm64-inl.h` suggests it defines how different operations (interfaces) are described, specifically regarding register usage. The `.inl.h` suffix usually signifies inline header files.

2. **High-Level Purpose:** The core function of this file is to define *interface descriptors*. These descriptors act like blueprints, specifying how arguments and return values are passed to and from various code snippets (like built-in functions or stubs) within the V8 engine on ARM64. The primary focus is on *register allocation*.

3. **Key Data Structures:** The code heavily uses `CallInterfaceDescriptor` and its variations (`StaticCallInterfaceDescriptor`). These are clearly the central data structures. They seem to hold information about which registers are used for arguments, return values, and potentially other purposes. The nested `RegisterArray` and `DoubleRegisterArray` structures reinforce the idea of register allocation.

4. **Specific Descriptors:**  I start scanning through the defined descriptors. I notice patterns in their naming:
    * `LoadDescriptor`, `StoreDescriptor`: These likely describe memory access operations.
    * `Call*Descriptor`, `Construct*Descriptor`: These clearly relate to function calls and object construction.
    * `*BaselineDescriptor`: This suggests optimized or baseline versions of certain operations.
    * `*WithVectorDescriptor`: The "Vector" likely refers to feedback vectors used for optimization.
    * `Api*Descriptor`:  These likely deal with interactions with the V8 API.
    * `Interpreter*Descriptor`: These handle interactions with V8's bytecode interpreter.

5. **Register Usage:** For each descriptor, I look at the `registers()` method or specific `constexpr Register` members. This tells me *exactly* which ARM64 registers (like `x0`, `x1`, `d0`, `kContextRegister`) are used for specific roles (receiver, name, value, etc.). I see consistency in the naming (e.g., `ReceiverRegister`, `NameRegister`, `ValueRegister`).

6. **Conditional Compilation:** The `#if V8_TARGET_ARCH_ARM64` and `#if DEBUG` preprocessor directives indicate that the content is specific to the ARM64 architecture and that some checks are only enabled in debug builds.

7. **Inference and Deductions:** Based on the names and register assignments, I can infer the following:
    * **Optimization:** The presence of `Baseline` and `WithVector` descriptors suggests different levels of optimization within the engine.
    * **Function Calls:**  The various `Call*` and `Construct*` descriptors cover different calling conventions (varargs, spread, etc.).
    * **Property Access:** The `Load` and `Store` descriptors handle property access, including keyed access.
    * **Interpreter Integration:** The `InterpreterDispatchDescriptor` and related descriptors show how the interpreter interacts with the generated code.

8. **Addressing the Prompt's Questions:**

    * **Functionality:** Summarize the overall purpose (defining interface descriptors for ARM64). List specific areas covered by the descriptors (loads, stores, calls, etc.).
    * **`.tq` extension:**  Confirm that this file is `.h` and not `.tq`, therefore not a Torque source file.
    * **JavaScript Relationship:**  Connect the descriptors to common JavaScript operations. For example, `LoadDescriptor` relates to accessing object properties, `CallDescriptor` to function calls, etc. Provide simple JavaScript examples.
    * **Code Logic (Inference):** Choose a simple descriptor (like `LoadDescriptor`) and show how the registers would be used for a hypothetical property access.
    * **Common Programming Errors:** Explain how incorrect assumptions about register usage (which these descriptors help manage internally) could lead to errors if developers were working at this low level.

9. **Refinement and Organization:** Structure the answer clearly, using headings and bullet points to make it easy to read and understand. Ensure all parts of the prompt are addressed.

Essentially, I'm reading the code like a specification document. I identify the key components, understand their relationships, and then connect those low-level details to higher-level concepts in JavaScript and V8's operation. The naming conventions used in V8's codebase are very helpful in this process.

这是一个V8 JavaScript引擎的源代码文件，具体来说，它定义了在ARM64架构上，V8引擎内部各种操作的接口描述符（Interface Descriptors）。这些描述符详细说明了在调用特定的内置函数、运行时函数或生成代码时，哪些寄存器被用于传递参数和返回值。

**功能列表:**

1. **定义默认寄存器分配:**  为通用的函数调用定义了默认的通用寄存器（x0-x4）和浮点寄存器（d0-d6）用于传递参数，以及用于返回值的寄存器（kReturnRegister0/1/2，kFPReturnRegister0）。

2. **定义各种操作的寄存器约定:**  为V8引擎内部的各种操作定义了特定的寄存器使用约定。这些操作包括：
    * **内存访问:**  `LoadDescriptor`, `StoreDescriptor`, `KeyedLoadBaselineDescriptor`等，定义了用于传递接收者、属性名、槽位、向量等的寄存器。
    * **函数调用:** `CallInterfaceDescriptor`, `CallTrampolineDescriptor`, `CallVarargsDescriptor`, `ConstructVarargsDescriptor`等，定义了用于传递目标函数、参数数量、参数列表、新目标等的寄存器。
    * **API调用:** `ApiGetterDescriptor`, `CallApiCallbackOptimizedDescriptor`, `CallApiCallbackGenericDescriptor`等，定义了用于传递持有者、回调函数、参数数量等的寄存器。
    * **优化相关:**  `LoadWithVectorDescriptor`, `StoreWithVectorDescriptor`, `MaglevOptimizeCodeOrTailCallOptimizedCodeSlotDescriptor`等，涉及到反馈向量和优化的寄存器使用。
    * **解释器相关:** `InterpreterDispatchDescriptor`, `InterpreterPushArgsThenCallDescriptor`, `InterpreterPushArgsThenConstructDescriptor`等，定义了与解释器交互时使用的寄存器。
    * **其他操作:**  类型转换、比较、二元运算、异常处理等。

3. **提供调试断言:**  在DEBUG模式下，`StaticCallInterfaceDescriptor::VerifyArgumentRegisterCount` 函数会检查函数调用的参数数量是否与分配的寄存器数量一致。

**关于 `.tq` 结尾:**

`v8/src/codegen/arm64/interface-descriptors-arm64-inl.h` 文件以 `.h` 结尾，而不是 `.tq`。因此，它不是一个 V8 Torque 源代码文件。Torque 是一种用于编写 V8 内置函数的领域特定语言，它的文件通常以 `.tq` 结尾。这个 `.h` 文件是 C++ 头文件，用于定义 C++ 结构体和常量。

**与 JavaScript 的功能关系及 JavaScript 示例:**

`interface-descriptors-arm64-inl.h` 文件中定义的接口描述符是 V8 引擎实现 JavaScript 功能的基础。它定义了底层代码如何与 V8 的其他部分交互，以及如何高效地传递数据。

以下是一些 JavaScript 功能以及它们可能与此文件中定义的描述符相关的示例：

1. **属性访问 (Property Access):**

   ```javascript
   const obj = { x: 10 };
   const value = obj.x; // 属性读取
   obj.y = 20;        // 属性写入
   ```

   * **`LoadDescriptor`**:  当读取 `obj.x` 时，V8 内部可能会使用 `LoadDescriptor` 来指定将 `obj` (ReceiverRegister: `x1`) 和属性名 `'x'` (NameRegister: `x2`) 传递给加载操作的底层代码，并将结果存储在某个寄存器中。
   * **`StoreDescriptor`**: 当写入 `obj.y = 20` 时，`StoreDescriptor` 会指定将 `obj` (ReceiverRegister: `x1`)，属性名 `'y'` (NameRegister: `x2`) 和值 `20` (ValueRegister: `x0`) 传递给存储操作。

2. **函数调用 (Function Calls):**

   ```javascript
   function add(a, b) {
     return a + b;
   }
   const sum = add(5, 3);
   ```

   * **`CallInterfaceDescriptor` 或 `CallTrampolineDescriptor`**:  在调用 `add(5, 3)` 时，V8 会使用这些描述符来确定如何传递 `add` 函数的引用 (target) 和参数 `5` 和 `3`。默认情况下，参数可能会被放在 `x0`, `x1`, `x2` 等寄存器中。

3. **构造函数调用 (Constructor Calls):**

   ```javascript
   class Point {
     constructor(x, y) {
       this.x = x;
       this.y = y;
     }
   }
   const p = new Point(1, 2);
   ```

   * **`ConstructStubDescriptor` 或 `ConstructVarargsDescriptor`**: 当执行 `new Point(1, 2)` 时，这些描述符会指定如何传递 `Point` 构造函数的引用 (target)，`new.target` (通常是 `Point` 自身)，以及参数 `1` 和 `2`。

4. **API 调用 (Calling built-in functions or Web APIs):**

   ```javascript
   console.log("Hello");
   ```

   * **`CallApiCallbackOptimizedDescriptor` 或 `CallApiCallbackGenericDescriptor`**:  调用 `console.log` 这样的内置函数会涉及到 V8 的 C++ API。这些描述符会指定如何传递 `console` 对象 (HolderRegister: `x0`) 和 `log` 函数的回调地址 (CallbackRegister: `x3`) 以及参数。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个简单的属性读取操作 `obj.x`，并且 V8 引擎使用 `LoadDescriptor` 来处理它。

**假设输入:**

* `obj`: 一个 JavaScript 对象，其内部表示的地址位于某个内存位置。
* `'x'`:  代表属性名的字符串，其内部表示的地址位于某个内存位置。

**涉及的寄存器 (根据 `LoadDescriptor`):**

* `ReceiverRegister` (`x1`): 存储 `obj` 的指针。
* `NameRegister` (`x2`): 存储属性名 `'x'` 的指针。
* `SlotRegister` (`x0`):  在加载操作开始时，可能用于传递其他信息，但在加载完成后，通常会用于存储属性值所在的槽位或偏移量。

**代码逻辑 (简化描述):**

1. V8 的代码生成器或解释器会根据 `LoadDescriptor` 的定义，将 `obj` 的指针加载到 `x1` 寄存器，将 `'x'` 的指针加载到 `x2` 寄存器。
2. 一个底层的加载例程会被调用，该例程会使用 `x1` (对象地址) 和 `x2` (属性名) 来查找 `obj` 中名为 `'x'` 的属性。
3. 属性值的内存地址或值本身会被加载到某个寄存器中（可能最终会移动到累加器寄存器或其他目标寄存器）。

**输出:**

* 属性 `obj.x` 的值会被加载到某个寄存器中，以便后续的 JavaScript 代码可以使用它。

**用户常见的编程错误:**

虽然用户通常不会直接与这些底层的寄存器分配打交道，但是理解这些概念可以帮助理解一些与性能相关的错误，或者在与 V8 引擎的 C++ API 交互时可能遇到的问题。

1. **假设特定类型的对象总是以相同的方式表示:**  V8 内部对不同类型的对象可能有不同的布局和访问方式。直接假设所有对象的属性都以相同的方式存储和访问是错误的。

2. **在编写 Native 代码 (使用 C++ API) 时，不遵循 V8 的约定:**  如果开发者编写 C++ 代码来与 V8 交互（例如，通过 V8 的 C++ API 创建对象或调用函数），必须遵循 V8 规定的参数传递和返回值约定。不正确的寄存器使用或数据格式会导致崩溃或未定义的行为。

   ```c++
   // 错误示例 (假设的，不一定对应实际 V8 API)
   v8::Local<v8::Value> GetPropertyBad(v8::Local<v8::Object> obj, v8::Local<v8::String> key) {
     // 开发者可能错误地假设属性值总是在某个特定的寄存器中
     // 而实际上需要调用 V8 提供的 API
     // ... 错误的寄存器访问逻辑 ...
     return some_incorrect_value;
   }
   ```

3. **在编写内联汇编时，与 V8 的寄存器使用冲突:**  如果开发者尝试在 V8 中嵌入汇编代码，必须非常小心地管理寄存器的使用，避免与 V8 自身的寄存器分配策略冲突。`interface-descriptors-arm64-inl.h` 中定义的信息对于编写正确的内联汇编至关重要。

总而言之，`v8/src/codegen/arm64/interface-descriptors-arm64-inl.h` 是 V8 引擎在 ARM64 架构上实现高性能 JavaScript 执行的关键组成部分，它定义了底层代码交互的规则。理解这些描述符有助于深入了解 V8 的内部工作原理。

### 提示词
```
这是目录为v8/src/codegen/arm64/interface-descriptors-arm64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/interface-descriptors-arm64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CODEGEN_ARM64_INTERFACE_DESCRIPTORS_ARM64_INL_H_
#define V8_CODEGEN_ARM64_INTERFACE_DESCRIPTORS_ARM64_INL_H_

#if V8_TARGET_ARCH_ARM64

#include "src/base/template-utils.h"
#include "src/codegen/interface-descriptors.h"
#include "src/execution/frames.h"

namespace v8 {
namespace internal {

constexpr auto CallInterfaceDescriptor::DefaultRegisterArray() {
  auto registers = RegisterArray(x0, x1, x2, x3, x4);
  static_assert(registers.size() == kMaxBuiltinRegisterParams);
  return registers;
}

constexpr auto CallInterfaceDescriptor::DefaultDoubleRegisterArray() {
  auto registers = DoubleRegisterArray(d0, d1, d2, d3, d4, d5, d6);
  return registers;
}

constexpr auto CallInterfaceDescriptor::DefaultReturnRegisterArray() {
  auto registers =
      RegisterArray(kReturnRegister0, kReturnRegister1, kReturnRegister2);
  return registers;
}

constexpr auto CallInterfaceDescriptor::DefaultReturnDoubleRegisterArray() {
  // Padding to have as many double return registers as GP return registers.
  auto registers = DoubleRegisterArray(kFPReturnRegister0, no_dreg, no_dreg);
  return registers;
}

#if DEBUG
template <typename DerivedDescriptor>
void StaticCallInterfaceDescriptor<DerivedDescriptor>::
    VerifyArgumentRegisterCount(CallInterfaceDescriptorData* data, int argc) {
  RegList allocatable_regs = data->allocatable_registers();
  if (argc >= 1) DCHECK(allocatable_regs.has(x0));
  if (argc >= 2) DCHECK(allocatable_regs.has(x1));
  if (argc >= 3) DCHECK(allocatable_regs.has(x2));
  if (argc >= 4) DCHECK(allocatable_regs.has(x3));
  if (argc >= 5) DCHECK(allocatable_regs.has(x4));
  if (argc >= 6) DCHECK(allocatable_regs.has(x5));
  if (argc >= 7) DCHECK(allocatable_regs.has(x6));
  if (argc >= 8) DCHECK(allocatable_regs.has(x7));
}
#endif  // DEBUG

// static
constexpr auto WriteBarrierDescriptor::registers() {
  // TODO(leszeks): Remove x7 which is just there for padding.
  return RegisterArray(x1, x5, x4, x2, x0, x3, kContextRegister, x7);
}

// static
constexpr Register LoadDescriptor::ReceiverRegister() { return x1; }
// static
constexpr Register LoadDescriptor::NameRegister() { return x2; }
// static
constexpr Register LoadDescriptor::SlotRegister() { return x0; }

// static
constexpr Register LoadWithVectorDescriptor::VectorRegister() { return x3; }

// static
constexpr Register KeyedLoadBaselineDescriptor::ReceiverRegister() {
  return x1;
}
// static
constexpr Register KeyedLoadBaselineDescriptor::NameRegister() {
  return kInterpreterAccumulatorRegister;
}
// static
constexpr Register KeyedLoadBaselineDescriptor::SlotRegister() { return x2; }

// static
constexpr Register KeyedLoadWithVectorDescriptor::VectorRegister() {
  return x3;
}

// static
constexpr Register EnumeratedKeyedLoadBaselineDescriptor::EnumIndexRegister() {
  return x4;
}

// static
constexpr Register EnumeratedKeyedLoadBaselineDescriptor::CacheTypeRegister() {
  return x5;
}

// static
constexpr Register EnumeratedKeyedLoadBaselineDescriptor::SlotRegister() {
  return x2;
}

// static
constexpr Register KeyedHasICBaselineDescriptor::ReceiverRegister() {
  return kInterpreterAccumulatorRegister;
}
// static
constexpr Register KeyedHasICBaselineDescriptor::NameRegister() { return x1; }
// static
constexpr Register KeyedHasICBaselineDescriptor::SlotRegister() { return x2; }

// static
constexpr Register KeyedHasICWithVectorDescriptor::VectorRegister() {
  return x3;
}

// static
constexpr Register
LoadWithReceiverAndVectorDescriptor::LookupStartObjectRegister() {
  return x4;
}

// static
constexpr Register StoreDescriptor::ReceiverRegister() { return x1; }
// static
constexpr Register StoreDescriptor::NameRegister() { return x2; }
// static
constexpr Register StoreDescriptor::ValueRegister() { return x0; }
// static
constexpr Register StoreDescriptor::SlotRegister() { return x4; }

// static
constexpr Register StoreWithVectorDescriptor::VectorRegister() { return x3; }

// static
constexpr Register DefineKeyedOwnDescriptor::FlagsRegister() { return x5; }

// static
constexpr Register StoreTransitionDescriptor::MapRegister() { return x5; }

// static
constexpr Register ApiGetterDescriptor::HolderRegister() { return x0; }
// static
constexpr Register ApiGetterDescriptor::CallbackRegister() { return x3; }

// static
constexpr Register GrowArrayElementsDescriptor::ObjectRegister() { return x0; }
// static
constexpr Register GrowArrayElementsDescriptor::KeyRegister() { return x3; }

// static
constexpr Register BaselineLeaveFrameDescriptor::ParamsSizeRegister() {
  return x3;
}
// static
constexpr Register BaselineLeaveFrameDescriptor::WeightRegister() { return x4; }

// static
// static
constexpr Register TypeConversionDescriptor::ArgumentRegister() { return x0; }

// static
constexpr Register
MaglevOptimizeCodeOrTailCallOptimizedCodeSlotDescriptor::FlagsRegister() {
  return x8;
}
// static
constexpr Register MaglevOptimizeCodeOrTailCallOptimizedCodeSlotDescriptor::
    FeedbackVectorRegister() {
  return x9;
}
// static
constexpr Register
MaglevOptimizeCodeOrTailCallOptimizedCodeSlotDescriptor::TemporaryRegister() {
  return x5;
}

// static
constexpr auto TypeofDescriptor::registers() { return RegisterArray(x0); }

// static
constexpr auto CallTrampolineDescriptor::registers() {
  // x1: target
  // x0: number of arguments
  return RegisterArray(x1, x0);
}

constexpr auto CopyDataPropertiesWithExcludedPropertiesDescriptor::registers() {
  // r1 : the source
  // r0 : the excluded property count
  return RegisterArray(x1, x0);
}

constexpr auto
CopyDataPropertiesWithExcludedPropertiesOnStackDescriptor::registers() {
  // r1 : the source
  // r0 : the excluded property count
  // x2 : the excluded property base
  return RegisterArray(x1, x0, x2);
}

// static
constexpr auto CallVarargsDescriptor::registers() {
  // x0 : number of arguments (on the stack)
  // x1 : the target to call
  // x4 : arguments list length (untagged)
  // x2 : arguments list (FixedArray)
  return RegisterArray(x1, x0, x4, x2);
}

// static
constexpr auto CallForwardVarargsDescriptor::registers() {
  // x1: target
  // x0: number of arguments
  // x2: start index (to supported rest parameters)
  return RegisterArray(x1, x0, x2);
}

// static
constexpr auto CallFunctionTemplateDescriptor::registers() {
  // x1 : function template info
  // x2 : number of arguments (on the stack)
  return RegisterArray(x1, x2);
}

// static
constexpr auto CallFunctionTemplateGenericDescriptor::registers() {
  // x1 : function template info
  // x2 : number of arguments (on the stack)
  // x3 : topmost script-having context
  return RegisterArray(x1, x2, x3);
}

// static
constexpr auto CallWithSpreadDescriptor::registers() {
  // x0 : number of arguments (on the stack)
  // x1 : the target to call
  // x2 : the object to spread
  return RegisterArray(x1, x0, x2);
}

// static
constexpr auto CallWithArrayLikeDescriptor::registers() {
  // x1 : the target to call
  // x2 : the arguments list
  return RegisterArray(x1, x2);
}

// static
constexpr auto ConstructVarargsDescriptor::registers() {
  // x0 : number of arguments (on the stack)
  // x1 : the target to call
  // x3 : the new target
  // x4 : arguments list length (untagged)
  // x2 : arguments list (FixedArray)
  return RegisterArray(x1, x3, x0, x4, x2);
}

// static
constexpr auto ConstructForwardVarargsDescriptor::registers() {
  // x3: new target
  // x1: target
  // x0: number of arguments
  // x2: start index (to supported rest parameters)
  return RegisterArray(x1, x3, x0, x2);
}

// static
constexpr auto ConstructWithSpreadDescriptor::registers() {
  // x0 : number of arguments (on the stack)
  // x1 : the target to call
  // x3 : the new target
  // x2 : the object to spread
  return RegisterArray(x1, x3, x0, x2);
}

// static
constexpr auto ConstructWithArrayLikeDescriptor::registers() {
  // x1 : the target to call
  // x3 : the new target
  // x2 : the arguments list
  return RegisterArray(x1, x3, x2);
}

// static
constexpr auto ConstructStubDescriptor::registers() {
  // x3: new target
  // x1: target
  // x0: number of arguments
  return RegisterArray(x1, x3, x0);
}

// static
constexpr auto AbortDescriptor::registers() { return RegisterArray(x1); }

// static
constexpr auto CompareDescriptor::registers() {
  // x1: left operand
  // x0: right operand
  return RegisterArray(x1, x0);
}

// static
constexpr auto Compare_BaselineDescriptor::registers() {
  // x1: left operand
  // x0: right operand
  // x2: feedback slot
  return RegisterArray(x1, x0, x2);
}

// static
constexpr auto BinaryOpDescriptor::registers() {
  // x1: left operand
  // x0: right operand
  return RegisterArray(x1, x0);
}

// static
constexpr auto BinaryOp_BaselineDescriptor::registers() {
  // x1: left operand
  // x0: right operand
  // x2: feedback slot
  return RegisterArray(x1, x0, x2);
}

// static
constexpr auto BinarySmiOp_BaselineDescriptor::registers() {
  // x0: left operand
  // x1: right operand
  // x2: feedback slot
  return RegisterArray(x0, x1, x2);
}

// static
constexpr Register
CallApiCallbackOptimizedDescriptor::ApiFunctionAddressRegister() {
  return x1;
}
// static
constexpr Register
CallApiCallbackOptimizedDescriptor::ActualArgumentsCountRegister() {
  return x2;
}
// static
constexpr Register
CallApiCallbackOptimizedDescriptor::FunctionTemplateInfoRegister() {
  return x3;
}
// static
constexpr Register CallApiCallbackOptimizedDescriptor::HolderRegister() {
  return x0;
}

// static
constexpr Register
CallApiCallbackGenericDescriptor::ActualArgumentsCountRegister() {
  return x2;
}
// static
constexpr Register
CallApiCallbackGenericDescriptor::TopmostScriptHavingContextRegister() {
  return x1;
}
// static
constexpr Register
CallApiCallbackGenericDescriptor::FunctionTemplateInfoRegister() {
  return x3;
}
// static
constexpr Register CallApiCallbackGenericDescriptor::HolderRegister() {
  return x0;
}

// static
constexpr auto InterpreterDispatchDescriptor::registers() {
  return RegisterArray(
      kInterpreterAccumulatorRegister, kInterpreterBytecodeOffsetRegister,
      kInterpreterBytecodeArrayRegister, kInterpreterDispatchTableRegister);
}

// static
constexpr auto InterpreterPushArgsThenCallDescriptor::registers() {
  return RegisterArray(x0,   // argument count
                       x2,   // address of first argument
                       x1);  // the target callable to be call
}

// static
constexpr auto InterpreterPushArgsThenConstructDescriptor::registers() {
  return RegisterArray(
      x0,   // argument count
      x4,   // address of the first argument
      x1,   // constructor to call
      x3,   // new target
      x2);  // allocation site feedback if available, undefined otherwise
}

// static
constexpr auto ConstructForwardAllArgsDescriptor::registers() {
  return RegisterArray(x1,   // constructor to call
                       x3);  // new target
}

// static
constexpr auto ResumeGeneratorDescriptor::registers() {
  return RegisterArray(x0,   // the value to pass to the generator
                       x1);  // the JSGeneratorObject to resume
}

// static
constexpr auto RunMicrotasksEntryDescriptor::registers() {
  return RegisterArray(x0, x1);
}

constexpr auto WasmJSToWasmWrapperDescriptor::registers() {
  // Arbitrarily picked register.
  return RegisterArray(x8);
}

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_ARM64

#endif  // V8_CODEGEN_ARM64_INTERFACE_DESCRIPTORS_ARM64_INL_H_
```