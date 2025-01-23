Response:
Let's break down the thought process for analyzing this C++ header file and answering the user's request.

1. **Understanding the Goal:** The user wants to understand the functionality of this specific V8 header file (`interface-descriptors-s390-inl.h`). They also have specific follow-up questions related to Torque, JavaScript relevance, logic, and common errors.

2. **Initial Analysis - Header File Basics:**
   - The `#ifndef`, `#define`, and `#endif` guards indicate this is a header file designed to prevent multiple inclusions.
   - The `// Copyright` notice gives context – it's part of the V8 project.
   - `#include` directives show dependencies: `interface-descriptors.h` and `frames.h`. This suggests it's related to describing how functions are called and how the execution stack is structured.
   - The `namespace v8 { namespace internal { ... } }` structure is standard C++ for organizing code within a larger project.
   - The `#if V8_TARGET_ARCH_S390X` preprocessor directive is crucial. It immediately tells us this code is *specific* to the S390X architecture. This is a key piece of information.

3. **Core Functionality - Interface Descriptors:** The filename and the inclusion of `interface-descriptors.h` strongly suggest that this file defines *interface descriptors*. What are these?  They are likely structures or classes that describe how functions are called, including:
   - **Register Usage:** Which registers are used for passing arguments, returning values, and storing temporary data.
   - **Call Conventions:**  Implicit rules about how data is passed and managed during function calls.

4. **Examining the Code - Key Elements:**
   - **`CallInterfaceDescriptor`:**  Defines default register arrays for general-purpose and floating-point arguments and return values. The `static_assert` confirms the size of the register array.
   - **`StaticCallInterfaceDescriptor::VerifyArgumentRegisterCount`:**  This debug-only function checks if enough registers are allocated for the given number of arguments. This reinforces the idea that these descriptors manage argument passing.
   - **Specific Descriptor Types (e.g., `WriteBarrierDescriptor`, `LoadDescriptor`, `StoreDescriptor`):** These are the core of the file. Each descriptor likely represents a specific kind of operation or function call within the V8 engine. The `static constexpr Register ...()` functions within each descriptor define which registers are used for specific purposes (Receiver, Name, Value, Slot, Vector, etc.). This is the most concrete information about how V8 interacts with the underlying architecture.
   - **Groups of Descriptors:** Notice patterns like `Load...`, `Store...`, `Call...`, `Construct...`, `BinaryOp...`. This suggests logical groupings based on the type of operation.
   - **Descriptors with "Baseline" Suffix:** Descriptors like `KeyedLoadBaselineDescriptor` suggest optimizations or different execution paths within the V8 engine. "Baseline" likely refers to a less optimized or simpler version.
   - **Descriptors with "WithVector" Suffix:** These likely involve vector instructions or SIMD operations, hinting at performance optimizations.
   - **Descriptors with "Varargs" and "Spread" Suffixes:**  These clearly relate to JavaScript's variable arguments and spread syntax.
   - **`InterpreterDispatchDescriptor`, `InterpreterPushArgsThenCallDescriptor`, etc.:** These are specific to the interpreter, indicating how bytecode is executed.
   - **`WasmJSToWasmWrapperDescriptor`:** This relates to WebAssembly integration.

5. **Answering Specific User Questions:**

   - **Functionality:**  Summarize the observations from the code analysis. Emphasize the role of defining register usage for different operations on the S390X architecture.
   - **Torque:** Check the filename extension. Since it's `.inl.h`, it's *not* a Torque file. Explain what Torque is (a V8-specific language).
   - **JavaScript Relevance:**  Connect the descriptors to JavaScript concepts. For example, `LoadDescriptor` is related to accessing object properties, `CallVarargsDescriptor` handles function calls with variable arguments, etc. Provide concrete JavaScript examples to illustrate these connections.
   - **Logic and I/O:** Choose a simple descriptor with clear register assignments (like `LoadDescriptor`). Hypothesize input (registers containing specific values) and output (the intended action based on those registers).
   - **Common Programming Errors:** Think about the purpose of these descriptors. They enforce calling conventions. A common error would be a JavaScript developer *indirectly* causing problems by misusing language features that lead to incorrect register usage at the lower level. Focus on type errors or incorrect arguments leading to crashes or unexpected behavior.

6. **Structuring the Answer:** Organize the information logically, using headings and bullet points for clarity. Start with a general summary of the file's purpose, then address each of the user's specific questions.

7. **Refinement and Language:** Use clear and concise language. Avoid overly technical jargon where possible, or explain it if necessary. Double-check the details and ensure accuracy. For example, initially, I might have just said "deals with function calls," but it's more precise to say it defines *how* function calls are made at the assembly level for a specific architecture.

By following this structured approach, breaking down the code into smaller parts, and connecting the C++ code to higher-level JavaScript concepts, we can effectively answer the user's request and provide a comprehensive explanation.
好的，让我们来分析一下 `v8/src/codegen/s390/interface-descriptors-s390-inl.h` 这个 V8 源代码文件。

**功能概述**

这个头文件 (`interface-descriptors-s390-inl.h`) 的主要功能是为 V8 JavaScript 引擎在 s390 架构（包括 s390x）上生成代码时，定义各种操作和函数调用的接口描述符。

**更详细的解释:**

* **接口描述符 (Interface Descriptors):**  在 V8 的代码生成过程中，需要知道如何调用各种内置函数、运行时函数以及 JavaScript 代码。接口描述符就扮演着这样的角色，它们描述了函数调用时的参数传递方式、返回值位置以及使用的寄存器。
* **特定于架构 (s390):**  这个文件名的 `s390` 部分表明，这些接口描述符是专门为 s390 和 s390x 架构设计的。不同的 CPU 架构有不同的寄存器约定和调用约定，因此需要为每个架构定义相应的接口描述符。
* **`.inl.h` 后缀:**  `inl` 通常表示内联 (inline) 函数的定义。这个文件很可能包含了一些内联函数的定义，这些函数用于方便地访问和使用这些接口描述符。
* **寄存器分配:**  文件中大量使用了 `constexpr auto ... registers()` 这样的定义，它们指定了在特定操作或函数调用中使用的寄存器。例如，`LoadDescriptor::ReceiverRegister()` 返回用于传递接收者对象的寄存器。

**关于文件扩展名 `.tq`**

如果 `v8/src/codegen/s390/interface-descriptors-s390-inl.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 开发的一种领域特定语言 (DSL)，用于生成高效的 C++ 代码，特别是用于实现 V8 的内置函数和运行时代码。

**与 JavaScript 功能的关系 (并用 JavaScript 举例)**

`interface-descriptors-s390-inl.h` 文件虽然是 C++ 代码，但它直接关系到 V8 如何执行 JavaScript 代码。它定义了底层实现的细节，使得 V8 能够正确地进行各种操作。以下是一些 JavaScript 功能与其对应的接口描述符的关联示例：

1. **属性访问 (Property Access):**
   - JavaScript 代码: `const value = object.property;`
   - 相关的接口描述符: `LoadDescriptor`
   - `LoadDescriptor::ReceiverRegister()` 指定了存放 `object` 的寄存器。
   - `LoadDescriptor::NameRegister()` 指定了存放属性名 `"property"` 的寄存器。
   - V8 在生成代码时，会使用 `LoadDescriptor` 来确定如何将 `object` 和 `"property"` 传递给底层的加载属性的实现。

2. **函数调用 (Function Call):**
   - JavaScript 代码: `functionName(arg1, arg2);`
   - 相关的接口描述符: `CallInterfaceDescriptor`, `CallVarargsDescriptor`, `CallForwardVarargsDescriptor` 等 (取决于参数数量和调用方式)。
   - `CallInterfaceDescriptor::DefaultRegisterArray()` 定义了默认情况下用于传递参数的寄存器 (r2, r3, r4, r5, r6)。
   - V8 会使用这些描述符来设置寄存器，并将参数传递给被调用的函数。

3. **对象创建 (Object Creation):**
   - JavaScript 代码: `const obj = new MyClass();`
   - 相关的接口描述符: `ConstructStubDescriptor`, `ConstructVarargsDescriptor` 等。
   - 这些描述符定义了构造函数调用时目标函数、`new.target` 以及参数的传递方式。

4. **算术运算 (Arithmetic Operations):**
   - JavaScript 代码: `const sum = a + b;`
   - 相关的接口描述符: `BinaryOpDescriptor`, `BinaryOp_BaselineDescriptor`, `BinarySmiOp_BaselineDescriptor`.
   - 这些描述符定义了操作数寄存器 (如 `r3`, `r2`) 和可能的临时寄存器 (`r4`)。

**代码逻辑推理 (假设输入与输出)**

让我们以 `LoadDescriptor` 为例进行代码逻辑推理。

**假设输入:**

* `r3` 寄存器包含指向一个 JavaScript 对象的指针 (接收者对象)。
* `r4` 寄存器包含指向一个 JavaScript 字符串的指针 (属性名，例如 "name")。

**接口描述符:**

```c++
// static
constexpr Register LoadDescriptor::ReceiverRegister() { return r3; }
// static
constexpr Register LoadDescriptor::NameRegister() { return r4; }
// static
constexpr Register LoadDescriptor::SlotRegister() { return r2; }
```

**推理过程:**

当 V8 需要生成用于加载对象属性的代码时，它会使用 `LoadDescriptor`。根据这个描述符，代码生成器会知道：

1. 接收者对象（`object`）应该放在 `r3` 寄存器中。
2. 要访问的属性名（`property`）应该放在 `r4` 寄存器中。
3. `r2` 寄存器可能被用于存储一些中间状态或槽位信息（SlotRegister 的用途可能更偏向于内部优化，不一定总是直接对应最终结果）。

**可能的输出:**

执行完加载操作后，属性的值可能会被存储在：

*  **累加器寄存器 (Accumulator Register):**  在 V8 中，累加器寄存器常用于存放操作的最终结果。对于 s390 架构，累加器寄存器可能是预定义的，但在这个文件中没有直接显示。
*  **其他指定的返回寄存器:** 虽然 `LoadDescriptor` 本身没有明确定义返回寄存器，但通常会有通用的返回约定，例如 `CallInterfaceDescriptor::DefaultReturnRegisterArray()` 中定义的 `kReturnRegister0`。

**涉及用户常见的编程错误 (举例说明)**

虽然用户通常不会直接操作这些底层的接口描述符，但某些 JavaScript 编程错误可能会导致 V8 生成的代码与这些描述符定义的约定不符，从而引发运行时错误或崩溃。以下是一些可能的场景：

1. **尝试访问 `null` 或 `undefined` 的属性:**
   ```javascript
   let obj = null;
   console.log(obj.property); // TypeError: Cannot read properties of null (or undefined)
   ```
   在这种情况下，如果 V8 尝试使用 `LoadDescriptor` 来加载 `null` 对象的属性，底层的代码可能会尝试解引用一个空指针，导致崩溃。V8 会有相应的检查来避免这种情况，但这个例子说明了为什么属性访问的底层机制需要正确处理各种边界情况。

2. **类型不匹配导致的优化失败或运行时错误:**
   ```javascript
   function add(a, b) {
       return a + b;
   }

   add(5, 10);      // 假设 V8 为此生成了优化代码，期望 a 和 b 是数字
   add("hello", 10); // 这可能导致之前优化的代码失效或产生意外结果
   ```
   如果 V8 为 `add` 函数生成了假设 `a` 和 `b` 都是数字的优化代码，并且使用了 `BinaryOpDescriptor` 中为数字运算定义的寄存器，那么当传入字符串时，底层的加法操作可能无法正确执行。V8 的类型系统和优化机制会努力处理这种情况，但类型不匹配仍然是常见的编程错误，可能会暴露底层实现的某些问题。

3. **不正确的函数参数类型或数量:**
   ```javascript
   function greet(name) {
       console.log("Hello, " + name);
   }

   greet(); // 缺少参数
   greet(1, 2); // 参数过多
   ```
   当 JavaScript 代码以不符合函数定义的方式调用函数时，V8 在生成调用代码时需要使用相应的 `Call...Descriptor`。如果参数数量或类型不匹配，可能会导致传递到寄存器中的值不符合预期，从而在函数执行时出错。

**总结**

`v8/src/codegen/s390/interface-descriptors-s390-inl.h` 是 V8 在 s390 架构上生成代码的关键组成部分，它定义了各种操作和函数调用的接口规范。了解这些描述符有助于理解 V8 如何将 JavaScript 代码转换为机器码并执行，并能帮助理解某些运行时错误的底层原因。 虽然开发者通常不需要直接修改这些文件，但理解其作用对于深入了解 V8 的架构至关重要。

### 提示词
```
这是目录为v8/src/codegen/s390/interface-descriptors-s390-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/interface-descriptors-s390-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CODEGEN_S390_INTERFACE_DESCRIPTORS_S390_INL_H_
#define V8_CODEGEN_S390_INTERFACE_DESCRIPTORS_S390_INL_H_

#if V8_TARGET_ARCH_S390X

#include "src/codegen/interface-descriptors.h"
#include "src/execution/frames.h"

namespace v8 {
namespace internal {

constexpr auto CallInterfaceDescriptor::DefaultRegisterArray() {
  auto registers = RegisterArray(r2, r3, r4, r5, r6);
  static_assert(registers.size() == kMaxBuiltinRegisterParams);
  return registers;
}

constexpr auto CallInterfaceDescriptor::DefaultDoubleRegisterArray() {
  auto registers = DoubleRegisterArray(d1, d2, d3, d4, d5, d6, d7);
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
  if (argc >= 1) DCHECK(allocatable_regs.has(r2));
  if (argc >= 2) DCHECK(allocatable_regs.has(r3));
  if (argc >= 3) DCHECK(allocatable_regs.has(r4));
  if (argc >= 4) DCHECK(allocatable_regs.has(r5));
  if (argc >= 5) DCHECK(allocatable_regs.has(r6));
  if (argc >= 6) DCHECK(allocatable_regs.has(r7));
  if (argc >= 7) DCHECK(allocatable_regs.has(r8));
  if (argc >= 8) DCHECK(allocatable_regs.has(r9));
  // Additional arguments are passed on the stack.
}
#endif  // DEBUG

// static
constexpr auto WriteBarrierDescriptor::registers() {
  return RegisterArray(r3, r7, r6, r4, r2, r5, kContextRegister);
}

// static
constexpr Register LoadDescriptor::ReceiverRegister() { return r3; }
// static
constexpr Register LoadDescriptor::NameRegister() { return r4; }
// static
constexpr Register LoadDescriptor::SlotRegister() { return r2; }

// static
constexpr Register LoadWithVectorDescriptor::VectorRegister() { return r5; }

// static
constexpr Register KeyedLoadBaselineDescriptor::ReceiverRegister() {
  return r3;
}
// static
constexpr Register KeyedLoadBaselineDescriptor::NameRegister() {
  return kInterpreterAccumulatorRegister;
}
// static
constexpr Register KeyedLoadBaselineDescriptor::SlotRegister() { return r4; }

// static
constexpr Register KeyedLoadWithVectorDescriptor::VectorRegister() {
  return r5;
}

// static
constexpr Register EnumeratedKeyedLoadBaselineDescriptor::EnumIndexRegister() {
  return r6;
}

// static
constexpr Register EnumeratedKeyedLoadBaselineDescriptor::CacheTypeRegister() {
  return r7;
}

// static
constexpr Register EnumeratedKeyedLoadBaselineDescriptor::SlotRegister() {
  return r4;
}

// static
constexpr Register KeyedHasICBaselineDescriptor::ReceiverRegister() {
  return kInterpreterAccumulatorRegister;
}
// static
constexpr Register KeyedHasICBaselineDescriptor::NameRegister() { return r3; }
// static
constexpr Register KeyedHasICBaselineDescriptor::SlotRegister() { return r4; }

// static
constexpr Register KeyedHasICWithVectorDescriptor::VectorRegister() {
  return r5;
}

// static
constexpr Register
LoadWithReceiverAndVectorDescriptor::LookupStartObjectRegister() {
  return r6;
}

// static
constexpr Register StoreDescriptor::ReceiverRegister() { return r3; }
// static
constexpr Register StoreDescriptor::NameRegister() { return r4; }
// static
constexpr Register StoreDescriptor::ValueRegister() { return r2; }
// static
constexpr Register StoreDescriptor::SlotRegister() { return r6; }

// static
constexpr Register StoreWithVectorDescriptor::VectorRegister() { return r5; }

// static
constexpr Register DefineKeyedOwnDescriptor::FlagsRegister() { return r7; }

// static
constexpr Register StoreTransitionDescriptor::MapRegister() { return r7; }

// static
constexpr Register ApiGetterDescriptor::HolderRegister() { return r2; }
// static
constexpr Register ApiGetterDescriptor::CallbackRegister() { return r5; }

// static
constexpr Register GrowArrayElementsDescriptor::ObjectRegister() { return r2; }
// static
constexpr Register GrowArrayElementsDescriptor::KeyRegister() { return r5; }

// static
constexpr Register BaselineLeaveFrameDescriptor::ParamsSizeRegister() {
  // TODO(v8:11421): Implement on this platform.
  return r5;
}
// static
constexpr Register BaselineLeaveFrameDescriptor::WeightRegister() {
  // TODO(v8:11421): Implement on this platform.
  return r6;
}

// static
// static
constexpr Register TypeConversionDescriptor::ArgumentRegister() { return r2; }

// static
constexpr auto TypeofDescriptor::registers() { return RegisterArray(r2); }

// static
constexpr Register
MaglevOptimizeCodeOrTailCallOptimizedCodeSlotDescriptor::FlagsRegister() {
  return r4;
}
// static
constexpr Register MaglevOptimizeCodeOrTailCallOptimizedCodeSlotDescriptor::
    FeedbackVectorRegister() {
  return r7;
}
// static
constexpr Register
MaglevOptimizeCodeOrTailCallOptimizedCodeSlotDescriptor::TemporaryRegister() {
  return r6;
}

// static
constexpr auto CallTrampolineDescriptor::registers() {
  // r2 : number of arguments
  // r3 : the target to call
  return RegisterArray(r3, r2);
}

// static
constexpr auto CopyDataPropertiesWithExcludedPropertiesDescriptor::registers() {
  // r3 : the source
  // r2 : the excluded property count
  return RegisterArray(r3, r2);
}

// static
constexpr auto
CopyDataPropertiesWithExcludedPropertiesOnStackDescriptor::registers() {
  // r3 : the source
  // r2 : the excluded property count
  // r4 : the excluded property base
  return RegisterArray(r3, r2, r4);
}

// static
constexpr auto CallVarargsDescriptor::registers() {
  // r2 : number of arguments (on the stack)
  // r3 : the target to call
  // r6 : arguments list length (untagged)
  // r4 : arguments list (FixedArray)
  return RegisterArray(r3, r2, r6, r4);
}

// static
constexpr auto CallForwardVarargsDescriptor::registers() {
  // r2 : number of arguments
  // r4 : start index (to support rest parameters)
  // r3 : the target to call
  return RegisterArray(r3, r2, r4);
}

// static
constexpr auto CallFunctionTemplateDescriptor::registers() {
  // r3 : function template info
  // r4 : number of arguments (on the stack)
  return RegisterArray(r3, r4);
}

// static
constexpr auto CallFunctionTemplateGenericDescriptor::registers() {
  // r3 : function template info
  // r4 : number of arguments (on the stack)
  // r5 : topmost script-having context
  return RegisterArray(r3, r4, r5);
}

// static
constexpr auto CallWithSpreadDescriptor::registers() {
  // r2: number of arguments (on the stack)
  // r3 : the target to call
  // r4 : the object to spread
  return RegisterArray(r3, r2, r4);
}

// static
constexpr auto CallWithArrayLikeDescriptor::registers() {
  // r3 : the target to call
  // r4 : the arguments list
  return RegisterArray(r3, r4);
}

// static
constexpr auto ConstructVarargsDescriptor::registers() {
  // r2 : number of arguments (on the stack)
  // r3 : the target to call
  // r5 : the new target
  // r6 : arguments list length (untagged)
  // r4 : arguments list (FixedArray)
  return RegisterArray(r3, r5, r2, r6, r4);
}

// static
constexpr auto ConstructForwardVarargsDescriptor::registers() {
  // r2 : number of arguments
  // r5 : the new target
  // r4 : start index (to support rest parameters)
  // r3 : the target to call
  return RegisterArray(r3, r5, r2, r4);
}

// static
constexpr auto ConstructWithSpreadDescriptor::registers() {
  // r2 : number of arguments (on the stack)
  // r3 : the target to call
  // r5 : the new target
  // r4 : the object to spread
  return RegisterArray(r3, r5, r2, r4);
}

// static
constexpr auto ConstructWithArrayLikeDescriptor::registers() {
  // r3 : the target to call
  // r5 : the new target
  // r4 : the arguments list
  return RegisterArray(r3, r5, r4);
}

// static
constexpr auto ConstructStubDescriptor::registers() {
  // r2 : number of arguments
  // r3 : the target to call
  // r5 : the new target
  return RegisterArray(r3, r5, r2);
}

// static
constexpr auto AbortDescriptor::registers() { return RegisterArray(r3); }

// static
constexpr auto CompareDescriptor::registers() { return RegisterArray(r3, r2); }

// static
constexpr auto Compare_BaselineDescriptor::registers() {
  return RegisterArray(r3, r2, r4);
}

// static
constexpr auto BinaryOpDescriptor::registers() { return RegisterArray(r3, r2); }

// static
constexpr auto BinaryOp_BaselineDescriptor::registers() {
  return RegisterArray(r3, r2, r4);
}

// static
constexpr auto BinarySmiOp_BaselineDescriptor::registers() {
  return RegisterArray(r2, r3, r4);
}

// static
constexpr Register
CallApiCallbackOptimizedDescriptor::ApiFunctionAddressRegister() {
  return r3;
}
// static
constexpr Register
CallApiCallbackOptimizedDescriptor::ActualArgumentsCountRegister() {
  return r4;
}
// static
constexpr Register
CallApiCallbackOptimizedDescriptor::FunctionTemplateInfoRegister() {
  return r5;
}
// static
constexpr Register CallApiCallbackOptimizedDescriptor::HolderRegister() {
  return r2;
}
// static
constexpr Register
CallApiCallbackGenericDescriptor::ActualArgumentsCountRegister() {
  return r4;
}
// static
constexpr Register
CallApiCallbackGenericDescriptor::TopmostScriptHavingContextRegister() {
  return r3;
}
// static
constexpr Register
CallApiCallbackGenericDescriptor::FunctionTemplateInfoRegister() {
  return r5;
}
// static
constexpr Register CallApiCallbackGenericDescriptor::HolderRegister() {
  return r2;
}

// static
constexpr auto InterpreterDispatchDescriptor::registers() {
  return RegisterArray(
      kInterpreterAccumulatorRegister, kInterpreterBytecodeOffsetRegister,
      kInterpreterBytecodeArrayRegister, kInterpreterDispatchTableRegister);
}

// static
constexpr auto InterpreterPushArgsThenCallDescriptor::registers() {
  return RegisterArray(r2,   // argument count
                       r4,   // address of first argument
                       r3);  // the target callable to be call
}

// static
constexpr auto InterpreterPushArgsThenConstructDescriptor::registers() {
  return RegisterArray(
      r2,   // argument count
      r6,   // address of the first argument
      r3,   // constructor to call
      r5,   // new target
      r4);  // allocation site feedback if available, undefined otherwise
}

// static
constexpr auto ConstructForwardAllArgsDescriptor::registers() {
  return RegisterArray(r3,   // constructor to call
                       r5);  // new target
}

// static
constexpr auto ResumeGeneratorDescriptor::registers() {
  return RegisterArray(r2,   // the value to pass to the generator
                       r3);  // the JSGeneratorObject to resume
}

// static
constexpr auto RunMicrotasksEntryDescriptor::registers() {
  return RegisterArray(r2, r3);
}

constexpr auto WasmJSToWasmWrapperDescriptor::registers() {
  // Arbitrarily picked register.
  return RegisterArray(r8);
}
}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_S390X

#endif  // V8_CODEGEN_S390_INTERFACE_DESCRIPTORS_S390_INL_H_
```