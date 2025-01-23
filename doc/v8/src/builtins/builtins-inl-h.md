Response:
Let's break down the thought process to analyze the provided C++ header file.

**1. Understanding the Core Request:**

The request asks for the functionality of the given V8 source code file (`v8/src/builtins/builtins-inl.h`). It also has specific instructions about how to describe the functionality, including mentioning Torque if the filename ended in `.tq`, relating it to JavaScript, providing examples, and identifying common programming errors.

**2. Initial Analysis - Header File Structure:**

I immediately recognize that this is a C++ header file (`.h`). The `#ifndef`, `#define`, and `#endif` guards are standard C++ include guards, preventing multiple inclusions. The `#include` statements indicate dependencies on other V8 internal headers (`builtins.h` and `execution/isolate.h`). The `namespace v8 { namespace internal { ... } }` structure signifies this code is part of the V8 JavaScript engine's internal implementation.

**3. Examining the Content - Static constexpr Functions:**

The file primarily contains `static constexpr` functions within the `Builtins` class. Let's analyze what each function seems to do:

* **`RecordWrite`, `IndirectPointerBarrier`, `EphemeronKeyBarrier`:** These functions take a `SaveFPRegsMode` enum as input and return a `Builtin` enum value. The `switch` statements suggest they map different `SaveFPRegsMode` values to specific built-in functions related to memory management (record write, pointer barrier, ephemeron key barrier). The "FP" likely refers to floating-point registers, suggesting optimization or platform-specific considerations.

* **`AdaptorWithBuiltinExitFrame`:** This function takes an integer representing the formal parameter count and returns a `Builtin` enum value. The `switch` statement maps specific parameter counts to different "AdaptorWithBuiltinExitFrame" built-ins. This hints at function call adaptation based on the number of arguments.

* **`CallFunction`, `Call`:** Both functions take a `ConvertReceiverMode` enum and return a `Builtin` enum. The `switch` statement indicates they differentiate how the `this` value (receiver) of a function call is handled (null/undefined, not null/undefined, or any).

* **`IsAnyCall`:** This function takes a `Builtin` and returns a `bool`. It checks if the given `Builtin` is one of the `CallFunction` or `Call` variants. This suggests a way to identify different call mechanisms.

* **`NonPrimitiveToPrimitive`, `OrdinaryToPrimitive`:** These functions take an "hint" enum (`ToPrimitiveHint`, `OrdinaryToPrimitiveHint`) and return a `Builtin`. They seem related to converting non-primitive JavaScript values to primitive types (number, string, default).

* **`StringAdd`:** Takes `StringAddFlags` and returns a `Builtin`. This likely represents different strategies for string concatenation.

* **`LoadGlobalIC`, `LoadGlobalICInOptimizedCode`:** Take a `TypeofMode` and return a `Builtin`. "IC" likely stands for Inline Cache, a performance optimization technique. These seem related to accessing global variables, with different strategies depending on whether it's inside a `typeof` operation.

* **`CEntry`, `RuntimeCEntry`, `InterpreterCEntry`:** These are more complex. `CEntry` takes several arguments related to result size, argument passing mode, and whether a built-in exit frame is needed. The other two are wrappers around `CEntry` with some arguments fixed. "CEntry" likely refers to calling C++ functions from JavaScript. The different parameters likely handle various calling conventions and contexts.

* **`InterpreterPushArgsThenCall`, `InterpreterPushArgsThenConstruct`:** These functions take enums related to argument pushing and receiver mode and return `Builtin` values. They appear specific to the interpreter and how arguments are prepared for function calls and constructor calls.

* **`EntryOf`:** Takes a `Builtin` and an `Isolate` pointer and returns an `Address`. This likely retrieves the actual memory address of the built-in function.

* **`IsJSEntryVariant`:** Takes a `Builtin` and returns a `bool`. It checks if the `Builtin` is related to entering JavaScript execution.

* **`GetFormalParameterCount`:** Takes a `Builtin` and returns an `int`. It seems to retrieve the expected number of arguments for a given built-in function.

* **`WasmBuiltinHandleArrayIndex`, `WasmBuiltinHandleOf` (within `#ifdef V8_ENABLE_WEBASSEMBLY`):** These are related to WebAssembly. They calculate an index and retrieve a handle (likely a pointer or identifier) for WebAssembly built-in functions.

**4. Answering Specific Parts of the Request:**

* **Functionality:**  The core functionality is to provide a way to obtain specific `Builtin` enum values based on different criteria (flags, modes, counts). These `Builtin` enums represent different pre-compiled code snippets or entry points within the V8 engine. This allows the engine to efficiently select the correct implementation for various operations.

* **Torque:** The filename doesn't end in `.tq`, so it's not a Torque source file.

* **Relationship to JavaScript (with examples):**  Many of these built-ins directly correspond to JavaScript operations. For instance:
    * `CallFunction` relates to calling JavaScript functions.
    * `StringAdd` relates to the `+` operator for strings.
    * `NonPrimitiveToPrimitive` relates to implicit type conversions (e.g., when using an object where a string is expected).
    * `LoadGlobalIC` relates to accessing global variables.

    *Example:*
    ```javascript
    function myFunction(a, b) {
      return a + b;
    }

    myFunction(1, 2); // Internally, V8 might use a Builtin related to function calls.

    let str1 = "hello";
    let str2 = "world";
    let combined = str1 + str2; // V8 would use a Builtin like StringAdd.

    console.log(window.parseInt); // Accessing a global like parseInt involves a Builtin like LoadGlobalIC.
    ```

* **Code Logic Inference (with assumptions):**

    * **Assumption:** `SaveFPRegsMode::kIgnore` means floating-point registers don't need saving, while `SaveFPRegsMode::kSave` means they do.
    * **Input:** `Builtins::RecordWrite(SaveFPRegsMode::kSave)`
    * **Output:** `Builtin::kRecordWriteSaveFP`

    * **Assumption:** `ConvertReceiverMode` dictates how the `this` value is handled during a function call.
    * **Input:** `Builtins::CallFunction(ConvertReceiverMode::kNullOrUndefined)`
    * **Output:** `Builtin::kCallFunction_ReceiverIsNullOrUndefined`

* **Common Programming Errors:**

    * **Incorrect number of arguments:** While not directly *caused* by this header file, the `AdaptorWithBuiltinExitFrame` logic highlights the importance of providing the correct number of arguments when calling functions. JavaScript doesn't enforce strict argument counts, but V8 internally might have optimized paths for specific counts. Providing the wrong number might lead to performance overhead or unexpected behavior in edge cases.

    * **Type errors leading to implicit conversions:**  The `NonPrimitiveToPrimitive` built-ins are used during implicit type conversions. Relying too heavily on implicit conversions can make code harder to understand and can sometimes lead to unexpected results. For example, adding a number to an object might unexpectedly call the object's `toString()` method.

**5. Refining the Explanation:**

After this detailed analysis, I can synthesize the information into a clear and comprehensive explanation like the example you provided. The key is to connect the low-level C++ code to higher-level JavaScript concepts.

**Self-Correction/Refinement during the process:**

* Initially, I might not have immediately understood the purpose of the `SaveFPRegsMode`. Looking at the names of the related built-ins (`RecordWrite`, `IndirectPointerBarrier`, `EphemeronKeyBarrier`) and the "FP" in the enum would guide me to the idea of floating-point registers and memory management.
* I might have initially overlooked the WebAssembly-related code within the `#ifdef`. Recognizing the `#ifdef V8_ENABLE_WEBASSEMBLY` would prompt me to investigate those functions and their purpose.
* When explaining the JavaScript relationship, I'd need to think about which JavaScript operations would likely involve these underlying built-ins. This requires some knowledge of how JavaScript engines work internally.

By following this structured analysis and iterative refinement, I can arrive at a thorough and accurate explanation of the provided V8 source code.
好的，让我们来分析一下 `v8/src/builtins/builtins-inl.h` 这个 V8 源代码文件。

**功能概述**

`v8/src/builtins/builtins-inl.h` 是 V8 JavaScript 引擎中定义内建函数（built-ins）的一个头文件。它主要提供了一种便捷的方式来获取代表不同内建函数的 `Builtin` 枚举值。这些内建函数是 V8 引擎预先编译好的、用于执行特定操作的代码片段，例如对象属性访问、函数调用、类型转换等等。

**主要功能点：**

1. **提供获取 `Builtin` 枚举值的静态常量函数:** 文件中定义了许多 `static constexpr` 函数，这些函数根据不同的参数（例如执行模式、类型提示、参数数量等）返回相应的 `Builtin` 枚举值。`Builtin` 是一个枚举类型，它的每个成员都代表一个特定的内建函数。

2. **对内建函数进行分类和参数化:** 这些静态函数的名字和参数反映了它们所代表的内建函数的功能和执行场景。例如，`RecordWrite` 函数根据是否需要保存浮点寄存器返回不同的 `Builtin` 值，`CallFunction` 函数根据接收者（receiver）的处理模式返回不同的 `Builtin` 值。

3. **作为 V8 内部使用的查找表:**  这个文件可以被 V8 引擎的其他部分引用，以便在需要执行特定操作时，能够快速查找到对应的内建函数。

**关于 `.tq` 结尾**

如果 `v8/src/builtins/builtins-inl.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 专门设计的一种类型化的中间语言，用于编写高性能的内建函数。Torque 代码会被编译成 C++ 代码。由于当前文件名是 `.h`，所以它不是 Torque 文件，而是一个标准的 C++ 头文件。

**与 JavaScript 功能的关系（含 JavaScript 示例）**

`v8/src/builtins/builtins-inl.h` 中定义的 `Builtin` 枚举值和相关的静态函数，直接关联到 JavaScript 的各种核心功能。当 JavaScript 代码执行时，V8 引擎会根据操作类型调用相应的内建函数。

以下是一些 JavaScript 功能与 `builtins-inl.h` 中定义的内建函数的对应关系示例：

* **函数调用：**  `Builtins::CallFunction` 和 `Builtins::Call` 用于获取不同调用场景下的内建函数。

   ```javascript
   function myFunction() {
       console.log("Hello");
   }

   myFunction(); //  V8 内部会调用与 Builtins::CallFunction 或 Builtins::Call 相关的内建函数。

   const obj = {
       method() {
           console.log("Method called");
       }
   };
   obj.method(); // 这里可能涉及不同的 receiver 处理模式，对应 Builtins::Call 的不同变体。
   ```

* **类型转换：** `Builtins::NonPrimitiveToPrimitive` 和 `Builtins::OrdinaryToPrimitive` 用于获取将非原始值转换为原始值的内建函数。

   ```javascript
   let obj = {
       toString() {
           return "Object as string";
       },
       valueOf() {
           return 10;
       }
   };

   console.log(obj + ""); // 触发 Builtins::NonPrimitiveToPrimitive_Default (默认 hint 是 String)
   console.log(Number(obj)); // 触发 Builtins::OrdinaryToPrimitive_Number (hint 是 Number，会优先调用 valueOf)
   ```

* **字符串操作：** `Builtins::StringAdd` 用于获取字符串连接的内建函数。

   ```javascript
   let str1 = "Hello";
   let str2 = " World";
   let combined = str1 + str2; // 触发 Builtins::StringAdd 相关的内建函数。
   ```

* **全局变量访问：** `Builtins::LoadGlobalIC` 用于获取加载全局变量的内建函数。 "IC" 代表 Inline Cache，是 V8 的优化技术。

   ```javascript
   console.log(parseInt); // 访问全局变量 parseInt，V8 会使用 Builtins::LoadGlobalIC 相关的内建函数。
   ```

* **记录写屏障 (Record Write Barrier)：** `Builtins::RecordWrite` 与垃圾回收机制相关，用于在修改对象属性时通知垃圾回收器。

   ```javascript
   let obj1 = { data: null };
   let obj2 = { value: 10 };
   obj1.data = obj2; //  赋值操作可能触发 Builtins::RecordWrite，以便垃圾回收器跟踪对象之间的引用关系。
   ```

**代码逻辑推理（假设输入与输出）**

假设我们调用了以下 C++ 代码：

* **假设输入:** `Builtins::CallFunction(ConvertReceiverMode::kNotNullOrUndefined)`
* **推理:**  `ConvertReceiverMode::kNotNullOrUndefined` 表示在函数调用时，接收者（`this` 值）不为 `null` 或 `undefined`。
* **输出:** 根据 `builtins-inl.h` 中的 `switch` 语句，这个调用将返回 `Builtin::kCallFunction_ReceiverIsNotNullOrUndefined`。

另一个例子：

* **假设输入:** `Builtins::StringAdd(STRING_ADD_CONVERT_LEFT)`
* **推理:** `STRING_ADD_CONVERT_LEFT` 标志表示如果字符串连接操作的左侧操作数不是字符串，则需要将其转换为字符串。
* **输出:**  根据 `builtins-inl.h` 中的 `switch` 语句，这个调用将返回 `Builtin::kStringAddConvertLeft`。

**涉及用户常见的编程错误（举例说明）**

虽然这个头文件本身不直接涉及用户编写的 JavaScript 代码错误，但它背后代表的内建函数与一些常见的编程错误相关：

1. **`TypeError`：类型错误**

   ```javascript
   let obj = {};
   obj(); // TypeError: obj is not a function
   ```

   当尝试将一个非函数对象当作函数调用时，V8 会抛出 `TypeError`。这背后涉及到 V8 如何判断一个对象是否可调用，以及调用非函数对象时应该执行什么操作，这与相关的内建函数有关。

2. **`undefined` 或 `null` 引用错误**

   ```javascript
   let myObj = null;
   console.log(myObj.someProperty); // TypeError: Cannot read properties of null (reading 'someProperty')

   function myFunction(arg) {
       console.log(arg.length);
   }
   myFunction(); // TypeError: Cannot read properties of undefined (reading 'length')
   ```

   尝试访问 `null` 或 `undefined` 值的属性会导致 `TypeError`。在 V8 内部，访问对象属性的操作会调用相应的内建函数，这些内建函数会检查接收者是否为 `null` 或 `undefined`。

3. **隐式类型转换导致的意外行为**

   ```javascript
   console.log(1 + "1"); // 输出 "11"，发生了隐式类型转换
   console.log(1 + {});   // 输出 "1[object Object]"，对象被转换为字符串
   ```

   JavaScript 的隐式类型转换有时会导致意外结果。`Builtins::NonPrimitiveToPrimitive` 等内建函数负责执行这些类型转换，理解这些转换规则可以帮助避免错误。

**总结**

`v8/src/builtins/builtins-inl.h` 是 V8 引擎中非常核心的一个文件，它定义了获取各种内建函数的入口。这些内建函数是 V8 执行 JavaScript 代码的基础，与 JavaScript 的各种语法和功能紧密相关。理解这个文件有助于深入理解 V8 引擎的内部工作原理。

### 提示词
```
这是目录为v8/src/builtins/builtins-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_BUILTINS_BUILTINS_INL_H_
#define V8_BUILTINS_BUILTINS_INL_H_

#include "src/builtins/builtins.h"
#include "src/execution/isolate.h"

namespace v8 {
namespace internal {

// static
constexpr Builtin Builtins::RecordWrite(SaveFPRegsMode fp_mode) {
  switch (fp_mode) {
    case SaveFPRegsMode::kIgnore:
      return Builtin::kRecordWriteIgnoreFP;
    case SaveFPRegsMode::kSave:
      return Builtin::kRecordWriteSaveFP;
  }
}

// static
constexpr Builtin Builtins::IndirectPointerBarrier(SaveFPRegsMode fp_mode) {
  switch (fp_mode) {
    case SaveFPRegsMode::kIgnore:
      return Builtin::kIndirectPointerBarrierIgnoreFP;
    case SaveFPRegsMode::kSave:
      return Builtin::kIndirectPointerBarrierSaveFP;
  }
}

// static
constexpr Builtin Builtins::EphemeronKeyBarrier(SaveFPRegsMode fp_mode) {
  switch (fp_mode) {
    case SaveFPRegsMode::kIgnore:
      return Builtin::kEphemeronKeyBarrierIgnoreFP;
    case SaveFPRegsMode::kSave:
      return Builtin::kEphemeronKeyBarrierSaveFP;
  }
}

// static
constexpr Builtin Builtins::AdaptorWithBuiltinExitFrame(
    int formal_parameter_count) {
  switch (formal_parameter_count) {
    case kDontAdaptArgumentsSentinel:
    case JSParameterCount(0):
      return Builtin::kAdaptorWithBuiltinExitFrame0;
    case JSParameterCount(1):
      return Builtin::kAdaptorWithBuiltinExitFrame1;
    case JSParameterCount(2):
      return Builtin::kAdaptorWithBuiltinExitFrame2;
    case JSParameterCount(3):
      return Builtin::kAdaptorWithBuiltinExitFrame3;
    case JSParameterCount(4):
      return Builtin::kAdaptorWithBuiltinExitFrame4;
    case JSParameterCount(5):
      return Builtin::kAdaptorWithBuiltinExitFrame5;
  }
  UNREACHABLE();
}

// static
constexpr Builtin Builtins::CallFunction(ConvertReceiverMode mode) {
  switch (mode) {
    case ConvertReceiverMode::kNullOrUndefined:
      return Builtin::kCallFunction_ReceiverIsNullOrUndefined;
    case ConvertReceiverMode::kNotNullOrUndefined:
      return Builtin::kCallFunction_ReceiverIsNotNullOrUndefined;
    case ConvertReceiverMode::kAny:
      return Builtin::kCallFunction_ReceiverIsAny;
  }
  UNREACHABLE();
}

// static
constexpr Builtin Builtins::Call(ConvertReceiverMode mode) {
  switch (mode) {
    case ConvertReceiverMode::kNullOrUndefined:
      return Builtin::kCall_ReceiverIsNullOrUndefined;
    case ConvertReceiverMode::kNotNullOrUndefined:
      return Builtin::kCall_ReceiverIsNotNullOrUndefined;
    case ConvertReceiverMode::kAny:
      return Builtin::kCall_ReceiverIsAny;
  }
  UNREACHABLE();
}

// static
constexpr bool Builtins::IsAnyCall(Builtin builtin) {
  switch (builtin) {
    case Builtin::kCallFunction_ReceiverIsNullOrUndefined:
    case Builtin::kCallFunction_ReceiverIsNotNullOrUndefined:
    case Builtin::kCallFunction_ReceiverIsAny:
    case Builtin::kCall_ReceiverIsNullOrUndefined:
    case Builtin::kCall_ReceiverIsNotNullOrUndefined:
    case Builtin::kCall_ReceiverIsAny:
      return true;
    default:
      return false;
  }
}

// static
constexpr Builtin Builtins::NonPrimitiveToPrimitive(ToPrimitiveHint hint) {
  switch (hint) {
    case ToPrimitiveHint::kDefault:
      return Builtin::kNonPrimitiveToPrimitive_Default;
    case ToPrimitiveHint::kNumber:
      return Builtin::kNonPrimitiveToPrimitive_Number;
    case ToPrimitiveHint::kString:
      return Builtin::kNonPrimitiveToPrimitive_String;
  }
  UNREACHABLE();
}

// static
constexpr Builtin Builtins::OrdinaryToPrimitive(OrdinaryToPrimitiveHint hint) {
  switch (hint) {
    case OrdinaryToPrimitiveHint::kNumber:
      return Builtin::kOrdinaryToPrimitive_Number;
    case OrdinaryToPrimitiveHint::kString:
      return Builtin::kOrdinaryToPrimitive_String;
  }
  UNREACHABLE();
}

// static
constexpr Builtin Builtins::StringAdd(StringAddFlags flags) {
  switch (flags) {
    case STRING_ADD_CHECK_NONE:
      return Builtin::kStringAdd_CheckNone;
    case STRING_ADD_CONVERT_LEFT:
      return Builtin::kStringAddConvertLeft;
    case STRING_ADD_CONVERT_RIGHT:
      return Builtin::kStringAddConvertRight;
  }
  UNREACHABLE();
}

// static
constexpr Builtin Builtins::LoadGlobalIC(TypeofMode typeof_mode) {
  return typeof_mode == TypeofMode::kNotInside
             ? Builtin::kLoadGlobalICTrampoline
             : Builtin::kLoadGlobalICInsideTypeofTrampoline;
}

// static
constexpr Builtin Builtins::LoadGlobalICInOptimizedCode(
    TypeofMode typeof_mode) {
  return typeof_mode == TypeofMode::kNotInside
             ? Builtin::kLoadGlobalIC
             : Builtin::kLoadGlobalICInsideTypeof;
}

// static
constexpr Builtin Builtins::CEntry(int result_size, ArgvMode argv_mode,
                                   bool builtin_exit_frame,
                                   bool switch_to_central_stack) {
  // Aliases for readability below.
  const int rs = result_size;
  const ArgvMode am = argv_mode;
  const bool be = builtin_exit_frame;

  if (switch_to_central_stack) {
    DCHECK_EQ(result_size, 1);
    DCHECK_EQ(argv_mode, ArgvMode::kStack);
    DCHECK_EQ(builtin_exit_frame, false);
    return Builtin::kWasmCEntry;
  }

  if (rs == 1 && am == ArgvMode::kStack && !be) {
    return Builtin::kCEntry_Return1_ArgvOnStack_NoBuiltinExit;
  } else if (rs == 1 && am == ArgvMode::kStack && be) {
    return Builtin::kCEntry_Return1_ArgvOnStack_BuiltinExit;
  } else if (rs == 1 && am == ArgvMode::kRegister && !be) {
    return Builtin::kCEntry_Return1_ArgvInRegister_NoBuiltinExit;
  } else if (rs == 2 && am == ArgvMode::kStack && !be) {
    return Builtin::kCEntry_Return2_ArgvOnStack_NoBuiltinExit;
  } else if (rs == 2 && am == ArgvMode::kStack && be) {
    return Builtin::kCEntry_Return2_ArgvOnStack_BuiltinExit;
  } else if (rs == 2 && am == ArgvMode::kRegister && !be) {
    return Builtin::kCEntry_Return2_ArgvInRegister_NoBuiltinExit;
  }

  UNREACHABLE();
}

// static
constexpr Builtin Builtins::RuntimeCEntry(int result_size,
                                          bool switch_to_central_stack) {
  return CEntry(result_size, ArgvMode::kStack, false, switch_to_central_stack);
}

// static
constexpr Builtin Builtins::InterpreterCEntry(int result_size) {
  return CEntry(result_size, ArgvMode::kRegister);
}

// static
constexpr Builtin Builtins::InterpreterPushArgsThenCall(
    ConvertReceiverMode receiver_mode, InterpreterPushArgsMode mode) {
  switch (mode) {
    case InterpreterPushArgsMode::kArrayFunction:
      // There is no special-case handling of calls to Array. They will all go
      // through the kOther case below.
      UNREACHABLE();
    case InterpreterPushArgsMode::kWithFinalSpread:
      return Builtin::kInterpreterPushArgsThenCallWithFinalSpread;
    case InterpreterPushArgsMode::kOther:
      switch (receiver_mode) {
        case ConvertReceiverMode::kNullOrUndefined:
          return Builtin::kInterpreterPushUndefinedAndArgsThenCall;
        case ConvertReceiverMode::kNotNullOrUndefined:
        case ConvertReceiverMode::kAny:
          return Builtin::kInterpreterPushArgsThenCall;
      }
  }
  UNREACHABLE();
}

// static
constexpr Builtin Builtins::InterpreterPushArgsThenConstruct(
    InterpreterPushArgsMode mode) {
  switch (mode) {
    case InterpreterPushArgsMode::kArrayFunction:
      return Builtin::kInterpreterPushArgsThenConstructArrayFunction;
    case InterpreterPushArgsMode::kWithFinalSpread:
      return Builtin::kInterpreterPushArgsThenConstructWithFinalSpread;
    case InterpreterPushArgsMode::kOther:
      return Builtin::kInterpreterPushArgsThenConstruct;
  }
  UNREACHABLE();
}

// static
Address Builtins::EntryOf(Builtin builtin, Isolate* isolate) {
  return isolate->builtin_entry_table()[Builtins::ToInt(builtin)];
}

// static
constexpr bool Builtins::IsJSEntryVariant(Builtin builtin) {
  switch (builtin) {
    case Builtin::kJSEntry:
    case Builtin::kJSConstructEntry:
    case Builtin::kJSRunMicrotasksEntry:
      return true;
    default:
      return false;
  }
  UNREACHABLE();
}

// static
constexpr int Builtins::GetFormalParameterCount(Builtin builtin) {
#define CPP_BUILTIN(Name, Argc) \
  case Builtin::k##Name:        \
    return Argc;

  switch (builtin) {
    BUILTIN_LIST_C(CPP_BUILTIN)
    default:
      UNREACHABLE();
  }
#undef CPP_BUILTIN
}

#ifdef V8_ENABLE_WEBASSEMBLY

// static
template <Builtin builtin>
constexpr size_t Builtins::WasmBuiltinHandleArrayIndex() {
  constexpr size_t index =
      std::find(std::begin(Builtins::kWasmIndirectlyCallableBuiltins),
                std::end(Builtins::kWasmIndirectlyCallableBuiltins), builtin) -
      std::begin(Builtins::kWasmIndirectlyCallableBuiltins);
  static_assert(Builtins::kWasmIndirectlyCallableBuiltins[index] == builtin);
  return index;
}

// static
template <Builtin builtin>
wasm::WasmCodePointerTable::Handle Builtins::WasmBuiltinHandleOf(
    Isolate* isolate) {
  return isolate
      ->wasm_builtin_code_handles()[WasmBuiltinHandleArrayIndex<builtin>()];
}

#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace internal
}  // namespace v8

#endif  // V8_BUILTINS_BUILTINS_INL_H_
```