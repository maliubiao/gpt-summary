Response:
My thinking process to analyze the provided C++ code for `v8/src/debug/debug-interface.cc` went through several stages:

1. **Initial Scan and Keyword Recognition:** I first quickly scanned the code, looking for recognizable keywords and patterns related to debugging. Words like `debug`, `breakpoint`, `exception`, `step`, `inspector`, `script`, `context`, `function`, and `wasm` immediately stood out, giving me a high-level idea of the file's purpose. The `#include` directives also provided clues about the dependencies and functionalities involved (e.g., `v8-function.h`, `debug-coverage.h`, `wasm/wasm-engine.h`).

2. **Deconstructing the Structure:** I noticed the namespace `v8::debug`, indicating that this code is specifically for debugging functionalities within the V8 engine. I then examined the individual functions defined within this namespace.

3. **Categorizing Function Functionality:**  For each function, I tried to understand its purpose based on its name and the operations it performed. I started grouping them thematically:
    * **Context Management:** Functions like `SetContextId`, `GetContextId`.
    * **Inspector Integration:** `SetInspector`, `GetInspector`.
    * **Value Representation:** `GetBigIntStringValue`, `GetBigIntDescription`, `GetDateDescription`, `GetFunctionDescription`. These seem focused on formatting values for debugging output.
    * **Breakpoints and Stepping:** `SetBreakOnNextFunctionCall`, `ClearBreakOnNextFunctionCall`, `ChangeBreakOnException`, `SetBreakPointsActive`, `PrepareStep`, `PrepareRestartFrame`, `ClearStepping`, `BreakRightNow`.
    * **Internal Properties:** `GetInternalProperties`, `GetPrivateMembers`. These are about inspecting object internals.
    * **Script Handling:** `Script::*` methods (e.g., `Length`, `Size`, `GetSourceOffset`, `GetSourceLocation`, `SetBreakpoint`). These deal with inspecting and manipulating scripts.
    * **WASM Support:**  Sections with `#if V8_ENABLE_WEBASSEMBLY` and functions like `WasmScript::*`. This clearly indicates functionality related to debugging WebAssembly.
    * **Utility/Other:**  `GetCurrentPlatform`, `ForceGarbageCollection`.

4. **Inferring Relationships:**  I started to see how different functions interacted. For example, breakpoint-related functions likely rely on script information retrieved by `Script::*` methods. The inspector functions provide an interface to an external debugging tool.

5. **Considering the `.cc` Extension:**  The prompt specifically mentioned the `.cc` extension and its implication. Since it's a `.cc` file, it's C++ source code and *not* Torque (`.tq`).

6. **Identifying JavaScript Relationships:** For functions that seemed to expose debugging features accessible from JavaScript, I tried to formulate potential JavaScript examples. For instance, breakpoint-related functions directly map to debugger statements or APIs in JavaScript. The functions for getting descriptions relate to how JavaScript engines might format values in debuggers.

7. **Looking for Logic and Assumptions:** Some functions involved more complex logic, like `GetPrivateMembers` and `GetPossibleBreakpoints`. For these, I considered:
    * **Input:** What kind of data does the function receive? (e.g., `Context`, `Object`, `Location`).
    * **Output:** What does the function return? (e.g., `MaybeLocal<Array>`, `bool`, a vector of `BreakLocation`).
    * **Assumptions:**  What conditions need to be met for the function to work correctly? (e.g., the input `Object` having private members).

8. **Thinking About Common Errors:** I tried to connect the functionality to potential programming errors users might encounter while debugging. Setting breakpoints incorrectly, not understanding the scope of variables, or issues with asynchronous code were examples that came to mind.

9. **Structuring the Summary:** Finally, I organized my observations into a structured summary, covering the key functionalities, connections to JavaScript, potential logic, and common programming errors. I aimed for clarity and conciseness, using bullet points and clear headings. I also made sure to address all the specific points raised in the prompt.

**Self-Correction/Refinement:**

* **Initial Overgeneralization:**  At first, I might have described the file too broadly as "handling debugging." I refined this by breaking it down into specific areas like breakpoints, stepping, value inspection, etc.
* **Missing Nuances:**  I initially overlooked some of the finer details, like the different filters for private members or the specifics of how WASM breakpoints are handled. I reread the code segments to understand these better.
* **JavaScript Example Clarity:**  My initial JavaScript examples might have been too vague. I tried to make them more concrete and directly related to the C++ function's purpose.
* **Focusing on the Core:** I avoided getting bogged down in the low-level V8 details that aren't directly relevant to the *functional* summary requested. The goal was to explain *what* it does, not *how* it's implemented at the most granular level.

By following these steps, I was able to dissect the C++ code, understand its purpose within the V8 debugging framework, and generate a comprehensive summary addressing the prompt's requirements.
好的，让我们来分析一下 `v8/src/debug/debug-interface.cc` 这个 V8 源代码文件的功能。

**文件功能归纳:**

`v8/src/debug/debug-interface.cc` 文件是 V8 引擎中负责 **对外暴露调试接口** 的核心组件。它提供了一系列 C++ 函数，允许外部调试器（例如 Chrome DevTools）与 V8 引擎进行交互，以实现断点设置、单步执行、变量查看、调用栈检查等调试功能。

**详细功能列举:**

1. **上下文 (Context) 管理:**
   - `SetContextId`: 设置 V8 上下文的 ID。这可能用于在调试器中标识不同的上下文。
   - `GetContextId`: 获取 V8 上下文的 ID。

2. **Inspector 集成:**
   - `SetInspector`:  设置与该 Isolate 关联的 V8 Inspector 对象。Inspector 是 Chrome DevTools 使用的调试协议的 V8 实现。
   - `GetInspector`: 获取与该 Isolate 关联的 V8 Inspector 对象。

3. **BigInt, Date, Function 等对象的描述信息获取:**
   - `GetBigIntStringValue`: 获取 BigInt 对象的字符串表示形式。
   - `GetBigIntDescription`: 获取 BigInt 对象的描述信息 (带 "n" 后缀)。
   - `GetDateDescription`: 获取 Date 对象的描述信息 (本地日期和时间字符串)。
   - `GetFunctionDescription`: 获取 Function 对象的描述信息 (例如函数签名或 "[native code]")。 这对于理解函数类型（例如，原生函数或 WebAssembly 函数）很有用。

4. **断点控制:**
   - `SetBreakOnNextFunctionCall`: 设置在下一个函数调用时中断。
   - `ClearBreakOnNextFunctionCall`: 清除在下一个函数调用时中断的设置。
   - `ChangeBreakOnException`: 设置在捕获的或未捕获的异常上中断。
   - `SetBreakPointsActive`: 激活或禁用所有断点。
   - `SetBreakpoint` (在 `Script` 类中): 在脚本的指定位置设置断点。
   - `SetInstrumentationBreakpoint` (在 `Script` 类中): 为脚本设置一个插桩断点。
   - `RemoveBreakpoint`: 移除指定的断点。

5. **单步执行控制:**
   - `PrepareStep`:  准备进行单步执行操作 (例如，单步进入、单步跳过、单步跳出)。
   - `PrepareRestartFrame`: 准备重启指定的调用帧。
   - `ClearStepping`: 清除当前的单步执行设置。
   - `BreakRightNow`: 立即触发一个调试中断。
   - `SetTerminateOnResume`:  设置在调试会话恢复后终止程序。
   - `CanBreakProgram`: 检查当前程序是否可以被中断 (例如，是否所有帧都被黑盒化)。

6. **对象属性检查:**
   - `GetInternalProperties`: 获取对象的内部属性。
   - `GetPrivateMembers`: 获取对象的私有成员 (字段、方法、访问器)。

7. **脚本 (Script) 信息获取和操作:**
   - `ScriptSource`:  表示脚本的源代码，包括 JavaScript 和 WebAssembly。
   - `Script::Length`: 获取脚本源代码的长度。
   - `Script::Size`: 获取脚本源代码的大小 (字节数)。
   - `Script::JavaScriptCode`: 获取 JavaScript 脚本的源代码。
   - `Script::WasmBytecode`: 获取 WebAssembly 脚本的字节码。
   - `Script::GetIsolate`: 获取脚本所属的 Isolate。
   - `Script::OriginOptions`: 获取脚本的来源选项 (例如是否为模块)。
   - `Script::WasCompiled`: 检查脚本是否已编译。
   - `Script::IsEmbedded`: 检查脚本是否为内嵌脚本。
   - `Script::Id`: 获取脚本的 ID。
   - `Script::StartLine`, `Script::StartColumn`, `Script::EndLine`, `Script::EndColumn`: 获取脚本的起始和结束行列号。
   - `Script::Name`: 获取脚本的名称。
   - `Script::SourceURL`: 获取脚本的 SourceURL。
   - `Script::SourceMappingURL`: 获取脚本的 SourceMappingURL。
   - `Script::GetSha256Hash`: 获取脚本内容的 SHA256 哈希值。
   - `Script::ContextId`: 获取脚本所属的上下文 ID。
   - `Script::Source`: 获取脚本的 `ScriptSource` 对象。
   - `Script::IsWasm`: 检查脚本是否为 WebAssembly。
   - `Script::IsModule`: 检查脚本是否为模块。
   - `Script::GetPossibleBreakpoints`: 获取脚本中可能的断点位置。
   - `Script::GetSourceOffset`: 将脚本中的行列号转换为源代码偏移量。
   - `Script::GetSourceLocation`: 将脚本中的源代码偏移量转换为行列号。
   - `Script::SetScriptSource`:  设置脚本的新源代码 (用于热重载等功能)。

8. **WebAssembly (Wasm) 相关功能 (在 `#if V8_ENABLE_WEBASSEMBLY` 条件下):**
   - 提供了获取 WebAssembly 脚本的调试信息、函数范围、断点管理等功能。
   - `WasmScript::GetDebugSymbols`: 获取 WebAssembly 脚本的调试符号信息。
   - `WasmScript::NumFunctions`, `WasmScript::NumImportedFunctions`: 获取 WebAssembly 脚本中的函数数量。
   - `WasmScript::GetFunctionRange`: 获取 WebAssembly 函数的字节码范围。
   - `Script::IsWasm`: 检查脚本是否是 WebAssembly。
   - `Script::RemoveWasmBreakpoint`: 移除 WebAssembly 脚本的断点。

9. **其他工具函数:**
   - `GetCreationContext`: 获取对象被创建时的上下文。
   - `GetCurrentPlatform`: 获取当前的平台对象。
   - `ForceGarbageCollection`: 强制执行垃圾回收。

**关于文件扩展名 `.tq`:**

您的问题中提到，如果文件以 `.tq` 结尾，那么它是一个 V8 Torque 源代码。 **`v8/src/debug/debug-interface.cc` 以 `.cc` 结尾，因此它是一个标准的 C++ 源代码文件，而不是 Torque 文件。** Torque 文件通常用于定义 V8 的内置函数和类型系统。

**与 JavaScript 功能的关系及举例:**

`v8/src/debug/debug-interface.cc` 中的功能直接支撑了 JavaScript 的调试体验。当你在 Chrome DevTools 中进行调试时，DevTools 通过 V8 Inspector 协议与 V8 引擎进行通信，而 `debug-interface.cc` 提供的接口正是 V8 Inspector 协议实现的基础。

**JavaScript 举例:**

假设你在 JavaScript 代码中设置了一个断点：

```javascript
function myFunction(a, b) {
  debugger; // 设置断点
  return a + b;
}

myFunction(5, 10);
```

当 JavaScript 引擎执行到 `debugger;` 语句时，会触发一个调试事件。这个事件会通过 V8 Inspector 协议传递到 Chrome DevTools。

以下是一些 `debug-interface.cc` 中的函数可能参与到这个过程中的场景：

- **`Script::GetPossibleBreakpoints`:** 当 DevTools 需要展示当前脚本中可以设置断点的位置时，会调用此函数。
- **`Script::SetBreakpoint`:** 当你在 DevTools 中点击行号设置断点时，DevTools 会调用此函数在 V8 引擎中注册断点。
- **`BreakRightNow` (可能间接调用):**  `debugger;` 语句的执行最终会导致 V8 引擎触发中断，这可能与 `BreakRightNow` 函数的逻辑相关。
- **`GetFunctionDescription`:** 当你在 DevTools 中查看调用栈时，V8 会使用此函数来获取每个函数的信息，以便在 DevTools 中显示。
- **`GetInternalProperties` 和 `GetPrivateMembers`:** 当你在 DevTools 的 "Scope" 面板或对象检查器中查看变量时，这些函数会被调用来获取变量的值和属性。
- **`PrepareStep` 等:** 当你点击 DevTools 中的 "Step Over"、"Step Into" 或 "Step Out" 按钮时，DevTools 会调用相应的 `PrepareStep` 函数来控制 JavaScript 代码的执行流程。

**代码逻辑推理及假设输入输出:**

让我们以 `GetPrivateMembers` 函数为例进行逻辑推理：

**假设输入:**

- `context`: 一个 V8 的 `Context` 对象，表示执行上下文。
- `object`: 一个 V8 的 `Object` 对象，我们想要获取其私有成员。
- `filter`: 一个整数，表示要过滤的私有成员类型 (例如，只获取私有方法)。
- `names_out`: 一个空的 `LocalVector<Value>`，用于存储私有成员的名称。
- `values_out`: 一个空的 `LocalVector<Value>`，用于存储私有成员的值。

**代码逻辑:**

1. 函数首先根据 `filter` 参数确定需要包含哪些类型的私有成员 (方法、字段、访问器)。
2. 它使用 `KeyAccumulator::GetKeys` 获取对象自身的私有名称 (Symbol)。
3. 遍历这些私有名称：
   - 如果是私有品牌 Symbol (用于私有方法和访问器)，则获取其关联的 Context，并遍历该 Context 的本地变量，筛选出符合条件的私有方法或访问器。
   - 如果是私有字段的 Symbol，则直接获取其值。
4. 对于类，还会检查是否存在静态私有方法或访问器，并遍历类构造函数的 Context 以获取它们。
5. 将找到的私有成员的名称和值分别添加到 `names_out` 和 `values_out` 向量中。

**假设输出:**

假设 `object` 是一个类的实例，该类定义了一个私有字段 `#privateField` 和一个私有方法 `#privateMethod()`:

- 如果 `filter` 设置为包含私有字段和方法，那么 `names_out` 可能会包含一个 `String` 对象，其值为 "#privateField"，`values_out` 可能会包含该私有字段的值。同时，`names_out` 可能会包含另一个 `String` 对象，其值为 "#privateMethod"，`values_out` 可能会包含该私有方法的 `Function` 对象。

**用户常见的编程错误举例:**

`debug-interface.cc` 本身是 V8 引擎的内部代码，普通用户不会直接编写或修改它。 然而，它提供的调试功能可以帮助用户发现和修复 JavaScript 代码中的错误。

以下是一些常见的编程错误，可以通过 V8 的调试功能来定位：

1. **逻辑错误:**  代码执行流程不符合预期，例如条件判断错误、循环逻辑错误等。可以通过设置断点并单步执行来跟踪代码的执行路径，观察变量的值变化，从而找到逻辑错误所在。

   ```javascript
   function calculateSum(arr) {
     let sum = 0;
     for (let i = 1; i <= arr.length; i++) { // 错误：应该从 0 开始
       sum += arr[i]; // 错误：可能越界
     }
     return sum;
   }

   console.log(calculateSum([1, 2, 3])); // 可能会报错或返回错误结果
   ```

   在调试器中设置断点，单步执行，可以观察到 `i` 的值以及 `arr[i]` 的访问情况，从而发现数组越界和循环起始位置的错误。

2. **类型错误:**  对变量进行了不期望的操作，例如尝试对非数字类型进行算术运算。

   ```javascript
   function greet(name) {
     return "Hello, " + name.toUpperCase(); // 如果 name 不是字符串，会报错
   }

   greet(123); // 传入了数字
   ```

   在调试器中设置异常断点 (Break on Caught Exceptions 或 Break on Uncaught Exceptions)，可以捕获到类型错误，并查看错误发生时的变量值。

3. **作用域错误:**  在不期望的作用域访问变量。

   ```javascript
   function outer() {
     let x = 10;
     function inner() {
       console.log(x); // 可以访问外部作用域的 x
     }
     inner();
   }
   outer();

   function another() {
     console.log(x); // 错误：无法访问 outer 函数的局部变量 x
   }
   another();
   ```

   通过在调试器中查看作用域链 (Scope)，可以理解变量的可见性，从而找到作用域错误。

4. **异步编程错误:**  在使用 `setTimeout`、Promise 或 async/await 时，代码的执行顺序可能与预期不同。

   ```javascript
   function fetchData() {
     setTimeout(() => {
       console.log("Data fetched!");
       processData(); // 可能会在数据准备好之前执行
     }, 1000);
   }

   function processData() {
     console.log("Processing data...");
   }

   fetchData();
   ```

   在调试器中设置断点，可以观察异步操作的执行顺序，例如查看回调函数何时被调用。

**总结:**

`v8/src/debug/debug-interface.cc` 是 V8 引擎调试功能的核心接口，它提供了一组强大的 C++ 函数，用于与外部调试器交互，实现代码检查、断点控制、单步执行等功能。它直接支撑了 JavaScript 的调试体验，帮助开发者定位和修复代码中的各种错误。 虽然开发者不会直接修改这个文件，但理解其功能有助于更深入地理解 V8 引擎的调试机制。

Prompt: 
```
这是目录为v8/src/debug/debug-interface.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/debug/debug-interface.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/debug/debug-interface.h"

#include "include/v8-function.h"
#include "src/api/api-inl.h"
#include "src/base/utils/random-number-generator.h"
#include "src/codegen/compiler.h"
#include "src/codegen/script-details.h"
#include "src/date/date.h"
#include "src/debug/debug-coverage.h"
#include "src/debug/debug-evaluate.h"
#include "src/debug/debug-property-iterator.h"
#include "src/debug/debug-stack-trace-iterator.h"
#include "src/debug/debug.h"
#include "src/execution/vm-state-inl.h"
#include "src/heap/heap.h"
#include "src/objects/js-generator-inl.h"
#include "src/profiler/heap-profiler.h"
#include "src/strings/string-builder-inl.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/debug/debug-wasm-objects-inl.h"
#include "src/wasm/wasm-disassembler.h"
#include "src/wasm/wasm-engine.h"
#endif  // V8_ENABLE_WEBASSEMBLY

// Has to be the last include (doesn't have include guards):
#include "src/api/api-macros.h"

namespace v8 {
namespace debug {

void SetContextId(Local<Context> context, int id) {
  auto v8_context = Utils::OpenDirectHandle(*context);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(v8_context->GetIsolate());
  v8_context->set_debug_context_id(i::Smi::FromInt(id));
}

int GetContextId(Local<Context> context) {
  auto v8_context = Utils::OpenDirectHandle(*context);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(v8_context->GetIsolate());
  i::Tagged<i::Object> value = v8_context->debug_context_id();
  return (IsSmi(value)) ? i::Smi::ToInt(value) : 0;
}

void SetInspector(Isolate* isolate, v8_inspector::V8Inspector* inspector) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (inspector == nullptr) {
    i_isolate->set_inspector(nullptr);
  } else {
    i_isolate->set_inspector(inspector);
  }
}

v8_inspector::V8Inspector* GetInspector(Isolate* isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return i_isolate->inspector();
}

namespace {

i::Handle<i::String> GetBigIntStringPresentationHandle(
    i::Isolate* i_isolate, i::DirectHandle<i::BigInt> i_bigint) {
  // For large BigInts computing the decimal string representation
  // can take a long time, so we go with hexadecimal in that case.
  int radix = (i_bigint->Words64Count() > 100 * 1000) ? 16 : 10;
  i::Handle<i::String> string_value =
      i::BigInt::ToString(i_isolate, i_bigint, radix, i::kDontThrow)
          .ToHandleChecked();
  if (radix == 16) {
    if (i_bigint->IsNegative()) {
      string_value =
          i_isolate->factory()
              ->NewConsString(
                  i_isolate->factory()->NewStringFromAsciiChecked("-0x"),
                  i_isolate->factory()->NewProperSubString(
                      string_value, 1, string_value->length() - 1))
              .ToHandleChecked();
    } else {
      string_value =
          i_isolate->factory()
              ->NewConsString(
                  i_isolate->factory()->NewStringFromAsciiChecked("0x"),
                  string_value)
              .ToHandleChecked();
    }
  }
  return string_value;
}

}  // namespace

Local<String> GetBigIntStringValue(Isolate* isolate, Local<BigInt> bigint) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::DirectHandle<i::BigInt> i_bigint = Utils::OpenDirectHandle(*bigint);

  i::Handle<i::String> string_value =
      GetBigIntStringPresentationHandle(i_isolate, i_bigint);
  return Utils::ToLocal(string_value);
}

Local<String> GetBigIntDescription(Isolate* isolate, Local<BigInt> bigint) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::DirectHandle<i::BigInt> i_bigint = Utils::OpenDirectHandle(*bigint);

  i::Handle<i::String> string_value =
      GetBigIntStringPresentationHandle(i_isolate, i_bigint);

  i::Handle<i::String> description =
      i_isolate->factory()
          ->NewConsString(
              string_value,
              i_isolate->factory()->LookupSingleCharacterStringFromCode('n'))
          .ToHandleChecked();
  return Utils::ToLocal(description);
}

Local<String> GetDateDescription(Local<Date> date) {
  auto receiver = Utils::OpenDirectHandle(*date);
  auto jsdate = i::Cast<i::JSDate>(receiver);
  i::Isolate* i_isolate = jsdate->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto buffer = i::ToDateString(jsdate->value(), i_isolate->date_cache(),
                                i::ToDateStringMode::kLocalDateAndTime);
  return Utils::ToLocal(i_isolate->factory()
                            ->NewStringFromUtf8(base::VectorOf(buffer))
                            .ToHandleChecked());
}

Local<String> GetFunctionDescription(Local<Function> function) {
  auto receiver = Utils::OpenHandle(*function);
  auto i_isolate = receiver->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (IsJSBoundFunction(*receiver)) {
    return Utils::ToLocal(
        i::JSBoundFunction::ToString(i::Cast<i::JSBoundFunction>(receiver)));
  }
  if (IsJSFunction(*receiver)) {
    auto js_function = i::Cast<i::JSFunction>(receiver);
#if V8_ENABLE_WEBASSEMBLY
    if (js_function->shared()->HasWasmExportedFunctionData()) {
      i::DirectHandle<i::WasmExportedFunctionData> function_data(
          js_function->shared()->wasm_exported_function_data(), i_isolate);
      int func_index = function_data->function_index();
      i::DirectHandle<i::WasmTrustedInstanceData> instance_data(
          function_data->instance_data(), i_isolate);
      if (instance_data->module()->origin == i::wasm::kWasmOrigin) {
        // For asm.js functions, we can still print the source
        // code (hopefully), so don't bother with them here.
        auto debug_name =
            i::GetWasmFunctionDebugName(i_isolate, instance_data, func_index);
        i::IncrementalStringBuilder builder(i_isolate);
        builder.AppendCStringLiteral("function ");
        builder.AppendString(debug_name);
        builder.AppendCStringLiteral("() { [native code] }");
        return Utils::ToLocal(builder.Finish().ToHandleChecked());
      }
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    return Utils::ToLocal(i::JSFunction::ToString(js_function));
  }
  return Utils::ToLocal(
      receiver->GetIsolate()->factory()->function_native_code_string());
}

void SetBreakOnNextFunctionCall(Isolate* isolate) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i_isolate->debug()->SetBreakOnNextFunctionCall();
}

void ClearBreakOnNextFunctionCall(Isolate* isolate) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i_isolate->debug()->ClearBreakOnNextFunctionCall();
}

MaybeLocal<Array> GetInternalProperties(Isolate* v8_isolate,
                                        Local<Value> value) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(isolate);
  i::Handle<i::Object> val = Utils::OpenHandle(*value);
  i::Handle<i::JSArray> result;
  if (!i::Runtime::GetInternalProperties(isolate, val).ToHandle(&result))
    return MaybeLocal<Array>();
  return Utils::ToLocal(result);
}

namespace {

using FlagFilter = std::function<bool(i::IsStaticFlag)>;
using VariableModeFilter = std::function<bool(i::VariableMode)>;
using ContextLocalIterator = std::function<void(
    i::VariableMode, i::Handle<i::String>, i::Handle<i::Object>)>;

void ForEachContextLocal(i::Isolate* isolate,
                         i::DirectHandle<i::Context> context,
                         const VariableModeFilter& var_mode_filter,
                         const FlagFilter& flag_filter,
                         const ContextLocalIterator& context_local_it) {
  DCHECK_NO_SCRIPT_NO_EXCEPTION(isolate);
  i::Handle<i::ScopeInfo> scope_info(context->scope_info(), isolate);
  for (auto it : i::ScopeInfo::IterateLocalNames(scope_info)) {
    i::Handle<i::String> name(it->name(), isolate);
    i::VariableMode mode = scope_info->ContextLocalMode(it->index());
    if (!var_mode_filter(mode)) {
      continue;
    }
    i::IsStaticFlag flag = scope_info->ContextLocalIsStaticFlag(it->index());
    if (!flag_filter(flag)) {
      continue;
    }
    int context_index = scope_info->ContextHeaderLength() + it->index();
    i::Handle<i::Object> slot_value(context->get(context_index), isolate);
    context_local_it(mode, name, slot_value);
  }
}

}  // namespace

bool GetPrivateMembers(Local<Context> context, Local<Object> object, int filter,
                       LocalVector<Value>* names_out,
                       LocalVector<Value>* values_out) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  API_RCS_SCOPE(isolate, debug, GetPrivateMembers);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(isolate);

  bool include_methods =
      filter & static_cast<int>(PrivateMemberFilter::kPrivateMethods);
  bool include_fields =
      filter & static_cast<int>(PrivateMemberFilter::kPrivateFields);
  bool include_accessors =
      filter & static_cast<int>(PrivateMemberFilter::kPrivateAccessors);
  bool include_methods_or_accessors = include_methods || include_accessors;

  auto var_mode_filter =
      include_methods
          ? (include_accessors ? i::IsPrivateMethodOrAccessorVariableMode
                               : i::IsPrivateMethodVariableMode)
          : i::IsPrivateAccessorVariableMode;
  auto constexpr instance_filter = [](i::IsStaticFlag flag) {
    return flag == i::IsStaticFlag::kNotStatic;
  };
  auto constexpr static_filter = [](i::IsStaticFlag flag) {
    return flag == i::IsStaticFlag::kStatic;
  };

  i::Handle<i::JSReceiver> receiver = Utils::OpenHandle(*object);

  i::PropertyFilter key_filter =
      static_cast<i::PropertyFilter>(i::PropertyFilter::PRIVATE_NAMES_ONLY);
  i::Handle<i::FixedArray> keys;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, keys,
      i::KeyAccumulator::GetKeys(isolate, receiver,
                                 i::KeyCollectionMode::kOwnOnly, key_filter,
                                 i::GetKeysConversion::kConvertToString),
      false);

  // Estimate number of private fields and private instance methods/accessors.
  int private_entries_count = 0;
  auto count_private_entry =
      [&](i::VariableMode mode, i::DirectHandle<i::String>,
          i::DirectHandle<i::Object>) { private_entries_count++; };
  for (int i = 0; i < keys->length(); ++i) {
    // Exclude the private brand symbols.
    i::Handle<i::Symbol> key(i::Cast<i::Symbol>(keys->get(i)), isolate);
    if (key->is_private_brand()) {
      if (include_methods_or_accessors) {
        i::Handle<i::Object> value;
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, value, i::Object::GetProperty(isolate, receiver, key),
            false);

        i::DirectHandle<i::Context> value_context(i::Cast<i::Context>(*value),
                                                  isolate);
        ForEachContextLocal(isolate, value_context, var_mode_filter,
                            instance_filter, count_private_entry);
      }
    } else if (include_fields) {
      private_entries_count++;
    }
  }

  // Estimate number of static private methods/accessors for classes.
  bool has_static_private_methods_or_accessors = false;
  if (include_methods_or_accessors) {
    if (IsJSFunction(*receiver)) {
      i::DirectHandle<i::JSFunction> func(i::Cast<i::JSFunction>(*receiver),
                                          isolate);
      i::DirectHandle<i::SharedFunctionInfo> shared(func->shared(), isolate);
      if (shared->is_class_constructor() &&
          shared->has_static_private_methods_or_accessors()) {
        has_static_private_methods_or_accessors = true;
        i::DirectHandle<i::Context> func_context(func->context(), isolate);
        ForEachContextLocal(isolate, func_context, var_mode_filter,
                            static_filter, count_private_entry);
      }
    }
  }

  DCHECK(names_out->empty());
  names_out->reserve(private_entries_count);
  DCHECK(values_out->empty());
  values_out->reserve(private_entries_count);

  auto add_private_entry = [&](i::VariableMode mode, i::Handle<i::String> name,
                               i::Handle<i::Object> value) {
    DCHECK_IMPLIES(mode == i::VariableMode::kPrivateMethod,
                   IsJSFunction(*value));
    DCHECK_IMPLIES(mode != i::VariableMode::kPrivateMethod,
                   IsAccessorPair(*value));
    names_out->push_back(Utils::ToLocal(name));
    values_out->push_back(Utils::ToLocal(value));
  };
  if (has_static_private_methods_or_accessors) {
    i::DirectHandle<i::Context> receiver_context(
        i::Cast<i::JSFunction>(*receiver)->context(), isolate);
    ForEachContextLocal(isolate, receiver_context, var_mode_filter,
                        static_filter, add_private_entry);
  }

  for (int i = 0; i < keys->length(); ++i) {
    i::DirectHandle<i::Object> obj_key(keys->get(i), isolate);
    i::Handle<i::Symbol> key(i::Cast<i::Symbol>(*obj_key), isolate);
    CHECK(key->is_private_name());
    i::Handle<i::Object> value;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, value, i::Object::GetProperty(isolate, receiver, key), false);
    if (key->is_private_brand()) {
      if (include_methods_or_accessors) {
        DCHECK(IsContext(*value));
        i::DirectHandle<i::Context> value_context(i::Cast<i::Context>(*value),
                                                  isolate);
        ForEachContextLocal(isolate, value_context, var_mode_filter,
                            instance_filter, add_private_entry);
      }
    } else if (include_fields) {  // Private fields
      i::DirectHandle<i::String> name(
          i::Cast<i::String>(i::Cast<i::Symbol>(*key)->description()), isolate);
      names_out->push_back(Utils::ToLocal(name));
      values_out->push_back(Utils::ToLocal(value));
    }
  }

  DCHECK_EQ(names_out->size(), values_out->size());
  DCHECK_LE(names_out->size(), private_entries_count);
  return true;
}

MaybeLocal<Context> GetCreationContext(Local<Object> value) {
  if (IsJSGlobalProxy(*Utils::OpenDirectHandle(*value))) {
    return MaybeLocal<Context>();
  }
  START_ALLOW_USE_DEPRECATED();
  return value->GetCreationContext();
  END_ALLOW_USE_DEPRECATED();
}

void ChangeBreakOnException(Isolate* isolate, ExceptionBreakState type) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i_isolate->debug()->ChangeBreakOnException(
      i::BreakCaughtException,
      type == BreakOnCaughtException || type == BreakOnAnyException);
  i_isolate->debug()->ChangeBreakOnException(
      i::BreakUncaughtException,
      type == BreakOnUncaughtException || type == BreakOnAnyException);
}

void SetBreakPointsActive(Isolate* v8_isolate, bool is_active) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(isolate);
  isolate->debug()->set_break_points_active(is_active);
}

void PrepareStep(Isolate* v8_isolate, StepAction action) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_BASIC(isolate);
  CHECK(isolate->debug()->CheckExecutionState());
  // Clear all current stepping setup.
  isolate->debug()->ClearStepping();
  // Prepare step.
  isolate->debug()->PrepareStep(static_cast<i::StepAction>(action));
}

bool PrepareRestartFrame(Isolate* v8_isolate, int callFrameOrdinal) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_BASIC(isolate);
  CHECK(isolate->debug()->CheckExecutionState());

  i::DebugStackTraceIterator it(isolate, callFrameOrdinal);
  if (it.Done() || !it.CanBeRestarted()) return false;

  // Clear all current stepping setup.
  isolate->debug()->ClearStepping();
  it.PrepareRestart();
  return true;
}

void ClearStepping(Isolate* v8_isolate) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(isolate);
  // Clear all current stepping setup.
  isolate->debug()->ClearStepping();
}

void BreakRightNow(Isolate* v8_isolate,
                   base::EnumSet<debug::BreakReason> break_reasons) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_BASIC(isolate);
  isolate->debug()->HandleDebugBreak(i::kIgnoreIfAllFramesBlackboxed,
                                     break_reasons);
}

void SetTerminateOnResume(Isolate* v8_isolate) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(isolate);
  isolate->debug()->SetTerminateOnResume();
}

bool CanBreakProgram(Isolate* v8_isolate) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_BASIC(isolate);
  return !isolate->debug()->AllFramesOnStackAreBlackboxed();
}

size_t ScriptSource::Length() const {
  auto source = Utils::OpenDirectHandle(this);
  if (IsString(*source)) {
    return i::Cast<i::String>(source)->length();
  }
  return Size();
}

size_t ScriptSource::Size() const {
#if V8_ENABLE_WEBASSEMBLY
  MemorySpan<const uint8_t> wasm_bytecode;
  if (WasmBytecode().To(&wasm_bytecode)) {
    return wasm_bytecode.size();
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  auto source = Utils::OpenDirectHandle(this);
  if (!IsString(*source)) return 0;
  auto string = i::Cast<i::String>(source);
  return string->length() * (string->IsTwoByteRepresentation() ? 2 : 1);
}

MaybeLocal<String> ScriptSource::JavaScriptCode() const {
  i::Handle<i::HeapObject> source = Utils::OpenHandle(this);
  if (!IsString(*source)) return MaybeLocal<String>();
  return Utils::ToLocal(i::Cast<i::String>(source));
}

#if V8_ENABLE_WEBASSEMBLY
Maybe<MemorySpan<const uint8_t>> ScriptSource::WasmBytecode() const {
  auto source = Utils::OpenDirectHandle(this);
  if (!IsForeign(*source)) return Nothing<MemorySpan<const uint8_t>>();
  base::Vector<const uint8_t> wire_bytes =
      i::Cast<i::Managed<i::wasm::NativeModule>>(*source)->raw()->wire_bytes();
  return Just(MemorySpan<const uint8_t>{wire_bytes.begin(), wire_bytes.size()});
}
#endif  // V8_ENABLE_WEBASSEMBLY

Isolate* Script::GetIsolate() const {
  return reinterpret_cast<Isolate*>(
      Utils::OpenDirectHandle(this)->GetIsolate());
}

ScriptOriginOptions Script::OriginOptions() const {
  return Utils::OpenDirectHandle(this)->origin_options();
}

bool Script::WasCompiled() const {
  return Utils::OpenDirectHandle(this)->compilation_state() ==
         i::Script::CompilationState::kCompiled;
}

bool Script::IsEmbedded() const {
  auto script = Utils::OpenDirectHandle(this);
  return script->context_data() ==
         script->GetReadOnlyRoots().uninitialized_symbol();
}

int Script::Id() const { return Utils::OpenDirectHandle(this)->id(); }

int Script::StartLine() const {
  return Utils::OpenDirectHandle(this)->line_offset();
}

int Script::StartColumn() const {
  return Utils::OpenDirectHandle(this)->column_offset();
}

int Script::EndLine() const {
  i::DirectHandle<i::Script> script = Utils::OpenDirectHandle(this);
#if V8_ENABLE_WEBASSEMBLY
  if (script->type() == i::Script::Type::kWasm) return 0;
#endif  // V8_ENABLE_WEBASSEMBLY
  if (!IsString(script->source())) {
    return script->line_offset();
  }
  i::Isolate* isolate = script->GetIsolate();
  i::HandleScope scope(isolate);
  i::Script::PositionInfo info;
  i::Script::GetPositionInfo(
      script, i::Cast<i::String>(script->source())->length(), &info);
  return info.line;
}

int Script::EndColumn() const {
  i::DirectHandle<i::Script> script = Utils::OpenDirectHandle(this);
#if V8_ENABLE_WEBASSEMBLY
  if (script->type() == i::Script::Type::kWasm) {
    return script->wasm_native_module()->wire_bytes().length();
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  if (!IsString(script->source())) {
    return script->column_offset();
  }
  i::Isolate* isolate = script->GetIsolate();
  i::HandleScope scope(isolate);
  i::Script::PositionInfo info;
  i::Script::GetPositionInfo(
      script, i::Cast<i::String>(script->source())->length(), &info);
  return info.column;
}

MaybeLocal<String> Script::Name() const {
  auto script = Utils::OpenDirectHandle(this);
  i::Isolate* isolate = script->GetIsolate();
  i::DirectHandle<i::Object> value(script->name(), isolate);
  if (!IsString(*value)) return MaybeLocal<String>();
  return Utils::ToLocal(i::Cast<i::String>(value));
}

MaybeLocal<String> Script::SourceURL() const {
  auto script = Utils::OpenDirectHandle(this);
  i::Isolate* isolate = script->GetIsolate();
  i::DirectHandle<i::PrimitiveHeapObject> value(script->source_url(), isolate);
  if (!IsString(*value)) return MaybeLocal<String>();
  return Utils::ToLocal(i::Cast<i::String>(value));
}

MaybeLocal<String> Script::SourceMappingURL() const {
  auto script = Utils::OpenDirectHandle(this);
  i::Isolate* isolate = script->GetIsolate();
  i::DirectHandle<i::Object> value(script->source_mapping_url(), isolate);
  if (!IsString(*value)) return MaybeLocal<String>();
  return Utils::ToLocal(i::Cast<i::String>(value));
}

MaybeLocal<String> Script::GetSha256Hash() const {
  i::DirectHandle<i::Script> script = Utils::OpenDirectHandle(this);
  i::Isolate* isolate = script->GetIsolate();
  i::Handle<i::String> value =
      i::Script::GetScriptHash(isolate, script, /* forceForInspector: */ true);
  return Utils::ToLocal(value);
}

Maybe<int> Script::ContextId() const {
  auto script = Utils::OpenDirectHandle(this);
  i::Tagged<i::Object> value = script->context_data();
  if (IsSmi(value)) return Just(i::Smi::ToInt(value));
  return Nothing<int>();
}

Local<ScriptSource> Script::Source() const {
  auto script = Utils::OpenDirectHandle(this);
  i::Isolate* isolate = script->GetIsolate();
#if V8_ENABLE_WEBASSEMBLY
  if (script->type() == i::Script::Type::kWasm) {
    i::DirectHandle<i::Object> wasm_native_module(
        script->wasm_managed_native_module(), isolate);
    return Utils::Convert<i::Object, ScriptSource>(wasm_native_module);
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  i::DirectHandle<i::PrimitiveHeapObject> source(script->source(), isolate);
  return Utils::Convert<i::PrimitiveHeapObject, ScriptSource>(source);
}

#if V8_ENABLE_WEBASSEMBLY
bool Script::IsWasm() const {
  return Utils::OpenDirectHandle(this)->type() == i::Script::Type::kWasm;
}
#endif  // V8_ENABLE_WEBASSEMBLY

bool Script::IsModule() const {
  return Utils::OpenDirectHandle(this)->origin_options().IsModule();
}

namespace {

int GetSmiValue(i::DirectHandle<i::FixedArray> array, int index) {
  return i::Smi::ToInt(array->get(index));
}

bool CompareBreakLocation(const i::BreakLocation& loc1,
                          const i::BreakLocation& loc2) {
  return loc1.position() < loc2.position();
}

}  // namespace

bool Script::GetPossibleBreakpoints(
    const Location& start, const Location& end, bool restrict_to_function,
    std::vector<BreakLocation>* locations) const {
  CHECK(!start.IsEmpty());
  i::Handle<i::Script> script = Utils::OpenHandle(this);
#if V8_ENABLE_WEBASSEMBLY
  if (script->type() == i::Script::Type::kWasm) {
    i::wasm::NativeModule* native_module = script->wasm_native_module();
    return i::WasmScript::GetPossibleBreakpoints(native_module, start, end,
                                                 locations);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  i::Isolate* isolate = script->GetIsolate();

  int start_offset, end_offset;
  if (!GetSourceOffset(start, GetSourceOffsetMode::kClamp).To(&start_offset)) {
    return false;
  }
  if (end.IsEmpty()) {
    end_offset = std::numeric_limits<int>::max();
  } else if (!GetSourceOffset(end, GetSourceOffsetMode::kClamp)
                  .To(&end_offset)) {
    return false;
  }
  if (start_offset >= end_offset) return true;

  std::vector<i::BreakLocation> v8_locations;
  if (!isolate->debug()->GetPossibleBreakpoints(
          script, start_offset, end_offset, restrict_to_function,
          &v8_locations)) {
    return false;
  }

  std::sort(v8_locations.begin(), v8_locations.end(), CompareBreakLocation);
  for (const auto& v8_location : v8_locations) {
    Location location = GetSourceLocation(v8_location.position());
    locations->emplace_back(location.GetLineNumber(),
                            location.GetColumnNumber(), v8_location.type());
  }
  return true;
}

Maybe<int> Script::GetSourceOffset(const Location& location,
                                   GetSourceOffsetMode mode) const {
  i::DirectHandle<i::Script> script = Utils::OpenDirectHandle(this);
#if V8_ENABLE_WEBASSEMBLY
  if (script->type() == i::Script::Type::kWasm) {
    return location.GetLineNumber() == 0 ? Just(location.GetColumnNumber())
                                         : Nothing<int>();
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  int line = location.GetLineNumber();
  int column = location.GetColumnNumber();
  if (!script->HasSourceURLComment()) {
    // Line/column number for inline <script>s with sourceURL annotation
    // are supposed to be related to the <script> tag, otherwise they
    // are relative to the parent file. Keep this in sync with the logic
    // in GetSourceLocation() below.
    line -= script->line_offset();
    if (line == 0) column -= script->column_offset();
  }

  i::Script::InitLineEnds(script->GetIsolate(), script);
  auto line_ends = i::Cast<i::FixedArray>(
      i::direct_handle(script->line_ends(), script->GetIsolate()));
  if (line < 0) {
    if (mode == GetSourceOffsetMode::kClamp) {
      return Just(0);
    }
    return Nothing<int>();
  }
  if (line >= line_ends->length()) {
    if (mode == GetSourceOffsetMode::kClamp) {
      return Just(GetSmiValue(line_ends, line_ends->length() - 1));
    }
    return Nothing<int>();
  }
  if (column < 0) {
    if (mode != GetSourceOffsetMode::kClamp) {
      return Nothing<int>();
    }
    column = 0;
  }
  int offset = column;
  if (line > 0) {
    int prev_line_end_offset = GetSmiValue(line_ends, line - 1);
    offset += prev_line_end_offset + 1;
  }
  int line_end_offset = GetSmiValue(line_ends, line);
  if (offset > line_end_offset) {
    // Be permissive with columns that don't exist,
    // as long as they are clearly within the range
    // of the script.
    if (line < line_ends->length() - 1 || mode == GetSourceOffsetMode::kClamp) {
      return Just(line_end_offset);
    }
    return Nothing<int>();
  }
  return Just(offset);
}

Location Script::GetSourceLocation(int offset) const {
  i::DirectHandle<i::Script> script = Utils::OpenDirectHandle(this);
  i::Script::PositionInfo info;
  i::Script::GetPositionInfo(script, offset, &info);
  if (script->HasSourceURLComment()) {
    // Line/column number for inline <script>s with sourceURL annotation
    // are supposed to be related to the <script> tag, otherwise they
    // are relative to the parent file. Keep this in sync with the logic
    // in GetSourceOffset() above.
    info.line -= script->line_offset();
    if (info.line == 0) info.column -= script->column_offset();
  }
  return Location(info.line, info.column);
}

bool Script::SetScriptSource(Local<String> newSource, bool preview,
                             bool allow_top_frame_live_editing,
                             LiveEditResult* result) const {
  i::Handle<i::Script> script = Utils::OpenHandle(this);
  i::Isolate* isolate = script->GetIsolate();
  return isolate->debug()->SetScriptSource(
      script, Utils::OpenHandle(*newSource), preview,
      allow_top_frame_live_editing, result);
}

bool Script::SetBreakpoint(Local<String> condition, Location* location,
                           BreakpointId* id) const {
  i::Handle<i::Script> script = Utils::OpenHandle(this);
  i::Isolate* isolate = script->GetIsolate();
  int offset;
  if (!GetSourceOffset(*location).To(&offset)) {
    return false;
  }
  if (!isolate->debug()->SetBreakPointForScript(
          script, Utils::OpenHandle(*condition), &offset, id)) {
    return false;
  }
  *location = GetSourceLocation(offset);
  return true;
}

bool Script::SetInstrumentationBreakpoint(BreakpointId* id) const {
  i::Handle<i::Script> script = Utils::OpenHandle(this);
  i::Isolate* isolate = script->GetIsolate();
#if V8_ENABLE_WEBASSEMBLY
  if (script->type() == i::Script::Type::kWasm) {
    isolate->debug()->SetInstrumentationBreakpointForWasmScript(script, id);
    return true;
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  i::SharedFunctionInfo::ScriptIterator it(isolate, *script);
  for (i::Tagged<i::SharedFunctionInfo> sfi = it.Next(); !sfi.is_null();
       sfi = it.Next()) {
    if (sfi->is_toplevel()) {
      return isolate->debug()->SetBreakpointForFunction(
          handle(sfi, isolate), isolate->factory()->empty_string(), id,
          internal::Debug::kInstrumentation);
    }
  }
  return false;
}

#if V8_ENABLE_WEBASSEMBLY
void Script::RemoveWasmBreakpoint(BreakpointId id) {
  i::DirectHandle<i::Script> script = Utils::OpenDirectHandle(this);
  i::Isolate* isolate = script->GetIsolate();
  isolate->debug()->RemoveBreakpointForWasmScript(script, id);
}
#endif  //  V8_ENABLE_WEBASSEMBLY

void RemoveBreakpoint(Isolate* v8_isolate, BreakpointId id) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::HandleScope handle_scope(isolate);
  isolate->debug()->RemoveBreakpoint(id);
}

Platform* GetCurrentPlatform() { return i::V8::GetCurrentPlatform(); }

void ForceGarbageCollection(Isolate* isolate, StackState embedder_stack_state) {
  i::EmbedderStackStateScope stack_scope(
      reinterpret_cast<i::Isolate*>(isolate)->heap(),
      i::EmbedderStackStateOrigin::kImplicitThroughTask, embedder_stack_state);
  isolate->LowMemoryNotification();
}

#if V8_ENABLE_WEBASSEMBLY
WasmScript* WasmScript::Cast(Script* script) {
  CHECK(script->IsWasm());
  return static_cast<WasmScript*>(script);
}

Maybe<WasmScript::DebugSymbols::Type> GetDebugSymbolType(
    i::wasm::WasmDebugSymbols::Type type) {
  switch (type) {
    case i::wasm::WasmDebugSymbols::Type::EmbeddedDWARF:
      return Just(WasmScript::DebugSymbols::Type::EmbeddedDWARF);
    case i::wasm::WasmDebugSymbols::Type::ExternalDWARF:
      return Just(WasmScript::DebugSymbols::Type::ExternalDWARF);
    case i::wasm::WasmDebugSymbols::Type::SourceMap:
      return Just(WasmScript::DebugSymbols::Type::SourceMap);
    case i::wasm::WasmDebugSymbols::Type::None:
      return Nothing<WasmScript::DebugSymbols::Type>();
  }
}

std::vector<WasmScript::DebugSymbols> WasmScript::GetDebugSymbols() const {
  auto script = Utils::OpenDirectHandle(this);
  DCHECK_EQ(i::Script::Type::kWasm, script->type());

  std::vector<WasmScript::DebugSymbols> debug_symbols;
  auto symbols = script->wasm_native_module()->module()->debug_symbols;
  for (size_t i = 0; i < symbols.size(); ++i) {
    const i::wasm::WasmDebugSymbols& symbol = symbols[i];
    Maybe<WasmScript::DebugSymbols::Type> type =
        GetDebugSymbolType(symbol.type);
    if (type.IsNothing()) continue;

    internal::wasm::ModuleWireBytes wire_bytes(
        script->wasm_native_module()->wire_bytes());
    i::wasm::WasmName external_url =
        wire_bytes.GetNameOrNull(symbol.external_url);
    MemorySpan<const char> span = {external_url.data(), external_url.size()};
    debug_symbols.push_back({type.FromJust(), span});
  }
  return debug_symbols;
}

int WasmScript::NumFunctions() const {
  i::DisallowGarbageCollection no_gc;
  auto script = Utils::OpenDirectHandle(this);
  DCHECK_EQ(i::Script::Type::kWasm, script->type());
  i::wasm::NativeModule* native_module = script->wasm_native_module();
  const i::wasm::WasmModule* module = native_module->module();
  DCHECK_GE(i::kMaxInt, module->functions.size());
  return static_cast<int>(module->functions.size());
}

int WasmScript::NumImportedFunctions() const {
  i::DisallowGarbageCollection no_gc;
  auto script = Utils::OpenDirectHandle(this);
  DCHECK_EQ(i::Script::Type::kWasm, script->type());
  i::wasm::NativeModule* native_module = script->wasm_native_module();
  const i::wasm::WasmModule* module = native_module->module();
  DCHECK_GE(i::kMaxInt, module->num_imported_functions);
  return static_cast<int>(module->num_imported_functions);
}

std::pair<int, int> WasmScript::GetFunctionRange(int function_index) const {
  i::DisallowGarbageCollection no_gc;
  auto script = Utils::OpenDirectHandle(this);
  DCHECK_EQ(i::Script::Type::kWasm, script->type());
  i::wasm::NativeModule* native_module = script->wasm_native_module();
  const i::wasm::WasmModule* module = native_module->module();
  DCHECK_LE(0, function_index);
  DCHECK_GT(module->functions.size(), function_index);
  const i::wasm::WasmFunction& func = module->functions[function_index]
"""


```