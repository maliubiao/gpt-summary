Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for the functionality of `v8/src/objects/call-site-info.cc`, how it relates to JavaScript, examples, and potential user errors.

2. **Initial Scan for Keywords:**  I'll quickly scan the code for common keywords and patterns to get a general idea:
    * `#include`:  Indicates dependencies on other V8 components (`call-site-info-inl.h`, `shared-function-info.h`, `string-builder-inl.h`). The presence of `#if V8_ENABLE_WEBASSEMBLY` suggests interaction with WebAssembly.
    * `namespace v8::internal`:  Confirms this is internal V8 code.
    * Class Definition:  The code defines methods for the `CallSiteInfo` class.
    * Methods like `IsPromiseAll`, `IsNative`, `IsEval`, `IsUserJavaScript`, `IsMethodCall`, `IsToplevel`, `GetLineNumber`, `GetColumnNumber`, `GetFunctionName`, `GetMethodName`, `GetTypeName`, `GetScript*`, `Serialize*`. These method names strongly suggest the class is responsible for providing information about where a function call occurred.

3. **Core Functionality Identification:** Based on the method names, the central purpose of `CallSiteInfo` seems to be encapsulating and providing details about a specific point in the call stack. This information is crucial for:
    * **Debugging:**  Stack traces, error reporting.
    * **Profiling:**  Understanding performance bottlenecks.
    * **Developer Tools:**  Inspectors, debuggers.

4. **Categorizing Functionality:** I'll group the methods by their purpose:
    * **Call Type Identification:** `IsPromiseAll`, `IsPromiseAllSettled`, `IsPromiseAny`, `IsNative`, `IsEval`, `IsUserJavaScript`, `IsMethodCall`, `IsToplevel`, `IsConstructor`. These help categorize the nature of the call site.
    * **Source Location:** `GetLineNumber`, `GetColumnNumber`, `GetEnclosingLineNumber`, `GetEnclosingColumnNumber`, `GetScriptId`, `GetScriptName`, `GetScriptNameOrSourceURL`, `GetScriptSource`, `GetScriptSourceMappingURL`, `GetScriptHash`. These methods retrieve information about the source code where the call occurred.
    * **Function and Method Information:** `GetFunctionName`, `GetFunctionDebugName`, `GetMethodName`, `GetTypeName`. These extract details about the function being called.
    * **WebAssembly Specifics:**  Methods prefixed with `GetWasm*` and the `#if V8_ENABLE_WEBASSEMBLY` blocks indicate special handling for WebAssembly call sites.
    * **Internal Mechanics:** `GetSourcePosition`, `ComputeSourcePosition`, `ComputeLocation`, `GetSharedFunctionInfo`, `GetScript`. These are more internal to V8's representation.
    * **Serialization:** `SerializeCallSiteInfo`. This suggests formatting the information for output, likely as part of a stack trace.

5. **Relationship to JavaScript:** I'll connect the C++ concepts to their JavaScript counterparts. The most direct connection is through stack traces and error objects. When a JavaScript error occurs or you explicitly throw an error, the V8 engine internally uses mechanisms like `CallSiteInfo` to build the stack trace you see in the console. The methods in `CallSiteInfo` directly provide the data points needed for each frame in the stack trace. The examples provided in the initial good answer illustrate this clearly (e.g., how `getLineNumber` relates to the line number in a stack trace).

6. **Torque Check:** The prompt specifically asks about `.tq` files. A quick scan reveals no `.tq` suffix. The code is standard C++.

7. **Code Logic and Assumptions:**  I'll look for methods that perform calculations or have conditional logic. For instance, `GetLineNumber` and `GetColumnNumber` involve retrieving the script and then using utility functions to calculate the line and column based on a source position. The WebAssembly sections have specific logic for handling source positions. My assumptions would be things like:
    * The `CallSiteInfo` object has been correctly initialized with the necessary information about the call.
    * The `Script` and `SharedFunctionInfo` objects it references are valid.

8. **Common Programming Errors:** I'll think about how the information provided by `CallSiteInfo` helps developers and what errors might arise. Incorrect line numbers in stack traces due to source maps, errors in `eval` scenarios, and confusion with asynchronous call stacks are potential issues.

9. **Structuring the Output:** I'll organize the information logically:
    * Start with a high-level summary of the file's purpose.
    * List the key functionalities with brief descriptions.
    * Explain the connection to JavaScript with examples.
    * Address the Torque question.
    * Provide code logic examples with hypothetical inputs and outputs (even if simplified).
    * Discuss common programming errors related to call site information.

10. **Refinement and Details:**  I'll review the code again, paying attention to details like:
    * The use of `std::optional`.
    * The role of `SharedFunctionInfo` and `Script`.
    * The special handling for `eval` and WebAssembly.
    * The `SerializeCallSiteInfo` function and how it formats the output.

By following these steps, I can systematically analyze the C++ code and generate a comprehensive explanation that addresses all aspects of the request. The key is to understand the high-level purpose first and then dive into the details of the individual methods and their interactions.
`v8/src/objects/call-site-info.cc` 是 V8 引擎中一个关键的源代码文件，它的主要功能是**提供关于函数调用发生位置的详细信息**。这个信息对于错误报告、调试、性能分析以及实现 JavaScript 的 `Error.stack` 属性至关重要。

**具体功能列举：**

1. **表示调用点信息:** `CallSiteInfo` 类封装了关于一个特定函数调用点的信息，例如：
   - 调用的函数 (`function()`)
   - 接收者或实例 (`receiver_or_instance()`)
   - 代码偏移量或源码位置 (`code_offset_or_source_position()`)
   - 标志位 (`flags()`)，用于存储额外信息，例如是否已计算源码位置。

2. **判断调用类型:** 提供了一系列方法来判断调用点的特性：
   - `IsPromiseAll()`, `IsPromiseAllSettled()`, `IsPromiseAny()`: 判断是否是 Promise 的 `all`, `allSettled`, `any` 方法的调用。
   - `IsNative()`: 判断是否是原生 (C++) 函数调用。
   - `IsEval()`: 判断是否是 `eval()` 函数调用。
   - `IsUserJavaScript()`: 判断是否是用户编写的 JavaScript 代码调用（非 WebAssembly 或内置函数）。
   - `IsMethodCall()`: 判断是否是方法调用（例如 `object.method()`）。
   - `IsToplevel()`: 判断是否是顶层调用（全局作用域）。
   - `IsConstructor()`: 判断是否是构造函数调用 (`new Function()`)。

3. **获取源码位置信息:** 提供方法来获取调用点在源代码中的位置：
   - `GetLineNumber()`: 获取行号。
   - `GetColumnNumber()`: 获取列号。
   - `GetEnclosingLineNumber()`: 获取包含该调用的函数的起始行号。
   - `GetEnclosingColumnNumber()`: 获取包含该调用的函数的起始列号。
   - `GetScriptId()`: 获取脚本的 ID。
   - `GetScriptName()`: 获取脚本的名称。
   - `GetScriptNameOrSourceURL()`: 获取脚本的名称或 SourceURL。
   - `GetScriptSource()`: 获取脚本的源代码。
   - `GetScriptSourceMappingURL()`: 获取脚本的 Source Map URL。
   - `GetScriptHash()`: 获取脚本的哈希值。
   - `GetEvalOrigin()`: 对于 `eval()` 调用，获取 `eval` 发生的位置信息。

4. **获取函数和方法名称信息:**
   - `GetFunctionName()`: 获取函数名。对于匿名函数或 `eval` 调用，会返回特定的字符串。
   - `GetFunctionDebugName()`: 获取更详细的函数调试名称。
   - `GetMethodName()`: 获取方法名（如果是一个方法调用）。这个方法会尝试从接收者对象上推断方法名。
   - `GetTypeName()`: 获取类型名（对于方法调用，获取接收者的类型名）。

5. **WebAssembly 支持:** 包含针对 WebAssembly 调用的特殊处理（通过 `#if V8_ENABLE_WEBASSEMBLY` 控制）：
   - `IsWasm()`: 判断是否是 WebAssembly 调用。
   - `GetWasmFunctionIndex()`: 获取 WebAssembly 函数的索引。
   - `GetWasmInstance()`: 获取 WebAssembly 实例对象。
   - `GetWasmModuleName()`: 获取 WebAssembly 模块的名称。

6. **内部辅助方法:** 提供一些内部使用的辅助方法：
   - `GetSourcePosition()`: 获取源码位置的内部表示。
   - `ComputeSourcePosition()`: 计算源码位置。
   - `ComputeLocation()`: 计算消息位置信息。
   - `GetScript()`: 获取 `Script` 对象。
   - `GetSharedFunctionInfo()`: 获取 `SharedFunctionInfo` 对象。

7. **序列化:** 提供将 `CallSiteInfo` 对象序列化为字符串的方法 `SerializeCallSiteInfo()`，这用于生成错误堆栈信息。

**关于文件扩展名 `.tq`：**

如果 `v8/src/objects/call-site-info.cc` 以 `.tq` 结尾，那它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 使用的一种领域特定语言，用于生成高效的 C++ 代码，特别是用于实现内置函数和运行时代码。  但根据你提供的文件内容，**它是一个 `.cc` 文件，即标准的 C++ 源代码文件。**

**与 JavaScript 功能的关系及示例：**

`CallSiteInfo` 与 JavaScript 的错误处理和调试功能密切相关。当 JavaScript 代码抛出错误时，V8 引擎会收集调用栈信息，其中就包含了 `CallSiteInfo` 对象。这些对象随后被用来格式化 `Error.stack` 属性。

**JavaScript 示例：**

```javascript
function foo() {
  bar();
}

function bar() {
  throw new Error("Something went wrong!");
}

try {
  foo();
} catch (e) {
  console.log(e.stack);
}
```

当这段代码执行时，`e.stack` 会包含类似以下的输出：

```
Error: Something went wrong!
    at bar (file:///path/to/your/file.js:7:9)
    at foo (file:///path/to/your/file.js:3:3)
    at global (file:///path/to/your/file.js:11:3)
```

每一行（例如 `at bar (file:///path/to/your/file.js:7:9)`）的信息就是由 V8 内部的 `CallSiteInfo` 对象提供的。`CallSiteInfo` 负责确定函数名 (`bar`)、文件名 (`file:///path/to/your/file.js`)、行号 (`7`) 和列号 (`9`)。

**代码逻辑推理及假设输入输出：**

考虑 `GetLineNumber()` 方法：

**假设输入：** 一个指向 `CallSiteInfo` 对象的指针，该对象代表 `bar()` 函数的调用，并且 `bar()` 函数位于 `file.js` 文件的第 7 行。

**代码逻辑推理：**

1. `GetLineNumber()` 调用 `GetScript(isolate, info)` 来获取 `Script` 对象。
2. 从 `Script` 对象中获取源代码的位置信息 (`GetSourcePosition(info)`，这可能需要计算）。
3. 调用 `Script::GetLineNumber(script, position)`，将源代码位置转换为行号。
4. 如果脚本有 `sourceURLComment`，则会减去 `line_offset()`。
5. 返回计算出的行号。

**输出：**  `7`

**用户常见的编程错误：**

1. **依赖 `Error.stack` 的格式:** 开发者可能会编写代码来解析 `Error.stack` 字符串以获取调用信息。然而，`Error.stack` 的格式不是 ECMAScript 标准的一部分，不同 JavaScript 引擎的实现可能有所不同。依赖特定的格式可能会导致代码在不同环境下不可靠。

   ```javascript
   try {
     throw new Error("Test");
   } catch (e) {
     const stackLines = e.stack.split('\n');
     // 假设第二行包含文件名和行号
     const match = stackLines[1].match(/at .* \((.*):(\d+):\d+\)/);
     if (match) {
       const filename = match[1];
       const lineNumber = parseInt(match[2]);
       console.log(`Error in ${filename} at line ${lineNumber}`);
     }
   }
   ```

   **错误原因：** `stackLines[1]` 的内容和正则表达式的匹配规则都依赖于 V8 的 `Error.stack` 实现细节，在其他引擎中可能不适用。

2. **忽略异步操作的堆栈信息不完整性:** 在异步操作（如 Promises 或 `async/await`）中，默认的堆栈信息可能不包含完整的异步调用链。开发者可能会因此难以追踪异步操作中发生的错误。

   ```javascript
   async function fetchData() {
     // ... 某些操作可能抛出错误
     throw new Error("Data fetch failed");
   }

   async function processData() {
     await fetchData();
   }

   processData().catch(e => {
     console.error(e.stack); // 默认情况下，堆栈可能不包含 processData 的信息
   });
   ```

   **改进方法：**  一些工具或引擎扩展（如 V8 的 "async stack tags"）可以提供更完整的异步堆栈信息，但开发者需要了解这些特性并进行相应的配置。

总而言之，`v8/src/objects/call-site-info.cc` 是 V8 引擎中负责生成和管理函数调用位置信息的关键组件，它直接支撑着 JavaScript 的错误报告和调试功能。了解其功能有助于理解 V8 如何处理调用栈信息，并能帮助开发者避免一些与堆栈信息相关的常见编程错误。

Prompt: 
```
这是目录为v8/src/objects/call-site-info.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/call-site-info.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/call-site-info.h"

#include <optional>

#include "src/base/strings.h"
#include "src/objects/call-site-info-inl.h"
#include "src/objects/shared-function-info.h"
#include "src/strings/string-builder-inl.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/debug/debug-wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8::internal {

bool CallSiteInfo::IsPromiseAll() const {
  if (!IsAsync()) return false;
  Tagged<JSFunction> fun = Cast<JSFunction>(function());
  return fun == fun->native_context()->promise_all();
}

bool CallSiteInfo::IsPromiseAllSettled() const {
  if (!IsAsync()) return false;
  Tagged<JSFunction> fun = Cast<JSFunction>(function());
  return fun == fun->native_context()->promise_all_settled();
}

bool CallSiteInfo::IsPromiseAny() const {
  if (!IsAsync()) return false;
  Tagged<JSFunction> fun = Cast<JSFunction>(function());
  return fun == fun->native_context()->promise_any();
}

bool CallSiteInfo::IsNative() const {
#if V8_ENABLE_WEBASSEMBLY
  if (IsBuiltin()) return true;
#endif
  if (auto script = GetScript()) {
    return script.value()->type() == Script::Type::kNative;
  }
  return false;
}

bool CallSiteInfo::IsEval() const {
  if (auto script = GetScript()) {
    return script.value()->compilation_type() == Script::CompilationType::kEval;
  }
  return false;
}

bool CallSiteInfo::IsUserJavaScript() const {
#if V8_ENABLE_WEBASSEMBLY
  if (IsWasm()) return false;
  if (IsBuiltin()) return false;
#endif  // V8_ENABLE_WEBASSEMBLY
  return GetSharedFunctionInfo()->IsUserJavaScript();
}

bool CallSiteInfo::IsMethodCall() const {
#if V8_ENABLE_WEBASSEMBLY
  if (IsWasm()) return false;
  if (IsBuiltin()) return false;
#endif  // V8_ENABLE_WEBASSEMBLY
  return !IsToplevel() && !IsConstructor();
}

bool CallSiteInfo::IsToplevel() const {
  return IsJSGlobalProxy(receiver_or_instance()) ||
         IsNullOrUndefined(receiver_or_instance());
}

// static
int CallSiteInfo::GetLineNumber(DirectHandle<CallSiteInfo> info) {
  Isolate* isolate = info->GetIsolate();
#if V8_ENABLE_WEBASSEMBLY
  if (info->IsWasm() && !info->IsAsmJsWasm()) {
    return 1;
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  Handle<Script> script;
  if (GetScript(isolate, info).ToHandle(&script)) {
    int position = GetSourcePosition(info);
    int line_number = Script::GetLineNumber(script, position) + 1;
    if (script->HasSourceURLComment()) {
      line_number -= script->line_offset();
    }
    return line_number;
  }
  return Message::kNoLineNumberInfo;
}

// static
int CallSiteInfo::GetColumnNumber(DirectHandle<CallSiteInfo> info) {
  Isolate* isolate = info->GetIsolate();
  int position = GetSourcePosition(info);
#if V8_ENABLE_WEBASSEMBLY
  if (info->IsWasm() && !info->IsAsmJsWasm()) {
    return position + 1;
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  Handle<Script> script;
  if (GetScript(isolate, info).ToHandle(&script)) {
    Script::PositionInfo info;
    Script::GetPositionInfo(script, position, &info);
    int column_number = info.column + 1;
    if (script->HasSourceURLComment() && info.line == script->line_offset()) {
      column_number -= script->column_offset();
    }
    return column_number;
  }
  return Message::kNoColumnInfo;
}

// static
int CallSiteInfo::GetEnclosingLineNumber(DirectHandle<CallSiteInfo> info) {
  Isolate* isolate = info->GetIsolate();
#if V8_ENABLE_WEBASSEMBLY
  if (info->IsWasm() && !info->IsAsmJsWasm()) {
    return 1;
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  Handle<Script> script;
  if (!GetScript(isolate, info).ToHandle(&script)) {
    return Message::kNoLineNumberInfo;
  }
#if V8_ENABLE_WEBASSEMBLY
  if (info->IsAsmJsWasm()) {
    auto* module = info->GetWasmInstance()->module();
    auto func_index = info->GetWasmFunctionIndex();
    int position = wasm::GetSourcePosition(module, func_index, 0,
                                           info->IsAsmJsAtNumberConversion());
    return Script::GetLineNumber(script, position) + 1;
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  int position = info->GetSharedFunctionInfo()->function_token_position();
  return Script::GetLineNumber(script, position) + 1;
}

// static
int CallSiteInfo::GetEnclosingColumnNumber(DirectHandle<CallSiteInfo> info) {
  Isolate* isolate = info->GetIsolate();
#if V8_ENABLE_WEBASSEMBLY
  if (info->IsWasm() && !info->IsAsmJsWasm()) {
    auto* module = info->GetWasmInstance()->module();
    auto func_index = info->GetWasmFunctionIndex();
    return GetWasmFunctionOffset(module, func_index);
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  Handle<Script> script;
  if (!GetScript(isolate, info).ToHandle(&script)) {
    return Message::kNoColumnInfo;
  }
#if V8_ENABLE_WEBASSEMBLY
  if (info->IsAsmJsWasm()) {
    auto* module = info->GetWasmInstance()->module();
    auto func_index = info->GetWasmFunctionIndex();
    int position = wasm::GetSourcePosition(module, func_index, 0,
                                           info->IsAsmJsAtNumberConversion());
    return Script::GetColumnNumber(script, position) + 1;
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  int position = info->GetSharedFunctionInfo()->function_token_position();
  return Script::GetColumnNumber(script, position) + 1;
}

int CallSiteInfo::GetScriptId() const {
  if (auto script = GetScript()) {
    return script.value()->id();
  }
  return Message::kNoScriptIdInfo;
}

Tagged<Object> CallSiteInfo::GetScriptName() const {
  if (auto script = GetScript()) {
    return script.value()->name();
  }
  return ReadOnlyRoots(GetIsolate()).null_value();
}

Tagged<Object> CallSiteInfo::GetScriptNameOrSourceURL() const {
  if (auto script = GetScript()) {
    return script.value()->GetNameOrSourceURL();
  }
  return ReadOnlyRoots(GetIsolate()).null_value();
}

Tagged<Object> CallSiteInfo::GetScriptSource() const {
  if (auto script = GetScript()) {
    if (script.value()->HasValidSource()) {
      return script.value()->source();
    }
  }
  return ReadOnlyRoots(GetIsolate()).null_value();
}

Tagged<Object> CallSiteInfo::GetScriptSourceMappingURL() const {
  if (auto script = GetScript()) {
    return script.value()->source_mapping_url();
  }
  return ReadOnlyRoots(GetIsolate()).null_value();
}

// static
Handle<String> CallSiteInfo::GetScriptHash(DirectHandle<CallSiteInfo> info) {
  Handle<Script> script;
  Isolate* isolate = info->GetIsolate();
  if (!GetScript(isolate, info).ToHandle(&script)) {
    return isolate->factory()->empty_string();
  }
  if (script->HasValidSource()) {
    return Script::GetScriptHash(isolate, script, /*forceForInspector:*/ false);
  }
  return isolate->factory()->empty_string();
}

namespace {

MaybeHandle<String> FormatEvalOrigin(Isolate* isolate,
                                     DirectHandle<Script> script) {
  Handle<Object> sourceURL(script->GetNameOrSourceURL(), isolate);
  if (IsString(*sourceURL)) return Cast<String>(sourceURL);

  IncrementalStringBuilder builder(isolate);
  builder.AppendCStringLiteral("eval at ");
  if (script->has_eval_from_shared()) {
    DirectHandle<SharedFunctionInfo> eval_shared(script->eval_from_shared(),
                                                 isolate);
    auto eval_name = SharedFunctionInfo::DebugName(isolate, eval_shared);
    if (eval_name->length() != 0) {
      builder.AppendString(eval_name);
    } else {
      builder.AppendCStringLiteral("<anonymous>");
    }
    if (IsScript(eval_shared->script())) {
      DirectHandle<Script> eval_script(Cast<Script>(eval_shared->script()),
                                       isolate);
      builder.AppendCStringLiteral(" (");
      if (eval_script->compilation_type() == Script::CompilationType::kEval) {
        // Eval script originated from another eval.
        Handle<String> str;
        ASSIGN_RETURN_ON_EXCEPTION(isolate, str,
                                   FormatEvalOrigin(isolate, eval_script));
        builder.AppendString(str);
      } else {
        // eval script originated from "real" source.
        DirectHandle<Object> eval_script_name(eval_script->name(), isolate);
        if (IsString(*eval_script_name)) {
          builder.AppendString(Cast<String>(eval_script_name));
          Script::PositionInfo info;
          if (Script::GetPositionInfo(eval_script,
                                      Script::GetEvalPosition(isolate, script),
                                      &info, Script::OffsetFlag::kNoOffset)) {
            builder.AppendCharacter(':');
            builder.AppendInt(info.line + 1);
            builder.AppendCharacter(':');
            builder.AppendInt(info.column + 1);
          }
        } else {
          builder.AppendCStringLiteral("unknown source");
        }
      }
      builder.AppendCharacter(')');
    }
  } else {
    builder.AppendCStringLiteral("<anonymous>");
  }
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

}  // namespace

// static
Handle<PrimitiveHeapObject> CallSiteInfo::GetEvalOrigin(
    DirectHandle<CallSiteInfo> info) {
  auto isolate = info->GetIsolate();
  Handle<Script> script;
  if (!GetScript(isolate, info).ToHandle(&script) ||
      script->compilation_type() != Script::CompilationType::kEval) {
    return isolate->factory()->undefined_value();
  }
  return FormatEvalOrigin(isolate, script).ToHandleChecked();
}

// static
Handle<PrimitiveHeapObject> CallSiteInfo::GetFunctionName(
    DirectHandle<CallSiteInfo> info) {
  Isolate* isolate = info->GetIsolate();
#if V8_ENABLE_WEBASSEMBLY
  if (info->IsWasm()) {
    DirectHandle<WasmModuleObject> module_object(
        info->GetWasmInstance()->module_object(), isolate);
    uint32_t func_index = info->GetWasmFunctionIndex();
    Handle<String> name;
    if (WasmModuleObject::GetFunctionNameOrNull(isolate, module_object,
                                                func_index)
            .ToHandle(&name)) {
      return name;
    }
    return isolate->factory()->null_value();
  }
  if (info->IsBuiltin()) {
    Builtin builtin = Builtins::FromInt(Cast<Smi>(info->function()).value());
    return isolate->factory()->NewStringFromAsciiChecked(
        Builtins::NameForStackTrace(isolate, builtin));
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  Handle<JSFunction> function(Cast<JSFunction>(info->function()), isolate);
  if (function->shared()->HasBuiltinId()) {
    Builtin builtin = function->shared()->builtin_id();
    const char* maybe_known_name =
        Builtins::NameForStackTrace(isolate, builtin);
    if (maybe_known_name) {
      // This is for cases where using the builtin's name allows us to print
      // e.g. "String.indexOf", instead of just "indexOf" which is what we
      // would infer below.
      return isolate->factory()->NewStringFromAsciiChecked(maybe_known_name);
    }
  }
  Handle<String> name = JSFunction::GetDebugName(function);
  if (name->length() != 0) return name;
  if (info->IsEval()) return isolate->factory()->eval_string();
  return isolate->factory()->null_value();
}

// static
Handle<String> CallSiteInfo::GetFunctionDebugName(
    DirectHandle<CallSiteInfo> info) {
  Isolate* isolate = info->GetIsolate();
#if V8_ENABLE_WEBASSEMBLY
  if (info->IsWasm()) {
    return GetWasmFunctionDebugName(
        isolate,
        handle(info->GetWasmInstance()->trusted_data(isolate), isolate),
        info->GetWasmFunctionIndex());
  }
  if (info->IsBuiltin()) {
    return Cast<String>(GetFunctionName(info));
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  Handle<JSFunction> function(Cast<JSFunction>(info->function()), isolate);
  Handle<String> name = JSFunction::GetDebugName(function);
  if (name->length() == 0 && info->IsEval()) {
    name = isolate->factory()->eval_string();
  }
  return name;
}

namespace {

Tagged<PrimitiveHeapObject> InferMethodNameFromFastObject(
    Isolate* isolate, Tagged<JSObject> receiver, Tagged<JSFunction> fun,
    Tagged<PrimitiveHeapObject> name) {
  ReadOnlyRoots roots(isolate);
  Tagged<Map> map = receiver->map();
  Tagged<DescriptorArray> descriptors = map->instance_descriptors(isolate);
  for (auto i : map->IterateOwnDescriptors()) {
    Tagged<PrimitiveHeapObject> key = descriptors->GetKey(i);
    if (IsSymbol(key)) continue;
    auto details = descriptors->GetDetails(i);
    if (details.IsDontEnum()) continue;
    Tagged<Object> value;
    if (details.location() == PropertyLocation::kField) {
      auto field_index = FieldIndex::ForPropertyIndex(
          map, details.field_index(), details.representation());
      if (field_index.is_double()) continue;
      value = receiver->RawFastPropertyAt(isolate, field_index);
    } else {
      value = descriptors->GetStrongValue(i);
    }
    if (value != fun) {
      if (!IsAccessorPair(value)) continue;
      auto pair = Cast<AccessorPair>(value);
      if (pair->getter() != fun && pair->setter() != fun) continue;
    }
    if (name != key) {
      name = IsUndefined(name, isolate)
                 ? key
                 : Tagged<PrimitiveHeapObject>(roots.null_value());
    }
  }
  return name;
}

template <typename Dictionary>
Tagged<PrimitiveHeapObject> InferMethodNameFromDictionary(
    Isolate* isolate, Tagged<Dictionary> dictionary, Tagged<JSFunction> fun,
    Tagged<PrimitiveHeapObject> name) {
  ReadOnlyRoots roots(isolate);
  for (auto i : dictionary->IterateEntries()) {
    Tagged<Object> key;
    if (!dictionary->ToKey(roots, i, &key)) continue;
    if (IsSymbol(key)) continue;
    auto details = dictionary->DetailsAt(i);
    if (details.IsDontEnum()) continue;
    auto value = dictionary->ValueAt(i);
    if (value != fun) {
      if (!IsAccessorPair(value)) continue;
      auto pair = Cast<AccessorPair>(value);
      if (pair->getter() != fun && pair->setter() != fun) continue;
    }
    if (name != key) {
      name = IsUndefined(name, isolate)
                 ? Cast<PrimitiveHeapObject>(key)
                 : Tagged<PrimitiveHeapObject>(roots.null_value());
    }
  }
  return name;
}

Tagged<PrimitiveHeapObject> InferMethodName(Isolate* isolate,
                                            Tagged<JSReceiver> receiver,
                                            Tagged<JSFunction> fun) {
  DisallowGarbageCollection no_gc;
  ReadOnlyRoots roots(isolate);
  Tagged<PrimitiveHeapObject> name = roots.undefined_value();
  for (PrototypeIterator it(isolate, receiver, kStartAtReceiver); !it.IsAtEnd();
       it.Advance()) {
    auto current = it.GetCurrent();
    if (!IsJSObject(current)) break;
    auto object = Cast<JSObject>(current);
    if (IsAccessCheckNeeded(object)) break;
    if (object->HasFastProperties()) {
      name = InferMethodNameFromFastObject(isolate, object, fun, name);
    } else if (IsJSGlobalObject(object)) {
      name = InferMethodNameFromDictionary(
          isolate,
          Cast<JSGlobalObject>(object)->global_dictionary(kAcquireLoad), fun,
          name);
    } else if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      name = InferMethodNameFromDictionary(
          isolate, object->property_dictionary_swiss(), fun, name);
    } else {
      name = InferMethodNameFromDictionary(
          isolate, object->property_dictionary(), fun, name);
    }
  }
  if (IsUndefined(name, isolate)) return roots.null_value();
  return name;
}

}  // namespace

// static
Handle<Object> CallSiteInfo::GetMethodName(DirectHandle<CallSiteInfo> info) {
  Isolate* isolate = info->GetIsolate();
  Handle<Object> receiver_or_instance(info->receiver_or_instance(), isolate);
#if V8_ENABLE_WEBASSEMBLY
  if (info->IsWasm()) return isolate->factory()->null_value();
#endif  // V8_ENABLE_WEBASSEMBLY
  if (IsNullOrUndefined(*receiver_or_instance, isolate)) {
    return isolate->factory()->null_value();
  }

  Handle<JSFunction> function =
      handle(Cast<JSFunction>(info->function()), isolate);
  // Class members initializer function is not a method.
  if (IsClassMembersInitializerFunction(function->shared()->kind())) {
    return isolate->factory()->null_value();
  }

  Handle<JSReceiver> receiver =
      Object::ToObject(isolate, receiver_or_instance).ToHandleChecked();
  Handle<String> name(function->shared()->Name(), isolate);
  name = String::Flatten(isolate, name);

  // ES2015 gives getters and setters name prefixes which must
  // be stripped to find the property name.
  if (name->HasOneBytePrefix(base::CStrVector("get ")) ||
      name->HasOneBytePrefix(base::CStrVector("set "))) {
    name = isolate->factory()->NewProperSubString(name, 4, name->length());
  } else if (name->length() == 0) {
    // The function doesn't have a meaningful "name" property, however
    // the parser does store an inferred name "o.foo" for the common
    // case of `o.foo = function() {...}`, so see if we can derive a
    // property name to guess from that.
    name = handle(function->shared()->inferred_name(), isolate);
    for (int index = name->length(); --index >= 0;) {
      if (name->Get(index, isolate) == '.') {
        name = isolate->factory()->NewProperSubString(name, index + 1,
                                                      name->length());
        break;
      }
    }
  }

  if (name->length() != 0) {
    PropertyKey key(isolate, Cast<Name>(name));
    LookupIterator it(isolate, receiver, key,
                      LookupIterator::PROTOTYPE_CHAIN_SKIP_INTERCEPTOR);
    if (it.state() == LookupIterator::DATA) {
      if (it.GetDataValue().is_identical_to(function)) {
        return name;
      }
    } else if (it.state() == LookupIterator::ACCESSOR) {
      Handle<Object> accessors = it.GetAccessors();
      if (IsAccessorPair(*accessors)) {
        auto pair = Cast<AccessorPair>(accessors);
        if (pair->getter() == *function || pair->setter() == *function) {
          return name;
        }
      }
    }
  }

  return handle(InferMethodName(isolate, *receiver, *function), isolate);
}

// static
Handle<Object> CallSiteInfo::GetTypeName(DirectHandle<CallSiteInfo> info) {
  Isolate* isolate = info->GetIsolate();
  if (!info->IsMethodCall()) {
    return isolate->factory()->null_value();
  }
  Handle<JSReceiver> receiver =
      Object::ToObject(isolate, handle(info->receiver_or_instance(), isolate))
          .ToHandleChecked();
  if (IsJSProxy(*receiver)) {
    return isolate->factory()->Proxy_string();
  }
  if (IsJSFunction(*receiver)) {
    Handle<JSFunction> function = Cast<JSFunction>(receiver);
    Handle<String> class_name = JSFunction::GetDebugName(function);
    if (class_name->length() != 0) {
      return class_name;
    }
  }
  return JSReceiver::GetConstructorName(isolate, receiver);
}

#if V8_ENABLE_WEBASSEMBLY
uint32_t CallSiteInfo::GetWasmFunctionIndex() const {
  DCHECK(IsWasm());
  return Smi::ToInt(Cast<Smi>(function()));
}

Tagged<WasmInstanceObject> CallSiteInfo::GetWasmInstance() const {
  DCHECK(IsWasm());
  return Cast<WasmInstanceObject>(receiver_or_instance());
}

// static
Handle<Object> CallSiteInfo::GetWasmModuleName(
    DirectHandle<CallSiteInfo> info) {
  Isolate* isolate = info->GetIsolate();
  if (info->IsWasm()) {
    Handle<String> name;
    auto module_object =
        direct_handle(info->GetWasmInstance()->module_object(), isolate);
    if (WasmModuleObject::GetModuleNameOrNull(isolate, module_object)
            .ToHandle(&name)) {
      return name;
    }
  }
  return isolate->factory()->null_value();
}
#endif  // V8_ENABLE_WEBASSEMBLY

// static
int CallSiteInfo::GetSourcePosition(DirectHandle<CallSiteInfo> info) {
  if (info->flags() & kIsSourcePositionComputed) {
    return info->code_offset_or_source_position();
  }
  DCHECK(!info->IsPromiseAll());
  DCHECK(!info->IsPromiseAllSettled());
  DCHECK(!info->IsPromiseAny());
  int source_position =
      ComputeSourcePosition(info, info->code_offset_or_source_position());
  info->set_code_offset_or_source_position(source_position);
  info->set_flags(info->flags() | kIsSourcePositionComputed);
  return source_position;
}

// static
bool CallSiteInfo::ComputeLocation(DirectHandle<CallSiteInfo> info,
                                   MessageLocation* location) {
  Isolate* isolate = info->GetIsolate();
#if V8_ENABLE_WEBASSEMBLY
  if (info->IsWasm()) {
    int pos = GetSourcePosition(info);
    Handle<Script> script(info->GetWasmInstance()->module_object()->script(),
                          isolate);
    *location = MessageLocation(script, pos, pos + 1);
    return true;
  }
  if (info->IsBuiltin()) {
    return false;
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  Handle<SharedFunctionInfo> shared(info->GetSharedFunctionInfo(), isolate);
  if (!shared->IsSubjectToDebugging()) return false;
  Handle<Script> script(Cast<Script>(shared->script()), isolate);
  if (IsUndefined(script->source())) return false;
  if (info->flags() & kIsSourcePositionComputed ||
      (shared->HasBytecodeArray() &&
       shared->GetBytecodeArray(isolate)->HasSourcePositionTable())) {
    int pos = GetSourcePosition(info);
    *location = MessageLocation(script, pos, pos + 1, shared);
  } else {
    int code_offset = info->code_offset_or_source_position();
    *location = MessageLocation(script, shared, code_offset);
  }
  return true;
}

// static
int CallSiteInfo::ComputeSourcePosition(DirectHandle<CallSiteInfo> info,
                                        int offset) {
  Isolate* isolate = info->GetIsolate();
#if V8_ENABLE_WEBASSEMBLY
#if V8_ENABLE_DRUMBRAKE
  if (info->IsWasmInterpretedFrame()) {
    auto module = info->GetWasmInstance()->module();
    uint32_t func_index = info->GetWasmFunctionIndex();
    return wasm::GetSourcePosition(module, func_index, offset,
                                   info->IsAsmJsAtNumberConversion());
  } else {
#endif  // V8_ENABLE_DRUMBRAKE
    if (info->IsWasm()) {
      auto module = info->GetWasmInstance()->trusted_data(isolate)->module();
      uint32_t func_index = info->GetWasmFunctionIndex();
      return wasm::GetSourcePosition(module, func_index, offset,
                                     info->IsAsmJsAtNumberConversion());
    }
#if V8_ENABLE_DRUMBRAKE
  }
#endif  // V8_ENABLE_DRUMBRAKE
  if (info->IsBuiltin()) {
    return 0;
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  Handle<SharedFunctionInfo> shared(info->GetSharedFunctionInfo(), isolate);
  SharedFunctionInfo::EnsureSourcePositionsAvailable(isolate, shared);
  Tagged<HeapObject> code = info->code_object(isolate);
  DCHECK(IsCode(code) || IsBytecodeArray(code));
  return Cast<AbstractCode>(code)->SourcePosition(isolate, offset);
}

std::optional<Tagged<Script>> CallSiteInfo::GetScript() const {
#if V8_ENABLE_WEBASSEMBLY
  if (IsWasm()) {
    return GetWasmInstance()
        ->trusted_data(GetIsolate())
        ->module_object()
        ->script();
  }
  if (IsBuiltin()) {
    return std::nullopt;
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  Tagged<Object> script = GetSharedFunctionInfo()->script();
  if (IsScript(script)) return Cast<Script>(script);
  return std::nullopt;
}

Tagged<SharedFunctionInfo> CallSiteInfo::GetSharedFunctionInfo() const {
#if V8_ENABLE_WEBASSEMBLY
  DCHECK(!IsWasm());
  DCHECK(!IsBuiltin());
#endif  // V8_ENABLE_WEBASSEMBLY
  return Cast<JSFunction>(function())->shared();
}

// static
MaybeHandle<Script> CallSiteInfo::GetScript(Isolate* isolate,
                                            DirectHandle<CallSiteInfo> info) {
  if (auto script = info->GetScript()) {
    return handle(*script, isolate);
  }
  return kNullMaybeHandle;
}

namespace {

bool IsNonEmptyString(DirectHandle<Object> object) {
  return (IsString(*object) && Cast<String>(*object)->length() > 0);
}

void AppendFileLocation(Isolate* isolate, DirectHandle<CallSiteInfo> frame,
                        IncrementalStringBuilder* builder) {
  Handle<Object> script_name_or_source_url(frame->GetScriptNameOrSourceURL(),
                                           isolate);
  if (!IsString(*script_name_or_source_url) && frame->IsEval()) {
    builder->AppendString(Cast<String>(CallSiteInfo::GetEvalOrigin(frame)));
    // Expecting source position to follow.
    builder->AppendCStringLiteral(", ");
  }

  if (IsNonEmptyString(script_name_or_source_url)) {
    builder->AppendString(Cast<String>(script_name_or_source_url));
  } else {
    // Source code does not originate from a file and is not native, but we
    // can still get the source position inside the source string, e.g. in
    // an eval string.
    builder->AppendCStringLiteral("<anonymous>");
  }

  int line_number = CallSiteInfo::GetLineNumber(frame);
  if (line_number != Message::kNoLineNumberInfo) {
    builder->AppendCharacter(':');
    builder->AppendInt(line_number);

    int column_number = CallSiteInfo::GetColumnNumber(frame);
    if (column_number != Message::kNoColumnInfo) {
      builder->AppendCharacter(':');
      builder->AppendInt(column_number);
    }
  }
}

// Returns true iff
// 1. the subject ends with '.' + pattern or ' ' + pattern, or
// 2. subject == pattern.
bool StringEndsWithMethodName(Isolate* isolate, Handle<String> subject,
                              Handle<String> pattern) {
  if (String::Equals(isolate, subject, pattern)) return true;

  FlatStringReader subject_reader(isolate, String::Flatten(isolate, subject));
  FlatStringReader pattern_reader(isolate, String::Flatten(isolate, pattern));

  int pattern_index = pattern_reader.length() - 1;
  int subject_index = subject_reader.length() - 1;
  // Iterate over len + 1.
  for (uint32_t i = 0; i <= pattern_reader.length(); i++) {
    if (subject_index < 0) {
      return false;
    }

    const base::uc32 subject_char = subject_reader.Get(subject_index);
    if (i == pattern_reader.length()) {
      if (subject_char != '.' && subject_char != ' ') return false;
    } else if (subject_char != pattern_reader.Get(pattern_index)) {
      return false;
    }

    pattern_index--;
    subject_index--;
  }

  return true;
}

void AppendMethodCall(Isolate* isolate, DirectHandle<CallSiteInfo> frame,
                      IncrementalStringBuilder* builder) {
  Handle<Object> type_name = CallSiteInfo::GetTypeName(frame);
  Handle<Object> method_name = CallSiteInfo::GetMethodName(frame);
  Handle<Object> function_name = CallSiteInfo::GetFunctionName(frame);

  if (IsNonEmptyString(function_name)) {
    Handle<String> function_string = Cast<String>(function_name);
    if (IsNonEmptyString(type_name)) {
      Handle<String> type_string = Cast<String>(type_name);
      if (String::IsIdentifier(isolate, function_string) &&
          !String::Equals(isolate, function_string, type_string)) {
        builder->AppendString(type_string);
        builder->AppendCharacter('.');
      }
    }
    builder->AppendString(function_string);

    if (IsNonEmptyString(method_name)) {
      Handle<String> method_string = Cast<String>(method_name);
      if (!StringEndsWithMethodName(isolate, function_string, method_string)) {
        builder->AppendCStringLiteral(" [as ");
        builder->AppendString(method_string);
        builder->AppendCharacter(']');
      }
    }
  } else {
    if (IsNonEmptyString(type_name)) {
      builder->AppendString(Cast<String>(type_name));
      builder->AppendCharacter('.');
    }
    if (IsNonEmptyString(method_name)) {
      builder->AppendString(Cast<String>(method_name));
    } else {
      builder->AppendCStringLiteral("<anonymous>");
    }
  }
}

void SerializeJSStackFrame(Isolate* isolate, DirectHandle<CallSiteInfo> frame,
                           IncrementalStringBuilder* builder) {
  Handle<Object> function_name = CallSiteInfo::GetFunctionName(frame);
  if (frame->IsAsync()) {
    builder->AppendCStringLiteral("async ");
    if (frame->IsPromiseAll() || frame->IsPromiseAny() ||
        frame->IsPromiseAllSettled()) {
      builder->AppendCStringLiteral("Promise.");
      builder->AppendString(Cast<String>(function_name));
      builder->AppendCStringLiteral(" (index ");
      builder->AppendInt(CallSiteInfo::GetSourcePosition(frame));
      builder->AppendCharacter(')');
      return;
    }
  }
  if (frame->IsMethodCall()) {
    AppendMethodCall(isolate, frame, builder);
  } else if (frame->IsConstructor()) {
    builder->AppendCStringLiteral("new ");
    if (IsNonEmptyString(function_name)) {
      builder->AppendString(Cast<String>(function_name));
    } else {
      builder->AppendCStringLiteral("<anonymous>");
    }
  } else if (IsNonEmptyString(function_name)) {
    builder->AppendString(Cast<String>(function_name));
  } else {
    AppendFileLocation(isolate, frame, builder);
    return;
  }
  builder->AppendCStringLiteral(" (");
  AppendFileLocation(isolate, frame, builder);
  builder->AppendCharacter(')');
}

#if V8_ENABLE_WEBASSEMBLY
void SerializeWasmStackFrame(Isolate* isolate, DirectHandle<CallSiteInfo> frame,
                             IncrementalStringBuilder* builder) {
  Handle<Object> module_name = CallSiteInfo::GetWasmModuleName(frame);
  Handle<Object> function_name = CallSiteInfo::GetFunctionName(frame);
  const bool has_name = !IsNull(*module_name) || !IsNull(*function_name);
  if (has_name) {
    if (IsNull(*module_name)) {
      builder->AppendString(Cast<String>(function_name));
    } else {
      builder->AppendString(Cast<String>(module_name));
      if (!IsNull(*function_name)) {
        builder->AppendCharacter('.');
        builder->AppendString(Cast<String>(function_name));
      }
    }
    builder->AppendCStringLiteral(" (");
  }

  Handle<Object> url(frame->GetScriptNameOrSourceURL(), isolate);
  if (IsNonEmptyString(url)) {
    builder->AppendString(Cast<String>(url));
  } else {
    builder->AppendCStringLiteral("<anonymous>");
  }
  builder->AppendCharacter(':');

  const int wasm_func_index = frame->GetWasmFunctionIndex();
  builder->AppendCStringLiteral("wasm-function[");
  builder->AppendInt(wasm_func_index);
  builder->AppendCStringLiteral("]:");

  char buffer[16];
  SNPrintF(base::ArrayVector(buffer), "0x%x",
           CallSiteInfo::GetColumnNumber(frame) - 1);
  builder->AppendCString(buffer);

  if (has_name) builder->AppendCharacter(')');
}

void SerializeBuiltinStackFrame(Isolate* isolate,
                                DirectHandle<CallSiteInfo> frame,
                                IncrementalStringBuilder* builder) {
  builder->AppendString(Cast<String>(CallSiteInfo::GetFunctionName(frame)));
  builder->AppendCStringLiteral(" (<anonymous>)");
}
#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace

void SerializeCallSiteInfo(Isolate* isolate, DirectHandle<CallSiteInfo> frame,
                           IncrementalStringBuilder* builder) {
#if V8_ENABLE_WEBASSEMBLY
  if (frame->IsWasm() && !frame->IsAsmJsWasm()) {
    SerializeWasmStackFrame(isolate, frame, builder);
    return;
  }
  if (frame->IsBuiltin()) {
    SerializeBuiltinStackFrame(isolate, frame, builder);
    return;
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  SerializeJSStackFrame(isolate, frame, builder);
}

MaybeHandle<String> SerializeCallSiteInfo(Isolate* isolate,
                                          DirectHandle<CallSiteInfo> frame) {
  IncrementalStringBuilder builder(isolate);
  SerializeCallSiteInfo(isolate, frame, &builder);
  return indirect_handle(builder.Finish(), isolate);
}

}  // namespace v8::internal

"""

```