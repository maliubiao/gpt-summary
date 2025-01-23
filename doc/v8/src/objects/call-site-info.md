Response: Let's break down the thought process for analyzing the `call-site-info.cc` file.

1. **Understand the Goal:** The request asks for a summary of the file's functionality and an illustration with JavaScript. This means I need to identify the core purpose of the code and connect it to concepts that JavaScript developers would be familiar with.

2. **Initial Skim for Keywords and Concepts:**  I'll quickly scan the code for recurring terms and recognizable patterns. Keywords like "CallSiteInfo," "Script," "JSFunction," "Promise," "eval," "Wasm," and "line number" jump out. The presence of `#ifdef V8_ENABLE_WEBASSEMBLY` suggests handling WebAssembly-specific cases.

3. **Identify the Core Data Structure:** The name of the file and the class `CallSiteInfo` strongly suggest this code is about representing information about where functions are called from. This is a crucial concept for debugging and error reporting.

4. **Analyze Key Methods and their Functionality:** Now I'll go through the methods, grouping them by their apparent purpose:

    * **"Is..." methods (e.g., `IsPromiseAll`, `IsNative`, `IsEval`, `IsUserJavaScript`, `IsMethodCall`, `IsToplevel`):** These seem to be boolean checks to categorize the call site. They provide contextual information about the call.

    * **Getter methods related to location (e.g., `GetLineNumber`, `GetColumnNumber`, `GetScriptId`, `GetScriptName`):** These methods extract specific details about the location of the call within the source code. The static nature of some of these getters suggests they operate on a `CallSiteInfo` object.

    * **Getter methods related to the function being called (e.g., `GetFunctionName`, `GetMethodName`, `GetTypeName`):** These methods aim to identify and describe the function involved in the call. The logic for `GetMethodName` looks a bit more complex, suggesting it tries to infer the method name in various situations.

    * **WebAssembly-related methods (e.g., `GetWasmFunctionIndex`, `GetWasmInstance`, `GetWasmModuleName`):**  These clearly handle cases where the call originates from WebAssembly code.

    * **`ComputeLocation` and `ComputeSourcePosition`:** These likely deal with calculating the precise source code position based on internal V8 data structures.

    * **`GetScript`:** This retrieves the `Script` object associated with the call site.

    * **`SerializeCallSiteInfo`:** This method stands out as it appears to format the call site information into a human-readable string.

5. **Infer the Overall Purpose:** Based on the analyzed methods, the core function of `CallSiteInfo` is to encapsulate and provide access to detailed information about a specific point where a function is called. This information includes the function itself, the receiver object (the `this` value), the location in the source code, and metadata about the script.

6. **Connect to JavaScript Concepts:**  Now, how does this relate to JavaScript? The most direct connection is the **stack trace**. When an error occurs or when you use `console.trace()`, you see a list of function calls leading to that point. Each line in the stack trace represents a "call site."

7. **Develop the JavaScript Example:** To illustrate, I need to create a scenario where a stack trace is generated and then relate the elements of that stack trace to the information provided by `CallSiteInfo`. I should demonstrate different types of function calls (regular, method, constructor, `eval`) to showcase the various `Is...` and `Get...` methods in action. Including an asynchronous call demonstrates the `IsAsync` and promise-related methods.

8. **Explain the Connection:** After the example, I need to explicitly state how the `CallSiteInfo` data would be used to generate the stack trace information seen in the JavaScript console. I should mention the role of methods like `GetFunctionName`, `GetMethodName`, `GetLineNumber`, and `GetColumnNumber`.

9. **Refine and Organize:**  Review the summary and the JavaScript example for clarity and accuracy. Ensure that the explanation is easy to understand for someone with a JavaScript background. Organize the information logically, starting with the general purpose and then diving into specifics.

10. **Address WebAssembly (If Applicable):**  Since the code includes WebAssembly support, it's important to mention this and briefly explain how `CallSiteInfo` handles call sites originating from WebAssembly modules. The example doesn't necessarily *need* to include WebAssembly, but acknowledging its presence in the C++ code is important for a complete summary.

This iterative process of scanning, analyzing, connecting to JavaScript concepts, and refining the explanation allows for a comprehensive and accurate summary of the `call-site-info.cc` file.
这个 C++ 源代码文件 `v8/src/objects/call-site-info.cc` 的主要功能是**提供关于函数调用位置的详细信息**。它定义了一个名为 `CallSiteInfo` 的类，该类封装了用于描述 JavaScript 代码执行过程中特定调用点的各种属性。

**具体功能归纳:**

1. **存储和访问调用点信息:** `CallSiteInfo` 对象存储了与特定函数调用相关的信息，例如：
    * **调用的函数:**  通过 `function()` 方法获取。
    * **接收者 (receiver) 或实例:** 通过 `receiver_or_instance()` 方法获取，用于判断 `this` 的值。
    * **代码偏移量 (code offset) 或源码位置 (source position):**  用于定位代码中的具体位置。
    * **标志位 (flags):**  例如，指示是否是异步调用、是否已计算源码位置等。

2. **提供便捷的判断方法:**  `CallSiteInfo` 类提供了多个 `Is...()` 方法，用于判断调用点的特定属性：
    * `IsPromiseAll()`, `IsPromiseAllSettled()`, `IsPromiseAny()`: 判断是否是 Promise 相关的方法调用。
    * `IsNative()`: 判断是否是原生代码调用。
    * `IsEval()`: 判断是否是通过 `eval()` 执行的代码。
    * `IsUserJavaScript()`: 判断是否是用户编写的 JavaScript 代码。
    * `IsMethodCall()`: 判断是否是方法调用。
    * `IsToplevel()`: 判断是否是顶层调用。
    * `IsWasm()` 和 `IsBuiltin()`:  判断是否是 WebAssembly 或内置函数的调用。

3. **获取源代码位置信息:**  提供静态方法用于获取更具体的源代码位置信息：
    * `GetLineNumber()`: 获取调用发生时的行号。
    * `GetColumnNumber()`: 获取调用发生时的列号。
    * `GetEnclosingLineNumber()`: 获取包含该调用的代码块的起始行号。
    * `GetEnclosingColumnNumber()`: 获取包含该调用的代码块的起始列号。
    * `GetScriptId()`: 获取脚本的 ID。
    * `GetScriptName()` 和 `GetScriptNameOrSourceURL()`: 获取脚本的名称或源 URL。
    * `GetScriptSource()`: 获取脚本的源代码。
    * `GetScriptHash()`: 获取脚本的哈希值。

4. **获取函数名称相关信息:**
    * `GetFunctionName()`: 获取函数的名称。
    * `GetFunctionDebugName()`: 获取函数的调试名称。
    * `GetMethodName()`:  尝试推断方法调用的方法名。
    * `GetTypeName()`:  获取调用对象的类型名称。

5. **处理 `eval` 调用:** 提供 `GetEvalOrigin()` 方法，用于获取 `eval` 代码的来源信息。

6. **处理 WebAssembly 调用:**  在启用 WebAssembly 的情况下，提供专门的方法来获取 WebAssembly 相关的调用信息，例如：
    * `GetWasmFunctionIndex()`: 获取 WebAssembly 函数的索引。
    * `GetWasmInstance()`: 获取 WebAssembly 实例。
    * `GetWasmModuleName()`: 获取 WebAssembly 模块的名称.

7. **计算和缓存源码位置:**  `GetSourcePosition()` 方法用于计算调用点的源码位置，并将其缓存起来，避免重复计算。

8. **将调用点信息序列化为字符串:** `SerializeCallSiteInfo()` 方法将 `CallSiteInfo` 对象的信息格式化为人类可读的字符串，这通常用于生成堆栈跟踪信息。

**与 JavaScript 的关系 (及其 JavaScript 示例):**

`CallSiteInfo` 类是 V8 引擎内部用于实现 JavaScript **堆栈跟踪 (stack trace)** 功能的关键组成部分。当 JavaScript 代码发生错误或开发者主动请求堆栈信息时 (例如使用 `console.trace()` 或捕获异常)，V8 引擎会创建 `CallSiteInfo` 对象来记录每个调用帧的信息。

以下 JavaScript 示例展示了如何获取和理解堆栈跟踪信息，以及 `CallSiteInfo` 如何在幕后提供这些信息：

```javascript
function bar() {
  console.trace('Trace from bar');
  throw new Error('Something went wrong in bar');
}

function foo() {
  bar();
}

try {
  foo();
} catch (e) {
  console.error(e.stack);
}
```

**输出的堆栈跟踪 (可能因浏览器/Node.js 环境而略有不同):**

```
Trace from bar
Error: Something went wrong in bar
    at bar (file:///path/to/your/file.js:2:9)
    at foo (file:///path/to/your/file.js:6:3)
    at file:///path/to/your/file.js:10:3
```

**`CallSiteInfo` 在幕后扮演的角色:**

对于堆栈跟踪中的每一行，V8 引擎会创建一个 `CallSiteInfo` 对象，并使用该对象的方法来提取和格式化信息：

* **`at bar (file:///path/to/your/file.js:2:9)`:**
    * `GetFunctionName()` 可能返回 `"bar"`。
    * `GetScriptNameOrSourceURL()` 可能返回 `"file:///path/to/your/file.js"`。
    * `GetLineNumber()` 可能返回 `2`。
    * `GetColumnNumber()` 可能返回 `9`。

* **`at foo (file:///path/to/your/file.js:6:3)`:**
    * `GetFunctionName()` 可能返回 `"foo"`。
    * `GetScriptNameOrSourceURL()` 可能返回 `"file:///path/to/your/file.js"`。
    * `GetLineNumber()` 可能返回 `6`。
    * `GetColumnNumber()` 可能返回 `3`。

* **`at file:///path/to/your/file.js:10:3`:**  （这是匿名顶层调用）
    * `GetFunctionName()` 可能返回 `null` 或空字符串。
    * `GetScriptNameOrSourceURL()` 可能返回 `"file:///path/to/your/file.js"`。
    * `GetLineNumber()` 可能返回 `10`。
    * `GetColumnNumber()` 可能返回 `3`。
    * `IsToplevel()` 将返回 `true`。

**更多 JavaScript 示例:**

* **`eval()` 的调用:**

```javascript
function outer() {
  const code = 'function inner() { throw new Error("Eval Error"); } inner();';
  eval(code);
}

try {
  outer();
} catch (e) {
  console.error(e.stack);
}
```

在堆栈跟踪中，`CallSiteInfo::IsEval()` 将为 `eval()` 调用的帧返回 `true`，`GetEvalOrigin()` 将提供 `eval` 代码的来源信息。

* **Promise 的调用:**

```javascript
async function myAsyncFunc() {
  await Promise.resolve();
  throw new Error("Async Error");
}

myAsyncFunc().catch(e => console.error(e.stack));
```

对于 Promise 相关的调用，`CallSiteInfo::IsAsync()` 将返回 `true`。

**总结:**

`v8/src/objects/call-site-info.cc` 中定义的 `CallSiteInfo` 类是 V8 引擎中用于捕获和描述 JavaScript 函数调用信息的关键数据结构。它为生成详细的堆栈跟踪提供了基础，帮助开发者理解代码的执行流程和定位错误发生的位置。虽然 JavaScript 开发者不能直接操作 `CallSiteInfo` 对象，但他们通过查看堆栈跟踪来间接地利用其提供的信息。

### 提示词
```
这是目录为v8/src/objects/call-site-info.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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
```