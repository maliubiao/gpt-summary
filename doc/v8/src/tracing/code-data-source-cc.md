Response:
Let's break down the thought process for analyzing this C++ code and fulfilling the request.

1. **Understanding the Goal:** The primary goal is to understand the functionality of `code-data-source.cc` within the V8 project, specifically in the context of tracing. The request asks for a functional summary, connections to JavaScript, example usage, and handling of common programming errors (although this last point might be less directly applicable here).

2. **Initial Code Scan (High-Level):**  I'd first scan the `#include` directives to understand the dependencies. Notice includes like `protos/perfetto/...`, `src/execution/isolate.h`, `src/objects/...`, `src/tracing/perfetto-logger.h`. This immediately suggests that this code is involved in sending data (likely code-related information) to the Perfetto tracing system.

3. **Key Classes and Namespaces:**  Identify the core classes and namespaces: `v8::internal::CodeDataSource` and its associated `CodeDataSourceIncrementalState`. The namespaces indicate this is internal V8 functionality.

4. **Perfetto Integration:** The repeated use of `perfetto` and protobuf-related types (`V8Config`, `InternedV8JsScript`, etc.) confirms the Perfetto integration. The `PERFETTO_DEFINE_DATA_SOURCE_STATIC_MEMBERS` macro solidifies this. This tells us the file is about *providing* code data to Perfetto.

5. **Core Functionality - Interning:** The functions `InternIsolate`, `InternJsScript`, `InternJsFunction`, `InternWasmScript`, and `InternJsFunctionName` are crucial. The term "Intern" strongly suggests a mechanism for efficiently representing and deduplicating data. Instead of sending the full string of a function name or the entire script source repeatedly, these functions assign unique IDs (iids) to them and store them. Subsequent references will use the ID. This is a common optimization in tracing and serialization.

6. **Mapping V8 Concepts to Perfetto:** Examine the `GetJsScriptType` and `GetJsFunctionKind` functions. They translate V8's internal representations of script and function types into corresponding Perfetto enum values. This is the core of the data transformation.

7. **Incremental State:** The `CodeDataSourceIncrementalState` class and its methods (`Init`, `FlushInternedData`) suggest a stateful mechanism for collecting and sending data incrementally. `FlushInternedData` hints that interned data is buffered and sent periodically. The configuration options (`log_script_sources_`, `log_instructions_`) indicate configurable aspects of the tracing.

8. **Lifecycle Methods:** The `OnSetup`, `OnStart`, and `OnStop` methods are typical lifecycle callbacks for Perfetto data sources, handling configuration, enabling, and disabling data collection. `PerfettoLogger::OnCodeDataSourceStart/Stop` likely handles related actions on the Perfetto side.

9. **Connecting to JavaScript:** The code explicitly deals with `Script` and `SharedFunctionInfo` objects, which are fundamental to JavaScript execution in V8. The interning of scripts and function names directly links the tracing data to the executed JavaScript code.

10. **JavaScript Example (Mental Model):**  Think about a simple JavaScript code snippet and how this code would trace it. When a function is defined, `InternJsFunction` would be called. When the script is loaded, `InternJsScript`. The function and script names would be interned.

11. **Torque Check:** The request mentions `.tq` files. The code has no `.tq` extension, so it's clearly not a Torque file.

12. **Code Logic and Assumptions:**  The interning logic assumes that the same script or function name might be encountered multiple times. The "unique ID" generation implies some form of internal counter or state management.

13. **Common Programming Errors (Limited Relevance):** This code is more about infrastructure than direct user-level programming. Common errors related to *using* tracing would involve incorrect configuration or misunderstanding the traced data. Direct errors *within* this code would be related to memory management, incorrect protobuf serialization, or race conditions (though not immediately apparent in this snippet).

14. **Structuring the Answer:** Organize the findings logically, starting with the main function, then details of interning, JavaScript connection, examples, and finally the error section. Use clear headings and bullet points for readability.

15. **Refinement and Wording:** Review the answer for clarity and accuracy. Ensure the JavaScript examples are simple and illustrative. Use precise language to describe the technical concepts.

Self-Correction/Refinement during the process:

* **Initial thought:** Is this about *executing* code?  No, the Perfetto integration points strongly towards *observing* or *monitoring* code execution.
* **Clarification on "Interning":**  Make sure to explain *why* interning is used (efficiency).
* **JavaScript example specificity:**  Instead of just saying it's related to JavaScript, provide concrete examples of functions and scripts.
* **Error focus:**  Realize that the "common programming errors" aspect is less directly applicable to *this specific code* and shift the focus to potential issues within the tracing system itself or the interpretation of the data.

By following this structured analysis, combined with knowledge of V8 internals and tracing concepts, one can effectively dissect and explain the functionality of the provided C++ code.
好的，让我们来分析一下 `v8/src/tracing/code-data-source.cc` 文件的功能。

**功能概览**

`v8/src/tracing/code-data-source.cc` 是 V8 引擎中用于收集代码相关数据的 Perfetto 数据源。它的主要功能是将 V8 引擎内部的关于 JavaScript 代码结构（如脚本、函数）以及执行环境（如 Isolate）的信息，以特定的格式发送给 Perfetto 追踪系统。这些信息对于性能分析、调试和理解 V8 的运行行为至关重要。

**主要功能点**

1. **作为 Perfetto 数据源:**  该文件实现了 Perfetto 数据源的接口，允许 Perfetto 系统订阅并接收来自 V8 的代码数据。`PERFETTO_DEFINE_DATA_SOURCE_STATIC_MEMBERS` 宏就定义了这个数据源。

2. **配置管理:**  通过 `OnSetup` 函数，它可以接收来自 Perfetto 的配置信息（`V8Config`），例如是否需要记录脚本源代码。

3. **Isolate 信息收集:**  `InternIsolate` 函数负责收集和“实习化”（intern）Isolate 的信息。Isolate 是 V8 引擎的独立执行环境。收集的信息包括 Isolate ID、进程 ID、嵌入式 Blob 代码的起始地址和大小，以及代码段的内存范围。

4. **JavaScript 脚本信息收集:** `InternJsScript` 函数收集 JavaScript 脚本的信息，例如脚本 ID、类型（eval, native, extension, normal, inspector），以及脚本的名称和源代码（如果配置允许）。

5. **JavaScript 函数信息收集:** `InternJsFunction` 函数收集 JavaScript 函数的信息，例如函数名、所属脚本的 ID、函数类型（普通函数、箭头函数、生成器函数等）以及函数在脚本中的起始位置。

6. **WebAssembly 脚本信息收集:** `InternWasmScript` 函数收集 WebAssembly 脚本的信息，包括脚本 ID 和 URL。

7. **字符串实习化:** `InternJsFunctionName` 函数用于实习化 JavaScript 函数名，避免重复发送相同的字符串，提高效率。

8. **增量式数据发送:** `CodeDataSourceIncrementalState` 类管理增量式的数据收集和发送。`FlushInternedData` 函数将收集到的实习化数据打包发送到 Perfetto。

9. **生命周期管理:** `OnStart` 和 `OnStop` 函数分别在数据源启动和停止时被调用，用于管理 PerfettoLogger 的状态。

**关于文件后缀 `.tq`**

如果 `v8/src/tracing/code-data-source.cc` 的文件名以 `.tq` 结尾，那么它将是一个 **Torque** 源代码文件。Torque 是 V8 用来生成高效的 C++ 代码的领域特定语言。然而，根据你提供的文件名，它以 `.cc` 结尾，所以它是一个标准的 C++ 源代码文件。

**与 JavaScript 的关系 (及 JavaScript 示例)**

`v8/src/tracing/code-data-source.cc` 的核心功能是收集关于 **JavaScript 代码** 的信息。它记录了脚本、函数以及它们的各种属性。这些信息直接反映了执行在 V8 引擎上的 JavaScript 代码的结构。

**JavaScript 示例:**

假设有以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

const multiply = (x, y) => x * y;

eval("console.log('dynamic code')");
```

当 V8 引擎执行这段代码时，`code-data-source.cc` 会收集以下信息（部分）：

* **脚本信息:**
    * 脚本 ID (一个内部生成的唯一标识符)
    * 类型: `NORMAL` (对于普通的脚本) 或 `EVAL` (对于 `eval` 执行的代码)
    * 名称: 可能是一个文件名或者 `eval` 等
    * 源代码: (如果配置允许)  `function add(a, b) { ... } const multiply = ... eval(...)`
* **函数信息:**
    * `add` 函数:
        * 函数名 ID (指向实习化的 "add" 字符串)
        * 所属脚本的 ID
        * 类型: `NORMAL_FUNCTION`
        * 起始位置 (在脚本中的字节偏移量)
    * `multiply` 函数:
        * 函数名 ID (指向实习化的 "multiply" 字符串)
        * 所属脚本的 ID
        * 类型: `ARROW_FUNCTION`
        * 起始位置
* **`eval` 执行的代码:**
    * 脚本信息:
        * 脚本 ID
        * 类型: `EVAL`
        * 名称:  通常是 "eval"
        * 源代码: (如果配置允许) `console.log('dynamic code')`

**代码逻辑推理与假设输入输出**

让我们以 `InternJsFunction` 函数为例进行代码逻辑推理。

**假设输入:**

* `isolate`: 当前 V8 的执行环境 (Isolate) 的引用。
* `info`: 一个指向 `SharedFunctionInfo` 对象的句柄。`SharedFunctionInfo` 包含了关于函数的重要元数据，例如函数名、类型、所属脚本等。
* `v8_js_script_iid`:  所属脚本的实习化 ID，由 `InternJsScript` 函数生成。
* `line_num`, `column_num`: 函数在源代码中的行号和列号（虽然在这个函数中未使用）。

**代码逻辑:**

1. **获取函数名:**  通过 `SharedFunctionInfo::DebugName(&isolate, info)` 获取函数的调试名称（一个字符串）。
2. **实习化函数名:** 调用 `InternJsFunctionName` 将函数名字符串实习化，得到一个唯一的 ID (`v8_js_function_name_iid`)。
3. **创建函数唯一标识:**  使用脚本 ID、是否为顶层函数以及起始位置创建一个用于查找的键 (`Function`)。
4. **查找或插入函数信息:** 在 `functions_` 映射中查找是否已存在相同的函数信息。
   * **如果存在:** 返回已存在的实习化 ID。
   * **如果不存在:**
      * 生成一个新的实习化 ID (`next_function_iid()`).
      * 将新的函数信息（包括实习化 ID 和相关属性）添加到 `serialized_interned_data_` 中，以便稍后发送给 Perfetto。
      * 将新的函数信息和实习化 ID 存入 `functions_` 映射。
      * 返回新的实习化 ID。

**假设输出:**

如果输入的 `info` 指向一个名为 `add` 的函数，且该函数所属的脚本的实习化 ID 为 `123`，起始位置为 `10`，则 `InternJsFunction` 函数可能会返回一个新的唯一的函数实习化 ID，例如 `456`。同时，`serialized_interned_data_` 中会添加一个 `v8_js_function` 消息，包含 `iid: 456`, `v8_js_function_name_iid: <add 的实习化 ID>`, `v8_js_script_iid: 123`, `kind: NORMAL_FUNCTION`, `byte_offset: 10` 等信息。

**涉及用户常见的编程错误 (间接)**

虽然 `code-data-source.cc` 本身是 V8 内部的代码，用户不会直接编写或修改它，但它收集的信息可以帮助开发者诊断与 JavaScript 代码相关的性能问题。

**常见编程错误以及如何通过这些数据发现:**

1. **过多的匿名函数或 `eval` 用法:**
   * **Perfetto 数据:** 通过分析 `InternJsScript` 和 `InternJsFunction` 生成的数据，可以发现是否有大量的脚本类型为 `EVAL`，或者存在大量函数名为空或自动生成的函数。
   * **错误示例:**  在循环中动态生成和执行代码：
     ```javascript
     for (let i = 0; i < 1000; i++) {
       eval(`function temp${i}() { console.log(i); } temp${i}();`);
     }
     ```
   * **分析:** Perfetto 追踪数据会显示大量的 `EVAL` 类型的脚本和许多名字类似 `temp0`, `temp1` 的函数，这可能提示开发者需要避免这种模式。

2. **性能瓶颈在特定的函数中:**
   * **Perfetto 数据:**  Perfetto 可以将这些代码数据与其他性能数据（如 CPU 采样）关联起来。如果某个特定的函数 ID 频繁出现在性能瓶颈中，开发者就可以定位到需要优化的函数。
   * **错误示例:**  一个效率很低的排序算法。
     ```javascript
     function inefficientSort(arr) {
       // ... 效率很低的代码 ...
     }
     ```
   * **分析:** Perfetto 追踪可能会显示 `inefficientSort` 函数的执行时间占比很高。

3. **不必要的脚本编译:**
   * **Perfetto 数据:**  如果频繁出现新的脚本被编译的信息，可能意味着代码结构存在问题，例如模块加载不当或者代码分割不足。
   * **错误示例:**  在一个大型单体文件中包含了所有代码，导致初始加载时所有代码都需要被解析和编译。
   * **分析:** Perfetto 数据可能显示初始加载时有大量的脚本被记录。

**总结**

`v8/src/tracing/code-data-source.cc` 是 V8 引擎中一个关键的组件，它负责将 V8 内部的 JavaScript 代码结构信息以结构化的方式导出到 Perfetto 追踪系统。这些数据对于理解 V8 的运行机制、进行性能分析和调试至关重要。虽然开发者不会直接修改这个文件，但通过分析它产生的数据，可以帮助他们识别和修复 JavaScript 代码中的性能问题和潜在的错误模式。

### 提示词
```
这是目录为v8/src/tracing/code-data-source.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/tracing/code-data-source.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/tracing/code-data-source.h"

#include "protos/perfetto/common/data_source_descriptor.gen.h"
#include "protos/perfetto/config/chrome/v8_config.gen.h"
#include "protos/perfetto/trace/chrome/v8.pbzero.h"
#include "src/execution/isolate.h"
#include "src/handles/handles.h"
#include "src/heap/code-range.h"
#include "src/objects/function-kind.h"
#include "src/objects/script.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/string-inl.h"
#include "src/tracing/perfetto-logger.h"
#include "src/tracing/perfetto-utils.h"

PERFETTO_DEFINE_DATA_SOURCE_STATIC_MEMBERS(v8::internal::CodeDataSource,
                                           v8::internal::CodeDataSourceTraits);

namespace v8 {
namespace internal {
namespace {

using ::perfetto::protos::gen::V8Config;
using ::perfetto::protos::pbzero::InternedV8JsFunction;
using ::perfetto::protos::pbzero::InternedV8JsScript;
using ::perfetto::protos::pbzero::InternedV8String;
using ::perfetto::protos::pbzero::TracePacket;

InternedV8JsScript::Type GetJsScriptType(Tagged<Script> script) {
  if (script->compilation_type() == Script::CompilationType::kEval) {
    return InternedV8JsScript::TYPE_EVAL;
  }

  // TODO(carlscab): Camillo to extend the Script::Type enum. compilation_type
  // will no longer be needed.

  switch (script->type()) {
    case Script::Type::kNative:
      return InternedV8JsScript::TYPE_NATIVE;
    case Script::Type::kExtension:
      return InternedV8JsScript::TYPE_EXTENSION;
    case Script::Type::kNormal:
      return InternedV8JsScript::TYPE_NORMAL;
#if V8_ENABLE_WEBASSEMBLY
    case Script::Type::kWasm:
      UNREACHABLE();
#endif  // V8_ENABLE_WEBASSEMBLY
    case Script::Type::kInspector:
      return InternedV8JsScript::TYPE_INSPECTOR;
  }
}

InternedV8JsFunction::Kind GetJsFunctionKind(FunctionKind kind) {
  switch (kind) {
    case FunctionKind::kNormalFunction:
      return InternedV8JsFunction::KIND_NORMAL_FUNCTION;
    case FunctionKind::kModule:
      return InternedV8JsFunction::KIND_MODULE;
    case FunctionKind::kModuleWithTopLevelAwait:
      return InternedV8JsFunction::KIND_ASYNC_MODULE;
    case FunctionKind::kBaseConstructor:
      return InternedV8JsFunction::KIND_BASE_CONSTRUCTOR;
    case FunctionKind::kDefaultBaseConstructor:
      return InternedV8JsFunction::KIND_DEFAULT_BASE_CONSTRUCTOR;
    case FunctionKind::kDefaultDerivedConstructor:
      return InternedV8JsFunction::KIND_DEFAULT_DERIVED_CONSTRUCTOR;
    case FunctionKind::kDerivedConstructor:
      return InternedV8JsFunction::KIND_DERIVED_CONSTRUCTOR;
    case FunctionKind::kGetterFunction:
      return InternedV8JsFunction::KIND_GETTER_FUNCTION;
    case FunctionKind::kStaticGetterFunction:
      return InternedV8JsFunction::KIND_STATIC_GETTER_FUNCTION;
    case FunctionKind::kSetterFunction:
      return InternedV8JsFunction::KIND_SETTER_FUNCTION;
    case FunctionKind::kStaticSetterFunction:
      return InternedV8JsFunction::KIND_STATIC_SETTER_FUNCTION;
    case FunctionKind::kArrowFunction:
      return InternedV8JsFunction::KIND_ARROW_FUNCTION;
    case FunctionKind::kAsyncArrowFunction:
      return InternedV8JsFunction::KIND_ASYNC_ARROW_FUNCTION;
    case FunctionKind::kAsyncFunction:
      return InternedV8JsFunction::KIND_ASYNC_FUNCTION;
    case FunctionKind::kAsyncConciseMethod:
      return InternedV8JsFunction::KIND_ASYNC_CONCISE_METHOD;
    case FunctionKind::kStaticAsyncConciseMethod:
      return InternedV8JsFunction::KIND_STATIC_ASYNC_CONCISE_METHOD;
    case FunctionKind::kAsyncConciseGeneratorMethod:
      return InternedV8JsFunction::KIND_ASYNC_CONCISE_GENERATOR_METHOD;
    case FunctionKind::kStaticAsyncConciseGeneratorMethod:
      return InternedV8JsFunction::KIND_STATIC_ASYNC_CONCISE_GENERATOR_METHOD;
    case FunctionKind::kAsyncGeneratorFunction:
      return InternedV8JsFunction::KIND_ASYNC_GENERATOR_FUNCTION;
    case FunctionKind::kGeneratorFunction:
      return InternedV8JsFunction::KIND_GENERATOR_FUNCTION;
    case FunctionKind::kConciseGeneratorMethod:
      return InternedV8JsFunction::KIND_CONCISE_GENERATOR_METHOD;
    case FunctionKind::kStaticConciseGeneratorMethod:
      return InternedV8JsFunction::KIND_STATIC_CONCISE_GENERATOR_METHOD;
    case FunctionKind::kConciseMethod:
      return InternedV8JsFunction::KIND_CONCISE_METHOD;
    case FunctionKind::kStaticConciseMethod:
      return InternedV8JsFunction::KIND_STATIC_CONCISE_METHOD;
    case FunctionKind::kClassMembersInitializerFunction:
      return InternedV8JsFunction::KIND_CLASS_MEMBERS_INITIALIZER_FUNCTION;
    case FunctionKind::kClassStaticInitializerFunction:
      return InternedV8JsFunction::KIND_CLASS_STATIC_INITIALIZER_FUNCTION;
    case FunctionKind::kInvalid:
      return InternedV8JsFunction::KIND_INVALID;
  }

  return InternedV8JsFunction::KIND_UNKNOWN;
}

}  // namespace

void CodeDataSourceIncrementalState::Init(
    const CodeDataSource::TraceContext& context) {
  if (auto ds = context.GetDataSourceLocked(); ds) {
    const V8Config& config = ds->config();
    log_script_sources_ = config.log_script_sources();
    log_instructions_ = config.log_instructions();
  }
  initialized_ = true;
}

void CodeDataSourceIncrementalState::FlushInternedData(
    CodeDataSource::TraceContext::TracePacketHandle& packet) {
  auto ranges = serialized_interned_data_.GetRanges();
  packet->AppendScatteredBytes(TracePacket::kInternedDataFieldNumber,
                               &ranges[0], ranges.size());
  serialized_interned_data_.Reset();
}

uint64_t CodeDataSourceIncrementalState::InternIsolate(Isolate& isolate) {
  auto [it, was_inserted] = isolates_.emplace(isolate.id(), next_isolate_iid());
  uint64_t iid = it->second;
  if (!was_inserted) {
    return iid;
  }

  auto* isolate_proto = serialized_interned_data_->add_v8_isolate();
  isolate_proto->set_iid(iid);
  isolate_proto->set_isolate_id(isolate.id());
  isolate_proto->set_pid(base::OS::GetCurrentProcessId());
  isolate_proto->set_embedded_blob_code_start_address(
      reinterpret_cast<uint64_t>(isolate.embedded_blob_code()));
  isolate_proto->set_embedded_blob_code_size(isolate.embedded_blob_code_size());
  if (auto* code_range = isolate.heap()->code_range(); code_range != nullptr) {
    auto* v8_code_range = isolate_proto->set_code_range();
    v8_code_range->set_base_address(code_range->base());
    v8_code_range->set_size(code_range->size());
    if (code_range == IsolateGroup::current()->GetCodeRange()) {
      // FIXME(42204573): Belongs to isolate group, not process.
      v8_code_range->set_is_process_wide(true);
    }
    if (auto* embedded_builtins_start = code_range->embedded_blob_code_copy();
        embedded_builtins_start != nullptr) {
      v8_code_range->set_embedded_blob_code_copy_start_address(
          reinterpret_cast<uint64_t>(embedded_builtins_start));
    }
  }

  return iid;
}

uint64_t CodeDataSourceIncrementalState::InternJsScript(Isolate& isolate,
                                                        Tagged<Script> script) {
  auto [it, was_inserted] = scripts_.emplace(
      CodeDataSourceIncrementalState::ScriptUniqueId{isolate.id(),
                                                     script->id()},
      next_script_iid());
  uint64_t iid = it->second;
  if (!was_inserted) {
    return iid;
  }

  auto* proto = serialized_interned_data_->add_v8_js_script();
  proto->set_iid(iid);
  proto->set_script_id(script->id());
  proto->set_type(GetJsScriptType(script));
  if (IsString(script->name())) {
    PerfettoV8String(Cast<String>(script->name()))
        .WriteToProto(*proto->set_name());
  }
  if (log_script_sources() && IsString(script->source())) {
    PerfettoV8String(Cast<String>(script->source()))
        .WriteToProto(*proto->set_source());
  }

  return iid;
}

uint64_t CodeDataSourceIncrementalState::InternJsFunction(
    Isolate& isolate, Handle<SharedFunctionInfo> info,
    uint64_t v8_js_script_iid, int line_num, int column_num) {
  Handle<String> function_name = SharedFunctionInfo::DebugName(&isolate, info);
  uint64_t v8_js_function_name_iid = InternJsFunctionName(*function_name);

  auto [it, was_inserted] = functions_.emplace(
      CodeDataSourceIncrementalState::Function{
          v8_js_script_iid, info->is_toplevel(), info->StartPosition()},
      next_function_iid());
  const uint64_t iid = it->second;
  if (!was_inserted) {
    return iid;
  }

  auto* function_proto = serialized_interned_data_->add_v8_js_function();
  function_proto->set_iid(iid);
  function_proto->set_v8_js_function_name_iid(v8_js_function_name_iid);
  function_proto->set_v8_js_script_iid(v8_js_script_iid);
  function_proto->set_kind(GetJsFunctionKind(info->kind()));
  int32_t start_position = info->StartPosition();
  if (start_position >= 0) {
    function_proto->set_byte_offset(static_cast<uint32_t>(start_position));
  }

  return iid;
}

uint64_t CodeDataSourceIncrementalState::InternWasmScript(
    Isolate& isolate, int script_id, const std::string& url) {
  auto [it, was_inserted] = scripts_.emplace(
      CodeDataSourceIncrementalState::ScriptUniqueId{isolate.id(), script_id},
      next_script_iid());
  uint64_t iid = it->second;
  if (!was_inserted) {
    return iid;
  }

  auto* script = serialized_interned_data_->add_v8_wasm_script();
  script->set_iid(iid);
  script->set_script_id(script_id);
  script->set_url(url);

  // TODO(carlscab): Log scrip source if needed.

  return iid;
}

uint64_t CodeDataSourceIncrementalState::InternJsFunctionName(
    Tagged<String> function_name) {
  auto [it, was_inserted] = js_function_names_.emplace(
      PerfettoV8String(function_name), next_js_function_name_iid());
  uint64_t iid = it->second;
  if (!was_inserted) {
    return iid;
  }

  auto* v8_function_name = serialized_interned_data_->add_v8_js_function_name();
  v8_function_name->set_iid(iid);
  it->first.WriteToProto(*v8_function_name);
  return iid;
}

// static
void CodeDataSource::Register() {
  perfetto::DataSourceDescriptor desc;
  desc.set_name("dev.v8.code");
  Base::Register(desc);
}

void CodeDataSource::OnSetup(const SetupArgs& args) {
  config_.ParseFromString(args.config->v8_config_raw());
}

void CodeDataSource::OnStart(const StartArgs&) {
  PerfettoLogger::OnCodeDataSourceStart();
}

void CodeDataSource::OnStop(const StopArgs&) {
  PerfettoLogger::OnCodeDataSourceStop();
}

}  // namespace internal
}  // namespace v8
```