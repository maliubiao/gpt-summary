Response:
The user wants a summary of the provided C++ code from `v8/src/api/api.cc`. They've given constraints and questions to guide the summarization.

Here's a breakdown of the request and how to address each point:

1. **List the functionalities:**  Read through the code and identify the key areas and responsibilities of this file. Pay attention to the included headers and the functions defined.

2. **Check for `.tq` extension:** Look at the file path provided. Since it's `.cc`, it's not a Torque file.

3. **Relation to JavaScript (with examples):** Identify functionalities that directly expose V8's core to JavaScript or facilitate the execution of JavaScript code. Provide simple JavaScript examples demonstrating these functionalities.

4. **Code logic reasoning (with input/output):** If there are self-contained logical blocks in the provided snippet (though unlikely in this introductory part), try to analyze their behavior with hypothetical inputs. In this first part, the focus is more on setup and infrastructure, so this might be less applicable.

5. **Common programming errors:** Think about how developers using the V8 API might misuse the functionalities exposed in this file and provide illustrative examples.

6. **归纳一下它的功能 (Summarize its functionality):** Based on the identified functionalities, provide a concise summary of the role of `v8/src/api/api.cc`.

**Mental Sandbox:**

* **Initial Scan:** The included headers suggest this file deals with core V8 API elements, memory management, exception handling, snapshots, extensions, and resource constraints.
* **Key Functions:**  Focus on functions like `FatalProcessOutOfMemory`, `ReportApiFailure`, `SetSnapshotDataBlob`, `SetFlagsFromString`, `RegisterExtension`, and the `SnapshotCreator` class. These seem central to the file's purpose.
* **JavaScript Connection:** The `v8::` namespace clearly indicates the C++ API exposed to embedders, which are often used to run JavaScript. Think about how concepts like `Isolate`, `Context`, `Script`, and `Value` relate to JavaScript execution.
* **Error Handling:**  The error handling mechanisms seem crucial. Consider OOM errors and general API failures.
* **Snapshots:** The `SnapshotCreator` is definitely related to creating and using V8 snapshots for faster startup.
* **Extensions:** The `Extension` mechanism is for adding custom C++ functionality to the V8 engine.

**Constraint Checklist & Confidence Score:**

* List functionalities: Yes
* Check `.tq`: Yes
* JavaScript relation & examples: Yes
* Code logic reasoning: Low applicability in this part, but will look.
* Common errors: Yes
* Summarize: Yes

Confidence Score: 5/5 -  I'm confident I can address all aspects of the request effectively for this initial part of the file.

Strategizing complete. I will now proceed with generating the response based on the above analysis.
这是V8源代码文件 `v8/src/api/api.cc` 的第一部分，它定义了 V8 JavaScript 引擎的 **公共 C++ API** 的核心部分。 这部分主要关注以下几个核心功能：

**功能列举:**

1. **异常处理机制:**
   - 定义了 V8 遇到内存不足 (Out-of-Memory, OOM) 等致命错误时的处理方式，包括调用回调函数、打印错误信息、生成堆快照等。
   - 提供了 `FatalProcessOutOfMemory` 函数来处理致命的内存分配失败。
   - 提供了 `ReportApiFailure` 和 `ReportOOMFailure` 用于报告 API 使用错误和内存分配失败。
   - 允许设置 OOM 错误回调 (`g_oom_error_callback`) 和致命错误回调 (`FatalErrorCallback`)，以便嵌入器定制错误处理行为。

2. **快照 (Snapshot) 功能:**
   - 提供了 `SnapshotCreator` 类，用于创建 V8 堆的快照，以便在后续启动时更快地加载。
   - 允许添加默认上下文 (`SetDefaultContext`) 和额外的上下文 (`AddContext`) 到快照中。
   - 允许添加任意数据 (`AddData`) 到快照中。
   - 提供了 `CreateBlob` 函数来生成快照数据。
   - 提供了 `SetSnapshotDataBlob` 函数用于设置快照数据。
   - 提供了 `StartupData` 结构体来表示快照数据，并包含检查快照是否有效和可重新哈希的方法。

3. **标志 (Flags) 设置:**
   - 提供了 `SetFlagsFromString` 和 `SetFlagsFromCommandLine` 函数，允许在程序运行时设置 V8 的各种命令行标志，从而影响其行为和性能。

4. **扩展 (Extension) 机制:**
   - 定义了 `Extension` 类，允许嵌入器向 V8 引擎注册自定义的 C++ 扩展，从而在 JavaScript 中调用 C++ 代码。
   - 提供了 `RegisterExtension` 函数来注册扩展。
   - 使用 `RegisteredExtension` 链表来管理注册的扩展。

5. **资源约束 (Resource Constraints):**
   - 提供了 `ResourceConstraints` 类，用于设置 V8 引擎的资源限制，例如初始堆大小、最大堆大小、新生代和老年代的大小等，以控制 V8 的内存使用。
   - 提供了根据物理内存大小和虚拟内存限制自动配置默认资源约束的方法。

6. **句柄 (Handles) 管理 (内部使用):**
   - 提供了一些内部函数，例如 `GlobalizeReference`, `CopyGlobalReference`, `MoveGlobalReference`, `MakeWeak`, `DisposeGlobal` 等，用于管理 V8 对象的句柄，这对于 V8 的内部对象生命周期管理至关重要。

7. **Dcheck 和 Fatal Error 处理:**
   - 提供了 `SetDcheckErrorHandler` 和 `SetFatalErrorHandler` 函数，允许设置 dcheck 失败和致命错误的自定义处理函数。

**关于 `.tq` 结尾:**

`v8/src/api/api.cc` 以 `.cc` 结尾，表示这是一个 **C++ 源代码文件**。 如果它以 `.tq` 结尾，那它才是一个 **V8 Torque 源代码文件**。 Torque 是一种 V8 内部使用的领域特定语言，用于定义内置函数和运行时代码。

**与 JavaScript 的关系及 JavaScript 示例:**

`v8/src/api/api.cc` 中定义的功能是 V8 引擎提供给外部 (例如 Node.js, Chromium 等) 使用的 **C++ API**。 这些 API 允许嵌入器控制 V8 引擎的行为，例如创建和管理 JavaScript 虚拟机 (Isolate)、执行 JavaScript 代码、与 JavaScript 对象交互等。

以下是一些与此部分 C++ 代码功能相关的 JavaScript 概念和示例：

1. **异常处理:** 当 JavaScript 代码执行出错时，V8 会抛出异常。 嵌入器可以使用 V8 的 C++ API 捕获和处理这些异常。

   ```javascript
   try {
     throw new Error("Something went wrong!");
   } catch (e) {
     console.error("Caught an error:", e.message);
     // V8 的 C++ API 允许嵌入器在这里进行更底层的错误处理
   }
   ```

2. **快照:**  快照功能允许 V8 将其内部状态保存到文件中，以便后续启动时可以快速恢复，减少启动时间。这在 Node.js 和浏览器中都有应用。

   虽然 JavaScript 代码本身不能直接创建或操作快照，但快照的目的是为了加速 JavaScript 代码的执行。

3. **扩展:**  V8 扩展允许你用 C++ 编写功能，然后在 JavaScript 中调用。

   假设你在 C++ 扩展中注册了一个名为 `myExtensionFunction` 的函数：

   ```javascript
   // 假设 myExtensionFunction 是一个 C++ 扩展提供的全局函数
   let result = myExtensionFunction(10, 20);
   console.log(result);
   ```

4. **资源约束:** 虽然 JavaScript 代码无法直接设置 V8 的堆大小等资源约束，但这些约束会直接影响 JavaScript 代码的执行，例如，当达到最大堆大小时，可能会导致 OOM 错误。

   ```javascript
   // 如果 V8 的最大堆大小设置得很小，执行以下代码可能会导致 OOM 错误
   let largeArray = [];
   for (let i = 0; i < 1e9; i++) {
     largeArray.push(i);
   }
   ```

**代码逻辑推理 (此部分代码主要为 API 定义和基础架构，逻辑推理较少):**

由于这部分代码主要是 API 的声明和一些基础的错误处理、初始化逻辑，因此直接的“假设输入与输出”的代码逻辑推理较少。  它更多是定义了接口和行为规范。

**用户常见的编程错误:**

1. **忘记处理 OOM 错误:**  如果嵌入器没有正确设置或处理 `g_oom_error_callback`，当 V8 发生 OOM 错误时，程序可能会直接崩溃，而没有机会进行清理或记录日志。

2. **错误地设置快照:**  如果在创建或加载快照时出现错误（例如，快照数据损坏），可能会导致 V8 启动失败或行为异常。

3. **不正确地管理扩展的生命周期:**  如果扩展中使用的资源没有正确释放，可能会导致内存泄漏。

4. **设置不合理的资源约束:**  如果设置的堆大小过小，可能会导致频繁的垃圾回收，降低性能；如果设置的堆大小过大，可能会浪费内存。

5. **在没有 `Locker` 的情况下调用 V8 API:** V8 的某些 API 只能在持有 `Locker` 的线程中调用。如果在非 `Locker` 线程中调用这些 API，可能会导致崩溃或未定义的行为。

**归纳一下它的功能:**

总而言之，`v8/src/api/api.cc` 的第一部分定义了 V8 引擎 **公共 C++ API 的核心基础设施**，涵盖了异常处理、快照机制、扩展注册、资源管理等关键功能。 它为嵌入器提供了控制 V8 引擎行为的基础接口，使得外部程序能够安全有效地集成和使用 V8 引擎来执行 JavaScript 代码。 这部分代码更像是 V8 引擎与外部世界交互的 “门面” 和 “控制中心”。

Prompt: 
```
这是目录为v8/src/api/api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/api/api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共15部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/api/api.h"

#include <algorithm>  // For min
#include <cmath>      // For isnan.
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <utility>  // For move
#include <vector>

#include "include/v8-array-buffer.h"
#include "include/v8-callbacks.h"
#include "include/v8-cppgc.h"
#include "include/v8-date.h"
#include "include/v8-embedder-state-scope.h"
#include "include/v8-extension.h"
#include "include/v8-fast-api-calls.h"
#include "include/v8-function.h"
#include "include/v8-json.h"
#include "include/v8-locker.h"
#include "include/v8-primitive-object.h"
#include "include/v8-profiler.h"
#include "include/v8-source-location.h"
#include "include/v8-template.h"
#include "include/v8-unwinder-state.h"
#include "include/v8-util.h"
#include "include/v8-wasm.h"
#include "src/api/api-arguments.h"
#include "src/api/api-inl.h"
#include "src/api/api-natives.h"
#include "src/base/functional.h"
#include "src/base/logging.h"
#include "src/base/platform/memory.h"
#include "src/base/platform/platform.h"
#include "src/base/platform/time.h"
#include "src/base/safe_conversions.h"
#include "src/base/utils/random-number-generator.h"
#include "src/base/vector.h"
#include "src/builtins/accessors.h"
#include "src/builtins/builtins-utils.h"
#include "src/codegen/compilation-cache.h"
#include "src/codegen/compiler.h"
#include "src/codegen/cpu-features.h"
#include "src/codegen/script-details.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/compiler-dispatcher/lazy-compile-dispatcher.h"
#include "src/date/date.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/embedder-state.h"
#include "src/execution/execution.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/messages.h"
#include "src/execution/microtask-queue.h"
#include "src/execution/simulator.h"
#include "src/execution/v8threads.h"
#include "src/execution/vm-state-inl.h"
#include "src/handles/global-handles.h"
#include "src/handles/persistent-handles.h"
#include "src/handles/shared-object-conveyor-handles.h"
#include "src/handles/traced-handles-inl.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-write-barrier.h"
#include "src/heap/safepoint.h"
#include "src/heap/visit-object.h"
#include "src/init/bootstrapper.h"
#include "src/init/icu_util.h"
#include "src/init/startup-data-util.h"
#include "src/init/v8.h"
#include "src/json/json-parser.h"
#include "src/json/json-stringifier.h"
#include "src/logging/counters-scopes.h"
#include "src/logging/metrics.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/logging/tracing-flags.h"
#include "src/numbers/conversions-inl.h"
#include "src/objects/api-callbacks.h"
#include "src/objects/backing-store.h"
#include "src/objects/contexts.h"
#include "src/objects/embedder-data-array-inl.h"
#include "src/objects/embedder-data-slot-inl.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/heap-object.h"
#include "src/objects/instance-type-inl.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/js-objects.h"
#include "src/objects/js-promise-inl.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/js-weak-refs-inl.h"
#include "src/objects/module-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/oddball.h"
#include "src/objects/ordered-hash-table-inl.h"
#include "src/objects/primitive-heap-object.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/property-details.h"
#include "src/objects/property.h"
#include "src/objects/prototype.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/slots.h"
#include "src/objects/smi.h"
#include "src/objects/string.h"
#include "src/objects/synthetic-module-inl.h"
#include "src/objects/templates.h"
#include "src/objects/value-serializer.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/parser.h"
#include "src/parsing/pending-compilation-error-handler.h"
#include "src/parsing/scanner-character-streams.h"
#include "src/profiler/cpu-profiler.h"
#include "src/profiler/heap-profiler.h"
#include "src/profiler/heap-snapshot-generator-inl.h"
#include "src/profiler/profile-generator-inl.h"
#include "src/profiler/tick-sample.h"
#include "src/regexp/regexp-utils.h"
#include "src/roots/static-roots.h"
#include "src/runtime/runtime.h"
#include "src/sandbox/external-pointer.h"
#include "src/sandbox/isolate.h"
#include "src/sandbox/sandbox.h"
#include "src/snapshot/code-serializer.h"
#include "src/snapshot/embedded/embedded-data.h"
#include "src/snapshot/snapshot.h"
#include "src/strings/char-predicates-inl.h"
#include "src/strings/string-hasher.h"
#include "src/strings/unicode-inl.h"
#include "src/tracing/trace-event.h"
#include "src/utils/detachable-vector.h"
#include "src/utils/identity-map.h"
#include "src/utils/version.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/debug/debug-wasm-objects.h"
#include "src/trap-handler/trap-handler.h"
#include "src/wasm/streaming-decoder.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-js.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-result.h"
#include "src/wasm/wasm-serialization.h"
#endif  // V8_ENABLE_WEBASSEMBLY

#if V8_OS_LINUX || V8_OS_DARWIN || V8_OS_FREEBSD
#include <signal.h>
#include <unistd.h>

#if V8_ENABLE_WEBASSEMBLY
#include "include/v8-wasm-trap-handler-posix.h"
#include "src/trap-handler/handler-inside-posix.h"
#endif  // V8_ENABLE_WEBASSEMBLY

#endif  // V8_OS_LINUX || V8_OS_DARWIN || V8_OS_FREEBSD

#if V8_OS_WIN
#include "include/v8-wasm-trap-handler-win.h"
#include "src/trap-handler/handler-inside-win.h"
#if defined(V8_OS_WIN64)
#include "src/base/platform/wrappers.h"
#include "src/diagnostics/unwinding-info-win64.h"
#endif  // V8_OS_WIN64
#endif  // V8_OS_WIN

#if defined(V8_OS_WIN) && defined(V8_ENABLE_ETW_STACK_WALKING)
#include "src/diagnostics/etw-jit-win.h"
#endif

// Has to be the last include (doesn't have include guards):
#include "src/api/api-macros.h"

namespace v8 {

static OOMErrorCallback g_oom_error_callback = nullptr;

static ScriptOrigin GetScriptOriginForScript(
    i::Isolate* i_isolate, i::DirectHandle<i::Script> script) {
  i::DirectHandle<i::Object> scriptName(script->GetNameOrSourceURL(),
                                        i_isolate);
  i::DirectHandle<i::Object> source_map_url(script->source_mapping_url(),
                                            i_isolate);
  i::DirectHandle<i::Object> host_defined_options(
      script->host_defined_options(), i_isolate);
  ScriptOriginOptions options(script->origin_options());
  bool is_wasm = false;
#if V8_ENABLE_WEBASSEMBLY
  is_wasm = script->type() == i::Script::Type::kWasm;
#endif  // V8_ENABLE_WEBASSEMBLY
  v8::ScriptOrigin origin(
      Utils::ToLocal(scriptName), script->line_offset(),
      script->column_offset(), options.IsSharedCrossOrigin(), script->id(),
      Utils::ToLocal(source_map_url), options.IsOpaque(), is_wasm,
      options.IsModule(), Utils::ToLocal(host_defined_options));
  return origin;
}

// --- E x c e p t i o n   B e h a v i o r ---

// When V8 cannot allocate memory FatalProcessOutOfMemory is called. The default
// OOM error handler is called and execution is stopped.
void i::V8::FatalProcessOutOfMemory(i::Isolate* i_isolate, const char* location,
                                    const OOMDetails& details) {
  char last_few_messages[Heap::kTraceRingBufferSize + 1];
  char js_stacktrace[Heap::kStacktraceBufferSize + 1];
  i::HeapStats heap_stats;

  if (i_isolate == nullptr) {
    i_isolate = Isolate::TryGetCurrent();
  }

  if (i_isolate == nullptr) {
    // If the Isolate is not available for the current thread we cannot retrieve
    // memory information from the Isolate. Write easy-to-recognize values on
    // the stack.
    memset(last_few_messages, 0x0BADC0DE, Heap::kTraceRingBufferSize + 1);
    memset(js_stacktrace, 0x0BADC0DE, Heap::kStacktraceBufferSize + 1);
    memset(&heap_stats, 0xBADC0DE, sizeof(heap_stats));
    // Give the embedder a chance to handle the condition. If it doesn't,
    // just crash.
    if (g_oom_error_callback) g_oom_error_callback(location, details);
    base::FatalOOM(base::OOMType::kProcess, location);
    UNREACHABLE();
  }

  memset(last_few_messages, 0, Heap::kTraceRingBufferSize + 1);
  memset(js_stacktrace, 0, Heap::kStacktraceBufferSize + 1);

  intptr_t start_marker;
  heap_stats.start_marker = &start_marker;
  size_t ro_space_size;
  heap_stats.ro_space_size = &ro_space_size;
  size_t ro_space_capacity;
  heap_stats.ro_space_capacity = &ro_space_capacity;
  size_t new_space_size;
  heap_stats.new_space_size = &new_space_size;
  size_t new_space_capacity;
  heap_stats.new_space_capacity = &new_space_capacity;
  size_t old_space_size;
  heap_stats.old_space_size = &old_space_size;
  size_t old_space_capacity;
  heap_stats.old_space_capacity = &old_space_capacity;
  size_t code_space_size;
  heap_stats.code_space_size = &code_space_size;
  size_t code_space_capacity;
  heap_stats.code_space_capacity = &code_space_capacity;
  size_t map_space_size;
  heap_stats.map_space_size = &map_space_size;
  size_t map_space_capacity;
  heap_stats.map_space_capacity = &map_space_capacity;
  size_t lo_space_size;
  heap_stats.lo_space_size = &lo_space_size;
  size_t code_lo_space_size;
  heap_stats.code_lo_space_size = &code_lo_space_size;
  size_t global_handle_count;
  heap_stats.global_handle_count = &global_handle_count;
  size_t weak_global_handle_count;
  heap_stats.weak_global_handle_count = &weak_global_handle_count;
  size_t pending_global_handle_count;
  heap_stats.pending_global_handle_count = &pending_global_handle_count;
  size_t near_death_global_handle_count;
  heap_stats.near_death_global_handle_count = &near_death_global_handle_count;
  size_t free_global_handle_count;
  heap_stats.free_global_handle_count = &free_global_handle_count;
  size_t memory_allocator_size;
  heap_stats.memory_allocator_size = &memory_allocator_size;
  size_t memory_allocator_capacity;
  heap_stats.memory_allocator_capacity = &memory_allocator_capacity;
  size_t malloced_memory;
  heap_stats.malloced_memory = &malloced_memory;
  size_t malloced_peak_memory;
  heap_stats.malloced_peak_memory = &malloced_peak_memory;
  size_t objects_per_type[LAST_TYPE + 1] = {0};
  heap_stats.objects_per_type = objects_per_type;
  size_t size_per_type[LAST_TYPE + 1] = {0};
  heap_stats.size_per_type = size_per_type;
  int os_error;
  heap_stats.os_error = &os_error;
  heap_stats.last_few_messages = last_few_messages;
  heap_stats.js_stacktrace = js_stacktrace;
  intptr_t end_marker;
  heap_stats.end_marker = &end_marker;
  if (i_isolate->heap()->HasBeenSetUp()) {
    // BUG(1718): Don't use the take_snapshot since we don't support
    // HeapObjectIterator here without doing a special GC.
    i_isolate->heap()->RecordStats(&heap_stats, false);
    if (!v8_flags.correctness_fuzzer_suppressions) {
      char* first_newline = strchr(last_few_messages, '\n');
      if (first_newline == nullptr || first_newline[1] == '\0')
        first_newline = last_few_messages;
      base::OS::PrintError("\n<--- Last few GCs --->\n%s\n", first_newline);
      base::OS::PrintError("\n<--- JS stacktrace --->\n%s\n", js_stacktrace);
    }
  }
  Utils::ReportOOMFailure(i_isolate, location, details);
  if (g_oom_error_callback) g_oom_error_callback(location, details);
  // If the fatal error handler returns, we stop execution.
  FATAL("API fatal error handler returned after process out of memory");
}

void i::V8::FatalProcessOutOfMemory(i::Isolate* i_isolate, const char* location,
                                    const char* detail) {
  OOMDetails details;
  details.detail = detail;
  FatalProcessOutOfMemory(i_isolate, location, details);
}

void Utils::ReportApiFailure(const char* location, const char* message) {
  i::Isolate* i_isolate = i::Isolate::TryGetCurrent();
  FatalErrorCallback callback = nullptr;
  if (i_isolate != nullptr) {
    callback = i_isolate->exception_behavior();
  }
  if (callback == nullptr) {
    base::OS::PrintError("\n#\n# Fatal error in %s\n# %s\n#\n\n", location,
                         message);
    base::OS::Abort();
  } else {
    callback(location, message);
  }
  i_isolate->SignalFatalError();
}

void Utils::ReportOOMFailure(i::Isolate* i_isolate, const char* location,
                             const OOMDetails& details) {
  if (auto oom_callback = i_isolate->oom_behavior()) {
    oom_callback(location, details);
  } else {
    // TODO(wfh): Remove this fallback once Blink is setting OOM handler. See
    // crbug.com/614440.
    FatalErrorCallback fatal_callback = i_isolate->exception_behavior();
    if (fatal_callback == nullptr) {
      base::OOMType type = details.is_heap_oom ? base::OOMType::kJavaScript
                                               : base::OOMType::kProcess;
      base::FatalOOM(type, location);
      UNREACHABLE();
    } else {
      fatal_callback(location,
                     details.is_heap_oom
                         ? "Allocation failed - JavaScript heap out of memory"
                         : "Allocation failed - process out of memory");
    }
  }
  i_isolate->SignalFatalError();
}

void V8::SetSnapshotDataBlob(StartupData* snapshot_blob) {
  i::V8::SetSnapshotBlob(snapshot_blob);
}

namespace {

#ifdef V8_ENABLE_SANDBOX
// ArrayBufferAllocator to use when the sandbox is enabled in which case all
// ArrayBuffer backing stores need to be allocated inside the sandbox.
class ArrayBufferAllocator : public v8::ArrayBuffer::Allocator {
 public:
  void* Allocate(size_t length) override {
    return allocator_->Allocate(length);
  }

  void* AllocateUninitialized(size_t length) override {
    return Allocate(length);
  }

  void Free(void* data, size_t length) override {
    return allocator_->Free(data);
  }

 private:
  // Backend allocator shared by all ArrayBufferAllocator instances. This way,
  // there is a single region of virtual address space reserved inside the
  // sandbox from which all ArrayBufferAllocators allocate their memory,
  // instead of each allocator creating their own region, which may cause
  // address space exhaustion inside the sandbox.
  // TODO(chromium:1340224): replace this with a more efficient allocator.
  class BackendAllocator {
   public:
    BackendAllocator() {
      CHECK(i::GetProcessWideSandbox()->is_initialized());
      VirtualAddressSpace* vas = i::GetProcessWideSandbox()->address_space();
      constexpr size_t max_backing_memory_size = 8ULL * i::GB;
      constexpr size_t min_backing_memory_size = 1ULL * i::GB;
      size_t backing_memory_size = max_backing_memory_size;
      i::Address backing_memory_base = 0;
      while (!backing_memory_base &&
             backing_memory_size >= min_backing_memory_size) {
        backing_memory_base = vas->AllocatePages(
            VirtualAddressSpace::kNoHint, backing_memory_size, kChunkSize,
            PagePermissions::kNoAccess);
        if (!backing_memory_base) {
          backing_memory_size /= 2;
        }
      }
      if (!backing_memory_base) {
        i::V8::FatalProcessOutOfMemory(
            nullptr,
            "Could not reserve backing memory for ArrayBufferAllocators");
      }
      DCHECK(IsAligned(backing_memory_base, kChunkSize));

      region_alloc_ = std::make_unique<base::RegionAllocator>(
          backing_memory_base, backing_memory_size, kAllocationGranularity);
      end_of_accessible_region_ = region_alloc_->begin();

      // Install an on-merge callback to discard or decommit unused pages.
      region_alloc_->set_on_merge_callback([this](i::Address start,
                                                  size_t size) {
        mutex_.AssertHeld();
        VirtualAddressSpace* vas = i::GetProcessWideSandbox()->address_space();
        i::Address end = start + size;
        if (end == region_alloc_->end() &&
            start <= end_of_accessible_region_ - kChunkSize) {
          // Can shrink the accessible region.
          i::Address new_end_of_accessible_region = RoundUp(start, kChunkSize);
          size_t size =
              end_of_accessible_region_ - new_end_of_accessible_region;
          if (!vas->DecommitPages(new_end_of_accessible_region, size)) {
            i::V8::FatalProcessOutOfMemory(
                nullptr, "ArrayBufferAllocator::BackendAllocator()");
          }
          end_of_accessible_region_ = new_end_of_accessible_region;
        } else if (size >= 2 * kChunkSize) {
          // Can discard pages. The pages stay accessible, so the size of the
          // accessible region doesn't change.
          i::Address chunk_start = RoundUp(start, kChunkSize);
          i::Address chunk_end = RoundDown(start + size, kChunkSize);
          if (!vas->DiscardSystemPages(chunk_start, chunk_end - chunk_start)) {
            i::V8::FatalProcessOutOfMemory(
                nullptr, "ArrayBufferAllocator::BackendAllocator()");
          }
        }
      });
    }

    ~BackendAllocator() {
      // The sandbox may already have been torn down, in which case there's no
      // need to free any memory.
      if (i::GetProcessWideSandbox()->is_initialized()) {
        VirtualAddressSpace* vas = i::GetProcessWideSandbox()->address_space();
        vas->FreePages(region_alloc_->begin(), region_alloc_->size());
      }
    }

    BackendAllocator(const BackendAllocator&) = delete;
    BackendAllocator& operator=(const BackendAllocator&) = delete;

    void* Allocate(size_t length) {
      base::MutexGuard guard(&mutex_);

      length = RoundUp(length, kAllocationGranularity);
      i::Address region = region_alloc_->AllocateRegion(length);
      if (region == base::RegionAllocator::kAllocationFailure) return nullptr;

      // Check if the memory is inside the accessible region. If not, grow it.
      i::Address end = region + length;
      size_t length_to_memset = length;
      if (end > end_of_accessible_region_) {
        VirtualAddressSpace* vas = i::GetProcessWideSandbox()->address_space();
        i::Address new_end_of_accessible_region = RoundUp(end, kChunkSize);
        size_t size = new_end_of_accessible_region - end_of_accessible_region_;
        if (!vas->SetPagePermissions(end_of_accessible_region_, size,
                                     PagePermissions::kReadWrite)) {
          if (!region_alloc_->FreeRegion(region)) {
            i::V8::FatalProcessOutOfMemory(
                nullptr, "ArrayBufferAllocator::BackendAllocator::Allocate()");
          }
          return nullptr;
        }

        // The pages that were inaccessible are guaranteed to be zeroed, so only
        // memset until the previous end of the accessible region.
        length_to_memset = end_of_accessible_region_ - region;
        end_of_accessible_region_ = new_end_of_accessible_region;
      }

      void* mem = reinterpret_cast<void*>(region);
      memset(mem, 0, length_to_memset);
      return mem;
    }

    void Free(void* data) {
      base::MutexGuard guard(&mutex_);
      region_alloc_->FreeRegion(reinterpret_cast<i::Address>(data));
    }

    static BackendAllocator* SharedInstance() {
      static base::LeakyObject<BackendAllocator> instance;
      return instance.get();
    }

   private:
    // Use a region allocator with a "page size" of 128 bytes as a reasonable
    // compromise between the number of regions it has to manage and the amount
    // of memory wasted due to rounding allocation sizes up to the page size.
    static constexpr size_t kAllocationGranularity = 128;
    // The backing memory's accessible region is grown in chunks of this size.
    static constexpr size_t kChunkSize = 1 * i::MB;

    std::unique_ptr<base::RegionAllocator> region_alloc_;
    size_t end_of_accessible_region_;
    base::Mutex mutex_;
  };

  BackendAllocator* allocator_ = BackendAllocator::SharedInstance();
};

#else

class ArrayBufferAllocator : public v8::ArrayBuffer::Allocator {
 public:
  void* Allocate(size_t length) override { return base::Calloc(length, 1); }

  void* AllocateUninitialized(size_t length) override {
    return base::Malloc(length);
  }

  void Free(void* data, size_t) override { base::Free(data); }

  void* Reallocate(void* data, size_t old_length, size_t new_length) override {
    void* new_data = base::Realloc(data, new_length);
    if (new_length > old_length) {
      memset(reinterpret_cast<uint8_t*>(new_data) + old_length, 0,
             new_length - old_length);
    }
    return new_data;
  }
};
#endif  // V8_ENABLE_SANDBOX

}  // namespace

SnapshotCreator::SnapshotCreator(Isolate* v8_isolate,
                                 const intptr_t* external_references,
                                 const StartupData* existing_snapshot,
                                 bool owns_isolate)
    : impl_(new i::SnapshotCreatorImpl(
          reinterpret_cast<i::Isolate*>(v8_isolate), external_references,
          existing_snapshot, owns_isolate)) {}

SnapshotCreator::SnapshotCreator(const intptr_t* external_references,
                                 const StartupData* existing_snapshot)
    : SnapshotCreator(nullptr, external_references, existing_snapshot) {}

SnapshotCreator::SnapshotCreator(const v8::Isolate::CreateParams& params)
    : impl_(new i::SnapshotCreatorImpl(params)) {}

SnapshotCreator::SnapshotCreator(v8::Isolate* isolate,
                                 const v8::Isolate::CreateParams& params)
    : impl_(new i::SnapshotCreatorImpl(reinterpret_cast<i::Isolate*>(isolate),
                                       params)) {}

SnapshotCreator::~SnapshotCreator() {
  DCHECK_NOT_NULL(impl_);
  delete impl_;
}

Isolate* SnapshotCreator::GetIsolate() {
  return reinterpret_cast<v8::Isolate*>(impl_->isolate());
}

void SnapshotCreator::SetDefaultContext(
    Local<Context> context,
    SerializeInternalFieldsCallback internal_fields_serializer,
    SerializeContextDataCallback context_data_serializer,
    SerializeAPIWrapperCallback api_wrapper_serializer) {
  impl_->SetDefaultContext(
      Utils::OpenHandle(*context),
      i::SerializeEmbedderFieldsCallback(internal_fields_serializer,
                                         context_data_serializer,
                                         api_wrapper_serializer));
}

size_t SnapshotCreator::AddContext(
    Local<Context> context,
    SerializeInternalFieldsCallback internal_fields_serializer,
    SerializeContextDataCallback context_data_serializer,
    SerializeAPIWrapperCallback api_wrapper_serializer) {
  return impl_->AddContext(
      Utils::OpenHandle(*context),
      i::SerializeEmbedderFieldsCallback(internal_fields_serializer,
                                         context_data_serializer,
                                         api_wrapper_serializer));
}

size_t SnapshotCreator::AddData(i::Address object) {
  return impl_->AddData(object);
}

size_t SnapshotCreator::AddData(Local<Context> context, i::Address object) {
  return impl_->AddData(Utils::OpenHandle(*context), object);
}

StartupData SnapshotCreator::CreateBlob(
    SnapshotCreator::FunctionCodeHandling function_code_handling) {
  return impl_->CreateBlob(function_code_handling);
}

bool StartupData::CanBeRehashed() const {
  DCHECK(i::Snapshot::VerifyChecksum(this));
  return i::Snapshot::ExtractRehashability(this);
}

bool StartupData::IsValid() const { return i::Snapshot::VersionIsValid(this); }

void V8::SetDcheckErrorHandler(DcheckErrorCallback that) {
  v8::base::SetDcheckFunction(that);
}

void V8::SetFatalErrorHandler(V8FatalErrorCallback that) {
  v8::base::SetFatalFunction(that);
}

void V8::SetFlagsFromString(const char* str) {
  SetFlagsFromString(str, strlen(str));
}

void V8::SetFlagsFromString(const char* str, size_t length) {
  i::FlagList::SetFlagsFromString(str, length);
}

void V8::SetFlagsFromCommandLine(int* argc, char** argv, bool remove_flags) {
  using HelpOptions = i::FlagList::HelpOptions;
  i::FlagList::SetFlagsFromCommandLine(argc, argv, remove_flags,
                                       HelpOptions(HelpOptions::kDontExit));
}

RegisteredExtension* RegisteredExtension::first_extension_ = nullptr;

RegisteredExtension::RegisteredExtension(std::unique_ptr<Extension> extension)
    : extension_(std::move(extension)) {}

// static
void RegisteredExtension::Register(std::unique_ptr<Extension> extension) {
  RegisteredExtension* new_extension =
      new RegisteredExtension(std::move(extension));
  new_extension->next_ = first_extension_;
  first_extension_ = new_extension;
}

// static
void RegisteredExtension::UnregisterAll() {
  RegisteredExtension* re = first_extension_;
  while (re != nullptr) {
    RegisteredExtension* next = re->next();
    delete re;
    re = next;
  }
  first_extension_ = nullptr;
}

namespace {
class ExtensionResource : public String::ExternalOneByteStringResource {
 public:
  ExtensionResource() : data_(nullptr), length_(0) {}
  ExtensionResource(const char* data, size_t length)
      : data_(data), length_(length) {}
  const char* data() const override { return data_; }
  size_t length() const override { return length_; }
  void Dispose() override {}

 private:
  const char* data_;
  size_t length_;
};
}  // anonymous namespace

void RegisterExtension(std::unique_ptr<Extension> extension) {
  RegisteredExtension::Register(std::move(extension));
}

Extension::Extension(const char* name, const char* source, int dep_count,
                     const char** deps, int source_length)
    : name_(name),
      source_length_(source_length >= 0
                         ? source_length
                         : (source ? static_cast<int>(strlen(source)) : 0)),
      dep_count_(dep_count),
      deps_(deps),
      auto_enable_(false) {
  source_ = new ExtensionResource(source, source_length_);
  CHECK(source != nullptr || source_length_ == 0);
}

void ResourceConstraints::ConfigureDefaultsFromHeapSize(
    size_t initial_heap_size_in_bytes, size_t maximum_heap_size_in_bytes) {
  CHECK_LE(initial_heap_size_in_bytes, maximum_heap_size_in_bytes);
  if (maximum_heap_size_in_bytes == 0) {
    return;
  }
  size_t young_generation, old_generation;
  i::Heap::GenerationSizesFromHeapSize(maximum_heap_size_in_bytes,
                                       &young_generation, &old_generation);
  set_max_young_generation_size_in_bytes(
      std::max(young_generation, i::Heap::MinYoungGenerationSize()));
  set_max_old_generation_size_in_bytes(
      std::max(old_generation, i::Heap::MinOldGenerationSize()));
  if (initial_heap_size_in_bytes > 0) {
    i::Heap::GenerationSizesFromHeapSize(initial_heap_size_in_bytes,
                                         &young_generation, &old_generation);
    // We do not set lower bounds for the initial sizes.
    set_initial_young_generation_size_in_bytes(young_generation);
    set_initial_old_generation_size_in_bytes(old_generation);
  }
  if (i::kPlatformRequiresCodeRange) {
    set_code_range_size_in_bytes(
        std::min(i::kMaximalCodeRangeSize, maximum_heap_size_in_bytes));
  }
}

void ResourceConstraints::ConfigureDefaults(uint64_t physical_memory,
                                            uint64_t virtual_memory_limit) {
  size_t heap_size = i::Heap::HeapSizeFromPhysicalMemory(physical_memory);
  size_t young_generation, old_generation;
  i::Heap::GenerationSizesFromHeapSize(heap_size, &young_generation,
                                       &old_generation);
  set_max_young_generation_size_in_bytes(young_generation);
  set_max_old_generation_size_in_bytes(old_generation);

  if (virtual_memory_limit > 0 && i::kPlatformRequiresCodeRange) {
    set_code_range_size_in_bytes(
        std::min(i::kMaximalCodeRangeSize,
                 static_cast<size_t>(virtual_memory_limit / 8)));
  }
}

namespace api_internal {
void StackAllocated<true>::VerifyOnStack() const {
  if (internal::StackAllocatedCheck::Get()) {
    DCHECK(::heap::base::Stack::IsOnStack(this));
  }
}
}  // namespace api_internal

namespace internal {

void VerifyHandleIsNonEmpty(bool is_empty) {
  Utils::ApiCheck(!is_empty, "v8::ReturnValue",
                  "SetNonEmpty() called with empty handle.");
}

i::Address* GlobalizeTracedReference(
    i::Isolate* i_isolate, i::Address value, internal::Address* slot,
    TracedReferenceStoreMode store_mode,
    TracedReferenceHandling reference_handling) {
  return i_isolate->traced_handles()
      ->Create(value, slot, store_mode, reference_handling)
      .location();
}

void MoveTracedReference(internal::Address** from, internal::Address** to) {
  TracedHandles::Move(from, to);
}

void CopyTracedReference(const internal::Address* const* from,
                         internal::Address** to) {
  TracedHandles::Copy(from, to);
}

void DisposeTracedReference(internal::Address* location) {
  TracedHandles::Destroy(location);
}

#if V8_STATIC_ROOTS_BOOL

// Check static root constants exposed in v8-internal.h.

namespace {
constexpr InstanceTypeChecker::TaggedAddressRange kStringMapRange =
    *InstanceTypeChecker::UniqueMapRangeOfInstanceTypeRange(FIRST_STRING_TYPE,
                                                            LAST_STRING_TYPE);
}  // namespace

#define EXPORTED_STATIC_ROOTS_PTR_MAPPING(V)                \
  V(UndefinedValue, i::StaticReadOnlyRoot::kUndefinedValue) \
  V(NullValue, i::StaticReadOnlyRoot::kNullValue)           \
  V(TrueValue, i::StaticReadOnlyRoot::kTrueValue)           \
  V(FalseValue, i::StaticReadOnlyRoot::kFalseValue)         \
  V(EmptyString, i::StaticReadOnlyRoot::kempty_string)      \
  V(TheHoleValue, i::StaticReadOnlyRoot::kTheHoleValue)     \
  V(StringMapLowerBound, kStringMapRange.first)             \
  V(StringMapUpperBound, kStringMapRange.second)

static_assert(std::is_same<Internals::Tagged_t, Tagged_t>::value);
// Ensure they have the correct value.
#define CHECK_STATIC_ROOT(name, value) \
  static_assert(Internals::StaticReadOnlyRoot::k##name == value);
EXPORTED_STATIC_ROOTS_PTR_MAPPING(CHECK_STATIC_ROOT)
#undef CHECK_STATIC_ROOT
#define PLUS_ONE(...) +1
static constexpr int kNumberOfCheckedStaticRoots =
    0 EXPORTED_STATIC_ROOTS_PTR_MAPPING(PLUS_ONE);
#undef EXPORTED_STATIC_ROOTS_PTR_MAPPING
static_assert(Internals::StaticReadOnlyRoot::kNumberOfExportedStaticRoots ==
              kNumberOfCheckedStaticRoots);

#endif  // V8_STATIC_ROOTS_BOOL

}  // namespace internal

namespace api_internal {

i::Address* GlobalizeReference(i::Isolate* i_isolate, i::Address value) {
  API_RCS_SCOPE(i_isolate, Persistent, New);
  i::Handle<i::Object> result = i_isolate->global_handles()->Create(value);
#ifdef VERIFY_HEAP
  if (i::v8_flags.verify_heap) {
    i::Object::ObjectVerify(i::Tagged<i::Object>(value), i_isolate);
  }
#endif  // VERIFY_HEAP
  return result.location();
}

i::Address* CopyGlobalReference(i::Address* from) {
  i::Handle<i::Object> result = i::GlobalHandles::CopyGlobal(from);
  return result.location();
}

void MoveGlobalReference(internal::Address** from, internal::Address** to) {
  i::GlobalHandles::MoveGlobal(from, to);
}

void MakeWeak(i::Address* location, void* parameter,
              WeakCallbackInfo<void>::Callback weak_callback,
              WeakCallbackType type) {
  i::GlobalHandles::MakeWeak(location, parameter, weak_callback, type);
}

void MakeWeak(i::Address** location_addr) {
  i::GlobalHandles::MakeWeak(location_addr);
}

void* ClearWeak(i::Address* location) {
  return i::GlobalHandles::ClearWeakness(location);
}

void AnnotateStrongRetainer(i::Address* location, const char* label) {
  i::GlobalHandles::AnnotateStrongRetainer(location, label);
}

void DisposeGlobal(i::Address* location) {
  i::GlobalHandles::Destroy(location);
}

i::Address* Eternalize(Isolate* v8_isolate, Value* value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::Tagged<i::Object> object = *Utils::OpenDirectHandle(value);
  int index = -1;
  i_isolate->eternal_handles()->Create(i_isolate, object, &index);
  return i_isolate->eternal_handles()->Get(index).location();
}

void FromJustIsNothing() {
  Utils::ApiCheck(false, "v8::FromJust", "Maybe value is Nothing");
}

void ToLocalEmpty() {
  Utils::ApiCheck(false, "v8::ToLocalChecked", "Empty MaybeLocal");
}

void InternalFieldOutOfBounds(int index) {
  Utils::ApiCheck(0 <= index && index < kInternalFieldsInWeakCallback,
                  "WeakCallbackInfo::GetInternalField",
               
"""


```