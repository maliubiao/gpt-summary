Response: My goal is to summarize the functionality of the provided C++ code snippet, part 1 of v8/src/api/api.cc, and illustrate its connection to JavaScript.

**Thinking Process:**

1. **Identify the Core Purpose:** The filename `api.cc` strongly suggests this file defines the interface between the V8 JavaScript engine's internal implementation and the external world (embedders). The `#include "src/api/api.h"` confirms this.

2. **Scan for Key V8 Concepts:**  I'll look for keywords and class names that are central to V8's API and JavaScript execution. These include:
    * `Isolate`: The fundamental independent instance of the V8 engine.
    * `Context`: Represents a JavaScript execution environment.
    * `HandleScope`: Manages the lifetime of V8 objects within a C++ scope.
    * `Template` (ObjectTemplate, FunctionTemplate): Mechanisms for defining the structure and behavior of JavaScript objects and functions in C++.
    * `FunctionCallback`:  The type of C++ function that can be called from JavaScript.
    * `Value`: The base class for all JavaScript values in the V8 API.
    * `String`, `Number`, `Boolean`, `Object`, `Function`:  Represent JavaScript primitive types and objects.
    * `SnapshotCreator`: For creating snapshots of the V8 heap.
    * `Extension`:  Allows embedding custom C++ functionality into V8.
    * Error Handling (`FatalProcessOutOfMemory`, `ReportApiFailure`, `ReportOOMFailure`):  Mechanisms for reporting and handling critical errors.

3. **Analyze Sections and Functionalities:** I will go through the code block by block, noting the purpose of different sections:
    * **Includes:**  A large number of header files point to the wide range of V8's internal functionalities that this API layer interacts with (heap management, execution, compilation, debugging, etc.).
    * **Error Handling:** The code defines how V8 reacts to out-of-memory situations and other fatal errors. The `g_oom_error_callback` suggests a way for embedders to customize this.
    * **Snapshotting:** The `SnapshotCreator` class is used for creating and managing snapshots of the V8 heap, a crucial optimization for startup time.
    * **ArrayBuffer Allocation:** The code handles allocation of memory for `ArrayBuffer`s, potentially with sandbox considerations.
    * **Extensions:**  The `Extension` and `RegisteredExtension` classes allow embedding custom C++ code into the V8 environment.
    * **Resource Constraints:**  This section deals with setting limits on memory usage.
    * **Handles and Scopes:**  `HandleScope`, `EscapableHandleScope`, and `SealHandleScope` are fundamental for managing the lifetime of V8 objects in the C++ API and preventing memory leaks.
    * **Templates (ObjectTemplate and FunctionTemplate):** This is a significant portion. The code defines how to create templates for JavaScript objects and functions, including setting properties, methods, accessors, and prototypes.
    * **Context Management:**  Functions like `Enter` and `Exit` manage the execution context. `GetEmbedderData` and `SetEmbedderData` allow associating embedder-specific data with contexts.

4. **Identify JavaScript Relationships:** For each V8 API element, I will think about its direct counterpart or how it manifests in JavaScript:
    * `Isolate`:  No direct JavaScript equivalent, but the entire JavaScript execution happens within an isolate.
    * `Context`:  Corresponds to a global scope in JavaScript (the `window` object in browsers, or the global object in Node.js).
    * `HandleScope`:  Doesn't have a direct JS equivalent, it's a C++ construct for memory management within the API.
    * `ObjectTemplate`: Used to define the "class" or structure of JavaScript objects created using a constructor function.
    * `FunctionTemplate`:  Used to create constructor functions in JavaScript or to bind C++ functions to JavaScript.
    * `FunctionCallback`:  The C++ function that gets called when a JavaScript function (created from a `FunctionTemplate`) is invoked.
    * `Value`:  Represents any JavaScript value (number, string, object, function, etc.).
    * `String`, `Number`, `Boolean`, `Object`, `Function`: Direct JavaScript types.
    * `Snapshot`: Used for faster startup by serializing the initial state of the V8 heap.
    * `Extension`:  Allows you to provide custom JavaScript functions and objects implemented in C++.

5. **Construct JavaScript Examples:** I will create simple JavaScript code snippets that demonstrate how the C++ functionalities exposed by this API are used:
    * Creating objects based on `ObjectTemplate`.
    * Defining constructor functions using `FunctionTemplate`.
    * Calling C++ functions bound through `FunctionTemplate`.
    * Setting properties and accessors.

6. **Summarize Functionality:**  Based on the analysis, I will write a concise summary of the file's purpose.

7. **Review and Refine:** I'll review the summary and examples for clarity, accuracy, and completeness. I'll ensure the examples are simple and directly illustrate the C++ API's effect on JavaScript behavior. I will also emphasize that this file is *part* of the larger V8 API.

**(Self-Correction during the process):**

* Initially, I might focus too much on low-level details like memory management. I need to shift the focus to the *user-facing* functionalities and their impact on JavaScript.
* I might need to clarify the distinction between `ObjectTemplate` and `FunctionTemplate`. `FunctionTemplate` is used to create constructor functions, which in turn use an `ObjectTemplate` to define the structure of the created objects.
*  I should ensure the JavaScript examples are simple and directly relate to the C++ code being discussed in *this specific part* of the file.

By following these steps, I can effectively analyze the C++ code and explain its functionality and relationship to JavaScript in a clear and understandable way.
This is the first part of the `v8/src/api/api.cc` file, and it primarily focuses on **defining core V8 API functionalities and data structures that bridge the gap between the C++ V8 engine and embedders (applications that use V8).**  It sets the foundation for interacting with the JavaScript engine from C++.

Here's a breakdown of its functionality:

**Core V8 Concepts and Initialization:**

* **Includes:**  It includes a vast array of V8 internal headers (`src/...`) and public API headers (`include/v8-*.h`). This signifies that this file acts as a central point for exposing various V8 functionalities.
* **Error Handling:** It defines how V8 handles out-of-memory errors (`FatalProcessOutOfMemory`) and API usage errors (`ReportApiFailure`, `ReportOOMFailure`). This includes mechanisms for reporting these errors and potentially allowing embedders to handle them.
* **Snapshotting:** It introduces the `SnapshotCreator` class, which is crucial for creating snapshots of the V8 heap. Snapshots allow for faster startup times by pre-initializing the engine.
* **ArrayBuffer Allocation:** It provides a custom `ArrayBufferAllocator`, especially relevant when sandboxing is enabled, to control how `ArrayBuffer` memory is allocated.
* **Extensions:** It defines the `Extension` and `RegisteredExtension` classes, enabling embedders to register custom C++ code that can be exposed to JavaScript.
* **Resource Constraints:** It defines the `ResourceConstraints` class, allowing embedders to configure memory limits and other resource settings for the V8 engine.

**Fundamental API Building Blocks:**

* **Handles and Scopes:** It lays the groundwork for V8's handle system with `HandleScope`, `EscapableHandleScope`, and `SealHandleScope`. These are essential for managing the lifetime of V8 objects in the C++ API and preventing memory leaks.
* **Context Management:** It defines the `Context` class, representing a JavaScript execution environment. It includes functions like `Enter` and `Exit` for managing the current execution context and methods to store embedder-specific data within a context (`GetEmbedderData`, `SetEmbedderData`).
* **Templates (ObjectTemplate and FunctionTemplate):**  A significant portion of this part focuses on `Template`, `ObjectTemplate`, and `FunctionTemplate`. These are the primary mechanisms for defining the structure and behavior of JavaScript objects and functions within the C++ API. It includes functions to:
    * Set properties (data and accessors) on templates.
    * Set prototypes for functions.
    * Define how functions are called (`SetCallHandler`).
    * Create instance templates for function constructors.
    * Set class names and other attributes for functions.

**Relationship to JavaScript (with examples):**

This file directly enables the creation and manipulation of JavaScript constructs from C++. Here's how some of the defined elements relate to JavaScript:

* **`Context`:** Represents a JavaScript global scope.

   ```javascript
   // In JavaScript, this represents the global object (window in browsers, global in Node.js).
   // In C++, you would obtain a Context object to run JavaScript code.
   ```

* **`ObjectTemplate`:** Used to define the "shape" of JavaScript objects.

   ```javascript
   // In JavaScript, you might create objects like this:
   const myObject = {
       name: "Example",
       value: 10
   };

   // In C++, you'd use an ObjectTemplate to define that 'myObject' has 'name' and 'value' properties.
   ```

* **`FunctionTemplate`:** Used to create JavaScript constructor functions or to bind C++ functions to JavaScript.

   ```javascript
   // In JavaScript, a constructor function:
   function MyClass(name) {
       this.name = name;
   }
   MyClass.prototype.greet = function() {
       console.log("Hello, " + this.name);
   };
   const instance = new MyClass("World");
   instance.greet(); // Output: Hello, World

   // In C++, you'd use a FunctionTemplate to create 'MyClass' and potentially bind the 'greet' method to a C++ function.
   ```

* **`FunctionCallback`:** The C++ function that gets called when a JavaScript function created from a `FunctionTemplate` is invoked.

   ```javascript
   // If you bind a C++ function to a JavaScript function using FunctionTemplate,
   // the FunctionCallback in C++ is what gets executed when the JavaScript function is called.
   function myFunction() {
       // This JavaScript call would trigger a corresponding FunctionCallback in C++.
   }
   myFunction();
   ```

* **`Template::Set`:** Allows setting properties on JavaScript objects (defined by an `ObjectTemplate`).

   ```javascript
   // In JavaScript:
   const obj = {};
   obj.propertyName = "some value";

   // In C++, using a Template, you can predefine the 'propertyName' on objects created from that template.
   ```

* **`Template::SetAccessorProperty`:** Enables defining getter and setter functions for JavaScript object properties.

   ```javascript
   // In JavaScript:
   const obj = {
       _age: 0,
       get age() {
           return this._age;
       },
       set age(value) {
           this._age = value;
       }
   };
   obj.age = 25;
   console.log(obj.age); // Output: 25

   // In C++, you'd use SetAccessorProperty on a Template to define the 'age' getter and setter using C++ functions.
   ```

**In summary, this first part of `api.cc` lays the fundamental groundwork for embedders to:**

* **Initialize and configure the V8 engine.**
* **Create and manage JavaScript execution environments (Contexts).**
* **Define the structure and behavior of JavaScript objects and functions using Templates.**
* **Bind C++ functions to JavaScript for extending its functionality.**
* **Handle errors and manage the lifecycle of V8 objects.**

It's the essential entry point for interacting with V8 from a C++ application and sets the stage for more advanced API functionalities in the subsequent parts of the file.

Prompt: 
```
这是目录为v8/src/api/api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共8部分，请归纳一下它的功能

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
                  "Internal field out of bounds");
}

}  // namespace api_internal

// --- H a n d l e s ---

HandleScope::HandleScope(Isolate* v8_isolate) { Initialize(v8_isolate); }

void HandleScope::Initialize(Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  // We do not want to check the correct usage of the Locker class all over the
  // place, so we do it only here: Without a HandleScope, an embedder can do
  // almost nothing, so it is enough to check in this central place.
  // We make an exception if the serializer is enabled, which means that the
  // Isolate is exclusively used to create a snapshot.
  Utils::ApiCheck(!i_isolate->was_locker_ever_used() ||
                      i_isolate->thread_manager()->IsLockedByCurrentThread() ||
                      i_isolate->serializer_enabled(),
                  "HandleScope::HandleScope",
                  "Entering the V8 API without proper locking in place");
  i::HandleScopeData* current = i_isolate->handle_scope_data();
  i_isolate_ = i_isolate;
  prev_next_ = current->next;
  prev_limit_ = current->limit;
  current->level++;
#ifdef V8_ENABLE_CHECKS
  scope_level_ = current->level;
#endif
}

HandleScope::~HandleScope() {
#ifdef V8_ENABLE_CHECKS
  CHECK_EQ(scope_level_, i_isolate_->handle_scope_data()->level);
#endif
  i::HandleScope::CloseScope(i_isolate_, prev_next_, prev_limit_);
}

void* HandleScope::operator new(size_t) { base::OS::Abort(); }
void* HandleScope::operator new[](size_t) { base::OS::Abort(); }
void HandleScope::operator delete(void*, size_t) { base::OS::Abort(); }
void HandleScope::operator delete[](void*, size_t) { base::OS::Abort(); }

int HandleScope::NumberOfHandles(Isolate* v8_isolate) {
  return i::HandleScope::NumberOfHandles(
      reinterpret_cast<i::Isolate*>(v8_isolate));
}

i::Address* HandleScope::CreateHandle(i::Isolate* i_isolate, i::Address value) {
  return i::HandleScope::CreateHandle(i_isolate, value);
}

#ifdef V8_ENABLE_DIRECT_HANDLE

i::Address* HandleScope::CreateHandleForCurrentIsolate(i::Address value) {
  i::Isolate* i_isolate = i::Isolate::Current();
  return i::HandleScope::CreateHandle(i_isolate, value);
}

#endif  // V8_ENABLE_DIRECT_HANDLE

EscapableHandleScopeBase::EscapableHandleScopeBase(Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  escape_slot_ = CreateHandle(
      i_isolate, i::ReadOnlyRoots(i_isolate).the_hole_value().ptr());
  Initialize(v8_isolate);
}

i::Address* EscapableHandleScopeBase::EscapeSlot(i::Address* escape_value) {
  DCHECK_NOT_NULL(escape_value);
  DCHECK(i::IsTheHole(i::Tagged<i::Object>(*escape_slot_),
                      reinterpret_cast<i::Isolate*>(GetIsolate())));
  *escape_slot_ = *escape_value;
  return escape_slot_;
}

SealHandleScope::SealHandleScope(Isolate* v8_isolate)
    : i_isolate_(reinterpret_cast<i::Isolate*>(v8_isolate)) {
  i::HandleScopeData* current = i_isolate_->handle_scope_data();
  prev_limit_ = current->limit;
  current->limit = current->next;
  prev_sealed_level_ = current->sealed_level;
  current->sealed_level = current->level;
}

SealHandleScope::~SealHandleScope() {
  i::HandleScopeData* current = i_isolate_->handle_scope_data();
  DCHECK_EQ(current->next, current->limit);
  current->limit = prev_limit_;
  DCHECK_EQ(current->level, current->sealed_level);
  current->sealed_level = prev_sealed_level_;
}

bool Data::IsModule() const {
  return i::IsModule(*Utils::OpenDirectHandle(this));
}
bool Data::IsFixedArray() const {
  return i::IsFixedArray(*Utils::OpenDirectHandle(this));
}

bool Data::IsValue() const {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::Object> self = *Utils::OpenDirectHandle(this);
  if (i::IsSmi(self)) return true;
  i::Tagged<i::HeapObject> heap_object = i::Cast<i::HeapObject>(self);
  DCHECK(!IsTheHole(heap_object));
  if (i::IsSymbol(heap_object)) {
    return !i::Cast<i::Symbol>(heap_object)->is_private();
  }
  return IsPrimitiveHeapObject(heap_object) || IsJSReceiver(heap_object);
}

bool Data::IsPrivate() const {
  return i::IsPrivateSymbol(*Utils::OpenDirectHandle(this));
}

bool Data::IsObjectTemplate() const {
  return i::IsObjectTemplateInfo(*Utils::OpenDirectHandle(this));
}

bool Data::IsFunctionTemplate() const {
  return i::IsFunctionTemplateInfo(*Utils::OpenDirectHandle(this));
}

bool Data::IsContext() const {
  return i::IsContext(*Utils::OpenDirectHandle(this));
}

void Context::Enter() {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::NativeContext> env = *Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = env->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScopeImplementer* impl = i_isolate->handle_scope_implementer();
  impl->EnterContext(env);
  impl->SaveContext(i_isolate->context());
  i_isolate->set_context(env);
}

void Context::Exit() {
  auto env = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = env->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScopeImplementer* impl = i_isolate->handle_scope_implementer();
  if (!Utils::ApiCheck(impl->LastEnteredContextWas(*env), "v8::Context::Exit()",
                       "Cannot exit non-entered context")) {
    return;
  }
  impl->LeaveContext();
  i_isolate->set_context(impl->RestoreContext());
}

Context::BackupIncumbentScope::BackupIncumbentScope(
    Local<Context> backup_incumbent_context)
    : backup_incumbent_context_(backup_incumbent_context) {
  DCHECK(!backup_incumbent_context_.IsEmpty());

  auto env = Utils::OpenDirectHandle(*backup_incumbent_context_);
  i::Isolate* i_isolate = env->GetIsolate();

  js_stack_comparable_address_ =
      i::SimulatorStack::RegisterJSStackComparableAddress(i_isolate);

  prev_ = i_isolate->top_backup_incumbent_scope();
  i_isolate->set_top_backup_incumbent_scope(this);
  // Enforce slow incumbent computation in order to make it find this
  // BackupIncumbentScope.
  i_isolate->clear_topmost_script_having_context();
}

Context::BackupIncumbentScope::~BackupIncumbentScope() {
  auto env = Utils::OpenDirectHandle(*backup_incumbent_context_);
  i::Isolate* i_isolate = env->GetIsolate();

  i::SimulatorStack::UnregisterJSStackComparableAddress(i_isolate);

  i_isolate->set_top_backup_incumbent_scope(prev_);
}

static_assert(i::Internals::kEmbedderDataSlotSize == i::kEmbedderDataSlotSize);
static_assert(i::Internals::kEmbedderDataSlotExternalPointerOffset ==
              i::EmbedderDataSlot::kExternalPointerOffset);

static i::Handle<i::EmbedderDataArray> EmbedderDataFor(Context* context,
                                                       int index, bool can_grow,
                                                       const char* location) {
  auto env = Utils::OpenDirectHandle(context);
  i::Isolate* i_isolate = env->GetIsolate();
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  bool ok = Utils::ApiCheck(i::IsNativeContext(*env), location,
                            "Not a native context") &&
            Utils::ApiCheck(index >= 0, location, "Negative index");
  if (!ok) return i::Handle<i::EmbedderDataArray>();
  // TODO(ishell): remove cast once embedder_data slot has a proper type.
  i::Handle<i::EmbedderDataArray> data(
      i::Cast<i::EmbedderDataArray>(env->embedder_data()), i_isolate);
  if (index < data->length()) return data;
  if (!Utils::ApiCheck(can_grow && index < i::EmbedderDataArray::kMaxLength,
                       location, "Index too large")) {
    return i::Handle<i::EmbedderDataArray>();
  }
  data = i::EmbedderDataArray::EnsureCapacity(i_isolate, data, index);
  env->set_embedder_data(*data);
  return data;
}

uint32_t Context::GetNumberOfEmbedderDataFields() {
  auto context = Utils::OpenDirectHandle(this);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(context->GetIsolate());
  Utils::ApiCheck(i::IsNativeContext(*context),
                  "Context::GetNumberOfEmbedderDataFields",
                  "Not a native context");
  // TODO(ishell): remove cast once embedder_data slot has a proper type.
  return static_cast<uint32_t>(
      i::Cast<i::EmbedderDataArray>(context->embedder_data())->length());
}

v8::Local<v8::Value> Context::SlowGetEmbedderData(int index) {
  const char* location = "v8::Context::GetEmbedderData()";
  i::Handle<i::EmbedderDataArray> data =
      EmbedderDataFor(this, index, false, location);
  if (data.is_null()) return Local<Value>();
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  return Utils::ToLocal(i::direct_handle(
      i::EmbedderDataSlot(*data, index).load_tagged(), i_isolate));
}

void Context::SetEmbedderData(int index, v8::Local<Value> value) {
  const char* location = "v8::Context::SetEmbedderData()";
  i::Handle<i::EmbedderDataArray> data =
      EmbedderDataFor(this, index, true, location);
  if (data.is_null()) return;
  auto val = Utils::OpenDirectHandle(*value);
  i::EmbedderDataSlot::store_tagged(*data, index, *val);
  DCHECK_EQ(*Utils::OpenDirectHandle(*value),
            *Utils::OpenDirectHandle(*GetEmbedderData(index)));
}

void* Context::SlowGetAlignedPointerFromEmbedderData(int index) {
  const char* location = "v8::Context::GetAlignedPointerFromEmbedderData()";
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  i::HandleScope handle_scope(i_isolate);
  i::Handle<i::EmbedderDataArray> data =
      EmbedderDataFor(this, index, false, location);
  if (data.is_null()) return nullptr;
  void* result;
  Utils::ApiCheck(
      i::EmbedderDataSlot(*data, index).ToAlignedPointer(i_isolate, &result),
      location, "Pointer is not aligned");
  return result;
}

void Context::SetAlignedPointerInEmbedderData(int index, void* value) {
  const char* location = "v8::Context::SetAlignedPointerInEmbedderData()";
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  i::DirectHandle<i::EmbedderDataArray> data =
      EmbedderDataFor(this, index, true, location);
  bool ok = i::EmbedderDataSlot(*data, index)
                .store_aligned_pointer(i_isolate, *data, value);
  Utils::ApiCheck(ok, location, "Pointer is not aligned");
  DCHECK_EQ(value, GetAlignedPointerFromEmbedderData(index));
}

// --- T e m p l a t e ---

void Template::Set(v8::Local<Name> name, v8::Local<Data> value,
                   v8::PropertyAttribute attribute) {
  auto templ = Utils::OpenHandle(this);
  i::Isolate* i_isolate = templ->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  auto value_obj = Utils::OpenHandle(*value);

  Utils::ApiCheck(!IsJSReceiver(*value_obj) || IsTemplateInfo(*value_obj),
                  "v8::Template::Set",
                  "Invalid value, must be a primitive or a Template");

  // The template cache only performs shallow clones, if we set an
  // ObjectTemplate as a property value then we can not cache the receiver
  // template.
  if (i::IsObjectTemplateInfo(*value_obj)) {
    templ->set_serial_number(i::TemplateInfo::kDoNotCache);
  }

  i::ApiNatives::AddDataProperty(i_isolate, templ, Utils::OpenHandle(*name),
                                 value_obj,
                                 static_cast<i::PropertyAttributes>(attribute));
}

void Template::SetPrivate(v8::Local<Private> name, v8::Local<Data> value,
                          v8::PropertyAttribute attribute) {
  Set(Local<Name>::Cast(name), value, attribute);
}

void Template::SetAccessorProperty(v8::Local<v8::Name> name,
                                   v8::Local<FunctionTemplate> getter,
                                   v8::Local<FunctionTemplate> setter,
                                   v8::PropertyAttribute attribute) {
  auto templ = Utils::OpenHandle(this);
  auto i_isolate = templ->GetIsolateChecked();
  i::Handle<i::FunctionTemplateInfo> i_getter;
  if (!getter.IsEmpty()) {
    i_getter = Utils::OpenHandle(*getter);
    Utils::ApiCheck(i_getter->has_callback(i_isolate),
                    "v8::Template::SetAccessorProperty",
                    "Getter must have a call handler");
  }
  i::Handle<i::FunctionTemplateInfo> i_setter;
  if (!setter.IsEmpty()) {
    i_setter = Utils::OpenHandle(*setter);
    Utils::ApiCheck(i_setter->has_callback(i_isolate),
                    "v8::Template::SetAccessorProperty",
                    "Setter must have a call handler");
  }
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  DCHECK(!name.IsEmpty());
  DCHECK(!getter.IsEmpty() || !setter.IsEmpty());
  i::HandleScope scope(i_isolate);
  i::ApiNatives::AddAccessorProperty(
      i_isolate, templ, Utils::OpenHandle(*name), i_getter, i_setter,
      static_cast<i::PropertyAttributes>(attribute));
}

// --- F u n c t i o n   T e m p l a t e ---

Local<ObjectTemplate> FunctionTemplate::PrototypeTemplate() {
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = self->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::DirectHandle<i::HeapObject> heap_obj(self->GetPrototypeTemplate(),
                                          i_isolate);
  if (i::IsUndefined(*heap_obj, i_isolate)) {
    // Do not cache prototype objects.
    constexpr bool do_not_cache = true;
    i::Handle<i::ObjectTemplateInfo> proto_template =
        i_isolate->factory()->NewObjectTemplateInfo(
            i::Handle<i::FunctionTemplateInfo>(), do_not_cache);
    i::FunctionTemplateInfo::SetPrototypeTemplate(i_isolate, self,
                                                  proto_template);
    return Utils::ToLocal(proto_template);
  }
  return ToApiHandle<ObjectTemplate>(heap_obj);
}

void FunctionTemplate::SetPrototypeProviderTemplate(
    Local<FunctionTemplate> prototype_provider) {
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = self->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::DirectHandle<i::FunctionTemplateInfo> result =
      Utils::OpenDirectHandle(*prototype_provider);
  Utils::ApiCheck(i::IsUndefined(self->GetPrototypeTemplate(), i_isolate),
                  "v8::FunctionTemplate::SetPrototypeProviderTemplate",
                  "Protoype must be undefined");
  Utils::ApiCheck(i::IsUndefined(self->GetParentTemplate(), i_isolate),
                  "v8::FunctionTemplate::SetPrototypeProviderTemplate",
                  "Prototype provider must be empty");
  i::FunctionTemplateInfo::SetPrototypeProviderTemplate(i_isolate, self,
                                                        result);
}

namespace {
static void EnsureNotPublished(i::DirectHandle<i::FunctionTemplateInfo> info,
                               const char* func) {
  DCHECK_IMPLIES(info->instantiated(), info->published());
  Utils::ApiCheck(!info->published(), func,
                  "FunctionTemplate already instantiated");
}

i::Handle<i::FunctionTemplateInfo> FunctionTemplateNew(
    i::Isolate* i_isolate, FunctionCallback callback, v8::Local<Value> data,
    v8::Local<Signature> signature, int length, ConstructorBehavior behavior,
    bool do_not_cache,
    v8::Local<Private> cached_property_name = v8::Local<Private>(),
    SideEffectType side_effect_type = SideEffectType::kHasSideEffect,
    const MemorySpan<const CFunction>& c_function_overloads = {}) {
  i::Handle<i::FunctionTemplateInfo> obj =
      i_isolate->factory()->NewFunctionTemplateInfo(length, do_not_cache);
  {
    // Disallow GC until all fields of obj have acceptable types.
    i::DisallowGarbageCollection no_gc;
    i::Tagged<i::FunctionTemplateInfo> raw = *obj;
    if (!signature.IsEmpty()) {
      raw->set_signature(*Utils::OpenDirectHandle(*signature));
    }
    if (!cached_property_name.IsEmpty()) {
      raw->set_cached_property_name(
          *Utils::OpenDirectHandle(*cached_property_name));
    }
    if (behavior == ConstructorBehavior::kThrow) {
      raw->set_remove_prototype(true);
    }
  }
  if (callback != nullptr) {
    Utils::ToLocal(obj)->SetCallHandler(callback, data, side_effect_type,
                                        c_function_overloads);
  }
  return obj;
}
}  // namespace

void FunctionTemplate::Inherit(v8::Local<FunctionTemplate> value) {
  auto info = Utils::OpenHandle(this);
  EnsureNotPublished(info, "v8::FunctionTemplate::Inherit");
  i::Isolate* i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  Utils::ApiCheck(
      i::IsUndefined(info->GetPrototypeProviderTemplate(), i_isolate),
      "v8::FunctionTemplate::Inherit", "Protoype provider must be empty");
  i::FunctionTemplateInfo::SetParentTemplate(i_isolate, info,
                                             Utils::OpenHandle(*value));
}

Local<FunctionTemplate> FunctionTemplate::New(
    Isolate* v8_isolate, FunctionCallback callback, v8::Local<Value> data,
    v8::Local<Signature> signature, int length, ConstructorBehavior behavior,
    SideEffectType side_effect_type, const CFunction* c_function,
    uint16_t instance_type, uint16_t allowed_receiver_instance_type_range_start,
    uint16_t allowed_receiver_instance_type_range_end) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  // Changes to the environment cannot be captured in the snapshot. Expect no
  // function templates when the isolate is created for serialization.
  API_RCS_SCOPE(i_isolate, FunctionTemplate, New);

  if (!Utils::ApiCheck(
          !c_function || behavior == ConstructorBehavior::kThrow,
          "FunctionTemplate::New",
          "Fast API calls are not supported for constructor functions")) {
    return Local<FunctionTemplate>();
  }

  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::FunctionTemplateInfo> templ = FunctionTemplateNew(
      i_isolate, callback, data, signature, length, behavior, false,
      Local<Private>(), side_effect_type,
      c_function ? MemorySpan<const CFunction>{c_function, 1}
                 : MemorySpan<const CFunction>{});

  if (instance_type) {
    if (!Utils::ApiCheck(
            base::IsInRange(static_cast<int>(instance_type),
                            i::Internals::kFirstEmbedderJSApiObjectType,
                            i::Internals::kLastEmbedderJSApiObjectType),
            "FunctionTemplate::New",
            "instance_type is outside the range of valid JSApiObject types")) {
      return Local<FunctionTemplate>();
    }
    templ->SetInstanceType(instance_type);
  }

  if (allowed_receiver_instance_type_range_start ||
      allowed_receiver_instance_type_range_end) {
    if (!Utils::ApiCheck(i::Internals::kFirstEmbedderJSApiObjectType <=
                                 allowed_receiver_instance_type_range_start &&
                             allowed_receiver_instance_type_range_start <=
                                 allowed_receiver_instance_type_range_end &&
                             allowed_receiver_instance_type_range_end <=
                                 i::Internals::kLastEmbedderJSApiObjectType,
                         "FunctionTemplate::New",
                         "allowed receiver instance type range is outside the "
                         "range of valid JSApiObject types")) {
      return Local<FunctionTemplate>();
    }
    templ->SetAllowedReceiverInstanceTypeRange(
        allowed_receiver_instance_type_range_start,
        allowed_receiver_instance_type_range_end);
  }
  return Utils::ToLocal(templ);
}

Local<FunctionTemplate> FunctionTemplate::NewWithCFunctionOverloads(
    Isolate* v8_isolate, FunctionCallback callback, v8::Local<Value> data,
    v8::Local<Signature> signature, int length, ConstructorBehavior behavior,
    SideEffectType side_effect_type,
    const MemorySpan<const CFunction>& c_function_overloads) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, FunctionTemplate, New);

  // Check that all overloads of the fast API callback have different numbers of
  // parameters. Since the number of overloads is supposed to be small, just
  // comparing them with each other should be fine.
  for (size_t i = 0; i < c_function_overloads.size(); ++i) {
    for (size_t j = i + 1; j < c_function_overloads.size(); ++j) {
      CHECK_NE(c_function_overloads.data()[i].ArgumentCount(),
               c_function_overloads.data()[j].ArgumentCount());
    }
  }

  if (!Utils::ApiCheck(
          c_function_overloads.empty() ||
              behavior == ConstructorBehavior::kThrow,
          "FunctionTemplate::NewWithCFunctionOverloads",
          "Fast API calls are not supported for constructor functions")) {
    return Local<FunctionTemplate>();
  }

  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::FunctionTemplateInfo> templ = FunctionTemplateNew(
      i_isolate, callback, data, signature, length, behavior, false,
      Local<Private>(), side_effect_type, c_function_overloads);
  return Utils::ToLocal(templ);
}

Local<FunctionTemplate> FunctionTemplate::NewWithCache(
    Isolate* v8_isolate, FunctionCallback callback,
    Local<Private> cache_property, Local<Value> data,
    Local<Signature> signature, int length, SideEffectType side_effect_type) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, FunctionTemplate, NewWithCache);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::FunctionTemplateInfo> templ = FunctionTemplateNew(
      i_isolate, callback, data, signature, length, ConstructorBehavior::kAllow,
      false, cache_property, side_effect_type);
  return Utils::ToLocal(templ);
}

Local<Signature> Signature::New(Isolate* v8_isolate,
                                Local<FunctionTemplate> receiver) {
  return Local<Signature>::Cast(receiver);
}

#define SET_FIELD_WRAPPED(i_isolate, obj, setter, cdata, tag) \
  do {                                                        \
    i::DirectHandle<i::UnionOf<i::Smi, i::Foreign>> foreign = \
        FromCData<tag>(i_isolate, cdata);                     \
    (obj)->setter(*foreign);                                  \
  } while (false)

void FunctionTemplate::SetCallHandler(
    FunctionCallback callback, v8::Local<Value> data,
    SideEffectType side_effect_type,
    const MemorySpan<const CFunction>& c_function_overloads) {
  auto info = Utils::OpenHandle(this);
  EnsureNotPublished(info, "v8::FunctionTemplate::SetCallHandler");
  i::Isolate* i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  info->set_has_side_effects(side_effect_type !=
                             SideEffectType::kHasNoSideEffect);
  info->set_callback(i_isolate, reinterpret_cast<i::Address>(callback));
  if (data.IsEmpty()) {
    data = v8::Undefined(reinterpret_cast<v8::Isolate*>(i_isolate));
  }
  // "Release" callback and callback data fields.
  info->set_callback_data(*Utils::OpenDirectHandle(*data), kReleaseStore);

  if (!c_function_overloads.empty()) {
    // Stores the data for a sequence of CFunction overloads into a single
    // FixedArray, as [address_0, signature_0, ... address_n-1, signature_n-1].
    i::DirectHandle<i::FixedArray> function_overloads =
        i_isolate->factory()->NewFixedArray(static_cast<int>(
            c_function_overloads.size() *
            i::FunctionTemplateInfo::kFunctionOverloadEntrySize));
    int function_count = static_cast<int>(c_function_overloads.size());
    for (int i = 0; i < function_count; i++) {
      const CFunction& c_function = c_function_overloads.data()[i];
      i::DirectHandle<i::Object> address = FromCData<internal::kCFunctionTag>(
          i_isolate, c_function.GetAddress());
      function_overloads->set(
          i::FunctionTemplateInfo::kFunctionOverloadEntrySize * i, *address);
      i::DirectHandle<i::Object> signature =
          FromCData<internal::kCFunctionInfoTag>(i_isolate,
                                                 c_function.GetTypeInfo());
      function_overloads->set(
          i::FunctionTemplateInfo::kFunctionOverloadEntrySize * i + 1,
          *signature);
    }
    i::FunctionTemplateInfo::SetCFunctionOverloads(i_isolate, info,
                                                   function_overloads);
  }
}

namespace {

template <typename Getter, typename Setter>
i::Handle<i::AccessorInfo> MakeAccessorInfo(i::Isolate* i_isolate,
                                            v8::Local<Name> name, Getter getter,
                                            Setter setter,
                                            v8::Local<Value> data,
                                            bool replace_on_access) {
  i::Handle<i::AccessorInfo> obj = i_isolate->factory()->NewAccessorInfo();
  obj->set_getter(i_isolate, reinterpret_cast<i::Address>(getter));
  DCHECK_IMPLIES(replace_on_access, setter == nullptr);
  if (setter == nullptr) {
    setter = reinterpret_cast<Setter>(&i::Accessors::ReconfigureToDataProperty);
  }
  obj->set_setter(i_isolate, reinterpret_cast<i::Address>(setter));

  auto accessor_name = Utils::OpenHandle(*name);
  if (!IsUniqueName(*accessor_name)) {
    accessor_name = i_isolate->factory()->InternalizeString(
        i::Cast<i::String>(accessor_name));
  }
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::AccessorInfo> raw_obj = *obj;
  if (data.IsEmpty()) {
    raw_obj->set_data(i::ReadOnlyRoots(i_isolate).undefined_value());
  } else {
    raw_obj->set_data(*Utils::OpenDirectHandle(*data));
  }
  raw_obj->set_name(*accessor_name);
  raw_obj->set_replace_on_access(replace_on_access);
  raw_obj->set_initial_property_attributes(i::NONE);
  return obj;
}

}  // namespace

Local<ObjectTemplate> FunctionTemplate::InstanceTemplate() {
  auto constructor = Utils::OpenHandle(this, true);
  if (!Utils::ApiCheck(!constructor.is_null(),
                       "v8::FunctionTemplate::InstanceTemplate()",
                       "Reading from empty handle")) {
    return Local<ObjectTemplate>();
  }
  i::Isolate* i_isolate = constructor->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto maybe_templ = constructor->GetInstanceTemplate();
  if (!i::IsUndefined(maybe_templ, i_isolate)) {
    return Utils::ToLocal(i::direct_handle(
        i::Cast<i::ObjectTemplateInfo>(maybe_templ), i_isolate));
  }
  constexpr bool do_not_cache = false;
  i::Handle<i::ObjectTemplateInfo> templ =
      i_isolate->factory()->NewObjectTemplateInfo(constructor, do_not_cache);
  i::FunctionTemplateInfo::SetInstanceTemplate(i_isolate, constructor, templ);
  return Utils::ToLocal(templ);
}

void FunctionTemplate::SetLength(int length) {
  auto info = Utils::OpenDirectHandle(this);
  EnsureNotPublished(info, "v8::FunctionTemplate::SetLength");
  i::Isolate* i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  info->set_length(length);
}

void FunctionTemplate::SetClassName(Local<String> name) {
  auto info = Utils::OpenDirectHandle(this);
  EnsureNotPublished(info, "v8::FunctionTemplate::SetClassName");
  i::Isolate* i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  info->set_class_name(*Utils::OpenDirectHandle(*name));
}

void FunctionTemplate::SetInterfaceName(Local<String> name) {
  auto info = Utils::OpenDirectHandle(this);
  EnsureNotPublished(info, "v8::FunctionTemplate::SetInterfaceName");
  i::Isolate* i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  info->set_interface_name(*Utils::OpenDirectHandle(*name));
}

void FunctionTemplate::SetExceptionContext(ExceptionContext context) {
  auto info = Utils::OpenDirectHandle(this);
  EnsureNotPublished(info, "v8::FunctionTemplate::SetExceptionContext");
  i::Isolate* i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  info->set_exception_context(static_cast<uint32_t>(context));
}

void FunctionTemplate::SetAcceptAnyReceiver(bool value) {
  auto info = Utils::OpenDirectHandle(this);
  EnsureNotPublished(info, "v8::FunctionTemplate::SetAcceptAnyReceiver");
  i::Isolate* i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  info->set_accept_any_receiver(value);
}

void FunctionTemplate::ReadOnlyPrototype() {
  auto info = Utils::OpenDirectHandle(this);
  EnsureNotPublished(info, "v8::FunctionTemplate::ReadOnlyPrototype");
  i::Isolate* i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  info->set_read_only_prototype(true);
}

void FunctionTemplate::RemovePrototype() {
  auto info = Utils::OpenDirectHandle(this);
  EnsureNotPublished(info, "v8::FunctionTemplate::RemovePrototype");
  i::Isolate* i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  info->set_remove_prototype(true);
}

// --- O b j e c t T e m p l a t e ---

Local<ObjectTemplate> ObjectTemplate::New(
    Isolate* v8_isolate, v8::Local<FunctionTemplate> constructor) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, ObjectTemplate, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  constexpr bool do_not_cache = false;
  i::Handle<i::ObjectTemplateInfo> obj =
      i_isolate->factory()->NewObjectTemplateInfo(
          Utils::OpenDirectHandle(*constructor, true), do_not_cache);
  return Utils::ToLocal(obj);
}

namespace {
// Ensure that the object template has a constructor.  If no
// constructor is available we create one.
i::Handle<i::FunctionTemplateInfo> EnsureConstructor(
    i::Isolate* i_isolate, ObjectTemplate* object_template) {
  i::Tagged<i::Object> obj =
      Utils::OpenDirectHandle(object_template)->constructor();
  if (!IsUndefined(obj, i_isolate)) {
    i::Tagged<i::FunctionTemplateInfo> info =
        i::Cast<i::FunctionTemplateInfo>(obj);
    return i::Handle<i::FunctionTemplateInfo>(info, i_isolate);
  }
  Local<FunctionTemplate> templ =
      FunctionTemplate::New(reinterpret_cast<Isolate*>(i_isolate));
  auto constructor = Utils::OpenHandle(*templ);
  i::FunctionTemplateInfo::SetInstanceTemplate(
      i_isolate, constructor, Utils::OpenHandle(object_template));
  Utils::OpenDirectHandle(object_template)->set_constructor(*constructor);
  return constructor;
}

template <typename Getter, typename Setter, typename Data, typename Template>
void TemplateSetAccessor(Template* template_obj, v8::Local<Name> name,
                         Getter getter, Setter setter, Data data,
                         PropertyAttribute attribute, bool replace_on_access,
                         SideEffectType getter_side_effect_type,
                         SideEffectType setter_side_effect_type) {
  auto info = Utils::OpenHandle(template_obj);
  auto i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  i::Handle<i::AccessorInfo> accessor_info = MakeAccessorInfo(
      i_isolate, name, getter, setter, data, replace_on_access);
  {
    i::DisallowGarbageCollection no_gc;
    i::Tagged<i::AccessorInfo> raw = *accessor_info;
    raw->set_initial_property_attributes(
        static_cast<i::PropertyAttributes>(attribute));
    raw->set_getter_side_effect_type(getter_side_effect_type);
    raw->set_setter_side_effect_type(setter_side_effect_type);
  }
  i::ApiNatives::AddNativeDataProperty(i_isolate, info, accessor_info);
}
}  // namespace

void Template::SetNativeDataProperty(v8::Local<Name> name,
                                     AccessorNameGetterCallback getter,
                                     AccessorNameSetterCallback setter,
                                     v8::Local<Value> data,
                                     PropertyAttribute attribute,
                                     SideEffectType getter_side_effect_type,
                                     SideEffectType setter_side_effect_type) {
  TemplateSetAccessor(this, name, getter, setter, data, attribute, false,
                      getter_side_effect_type, setter_side_effect_type);
}

void Template::SetLazyDataProperty(v8::Local<Name> name,
                                   AccessorNameGetterCallback getter,
                                   v8::Local<Value> data,
                                   PropertyAttribute attribute,
                                   SideEffectType getter_side_effect_type,
                                   SideEffectType setter_side_effect_type) {
  TemplateSetAccessor(
      this, name, getter, static_cast<AccessorNameSetterCallback>(nullptr),
      data, attribute, true, getter_side_effect_type, setter_side_effect_type);
}

void Template::SetIntrinsicDataProperty(Local<Name> name, Intrinsic intrinsic,
                                        PropertyAttribute attribute) {
  auto templ = Utils::OpenHandle(this);
  i::Isolate* i_isolate = templ->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  i::ApiNatives::AddDataProperty(i_isolate, templ, Utils::OpenH
"""


```