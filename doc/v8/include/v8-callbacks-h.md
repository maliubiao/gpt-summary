Response:
My thinking process to analyze the `v8-callbacks.h` header file goes through these stages:

1. **Initial Scan and High-Level Understanding:** I first quickly read through the file, paying attention to the `#ifndef` guard, include statements, and the namespace declaration (`namespace v8`). This tells me it's a header file defining interfaces within the V8 JavaScript engine. The `// Copyright` and license information confirm its origin. The included headers suggest dependencies on core C++ functionalities (`stddef.h`, `<functional>`, `<string>`) and V8's internal structures (`v8-data.h`, `v8-local-handle.h`, `v8-promise.h`, `v8config.h`).

2. **Identifying Key Structures and Enums:** I look for major structures (`struct`) and enumerations (`enum`). These are often the building blocks of the API defined in the header. I notice structures like `JitCodeEvent`, `OOMDetails`, and enums like `JitCodeEvent::EventType`, `GCType`, `GCCallbackFlags`, `AccessType`, `ModuleImportPhase`, and `CrashKeyId`. These give me clues about the various aspects of V8's functionality that callbacks can interact with: JIT code, garbage collection, exceptions, tracing, module loading, etc.

3. **Focusing on `using` Declarations for Callbacks:** The core of this file is the definition of callback function types using `using`. These declarations (e.g., `using JitCodeEventHandler = void (*)(const JitCodeEvent* event);`) are crucial. I systematically go through each `using` declaration, noting the function signature (return type and parameters) and the corresponding name. This gives me a list of all the different types of callbacks V8 allows embedding applications to register.

4. **Categorizing Callbacks by Functionality:**  As I list the callbacks, I start to group them based on the area of V8 they relate to. For instance, callbacks related to code generation (`JitCodeEventHandler`, `ModifyCodeGenerationFromStringsCallback`), garbage collection (`GCCallback`, `NearHeapLimitCallback`), exceptions (`UnhandledExceptionCallback`, `FatalErrorCallback`, `OOMErrorCallback`, `MessageCallback`), module loading (`HostImportModuleDynamicallyCallback`, `HostImportModuleWithPhaseDynamicallyCallback`, `HostInitializeImportMetaObjectCallback`), and so on. This categorization helps organize the information and understand the overall purpose of the file.

5. **Checking for Torque Source (`.tq`):** I specifically look for any mention of `.tq` file extensions. The prompt asks about this. In this case, there's no mention of `.tq`, so I can confidently state that this is not a Torque source file.

6. **Analyzing JavaScript Relevance and Providing Examples:**  For each callback category, I consider if and how it relates to JavaScript functionality. For example:
    * **JIT Code Events:** Directly related to how JavaScript code is compiled and executed. I can illustrate this with the concept of performance monitoring or debugging tools.
    * **Garbage Collection:** Although usually transparent to JavaScript developers, understanding GC callbacks helps understand memory management within the engine.
    * **Exceptions:**  Callbacks like `UnhandledExceptionCallback` and `MessageCallback` are directly related to how JavaScript errors are handled and reported. I can provide examples of `try...catch` and error reporting.
    * **Module Loading:** Callbacks like `HostImportModuleDynamicallyCallback` are central to JavaScript's `import()` syntax and module resolution. I can illustrate this with a simple dynamic import example.
    * **PrepareStackTraceCallback:** Directly impacts how stack traces are generated for JavaScript errors.

7. **Considering Code Logic and Providing Examples:**  For callbacks that might involve some decision-making or data transformation, I think about potential input and output scenarios. For example, `NearHeapLimitCallback` takes the current and initial heap limits as input and can return a new limit. `ModifyCodeGenerationFromStringsCallback` takes source code as input and can potentially modify it.

8. **Identifying Potential User Programming Errors:**  I think about common mistakes developers might make when interacting with these callbacks. For instance:
    * Performing allocations within GC callbacks.
    * Incorrectly handling promises in dynamic import callbacks.
    * Not understanding the lifecycle and implications of certain callbacks (e.g., crash keys).

9. **Structuring the Output:** Finally, I organize the gathered information into a clear and structured response, addressing each part of the prompt:
    * Functionality listing.
    * Torque source check.
    * JavaScript relevance with examples.
    * Code logic examples with input/output.
    * Common programming errors.

By following this detailed process, I can systematically analyze the header file, understand its purpose and the various ways it allows embedding applications to interact with the V8 JavaScript engine, and provide comprehensive answers to the given prompt.
This C++ header file, `v8/include/v8-callbacks.h`, defines a collection of **callback function types** used by the V8 JavaScript engine to interact with its embedder (the application or environment that hosts V8). It essentially provides a set of hooks that allow the embedder to:

**Core Functionality of `v8-callbacks.h`:**

* **Receive Notifications about V8 Events:**  The embedder can register functions to be called when specific events occur within V8, such as:
    * JIT code generation and movement.
    * Garbage collection start and finish.
    * Unhandled JavaScript exceptions.
    * Fatal errors and out-of-memory situations.
    * JavaScript message processing (errors, warnings).
    * Tracing events.
    * Script entry and exit.
    * Failed access checks on objects.
    * WebAssembly compilation and execution events.
    * Dynamic module imports.
    * Access to `import.meta`.
    * ShadowRealm creation.
    * Generation of stack traces.

* **Influence V8's Behavior:** Some callbacks allow the embedder to influence V8's execution:
    * Modify code generation from strings (e.g., for security or instrumentation).
    * Allow or disallow WebAssembly code generation.
    * Provide custom implementations for certain WebAssembly APIs.
    * Resolve module specifiers during dynamic imports.
    * Provide hints for function compilation.
    * Customize stack trace generation.
    * Filter ETW tracing on Windows.

* **Provide Custom Implementations:**  For features like dynamic module loading and certain WebAssembly APIs, the embedder *must* provide implementations via these callbacks.

* **Gather Performance Data:** Callbacks for JIT code events and garbage collection provide insights into V8's runtime behavior for performance monitoring and analysis.

* **Integrate with Embedder's Infrastructure:** Callbacks allow V8 to report errors, log events, and potentially request resources from the embedding environment.

**Is it a Torque source file?**

The file `v8/include/v8-callbacks.h` ends with `.h`, indicating it's a **C++ header file**. It is **not** a Torque source file, which would end with `.tq`.

**Relationship with JavaScript and Examples:**

Many of these callbacks are directly related to JavaScript features and execution. Here are some examples in JavaScript:

1. **`JitCodeEventHandler`:** This callback is triggered when JavaScript code is compiled and optimized (JITted). While you don't directly interact with this in JavaScript, its effects are fundamental to performance.

2. **`GCCallback`:** This callback is triggered during garbage collection. While JavaScript has automatic garbage collection, understanding when it happens can be relevant for performance tuning in very specific scenarios.

3. **`MessageCallback`:** This callback is invoked when a JavaScript error or warning occurs. In JavaScript, you can catch errors using `try...catch`:

   ```javascript
   try {
     // Code that might throw an error
     undefinedFunction();
   } catch (error) {
     console.error("Caught an error:", error);
   }
   ```

   The `MessageCallback` in the embedder would receive details about this error.

4. **`HostImportModuleDynamicallyCallback`:** This is crucial for the `import()` syntax in JavaScript (dynamic imports):

   ```javascript
   async function loadModule() {
     try {
       const module = await import('./my-module.js');
       module.someFunction();
     } catch (error) {
       console.error("Failed to load module:", error);
     }
   }

   loadModule();
   ```

   When the `import()` statement is encountered, V8 uses the `HostImportModuleDynamicallyCallback` to ask the embedder to actually fetch, compile, and instantiate the module.

5. **`PrepareStackTraceCallback`:** This callback allows customizing how stack traces are generated when an error occurs. In JavaScript, you can access the stack trace of an error object:

   ```javascript
   try {
     throw new Error("Something went wrong");
   } catch (error) {
     console.log(error.stack);
   }
   ```

   The `PrepareStackTraceCallback` in the embedder could modify the format or content of this `error.stack` string.

**Code Logic Inference (with Assumptions):**

Let's take the `NearHeapLimitCallback` as an example:

**Assumptions:**

* The embedder has set a `NearHeapLimitCallback`.
* The V8 heap is approaching its current limit.

**Input:**

* `data`: A pointer to user-defined data passed when the callback was set.
* `current_heap_limit`: The current maximum size of the V8 heap.
* `initial_heap_limit`: The heap limit set when the V8 isolate was created.

**Logic:**

The callback function implemented by the embedder might contain logic like this:

```c++
size_t MyNearHeapLimitCallback(void* data, size_t current_heap_limit, size_t initial_heap_limit) {
  // Check if we have enough free system memory (hypothetical).
  if (HasEnoughFreeMemory()) {
    // Increase the heap limit by a certain amount.
    return current_heap_limit + (10 * 1024 * 1024); // Increase by 10MB
  } else {
    // Indicate that the limit cannot be extended.
    return current_heap_limit;
  }
}
```

**Output:**

* **If the embedder decides to extend the limit:** The callback returns a new `size_t` value greater than `current_heap_limit`. V8 will attempt to increase the heap size to this new limit.
* **If the embedder cannot or doesn't want to extend the limit:** The callback returns `current_heap_limit`. V8 will proceed with garbage collection or potentially throw an out-of-memory error if the situation doesn't improve.

**Common User Programming Errors:**

1. **Performing Allocations in GC Callbacks:** The documentation explicitly states that allocations are **not allowed** in garbage collection callbacks (`GCCallback`). Doing so can lead to deadlocks or crashes because the garbage collector might be in a state where memory allocation is unsafe.

   **Example (Incorrect):**

   ```c++
   void MyGCCallback(v8::GCType type, v8::GCCallbackFlags flags) {
     // Potentially allocates memory by creating a V8 string
     v8::Local<v8::String> str = v8::String::NewFromUtf8(v8::Isolate::GetCurrent(), "GC Happened").ToLocalChecked();
     // ... further operations that might allocate ...
   }
   ```

2. **Incorrectly Handling Promises in `HostImportModuleDynamicallyCallback`:** This callback must return a `v8::MaybeLocal<v8::Promise>`. A common error is not creating and returning a Promise that will eventually resolve or reject with the module namespace or an error.

   **Example (Incorrect - Returning an empty MaybeLocal on success):**

   ```c++
   v8::MaybeLocal<v8::Promise> MyHostImportModuleDynamicallyCallback(
       v8::Local<v8::Context> context, v8::Local<v8::Data> host_defined_options,
       v8::Local<v8::Value> resource_name, v8::Local<v8::String> specifier,
       v8::Local<v8::FixedArray> import_attributes) {
     // ... (fetch, compile, instantiate the module) ...

     if (module_loaded_successfully) {
       // Missing: Create a Promise and resolve it with the module namespace
       return v8::MaybeLocal<v8::Promise>(); // Incorrect!
     } else {
       // ... create and reject a Promise ...
     }
   }
   ```

3. **Ignoring Error Conditions:** In callbacks like `ModifyCodeGenerationFromStringsCallback`, if the callback intends to block code generation, it should set `codegen_allowed` to `false`. Ignoring this and always returning `true` might bypass security checks.

4. **Leaking Memory in Callbacks:** If a callback allocates resources (e.g., memory, file handles), it's crucial to ensure those resources are properly released when they are no longer needed. This is especially important in callbacks that might be called repeatedly.

In summary, `v8-callbacks.h` is a vital header for embedding V8, providing a rich set of hooks for the embedder to observe and interact with the JavaScript engine's execution. Understanding these callbacks is crucial for building robust and integrated applications that leverage V8.

### 提示词
```
这是目录为v8/include/v8-callbacks.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-callbacks.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_V8_ISOLATE_CALLBACKS_H_
#define INCLUDE_V8_ISOLATE_CALLBACKS_H_

#include <stddef.h>

#include <functional>
#include <string>

#include "cppgc/common.h"
#include "v8-data.h"          // NOLINT(build/include_directory)
#include "v8-local-handle.h"  // NOLINT(build/include_directory)
#include "v8-promise.h"       // NOLINT(build/include_directory)
#include "v8config.h"         // NOLINT(build/include_directory)

#if defined(V8_OS_WIN)
struct _EXCEPTION_POINTERS;
#endif

namespace v8 {

template <typename T>
class FunctionCallbackInfo;
class Isolate;
class Message;
class Module;
class Object;
class Promise;
class ScriptOrModule;
class String;
class UnboundScript;
class Value;

/**
 * A JIT code event is issued each time code is added, moved or removed.
 *
 * \note removal events are not currently issued.
 */
struct JitCodeEvent {
  enum EventType {
    CODE_ADDED,
    CODE_MOVED,
    CODE_REMOVED,
    CODE_ADD_LINE_POS_INFO,
    CODE_START_LINE_INFO_RECORDING,
    CODE_END_LINE_INFO_RECORDING
  };
  // Definition of the code position type. The "POSITION" type means the place
  // in the source code which are of interest when making stack traces to
  // pin-point the source location of a stack frame as close as possible.
  // The "STATEMENT_POSITION" means the place at the beginning of each
  // statement, and is used to indicate possible break locations.
  enum PositionType { POSITION, STATEMENT_POSITION };

  // There are three different kinds of CodeType, one for JIT code generated
  // by the optimizing compiler, one for byte code generated for the
  // interpreter, and one for code generated from Wasm. For JIT_CODE and
  // WASM_CODE, |code_start| points to the beginning of jitted assembly code,
  // while for BYTE_CODE events, |code_start| points to the first bytecode of
  // the interpreted function.
  enum CodeType { BYTE_CODE, JIT_CODE, WASM_CODE };

  // Type of event.
  EventType type;
  CodeType code_type;
  // Start of the instructions.
  void* code_start;
  // Size of the instructions.
  size_t code_len;
  // Script info for CODE_ADDED event.
  Local<UnboundScript> script;
  // User-defined data for *_LINE_INFO_* event. It's used to hold the source
  // code line information which is returned from the
  // CODE_START_LINE_INFO_RECORDING event. And it's passed to subsequent
  // CODE_ADD_LINE_POS_INFO and CODE_END_LINE_INFO_RECORDING events.
  void* user_data;

  struct name_t {
    // Name of the object associated with the code, note that the string is not
    // zero-terminated.
    const char* str;
    // Number of chars in str.
    size_t len;
  };

  struct line_info_t {
    // PC offset
    size_t offset;
    // Code position
    size_t pos;
    // The position type.
    PositionType position_type;
  };

  struct wasm_source_info_t {
    // Source file name.
    const char* filename;
    // Length of filename.
    size_t filename_size;
    // Line number table, which maps offsets of JITted code to line numbers of
    // source file.
    const line_info_t* line_number_table;
    // Number of entries in the line number table.
    size_t line_number_table_size;
  };

  wasm_source_info_t* wasm_source_info = nullptr;

  union {
    // Only valid for CODE_ADDED.
    struct name_t name;

    // Only valid for CODE_ADD_LINE_POS_INFO
    struct line_info_t line_info;

    // New location of instructions. Only valid for CODE_MOVED.
    void* new_code_start;
  };

  Isolate* isolate;
};

/**
 * Option flags passed to the SetJitCodeEventHandler function.
 */
enum JitCodeEventOptions {
  kJitCodeEventDefault = 0,
  // Generate callbacks for already existent code.
  kJitCodeEventEnumExisting = 1
};

/**
 * Callback function passed to SetJitCodeEventHandler.
 *
 * \param event code add, move or removal event.
 */
using JitCodeEventHandler = void (*)(const JitCodeEvent* event);

// --- Garbage Collection Callbacks ---

/**
 * Applications can register callback functions which will be called before and
 * after certain garbage collection operations.  Allocations are not allowed in
 * the callback functions, you therefore cannot manipulate objects (set or
 * delete properties for example) since it is possible such operations will
 * result in the allocation of objects.
 * TODO(v8:12612): Deprecate kGCTypeMinorMarkSweep after updating blink.
 */
enum GCType {
  kGCTypeScavenge = 1 << 0,
  kGCTypeMinorMarkSweep = 1 << 1,
  kGCTypeMarkSweepCompact = 1 << 2,
  kGCTypeIncrementalMarking = 1 << 3,
  kGCTypeProcessWeakCallbacks = 1 << 4,
  kGCTypeAll = kGCTypeScavenge | kGCTypeMinorMarkSweep |
               kGCTypeMarkSweepCompact | kGCTypeIncrementalMarking |
               kGCTypeProcessWeakCallbacks
};

/**
 * GCCallbackFlags is used to notify additional information about the GC
 * callback.
 *   - kGCCallbackFlagConstructRetainedObjectInfos: The GC callback is for
 *     constructing retained object infos.
 *   - kGCCallbackFlagForced: The GC callback is for a forced GC for testing.
 *   - kGCCallbackFlagSynchronousPhantomCallbackProcessing: The GC callback
 *     is called synchronously without getting posted to an idle task.
 *   - kGCCallbackFlagCollectAllAvailableGarbage: The GC callback is called
 *     in a phase where V8 is trying to collect all available garbage
 *     (e.g., handling a low memory notification).
 *   - kGCCallbackScheduleIdleGarbageCollection: The GC callback is called to
 *     trigger an idle garbage collection.
 */
enum GCCallbackFlags {
  kNoGCCallbackFlags = 0,
  kGCCallbackFlagConstructRetainedObjectInfos = 1 << 1,
  kGCCallbackFlagForced = 1 << 2,
  kGCCallbackFlagSynchronousPhantomCallbackProcessing = 1 << 3,
  kGCCallbackFlagCollectAllAvailableGarbage = 1 << 4,
  kGCCallbackFlagCollectAllExternalMemory = 1 << 5,
  kGCCallbackScheduleIdleGarbageCollection = 1 << 6,
};

using GCCallback = void (*)(GCType type, GCCallbackFlags flags);

using InterruptCallback = void (*)(Isolate* isolate, void* data);

/**
 * This callback is invoked when the heap size is close to the heap limit and
 * V8 is likely to abort with out-of-memory error.
 * The callback can extend the heap limit by returning a value that is greater
 * than the current_heap_limit. The initial heap limit is the limit that was
 * set after heap setup.
 */
using NearHeapLimitCallback = size_t (*)(void* data, size_t current_heap_limit,
                                         size_t initial_heap_limit);

/**
 * Callback function passed to SetUnhandledExceptionCallback.
 */
#if defined(V8_OS_WIN)
using UnhandledExceptionCallback =
    int (*)(_EXCEPTION_POINTERS* exception_pointers);
#endif

// --- Counters Callbacks ---

using CounterLookupCallback = int* (*)(const char* name);

using CreateHistogramCallback = void* (*)(const char* name, int min, int max,
                                          size_t buckets);

using AddHistogramSampleCallback = void (*)(void* histogram, int sample);

// --- Exceptions ---

using FatalErrorCallback = void (*)(const char* location, const char* message);

struct OOMDetails {
  bool is_heap_oom = false;
  const char* detail = nullptr;
};

using OOMErrorCallback = void (*)(const char* location,
                                  const OOMDetails& details);

using MessageCallback = void (*)(Local<Message> message, Local<Value> data);

// --- Tracing ---

enum LogEventStatus : int { kStart = 0, kEnd = 1, kLog = 2 };
using LogEventCallback = void (*)(const char* name,
                                  int /* LogEventStatus */ status);

// --- Crashkeys Callback ---
enum class CrashKeyId {
  kIsolateAddress,
  kReadonlySpaceFirstPageAddress,
  kMapSpaceFirstPageAddress V8_ENUM_DEPRECATE_SOON("Map space got removed"),
  kOldSpaceFirstPageAddress,
  kCodeRangeBaseAddress,
  kCodeSpaceFirstPageAddress,
  kDumpType,
  kSnapshotChecksumCalculated,
  kSnapshotChecksumExpected,
};

using AddCrashKeyCallback = void (*)(CrashKeyId id, const std::string& value);

// --- Enter/Leave Script Callback ---
using BeforeCallEnteredCallback = void (*)(Isolate*);
using CallCompletedCallback = void (*)(Isolate*);

// --- Modify Code Generation From Strings Callback ---
struct ModifyCodeGenerationFromStringsResult {
  // If true, proceed with the codegen algorithm. Otherwise, block it.
  bool codegen_allowed = false;
  // Overwrite the original source with this string, if present.
  // Use the original source if empty.
  // This field is considered only if codegen_allowed is true.
  MaybeLocal<String> modified_source;
};

/**
 * Callback to check if codegen is allowed from a source object, and convert
 * the source to string if necessary. See: ModifyCodeGenerationFromStrings.
 */
using ModifyCodeGenerationFromStringsCallback =
    ModifyCodeGenerationFromStringsResult (*)(Local<Context> context,
                                              Local<Value> source);
using ModifyCodeGenerationFromStringsCallback2 =
    ModifyCodeGenerationFromStringsResult (*)(Local<Context> context,
                                              Local<Value> source,
                                              bool is_code_like);

// --- Failed Access Check Callback ---

/**
 * Access type specification.
 */
enum AccessType {
  ACCESS_GET,
  ACCESS_SET,
  ACCESS_HAS,
  ACCESS_DELETE,
  ACCESS_KEYS
};

using FailedAccessCheckCallback = void (*)(Local<Object> target,
                                           AccessType type, Local<Value> data);

// --- WebAssembly compilation callbacks ---
using ExtensionCallback = bool (*)(const FunctionCallbackInfo<Value>&);

using AllowWasmCodeGenerationCallback = bool (*)(Local<Context> context,
                                                 Local<String> source);

// --- Callback for APIs defined on v8-supported objects, but implemented
// by the embedder. Example: WebAssembly.{compile|instantiate}Streaming ---
using ApiImplementationCallback = void (*)(const FunctionCallbackInfo<Value>&);

// --- Callback for WebAssembly.compileStreaming ---
using WasmStreamingCallback = void (*)(const FunctionCallbackInfo<Value>&);

enum class WasmAsyncSuccess { kSuccess, kFail };

// --- Callback called when async WebAssembly operations finish ---
using WasmAsyncResolvePromiseCallback = void (*)(
    Isolate* isolate, Local<Context> context, Local<Promise::Resolver> resolver,
    Local<Value> result, WasmAsyncSuccess success);

// --- Callback for loading source map file for Wasm profiling support
using WasmLoadSourceMapCallback = Local<String> (*)(Isolate* isolate,
                                                    const char* name);

// --- Callback for checking if WebAssembly imported strings are enabled ---
using WasmImportedStringsEnabledCallback = bool (*)(Local<Context> context);

// --- Callback for checking if the SharedArrayBuffer constructor is enabled ---
using SharedArrayBufferConstructorEnabledCallback =
    bool (*)(Local<Context> context);

// --- Callback for checking if the compile hints magic comments are enabled ---
using JavaScriptCompileHintsMagicEnabledCallback =
    bool (*)(Local<Context> context);

// --- Callback for checking if WebAssembly JSPI is enabled ---
using WasmJSPIEnabledCallback = bool (*)(Local<Context> context);

/**
 * Import phases in import requests.
 */
enum class ModuleImportPhase {
  kSource,
  kEvaluation,
};

/**
 * HostImportModuleDynamicallyCallback is called when we
 * require the embedder to load a module. This is used as part of the dynamic
 * import syntax.
 *
 * The referrer contains metadata about the script/module that calls
 * import.
 *
 * The specifier is the name of the module that should be imported.
 *
 * The import_attributes are import attributes for this request in the form:
 * [key1, value1, key2, value2, ...] where the keys and values are of type
 * v8::String. Note, unlike the FixedArray passed to ResolveModuleCallback and
 * returned from ModuleRequest::GetImportAttributes(), this array does not
 * contain the source Locations of the attributes.
 *
 * The embedder must compile, instantiate, evaluate the Module, and
 * obtain its namespace object.
 *
 * The Promise returned from this function is forwarded to userland
 * JavaScript. The embedder must resolve this promise with the module
 * namespace object. In case of an exception, the embedder must reject
 * this promise with the exception. If the promise creation itself
 * fails (e.g. due to stack overflow), the embedder must propagate
 * that exception by returning an empty MaybeLocal.
 */
using HostImportModuleDynamicallyCallback = MaybeLocal<Promise> (*)(
    Local<Context> context, Local<Data> host_defined_options,
    Local<Value> resource_name, Local<String> specifier,
    Local<FixedArray> import_attributes);

/**
 * HostImportModuleWithPhaseDynamicallyCallback is called when we
 * require the embedder to load a module with a specific phase. This is used
 * as part of the dynamic import syntax.
 *
 * The referrer contains metadata about the script/module that calls
 * import.
 *
 * The specifier is the name of the module that should be imported.
 *
 * The phase is the phase of the import requested.
 *
 * The import_attributes are import attributes for this request in the form:
 * [key1, value1, key2, value2, ...] where the keys and values are of type
 * v8::String. Note, unlike the FixedArray passed to ResolveModuleCallback and
 * returned from ModuleRequest::GetImportAttributes(), this array does not
 * contain the source Locations of the attributes.
 *
 * The Promise returned from this function is forwarded to userland
 * JavaScript. The embedder must resolve this promise according to the phase
 * requested:
 * - For ModuleImportPhase::kSource, the promise must be resolved with a
 *   compiled ModuleSource object, or rejected with a SyntaxError if the
 *   module does not support source representation.
 * - For ModuleImportPhase::kEvaluation, the promise must be resolved with a
 *   ModuleNamespace object of a module that has been compiled, instantiated,
 *   and evaluated.
 *
 * In case of an exception, the embedder must reject this promise with the
 * exception. If the promise creation itself fails (e.g. due to stack
 * overflow), the embedder must propagate that exception by returning an empty
 * MaybeLocal.
 *
 * This callback is still experimental and is only invoked for source phase
 * imports.
 */
using HostImportModuleWithPhaseDynamicallyCallback = MaybeLocal<Promise> (*)(
    Local<Context> context, Local<Data> host_defined_options,
    Local<Value> resource_name, Local<String> specifier,
    ModuleImportPhase phase, Local<FixedArray> import_attributes);

/**
 * Callback for requesting a compile hint for a function from the embedder. The
 * first parameter is the position of the function in source code and the second
 * parameter is embedder data to be passed back.
 */
using CompileHintCallback = bool (*)(int, void*);

/**
 * HostInitializeImportMetaObjectCallback is called the first time import.meta
 * is accessed for a module. Subsequent access will reuse the same value.
 *
 * The method combines two implementation-defined abstract operations into one:
 * HostGetImportMetaProperties and HostFinalizeImportMeta.
 *
 * The embedder should use v8::Object::CreateDataProperty to add properties on
 * the meta object.
 */
using HostInitializeImportMetaObjectCallback = void (*)(Local<Context> context,
                                                        Local<Module> module,
                                                        Local<Object> meta);

/**
 * HostCreateShadowRealmContextCallback is called each time a ShadowRealm is
 * being constructed in the initiator_context.
 *
 * The method combines Context creation and implementation defined abstract
 * operation HostInitializeShadowRealm into one.
 *
 * The embedder should use v8::Context::New or v8::Context:NewFromSnapshot to
 * create a new context. If the creation fails, the embedder must propagate
 * that exception by returning an empty MaybeLocal.
 */
using HostCreateShadowRealmContextCallback =
    MaybeLocal<Context> (*)(Local<Context> initiator_context);

/**
 * PrepareStackTraceCallback is called when the stack property of an error is
 * first accessed. The return value will be used as the stack value. If this
 * callback is registed, the |Error.prepareStackTrace| API will be disabled.
 * |sites| is an array of call sites, specified in
 * https://v8.dev/docs/stack-trace-api
 */
using PrepareStackTraceCallback = MaybeLocal<Value> (*)(Local<Context> context,
                                                        Local<Value> error,
                                                        Local<Array> sites);

#if defined(V8_OS_WIN)
/**
 * Callback to selectively enable ETW tracing based on the document URL.
 * Implemented by the embedder, it should never call back into V8.
 *
 * Windows allows passing additional data to the ETW EnableCallback:
 * https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nc-evntprov-penablecallback
 *
 * This data can be configured in a WPR (Windows Performance Recorder)
 * profile, adding a CustomFilter to an EventProvider like the following:
 *
 * <EventProvider Id=".." Name="57277741-3638-4A4B-BDBA-0AC6E45DA56C" Level="5">
 *   <CustomFilter Type="0x80000000" Value="AQABAAAAAAA..." />
 * </EventProvider>
 *
 * Where:
 * - Name="57277741-3638-4A4B-BDBA-0AC6E45DA56C" is the GUID of the V8
 *     ETW provider, (see src/libplatform/etw/etw-provider-win.h),
 * - Type="0x80000000" is EVENT_FILTER_TYPE_SCHEMATIZED,
 * - Value="AQABAAAAAA..." is a base64-encoded byte array that is
 *     base64-decoded by Windows and passed to the ETW enable callback in
 *     the 'PEVENT_FILTER_DESCRIPTOR FilterData' argument; see:
 * https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor.
 *
 * This array contains a struct EVENT_FILTER_HEADER followed by a
 * variable length payload, and as payload we pass a string in JSON format,
 * with a list of regular expressions that should match the document URL
 * in order to enable ETW tracing:
 *   {
 *     "version": "1.0",
 *     "filtered_urls": [
 *         "https:\/\/.*\.chromium\.org\/.*", "https://v8.dev/";, "..."
 *     ]
 *  }
 */
using FilterETWSessionByURLCallback =
    bool (*)(Local<Context> context, const std::string& etw_filter_payload);
#endif  // V8_OS_WIN

}  // namespace v8

#endif  // INCLUDE_V8_ISOLATE_CALLBACKS_H_
```