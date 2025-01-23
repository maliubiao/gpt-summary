Response:
Let's break down the thought process for analyzing this C++ header file.

**1. Initial Scan and High-Level Understanding:**

The first thing I do is a quick skim to get the overall purpose. Keywords like `WebAssembly`, `#ifndef V8_WASM_WASM_ENGINE_H_`, `namespace wasm`, and class names like `WasmEngine`, `NativeModuleCache`, `CompilationResultResolver` immediately signal this is related to V8's WebAssembly engine. The copyright notice confirms it's part of the V8 project. The `#if !V8_ENABLE_WEBASSEMBLY` block tells me this code is conditional on WebAssembly being enabled.

**2. Identifying Key Classes and Their Roles:**

Next, I focus on the major classes and try to infer their responsibilities based on their names and member functions.

*   **`WasmEngine`**: This seems like the central orchestrator. Functions like `SyncCompile`, `AsyncCompile`, `SyncInstantiate`, `AsyncInstantiate`, `ImportNativeModule`, `FlushLiftoffCode`, etc., clearly indicate it manages the entire lifecycle of WebAssembly modules.
*   **`NativeModuleCache`**:  The name suggests caching of compiled modules. The `Key` struct with `prefix_hash`, `compile_imports`, and `bytes` reinforces this. The functions like `MaybeGetNativeModule`, `Update`, `Erase` confirm its caching role.
*   **`CompilationResultResolver` and `InstantiationResultResolver`**:  These look like callback interfaces for asynchronous operations. `OnCompilationSucceeded`, `OnCompilationFailed`, `OnInstantiationSucceeded`, `OnInstantiationFailed` strongly suggest this.
*   **`NativeModule`**: This likely represents a compiled WebAssembly module in memory. Its details are not in this header, but its existence is crucial.
*   **`AsyncCompileJob`**:  This clearly relates to asynchronous compilation tasks.
*   **`StreamingDecoder`**: This suggests handling the streaming compilation process.

**3. Analyzing Functionality Through Public Methods:**

I then go through the public methods of the `WasmEngine` class, as they represent the primary interface for interacting with the WebAssembly engine. I categorize them based on their likely function:

*   **Compilation:** `SyncValidate`, `SyncCompileTranslatedAsmJs`, `FinalizeTranslatedAsmJs`, `SyncCompile`, `AsyncCompile`, `StartStreamingCompilation`, `CompileFunction`.
*   **Instantiation:** `SyncInstantiate`, `AsyncInstantiate`.
*   **Module Management:** `ImportNativeModule`, `NewNativeModule`, `MaybeGetNativeModule`, `UpdateNativeModuleCache`, `FreeNativeModule`.
*   **Code Management/Optimization:** `FlushLiftoffCode`, `GetLiftoffCodeSizeForTesting`, `SampleTopTierCodeSizeInAllIsolates`, `ReportLiveCodeForGC`, `AddPotentiallyDeadCode`, `FreeDeadCode`.
*   **Debugging:** `EnterDebuggingForIsolate`, `LeaveDebuggingForIsolate`.
*   **Resource Management:** `allocator()`, `GetOrCreateTurboStatistics`, `DumpAndResetTurboStatistics`, `DeleteCompileJobsOnContext`, `DeleteCompileJobsOnIsolate`, `AddIsolate`, `RemoveIsolate`.
*   **Code Logging:** `LogCode`, `LogWrapperCode`, `EnableCodeLogging`, `LogOutstandingCodesForIsolate`.
*   **Other:** `GetBarrierForBackgroundCompile`, `type_canonicalizer()`, `call_descriptors()`, `EstimateCurrentMemoryConsumption`, `GetDeoptsExecutedCount`, `IncrementDeoptsExecutedCount`, `InitializeOncePerProcess`, `GlobalTearDown`, `NewOrphanedGlobalHandle`, `FreeAllOrphanedGlobalHandles`.

**4. Identifying Potential JavaScript Relationships:**

As I go through the methods, I consider how these functionalities might be exposed to JavaScript. The compilation and instantiation methods are the most obvious connections to the `WebAssembly` API in JavaScript. I think about the corresponding JavaScript code that would trigger these actions (e.g., `WebAssembly.compile()`, `WebAssembly.instantiate()`).

**5. Looking for Code Logic and Assumptions:**

I examine methods like those in `NativeModuleCache`. The `Key` structure and the logic within `MaybeGetNativeModule` and `UpdateNativeModuleCache` indicate a locking mechanism to prevent race conditions during module creation. The use of `std::optional<std::weak_ptr<NativeModule>>` is a key detail for understanding the cache's behavior, allowing for tracking in-progress compilations and handling expired entries.

**6. Considering Common Programming Errors:**

Based on the functionality, I consider potential errors a user might make when working with WebAssembly. Incorrect imports, invalid module bytes, and attempting to use a module before compilation/instantiation are common scenarios. The asynchronous nature of compilation and instantiation also raises the possibility of errors in handling promises or callbacks.

**7. Addressing Specific Constraints from the Prompt:**

Throughout the analysis, I keep the prompt's specific requirements in mind:

*   **Listing functions:** I systematically list the functionalities.
*   **Torque:** I check the file extension and note that it's a C++ header.
*   **JavaScript examples:** I provide relevant JavaScript examples where the functionality connects to the JS API.
*   **Code logic reasoning:** I focus on the caching logic in `NativeModuleCache` as a key example.
*   **Common programming errors:** I provide examples of typical WebAssembly usage errors.

**8. Structuring the Output:**

Finally, I organize the information into a clear and structured format, using headings and bullet points to make it easy to read and understand. I ensure I address all parts of the prompt.

**Self-Correction/Refinement During the Process:**

*   Initially, I might have just listed the methods without grouping them by functionality. I then realize that grouping provides a better overview.
*   I might initially miss the connection between `NativeModuleCache` and streaming compilation. Upon closer inspection of `GetStreamingCompilationOwnership`, I realize the relationship.
*   I might need to rephrase some explanations for clarity and accuracy. For instance, instead of just saying "manages modules," I elaborate on what "managing" entails (compilation, instantiation, caching, etc.).

By following this methodical approach, combining scanning, inference, and attention to detail, I can effectively analyze a complex header file like `wasm-engine.h`.
This is a header file (`wasm-engine.h`) in the V8 JavaScript engine's source code, specifically related to the WebAssembly (Wasm) engine. Let's break down its functionality based on the provided code:

**Core Functionality of `v8/src/wasm/wasm-engine.h`:**

This header file defines the `WasmEngine` class, which is the central component responsible for managing the lifecycle of WebAssembly modules within V8. Its main responsibilities include:

1. **Compilation of WebAssembly Modules:**
    *   **Synchronous Compilation (`SyncCompile`, `SyncCompileTranslatedAsmJs`):**  Compiles WebAssembly bytecode into executable code on the current thread. Handles both standard Wasm modules and translated asm.js modules.
    *   **Asynchronous Compilation (`AsyncCompile`, `StartStreamingCompilation`):**  Initiates compilation in the background, allowing the main thread to remain responsive. `StartStreamingCompilation` suggests support for compiling modules as they are being downloaded.
    *   **Tiered Compilation (`CompileFunction`):** Allows compiling individual functions at different optimization levels (tiers).

2. **Instantiation of WebAssembly Modules:**
    *   **Synchronous Instantiation (`SyncInstantiate`):** Creates an instance of a compiled Wasm module, linking it with provided imports (functions, memories, globals from JavaScript).
    *   **Asynchronous Instantiation (`AsyncInstantiate`):** Instantiates a module in the background.

3. **Caching of Compiled Modules (`NativeModuleCache`):**
    *   Stores compiled `NativeModule` objects (which contain the compiled code) based on their bytecode and compile-time imports. This avoids recompiling the same module repeatedly.
    *   Manages concurrent access to the cache to prevent race conditions during compilation.
    *   Supports streaming compilation by tracking which modules are being compiled.

4. **Management of `NativeModule` Objects:**
    *   `NativeModule` likely represents the compiled form of a Wasm module, containing the machine code and metadata. The `WasmEngine` creates, manages, and frees these objects.
    *   Handles importing native modules (compiled code) between different JavaScript contexts or isolates.

5. **Debugging Support:**
    *   Provides hooks for entering and leaving debugging mode for Wasm code (`EnterDebuggingForIsolate`, `LeaveDebuggingForIsolate`).
    *   Integration with a GDB remote debugger (if `V8_ENABLE_WASM_GDB_REMOTE_DEBUGGING` is defined).

6. **Memory Management:**
    *   Uses an `AccountingAllocator` for managing memory allocated for Wasm compilation and execution.
    *   Includes mechanisms for freeing dead code and managing potentially dead code to optimize memory usage.

7. **Code Logging and Profiling:**
    *   Supports logging of generated Wasm code for debugging and performance analysis (`LogCode`, `LogWrapperCode`, `EnableCodeLogging`).
    *   Collects compilation statistics for TurboFan (V8's optimizing compiler).

8. **Integration with V8's Isolate and Context Model:**
    *   Tracks which isolates (independent V8 instances) are using the `WasmEngine`.
    *   Handles the disposal of compilation jobs when a context or isolate is being torn down.

9. **Asm.js Support:**
    *   Includes specific functions for compiling and finalizing translated asm.js code (`SyncCompileTranslatedAsmJs`, `FinalizeTranslatedAsmJs`).

**Specific Points from the Code:**

*   **Conditional Compilation:** The `#if !V8_ENABLE_WEBASSEMBLY` block ensures this header is only included when WebAssembly support is enabled in the V8 build.
*   **Result Resolvers:** The `CompilationResultResolver` and `InstantiationResultResolver` are abstract interfaces used as callbacks for asynchronous compilation and instantiation operations. They define how the engine informs the caller about the success or failure of these operations.
*   **Native Module Cache Key:** The `NativeModuleCache::Key` structure defines how compiled modules are identified and stored in the cache. It includes the hash of the module's prefix, compile-time imports, and the raw bytecode.
*   **Mutex and Condition Variable:** The `NativeModuleCache` uses a mutex (`mutex_`) and a condition variable (`cache_cv_`) to synchronize access to the cache and manage concurrent compilation of the same module.
*   **Operations Barrier:** The `OperationsBarrier` is likely used to ensure that background compilation tasks are completed before certain operations (like isolate shutdown) proceed.

**Is `v8/src/wasm/wasm-engine.h` a Torque Source File?**

No, `v8/src/wasm/wasm-engine.h` has the `.h` extension, which is the standard convention for C++ header files. Torque source files in V8 typically have the `.tq` extension.

**Relationship to JavaScript and Examples:**

The functionality defined in `wasm-engine.h` is directly related to the `WebAssembly` API available in JavaScript. When you use the `WebAssembly` API, you are interacting with the underlying mechanisms managed by the `WasmEngine`.

**JavaScript Examples:**

```javascript
// Example of compiling a WebAssembly module (asynchronous)
fetch('my_wasm_module.wasm')
  .then(response => response.arrayBuffer())
  .then(bytes => WebAssembly.compile(bytes)) // This triggers the AsyncCompile path in WasmEngine
  .then(module => {
    // Module is compiled
    console.log("Wasm module compiled:", module);

    // Example of instantiating a WebAssembly module (asynchronous)
    const importObject = { /* ... your imports ... */ };
    return WebAssembly.instantiate(module, importObject); // This triggers the AsyncInstantiate path
  })
  .then(instance => {
    // Instance is created
    console.log("Wasm instance:", instance);
    // Call exported functions
    instance.exports.myFunction();
  })
  .catch(error => {
    console.error("Error with WebAssembly:", error);
  });

// Example of synchronous compilation and instantiation (less common in modern JS)
try {
  const bytes = new Uint8Array([.../* your wasm bytecode */]);
  const module = new WebAssembly.Module(bytes); // This might trigger the SyncCompile path
  const importObject = { /* ... your imports ... */ };
  const instance = new WebAssembly.Instance(module, importObject); // This might trigger the SyncInstantiate path
  instance.exports.anotherFunction();
} catch (error) {
  console.error("Error with WebAssembly:", error);
}
```

**Code Logic Reasoning and Assumptions:**

Let's focus on the `NativeModuleCache` as an example of code logic.

**Assumption:**  We have two asynchronous compilation requests for the *same* WebAssembly module bytecode arriving nearly simultaneously.

**Input:**

1. **Compilation Request 1:**  Arrives first with `prefix_hash = X`, `compile_imports = I`, `wire_bytes = B`.
2. **Compilation Request 2:** Arrives shortly after with the *same* `prefix_hash = X`, `compile_imports = I`, `wire_bytes = B`.

**Logic in `NativeModuleCache` (simplified):**

1. **Request 1:**
    *   `MaybeGetNativeModule(..., B, I)` is called.
    *   The cache doesn't have an entry for the key `(X, I, B)`.
    *   A `nullopt` (empty optional) is inserted into the cache for this key, indicating compilation is in progress.
    *   The function returns `nullptr`, signaling that the module is not yet in the cache, but is being built.

2. **Request 2:**
    *   `MaybeGetNativeModule(..., B, I)` is called.
    *   The cache *now* has an entry for the key `(X, I, B)`, and its value is `nullopt`.
    *   Request 2 knows that another thread is already compiling this module.
    *   Request 2 will likely wait on the `cache_cv_` condition variable associated with the cache's mutex.

3. **Request 1 Finishes Compilation:**
    *   The compilation succeeds, producing a `NativeModule` object.
    *   `UpdateNativeModuleCache(false, native_module, ...)` is called.
    *   The `nullopt` entry in the cache is replaced with a `weak_ptr` to the newly created `NativeModule`.
    *   The `cache_cv_` condition variable is signaled, waking up waiting threads (like Request 2).

4. **Request 2 Resumes:**
    *   Request 2 wakes up, reacquires the mutex, and calls `MaybeGetNativeModule(..., B, I)` again.
    *   This time, the cache contains a valid `weak_ptr` to the compiled `NativeModule`.
    *   The function returns a `shared_ptr` to the `NativeModule`.

**Output:** Both compilation requests ultimately receive a shared pointer to the *same* compiled `NativeModule`, avoiding redundant compilation.

**User-Common Programming Errors:**

1. **Incorrect Imports:** Providing an `importObject` to `WebAssembly.instantiate` that doesn't match the imports declared in the WebAssembly module will lead to an instantiation error.

    ```javascript
    // WebAssembly module imports a function named 'consoleLog'
    const importObject = {
      // Oops, typo in the import name!
      "js": { "consoLog": function(arg) { console.log(arg); } }
    };

    fetch('my_module.wasm')
      .then(response => response.arrayBuffer())
      .then(bytes => WebAssembly.instantiate(bytes, importObject))
      .catch(error => {
        console.error("Instantiation error:", error); // This will likely happen
      });
    ```

2. **Invalid WebAssembly Bytes:** Attempting to compile or instantiate data that is not valid WebAssembly bytecode will result in an error.

    ```javascript
    const invalidWasmBytes = new Uint8Array([0, 1, 2, 3, 4]); // Definitely not valid WASM
    WebAssembly.compile(invalidWasmBytes)
      .catch(error => {
        console.error("Compilation error:", error);
      });
    ```

3. **Using Asynchronous Operations Incorrectly:**  Not handling the promises returned by `WebAssembly.compile` and `WebAssembly.instantiate` correctly can lead to errors or trying to use the module before it's ready.

    ```javascript
    let myModule;

    WebAssembly.compile(fetch('my_module.wasm')) // Incorrect - fetch returns a Promise
      .then(module => {
        myModule = module;
      });

    // Potential error: myModule might be undefined here if the fetch is slow
    WebAssembly.instantiate(myModule, {});
    ```

4. **Security Errors (e.g., trying to access memory out of bounds):** While not directly related to the `WasmEngine`'s compilation and instantiation, these are common runtime errors when working with WebAssembly.

5. **Mixing Synchronous and Asynchronous APIs Inappropriately:**  While the synchronous APIs exist, they can block the main thread and are generally discouraged in web environments.

This detailed breakdown illustrates the key functionalities and relationships defined within the `v8/src/wasm/wasm-engine.h` header file, highlighting its crucial role in V8's WebAssembly implementation.

### 提示词
```
这是目录为v8/src/wasm/wasm-engine.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-engine.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_WASM_ENGINE_H_
#define V8_WASM_WASM_ENGINE_H_

#include <algorithm>
#include <map>
#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>

#include "src/base/platform/condition-variable.h"
#include "src/base/platform/mutex.h"
#include "src/compiler/wasm-call-descriptors.h"
#include "src/tasks/cancelable-task.h"
#include "src/tasks/operations-barrier.h"
#include "src/wasm/canonical-types.h"
#include "src/wasm/stacks.h"
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-tier.h"
#include "src/zone/accounting-allocator.h"

namespace v8 {
namespace internal {

class AsmWasmData;
class CodeTracer;
class CompilationStatistics;
class HeapNumber;
class WasmInstanceObject;
class WasmModuleObject;
class JSArrayBuffer;

namespace wasm {

#ifdef V8_ENABLE_WASM_GDB_REMOTE_DEBUGGING
namespace gdb_server {
class GdbServer;
}  // namespace gdb_server
#endif  // V8_ENABLE_WASM_GDB_REMOTE_DEBUGGING

class AsyncCompileJob;
class ErrorThrower;
struct ModuleWireBytes;
class StreamingDecoder;
class WasmEnabledFeatures;
class WasmOrphanedGlobalHandle;

class V8_EXPORT_PRIVATE CompilationResultResolver {
 public:
  virtual void OnCompilationSucceeded(Handle<WasmModuleObject> result) = 0;
  virtual void OnCompilationFailed(Handle<Object> error_reason) = 0;
  virtual ~CompilationResultResolver() = default;
};

class V8_EXPORT_PRIVATE InstantiationResultResolver {
 public:
  virtual void OnInstantiationSucceeded(Handle<WasmInstanceObject> result) = 0;
  virtual void OnInstantiationFailed(Handle<Object> error_reason) = 0;
  virtual ~InstantiationResultResolver() = default;
};

// Native modules cached by their wire bytes and compile-time imports.
class NativeModuleCache {
 public:
  struct Key {
    Key(size_t prefix_hash, CompileTimeImports compile_imports,
        const base::Vector<const uint8_t>& bytes)
        : prefix_hash(prefix_hash),
          compile_imports(std::move(compile_imports)),
          bytes(bytes) {}

    // Store the prefix hash as part of the key for faster lookup, and to
    // quickly check existing prefixes for streaming compilation.
    size_t prefix_hash;
    CompileTimeImports compile_imports;
    base::Vector<const uint8_t> bytes;

    bool operator==(const Key& other) const {
      bool eq = bytes == other.bytes &&
                compile_imports.compare(other.compile_imports) == 0;
      DCHECK_IMPLIES(eq, prefix_hash == other.prefix_hash);
      return eq;
    }

    bool operator<(const Key& other) const {
      if (prefix_hash != other.prefix_hash) {
        DCHECK_IMPLIES(!bytes.empty() && !other.bytes.empty(),
                       bytes != other.bytes);
        return prefix_hash < other.prefix_hash;
      }
      if (bytes.size() != other.bytes.size()) {
        return bytes.size() < other.bytes.size();
      }
      if (int cmp = compile_imports.compare(other.compile_imports)) {
        return cmp < 0;
      }
      // Fast path when the base pointers are the same.
      // Also handles the {nullptr} case which would be UB for memcmp.
      if (bytes.begin() == other.bytes.begin()) {
        DCHECK_EQ(prefix_hash, other.prefix_hash);
        return false;
      }
      DCHECK_NOT_NULL(bytes.begin());
      DCHECK_NOT_NULL(other.bytes.begin());
      return memcmp(bytes.begin(), other.bytes.begin(), bytes.size()) < 0;
    }
  };

  std::shared_ptr<NativeModule> MaybeGetNativeModule(
      ModuleOrigin origin, base::Vector<const uint8_t> wire_bytes,
      const CompileTimeImports& compile_imports);
  bool GetStreamingCompilationOwnership(
      size_t prefix_hash, const CompileTimeImports& compile_imports);
  void StreamingCompilationFailed(size_t prefix_hash,
                                  const CompileTimeImports& compile_imports);
  std::shared_ptr<NativeModule> Update(
      std::shared_ptr<NativeModule> native_module, bool error);
  void Erase(NativeModule* native_module);

  bool empty() const { return map_.empty(); }

  // Hash the wire bytes up to the code section header. Used as a heuristic to
  // avoid streaming compilation of modules that are likely already in the
  // cache. See {GetStreamingCompilationOwnership}. Assumes that the bytes have
  // already been validated.
  static size_t PrefixHash(base::Vector<const uint8_t> wire_bytes);

 private:
  // Each key points to the corresponding native module's wire bytes, so they
  // should always be valid as long as the native module is alive.  When
  // the native module dies, {FreeNativeModule} deletes the entry from the
  // map, so that we do not leave any dangling key pointing to an expired
  // weak_ptr. This also serves as a way to regularly clean up the map, which
  // would otherwise accumulate expired entries.
  // A {nullopt} value is inserted to indicate that this native module is
  // currently being created in some thread, and that other threads should wait
  // before trying to get it from the cache.
  // By contrast, an expired {weak_ptr} indicates that the native module died
  // and will soon be cleaned up from the cache.
  std::map<Key, std::optional<std::weak_ptr<NativeModule>>> map_;

  base::Mutex mutex_;

  // This condition variable is used to synchronize threads compiling the same
  // module. Only one thread will create the {NativeModule}. Other threads
  // will wait on this variable until the first thread wakes them up.
  base::ConditionVariable cache_cv_;
};

// The central data structure that represents an engine instance capable of
// loading, instantiating, and executing Wasm code.
class V8_EXPORT_PRIVATE WasmEngine {
  class LogCodesTask;

 public:
  WasmEngine();
  WasmEngine(const WasmEngine&) = delete;
  WasmEngine& operator=(const WasmEngine&) = delete;
  ~WasmEngine();

  // Synchronously validates the given bytes. Returns whether the bytes
  // represent a valid encoded Wasm module.
  bool SyncValidate(Isolate* isolate, WasmEnabledFeatures enabled,
                    CompileTimeImports compile_imports, ModuleWireBytes bytes);

  // Synchronously compiles the given bytes that represent a translated
  // asm.js module.
  MaybeHandle<AsmWasmData> SyncCompileTranslatedAsmJs(
      Isolate* isolate, ErrorThrower* thrower, ModuleWireBytes bytes,
      DirectHandle<Script> script,
      base::Vector<const uint8_t> asm_js_offset_table_bytes,
      DirectHandle<HeapNumber> uses_bitset, LanguageMode language_mode);
  Handle<WasmModuleObject> FinalizeTranslatedAsmJs(
      Isolate* isolate, DirectHandle<AsmWasmData> asm_wasm_data,
      DirectHandle<Script> script);

  // Synchronously compiles the given bytes that represent an encoded Wasm
  // module.
  MaybeHandle<WasmModuleObject> SyncCompile(Isolate* isolate,
                                            WasmEnabledFeatures enabled,
                                            CompileTimeImports compile_imports,
                                            ErrorThrower* thrower,
                                            ModuleWireBytes bytes);

  // Synchronously instantiate the given Wasm module with the given imports.
  // If the module represents an asm.js module, then the supplied {memory}
  // should be used as the memory of the instance.
  MaybeHandle<WasmInstanceObject> SyncInstantiate(
      Isolate* isolate, ErrorThrower* thrower,
      Handle<WasmModuleObject> module_object, MaybeHandle<JSReceiver> imports,
      MaybeHandle<JSArrayBuffer> memory);

  // Begin an asynchronous compilation of the given bytes that represent an
  // encoded Wasm module.
  // The {is_shared} flag indicates if the bytes backing the module could
  // be shared across threads, i.e. could be concurrently modified.
  void AsyncCompile(Isolate* isolate, WasmEnabledFeatures enabled,
                    CompileTimeImports compile_imports,
                    std::shared_ptr<CompilationResultResolver> resolver,
                    ModuleWireBytes bytes, bool is_shared,
                    const char* api_method_name_for_errors);

  // Begin an asynchronous instantiation of the given Wasm module.
  void AsyncInstantiate(Isolate* isolate,
                        std::unique_ptr<InstantiationResultResolver> resolver,
                        Handle<WasmModuleObject> module_object,
                        MaybeHandle<JSReceiver> imports);

  std::shared_ptr<StreamingDecoder> StartStreamingCompilation(
      Isolate* isolate, WasmEnabledFeatures enabled,
      CompileTimeImports compile_imports, Handle<Context> context,
      const char* api_method_name,
      std::shared_ptr<CompilationResultResolver> resolver);

  // Compiles the function with the given index at a specific compilation tier.
  // Errors are stored internally in the CompilationState.
  // This is mostly used for testing to force a function into a specific tier.
  void CompileFunction(Counters* counters, NativeModule* native_module,
                       uint32_t function_index, ExecutionTier tier);

  void EnterDebuggingForIsolate(Isolate* isolate);

  void LeaveDebuggingForIsolate(Isolate* isolate);

  // Imports the shared part of a module from a different Context/Isolate using
  // the the same engine, recreating a full module object in the given Isolate.
  Handle<WasmModuleObject> ImportNativeModule(
      Isolate* isolate, std::shared_ptr<NativeModule> shared_module,
      base::Vector<const char> source_url);

  // Flushes all Liftoff code and returns the sizes of the removed
  // (executable) code and the removed metadata.
  std::pair<size_t, size_t> FlushLiftoffCode();

  // Returns the code size of all Liftoff compiled functions in all modules.
  size_t GetLiftoffCodeSizeForTesting();

  AccountingAllocator* allocator() { return &allocator_; }

  // Compilation statistics for TurboFan compilations. Returns a shared_ptr
  // so that background compilation jobs can hold on to it while the main thread
  // shuts down.
  std::shared_ptr<CompilationStatistics> GetOrCreateTurboStatistics();

  // Prints the gathered compilation statistics, then resets them.
  void DumpAndResetTurboStatistics();
  // Prints the gathered compilation statistics (without resetting them).
  void DumpTurboStatistics();

  // Used to redirect tracing output from {stdout} to a file.
  CodeTracer* GetCodeTracer();

  // Remove {job} from the list of active compile jobs.
  std::unique_ptr<AsyncCompileJob> RemoveCompileJob(AsyncCompileJob* job);

  // Returns true if at least one AsyncCompileJob that belongs to the given
  // Isolate is currently running.
  bool HasRunningCompileJob(Isolate* isolate);

  // Deletes all AsyncCompileJobs that belong to the given context. All
  // compilation is aborted, no more callbacks will be triggered. This is used
  // when a context is disposed, e.g. because of browser navigation.
  void DeleteCompileJobsOnContext(Handle<Context> context);

  // Deletes all AsyncCompileJobs that belong to the given Isolate. All
  // compilation is aborted, no more callbacks will be triggered. This is used
  // for tearing down an isolate, or to clean it up to be reused.
  void DeleteCompileJobsOnIsolate(Isolate* isolate);

  // Manage the set of Isolates that use this WasmEngine.
  void AddIsolate(Isolate* isolate);
  void RemoveIsolate(Isolate* isolate);

  // Trigger code logging for the given code objects in all Isolates which have
  // access to the NativeModule containing this code. This method can be called
  // from background threads.
  void LogCode(base::Vector<WasmCode*>);
  // Trigger code logging for the given code object, which must be a wrapper
  // that is shared engine-wide. This method can be called from background
  // threads.
  // Returns whether code logging was triggered in any isolate.
  bool LogWrapperCode(WasmCode*);

  // Enable code logging for the given Isolate. Initially, code logging is
  // enabled if {WasmCode::ShouldBeLogged(Isolate*)} returns true during
  // {AddIsolate}.
  void EnableCodeLogging(Isolate*);

  // This is called from the foreground thread of the Isolate to log all
  // outstanding code objects (added via {LogCode}).
  void LogOutstandingCodesForIsolate(Isolate*);

  // Create a new NativeModule. The caller is responsible for its
  // lifetime. The native module will be given some memory for code,
  // which will be page size aligned. The size of the initial memory
  // is determined by {code_size_estimate}. The native module may later request
  // more memory.
  // TODO(wasm): isolate is only required here for CompilationState.
  std::shared_ptr<NativeModule> NewNativeModule(
      Isolate* isolate, WasmEnabledFeatures enabled_features,
      WasmDetectedFeatures detected_features,
      CompileTimeImports compile_imports,
      std::shared_ptr<const WasmModule> module, size_t code_size_estimate);

  // Try getting a cached {NativeModule}, or get ownership for its creation.
  // Return {nullptr} if no {NativeModule} exists for these bytes. In this case,
  // a {nullopt} entry is added to let other threads know that a {NativeModule}
  // for these bytes is currently being created. The caller should eventually
  // call {UpdateNativeModuleCache} to update the entry and wake up other
  // threads. The {wire_bytes}' underlying array should be valid at least until
  // the call to {UpdateNativeModuleCache}.
  // The provided {CompileTimeImports} are considered part of the caching key,
  // because they change the generated code as well as the behavior of the
  // {imports()} function of any WasmModuleObjects we'll create for this
  // NativeModule later.
  std::shared_ptr<NativeModule> MaybeGetNativeModule(
      ModuleOrigin origin, base::Vector<const uint8_t> wire_bytes,
      const CompileTimeImports& compile_imports, Isolate* isolate);

  // Replace the temporary {nullopt} with the new native module, or
  // erase it if any error occurred. Wake up blocked threads waiting for this
  // module.
  // To avoid a deadlock on the main thread between synchronous and streaming
  // compilation, two compilation jobs might compile the same native module at
  // the same time. In this case the first call to {UpdateNativeModuleCache}
  // will insert the native module in the cache, and the last call will receive
  // the existing entry from the cache.
  // Return the cached entry, or {native_module} if there was no previously
  // cached module.
  std::shared_ptr<NativeModule> UpdateNativeModuleCache(
      bool has_error, std::shared_ptr<NativeModule> native_module,
      Isolate* isolate);

  // Register this prefix hash for a streaming compilation job.
  // If the hash is not in the cache yet, the function returns true and the
  // caller owns the compilation of this module.
  // Otherwise another compilation job is currently preparing or has already
  // prepared a module with the same prefix hash. The caller should wait until
  // the stream is finished and call {MaybeGetNativeModule} to either get the
  // module from the cache or get ownership for the compilation of these bytes.
  bool GetStreamingCompilationOwnership(
      size_t prefix_hash, const CompileTimeImports& compile_imports);

  // Remove the prefix hash from the cache when compilation failed. If
  // compilation succeeded, {UpdateNativeModuleCache} should be called instead.
  void StreamingCompilationFailed(size_t prefix_hash,
                                  const CompileTimeImports& compile_imports);

  void FreeNativeModule(NativeModule*);
  void ClearWeakScriptHandle(Isolate* isolate,
                             std::unique_ptr<Address*> location);

  // Sample the code size of the given {NativeModule} in all isolates that have
  // access to it. Call this after top-tier compilation finished.
  // This will spawn foreground tasks that do *not* keep the NativeModule alive.
  void SampleTopTierCodeSizeInAllIsolates(const std::shared_ptr<NativeModule>&);

  // Called by each Isolate to report its live code for a GC cycle. First
  // version reports an externally determined set of live code (might be empty),
  // second version gets live code from the execution stack of that isolate.
  void ReportLiveCodeForGC(Isolate*, base::Vector<WasmCode*>);
  void ReportLiveCodeFromStackForGC(Isolate*);

  // Add potentially dead code. The occurrence in the set of potentially dead
  // code counts as a reference, and is decremented on the next GC.
  // Returns {true} if the code was added to the set of potentially dead code,
  // {false} if an entry already exists. The ref count is *unchanged* in any
  // case.
  V8_WARN_UNUSED_RESULT bool AddPotentiallyDeadCode(WasmCode*);

  // Free dead code.
  using DeadCodeMap = std::unordered_map<NativeModule*, std::vector<WasmCode*>>;
  void FreeDeadCode(const DeadCodeMap&, std::vector<WasmCode*>&);
  void FreeDeadCodeLocked(const DeadCodeMap&, std::vector<WasmCode*>&);

  Handle<Script> GetOrCreateScript(Isolate*,
                                   const std::shared_ptr<NativeModule>&,
                                   base::Vector<const char> source_url);

  // Returns a barrier allowing background compile operations if valid and
  // preventing this object from being destroyed.
  std::shared_ptr<OperationsBarrier> GetBarrierForBackgroundCompile();

  TypeCanonicalizer* type_canonicalizer() { return &type_canonicalizer_; }

  compiler::WasmCallDescriptors* call_descriptors() {
    return &call_descriptors_;
  }

  // Returns an approximation of current off-heap memory used by this engine,
  // excluding code space.
  size_t EstimateCurrentMemoryConsumption() const;

  int GetDeoptsExecutedCount() const;
  int IncrementDeoptsExecutedCount();

  // Call on process start and exit.
  static void InitializeOncePerProcess();
  static void GlobalTearDown();

  static WasmOrphanedGlobalHandle* NewOrphanedGlobalHandle(
      WasmOrphanedGlobalHandle** pointer);
  static void FreeAllOrphanedGlobalHandles(WasmOrphanedGlobalHandle* start);

 private:
  struct CurrentGCInfo;
  struct IsolateInfo;
  struct NativeModuleInfo;

  AsyncCompileJob* CreateAsyncCompileJob(
      Isolate* isolate, WasmEnabledFeatures enabled,
      CompileTimeImports compile_imports,
      base::OwnedVector<const uint8_t> bytes, DirectHandle<Context> context,
      const char* api_method_name,
      std::shared_ptr<CompilationResultResolver> resolver, int compilation_id);

  void TriggerGC(int8_t gc_sequence_index);

  // Remove an isolate from the outstanding isolates of the current GC. Returns
  // true if the isolate was still outstanding, false otherwise. Hold {mutex_}
  // when calling this method.
  bool RemoveIsolateFromCurrentGC(Isolate*);

  // Finish a GC if there are no more outstanding isolates. Hold {mutex_} when
  // calling this method.
  void PotentiallyFinishCurrentGC();

  // Enable/disable code logging on the NativeModule, updating
  // {num_modules_with_code_logging_} accordingly.
  void EnableCodeLogging(NativeModule*);
  void DisableCodeLogging(NativeModule*);

  AccountingAllocator allocator_;

#ifdef V8_ENABLE_WASM_GDB_REMOTE_DEBUGGING
  // Implements a GDB-remote stub for WebAssembly debugging.
  std::unique_ptr<gdb_server::GdbServer> gdb_server_;
#endif  // V8_ENABLE_WASM_GDB_REMOTE_DEBUGGING

  std::atomic<int> next_compilation_id_{0};

  // Counter for number of times a deopt was executed.
  std::atomic<int> deopts_executed_{0};

  TypeCanonicalizer type_canonicalizer_;

  compiler::WasmCallDescriptors call_descriptors_;

  // This mutex protects all information which is mutated concurrently or
  // fields that are initialized lazily on the first access.
  mutable base::Mutex mutex_;

  //////////////////////////////////////////////////////////////////////////////
  // Protected by {mutex_}:

  // We use an AsyncCompileJob as the key for itself so that we can delete the
  // job from the map when it is finished.
  std::unordered_map<AsyncCompileJob*, std::unique_ptr<AsyncCompileJob>>
      async_compile_jobs_;

  std::shared_ptr<CompilationStatistics> compilation_stats_;
  std::unique_ptr<CodeTracer> code_tracer_;

  // Set of isolates which use this WasmEngine.
  std::unordered_map<Isolate*, std::unique_ptr<IsolateInfo>> isolates_;

  // Set of native modules managed by this engine.
  std::unordered_map<NativeModule*, std::unique_ptr<NativeModuleInfo>>
      native_modules_;

  std::shared_ptr<OperationsBarrier> operations_barrier_{
      std::make_shared<OperationsBarrier>()};

  // Store the number of modules which have code logging enabled. This is then
  // used for a fast-path to avoid taking the mutex and iterating Isolates or
  // NativeModules.
  std::atomic<size_t> num_modules_with_code_logging_{0};

  // Size of code that became dead since the last GC. If this exceeds a certain
  // threshold, a new GC is triggered.
  size_t new_potentially_dead_code_size_ = 0;
  // Set of potentially dead code. This set holds one ref for each code object,
  // until code is detected to be really dead. At that point, the ref count is
  // decremented and code is moved to the {dead_code} set. If the code is
  // finally deleted, it is also removed from {dead_code}.
  std::unordered_set<WasmCode*> potentially_dead_code_;
  // Code that is not being executed in any isolate any more, but the ref count
  // did not drop to zero yet.
  std::unordered_set<WasmCode*> dead_code_;
  int8_t num_code_gcs_triggered_ = 0;

  // If an engine-wide GC is currently running, this pointer stores information
  // about that.
  std::unique_ptr<CurrentGCInfo> current_gc_info_;

  NativeModuleCache native_module_cache_;

  // End of fields protected by {mutex_}.
  //////////////////////////////////////////////////////////////////////////////
};

// Returns a reference to the WasmEngine shared by the entire process.
V8_EXPORT_PRIVATE WasmEngine* GetWasmEngine();

// Returns a reference to the WasmCodeManager shared by the entire process.
V8_EXPORT_PRIVATE WasmCodeManager* GetWasmCodeManager();

// Returns a reference to the WasmImportWrapperCache shared by the entire
// process.
V8_EXPORT_PRIVATE WasmImportWrapperCache* GetWasmImportWrapperCache();

}  // namespace wasm
}  // namespace internal
}  // namespace v8

#endif  // V8_WASM_WASM_ENGINE_H_
```