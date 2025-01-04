Response: The user wants to understand the functionality of the C++ source code file `v8/src/api/api.cc`.
They have provided a snippet of the code and mentioned it's part 7 of 8.
The goal is to summarize the functionality and illustrate its relation to JavaScript using examples.

Based on the code snippet, it seems this part of the file primarily deals with the `v8::Isolate` class and its related functionalities. An `Isolate` in V8 represents an isolated instance of the V8 JavaScript engine.

Here's a breakdown of the functionalities in the snippet:

1. **Managing C++ Heaps:**
   - `AttachCppHeap`, `DetachCppHeap`, `GetCppHeap`: Functions to manage a separate C++ heap associated with the V8 isolate.

2. **External Memory Tracking:**
   - `SetGetExternallyAllocatedMemoryInBytesCallback`: Allows setting a callback to report externally allocated memory.

3. **Execution Control:**
   - `TerminateExecution`, `IsExecutionTerminating`, `CancelTerminateExecution`: Functions to control JavaScript execution, allowing termination and checking the termination status.
   - `RequestInterrupt`: Allows requesting an interrupt in the JavaScript execution.

4. **Background Tasks:**
   - `HasPendingBackgroundTasks`: Checks if there are pending background tasks (primarily related to WebAssembly compilation).

5. **Garbage Collection (for Testing):**
   - `RequestGarbageCollectionForTesting`: Allows triggering garbage collection for testing purposes.

6. **Getting the Current Isolate:**
   - `GetCurrent`, `TryGetCurrent`, `IsCurrent`: Functions to access the currently active isolate.

7. **Isolate Creation and Initialization:**
   - `Allocate`, `Initialize`, `New`, `CreateParams`: Functions and structures related to creating and initializing new V8 isolates.

8. **Isolate Disposal:**
   - `Dispose`:  Releases resources associated with an isolate.

9. **Statistics and Metadata:**
   - `DumpAndResetStats`, `DiscardThreadSpecificMetadata`: Functions for managing isolate statistics and thread-specific data.

10. **Entering and Exiting an Isolate:**
    - `Enter`, `Exit`:  Functions to make an isolate the currently active one for the current thread.

11. **Callbacks for Various Events:**
    - `SetAbortOnUncaughtExceptionCallback`, `SetHostImportModuleDynamicallyCallback`, etc.:  Setting callbacks for various JavaScript runtime events like uncaught exceptions, dynamic imports, stack trace preparation, etc.

12. **Stack Trace Limit:**
    - `GetStackTraceLimit`: Retrieves the limit for stack trace collection.

13. **Controlling JavaScript Execution (Disallow/Allow Scopes):**
    - `DisallowJavascriptExecutionScope`, `AllowJavascriptExecutionScope`: Scopes to temporarily disallow or allow JavaScript execution.

14. **Suppressing Microtask Execution:**
    - `SuppressMicrotaskExecutionScope`:  A scope to prevent microtasks from running.

15. **Data from Snapshots:**
    - `GetDataFromSnapshotOnce`: Retrieves data stored in the initial snapshot.

16. **Continuation Preserved Embedder Data:**
    - `GetContinuationPreservedEmbedderData`, `SetContinuationPreservedEmbedderData`: Functions to manage data that persists across continuations.

17. **Heap Statistics:**
    - `GetHeapStatistics`, `NumberOfHeapSpaces`, `GetHeapSpaceStatistics`, `NumberOfTrackedHeapObjectTypes`, `GetHeapObjectStatisticsAtLastGC`, `GetHeapCodeAndMetadataStatistics`, `MeasureMemory`:  Functions to gather various statistics about the V8 heap.

18. **Stack Sampling:**
    - `GetStackSample`:  Allows retrieving a stack sample at a given point.

19. **External Allocated Memory Adjustment:**
    - `AdjustAmountOfExternalAllocatedMemory`:  Allows the embedder to inform V8 about changes in externally allocated memory.

20. **Event Logging:**
    - `SetEventLogger`: Sets a callback for logging V8 events.

21. **Call/Promise Hooks and Callbacks:**
    - `AddBeforeCallEnteredCallback`, `RemoveBeforeCallEnteredCallback`, `AddCallCompletedCallback`, `RemoveCallCompletedCallback`, `SetAtomicsWaitCallback`, `SetPromiseHook`, `SetPromiseRejectCallback`, `SetExceptionPropagationCallback`: Setting callbacks for function calls and promise lifecycle events.

22. **Microtask Management:**
    - `PerformMicrotaskCheckpoint`, `EnqueueMicrotask`, `SetMicrotasksPolicy`, `GetMicrotasksPolicy`, `AddMicrotasksCompletedCallback`, `RemoveMicrotasksCompletedCallback`: Functions to manage the microtask queue.

23. **Use Counter and Metrics:**
    - `SetUseCounterCallback`, `SetCounterFunction`, `SetCreateHistogramFunction`, `SetAddHistogramSampleFunction`, `SetMetricsRecorder`: Setting callbacks and functions for tracking feature usage and recording metrics.

24. **Crash Keys:**
    - `SetAddCrashKeyCallback`:  Allows setting a callback to add crash keys for debugging.

25. **Memory Pressure and Notifications:**
    - `LowMemoryNotification`, `ContextDisposedNotification`, `IsolateInForegroundNotification`, `IsolateInBackgroundNotification`, `SetPriority`, `MemoryPressureNotification`, `SetBatterySaverMode`: Functions to handle memory pressure events and isolate priority.

26. **Cache Clearing:**
    - `ClearCachesForTesting`: Clears internal caches (primarily for testing).

27. **RAIL Mode:**
    - `SetRAILMode`: Sets the RAIL (Response, Animation, Idle, Load) mode.

28. **Loading State:**
    - `UpdateLoadStartTime`, `SetIsLoading`: Functions to manage the loading state of the isolate.

29. **Heap Limit Manipulation (Debugging):**
    - `IncreaseHeapLimitForDebugging`, `RestoreOriginalHeapLimit`, `IsHeapLimitIncreasedForDebugging`: Functions for temporarily adjusting the heap limit for debugging.

30. **JIT Code Event Handling:**
    - `SetJitCodeEventHandler`: Sets a callback to receive notifications about JIT-compiled code.

31. **Stack Limit Setting:**
    - `SetStackLimit`:  Allows setting a custom stack limit.

32. **Code Range Information:**
    - `GetCodeRange`, `GetEmbeddedCodeRange`: Functions to retrieve the memory ranges where V8 code is stored.

33. **JSEntry Stubs:**
    - `GetJSEntryStubs`: Returns information about the entry points for executing JavaScript code.

34. **Copying Code Pages:**
    - `CopyCodePages`:  Allows copying the memory ranges of code pages.

35. **Setting Various Callbacks (Macros):**
    - The `CALLBACK_SETTER` macro is used to define setters for various callbacks related to error handling, WebAssembly, and other features.

36. **Conditional Feature Installation:**
    - `InstallConditionalFeatures`: Installs features that depend on the current context or environment.

37. **Near Heap Limit Callbacks:**
    - `AddNearHeapLimitCallback`, `RemoveNearHeapLimitCallback`, `AutomaticallyRestoreInitialHeapLimit`: Functions to manage callbacks triggered when the heap usage approaches its limit.

38. **Isolate Death Check:**
    - `IsDead`: Checks if the isolate is in a dead state.

39. **Message Listeners:**
    - `AddMessageListener`, `AddMessageListenerWithErrorLevel`, `RemoveMessageListeners`: Functions to manage listeners for V8 messages (errors, warnings).

40. **Failed Access Check Callback:**
    - `SetFailedAccessCheckCallbackFunction`: Sets a callback for when access checks fail.

41. **Uncaught Exception Stack Trace Capture:**
    - `SetCaptureStackTraceForUncaughtExceptions`: Configures the capture of stack traces for uncaught exceptions.

42. **External Resource Visiting:**
    - `VisitExternalResources`: Allows visiting external resources managed by the isolate.

43. **Isolate Usage Check:**
    - `IsInUse`: Checks if the isolate is currently being used by a thread.

44. **Atomics Wait Permission:**
    - `SetAllowAtomicsWait`:  Controls whether `Atomics.wait` is allowed.

45. **Date/Time and Locale Configuration Change Notifications:**
    - `DateTimeConfigurationChangeNotification`, `LocaleConfigurationChangeNotification`, `GetDefaultLocale`: Functions to notify V8 about changes in date/time and locale settings.

46. **ETW Session Filtering (Windows):**
    - `SetFilterETWSessionByURLCallback`: Allows setting a callback to filter ETW sessions based on URL.

47. **Checking if an Object is Code-Like:**
    - `Object::IsCodeLike`: Determines if a given object behaves like code.

48. **Microtask Queue Creation:**
    - `MicrotaskQueue::New`: Creates a new microtask queue.

49. **Microtask Scopes:**
    - `MicrotasksScope`:  A class to manage the execution of microtasks within a specific scope.

50. **String Conversion Utilities:**
    - `String::Utf8Value`, `String::Value`, `String::ValueView`:  Utilities for converting V8 strings to C++ strings.

51. **Exception Creation:**
    - `Exception::RangeError`, `Exception::ReferenceError`, etc.: Static methods to create specific types of JavaScript errors.

52. **Message and Stack Trace from Exceptions:**
    - `Exception::CreateMessage`, `Exception::GetStackTrace`, `Exception::CaptureStackTrace`: Functions to extract information from JavaScript exceptions.

53. **Previewing Object Entries (Maps/Sets):**
    - `Object::PreviewEntries`:  Provides a way to get a preview of the entries in Map and Set objects.

54. **CPU Profiling:**
    - Classes and functions related to CPU profiling (`CpuProfileNode`, `CpuProfile`, `CpuProfiler`, `CpuProfilingOptions`, `CodeEvent`). These allow starting, stopping, and analyzing CPU profiles of JavaScript execution.

**Relationship to JavaScript and Examples:**

The `v8::Isolate` class and its methods are fundamental to embedding the V8 engine in a C++ application. While you don't directly interact with `v8::Isolate` objects in standard JavaScript code, its functionalities enable the features you use.

Here are some examples linking the C++ code to JavaScript behavior:

1. **Creating and Disposing of V8 Instances:**
   ```javascript
   // In a Node.js environment (which uses V8):
   // The creation of the V8 isolate is handled internally.
   // You don't directly create or dispose of isolates.
   ```
   The `Isolate::New` and `Isolate::Dispose` methods in C++ are used internally by environments like Node.js to manage V8 instances.

2. **Garbage Collection:**
   ```javascript
   // JavaScript:
   // Garbage collection happens automatically.
   // You might trigger it indirectly through memory allocation patterns.

   // Manually triggering GC (only available with --expose-gc flag):
   if (global.gc) {
     global.gc();
   }
   ```
   The `Isolate::RequestGarbageCollectionForTesting` method in C++ (used with the `--expose-gc` flag) allows triggering GC, which is the underlying mechanism for JavaScript's automatic memory management.

3. **Handling Uncaught Exceptions:**
   ```javascript
   // JavaScript:
   try {
     throw new Error("Something went wrong!");
   } catch (e) {
     console.error("Caught an error:", e.message);
   }

   // If not caught:
   // Uncaught Error: Something went wrong!
   //     at <anonymous>:2:7
   ```
   The `Isolate::SetAbortOnUncaughtExceptionCallback` method in C++ allows the embedder to customize how uncaught JavaScript exceptions are handled.

4. **Dynamic Imports:**
   ```javascript
   // JavaScript:
   async function loadModule() {
     const module = await import('./my-module.js');
     module.doSomething();
   }
   loadModule();
   ```
   The `Isolate::SetHostImportModuleDynamicallyCallback` method in C++ provides a hook for the embedder to control how dynamic imports are resolved and loaded.

5. **Microtasks (Promises, async/await):**
   ```javascript
   // JavaScript:
   Promise.resolve().then(() => console.log("Microtask executed"));
   console.log("Synchronous code");
   ```
   The `Isolate::PerformMicrotaskCheckpoint`, `Isolate::EnqueueMicrotask`, and related methods manage the microtask queue, which is crucial for the execution of Promises and `async/await` in JavaScript.

6. **CPU Profiling:**
   ```javascript
   // In Node.js (using the 'v8-profiler' module or built-in inspector APIs):
   const profiler = require('v8-profiler-next');
   profiler.startProfiling('My Profile');
   // ... some code to profile ...
   const profile = profiler.stopProfiling('My Profile');
   profile.export(function(error, result) {
     // Save the profile to a file
   });
   ```
   The `CpuProfiler` class and its methods in C++ provide the underlying implementation for JavaScript CPU profiling tools.

In summary, this section of `api.cc` defines the core functionalities of a V8 isolate, providing the foundation for executing JavaScript code and managing the JavaScript runtime environment within a C++ embedding. It exposes a wide range of control and introspection capabilities to the embedder.

```cpp
#include "v8/src/api/api.h"

#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "include/v8-metrics.h"
#include "include/v8-platform.h"
#include "include/v8-profiler.h"
#include "src/base/atomic-utils.h"
#include "src/base/embedded-file-reader.h"
#include "src/base/logging.h"
#include "src/base/platform/mutex.h"
#include "src/base/strings.h"
#include "src/codegen/compilation-cache.h"
#include "src/common/globals.h"
#include "src/common/ptr-compr-inl.h"
#include "src/core/code-event-logger.h"
#include "src/core/counters.h"
#include "src/core/cpu-profiler.h"
#include "src/core/date/date.h"
#include "src/core/debug/debug.h"
#include "src/core/execution/isolate.h"
#include "src/core/execution/microtask-queue.h"
#include "src/core/execution/vm-state-inl.h"
#include "src/core/heap/embedder-tracing.h"
#include "src/core/heap/gc-tracer.h"
#include "src/core/heap/heap-inl.h"
#include "src/core/heap/read-only-heap.h"
#include "src/core/inspector/string-mirror.h"
#include "src/core/logging/counters-scopes.h"
#include "src/core/logging/log.h"
#include "src/core/objects/allocation-site-inl.h"
#include "src/core/objects/js-array-buffer-inl.h"
#include "src/core/objects/js-collection-inl.h"
#include "src/core/objects/lookup-inl.h"
#include "src/core/profiler/cpu-profiler-inl.h"
#include "src/core/profiler/profile-generator.h"
#include "src/core/root-finder.h"
#include "src/core/snapshot/snapshot.h"
#include "src/core/strings/string-builder-inl.h"
#include "src/core/strings/string-search.h"
#include "src/core/wasm/wasm-engine.h"
#include "src/core/wasm/wasm-js.h"
#include "src/execution/isolate-inl.h"
#include "src/handles/handles-inl.h"
#include "src/heap/factory.h"
#include "src/heap/gc-idle-time-handler.h"
#include "src/heap/heap-write-barrier-inl.h"
#include "src/logging/tracing-inl.h"
#include "src/objects/api-callbacks.h"
#include "src/objects/cell.h"
#include "src/objects/code.h"
#include "src/objects/foreign.h"
#include "src/objects/heap-object.h"
#include "src/objects/internal-indexables.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-collection.h"
#include "src/objects/js-generator.h"
#include "src/objects/js-promise.h"
#include "src/objects/lookup.h"
#include "src/objects/map.h"
#include "src/objects/microtask.h"
#include "src/objects/objects-inl.h"
#include "src/objects/prototype.h"
#include "src/objects/slots.h"
#include "src/objects/source-text-module.h"
#include "src/objects/stack-frame-info-inl.h"
#include "src/objects/visitors.h"
#include "src/runtime/runtime.h"
#include "src/strings/string-hasher.h"
#include "src/tracing/tracing-category-observer.h"
#include "src/utils/utils-inl.h"
#include "v8/include/v8-util.h"

namespace v8 {

void Isolate::SetAllowCodeGenerationFromStringsCallback(
    AllowCodeGenerationFromStringsCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->set_allow_code_gen_callback(callback);
}

void Isolate::AttachCppHeap(CppHeap* cpp_heap) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isol
Prompt: 
```
这是目录为v8/src/api/api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第7部分，共8部分，请归纳一下它的功能

"""
ate*>(this);
  i_isolate->heap()->AttachCppHeap(cpp_heap);
}

void Isolate::DetachCppHeap() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->DetachCppHeap();
}

CppHeap* Isolate::GetCppHeap() const {
  const i::Isolate* i_isolate = reinterpret_cast<const i::Isolate*>(this);
  return i_isolate->heap()->cpp_heap();
}

void Isolate::SetGetExternallyAllocatedMemoryInBytesCallback(
    GetExternallyAllocatedMemoryInBytesCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->SetGetExternallyAllocatedMemoryInBytesCallback(callback);
}

void Isolate::TerminateExecution() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->stack_guard()->RequestTerminateExecution();
}

bool Isolate::IsExecutionTerminating() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
#ifdef DEBUG
  // This method might be called on a thread that's not bound to any Isolate
  // and thus pointer compression schemes might have cage base value unset.
  // Read-only roots accessors contain type DCHECKs which require access to
  // V8 heap in order to check the object type. So, allow heap access here
  // to let the checks work.
  i::PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
#endif  // DEBUG
  return i_isolate->is_execution_terminating();
}

void Isolate::CancelTerminateExecution() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->stack_guard()->ClearTerminateExecution();
  i_isolate->CancelTerminateExecution();
}

void Isolate::RequestInterrupt(InterruptCallback callback, void* data) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->RequestInterrupt(callback, data);
}

bool Isolate::HasPendingBackgroundTasks() {
#if V8_ENABLE_WEBASSEMBLY
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return i::wasm::GetWasmEngine()->HasRunningCompileJob(i_isolate);
#else
  return false;
#endif  // V8_ENABLE_WEBASSEMBLY
}

void Isolate::RequestGarbageCollectionForTesting(GarbageCollectionType type) {
  Utils::ApiCheck(i::v8_flags.expose_gc,
                  "v8::Isolate::RequestGarbageCollectionForTesting",
                  "Must use --expose-gc");
  if (type == kMinorGarbageCollection) {
    reinterpret_cast<i::Isolate*>(this)->heap()->CollectGarbage(
        i::NEW_SPACE, i::GarbageCollectionReason::kTesting,
        kGCCallbackFlagForced);
  } else {
    DCHECK_EQ(kFullGarbageCollection, type);
    reinterpret_cast<i::Isolate*>(this)->heap()->PreciseCollectAllGarbage(
        i::GCFlag::kNoFlags, i::GarbageCollectionReason::kTesting,
        kGCCallbackFlagForced);
  }
}

void Isolate::RequestGarbageCollectionForTesting(GarbageCollectionType type,
                                                 StackState stack_state) {
  std::optional<i::EmbedderStackStateScope> stack_scope;
  if (type == kFullGarbageCollection) {
    stack_scope.emplace(reinterpret_cast<i::Isolate*>(this)->heap(),
                        i::EmbedderStackStateOrigin::kExplicitInvocation,
                        stack_state);
  }
  RequestGarbageCollectionForTesting(type);
}

Isolate* Isolate::GetCurrent() {
  i::Isolate* i_isolate = i::Isolate::Current();
  return reinterpret_cast<Isolate*>(i_isolate);
}

Isolate* Isolate::TryGetCurrent() {
  i::Isolate* i_isolate = i::Isolate::TryGetCurrent();
  return reinterpret_cast<Isolate*>(i_isolate);
}

bool Isolate::IsCurrent() const {
  return reinterpret_cast<const i::Isolate*>(this)->IsCurrent();
}

// static
Isolate* Isolate::Allocate() {
  return reinterpret_cast<Isolate*>(i::Isolate::New());
}

Isolate::CreateParams::CreateParams() = default;

Isolate::CreateParams::~CreateParams() = default;

// static
// This is separate so that tests can provide a different |isolate|.
void Isolate::Initialize(Isolate* v8_isolate,
                         const v8::Isolate::CreateParams& params) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  TRACE_EVENT_CALL_STATS_SCOPED(i_isolate, "v8", "V8.IsolateInitialize");
  if (auto allocator = params.array_buffer_allocator_shared) {
    CHECK(params.array_buffer_allocator == nullptr ||
          params.array_buffer_allocator == allocator.get());
    i_isolate->set_array_buffer_allocator(allocator.get());
    i_isolate->set_array_buffer_allocator_shared(std::move(allocator));
  } else {
    CHECK_NOT_NULL(params.array_buffer_allocator);
    i_isolate->set_array_buffer_allocator(params.array_buffer_allocator);
  }
  if (params.snapshot_blob != nullptr) {
    i_isolate->set_snapshot_blob(params.snapshot_blob);
  } else {
    i_isolate->set_snapshot_blob(i::Snapshot::DefaultSnapshotBlob());
  }

  if (params.fatal_error_callback) {
    v8_isolate->SetFatalErrorHandler(params.fatal_error_callback);
  }

#if __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
  if (params.oom_error_callback) {
    v8_isolate->SetOOMErrorHandler(params.oom_error_callback);
  }
#if __clang__
#pragma clang diagnostic pop
#endif

  if (params.counter_lookup_callback) {
    v8_isolate->SetCounterFunction(params.counter_lookup_callback);
  }

  if (params.create_histogram_callback) {
    v8_isolate->SetCreateHistogramFunction(params.create_histogram_callback);
  }

  if (params.add_histogram_sample_callback) {
    v8_isolate->SetAddHistogramSampleFunction(
        params.add_histogram_sample_callback);
  }

  i_isolate->set_api_external_references(params.external_references);
  i_isolate->set_allow_atomics_wait(params.allow_atomics_wait);

  i_isolate->heap()->ConfigureHeap(params.constraints, params.cpp_heap);
  if (params.constraints.stack_limit() != nullptr) {
    uintptr_t limit =
        reinterpret_cast<uintptr_t>(params.constraints.stack_limit());
    i_isolate->stack_guard()->SetStackLimit(limit);
  }

  // TODO(v8:2487): Once we got rid of Isolate::Current(), we can remove this.
  Isolate::Scope isolate_scope(v8_isolate);
  if (i_isolate->snapshot_blob() == nullptr) {
    FATAL(
        "V8 snapshot blob was not set during initialization. This can mean "
        "that the snapshot blob file is corrupted or missing.");
  }
  if (!i::Snapshot::Initialize(i_isolate)) {
    // If snapshot data was provided and we failed to deserialize it must
    // have been corrupted.
    FATAL(
        "Failed to deserialize the V8 snapshot blob. This can mean that the "
        "snapshot blob file is corrupted or missing.");
  }

  {
    // Set up code event handlers. Needs to be after i::Snapshot::Initialize
    // because that is where we add the isolate to WasmEngine.
    auto code_event_handler = params.code_event_handler;
    if (code_event_handler) {
      v8_isolate->SetJitCodeEventHandler(kJitCodeEventEnumExisting,
                                         code_event_handler);
    }
  }

  i_isolate->set_embedder_wrapper_type_index(
      params.embedder_wrapper_type_index);
  i_isolate->set_embedder_wrapper_object_index(
      params.embedder_wrapper_object_index);

  if (!i::V8::GetCurrentPlatform()
           ->GetForegroundTaskRunner(v8_isolate)
           ->NonNestableTasksEnabled()) {
    FATAL(
        "The current platform's foreground task runner does not have "
        "non-nestable tasks enabled. The embedder must provide one.");
  }
}

Isolate* Isolate::New(const Isolate::CreateParams& params) {
  Isolate* v8_isolate = Allocate();
  Initialize(v8_isolate, params);
  return v8_isolate;
}

void Isolate::Dispose() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  if (!Utils::ApiCheck(!i_isolate->IsInUse(), "v8::Isolate::Dispose()",
                       "Disposing the isolate that is entered by a thread")) {
    return;
  }
  i::Isolate::Delete(i_isolate);
}

void Isolate::DumpAndResetStats() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
#ifdef DEBUG
  // This method might be called on a thread that's not bound to any Isolate
  // and thus pointer compression schemes might have cage base value unset.
  // Read-only roots accessors contain type DCHECKs which require access to
  // V8 heap in order to check the object type. So, allow heap access here
  // to let the checks work.
  i::PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
#endif  // DEBUG
  i_isolate->DumpAndResetStats();
}

void Isolate::DiscardThreadSpecificMetadata() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->DiscardPerThreadDataForThisThread();
}

void Isolate::Enter() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->Enter();
}

void Isolate::Exit() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->Exit();
}

void Isolate::SetAbortOnUncaughtExceptionCallback(
    AbortOnUncaughtExceptionCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetAbortOnUncaughtExceptionCallback(callback);
}

void Isolate::SetHostImportModuleDynamicallyCallback(
    HostImportModuleDynamicallyCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetHostImportModuleDynamicallyCallback(callback);
}

void Isolate::SetHostImportModuleWithPhaseDynamicallyCallback(
    HostImportModuleWithPhaseDynamicallyCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetHostImportModuleWithPhaseDynamicallyCallback(callback);
}

void Isolate::SetHostInitializeImportMetaObjectCallback(
    HostInitializeImportMetaObjectCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetHostInitializeImportMetaObjectCallback(callback);
}

void Isolate::SetHostCreateShadowRealmContextCallback(
    HostCreateShadowRealmContextCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetHostCreateShadowRealmContextCallback(callback);
}

void Isolate::SetPrepareStackTraceCallback(PrepareStackTraceCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetPrepareStackTraceCallback(callback);
}

int Isolate::GetStackTraceLimit() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  int stack_trace_limit = 0;
  if (!i_isolate->GetStackTraceLimit(i_isolate, &stack_trace_limit)) {
    return i::v8_flags.stack_trace_limit;
  }
  return stack_trace_limit;
}

Isolate::DisallowJavascriptExecutionScope::DisallowJavascriptExecutionScope(
    Isolate* v8_isolate,
    Isolate::DisallowJavascriptExecutionScope::OnFailure on_failure)
    : v8_isolate_(v8_isolate), on_failure_(on_failure) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  switch (on_failure_) {
    case CRASH_ON_FAILURE:
      i::DisallowJavascriptExecution::Open(i_isolate, &was_execution_allowed_);
      break;
    case THROW_ON_FAILURE:
      i::ThrowOnJavascriptExecution::Open(i_isolate, &was_execution_allowed_);
      break;
    case DUMP_ON_FAILURE:
      i::DumpOnJavascriptExecution::Open(i_isolate, &was_execution_allowed_);
      break;
  }
}

Isolate::DisallowJavascriptExecutionScope::~DisallowJavascriptExecutionScope() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate_);
  switch (on_failure_) {
    case CRASH_ON_FAILURE:
      i::DisallowJavascriptExecution::Close(i_isolate, was_execution_allowed_);
      break;
    case THROW_ON_FAILURE:
      i::ThrowOnJavascriptExecution::Close(i_isolate, was_execution_allowed_);
      break;
    case DUMP_ON_FAILURE:
      i::DumpOnJavascriptExecution::Close(i_isolate, was_execution_allowed_);
      break;
  }
}

Isolate::AllowJavascriptExecutionScope::AllowJavascriptExecutionScope(
    Isolate* v8_isolate)
    : v8_isolate_(v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::AllowJavascriptExecution::Open(i_isolate, &was_execution_allowed_assert_);
  i::NoThrowOnJavascriptExecution::Open(i_isolate,
                                        &was_execution_allowed_throws_);
  i::NoDumpOnJavascriptExecution::Open(i_isolate, &was_execution_allowed_dump_);
}

Isolate::AllowJavascriptExecutionScope::~AllowJavascriptExecutionScope() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate_);
  i::AllowJavascriptExecution::Close(i_isolate, was_execution_allowed_assert_);
  i::NoThrowOnJavascriptExecution::Close(i_isolate,
                                         was_execution_allowed_throws_);
  i::NoDumpOnJavascriptExecution::Close(i_isolate, was_execution_allowed_dump_);
}

Isolate::SuppressMicrotaskExecutionScope::SuppressMicrotaskExecutionScope(
    Isolate* v8_isolate, MicrotaskQueue* microtask_queue)
    : i_isolate_(reinterpret_cast<i::Isolate*>(v8_isolate)),
      microtask_queue_(microtask_queue
                           ? static_cast<i::MicrotaskQueue*>(microtask_queue)
                           : i_isolate_->default_microtask_queue()) {
  i_isolate_->thread_local_top()->IncrementCallDepth<true>(this);
  microtask_queue_->IncrementMicrotasksSuppressions();
}

Isolate::SuppressMicrotaskExecutionScope::~SuppressMicrotaskExecutionScope() {
  microtask_queue_->DecrementMicrotasksSuppressions();
  i_isolate_->thread_local_top()->DecrementCallDepth(this);
}

i::ValueHelper::InternalRepresentationType Isolate::GetDataFromSnapshotOnce(
    size_t index) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  auto list = i::Cast<i::FixedArray>(i_isolate->heap()->serialized_objects());
  return GetSerializedDataFromFixedArray(i_isolate, list, index);
}

Local<Value> Isolate::GetContinuationPreservedEmbedderData() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  return ToApiHandle<Object>(i::direct_handle(
      i_isolate->isolate_data()->continuation_preserved_embedder_data(),
      i_isolate));
#else   // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  return v8::Undefined(reinterpret_cast<v8::Isolate*>(i_isolate));
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
}

void Isolate::SetContinuationPreservedEmbedderData(Local<Value> data) {
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  if (data.IsEmpty())
    data = v8::Undefined(reinterpret_cast<v8::Isolate*>(this));
  i_isolate->isolate_data()->set_continuation_preserved_embedder_data(
      *Utils::OpenDirectHandle(*data));
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
}

void Isolate::GetHeapStatistics(HeapStatistics* heap_statistics) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Heap* heap = i_isolate->heap();

  heap->FreeMainThreadLinearAllocationAreas();

  // The order of acquiring memory statistics is important here. We query in
  // this order because of concurrent allocation: 1) used memory 2) comitted
  // physical memory 3) committed memory. Therefore the condition used <=
  // committed physical <= committed should hold.
  heap_statistics->used_global_handles_size_ = heap->UsedGlobalHandlesSize();
  heap_statistics->total_global_handles_size_ = heap->TotalGlobalHandlesSize();
  DCHECK_LE(heap_statistics->used_global_handles_size_,
            heap_statistics->total_global_handles_size_);

  heap_statistics->used_heap_size_ = heap->SizeOfObjects();
  heap_statistics->total_physical_size_ = heap->CommittedPhysicalMemory();
  heap_statistics->total_heap_size_ = heap->CommittedMemory();

  heap_statistics->total_available_size_ = heap->Available();

  if (!i::ReadOnlyHeap::IsReadOnlySpaceShared()) {
    i::ReadOnlySpace* ro_space = heap->read_only_space();
    heap_statistics->used_heap_size_ += ro_space->Size();
    heap_statistics->total_physical_size_ +=
        ro_space->CommittedPhysicalMemory();
    heap_statistics->total_heap_size_ += ro_space->CommittedMemory();
  }

  // TODO(dinfuehr): Right now used <= committed physical does not hold. Fix
  // this and add DCHECK.
  DCHECK_LE(heap_statistics->used_heap_size_,
            heap_statistics->total_heap_size_);

  heap_statistics->total_heap_size_executable_ =
      heap->CommittedMemoryExecutable();
  heap_statistics->heap_size_limit_ = heap->MaxReserved();
  // TODO(7424): There is no public API for the {WasmEngine} yet. Once such an
  // API becomes available we should report the malloced memory separately. For
  // now we just add the values, thereby over-approximating the peak slightly.
  heap_statistics->malloced_memory_ =
      i_isolate->allocator()->GetCurrentMemoryUsage() +
      i_isolate->string_table()->GetCurrentMemoryUsage();
  // On 32-bit systems backing_store_bytes() might overflow size_t temporarily
  // due to concurrent array buffer sweeping.
  heap_statistics->external_memory_ =
      i_isolate->heap()->backing_store_bytes() < SIZE_MAX
          ? static_cast<size_t>(i_isolate->heap()->backing_store_bytes())
          : SIZE_MAX;
  heap_statistics->peak_malloced_memory_ =
      i_isolate->allocator()->GetMaxMemoryUsage();
  heap_statistics->number_of_native_contexts_ = heap->NumberOfNativeContexts();
  heap_statistics->number_of_detached_contexts_ =
      heap->NumberOfDetachedContexts();
  heap_statistics->does_zap_garbage_ = i::heap::ShouldZapGarbage();

#if V8_ENABLE_WEBASSEMBLY
  heap_statistics->malloced_memory_ +=
      i::wasm::GetWasmEngine()->allocator()->GetCurrentMemoryUsage();
  heap_statistics->peak_malloced_memory_ +=
      i::wasm::GetWasmEngine()->allocator()->GetMaxMemoryUsage();
#endif  // V8_ENABLE_WEBASSEMBLY
}

size_t Isolate::NumberOfHeapSpaces() {
  return i::LAST_SPACE - i::FIRST_SPACE + 1;
}

bool Isolate::GetHeapSpaceStatistics(HeapSpaceStatistics* space_statistics,
                                     size_t index) {
  if (!space_statistics) return false;
  if (!i::Heap::IsValidAllocationSpace(static_cast<i::AllocationSpace>(index)))
    return false;

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Heap* heap = i_isolate->heap();

  heap->FreeMainThreadLinearAllocationAreas();

  i::AllocationSpace allocation_space = static_cast<i::AllocationSpace>(index);
  space_statistics->space_name_ = i::ToString(allocation_space);

  if (allocation_space == i::RO_SPACE) {
    if (i::ReadOnlyHeap::IsReadOnlySpaceShared()) {
      // RO_SPACE memory is accounted for elsewhere when ReadOnlyHeap is shared.
      space_statistics->space_size_ = 0;
      space_statistics->space_used_size_ = 0;
      space_statistics->space_available_size_ = 0;
      space_statistics->physical_space_size_ = 0;
    } else {
      i::ReadOnlySpace* space = heap->read_only_space();
      space_statistics->space_size_ = space->CommittedMemory();
      space_statistics->space_used_size_ = space->Size();
      space_statistics->space_available_size_ = 0;
      space_statistics->physical_space_size_ = space->CommittedPhysicalMemory();
    }
  } else {
    i::Space* space = heap->space(static_cast<int>(index));
    space_statistics->space_size_ = space ? space->CommittedMemory() : 0;
    space_statistics->space_used_size_ = space ? space->SizeOfObjects() : 0;
    space_statistics->space_available_size_ = space ? space->Available() : 0;
    space_statistics->physical_space_size_ =
        space ? space->CommittedPhysicalMemory() : 0;
  }
  return true;
}

size_t Isolate::NumberOfTrackedHeapObjectTypes() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Heap* heap = i_isolate->heap();
  return heap->NumberOfTrackedHeapObjectTypes();
}

bool Isolate::GetHeapObjectStatisticsAtLastGC(
    HeapObjectStatistics* object_statistics, size_t type_index) {
  if (!object_statistics) return false;
  if (V8_LIKELY(!i::TracingFlags::is_gc_stats_enabled())) return false;

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Heap* heap = i_isolate->heap();
  if (type_index >= heap->NumberOfTrackedHeapObjectTypes()) return false;

  const char* object_type;
  const char* object_sub_type;
  size_t object_count = heap->ObjectCountAtLastGC(type_index);
  size_t object_size = heap->ObjectSizeAtLastGC(type_index);
  if (!heap->GetObjectTypeName(type_index, &object_type, &object_sub_type)) {
    // There should be no objects counted when the type is unknown.
    DCHECK_EQ(object_count, 0U);
    DCHECK_EQ(object_size, 0U);
    return false;
  }

  object_statistics->object_type_ = object_type;
  object_statistics->object_sub_type_ = object_sub_type;
  object_statistics->object_count_ = object_count;
  object_statistics->object_size_ = object_size;
  return true;
}

bool Isolate::GetHeapCodeAndMetadataStatistics(
    HeapCodeStatistics* code_statistics) {
  if (!code_statistics) return false;

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->CollectCodeStatistics();

  code_statistics->code_and_metadata_size_ =
      i_isolate->code_and_metadata_size();
  code_statistics->bytecode_and_metadata_size_ =
      i_isolate->bytecode_and_metadata_size();
  code_statistics->external_script_source_size_ =
      i_isolate->external_script_source_size();
  code_statistics->cpu_profiler_metadata_size_ =
      i::CpuProfiler::GetAllProfilersMemorySize(i_isolate);

  return true;
}

bool Isolate::MeasureMemory(std::unique_ptr<MeasureMemoryDelegate> delegate,
                            MeasureMemoryExecution execution) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return i_isolate->heap()->MeasureMemory(std::move(delegate), execution);
}

std::unique_ptr<MeasureMemoryDelegate> MeasureMemoryDelegate::Default(
    Isolate* v8_isolate, Local<Context> context,
    Local<Promise::Resolver> promise_resolver, MeasureMemoryMode mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  return i_isolate->heap()->CreateDefaultMeasureMemoryDelegate(
      context, promise_resolver, mode);
}

void Isolate::GetStackSample(const RegisterState& state, void** frames,
                             size_t frames_limit, SampleInfo* sample_info) {
  RegisterState regs = state;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  if (i::TickSample::GetStackSample(i_isolate, &regs,
                                    i::TickSample::kSkipCEntryFrame, frames,
                                    frames_limit, sample_info)) {
    return;
  }
  sample_info->frames_count = 0;
  sample_info->vm_state = OTHER;
  sample_info->external_callback_entry = nullptr;
}

int64_t Isolate::AdjustAmountOfExternalAllocatedMemory(
    int64_t change_in_bytes) {
  // Try to check for unreasonably large or small values from the embedder.
  static constexpr int64_t kMaxReasonableBytes = int64_t(1) << 60;
  static constexpr int64_t kMinReasonableBytes = -kMaxReasonableBytes;
  static_assert(kMaxReasonableBytes >= i::JSArrayBuffer::kMaxByteLength);
  CHECK(kMinReasonableBytes <= change_in_bytes &&
        change_in_bytes < kMaxReasonableBytes);

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  const uint64_t amount =
      i_isolate->heap()->UpdateExternalMemory(change_in_bytes);

  if (change_in_bytes <= 0) {
    return amount;
  }

  if (amount > i_isolate->heap()->external_memory_limit_for_interrupt()) {
    HandleExternalMemoryInterrupt();
  }
  return amount;
}

void Isolate::SetEventLogger(LogEventCallback that) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->set_event_logger(that);
}

void Isolate::AddBeforeCallEnteredCallback(BeforeCallEnteredCallback callback) {
  if (callback == nullptr) return;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->AddBeforeCallEnteredCallback(callback);
}

void Isolate::RemoveBeforeCallEnteredCallback(
    BeforeCallEnteredCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->RemoveBeforeCallEnteredCallback(callback);
}

void Isolate::AddCallCompletedCallback(CallCompletedCallback callback) {
  if (callback == nullptr) return;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->AddCallCompletedCallback(callback);
}

void Isolate::RemoveCallCompletedCallback(CallCompletedCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->RemoveCallCompletedCallback(callback);
}

void Isolate::AtomicsWaitWakeHandle::Wake() {
  reinterpret_cast<i::AtomicsWaitWakeHandle*>(this)->Wake();
}

void Isolate::SetAtomicsWaitCallback(AtomicsWaitCallback callback, void* data) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetAtomicsWaitCallback(callback, data);
}

void Isolate::SetPromiseHook(PromiseHook hook) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetPromiseHook(hook);
}

void Isolate::SetPromiseRejectCallback(PromiseRejectCallback callback) {
  if (callback == nullptr) return;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetPromiseRejectCallback(callback);
}

void Isolate::SetExceptionPropagationCallback(
    ExceptionPropagationCallback callback) {
  if (callback == nullptr) return;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetExceptionPropagationCallback(callback);
}

void Isolate::PerformMicrotaskCheckpoint() {
  DCHECK_NE(MicrotasksPolicy::kScoped, GetMicrotasksPolicy());
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->default_microtask_queue()->PerformCheckpoint(this);
}

void Isolate::EnqueueMicrotask(Local<Function> v8_function) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  auto function = Utils::OpenHandle(*v8_function);
  i::Handle<i::NativeContext> handler_context;
  if (!i::JSReceiver::GetContextForMicrotask(function).ToHandle(
          &handler_context))
    handler_context = i_isolate->native_context();
  MicrotaskQueue* microtask_queue = handler_context->microtask_queue();
  if (microtask_queue) microtask_queue->EnqueueMicrotask(this, v8_function);
}

void Isolate::EnqueueMicrotask(MicrotaskCallback callback, void* data) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->default_microtask_queue()->EnqueueMicrotask(this, callback, data);
}

void Isolate::SetMicrotasksPolicy(MicrotasksPolicy policy) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->default_microtask_queue()->set_microtasks_policy(policy);
}

MicrotasksPolicy Isolate::GetMicrotasksPolicy() const {
  i::Isolate* i_isolate =
      reinterpret_cast<i::Isolate*>(const_cast<Isolate*>(this));
  return i_isolate->default_microtask_queue()->microtasks_policy();
}

void Isolate::AddMicrotasksCompletedCallback(
    MicrotasksCompletedCallbackWithData callback, void* data) {
  DCHECK(callback);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->default_microtask_queue()->AddMicrotasksCompletedCallback(callback,
                                                                       data);
}

void Isolate::RemoveMicrotasksCompletedCallback(
    MicrotasksCompletedCallbackWithData callback, void* data) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->default_microtask_queue()->RemoveMicrotasksCompletedCallback(
      callback, data);
}

void Isolate::SetUseCounterCallback(UseCounterCallback callback) {
  reinterpret_cast<i::Isolate*>(this)->SetUseCounterCallback(callback);
}

void Isolate::SetCounterFunction(CounterLookupCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->counters()->ResetCounterFunction(callback);
}

void Isolate::SetCreateHistogramFunction(CreateHistogramCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->counters()->ResetCreateHistogramFunction(callback);
}

void Isolate::SetAddHistogramSampleFunction(
    AddHistogramSampleCallback callback) {
  reinterpret_cast<i::Isolate*>(this)
      ->counters()
      ->SetAddHistogramSampleFunction(callback);
}

void Isolate::SetMetricsRecorder(
    const std::shared_ptr<metrics::Recorder>& metrics_recorder) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->metrics_recorder()->SetEmbedderRecorder(i_isolate,
                                                     metrics_recorder);
}

void Isolate::SetAddCrashKeyCallback(AddCrashKeyCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetAddCrashKeyCallback(callback);
}

void Isolate::LowMemoryNotification() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  {
    i::NestedTimedHistogramScope idle_notification_scope(
        i_isolate->counters()->gc_low_memory_notification());
    TRACE_EVENT0("v8", "V8.GCLowMemoryNotification");
#ifdef DEBUG
    // This method might be called on a thread that's not bound to any Isolate
    // and thus pointer compression schemes might have cage base value unset.
    // Read-only roots accessors contain type DCHECKs which require access to
    // V8 heap in order to check the object type. So, allow heap access here
    // to let the checks work.
    i::PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
#endif  // DEBUG
    i_isolate->heap()->CollectAllAvailableGarbage(
        i::GarbageCollectionReason::kLowMemoryNotification);
  }
}

int Isolate::ContextDisposedNotification(bool dependant_context) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
#if V8_ENABLE_WEBASSEMBLY
  if (!dependant_context) {
    if (!i_isolate->context().is_null()) {
      // We left the current context, we can abort all WebAssembly compilations
      // of that context.
      // A handle scope for the native context.
      i::HandleScope handle_scope(i_isolate);
      i::wasm::GetWasmEngine()->DeleteCompileJobsOnContext(
          i_isolate->native_context());
    }
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  i_isolate->AbortConcurrentOptimization(i::BlockingBehavior::kDontBlock);
  // TODO(ahaas): move other non-heap activity out of the heap call.
  return i_isolate->heap()->NotifyContextDisposed(dependant_context);
}

void Isolate::IsolateInForegroundNotification() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return i_isolate->SetPriority(Priority::kUserBlocking);
}

void Isolate::IsolateInBackgroundNotification() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return i_isolate->SetPriority(Priority::kBestEffort);
}

void Isolate::SetPriority(Priority priority) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return i_isolate->SetPriority(priority);
}

void Isolate::MemoryPressureNotification(MemoryPressureLevel level) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  bool on_isolate_thread =
      i_isolate->was_locker_ever_used()
          ? i_isolate->thread_manager()->IsLockedByCurrentThread()
          : i::ThreadId::Current() == i_isolate->thread_id();
  i_isolate->heap()->MemoryPressureNotification(level, on_isolate_thread);
}

void Isolate::SetBatterySaverMode(bool battery_saver_mode_enabled) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->set_battery_saver_mode_enabled(battery_saver_mode_enabled);
}

void Isolate::ClearCachesForTesting() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->AbortConcurrentOptimization(i::BlockingBehavior::kBlock);
  i_isolate->ClearSerializerData();
  i_isolate->compilation_cache()->Clear();
}

void Isolate::SetRAILMode(RAILMode rail_mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetRAILMode(rail_mode);
}

void Isolate::UpdateLoadStartTime() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->UpdateLoadStartTime();
}

void Isolate::SetIsLoading(bool is_loading) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetIsLoading(is_loading);
}

void Isolate::IncreaseHeapLimitForDebugging() {
  // No-op.
}

void Isolate::RestoreOriginalHeapLimit() {
  // No-op.
}

bool Isolate::IsHeapLimitIncreasedForDebugging() { return false; }

void Isolate::SetJitCodeEventHandler(JitCodeEventOptions options,
                                     JitCodeEventHandler event_handler) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  // Ensure that logging is initialized for our isolate.
  i_isolate->InitializeLoggingAndCounters();
  i_isolate->v8_file_logger()->SetCodeEventHandler(options, event_handler);
}

void Isolate::SetStackLimit(uintptr_t stack_limit) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  CHECK(stack_limit);
  i_isolate->stack_guard()->SetStackLimit(stack_limit);
}

void Isolate::GetCodeRange(void** start, size_t* length_in_bytes) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  const base::AddressRegion& code_region = i_isolate->heap()->code_region();
  *start = reinterpret_cast<void*>(code_region.begin());
  *length_in_bytes = code_region.size();
}

void Isolate::GetEmbeddedCodeRange(const void** start,
                                   size_t* length_in_bytes) {
  // Note, we should return the embedded code rande from the .text section here.
  i::EmbeddedData d = i::EmbeddedData::FromBlob();
  *start = reinterpret_cast<const void*>(d.code());
  *length_in_bytes = d.code_size();
}

JSEntryStubs Isolate::GetJSEntryStubs() {
  JSEntryStubs entry_stubs;

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  std::array<std::pair<i::Builtin, JSEntryStub*>, 3> stubs = {
      {{i::Builtin::kJSEntry, &entry_stubs.js_entry_stub},
       {i::Builtin::kJSConstructEntry, &entry_stubs.js_construct_entry_stub},
       {i::Builtin::kJSRunMicrotasksEntry,
        &entry_stubs.js_run_microtasks_entry_stub}}};
  for (auto& pair : stubs) {
    i::Tagged<i::Code> js_entry = i_isolate->builtins()->code(pair.first);
    pair.second->code.start =
        reinterpret_cast<const void*>(js_entry->instruction_start());
    pair.second->code.length_in_bytes = js_entry->instruction_size();
  }

  return entry_stubs;
}

size_t Isolate::CopyCodePages(size_t capacity, MemoryRange* code_pages_out) {
#if !defined(V8_TARGET_ARCH_64_BIT) && !defined(V8_TARGET_ARCH_ARM)
  // Not implemented on other platforms.
  UNREACHABLE();
#else

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  std::vector<MemoryRange>* code_pages = i_isolate->GetCodePages();

  DCHECK_NOT_NULL(code_pages);

  // Copy as many elements into the output vector as we can. If the
  // caller-provided buffer is not big enough, we fill it, and the caller can
  // provide a bigger one next time. We do it this way because allocation is not
  // allowed in signal handlers.
  size_t limit = std::min(capacity, code_pages->size());
  for (size_t i = 0; i < limit; i++) {
    code_pages_out[i] = code_pages->at(i);
  }
  return code_pages->size();
#endif
}

#define CALLBACK_SETTER(ExternalName, Type, InternalName)        \
  void Isolate::Set##ExternalName(Type callback) {               \
    i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this); \
    i_isolate->set_##InternalName(callback);                     \
  }

CALLBACK_SETTER(FatalErrorHandler, FatalErrorCallback, exception_behavior)
CALLBACK_SETTER(OOMErrorHandler, OOMErrorCallback, oom_behavior)
CALLBACK_SETTER(ModifyCodeGenerationFromStringsCallback,
                ModifyCodeGenerationFromStringsCallback2,
                modify_code_gen_callback)
CALLBACK_SETTER(AllowWasmCodeGenerationCallback,
                AllowWasmCodeGenerationCallback, allow_wasm_code_gen_callback)

CALLBACK_SETTER(WasmModuleCallback, ExtensionCallback, wasm_module_callback)
CALLBACK_SETTER(WasmInstanceCallback, ExtensionCallback, wasm_instance_callback)

CALLBACK_SETTER(WasmStreamingCallback, WasmStreamingCallback,
                wasm_streaming_callback)

CALLBACK_SETTER(WasmAsyncResolvePromiseCallback,
                WasmAsyncResolvePromiseCallback,
                wasm_async_resolve_promise_callback)

CALLBACK_SETTER(WasmLoadSourceMapCallback, WasmLoadSourceMapCallback,
                wasm_load_source_map_callback)

CALLBACK_SETTER(WasmImportedStringsEnabledCallback,
                WasmImportedStringsEnabledCallback,
                wasm_imported_strings_enabled_callback)

CALLBACK_SETTER(WasmJSPIEnabledCallback, WasmJSPIEnabledCallback,
                wasm_jspi_enabled_callback)

CALLBACK_SETTER(SharedArrayBufferConstructorEnabledCallback,
                SharedArrayBufferConstructorEnabledCallback,
                sharedarraybuffer_constructor_enabled_callback)

// TODO(42203853): Remove this after the deprecated API is removed. Right now,
// the embedder can still set the callback, but it's never called.
CALLBACK_SETTER(JavaScriptCompileHintsMagicEnabledCallback,
                JavaScriptCompileHintsMagicEnabledCallback,
                compile_hints_magic_enabled_callback)

void Isolate::InstallConditionalFeatures(Local<Context> context) {
  v8::HandleScope handle_scope(this);
  v8::Context::Scope context_scope(context);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  if (i_isolate->is_execution_terminating()) return;
  i_isolate->InstallConditionalFeatures(Utils::OpenHandle(*context));
  if (i_isolate->has_exception()) return;
#if V8_ENABLE_WEBASSEMBLY
  i::WasmJs::InstallConditionalFeatures(i_isolate, Utils::OpenHandle(*context));
#endif  // V8_ENABLE_WEBASSEMBLY
}

void Isolate::AddNearHeapLimitCallback(v8::NearHeapLimitCallback callback,
                                       void* data) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->AddNearHeapLimitCallback(callback, data);
}

void Isolate::RemoveNearHeapLimitCallback(v8::NearHeapLimitCallback callback,
                                          size_t heap_limit) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->RemoveNearHeapLimitCallback(callback, heap_limit);
}

void Isolate::AutomaticallyRestoreInitialHeapLimit(double threshold_percent) {
  DCHECK_GT(threshold_percent, 0.0);
  DCHECK_LT(threshold_percent, 1.0);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->AutomaticallyRestoreInitialHeapLimit(threshold_percent);
}

bool Isolate::IsDead() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return i_isolate->IsDead();
}

bool Isolate::AddMessageListener(MessageCallback that, Local<Value> data) {
  return AddMessageListenerWithErrorLevel(that, kMessageError, data);
}

bool Isolate::AddMessageListenerWithErrorLevel(MessageCallback that,
                                               int message_levels,
                                               Local<Value> data) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  i::Handle<i::ArrayList> list = i_isolate->factory()->message_listeners();
  i::DirectHandle<i::FixedArray> listener =
      i_isolate->factory()->NewFixedArray(3);
  i::DirectHandle<i::Foreign> foreign =
      i_isolate->factory()->NewForeign<internal::kMessageListenerTag>(
          FUNCTION_ADDR(that));
  listener->set(0, *foreign);
  listener->set(1, data.IsEmpty()
                       ? i::ReadOnlyRoots(i_isolate).undefined_value()
                       : *Utils::OpenDirectHandle(*data));
  listener->set(2, i::Smi::FromInt(message_levels));
  list = i::ArrayList::Add(i_isolate, list, listener);
  i_isolate->heap()->SetMessageListeners(*list);
  return true;
}

void Isolate::RemoveMessageListeners(MessageCallback that) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::ArrayList> listeners = i_isolate->heap()->message_listeners();
  for (int i = 0; i < listeners->length(); i++) {
    if (i::IsUndefined(listeners->get(i), i_isolate)) {
      continue;  // skip deleted ones
    }
    i::Tagged<i::FixedArray> listener =
        i::Cast<i::FixedArray>(listeners->get(i));
    i::Tagged<i::Foreign> callback_obj = i::Cast<i::Foreign>(listener->get(0));
    if (callback_obj->foreign_address<internal::kMessageListenerTag>() ==
        FUNCTION_ADDR(that)) {
      listeners->set(i, i::ReadOnlyRoots(i_isolate).undefined_value());
    }
  }
}

void Isolate::SetFailedAccessCheckCallbackFunction(
    FailedAccessCheckCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetFailedAccessCheckCallback(callback);
}

void Isolate::SetCaptureStackTraceForUncaughtExceptions(
    bool capture, int frame_limit, StackTrace::StackTraceOptions options) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetCaptureStackTraceForUncaughtExceptions(capture, frame_limit,
                                                       options);
}

void Isolate::VisitExternalResources(ExternalResourceVisitor* visitor) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->VisitExternalResources(visitor);
}

bool Isolate::IsInUse() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return i_isolate->IsInUse();
}

void Isolate::SetAllowAtomicsWait(bool allow) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->set_allow_atomics_wait(allow);
}

void v8::Isolate::DateTimeConfigurationChangeNotification(
    TimeZoneDetection time_zone_detection) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  API_RCS_SCOPE(i_isolate, Isolate, DateTimeConfigurationChangeNotification);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i_isolate->date_cache()->ResetDateCache(
      static_cast<base::TimezoneCache::TimeZoneDetection>(time_zone_detection));
#ifdef V8_INTL_SUPPORT
  i_isolate->clear_cached_icu_object(
      i::Isolate::ICUObjectCacheType::kDefaultSimpleDateFormat);
  i_isolate->clear_cached_icu_object(
      i::Isolate::ICUObjectCacheType::kDefaultSimpleDateFormatForTime);
  i_isolate->clear_cached_icu_object(
      i::Isolate::ICUObjectCacheType::kDefaultSimpleDateFormatForDate);
#endif  // V8_INTL_SUPPORT
}

void v8::Isolate::LocaleConfigurationChangeNotification() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  API_RCS_SCOPE(i_isolate, Isolate, LocaleConfigurationChangeNotification);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);

#ifdef V8_INTL_SUPPORT
  i_isolate->ResetDefaultLocale();
#endif  // V8_INTL_SUPPORT
}

std::string Isolate::GetDefaultLocale() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);

#ifdef V8_INTL_SUPPORT
  return i_isolate->DefaultLocale();
#else
  return std::string();
#endif
}

#if defined(V8_OS_WIN) && defined(V8_ENABLE_ETW_STACK_WALKING)
void Isolate::SetFilterETWSessionByURLCallback(
    FilterETWSessionByURLCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetFilterETWSessionByURLCallback(callback);
}
#endif  // V8_OS_WIN && V8_ENABLE_ETW_STACK_WALKING

bool v8::Object::IsCodeLike(v8::Isolate* v8_isolate) const {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, Object, IsCodeLike);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  return Utils::OpenDirectHandle(this)->IsCodeLike(i_isolate);
}

// static
std::unique_ptr<MicrotaskQueue> MicrotaskQueue::New(Isolate* v8_isolate,
                                                    MicrotasksPolicy policy) {
  auto microtask_queue =
      i::MicrotaskQueue::New(reinterpret_cast<i::Isolate*>(v8_isolate));
  microtask_queue->set_microtasks_policy(policy);
  std::unique_ptr<MicrotaskQueue> ret(std::move(microtask_queue));
  return ret;
}

MicrotasksScope::MicrotasksScope(Local<Context> v8_context,
                                 MicrotasksScope::Type type)
    : MicrotasksScope(v8_context->GetIsolate(), v8_context->GetMicrotaskQueue(),
                      type) {}

MicrotasksScope::MicrotasksScope(Isolate* v8_isolate,
                                 MicrotaskQueue* microtask_queue,
                                 MicrotasksScope::Type type)
    : i_isolate_(reinterpret_cast<i::Isolate*>(v8_isolate)),
      microtask_queue_(microtask_queue
                           ? static_cast<i::MicrotaskQueue*>(microtask_queue)
                           : i_isolate_->default_microtask_queue()),
      run_(type == MicrotasksScope::kRunMicrotasks) {
  if (run_) microtask_queue_->IncrementMicrotasksScopeDepth();
#ifdef DEBUG
  if (!run_) microtask_queue_->IncrementDebugMicrotasksScopeDepth();
#endif
}

MicrotasksScope::~MicrotasksScope() {
  if (run_) {
    microtask_queue_->DecrementMicrotasksScopeDepth();
    if (MicrotasksPolicy::kScoped == microtask_queue_->microtasks_policy() &&
        !i_isolate_->has_exception()) {
      microtask_queue_->PerformCheckpoint(
          reinterpret_cast<Isolate*>(i_isolate_));
      DCHECK_IMPLIES(i_isolate_->has_exception(),
                     i_isolate_->is_execution_terminating());
    }
  }
#ifdef DEBUG
  if (!run_) microtask_queue_->DecrementDebugMicrotasksScopeDepth();
#endif
}

// static
void MicrotasksScope::PerformCheckpoint(Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  auto* microtask_queue = i_isolate->default_microtask_queue();
  microtask_queue->PerformCheckpoint(v8_isolate);
}

// static
int MicrotasksScope::GetCurrentDepth(Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  auto* microtask_queue = i_isolate->default_microtask_queue();
  return microtask_queue->GetMicrotasksScopeDepth();
}

// static
bool MicrotasksScope::IsRunningMicrotasks(Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  auto* microtask_queue = i_isolate->default_microtask_queue();
  return microtask_queue->IsRunningMicrotasks();
}

String::Utf8Value::Utf8Value(v8::Isolate* v8_isolate, v8::Local<v8::Value> obj,
                             WriteOptions options)
    : str_(nullptr), length_(0) {
  if (obj.IsEmpty()) return;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  Local<Context> context = v8_isolate->GetCurrentContext();
  ENTER_V8_BASIC(i_isolate);
  i::HandleScope scope(i_isolate);
  TryCatch try_catch(v8_isolate);
  Local<String> str;
  if (!obj->ToString(context).ToLocal(&str)) return;
  length_ = str->Utf8LengthV2(v8_isolate);
  str_ = i::NewArray<char>(length_ + 1);
  int flags = String::WriteFlags::kNullTerminate;
  if (options & REPLACE_INVALID_UTF8)
    flags |= String::WriteFlags::kReplaceInvalidUtf8;
  str->WriteUtf8V2(v8_isolate, str_, length_ + 1, flags);
}

String::Utf8Value::~Utf8Value() { i::DeleteArray(str_); }

String::Value::Value(v8::Isolate* v8_isolate, v8::Local<v8::Value> obj)
    : str_(nullptr), length_(0) {
  if (obj.IsEmpty()) return;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::HandleScope scope(i_isolate);
  Local<Context> context = v8_isolate->GetCurrentContext();
  ENTER_V8_BASIC(i_isolate);
  TryCatch try_catch(v8_isolate);
  Local<String> str;
  if (!obj->ToString(context).ToLocal(&str)) return;
  length_ = str->Length();
  str_ = i::NewArray<uint16_t>(length_ + 1);
  str->WriteV2(v8_isolate, 0, length_, str_,
               String::WriteFlags::kNullTerminate);
}

String::Value::~Value() { i::DeleteArray(str_); }

String::ValueView::ValueView(v8::Isolate* v8_isolate,
                             v8::Local<v8::String> str) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::HandleScope scope(i_isolate);
  i::Handle<i::String> i_str = Utils::OpenHandle(*str);
  i::Handle<i::String> i_flat_str = i::String::Flatten(i_isolate, i_str);

  flat_str_ = Utils::ToLocal(i_flat_str);

  i::DisallowGarbageCollectionInRelease* no_gc =
      new (no_gc_debug_scope_) i::DisallowGarbageCollectionInRelease();
  i::String::FlatContent flat_content = i_flat_str->GetFlatContent(*no_gc);
  DCHECK(flat_content.IsFlat());
  is_one_byte_ = flat_content.IsOneByte();
  length_ = flat_content.length();
  if (is_one_byte_) {
    data8_ = flat_content.ToOneByteVector().data();
  } else {
    data16_ = flat_content.ToUC16Vector().data();
  }
}

String::ValueView::~ValueView() {
  using i::DisallowGarbageCollectionInRelease;
  DisallowGarbageCollectionInRelease* no_gc =
      reinterpret_cast<DisallowGarbageCollectionInRelease*>(no_gc_debug_scope_);
  no_gc->~DisallowGarbageCollectionInRelease();
}

void String::ValueView::CheckOneByte(bool is_one_byte) const {
  if (is_one_byte) {
    Utils::ApiCheck(is_one_byte_, "v8::String::ValueView::data8",
                    "Called the one-byte accessor on a two-byte string view.");
  } else {
    Utils::ApiCheck(!is_one_byte_, "v8::String::ValueView::data16",
                    "Called the two-byte accessor on a one-byte string view.");
  }
}

#define DEFINE_ERROR(NAME, name)                                              \
  Local<Value> Exception::NAME(v8::Local<v8::String> raw_message,             \
                               v8::Local<v8::Value> raw_options) {            \
    i::Isolate* i_isolate = i::Isolate::Current();                            \
    API_RCS_SCOPE(i_isolate, NAME, New);                                      \
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);                               \
    i::Tagged<i::Object> error;                                               \
    {                                                                         \
      i::HandleScope scope(i_isolate);                                        \
      i::Handle<i::Object> options;                                           \
      if (!raw_options.IsEmpty()) {                                           \
        options = Utils::OpenHandle(*raw_options);                            \
      }                                                                       \
      auto message = Utils::OpenHandle(*raw_message);                         \
      i::Handle<i::JSFunction> constructor = i_isolate->name##_function();    \
      error = *i_isolate->factory()->NewError(constructor, message, options); \
    }                                                                         \
    return Utils::ToLocal(i::direct_handle(error, i_isolate));                \
  }

DEFINE_ERROR(RangeError, range_error)
DEFINE_ERROR(ReferenceError, reference_error)
DEFINE_ERROR(SyntaxError, syntax_error)
DEFINE_ERROR(TypeError, type_error)
DEFINE_ERROR(WasmCompileError, wasm_compile_error)
DEFINE_ERROR(WasmLinkError, wasm_link_error)
DEFINE_ERROR(WasmRuntimeError, wasm_runtime_error)
DEFINE_ERROR(Error, error)

#undef DEFINE_ERROR

Local<Message> Exception::CreateMessage(Isolate* v8_isolate,
                                        Local<Value> exception) {
  auto obj = Utils::OpenHandle(*exception);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  return Utils::MessageToLocal(
      scope.CloseAndEscape(i_isolate->CreateMessage(obj, nullptr)));
}

Local<StackTrace> Exception::GetStackTrace(Local<Value> exception) {
  auto obj = Utils::OpenHandle(*exception);
  if (!IsJSObject(*obj)) return {};
  auto js_obj = i::Cast<i::JSObject>(obj);
  i::Isolate* i_isolate = js_obj->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto stack_trace = i_isolate->GetDetailedStackTrace(js_obj);
  return Utils::StackTraceToLocal(stack_trace);
}

Maybe<bool> Exception::CaptureStackTrace(Local<Context> context,
                                         Local<Object> object) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8_NO_SCRIPT(i_isolate, context, Exception, CaptureStackTrace,
                     i::HandleScope);
  auto obj = Utils::OpenHandle(*object);
  if (!IsJSObject(*obj)) return Just(false);

  auto js_obj = i::Cast<i::JSObject>(obj);

  i::FrameSkipMode mode = i::FrameSkipMode::SKIP_FIRST;

  auto result = i::ErrorUtils::CaptureStackTrace(i_isolate, js_obj, mode,
                                                 i::Handle<i::Object>());

  i::Handle<i::Object> handle;
  has_exception = !result.ToHandle(&handle);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(true);
}

v8::MaybeLocal<v8::Array> v8::Object::PreviewEntries(bool* is_key_value) {
  auto object = Utils::OpenHandle(this);
  i::Isolate* i_isolate = object->GetIsolate();
  if (i_isolate->is_execution_terminating()) return {};
  if (IsMap()) {
    *is_key_value = true;
    return Map::Cast(this)->AsArray();
  }
  if (IsSet()) {
    *is_key_value = false;
    return Set::Cast(this)->AsArray();
  }

  Isolate* v8_isolate = reinterpret_cast<Isolate*>(i_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (i::IsJSWeakCollection(*object)) {
    *is_key_value = IsJSWeakMap(*object);
    return Utils::ToLocal(i::JSWeakCollection::GetEntries(
        i::Cast<i::JSWeakCollection>(object), 0));
  }
  if (i::IsJSMapIterator(*object)) {
    auto it = i::Cast<i::JSMapIterator>(object);
    MapAsArrayKind const kind =
        static_cast<MapAsArrayKind>(it->map()->instance_type());
    *is_key_value = kind == MapAsArrayKind::kEntries;
    if (!it->HasMore()) return v8::Array::New(v8_isolate);
    return Utils::ToLocal(
        MapAsArray(i_isolate, it->table(), i::Smi::ToInt(it->index()), kind));
  }
  if (i::IsJSSetIterator(*object)) {
    auto it = i::Cast<i::JSSetIterator>(object);
    SetAsArrayKind const kind =
        static_cast<SetAsArrayKind>(it->map()->instance_type());
    *is_key_value = kind == SetAsArrayKind::kEntries;
    if (!it->HasMore()) return v8::Array::New(v8_isolate);
    return Utils::ToLocal(
        SetAsArray(i_isolate, it->table(), i::Smi::ToInt(it->index()), kind));
  }
  return v8::MaybeLocal<v8::Array>();
}

Local<String> CpuProfileNode::GetFunctionName() const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  i::Isolate* i_isolate = node->isolate();
  const i::CodeEntry* entry = node->entry();
  i::DirectHandle<i::String> name =
      i_isolate->factory()->InternalizeUtf8String(entry->name());
  return ToApiHandle<String>(name);
}

const char* CpuProfileNode::GetFunctionNameStr() const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  return node->entry()->name();
}

int CpuProfileNode::GetScriptId() const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  const i::CodeEntry* entry = node->entry();
  return entry->script_id();
}

Local<String> CpuProfileNode::GetScriptResourceName() const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  i::Isolate* i_isolate = node->isolate();
  return ToApiHandle<String>(i_isolate->factory()->InternalizeUtf8String(
      node->entry()->resource_name()));
}

const char* CpuProfileNode::GetScriptResourceNameStr() const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  return node->entry()->resource_name();
}

bool CpuProfileNode::IsScriptSharedCrossOrigin() const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  return node->entry()->is_shared_cross_origin();
}

int CpuProfileNode::GetLineNumber() const {
  return reinterpret_cast<const i::ProfileNode*>(this)->line_number();
}

int CpuProfileNode::GetColumnNumber() const {
  return reinterpret_cast<const i::ProfileNode*>(this)
      ->entry()
      ->column_number();
}

unsigned int CpuProfileNode::GetHitLineCount() const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  return node->GetHitLineCount();
}

bool CpuProfileNode::GetLineTicks(LineTick* entries,
                                  unsigned int length) const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  return node->GetLineTicks(entries, length);
}

const char* CpuProfileNode::GetBailoutReason() const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  return node->entry()->bailout_reason();
}

unsigned CpuProfileNode::GetHitCount() const {
  return reinterpret_cast<const i::ProfileNode*>(this)->self_ticks();
}

unsigned CpuProfileNode::GetNodeId() const {
  return reinterpret_cast<const i::ProfileNode*>(this)->id();
}

CpuProfileNode::SourceType CpuProfileNode::GetSourceType() const {
  return reinterpret_cast<const i::ProfileNode*>(this)->source_type();
}

int CpuProfileNode::GetChildrenCount() const {
  return static_cast<int>(
      reinterpret_cast<const i::ProfileNode*>(this)->children()->size());
}

const CpuProfileNode* CpuProfileNode::GetChild(int index) const {
  const i::ProfileNode* child =
      reinterpret_cast<const i::ProfileNode*>(this)->children()->at(index);
  return reinterpret_cast<const CpuProfileNode*>(child);
}

const CpuProfileNode* CpuProfileNode::GetParent() const {
  const i::ProfileNode* parent =
      reinterpret_cast<const i::ProfileNode*>(this)->parent();
  return reinterpret_cast<const CpuProfileNode*>(parent);
}

const std::vector<CpuProfileDeoptInfo>& CpuProfileNode::GetDeoptInfos() const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  return node->deopt_infos();
}

void CpuProfile::Delete() {
  i::CpuProfile* profile = reinterpret_cast<i::CpuProfile*>(this);
  i::CpuProfiler* profiler = profile->cpu_profiler();
  DCHECK_NOT_NULL(profiler);
  profiler->DeleteProfile(profile);
}

Local<String> CpuProfile::GetTitle() const {
  const i::CpuProfile* profile = reinterpret_cast<const i::CpuProfile*>(this);
  i::Isolate* i_isolate = profile->top_down()->isolate();
  return ToApiHandle<String>(
      i_isolate->factory()->InternalizeUtf8String(profile->title()));
}

const CpuProfileNode* CpuProfile::GetTopDownRoot() const {
  const i::CpuProfile* profile = reinterpret_cast<const i::CpuProfile*>(this);
  return reinterpret_cast<const CpuProfileNode*>(profile->top_down()->root());
}

const CpuProfileNode* CpuProfile::GetSample(int index) const {
  const i::CpuProfile* profile = reinterpret_cast<const i::CpuProfile*>(this);
  return reinterpret_cast<const CpuProfileNode*>(profile->sample(index).node);
}

const int CpuProfileNode::kNoLineNumberInfo;
const int CpuProfileNode::kNoColumnNumberInfo;

int64_t CpuProfile::GetSampleTimestamp(int index) const {
  const i::CpuProfile* profile = reinterpret_cast<const i::CpuProfile*>(this);
  return profile->sample(index).timestamp.since_origin().InMicroseconds();
}

StateTag CpuProfile::GetSampleState(int index) const {
  const i::CpuProfile* profile = reinterpret_cast<const i::CpuProfile*>(this);
  return profile->sample(index).state_tag;
}

EmbedderStateTag CpuProfile::GetSampleEmbedderState(int index) const {
  const i::CpuProfile* profile = reinterpret_cast<const i::CpuProfile*>(this);
  return profile->sample(index).embedder_state_tag;
}

int64_t CpuProfile::GetStartTime() const {
  const i::CpuProfile* profile = reinterpret_cast<const i::CpuProfile*>(this);
  return profile->start_time().since_origin().InMicroseconds();
}

int64_t CpuProfile::GetEndTime() const {
  const i::CpuProfile* profile = reinterpret_cast<const i::CpuProfile*>(this);
  return profile->end_time().since_origin().InMicroseconds();
}

static i::CpuProfile* ToInternal(const CpuProfile* profile) {
  return const_cast<i::CpuProfile*>(
      reinterpret_cast<const i::CpuProfile*>(profile));
}

void CpuProfile::Serialize(OutputStream* stream,
                           CpuProfile::SerializationFormat format) const {
  Utils::ApiCheck(format == kJSON, "v8::CpuProfile::Serialize",
                  "Unknown serialization format");
  Utils::ApiCheck(stream->GetChunkSize() > 0, "v8::CpuProfile::Serialize",
                  "Invalid stream chunk size");
  i::CpuProfileJSONSerializer serializer(ToInternal(this));
  serializer.Serialize(stream);
}

int CpuProfile::GetSamplesCount() const {
  return reinterpret_cast<const i::CpuProfile*>(this)->samples_count();
}

CpuProfiler* CpuProfiler::New(Isolate* v8_isolate,
                              CpuProfilingNamingMode naming_mode,
                              CpuProfilingLoggingMode logging_mode) {
  return reinterpret_cast<CpuProfiler*>(new i::CpuProfiler(
      reinterpret_cast<i::Isolate*>(v8_isolate), naming_mode, logging_mode));
}

CpuProfilingOptions::CpuProfilingOptions(CpuProfilingMode mode,
                                         unsigned max_samples,
                                         int sampling_interval_us,
                                         MaybeLocal<Context> filter_context)
    : mode_(mode),
      max_samples_(max_samples),
      sampling_interval_us_(sampling_interval_us) {
  if (!filter_context.IsEmpty()) {
    Local<Context> local_filter_context = filter_context.ToLocalChecked();
    filter_context_.Reset(local_filter_context->GetIsolate(),
                          local_filter_context);
    filter_context_.SetWeak();
  }
}

void* CpuProfilingOptions::raw_filter_context() const {
  return reinterpret_cast<void*>(
      i::Cast<i::Context>(*Utils::OpenPersistent(filter_context_))
          ->native_context()
          .address());
}

void CpuProfiler::Dispose() { delete reinterpret_cast<i::CpuProfiler*>(this); }

// static
void CpuProfiler::CollectSample(Isolate* v8_isolate) {
  i::CpuProfiler::CollectSample(reinterpret_cast<i::Isolate*>(v8_isolate));
}

void CpuProfiler::SetSamplingInterval(int us) {
  DCHECK_GE(us, 0);
  return reinterpret_cast<i::CpuProfiler*>(this)->set_sampling_interval(
      base::TimeDelta::FromMicroseconds(us));
}

void CpuProfiler::SetUsePreciseSampling(bool use_precise_sampling) {
  reinterpret_cast<i::CpuProfiler*>(this)->set_use_precise_sampling(
      use_precise_sampling);
}

CpuProfilingResult CpuProfiler::Start(
    CpuProfilingOptions options,
    std::unique_ptr<DiscardedSamplesDelegate> delegate) {
  return reinterpret_cast<i::CpuProfiler*>(this)->StartProfiling(
      std::move(options), std::move(delegate));
}

CpuProfilingResult CpuProfiler::Start(
    Local<String> title, CpuProfilingOptions options,
    std::unique_ptr<DiscardedSamplesDelegate> delegate) {
  return reinterpret_cast<i::CpuProfiler*>(this)->StartProfiling(
      *Utils::OpenDirectHandle(*title), std::move(options),
      std::move(delegate));
}

CpuProfilingResult CpuProfiler::Start(Local<String> title,
                                      bool record_samples) {
  CpuProfilingOptions options(
      kLeafNodeLineNumbers,
      record_samples ? CpuProfilingOptions::kNoSampleLimit : 0);
  return reinterpret_cast<i::CpuProfiler*>(this)->StartProfiling(
      *Utils::OpenDirectHandle(*title), std::move(options));
}

CpuProfilingResult CpuProfiler::Start(Local<String> title,
                                      CpuProfilingMode mode,
                                      bool record_samples,
                                      unsigned max_samples) {
  CpuProfilingOptions options(mode, record_samples ? max_samples : 0);
  return reinterpret_cast<i::CpuProfiler*>(this)->StartProfiling(
      *Utils::OpenDirectHandle(*title), std::move(options));
}

CpuProfilingStatus CpuProfiler::StartProfiling(
    Local<String> title, CpuProfilingOptions options,
    std::unique_ptr<DiscardedSamplesDelegate> delegate) {
  return Start(title, std::move(options), std::move(delegate)).status;
}

CpuProfilingStatus CpuProfiler::StartProfiling(Local<String> title,
                                               bool record_samples) {
  return Start(title, record_samples).status;
}

CpuProfilingStatus CpuProfiler::StartProfiling(Local<String> title,
                                               CpuProfilingMode mode,
                                               bool record_samples,
                                               unsigned max_samples) {
  return Start(title, mode, record_samples, max_samples).status;
}

CpuProfile* CpuProfiler::StopProfiling(Local<String> title) {
  return reinterpret_cast<CpuProfile*>(
      reinterpret_cast<i::CpuProfiler*>(this)->StopProfiling(
          *Utils::OpenDirectHandle(*title)));
}

CpuProfile* CpuProfiler::Stop(ProfilerId id) {
  return reinterpret_cast<CpuProfile*>(
      reinterpret_cast<i::CpuProfiler*>(this)->StopProfiling(id));
}

void CpuProfiler::UseDetailedSourcePositionsForProfiling(Isolate* v8_isolate) {
  reinterpret_cast<i::Isolate*>(v8_isolate)
      ->SetDetailedSourcePositionsForProfiling(true);
}

uintptr_t CodeEvent::GetCodeStartAddress() {
  return reinterpret_cast<i::CodeEvent*>(this)->code_start_address;
}

size_t CodeEvent::GetCodeSize() {
  return reinterpret_cast<i::CodeEvent*>(this)->code_size;
}

Local<String> CodeEvent::GetFunctionName() {
  return ToApiHandle<String>(
      reinterpret_cast<i::CodeEvent*>(this)->function_name);
}

Local<String> CodeEvent::GetScriptName() {
  return ToApiHandle<String>(
      reinterpret_cast<i::CodeEvent*>(this)->script_name);
}

int CodeEvent::GetScriptLine() {
  return reinterpret_cast<i::CodeEvent*>(this)->script_line;
}

int CodeEvent::GetScriptColumn() {
  return reinterpret_cast<i::CodeEvent*>(this)->script_column;
}

CodeEventType CodeEvent::GetCodeType() {
  return reinterpret_cast<i::CodeEvent*>(this)->code_type;
}

const char* CodeEvent::GetComment() {
  return reinterpret_cast<i::CodeEvent*>(this)->comment;
}

uintptr_t CodeEvent::GetPreviousCodeStartAddress() {
  return 
"""


```