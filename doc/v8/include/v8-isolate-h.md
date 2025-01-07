Response:
The user wants a summary of the functionality of the `v8/include/v8-isolate.h` header file, assuming it's a C++ header file (since it doesn't end in `.tq`). The request includes several constraints and specific points to address:

1. **List the functions:** This requires parsing the header file and extracting the class and method declarations.
2. **`.tq` check:** The file name ends in `.h`, so this part is straightforward.
3. **Relationship to Javascript (with examples):**  This requires understanding how the C++ API interacts with Javascript functionality.
4. **Code Logic Reasoning (with input/output):**  This will involve identifying methods that perform some kind of transformation or calculation.
5. **Common Programming Errors:**  This requires thinking about how developers might misuse the Isolate API.
6. **Overall Functionality Summary:** A concise summary of the header's purpose.

**Mental Walkthrough:**

* **Parsing:** I'll scan the header file for class definitions (primarily `Isolate` and `ResourceConstraints`) and their public methods. I'll pay attention to the `V8_EXPORT` macro, indicating public API.
* **`.tq` Check:**  Simple file extension check - `.h` is not `.tq`.
* **Javascript Relationship:** I'll look for methods that relate to creating Javascript environments, executing code, managing memory, and handling callbacks. For example,  `Enter()`, `Exit()`, memory management related methods, and callback setters. I need to translate these C++ concepts into how they manifest in Javascript.
* **Code Logic:**  Methods like `GetHeapStatistics` and `GetStackSample` involve gathering and reporting data. I can create hypothetical scenarios for these.
* **Common Errors:**  Think about multi-threading issues (not using `Locker`), memory leaks (not disposing of isolates), and incorrect usage of scopes.
* **Summary:** Combine all the above points into a concise description of the header's role in V8.

**Constraint Checklist & Confidence Score:**

* List the functions: Yes
* `.tq` check: Yes
* Javascript relationship & examples: Yes
* Code logic & input/output: Yes
* Common errors & examples: Yes
* Overall functionality: Yes

Confidence Score: 5/5 - I am confident I can address all parts of the request accurately.

**Potential Challenges and Refinements:**

* **Granularity of Functions:** The request asks to "list the functions." Should I include all public methods, or just the most significant ones?  For the first part, listing all public methods is likely the most accurate interpretation.
* **Javascript Examples:** The examples need to be simple and clearly demonstrate the connection to the C++ API.
* **Code Logic Assumptions:**  Since I don't have the actual implementation, the code logic reasoning will be based on the method names and their documented purpose. The input/output will be illustrative.

Strategizing complete. I will now proceed with generating the response by following the outlined steps.
好的，根据你提供的 V8 源代码头文件 `v8/include/v8-isolate.h` 的内容，这是第一部分，我将归纳一下它的功能。

**功能归纳：**

`v8/include/v8-isolate.h` 文件是 V8 JavaScript 引擎的核心头文件之一，它定义了 `v8::Isolate` 类以及相关的配置和管理接口。`Isolate` 代表了 V8 引擎的一个独立实例，拥有完全隔离的状态。这个头文件的主要功能可以概括为：

1. **定义了 V8 引擎的独立运行实例 (`v8::Isolate`)：**  这是 V8 提供的最顶层的抽象，每个 `Isolate` 实例都拥有自己的堆、执行上下文等，使得在同一进程中运行多个独立的 JavaScript 环境成为可能。

2. **提供了创建和管理 `Isolate` 实例的接口：**  包括静态方法 `Allocate()` 和 `New()` 用于创建 `Isolate`，以及 `Dispose()` 方法用于销毁 `Isolate` 实例并释放资源。

3. **定义了 `Isolate` 的配置参数 (`CreateParams`)：**  允许开发者在创建 `Isolate` 时进行各种配置，例如：
    * 设置内存限制 (`ResourceConstraints`)，包括堆大小、栈大小、代码段大小等。
    * 提供快照数据 (`snapshot_blob`) 用于加速 `Isolate` 的启动。
    * 设置内存分配器 (`array_buffer_allocator`) 用于 `ArrayBuffer` 的内存管理。
    * 提供外部引用 (`external_references`) 用于序列化和反序列化。
    * 设置错误处理回调 (`fatal_error_callback`, `oom_error_callback`)。

4. **提供了进入和退出 `Isolate` 的机制 (`Enter()`, `Exit()`) 和作用域管理类 (`Scope`)：**  在多线程环境中，需要显式地进入一个 `Isolate` 才能在该 `Isolate` 中执行 JavaScript 代码。`Scope` 类简化了进入和退出 `Isolate` 的操作。

5. **提供了限制 JavaScript 执行的作用域 (`DisallowJavascriptExecutionScope`) 和允许 JavaScript 执行的作用域 (`AllowJavascriptExecutionScope`)：**  用于在某些特定的代码段中强制禁止或允许 JavaScript 的执行。

6. **提供了抑制微任务执行的作用域 (`SuppressMicrotaskExecutionScope`)：**  允许在特定的操作中暂停微任务的自动执行。

7. **定义了资源约束 (`ResourceConstraints`) 类：**  用于配置 `Isolate` 的内存使用限制，包括堆大小、栈大小等。

8. **定义了各种回调类型：**  例如，用于处理即时编译代码事件 (`JitCodeEventHandler`)，统计计数器 (`CounterLookupCallback`)，直方图 (`CreateHistogramCallback`, `AddHistogramSampleCallback`)，以及处理未捕获异常 (`AbortOnUncaughtExceptionCallback`) 等。

9. **提供了与内存管理和垃圾回收相关的接口：**  例如，获取堆统计信息 (`GetHeapStatistics`, `GetHeapSpaceStatistics`, `GetHeapObjectStatisticsAtLastGC`, `GetHeapCodeAndMetadataStatistics`)，以及手动触发垃圾回收 (`RequestGarbageCollectionForTesting`)。

10. **提供了获取调用栈信息的接口 (`GetStackSample`)。**

11. **定义了内存压力通知 (`MemoryPressureNotification`) 和电池保护模式 (`SetBatterySaverMode`) 的接口，允许宿主环境向 V8 提供系统状态信息。**

**关于文件类型和 JavaScript 关系：**

* `v8/include/v8-isolate.h` **没有**以 `.tq` 结尾，因此它是一个 **C++ 头文件**，而不是 V8 Torque 源代码。
* 这个头文件与 JavaScript 的功能 **密切相关**，因为它定义了 V8 引擎的核心实例 `Isolate`，而 JavaScript 代码就是在 `Isolate` 中运行的。

在后续的部分，我们可以更深入地探讨其中的某些功能，并使用 JavaScript 示例来展示其联系。

Prompt: 
```
这是目录为v8/include/v8-isolate.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-isolate.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_V8_ISOLATE_H_
#define INCLUDE_V8_ISOLATE_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <utility>

#include "cppgc/common.h"
#include "v8-array-buffer.h"       // NOLINT(build/include_directory)
#include "v8-callbacks.h"          // NOLINT(build/include_directory)
#include "v8-data.h"               // NOLINT(build/include_directory)
#include "v8-debug.h"              // NOLINT(build/include_directory)
#include "v8-embedder-heap.h"      // NOLINT(build/include_directory)
#include "v8-exception.h"          // NOLINT(build/include_directory)
#include "v8-function-callback.h"  // NOLINT(build/include_directory)
#include "v8-internal.h"           // NOLINT(build/include_directory)
#include "v8-local-handle.h"       // NOLINT(build/include_directory)
#include "v8-microtask.h"          // NOLINT(build/include_directory)
#include "v8-persistent-handle.h"  // NOLINT(build/include_directory)
#include "v8-primitive.h"          // NOLINT(build/include_directory)
#include "v8-statistics.h"         // NOLINT(build/include_directory)
#include "v8-unwinder.h"           // NOLINT(build/include_directory)
#include "v8config.h"              // NOLINT(build/include_directory)

namespace v8 {

class CppHeap;
class HeapProfiler;
class MicrotaskQueue;
class StartupData;
class ScriptOrModule;
class SharedArrayBuffer;

namespace internal {
class MicrotaskQueue;
class ThreadLocalTop;
}  // namespace internal

namespace metrics {
class Recorder;
}  // namespace metrics

/**
 * A set of constraints that specifies the limits of the runtime's memory use.
 * You must set the heap size before initializing the VM - the size cannot be
 * adjusted after the VM is initialized.
 *
 * If you are using threads then you should hold the V8::Locker lock while
 * setting the stack limit and you must set a non-default stack limit separately
 * for each thread.
 *
 * The arguments for set_max_semi_space_size, set_max_old_space_size,
 * set_max_executable_size, set_code_range_size specify limits in MB.
 *
 * The argument for set_max_semi_space_size_in_kb is in KB.
 */
class V8_EXPORT ResourceConstraints {
 public:
  /**
   * Configures the constraints with reasonable default values based on the
   * provided heap size limit. The heap size includes both the young and
   * the old generation.
   *
   * \param initial_heap_size_in_bytes The initial heap size or zero.
   *    By default V8 starts with a small heap and dynamically grows it to
   *    match the set of live objects. This may lead to ineffective
   *    garbage collections at startup if the live set is large.
   *    Setting the initial heap size avoids such garbage collections.
   *    Note that this does not affect young generation garbage collections.
   *
   * \param maximum_heap_size_in_bytes The hard limit for the heap size.
   *    When the heap size approaches this limit, V8 will perform series of
   *    garbage collections and invoke the NearHeapLimitCallback. If the garbage
   *    collections do not help and the callback does not increase the limit,
   *    then V8 will crash with V8::FatalProcessOutOfMemory.
   */
  void ConfigureDefaultsFromHeapSize(size_t initial_heap_size_in_bytes,
                                     size_t maximum_heap_size_in_bytes);

  /**
   * Configures the constraints with reasonable default values based on the
   * capabilities of the current device the VM is running on.
   *
   * \param physical_memory The total amount of physical memory on the current
   *   device, in bytes.
   * \param virtual_memory_limit The amount of virtual memory on the current
   *   device, in bytes, or zero, if there is no limit.
   */
  void ConfigureDefaults(uint64_t physical_memory,
                         uint64_t virtual_memory_limit);

  /**
   * The address beyond which the VM's stack may not grow.
   */
  uint32_t* stack_limit() const { return stack_limit_; }
  void set_stack_limit(uint32_t* value) { stack_limit_ = value; }

  /**
   * The amount of virtual memory reserved for generated code. This is relevant
   * for 64-bit architectures that rely on code range for calls in code.
   *
   * When V8_COMPRESS_POINTERS_IN_SHARED_CAGE is defined, there is a shared
   * process-wide code range that is lazily initialized. This value is used to
   * configure that shared code range when the first Isolate is
   * created. Subsequent Isolates ignore this value.
   */
  size_t code_range_size_in_bytes() const { return code_range_size_; }
  void set_code_range_size_in_bytes(size_t limit) { code_range_size_ = limit; }

  /**
   * The maximum size of the old generation.
   * When the old generation approaches this limit, V8 will perform series of
   * garbage collections and invoke the NearHeapLimitCallback.
   * If the garbage collections do not help and the callback does not
   * increase the limit, then V8 will crash with V8::FatalProcessOutOfMemory.
   */
  size_t max_old_generation_size_in_bytes() const {
    return max_old_generation_size_;
  }
  void set_max_old_generation_size_in_bytes(size_t limit) {
    max_old_generation_size_ = limit;
  }

  /**
   * The maximum size of the young generation, which consists of two semi-spaces
   * and a large object space. This affects frequency of Scavenge garbage
   * collections and should be typically much smaller that the old generation.
   */
  size_t max_young_generation_size_in_bytes() const {
    return max_young_generation_size_;
  }
  void set_max_young_generation_size_in_bytes(size_t limit) {
    max_young_generation_size_ = limit;
  }

  size_t initial_old_generation_size_in_bytes() const {
    return initial_old_generation_size_;
  }
  void set_initial_old_generation_size_in_bytes(size_t initial_size) {
    initial_old_generation_size_ = initial_size;
  }

  size_t initial_young_generation_size_in_bytes() const {
    return initial_young_generation_size_;
  }
  void set_initial_young_generation_size_in_bytes(size_t initial_size) {
    initial_young_generation_size_ = initial_size;
  }

 private:
  static constexpr size_t kMB = 1048576u;
  size_t code_range_size_ = 0;
  size_t max_old_generation_size_ = 0;
  size_t max_young_generation_size_ = 0;
  size_t initial_old_generation_size_ = 0;
  size_t initial_young_generation_size_ = 0;
  uint32_t* stack_limit_ = nullptr;
};

/**
 * Option flags passed to the SetRAILMode function.
 * See documentation https://developers.google.com/web/tools/chrome-devtools/
 * profile/evaluate-performance/rail
 */
enum RAILMode : unsigned {
  // Response performance mode: In this mode very low virtual machine latency
  // is provided. V8 will try to avoid JavaScript execution interruptions.
  // Throughput may be throttled.
  PERFORMANCE_RESPONSE,
  // Animation performance mode: In this mode low virtual machine latency is
  // provided. V8 will try to avoid as many JavaScript execution interruptions
  // as possible. Throughput may be throttled. This is the default mode.
  PERFORMANCE_ANIMATION,
  // Idle performance mode: The embedder is idle. V8 can complete deferred work
  // in this mode.
  PERFORMANCE_IDLE,
  // Load performance mode: In this mode high throughput is provided. V8 may
  // turn off latency optimizations.
  PERFORMANCE_LOAD
};

/**
 * Memory pressure level for the MemoryPressureNotification.
 * kNone hints V8 that there is no memory pressure.
 * kModerate hints V8 to speed up incremental garbage collection at the cost of
 * of higher latency due to garbage collection pauses.
 * kCritical hints V8 to free memory as soon as possible. Garbage collection
 * pauses at this level will be large.
 */
enum class MemoryPressureLevel { kNone, kModerate, kCritical };

/**
 * Indicator for the stack state.
 */
using StackState = cppgc::EmbedderStackState;

/**
 * Isolate represents an isolated instance of the V8 engine.  V8 isolates have
 * completely separate states.  Objects from one isolate must not be used in
 * other isolates.  The embedder can create multiple isolates and use them in
 * parallel in multiple threads.  An isolate can be entered by at most one
 * thread at any given time.  The Locker/Unlocker API must be used to
 * synchronize.
 */
class V8_EXPORT Isolate {
 public:
  /**
   * Initial configuration parameters for a new Isolate.
   */
  struct V8_EXPORT CreateParams {
    CreateParams();
    ~CreateParams();

    ALLOW_COPY_AND_MOVE_WITH_DEPRECATED_FIELDS(CreateParams)

    /**
     * Allows the host application to provide the address of a function that is
     * notified each time code is added, moved or removed.
     */
    JitCodeEventHandler code_event_handler = nullptr;

    /**
     * ResourceConstraints to use for the new Isolate.
     */
    ResourceConstraints constraints;

    /**
     * Explicitly specify a startup snapshot blob. The embedder owns the blob.
     * The embedder *must* ensure that the snapshot is from a trusted source.
     */
    const StartupData* snapshot_blob = nullptr;

    /**
     * Enables the host application to provide a mechanism for recording
     * statistics counters.
     */
    CounterLookupCallback counter_lookup_callback = nullptr;

    /**
     * Enables the host application to provide a mechanism for recording
     * histograms. The CreateHistogram function returns a
     * histogram which will later be passed to the AddHistogramSample
     * function.
     */
    CreateHistogramCallback create_histogram_callback = nullptr;
    AddHistogramSampleCallback add_histogram_sample_callback = nullptr;

    /**
     * The ArrayBuffer::Allocator to use for allocating and freeing the backing
     * store of ArrayBuffers.
     *
     * If the shared_ptr version is used, the Isolate instance and every
     * |BackingStore| allocated using this allocator hold a std::shared_ptr
     * to the allocator, in order to facilitate lifetime
     * management for the allocator instance.
     */
    ArrayBuffer::Allocator* array_buffer_allocator = nullptr;
    std::shared_ptr<ArrayBuffer::Allocator> array_buffer_allocator_shared;

    /**
     * Specifies an optional nullptr-terminated array of raw addresses in the
     * embedder that V8 can match against during serialization and use for
     * deserialization. This array and its content must stay valid for the
     * entire lifetime of the isolate.
     */
    const intptr_t* external_references = nullptr;

    /**
     * Whether calling Atomics.wait (a function that may block) is allowed in
     * this isolate. This can also be configured via SetAllowAtomicsWait.
     */
    bool allow_atomics_wait = true;

    /**
     * The following parameters describe the offsets for addressing type info
     * for wrapped API objects and are used by the fast C API
     * (for details see v8-fast-api-calls.h).
     */
    int embedder_wrapper_type_index = -1;
    int embedder_wrapper_object_index = -1;

    /**
     * Callbacks to invoke in case of fatal or OOM errors.
     */
    FatalErrorCallback fatal_error_callback = nullptr;
    OOMErrorCallback oom_error_callback = nullptr;

    /**
     * A CppHeap used to construct the Isolate. V8 takes ownership of the
     * CppHeap passed this way.
     */
    CppHeap* cpp_heap = nullptr;
  };

  /**
   * Stack-allocated class which sets the isolate for all operations
   * executed within a local scope.
   */
  class V8_EXPORT V8_NODISCARD Scope {
   public:
    explicit Scope(Isolate* isolate) : v8_isolate_(isolate) {
      v8_isolate_->Enter();
    }

    ~Scope() { v8_isolate_->Exit(); }

    // Prevent copying of Scope objects.
    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;

   private:
    Isolate* const v8_isolate_;
  };

  /**
   * Assert that no Javascript code is invoked.
   */
  class V8_EXPORT V8_NODISCARD DisallowJavascriptExecutionScope {
   public:
    enum OnFailure { CRASH_ON_FAILURE, THROW_ON_FAILURE, DUMP_ON_FAILURE };

    DisallowJavascriptExecutionScope(Isolate* isolate, OnFailure on_failure);
    ~DisallowJavascriptExecutionScope();

    // Prevent copying of Scope objects.
    DisallowJavascriptExecutionScope(const DisallowJavascriptExecutionScope&) =
        delete;
    DisallowJavascriptExecutionScope& operator=(
        const DisallowJavascriptExecutionScope&) = delete;

   private:
    v8::Isolate* const v8_isolate_;
    const OnFailure on_failure_;
    bool was_execution_allowed_;
  };

  /**
   * Introduce exception to DisallowJavascriptExecutionScope.
   */
  class V8_EXPORT V8_NODISCARD AllowJavascriptExecutionScope {
   public:
    explicit AllowJavascriptExecutionScope(Isolate* isolate);
    ~AllowJavascriptExecutionScope();

    // Prevent copying of Scope objects.
    AllowJavascriptExecutionScope(const AllowJavascriptExecutionScope&) =
        delete;
    AllowJavascriptExecutionScope& operator=(
        const AllowJavascriptExecutionScope&) = delete;

   private:
    Isolate* const v8_isolate_;
    bool was_execution_allowed_assert_;
    bool was_execution_allowed_throws_;
    bool was_execution_allowed_dump_;
  };

  /**
   * Do not run microtasks while this scope is active, even if microtasks are
   * automatically executed otherwise.
   */
  class V8_EXPORT V8_NODISCARD SuppressMicrotaskExecutionScope {
   public:
    explicit SuppressMicrotaskExecutionScope(
        Isolate* isolate, MicrotaskQueue* microtask_queue = nullptr);
    ~SuppressMicrotaskExecutionScope();

    // Prevent copying of Scope objects.
    SuppressMicrotaskExecutionScope(const SuppressMicrotaskExecutionScope&) =
        delete;
    SuppressMicrotaskExecutionScope& operator=(
        const SuppressMicrotaskExecutionScope&) = delete;

   private:
    internal::Isolate* const i_isolate_;
    internal::MicrotaskQueue* const microtask_queue_;
    internal::Address previous_stack_height_;

    friend class internal::ThreadLocalTop;
  };

  /**
   * Types of garbage collections that can be requested via
   * RequestGarbageCollectionForTesting.
   */
  enum GarbageCollectionType {
    kFullGarbageCollection,
    kMinorGarbageCollection
  };

  /**
   * Features reported via the SetUseCounterCallback callback. Do not change
   * assigned numbers of existing items; add new features to the end of this
   * list.
   * Dead features can be marked `V8_DEPRECATE_SOON`, then `V8_DEPRECATED`, and
   * then finally be renamed to `kOBSOLETE_...` to stop embedders from using
   * them.
   */
  enum UseCounterFeature {
    kUseAsm = 0,
    kBreakIterator = 1,
    kOBSOLETE_LegacyConst = 2,
    kOBSOLETE_MarkDequeOverflow = 3,
    kOBSOLETE_StoreBufferOverflow = 4,
    kOBSOLETE_SlotsBufferOverflow = 5,
    kOBSOLETE_ObjectObserve = 6,
    kForcedGC = 7,
    kSloppyMode = 8,
    kStrictMode = 9,
    kOBSOLETE_StrongMode = 10,
    kRegExpPrototypeStickyGetter = 11,
    kRegExpPrototypeToString = 12,
    kRegExpPrototypeUnicodeGetter = 13,
    kOBSOLETE_IntlV8Parse = 14,
    kOBSOLETE_IntlPattern = 15,
    kOBSOLETE_IntlResolved = 16,
    kOBSOLETE_PromiseChain = 17,
    kOBSOLETE_PromiseAccept = 18,
    kOBSOLETE_PromiseDefer = 19,
    kHtmlCommentInExternalScript = 20,
    kHtmlComment = 21,
    kSloppyModeBlockScopedFunctionRedefinition = 22,
    kForInInitializer = 23,
    kOBSOLETE_ArrayProtectorDirtied = 24,
    kArraySpeciesModified = 25,
    kArrayPrototypeConstructorModified = 26,
    kOBSOLETE_ArrayInstanceProtoModified = 27,
    kArrayInstanceConstructorModified = 28,
    kOBSOLETE_LegacyFunctionDeclaration = 29,
    kOBSOLETE_RegExpPrototypeSourceGetter = 30,
    kOBSOLETE_RegExpPrototypeOldFlagGetter = 31,
    kDecimalWithLeadingZeroInStrictMode = 32,
    kLegacyDateParser = 33,
    kDefineGetterOrSetterWouldThrow = 34,
    kFunctionConstructorReturnedUndefined = 35,
    kAssigmentExpressionLHSIsCallInSloppy = 36,
    kAssigmentExpressionLHSIsCallInStrict = 37,
    kPromiseConstructorReturnedUndefined = 38,
    kOBSOLETE_ConstructorNonUndefinedPrimitiveReturn = 39,
    kOBSOLETE_LabeledExpressionStatement = 40,
    kOBSOLETE_LineOrParagraphSeparatorAsLineTerminator = 41,
    kIndexAccessor = 42,
    kErrorCaptureStackTrace = 43,
    kErrorPrepareStackTrace = 44,
    kErrorStackTraceLimit = 45,
    kWebAssemblyInstantiation = 46,
    kDeoptimizerDisableSpeculation = 47,
    kOBSOLETE_ArrayPrototypeSortJSArrayModifiedPrototype = 48,
    kFunctionTokenOffsetTooLongForToString = 49,
    kWasmSharedMemory = 50,
    kWasmThreadOpcodes = 51,
    kOBSOLETE_AtomicsNotify = 52,
    kOBSOLETE_AtomicsWake = 53,
    kCollator = 54,
    kNumberFormat = 55,
    kDateTimeFormat = 56,
    kPluralRules = 57,
    kRelativeTimeFormat = 58,
    kLocale = 59,
    kListFormat = 60,
    kSegmenter = 61,
    kStringLocaleCompare = 62,
    kOBSOLETE_StringToLocaleUpperCase = 63,
    kStringToLocaleLowerCase = 64,
    kNumberToLocaleString = 65,
    kDateToLocaleString = 66,
    kDateToLocaleDateString = 67,
    kDateToLocaleTimeString = 68,
    kAttemptOverrideReadOnlyOnPrototypeSloppy = 69,
    kAttemptOverrideReadOnlyOnPrototypeStrict = 70,
    kOBSOLETE_OptimizedFunctionWithOneShotBytecode = 71,
    kRegExpMatchIsTrueishOnNonJSRegExp = 72,
    kRegExpMatchIsFalseishOnJSRegExp = 73,
    kOBSOLETE_DateGetTimezoneOffset = 74,
    kStringNormalize = 75,
    kCallSiteAPIGetFunctionSloppyCall = 76,
    kCallSiteAPIGetThisSloppyCall = 77,
    kOBSOLETE_RegExpMatchAllWithNonGlobalRegExp = 78,
    kRegExpExecCalledOnSlowRegExp = 79,
    kRegExpReplaceCalledOnSlowRegExp = 80,
    kDisplayNames = 81,
    kSharedArrayBufferConstructed = 82,
    kArrayPrototypeHasElements = 83,
    kObjectPrototypeHasElements = 84,
    kNumberFormatStyleUnit = 85,
    kDateTimeFormatRange = 86,
    kDateTimeFormatDateTimeStyle = 87,
    kBreakIteratorTypeWord = 88,
    kBreakIteratorTypeLine = 89,
    kInvalidatedArrayBufferDetachingProtector = 90,
    kInvalidatedArrayConstructorProtector = 91,
    kInvalidatedArrayIteratorLookupChainProtector = 92,
    kInvalidatedArraySpeciesLookupChainProtector = 93,
    kInvalidatedIsConcatSpreadableLookupChainProtector = 94,
    kInvalidatedMapIteratorLookupChainProtector = 95,
    kInvalidatedNoElementsProtector = 96,
    kInvalidatedPromiseHookProtector = 97,
    kInvalidatedPromiseResolveLookupChainProtector = 98,
    kInvalidatedPromiseSpeciesLookupChainProtector = 99,
    kInvalidatedPromiseThenLookupChainProtector = 100,
    kInvalidatedRegExpSpeciesLookupChainProtector = 101,
    kInvalidatedSetIteratorLookupChainProtector = 102,
    kInvalidatedStringIteratorLookupChainProtector = 103,
    kInvalidatedStringLengthOverflowLookupChainProtector = 104,
    kInvalidatedTypedArraySpeciesLookupChainProtector = 105,
    kWasmSimdOpcodes = 106,
    kVarRedeclaredCatchBinding = 107,
    kWasmRefTypes = 108,
    kOBSOLETE_WasmBulkMemory = 109,
    kOBSOLETE_WasmMultiValue = 110,
    kWasmExceptionHandling = 111,
    kInvalidatedMegaDOMProtector = 112,
    kFunctionPrototypeArguments = 113,
    kFunctionPrototypeCaller = 114,
    kTurboFanOsrCompileStarted = 115,
    kAsyncStackTaggingCreateTaskCall = 116,
    kDurationFormat = 117,
    kInvalidatedNumberStringNotRegexpLikeProtector = 118,
    kOBSOLETE_RegExpUnicodeSetIncompatibilitiesWithUnicodeMode = 119,
    kOBSOLETE_ImportAssertionDeprecatedSyntax = 120,
    kLocaleInfoObsoletedGetters = 121,
    kLocaleInfoFunctions = 122,
    kCompileHintsMagicAll = 123,
    kInvalidatedNoProfilingProtector = 124,
    kWasmMemory64 = 125,
    kWasmMultiMemory = 126,
    kWasmGC = 127,
    kWasmImportedStrings = 128,
    kSourceMappingUrlMagicCommentAtSign = 129,
    kTemporalObject = 130,
    kWasmModuleCompilation = 131,
    kInvalidatedNoUndetectableObjectsProtector = 132,
    kWasmJavaScriptPromiseIntegration = 133,
    kWasmReturnCall = 134,
    kWasmExtendedConst = 135,
    kWasmRelaxedSimd = 136,
    kWasmTypeReflection = 137,
    kWasmExnRef = 138,
    kWasmTypedFuncRef = 139,
    kInvalidatedStringWrapperToPrimitiveProtector = 140,
    kDocumentAllLegacyCall = 141,
    kDocumentAllLegacyConstruct = 142,
    kConsoleContext = 143,
    kWasmImportedStringsUtf8 = 144,
    kResizableArrayBuffer = 145,
    kGrowableSharedArrayBuffer = 146,
    kArrayByCopy = 147,
    kArrayFromAsync = 148,
    kIteratorMethods = 149,
    kPromiseAny = 150,
    kSetMethods = 151,
    kArrayFindLast = 152,
    kArrayGroup = 153,
    kArrayBufferTransfer = 154,
    kPromiseWithResolvers = 155,
    kAtomicsWaitAsync = 156,

    // If you add new values here, you'll also need to update Chromium's:
    // web_feature.mojom, use_counter_callback.cc, and enums.xml. V8 changes to
    // this list need to be landed first, then changes on the Chromium side.
    kUseCounterFeatureCount  // This enum value must be last.
  };

  enum MessageErrorLevel {
    kMessageLog = (1 << 0),
    kMessageDebug = (1 << 1),
    kMessageInfo = (1 << 2),
    kMessageError = (1 << 3),
    kMessageWarning = (1 << 4),
    kMessageAll = kMessageLog | kMessageDebug | kMessageInfo | kMessageError |
                  kMessageWarning,
  };

  // The different priorities that an isolate can have.
  enum class Priority {
    // The isolate does not relate to content that is currently important
    // to the user. Lowest priority.
    kBestEffort,

    // The isolate contributes to content that is visible to the user, like a
    // visible iframe that's not interacted directly with. High priority.
    kUserVisible,

    // The isolate contributes to content that is of the utmost importance to
    // the user, like visible content in the focused window. Highest priority.
    kUserBlocking,
  };

  using UseCounterCallback = void (*)(Isolate* isolate,
                                      UseCounterFeature feature);

  /**
   * Allocates a new isolate but does not initialize it. Does not change the
   * currently entered isolate.
   *
   * Only Isolate::GetData() and Isolate::SetData(), which access the
   * embedder-controlled parts of the isolate, are allowed to be called on the
   * uninitialized isolate. To initialize the isolate, call
   * `Isolate::Initialize()` or initialize a `SnapshotCreator`.
   *
   * When an isolate is no longer used its resources should be freed
   * by calling Dispose().  Using the delete operator is not allowed.
   *
   * V8::Initialize() must have run prior to this.
   */
  static Isolate* Allocate();

  /**
   * Initialize an Isolate previously allocated by Isolate::Allocate().
   */
  static void Initialize(Isolate* isolate, const CreateParams& params);

  /**
   * Creates a new isolate.  Does not change the currently entered
   * isolate.
   *
   * When an isolate is no longer used its resources should be freed
   * by calling Dispose().  Using the delete operator is not allowed.
   *
   * V8::Initialize() must have run prior to this.
   */
  static Isolate* New(const CreateParams& params);

  /**
   * Returns the entered isolate for the current thread or NULL in
   * case there is no current isolate.
   *
   * This method must not be invoked before V8::Initialize() was invoked.
   */
  static Isolate* GetCurrent();

  /**
   * Returns the entered isolate for the current thread or NULL in
   * case there is no current isolate.
   *
   * No checks are performed by this method.
   */
  static Isolate* TryGetCurrent();

  /**
   * Return true if this isolate is currently active.
   **/
  bool IsCurrent() const;

  /**
   * Clears the set of objects held strongly by the heap. This set of
   * objects are originally built when a WeakRef is created or
   * successfully dereferenced.
   *
   * This is invoked automatically after microtasks are run. See
   * MicrotasksPolicy for when microtasks are run.
   *
   * This needs to be manually invoked only if the embedder is manually running
   * microtasks via a custom MicrotaskQueue class's PerformCheckpoint. In that
   * case, it is the embedder's responsibility to make this call at a time which
   * does not interrupt synchronous ECMAScript code execution.
   */
  void ClearKeptObjects();

  /**
   * Custom callback used by embedders to help V8 determine if it should abort
   * when it throws and no internal handler is predicted to catch the
   * exception. If --abort-on-uncaught-exception is used on the command line,
   * then V8 will abort if either:
   * - no custom callback is set.
   * - the custom callback set returns true.
   * Otherwise, the custom callback will not be called and V8 will not abort.
   */
  using AbortOnUncaughtExceptionCallback = bool (*)(Isolate*);
  void SetAbortOnUncaughtExceptionCallback(
      AbortOnUncaughtExceptionCallback callback);

  /**
   * This specifies the callback called by the upcoming dynamic
   * import() language feature to load modules.
   */
  void SetHostImportModuleDynamicallyCallback(
      HostImportModuleDynamicallyCallback callback);

  /**
   * This specifies the callback called by the upcoming dynamic
   * import() and import.source() language feature to load modules.
   *
   * This API is experimental and is expected to be changed or removed in the
   * future. The callback is currently only called when for source-phase
   * imports. Evaluation-phase imports use the existing
   * HostImportModuleDynamicallyCallback callback.
   */
  void SetHostImportModuleWithPhaseDynamicallyCallback(
      HostImportModuleWithPhaseDynamicallyCallback callback);

  /**
   * This specifies the callback called by the upcoming import.meta
   * language feature to retrieve host-defined meta data for a module.
   */
  void SetHostInitializeImportMetaObjectCallback(
      HostInitializeImportMetaObjectCallback callback);

  /**
   * This specifies the callback called by the upcoming ShadowRealm
   * construction language feature to retrieve host created globals.
   */
  void SetHostCreateShadowRealmContextCallback(
      HostCreateShadowRealmContextCallback callback);

  /**
   * This specifies the callback called when the stack property of Error
   * is accessed.
   */
  void SetPrepareStackTraceCallback(PrepareStackTraceCallback callback);

  /**
   * Get the stackTraceLimit property of Error.
   */
  int GetStackTraceLimit();

#if defined(V8_OS_WIN)
  /**
   * This specifies the callback called when an ETW tracing session starts.
   */
  void SetFilterETWSessionByURLCallback(FilterETWSessionByURLCallback callback);
#endif  // V8_OS_WIN

  /**
   * Optional notification that the system is running low on memory.
   * V8 uses these notifications to guide heuristics.
   * It is allowed to call this function from another thread while
   * the isolate is executing long running JavaScript code.
   */
  void MemoryPressureNotification(MemoryPressureLevel level);

  /**
   * Optional request from the embedder to tune v8 towards energy efficiency
   * rather than speed if `battery_saver_mode_enabled` is true, because the
   * embedder is in battery saver mode. If false, the correct tuning is left
   * to v8 to decide.
   */
  void SetBatterySaverMode(bool battery_saver_mode_enabled);

  /**
   * Drop non-essential caches. Should only be called from testing code.
   * The method can potentially block for a long time and does not necessarily
   * trigger GC.
   */
  void ClearCachesForTesting();

  /**
   * Methods below this point require holding a lock (using Locker) in
   * a multi-threaded environment.
   */

  /**
   * Sets this isolate as the entered one for the current thread.
   * Saves the previously entered one (if any), so that it can be
   * restored when exiting.  Re-entering an isolate is allowed.
   */
  void Enter();

  /**
   * Exits this isolate by restoring the previously entered one in the
   * current thread.  The isolate may still stay the same, if it was
   * entered more than once.
   *
   * Requires: this == Isolate::GetCurrent().
   */
  void Exit();

  /**
   * Disposes the isolate.  The isolate must not be entered by any
   * thread to be disposable.
   */
  void Dispose();

  /**
   * Dumps activated low-level V8 internal stats. This can be used instead
   * of performing a full isolate disposal.
   */
  void DumpAndResetStats();

  /**
   * Discards all V8 thread-specific data for the Isolate. Should be used
   * if a thread is terminating and it has used an Isolate that will outlive
   * the thread -- all thread-specific data for an Isolate is discarded when
   * an Isolate is disposed so this call is pointless if an Isolate is about
   * to be Disposed.
   */
  void DiscardThreadSpecificMetadata();

  /**
   * Associate embedder-specific data with the isolate. |slot| has to be
   * between 0 and GetNumberOfDataSlots() - 1.
   */
  V8_INLINE void SetData(uint32_t slot, void* data);

  /**
   * Retrieve embedder-specific data from the isolate.
   * Returns NULL if SetData has never been called for the given |slot|.
   */
  V8_INLINE void* GetData(uint32_t slot);

  /**
   * Returns the maximum number of available embedder data slots. Valid slots
   * are in the range of 0 - GetNumberOfDataSlots() - 1.
   */
  V8_INLINE static uint32_t GetNumberOfDataSlots();

  /**
   * Return data that was previously attached to the isolate snapshot via
   * SnapshotCreator, and removes the reference to it.
   * Repeated call with the same index returns an empty MaybeLocal.
   */
  template <class T>
  V8_INLINE MaybeLocal<T> GetDataFromSnapshotOnce(size_t index);

  /**
   * Returns the value that was set or restored by
   * SetContinuationPreservedEmbedderData(), if any.
   */
  Local<Value> GetContinuationPreservedEmbedderData();

  /**
   * Sets a value that will be stored on continuations and reset while the
   * continuation runs.
   */
  void SetContinuationPreservedEmbedderData(Local<Value> data);

  /**
   * Get statistics about the heap memory usage.
   */
  void GetHeapStatistics(HeapStatistics* heap_statistics);

  /**
   * Returns the number of spaces in the heap.
   */
  size_t NumberOfHeapSpaces();

  /**
   * Get the memory usage of a space in the heap.
   *
   * \param space_statistics The HeapSpaceStatistics object to fill in
   *   statistics.
   * \param index The index of the space to get statistics from, which ranges
   *   from 0 to NumberOfHeapSpaces() - 1.
   * \returns true on success.
   */
  bool GetHeapSpaceStatistics(HeapSpaceStatistics* space_statistics,
                              size_t index);

  /**
   * Returns the number of types of objects tracked in the heap at GC.
   */
  size_t NumberOfTrackedHeapObjectTypes();

  /**
   * Get statistics about objects in the heap.
   *
   * \param object_statistics The HeapObjectStatistics object to fill in
   *   statistics of objects of given type, which were live in the previous GC.
   * \param type_index The index of the type of object to fill details about,
   *   which ranges from 0 to NumberOfTrackedHeapObjectTypes() - 1.
   * \returns true on success.
   */
  bool GetHeapObjectStatisticsAtLastGC(HeapObjectStatistics* object_statistics,
                                       size_t type_index);

  /**
   * Get statistics about code and its metadata in the heap.
   *
   * \param object_statistics The HeapCodeStatistics object to fill in
   *   statistics of code, bytecode and their metadata.
   * \returns true on success.
   */
  bool GetHeapCodeAndMetadataStatistics(HeapCodeStatistics* object_statistics);

  /**
   * This API is experimental and may change significantly.
   *
   * Enqueues a memory measurement request and invokes the delegate with the
   * results.
   *
   * \param delegate the delegate that defines which contexts to measure and
   *   reports the results.
   *
   * \param execution promptness executing the memory measurement.
   *   The kEager value is expected to be used only in tests.
   */
  bool MeasureMemory(
      std::unique_ptr<MeasureMemoryDelegate> delegate,
      MeasureMemoryExecution execution = MeasureMemoryExecution::kDefault);

  /**
   * Get a call stack sample from the isolate.
   * \param state Execution state.
   * \param frames Caller allocated buffer to store stack frames.
   * \param frames_limit Maximum number of frames to capture. The buffer must
   *                     be large enough to hold the number of frames.
   * \param sample_info The sample info is filled up by the function
   *                    provides number of actual captured stack frames and
   *                    the current VM state.
   * \note GetStackSample should only be called when the JS thread is paused or
   *       interrupted. Otherwise the behavior is undefined.
   */
  void GetStackSample(const RegisterState& state, void** frames,
                      size_t frames_limit, SampleInfo* sample_info);

  /**
   * Adjusts the amount of regist
"""


```