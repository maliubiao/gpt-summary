Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Initial Scan and Overall Purpose:**  The first step is to quickly scan the file looking for obvious clues about its purpose. The filename `runtime-call-stats.h` strongly suggests it's related to tracking statistics about runtime calls. The copyright notice and `#ifndef` guard are standard for header files.

2. **Conditional Compilation (`#ifdef V8_RUNTIME_CALL_STATS`):**  Notice the large block of code wrapped in `#ifdef V8_RUNTIME_CALL_STATS`. This is a critical piece of information. It means the functionality within this block is *optional* and only compiled if `V8_RUNTIME_CALL_STATS` is defined. This immediately tells us this is for a specific build configuration, likely related to debugging or profiling.

3. **Key Classes: `RuntimeCallCounter` and `RuntimeCallTimer`:**  These are the core data structures.

    * **`RuntimeCallCounter`:**  Seems straightforward. It holds a `name`, a `count`, and `time`. The methods `Increment()`, `Add(base::TimeDelta)`, `Reset()`, and `Dump()` suggest it's used to count occurrences and track the time spent in some operation.

    * **`RuntimeCallTimer`:** This class is more complex. The presence of `parent_`, `Start()`, `Stop()`, `Pause()`, and `Resume()` strongly indicates it's used for measuring the duration of specific code blocks, potentially in a nested manner (hence the `parent`). The `Now()` and `NowCPUTime()` suggest different time sources can be used.

4. **Macros: `FOR_EACH_..._COUNTER`:** The numerous macros like `FOR_EACH_GC_COUNTER`, `FOR_EACH_API_COUNTER`, etc., are a big hint. These macros are clearly used to generate lists of different kinds of "counters". The names within these macros (e.g., `ArrayBuffer_New`, `Function_Call`, `Compile_Script`) give us concrete examples of what's being tracked. This also suggests a systematic way to enumerate these counters.

5. **Enum `RuntimeCallCounterId`:**  This enum ties everything together. It lists all the possible counters, and the `#define CALL_RUNTIME_COUNTER` lines within it link back to the `FOR_EACH_..._COUNTER` macros. This confirms that these macros are defining the *types* of runtime calls being tracked.

6. **Relationship to JavaScript (Speculation and Connection):**  While the header is C++, the names within the macros often correspond to JavaScript concepts (e.g., `ArrayBuffer`, `Function`, `Promise`, `JSON`). This strongly suggests that the stats being collected are related to the execution of JavaScript code within the V8 engine.

7. **Inferring Functionality:** Based on the identified components, we can now start piecing together the functionality:

    * This header defines a system for tracking statistics about various runtime calls within V8.
    * It uses counters (`RuntimeCallCounter`) to record the number of times something happens and the time it takes.
    * Timers (`RuntimeCallTimer`) are used to precisely measure the duration of these calls, even when they are nested.
    * The macros provide a structured way to define different categories of counters (GC, API, compiler phases, etc.).
    * The `RuntimeCallCounterId` enum provides a central enumeration of all the tracked events.
    * This system is likely used for performance analysis, debugging, and understanding the behavior of the V8 engine.

8. **Addressing Specific Questions:** Now, let's go through the prompt's questions:

    * **Functionality:** Summarize the inferred functionality.
    * **`.tq` extension:** The prompt provides this information directly – if the file had that extension, it would be a Torque file. Since it doesn't, this part is irrelevant for this specific file.
    * **Relationship to JavaScript:** Connect the macro names to JavaScript concepts and provide examples.
    * **Code Logic Inference:** The timer mechanism (`Start`, `Stop`, `Pause`, `Resume`) involves basic time calculations. A simple scenario with nested calls can be used as an example.
    * **Common Programming Errors:** Think about how developers might misuse such a system if they were directly interacting with it (though this is unlikely for typical V8 users). For instance, forgetting to `Stop()` a timer.
    * **Summary:** Condense the main points.

9. **Structuring the Output:** Organize the findings into logical sections, addressing each point in the prompt clearly. Use formatting (like bullet points) to improve readability. Provide code examples where requested.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps this is only about internal V8 calls.
* **Correction:** The presence of `FOR_EACH_API_COUNTER` and names like `ArrayBuffer_New` clearly show it tracks API calls exposed to JavaScript.
* **Initial thought:** The timing might be very basic.
* **Refinement:** The `RuntimeCallTimer` with its parent tracking and `Pause`/`Resume` functionality suggests more sophisticated nested timing measurements.

By following this methodical approach of scanning, identifying key components, inferring functionality, and then addressing the specific questions, we can arrive at a comprehensive understanding of the header file's purpose.
这是 V8 引擎源代码 `v8/src/logging/runtime-call-stats.h` 的第一部分，其主要功能是定义了一套用于**统计 V8 引擎在运行时各种函数调用**的机制。

**功能归纳:**

1. **定义了用于记录运行时调用信息的类:**
   - `RuntimeCallCounter`: 用于记录单个函数或操作的调用次数和花费的时间。
   - `RuntimeCallTimer`: 用于精确测量函数调用的耗时，支持嵌套调用计时。

2. **提供了宏定义用于声明各种需要统计的调用类型:**
   - `FOR_EACH_GC_COUNTER`: 垃圾回收相关的计数器。
   - `FOR_EACH_API_COUNTER`: V8 C++ API 相关的计数器，对应 JavaScript 中使用的 API。
   - `FOR_EACH_THREAD_SPECIFIC_COUNTER`: 线程特定的计数器，例如编译和优化的各个阶段。
   - `FOR_EACH_MANUAL_COUNTER`: 手动记录的计数器，例如回调函数和编译的不同阶段。
   - `FOR_EACH_HANDLER_COUNTER`:  与 IC (Inline Cache) 处理相关的计数器。

3. **定义了枚举类型 `RuntimeCallCounterId`:**  该枚举列举了所有需要统计的调用类型，与上述宏定义配合使用，方便索引和管理各种计数器。

4. **提供了配置选项:** 通过 `#ifdef V8_RUNTIME_CALL_STATS` 宏进行条件编译，意味着只有在定义了 `V8_RUNTIME_CALL_STATS` 宏的情况下，这部分代码才会被编译。这通常用于调试或性能分析版本的 V8。

**关于文件扩展名和 Torque:**

根据您的描述，如果 `v8/src/logging/runtime-call-stats.h` 以 `.tq` 结尾，那么它确实是 V8 Torque 源代码。但当前提供的代码片段显示其扩展名为 `.h`，因此它是 **C++ 头文件**。Torque 是一种用于定义 V8 内部 Builtin 函数的领域特定语言。

**与 JavaScript 功能的关系（通过 `FOR_EACH_API_COUNTER` 分析）:**

`FOR_EACH_API_COUNTER` 宏中列举的条目直接对应了 V8 引擎暴露给 JavaScript 的 C++ API。  通过这些计数器，可以统计 JavaScript 代码在运行时调用了哪些 V8 内部的 C++ 函数。

**JavaScript 示例:**

```javascript
// 假设我们关注的是 ArrayBuffer 的创建和使用

// 对应 API 计数器: V(ArrayBuffer_New)
const buffer = new ArrayBuffer(1024);

// 对应 API 计数器: V(ArrayBuffer_Cast)
const uint8Array = new Uint8Array(buffer);

// 对应 API 计数器: V(ArrayBuffer_Detach)
buffer.transfer();

// 对应 API 计数器: V(Function_Call)  (例如数组的 map 方法)
const squared = uint8Array.map(x => x * x);

// 对应 API 计数器: V(JSON_Stringify), V(JSON_Parse)
const obj = { a: 1, b: 2 };
const jsonString = JSON.stringify(obj);
const parsedObj = JSON.parse(jsonString);

// 对应 API 计数器: V(Promise_Then), V(Promise_Resolve)
const promise = new Promise((resolve) => {
  setTimeout(() => resolve(5), 100);
});
promise.then(value => console.log(value));
```

在这个 JavaScript 例子中，每当执行 `new ArrayBuffer()`, `new Uint8Array(buffer)`, `buffer.transfer()`, `uint8Array.map()`, `JSON.stringify()`, `JSON.parse()`, 以及 Promise 相关的操作时，V8 内部就会调用相应的 C++ API，并且 `FOR_EACH_API_COUNTER` 中定义的对应计数器就会被递增。

**代码逻辑推理 (以 `RuntimeCallTimer` 为例):**

**假设输入:**

1. 有一个全局的 `RuntimeCallStats` 对象（虽然代码中未直接给出，但可以推断存在）。
2. 想要测量 JavaScript 中 `Array.prototype.map` 方法的执行时间。

**内部执行流程 (简化):**

1. 当 `Array.prototype.map` 被调用时，V8 内部可能会在开始执行 `map` 的 C++ 实现前，调用 `RuntimeCallTimer::Start()`，传入对应的 `RuntimeCallCounter` (例如 `kRuntime_ArrayMap` 或类似的)。
2. 如果此时没有其他活跃的计时器，`Start()` 会记录当前时间。
3. `map` 方法的 C++ 实现开始执行。
4. 在 `map` 方法执行完毕后，V8 内部会调用 `RuntimeCallTimer::Stop()`。
5. `Stop()` 会计算结束时间和开始时间的差值，并将这个时间差添加到对应的 `RuntimeCallCounter` 的 `time_` 成员中，同时递增 `count_` 成员。

**输出:**

- `kRuntime_ArrayMap` 对应的 `RuntimeCallCounter` 的 `count_` 值会增加 1。
- `kRuntime_ArrayMap` 对应的 `RuntimeCallCounter` 的 `time_` 值会增加本次 `map` 执行所花费的微秒数。

**涉及用户常见的编程错误 (如果用户可以直接操作这些计数器，但这通常不会发生):**

如果用户可以直接操作这些底层的计数器和计时器（在 V8 的使用场景中通常不会直接暴露给用户），那么可能会犯以下错误：

1. **忘记停止计时器:**  如果调用了 `RuntimeCallTimer::Start()` 但忘记调用 `Stop()`，会导致计时不准确，并且可能影响父计时器的测量。

   ```c++
   // 假设用户可以手动操作 (实际不太可能)
   RuntimeCallCounter myCounter("MyOperation");
   RuntimeCallTimer timer;
   timer.Start(&myCounter, nullptr);

   // 执行某些操作
   // ... 但忘记调用 timer.Stop();

   // 最终 myCounter 的 time_ 值可能不准确，因为它还在累积时间。
   ```

2. **在错误的线程中操作计数器:**  如果计数器没有正确地进行线程安全处理，在多线程环境中可能会导致数据竞争和不准确的统计。

3. **重复启动计时器而没有停止:**  这会导致时间被重复计算。

   ```c++
   RuntimeCallCounter myCounter("MyOperation");
   RuntimeCallTimer timer;

   timer.Start(&myCounter, nullptr);
   // ...
   timer.Start(&myCounter, nullptr); // 错误：已经启动了，应该先 Stop()
   ```

**总结:**

`v8/src/logging/runtime-call-stats.h` 的主要功能是为 V8 引擎提供了一个内部的统计框架，用于追踪各种运行时函数调用的次数和耗时。这对于性能分析、调试以及理解 V8 引擎的内部行为至关重要。它通过定义计数器类、计时器类以及一系列宏来实现对不同类型调用的精细化统计。虽然用户通常不会直接操作这些底层的统计机制，但理解其原理有助于理解 V8 引擎的工作方式。

### 提示词
```
这是目录为v8/src/logging/runtime-call-stats.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/logging/runtime-call-stats.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_LOGGING_RUNTIME_CALL_STATS_H_
#define V8_LOGGING_RUNTIME_CALL_STATS_H_

#include <optional>

#include "src/base/macros.h"

#ifdef V8_RUNTIME_CALL_STATS

#include "src/base/atomic-utils.h"
#include "src/base/platform/platform.h"
#include "src/base/platform/time.h"
#include "src/builtins/builtins-definitions.h"
#include "src/execution/thread-id.h"
#include "src/init/heap-symbols.h"
#include "src/logging/tracing-flags.h"
#include "src/runtime/runtime.h"
#include "src/tracing/traced-value.h"
#include "src/tracing/tracing-category-observer.h"

#endif  // V8_RUNTIME_CALL_STATS

namespace v8 {
namespace internal {

#ifdef V8_RUNTIME_CALL_STATS

class RuntimeCallCounter final {
 public:
  RuntimeCallCounter() : RuntimeCallCounter(nullptr) {}
  explicit RuntimeCallCounter(const char* name)
      : name_(name), count_(0), time_(0) {}
  V8_NOINLINE void Reset();
  V8_NOINLINE void Dump(v8::tracing::TracedValue* value);
  void Add(RuntimeCallCounter* other);

  const char* name() const { return name_; }
  int64_t count() const { return count_; }
  base::TimeDelta time() const {
    return base::TimeDelta::FromMicroseconds(time_);
  }
  void Increment() { count_++; }
  void Add(base::TimeDelta delta) { time_ += delta.InMicroseconds(); }

 private:
  friend class RuntimeCallStats;

  const char* name_;
  int64_t count_;
  // Stored as int64_t so that its initialization can be deferred.
  int64_t time_;
};

// RuntimeCallTimer is used to keep track of the stack of currently active
// timers used for properly measuring the own time of a RuntimeCallCounter.
class RuntimeCallTimer final {
 public:
  RuntimeCallCounter* counter() { return counter_; }
  void set_counter(RuntimeCallCounter* counter) { counter_ = counter; }
  RuntimeCallTimer* parent() const { return parent_.Value(); }
  void set_parent(RuntimeCallTimer* timer) { parent_.SetValue(timer); }
  const char* name() const { return counter_->name(); }

  inline bool IsStarted() const { return start_ticks_ != base::TimeTicks(); }

  inline void Start(RuntimeCallCounter* counter, RuntimeCallTimer* parent) {
    DCHECK(!IsStarted());
    counter_ = counter;
    parent_.SetValue(parent);
    if (TracingFlags::runtime_stats.load(std::memory_order_relaxed) ==
        v8::tracing::TracingCategoryObserver::ENABLED_BY_SAMPLING) {
      return;
    }
    base::TimeTicks now = RuntimeCallTimer::Now();
    if (parent) parent->Pause(now);
    Resume(now);
    DCHECK(IsStarted());
  }

  void Snapshot();

  inline RuntimeCallTimer* Stop() {
    if (!IsStarted()) return parent();
    base::TimeTicks now = RuntimeCallTimer::Now();
    Pause(now);
    counter_->Increment();
    CommitTimeToCounter();

    RuntimeCallTimer* parent_timer = parent();
    if (parent_timer) {
      parent_timer->Resume(now);
    }
    return parent_timer;
  }

  // Make the time source configurable for testing purposes.
  V8_EXPORT_PRIVATE static base::TimeTicks (*Now)();

  // Helper to switch over to CPU time.
  static base::TimeTicks NowCPUTime();

 private:
  inline void Pause(base::TimeTicks now) {
    DCHECK(IsStarted());
    elapsed_ += (now - start_ticks_);
    start_ticks_ = base::TimeTicks();
  }

  inline void Resume(base::TimeTicks now) {
    DCHECK(!IsStarted());
    start_ticks_ = now;
  }

  inline void CommitTimeToCounter() {
    counter_->Add(elapsed_);
    elapsed_ = base::TimeDelta();
  }

  RuntimeCallCounter* counter_ = nullptr;
  base::AtomicValue<RuntimeCallTimer*> parent_;
  base::TimeTicks start_ticks_;
  base::TimeDelta elapsed_;
};

#define FOR_EACH_GC_COUNTER(V) \
  TRACER_SCOPES(V)             \
  TRACER_BACKGROUND_SCOPES(V)

#define FOR_EACH_API_COUNTER(V)                            \
  V(AccessorPair_New)                                      \
  V(ArrayBuffer_Cast)                                      \
  V(ArrayBuffer_Detach)                                    \
  V(ArrayBuffer_MaybeNew)                                  \
  V(ArrayBuffer_New)                                       \
  V(ArrayBuffer_NewBackingStore)                           \
  V(ArrayBuffer_BackingStore_Reallocate)                   \
  V(Array_CloneElementAt)                                  \
  V(Array_Iterate)                                         \
  V(Array_New)                                             \
  V(BigInt64Array_New)                                     \
  V(BigInt_NewFromWords)                                   \
  V(BigIntObject_BigIntValue)                              \
  V(BigIntObject_New)                                      \
  V(BigUint64Array_New)                                    \
  V(BooleanObject_BooleanValue)                            \
  V(BooleanObject_New)                                     \
  V(Context_DeepFreeze)                                    \
  V(Context_New)                                           \
  V(Context_NewRemoteContext)                              \
  V(DataView_New)                                          \
  V(Date_New)                                              \
  V(Date_Parse)                                            \
  V(Debug_Call)                                            \
  V(debug_GetPrivateMembers)                               \
  V(DictionaryTemplate_New)                                \
  V(DictionaryTemplate_NewInstance)                        \
  V(Error_New)                                             \
  V(Exception_CaptureStackTrace)                           \
  V(External_New)                                          \
  V(Float16Array_New)                                      \
  V(Float32Array_New)                                      \
  V(Float64Array_New)                                      \
  V(Function_Call)                                         \
  V(Function_New)                                          \
  V(Function_FunctionProtoToString)                        \
  V(Function_NewInstance)                                  \
  V(FunctionTemplate_GetFunction)                          \
  V(FunctionTemplate_New)                                  \
  V(FunctionTemplate_NewRemoteInstance)                    \
  V(FunctionTemplate_NewWithCache)                         \
  V(FunctionTemplate_NewWithFastHandler)                   \
  V(Int16Array_New)                                        \
  V(Int32Array_New)                                        \
  V(Int8Array_New)                                         \
  V(Isolate_DateTimeConfigurationChangeNotification)       \
  V(Isolate_LocaleConfigurationChangeNotification)         \
  V(JSON_Parse)                                            \
  V(JSON_Stringify)                                        \
  V(Map_AsArray)                                           \
  V(Map_Clear)                                             \
  V(Map_Delete)                                            \
  V(Map_Get)                                               \
  V(Map_Has)                                               \
  V(Map_New)                                               \
  V(Map_Set)                                               \
  V(Message_GetEndColumn)                                  \
  V(Message_GetLineNumber)                                 \
  V(Message_GetSourceLine)                                 \
  V(Message_GetStartColumn)                                \
  V(Module_Evaluate)                                       \
  V(Module_InstantiateModule)                              \
  V(Module_SetSyntheticModuleExport)                       \
  V(NumberObject_New)                                      \
  V(NumberObject_NumberValue)                              \
  V(Object_CallAsConstructor)                              \
  V(Object_CallAsFunction)                                 \
  V(Object_CreateDataProperty)                             \
  V(Object_DefineOwnProperty)                              \
  V(Object_DefineProperty)                                 \
  V(Object_Delete)                                         \
  V(Object_DeleteProperty)                                 \
  V(Object_ForceSet)                                       \
  V(Object_Get)                                            \
  V(Object_GetOwnPropertyDescriptor)                       \
  V(Object_GetOwnPropertyNames)                            \
  V(Object_GetPropertyAttributes)                          \
  V(Object_GetPropertyNames)                               \
  V(Object_GetRealNamedProperty)                           \
  V(Object_GetRealNamedPropertyAttributes)                 \
  V(Object_GetRealNamedPropertyAttributesInPrototypeChain) \
  V(Object_GetRealNamedPropertyInPrototypeChain)           \
  V(Object_Has)                                            \
  V(Object_HasOwnProperty)                                 \
  V(Object_HasRealIndexedProperty)                         \
  V(Object_HasRealNamedCallbackProperty)                   \
  V(Object_HasRealNamedProperty)                           \
  V(Object_IsCodeLike)                                     \
  V(Object_New)                                            \
  V(Object_ObjectProtoToString)                            \
  V(Object_Set)                                            \
  V(Object_SetAccessor)                                    \
  V(Object_SetIntegrityLevel)                              \
  V(Object_SetPrivate)                                     \
  V(Object_SetPrototype)                                   \
  V(ObjectTemplate_New)                                    \
  V(ObjectTemplate_NewInstance)                            \
  V(Object_ToArrayIndex)                                   \
  V(Object_ToBigInt)                                       \
  V(Object_ToDetailString)                                 \
  V(Object_ToInt32)                                        \
  V(Object_ToInteger)                                      \
  V(Object_ToNumber)                                       \
  V(Object_ToNumeric)                                      \
  V(Object_ToObject)                                       \
  V(Object_ToPrimitive)                                    \
  V(Object_ToString)                                       \
  V(Object_ToUint32)                                       \
  V(Persistent_New)                                        \
  V(Private_New)                                           \
  V(Promise_Catch)                                         \
  V(Promise_Chain)                                         \
  V(Promise_HasRejectHandler)                              \
  V(Promise_Resolver_New)                                  \
  V(Promise_Resolver_Reject)                               \
  V(Promise_Resolver_Resolve)                              \
  V(Promise_Result)                                        \
  V(Promise_Status)                                        \
  V(Promise_Then)                                          \
  V(Proxy_New)                                             \
  V(RangeError_New)                                        \
  V(ReferenceError_New)                                    \
  V(RegExp_Exec)                                           \
  V(RegExp_New)                                            \
  V(ScriptCompiler_Compile)                                \
  V(ScriptCompiler_CompileFunction)                        \
  V(ScriptCompiler_CompileUnbound)                         \
  V(Script_Run)                                            \
  V(Set_Add)                                               \
  V(Set_AsArray)                                           \
  V(Set_Clear)                                             \
  V(Set_Delete)                                            \
  V(Set_Has)                                               \
  V(Set_New)                                               \
  V(SharedArrayBuffer_New)                                 \
  V(SharedArrayBuffer_NewBackingStore)                     \
  V(String_Concat)                                         \
  V(String_NewExternalOneByte)                             \
  V(String_NewExternalTwoByte)                             \
  V(String_NewFromOneByte)                                 \
  V(String_NewFromTwoByte)                                 \
  V(String_NewFromUtf8)                                    \
  V(String_NewFromUtf8Literal)                             \
  V(StringObject_New)                                      \
  V(StringObject_StringValue)                              \
  V(String_Write)                                          \
  V(String_WriteUtf8)                                      \
  V(Symbol_New)                                            \
  V(SymbolObject_New)                                      \
  V(SymbolObject_SymbolValue)                              \
  V(SyntaxError_New)                                       \
  V(TracedGlobal_New)                                      \
  V(TryCatch_StackTrace)                                   \
  V(TypeError_New)                                         \
  V(Uint16Array_New)                                       \
  V(Uint32Array_New)                                       \
  V(Uint8Array_New)                                        \
  V(Uint8ClampedArray_New)                                 \
  V(UnboundModuleScript_GetSourceMappingURL)               \
  V(UnboundModuleScript_GetSourceURL)                      \
  V(UnboundScript_GetColumnNumber)                         \
  V(UnboundScript_GetId)                                   \
  V(UnboundScript_GetLineNumber)                           \
  V(UnboundScript_GetName)                                 \
  V(UnboundScript_GetSourceMappingURL)                     \
  V(UnboundScript_GetSourceURL)                            \
  V(ValueDeserializer_ReadHeader)                          \
  V(ValueDeserializer_ReadValue)                           \
  V(ValueSerializer_WriteValue)                            \
  V(Value_Equals)                                          \
  V(Value_InstanceOf)                                      \
  V(Value_Int32Value)                                      \
  V(Value_IntegerValue)                                    \
  V(Value_NumberValue)                                     \
  V(Value_TypeOf)                                          \
  V(Value_Uint32Value)                                     \
  V(WasmCompileError_New)                                  \
  V(WasmLinkError_New)                                     \
  V(WasmRuntimeError_New)                                  \
  V(WeakMap_Delete)                                        \
  V(WeakMap_Get)                                           \
  V(WeakMap_New)                                           \
  V(WeakMap_Set)

#define ADD_THREAD_SPECIFIC_COUNTER(V, Prefix, Suffix) \
  V(Prefix##Suffix)                                    \
  V(Prefix##Background##Suffix)

#define FOR_EACH_THREAD_SPECIFIC_COUNTER(V)                                   \
  ADD_THREAD_SPECIFIC_COUNTER(V, Compile, Analyse)                            \
  ADD_THREAD_SPECIFIC_COUNTER(V, Compile, Eval)                               \
  ADD_THREAD_SPECIFIC_COUNTER(V, Compile, Function)                           \
  ADD_THREAD_SPECIFIC_COUNTER(V, Compile, Ignition)                           \
  ADD_THREAD_SPECIFIC_COUNTER(V, Compile, IgnitionFinalization)               \
  ADD_THREAD_SPECIFIC_COUNTER(V, Compile, RewriteReturnResult)                \
  ADD_THREAD_SPECIFIC_COUNTER(V, Compile, ScopeAnalysis)                      \
  ADD_THREAD_SPECIFIC_COUNTER(V, Compile, Script)                             \
  ADD_THREAD_SPECIFIC_COUNTER(V, Compile, CompileTask)                        \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, AllocateFPRegisters)               \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, AllocateSimd128Registers)          \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, AllocateGeneralRegisters)          \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, AssembleCode)                      \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, AssignSpillSlots)                  \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, BitcastElision)                    \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, BranchConditionDuplication)        \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, BuildLiveRangeBundles)             \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, BuildLiveRanges)                   \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, BytecodeGraphBuilder)              \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, CommitAssignment)                  \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, ConnectRanges)                     \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, CSAEarlyOptimization)              \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, CSAOptimization)                   \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, DecideSpillingMode)                \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, DecompressionOptimization)         \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, EarlyGraphTrimming)                \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, EarlyOptimization)                 \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, EscapeAnalysis)                    \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, FinalizeCode)                      \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, FrameElision)                      \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, GenericLowering)                   \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, Inlining)                          \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, JSWasmInlining)                    \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, JSWasmLowering)                    \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, JumpThreading)                     \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, LoadElimination)                   \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, LocateSpillSlots)                  \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, LoopExitElimination)               \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, LoopPeeling)                       \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, MachineOperatorOptimization)       \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, PairingOptimization)               \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, MeetRegisterConstraints)           \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, MemoryOptimization)                \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, OptimizeMoves)                     \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, PopulateReferenceMaps)             \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, PrintGraph)                        \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, PrintTurboshaftGraph)              \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, ResolveControlFlow)                \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, ResolvePhis)                       \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize,                                    \
                              ScheduledEffectControlLinearization)            \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, ScheduledMachineLowering)          \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, Scheduling)                        \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, SelectInstructions)                \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, SimplifiedLowering)                \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, SimplifyLoops)                     \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TraceScheduleAndVerify)            \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftBlockInstrumentation)    \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftBuildGraph)              \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize,                                    \
                              TurboshaftCodeEliminationAndSimplification)     \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftCsaBranchElimination)    \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftWasmInJSInlining)        \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize,                                    \
                              TurboshaftCsaEarlyMachineOptimization)          \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftCsaLateEscapeAnalysis)   \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftCsaLoadElimination)      \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftCsaOptimize)             \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftDebugFeatureLowering)    \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize,                                    \
                              TurboshaftDecompressionOptimization)            \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftGrowableStacks)          \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftInstructionSelection)    \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftInt64Lowering)           \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftLateOptimization)        \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftLoopPeeling)             \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftLoopUnrolling)           \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftMachineLowering)         \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftMaglevGraphBuilding)     \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftOptimize)                \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftProfileApplication)      \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftRecreateSchedule)        \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftSpecialRPOScheduling)    \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftStoreStoreElimination)   \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftTagUntagLowering)        \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftTypeAssertions)          \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftTypedOptimizations)      \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftWasmDeadCodeElimination) \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftWasmGCOptimize)          \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftWasmOptimize)            \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftWasmLowering)            \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TurboshaftWasmRevec)               \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TypeAssertions)                    \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, TypedLowering)                     \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, Typer)                             \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, Untyper)                           \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, VerifyGraph)                       \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, WasmBaseOptimization)              \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, WasmGCLowering)                    \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, WasmGCOptimization)                \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, WasmInlining)                      \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, WasmLoopPeeling)                   \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, WasmLoopUnrolling)                 \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, WasmOptimization)                  \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, WasmJSLowering)                    \
  ADD_THREAD_SPECIFIC_COUNTER(V, Optimize, WasmTyping)                        \
                                                                              \
  ADD_THREAD_SPECIFIC_COUNTER(V, Parse, ArrowFunctionLiteral)                 \
  ADD_THREAD_SPECIFIC_COUNTER(V, Parse, FunctionLiteral)                      \
  ADD_THREAD_SPECIFIC_COUNTER(V, Parse, Program)                              \
  ADD_THREAD_SPECIFIC_COUNTER(V, PreParse, ArrowFunctionLiteral)              \
  ADD_THREAD_SPECIFIC_COUNTER(V, PreParse, WithVariableResolution)

#define FOR_EACH_MANUAL_COUNTER(V)             \
  V(AccessorGetterCallback)                    \
  V(AccessorSetterCallback)                    \
  V(ArrayLengthGetter)                         \
  V(ArrayLengthSetter)                         \
  V(BoundFunctionLengthGetter)                 \
  V(BoundFunctionNameGetter)                   \
  V(CodeGenerationFromStringsCallbacks)        \
  V(CompileBackgroundBaseline)                 \
  V(CompileBackgroundBaselinePreVisit)         \
  V(CompileBackgroundBaselineVisit)            \
  V(CompileBackgroundBaselineBuild)            \
  V(CompileBaseline)                           \
  V(CompileBaselineFinalization)               \
  V(CompileBaselinePreVisit)                   \
  V(CompileBaselineVisit)                      \
  V(CompileBaselineBuild)                      \
  V(CompileCollectSourcePositions)             \
  V(CompileDeserialize)                        \
  V(CompileEnqueueOnDispatcher)                \
  V(CompileFinalizeBackgroundCompileTask)      \
  V(CompileFinishNowOnDispatcher)              \
  V(CompileGetFromOptimizedCodeMap)            \
  V(CompilePublishBackgroundFinalization)      \
  V(CompileSerialize)                          \
  V(CompileWaitForDispatcher)                  \
  V(ConfigureInstance)                         \
  V(CreateApiFunction)                         \
  V(Debugger)                                  \
  V(DebuggerCallback)                          \
  V(DeoptimizeCode)                            \
  V(DeserializeContext)                        \
  V(DeserializeIsolate)                        \
  V(FinalizationRegistryCleanupFromTask)       \
  V(FunctionCallback)                          \
  V(FunctionLengthGetter)                      \
  V(FunctionPrototypeGetter)                   \
  V(FunctionPrototypeSetter)                   \
  V(GCEpilogueCallback)                        \
  V(GCPrologueCallback)                        \
  V(GC_Custom_AllAvailableGarbage)             \
  V(GC_Custom_IncrementalMarkingObserver)      \
  V(GC_Custom_SlowAllocateRaw)                 \
  V(Genesis)                                   \
  V(GetCompatibleReceiver)                     \
  V(GetMoreDataCallback)                       \
  V(IndexedDefinerCallback)                    \
  V(IndexedDeleterCallback)                    \
  V(IndexedDescriptorCallback)                 \
  V(IndexedEnumeratorCallback)                 \
  V(IndexedGetterCallback)                     \
  V(IndexedQueryCallback)                      \
  V(IndexedSetterCallback)                     \
  V(InstantiateFunction)                       \
  V(InstantiateObject)                         \
  V(Invoke)                                    \
  V(InvokeApiFunction)                         \
  V(InvokeApiInterruptCallbacks)               \
  V(IsCompatibleReceiver)                      \
  V(IsCompatibleReceiverMap)                   \
  V(IsTemplateFor)                             \
  V(JS_Execution)                              \
  V(Map_SetPrototype)                          \
  V(Map_TransitionToAccessorProperty)          \
  V(Map_TransitionToDataProperty)              \
  V(MessageListenerCallback)                   \
  V(NamedDefinerCallback)                      \
  V(NamedDeleterCallback)                      \
  V(NamedDescriptorCallback)                   \
  V(NamedEnumeratorCallback)                   \
  V(NamedGetterCallback)                       \
  V(NamedQueryCallback)                        \
  V(NamedSetterCallback)                       \
  V(ObjectVerify)                              \
  V(Object_DeleteProperty)                     \
  V(OptimizeBackgroundDispatcherJob)           \
  V(OptimizeCode)                              \
  V(OptimizeConcurrentFinalize)                \
  V(OptimizeConcurrentFinalizeMaglev)          \
  V(OptimizeConcurrentPrepare)                 \
  V(OptimizeFinalizePipelineJob)               \
  V(OptimizeHeapBrokerInitialization)          \
  V(OptimizeNonConcurrent)                     \
  V(OptimizeNonConcurrentMaglev)               \
  V(OptimizeBackgroundMaglev)                  \
  V(OptimizeRevectorizer)                      \
  V(OptimizeSerialization)                     \
  V(OptimizeSerializeMetadata)                 \
  V(ParseEval)                                 \
  V(ParseFunction)                             \
  V(PropertyCallback)                          \
  V(PrototypeMap_TransitionToAccessorProperty) \
  V(PrototypeMap_TransitionToDataProperty)     \
  V(PrototypeObject_DeleteProperty)            \
  V(ReconfigureToDataProperty)                 \
  V(SnapshotDecompress)                        \
  V(StringLengthGetter)                        \
  V(TestCounter1)                              \
  V(TestCounter2)                              \
  V(TestCounter3)                              \
  V(UpdateProtector)                           \
  V(WrappedFunctionLengthGetter)               \
  V(WrappedFunctionNameGetter)

#define FOR_EACH_HANDLER_COUNTER(V)               \
  V(KeyedLoadIC_KeyedLoadSloppyArgumentsStub)     \
  V(KeyedLoadIC_LoadElementDH)                    \
  V(KeyedLoadIC_LoadIndexedInterceptorStub)       \
  V(KeyedLoadIC_LoadIndexedStringDH)              \
  V(KeyedLoadIC_SlowStub)                         \
  V(KeyedStoreIC_ElementsTransitionAndStoreStub)  \
  V(KeyedStoreIC_KeyedStoreSloppyArgumentsStub)   \
  V(KeyedStoreIC_SlowStub)                        \
  V(KeyedStoreIC_StoreElementStub)                \
  V(KeyedStoreIC_StoreFastElementStub)            \
  V(LoadGlobalIC_LoadScriptContextField)          \
  V(LoadGlobalIC_SlowStub)                        \
  V(LoadIC_FunctionPrototypeStub)                 \
  V(LoadIC_HandlerCacheHit_Accessor)              \
  V(LoadIC_LoadAccessorDH)                        \
  V(LoadIC_LoadAccessorFromPrototypeDH)           \
  V(LoadIC_LoadApiGetterFromPrototypeDH)          \
  V(LoadIC_LoadCallback)                          \
  V(LoadIC_LoadConstantDH)                        \
  V(LoadIC_LoadConstantFromPrototypeDH)           \
  V(LoadIC_LoadFieldDH)                           \
  V(LoadIC_LoadFieldFromPrototypeDH)              \
  V(LoadIC_LoadGlobalDH)                          \
  V(LoadIC_LoadGlobalFromPrototypeDH)             \
  V(LoadIC_LoadIntegerIndexedExoticDH)            \
  V(LoadIC_LoadInterceptorDH)                     \
  V(LoadIC_LoadInterceptorFromPrototypeDH)        \
  V(LoadIC_LoadNativeDataPropertyDH)              \
  V(LoadIC_LoadNativeDataPropertyFromPrototypeDH) \
  V(LoadIC_LoadNonexistentDH)                     \
  V(LoadIC_LoadNonMaskingInterceptorDH)           \
  V(LoadIC_LoadNormalDH)                          \
  V(LoadIC_LoadNormalFromPrototypeDH)             \
  V(LoadIC_NonReceiver)                           \
  V(LoadIC_SlowStub)                              \
  V(LoadIC_StringLength)                          \
  V(LoadIC_StringWrapperLength)                   \
  V(StoreGlobalIC_SlowStub)                       \
  V(StoreGlobalIC_StoreScriptContextField)        \
  V(StoreIC_HandlerCacheHit_Accessor)             \
  V(StoreIC_NonReceiver)                          \
  V(StoreIC_SlowStub)                             \
  V(StoreIC_StoreAccessorDH)                      \
  V(StoreIC_StoreAccessorOnPrototypeDH)           \
  V(StoreIC_StoreApiSetterOnPrototypeDH)          \
  V(StoreIC_StoreFieldDH)                         \
  V(StoreIC_StoreGlobalDH)                        \
  V(StoreIC_StoreGlobalTransitionDH)              \
  V(StoreIC_StoreInterceptorStub)                 \
  V(StoreIC_StoreNativeDataPropertyDH)            \
  V(StoreIC_StoreNativeDataPropertyOnPrototypeDH) \
  V(StoreIC_StoreNormalDH)                        \
  V(StoreIC_StoreTransitionDH)                    \
  V(StoreInArrayLiteralIC_SlowStub)

enum RuntimeCallCounterId {
#define CALL_RUNTIME_COUNTER(name) kGC_##name,
  FOR_EACH_GC_COUNTER(CALL_RUNTIME_COUNTER)
#undef CALL_RUNTIME_COUNTER
#define CALL_RUNTIME_COUNTER(name) k##name,
      FOR_EACH_MANUAL_COUNTER(CALL_RUNTIME_COUNTER)
#undef CALL_RUNTIME_COUNTER
#define CALL_RUNTIME_COUNTER(name, nargs, ressize) kRuntime_##name,
          FOR_EACH_INTRINSIC(CALL_RUNTIME_COUNTER)
#undef CALL_RUNTIME_COUNTER
#define CALL_BUILTIN_COUNTER(name, Argc) kBuiltin_##name,
              BUILTIN_LIST_C(CALL_BUILTIN_COUNTER)
#undef CALL_BUILTIN_COUNTER
#define CALL_BUILTIN_COUNTER(name) kAPI_##name,
                  FOR_EACH_API_COUNTER(CALL_BUILTIN_COUNTER)
#undef CALL_BUILTIN_COUNTER
#define CALL_BUILTIN_COUNTER(name) kHandler_#
```