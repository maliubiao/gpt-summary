Response:
Let's break down the thought process for analyzing the provided C++ header file (`v8/src/tracing/trace-event.h`).

**1. Initial Scan and Purpose Identification:**

* **Keywords:**  Immediately, terms like "tracing," "trace event," "categories," "macros" jump out. This strongly suggests the file is about V8's internal tracing/logging mechanism.
* **Copyright & License:** Standard boilerplate, confirming it's part of the V8 project.
* **Include Guards:** `#ifndef V8_TRACING_TRACE_EVENT_H_` and `#define V8_TRACING_TRACE_EVENT_H_` are classic header file guards, preventing multiple inclusions.
* **Includes:**  `stddef.h`, `memory` are standard C++ headers. The `#include "v8config.h"` is a V8-specific configuration header. The conditional inclusion of either `trace-categories.h` and `debug_annotation.pbzero.h` (for Perfetto) or `trace-event-no-perfetto.h` hints at different tracing backends. `include/v8-platform.h` provides platform-specific abstractions, and `src/base/atomicops.h` and `src/base/macros.h` suggest low-level utilities.
* **Comment:** "This header file defines implementation details of how the trace macros...collect and store trace events." This is a crucial statement defining the file's role. It's *implementation-specific*, not the user-facing API.

**2. Deeper Dive into Core Concepts:**

* **Category Groups:** The `CategoryGroupEnabledFlags` enum and mentions of `category_group` are central. Tracing is organized by categories. The flags indicate *why* a category might be enabled (recording, callback, ETW).
* **Perfetto Conditional Compilation:**  The `#if defined(V8_USE_PERFETTO)` blocks clearly indicate that V8 can use either Perfetto (a system-wide tracing framework) or its own internal mechanism. This significantly impacts the code.
* **Macros:**  The file is full of macros (`#define`). Recognize that these are code substitutions done by the preprocessor. They are the primary way tracing is likely initiated within V8's codebase.
* **`TRACE_EVENT_API_*` Macros:** These look like function pointers or function-like macros that abstract the actual tracing implementation. This promotes flexibility and allows switching between Perfetto and the internal implementation.
* **Atomic Operations:** The `TRACE_EVENT_API_ATOMIC_*` macros and mentions of `v8::base::AtomicWord` are related to thread safety. Tracing likely happens from multiple threads, so atomic operations are needed to protect shared state.
* **`INTERNAL_TRACE_EVENT_*` Macros:** These are internal helper macros, likely used to simplify the definition of the user-facing `TRACE_EVENT` macros (which are likely in another header file). They handle things like getting category info and adding events.
* **`ScopedTracer`:**  This class is clearly for measuring the duration of events. It likely gets created at the beginning of a traced section and its destructor is responsible for recording the end time.
* **`CallStatsScopedTracer`:** This is related to collecting runtime call statistics when tracing is enabled. The `V8_RUNTIME_CALL_STATS` preprocessor definition indicates it's an optional feature.
* **`TraceID`:** This class seems to handle different ways of representing trace event IDs (integers, pointers, with scopes).
* **`TraceStringWithCopy`:** This is a hint that by default, string arguments to trace events might not be copied for performance reasons (assuming they have a long lifespan). This macro forces a copy.

**3. Answering the Specific Questions:**

* **Functionality:** Based on the above, the core function is to provide the *implementation details* for V8's tracing system. This includes mechanisms for enabling/disabling categories, adding trace events with different phases, arguments, and timestamps, and handling scoped events.
* **`.tq` Extension:** The file ends in `.h`, not `.tq`. Therefore, it's a standard C++ header, not a Torque source file.
* **Relationship to JavaScript:**  While this header is C++, tracing *directly* relates to observing and understanding JavaScript execution within V8. When JavaScript code runs, V8 internals emit trace events using this infrastructure. The events can then be analyzed to understand performance, identify bottlenecks, etc. Examples would be tracing garbage collection, compilation, or specific JavaScript API calls. A simple conceptual JavaScript example (though not directly interacting with this header) is shown in the provided good answer, demonstrating the *impact* of tracing on understanding JS execution.
* **Code Logic Inference:**  The macros reveal some logic. For example, `INTERNAL_TRACE_EVENT_GET_CATEGORY_INFO` shows how the enabled state of a category is retrieved and cached (using atomic operations). The `INTERNAL_TRACE_EVENT_ADD` macro shows the conditional addition of an event based on whether the category is enabled. Hypothetical input/output can be designed around these macros.
* **Common Programming Errors:** The use of macros can be error-prone if not used carefully (e.g., unintended side effects, name collisions). The `TRACE_STR_COPY` macro hints at potential lifetime issues with string arguments if the default behavior is assumed. Forgetting to enable tracing or using incorrect category names are also common issues.

**4. Structuring the Answer:**

Organize the findings into logical sections, as shown in the good answer. Start with a high-level overview of the file's purpose and then delve into specific features. Use clear and concise language, and provide code snippets to illustrate key concepts. Address each of the specific questions from the prompt directly.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Are the `TRACE_EVENT_API_*` macros actual function pointers?  *Correction:*  They could be function-like macros that expand to inline code, offering more performance. The `#define` syntax confirms they are macros.
* **Question:** How does this relate to the user-facing tracing API? *Clarification:* This file is *implementation details*. The user-facing API (likely involving macros like `TRACE_EVENT_BEGIN`, `TRACE_EVENT_END`) would be defined elsewhere and would likely use the mechanisms defined in this header.
* **Consideration:** The complexity introduced by the Perfetto conditional compilation needs to be highlighted.

By following this structured approach, starting with a broad understanding and then drilling down into specifics, one can effectively analyze and explain the functionality of a complex header file like `trace-event.h`.
好的，让我们来分析一下 `v8/src/tracing/trace-event.h` 这个 V8 源代码文件的功能。

**文件功能概览**

`v8/src/tracing/trace-event.h` 文件是 V8 JavaScript 引擎中 tracing（跟踪）机制的核心头文件之一。它定义了用于收集和存储跟踪事件的底层实现细节和 API。 简而言之，它的主要功能是：

1. **定义了用于表示和操作跟踪事件的数据结构和宏。**
2. **提供了向 V8 的 tracing 系统添加跟踪事件的接口。**
3. **处理了在不同 tracing 后端（例如，Perfetto 和 V8 内部的 tracing）之间的抽象。**
4. **定义了用于控制跟踪类别启用状态的机制。**
5. **包含了一些用于优化 tracing 性能的技巧，例如避免不必要的字符串拷贝。**

**详细功能分解**

* **条件编译和后端抽象:**
    * 文件开头使用 `#if defined(V8_USE_PERFETTO)` 来根据是否启用 Perfetto 进行条件编译。
    * Perfetto 是一个更通用的系统级跟踪工具。如果启用了 Perfetto，V8 的 tracing 事件可以被发送到 Perfetto 进行统一分析。
    * 如果未启用 Perfetto，则使用 V8 内部的 tracing 实现，相关的定义在 `trace-event-no-perfetto.h` 中。
    * 这体现了 V8 tracing 系统的灵活性，可以根据构建配置选择不同的后端。

* **跟踪类别 (Trace Categories):**
    * `CategoryGroupEnabledFlags` 枚举定义了跟踪类别组的启用标志。这些标志指示了类别组是否因记录模式、事件回调或导出到 ETW (Event Tracing for Windows) 而启用。
    * `TRACE_EVENT_API_GET_CATEGORY_GROUP_ENABLED` 宏（在非 Perfetto 情况下）定义了获取给定类别组启用状态的接口。这允许在实际记录事件之前快速检查类别是否已启用，从而避免不必要的开销。

* **添加跟踪事件:**
    * `TRACE_EVENT_API_ADD_TRACE_EVENT` 和 `TRACE_EVENT_API_ADD_TRACE_EVENT_WITH_TIMESTAMP` 宏（在非 Perfetto 情况下）定义了向 tracing 系统添加事件的接口。
    * 这些宏接受事件的阶段、类别、名称、作用域、ID、绑定 ID、参数等信息。
    * 参数通过名称、类型和值进行传递。
    * `INTERNAL_TRACE_EVENT_ADD` 等内部宏简化了添加事件的过程。

* **作用域跟踪 (Scoped Tracing):**
    * `INTERNAL_TRACE_EVENT_ADD_SCOPED` 宏用于方便地记录具有开始和结束时间的事件。它创建了一个 `ScopedTracer` 对象，在对象创建时记录开始事件，在对象销毁时记录结束事件，并计算持续时间。

* **Trace ID:**
    * `TraceID` 类用于表示跟踪事件的 ID。它可以携带一个作用域字符串，用于更清晰地标识 ID的来源。
    * `TRACE_ID_WITH_SCOPE` 宏用于创建带有作用域的 `TraceID`。

* **字符串处理:**
    * `TRACE_STR_COPY` 宏用于强制复制 `const char*` 类型的跟踪事件参数。默认情况下，tracing 系统可能假设字符串具有长生命周期，不会立即复制。使用此宏可以确保在字符串生命周期较短的情况下正确记录数据。

* **原子操作:**
    * `TRACE_EVENT_API_ATOMIC_WORD`, `TRACE_EVENT_API_ATOMIC_LOAD`, `TRACE_EVENT_API_ATOMIC_STORE` 等宏定义了用于线程安全访问跟踪状态的原子操作。这对于在多线程环境中记录跟踪事件至关重要。

* **性能优化:**
    * 文件中的许多设计决策都旨在减少 tracing 的性能开销，特别是在 tracing 未启用时。例如，使用宏进行早期检查类别启用状态。

**如果 `v8/src/tracing/trace-event.h` 以 `.tq` 结尾**

如果 `v8/src/tracing/trace-event.h` 以 `.tq` 结尾，那么它将是 **V8 Torque 源代码** 文件。Torque 是 V8 用来定义其内置函数和运行时函数的领域特定语言。

在这种情况下，这个文件会包含使用 Torque 语法编写的、与 tracing 功能相关的代码。这可能包括：

* 定义用于操作 tracing 数据的类型和结构。
* 定义用于在 Torque 代码中触发 tracing 事件的内置函数或宏。
* 实现与 tracing 相关的复杂逻辑。

**与 JavaScript 的功能关系及示例**

`v8/src/tracing/trace-event.h` 定义的底层 tracing 机制是 V8 观察和分析 JavaScript 代码执行情况的基础。当 JavaScript 代码在 V8 中运行时，引擎会在关键点插入 tracing 事件，例如：

* **垃圾回收 (Garbage Collection):**  记录 GC 的开始、结束、耗时等信息。
* **编译 (Compilation):** 记录代码编译的开始、结束、优化阶段等信息。
* **内置函数调用 (Built-in Function Calls):**  记录对 `Array.push`, `console.log` 等内置函数的调用。
* **Promise 操作:** 记录 Promise 的创建、resolve、reject 等操作。
* **V8 内部的各种事件:**  例如，作用域创建、函数调用、内存分配等。

**JavaScript 示例**

虽然 JavaScript 代码本身不能直接操作 `v8/src/tracing/trace-event.h` 中定义的 API，但可以通过 V8 提供的 tracing 功能来观察 JavaScript 代码的执行情况。例如，可以使用 Chrome DevTools 的 Performance 面板或 V8 提供的命令行标志来启用和查看 tracing 数据。

假设有以下 JavaScript 代码：

```javascript
function add(a, b) {
  console.time('add');
  const result = a + b;
  console.timeEnd('add');
  return result;
}

add(5, 10);
```

当这段代码在启用了 tracing 的 V8 环境中运行时，`v8/src/tracing/trace-event.h` 中定义的机制会记录与 `console.time` 和 `console.timeEnd` 相关的事件，以及 `add` 函数的执行信息。这些事件会包含时间戳、持续时间等信息，帮助开发者分析代码的性能。

**代码逻辑推理**

让我们以 `INTERNAL_TRACE_EVENT_GET_CATEGORY_INFO` 宏为例进行代码逻辑推理。

```c++
#define INTERNAL_TRACE_EVENT_GET_CATEGORY_INFO(category_group)             \
  static TRACE_EVENT_API_ATOMIC_WORD INTERNAL_TRACE_EVENT_UID(atomic) = 0; \
  const uint8_t* INTERNAL_TRACE_EVENT_UID(category_group_enabled);         \
  INTERNAL_TRACE_EVENT_GET_CATEGORY_INFO_CUSTOM_VARIABLES(                 \
      category_group, INTERNAL_TRACE_EVENT_UID(atomic),                    \
      INTERNAL_TRACE_EVENT_UID(category_group_enabled));

#define INTERNAL_TRACE_EVENT_GET_CATEGORY_INFO_CUSTOM_VARIABLES(             \
    category_group, atomic, category_group_enabled)                          \
  category_group_enabled =                                                   \
      reinterpret_cast<const uint8_t*>(TRACE_EVENT_API_ATOMIC_LOAD(atomic)); \
  if (!category_group_enabled) {                                             \
    category_group_enabled =                                                 \
        TRACE_EVENT_API_GET_CATEGORY_GROUP_ENABLED(category_group);          \
    TRACE_EVENT_API_ATOMIC_STORE(                                            \
        atomic, reinterpret_cast<TRACE_EVENT_API_ATOMIC_WORD>(               \
                    category_group_enabled));                                \
  }
```

**假设输入:**

* `category_group`: 字符串常量，例如 `"v8.gc"`，表示垃圾回收的跟踪类别。
* 假设该类别组最初未被启用，因此与该类别关联的原子变量 `INTERNAL_TRACE_EVENT_UID(atomic)` 的初始值为 0。

**输出:**

* `INTERNAL_TRACE_EVENT_UID(category_group_enabled)`:  指向一个 `uint8_t` 的指针，该值表示类别组是否已启用。

**推理过程:**

1. **静态变量初始化:**  `static TRACE_EVENT_API_ATOMIC_WORD INTERNAL_TRACE_EVENT_UID(atomic) = 0;`  为当前 `category_group` 创建一个静态的原子变量，用于存储指向类别组启用状态的指针。首次调用时，该变量初始化为 0。

2. **声明指针:** `const uint8_t* INTERNAL_TRACE_EVENT_UID(category_group_enabled);` 声明一个指向 `uint8_t` 的指针，用于存储类别组的启用状态。

3. **尝试加载已缓存的状态:** `category_group_enabled = reinterpret_cast<const uint8_t*>(TRACE_EVENT_API_ATOMIC_LOAD(atomic));` 尝试从原子变量中加载已缓存的类别组启用状态。由于是首次调用，`atomic` 的值为 0，`category_group_enabled` 将被赋值为 `nullptr`。

4. **如果未缓存，则获取并缓存:** `if (!category_group_enabled)` 判断类别组启用状态是否已缓存。由于 `category_group_enabled` 为 `nullptr`，条件成立。
   * `category_group_enabled = TRACE_EVENT_API_GET_CATEGORY_GROUP_ENABLED(category_group);` 调用 `TRACE_EVENT_API_GET_CATEGORY_GROUP_ENABLED` 宏（它会调用实际的函数）来获取 `category_group` 的当前启用状态。
   * `TRACE_EVENT_API_ATOMIC_STORE(atomic, reinterpret_cast<TRACE_EVENT_API_ATOMIC_WORD>(category_group_enabled));` 将获取到的类别组启用状态的指针存储到原子变量 `atomic` 中，以便后续调用可以快速访问，实现缓存。

**输出:** `INTERNAL_TRACE_EVENT_UID(category_group_enabled)` 将指向一个 `uint8_t`，其值表示 `"v8.gc"` 类别组的当前启用状态。

**涉及用户常见的编程错误**

虽然用户通常不会直接修改或使用 `v8/src/tracing/trace-event.h`，但理解其背后的机制可以帮助避免与 tracing 相关的常见错误：

1. **忘记启用跟踪类别:** 用户可能期望看到某些 tracing 信息，但忘记在启动 V8 或 Chrome 时启用相应的跟踪类别。这会导致没有事件被记录。

   **示例 (命令行标志):**  启动 Node.js 时忘记添加 `--trace-gc` 来跟踪垃圾回收事件。

2. **使用错误的跟踪类别名称:**  用户可能使用了错误的类别名称，导致 tracing 系统无法识别，从而没有事件被记录。

   **示例:**  假设用户想跟踪编译事件，但错误地使用了 `"v8.compilation.wrong"` 而不是正确的 `"v8.compile"` 类别。

3. **过度依赖未复制的字符串参数:**  如果用户向 tracing 事件传递了生命周期很短的局部字符串，并且没有使用 `TRACE_STR_COPY`，那么在 tracing 系统尝试访问该字符串时，它可能已经被释放，导致崩溃或数据损坏。

   **示例 (假设的 tracing 宏):**
   ```c++
   void foo() {
     std::string local_string = "short-lived string";
     TRACE_EVENT0("my_category", "my_event", local_string.c_str()); // 潜在问题
   }
   ```
   在这种情况下，当 `foo` 函数返回时，`local_string` 被销毁，`TRACE_EVENT0` 宏可能会持有指向已释放内存的指针。应该使用 `TRACE_STR_COPY(local_string.c_str())`。

4. **在性能关键代码中过度使用 tracing:**  虽然 tracing 对于诊断和性能分析很有用，但在性能高度敏感的代码路径中过度使用 tracing 宏可能会引入明显的性能开销，即使在 tracing 未启用时，宏的展开和条件判断也可能产生影响。

理解 `v8/src/tracing/trace-event.h` 的功能有助于开发者更有效地利用 V8 的 tracing 功能进行性能分析和问题排查。

Prompt: 
```
这是目录为v8/src/tracing/trace-event.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/tracing/trace-event.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_TRACING_TRACE_EVENT_H_
#define V8_TRACING_TRACE_EVENT_H_

#include <stddef.h>
#include <memory>

// Include first to ensure that V8_USE_PERFETTO can be defined before use.
#include "v8config.h"  // NOLINT(build/include_directory)

#if defined(V8_USE_PERFETTO)
#include "protos/perfetto/trace/track_event/debug_annotation.pbzero.h"
#include "src/tracing/trace-categories.h"
#else
#include "src/tracing/trace-event-no-perfetto.h"
#endif  // !defined(V8_USE_PERFETTO)

#include "include/v8-platform.h"
#include "src/base/atomicops.h"
#include "src/base/macros.h"

// This header file defines implementation details of how the trace macros in
// trace-event-no-perfetto.h collect and store trace events. Anything not
// implementation-specific should go in trace_macros_common.h instead of here.


// The pointer returned from GetCategoryGroupEnabled() points to a
// value with zero or more of the following bits. Used in this class only.
// The TRACE_EVENT macros should only use the value as a bool.
// These values must be in sync with macro values in trace_log.h in
// chromium.
enum CategoryGroupEnabledFlags {
  // Category group enabled for the recording mode.
  kEnabledForRecording_CategoryGroupEnabledFlags = 1 << 0,
  // Category group enabled by SetEventCallbackEnabled().
  kEnabledForEventCallback_CategoryGroupEnabledFlags = 1 << 2,
  // Category group enabled to export events to ETW.
  kEnabledForETWExport_CategoryGroupEnabledFlags = 1 << 3,
};

#if !defined(V8_USE_PERFETTO)

// TODO(petermarshall): Remove with the old tracing implementation - Perfetto
// copies const char* arguments by default.
// By default, const char* argument values are assumed to have long-lived scope
// and will not be copied. Use this macro to force a const char* to be copied.
#define TRACE_STR_COPY(str) v8::internal::tracing::TraceStringWithCopy(str)

// By default, trace IDs are eventually converted to a single 64-bit number. Use
// this macro to add a scope string.
#define TRACE_ID_WITH_SCOPE(scope, id) \
  v8::internal::tracing::TraceID::WithScope(scope, id)

#define INTERNAL_TRACE_EVENT_CATEGORY_GROUP_ENABLED_FOR_RECORDING_MODE() \
  TRACE_EVENT_API_LOAD_CATEGORY_GROUP_ENABLED() &                        \
      (kEnabledForRecording_CategoryGroupEnabledFlags |                  \
       kEnabledForEventCallback_CategoryGroupEnabledFlags)

// The following macro has no implementation, but it needs to exist since
// it gets called from scoped trace events. It cannot call UNIMPLEMENTED()
// since an empty implementation is a valid one.
#define INTERNAL_TRACE_MEMORY(category, name)

////////////////////////////////////////////////////////////////////////////////
// Implementation specific tracing API definitions.

// Get a pointer to the enabled state of the given trace category. Only
// long-lived literal strings should be given as the category group. The
// returned pointer can be held permanently in a local static for example. If
// the unsigned char is non-zero, tracing is enabled. If tracing is enabled,
// TRACE_EVENT_API_ADD_TRACE_EVENT can be called. It's OK if tracing is disabled
// between the load of the tracing state and the call to
// TRACE_EVENT_API_ADD_TRACE_EVENT, because this flag only provides an early out
// for best performance when tracing is disabled.
// const uint8_t*
//     TRACE_EVENT_API_GET_CATEGORY_GROUP_ENABLED(const char* category_group)
#define TRACE_EVENT_API_GET_CATEGORY_GROUP_ENABLED                \
  v8::internal::tracing::TraceEventHelper::GetTracingController() \
      ->GetCategoryGroupEnabled

// Get the number of times traces have been recorded. This is used to implement
// the TRACE_EVENT_IS_NEW_TRACE facility.
// unsigned int TRACE_EVENT_API_GET_NUM_TRACES_RECORDED()
#define TRACE_EVENT_API_GET_NUM_TRACES_RECORDED UNIMPLEMENTED()

// Add a trace event to the platform tracing system.
// uint64_t TRACE_EVENT_API_ADD_TRACE_EVENT(
//                    char phase,
//                    const uint8_t* category_group_enabled,
//                    const char* name,
//                    const char* scope,
//                    uint64_t id,
//                    uint64_t bind_id,
//                    int num_args,
//                    const char** arg_names,
//                    const uint8_t* arg_types,
//                    const uint64_t* arg_values,
//                    unsigned int flags)
#define TRACE_EVENT_API_ADD_TRACE_EVENT v8::internal::tracing::AddTraceEventImpl

// Add a trace event to the platform tracing system.
// uint64_t TRACE_EVENT_API_ADD_TRACE_EVENT_WITH_TIMESTAMP(
//                    char phase,
//                    const uint8_t* category_group_enabled,
//                    const char* name,
//                    const char* scope,
//                    uint64_t id,
//                    uint64_t bind_id,
//                    int num_args,
//                    const char** arg_names,
//                    const uint8_t* arg_types,
//                    const uint64_t* arg_values,
//                    unsigned int flags,
//                    int64_t timestamp)
#define TRACE_EVENT_API_ADD_TRACE_EVENT_WITH_TIMESTAMP \
  v8::internal::tracing::AddTraceEventWithTimestampImpl

// Set the duration field of a COMPLETE trace event.
// void TRACE_EVENT_API_UPDATE_TRACE_EVENT_DURATION(
//     const uint8_t* category_group_enabled,
//     const char* name,
//     uint64_t id)
#define TRACE_EVENT_API_UPDATE_TRACE_EVENT_DURATION               \
  v8::internal::tracing::TraceEventHelper::GetTracingController() \
      ->UpdateTraceEventDuration

// Defines atomic operations used internally by the tracing system.
// Acquire/release barriers are important here: crbug.com/1330114#c8.
#define TRACE_EVENT_API_ATOMIC_WORD v8::base::AtomicWord
#define TRACE_EVENT_API_ATOMIC_LOAD(var) v8::base::Acquire_Load(&(var))
#define TRACE_EVENT_API_ATOMIC_STORE(var, value) \
  v8::base::Release_Store(&(var), (value))
// This load can be Relaxed because it's reading the state of
// `category_group_enabled` and not inferring other variable's state from the
// result.
#define TRACE_EVENT_API_LOAD_CATEGORY_GROUP_ENABLED()                \
  v8::base::Relaxed_Load(reinterpret_cast<const v8::base::Atomic8*>( \
      INTERNAL_TRACE_EVENT_UID(category_group_enabled)))

////////////////////////////////////////////////////////////////////////////////

// Implementation detail: trace event macros create temporary variables
// to keep instrumentation overhead low. These macros give each temporary
// variable a unique name based on the line number to prevent name collisions.
#define INTERNAL_TRACE_EVENT_UID3(a, b) trace_event_unique_##a##b
#define INTERNAL_TRACE_EVENT_UID2(a, b) INTERNAL_TRACE_EVENT_UID3(a, b)
#define INTERNAL_TRACE_EVENT_UID(name_prefix) \
  INTERNAL_TRACE_EVENT_UID2(name_prefix, __LINE__)

// Implementation detail: internal macro to create static category.
// No barriers are needed, because this code is designed to operate safely
// even when the unsigned char* points to garbage data (which may be the case
// on processors without cache coherency).
// TODO(fmeawad): This implementation contradicts that we can have a different
// configuration for each isolate,
// https://code.google.com/p/v8/issues/detail?id=4563
#define INTERNAL_TRACE_EVENT_GET_CATEGORY_INFO_CUSTOM_VARIABLES(             \
    category_group, atomic, category_group_enabled)                          \
  category_group_enabled =                                                   \
      reinterpret_cast<const uint8_t*>(TRACE_EVENT_API_ATOMIC_LOAD(atomic)); \
  if (!category_group_enabled) {                                             \
    category_group_enabled =                                                 \
        TRACE_EVENT_API_GET_CATEGORY_GROUP_ENABLED(category_group);          \
    TRACE_EVENT_API_ATOMIC_STORE(                                            \
        atomic, reinterpret_cast<TRACE_EVENT_API_ATOMIC_WORD>(               \
                    category_group_enabled));                                \
  }

#define INTERNAL_TRACE_EVENT_GET_CATEGORY_INFO(category_group)             \
  static TRACE_EVENT_API_ATOMIC_WORD INTERNAL_TRACE_EVENT_UID(atomic) = 0; \
  const uint8_t* INTERNAL_TRACE_EVENT_UID(category_group_enabled);         \
  INTERNAL_TRACE_EVENT_GET_CATEGORY_INFO_CUSTOM_VARIABLES(                 \
      category_group, INTERNAL_TRACE_EVENT_UID(atomic),                    \
      INTERNAL_TRACE_EVENT_UID(category_group_enabled));

// Implementation detail: internal macro to create static category and add
// event if the category is enabled.
#define INTERNAL_TRACE_EVENT_ADD(phase, category_group, name, flags, ...)    \
  do {                                                                       \
    INTERNAL_TRACE_EVENT_GET_CATEGORY_INFO(category_group);                  \
    if (INTERNAL_TRACE_EVENT_CATEGORY_GROUP_ENABLED_FOR_RECORDING_MODE()) {  \
      v8::internal::tracing::AddTraceEvent(                                  \
          phase, INTERNAL_TRACE_EVENT_UID(category_group_enabled), name,     \
          v8::internal::tracing::kGlobalScope, v8::internal::tracing::kNoId, \
          v8::internal::tracing::kNoId, flags, ##__VA_ARGS__);               \
    }                                                                        \
  } while (false)

// Implementation detail: internal macro to create static category and add begin
// event if the category is enabled. Also adds the end event when the scope
// ends.
#define INTERNAL_TRACE_EVENT_ADD_SCOPED(category_group, name, ...)           \
  INTERNAL_TRACE_EVENT_GET_CATEGORY_INFO(category_group);                    \
  v8::internal::tracing::ScopedTracer INTERNAL_TRACE_EVENT_UID(tracer);      \
  if (INTERNAL_TRACE_EVENT_CATEGORY_GROUP_ENABLED_FOR_RECORDING_MODE()) {    \
    uint64_t h = v8::internal::tracing::AddTraceEvent(                       \
        TRACE_EVENT_PHASE_COMPLETE,                                          \
        INTERNAL_TRACE_EVENT_UID(category_group_enabled), name,              \
        v8::internal::tracing::kGlobalScope, v8::internal::tracing::kNoId,   \
        v8::internal::tracing::kNoId, TRACE_EVENT_FLAG_NONE, ##__VA_ARGS__); \
    INTERNAL_TRACE_EVENT_UID(tracer)                                         \
        .Initialize(INTERNAL_TRACE_EVENT_UID(category_group_enabled), name,  \
                    h);                                                      \
  }

#define INTERNAL_TRACE_EVENT_ADD_SCOPED_WITH_FLOW(category_group, name,     \
                                                  bind_id, flow_flags, ...) \
  INTERNAL_TRACE_EVENT_GET_CATEGORY_INFO(category_group);                   \
  v8::internal::tracing::ScopedTracer INTERNAL_TRACE_EVENT_UID(tracer);     \
  if (INTERNAL_TRACE_EVENT_CATEGORY_GROUP_ENABLED_FOR_RECORDING_MODE()) {   \
    unsigned int trace_event_flags = flow_flags;                            \
    v8::internal::tracing::TraceID trace_event_bind_id(bind_id,             \
                                                       &trace_event_flags); \
    uint64_t h = v8::internal::tracing::AddTraceEvent(                      \
        TRACE_EVENT_PHASE_COMPLETE,                                         \
        INTERNAL_TRACE_EVENT_UID(category_group_enabled), name,             \
        v8::internal::tracing::kGlobalScope, v8::internal::tracing::kNoId,  \
        trace_event_bind_id.raw_id(), trace_event_flags, ##__VA_ARGS__);    \
    INTERNAL_TRACE_EVENT_UID(tracer)                                        \
        .Initialize(INTERNAL_TRACE_EVENT_UID(category_group_enabled), name, \
                    h);                                                     \
  }

// Implementation detail: internal macro to create static category and add
// event if the category is enabled.
#define INTERNAL_TRACE_EVENT_ADD_WITH_ID(phase, category_group, name, id,      \
                                         flags, ...)                           \
  do {                                                                         \
    INTERNAL_TRACE_EVENT_GET_CATEGORY_INFO(category_group);                    \
    if (INTERNAL_TRACE_EVENT_CATEGORY_GROUP_ENABLED_FOR_RECORDING_MODE()) {    \
      unsigned int trace_event_flags = flags | TRACE_EVENT_FLAG_HAS_ID;        \
      v8::internal::tracing::TraceID trace_event_trace_id(id,                  \
                                                          &trace_event_flags); \
      v8::internal::tracing::AddTraceEvent(                                    \
          phase, INTERNAL_TRACE_EVENT_UID(category_group_enabled), name,       \
          trace_event_trace_id.scope(), trace_event_trace_id.raw_id(),         \
          v8::internal::tracing::kNoId, trace_event_flags, ##__VA_ARGS__);     \
    }                                                                          \
  } while (false)

// Adds a trace event with a given timestamp.
#define INTERNAL_TRACE_EVENT_ADD_WITH_TIMESTAMP(phase, category_group, name, \
                                                timestamp, flags, ...)       \
  do {                                                                       \
    INTERNAL_TRACE_EVENT_GET_CATEGORY_INFO(category_group);                  \
    if (INTERNAL_TRACE_EVENT_CATEGORY_GROUP_ENABLED_FOR_RECORDING_MODE()) {  \
      v8::internal::tracing::AddTraceEventWithTimestamp(                     \
          phase, INTERNAL_TRACE_EVENT_UID(category_group_enabled), name,     \
          v8::internal::tracing::kGlobalScope, v8::internal::tracing::kNoId, \
          v8::internal::tracing::kNoId, flags, timestamp, ##__VA_ARGS__);    \
    }                                                                        \
  } while (false)

// Adds a trace event with a given id and timestamp.
#define INTERNAL_TRACE_EVENT_ADD_WITH_ID_AND_TIMESTAMP(                        \
    phase, category_group, name, id, timestamp, flags, ...)                    \
  do {                                                                         \
    INTERNAL_TRACE_EVENT_GET_CATEGORY_INFO(category_group);                    \
    if (INTERNAL_TRACE_EVENT_CATEGORY_GROUP_ENABLED_FOR_RECORDING_MODE()) {    \
      unsigned int trace_event_flags = flags | TRACE_EVENT_FLAG_HAS_ID;        \
      v8::internal::tracing::TraceID trace_event_trace_id(id,                  \
                                                          &trace_event_flags); \
      v8::internal::tracing::AddTraceEventWithTimestamp(                       \
          phase, INTERNAL_TRACE_EVENT_UID(category_group_enabled), name,       \
          trace_event_trace_id.scope(), trace_event_trace_id.raw_id(),         \
          v8::internal::tracing::kNoId, trace_event_flags, timestamp,          \
          ##__VA_ARGS__);                                                      \
    }                                                                          \
  } while (false)

// Adds a trace event with a given id, thread_id, and timestamp. This redirects
// to INTERNAL_TRACE_EVENT_ADD_WITH_ID_AND_TIMESTAMP as we presently do not care
// about the thread id.
#define INTERNAL_TRACE_EVENT_ADD_WITH_ID_TID_AND_TIMESTAMP(            \
    phase, category_group, name, id, thread_id, timestamp, flags, ...) \
  INTERNAL_TRACE_EVENT_ADD_WITH_ID_AND_TIMESTAMP(                      \
      phase, category_group, name, id, timestamp, flags, ##__VA_ARGS__)

#define TRACE_EVENT_CALL_STATS_SCOPED(isolate, category_group, name) \
  INTERNAL_TRACE_EVENT_CALL_STATS_SCOPED(isolate, category_group, name)

#ifdef V8_RUNTIME_CALL_STATS
#define INTERNAL_TRACE_EVENT_CALL_STATS_SCOPED(isolate, category_group, name)  \
  INTERNAL_TRACE_EVENT_GET_CATEGORY_INFO(category_group);                      \
  v8::internal::tracing::CallStatsScopedTracer INTERNAL_TRACE_EVENT_UID(       \
      tracer);                                                                 \
  if (INTERNAL_TRACE_EVENT_CATEGORY_GROUP_ENABLED_FOR_RECORDING_MODE()) {      \
    INTERNAL_TRACE_EVENT_UID(tracer)                                           \
        .Initialize(isolate, INTERNAL_TRACE_EVENT_UID(category_group_enabled), \
                    name);                                                     \
  }
#else  // V8_RUNTIME_CALL_STATS
#define INTERNAL_TRACE_EVENT_CALL_STATS_SCOPED(isolate, category_group, name)
#endif  // V8_RUNTIME_CALL_STATS

namespace v8 {
namespace internal {

class Isolate;

namespace tracing {

// Specify these values when the corresponding argument of AddTraceEvent
// is not used.
const int kZeroNumArgs = 0;
const decltype(nullptr) kGlobalScope = nullptr;
const uint64_t kNoId = 0;

class TraceEventHelper {
 public:
  V8_EXPORT_PRIVATE static v8::TracingController* GetTracingController();
};

// TraceID encapsulates an ID that can either be an integer or pointer.
class TraceID {
 public:
  class WithScope {
   public:
    WithScope(const char* scope, uint64_t raw_id)
        : scope_(scope), raw_id_(raw_id) {}
    uint64_t raw_id() const { return raw_id_; }
    const char* scope() const { return scope_; }

   private:
    const char* scope_ = nullptr;
    uint64_t raw_id_;
  };

  TraceID(const void* raw_id, unsigned int* flags)
      : raw_id_(static_cast<uint64_t>(reinterpret_cast<uintptr_t>(raw_id))) {}
  TraceID(uint64_t raw_id, unsigned int* flags) : raw_id_(raw_id) {
    (void)flags;
  }
  TraceID(unsigned int raw_id, unsigned int* flags) : raw_id_(raw_id) {
    (void)flags;
  }
  TraceID(uint16_t raw_id, unsigned int* flags) : raw_id_(raw_id) {
    (void)flags;
  }
  TraceID(unsigned char raw_id, unsigned int* flags) : raw_id_(raw_id) {
    (void)flags;
  }
  TraceID(int64_t raw_id, unsigned int* flags)
      : raw_id_(static_cast<uint64_t>(raw_id)) {
    (void)flags;
  }
  TraceID(int raw_id, unsigned int* flags)
      : raw_id_(static_cast<uint64_t>(raw_id)) {
    (void)flags;
  }
  TraceID(int16_t raw_id, unsigned int* flags)
      : raw_id_(static_cast<uint64_t>(raw_id)) {
    (void)flags;
  }
  TraceID(signed char raw_id, unsigned int* flags)
      : raw_id_(static_cast<uint64_t>(raw_id)) {
    (void)flags;
  }
  TraceID(WithScope scoped_id, unsigned int* flags)
      : scope_(scoped_id.scope()), raw_id_(scoped_id.raw_id()) {}

  uint64_t raw_id() const { return raw_id_; }
  const char* scope() const { return scope_; }

 private:
  const char* scope_ = nullptr;
  uint64_t raw_id_;
};

// Simple container for const char* that should be copied instead of retained.
class TraceStringWithCopy {
 public:
  explicit TraceStringWithCopy(const char* str) : str_(str) {}
  operator const char*() const { return str_; }

 private:
  const char* str_;
};

static V8_INLINE uint64_t AddTraceEventImpl(
    char phase, const uint8_t* category_group_enabled, const char* name,
    const char* scope, uint64_t id, uint64_t bind_id, int32_t num_args,
    const char** arg_names, const uint8_t* arg_types,
    const uint64_t* arg_values, unsigned int flags) {
  std::unique_ptr<ConvertableToTraceFormat> arg_convertables[2];
  if (num_args > 0 && arg_types[0] == TRACE_VALUE_TYPE_CONVERTABLE) {
    arg_convertables[0].reset(reinterpret_cast<ConvertableToTraceFormat*>(
        static_cast<intptr_t>(arg_values[0])));
  }
  if (num_args > 1 && arg_types[1] == TRACE_VALUE_TYPE_CONVERTABLE) {
    arg_convertables[1].reset(reinterpret_cast<ConvertableToTraceFormat*>(
        static_cast<intptr_t>(arg_values[1])));
  }
  DCHECK_LE(num_args, 2);
  v8::TracingController* controller =
      v8::internal::tracing::TraceEventHelper::GetTracingController();
  return controller->AddTraceEvent(phase, category_group_enabled, name, scope,
                                   id, bind_id, num_args, arg_names, arg_types,
                                   arg_values, arg_convertables, flags);
}

static V8_INLINE uint64_t AddTraceEventWithTimestampImpl(
    char phase, const uint8_t* category_group_enabled, const char* name,
    const char* scope, uint64_t id, uint64_t bind_id, int32_t num_args,
    const char** arg_names, const uint8_t* arg_types,
    const uint64_t* arg_values, unsigned int flags, int64_t timestamp) {
  std::unique_ptr<ConvertableToTraceFormat> arg_convertables[2];
  if (num_args > 0 && arg_types[0] == TRACE_VALUE_TYPE_CONVERTABLE) {
    arg_convertables[0].reset(reinterpret_cast<ConvertableToTraceFormat*>(
        static_cast<intptr_t>(arg_values[0])));
  }
  if (num_args > 1 && arg_types[1] == TRACE_VALUE_TYPE_CONVERTABLE) {
    arg_convertables[1].reset(reinterpret_cast<ConvertableToTraceFormat*>(
        static_cast<intptr_t>(arg_values[1])));
  }
  DCHECK_LE(num_args, 2);
  v8::TracingController* controller =
      v8::internal::tracing::TraceEventHelper::GetTracingController();
  return controller->AddTraceEventWithTimestamp(
      phase, category_group_enabled, name, scope, id, bind_id, num_args,
      arg_names, arg_types, arg_values, arg_convertables, flags, timestamp);
}

// Define SetTraceValue for each allowed type. It stores the type and
// value in the return arguments. This allows this API to avoid declaring any
// structures so that it is portable to third_party libraries.
// This is the base implementation for integer types (including bool) and enums.
template <typename T>
static V8_INLINE typename std::enable_if<
    std::is_integral<T>::value || std::is_enum<T>::value, void>::type
SetTraceValue(T arg, unsigned char* type, uint64_t* value) {
  *type = std::is_same<T, bool>::value
              ? TRACE_VALUE_TYPE_BOOL
              : std::is_signed<T>::value ? TRACE_VALUE_TYPE_INT
                                         : TRACE_VALUE_TYPE_UINT;
  *value = static_cast<uint64_t>(arg);
}

#define INTERNAL_DECLARE_SET_TRACE_VALUE(actual_type, value_type_id)        \
  static V8_INLINE void SetTraceValue(actual_type arg, unsigned char* type, \
                                      uint64_t* value) {                    \
    *type = value_type_id;                                                  \
    *value = 0;                                                             \
    static_assert(sizeof(arg) <= sizeof(*value));                           \
    memcpy(value, &arg, sizeof(arg));                                       \
  }
INTERNAL_DECLARE_SET_TRACE_VALUE(double, TRACE_VALUE_TYPE_DOUBLE)
INTERNAL_DECLARE_SET_TRACE_VALUE(const void*, TRACE_VALUE_TYPE_POINTER)
INTERNAL_DECLARE_SET_TRACE_VALUE(const char*, TRACE_VALUE_TYPE_STRING)
INTERNAL_DECLARE_SET_TRACE_VALUE(const TraceStringWithCopy&,
                                 TRACE_VALUE_TYPE_COPY_STRING)
#undef INTERNAL_DECLARE_SET_TRACE_VALUE

static V8_INLINE void SetTraceValue(ConvertableToTraceFormat* convertable_value,
                                    unsigned char* type, uint64_t* value) {
  *type = TRACE_VALUE_TYPE_CONVERTABLE;
  *value = static_cast<uint64_t>(reinterpret_cast<intptr_t>(convertable_value));
}

template <typename T>
static V8_INLINE typename std::enable_if<
    std::is_convertible<T*, ConvertableToTraceFormat*>::value>::type
SetTraceValue(std::unique_ptr<T> ptr, unsigned char* type, uint64_t* value) {
  SetTraceValue(ptr.release(), type, value);
}

// These AddTraceEvent template
// function is defined here instead of in the macro, because the arg_values
// could be temporary objects, such as std::string. In order to store
// pointers to the internal c_str and pass through to the tracing API,
// the arg_values must live throughout these procedures.

static V8_INLINE uint64_t AddTraceEvent(char phase,
                                        const uint8_t* category_group_enabled,
                                        const char* name, const char* scope,
                                        uint64_t id, uint64_t bind_id,
                                        unsigned int flags) {
  return TRACE_EVENT_API_ADD_TRACE_EVENT(phase, category_group_enabled, name,
                                         scope, id, bind_id, kZeroNumArgs,
                                         nullptr, nullptr, nullptr, flags);
}

template <class ARG1_TYPE>
static V8_INLINE uint64_t AddTraceEvent(
    char phase, const uint8_t* category_group_enabled, const char* name,
    const char* scope, uint64_t id, uint64_t bind_id, unsigned int flags,
    const char* arg1_name, ARG1_TYPE&& arg1_val) {
  const int num_args = 1;
  uint8_t arg_type;
  uint64_t arg_value;
  SetTraceValue(std::forward<ARG1_TYPE>(arg1_val), &arg_type, &arg_value);
  return TRACE_EVENT_API_ADD_TRACE_EVENT(
      phase, category_group_enabled, name, scope, id, bind_id, num_args,
      &arg1_name, &arg_type, &arg_value, flags);
}

template <class ARG1_TYPE, class ARG2_TYPE>
static V8_INLINE uint64_t AddTraceEvent(
    char phase, const uint8_t* category_group_enabled, const char* name,
    const char* scope, uint64_t id, uint64_t bind_id, unsigned int flags,
    const char* arg1_name, ARG1_TYPE&& arg1_val, const char* arg2_name,
    ARG2_TYPE&& arg2_val) {
  const int num_args = 2;
  const char* arg_names[2] = {arg1_name, arg2_name};
  unsigned char arg_types[2];
  uint64_t arg_values[2];
  SetTraceValue(std::forward<ARG1_TYPE>(arg1_val), &arg_types[0],
                &arg_values[0]);
  SetTraceValue(std::forward<ARG2_TYPE>(arg2_val), &arg_types[1],
                &arg_values[1]);
  return TRACE_EVENT_API_ADD_TRACE_EVENT(
      phase, category_group_enabled, name, scope, id, bind_id, num_args,
      arg_names, arg_types, arg_values, flags);
}

static V8_INLINE uint64_t AddTraceEventWithTimestamp(
    char phase, const uint8_t* category_group_enabled, const char* name,
    const char* scope, uint64_t id, uint64_t bind_id, unsigned int flags,
    int64_t timestamp) {
  return TRACE_EVENT_API_ADD_TRACE_EVENT_WITH_TIMESTAMP(
      phase, category_group_enabled, name, scope, id, bind_id, kZeroNumArgs,
      nullptr, nullptr, nullptr, flags, timestamp);
}

template <class ARG1_TYPE>
static V8_INLINE uint64_t AddTraceEventWithTimestamp(
    char phase, const uint8_t* category_group_enabled, const char* name,
    const char* scope, uint64_t id, uint64_t bind_id, unsigned int flags,
    int64_t timestamp, const char* arg1_name, ARG1_TYPE&& arg1_val) {
  const int num_args = 1;
  uint8_t arg_type;
  uint64_t arg_value;
  SetTraceValue(std::forward<ARG1_TYPE>(arg1_val), &arg_type, &arg_value);
  return TRACE_EVENT_API_ADD_TRACE_EVENT_WITH_TIMESTAMP(
      phase, category_group_enabled, name, scope, id, bind_id, num_args,
      &arg1_name, &arg_type, &arg_value, flags, timestamp);
}

template <class ARG1_TYPE, class ARG2_TYPE>
static V8_INLINE uint64_t AddTraceEventWithTimestamp(
    char phase, const uint8_t* category_group_enabled, const char* name,
    const char* scope, uint64_t id, uint64_t bind_id, unsigned int flags,
    int64_t timestamp, const char* arg1_name, ARG1_TYPE&& arg1_val,
    const char* arg2_name, ARG2_TYPE&& arg2_val) {
  const int num_args = 2;
  const char* arg_names[2] = {arg1_name, arg2_name};
  unsigned char arg_types[2];
  uint64_t arg_values[2];
  SetTraceValue(std::forward<ARG1_TYPE>(arg1_val), &arg_types[0],
                &arg_values[0]);
  SetTraceValue(std::forward<ARG2_TYPE>(arg2_val), &arg_types[1],
                &arg_values[1]);
  return TRACE_EVENT_API_ADD_TRACE_EVENT_WITH_TIMESTAMP(
      phase, category_group_enabled, name, scope, id, bind_id, num_args,
      arg_names, arg_types, arg_values, flags, timestamp);
}

// Used by TRACE_EVENTx macros. Do not use directly.
class ScopedTracer {
 public:
  // Note: members of data_ intentionally left uninitialized. See Initialize.
  ScopedTracer() : p_data_(nullptr) {}

  ~ScopedTracer() {
    if (p_data_ && base::Relaxed_Load(reinterpret_cast<const base::Atomic8*>(
                       data_.category_group_enabled))) {
      TRACE_EVENT_API_UPDATE_TRACE_EVENT_DURATION(
          data_.category_group_enabled, data_.name, data_.event_handle);
    }
  }

  void Initialize(const uint8_t* category_group_enabled, const char* name,
                  uint64_t event_handle) {
    data_.category_group_enabled = category_group_enabled;
    data_.name = name;
    data_.event_handle = event_handle;
    p_data_ = &data_;
  }

 private:
  // This Data struct workaround is to avoid initializing all the members
  // in Data during construction of this object, since this object is always
  // constructed, even when tracing is disabled. If the members of Data were
  // members of this class instead, compiler warnings occur about potential
  // uninitialized accesses.
  struct Data {
    const uint8_t* category_group_enabled;
    const char* name;
    uint64_t event_handle;
  };
  Data* p_data_;
  Data data_;
};

#ifdef V8_RUNTIME_CALL_STATS
// Do not use directly.
class CallStatsScopedTracer {
 public:
  CallStatsScopedTracer() : p_data_(nullptr) {}
  ~CallStatsScopedTracer() {
    if (V8_UNLIKELY(p_data_ && *data_.category_group_enabled)) {
      AddEndTraceEvent();
    }
  }

  void Initialize(v8::internal::Isolate* isolate,
                  const uint8_t* category_group_enabled, const char* name);

 private:
  void AddEndTraceEvent();
  struct Data {
    const uint8_t* category_group_enabled;
    const char* name;
    v8::internal::Isolate* isolate;
  };
  bool has_parent_scope_;
  Data* p_data_;
  Data data_;
};
#endif  // V8_RUNTIME_CALL_STATS

}  // namespace tracing
}  // namespace internal
}  // namespace v8

#else  // defined(V8_USE_PERFETTO)

#ifdef V8_RUNTIME_CALL_STATS

#define TRACE_EVENT_CALL_STATS_SCOPED(isolate, category, name)             \
  struct PERFETTO_UID(ScopedEvent) {                                       \
    struct ScopedStats {                                                   \
      ScopedStats(v8::internal::Isolate* isolate_arg, int) {               \
        TRACE_EVENT_BEGIN(category, name, [&](perfetto::EventContext) {    \
          isolate_ = isolate_arg;                                          \
          internal::RuntimeCallStats* table =                              \
              isolate_->counters()->runtime_call_stats();                  \
          has_parent_scope_ = table->InUse();                              \
          if (!has_parent_scope_) table->Reset();                          \
        });                                                                \
      }                                                                    \
      ~ScopedStats() {                                                     \
        TRACE_EVENT_END(category, [&](perfetto::EventContext ctx) {        \
          if (!has_parent_scope_ && isolate_) {                            \
            /* TODO(skyostil): Write as typed event instead of JSON */     \
            auto value = v8::tracing::TracedValue::Create();               \
            isolate_->counters()->runtime_call_stats()->Dump(value.get()); \
            auto annotation = ctx.event()->add_debug_annotations();        \
            annotation->set_name("runtime-call-stats");                    \
            value->Add(annotation);                                        \
          }                                                                \
        });                                                                \
      }                                                                    \
      v8::internal::Isolate* isolate_ = nullptr;                           \
      bool has_parent_scope_ = false;                                      \
    } stats;                                                               \
  } PERFETTO_UID(scoped_event) {                                           \
    { isolate, 0 }                                                         \
  }
#else  // V8_RUNTIME_CALL_STATS
#define TRACE_EVENT_CALL_STATS_SCOPED(isolate, category, name)
#endif  // V8_RUNTIME_CALL_STATS
#endif  // defined(V8_USE_PERFETTO)

#endif  // V8_TRACING_TRACE_EVENT_H_

"""

```