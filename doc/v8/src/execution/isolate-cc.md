Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine. Here's a breakdown of the thought process to arrive at the answer:

1. **Identify the core file:** The file is `v8/src/execution/isolate.cc`. The name "isolate" is a strong indicator of its primary function. In V8, an isolate represents an independent instance of the JavaScript engine.

2. **Scan the includes:**  The `#include` directives provide a high-level overview of the file's dependencies and thus, its concerns. Look for recurring themes and important V8 components. Notable includes include:
    * `v8-template.h`:  Suggests interaction with the V8 API.
    * `api/...`: Reinforces API involvement.
    * `ast/...`: Indicates involvement in Abstract Syntax Tree processing.
    * `codegen/...`: Points to code generation and compilation.
    * `execution/...`: This directory itself suggests core execution logic.
    * `heap/...`:  Indicates memory management and garbage collection.
    * `builtins/...`: Shows interaction with built-in JavaScript functions.
    * `objects/...`:  Suggests handling of JavaScript objects in the engine.
    * `debug/...`: Implies debugging and profiling capabilities.
    * `snapshot/...`:  Points to snapshotting and deserialization mechanisms.
    * `wasm/...`: Shows support for WebAssembly.

3. **Examine the namespace:** The code is within the `v8::internal` namespace, which is where V8's internal implementation details reside.

4. **Analyze key data structures and functions:**  Look for significant variables and functions. The `Isolate` class itself is the most important. Pay attention to static members and member variables.
    * **Embedded Blob:** The code heavily deals with "embedded blobs."  The names `DefaultEmbeddedBlobCode`, `StickyEmbeddedBlob`, `CurrentEmbeddedBlob` strongly suggest this is about storing and managing pre-compiled code and data. This is crucial for fast startup.
    * **Thread Management:** Variables like `thread_data_table_`, `thread_data_table_mutex_`, and functions like `FindOrAllocatePerThreadDataForThisThread` clearly indicate the isolate manages data specific to individual threads.
    * **Current Isolate:** The `g_current_isolate_` variable and related functions (`SetCurrent`, `TryGetCurrent`) are vital for accessing the currently active isolate.
    * **Stack Tracing:** Functions like `StackTraceString`, `PushStackTraceAndDie` point to error handling and debugging capabilities.
    * **Root Visiting:**  The `Iterate` functions are related to garbage collection, as they allow the garbage collector to traverse the object graph.
    * **Try-Catch:** `RegisterTryCatchHandler` and `UnregisterTryCatchHandler` are related to JavaScript's exception handling mechanism.

5. **Consider conditional compilation:** The `#ifdef` directives (e.g., `V8_USE_PERFETTO`, `V8_ENABLE_WEBASSEMBLY`) highlight optional features and platform-specific code.

6. **Infer functionality based on the above observations:** Combine the information from the includes, namespaces, key structures, and functions to deduce the main responsibilities of `isolate.cc`.

7. **Address specific instructions from the prompt:**
    * **.tq extension:** The code snippet is `.cc`, not `.tq`, so it's a standard C++ source file.
    * **JavaScript relationship:**  The numerous includes related to JavaScript concepts (objects, functions, builtins, AST, etc.) clearly show a strong relationship. The example with `TryCatch` directly demonstrates how this C++ code implements a fundamental JavaScript feature.
    * **Code logic inference:**  The embedded blob management offers a good opportunity. The logic involves checking for sticky blobs and refcounting. Propose a scenario with setting and freeing the sticky blob.
    * **Common programming errors:**  Relate the `TryCatch` mechanism to a common JavaScript error – unhandled exceptions – and how `try...catch` solves it.

8. **Structure the summary:** Organize the findings into logical categories: core purpose, key responsibilities, relationship to JavaScript, and answers to the specific questions in the prompt.

9. **Refine and clarify:** Ensure the language is precise and easy to understand, avoiding jargon where possible, or explaining it when necessary. For example, explaining what an "isolate" is in the context of V8 is helpful. Also, check for consistency and completeness in the summary.
好的，让我们来分析一下 `v8/src/execution/isolate.cc` 这个文件的功能。

**核心功能归纳**

`v8/src/execution/isolate.cc` 文件是 V8 JavaScript 引擎中 **Isolate** 类的实现文件。Isolate 是 V8 中一个核心概念，它代表了一个 **独立的 JavaScript 虚拟机实例**。可以将其理解为一个独立的沙箱环境，拥有自己的堆、全局对象、内置函数等。  一个进程中可以存在多个 Isolate，它们之间相互隔离，互不影响。

**主要功能点**

基于代码中的引用和实现，我们可以列举出 `v8/src/execution/isolate.cc` 的主要功能：

1. **Isolate 的创建和初始化:**  负责 Isolate 实例的创建、内存分配以及各种子系统的初始化，例如堆管理器 (`Heap`)、内置函数 (`Builtins`)、快照机制 (`Snapshot`) 等。
2. **管理独立的执行环境:**  为 JavaScript 代码的执行提供一个隔离的环境，包括独立的内存空间、全局状态和执行上下文。
3. **线程管理:**  管理与 Isolate 关联的线程，包括为每个线程分配和管理线程本地数据 (`PerIsolateThreadData`)。
4. **内置功能和根对象的访问:**  提供访问内置函数、全局对象以及其他核心 V8 根对象的入口。
5. **异常处理:**  支持 JavaScript 的 `try...catch` 异常处理机制，维护当前线程的异常状态。
6. **栈追踪:**  提供生成和打印 JavaScript 栈追踪信息的功能，用于错误调试和分析。
7. **快照支持:**  处理 V8 的快照机制，包括嵌入式快照的加载和管理，用于加速启动。
8. **内置 Blob 管理:**  负责管理嵌入式 Blob（包含预编译代码和数据），用于快速启动和执行内置功能。
9. **垃圾回收支持:**  与垃圾回收器协同工作，提供遍历 Isolate 中所有根对象的能力，以确保垃圾回收的正确性。
10. **调试支持:**  提供与调试器交互的接口，例如栈帧迭代、断点管理等。
11. **WebAssembly 支持:**  集成 WebAssembly 的相关功能，包括管理 WebAssembly 模块和实例。
12. **性能分析和监控:**  集成性能分析和监控相关的工具，例如计数器、日志记录等。
13. **TLS (Thread Local Storage) 管理:**  管理线程本地存储，例如当前 Isolate 的指针。

**关于文件扩展名和 Torque**

你提到如果 `v8/src/execution/isolate.cc` 以 `.tq` 结尾，那它就是一个 V8 Torque 源代码。这是正确的。Torque 是 V8 用于生成高效内置函数的领域特定语言。由于 `isolate.cc` 是 `.cc` 结尾，它是一个标准的 C++ 源文件。这意味着 `Isolate` 类的核心逻辑是用 C++ 实现的。

**与 JavaScript 功能的关系及示例**

`v8/src/execution/isolate.cc` 与 JavaScript 的功能有着根本的联系。它实现了 JavaScript 运行的基础设施。 让我们用 JavaScript 的 `try...catch` 来说明：

```javascript
try {
  // 可能会抛出错误的代码
  throw new Error("Something went wrong!");
} catch (error) {
  // 捕获并处理错误
  console.error("Caught an error:", error.message);
}
```

在这个 JavaScript 代码中，`try...catch` 结构允许我们捕获和处理运行时错误。  `v8/src/execution/isolate.cc` 中的相关代码（例如 `RegisterTryCatchHandler`，`UnregisterTryCatchHandler`，以及 `ThreadLocalTop` 中的 `try_catch_handler_` 成员）就负责在 V8 引擎内部管理这些 `try...catch` 块的信息，当 JavaScript 代码抛出错误时，V8 能够找到最近的 `catch` 块并执行相应的处理逻辑。

**代码逻辑推理及假设输入输出**

让我们以嵌入式 Blob 的管理为例进行代码逻辑推理。

**假设输入:**

1. 在 Isolate 初始化时，没有设置粘性嵌入式 Blob (`sticky_embedded_blob_code_` 为 `nullptr`)。
2. Isolate 使用默认的嵌入式 Blob (`DefaultEmbeddedBlobCode` 和 `DefaultEmbeddedBlobData`).

**代码逻辑 (简化):**

当需要获取当前使用的嵌入式 Blob 代码时，`Isolate::CurrentEmbeddedBlobCode()` 会执行以下逻辑（简化）：

1. 检查是否有粘性嵌入式 Blob (`StickyEmbeddedBlobCode()`).
2. 如果存在粘性 Blob，则返回粘性 Blob 的代码。
3. 如果不存在粘性 Blob，则返回默认的嵌入式 Blob 代码 (`DefaultEmbeddedBlobCode()`).

**预期输出:**

在这种假设的输入下，`Isolate::CurrentEmbeddedBlobCode()` 将返回 `DefaultEmbeddedBlobCode()` 的值，因为没有设置粘性嵌入式 Blob。

**用户常见的编程错误**

虽然 `isolate.cc` 是 V8 内部实现，普通 JavaScript 开发者不会直接操作它，但理解其背后的原理有助于理解 V8 的行为，从而避免一些潜在的错误。

一个相关的概念是 **Isolate 的隔离性**。 用户可能会错误地认为在不同的 Isolate 之间可以共享 JavaScript 对象或状态。

**例如，以下是一个常见的误解:**

假设你在 Node.js 环境中创建了两个 Isolate：

```javascript
const v8 = require('v8');

const isolate1 = new v8.Isolate();
const isolate2 = new v8.Isolate();

isolate1.runInContext(() => {
  global.myVar = 10;
});

isolate2.runInContext(() => {
  console.log(global.myVar); // 可能会期望输出 10，但实际上会出错或输出 undefined
});
```

这个例子试图在一个 Isolate 中设置全局变量，然后在另一个 Isolate 中访问它。由于 Isolate 之间的隔离性，`isolate2` 无法直接访问 `isolate1` 的全局变量。这是因为每个 Isolate 都有自己独立的全局对象。

**归纳一下它的功能 (针对第 1 部分)**

提供的代码片段主要负责以下与 Isolate 初始化和管理相关的功能：

*   **嵌入式 Blob 的加载和管理:**  定义了用于获取默认、粘性以及当前使用的嵌入式 Blob 的函数，并处理其生命周期。
*   **当前嵌入式 Blob 的访问器:**  提供了静态方法来访问当前 Isolate 使用的嵌入式 Blob 的代码和数据。
*   **短内置调用区域的计算:**  定义了 `GetShortBuiltinsCallRegion` 函数，用于计算一个地址范围，以便在其中进行高效的短距离调用。
*   **为嵌入式 Blob 计算哈希值:**  定义了 `HashIsolateForEmbeddedBlob` 函数，用于计算 Isolate 状态的哈希值，这对于确保嵌入式 Blob 的一致性非常重要。
*   **线程本地数据的管理:**  定义了用于查找、分配和丢弃线程本地数据的方法。
*   **设置和获取当前 Isolate:**  提供了全局变量和函数来跟踪和访问当前正在执行的 Isolate。

总的来说，代码片段是 `v8/src/execution/isolate.cc` 的一部分，专注于 Isolate 的启动、核心资源的初始化（特别是嵌入式 Blob），以及与线程管理相关的基础功能。

Prompt: 
```
这是目录为v8/src/execution/isolate.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/isolate.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共9部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/isolate.h"

#include <stdlib.h>

#include <atomic>
#include <cstdint>
#include <fstream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>

#include "include/v8-template.h"
#include "src/api/api-arguments-inl.h"
#include "src/api/api-inl.h"
#include "src/ast/ast-value-factory.h"
#include "src/ast/scopes.h"
#include "src/base/hashmap.h"
#include "src/base/logging.h"
#include "src/base/platform/mutex.h"
#include "src/base/platform/platform.h"
#include "src/base/platform/wrappers.h"
#include "src/base/sys-info.h"
#include "src/base/utils/random-number-generator.h"
#include "src/baseline/baseline-batch-compiler.h"
#include "src/bigint/bigint.h"
#include "src/builtins/builtins-promise.h"
#include "src/builtins/builtins.h"
#include "src/builtins/constants-table-builder.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/compilation-cache.h"
#include "src/codegen/flush-instruction-cache.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/common/ptr-compr-inl.h"
#include "src/common/thread-local-storage.h"
#include "src/compiler-dispatcher/lazy-compile-dispatcher.h"
#include "src/compiler-dispatcher/optimizing-compile-dispatcher.h"
#include "src/date/date.h"
#include "src/debug/debug-frames.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/deoptimizer/materialized-object-store.h"
#include "src/diagnostics/basic-block-profiler.h"
#include "src/diagnostics/compilation-statistics.h"
#include "src/execution/frames-inl.h"
#include "src/execution/frames.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/local-isolate.h"
#include "src/execution/messages.h"
#include "src/execution/microtask-queue.h"
#include "src/execution/protectors-inl.h"
#include "src/execution/simulator.h"
#include "src/execution/tiering-manager.h"
#include "src/execution/v8threads.h"
#include "src/execution/vm-state-inl.h"
#include "src/flags/flags.h"
#include "src/handles/global-handles-inl.h"
#include "src/handles/persistent-handles.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-verifier.h"
#include "src/heap/local-heap-inl.h"
#include "src/heap/parked-scope.h"
#include "src/heap/read-only-heap.h"
#include "src/heap/safepoint.h"
#include "src/ic/stub-cache.h"
#include "src/init/bootstrapper.h"
#include "src/init/setup-isolate.h"
#include "src/init/v8.h"
#include "src/interpreter/bytecode-array-iterator.h"
#include "src/interpreter/bytecodes.h"
#include "src/interpreter/interpreter.h"
#include "src/libsampler/sampler.h"
#include "src/logging/counters.h"
#include "src/logging/log.h"
#include "src/logging/metrics.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/numbers/hash-seed-inl.h"
#include "src/objects/backing-store.h"
#include "src/objects/call-site-info-inl.h"
#include "src/objects/elements.h"
#include "src/objects/feedback-vector.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/instance-type-inl.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-atomics-synchronization-inl.h"
#include "src/objects/js-function.h"
#include "src/objects/js-generator-inl.h"
#include "src/objects/js-struct-inl.h"
#include "src/objects/js-weak-refs-inl.h"
#include "src/objects/managed-inl.h"
#include "src/objects/module-inl.h"
#include "src/objects/promise-inl.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/prototype.h"
#include "src/objects/slots.h"
#include "src/objects/smi.h"
#include "src/objects/source-text-module-inl.h"
#include "src/objects/string-set-inl.h"
#include "src/objects/visitors.h"
#include "src/objects/waiter-queue-node.h"
#include "src/profiler/heap-profiler.h"
#include "src/profiler/tracing-cpu-profiler.h"
#include "src/regexp/regexp-stack.h"
#include "src/roots/roots.h"
#include "src/roots/static-roots.h"
#include "src/sandbox/js-dispatch-table-inl.h"
#include "src/snapshot/embedded/embedded-data-inl.h"
#include "src/snapshot/embedded/embedded-file-writer-interface.h"
#include "src/snapshot/read-only-deserializer.h"
#include "src/snapshot/shared-heap-deserializer.h"
#include "src/snapshot/snapshot.h"
#include "src/snapshot/startup-deserializer.h"
#include "src/strings/string-builder-inl.h"
#include "src/strings/string-stream.h"
#include "src/tasks/cancelable-task.h"

#if defined(V8_USE_PERFETTO)
#include "src/tracing/perfetto-logger.h"
#endif  // defined(V8_USE_PERFETTO)

#include "src/tracing/tracing-category-observer.h"
#include "src/utils/address-map.h"
#include "src/utils/ostreams.h"
#include "src/utils/version.h"
#include "src/zone/accounting-allocator.h"
#include "src/zone/type-stats.h"
#ifdef V8_INTL_SUPPORT
#include "src/objects/intl-objects.h"
#include "unicode/locid.h"
#include "unicode/uobject.h"
#endif  // V8_INTL_SUPPORT

#if V8_ENABLE_MAGLEV
#include "src/maglev/maglev-concurrent-dispatcher.h"
#endif  // V8_ENABLE_MAGLEV

#if V8_ENABLE_WEBASSEMBLY
#include "src/builtins/builtins-inl.h"
#include "src/debug/debug-wasm-objects.h"
#include "src/trap-handler/trap-handler.h"
#include "src/wasm/stacks.h"
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-code-pointer-table-inl.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects.h"

#if V8_ENABLE_DRUMBRAKE
#include "src/wasm/interpreter/wasm-interpreter.h"
#endif  // V8_ENABLE_DRUMBRAKE
#endif  // V8_ENABLE_WEBASSEMBLY

#if defined(V8_OS_WIN) && defined(V8_ENABLE_ETW_STACK_WALKING)
#include "src/diagnostics/etw-jit-win.h"
#endif

#if defined(V8_OS_WIN64)
#include "src/diagnostics/unwinding-info-win64.h"
#endif  // V8_OS_WIN64

#if USE_SIMULATOR
#include "src/execution/simulator-base.h"
#endif

extern "C" const uint8_t v8_Default_embedded_blob_code_[];
extern "C" uint32_t v8_Default_embedded_blob_code_size_;
extern "C" const uint8_t v8_Default_embedded_blob_data_[];
extern "C" uint32_t v8_Default_embedded_blob_data_size_;

namespace v8 {
namespace internal {

#ifdef DEBUG
#define TRACE_ISOLATE(tag)                                                  \
  do {                                                                      \
    if (v8_flags.trace_isolates) {                                          \
      PrintF("Isolate %p (id %d)" #tag "\n", reinterpret_cast<void*>(this), \
             id());                                                         \
    }                                                                       \
  } while (false)
#else
#define TRACE_ISOLATE(tag)
#endif

const uint8_t* DefaultEmbeddedBlobCode() {
  return v8_Default_embedded_blob_code_;
}
uint32_t DefaultEmbeddedBlobCodeSize() {
  return v8_Default_embedded_blob_code_size_;
}
const uint8_t* DefaultEmbeddedBlobData() {
  return v8_Default_embedded_blob_data_;
}
uint32_t DefaultEmbeddedBlobDataSize() {
  return v8_Default_embedded_blob_data_size_;
}

namespace {
// These variables provide access to the current embedded blob without requiring
// an isolate instance. This is needed e.g. by
// InstructionStream::InstructionStart, which may not have access to an isolate
// but still needs to access the embedded blob. The variables are initialized by
// each isolate in Init(). Writes and reads are relaxed since we can guarantee
// that the current thread has initialized these variables before accessing
// them. Different threads may race, but this is fine since they all attempt to
// set the same values of the blob pointer and size.

std::atomic<const uint8_t*> current_embedded_blob_code_(nullptr);
std::atomic<uint32_t> current_embedded_blob_code_size_(0);
std::atomic<const uint8_t*> current_embedded_blob_data_(nullptr);
std::atomic<uint32_t> current_embedded_blob_data_size_(0);

// The various workflows around embedded snapshots are fairly complex. We need
// to support plain old snapshot builds, nosnap builds, and the requirements of
// subtly different serialization tests. There's two related knobs to twiddle:
//
// - The default embedded blob may be overridden by setting the sticky embedded
// blob. This is set automatically whenever we create a new embedded blob.
//
// - Lifecycle management can be either manual or set to refcounting.
//
// A few situations to demonstrate their use:
//
// - A plain old snapshot build neither overrides the default blob nor
// refcounts.
//
// - mksnapshot sets the sticky blob and manually frees the embedded
// blob once done.
//
// - Most serializer tests do the same.
//
// - Nosnapshot builds set the sticky blob and enable refcounting.

// This mutex protects access to the following variables:
// - sticky_embedded_blob_code_
// - sticky_embedded_blob_code_size_
// - sticky_embedded_blob_data_
// - sticky_embedded_blob_data_size_
// - enable_embedded_blob_refcounting_
// - current_embedded_blob_refs_
base::LazyMutex current_embedded_blob_refcount_mutex_ = LAZY_MUTEX_INITIALIZER;

const uint8_t* sticky_embedded_blob_code_ = nullptr;
uint32_t sticky_embedded_blob_code_size_ = 0;
const uint8_t* sticky_embedded_blob_data_ = nullptr;
uint32_t sticky_embedded_blob_data_size_ = 0;

bool enable_embedded_blob_refcounting_ = true;
int current_embedded_blob_refs_ = 0;

const uint8_t* StickyEmbeddedBlobCode() { return sticky_embedded_blob_code_; }
uint32_t StickyEmbeddedBlobCodeSize() {
  return sticky_embedded_blob_code_size_;
}
const uint8_t* StickyEmbeddedBlobData() { return sticky_embedded_blob_data_; }
uint32_t StickyEmbeddedBlobDataSize() {
  return sticky_embedded_blob_data_size_;
}

void SetStickyEmbeddedBlob(const uint8_t* code, uint32_t code_size,
                           const uint8_t* data, uint32_t data_size) {
  sticky_embedded_blob_code_ = code;
  sticky_embedded_blob_code_size_ = code_size;
  sticky_embedded_blob_data_ = data;
  sticky_embedded_blob_data_size_ = data_size;
}

}  // namespace

void DisableEmbeddedBlobRefcounting() {
  base::MutexGuard guard(current_embedded_blob_refcount_mutex_.Pointer());
  enable_embedded_blob_refcounting_ = false;
}

void FreeCurrentEmbeddedBlob() {
  CHECK(!enable_embedded_blob_refcounting_);
  base::MutexGuard guard(current_embedded_blob_refcount_mutex_.Pointer());

  if (StickyEmbeddedBlobCode() == nullptr) return;

  CHECK_EQ(StickyEmbeddedBlobCode(), Isolate::CurrentEmbeddedBlobCode());
  CHECK_EQ(StickyEmbeddedBlobData(), Isolate::CurrentEmbeddedBlobData());

  OffHeapInstructionStream::FreeOffHeapOffHeapInstructionStream(
      const_cast<uint8_t*>(Isolate::CurrentEmbeddedBlobCode()),
      Isolate::CurrentEmbeddedBlobCodeSize(),
      const_cast<uint8_t*>(Isolate::CurrentEmbeddedBlobData()),
      Isolate::CurrentEmbeddedBlobDataSize());

  current_embedded_blob_code_.store(nullptr, std::memory_order_relaxed);
  current_embedded_blob_code_size_.store(0, std::memory_order_relaxed);
  current_embedded_blob_data_.store(nullptr, std::memory_order_relaxed);
  current_embedded_blob_data_size_.store(0, std::memory_order_relaxed);
  sticky_embedded_blob_code_ = nullptr;
  sticky_embedded_blob_code_size_ = 0;
  sticky_embedded_blob_data_ = nullptr;
  sticky_embedded_blob_data_size_ = 0;
}

// static
bool Isolate::CurrentEmbeddedBlobIsBinaryEmbedded() {
  // In some situations, we must be able to rely on the embedded blob being
  // immortal immovable. This is the case if the blob is binary-embedded.
  // See blob lifecycle controls above for descriptions of when the current
  // embedded blob may change (e.g. in tests or mksnapshot). If the blob is
  // binary-embedded, it is immortal immovable.
  const uint8_t* code =
      current_embedded_blob_code_.load(std::memory_order_relaxed);
  if (code == nullptr) return false;
  return code == DefaultEmbeddedBlobCode();
}

void Isolate::SetEmbeddedBlob(const uint8_t* code, uint32_t code_size,
                              const uint8_t* data, uint32_t data_size) {
  CHECK_NOT_NULL(code);
  CHECK_NOT_NULL(data);

  embedded_blob_code_ = code;
  embedded_blob_code_size_ = code_size;
  embedded_blob_data_ = data;
  embedded_blob_data_size_ = data_size;
  current_embedded_blob_code_.store(code, std::memory_order_relaxed);
  current_embedded_blob_code_size_.store(code_size, std::memory_order_relaxed);
  current_embedded_blob_data_.store(data, std::memory_order_relaxed);
  current_embedded_blob_data_size_.store(data_size, std::memory_order_relaxed);

#ifdef DEBUG
  // Verify that the contents of the embedded blob are unchanged from
  // serialization-time, just to ensure the compiler isn't messing with us.
  EmbeddedData d = EmbeddedData::FromBlob();
  if (d.EmbeddedBlobDataHash() != d.CreateEmbeddedBlobDataHash()) {
    FATAL(
        "Embedded blob data section checksum verification failed. This "
        "indicates that the embedded blob has been modified since compilation "
        "time.");
  }
  if (v8_flags.text_is_readable) {
    if (d.EmbeddedBlobCodeHash() != d.CreateEmbeddedBlobCodeHash()) {
      FATAL(
          "Embedded blob code section checksum verification failed. This "
          "indicates that the embedded blob has been modified since "
          "compilation time. A common cause is a debugging breakpoint set "
          "within builtin code.");
    }
  }
#endif  // DEBUG
}

void Isolate::ClearEmbeddedBlob() {
  CHECK(enable_embedded_blob_refcounting_);
  CHECK_EQ(embedded_blob_code_, CurrentEmbeddedBlobCode());
  CHECK_EQ(embedded_blob_code_, StickyEmbeddedBlobCode());
  CHECK_EQ(embedded_blob_data_, CurrentEmbeddedBlobData());
  CHECK_EQ(embedded_blob_data_, StickyEmbeddedBlobData());

  embedded_blob_code_ = nullptr;
  embedded_blob_code_size_ = 0;
  embedded_blob_data_ = nullptr;
  embedded_blob_data_size_ = 0;
  current_embedded_blob_code_.store(nullptr, std::memory_order_relaxed);
  current_embedded_blob_code_size_.store(0, std::memory_order_relaxed);
  current_embedded_blob_data_.store(nullptr, std::memory_order_relaxed);
  current_embedded_blob_data_size_.store(0, std::memory_order_relaxed);
  sticky_embedded_blob_code_ = nullptr;
  sticky_embedded_blob_code_size_ = 0;
  sticky_embedded_blob_data_ = nullptr;
  sticky_embedded_blob_data_size_ = 0;
}

const uint8_t* Isolate::embedded_blob_code() const {
  return embedded_blob_code_;
}
uint32_t Isolate::embedded_blob_code_size() const {
  return embedded_blob_code_size_;
}
const uint8_t* Isolate::embedded_blob_data() const {
  return embedded_blob_data_;
}
uint32_t Isolate::embedded_blob_data_size() const {
  return embedded_blob_data_size_;
}

// static
const uint8_t* Isolate::CurrentEmbeddedBlobCode() {
  return current_embedded_blob_code_.load(std::memory_order_relaxed);
}

// static
uint32_t Isolate::CurrentEmbeddedBlobCodeSize() {
  return current_embedded_blob_code_size_.load(std::memory_order_relaxed);
}

// static
const uint8_t* Isolate::CurrentEmbeddedBlobData() {
  return current_embedded_blob_data_.load(std::memory_order_relaxed);
}

// static
uint32_t Isolate::CurrentEmbeddedBlobDataSize() {
  return current_embedded_blob_data_size_.load(std::memory_order_relaxed);
}

// static
base::AddressRegion Isolate::GetShortBuiltinsCallRegion() {
  // Update calculations below if the assert fails.
  static_assert(kMaxPCRelativeCodeRangeInMB <= 4096);
  if (kMaxPCRelativeCodeRangeInMB == 0) {
    // Return empty region if pc-relative calls/jumps are not supported.
    return base::AddressRegion(kNullAddress, 0);
  }
  constexpr size_t max_size = std::numeric_limits<size_t>::max();
  if (uint64_t{kMaxPCRelativeCodeRangeInMB} * MB > max_size) {
    // The whole addressable space is reachable with pc-relative calls/jumps.
    return base::AddressRegion(kNullAddress, max_size);
  }
  constexpr size_t radius = kMaxPCRelativeCodeRangeInMB * MB;

  DCHECK_LT(CurrentEmbeddedBlobCodeSize(), radius);
  Address embedded_blob_code_start =
      reinterpret_cast<Address>(CurrentEmbeddedBlobCode());
  if (embedded_blob_code_start == kNullAddress) {
    // Return empty region if there's no embedded blob.
    return base::AddressRegion(kNullAddress, 0);
  }
  Address embedded_blob_code_end =
      embedded_blob_code_start + CurrentEmbeddedBlobCodeSize();
  Address region_start =
      (embedded_blob_code_end > radius) ? (embedded_blob_code_end - radius) : 0;
  Address region_end = embedded_blob_code_start + radius;
  if (region_end < embedded_blob_code_start) {
    region_end = static_cast<Address>(-1);
  }
  return base::AddressRegion(region_start, region_end - region_start);
}

size_t Isolate::HashIsolateForEmbeddedBlob() {
  DCHECK(builtins_.is_initialized());
  DCHECK(Builtins::AllBuiltinsAreIsolateIndependent());

  DisallowGarbageCollection no_gc;

  static constexpr size_t kSeed = 0;
  size_t hash = kSeed;

  // Hash static entries of the roots table.
  hash = base::hash_combine(hash, V8_STATIC_ROOTS_BOOL);
#if V8_STATIC_ROOTS_BOOL
  hash = base::hash_combine(hash,
                            static_cast<int>(RootIndex::kReadOnlyRootsCount));
  RootIndex i = RootIndex::kFirstReadOnlyRoot;
  for (auto ptr : StaticReadOnlyRootsPointerTable) {
    hash = base::hash_combine(ptr, hash);
    ++i;
  }
#endif  // V8_STATIC_ROOTS_BOOL

  // Hash data sections of builtin code objects.
  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
       ++builtin) {
    Tagged<Code> code = builtins()->code(builtin);

    DCHECK(Internals::HasHeapObjectTag(code.ptr()));
    uint8_t* const code_ptr = reinterpret_cast<uint8_t*>(code.address());

    // These static asserts ensure we don't miss relevant fields. We don't hash
    // instruction_start, but other data fields must remain the same.
    static_assert(Code::kEndOfStrongFieldsOffset ==
                  Code::kInstructionStartOffset);
#ifndef V8_ENABLE_SANDBOX
    static_assert(Code::kInstructionStartOffsetEnd + 1 == Code::kFlagsOffset);
#endif
    static_assert(Code::kFlagsOffsetEnd + 1 == Code::kInstructionSizeOffset);
    static_assert(Code::kInstructionSizeOffsetEnd + 1 ==
                  Code::kMetadataSizeOffset);
    static_assert(Code::kMetadataSizeOffsetEnd + 1 ==
                  Code::kInlinedBytecodeSizeOffset);
    static_assert(Code::kInlinedBytecodeSizeOffsetEnd + 1 ==
                  Code::kOsrOffsetOffset);
    static_assert(Code::kOsrOffsetOffsetEnd + 1 ==
                  Code::kHandlerTableOffsetOffset);
    static_assert(Code::kHandlerTableOffsetOffsetEnd + 1 ==
                  Code::kUnwindingInfoOffsetOffset);
    static_assert(Code::kUnwindingInfoOffsetOffsetEnd + 1 ==
                  Code::kConstantPoolOffsetOffset);
    static_assert(Code::kConstantPoolOffsetOffsetEnd + 1 ==
                  Code::kCodeCommentsOffsetOffset);
    static_assert(Code::kCodeCommentsOffsetOffsetEnd + 1 ==
                  Code::kBuiltinJumpTableInfoOffsetOffset);
    static_assert(Code::kBuiltinJumpTableInfoOffsetOffsetEnd + 1 ==
                  Code::kParameterCountOffset);
    static_assert(Code::kParameterCountOffsetEnd + 1 == Code::kBuiltinIdOffset);
    static_assert(Code::kBuiltinIdOffsetEnd + 1 == Code::kUnalignedSize);
    static constexpr int kStartOffset = Code::kFlagsOffset;

    for (int j = kStartOffset; j < Code::kUnalignedSize; j++) {
      hash = base::hash_combine(hash, size_t{code_ptr[j]});
    }
  }

  // The builtins constants table is also tightly tied to embedded builtins.
  hash = base::hash_combine(
      hash, static_cast<size_t>(heap_.builtins_constants_table()->length()));

  return hash;
}

thread_local Isolate::PerIsolateThreadData* g_current_per_isolate_thread_data_
    V8_CONSTINIT = nullptr;
thread_local Isolate* g_current_isolate_ V8_CONSTINIT = nullptr;

V8_TLS_DEFINE_GETTER(Isolate::TryGetCurrent, Isolate*, g_current_isolate_)

// static
void Isolate::SetCurrent(Isolate* isolate) { g_current_isolate_ = isolate; }

namespace {
// A global counter for all generated Isolates, might overflow.
std::atomic<int> isolate_counter{0};
}  // namespace

Isolate::PerIsolateThreadData*
Isolate::FindOrAllocatePerThreadDataForThisThread() {
  ThreadId thread_id = ThreadId::Current();
  PerIsolateThreadData* per_thread = nullptr;
  {
    base::MutexGuard lock_guard(&thread_data_table_mutex_);
    per_thread = thread_data_table_.Lookup(thread_id);
    if (per_thread == nullptr) {
      if (v8_flags.adjust_os_scheduling_parameters) {
        base::OS::AdjustSchedulingParams();
      }
      per_thread = new PerIsolateThreadData(this, thread_id);
      thread_data_table_.Insert(per_thread);
    }
    DCHECK(thread_data_table_.Lookup(thread_id) == per_thread);
  }
  return per_thread;
}

void Isolate::DiscardPerThreadDataForThisThread() {
  ThreadId thread_id = ThreadId::TryGetCurrent();
  if (thread_id.IsValid()) {
    DCHECK_NE(thread_manager_->mutex_owner_.load(std::memory_order_relaxed),
              thread_id);
    base::MutexGuard lock_guard(&thread_data_table_mutex_);
    PerIsolateThreadData* per_thread = thread_data_table_.Lookup(thread_id);
    if (per_thread) {
      DCHECK(!per_thread->thread_state_);
      thread_data_table_.Remove(per_thread);
    }
  }
}

Isolate::PerIsolateThreadData* Isolate::FindPerThreadDataForThisThread() {
  ThreadId thread_id = ThreadId::Current();
  return FindPerThreadDataForThread(thread_id);
}

Isolate::PerIsolateThreadData* Isolate::FindPerThreadDataForThread(
    ThreadId thread_id) {
  PerIsolateThreadData* per_thread = nullptr;
  {
    base::MutexGuard lock_guard(&thread_data_table_mutex_);
    per_thread = thread_data_table_.Lookup(thread_id);
  }
  return per_thread;
}

void Isolate::InitializeOncePerProcess() { Heap::InitializeOncePerProcess(); }

Address Isolate::get_address_from_id(IsolateAddressId id) {
  return isolate_addresses_[id];
}

char* Isolate::Iterate(RootVisitor* v, char* thread_storage) {
  ThreadLocalTop* thread = reinterpret_cast<ThreadLocalTop*>(thread_storage);
  Iterate(v, thread);
  // Normally, ThreadLocalTop::topmost_script_having_context_ is visited weakly
  // but in order to simplify handling of frozen threads we just clear it.
  // Otherwise, we'd need to traverse the thread_storage again just to find this
  // one field.
  thread->topmost_script_having_context_ = Context();
  return thread_storage + sizeof(ThreadLocalTop);
}

void Isolate::IterateThread(ThreadVisitor* v, char* t) {
  ThreadLocalTop* thread = reinterpret_cast<ThreadLocalTop*>(t);
  v->VisitThread(this, thread);
}

void Isolate::Iterate(RootVisitor* v, ThreadLocalTop* thread) {
  // Visit the roots from the top for a given thread.
  v->VisitRootPointer(Root::kStackRoots, nullptr,
                      FullObjectSlot(&thread->exception_));
  v->VisitRootPointer(Root::kStackRoots, nullptr,
                      FullObjectSlot(&thread->pending_message_));
  v->VisitRootPointer(Root::kStackRoots, nullptr,
                      FullObjectSlot(&thread->context_));

  for (v8::TryCatch* block = thread->try_catch_handler_; block != nullptr;
       block = block->next_) {
    // TODO(3770): Make TryCatch::exception_ an Address (and message_obj_ too).
    v->VisitRootPointer(
        Root::kStackRoots, nullptr,
        FullObjectSlot(reinterpret_cast<Address>(&(block->exception_))));
    v->VisitRootPointer(
        Root::kStackRoots, nullptr,
        FullObjectSlot(reinterpret_cast<Address>(&(block->message_obj_))));
  }

  v->VisitRootPointer(
      Root::kStackRoots, nullptr,
      FullObjectSlot(continuation_preserved_embedder_data_address()));

  // Iterate over pointers on native execution stack.
#if V8_ENABLE_WEBASSEMBLY
  wasm::WasmCodeRefScope wasm_code_ref_scope;

  for (const std::unique_ptr<wasm::StackMemory>& stack : wasm_stacks_) {
    if (stack->IsActive()) {
      continue;
    }
    for (StackFrameIterator it(this, stack.get()); !it.done(); it.Advance()) {
      it.frame()->Iterate(v);
    }
  }
  StackFrameIterator it(this, thread, StackFrameIterator::FirstStackOnly{});
#else
  StackFrameIterator it(this, thread);
#endif
  for (; !it.done(); it.Advance()) {
    it.frame()->Iterate(v);
  }
}

void Isolate::Iterate(RootVisitor* v) {
  ThreadLocalTop* current_t = thread_local_top();
  Iterate(v, current_t);
}

void Isolate::RegisterTryCatchHandler(v8::TryCatch* that) {
  thread_local_top()->try_catch_handler_ = that;
}

void Isolate::UnregisterTryCatchHandler(v8::TryCatch* that) {
  DCHECK_EQ(thread_local_top()->try_catch_handler_, that);
  thread_local_top()->try_catch_handler_ = that->next_;
  SimulatorStack::UnregisterJSStackComparableAddress(this);
}

Handle<String> Isolate::StackTraceString() {
  if (stack_trace_nesting_level_ == 0) {
    stack_trace_nesting_level_++;
    HeapStringAllocator allocator;
    StringStream::ClearMentionedObjectCache(this);
    StringStream accumulator(&allocator);
    incomplete_message_ = &accumulator;
    PrintStack(&accumulator);
    Handle<String> stack_trace = accumulator.ToString(this);
    incomplete_message_ = nullptr;
    stack_trace_nesting_level_ = 0;
    return stack_trace;
  } else if (stack_trace_nesting_level_ == 1) {
    stack_trace_nesting_level_++;
    base::OS::PrintError(
        "\n\nAttempt to print stack while printing stack (double fault)\n");
    base::OS::PrintError(
        "If you are lucky you may find a partial stack dump on stdout.\n\n");
    incomplete_message_->OutputToStdOut();
    return factory()->empty_string();
  } else {
    base::OS::Abort();
  }
}

void Isolate::PushStackTraceAndDie(void* ptr1, void* ptr2, void* ptr3,
                                   void* ptr4, void* ptr5, void* ptr6) {
  StackTraceFailureMessage message(this,
                                   StackTraceFailureMessage::kIncludeStackTrace,
                                   ptr1, ptr2, ptr3, ptr4, ptr5, ptr6);
  message.Print();
  base::OS::Abort();
}

void Isolate::PushParamsAndDie(void* ptr1, void* ptr2, void* ptr3, void* ptr4,
                               void* ptr5, void* ptr6) {
  StackTraceFailureMessage message(
      this, StackTraceFailureMessage::kDontIncludeStackTrace, ptr1, ptr2, ptr3,
      ptr4, ptr5, ptr6);
  message.Print();
  base::OS::Abort();
}

void Isolate::PushStackTraceAndContinue(void* ptr1, void* ptr2, void* ptr3,
                                        void* ptr4, void* ptr5, void* ptr6) {
  StackTraceFailureMessage message(this,
                                   StackTraceFailureMessage::kIncludeStackTrace,
                                   ptr1, ptr2, ptr3, ptr4, ptr5, ptr6);
  message.Print();
  V8::GetCurrentPlatform()->DumpWithoutCrashing();
}

void Isolate::PushParamsAndContinue(void* ptr1, void* ptr2, void* ptr3,
                                    void* ptr4, void* ptr5, void* ptr6) {
  StackTraceFailureMessage message(
      this, StackTraceFailureMessage::kDontIncludeStackTrace, ptr1, ptr2, ptr3,
      ptr4, ptr5, ptr6);
  message.Print();
  V8::GetCurrentPlatform()->DumpWithoutCrashing();
}

void StackTraceFailureMessage::Print() volatile {
  // Print the details of this failure message object, including its own address
  // to force stack allocation.
  base::OS::PrintError(
      "Stacktrace:\n    ptr1=%p\n    ptr2=%p\n    ptr3=%p\n    ptr4=%p\n    "
      "ptr5=%p\n    ptr6=%p\n    failure_message_object=%p\n%s",
      ptr1_, ptr2_, ptr3_, ptr4_, ptr5_, ptr6_, this, &js_stack_trace_[0]);
}

StackTraceFailureMessage::StackTraceFailureMessage(
    Isolate* isolate, StackTraceFailureMessage::StackTraceMode mode, void* ptr1,
    void* ptr2, void* ptr3, void* ptr4, void* ptr5, void* ptr6) {
  isolate_ = isolate;
  ptr1_ = ptr1;
  ptr2_ = ptr2;
  ptr3_ = ptr3;
  ptr4_ = ptr4;
  ptr5_ = ptr5;
  ptr6_ = ptr6;
  // Write a stracktrace into the {js_stack_trace_} buffer.
  const size_t buffer_length = arraysize(js_stack_trace_);
  memset(&js_stack_trace_, 0, buffer_length);
  memset(&code_objects_, 0, sizeof(code_objects_));
  if (mode == kIncludeStackTrace) {
    FixedStringAllocator fixed(&js_stack_trace_[0], buffer_length - 1);
    StringStream accumulator(&fixed, StringStream::kPrintObjectConcise);
    isolate->PrintStack(&accumulator, Isolate::kPrintStackVerbose);
    // Keeping a reference to the last code objects to increase likelihood that
    // they get included in the minidump.
    const size_t code_objects_length = arraysize(code_objects_);
    size_t i = 0;
    StackFrameIterator it(isolate);
    for (; !it.done() && i < code_objects_length; it.Advance()) {
      code_objects_[i++] =
          reinterpret_cast<void*>(it.frame()->unchecked_code().ptr());
    }
  }
}

bool NoExtension(const v8::FunctionCallbackInfo<v8::Value>&) { return false; }

namespace {

bool IsBuiltinFunction(Isolate* isolate, Tagged<HeapObject> object,
                       Builtin builtin) {
  if (!IsJSFunction(object)) return false;
  Tagged<JSFunction> const function = Cast<JSFunction>(object);
  // Currently we have to use full pointer comparison here as builtin Code
  // objects are still inside the sandbox while runtime-generated Code objects
  // are in trusted space.
  static_assert(!kAllCodeObjectsLiveInTrustedSpace);
  return function->code(isolate).SafeEquals(isolate->builtins()->code(builtin));
}

// Check if the function is one of the known async function or
// async generator fulfill handlers.
bool IsBuiltinAsyncFulfillHandler(Isolate* isolate, Tagged<HeapObject> object) {
  return IsBuiltinFunction(isolate, object,
                           Builtin::kAsyncFunctionAwaitResolveClosure) ||
         IsBuiltinFunction(isolate, object,
                           Builtin::kAsyncGeneratorAwaitResolveClosure) ||
         IsBuiltinFunction(
             isolate, object,
             Builtin::kAsyncGeneratorYieldWithAwaitResolveClosure);
}

// Check if the function is one of the known async function or
// async generator fulfill handlers.
bool IsBuiltinAsyncRejectHandler(Isolate* isolate, Tagged<HeapObject> object) {
  return IsBuiltinFunction(isolate, object,
                           Builtin::kAsyncFunctionAwaitRejectClosure) ||
         IsBuiltinFunction(isolate, object,
                           Builtin::kAsyncGeneratorAwaitRejectClosure);
}

// Check if the function is one of the known builtin rejection handlers that
// rethrows the exception instead of catching it.
bool IsBuiltinForwardingRejectHandler(Isolate* isolate,
                                      Tagged<HeapObject> object) {
  return IsBuiltinFunction(isolate, object, Builtin::kPromiseCatchFinally) ||
         IsBuiltinFunction(isolate, object,
                           Builtin::kAsyncFromSyncIteratorCloseSyncAndRethrow);
}

MaybeHandle<JSGeneratorObject> TryGetAsyncGenerator(
    Isolate* isolate, DirectHandle<PromiseReaction> reaction) {
  // Check if the {reaction} has one of the known async function or
  // async generator continuations as its fulfill handler.
  if (IsBuiltinAsyncFulfillHandler(isolate, reaction->fulfill_handler())) {
    // Now peek into the handlers' AwaitContext to get to
    // the JSGeneratorObject for the async function.
    DirectHandle<Context> context(
        Cast<JSFunction>(reaction->fulfill_handler())->context(), isolate);
    Handle<JSGeneratorObject> generator_object(
        Cast<JSGeneratorObject>(context->extension()), isolate);
    return generator_object;
  }
  return MaybeHandle<JSGeneratorObject>();
}

#if V8_ENABLE_WEBASSEMBLY
MaybeHandle<WasmSuspenderObject> TryGetWasmSuspender(
    Isolate* isolate, Tagged<HeapObject> handler) {
  // Check if the {handler} is WasmResume.
  if (IsBuiltinFunction(isolate, handler, Builtin::kWasmResume)) {
    // Now peek into the handlers' AwaitContext to get to
    // the JSGeneratorObject for the async function.
    Tagged<SharedFunctionInfo> shared = Cast<JSFunction>(handler)->shared();
    if (shared->HasWasmResumeData()) {
      return handle(shared->wasm_resume_data()->suspender(), isolate);
    }
  }
  return MaybeHandle<WasmSuspenderObject>();
}
#endif  // V8_ENABLE_WEBASSEMBLY

int GetGeneratorBytecodeOffset(
    DirectHandle<JSGeneratorObject> generator_object) {
  // The stored bytecode offset is relative to a different base than what
  // is used in the source position table, hence the subtraction.
  return Smi::ToInt(generator_object->input_or_debug_pos()) -
         (BytecodeArray::kHeaderSize - kHeapObjectTag);
}

class CallSiteBuilder {
 public:
  CallSiteBuilder(Isolate* isolate, FrameSkipMode mode, int limit,
                  Handle<Object> caller)
      : isolate_(isolate),
        mode_(mode),
        limit_(limit),
        caller_(caller),
        skip_next_frame_(mode != SKIP_NONE) {
    DCHECK_IMPLIES(mode_ == SKIP_UNTIL_SEEN, IsJSFunction(*caller_));
    // Modern web applications are usually built with multiple layers of
    // framework and libr
"""


```