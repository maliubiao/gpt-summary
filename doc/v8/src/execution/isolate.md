Response: The user wants a summary of the C++ source code file `v8/src/execution/isolate.cc`. They also want to know how it relates to JavaScript and see a JavaScript example if applicable.

**Plan:**

1. **Identify the core concept:** The filename `isolate.cc` strongly suggests this file is about the `Isolate` class in V8.
2. **Infer the role of `Isolate`:** Based on general knowledge of JavaScript engines, `Isolate` likely represents an isolated execution environment for JavaScript code.
3. **Scan the included headers:** The headers provide clues about the functionalities within the file. Look for common themes. Many headers relate to memory management (`heap/*`), compilation (`codegen/*`, `compiler-dispatcher/*`), execution (`execution/*`), and core JavaScript concepts (`objects/*`, `builtins/*`).
4. **Examine key functions and data structures:**  Look for prominent functions (like constructors, initialization methods) and data members that reveal the responsibilities of the `Isolate`.
5. **Connect to JavaScript:** Consider how the features implemented in this C++ code are exposed or used when running JavaScript code. Think about things like creating execution environments, handling errors, managing memory, and optimizing code.
6. **Construct a summary:** Combine the observations into a concise description of the file's purpose.
7. **Provide a JavaScript example:** Illustrate the connection to JavaScript by showing how a concept related to the `Isolate` is used in JavaScript. Creating different V8 isolates should be a good example.
这个C++源代码文件 `v8/src/execution/isolate.cc` 的主要功能是**定义和实现了 V8 引擎的核心类 `Isolate`**。

`Isolate` 类在 V8 中代表了一个**独立的 JavaScript 执行环境**。 它可以被看作是一个独立的虚拟机实例，拥有自己的堆、内置对象、全局上下文等。这意味着在同一个进程中可以创建多个 `Isolate` 实例，它们之间互不干扰，拥有各自独立的资源和状态。

**以下是该文件的一些关键功能点：**

* **Isolate 的创建和初始化:**  代码负责 `Isolate` 对象的创建、分配必要的资源（如堆内存）、初始化内置对象和函数、设置默认的嵌入式 blob (包含预编译的代码)。
* **执行上下文管理:**  `Isolate` 维护着当前正在执行的 JavaScript 代码的上下文信息，包括全局对象、作用域链等。
* **内存管理 (Heap):**  `Isolate` 拥有自己的堆内存，负责 JavaScript 对象的分配和垃圾回收。
* **内置功能:**  `Isolate` 包含了对 JavaScript 内置对象和函数的引用。
* **错误处理和异常:**  `Isolate` 负责捕获和处理 JavaScript 运行时发生的错误和异常。
* **堆栈跟踪:**  该文件包含生成和管理 JavaScript 调用堆栈信息的功能。
* **异步操作:**  `Isolate` 管理异步操作，例如 Promises 和 async/await。
* **编译和优化:**  `Isolate` 与代码编译和优化模块交互，包括即时编译 (JIT) 和解释执行。
* **调试支持:**  `Isolate` 提供了用于调试 JavaScript 代码的功能。
* **与 V8 API 的交互:**  `Isolate` 是 V8 C++ API 的核心组成部分，用于与外部环境交互，例如创建执行上下文、执行 JavaScript 代码等。

**与 JavaScript 的功能关系及 JavaScript 示例:**

`Isolate` 类是 V8 引擎运行 JavaScript 代码的基础。 每当你运行一段 JavaScript 代码，它都运行在一个 `Isolate` 实例中。

**JavaScript 示例:**

虽然你不能直接在 JavaScript 中操作 `Isolate` 对象（因为它是 C++ 的概念），但是你可以观察到 `Isolate` 的隔离性带来的影响。

在 Node.js 环境中，你可以使用 `vm` 模块创建新的 JavaScript 上下文，这些上下文背后就对应着不同的 `Isolate` (或者共享的 `Isolate` 但具有不同的上下文):

```javascript
const vm = require('vm');

// 创建一个新的上下文（可能对应一个新的 Isolate 或者一个新的 Context 在同一 Isolate 中）
const context1 = vm.createContext({ value: 10 });
const context2 = vm.createContext({ value: 20 });

// 在不同的上下文中执行相同的代码
vm.runInContext('console.log(value);', context1); // 输出: 10
vm.runInContext('console.log(value);', context2); // 输出: 20

// 修改一个上下文中的变量不会影响另一个上下文
vm.runInContext('value = 100;', context1);
vm.runInContext('console.log(value);', context1); // 输出: 100
vm.runInContext('console.log(value);', context2); // 输出: 20
```

在这个例子中，`context1` 和 `context2` 可以被认为是运行在逻辑上隔离的环境中。虽然 `vm.createContext` 的具体实现细节可能涉及上下文的创建而非完全独立的 `Isolate`，但它展示了不同执行环境之间状态隔离的概念，这与 `Isolate` 的核心思想是一致的。

总而言之，`v8/src/execution/isolate.cc` 是 V8 引擎的核心组件，负责创建和管理独立的 JavaScript 执行环境，为 JavaScript 代码的运行提供了必要的资源和基础设施。 你编写和运行的每一行 JavaScript 代码都依赖于 `Isolate` 提供的功能。

Prompt: 
```
这是目录为v8/src/execution/isolate.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共5部分，请归纳一下它的功能

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
    // framework and library code, and stack depth tends to be more than
    // a dozen frames, so we over-allocate a bit here to avoid growing
    // the elements array in the common case.
    elements_ = isolate->factory()->NewFixedArray(std::min(64, limit));
  }

  bool Visit(FrameSummary const& summary) {
    if (Full()) return false;
#if V8_ENABLE_WEBASSEMBLY
#if V8_ENABLE_DRUMBRAKE
    if (summary.IsWasmInterpreted()) {
      AppendWasmInterpretedFrame(summary.AsWasmInterpreted());
      return true;
      // FrameSummary::IsWasm() should be renamed FrameSummary::IsWasmCompiled
      // to be more precise, but we'll leave it as it is to try to reduce merge
      // churn.
    } else {
#endif  // V8_ENABLE_DRUMBRAKE
      if (summary.IsWasm()) {
        AppendWasmFrame(summary.AsWasm());
        return true;
      }
#if V8_ENABLE_DRUMBRAKE
    }
#endif  // V8_ENABLE_DRUMBRAKE
    if (summary.IsWasmInlined()) {
      AppendWasmInlinedFrame(summary.AsWasmInlined());
      return true;
    }
    if (summary.IsBuiltin()) {
      AppendBuiltinFrame(summary.AsBuiltin());
      return true;
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    AppendJavaScriptFrame(summary.AsJavaScript());
    return true;
  }

  void AppendAsyncFrame(DirectHandle<JSGeneratorObject> generator_object) {
    DirectHandle<JSFunction> function(generator_object->function(), isolate_);
    if (!IsVisibleInStackTrace(function)) return;
    int flags = CallSiteInfo::kIsAsync;
    if (IsStrictFrame(function)) flags |= CallSiteInfo::kIsStrict;

    Handle<JSAny> receiver(generator_object->receiver(), isolate_);
    DirectHandle<BytecodeArray> code(
        function->shared()->GetBytecodeArray(isolate_), isolate_);
    int offset = GetGeneratorBytecodeOffset(generator_object);

    DirectHandle<FixedArray> parameters =
        isolate_->factory()->empty_fixed_array();
    if (V8_UNLIKELY(v8_flags.detailed_error_stack_trace)) {
      parameters = isolate_->factory()->CopyFixedArrayUpTo(
          handle(generator_object->parameters_and_registers(), isolate_),
          function->shared()
              ->internal_formal_parameter_count_without_receiver());
    }

    AppendFrame(receiver, function, code, offset, flags, parameters);
  }

  void AppendPromiseCombinatorFrame(DirectHandle<JSFunction> element_function,
                                    DirectHandle<JSFunction> combinator) {
    if (!IsVisibleInStackTrace(combinator)) return;
    int flags =
        CallSiteInfo::kIsAsync | CallSiteInfo::kIsSourcePositionComputed;

    Handle<JSFunction> receiver(
        combinator->native_context()->promise_function(), isolate_);
    DirectHandle<Code> code(combinator->code(isolate_), isolate_);

    // TODO(mmarchini) save Promises list from the Promise combinator
    DirectHandle<FixedArray> parameters =
        isolate_->factory()->empty_fixed_array();

    // We store the offset of the promise into the element function's
    // hash field for element callbacks.
    int promise_index = Smi::ToInt(element_function->GetIdentityHash()) - 1;

    AppendFrame(receiver, combinator, code, promise_index, flags, parameters);
  }

  void AppendJavaScriptFrame(
      FrameSummary::JavaScriptFrameSummary const& summary) {
    // Filter out internal frames that we do not want to show.
    if (!IsVisibleInStackTrace(summary.function())) return;

    int flags = 0;
    DirectHandle<JSFunction> function = summary.function();
    if (IsStrictFrame(function)) flags |= CallSiteInfo::kIsStrict;
    if (summary.is_constructor()) flags |= CallSiteInfo::kIsConstructor;

    AppendFrame(Cast<UnionOf<JSAny, Hole>>(summary.receiver()), function,
                summary.abstract_code(), summary.code_offset(), flags,
                summary.parameters());
  }

#if V8_ENABLE_WEBASSEMBLY
  void AppendWasmFrame(FrameSummary::WasmFrameSummary const& summary) {
    if (summary.code()->kind() != wasm::WasmCode::kWasmFunction) return;
    Handle<WasmInstanceObject> instance = summary.wasm_instance();
    int flags = CallSiteInfo::kIsWasm;
    if (instance->module_object()->is_asm_js()) {
      flags |= CallSiteInfo::kIsAsmJsWasm;
      if (summary.at_to_number_conversion()) {
        flags |= CallSiteInfo::kIsAsmJsAtNumberConversion;
      }
    }

    DirectHandle<HeapObject> code = isolate_->factory()->undefined_value();
    AppendFrame(instance,
                handle(Smi::FromInt(summary.function_index()), isolate_), code,
                summary.code_offset(), flags,
                isolate_->factory()->empty_fixed_array());
  }

#if V8_ENABLE_DRUMBRAKE
  void AppendWasmInterpretedFrame(
      FrameSummary::WasmInterpretedFrameSummary const& summary) {
    Handle<WasmInstanceObject> instance = summary.wasm_instance();
    int flags = CallSiteInfo::kIsWasm | CallSiteInfo::kIsWasmInterpretedFrame;
    DCHECK(!instance->module_object()->is_asm_js());
    // We don't have any code object in the interpreter, so we pass 'undefined'.
    auto code = isolate_->factory()->undefined_value();
    AppendFrame(instance,
                handle(Smi::FromInt(summary.function_index()), isolate_), code,
                summary.byte_offset(), flags,
                isolate_->factory()->empty_fixed_array());
  }
#endif  // V8_ENABLE_DRUMBRAKE

  void AppendWasmInlinedFrame(
      FrameSummary::WasmInlinedFrameSummary const& summary) {
    DirectHandle<HeapObject> code = isolate_->factory()->undefined_value();
    int flags = CallSiteInfo::kIsWasm;
    AppendFrame(summary.wasm_instance(),
                handle(Smi::FromInt(summary.function_index()), isolate_), code,
                summary.code_offset(), flags,
                isolate_->factory()->empty_fixed_array());
  }

  void AppendBuiltinFrame(FrameSummary::BuiltinFrameSummary const& summary) {
    Builtin builtin = summary.builtin();
    DirectHandle<Code> code = isolate_->builtins()->code_handle(builtin);
    DirectHandle<Smi> function(Smi::FromInt(static_cast<int>(builtin)),
                               isolate_);
    int flags = CallSiteInfo::kIsBuiltin;
    AppendFrame(Cast<UnionOf<JSAny, Hole>>(summary.receiver()), function, code,
                summary.code_offset(), flags,
                isolate_->factory()->empty_fixed_array());
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  bool Full() { return index_ >= limit_; }

  Handle<FixedArray> Build() {
    return FixedArray::RightTrimOrEmpty(isolate_, elements_, index_);
  }

 private:
  // Poison stack frames below the first strict mode frame.
  // The stack trace API should not expose receivers and function
  // objects on frames deeper than the top-most one with a strict mode
  // function.
  bool IsStrictFrame(DirectHandle<JSFunction> function) {
    if (!encountered_strict_function_) {
      encountered_strict_function_ =
          is_strict(function->shared()->language_mode());
    }
    return encountered_strict_function_;
  }

  // Determines whether the given stack frame should be displayed in a stack
  // trace.
  bool IsVisibleInStackTrace(DirectHandle<JSFunction> function) {
    return ShouldIncludeFrame(function) && IsNotHidden(function);
  }

  // This mechanism excludes a number of uninteresting frames from the stack
  // trace. This can be be the first frame (which will be a builtin-exit frame
  // for the error constructor builtin) or every frame until encountering a
  // user-specified function.
  bool ShouldIncludeFrame(DirectHandle<JSFunction> function) {
    switch (mode_) {
      case SKIP_NONE:
        return true;
      case SKIP_FIRST:
        if (!skip_next_frame_) return true;
        skip_next_frame_ = false;
        return false;
      case SKIP_UNTIL_SEEN:
        if (skip_next_frame_ && (*function == *caller_)) {
          skip_next_frame_ = false;
          return false;
        }
        return !skip_next_frame_;
    }
    UNREACHABLE();
  }

  bool IsNotHidden(DirectHandle<JSFunction> function) {
    // TODO(szuend): Remove this check once the flag is enabled
    //               by default.
    if (!v8_flags.experimental_stack_trace_frames &&
        function->shared()->IsApiFunction()) {
      return false;
    }
    // Functions defined not in user scripts are not visible unless directly
    // exposed, in which case the native flag is set.
    // The --builtins-in-stack-traces command line flag allows including
    // internal call sites in the stack trace for debugging purposes.
    if (!v8_flags.builtins_in_stack_traces &&
        !function->shared()->IsUserJavaScript()) {
      return function->shared()->native() ||
             function->shared()->IsApiFunction();
    }
    return true;
  }

  void AppendFrame(Handle<UnionOf<JSAny, Hole>> receiver_or_instance,
                   DirectHandle<UnionOf<Smi, JSFunction>> function,
                   DirectHandle<HeapObject> code, int offset, int flags,
                   DirectHandle<FixedArray> parameters) {
    if (IsTheHole(*receiver_or_instance, isolate_)) {
      // TODO(jgruber): Fix all cases in which frames give us a hole value
      // (e.g. the receiver in RegExp constructor frames).
      receiver_or_instance = isolate_->factory()->undefined_value();
    }
    auto info = isolate_->factory()->NewCallSiteInfo(
        Cast<JSAny>(receiver_or_instance), function, code, offset, flags,
        parameters);
    elements_ = FixedArray::SetAndGrow(isolate_, elements_, index_++, info);
  }

  Isolate* isolate_;
  const FrameSkipMode mode_;
  int index_ = 0;
  const int limit_;
  const Handle<Object> caller_;
  bool skip_next_frame_;
  bool encountered_strict_function_ = false;
  Handle<FixedArray> elements_;
};

void CaptureAsyncStackTrace(Isolate* isolate, DirectHandle<JSPromise> promise,
                            CallSiteBuilder* builder) {
  while (!builder->Full()) {
    // Check that the {promise} is not settled.
    if (promise->status() != Promise::kPending) return;

    // Check that we have exactly one PromiseReaction on the {promise}.
    if (!IsPromiseReaction(promise->reactions())) return;
    DirectHandle<PromiseReaction> reaction(
        Cast<PromiseReaction>(promise->reactions()), isolate);
    if (!IsSmi(reaction->next())) return;

    Handle<JSGeneratorObject> generator_object;

    if (TryGetAsyncGenerator(isolate, reaction).ToHandle(&generator_object)) {
      CHECK(generator_object->is_suspended());

      // Append async frame corresponding to the {generator_object}.
      builder->AppendAsyncFrame(generator_object);

      // Try to continue from here.
      if (IsJSAsyncFunctionObject(*generator_object)) {
        auto async_function_object =
            Cast<JSAsyncFunctionObject>(generator_object);
        promise = handle(async_function_object->promise(), isolate);
      } else {
        auto async_generator_object =
            Cast<JSAsyncGeneratorObject>(generator_object);
        if (IsUndefined(async_generator_object->queue(), isolate)) return;
        DirectHandle<AsyncGeneratorRequest> async_generator_request(
            Cast<AsyncGeneratorRequest>(async_generator_object->queue()),
            isolate);
        promise = handle(Cast<JSPromise>(async_generator_request->promise()),
                         isolate);
      }
    } else if (IsBuiltinFunction(isolate, reaction->fulfill_handler(),
                                 Builtin::kPromiseAllResolveElementClosure)) {
      DirectHandle<JSFunction> function(
          Cast<JSFunction>(reaction->fulfill_handler()), isolate);
      DirectHandle<Context> context(function->context(), isolate);
      DirectHandle<JSFunction> combinator(
          context->native_context()->promise_all(), isolate);
      builder->AppendPromiseCombinatorFrame(function, combinator);

      if (IsNativeContext(*context)) {
        // NativeContext is used as a marker that the closure was already
        // called. We can't access the reject element context any more.
        return;
      }

      // Now peek into the Promise.all() resolve element context to
      // find the promise capability that's being resolved when all
      // the concurrent promises resolve.
      int const index =
          PromiseBuiltins::kPromiseAllResolveElementCapabilitySlot;
      DirectHandle<PromiseCapability> capability(
          Cast<PromiseCapability>(context->get(index)), isolate);
      if (!IsJSPromise(capability->promise())) return;
      promise = handle(Cast<JSPromise>(capability->promise()), isolate);
    } else if (IsBuiltinFunction(
                   isolate, reaction->fulfill_handler(),
                   Builtin::kPromiseAllSettledResolveElementClosure)) {
      DirectHandle<JSFunction> function(
          Cast<JSFunction>(reaction->fulfill_handler()), isolate);
      DirectHandle<Context> context(function->context(), isolate);
      DirectHandle<JSFunction> combinator(
          context->native_context()->promise_all_settled(), isolate);
      builder->AppendPromiseCombinatorFrame(function, combinator);

      if (IsNativeContext(*context)) {
        // NativeContext is used as a marker that the closure was already
        // called. We can't access the reject element context any more.
        return;
      }

      // Now peek into the Promise.allSettled() resolve element context to
      // find the promise capability that's being resolved when all
      // the concurrent promises resolve.
      int const index =
          PromiseBuiltins::kPromiseAllResolveElementCapabilitySlot;
      DirectHandle<PromiseCapability> capability(
          Cast<PromiseCapability>(context->get(index)), isolate);
      if (!IsJSPromise(capability->promise())) return;
      promise = handle(Cast<JSPromise>(capability->promise()), isolate);
    } else if (IsBuiltinFunction(isolate, reaction->reject_handler(),
                                 Builtin::kPromiseAnyRejectElementClosure)) {
      DirectHandle<JSFunction> function(
          Cast<JSFunction>(reaction->reject_handler()), isolate);
      DirectHandle<Context> context(function->context(), isolate);
      DirectHandle<JSFunction> combinator(
          context->native_context()->promise_any(), isolate);
      builder->AppendPromiseCombinatorFrame(function, combinator);

      if (IsNativeContext(*context)) {
        // NativeContext is used as a marker that the closure was already
        // called. We can't access the reject element context any more.
        return;
      }

      // Now peek into the Promise.any() reject element context to
      // find the promise capability that's being resolved when any of
      // the concurrent promises resolve.
      int const index = PromiseBuiltins::kPromiseAnyRejectElementCapabilitySlot;
      DirectHandle<PromiseCapability> capability(
          Cast<PromiseCapability>(context->get(index)), isolate);
      if (!IsJSPromise(capability->promise())) return;
      promise = handle(Cast<JSPromise>(capability->promise()), isolate);
    } else if (IsBuiltinFunction(isolate, reaction->fulfill_handler(),
                                 Builtin::kPromiseCapabilityDefaultResolve)) {
      DirectHandle<JSFunction> function(
          Cast<JSFunction>(reaction->fulfill_handler()), isolate);
      DirectHandle<Context> context(function->context(), isolate);
      promise =
          handle(Cast<JSPromise>(context->get(PromiseBuiltins::kPromiseSlot)),
                 isolate);
    } else {
      // We have some generic promise chain here, so try to
      // continue with the chained promise on the reaction
      // (only works for native promise chains).
      Handle<HeapObject> promise_or_capability(
          reaction->promise_or_capability(), isolate);
      if (IsJSPromise(*promise_or_capability)) {
        promise = Cast<JSPromise>(promise_or_capability);
      } else if (IsPromiseCapability(*promise_or_capability)) {
        auto capability = Cast<PromiseCapability>(promise_or_capability);
        if (!IsJSPromise(capability->promise())) return;
        promise = handle(Cast<JSPromise>(capability->promise()), isolate);
      } else {
        // Otherwise the {promise_or_capability} must be undefined here.
        CHECK(IsUndefined(*promise_or_capability, isolate));
        return;
      }
    }
  }
}

MaybeHandle<JSPromise> TryGetCurrentTaskPromise(Isolate* isolate) {
  Handle<Object> current_microtask = isolate->factory()->current_microtask();
  if (IsPromiseReactionJobTask(*current_microtask)) {
    auto promise_reaction_job_task =
        Cast<PromiseReactionJobTask>(current_microtask);
    // Check if the {reaction} has one of the known async function or
    // async generator continuations as its fulfill handler.
    if (IsBuiltinAsyncFulfillHandler(isolate,
                                     promise_reaction_job_task->handler()) ||
        IsBuiltinAsyncRejectHandler(isolate,
                                    promise_reaction_job_task->handler())) {
      // Now peek into the handlers' AwaitContext to get to
      // the JSGeneratorObject for the async function.
      DirectHandle<Context> context(
          Cast<JSFunction>(promise_reaction_job_task->handler())->context(),
          isolate);
      Handle<JSGeneratorObject> generator_object(
          Cast<JSGeneratorObject>(context->extension()), isolate);
      if (generator_object->is_executing()) {
        if (IsJSAsyncFunctionObject(*generator_object)) {
          auto async_function_object =
              Cast<JSAsyncFunctionObject>(generator_object);
          Handle<JSPromise> promise(async_function_object->promise(), isolate);
          return promise;
        } else {
          auto async_generator_object =
              Cast<JSAsyncGeneratorObject>(generator_object);
          DirectHandle<Object> queue(async_generator_object->queue(), isolate);
          if (!IsUndefined(*queue, isolate)) {
            auto async_generator_request = Cast<AsyncGeneratorRequest>(queue);
            Handle<JSPromise> promise(
                Cast<JSPromise>(async_generator_request->promise()), isolate);
            return promise;
          }
        }
      }
    } else {
#if V8_ENABLE_WEBASSEMBLY
      Handle<WasmSuspenderObject> suspender;
      if (TryGetWasmSuspender(isolate, promise_reaction_job_task->handler())
              .ToHandle(&suspender)) {
        // The {promise_reaction_job_task} belongs to a suspended Wasm stack
        return handle(suspender->promise(), isolate);
      }
#endif  // V8_ENABLE_WEBASSEMBLY

      // The {promise_reaction_job_task} doesn't belong to an await (or
      // yield inside an async generator) or a suspended Wasm stack,
      // but we might still be able to find an async frame if we follow
      // along the chain of promises on the {promise_reaction_job_task}.
      Handle<HeapObject> promise_or_capability(
          promise_reaction_job_task->promise_or_capability(), isolate);
      if (IsJSPromise(*promise_or_capability)) {
        Handle<JSPromise> promise = Cast<JSPromise>(promise_or_capability);
        return promise;
      }
    }
  }
  return MaybeHandle<JSPromise>();
}

void CaptureAsyncStackTrace(Isolate* isolate, CallSiteBuilder* builder) {
  Handle<JSPromise> promise;
  if (TryGetCurrentTaskPromise(isolate).ToHandle(&promise)) {
    CaptureAsyncStackTrace(isolate, promise, builder);
  }
}

template <typename Visitor>
void VisitStack(Isolate* isolate, Visitor* visitor,
                StackTrace::StackTraceOptions options = StackTrace::kDetailed) {
  DisallowJavascriptExecution no_js(isolate);
  for (StackFrameIterator it(isolate); !it.done(); it.Advance()) {
    StackFrame* frame = it.frame();
    switch (frame->type()) {
      case StackFrame::API_CALLBACK_EXIT:
      case StackFrame::BUILTIN_EXIT:
      case StackFrame::JAVASCRIPT_BUILTIN_CONTINUATION:
      case StackFrame::JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH:
      case StackFrame::TURBOFAN_JS:
      case StackFrame::MAGLEV:
      case StackFrame::INTERPRETED:
      case StackFrame::BASELINE:
      case StackFrame::BUILTIN:
#if V8_ENABLE_WEBASSEMBLY
      case StackFrame::STUB:
      case StackFrame::WASM:
      case StackFrame::WASM_SEGMENT_START:
#if V8_ENABLE_DRUMBRAKE
      case StackFrame::WASM_INTERPRETER_ENTRY:
#endif  // V8_ENABLE_DRUMBRAKE
#endif  // V8_ENABLE_WEBASSEMBLY
      {
        // A standard frame may include many summarized frames (due to
        // inlining).
        std::vector<FrameSummary> summaries;
        CommonFrame::cast(frame)->Summarize(&summaries);
        for (auto rit = summaries.rbegin(); rit != summaries.rend(); ++rit) {
          FrameSummary& summary = *rit;
          // Skip frames from other origins when asked to do so.
          if (!(options & StackTrace::kExposeFramesAcrossSecurityOrigins) &&
              !summary.native_context()->HasSameSecurityTokenAs(
                  isolate->context())) {
            continue;
          }
          if (!visitor->Visit(summary)) return;
        }
        break;
      }

      default:
        break;
    }
  }
}

Handle<FixedArray> CaptureSimpleStackTrace(Isolate* isolate, int limit,
                                           FrameSkipMode mode,
                                           Handle<Object> caller) {
  TRACE_EVENT_BEGIN1(TRACE_DISABLED_BY_DEFAULT("v8.stack_trace"), __func__,
                     "maxFrameCount", limit);

#if V8_ENABLE_WEBASSEMBLY
  wasm::WasmCodeRefScope code_ref_scope;
#endif  // V8_ENABLE_WEBASSEMBLY

  CallSiteBuilder builder(isolate, mode, limit, caller);
  VisitStack(isolate, &builder);

  // If --async-stack-traces are enabled and the "current microtask" is a
  // PromiseReactionJobTask, we try to enrich the stack trace with async
  // frames.
  if (v8_flags.async_stack_traces) {
    CaptureAsyncStackTrace(isolate, &builder);
  }

  Handle<FixedArray> stack_trace = builder.Build();
  TRACE_EVENT_END1(TRACE_DISABLED_BY_DEFAULT("v8.stack_trace"), __func__,
                   "frameCount", stack_trace->length());
  return stack_trace;
}

Handle<StackTraceInfo> GetDetailedStackTraceFromCallSiteInfos(
    Isolate* isolate, DirectHandle<FixedArray> call_site_infos, int limit) {
  auto frames = isolate->factory()->NewFixedArray(
      std::min(limit, call_site_infos->length()));
  int index = 0;
  for (int i = 0; i < call_site_infos->length() && index < limit; ++i) {
    DirectHandle<CallSiteInfo> call_site_info(
        Cast<CallSiteInfo>(call_site_infos->get(i)), isolate);
    if (call_site_info->IsAsync()) {
      break;
    }
    Handle<Script> script;
    if (!CallSiteInfo::GetScript(isolate, call_site_info).ToHandle(&script) ||
        !script->IsSubjectToDebugging()) {
      continue;
    }
    DirectHandle<StackFrameInfo> stack_frame_info =
        isolate->factory()->NewStackFrameInfo(
            script, CallSiteInfo::GetSourcePosition(call_site_info),
            CallSiteInfo::GetFunctionDebugName(call_site_info),
            IsConstructor(*call_site_info));
    frames->set(index++, *stack_frame_info);
  }
  frames = FixedArray::RightTrimOrEmpty(isolate, frames, index);
  return isolate->factory()->NewStackTraceInfo(frames);
}

}  // namespace

MaybeHandle<JSObject> Isolate::CaptureAndSetErrorStack(
    Handle<JSObject> error_object, FrameSkipMode mode, Handle<Object> caller) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.stack_trace"), __func__);
  Handle<UnionOf<Undefined, FixedArray>> call_site_infos_or_formatted_stack =
      factory()->undefined_value();

  // Capture the "simple stack trace" for the error.stack property,
  // which can be disabled by setting Error.stackTraceLimit to a non
  // number value or simply deleting the property. If the inspector
  // is active, and requests more stack frames than the JavaScript
  // program itself, we collect up to the maximum.
  int stack_trace_limit = 0;
  if (GetStackTraceLimit(this, &stack_trace_limit)) {
    int limit = stack_trace_limit;
    if (capture_stack_trace_for_uncaught_exceptions_ &&
        !(stack_trace_for_uncaught_exceptions_options_ &
          StackTrace::kExposeFramesAcrossSecurityOrigins)) {
      // Collect up to the maximum of what the JavaScript program and
      // the inspector want. There's a special case here where the API
      // can ask the stack traces to also include cross-origin frames,
      // in which case we collect a separate trace below. Note that
      // the inspector doesn't use this option, so we could as well
      // just deprecate this in the future.
      if (limit < stack_trace_for_uncaught_exceptions_frame_limit_) {
        limit = stack_trace_for_uncaught_exceptions_frame_limit_;
      }
    }
    call_site_infos_or_formatted_stack =
        CaptureSimpleStackTrace(this, limit, mode, caller);
  }
  Handle<Object> error_stack = call_site_infos_or_formatted_stack;

  // Next is the inspector part: Depending on whether we got a "simple
  // stack trace" above and whether that's usable (meaning the API
  // didn't request to include cross-origin frames), we remember the
  // cap for the stack trace (either a positive limit indicating that
  // the Error.stackTraceLimit value was below what was requested via
  // the API, or a negative limit to indicate the opposite), or we
  // collect a "detailed stack trace" eagerly and stash that away.
  if (capture_stack_trace_for_uncaught_exceptions_) {
    Handle<StackTraceInfo> stack_trace;
    if (IsUndefined(*call_site_infos_or_formatted_stack, this) ||
        (stack_trace_for_uncaught_exceptions_options_ &
         StackTrace::kExposeFramesAcrossSecurityOrigins)) {
      stack_trace = CaptureDetailedStackTrace(
          stack_trace_for_uncaught_exceptions_frame_limit_,
          stack_trace_for_uncaught_exceptions_options_);
    } else {
      auto call_site_infos =
          Cast<FixedArray>(call_site_infos_or_formatted_stack);
      stack_trace = GetDetailedStackTraceFromCallSiteInfos(
          this, call_site_infos,
          stack_trace_for_uncaught_exceptions_frame_limit_);
      if (stack_trace_limit < call_site_infos->length()) {
        call_site_infos_or_formatted_stack = FixedArray::RightTrimOrEmpty(
            this, call_site_infos, stack_trace_limit);
      }
      // Notify the debugger.
      OnStackTraceCaptured(stack_trace);
    }
    error_stack = factory()->NewErrorStackData(
        call_site_infos_or_formatted_stack, stack_trace);
  }

  RETURN_ON_EXCEPTION(
      this,
      Object::SetProperty(this, error_object, factory()->error_stack_symbol(),
                          error_stack, StoreOrigin::kMaybeKeyed,
                          Just(ShouldThrow::kThrowOnError)));
  return error_object;
}

Handle<StackTraceInfo> Isolate::GetDetailedStackTrace(
    Handle<JSReceiver> maybe_error_object) {
  ErrorUtils::StackPropertyLookupResult lookup =
      ErrorUtils::GetErrorStackProperty(this, maybe_error_object);
  if (!IsErrorStackData(*lookup.error_stack)) return {};
  return handle(Cast<ErrorStackData>(lookup.error_stack)->stack_trace(), this);
}

Handle<FixedArray> Isolate::GetSimpleStackTrace(
    Handle<JSReceiver> maybe_error_object) {
  ErrorUtils::StackPropertyLookupResult lookup =
      ErrorUtils::GetErrorStackProperty(this, maybe_error_object);

  if (IsFixedArray(*lookup.error_stack)) {
    return Cast<FixedArray>(lookup.error_stack);
  }
  if (!IsErrorStackData(*lookup.error_stack)) {
    return factory()->empty_fixed_array();
  }
  auto error_stack_data = Cast<ErrorStackData>(lookup.error_stack);
  if (!error_stack_data->HasCallSiteInfos()) {
    return factory()->empty_fixed_array();
  }
  return handle(error_stack_data->call_site_infos(), this);
}

Address Isolate::GetAbstractPC(int* line, int* column) {
  JavaScriptStackFrameIterator it(this);

  if (it.done()) {
    *line = -1;
    *column = -1;
    return kNullAddress;
  }
  JavaScriptFrame* frame = it.frame();
  DCHECK(!frame->is_builtin());

  Handle<SharedFunctionInfo> shared(frame->function()->shared(), this);
  SharedFunctionInfo::EnsureSourcePositionsAvailable(this, shared);
  int position = frame->position();

  Tagged<Object> maybe_script = frame->function()->shared()->script();
  if (IsScript(maybe_script)) {
    DirectHandle<Script> script(Cast<Script>(maybe_script), this);
    Script::PositionInfo info;
    Script::GetPositionInfo(script, position, &info);
    *line = info.line + 1;
    *column = info.column + 1;
  } else {
    *line = position;
    *column = -1;
  }

  if (frame->is_unoptimized()) {
    UnoptimizedJSFrame* iframe = static_cast<UnoptimizedJSFrame*>(frame);
    Address bytecode_start =
        iframe->GetBytecodeArray()->GetFirstBytecodeAddress();
    return bytecode_start + iframe->GetBytecodeOffset();
  }

  return frame->pc();
}

namespace {

class StackFrameBuilder {
 public:
  StackFrameBuilder(Isolate* isolate, int limit)
      : isolate_(isolate),
        frames_(isolate_->factory()->empty_fixed_array()),
        index_(0),
        limit_(limit) {}

  bool Visit(FrameSummary& summary) {
    // Check if we have enough capacity left.
    if (index_ >= limit_) return false;
    // Skip frames that aren't subject to debugging.
    if (!summary.is_subject_to_debugging()) return true;
    DirectHandle<StackFrameInfo> frame = summary.CreateStackFrameInfo();
    frames_ = FixedArray::SetAndGrow(isolate_, frames_, index_++, frame);
    return true;
  }

  Handle<FixedArray> Build() {
    return FixedArray::RightTrimOrEmpty(isolate_, frames_, index_);
  }

 private:
  Isolate* isolate_;
  Handle<FixedArray> frames_;
  int index_;
  int limit_;
};

}  // namespace

Handle<StackTraceInfo> Isolate::CaptureDetailedStackTrace(
    int limit, StackTrace::StackTraceOptions options) {
  TRACE_EVENT_BEGIN1(TRACE_DISABLED_BY_DEFAULT("v8.stack_trace"), __func__,
                     "maxFrameCount", limit);
  StackFrameBuilder builder(this, limit);
  VisitStack(this, &builder, options);
  auto frames = builder.Build();
  TRACE_EVENT_END1(TRACE_DISABLED_BY_DEFAULT("v8.stack_trace"), __func__,
                   "frameCount", frames->length());
  auto stack_trace = factory()->NewStackTraceInfo(frames);
  OnStackTraceCaptured(stack_trace);
  return stack_trace;
}

namespace {

class CurrentScriptNameStackVisitor {
 public:
  explicit CurrentScriptNameStackVisitor(Isolate* isolate)
      : isolate_(isolate) {}

  bool Visit(FrameSummary& summary) {
    // Skip frames that aren't subject to debugging. Keep this in sync with
    // StackFrameBuilder::Visit so both visitors visit the same frames.
    if (!summary.is_subject_to_debugging()) return true;

    // Frames that are subject to debugging always have a valid script object.
    auto script = Cast<Script>(summary.script());
    Handle<Object> name_or_url_obj(script->GetNameOrSourceURL(), isolate_);
    if (!IsString(*name_or_url_obj)) return true;

    auto name_or_url = Cast<String>(name_or_url_obj);
    if (!name_or_url->length()) return true;

    name_or_url_ = name_or_url;
    return false;
  }

  Handle<String> CurrentScriptNameOrSourceURL() const { return name_or_url_; }

 private:
  Isolate* const isolate_;
  Handle<String> name_or_url_;
};

class CurrentScriptStackVisitor {
 public:
  bool Visit(FrameSummary& summary) {
    // Skip frames that aren't subject to debugging. Keep this in sync with
    // StackFrameBuilder::Visit so both visitors visit the same frames.
    if (!summary.is_subject_to_debugging()) return true;

    // Frames that are subject to debugging always have a valid script object.
    current_script_ = Cast<Script>(summary.script());
    return false;
  }

  MaybeHandle<Script> CurrentScript() const { return current_script_; }

 private:
  MaybeHandle<Script> current_script_;
};

}  // namespace

Handle<String> Isolate::CurrentScriptNameOrSourceURL() {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.stack_trace"), __func__);
  CurrentScriptNameStackVisitor visitor(this);
  VisitStack(this, &visitor);
  return visitor.CurrentScriptNameOrSourceURL();
}

MaybeHandle<Script> Isolate::CurrentReferrerScript() {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.stack_trace"), __func__);
  CurrentScriptStackVisitor visitor{};
  VisitStack(this, &visitor);
  Handle<Script> script;
  if (!visitor.CurrentScript().ToHandle(&script)) {
    return MaybeHandle<Script>();
  }
  return handle(script->GetEvalOrigin(), this);
}

bool Isolate::GetStackTraceLimit(Isolate* isolate, int* result) {
  if (v8_flags.correctness_fuzzer_suppressions) return false;
  Handle<JSObject> error = isolate->error_function();

  Handle<String> key = isolate->factory()->stackTraceLimit_string();
  DirectHandle<Object> stack_trace_limit =
      JSReceiver::GetDataProperty(isolate, error, key);
  if (!IsNumber(*stack_trace_limit)) return false;

  // Ensure that limit is not negative.
  *result = std::max(
      FastD2IChecked(Object::NumberValue(Cast<Number>(*stack_trace_limit))), 0);

  if (*result != v8_flags.stack_trace_limit) {
    isolate->CountU
"""


```