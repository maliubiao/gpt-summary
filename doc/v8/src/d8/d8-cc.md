Response:
The user wants a summary of the functionality of the C++ code in `v8/src/d8/d8.cc`. I need to identify the main purposes and features implemented in this file.

Here's a breakdown of the code's components and their probable functionalities:

* **Includes:** Standard C/C++ libraries and V8 headers. This suggests core system operations and interaction with the V8 engine.
* **Preprocessor directives (e.g., `#ifdef ENABLE_VTUNE_JIT_INTERFACE`):** Conditional compilation for different platforms, debugging tools, or features.
* **Namespaces:** `v8` indicates core V8 functionality. The anonymous namespace `namespace {` contains helper functions and classes specific to this file.
* **Global variables (e.g., `g_default_platform`, `Shell::counter_map_`):** Configuration and state management for the `d8` tool.
* **Classes and structs (e.g., `ArrayBufferAllocatorBase`, `Shell`, `Worker`):**  Represent core components and their relationships. `Shell` likely represents the `d8` REPL environment itself.
* **Functions (e.g., `ThrowError`, `CompileString`, `CreateScriptOrigin`):**  Implement specific actions, like error handling, script compilation, and setting up script contexts.
* **ArrayBuffer Allocators (e.g., `ShellArrayBufferAllocator`, `MockArrayBufferAllocator`):** Custom memory management strategies, potentially for testing or specific performance scenarios.
* **Tracing (`namespace tracing`):** Functionality related to performance tracing and profiling.
* **Module loading (`class ModuleEmbedderData`):**  Support for ECMAScript modules.
* **WebAssembly (`#if V8_ENABLE_WEBASSEMBLY`):** Integration with WebAssembly.
* **Fuzzing (`#ifdef V8_FUZZILLI`):** Support for fuzz testing.
* **Threading (`thread_local Worker* current_worker_`):**  Support for multi-threading and workers.

Based on these observations, the main functionalities of `v8/src/d8/d8.cc` are likely related to:

1. **Being the core implementation of the `d8` command-line tool:** This involves setting up the V8 environment, handling input, executing JavaScript code, and providing a REPL.
2. **Providing debugging and profiling capabilities:**  The inclusion of headers related to debugging, profiling, and tracing strongly suggests this.
3. **Supporting different script types:**  The code handles classic JavaScript, modules, and potentially WebAssembly.
4. **Managing memory allocation for ArrayBuffers:** Custom allocators indicate specific needs for performance or testing.
5. **Supporting multi-threading and workers:** The presence of a `Worker` class and related logic points to this.
6. **Facilitating testing and development:**  Mock allocators and fuzzing support suggest the file plays a role in V8's development process.

Since the user requested a summary for the first part, I will focus on these core functionalities as evidenced by the included headers and early parts of the code. I will also note that the file is a C++ source file and not a Torque file.
好的，让我们来分析一下 `v8/src/d8/d8.cc` 的功能。

**功能归纳:**

`v8/src/d8/d8.cc` 是 V8 JavaScript 引擎提供的命令行工具 `d8` 的主要源代码文件。 它的核心功能是：

1. **作为 V8 引擎的命令行交互式解释器 (REPL) 和脚本执行器：** 它允许用户在命令行中直接输入和执行 JavaScript 代码，也可以执行包含 JavaScript 代码的文件。
2. **提供 V8 引擎的各种调试和分析功能：**  通过命令行参数，可以启用和配置 V8 的各种特性，例如：
    * **调试 (Inspector):**  可以连接到 Chrome DevTools 进行远程调试。
    * **性能分析 (Profiler):** 可以收集 CPU 和内存使用情况，帮助开发者优化代码。
    * **代码缓存 (Code Cache):**  支持将编译后的代码缓存到磁盘，加速后续执行。
    * **跟踪 (Tracing):**  可以记录 V8 内部的事件，用于性能分析和调试。
3. **支持 WebAssembly：**  允许加载和执行 WebAssembly 模块。
4. **支持 ECMAScript 模块 (Modules)：**  能够加载和执行 ES 模块。
5. **提供一些 V8 特有的扩展功能：**  例如，`d8` 提供了一些全局对象和函数，方便与 V8 引擎交互，例如控制垃圾回收等。
6. **进行 V8 引擎的测试和开发：**  `d8` 自身也被用于 V8 引擎的测试和开发，例如通过命令行参数模拟各种场景。
7. **支持 Workers (多线程)：**  允许创建和管理 JavaScript Worker 线程。
8. **支持 Fuzzing (模糊测试)：** 集成了 Fuzzilli 用于对 V8 进行安全测试。

**关于文件类型:**

`v8/src/d8/d8.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**，而不是 V8 Torque 源代码文件。 Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`d8` 工具直接运行 JavaScript 代码，因此其功能与所有标准的 JavaScript 功能都有关系。以下是一些示例，展示了 `d8` 如何与 JavaScript 功能交互：

**1. 基本 JavaScript 执行:**

假设你有一个名为 `hello.js` 的文件，内容如下：

```javascript
console.log("Hello, world!");
```

你可以使用 `d8` 执行它：

```bash
./d8 hello.js
```

**输出:**

```
Hello, world!
```

**2. 使用内置对象和函数:**

你可以在 `d8` 中使用 JavaScript 的内置对象和函数：

```bash
./d8 -e 'console.log(Math.PI);'
```

**输出:**

```
3.141592653589793
```

**3. 模块的加载和执行:**

假设你有两个文件，`module.js`:

```javascript
// module.js
export function greet(name) {
  return `Hello, ${name}!`;
}
```

和 `main.js`:

```javascript
// main.js
import { greet } from './module.js';
console.log(greet("D8 User"));
```

你可以使用 `d8` 执行 `main.js`：

```bash
./d8 main.js
```

**输出:**

```
Hello, D8 User!
```

**4. 使用 `d8` 提供的全局对象 (假设有，虽然此代码片段中未直接体现):**

虽然给出的代码片段没有直接展示 `d8` 特有的全局对象，但 `d8` 可能会提供一些额外的全局对象或函数来控制 V8 引擎的行为。 例如，早期的 `d8` 版本可能提供类似 `gc()` 的函数来手动触发垃圾回收。

**代码逻辑推理 (假设输入与输出):**

由于这是代码的头部，并没有具体的业务逻辑需要推理，但我们可以假设一个简单的场景：

**假设输入:**  使用 `d8` 执行一个包含 `1 + 1` 的 JavaScript 代码片段。

**d8 命令:**

```bash
./d8 -e 'console.log(1 + 1);'
```

**代码逻辑 (推测):**

1. `d8` 启动并解析命令行参数 `-e 'console.log(1 + 1);'`.
2. `d8` 初始化 V8 引擎。
3. `d8` 创建一个 V8 上下文 (Context)。
4. `d8` 将 JavaScript 代码 `console.log(1 + 1);` 传递给 V8 引擎进行编译。
5. V8 引擎执行编译后的代码。
6. `console.log(1 + 1)`  计算结果为 `2`。
7. `console.log(2)` 将 `2` 输出到 `d8` 的标准输出。

**假设输出:**

```
2
```

**用户常见的编程错误 (与 `d8` 使用相关的):**

1. **路径错误:**  执行脚本时，如果脚本路径不正确，`d8` 会报错。
   ```bash
   ./d8 non_existent_file.js  // 错误的文件路径
   ```
   **错误信息可能包含:**  "Error reading file: non_existent_file.js" 或类似信息。

2. **语法错误:**  JavaScript 代码中存在语法错误会导致 `d8` 抛出异常并终止执行。
   ```bash
   ./d8 -e 'console.log("Hello"' // 缺少引号
   ```
   **错误信息可能包含:**  "SyntaxError: Unexpected end of input" 或类似信息。

3. **模块加载错误:**  在使用模块时，如果模块路径不正确或者模块没有正确导出，会导致加载错误。
   ```bash
   ./d8 main.js // 假设 main.js 导入了一个不存在的模块
   ```
   **错误信息可能包含:**  "Cannot find module '...' " 或类似信息。

4. **命令行参数错误:**  使用了 `d8` 不支持的命令行参数，或者参数格式错误。
   ```bash
   ./d8 --invalid-flag  // 不存在的 flag
   ```
   **错误信息可能包含:**  "Error: Unknown flag --invalid-flag" 或类似信息。

**总结 (针对第 1 部分):**

这段代码是 V8 引擎命令行工具 `d8` 的核心部分，负责初始化和配置 V8 引擎，处理命令行参数，编译和执行 JavaScript 代码，并提供基本的调试和分析功能。 它是一个 C++ 文件，而非 Torque 文件。

Prompt: 
```
这是目录为v8/src/d8/d8.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/d8/d8.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共8部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <string>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef ENABLE_VTUNE_JIT_INTERFACE
#include "src/third_party/vtune/v8-vtune.h"
#endif

#include "include/libplatform/libplatform.h"
#include "include/libplatform/v8-tracing.h"
#include "include/v8-function.h"
#include "include/v8-initialization.h"
#include "include/v8-inspector.h"
#include "include/v8-isolate.h"
#include "include/v8-json.h"
#include "include/v8-locker.h"
#include "include/v8-profiler.h"
#include "include/v8-wasm.h"
#include "src/api/api-inl.h"
#include "src/base/cpu.h"
#include "src/base/logging.h"
#include "src/base/platform/memory.h"
#include "src/base/platform/platform.h"
#include "src/base/platform/time.h"
#include "src/base/platform/wrappers.h"
#include "src/base/sanitizer/msan.h"
#include "src/base/sys-info.h"
#include "src/base/utils/random-number-generator.h"
#include "src/compiler-dispatcher/optimizing-compile-dispatcher.h"
#include "src/d8/d8-console.h"
#include "src/d8/d8-platforms.h"
#include "src/d8/d8.h"
#include "src/debug/debug-interface.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/diagnostics/basic-block-profiler.h"
#include "src/execution/microtask-queue.h"
#include "src/execution/v8threads.h"
#include "src/execution/vm-state-inl.h"
#include "src/flags/flags.h"
#include "src/handles/maybe-handles.h"
#include "src/heap/parked-scope-inl.h"
#include "src/init/v8.h"
#include "src/interpreter/interpreter.h"
#include "src/logging/counters.h"
#include "src/logging/log-file.h"
#include "src/objects/managed-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/objects.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/parsing.h"
#include "src/parsing/scanner-character-streams.h"
#include "src/profiler/profile-generator.h"
#include "src/snapshot/snapshot.h"
#include "src/tasks/cancelable-task.h"
#include "src/utils/ostreams.h"
#include "src/utils/utils.h"

#ifdef V8_OS_DARWIN
#include <mach/mach.h>
#include <mach/task_policy.h>
#endif

#ifdef V8_ENABLE_MAGLEV
#include "src/maglev/maglev-concurrent-dispatcher.h"
#endif  // V8_ENABLE_MAGLEV

#if V8_OS_POSIX
#include <signal.h>
#endif  // V8_OS_POSIX

#ifdef V8_FUZZILLI
#include "src/fuzzilli/cov.h"
#include "src/fuzzilli/fuzzilli.h"
#endif  // V8_FUZZILLI

#ifdef V8_USE_PERFETTO
#include "perfetto/tracing/track_event.h"
#include "perfetto/tracing/track_event_legacy.h"
#endif  // V8_USE_PERFETTO

#ifdef V8_INTL_SUPPORT
#include "unicode/locid.h"
#endif  // V8_INTL_SUPPORT

#ifdef V8_OS_LINUX
#include <sys/mman.h>  // For MultiMappedAllocator.
#endif

#if defined(V8_OS_WIN)
#include <windows.h>
#else
#include <unistd.h>
#endif  // defined(V8_OS_WIN)

#if V8_ENABLE_WEBASSEMBLY
#include "src/trap-handler/trap-handler.h"
#endif  // V8_ENABLE_WEBASSEMBLY

#ifndef DCHECK
#define DCHECK(condition) assert(condition)
#endif

#ifndef CHECK
#define CHECK(condition) assert(condition)
#endif

namespace v8 {

namespace {

// Set on worker threads to the current Worker instance.
thread_local Worker* current_worker_ = nullptr;

#ifdef V8_FUZZILLI
bool fuzzilli_reprl = true;
#else
bool fuzzilli_reprl = false;
#endif  // V8_FUZZILLI

// Base class for shell ArrayBuffer allocators. It forwards all operations to
// the default v8 allocator.
class ArrayBufferAllocatorBase : public v8::ArrayBuffer::Allocator {
 public:
  void* Allocate(size_t length) override {
    return allocator_->Allocate(length);
  }

  void* AllocateUninitialized(size_t length) override {
    return allocator_->AllocateUninitialized(length);
  }

  void Free(void* data, size_t length) override {
    allocator_->Free(data, length);
  }

 private:
  std::unique_ptr<Allocator> allocator_ =
      std::unique_ptr<Allocator>(NewDefaultAllocator());
};

// ArrayBuffer allocator that can use virtual memory to improve performance.
class ShellArrayBufferAllocator : public ArrayBufferAllocatorBase {
 public:
  void* Allocate(size_t length) override {
    if (length >= kVMThreshold) return AllocateVM(length);
    return ArrayBufferAllocatorBase::Allocate(length);
  }

  void* AllocateUninitialized(size_t length) override {
    if (length >= kVMThreshold) return AllocateVM(length);
    return ArrayBufferAllocatorBase::AllocateUninitialized(length);
  }

  void Free(void* data, size_t length) override {
    if (length >= kVMThreshold) {
      FreeVM(data, length);
    } else {
      ArrayBufferAllocatorBase::Free(data, length);
    }
  }

 private:
  static constexpr size_t kVMThreshold = 65536;

  void* AllocateVM(size_t length) {
    DCHECK_LE(kVMThreshold, length);
    v8::PageAllocator* page_allocator = i::GetArrayBufferPageAllocator();
    size_t page_size = page_allocator->AllocatePageSize();
    size_t allocated = RoundUp(length, page_size);
    return i::AllocatePages(page_allocator, nullptr, allocated, page_size,
                            PageAllocator::kReadWrite);
  }

  void FreeVM(void* data, size_t length) {
    v8::PageAllocator* page_allocator = i::GetArrayBufferPageAllocator();
    size_t page_size = page_allocator->AllocatePageSize();
    size_t allocated = RoundUp(length, page_size);
    i::FreePages(page_allocator, data, allocated);
  }
};

// ArrayBuffer allocator that never allocates over 10MB.
class MockArrayBufferAllocator : public ArrayBufferAllocatorBase {
 protected:
  void* Allocate(size_t length) override {
    return ArrayBufferAllocatorBase::Allocate(Adjust(length));
  }

  void* AllocateUninitialized(size_t length) override {
    return ArrayBufferAllocatorBase::AllocateUninitialized(Adjust(length));
  }

  void Free(void* data, size_t length) override {
    return ArrayBufferAllocatorBase::Free(data, Adjust(length));
  }

 private:
  size_t Adjust(size_t length) {
    const size_t kAllocationLimit = 10 * i::MB;
    return length > kAllocationLimit ? i::AllocatePageSize() : length;
  }
};

// ArrayBuffer allocator that can be equipped with a limit to simulate system
// OOM.
class MockArrayBufferAllocatiorWithLimit : public MockArrayBufferAllocator {
 public:
  explicit MockArrayBufferAllocatiorWithLimit(size_t allocation_limit)
      : space_left_(allocation_limit) {}

 protected:
  void* Allocate(size_t length) override {
    if (length > space_left_) {
      return nullptr;
    }
    space_left_ -= length;
    return MockArrayBufferAllocator::Allocate(length);
  }

  void* AllocateUninitialized(size_t length) override {
    if (length > space_left_) {
      return nullptr;
    }
    space_left_ -= length;
    return MockArrayBufferAllocator::AllocateUninitialized(length);
  }

  void Free(void* data, size_t length) override {
    space_left_ += length;
    return MockArrayBufferAllocator::Free(data, length);
  }

 private:
  std::atomic<size_t> space_left_;
};

#ifdef V8_OS_LINUX

// This is a mock allocator variant that provides a huge virtual allocation
// backed by a small real allocation that is repeatedly mapped. If you create an
// array on memory allocated by this allocator, you will observe that elements
// will alias each other as if their indices were modulo-divided by the real
// allocation length.
// The purpose is to allow stability-testing of huge (typed) arrays without
// actually consuming huge amounts of physical memory.
// This is currently only available on Linux because it relies on {mremap}.
class MultiMappedAllocator : public ArrayBufferAllocatorBase {
 protected:
  void* Allocate(size_t length) override {
    if (length < kChunkSize) {
      return ArrayBufferAllocatorBase::Allocate(length);
    }
    // We use mmap, which initializes pages to zero anyway.
    return AllocateUninitialized(length);
  }

  void* AllocateUninitialized(size_t length) override {
    if (length < kChunkSize) {
      return ArrayBufferAllocatorBase::AllocateUninitialized(length);
    }
    size_t rounded_length = RoundUp(length, kChunkSize);
    int prot = PROT_READ | PROT_WRITE;
    // We have to specify MAP_SHARED to make {mremap} below do what we want.
    int flags = MAP_SHARED | MAP_ANONYMOUS;
    void* real_alloc = mmap(nullptr, kChunkSize, prot, flags, -1, 0);
    if (reinterpret_cast<intptr_t>(real_alloc) == -1) {
      // If we ran into some limit (physical or virtual memory, or number
      // of mappings, etc), return {nullptr}, which callers can handle.
      if (errno == ENOMEM) {
        return nullptr;
      }
      // Other errors may be bugs which we want to learn about.
      FATAL("mmap (real) failed with error %d: %s", errno, strerror(errno));
    }
#ifdef V8_ENABLE_SANDBOX
    // The backing memory must be allocated inside the sandbox as it will be
    // used for array buffer contents.
    // Here we go into somewhat less-well-defined territory by using the
    // sandbox's virtual address space to essentially just reserve a number of
    // OS pages inside the sandbox, but then using mremap to replace these
    // pages directly afterwards. In practice, this works fine however.
    VirtualAddressSpace* vas = i::GetProcessWideSandbox()->address_space();
    i::Address in_sandbox_page_reservation = vas->AllocatePages(
        VirtualAddressSpace::kNoHint, rounded_length,
        vas->allocation_granularity(), PagePermissions::kNoAccess);
    void* virtual_alloc =
        in_sandbox_page_reservation != 0
            ? reinterpret_cast<void*>(in_sandbox_page_reservation)
            : reinterpret_cast<void*>(-1);
#else
    void* virtual_alloc =
        mmap(nullptr, rounded_length, prot, flags | MAP_NORESERVE, -1, 0);
#endif
    if (reinterpret_cast<intptr_t>(virtual_alloc) == -1) {
      if (errno == ENOMEM) {
        // Undo earlier, successful mappings.
        munmap(real_alloc, kChunkSize);
        return nullptr;
      }
      FATAL("mmap (virtual) failed with error %d: %s", errno, strerror(errno));
    }
    i::Address virtual_base = reinterpret_cast<i::Address>(virtual_alloc);
    i::Address virtual_end = virtual_base + rounded_length;
    for (i::Address to_map = virtual_base; to_map < virtual_end;
         to_map += kChunkSize) {
      // Specifying 0 as the "old size" causes the existing map entry to not
      // get deleted, which is important so that we can remap it again in the
      // next iteration of this loop.
      void* result =
          mremap(real_alloc, 0, kChunkSize, MREMAP_MAYMOVE | MREMAP_FIXED,
                 reinterpret_cast<void*>(to_map));
      if (reinterpret_cast<intptr_t>(result) == -1) {
        if (errno == ENOMEM) {
          // Undo earlier, successful mappings.
          munmap(real_alloc, kChunkSize);
#ifdef V8_ENABLE_SANDBOX
          vas->FreePages(in_sandbox_page_reservation, rounded_length);
#else
          munmap(virtual_alloc, rounded_length);
#endif
          return nullptr;
        }
        FATAL("mremap failed with error %d: %s", errno, strerror(errno));
      }
    }
    base::MutexGuard lock_guard(&regions_mutex_);
    regions_[virtual_alloc] = real_alloc;
    return virtual_alloc;
  }

  void Free(void* data, size_t length) override {
    if (length < kChunkSize) {
      return ArrayBufferAllocatorBase::Free(data, length);
    }
    base::MutexGuard lock_guard(&regions_mutex_);
    void* real_alloc = regions_[data];
    munmap(real_alloc, kChunkSize);
    size_t rounded_length = RoundUp(length, kChunkSize);
#ifdef V8_ENABLE_SANDBOX
    VirtualAddressSpace* vas = i::GetProcessWideSandbox()->address_space();
    vas->FreePages(reinterpret_cast<i::Address>(data), rounded_length);
#else
    munmap(data, rounded_length);
#endif
    regions_.erase(data);
  }

 private:
  // Aiming for a "Huge Page" (2M on Linux x64) to go easy on the TLB.
  static constexpr size_t kChunkSize = 2 * 1024 * 1024;

  std::unordered_map<void*, void*> regions_;
  base::Mutex regions_mutex_;
};

#endif  // V8_OS_LINUX

v8::Platform* g_default_platform;
std::unique_ptr<v8::Platform> g_platform;

template <int N>
void ThrowError(Isolate* isolate, const char (&message)[N]) {
  if (isolate->IsExecutionTerminating()) return;
  isolate->ThrowError(message);
}

void ThrowError(Isolate* isolate, Local<String> message) {
  if (isolate->IsExecutionTerminating()) return;
  isolate->ThrowError(message);
}

void ThrowException(Isolate* isolate, Local<Value> exception) {
  if (isolate->IsExecutionTerminating()) return;
  isolate->ThrowException(exception);
}

static MaybeLocal<Value> TryGetValue(v8::Isolate* isolate,
                                     Local<Context> context,
                                     Local<v8::Object> object,
                                     const char* property) {
  MaybeLocal<String> v8_str = String::NewFromUtf8(isolate, property);
  if (v8_str.IsEmpty()) return {};
  return object->Get(context, v8_str.ToLocalChecked());
}

static Local<Value> GetValue(v8::Isolate* isolate, Local<Context> context,
                             Local<v8::Object> object, const char* property) {
  return TryGetValue(isolate, context, object, property).ToLocalChecked();
}

std::shared_ptr<Worker> GetWorkerFromInternalField(Isolate* isolate,
                                                   Local<Object> object) {
  if (object->InternalFieldCount() != 1) {
    ThrowError(isolate, "this is not a Worker");
    return nullptr;
  }

  i::DirectHandle<i::Object> handle =
      Utils::OpenDirectHandle(*object->GetInternalField(0));
  if (IsSmi(*handle)) {
    ThrowError(isolate, "Worker is defunct because main thread is terminating");
    return nullptr;
  }
  auto managed = i::Cast<i::Managed<Worker>>(handle);
  return managed->get();
}

base::Thread::Options GetThreadOptions(const char* name) {
  // On some systems (OSX 10.6) the stack size default is 0.5Mb or less
  // which is not enough to parse the big literal expressions used in tests.
  // The stack size should be at least StackGuard::kLimitSize + some
  // OS-specific padding for thread startup code.  2Mbytes seems to be enough.
  return base::Thread::Options(name, 2 * i::MB);
}

}  // namespace

namespace tracing {

namespace {

static constexpr char kIncludedCategoriesParam[] = "included_categories";
static constexpr char kTraceConfigParam[] = "trace_config";

class TraceConfigParser {
 public:
  static void FillTraceConfig(v8::Isolate* isolate,
                              platform::tracing::TraceConfig* trace_config,
                              const char* json_str) {
    HandleScope outer_scope(isolate);
    Local<Context> context = Context::New(isolate);
    Context::Scope context_scope(context);
    HandleScope inner_scope(isolate);

    Local<String> source =
        String::NewFromUtf8(isolate, json_str).ToLocalChecked();
    Local<Value> result = JSON::Parse(context, source).ToLocalChecked();
    Local<v8::Object> trace_config_object = result.As<v8::Object>();
    // Try reading 'trace_config' property from a full chrome trace config.
    // https://chromium.googlesource.com/chromium/src/+/master/docs/memory-infra/memory_infra_startup_tracing.md#the-advanced-way
    Local<Value> maybe_trace_config_object =
        GetValue(isolate, context, trace_config_object, kTraceConfigParam);
    if (maybe_trace_config_object->IsObject()) {
      trace_config_object = maybe_trace_config_object.As<Object>();
    }

    UpdateIncludedCategoriesList(isolate, context, trace_config_object,
                                 trace_config);
  }

 private:
  static int UpdateIncludedCategoriesList(
      v8::Isolate* isolate, Local<Context> context, Local<v8::Object> object,
      platform::tracing::TraceConfig* trace_config) {
    Local<Value> value =
        GetValue(isolate, context, object, kIncludedCategoriesParam);
    if (value->IsArray()) {
      Local<Array> v8_array = value.As<Array>();
      for (int i = 0, length = v8_array->Length(); i < length; ++i) {
        Local<Value> v = v8_array->Get(context, i)
                             .ToLocalChecked()
                             ->ToString(context)
                             .ToLocalChecked();
        String::Utf8Value str(isolate, v->ToString(context).ToLocalChecked());
        trace_config->AddIncludedCategory(*str);
      }
      return v8_array->Length();
    }
    return 0;
  }
};

}  // namespace

static platform::tracing::TraceConfig* CreateTraceConfigFromJSON(
    v8::Isolate* isolate, const char* json_str) {
  platform::tracing::TraceConfig* trace_config =
      new platform::tracing::TraceConfig();
  TraceConfigParser::FillTraceConfig(isolate, trace_config, json_str);
  return trace_config;
}

}  // namespace tracing

class ExternalOwningOneByteStringResource
    : public String::ExternalOneByteStringResource {
 public:
  ExternalOwningOneByteStringResource() = default;
  ExternalOwningOneByteStringResource(
      std::unique_ptr<base::OS::MemoryMappedFile> file)
      : file_(std::move(file)) {}
  const char* data() const override {
    return static_cast<char*>(file_->memory());
  }
  size_t length() const override { return file_->size(); }

 private:
  std::unique_ptr<base::OS::MemoryMappedFile> file_;
};

// static variables:
CounterMap* Shell::counter_map_;
base::SharedMutex Shell::counter_mutex_;
base::OS::MemoryMappedFile* Shell::counters_file_ = nullptr;
CounterCollection Shell::local_counters_;
CounterCollection* Shell::counters_ = &local_counters_;
base::LazyMutex Shell::context_mutex_;
const base::TimeTicks Shell::kInitialTicks = base::TimeTicks::Now();
Global<Function> Shell::stringify_function_;
base::Mutex Shell::profiler_end_callback_lock_;
std::map<Isolate*, std::pair<Global<Function>, Global<Context>>>
    Shell::profiler_end_callback_;
base::LazyMutex Shell::workers_mutex_;
bool Shell::allow_new_workers_ = true;

std::unordered_set<std::shared_ptr<Worker>> Shell::running_workers_;
std::atomic<bool> Shell::script_executed_{false};
std::atomic<bool> Shell::valid_fuzz_script_{false};
base::LazyMutex Shell::cached_code_mutex_;
std::map<std::string, std::unique_ptr<ScriptCompiler::CachedData>>
    Shell::cached_code_map_;
std::atomic<int> Shell::unhandled_promise_rejections_{0};

Global<Context> Shell::evaluation_context_;
ArrayBuffer::Allocator* Shell::array_buffer_allocator;
bool check_d8_flag_contradictions = true;
ShellOptions Shell::options;
base::OnceType Shell::quit_once_ = V8_ONCE_INIT;

ScriptCompiler::CachedData* Shell::LookupCodeCache(Isolate* isolate,
                                                   Local<Value> source) {
  i::ParkedMutexGuard lock_guard(
      reinterpret_cast<i::Isolate*>(isolate)->main_thread_local_isolate(),
      cached_code_mutex_.Pointer());
  CHECK(source->IsString());
  v8::String::Utf8Value key(isolate, source);
  DCHECK(*key);
  auto entry = cached_code_map_.find(*key);
  if (entry != cached_code_map_.end() && entry->second) {
    int length = entry->second->length;
    uint8_t* cache = new uint8_t[length];
    memcpy(cache, entry->second->data, length);
    ScriptCompiler::CachedData* cached_data = new ScriptCompiler::CachedData(
        cache, length, ScriptCompiler::CachedData::BufferOwned);
    return cached_data;
  }
  return nullptr;
}

void Shell::StoreInCodeCache(Isolate* isolate, Local<Value> source,
                             const ScriptCompiler::CachedData* cache_data) {
  i::ParkedMutexGuard lock_guard(
      reinterpret_cast<i::Isolate*>(isolate)->main_thread_local_isolate(),
      cached_code_mutex_.Pointer());
  CHECK(source->IsString());
  if (cache_data == nullptr) return;
  v8::String::Utf8Value key(isolate, source);
  DCHECK(*key);
  int length = cache_data->length;
  uint8_t* cache = new uint8_t[length];
  memcpy(cache, cache_data->data, length);
  cached_code_map_[*key] = std::unique_ptr<ScriptCompiler::CachedData>(
      new ScriptCompiler::CachedData(cache, length,
                                     ScriptCompiler::CachedData::BufferOwned));
}

// Dummy external source stream which returns the whole source in one go.
// TODO(leszeks): Also test chunking the data.
class DummySourceStream : public v8::ScriptCompiler::ExternalSourceStream {
 public:
  DummySourceStream(Isolate* isolate, Local<String> source) : done_(false) {
    source_length_ = source->Length();
    source_buffer_ = std::make_unique<uint16_t[]>(source_length_);
    source->WriteV2(isolate, 0, source_length_, source_buffer_.get());
  }

  size_t GetMoreData(const uint8_t** src) override {
    if (done_) {
      return 0;
    }
    *src = reinterpret_cast<uint8_t*>(source_buffer_.release());
    done_ = true;

    return source_length_ * 2;
  }

 private:
  uint32_t source_length_;
  std::unique_ptr<uint16_t[]> source_buffer_;
  bool done_;
};

// Run a ScriptStreamingTask in a separate thread.
class StreamerThread : public v8::base::Thread {
 public:
  static void StartThreadForTaskAndJoin(
      v8::ScriptCompiler::ScriptStreamingTask* task) {
    StreamerThread thread(task);
    CHECK(thread.Start());
    thread.Join();
  }

  explicit StreamerThread(v8::ScriptCompiler::ScriptStreamingTask* task)
      : Thread(Thread::Options()), task_(task) {}

  void Run() override { task_->Run(); }

 private:
  v8::ScriptCompiler::ScriptStreamingTask* task_;
};

namespace {
template <class T>
MaybeLocal<T> CompileStreamed(Local<Context> context,
                              ScriptCompiler::StreamedSource* v8_source,
                              Local<String> full_source_string,
                              const ScriptOrigin& origin) {}

template <>
MaybeLocal<Script> CompileStreamed(Local<Context> context,
                                   ScriptCompiler::StreamedSource* v8_source,
                                   Local<String> full_source_string,
                                   const ScriptOrigin& origin) {
  return ScriptCompiler::Compile(context, v8_source, full_source_string,
                                 origin);
}

template <>
MaybeLocal<Module> CompileStreamed(Local<Context> context,
                                   ScriptCompiler::StreamedSource* v8_source,
                                   Local<String> full_source_string,
                                   const ScriptOrigin& origin) {
  return ScriptCompiler::CompileModule(context, v8_source, full_source_string,
                                       origin);
}

template <class T>
MaybeLocal<T> Compile(Local<Context> context, ScriptCompiler::Source* source,
                      ScriptCompiler::CompileOptions options) {}
template <>
MaybeLocal<Script> Compile(Local<Context> context,
                           ScriptCompiler::Source* source,
                           ScriptCompiler::CompileOptions options) {
  return ScriptCompiler::Compile(context, source, options);
}

template <>
MaybeLocal<Module> Compile(Local<Context> context,
                           ScriptCompiler::Source* source,
                           ScriptCompiler::CompileOptions options) {
  return ScriptCompiler::CompileModule(context->GetIsolate(), source, options);
}

}  // namespace

template <class T>
MaybeLocal<T> Shell::CompileString(Isolate* isolate, Local<Context> context,
                                   Local<String> source,
                                   const ScriptOrigin& origin) {
  if (options.streaming_compile) {
    v8::ScriptCompiler::StreamedSource streamed_source(
        std::make_unique<DummySourceStream>(isolate, source),
        v8::ScriptCompiler::StreamedSource::TWO_BYTE);
    std::unique_ptr<v8::ScriptCompiler::ScriptStreamingTask> streaming_task(
        v8::ScriptCompiler::StartStreaming(isolate, &streamed_source,
                                           std::is_same<T, Module>::value
                                               ? v8::ScriptType::kModule
                                               : v8::ScriptType::kClassic));
    StreamerThread::StartThreadForTaskAndJoin(streaming_task.get());
    return CompileStreamed<T>(context, &streamed_source, source, origin);
  }

  ScriptCompiler::CachedData* cached_code = nullptr;
  if (options.compile_options & ScriptCompiler::kConsumeCodeCache) {
    cached_code = LookupCodeCache(isolate, source);
  }
  ScriptCompiler::Source script_source(source, origin, cached_code);
  MaybeLocal<T> result =
      Compile<T>(context, &script_source,
                 cached_code ? ScriptCompiler::kConsumeCodeCache
                             : ScriptCompiler::kNoCompileOptions);
  if (cached_code) CHECK(!cached_code->rejected);
  return result;
}

namespace {
// For testing.
const int kHostDefinedOptionsLength = 2;
const uint32_t kHostDefinedOptionsMagicConstant = 0xF1F2F3F0;

const char kDataURLPrefix[] = "data:text/javascript,";

std::string ToSTLString(Isolate* isolate, Local<String> v8_str) {
  String::Utf8Value utf8(isolate, v8_str);
  // Should not be able to fail since the input is a String.
  CHECK(*utf8);
  return *utf8;
}

// Per-context Module data, allowing sharing of module maps
// across top-level module loads.
class ModuleEmbedderData {
 private:
  class ModuleGlobalHash {
   public:
    explicit ModuleGlobalHash(Isolate* isolate) : isolate_(isolate) {}
    size_t operator()(const Global<Module>& module) const {
      return module.Get(isolate_)->GetIdentityHash();
    }

   private:
    Isolate* isolate_;
  };

 public:
  static constexpr i::ExternalPointerTag kManagedTag = i::kGenericManagedTag;

  explicit ModuleEmbedderData(Isolate* isolate)
      : isolate_(isolate),
        module_to_specifier_map(10, ModuleGlobalHash(isolate)),
        json_module_to_parsed_json_map(
            10, module_to_specifier_map.hash_function()) {}

  std::string GetModuleSpecifier(Local<Module> module) {
    Global<Module> global_module(isolate_, module);
    auto specifier_it = module_to_specifier_map.find(global_module);
    CHECK(specifier_it != module_to_specifier_map.end());
    return specifier_it->second;
  }

  Local<Module> GetModule(
      std::pair<std::string, ModuleType> module_specifier_and_type) {
    auto module_it = module_map.find(module_specifier_and_type);
    CHECK(module_it != module_map.end());
    return module_it->second.Get(isolate_);
  }

  Local<Object> GetModuleSource(
      std::pair<std::string, ModuleType> module_specifier_and_type) {
    auto module_source_it = module_source_map.find(module_specifier_and_type);
    CHECK(module_source_it != module_source_map.end());
    return module_source_it->second.Get(isolate_);
  }

  Local<Value> GetJsonModuleValue(Local<Module> module) {
    auto json_value_it =
        json_module_to_parsed_json_map.find(Global<Module>(isolate_, module));
    CHECK(json_value_it != json_module_to_parsed_json_map.end());
    return json_value_it->second.Get(isolate_);
  }

  static ModuleType ModuleTypeFromImportSpecifierAndAttributes(
      Local<Context> context, const std::string& specifier,
      Local<FixedArray> import_attributes, bool hasPositions) {
    Isolate* isolate = context->GetIsolate();
    const int kV8AssertionEntrySize = hasPositions ? 3 : 2;
    for (int i = 0; i < import_attributes->Length();
         i += kV8AssertionEntrySize) {
      Local<String> v8_assertion_key =
          import_attributes->Get(context, i).As<v8::String>();
      std::string assertion_key = ToSTLString(isolate, v8_assertion_key);

      if (assertion_key == "type") {
        Local<String> v8_assertion_value =
            import_attributes->Get(context, i + 1).As<String>();
        std::string assertion_value = ToSTLString(isolate, v8_assertion_value);
        if (assertion_value == "json") {
          return ModuleType::kJSON;
        } else {
          // JSON and WebAssembly are currently the only supported non-JS types
          return ModuleType::kInvalid;
        }
      }
    }

    // If no type is asserted, check for the extension. Otherwise default to JS.
    if (specifier.ends_with(".wasm")) {
      return ModuleType::kWebAssembly;
    }
    return ModuleType::kJavaScript;
  }

  Isolate* isolate_;
  // Map from (normalized module specifier, module type) pair to Module.
  std::map<std::pair<std::string, ModuleType>, Global<Module>> module_map;
  // Map from (normalized module specifier, module type) pair to ModuleSource.
  std::map<std::pair<std::string, ModuleType>, Global<Object>>
      module_source_map;
  // Map from Module to its URL as defined in the ScriptOrigin
  std::unordered_map<Global<Module>, std::string, ModuleGlobalHash>
      module_to_specifier_map;
  // Map from JSON Module to its parsed content, for use in module
  // JSONModuleEvaluationSteps
  std::unordered_map<Global<Module>, Global<Value>, ModuleGlobalHash>
      json_module_to_parsed_json_map;

  // Origin location used for resolving modules when referrer is null.
  std::string origin;
};

enum { kModuleEmbedderDataIndex, kInspectorClientIndex };

std::shared_ptr<ModuleEmbedderData> InitializeModuleEmbedderData(
    Local<Context> context) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  const size_t kModuleEmbedderDataEstimate = 4 * 1024;  // module map.
  i::Handle<i::Managed<ModuleEmbedderData>> module_data_managed =
      i::Managed<ModuleEmbedderData>::From(
          i_isolate, kModuleEmbedderDataEstimate,
          std::make_shared<ModuleEmbedderData>(context->GetIsolate()));
  v8::Local<v8::Value> module_data = Utils::ToLocal(module_data_managed);
  context->SetEmbedderData(kModuleEmbedderDataIndex, module_data);
  return module_data_managed->get();
}

std::shared_ptr<ModuleEmbedderData> GetModuleDataFromContext(
    Local<Context> context) {
  v8::Local<v8::Value> module_data =
      context->GetEmbedderData(kModuleEmbedderDataIndex);
  i::DirectHandle<i::Managed<ModuleEmbedderData>> module_data_managed =
      i::Cast<i::Managed<ModuleEmbedderData>>(
          Utils::OpenDirectHandle<Value, i::Object>(module_data));
  return module_data_managed->get();
}

ScriptOrigin CreateScriptOrigin(Isolate* isolate, Local<String> resource_name,
                                v8::ScriptType type) {
  Local<PrimitiveArray> options =
      PrimitiveArray::New(isolate, kHostDefinedOptionsLength);
  options->Set(isolate, 0,
               v8::Uint32::New(isolate, kHostDefinedOptionsMagicConstant));
  options->Set(isolate, 1, resource_name);
  return ScriptOrigin(resource_name, 0, 0, false, -1, Local<Value>(), false,
                      false, type == v8::ScriptType::kModule, options);
}

bool IsValidHostDefinedOptions(Local<Context> context, Local<Data> options,
                               Local<Value> resource_name) {
  if (!options->IsFixedArray()) return false;
  Local<FixedArray> array = options.As<FixedArray>();
  if (array->Length() != kHostDefinedOptionsLength) return false;
  uint32_t magic = 0;
  if (!array->Get(context, 0).As<Value>()->Uint32Value(context).To(&magic)) {
    return false;
  }
  if (magic != kHostDefinedOptionsMagicConstant) return false;
  return array->Get(context, 1).As<String>()->StrictEquals(resource_name);
}

class D8WasmAsyncResolvePromiseTask : public v8::Task {
 public:
  D8WasmAsyncResolvePromiseTask(v8::Isolate* isolate,
                                v8::Local<v8::Context> context,
                                v8::Local<v8::Promise::Resolver> resolver,
                                v8::Local<v8::Value> result,
                                WasmAsyncSuccess success)
      : isolate_(isolate),
        context_(isolate, context),
        resolver_(isolate, resolver),
        result_(isolate, result),
        success_(success) {}

  void Run() override {
    v8::HandleScope scope(isolate_);
    v8::Local<v8::Context> context = context_.Get(isolate_);
    v8::Context::Scope context_scope(context);
    MicrotasksScope microtasks_scope(context,
                                     MicrotasksScope::kDoNotRunMicrotasks);
    v8::Local<v8::Promise::Resolver> resolver = resolver_.Get(isolate_);
    v8::Local<v8::Value> result = result_.Get(isolate_);

    Maybe<bool> ret = success_ == WasmAsyncSuccess::kSuccess
                          ? resolver->Resolve(context, result)
                          : resolver->Reject(context, result);
    // It's guaranteed that no exceptions will be thrown by these
    // operations, but execution might be terminating.
    CHECK(ret.IsJust() ? ret.FromJust() : isolate_->IsExecutionTerminating());
  }

 private:
  v8::Isolate* isolate_;
  v8::Global<v8::Context> context_;
  v8::Global<v8::Promise::Resolver> resolver_;
  v8::Global<v8::Value> result_;
  WasmAsyncSuccess success_;
};

void D8WasmAsyncResolvePromiseCallback(
    v8::Isolate* isolate, v8::Local<v8::Cont
"""


```