Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Understanding the Core Goal:**

The initial comments are crucial. The code explicitly states its purpose: "stress-tests the crash recovery of the disk cache."  This immediately tells us it's not a typical application; it's a testing/stressing tool. The parent process launches child processes repeatedly, and the child process has two main tasks: exercising the cache and intentionally crashing itself.

**2. Deconstructing the Parent Process (MasterCode):**

* **`MasterCode()`:** This function is straightforward. It's a loop that calls `RunSlave()` repeatedly. The key observation is that it expects the slave to crash (`kExpectedCrash`). If a slave exits with a *different* code, the master terminates. This highlights the focus on crash *recovery*, not just normal operation.

**3. Analyzing the Child Process (Implicitly in `main` with `argc < 2` check):**

* **Command-line arguments:**  The `if (argc < 2)` check in `main` distinguishes between the master and the slave. The master calls the executable without arguments, and the slaves are launched *with* an argument (the iteration number).
* **`StartCrashThread()` and `CrashCallback()`:** These functions are responsible for the intentional crashing. `StartCrashThread` creates a separate thread, and `CrashCallback` (executed periodically on that thread) has a chance to call `base::Process::TerminateCurrentProcessImmediately()`. This confirms the intentional crashing mechanism.
* **`StressTheCache()`:**  This is the heart of the cache exercising logic in the child process.

**4. Diving into `StressTheCache()`:**

* **Cache Initialization:**  The code creates a `disk_cache::BackendImpl`. Key details: a temporary path, a size limit, and flags like `kNoLoadProtection`.
* **`GenerateStressKey()`:**  This creates random-like keys for cache entries.
* **`EntryWrapper` Class:** This class represents an individual cache entry and the operations performed on it. It's crucial for understanding how the cache is being exercised.
* **`LoopTask()`:**  This is the driver of the cache operations. It randomly picks an entry and performs an action (open, create, read, write, delete). The recursion via `PostTask` ensures continuous activity.
* **Key Operations in `EntryWrapper`:**  Pay close attention to `DoOpen`, `OnOpenDone`, `DoRead`, `OnReadDone`, `DoWrite`, `OnWriteDone`, `DoDelete`, and `OnDeleteDone`. These methods simulate real-world cache interactions.

**5. Identifying Potential Connections to JavaScript (Instruction 2):**

This requires thinking about where a browser's network stack interacts with JavaScript. The disk cache is primarily used for storing web resources. Therefore, JavaScript's interaction is *indirect*.

* **Network Requests:**  JavaScript initiates network requests (e.g., fetching images, scripts, data via `fetch` or `XMLHttpRequest`). The network stack, including the cache, handles these requests behind the scenes.
* **Caching Headers:**  JavaScript can't directly control the disk cache at this level. However, server-sent HTTP headers (like `Cache-Control`, `Expires`) *influence* how the cache behaves, and JavaScript can inspect these headers.
* **Service Workers:**  A more direct link is Service Workers. They can intercept network requests and *programmatically* interact with the browser's cache (though usually a separate Service Worker cache, not the *disk* cache being tested here). This is a slightly advanced connection but worth mentioning.

**6. Constructing Examples (Instruction 3):**

The prompt asks for "logical reasoning" and examples. This means creating scenarios to illustrate how the code works.

* **Master-Slave Interaction:**  The basic flow of the master launching slaves and checking exit codes is a key example.
* **Cache Operations:**  Illustrate the sequence of operations within `EntryWrapper` (open/create, read, write, delete).
* **Crash Scenario:**  Explain how the `CrashCallback` leads to termination.

**7. Identifying User/Programming Errors (Instruction 4):**

Think about how someone might misuse or misunderstand this *testing tool*.

* **Running the Slave Directly:**  This breaks the intended master-slave setup.
* **Incorrect Arguments:**  If the master is modified, providing the wrong iteration number could lead to confusion.
* **Cache Corruption (Intentional):** The tool is designed to *stress* the cache, potentially leading to corruption. This isn't strictly a *user* error but a consequence of the tool's purpose.

**8. Tracing User Actions (Instruction 5):**

This requires thinking about how a user action in a browser eventually leads to the disk cache being used.

* **Basic Navigation:**  Typing a URL and hitting Enter is the simplest example.
* **Resource Loading:**  Browsing a website involves loading many resources (images, CSS, JS), all candidates for caching.
* **Back/Forward Button:**  These actions often rely on the cache.
* **Offline Functionality (Service Workers):**  Although not directly related to *this specific cache*, it's a relevant browser feature that utilizes caching.

**9. Iterative Refinement:**

After the initial analysis, review and refine the answers. Are the explanations clear? Are the examples accurate?  Have all aspects of the prompt been addressed?  For instance, initially, I might not have considered Service Workers as a JavaScript connection, but further reflection would bring that to mind. Similarly, thinking more deeply about the `EntryWrapper`'s states clarifies the cache operation logic.

By following this structured thought process, covering the code's purpose, dissecting its components, and considering the connections to JavaScript, potential errors, and user actions, we can construct a comprehensive and accurate answer to the prompt.
这个C++源代码文件 `stress_cache.cc` 是 Chromium 网络栈中的一个压力测试工具，专门用于测试磁盘缓存的崩溃恢复能力。  它通过模拟意外崩溃来验证磁盘缓存是否能保持数据一致性，并且不会产生关键错误。

下面详细列举其功能以及与其他方面的关系：

**1. 主要功能:**

* **磁盘缓存压力测试:**  核心目标是通过大量的并发读写、创建、删除等操作来对磁盘缓存进行高强度的压力测试。
* **模拟崩溃:**  该工具会启动一个子进程，子进程会持续不断地操作磁盘缓存，并在一个独立的线程中随机地终止自身，模拟应用程序意外崩溃的情况。
* **崩溃恢复验证:** 父进程（主进程）会监控子进程的退出码。如果子进程以预期的崩溃代码退出，父进程会继续启动新的子进程进行测试。如果子进程以非预期的错误退出，则父进程会认为测试失败并退出。
* **多进程/多线程并发:** 使用父子进程架构，子进程内部使用多个线程（一个用于缓存操作，一个用于模拟崩溃），增加了测试的并发性。
* **随机性操作:**  子进程对缓存的操作（例如，创建/打开哪个条目、写入多少数据、是否截断数据、何时关闭或删除条目）都带有一定的随机性，更贴近真实使用场景中不可预测的行为。
* **可配置的参数 (虽然代码中硬编码):**  虽然当前代码中缓存大小、条目数量等参数是硬编码的，但在设计上这些参数可以被调整，以便测试不同配置下的缓存行为。
* **日志和调试支持:** 代码中包含 `printf` 输出，可以用来观察测试进度和状态。此外，当发生非预期崩溃时，会触发调试器 (`base::debug::BreakDebugger()`)，方便开发人员进行调试。

**2. 与 JavaScript 功能的关系 (间接关系):**

`stress_cache.cc` 本身是用 C++ 编写的，直接与 JavaScript 没有代码层面的交互。但是，它测试的是 Chromium 网络栈的核心组件——磁盘缓存。  磁盘缓存在浏览器中扮演着至关重要的角色，它存储着从网络下载的资源（例如，HTML 文件、CSS 样式表、JavaScript 文件、图片等）。

当 JavaScript 代码执行时，如果需要加载一个资源（例如，通过 `<img>` 标签请求图片，或者通过 `<script>` 标签请求 JavaScript 文件，或者通过 `fetch` API 发起网络请求），浏览器会首先检查磁盘缓存中是否存在该资源的副本。

* **加速页面加载:** 如果资源在缓存中命中，浏览器可以直接从缓存中加载，而无需再次发起网络请求，从而显著提升页面加载速度。`stress_cache.cc` 的正常运行保证了在 JavaScript 需要快速加载资源时，缓存能够可靠地提供服务。
* **离线访问支持 (Service Workers):**  虽然 `stress_cache.cc` 主要测试的是 HTTP 缓存，但其稳定性也间接影响了 Service Workers 的可靠性。Service Workers 可以拦截网络请求，并从缓存中提供资源，从而实现离线访问功能。如果磁盘缓存不稳定，Service Workers 的功能也会受到影响，最终影响 JavaScript 应用的离线体验。
* **缓存策略和 JavaScript 的影响:**  虽然 JavaScript 代码本身不能直接操作 HTTP 缓存的实现细节，但服务器返回的 HTTP 缓存头信息（例如 `Cache-Control`, `Expires`）会指导浏览器如何缓存资源。JavaScript 可以通过 `fetch` API 或 `XMLHttpRequest` 对象获取这些头信息，并根据这些信息来决定如何处理缓存的资源。`stress_cache.cc` 的测试确保了浏览器能够正确地解析和遵循这些缓存策略。

**举例说明:**

假设一个网页包含一个大的 JavaScript 文件 `app.js`。

1. **用户第一次访问该网页:**  浏览器会下载 `app.js` 文件，并将其存储到磁盘缓存中（如果服务器返回了合适的缓存头）。
2. **JavaScript 代码执行:**  JavaScript 代码开始执行，它可能会依赖于一些缓存的资源。
3. **用户刷新页面或稍后再次访问:**  浏览器会首先检查磁盘缓存，如果 `app.js` 仍然有效且未过期，浏览器会直接从缓存加载，而不是重新从服务器下载。  `stress_cache.cc` 的测试确保了在这种情况下，即使之前发生过崩溃，缓存中的 `app.js` 文件仍然是完整且可用的，JavaScript 代码可以正常执行。
4. **模拟崩溃场景:** 在 `stress_cache.cc` 的测试中，如果子进程在写入 `app.js` 的缓存条目时突然崩溃，父进程会验证在崩溃恢复后，缓存系统是否能够正确处理这种情况，例如，避免数据损坏，或者在必要时重新下载资源。这保证了即使浏览器发生意外崩溃，下次启动时 JavaScript 代码的加载和执行仍然是可靠的。

**3. 逻辑推理和假设输入与输出:**

由于该程序是一个压力测试工具，其核心逻辑在于循环执行子进程并检查其退出状态。

**假设输入:**  无特定的用户输入。该工具通过命令行启动。对于子进程，主要的“输入”是父进程传递的迭代次数。

**假设输出:**

* **正常运行 (无错误):** 父进程会持续循环启动子进程，每个子进程会进行大量的缓存操作并最终以预期的崩溃代码退出。父进程会打印类似 "Iteration 0, initial entries: ..." 的信息，并最终可能输出 "More than enough..." 表示测试通过。
* **发现非预期崩溃:** 如果某个子进程以非预期的退出码退出，父进程会立即打印该退出码并退出自身，表明测试发现了潜在的缓存恢复问题。
* **调试信息:** 如果在子进程中设置了断点或者发生了断言失败，会触发调试器 (`base::debug::BreakDebugger()`)。
* **日志信息:**  子进程会周期性地打印 "Entries: 数字" 来显示缓存操作的进度。

**例如:**

* **假设输入 (命令行):** 运行 `stress_cache` 可执行文件时不带参数会启动父进程。运行 `stress_cache 0` (或其他数字) 会启动一个子进程。
* **假设输出 (正常情况):**
  ```
  Iteration 0, initial entries: 0
  Entries: 100
  Entries: 200
  ...
  sweet death...
  Iteration 1, initial entries: 123
  Entries: 100
  Entries: 200
  ...
  sweet death...
  More than enough...
  ```
* **假设输出 (发现非预期崩溃):**
  ```
  Iteration 5, initial entries: 456
  Entries: 100
  Entries: 200
  ...
  Unexpected exit code: -1073741819
  ```

**4. 涉及用户或编程常见的使用错误:**

* **直接运行子进程:**  用户可能会错误地直接运行 `stress_cache` 命令并带上数字参数（期望运行主进程）。实际上，不带参数运行才会启动主进程，带参数运行的是子进程，子进程的生命周期和行为由主进程控制。
* **误解退出码:** 用户可能不理解预期的退出码 `kExpectedCrash` 的含义，并认为任何非 0 的退出码都是错误。该工具的逻辑是专门设计为子进程主动崩溃的。
* **干扰测试环境:** 如果用户在测试运行时对磁盘缓存目录进行手动操作（例如，删除文件），可能会干扰测试结果，导致非预期的错误。
* **编译配置不当:**  如果编译时没有启用合适的标志（例如，用于崩溃处理的标志），测试可能无法按预期工作。
* **资源限制:**  如果运行测试的系统资源（例如，磁盘空间、内存）不足，可能会导致测试失败，但这并非工具本身的问题。

**5. 用户操作如何一步步的到达这里，作为调试线索:**

通常用户不会直接“到达” `stress_cache.cc` 的代码层面。 这个文件是一个开发和测试工具，不是用户直接交互的浏览器功能。  但是，可以从用户的角度推断出可能导致该工具被运行的情况：

1. **Chromium 开发人员进行网络栈的开发或调试:**  开发人员在修改或优化 Chromium 的网络栈（特别是磁盘缓存部分）时，会使用 `stress_cache.cc` 这样的工具来验证其代码的稳定性和崩溃恢复能力。
2. **进行性能测试或压力测试:**  为了评估 Chromium 在高负载情况下的表现，开发人员可能会运行 `stress_cache.cc` 来模拟大量的缓存操作，观察系统的行为。
3. **排查与磁盘缓存相关的 Bug:** 当用户报告了与缓存相关的 Bug（例如，页面加载异常、资源丢失等）时，开发人员可能会使用 `stress_cache.cc` 来重现或模拟这些场景，以帮助定位问题。
4. **自动化测试框架:**  `stress_cache.cc` 很可能被集成到 Chromium 的自动化测试框架中，作为持续集成的一部分，定期运行以确保代码的质量。

**调试线索:**

如果一个开发人员需要调试 `stress_cache.cc` 或者其测试的磁盘缓存功能，可能的调试步骤包括：

* **设置断点:** 在 `stress_cache.cc` 的关键位置（例如，缓存操作函数、崩溃处理函数）设置断点，以便观察程序运行时的状态。
* **查看日志输出:**  分析 `printf` 输出的日志信息，了解父子进程的运行状态、缓存操作的进度等。
* **分析崩溃转储 (Crash Dump):** 如果发生了非预期的崩溃，分析生成的崩溃转储文件可以提供更详细的错误信息和调用堆栈，帮助定位问题根源。
* **使用 Valgrind 或其他内存检测工具:**  检查是否存在内存泄漏或其他的内存相关错误。
* **单步调试:**  使用调试器逐行执行代码，特别是当出现问题难以定位时。
* **修改代码并重新编译:**  为了验证某些假设或修复 Bug，开发人员可能会修改 `stress_cache.cc` 或相关的磁盘缓存代码，然后重新编译并运行测试。
* **检查磁盘缓存内容:**  在测试运行过程中或结束后，检查磁盘缓存目录中的文件，查看缓存条目的状态和数据是否符合预期。

总而言之，`stress_cache.cc` 是一个专注于磁盘缓存崩溃恢复的内部测试工具，它通过模拟真实世界中可能发生的崩溃场景来保障 Chromium 网络栈的稳定性和可靠性，最终提升用户浏览网页的体验。它与 JavaScript 功能的关系是间接的，通过确保底层缓存的稳定运行，来保障 JavaScript 代码能够可靠地加载和使用缓存的资源。

### 提示词
```
这是目录为net/tools/stress_cache/stress_cache.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

// This is a simple application that stress-tests the crash recovery of the disk
// cache. The main application starts a copy of itself on a loop, checking the
// exit code of the child process. When the child dies in an unexpected way,
// the main application quits.

// The child application has two threads: one to exercise the cache in an
// infinite loop, and another one to asynchronously kill the process.

// A regular build should never crash.
// To test that the disk cache doesn't generate critical errors with regular
// application level crashes, edit stress_support.h.

#include <string>
#include <string_view>
#include <vector>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/debug/debugger.h"
#include "base/files/file_path.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/message_loop/message_pump_type.h"
#include "base/path_service.h"
#include "base/process/launch.h"
#include "base/process/process.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task/single_thread_task_executor.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/disk_cache/backend_cleanup_tracker.h"
#include "net/disk_cache/blockfile/backend_impl.h"
#include "net/disk_cache/blockfile/stress_support.h"
#include "net/disk_cache/disk_cache.h"
#include "net/disk_cache/disk_cache_test_util.h"

#if BUILDFLAG(IS_WIN)
#include "base/logging_win.h"
#endif

using base::Time;

const int kError = -1;
const int kExpectedCrash = 100;

// Starts a new process.
int RunSlave(int iteration) {
  base::FilePath exe;
  base::PathService::Get(base::FILE_EXE, &exe);

  base::CommandLine cmdline(exe);
  cmdline.AppendArg(base::NumberToString(iteration));

  base::Process process = base::LaunchProcess(cmdline, base::LaunchOptions());
  if (!process.IsValid()) {
    printf("Unable to run test\n");
    return kError;
  }

  int exit_code;
  if (!process.WaitForExit(&exit_code)) {
    printf("Unable to get return code\n");
    return kError;
  }
  return exit_code;
}

// Main loop for the master process.
int MasterCode() {
  for (int i = 0; i < 100000; i++) {
    int ret = RunSlave(i);
    if (kExpectedCrash != ret)
      return ret;
  }

  printf("More than enough...\n");

  return 0;
}

// -----------------------------------------------------------------------

std::string GenerateStressKey() {
  char key[20 * 1024];
  size_t size = 50 + rand() % 20000;
  CacheTestFillBuffer(key, size, true);

  key[size - 1] = '\0';
  return std::string(key);
}

// kNumKeys is meant to be enough to have about 3x or 4x iterations before
// the process crashes.
#ifdef NDEBUG
const int kNumKeys = 4000;
#else
const int kNumKeys = 1200;
#endif
const int kNumEntries = 30;
const int kBufferSize = 2000;
const int kReadSize = 20;

// Things that an entry can be doing.
enum Operation { NONE, OPEN, CREATE, READ, WRITE, DOOM };

// This class encapsulates a cache entry and the operations performed on that
// entry. An entry is opened or created as needed, the current content is then
// verified and then something is written to the entry. At that point, the
// |state_| becomes NONE again, waiting for another write, unless the entry is
// closed or deleted.
class EntryWrapper {
 public:
  EntryWrapper() {
    buffer_ = base::MakeRefCounted<net::IOBufferWithSize>(kBufferSize);
    memset(buffer_->data(), 'k', kBufferSize);
  }

  Operation state() const { return state_; }

  void DoOpen(int key);

 private:
  void OnOpenDone(int key, disk_cache::EntryResult result);
  void DoRead();
  void OnReadDone(int result);
  void DoWrite();
  void OnWriteDone(int size, int result);
  void DoDelete(const std::string& key);
  void OnDeleteDone(int result);
  void DoIdle();

  disk_cache::Entry* entry_ = nullptr;
  Operation state_ = NONE;
  scoped_refptr<net::IOBuffer> buffer_;
};

// The data that the main thread is working on.
struct Data {
  Data() = default;

  int pendig_operations = 0;  // Counter of simultaneous operations.
  int writes = 0;             // How many writes since this iteration started.
  int iteration = 0;          // The iteration (number of crashes).
  disk_cache::BackendImpl* cache = nullptr;
  std::string keys[kNumKeys];
  EntryWrapper entries[kNumEntries];
};

Data* g_data = nullptr;

void EntryWrapper::DoOpen(int key) {
  DCHECK_EQ(state_, NONE);
  if (entry_)
    return DoRead();

  state_ = OPEN;
  disk_cache::EntryResult result = g_data->cache->OpenEntry(
      g_data->keys[key], net::HIGHEST,
      base::BindOnce(&EntryWrapper::OnOpenDone, base::Unretained(this), key));
  if (result.net_error() != net::ERR_IO_PENDING)
    OnOpenDone(key, std::move(result));
}

void EntryWrapper::OnOpenDone(int key, disk_cache::EntryResult result) {
  if (result.net_error() == net::OK) {
    entry_ = result.ReleaseEntry();
    return DoRead();
  }

  CHECK_EQ(state_, OPEN);
  state_ = CREATE;
  result = g_data->cache->CreateEntry(
      g_data->keys[key], net::HIGHEST,
      base::BindOnce(&EntryWrapper::OnOpenDone, base::Unretained(this), key));
  if (result.net_error() != net::ERR_IO_PENDING)
    OnOpenDone(key, std::move(result));
}

void EntryWrapper::DoRead() {
  int current_size = entry_->GetDataSize(0);
  if (!current_size)
    return DoWrite();

  state_ = READ;
  memset(buffer_->data(), 'k', kReadSize);
  int rv = entry_->ReadData(
      0, 0, buffer_.get(), kReadSize,
      base::BindOnce(&EntryWrapper::OnReadDone, base::Unretained(this)));
  if (rv != net::ERR_IO_PENDING)
    OnReadDone(rv);
}

void EntryWrapper::OnReadDone(int result) {
  DCHECK_EQ(state_, READ);
  CHECK_EQ(result, kReadSize);
  CHECK_EQ(0, memcmp(buffer_->data(), "Write: ", 7));
  DoWrite();
}

void EntryWrapper::DoWrite() {
  bool truncate = (rand() % 2 == 0);
  int size = kBufferSize - (rand() % 20) * kBufferSize / 20;
  state_ = WRITE;
  base::snprintf(buffer_->data(), kBufferSize,
                 "Write: %d iter: %d, size: %d, truncate: %d     ",
                 g_data->writes, g_data->iteration, size, truncate ? 1 : 0);
  int rv = entry_->WriteData(
      0, 0, buffer_.get(), size,
      base::BindOnce(&EntryWrapper::OnWriteDone, base::Unretained(this), size),
      truncate);
  if (rv != net::ERR_IO_PENDING)
    OnWriteDone(size, rv);
}

void EntryWrapper::OnWriteDone(int size, int result) {
  DCHECK_EQ(state_, WRITE);
  CHECK_EQ(size, result);
  if (!(g_data->writes++ % 100))
    printf("Entries: %d    \r", g_data->writes);

  int random = rand() % 100;
  std::string key = entry_->GetKey();
  if (random > 90)
    return DoDelete(key);  // 10% delete then close.

  if (random > 60) {  // 20% close.
    entry_->Close();
    entry_ = nullptr;
  }

  if (random > 80)
    return DoDelete(key);  // 10% close then delete.

  DoIdle();  // 60% do another write later.
}

void EntryWrapper::DoDelete(const std::string& key) {
  state_ = DOOM;
  int rv = g_data->cache->DoomEntry(
      key, net::HIGHEST,
      base::BindOnce(&EntryWrapper::OnDeleteDone, base::Unretained(this)));
  if (rv != net::ERR_IO_PENDING)
    OnDeleteDone(rv);
}

void EntryWrapper::OnDeleteDone(int result) {
  DCHECK_EQ(state_, DOOM);
  if (entry_) {
    entry_->Close();
    entry_ = nullptr;
  }
  DoIdle();
}

void LoopTask();

void EntryWrapper::DoIdle() {
  state_ = NONE;
  g_data->pendig_operations--;
  DCHECK(g_data->pendig_operations);
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&LoopTask));
}

// The task that keeps the main thread busy. Whenever an entry becomes idle this
// task is executed again.
void LoopTask() {
  if (g_data->pendig_operations >= kNumEntries)
    return;

  int slot = rand() % kNumEntries;
  if (g_data->entries[slot].state() == NONE) {
    // Each slot will have some keys assigned to it so that the same entry will
    // not be open by two slots, which means that the state is well known at
    // all times.
    int keys_per_entry = kNumKeys / kNumEntries;
    int key = rand() % keys_per_entry + keys_per_entry * slot;
    g_data->pendig_operations++;
    g_data->entries[slot].DoOpen(key);
  }

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&LoopTask));
}

// This thread will loop forever, adding and removing entries from the cache.
// iteration is the current crash cycle, so the entries on the cache are marked
// to know which instance of the application wrote them.
void StressTheCache(int iteration) {
  int cache_size = 0x2000000;  // 32MB.
  uint32_t mask = 0xfff;       // 4096 entries.

  base::FilePath path;
  base::PathService::Get(base::DIR_TEMP, &path);
  path = path.AppendASCII("cache_test_stress");

  base::Thread cache_thread("CacheThread");
  if (!cache_thread.StartWithOptions(
          base::Thread::Options(base::MessagePumpType::IO, 0)))
    return;

  g_data = new Data();
  g_data->iteration = iteration;
  g_data->cache = new disk_cache::BackendImpl(
      path, mask, /*cleanup_tracker=*/nullptr, cache_thread.task_runner().get(),
      net::DISK_CACHE, nullptr);
  g_data->cache->SetMaxSize(cache_size);
  g_data->cache->SetFlags(disk_cache::kNoLoadProtection);

  net::TestCompletionCallback cb;
  g_data->cache->Init(cb.callback());

  if (cb.WaitForResult() != net::OK) {
    printf("Unable to initialize cache.\n");
    return;
  }
  printf("Iteration %d, initial entries: %d\n", iteration,
         g_data->cache->GetEntryCount());

  int seed = static_cast<int>(Time::Now().ToInternalValue());
  srand(seed);

  for (auto& key : g_data->keys)
    key = GenerateStressKey();

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&LoopTask));
  base::RunLoop().Run();
}

// We want to prevent the timer thread from killing the process while we are
// waiting for the debugger to attach.
bool g_crashing = false;

// RunSoon() and CrashCallback() reference each other, unfortunately.
void RunSoon(scoped_refptr<base::SingleThreadTaskRunner> task_runner);

void CrashCallback() {
  // Keep trying to run.
  RunSoon(base::SingleThreadTaskRunner::GetCurrentDefault());

  if (g_crashing)
    return;

  if (rand() % 100 > 30) {
    printf("sweet death...\n");

    // Terminate the current process without doing normal process-exit cleanup.
    base::Process::TerminateCurrentProcessImmediately(kExpectedCrash);
  }
}

void RunSoon(scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  const base::TimeDelta kTaskDelay = base::Seconds(10);
  task_runner->PostDelayedTask(FROM_HERE, base::BindOnce(&CrashCallback),
                               kTaskDelay);
}

// We leak everything here :)
bool StartCrashThread() {
  base::Thread* thread = new base::Thread("party_crasher");
  if (!thread->Start())
    return false;

  RunSoon(thread->task_runner());
  return true;
}

void CrashHandler(const char* file,
                  int line,
                  std::string_view str,
                  std::string_view stack_trace) {
  g_crashing = true;
  base::debug::BreakDebugger();
}

// -----------------------------------------------------------------------

#if BUILDFLAG(IS_WIN)
// {B9A153D4-31C3-48e4-9ABF-D54383F14A0D}
const GUID kStressCacheTraceProviderName = {
    0xb9a153d4, 0x31c3, 0x48e4,
        { 0x9a, 0xbf, 0xd5, 0x43, 0x83, 0xf1, 0x4a, 0xd } };
#endif

int main(int argc, const char* argv[]) {
  // Setup an AtExitManager so Singleton objects will be destructed.
  base::AtExitManager at_exit_manager;

  if (argc < 2)
    return MasterCode();

  logging::ScopedLogAssertHandler scoped_assert_handler(
      base::BindRepeating(CrashHandler));

#if BUILDFLAG(IS_WIN)
  logging::LogEventProvider::Initialize(kStressCacheTraceProviderName);
#else
  base::CommandLine::Init(argc, argv);
  logging::LoggingSettings settings;
  settings.logging_dest =
      logging::LOG_TO_SYSTEM_DEBUG_LOG | logging::LOG_TO_STDERR;
  logging::InitLogging(settings);
#endif

  // Some time for the memory manager to flush stuff.
  base::PlatformThread::Sleep(base::Seconds(3));
  base::SingleThreadTaskExecutor io_task_executor(base::MessagePumpType::IO);

  char* end;
  long int iteration = strtol(argv[1], &end, 0);

  if (!StartCrashThread()) {
    printf("failed to start thread\n");
    return kError;
  }

  StressTheCache(iteration);
  return 0;
}
```