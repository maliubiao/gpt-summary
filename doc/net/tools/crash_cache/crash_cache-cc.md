Response:
Let's break down the thought process for analyzing the `crash_cache.cc` file.

1. **Understanding the Purpose:** The initial comments are crucial. They explicitly state the program's goal: "generates the set of files needed for the crash-cache unit tests". This immediately tells us it's a tool for *testing*, not core functionality used during normal browser operation. The mention of "debug mode" reinforces this.

2. **Identifying Key Actions and Concepts:**  Skimming through the code reveals important elements:
    * **`RankCrashes` enum:** This is central. It represents different points where the cache is intentionally crashed. The names like `INSERT_EMPTY_1`, `REMOVE_ONE_1`, etc., hint at the specific scenarios being tested.
    * **Master/Slave processes:** The code uses `base::LaunchProcess`. This indicates a two-part structure: a "master" process that orchestrates the testing and "slave" processes that perform the actual cache operations and crashes.
    * **Cache operations:**  Keywords like `CreateCache`, `CreateEntry`, `OpenEntry`, `Doom`, `FlushQueue` point to the cache's internal workings being manipulated.
    * **File paths:** The code constructs file paths within the `cache_tests/new_crashes` directory. This signifies the test outputs are files representing crashed cache states.
    * **`g_rankings_crash`:** This global variable seems to be the mechanism for triggering the intentional crashes in the slave processes.
    * **Error handling:**  The `Errors` enum and the checks for return codes indicate a focus on verifying successful (or intentionally failing) test runs.

3. **Tracing the Execution Flow:**  Understanding how the program works involves following the `main` function:
    * **Master process (`argc < 2`):**  It iterates through the `RankCrashes` enum, launching a slave process for each crash scenario.
    * **Slave process (`argc >= 2`):** It receives the `RankCrashes` value as a command-line argument. It creates a target directory based on the crash type and then calls `SlaveCode`.
    * **`SlaveCode`:** This is the core of the slave. It creates a cache, performs specific operations (inserting, removing), and crucially, sets `disk_cache::g_rankings_crash` *before* a potentially problematic operation. This is the injection point for the simulated crash.

4. **Connecting to JavaScript (or lack thereof):** The analysis needs to address the prompt's question about JavaScript. Looking at the imports and the code's operations, there's no direct interaction with JavaScript. The focus is entirely on low-level disk cache manipulation. The connection is *indirect*: the network stack (which this code is part of) handles requests initiated by JavaScript, and the disk cache stores resources fetched for those requests. Therefore, this tool tests the *robustness* of the cache when things go wrong, potentially due to issues arising from JavaScript-initiated network activity.

5. **Constructing Examples (Assumptions and Outputs):**  Since the code is about testing, providing examples requires understanding the *intent* of each `RankCrashes` value.
    * **Assumption:**  When `INSERT_EMPTY_1` is passed to the slave, the code intends to crash *during* an empty insert.
    * **Output:**  The resulting file will represent a cache directory with partially written data related to that insert operation.
    * **User Action:**  While users don't directly interact with this tool,  a user browsing a website could trigger network requests that lead to cache operations. A bug in the cache during an insert initiated by such a request *could* lead to the kind of state this tool generates for testing.

6. **Identifying Usage Errors:** The code itself isn't directly used by end-users. The errors would be related to developers running the tool incorrectly:
    * Running without arguments.
    * Providing invalid `RankCrashes` values.
    * Running it when the destination directories already exist.

7. **Debugging Clues:**  Understanding how a real-world crash might lead to a state similar to the generated files is key for debugging:
    * **User action:**  User navigates to a page -> Browser requests resources -> Cache attempts to store them.
    * **Potential issue:**  Disk I/O error, power loss, or a bug in the cache code itself *during* a write operation.
    * **Result:** The cache on disk is left in an inconsistent state, which the recovery mechanisms (tested by this tool's output) need to handle.

8. **Refining the Explanation:**  Organize the findings logically, starting with the core purpose and then delving into specifics. Use clear language and avoid jargon where possible. Explicitly address each part of the prompt (functionality, JavaScript relation, examples, errors, debugging).

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is about crashing the browser."  **Correction:** No, it's about intentionally crashing the *cache* for testing purposes.
* **Initial thought:** "JavaScript directly calls this code." **Correction:** No direct call. The relationship is indirect through network requests and resource caching.
* **Initial thought:** Focus only on the code's execution. **Refinement:**  Need to explain *why* this code exists and how it fits into the larger context of browser development and testing.

By following this detailed breakdown and incorporating corrections, we arrive at a comprehensive and accurate analysis of the `crash_cache.cc` file.
这个 C++ 源代码文件 `crash_cache.cc` 是 Chromium 网络栈中的一个 **测试工具**，专门用于生成各种因模拟崩溃而损坏的磁盘缓存状态。这些生成的缓存状态文件随后被用于单元测试，以验证磁盘缓存的恢复机制是否正常工作。

**功能列举:**

1. **模拟磁盘缓存崩溃:**  该工具通过在特定的操作点设置标志 (`disk_cache::g_rankings_crash`)，然后在这些点上提前终止缓存的操作，从而模拟不同的崩溃场景。
2. **生成不同的崩溃状态:**  它能够模拟发生在缓存操作的不同阶段的崩溃，例如：
    * **插入新条目时崩溃:** 在插入空条目、插入第一个条目、插入多个条目时模拟崩溃。
    * **移除条目时崩溃:**  在移除单个条目、移除头部条目、移除尾部条目时模拟崩溃。
    * **高负载操作时崩溃:** 在缓存负载较高的情况下进行插入和删除操作时模拟崩溃。
3. **生成用于单元测试的文件:**  工具的输出是一系列目录，每个目录代表一种特定的崩溃状态。这些目录中包含着模拟崩溃发生时的缓存文件。
4. **主从进程模型:**  该工具使用主从进程模型。
    * **主进程 (MasterCode):**  负责循环遍历所有定义的崩溃场景，并为每个场景启动一个子进程。
    * **子进程 (SlaveCode):**  接收主进程传递的崩溃类型参数，创建相应的缓存操作，并在指定的操作点模拟崩溃，将崩溃后的缓存状态写入磁盘。
5. **可配置的崩溃点:**  通过 `RankCrashes` 枚举类型定义了各种可能的崩溃点，例如 `INSERT_EMPTY_1` 表示在插入空条目的某个阶段崩溃。
6. **针对特定缓存操作的崩溃模拟:**  它模拟了诸如 `CreateEntry`, `OpenEntry`, `Doom` (删除条目) 等关键缓存操作中的崩溃。

**与 JavaScript 功能的关系:**

这个工具本身 **不直接与 JavaScript 代码交互**。它的作用是在较低的 C++ 层面上模拟磁盘缓存的损坏。然而，它的存在对于保证 Chromium 浏览器（包括执行 JavaScript 代码的环境）的稳定性至关重要。

**举例说明关系:**

1. **用户在网页上发起网络请求:** 当用户在浏览器中访问一个网页，浏览器会使用网络栈来请求网页资源（HTML、CSS、JavaScript、图片等）。
2. **缓存存储:**  网络栈中的磁盘缓存负责存储这些下载的资源，以便下次访问时可以更快地加载，而无需重新下载。
3. **潜在的崩溃场景:**  如果在存储这些资源到磁盘缓存的过程中，例如在写入缓存条目的元数据或数据时，系统发生崩溃（比如断电、操作系统错误等），就会导致缓存数据损坏。
4. **`crash_cache.cc` 的作用:** 这个工具模拟了上述的崩溃场景，生成各种损坏的缓存状态。
5. **单元测试验证恢复能力:**  Chromium 的单元测试会使用这些生成的损坏缓存状态来测试磁盘缓存的恢复逻辑。例如，测试在遇到 `INSERT_EMPTY_1` 类型的崩溃后，缓存能否正确地启动并忽略或修复不完整的条目，避免浏览器崩溃或数据丢失。

**因此，尽管 `crash_cache.cc` 不直接操作 JavaScript，但它保证了当 JavaScript 代码触发网络请求并导致缓存操作时，即使发生意外崩溃，缓存也能自我恢复，从而提高浏览器的稳定性和用户体验。**

**逻辑推理、假设输入与输出:**

**假设输入:**  运行 `crash_cache` 工具，并让其执行 `INSERT_ONE_2` 崩溃场景。

**逻辑推理:**

1. 主进程启动一个子进程，并传递参数 `INSERT_ONE_2`。
2. 子进程的 `SlaveCode` 函数会被调用，参数 `action` 为 `INSERT_ONE_2`。
3. `SlaveCode` 会创建一个新的磁盘缓存目录。
4. `SimpleInsert` 函数会被调用。
5. `SimpleInsert` 首先会创建一个空的缓存。
6. 然后，它会尝试创建一个名为 "the first key" 的缓存条目。
7. 在 `disk_cache::g_rankings_crash = action;` 之后，且在实际完成条目插入操作之前，程序会因为模拟崩溃而终止。

**预期输出:**

在 `net/data/cache_tests/new_crashes/insert_one2` 目录下，会生成包含部分缓存数据的磁盘文件。这些文件可能包含：

* 索引文件 (index)：可能包含了部分关于 "the first key" 的元数据，但可能不完整。
* 数据文件 (data_0, data_1 等)：可能包含了部分与 "the first key" 相关的数据，但也可能不完整。

**涉及用户或编程常见的使用错误:**

1. **运行工具时目标目录已存在:** 如果 `net/data/cache_tests/new_crashes/` 下的某个崩溃场景目录已经存在（例如，之前运行过该场景），工具会报错并退出，因为 `CreateTargetFolder` 会检查目录是否存在。
   ```
   // 如果目录已存在，则返回 false
   if (base::PathExists(*full_path))
     return false;
   ```
   **用户错误:**  忘记清理之前运行生成的测试数据。
   **修复方法:**  在再次运行工具之前，手动删除或清空 `net/data/cache_tests/new_crashes/` 目录。

2. **提供的参数无效:** 如果直接运行 `crash_cache`，或者提供的命令行参数不是有效的 `RankCrashes` 枚举值，程序会报错。
   ```c++
   if (action <= disk_cache::NO_CRASH || action >= disk_cache::MAX_CRASH) {
     printf("Invalid action\n");
     return INVALID_ARGUMENT;
   }
   ```
   **用户错误:**  不熟悉工具的使用方法或提供的参数。
   **修复方法:**  查阅工具的文档或源代码，了解正确的参数取值范围。

**用户操作是如何一步步的到达这里，作为调试线索:**

虽然用户不直接与 `crash_cache.cc` 交互，但理解用户操作如何触发可能导致缓存损坏的情况，有助于理解该工具存在的意义和调试方向。

1. **用户浏览网页:** 用户在 Chrome 浏览器中输入网址或点击链接。
2. **浏览器发起网络请求:** Chrome 的网络栈会根据用户的操作发起 HTTP(S) 请求去获取网页资源。
3. **资源下载与缓存:** 下载的资源（HTML、CSS、JavaScript、图片等）会被存储到磁盘缓存中以加速后续访问。
4. **潜在的崩溃点 (与 `crash_cache.cc` 模拟场景对应):**
   * **下载新资源并尝试创建缓存条目时:**  如果在 `SimpleInsert` 模拟的场景中发生崩溃，意味着在新的资源被下载并尝试写入缓存时，系统发生了异常。
   * **更新或删除缓存条目时:** 如果在 `SimpleRemove` 或 `HeadRemove` 模拟的场景中发生崩溃，意味着在缓存因空间限制或其他原因需要删除旧条目或更新现有条目时，系统发生了异常。
5. **实际崩溃发生:**  由于硬件故障（如磁盘错误）、操作系统问题、电源故障或甚至是 Chromium 自身代码的 bug，可能在缓存操作的关键时刻发生崩溃。
6. **缓存状态不一致:** 崩溃会导致缓存文件写入不完整或元数据丢失，最终导致磁盘缓存处于不一致的状态。

**调试线索:**

当开发者在调试与磁盘缓存相关的崩溃或数据损坏问题时，`crash_cache.cc` 生成的测试数据可以作为非常有价值的调试线索：

* **重现崩溃场景:** 开发者可以使用该工具生成特定类型的损坏缓存，然后在调试环境中使用这些损坏的缓存来重现用户遇到的问题。
* **验证恢复逻辑:** 开发者可以修改磁盘缓存的恢复代码，然后使用 `crash_cache.cc` 生成的各种崩溃状态来测试修改后的恢复逻辑是否能够正确处理这些异常情况。
* **分析崩溃原因:** 通过分析 `crash_cache.cc` 模拟的不同崩溃点，可以帮助开发者定位可能导致实际崩溃的代码区域。例如，如果发现某个特定类型的崩溃状态无法被正确恢复，那么可能需要重点检查与该崩溃类型相关的缓存操作代码。

总而言之，`crash_cache.cc` 是一个幕后英雄，它通过模拟各种缓存崩溃场景，帮助 Chromium 团队确保磁盘缓存的健壮性和可靠性，从而间接地提升了用户的浏览体验。

### 提示词
```
这是目录为net/tools/crash_cache/crash_cache.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2011 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

// This command-line program generates the set of files needed for the crash-
// cache unit tests (DiskCacheTest,CacheBackend_Recover*). This program only
// works properly on debug mode, because the crash functionality is not compiled
// on release builds of the cache.

#include <string>

#include "base/at_exit.h"
#include "base/check.h"
#include "base/command_line.h"
#include "base/files/file_util.h"
#include "base/message_loop/message_pump_type.h"
#include "base/path_service.h"
#include "base/process/kill.h"
#include "base/process/launch.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task/single_thread_task_executor.h"
#include "base/threading/thread.h"
#include "base/time/time.h"
#include "net/base/net_errors.h"
#include "net/base/net_export.h"
#include "net/base/test_completion_callback.h"
#include "net/disk_cache/backend_cleanup_tracker.h"
#include "net/disk_cache/blockfile/backend_impl.h"
#include "net/disk_cache/blockfile/rankings.h"
#include "net/disk_cache/disk_cache.h"
#include "net/disk_cache/disk_cache_test_util.h"

using base::Time;

enum Errors {
  GENERIC = -1,
  ALL_GOOD = 0,
  INVALID_ARGUMENT = 1,
  CRASH_OVERWRITE,
  NOT_REACHED
};

using disk_cache::RankCrashes;

// Starts a new process, to generate the files.
int RunSlave(RankCrashes action) {
  base::FilePath exe;
  base::PathService::Get(base::FILE_EXE, &exe);

  base::CommandLine cmdline(exe);
  cmdline.AppendArg(base::NumberToString(action));

  base::Process process = base::LaunchProcess(cmdline, base::LaunchOptions());
  if (!process.IsValid()) {
    printf("Unable to run test %d\n", action);
    return GENERIC;
  }

  int exit_code;

  if (!process.WaitForExit(&exit_code)) {
    printf("Unable to get return code, test %d\n", action);
    return GENERIC;
  }
  if (ALL_GOOD != exit_code)
    printf("Test %d failed, code %d\n", action, exit_code);

  return exit_code;
}

// Main loop for the master process.
int MasterCode() {
  for (int i = disk_cache::NO_CRASH + 1; i < disk_cache::MAX_CRASH; i++) {
    int ret = RunSlave(static_cast<RankCrashes>(i));
    if (ALL_GOOD != ret)
      return ret;
  }

  return ALL_GOOD;
}

// -----------------------------------------------------------------------

namespace disk_cache {
NET_EXPORT_PRIVATE extern RankCrashes g_rankings_crash;
}

const char kCrashEntryName[] = "the first key";

// Creates the destinaton folder for this run, and returns it on full_path.
bool CreateTargetFolder(const base::FilePath& path, RankCrashes action,
                        base::FilePath* full_path) {
  const char* const folders[] = {
    "",
    "insert_empty1",
    "insert_empty2",
    "insert_empty3",
    "insert_one1",
    "insert_one2",
    "insert_one3",
    "insert_load1",
    "insert_load2",
    "remove_one1",
    "remove_one2",
    "remove_one3",
    "remove_one4",
    "remove_head1",
    "remove_head2",
    "remove_head3",
    "remove_head4",
    "remove_tail1",
    "remove_tail2",
    "remove_tail3",
    "remove_load1",
    "remove_load2",
    "remove_load3"
  };
  static_assert(std::size(folders) == disk_cache::MAX_CRASH, "sync folders");
  DCHECK(action > disk_cache::NO_CRASH && action < disk_cache::MAX_CRASH);

  *full_path = path.AppendASCII(folders[action]);

  if (base::PathExists(*full_path))
    return false;

  return base::CreateDirectory(*full_path);
}

// Makes sure that any pending task is processed.
void FlushQueue(disk_cache::Backend* cache) {
  net::TestCompletionCallback cb;
  int rv =
      reinterpret_cast<disk_cache::BackendImpl*>(cache)->FlushQueueForTest(
          cb.callback());
  cb.GetResult(rv);  // Ignore the result;
}

bool CreateCache(const base::FilePath& path,
                 base::Thread* thread,
                 disk_cache::Backend** cache,
                 net::TestCompletionCallback* cb) {
  int size = 1024 * 1024;
  disk_cache::BackendImpl* backend = new disk_cache::BackendImpl(
      path, /* cleanup_tracker = */ nullptr, thread->task_runner().get(),
      net::DISK_CACHE, /* net_log = */ nullptr);
  backend->SetMaxSize(size);
  backend->SetFlags(disk_cache::kNoRandom);
  backend->Init(cb->callback());
  *cache = backend;
  return (cb->WaitForResult() == net::OK && !(*cache)->GetEntryCount());
}

// Generates the files for an empty and one item cache.
int SimpleInsert(const base::FilePath& path, RankCrashes action,
                 base::Thread* cache_thread) {
  net::TestCompletionCallback cb;
  disk_cache::Backend* cache;
  if (!CreateCache(path, cache_thread, &cache, &cb))
    return GENERIC;

  const char* test_name = "some other key";

  if (action <= disk_cache::INSERT_EMPTY_3) {
    test_name = kCrashEntryName;
    disk_cache::g_rankings_crash = action;
  }

  TestEntryResultCompletionCallback cb_create;
  disk_cache::EntryResult result = cb_create.GetResult(
      cache->CreateEntry(test_name, net::HIGHEST, cb_create.callback()));
  if (result.net_error() != net::OK)
    return GENERIC;

  result.ReleaseEntry()->Close();
  FlushQueue(cache);

  DCHECK(action <= disk_cache::INSERT_ONE_3);
  disk_cache::g_rankings_crash = action;
  test_name = kCrashEntryName;

  result = cb_create.GetResult(
      cache->CreateEntry(test_name, net::HIGHEST, cb_create.callback()));
  if (result.net_error() != net::OK)
    return GENERIC;

  return NOT_REACHED;
}

// Generates the files for a one item cache, and removing the head.
int SimpleRemove(const base::FilePath& path, RankCrashes action,
                 base::Thread* cache_thread) {
  DCHECK(action >= disk_cache::REMOVE_ONE_1);
  DCHECK(action <= disk_cache::REMOVE_TAIL_3);

  net::TestCompletionCallback cb;
  disk_cache::Backend* cache;
  if (!CreateCache(path, cache_thread, &cache, &cb))
    return GENERIC;

  TestEntryResultCompletionCallback cb_create;
  disk_cache::EntryResult result = cb_create.GetResult(
      cache->CreateEntry(kCrashEntryName, net::HIGHEST, cb_create.callback()));
  if (result.net_error() != net::OK)
    return GENERIC;

  result.ReleaseEntry()->Close();
  FlushQueue(cache);

  if (action >= disk_cache::REMOVE_TAIL_1) {
    result = cb_create.GetResult(cache->CreateEntry(
        "some other key", net::HIGHEST, cb_create.callback()));
    if (result.net_error() != net::OK)
      return GENERIC;

    result.ReleaseEntry()->Close();
    FlushQueue(cache);
  }

  result = cb_create.GetResult(
      cache->OpenEntry(kCrashEntryName, net::HIGHEST, cb_create.callback()));
  if (result.net_error() != net::OK)
    return GENERIC;

  disk_cache::g_rankings_crash = action;
  disk_cache::Entry* entry = result.ReleaseEntry();
  entry->Doom();
  entry->Close();
  FlushQueue(cache);

  return NOT_REACHED;
}

int HeadRemove(const base::FilePath& path, RankCrashes action,
               base::Thread* cache_thread) {
  DCHECK(action >= disk_cache::REMOVE_HEAD_1);
  DCHECK(action <= disk_cache::REMOVE_HEAD_4);

  net::TestCompletionCallback cb;
  disk_cache::Backend* cache;
  if (!CreateCache(path, cache_thread, &cache, &cb))
    return GENERIC;

  TestEntryResultCompletionCallback cb_create;
  disk_cache::EntryResult result = cb_create.GetResult(
      cache->CreateEntry("some other key", net::HIGHEST, cb_create.callback()));
  if (result.net_error() != net::OK)
    return GENERIC;

  result.ReleaseEntry()->Close();
  FlushQueue(cache);
  result = cb_create.GetResult(
      cache->CreateEntry(kCrashEntryName, net::HIGHEST, cb_create.callback()));
  if (result.net_error() != net::OK)
    return GENERIC;

  result.ReleaseEntry()->Close();
  FlushQueue(cache);

  result = cb_create.GetResult(
      cache->OpenEntry(kCrashEntryName, net::HIGHEST, cb_create.callback()));
  if (result.net_error() != net::OK)
    return GENERIC;

  disk_cache::g_rankings_crash = action;
  disk_cache::Entry* entry = result.ReleaseEntry();
  entry->Doom();
  entry->Close();
  FlushQueue(cache);

  return NOT_REACHED;
}

// Generates the files for insertion and removals on heavy loaded caches.
int LoadOperations(const base::FilePath& path, RankCrashes action,
                   base::Thread* cache_thread) {
  DCHECK(action >= disk_cache::INSERT_LOAD_1);

  // Work with a tiny index table (16 entries).
  disk_cache::BackendImpl* cache = new disk_cache::BackendImpl(
      path, 0xf, /*cleanup_tracker=*/nullptr, cache_thread->task_runner().get(),
      net::DISK_CACHE, nullptr);
  if (!cache->SetMaxSize(0x100000))
    return GENERIC;

  // No experiments and use a simple LRU.
  cache->SetFlags(disk_cache::kNoRandom);
  net::TestCompletionCallback cb;
  cache->Init(cb.callback());
  if (cb.WaitForResult() != net::OK || cache->GetEntryCount())
    return GENERIC;

  int seed = static_cast<int>(Time::Now().ToInternalValue());
  srand(seed);

  TestEntryResultCompletionCallback cb_create;
  for (int i = 0; i < 100; i++) {
    std::string key = GenerateKey(true);
    disk_cache::EntryResult result = cb_create.GetResult(
        cache->CreateEntry(key, net::HIGHEST, cb_create.callback()));
    if (result.net_error() != net::OK)
      return GENERIC;
    result.ReleaseEntry()->Close();
    FlushQueue(cache);
    if (50 == i && action >= disk_cache::REMOVE_LOAD_1) {
      result = cb_create.GetResult(cache->CreateEntry(
          kCrashEntryName, net::HIGHEST, cb_create.callback()));
      if (result.net_error() != net::OK)
        return GENERIC;
      result.ReleaseEntry()->Close();
      FlushQueue(cache);
    }
  }

  if (action <= disk_cache::INSERT_LOAD_2) {
    disk_cache::g_rankings_crash = action;

    disk_cache::EntryResult result = cb_create.GetResult(cache->CreateEntry(
        kCrashEntryName, net::HIGHEST, cb_create.callback()));
    if (result.net_error() != net::OK)
      return GENERIC;
    result.ReleaseEntry();  // leaks.
  }

  disk_cache::EntryResult result = cb_create.GetResult(
      cache->OpenEntry(kCrashEntryName, net::HIGHEST, cb_create.callback()));
  if (result.net_error() != net::OK)
    return GENERIC;

  disk_cache::g_rankings_crash = action;

  disk_cache::Entry* entry = result.ReleaseEntry();
  entry->Doom();
  entry->Close();
  FlushQueue(cache);

  return NOT_REACHED;
}

// Main function on the child process.
int SlaveCode(const base::FilePath& path, RankCrashes action) {
  base::SingleThreadTaskExecutor io_task_executor(base::MessagePumpType::IO);

  base::FilePath full_path;
  if (!CreateTargetFolder(path, action, &full_path)) {
    printf("Destination folder found, please remove it.\n");
    return CRASH_OVERWRITE;
  }

  base::Thread cache_thread("CacheThread");
  if (!cache_thread.StartWithOptions(
          base::Thread::Options(base::MessagePumpType::IO, 0)))
    return GENERIC;

  if (action <= disk_cache::INSERT_ONE_3)
    return SimpleInsert(full_path, action, &cache_thread);

  if (action <= disk_cache::INSERT_LOAD_2)
    return LoadOperations(full_path, action, &cache_thread);

  if (action <= disk_cache::REMOVE_ONE_4)
    return SimpleRemove(full_path, action, &cache_thread);

  if (action <= disk_cache::REMOVE_HEAD_4)
    return HeadRemove(full_path, action, &cache_thread);

  if (action <= disk_cache::REMOVE_TAIL_3)
    return SimpleRemove(full_path, action, &cache_thread);

  if (action <= disk_cache::REMOVE_LOAD_3)
    return LoadOperations(full_path, action, &cache_thread);

  return NOT_REACHED;
}

// -----------------------------------------------------------------------

int main(int argc, const char* argv[]) {
  // Setup an AtExitManager so Singleton objects will be destructed.
  base::AtExitManager at_exit_manager;

  if (argc < 2)
    return MasterCode();

  char* end;
  RankCrashes action = static_cast<RankCrashes>(strtol(argv[1], &end, 0));
  if (action <= disk_cache::NO_CRASH || action >= disk_cache::MAX_CRASH) {
    printf("Invalid action\n");
    return INVALID_ARGUMENT;
  }

  base::FilePath path;
  base::PathService::Get(base::DIR_SRC_TEST_DATA_ROOT, &path);
  path = path.AppendASCII("net");
  path = path.AppendASCII("data");
  path = path.AppendASCII("cache_tests");
  path = path.AppendASCII("new_crashes");

  return SlaveCode(path, action);
}
```