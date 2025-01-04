Response:
Let's break down the thought process for analyzing this C++ performance test file.

1. **Understand the Goal:** The file name `disk_cache_perftest.cc` immediately suggests its purpose: performance testing of the Chromium disk cache. The `_perftest` suffix is a common convention for performance test files.

2. **Identify Key Components (by scanning includes and namespaces):**

   * **Core Libraries:**  The includes like `<limits>`, `<memory>`, `<string>`, etc., are standard C++ libraries. `base/` headers indicate the use of Chromium's base library (threading, files, strings, etc.).
   * **Networking:**  Includes like `net/base/cache_type.h`, `net/base/completion_repeating_callback.h`, `net/base/io_buffer.h`, `net/base/net_errors.h` clearly point to networking functionalities.
   * **Disk Cache Specifics:** The `net/disk_cache/` headers are crucial. They reveal the different implementations being tested: `blockfile/` and `simple/`. This suggests the test covers both older and newer disk cache architectures.
   * **Testing Frameworks:** `testing/gtest/include/gtest/gtest.h` and `testing/perf/perf_result_reporter.h` confirm this is a Google Test-based performance test that reports metrics.
   * **Build Configuration:** `#ifdef UNSAFE_BUFFERS_BUILD` and `build/build_config.h` are for platform-specific configurations.

3. **Infer Functionality (by examining the code structure and key variables):**

   * **Test Setup:** The `DiskCachePerfTest` class inherits from `DiskCacheTestWithCache`, indicating a setup that creates and manages a test cache environment. The `SetUpDiskCacheReporter` and `SetUpSimpleIndexReporter` functions register performance metrics.
   * **Workload Generation:** The `TestEntry` struct and the `entries_` vector suggest the test involves creating and manipulating cache entries with keys and data. The `GenerateKey` function (from `disk_cache_test_util.h`) is likely used to create unique cache keys. The `kNumEntries`, `kHeadersSize`, and `kBodySize` constants define the scale of the test.
   * **Write Performance:** The `TimeWrites` function seems to measure the time taken to write a large number of cache entries. The `WriteHandler` class manages the asynchronous write operations, using `CreateEntry` and `WriteData`. The use of `kMaxParallelOperations` implies testing with concurrent writes.
   * **Read Performance:** The `TimeReads` function measures read performance, with the `WhatToRead` enum controlling whether to read only headers or the entire entry. The `ReadHandler` manages asynchronous reads using `OpenEntry` and `ReadData`.
   * **Specific Benchmarks:**  The individual `TEST_F` macros define different performance benchmarks:
      * `BlockfileHashes`: Measures the time to hash cache keys.
      * `BlockFilesPerformance`:  Tests the performance of block file operations (creation and deletion).
      * `SimpleCacheInitialReadPortion`: Attempts to isolate the initial read overhead in the simple cache.
      * `EvictionPerformance` (in `SimpleIndexPerfTest`):  Measures the time taken by the `SimpleIndex` to select entries for eviction.
   * **System Cache Impact:** The `ResetAndEvictSystemDiskCache` function highlights the awareness of system-level caching and the need to mitigate its effects during benchmarking.

4. **Analyze Potential JavaScript Relevance:**

   * **Indirect Relationship:** Disk cache is fundamental to web browsing. JavaScript running in a browser will trigger network requests. The disk cache stores responses to these requests. Therefore, the performance of the disk cache directly impacts the perceived performance of JavaScript-heavy web applications. *Crucially, the C++ code itself doesn't *directly* interact with JavaScript.*
   * **Example Scenario:** A JavaScript application might fetch many resources (images, scripts, stylesheets). If the disk cache is slow, these resources will take longer to load from the cache, slowing down the application.

5. **Infer Logic and Provide Input/Output Examples:**

   * **`TimeWrites`:**
      * **Input (Implicit):**  Cache backend in a clean state.
      * **Output (Performance Metric):** The time taken to write `kNumEntries` entries to the cache.
   * **`TimeReads`:**
      * **Input (Implicit):**  Cache populated with entries. `what_to_read` specifies headers only or full entry.
      * **Output (Performance Metric):** The time taken to read the specified data from `kNumEntries`.
   * **`BlockFilesPerformance`:**
      * **Input (Implicit):** Initialized block files.
      * **Output (Performance Metrics):** Time to fill blocks sequentially and time to create and delete blocks randomly.
   * **`SimpleCacheInitialReadPortion`:**
      * **Input (Implicit):** Cache with pre-written entries.
      * **Output (Performance Metrics):** Time spent in the initial read portion and the event loop portion.
   * **`EvictionPerformance`:**
      * **Input (Implicit):**  A `SimpleIndex` with a certain number of entries and a target size reduction.
      * **Output (Performance Metric):** The average time taken to evict entries.

6. **Identify Common Usage Errors (from a developer's perspective):**

   * **Incorrect Cache Initialization:**  Forgetting to initialize the cache (`InitCache()`) or setting an insufficient maximum size.
   * **Incorrect Key Generation:** Using non-unique keys would lead to overwriting entries instead of creating new ones, skewing write performance.
   * **Buffer Management Issues:**  Incorrect buffer sizes or not handling buffer allocation/deallocation correctly in real-world usage could lead to crashes or unexpected behavior. This isn't directly tested here but is a general concern when using `IOBuffer`.
   * **Asynchronous Operation Handling:**  Failing to handle the asynchronous nature of cache operations (using callbacks correctly) can lead to data corruption or race conditions. The test demonstrates proper use of callbacks.

7. **Trace User Operations (Debugging Perspective):**

   * **Basic Web Browsing:** A user navigates to a website. The browser fetches resources (HTML, CSS, JavaScript, images). The network stack checks the disk cache for these resources. If found, the cached version is used. This directly involves the read paths tested in `TimeReads`.
   * **Cache Invalidation/Updates:** A user revisits a website, or the website indicates that resources have changed. The browser might need to fetch updated resources and write them to the cache, potentially evicting older entries. This touches upon the write paths in `TimeWrites` and the eviction logic tested in `EvictionPerformance`.
   * **Developer Tools:** A developer might clear the browser cache through developer tools. This would trigger the cache deletion mechanisms, indirectly related to the block file operations tested in `BlockFilesPerformance`.
   * **Programmatic Cache Usage (Less Common in typical user scenarios):**  Extensions or embedded applications might directly interact with the Chromium network stack and its cache, although this is less common for typical end-users.

8. **Refine and Organize:** Finally, organize the gathered information into clear sections, using headings and bullet points for readability, as demonstrated in the desired answer format. Emphasize the core functionality, JavaScript relevance (and its indirect nature), provide concrete examples, and address potential errors and debugging steps.
这个文件 `net/disk_cache/disk_cache_perftest.cc` 是 Chromium 网络栈中用于 **性能测试** 的源代码文件，它专门用来衡量磁盘缓存的读写性能以及一些内部操作的效率。

**它的主要功能包括:**

1. **模拟缓存写入操作:**  测试向磁盘缓存写入大量条目的性能，包括创建条目、写入头部和主体数据等。
2. **模拟缓存读取操作:** 测试从磁盘缓存中读取条目的性能，可以分别测试只读取头部和读取完整条目的性能。
3. **测试冷启动和热启动性能:** 通过在读取前清除系统缓存，模拟冷启动场景，测试从磁盘读取的初始性能；在不清除系统缓存的情况下进行读取，模拟热启动场景，测试从系统缓存读取的性能。
4. **测试缓存内部操作:** 例如，测试计算缓存键哈希值的性能，以及块文件（blockfile）的创建、删除等操作的性能。
5. **针对不同的缓存后端进行测试:** 该文件可以用于测试 `blockfile` 类型的缓存后端以及 `simple` 类型的缓存后端。
6. **收集性能指标:** 使用 Chromium 的 `perf_test::PerfResultReporter` 框架来记录测试结果，例如写入时间、冷热启动读取时间等。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的磁盘缓存是 Web 浏览器中至关重要的组成部分，**直接影响 JavaScript 应用的性能**。

* **加速资源加载:** 当 JavaScript 应用需要加载图片、脚本、样式表等资源时，浏览器会首先检查磁盘缓存。如果资源存在于缓存中，浏览器可以直接从磁盘加载，而无需重新从网络下载，从而显著提高加载速度。这个文件的测试正是为了确保这种加载过程足够快速。
* **Service Worker Cache API:**  Service Workers 允许 JavaScript 代码拦截网络请求并自定义响应。Service Worker 可以使用 Cache API 将资源存储在浏览器控制的缓存中。虽然 Service Worker 的 Cache API 有自己的实现，但理解底层磁盘缓存的性能对于优化 Service Worker 的资源加载仍然很重要。这个文件测试的底层磁盘缓存性能，也会影响到 Service Worker Cache API 的效率。

**举例说明 JavaScript 的关系:**

假设一个 JavaScript 应用需要加载一个大的图片文件 `image.jpg`。

1. **首次加载 (缓存未命中):**
   - JavaScript 代码执行 `fetch('image.jpg')` 发起网络请求。
   - 浏览器向服务器请求 `image.jpg`。
   - 服务器返回图片数据。
   - **磁盘缓存模块（这个文件测试的对象）** 将图片数据写入磁盘缓存。
   - JavaScript 代码接收到图片数据并显示。
2. **再次加载 (缓存命中):**
   - JavaScript 代码再次执行 `fetch('image.jpg')`。
   - 浏览器检查磁盘缓存，发现 `image.jpg` 存在。
   - **磁盘缓存模块** 从磁盘读取图片数据。
   - JavaScript 代码接收到图片数据并显示，这次加载速度会明显快于第一次，因为避免了网络请求。

这个 `disk_cache_perftest.cc` 的测试目标就是确保在第二步中，从磁盘缓存读取 `image.jpg` 的速度足够快，从而提升用户体验。

**逻辑推理 (假设输入与输出):**

假设我们运行了 `TimeWrites` 测试，其目的是测试写入缓存的性能。

* **假设输入:**
    * 缓存目录为空或包含一些旧的缓存数据。
    * `kNumEntries` 设置为 10000，表示要写入 10000 个缓存条目。
    * 每个条目的头部大小固定为 `kHeadersSize` (2000 字节)。
    * 每个条目的主体大小在 0 到 `kBodySize` (72 * 1024 - 1 字节) 之间随机。
* **预期输出:**
    * 测试报告会输出 `DiskCache.cache_entries_write_time` 指标，单位为毫秒 (ms)。这个值代表写入这 10000 个缓存条目所花费的总时间。例如，可能输出 `DiskCache.cache_entries_write_time: 1500 ms on blockfile_cache`。

假设我们运行了 `TimeReads` 测试，测试读取缓存的性能 (冷启动，只读头部)。

* **假设输入:**
    * 缓存目录中已经存在之前 `TimeWrites` 测试写入的 10000 个缓存条目。
    * 在读取之前，执行了 `ResetAndEvictSystemDiskCache()`，清除了系统缓存。
    * 测试模式设置为 `WhatToRead::HEADERS_ONLY`，表示只读取缓存条目的头部。
* **预期输出:**
    * 测试报告会输出 `DiskCache.cache_headers_read_time_cold` 指标，单位为毫秒 (ms)。这个值代表在冷启动情况下读取这 10000 个缓存条目头部所花费的总时间。例如，可能输出 `DiskCache.cache_headers_read_time_cold: 800 ms on blockfile_cache`。

**用户或编程常见的使用错误:**

这个文件是性能测试代码，用户不会直接操作它。但是，**使用 Chromium 磁盘缓存的开发者**可能会遇到以下常见错误，而这些错误会影响到这里测试的性能指标：

1. **缓存大小设置不当:**
   * **错误示例:** 将缓存最大大小设置得过小，导致频繁的缓存淘汰，降低缓存命中率，从而使得此处测试的读取性能下降。
   * **如何到达这里 (调试线索):**  用户抱怨网页加载速度慢，特别是重复访问时仍然很慢。开发者通过调试发现缓存命中率很低，进一步检查发现缓存大小配置不合理。
2. **缓存键生成不合理:**
   * **错误示例:** 使用动态生成但经常变化的 URL 作为缓存键，导致每次请求都被视为新的请求，无法利用缓存。
   * **如何到达这里 (调试线索):**  开发者观察到尽管资源内容没有变化，但每次请求都会重新下载。检查网络请求头和缓存策略后，发现缓存键的生成方式有问题。
3. **缓存策略配置错误:**
   * **错误示例:**  服务端返回的 HTTP 响应头中缺少或设置了错误的缓存控制指令（如 `Cache-Control`, `Expires`），导致浏览器无法正确缓存资源。
   * **如何到达这里 (调试线索):**  用户反馈某些应该被缓存的资源每次都会重新加载。开发者检查网络请求头，发现服务端返回的缓存控制指令阻止了缓存。
4. **并发访问缓存不当:**
   * **错误示例:** 在多线程或多进程环境下，不加控制地并发读写缓存，可能导致数据损坏或性能下降。虽然这个测试用例模拟了并发操作，但在实际应用中需要更谨慎地处理同步问题。
   * **如何到达这里 (调试线索):**  在复杂应用中，可能出现缓存数据不一致或者缓存操作异常的情况。开发者需要分析多线程/多进程的缓存访问模式，找出并发冲突的原因。

**用户操作是如何一步步的到达这里，作为调试线索:**

从用户的角度来看，他们不会直接 "到达" 这个 C++ 文件。但是，用户的操作会触发浏览器使用磁盘缓存，而这个文件的测试就是为了确保这个过程高效。以下是一个用户操作如何间接关联到这个文件的调试：

1. **用户访问一个网页:** 用户在浏览器地址栏输入网址或点击链接。
2. **浏览器发起网络请求:** 浏览器解析 URL，并向服务器发起请求获取网页资源（HTML、CSS、JavaScript、图片等）。
3. **缓存检查:**  在发起网络请求之前，浏览器会**检查磁盘缓存**（这是 `disk_cache_perftest.cc` 测试的核心组件），看是否已经存在该资源的有效副本。
4. **缓存命中 (理想情况):**
   - 如果缓存中存在有效副本，浏览器会**从磁盘缓存中读取资源**。这个读取操作的性能正是 `TimeReads` 测试所关注的。
   - 浏览器使用缓存的资源渲染网页，用户看到加载速度很快。
5. **缓存未命中 (或需要更新):**
   - 如果缓存中没有该资源，或者缓存的副本已过期，浏览器会向服务器发送网络请求。
   - 服务器返回资源数据。
   - **磁盘缓存模块** 将新下载的资源**写入磁盘缓存**。这个写入操作的性能是 `TimeWrites` 测试所关注的。
   - 浏览器使用新下载的资源渲染网页。

**作为调试线索:**

* **网页加载缓慢:** 如果用户抱怨网页加载缓慢，尤其是在重复访问时仍然很慢，那么可能是磁盘缓存的读写性能存在问题。开发者可能会查看这个文件的测试结果，或者针对磁盘缓存进行更深入的性能分析。
* **资源重复下载:** 如果开发者观察到本应从缓存加载的资源每次都重新下载，那么可能是缓存策略配置不当或者缓存键生成有问题。这虽然不是 `disk_cache_perftest.cc` 直接测试的内容，但缓存策略和键的正确性直接影响缓存的命中率，从而影响到这里测试的性能指标。
* **高 CPU/磁盘 I/O:**  如果用户或者开发者观察到浏览器进程占用过高的 CPU 或磁盘 I/O，可能与大量的缓存读写操作有关。这可以作为进一步调查磁盘缓存性能的线索，并可能需要参考 `disk_cache_perftest.cc` 的测试方法来分析具体瓶颈。

总之，`net/disk_cache/disk_cache_perftest.cc` 是幕后英雄，它通过严谨的性能测试，保障了 Chromium 磁盘缓存的高效运行，最终提升了用户的网页浏览体验，也间接地影响了 JavaScript 应用的加载速度。

Prompt: 
```
这是目录为net/disk_cache/disk_cache_perftest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2011 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include <limits>
#include <memory>
#include <string>

#include "base/barrier_closure.h"
#include "base/files/file_enumerator.h"
#include "base/files/file_path.h"
#include "base/functional/bind.h"
#include "base/hash/hash.h"
#include "base/memory/raw_ptr.h"
#include "base/process/process_metrics.h"
#include "base/rand_util.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/test/scoped_run_loop_timeout.h"
#include "base/test/test_file_util.h"
#include "base/test/test_timeouts.h"
#include "base/threading/thread.h"
#include "base/time/time.h"
#include "base/timer/elapsed_timer.h"
#include "build/build_config.h"
#include "net/base/cache_type.h"
#include "net/base/completion_repeating_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/disk_cache/backend_cleanup_tracker.h"
#include "net/disk_cache/blockfile/backend_impl.h"
#include "net/disk_cache/blockfile/block_files.h"
#include "net/disk_cache/disk_cache.h"
#include "net/disk_cache/disk_cache_test_base.h"
#include "net/disk_cache/disk_cache_test_util.h"
#include "net/disk_cache/simple/simple_backend_impl.h"
#include "net/disk_cache/simple/simple_index.h"
#include "net/disk_cache/simple/simple_index_file.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/perf/perf_result_reporter.h"
#include "testing/platform_test.h"

using base::Time;

namespace {

const size_t kNumEntries = 10000;
const int kHeadersSize = 2000;

const int kBodySize = 72 * 1024 - 1;

// HttpCache likes this chunk size.
const int kChunkSize = 32 * 1024;

// As of 2017-01-12, this is a typical per-tab limit on HTTP connections.
const int kMaxParallelOperations = 10;

static constexpr char kMetricPrefixDiskCache[] = "DiskCache.";
static constexpr char kMetricPrefixSimpleIndex[] = "SimpleIndex.";
static constexpr char kMetricCacheEntriesWriteTimeMs[] =
    "cache_entries_write_time";
static constexpr char kMetricCacheHeadersReadTimeColdMs[] =
    "cache_headers_read_time_cold";
static constexpr char kMetricCacheHeadersReadTimeWarmMs[] =
    "cache_headers_read_time_warm";
static constexpr char kMetricCacheEntriesReadTimeColdMs[] =
    "cache_entries_read_time_cold";
static constexpr char kMetricCacheEntriesReadTimeWarmMs[] =
    "cache_entries_read_time_warm";
static constexpr char kMetricCacheKeysHashTimeMs[] = "cache_keys_hash_time";
static constexpr char kMetricFillBlocksTimeMs[] = "fill_sequential_blocks_time";
static constexpr char kMetricCreateDeleteBlocksTimeMs[] =
    "create_and_delete_random_blocks_time";
static constexpr char kMetricSimpleCacheInitTotalTimeMs[] =
    "simple_cache_initial_read_total_time";
static constexpr char kMetricSimpleCacheInitPerEntryTimeUs[] =
    "simple_cache_initial_read_per_entry_time";
static constexpr char kMetricAverageEvictionTimeMs[] = "average_eviction_time";

perf_test::PerfResultReporter SetUpDiskCacheReporter(const std::string& story) {
  perf_test::PerfResultReporter reporter(kMetricPrefixDiskCache, story);
  reporter.RegisterImportantMetric(kMetricCacheEntriesWriteTimeMs, "ms");
  reporter.RegisterImportantMetric(kMetricCacheHeadersReadTimeColdMs, "ms");
  reporter.RegisterImportantMetric(kMetricCacheHeadersReadTimeWarmMs, "ms");
  reporter.RegisterImportantMetric(kMetricCacheEntriesReadTimeColdMs, "ms");
  reporter.RegisterImportantMetric(kMetricCacheEntriesReadTimeWarmMs, "ms");
  reporter.RegisterImportantMetric(kMetricCacheKeysHashTimeMs, "ms");
  reporter.RegisterImportantMetric(kMetricFillBlocksTimeMs, "ms");
  reporter.RegisterImportantMetric(kMetricCreateDeleteBlocksTimeMs, "ms");
  reporter.RegisterImportantMetric(kMetricSimpleCacheInitTotalTimeMs, "ms");
  reporter.RegisterImportantMetric(kMetricSimpleCacheInitPerEntryTimeUs, "us");
  return reporter;
}

perf_test::PerfResultReporter SetUpSimpleIndexReporter(
    const std::string& story) {
  perf_test::PerfResultReporter reporter(kMetricPrefixSimpleIndex, story);
  reporter.RegisterImportantMetric(kMetricAverageEvictionTimeMs, "ms");
  return reporter;
}

void MaybeIncreaseFdLimitTo(unsigned int max_descriptors) {
#if BUILDFLAG(IS_POSIX)
  base::IncreaseFdLimitTo(max_descriptors);
#endif
}

struct TestEntry {
  std::string key;
  int data_len;
};

enum class WhatToRead {
  HEADERS_ONLY,
  HEADERS_AND_BODY,
};

class DiskCachePerfTest : public DiskCacheTestWithCache {
 public:
  DiskCachePerfTest() { MaybeIncreaseFdLimitTo(kFdLimitForCacheTests); }

  const std::vector<TestEntry>& entries() const { return entries_; }

 protected:
  // Helper methods for constructing tests.
  bool TimeWrites(const std::string& story);
  bool TimeReads(WhatToRead what_to_read,
                 const std::string& metric,
                 const std::string& story);
  void ResetAndEvictSystemDiskCache();

  // Callbacks used within tests for intermediate operations.
  void WriteCallback(net::CompletionOnceCallback final_callback,
                     scoped_refptr<net::IOBuffer> headers_buffer,
                     scoped_refptr<net::IOBuffer> body_buffer,
                     disk_cache::Entry* cache_entry,
                     int entry_index,
                     size_t write_offset,
                     int result);

  // Complete perf tests.
  void CacheBackendPerformance(const std::string& story);

  const size_t kFdLimitForCacheTests = 8192;

  std::vector<TestEntry> entries_;
};

class WriteHandler {
 public:
  WriteHandler(const DiskCachePerfTest* test,
               disk_cache::Backend* cache,
               net::CompletionOnceCallback final_callback)
      : test_(test), cache_(cache), final_callback_(std::move(final_callback)) {
    CacheTestFillBuffer(headers_buffer_->data(), kHeadersSize, false);
    CacheTestFillBuffer(body_buffer_->data(), kChunkSize, false);
  }

  void Run();

 protected:
  void CreateNextEntry();

  void CreateCallback(int data_len, disk_cache::EntryResult result);
  void WriteDataCallback(disk_cache::Entry* entry,
                         int next_offset,
                         int data_len,
                         int expected_result,
                         int result);

 private:
  bool CheckForErrorAndCancel(int result);

  raw_ptr<const DiskCachePerfTest> test_;
  raw_ptr<disk_cache::Backend> cache_;
  net::CompletionOnceCallback final_callback_;

  size_t next_entry_index_ = 0;
  size_t pending_operations_count_ = 0;

  int pending_result_ = net::OK;

  scoped_refptr<net::IOBuffer> headers_buffer_ =
      base::MakeRefCounted<net::IOBufferWithSize>(kHeadersSize);
  scoped_refptr<net::IOBuffer> body_buffer_ =
      base::MakeRefCounted<net::IOBufferWithSize>(kChunkSize);
};

void WriteHandler::Run() {
  for (int i = 0; i < kMaxParallelOperations; ++i) {
    ++pending_operations_count_;
    CreateNextEntry();
  }
}

void WriteHandler::CreateNextEntry() {
  ASSERT_GT(kNumEntries, next_entry_index_);
  TestEntry test_entry = test_->entries()[next_entry_index_++];
  auto callback =
      base::BindRepeating(&WriteHandler::CreateCallback, base::Unretained(this),
                          test_entry.data_len);
  disk_cache::EntryResult result =
      cache_->CreateEntry(test_entry.key, net::HIGHEST, callback);
  if (result.net_error() != net::ERR_IO_PENDING)
    callback.Run(std::move(result));
}

void WriteHandler::CreateCallback(int data_len,
                                  disk_cache::EntryResult result) {
  if (CheckForErrorAndCancel(result.net_error()))
    return;

  disk_cache::Entry* entry = result.ReleaseEntry();
  net::CompletionRepeatingCallback callback = base::BindRepeating(
      &WriteHandler::WriteDataCallback, base::Unretained(this), entry, 0,
      data_len, kHeadersSize);
  int new_result = entry->WriteData(0, 0, headers_buffer_.get(), kHeadersSize,
                                    callback, false);
  if (new_result != net::ERR_IO_PENDING)
    callback.Run(new_result);
}

void WriteHandler::WriteDataCallback(disk_cache::Entry* entry,
                                     int next_offset,
                                     int data_len,
                                     int expected_result,
                                     int result) {
  if (CheckForErrorAndCancel(result)) {
    entry->Close();
    return;
  }
  DCHECK_LE(next_offset, data_len);
  if (next_offset == data_len) {
    entry->Close();
    if (next_entry_index_ < kNumEntries) {
      CreateNextEntry();
    } else {
      --pending_operations_count_;
      if (pending_operations_count_ == 0)
        std::move(final_callback_).Run(net::OK);
    }
    return;
  }

  int write_size = std::min(kChunkSize, data_len - next_offset);
  net::CompletionRepeatingCallback callback = base::BindRepeating(
      &WriteHandler::WriteDataCallback, base::Unretained(this), entry,
      next_offset + write_size, data_len, write_size);
  int new_result = entry->WriteData(1, next_offset, body_buffer_.get(),
                                    write_size, callback, true);
  if (new_result != net::ERR_IO_PENDING)
    callback.Run(new_result);
}

bool WriteHandler::CheckForErrorAndCancel(int result) {
  DCHECK_NE(net::ERR_IO_PENDING, result);
  if (result != net::OK && !(result > 0))
    pending_result_ = result;
  if (pending_result_ != net::OK) {
    --pending_operations_count_;
    if (pending_operations_count_ == 0)
      std::move(final_callback_).Run(pending_result_);
    return true;
  }
  return false;
}

class ReadHandler {
 public:
  ReadHandler(const DiskCachePerfTest* test,
              WhatToRead what_to_read,
              disk_cache::Backend* cache,
              net::CompletionOnceCallback final_callback)
      : test_(test),
        what_to_read_(what_to_read),
        cache_(cache),
        final_callback_(std::move(final_callback)) {
    for (auto& read_buffer : read_buffers_) {
      read_buffer = base::MakeRefCounted<net::IOBufferWithSize>(
          std::max(kHeadersSize, kChunkSize));
    }
  }

  void Run();

 protected:
  void OpenNextEntry(int parallel_operation_index);

  void OpenCallback(int parallel_operation_index,
                    int data_len,
                    disk_cache::EntryResult result);
  void ReadDataCallback(int parallel_operation_index,
                        disk_cache::Entry* entry,
                        int next_offset,
                        int data_len,
                        int expected_result,
                        int result);

 private:
  bool CheckForErrorAndCancel(int result);

  raw_ptr<const DiskCachePerfTest> test_;
  const WhatToRead what_to_read_;

  raw_ptr<disk_cache::Backend> cache_;
  net::CompletionOnceCallback final_callback_;

  size_t next_entry_index_ = 0;
  size_t pending_operations_count_ = 0;

  int pending_result_ = net::OK;

  scoped_refptr<net::IOBuffer> read_buffers_[kMaxParallelOperations];
};

void ReadHandler::Run() {
  for (int i = 0; i < kMaxParallelOperations; ++i) {
    OpenNextEntry(pending_operations_count_);
    ++pending_operations_count_;
  }
}

void ReadHandler::OpenNextEntry(int parallel_operation_index) {
  ASSERT_GT(kNumEntries, next_entry_index_);
  TestEntry test_entry = test_->entries()[next_entry_index_++];
  auto callback =
      base::BindRepeating(&ReadHandler::OpenCallback, base::Unretained(this),
                          parallel_operation_index, test_entry.data_len);
  disk_cache::EntryResult result =
      cache_->OpenEntry(test_entry.key, net::HIGHEST, callback);
  if (result.net_error() != net::ERR_IO_PENDING)
    callback.Run(std::move(result));
}

void ReadHandler::OpenCallback(int parallel_operation_index,
                               int data_len,
                               disk_cache::EntryResult result) {
  if (CheckForErrorAndCancel(result.net_error()))
    return;

  disk_cache::Entry* entry = result.ReleaseEntry();

  EXPECT_EQ(data_len, entry->GetDataSize(1));

  net::CompletionRepeatingCallback callback = base::BindRepeating(
      &ReadHandler::ReadDataCallback, base::Unretained(this),
      parallel_operation_index, entry, 0, data_len, kHeadersSize);
  int new_result =
      entry->ReadData(0, 0, read_buffers_[parallel_operation_index].get(),
                      kChunkSize, callback);
  if (new_result != net::ERR_IO_PENDING)
    callback.Run(new_result);
}

void ReadHandler::ReadDataCallback(int parallel_operation_index,
                                   disk_cache::Entry* entry,
                                   int next_offset,
                                   int data_len,
                                   int expected_result,
                                   int result) {
  if (CheckForErrorAndCancel(result)) {
    entry->Close();
    return;
  }
  DCHECK_LE(next_offset, data_len);
  if (what_to_read_ == WhatToRead::HEADERS_ONLY || next_offset == data_len) {
    entry->Close();
    if (next_entry_index_ < kNumEntries) {
      OpenNextEntry(parallel_operation_index);
    } else {
      --pending_operations_count_;
      if (pending_operations_count_ == 0)
        std::move(final_callback_).Run(net::OK);
    }
    return;
  }

  int expected_read_size = std::min(kChunkSize, data_len - next_offset);
  net::CompletionRepeatingCallback callback = base::BindRepeating(
      &ReadHandler::ReadDataCallback, base::Unretained(this),
      parallel_operation_index, entry, next_offset + expected_read_size,
      data_len, expected_read_size);
  int new_result = entry->ReadData(
      1, next_offset, read_buffers_[parallel_operation_index].get(), kChunkSize,
      callback);
  if (new_result != net::ERR_IO_PENDING)
    callback.Run(new_result);
}

bool ReadHandler::CheckForErrorAndCancel(int result) {
  DCHECK_NE(net::ERR_IO_PENDING, result);
  if (result != net::OK && !(result > 0))
    pending_result_ = result;
  if (pending_result_ != net::OK) {
    --pending_operations_count_;
    if (pending_operations_count_ == 0)
      std::move(final_callback_).Run(pending_result_);
    return true;
  }
  return false;
}

bool DiskCachePerfTest::TimeWrites(const std::string& story) {
  for (size_t i = 0; i < kNumEntries; i++) {
    TestEntry entry;
    entry.key = GenerateKey(true);
    entry.data_len = base::RandInt(0, kBodySize);
    entries_.push_back(entry);
  }

  net::TestCompletionCallback cb;

  auto reporter = SetUpDiskCacheReporter(story);
  base::ElapsedTimer write_timer;

  WriteHandler write_handler(this, cache_.get(), cb.callback());
  write_handler.Run();
  auto result = cb.WaitForResult();
  reporter.AddResult(kMetricCacheEntriesWriteTimeMs,
                     write_timer.Elapsed().InMillisecondsF());
  return result == net::OK;
}

bool DiskCachePerfTest::TimeReads(WhatToRead what_to_read,
                                  const std::string& metric,
                                  const std::string& story) {
  auto reporter = SetUpDiskCacheReporter(story);
  base::ElapsedTimer timer;

  net::TestCompletionCallback cb;
  ReadHandler read_handler(this, what_to_read, cache_.get(), cb.callback());
  read_handler.Run();
  auto result = cb.WaitForResult();
  reporter.AddResult(metric, timer.Elapsed().InMillisecondsF());
  return result == net::OK;
}

TEST_F(DiskCachePerfTest, BlockfileHashes) {
  auto reporter = SetUpDiskCacheReporter("baseline_story");
  base::ElapsedTimer timer;
  for (int i = 0; i < 300000; i++) {
    std::string key = GenerateKey(true);
    // TODO(dcheng): It's unclear if this is sufficient to keep a sufficiently
    // smart optimizer from simply discarding the function call if it realizes
    // there are no side effects.
    base::PersistentHash(key);
  }
  reporter.AddResult(kMetricCacheKeysHashTimeMs,
                     timer.Elapsed().InMillisecondsF());
}

void DiskCachePerfTest::ResetAndEvictSystemDiskCache() {
  base::RunLoop().RunUntilIdle();
  cache_.reset();

  // Flush all files in the cache out of system memory.
  const base::FilePath::StringType file_pattern = FILE_PATH_LITERAL("*");
  base::FileEnumerator enumerator(cache_path_, true /* recursive */,
                                  base::FileEnumerator::FILES, file_pattern);
  for (base::FilePath file_path = enumerator.Next(); !file_path.empty();
       file_path = enumerator.Next()) {
    ASSERT_TRUE(base::EvictFileFromSystemCache(file_path));
  }
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_ANDROID)
  // And, cache directories, on platforms where the eviction utility supports
  // this (currently Linux and Android only).
  if (simple_cache_mode_) {
    ASSERT_TRUE(
        base::EvictFileFromSystemCache(cache_path_.AppendASCII("index-dir")));
  }
  ASSERT_TRUE(base::EvictFileFromSystemCache(cache_path_));
#endif

  DisableFirstCleanup();
  InitCache();
}

void DiskCachePerfTest::CacheBackendPerformance(const std::string& story) {
  base::test::ScopedRunLoopTimeout default_timeout(
      FROM_HERE, TestTimeouts::action_max_timeout());

  LOG(ERROR) << "Using cache at:" << cache_path_.MaybeAsASCII();
  SetMaxSize(500 * 1024 * 1024);
  InitCache();
  EXPECT_TRUE(TimeWrites(story));

  disk_cache::FlushCacheThreadForTesting();
  base::RunLoop().RunUntilIdle();

  ResetAndEvictSystemDiskCache();
  EXPECT_TRUE(TimeReads(WhatToRead::HEADERS_ONLY,
                        kMetricCacheHeadersReadTimeColdMs, story));
  EXPECT_TRUE(TimeReads(WhatToRead::HEADERS_ONLY,
                        kMetricCacheHeadersReadTimeWarmMs, story));

  disk_cache::FlushCacheThreadForTesting();
  base::RunLoop().RunUntilIdle();

  ResetAndEvictSystemDiskCache();
  EXPECT_TRUE(TimeReads(WhatToRead::HEADERS_AND_BODY,
                        kMetricCacheEntriesReadTimeColdMs, story));
  EXPECT_TRUE(TimeReads(WhatToRead::HEADERS_AND_BODY,
                        kMetricCacheEntriesReadTimeWarmMs, story));

  disk_cache::FlushCacheThreadForTesting();
  base::RunLoop().RunUntilIdle();
}

#if BUILDFLAG(IS_FUCHSIA)
// TODO(crbug.com/41393579): Fix this test on Fuchsia and re-enable.
#define MAYBE_CacheBackendPerformance DISABLED_CacheBackendPerformance
#else
#define MAYBE_CacheBackendPerformance CacheBackendPerformance
#endif
TEST_F(DiskCachePerfTest, MAYBE_CacheBackendPerformance) {
  CacheBackendPerformance("blockfile_cache");
}

#if BUILDFLAG(IS_FUCHSIA)
// TODO(crbug.com/41393579): Fix this test on Fuchsia and re-enable.
#define MAYBE_SimpleCacheBackendPerformance \
  DISABLED_SimpleCacheBackendPerformance
#else
#define MAYBE_SimpleCacheBackendPerformance SimpleCacheBackendPerformance
#endif
TEST_F(DiskCachePerfTest, MAYBE_SimpleCacheBackendPerformance) {
  SetSimpleCacheMode();
  CacheBackendPerformance("simple_cache");
}

// Creating and deleting "entries" on a block-file is something quite frequent
// (after all, almost everything is stored on block files). The operation is
// almost free when the file is empty, but can be expensive if the file gets
// fragmented, or if we have multiple files. This test measures that scenario,
// by using multiple, highly fragmented files.
TEST_F(DiskCachePerfTest, BlockFilesPerformance) {
  ASSERT_TRUE(CleanupCacheDir());

  disk_cache::BlockFiles files(cache_path_);
  ASSERT_TRUE(files.Init(true));

  const int kNumBlocks = 60000;
  disk_cache::Addr address[kNumBlocks];

  auto reporter = SetUpDiskCacheReporter("blockfile_cache");
  base::ElapsedTimer sequential_timer;

  // Fill up the 32-byte block file (use three files).
  for (auto& addr : address) {
    int block_size = base::RandInt(1, 4);
    EXPECT_TRUE(files.CreateBlock(disk_cache::RANKINGS, block_size, &addr));
  }

  reporter.AddResult(kMetricFillBlocksTimeMs,
                     sequential_timer.Elapsed().InMillisecondsF());
  base::ElapsedTimer random_timer;

  for (int i = 0; i < 200000; i++) {
    int block_size = base::RandInt(1, 4);
    int entry = base::RandInt(0, kNumBlocks - 1);

    files.DeleteBlock(address[entry], false);
    EXPECT_TRUE(
        files.CreateBlock(disk_cache::RANKINGS, block_size, &address[entry]));
  }

  reporter.AddResult(kMetricCreateDeleteBlocksTimeMs,
                     random_timer.Elapsed().InMillisecondsF());
  base::RunLoop().RunUntilIdle();
}

void VerifyRvAndCallClosure(base::RepeatingClosure* c, int expect_rv, int rv) {
  EXPECT_EQ(expect_rv, rv);
  c->Run();
}

TEST_F(DiskCachePerfTest, SimpleCacheInitialReadPortion) {
  // A benchmark that aims to measure how much time we take in I/O thread
  // for initial bookkeeping before returning to the caller, and how much
  // after (batched up some). The later portion includes some event loop
  // overhead.
  const int kBatchSize = 100;

  SetSimpleCacheMode();

  InitCache();
  // Write out the entries, and keep their objects around.
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kHeadersSize);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kBodySize);

  CacheTestFillBuffer(buffer1->data(), kHeadersSize, false);
  CacheTestFillBuffer(buffer2->data(), kBodySize, false);

  disk_cache::Entry* cache_entry[kBatchSize];
  for (int i = 0; i < kBatchSize; ++i) {
    TestEntryResultCompletionCallback cb_create;
    disk_cache::EntryResult result = cb_create.GetResult(cache_->CreateEntry(
        base::NumberToString(i), net::HIGHEST, cb_create.callback()));
    ASSERT_EQ(net::OK, result.net_error());
    cache_entry[i] = result.ReleaseEntry();

    net::TestCompletionCallback cb;
    int rv = cache_entry[i]->WriteData(0, 0, buffer1.get(), kHeadersSize,
                                       cb.callback(), false);
    ASSERT_EQ(kHeadersSize, cb.GetResult(rv));
    rv = cache_entry[i]->WriteData(1, 0, buffer2.get(), kBodySize,
                                   cb.callback(), false);
    ASSERT_EQ(kBodySize, cb.GetResult(rv));
  }

  // Now repeatedly read these, batching up the waiting to try to
  // account for the two portions separately. Note that we need separate entries
  // since we are trying to keep interesting work from being on the delayed-done
  // portion.
  const int kIterations = 50000;

  double elapsed_early = 0.0;
  double elapsed_late = 0.0;

  for (int i = 0; i < kIterations; ++i) {
    base::RunLoop event_loop;
    base::RepeatingClosure barrier =
        base::BarrierClosure(kBatchSize, event_loop.QuitWhenIdleClosure());
    net::CompletionRepeatingCallback cb_batch(base::BindRepeating(
        VerifyRvAndCallClosure, base::Unretained(&barrier), kHeadersSize));

    base::ElapsedTimer timer_early;
    for (auto* entry : cache_entry) {
      int rv = entry->ReadData(0, 0, buffer1.get(), kHeadersSize, cb_batch);
      if (rv != net::ERR_IO_PENDING) {
        barrier.Run();
        ASSERT_EQ(kHeadersSize, rv);
      }
    }
    elapsed_early += timer_early.Elapsed().InMillisecondsF();

    base::ElapsedTimer timer_late;
    event_loop.Run();
    elapsed_late += timer_late.Elapsed().InMillisecondsF();
  }

  // Cleanup
  for (auto* entry : cache_entry)
    entry->Close();

  disk_cache::FlushCacheThreadForTesting();
  base::RunLoop().RunUntilIdle();
  auto reporter = SetUpDiskCacheReporter("early_portion");
  reporter.AddResult(kMetricSimpleCacheInitTotalTimeMs, elapsed_early);
  reporter.AddResult(kMetricSimpleCacheInitPerEntryTimeUs,
                     1000 * (elapsed_early / (kIterations * kBatchSize)));
  reporter = SetUpDiskCacheReporter("event_loop_portion");
  reporter.AddResult(kMetricSimpleCacheInitTotalTimeMs, elapsed_late);
  reporter.AddResult(kMetricSimpleCacheInitPerEntryTimeUs,
                     1000 * (elapsed_late / (kIterations * kBatchSize)));
}

#if BUILDFLAG(IS_FUCHSIA)
// TODO(crbug.com/40222788): Fix this test on Fuchsia and re-enable.
#define MAYBE_EvictionPerformance DISABLED_EvictionPerformance
#else
#define MAYBE_EvictionPerformance EvictionPerformance
#endif
// Measures how quickly SimpleIndex can compute which entries to evict.
TEST(SimpleIndexPerfTest, MAYBE_EvictionPerformance) {
  const int kEntries = 10000;

  class NoOpDelegate : public disk_cache::SimpleIndexDelegate {
    void DoomEntries(std::vector<uint64_t>* entry_hashes,
                     net::CompletionOnceCallback callback) override {}
  };

  NoOpDelegate delegate;
  base::Time start(base::Time::Now());

  double evict_elapsed_ms = 0;
  int iterations = 0;
  while (iterations < 61000) {
    ++iterations;
    disk_cache::SimpleIndex index(/* io_thread = */ nullptr,
                                  /* cleanup_tracker = */ nullptr, &delegate,
                                  net::DISK_CACHE,
                                  /* simple_index_file = */ nullptr);

    // Make sure large enough to not evict on insertion.
    index.SetMaxSize(kEntries * 2);

    for (int i = 0; i < kEntries; ++i) {
      index.InsertEntryForTesting(
          i, disk_cache::EntryMetadata(start + base::Seconds(i), 1u));
    }

    // Trigger an eviction.
    base::ElapsedTimer timer;
    index.SetMaxSize(kEntries);
    index.UpdateEntrySize(0, 1u);
    evict_elapsed_ms += timer.Elapsed().InMillisecondsF();
  }

  auto reporter = SetUpSimpleIndexReporter("baseline_story");
  reporter.AddResult(kMetricAverageEvictionTimeMs,
                     evict_elapsed_ms / iterations);
}

}  // namespace

"""

```