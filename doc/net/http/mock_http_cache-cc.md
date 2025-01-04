Response:
Let's break down the thought process for analyzing this `mock_http_cache.cc` file.

1. **Understanding the Request:** The request asks for the functionality of the file, its relation to JavaScript, examples of logical reasoning, common user errors, and debugging steps to reach this code. This provides a clear roadmap for analysis.

2. **Initial Scan and Keyword Recognition:**  The first step is to quickly scan the file for important keywords and structures. I'm looking for things like:
    * `#include`:  To understand dependencies.
    * `namespace net`: To identify the scope.
    * Class definitions (`MockDiskEntry`, `MockDiskCache`, `MockHttpCache`): These are the core components.
    * Method names like `OpenOrCreateEntry`, `ReadData`, `WriteData`, `Doom`, `CreateTransaction`: These hint at the functionalities.
    * `TEST_MODE_*`: Suggests this is related to testing.
    * Comments like "// During testing...":  Explicitly confirms its testing purpose.

3. **Core Functionality Identification (High-Level):** Based on the class names and methods, it's evident that this code provides a *mock* implementation of an HTTP cache. "Mock" implies a simplified, in-memory version used for testing, rather than a real disk-based cache. This immediately answers the main function question.

4. **Dissecting Key Classes:**  Now, I'll delve into the individual classes to understand their roles:

    * **`MockDiskEntry`:** This represents a single entry within the mock cache. It stores the key and data, and provides methods for reading, writing, and managing the entry's state (doomed, sparse). The `CallbackLater` mechanism is interesting and needs closer examination. The presence of `defer_op_`, `resume_callback_`, and `ignore_callbacks_` signals control over asynchronous operations for testing.

    * **`MockDiskCache`:** This acts as the container for `MockDiskEntry` objects. It provides methods for opening, creating, and deleting entries, simulating the behavior of a `disk_cache::Backend`. The `entries_` map is the central storage.

    * **`MockHttpCache`:** This is the high-level mock cache, integrating the `MockDiskCache` and a `MockNetworkLayer` (though the latter isn't in this file). It provides an interface similar to a real `HttpCache`, offering methods like `CreateTransaction`, `ReadResponseInfo`, and `WriteResponseInfo`. The `g_test_mode` and related methods are clearly for controlling testing behavior.

5. **JavaScript Relationship:** The key point here is that *this code is C++*. It operates within the Chromium browser's network stack. JavaScript running in a web page interacts with the browser's network layer through APIs. The *real* HTTP cache is what JavaScript ultimately benefits from. The *mock* cache is used for *testing the C++ code that interacts with the real cache*. Therefore, the relationship is indirect: the mock helps ensure the correctness of the C++ code that *supports* the caching mechanism that JavaScript uses. An example would be testing a feature that relies on retrieving cached data. The mock allows testing this logic without hitting a real disk cache.

6. **Logical Reasoning Examples:**  The request asks for assumptions, inputs, and outputs. This requires looking at the logic within the methods. Good candidates are methods with conditional behavior:

    * **`MockDiskEntry::ReadData`:**  The logic handles offsets, buffer lengths, and potential read failures. The `defer_op_` mechanism is a prime example of controllable asynchronous behavior.
    * **`MockDiskCache::OpenOrCreateEntry`:**  The logic tries to open first, then creates if opening fails. This is a clear decision-making process.
    * **`MockDiskCache::CreateEntry`:** The logic checks for existing entries and handles the `double_create_check_` scenario.

7. **Common User/Programming Errors:** Since this is mock code for *internal testing*,  the errors aren't directly related to end-user actions. They are more about *test setup* and *incorrect assumptions within the tests*. Examples include forgetting to resume deferred operations, misusing test modes, or expecting specific outcomes with forced failures.

8. **Debugging Steps:**  To reach this code during debugging, a developer would likely be:

    * **Working on network caching functionality:**  They'd be stepping through the code that interacts with the HTTP cache.
    * **Running unit tests:** The mock cache is heavily used in unit tests for the network stack. Breakpoints would be set within the mock implementation.
    * **Investigating caching-related bugs:** If a bug involves how the cache stores or retrieves data, a developer might trace the code execution into the cache implementation, and in test environments, that often leads to the mock.

9. **Review and Refine:** After the initial analysis, I'd review the findings to ensure they are accurate, clear, and address all parts of the request. I'd check for any missing pieces or areas where the explanation could be improved. For example, initially, I might not have emphasized the "indirect" relationship with JavaScript strongly enough. A review would prompt me to clarify this. Similarly, making sure the assumed inputs and outputs for logical reasoning examples are concrete and understandable is important.

This systematic approach, moving from high-level understanding to detailed analysis and then focusing on the specific requirements of the request, allows for a comprehensive and accurate explanation of the `mock_http_cache.cc` file.
好的，让我们来分析一下 `net/http/mock_http_cache.cc` 这个文件。

**文件功能:**

`mock_http_cache.cc` 文件在 Chromium 网络栈中提供了一个 **模拟的 HTTP 缓存** 功能。  它并不是一个真正的、将数据存储在磁盘上的缓存实现，而是一个用于 **测试目的** 的内存缓存。  它的主要功能包括：

1. **模拟缓存条目的创建、打开、读取、写入和删除：**  `MockDiskEntry` 类模拟了缓存中的单个条目，提供了 `ReadData`、`WriteData`、`Doom` (删除) 等方法。
2. **模拟缓存后端的行为：** `MockDiskCache` 类模拟了磁盘缓存后端的行为，允许创建和管理多个 `MockDiskEntry` 对象。它实现了 `disk_cache::Backend` 接口的关键方法，如 `OpenOrCreateEntry`、`OpenEntry`、`CreateEntry` 和 `DoomEntry`。
3. **支持同步和异步操作的模拟：**  通过 `TEST_MODE_*` 常量和 `CallbackLater` 函数，可以模拟缓存操作的同步和异步行为，这对于测试网络栈中与缓存交互的异步逻辑非常重要。
4. **允许注入错误和延迟：**  通过 `fail_requests_`、`defer_op_` 等成员变量，可以模拟缓存操作失败或延迟的情况，用于测试错误处理逻辑。
5. **支持稀疏缓存的模拟：**  `MockDiskEntry` 提供了 `ReadSparseData`、`WriteSparseData` 等方法，用于模拟稀疏缓存的行为，这在某些下载场景中很有用。
6. **集成到 `HttpCache`：** `MockHttpCache` 类将 `MockDiskCache` 集成到一个简化的 `HttpCache` 中，用于进行更高层次的缓存交互测试。
7. **提供测试辅助功能：**  例如 `GetTestMode` 和 `SetTestMode` 允许全局控制测试模式，`IgnoreCallbacks` 可以暂停回调的执行。

**与 JavaScript 的关系：**

`mock_http_cache.cc` 本身是用 C++ 编写的，直接与 JavaScript 没有交互。 然而，它通过以下方式间接地与 JavaScript 的功能相关：

* **测试浏览器缓存逻辑：** JavaScript 可以通过浏览器的 API（例如 `fetch` 或 `XMLHttpRequest`）发起网络请求。浏览器内部的网络栈会利用 HTTP 缓存来提高性能。`mock_http_cache.cc` 用于测试 Chromium 网络栈中管理和使用缓存的 C++ 代码的正确性。 换句话说，它确保了当 JavaScript 发起请求时，缓存的 C++ 实现能够按照预期工作。
* **确保缓存策略的正确性：** 浏览器的缓存策略（例如，何时从缓存加载资源，何时重新请求）是由 C++ 代码实现的。 `mock_http_cache.cc` 可以帮助测试这些策略在各种情况下的正确性，从而确保 JavaScript 代码能够获得正确的缓存行为。

**举例说明:**

假设一个 JavaScript 代码发起了一个 `GET` 请求到一个特定的 URL。

1. **正常情况（使用真实缓存）：** 浏览器会首先检查真实的 HTTP 缓存中是否存在该 URL 的有效缓存副本。如果存在，浏览器可能会直接从缓存加载，而无需发起网络请求。
2. **使用 `mock_http_cache` 进行测试：** 在测试环境中，我们可以配置 Chromium 使用 `MockHttpCache`。
    * **假设输入：** 测试代码预先在 `MockDiskCache` 中为该 URL 创建了一个 `MockDiskEntry`，并写入了特定的响应头和内容。
    * **逻辑推理：** 当 JavaScript 发起相同的 `GET` 请求时，Chromium 的网络栈会调用 `MockHttpCache` 的方法来查找缓存条目。由于我们预先创建了条目，`MockHttpCache` 会返回该 `MockDiskEntry`。
    * **输出：** 测试代码可以验证 `MockDiskEntry` 中的响应头和内容是否与预期一致，从而验证缓存的读取逻辑是否正确。

**逻辑推理举例：**

假设我们要测试当缓存条目被标记为 `doomed` (要删除) 后的行为。

* **假设输入：**
    1. 在 `MockDiskCache` 中创建了一个 URL "http://example.com/data" 的缓存条目。
    2. 调用 `MockDiskCache::DoomEntry("http://example.com/data", ...)` 将该条目标记为要删除。
    3. 尝试再次使用 `MockDiskCache::OpenEntry("http://example.com/data", ...)` 打开该条目。
* **逻辑推理：** `MockDiskCache::OpenEntry` 方法会检查要打开的条目是否已经被标记为 `doomed_`。如果是，它会释放该条目并从内部 `entries_` 映射中移除，并返回一个表示打开失败的错误码。
* **输出：**  调用 `OpenEntry` 应该返回一个错误码（例如 `ERR_CACHE_OPEN_FAILURE`），并且内部的 `entries_` 映射中不再包含 "http://example.com/data" 的条目。

**用户或编程常见的使用错误举例：**

由于 `mock_http_cache.cc` 主要用于内部测试，用户直接使用它的场景很少。  常见的 "使用错误" 更多是发生在编写和运行网络栈的测试代码时：

* **忘记恢复被延迟的操作：** `MockDiskEntry` 和 `MockDiskCache` 提供了延迟操作的功能（例如通过 `defer_op_`）。如果在测试中设置了延迟，但忘记在后续步骤中调用 `ResumeDiskEntryOperation` 或 `ResumeCacheOperation`，会导致测试一直处于挂起状态。
* **不正确地设置测试模式：**  `GetTestMode` 和 `SetTestMode` 用于控制同步/异步行为。如果在测试中不小心设置了错误的测试模式，可能会导致测试结果与预期不符。例如，期望异步操作但实际执行了同步操作，或者反之。
* **过度依赖 Mock 行为：**  开发者可能会过于依赖 `mock_http_cache` 的特定行为，而忽略了真实缓存可能存在的细微差别。这可能会导致测试通过，但在真实环境中出现问题。
* **忘记清理 Mock 缓存状态：** 在不同的测试用例之间，如果没有正确清理 `MockDiskCache` 中的条目，可能会导致测试用例之间相互影响，产生难以调试的错误。

**用户操作如何一步步到达这里（调试线索）：**

一个开发者在调试与 HTTP 缓存相关的 Chromium 网络栈代码时，可能会逐步进入 `mock_http_cache.cc`：

1. **用户报告了缓存相关的问题：** 比如网页资源没有被正确缓存，或者缓存过期策略失效。
2. **开发者开始调试网络请求流程：** 他们可能会从处理网络请求的入口点开始，例如 `URLRequest` 或 `HttpTransaction`。
3. **代码执行到缓存交互部分：**  在处理请求的过程中，网络栈的代码会尝试从缓存中读取或写入数据。这涉及到与 `HttpCache` 类的交互。
4. **在测试环境中运行代码：** 为了更容易调试和隔离问题，开发者通常会在测试环境中使用 Mock 对象替换真实的组件。
5. **`HttpCache` 使用了 `MockDiskCache`：** 在测试环境中，`HttpCache` 可能会被配置为使用 `MockBackendFactory` 创建的 `MockDiskCache` 作为其后端存储。
6. **进入 `MockDiskCache` 或 `MockDiskEntry` 的方法：** 当网络栈的代码尝试操作缓存时（例如打开、读取、写入条目），就会调用 `MockDiskCache` 或 `MockDiskEntry` 中相应的方法。
7. **设置断点进行调试：** 开发者可以在 `mock_http_cache.cc` 的关键方法（例如 `OpenEntry`, `ReadData`, `WriteData`) 中设置断点，观察代码的执行流程，查看缓存的状态，以及模拟行为是否符合预期。

总而言之，`mock_http_cache.cc` 是 Chromium 网络栈中一个至关重要的测试工具，它允许开发者在隔离的环境中测试缓存逻辑，确保缓存功能的正确性和稳定性，最终保障了用户通过浏览器访问网页时的性能和体验。

Prompt: 
```
这是目录为net/http/mock_http_cache.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/http/mock_http_cache.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <utility>

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/task/single_thread_task_runner.h"
#include "net/base/features.h"
#include "net/base/net_errors.h"
#include "net/disk_cache/disk_cache_test_util.h"
#include "net/http/http_cache_writers.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

// During testing, we are going to limit the size of a cache entry to this many
// bytes using DCHECKs in order to prevent a test from causing unbounded memory
// growth. In practice cache entry shouldn't come anywhere near this limit for
// tests that use the mock cache. If they do, that's likely a problem with the
// test. If a test requires using massive cache entries, they should use a real
// cache backend instead.
const int kMaxMockCacheEntrySize = 100 * 1000 * 1000;

// We can override the test mode for a given operation by setting this global
// variable.
int g_test_mode = 0;

int GetTestModeForEntry(const std::string& key) {
  GURL url(HttpCache::GetResourceURLFromHttpCacheKey(key));
  const MockTransaction* t = FindMockTransaction(url);
  DCHECK(t);
  return t->test_mode;
}

}  // namespace

//-----------------------------------------------------------------------------

struct MockDiskEntry::CallbackInfo {
  scoped_refptr<MockDiskEntry> entry;
  base::OnceClosure callback;
};

MockDiskEntry::MockDiskEntry(const std::string& key)
    : key_(key), max_file_size_(std::numeric_limits<int>::max()) {
  test_mode_ = GetTestModeForEntry(key);
}

void MockDiskEntry::Doom() {
  doomed_ = true;
}

void MockDiskEntry::Close() {
  Release();
}

std::string MockDiskEntry::GetKey() const {
  return key_;
}

base::Time MockDiskEntry::GetLastUsed() const {
  return base::Time::Now();
}

base::Time MockDiskEntry::GetLastModified() const {
  return base::Time::Now();
}

int32_t MockDiskEntry::GetDataSize(int index) const {
  DCHECK(index >= 0 && index < kNumCacheEntryDataIndices);
  return static_cast<int32_t>(data_[index].size());
}

int MockDiskEntry::ReadData(int index,
                            int offset,
                            IOBuffer* buf,
                            int buf_len,
                            CompletionOnceCallback callback) {
  DCHECK(index >= 0 && index < kNumCacheEntryDataIndices);
  DCHECK(!callback.is_null());

  if (fail_requests_ & FAIL_READ) {
    return ERR_CACHE_READ_FAILURE;
  }

  if (offset < 0 || offset > static_cast<int>(data_[index].size())) {
    return ERR_FAILED;
  }
  if (static_cast<size_t>(offset) == data_[index].size()) {
    return 0;
  }

  int num = std::min(buf_len, static_cast<int>(data_[index].size()) - offset);
  memcpy(buf->data(), &data_[index][offset], num);

  if (MockHttpCache::GetTestMode(test_mode_) & TEST_MODE_SYNC_CACHE_READ) {
    return num;
  }

  // Pause and resume.
  if (defer_op_ == DEFER_READ) {
    defer_op_ = DEFER_NONE;
    resume_callback_ = std::move(callback);
    resume_return_code_ = num;
    return ERR_IO_PENDING;
  }

  CallbackLater(std::move(callback), num);
  return ERR_IO_PENDING;
}

void MockDiskEntry::ResumeDiskEntryOperation() {
  DCHECK(!resume_callback_.is_null());
  CallbackLater(std::move(resume_callback_), resume_return_code_);
  resume_return_code_ = 0;
}

int MockDiskEntry::WriteData(int index,
                             int offset,
                             IOBuffer* buf,
                             int buf_len,
                             CompletionOnceCallback callback,
                             bool truncate) {
  DCHECK(index >= 0 && index < kNumCacheEntryDataIndices);
  DCHECK(!callback.is_null());
  DCHECK(truncate);

  if (fail_requests_ & FAIL_WRITE) {
    CallbackLater(std::move(callback), ERR_CACHE_READ_FAILURE);
    return ERR_IO_PENDING;
  }

  if (offset < 0 || offset > static_cast<int>(data_[index].size())) {
    return ERR_FAILED;
  }

  DCHECK_LT(offset + buf_len, kMaxMockCacheEntrySize);
  if (offset + buf_len > max_file_size_ && index == 1) {
    return ERR_FAILED;
  }

  data_[index].resize(offset + buf_len);
  if (buf_len) {
    memcpy(&data_[index][offset], buf->data(), buf_len);
  }

  if (MockHttpCache::GetTestMode(test_mode_) & TEST_MODE_SYNC_CACHE_WRITE) {
    return buf_len;
  }

  if (defer_op_ == DEFER_WRITE) {
    defer_op_ = DEFER_NONE;
    resume_callback_ = std::move(callback);
    resume_return_code_ = buf_len;
    return ERR_IO_PENDING;
  }

  CallbackLater(std::move(callback), buf_len);
  return ERR_IO_PENDING;
}

int MockDiskEntry::ReadSparseData(int64_t offset,
                                  IOBuffer* buf,
                                  int buf_len,
                                  CompletionOnceCallback callback) {
  DCHECK(!callback.is_null());
  if (fail_sparse_requests_) {
    return ERR_NOT_IMPLEMENTED;
  }
  if (!sparse_ || busy_ || cancel_) {
    return ERR_CACHE_OPERATION_NOT_SUPPORTED;
  }
  if (offset < 0) {
    return ERR_FAILED;
  }

  if (fail_requests_ & FAIL_READ_SPARSE) {
    return ERR_CACHE_READ_FAILURE;
  }

  DCHECK(offset < std::numeric_limits<int32_t>::max());
  int real_offset = static_cast<int>(offset);
  if (!buf_len) {
    return 0;
  }

  int num = std::min(static_cast<int>(data_[1].size()) - real_offset, buf_len);
  memcpy(buf->data(), &data_[1][real_offset], num);

  if (MockHttpCache::GetTestMode(test_mode_) & TEST_MODE_SYNC_CACHE_READ) {
    return num;
  }

  CallbackLater(std::move(callback), num);
  busy_ = true;
  delayed_ = false;
  return ERR_IO_PENDING;
}

int MockDiskEntry::WriteSparseData(int64_t offset,
                                   IOBuffer* buf,
                                   int buf_len,
                                   CompletionOnceCallback callback) {
  DCHECK(!callback.is_null());
  if (fail_sparse_requests_) {
    return ERR_NOT_IMPLEMENTED;
  }
  if (busy_ || cancel_) {
    return ERR_CACHE_OPERATION_NOT_SUPPORTED;
  }
  if (!sparse_) {
    if (data_[1].size()) {
      return ERR_CACHE_OPERATION_NOT_SUPPORTED;
    }
    sparse_ = true;
  }
  if (offset < 0) {
    return ERR_FAILED;
  }
  if (!buf_len) {
    return 0;
  }

  if (fail_requests_ & FAIL_WRITE_SPARSE) {
    return ERR_CACHE_READ_FAILURE;
  }

  DCHECK(offset < std::numeric_limits<int32_t>::max());
  int real_offset = static_cast<int>(offset);

  if (static_cast<int>(data_[1].size()) < real_offset + buf_len) {
    DCHECK_LT(real_offset + buf_len, kMaxMockCacheEntrySize);
    data_[1].resize(real_offset + buf_len);
  }

  memcpy(&data_[1][real_offset], buf->data(), buf_len);
  if (MockHttpCache::GetTestMode(test_mode_) & TEST_MODE_SYNC_CACHE_WRITE) {
    return buf_len;
  }

  CallbackLater(std::move(callback), buf_len);
  return ERR_IO_PENDING;
}

disk_cache::RangeResult MockDiskEntry::GetAvailableRange(
    int64_t offset,
    int len,
    RangeResultCallback callback) {
  DCHECK(!callback.is_null());
  if (!sparse_ || busy_ || cancel_) {
    return RangeResult(ERR_CACHE_OPERATION_NOT_SUPPORTED);
  }
  if (offset < 0) {
    return RangeResult(ERR_FAILED);
  }

  if (fail_requests_ & FAIL_GET_AVAILABLE_RANGE) {
    return RangeResult(ERR_CACHE_READ_FAILURE);
  }

  RangeResult result;
  result.net_error = OK;
  result.start = offset;
  result.available_len = 0;
  DCHECK(offset < std::numeric_limits<int32_t>::max());
  int real_offset = static_cast<int>(offset);
  if (static_cast<int>(data_[1].size()) < real_offset) {
    return result;
  }

  int num = std::min(static_cast<int>(data_[1].size()) - real_offset, len);
  for (; num > 0; num--, real_offset++) {
    if (!result.available_len) {
      if (data_[1][real_offset]) {
        result.available_len++;
        result.start = real_offset;
      }
    } else {
      if (!data_[1][real_offset]) {
        break;
      }
      result.available_len++;
    }
  }
  if (MockHttpCache::GetTestMode(test_mode_) & TEST_MODE_SYNC_CACHE_WRITE) {
    return result;
  }

  CallbackLater(base::BindOnce(std::move(callback), result));
  return RangeResult(ERR_IO_PENDING);
}

bool MockDiskEntry::CouldBeSparse() const {
  if (fail_sparse_requests_) {
    return false;
  }
  return sparse_;
}

void MockDiskEntry::CancelSparseIO() {
  cancel_ = true;
}

Error MockDiskEntry::ReadyForSparseIO(CompletionOnceCallback callback) {
  if (fail_sparse_requests_) {
    return ERR_NOT_IMPLEMENTED;
  }
  if (!cancel_) {
    return OK;
  }

  cancel_ = false;
  DCHECK(!callback.is_null());
  if (MockHttpCache::GetTestMode(test_mode_) & TEST_MODE_SYNC_CACHE_READ) {
    return OK;
  }

  // The pending operation is already in the message loop (and hopefully
  // already in the second pass).  Just notify the caller that it finished.
  CallbackLater(std::move(callback), 0);
  return ERR_IO_PENDING;
}

void MockDiskEntry::SetLastUsedTimeForTest(base::Time time) {
  NOTREACHED();
}

// If |value| is true, don't deliver any completion callbacks until called
// again with |value| set to false.  Caution: remember to enable callbacks
// again or all subsequent tests will fail.
// Static.
void MockDiskEntry::IgnoreCallbacks(bool value) {
  if (ignore_callbacks_ == value) {
    return;
  }
  ignore_callbacks_ = value;
  if (!value) {
    StoreAndDeliverCallbacks(false, nullptr, base::OnceClosure());
  }
}

MockDiskEntry::~MockDiskEntry() = default;

// Unlike the callbacks for MockHttpTransaction, we want this one to run even
// if the consumer called Close on the MockDiskEntry.  We achieve that by
// leveraging the fact that this class is reference counted.
void MockDiskEntry::CallbackLater(base::OnceClosure callback) {
  if (ignore_callbacks_) {
    return StoreAndDeliverCallbacks(true, this, std::move(callback));
  }
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&MockDiskEntry::RunCallback, this, std::move(callback)));
}

void MockDiskEntry::CallbackLater(CompletionOnceCallback callback, int result) {
  CallbackLater(base::BindOnce(std::move(callback), result));
}

void MockDiskEntry::RunCallback(base::OnceClosure callback) {
  if (busy_) {
    // This is kind of hacky, but controlling the behavior of just this entry
    // from a test is sort of complicated.  What we really want to do is
    // delay the delivery of a sparse IO operation a little more so that the
    // request start operation (async) will finish without seeing the end of
    // this operation (already posted to the message loop)... and without
    // just delaying for n mS (which may cause trouble with slow bots).  So
    // we re-post this operation (all async sparse IO operations will take two
    // trips through the message loop instead of one).
    if (!delayed_) {
      delayed_ = true;
      return CallbackLater(std::move(callback));
    }
  }
  busy_ = false;
  std::move(callback).Run();
}

// When |store| is true, stores the callback to be delivered later; otherwise
// delivers any callback previously stored.
// Static.
void MockDiskEntry::StoreAndDeliverCallbacks(bool store,
                                             MockDiskEntry* entry,
                                             base::OnceClosure callback) {
  static std::vector<CallbackInfo> callback_list;
  if (store) {
    CallbackInfo c = {entry, std::move(callback)};
    callback_list.push_back(std::move(c));
  } else {
    for (auto& callback_info : callback_list) {
      callback_info.entry->CallbackLater(std::move(callback_info.callback));
    }
    callback_list.clear();
  }
}

// Statics.
bool MockDiskEntry::ignore_callbacks_ = false;

//-----------------------------------------------------------------------------

MockDiskCache::MockDiskCache()
    : Backend(DISK_CACHE), max_file_size_(std::numeric_limits<int>::max()) {}

MockDiskCache::~MockDiskCache() {
  ReleaseAll();
}

int32_t MockDiskCache::GetEntryCount() const {
  return static_cast<int32_t>(entries_.size());
}

disk_cache::EntryResult MockDiskCache::OpenOrCreateEntry(
    const std::string& key,
    RequestPriority request_priority,
    EntryResultCallback callback) {
  DCHECK(!callback.is_null());

  if (force_fail_callback_later_) {
    CallbackLater(base::BindOnce(
        std::move(callback),
        EntryResult::MakeError(ERR_CACHE_OPEN_OR_CREATE_FAILURE)));
    return EntryResult::MakeError(ERR_IO_PENDING);
  }

  if (fail_requests_) {
    return EntryResult::MakeError(ERR_CACHE_OPEN_OR_CREATE_FAILURE);
  }

  EntryResult result;

  // First try opening the entry.
  auto split_callback = base::SplitOnceCallback(std::move(callback));
  result = OpenEntry(key, request_priority, std::move(split_callback.first));
  if (result.net_error() == OK || result.net_error() == ERR_IO_PENDING) {
    return result;
  }

  // Unable to open, try creating the entry.
  result = CreateEntry(key, request_priority, std::move(split_callback.second));
  if (result.net_error() == OK || result.net_error() == ERR_IO_PENDING) {
    return result;
  }

  return EntryResult::MakeError(ERR_CACHE_OPEN_OR_CREATE_FAILURE);
}

disk_cache::EntryResult MockDiskCache::OpenEntry(
    const std::string& key,
    RequestPriority request_priority,
    EntryResultCallback callback) {
  DCHECK(!callback.is_null());
  if (force_fail_callback_later_) {
    CallbackLater(base::BindOnce(
        std::move(callback), EntryResult::MakeError(ERR_CACHE_OPEN_FAILURE)));
    return EntryResult::MakeError(ERR_IO_PENDING);
  }

  if (fail_requests_) {
    return EntryResult::MakeError(ERR_CACHE_OPEN_FAILURE);
  }

  auto it = entries_.find(key);
  if (it == entries_.end()) {
    return EntryResult::MakeError(ERR_CACHE_OPEN_FAILURE);
  }

  if (it->second->is_doomed()) {
    it->second->Release();
    entries_.erase(it);
    return EntryResult::MakeError(ERR_CACHE_OPEN_FAILURE);
  }

  open_count_++;

  MockDiskEntry* entry = it->second;
  entry->AddRef();

  if (soft_failures_ || soft_failures_one_instance_) {
    entry->set_fail_requests(soft_failures_ | soft_failures_one_instance_);
    soft_failures_one_instance_ = 0;
  }

  entry->set_max_file_size(max_file_size_);

  EntryResult result = EntryResult::MakeOpened(entry);
  if (GetTestModeForEntry(key) & TEST_MODE_SYNC_CACHE_START) {
    return result;
  }

  CallbackLater(base::BindOnce(std::move(callback), std::move(result)));
  return EntryResult::MakeError(ERR_IO_PENDING);
}

disk_cache::EntryResult MockDiskCache::CreateEntry(
    const std::string& key,
    RequestPriority request_priority,
    EntryResultCallback callback) {
  DCHECK(!callback.is_null());
  if (force_fail_callback_later_) {
    CallbackLater(base::BindOnce(
        std::move(callback), EntryResult::MakeError(ERR_CACHE_CREATE_FAILURE)));
    return EntryResult::MakeError(ERR_IO_PENDING);
  }

  if (fail_requests_) {
    return EntryResult::MakeError(ERR_CACHE_CREATE_FAILURE);
  }

  auto it = entries_.find(key);
  if (it != entries_.end()) {
    if (!it->second->is_doomed()) {
      if (double_create_check_) {
        NOTREACHED();
      } else {
        return EntryResult::MakeError(ERR_CACHE_CREATE_FAILURE);
      }
    }
    it->second->Release();
    entries_.erase(it);
  }

  create_count_++;

  MockDiskEntry* new_entry = new MockDiskEntry(key);

  new_entry->AddRef();
  entries_[key] = new_entry;

  new_entry->AddRef();

  if (soft_failures_ || soft_failures_one_instance_) {
    new_entry->set_fail_requests(soft_failures_ | soft_failures_one_instance_);
    soft_failures_one_instance_ = 0;
  }

  if (fail_sparse_requests_) {
    new_entry->set_fail_sparse_requests();
  }

  new_entry->set_max_file_size(max_file_size_);

  EntryResult result = EntryResult::MakeCreated(new_entry);
  if (GetTestModeForEntry(key) & TEST_MODE_SYNC_CACHE_START) {
    return result;
  }

  // Pause and resume.
  if (defer_op_ == MockDiskEntry::DEFER_CREATE) {
    defer_op_ = MockDiskEntry::DEFER_NONE;
    resume_callback_ = base::BindOnce(std::move(callback), std::move(result));
    return EntryResult::MakeError(ERR_IO_PENDING);
  }

  CallbackLater(base::BindOnce(std::move(callback), std::move(result)));
  return EntryResult::MakeError(ERR_IO_PENDING);
}

Error MockDiskCache::DoomEntry(const std::string& key,
                               RequestPriority request_priority,
                               CompletionOnceCallback callback) {
  DCHECK(!callback.is_null());
  if (force_fail_callback_later_) {
    CallbackLater(base::BindOnce(std::move(callback), ERR_CACHE_DOOM_FAILURE));
    return ERR_IO_PENDING;
  }

  if (fail_requests_) {
    return ERR_CACHE_DOOM_FAILURE;
  }

  auto it = entries_.find(key);
  if (it != entries_.end()) {
    it->second->Release();
    entries_.erase(it);
    doomed_count_++;
  }

  if (GetTestModeForEntry(key) & TEST_MODE_SYNC_CACHE_START) {
    return OK;
  }

  CallbackLater(base::BindOnce(std::move(callback), OK));
  return ERR_IO_PENDING;
}

Error MockDiskCache::DoomAllEntries(CompletionOnceCallback callback) {
  return ERR_NOT_IMPLEMENTED;
}

Error MockDiskCache::DoomEntriesBetween(const base::Time initial_time,
                                        const base::Time end_time,
                                        CompletionOnceCallback callback) {
  return ERR_NOT_IMPLEMENTED;
}

Error MockDiskCache::DoomEntriesSince(const base::Time initial_time,
                                      CompletionOnceCallback callback) {
  return ERR_NOT_IMPLEMENTED;
}

int64_t MockDiskCache::CalculateSizeOfAllEntries(
    Int64CompletionOnceCallback callback) {
  return ERR_NOT_IMPLEMENTED;
}

class MockDiskCache::NotImplementedIterator : public Iterator {
 public:
  EntryResult OpenNextEntry(EntryResultCallback callback) override {
    return EntryResult::MakeError(ERR_NOT_IMPLEMENTED);
  }
};

std::unique_ptr<disk_cache::Backend::Iterator> MockDiskCache::CreateIterator() {
  return std::make_unique<NotImplementedIterator>();
}

void MockDiskCache::GetStats(base::StringPairs* stats) {}

void MockDiskCache::OnExternalCacheHit(const std::string& key) {
  external_cache_hits_.push_back(key);
}

uint8_t MockDiskCache::GetEntryInMemoryData(const std::string& key) {
  if (!support_in_memory_entry_data_) {
    return 0;
  }

  auto it = entries_.find(key);
  if (it != entries_.end()) {
    return it->second->in_memory_data();
  }
  return 0;
}

void MockDiskCache::SetEntryInMemoryData(const std::string& key, uint8_t data) {
  auto it = entries_.find(key);
  if (it != entries_.end()) {
    it->second->set_in_memory_data(data);
  }
}

int64_t MockDiskCache::MaxFileSize() const {
  return max_file_size_;
}

void MockDiskCache::ReleaseAll() {
  for (auto entry : entries_) {
    entry.second->Release();
  }
  entries_.clear();
}

void MockDiskCache::CallbackLater(base::OnceClosure callback) {
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, std::move(callback));
}

bool MockDiskCache::IsDiskEntryDoomed(const std::string& key) {
  auto it = entries_.find(key);
  if (it != entries_.end()) {
    return it->second->is_doomed();
  }

  return false;
}

void MockDiskCache::ResumeCacheOperation() {
  DCHECK(!resume_callback_.is_null());
  CallbackLater(std::move(resume_callback_));
}

scoped_refptr<MockDiskEntry> MockDiskCache::GetDiskEntryRef(
    const std::string& key) {
  auto it = entries_.find(key);
  if (it == entries_.end()) {
    return nullptr;
  }
  return it->second.get();
}

const std::vector<std::string>& MockDiskCache::GetExternalCacheHits() const {
  return external_cache_hits_;
}

//-----------------------------------------------------------------------------

disk_cache::BackendResult MockBackendFactory::CreateBackend(
    NetLog* net_log,
    disk_cache::BackendResultCallback callback) {
  return disk_cache::BackendResult::Make(std::make_unique<MockDiskCache>());
}

//-----------------------------------------------------------------------------

MockHttpCache::MockHttpCache()
    : MockHttpCache(std::make_unique<MockBackendFactory>()) {}

MockHttpCache::MockHttpCache(
    std::unique_ptr<HttpCache::BackendFactory> disk_cache_factory)
    : http_cache_(std::make_unique<MockNetworkLayer>(),
                  std::move(disk_cache_factory)) {}

disk_cache::Backend* MockHttpCache::backend() {
  TestGetBackendCompletionCallback cb;
  HttpCache::GetBackendResult result = http_cache_.GetBackend(cb.callback());
  result = cb.GetResult(result);
  return (result.first == OK) ? result.second : nullptr;
}

MockDiskCache* MockHttpCache::disk_cache() {
  return static_cast<MockDiskCache*>(backend());
}

int MockHttpCache::CreateTransaction(std::unique_ptr<HttpTransaction>* trans) {
  return http_cache_.CreateTransaction(DEFAULT_PRIORITY, trans);
}

void MockHttpCache::SimulateCacheLockTimeout() {
  http_cache_.SimulateCacheLockTimeoutForTesting();
}

void MockHttpCache::SimulateCacheLockTimeoutAfterHeaders() {
  http_cache_.SimulateCacheLockTimeoutAfterHeadersForTesting();
}

void MockHttpCache::FailConditionalizations() {
  http_cache_.FailConditionalizationForTest();
}

bool MockHttpCache::ReadResponseInfo(disk_cache::Entry* disk_entry,
                                     HttpResponseInfo* response_info,
                                     bool* response_truncated) {
  int size = disk_entry->GetDataSize(0);

  TestCompletionCallback cb;
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(size);
  int rv = disk_entry->ReadData(0, 0, buffer.get(), size, cb.callback());
  rv = cb.GetResult(rv);
  EXPECT_EQ(size, rv);

  return HttpCache::ParseResponseInfo(buffer->span(), response_info,
                                      response_truncated);
}

bool MockHttpCache::WriteResponseInfo(disk_cache::Entry* disk_entry,
                                      const HttpResponseInfo* response_info,
                                      bool skip_transient_headers,
                                      bool response_truncated) {
  base::Pickle pickle;
  response_info->Persist(&pickle, skip_transient_headers, response_truncated);

  TestCompletionCallback cb;
  int len = static_cast<int>(pickle.size());
  auto data = base::MakeRefCounted<WrappedIOBuffer>(pickle);

  int rv = disk_entry->WriteData(0, 0, data.get(), len, cb.callback(), true);
  rv = cb.GetResult(rv);
  return (rv == len);
}

bool MockHttpCache::OpenBackendEntry(const std::string& key,
                                     disk_cache::Entry** entry) {
  TestEntryResultCompletionCallback cb;
  disk_cache::EntryResult result =
      backend()->OpenEntry(key, HIGHEST, cb.callback());
  result = cb.GetResult(std::move(result));
  if (result.net_error() == OK) {
    *entry = result.ReleaseEntry();
    return true;
  } else {
    return false;
  }
}

bool MockHttpCache::CreateBackendEntry(const std::string& key,
                                       disk_cache::Entry** entry,
                                       NetLog* net_log) {
  TestEntryResultCompletionCallback cb;
  disk_cache::EntryResult result =
      backend()->CreateEntry(key, HIGHEST, cb.callback());
  result = cb.GetResult(std::move(result));
  if (result.net_error() == OK) {
    *entry = result.ReleaseEntry();
    return true;
  } else {
    return false;
  }
}

// Static.
int MockHttpCache::GetTestMode(int test_mode) {
  if (!g_test_mode) {
    return test_mode;
  }

  return g_test_mode;
}

// Static.
void MockHttpCache::SetTestMode(int test_mode) {
  g_test_mode = test_mode;
}

bool MockHttpCache::IsWriterPresent(const std::string& key) {
  auto entry = http_cache_.GetActiveEntry(key);
  return entry && entry->HasWriters() && !entry->writers()->IsEmpty();
}

bool MockHttpCache::IsHeadersTransactionPresent(const std::string& key) {
  auto entry = http_cache_.GetActiveEntry(key);
  return entry && entry->headers_transaction();
}

int MockHttpCache::GetCountReaders(const std::string& key) {
  auto entry = http_cache_.GetActiveEntry(key);
  return entry ? entry->readers().size() : 0;
}

int MockHttpCache::GetCountAddToEntryQueue(const std::string& key) {
  auto entry = http_cache_.GetActiveEntry(key);
  return entry ? entry->add_to_entry_queue().size() : 0;
}

int MockHttpCache::GetCountDoneHeadersQueue(const std::string& key) {
  auto entry = http_cache_.GetActiveEntry(key);
  return entry ? entry->done_headers_queue().size() : 0;
}

int MockHttpCache::GetCountWriterTransactions(const std::string& key) {
  auto entry = http_cache_.GetActiveEntry(key);
  return entry && entry->writers() ? entry->writers()->GetTransactionsCount()
                                   : 0;
}

base::WeakPtr<HttpCache> MockHttpCache::GetWeakPtr() {
  return http_cache_.GetWeakPtr();
}

//-----------------------------------------------------------------------------

disk_cache::EntryResult MockDiskCacheNoCB::CreateEntry(
    const std::string& key,
    RequestPriority request_priority,
    EntryResultCallback callback) {
  return EntryResult::MakeError(ERR_IO_PENDING);
}

//-----------------------------------------------------------------------------

disk_cache::BackendResult MockBackendNoCbFactory::CreateBackend(
    NetLog* net_log,
    disk_cache::BackendResultCallback callback) {
  return disk_cache::BackendResult::Make(std::make_unique<MockDiskCacheNoCB>());
}

//-----------------------------------------------------------------------------

MockBlockingBackendFactory::MockBlockingBackendFactory() = default;
MockBlockingBackendFactory::~MockBlockingBackendFactory() = default;

disk_cache::BackendResult MockBlockingBackendFactory::CreateBackend(
    NetLog* net_log,
    disk_cache::BackendResultCallback callback) {
  if (!block_) {
    return MakeResult();
  }

  callback_ = std::move(callback);
  return disk_cache::BackendResult::MakeError(ERR_IO_PENDING);
}

void MockBlockingBackendFactory::FinishCreation() {
  block_ = false;
  if (!callback_.is_null()) {
    // Running the callback might delete |this|.
    std::move(callback_).Run(MakeResult());
  }
}

disk_cache::BackendResult MockBlockingBackendFactory::MakeResult() {
  if (fail_) {
    return disk_cache::BackendResult::MakeError(ERR_FAILED);
  } else {
    return disk_cache::BackendResult::Make(std::make_unique<MockDiskCache>());
  }
}

}  // namespace net

"""

```