Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Core Purpose:** The initial overview section is crucial. It states, "The main entry point is CertNetFetcherURLRequest. This is an implementation of CertNetFetcher that provides a service for fetching network requests."  This immediately tells us the primary function: fetching URLs. The description of synchronous interface with asynchronous implementation is also key.

2. **Identify Key Classes and Their Roles:**  The overview then lists the main classes and their thread affinity. This is vital for understanding the code's structure and how data flows. I would make a mental or physical note of these:

    * **CertNetFetcherURLRequest:** The main entry point, handles requests from the caller thread, and coordinates with the network thread.
    * **RequestCore:**  A bridge between threads, holding the result and a signal for completion.
    * **CertNetFetcherRequestImpl:**  A wrapper on the caller thread for cancellation and waiting.
    * **AsyncCertNetFetcherURLRequest:** The workhorse on the network thread, managing requests, deduplication, timeouts, and using `URLRequest`.
    * **Job:** Represents a single URL fetch, including the `URLRequest` and related logic.

3. **Trace the Request Flow (Mental Execution):**  Imagine a caller wanting to fetch a URL. How does it flow through these classes?

    * Caller thread calls `CertNetFetcherURLRequest::Fetch...`.
    * `CertNetFetcherURLRequest` creates a `RequestCore` and posts a task to the network thread (`DoFetchOnNetworkSequence`).
    * On the network thread, `AsyncCertNetFetcherURLRequest::Fetch` is called.
    * `AsyncCertNetFetcherURLRequest` checks for existing `Job` (deduplication).
    * If no existing `Job`, a new one is created.
    * The `RequestCore` is attached to the `Job`.
    * The `Job` starts a `URLRequest`.
    * The `URLRequest` completes (success or failure).
    * The `Job` signals the `RequestCore` with the result.
    * The caller thread waits on the `RequestCore`'s signal.

4. **Look for Specific Functionality:**  Scan the code for keywords and patterns related to the request. Pay attention to:

    * **URL Handling:**  `GURL`, URL manipulation.
    * **HTTP Methods:**  GET, POST (though POST is noted as TODO).
    * **Timeouts:** `base::TimeDelta`, timers.
    * **Error Handling:**  `net::Error`.
    * **Response Handling:**  Reading the response body, maximum size limits.
    * **Threading and Synchronization:** `base::WaitableEvent`, task posting.
    * **Network Stack Integration:** `URLRequest`, `URLRequestContext`.
    * **Deduplication:**  The logic in `AsyncCertNetFetcherURLRequest::FindJob` and how `Job`s are reused.

5. **Address the Specific Questions:** Now, go back to the prompt's requirements:

    * **Functionality Listing:**  Summarize the key actions of the code based on the above analysis.
    * **Relationship with JavaScript:**  This requires understanding where this code fits in the Chromium architecture. Recognize that network requests initiated by JavaScript (e.g., `fetch()`, `XMLHttpRequest`) eventually go through the network stack where this code resides.
    * **Logic Reasoning (Hypothetical Input/Output):**  Choose a simple scenario, like fetching a small, successful HTTP URL, and trace the expected flow and data. Consider edge cases like timeouts or errors.
    * **User/Programming Errors:** Think about common mistakes when *using* a networking API like this. For example, not handling errors, incorrect URLs, or exceeding response size limits.
    * **User Steps to Reach the Code (Debugging Clues):** Consider the user actions that trigger certificate validation, which is the stated use case for this code. Navigating to HTTPS sites is the primary trigger.

6. **Refine and Organize:**  Structure the findings clearly, using headings and bullet points. Provide concrete examples where possible. For the JavaScript interaction, explain the *indirect* relationship. For errors, give specific code snippets or scenarios.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This code directly handles JavaScript `fetch()` calls."  **Correction:** Realize that this is a lower-level component of the network stack. JavaScript interacts with higher-level APIs that *eventually* utilize this kind of code.
* **Initial thought:**  Focus on the `URLRequest` only. **Correction:**  Recognize the importance of the other classes like `RequestCore` and `AsyncCertNetFetcherURLRequest` in managing the asynchronous nature and thread safety.
* **Initial thought:**  Omit error handling details. **Correction:**  Realize that error handling is a crucial aspect of networking code and should be included in the functionality description and error examples.
* **Initial thought:**  Provide a very technical explanation of deduplication. **Correction:** Simplify the explanation to focus on the benefit (avoiding redundant requests) rather than overly complex internal details.

By following these steps, progressively understanding the code's purpose, structure, and specific functions, you can effectively answer the questions posed in the prompt. The key is to start with the high-level overview and then delve into the details, constantly relating the parts back to the overall goal.
这个文件 `net/cert_net/cert_net_fetcher_url_request.cc` 是 Chromium 网络栈中用于实现证书网络获取功能的一部分。 它提供了一种通过 `URLRequest` 发起网络请求以获取证书相关数据的机制，例如 CRL (证书吊销列表), OCSP (在线证书状态协议) 响应和 AIA (Authority Information Access) 信息。

下面是它的功能列表以及对你提出问题的解答：

**功能列表:**

1. **发起和管理网络请求:**  `CertNetFetcherURLRequest` 是 `CertNetFetcher` 接口的一个实现，它使用 `URLRequest` 来进行实际的网络数据获取。
2. **同步接口，异步实现:**  提供同步的 `CertNetFetcher` 接口给调用者，允许他们发起请求并等待结果。 但实际的网络请求是在网络线程上异步执行的。
3. **线程安全:** 该类及其相关类设计为跨线程工作，允许调用者线程发起请求，而实际的网络操作在网络线程上进行。
4. **请求取消:**  允许调用者取消正在进行的网络请求。
5. **请求等待:**  允许调用者阻塞当前线程，直到网络请求完成并获取结果。
6. **请求去重 (Deduplication):**  `AsyncCertNetFetcherURLRequest` 负责管理正在进行的请求，并会尝试去重具有相同参数的请求，以避免不必要的网络流量。
7. **超时处理:**  可以为网络请求设置超时时间，防止请求无限期地挂起。
8. **限制响应大小:**  可以配置获取不同类型证书数据（CRL, AIA/OCSP）的最大响应大小，防止下载过大的文件。
9. **处理重定向:**  能够处理 HTTP 重定向。
10. **错误处理:**  报告网络请求过程中发生的错误。

**与 JavaScript 功能的关系:**

`net/cert_net/cert_net_fetcher_url_request.cc` 本身并不直接与 JavaScript 代码交互。然而，它在 Chromium 的网络栈中扮演着重要的角色，而网络栈是 JavaScript 发起的网络请求的基础设施。

**举例说明:**

当一个 JavaScript 代码通过 `fetch()` API 或 `XMLHttpRequest` 发起一个 HTTPS 请求时，浏览器需要验证服务器的 SSL/TLS 证书。 在证书验证过程中，浏览器可能会遇到需要获取额外信息的场景，例如：

* **获取 CRL:**  检查证书是否已被吊销。
* **获取 OCSP 响应:**  向 OCSP 服务器查询证书的当前状态。
* **获取 AIA 信息:**  获取颁发机构的证书或其他中间证书。

在这种情况下，Chromium 的证书验证器 (Certificate Verifier) 会使用 `CertNetFetcher` 接口来发起这些额外的网络请求。 `CertNetFetcherURLRequest` 就是 `CertNetFetcher` 的一个实现，负责使用 `URLRequest` 来完成这些获取操作。

**所以，虽然 JavaScript 代码不直接调用 `CertNetFetcherURLRequest` 中的函数，但当 JavaScript 发起 HTTPS 请求时，这个文件中的代码会被 Chromium 的内部机制调用，以完成证书链的验证。**

**逻辑推理 (假设输入与输出):**

**假设输入:**

* 调用者线程调用 `CertNetFetcherURLRequest::FetchOcsp`，并提供一个 OCSP 服务器的 URL (`http://ocsp.example.com/`).
* 超时时间设置为 1000 毫秒。
* 假设网络连接正常，OCSP 服务器返回一个有效的 OCSP 响应。

**输出:**

1. `CertNetFetcherURLRequest::FetchOcsp` 会创建一个 `RequestCore` 对象，用于跟踪请求的状态。
2. 一个包含请求参数的 `RequestParams` 对象会被创建，包括 OCSP URL，GET 方法，以及设置的超时时间和最大响应大小。
3. 一个任务会被 Post 到网络线程，调用 `CertNetFetcherURLRequest::DoFetchOnNetworkSequence`。
4. 在网络线程上，`AsyncCertNetFetcherURLRequest` 会检查是否已经存在相同的请求。 如果没有，会创建一个新的 `Job` 对象来处理这个请求。
5. `Job` 对象会创建一个 `URLRequest` 对象，向 `http://ocsp.example.com/` 发起 GET 请求。
6. `URLRequest` 完成后，`Job` 对象会将 OCSP 响应数据存储在 `response_body_` 中。
7. `Job` 对象会调用 `RequestCore::OnJobCompleted`，将结果（成功，包含 OCSP 响应数据）传递回调用者线程。
8. 调用者线程上的 `CertNetFetcher::Request` 对象（`CertNetFetcherRequestImpl`）会收到通知，并且当调用者调用 `WaitForResult` 时，会返回 `OK` 错误码和 OCSP 响应数据。

**如果假设输入中 OCSP 服务器返回错误 (例如 HTTP 404):**

* 输出结果中的错误码将会是 `ERR_HTTP_RESPONSE_CODE_FAILURE`，并且响应数据可能为空或包含错误信息。

**如果假设输入中网络超时:**

* 输出结果中的错误码将会是 `ERR_TIMED_OUT`，并且响应数据为空。

**用户或编程常见的使用错误:**

1. **未在网络线程上创建和销毁 `CertNetFetcherURLRequest`:**  代码注释明确指出 `CertNetFetcherURLRequest` 必须在网络线程上创建和销毁。 如果在错误的线程上进行操作，会导致崩溃或未定义的行为。

   ```c++
   // 错误示例 (假设当前线程不是网络线程)
   auto fetcher = std::make_unique<net::CertNetFetcherURLRequest>();
   // ... 使用 fetcher ...
   // 错误：析构函数应该在网络线程上调用
   fetcher.reset();
   ```

2. **在调用 `WaitForResult` 后重复调用:** `WaitForResult` 旨在被调用一次以获取结果。 重复调用会导致断言失败或未定义的行为。

   ```c++
   net::Error error;
   std::vector<uint8_t> data;
   auto request = fetcher->FetchOcsp(url);
   request->WaitForResult(&error, &data);
   // 错误：不应该再次调用 WaitForResult
   // request->WaitForResult(&error, &data);
   ```

3. **在错误的线程上调用 `WaitForResult`:**  `WaitForResult` 应该在创建请求的线程上调用（通常是非网络线程，即调用者线程）。在网络线程上调用 `WaitForResult` 可能会导致死锁。

4. **忘记处理错误:**  调用 `WaitForResult` 后，必须检查返回的 `error` 代码，以确定请求是否成功。忽略错误可能导致程序逻辑错误。

   ```c++
   net::Error error;
   std::vector<uint8_t> data;
   auto request = fetcher->FetchOcsp(url);
   request->WaitForResult(&error, &data);
   // 正确的做法是检查 error
   if (error != net::OK) {
       // 处理错误
       LOG(ERROR) << "Failed to fetch OCSP: " << error;
   }
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

当用户进行以下操作时，可能会触发 `net/cert_net/cert_net_fetcher_url_request.cc` 中的代码：

1. **用户访问 HTTPS 网站:** 这是最常见的情况。当用户在浏览器地址栏中输入一个 `https://` 开头的 URL 并访问时，浏览器需要验证服务器的证书。
2. **浏览器遇到需要额外信息的证书链:**  在证书验证过程中，如果浏览器发现证书链中缺少必要的信息，例如 CRL 分发点或 AIA 扩展，它会尝试获取这些信息。
3. **证书验证器 (Certificate Verifier) 发起网络请求:** Chromium 的证书验证器会使用 `CertNetFetcher` 接口来发起获取 CRL、OCSP 响应或 AIA 信息的网络请求。
4. **`CertNetFetcherURLRequest` 被调用:** 作为 `CertNetFetcher` 的实现，`CertNetFetcherURLRequest` 会接收到这些请求，并创建相应的 `URLRequest` 对象。

**作为调试线索:**

* **检查网络日志 (NetLog):**  Chromium 的 NetLog 可以记录详细的网络请求信息，包括由 `CertNetFetcherURLRequest` 发起的请求。你可以查看请求的 URL、状态码、耗时等信息，以判断是否是因为证书相关的网络请求失败导致问题。
* **证书错误信息:**  如果证书验证失败，浏览器通常会显示相关的错误信息。这些错误信息可能指示是由于无法获取 CRL 或 OCSP 响应导致的。
* **开发者工具 -> 安全:**  在 Chrome 的开发者工具的 "安全" 标签页中，可以查看当前网站的证书信息，包括 CRL 和 OCSP 的信息。如果这些信息的加载状态显示失败，可能就与 `CertNetFetcherURLRequest` 有关。
* **断点调试:**  如果你正在开发或调试 Chromium，可以在 `net/cert_net/cert_net_fetcher_url_request.cc` 中设置断点，跟踪网络请求的创建、执行和完成过程，以查找问题的原因。

总而言之，`net/cert_net/cert_net_fetcher_url_request.cc` 是 Chromium 网络栈中一个关键的组成部分，负责在证书验证过程中获取必要的网络资源，以确保安全连接。虽然用户和 JavaScript 代码不直接与之交互，但它的正常运作对于 HTTPS 连接的建立至关重要。

Prompt: 
```
这是目录为net/cert_net/cert_net_fetcher_url_request.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Overview
//
// The main entry point is CertNetFetcherURLRequest. This is an implementation
// of CertNetFetcher that provides a service for fetching network requests.
//
// The interface for CertNetFetcher is synchronous, however allows
// overlapping requests. When starting a request CertNetFetcherURLRequest
// returns a CertNetFetcher::Request (CertNetFetcherRequestImpl) that the
// caller can use to cancel the fetch, or wait for it to complete
// (blocking).
//
// The CertNetFetcherURLRequest is shared between a network thread and a
// caller thread that waits for fetches to happen on the network thread.
//
// The classes are mainly organized based on their thread affinity:
//
// ---------------
// Straddles caller thread and network thread
// ---------------
//
// CertNetFetcherURLRequest (implements CertNetFetcher)
//   * Main entry point. Must be created and shutdown from the network thread.
//   * Provides a service to start/cancel/wait for URL fetches, to be
//     used on the caller thread.
//   * Returns callers a CertNetFetcher::Request as a handle
//   * Requests can run in parallel, however will block the current thread when
//     reading results.
//   * Posts tasks to network thread to coordinate actual work
//
// RequestCore
//   * Reference-counted bridge between CertNetFetcherRequestImpl and the
//     dependencies on the network thread
//   * Holds the result of the request, a WaitableEvent for signaling
//     completion, and pointers for canceling work on network thread.
//
// ---------------
// Lives on caller thread
// ---------------
//
// CertNetFetcherRequestImpl (implements CertNetFetcher::Request)
//   * Wrapper for cancelling events, or waiting for a request to complete
//   * Waits on a WaitableEvent to complete requests.
//
// ---------------
// Lives on network thread
// ---------------
//
// AsyncCertNetFetcherURLRequest
//   * Asynchronous manager for outstanding requests. Handles de-duplication,
//     timeouts, and actual integration with network stack. This is where the
//     majority of the logic lives.
//   * Signals completion of requests through RequestCore's WaitableEvent.
//   * Attaches requests to Jobs for the purpose of de-duplication

#include "net/cert_net/cert_net_fetcher_url_request.h"

#include <memory>
#include <tuple>
#include <utility>

#include "base/check_op.h"
#include "base/containers/extend.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/not_fatal_until.h"
#include "base/numerics/safe_math.h"
#include "base/ranges/algorithm.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "net/base/io_buffer.h"
#include "net/base/isolation_info.h"
#include "net/base/load_flags.h"
#include "net/cert/cert_net_fetcher.h"
#include "net/cookies/site_for_cookies.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/url_request/redirect_info.h"
#include "net/url_request/url_request_context.h"
#include "url/origin.h"

// TODO(eroman): Add support for POST parameters.
// TODO(eroman): Add controls for bypassing the cache.
// TODO(eroman): Add a maximum number of in-flight jobs/requests.
// TODO(eroman): Add NetLog integration.

namespace net {

namespace {

// The size of the buffer used for reading the response body of the URLRequest.
const int kReadBufferSizeInBytes = 4096;

// The maximum size in bytes for the response body when fetching a CRL.
const int kMaxResponseSizeInBytesForCrl = 5 * 1024 * 1024;

// The maximum size in bytes for the response body when fetching an AIA URL
// (caIssuers/OCSP).
const int kMaxResponseSizeInBytesForAia = 64 * 1024;

// The default timeout in seconds for fetch requests.
const int kTimeoutSeconds = 15;

class Job;

struct JobToRequestParamsComparator;

struct JobComparator {
  bool operator()(const Job* job1, const Job* job2) const;
};

// Would be a set<unique_ptr> but extraction of owned objects from a set of
// owned types doesn't come until C++17.
using JobSet = std::map<Job*, std::unique_ptr<Job>, JobComparator>;

}  // namespace

// AsyncCertNetFetcherURLRequest manages URLRequests in an async fashion on the
// URLRequestContexts's task runner thread.
//
//  * Schedules
//  * De-duplicates requests
//  * Handles timeouts
class CertNetFetcherURLRequest::AsyncCertNetFetcherURLRequest {
 public:
  // Initializes AsyncCertNetFetcherURLRequest using the specified
  // URLRequestContext for issuing requests. |context| must remain valid until
  // Shutdown() is called or the AsyncCertNetFetcherURLRequest is destroyed.
  explicit AsyncCertNetFetcherURLRequest(URLRequestContext* context);

  AsyncCertNetFetcherURLRequest(const AsyncCertNetFetcherURLRequest&) = delete;
  AsyncCertNetFetcherURLRequest& operator=(
      const AsyncCertNetFetcherURLRequest&) = delete;

  // The AsyncCertNetFetcherURLRequest is expected to be kept alive until all
  // requests have completed or Shutdown() is called.
  ~AsyncCertNetFetcherURLRequest();

  // Starts an asynchronous request to fetch the given URL. On completion
  // request->OnJobCompleted() will be invoked.
  void Fetch(std::unique_ptr<RequestParams> request_params,
             scoped_refptr<RequestCore> request);

  // Removes |job| from the in progress jobs and transfers ownership to the
  // caller.
  std::unique_ptr<Job> RemoveJob(Job* job);

  // Cancels outstanding jobs, which stops network requests and signals the
  // corresponding RequestCores that the requests have completed.
  void Shutdown();

 private:
  // Finds a job with a matching RequestPararms or returns nullptr if there was
  // no match.
  Job* FindJob(const RequestParams& params);

  // The in-progress jobs. This set does not contain the job which is actively
  // invoking callbacks (OnJobCompleted).
  JobSet jobs_;

  // Not owned. |context_| must outlive the AsyncCertNetFetcherURLRequest.
  raw_ptr<URLRequestContext> context_ = nullptr;

  THREAD_CHECKER(thread_checker_);
};

namespace {

// Policy for which URLs are allowed to be fetched. This is called both for the
// initial URL and for each redirect. Returns OK on success or a net error
// code on failure.
Error CanFetchUrl(const GURL& url) {
  if (!url.SchemeIs("http"))
    return ERR_DISALLOWED_URL_SCHEME;
  return OK;
}

base::TimeDelta GetTimeout(int timeout_milliseconds) {
  if (timeout_milliseconds == CertNetFetcher::DEFAULT)
    return base::Seconds(kTimeoutSeconds);
  return base::Milliseconds(timeout_milliseconds);
}

size_t GetMaxResponseBytes(int max_response_bytes,
                           size_t default_max_response_bytes) {
  if (max_response_bytes == CertNetFetcher::DEFAULT)
    return default_max_response_bytes;

  // Ensure that the specified limit is not negative, and cannot result in an
  // overflow while reading.
  base::CheckedNumeric<size_t> check(max_response_bytes);
  check += kReadBufferSizeInBytes;
  DCHECK(check.IsValid());

  return max_response_bytes;
}

enum HttpMethod {
  HTTP_METHOD_GET,
  HTTP_METHOD_POST,
};

}  // namespace

// RequestCore tracks an outstanding call to Fetch(). It is
// reference-counted for ease of sharing between threads.
class CertNetFetcherURLRequest::RequestCore
    : public base::RefCountedThreadSafe<RequestCore> {
 public:
  explicit RequestCore(scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : completion_event_(base::WaitableEvent::ResetPolicy::MANUAL,
                          base::WaitableEvent::InitialState::NOT_SIGNALED),
        task_runner_(std::move(task_runner)) {}

  RequestCore(const RequestCore&) = delete;
  RequestCore& operator=(const RequestCore&) = delete;

  void AttachedToJob(Job* job) {
    DCHECK(task_runner_->RunsTasksInCurrentSequence());
    DCHECK(!job_);
    // Requests should not be attached to jobs after they have been signalled
    // with a cancellation error (which happens via either Cancel() or
    // SignalImmediateError()).
    DCHECK_NE(error_, ERR_ABORTED);
    job_ = job;
  }

  void OnJobCompleted(Job* job,
                      Error error,
                      const std::vector<uint8_t>& response_body) {
    DCHECK(task_runner_->RunsTasksInCurrentSequence());

    DCHECK_EQ(job_, job);
    job_ = nullptr;

    error_ = error;
    bytes_ = response_body;
    completion_event_.Signal();
  }

  // Detaches this request from its job (if it is attached to any) and
  // signals completion with ERR_ABORTED. Can be called from any thread.
  void CancelJob();

  // Can be used to signal that an error was encountered before the request was
  // attached to a job. Can be called from any thread.
  void SignalImmediateError();

  // Should only be called once.
  void WaitForResult(Error* error, std::vector<uint8_t>* bytes) {
    DCHECK(!task_runner_->RunsTasksInCurrentSequence());

    completion_event_.Wait();
    *bytes = std::move(bytes_);
    *error = error_;

    error_ = ERR_UNEXPECTED;
  }

 private:
  friend class base::RefCountedThreadSafe<RequestCore>;

  ~RequestCore() {
    // Requests should have been cancelled prior to destruction.
    DCHECK(!job_);
  }

  // A non-owned pointer to the job that is executing the request.
  raw_ptr<Job> job_ = nullptr;

  // May be written to from network thread, or from the caller thread only when
  // there is no work that will be done on the network thread (e.g. when the
  // network thread has been shutdown before the request begins). See comment in
  // SignalImmediateError.
  Error error_ = OK;
  std::vector<uint8_t> bytes_;

  // Indicates when |error_| and |bytes_| have been written to.
  base::WaitableEvent completion_event_;

  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
};

struct CertNetFetcherURLRequest::RequestParams {
  RequestParams();

  RequestParams(const RequestParams&) = delete;
  RequestParams& operator=(const RequestParams&) = delete;

  bool operator<(const RequestParams& other) const;

  GURL url;
  HttpMethod http_method = HTTP_METHOD_GET;
  size_t max_response_bytes = 0;

  // If set to a value <= 0 then means "no timeout".
  base::TimeDelta timeout;

  // IMPORTANT: When adding fields to this structure, update operator<().
};

CertNetFetcherURLRequest::RequestParams::RequestParams() = default;

bool CertNetFetcherURLRequest::RequestParams::operator<(
    const RequestParams& other) const {
  return std::tie(url, http_method, max_response_bytes, timeout) <
         std::tie(other.url, other.http_method, other.max_response_bytes,
                  other.timeout);
}

namespace {

// Job tracks an outstanding URLRequest as well as all of the pending requests
// for it.
class Job : public URLRequest::Delegate {
 public:
  Job(std::unique_ptr<CertNetFetcherURLRequest::RequestParams> request_params,
      CertNetFetcherURLRequest::AsyncCertNetFetcherURLRequest* parent);

  Job(const Job&) = delete;
  Job& operator=(const Job&) = delete;

  ~Job() override;

  const CertNetFetcherURLRequest::RequestParams& request_params() const {
    return *request_params_;
  }

  // Creates a request and attaches it to the job. When the job completes it
  // will notify the request of completion through OnJobCompleted.
  void AttachRequest(
      scoped_refptr<CertNetFetcherURLRequest::RequestCore> request);

  // Removes |request| from the job.
  void DetachRequest(CertNetFetcherURLRequest::RequestCore* request);

  // Creates and starts a URLRequest for the job. After the URLRequest has
  // completed, OnJobCompleted() will be invoked and all the registered requests
  // notified of completion.
  void StartURLRequest(URLRequestContext* context);

  // Cancels the request with an ERR_ABORTED error and invokes
  // RequestCore::OnJobCompleted() to notify the registered requests of the
  // cancellation. The job is *not* removed from the
  // AsyncCertNetFetcherURLRequest.
  void Cancel();

 private:
  // Implementation of URLRequest::Delegate
  void OnReceivedRedirect(URLRequest* request,
                          const RedirectInfo& redirect_info,
                          bool* defer_redirect) override;
  void OnResponseStarted(URLRequest* request, int net_error) override;
  void OnReadCompleted(URLRequest* request, int bytes_read) override;

  // Clears the URLRequest and timer. Helper for doing work common to
  // cancellation and job completion.
  void Stop();

  // Reads as much data as available from |request|.
  void ReadBody(URLRequest* request);

  // Helper to copy the partial bytes read from the read IOBuffer to an
  // aggregated buffer.
  bool ConsumeBytesRead(URLRequest* request, int num_bytes);

  // Called when the URLRequest has completed (either success or failure).
  void OnUrlRequestCompleted(int net_error);

  // Called when the Job has completed. The job may finish in response to a
  // timeout, an invalid URL, or the URLRequest completing. By the time this
  // method is called, the |response_body_| variable have been assigned.
  void OnJobCompleted(Error error);

  // Calls r->OnJobCompleted() for each RequestCore |r| currently attached
  // to this job, and then clears |requests_|.
  void CompleteAndClearRequests(Error error);

  // Cancels a request with a specified error code and calls
  // OnUrlRequestCompleted().
  void FailRequest(Error error);

  // The requests attached to this job.
  std::vector<scoped_refptr<CertNetFetcherURLRequest::RequestCore>> requests_;

  // The input parameters for starting a URLRequest.
  std::unique_ptr<CertNetFetcherURLRequest::RequestParams> request_params_;

  // The URLRequest response information.
  std::vector<uint8_t> response_body_;

  std::unique_ptr<URLRequest> url_request_;
  scoped_refptr<IOBuffer> read_buffer_;

  // Used to timeout the job when the URLRequest takes too long. This timer is
  // also used for notifying a failure to start the URLRequest.
  base::OneShotTimer timer_;

  // Non-owned pointer to the AsyncCertNetFetcherURLRequest that created this
  // job.
  raw_ptr<CertNetFetcherURLRequest::AsyncCertNetFetcherURLRequest> parent_;
};

}  // namespace

void CertNetFetcherURLRequest::RequestCore::CancelJob() {
  if (!task_runner_->RunsTasksInCurrentSequence()) {
    task_runner_->PostTask(FROM_HERE,
                           base::BindOnce(&RequestCore::CancelJob, this));
    return;
  }

  if (job_) {
    auto* job = job_.get();
    job_ = nullptr;
    job->DetachRequest(this);
  }

  SignalImmediateError();
}

void CertNetFetcherURLRequest::RequestCore::SignalImmediateError() {
  // These data members are normally only written on the network thread, but it
  // is safe to write here from either thread. This is because
  // SignalImmediateError is only to be called before this request is attached
  // to a job. In particular, if called from the caller thread, no work will be
  // done on the network thread for this request, so these variables will only
  // be written and read on the caller thread. If called from the network
  // thread, they will only be written to on the network thread and will not be
  // read on the caller thread until |completion_event_| is signalled (after
  // which it will be not be written on the network thread again).
  DCHECK(!job_);
  error_ = ERR_ABORTED;
  bytes_.clear();
  completion_event_.Signal();
}

namespace {

Job::Job(
    std::unique_ptr<CertNetFetcherURLRequest::RequestParams> request_params,
    CertNetFetcherURLRequest::AsyncCertNetFetcherURLRequest* parent)
    : request_params_(std::move(request_params)), parent_(parent) {}

Job::~Job() {
  DCHECK(requests_.empty());
  Stop();
}

void Job::AttachRequest(
    scoped_refptr<CertNetFetcherURLRequest::RequestCore> request) {
  request->AttachedToJob(this);
  requests_.push_back(std::move(request));
}

void Job::DetachRequest(CertNetFetcherURLRequest::RequestCore* request) {
  std::unique_ptr<Job> delete_this;

  auto it = base::ranges::find(requests_, request);
  CHECK(it != requests_.end(), base::NotFatalUntil::M130);
  requests_.erase(it);

  // If there are no longer any requests attached to the job then
  // cancel and delete it.
  if (requests_.empty())
    delete_this = parent_->RemoveJob(this);
}

void Job::StartURLRequest(URLRequestContext* context) {
  Error error = CanFetchUrl(request_params_->url);
  if (error != OK) {
    OnJobCompleted(error);
    return;
  }

  // Start the URLRequest.
  read_buffer_ = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSizeInBytes);
  NetworkTrafficAnnotationTag traffic_annotation =
      DefineNetworkTrafficAnnotation("certificate_verifier_url_request",
                                     R"(
        semantics {
          sender: "Certificate Verifier"
          description:
            "When verifying certificates, the browser may need to fetch "
            "additional URLs that are encoded in the server-provided "
            "certificate chain. This may be part of revocation checking ("
            "Online Certificate Status Protocol, Certificate Revocation List), "
            "or path building (Authority Information Access fetches). Please "
            "refer to the following for more on above protocols: "
            "https://tools.ietf.org/html/rfc6960, "
            "https://tools.ietf.org/html/rfc5280#section-4.2.1.13, and"
            "https://tools.ietf.org/html/rfc5280#section-5.2.7."
            "NOTE: this path is being deprecated. Please see the"
            "certificate_verifier_url_loader annotation for the new path."
          trigger:
            "Verifying a certificate (likely in response to navigating to an "
            "'https://' website)."
          data:
            "In the case of OCSP this may divulge the website being viewed. No "
            "user data in other cases."
          destination: OTHER
          destination_other:
            "The URL specified in the certificate."
        }
        policy {
          cookies_allowed: NO
          setting: "This feature cannot be disabled by settings."
          policy_exception_justification: "Not implemented."
        })");
  url_request_ = context->CreateRequest(request_params_->url, DEFAULT_PRIORITY,
                                        this, traffic_annotation);
  if (request_params_->http_method == HTTP_METHOD_POST)
    url_request_->set_method("POST");
  url_request_->set_allow_credentials(false);

  // Disable secure DNS for hostname lookups triggered by certificate network
  // fetches to prevent deadlock.
  url_request_->SetSecureDnsPolicy(SecureDnsPolicy::kDisable);

  // Create IsolationInfo based on the origin of the requested URL.
  // TODO(crbug.com/40104280): Cert validation needs to either be
  // double-keyed or based on a static database, to protect it from being used
  // as a cross-site user tracking vector. For now, just treat it as if it were
  // a subresource request of the origin used for the request. This allows the
  // result to still be cached in the HTTP cache, and lets URLRequest DCHECK
  // that all requests have non-empty IsolationInfos.
  url::Origin origin = url::Origin::Create(request_params_->url);
  url_request_->set_isolation_info(IsolationInfo::Create(
      IsolationInfo::RequestType::kOther, origin /* top_frame_origin */,
      origin /* frame_origin */, SiteForCookies()));

  // Ensure that we bypass HSTS for all requests sent through
  // CertNetFetcherURLRequest, since AIA/CRL/OCSP requests must be in HTTP to
  // avoid circular dependencies.
  url_request_->SetLoadFlags(url_request_->load_flags() |
                             net::LOAD_SHOULD_BYPASS_HSTS);

  url_request_->Start();

  // Start a timer to limit how long the job runs for.
  if (request_params_->timeout.is_positive()) {
    timer_.Start(FROM_HERE, request_params_->timeout,
                 base::BindOnce(&Job::FailRequest, base::Unretained(this),
                                ERR_TIMED_OUT));
  }
}

void Job::Cancel() {
  // Stop the timer and clear the URLRequest.
  Stop();
  // Signal attached requests that they've been completed.
  CompleteAndClearRequests(static_cast<Error>(ERR_ABORTED));
}

void Job::OnReceivedRedirect(URLRequest* request,
                             const RedirectInfo& redirect_info,
                             bool* defer_redirect) {
  DCHECK_EQ(url_request_.get(), request);

  // Ensure that the new URL matches the policy.
  Error error = CanFetchUrl(redirect_info.new_url);
  if (error != OK) {
    FailRequest(error);
    return;
  }
}

void Job::OnResponseStarted(URLRequest* request, int net_error) {
  DCHECK_EQ(url_request_.get(), request);
  DCHECK_NE(ERR_IO_PENDING, net_error);

  if (net_error != OK) {
    OnUrlRequestCompleted(net_error);
    return;
  }

  if (request->GetResponseCode() != 200) {
    FailRequest(ERR_HTTP_RESPONSE_CODE_FAILURE);
    return;
  }

  ReadBody(request);
}

void Job::OnReadCompleted(URLRequest* request, int bytes_read) {
  DCHECK_EQ(url_request_.get(), request);
  DCHECK_NE(ERR_IO_PENDING, bytes_read);

  // Keep reading the response body.
  if (ConsumeBytesRead(request, bytes_read))
    ReadBody(request);
}

void Job::Stop() {
  timer_.Stop();
  url_request_.reset();
}

void Job::ReadBody(URLRequest* request) {
  // Read as many bytes as are available synchronously.
  int num_bytes = 0;
  while (num_bytes >= 0) {
    num_bytes = request->Read(read_buffer_.get(), kReadBufferSizeInBytes);
    if (num_bytes == ERR_IO_PENDING)
      return;
    if (!ConsumeBytesRead(request, num_bytes))
      return;
  }

  OnUrlRequestCompleted(num_bytes);
}

bool Job::ConsumeBytesRead(URLRequest* request, int num_bytes) {
  DCHECK_NE(ERR_IO_PENDING, num_bytes);
  if (num_bytes <= 0) {
    // Error while reading, or EOF.
    OnUrlRequestCompleted(num_bytes);
    return false;
  }

  // Enforce maximum size bound.
  const auto num_bytes_s = static_cast<size_t>(num_bytes);
  if (num_bytes_s + response_body_.size() >
      request_params_->max_response_bytes) {
    FailRequest(ERR_FILE_TOO_BIG);
    return false;
  }

  // Append the data to |response_body_|.
  response_body_.reserve(response_body_.size() + num_bytes_s);
  base::Extend(response_body_, read_buffer_->span().first(num_bytes_s));
  return true;
}

void Job::OnUrlRequestCompleted(int net_error) {
  DCHECK_NE(ERR_IO_PENDING, net_error);
  Error result = static_cast<Error>(net_error);
  OnJobCompleted(result);
}

void Job::OnJobCompleted(Error error) {
  DCHECK_NE(ERR_IO_PENDING, error);
  // Stop the timer and clear the URLRequest.
  Stop();

  std::unique_ptr<Job> delete_this = parent_->RemoveJob(this);
  CompleteAndClearRequests(error);
}

void Job::CompleteAndClearRequests(Error error) {
  for (const auto& request : requests_) {
    request->OnJobCompleted(this, error, response_body_);
  }

  requests_.clear();
}

void Job::FailRequest(Error error) {
  DCHECK_NE(ERR_IO_PENDING, error);
  int result = url_request_->CancelWithError(error);
  OnUrlRequestCompleted(result);
}

}  // namespace

CertNetFetcherURLRequest::AsyncCertNetFetcherURLRequest::
    AsyncCertNetFetcherURLRequest(URLRequestContext* context)
    : context_(context) {
  // Allow creation to happen from another thread.
  DETACH_FROM_THREAD(thread_checker_);
}

CertNetFetcherURLRequest::AsyncCertNetFetcherURLRequest::
    ~AsyncCertNetFetcherURLRequest() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  jobs_.clear();
}

bool JobComparator::operator()(const Job* job1, const Job* job2) const {
  return job1->request_params() < job2->request_params();
}

void CertNetFetcherURLRequest::AsyncCertNetFetcherURLRequest::Fetch(
    std::unique_ptr<RequestParams> request_params,
    scoped_refptr<RequestCore> request) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // If there is an in-progress job that matches the request parameters use it.
  // Otherwise start a new job.
  Job* job = FindJob(*request_params);
  if (job) {
    job->AttachRequest(std::move(request));
    return;
  }

  auto new_job = std::make_unique<Job>(std::move(request_params), this);
  job = new_job.get();
  jobs_[job] = std::move(new_job);
  // Attach the request before calling StartURLRequest; this ensures that the
  // request will get signalled if StartURLRequest completes the job
  // synchronously.
  job->AttachRequest(std::move(request));
  job->StartURLRequest(context_);
}

void CertNetFetcherURLRequest::AsyncCertNetFetcherURLRequest::Shutdown() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  for (const auto& job : jobs_) {
    job.first->Cancel();
  }
  jobs_.clear();
}

namespace {

struct JobToRequestParamsComparator {
  bool operator()(const JobSet::value_type& job,
                  const CertNetFetcherURLRequest::RequestParams& value) const {
    return job.first->request_params() < value;
  }
};

}  // namespace

Job* CertNetFetcherURLRequest::AsyncCertNetFetcherURLRequest::FindJob(
    const RequestParams& params) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // The JobSet is kept in sorted order so items can be found using binary
  // search.
  auto it = std::lower_bound(jobs_.begin(), jobs_.end(), params,
                             JobToRequestParamsComparator());
  if (it != jobs_.end() && !(params < (*it).first->request_params()))
    return (*it).first;
  return nullptr;
}

std::unique_ptr<Job>
CertNetFetcherURLRequest::AsyncCertNetFetcherURLRequest::RemoveJob(Job* job) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  auto it = jobs_.find(job);
  CHECK(it != jobs_.end());
  std::unique_ptr<Job> owned_job = std::move(it->second);
  jobs_.erase(it);
  return owned_job;
}

namespace {

class CertNetFetcherRequestImpl : public CertNetFetcher::Request {
 public:
  explicit CertNetFetcherRequestImpl(
      scoped_refptr<CertNetFetcherURLRequest::RequestCore> core)
      : core_(std::move(core)) {
    DCHECK(core_);
  }

  void WaitForResult(Error* error, std::vector<uint8_t>* bytes) override {
    // Should only be called a single time.
    DCHECK(core_);
    core_->WaitForResult(error, bytes);
    core_ = nullptr;
  }

  ~CertNetFetcherRequestImpl() override {
    if (core_)
      core_->CancelJob();
  }

 private:
  scoped_refptr<CertNetFetcherURLRequest::RequestCore> core_;
};

}  // namespace

CertNetFetcherURLRequest::CertNetFetcherURLRequest()
    : task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault()) {}

CertNetFetcherURLRequest::~CertNetFetcherURLRequest() {
  // The fetcher must be shutdown (at which point |context_| will be set to
  // null) before destruction.
  DCHECK(!context_);
}

void CertNetFetcherURLRequest::SetURLRequestContext(
    URLRequestContext* context) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  context_ = context;
}

// static
base::TimeDelta CertNetFetcherURLRequest::GetDefaultTimeoutForTesting() {
  return GetTimeout(CertNetFetcher::DEFAULT);
}

void CertNetFetcherURLRequest::Shutdown() {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  if (impl_) {
    impl_->Shutdown();
    impl_.reset();
  }
  context_ = nullptr;
}

std::unique_ptr<CertNetFetcher::Request>
CertNetFetcherURLRequest::FetchCaIssuers(const GURL& url,
                                         int timeout_milliseconds,
                                         int max_response_bytes) {
  auto request_params = std::make_unique<RequestParams>();

  request_params->url = url;
  request_params->http_method = HTTP_METHOD_GET;
  request_params->timeout = GetTimeout(timeout_milliseconds);
  request_params->max_response_bytes =
      GetMaxResponseBytes(max_response_bytes, kMaxResponseSizeInBytesForAia);

  return DoFetch(std::move(request_params));
}

std::unique_ptr<CertNetFetcher::Request> CertNetFetcherURLRequest::FetchCrl(
    const GURL& url,
    int timeout_milliseconds,
    int max_response_bytes) {
  auto request_params = std::make_unique<RequestParams>();

  request_params->url = url;
  request_params->http_method = HTTP_METHOD_GET;
  request_params->timeout = GetTimeout(timeout_milliseconds);
  request_params->max_response_bytes =
      GetMaxResponseBytes(max_response_bytes, kMaxResponseSizeInBytesForCrl);

  return DoFetch(std::move(request_params));
}

std::unique_ptr<CertNetFetcher::Request> CertNetFetcherURLRequest::FetchOcsp(
    const GURL& url,
    int timeout_milliseconds,
    int max_response_bytes) {
  auto request_params = std::make_unique<RequestParams>();

  request_params->url = url;
  request_params->http_method = HTTP_METHOD_GET;
  request_params->timeout = GetTimeout(timeout_milliseconds);
  request_params->max_response_bytes =
      GetMaxResponseBytes(max_response_bytes, kMaxResponseSizeInBytesForAia);

  return DoFetch(std::move(request_params));
}

void CertNetFetcherURLRequest::DoFetchOnNetworkSequence(
    std::unique_ptr<RequestParams> request_params,
    scoped_refptr<RequestCore> request) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  if (!context_) {
    // The fetcher might have been shutdown between when this task was posted
    // and when it is running. In this case, signal the request and do not
    // start a network request.
    request->SignalImmediateError();
    return;
  }

  if (!impl_) {
    impl_ = std::make_unique<AsyncCertNetFetcherURLRequest>(context_);
  }

  impl_->Fetch(std::move(request_params), request);
}

std::unique_ptr<CertNetFetcherURLRequest::Request>
CertNetFetcherURLRequest::DoFetch(
    std::unique_ptr<RequestParams> request_params) {
  auto request_core = base::MakeRefCounted<RequestCore>(task_runner_);

  // If the fetcher has already been shutdown, DoFetchOnNetworkSequence will
  // signal the request with an error. However, if the fetcher shuts down
  // before DoFetchOnNetworkSequence runs and PostTask still returns true,
  // then the request will hang (that is, WaitForResult will not return).
  if (!task_runner_->PostTask(
          FROM_HERE,
          base::BindOnce(&CertNetFetcherURLRequest::DoFetchOnNetworkSequence,
                         this, std::move(request_params), request_core))) {
    request_core->SignalImmediateError();
  }

  return std::make_unique<CertNetFetcherRequestImpl>(std::move(request_core));
}

}  // namespace net

"""

```