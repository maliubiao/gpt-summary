Response:
Let's break down the thought process to analyze the provided C++ code for `coalescing_cert_verifier.cc`.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of this code, its relationship with JavaScript (if any), its logic through example inputs and outputs, common usage errors, and how a user might trigger this code.

**2. Initial Scan and Core Concepts:**

The code begins with a clear "DESIGN OVERVIEW". This is the best place to start. The key takeaways from this section are:

* **Coalescing:**  The core purpose is to group multiple `Verify()` calls into a single underlying `CertVerifier` call. This is for performance optimization.
* **Job:** Represents a single verification process to the underlying verifier. Manages the underlying `CertVerify::Request` and tracks interested `Request` objects.
* **Request:** Represents a single call to `CoalescingCertVerifier::Verify()` from the caller. Allows cancellation.
* **Ownership:** The overview clearly explains the ownership relationships between `CoalescingCertVerifier`, `Job`, and `Request`. This is crucial for understanding lifetime management.

**3. Deeper Dive into Key Classes:**

* **`CoalescingCertVerifier`:** This is the main class. It holds the underlying `CertVerifier` and manages the `Job` objects. The `Verify()` method is the entry point for coalescing.
* **`Job`:**  This class handles the actual interaction with the underlying `CertVerifier`. It manages the list of `Request` objects interested in its result. Key methods: `AddRequest`, `AbortRequest`, `Start`, `OnVerifyComplete`.
* **`Request`:**  This is a simple class representing a single verification request. It holds the callback and the associated `CertVerifyResult`. Key methods: `Complete`, `OnJobAbort`.

**4. Identifying Functionality:**

Based on the class structure and the design overview, we can list the functionalities:

* **Request Coalescing:** Grouping identical verification requests.
* **Underlying CertVerifier Interaction:**  Delegating the actual verification to another `CertVerifier`.
* **Request Management:**  Tracking and managing individual verification requests.
* **Cancellation:**  Allowing individual requests and the entire verifier to be cancelled.
* **Asynchronous Operations:** Handling asynchronous verification processes.
* **Result Handling:**  Distributing the verification result to all interested requests.
* **Configuration Updates:**  Handling configuration changes and invalidating existing joinable jobs.
* **Metrics Collection:**  Collecting latency metrics for verification jobs.

**5. Relationship with JavaScript:**

This is a crucial part of the prompt. The key is to understand how this C++ code might be used in a web browser context where JavaScript is involved.

* **Network Stack:** Recognize that this is part of Chromium's network stack, which handles HTTPS requests initiated by JavaScript.
* **`fetch()` API:** A primary way JavaScript interacts with network resources. When `fetch()` is used for an HTTPS URL, it triggers certificate verification.
* **Event Flow:**  Imagine a JavaScript `fetch()` call -> Chromium browser processes the request -> The network stack (including this code) is involved in verifying the server's certificate.

**Example Scenario (JavaScript Interaction):**

A simple `fetch()` call to an HTTPS website demonstrates the connection. Explain how multiple rapid `fetch()` calls to the *same* HTTPS site could trigger the coalescing logic.

**6. Logic and Examples (Hypothetical):**

Create simple, illustrative scenarios to demonstrate the coalescing behavior.

* **Scenario 1 (Coalescing):** Two identical `Verify()` calls are made before the first one completes. Show how they are joined into a single `Job`.
* **Scenario 2 (No Coalescing):** Two `Verify()` calls with different parameters are made. Show that separate `Job` objects are created.
* **Scenario 3 (Cancellation):** Demonstrate how cancelling a `Request` affects the `Job`, especially if it's the last request.

**7. Common Usage Errors:**

Think about how developers interacting with the `CertVerifier` interface (which `CoalescingCertVerifier` implements) might make mistakes.

* **Incorrect Lifetime Management:**  The design overview emphasizes ownership. A common error could be deleting the `Request` object prematurely or expecting the callback to be invoked after the `CoalescingCertVerifier` is destroyed.
* **Ignoring Return Values:**  The `Verify()` method returns an error code. Ignoring this could lead to incorrect handling of synchronous verification results.

**8. Debugging and User Actions:**

Consider how a developer would debug issues involving this code and what user actions might lead to this code being executed.

* **User Actions:**  Browsing HTTPS websites, particularly making multiple requests to the same site quickly.
* **Debugging:**  Explain how network logging (mentioned in the code via `net_log_`) can be used to trace the execution flow, identify coalesced requests, and diagnose errors. Highlight the specific log events mentioned in the code (e.g., `CERT_VERIFIER_JOB`, `CERT_VERIFIER_REQUEST`).

**9. Structure and Refinement:**

Organize the information logically, using headings and bullet points for clarity. Ensure that the explanation flows well and addresses all aspects of the prompt. Review and refine the language for accuracy and clarity. For example, ensure consistent terminology (e.g., always refer to the underlying verifier as such).

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Perhaps JavaScript directly calls this C++ code.
* **Correction:** Realize that JavaScript interacts with the browser's APIs, which in turn utilize the underlying C++ network stack. The connection is indirect.
* **Initial thought:** Focus heavily on the low-level details of linked lists.
* **Correction:** While understanding the data structures is helpful, focus on the *purpose* of these structures in the overall coalescing logic. The design overview emphasizes the high-level algorithm.
* **Initial thought:**  Provide very technical C++ code examples.
* **Correction:**  Keep the examples conceptual and focus on the input and output behavior rather than detailed C++ syntax.

By following this structured thought process, combining high-level understanding with examination of the code structure and key methods, and then connecting it to the user and developer perspectives, we arrive at a comprehensive and accurate analysis.
好的，我们来详细分析一下 `net/cert/coalescing_cert_verifier.cc` 这个文件。

**功能概述**

`CoalescingCertVerifier` 的主要功能是**合并（coalesce）多个相同的证书验证请求，以减少对底层 `CertVerifier` 的重复调用**。  这是一种优化策略，尤其在以下场景中非常有用：

* **高并发请求:** 当有多个几乎同时发生的，对同一服务器证书的验证请求时。
* **昂贵的底层验证器:** 当底层的证书验证操作比较耗时，例如需要访问系统证书存储或进行跨进程通信时。

通过合并请求，`CoalescingCertVerifier` 可以将多个 `Verify()` 调用合并成对底层 `CertVerifier` 的单次调用，从而节省资源并提高性能。

**与 JavaScript 的关系**

虽然 `CoalescingCertVerifier` 是 C++ 代码，但它在 Chromium 的网络栈中扮演着关键角色，而网络栈是浏览器与互联网交互的基础。JavaScript 代码（例如网页中的脚本）通过浏览器提供的 API 发起网络请求（例如使用 `fetch` 或 `XMLHttpRequest`）。当这些请求涉及到 HTTPS 连接时，就需要进行服务器证书的验证。

`CoalescingCertVerifier` 就位于这个证书验证流程中。当 JavaScript 发起多个对同一 HTTPS 站点的请求时，这些请求可能会触发多个证书验证请求。`CoalescingCertVerifier` 会识别出这些请求是针对同一个证书的，并将它们合并成一个底层的验证操作。

**举例说明:**

假设一个网页的 JavaScript 代码在很短的时间内发起了两个 `fetch` 请求，都指向 `https://example.com`。

1. **JavaScript 发起请求:**
   ```javascript
   fetch('https://example.com/resource1');
   fetch('https://example.com/resource2');
   ```

2. **网络栈处理请求:** Chromium 的网络栈接收到这两个请求，并需要验证 `example.com` 的 SSL/TLS 证书。

3. **`CoalescingCertVerifier` 介入:**  `CoalescingCertVerifier` 接收到两个几乎相同的证书验证请求（因为它们的目标主机相同）。

4. **请求合并:** `CoalescingCertVerifier` 识别出这两个请求可以合并。它会创建一个 `Job` 对象来代表这次合并的验证任务，并将这两个原始请求关联到这个 `Job`。

5. **底层验证:**  `CoalescingCertVerifier` 只会调用底层 `CertVerifier` 一次来验证 `example.com` 的证书。

6. **结果分发:** 当底层 `CertVerifier` 完成验证后，`CoalescingCertVerifier` 会将验证结果（成功或失败）分发给与该 `Job` 关联的所有原始请求，从而完成 JavaScript `fetch` 操作的回调。

**逻辑推理 (假设输入与输出)**

**假设输入:**

* **请求 1:** 验证 `params_a`，对应 `https://example.com` 的证书。
* **请求 2:** 验证 `params_a`，同样对应 `https://example.com` 的证书。
* 假设当前没有正在进行的针对 `https://example.com` 的验证。

**处理过程:**

1. `CoalescingCertVerifier::Verify(params_a, ...)` 被调用（请求 1）。
2. `FindJob(params_a)` 返回 `nullptr`，因为没有匹配的正在进行的任务。
3. 创建一个新的 `Job` 对象 `job_a`，用于验证 `params_a`。
4. 调用底层 `verifier_->Verify(params_a, ...)` 启动验证。假设返回 `ERR_IO_PENDING` (异步完成)。
5. `joinable_jobs_[params_a]` 存储 `job_a`。
6. 创建一个 `Request` 对象 `request_1` 并关联到 `job_a`。
7. `CoalescingCertVerifier::Verify(params_a, ...)` 再次被调用（请求 2）。
8. `FindJob(params_a)` 返回 `job_a`。
9. 创建一个新的 `Request` 对象 `request_2` 并关联到 `job_a`。
10. 当底层验证完成时，`Job::OnVerifyComplete()` 被调用。
11. `OnVerifyComplete()` 会将结果分发给 `request_1` 和 `request_2`。

**输出:**

* 两个原始的 `Verify()` 调用都将收到相同的验证结果。

**假设输入 (不同的参数):**

* **请求 1:** 验证 `params_a` (例如 `https://example.com`)。
* **请求 2:** 验证 `params_b` (例如 `https://different.com`)。

**处理过程:**

与上述过程类似，但是 `FindJob()` 在处理请求 2 时不会找到匹配的 `Job`，因此会为 `params_b` 创建一个新的 `Job`，并独立地进行底层验证。

**输出:**

* 两个原始的 `Verify()` 调用将收到各自的验证结果。

**用户或编程常见的使用错误**

1. **错误地管理 `CertVerifier::Request` 的生命周期:**  `Request` 对象由调用者拥有。如果调用者过早地销毁 `Request` 对象，会导致程序崩溃或未定义的行为，因为 `Job` 可能会尝试访问已释放的内存。

   **示例:**

   ```c++
   std::unique_ptr<CertVerifier::Request> req;
   verifier->Verify(params, &result, callback, &req, net_log);
   // ... 一些代码 ...
   // 错误：过早销毁了 req
   req.reset();
   ```

2. **假设同步完成但未检查返回值:**  `CertVerifier::Verify()` 可以同步或异步完成。如果假设总是异步完成，但实际上是同步完成并返回了错误码，那么可能会忽略错误。

   **示例:**

   ```c++
   int rv = verifier->Verify(params, &result, callback, &req, net_log);
   if (rv == ERR_IO_PENDING) {
       // 假设总是异步
   } else {
       // 错误：没有处理同步完成的情况
   }
   ```

3. **在回调函数中删除 `CoalescingCertVerifier` 对象:** 代码中特别提到了这种情况的复杂性。如果在证书验证的回调函数中删除了 `CoalescingCertVerifier` 对象，需要特别小心确保所有相关的 `Job` 和 `Request` 对象都能正确清理，避免悬挂指针。

**用户操作如何一步步到达这里 (作为调试线索)**

当开发者需要调试与 `CoalescingCertVerifier` 相关的问题时，可以按照以下用户操作路径追踪：

1. **用户在浏览器中输入 HTTPS 网址并访问:**  这是最直接的触发证书验证的场景。

2. **用户点击 HTTPS 链接:**  与访问网址类似，点击 HTTPS 链接会触发新的网络请求，从而可能触发证书验证。

3. **网页通过 JavaScript 发起 HTTPS 请求 (例如使用 `fetch` 或 `XMLHttpRequest`):**  开发者可以通过检查网页的 JavaScript 代码来确认是否发起了这类请求。

4. **浏览器网络栈处理请求:**  使用 Chromium 的网络日志 (可以通过 `chrome://net-export/` 或 `--log-net-log`) 可以捕获网络请求的详细信息，包括证书验证的开始和结束。

5. **`CoalescingCertVerifier` 的日志:**  `CoalescingCertVerifier` 自身也包含了一些日志记录 (通过 `net_log_`)。开发者可以在 Chromium 的源代码中添加更多的日志，以便更详细地跟踪请求的合并过程。关键的日志事件包括：
   * `NetLogEventType::CERT_VERIFIER_JOB`: 表示一个验证任务的开始和结束。
   * `NetLogEventType::CERT_VERIFIER_REQUEST`: 表示一个独立的验证请求。
   * `NetLogEventType::CERT_VERIFIER_REQUEST_BOUND_TO_JOB`: 表示一个请求被绑定到一个已有的任务。
   * `NetLogEventType::CANCELLED`: 表示请求或任务被取消。

通过分析网络日志和 `CoalescingCertVerifier` 的内部日志，开发者可以观察到请求是否被合并，验证过程是否成功，以及是否存在任何错误。

**总结**

`CoalescingCertVerifier` 是 Chromium 网络栈中一个重要的性能优化组件，它通过合并重复的证书验证请求来提高效率。理解其工作原理、与 JavaScript 的关系以及可能出现的错误，对于开发和调试涉及 HTTPS 连接的应用至关重要。通过仔细分析网络日志和添加适当的调试信息，可以有效地追踪和解决与证书验证相关的问题。

Prompt: 
```
这是目录为net/cert/coalescing_cert_verifier.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/coalescing_cert_verifier.h"

#include "base/containers/linked_list.h"
#include "base/containers/unique_ptr_adapters.h"
#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/histogram_macros.h"
#include "base/not_fatal_until.h"
#include "base/ranges/algorithm.h"
#include "base/strings/string_number_conversions.h"
#include "base/time/time.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/crl_set.h"
#include "net/cert/x509_certificate_net_log_param.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_source_type.h"
#include "net/log/net_log_values.h"
#include "net/log/net_log_with_source.h"
#include "third_party/boringssl/src/pki/pem.h"

namespace net {

// DESIGN OVERVIEW:
//
// The CoalescingCertVerifier implements an algorithm to group multiple calls
// to Verify() into a single Job. This avoids overloading the underlying
// CertVerifier, particularly those that are expensive to talk to (e.g.
// talking to the system verifier or across processes), batching multiple
// requests to CoaleacingCertVerifier::Verify() into a single underlying call.
//
// However, this makes lifetime management a bit more complex.
//   - The Job object represents all of the state for a single verification to
//     the CoalescingCertVerifier's underlying CertVerifier.
//       * It keeps the CertVerifyResult alive, which is required as long as
//         there is a pending verification.
//       * It keeps the CertVerify::Request to the underlying verifier alive,
//         as long as there is a pending Request attached to the Job.
//       * It keeps track of every CoalescingCertVerifier::Request that is
//         interested in receiving notification. However, it does NOT own
//         these objects, and thus needs to coordinate with the Request (via
//         AddRequest/AbortRequest) to make sure it never has a stale
//         pointer.
//         NB: It would have also been possible for the Job to only
//         hold WeakPtr<Request>s, rather than Request*, but that seemed less
//         clear as to the lifetime invariants, even if it was more clear
//         about how the pointers are used.
//  - The Job object is always owned by the CoalescingCertVerifier. If the
//    CoalescingCertVerifier is deleted, all in-flight requests to the
//    underlying verifier should be cancelled. When the Job goes away, all the
//    Requests will be orphaned.
//  - The Request object is always owned by the CALLER. It is a handle to
//    allow a caller to cancel a request, per the CertVerifier interface. If
//    the Request goes away, no caller callbacks should be invoked if the Job
//    it was (previously) attached to completes.
//  - Per the CertVerifier interface, when the CoalescingCertVerifier is
//    deleted, then regardless of there being any live Requests, none of those
//    caller callbacks should be invoked.
//
// Finally, to add to the complexity, it's possible that, during the handling
// of a result from the underlying CertVerifier, a Job may begin dispatching
// to its Requests. The Request may delete the CoalescingCertVerifier. If that
// happens, then the Job being processed is also deleted, and none of the
// other Requests should be notified.

namespace {

base::Value::Dict CertVerifierParams(
    const CertVerifier::RequestParams& params) {
  base::Value::Dict dict;
  dict.Set("certificates",
           NetLogX509CertificateList(params.certificate().get()));
  if (!params.ocsp_response().empty()) {
    dict.Set("ocsp_response",
             bssl::PEMEncode(params.ocsp_response(), "NETLOG OCSP RESPONSE"));
  }
  if (!params.sct_list().empty()) {
    dict.Set("sct_list", bssl::PEMEncode(params.sct_list(), "NETLOG SCT LIST"));
  }
  dict.Set("host", NetLogStringValue(params.hostname()));
  dict.Set("verifier_flags", params.flags());

  return dict;
}

}  // namespace

// Job contains all the state for a single verification using the underlying
// verifier.
class CoalescingCertVerifier::Job {
 public:
  Job(CoalescingCertVerifier* parent,
      const CertVerifier::RequestParams& params,
      NetLog* net_log,
      bool is_first_job);
  ~Job();

  const CertVerifier::RequestParams& params() const { return params_; }
  const CertVerifyResult& verify_result() const { return verify_result_; }

  // Attaches |request|, causing it to be notified once this Job completes.
  void AddRequest(CoalescingCertVerifier::Request* request);

  // Stops |request| from being notified. If there are no Requests remaining,
  // the Job will be cancelled.
  // NOTE: It's only necessary to call this if the Job has not yet completed.
  // If the Request has been notified of completion, this should not be called.
  void AbortRequest(CoalescingCertVerifier::Request* request);

  // Starts a verification using |underlying_verifier|. If this completes
  // synchronously, returns the result code, with the associated result being
  // available via |verify_result()|. Otherwise, it will complete
  // asynchronously, notifying any Requests associated via |AttachRequest|.
  int Start(CertVerifier* underlying_verifier);

 private:
  void OnVerifyComplete(int result);

  void LogMetrics();

  raw_ptr<CoalescingCertVerifier> parent_verifier_;
  const CertVerifier::RequestParams params_;
  const NetLogWithSource net_log_;
  bool is_first_job_ = false;
  CertVerifyResult verify_result_;

  base::TimeTicks start_time_;
  std::unique_ptr<CertVerifier::Request> pending_request_;

  base::LinkedList<CoalescingCertVerifier::Request> attached_requests_;
  base::WeakPtrFactory<Job> weak_ptr_factory_{this};
};

// Tracks the state associated with a single CoalescingCertVerifier::Verify
// request.
//
// There are two ways for requests to be cancelled:
//   - The caller of Verify() can delete the Request object, indicating
//     they are no longer interested in this particular request.
//   - The caller can delete the CoalescingCertVerifier, which should cause
//     all in-process Jobs to be aborted and deleted. Any Requests attached to
//     Jobs should be orphaned, and do nothing when the Request is (eventually)
//     deleted.
class CoalescingCertVerifier::Request
    : public base::LinkNode<CoalescingCertVerifier::Request>,
      public CertVerifier::Request {
 public:
  // Create a request that will be attached to |job|, and will notify
  // |callback| and fill |verify_result| if the Job completes successfully.
  // If the Request is deleted, or the Job is deleted, |callback| will not
  // be notified.
  Request(CoalescingCertVerifier::Job* job,
          CertVerifyResult* verify_result,
          CompletionOnceCallback callback,
          const NetLogWithSource& net_log);

  ~Request() override;

  const NetLogWithSource& net_log() const { return net_log_; }

  // Called by Job to complete the requests (either successfully or as a sign
  // that the underlying Job is going away).
  void Complete(int result);

  // Called when |job_| is being deleted, to ensure that the Request does not
  // attempt to access the Job further. No callbacks will be invoked,
  // consistent with the CoalescingCertVerifier's contract.
  void OnJobAbort();

 private:
  raw_ptr<CoalescingCertVerifier::Job> job_;

  raw_ptr<CertVerifyResult> verify_result_;
  CompletionOnceCallback callback_;
  const NetLogWithSource net_log_;
};

CoalescingCertVerifier::Job::Job(CoalescingCertVerifier* parent,
                                 const CertVerifier::RequestParams& params,
                                 NetLog* net_log,
                                 bool is_first_job)
    : parent_verifier_(parent),
      params_(params),
      net_log_(
          NetLogWithSource::Make(net_log, NetLogSourceType::CERT_VERIFIER_JOB)),
      is_first_job_(is_first_job) {}

CoalescingCertVerifier::Job::~Job() {
  // If there was at least one outstanding Request still pending, then this
  // Job was aborted, rather than being completed normally and cleaned up.
  if (!attached_requests_.empty() && pending_request_) {
    net_log_.AddEvent(NetLogEventType::CANCELLED);
    net_log_.EndEvent(NetLogEventType::CERT_VERIFIER_JOB);
  }

  while (!attached_requests_.empty()) {
    auto* link_node = attached_requests_.head();
    link_node->RemoveFromList();
    link_node->value()->OnJobAbort();
  }
}

void CoalescingCertVerifier::Job::AddRequest(
    CoalescingCertVerifier::Request* request) {
  // There must be a pending asynchronous verification in process.
  DCHECK(pending_request_);

  request->net_log().AddEventReferencingSource(
      NetLogEventType::CERT_VERIFIER_REQUEST_BOUND_TO_JOB, net_log_.source());
  attached_requests_.Append(request);
}

void CoalescingCertVerifier::Job::AbortRequest(
    CoalescingCertVerifier::Request* request) {
  // Check to make sure |request| hasn't already been removed.
  DCHECK(request->previous() || request->next());

  request->RemoveFromList();

  // If there are no more pending requests, abort. This isn't strictly
  // necessary; the request could be allowed to run to completion (and
  // potentially to allow later Requests to join in), but in keeping with the
  // idea of providing more stable guarantees about resources, clean up early.
  if (attached_requests_.empty()) {
    // If this was the last Request, then the Job had not yet completed; this
    // matches the logic in the dtor, which handles when it's the Job that is
    // deleted first, rather than the last Request.
    net_log_.AddEvent(NetLogEventType::CANCELLED);
    net_log_.EndEvent(NetLogEventType::CERT_VERIFIER_JOB);

    // DANGER: This will cause |this_| to be deleted!
    parent_verifier_->RemoveJob(this);
    return;
  }
}

int CoalescingCertVerifier::Job::Start(CertVerifier* underlying_verifier) {
  // Requests are only attached for asynchronous completion, so they must
  // always be attached after Start() has been called.
  DCHECK(attached_requests_.empty());
  // There should not be a pending request already started (e.g. Start called
  // multiple times).
  DCHECK(!pending_request_);

  net_log_.BeginEvent(NetLogEventType::CERT_VERIFIER_JOB,
                      [&] { return CertVerifierParams(params_); });

  verify_result_.Reset();

  start_time_ = base::TimeTicks::Now();
  int result = underlying_verifier->Verify(
      params_, &verify_result_,
      // Safe, because |verify_request_| is self-owned and guarantees the
      // callback won't be called if |this| is deleted.
      base::BindOnce(&CoalescingCertVerifier::Job::OnVerifyComplete,
                     base::Unretained(this)),
      &pending_request_, net_log_);
  if (result != ERR_IO_PENDING) {
    LogMetrics();
    net_log_.EndEvent(NetLogEventType::CERT_VERIFIER_JOB,
                      [&] { return verify_result_.NetLogParams(result); });
  }

  return result;
}

void CoalescingCertVerifier::Job::OnVerifyComplete(int result) {
  LogMetrics();

  pending_request_.reset();  // Reset to signal clean completion.
  net_log_.EndEvent(NetLogEventType::CERT_VERIFIER_JOB,
                    [&] { return verify_result_.NetLogParams(result); });

  // It's possible that during the process of invoking a callback for a
  // Request, |this| may get deleted (along with the associated parent). If
  // that happens, it's important to ensure that processing of the Job is
  // stopped - i.e. no other callbacks are invoked for other Requests, nor is
  // |this| accessed.
  //
  // To help detect and protect against this, a WeakPtr to |this| is taken. If
  // |this| is deleted, the destructor will have invalidated the WeakPtr.
  //
  // Note that if a Job had already been deleted, this method would not have
  // been invoked in the first place, as the Job (via |pending_request_|) owns
  // the underlying CertVerifier::Request that this method was bound to as a
  // callback. This is why it's OK to grab the WeakPtr from |this| initially.
  base::WeakPtr<Job> weak_this = weak_ptr_factory_.GetWeakPtr();
  while (!attached_requests_.empty()) {
    // Note: It's also possible for additional Requests to be attached to the
    // current Job while processing a Request.
    auto* link_node = attached_requests_.head();
    link_node->RemoveFromList();

    // Note: |this| MAY be deleted here.
    //   - If the CoalescingCertVerifier is deleted, it will delete the
    //     Jobs (including |this|)
    //   - If this is the second-to-last Request, and the completion of this
    //     event causes the other Request to be deleted, detaching that Request
    //     from this Job will lead to this Job being deleted (via
    //     Job::AbortRequest())
    link_node->value()->Complete(result);

    // Check if |this| has been deleted (which implicitly includes
    // |parent_verifier_|), and abort if so, since no further cleanup is
    // needed.
    if (!weak_this)
      return;
  }

  // DANGER: |this| will be invalidated (deleted) after this point.
  return parent_verifier_->RemoveJob(this);
}

void CoalescingCertVerifier::Job::LogMetrics() {
  base::TimeDelta latency = base::TimeTicks::Now() - start_time_;
  UMA_HISTOGRAM_CUSTOM_TIMES("Net.CertVerifier_Job_Latency", latency,
                             base::Milliseconds(1), base::Minutes(10), 100);
  if (is_first_job_) {
    UMA_HISTOGRAM_CUSTOM_TIMES("Net.CertVerifier_First_Job_Latency", latency,
                               base::Milliseconds(1), base::Minutes(10), 100);
  }
}

CoalescingCertVerifier::Request::Request(CoalescingCertVerifier::Job* job,
                                         CertVerifyResult* verify_result,
                                         CompletionOnceCallback callback,
                                         const NetLogWithSource& net_log)
    : job_(job),
      verify_result_(verify_result),
      callback_(std::move(callback)),
      net_log_(net_log) {
  net_log_.BeginEvent(NetLogEventType::CERT_VERIFIER_REQUEST);
}

CoalescingCertVerifier::Request::~Request() {
  if (job_) {
    net_log_.AddEvent(NetLogEventType::CANCELLED);
    net_log_.EndEvent(NetLogEventType::CERT_VERIFIER_REQUEST);

    // Need to null out `job_` before aborting the request to avoid a dangling
    // pointer warning, as aborting the request may delete `job_`.
    auto* job = job_.get();
    job_ = nullptr;

    // If the Request is deleted before the Job, then detach from the Job.
    // Note: This may cause |job_| to be deleted.
    job->AbortRequest(this);
  }
}

void CoalescingCertVerifier::Request::Complete(int result) {
  DCHECK(job_);  // There must be a pending/non-aborted job to complete.

  *verify_result_ = job_->verify_result();

  // On successful completion, the Job removes the Request from its set;
  // similarly, break the association here so that when the Request is
  // deleted, it does not try to abort the (now-completed) Job.
  job_ = nullptr;

  // Also need to break the association with `verify_result_`, so that
  // dangling pointer checks the result and the Request be destroyed
  // in any order.
  verify_result_ = nullptr;

  net_log_.EndEvent(NetLogEventType::CERT_VERIFIER_REQUEST);

  // Run |callback_|, which may delete |this|.
  std::move(callback_).Run(result);
}

void CoalescingCertVerifier::Request::OnJobAbort() {
  DCHECK(job_);  // There must be a pending job to abort.

  // If the Job is deleted before the Request, just clean up. The Request will
  // eventually be deleted by the caller.
  net_log_.AddEvent(NetLogEventType::CANCELLED);
  net_log_.EndEvent(NetLogEventType::CERT_VERIFIER_REQUEST);

  job_ = nullptr;
  // Note: May delete |this|, if the caller made |callback_| own the Request.
  callback_.Reset();
}

CoalescingCertVerifier::CoalescingCertVerifier(
    std::unique_ptr<CertVerifier> verifier)
    : verifier_(std::move(verifier)) {
  verifier_->AddObserver(this);
}

CoalescingCertVerifier::~CoalescingCertVerifier() {
  verifier_->RemoveObserver(this);
}

int CoalescingCertVerifier::Verify(
    const RequestParams& params,
    CertVerifyResult* verify_result,
    CompletionOnceCallback callback,
    std::unique_ptr<CertVerifier::Request>* out_req,
    const NetLogWithSource& net_log) {
  DCHECK(verify_result);
  DCHECK(!callback.is_null());

  out_req->reset();
  ++requests_;

  Job* job = FindJob(params);
  if (job) {
    // An identical request is in-flight and joinable, so just attach the
    // callback.
    ++inflight_joins_;
  } else {
    // No existing Jobs can be used. Create and start a new one.
    std::unique_ptr<Job> new_job =
        std::make_unique<Job>(this, params, net_log.net_log(), requests_ == 1);
    int result = new_job->Start(verifier_.get());
    if (result != ERR_IO_PENDING) {
      *verify_result = new_job->verify_result();
      return result;
    }

    job = new_job.get();
    joinable_jobs_[params] = std::move(new_job);
  }

  std::unique_ptr<CoalescingCertVerifier::Request> request =
      std::make_unique<CoalescingCertVerifier::Request>(
          job, verify_result, std::move(callback), net_log);
  job->AddRequest(request.get());
  *out_req = std::move(request);
  return ERR_IO_PENDING;
}

void CoalescingCertVerifier::SetConfig(const CertVerifier::Config& config) {
  verifier_->SetConfig(config);

  IncrementGenerationAndMakeCurrentJobsUnjoinable();
}

void CoalescingCertVerifier::AddObserver(CertVerifier::Observer* observer) {
  verifier_->AddObserver(observer);
}

void CoalescingCertVerifier::RemoveObserver(CertVerifier::Observer* observer) {
  verifier_->RemoveObserver(observer);
}

CoalescingCertVerifier::Job* CoalescingCertVerifier::FindJob(
    const RequestParams& params) {
  auto it = joinable_jobs_.find(params);
  if (it != joinable_jobs_.end())
    return it->second.get();
  return nullptr;
}

void CoalescingCertVerifier::RemoveJob(Job* job) {
  // See if this was a job from the current configuration generation.
  // Note: It's also necessary to compare that the underlying pointer is the
  // same, and not merely a Job with the same parameters.
  auto joinable_it = joinable_jobs_.find(job->params());
  if (joinable_it != joinable_jobs_.end() && joinable_it->second.get() == job) {
    joinable_jobs_.erase(joinable_it);
    return;
  }

  // Otherwise, it MUST have been a job from a previous generation.
  auto inflight_it =
      base::ranges::find_if(inflight_jobs_, base::MatchesUniquePtr(job));
  CHECK(inflight_it != inflight_jobs_.end(), base::NotFatalUntil::M130);
  inflight_jobs_.erase(inflight_it);
  return;
}

void CoalescingCertVerifier::IncrementGenerationAndMakeCurrentJobsUnjoinable() {
  for (auto& job : joinable_jobs_) {
    inflight_jobs_.emplace_back(std::move(job.second));
  }
  joinable_jobs_.clear();
}

void CoalescingCertVerifier::OnCertVerifierChanged() {
  IncrementGenerationAndMakeCurrentJobsUnjoinable();
}

}  // namespace net

"""

```