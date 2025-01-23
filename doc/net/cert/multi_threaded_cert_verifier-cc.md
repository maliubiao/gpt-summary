Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Core Purpose:** The file name `multi_threaded_cert_verifier.cc` immediately suggests its main function: verifying certificates in a multi-threaded environment. This is a critical piece of any secure network communication.

2. **Identify Key Components:** Scan the code for major classes and data structures. The most important one is `MultiThreadedCertVerifier` itself. Also note `InternalRequest`, `CertVerifyProc`, `CertVerifyResult`, and `CertVerifier::Config`. These names give strong hints about their roles.

3. **Trace the Verification Flow:**  How does a certificate verification request actually happen? Look for the `Verify` method in `MultiThreadedCertVerifier`. This appears to be the entry point. Follow the execution flow from there:
    * Input validation (`callback.is_null()`, `verify_result`, `hostname`).
    * Creation of an `InternalRequest`.
    * Calling `InternalRequest::Start`.
    * `InternalRequest::Start` uses `base::ThreadPool::PostTaskAndReplyWithResult` to offload the actual verification.
    * The worker thread executes `DoVerifyOnWorkerThread`.
    * `DoVerifyOnWorkerThread` calls `verify_proc_->Verify`.
    * The result is passed back to `InternalRequest::OnJobComplete`.
    * `OnJobComplete` handles the callback to the original caller.

4. **Examine Supporting Classes:**  What do the other classes do?
    * `InternalRequest`:  Manages a single verification request, including cancellation. Notice the use of `base::WeakPtr` to avoid issues if the `MultiThreadedCertVerifier` is destroyed.
    * `CertVerifyProc`: Represents the actual certificate verification logic (delegated to an underlying implementation, likely platform-specific).
    * `CertVerifyResult`:  Holds the outcome of the verification.
    * `CertVerifier::Config`: Allows customization of the verification process.
    * `ResultHelper`:  A simple structure to bundle the results from the worker thread.

5. **Look for Multi-threading Aspects:**  The name is a big clue. The use of `base::ThreadPool::PostTaskAndReplyWithResult` is the most explicit indication of multi-threading. Also note the comment about `MultiThreadedCertVerifierScopedAllowBaseSyncPrimitives`, which suggests potential blocking operations within the worker thread.

6. **Consider JavaScript Interaction:**  Think about how certificate verification impacts a web browser. JavaScript makes network requests. The browser needs to verify the server's certificate to establish a secure HTTPS connection. Therefore, while this C++ code doesn't *directly* interact with JavaScript code, it's a fundamental component supporting secure JavaScript operations.

7. **Identify Potential Issues (Debugging and Errors):**
    * **Cancellation:** The `InternalRequest` mechanism handles cancellation, but the underlying verification is blocking. This highlights a potential performance issue if verification takes a long time.
    * **Invalid Arguments:** The `Verify` method checks for basic invalid arguments.
    * **Thread Safety:**  The code uses locking mechanisms implicitly via the thread pool, but improper usage elsewhere could lead to issues.
    * **Configuration Errors:**  Incorrect `CertVerifier::Config` can lead to unexpected verification behavior.

8. **Infer User Actions:** How does a user trigger this code?  Any action that requires a secure network connection will involve certificate verification. Navigating to an HTTPS website, using web APIs that make secure requests (e.g., `fetch`), or installing a PWA are all examples.

9. **Construct Hypothetical Scenarios:** Create simple examples to illustrate the behavior. Think about both successful and failing verifications. This helps solidify understanding and demonstrates potential inputs and outputs.

10. **Refine and Organize:**  Structure the analysis logically, covering the functionality, JavaScript relevance, logic/IO, usage errors, and debugging. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Is this code *directly* called by JavaScript?"  **Correction:** No, it's a lower-level C++ component. The interaction is indirect, through browser APIs.
* **Realization:** The "cancellation" isn't a true interrupt, but rather a way to prevent the callback from firing. This is important to clarify.
* **Emphasis:**  Highlight the role of the thread pool in enabling non-blocking behavior on the main browser thread.
* **Debugging Focus:** Emphasize the asynchronous nature and the importance of net-internals logging for troubleshooting.

By following these steps, combining code reading with conceptual understanding of the underlying network security principles, one can effectively analyze and explain the functionality of a complex piece of code like `multi_threaded_cert_verifier.cc`.
这个文件 `net/cert/multi_threaded_cert_verifier.cc` 是 Chromium 网络栈中负责多线程证书验证的关键组件。它的主要功能是：

**核心功能:**

1. **异步证书验证:** 它允许在后台线程执行耗时的证书验证操作，避免阻塞浏览器的主线程，从而提高用户界面的响应速度。
2. **封装 `CertVerifyProc`:** 它充当 `CertVerifyProc` 的一个包装器，`CertVerifyProc` 是实际执行证书验证逻辑的类。`MultiThreadedCertVerifier` 负责在工作线程上调用 `CertVerifyProc` 的 `Verify` 方法。
3. **管理验证请求:** 它维护一个待处理的验证请求列表，并管理请求的生命周期，包括启动、完成和取消。
4. **配置证书验证:** 它接收并存储证书验证的配置信息 (`CertVerifier::Config`)，例如是否启用吊销检查、是否强制吊销检查本地锚点等，并将这些配置传递给底层的 `CertVerifyProc`。
5. **观察者模式:** 它实现了观察者模式，允许其他组件注册并接收证书验证器配置更改的通知。
6. **错误处理和结果传递:** 它负责接收工作线程返回的验证结果（包括错误码和详细的验证信息 `CertVerifyResult`），并将结果通过回调函数传递给请求的发起者。

**与 JavaScript 功能的关系:**

虽然这个 C++ 代码本身不直接与 JavaScript 代码交互，但它是浏览器安全机制的关键组成部分，直接影响到通过 JavaScript 发起的网络请求的安全性。

**举例说明:**

当一个网页上的 JavaScript 代码发起一个 HTTPS 请求（例如使用 `fetch` API）时，浏览器需要验证服务器提供的 SSL/TLS 证书。这个验证过程会涉及到 `MultiThreadedCertVerifier`。

1. **JavaScript 发起请求:** JavaScript 代码执行 `fetch('https://example.com')`。
2. **网络栈介入:** Chromium 的网络栈开始处理这个请求。
3. **证书验证启动:**  网络栈会提取服务器提供的证书链，并创建一个证书验证请求。
4. **`MultiThreadedCertVerifier` 参与:**  网络栈会调用 `MultiThreadedCertVerifier::Verify` 方法，将证书、主机名等信息传递给它。
5. **后台线程验证:** `MultiThreadedCertVerifier` 将验证任务投递到一个工作线程上执行。这个工作线程会调用 `CertVerifyProc::Verify` 执行实际的验证逻辑，例如检查证书签名、有效期、吊销状态等。
6. **结果回调:** 工作线程完成验证后，会将结果传递回 `MultiThreadedCertVerifier`。
7. **通知 JavaScript:** `MultiThreadedCertVerifier` 通过之前传递的回调函数通知网络栈验证结果。
8. **请求处理继续或失败:** 如果证书验证成功，网络栈会继续建立连接并完成请求。如果验证失败，网络栈会终止连接，JavaScript 代码会收到一个错误，例如 `net::ERR_CERT_AUTHORITY_INVALID`。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* **`params` (CertVerifier::RequestParams):**
    * `certificate()`: 一个指向需要验证的 `X509Certificate` 对象的智能指针，代表服务器提供的证书。
    * `hostname()`: 字符串 "example.com"，请求的主机名。
    * 其他参数（例如 `ocsp_response`, `sct_list`）可能为空或包含特定信息。
    * `flags()`: 可能包含 `CertVerifier::VERIFY_DISABLE_NETWORK_FETCHES` 等标志。
* **`config_` (CertVerifier::Config):**
    * `enable_rev_checking`: true (启用吊销检查)。
    * `require_rev_checking_local_anchors`: false。
    * 其他配置项。
* **回调函数 `callback`:** 一个用于接收验证结果的回调函数。

**逻辑推理过程:**

1. `MultiThreadedCertVerifier::Verify` 被调用，传入上述参数。
2. 创建一个 `InternalRequest` 对象来管理本次验证。
3. `GetFlagsForConfig` 函数根据 `config_` 生成 `CertVerifyProc` 的标志，例如设置 `VERIFY_REV_CHECKING_ENABLED`。如果 `params.flags()` 包含 `VERIFY_DISABLE_NETWORK_FETCHES`，也会将其添加到标志中。
4. `base::ThreadPool::PostTaskAndReplyWithResult` 被调用，将 `DoVerifyOnWorkerThread` 函数投递到工作线程池执行。
5. `DoVerifyOnWorkerThread` 函数在工作线程上被执行：
    * 创建一个 `ResultHelper` 对象来存储结果。
    * 调用 `verify_proc_->Verify`，传入证书、主机名、配置标志等参数。
    * 实际的证书验证逻辑在 `CertVerifyProc` 中执行，例如检查证书链的有效性、吊销状态等。
6. `verify_proc_->Verify` 执行完成后，将错误码和 `CertVerifyResult` 存储在 `ResultHelper` 中。
7. `base::BindOnce` 提供的回调函数（`MultiThreadedCertVerifier::InternalRequest::OnJobComplete`) 在主线程上被调用，接收 `ResultHelper` 的结果。

**可能的输出:**

* **如果证书验证成功:**
    * `verify_result` 指向的 `CertVerifyResult` 对象会被填充，包含例如证书链、策略信息等。
    * 回调函数 `callback` 会被调用，传入 `net::OK` (0) 作为错误码。
* **如果证书验证失败 (例如证书已吊销):**
    * `verify_result` 指向的 `CertVerifyResult` 对象会被填充，包含具体的错误原因，例如 `net::ERR_CERT_REVOKED`。
    * 回调函数 `callback` 会被调用，传入 `net::ERR_CERT_REVOKED` 作为错误码。

**涉及用户或编程常见的使用错误:**

1. **回调函数未正确处理:** 开发者在调用 `Verify` 时提供的回调函数没有正确处理验证结果，例如没有检查错误码，导致即使证书验证失败也没有采取相应的安全措施。

   ```c++
   // 错误示例：未检查错误码
   cert_verifier->Verify(params, &verify_result,
                         base::BindOnce([](int result) {
                           // 假设请求总是成功
                           LOG(INFO) << "证书验证完成";
                         }),
                         &request, net_log);
   ```

2. **传入空的主机名:**  调用 `Verify` 时传入空字符串作为主机名，这会导致 `Verify` 方法立即返回 `ERR_INVALID_ARGUMENT`。

   ```c++
   CertVerifier::RequestParams params;
   params.set_hostname(""); // 错误：主机名为空
   // ... 其他参数设置
   ```

3. **在析构 `MultiThreadedCertVerifier` 之后尝试使用其 `Request` 对象:**  `MultiThreadedCertVerifier` 析构时会重置所有未完成请求的回调函数。如果在析构后尝试操作这些请求对象，可能会导致程序崩溃或未定义的行为。

4. **错误地配置 `CertVerifier::Config`:**  例如，错误地禁用吊销检查，可能导致接受已被吊销的证书，从而带来安全风险。

   ```c++
   CertVerifier::Config config;
   config.enable_rev_checking = false; // 错误：禁用吊销检查
   cert_verifier->SetConfig(config);
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在 Chrome 浏览器中访问一个 HTTPS 网站 `https://example.com`，以下是可能触发 `MultiThreadedCertVerifier` 的步骤：

1. **用户在地址栏输入 `https://example.com` 并按下 Enter 键。**
2. **浏览器主进程发起导航请求。**
3. **网络线程处理导航请求，并尝试与 `example.com` 服务器建立 TCP 连接。**
4. **TCP 连接建立后，开始 TLS 握手。**
5. **服务器向浏览器发送其 SSL/TLS 证书链。**
6. **网络线程接收到证书链，并判断需要进行证书验证。**
7. **网络线程创建 `CertVerifier::RequestParams` 对象，包含服务器提供的证书、主机名 `example.com` 等信息。**
8. **网络线程获取 `MultiThreadedCertVerifier` 的实例。**
9. **网络线程调用 `MultiThreadedCertVerifier::Verify` 方法，传入 `RequestParams` 和一个回调函数。**
10. **`MultiThreadedCertVerifier` 将验证任务投递到工作线程池。**
11. **工作线程执行 `CertVerifyProc::Verify` 进行实际的证书验证。**
12. **验证结果通过回调函数传递回网络线程。**
13. **根据验证结果，网络线程决定是否继续 TLS 握手并建立安全连接。**
14. **如果验证成功，浏览器会加载网页内容；如果验证失败，浏览器会显示安全错误页面 (例如 NET::ERR_CERT_AUTHORITY_INVALID)。**

**作为调试线索:**

当遇到与证书验证相关的网络问题时，可以关注以下几个方面来定位问题是否与 `MultiThreadedCertVerifier` 相关：

* **Chrome 的 `net-internals` 工具:**  在 Chrome 浏览器中访问 `chrome://net-internals/#events` 可以查看详细的网络事件日志，包括证书验证的开始、结束、结果等信息。搜索与 "CERT_VERIFIER" 相关的事件可以追踪 `MultiThreadedCertVerifier` 的执行过程。
* **错误码:**  观察网络请求失败的错误码。例如 `net::ERR_CERT_AUTHORITY_INVALID`, `net::ERR_CERT_REVOKED`, `net::ERR_CERT_DATE_INVALID` 等错误码通常意味着证书验证失败，这可能是 `MultiThreadedCertVerifier` 的输出。
* **证书信息:**  检查服务器提供的证书是否正确，例如证书是否过期、是否由受信任的 CA 签发、主机名是否匹配等。
* **网络环境:**  检查用户的网络环境是否存在问题，例如网络连接不稳定、防火墙阻止了 OCSP 或 CRL 请求等，这些都可能影响证书吊销检查。
* **Chrome 配置:**  检查 Chrome 的安全设置，例如是否禁用了某些证书验证功能。

通过结合这些调试线索，可以逐步排查与 `MultiThreadedCertVerifier` 相关的证书验证问题。

### 提示词
```
这是目录为net/cert/multi_threaded_cert_verifier.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/cert/multi_threaded_cert_verifier.h"

#include "base/check_op.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/task/thread_pool.h"
#include "base/threading/thread_restrictions.h"
#include "net/base/net_errors.h"
#include "net/base/trace_constants.h"
#include "net/base/tracing.h"
#include "net/cert/cert_verify_proc.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/x509_certificate.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source_type.h"
#include "net/log/net_log_with_source.h"

namespace net {

// Allows DoVerifyOnWorkerThread to wait on a base::WaitableEvent.
// DoVerifyOnWorkerThread may wait on network operations done on a separate
// sequence. For instance when using the NSS-based implementation of certificate
// verification, the library requires a blocking callback for fetching OCSP and
// AIA responses.
class [[maybe_unused,
        nodiscard]] MultiThreadedCertVerifierScopedAllowBaseSyncPrimitives
    : public base::ScopedAllowBaseSyncPrimitives{};

namespace {

// Used to pass the result of DoVerifyOnWorkerThread() to
// MultiThreadedCertVerifier::InternalRequest::OnJobComplete().
struct ResultHelper {
  int error;
  CertVerifyResult result;
  NetLogWithSource net_log;
};

int GetFlagsForConfig(const CertVerifier::Config& config) {
  int flags = 0;

  if (config.enable_rev_checking)
    flags |= CertVerifyProc::VERIFY_REV_CHECKING_ENABLED;
  if (config.require_rev_checking_local_anchors)
    flags |= CertVerifyProc::VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS;
  if (config.enable_sha1_local_anchors)
    flags |= CertVerifyProc::VERIFY_ENABLE_SHA1_LOCAL_ANCHORS;
  if (config.disable_symantec_enforcement)
    flags |= CertVerifyProc::VERIFY_DISABLE_SYMANTEC_ENFORCEMENT;

  return flags;
}

// Runs the verification synchronously on a worker thread.
std::unique_ptr<ResultHelper> DoVerifyOnWorkerThread(
    const scoped_refptr<CertVerifyProc>& verify_proc,
    const scoped_refptr<X509Certificate>& cert,
    const std::string& hostname,
    const std::string& ocsp_response,
    const std::string& sct_list,
    int flags,
    const NetLogWithSource& net_log) {
  TRACE_EVENT0(NetTracingCategory(), "DoVerifyOnWorkerThread");
  auto verify_result = std::make_unique<ResultHelper>();
  verify_result->net_log = net_log;
  MultiThreadedCertVerifierScopedAllowBaseSyncPrimitives
      allow_base_sync_primitives;
  verify_result->error =
      verify_proc->Verify(cert.get(), hostname, ocsp_response, sct_list, flags,
                          &verify_result->result, net_log);
  return verify_result;
}

}  // namespace

// Helper to allow callers to cancel pending CertVerifier::Verify requests.
// Note that because the CertVerifyProc is blocking, it's not actually
// possible to cancel the in-progress request; instead, this simply guarantees
// that the provided callback will not be invoked if the Request is deleted.
class MultiThreadedCertVerifier::InternalRequest
    : public CertVerifier::Request,
      public base::LinkNode<InternalRequest> {
 public:
  InternalRequest(CompletionOnceCallback callback,
                  CertVerifyResult* caller_result);
  ~InternalRequest() override;

  void Start(const scoped_refptr<CertVerifyProc>& verify_proc,
             const CertVerifier::Config& config,
             const CertVerifier::RequestParams& params,
             const NetLogWithSource& caller_net_log);

  void ResetCallback() { callback_.Reset(); }

 private:
  // This is a static method with a |self| weak pointer instead of a regular
  // method, so that PostTask will still run it even if the weakptr is no
  // longer valid.
  static void OnJobComplete(base::WeakPtr<InternalRequest> self,
                            std::unique_ptr<ResultHelper> verify_result);

  CompletionOnceCallback callback_;
  raw_ptr<CertVerifyResult> caller_result_;

  base::WeakPtrFactory<InternalRequest> weak_factory_{this};
};

MultiThreadedCertVerifier::InternalRequest::InternalRequest(
    CompletionOnceCallback callback,
    CertVerifyResult* caller_result)
    : callback_(std::move(callback)), caller_result_(caller_result) {}

MultiThreadedCertVerifier::InternalRequest::~InternalRequest() {
  if (callback_) {
    // This InternalRequest was eagerly cancelled as the callback is still
    // valid, so |this| needs to be removed from MultiThreadedCertVerifier's
    // list.
    RemoveFromList();
  }
}

void MultiThreadedCertVerifier::InternalRequest::Start(
    const scoped_refptr<CertVerifyProc>& verify_proc,
    const CertVerifier::Config& config,
    const CertVerifier::RequestParams& params,
    const NetLogWithSource& caller_net_log) {
  const NetLogWithSource net_log(NetLogWithSource::Make(
      caller_net_log.net_log(), NetLogSourceType::CERT_VERIFIER_TASK));
  net_log.BeginEvent(NetLogEventType::CERT_VERIFIER_TASK);
  caller_net_log.AddEventReferencingSource(
      NetLogEventType::CERT_VERIFIER_TASK_BOUND, net_log.source());

  int flags = GetFlagsForConfig(config);
  if (params.flags() & CertVerifier::VERIFY_DISABLE_NETWORK_FETCHES) {
    flags |= CertVerifyProc::VERIFY_DISABLE_NETWORK_FETCHES;
  }
  base::ThreadPool::PostTaskAndReplyWithResult(
      FROM_HERE,
      {base::MayBlock(), base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
      base::BindOnce(&DoVerifyOnWorkerThread, verify_proc, params.certificate(),
                     params.hostname(), params.ocsp_response(),
                     params.sct_list(), flags, net_log),
      base::BindOnce(&MultiThreadedCertVerifier::InternalRequest::OnJobComplete,
                     weak_factory_.GetWeakPtr()));
}

// static
void MultiThreadedCertVerifier::InternalRequest::OnJobComplete(
    base::WeakPtr<InternalRequest> self,
    std::unique_ptr<ResultHelper> verify_result) {
  // Always log the EndEvent, even if the Request has been destroyed.
  verify_result->net_log.EndEvent(NetLogEventType::CERT_VERIFIER_TASK);

  // Check |self| weakptr and don't continue if the Request was destroyed.
  if (!self)
    return;

  DCHECK(verify_result);

  // If the MultiThreadedCertVerifier has been deleted, the callback will have
  // been reset to null.
  if (!self->callback_)
    return;

  // If ~MultiThreadedCertVerifier has not Reset() our callback, then this
  // InternalRequest will not have been removed from MultiThreadedCertVerifier's
  // list yet.
  self->RemoveFromList();

  *self->caller_result_ = verify_result->result;
  // Note: May delete |self|.
  std::move(self->callback_).Run(verify_result->error);
}

MultiThreadedCertVerifier::MultiThreadedCertVerifier(
    scoped_refptr<CertVerifyProc> verify_proc,
    scoped_refptr<CertVerifyProcFactory> verify_proc_factory)
    : verify_proc_(std::move(verify_proc)),
      verify_proc_factory_(std::move(verify_proc_factory)) {
  CHECK(verify_proc_);
  CHECK(verify_proc_factory_);
}

MultiThreadedCertVerifier::~MultiThreadedCertVerifier() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // Reset the callbacks for each InternalRequest to fulfill the respective
  // net::CertVerifier contract.
  for (base::LinkNode<InternalRequest>* node = request_list_.head();
       node != request_list_.end();) {
    // Resetting the callback may delete the request, so save a pointer to the
    // next node first.
    base::LinkNode<InternalRequest>* next_node = node->next();
    node->value()->ResetCallback();
    node = next_node;
  }
}

int MultiThreadedCertVerifier::Verify(const RequestParams& params,
                                      CertVerifyResult* verify_result,
                                      CompletionOnceCallback callback,
                                      std::unique_ptr<Request>* out_req,
                                      const NetLogWithSource& net_log) {
  CHECK(params.certificate());
  out_req->reset();

  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (callback.is_null() || !verify_result || params.hostname().empty())
    return ERR_INVALID_ARGUMENT;

  std::unique_ptr<InternalRequest> request =
      std::make_unique<InternalRequest>(std::move(callback), verify_result);
  request->Start(verify_proc_, config_, params, net_log);
  request_list_.Append(request.get());
  *out_req = std::move(request);
  return ERR_IO_PENDING;
}

void MultiThreadedCertVerifier::UpdateVerifyProcData(
    scoped_refptr<CertNetFetcher> cert_net_fetcher,
    const net::CertVerifyProc::ImplParams& impl_params,
    const net::CertVerifyProc::InstanceParams& instance_params) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  verify_proc_ = verify_proc_factory_->CreateCertVerifyProc(
      std::move(cert_net_fetcher), impl_params, instance_params);
  CHECK(verify_proc_);
  NotifyCertVerifierChanged();
}

void MultiThreadedCertVerifier::SetConfig(const CertVerifier::Config& config) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  config_ = config;
}

void MultiThreadedCertVerifier::AddObserver(Observer* observer) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  observers_.AddObserver(observer);
}

void MultiThreadedCertVerifier::RemoveObserver(Observer* observer) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  observers_.RemoveObserver(observer);
}

void MultiThreadedCertVerifier::NotifyCertVerifierChanged() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  for (Observer& observer : observers_) {
    observer.OnCertVerifierChanged();
  }
}

}  // namespace net
```