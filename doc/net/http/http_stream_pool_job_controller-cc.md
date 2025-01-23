Response:
Let's break down the thought process for analyzing this Chromium source code.

1. **Understand the Goal:** The primary goal is to analyze the `HttpStreamPool::JobController` class in `http_stream_pool_job_controller.cc` and explain its functionality, its relation to JavaScript (if any), logical inferences, potential user/programming errors, and debugging information.

2. **Initial Code Scan (Keywords and Structure):** Quickly scan the code for keywords that provide clues about its purpose. Look for:
    * Class names: `HttpStreamPool`, `JobController`, `HttpStreamRequest`, `HttpStream`, `SpdySession`, `QuicSession`. These suggest it's involved in managing HTTP/2 and QUIC connections.
    * Method names: `RequestStream`, `Preconnect`, `OnStreamReady`, `OnStreamFailed`, `CalculateAlternative`. These hint at the lifecycle of requesting and establishing HTTP connections.
    * Member variables: `origin_stream_key_`, `alternative_`, `origin_job_`, `alternative_job_`. These point to the core logic of handling primary and alternative connection attempts.
    * Includes: Headers like `net/http/...`, `net/quic/...`, `net/spdy/...` confirm the involvement of different HTTP protocols.

3. **Identify Core Functionality (Step-by-Step Logic):**  Trace the execution flow of key methods:
    * **`RequestStream()`:** This appears to be the main entry point for requesting a new HTTP stream. It first checks for existing QUIC/HTTP/2 sessions. If none are found, it potentially starts an "alternative job" (likely for QUIC or HTTP/2 via Alt-Svc) and then an "origin job" (likely for the initial protocol, perhaps HTTP/1.1 or HTTP/2).
    * **`CalculateAlternative()`:** This static method determines if an alternative protocol (like QUIC) should be attempted based on Alt-Svc information.
    * **`Preconnect()`:** This method handles pre-establishing connections. It checks if the port is allowed and if existing sessions can be used.
    * **`OnStreamReady()`, `OnStreamFailed()`, `OnCertificateError()`, `OnNeedsClientAuth()`:** These are callbacks from the `Job` objects, indicating the outcome of connection attempts. They handle success, failures, and TLS-related events.

4. **Infer Relationships and Responsibilities:** Based on the identified functionality, deduce the class's responsibilities:
    * Managing the lifecycle of requesting an HTTP stream.
    * Trying both the origin protocol and alternative protocols (like QUIC) concurrently or sequentially.
    * Reusing existing HTTP/2 and QUIC sessions.
    * Handling connection errors and TLS authentication challenges.
    * Interacting with `HttpStreamPool`, `HttpStreamRequest`, and `Job` classes.

5. **Look for JavaScript Connections (or Lack Thereof):** Carefully examine the methods and data structures. There's no direct mention of JavaScript APIs like `fetch()` or `XMLHttpRequest`. The focus is on the underlying network stack implementation. Conclude that the relationship is indirect: JavaScript uses browser APIs which eventually rely on this code for network communication.

6. **Construct Logical Inferences (Input/Output Examples):** Create hypothetical scenarios to illustrate the class's behavior:
    * **Scenario 1 (Successful HTTP/2):** Request to an HTTP/2 server. The `RequestStream` finds an existing HTTP/2 session and returns it.
    * **Scenario 2 (Successful QUIC after Alt-Svc):** Request to an HTTPS server with Alt-Svc advertising QUIC. The alternative job succeeds, and a QUIC connection is established.
    * **Scenario 3 (HTTP/1.1 Fallback):**  Request to an HTTPS server. The alternative job (QUIC) fails, so the origin job (likely HTTP/1.1 or HTTP/2) establishes a connection.
    * **Scenario 4 (Preconnect):** Call `Preconnect`. If an existing session is available, it returns immediately. Otherwise, it triggers a preconnection attempt.

7. **Identify Potential User/Programming Errors:** Think about how developers using the Chromium network stack might misuse it or encounter problems:
    * **Incorrect Alt-Svc configuration:**  The server might advertise an alternative service that isn't actually working.
    * **Firewall blocking QUIC:** A user's firewall could block UDP, preventing QUIC connections.
    * **Mismatched configurations:** Issues could arise if the client and server have conflicting QUIC or HTTP/2 settings.

8. **Consider Debugging Scenarios (User Actions and Code Path):**  Imagine a user scenario and trace how it might lead to this code:
    * User types a URL in the address bar.
    * Browser resolves the hostname.
    * `HttpStreamPool::RequestStream` is called to get a connection.
    * `JobController` is created to manage the connection attempt.
    * This sequence provides a debugging path, allowing developers to step through the code.

9. **Structure the Explanation:** Organize the findings into logical sections as requested:
    * Functionality overview.
    * Relationship to JavaScript (and explain the indirect link).
    * Logical inferences (with input/output examples).
    * User/programming errors.
    * Debugging information.

10. **Refine and Review:** Read through the explanation to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that need further elaboration. For example, initially, I might have just said "it manages connections," but refining it to specify "concurrent or sequential attempts for origin and alternative protocols" is more precise. I also considered the use of `PostTask` and its implications, adding that detail.
This C++ source code file, `http_stream_pool_job_controller.cc`, is part of the Chromium network stack and is responsible for managing the process of establishing an HTTP connection. It acts as a coordinator for trying different connection methods, including the origin protocol and potentially alternative protocols like QUIC or HTTP/2 via Alt-Svc.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Initiating Connection Attempts:**  The `JobController` is created when a request for an HTTP stream is made. It takes information about the destination, proxy, and available alternative services.

2. **Managing Origin and Alternative Jobs:**
   - It creates and manages two types of `Job` objects: an "origin job" and an "alternative job".
   - The **origin job** attempts to establish a connection using the initially requested protocol (which might be HTTP/1.1 or HTTP/2).
   - The **alternative job** (if applicable) attempts to establish a connection using an advertised alternative protocol, most commonly QUIC or HTTP/2 over a different port. The `CalculateAlternative` function determines if an alternative job should be created based on available Alternative Service (Alt-Svc) information.

3. **Prioritizing Connection Attempts:** It starts the alternative job (if it exists) first. If the alternative job succeeds quickly, the origin job might be canceled. This prioritizes newer, potentially faster protocols like QUIC.

4. **Reusing Existing Sessions:** Before creating new jobs, it checks if there are existing reusable HTTP/2 (SpdySession) or QUIC sessions available for the target origin or the alternative service. This avoids unnecessary connection establishment.

5. **Handling Connection Success and Failure:**
   - It listens for success (`OnStreamReady`) or failure (`OnStreamFailed`) events from the managed `Job` objects.
   - Upon success, it provides the established `HttpStream` to the requesting delegate.
   - Upon failure, it handles the error and potentially falls back to the other job or reports the error to the delegate.

6. **Handling TLS/SSL Errors:** It handles certificate errors (`OnCertificateError`) and client authentication requests (`OnNeedsClientAuth`) that might occur during the connection handshake.

7. **Preconnecting:** The `Preconnect` method allows for proactively establishing connections to a server, even before a request is made. This can improve performance by reducing latency for subsequent requests.

8. **Respecting Limits:** It respects connection limits configured in the network stack, unless the `LOAD_IGNORE_LIMITS` flag is set on the request.

9. **Marking Broken Alternative Services:** If an alternative connection attempt fails, it can inform the `HttpServerProperties` to mark that alternative service as broken for future requests, preventing repeated failed attempts.

**Relationship to JavaScript:**

This C++ code doesn't directly interact with JavaScript code in the renderer process. However, it's a crucial part of the Chromium network stack that **underpins the functionality of JavaScript network APIs** like `fetch()` and `XMLHttpRequest`.

**Example:**

Imagine a JavaScript application using `fetch()` to request an HTTPS resource from `https://example.com`.

1. The JavaScript `fetch()` call is translated into a network request within the browser.
2. The network stack creates an `HttpStreamPool::JobController` for this request.
3. `JobController` checks if there's an Alt-Svc entry for `example.com` indicating QUIC is available.
4. If so, an **alternative job** is created to attempt a QUIC connection.
5. Simultaneously or shortly after, an **origin job** is created to attempt a connection using the standard HTTPS protocol (potentially HTTP/2 or HTTP/1.1).
6. If the QUIC connection succeeds quickly, the `OnStreamReady` method of the `JobController` is called.
7. The `JobController` then provides the established QUIC stream to the higher layers of the network stack, eventually providing the response data back to the JavaScript `fetch()` promise.

**Logical Inferences (Hypothetical Input & Output):**

**Scenario 1: Successful QUIC Connection via Alt-Svc**

* **Input:** A request to `https://alt-svc.example.com`, where the server advertises QUIC.
* **Assumption:** The client has learned about this Alt-Svc entry previously.
* **`CalculateAlternative` Output:** Returns an `Alternative` object with `protocol = NextProto::kProtoQUIC`.
* **Process:** An `alternative_job_` for QUIC is started. It connects successfully.
* **Output (`OnStreamReady`):**  The `JobController` receives an `HttpStream` of type `QuicHttpStream` and `negotiated_protocol = NextProto::kProtoQUIC`. The `origin_job_` might be canceled.

**Scenario 2: Fallback to HTTP/1.1 after QUIC Failure**

* **Input:** A request to `https://no-quic.example.com`. The server *might* advertise QUIC, but the connection fails.
* **Assumption:**  The client attempts a QUIC connection.
* **Process:** The `alternative_job_` for QUIC fails (`OnStreamFailed`). The `origin_job_` (attempting HTTP/1.1 or HTTP/2) proceeds and connects successfully.
* **Output (`OnStreamReady`):** The `JobController` receives an `HttpStream` of type `SpdyHttpStream` (for HTTP/2) or a regular `HttpStream` (for HTTP/1.1) and the corresponding `negotiated_protocol`.

**User or Programming Common Usage Errors:**

1. **Incorrectly configured Alternative Services on the server:** If the server advertises an alternative service (like QUIC) on a port that's not actually listening or is misconfigured, the `alternative_job_` will fail, potentially delaying the connection establishment while the fallback happens. This isn't a direct *user* error but a server configuration issue that impacts the user experience.

2. **Firewalls blocking QUIC:** If a user's firewall blocks UDP traffic, QUIC connections (the most common alternative service) will fail. This will force connections to fall back to TCP-based protocols, potentially impacting performance.

3. **Relying on specific protocol behavior without checking:**  A developer might assume a certain protocol (like HTTP/2) will always be used if advertised. However, network conditions or server issues can lead to fallbacks. Robust applications should handle different negotiated protocols gracefully.

**User Operations and Debugging Clues:**

Let's trace how a user action can lead to this code:

1. **User types a URL in the address bar (e.g., `https://www.example.com`).**
2. **The browser's UI process initiates a navigation.**
3. **The network service in Chromium receives the request.**
4. **The network service determines the destination and checks for cached resources.**
5. **To fetch the resource, the `HttpStreamPool` is asked for an `HttpStream`.**
6. **`HttpStreamPool::RequestStream` is called.**
7. **This is where the `HttpStreamPool::JobController` is created.**
8. **The `JobController` will then proceed with creating and managing the `origin_job_` and potentially the `alternative_job_` as described earlier.**

**Debugging Clues:**

* **NetLog:** Chromium's NetLog is an invaluable tool for debugging network issues. When a connection is being established, the NetLog will record events related to the `HttpStreamPool::JobController`, including the creation of jobs, attempts to reuse sessions, and the success or failure of connection attempts for both the origin and alternative protocols. Look for events like:
    * "http_stream_pool_job_controller_created"
    * "http_stream_pool_job_started" (for both origin and alternative jobs)
    * "http_stream_request_http2_session_reused" or "quic_session_got_from_pool" (if existing sessions are reused)
    * "http_stream_job_done" (indicating the outcome of a job)
    * Error events related to connection failures.

* **Experiment Flags:** Chromium has various experiment flags related to networking. Toggling these flags can sometimes help isolate issues by enabling or disabling specific features, such as QUIC or Alt-Svc.

* **Code Breakpoints:** Developers can set breakpoints in the `http_stream_pool_job_controller.cc` file to step through the code and observe the flow of execution, the values of variables, and the decisions being made during the connection establishment process. Pay attention to:
    * The outcome of `CalculateAlternative`.
    * Whether existing sessions are found.
    * The success or failure of the `Start()` method for the jobs.
    * The reasons for `OnStreamFailed` calls.

In summary, `http_stream_pool_job_controller.cc` plays a vital role in optimizing HTTP connection establishment in Chromium by intelligently managing attempts using the origin protocol and potentially faster alternative protocols, while also efficiently reusing existing connections. It's a key component that impacts the performance and reliability of web browsing.

### 提示词
```
这是目录为net/http/http_stream_pool_job_controller.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_pool_job_controller.h"

#include <memory>
#include <optional>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "base/notreached.h"
#include "base/task/sequenced_task_runner.h"
#include "net/base/load_flags.h"
#include "net/base/load_states.h"
#include "net/base/net_error_details.h"
#include "net/base/net_errors.h"
#include "net/base/port_util.h"
#include "net/base/request_priority.h"
#include "net/dns/public/resolve_error_info.h"
#include "net/http/alternative_service.h"
#include "net/http/http_network_session.h"
#include "net/http/http_stream_key.h"
#include "net/http/http_stream_pool.h"
#include "net/http/http_stream_pool_group.h"
#include "net/http/http_stream_pool_job.h"
#include "net/http/http_stream_pool_request_info.h"
#include "net/http/http_stream_request.h"
#include "net/quic/quic_chromium_client_session.h"
#include "net/quic/quic_http_stream.h"
#include "net/socket/next_proto.h"
#include "net/spdy/spdy_http_stream.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_config.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_versions.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

namespace net {

// static
std::optional<HttpStreamPool::JobController::Alternative>
HttpStreamPool::JobController::CalculateAlternative(
    HttpStreamPool* pool,
    const HttpStreamKey& origin_stream_key,
    const HttpStreamPoolRequestInfo& request_info,
    bool enable_alternative_services) {
  const NextProto protocol = request_info.alternative_service_info.protocol();

  if (!enable_alternative_services || protocol == NextProto::kProtoUnknown) {
    return std::nullopt;
  }

  CHECK(protocol == NextProto::kProtoHTTP2 ||
        protocol == NextProto::kProtoQUIC);

  url::SchemeHostPort destination(
      url::kHttpsScheme,
      request_info.alternative_service_info.host_port_pair().host(),
      request_info.alternative_service_info.host_port_pair().port());

  // If the alternative endpoint's destination is the same as origin, we don't
  // need an alternative job since the origin job will handle all protocols for
  // the destination.
  if (destination == request_info.destination) {
    return std::nullopt;
  }

  HttpStreamKey stream_key(
      destination, request_info.privacy_mode, request_info.socket_tag,
      request_info.network_anonymization_key, request_info.secure_dns_policy,
      request_info.disable_cert_network_fetches);

  Alternative alternative = {
      .stream_key = std::move(stream_key),
      .protocol = request_info.alternative_service_info.protocol(),
      .quic_version = quic::ParsedQuicVersion::Unsupported()};

  if (protocol == NextProto::kProtoQUIC) {
    alternative.quic_version =
        pool->SelectQuicVersion(request_info.alternative_service_info);
    alternative.quic_key =
        origin_stream_key.CalculateQuicSessionAliasKey(std::move(destination));
  }

  return alternative;
}

HttpStreamPool::JobController::JobController(
    HttpStreamPool* pool,
    HttpStreamPoolRequestInfo request_info,
    bool enable_ip_based_pooling,
    bool enable_alternative_services)
    : pool_(pool),
      enable_ip_based_pooling_(enable_ip_based_pooling),
      enable_alternative_services_(enable_alternative_services),
      respect_limits_(request_info.load_flags & LOAD_IGNORE_LIMITS
                          ? RespectLimits::kIgnore
                          : RespectLimits::kRespect),
      is_http1_allowed_(request_info.is_http1_allowed),
      proxy_info_(request_info.proxy_info),
      alternative_service_info_(request_info.alternative_service_info),
      origin_stream_key_(request_info.destination,
                         request_info.privacy_mode,
                         request_info.socket_tag,
                         request_info.network_anonymization_key,
                         request_info.secure_dns_policy,
                         request_info.disable_cert_network_fetches),
      origin_quic_key_(origin_stream_key_.CalculateQuicSessionAliasKey()),
      alternative_(CalculateAlternative(pool,
                                        origin_stream_key_,
                                        request_info,
                                        enable_alternative_services_)) {
  CHECK(proxy_info_.is_direct());
  if (!alternative_.has_value() &&
      alternative_service_info_.protocol() == NextProto::kProtoQUIC) {
    origin_quic_version_ = pool_->SelectQuicVersion(alternative_service_info_);
  }
}

HttpStreamPool::JobController::~JobController() = default;

std::unique_ptr<HttpStreamRequest> HttpStreamPool::JobController::RequestStream(
    HttpStreamRequest::Delegate* delegate,
    RequestPriority priority,
    const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs,
    const NetLogWithSource& net_log) {
  CHECK(!delegate_);
  CHECK(!stream_request_);

  if (pool_->delegate_for_testing_) {
    pool_->delegate_for_testing_->OnRequestStream(origin_stream_key_);
  }

  delegate_ = delegate;
  auto stream_request = std::make_unique<HttpStreamRequest>(
      this, /*websocket_handshake_stream_create_helper=*/nullptr, net_log,
      HttpStreamRequest::HTTP_STREAM);
  stream_request_ = stream_request.get();

  std::unique_ptr<HttpStream> quic_http_stream =
      MaybeCreateStreamFromExistingQuicSession();
  if (quic_http_stream) {
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(
            &HttpStreamPool::JobController::CallRequestCompleteAndStreamReady,
            weak_ptr_factory_.GetWeakPtr(), std::move(quic_http_stream),
            NextProto::kProtoQUIC));
    return stream_request;
  }

  SpdySessionKey spdy_session_key =
      origin_stream_key_.CalculateSpdySessionKey();
  base::WeakPtr<SpdySession> spdy_session = pool_->FindAvailableSpdySession(
      origin_stream_key_, spdy_session_key, enable_ip_based_pooling_, net_log);
  if (spdy_session) {
    auto http_stream = std::make_unique<SpdyHttpStream>(
        spdy_session, net_log.source(),
        spdy_session_pool()->GetDnsAliasesForSessionKey(spdy_session_key));
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(
            &HttpStreamPool::JobController::CallRequestCompleteAndStreamReady,
            weak_ptr_factory_.GetWeakPtr(), std::move(http_stream),
            NextProto::kProtoHTTP2));
    return stream_request;
  }

  if (alternative_.has_value()) {
    alternative_job_ =
        pool_
            ->GetOrCreateGroup(alternative_->stream_key, alternative_->quic_key)
            .CreateJob(this, alternative_->protocol, is_http1_allowed_,
                       proxy_info_);
    alternative_job_->Start(
        priority, allowed_bad_certs, respect_limits_, enable_ip_based_pooling_,
        enable_alternative_services_, alternative_->quic_version, net_log);
  } else {
    alternative_job_result_ = OK;
  }

  const bool alternative_job_succeeded = alternative_job_ &&
                                         alternative_job_result_.has_value() &&
                                         *alternative_job_result_ == OK;
  if (!alternative_job_succeeded) {
    origin_job_ = pool_->GetOrCreateGroup(origin_stream_key_, origin_quic_key_)
                      .CreateJob(this, NextProto::kProtoUnknown,
                                 is_http1_allowed_, proxy_info_);
    origin_job_->Start(priority, allowed_bad_certs, respect_limits_,
                       enable_ip_based_pooling_, enable_alternative_services_,
                       origin_quic_version_, net_log);
  }

  return stream_request;
}

int HttpStreamPool::JobController::Preconnect(
    size_t num_streams,
    CompletionOnceCallback callback) {
  num_streams = std::min(kDefaultMaxStreamSocketsPerGroup, num_streams);

  if (!IsPortAllowedForScheme(origin_stream_key_.destination().port(),
                              origin_stream_key_.destination().scheme())) {
    return ERR_UNSAFE_PORT;
  }

  if (CanUseExistingQuicSession()) {
    return OK;
  }

  SpdySessionKey spdy_session_key =
      origin_stream_key_.CalculateSpdySessionKey();
  bool had_spdy_session = spdy_session_pool()->HasAvailableSession(
      spdy_session_key, /*is_websocket=*/false);
  if (pool_->FindAvailableSpdySession(origin_stream_key_, spdy_session_key,
                                      /*enable_ip_based_pooling=*/true)) {
    return OK;
  }
  if (had_spdy_session) {
    // We had a SPDY session but the server required HTTP/1.1. The session is
    // going away right now.
    return ERR_HTTP_1_1_REQUIRED;
  }

  if (pool_->delegate_for_testing_) {
    // Some tests expect OnPreconnect() is called after checking existing
    // sessions.
    std::optional<int> result = pool_->delegate_for_testing_->OnPreconnect(
        origin_stream_key_, num_streams);
    if (result.has_value()) {
      return *result;
    }
  }

  return pool_->GetOrCreateGroup(origin_stream_key_, origin_quic_key_)
      .Preconnect(num_streams, origin_quic_version_, std::move(callback));
}

void HttpStreamPool::JobController::OnStreamReady(
    Job* job,
    std::unique_ptr<HttpStream> stream,
    NextProto negotiated_protocol) {
  SetJobResult(job, OK);
  // Use PostTask to align the behavior with HttpStreamFactory::Job, see
  // https://crrev.com/2827533002.
  // TODO(crbug.com/346835898): Avoid using PostTask here if possible.
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&JobController::CallRequestCompleteAndStreamReady,
                     weak_ptr_factory_.GetWeakPtr(), std::move(stream),
                     negotiated_protocol));
}

void HttpStreamPool::JobController::OnStreamFailed(
    Job* job,
    int status,
    const NetErrorDetails& net_error_details,
    ResolveErrorInfo resolve_error_info) {
  stream_request_->AddConnectionAttempts(job->connection_attempts());
  SetJobResult(job, status);
  if (AllJobsFinished()) {
    // Use PostTask to align the behavior with HttpStreamFactory::Job, see
    // https://crrev.com/2827533002.
    // TODO(crbug.com/346835898): Avoid using PostTask here if possible.
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&JobController::CallOnStreamFailed,
                       weak_ptr_factory_.GetWeakPtr(), status,
                       net_error_details, std::move(resolve_error_info)));
  }
}

void HttpStreamPool::JobController::OnCertificateError(
    Job* job,
    int status,
    const SSLInfo& ssl_info) {
  stream_request_->AddConnectionAttempts(job->connection_attempts());
  CancelOtherJob(job);
  // Use PostTask to align the behavior with HttpStreamFactory::Job, see
  // https://crrev.com/2827533002.
  // TODO(crbug.com/346835898): Avoid using PostTask here if possible.
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&JobController::CallOnCertificateError,
                     weak_ptr_factory_.GetWeakPtr(), status, ssl_info));
}

void HttpStreamPool::JobController::OnNeedsClientAuth(
    Job* job,
    SSLCertRequestInfo* cert_info) {
  stream_request_->AddConnectionAttempts(job->connection_attempts());
  CancelOtherJob(job);
  // Use PostTask to align the behavior with HttpStreamFactory::Job, see
  // https://crrev.com/2827533002.
  // TODO(crbug.com/346835898): Avoid using PostTask here if possible.
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&JobController::CallOnNeedsClientAuth,
                                weak_ptr_factory_.GetWeakPtr(),
                                base::RetainedRef(cert_info)));
}

LoadState HttpStreamPool::JobController::GetLoadState() const {
  CHECK(stream_request_);
  if (stream_request_->completed()) {
    return LOAD_STATE_IDLE;
  }

  if (origin_job_) {
    return origin_job_->GetLoadState();
  }
  if (alternative_job_) {
    return alternative_job_->GetLoadState();
  }
  return LOAD_STATE_IDLE;
}

void HttpStreamPool::JobController::OnRequestComplete() {
  delegate_ = nullptr;
  stream_request_ = nullptr;

  origin_job_.reset();
  alternative_job_.reset();
  MaybeMarkAlternativeServiceBroken();

  pool_->OnJobControllerComplete(this);
}

int HttpStreamPool::JobController::RestartTunnelWithProxyAuth() {
  NOTREACHED();
}

void HttpStreamPool::JobController::SetPriority(RequestPriority priority) {
  if (origin_job_) {
    origin_job_->SetPriority(priority);
  }
  if (alternative_job_) {
    alternative_job_->SetPriority(priority);
  }
}

QuicSessionPool* HttpStreamPool::JobController::quic_session_pool() {
  return pool_->http_network_session()->quic_session_pool();
}

SpdySessionPool* HttpStreamPool::JobController::spdy_session_pool() {
  return pool_->http_network_session()->spdy_session_pool();
}

std::unique_ptr<HttpStream>
HttpStreamPool::JobController::MaybeCreateStreamFromExistingQuicSession() {
  std::unique_ptr<HttpStream> stream =
      MaybeCreateStreamFromExistingQuicSessionInternal(origin_quic_key_);
  if (stream) {
    return stream;
  }

  if (alternative_.has_value()) {
    stream = MaybeCreateStreamFromExistingQuicSessionInternal(
        alternative_->quic_key);
  }

  return stream;
}

std::unique_ptr<HttpStream>
HttpStreamPool::JobController::MaybeCreateStreamFromExistingQuicSessionInternal(
    const QuicSessionAliasKey& key) {
  if (!key.destination().IsValid() ||
      !pool_->CanUseQuic(
          key.destination(), key.session_key().network_anonymization_key(),
          enable_ip_based_pooling_, enable_alternative_services_)) {
    return nullptr;
  }

  QuicChromiumClientSession* quic_session =
      quic_session_pool()->FindExistingSession(key.session_key(),
                                               key.destination());
  if (quic_session) {
    return std::make_unique<QuicHttpStream>(
        quic_session->CreateHandle(key.destination()),
        quic_session->GetDnsAliasesForSessionKey(key.session_key()));
  }

  if (alternative_.has_value()) {
    return nullptr;
  }

  return nullptr;
}

bool HttpStreamPool::JobController::CanUseExistingQuicSession() {
  return pool_->CanUseExistingQuicSession(
      origin_quic_key_, enable_ip_based_pooling_, enable_alternative_services_);
}

void HttpStreamPool::JobController::CallRequestCompleteAndStreamReady(
    std::unique_ptr<HttpStream> stream,
    NextProto negotiated_protocol) {
  CHECK(stream_request_);
  CHECK(delegate_);
  stream_request_->Complete(negotiated_protocol,
                            ALTERNATE_PROTOCOL_USAGE_UNSPECIFIED_REASON);
  delegate_->OnStreamReady(proxy_info_, std::move(stream));
}

void HttpStreamPool::JobController::CallOnStreamFailed(
    int status,
    const NetErrorDetails& net_error_details,
    ResolveErrorInfo resolve_error_info) {
  delegate_->OnStreamFailed(status, net_error_details, proxy_info_,
                            std::move(resolve_error_info));
}

void HttpStreamPool::JobController::CallOnCertificateError(
    int status,
    const SSLInfo& ssl_info) {
  delegate_->OnCertificateError(status, ssl_info);
}

void HttpStreamPool::JobController::CallOnNeedsClientAuth(
    SSLCertRequestInfo* cert_info) {
  delegate_->OnNeedsClientAuth(cert_info);
}

void HttpStreamPool::JobController::SetJobResult(Job* job, int status) {
  if (origin_job_.get() == job) {
    origin_job_result_ = status;
  } else if (alternative_job_.get() == job) {
    alternative_job_result_ = status;
  } else {
    NOTREACHED();
  }
}

void HttpStreamPool::JobController::CancelOtherJob(Job* job) {
  if (origin_job_.get() == job) {
    alternative_job_.reset();
  } else if (alternative_job_.get() == job) {
    origin_job_.reset();
  } else {
    NOTREACHED();
  }
}

bool HttpStreamPool::JobController::AllJobsFinished() {
  return origin_job_result_.has_value() && alternative_job_result_.has_value();
}

void HttpStreamPool::JobController::MaybeMarkAlternativeServiceBroken() {
  // If alternative job succeeds or not completed, no brokenness to report.
  if (!alternative_job_result_.has_value() || *alternative_job_result_ == OK) {
    return;
  }

  // No brokenness to report if the origin job fails.
  if (origin_job_result_.has_value() && *origin_job_result_ != OK) {
    return;
  }

  CHECK(alternative_.has_value());

  pool_->http_network_session()
      ->http_server_properties()
      ->MarkAlternativeServiceBroken(
          alternative_service_info_.alternative_service(),
          alternative_->stream_key.network_anonymization_key());
}

}  // namespace net
```