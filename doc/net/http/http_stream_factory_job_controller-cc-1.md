Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is the second part of the `HttpStreamFactory::JobController` class in Chromium's network stack.

I need to analyze the methods in this part of the code and describe what they do. I also need to address specific points from the prompt:
1. **Functionality:**  Provide a general overview of what this code does.
2. **JavaScript Relation:** Explain if and how it interacts with JavaScript.
3. **Logic Inference:**  Provide examples of input and output based on the logic within the code.
4. **User/Programming Errors:**  Give examples of common mistakes related to this code.
5. **User Operation to Reach Here:** Describe the steps a user takes that eventually involve this code.
6. **Summary of Functionality (Part 2):**  Specifically summarize the functionality presented in this code snippet.

**Plan:**
1. Go through each method in the provided snippet and describe its purpose.
2. Analyze potential connections to JavaScript (mostly indirect through network requests).
3. Identify key decision points in the logic and create hypothetical input/output scenarios.
4. Consider common errors that might occur during the execution of these methods.
5. Outline the user actions that trigger network requests, leading to this code being executed.
6. Condense the functionalities of the methods in this part into a concise summary.
这是 `net/http/http_stream_factory_job_controller.cc` 文件 `HttpStreamFactory::JobController` 类的第二部分代码。基于这段代码，我们可以归纳其主要功能如下：

**主要功能归纳：**

这段代码主要负责管理和协调多个 `Job` 对象（`main_job_`, `alternative_job_`, `dns_alpn_h3_job_`），这些 `Job` 对象尝试建立 HTTP 或 QUIC 连接以满足一个网络请求。其核心功能包括：

* **启动和管理不同的连接尝试 (Jobs):** 负责启动主连接尝试 (`main_job_`)，可选的备用连接尝试 (`alternative_job_`)，以及基于 DNS 的 ALPN HTTP/3 连接尝试 (`dns_alpn_h3_job_`)。它会根据不同的条件和策略决定是否启动这些 Job。
* **优化连接过程：**  通过尝试不同的连接方式（例如，通过备用协议或 HTTP/3）来加速连接建立。
* **处理连接成功和失败：** 监听各个 `Job` 的完成状态，并在其中一个 `Job` 成功时绑定请求到该 `Job`。
* **清理不必要的 Job：** 当一个更优的连接方式（例如，通过 QUIC）可用时，取消或停止其他不再需要的 `Job`。
* **报告备用协议的可用性和失败情况：** 记录备用协议的使用情况，并在备用连接失败时报告，以便后续避免使用已损坏的备用协议。
* **处理代理重试：**  在连接失败时，如果适用，会触发代理回退机制。
* **切换到 HttpStreamPool:** 在某些情况下，会将请求切换到 `HttpStreamPool` 进行处理。

**更详细的功能说明：**

* **`Start()`:**
    *  负责启动 `main_job_`， `alternative_job_` 和 `dns_alpn_h3_job_`。
    *  根据是否存在可用的备用连接或 DNS ALPN HTTP/3 连接来决定是否阻塞 `main_job_` 的启动，以优化 fallback 逻辑。
    * **假设输入与输出:**
        * **假设输入:**  存在一个 `request_` 对象，并且 `alternative_job_` 和 `dns_alpn_h3_job_` 都已创建。
        * **输出:**  会依次调用 `alternative_job_->Start()`, `dns_alpn_h3_job_->Start()` 和 `main_job_->Start()`。如果不存在备用连接但存在 DNS ALPN HTTP/3 连接且主连接有可用 socket，则 `main_job_is_blocked_` 会被设置为 `true`。

* **`ClearInappropriateJobs()`:**
    *  根据当前可用的连接情况清理不必要的 `Job`。
    *  如果 `dns_alpn_h3_job_` 有可用的 QUIC 会话，则清除 `main_job_` 和 `alternative_job_`。
    *  如果 `alternative_job_` 有可用的 QUIC 会话，或者其目标与 DNS Job 相同，则清除 `dns_alpn_h3_job_`。

* **`BindJob(Job* job)`:**
    *  将请求绑定到成功的 `Job`。
    *  记录绑定事件到 NetLog。
    *  调用 `OrphanUnboundJob()` 来处理未绑定的 `Job`。

* **`OrphanUnboundJob()`:**
    *  当请求绑定到某个 `Job` 后，处理其他未绑定的 `Job`。
    *  如果绑定的是 `main_job_`，则允许 `alternative_job_` 和 `dns_alpn_h3_job_` 完成，以便报告潜在的损坏的备用服务。
    *  如果绑定的是 `alternative_job_` 或 `dns_alpn_h3_job_`，且特定条件下，会重置 `main_job_`。

* **`OnJobSucceeded(Job* job)`:**
    *  当一个 `Job` 成功时被调用。
    *  如果还没有绑定 `Job`，则调用 `BindJob()` 进行绑定。

* **`MarkRequestComplete(Job* job)`:**
    *  标记请求完成。
    *  计算并报告备用协议的使用情况。

* **`MaybeReportBrokenAlternativeService(...)`:**
    *  检查备用连接是否失败，并根据情况向 `HttpServerProperties` 报告损坏的备用服务，以便后续避免使用。
    * **假设输入与输出:**
        * **假设输入:** `alt_service` 表示一个备用服务，`alt_job_net_error` 是备用连接的错误码 (例如 `ERR_CONNECTION_REFUSED`)， `main_job_net_error_` 为 `OK`。
        * **输出:**  如果 `alt_job_net_error` 不是 `OK`，并且 `main_job_net_error_` 是 `OK`，则会调用 `session_->http_server_properties()->MarkAlternativeServiceBroken()` 来标记该备用服务为损坏。同时会记录相应的 UMA 指标。

* **`MaybeNotifyFactoryOfCompletion()`:**
    *  当所有 `Job` 都完成或被清理后，通知 `HttpStreamFactory` 请求处理完成。
    *  在此之前会调用 `MaybeReportBrokenAlternativeService` 报告备用协议的失败情况。

* **`NotifyRequestFailed(int rv)`:**
    *  通知 `delegate_` 请求失败。

* **`RewriteUrlWithHostMappingRules(GURL& url)` 和 `DuplicateUrlWithHostMappingRules(const GURL& url)`:**
    *  根据主机映射规则重写 URL。

* **`GetAlternativeServiceInfoFor(...)` 和 `GetAlternativeServiceInfoInternal(...)`:**
    *  根据 `HttpServerProperties` 获取可用的备用服务信息。
    *  根据是否启用备用服务、备用服务是否已损坏、端口限制等条件进行筛选。
    * **假设输入与输出:**
        * **假设输入:**  一个 HTTPS 的 `http_request_info_url`，并且 `HttpServerProperties` 中存在该域名的备用服务信息，且该备用服务未被标记为损坏。
        * **输出:**  返回包含该备用服务信息的 `AlternativeServiceInfo` 对象。如果所有备用服务都被标记为损坏，并且是 QUIC，则会调用 `delegate_->OnQuicBroken()`。

* **`SelectQuicVersion(...)`:**
    *  选择支持的 QUIC 版本。

* **`ReportAlternateProtocolUsage(...)`:**
    *  记录备用协议的使用情况到 UMA 指标。

* **`IsJobOrphaned(Job* job)`:**
    *  判断一个 `Job` 是否被孤立（不再与当前请求关联）。

* **`CalculateAlternateProtocolUsage(Job* job)`:**
    *  计算备用协议的使用方式，用于统计。

* **`ReconsiderProxyAfterError(Job* job, int error)`:**
    *  在 `Job` 失败后，如果允许，触发代理回退机制。
    *  会清除客户端证书，并尝试回退到下一个代理。
    * **假设输入与输出:**
        * **假设输入:** 一个 `Job` 失败，错误码为 `ERR_PROXY_CONNECTION_FAILED`，且 `proxy_info_` 中有多个代理服务器。
        * **输出:** 如果 `job->should_reconsider_proxy()` 返回 `true` 且未设置 `LOAD_BYPASS_PROXY`，则会调用 `proxy_info_.Fallback()` 尝试使用下一个代理，并重置相关的 Job。

* **`IsQuicAllowedForHost(const std::string& host)`:**
    *  检查给定的主机是否在 QUIC 允许列表中。

* **`SwitchToHttpStreamPool()`:**
    *  将请求切换到 `HttpStreamPool` 进行处理，用于预连接或直接连接。

* **`OnPoolPreconnectsComplete(int rv)` 和 `CallOnSwitchesToHttpStreamPool(...)`:**
    *  处理切换到 `HttpStreamPool` 的完成回调。

**与 JavaScript 的关系：**

这个 C++ 代码本身不直接与 JavaScript 交互。但是，它在 Chromium 网络栈中扮演着关键角色，处理由渲染进程（其中运行 JavaScript）发起的网络请求。

* 当 JavaScript 代码发起一个 HTTP 或 HTTPS 请求（例如，使用 `fetch()` API 或 `XMLHttpRequest`），该请求会经过 Chromium 的网络栈，最终会到达这里。
* `HttpStreamFactory::JobController` 的工作是建立连接以满足这个请求。
* JavaScript 代码无法直接控制 `JobController` 的行为，但请求的属性（例如，是否允许使用备用协议）可能会影响其决策。
* `JobController` 最终建立的连接类型（例如，HTTP/1.1, HTTP/2, QUIC）会影响浏览器和服务器之间的通信方式，但这对于运行在网页中的 JavaScript 代码来说是透明的。

**用户或编程常见的使用错误：**

* **配置错误的备用服务信息：** 如果服务器配置了错误的 `Alt-Svc` 头，导致备用连接尝试失败，`JobController` 会报告这些错误，但用户或开发者无法直接修复这里的代码。错误通常需要在服务器端修复。
* **网络环境问题：**  网络不稳定或者防火墙阻止了备用协议（如 QUIC）的连接，会导致 `JobController` 尝试回退到其他连接方式。这不是代码错误，而是环境问题。
* **不正确的代理配置：** 如果用户配置了无法正常工作的代理，`ReconsiderProxyAfterError` 可能会被调用来尝试回退，但这表明用户的代理配置有问题。
* **过早释放资源：** 虽然不太可能直接发生在这个类中，但在网络栈的其他部分，如果过早释放了 `request_` 或 `delegate_` 相关的资源，可能会导致程序崩溃或未定义的行为。`DCHECK` 宏用于在开发阶段检测这些潜在的问题。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入一个 HTTPS 网址并回车，或者点击一个 HTTPS 链接。**
2. **渲染进程（Browser Process 的一部分，负责页面渲染）中的 JavaScript 代码（如果页面有）发起一个 `fetch()` 请求或者 `XMLHttpRequest`。**
3. **网络请求被传递到 Browser Process 的网络服务（Network Service）。**
4. **`URLRequest` 对象被创建，用于处理该请求。**
5. **`HttpStreamFactory` 负责创建建立 HTTP 连接的 `HttpStream` 对象。**
6. **`HttpStreamFactory::JobController` 被创建来协调连接建立过程。**
7. **`JobController` 根据配置和服务器提供的备用服务信息，创建 `main_job_`, `alternative_job_`, 和 `dns_alpn_h3_job_` 等对象来尝试建立连接。**
8. **这段代码中的方法会被调用，以启动、管理和监控这些连接尝试。**

**总结（针对第二部分代码）：**

这段代码集中处理了 `HttpStreamFactory::JobController` 中与连接管理、备用协议处理、错误回退以及与 `HttpStreamPool` 交互相关的逻辑。它负责orchestrating不同的连接尝试，并根据结果做出决策，以优化连接速度和可靠性，并报告备用协议的运行状况。

Prompt: 
```
这是目录为net/http/http_stream_factory_job_controller.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
tiveSocket() &&
                      !main_job_->HasAvailableSpdySession())))) {
    // We don't block |main_job_| when |alternative_job_| doesn't exists and
    // |dns_alpn_h3_job_| exists and an active socket is available for
    // |main_job_|. This is intended to make the fallback logic faster.
    main_job_is_blocked_ = true;
  }

  if (alternative_job_) {
    alternative_job_->Start(request_->stream_type());
  }

  if (dns_alpn_h3_job_) {
    dns_alpn_h3_job_->Start(request_->stream_type());
  }

  if (main_job_) {
    main_job_->Start(request_->stream_type());
  }
  return OK;
}

void HttpStreamFactory::JobController::ClearInappropriateJobs() {
  if (dns_alpn_h3_job_ && dns_alpn_h3_job_->HasAvailableQuicSession()) {
    // Clear |main_job_| and |alternative_job_| here not to start them when
    // there is an active session available for |dns_alpn_h3_job_|.
    main_job_.reset();
    alternative_job_.reset();
  }

  if (alternative_job_ && dns_alpn_h3_job_ &&
      (alternative_job_->HasAvailableQuicSession() ||
       (alternative_service_info_.alternative_service() ==
        GetAlternativeServiceForDnsJob(http_request_info_url_)))) {
    // Clear |dns_alpn_h3_job_|, when there is an active session available for
    // |alternative_job_| or |alternative_job_| was created for the same
    // destination.
    dns_alpn_h3_job_.reset();
  }
}

void HttpStreamFactory::JobController::BindJob(Job* job) {
  DCHECK(request_);
  DCHECK(job);
  DCHECK(job == alternative_job_.get() || job == main_job_.get() ||
         job == dns_alpn_h3_job_.get());
  DCHECK(!job_bound_);
  DCHECK(!bound_job_);

  job_bound_ = true;
  bound_job_ = job;

  request_->net_log().AddEventReferencingSource(
      NetLogEventType::HTTP_STREAM_REQUEST_BOUND_TO_JOB,
      job->net_log().source());
  job->net_log().AddEventReferencingSource(
      NetLogEventType::HTTP_STREAM_JOB_BOUND_TO_REQUEST,
      request_->net_log().source());

  OrphanUnboundJob();
}

void HttpStreamFactory::JobController::OrphanUnboundJob() {
  DCHECK(request_);
  DCHECK(bound_job_);

  if (bound_job_->job_type() == MAIN) {
    // Allow |alternative_job_| and |dns_alpn_h3_job_| to run to completion,
    // rather than resetting them to check if there is any broken alternative
    // service to report. OnOrphanedJobComplete() will clean up |this| when the
    // jobs complete.
    if (alternative_job_) {
      DCHECK(!is_websocket_);
      alternative_job_->Orphan();
    }
    if (dns_alpn_h3_job_) {
      DCHECK(!is_websocket_);
      dns_alpn_h3_job_->Orphan();
    }
    return;
  }

  if (bound_job_->job_type() == ALTERNATIVE) {
    if (!alternative_job_failed_on_default_network_ && !dns_alpn_h3_job_) {
      // |request_| is bound to the alternative job and the alternative job
      // succeeds on the default network, and there is no DNS alt job. This
      // means that the main job is no longer needed, so cancel it now. Pending
      // ConnectJobs will return established sockets to socket pools if
      // applicable.
      // https://crbug.com/757548.
      // The main job still needs to run if the alternative job succeeds on the
      // alternate network in order to figure out whether QUIC should be marked
      // as broken until the default network changes. And also the main job
      // still needs to run if the DNS alt job exists to figure out whether
      // the DNS alpn service is broken.
      DCHECK(!main_job_ || (alternative_job_net_error_ == OK));
      main_job_.reset();
    }
    // Allow |dns_alpn_h3_job_| to run to completion, rather than resetting
    // it to check if there is any broken alternative service to report.
    // OnOrphanedJobComplete() will clean up |this| when the job completes.
    if (dns_alpn_h3_job_) {
      DCHECK(!is_websocket_);
      dns_alpn_h3_job_->Orphan();
    }
  }
  if (bound_job_->job_type() == DNS_ALPN_H3) {
    if (!dns_alpn_h3_job_failed_on_default_network_ && !alternative_job_) {
      DCHECK(!main_job_ || (dns_alpn_h3_job_net_error_ == OK));
      main_job_.reset();
    }
    // Allow |alternative_job_| to run to completion, rather than resetting
    // it to check if there is any broken alternative service to report.
    // OnOrphanedJobComplete() will clean up |this| when the job completes.
    if (alternative_job_) {
      DCHECK(!is_websocket_);
      alternative_job_->Orphan();
    }
  }
}

void HttpStreamFactory::JobController::OnJobSucceeded(Job* job) {
  DCHECK(job);
  if (!bound_job_) {
    BindJob(job);
    return;
  }
}

void HttpStreamFactory::JobController::MarkRequestComplete(Job* job) {
  if (request_) {
    AlternateProtocolUsage alternate_protocol_usage =
        CalculateAlternateProtocolUsage(job);
    request_->Complete(job->negotiated_protocol(), alternate_protocol_usage);
    ReportAlternateProtocolUsage(alternate_protocol_usage,
                                 HasGoogleHost(job->origin_url()));
  }
}

void HttpStreamFactory::JobController::MaybeReportBrokenAlternativeService(
    const AlternativeService& alt_service,
    int alt_job_net_error,
    bool alt_job_failed_on_default_network,
    const std::string& histogram_name_for_failure) {
  // If alternative job succeeds on the default network, no brokenness to
  // report.
  if (alt_job_net_error == OK && !alt_job_failed_on_default_network) {
    return;
  }

  // No brokenness to report if the main job fails.
  if (main_job_net_error_ != OK) {
    return;
  }

  // No need to record DNS_NO_MATCHING_SUPPORTED_ALPN error.
  if (alt_job_net_error == ERR_DNS_NO_MATCHING_SUPPORTED_ALPN) {
    return;
  }

  if (alt_job_failed_on_default_network && alt_job_net_error == OK) {
    // Alternative job failed on the default network but succeeds on the
    // non-default network, mark alternative service broken until the default
    // network changes.
    session_->http_server_properties()
        ->MarkAlternativeServiceBrokenUntilDefaultNetworkChanges(
            alt_service, request_info_.network_anonymization_key);
    return;
  }

  if (alt_job_net_error == ERR_NETWORK_CHANGED ||
      alt_job_net_error == ERR_INTERNET_DISCONNECTED ||
      (alt_job_net_error == ERR_NAME_NOT_RESOLVED &&
       http_request_info_url_.host() == alt_service.host)) {
    // No need to mark alternative service as broken.
    return;
  }

  // Report brokenness if alternative job failed.
  base::UmaHistogramSparse(histogram_name_for_failure, -alt_job_net_error);

  HistogramBrokenAlternateProtocolLocation(
      BROKEN_ALTERNATE_PROTOCOL_LOCATION_HTTP_STREAM_FACTORY_JOB_ALT);
  session_->http_server_properties()->MarkAlternativeServiceBroken(
      alt_service, request_info_.network_anonymization_key);
}

void HttpStreamFactory::JobController::MaybeNotifyFactoryOfCompletion() {
  if (switched_to_http_stream_pool_) {
    factory_->OnJobControllerComplete(this);
    return;
  }

  if (main_job_ || alternative_job_ || dns_alpn_h3_job_) {
    return;
  }

  // All jobs are gone.
  // Report brokenness for the alternate jobs if apply.
  MaybeReportBrokenAlternativeService(
      alternative_service_info_.alternative_service(),
      alternative_job_net_error_, alternative_job_failed_on_default_network_,
      "Net.AlternateServiceFailed");
  // Report for the DNS alt job if apply.
  MaybeReportBrokenAlternativeService(
      GetAlternativeServiceForDnsJob(http_request_info_url_),
      dns_alpn_h3_job_net_error_, dns_alpn_h3_job_failed_on_default_network_,
      "Net.AlternateServiceForDnsAlpnH3Failed");

  // Reset error status for Jobs after reporting brokenness to avoid redundant
  // reporting.
  ResetErrorStatusForJobs();

  if (request_) {
    return;
  }
  DCHECK(!bound_job_);
  factory_->OnJobControllerComplete(this);
}

void HttpStreamFactory::JobController::NotifyRequestFailed(int rv) {
  if (!request_) {
    return;
  }
  delegate_->OnStreamFailed(rv, NetErrorDetails(), ProxyInfo(),
                            ResolveErrorInfo());
}

void HttpStreamFactory::JobController::RewriteUrlWithHostMappingRules(
    GURL& url) const {
  session_->params().host_mapping_rules.RewriteUrl(url);
}

GURL HttpStreamFactory::JobController::DuplicateUrlWithHostMappingRules(
    const GURL& url) const {
  GURL copy = url;
  RewriteUrlWithHostMappingRules(copy);
  return copy;
}

AlternativeServiceInfo
HttpStreamFactory::JobController::GetAlternativeServiceInfoFor(
    const GURL& http_request_info_url,
    const StreamRequestInfo& request_info,
    HttpStreamRequest::Delegate* delegate,
    HttpStreamRequest::StreamType stream_type) {
  if (!enable_alternative_services_) {
    return AlternativeServiceInfo();
  }

  AlternativeServiceInfo alternative_service_info =
      GetAlternativeServiceInfoInternal(http_request_info_url, request_info,
                                        delegate, stream_type);
  AlternativeServiceType type;
  if (alternative_service_info.protocol() == kProtoUnknown) {
    type = NO_ALTERNATIVE_SERVICE;
  } else if (alternative_service_info.protocol() == kProtoQUIC) {
    if (http_request_info_url.host_piece() ==
        alternative_service_info.alternative_service().host) {
      type = QUIC_SAME_DESTINATION;
    } else {
      type = QUIC_DIFFERENT_DESTINATION;
    }
  } else {
    if (http_request_info_url.host_piece() ==
        alternative_service_info.alternative_service().host) {
      type = NOT_QUIC_SAME_DESTINATION;
    } else {
      type = NOT_QUIC_DIFFERENT_DESTINATION;
    }
  }
  UMA_HISTOGRAM_ENUMERATION("Net.AlternativeServiceTypeForRequest", type,
                            MAX_ALTERNATIVE_SERVICE_TYPE);
  return alternative_service_info;
}

AlternativeServiceInfo
HttpStreamFactory::JobController::GetAlternativeServiceInfoInternal(
    const GURL& http_request_info_url,
    const StreamRequestInfo& request_info,
    HttpStreamRequest::Delegate* delegate,
    HttpStreamRequest::StreamType stream_type) {
  GURL original_url = http_request_info_url;

  if (!original_url.SchemeIs(url::kHttpsScheme)) {
    return AlternativeServiceInfo();
  }

  HttpServerProperties& http_server_properties =
      *session_->http_server_properties();
  const AlternativeServiceInfoVector alternative_service_info_vector =
      http_server_properties.GetAlternativeServiceInfos(
          url::SchemeHostPort(original_url),
          request_info.network_anonymization_key);
  if (alternative_service_info_vector.empty()) {
    return AlternativeServiceInfo();
  }

  bool quic_advertised = false;
  bool quic_all_broken = true;

  // First alternative service that is not marked as broken.
  AlternativeServiceInfo first_alternative_service_info;

  bool is_any_broken = false;
  for (const AlternativeServiceInfo& alternative_service_info :
       alternative_service_info_vector) {
    DCHECK(IsAlternateProtocolValid(alternative_service_info.protocol()));
    if (!quic_advertised && alternative_service_info.protocol() == kProtoQUIC) {
      quic_advertised = true;
    }
    const bool is_broken = http_server_properties.IsAlternativeServiceBroken(
        alternative_service_info.alternative_service(),
        request_info.network_anonymization_key);
    net_log_.AddEvent(
        NetLogEventType::HTTP_STREAM_JOB_CONTROLLER_ALT_SVC_FOUND, [&] {
          return NetLogAltSvcParams(&alternative_service_info, is_broken);
        });
    if (is_broken) {
      if (!is_any_broken) {
        // Only log the broken alternative service once per request.
        is_any_broken = true;
        HistogramAlternateProtocolUsage(ALTERNATE_PROTOCOL_USAGE_BROKEN,
                                        HasGoogleHost(original_url));
      }
      continue;
    }

    // Some shared unix systems may have user home directories (like
    // http://foo.com/~mike) which allow users to emit headers.  This is a bad
    // idea already, but with Alternate-Protocol, it provides the ability for a
    // single user on a multi-user system to hijack the alternate protocol.
    // These systems also enforce ports <1024 as restricted ports.  So don't
    // allow protocol upgrades to user-controllable ports.
    const int kUnrestrictedPort = 1024;
    if (!session_->params().enable_user_alternate_protocol_ports &&
        (alternative_service_info.alternative_service().port >=
             kUnrestrictedPort &&
         original_url.EffectiveIntPort() < kUnrestrictedPort)) {
      continue;
    }

    if (alternative_service_info.protocol() == kProtoHTTP2) {
      if (!session_->params().enable_http2_alternative_service) {
        continue;
      }

      // Cache this entry if we don't have a non-broken Alt-Svc yet.
      if (first_alternative_service_info.protocol() == kProtoUnknown) {
        first_alternative_service_info = alternative_service_info;
      }
      continue;
    }

    DCHECK_EQ(kProtoQUIC, alternative_service_info.protocol());
    quic_all_broken = false;
    if (!session_->IsQuicEnabled()) {
      continue;
    }

    if (!original_url.SchemeIs(url::kHttpsScheme)) {
      continue;
    }

    // If there is no QUIC version in the advertised versions that is
    // supported, ignore this entry.
    if (SelectQuicVersion(alternative_service_info.advertised_versions()) ==
        quic::ParsedQuicVersion::Unsupported()) {
      continue;
    }

    // Check whether there is an existing QUIC session to use for this origin.
    GURL mapped_origin = original_url;
    RewriteUrlWithHostMappingRules(mapped_origin);
    QuicSessionKey session_key(
        HostPortPair::FromURL(mapped_origin), request_info.privacy_mode,
        proxy_info_.proxy_chain(), SessionUsage::kDestination,
        request_info.socket_tag, request_info.network_anonymization_key,
        request_info.secure_dns_policy, /*require_dns_https_alpn=*/false);

    GURL destination = CreateAltSvcUrl(
        original_url, alternative_service_info.host_port_pair());
    if (session_key.host() != destination.host_piece() &&
        !session_->context().quic_context->params()->allow_remote_alt_svc) {
      continue;
    }
    RewriteUrlWithHostMappingRules(destination);

    if (session_->quic_session_pool()->CanUseExistingSession(
            session_key, url::SchemeHostPort(destination))) {
      return alternative_service_info;
    }

    if (!IsQuicAllowedForHost(destination.host())) {
      continue;
    }

    // Cache this entry if we don't have a non-broken Alt-Svc yet.
    if (first_alternative_service_info.protocol() == kProtoUnknown) {
      first_alternative_service_info = alternative_service_info;
    }
  }

  // Ask delegate to mark QUIC as broken for the origin.
  if (quic_advertised && quic_all_broken && delegate != nullptr) {
    delegate->OnQuicBroken();
  }

  return first_alternative_service_info;
}

quic::ParsedQuicVersion HttpStreamFactory::JobController::SelectQuicVersion(
    const quic::ParsedQuicVersionVector& advertised_versions) {
  return session_->context().quic_context->SelectQuicVersion(
      advertised_versions);
}

void HttpStreamFactory::JobController::ReportAlternateProtocolUsage(
    AlternateProtocolUsage alternate_protocol_usage,
    bool is_google_host) const {
  DCHECK_LT(alternate_protocol_usage, ALTERNATE_PROTOCOL_USAGE_MAX);
  HistogramAlternateProtocolUsage(alternate_protocol_usage, is_google_host);
}

bool HttpStreamFactory::JobController::IsJobOrphaned(Job* job) const {
  return !request_ || (job_bound_ && bound_job_ != job);
}

AlternateProtocolUsage
HttpStreamFactory::JobController::CalculateAlternateProtocolUsage(
    Job* job) const {
  if ((main_job_ && alternative_job_) || dns_alpn_h3_job_) {
    if (job == main_job_.get()) {
      return ALTERNATE_PROTOCOL_USAGE_MAIN_JOB_WON_RACE;
    }
    if (job == alternative_job_.get()) {
      if (job->using_existing_quic_session()) {
        return ALTERNATE_PROTOCOL_USAGE_NO_RACE;
      }
      return ALTERNATE_PROTOCOL_USAGE_WON_RACE;
    }
    if (job == dns_alpn_h3_job_.get()) {
      if (job->using_existing_quic_session()) {
        return ALTERNATE_PROTOCOL_USAGE_DNS_ALPN_H3_JOB_WON_WITHOUT_RACE;
      }
      return ALTERNATE_PROTOCOL_USAGE_DNS_ALPN_H3_JOB_WON_RACE;
    }
  }
  // TODO(crbug.com/40232167): Implement better logic to support uncovered
  // cases.
  return ALTERNATE_PROTOCOL_USAGE_UNSPECIFIED_REASON;
}

int HttpStreamFactory::JobController::ReconsiderProxyAfterError(Job* job,
                                                                int error) {
  // ReconsiderProxyAfterError() should only be called when the last job fails.
  DCHECK_EQ(1, GetJobCount());
  DCHECK(!proxy_resolve_request_);

  if (!job->should_reconsider_proxy()) {
    return error;
  }

  if (request_info_.load_flags & LOAD_BYPASS_PROXY) {
    return error;
  }

  // Clear client certificates for all proxies in the chain.
  // TODO(crbug.com/40284947): client certificates for multi-proxy
  // chains are not yet supported, and this is only tested with single-proxy
  // chains.
  for (auto& proxy_server : proxy_info_.proxy_chain().proxy_servers()) {
    if (proxy_server.is_secure_http_like()) {
      session_->ssl_client_context()->ClearClientCertificate(
          proxy_server.host_port_pair());
    }
  }

  if (!proxy_info_.Fallback(error, net_log_)) {
    // If there is no more proxy to fallback to, fail the transaction
    // with the last connection error we got.
    return error;
  }

  // Abandon all Jobs and start over.
  job_bound_ = false;
  bound_job_ = nullptr;
  dns_alpn_h3_job_.reset();
  alternative_job_.reset();
  main_job_.reset();
  ResetErrorStatusForJobs();
  // Also resets states that related to the old main job. In particular,
  // cancels |resume_main_job_callback_| so there won't be any delayed
  // ResumeMainJob() left in the task queue.
  resume_main_job_callback_.Cancel();
  main_job_is_resumed_ = false;
  main_job_is_blocked_ = false;

  next_state_ = STATE_RESOLVE_PROXY_COMPLETE;
  return OK;
}

bool HttpStreamFactory::JobController::IsQuicAllowedForHost(
    const std::string& host) {
  const base::flat_set<std::string>& host_allowlist =
      session_->params().quic_host_allowlist;
  if (host_allowlist.empty()) {
    return true;
  }

  std::string lowered_host = base::ToLowerASCII(host);
  return base::Contains(host_allowlist, lowered_host);
}

void HttpStreamFactory::JobController::SwitchToHttpStreamPool() {
  CHECK(request_info_.socket_tag == SocketTag());
  CHECK_EQ(stream_type_, HttpStreamRequest::HTTP_STREAM);

  switched_to_http_stream_pool_ = true;

  bool disable_cert_network_fetches =
      !!(request_info_.load_flags & LOAD_DISABLE_CERT_NETWORK_FETCHES);
  HttpStreamPoolRequestInfo pool_request_info(
      url::SchemeHostPort(origin_url_), request_info_.privacy_mode,
      request_info_.socket_tag, request_info_.network_anonymization_key,
      request_info_.secure_dns_policy, disable_cert_network_fetches,
      alternative_service_info_, request_info_.is_http1_allowed,
      request_info_.load_flags, proxy_info_);
  if (is_preconnect_) {
    int rv = session_->http_stream_pool()->Preconnect(
        std::move(pool_request_info), num_streams_,
        base::BindOnce(&JobController::OnPoolPreconnectsComplete,
                       ptr_factory_.GetWeakPtr()));
    if (rv != ERR_IO_PENDING) {
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(&JobController::OnPoolPreconnectsComplete,
                                    ptr_factory_.GetWeakPtr(), rv));
    }
    return;
  }

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&JobController::CallOnSwitchesToHttpStreamPool,
                     ptr_factory_.GetWeakPtr(), std::move(pool_request_info)));
}

void HttpStreamFactory::JobController::OnPoolPreconnectsComplete(int rv) {
  CHECK(switched_to_http_stream_pool_);
  factory_->OnPreconnectsCompleteInternal();
  MaybeNotifyFactoryOfCompletion();
}

void HttpStreamFactory::JobController::CallOnSwitchesToHttpStreamPool(
    HttpStreamPoolRequestInfo request_info) {
  CHECK(request_);
  CHECK(delegate_);

  // `request_` and `delegate_` will be reset later.

  delegate_->OnSwitchesToHttpStreamPool(std::move(request_info));
}

}  // namespace net

"""


```