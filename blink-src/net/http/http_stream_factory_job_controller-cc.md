Response:
The user wants a summary of the functionality of the provided C++ code file, `http_stream_factory_job_controller.cc`.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:**  The file name itself gives a strong hint: `HttpStreamFactory::JobController`. This suggests a class responsible for managing the lifecycle of HTTP stream "jobs". "Controller" implies orchestration and management of these jobs.

2. **Scan for Key Classes and Methods:**  Look for prominent class names and methods within the code.
    * `HttpStreamFactory::JobController`: The central class.
    * `Job`:  The type of work being managed. The code has `main_job_`, `alternative_job_`, and `dns_alpn_h3_job_`, indicating different types of jobs.
    * `HttpStreamRequest`: Represents an incoming request for an HTTP stream.
    * `Delegate`:  An interface for communication with the requester of the stream.
    * `HttpNetworkSession`: The overall HTTP session context.
    * `ProxyResolutionService`: Deals with finding the appropriate proxy server.
    * `Start`, `Preconnect`: Methods for initiating the stream creation process.
    * `OnStreamReady`, `OnStreamFailed`, etc.: Callback methods for handling job completion.

3. **Infer High-Level Functionality:** Based on the identified classes and methods,  we can infer that `JobController` is responsible for:
    * Taking an `HttpStreamRequest`.
    * Determining how to fulfill that request (potentially involving proxies and alternative protocols like QUIC/HTTP/3).
    * Creating and managing `Job` objects to handle the actual network communication.
    * Coordinating between different potential connection attempts (main job vs. alternative job).
    * Notifying the `Delegate` about the success or failure of the request.

4. **Analyze the Different Job Types:** The presence of `main_job_`, `alternative_job_`, and `dns_alpn_h3_job_` suggests a strategy for optimizing connection establishment:
    * `main_job_`: The primary attempt to establish a connection.
    * `alternative_job_`: Attempts to use alternative protocols or server locations (Alt-Svc).
    * `dns_alpn_h3_job_`:  Specifically for trying HTTP/3 based on DNS records.

5. **Consider the Role of Proxy Resolution:** The code clearly interacts with a `ProxyResolutionService`. This indicates that `JobController` handles determining the appropriate proxy server to use before attempting to connect.

6. **Look for Specific Logic and Interactions:**
    * **Alternative Services:** The code checks for and utilizes alternative services.
    * **QUIC/HTTP/3:** There are specific paths for QUIC and HTTP/3.
    * **Preconnect:** Support for pre-establishing connections.
    * **Happy Eyeballs:** Mention of `features::kHappyEyeballsV3` indicates handling of parallel connection attempts.
    * **Error Handling and Retries:** The presence of `OnStreamFailed` and logic for reconsidering proxies after errors.

7. **Formulate the Summary:**  Combine the inferences from the previous steps into a concise summary. Focus on the key responsibilities and the overall flow of the process.

8. **Address the "Part 1" Request:** Since this is part 1 of a multi-part request, the summary should primarily focus on the overall role and core responsibilities of the class, without delving into the specifics of the `RunLoop` and state machine which are likely to be more detailed in the subsequent parts. Emphasize the initiation and high-level management of jobs.
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_factory_job_controller.h"

#include <string>
#include <utility>

#include "base/containers/contains.h"
#include "base/functional/bind.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/task/single_thread_task_runner.h"
#include "base/values.h"
#include "net/base/features.h"
#include "net/base/host_mapping_rules.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/privacy_mode.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_string_util.h"
#include "net/base/session_usage.h"
#include "net/base/url_util.h"
#include "net/http/alternative_service.h"
#include "net/http/bidirectional_stream_impl.h"
#include "net/http/http_stream_key.h"
#include "net/http/http_stream_pool.h"
#include "net/http/http_stream_pool_request_info.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"
#include "net/proxy_resolution/proxy_info.h"
#include "net/proxy_resolution/proxy_resolution_request.h"
#include "net/proxy_resolution/proxy_resolution_service.h"
#include "net/quic/quic_session_key.h"
#include "net/socket/next_proto.h"
#include "net/spdy/spdy_session.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_versions.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

namespace net {

namespace {

// Returns parameters associated with the proxy resolution.
base::Value::Dict NetLogHttpStreamJobProxyChainResolved(
    const ProxyChain& proxy_chain) {
  base::Value::Dict dict;

  dict.Set("proxy_chain",
           proxy_chain.IsValid() ? proxy_chain.ToDebugString() : std::string());
  return dict;
}

GURL CreateAltSvcUrl(const GURL& origin_url,
                     const HostPortPair& alternative_destination) {
  DCHECK(origin_url.is_valid());
  DCHECK(origin_url.IsStandard());

  GURL::Replacements replacements;
  std::string port_str = base::NumberToString(alternative_destination.port());
  replacements.SetPortStr(port_str);
  replacements.SetHostStr(alternative_destination.host());

  return origin_url.ReplaceComponents(replacements);
}

void ConvertWsToHttp(url::SchemeHostPort& input) {
  if (base::EqualsCaseInsensitiveASCII(input.scheme(), url::kHttpScheme) ||
      base::EqualsCaseInsensitiveASCII(input.scheme(), url::kHttpsScheme)) {
    return;
  }

  if (base::EqualsCaseInsensitiveASCII(input.scheme(), url::kWsScheme)) {
    input = url::SchemeHostPort(url::kHttpScheme, input.host(), input.port());
    return;
  }

  DCHECK(base::EqualsCaseInsensitiveASCII(input.scheme(), url::kWssScheme));
  input = url::SchemeHostPort(url::kHttpsScheme, input.host(), input.port());
}

void HistogramProxyUsed(const ProxyInfo& proxy_info, bool success) {
  const ProxyServer::Scheme max_scheme = ProxyServer::Scheme::SCHEME_QUIC;
  ProxyServer::Scheme proxy_scheme = ProxyServer::Scheme::SCHEME_INVALID;
  if (!proxy_info.is_empty() && !proxy_info.is_direct()) {
    if (proxy_info.proxy_chain().is_multi_proxy()) {
      // TODO(crbug.com/40284947): Update this histogram to have a new
      // bucket for multi-chain proxies. Until then, don't influence the
      // existing metric counts which have historically been only for single-hop
      // proxies.
      return;
    }
    proxy_scheme = proxy_info.proxy_chain().is_direct()
                       ? static_cast<ProxyServer::Scheme>(1)
                       : proxy_info.proxy_chain().First().scheme();
  }
  if (success) {
    UMA_HISTOGRAM_ENUMERATION("Net.HttpJob.ProxyTypeSuccess", proxy_scheme,
                              max_scheme);
  } else {
    UMA_HISTOGRAM_ENUMERATION("Net.HttpJob.ProxyTypeFailed", proxy_scheme,
                              max_scheme);
  }
}

// Generate a AlternativeService for DNS alt job. Note: Chrome does not yet
// support different port DNS alpn.
AlternativeService GetAlternativeServiceForDnsJob(const GURL& url) {
  return AlternativeService(kProtoQUIC, HostPortPair::FromURL(url));
}

base::Value::Dict NetLogAltSvcParams(const AlternativeServiceInfo* alt_svc_info,
                                     bool is_broken) {
  base::Value::Dict dict;
  dict.Set("alt_svc", alt_svc_info->ToString());
  dict.Set("is_broken", is_broken);
  return dict;
}

}  // namespace

// The maximum time to wait for the alternate job to complete before resuming
// the main job.
const int kMaxDelayTimeForMainJobSecs = 3;

HttpStreamFactory::JobController::JobController(
    HttpStreamFactory* factory,
    HttpStreamRequest::Delegate* delegate,
    HttpNetworkSession* session,
    JobFactory* job_factory,
    const HttpRequestInfo& http_request_info,
    bool is_preconnect,
    bool is_websocket,
    bool enable_ip_based_pooling,
    bool enable_alternative_services,
    bool delay_main_job_with_available_spdy_session,
    const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs)
    : factory_(factory),
      session_(session),
      job_factory_(job_factory),
      delegate_(delegate),
      is_preconnect_(is_preconnect),
      is_websocket_(is_websocket),
      enable_ip_based_pooling_(enable_ip_based_pooling),
      enable_alternative_services_(enable_alternative_services),
      delay_main_job_with_available_spdy_session_(
          delay_main_job_with_available_spdy_session),
      http_request_info_url_(http_request_info.url),
      origin_url_(DuplicateUrlWithHostMappingRules(http_request_info.url)),
      request_info_(http_request_info),
      allowed_bad_certs_(allowed_bad_certs),
      net_log_(NetLogWithSource::Make(
          session->net_log(),
          NetLogSourceType::HTTP_STREAM_JOB_CONTROLLER)) {
  DCHECK(factory_);
  DCHECK(session_);
  DCHECK(job_factory_);
  DCHECK(base::EqualsCaseInsensitiveASCII(origin_url_.scheme_piece(),
                                          url::kHttpScheme) ||
         base::EqualsCaseInsensitiveASCII(origin_url_.scheme_piece(),
                                          url::kHttpsScheme) ||
         base::EqualsCaseInsensitiveASCII(origin_url_.scheme_piece(),
                                          url::kWsScheme) ||
         base::EqualsCaseInsensitiveASCII(origin_url_.scheme_piece(),
                                          url::kWssScheme));

  net_log_.BeginEvent(NetLogEventType::HTTP_STREAM_JOB_CONTROLLER, [&] {
    base::Value::Dict dict;
    dict.Set("url", http_request_info.url.possibly_invalid_spec());
    if (origin_url_ != http_request_info.url) {
      dict.Set("url_after_host_mapping", origin_url_.possibly_invalid_spec());
    }
    dict.Set("is_preconnect", is_preconnect_);
    dict.Set("privacy_mode",
             PrivacyModeToDebugString(request_info_.privacy_mode));
    base::Value::List allowed_bad_certs_list;
    for (const auto& cert_and_status : allowed_bad_certs_) {
      allowed_bad_certs_list.Append(
          cert_and_status.cert->subject().GetDisplayName());
    }
    dict.Set("allowed_bad_certs", std::move(allowed_bad_certs_list));
    return dict;
  });
}

HttpStreamFactory::JobController::~JobController() {
  bound_job_ = nullptr;
  main_job_.reset();
  alternative_job_.reset();
  dns_alpn_h3_job_.reset();
  if (proxy_resolve_request_) {
    DCHECK_EQ(STATE_RESOLVE_PROXY_COMPLETE, next_state_);
    proxy_resolve_request_.reset();
  }
  net_log_.EndEvent(NetLogEventType::HTTP_STREAM_JOB_CONTROLLER);
}

std::unique_ptr<HttpStreamRequest> HttpStreamFactory::JobController::Start(
    HttpStreamRequest::Delegate* delegate,
    WebSocketHandshakeStreamBase::CreateHelper*
        websocket_handshake_stream_create_helper,
    const NetLogWithSource& source_net_log,
    HttpStreamRequest::StreamType stream_type,
    RequestPriority priority) {
  DCHECK(!request_);

  stream_type_ = stream_type;
  priority_ = priority;

  auto request = std::make_unique<HttpStreamRequest>(
      this, websocket_handshake_stream_create_helper, source_net_log,
      stream_type);
  // Keep a raw pointer but release ownership of HttpStreamRequest instance.
  request_ = request.get();

  // Associates |net_log_| with |source_net_log|.
  source_net_log.AddEventReferencingSource(
      NetLogEventType::HTTP_STREAM_JOB_CONTROLLER_BOUND, net_log_.source());
  net_log_.AddEventReferencingSource(
      NetLogEventType::HTTP_STREAM_JOB_CONTROLLER_BOUND,
      source_net_log.source());

  RunLoop(OK);

  return request;
}

void HttpStreamFactory::JobController::Preconnect(int num_streams) {
  DCHECK(!main_job_);
  DCHECK(!alternative_job_);
  DCHECK(is_preconnect_);

  stream_type_ = HttpStreamRequest::HTTP_STREAM;
  num_streams_ = num_streams;

  RunLoop(OK);
}

LoadState HttpStreamFactory::JobController::GetLoadState() const {
  DCHECK(request_);
  if (next_state_ == STATE_RESOLVE_PROXY_COMPLETE) {
    return proxy_resolve_request_->GetLoadState();
  }
  if (bound_job_) {
    return bound_job_->GetLoadState();
  }
  if (main_job_) {
    return main_job_->GetLoadState();
  }
  if (alternative_job_) {
    return alternative_job_->GetLoadState();
  }
  if (dns_alpn_h3_job_) {
    return dns_alpn_h3_job_->GetLoadState();
  }

  // When proxy resolution fails, there is no job created and
  // NotifyRequestFailed() is executed one message loop iteration later.
  return LOAD_STATE_IDLE;
}

void HttpStreamFactory::JobController::OnRequestComplete() {
  DCHECK(request_);
  request_ = nullptr;
  // This is called when the delegate is destroying its HttpStreamRequest, so
  // it's no longer safe to call into it after this point.
  delegate_ = nullptr;

  if (!job_bound_) {
    alternative_job_.reset();
    main_job_.reset();
    dns_alpn_h3_job_.reset();
  } else {
    if (bound_job_->job_type() == MAIN) {
      bound_job_ = nullptr;
      main_job_.reset();
    } else if (bound_job_->job_type() == ALTERNATIVE) {
      bound_job_ = nullptr;
      alternative_job_.reset();
    } else {
      DCHECK(bound_job_->job_type() == DNS_ALPN_H3);
      bound_job_ = nullptr;
      dns_alpn_h3_job_.reset();
    }
  }
  MaybeNotifyFactoryOfCompletion();
}

int HttpStreamFactory::JobController::RestartTunnelWithProxyAuth() {
  DCHECK(bound_job_);
  return bound_job_->RestartTunnelWithProxyAuth();
}

void HttpStreamFactory::JobController::SetPriority(RequestPriority priority) {
  if (main_job_) {
    main_job_->SetPriority(priority);
  }
  if (alternative_job_) {
    alternative_job_->SetPriority(priority);
  }
  if (dns_alpn_h3_job_) {
    dns_alpn_h3_job_->SetPriority(priority);
  }
  if (preconnect_backup_job_) {
    preconnect_backup_job_->SetPriority(priority);
  }
}

void HttpStreamFactory::JobController::OnStreamReady(Job* job) {
  DCHECK(job);

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated HttpStreamRequest, |job| has been
    // orphaned.
    OnOrphanedJobComplete(job);
    return;
  }
  std::unique_ptr<HttpStream> stream = job->ReleaseStream();
  DCHECK(stream);

  MarkRequestComplete(job);

  if (!request_) {
    return;
  }
  DCHECK(!is_websocket_);
  DCHECK_EQ(HttpStreamRequest::HTTP_STREAM, request_->stream_type());
  OnJobSucceeded(job);

  // TODO(bnc): Remove when https://crbug.com/461981 is fixed.
  CHECK(request_);

  DCHECK(request_->completed());

  HistogramProxyUsed(job->proxy_info(), /*success=*/true);
  delegate_->OnStreamReady(job->proxy_info(), std::move(stream));
}

void HttpStreamFactory::JobController::OnBidirectionalStreamImplReady(
    Job* job,
    const ProxyInfo& used_proxy_info) {
  DCHECK(job);

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated HttpStreamRequest, |job| has been
    // orphaned.
    OnOrphanedJobComplete(job);
    return;
  }

  MarkRequestComplete(job);

  if (!request_) {
    return;
  }
  std::unique_ptr<BidirectionalStreamImpl> stream =
      job->ReleaseBidirectionalStream();
  DCHECK(stream);
  DCHECK(!is_websocket_);
  DCHECK_EQ(HttpStreamRequest::BIDIRECTIONAL_STREAM, request_->stream_type());

  OnJobSucceeded(job);
  DCHECK(request_->completed());
  delegate_->OnBidirectionalStreamImplReady(used_proxy_info, std::move(stream));
}

void HttpStreamFactory::JobController::OnWebSocketHandshakeStreamReady(
    Job* job,
    const ProxyInfo& used_proxy_info,
    std::unique_ptr<WebSocketHandshakeStreamBase> stream) {
  DCHECK(job);
  MarkRequestComplete(job);

  if (!request_) {
    return;
  }
  DCHECK(is_websocket_);
  DCHECK_EQ(HttpStreamRequest::HTTP_STREAM, request_->stream_type());
  DCHECK(stream);

  OnJobSucceeded(job);
  DCHECK(request_->completed());
  delegate_->OnWebSocketHandshakeStreamReady(used_proxy_info,
                                             std::move(stream));
}

void HttpStreamFactory::JobController::OnQuicHostResolution(
    const url::SchemeHostPort& destination,
    base::TimeTicks dns_resolution_start_time,
    base::TimeTicks dns_resolution_end_time) {
  if (!request_) {
    return;
  }
  if (destination != url::SchemeHostPort(origin_url_)) {
    // Ignores different destination alternative job's DNS resolution time.
    return;
  }
  // QUIC jobs (ALTERNATIVE, DNS_ALPN_H3) are started before the non-QUIC (MAIN)
  // job. So we set the DNS resolution overrides to use the DNS timing of the
  // QUIC jobs.
  request_->SetDnsResolutionTimeOverrides(dns_resolution_start_time,
                                          dns_resolution_end_time);
}

void HttpStreamFactory::JobController::OnStreamFailed(Job* job, int status) {
  DCHECK_NE(OK, status);
  if (job->job_type() == MAIN) {
    DCHECK_EQ(main_job_.get(), job);
    main_job_net_error_ = status;
  } else if (job->job_type() == ALTERNATIVE) {
    DCHECK_EQ(alternative_job_.get(), job);
    DCHECK_NE(kProtoUnknown, alternative_service_info_.protocol());
    alternative_job_net_error_ = status;
  } else {
    DCHECK_EQ(job->job_type(), DNS_ALPN_H3);
    DCHECK_EQ(dns_alpn_h3_job_.get(), job);
    dns_alpn_h3_job_net_error_ = status;
  }

  MaybeResumeMainJob(job, base::TimeDelta());

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated HttpStreamRequest, |job| has been
    // orphaned.
    OnOrphanedJobComplete(job);
    return;
  }

  if (!request_) {
    return;
  }
  DCHECK_NE(OK, status);
  DCHECK(job);

  if (!bound_job_) {
    if (GetJobCount() >= 2) {
      // Hey, we've got other jobs! Maybe one of them will succeed, let's just
      // ignore this failure.
      if (job->job_type() == MAIN) {
        DCHECK_EQ(main_job_.get(), job);
        main_job_.reset();
      } else if (job->job_type() == ALTERNATIVE) {
        DCHECK_EQ(alternative_job_.get(), job);
        alternative_job_.reset();
      } else {
        DCHECK_EQ(job->job_type(), DNS_ALPN_H3);
        DCHECK_EQ(dns_alpn_h3_job_.get(), job);
        dns_alpn_h3_job_.reset();
      }
      return;
    } else {
      BindJob(job);
    }
  }

  status = ReconsiderProxyAfterError(job, status);
  if (next_state_ == STATE_RESOLVE_PROXY_COMPLETE) {
    if (status == ERR_IO_PENDING) {
      return;
    }
    DCHECK_EQ(OK, status);
    RunLoop(status);
    return;
  }

  HistogramProxyUsed(job->proxy_info(), /*success=*/false);
  delegate_->OnStreamFailed(status, *job->net_error_details(),
                            job->proxy_info(), job->resolve_error_info());
}

void HttpStreamFactory::JobController::OnFailedOnDefaultNetwork(Job* job) {
  if (job->job_type() == ALTERNATIVE) {
    DCHECK_EQ(alternative_job_.get(), job);
    alternative_job_failed_on_default_network_ = true;
  } else {
    DCHECK_EQ(job->job_type(), DNS_ALPN_H3);
    DCHECK_EQ(dns_alpn_h3_job_.get(), job);
    dns_alpn_h3_job_failed_on_default_network_ = true;
  }
}

void HttpStreamFactory::JobController::OnCertificateError(
    Job* job,
    int status,
    const SSLInfo& ssl_info) {
  MaybeResumeMainJob(job, base::TimeDelta());

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated HttpStreamRequest, |job| has been
    // orphaned.
    OnOrphanedJobComplete(job);
    return;
  }

  if (!request_) {
    return;
  }
  DCHECK_NE(OK, status);
  if (!bound_job_) {
    BindJob(job);
  }

  delegate_->OnCertificateError(status, ssl_info);
}

void HttpStreamFactory::JobController::OnNeedsClientAuth(
    Job* job,
    SSLCertRequestInfo* cert_info) {
  MaybeResumeMainJob(job, base::TimeDelta());

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated HttpStreamRequest, |job| has been
    // orphaned.
    OnOrphanedJobComplete(job);
    return;
  }
  if (!request_) {
    return;
  }
  if (!bound_job_) {
    BindJob(job);
  }

  delegate_->OnNeedsClientAuth(cert_info);
}

void HttpStreamFactory::JobController::OnNeedsProxyAuth(
    Job* job,
    const HttpResponseInfo& proxy_response,
    const ProxyInfo& used_proxy_info,
    HttpAuthController* auth_controller) {
  MaybeResumeMainJob(job, base::TimeDelta());

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated HttpStreamRequest, |job| has been
    // orphaned.
    OnOrphanedJobComplete(job);
    return;
  }

  if (!request_) {
    return;
  }
  if (!bound_job_) {
    BindJob(job);
  }
  delegate_->OnNeedsProxyAuth(proxy_response, used_proxy_info, auth_controller);
}

void HttpStreamFactory::JobController::OnPreconnectsComplete(Job* job,
                                                             int result) {
  // Preconnects only run as `main_job_`, never `alternative_job_` or
  // `dns_alpn_h3_job_`.
  DCHECK_EQ(main_job_.get(), job);

  // If the job failed because there were no matching HTTPS records in DNS, run
  // the backup job. A TCP-based protocol may work instead.
  if (result == ERR_DNS_NO_MATCHING_SUPPORTED_ALPN && preconnect_backup_job_) {
    DCHECK_EQ(job->job_type(), PRECONNECT_DNS_ALPN_H3);
    main_job_ = std::move(preconnect_backup_job_);
    main_job_->Preconnect(num_streams_);
    return;
  }

  main_job_.reset();
  preconnect_backup_job_.reset();
  ResetErrorStatusForJobs();
  factory_->OnPreconnectsCompleteInternal();
  MaybeNotifyFactoryOfCompletion();
}

void HttpStreamFactory::JobController::OnOrphanedJobComplete(const Job* job) {
  if (job->job_type() == MAIN) {
    DCHECK_EQ(main_job_.get(), job);
    main_job_.reset();
  } else if (job->job_type() == ALTERNATIVE) {
    DCHECK_EQ(alternative_job_.get(), job);
    alternative_job_.reset();
  } else {
    DCHECK_EQ(job->job_type(), DNS_ALPN_H3);
    DCHECK_EQ(dns_alpn_h3_job_.get(), job);
    dns_alpn_h3_job_.reset();
  }

  MaybeNotifyFactoryOfCompletion();
}

void HttpStreamFactory::JobController::AddConnectionAttemptsToRequest(
    Job* job,
    const ConnectionAttempts& attempts) {
  if (is_preconnect_ || IsJobOrphaned(job)) {
    return;
  }

  request_->AddConnectionAttempts(attempts);
}

void HttpStreamFactory::JobController::ResumeMainJobLater(
    const base::TimeDelta& delay) {
  net_log_.AddEventWithInt64Params(NetLogEventType::HTTP_STREAM_JOB_DELAYED,
                                   "delay", delay.InMilliseconds());
  resume_main_job_callback_.Reset(
      base::BindOnce(&HttpStreamFactory::JobController::ResumeMainJob,
                     ptr_factory_.GetWeakPtr()));
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE, resume_main_job_callback_.callback(), delay);
}

void HttpStreamFactory::JobController::ResumeMainJob() {
  DCHECK(main_job_);

  if (main_job_is_resumed_) {
    return;
  }
  main_job_is_resumed_ = true;
  main_job_->net_log().AddEventWithInt64Params(
      NetLogEventType::HTTP_STREAM_JOB_RESUMED, "delay",
      main_job_wait_time_.InMilliseconds());

  main_job_->Resume();
  main_job_wait_time_ = base::TimeDelta();
}

void HttpStreamFactory::JobController::ResetErrorStatusForJobs() {
  main_job_net_error_ = OK;
  alternative_job_net_error_ = OK;
  alternative_job_failed_on_default_network_ = false;
  dns_alpn_h3_job_net_error_ = OK;
  dns_alpn_h3_job_failed_on_default_network_ = false;
}

void HttpStreamFactory::JobController::MaybeResumeMainJob(
    Job* job,
    const base::TimeDelta& delay) {
  DCHECK(delay == base::TimeDelta() || delay == main_job_wait_time_);
  DCHECK(job == main_job_.get() || job == alternative_job_.get() ||
         job == dns_alpn_h3_job_.get());

  if (job == main_job_.get()) {
    return;
  }
  if (job == dns_alpn_h3_job_.get() && alternative_job_) {
    return;
  }
  if (!main_job_) {
    return;
  }

  main_job_is_blocked_ = false;

  if (!main_job_->is_waiting()) {
    // There are two cases where the main job is not in WAIT state:
    //   1) The main job hasn't got to waiting state, do not yet post a task to
    //      resume since that will happen in ShouldWait().
    //   2) The main job has passed waiting state, so the main job does not need
    //      to be resumed.
    return;
  }

  main_job_wait_time_ = delay;

  ResumeMainJobLater(main_job_wait_time_);
}

void HttpStreamFactory::JobController::OnConnectionInitialized(Job* job,
                                                               int rv) {
  if (rv != OK) {
    // Resume the main job as there's an error raised in connection
    // initiation.
    return MaybeResumeMainJob(job, main_job_wait_time_);
  }
}

bool HttpStreamFactory::JobController::ShouldWait(Job* job) {
  // The alternative job never waits.
  if (job == alternative_job_.get() || job == dns_alpn_h3_job_.get()) {
    return false;
  }
  DCHECK_EQ(main_job_.get(), job);
  if (main_job_is_blocked_) {
    return true;
  }

  if (main_job_wait_time_.is_zero()) {
    return false;
  }

  ResumeMainJobLater(main_job_wait_time_);
  return true;
}

const NetLogWithSource* HttpStreamFactory::JobController::GetNetLog() const {
  return &net_log_;
}

void HttpStreamFactory::JobController::MaybeSetWaitTimeForMainJob(
    const base::TimeDelta& delay) {
  if (main_job_is_blocked_) {
    const bool has_available_spdy_session =
        main_job_->HasAvailableSpdySession();
    if (!delay_main_job_with_available_spdy_session_ &&
        has_available_spdy_session) {
      main_job_wait_time_ = base::TimeDelta();
    } else {
      main_job_wait_time_ =
          std::min(delay, base::Seconds(kMaxDelayTimeForMainJobSecs));
    }
    if (has_available_spdy_session) {
      UMA_HISTOGRAM_TIMES("Net.HttpJob.MainJobWaitTimeWithAvailableSpdySession",
                          main_job_wait_time_);
    } else {
      UMA_HISTOGRAM_TIMES(
          "Net.HttpJob.MainJobWaitTimeWithoutAvailableSpdySession",
          main_job_wait_time_);
    }
  }
}

bool HttpStreamFactory::JobController::HasPendingMainJob() const {
  return main_job_.get() != nullptr;
}

bool HttpStreamFactory::JobController::HasPendingAltJob() const {
  return alternative_job_.get() != nullptr;
}

WebSocketHandshakeStreamBase::CreateHelper*
HttpStreamFactory::JobController::websocket_handshake_stream_create_helper() {
  DCHECK(request_);
  return request_->websocket_handshake_stream_create_helper();
}

void HttpStreamFactory::JobController::OnIOComplete(int result) {
  RunLoop(result);
}

void HttpStreamFactory::JobController::RunLoop(int result) {
  int rv = DoLoop(result);
  if (rv == ERR_IO_PENDING) {
    return;
  }
  if (rv != OK) {
    // DoLoop can only fail during proxy resolution step which happens before
    // any jobs are created. Notify |request_| of the failure one message loop
    // iteration later to avoid re-entrancy.
    D
Prompt: 
```
这是目录为net/http/http_stream_factory_job_controller.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_factory_job_controller.h"

#include <string>
#include <utility>

#include "base/containers/contains.h"
#include "base/functional/bind.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/task/single_thread_task_runner.h"
#include "base/values.h"
#include "net/base/features.h"
#include "net/base/host_mapping_rules.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/privacy_mode.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_string_util.h"
#include "net/base/session_usage.h"
#include "net/base/url_util.h"
#include "net/http/alternative_service.h"
#include "net/http/bidirectional_stream_impl.h"
#include "net/http/http_stream_key.h"
#include "net/http/http_stream_pool.h"
#include "net/http/http_stream_pool_request_info.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"
#include "net/proxy_resolution/proxy_info.h"
#include "net/proxy_resolution/proxy_resolution_request.h"
#include "net/proxy_resolution/proxy_resolution_service.h"
#include "net/quic/quic_session_key.h"
#include "net/socket/next_proto.h"
#include "net/spdy/spdy_session.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_versions.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

namespace net {

namespace {

// Returns parameters associated with the proxy resolution.
base::Value::Dict NetLogHttpStreamJobProxyChainResolved(
    const ProxyChain& proxy_chain) {
  base::Value::Dict dict;

  dict.Set("proxy_chain",
           proxy_chain.IsValid() ? proxy_chain.ToDebugString() : std::string());
  return dict;
}

GURL CreateAltSvcUrl(const GURL& origin_url,
                     const HostPortPair& alternative_destination) {
  DCHECK(origin_url.is_valid());
  DCHECK(origin_url.IsStandard());

  GURL::Replacements replacements;
  std::string port_str = base::NumberToString(alternative_destination.port());
  replacements.SetPortStr(port_str);
  replacements.SetHostStr(alternative_destination.host());

  return origin_url.ReplaceComponents(replacements);
}

void ConvertWsToHttp(url::SchemeHostPort& input) {
  if (base::EqualsCaseInsensitiveASCII(input.scheme(), url::kHttpScheme) ||
      base::EqualsCaseInsensitiveASCII(input.scheme(), url::kHttpsScheme)) {
    return;
  }

  if (base::EqualsCaseInsensitiveASCII(input.scheme(), url::kWsScheme)) {
    input = url::SchemeHostPort(url::kHttpScheme, input.host(), input.port());
    return;
  }

  DCHECK(base::EqualsCaseInsensitiveASCII(input.scheme(), url::kWssScheme));
  input = url::SchemeHostPort(url::kHttpsScheme, input.host(), input.port());
}

void HistogramProxyUsed(const ProxyInfo& proxy_info, bool success) {
  const ProxyServer::Scheme max_scheme = ProxyServer::Scheme::SCHEME_QUIC;
  ProxyServer::Scheme proxy_scheme = ProxyServer::Scheme::SCHEME_INVALID;
  if (!proxy_info.is_empty() && !proxy_info.is_direct()) {
    if (proxy_info.proxy_chain().is_multi_proxy()) {
      // TODO(crbug.com/40284947): Update this histogram to have a new
      // bucket for multi-chain proxies. Until then, don't influence the
      // existing metric counts which have historically been only for single-hop
      // proxies.
      return;
    }
    proxy_scheme = proxy_info.proxy_chain().is_direct()
                       ? static_cast<ProxyServer::Scheme>(1)
                       : proxy_info.proxy_chain().First().scheme();
  }
  if (success) {
    UMA_HISTOGRAM_ENUMERATION("Net.HttpJob.ProxyTypeSuccess", proxy_scheme,
                              max_scheme);
  } else {
    UMA_HISTOGRAM_ENUMERATION("Net.HttpJob.ProxyTypeFailed", proxy_scheme,
                              max_scheme);
  }
}

// Generate a AlternativeService for DNS alt job. Note: Chrome does not yet
// support different port DNS alpn.
AlternativeService GetAlternativeServiceForDnsJob(const GURL& url) {
  return AlternativeService(kProtoQUIC, HostPortPair::FromURL(url));
}

base::Value::Dict NetLogAltSvcParams(const AlternativeServiceInfo* alt_svc_info,
                                     bool is_broken) {
  base::Value::Dict dict;
  dict.Set("alt_svc", alt_svc_info->ToString());
  dict.Set("is_broken", is_broken);
  return dict;
}

}  // namespace

// The maximum time to wait for the alternate job to complete before resuming
// the main job.
const int kMaxDelayTimeForMainJobSecs = 3;

HttpStreamFactory::JobController::JobController(
    HttpStreamFactory* factory,
    HttpStreamRequest::Delegate* delegate,
    HttpNetworkSession* session,
    JobFactory* job_factory,
    const HttpRequestInfo& http_request_info,
    bool is_preconnect,
    bool is_websocket,
    bool enable_ip_based_pooling,
    bool enable_alternative_services,
    bool delay_main_job_with_available_spdy_session,
    const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs)
    : factory_(factory),
      session_(session),
      job_factory_(job_factory),
      delegate_(delegate),
      is_preconnect_(is_preconnect),
      is_websocket_(is_websocket),
      enable_ip_based_pooling_(enable_ip_based_pooling),
      enable_alternative_services_(enable_alternative_services),
      delay_main_job_with_available_spdy_session_(
          delay_main_job_with_available_spdy_session),
      http_request_info_url_(http_request_info.url),
      origin_url_(DuplicateUrlWithHostMappingRules(http_request_info.url)),
      request_info_(http_request_info),
      allowed_bad_certs_(allowed_bad_certs),
      net_log_(NetLogWithSource::Make(
          session->net_log(),
          NetLogSourceType::HTTP_STREAM_JOB_CONTROLLER)) {
  DCHECK(factory_);
  DCHECK(session_);
  DCHECK(job_factory_);
  DCHECK(base::EqualsCaseInsensitiveASCII(origin_url_.scheme_piece(),
                                          url::kHttpScheme) ||
         base::EqualsCaseInsensitiveASCII(origin_url_.scheme_piece(),
                                          url::kHttpsScheme) ||
         base::EqualsCaseInsensitiveASCII(origin_url_.scheme_piece(),
                                          url::kWsScheme) ||
         base::EqualsCaseInsensitiveASCII(origin_url_.scheme_piece(),
                                          url::kWssScheme));

  net_log_.BeginEvent(NetLogEventType::HTTP_STREAM_JOB_CONTROLLER, [&] {
    base::Value::Dict dict;
    dict.Set("url", http_request_info.url.possibly_invalid_spec());
    if (origin_url_ != http_request_info.url) {
      dict.Set("url_after_host_mapping", origin_url_.possibly_invalid_spec());
    }
    dict.Set("is_preconnect", is_preconnect_);
    dict.Set("privacy_mode",
             PrivacyModeToDebugString(request_info_.privacy_mode));
    base::Value::List allowed_bad_certs_list;
    for (const auto& cert_and_status : allowed_bad_certs_) {
      allowed_bad_certs_list.Append(
          cert_and_status.cert->subject().GetDisplayName());
    }
    dict.Set("allowed_bad_certs", std::move(allowed_bad_certs_list));
    return dict;
  });
}

HttpStreamFactory::JobController::~JobController() {
  bound_job_ = nullptr;
  main_job_.reset();
  alternative_job_.reset();
  dns_alpn_h3_job_.reset();
  if (proxy_resolve_request_) {
    DCHECK_EQ(STATE_RESOLVE_PROXY_COMPLETE, next_state_);
    proxy_resolve_request_.reset();
  }
  net_log_.EndEvent(NetLogEventType::HTTP_STREAM_JOB_CONTROLLER);
}

std::unique_ptr<HttpStreamRequest> HttpStreamFactory::JobController::Start(
    HttpStreamRequest::Delegate* delegate,
    WebSocketHandshakeStreamBase::CreateHelper*
        websocket_handshake_stream_create_helper,
    const NetLogWithSource& source_net_log,
    HttpStreamRequest::StreamType stream_type,
    RequestPriority priority) {
  DCHECK(!request_);

  stream_type_ = stream_type;
  priority_ = priority;

  auto request = std::make_unique<HttpStreamRequest>(
      this, websocket_handshake_stream_create_helper, source_net_log,
      stream_type);
  // Keep a raw pointer but release ownership of HttpStreamRequest instance.
  request_ = request.get();

  // Associates |net_log_| with |source_net_log|.
  source_net_log.AddEventReferencingSource(
      NetLogEventType::HTTP_STREAM_JOB_CONTROLLER_BOUND, net_log_.source());
  net_log_.AddEventReferencingSource(
      NetLogEventType::HTTP_STREAM_JOB_CONTROLLER_BOUND,
      source_net_log.source());

  RunLoop(OK);

  return request;
}

void HttpStreamFactory::JobController::Preconnect(int num_streams) {
  DCHECK(!main_job_);
  DCHECK(!alternative_job_);
  DCHECK(is_preconnect_);

  stream_type_ = HttpStreamRequest::HTTP_STREAM;
  num_streams_ = num_streams;

  RunLoop(OK);
}

LoadState HttpStreamFactory::JobController::GetLoadState() const {
  DCHECK(request_);
  if (next_state_ == STATE_RESOLVE_PROXY_COMPLETE) {
    return proxy_resolve_request_->GetLoadState();
  }
  if (bound_job_) {
    return bound_job_->GetLoadState();
  }
  if (main_job_) {
    return main_job_->GetLoadState();
  }
  if (alternative_job_) {
    return alternative_job_->GetLoadState();
  }
  if (dns_alpn_h3_job_) {
    return dns_alpn_h3_job_->GetLoadState();
  }

  // When proxy resolution fails, there is no job created and
  // NotifyRequestFailed() is executed one message loop iteration later.
  return LOAD_STATE_IDLE;
}

void HttpStreamFactory::JobController::OnRequestComplete() {
  DCHECK(request_);
  request_ = nullptr;
  // This is called when the delegate is destroying its HttpStreamRequest, so
  // it's no longer safe to call into it after this point.
  delegate_ = nullptr;

  if (!job_bound_) {
    alternative_job_.reset();
    main_job_.reset();
    dns_alpn_h3_job_.reset();
  } else {
    if (bound_job_->job_type() == MAIN) {
      bound_job_ = nullptr;
      main_job_.reset();
    } else if (bound_job_->job_type() == ALTERNATIVE) {
      bound_job_ = nullptr;
      alternative_job_.reset();
    } else {
      DCHECK(bound_job_->job_type() == DNS_ALPN_H3);
      bound_job_ = nullptr;
      dns_alpn_h3_job_.reset();
    }
  }
  MaybeNotifyFactoryOfCompletion();
}

int HttpStreamFactory::JobController::RestartTunnelWithProxyAuth() {
  DCHECK(bound_job_);
  return bound_job_->RestartTunnelWithProxyAuth();
}

void HttpStreamFactory::JobController::SetPriority(RequestPriority priority) {
  if (main_job_) {
    main_job_->SetPriority(priority);
  }
  if (alternative_job_) {
    alternative_job_->SetPriority(priority);
  }
  if (dns_alpn_h3_job_) {
    dns_alpn_h3_job_->SetPriority(priority);
  }
  if (preconnect_backup_job_) {
    preconnect_backup_job_->SetPriority(priority);
  }
}

void HttpStreamFactory::JobController::OnStreamReady(Job* job) {
  DCHECK(job);

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated HttpStreamRequest, |job| has been
    // orphaned.
    OnOrphanedJobComplete(job);
    return;
  }
  std::unique_ptr<HttpStream> stream = job->ReleaseStream();
  DCHECK(stream);

  MarkRequestComplete(job);

  if (!request_) {
    return;
  }
  DCHECK(!is_websocket_);
  DCHECK_EQ(HttpStreamRequest::HTTP_STREAM, request_->stream_type());
  OnJobSucceeded(job);

  // TODO(bnc): Remove when https://crbug.com/461981 is fixed.
  CHECK(request_);

  DCHECK(request_->completed());

  HistogramProxyUsed(job->proxy_info(), /*success=*/true);
  delegate_->OnStreamReady(job->proxy_info(), std::move(stream));
}

void HttpStreamFactory::JobController::OnBidirectionalStreamImplReady(
    Job* job,
    const ProxyInfo& used_proxy_info) {
  DCHECK(job);

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated HttpStreamRequest, |job| has been
    // orphaned.
    OnOrphanedJobComplete(job);
    return;
  }

  MarkRequestComplete(job);

  if (!request_) {
    return;
  }
  std::unique_ptr<BidirectionalStreamImpl> stream =
      job->ReleaseBidirectionalStream();
  DCHECK(stream);
  DCHECK(!is_websocket_);
  DCHECK_EQ(HttpStreamRequest::BIDIRECTIONAL_STREAM, request_->stream_type());

  OnJobSucceeded(job);
  DCHECK(request_->completed());
  delegate_->OnBidirectionalStreamImplReady(used_proxy_info, std::move(stream));
}

void HttpStreamFactory::JobController::OnWebSocketHandshakeStreamReady(
    Job* job,
    const ProxyInfo& used_proxy_info,
    std::unique_ptr<WebSocketHandshakeStreamBase> stream) {
  DCHECK(job);
  MarkRequestComplete(job);

  if (!request_) {
    return;
  }
  DCHECK(is_websocket_);
  DCHECK_EQ(HttpStreamRequest::HTTP_STREAM, request_->stream_type());
  DCHECK(stream);

  OnJobSucceeded(job);
  DCHECK(request_->completed());
  delegate_->OnWebSocketHandshakeStreamReady(used_proxy_info,
                                             std::move(stream));
}

void HttpStreamFactory::JobController::OnQuicHostResolution(
    const url::SchemeHostPort& destination,
    base::TimeTicks dns_resolution_start_time,
    base::TimeTicks dns_resolution_end_time) {
  if (!request_) {
    return;
  }
  if (destination != url::SchemeHostPort(origin_url_)) {
    // Ignores different destination alternative job's DNS resolution time.
    return;
  }
  // QUIC jobs (ALTERNATIVE, DNS_ALPN_H3) are started before the non-QUIC (MAIN)
  // job. So we set the DNS resolution overrides to use the DNS timing of the
  // QUIC jobs.
  request_->SetDnsResolutionTimeOverrides(dns_resolution_start_time,
                                          dns_resolution_end_time);
}

void HttpStreamFactory::JobController::OnStreamFailed(Job* job, int status) {
  DCHECK_NE(OK, status);
  if (job->job_type() == MAIN) {
    DCHECK_EQ(main_job_.get(), job);
    main_job_net_error_ = status;
  } else if (job->job_type() == ALTERNATIVE) {
    DCHECK_EQ(alternative_job_.get(), job);
    DCHECK_NE(kProtoUnknown, alternative_service_info_.protocol());
    alternative_job_net_error_ = status;
  } else {
    DCHECK_EQ(job->job_type(), DNS_ALPN_H3);
    DCHECK_EQ(dns_alpn_h3_job_.get(), job);
    dns_alpn_h3_job_net_error_ = status;
  }

  MaybeResumeMainJob(job, base::TimeDelta());

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated HttpStreamRequest, |job| has been
    // orphaned.
    OnOrphanedJobComplete(job);
    return;
  }

  if (!request_) {
    return;
  }
  DCHECK_NE(OK, status);
  DCHECK(job);

  if (!bound_job_) {
    if (GetJobCount() >= 2) {
      // Hey, we've got other jobs! Maybe one of them will succeed, let's just
      // ignore this failure.
      if (job->job_type() == MAIN) {
        DCHECK_EQ(main_job_.get(), job);
        main_job_.reset();
      } else if (job->job_type() == ALTERNATIVE) {
        DCHECK_EQ(alternative_job_.get(), job);
        alternative_job_.reset();
      } else {
        DCHECK_EQ(job->job_type(), DNS_ALPN_H3);
        DCHECK_EQ(dns_alpn_h3_job_.get(), job);
        dns_alpn_h3_job_.reset();
      }
      return;
    } else {
      BindJob(job);
    }
  }

  status = ReconsiderProxyAfterError(job, status);
  if (next_state_ == STATE_RESOLVE_PROXY_COMPLETE) {
    if (status == ERR_IO_PENDING) {
      return;
    }
    DCHECK_EQ(OK, status);
    RunLoop(status);
    return;
  }

  HistogramProxyUsed(job->proxy_info(), /*success=*/false);
  delegate_->OnStreamFailed(status, *job->net_error_details(),
                            job->proxy_info(), job->resolve_error_info());
}

void HttpStreamFactory::JobController::OnFailedOnDefaultNetwork(Job* job) {
  if (job->job_type() == ALTERNATIVE) {
    DCHECK_EQ(alternative_job_.get(), job);
    alternative_job_failed_on_default_network_ = true;
  } else {
    DCHECK_EQ(job->job_type(), DNS_ALPN_H3);
    DCHECK_EQ(dns_alpn_h3_job_.get(), job);
    dns_alpn_h3_job_failed_on_default_network_ = true;
  }
}

void HttpStreamFactory::JobController::OnCertificateError(
    Job* job,
    int status,
    const SSLInfo& ssl_info) {
  MaybeResumeMainJob(job, base::TimeDelta());

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated HttpStreamRequest, |job| has been
    // orphaned.
    OnOrphanedJobComplete(job);
    return;
  }

  if (!request_) {
    return;
  }
  DCHECK_NE(OK, status);
  if (!bound_job_) {
    BindJob(job);
  }

  delegate_->OnCertificateError(status, ssl_info);
}

void HttpStreamFactory::JobController::OnNeedsClientAuth(
    Job* job,
    SSLCertRequestInfo* cert_info) {
  MaybeResumeMainJob(job, base::TimeDelta());

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated HttpStreamRequest, |job| has been
    // orphaned.
    OnOrphanedJobComplete(job);
    return;
  }
  if (!request_) {
    return;
  }
  if (!bound_job_) {
    BindJob(job);
  }

  delegate_->OnNeedsClientAuth(cert_info);
}

void HttpStreamFactory::JobController::OnNeedsProxyAuth(
    Job* job,
    const HttpResponseInfo& proxy_response,
    const ProxyInfo& used_proxy_info,
    HttpAuthController* auth_controller) {
  MaybeResumeMainJob(job, base::TimeDelta());

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated HttpStreamRequest, |job| has been
    // orphaned.
    OnOrphanedJobComplete(job);
    return;
  }

  if (!request_) {
    return;
  }
  if (!bound_job_) {
    BindJob(job);
  }
  delegate_->OnNeedsProxyAuth(proxy_response, used_proxy_info, auth_controller);
}

void HttpStreamFactory::JobController::OnPreconnectsComplete(Job* job,
                                                             int result) {
  // Preconnects only run as `main_job_`, never `alternative_job_` or
  // `dns_alpn_h3_job_`.
  DCHECK_EQ(main_job_.get(), job);

  // If the job failed because there were no matching HTTPS records in DNS, run
  // the backup job. A TCP-based protocol may work instead.
  if (result == ERR_DNS_NO_MATCHING_SUPPORTED_ALPN && preconnect_backup_job_) {
    DCHECK_EQ(job->job_type(), PRECONNECT_DNS_ALPN_H3);
    main_job_ = std::move(preconnect_backup_job_);
    main_job_->Preconnect(num_streams_);
    return;
  }

  main_job_.reset();
  preconnect_backup_job_.reset();
  ResetErrorStatusForJobs();
  factory_->OnPreconnectsCompleteInternal();
  MaybeNotifyFactoryOfCompletion();
}

void HttpStreamFactory::JobController::OnOrphanedJobComplete(const Job* job) {
  if (job->job_type() == MAIN) {
    DCHECK_EQ(main_job_.get(), job);
    main_job_.reset();
  } else if (job->job_type() == ALTERNATIVE) {
    DCHECK_EQ(alternative_job_.get(), job);
    alternative_job_.reset();
  } else {
    DCHECK_EQ(job->job_type(), DNS_ALPN_H3);
    DCHECK_EQ(dns_alpn_h3_job_.get(), job);
    dns_alpn_h3_job_.reset();
  }

  MaybeNotifyFactoryOfCompletion();
}

void HttpStreamFactory::JobController::AddConnectionAttemptsToRequest(
    Job* job,
    const ConnectionAttempts& attempts) {
  if (is_preconnect_ || IsJobOrphaned(job)) {
    return;
  }

  request_->AddConnectionAttempts(attempts);
}

void HttpStreamFactory::JobController::ResumeMainJobLater(
    const base::TimeDelta& delay) {
  net_log_.AddEventWithInt64Params(NetLogEventType::HTTP_STREAM_JOB_DELAYED,
                                   "delay", delay.InMilliseconds());
  resume_main_job_callback_.Reset(
      base::BindOnce(&HttpStreamFactory::JobController::ResumeMainJob,
                     ptr_factory_.GetWeakPtr()));
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE, resume_main_job_callback_.callback(), delay);
}

void HttpStreamFactory::JobController::ResumeMainJob() {
  DCHECK(main_job_);

  if (main_job_is_resumed_) {
    return;
  }
  main_job_is_resumed_ = true;
  main_job_->net_log().AddEventWithInt64Params(
      NetLogEventType::HTTP_STREAM_JOB_RESUMED, "delay",
      main_job_wait_time_.InMilliseconds());

  main_job_->Resume();
  main_job_wait_time_ = base::TimeDelta();
}

void HttpStreamFactory::JobController::ResetErrorStatusForJobs() {
  main_job_net_error_ = OK;
  alternative_job_net_error_ = OK;
  alternative_job_failed_on_default_network_ = false;
  dns_alpn_h3_job_net_error_ = OK;
  dns_alpn_h3_job_failed_on_default_network_ = false;
}

void HttpStreamFactory::JobController::MaybeResumeMainJob(
    Job* job,
    const base::TimeDelta& delay) {
  DCHECK(delay == base::TimeDelta() || delay == main_job_wait_time_);
  DCHECK(job == main_job_.get() || job == alternative_job_.get() ||
         job == dns_alpn_h3_job_.get());

  if (job == main_job_.get()) {
    return;
  }
  if (job == dns_alpn_h3_job_.get() && alternative_job_) {
    return;
  }
  if (!main_job_) {
    return;
  }

  main_job_is_blocked_ = false;

  if (!main_job_->is_waiting()) {
    // There are two cases where the main job is not in WAIT state:
    //   1) The main job hasn't got to waiting state, do not yet post a task to
    //      resume since that will happen in ShouldWait().
    //   2) The main job has passed waiting state, so the main job does not need
    //      to be resumed.
    return;
  }

  main_job_wait_time_ = delay;

  ResumeMainJobLater(main_job_wait_time_);
}

void HttpStreamFactory::JobController::OnConnectionInitialized(Job* job,
                                                               int rv) {
  if (rv != OK) {
    // Resume the main job as there's an error raised in connection
    // initiation.
    return MaybeResumeMainJob(job, main_job_wait_time_);
  }
}

bool HttpStreamFactory::JobController::ShouldWait(Job* job) {
  // The alternative job never waits.
  if (job == alternative_job_.get() || job == dns_alpn_h3_job_.get()) {
    return false;
  }
  DCHECK_EQ(main_job_.get(), job);
  if (main_job_is_blocked_) {
    return true;
  }

  if (main_job_wait_time_.is_zero()) {
    return false;
  }

  ResumeMainJobLater(main_job_wait_time_);
  return true;
}

const NetLogWithSource* HttpStreamFactory::JobController::GetNetLog() const {
  return &net_log_;
}

void HttpStreamFactory::JobController::MaybeSetWaitTimeForMainJob(
    const base::TimeDelta& delay) {
  if (main_job_is_blocked_) {
    const bool has_available_spdy_session =
        main_job_->HasAvailableSpdySession();
    if (!delay_main_job_with_available_spdy_session_ &&
        has_available_spdy_session) {
      main_job_wait_time_ = base::TimeDelta();
    } else {
      main_job_wait_time_ =
          std::min(delay, base::Seconds(kMaxDelayTimeForMainJobSecs));
    }
    if (has_available_spdy_session) {
      UMA_HISTOGRAM_TIMES("Net.HttpJob.MainJobWaitTimeWithAvailableSpdySession",
                          main_job_wait_time_);
    } else {
      UMA_HISTOGRAM_TIMES(
          "Net.HttpJob.MainJobWaitTimeWithoutAvailableSpdySession",
          main_job_wait_time_);
    }
  }
}

bool HttpStreamFactory::JobController::HasPendingMainJob() const {
  return main_job_.get() != nullptr;
}

bool HttpStreamFactory::JobController::HasPendingAltJob() const {
  return alternative_job_.get() != nullptr;
}

WebSocketHandshakeStreamBase::CreateHelper*
HttpStreamFactory::JobController::websocket_handshake_stream_create_helper() {
  DCHECK(request_);
  return request_->websocket_handshake_stream_create_helper();
}

void HttpStreamFactory::JobController::OnIOComplete(int result) {
  RunLoop(result);
}

void HttpStreamFactory::JobController::RunLoop(int result) {
  int rv = DoLoop(result);
  if (rv == ERR_IO_PENDING) {
    return;
  }
  if (rv != OK) {
    // DoLoop can only fail during proxy resolution step which happens before
    // any jobs are created. Notify |request_| of the failure one message loop
    // iteration later to avoid re-entrancy.
    DCHECK(!main_job_);
    DCHECK(!alternative_job_);
    DCHECK(!dns_alpn_h3_job_);
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&HttpStreamFactory::JobController::NotifyRequestFailed,
                       ptr_factory_.GetWeakPtr(), rv));
  }
}

int HttpStreamFactory::JobController::DoLoop(int rv) {
  DCHECK_NE(next_state_, STATE_NONE);
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_RESOLVE_PROXY:
        DCHECK_EQ(OK, rv);
        rv = DoResolveProxy();
        break;
      case STATE_RESOLVE_PROXY_COMPLETE:
        rv = DoResolveProxyComplete(rv);
        break;
      case STATE_CREATE_JOBS:
        DCHECK_EQ(OK, rv);
        rv = DoCreateJobs();
        break;
      default:
        NOTREACHED() << "bad state";
    }
  } while (next_state_ != STATE_NONE && rv != ERR_IO_PENDING);
  return rv;
}

int HttpStreamFactory::JobController::DoResolveProxy() {
  DCHECK(!proxy_resolve_request_);

  next_state_ = STATE_RESOLVE_PROXY_COMPLETE;

  if (request_info_.load_flags & LOAD_BYPASS_PROXY) {
    proxy_info_.UseDirect();
    return OK;
  }

  CompletionOnceCallback io_callback =
      base::BindOnce(&JobController::OnIOComplete, base::Unretained(this));
  return session_->proxy_resolution_service()->ResolveProxy(
      origin_url_, request_info_.method,
      request_info_.network_anonymization_key, &proxy_info_,
      std::move(io_callback), &proxy_resolve_request_, net_log_);
}

int HttpStreamFactory::JobController::DoResolveProxyComplete(int rv) {
  DCHECK_NE(ERR_IO_PENDING, rv);

  proxy_resolve_request_ = nullptr;
  net_log_.AddEvent(
      NetLogEventType::HTTP_STREAM_JOB_CONTROLLER_PROXY_SERVER_RESOLVED, [&] {
        return NetLogHttpStreamJobProxyChainResolved(
            proxy_info_.is_empty() ? ProxyChain() : proxy_info_.proxy_chain());
      });

  if (rv != OK) {
    return rv;
  }
  // Remove unsupported proxies from the list.
  int supported_proxies = ProxyServer::SCHEME_HTTP | ProxyServer::SCHEME_HTTPS |
                          ProxyServer::SCHEME_SOCKS4 |
                          ProxyServer::SCHEME_SOCKS5;
  // WebSockets is not supported over QUIC.
  if (session_->IsQuicEnabled() && !is_websocket_) {
    supported_proxies |= ProxyServer::SCHEME_QUIC;
  }
  proxy_info_.RemoveProxiesWithoutScheme(supported_proxies);

  if (proxy_info_.is_empty()) {
    // No proxies/direct to choose from.
    return ERR_NO_SUPPORTED_PROXIES;
  }

  next_state_ = STATE_CREATE_JOBS;
  return rv;
}

int HttpStreamFactory::JobController::DoCreateJobs() {
  DCHECK(!main_job_);
  DCHECK(!alternative_job_);
  DCHECK(origin_url_.is_valid());
  DCHECK(origin_url_.IsStandard());

  url::SchemeHostPort destination(origin_url_);
  DCHECK(destination.IsValid());
  ConvertWsToHttp(destination);

  // Create an alternative job if alternative service is set up for this domain.
  // This is applicable even if the connection will be made via a proxy.
  alternative_service_info_ = GetAlternativeServiceInfoFor(
      http_request_info_url_, request_info_, delegate_, stream_type_);

  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3) &&
      proxy_info_.is_direct() && !is_websocket_) {
    SwitchToHttpStreamPool();
    return OK;
  }

  quic::ParsedQuicVersion quic_version = quic::ParsedQuicVersion::Unsupported();
  if (alternative_service_info_.protocol() == kProtoQUIC) {
    quic_version =
        SelectQuicVersion(alternative_service_info_.advertised_versions());
    DCHECK_NE(quic_version, quic::ParsedQuicVersion::Unsupported());
  }

  // Getting ALPN for H3 from DNS has a lot of preconditions. Among them:
  // - proxied connections perform DNS on the proxy, so they can't get supported
  //   ALPNs from DNS
  const bool dns_alpn_h3_job_enabled =
      !session_->ShouldForceQuic(destination, proxy_info_, is_websocket_) &&
      enable_alternative_services_ &&
      session_->params().use_dns_https_svcb_alpn &&
      base::EqualsCaseInsensitiveASCII(origin_url_.scheme(),
                                       url::kHttpsScheme) &&
      session_->IsQuicEnabled() && proxy_info_.is_direct() &&
      !session_->http_server_properties()->IsAlternativeServiceBroken(
          GetAlternativeServiceForDnsJob(origin_url_),
          request_info_.network_anonymization_key);

  if (is_preconnect_) {
    // Due to how the socket pools handle priorities and idle sockets, only IDLE
    // priority currently makes sense for preconnects. The priority for
    // preconnects is currently ignored (see RequestSocketsForPool()), but could
    // be used at some point for proxy resolution or something.
    // Note: When `dns_alpn_h3_job_enabled` is true, we create a
    // PRECONNECT_DNS_ALPN_H3 job. If no matching HTTPS DNS ALPN records are
    // received, the PRECONNECT_DNS_ALPN_H3 job will fail with
    // ERR_DNS_NO_MATCHING_SUPPORTED_ALPN, and `preconnect_backup_job_` will
    // be started in OnPreconnectsComplete().
    std::unique_ptr<Job> preconnect_job = job_factory_->CreateJob(
        this, dns_alpn_h3_job_enabled ? PRECONNECT_DNS_ALPN_H3 : PRECONNECT,
        session_, request_info_, IDLE, proxy_info_, allowed_bad_certs_,
        destination, origin_url_, is_websocket_, enable_ip_based_pooling_,
        net_log_.net_log(), NextProto::kProtoUnknown,
        quic::ParsedQuicVersion::Unsupported());
    // When there is an valid alternative service info, and `preconnect_job`
    // has no existing QUIC session, create a job for the alternative service.
    if (alternative_service_info_.protocol() != kProtoUnknown &&
        !preconnect_job->HasAvailableQuicSession()) {
      GURL alternative_url = CreateAltSvcUrl(
          origin_url_, alternative_service_info_.host_port_pair());
      RewriteUrlWithHostMappingRules(alternative_url);

      url::SchemeHostPort alternative_destination =
          url::SchemeHostPort(alternative_url);
      ConvertWsToHttp(alternative_destination);

      main_job_ = job_factory_->CreateJob(
          this, PRECONNECT, session_, request_info_, IDLE, proxy_info_,
          allowed_bad_certs_, std::move(alternative_destination), origin_url_,
          is_websocket_, enable_ip_based_pooling_, session_->net_log(),
          alternative_service_info_.protocol(), quic_version);
    } else {
      main_job_ = std::move(preconnect_job);

      if (dns_alpn_h3_job_enabled) {
        preconnect_backup_job_ = job_factory_->CreateJob(
            this, PRECONNECT, session_, request_info_, IDLE, proxy_info_,
            allowed_bad_certs_, std::move(destination), origin_url_,
            is_websocket_, enable_ip_based_pooling_, net_log_.net_log(),
            NextProto::kProtoUnknown, quic::ParsedQuicVersion::Unsupported());
      }
    }
    main_job_->Preconnect(num_streams_);
    return OK;
  }
  main_job_ = job_factory_->CreateJob(
      this, MAIN, session_, request_info_, priority_, proxy_info_,
      allowed_bad_certs_, std::move(destination), origin_url_, is_websocket_,
      enable_ip_based_pooling_, net_log_.net_log(), NextProto::kProtoUnknown,
      quic::ParsedQuicVersion::Unsupported());

  // Alternative Service can only be set for HTTPS requests while Alternative
  // Proxy is set for HTTP requests.
  // The main job may use HTTP/3 if the origin is specified in
  // `--origin-to-force-quic-on` switch. In that case, do not create
  // `alternative_job_` and `dns_alpn_h3_job_`.
  if ((alternative_service_info_.protocol() != kProtoUnknown) &&
      !main_job_->using_quic()) {
    DCHECK(origin_url_.SchemeIs(url::kHttpsScheme));
    DCHECK(!is_websocket_);
    DVLOG(1) << "Selected alternative service (host: "
             << alternative_service_info_.host_port_pair().host()
             << " port: " << alternative_service_info_.host_port_pair().port()
             << " version: " << quic_version << ")";

    GURL alternative_url = CreateAltSvcUrl(
        origin_url_, alternative_service_info_.host_port_pair());
    RewriteUrlWithHostMappingRules(alternative_url);

    url::SchemeHostPort alternative_destination =
        url::SchemeHostPort(alternative_url);
    ConvertWsToHttp(alternative_destination);

    alternative_job_ = job_factory_->CreateJob(
        this, ALTERNATIVE, session_, request_info_, priority_, proxy_info_,
        allowed_bad_certs_, std::move(alternative_destination), origin_url_,
        is_websocket_, enable_ip_based_pooling_, net_log_.net_log(),
        alternative_service_info_.protocol(), quic_version);
  }

  if (dns_alpn_h3_job_enabled && !main_job_->using_quic()) {
    DCHECK(!is_websocket_);
    url::SchemeHostPort dns_alpn_h3_destination =
        url::SchemeHostPort(origin_url_);
    dns_alpn_h3_job_ = job_factory_->CreateJob(
        this, DNS_ALPN_H3, session_, request_info_, priority_, proxy_info_,
        allowed_bad_certs_, std::move(dns_alpn_h3_destination), origin_url_,
        is_websocket_, enable_ip_based_pooling_, net_log_.net_log(),
        NextProto::kProtoUnknown, quic::ParsedQuicVersion::Unsupported());
  }

  ClearInappropriateJobs();

  if (main_job_ && (alternative_job_ ||
                    (dns_alpn_h3_job_ &&
                     (!main_job_->TargettedSocketGroupHasAc
"""


```