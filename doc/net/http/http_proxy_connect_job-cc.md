Response:
Let's break down the thought process for analyzing this C++ code snippet. The goal is to understand its functionality and address the specific prompts in the request.

**1. Initial Reading and High-Level Understanding:**

* **Keywords:**  "net/http/http_proxy_connect_job.cc", "chromium", "network stack", "proxy", "CONNECT". These immediately tell me the code is about establishing connections through HTTP proxies in Chrome. The filename `http_proxy_connect_job` is very descriptive.
* **Includes:**  Scanning the `#include` directives gives a good overview of the involved components: networking primitives (`net/base`, `net/socket`), HTTP specifics (`net/http`), QUIC (`net/quic`), SPDY (`net/spdy`), logging (`net/log`), and utilities (`base`). The inclusion of `http_proxy_client_socket.h`, `net/socket/ssl_connect_job.h`, `net/socket/transport_connect_job.h`, `net/spdy/spdy_proxy_client_socket.h`, and `net/quic/quic_proxy_client_socket.h` highlights the core function: managing different ways to connect through proxies.
* **Namespace:** The code is within the `net` namespace, further confirming its networking focus.
* **Class `HttpProxyConnectJob`:** This is the central class. It inherits from `ConnectJob`, suggesting it's responsible for a specific type of connection establishment.

**2. Deeper Dive into Functionality:**

* **Constructor and `ConnectInternal()`:**  The constructor takes parameters related to the connection, and `ConnectInternal()` seems to initiate the connection process.
* **State Machine:** The `DoLoop()` method and the `next_state_` member strongly suggest a state machine pattern. This is common for asynchronous operations like network connections. Tracing the different `STATE_` values within `DoLoop()` reveals the connection flow:
    * Begin (`STATE_BEGIN_CONNECT`)
    * Transport connection (TCP/TLS to the proxy itself) (`STATE_TRANSPORT_CONNECT`, `STATE_TRANSPORT_CONNECT_COMPLETE`)
    * Proxy connection (establishing the tunnel through the proxy) using HTTP CONNECT, SPDY, or QUIC (`STATE_HTTP_PROXY_CONNECT`, `STATE_SPDY_PROXY_CREATE_STREAM`, `STATE_QUIC_PROXY_CREATE_SESSION`, etc.)
    * Authentication handling (`STATE_RESTART_WITH_AUTH`)
* **`HttpProxySocketParams`:**  This class holds the necessary configuration for establishing the proxy connection (endpoint, proxy chain, tunneling, etc.).
* **Timeout Logic:** The `HttpProxyTimeoutExperiments` class and the `AlternateNestedConnectionTimeout()` function deal with adaptive timeouts based on network conditions. This is important for performance.
* **Authentication:** The `HttpAuthController` is used for handling proxy authentication challenges.
* **QUIC and SPDY:**  The code explicitly handles connecting through QUIC and SPDY proxies, showcasing its modern networking capabilities.
* **Error Handling:** The code checks for various errors (`ERR_PROXY_AUTH_REQUESTED`, `ERR_HTTP_1_1_REQUIRED`, SSL certificate errors, etc.) and takes appropriate actions.

**3. Addressing Specific Prompts:**

* **Functionality Listing:**  Based on the above analysis, the functionality can be summarized as establishing connections through various types of HTTP proxies (HTTP, HTTPS, QUIC) and handling proxy authentication.
* **Relationship with JavaScript:**  This is where I need to connect the backend (C++) with the frontend (JavaScript). JavaScript in a browser makes requests. When a proxy is configured, the browser uses this C++ code to handle the underlying proxy connection. Key connection points are:
    * When JavaScript makes an HTTP/HTTPS request, and a proxy is configured, the browser's network stack (using this C++ code) will establish the connection to the proxy.
    * Proxy settings are often configured by the user or an administrator, influencing whether this code is used.
    * Features like "QUIC" might be enabled or disabled, impacting which parts of this code are executed.
    * Error conditions handled here (like proxy authentication failures) can eventually manifest as errors in the JavaScript.
* **Logical Reasoning (Hypothetical Input/Output):** I need to create simple scenarios to illustrate the code's behavior. A successful HTTP proxy connection and a failed authentication attempt are good examples.
* **User/Programming Errors:**  Think about common mistakes when dealing with proxies. Incorrect proxy settings, firewalls blocking ports, or wrong authentication details are prime examples.
* **User Operations as Debugging Clues:**  How does a user end up triggering this code?  Configuring proxy settings, accessing a website that requires a proxy, or encountering proxy authentication prompts are key steps.
* **Summarizing Functionality (Part 1):** Focus on the core responsibilities of the code up to this point in the file: primarily the initial setup and the transport layer connection.

**4. Refinement and Structuring:**

* **Organization:** Group related functionalities together (e.g., timeout logic, authentication).
* **Clarity:** Use clear and concise language. Avoid overly technical jargon where possible.
* **Examples:**  Provide concrete examples to illustrate the concepts.
* **Code Snippets (where appropriate):**  Reference specific parts of the code to support the explanations.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe focus too much on the low-level socket details.
* **Correction:** Realize the request is about the *functionality* from a higher level, including how it relates to the browser and user actions. Shift the focus to the overall connection process and its implications.
* **Initial thought:**  Overlook the JavaScript connection.
* **Correction:**  Remember the context – this is browser code. Think about how web requests and proxy configurations in the browser relate to this backend code.
* **Initial thought:** Provide very detailed input/output scenarios.
* **Correction:** Keep the hypothetical scenarios simple and illustrative, focusing on the key aspects of the code's logic.

By following these steps, I can systematically analyze the C++ code and generate a comprehensive and accurate response that addresses all aspects of the user's request.
This C++ source code file, `http_proxy_connect_job.cc`, which is part of the Chromium network stack, is responsible for establishing a connection to a target server through an HTTP proxy. It manages the process of connecting to the proxy server itself and then issuing the necessary commands to tunnel through it to the ultimate destination.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Managing the Proxy Connection Lifecycle:** This class (`HttpProxyConnectJob`) is a `ConnectJob`, indicating its role in the process of establishing network connections. It orchestrates the steps involved in connecting through a proxy.

2. **Handling Different Proxy Types:**  The code supports various types of proxies, including:
    * **HTTP Proxies:**  Connects to the proxy server using standard HTTP.
    * **HTTPS Proxies (CONNECT over HTTPS):** Connects to the proxy server over a secure TLS/SSL connection.
    * **QUIC Proxies:** Connects to the proxy server using the QUIC protocol.
    * **SPDY Proxies (HTTP/2 Proxies):** Connects to the proxy server using the SPDY/HTTP/2 protocol.

3. **Establishing a Tunnel (CONNECT Method):** For non-transparent proxies, the code implements the HTTP `CONNECT` method to create a tunnel through the proxy to the destination server. This involves sending a `CONNECT` request to the proxy and waiting for a successful "200 Connection established" response.

4. **Proxy Authentication:** The code integrates with Chromium's authentication framework (`HttpAuthController`) to handle proxy authentication challenges (e.g., Basic, Digest). It can automatically retry the connection with the necessary credentials if the proxy requires authentication.

5. **Timeout Management:**  It implements specific timeouts for the proxy connection process, in addition to the underlying socket timeouts. These timeouts can be adaptive based on network conditions (RTT estimates).

6. **Error Handling:** The code handles various errors that can occur during the proxy connection process, such as:
    * Proxy connection failures.
    * Proxy authentication failures.
    * SSL certificate errors related to the proxy server.
    * Negotiation failures with the proxy (e.g., HTTP/1.1 required).

7. **Logging and Metrics:** The code uses Chromium's logging (`net_log`) and metrics infrastructure to record events and performance data related to proxy connections.

8. **Integration with Underlying Socket Layers:** It utilizes `TransportConnectJob`, `SSLConnectJob`, `QuicSessionRequest`, and `SpdyStreamRequest` to establish the initial connection to the proxy server based on its protocol.

9. **User Agent Handling:** It incorporates the user agent string when making the `CONNECT` request to the proxy.

**Relationship with JavaScript Functionality:**

While this C++ code doesn't directly execute JavaScript, it plays a crucial role in enabling network requests initiated by JavaScript code running in a web browser. Here's how they are connected:

* **JavaScript `fetch()` or `XMLHttpRequest`:** When JavaScript code in a web page makes an HTTP or HTTPS request, and a proxy server is configured in the browser settings (or through an extension), the browser's network stack, including this `HttpProxyConnectJob` code, is invoked.

* **Proxy Configuration:** The browser's proxy settings (obtained from the operating system, user configuration, or PAC scripts) determine whether a proxy should be used for a particular request. If a proxy is required, this code handles the connection to that proxy.

* **Transparently to JavaScript:**  From the JavaScript developer's perspective, the proxy connection is often transparent. The JavaScript code initiates a request to the target server, and the browser handles the underlying proxy communication.

* **Error Reporting:** If the proxy connection fails (due to authentication, connection issues, etc.), this C++ code will generate error codes that can eventually be surfaced to the JavaScript layer, often as network errors in the `fetch()` API or `XMLHttpRequest` object.

**Example:**

Imagine a JavaScript application making a `fetch()` request to `https://example.com`. The user's browser is configured to use an HTTP proxy at `proxy.mycompany.com:8080`.

1. The JavaScript `fetch()` call initiates a network request.
2. The browser's network stack determines that a proxy needs to be used for this request.
3. An `HttpProxyConnectJob` is created with the proxy address and the target `example.com`.
4. This code might first establish a TCP connection to `proxy.mycompany.com:8080` using a `TransportConnectJob`.
5. It then sends an HTTP `CONNECT` request to the proxy:
   ```
   CONNECT example.com:443 HTTP/1.1
   Host: example.com:443
   User-Agent: [Browser User Agent String]
   ```
6. If the proxy requires authentication, the `HttpAuthController` will handle the authentication handshake.
7. Upon receiving a "200 Connection established" response from the proxy, a tunnel is established.
8. The browser then uses this tunnel to send the actual request to `example.com`.
9. The response from `example.com` travels back through the tunnel and is eventually received by the JavaScript `fetch()` API.

**Logical Reasoning (Hypothetical Input and Output):**

**Assumption:** The browser is configured to use an HTTP proxy at `proxy.example.net:80`. The target URL is `https://secure.example.org`.

**Input:**
* **Target Host:** `secure.example.org`
* **Target Port:** 443 (for HTTPS)
* **Proxy Host:** `proxy.example.net`
* **Proxy Port:** 80
* **Tunneling Required:** Yes (since it's an HTTPS target through an HTTP proxy)

**Steps within `HttpProxyConnectJob`:**

1. **`STATE_BEGIN_CONNECT`:** Start the connection process.
2. **`STATE_TRANSPORT_CONNECT`:** Initiate a TCP connection to `proxy.example.net:80`.
3. **`STATE_TRANSPORT_CONNECT_COMPLETE`:** The TCP connection to the proxy is successful.
4. **`STATE_HTTP_PROXY_CONNECT`:** Send the `CONNECT` request to the proxy:
   ```
   CONNECT secure.example.org:443 HTTP/1.1
   Host: secure.example.org:443
   User-Agent: [Browser User Agent String]
   ```
5. **`STATE_HTTP_PROXY_CONNECT_COMPLETE`:**
   * **Successful Output:** If the proxy responds with "HTTP/1.1 200 Connection established", the connection is successful. The underlying socket is now ready to be used for secure communication with `secure.example.org`.
   * **Error Output (Example - Proxy Authentication Required):** If the proxy responds with "HTTP/1.1 407 Proxy Authentication Required", the state transitions to handle authentication (`STATE_RESTART_WITH_AUTH`). The output would be an error indicating the need for proxy authentication.

**User or Programming Common Usage Errors:**

1. **Incorrect Proxy Settings:** Users might enter the wrong proxy server address or port in their browser settings. This will lead to connection failures within `HttpProxyConnectJob`. The error might be something like `ERR_PROXY_CONNECTION_FAILED`.

2. **Firewall Blocking Proxy:** A firewall might be blocking the connection to the specified proxy server. This would result in the underlying TCP connection failing, leading to errors in the `STATE_TRANSPORT_CONNECT` phase.

3. **Proxy Authentication Issues:**
   * **Incorrect Credentials:** Users might provide wrong usernames or passwords for proxy authentication. This will lead to the `HttpAuthController` failing and the `HttpProxyConnectJob` returning an `ERR_PROXY_AUTH_REQUESTED` error (and potentially retrying if credentials are available).
   * **Unsupported Authentication Scheme:** The proxy might be using an authentication scheme that the browser doesn't support.

4. **Proxy Requiring HTTP/1.1:** Some older proxies might not support HTTP/2 for tunneling. If the browser tries to use HTTP/2, the proxy might respond with an error, leading to the `HttpProxyConnectJob` potentially falling back to HTTP/1.1.

**User Operations to Reach This Code (Debugging Clues):**

To trigger this code path, a user would typically:

1. **Configure Proxy Settings:**  The user (or system administrator) would need to configure proxy settings within the operating system or the browser itself. This includes specifying the proxy server address, port, and potentially authentication details.

2. **Attempt to Access a Website:** Once the proxy is configured, any attempt by the user to access a website will go through the configured proxy.

3. **Specific Scenarios:**
   * **Accessing an HTTPS site with an HTTP proxy:** This will definitely trigger the `CONNECT` method logic within `HttpProxyConnectJob`.
   * **Accessing a site that requires proxy authentication:** This will exercise the authentication handling logic.
   * **Accessing a site when the proxy server is unavailable or has issues:** This will lead to error conditions being handled by this code.

**Debugging Steps:** If you were debugging a network issue and suspect a proxy is involved, you might:

1. **Check the Browser's Network Logs:** Chromium's DevTools (Network tab) provides detailed logs of network requests, including information about proxy usage and any errors encountered during the proxy connection.

2. **Use `net-internals` (chrome://net-internals):** This powerful debugging tool in Chrome provides in-depth information about network events, including proxy resolution, socket connections, and authentication challenges. You can see the `HttpProxyConnectJob` being created and its state transitions.

3. **Check Proxy Server Logs:** If you have access to the proxy server logs, you can examine them to see if the browser is connecting and if there are any errors on the proxy side.

**Summary of Functionality (Part 1):**

The primary function of the code in this first part of `http_proxy_connect_job.cc` is to **initiate and manage the initial connection to the proxy server itself**. This involves:

* **Determining the type of proxy:** (HTTP, HTTPS, QUIC).
* **Establishing a transport-level connection:** Using TCP or TLS to the proxy server's address and port.
* **Handling potential errors during the initial connection:** Such as connection refused or SSL handshake failures.
* **Preparing for the next stage:** Which involves either directly using the connection (if not tunneling) or initiating the proxy tunneling process (using `CONNECT` for HTTP proxies, or setting up streams for SPDY/QUIC proxies).

It sets the foundation for the subsequent steps of establishing the tunnel and communicating with the target server through the proxy.

### 提示词
```
这是目录为net/http/http_proxy_connect_job.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_proxy_connect_job.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_functions.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/values.h"
#include "build/build_config.h"
#include "http_proxy_client_socket.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/base/http_user_agent_settings.h"
#include "net/base/net_errors.h"
#include "net/base/proxy_chain.h"
#include "net/base/session_usage.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/log/net_log_source_type.h"
#include "net/log/net_log_with_source.h"
#include "net/nqe/network_quality_estimator.h"
#include "net/quic/quic_context.h"
#include "net/quic/quic_http_utils.h"
#include "net/quic/quic_proxy_client_socket.h"
#include "net/quic/quic_session_key.h"
#include "net/quic/quic_session_pool.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/next_proto.h"
#include "net/socket/ssl_client_socket.h"
#include "net/socket/ssl_connect_job.h"
#include "net/socket/transport_client_socket_pool.h"
#include "net/socket/transport_connect_job.h"
#include "net/spdy/multiplexed_session_creation_initiator.h"
#include "net/spdy/spdy_proxy_client_socket.h"
#include "net/spdy/spdy_session.h"
#include "net/spdy/spdy_session_pool.h"
#include "net/spdy/spdy_stream.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"

namespace net {

namespace {

// HttpProxyConnectJobs will time out after this many seconds.  Note this is in
// addition to the timeout for the transport socket.
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
constexpr base::TimeDelta kHttpProxyConnectJobTunnelTimeout = base::Seconds(10);
#else
constexpr base::TimeDelta kHttpProxyConnectJobTunnelTimeout = base::Seconds(30);
#endif

class HttpProxyTimeoutExperiments {
 public:
  HttpProxyTimeoutExperiments() { Init(); }

  ~HttpProxyTimeoutExperiments() = default;

  void Init() {
    min_proxy_connection_timeout_ =
        base::Seconds(GetInt32Param("min_proxy_connection_timeout_seconds", 8));
    max_proxy_connection_timeout_ = base::Seconds(
        GetInt32Param("max_proxy_connection_timeout_seconds", 30));
    ssl_http_rtt_multiplier_ = GetInt32Param("ssl_http_rtt_multiplier", 10);
    non_ssl_http_rtt_multiplier_ =
        GetInt32Param("non_ssl_http_rtt_multiplier", 5);

    DCHECK_LT(0, ssl_http_rtt_multiplier_);
    DCHECK_LT(0, non_ssl_http_rtt_multiplier_);
    DCHECK_LE(base::TimeDelta(), min_proxy_connection_timeout_);
    DCHECK_LE(base::TimeDelta(), max_proxy_connection_timeout_);
    DCHECK_LE(min_proxy_connection_timeout_, max_proxy_connection_timeout_);
  }

  base::TimeDelta min_proxy_connection_timeout() const {
    return min_proxy_connection_timeout_;
  }
  base::TimeDelta max_proxy_connection_timeout() const {
    return max_proxy_connection_timeout_;
  }
  int32_t ssl_http_rtt_multiplier() const { return ssl_http_rtt_multiplier_; }
  int32_t non_ssl_http_rtt_multiplier() const {
    return non_ssl_http_rtt_multiplier_;
  }

 private:
  // Returns the value of the parameter |param_name| for the field trial
  // "NetAdaptiveProxyConnectionTimeout". If the value of the parameter is
  // unavailable, then |default_value| is available.
  static int32_t GetInt32Param(const std::string& param_name,
                               int32_t default_value) {
    int32_t param;
    if (!base::StringToInt(base::GetFieldTrialParamValue(
                               "NetAdaptiveProxyConnectionTimeout", param_name),
                           &param)) {
      return default_value;
    }
    return param;
  }

  // For secure proxies, the connection timeout is set to
  // |ssl_http_rtt_multiplier_| times the HTTP RTT estimate. For insecure
  // proxies, the connection timeout is set to |non_ssl_http_rtt_multiplier_|
  // times the HTTP RTT estimate. In either case, the connection timeout
  // is clamped to be between |min_proxy_connection_timeout_| and
  // |max_proxy_connection_timeout_|.
  base::TimeDelta min_proxy_connection_timeout_;
  base::TimeDelta max_proxy_connection_timeout_;
  int32_t ssl_http_rtt_multiplier_;
  int32_t non_ssl_http_rtt_multiplier_;
};

HttpProxyTimeoutExperiments* GetProxyTimeoutExperiments() {
  static HttpProxyTimeoutExperiments proxy_timeout_experiments;
  return &proxy_timeout_experiments;
}

// Make a URL for a proxy, for use in proxy auth challenges.
GURL MakeProxyUrl(const HttpProxySocketParams& params) {
  const bool is_https = params.is_over_ssl() || params.is_over_quic();
  return GURL((is_https ? "https://" : "http://") +
              params.proxy_server().host_port_pair().ToString());
}

}  // namespace

HttpProxySocketParams::HttpProxySocketParams(
    ConnectJobParams nested_params,
    const HostPortPair& endpoint,
    const ProxyChain& proxy_chain,
    size_t proxy_chain_index,
    bool tunnel,
    const NetworkTrafficAnnotationTag traffic_annotation,
    const NetworkAnonymizationKey& network_anonymization_key,
    SecureDnsPolicy secure_dns_policy)
    : HttpProxySocketParams(std::move(nested_params),
                            std::nullopt,
                            endpoint,
                            proxy_chain,
                            proxy_chain_index,
                            tunnel,
                            std::move(traffic_annotation),
                            network_anonymization_key,
                            secure_dns_policy) {}

HttpProxySocketParams::HttpProxySocketParams(
    SSLConfig quic_ssl_config,
    const HostPortPair& endpoint,
    const ProxyChain& proxy_chain,
    size_t proxy_chain_index,
    bool tunnel,
    const NetworkTrafficAnnotationTag traffic_annotation,
    const NetworkAnonymizationKey& network_anonymization_key,
    SecureDnsPolicy secure_dns_policy)
    : HttpProxySocketParams(std::nullopt,
                            std::move(quic_ssl_config),
                            endpoint,
                            proxy_chain,
                            proxy_chain_index,
                            tunnel,
                            std::move(traffic_annotation),
                            network_anonymization_key,
                            secure_dns_policy) {}

HttpProxySocketParams::HttpProxySocketParams(
    std::optional<ConnectJobParams> nested_params,
    std::optional<SSLConfig> quic_ssl_config,
    const HostPortPair& endpoint,
    const ProxyChain& proxy_chain,
    size_t proxy_chain_index,
    bool tunnel,
    const NetworkTrafficAnnotationTag traffic_annotation,
    const NetworkAnonymizationKey& network_anonymization_key,
    SecureDnsPolicy secure_dns_policy)
    : nested_params_(std::move(nested_params)),
      quic_ssl_config_(std::move(quic_ssl_config)),
      endpoint_(endpoint),
      proxy_chain_(proxy_chain),
      proxy_chain_index_(proxy_chain_index),
      tunnel_(tunnel),
      network_anonymization_key_(network_anonymization_key),
      traffic_annotation_(traffic_annotation),
      secure_dns_policy_(secure_dns_policy) {
  DCHECK(!proxy_chain_.is_direct());
  DCHECK(proxy_chain_.IsValid());
  CHECK(proxy_chain_index_ < proxy_chain_.length());

  // This is either a connection to an HTTP proxy,an SSL proxy, or a QUIC proxy.
  DCHECK(nested_params_ || quic_ssl_config_);
  DCHECK(!(nested_params_ && quic_ssl_config_));

  // Only supports proxy endpoints without scheme for now.
  // TODO(crbug.com/40181080): Handle scheme.
  if (is_over_transport()) {
    DCHECK(absl::holds_alternative<HostPortPair>(
        nested_params_->transport()->destination()));
  } else if (is_over_ssl() && nested_params_->ssl()->GetConnectionType() ==
                                  SSLSocketParams::ConnectionType::DIRECT) {
    DCHECK(absl::holds_alternative<HostPortPair>(
        nested_params_->ssl()->GetDirectConnectionParams()->destination()));
  }
}

HttpProxySocketParams::~HttpProxySocketParams() = default;

std::unique_ptr<HttpProxyConnectJob> HttpProxyConnectJob::Factory::Create(
    RequestPriority priority,
    const SocketTag& socket_tag,
    const CommonConnectJobParams* common_connect_job_params,
    scoped_refptr<HttpProxySocketParams> params,
    ConnectJob::Delegate* delegate,
    const NetLogWithSource* net_log) {
  return std::make_unique<HttpProxyConnectJob>(
      priority, socket_tag, common_connect_job_params, std::move(params),
      delegate, net_log);
}

HttpProxyConnectJob::HttpProxyConnectJob(
    RequestPriority priority,
    const SocketTag& socket_tag,
    const CommonConnectJobParams* common_connect_job_params,
    scoped_refptr<HttpProxySocketParams> params,
    ConnectJob::Delegate* delegate,
    const NetLogWithSource* net_log)
    : ConnectJob(priority,
                 socket_tag,
                 base::TimeDelta() /* The socket takes care of timeouts */,
                 common_connect_job_params,
                 delegate,
                 net_log,
                 NetLogSourceType::HTTP_PROXY_CONNECT_JOB,
                 NetLogEventType::HTTP_PROXY_CONNECT_JOB_CONNECT),
      params_(std::move(params)),
      http_auth_controller_(
          params_->tunnel()
              ? base::MakeRefCounted<HttpAuthController>(
                    HttpAuth::AUTH_PROXY,
                    MakeProxyUrl(*params_),
                    params_->network_anonymization_key(),
                    common_connect_job_params->http_auth_cache,
                    common_connect_job_params->http_auth_handler_factory,
                    host_resolver())
              : nullptr) {}

HttpProxyConnectJob::~HttpProxyConnectJob() = default;

const RequestPriority HttpProxyConnectJob::kH2QuicTunnelPriority =
    DEFAULT_PRIORITY;

LoadState HttpProxyConnectJob::GetLoadState() const {
  switch (next_state_) {
    case STATE_TRANSPORT_CONNECT_COMPLETE:
      return nested_connect_job_->GetLoadState();
    case STATE_HTTP_PROXY_CONNECT:
    case STATE_HTTP_PROXY_CONNECT_COMPLETE:
    case STATE_SPDY_PROXY_CREATE_STREAM:
    case STATE_SPDY_PROXY_CREATE_STREAM_COMPLETE:
    case STATE_QUIC_PROXY_CREATE_SESSION:
    case STATE_QUIC_PROXY_CREATE_STREAM:
    case STATE_QUIC_PROXY_CREATE_STREAM_COMPLETE:
    case STATE_RESTART_WITH_AUTH:
    case STATE_RESTART_WITH_AUTH_COMPLETE:
      return LOAD_STATE_ESTABLISHING_PROXY_TUNNEL;
    // This state shouldn't be possible to be called in.
    case STATE_TRANSPORT_CONNECT:
      NOTREACHED();
    case STATE_BEGIN_CONNECT:
    case STATE_NONE:
      // May be possible for this method to be called after an error, shouldn't
      // be called after a successful connect.
      break;
  }
  return LOAD_STATE_IDLE;
}

bool HttpProxyConnectJob::HasEstablishedConnection() const {
  if (has_established_connection_) {
    return true;
  }

  // It's possible the nested connect job has established a connection, but
  // hasn't completed yet (For example, an SSLConnectJob may be negotiating
  // SSL).
  if (nested_connect_job_) {
    return nested_connect_job_->HasEstablishedConnection();
  }
  return false;
}

ResolveErrorInfo HttpProxyConnectJob::GetResolveErrorInfo() const {
  return resolve_error_info_;
}

bool HttpProxyConnectJob::IsSSLError() const {
  return ssl_cert_request_info_ != nullptr;
}

scoped_refptr<SSLCertRequestInfo> HttpProxyConnectJob::GetCertRequestInfo() {
  return ssl_cert_request_info_;
}

void HttpProxyConnectJob::OnConnectJobComplete(int result, ConnectJob* job) {
  DCHECK_EQ(nested_connect_job_.get(), job);
  DCHECK_EQ(next_state_, STATE_TRANSPORT_CONNECT_COMPLETE);
  OnIOComplete(result);
}

void HttpProxyConnectJob::OnNeedsProxyAuth(
    const HttpResponseInfo& response,
    HttpAuthController* auth_controller,
    base::OnceClosure restart_with_auth_callback,
    ConnectJob* job) {
  // None of the nested ConnectJob used by this class can encounter auth
  // challenges. Instead, the challenges are returned by the ProxyClientSocket
  // implementations after nested_connect_job_ has already established a
  // connection.
  NOTREACHED();
}

base::TimeDelta HttpProxyConnectJob::AlternateNestedConnectionTimeout(
    const HttpProxySocketParams& params,
    const NetworkQualityEstimator* network_quality_estimator) {
  base::TimeDelta default_alternate_timeout;

  // On Android and iOS, a default proxy connection timeout is used instead of
  // the actual TCP/SSL timeouts of nested jobs.
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
  default_alternate_timeout = kHttpProxyConnectJobTunnelTimeout;
#endif  // !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)

  bool is_https = params.proxy_server().is_https();

  if (!network_quality_estimator) {
    return default_alternate_timeout;
  }

  std::optional<base::TimeDelta> http_rtt_estimate =
      network_quality_estimator->GetHttpRTT();
  if (!http_rtt_estimate) {
    return default_alternate_timeout;
  }

  int32_t multiplier =
      is_https ? GetProxyTimeoutExperiments()->ssl_http_rtt_multiplier()
               : GetProxyTimeoutExperiments()->non_ssl_http_rtt_multiplier();
  base::TimeDelta timeout = multiplier * http_rtt_estimate.value();
  // Ensure that connection timeout is between
  // |min_proxy_connection_timeout_| and |max_proxy_connection_timeout_|.
  return std::clamp(
      timeout, GetProxyTimeoutExperiments()->min_proxy_connection_timeout(),
      GetProxyTimeoutExperiments()->max_proxy_connection_timeout());
}

base::TimeDelta HttpProxyConnectJob::TunnelTimeoutForTesting() {
  return kHttpProxyConnectJobTunnelTimeout;
}

void HttpProxyConnectJob::UpdateFieldTrialParametersForTesting() {
  GetProxyTimeoutExperiments()->Init();
}

int HttpProxyConnectJob::ConnectInternal() {
  DCHECK_EQ(next_state_, STATE_NONE);
  next_state_ = STATE_BEGIN_CONNECT;
  return DoLoop(OK);
}

ProxyServer::Scheme HttpProxyConnectJob::GetProxyServerScheme() const {
  return params_->proxy_server().scheme();
}

void HttpProxyConnectJob::OnIOComplete(int result) {
  int rv = DoLoop(result);
  if (rv != ERR_IO_PENDING) {
    // May delete |this|.
    NotifyDelegateOfCompletion(rv);
  }
}

void HttpProxyConnectJob::RestartWithAuthCredentials() {
  DCHECK(transport_socket_);
  DCHECK_EQ(STATE_NONE, next_state_);

  // Always do this asynchronously, to avoid re-entrancy.
  next_state_ = STATE_RESTART_WITH_AUTH;
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&HttpProxyConnectJob::OnIOComplete,
                                weak_ptr_factory_.GetWeakPtr(), OK));
}

int HttpProxyConnectJob::DoLoop(int result) {
  DCHECK_NE(next_state_, STATE_NONE);

  int rv = result;
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_BEGIN_CONNECT:
        DCHECK_EQ(OK, rv);
        rv = DoBeginConnect();
        break;
      case STATE_TRANSPORT_CONNECT:
        DCHECK_EQ(OK, rv);
        rv = DoTransportConnect();
        break;
      case STATE_TRANSPORT_CONNECT_COMPLETE:
        rv = DoTransportConnectComplete(rv);
        break;
      case STATE_HTTP_PROXY_CONNECT:
        DCHECK_EQ(OK, rv);
        rv = DoHttpProxyConnect();
        break;
      case STATE_HTTP_PROXY_CONNECT_COMPLETE:
        rv = DoHttpProxyConnectComplete(rv);
        break;
      case STATE_SPDY_PROXY_CREATE_STREAM:
        DCHECK_EQ(OK, rv);
        rv = DoSpdyProxyCreateStream();
        break;
      case STATE_SPDY_PROXY_CREATE_STREAM_COMPLETE:
        rv = DoSpdyProxyCreateStreamComplete(rv);
        break;
      case STATE_QUIC_PROXY_CREATE_SESSION:
        DCHECK_EQ(OK, rv);
        rv = DoQuicProxyCreateSession();
        break;
      case STATE_QUIC_PROXY_CREATE_STREAM:
        rv = DoQuicProxyCreateStream(rv);
        break;
      case STATE_QUIC_PROXY_CREATE_STREAM_COMPLETE:
        rv = DoQuicProxyCreateStreamComplete(rv);
        break;
      case STATE_RESTART_WITH_AUTH:
        DCHECK_EQ(OK, rv);
        rv = DoRestartWithAuth();
        break;
      case STATE_RESTART_WITH_AUTH_COMPLETE:
        rv = DoRestartWithAuthComplete(rv);
        break;
      default:
        NOTREACHED() << "bad state";
    }
  } while (rv != ERR_IO_PENDING && next_state_ != STATE_NONE);

  return rv;
}

int HttpProxyConnectJob::DoBeginConnect() {
  connect_start_time_ = base::TimeTicks::Now();
  ResetTimer(
      AlternateNestedConnectionTimeout(*params_, network_quality_estimator()));
  switch (GetProxyServerScheme()) {
    case ProxyServer::SCHEME_QUIC:
      next_state_ = STATE_QUIC_PROXY_CREATE_SESSION;
      // QUIC connections are always considered to have been established.
      // |has_established_connection_| is only used to start retries if a
      // connection hasn't been established yet, and QUIC has its own connection
      // establishment logic.
      has_established_connection_ = true;
      break;
    case ProxyServer::SCHEME_HTTP:
    case ProxyServer::SCHEME_HTTPS:
      next_state_ = STATE_TRANSPORT_CONNECT;
      break;
    default:
      NOTREACHED();
  }
  return OK;
}

int HttpProxyConnectJob::DoTransportConnect() {
  ProxyServer::Scheme scheme = GetProxyServerScheme();
  if (scheme == ProxyServer::SCHEME_HTTP) {
    nested_connect_job_ = std::make_unique<TransportConnectJob>(
        priority(), socket_tag(), common_connect_job_params(),
        params_->transport_params(), this, &net_log());
  } else {
    DCHECK_EQ(scheme, ProxyServer::SCHEME_HTTPS);
    DCHECK(params_->is_over_ssl());
    // Skip making a new connection if we have an existing HTTP/2 session.
    if (params_->tunnel() &&
        common_connect_job_params()->spdy_session_pool->FindAvailableSession(
            CreateSpdySessionKey(), /*enable_ip_based_pooling=*/false,
            /*is_websocket=*/false, net_log())) {
      next_state_ = STATE_SPDY_PROXY_CREATE_STREAM;
      return OK;
    }

    nested_connect_job_ = std::make_unique<SSLConnectJob>(
        priority(), socket_tag(), common_connect_job_params(),
        params_->ssl_params(), this, &net_log());
  }

  next_state_ = STATE_TRANSPORT_CONNECT_COMPLETE;
  return nested_connect_job_->Connect();
}

int HttpProxyConnectJob::DoTransportConnectComplete(int result) {
  resolve_error_info_ = nested_connect_job_->GetResolveErrorInfo();
  ProxyServer::Scheme scheme = GetProxyServerScheme();
  if (result != OK) {
    // Only record latency for connections to the first proxy in a chain.
    if (params_->proxy_chain_index() == 0) {
      EmitConnectLatency(NextProto::kProtoUnknown,
                         params_->proxy_server().scheme(),
                         HttpConnectResult::kError,
                         base::TimeTicks::Now() - connect_start_time_);
    }

    if (IsCertificateError(result)) {
      DCHECK_EQ(ProxyServer::SCHEME_HTTPS, scheme);
      // TODO(rch): allow the user to deal with proxy cert errors in the
      // same way as server cert errors.
      return ERR_PROXY_CERTIFICATE_INVALID;
    }

    if (result == ERR_SSL_CLIENT_AUTH_CERT_NEEDED) {
      DCHECK_EQ(ProxyServer::SCHEME_HTTPS, scheme);
      ssl_cert_request_info_ = nested_connect_job_->GetCertRequestInfo();
      if (params_->proxy_chain().is_multi_proxy() && !ssl_cert_request_info_) {
        // When multi-proxy chains are in use, it's possible that a client auth
        // cert is requested by the first proxy after the transport connection
        // to it has been established. When this occurs,
        // ERR_SSL_CLIENT_AUTH_CERT_NEEDED will get passed back to the parent
        // SSLConnectJob and then to the parent HttpProxyConnectJob, but the SSL
        // cert request info won't have been set up for the parent
        // HttpProxyConnectJob to use it in this method. Fail gracefully when
        // this case is encountered.
        // TODO(crbug.com/40284947): Investigate whether changes are
        // needed to support making the SSL cert request info available here in
        // the case described above. Just returning `result` here makes the
        // behavior for multi-proxy chains match that of single-proxy chains
        // (where the proxied request fails with ERR_SSL_CLIENT_AUTH_CERT_NEEDED
        // and no `SSLCertRequestInfo` is available from the corresponding
        // `ResponseInfo`), though, so it could be that no further action is
        // needed here.
        return result;
      }
      DCHECK(ssl_cert_request_info_);
      ssl_cert_request_info_->is_proxy = true;
      return result;
    }

    // If this transport connection was attempting to be made through other
    // proxies, prefer to propagate errors from attempting to establish the
    // previous proxy connection(s) instead of returning
    // `ERR_PROXY_CONNECTION_FAILED`. For instance, if the attempt to connect to
    // the first proxy resulted in `ERR_PROXY_HTTP_1_1_REQUIRED`, return that so
    // that the whole job will be restarted using HTTP/1.1.
    if (params_->proxy_chain_index() != 0) {
      return result;
    }

    return ERR_PROXY_CONNECTION_FAILED;
  }

  NextProto next_proto = nested_connect_job_->socket()->GetNegotiatedProtocol();
  // Only record latency for connections to the first proxy in a chain.
  if (params_->proxy_chain_index() == 0) {
    EmitConnectLatency(next_proto, params_->proxy_server().scheme(),
                       HttpConnectResult::kSuccess,
                       base::TimeTicks::Now() - connect_start_time_);
  }
  has_established_connection_ = true;

  if (!params_->tunnel()) {
    // If not tunneling, this is an HTTP URL being fetched directly over the
    // proxy. Return the underlying socket directly. The caller will handle the
    // ALPN protocol, etc., from here. Clear the DNS aliases to match the other
    // proxy codepaths.
    SetSocket(nested_connect_job_->PassSocket(),
              /*dns_aliases=*/std::set<std::string>());
    return result;
  }

  // Establish a tunnel over the proxy by making a CONNECT request. HTTP/1.1 and
  // HTTP/2 handle CONNECT differently.
  if (next_proto == kProtoHTTP2) {
    DCHECK_EQ(ProxyServer::SCHEME_HTTPS, scheme);
    next_state_ = STATE_SPDY_PROXY_CREATE_STREAM;
  } else {
    next_state_ = STATE_HTTP_PROXY_CONNECT;
  }
  return result;
}

int HttpProxyConnectJob::DoHttpProxyConnect() {
  DCHECK(params_->tunnel());
  next_state_ = STATE_HTTP_PROXY_CONNECT_COMPLETE;

  // Reset the timer to just the length of time allowed for HttpProxy handshake
  // so that a fast TCP connection plus a slow HttpProxy failure doesn't take
  // longer to timeout than it should.
  ResetTimer(kHttpProxyConnectJobTunnelTimeout);

  // Add a HttpProxy connection on top of the tcp socket.
  transport_socket_ = std::make_unique<HttpProxyClientSocket>(
      nested_connect_job_->PassSocket(), GetUserAgent(), params_->endpoint(),
      params_->proxy_chain(), params_->proxy_chain_index(),
      http_auth_controller_, common_connect_job_params()->proxy_delegate,
      params_->traffic_annotation());
  nested_connect_job_.reset();
  return transport_socket_->Connect(base::BindOnce(
      &HttpProxyConnectJob::OnIOComplete, base::Unretained(this)));
}

int HttpProxyConnectJob::DoHttpProxyConnectComplete(int result) {
  // Always inform caller of auth requests asynchronously.
  if (result == ERR_PROXY_AUTH_REQUESTED) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&HttpProxyConnectJob::OnAuthChallenge,
                                  weak_ptr_factory_.GetWeakPtr()));
    return ERR_IO_PENDING;
  }

  if (result == ERR_HTTP_1_1_REQUIRED) {
    return ERR_PROXY_HTTP_1_1_REQUIRED;
  }

  // In TLS 1.2 with False Start or TLS 1.3, alerts from the server rejecting
  // our client certificate are received at the first Read(), not Connect(), so
  // the error mapping in DoTransportConnectComplete does not apply. Repeat the
  // mapping here.
  if (result == ERR_BAD_SSL_CLIENT_AUTH_CERT) {
    return ERR_PROXY_CONNECTION_FAILED;
  }

  if (result == OK) {
    SetSocket(std::move(transport_socket_), /*dns_aliases=*/std::nullopt);
  }

  return result;
}

int HttpProxyConnectJob::DoSpdyProxyCreateStream() {
  DCHECK(params_->tunnel());
  DCHECK(params_->is_over_ssl());

  // Reset the timer to just the length of time allowed for HttpProxy handshake
  // so that a fast TCP connection plus a slow HttpProxy failure doesn't take
  // longer to timeout than it should.
  ResetTimer(kHttpProxyConnectJobTunnelTimeout);

  SpdySessionKey key = CreateSpdySessionKey();
  base::WeakPtr<SpdySession> spdy_session =
      common_connect_job_params()->spdy_session_pool->FindAvailableSession(
          key, /* enable_ip_based_pooling = */ false,
          /* is_websocket = */ false, net_log());
  // It's possible that a session to the proxy has recently been created
  if (spdy_session) {
    nested_connect_job_.reset();
  } else {
    // Create a session direct to the proxy itself
    base::expected<base::WeakPtr<SpdySession>, int> spdy_session_result =
        common_connect_job_params()
            ->spdy_session_pool->CreateAvailableSessionFromSocket(
                key, nested_connect_job_->PassSocket(),
                nested_connect_job_->connect_timing(), net_log());
    nested_connect_job_.reset();
    if (!spdy_session_result.has_value()) {
      return spdy_session_result.error();
    }
    spdy_session = std::move(spdy_session_result.value());
  }

  next_state_ = STATE_SPDY_PROXY_CREATE_STREAM_COMPLETE;
  spdy_stream_request_ = std::make_unique<SpdyStreamRequest>();
  return spdy_stream_request_->StartRequest(
      SPDY_BIDIRECTIONAL_STREAM, spdy_session,
      GURL("https://" + params_->endpoint().ToString()),
      false /* no early data */, kH2QuicTunnelPriority, socket_tag(),
      spdy_session->net_log(),
      base::BindOnce(&HttpProxyConnectJob::OnIOComplete,
                     base::Unretained(this)),
      params_->traffic_annotation());
}

int HttpProxyConnectJob::DoSpdyProxyCreateStreamComplete(int result) {
  if (result < 0) {
    // See the comment in DoHttpProxyConnectComplete(). HTTP/2 proxies will
    // typically also fail here, as a result of SpdyProxyClientSocket::Connect()
    // below, but the error may surface out of SpdyStreamRequest if there were
    // enough requests in parallel that stream creation became asynchronous.
    if (result == ERR_BAD_SSL_CLIENT_AUTH_CERT) {
      result = ERR_PROXY_CONNECTION_FAILED;
    }

    spdy_stream_request_.reset();
    return result;
  }

  next_state_ = STATE_HTTP_PROXY_CONNECT_COMPLETE;
  base::WeakPtr<SpdyStream> stream = spdy_stream_request_->ReleaseStream();
  spdy_stream_request_.reset();
  DCHECK(stream.get());
  // |transport_socket_| will set itself as |stream|'s delegate.
  transport_socket_ = std::make_unique<SpdyProxyClientSocket>(
      stream, params_->proxy_chain(), params_->proxy_chain_index(),
      GetUserAgent(), params_->endpoint(), net_log(), http_auth_controller_,
      common_connect_job_params()->proxy_delegate);
  return transport_socket_->Connect(base::BindOnce(
      &HttpProxyConnectJob::OnIOComplete, base::Unretained(this)));
}

int HttpProxyConnectJob::DoQuicProxyCreateSession() {
  DCHECK(params_->tunnel());
  DCHECK(!common_connect_job_params()->quic_supported_versions->empty());
  const SSLConfig& ssl_config = params_->quic_ssl_config().value();

  // Reset the timer to just the length of time allowed for HttpProxy handshake
  // so that a fast QUIC connection plus a slow tunnel setup doesn't take longer
  // to timeout than it should.
  ResetTimer(kHttpProxyConnectJobTunnelTimeout);

  next_state_ = STATE_QUIC_PROXY_CREATE_STREAM;
  const HostPortPair& proxy_server = params_->proxy_server().host_port_pair();
  quic_session_request_ = std::make_unique<QuicSessionRequest>(
      common_connect_job_params()->quic_session_pool);

  // Select the default QUIC version for the session to the proxy, since there
  // is no DNS or Alt-Svc information to use.
  quic::ParsedQuicVersion quic_version = SupportedQuicVersionForProxying();

  // The QuicSessionRequest will handle connecting to any proxies earlier in the
  // chain to this one, but expects a ProxyChain containing only QUIC proxies.
  ProxyChain quic_proxies =
      params_->proxy_chain().Prefix(params_->proxy_chain_index());

  // The ConnectJobParamsFactory ensures that this prefix is all QUIC proxies.
  for (const ProxyServer& ps : quic_proxies.proxy_servers()) {
    CHECK(ps.is_quic());
  }

  return quic_session_request_->Request(
      // TODO(crbug.com/40181080) Pass the destination directly once it's
      // converted to contain scheme.
      url::SchemeHostPort(url::kHttpsScheme, proxy_server.host(),
                          proxy_server.port()),
      quic_version, quic_proxies, params_->traffic_annotation(),
      http_user_agent_settings(), SessionUsage::kProxy, ssl_config.privacy_mode,
      kH2QuicTunnelPriority, socket_tag(), params_->network_anonymization_key(),
      params_->secure_dns_policy(),
      /*require_dns_https_alpn=*/false, ssl_config.GetCertVerifyFlags(),
      GURL("https://" + proxy_server.ToString()), net_log(),
      &quic_net_error_details_, MultiplexedSessionCreationInitiator::kUnknown,
      /*failed_on_default_network_callback=*/CompletionOnceCallback(),
      base::BindOnce(&HttpProxyConnectJob::OnIOComplete,
                     base::Unretained(this)));
}

int HttpProxyConnectJob::DoQuicProxyCreateStream(int result) {
  if (result < 0) {
    quic_session_request_.reset();
    return result;
  }

  next_state_ = STATE_QUIC_PROXY_CREATE_STREAM_COMPLETE;
  quic_session_ = quic_session_request_->ReleaseSessionHandle();
  quic_session_request_.reset();

  return quic_session_->RequestStream(
      false,
      base::BindOnce(&HttpProxyConnectJob::OnIOComplete,
                     base::Unretained(this)),
      params_->traffic_annotation());
}

int HttpProxyConnectJob::DoQuicProxyCreateStreamComplete(int result) {
  if (result < 0) {
    return result;
  }

  next_state_ = STATE_HTTP_PROXY_CONNECT_COMPLETE;
  std::unique_ptr<QuicChromiumClientStream::Handle> quic_stream =
      quic_session_->ReleaseStream();

  uint8_t urgency = ConvertRequestPriorityToQuicPriority(kH2QuicTunnelPriority);
  quic_stream->SetPriority(quic::QuicStreamPriority(
      quic::HttpStreamPriority{urgency, kDefaultPriorityIncremental}));

  transport_socket_ = std::make_unique<QuicProxyClientSocket>(
      std::move(quic_stream), std::move(quic_session_), params_->proxy_chain(),
      params_->proxy_chain_index(), GetUserAgent(), params_->endpoint(),
      net_log(), http_auth_controller_,
      common_connect_job_params()->proxy_delegate);
  return transport_socket_->Connect(base::BindOnce(
      &HttpProxyConnectJob::OnIOComplete, base::Unretained(this)));
}

int HttpProxyConnectJob::DoRestartWithAuth() {
  DCHECK(transport_socket_);

  // Start the timeout timer again.
  ResetTimer(kHttpProxyConnectJobTunnelTimeout);

  next_state_ = STATE_RESTART_WITH_AUTH_COMPLETE;
  return transport_socket_->RestartWithAuth(base::BindOnce(
      &HttpProxyConnectJob::OnIOComplete, base::Unretained(this)));
}

int HttpProxyConnectJob::DoRestartWithAuthComplete(int result) {
  DCHECK_NE(ERR_IO_PENDING, result);

  if (result == OK && !transport_socket_->IsConnected()) {
    result = ERR_UNABLE_TO_REUSE_CONNECTION_FOR_PROXY_AUTH;
  }

  // If the connection could not be reused to attempt to send proxy auth
  // credentials, try reconnecting. Do not reset the HttpAuthController in this
  // case; the server may, for instance, send "Proxy-Connection: close" and
  // expect that each leg of the authentication progress on separate
  // connections.
  bool reconnect = result == ERR_UNABLE_TO_REUSE_CONNECTION_FOR_PROXY_AUTH;

  // If auth credentials were sent but the connection was closed, the server may
  // have timed out while the user was selecting credentials. Retry once.
  if (!has_restarted_ &&
      (result == ERR_CONNECTION_CLOSED || result == ERR_CONNECTION_RESET ||
       result == ERR_CONNECTION_ABORTED ||
       result == ERR_SOCKET_NOT_CONNECTED)) {
    reconnect = true;
    has_restarted_ = true;

    // Release any auth state bound to the connection. The new connection will
    // start the current scheme and identity from scratch.
    if (http_auth_controller_) {
      http_auth_controller_->OnConnectionClosed();
    }
  }
```