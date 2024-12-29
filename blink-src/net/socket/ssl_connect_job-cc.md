Response:
Let's break down the request and the provided code to construct the response.

**1. Understanding the Core Task:**

The main goal is to analyze `ssl_connect_job.cc` and explain its purpose, its relation to JavaScript (if any), its internal logic, potential user errors, and how a user's actions might lead to this code being executed.

**2. Initial Code Scan and Key Components:**

My first read-through of the code highlighted these key elements:

* **`SSLConnectJob` Class:** The central entity. It seems responsible for establishing secure connections (HTTPS).
* **Nested Connect Jobs:**  The code uses `TransportConnectJob`, `SOCKSConnectJob`, and `HttpProxyConnectJob`. This suggests that establishing an SSL connection can involve different underlying connection types.
* **States (Enum `State`):**  A clear state machine governs the connection process.
* **Callbacks (`OnIOComplete`, `OnConnectJobComplete`):**  Asynchronous operations are managed using callbacks.
* **SSL Handshake:** The `STATE_SSL_CONNECT` and `STATE_SSL_CONNECT_COMPLETE` states clearly indicate the SSL/TLS handshake.
* **`SSLClientSocket`:**  This class is responsible for the actual SSL negotiation.
* **Error Handling:**  The code checks for various errors (e.g., `ERR_CONNECTION_CLOSED`, `ERR_SSL_PROTOCOL_ERROR`).
* **ECH (Encrypted Client Hello):**  The code has logic for handling ECH, including retries.
* **Metrics and Logging (`NetLogWithSource`):** The code interacts with Chromium's logging system.

**3. Functionality Deduction:**

Based on the code structure and names, I inferred the following functionalities:

* Orchestrating the SSL connection process.
* Handling different underlying connection types (direct, SOCKS proxy, HTTP proxy).
* Managing the SSL handshake.
* Handling SSL-related errors.
* Implementing retries (especially for ECH).
* Providing information about connection attempts and errors.
* Interacting with Chromium's network logging.

**4. JavaScript Relationship (Crucial Point):**

This is a C++ file in Chromium's network stack. It doesn't directly execute JavaScript. However, it's a *fundamental building block* for features JavaScript uses. I focused on this indirect relationship:

* **HTTPS Requests:**  JavaScript's `fetch` API or `XMLHttpRequest` are the primary ways web pages make network requests. When these requests are to `https://...` URLs, this C++ code will be involved.
* **Browser Security:**  The security established by this code is essential for protecting user data in web browsers.
* **Permissions and Errors:** JavaScript can be affected by connection failures or certificate errors handled by this code.

**5. Logical Reasoning (Input/Output):**

I considered the different paths through the state machine:

* **Direct Connection:** Input: Hostname/IP, port, SSL configuration. Output: Securely connected socket or an error.
* **Proxy Connections:** Input: Proxy server details, target hostname/IP, port, SSL configuration. Output: Securely connected socket via the proxy or an error.
* **ECH Retries:** Input: Initial connection attempt failure, ECH retry configurations. Output: Securely connected socket using the retry configurations or further errors.

**6. User/Programming Errors:**

I thought about common scenarios where things might go wrong:

* **Incorrect Proxy Settings:**  Users entering wrong proxy details.
* **Firewall Blocking:** Network firewalls interfering with connections.
* **Outdated Browsers:** Browsers not supporting the server's SSL/TLS version.
* **Certificate Issues:**  Invalid or expired certificates.
* **Incorrect ECH Configuration (less common for users):** While the user doesn't directly *configure* ECH, server-side misconfiguration or network issues can surface as errors.

**7. User Steps to Reach the Code (Debugging Context):**

I imagined a user scenario:

* User types an HTTPS address in the browser.
* The browser resolves the domain name.
* The browser needs to establish a secure connection.
* The `SSLConnectJob` is created to handle this.

I also considered proxy scenarios:

* User has configured a proxy.
* The browser first connects to the proxy.
* Then, the `SSLConnectJob` establishes the secure connection *through* the proxy.

**8. Structuring the Response:**

I organized the information into the requested categories:

* **Functionality:**  A concise summary of what the code does.
* **JavaScript Relationship:** Explaining the *indirect* link through web APIs.
* **Logical Reasoning:** Providing concrete input/output examples for different scenarios.
* **User/Programming Errors:** Listing common mistakes and their causes.
* **User Steps (Debugging):**  Tracing how a user action triggers this code.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Perhaps focus on the direct C++ API calls.
* **Correction:** Realized the user's perspective is key. The link to JavaScript is through high-level APIs.
* **Initial thought:**  List every possible error code.
* **Correction:** Focused on common and understandable user errors.
* **Initial thought:** Explain all the technical details of SSL/TLS.
* **Correction:**  Kept the explanation focused on the `SSLConnectJob`'s role within that broader process. Avoided going deep into the intricacies of TLS handshakes unless directly relevant to the code's behavior.

By following this thought process, I aimed to provide a comprehensive yet understandable explanation of the `ssl_connect_job.cc` file, addressing all aspects of the prompt.
这个文件 `net/socket/ssl_connect_job.cc` 是 Chromium 网络栈中负责建立安全连接 (HTTPS) 的核心组件。它的主要功能是管理 SSL/TLS 握手过程，并根据需要处理不同的底层连接类型（例如，直接连接、通过 HTTP 代理或 SOCKS 代理）。

以下是该文件的详细功能列表：

**主要功能:**

1. **协调 SSL/TLS 连接建立:** `SSLConnectJob` 类负责 orchestrating整个 SSL/TLS 连接的建立过程。它是一个状态机，通过不同的状态来管理握手的各个阶段。

2. **处理不同的底层连接:**
   - **直接连接:** 如果是直接连接到目标服务器，它会使用 `TransportConnectJob` 来建立底层的 TCP 连接。
   - **HTTP 代理:** 如果需要通过 HTTP 代理连接，它会使用 `HttpProxyConnectJob` 来建立到代理的连接，并执行 `CONNECT` 方法建立隧道。
   - **SOCKS 代理:** 如果需要通过 SOCKS 代理连接，它会使用 `SOCKSConnectJob` 来建立到代理的连接。

3. **执行 SSL/TLS 握手:**  在底层连接建立后，`SSLConnectJob` 会创建 `SSLClientSocket` 对象，并调用其 `Connect()` 方法来执行 SSL/TLS 握手。

4. **处理 SSL/TLS 相关的错误:**  它会处理握手过程中可能出现的各种错误，例如连接被关闭、协议错误、版本不匹配、证书错误等。

5. **处理客户端证书认证:** 如果服务器要求客户端提供证书，`SSLConnectJob` 会获取证书请求信息 (`SSLCertRequestInfo`) 并将其传递给上层。

6. **支持 Encrypted Client Hello (ECH):**  代码包含了处理 ECH 的逻辑，包括初始连接尝试和使用服务器提供的重试配置进行重试。

7. **记录连接尝试和错误信息:** 它会记录连接尝试的地址和结果，以及解析错误信息。

8. **集成到 Chromium 的 NetLog 系统:**  `SSLConnectJob` 使用 Chromium 的 NetLog 系统来记录连接过程中的各种事件，用于调试和分析。

9. **管理连接超时:** 它设置 SSL 握手阶段的超时时间。

**与 JavaScript 功能的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它是浏览器处理 HTTPS 请求的关键部分，而 HTTPS 是现代 Web 的基础。当 JavaScript 代码（例如，通过 `fetch` API 或 `XMLHttpRequest`）发起一个到 `https://` 开头的 URL 的请求时，Chromium 的网络栈最终会使用 `SSLConnectJob` 来建立与服务器的安全连接。

**举例说明:**

假设一个 JavaScript 脚本尝试从 `https://example.com` 获取数据：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中，用户浏览器的网络栈会经历以下步骤（简化）：

1. **域名解析:** 浏览器首先会解析 `example.com` 的 IP 地址。
2. **建立 TCP 连接:**  根据网络配置，可能会直接连接，也可能通过代理服务器连接。如果直接连接，则会创建一个 `TransportConnectJob`。如果需要通过代理，则会创建 `HttpProxyConnectJob` 或 `SOCKSConnectJob`。
3. **创建 SSLConnectJob:** 一旦底层的 TCP 连接建立，或者通过代理建立了隧道，就会创建一个 `SSLConnectJob` 来处理与 `example.com` 服务器的 SSL/TLS 握手。
4. **执行 SSL 握手:** `SSLConnectJob` 会使用 `SSLClientSocket` 与服务器进行密钥交换、身份验证等操作，最终建立加密连接。
5. **发送 HTTP 请求:**  一旦安全连接建立，浏览器就可以通过该连接发送实际的 HTTP 请求来获取 `data.json`。
6. **接收 HTTP 响应:** 服务器通过加密连接返回 `data.json` 的内容。
7. **JavaScript 处理数据:** 浏览器接收到响应后，JavaScript 代码才能处理返回的 JSON 数据。

**逻辑推理 (假设输入与输出):**

**场景 1: 直接连接到 HTTPS 服务器**

* **假设输入:**
    * `SSLSocketParams` 包含目标主机 `example.com:443`，SSL 配置信息。
    * 网络条件良好。
* **输出:**
    * 成功建立与 `example.com:443` 的安全连接。
    * `ssl_socket_` 成员变量指向一个可用的 `SSLClientSocket` 对象。
    * NetLog 中记录连接建立的各个阶段。

**场景 2: 通过 HTTP 代理连接到 HTTPS 服务器**

* **假设输入:**
    * `SSLSocketParams` 包含目标主机 `secure.example.com:443` 和 HTTP 代理服务器 `proxy.example.net:8080` 的信息。
    * 代理服务器运行正常。
* **输出:**
    * 先建立到 `proxy.example.net:8080` 的连接 (由 `HttpProxyConnectJob` 完成)。
    * 然后通过代理发送 `CONNECT secure.example.com:443` 请求，建立隧道。
    * 最终建立通过代理到 `secure.example.com:443` 的安全连接。

**场景 3: SSL 握手失败 (例如，证书错误)**

* **假设输入:**
    * `SSLSocketParams` 包含目标主机，但目标服务器的 SSL 证书无效（例如，过期、自签名）。
* **输出:**
    * `DoSSLConnectComplete` 函数会返回一个错误码，例如 `ERR_CERT_DATE_INVALID` 或 `ERR_CERT_AUTHORITY_INVALID`。
    * `NotifyDelegateOfCompletion` 会被调用，并将错误码传递给上层。
    * JavaScript 代码可能会收到一个网络错误，指示连接失败。

**用户或编程常见的使用错误 (举例说明):**

1. **错误的代理配置:** 用户在操作系统或浏览器中配置了错误的 HTTP 或 SOCKS 代理服务器地址或端口。
   - **后果:** `SSLConnectJob` 的前置步骤（`HttpProxyConnectJob` 或 `SOCKSConnectJob`）可能会失败，导致连接错误，用户可能会看到 "代理服务器无响应" 或类似的错误信息。

2. **防火墙阻止连接:** 用户的本地防火墙或网络防火墙阻止了到目标 HTTPS 服务器的 443 端口的连接。
   - **后果:** 底层的 TCP 连接建立失败，`TransportConnectJob` 可能会返回 `ERR_CONNECTION_REFUSED` 或 `ERR_CONNECTION_TIMED_OUT`，`SSLConnectJob` 也无法启动 SSL 握手。

3. **浏览器或操作系统时钟不准确:** SSL/TLS 握手依赖于时间同步。如果用户的计算机时钟严重不准确，可能会导致证书验证失败。
   - **后果:** `SSLConnectJob` 在执行证书验证时可能会失败，返回 `ERR_CERT_DATE_INVALID`，即使证书本身是有效的。

4. **服务器配置错误 (对用户而言是间接的):**  目标 HTTPS 服务器的 SSL/TLS 配置存在问题，例如不支持浏览器支持的协议版本或密码套件。
   - **Consequences:** `SSLConnectJob` 在 `DoSSLConnectComplete` 中可能会因为 `ERR_SSL_PROTOCOL_ERROR` 或 `ERR_SSL_VERSION_OR_CIPHER_MISMATCH` 而失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入一个 `https://` 开头的 URL 并按下回车键。**
2. **浏览器解析 URL，提取主机名和端口 (通常是 443)。**
3. **浏览器查找该主机名的 IP 地址 (DNS 查询)。**
4. **浏览器根据配置决定是否需要使用代理服务器。**
   - **如果不需要代理:**  浏览器创建一个 `TransportConnectJob` 来建立到目标服务器的 TCP 连接。
   - **如果需要代理:**
     - 对于 HTTP 代理，浏览器创建一个 `HttpProxyConnectJob` 来连接到代理服务器。
     - 对于 SOCKS 代理，浏览器创建一个 `SOCKSConnectJob` 来连接到代理服务器。
5. **一旦底层的 TCP 连接建立 (或者通过代理建立了隧道)，Chromium 的网络栈会创建一个 `SSLConnectJob` 对象。**
6. **`SSLConnectJob` 的 `Connect()` 方法被调用，启动连接过程。**
7. **`SSLConnectJob` 进入其状态机，根据底层连接类型执行相应的操作 (例如，直接跳到 `STATE_TRANSPORT_CONNECT_COMPLETE`，或者先执行代理连接相关的状态)。**
8. **最终，`SSLConnectJob` 进入 `STATE_SSL_CONNECT` 状态，创建 `SSLClientSocket` 并开始 SSL/TLS 握手。**
9. **在握手过程中，如果发生错误，`SSLConnectJob` 会记录错误信息并通过 NetLog 提供调试线索。**
10. **如果握手成功，`SSLConnectJob` 将建立的 `SSLClientSocket` 返回给上层，以便进行安全的 HTTP 通信。**
11. **如果握手失败，`SSLConnectJob` 会通知上层连接失败，并提供相应的错误码。**

因此，当你在调试一个 HTTPS 连接问题时，查看 NetLog 中 `SSL_CONNECT_JOB` 相关的事件，以及其前后的 `TRANSPORT_CONNECT_JOB`、`HTTP_PROXY_CONNECT_JOB` 或 `SOCKS_CONNECT_JOB` 的事件，可以帮助你理解连接建立的哪个阶段出现了问题。错误码和相关的详细信息可以帮助你定位问题的根源，例如是网络问题、代理配置问题还是 SSL/TLS 握手问题。

Prompt: 
```
这是目录为net/socket/ssl_connect_job.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/ssl_connect_job.h"

#include <cstdlib>
#include <memory>
#include <utility>

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "net/base/connection_endpoint_metadata.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_errors.h"
#include "net/base/trace_constants.h"
#include "net/base/tracing.h"
#include "net/base/url_util.h"
#include "net/cert/x509_util.h"
#include "net/http/http_proxy_connect_job.h"
#include "net/log/net_log_source_type.h"
#include "net/log/net_log_values.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/socks_connect_job.h"
#include "net/socket/ssl_client_socket.h"
#include "net/socket/transport_connect_job.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/ssl_info.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "third_party/boringssl/src/include/openssl/pool.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"

namespace net {

namespace {

// Timeout for the SSL handshake portion of the connect.
constexpr base::TimeDelta kSSLHandshakeTimeout(base::Seconds(30));

}  // namespace

SSLSocketParams::SSLSocketParams(
    ConnectJobParams nested_params,
    const HostPortPair& host_and_port,
    const SSLConfig& ssl_config,
    NetworkAnonymizationKey network_anonymization_key)
    : nested_params_(nested_params),
      host_and_port_(host_and_port),
      ssl_config_(ssl_config),
      network_anonymization_key_(network_anonymization_key) {
  CHECK(!nested_params_.is_ssl());
}

SSLSocketParams::~SSLSocketParams() = default;

SSLSocketParams::ConnectionType SSLSocketParams::GetConnectionType() const {
  if (nested_params_.is_socks()) {
    return SOCKS_PROXY;
  }
  if (nested_params_.is_http_proxy()) {
    return HTTP_PROXY;
  }
  return DIRECT;
}

std::unique_ptr<SSLConnectJob> SSLConnectJob::Factory::Create(
    RequestPriority priority,
    const SocketTag& socket_tag,
    const CommonConnectJobParams* common_connect_job_params,
    scoped_refptr<SSLSocketParams> params,
    ConnectJob::Delegate* delegate,
    const NetLogWithSource* net_log) {
  return std::make_unique<SSLConnectJob>(priority, socket_tag,
                                         common_connect_job_params,
                                         std::move(params), delegate, net_log);
}

SSLConnectJob::SSLConnectJob(
    RequestPriority priority,
    const SocketTag& socket_tag,
    const CommonConnectJobParams* common_connect_job_params,
    scoped_refptr<SSLSocketParams> params,
    ConnectJob::Delegate* delegate,
    const NetLogWithSource* net_log)
    : ConnectJob(
          priority,
          socket_tag,
          // The SSLConnectJob's timer is only started during the SSL handshake.
          base::TimeDelta(),
          common_connect_job_params,
          delegate,
          net_log,
          NetLogSourceType::SSL_CONNECT_JOB,
          NetLogEventType::SSL_CONNECT_JOB_CONNECT),
      params_(std::move(params)),
      callback_(base::BindRepeating(&SSLConnectJob::OnIOComplete,
                                    base::Unretained(this))) {}

SSLConnectJob::~SSLConnectJob() {
  // In the case the job was canceled, need to delete nested job first to
  // correctly order NetLog events.
  nested_connect_job_.reset();
}

LoadState SSLConnectJob::GetLoadState() const {
  switch (next_state_) {
    case STATE_TRANSPORT_CONNECT:
    case STATE_SOCKS_CONNECT:
    case STATE_TUNNEL_CONNECT:
      return LOAD_STATE_IDLE;
    case STATE_TRANSPORT_CONNECT_COMPLETE:
    case STATE_SOCKS_CONNECT_COMPLETE:
      return nested_connect_job_->GetLoadState();
    case STATE_TUNNEL_CONNECT_COMPLETE:
      if (nested_socket_) {
        return LOAD_STATE_ESTABLISHING_PROXY_TUNNEL;
      }
      return nested_connect_job_->GetLoadState();
    case STATE_SSL_CONNECT:
    case STATE_SSL_CONNECT_COMPLETE:
      return LOAD_STATE_SSL_HANDSHAKE;
    default:
      NOTREACHED();
  }
}

bool SSLConnectJob::HasEstablishedConnection() const {
  // If waiting on a nested ConnectJob, defer to that ConnectJob's state.
  if (nested_connect_job_) {
    return nested_connect_job_->HasEstablishedConnection();
  }
  // Otherwise, return true if a socket has been created.
  return nested_socket_ || ssl_socket_;
}

void SSLConnectJob::OnConnectJobComplete(int result, ConnectJob* job) {
  DCHECK_EQ(job, nested_connect_job_.get());
  OnIOComplete(result);
}

void SSLConnectJob::OnNeedsProxyAuth(
    const HttpResponseInfo& response,
    HttpAuthController* auth_controller,
    base::OnceClosure restart_with_auth_callback,
    ConnectJob* job) {
  DCHECK_EQ(next_state_, STATE_TUNNEL_CONNECT_COMPLETE);

  // The timer shouldn't have started running yet, since the handshake only
  // starts after a tunnel has been established through the proxy.
  DCHECK(!TimerIsRunning());

  // Just pass the callback up to the consumer. This class doesn't need to do
  // anything once credentials are provided.
  NotifyDelegateOfProxyAuth(response, auth_controller,
                            std::move(restart_with_auth_callback));
}

ConnectionAttempts SSLConnectJob::GetConnectionAttempts() const {
  return connection_attempts_;
}

ResolveErrorInfo SSLConnectJob::GetResolveErrorInfo() const {
  return resolve_error_info_;
}

bool SSLConnectJob::IsSSLError() const {
  return ssl_negotiation_started_;
}

scoped_refptr<SSLCertRequestInfo> SSLConnectJob::GetCertRequestInfo() {
  return ssl_cert_request_info_;
}

base::TimeDelta SSLConnectJob::HandshakeTimeoutForTesting() {
  return kSSLHandshakeTimeout;
}

void SSLConnectJob::OnIOComplete(int result) {
  int rv = DoLoop(result);
  if (rv != ERR_IO_PENDING) {
    NotifyDelegateOfCompletion(rv);  // Deletes |this|.
  }
}

int SSLConnectJob::DoLoop(int result) {
  TRACE_EVENT0(NetTracingCategory(), "SSLConnectJob::DoLoop");
  DCHECK_NE(next_state_, STATE_NONE);

  int rv = result;
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_TRANSPORT_CONNECT:
        DCHECK_EQ(OK, rv);
        rv = DoTransportConnect();
        break;
      case STATE_TRANSPORT_CONNECT_COMPLETE:
        rv = DoTransportConnectComplete(rv);
        break;
      case STATE_SOCKS_CONNECT:
        DCHECK_EQ(OK, rv);
        rv = DoSOCKSConnect();
        break;
      case STATE_SOCKS_CONNECT_COMPLETE:
        rv = DoSOCKSConnectComplete(rv);
        break;
      case STATE_TUNNEL_CONNECT:
        DCHECK_EQ(OK, rv);
        rv = DoTunnelConnect();
        break;
      case STATE_TUNNEL_CONNECT_COMPLETE:
        rv = DoTunnelConnectComplete(rv);
        break;
      case STATE_SSL_CONNECT:
        DCHECK_EQ(OK, rv);
        rv = DoSSLConnect();
        break;
      case STATE_SSL_CONNECT_COMPLETE:
        rv = DoSSLConnectComplete(rv);
        break;
      default:
        NOTREACHED() << "bad state";
    }
  } while (rv != ERR_IO_PENDING && next_state_ != STATE_NONE);

  return rv;
}

int SSLConnectJob::DoTransportConnect() {
  DCHECK(!nested_connect_job_);
  DCHECK(params_->GetDirectConnectionParams());
  DCHECK(!TimerIsRunning());

  next_state_ = STATE_TRANSPORT_CONNECT_COMPLETE;
  // If this is an ECH retry, connect to the same server as before.
  std::optional<TransportConnectJob::EndpointResultOverride>
      endpoint_result_override;
  if (ech_retry_configs_) {
    DCHECK(ssl_client_context()->config().ech_enabled);
    DCHECK(endpoint_result_);
    endpoint_result_override.emplace(*endpoint_result_, dns_aliases_);
  }
  nested_connect_job_ = std::make_unique<TransportConnectJob>(
      priority(), socket_tag(), common_connect_job_params(),
      params_->GetDirectConnectionParams(), this, &net_log(),
      std::move(endpoint_result_override));
  return nested_connect_job_->Connect();
}

int SSLConnectJob::DoTransportConnectComplete(int result) {
  resolve_error_info_ = nested_connect_job_->GetResolveErrorInfo();
  ConnectionAttempts connection_attempts =
      nested_connect_job_->GetConnectionAttempts();
  connection_attempts_.insert(connection_attempts_.end(),
                              connection_attempts.begin(),
                              connection_attempts.end());
  if (result == OK) {
    next_state_ = STATE_SSL_CONNECT;
    nested_socket_ = nested_connect_job_->PassSocket();
    nested_socket_->GetPeerAddress(&server_address_);
    dns_aliases_ = nested_socket_->GetDnsAliases();
  }

  return result;
}

int SSLConnectJob::DoSOCKSConnect() {
  DCHECK(!nested_connect_job_);
  DCHECK(params_->GetSocksProxyConnectionParams());
  DCHECK(!TimerIsRunning());

  next_state_ = STATE_SOCKS_CONNECT_COMPLETE;
  nested_connect_job_ = std::make_unique<SOCKSConnectJob>(
      priority(), socket_tag(), common_connect_job_params(),
      params_->GetSocksProxyConnectionParams(), this, &net_log());
  return nested_connect_job_->Connect();
}

int SSLConnectJob::DoSOCKSConnectComplete(int result) {
  resolve_error_info_ = nested_connect_job_->GetResolveErrorInfo();
  if (result == OK) {
    next_state_ = STATE_SSL_CONNECT;
    nested_socket_ = nested_connect_job_->PassSocket();
  }

  return result;
}

int SSLConnectJob::DoTunnelConnect() {
  DCHECK(!nested_connect_job_);
  DCHECK(params_->GetHttpProxyConnectionParams());
  DCHECK(!TimerIsRunning());

  next_state_ = STATE_TUNNEL_CONNECT_COMPLETE;
  nested_connect_job_ = std::make_unique<HttpProxyConnectJob>(
      priority(), socket_tag(), common_connect_job_params(),
      params_->GetHttpProxyConnectionParams(), this, &net_log());
  return nested_connect_job_->Connect();
}

int SSLConnectJob::DoTunnelConnectComplete(int result) {
  resolve_error_info_ = nested_connect_job_->GetResolveErrorInfo();
  nested_socket_ = nested_connect_job_->PassSocket();

  if (result < 0) {
    // Extract the information needed to prompt for appropriate proxy
    // authentication so that when ClientSocketPoolBaseHelper calls
    // |GetAdditionalErrorState|, we can easily set the state.
    if (result == ERR_SSL_CLIENT_AUTH_CERT_NEEDED) {
      ssl_cert_request_info_ = nested_connect_job_->GetCertRequestInfo();
    }
    return result;
  }

  next_state_ = STATE_SSL_CONNECT;
  return result;
}

int SSLConnectJob::DoSSLConnect() {
  TRACE_EVENT0(NetTracingCategory(), "SSLConnectJob::DoSSLConnect");
  DCHECK(!TimerIsRunning());

  next_state_ = STATE_SSL_CONNECT_COMPLETE;

  // Set the timeout to just the time allowed for the SSL handshake.
  ResetTimer(kSSLHandshakeTimeout);

  // Get the transport's connect start and DNS times.
  const LoadTimingInfo::ConnectTiming& socket_connect_timing =
      nested_connect_job_->connect_timing();

  // Overwriting |connect_start| serves two purposes - it adjusts timing so
  // |connect_start| doesn't include dns times, and it adjusts the time so
  // as not to include time spent waiting for an idle socket.
  connect_timing_.connect_start = socket_connect_timing.connect_start;
  connect_timing_.domain_lookup_start =
      socket_connect_timing.domain_lookup_start;
  connect_timing_.domain_lookup_end = socket_connect_timing.domain_lookup_end;

  ssl_negotiation_started_ = true;
  connect_timing_.ssl_start = base::TimeTicks::Now();

  // Save the `HostResolverEndpointResult`. `nested_connect_job_` is destroyed
  // at the end of this function.
  endpoint_result_ = nested_connect_job_->GetHostResolverEndpointResult();

  SSLConfig ssl_config = params_->ssl_config();
  ssl_config.ignore_certificate_errors =
      *common_connect_job_params()->ignore_certificate_errors;
  ssl_config.network_anonymization_key = params_->network_anonymization_key();

  if (ssl_client_context()->config().ech_enabled) {
    if (ech_retry_configs_) {
      ssl_config.ech_config_list = *ech_retry_configs_;
    } else if (endpoint_result_) {
      ssl_config.ech_config_list = endpoint_result_->metadata.ech_config_list;
    }
    if (!ssl_config.ech_config_list.empty()) {
      // Overriding the DNS lookup only works for direct connections. We
      // currently do not support ECH with other connection types.
      DCHECK_EQ(params_->GetConnectionType(), SSLSocketParams::DIRECT);
    }
  }

  ssl_socket_ = client_socket_factory()->CreateSSLClientSocket(
      ssl_client_context(), std::move(nested_socket_), params_->host_and_port(),
      ssl_config);
  nested_connect_job_.reset();
  return ssl_socket_->Connect(callback_);
}

int SSLConnectJob::DoSSLConnectComplete(int result) {
  connect_timing_.ssl_end = base::TimeTicks::Now();

  if (result != OK && !server_address_.address().empty()) {
    connection_attempts_.push_back(ConnectionAttempt(server_address_, result));
    server_address_ = IPEndPoint();
  }

  // Historically, many servers which negotiated SHA-1 server signatures in
  // TLS 1.2 actually support SHA-2 but preferentially sign SHA-1 if available.
  // In order to get accurate metrics while deprecating SHA-1, we initially
  // connected with SHA-1 disabled and then retried with enabled.
  //
  // SHA-1 is now always disabled, but we retained the fallback to separate the
  // effect of disabling SHA-1 from the effect of having a single automatic
  // retry on a potentially unreliably network connection.
  //
  // TODO(crbug.com/40085786): Remove this now redundant retry.
  if (disable_legacy_crypto_with_fallback_ &&
      (result == ERR_CONNECTION_CLOSED || result == ERR_CONNECTION_RESET ||
       result == ERR_SSL_PROTOCOL_ERROR ||
       result == ERR_SSL_VERSION_OR_CIPHER_MISMATCH)) {
    ResetStateForRestart();
    disable_legacy_crypto_with_fallback_ = false;
    next_state_ = GetInitialState(params_->GetConnectionType());
    return OK;
  }

  // We record metrics based on whether the server advertised ECH support in
  // DNS. This allows the metrics to measure the same set of servers in both
  // control and experiment group.
  const bool is_ech_capable =
      endpoint_result_ && !endpoint_result_->metadata.ech_config_list.empty();
  const bool ech_enabled = ssl_client_context()->config().ech_enabled;

  if (!ech_retry_configs_ && result == ERR_ECH_NOT_NEGOTIATED && ech_enabled) {
    // We used ECH, and the server could not decrypt the ClientHello. However,
    // it was able to handshake with the public name and send authenticated
    // retry configs. If this is not the first time around, retry the connection
    // with the new ECHConfigList, or with ECH disabled (empty retry configs),
    // as directed.
    //
    // See
    // https://www.ietf.org/archive/id/draft-ietf-tls-esni-13.html#section-6.1.6
    DCHECK(is_ech_capable);
    ech_retry_configs_ = ssl_socket_->GetECHRetryConfigs();
    net_log().AddEvent(
        NetLogEventType::SSL_CONNECT_JOB_RESTART_WITH_ECH_CONFIG_LIST, [&] {
          return base::Value::Dict().Set(
              "bytes", NetLogBinaryValue(*ech_retry_configs_));
        });

    ResetStateForRestart();
    next_state_ = GetInitialState(params_->GetConnectionType());
    return OK;
  }

  SSLClientSocket::RecordSSLConnectResult(ssl_socket_.get(), result,
                                          is_ech_capable, ech_enabled,
                                          ech_retry_configs_, connect_timing_);

  if (result == OK || IsCertificateError(result)) {
    SetSocket(std::move(ssl_socket_), std::move(dns_aliases_));
  } else if (result == ERR_SSL_CLIENT_AUTH_CERT_NEEDED) {
    ssl_cert_request_info_ = base::MakeRefCounted<SSLCertRequestInfo>();
    ssl_socket_->GetSSLCertRequestInfo(ssl_cert_request_info_.get());
  }

  return result;
}

SSLConnectJob::State SSLConnectJob::GetInitialState(
    SSLSocketParams::ConnectionType connection_type) {
  switch (connection_type) {
    case SSLSocketParams::DIRECT:
      return STATE_TRANSPORT_CONNECT;
    case SSLSocketParams::HTTP_PROXY:
      return STATE_TUNNEL_CONNECT;
    case SSLSocketParams::SOCKS_PROXY:
      return STATE_SOCKS_CONNECT;
  }
  NOTREACHED();
}

int SSLConnectJob::ConnectInternal() {
  next_state_ = GetInitialState(params_->GetConnectionType());
  return DoLoop(OK);
}

void SSLConnectJob::ResetStateForRestart() {
  ResetTimer(base::TimeDelta());
  nested_connect_job_ = nullptr;
  nested_socket_ = nullptr;
  ssl_socket_ = nullptr;
  ssl_cert_request_info_ = nullptr;
  ssl_negotiation_started_ = false;
  resolve_error_info_ = ResolveErrorInfo();
  server_address_ = IPEndPoint();
}

void SSLConnectJob::ChangePriorityInternal(RequestPriority priority) {
  if (nested_connect_job_) {
    nested_connect_job_->ChangePriority(priority);
  }
}

}  // namespace net

"""

```