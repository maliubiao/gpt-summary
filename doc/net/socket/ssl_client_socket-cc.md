Response:
Let's break down the thought process for analyzing this C++ code and answering the user's request.

**1. Understanding the Core Request:**

The user wants to understand the functionality of `ssl_client_socket.cc` within the Chromium networking stack. Specifically, they are interested in:

* **Functionality:** What does this file *do*?
* **Relationship to JavaScript:** How does this low-level C++ interact with high-level JavaScript?
* **Logic and I/O:** Can we infer inputs and outputs for specific logical sections?
* **Common Errors:** What mistakes do users or programmers make when interacting with this kind of code?
* **Debugging:** How would someone end up in this code during debugging?

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly read through the code, looking for key terms and patterns:

* **Headers:** `#include` statements indicate dependencies and high-level functionality. We see things like `net/socket/ssl_client_socket.h`, `net/ssl/...`, `net/log/...`, `base/metrics/...`. This immediately tells us we're dealing with SSL/TLS, sockets, logging, and performance metrics.
* **Namespaces:** `namespace net { ... }` confirms this is part of the networking stack.
* **Classes:** `SSLClientSocket`, `SSLClientContext`, `SSLClientSocketImpl`. This suggests a class hierarchy for managing SSL client connections.
* **Methods:**  Look for verbs. `RecordSSLConnectResult`, `SetSSLKeyLogger`, `SerializeNextProtos`, `CreateSSLClientSocket`, `GetClientCertificate`, `SetClientCertificate`, `ClearClientCertificate`, `AddObserver`, `RemoveObserver`, `OnSSLContextConfigChanged`, etc. These tell us what actions these classes perform.
* **Data Structures:** `HostPortPair`, `SSLConfig`, `SSLInfo`, `X509Certificate`, `SSLPrivateKey`, `NextProtoVector`. These are the data being manipulated.
* **Logging:**  `net::NetLog::Get()->AddGlobalEntry(...)` indicates logging of events.
* **Metrics:** `base::UmaHistogram...` shows collection of performance and error data.
* **Callbacks/Observers:** The `Observer` pattern is evident in `AddObserver` and `RemoveObserver`, suggesting event-driven behavior.
* **Caching:** `ssl_client_session_cache_`, `ssl_client_auth_cache_` point to caching mechanisms.

**3. Deeper Analysis of Key Sections:**

Now, let's zoom in on the more important parts:

* **`SSLClientSocket` (Base Class):** This appears to be an abstract interface. The static methods suggest utility functions.
* **`SSLClientSocket::RecordSSLConnectResult`:** This function is clearly responsible for logging the outcome of an SSL connection attempt, including metrics related to ECH (Encrypted Client Hello). It also tracks connection latency, SSL version, and cipher suite.
* **`SSLClientSocket::SerializeNextProtos`:** This deals with converting ALPN (Application-Layer Protocol Negotiation) protocol lists into a wire format.
* **`SSLClientContext`:** This class seems to manage the overall SSL client configuration and lifecycle. It holds references to key components like the certificate verifier, transport security state, and session cache. The methods for getting, setting, and clearing client certificates are crucial. The observer pattern here is used to notify components of configuration changes.

**4. Connecting to JavaScript:**

This is the trickiest part. We need to bridge the gap between low-level C++ and high-level JavaScript. The key is to think about *how* JavaScript in a browser interacts with the network:

* **`fetch()` API:** The most common way to make network requests.
* **`XMLHttpRequest`:**  The older API for making HTTP requests.
* **WebSockets:** For persistent, bidirectional connections.

These JavaScript APIs don't directly call these C++ functions. Instead, they go through layers of abstraction within the browser. The rendering engine (like Blink) will eventually delegate network requests to the network service (where this code lives). The connection is more indirect.

**Key Insight:** The `SSLClientSocket` is responsible for establishing the *secure* connection underlying those JavaScript requests. It's the engine that makes HTTPS possible.

**5. Inferring Logic, Inputs, and Outputs:**

For methods like `ClearClientCertificateIfNeeded` and `ClearMatchingClientCertificate`, we can reason about the inputs and outputs:

* **`ClearClientCertificateIfNeeded`:**
    * **Input:** A `HostPortPair` and a certificate.
    * **Logic:** Check if a *different* certificate is cached for that host. If so, clear the cache.
    * **Output:**  Potentially clears the cached client certificate and notifies observers.
* **`ClearMatchingClientCertificate`:**
    * **Input:** A certificate.
    * **Logic:** Iterate through all cached client certificates and clear those that match the input certificate (excluding the chain).
    * **Output:**  Potentially clears multiple cached client certificates and notifies observers.

**6. Identifying Common Errors:**

Think about common mistakes developers or users make related to SSL/TLS:

* **Incorrect SSL configuration:**  Misconfiguring certificates, private keys, or cipher suites on the server. This code doesn't *configure* the server, but it reacts to the server's configuration.
* **Certificate errors:** Expired certificates, self-signed certificates, hostname mismatch. The certificate verification logic (handled by `CertVerifier`) plays a role here.
* **Client certificate issues:** Not providing a required client certificate, providing an incorrect one. The caching mechanism in this code aims to help manage these.
* **Network connectivity problems:**  These are lower-level than SSL, but they can surface as SSL connection failures.

**7. Tracing User Actions for Debugging:**

Imagine a user experiencing an SSL error in their browser:

1. **User types a URL (HTTPS).**
2. **Browser initiates a network request.**
3. **The network service attempts to establish a TCP connection.**
4. **The `SSLClientSocket` is created to handle the TLS handshake.**
5. **Potential points of failure:**
    * **Certificate verification failure:**  The `CertVerifier` is involved.
    * **Handshake failure:** Issues with cipher suites, protocol versions, client certificates.
    * **Server errors:** The server might reject the connection.
6. **Developers might set breakpoints in `SSLClientSocketImpl::Connect()` (the concrete implementation) or `SSLClientSocket::RecordSSLConnectResult()` to understand the failure.**

**8. Structuring the Answer:**

Finally, organize the information logically, using clear headings and examples. Address each part of the user's request explicitly. Use the code snippets provided to illustrate the points being made. Be precise and avoid making assumptions.
这个文件 `net/socket/ssl_client_socket.cc` 是 Chromium 网络栈中处理客户端 SSL/TLS 连接的核心组件之一。它定义了 `SSLClientSocket` 接口和 `SSLClientContext` 类，并提供了一些辅助函数，用于管理和执行客户端的 SSL/TLS 握手和数据传输。

**主要功能列举:**

1. **`SSLClientSocket` 接口定义:**
   - 定义了客户端 SSL 套接字的基本操作接口，例如连接、读取、写入、断开连接以及获取 SSL 连接信息等。
   - 这是一个抽象基类，具体的实现由 `SSLClientSocketImpl` 提供。
   - 提供了静态方法 `SetSSLKeyLogger`，用于设置 SSL 密钥记录器，这对于调试和分析 SSL 连接非常有用。
   - 提供了静态方法 `SerializeNextProtos`，用于将 ALPN (Application-Layer Protocol Negotiation) 协议列表序列化为网络传输格式。
   - 提供了静态方法 `RecordSSLConnectResult`，用于记录 SSL 连接的结果，包括成功、失败以及相关的性能指标和 ECH (Encrypted Client Hello) 信息。

2. **`SSLClientContext` 类:**
   - 管理客户端 SSL 连接的上下文信息，例如 SSL 配置、证书验证器、传输安全状态、SSL 会话缓存等。
   - 负责创建 `SSLClientSocket` 的实例。
   - 管理客户端证书的缓存和选择。
   - 提供接口用于获取、设置和清除客户端证书。
   - 监听 SSL 配置服务、证书验证器和证书数据库的变化，并在必要时通知相关的观察者。
   - 维护了一个观察者列表，用于通知其他组件 SSL 配置的变化。

**与 Javascript 的功能关系:**

`ssl_client_socket.cc` 本身是用 C++ 编写的，与 JavaScript 没有直接的语法层面的关系。然而，它在浏览器中扮演着至关重要的角色，使得 JavaScript 可以通过 HTTPS 建立安全的网络连接。

**举例说明:**

当 JavaScript 代码使用 `fetch()` API 或 `XMLHttpRequest` 发起一个 HTTPS 请求时，底层的网络栈就会使用 `SSLClientSocket` 来建立与服务器的安全连接。

**假设输入与输出 (针对 `SSLClientContext` 的客户端证书管理):**

**假设输入 (对于 `SetClientCertificate`):**

- `server`: 一个 `HostPortPair` 对象，例如 `("example.com", 443)`。
- `client_cert`: 一个指向 `X509Certificate` 对象的智能指针，代表客户端证书。
- `private_key`: 一个指向 `SSLPrivateKey` 对象的智能指针，代表客户端私钥。

**逻辑推理:** `SSLClientContext` 将指定的客户端证书和私钥与给定的服务器关联并缓存起来。之后，当与该服务器建立新的 SSL 连接时，如果需要客户端认证，就会使用这个缓存的证书。同时，由于客户端证书的变更可能会影响会话恢复，相关的 SSL 会话缓存也会被清除。

**输出 (副作用):**

- 客户端证书和私钥被添加到 `ssl_client_auth_cache_` 中。
- 如果 `ssl_client_session_cache_` 存在，则会清除与该服务器相关的会话。
- 注册到 `SSLClientContext` 的观察者会被通知 SSL 配置发生了针对特定服务器的改变。

**假设输入 (对于 `GetClientCertificate`):**

- `server`: 一个 `HostPortPair` 对象，例如 `("example.com", 443)`。
- `client_cert`: 一个指向 `X509Certificate` 对象的智能指针的指针，用于接收输出的客户端证书。
- `private_key`: 一个指向 `SSLPrivateKey` 对象的智能指针的指针，用于接收输出的客户端私钥。

**逻辑推理:** `SSLClientContext` 在其 `ssl_client_auth_cache_` 中查找与给定服务器关联的客户端证书和私钥。

**输出:**

- 如果找到匹配的客户端证书和私钥，则 `GetClientCertificate` 返回 `true`，并且 `client_cert` 和 `private_key` 指针指向相应的对象。
- 如果没有找到匹配的，则返回 `false`，并且 `client_cert` 和 `private_key` 指针可能保持不变。

**用户或编程常见的使用错误:**

1. **未正确配置 SSL 上下文:** 如果 `SSLClientContext` 初始化时没有正确的 `CertVerifier` 或 `TransportSecurityState`，可能导致证书验证失败或安全策略执行不正确。

2. **在不需要客户端证书时设置了客户端证书:**  这虽然不会导致错误，但可能会增加握手过程的复杂性。

3. **忘记清除过期的或不再需要的客户端证书:**  如果用户更改了客户端证书偏好，但旧的证书仍然被缓存，可能会导致意外的行为。  `ClearClientCertificate` 和 `ClearMatchingClientCertificate` 方法用于解决这个问题。

4. **假设 `GetClientCertificate` 总是返回证书:**  开发者需要检查 `GetClientCertificate` 的返回值，以确定是否真的找到了缓存的客户端证书。

**用户操作如何一步步到达这里，作为调试线索:**

假设用户在使用 Chrome 浏览器访问一个需要客户端证书认证的 HTTPS 网站时遇到问题。

1. **用户在地址栏输入 HTTPS URL 并回车。**
2. **Chrome 的网络栈开始解析 URL 并尝试建立 TCP 连接。**
3. **TCP 连接建立后，网络栈会创建一个 `SSLClientSocket` 实例，通常是通过 `SSLClientContext::CreateSSLClientSocket`。**
4. **`SSLClientSocket` 开始执行 SSL/TLS 握手。**
5. **如果服务器要求客户端证书，`SSLClientSocket` 会调用 `SSLClientContext::GetClientCertificate` 来查找是否有为该服务器缓存的客户端证书。**
6. **如果找到缓存的证书，`SSLClientSocket` 会使用该证书进行客户端认证。**
7. **如果握手失败（例如，由于证书问题），相关的错误信息会被记录，开发者可以通过 Chrome 的 `chrome://net-internals/#events` 或其他调试工具查看。**

**调试线索:**

- **网络日志 (chrome://net-internals/#events):**  可以查看 SSL 连接的详细事件，包括客户端证书的查找、发送等信息。
- **SSL 密钥日志:** 如果设置了 SSL 密钥记录器，可以记录 SSL 会话密钥，用于 Wireshark 等工具进行解密分析。
- **断点调试:**  开发者可以在 `SSLClientContext::GetClientCertificate`、`SSLClientContext::SetClientCertificate` 或 `SSLClientSocketImpl` 的连接方法中设置断点，查看客户端证书的查找和使用流程。
- **查看客户端证书管理器:**  检查浏览器中安装的客户端证书是否正确，是否被启用。

总而言之，`net/socket/ssl_client_socket.cc` 是 Chromium 中实现客户端安全连接的关键部分，它负责管理 SSL 握手、客户端证书，并提供必要的接口和机制来确保网络通信的安全。它虽然不直接与 JavaScript 交互，但却是 JavaScript 通过 HTTPS 进行安全通信的基石。

Prompt: 
```
这是目录为net/socket/ssl_client_socket.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/ssl_client_socket.h"

#include <string>

#include "base/containers/flat_tree.h"
#include "base/logging.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/observer_list.h"
#include "base/values.h"
#include "net/cert/x509_certificate_net_log_param.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/socket/ssl_client_socket_impl.h"
#include "net/socket/stream_socket.h"
#include "net/ssl/ssl_client_session_cache.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/ssl_info.h"
#include "net/ssl/ssl_key_logger.h"

namespace net {

namespace {

// Returns true if |first_cert| and |second_cert| represent the same certificate
// (with the same chain), or if they're both NULL.
bool AreCertificatesEqual(const scoped_refptr<X509Certificate>& first_cert,
                          const scoped_refptr<X509Certificate>& second_cert,
                          bool include_chain = true) {
  return (!first_cert && !second_cert) ||
         (first_cert && second_cert &&
          (include_chain
               ? first_cert->EqualsIncludingChain(second_cert.get())
               : first_cert->EqualsExcludingChain(second_cert.get())));
}

// Returns a base::Value::Dict value NetLog parameter with the expected format
// for events of type CLEAR_CACHED_CLIENT_CERT.
base::Value::Dict NetLogClearCachedClientCertParams(
    const net::HostPortPair& host,
    const scoped_refptr<net::X509Certificate>& cert,
    bool is_cleared) {
  return base::Value::Dict()
      .Set("host", host.ToString())
      .Set("certificates", cert ? net::NetLogX509CertificateList(cert.get())
                                : base::Value(base::Value::List()))
      .Set("is_cleared", is_cleared);
}

// Returns a base::Value::Dict value NetLog parameter with the expected format
// for events of type CLEAR_MATCHING_CACHED_CLIENT_CERT.
base::Value::Dict NetLogClearMatchingCachedClientCertParams(
    const base::flat_set<net::HostPortPair>& hosts,
    const scoped_refptr<net::X509Certificate>& cert) {
  base::Value::List hosts_values;
  for (const auto& host : hosts) {
    hosts_values.Append(host.ToString());
  }

  return base::Value::Dict()
      .Set("hosts", base::Value(std::move(hosts_values)))
      .Set("certificates", cert ? net::NetLogX509CertificateList(cert.get())
                                : base::Value(base::Value::List()));
}

}  // namespace

// static
void SSLClientSocket::RecordSSLConnectResult(
    SSLClientSocket* ssl_socket,
    int result,
    bool is_ech_capable,
    bool ech_enabled,
    const std::optional<std::vector<uint8_t>>& ech_retry_configs,
    const LoadTimingInfo::ConnectTiming& connect_timing) {
  if (is_ech_capable && ech_enabled) {
    // These values are persisted to logs. Entries should not be renumbered
    // and numeric values should never be reused.
    enum class ECHResult {
      // The connection succeeded on the initial connection.
      kSuccessInitial = 0,
      // The connection failed on the initial connection, without providing
      // retry configs.
      kErrorInitial = 1,
      // The connection succeeded after getting retry configs.
      kSuccessRetry = 2,
      // The connection failed after getting retry configs.
      kErrorRetry = 3,
      // The connection succeeded after getting a rollback signal.
      kSuccessRollback = 4,
      // The connection failed after getting a rollback signal.
      kErrorRollback = 5,
      kMaxValue = kErrorRollback,
    };
    const bool is_ok = result == OK;
    ECHResult ech_result;
    if (!ech_retry_configs.has_value()) {
      ech_result =
          is_ok ? ECHResult::kSuccessInitial : ECHResult::kErrorInitial;
    } else if (ech_retry_configs->empty()) {
      ech_result =
          is_ok ? ECHResult::kSuccessRollback : ECHResult::kErrorRollback;
    } else {
      ech_result = is_ok ? ECHResult::kSuccessRetry : ECHResult::kErrorRetry;
    }
    base::UmaHistogramEnumeration("Net.SSL.ECHResult", ech_result);
  }

  if (result == OK) {
    DCHECK(!connect_timing.ssl_start.is_null());
    CHECK(ssl_socket);
    base::TimeDelta connect_duration =
        connect_timing.ssl_end - connect_timing.ssl_start;
    UMA_HISTOGRAM_CUSTOM_TIMES("Net.SSL_Connection_Latency_2", connect_duration,
                               base::Milliseconds(1), base::Minutes(1), 100);
    if (is_ech_capable) {
      UMA_HISTOGRAM_CUSTOM_TIMES("Net.SSL_Connection_Latency_ECH",
                                 connect_duration, base::Milliseconds(1),
                                 base::Minutes(1), 100);
    }

    SSLInfo ssl_info;
    bool has_ssl_info = ssl_socket->GetSSLInfo(&ssl_info);
    DCHECK(has_ssl_info);

    SSLVersion version =
        SSLConnectionStatusToVersion(ssl_info.connection_status);
    UMA_HISTOGRAM_ENUMERATION("Net.SSLVersion", version,
                              SSL_CONNECTION_VERSION_MAX);

    uint16_t cipher_suite =
        SSLConnectionStatusToCipherSuite(ssl_info.connection_status);
    base::UmaHistogramSparse("Net.SSL_CipherSuite", cipher_suite);

    if (ssl_info.key_exchange_group != 0) {
      base::UmaHistogramSparse("Net.SSL_KeyExchange.ECDHE",
                               ssl_info.key_exchange_group);
    }
  }

  base::UmaHistogramSparse("Net.SSL_Connection_Error", std::abs(result));
  if (is_ech_capable) {
    base::UmaHistogramSparse("Net.SSL_Connection_Error_ECH", std::abs(result));
  }
}

SSLClientSocket::SSLClientSocket() = default;

// static
void SSLClientSocket::SetSSLKeyLogger(std::unique_ptr<SSLKeyLogger> logger) {
  SSLClientSocketImpl::SetSSLKeyLogger(std::move(logger));
}

// static
std::vector<uint8_t> SSLClientSocket::SerializeNextProtos(
    const NextProtoVector& next_protos) {
  std::vector<uint8_t> wire_protos;
  for (const NextProto next_proto : next_protos) {
    const std::string proto = NextProtoToString(next_proto);
    if (proto.size() > 255) {
      LOG(WARNING) << "Ignoring overlong ALPN protocol: " << proto;
      continue;
    }
    if (proto.size() == 0) {
      LOG(WARNING) << "Ignoring empty ALPN protocol";
      continue;
    }
    wire_protos.push_back(proto.size());
    for (const char ch : proto) {
      wire_protos.push_back(static_cast<uint8_t>(ch));
    }
  }

  return wire_protos;
}

SSLClientContext::SSLClientContext(
    SSLConfigService* ssl_config_service,
    CertVerifier* cert_verifier,
    TransportSecurityState* transport_security_state,
    SSLClientSessionCache* ssl_client_session_cache,
    SCTAuditingDelegate* sct_auditing_delegate)
    : ssl_config_service_(ssl_config_service),
      cert_verifier_(cert_verifier),
      transport_security_state_(transport_security_state),
      ssl_client_session_cache_(ssl_client_session_cache),
      sct_auditing_delegate_(sct_auditing_delegate) {
  CHECK(cert_verifier_);
  CHECK(transport_security_state_);

  if (ssl_config_service_) {
    config_ = ssl_config_service_->GetSSLContextConfig();
    ssl_config_service_->AddObserver(this);
  }
  cert_verifier_->AddObserver(this);
  CertDatabase::GetInstance()->AddObserver(this);
}

SSLClientContext::~SSLClientContext() {
  if (ssl_config_service_) {
    ssl_config_service_->RemoveObserver(this);
  }
  cert_verifier_->RemoveObserver(this);
  CertDatabase::GetInstance()->RemoveObserver(this);
}

std::unique_ptr<SSLClientSocket> SSLClientContext::CreateSSLClientSocket(
    std::unique_ptr<StreamSocket> stream_socket,
    const HostPortPair& host_and_port,
    const SSLConfig& ssl_config) {
  return std::make_unique<SSLClientSocketImpl>(this, std::move(stream_socket),
                                               host_and_port, ssl_config);
}

bool SSLClientContext::GetClientCertificate(
    const HostPortPair& server,
    scoped_refptr<X509Certificate>* client_cert,
    scoped_refptr<SSLPrivateKey>* private_key) {
  return ssl_client_auth_cache_.Lookup(server, client_cert, private_key);
}

void SSLClientContext::SetClientCertificate(
    const HostPortPair& server,
    scoped_refptr<X509Certificate> client_cert,
    scoped_refptr<SSLPrivateKey> private_key) {
  ssl_client_auth_cache_.Add(server, std::move(client_cert),
                             std::move(private_key));

  if (ssl_client_session_cache_) {
    // Session resumption bypasses client certificate negotiation, so flush all
    // associated sessions when preferences change.
    ssl_client_session_cache_->FlushForServers({server});
  }
  NotifySSLConfigForServersChanged({server});
}

bool SSLClientContext::ClearClientCertificate(const HostPortPair& server) {
  if (!ssl_client_auth_cache_.Remove(server)) {
    return false;
  }

  if (ssl_client_session_cache_) {
    // Session resumption bypasses client certificate negotiation, so flush all
    // associated sessions when preferences change.
    ssl_client_session_cache_->FlushForServers({server});
  }
  NotifySSLConfigForServersChanged({server});
  return true;
}

void SSLClientContext::AddObserver(Observer* observer) {
  observers_.AddObserver(observer);
}

void SSLClientContext::RemoveObserver(Observer* observer) {
  observers_.RemoveObserver(observer);
}

void SSLClientContext::OnSSLContextConfigChanged() {
  config_ = ssl_config_service_->GetSSLContextConfig();
  if (ssl_client_session_cache_) {
    ssl_client_session_cache_->Flush();
  }
  NotifySSLConfigChanged(SSLConfigChangeType::kSSLConfigChanged);
}

void SSLClientContext::OnCertVerifierChanged() {
  NotifySSLConfigChanged(SSLConfigChangeType::kCertVerifierChanged);
}

void SSLClientContext::OnTrustStoreChanged() {
  NotifySSLConfigChanged(SSLConfigChangeType::kCertDatabaseChanged);
}

void SSLClientContext::OnClientCertStoreChanged() {
  base::flat_set<HostPortPair> servers =
      ssl_client_auth_cache_.GetCachedServers();
  ssl_client_auth_cache_.Clear();
  if (ssl_client_session_cache_) {
    ssl_client_session_cache_->FlushForServers(servers);
  }
  NotifySSLConfigForServersChanged(servers);
}

void SSLClientContext::ClearClientCertificateIfNeeded(
    const net::HostPortPair& host,
    const scoped_refptr<net::X509Certificate>& certificate) {
  scoped_refptr<X509Certificate> cached_certificate;
  scoped_refptr<SSLPrivateKey> cached_private_key;
  if (!ssl_client_auth_cache_.Lookup(host, &cached_certificate,
                                     &cached_private_key) ||
      AreCertificatesEqual(cached_certificate, certificate)) {
    // No cached client certificate preference for this host.
    net::NetLog::Get()->AddGlobalEntry(
        NetLogEventType::CLEAR_CACHED_CLIENT_CERT, [&]() {
          return NetLogClearCachedClientCertParams(host, certificate,
                                                   /*is_cleared=*/false);
        });
    return;
  }

  net::NetLog::Get()->AddGlobalEntry(
      NetLogEventType::CLEAR_CACHED_CLIENT_CERT, [&]() {
        return NetLogClearCachedClientCertParams(host, certificate,
                                                 /*is_cleared=*/true);
      });

  ssl_client_auth_cache_.Remove(host);

  if (ssl_client_session_cache_) {
    ssl_client_session_cache_->FlushForServers({host});
  }

  NotifySSLConfigForServersChanged({host});
}

void SSLClientContext::ClearMatchingClientCertificate(
    const scoped_refptr<net::X509Certificate>& certificate) {
  CHECK(certificate);

  base::flat_set<HostPortPair> cleared_servers;
  for (const auto& server : ssl_client_auth_cache_.GetCachedServers()) {
    scoped_refptr<X509Certificate> cached_certificate;
    scoped_refptr<SSLPrivateKey> cached_private_key;
    if (ssl_client_auth_cache_.Lookup(server, &cached_certificate,
                                      &cached_private_key) &&
        AreCertificatesEqual(cached_certificate, certificate,
                             /*include_chain=*/false)) {
      cleared_servers.insert(cleared_servers.end(), server);
    }
  }

  net::NetLog::Get()->AddGlobalEntry(
      NetLogEventType::CLEAR_MATCHING_CACHED_CLIENT_CERT, [&]() {
        return NetLogClearMatchingCachedClientCertParams(cleared_servers,
                                                         certificate);
      });

  if (cleared_servers.empty()) {
    return;
  }

  for (const auto& server_to_clear : cleared_servers) {
    ssl_client_auth_cache_.Remove(server_to_clear);
  }

  if (ssl_client_session_cache_) {
    ssl_client_session_cache_->FlushForServers(cleared_servers);
  }

  NotifySSLConfigForServersChanged(cleared_servers);
}

void SSLClientContext::NotifySSLConfigChanged(SSLConfigChangeType change_type) {
  for (Observer& observer : observers_) {
    observer.OnSSLConfigChanged(change_type);
  }
}

void SSLClientContext::NotifySSLConfigForServersChanged(
    const base::flat_set<HostPortPair>& servers) {
  for (Observer& observer : observers_) {
    observer.OnSSLConfigForServersChanged(servers);
  }
}

}  // namespace net

"""

```