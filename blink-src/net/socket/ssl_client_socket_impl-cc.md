Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understand the Goal:** The request asks for a functional summary of `ssl_client_socket_impl.cc`, focusing on its interaction with JavaScript, logical reasoning, common errors, debugging, and a general summary. It also specifies this is part 1 of 2.

2. **Initial Scan and Keyword Spotting:**  Quickly read through the code, looking for obvious patterns and keywords. Notice things like `#include`, `namespace net`, class definitions (`SSLClientSocketImpl`), function names (`Connect`, `Read`, `Write`, `Disconnect`),  BoringSSL function calls (`SSL_*`), NetLog events, and data structures like `SSLConfig`, `SSLInfo`. This gives a high-level idea of the file's purpose: managing SSL/TLS client connections.

3. **Deconstruct the Request - Functionality:**
    * **Core Functionality:**  The primary purpose is to implement an SSL client socket. This means handling the SSL/TLS handshake, encrypting and decrypting data, and interfacing with a lower-level stream socket.
    * **Key Features:** List the specific actions the code enables: connecting, disconnecting, reading, writing, handling certificates, managing sessions, exporting keying material, and logging.

4. **Address JavaScript Interaction:** This requires understanding how network requests initiated from JavaScript reach this C++ code.
    * **Browser Architecture:** Recall the basic browser architecture. JavaScript uses browser APIs (like `fetch` or `XMLHttpRequest`). These APIs interact with the network stack, which eventually leads to socket creation and management.
    * **Mapping the Flow:** Trace a hypothetical `fetch("https://example.com")` request. JavaScript calls the API, the browser's network service handles DNS resolution, connection establishment (TCP), and then SSL/TLS negotiation. `SSLClientSocketImpl` is the component responsible for the SSL/TLS part.
    * **Specific Examples:** Connect the JavaScript action (e.g., `fetch`) to the C++ function (`Connect`). Explain how data sent by JavaScript is handled by the `Write` function, and data received is handled by `Read`.

5. **Logical Reasoning (Assumptions and Outputs):**  This requires picking a specific function and walking through its logic with example inputs.
    * **Choose a Relevant Function:** `Connect` is a good choice as it's fundamental.
    * **Identify Inputs:** The `Connect` function takes a `CompletionOnceCallback`. Implicit inputs are the `host_and_port_` and `ssl_config_`.
    * **Trace the Execution:** Mentally (or on paper) follow the steps within `Connect`: logging, initialization (`Init`), setting the connection state, and the handshake loop (`DoHandshakeLoop`).
    * **Consider Different Scenarios:**  Think about success (handshake completes), immediate failure during `Init`, and asynchronous operation (waiting for I/O).
    * **Define Outputs:** Describe what the function returns in each scenario (e.g., `OK`, `ERR_...`, `ERR_IO_PENDING`).

6. **Common Usage Errors:** Think about mistakes developers might make when using or interacting with a network socket, especially an SSL socket.
    * **Improper Disconnection:**  Forgetting to disconnect can lead to resource leaks or unexpected behavior.
    * **Incorrect Callback Handling:**  Mishandling the completion callbacks can lead to crashes or incorrect logic.
    * **Configuration Issues:** Problems with `SSLConfig` (e.g., unsupported protocols) are common.
    * **Certificate Errors:** Misconfigurations or invalid certificates are frequent issues.

7. **Debugging Workflow:** How would a developer find their way to this code?
    * **Start with the Symptom:**  A user reports a problem (e.g., a website doesn't load, a security warning).
    * **Developer Tools:** Explain how browser developer tools can reveal network errors and connection details.
    * **NetLog:** Emphasize the importance of the NetLog for detailed network activity.
    * **Stack Traces:**  Describe how debugging tools can lead to specific function calls within this file.
    * **Keywords for Searching:** Suggest keywords a developer might use to search the codebase.

8. **Part 1 Summary:** Condense the key functionalities and responsibilities of the code covered in the snippet. Focus on the core role of managing SSL client connections.

9. **Review and Refine:**  Read through the entire analysis. Ensure clarity, accuracy, and completeness. Check if all aspects of the request have been addressed. Ensure the language is precise and avoids jargon where possible, or explains it clearly. For example, initially, I might have just said "handles the handshake," but refining it to "handles the SSL/TLS handshake, including negotiating encryption algorithms and verifying the server's certificate" is more informative.

10. **Consider the "Part 1 of 2" Aspect:** This likely means the next part will delve into more specific details or related files. Keep the summary of part 1 somewhat high-level, leaving room for more granular details in part 2.

This systematic approach allows for a comprehensive understanding of the code and addresses all aspects of the prompt effectively. It combines code reading with knowledge of browser architecture, networking principles, and debugging techniques.
Let's break down the functionality of the provided `ssl_client_socket_impl.cc` file (Part 1) and address your specific questions.

**Core Functionality of `ssl_client_socket_impl.cc` (Part 1):**

This file implements the `SSLClientSocketImpl` class, which is a crucial component in Chromium's network stack responsible for establishing and managing secure TLS/SSL client connections. It acts as a wrapper around a lower-level `StreamSocket` and adds TLS/SSL encryption and decryption capabilities.

Here's a breakdown of its key responsibilities:

1. **TLS/SSL Handshake Initiation and Management:**
   - Initiates the TLS/SSL handshake with a server.
   - Manages the different stages of the handshake (client hello, server hello, certificate exchange, key exchange, etc.).
   - Handles renegotiation of the TLS/SSL session.
   - Supports features like session resumption for faster connections.
   - Implements logic for Encrypted Client Hello (ECH).

2. **Secure Data Transmission (Read and Write):**
   - Encrypts data before sending it to the server using the established TLS/SSL session.
   - Decrypts data received from the server.
   - Provides `Read` and `Write` methods for secure communication, similar to a regular socket.

3. **Certificate Handling and Verification:**
   - Sends the client certificate to the server if required (mutual TLS).
   - Verifies the server's certificate to ensure the connection is to the intended server and not an attacker.
   - Integrates with Chromium's certificate verification framework (`CertVerifier`).
   - Handles Certificate Transparency (CT) verification.
   - Supports OCSP stapling for improved certificate revocation checks.

4. **Protocol Negotiation (ALPN):**
   - Negotiates the application-layer protocol (e.g., HTTP/2, HTTP/3) with the server using ALPN (Application-Layer Protocol Negotiation).

5. **Session Management:**
   - Integrates with the `SSLClientSessionCache` to store and reuse TLS/SSL session tickets for faster subsequent connections.

6. **Error Handling:**
   - Maps errors from the underlying BoringSSL library to Chromium's `net::Error` codes.
   - Handles various TLS/SSL-related errors (e.g., certificate errors, handshake failures).

7. **Logging and Debugging:**
   - Uses Chromium's `NetLog` system to record events related to the TLS/SSL connection for debugging and analysis.
   - Logs details about the handshake process, certificate verification, and errors.

8. **Integration with Lower Layers:**
   - Operates on top of a `StreamSocket` (e.g., a TCP socket).
   - Uses `SocketBIOAdapter` to interface with the underlying socket's read and write operations.

9. **Key Logging:**
   - Supports logging of TLS/SSL session keys for debugging purposes (e.g., with Wireshark).

**Relationship with JavaScript Functionality:**

Yes, `SSLClientSocketImpl` is directly related to how JavaScript running in a browser performs secure network requests. Here's how:

* **`fetch()` API:** When JavaScript uses the `fetch()` API (or `XMLHttpRequest`) to make an HTTPS request, the browser's network stack internally uses `SSLClientSocketImpl` to establish the secure connection to the server.
* **WebSockets (WSS):** For secure WebSocket connections (using the `wss://` protocol), `SSLClientSocketImpl` is responsible for the TLS/SSL handshake and secure communication.
* **Other Secure APIs:** Any browser API that requires a secure connection (e.g., some aspects of WebRTC) will likely involve `SSLClientSocketImpl` in the underlying implementation.

**Example:**

Imagine a simple JavaScript `fetch()` call:

```javascript
fetch('https://www.example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

**Behind the Scenes (Simplified):**

1. **JavaScript initiates the `fetch()` call.**
2. **The browser's network service (written in C++) takes over.**
3. **DNS resolution:** The browser resolves `www.example.com` to an IP address.
4. **TCP connection:** A TCP connection is established with the server's IP address and port 443.
5. **`SSLClientSocketImpl::Connect()` is called:** This function is responsible for initiating the TLS/SSL handshake.
6. **Handshake process:** `SSLClientSocketImpl` interacts with the server, exchanging messages to agree on encryption algorithms, verify certificates, and establish a secure session.
7. **Secure data transfer:** Once the handshake is complete, when JavaScript receives the response data, the encrypted data received by the underlying socket is decrypted by `SSLClientSocketImpl` before being passed back to the JavaScript `fetch()` API.

**Logical Reasoning (Hypothetical Input & Output):**

Let's consider the `Connect()` function:

**Hypothetical Input:**

* `SSLClientSocketImpl` instance is created with a `StreamSocket` connected to `www.example.com:443`.
* `ssl_config_` specifies TLS 1.3 as the minimum version and includes ALPN for "h2" (HTTP/2).
* No cached session exists for this host.

**Logical Flow within `Connect()` (Based on the Code):**

1. `net_log_.BeginEvent(NetLogEventType::SSL_CONNECT);`: Start logging the connection attempt.
2. `Init()` is called:
   - A new `SSL` object from BoringSSL is created.
   - SNI (Server Name Indication) is set to `www.example.com`.
   - TLS protocol versions are configured (minimum TLS 1.3).
   - ALPN protocols are set to "h2".
   - Certificate verification callbacks are set up.
3. `SSL_set_connect_state(ssl_.get());`: Set the SSL object to client connection mode.
4. `next_handshake_state_ = STATE_HANDSHAKE;`: Move to the handshake state.
5. `DoHandshakeLoop(OK)` is called:
   - This function drives the actual TLS handshake using `SSL_do_handshake()`.
   - It will likely involve multiple calls to `stream_socket_->Read()` and `stream_socket_->Write()` through the `transport_adapter_` to exchange handshake messages.
   - If the handshake requires asynchronous I/O (waiting for data from the network), it will return `ERR_IO_PENDING`.

**Hypothetical Output:**

* **Success:** If the handshake completes successfully:
   - `DoHandshakeLoop()` returns `OK`.
   - `completed_connect_` is set to `true`.
   - `negotiated_protocol_` is set to `NextProto::kHttp2` (assuming the server supports it).
   - `net_log_.EndEvent(NetLogEventType::SSL_CONNECT, NetLog::OK);` is called.
   - The `Connect()` callback is invoked with `OK`.
* **Failure (e.g., Certificate Error):** If the server's certificate is invalid:
   - `DoHandshakeLoop()` might return `ERR_CERT_AUTHORITY_INVALID` or a similar error.
   - `completed_connect_` remains `false`.
   - `net_log_.EndEvent(NetLogEventType::SSL_CONNECT, error_code);` is called with the specific error.
   - The `Connect()` callback is invoked with the error code.
* **Asynchronous Pending:** If the handshake is waiting for network I/O:
   - `DoHandshakeLoop()` returns `ERR_IO_PENDING`.
   - `user_connect_callback_` is stored.
   - The `Connect()` function returns `ERR_IO_PENDING`. The handshake will continue when the underlying socket becomes ready for reading or writing.

**User or Programming Common Usage Errors:**

1. **Incorrectly configuring `SSLConfig`:**
   - **Example:** Disabling TLS 1.3 when the server only supports it, leading to a handshake failure.
   - **Example:** Providing an invalid list of ALPN protocols.
2. **Not handling `ERR_IO_PENDING` correctly:**
   - **Example:**  The code calling `Connect()` doesn't implement the callback mechanism properly, leading to the connection not being fully established.
3. **Calling socket methods before `Connect()` completes:**
   - **Example:** Attempting to `Read()` or `Write()` on the `SSLClientSocketImpl` before the handshake has finished, which can lead to unexpected behavior or errors.
4. **Mismatched SSL/TLS versions:**
   - **Example:** The client is configured to only support older TLS versions, while the server requires a newer version.
5. **Certificate errors:**
   - **Example:** Trying to connect to a server with an expired or self-signed certificate without proper configuration to allow it (which is generally discouraged for security reasons).
6. **Disconnecting the underlying `StreamSocket` directly:**
   - **Example:** Instead of calling `ssl_client_socket->Disconnect()`, directly calling `stream_socket_->Disconnect()`. This can leave the SSL state in an inconsistent state.

**User Operation Steps Leading Here (Debugging Clues):**

Let's consider a user browsing to an HTTPS website:

1. **User types `https://www.example.com` in the address bar or clicks a link.**
2. **The browser initiates a network request.**
3. **DNS resolution occurs.**
4. **A TCP connection is established with the server on port 443.**
5. **Chromium's network stack determines that an SSL/TLS connection is needed (due to `https://`).**
6. **An `SSLClientSocketImpl` instance is created.**
7. **The `Connect()` method of `SSLClientSocketImpl` is called.**
8. **The code within this file (Part 1) executes to perform the TLS/SSL handshake.**

**Debugging Clues:**

* **Network Panel in Developer Tools:** If the user encounters an error, the browser's developer tools (Network tab) will show details about the request, including the connection status and any SSL/TLS errors.
* **`chrome://net-export/` (NetLog):**  A developer can enable detailed network logging using `chrome://net-export/`. This log will contain events specifically related to the `SSLClientSocketImpl`, such as the start and end of the handshake, certificate verification results, and any errors encountered. Searching the NetLog for events with types like `SSL_CONNECT`, `SSL_HANDSHAKE`, `CERT_VERIFY`, etc., will lead directly to the relevant code in `ssl_client_socket_impl.cc`.
* **Error Messages:** Specific error messages displayed in the browser (e.g., "Your connection is not secure," certificate errors) often correspond to specific error codes handled within `SSLClientSocketImpl`.
* **Stack Traces (if a crash occurs):** If there's a bug in the SSL implementation that leads to a crash, a stack trace will often point to functions within this file or related SSL/BoringSSL code.

**Summary of Functionality (Part 1):**

In essence, the first part of `ssl_client_socket_impl.cc` focuses on the **establishment and initial management of secure TLS/SSL client connections**. It handles the crucial handshake process, negotiates protocols, sets up encryption, and integrates with certificate verification mechanisms. This part lays the foundation for secure data transfer, which will likely be the focus of the subsequent parts of the file.

Prompt: 
```
这是目录为net/socket/ssl_client_socket_impl.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/socket/ssl_client_socket_impl.h"

#include <errno.h>
#include <string.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <memory>
#include <string_view>
#include <utility>

#include "base/containers/span.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/lazy_instance.h"
#include "base/location.h"
#include "base/memory/singleton.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/rand_util.h"
#include "base/synchronization/lock.h"
#include "base/task/sequenced_task_runner.h"
#include "base/values.h"
#include "build/build_config.h"
#include "crypto/ec_private_key.h"
#include "crypto/openssl_util.h"
#include "net/base/features.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "net/base/trace_constants.h"
#include "net/base/tracing.h"
#include "net/base/url_util.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_verifier.h"
#include "net/cert/sct_auditing_delegate.h"
#include "net/cert/sct_status_flags.h"
#include "net/cert/x509_certificate_net_log_param.h"
#include "net/cert/x509_util.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_values.h"
#include "net/ssl/cert_compression.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_cipher_suite_names.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/ssl_handshake_details.h"
#include "net/ssl/ssl_info.h"
#include "net/ssl/ssl_key_logger.h"
#include "net/ssl/ssl_private_key.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "third_party/boringssl/src/include/openssl/bio.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/err.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"

namespace net {

namespace {

// This constant can be any non-negative/non-zero value (eg: it does not
// overlap with any value of the net::Error range, including net::OK).
const int kSSLClientSocketNoPendingResult = 1;
// This constant can be any non-negative/non-zero value (eg: it does not
// overlap with any value of the net::Error range, including net::OK).
const int kCertVerifyPending = 1;

// Default size of the internal BoringSSL buffers.
const int kDefaultOpenSSLBufferSize = 17 * 1024;

base::Value::Dict NetLogPrivateKeyOperationParams(uint16_t algorithm,
                                                  SSLPrivateKey* key) {
  return base::Value::Dict()
      .Set("algorithm",
           SSL_get_signature_algorithm_name(algorithm, 0 /* exclude curve */))
      .Set("provider", key->GetProviderName());
}

base::Value::Dict NetLogSSLInfoParams(SSLClientSocketImpl* socket) {
  SSLInfo ssl_info;
  if (!socket->GetSSLInfo(&ssl_info)) {
    return base::Value::Dict();
  }

  const char* version_str;
  SSLVersionToString(&version_str,
                     SSLConnectionStatusToVersion(ssl_info.connection_status));
  return base::Value::Dict()
      .Set("version", version_str)
      .Set("is_resumed", ssl_info.handshake_type == SSLInfo::HANDSHAKE_RESUME)
      .Set("cipher_suite",
           SSLConnectionStatusToCipherSuite(ssl_info.connection_status))
      .Set("key_exchange_group", ssl_info.key_exchange_group)
      .Set("peer_signature_algorithm", ssl_info.peer_signature_algorithm)
      .Set("encrypted_client_hello", ssl_info.encrypted_client_hello)
      .Set("next_proto", NextProtoToString(socket->GetNegotiatedProtocol()));
}

base::Value::Dict NetLogSSLAlertParams(const void* bytes, size_t len) {
  return base::Value::Dict().Set("bytes", NetLogBinaryValue(bytes, len));
}

base::Value::Dict NetLogSSLMessageParams(bool is_write,
                                         const void* bytes,
                                         size_t len,
                                         NetLogCaptureMode capture_mode) {
  if (len == 0) {
    NOTREACHED();
  }

  base::Value::Dict dict;
  // The handshake message type is the first byte. Include it so elided messages
  // still report their type.
  uint8_t type = reinterpret_cast<const uint8_t*>(bytes)[0];
  dict.Set("type", type);

  // Elide client certificate messages unless logging socket bytes. The client
  // certificate does not contain information needed to impersonate the user
  // (that's the private key which isn't sent over the wire), but it may contain
  // information on the user's identity.
  if (!is_write || type != SSL3_MT_CERTIFICATE ||
      NetLogCaptureIncludesSocketBytes(capture_mode)) {
    dict.Set("bytes", NetLogBinaryValue(bytes, len));
  }

  return dict;
}

bool HostIsIPAddressNoBrackets(std::string_view host) {
  // Note this cannot directly call url::HostIsIPAddress, because that function
  // expects bracketed IPv6 literals. By the time hosts reach SSLClientSocket,
  // brackets have been removed.
  IPAddress unused;
  return unused.AssignFromIPLiteral(host);
}

}  // namespace

class SSLClientSocketImpl::SSLContext {
 public:
  static SSLContext* GetInstance() {
    return base::Singleton<SSLContext,
                           base::LeakySingletonTraits<SSLContext>>::get();
  }
  SSL_CTX* ssl_ctx() { return ssl_ctx_.get(); }

  SSLClientSocketImpl* GetClientSocketFromSSL(const SSL* ssl) {
    DCHECK(ssl);
    SSLClientSocketImpl* socket = static_cast<SSLClientSocketImpl*>(
        SSL_get_ex_data(ssl, ssl_socket_data_index_));
    DCHECK(socket);
    return socket;
  }

  bool SetClientSocketForSSL(SSL* ssl, SSLClientSocketImpl* socket) {
    return SSL_set_ex_data(ssl, ssl_socket_data_index_, socket) != 0;
  }

  void SetSSLKeyLogger(std::unique_ptr<SSLKeyLogger> logger) {
    net::SSLKeyLoggerManager::SetSSLKeyLogger(std::move(logger));
    SSL_CTX_set_keylog_callback(ssl_ctx_.get(),
                                SSLKeyLoggerManager::KeyLogCallback);
  }

  static const SSL_PRIVATE_KEY_METHOD kPrivateKeyMethod;

 private:
  friend struct base::DefaultSingletonTraits<SSLContext>;

  SSLContext() {
    ssl_socket_data_index_ =
        SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    DCHECK_NE(ssl_socket_data_index_, -1);
    ssl_ctx_.reset(SSL_CTX_new(TLS_with_buffers_method()));
    SSL_CTX_set_cert_cb(ssl_ctx_.get(), ClientCertRequestCallback, nullptr);

    // Verifies the server certificate even on resumed sessions.
    SSL_CTX_set_reverify_on_resume(ssl_ctx_.get(), 1);
    SSL_CTX_set_custom_verify(ssl_ctx_.get(), SSL_VERIFY_PEER,
                              VerifyCertCallback);
    // Disable the internal session cache. Session caching is handled
    // externally (i.e. by SSLClientSessionCache).
    SSL_CTX_set_session_cache_mode(
        ssl_ctx_.get(), SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
    SSL_CTX_sess_set_new_cb(ssl_ctx_.get(), NewSessionCallback);
    SSL_CTX_set_timeout(ssl_ctx_.get(), 1 * 60 * 60 /* one hour */);

    SSL_CTX_set_grease_enabled(ssl_ctx_.get(), 1);

    // Deduplicate all certificates minted from the SSL_CTX in memory.
    SSL_CTX_set0_buffer_pool(ssl_ctx_.get(), x509_util::GetBufferPool());

    SSL_CTX_set_msg_callback(ssl_ctx_.get(), MessageCallback);

    ConfigureCertificateCompression(ssl_ctx_.get());
  }

  static int ClientCertRequestCallback(SSL* ssl, void* arg) {
    SSLClientSocketImpl* socket = GetInstance()->GetClientSocketFromSSL(ssl);
    DCHECK(socket);
    return socket->ClientCertRequestCallback(ssl);
  }

  static int NewSessionCallback(SSL* ssl, SSL_SESSION* session) {
    SSLClientSocketImpl* socket = GetInstance()->GetClientSocketFromSSL(ssl);
    return socket->NewSessionCallback(session);
  }

  static ssl_private_key_result_t PrivateKeySignCallback(SSL* ssl,
                                                         uint8_t* out,
                                                         size_t* out_len,
                                                         size_t max_out,
                                                         uint16_t algorithm,
                                                         const uint8_t* in,
                                                         size_t in_len) {
    SSLClientSocketImpl* socket = GetInstance()->GetClientSocketFromSSL(ssl);
    return socket->PrivateKeySignCallback(out, out_len, max_out, algorithm, in,
                                          in_len);
  }

  static ssl_private_key_result_t PrivateKeyCompleteCallback(SSL* ssl,
                                                             uint8_t* out,
                                                             size_t* out_len,
                                                             size_t max_out) {
    SSLClientSocketImpl* socket = GetInstance()->GetClientSocketFromSSL(ssl);
    return socket->PrivateKeyCompleteCallback(out, out_len, max_out);
  }

  static void MessageCallback(int is_write,
                              int version,
                              int content_type,
                              const void* buf,
                              size_t len,
                              SSL* ssl,
                              void* arg) {
    SSLClientSocketImpl* socket = GetInstance()->GetClientSocketFromSSL(ssl);
    return socket->MessageCallback(is_write, content_type, buf, len);
  }

  // This is the index used with SSL_get_ex_data to retrieve the owner
  // SSLClientSocketImpl object from an SSL instance.
  int ssl_socket_data_index_;

  bssl::UniquePtr<SSL_CTX> ssl_ctx_;
};

const SSL_PRIVATE_KEY_METHOD
    SSLClientSocketImpl::SSLContext::kPrivateKeyMethod = {
        &SSLClientSocketImpl::SSLContext::PrivateKeySignCallback,
        nullptr /* decrypt */,
        &SSLClientSocketImpl::SSLContext::PrivateKeyCompleteCallback,
};

SSLClientSocketImpl::SSLClientSocketImpl(
    SSLClientContext* context,
    std::unique_ptr<StreamSocket> stream_socket,
    const HostPortPair& host_and_port,
    const SSLConfig& ssl_config)
    : pending_read_error_(kSSLClientSocketNoPendingResult),
      context_(context),
      cert_verification_result_(kCertVerifyPending),
      stream_socket_(std::move(stream_socket)),
      host_and_port_(host_and_port),
      ssl_config_(ssl_config),
      signature_result_(kSSLClientSocketNoPendingResult),
      net_log_(stream_socket_->NetLog()) {
  CHECK(context_);
}

SSLClientSocketImpl::~SSLClientSocketImpl() {
  Disconnect();
}

void SSLClientSocketImpl::SetSSLKeyLogger(
    std::unique_ptr<SSLKeyLogger> logger) {
  SSLContext::GetInstance()->SetSSLKeyLogger(std::move(logger));
}

std::vector<uint8_t> SSLClientSocketImpl::GetECHRetryConfigs() {
  const uint8_t* retry_configs;
  size_t retry_configs_len;
  SSL_get0_ech_retry_configs(ssl_.get(), &retry_configs, &retry_configs_len);
  return std::vector<uint8_t>(retry_configs, retry_configs + retry_configs_len);
}

int SSLClientSocketImpl::ExportKeyingMaterial(std::string_view label,
                                              bool has_context,
                                              std::string_view context,
                                              unsigned char* out,
                                              unsigned int outlen) {
  if (!IsConnected())
    return ERR_SOCKET_NOT_CONNECTED;

  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  if (!SSL_export_keying_material(
          ssl_.get(), out, outlen, label.data(), label.size(),
          reinterpret_cast<const unsigned char*>(context.data()),
          context.length(), has_context ? 1 : 0)) {
    LOG(ERROR) << "Failed to export keying material.";
    return ERR_FAILED;
  }

  return OK;
}

int SSLClientSocketImpl::Connect(CompletionOnceCallback callback) {
  // Although StreamSocket does allow calling Connect() after Disconnect(),
  // this has never worked for layered sockets. CHECK to detect any consumers
  // reconnecting an SSL socket.
  //
  // TODO(davidben,mmenke): Remove this API feature. See
  // https://crbug.com/499289.
  CHECK(!disconnected_);

  net_log_.BeginEvent(NetLogEventType::SSL_CONNECT);

  // Set up new ssl object.
  int rv = Init();
  if (rv != OK) {
    LogConnectEndEvent(rv);
    return rv;
  }

  // Set SSL to client mode. Handshake happens in the loop below.
  SSL_set_connect_state(ssl_.get());

  next_handshake_state_ = STATE_HANDSHAKE;
  rv = DoHandshakeLoop(OK);
  if (rv == ERR_IO_PENDING) {
    user_connect_callback_ = std::move(callback);
  } else {
    LogConnectEndEvent(rv);
  }

  return rv > OK ? OK : rv;
}

void SSLClientSocketImpl::Disconnect() {
  disconnected_ = true;

  // Shut down anything that may call us back.
  cert_verifier_request_.reset();
  weak_factory_.InvalidateWeakPtrs();
  transport_adapter_.reset();

  // Release user callbacks.
  user_connect_callback_.Reset();
  user_read_callback_.Reset();
  user_write_callback_.Reset();
  user_read_buf_ = nullptr;
  user_read_buf_len_ = 0;
  user_write_buf_ = nullptr;
  user_write_buf_len_ = 0;

  stream_socket_->Disconnect();
}

// ConfirmHandshake may only be called on a connected socket and, like other
// socket methods, there may only be one ConfirmHandshake operation in progress
// at once.
int SSLClientSocketImpl::ConfirmHandshake(CompletionOnceCallback callback) {
  CHECK(completed_connect_);
  CHECK(!in_confirm_handshake_);
  if (!SSL_in_early_data(ssl_.get())) {
    return OK;
  }

  net_log_.BeginEvent(NetLogEventType::SSL_CONFIRM_HANDSHAKE);
  next_handshake_state_ = STATE_HANDSHAKE;
  in_confirm_handshake_ = true;
  int rv = DoHandshakeLoop(OK);
  if (rv == ERR_IO_PENDING) {
    user_connect_callback_ = std::move(callback);
  } else {
    net_log_.EndEvent(NetLogEventType::SSL_CONFIRM_HANDSHAKE);
    in_confirm_handshake_ = false;
  }

  return rv > OK ? OK : rv;
}

bool SSLClientSocketImpl::IsConnected() const {
  // If the handshake has not yet completed or the socket has been explicitly
  // disconnected.
  if (!completed_connect_ || disconnected_)
    return false;
  // If an asynchronous operation is still pending.
  if (user_read_buf_.get() || user_write_buf_.get())
    return true;

  return stream_socket_->IsConnected();
}

bool SSLClientSocketImpl::IsConnectedAndIdle() const {
  // If the handshake has not yet completed or the socket has been explicitly
  // disconnected.
  if (!completed_connect_ || disconnected_)
    return false;
  // If an asynchronous operation is still pending.
  if (user_read_buf_.get() || user_write_buf_.get())
    return false;

  // If there is data read from the network that has not yet been consumed, do
  // not treat the connection as idle.
  //
  // Note that this does not check whether there is ciphertext that has not yet
  // been flushed to the network. |Write| returns early, so this can cause race
  // conditions which cause a socket to not be treated reusable when it should
  // be. See https://crbug.com/466147.
  if (transport_adapter_->HasPendingReadData())
    return false;

  return stream_socket_->IsConnectedAndIdle();
}

int SSLClientSocketImpl::GetPeerAddress(IPEndPoint* addressList) const {
  return stream_socket_->GetPeerAddress(addressList);
}

int SSLClientSocketImpl::GetLocalAddress(IPEndPoint* addressList) const {
  return stream_socket_->GetLocalAddress(addressList);
}

const NetLogWithSource& SSLClientSocketImpl::NetLog() const {
  return net_log_;
}

bool SSLClientSocketImpl::WasEverUsed() const {
  return was_ever_used_;
}

NextProto SSLClientSocketImpl::GetNegotiatedProtocol() const {
  return negotiated_protocol_;
}

std::optional<std::string_view>
SSLClientSocketImpl::GetPeerApplicationSettings() const {
  if (!SSL_has_application_settings(ssl_.get())) {
    return std::nullopt;
  }

  const uint8_t* out_data;
  size_t out_len;
  SSL_get0_peer_application_settings(ssl_.get(), &out_data, &out_len);
  return std::string_view{reinterpret_cast<const char*>(out_data), out_len};
}

bool SSLClientSocketImpl::GetSSLInfo(SSLInfo* ssl_info) {
  ssl_info->Reset();
  if (!server_cert_)
    return false;

  ssl_info->cert = server_cert_verify_result_.verified_cert;
  ssl_info->unverified_cert = server_cert_;
  ssl_info->cert_status = server_cert_verify_result_.cert_status;
  ssl_info->is_issued_by_known_root =
      server_cert_verify_result_.is_issued_by_known_root;
  ssl_info->pkp_bypassed = pkp_bypassed_;
  ssl_info->public_key_hashes = server_cert_verify_result_.public_key_hashes;
  ssl_info->client_cert_sent = send_client_cert_ && client_cert_.get();
  ssl_info->encrypted_client_hello = SSL_ech_accepted(ssl_.get());
  ssl_info->ocsp_result = server_cert_verify_result_.ocsp_result;
  ssl_info->is_fatal_cert_error = is_fatal_cert_error_;
  ssl_info->signed_certificate_timestamps = server_cert_verify_result_.scts;
  ssl_info->ct_policy_compliance = server_cert_verify_result_.policy_compliance;

  const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl_.get());
  CHECK(cipher);
  // Historically, the "group" was known as "curve".
  ssl_info->key_exchange_group = SSL_get_curve_id(ssl_.get());
  ssl_info->peer_signature_algorithm =
      SSL_get_peer_signature_algorithm(ssl_.get());

  SSLConnectionStatusSetCipherSuite(SSL_CIPHER_get_protocol_id(cipher),
                                    &ssl_info->connection_status);
  SSLConnectionStatusSetVersion(GetNetSSLVersion(ssl_.get()),
                                &ssl_info->connection_status);

  ssl_info->handshake_type = SSL_session_reused(ssl_.get())
                                 ? SSLInfo::HANDSHAKE_RESUME
                                 : SSLInfo::HANDSHAKE_FULL;

  return true;
}

int64_t SSLClientSocketImpl::GetTotalReceivedBytes() const {
  return stream_socket_->GetTotalReceivedBytes();
}

void SSLClientSocketImpl::GetSSLCertRequestInfo(
    SSLCertRequestInfo* cert_request_info) const {
  if (!ssl_) {
    NOTREACHED();
  }

  cert_request_info->host_and_port = host_and_port_;

  cert_request_info->cert_authorities.clear();
  const STACK_OF(CRYPTO_BUFFER)* authorities =
      SSL_get0_server_requested_CAs(ssl_.get());
  for (const CRYPTO_BUFFER* ca_name : authorities) {
    cert_request_info->cert_authorities.emplace_back(
        reinterpret_cast<const char*>(CRYPTO_BUFFER_data(ca_name)),
        CRYPTO_BUFFER_len(ca_name));
  }

  const uint16_t* algorithms;
  size_t num_algorithms =
      SSL_get0_peer_verify_algorithms(ssl_.get(), &algorithms);
  cert_request_info->signature_algorithms.assign(algorithms,
                                                 algorithms + num_algorithms);
}

void SSLClientSocketImpl::ApplySocketTag(const SocketTag& tag) {
  return stream_socket_->ApplySocketTag(tag);
}

int SSLClientSocketImpl::Read(IOBuffer* buf,
                              int buf_len,
                              CompletionOnceCallback callback) {
  int rv = ReadIfReady(buf, buf_len, std::move(callback));
  if (rv == ERR_IO_PENDING) {
    user_read_buf_ = buf;
    user_read_buf_len_ = buf_len;
  }
  return rv;
}

int SSLClientSocketImpl::ReadIfReady(IOBuffer* buf,
                                     int buf_len,
                                     CompletionOnceCallback callback) {
  int rv = DoPayloadRead(buf, buf_len);

  if (rv == ERR_IO_PENDING) {
    user_read_callback_ = std::move(callback);
  } else {
    if (rv > 0)
      was_ever_used_ = true;
  }
  return rv;
}

int SSLClientSocketImpl::CancelReadIfReady() {
  DCHECK(user_read_callback_);
  DCHECK(!user_read_buf_);

  // Cancel |user_read_callback_|, because caller does not expect the callback
  // to be invoked after they have canceled the ReadIfReady.
  //
  // We do not pass the signal on to |stream_socket_| or |transport_adapter_|.
  // Multiple operations may be waiting on a transport ReadIfReady().
  // Conversely, an SSL ReadIfReady() may be blocked on something other than a
  // transport ReadIfReady(). Instead, the underlying transport ReadIfReady()
  // will continue running (with no underlying buffer). When it completes, it
  // will signal OnReadReady(), which will notice there is no read operation to
  // progress and skip it.
  user_read_callback_.Reset();
  return OK;
}

int SSLClientSocketImpl::Write(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  user_write_buf_ = buf;
  user_write_buf_len_ = buf_len;

  int rv = DoPayloadWrite();

  if (rv == ERR_IO_PENDING) {
    user_write_callback_ = std::move(callback);
  } else {
    if (rv > 0) {
      CHECK_LE(rv, buf_len);
      was_ever_used_ = true;
    }
    user_write_buf_ = nullptr;
    user_write_buf_len_ = 0;
  }

  return rv;
}

int SSLClientSocketImpl::SetReceiveBufferSize(int32_t size) {
  return stream_socket_->SetReceiveBufferSize(size);
}

int SSLClientSocketImpl::SetSendBufferSize(int32_t size) {
  return stream_socket_->SetSendBufferSize(size);
}

void SSLClientSocketImpl::OnReadReady() {
  // During a renegotiation, either Read or Write calls may be blocked on a
  // transport read.
  RetryAllOperations();
}

void SSLClientSocketImpl::OnWriteReady() {
  // During a renegotiation, either Read or Write calls may be blocked on a
  // transport read.
  RetryAllOperations();
}

int SSLClientSocketImpl::Init() {
  DCHECK(!ssl_);

  SSLContext* context = SSLContext::GetInstance();
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  ssl_.reset(SSL_new(context->ssl_ctx()));
  if (!ssl_ || !context->SetClientSocketForSSL(ssl_.get(), this))
    return ERR_UNEXPECTED;

  const bool host_is_ip_address =
      HostIsIPAddressNoBrackets(host_and_port_.host());

  // SNI should only contain valid DNS hostnames, not IP addresses (see RFC
  // 6066, Section 3).
  //
  // TODO(rsleevi): Should this code allow hostnames that violate the LDH rule?
  // See https://crbug.com/496472 and https://crbug.com/496468 for discussion.
  if (!host_is_ip_address &&
      !SSL_set_tlsext_host_name(ssl_.get(), host_and_port_.host().c_str())) {
    return ERR_UNEXPECTED;
  }

  if (context_->config().PostQuantumKeyAgreementEnabled()) {
    const uint16_t postquantum_group =
        base::FeatureList::IsEnabled(features::kUseMLKEM)
            ? SSL_GROUP_X25519_MLKEM768
            : SSL_GROUP_X25519_KYBER768_DRAFT00;
    const uint16_t kGroups[] = {postquantum_group, SSL_GROUP_X25519,
                                SSL_GROUP_SECP256R1, SSL_GROUP_SECP384R1};
    if (!SSL_set1_group_ids(ssl_.get(), kGroups, std::size(kGroups))) {
      return ERR_UNEXPECTED;
    }
  }

  if (IsCachingEnabled()) {
    bssl::UniquePtr<SSL_SESSION> session =
        context_->ssl_client_session_cache()->Lookup(
            GetSessionCacheKey(/*dest_ip_addr=*/std::nullopt));
    if (!session) {
      // If a previous session negotiated an RSA cipher suite then it may have
      // been inserted into the cache keyed by both hostname and resolved IP
      // address. See https://crbug.com/969684.
      IPEndPoint peer_address;
      if (stream_socket_->GetPeerAddress(&peer_address) == OK) {
        session = context_->ssl_client_session_cache()->Lookup(
            GetSessionCacheKey(peer_address.address()));
      }
    }
    if (session)
      SSL_set_session(ssl_.get(), session.get());
  }

  transport_adapter_ = std::make_unique<SocketBIOAdapter>(
      stream_socket_.get(), kDefaultOpenSSLBufferSize,
      kDefaultOpenSSLBufferSize, this);
  BIO* transport_bio = transport_adapter_->bio();

  BIO_up_ref(transport_bio);  // SSL_set0_rbio takes ownership.
  SSL_set0_rbio(ssl_.get(), transport_bio);

  BIO_up_ref(transport_bio);  // SSL_set0_wbio takes ownership.
  SSL_set0_wbio(ssl_.get(), transport_bio);

  uint16_t version_min =
      ssl_config_.version_min_override.value_or(context_->config().version_min);
  uint16_t version_max =
      ssl_config_.version_max_override.value_or(context_->config().version_max);
  if (version_min < TLS1_2_VERSION || version_max < TLS1_2_VERSION) {
    // TLS versions before TLS 1.2 are no longer supported.
    return ERR_UNEXPECTED;
  }

  if (!SSL_set_min_proto_version(ssl_.get(), version_min) ||
      !SSL_set_max_proto_version(ssl_.get(), version_max)) {
    return ERR_UNEXPECTED;
  }

  SSL_set_early_data_enabled(ssl_.get(), ssl_config_.early_data_enabled);

  // OpenSSL defaults some options to on, others to off. To avoid ambiguity,
  // set everything we care about to an absolute value.
  SslSetClearMask options;
  options.ConfigureFlag(SSL_OP_NO_COMPRESSION, true);

  // TODO(joth): Set this conditionally, see http://crbug.com/55410
  options.ConfigureFlag(SSL_OP_LEGACY_SERVER_CONNECT, true);

  SSL_set_options(ssl_.get(), options.set_mask);
  SSL_clear_options(ssl_.get(), options.clear_mask);

  // Same as above, this time for the SSL mode.
  SslSetClearMask mode;

  mode.ConfigureFlag(SSL_MODE_RELEASE_BUFFERS, true);
  mode.ConfigureFlag(SSL_MODE_CBC_RECORD_SPLITTING, true);

  mode.ConfigureFlag(SSL_MODE_ENABLE_FALSE_START, true);

  SSL_set_mode(ssl_.get(), mode.set_mask);
  SSL_clear_mode(ssl_.get(), mode.clear_mask);

  // Use BoringSSL defaults, but disable 3DES and HMAC-SHA1 ciphers in ECDSA.
  // These are the remaining CBC-mode ECDSA ciphers.
  std::string command("ALL:!aPSK:!ECDSA+SHA1:!3DES");

  if (ssl_config_.require_ecdhe)
    command.append(":!kRSA");

  // Remove any disabled ciphers.
  for (uint16_t id : context_->config().disabled_cipher_suites) {
    const SSL_CIPHER* cipher = SSL_get_cipher_by_value(id);
    if (cipher) {
      command.append(":!");
      command.append(SSL_CIPHER_get_name(cipher));
    }
  }

  if (!SSL_set_strict_cipher_list(ssl_.get(), command.c_str())) {
    LOG(ERROR) << "SSL_set_cipher_list('" << command << "') failed";
    return ERR_UNEXPECTED;
  }

  // Disable SHA-1 server signatures.
  // TODO(crbug.com/boringssl/699): Once the default is flipped in BoringSSL, we
  // no longer need to override it.
  static const uint16_t kVerifyPrefs[] = {
      SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_RSA_PSS_RSAE_SHA256,
      SSL_SIGN_RSA_PKCS1_SHA256,       SSL_SIGN_ECDSA_SECP384R1_SHA384,
      SSL_SIGN_RSA_PSS_RSAE_SHA384,    SSL_SIGN_RSA_PKCS1_SHA384,
      SSL_SIGN_RSA_PSS_RSAE_SHA512,    SSL_SIGN_RSA_PKCS1_SHA512,
  };
  if (!SSL_set_verify_algorithm_prefs(ssl_.get(), kVerifyPrefs,
                                      std::size(kVerifyPrefs))) {
    return ERR_UNEXPECTED;
  }

  SSL_set_alps_use_new_codepoint(
      ssl_.get(),
      base::FeatureList::IsEnabled(features::kUseNewAlpsCodepointHttp2));

  if (!ssl_config_.alpn_protos.empty()) {
    std::vector<uint8_t> wire_protos =
        SerializeNextProtos(ssl_config_.alpn_protos);
    SSL_set_alpn_protos(ssl_.get(), wire_protos.data(), wire_protos.size());

    for (NextProto proto : ssl_config_.alpn_protos) {
      auto iter = ssl_config_.application_settings.find(proto);
      if (iter != ssl_config_.application_settings.end()) {
        const char* proto_string = NextProtoToString(proto);
        if (!SSL_add_application_settings(
                ssl_.get(), reinterpret_cast<const uint8_t*>(proto_string),
                strlen(proto_string), iter->second.data(),
                iter->second.size())) {
          return ERR_UNEXPECTED;
        }
      }
    }
  }

  SSL_enable_signed_cert_timestamps(ssl_.get());
  SSL_enable_ocsp_stapling(ssl_.get());

  // Configure BoringSSL to allow renegotiations. Once the initial handshake
  // completes, if renegotiations are not allowed, the default reject value will
  // be restored. This is done in this order to permit a BoringSSL
  // optimization. See https://crbug.com/boringssl/123. Use
  // ssl_renegotiate_explicit rather than ssl_renegotiate_freely so DoPeek()
  // does not trigger renegotiations.
  SSL_set_renegotiate_mode(ssl_.get(), ssl_renegotiate_explicit);

  SSL_set_shed_handshake_config(ssl_.get(), 1);

  // TODO(crbug.com/40089326), if |ssl_config_.privacy_mode| is enabled,
  // this should always continue with no client certificate.
  if (ssl_config_.privacy_mode == PRIVACY_MODE_ENABLED_WITHOUT_CLIENT_CERTS) {
    send_client_cert_ = true;
  } else {
    send_client_cert_ = context_->GetClientCertificate(
        host_and_port_, &client_cert_, &client_private_key_);
  }

  if (context_->config().ech_enabled) {
    // TODO(crbug.com/41482204): Enable this unconditionally.
    SSL_set_enable_ech_grease(ssl_.get(), 1);
  }
  if (!ssl_config_.ech_config_list.empty()) {
    DCHECK(context_->config().ech_enabled);
    net_log_.AddEvent(NetLogEventType::SSL_ECH_CONFIG_LIST, [&] {
      return base::Value::Dict().Set(
          "bytes", NetLogBinaryValue(ssl_config_.ech_config_list));
    });
    if (!SSL_set1_ech_config_list(ssl_.get(),
                                  ssl_config_.ech_config_list.data(),
                                  ssl_config_.ech_config_list.size())) {
      return ERR_INVALID_ECH_CONFIG_LIST;
    }
  }

  SSL_set_permute_extensions(ssl_.get(), 1);

  return OK;
}

void SSLClientSocketImpl::DoReadCallback(int rv) {
  // Since Run may result in Read being called, clear |user_read_callback_|
  // up front.
  if (rv > 0)
    was_ever_used_ = true;
  user_read_buf_ = nullptr;
  user_read_buf_len_ = 0;
  std::move(user_read_callback_).Run(rv);
}

void SSLClientSocketImpl::DoWriteCallback(int rv) {
  // Since Run may result in Write being called, clear |user_write_callback_|
  // up front.
  if (rv > 0)
    was_ever_used_ = true;
  user_write_buf_ = nullptr;
  user_write_buf_len_ = 0;
  std::move(user_write_callback_).Run(rv);
}

int SSLClientSocketImpl::DoHandshake() {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  int rv = SSL_do_handshake(ssl_.get());
  int net_error = OK;
  if (rv <= 0) {
    int ssl_error = SSL_get_error(ssl_.get(), rv);
    if (ssl_error == SSL_ERROR_WANT_X509_LOOKUP && !send_client_cert_) {
      return ERR_SSL_CLIENT_AUTH_CERT_NEEDED;
    }
    if (ssl_error == SSL_ERROR_WANT_PRIVATE_KEY_OPERATION) {
      DCHECK(client_private_key_);
      DCHECK_NE(kSSLClientSocketNoPendingResult, signature_result_);
      next_handshake_state_ = STATE_HANDSHAKE;
      return ERR_IO_PENDING;
    }
    if (ssl_error == SSL_ERROR_WANT_CERTIFICATE_VERIFY) {
      DCHECK(cert_verifier_request_);
      next_handshake_state_ = STATE_HANDSHAKE;
      return ERR_IO_PENDING;
    }

    OpenSSLErrorInfo error_info;
    net_error = MapLastOpenSSLError(ssl_error, err_tracer, &error_info);
    if (net_error == ERR_IO_PENDING) {
      // If not done, stay in this state
      next_handshake_state_ = STATE_HANDSHAKE;
      return ERR_IO_PENDING;
    }

    LOG(ERROR) << "handshake failed; returned " << rv << ", SSL error code "
               << ssl_error << ", net_error " << net_error;
    NetLogOpenSSLError(net_log_, NetLogEventType::SSL_HANDSHAKE_ERROR,
                       net_error, ssl_error, error_info);
  }

  next_handshake_state_ = STATE_HANDSHAKE_COMPLETE;
  return net_error;
}

int SSLClientSocketImpl::DoHandshakeComplete(int result) {
  if (result < 0)
    return result;

  if (in_confirm_handshake_) {
    next_handshake_state_ = STATE_NONE;
    return OK;
  }

  // If ECH overrode certificate verification to authenticate a fallback, using
  // the socket for application data would bypass server authentication.
  // BoringSSL will never complete the handshake in this case, so this should
  // not happen.
  CHECK(!used_ech_name_override_);

  const uint8_t* alpn_proto = nullptr;
  unsigned alpn_len = 0;
  SSL_get0_alpn_selected(ssl_.get(), &alpn_proto, &alpn_len);
  if (alpn_len > 0) {
    std::string_view proto(reinterpret_cast<const char*>(alpn_proto), alpn_len);
    negotiated_protocol_ = NextProtoFromString(proto);
  }

  RecordNegotiatedProtocol();

  const uint8_t* ocsp_response_raw;
  size_t ocsp_response_len;
  SSL_get0_ocsp_response(ssl_.get(), &ocsp_response_raw, &ocsp_response_len);
  set_stapled_ocsp_response_received(ocsp_response_len != 0);

  const uint8_t* sct_list;
  size_t sct_list_len;
  SSL_get0_signed_cert_timestamp_list(ssl_.get(), &sct_list, &sct_list_len);
  set_signed_cert_timestamps_received(sct_list_len != 0);

  if (!IsRenegotiationAllowed())
    SSL_set_renegotiate_mode(ssl_.get(), ssl_renegotiate_never);

  uint16_t signature_algorithm = SSL_get_peer_signat
"""


```