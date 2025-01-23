Response:
Let's break down the thought process for analyzing the provided C++ code of `embedded_test_server.cc`.

1. **Understand the Goal:** The primary objective is to understand the functionality of this code file within the Chromium networking stack, identify its relationship with JavaScript (if any), and highlight potential usage errors and debugging strategies. Crucially, it's the *first part* of a larger file.

2. **Initial Scan for Key Concepts:** Quickly skim the code for recognizable terms and patterns. Keywords like `EmbeddedTestServer`, `HTTP`, `HTTPS`, `SSL`, `certificate`, `request`, `response`, `socket`, `URL`, and file paths (like `net/test/`) immediately stand out. This suggests the file is about creating a lightweight, in-process server for testing network interactions.

3. **Identify Core Functionality (The "What"):**  Based on the keywords, the central function is likely to *simulate* a real web server. It can handle HTTP and HTTPS requests, manage certificates for TLS, and serve responses. The "embedded" part implies it's intended for testing scenarios, not as a production server.

4. **Analyze Key Classes and Methods:** Focus on the `EmbeddedTestServer` class and its prominent methods:
    * `Start()`, `InitializeAndListen()`, `StartAcceptingConnections()`:  These clearly handle server startup and network listening.
    * `ShutdownAndWaitUntilComplete()`:  Manages server shutdown.
    * `RegisterRequestHandler()`, `RegisterDefaultHandler()`:  Deal with how the server decides how to respond to incoming requests.
    * `GetURL()`:  Provides URLs for the simulated server.
    * `SetSSLConfig()`:  Configures SSL/TLS settings.
    * Methods related to certificates (`InitializeCertAndKeyFromFile()`, `GenerateCertAndKey()`, `GetCertificate()`): These manage the server's SSL certificates.
    * Methods for handling requests (`HandleRequest()`, `DispatchResponseToDelegate()`): These are the core logic for processing incoming HTTP requests.

5. **Look for JavaScript Connections:**  Carefully read through the code, looking for any direct interactions with JavaScript. In this *first part* of the file, there are *no explicit mentions* of JavaScript APIs or execution. However, the *purpose* of the `EmbeddedTestServer` – to serve web content – is directly related to what a browser (which executes JavaScript) interacts with.

6. **Infer JavaScript Relevance (The "Why" for JavaScript):** Even without direct JavaScript code, the server's functionality is crucial for testing web features. JavaScript code running in a browser will make requests to this server. Therefore, *the server's behavior directly impacts how JavaScript works in test environments*.

7. **Identify Logical Reasoning and Potential Inputs/Outputs:**  Focus on methods that involve decisions or transformations:
    * `ServeResponseForPath()`, `ServeResponseForSubPaths()`: These functions check the requested path and construct an HTTP response. *Input: request URL; Output: HTTP response (or null if the path doesn't match).*
    * The OCSP-related functions (`MaybeCreateOCSPResponse()`, `BuildOCSPResponse()`, etc.): These generate OCSP responses based on configuration. *Input: OCSP configuration, certificate details; Output: OCSP response data.*

8. **Spot Potential User/Programming Errors:** Consider common mistakes when setting up or using a test server:
    * Incorrect port number leading to server startup failure.
    * Forgetting to register request handlers, resulting in 404 errors.
    * Misconfiguring SSL certificates, causing connection errors.
    * Trying to start the server multiple times without shutting it down.
    * Setting the connection listener after the server has started.

9. **Trace User Operations (Debugging Clues):**  Think about how a developer might end up looking at this code during debugging:
    * A test is failing because the server isn't responding as expected.
    * SSL connections are failing.
    * The server is not serving the correct files.
    * A developer wants to understand how request routing works.
    * They suspect an issue with certificate generation or OCSP responses.

10. **Summarize the Functionality (For Part 1):** Condense the findings into a concise summary, highlighting the key purpose and capabilities of the `EmbeddedTestServer` as presented in this section of the code. Emphasize the test-focused nature.

11. **Structure the Answer:**  Organize the information logically according to the prompt's requirements:
    * List of functions.
    * JavaScript relationship with examples.
    * Logical reasoning with input/output.
    * Common usage errors.
    * Debugging steps.
    * Summary of Part 1.

12. **Review and Refine:** Read through the generated answer, ensuring clarity, accuracy, and completeness based on the provided code snippet. Double-check for any misinterpretations or omissions. For example, initially, I might focus too much on the technical details of socket management. However, considering the user's perspective and the overall purpose of the class, the request handling and certificate management aspects are equally important. Also, ensure the focus remains on *this specific part* of the file, as instructed.
这是 Chromium 网络栈中 `net/test/embedded_test_server/embedded_test_server.cc` 文件的第一部分。根据你提供的代码，我们可以归纳出以下功能：

**主要功能:**

1. **创建一个嵌入式 HTTP/HTTPS 测试服务器:**  这个文件的核心功能是实现一个轻量级的、用于测试的网络服务器。它可以模拟真实的 HTTP 和 HTTPS 服务器的行为，用于在测试环境中验证网络相关的代码。

2. **支持 HTTP 和 HTTPS:** 通过 `EmbeddedTestServer` 类的构造函数，可以指定服务器的类型为 HTTP (`TYPE_HTTP`) 或 HTTPS (`TYPE_HTTPS`)。

3. **管理连接和监听:**  `InitializeAndListen` 方法负责绑定地址和端口，并开始监听连接。`DoAcceptLoop` 方法（在后续部分）负责接受新的连接。

4. **处理 HTTP 请求:**  `HandleRequest` 方法是处理接收到的 HTTP 请求的核心。它会将请求传递给注册的请求处理器 (`request_handlers_`) 或默认的请求处理器 (`default_request_handlers_`)。

5. **提供灵活的请求处理机制:**
    * **注册特定的请求处理器:**  可以通过 `RegisterRequestHandler` 注册针对特定 URL 路径的处理器。
    * **注册默认的请求处理器:** 可以通过 `RegisterDefaultHandler` 注册用于处理所有未被特定处理器处理的请求。
    * **支持简单的响应:**  `ServeResponseForPath` 和 `ServeResponseForSubPaths` 提供创建简单 HTTP 响应的辅助函数。

6. **支持 SSL/TLS 配置 (HTTPS):**
    * **加载预定义的证书:** 可以通过 `SetSSLConfig` 方法配置服务器使用预先生成的证书（例如 `ok_cert.pem`）。
    * **动态生成证书:**  可以配置服务器动态生成证书，包括设置域名、IP 地址、密钥用途、扩展密钥用途、证书策略、SCT 信息等。
    * **OCSP Stapling 支持:**  支持配置 OCSP Stapling 的响应。
    * **AIA (Authority Information Access) 支持:**  可以配置服务器通过 AIA 提供中间证书和 OCSP 响应。

7. **提供服务器的 URL:**  `GetURL` 方法可以根据相对路径生成服务器的完整 URL。

8. **管理服务器生命周期:** `Start`, `StartAndReturnHandle`, `StartAcceptingConnections`, `ShutdownAndWaitUntilComplete` 等方法用于启动和关闭服务器。

**与 JavaScript 的关系举例说明:**

嵌入式测试服务器本身是用 C++ 编写的，不直接执行 JavaScript 代码。但是，它在前端 JavaScript 测试中扮演着至关重要的角色。JavaScript 代码运行在浏览器环境中，需要与服务器进行交互。`EmbeddedTestServer` 允许开发者在测试环境中模拟这些服务器交互，而无需部署真实的服务器。

**举例说明:**

假设你的 JavaScript 代码需要从服务器的 `/data.json` 路径获取 JSON 数据。

1. **C++ 代码设置服务器响应:** 你可以使用 `EmbeddedTestServer` 在 C++ 测试代码中注册一个处理器，使其在接收到 `/data.json` 的请求时返回特定的 JSON 数据。

   ```c++
   EmbeddedTestServer server(net::EmbeddedTestServer::TYPE_HTTP);
   server.RegisterRequestHandler(base::BindRepeating(
       [](const HttpRequest& request) -> std::unique_ptr<HttpResponse> {
         if (request.GetURL().path() == "/data.json") {
           auto http_response = std::make_unique<BasicHttpResponse>();
           http_response->set_code(HTTP_OK);
           http_response->set_content_type("application/json");
           http_response->set_content("{\"name\": \"test\", \"value\": 123}");
           return http_response;
         }
         return nullptr;
       }));
   ASSERT_TRUE(server.Start());
   ```

2. **JavaScript 代码发起请求:** 你的 JavaScript 测试代码会向服务器的 `/data.json` 发起请求。

   ```javascript
   fetch(server.GetURL("/data.json"))
     .then(response => response.json())
     .then(data => {
       // 断言 data.name === "test"
       // 断言 data.value === 123
     });
   ```

在这种情况下，`EmbeddedTestServer` 模拟了真实的服务器行为，使得 JavaScript 测试可以在一个受控的环境中进行，而无需依赖外部服务器。

**逻辑推理的假设输入与输出:**

* **假设输入:**  一个 HTTP GET 请求，路径为 `/resource`，服务器注册了一个处理 `/resource` 的处理器，返回状态码 200 和内容 "Hello World"。
* **输出:** `HandleRequest` 方法会调用注册的处理器，创建一个 `BasicHttpResponse` 对象，设置状态码为 200，内容类型为 "text/plain"，内容为 "Hello World"，最终通过 `DispatchResponseToDelegate` 发送回客户端。

* **假设输入 (HTTPS):** 一个 HTTPS 请求，服务器配置了 `CERT_OK` 证书。
* **输出:** 服务器会使用 `ok_cert.pem` 中的证书和私钥建立安全的 TLS 连接。客户端可以成功地与服务器建立 HTTPS 连接。

**涉及用户或编程常见的使用错误举例说明:**

1. **忘记注册请求处理器:** 如果用户启动了服务器，但是没有为特定的 URL 注册请求处理器，当客户端请求该 URL 时，`HandleRequest` 方法会找不到匹配的处理器，最终会返回一个 404 Not Found 的响应。

   ```c++
   EmbeddedTestServer server(net::EmbeddedTestServer::TYPE_HTTP);
   ASSERT_TRUE(server.Start());
   // 客户端请求 server.GetURL("/data.json") 会得到 404
   ```

2. **SSL 配置错误 (HTTPS):**  如果用户尝试启动 HTTPS 服务器，但没有正确配置 SSL 证书或私钥，`InitializeSSLServerContext` 方法可能会失败，导致服务器启动失败。例如，指定了一个不存在的证书文件名。

   ```c++
   EmbeddedTestServer server(net::EmbeddedTestServer::TYPE_HTTPS);
   net::SSLServerConfig ssl_config;
   // 错误：假设 "non_existent_cert.pem" 不存在
   server.SetSSLConfig(net::EmbeddedTestServer::CERT_OK, ssl_config);
   // InitializeSSLServerContext 可能会失败
   ASSERT_TRUE(server.Start()); // 可能失败
   ```

3. **在服务器启动后设置连接监听器:**  代码中明确指出 `ConnectionListener must be set before starting the server.`，如果在服务器启动后调用 `SetConnectionListener` 会导致 `DCHECK` 失败。

   ```c++
   EmbeddedTestServer server(net::EmbeddedTestServer::TYPE_HTTP);
   ASSERT_TRUE(server.Start());
   EmbeddedTestServerConnectionListener listener;
   // 错误：服务器已经启动
   server.SetConnectionListener(&listener); // 会导致 DCHECK 失败
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

当开发者在 Chromium 中进行网络相关的测试时，他们可能会使用 `EmbeddedTestServer` 来模拟服务器行为。以下是一些可能导致开发者查看这段代码的情况：

1. **测试失败，怀疑服务器行为异常:**  如果一个网络相关的测试失败了，开发者可能会怀疑是 `EmbeddedTestServer` 的行为不符合预期，例如没有正确响应请求，SSL 配置错误等。他们会查看 `embedded_test_server.cc` 来理解服务器的内部逻辑。

2. **调试 HTTPS 连接问题:**  如果测试涉及到 HTTPS 连接，开发者可能会查看 `InitializeSSLServerContext` 和相关的证书配置代码，以排查证书加载、生成或握手过程中的问题。

3. **理解请求处理流程:**  当需要理解 `EmbeddedTestServer` 如何接收和处理 HTTP 请求时，开发者会查看 `DoAcceptLoop`（在后续部分）和 `HandleRequest` 方法，以及请求处理器注册的机制。

4. **添加新的测试功能:**  当需要为网络相关的测试添加新的功能时，开发者可能会参考 `EmbeddedTestServer` 的现有代码，例如添加新的请求处理器、自定义 SSL 配置等。

5. **排查性能问题:**  虽然 `EmbeddedTestServer` 主要用于功能测试，但在某些情况下，开发者也可能会查看其代码来了解其性能特性，例如连接处理的效率。

**归纳一下它的功能 (第1部分):**

这段代码定义并实现了 `EmbeddedTestServer` 类的核心功能，使其能够作为一个用于网络测试的嵌入式 HTTP/HTTPS 服务器。它负责服务器的启动、监听、SSL/TLS 配置以及基本的请求处理框架。  它提供了灵活的方式来注册请求处理器，以便在测试中模拟各种服务器行为。  主要侧重于服务器的初始化和配置阶段。后续部分将涉及连接处理和更具体的请求分发逻辑。

### 提示词
```
这是目录为net/test/embedded_test_server/embedded_test_server.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/test/embedded_test_server/embedded_test_server.h"

#include <stdint.h>

#include <memory>
#include <optional>
#include <string_view>
#include <utility>

#include "base/files/file_path.h"
#include "base/functional/bind.h"
#include "base/functional/callback_forward.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/message_loop/message_pump_type.h"
#include "base/path_service.h"
#include "base/process/process_metrics.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/task/current_thread.h"
#include "base/task/single_thread_task_executor.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "base/threading/thread_restrictions.h"
#include "crypto/rsa_private_key.h"
#include "net/base/hex_utils.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/port_util.h"
#include "net/log/net_log_source.h"
#include "net/socket/next_proto.h"
#include "net/socket/ssl_server_socket.h"
#include "net/socket/stream_socket.h"
#include "net/socket/tcp_server_socket.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/ssl/ssl_info.h"
#include "net/ssl/ssl_server_config.h"
#include "net/test/cert_builder.h"
#include "net/test/cert_test_util.h"
#include "net/test/embedded_test_server/default_handlers.h"
#include "net/test/embedded_test_server/embedded_test_server_connection_listener.h"
#include "net/test/embedded_test_server/http_request.h"
#include "net/test/embedded_test_server/http_response.h"
#include "net/test/embedded_test_server/request_handler_util.h"
#include "net/test/key_util.h"
#include "net/test/revocation_builder.h"
#include "net/test/test_data_directory.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_frame_builder.h"
#include "third_party/boringssl/src/pki/extended_key_usage.h"
#include "url/origin.h"

namespace net::test_server {

namespace {

std::unique_ptr<HttpResponse> ServeResponseForPath(
    const std::string& expected_path,
    HttpStatusCode status_code,
    const std::string& content_type,
    const std::string& content,
    const HttpRequest& request) {
  if (request.GetURL().path() != expected_path)
    return nullptr;

  auto http_response = std::make_unique<BasicHttpResponse>();
  http_response->set_code(status_code);
  http_response->set_content_type(content_type);
  http_response->set_content(content);
  return http_response;
}

// Serves response for |expected_path| or any subpath of it.
// |expected_path| should not include a trailing "/".
std::unique_ptr<HttpResponse> ServeResponseForSubPaths(
    const std::string& expected_path,
    HttpStatusCode status_code,
    const std::string& content_type,
    const std::string& content,
    const HttpRequest& request) {
  if (request.GetURL().path() != expected_path &&
      !request.GetURL().path().starts_with(expected_path + "/")) {
    return nullptr;
  }

  auto http_response = std::make_unique<BasicHttpResponse>();
  http_response->set_code(status_code);
  http_response->set_content_type(content_type);
  http_response->set_content(content);
  return http_response;
}

bool MaybeCreateOCSPResponse(CertBuilder* target,
                             const EmbeddedTestServer::OCSPConfig& config,
                             std::string* out_response) {
  using OCSPResponseType = EmbeddedTestServer::OCSPConfig::ResponseType;

  if (!config.single_responses.empty() &&
      config.response_type != OCSPResponseType::kSuccessful) {
    // OCSPConfig contained single_responses for a non-successful response.
    return false;
  }

  if (config.response_type == OCSPResponseType::kOff) {
    *out_response = std::string();
    return true;
  }

  if (!target) {
    // OCSPConfig enabled but corresponding certificate is null.
    return false;
  }

  switch (config.response_type) {
    case OCSPResponseType::kOff:
      return false;
    case OCSPResponseType::kMalformedRequest:
      *out_response = BuildOCSPResponseError(
          bssl::OCSPResponse::ResponseStatus::MALFORMED_REQUEST);
      return true;
    case OCSPResponseType::kInternalError:
      *out_response = BuildOCSPResponseError(
          bssl::OCSPResponse::ResponseStatus::INTERNAL_ERROR);
      return true;
    case OCSPResponseType::kTryLater:
      *out_response =
          BuildOCSPResponseError(bssl::OCSPResponse::ResponseStatus::TRY_LATER);
      return true;
    case OCSPResponseType::kSigRequired:
      *out_response = BuildOCSPResponseError(
          bssl::OCSPResponse::ResponseStatus::SIG_REQUIRED);
      return true;
    case OCSPResponseType::kUnauthorized:
      *out_response = BuildOCSPResponseError(
          bssl::OCSPResponse::ResponseStatus::UNAUTHORIZED);
      return true;
    case OCSPResponseType::kInvalidResponse:
      *out_response = "3";
      return true;
    case OCSPResponseType::kInvalidResponseData:
      *out_response =
          BuildOCSPResponseWithResponseData(target->issuer()->GetKey(),
                                            // OCTET_STRING { "not ocsp data" }
                                            "\x04\x0dnot ocsp data");
      return true;
    case OCSPResponseType::kSuccessful:
      break;
  }

  base::Time now = base::Time::Now();
  base::Time target_not_before, target_not_after;
  if (!target->GetValidity(&target_not_before, &target_not_after))
    return false;
  base::Time produced_at;
  using OCSPProduced = EmbeddedTestServer::OCSPConfig::Produced;
  switch (config.produced) {
    case OCSPProduced::kValid:
      produced_at = std::max(now - base::Days(1), target_not_before);
      break;
    case OCSPProduced::kBeforeCert:
      produced_at = target_not_before - base::Days(1);
      break;
    case OCSPProduced::kAfterCert:
      produced_at = target_not_after + base::Days(1);
      break;
  }

  std::vector<OCSPBuilderSingleResponse> responses;
  for (const auto& config_response : config.single_responses) {
    OCSPBuilderSingleResponse response;
    response.serial = target->GetSerialNumber();
    if (config_response.serial ==
        EmbeddedTestServer::OCSPConfig::SingleResponse::Serial::kMismatch) {
      response.serial ^= 1;
    }
    response.cert_status = config_response.cert_status;
    // |revocation_time| is ignored if |cert_status| is not REVOKED.
    response.revocation_time = now - base::Days(1000);

    using OCSPDate = EmbeddedTestServer::OCSPConfig::SingleResponse::Date;
    switch (config_response.ocsp_date) {
      case OCSPDate::kValid:
        response.this_update = now - base::Days(1);
        response.next_update = response.this_update + base::Days(7);
        break;
      case OCSPDate::kOld:
        response.this_update = now - base::Days(8);
        response.next_update = response.this_update + base::Days(7);
        break;
      case OCSPDate::kEarly:
        response.this_update = now + base::Days(1);
        response.next_update = response.this_update + base::Days(7);
        break;
      case OCSPDate::kLong:
        response.this_update = now - base::Days(365);
        response.next_update = response.this_update + base::Days(366);
        break;
      case OCSPDate::kLonger:
        response.this_update = now - base::Days(367);
        response.next_update = response.this_update + base::Days(368);
        break;
    }

    responses.push_back(response);
  }
  *out_response =
      BuildOCSPResponse(target->issuer()->GetSubject(),
                        target->issuer()->GetKey(), produced_at, responses);
  return true;
}

void DispatchResponseToDelegate(std::unique_ptr<HttpResponse> response,
                                base::WeakPtr<HttpResponseDelegate> delegate) {
  HttpResponse* const response_ptr = response.get();
  delegate->AddResponse(std::move(response));
  response_ptr->SendResponse(delegate);
}

}  // namespace

EmbeddedTestServerHandle::EmbeddedTestServerHandle(
    EmbeddedTestServerHandle&& other) {
  operator=(std::move(other));
}

EmbeddedTestServerHandle& EmbeddedTestServerHandle::operator=(
    EmbeddedTestServerHandle&& other) {
  EmbeddedTestServerHandle temporary;
  std::swap(other.test_server_, temporary.test_server_);
  std::swap(temporary.test_server_, test_server_);
  return *this;
}

EmbeddedTestServerHandle::EmbeddedTestServerHandle(
    EmbeddedTestServer* test_server)
    : test_server_(test_server) {}

EmbeddedTestServerHandle::~EmbeddedTestServerHandle() {
  if (test_server_)
    CHECK(test_server_->ShutdownAndWaitUntilComplete());
}

EmbeddedTestServer::OCSPConfig::OCSPConfig() = default;
EmbeddedTestServer::OCSPConfig::OCSPConfig(ResponseType response_type)
    : response_type(response_type) {}
EmbeddedTestServer::OCSPConfig::OCSPConfig(
    std::vector<SingleResponse> single_responses,
    Produced produced)
    : response_type(ResponseType::kSuccessful),
      produced(produced),
      single_responses(std::move(single_responses)) {}
EmbeddedTestServer::OCSPConfig::OCSPConfig(const OCSPConfig&) = default;
EmbeddedTestServer::OCSPConfig::OCSPConfig(OCSPConfig&&) = default;
EmbeddedTestServer::OCSPConfig::~OCSPConfig() = default;
EmbeddedTestServer::OCSPConfig& EmbeddedTestServer::OCSPConfig::operator=(
    const OCSPConfig&) = default;
EmbeddedTestServer::OCSPConfig& EmbeddedTestServer::OCSPConfig::operator=(
    OCSPConfig&&) = default;

EmbeddedTestServer::ServerCertificateConfig::ServerCertificateConfig() =
    default;
EmbeddedTestServer::ServerCertificateConfig::ServerCertificateConfig(
    const ServerCertificateConfig&) = default;
EmbeddedTestServer::ServerCertificateConfig::ServerCertificateConfig(
    ServerCertificateConfig&&) = default;
EmbeddedTestServer::ServerCertificateConfig::~ServerCertificateConfig() =
    default;
EmbeddedTestServer::ServerCertificateConfig&
EmbeddedTestServer::ServerCertificateConfig::operator=(
    const ServerCertificateConfig&) = default;
EmbeddedTestServer::ServerCertificateConfig&
EmbeddedTestServer::ServerCertificateConfig::operator=(
    ServerCertificateConfig&&) = default;

EmbeddedTestServer::EmbeddedTestServer() : EmbeddedTestServer(TYPE_HTTP) {}

EmbeddedTestServer::EmbeddedTestServer(Type type,
                                       HttpConnection::Protocol protocol)
    : is_using_ssl_(type == TYPE_HTTPS), protocol_(protocol) {
  DCHECK(thread_checker_.CalledOnValidThread());
  // HTTP/2 is only valid by negotiation via TLS ALPN
  DCHECK(protocol_ != HttpConnection::Protocol::kHttp2 || type == TYPE_HTTPS);

  if (!is_using_ssl_)
    return;
  scoped_test_root_ = RegisterTestCerts();
}

EmbeddedTestServer::~EmbeddedTestServer() {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (Started())
    CHECK(ShutdownAndWaitUntilComplete());

  {
    base::ScopedAllowBaseSyncPrimitivesForTesting allow_wait_for_thread_join;
    io_thread_.reset();
  }
}

ScopedTestRoot EmbeddedTestServer::RegisterTestCerts() {
  base::ScopedAllowBlockingForTesting allow_blocking;
  auto root = ImportCertFromFile(GetRootCertPemPath());
  if (!root)
    return ScopedTestRoot();
  return ScopedTestRoot(root);
}

void EmbeddedTestServer::SetConnectionListener(
    EmbeddedTestServerConnectionListener* listener) {
  DCHECK(!io_thread_)
      << "ConnectionListener must be set before starting the server.";
  connection_listener_ = listener;
}

EmbeddedTestServerHandle EmbeddedTestServer::StartAndReturnHandle(int port) {
  bool result = Start(port);
  return result ? EmbeddedTestServerHandle(this) : EmbeddedTestServerHandle();
}

bool EmbeddedTestServer::Start(int port, std::string_view address) {
  bool success = InitializeAndListen(port, address);
  if (success)
    StartAcceptingConnections();
  return success;
}

bool EmbeddedTestServer::InitializeAndListen(int port,
                                             std::string_view address) {
  DCHECK(!Started());

  const int max_tries = 5;
  int num_tries = 0;
  bool is_valid_port = false;

  do {
    if (++num_tries > max_tries) {
      LOG(ERROR) << "Failed to listen on a valid port after " << max_tries
                 << " attempts.";
      listen_socket_.reset();
      return false;
    }

    listen_socket_ = std::make_unique<TCPServerSocket>(nullptr, NetLogSource());

    int result =
        listen_socket_->ListenWithAddressAndPort(address.data(), port, 10);
    if (result) {
      LOG(ERROR) << "Listen failed: " << ErrorToString(result);
      listen_socket_.reset();
      return false;
    }

    result = listen_socket_->GetLocalAddress(&local_endpoint_);
    if (result != OK) {
      LOG(ERROR) << "GetLocalAddress failed: " << ErrorToString(result);
      listen_socket_.reset();
      return false;
    }

    port_ = local_endpoint_.port();
    is_valid_port |= net::IsPortAllowedForScheme(
        port_, is_using_ssl_ ? url::kHttpsScheme : url::kHttpScheme);
  } while (!is_valid_port);

  if (is_using_ssl_) {
    base_url_ = GURL("https://" + local_endpoint_.ToString());
    if (cert_ == CERT_MISMATCHED_NAME || cert_ == CERT_COMMON_NAME_IS_DOMAIN) {
      base_url_ = GURL(
          base::StringPrintf("https://localhost:%d", local_endpoint_.port()));
    }
  } else {
    base_url_ = GURL("http://" + local_endpoint_.ToString());
  }

  listen_socket_->DetachFromThread();

  if (is_using_ssl_ && !InitializeSSLServerContext())
    return false;

  return true;
}

bool EmbeddedTestServer::UsingStaticCert() const {
  return !GetCertificateName().empty();
}

bool EmbeddedTestServer::InitializeCertAndKeyFromFile() {
  base::ScopedAllowBlockingForTesting allow_blocking;
  base::FilePath certs_dir(GetTestCertsDirectory());
  std::string cert_name = GetCertificateName();
  if (cert_name.empty())
    return false;

  x509_cert_ = CreateCertificateChainFromFile(certs_dir, cert_name,
                                              X509Certificate::FORMAT_AUTO);
  if (!x509_cert_)
    return false;

  private_key_ =
      key_util::LoadEVP_PKEYFromPEM(certs_dir.AppendASCII(cert_name));
  return !!private_key_;
}

bool EmbeddedTestServer::GenerateCertAndKey() {
  // Create AIA server and start listening. Need to have the socket initialized
  // so the URL can be put in the AIA records of the generated certs.
  aia_http_server_ = std::make_unique<EmbeddedTestServer>(TYPE_HTTP);
  if (!aia_http_server_->InitializeAndListen())
    return false;

  base::ScopedAllowBlockingForTesting allow_blocking;
  base::FilePath certs_dir(GetTestCertsDirectory());
  auto now = base::Time::Now();

  std::unique_ptr<CertBuilder> root;
  switch (cert_config_.root) {
    case RootType::kTestRootCa:
      root = CertBuilder::FromStaticCertFile(
          certs_dir.AppendASCII("root_ca_cert.pem"));
      break;
    case RootType::kUniqueRoot:
      root = std::make_unique<CertBuilder>(nullptr, nullptr);
      root->SetValidity(now - base::Days(100), now + base::Days(1000));
      root->SetBasicConstraints(/*is_ca=*/true, /*path_len=*/-1);
      root->SetKeyUsages(
          {bssl::KEY_USAGE_BIT_KEY_CERT_SIGN, bssl::KEY_USAGE_BIT_CRL_SIGN});
      if (!cert_config_.root_dns_names.empty()) {
        root->SetSubjectAltNames(cert_config_.root_dns_names, {});
      }
      break;
  }

  // Will be nullptr if cert_config_.intermediate == kNone.
  std::unique_ptr<CertBuilder> intermediate;
  std::unique_ptr<CertBuilder> leaf;

  if (cert_config_.intermediate != IntermediateType::kNone) {
    intermediate = std::make_unique<CertBuilder>(nullptr, root.get());
    intermediate->SetValidity(now - base::Days(100), now + base::Days(1000));
    intermediate->SetBasicConstraints(/*is_ca=*/true, /*path_len=*/-1);
    intermediate->SetKeyUsages(
        {bssl::KEY_USAGE_BIT_KEY_CERT_SIGN, bssl::KEY_USAGE_BIT_CRL_SIGN});

    leaf = std::make_unique<CertBuilder>(nullptr, intermediate.get());
  } else {
    leaf = std::make_unique<CertBuilder>(nullptr, root.get());
  }
  std::vector<GURL> leaf_ca_issuers_urls;
  std::vector<GURL> leaf_ocsp_urls;

  leaf->SetValidity(now - base::Days(1), now + base::Days(20));
  leaf->SetBasicConstraints(/*is_ca=*/cert_config_.leaf_is_ca, /*path_len=*/-1);
  leaf->SetExtendedKeyUsages({bssl::der::Input(bssl::kServerAuth)});

  if (!cert_config_.policy_oids.empty()) {
    leaf->SetCertificatePolicies(cert_config_.policy_oids);
    if (intermediate)
      intermediate->SetCertificatePolicies(cert_config_.policy_oids);
  }

  if (!cert_config_.dns_names.empty() || !cert_config_.ip_addresses.empty()) {
    leaf->SetSubjectAltNames(cert_config_.dns_names, cert_config_.ip_addresses);
  } else {
    leaf->SetSubjectAltNames({}, {net::IPAddress::IPv4Localhost()});
  }

  if (!cert_config_.key_usages.empty()) {
    leaf->SetKeyUsages(cert_config_.key_usages);
  } else {
    leaf->SetKeyUsages({bssl::KEY_USAGE_BIT_DIGITAL_SIGNATURE});
  }

  if (!cert_config_.embedded_scts.empty()) {
    leaf->SetSctConfig(cert_config_.embedded_scts);
  }

  const std::string leaf_serial_text =
      base::NumberToString(leaf->GetSerialNumber());
  const std::string intermediate_serial_text =
      intermediate ? base::NumberToString(intermediate->GetSerialNumber()) : "";

  std::string ocsp_response;
  if (!MaybeCreateOCSPResponse(leaf.get(), cert_config_.ocsp_config,
                               &ocsp_response)) {
    return false;
  }
  if (!ocsp_response.empty()) {
    std::string ocsp_path = "/ocsp/" + leaf_serial_text;
    leaf_ocsp_urls.push_back(aia_http_server_->GetURL(ocsp_path));
    aia_http_server_->RegisterRequestHandler(
        base::BindRepeating(ServeResponseForSubPaths, ocsp_path, HTTP_OK,
                            "application/ocsp-response", ocsp_response));
  }

  std::string stapled_ocsp_response;
  if (!MaybeCreateOCSPResponse(leaf.get(), cert_config_.stapled_ocsp_config,
                               &stapled_ocsp_response)) {
    return false;
  }
  if (!stapled_ocsp_response.empty()) {
    ssl_config_.ocsp_response = std::vector<uint8_t>(
        stapled_ocsp_response.begin(), stapled_ocsp_response.end());
  }

  std::string intermediate_ocsp_response;
  if (!MaybeCreateOCSPResponse(intermediate.get(),
                               cert_config_.intermediate_ocsp_config,
                               &intermediate_ocsp_response)) {
    return false;
  }
  if (!intermediate_ocsp_response.empty()) {
    std::string intermediate_ocsp_path = "/ocsp/" + intermediate_serial_text;
    intermediate->SetCaIssuersAndOCSPUrls(
        {}, {aia_http_server_->GetURL(intermediate_ocsp_path)});
    aia_http_server_->RegisterRequestHandler(base::BindRepeating(
        ServeResponseForSubPaths, intermediate_ocsp_path, HTTP_OK,
        "application/ocsp-response", intermediate_ocsp_response));
  }

  if (cert_config_.intermediate == IntermediateType::kByAIA) {
    std::string ca_issuers_path = "/ca_issuers/" + intermediate_serial_text;
    leaf_ca_issuers_urls.push_back(aia_http_server_->GetURL(ca_issuers_path));

    // Setup AIA server to serve the intermediate referred to by the leaf.
    aia_http_server_->RegisterRequestHandler(
        base::BindRepeating(ServeResponseForPath, ca_issuers_path, HTTP_OK,
                            "application/pkix-cert", intermediate->GetDER()));
  }

  if (!leaf_ca_issuers_urls.empty() || !leaf_ocsp_urls.empty()) {
    leaf->SetCaIssuersAndOCSPUrls(leaf_ca_issuers_urls, leaf_ocsp_urls);
  }

  if (cert_config_.intermediate == IntermediateType::kByAIA ||
      cert_config_.intermediate == IntermediateType::kMissing) {
    // Server certificate chain does not include the intermediate.
    x509_cert_ = leaf->GetX509Certificate();
  } else {
    // Server certificate chain will include the intermediate, if there is one.
    x509_cert_ = leaf->GetX509CertificateChain();
  }

  if (intermediate) {
    intermediate_ = intermediate->GetX509Certificate();
  }

  root_ = root->GetX509Certificate();

  private_key_ = bssl::UpRef(leaf->GetKey());

  // If this server is already accepting connections but is being reconfigured,
  // start the new AIA server now. Otherwise, wait until
  // StartAcceptingConnections so that this server and the AIA server start at
  // the same time. (If the test only called InitializeAndListen they expect no
  // threads to be created yet.)
  if (io_thread_)
    aia_http_server_->StartAcceptingConnections();

  return true;
}

bool EmbeddedTestServer::InitializeSSLServerContext() {
  if (UsingStaticCert()) {
    if (!InitializeCertAndKeyFromFile())
      return false;
  } else {
    if (!GenerateCertAndKey())
      return false;
  }

  if (protocol_ == HttpConnection::Protocol::kHttp2) {
    ssl_config_.alpn_protos = {NextProto::kProtoHTTP2};
    if (!alps_accept_ch_.empty()) {
      base::StringPairs origin_accept_ch;
      size_t frame_size = spdy::kFrameHeaderSize;
      // Figure out size and generate origins
      for (const auto& pair : alps_accept_ch_) {
        std::string_view hostname = pair.first;
        std::string accept_ch = pair.second;

        GURL url = hostname.empty() ? GetURL("/") : GetURL(hostname, "/");
        std::string origin = url::Origin::Create(url).Serialize();

        frame_size += accept_ch.size() + origin.size() +
                      (sizeof(uint16_t) * 2);  // = Origin-Len + Value-Len

        origin_accept_ch.push_back({std::move(origin), std::move(accept_ch)});
      }

      spdy::SpdyFrameBuilder builder(frame_size);
      builder.BeginNewFrame(spdy::SpdyFrameType::ACCEPT_CH, 0, 0);
      for (const auto& pair : origin_accept_ch) {
        std::string_view origin = pair.first;
        std::string_view accept_ch = pair.second;

        builder.WriteUInt16(origin.size());
        builder.WriteBytes(origin.data(), origin.size());

        builder.WriteUInt16(accept_ch.size());
        builder.WriteBytes(accept_ch.data(), accept_ch.size());
      }

      spdy::SpdySerializedFrame serialized_frame = builder.take();
      DCHECK_EQ(frame_size, serialized_frame.size());

      ssl_config_.application_settings[NextProto::kProtoHTTP2] =
          std::vector<uint8_t>(
              serialized_frame.data(),
              serialized_frame.data() + serialized_frame.size());

      ssl_config_.client_hello_callback_for_testing =
          base::BindRepeating([](const SSL_CLIENT_HELLO* client_hello) {
            // Configure the server to use the ALPS codepoint that the client
            // offered.
            const uint8_t* unused_extension_bytes;
            size_t unused_extension_len;
            int use_alps_new_codepoint = SSL_early_callback_ctx_extension_get(
                client_hello, TLSEXT_TYPE_application_settings,
                &unused_extension_bytes, &unused_extension_len);
            // Make sure we use the right ALPS codepoint.
            SSL_set_alps_use_new_codepoint(client_hello->ssl,
                                           use_alps_new_codepoint);
            return true;
          });
    }
  }

  context_ =
      CreateSSLServerContext(x509_cert_.get(), private_key_.get(), ssl_config_);
  return true;
}

EmbeddedTestServerHandle
EmbeddedTestServer::StartAcceptingConnectionsAndReturnHandle() {
  StartAcceptingConnections();
  return EmbeddedTestServerHandle(this);
}

void EmbeddedTestServer::StartAcceptingConnections() {
  DCHECK(Started());
  DCHECK(!io_thread_) << "Server must not be started while server is running";

  if (aia_http_server_)
    aia_http_server_->StartAcceptingConnections();

  base::Thread::Options thread_options;
  thread_options.message_pump_type = base::MessagePumpType::IO;
  io_thread_ = std::make_unique<base::Thread>("EmbeddedTestServer IO Thread");
  CHECK(io_thread_->StartWithOptions(std::move(thread_options)));
  CHECK(io_thread_->WaitUntilThreadStarted());

  io_thread_->task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&EmbeddedTestServer::DoAcceptLoop,
                                base::Unretained(this)));
}

bool EmbeddedTestServer::ShutdownAndWaitUntilComplete() {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!io_thread_) {
    // Can't stop a server that never started.
    return true;
  }

  // Ensure that the AIA HTTP server is no longer Started().
  bool aia_http_server_not_started = true;
  if (aia_http_server_ && aia_http_server_->Started()) {
    aia_http_server_not_started =
        aia_http_server_->ShutdownAndWaitUntilComplete();
  }

  // Return false if either this or the AIA HTTP server are still Started().
  return PostTaskToIOThreadAndWait(
             base::BindOnce(&EmbeddedTestServer::ShutdownOnIOThread,
                            base::Unretained(this))) &&
         aia_http_server_not_started;
}

// static
base::FilePath EmbeddedTestServer::GetRootCertPemPath() {
  return GetTestCertsDirectory().AppendASCII("root_ca_cert.pem");
}

void EmbeddedTestServer::ShutdownOnIOThread() {
  DCHECK(io_thread_->task_runner()->BelongsToCurrentThread());
  weak_factory_.InvalidateWeakPtrs();
  shutdown_closures_.Notify();
  listen_socket_.reset();
  connections_.clear();
}

HttpConnection* EmbeddedTestServer::GetConnectionForSocket(
    const StreamSocket* socket) {
  auto it = connections_.find(socket);
  if (it != connections_.end()) {
    return it->second.get();
  }
  return nullptr;
}

void EmbeddedTestServer::HandleRequest(
    base::WeakPtr<HttpResponseDelegate> delegate,
    std::unique_ptr<HttpRequest> request,
    const StreamSocket* socket) {
  DCHECK(io_thread_->task_runner()->BelongsToCurrentThread());
  request->base_url = base_url_;

  for (const auto& monitor : request_monitors_)
    monitor.Run(*request);

  HttpConnection* connection = GetConnectionForSocket(socket);
  CHECK(connection);

  if (auth_handler_) {
    auto auth_result = auth_handler_.Run(*request);
    if (auth_result) {
      DispatchResponseToDelegate(std::move(auth_result), delegate);
      return;
    }
  }

  for (const auto& upgrade_request_handler : upgrade_request_handlers_) {
    auto upgrade_response = upgrade_request_handler.Run(*request, connection);
    if (upgrade_response.has_value()) {
      if (upgrade_response.value() == UpgradeResult::kUpgraded) {
        connections_.erase(socket);
        return;
      }
    } else {
      CHECK(upgrade_response.error());
      DispatchResponseToDelegate(std::move(upgrade_response.error()), delegate);
      return;
    }
  }

  std::unique_ptr<HttpResponse> response;

  for (const auto& handler : request_handlers_) {
    response = handler.Run(*request);
    if (response)
      break;
  }

  if (!response) {
    for (const auto& handler : default_request_handlers_) {
      response = handler.Run(*request);
      if (response)
        break;
    }
  }

  if (!response) {
    LOG(WARNING) << "Request not handled. Returning 404: "
                 << request->relative_url;
    auto not_found_response = std::make_unique<BasicHttpResponse>();
    not_found_response->set_code(HTTP_NOT_FOUND);
    response = std::move(not_found_response);
  }

  DispatchResponseToDelegate(std::move(response), delegate);
}

GURL EmbeddedTestServer::GetURL(std::string_view relative_url) const {
  DCHECK(Started()) << "You must start the server first.";
  DCHECK(relative_url.starts_with("/")) << relative_url;
  return base_url_.Resolve(relative_url);
}

GURL EmbeddedTestServer::GetURL(std::string_view hostname,
                                std::string_view relative_url) const {
  GURL local_url = GetURL(relative_url);
  GURL::Replacements replace_host;
  replace_host.SetHostStr(hostname);
  return local_url.ReplaceComponents(replace_host);
}

url::Origin EmbeddedTestServer::GetOrigin(
    const std::optional<std::string>& hostname) const {
  if (hostname)
    return url::Origin::Create(GetURL(*hostname, "/"));
  return url::Origin::Create(base_url_);
}

bool EmbeddedTestServer::GetAddressList(AddressList* address_list) const {
  *address_list = AddressList(local_endpoint_);
  return true;
}

std::string EmbeddedTestServer::GetIPLiteralString() const {
  return local_endpoint_.address().ToString();
}

void EmbeddedTestServer::SetSSLConfigInternal(
    ServerCertificate cert,
    const ServerCertificateConfig* cert_config,
    const SSLServerConfig& ssl_config) {
  DCHECK(!Started());
  cert_ = cert;
  DCHECK(!cert_config || cert == CERT_AUTO);
  cert_config_ = cert_config ? *cert_config : ServerCertificateConfig();
  x509_cert_ = nullptr;
  private_key_ = nullptr;
  ssl_config_ = ssl_config;
}

void EmbeddedTestServer::SetSSLConfig(ServerCertificate cert,
                                      const SSLServerConfig& ssl_config) {
  SetSSLConfigInternal(cert, /*cert_config=*/nullptr, ssl_config);
}

void EmbeddedTestServer::SetSSLConfig(ServerCertificate cert) {
  SetSSLConfigInternal(cert, /*cert_config=*/nullptr, SSLServerConfig());
}

void EmbeddedTestServer::SetSSLConfig(
    const ServerCertificateConfig& cert_config,
    const SSLServerConfig& ssl_config) {
  SetSSLConfigInternal(CERT_AUTO, &cert_config, ssl_config);
}

void EmbeddedTestServer::SetSSLConfig(
    const ServerCertificateConfig& cert_config) {
  SetSSLConfigInternal(CERT_AUTO, &cert_config, SSLServerConfig());
}

void EmbeddedTestServer::SetCertHostnames(std::vector<std::string> hostnames) {
  ServerCertificateConfig cert_config;
  cert_config.dns_names = std::move(hostnames);
  cert_config.ip_addresses = {net::IPAddress::IPv4Localhost()};
  SetSSLConfig(cert_config);
}

bool EmbeddedTestServer::ResetSSLConfigOnIOThread(
    ServerCertificate cert,
    const SSLServerConfig& ssl_config) {
  cert_ = cert;
  cert_config_ = ServerCertificateConfig();
  ssl_config_ = ssl_config;
  connections_.clear();
  return InitializeSSLServerContext();
}

bool EmbeddedTestServer::ResetSSLConfig(ServerCertificate cert,
                                        const SSLServerConfig& ssl_config) {
  return PostTaskToIOThreadAndWaitWithResult(
      base::BindOnce(&EmbeddedTestServer::ResetSSLConfigOnIOThread,
                     base::Unretained(this), cert, ssl_config));
}

std::string EmbeddedTestServer::GetCertificateName() const {
  DCHECK(is_using_ssl_);
  switch (cert_) {
    case CERT_OK:
    case CERT_MISMATCHED_NAME:
      return "ok_cert.pem";
    case CERT_COMMON_NAME_IS_DOMAIN:
      return "localhost_cert.pem";
    case CERT_EXPIRED:
      return "expired_cert.pem";
    case CERT_CHAIN_WRONG_ROOT:
      // This chain uses its own dedicated test root certificate to avoid
      // side-effects that may affect testing.
      return "redundant-server-chain.pem";
    case CERT_COMMON_NAME_ONLY:
      return "common_name_only.pem";
    case CERT_SHA1_LEAF:
      return "sha1_leaf.pem";
    case CERT_OK_BY_INTERMEDIATE:
      return "ok_cert_by_intermediate.pem";
    case CERT_BAD_VALIDITY:
      return "bad_validity.pem";
    case CERT_TEST_NAMES:
      return "test_names.pem";
    case CERT_KEY_USAGE_RSA_ENCIPHERMENT:
      return "key_usage_rsa_keyencipherment.pem";
    case CERT_KEY_USAGE_RSA_DIGITAL_SIGNATURE:
      return "key_usage_rsa_digitalsignature.pem";
    case CERT_AUTO:
      return std::string();
  }

  return "ok_cert.pem";
}

scoped_refptr<X509Certificate> EmbeddedTestServer::GetCertificate() {
  DCHECK(is_using_ssl_);
  if (!x509_cert_) {
    // Some tests want to get the certificate before the server has been
    // initialized, so load it now if necessary. This is only possible if using
    // a static certificate.
    // TODO(mattm): change contract to require initializing first in all cases,
    // update callers.
    CHECK(UsingStaticCert());
    // TODO(mattm): change contract to return nullptr on error instead of
    // CHECKing, update callers.
    CHECK(InitializeCertAndKeyFromFile());
  }
  return x509_cert_;
}

scoped_refptr<X509Certificate> EmbeddedTestServer::GetGeneratedIntermediate() {
  DCHECK(is_using_ssl_);
  DCHECK(!UsingStaticCert());
  return intermediate_;
}

scoped_refptr<X509Certificate> EmbeddedTestServer::GetRoot() {
  DCHECK(is_using_ssl_);
  return root_;
}

void EmbeddedTestServer::ServeFilesFromDirectory(
    const base::FilePath& directory) {
  RegisterDefaultHandler(base::BindRepeating(&HandleFileRequest, directory));
}

void EmbeddedTestServer::ServeFilesFromSourceDirectory(
    std::string_view relative) {
  base::FilePath test_data_dir;
  CHECK(base::PathService::Get(base::DIR_SRC_TEST_DATA_ROOT, &test_data_dir));
  ServeFilesFromDirectory(test_data_dir.AppendASCII(relative));
}

void EmbeddedTestServer::ServeFilesFromSourceDirectory(
    const base::File
```