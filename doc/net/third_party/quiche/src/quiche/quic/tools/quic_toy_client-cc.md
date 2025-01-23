Response:
Let's break down the thought process for analyzing the `quic_toy_client.cc` file.

1. **Understanding the Core Purpose:** The initial comments are crucial. "A binary wrapper for QuicClient."  This immediately tells us it's a command-line tool for interacting with a QUIC server. The "connects to a host using QUIC, sends a request, displays response" reinforces this. The usage examples further solidify this understanding.

2. **Identifying Key Functionality through Command-Line Flags:** The extensive list of `DEFINE_QUICHE_COMMAND_LINE_FLAG` is a treasure trove of information. Each flag hints at a specific capability of the tool. I would systematically go through these, categorizing them:

    * **Connection Basics:** `host`, `port`, `ip_version_for_host_lookup`
    * **Request Details:** `body`, `body_hex`, `headers`
    * **Output Control:** `quiet`, `output_resolved_server_address`
    * **QUIC Protocol Specifics:** `quic_version`, `connection_options`, `client_connection_options`, `version_mismatch_ok`, `force_version_negotiation`, `multi_packet_chlo`, `initial_mtu`
    * **Request Repetition:** `num_requests`, `ignore_errors`
    * **Security:** `disable_certificate_verification`, `default_client_cert`, `default_client_cert_key`, `signing_algorithms_pref`
    * **Response Handling:** `redirect_is_success`, `drop_response_body`
    * **Connection Management:** `disable_port_changes`, `one_connection_per_request`
    * **Connection IDs:** `server_connection_id`, `server_connection_id_length`, `client_connection_id_length`
    * **Timeouts/Limits:** `max_time_before_crypto_handshake_ms`, `max_inbound_header_list_size`
    * **Network Interface:** `interface_name`

3. **Tracing the Execution Flow:** The `SendRequestsAndPrintResponses` function is the heart of the client. I'd follow the logic step-by-step:

    * **Parse URL and Flags:** Extract target host, port, and other settings from the command line.
    * **Version Handling:** Determine the QUIC versions to use.
    * **Client Initialization:** Create a `QuicSpdyClientBase` object, setting up security (proof verification, client certificates), connection options, and MTU.
    * **Connection Establishment:** Call `client->Initialize()` and `client->Connect()`. Pay attention to error handling (version mismatch).
    * **Request Construction:** Build the HTTP request headers and body based on flags.
    * **Sending Requests (Loop):** Iterate `num_requests` times:
        * Send the request using `client->SendRequestAndWaitForResponse()`.
        * Print request and response information (controlled by `quiet`).
        * Check for connection errors.
        * Evaluate the response code.
        * Handle multiple requests (reconnecting, changing ports).

4. **Identifying Potential Links to JavaScript:**  This requires thinking about where Chromium's network stack interacts with the browser environment. Key areas to consider are:

    * **Fetching Resources:**  JavaScript's `fetch` API is a prime candidate. The `quic_toy_client` mimics a basic HTTP client, similar to what `fetch` does under the hood.
    * **WebSockets (Less Direct):** While this tool focuses on HTTP-like requests, QUIC is also used for WebSockets in Chromium.
    * **Service Workers:** These can intercept network requests.
    * **Network APIs in Extensions:** Browser extensions might use network APIs that leverage the underlying stack.

5. **Formulating Examples for JavaScript Interaction:**  Based on the identified links, construct concrete examples. Show how a `fetch` call might conceptually translate to the actions performed by `quic_toy_client`. Emphasize the common elements like URLs, headers, methods, and body.

6. **Considering Logic and Input/Output:**  Select a few key flags to demonstrate input-output relationships. Think about how changing a flag affects the client's behavior and the resulting output. Examples like `--body`, `--headers`, and `--quic_version` are good choices.

7. **Identifying Common User/Programming Errors:** Focus on mistakes a user might make when using the command-line tool or errors a developer might encounter when integrating or testing with it. Think about:

    * **Incorrect flag usage:** Typos, missing arguments, conflicting flags.
    * **Network issues:**  Server not running, incorrect host/port.
    * **Security configuration:**  Certificate problems.
    * **Protocol mismatches:**  Incorrect QUIC version.

8. **Tracing User Actions to the Code:**  Imagine a user wanting to test a specific QUIC server. Map out the steps they would take:

    * Open a terminal.
    * Construct the `quic_client` command with appropriate flags (URL, host, port, etc.).
    * Execute the command.
    * The operating system launches the `quic_client` binary.
    * The `main` function (not shown but implied) parses the command-line arguments.
    * The `SendRequestsAndPrintResponses` function is called with the parsed information.

9. **Review and Refine:** Go through the generated information, ensuring clarity, accuracy, and completeness. Check for any logical inconsistencies or areas that could be explained better. For example, initially, I might only think about `fetch`, but then realizing Service Workers also intercept network requests would broaden the scope of potential JavaScript interaction. Similarly, making sure the assumptions in the input/output examples are clear is important.好的，我们来详细分析一下 `net/third_party/quiche/src/quiche/quic/tools/quic_toy_client.cc` 这个文件。

**文件功能概述:**

`quic_toy_client.cc` 是 Chromium 网络栈中一个基于 QUIC 协议的命令行客户端工具。 它的主要功能是：

1. **建立 QUIC 连接:**  能够连接到指定的服务器地址（主机名或 IP 地址和端口）。
2. **发送 HTTP 请求:**  可以发送 GET 或 POST 请求到服务器上的指定 URL。
3. **自定义请求头:**  允许用户通过命令行参数添加自定义的 HTTP 请求头。
4. **发送请求体:**  支持发送 POST 请求，并允许用户指定请求体的内容（普通文本或十六进制编码）。
5. **接收并显示响应:**  接收服务器返回的 HTTP 响应头、响应体和尾部（trailers），并将其打印到终端。
6. **支持多种 QUIC 版本:**  可以指定要使用的 QUIC 协议版本。
7. **控制连接选项:**  允许用户设置 QUIC 连接的各种选项。
8. **处理重定向:**  可以配置是否将 HTTP 3xx 重定向视为成功。
9. **模拟多次请求:**  可以对同一个连接或不同的连接发送多次请求。
10. **忽略错误:**  可以选择忽略连接或响应中出现的错误。
11. **禁用证书验证:**  为了测试目的，可以禁用服务器证书的验证。
12. **发送客户端证书:**  支持在服务器请求时发送客户端证书。
13. **控制数据接收:**  可以配置是否立即丢弃响应体。
14. **控制端口变化:**  可以禁用在每次请求后更改本地端口的行为。
15. **使用指定连接ID:** 可以指定客户端和服务器的连接ID。
16. **设置超时:**  可以设置加密握手前的最大等待时间。
17. **设置最大头部列表大小:** 可以配置允许接收的最大头部列表大小。
18. **绑定网络接口:** 可以指定用于 QUIC UDP 套接字的绑定网络接口。
19. **配置签名算法:** 可以配置客户端支持的签名算法。

**与 JavaScript 的关系及举例说明:**

虽然 `quic_toy_client.cc` 是一个 C++ 编写的命令行工具，它模拟了浏览器发起网络请求的行为，这与 JavaScript 在浏览器环境中通过 `fetch` API 或 `XMLHttpRequest` 发起请求的功能是类似的。

**举例说明:**

假设我们在 JavaScript 中使用 `fetch` API 发送一个 POST 请求：

```javascript
fetch('https://www.example.com/data', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-Custom-Header': 'some-value'
  },
  body: JSON.stringify({ key: 'value' })
})
.then(response => response.json())
.then(data => console.log(data));
```

使用 `quic_toy_client` 可以实现类似的功能：

```bash
./quic_client www.example.com/data --body='{"key": "value"}' --headers="Content-Type: application/json; X-Custom-Header: some-value"
```

**对应关系:**

* **`fetch('https://www.example.com/data', ...)`:**  对应 `quic_client www.example.com/data`。
* **`method: 'POST'`:** 对应命令行隐含的 `--body` 参数存在时使用 POST 方法。
* **`headers: { 'Content-Type': 'application/json', 'X-Custom-Header': 'some-value' }`:** 对应命令行参数 `--headers="Content-Type: application/json; X-Custom-Header: some-value"`。
* **`body: JSON.stringify({ key: 'value' })`:** 对应命令行参数 `--body='{"key": "value"}'`。
* **`response => response.json()`:** `quic_toy_client` 会将响应头和响应体打印到终端，用户可以根据需要解析 JSON 响应体。

**逻辑推理及假设输入与输出:**

**假设输入:**

```bash
./quic_client www.example.com --port=443 --quic_version=h3-29 --body_hex="68656c6c6f" --headers="Custom-Header: test"
```

**逻辑推理:**

1. **解析参数:** `quic_toy_client` 解析命令行参数，包括目标主机 `www.example.com`，端口 `443`，使用的 QUIC 版本 `h3-29`，请求体内容为十六进制 `"68656c6c6f"`，以及自定义请求头 `Custom-Header: test`。
2. **建立连接:**  尝试使用 QUIC h3-29 版本连接到 `www.example.com:443`。
3. **构建请求:**  创建一个 POST 请求，请求路径为 `/`（默认），请求头包含 `Custom-Header: test` 和根据请求体推断的 `Content-Length` 等。请求体为 `"hello"` (因为 "68656c6c6f" 的十六进制解码结果是 "hello")。
4. **发送请求并接收响应:**  将请求发送到服务器并等待响应。
5. **打印输出:**  将接收到的响应头、响应体等信息打印到终端。

**可能的输出 (部分):**

```
Connected to www.example.com:443
Request:
headers::method: POST
:scheme: https
:authority: www.example.com:443
:path: /
Custom-Header: test
body:
68656c6c6f

Response:
headers: :status: 200
Content-Type: text/html; charset=UTF-8
... (其他响应头)
body: <!doctype html>... (服务器返回的 HTML 内容)
trailers:  // 如果有的话
early data accepted: false // 或 true
Request succeeded (200).
```

**用户或编程常见的使用错误:**

1. **主机名或 URL 错误:**  输入不存在的主机名或错误的 URL 会导致连接失败。
   * **示例:** `./quic_client non-existent-host.com`
   * **错误信息:**  可能类似 "Failed to connect to non-existent-host.com:443. QUIC_ADDRESS_RESOLUTION_ERROR ..."

2. **端口号错误:**  指定错误的端口号，服务器可能没有在该端口监听 QUIC 连接。
   * **示例:** `./quic_client www.google.com --port=80` (通常 HTTPS 的 QUIC 在 443 端口)
   * **错误信息:** 可能类似 "Failed to connect to www.google.com:80. QUIC_CONNECTION_REFUSED ..."

3. **QUIC 版本不兼容:**  指定的 QUIC 版本服务器不支持。
   * **示例:** `./quic_client www.google.com --quic_version=999`
   * **错误信息:** 可能类似 "Failed to negotiate version with www.google.com:443. ..." 或者直接连接失败。

4. **请求体格式错误:**  当使用 `--body_hex` 时，提供的十六进制字符串不是有效的十六进制。
   * **示例:** `./quic_client www.example.com --body_hex="invalid-hex"`
   * **错误信息:** "Failed to parse --body_hex."

5. **请求头格式错误:**  在 `--headers` 中提供的请求头格式不正确。
   * **示例:** `./quic_client www.example.com --headers="Invalid-Header"` (缺少冒号和值)
   * **行为:**  该请求头可能被忽略或导致请求错误，具体取决于服务器的实现。

6. **缺少必要的证书:**  当服务器要求客户端证书，但用户没有提供时。
   * **示例:**  服务器配置要求客户端证书，但运行 `./quic_client ...` 时没有使用 `--default_client_cert` 和 `--default_client_cert_key`。
   * **错误信息:**  连接可能被服务器拒绝，或者握手失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chrome 浏览器访问一个网站时遇到了问题，怀疑是 QUIC 连接的问题，想要使用 `quic_toy_client` 来进行更细致的测试。以下是可能的操作步骤：

1. **了解目标网站的地址:** 用户需要知道要测试的网站的 URL，例如 `https://www.example.com`。
2. **确定需要测试的场景:** 用户可能想要测试：
   * 基本的连接是否正常。
   * 特定 QUIC 版本是否可用。
   * 发送特定请求头或请求体是否会导致问题。
3. **打开终端/命令行界面:** 用户需要在计算机上打开一个终端或命令行界面。
4. **定位 `quic_client` 可执行文件:**  用户需要找到 `quic_client` 可执行文件所在的路径。通常在 Chromium 的构建输出目录中。
5. **构建 `quic_client` 命令:**  根据需要测试的场景，用户会构建包含各种命令行参数的 `quic_client` 命令。例如：
   * 测试基本连接：`./quic_client www.example.com`
   * 测试特定版本：`./quic_client www.example.com --quic_version=h3-29`
   * 发送 POST 请求：`./quic_client www.example.com --body="test data"`
   * 添加自定义请求头：`./quic_client www.example.com --headers="X-Debug: true"`
6. **执行命令:** 用户在终端中输入并执行构建好的命令。
7. **观察输出:**  用户会观察 `quic_client` 的输出，包括连接信息、请求信息、响应头、响应体等。
8. **分析结果:**  根据输出信息，用户可以判断连接是否成功，服务器的响应是否符合预期，是否存在版本协商问题等等。

**作为调试线索:**

`quic_toy_client` 的输出可以作为重要的调试线索：

* **连接状态:**  可以确认是否成功连接到服务器，如果失败，可以查看错误信息，例如版本不匹配、连接被拒绝等。
* **请求详情:**  可以确认发送的请求头和请求体是否正确，这有助于排查客户端请求构建的问题。
* **响应详情:**  可以查看服务器返回的响应状态码、响应头和响应体，这有助于判断服务器端的行为是否正常。
* **QUIC 版本协商:**  可以查看客户端和服务器最终协商使用的 QUIC 版本，判断是否存在版本兼容性问题。
* **错误信息:**  `quic_client` 可能会输出详细的错误信息，帮助用户定位问题所在。

通过使用 `quic_toy_client`，开发人员可以独立于浏览器环境测试 QUIC 连接和请求，从而更方便地诊断网络问题。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/tools/quic_toy_client.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A binary wrapper for QuicClient.
// Connects to a host using QUIC, sends a request to the provided URL, and
// displays the response.
//
// Some usage examples:
//
// Standard request/response:
//   quic_client www.google.com
//   quic_client www.google.com --quiet
//   quic_client www.google.com --port=443
//
// Use a specific version:
//   quic_client www.google.com --quic_version=23
//
// Send a POST instead of a GET:
//   quic_client www.google.com --body="this is a POST body"
//
// Append additional headers to the request:
//   quic_client www.google.com --headers="Header-A: 1234; Header-B: 5678"
//
// Connect to a host different to the URL being requested:
//   quic_client mail.google.com --host=www.google.com
//
// Connect to a specific IP:
//   IP=`dig www.google.com +short | head -1`
//   quic_client www.google.com --host=${IP}
//
// Send repeated requests and change ephemeral port between requests
//   quic_client www.google.com --num_requests=10
//
// Try to connect to a host which does not speak QUIC:
//   quic_client www.example.com
//
// This tool is available as a built binary at:
// /google/data/ro/teams/quic/tools/quic_client
// After submitting changes to this file, you will need to follow the
// instructions at go/quic_client_binary_update

#include "quiche/quic/tools/quic_toy_client.h"

#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/escaping.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/quic_client_session_cache.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_default_proof_providers.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/fake_proof_verifier.h"
#include "quiche/quic/tools/quic_url.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_text_utils.h"

namespace {

using quiche::QuicheTextUtils;

}  // namespace

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, host, "",
    "The IP or hostname to connect to. If not provided, the host "
    "will be derived from the provided URL.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(int32_t, port, 0, "The port to connect to.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(std::string, ip_version_for_host_lookup, "",
                                "Only used if host address lookup is needed. "
                                "4=ipv4; 6=ipv6; otherwise=don't care.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(std::string, body, "",
                                "If set, send a POST with this body.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, body_hex, "",
    "If set, contents are converted from hex to ascii, before "
    "sending as body of a POST. e.g. --body_hex=\"68656c6c6f\"");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, headers, "",
    "A semicolon separated list of key:value pairs to "
    "add to request headers.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(bool, quiet, false,
                                "Set to true for a quieter output experience.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, output_resolved_server_address, false,
    "Set to true to print the resolved IP of the server.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, quic_version, "",
    "QUIC version to speak, e.g. 21. If not set, then all available "
    "versions are offered in the handshake. Also supports wire versions "
    "such as Q043 or T099.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, connection_options, "",
    "Connection options as ASCII tags separated by commas, "
    "e.g. \"ABCD,EFGH\"");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, client_connection_options, "",
    "Client connection options as ASCII tags separated by commas, "
    "e.g. \"ABCD,EFGH\"");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, version_mismatch_ok, false,
    "If true, a version mismatch in the handshake is not considered a "
    "failure. Useful for probing a server to determine if it speaks "
    "any version of QUIC.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, force_version_negotiation, false,
    "If true, start by proposing a version that is reserved for version "
    "negotiation.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, multi_packet_chlo, false,
    "If true, add a transport parameter to make the ClientHello span two "
    "packets. Only works with QUIC+TLS.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, redirect_is_success, true,
    "If true, an HTTP response code of 3xx is considered to be a "
    "successful response, otherwise a failure.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(int32_t, initial_mtu, 0,
                                "Initial MTU of the connection.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, num_requests, 1,
    "How many sequential requests to make on a single connection.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(bool, ignore_errors, false,
                                "If true, ignore connection/response errors "
                                "and send all num_requests anyway.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, disable_certificate_verification, false,
    "If true, don't verify the server certificate.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, default_client_cert, "",
    "The path to the file containing PEM-encoded client default certificate to "
    "be sent to the server, if server requested client certs.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, default_client_cert_key, "",
    "The path to the file containing PEM-encoded private key of the client's "
    "default certificate for signing, if server requested client certs.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, drop_response_body, false,
    "If true, drop response body immediately after it is received.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, disable_port_changes, false,
    "If true, do not change local port after each request.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(bool, one_connection_per_request, false,
                                "If true, close the connection after each "
                                "request. This allows testing 0-RTT.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, server_connection_id, "",
    "If non-empty, the client will use the given server connection id for all "
    "connections. The flag value is the hex-string of the on-wire connection id"
    " bytes, e.g. '--server_connection_id=0123456789abcdef'.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, server_connection_id_length, -1,
    "Length of the server connection ID used. This flag has no effects if "
    "--server_connection_id is non-empty.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(int32_t, client_connection_id_length, -1,
                                "Length of the client connection ID used.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(int32_t, max_time_before_crypto_handshake_ms,
                                10000,
                                "Max time to wait before handshake completes.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, max_inbound_header_list_size, 128 * 1024,
    "Max inbound header list size. 0 means default.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(std::string, interface_name, "",
                                "Interface name to bind QUIC UDP sockets to.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, signing_algorithms_pref, "",
    "A textual specification of a set of signature algorithms that can be "
    "accepted by boring SSL SSL_set1_sigalgs_list()");

namespace quic {
namespace {

// Creates a ClientProofSource which only contains a default client certificate.
// Return nullptr for failure.
std::unique_ptr<ClientProofSource> CreateTestClientProofSource(
    absl::string_view default_client_cert_file,
    absl::string_view default_client_cert_key_file) {
  std::ifstream cert_stream(std::string{default_client_cert_file},
                            std::ios::binary);
  std::vector<std::string> certs =
      CertificateView::LoadPemFromStream(&cert_stream);
  if (certs.empty()) {
    std::cerr << "Failed to load client certs." << std::endl;
    return nullptr;
  }

  std::ifstream key_stream(std::string{default_client_cert_key_file},
                           std::ios::binary);
  std::unique_ptr<CertificatePrivateKey> private_key =
      CertificatePrivateKey::LoadPemFromStream(&key_stream);
  if (private_key == nullptr) {
    std::cerr << "Failed to load client cert key." << std::endl;
    return nullptr;
  }

  auto proof_source = std::make_unique<DefaultClientProofSource>();
  proof_source->AddCertAndKey(
      {"*"},
      quiche::QuicheReferenceCountedPointer<ClientProofSource::Chain>(
          new ClientProofSource::Chain(certs)),
      std::move(*private_key));

  return proof_source;
}

}  // namespace

QuicToyClient::QuicToyClient(ClientFactory* client_factory)
    : client_factory_(client_factory) {}

int QuicToyClient::SendRequestsAndPrintResponses(
    std::vector<std::string> urls) {
  QuicUrl url(urls[0], "https");
  std::string host = quiche::GetQuicheCommandLineFlag(FLAGS_host);
  if (host.empty()) {
    host = url.host();
  }
  int port = quiche::GetQuicheCommandLineFlag(FLAGS_port);
  if (port == 0) {
    port = url.port();
  }

  quic::ParsedQuicVersionVector versions = quic::CurrentSupportedVersions();

  std::string quic_version_string =
      quiche::GetQuicheCommandLineFlag(FLAGS_quic_version);
  if (!quic_version_string.empty()) {
    versions = quic::ParseQuicVersionVectorString(quic_version_string);
  }

  if (versions.empty()) {
    std::cerr << "No known version selected." << std::endl;
    return 1;
  }

  for (const quic::ParsedQuicVersion& version : versions) {
    quic::QuicEnableVersion(version);
  }

  if (quiche::GetQuicheCommandLineFlag(FLAGS_force_version_negotiation)) {
    versions.insert(versions.begin(),
                    quic::QuicVersionReservedForNegotiation());
  }

  const int32_t num_requests(
      quiche::GetQuicheCommandLineFlag(FLAGS_num_requests));
  std::unique_ptr<quic::ProofVerifier> proof_verifier;
  if (quiche::GetQuicheCommandLineFlag(
          FLAGS_disable_certificate_verification)) {
    proof_verifier = std::make_unique<FakeProofVerifier>();
  } else {
    proof_verifier = quic::CreateDefaultProofVerifier(url.host());
  }
  std::unique_ptr<quic::SessionCache> session_cache;
  if (num_requests > 1 &&
      quiche::GetQuicheCommandLineFlag(FLAGS_one_connection_per_request)) {
    session_cache = std::make_unique<QuicClientSessionCache>();
  }

  QuicConfig config;
  std::string connection_options_string =
      quiche::GetQuicheCommandLineFlag(FLAGS_connection_options);
  if (!connection_options_string.empty()) {
    config.SetConnectionOptionsToSend(
        ParseQuicTagVector(connection_options_string));
  }
  std::string client_connection_options_string =
      quiche::GetQuicheCommandLineFlag(FLAGS_client_connection_options);
  if (!client_connection_options_string.empty()) {
    config.SetClientConnectionOptions(
        ParseQuicTagVector(client_connection_options_string));
  }
  if (quiche::GetQuicheCommandLineFlag(FLAGS_multi_packet_chlo)) {
    // Make the ClientHello span multiple packets by adding a large 'discard'
    // transport parameter.
    config.SetDiscardLengthToSend(2000);
  }
  config.set_max_time_before_crypto_handshake(
      QuicTime::Delta::FromMilliseconds(quiche::GetQuicheCommandLineFlag(
          FLAGS_max_time_before_crypto_handshake_ms)));

  int address_family_for_lookup = AF_UNSPEC;
  if (quiche::GetQuicheCommandLineFlag(FLAGS_ip_version_for_host_lookup) ==
      "4") {
    address_family_for_lookup = AF_INET;
  } else if (quiche::GetQuicheCommandLineFlag(
                 FLAGS_ip_version_for_host_lookup) == "6") {
    address_family_for_lookup = AF_INET6;
  }

  // Build the client, and try to connect.
  std::unique_ptr<QuicSpdyClientBase> client = client_factory_->CreateClient(
      url.host(), host, address_family_for_lookup, port, versions, config,
      std::move(proof_verifier), std::move(session_cache));

  if (client == nullptr) {
    std::cerr << "Failed to create client." << std::endl;
    return 1;
  }

  if (!quiche::GetQuicheCommandLineFlag(FLAGS_default_client_cert).empty() &&
      !quiche::GetQuicheCommandLineFlag(FLAGS_default_client_cert_key)
           .empty()) {
    std::unique_ptr<ClientProofSource> proof_source =
        CreateTestClientProofSource(
            quiche::GetQuicheCommandLineFlag(FLAGS_default_client_cert),
            quiche::GetQuicheCommandLineFlag(FLAGS_default_client_cert_key));
    if (proof_source == nullptr) {
      std::cerr << "Failed to create client proof source." << std::endl;
      return 1;
    }
    client->crypto_config()->set_proof_source(std::move(proof_source));
  }

  int32_t initial_mtu = quiche::GetQuicheCommandLineFlag(FLAGS_initial_mtu);
  client->set_initial_max_packet_length(
      initial_mtu != 0 ? initial_mtu : quic::kDefaultMaxPacketSize);
  client->set_drop_response_body(
      quiche::GetQuicheCommandLineFlag(FLAGS_drop_response_body));
  const std::string server_connection_id_hex_string =
      quiche::GetQuicheCommandLineFlag(FLAGS_server_connection_id);
  QUICHE_CHECK(server_connection_id_hex_string.size() % 2 == 0)
      << "The length of --server_connection_id must be even. It is "
      << server_connection_id_hex_string.size() << "-byte long.";
  if (!server_connection_id_hex_string.empty()) {
    std::string server_connection_id_bytes;
    QUICHE_CHECK(absl::HexStringToBytes(server_connection_id_hex_string,
                                        &server_connection_id_bytes))
        << "Failed to parse --server_connection_id hex string.";
    client->set_server_connection_id_override(QuicConnectionId(
        server_connection_id_bytes.data(), server_connection_id_bytes.size()));
  }
  const int32_t server_connection_id_length =
      quiche::GetQuicheCommandLineFlag(FLAGS_server_connection_id_length);
  if (server_connection_id_length >= 0) {
    client->set_server_connection_id_length(server_connection_id_length);
  }
  const int32_t client_connection_id_length =
      quiche::GetQuicheCommandLineFlag(FLAGS_client_connection_id_length);
  if (client_connection_id_length >= 0) {
    client->set_client_connection_id_length(client_connection_id_length);
  }
  const size_t max_inbound_header_list_size =
      quiche::GetQuicheCommandLineFlag(FLAGS_max_inbound_header_list_size);
  if (max_inbound_header_list_size > 0) {
    client->set_max_inbound_header_list_size(max_inbound_header_list_size);
  }
  const std::string interface_name =
      quiche::GetQuicheCommandLineFlag(FLAGS_interface_name);
  if (!interface_name.empty()) {
    client->set_interface_name(interface_name);
  }
  const std::string signing_algorithms_pref =
      quiche::GetQuicheCommandLineFlag(FLAGS_signing_algorithms_pref);
  if (!signing_algorithms_pref.empty()) {
    client->SetTlsSignatureAlgorithms(signing_algorithms_pref);
  }
  if (!client->Initialize()) {
    std::cerr << "Failed to initialize client." << std::endl;
    return 1;
  }
  if (!client->Connect()) {
    quic::QuicErrorCode error = client->session()->error();
    if (error == quic::QUIC_INVALID_VERSION) {
      std::cerr << "Failed to negotiate version with " << host << ":" << port
                << ". " << client->session()->error_details() << std::endl;
      // 0: No error.
      // 20: Failed to connect due to QUIC_INVALID_VERSION.
      return quiche::GetQuicheCommandLineFlag(FLAGS_version_mismatch_ok) ? 0
                                                                         : 20;
    }
    std::cerr << "Failed to connect to " << host << ":" << port << ". "
              << quic::QuicErrorCodeToString(error) << " "
              << client->session()->error_details() << std::endl;
    return 1;
  }

  std::cout << "Connected to " << host << ":" << port;
  if (quiche::GetQuicheCommandLineFlag(FLAGS_output_resolved_server_address)) {
    std::cout << ", resolved IP " << client->server_address().host().ToString();
  }
  std::cout << std::endl;

  // Construct the string body from flags, if provided.
  std::string body = quiche::GetQuicheCommandLineFlag(FLAGS_body);
  if (!quiche::GetQuicheCommandLineFlag(FLAGS_body_hex).empty()) {
    QUICHE_DCHECK(quiche::GetQuicheCommandLineFlag(FLAGS_body).empty())
        << "Only set one of --body and --body_hex.";
    const bool success = absl::HexStringToBytes(
        quiche::GetQuicheCommandLineFlag(FLAGS_body_hex), &body);
    QUICHE_DCHECK(success) << "Failed to parse --body_hex.";
  }

  // Construct a GET or POST request for supplied URL.
  quiche::HttpHeaderBlock header_block;
  header_block[":method"] = body.empty() ? "GET" : "POST";
  header_block[":scheme"] = url.scheme();
  header_block[":authority"] = url.HostPort();
  header_block[":path"] = url.PathParamsQuery();

  // Append any additional headers supplied on the command line.
  const std::string headers = quiche::GetQuicheCommandLineFlag(FLAGS_headers);
  for (absl::string_view sp : absl::StrSplit(headers, ';')) {
    QuicheTextUtils::RemoveLeadingAndTrailingWhitespace(&sp);
    if (sp.empty()) {
      continue;
    }
    std::vector<absl::string_view> kv =
        absl::StrSplit(sp, absl::MaxSplits(':', 1));
    QuicheTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[0]);
    QuicheTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[1]);
    header_block[kv[0]] = kv[1];
  }

  // Make sure to store the response, for later output.
  client->set_store_response(true);

  for (int i = 0; i < num_requests; ++i) {
    // Send the request.
    client->SendRequestAndWaitForResponse(header_block, body, /*fin=*/true);

    // Print request and response details.
    if (!quiche::GetQuicheCommandLineFlag(FLAGS_quiet)) {
      std::cout << "Request:" << std::endl;
      std::cout << "headers:" << header_block.DebugString();
      if (!quiche::GetQuicheCommandLineFlag(FLAGS_body_hex).empty()) {
        // Print the user provided hex, rather than binary body.
        std::cout << "body:\n" << QuicheTextUtils::HexDump(body) << std::endl;
      } else {
        std::cout << "body: " << body << std::endl;
      }
      std::cout << std::endl;

      if (!client->preliminary_response_headers().empty()) {
        std::cout << "Preliminary response headers: "
                  << client->preliminary_response_headers() << std::endl;
        std::cout << std::endl;
      }

      std::cout << "Response:" << std::endl;
      std::cout << "headers: " << client->latest_response_headers()
                << std::endl;
      std::string response_body = client->latest_response_body();
      if (!quiche::GetQuicheCommandLineFlag(FLAGS_body_hex).empty()) {
        // Assume response is binary data.
        std::cout << "body:\n"
                  << QuicheTextUtils::HexDump(response_body) << std::endl;
      } else {
        std::cout << "body: " << response_body << std::endl;
      }
      std::cout << "trailers: " << client->latest_response_trailers()
                << std::endl;
      std::cout << "early data accepted: " << client->EarlyDataAccepted()
                << std::endl;
      QUIC_LOG(INFO) << "Request completed with TTFB(us): "
                     << client->latest_ttfb().ToMicroseconds() << ", TTLB(us): "
                     << client->latest_ttlb().ToMicroseconds();
    }

    if (!client->connected()) {
      std::cerr << "Request caused connection failure. Error: "
                << quic::QuicErrorCodeToString(client->session()->error())
                << std::endl;
      if (!quiche::GetQuicheCommandLineFlag(FLAGS_ignore_errors)) {
        return 1;
      }
    }

    int response_code = client->latest_response_code();
    if (response_code >= 200 && response_code < 300) {
      std::cout << "Request succeeded (" << response_code << ")." << std::endl;
    } else if (response_code >= 300 && response_code < 400) {
      if (quiche::GetQuicheCommandLineFlag(FLAGS_redirect_is_success)) {
        std::cout << "Request succeeded (redirect " << response_code << ")."
                  << std::endl;
      } else {
        std::cout << "Request failed (redirect " << response_code << ")."
                  << std::endl;
        if (!quiche::GetQuicheCommandLineFlag(FLAGS_ignore_errors)) {
          return 1;
        }
      }
    } else {
      std::cout << "Request failed (" << response_code << ")." << std::endl;
      if (!quiche::GetQuicheCommandLineFlag(FLAGS_ignore_errors)) {
        return 1;
      }
    }

    if (i + 1 < num_requests) {  // There are more requests to perform.
      if (quiche::GetQuicheCommandLineFlag(FLAGS_one_connection_per_request)) {
        std::cout << "Disconnecting client between requests." << std::endl;
        client->Disconnect();
        if (!client->Initialize()) {
          std::cerr << "Failed to reinitialize client between requests."
                    << std::endl;
          return 1;
        }
        if (!client->Connect()) {
          std::cerr << "Failed to reconnect client between requests."
                    << std::endl;
          if (!quiche::GetQuicheCommandLineFlag(FLAGS_ignore_errors)) {
            return 1;
          }
        }
      } else if (!quiche::GetQuicheCommandLineFlag(
                     FLAGS_disable_port_changes)) {
        // Change the ephemeral port.
        if (!client->ChangeEphemeralPort()) {
          std::cerr << "Failed to change ephemeral port." << std::endl;
          return 1;
        }
      }
    }
  }

  return 0;
}

}  // namespace quic
```