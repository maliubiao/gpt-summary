Response:
Let's break down the thought process for analyzing the C++ code and generating the response.

1. **Understanding the Core Request:** The fundamental request is to analyze the provided C++ code (`quic_simple_test_server.cc`) and describe its functionality, potential connections to JavaScript, logical inferences with examples, common usage errors, and debugging information.

2. **Initial Code Scan (Skimming):**  The first step is a quick skim to grasp the overall purpose. Keywords like "test server," "QUIC," "memory cache," "HTTP/2," and file paths related to certificates immediately jump out. This suggests the code implements a simplified QUIC server for testing purposes, likely simulating responses from a real web server.

3. **Identifying Key Components:**  Next, identify the main actors and data structures:
    * **`QuicSimpleTestServer` class:** This is the primary interface for interacting with the test server.
    * **`quic::QuicSimpleServer`:**  This is likely the core QUIC server implementation from the `quiche` library.
    * **`quic::QuicMemoryCacheBackend`:** This indicates the server uses an in-memory cache to store and serve responses, simplifying the testing process.
    * **Constants:**  The defined constants (like `kHelloPath`, `kHelloBodyValue`, etc.) define the default responses served by the test server.
    * **Global variables (`g_quic_server_thread`, `g_quic_cache_backend`, `g_quic_server`, `g_quic_server_port`):** These manage the server's lifecycle and state.
    * **Helper functions:** Functions like `SetupQuicMemoryCacheBackend`, `StartQuicServerOnServerThread`, `ShutdownOnServerThread`, etc., manage specific parts of the server's setup and teardown.

4. **Analyzing Functionality (Step-by-Step):** Go through the code method by method, understanding what each function does:
    * **Getters (`GetDomain`, `GetHost`, `GetHostPort`, `GetFileURL`, etc.):** These provide access to server configuration information.
    * **Constants as Getters:**  Methods like `GetHelloPath`, `GetHelloBodyValue` simply return pre-defined constants. This highlights the static nature of the default responses.
    * **`SetupQuicMemoryCacheBackend()`:**  Populates the in-memory cache with default responses for `/hello.txt` and `/simple.txt`. Notice the inclusion of headers and trailers for `/hello.txt`.
    * **`StartQuicServerOnServerThread()`:**  This is the core startup logic. It creates the QUIC server, configures certificates, sets up the memory cache, and starts listening on a port. The retry logic for finding an allowed port is interesting.
    * **`ShutdownOnServerThread()` and `ShutdownDispatcherOnServerThread()`:**  Handle the graceful shutdown of the server and its dispatcher. The use of a separate thread is important to note.
    * **`Start()`:**  Creates and starts a dedicated thread for the QUIC server.
    * **`AddResponse()` and `AddResponseWithEarlyHints()`:**  Allow adding custom responses to the in-memory cache dynamically.
    * **`SetResponseDelay()`:**  Simulates network latency by adding a delay to specific responses.
    * **`ShutdownDispatcherForTesting()`:**  Provides a way to simulate server-side errors by shutting down the dispatcher without fully stopping the server.
    * **`Shutdown()`:**  Performs a full server shutdown.
    * **`GetPort()`:**  Returns the port the server is listening on.

5. **Identifying Connections to JavaScript:**  The key connection is through web browsers. JavaScript running in a browser can make HTTPS requests. This test server, by implementing QUIC and serving HTTPS, can be used to test how browsers (and therefore JavaScript within them) interact with QUIC. Think about scenarios like fetching data using `fetch()` or `XMLHttpRequest`. The server's responses directly affect what the JavaScript code receives.

6. **Logical Inferences with Examples:** Consider common scenarios and how the server would respond:
    * **Successful Request:**  A browser requesting `/hello.txt` should receive the pre-configured headers, body, and trailers.
    * **Adding Custom Responses:** Demonstrating how `AddResponse` can change the server's behavior.
    * **Early Hints:** Explaining the purpose and potential usage of `AddResponseWithEarlyHints`.
    * **Simulating Errors:**  Showing how `ShutdownDispatcherForTesting` can induce errors on the client side.

7. **Common Usage Errors:**  Think about mistakes a developer might make when using this test server:
    * **Incorrect Port:**  Using the wrong port to connect.
    * **Forgetting to Start:** Trying to connect before the server is started.
    * **Conflicting Ports:** Another service using the same port.
    * **Incorrect Path:** Requesting a path not registered in the cache.

8. **Debugging Information (User Actions):**  Trace the steps a user might take that lead to the execution of this code. This usually involves a developer running tests or the browser interacting with a website. The key is to connect user actions to the server's execution.

9. **Structuring the Response:** Organize the information logically using headings and bullet points for clarity. Start with the core functionality, then move to JavaScript connections, inferences, errors, and debugging.

10. **Refinement and Language:** Review the generated response for clarity, accuracy, and completeness. Use precise language and avoid jargon where possible. Ensure the examples are easy to understand. For instance, instead of just saying "browser makes a request," specify using `fetch()` or `XMLHttpRequest`.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the server directly interacts with Node.js. **Correction:** While possible, the primary use case is likely browser testing via HTTPS.
* **Focusing too much on low-level QUIC details:** **Correction:** Keep the explanation focused on the purpose and usage of *this specific test server* rather than deep dives into the QUIC protocol itself.
* **Not enough concrete examples:** **Correction:** Add specific examples for assumptions and errors to make the explanation more practical.
* **Vague debugging information:** **Correction:**  Clearly outline the steps a developer would take to use this server in a testing context.

By following these steps, iteratively analyzing the code, and refining the explanation, we can arrive at a comprehensive and informative answer to the initial request.
好的，让我们来详细分析一下 `net/test/quic_simple_test_server.cc` 这个 Chromium 网络栈的源代码文件。

**功能概述:**

`QuicSimpleTestServer` 的主要功能是**创建一个简单易用的 QUIC 服务器，用于在 Chromium 网络栈的测试环境中模拟真实的 QUIC 服务器行为。** 它的设计目标是简化测试流程，允许开发人员方便地验证 QUIC 协议的客户端实现以及与基于 QUIC 的网络功能相关的代码。

更具体地说，这个测试服务器具有以下关键功能：

1. **基于内存的响应:** 它使用 `quic::QuicMemoryCacheBackend` 来存储预定义的 HTTP 响应。这意味着它不需要实际的文件系统交互，响应速度非常快，适合测试环境。
2. **预定义响应:**  它预先配置了一些默认的响应，例如针对 `/hello.txt` 和 `/simple.txt` 的请求，包含了 HTTP 头部和 Body。`hello.txt` 的响应还包含了 HTTP/2 Trailers。
3. **动态添加响应:**  它提供了 `AddResponse` 和 `AddResponseWithEarlyHints` 方法，允许在运行时动态地添加新的请求路径和对应的响应，这使得它可以模拟各种不同的服务器行为。
4. **模拟延迟:**  `SetResponseDelay` 方法允许为特定的请求路径设置响应延迟，用于模拟网络延迟情况。
5. **控制服务器生命周期:** 提供了 `Start` 和 `Shutdown` 方法来启动和停止服务器。服务器运行在一个独立的线程中。
6. **模拟服务器错误:** `ShutdownDispatcherForTesting` 方法可以用来模拟服务器 dispatcher 关闭的情况，这可以用于测试客户端对连接中断的处理。
7. **提供服务器地址信息:**  提供 `GetPort` 等方法来获取服务器监听的端口号。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它与 JavaScript 的功能有密切关系，因为它模拟了一个可以被 Web 浏览器（运行 JavaScript 代码）访问的 QUIC 服务器。

**举例说明:**

假设你正在开发一个使用 `fetch` API 通过 QUIC 请求数据的 JavaScript 应用，并希望测试在接收到带有 HTTP/2 Trailers 的响应时，你的代码是否能够正确处理。

1. 你可以使用 `QuicSimpleTestServer` 并让它运行起来。
2. 你的 JavaScript 代码可以使用 `fetch` API 向 `QuicSimpleTestServer` 提供的 `/hello.txt` URL 发起请求。
3. `QuicSimpleTestServer` 会返回预定义的包含 Trailers 的响应。
4. 你的 JavaScript 代码可以检查 `fetch` API 返回的 Response 对象，确认是否能够正确访问和处理这些 Trailers。

**假设输入与输出 (逻辑推理):**

**假设输入:**

* **场景 1:  请求预定义的路径 `/hello.txt`**
    * 用户操作：浏览器或测试工具向 `https://test.example.com:<port>/hello.txt` 发送 QUIC 请求。
    * `QuicSimpleTestServer` 的内存缓存中已经存在 `/hello.txt` 的响应。

* **场景 2:  动态添加响应后请求新路径 `/custom.txt`**
    * 用户操作：在测试代码中调用 `AddResponse("/custom.txt", headers, "Custom Body")` 添加了新的响应。
    * 用户操作：浏览器或测试工具向 `https://test.example.com:<port>/custom.txt` 发送 QUIC 请求。

* **场景 3:  请求设置了延迟的路径 `/delayed.txt`**
    * 用户操作：在测试代码中调用 `SetResponseDelay("/delayed.txt", 2 seconds)` 设置了延迟。
    * 用户操作：浏览器或测试工具向 `https://test.example.com:<port>/delayed.txt` 发送 QUIC 请求。

* **场景 4:  在 Dispatcher 关闭后发送请求**
    * 用户操作：在测试代码中调用 `ShutdownDispatcherForTesting()` 关闭了服务器的 dispatcher。
    * 用户操作：浏览器或测试工具向 `https://test.example.com:<port>/hello.txt` 发送 QUIC 请求。

**预期输出:**

* **场景 1:** 客户端收到 HTTP 状态码 `200 OK`，Body 为 "Hello from QUIC Server"，并且可以访问到名为 `hello_header` 值为 "hello header value" 的头部，以及名为 `hello_trailer` 值为 "hello trailer value" 的 Trailer。

* **场景 2:** 客户端收到 HTTP 状态码，Body 为 "Custom Body"，以及在 `AddResponse` 中设置的头部。

* **场景 3:** 客户端在发送请求后，会等待大约 2 秒后才收到服务器的响应。

* **场景 4:** 客户端的 QUIC 连接可能会中断，或者请求会超时，具体取决于客户端的实现。客户端应该能够处理这种连接错误。

**用户或编程常见的使用错误:**

1. **忘记启动服务器:**  在进行测试之前没有调用 `QuicSimpleTestServer::Start()`，导致连接失败。
   ```c++
   net::QuicSimpleTestServer server;
   // 忘记调用 server.Start();
   // ... 尝试连接服务器 ...
   ```

2. **使用了错误的端口:**  客户端尝试连接的端口与 `QuicSimpleTestServer` 实际监听的端口不一致。可以通过 `QuicSimpleTestServer::GetPort()` 获取正确的端口号。
   ```c++
   net::QuicSimpleTestServer server;
   server.Start();
   int port = server.GetPort();
   // ... 客户端连接到错误的端口，例如 8080 而不是 'port' ...
   ```

3. **请求了未定义的路径:**  客户端请求的路径在 `QuicSimpleTestServer` 的内存缓存中没有对应的响应。
   ```c++
   net::QuicSimpleTestServer server;
   server.Start();
   // 没有为 "/unknown.txt" 添加响应
   // ... 客户端请求 "https://test.example.com:<port>/unknown.txt" ...
   ```

4. **在服务器关闭后尝试连接:**  在调用 `QuicSimpleTestServer::Shutdown()` 后，客户端尝试建立新的连接或发送请求会导致连接失败。
   ```c++
   net::QuicSimpleTestServer server;
   server.Start();
   // ... 进行一些测试 ...
   server.Shutdown();
   // ... 尝试连接服务器，将会失败 ...
   ```

5. **端口冲突:**  `QuicSimpleTestServer` 尝试监听的端口已经被其他程序占用，导致启动失败。虽然代码中有重试机制，但在某些情况下仍然可能失败。

**用户操作如何一步步的到达这里 (作为调试线索):**

假设开发者在调试一个与 Chromium 网络栈中 QUIC 客户端实现相关的 Bug。以下步骤可能会导致 `QuicSimpleTestServer` 被使用：

1. **开发者编写了一个网络测试:**  开发者为了验证 QUIC 客户端的特定行为（例如处理 HTTP/2 Trailers、Early Hints 或连接迁移），编写了一个 C++ 测试用例。
2. **测试用例实例化 `QuicSimpleTestServer`:**  在测试用例的 `SetUp` 方法或者测试主体中，会创建一个 `QuicSimpleTestServer` 的实例。
3. **启动测试服务器:** 测试用例调用 `server.Start()` 方法来启动测试用的 QUIC 服务器。这个操作会创建并启动一个新的线程来运行服务器。
4. **客户端发起连接和请求:**  测试用例使用 Chromium 的 QUIC 客户端 API (例如 `URLRequestContext`, `TransportClientSocketPool`) 构建请求，并连接到 `QuicSimpleTestServer` 提供的地址和端口。
5. **`QuicSimpleTestServer` 处理请求:**  服务器接收到客户端的连接和请求，然后在 `quic::QuicMemoryCacheBackend` 中查找对应的响应。
6. **返回响应:**  找到响应后，`QuicSimpleTestServer` 将预定义的 HTTP 响应（可能包含头部和 Trailers）通过 QUIC 连接发送回客户端。
7. **客户端处理响应:**  Chromium 的 QUIC 客户端接收并处理服务器的响应。
8. **断言测试结果:**  测试用例会检查客户端收到的响应是否符合预期，以此来验证 QUIC 客户端的正确性。

**调试线索:**

* **如果测试失败，并且涉及到服务器端的行为:**  开发者可能会查看 `QuicSimpleTestServer` 的代码，确认是否配置了正确的响应，是否模拟了预期的延迟，或者是否触发了特定的服务器端状态（例如通过 `ShutdownDispatcherForTesting`）。
* **检查 `QuicSimpleTestServer` 的日志输出 (如果有的话):**  虽然这个简单的测试服务器可能没有复杂的日志记录，但任何输出都可以提供关于服务器行为的信息。
* **单步调试测试代码:**  开发者可能会在测试代码中设置断点，逐步执行，查看 `QuicSimpleTestServer` 的状态，以及客户端与服务器之间的交互过程。
* **修改 `QuicSimpleTestServer` 的行为:**  为了更精确地模拟某些场景，开发者可能会临时修改 `QuicSimpleTestServer` 的代码，例如添加新的响应，修改现有的响应内容，或者调整延迟时间。

总而言之，`net/test/quic_simple_test_server.cc` 是 Chromium 网络栈中一个非常重要的测试工具，它通过提供一个可控且易于配置的 QUIC 服务器，极大地简化了 QUIC 相关的测试工作。它的功能涵盖了基本请求响应、模拟延迟、动态添加响应以及模拟服务器错误等多个方面，使得开发者可以更加方便地验证 QUIC 客户端的各种行为。

### 提示词
```
这是目录为net/test/quic_simple_test_server.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/quic_simple_test_server.h"

#include <memory>
#include <utility>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/message_loop/message_pump_type.h"
#include "base/path_service.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/port_util.h"
#include "net/quic/crypto/proof_source_chromium.h"
#include "net/test/test_data_directory.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_dispatcher.h"
#include "net/third_party/quiche/src/quiche/quic/tools/quic_memory_cache_backend.h"
#include "net/tools/quic/quic_simple_server.h"

namespace {

const char kTestServerDomain[] = "example.com";
// This must match the certificate used (quic-chain.pem and quic-leaf-cert.key).
const char kTestServerHost[] = "test.example.com";

const char kStatusHeader[] = ":status";

const char kHelloPath[] = "/hello.txt";
const char kHelloBodyValue[] = "Hello from QUIC Server";
const char kHelloStatus[] = "200";

const char kHelloHeaderName[] = "hello_header";
const char kHelloHeaderValue[] = "hello header value";

const char kHelloTrailerName[] = "hello_trailer";
const char kHelloTrailerValue[] = "hello trailer value";

const char kSimplePath[] = "/simple.txt";
const char kSimpleBodyValue[] = "Simple Hello from QUIC Server";
const char kSimpleStatus[] = "200";

const char kSimpleHeaderName[] = "hello_header";
const char kSimpleHeaderValue[] = "hello header value";
const std::string kCombinedHelloHeaderValue = std::string("foo\0bar", 7);
const char kCombinedHeaderName[] = "combined";

base::Thread* g_quic_server_thread = nullptr;
quic::QuicMemoryCacheBackend* g_quic_cache_backend = nullptr;
net::QuicSimpleServer* g_quic_server = nullptr;
int g_quic_server_port = 0;

}  // namespace

namespace net {

std::string const QuicSimpleTestServer::GetDomain() {
  return kTestServerDomain;
}

std::string const QuicSimpleTestServer::GetHost() {
  return kTestServerHost;
}

HostPortPair const QuicSimpleTestServer::GetHostPort() {
  return HostPortPair(kTestServerHost, GetPort());
}

GURL QuicSimpleTestServer::GetFileURL(const std::string& file_path) {
  return GURL("https://test.example.com:" + base::NumberToString(GetPort()))
      .Resolve(file_path);
}

GURL QuicSimpleTestServer::GetHelloURL() {
  // Don't include |port| into Hello URL as it is mapped differently.
  return GURL("https://test.example.com").Resolve(kHelloPath);
}

std::string const QuicSimpleTestServer::GetStatusHeaderName() {
  return kStatusHeader;
}

// Hello Url returns response with HTTP/2 headers and trailers.
std::string const QuicSimpleTestServer::GetHelloPath() {
  return kHelloPath;
}

std::string const QuicSimpleTestServer::GetHelloBodyValue() {
  return kHelloBodyValue;
}
std::string const QuicSimpleTestServer::GetHelloStatus() {
  return kHelloStatus;
}

std::string const QuicSimpleTestServer::GetHelloHeaderName() {
  return kHelloHeaderName;
}

std::string const QuicSimpleTestServer::GetHelloHeaderValue() {
  return kHelloHeaderValue;
}

std::string const QuicSimpleTestServer::GetCombinedHeaderName() {
  return kCombinedHeaderName;
}

std::string const QuicSimpleTestServer::GetHelloTrailerName() {
  return kHelloTrailerName;
}

std::string const QuicSimpleTestServer::GetHelloTrailerValue() {
  return kHelloTrailerValue;
}

// Simple Url returns response without HTTP/2 trailers.
GURL QuicSimpleTestServer::GetSimpleURL() {
  // Don't include |port| into Simple URL as it is mapped differently.
  return GURL("https://test.example.com").Resolve(kSimplePath);
}

std::string const QuicSimpleTestServer::GetSimpleBodyValue() {
  return kSimpleBodyValue;
}

std::string const QuicSimpleTestServer::GetSimpleStatus() {
  return kSimpleStatus;
}

std::string const QuicSimpleTestServer::GetSimpleHeaderName() {
  return kSimpleHeaderName;
}

std::string const QuicSimpleTestServer::GetSimpleHeaderValue() {
  return kSimpleHeaderValue;
}

void SetupQuicMemoryCacheBackend() {
  quiche::HttpHeaderBlock headers;
  headers[kHelloHeaderName] = kHelloHeaderValue;
  headers[kStatusHeader] = kHelloStatus;
  headers[kCombinedHeaderName] = kCombinedHelloHeaderValue;
  quiche::HttpHeaderBlock trailers;
  trailers[kHelloTrailerName] = kHelloTrailerValue;
  g_quic_cache_backend = new quic::QuicMemoryCacheBackend();
  g_quic_cache_backend->AddResponse(base::StringPrintf("%s", kTestServerHost),
                                    kHelloPath, std::move(headers),
                                    kHelloBodyValue, std::move(trailers));
  headers[kSimpleHeaderName] = kSimpleHeaderValue;
  headers[kStatusHeader] = kSimpleStatus;
  g_quic_cache_backend->AddResponse(base::StringPrintf("%s", kTestServerHost),
                                    kSimplePath, std::move(headers),
                                    kSimpleBodyValue);
}

void StartQuicServerOnServerThread(const base::FilePath& test_files_root,
                                   base::WaitableEvent* server_started_event) {
  CHECK(g_quic_server_thread->task_runner()->BelongsToCurrentThread());
  CHECK(!g_quic_server);

  quic::QuicConfig config;
  // Set up server certs.
  base::FilePath directory;
  directory = test_files_root;
  auto proof_source = std::make_unique<ProofSourceChromium>();
  CHECK(proof_source->Initialize(directory.AppendASCII("quic-chain.pem"),
                                 directory.AppendASCII("quic-leaf-cert.key"),
                                 base::FilePath()));
  SetupQuicMemoryCacheBackend();

  // If we happen to list on a disallowed port, connections will fail. Try in a
  // loop until we get an allowed port.
  std::unique_ptr<QuicSimpleServer> server;
  bool got_allowed_port = false;
  constexpr int kMaxTries = 100;
  int rv = 0;

  for (int tries = 0; !got_allowed_port && tries < kMaxTries; ++tries) {
    server = std::make_unique<QuicSimpleServer>(
        std::move(proof_source), config,
        quic::QuicCryptoServerConfig::ConfigOptions(),
        quic::AllSupportedVersions(), g_quic_cache_backend);

    // Start listening on an unbound port.
    rv = server->Listen(IPEndPoint(IPAddress::IPv4AllZeros(), 0));
    if (rv >= 0) {
      got_allowed_port |= IsPortAllowedForScheme(
          server->server_address().port(), url::kHttpsScheme);
    }
  }

  CHECK_GE(rv, 0) << "QuicSimpleTestServer: Listen failed";
  CHECK(got_allowed_port);
  g_quic_server_port = server->server_address().port();
  g_quic_server = server.release();
  server_started_event->Signal();
}

void ShutdownOnServerThread(base::WaitableEvent* server_stopped_event) {
  DCHECK(g_quic_server_thread->task_runner()->BelongsToCurrentThread());
  g_quic_server->Shutdown();
  delete g_quic_server;
  g_quic_server = nullptr;
  delete g_quic_cache_backend;
  g_quic_cache_backend = nullptr;
  server_stopped_event->Signal();
}

void ShutdownDispatcherOnServerThread(
    base::WaitableEvent* dispatcher_stopped_event) {
  DCHECK(g_quic_server_thread->task_runner()->BelongsToCurrentThread());
  g_quic_server->dispatcher()->Shutdown();
  dispatcher_stopped_event->Signal();
}

bool QuicSimpleTestServer::Start() {
  CHECK(!g_quic_server_thread);
  g_quic_server_thread = new base::Thread("quic server thread");
  base::Thread::Options thread_options;
  thread_options.message_pump_type = base::MessagePumpType::IO;
  bool started =
      g_quic_server_thread->StartWithOptions(std::move(thread_options));
  CHECK(started);
  base::FilePath test_files_root = GetTestCertsDirectory();

  base::WaitableEvent server_started_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  g_quic_server_thread->task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&StartQuicServerOnServerThread, test_files_root,
                                &server_started_event));
  server_started_event.Wait();
  return true;
}

void QuicSimpleTestServer::AddResponse(const std::string& path,
                                       quiche::HttpHeaderBlock response_headers,
                                       const std::string& response_body) {
  g_quic_cache_backend->AddResponse(
      base::StringPrintf("%s:%d", kTestServerHost, GetPort()), path,
      std::move(response_headers), response_body);
}

void QuicSimpleTestServer::AddResponseWithEarlyHints(
    const std::string& path,
    const quiche::HttpHeaderBlock& response_headers,
    const std::string& response_body,
    const std::vector<quiche::HttpHeaderBlock>& early_hints) {
  g_quic_cache_backend->AddResponseWithEarlyHints(kTestServerHost, path,
                                                  response_headers.Clone(),
                                                  response_body, early_hints);
}

void QuicSimpleTestServer::SetResponseDelay(const std::string& path,
                                            base::TimeDelta delay) {
  g_quic_cache_backend->SetResponseDelay(
      base::StringPrintf("%s:%d", kTestServerHost, GetPort()), path,
      quic::QuicTime::Delta::FromMicroseconds(delay.InMicroseconds()));
}

// Shut down the server dispatcher, and the stream should error out.
void QuicSimpleTestServer::ShutdownDispatcherForTesting() {
  if (!g_quic_server)
    return;
  DCHECK(!g_quic_server_thread->task_runner()->BelongsToCurrentThread());
  base::WaitableEvent dispatcher_stopped_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  g_quic_server_thread->task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&ShutdownDispatcherOnServerThread,
                                &dispatcher_stopped_event));
  dispatcher_stopped_event.Wait();
}

void QuicSimpleTestServer::Shutdown() {
  if (!g_quic_server)
    return;
  DCHECK(!g_quic_server_thread->task_runner()->BelongsToCurrentThread());
  base::WaitableEvent server_stopped_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  g_quic_server_thread->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&ShutdownOnServerThread, &server_stopped_event));
  server_stopped_event.Wait();
  delete g_quic_server_thread;
  g_quic_server_thread = nullptr;
}

int QuicSimpleTestServer::GetPort() {
  return g_quic_server_port;
}

}  // namespace net
```