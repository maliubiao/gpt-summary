Response:
The user wants to understand the functionality of the `socket_test_util.cc` file in Chromium's network stack. They've asked for:

1. **Functionality Summary:** What does this file do?
2. **Relationship to JavaScript:** Does it interact with JavaScript? If so, how?
3. **Logical Reasoning Examples:** Provide examples of input and output for its functions.
4. **Common Usage Errors:**  Illustrate mistakes developers might make when using this code.
5. **Debugging Context:** Explain how a user's action could lead to this code being executed.
6. **Summary of the Provided Code (Part 1):**  Summarize the functionality of the code snippet they've provided.

Let's address these points systematically by analyzing the provided code.

**1. Functionality Summary:**

Scanning the includes and class definitions reveals the core purpose. The file seems to provide utilities for testing network sockets. It includes mock implementations of sockets (`MockTCPClientSocket`, `MockUDPClientSocket`, `MockSSLClientSocket`), data providers to simulate network behavior (`SocketDataProvider`, `StaticSocketDataProvider`, `SSLSocketDataProvider`, `SequencedSocketData`), and a factory to create these mock sockets (`MockClientSocketFactory`). The presence of `MockRead`, `MockWrite`, `MockConnect`, and `MockConfirm` structs suggests a way to predefine the expected I/O behavior of the mock sockets.

**2. Relationship to JavaScript:**

This C++ code is part of Chromium's network stack, which is a lower-level component. While it doesn't directly execute JavaScript, it's crucial for network communication initiated by JavaScript in web pages or within the browser's UI. When JavaScript uses APIs like `fetch` or `XMLHttpRequest`, the underlying network requests eventually rely on this C++ code to handle socket creation, data transfer, and SSL/TLS negotiation.

**3. Logical Reasoning Examples:**

Consider the `StaticSocketDataProvider`. A developer might want to test how their code reacts to a server sending a specific response.

* **Assumption:** The server will send "Hello World!" after the client sends a request.

* **Input (Mock Data):**
    * `MockWrite(SYNCHRONOUS, 0, "Client Request")`  // Client sends a request.
    * `MockRead(SYNCHRONOUS, 1, "Hello World!")` // Server responds.

* **Output (Behavior):** When the mock socket's `Read()` method is called, it will return "Hello World!". When the `Write()` method is called with "Client Request", it will be considered a successful write.

Consider the `SequencedSocketData`. This allows for more complex, asynchronous scenarios.

* **Assumption:** The server will send a partial response ("Hel") then wait for an acknowledgement ("ACK") before sending the rest ("lo World!").

* **Input (Mock Data):**
    * `MockRead(ASYNC, 0, "Hel")`
    * `MockWrite(ASYNC, 1, "ACK")`
    * `MockRead(ASYNC, 2, "lo World!")`

* **Output (Behavior):** The first `Read()` call will return "Hel" asynchronously. The client's code will need to send "ACK". Only then will the next `Read()` return "lo World!".

**4. Common Usage Errors:**

* **Mismatch between expected and actual write data:**  A developer might define a `MockWrite` with specific data, but the code under test writes different data. The test will fail because `VerifyWriteData` will return `false`. For example, expecting "GET / HTTP/1.1" but the code sends "GET /index.html HTTP/1.1".

* **Incorrect sequencing of mock reads/writes in `SequencedSocketData`:** The sequence numbers in `MockRead` and `MockWrite` must be contiguous and start from 0. Skipping a sequence number or repeating one will lead to a check failure during `SequencedSocketData` initialization.

* **Forgetting to consume all mock data:** If the test doesn't perform enough read or write operations to exhaust the provided `MockRead` and `MockWrite` data, the `ExpectAllReadDataConsumed` or `ExpectAllWriteDataConsumed` checks will fail at the end of the test.

**5. Debugging Context:**

A user action like clicking a link in a web browser triggers a navigation. This involves several steps:

1. **User clicks a link:** The browser captures the click event.
2. **Navigation starts:** The browser initiates a network request to fetch the new page.
3. **DNS resolution:** The browser resolves the hostname in the URL to an IP address.
4. **Socket creation:** The browser creates a TCP socket (or potentially a QUIC socket) to connect to the server. This is where the `MockClientSocketFactory` and associated mock socket classes become relevant in a testing environment.
5. **Connection establishment:** The socket attempts to establish a connection. In a testing scenario, `MockConnect` data would control the success or failure of this.
6. **Data transfer:** Once connected, the browser sends an HTTP request. The `MockWrite` data simulates the expected outgoing data. The server's response is simulated by `MockRead` data.
7. **Page rendering:** The received data is processed and the new web page is rendered.

During testing, if there's an issue with the network communication (e.g., the connection fails, the server sends unexpected data), the test might involve the code in `socket_test_util.cc` to simulate and verify the socket behavior under different conditions.

**6. Summary of the Provided Code (Part 1):**

The first part of `net/socket/socket_test_util.cc` defines various utility classes and functions for mocking network socket behavior in tests. Key components include:

* **Helper functions for data dumping:** `DumpData`, `DumpMockReadWrite` format and output mock data for debugging.
* **Mock I/O primitives:** `MockConnect`, `MockConfirm`, `MockRead`, `MockWrite` structures represent expected socket events (connection attempts, data reads, data writes) with configurable behavior (synchronous/asynchronous, success/failure).
* **Data provider base class:** `SocketDataProvider` serves as an interface for providing mock socket data.
* **Static data provider:** `StaticSocketDataProvider` and its helper class `StaticSocketDataHelper` allow defining a fixed sequence of `MockRead` and `MockWrite` operations. This is useful for simple, predictable scenarios.
* **SSL-specific data provider:** `SSLSocketDataProvider` extends `StaticSocketDataProvider` to include mock data for SSL/TLS handshake parameters and results.

Essentially, this section provides the building blocks for creating controlled, predictable network interactions in test environments, enabling developers to verify the correctness of network-related code without relying on actual network connections. It focuses on synchronous and simple asynchronous mocking.

这是 `net/socket/socket_test_util.cc` 文件的前半部分，它主要的功能是提供了一系列用于在 Chromium 网络栈的单元测试中模拟网络 socket 行为的工具类和函数。  这些工具使得开发者可以在不依赖真实网络环境的情况下，测试网络相关的代码逻辑。

**主要功能归纳:**

1. **Mock I/O 操作:** 定义了用于模拟 socket 连接、读取和写入操作的数据结构，例如 `MockConnect`、`MockConfirm`、`MockRead` 和 `MockWrite`。这些结构体可以配置为同步或异步操作，并指定预期的结果（成功或特定的错误码）。

2. **数据提供器 (Data Providers):**  提供了多种类来模拟 socket 的数据输入和输出：
   - `SocketDataProvider`:  作为所有数据提供器的基类。
   - `StaticSocketDataProvider`:  允许预先定义一系列静态的读取和写入操作。测试时，socket 会按照预定义的顺序返回数据或模拟写入操作。
   - `SSLSocketDataProvider`:  继承自 `StaticSocketDataProvider`，并扩展了对 SSL/TLS 连接模拟的支持，可以指定模拟的 SSL 连接结果、SSL 信息等。
   - `SequencedSocketData`:  允许定义更复杂的、有顺序的异步读取和写入操作序列。它可以模拟网络交互中的暂停和恢复，更贴合真实的异步网络场景。

3. **Mock Socket 工厂 (Socket Factory):**  `MockClientSocketFactory` 用于创建模拟的客户端 socket 对象，例如 `MockTCPClientSocket` 和 `MockUDPClientSocket`。  它允许在测试中方便地使用预先配置好的数据提供器来模拟 socket 的行为。

4. **辅助调试工具:**  包含了一些用于调试和日志输出的辅助函数，例如 `DumpData` 和 `DumpMockReadWrite`，可以将 mock 的数据以易于阅读的格式打印出来，方便开发者理解和调试测试过程。

**与 JavaScript 的关系 (如果存在):**

这个 C++ 文件本身不直接包含 JavaScript 代码，但它所提供的功能对于测试那些与 JavaScript 交互的网络功能至关重要。

**举例说明:** 假设一个 JavaScript 应用使用 `fetch` API 发起一个 HTTP 请求。在 Chromium 的单元测试中，我们可以使用 `MockClientSocketFactory` 和 `StaticSocketDataProvider` 来模拟这个请求和响应的过程：

* **模拟请求:** 可以定义一个 `MockWrite` 对象，包含预期的 HTTP 请求头和数据。
* **模拟响应:** 可以定义一个 `MockRead` 对象，包含预期的 HTTP 响应头和数据。

当 JavaScript 代码执行 `fetch` 并尝试通过 socket 发送数据时，mock socket 会 "接收" 到预定义的请求数据。当 JavaScript 代码尝试从 socket 读取数据时，mock socket 会返回预定义的响应数据。这样，就可以在不实际发送网络请求的情况下测试 JavaScript 代码处理网络请求和响应的逻辑。

**逻辑推理举例 (假设输入与输出):**

**场景：** 测试代码尝试从一个 TCP socket 读取数据，并且我们使用 `StaticSocketDataProvider` 预设了一个读取操作。

**假设输入:**

* `StaticSocketDataProvider` 被配置为包含一个 `MockRead(SYNCHRONOUS, 0, "Hello")`。
* 测试代码调用 mock socket 的 `Read()` 方法。

**输出:**

* mock socket 的 `Read()` 方法会同步返回 "Hello"，并成功读取 5 个字节。

**用户或编程常见的使用错误:**

1. **预期的写入数据与实际写入数据不匹配:**  如果 `StaticSocketDataProvider` 中定义的 `MockWrite` 数据与测试代码实际写入的数据不一致，测试将会失败。例如，预期写入 "GET / HTTP/1.1"，但代码实际写入 "GET /index.html HTTP/1.1"。

2. **没有消耗完所有预设的读取数据:**  如果 `StaticSocketDataProvider` 中定义了多个 `MockRead` 操作，但测试代码只读取了部分数据，在测试结束时可能会有断言失败，提示还有未消耗的读取数据。

3. **在 `SequencedSocketData` 中序列号设置错误:**  在 `SequencedSocketData` 中，`MockRead` 和 `MockWrite` 的 `sequence_number` 必须是连续的，从 0 开始递增。如果序列号不连续或重复，初始化时会触发断言失败。

**用户操作如何一步步到达这里 (调试线索):**

假设开发者正在测试一个浏览器功能，该功能需要在用户访问某个 HTTPS 网站时进行特定的 SSL/TLS 协商。为了进行单元测试，开发者可能会：

1. **编写单元测试代码:**  使用 gtest 框架，创建一个测试用例来模拟用户访问该网站的场景。
2. **使用 `MockClientSocketFactory`:** 在测试用例中创建一个 `MockClientSocketFactory` 对象。
3. **添加 `SSLSocketDataProvider`:** 创建一个 `SSLSocketDataProvider` 对象，用于模拟 SSL 连接过程，包括模拟服务器返回的证书、协商的加密套件等。例如，可以设置 `connect` 成员模拟连接成功，并设置 `ssl_info` 成员模拟 SSL 连接的状态。
4. **将 `SSLSocketDataProvider` 添加到工厂:** 调用 `mock_client_socket_factory->AddSSLSocketDataProvider(ssl_data_provider)`，将模拟的 SSL 数据提供器添加到 socket 工厂中。
5. **执行网络操作:**  在测试代码中，模拟用户触发网络请求，例如通过创建一个 `URLRequest` 并调用 `Start()` 方法。
6. **`MockClientSocketFactory` 创建 mock socket:** 当 `URLRequest` 需要创建 SSL socket 时，会调用 `MockClientSocketFactory::CreateSSLClientSocket` 方法。
7. **使用 `SSLSocketDataProvider` 提供 mock 数据:**  创建的 mock SSL socket 会使用之前添加的 `SSLSocketDataProvider` 来模拟 SSL 连接的各个阶段，例如模拟握手过程、证书验证等。

如果在测试过程中出现错误，例如 SSL 握手失败，开发者可能会查看 `SSLSocketDataProvider` 的配置，检查模拟的证书是否正确，模拟的握手过程是否符合预期。`DumpMockReadWrite` 等辅助函数可以帮助开发者查看 mock socket 的数据交互过程。

**本部分功能总结:**

总而言之，`net/socket/socket_test_util.cc` 的前半部分提供了一套强大的工具，用于在 Chromium 网络栈的单元测试中精确地模拟各种 socket 行为，包括 TCP 和 SSL 连接，以及数据的读取和写入。这些工具使得开发者可以编写可靠且高效的单元测试，而无需依赖真实的、不可控的网络环境。

Prompt: 
```
这是目录为net/socket/socket_test_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/socket/socket_test_util.h"

#include <inttypes.h>  // For SCNx64
#include <stdint.h>
#include <stdio.h>

#include <memory>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/compiler_specific.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/rand_util.h"
#include "base/ranges/algorithm.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/address_family.h"
#include "net/base/address_list.h"
#include "net/base/auth.h"
#include "net/base/completion_once_callback.h"
#include "net/base/hex_utils.h"
#include "net/base/ip_address.h"
#include "net/base/load_timing_info.h"
#include "net/base/net_errors.h"
#include "net/base/proxy_server.h"
#include "net/http/http_network_session.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_source_type.h"
#include "net/socket/connect_job.h"
#include "net/socket/socket.h"
#include "net/socket/stream_socket.h"
#include "net/socket/websocket_endpoint_lock_manager.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/ssl_info.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/abseil-cpp/absl/strings/ascii.h"

#if BUILDFLAG(IS_ANDROID)
#include "base/android/build_info.h"
#endif

#define NET_TRACE(level, s) VLOG(level) << s << __FUNCTION__ << "() "

namespace net {
namespace {

inline char AsciifyHigh(char x) {
  char nybble = static_cast<char>((x >> 4) & 0x0F);
  return nybble + ((nybble < 0x0A) ? '0' : 'A' - 10);
}

inline char AsciifyLow(char x) {
  char nybble = static_cast<char>((x >> 0) & 0x0F);
  return nybble + ((nybble < 0x0A) ? '0' : 'A' - 10);
}

inline char Asciify(char x) {
  return absl::ascii_isprint(static_cast<unsigned char>(x)) ? x : '.';
}

void DumpData(const char* data, int data_len) {
  if (logging::LOGGING_INFO < logging::GetMinLogLevel()) {
    return;
  }
  DVLOG(1) << "Length:  " << data_len;
  const char* pfx = "Data:    ";
  if (!data || (data_len <= 0)) {
    DVLOG(1) << pfx << "<None>";
  } else {
    int i;
    for (i = 0; i <= (data_len - 4); i += 4) {
      DVLOG(1) << pfx << AsciifyHigh(data[i + 0]) << AsciifyLow(data[i + 0])
               << AsciifyHigh(data[i + 1]) << AsciifyLow(data[i + 1])
               << AsciifyHigh(data[i + 2]) << AsciifyLow(data[i + 2])
               << AsciifyHigh(data[i + 3]) << AsciifyLow(data[i + 3]) << "  '"
               << Asciify(data[i + 0]) << Asciify(data[i + 1])
               << Asciify(data[i + 2]) << Asciify(data[i + 3]) << "'";
      pfx = "         ";
    }
    // Take care of any 'trailing' bytes, if data_len was not a multiple of 4.
    switch (data_len - i) {
      case 3:
        DVLOG(1) << pfx << AsciifyHigh(data[i + 0]) << AsciifyLow(data[i + 0])
                 << AsciifyHigh(data[i + 1]) << AsciifyLow(data[i + 1])
                 << AsciifyHigh(data[i + 2]) << AsciifyLow(data[i + 2])
                 << "    '" << Asciify(data[i + 0]) << Asciify(data[i + 1])
                 << Asciify(data[i + 2]) << " '";
        break;
      case 2:
        DVLOG(1) << pfx << AsciifyHigh(data[i + 0]) << AsciifyLow(data[i + 0])
                 << AsciifyHigh(data[i + 1]) << AsciifyLow(data[i + 1])
                 << "      '" << Asciify(data[i + 0]) << Asciify(data[i + 1])
                 << "  '";
        break;
      case 1:
        DVLOG(1) << pfx << AsciifyHigh(data[i + 0]) << AsciifyLow(data[i + 0])
                 << "        '" << Asciify(data[i + 0]) << "   '";
        break;
    }
  }
}

template <MockReadWriteType type>
void DumpMockReadWrite(const MockReadWrite<type>& r) {
  if (logging::LOGGING_INFO < logging::GetMinLogLevel()) {
    return;
  }
  DVLOG(1) << "Async:   " << (r.mode == ASYNC) << "\nResult:  " << r.result;
  DumpData(r.data, r.data_len);
  const char* stop = (r.sequence_number & MockRead::STOPLOOP) ? " (STOP)" : "";
  DVLOG(1) << "Stage:   " << (r.sequence_number & ~MockRead::STOPLOOP) << stop;
}

void RunClosureIfNonNull(base::OnceClosure closure) {
  if (!closure.is_null()) {
    std::move(closure).Run();
  }
}

}  // namespace

MockConnectCompleter::MockConnectCompleter() = default;

MockConnectCompleter::~MockConnectCompleter() = default;

void MockConnectCompleter::SetCallback(CompletionOnceCallback callback) {
  CHECK(!callback_);
  callback_ = std::move(callback);
}

void MockConnectCompleter::Complete(int result) {
  CHECK(callback_);
  std::move(callback_).Run(result);
}

MockConnect::MockConnect() : mode(ASYNC), result(OK) {
  peer_addr = IPEndPoint(IPAddress(192, 0, 2, 33), 0);
}

MockConnect::MockConnect(IoMode io_mode, int r) : mode(io_mode), result(r) {
  peer_addr = IPEndPoint(IPAddress(192, 0, 2, 33), 0);
}

MockConnect::MockConnect(IoMode io_mode, int r, IPEndPoint addr)
    : mode(io_mode), result(r), peer_addr(addr) {}

MockConnect::MockConnect(IoMode io_mode,
                         int r,
                         IPEndPoint addr,
                         bool first_attempt_fails)
    : mode(io_mode),
      result(r),
      peer_addr(addr),
      first_attempt_fails(first_attempt_fails) {}

MockConnect::MockConnect(MockConnectCompleter* completer)
    : mode(ASYNC), result(OK), completer(completer) {}

MockConnect::~MockConnect() = default;

MockConfirm::MockConfirm() : mode(SYNCHRONOUS), result(OK) {}

MockConfirm::MockConfirm(IoMode io_mode, int r) : mode(io_mode), result(r) {}

MockConfirm::~MockConfirm() = default;

bool SocketDataProvider::IsIdle() const {
  return true;
}

void SocketDataProvider::Initialize(AsyncSocket* socket) {
  CHECK(!socket_);
  CHECK(socket);
  socket_ = socket;
  Reset();
}

void SocketDataProvider::DetachSocket() {
  CHECK(socket_);
  socket_ = nullptr;
}

SocketDataProvider::SocketDataProvider() = default;

SocketDataProvider::~SocketDataProvider() {
  if (socket_)
    socket_->OnDataProviderDestroyed();
}

StaticSocketDataHelper::StaticSocketDataHelper(
    base::span<const MockRead> reads,
    base::span<const MockWrite> writes)
    : reads_(reads), writes_(writes) {}

StaticSocketDataHelper::~StaticSocketDataHelper() = default;

const MockRead& StaticSocketDataHelper::PeekRead() const {
  CHECK(!AllReadDataConsumed());
  return reads_[read_index_];
}

const MockWrite& StaticSocketDataHelper::PeekWrite() const {
  CHECK(!AllWriteDataConsumed());
  return writes_[write_index_];
}

const MockRead& StaticSocketDataHelper::AdvanceRead() {
  CHECK(!AllReadDataConsumed());
  return reads_[read_index_++];
}

const MockWrite& StaticSocketDataHelper::AdvanceWrite() {
  CHECK(!AllWriteDataConsumed());
  return writes_[write_index_++];
}

void StaticSocketDataHelper::Reset() {
  read_index_ = 0;
  write_index_ = 0;
}

bool StaticSocketDataHelper::VerifyWriteData(const std::string& data,
                                             SocketDataPrinter* printer) {
  CHECK(!AllWriteDataConsumed());
  // Check that the actual data matches the expectations, skipping over any
  // pause events.
  const MockWrite& next_write = PeekRealWrite();
  if (!next_write.data)
    return true;

  // Note: Partial writes are supported here.  If the expected data
  // is a match, but shorter than the write actually written, that is legal.
  // Example:
  //   Application writes "foobarbaz" (9 bytes)
  //   Expected write was "foo" (3 bytes)
  //   This is a success, and the function returns true.
  std::string expected_data(next_write.data, next_write.data_len);
  std::string actual_data(data.substr(0, next_write.data_len));
  if (printer) {
    EXPECT_TRUE(actual_data == expected_data)
        << "Actual formatted write data:\n"
        << printer->PrintWrite(data) << "Expected formatted write data:\n"
        << printer->PrintWrite(expected_data) << "Actual raw write data:\n"
        << HexDump(data) << "Expected raw write data:\n"
        << HexDump(expected_data);
  } else {
    EXPECT_TRUE(actual_data == expected_data)
        << "Actual write data:\n"
        << HexDump(data) << "Expected write data:\n"
        << HexDump(expected_data);
  }
  return expected_data == actual_data;
}

void StaticSocketDataHelper::ExpectAllReadDataConsumed(
    SocketDataPrinter* printer) const {
  if (AllReadDataConsumed()) {
    return;
  }

  std::ostringstream msg;
  if (read_index_ < read_count()) {
    msg << "Unconsumed reads:\n";
    for (size_t i = read_index_; i < read_count(); i++) {
      msg << (reads_[i].mode == ASYNC ? "ASYNC" : "SYNC") << " MockRead seq "
          << reads_[i].sequence_number << ":\n";
      if (reads_[i].result != OK) {
        msg << "Result: " << reads_[i].result << "\n";
      }
      if (reads_[i].data) {
        std::string data(reads_[i].data, reads_[i].data_len);
        if (printer) {
          msg << printer->PrintWrite(data);
        }
        msg << HexDump(data);
      }
    }
  }
  EXPECT_TRUE(AllReadDataConsumed()) << msg.str();
}

void StaticSocketDataHelper::ExpectAllWriteDataConsumed(
    SocketDataPrinter* printer) const {
  if (AllWriteDataConsumed()) {
    return;
  }

  std::ostringstream msg;
  if (write_index_ < write_count()) {
    msg << "Unconsumed writes:\n";
    for (size_t i = write_index_; i < write_count(); i++) {
      msg << (writes_[i].mode == ASYNC ? "ASYNC" : "SYNC") << " MockWrite seq "
          << writes_[i].sequence_number << ":\n";
      if (writes_[i].result != OK) {
        msg << "Result: " << writes_[i].result << "\n";
      }
      if (writes_[i].data) {
        std::string data(writes_[i].data, writes_[i].data_len);
        if (printer) {
          msg << printer->PrintWrite(data);
        }
        msg << HexDump(data);
      }
    }
  }
  EXPECT_TRUE(AllWriteDataConsumed()) << msg.str();
}

const MockWrite& StaticSocketDataHelper::PeekRealWrite() const {
  for (size_t i = write_index_; i < write_count(); i++) {
    if (writes_[i].mode != ASYNC || writes_[i].result != ERR_IO_PENDING)
      return writes_[i];
  }

  NOTREACHED() << "No write data available.";
}

StaticSocketDataProvider::StaticSocketDataProvider()
    : StaticSocketDataProvider(base::span<const MockRead>(),
                               base::span<const MockWrite>()) {}

StaticSocketDataProvider::StaticSocketDataProvider(
    base::span<const MockRead> reads,
    base::span<const MockWrite> writes)
    : helper_(reads, writes) {}

StaticSocketDataProvider::~StaticSocketDataProvider() = default;

void StaticSocketDataProvider::Pause() {
  paused_ = true;
}

void StaticSocketDataProvider::Resume() {
  paused_ = false;
}

MockRead StaticSocketDataProvider::OnRead() {
  if (AllReadDataConsumed()) {
    const net::MockRead pending_read(net::SYNCHRONOUS, net::ERR_IO_PENDING);
    return pending_read;
  }

  return helper_.AdvanceRead();
}

MockWriteResult StaticSocketDataProvider::OnWrite(const std::string& data) {
  if (helper_.write_count() == 0) {
    // Not using mock writes; succeed synchronously.
    return MockWriteResult(SYNCHRONOUS, data.length());
  }
  if (printer_) {
    EXPECT_FALSE(helper_.AllWriteDataConsumed())
        << "No more mock data to match write:\nFormatted write data:\n"
        << printer_->PrintWrite(data) << "Raw write data:\n"
        << HexDump(data);
  } else {
    EXPECT_FALSE(helper_.AllWriteDataConsumed())
        << "No more mock data to match write:\nRaw write data:\n"
        << HexDump(data);
  }
  if (helper_.AllWriteDataConsumed()) {
    return MockWriteResult(SYNCHRONOUS, ERR_UNEXPECTED);
  }

  // Check that what we are writing matches the expectation.
  // Then give the mocked return value.
  if (!helper_.VerifyWriteData(data, printer_))
    return MockWriteResult(SYNCHRONOUS, ERR_UNEXPECTED);

  const MockWrite& next_write = helper_.AdvanceWrite();
  // In the case that the write was successful, return the number of bytes
  // written. Otherwise return the error code.
  int result =
      next_write.result == OK ? next_write.data_len : next_write.result;
  return MockWriteResult(next_write.mode, result);
}

bool StaticSocketDataProvider::AllReadDataConsumed() const {
  return paused_ || helper_.AllReadDataConsumed();
}

bool StaticSocketDataProvider::AllWriteDataConsumed() const {
  return helper_.AllWriteDataConsumed();
}

void StaticSocketDataProvider::Reset() {
  helper_.Reset();
}

SSLSocketDataProvider::SSLSocketDataProvider(IoMode mode, int result)
    : connect(mode, result),
      expected_ssl_version_min(kDefaultSSLVersionMin),
      expected_ssl_version_max(kDefaultSSLVersionMax) {
  SSLConnectionStatusSetVersion(SSL_CONNECTION_VERSION_TLS1_3,
                                &ssl_info.connection_status);
  // Set to TLS_CHACHA20_POLY1305_SHA256
  SSLConnectionStatusSetCipherSuite(0x1301, &ssl_info.connection_status);
}

SSLSocketDataProvider::SSLSocketDataProvider(MockConnectCompleter* completer)
    : connect(completer),
      expected_ssl_version_min(kDefaultSSLVersionMin),
      expected_ssl_version_max(kDefaultSSLVersionMax) {
  SSLConnectionStatusSetVersion(SSL_CONNECTION_VERSION_TLS1_3,
                                &ssl_info.connection_status);
  // Set to TLS_CHACHA20_POLY1305_SHA256
  SSLConnectionStatusSetCipherSuite(0x1301, &ssl_info.connection_status);
}

SSLSocketDataProvider::SSLSocketDataProvider(
    const SSLSocketDataProvider& other) = default;

SSLSocketDataProvider::~SSLSocketDataProvider() = default;

SequencedSocketData::SequencedSocketData()
    : SequencedSocketData(base::span<const MockRead>(),
                          base::span<const MockWrite>()) {}

SequencedSocketData::SequencedSocketData(base::span<const MockRead> reads,
                                         base::span<const MockWrite> writes)
    : helper_(reads, writes) {
  // Check that reads and writes have a contiguous set of sequence numbers
  // starting from 0 and working their way up, with no repeats and skipping
  // no values.
  int next_sequence_number = 0;
  bool last_event_was_pause = false;

  auto next_read = reads.begin();
  auto next_write = writes.begin();
  while (next_read != reads.end() || next_write != writes.end()) {
    if (next_read != reads.end() &&
        next_read->sequence_number == next_sequence_number) {
      // Check if this is a pause.
      if (next_read->mode == ASYNC && next_read->result == ERR_IO_PENDING) {
        CHECK(!last_event_was_pause)
            << "Two pauses in a row are not allowed: " << next_sequence_number;
        last_event_was_pause = true;
      } else if (last_event_was_pause) {
        CHECK_EQ(ASYNC, next_read->mode)
            << "A sync event after a pause makes no sense: "
            << next_sequence_number;
        CHECK_NE(ERR_IO_PENDING, next_read->result)
            << "A pause event after a pause makes no sense: "
            << next_sequence_number;
        last_event_was_pause = false;
      }

      ++next_read;
      ++next_sequence_number;
      continue;
    }
    if (next_write != writes.end() &&
        next_write->sequence_number == next_sequence_number) {
      // Check if this is a pause.
      if (next_write->mode == ASYNC && next_write->result == ERR_IO_PENDING) {
        CHECK(!last_event_was_pause)
            << "Two pauses in a row are not allowed: " << next_sequence_number;
        last_event_was_pause = true;
      } else if (last_event_was_pause) {
        CHECK_EQ(ASYNC, next_write->mode)
            << "A sync event after a pause makes no sense: "
            << next_sequence_number;
        CHECK_NE(ERR_IO_PENDING, next_write->result)
            << "A pause event after a pause makes no sense: "
            << next_sequence_number;
        last_event_was_pause = false;
      }

      ++next_write;
      ++next_sequence_number;
      continue;
    }
    if (next_write != writes.end()) {
      CHECK(false) << "Sequence number " << next_write->sequence_number
                   << " not found where expected: " << next_sequence_number;
    } else {
      CHECK(false) << "Too few writes, next expected sequence number: "
                   << next_sequence_number;
    }
    return;
  }

  // Last event must not be a pause.  For the final event to indicate the
  // operation never completes, it should be SYNCHRONOUS and return
  // ERR_IO_PENDING.
  CHECK(!last_event_was_pause);

  CHECK(next_read == reads.end());
  CHECK(next_write == writes.end());
}

SequencedSocketData::SequencedSocketData(const MockConnect& connect,
                                         base::span<const MockRead> reads,
                                         base::span<const MockWrite> writes)
    : SequencedSocketData(reads, writes) {
  set_connect_data(connect);
}
MockRead SequencedSocketData::OnRead() {
  CHECK_EQ(IoState::kIdle, read_state_);
  CHECK(!helper_.AllReadDataConsumed())
      << "Application tried to read but there is no read data left";

  NET_TRACE(1, " *** ") << "sequence_number: " << sequence_number_;
  const MockRead& next_read = helper_.PeekRead();
  NET_TRACE(1, " *** ") << "next_read: " << next_read.sequence_number;
  CHECK_GE(next_read.sequence_number, sequence_number_);

  if (next_read.sequence_number <= sequence_number_) {
    if (next_read.mode == SYNCHRONOUS) {
      NET_TRACE(1, " *** ") << "Returning synchronously";
      DumpMockReadWrite(next_read);
      helper_.AdvanceRead();
      ++sequence_number_;
      MaybePostWriteCompleteTask();
      return next_read;
    }

    // If the result is ERR_IO_PENDING, then pause.
    if (next_read.result == ERR_IO_PENDING) {
      NET_TRACE(1, " *** ") << "Pausing read at: " << sequence_number_;
      read_state_ = IoState::kPaused;
      if (run_until_paused_run_loop_)
        run_until_paused_run_loop_->Quit();
      return MockRead(SYNCHRONOUS, ERR_IO_PENDING);
    }
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&SequencedSocketData::OnReadComplete,
                                  weak_factory_.GetWeakPtr()));
    CHECK_NE(IoState::kCompleting, write_state_);
    read_state_ = IoState::kCompleting;
  } else if (next_read.mode == SYNCHRONOUS) {
    ADD_FAILURE() << "Unable to perform synchronous IO while stopped";
    return MockRead(SYNCHRONOUS, ERR_UNEXPECTED);
  } else {
    NET_TRACE(1, " *** ") << "Waiting for write to trigger read";
    read_state_ = IoState::kPending;
  }

  return MockRead(SYNCHRONOUS, ERR_IO_PENDING);
}

MockWriteResult SequencedSocketData::OnWrite(const std::string& data) {
  CHECK_EQ(IoState::kIdle, write_state_);
  if (printer_) {
    CHECK(!helper_.AllWriteDataConsumed())
        << "\nNo more mock data to match write:\nFormatted write data:\n"
        << printer_->PrintWrite(data) << "Raw write data:\n"
        << HexDump(data);
  } else {
    CHECK(!helper_.AllWriteDataConsumed())
        << "\nNo more mock data to match write:\nRaw write data:\n"
        << HexDump(data);
  }

  NET_TRACE(1, " *** ") << "sequence_number: " << sequence_number_;
  const MockWrite& next_write = helper_.PeekWrite();
  NET_TRACE(1, " *** ") << "next_write: " << next_write.sequence_number;
  CHECK_GE(next_write.sequence_number, sequence_number_);

  if (!helper_.VerifyWriteData(data, printer_))
    return MockWriteResult(SYNCHRONOUS, ERR_UNEXPECTED);

  if (next_write.sequence_number <= sequence_number_) {
    if (next_write.mode == SYNCHRONOUS) {
      helper_.AdvanceWrite();
      ++sequence_number_;
      MaybePostReadCompleteTask();
      // In the case that the write was successful, return the number of bytes
      // written. Otherwise return the error code.
      int rv =
          next_write.result != OK ? next_write.result : next_write.data_len;
      NET_TRACE(1, " *** ") << "Returning synchronously";
      return MockWriteResult(SYNCHRONOUS, rv);
    }

    // If the result is ERR_IO_PENDING, then pause.
    if (next_write.result == ERR_IO_PENDING) {
      NET_TRACE(1, " *** ") << "Pausing write at: " << sequence_number_;
      write_state_ = IoState::kPaused;
      if (run_until_paused_run_loop_)
        run_until_paused_run_loop_->Quit();
      return MockWriteResult(SYNCHRONOUS, ERR_IO_PENDING);
    }

    NET_TRACE(1, " *** ") << "Posting task to complete write";
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&SequencedSocketData::OnWriteComplete,
                                  weak_factory_.GetWeakPtr()));
    CHECK_NE(IoState::kCompleting, read_state_);
    write_state_ = IoState::kCompleting;
  } else if (next_write.mode == SYNCHRONOUS) {
    ADD_FAILURE() << "Unable to perform synchronous IO while stopped";
    return MockWriteResult(SYNCHRONOUS, ERR_UNEXPECTED);
  } else {
    NET_TRACE(1, " *** ") << "Waiting for read to trigger write";
    write_state_ = IoState::kPending;
  }

  return MockWriteResult(SYNCHRONOUS, ERR_IO_PENDING);
}

bool SequencedSocketData::AllReadDataConsumed() const {
  return helper_.AllReadDataConsumed();
}

void SequencedSocketData::CancelPendingRead() {
  DCHECK_EQ(IoState::kPending, read_state_);

  read_state_ = IoState::kIdle;
}

bool SequencedSocketData::AllWriteDataConsumed() const {
  return helper_.AllWriteDataConsumed();
}

void SequencedSocketData::ExpectAllReadDataConsumed() const {
  helper_.ExpectAllReadDataConsumed(printer_.get());
}

void SequencedSocketData::ExpectAllWriteDataConsumed() const {
  helper_.ExpectAllWriteDataConsumed(printer_.get());
}

bool SequencedSocketData::IsIdle() const {
  // If |busy_before_sync_reads_| is not set, always considered idle.  If
  // no reads left, or the next operation is a write, also consider it idle.
  if (!busy_before_sync_reads_ || helper_.AllReadDataConsumed() ||
      helper_.PeekRead().sequence_number != sequence_number_) {
    return true;
  }

  // If the next operation is synchronous read, treat the socket as not idle.
  if (helper_.PeekRead().mode == SYNCHRONOUS)
    return false;
  return true;
}

bool SequencedSocketData::IsPaused() const {
  // Both states should not be paused.
  DCHECK(read_state_ != IoState::kPaused || write_state_ != IoState::kPaused);
  return write_state_ == IoState::kPaused || read_state_ == IoState::kPaused;
}

void SequencedSocketData::Resume() {
  if (!IsPaused()) {
    ADD_FAILURE() << "Unable to Resume when not paused.";
    return;
  }

  sequence_number_++;
  if (read_state_ == IoState::kPaused) {
    read_state_ = IoState::kPending;
    helper_.AdvanceRead();
  } else {  // write_state_ == IoState::kPaused
    write_state_ = IoState::kPending;
    helper_.AdvanceWrite();
  }

  if (!helper_.AllWriteDataConsumed() &&
      helper_.PeekWrite().sequence_number == sequence_number_) {
    // The next event hasn't even started yet.  Pausing isn't really needed in
    // that case, but may as well support it.
    if (write_state_ != IoState::kPending)
      return;
    write_state_ = IoState::kCompleting;
    OnWriteComplete();
    return;
  }

  CHECK(!helper_.AllReadDataConsumed());

  // The next event hasn't even started yet.  Pausing isn't really needed in
  // that case, but may as well support it.
  if (read_state_ != IoState::kPending)
    return;
  read_state_ = IoState::kCompleting;
  OnReadComplete();
}

void SequencedSocketData::RunUntilPaused() {
  CHECK(!run_until_paused_run_loop_);

  if (IsPaused())
    return;

  run_until_paused_run_loop_ = std::make_unique<base::RunLoop>();
  run_until_paused_run_loop_->Run();
  run_until_paused_run_loop_.reset();
  DCHECK(IsPaused());
}

void SequencedSocketData::MaybePostReadCompleteTask() {
  NET_TRACE(1, " ****** ") << " current: " << sequence_number_;
  // Only trigger the next read to complete if there is already a read pending
  // which should complete at the current sequence number.
  if (read_state_ != IoState::kPending ||
      helper_.PeekRead().sequence_number != sequence_number_) {
    return;
  }

  // If the result is ERR_IO_PENDING, then pause.
  if (helper_.PeekRead().result == ERR_IO_PENDING) {
    NET_TRACE(1, " *** ") << "Pausing read at: " << sequence_number_;
    read_state_ = IoState::kPaused;
    if (run_until_paused_run_loop_)
      run_until_paused_run_loop_->Quit();
    return;
  }

  NET_TRACE(1, " ****** ") << "Posting task to complete read: "
                           << sequence_number_;
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&SequencedSocketData::OnReadComplete,
                                weak_factory_.GetWeakPtr()));
  CHECK_NE(IoState::kCompleting, write_state_);
  read_state_ = IoState::kCompleting;
}

void SequencedSocketData::MaybePostWriteCompleteTask() {
  NET_TRACE(1, " ****** ") << " current: " << sequence_number_;
  // Only trigger the next write to complete if there is already a write pending
  // which should complete at the current sequence number.
  if (write_state_ != IoState::kPending ||
      helper_.PeekWrite().sequence_number != sequence_number_) {
    return;
  }

  // If the result is ERR_IO_PENDING, then pause.
  if (helper_.PeekWrite().result == ERR_IO_PENDING) {
    NET_TRACE(1, " *** ") << "Pausing write at: " << sequence_number_;
    write_state_ = IoState::kPaused;
    if (run_until_paused_run_loop_)
      run_until_paused_run_loop_->Quit();
    return;
  }

  NET_TRACE(1, " ****** ") << "Posting task to complete write: "
                           << sequence_number_;
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&SequencedSocketData::OnWriteComplete,
                                weak_factory_.GetWeakPtr()));
  CHECK_NE(IoState::kCompleting, read_state_);
  write_state_ = IoState::kCompleting;
}

void SequencedSocketData::Reset() {
  helper_.Reset();
  sequence_number_ = 0;
  read_state_ = IoState::kIdle;
  write_state_ = IoState::kIdle;
  weak_factory_.InvalidateWeakPtrs();
}

void SequencedSocketData::OnReadComplete() {
  CHECK_EQ(IoState::kCompleting, read_state_);
  NET_TRACE(1, " *** ") << "Completing read for: " << sequence_number_;

  MockRead data = helper_.AdvanceRead();
  DCHECK_EQ(sequence_number_, data.sequence_number);
  sequence_number_++;
  read_state_ = IoState::kIdle;

  // The result of this read completing might trigger the completion
  // of a pending write. If so, post a task to complete the write later.
  // Since the socket may call back into the SequencedSocketData
  // from socket()->OnReadComplete(), trigger the write task to be posted
  // before calling that.
  MaybePostWriteCompleteTask();

  if (!socket()) {
    NET_TRACE(1, " *** ") << "No socket available to complete read";
    return;
  }

  NET_TRACE(1, " *** ") << "Completing socket read for: "
                        << data.sequence_number;
  DumpMockReadWrite(data);
  socket()->OnReadComplete(data);
  NET_TRACE(1, " *** ") << "Done";
}

void SequencedSocketData::OnWriteComplete() {
  CHECK_EQ(IoState::kCompleting, write_state_);
  NET_TRACE(1, " *** ") << " Completing write for: " << sequence_number_;

  const MockWrite& data = helper_.AdvanceWrite();
  DCHECK_EQ(sequence_number_, data.sequence_number);
  sequence_number_++;
  write_state_ = IoState::kIdle;
  int rv = data.result == OK ? data.data_len : data.result;

  // The result of this write completing might trigger the completion
  // of a pending read. If so, post a task to complete the read later.
  // Since the socket may call back into the SequencedSocketData
  // from socket()->OnWriteComplete(), trigger the write task to be posted
  // before calling that.
  MaybePostReadCompleteTask();

  if (!socket()) {
    NET_TRACE(1, " *** ") << "No socket available to complete write";
    return;
  }

  NET_TRACE(1, " *** ") << " Completing socket write for: "
                        << data.sequence_number;
  socket()->OnWriteComplete(rv);
  NET_TRACE(1, " *** ") << "Done";
}

SequencedSocketData::~SequencedSocketData() = default;

MockClientSocketFactory::MockClientSocketFactory() = default;

MockClientSocketFactory::~MockClientSocketFactory() = default;

void MockClientSocketFactory::AddSocketDataProvider(SocketDataProvider* data) {
  mock_data_.Add(data);
}

void MockClientSocketFactory::AddTcpSocketDataProvider(
    SocketDataProvider* data) {
  mock_tcp_data_.Add(data);
}

void MockClientSocketFactory::AddSSLSocketDataProvider(
    SSLSocketDataProvider* data) {
  mock_ssl_data_.Add(data);
}

void MockClientSocketFactory::ResetNextMockIndexes() {
  mock_data_.ResetNextIndex();
  mock_ssl_data_.ResetNextIndex();
}

std::unique_ptr<DatagramClientSocket>
MockClientSocketFactory::CreateDatagramClientSocket(
    DatagramSocket::BindType bind_type,
    NetLog* net_log,
    const NetLogSource& source) {
  NET_TRACE(1, " *** ") << "mock_data_index: " << mock_data_.next_index();
  SocketDataProvider* data_provider = mock_data_.GetNext();
  auto socket = std::make_unique<MockUDPClientSocket>(data_provider, net_log);
  if (bind_type == DatagramSocket::RANDOM_BIND)
    socket->set_source_port(static_cast<uint16_t>(base::RandInt(1025, 65535)));
  udp_client_socket_ports_.push_back(socket->source_port());
  return std::move(socket);
}

std::unique_ptr<TransportClientSocket>
MockClientSocketFactory::CreateTransportClientSocket(
    const AddressList& addresses,
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    NetworkQualityEstimator* network_quality_estimator,
    NetLog* net_log,
    const NetLogSource& source) {
  SocketDataProvider* data_provider = mock_tcp_data_.GetNextWithoutAsserting();
  if (data_provider) {
    NET_TRACE(1, " *** ") << "mock_tcp_data_index: "
                          << (mock_tcp_data_.next_index() - 1);
  } else {
    NET_TRACE(1, " *** ") << "mock_data_index: " << mock_data_.next_index();
    data_provider = mock_data_.GetNext();
  }
  auto socket =
      std::make_unique<MockTCPClientSocket>(addresses, net_log, data_provider);
  if (enable_read_if_ready_)
    socket->set_enable_read_if_ready(enable_read_if_ready_);
  return std::move(socket);
}

std::unique_ptr<SSLClientSocket> MockClientSocketFactory::CreateSSLClientSocket(
    SSLClientContext* context,
    std::unique_ptr<StreamSocket> stream_socket,
    const HostPortPair& host_and_port,
    const SSLConfig& ssl_config) {
  NET_TRACE(1, " *** ") << "mock_ssl_data_index: "
                        << mock_ssl_data_.next_index();
  SSLSocketDataProvider* next_ssl_data = mock_ssl_data_.GetNext();
  if (next_ssl_data->next_protos_expected_in_ssl_config.has_value()) {
    EXPECT_TRUE(base::ranges::equal(
        next_ssl_data->next_protos_expected_in_ssl_config.value(),
        ssl_config.alpn_protos));
  }
  if (next_ssl_data->expected_application_settings) {
    EXPECT_EQ(*next_ssl_data->expected_application_settings,
              ssl_config.application_settings);
  }

  // The protocol version used is a combination of the per-socket SSLConfig and
  // the SSLConfigService.
  EXPECT_EQ(
      next_ssl_data->expected_ssl_version_min,
      ssl_config.version_min_override.value_or(context->config().version_min));
  EXPECT_EQ(
      next_ssl_data->expected_ssl_version_max,
      ssl_config.version_max_override.value_or(context->config().version_max));

  if (next_ssl_data->expected_early_data_enabled) {
    EXPECT_EQ(*next_ssl_data->expected_early_data_enabled,
              ssl_config.early_data_enabled);
  }

  if (next_ssl_data->expected_send_client_cert) {
    // Client certificate preferences come from |context|.
    scoped_refptr<X509Certificate> client_cert;
    scoped_refptr<SSLPrivateKey> client_private_key;
    bool send_client_cert = context->GetClientCertificate(
        host_and_port, &client_cert, &client_private_key);

    EXPECT_EQ(*next_ssl_data->expected_send_client_cert, send_client_cert);
    // Note |send_client_cert| may be true while |client_cert| is null if the
    // socket is configured to continue without a certificate, as opposed to
    // surfacing the certificate challenge.
    EXPECT_EQ(!!next_ssl_data->expected_client_cert, !!client_cert);
    if (next_ssl_data->expected_client_cert && client_cert) {
      EXPECT_TRUE(next_ssl_data->expected_client_cert->EqualsIncludingChain(
          client_
"""


```