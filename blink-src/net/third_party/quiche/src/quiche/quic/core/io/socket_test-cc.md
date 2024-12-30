Response:
Let's break down the thought process for analyzing the `socket_test.cc` file.

1. **Understand the Goal:** The primary goal is to understand the *functionality* of this C++ file within the Chromium networking stack, specifically in the context of QUIC. It's a test file, so its purpose is to verify the behavior of the `socket.h` API.

2. **Initial Scan for Keywords:** Look for obvious clues. Keywords like "TEST", "EXPECT", "CreateSocket", "Bind", "Listen", "Send", "Receive", etc., jump out. These immediately suggest it's a testing file for socket-related operations.

3. **File Path Context:** The path `net/third_party/quiche/src/quiche/quic/core/io/socket_test.cc` is crucial. It tells us:
    * `net`:  It's part of the Chromium networking stack.
    * `third_party/quiche`: It uses the Quiche library, which is Google's QUIC implementation.
    * `quic/core/io`: It's specifically related to the I/O (input/output) aspects of QUIC at its core.
    * `socket_test.cc`:  It's the test file for something related to "socket."

4. **Analyze Includes:**  The included headers provide more context:
    * `#include "quiche/quic/core/io/socket.h"`:  This is the *target* of the tests. The file is testing the API defined in `socket.h`.
    * Other `quiche/...` includes: Indicate it uses Quiche's platform abstractions (like `QuicIpAddress`, `QuicSocketAddress`) and testing utilities.
    * `<string>`, `absl/...`:  Standard C++ and Abseil libraries for strings, status codes, etc.
    * `quiche/common/platform/api/...`:  Platform-independent APIs for logging and testing.

5. **Examine the Tests (The Heart of the File):**  Go through each `TEST` function individually. For each test:
    * **Identify the operation being tested:**  The test name is usually a good indicator (e.g., `CreateAndCloseSocket`, `Bind`, `SendTo`).
    * **Look at the setup:** What objects are created? Are any initial conditions set?
    * **Focus on the `QUICHE_EXPECT_OK` and `EXPECT_THAT` calls:** These are the assertions that verify the expected behavior. What are they checking for? Success? Specific error codes?
    * **Note any conditional logic:**  The raw socket tests often have `if (socket == kInvalidSocketFd) { GTEST_SKIP(); }`. This indicates potential platform limitations or privilege requirements.
    * **Pay attention to the parameters used in the tested functions:** What kind of socket is being created (UDP, TCP, raw)? What addresses and ports are being used?

6. **Synthesize the Functionality:** Based on the individual tests, summarize the overall functionality of the file. It tests the basic socket operations (create, close, bind, listen, accept, send, receive) as they are implemented in the `quiche::quic::socket_api` namespace. It also includes tests specific to raw sockets.

7. **Consider JavaScript Relevance:**  Think about how these low-level socket operations relate to JavaScript. Directly, they don't. JavaScript running in a browser doesn't have direct access to OS-level sockets. *However*, the *underlying network communication* that JavaScript relies on uses these kinds of sockets. Therefore, it's important to explain the indirect relationship and give examples of higher-level JavaScript APIs (like `fetch`, `WebSocket`, `WebRTC`) that depend on this kind of lower-level implementation.

8. **Logical Reasoning (Hypothetical Inputs and Outputs):** For each test, imagine the "happy path" and potential error scenarios. Provide simple examples. For instance, for `Bind`, the input is a socket and a socket address, and a successful output is `OK`. A failure could be "Address already in use."

9. **Common User/Programming Errors:**  Think about the common pitfalls when working with sockets. For example, forgetting to bind before listening, trying to operate on an invalid socket, or not handling errors properly. Relate these back to the C++ code if possible (e.g., the tests check for specific error codes).

10. **Debugging Scenario:**  Imagine a user reports a networking issue in a Chromium browser. Explain how a developer might use this test file as part of the debugging process. This involves understanding how the tests verify the low-level socket functionality and how failures in these tests could point to the root cause of a larger issue.

11. **Structure and Clarity:** Organize the information logically. Start with a high-level summary, then go into details for each aspect (functionality, JavaScript relevance, reasoning, errors, debugging). Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "This file just tests sockets."  **Refinement:**  "It tests *specific socket operations* within the QUIC library's abstraction layer."
* **Initial thought on JavaScript:** "No direct connection." **Refinement:** "The connection is indirect but fundamental. JavaScript uses higher-level APIs built on top of this."
* **Making sure the examples are concrete:** Instead of just saying "network error," provide specific examples like "connection refused" or "address not available."

By following this systematic approach, you can effectively analyze a source code file and understand its purpose, even without being an expert in the specific codebase. The key is to break it down into smaller, manageable parts and use the available information (file path, includes, test names, assertions) to build a comprehensive understanding.
这个文件 `net/third_party/quiche/src/quiche/quic/core/io/socket_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，它的主要功能是**测试 `quiche/quic/core/io/socket.h` 中定义的 Socket API 的各种功能**。

更具体地说，它通过编写一系列的单元测试来验证以下 Socket API 的行为是否符合预期：

**主要功能测试点：**

* **创建和关闭 Socket:**
    * `CreateAndCloseSocket`: 测试创建 UDP socket 和关闭 socket 的基本功能。
    * `CreateAndCloseRawSocket`: 测试创建 Raw IP socket 和关闭 socket 的功能，同时验证了创建 Raw IP socket 需要管理员权限。
* **设置 Socket 属性:**
    * `SetSocketBlocking`: 测试设置 socket 为阻塞或非阻塞模式。
    * `SetReceiveBufferSize`: 测试设置接收缓冲区大小。
    * `SetSendBufferSize`: 测试设置发送缓冲区大小。
    * `SetIpHeaderIncludedForRaw` 和 `SetIpHeaderIncludedForRawV6`: 测试为 Raw IP socket 设置是否包含 IP 头部。
    * `SetIpHeaderIncludedForUdp`: 测试为 UDP socket 设置是否包含 IP 头部（预期会失败，因为 UDP socket 不允许这样做）。
* **Socket 连接和绑定:**
    * `Connect`: 测试连接到指定地址（对于 UDP socket，这只是设置了默认的发送目标）。
    * `Bind`: 测试将 socket 绑定到本地地址和端口。
* **获取 Socket 信息:**
    * `GetSocketError`: 测试获取 socket 上的错误状态。
    * `GetSocketAddress`: 测试获取 socket 本地绑定的地址和端口。
* **监听和接受连接 (TCP):**
    * `Listen`: 测试开始监听连接。
    * `Accept`: 测试接受新的连接（由于测试中没有发起连接，所以预期会返回不可用状态）。
* **发送和接收数据:**
    * `Receive`: 测试从 socket 接收数据（由于测试中没有发送数据，所以预期会返回不可用状态）。
    * `Peek`: 测试从 socket 窥视数据（不移除数据，由于测试中没有发送数据，所以预期会返回不可用状态）。
    * `Send`: 测试向已连接的 socket 发送数据。
    * `SendTo`: 测试向指定地址发送数据（无需连接）。
    * `SendToWithConnection`: 测试向已连接的 socket 发送数据，但仍然指定目标地址（对于 UDP 来说是允许的）。
    * `SendToForRaw`: 测试向 Raw IP socket 发送自定义的 IP 数据包。
    * `SendToForRawWithIpHeader`: 测试向 Raw IP socket 发送包含 IP 头的完整 IP 数据包。

**与 JavaScript 的关系：**

这个 C++ 文件直接与 JavaScript 没有直接的接口关系。JavaScript 运行在浏览器环境中，无法直接操作底层的 socket API。

然而，**JavaScript 中进行网络通信的 API，例如 `fetch`、`XMLHttpRequest`、`WebSocket`、`WebRTC` 等，其底层实现最终会依赖于操作系统提供的 socket API**。Chromium 浏览器作为这些 JavaScript API 的宿主环境，其网络栈 (包括 QUIC 的实现) 正是负责处理这些底层的 socket 操作。

因此，虽然 JavaScript 代码本身不会直接调用 `socket_api::CreateSocket` 或 `socket_api::SendTo` 这样的函数，但当 JavaScript 代码发起一个网络请求时，Chromium 浏览器内部会使用类似的 C++ 代码（包括经过像 `socket_test.cc` 这样的测试验证过的代码）来创建和管理 socket，发送和接收数据。

**举例说明：**

假设一个 JavaScript 应用程序使用 `fetch` API 向服务器发送一个 HTTP 请求：

```javascript
fetch('https://example.com/api/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当这段 JavaScript 代码执行时，Chromium 浏览器内部会经历以下（简化的）过程：

1. **DNS 解析:**  首先需要将 `example.com` 解析为 IP 地址。
2. **建立连接:**  根据协议（HTTPS 通常使用 TCP，但如果支持 QUIC，可能会使用 QUIC），浏览器会尝试与服务器建立连接。这可能涉及到创建 socket，执行 TCP 三次握手或 QUIC 握手等操作。**这里就会用到 `quiche/quic/core/io/socket.h` 中定义的 socket API 以及类似 `socket_test.cc` 中测试过的功能。**
3. **发送请求:**  构造 HTTP 请求报文，并通过建立的 socket 发送给服务器。**`socket_api::Send` 或 `socket_api::SendTo` 的实现会被调用。**
4. **接收响应:**  从 socket 接收服务器返回的 HTTP 响应报文。**`socket_api::Receive` 的实现会被调用。**
5. **数据处理:**  浏览器将接收到的数据解析成 JavaScript 可以处理的格式（例如 JSON）。
6. **关闭连接:**  在请求完成后，可能会关闭 socket 连接。**`socket_api::Close` 的实现会被调用。**

**逻辑推理 (假设输入与输出):**

以 `TEST(SocketTest, Bind)` 为例：

* **假设输入:**
    * `socket`: 一个通过 `CreateTestSocket(socket_api::SocketProtocol::kUdp)` 创建的 UDP socket 的文件描述符。
    * `address`: 一个 `QuicSocketAddress` 对象，例如 `QuicSocketAddress(quiche::TestLoopback(), /*port=*/0)`，表示绑定到本地回环地址的任意可用端口。
* **预期输出:** `socket_api::Bind` 函数调用成功，返回 `absl::OkStatus()`。这意味着 socket 成功绑定到了指定的地址和端口。如果绑定失败（例如端口已被占用），则会返回一个包含错误信息的 `absl::Status` 对象。

以 `TEST(SocketTest, SendTo)` 为例：

* **假设输入:**
    * `socket`: 一个通过 `CreateTestSocket(socket_api::SocketProtocol::kUdp)` 创建的 UDP socket 的文件描述符。
    * `peer_address`: 一个 `QuicSocketAddress` 对象，例如 `QuicSocketAddress(quiche::TestLoopback(), /*port=*/57290)`，表示目标地址和端口。
    * `buffer`: 一个包含要发送数据的 `absl::string_view`，例如 `"test data"`.
* **预期输出:** `socket_api::SendTo` 函数调用成功，返回一个 `absl::StatusOr<absl::string_view>`，其中 `absl::string_view` 的大小小于等于 `buffer` 的大小，表示成功发送的字节数。如果发送失败，则会返回一个包含错误信息的 `absl::Status` 对象。

**用户或编程常见的使用错误 (举例说明):**

* **未绑定 Socket 就尝试监听或接收:**  对于 TCP socket，必须先调用 `bind` 将 socket 绑定到本地地址和端口，才能调用 `listen` 开始监听连接。对于某些平台，UDP socket 也可能需要在接收前进行绑定。
    * **用户操作:**  用户编写了一个网络应用程序，尝试创建一个 TCP 服务器，但是忘记在调用 `listen` 之前调用 `bind`。
    * **调试线索:**  在测试中，`TEST(SocketTest, Listen)` 和 `TEST(SocketTest, Accept)` 会验证 `bind` 和 `listen` 的顺序和功能。如果 `bind` 的实现有问题，这些测试将会失败。
* **在已连接的 TCP Socket 上使用 `SendTo`:** 对于已连接的 TCP socket，应该使用 `send` 函数发送数据，而不是 `sendto`。`sendto` 通常用于无连接的协议，如 UDP。
    * **用户操作:**  用户错误地在已连接的 TCP socket 上调用了 `sendto` 并指定了目标地址。
    * **调试线索:**  虽然这个测试文件主要关注 `socket_api` 的正确性，但如果 `socket_api::SendTo` 的实现没有正确处理这种情况（例如返回错误），那么更上层的 QUIC 代码可能会出现问题，最终可能导致数据发送失败。
* **忘记处理 Socket 操作的错误:** Socket 操作可能会失败，例如创建 socket 失败、绑定失败、发送接收失败等。程序员需要检查返回的 `absl::Status` 对象并进行适当的错误处理。
    * **用户操作:**  用户编写了一个网络应用程序，但没有检查 `socket_api::CreateSocket` 或 `socket_api::Send` 的返回值，导致在 socket 操作失败时程序继续执行，可能会引发崩溃或不可预测的行为。
    * **调试线索:**  这个测试文件中的 `QUICHE_EXPECT_OK` 和 `EXPECT_THAT` 断言正是为了验证 socket API 在各种场景下是否返回预期的结果（成功或特定的错误）。如果这些断言失败，说明 `socket_api` 的实现存在问题，或者调用方式不正确。

**用户操作是如何一步步的到达这里 (作为调试线索):**

假设用户在使用 Chromium 浏览器浏览网页时遇到了网络连接问题，例如网页加载缓慢或无法加载。作为 Chromium 的开发者，在进行调试时可能会涉及以下步骤：

1. **用户报告问题:** 用户反馈无法访问某个网站或网络连接不稳定。
2. **网络层分析:** 开发者可能会首先检查更上层的网络协议，例如 HTTP/3 (QUIC) 或 HTTP/2 (TCP)。
3. **QUIC 层调试:** 如果问题与 QUIC 相关，开发者可能会深入 QUIC 协议的实现进行调试。
4. **Socket 层检查:** 如果怀疑是底层的 socket 操作有问题，开发者可能会查看与 socket 相关的代码，包括 `quiche/quic/core/io/socket.h` 和 `socket_test.cc`。
5. **运行单元测试:** 开发者可以运行 `socket_test.cc` 中的单元测试，以验证底层的 socket API 的基本功能是否正常。如果某些测试失败，则表明 `socket_api` 的实现可能存在 bug，这可能是导致用户网络连接问题的根本原因。
6. **代码审查:** 开发者可能会审查 `socket.h` 和 `socket_test.cc` 中涉及的代码，以理解 socket API 的实现细节和测试覆盖范围。
7. **添加日志和断点:** 为了更深入地了解问题，开发者可能会在 `quiche/quic/core/io/socket.cc` （`socket.h` 的实现文件）中添加日志输出或设置断点，以便在用户复现问题时跟踪代码执行流程，查看 socket 操作的返回值和状态。
8. **模拟用户场景:** 开发者可能会尝试模拟用户的网络环境和操作步骤，以便复现问题并进行调试。

总而言之，`socket_test.cc` 文件虽然是底层的单元测试，但它是保证 Chromium 网络栈中 socket API 正确性的关键组成部分。当用户遇到网络问题时，这些测试可以作为调试的起点，帮助开发者定位问题是否出在最底层的 socket 操作层面。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/io/socket_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/io/socket.h"

#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_ip_address_family.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/test_tools/test_ip_packets.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/platform/api/quiche_test_loopback.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

namespace quic::test {
namespace {

using quiche::test::QuicheTest;
using quiche::test::StatusIs;
using testing::Lt;
using testing::SizeIs;

SocketFd CreateTestSocket(socket_api::SocketProtocol protocol,
                          bool blocking = true) {
  absl::StatusOr<SocketFd> socket = socket_api::CreateSocket(
      quiche::TestLoopback().address_family(), protocol, blocking);

  if (socket.ok()) {
    return socket.value();
  } else {
    QUICHE_CHECK(false);
    return kInvalidSocketFd;
  }
}

SocketFd CreateTestRawSocket(
    bool blocking = true,
    IpAddressFamily address_family = IpAddressFamily::IP_UNSPEC) {
  absl::StatusOr<SocketFd> socket;
  switch (address_family) {
    case IpAddressFamily::IP_V4:
      socket = socket_api::CreateSocket(
          quiche::TestLoopback4().address_family(),
          socket_api::SocketProtocol::kRawIp, blocking);
      break;
    case IpAddressFamily::IP_V6:
      socket = socket_api::CreateSocket(
          quiche::TestLoopback6().address_family(),
          socket_api::SocketProtocol::kRawIp, blocking);
      break;
    case IpAddressFamily::IP_UNSPEC:
      socket = socket_api::CreateSocket(quiche::TestLoopback().address_family(),
                                        socket_api::SocketProtocol::kRawIp,
                                        blocking);
      break;
  }

  if (socket.ok()) {
    return socket.value();
  } else {
    // This is expected if test not run with relevant admin privileges or if
    // address family is unsupported.
    QUICHE_CHECK(absl::IsPermissionDenied(socket.status()) ||
                 absl::IsNotFound(socket.status()));
    return kInvalidSocketFd;
  }
}

TEST(SocketTest, CreateAndCloseSocket) {
  QuicIpAddress localhost_address = quiche::TestLoopback();
  absl::StatusOr<SocketFd> created_socket = socket_api::CreateSocket(
      localhost_address.address_family(), socket_api::SocketProtocol::kUdp);

  QUICHE_EXPECT_OK(created_socket.status());

  QUICHE_EXPECT_OK(socket_api::Close(created_socket.value()));
}

TEST(SocketTest, CreateAndCloseRawSocket) {
  QuicIpAddress localhost_address = quiche::TestLoopback();
  absl::StatusOr<SocketFd> created_socket = socket_api::CreateSocket(
      localhost_address.address_family(), socket_api::SocketProtocol::kRawIp);

  // Raw IP socket creation will typically fail if not run with relevant admin
  // privileges.
  if (!created_socket.ok()) {
    EXPECT_THAT(created_socket.status(),
                StatusIs(absl::StatusCode::kPermissionDenied));
    return;
  }

  QUICHE_EXPECT_OK(socket_api::Close(created_socket.value()));
}

TEST(SocketTest, SetSocketBlocking) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/true);

  QUICHE_EXPECT_OK(socket_api::SetSocketBlocking(socket, /*blocking=*/false));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, SetReceiveBufferSize) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/true);

  QUICHE_EXPECT_OK(socket_api::SetReceiveBufferSize(socket, /*size=*/100));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, SetSendBufferSize) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/true);

  QUICHE_EXPECT_OK(socket_api::SetSendBufferSize(socket, /*size=*/100));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, SetIpHeaderIncludedForRaw) {
  SocketFd socket =
      CreateTestRawSocket(/*blocking=*/true, IpAddressFamily::IP_V4);
  if (socket == kInvalidSocketFd) {
    GTEST_SKIP();
  }

  QUICHE_EXPECT_OK(socket_api::SetIpHeaderIncluded(
      socket, IpAddressFamily::IP_V4, /*ip_header_included=*/true));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, SetIpHeaderIncludedForRawV6) {
  SocketFd socket =
      CreateTestRawSocket(/*blocking=*/true, IpAddressFamily::IP_V6);
  if (socket == kInvalidSocketFd) {
    GTEST_SKIP();
  }

  QUICHE_EXPECT_OK(socket_api::SetIpHeaderIncluded(
      socket, IpAddressFamily::IP_V6, /*ip_header_included=*/true));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, SetIpHeaderIncludedForUdp) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/true);

  // Expect option only allowed for raw IP sockets.
  EXPECT_THAT(socket_api::SetIpHeaderIncluded(socket, IpAddressFamily::IP_V4,
                                              /*ip_header_included=*/true),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(socket_api::SetIpHeaderIncluded(socket, IpAddressFamily::IP_V6,
                                              /*ip_header_included=*/true),
              StatusIs(absl::StatusCode::kInvalidArgument));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, Connect) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp);

  // UDP, so "connecting" should succeed without any listening sockets.
  QUICHE_EXPECT_OK(socket_api::Connect(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0)));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, GetSocketError) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/true);

  absl::Status error = socket_api::GetSocketError(socket);
  QUICHE_EXPECT_OK(error);

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, Bind) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp);

  QUICHE_EXPECT_OK(socket_api::Bind(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0)));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, GetSocketAddress) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp);
  QUICHE_ASSERT_OK(socket_api::Bind(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0)));

  absl::StatusOr<QuicSocketAddress> address =
      socket_api::GetSocketAddress(socket);
  QUICHE_EXPECT_OK(address);
  EXPECT_TRUE(address.value().IsInitialized());
  EXPECT_EQ(address.value().host(), quiche::TestLoopback());

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, Listen) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kTcp);
  QUICHE_ASSERT_OK(socket_api::Bind(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0)));

  QUICHE_EXPECT_OK(socket_api::Listen(socket, /*backlog=*/5));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, Accept) {
  // Need a non-blocking socket to avoid waiting when no connection comes.
  SocketFd socket =
      CreateTestSocket(socket_api::SocketProtocol::kTcp, /*blocking=*/false);
  QUICHE_ASSERT_OK(socket_api::Bind(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0)));
  QUICHE_ASSERT_OK(socket_api::Listen(socket, /*backlog=*/5));

  // Nothing set up to connect, so expect kUnavailable.
  absl::StatusOr<socket_api::AcceptResult> result = socket_api::Accept(socket);
  EXPECT_THAT(result, StatusIs(absl::StatusCode::kUnavailable));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, Receive) {
  // Non-blocking to avoid waiting when no data to receive.
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/false);

  // On Windows, recv() fails on a socket that is connectionless and not bound.
  QUICHE_ASSERT_OK(socket_api::Bind(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0)));

  std::string buffer(100, 0);
  absl::StatusOr<absl::Span<char>> result =
      socket_api::Receive(socket, absl::MakeSpan(buffer));
  EXPECT_THAT(result, StatusIs(absl::StatusCode::kUnavailable));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, Peek) {
  // Non-blocking to avoid waiting when no data to receive.
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/false);

  // On Windows, recv() fails on a socket that is connectionless and not bound.
  QUICHE_ASSERT_OK(socket_api::Bind(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0)));

  std::string buffer(100, 0);
  absl::StatusOr<absl::Span<char>> result =
      socket_api::Receive(socket, absl::MakeSpan(buffer), /*peek=*/true);
  EXPECT_THAT(result, StatusIs(absl::StatusCode::kUnavailable));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, Send) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp);
  // UDP, so "connecting" should succeed without any listening sockets.
  QUICHE_ASSERT_OK(socket_api::Connect(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0)));

  char buffer[] = {12, 34, 56, 78};
  // Expect at least some data to be sent successfully.
  absl::StatusOr<absl::string_view> result =
      socket_api::Send(socket, absl::string_view(buffer, sizeof(buffer)));
  QUICHE_ASSERT_OK(result.status());
  EXPECT_THAT(result.value(), SizeIs(Lt(4)));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, SendTo) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp);

  // Send data to an arbitrarily-chosen ephemeral port.
  char buffer[] = {12, 34, 56, 78};
  absl::StatusOr<absl::string_view> result = socket_api::SendTo(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/57290),
      absl::string_view(buffer, sizeof(buffer)));

  // Expect at least some data to be sent successfully.
  QUICHE_ASSERT_OK(result.status());
  EXPECT_THAT(result.value(), SizeIs(Lt(4)));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, SendToWithConnection) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp);
  // UDP, so "connecting" should succeed without any listening sockets.
  QUICHE_ASSERT_OK(socket_api::Connect(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0)));

  // Send data to an arbitrarily-chosen ephemeral port.
  char buffer[] = {12, 34, 56, 78};
  absl::StatusOr<absl::string_view> result = socket_api::SendTo(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/50495),
      absl::string_view(buffer, sizeof(buffer)));
  // Expect at least some data to be sent successfully.
  QUICHE_ASSERT_OK(result.status());
  EXPECT_THAT(result.value(), SizeIs(Lt(4)));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, SendToForRaw) {
  SocketFd socket = CreateTestRawSocket(/*blocking=*/true);
  if (socket == kInvalidSocketFd) {
    GTEST_SKIP();
  }

  QuicIpAddress localhost_address = quiche::TestLoopback();
  QUICHE_EXPECT_OK(socket_api::SetIpHeaderIncluded(
      socket, localhost_address.address_family(),
      /*ip_header_included=*/false));

  // Arbitrarily-chosen ephemeral ports.
  QuicSocketAddress client_address(localhost_address, /*port=*/53368);
  QuicSocketAddress server_address(localhost_address, /*port=*/56362);
  std::string packet = CreateUdpPacket(client_address, server_address, "foo");
  absl::StatusOr<absl::string_view> result = socket_api::SendTo(
      socket, QuicSocketAddress(localhost_address, /*port=*/56362), packet);

  // Expect at least some data to be sent successfully.
  QUICHE_ASSERT_OK(result.status());
  EXPECT_THAT(result.value(), SizeIs(Lt(packet.size())));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, SendToForRawWithIpHeader) {
  SocketFd socket = CreateTestRawSocket(/*blocking=*/true);
  if (socket == kInvalidSocketFd) {
    GTEST_SKIP();
  }

  QuicIpAddress localhost_address = quiche::TestLoopback();
  QUICHE_EXPECT_OK(socket_api::SetIpHeaderIncluded(
      socket, localhost_address.address_family(), /*ip_header_included=*/true));

  // Arbitrarily-chosen ephemeral ports.
  QuicSocketAddress client_address(localhost_address, /*port=*/53368);
  QuicSocketAddress server_address(localhost_address, /*port=*/56362);
  std::string packet =
      CreateIpPacket(client_address.host(), server_address.host(),
                     CreateUdpPacket(client_address, server_address, "foo"));
  absl::StatusOr<absl::string_view> result = socket_api::SendTo(
      socket, QuicSocketAddress(localhost_address, /*port=*/56362), packet);

  // Expect at least some data to be sent successfully.
  QUICHE_ASSERT_OK(result.status());
  EXPECT_THAT(result.value(), SizeIs(Lt(packet.size())));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

}  // namespace
}  // namespace quic::test

"""

```