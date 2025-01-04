Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Understanding the Core Goal:**

The immediate request is to understand the *functionality* of the `http_stream_pool_group_unittest.cc` file within the Chromium networking stack. The file name itself strongly suggests it's testing the `HttpStreamPool::Group` class.

**2. Initial Scan for Key Components:**

I'd quickly scan the code for important elements:

* **Includes:** What other parts of the networking stack are being used? (`HttpStreamPool`, `HttpStream`, `HttpNetworkSession`, `StreamSocket`, etc.) This gives context.
* **Namespaces:**  The `net` namespace is crucial.
* **Test Fixture:**  The `HttpStreamPoolGroupTest` class inheriting from `TestWithTaskEnvironment` is the setup for running the tests. The constructor and `protected` members will likely handle initialization.
* **Individual Tests:** Look for `TEST_F`. These are the individual scenarios being tested.
* **Assertions:**  `ASSERT_EQ`, `ASSERT_TRUE`, `ASSERT_FALSE`, `EXPECT_THAT`. These tell us what properties of the `Group` are being verified in each test.
* **Key Methods of `Group` (through usage):** `CreateTextBasedStream`, `AddIdleStreamSocket`, `GetIdleStreamSocket`, `CleanupTimedoutIdleStreamSocketsForTesting`.

**3. Deconstructing Individual Tests (Example: `CreateTextBasedStream`):**

* **Setup:** A `FakeStreamSocket` is created.
* **Action:** `GetOrCreateTestGroup()` gets the `Group` object, and `CreateTextBasedStream` is called.
* **Verification:** Assertions check the counts of active and idle sockets in the `Group` and the total active streams in the `Pool`. This tells us that this test verifies the basic creation of a stream and its impact on the group's state.

**4. Identifying Recurring Patterns and Themes:**

As I go through the tests, I see common patterns:

* **Socket Creation and Management:**  Many tests involve creating `FakeStreamSocket` objects and observing how the `Group` manages their lifecycle (active, idle, timeout, disconnection).
* **Idle Socket Behavior:** Several tests specifically deal with adding idle sockets, retrieving them, and how various events (timeouts, disconnections, memory pressure, IP address changes) affect them.
* **IP Address Changes:** Tests with `NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests()` investigate how the `Group` reacts to network changes.
* **Memory Pressure:**  Tests involving `base::MemoryPressureListener` examine the `Group`'s behavior under memory constraints.
* **Resource Management:** The tests implicitly check for leaks by destroying the session and observing (or not observing) crashes.

**5. Inferring Functionality of `HttpStreamPool::Group`:**

Based on the tests, I can deduce that `HttpStreamPool::Group` is responsible for:

* Managing a collection of `HttpStream` objects and their underlying `StreamSocket`s for a specific origin (defined by `HttpStreamKey`).
* Tracking active and idle sockets.
* Releasing idle sockets after timeouts.
* Handling socket disconnections.
* Potentially prioritizing used sockets for reuse.
* Reacting to network changes (IP address changes).
* Responding to memory pressure by releasing idle resources.

**6. Addressing Specific Questions:**

* **Functionality Listing:**  This becomes a summary of the inferences made in step 5.
* **Relationship with JavaScript:** Since this is low-level networking code, there's no direct interaction with JavaScript. The connection is *indirect*. JavaScript in a browser makes HTTP requests. These requests eventually go through the networking stack, including the `HttpStreamPool` and its `Group`s. I need to explain this indirect link.
* **Logical Reasoning (Input/Output):**  Choose a simple test case (like `CreateTextBasedStream`) and explicitly state the setup (input) and the expected state (output) based on the assertions.
* **Common User/Programming Errors:** Think about how developers or the system *using* this code might cause issues. For example, not properly closing streams could lead to resource leaks, or network instability could affect socket management.
* **User Operation to Reach Here (Debugging):** Trace a typical user action (visiting a webpage) down through the browser's processes to the point where this code might be involved. This helps contextualize the code's role.

**7. Refinement and Organization:**

Finally, organize the findings into a clear and structured answer, using headings and bullet points for readability. Ensure the language is precise and avoids jargon where possible, or explains it when necessary. Double-check that all parts of the original request have been addressed.

This iterative process of scanning, deconstructing, identifying patterns, inferring functionality, and then explicitly answering the questions helps to thoroughly understand the purpose and role of this test file within the larger codebase.
这个文件 `net/http/http_stream_pool_group_unittest.cc` 是 Chromium 网络栈中用于测试 `HttpStreamPool::Group` 类的单元测试文件。`HttpStreamPool::Group` 负责管理特定网络连接的 HTTP 流（HTTP/1.1 或 HTTP/2）。

以下是它的功能列表：

**主要功能:**

1. **测试 `HttpStreamPool::Group` 的创建和销毁:** 验证 `HttpStreamPool::Group` 对象的正确创建和在适当时候被销毁。
2. **测试文本流的创建 (`CreateTextBasedStream`):**  测试在 `HttpStreamPool::Group` 中创建基于文本的 HTTP 流（例如，HTTP/1.1）的能力。它验证了创建流后，活动套接字计数的变化。
3. **测试空闲套接字的释放和超时机制:**
    * **未使用的空闲套接字 (`ReleaseStreamSocketUnused`):** 测试当 HTTP 流被释放且其底层的套接字未使用过时，该套接字会被放入空闲状态，并在超时后被清理。
    * **已使用的空闲套接字 (`ReleaseStreamSocketUsed`):** 测试当 HTTP 流被释放且其底层的套接字已被使用过时，该套接字也会被放入空闲状态，但超时时间可能更长。
    * **非空闲套接字 (`ReleaseStreamSocketNotIdle`):** 测试当套接字在释放时仍然处于非空闲状态时，`HttpStreamPool::Group` 的行为（通常不会将其放入空闲列表）。
4. **测试空闲套接字的断开和异常情况处理:**
    * **空闲套接字断开 (`IdleSocketDisconnected`):** 测试当一个空闲的套接字断开连接时，`HttpStreamPool::Group` 如何清理它。
    * **空闲套接字意外接收数据 (`IdleSocketReceivedDataUnexpectedly`):** 测试当一个空闲的套接字意外地接收到数据时（意味着它不再是真正空闲的），`HttpStreamPool::Group` 如何处理这种情况。
5. **测试获取空闲套接字 (`GetIdleStreamSocket`):**
    * **基本获取:** 测试从 `HttpStreamPool::Group` 中获取一个空闲套接字的能力。
    * **偏好已使用套接字 (`GetIdleStreamSocketPreferUsed`):** 测试在获取空闲套接字时，`HttpStreamPool::Group` 是否偏好之前被使用过的套接字。
    * **获取时断开连接:** 测试在尝试获取空闲套接字时，如果套接字断开连接，会发生什么。
    * **超时的空闲套接字 (`GetIdleStreamSocketTimedout`):** 测试尝试获取一个已经超时的空闲套接字的行为。
6. **测试网络地址变化的处理:**
    * **清理空闲套接字 (`IPAddressChangeCleanupIdleSocket`):** 测试当网络地址发生变化时，`HttpStreamPool::Group` 是否会清理空闲的套接字。
    * **释放活动流的套接字 (`IPAddressChangeReleaseStreamSocket`):** 测试当网络地址发生变化时，`HttpStreamPool::Group` 是否会释放正在使用的流的套接字。
    * **忽略地址变化 (`IPAddressChangeIgnored`):** 测试在配置为忽略 IP 地址变化时，`HttpStreamPool::Group` 的行为。
7. **测试内存压力下的行为:**
    * **刷新空闲流 (`FlushIdleStreamsOnMemoryPressure`):** 测试在系统内存压力较高时，`HttpStreamPool::Group` 是否会清理空闲的 HTTP 流以释放资源。
    * **禁用内存压力处理 (`MemoryPressureDisabled`):** 测试在禁用内存压力处理时，`HttpStreamPool::Group` 的行为。
8. **测试在流活动时销毁会话 (`DestroySessionWhileStreamAlive`):** 确保在存在活动 HTTP 流的情况下销毁 `HttpNetworkSession` 不会导致崩溃。

**与 JavaScript 的关系:**

`net/http/http_stream_pool_group_unittest.cc` 文件本身是用 C++ 编写的，直接与 JavaScript 没有交互。但是，它测试的 `HttpStreamPool::Group` 类是 Chromium 网络栈的核心组件，负责管理 HTTP 连接的复用，这对于浏览器加载网页至关重要。

**举例说明:**

当 JavaScript 代码发起一个 HTTP 请求（例如，通过 `fetch()` API 或 `XMLHttpRequest`），Chromium 浏览器会将这个请求传递给其网络栈。`HttpStreamPool` 及其 `Group` 会尝试找到或建立一个可以用于该请求的现有 TCP 连接（以及可能的 TLS 连接）。

1. **JavaScript 发起请求:**
   ```javascript
   fetch('https://example.com/data.json')
     .then(response => response.json())
     .then(data => console.log(data));
   ```

2. **网络栈处理:**  Chromium 的网络栈会查找是否已经存在到 `example.com` 的空闲连接。`HttpStreamPool::Group` 负责维护这些连接。

3. **连接复用或新建:** 如果存在空闲连接，`HttpStreamPool::Group` 会将其提供给新的请求，避免重新建立 TCP/TLS 连接的开销。如果不存在，则会建立新的连接。

4. **流的创建和管理:**  `HttpStreamPool::Group` 负责创建和管理用于传输数据的 HTTP 流。`CreateTextBasedStream` 测试的就是这种流的创建。

5. **连接的空闲和清理:** 当请求完成后，连接可能会被放回 `HttpStreamPool::Group` 的空闲列表以供后续请求使用。测试中的超时机制确保了不活跃的连接不会无限期占用资源。

**逻辑推理 (假设输入与输出):**

**假设输入 (以 `CreateTextBasedStream` 测试为例):**

* 调用 `GetOrCreateTestGroup()` 获取或创建一个针对特定 `HttpStreamKey` 的 `HttpStreamPool::Group` 实例。
* 创建一个 `FakeStreamSocket` 模拟一个已建立的 TCP 连接。
* 调用 `group.CreateTextBasedStream(std::move(stream_socket), ...)`。

**预期输出:**

* `group.ActiveStreamSocketCount()` 的值增加 1。
* `group.IdleStreamSocketCount()` 的值为 0。
* `pool().TotalActiveStreamCount()` 的值增加 1。
* 返回一个非空的 `std::unique_ptr<HttpStream>`，表示成功创建了一个 HTTP 流。

**用户或编程常见的使用错误 (与该测试文件相关的场景):**

1. **没有正确关闭 HTTP 流或响应:**  虽然测试代码模拟了流的创建和释放，但在实际编程中，如果开发者没有正确关闭 HTTP 响应的 body 或 HTTP 流本身，可能会导致底层的套接字没有被及时放回空闲池，或者资源泄漏。

   ```c++
   // 错误示例：忘记关闭 HttpStream
   std::unique_ptr<HttpStream> stream = group.CreateTextBasedStream(...);
   // ... 使用 stream
   // 没有显式调用 stream.reset() 或其他关闭操作
   ```

2. **对套接字状态的错误假设:** 开发者可能会错误地假设某个连接始终可用或处于特定状态，而没有考虑到网络波动、服务器断开连接等情况。`HttpStreamPool::Group` 的测试覆盖了这些边缘情况。

3. **资源管理不当导致内存压力:**  如果应用程序创建了大量的 HTTP 连接而没有有效地复用或关闭它们，可能会导致 `HttpStreamPool` 中积累过多的连接，从而触发内存压力。测试中的 `FlushIdleStreamsOnMemoryPressure` 模拟了这种情况。

**用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入网址或点击链接:** 用户的这个操作会触发浏览器发起网络请求。
2. **浏览器解析 URL:**  浏览器会解析输入的 URL，提取协议、域名、端口等信息。
3. **DNS 查询:**  如果需要，浏览器会进行 DNS 查询以获取服务器的 IP 地址。
4. **建立 TCP 连接 (如果需要):**  如果到目标服务器的 TCP 连接不存在，浏览器会尝试建立新的连接。
5. **TLS 握手 (如果使用 HTTPS):** 对于 HTTPS 连接，会进行 TLS 握手以建立安全连接。
6. **`HttpStreamPool` 查找或创建 HTTP 流:** 当需要发送 HTTP 请求时，Chromium 的网络栈会使用 `HttpStreamPool` 来查找是否已经存在可以复用的连接。`HttpStreamPool::Group` 负责管理特定 `HttpStreamKey`（例如，协议、主机名、端口）的连接。
7. **`GetOrCreateGroupForTesting` (在测试中):**  在单元测试中，`GetOrCreateTestGroup()` 函数模拟了 `HttpStreamPool` 根据 `HttpStreamKey` 获取或创建对应的 `HttpStreamPool::Group` 的过程。
8. **`CreateTextBasedStream` (在测试中和实际代码中):**  如果需要建立新的 HTTP/1.1 连接，或者复用现有连接但需要创建一个新的 HTTP 流，就会调用 `CreateTextBasedStream`。
9. **发送 HTTP 请求:** 一旦 HTTP 流建立，浏览器就可以通过该流发送实际的 HTTP 请求。
10. **接收 HTTP 响应:** 服务器通过相同的 HTTP 流发送响应。
11. **关闭连接或放入空闲池:** 请求完成后，连接可能会被关闭，或者如果可以复用，则会被放入 `HttpStreamPool::Group` 的空闲列表，等待后续请求。`ReleaseStreamSocketUnused` 和 `ReleaseStreamSocketUsed` 测试了连接被放回空闲池的场景。

**调试线索:**

如果网络请求出现问题，例如连接失败、连接被意外关闭、性能不佳等，开发者可能会查看以下方面，而这些都与 `HttpStreamPool::Group` 的功能相关：

* **连接复用是否正常工作:**  如果连接没有被正确复用，可能会导致建立连接的开销过大。
* **空闲连接的超时设置:**  如果超时时间过短，可能会导致连接频繁被关闭和重建。如果超时时间过长，可能会占用过多资源。
* **网络地址变化是否影响现有连接:**  在移动设备或网络环境不稳定的情况下，网络地址变化可能会导致连接中断。
* **内存压力是否导致连接被过早关闭:**  在高负载情况下，内存压力可能会影响连接的稳定性。

通过理解 `HttpStreamPool::Group` 的功能和其单元测试覆盖的场景，开发者可以更好地理解 Chromium 网络栈的连接管理机制，并排查相关的网络问题。

Prompt: 
```
这是目录为net/http/http_stream_pool_group_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_pool_group.h"

#include <memory>

#include "base/functional/callback_helpers.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "net/base/address_list.h"
#include "net/base/completion_once_callback.h"
#include "net/base/ip_address.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/network_change_notifier.h"
#include "net/base/privacy_mode.h"
#include "net/http/http_network_session.h"
#include "net/http/http_stream.h"
#include "net/http/http_stream_pool.h"
#include "net/http/http_stream_pool_test_util.h"
#include "net/log/net_log.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/stream_socket.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "url/scheme_host_port.h"

namespace net {

using test::IsOk;

using Group = HttpStreamPool::Group;

class HttpStreamPoolGroupTest : public TestWithTaskEnvironment {
 public:
  HttpStreamPoolGroupTest()
      : TestWithTaskEnvironment(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME),
        default_test_key_(url::SchemeHostPort("http", "a.test", 80),
                          PRIVACY_MODE_DISABLED,
                          SocketTag(),
                          NetworkAnonymizationKey(),
                          SecureDnsPolicy::kAllow,
                          /*disable_cert_network_fetches=*/false) {
    feature_list_.InitAndEnableFeature(features::kHappyEyeballsV3);
    session_deps_.ignore_ip_address_changes = false;
    session_deps_.disable_idle_sockets_close_on_memory_pressure = false;
    InitializePool();
  }

 protected:
  void set_ignore_ip_address_changes(bool ignore_ip_address_changes) {
    session_deps_.ignore_ip_address_changes = ignore_ip_address_changes;
  }

  void set_disable_idle_sockets_close_on_memory_pressure(
      bool disable_idle_sockets_close_on_memory_pressure) {
    session_deps_.disable_idle_sockets_close_on_memory_pressure =
        disable_idle_sockets_close_on_memory_pressure;
  }

  void InitializePool() {
    http_network_session_ =
        SpdySessionDependencies::SpdyCreateSession(&session_deps_);
  }

  Group& GetOrCreateTestGroup() {
    return pool().GetOrCreateGroupForTesting(default_test_key_);
  }

  Group* GetTestGroup() { return pool().GetGroupForTesting(default_test_key_); }

  HttpStreamPool& pool() { return *http_network_session_->http_stream_pool(); }

  void DestroyHttpNetworkSession() { http_network_session_.reset(); }

 private:
  base::test::ScopedFeatureList feature_list_;
  const HttpStreamKey default_test_key_;
  // For creating HttpNetworkSession.
  SpdySessionDependencies session_deps_;
  std::unique_ptr<HttpNetworkSession> http_network_session_;
};

TEST_F(HttpStreamPoolGroupTest, CreateTextBasedStream) {
  auto stream_socket = std::make_unique<FakeStreamSocket>();

  Group& group = GetOrCreateTestGroup();
  std::unique_ptr<HttpStream> stream = group.CreateTextBasedStream(
      std::move(stream_socket), StreamSocketHandle::SocketReuseType::kUnused,
      LoadTimingInfo::ConnectTiming());
  CHECK(stream);
  ASSERT_EQ(group.ActiveStreamSocketCount(), 1u);
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);
  ASSERT_EQ(pool().TotalActiveStreamCount(), 1u);
}

TEST_F(HttpStreamPoolGroupTest, ReleaseStreamSocketUnused) {
  auto stream_socket = std::make_unique<FakeStreamSocket>();

  Group& group = GetOrCreateTestGroup();
  std::unique_ptr<HttpStream> stream = group.CreateTextBasedStream(
      std::move(stream_socket), StreamSocketHandle::SocketReuseType::kUnused,
      LoadTimingInfo::ConnectTiming());
  CHECK(stream);

  stream.reset();
  ASSERT_EQ(group.ActiveStreamSocketCount(), 1u);
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);
  ASSERT_EQ(pool().TotalActiveStreamCount(), 1u);

  FastForwardBy(Group::kUnusedIdleStreamSocketTimeout);
  group.CleanupTimedoutIdleStreamSocketsForTesting();
  ASSERT_EQ(group.ActiveStreamSocketCount(), 0u);
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);
  ASSERT_EQ(pool().TotalActiveStreamCount(), 0u);
}

TEST_F(HttpStreamPoolGroupTest, ReleaseStreamSocketUsed) {
  auto stream_socket = std::make_unique<FakeStreamSocket>();
  stream_socket->set_was_ever_used(true);

  Group& group = GetOrCreateTestGroup();
  std::unique_ptr<HttpStream> stream = group.CreateTextBasedStream(
      std::move(stream_socket), StreamSocketHandle::SocketReuseType::kUnused,
      LoadTimingInfo::ConnectTiming());
  CHECK(stream);

  stream.reset();
  ASSERT_EQ(group.ActiveStreamSocketCount(), 1u);
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);
  ASSERT_EQ(pool().TotalActiveStreamCount(), 1u);

  static_assert(Group::kUnusedIdleStreamSocketTimeout <=
                Group::kUsedIdleStreamSocketTimeout);

  FastForwardBy(Group::kUnusedIdleStreamSocketTimeout);
  group.CleanupTimedoutIdleStreamSocketsForTesting();
  ASSERT_EQ(group.ActiveStreamSocketCount(), 1u);
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);
  ASSERT_EQ(pool().TotalActiveStreamCount(), 1u);

  FastForwardBy(Group::kUsedIdleStreamSocketTimeout);
  group.CleanupTimedoutIdleStreamSocketsForTesting();
  ASSERT_EQ(group.ActiveStreamSocketCount(), 0u);
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);
  ASSERT_EQ(pool().TotalActiveStreamCount(), 0u);
}

TEST_F(HttpStreamPoolGroupTest, ReleaseStreamSocketNotIdle) {
  auto stream_socket = std::make_unique<FakeStreamSocket>();
  stream_socket->set_is_idle(false);

  Group& group = GetOrCreateTestGroup();
  std::unique_ptr<HttpStream> stream = group.CreateTextBasedStream(
      std::move(stream_socket), StreamSocketHandle::SocketReuseType::kUnused,
      LoadTimingInfo::ConnectTiming());
  CHECK(stream);

  stream.reset();

  ASSERT_FALSE(GetTestGroup());
}

TEST_F(HttpStreamPoolGroupTest, IdleSocketDisconnected) {
  auto stream_socket = std::make_unique<FakeStreamSocket>();
  FakeStreamSocket* raw_stream_socket = stream_socket.get();

  Group& group = GetOrCreateTestGroup();
  std::unique_ptr<HttpStream> stream = group.CreateTextBasedStream(
      std::move(stream_socket), StreamSocketHandle::SocketReuseType::kUnused,
      LoadTimingInfo::ConnectTiming());
  CHECK(stream);

  stream.reset();
  ASSERT_EQ(group.ActiveStreamSocketCount(), 1u);
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);
  ASSERT_EQ(pool().TotalActiveStreamCount(), 1u);

  raw_stream_socket->set_is_connected(false);
  group.CleanupTimedoutIdleStreamSocketsForTesting();
  ASSERT_EQ(group.ActiveStreamSocketCount(), 0u);
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);
}

TEST_F(HttpStreamPoolGroupTest, IdleSocketReceivedDataUnexpectedly) {
  auto stream_socket = std::make_unique<FakeStreamSocket>();
  FakeStreamSocket* raw_stream_socket = stream_socket.get();

  Group& group = GetOrCreateTestGroup();
  std::unique_ptr<HttpStream> stream = group.CreateTextBasedStream(
      std::move(stream_socket), StreamSocketHandle::SocketReuseType::kUnused,
      LoadTimingInfo::ConnectTiming());
  CHECK(stream);

  stream.reset();
  ASSERT_EQ(group.ActiveStreamSocketCount(), 1u);
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);
  ASSERT_EQ(pool().TotalActiveStreamCount(), 1u);

  // Simulate the socket was used and not idle (received data).
  raw_stream_socket->set_was_ever_used(true);
  raw_stream_socket->set_is_idle(false);

  group.CleanupTimedoutIdleStreamSocketsForTesting();
  ASSERT_EQ(group.ActiveStreamSocketCount(), 0u);
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);
}

TEST_F(HttpStreamPoolGroupTest, GetIdleStreamSocket) {
  Group& group = GetOrCreateTestGroup();
  ASSERT_FALSE(group.GetIdleStreamSocket());

  auto stream_socket = std::make_unique<FakeStreamSocket>();
  group.AddIdleStreamSocket(std::move(stream_socket));
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);

  std::unique_ptr<StreamSocket> socket = group.GetIdleStreamSocket();
  ASSERT_TRUE(socket);
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);
}

TEST_F(HttpStreamPoolGroupTest, GetIdleStreamSocketPreferUsed) {
  Group& group = GetOrCreateTestGroup();

  // Add 3 idle streams. the first and the third ones are marked as used.
  auto stream_socket1 = std::make_unique<FakeStreamSocket>();
  auto stream_socket2 = std::make_unique<FakeStreamSocket>();
  auto stream_socket3 = std::make_unique<FakeStreamSocket>();

  stream_socket1->set_was_ever_used(true);
  stream_socket3->set_was_ever_used(true);

  stream_socket1->set_peer_addr(IPEndPoint(IPAddress(192, 0, 2, 1), 80));
  stream_socket2->set_peer_addr(IPEndPoint(IPAddress(192, 0, 2, 2), 80));
  stream_socket3->set_peer_addr(IPEndPoint(IPAddress(192, 0, 2, 3), 80));

  group.AddIdleStreamSocket(std::move(stream_socket1));
  group.AddIdleStreamSocket(std::move(stream_socket2));
  group.AddIdleStreamSocket(std::move(stream_socket3));
  ASSERT_EQ(group.IdleStreamSocketCount(), 3u);

  std::unique_ptr<StreamSocket> socket = group.GetIdleStreamSocket();
  ASSERT_TRUE(socket);
  ASSERT_EQ(group.IdleStreamSocketCount(), 2u);

  IPEndPoint peer;
  int rv = socket->GetPeerAddress(&peer);
  EXPECT_THAT(rv, IsOk());
  EXPECT_THAT(peer, IPEndPoint(IPAddress(192, 0, 2, 3), 80));
}

TEST_F(HttpStreamPoolGroupTest, GetIdleStreamSocketDisconnectedDuringIdle) {
  Group& group = GetOrCreateTestGroup();
  ASSERT_FALSE(group.GetIdleStreamSocket());

  auto stream_socket = std::make_unique<FakeStreamSocket>();
  FakeStreamSocket* raw_stream_socket = stream_socket.get();
  group.AddIdleStreamSocket(std::move(stream_socket));
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);

  raw_stream_socket->set_is_connected(false);
  ASSERT_FALSE(group.GetIdleStreamSocket());
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);
}

TEST_F(HttpStreamPoolGroupTest, GetIdleStreamSocketUsedSocketDisconnected) {
  Group& group = GetOrCreateTestGroup();
  ASSERT_FALSE(group.GetIdleStreamSocket());

  auto stream_socket = std::make_unique<FakeStreamSocket>();
  FakeStreamSocket* raw_stream_socket = stream_socket.get();
  group.AddIdleStreamSocket(std::move(stream_socket));
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);

  raw_stream_socket->set_was_ever_used(true);
  raw_stream_socket->set_is_connected(false);
  ASSERT_FALSE(group.GetIdleStreamSocket());
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);
}

TEST_F(HttpStreamPoolGroupTest, GetIdleStreamSocketTimedout) {
  Group& group = GetOrCreateTestGroup();

  auto stream_socket = std::make_unique<FakeStreamSocket>();
  group.AddIdleStreamSocket(std::move(stream_socket));
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);

  FastForwardBy(HttpStreamPool::Group::kUnusedIdleStreamSocketTimeout);

  ASSERT_FALSE(group.GetIdleStreamSocket());
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);
}

TEST_F(HttpStreamPoolGroupTest, IPAddressChangeCleanupIdleSocket) {
  auto stream_socket = std::make_unique<FakeStreamSocket>();

  Group& group = GetOrCreateTestGroup();
  std::unique_ptr<HttpStream> stream = group.CreateTextBasedStream(
      std::move(stream_socket), StreamSocketHandle::SocketReuseType::kUnused,
      LoadTimingInfo::ConnectTiming());
  CHECK(stream);

  stream.reset();
  ASSERT_EQ(group.ActiveStreamSocketCount(), 1u);
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);
  ASSERT_EQ(pool().TotalActiveStreamCount(), 1u);

  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  RunUntilIdle();

  group.CleanupTimedoutIdleStreamSocketsForTesting();
  ASSERT_EQ(group.ActiveStreamSocketCount(), 0u);
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);
}

TEST_F(HttpStreamPoolGroupTest, IPAddressChangeReleaseStreamSocket) {
  auto stream_socket = std::make_unique<FakeStreamSocket>();

  Group& group = GetOrCreateTestGroup();
  std::unique_ptr<HttpStream> stream = group.CreateTextBasedStream(
      std::move(stream_socket), StreamSocketHandle::SocketReuseType::kUnused,
      LoadTimingInfo::ConnectTiming());
  CHECK(stream);

  ASSERT_EQ(group.ActiveStreamSocketCount(), 1u);
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);
  ASSERT_EQ(pool().TotalActiveStreamCount(), 1u);

  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  RunUntilIdle();

  stream.reset();

  ASSERT_FALSE(GetTestGroup());
}

TEST_F(HttpStreamPoolGroupTest, IPAddressChangeIgnored) {
  set_ignore_ip_address_changes(true);
  InitializePool();

  auto stream_socket = std::make_unique<FakeStreamSocket>();
  Group& group = GetOrCreateTestGroup();
  std::unique_ptr<HttpStream> stream = group.CreateTextBasedStream(
      std::move(stream_socket), StreamSocketHandle::SocketReuseType::kUnused,
      LoadTimingInfo::ConnectTiming());
  CHECK(stream);

  ASSERT_EQ(group.ActiveStreamSocketCount(), 1u);
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);
  ASSERT_EQ(pool().TotalActiveStreamCount(), 1u);

  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  RunUntilIdle();

  stream.reset();

  group.CleanupTimedoutIdleStreamSocketsForTesting();
  ASSERT_EQ(group.ActiveStreamSocketCount(), 1u);
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);
  ASSERT_EQ(pool().TotalActiveStreamCount(), 1u);
}

TEST_F(HttpStreamPoolGroupTest, FlushIdleStreamsOnMemoryPressure) {
  set_disable_idle_sockets_close_on_memory_pressure(false);
  InitializePool();

  {
    Group& group = GetOrCreateTestGroup();
    ASSERT_FALSE(group.GetIdleStreamSocket());

    group.AddIdleStreamSocket(std::make_unique<FakeStreamSocket>());
    ASSERT_EQ(group.IdleStreamSocketCount(), 1u);

    // Idle sockets should be flushed on moderate memory pressure and `group`
    // should be destroyed.
    base::MemoryPressureListener::NotifyMemoryPressure(
        base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_MODERATE);
    FastForwardUntilNoTasksRemain();
    ASSERT_FALSE(GetTestGroup());
  }

  {
    Group& group = GetOrCreateTestGroup();
    group.AddIdleStreamSocket(std::make_unique<FakeStreamSocket>());
    ASSERT_EQ(group.IdleStreamSocketCount(), 1u);

    // Idle sockets should be flushed on critical memory pressure and `group`
    // should be destroyed.
    base::MemoryPressureListener::NotifyMemoryPressure(
        base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL);
    FastForwardUntilNoTasksRemain();
    ASSERT_FALSE(GetTestGroup());
  }
}

TEST_F(HttpStreamPoolGroupTest, MemoryPressureDisabled) {
  set_disable_idle_sockets_close_on_memory_pressure(true);
  InitializePool();

  Group& group = GetOrCreateTestGroup();
  ASSERT_FALSE(group.GetIdleStreamSocket());

  group.AddIdleStreamSocket(std::make_unique<FakeStreamSocket>());
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);

  // Idle sockets should be not flushed on moderate memory pressure.
  base::MemoryPressureListener::NotifyMemoryPressure(
      base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_MODERATE);
  base::RunLoop().RunUntilIdle();
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);

  // Idle sockets should be not flushed on critical memory pressure.
  base::MemoryPressureListener::NotifyMemoryPressure(
      base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL);
  base::RunLoop().RunUntilIdle();
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);
}

TEST_F(HttpStreamPoolGroupTest, DestroySessionWhileStreamAlive) {
  std::unique_ptr<HttpStream> stream =
      GetOrCreateTestGroup().CreateTextBasedStream(
          std::make_unique<FakeStreamSocket>(),
          StreamSocketHandle::SocketReuseType::kUnused,
          LoadTimingInfo::ConnectTiming());
  CHECK(stream);

  // Destroy the session. This should not cause a crash.
  DestroyHttpNetworkSession();
}

}  // namespace net

"""

```