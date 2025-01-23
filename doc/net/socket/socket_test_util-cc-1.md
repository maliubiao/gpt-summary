Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of Chromium's network stack. The file `net/socket/socket_test_util.cc` suggests it's related to testing socket functionality.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The file name strongly hints at testing. Looking at the class names (`MockClientSocket`, `MockTCPClientSocket`, `MockSSLClientSocket`, `MockUDPClientSocket`) confirms this. The core purpose is to provide mock implementations of socket interfaces for testing network code without relying on actual network connections.

2. **Categorize the Mock Sockets:**  There are distinct mock implementations for different socket types:
    * Basic Client Socket (`MockClientSocket`): Provides foundational mocking.
    * TCP Client Socket (`MockTCPClientSocket`): Simulates TCP connections, reads, and writes.
    * SSL Client Socket (`MockSSLClientSocket`):  Mocks secure (TLS/SSL) connections.
    * UDP Client Socket (`MockUDPClientSocket`):  Simulates UDP communication.

3. **Analyze Common Functionality:**  Each mock socket implements common socket operations:
    * `Connect()`: Simulates establishing a connection.
    * `Read()`:  Mocks receiving data.
    * `Write()`: Mocks sending data.
    * `Disconnect()`/`Close()`: Simulates closing the connection.
    * `GetPeerAddress()`/`GetLocalAddress()`: Returns mock addresses.
    * `IsConnected()`/`IsConnectedAndIdle()`:  Returns the mocked connection state.
    * `SetReceiveBufferSize()`/`SetSendBufferSize()`:  Mocks setting buffer sizes.
    * `SetNoDelay()`/`SetKeepAlive()`: Mocks setting socket options.

4. **Analyze Specific Functionality:**  Each mock socket has features specific to its protocol:
    * `MockTCPClientSocket`:  Handles `ReadIfReady`, `CancelReadIfReady`, and callbacks for asynchronous operations. Uses `SocketDataProvider` to control behavior.
    * `MockSSLClientSocket`: Handles `ConfirmHandshake`, `GetSSLInfo`, `ExportKeyingMaterial`, `GetECHRetryConfigs`, and interacts with `SSLSocketDataProvider`.
    * `MockUDPClientSocket`: Handles `SetDoNotFragment`, `SetRecvTos`, `SetTos`, `SetMulticastInterface`, and connecting using specific network handles.

5. **Identify Supporting Classes:**  Several supporting classes facilitate the mocking:
    * `SocketDataProvider`: Provides pre-configured data and control for `MockTCPClientSocket` and `MockUDPClientSocket`.
    * `SSLSocketDataProvider`: Provides pre-configured data and control for `MockSSLClientSocket`.
    * `MockRead`, `MockWriteResult`, `MockConnect`:  Structures used to define the behavior of read, write, and connect operations.
    * `TestSocketRequest`: Used in testing socket pools to track request completion order.
    * `ClientSocketPoolTest`:  A base class for testing client socket pools.
    * `MockTransportClientSocketPool`: A mock implementation of a transport client socket pool.
    * `MockConnectJob`:  A mock implementation of a connection job within the socket pool.

6. **Address the Specific Questions:**
    * **Functionality:**  List the functionalities identified in the previous steps.
    * **Relationship to JavaScript:**  Explain that while the code itself is C++, it's used in Chromium, which powers the Chrome browser. JavaScript running in the browser uses these network functionalities indirectly when making network requests. Provide an example of `fetch()` triggering the underlying network stack.
    * **Logical Reasoning (Assumptions/Inputs/Outputs):**  Demonstrate how the mock sockets can be used to simulate different scenarios. For example, show how `SocketDataProvider` can be set up to make a connection succeed or fail, or how a read operation can return specific data.
    * **User/Programming Errors:** Illustrate common mistakes when working with sockets, such as forgetting to handle connection errors or attempting to read/write on a disconnected socket. Explain how these mock objects can help uncover such errors during testing.
    * **User Operations leading here:** Describe a user action in the browser (like visiting a website) and trace it down to the point where these socket implementations might be used for testing.

7. **Summarize Functionality (for Part 2):** Condense the main points into a concise summary for this specific part of the file. Emphasize the mocking aspect and the different socket types covered.

8. **Review and Refine:** Read through the generated answer to ensure clarity, accuracy, and completeness. Check for any logical inconsistencies or areas that could be explained better. For example, ensure the JavaScript example is clear and the explanation of how testing helps prevent errors is understandable.
这是文件 `net/socket/socket_test_util.cc` 的第二部分，它主要定义了用于网络栈测试的各种 **mock（模拟）客户端 socket 类**。 这些 mock 类允许在测试环境中模拟网络连接和数据传输的行为，而无需建立真实的物理网络连接。

以下是这一部分的主要功能归纳：

**1. MockSSLClientSocket 类:**

*   **模拟 SSL/TLS 连接:**  `MockSSLClientSocket` 用于模拟安全的 SSL/TLS 客户端 socket。
*   **控制连接行为:**  通过关联 `SSLSocketDataProvider` 对象，可以预先设定连接的结果（成功或失败）、握手过程、证书信息等。
*   **模拟读写操作:**  实现了 `Read` 和 `Write` 方法，但实际上调用的是内部 `stream_socket_` (通常是 `MockTCPClientSocket`) 的对应方法。
*   **模拟 SSL 特有的操作:**  例如 `ConfirmHandshake` 用于模拟 SSL 握手确认过程，`GetSSLInfo` 返回预设的 SSL 信息，`ExportKeyingMaterial` 模拟导出密钥材料。
*   **支持 ECH (Encrypted Client Hello):**  提供了 `GetECHRetryConfigs` 来模拟 ECH 重试配置。
*   **异步操作:**  使用 `RunCallbackAsync` 和 `RunCallback` 支持模拟异步操作的回调。

**2. MockUDPClientSocket 类:**

*   **模拟 UDP 连接:**  `MockUDPClientSocket` 用于模拟无连接的 UDP 客户端 socket。
*   **控制连接行为:** 通过关联 `SocketDataProvider` 对象，可以预设连接的结果。
*   **模拟读写操作:** 实现了 `Read` 和 `Write` 方法，通过 `SocketDataProvider` 控制返回的数据和结果。
*   **支持连接操作:**  提供了 `Connect`、`ConnectUsingNetwork`、`ConnectUsingDefaultNetwork` 以及对应的异步版本，用于模拟 UDP 的连接过程。
*   **模拟设置 UDP 特有选项:** 例如 `SetDoNotFragment`、`SetRecvTos`、`SetTos`、`SetMulticastInterface`。
*   **异步操作:** 使用 `RunCallbackAsync` 和 `RunCallback` 支持模拟异步操作的回调。
*   **模拟数据包的 TOS (Type of Service) 字段:** 记录最后读取的数据包的 TOS 值。

**3. TestSocketRequest 类:**

*   **用于追踪异步请求顺序:**  `TestSocketRequest` 类用于在测试客户端 socket pool 时追踪异步请求完成的顺序。
*   **记录完成结果:**  每个请求对象可以记录其完成的结果。

**4. ClientSocketPoolTest 类:**

*   **用于测试客户端 socket pool 的基类:**  `ClientSocketPoolTest` 提供了一些辅助方法来管理和检查 socket pool 的状态。
*   **追踪请求顺序:**  使用 `GetOrderOfRequest` 方法来检查请求的完成顺序。
*   **释放连接:**  提供了 `ReleaseOneConnection` 和 `ReleaseAllConnections` 方法来模拟连接的释放。

**5. MockTransportClientSocketPool 和 MockConnectJob 类:**

*   **模拟传输层客户端 socket pool:**  `MockTransportClientSocketPool` 是一个简化的 socket pool 实现，用于测试更高层次的网络功能。
*   **模拟连接任务:**  `MockConnectJob` 模拟了 socket pool 中创建和连接 socket 的过程。

**与 JavaScript 的关系:**

虽然这些 C++ 代码本身不直接与 JavaScript 交互，但 Chromium 是 Chrome 浏览器的核心，它负责处理所有的网络请求。当 JavaScript 代码在浏览器中执行网络操作（例如使用 `fetch()` API 或 `XMLHttpRequest` 对象）时，最终会调用到 Chromium 网络栈的底层实现。

这些 mock 类在 **Chromium 的网络栈测试** 中扮演着关键角色。  当 Chromium 的开发者编写测试用例来验证网络功能的正确性时，他们会使用这些 mock 类来模拟各种网络场景，而无需依赖真实的服务器或网络环境。

**举例说明:**

假设一个 JavaScript 应用使用 `fetch()` 发起一个 HTTPS 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

在 Chromium 的网络栈测试中，可以使用 `MockSSLClientSocket` 来模拟与 `example.com` 的 SSL 连接。可以预先配置 `SSLSocketDataProvider` 来模拟以下场景：

*   **连接成功:**  测试 `fetch()` 是否能够成功获取数据。
*   **连接失败 (例如证书错误):**  测试 `fetch()` 是否能够正确处理错误，并且 JavaScript 代码是否能捕获到相应的异常。
*   **服务器返回特定数据:**  测试 `fetch()` 是否能够正确解析服务器返回的 JSON 数据。

**逻辑推理 (假设输入与输出):**

**假设输入 (针对 `MockTCPClientSocket::ReadIfReadyImpl`)**:

*   `connected_` 为 true。
*   `data_` (指向 `SocketDataProvider`) 有效。
*   `need_read_data_` 为 true。
*   `data_->OnRead()` 返回一个 `MockRead` 对象，其中 `result` 为 10，`data` 指向一个包含 "test data" 的缓冲区，`data_len` 为 9。
*   `buf_len` (传入 `ReadIfReadyImpl` 的缓冲区长度) 为 5。

**输出:**

*   `result` (返回值) 将为 5 (因为 `buf_len` 为 5，只读取了部分数据)。
*   `buf` 指向的缓冲区将包含 "test "。
*   `read_offset_` 将为 5。
*   `need_read_data_` 仍然为 true (因为还有数据未读取完)。

**用户或编程常见的使用错误 (针对 `MockTCPClientSocket`)：**

*   **错误:**  在 `Connect()` 尚未成功返回之前调用 `Read()` 或 `Write()`。
*   **模拟结果:**  `MockTCPClientSocket` 的 `Read()` 和 `Write()` 方法会检查 `connected_` 状态，如果未连接，则可能返回 `ERR_UNEXPECTED` 或其他错误码，从而在测试中暴露这个问题。
*   **错误:**  忘记处理异步操作的回调。
*   **模拟结果:**  测试用例可以使用 `MockTCPClientSocket` 和 `SocketDataProvider` 来模拟异步的读写操作，如果回调没有被正确处理，测试将会失败。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在 Chrome 浏览器中访问一个 HTTPS 网站 (例如 `https://example.com`).**
2. **浏览器进程的网络服务 (Network Service) 开始处理该请求。**
3. **网络服务需要创建一个 socket 连接到 `example.com` 的服务器。**
4. **在开发和测试阶段，Chromium 的开发者可能会配置使用 `MockClientSocket`、`MockTCPClientSocket` 或 `MockSSLClientSocket` 来模拟底层的 socket 连接，而不是建立真实的连接。** 这通常通过依赖注入或配置来实现。
5. **当网络服务的代码尝试连接、读取或写入数据时，它会调用这些 mock 对象的相应方法。**
6. **如果开发者正在调试网络相关的代码，他们可能会在这些 mock 类的函数中设置断点，以观察模拟的网络行为和数据流。**  例如，他们可能会在 `MockSSLClientSocket::Connect()` 中设置断点，以查看模拟的 SSL 连接过程。

**总结 (针对 Part 2 的功能):**

这部分代码定义了用于模拟客户端 socket 的关键 C++ 类，主要包括 `MockSSLClientSocket` 和 `MockUDPClientSocket`。这些 mock 类允许 Chromium 的开发者在测试环境中独立地验证网络栈的各个组件，模拟各种网络连接场景和数据传输行为，而无需依赖真实的物理网络。 此外，还包含用于辅助 socket pool 测试的类，如 `TestSocketRequest`, `ClientSocketPoolTest`, `MockTransportClientSocketPool`, 和 `MockConnectJob`。 这些 mock 工具是保证 Chromium 网络功能正确性和稳定性的重要组成部分。

### 提示词
```
这是目录为net/socket/socket_test_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
cert.get()));
    }
  }
  if (next_ssl_data->expected_host_and_port) {
    EXPECT_EQ(*next_ssl_data->expected_host_and_port, host_and_port);
  }
  if (next_ssl_data->expected_ignore_certificate_errors) {
    EXPECT_EQ(*next_ssl_data->expected_ignore_certificate_errors,
              ssl_config.ignore_certificate_errors);
  }
  if (next_ssl_data->expected_network_anonymization_key) {
    EXPECT_EQ(*next_ssl_data->expected_network_anonymization_key,
              ssl_config.network_anonymization_key);
  }
  if (next_ssl_data->expected_ech_config_list) {
    EXPECT_EQ(*next_ssl_data->expected_ech_config_list,
              ssl_config.ech_config_list);
  }
  return std::make_unique<MockSSLClientSocket>(
      std::move(stream_socket), host_and_port, ssl_config, next_ssl_data);
}

MockClientSocket::MockClientSocket(const NetLogWithSource& net_log)
    : net_log_(net_log) {
  local_addr_ = IPEndPoint(IPAddress(192, 0, 2, 33), 123);
  peer_addr_ = IPEndPoint(IPAddress(192, 0, 2, 33), 0);
}

int MockClientSocket::SetReceiveBufferSize(int32_t size) {
  return OK;
}

int MockClientSocket::SetSendBufferSize(int32_t size) {
  return OK;
}

int MockClientSocket::Bind(const net::IPEndPoint& local_addr) {
  local_addr_ = local_addr;
  return net::OK;
}

bool MockClientSocket::SetNoDelay(bool no_delay) {
  return true;
}

bool MockClientSocket::SetKeepAlive(bool enable, int delay) {
  return true;
}

void MockClientSocket::Disconnect() {
  connected_ = false;
}

bool MockClientSocket::IsConnected() const {
  return connected_;
}

bool MockClientSocket::IsConnectedAndIdle() const {
  return connected_;
}

int MockClientSocket::GetPeerAddress(IPEndPoint* address) const {
  if (!IsConnected())
    return ERR_SOCKET_NOT_CONNECTED;
  *address = peer_addr_;
  return OK;
}

int MockClientSocket::GetLocalAddress(IPEndPoint* address) const {
  *address = local_addr_;
  return OK;
}

const NetLogWithSource& MockClientSocket::NetLog() const {
  return net_log_;
}

NextProto MockClientSocket::GetNegotiatedProtocol() const {
  return kProtoUnknown;
}

MockClientSocket::~MockClientSocket() = default;

void MockClientSocket::RunCallbackAsync(CompletionOnceCallback callback,
                                        int result) {
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&MockClientSocket::RunCallback, weak_factory_.GetWeakPtr(),
                     std::move(callback), result));
}

void MockClientSocket::RunCallback(CompletionOnceCallback callback,
                                   int result) {
  std::move(callback).Run(result);
}

MockTCPClientSocket::MockTCPClientSocket(const AddressList& addresses,
                                         net::NetLog* net_log,
                                         SocketDataProvider* data)
    : MockClientSocket(
          NetLogWithSource::Make(net_log, NetLogSourceType::SOCKET)),
      addresses_(addresses),
      data_(data),
      read_data_(SYNCHRONOUS, ERR_UNEXPECTED) {
  DCHECK(data_);
  peer_addr_ = data->connect_data().peer_addr;
  data_->Initialize(this);
  if (data_->expected_addresses()) {
    EXPECT_EQ(*data_->expected_addresses(), addresses);
  }
}

MockTCPClientSocket::~MockTCPClientSocket() {
  if (data_)
    data_->DetachSocket();
}

int MockTCPClientSocket::Read(IOBuffer* buf,
                              int buf_len,
                              CompletionOnceCallback callback) {
  // If the buffer is already in use, a read is already in progress!
  DCHECK(!pending_read_buf_);
  // Use base::Unretained() is safe because MockClientSocket::RunCallbackAsync()
  // takes a weak ptr of the base class, MockClientSocket.
  int rv = ReadIfReadyImpl(
      buf, buf_len,
      base::BindOnce(&MockTCPClientSocket::RetryRead, base::Unretained(this)));
  if (rv == ERR_IO_PENDING) {
    DCHECK(callback);

    pending_read_buf_ = buf;
    pending_read_buf_len_ = buf_len;
    pending_read_callback_ = std::move(callback);
  }
  return rv;
}

int MockTCPClientSocket::ReadIfReady(IOBuffer* buf,
                                     int buf_len,
                                     CompletionOnceCallback callback) {
  DCHECK(!pending_read_if_ready_callback_);

  if (!enable_read_if_ready_)
    return ERR_READ_IF_READY_NOT_IMPLEMENTED;
  return ReadIfReadyImpl(buf, buf_len, std::move(callback));
}

int MockTCPClientSocket::CancelReadIfReady() {
  DCHECK(pending_read_if_ready_callback_);

  pending_read_if_ready_callback_.Reset();
  data_->CancelPendingRead();
  return OK;
}

int MockTCPClientSocket::Write(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& /* traffic_annotation */) {
  DCHECK(buf);
  DCHECK_GT(buf_len, 0);

  if (!connected_ || !data_)
    return ERR_UNEXPECTED;

  std::string data(buf->data(), buf_len);
  MockWriteResult write_result = data_->OnWrite(data);

  was_used_to_convey_data_ = true;

  if (write_result.result == ERR_CONNECTION_CLOSED) {
    // This MockWrite is just a marker to instruct us to set
    // peer_closed_connection_.
    peer_closed_connection_ = true;
  }
  // ERR_IO_PENDING is a signal that the socket data will call back
  // asynchronously later.
  if (write_result.result == ERR_IO_PENDING) {
    pending_write_callback_ = std::move(callback);
    return ERR_IO_PENDING;
  }

  if (write_result.mode == ASYNC) {
    RunCallbackAsync(std::move(callback), write_result.result);
    return ERR_IO_PENDING;
  }

  return write_result.result;
}

int MockTCPClientSocket::SetReceiveBufferSize(int32_t size) {
  if (!connected_)
    return net::ERR_UNEXPECTED;
  data_->set_receive_buffer_size(size);
  return data_->set_receive_buffer_size_result();
}

int MockTCPClientSocket::SetSendBufferSize(int32_t size) {
  if (!connected_)
    return net::ERR_UNEXPECTED;
  data_->set_send_buffer_size(size);
  return data_->set_send_buffer_size_result();
}

bool MockTCPClientSocket::SetNoDelay(bool no_delay) {
  if (!connected_)
    return false;
  data_->set_no_delay(no_delay);
  return data_->set_no_delay_result();
}

bool MockTCPClientSocket::SetKeepAlive(bool enable, int delay) {
  if (!connected_)
    return false;
  data_->set_keep_alive(enable, delay);
  return data_->set_keep_alive_result();
}

void MockTCPClientSocket::SetBeforeConnectCallback(
    const BeforeConnectCallback& before_connect_callback) {
  DCHECK(!before_connect_callback_);
  DCHECK(!connected_);

  before_connect_callback_ = before_connect_callback;
}

int MockTCPClientSocket::Connect(CompletionOnceCallback callback) {
  if (!data_)
    return ERR_UNEXPECTED;

  if (connected_)
    return OK;

  // Setting socket options fails if not connected, so need to set this before
  // calling |before_connect_callback_|.
  connected_ = true;

  if (before_connect_callback_) {
    for (size_t index = 0; index < addresses_.size(); index++) {
      int result = before_connect_callback_.Run();
      if (data_->connect_data().first_attempt_fails && index == 0) {
        continue;
      }
      DCHECK_NE(result, ERR_IO_PENDING);
      if (result != net::OK) {
        connected_ = false;
        return result;
      }
      break;
    }
  }

  peer_closed_connection_ = false;

  if (data_->connect_data().completer) {
    data_->connect_data().completer->SetCallback(std::move(callback));
    return ERR_IO_PENDING;
  }

  int result = data_->connect_data().result;
  IoMode mode = data_->connect_data().mode;
  if (mode == SYNCHRONOUS)
    return result;

  DCHECK(callback);

  if (result == ERR_IO_PENDING)
    pending_connect_callback_ = std::move(callback);
  else
    RunCallbackAsync(std::move(callback), result);
  return ERR_IO_PENDING;
}

void MockTCPClientSocket::Disconnect() {
  MockClientSocket::Disconnect();
  pending_connect_callback_.Reset();
  pending_read_callback_.Reset();
}

bool MockTCPClientSocket::IsConnected() const {
  if (!data_)
    return false;
  return connected_ && !peer_closed_connection_;
}

bool MockTCPClientSocket::IsConnectedAndIdle() const {
  if (!data_)
    return false;
  return IsConnected() && data_->IsIdle();
}

int MockTCPClientSocket::GetPeerAddress(IPEndPoint* address) const {
  if (addresses_.empty())
    return MockClientSocket::GetPeerAddress(address);

  if (data_->connect_data().first_attempt_fails) {
    DCHECK_GE(addresses_.size(), 2U);
    *address = addresses_[1];
  } else {
    *address = addresses_[0];
  }
  return OK;
}

bool MockTCPClientSocket::WasEverUsed() const {
  return was_used_to_convey_data_;
}

bool MockTCPClientSocket::GetSSLInfo(SSLInfo* ssl_info) {
  return false;
}

void MockTCPClientSocket::OnReadComplete(const MockRead& data) {
  // If |data_| has been destroyed, safest to just do nothing.
  if (!data_)
    return;

  // There must be a read pending.
  DCHECK(pending_read_if_ready_callback_);
  // You can't complete a read with another ERR_IO_PENDING status code.
  DCHECK_NE(ERR_IO_PENDING, data.result);
  // Since we've been waiting for data, need_read_data_ should be true.
  DCHECK(need_read_data_);

  read_data_ = data;
  need_read_data_ = false;

  // The caller is simulating that this IO completes right now.  Don't
  // let CompleteRead() schedule a callback.
  read_data_.mode = SYNCHRONOUS;
  RunCallback(std::move(pending_read_if_ready_callback_),
              read_data_.result > 0 ? OK : read_data_.result);
}

void MockTCPClientSocket::OnWriteComplete(int rv) {
  // If |data_| has been destroyed, safest to just do nothing.
  if (!data_)
    return;

  // There must be a read pending.
  DCHECK(!pending_write_callback_.is_null());
  RunCallback(std::move(pending_write_callback_), rv);
}

void MockTCPClientSocket::OnConnectComplete(const MockConnect& data) {
  // If |data_| has been destroyed, safest to just do nothing.
  if (!data_)
    return;

  RunCallback(std::move(pending_connect_callback_), data.result);
}

void MockTCPClientSocket::OnDataProviderDestroyed() {
  data_ = nullptr;
}

void MockTCPClientSocket::RetryRead(int rv) {
  DCHECK(pending_read_callback_);
  DCHECK(pending_read_buf_.get());
  DCHECK_LT(0, pending_read_buf_len_);

  if (rv == OK) {
    rv = ReadIfReadyImpl(pending_read_buf_.get(), pending_read_buf_len_,
                         base::BindOnce(&MockTCPClientSocket::RetryRead,
                                        base::Unretained(this)));
    if (rv == ERR_IO_PENDING)
      return;
  }
  pending_read_buf_ = nullptr;
  pending_read_buf_len_ = 0;
  RunCallback(std::move(pending_read_callback_), rv);
}

int MockTCPClientSocket::ReadIfReadyImpl(IOBuffer* buf,
                                         int buf_len,
                                         CompletionOnceCallback callback) {
  if (!connected_ || !data_)
    return ERR_UNEXPECTED;

  DCHECK(!pending_read_if_ready_callback_);

  if (need_read_data_) {
    read_data_ = data_->OnRead();
    if (read_data_.result == ERR_CONNECTION_CLOSED) {
      // This MockRead is just a marker to instruct us to set
      // peer_closed_connection_.
      peer_closed_connection_ = true;
    }
    if (read_data_.result == ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ) {
      // This MockRead is just a marker to instruct us to set
      // peer_closed_connection_.  Skip it and get the next one.
      read_data_ = data_->OnRead();
      peer_closed_connection_ = true;
    }
    // ERR_IO_PENDING means that the SocketDataProvider is taking responsibility
    // to complete the async IO manually later (via OnReadComplete).
    if (read_data_.result == ERR_IO_PENDING) {
      // We need to be using async IO in this case.
      DCHECK(!callback.is_null());
      pending_read_if_ready_callback_ = std::move(callback);
      return ERR_IO_PENDING;
    }
    need_read_data_ = false;
  }

  int result = read_data_.result;
  DCHECK_NE(ERR_IO_PENDING, result);
  if (read_data_.mode == ASYNC) {
    DCHECK(!callback.is_null());
    read_data_.mode = SYNCHRONOUS;
    pending_read_if_ready_callback_ = std::move(callback);
    // base::Unretained() is safe here because RunCallbackAsync will wrap it
    // with a callback associated with a weak ptr.
    RunCallbackAsync(
        base::BindOnce(&MockTCPClientSocket::RunReadIfReadyCallback,
                       base::Unretained(this)),
        result);
    return ERR_IO_PENDING;
  }

  was_used_to_convey_data_ = true;
  if (read_data_.data) {
    if (read_data_.data_len - read_offset_ > 0) {
      result = std::min(buf_len, read_data_.data_len - read_offset_);
      memcpy(buf->data(), read_data_.data + read_offset_, result);
      read_offset_ += result;
      if (read_offset_ == read_data_.data_len) {
        need_read_data_ = true;
        read_offset_ = 0;
      }
    } else {
      result = 0;  // EOF
    }
  }
  return result;
}

void MockTCPClientSocket::RunReadIfReadyCallback(int result) {
  // If ReadIfReady is already canceled, do nothing.
  if (!pending_read_if_ready_callback_)
    return;
  std::move(pending_read_if_ready_callback_).Run(result);
}

// static
void MockSSLClientSocket::ConnectCallback(
    MockSSLClientSocket* ssl_client_socket,
    CompletionOnceCallback callback,
    int rv) {
  if (rv == OK)
    ssl_client_socket->connected_ = true;
  std::move(callback).Run(rv);
}

MockSSLClientSocket::MockSSLClientSocket(
    std::unique_ptr<StreamSocket> stream_socket,
    const HostPortPair& host_and_port,
    const SSLConfig& ssl_config,
    SSLSocketDataProvider* data)
    : net_log_(stream_socket->NetLog()),
      stream_socket_(std::move(stream_socket)),
      data_(data) {
  DCHECK(data_);
  peer_addr_ = data->connect.peer_addr;
}

MockSSLClientSocket::~MockSSLClientSocket() {
  Disconnect();
}

int MockSSLClientSocket::Read(IOBuffer* buf,
                              int buf_len,
                              CompletionOnceCallback callback) {
  return stream_socket_->Read(buf, buf_len, std::move(callback));
}

int MockSSLClientSocket::ReadIfReady(IOBuffer* buf,
                                     int buf_len,
                                     CompletionOnceCallback callback) {
  return stream_socket_->ReadIfReady(buf, buf_len, std::move(callback));
}

int MockSSLClientSocket::Write(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  if (!data_->is_confirm_data_consumed)
    data_->write_called_before_confirm = true;
  return stream_socket_->Write(buf, buf_len, std::move(callback),
                               traffic_annotation);
}

int MockSSLClientSocket::CancelReadIfReady() {
  return stream_socket_->CancelReadIfReady();
}

int MockSSLClientSocket::Connect(CompletionOnceCallback callback) {
  DCHECK(stream_socket_->IsConnected());
  data_->is_connect_data_consumed = true;
  if (data_->connect.completer) {
    data_->connect.completer->SetCallback(std::move(callback));
    return ERR_IO_PENDING;
  }
  if (data_->connect.result == OK)
    connected_ = true;
  RunClosureIfNonNull(std::move(data_->connect_callback));
  if (data_->connect.mode == ASYNC) {
    RunCallbackAsync(std::move(callback), data_->connect.result);
    return ERR_IO_PENDING;
  }
  return data_->connect.result;
}

void MockSSLClientSocket::Disconnect() {
  if (stream_socket_ != nullptr)
    stream_socket_->Disconnect();
}

void MockSSLClientSocket::RunConfirmHandshakeCallback(
    CompletionOnceCallback callback,
    int result) {
  DCHECK(in_confirm_handshake_);
  in_confirm_handshake_ = false;
  data_->is_confirm_data_consumed = true;
  std::move(callback).Run(result);
}

int MockSSLClientSocket::ConfirmHandshake(CompletionOnceCallback callback) {
  DCHECK(stream_socket_->IsConnected());
  DCHECK(!in_confirm_handshake_);
  if (data_->is_confirm_data_consumed)
    return data_->confirm.result;
  RunClosureIfNonNull(std::move(data_->confirm_callback));
  if (data_->confirm.mode == ASYNC) {
    in_confirm_handshake_ = true;
    RunCallbackAsync(
        base::BindOnce(&MockSSLClientSocket::RunConfirmHandshakeCallback,
                       base::Unretained(this), std::move(callback)),
        data_->confirm.result);
    return ERR_IO_PENDING;
  }
  data_->is_confirm_data_consumed = true;
  if (data_->confirm.result == ERR_IO_PENDING) {
    // `MockConfirm(SYNCHRONOUS, ERR_IO_PENDING)` means `ConfirmHandshake()`
    // never completes.
    in_confirm_handshake_ = true;
  }
  return data_->confirm.result;
}

bool MockSSLClientSocket::IsConnected() const {
  return stream_socket_->IsConnected();
}

bool MockSSLClientSocket::IsConnectedAndIdle() const {
  return stream_socket_->IsConnectedAndIdle();
}

bool MockSSLClientSocket::WasEverUsed() const {
  return stream_socket_->WasEverUsed();
}

int MockSSLClientSocket::GetLocalAddress(IPEndPoint* address) const {
  *address = IPEndPoint(IPAddress(192, 0, 2, 33), 123);
  return OK;
}

int MockSSLClientSocket::GetPeerAddress(IPEndPoint* address) const {
  return stream_socket_->GetPeerAddress(address);
}

NextProto MockSSLClientSocket::GetNegotiatedProtocol() const {
  return data_->next_proto;
}

std::optional<std::string_view>
MockSSLClientSocket::GetPeerApplicationSettings() const {
  return data_->peer_application_settings;
}

bool MockSSLClientSocket::GetSSLInfo(SSLInfo* requested_ssl_info) {
  *requested_ssl_info = data_->ssl_info;
  return true;
}

void MockSSLClientSocket::ApplySocketTag(const SocketTag& tag) {
  return stream_socket_->ApplySocketTag(tag);
}

const NetLogWithSource& MockSSLClientSocket::NetLog() const {
  return net_log_;
}

int64_t MockSSLClientSocket::GetTotalReceivedBytes() const {
  NOTIMPLEMENTED();
  return 0;
}

int64_t MockClientSocket::GetTotalReceivedBytes() const {
  NOTIMPLEMENTED();
  return 0;
}

int MockSSLClientSocket::SetReceiveBufferSize(int32_t size) {
  return OK;
}

int MockSSLClientSocket::SetSendBufferSize(int32_t size) {
  return OK;
}

void MockSSLClientSocket::GetSSLCertRequestInfo(
    SSLCertRequestInfo* cert_request_info) const {
  DCHECK(cert_request_info);
  if (data_->cert_request_info) {
    cert_request_info->host_and_port = data_->cert_request_info->host_and_port;
    cert_request_info->is_proxy = data_->cert_request_info->is_proxy;
    cert_request_info->cert_authorities =
        data_->cert_request_info->cert_authorities;
    cert_request_info->signature_algorithms =
        data_->cert_request_info->signature_algorithms;
  } else {
    cert_request_info->Reset();
  }
}

int MockSSLClientSocket::ExportKeyingMaterial(std::string_view label,
                                              bool has_context,
                                              std::string_view context,
                                              unsigned char* out,
                                              unsigned int outlen) {
  memset(out, 'A', outlen);
  return OK;
}

std::vector<uint8_t> MockSSLClientSocket::GetECHRetryConfigs() {
  return data_->ech_retry_configs;
}

void MockSSLClientSocket::RunCallbackAsync(CompletionOnceCallback callback,
                                           int result) {
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&MockSSLClientSocket::RunCallback,
                     weak_factory_.GetWeakPtr(), std::move(callback), result));
}

void MockSSLClientSocket::RunCallback(CompletionOnceCallback callback,
                                      int result) {
  std::move(callback).Run(result);
}

void MockSSLClientSocket::OnReadComplete(const MockRead& data) {
  NOTIMPLEMENTED();
}

void MockSSLClientSocket::OnWriteComplete(int rv) {
  NOTIMPLEMENTED();
}

void MockSSLClientSocket::OnConnectComplete(const MockConnect& data) {
  NOTIMPLEMENTED();
}

MockUDPClientSocket::MockUDPClientSocket(SocketDataProvider* data,
                                         net::NetLog* net_log)
    : data_(data),
      read_data_(SYNCHRONOUS, ERR_UNEXPECTED),
      source_host_(IPAddress(192, 0, 2, 33)),
      net_log_(NetLogWithSource::Make(net_log,
                                      NetLogSourceType::UDP_CLIENT_SOCKET)) {
  if (data_) {
    data_->Initialize(this);
    peer_addr_ = data->connect_data().peer_addr;
  }
}

MockUDPClientSocket::~MockUDPClientSocket() {
  if (data_)
    data_->DetachSocket();
}

int MockUDPClientSocket::Read(IOBuffer* buf,
                              int buf_len,
                              CompletionOnceCallback callback) {
  DCHECK(callback);

  if (!connected_ || !data_)
    return ERR_UNEXPECTED;
  data_transferred_ = true;

  // If the buffer is already in use, a read is already in progress!
  DCHECK(!pending_read_buf_);

  // Store our async IO data.
  pending_read_buf_ = buf;
  pending_read_buf_len_ = buf_len;
  pending_read_callback_ = std::move(callback);

  if (need_read_data_) {
    read_data_ = data_->OnRead();
    last_tos_ = read_data_.tos;
    // ERR_IO_PENDING means that the SocketDataProvider is taking responsibility
    // to complete the async IO manually later (via OnReadComplete).
    if (read_data_.result == ERR_IO_PENDING) {
      // We need to be using async IO in this case.
      DCHECK(!pending_read_callback_.is_null());
      return ERR_IO_PENDING;
    }
    need_read_data_ = false;
  }

  return CompleteRead();
}

int MockUDPClientSocket::Write(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& /* traffic_annotation */) {
  DCHECK(buf);
  DCHECK_GT(buf_len, 0);
  DCHECK(callback);

  if (!connected_ || !data_)
    return ERR_UNEXPECTED;
  data_transferred_ = true;

  std::string data(buf->data(), buf_len);
  MockWriteResult write_result = data_->OnWrite(data);

  // ERR_IO_PENDING is a signal that the socket data will call back
  // asynchronously.
  if (write_result.result == ERR_IO_PENDING) {
    pending_write_callback_ = std::move(callback);
    return ERR_IO_PENDING;
  }
  if (write_result.mode == ASYNC) {
    RunCallbackAsync(std::move(callback), write_result.result);
    return ERR_IO_PENDING;
  }
  return write_result.result;
}

int MockUDPClientSocket::SetReceiveBufferSize(int32_t size) {
  return OK;
}

int MockUDPClientSocket::SetSendBufferSize(int32_t size) {
  return OK;
}

int MockUDPClientSocket::SetDoNotFragment() {
  return OK;
}

int MockUDPClientSocket::SetRecvTos() {
  return OK;
}

int MockUDPClientSocket::SetTos(DiffServCodePoint dscp, EcnCodePoint ecn) {
  return OK;
}

void MockUDPClientSocket::Close() {
  connected_ = false;
}

int MockUDPClientSocket::GetPeerAddress(IPEndPoint* address) const {
  if (!data_)
    return ERR_UNEXPECTED;

  *address = peer_addr_;
  return OK;
}

int MockUDPClientSocket::GetLocalAddress(IPEndPoint* address) const {
  *address = IPEndPoint(source_host_, source_port_);
  return OK;
}

void MockUDPClientSocket::UseNonBlockingIO() {}

int MockUDPClientSocket::SetMulticastInterface(uint32_t interface_index) {
  return OK;
}

const NetLogWithSource& MockUDPClientSocket::NetLog() const {
  return net_log_;
}

int MockUDPClientSocket::Connect(const IPEndPoint& address) {
  if (!data_)
    return ERR_UNEXPECTED;
  DCHECK_NE(data_->connect_data().result, ERR_IO_PENDING);
  connected_ = true;
  peer_addr_ = address;
  return data_->connect_data().result;
}

int MockUDPClientSocket::ConnectUsingNetwork(handles::NetworkHandle network,
                                             const IPEndPoint& address) {
  DCHECK(!connected_);
  if (!data_)
    return ERR_UNEXPECTED;
  DCHECK_NE(data_->connect_data().result, ERR_IO_PENDING);
  network_ = network;
  connected_ = true;
  peer_addr_ = address;
  return data_->connect_data().result;
}

int MockUDPClientSocket::ConnectUsingDefaultNetwork(const IPEndPoint& address) {
  DCHECK(!connected_);
  if (!data_)
    return ERR_UNEXPECTED;
  DCHECK_NE(data_->connect_data().result, ERR_IO_PENDING);
  network_ = kDefaultNetworkForTests;
  connected_ = true;
  peer_addr_ = address;
  return data_->connect_data().result;
}

int MockUDPClientSocket::ConnectAsync(const IPEndPoint& address,
                                      CompletionOnceCallback callback) {
  DCHECK(callback);
  if (!data_) {
    return ERR_UNEXPECTED;
  }
  connected_ = true;
  peer_addr_ = address;
  int result = data_->connect_data().result;
  IoMode mode = data_->connect_data().mode;
  if (data_->connect_data().completer) {
    data_->connect_data().completer->SetCallback(std::move(callback));
    return ERR_IO_PENDING;
  }
  if (mode == SYNCHRONOUS) {
    return result;
  }
  RunCallbackAsync(std::move(callback), result);
  return ERR_IO_PENDING;
}

int MockUDPClientSocket::ConnectUsingNetworkAsync(
    handles::NetworkHandle network,
    const IPEndPoint& address,
    CompletionOnceCallback callback) {
  DCHECK(callback);
  DCHECK(!connected_);
  if (!data_)
    return ERR_UNEXPECTED;
  network_ = network;
  connected_ = true;
  peer_addr_ = address;
  int result = data_->connect_data().result;
  IoMode mode = data_->connect_data().mode;
  if (data_->connect_data().completer) {
    data_->connect_data().completer->SetCallback(std::move(callback));
    return ERR_IO_PENDING;
  }
  if (mode == SYNCHRONOUS) {
    return result;
  }
  RunCallbackAsync(std::move(callback), result);
  return ERR_IO_PENDING;
}

int MockUDPClientSocket::ConnectUsingDefaultNetworkAsync(
    const IPEndPoint& address,
    CompletionOnceCallback callback) {
  DCHECK(!connected_);
  if (!data_)
    return ERR_UNEXPECTED;
  network_ = kDefaultNetworkForTests;
  connected_ = true;
  peer_addr_ = address;
  int result = data_->connect_data().result;
  IoMode mode = data_->connect_data().mode;
  if (data_->connect_data().completer) {
    data_->connect_data().completer->SetCallback(std::move(callback));
    return ERR_IO_PENDING;
  }
  if (mode == SYNCHRONOUS) {
    return result;
  }
  RunCallbackAsync(std::move(callback), result);
  return ERR_IO_PENDING;
}

handles::NetworkHandle MockUDPClientSocket::GetBoundNetwork() const {
  return network_;
}

void MockUDPClientSocket::ApplySocketTag(const SocketTag& tag) {
  tagged_before_data_transferred_ &= !data_transferred_ || tag == tag_;
  tag_ = tag;
}

DscpAndEcn MockUDPClientSocket::GetLastTos() const {
  return TosToDscpAndEcn(last_tos_);
}

void MockUDPClientSocket::OnReadComplete(const MockRead& data) {
  if (!data_)
    return;

  // There must be a read pending.
  DCHECK(pending_read_buf_.get());
  DCHECK(pending_read_callback_);
  // You can't complete a read with another ERR_IO_PENDING status code.
  DCHECK_NE(ERR_IO_PENDING, data.result);
  // Since we've been waiting for data, need_read_data_ should be true.
  DCHECK(need_read_data_);

  read_data_ = data;
  last_tos_ = data.tos;
  need_read_data_ = false;

  // The caller is simulating that this IO completes right now.  Don't
  // let CompleteRead() schedule a callback.
  read_data_.mode = SYNCHRONOUS;

  CompletionOnceCallback callback = std::move(pending_read_callback_);
  int rv = CompleteRead();
  RunCallback(std::move(callback), rv);
}

void MockUDPClientSocket::OnWriteComplete(int rv) {
  if (!data_)
    return;

  // There must be a read pending.
  DCHECK(!pending_write_callback_.is_null());
  RunCallback(std::move(pending_write_callback_), rv);
}

void MockUDPClientSocket::OnConnectComplete(const MockConnect& data) {
  NOTIMPLEMENTED();
}

void MockUDPClientSocket::OnDataProviderDestroyed() {
  data_ = nullptr;
}

int MockUDPClientSocket::CompleteRead() {
  DCHECK(pending_read_buf_.get());
  DCHECK(pending_read_buf_len_ > 0);

  // Save the pending async IO data and reset our |pending_| state.
  scoped_refptr<IOBuffer> buf = pending_read_buf_;
  int buf_len = pending_read_buf_len_;
  CompletionOnceCallback callback = std::move(pending_read_callback_);
  pending_read_buf_ = nullptr;
  pending_read_buf_len_ = 0;

  int result = read_data_.result;
  DCHECK(result != ERR_IO_PENDING);

  if (read_data_.data) {
    if (read_data_.data_len - read_offset_ > 0) {
      result = std::min(buf_len, read_data_.data_len - read_offset_);
      memcpy(buf->data(), read_data_.data + read_offset_, result);
      read_offset_ += result;
      if (read_offset_ == read_data_.data_len) {
        need_read_data_ = true;
        read_offset_ = 0;
      }
    } else {
      result = 0;  // EOF
    }
  }

  if (read_data_.mode == ASYNC) {
    DCHECK(!callback.is_null());
    RunCallbackAsync(std::move(callback), result);
    return ERR_IO_PENDING;
  }
  return result;
}

void MockUDPClientSocket::RunCallbackAsync(CompletionOnceCallback callback,
                                           int result) {
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&MockUDPClientSocket::RunCallback,
                     weak_factory_.GetWeakPtr(), std::move(callback), result));
}

void MockUDPClientSocket::RunCallback(CompletionOnceCallback callback,
                                      int result) {
  std::move(callback).Run(result);
}

TestSocketRequest::TestSocketRequest(
    std::vector<raw_ptr<TestSocketRequest, VectorExperimental>>* request_order,
    size_t* completion_count)
    : request_order_(request_order), completion_count_(completion_count) {
  DCHECK(request_order);
  DCHECK(completion_count);
}

TestSocketRequest::~TestSocketRequest() = default;

void TestSocketRequest::OnComplete(int result) {
  SetResult(result);
  (*completion_count_)++;
  request_order_->push_back(this);
}

// static
const int ClientSocketPoolTest::kIndexOutOfBounds = -1;

// static
const int ClientSocketPoolTest::kRequestNotFound = -2;

ClientSocketPoolTest::ClientSocketPoolTest() = default;
ClientSocketPoolTest::~ClientSocketPoolTest() = default;

int ClientSocketPoolTest::GetOrderOfRequest(size_t index) const {
  index--;
  if (index >= requests_.size())
    return kIndexOutOfBounds;

  for (size_t i = 0; i < request_order_.size(); i++)
    if (requests_[index].get() == request_order_[i])
      return i + 1;

  return kRequestNotFound;
}

bool ClientSocketPoolTest::ReleaseOneConnection(KeepAlive keep_alive) {
  for (std::unique_ptr<TestSocketRequest>& it : requests_) {
    if (it->handle()->is_initialized()) {
      if (keep_alive == NO_KEEP_ALIVE)
        it->handle()->socket()->Disconnect();
      it->handle()->Reset();
      base::RunLoop().RunUntilIdle();
      return true;
    }
  }
  return false;
}

void ClientSocketPoolTest::ReleaseAllConnections(KeepAlive keep_alive) {
  bool released_one;
  do {
    released_one = ReleaseOneConnection(keep_alive);
  } while (released_one);
}

MockTransportClientSocketPool::MockConnectJob::MockConnectJob(
    std::unique_ptr<StreamSocket> socket,
    ClientSocketHandle* handle,
    const SocketTag& socket_tag,
    CompletionOnceCallback callback,
    RequestPriority priority)
    : socket_(std::move(socket)),
      handle_(handle),
      socket_tag_(socket_tag),
      user_callback_(std::move(callback)),
      priority_(priority) {}

MockTransportClientSocketPool::MockConnectJob::~MockConnectJob() = default;

int MockTransportClientSocketPool::MockConnectJob::Connect() {
  socket_->ApplySocketTag(socket_tag_);
  int rv = socket_->Connect(
      base::BindOnce(&MockConnectJob::OnConnect, base::Unretained(this)));
  if (rv != ERR_IO_PENDING) {
    user_callback_.Reset();
    OnConnect(rv);
  }
  return rv;
}

bool MockTransportClientSocketPool::MockConnectJob::CancelHandle(
    const ClientSocketHandle* handle) {
  if (handle != handle_)
    return false;
  socket_.reset();
  handle_ = nullptr;
  user_callback_.Reset();
  return true;
}

void MockTransportClientSocketPool::MockConnectJob::OnConnect(int rv) {
  if (!socket_.get())
    return;
  if (rv == OK) {
    handle_->SetSocket(std::move(socket_));

    // Needed for socket pool tests that layer other sockets on top of mock
    // sockets.
    LoadTimingInfo::ConnectTiming connect_timing;
    base::TimeTicks now = base::TimeTicks::Now();
    connect_timing.domain_lookup_start = now;
    connect_timing.domain_lookup_end = now;
    connect_timing.connect_start = now;
    connect_timing.connect_end = now;
    handle_->set_connect_timing(connect_timing);
  } else {
    socket_.reset();

    // Needed to test copying of ConnectionAttempts in SSL ConnectJob.
    ConnectionAttempts attempts;
    attempts.push_back(ConnectionAttempt(IPEndPoint(), rv));
    handle_->set_connection_attempts(attempts);
  }

  handle_ = nullptr;

  if (!user_callback_.is_null()) {
    std::move(user_callback_).Run(rv);
  }
}

MockTransportClientSocketPool::MockTransportClientSocketPool(
    int max_sockets,
    int max_sockets_per_group,
    const CommonConnectJobParams* common_connect_job_params)
    : TransportClientSocketPool(
          max_sockets,
          max_sockets_per_group,
          base::Seconds(10) /* unused_idle_socket_timeout */,
          ProxyChain::Direct(),
          false /* is_for_websockets */,
```