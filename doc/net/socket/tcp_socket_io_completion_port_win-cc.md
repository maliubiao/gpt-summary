Response:
Let's break down the thought process for analyzing the given C++ code. The request asks for several things, so a structured approach is necessary.

**1. Understanding the Core Functionality:**

The first step is to grasp what the code *does*. Keywords and class names provide strong clues:

* `TcpSocketIoCompletionPortWin`:  This immediately suggests a TCP socket implementation for Windows using I/O completion ports. Completion ports are a Windows mechanism for asynchronous I/O.
* `IOContext`: This likely represents the context of an asynchronous I/O operation (read or write).
* `WSARecv`, `WSASend`: These are WinSock functions for receiving and sending data on a socket, specifically the asynchronous versions.
* `SetFileCompletionNotificationModes`, `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS`: These point to an optimization where completion notifications can be skipped if the operation completes immediately.
* `base::win::ObjectWatcher`, `WSAEvent`: These indicate a mechanism for waiting on events, likely for connection completion.
* `base::MessagePumpForIO::IOHandler`: This suggests integration with Chromium's I/O message loop, the central mechanism for handling asynchronous I/O in the browser.

From these clues, we can infer the core purpose: **This code implements asynchronous TCP socket I/O on Windows using I/O completion ports, with an optimization to potentially skip completion notifications for immediate successes.**

**2. Identifying Key Components and Their Roles:**

Now, let's detail the roles of the major parts:

* **`TcpSocketIoCompletionPortWin` class:**  The main class. It manages the socket, handles read and write operations, and interacts with the underlying Windows APIs.
* **`CoreImpl` class:**  A nested class that acts as the core implementation details, including the I/O handler, connection event management, and the logic for interacting with the Windows I/O system. This separation likely improves code organization.
* **`IOContext` struct:** Holds the necessary information for an asynchronous I/O operation, such as the buffer, buffer length, completion callback, and a pointer back to the `CoreImpl`.
* **Asynchronous I/O functions (`Read`, `Write`):** These initiate the asynchronous operations using `WSARecv` and `WSASend`. They set up the `IOContext` and return `ERR_IO_PENDING`.
* **Completion Handling (`OnIOCompleted`):**  This is the heart of the completion port mechanism. When an I/O operation finishes, the Windows kernel triggers this function. It retrieves the associated `IOContext` and calls the appropriate completion method (`DidCompleteRead`, `DidCompleteWrite`).
* **Connection Handling (`GetConnectEvent`, `WatchForConnect`, `OnObjectSignaled`):**  Handles the asynchronous connection establishment process. It creates a `WSAEvent`, uses `WSAEventSelect` to associate it with connection events, and waits for the event to be signaled.
* **`EnsureOverlappedIOInitialized`:** Sets up the I/O completion port association and the `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS` optimization.

**3. Analyzing Potential Interactions with JavaScript:**

The prompt specifically asks about JavaScript interaction. The key here is understanding how Chromium's network stack connects to the browser's JavaScript environment.

* **Network Service:**  Chromium's network stack typically runs in a separate process (the network service). This code likely resides within that process.
* **IPC (Inter-Process Communication):** JavaScript in the browser process needs to communicate with the network service to perform network requests. This is done via IPC.
* **No Direct Interaction:** This specific C++ file is a low-level socket implementation. JavaScript doesn't directly call these functions.

Therefore, the relationship is indirect. JavaScript makes a network request, which is eventually translated into calls to functions like `Read` and `Write` in this C++ code *within the network service*. The example of `fetch()` illustrates this flow.

**4. Considering Logical Reasoning and Examples:**

The prompt asks for assumed inputs and outputs. For `Read` and `Write`, the input is primarily the data buffer and its length. The output is an error code or the number of bytes transferred. Let's think about scenarios:

* **`Read` Success:** Input: a buffer and its size. Output: a positive number of bytes read.
* **`Read` Pending:** Input: a buffer and its size. Output: `ERR_IO_PENDING`.
* **`Read` Error:** Input: a buffer and its size. Output: a negative error code (e.g., `ERR_CONNECTION_RESET`).
* **`Write` Success:** Input: a buffer and its size. Output: the number of bytes written (equal to the input size in the success case).
* **`Write` Pending:** Input: a buffer and its size. Output: `ERR_IO_PENDING`.
* **`Write` Error:** Input: a buffer and its size. Output: a negative error code.

**5. Identifying Potential User/Programming Errors:**

Common mistakes when working with asynchronous I/O include:

* **Incorrect Buffer Management:**  The provided examples highlight problems like freeing the buffer prematurely or using an invalid buffer.
* **Forgetting Completion Callbacks:**  Asynchronous operations require callbacks. Not handling them correctly leads to errors or lost data.
* **Race Conditions:**  Without proper synchronization, data corruption can occur if multiple threads access the socket.
* **Incorrect Usage of Completion Ports:** Misunderstanding the completion port model can lead to deadlocks or other issues.

**6. Tracing User Actions (Debugging Clues):**

The request asks how a user action leads to this code. The key is to trace the network request flow:

1. **User Action:**  A user types a URL, clicks a link, or a webpage makes an XMLHttpRequest/fetch request.
2. **Browser Process:** The browser's rendering engine or JavaScript interpreter initiates the network request.
3. **Network Service (IPC):** The browser process communicates the request details to the network service via IPC.
4. **Request Handling:** The network service receives the request and determines that a TCP connection is needed.
5. **Socket Creation:**  The network service creates a `TcpSocketIoCompletionPortWin` object (or a similar socket implementation).
6. **Connection Establishment:** If a new connection is needed, the `Connect` method is called, eventually leading to `WSAConnect` and the connection handling logic in `CoreImpl`.
7. **Data Transfer:** When data needs to be sent or received, the `Write` or `Read` methods of `TcpSocketIoCompletionPortWin` are called.

**7. Structuring the Answer:**

Finally, the information needs to be presented clearly and logically, addressing each part of the original request:

* **Functionality Summary:** Start with a concise overview of the file's purpose.
* **Detailed Functionality:** Explain the key classes and methods, their roles, and how they work together.
* **JavaScript Relationship:** Clearly explain the indirect relationship through the network service and IPC, providing an example like `fetch()`.
* **Logical Reasoning (Input/Output):** Provide concrete examples of inputs and expected outputs for `Read` and `Write` in different scenarios.
* **User/Programming Errors:** List common pitfalls with asynchronous socket programming, illustrated with examples.
* **User Action Trace (Debugging):** Describe the step-by-step process from a user action to the execution of this code, emphasizing the role of the network service and IPC.

By following these steps, we can systematically analyze the code and construct a comprehensive answer that addresses all aspects of the request.
这个文件 `net/socket/tcp_socket_io_completion_port_win.cc` 是 Chromium 网络栈中关于 **TCP socket 在 Windows 平台使用 I/O 完成端口 (I/O Completion Ports, IOCP)** 的实现。 它的主要功能是提供一种高效的方式来处理异步的 TCP socket 的读写操作。

以下是它的详细功能点：

**核心功能:**

1. **异步 I/O 操作:**  该文件实现了 TCP socket 的异步读取 (`Read`) 和写入 (`Write`) 操作。  这意味着当调用 `Read` 或 `Write` 时，函数通常会立即返回 `ERR_IO_PENDING`，表示操作正在后台进行，当操作完成时会通过 I/O 完成端口通知。

2. **I/O 完成端口 (IOCP) 集成:**  它利用 Windows 的 I/O 完成端口机制来管理异步 I/O 操作。  IOCP 允许线程高效地等待多个 socket 上的 I/O 事件，避免了传统的多线程轮询或事件通知的开销。

3. **`CoreImpl` 类:**  定义了一个内部类 `CoreImpl`，它负责处理与 Windows 底层 I/O 操作的交互，包括：
    * 关联 socket 到 IOCP。
    * 监听连接事件。
    * 处理 I/O 完成事件 (`OnIOCompleted`)。
    * 管理连接事件的等待和通知。

4. **`IOContext` 结构体:**  定义了一个结构体 `IOContext`，用于存储每个异步 I/O 操作的上下文信息，例如：
    * 关联的 `CoreImpl` 对象。
    * 使用的缓冲区 (`IOBuffer`)。
    * 缓冲区长度。
    * 完成时调用的方法 (`completion_method`)。
    * 完成回调 (`completion_callback`)。

5. **`EnsureOverlappedIOInitialized` 函数:**  负责确保 socket 已经注册到 I/O 完成端口，并尝试启用 `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS` 优化。

6. **`FILE_SKIP_COMPLETION_PORT_ON_SUCCESS` 优化:**  尝试在 socket 上设置 `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS` 标志。 如果设置成功，当一个 I/O 操作立即完成时（例如，数据已经到达），系统可以跳过将通知放入完成端口的步骤，直接返回结果，从而减少开销。

7. **连接处理:**  通过 `GetConnectEvent` 和 `WatchForConnect` 方法以及 `connect_watcher_` 来异步监听 socket 的连接完成事件。

8. **错误处理:**  使用 `MapSystemError` 将 Windows 的错误码转换为 Chromium 的网络错误码。

9. **NetLog 集成:**  使用 `net_log_` 记录 socket 的事件和错误，用于调试和性能分析。

**与 JavaScript 的关系:**

该 C++ 代码本身不直接与 JavaScript 代码交互。 然而，它是 Chromium 网络栈的一部分，而网络栈负责处理浏览器中 JavaScript 发起的网络请求。

当 JavaScript 代码使用诸如 `fetch()` API 或 `XMLHttpRequest` 对象发起网络请求时，Chromium 浏览器会将这些请求传递给其网络服务进程。  在网络服务进程中，如果需要建立 TCP 连接，并且是在 Windows 平台上，那么最终可能会使用到 `TcpSocketIoCompletionPortWin` 来处理底层的 socket 操作。

**举例说明:**

假设 JavaScript 代码发起一个 `fetch()` 请求：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

1. **JavaScript 发起请求:**  JavaScript 代码调用 `fetch()`。
2. **浏览器进程处理:** 浏览器进程的网络模块接收到请求。
3. **传递到网络服务:** 浏览器进程通过 IPC (Inter-Process Communication) 将请求发送到网络服务进程。
4. **网络服务处理:** 网络服务进程解析请求，确定需要建立到 `example.com` 的 TCP 连接。
5. **Socket 创建:**  在 Windows 平台上，网络服务进程可能会创建一个 `TcpSocketIoCompletionPortWin` 对象来处理这个连接。
6. **连接和数据传输:** `TcpSocketIoCompletionPortWin` 使用 Windows 的 socket API 和 I/O 完成端口来建立连接和传输数据。  当需要读取 `data.json` 的内容时，会调用 `Read` 方法，该方法会异步地等待数据到达。
7. **完成通知:**  当数据到达时，Windows 会通过 I/O 完成端口通知网络服务进程。
8. **回调执行:**  `OnIOCompleted` 方法会被调用，处理接收到的数据，并将数据传递回网络栈的上层。
9. **响应返回:**  最终，数据会通过 IPC 传递回浏览器进程，`fetch()` API 的 promise 会 resolve，JavaScript 的 `.then()` 回调函数会被执行。

**逻辑推理 (假设输入与输出):**

**假设 `Read` 函数被调用：**

* **假设输入:**
    * `buf`: 一个指向 `IOBuffer` 的指针，用于存储接收到的数据。
    * `buf_len`:  希望读取的数据的长度。
    * `callback`: 一个在读取操作完成后调用的回调函数。
* **可能输出:**
    * `net::ERR_IO_PENDING`:  如果读取操作正在进行中，尚未完成。
    * 正数 (例如 `1024`): 如果读取操作立即完成，表示成功读取的字节数。
    * 负数 (例如 `net::ERR_CONNECTION_RESET`): 如果读取过程中发生错误。

**假设 `Write` 函数被调用：**

* **假设输入:**
    * `buf`: 一个指向 `IOBuffer` 的指针，包含要发送的数据。
    * `buf_len`: 要发送的数据的长度。
    * `callback`: 一个在写入操作完成后调用的回调函数。
    * `traffic_annotation`:  网络流量注解信息。
* **可能输出:**
    * `net::ERR_IO_PENDING`: 如果写入操作正在进行中，尚未完成。
    * 正数 (例如 `512`): 如果写入操作立即完成，表示成功发送的字节数。
    * 负数 (例如 `net::ERR_CONNECTION_REFUSED`): 如果写入过程中发生错误。

**用户或编程常见的使用错误:**

1. **在回调函数完成之前释放 `IOBuffer`:**  异步操作正在使用 `IOBuffer`，如果在操作完成之前释放它，会导致内存访问错误。
   ```c++
   void MyReadFunction(TcpSocketIoCompletionPortWin* socket) {
     scoped_refptr<IOBuffer> buffer = base::MakeRefCounted<IOBuffer>(1024);
     socket->Read(buffer.get(), 1024, base::BindOnce(&MyReadCallback));
     // 错误：在这里 buffer 可能会超出作用域，而读取操作可能还没完成。
   }

   void MyReadCallback(int result) {
     // ... 处理读取结果 ...
   }
   ```
   **正确做法:** 确保 `IOBuffer` 的生命周期足够长，通常通过在回调函数中处理完数据后再释放。 使用 `scoped_refptr` 可以方便地管理引用计数。

2. **忘记处理 `ERR_IO_PENDING`:**  异步操作通常会返回 `ERR_IO_PENDING`，表示操作正在后台进行。 程序员必须理解这一点，并在回调函数中处理操作结果，而不是假设操作会立即完成。

3. **在错误的线程调用 socket 方法:**  `TcpSocketIoCompletionPortWin` 的方法通常需要在特定的线程上调用（例如，I/O 线程）。  在错误的线程调用可能导致竞争条件或其他不可预测的行为。

4. **错误地使用完成回调:**  完成回调的签名必须与 `CompletionOnceCallback` 兼容。 错误的参数类型或数量会导致编译或运行时错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中输入 URL 并按下回车:**  这是一个最常见的触发网络请求的操作。
2. **浏览器解析 URL:** 浏览器解析输入的 URL，获取主机名和端口号。
3. **DNS 查询 (如果需要):** 浏览器需要将主机名解析为 IP 地址。这可能涉及 DNS 查询。
4. **建立 TCP 连接:**  一旦获取到 IP 地址，浏览器会尝试与服务器建立 TCP 连接。  在 Windows 平台上，这可能会涉及到创建 `TcpSocketIoCompletionPortWin` 对象。
5. **`Create()` 方法调用:**  `TcpSocketIoCompletionPortWin` 的 `Create()` 方法会被调用来创建底层的 socket。
6. **`Connect()` 方法调用:**  `Connect()` 方法会被调用来尝试建立连接。  这会触发底层的 `WSAConnect()` 调用，并使用 I/O 完成端口来异步等待连接建立完成。
7. **数据传输 (例如，加载网页资源):**  一旦连接建立，当浏览器请求网页的 HTML、CSS、JavaScript 或其他资源时，会调用 `Read()` 和 `Write()` 方法来发送 HTTP 请求和接收 HTTP 响应。
8. **I/O 完成端口事件:**  当网络数据到达或发送完成时，Windows 会将一个完成事件放入与 socket 关联的 I/O 完成端口。
9. **I/O 线程处理:**  Chromium 的 I/O 线程会监听 I/O 完成端口，并调用 `CoreImpl::OnIOCompleted()` 来处理完成的 I/O 操作。
10. **回调执行:**  在 `OnIOCompleted()` 中，会调用之前传递给 `Read()` 或 `Write()` 的回调函数，通知上层网络栈操作已完成，并传递结果（例如，接收到的数据或错误信息）。

**调试线索:**

* **NetLog:**  启用 Chromium 的 NetLog 功能 (可以通过 `chrome://net-export/` 或命令行参数) 可以记录详细的网络事件，包括 socket 的创建、连接、读写操作及其结果。 这可以帮助追踪用户操作如何触发了特定的 socket 操作。
* **断点调试:**  在 `TcpSocketIoCompletionPortWin.cc` 的关键函数（例如 `Read`, `Write`, `OnIOCompleted`) 设置断点，可以观察代码的执行流程和变量的值，以理解用户操作如何导致这些代码被执行。
* **Windows Performance Analyzer (WPA) 或其他性能分析工具:**  可以使用这些工具来分析系统调用和线程活动，查看 I/O 完成端口的使用情况，以及与 socket 相关的系统调用（例如 `WSARecv`, `WSASend`）。
* **抓包工具 (如 Wireshark):**  抓取网络数据包可以验证浏览器发送和接收的数据是否符合预期，以及排查网络层面的问题。

通过结合这些调试方法，可以更深入地了解用户操作与 `TcpSocketIoCompletionPortWin.cc` 代码执行之间的关系，并定位潜在的问题。

### 提示词
```
这是目录为net/socket/tcp_socket_io_completion_port_win.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/tcp_socket_io_completion_port_win.h"

#include <functional>
#include <utility>

#include "base/dcheck_is_on.h"
#include "base/memory/scoped_refptr.h"
#include "base/message_loop/message_pump_win.h"
#include "base/metrics/histogram_functions.h"
#include "base/notreached.h"
#include "base/numerics/checked_math.h"
#include "base/numerics/safe_conversions.h"
#include "base/rand_util.h"
#include "base/task/current_thread.h"
#include "base/threading/thread_checker.h"
#include "base/win/object_watcher.h"
#include "base/win/scoped_handle.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/log/net_log.h"
#include "net/socket/socket_net_log_params.h"

namespace net {

namespace {

// Outcome of setting FILE_SKIP_COMPLETION_PORT_ON_SUCCESS on a socket. Used in
// UMA histograms so should not be renumbered.
enum class SkipCompletionPortOnSuccessOutcome {
  kNotSupported,
  kSetFileCompletionNotificationModesFailed,
  kSuccess,
  kMaxValue = kSuccess
};

bool g_skip_completion_port_on_success_enabled = true;

// Returns true if all available transport protocols return Installable File
// System (IFS) handles. Returns false on error or if any available transport
// protocol doesn't return IFS handles. An IFS handle is required to use
// FILE_SKIP_COMPLETION_PORT_ON_SUCCESS. See
// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfilecompletionnotificationmodes#:~:text=FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
bool SkipCompletionPortOnSuccessIsSupported() {
  size_t info_count = 1;

  for (int num_attempts = 0; num_attempts < 3; ++num_attempts) {
    auto buffer = base::HeapArray<WSAPROTOCOL_INFOW>::Uninit(info_count);
    DWORD buffer_length =
        base::checked_cast<DWORD>(buffer.as_span().size_bytes());
    int result = ::WSAEnumProtocolsW(/*lpiProtocols=*/nullptr, buffer.data(),
                                     &buffer_length);
    if (result == SOCKET_ERROR) {
      if (::WSAGetLastError() == WSAENOBUFS) {
        // Insufficient buffer length: Try again with an updated `info_count`
        // computed from the requested `buffer_length`.
        info_count =
            base::CheckDiv(
                base::CheckAdd(buffer_length, sizeof(WSAPROTOCOL_INFOW) - 1),
                sizeof(WSAPROTOCOL_INFOW))
                .ValueOrDie();
        continue;
      }

      // Protocol retrieval error.
      return false;
    }

    // Return true iff all protocols return IFS handles.
    return base::ranges::all_of(
        buffer.subspan(0, result), [](const WSAPROTOCOL_INFOW& protocol_info) {
          return protocol_info.dwServiceFlags1 & XP1_IFS_HANDLES;
        });
  }

  // Too many protocol retrieval attempts failed due to insufficient buffer
  // length.
  return false;
}

// Returns true for 1/1000 calls, indicating if a subsampled histogram should be
// recorded.
bool ShouldRecordSubsampledHistogram() {
  // Not using `base::MetricsSubSampler` because it's not thread-safe sockets
  // could be used from multiple threads.
  static std::atomic<uint64_t> counter = base::RandUint64();
  // Relaxed memory order since there is no dependent memory access.
  uint64_t val = counter.fetch_add(1, std::memory_order_relaxed);
  return val % 1000 == 0;
}

class WSAEventHandleTraits {
 public:
  using Handle = WSAEVENT;

  WSAEventHandleTraits() = delete;
  WSAEventHandleTraits(const WSAEventHandleTraits&) = delete;
  WSAEventHandleTraits& operator=(const WSAEventHandleTraits&) = delete;

  static bool CloseHandle(Handle handle) {
    return ::WSACloseEvent(handle) != FALSE;
  }
  static bool IsHandleValid(Handle handle) {
    return handle != WSA_INVALID_EVENT;
  }
  static Handle NullHandle() { return WSA_INVALID_EVENT; }
};

// "Windows Sockets 2 event objects are system objects in Windows environments"
// so `base::win::VerifierTraits` verifier can be used.
// Source:
// https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsacreateevent
#if DCHECK_IS_ON()
using VerifierTraits = base::win::VerifierTraits;
#else
using VerifierTraits = base::win::DummyVerifierTraits;
#endif
using ScopedWSAEventHandle =
    base::win::GenericScopedHandle<WSAEventHandleTraits, VerifierTraits>;

}  // namespace

class TcpSocketIoCompletionPortWin::CoreImpl
    : public TCPSocketWin::Core,
      public base::win::ObjectWatcher::Delegate,
      public base::MessagePumpForIO::IOHandler {
 public:
  // Context for an overlapped I/O operation.
  struct IOContext : public base::MessagePumpForIO::IOContext {
    using CompletionMethod =
        int (TcpSocketIoCompletionPortWin::*)(DWORD bytes_transferred,
                                              DWORD error,
                                              scoped_refptr<IOBuffer> buffer,
                                              int buffer_length);

    explicit IOContext(scoped_refptr<CoreImpl> core);

    // Keeps the `CoreImpl` alive until the operation is complete. Required to
    // handle `base::MessagePumpForIO::IOHandler::OnIOCompleted`.
    const scoped_refptr<CoreImpl> core_keep_alive;

    // Buffer used for the operation.
    scoped_refptr<IOBuffer> buffer;
    int buffer_length = 0;

    // Method to call upon completion of the operation. The return value is
    // passed to `completion_callback`.
    CompletionMethod completion_method = nullptr;

    // External callback to invoke upon completion of the operation.
    CompletionOnceCallback completion_callback;
  };

  explicit CoreImpl(TcpSocketIoCompletionPortWin* socket);

  CoreImpl(const CoreImpl&) = delete;
  CoreImpl& operator=(const CoreImpl&) = delete;

  // TCPSocketWin::Core:
  void Detach() override;
  HANDLE GetConnectEvent() override;
  void WatchForConnect() override;

 private:
  ~CoreImpl() override;

  // base::win::ObjectWatcher::Delegate:
  void OnObjectSignaled(HANDLE object) override;

  // base::MessagePumpForIO::IOHandler:
  void OnIOCompleted(base::MessagePumpForIO::IOContext* context,
                     DWORD bytes_transferred,
                     DWORD error) override;

  // Stops watching and closes the connect event, if valid.
  void StopWatchingAndCloseConnectEvent();

  // Owning socket.
  raw_ptr<TcpSocketIoCompletionPortWin> socket_;

  // Event to watch for connect completion.
  ScopedWSAEventHandle connect_event_;

  // Watcher for `connect_event_`.
  base::win::ObjectWatcher connect_watcher_;
};

TcpSocketIoCompletionPortWin::DisableSkipCompletionPortOnSuccessForTesting::
    DisableSkipCompletionPortOnSuccessForTesting() {
  CHECK(g_skip_completion_port_on_success_enabled);
  g_skip_completion_port_on_success_enabled = false;
}

TcpSocketIoCompletionPortWin::DisableSkipCompletionPortOnSuccessForTesting::
    ~DisableSkipCompletionPortOnSuccessForTesting() {
  CHECK(!g_skip_completion_port_on_success_enabled);
  g_skip_completion_port_on_success_enabled = true;
}

TcpSocketIoCompletionPortWin::TcpSocketIoCompletionPortWin(
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    NetLog* net_log,
    const NetLogSource& source)
    : TCPSocketWin(std::move(socket_performance_watcher), net_log, source) {}

TcpSocketIoCompletionPortWin::TcpSocketIoCompletionPortWin(
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    NetLogWithSource net_log_source)
    : TCPSocketWin(std::move(socket_performance_watcher), net_log_source) {}

TcpSocketIoCompletionPortWin::~TcpSocketIoCompletionPortWin() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  Close();
}

int TcpSocketIoCompletionPortWin::Read(IOBuffer* buf,
                                       int buf_len,
                                       CompletionOnceCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  CHECK_NE(socket_, INVALID_SOCKET);

  if (!EnsureOverlappedIOInitialized()) {
    return net::ERR_FAILED;
  }

  CoreImpl& core = GetCoreImpl();

  WSABUF read_buffer;
  read_buffer.len = buf_len;
  read_buffer.buf = buf->data();
  DWORD flags = 0;
  DWORD bytes_read = 0;
  auto context = std::make_unique<CoreImpl::IOContext>(&core);

  const auto rv = ::WSARecv(socket_, &read_buffer, /*dwBufferCount=*/1,
                            /*lpNumberOfBytesRecvd=*/&bytes_read, &flags,
                            &context->overlapped,
                            /*lpCompletionRoutine=*/nullptr);

  // "Citations" below are from
  // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsarecv

  if (rv == 0) {
    // When "the receive operation has completed immediately, WSARecv returns
    // zero" and "completion routine will have already been scheduled", unless
    // the option to skip completion port on success is set.

    if (skip_completion_port_on_success_) {
      // Free `context` here since it will no longer be accessed.
      context.reset();
    } else {
      // Release `context` so that `OnIOCompleted()` can take ownership, but
      // don't set any member since completion is already handled.
      context.release();
    }

    ++num_pending_reads_;
    return DidCompleteRead(bytes_read, ERROR_SUCCESS, buf, buf_len);
  }

  CHECK_EQ(rv, SOCKET_ERROR);
  const int wsa_error = ::WSAGetLastError();
  if (wsa_error == WSA_IO_PENDING) {
    // "The error code WSA_IO_PENDING indicates that the overlapped operation
    // has been successfully initiated and that completion will be indicated at
    // a later time." Set members of `context` for proper completion handling
    // and release it so that `OnIOCompleted()` can take ownership.
    context->buffer = buf;
    context->buffer_length = buf_len;
    context->completion_callback = std::move(callback);
    context->completion_method = &TcpSocketIoCompletionPortWin::DidCompleteRead;
    context.release();

    ++num_pending_reads_;
    return ERR_IO_PENDING;
  }

  // "Any other error code [than WSA_IO_PENDING] indicates that [...] no
  // completion indication will occur", so free `context` here.
  context.reset();

  int net_error = MapSystemError(wsa_error);
  NetLogSocketError(net_log_, NetLogEventType::SOCKET_READ_ERROR, net_error,
                    wsa_error);
  return net_error;
}

int TcpSocketIoCompletionPortWin::ReadIfReady(IOBuffer* buf,
                                              int buf_len,
                                              CompletionOnceCallback callback) {
  return ERR_READ_IF_READY_NOT_IMPLEMENTED;
}

int TcpSocketIoCompletionPortWin::CancelReadIfReady() {
  NOTREACHED();
}

int TcpSocketIoCompletionPortWin::Write(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (!EnsureOverlappedIOInitialized()) {
    return net::ERR_FAILED;
  }

  CoreImpl& core = GetCoreImpl();

  WSABUF write_buffer;
  write_buffer.len = buf_len;
  write_buffer.buf = buf->data();
  DWORD bytes_sent = 0;
  auto context = std::make_unique<CoreImpl::IOContext>(&core);

  const int rv =
      ::WSASend(socket_, &write_buffer, /*dwBufferCount=*/1, &bytes_sent,
                /*dwFlags=*/0, &context->overlapped,
                /*lpCompletionRoutine=*/nullptr);

  // "Citations" below are from
  // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasend

  if (rv == 0) {
    // When "the send operation has completed immediately, WSASend returns zero"
    // and "completion routine will have already been scheduled", unless the
    // option to skip completion port on success is set.

    if (skip_completion_port_on_success_) {
      // Free `context` here since it will no longer be accessed.
      context.reset();
    } else {
      // Release `context` so that `OnIOCompleted()` can take ownership, but
      // don't set any member since completion is already handled.
      context.release();
    }

    return DidCompleteWrite(bytes_sent, ERROR_SUCCESS, buf, buf_len);
  }

  CHECK_EQ(rv, SOCKET_ERROR);
  const int wsa_error = ::WSAGetLastError();
  if (wsa_error == WSA_IO_PENDING) {
    // "The error code WSA_IO_PENDING indicates that the overlapped operation
    // has been successfully initiated and that completion will be indicated at
    // a later time." Set members of `context` for proper completion handling
    // and release it so that `OnIOCompleted()` can take ownership.
    context->buffer = buf;
    context->buffer_length = buf_len;
    context->completion_callback = std::move(callback);
    context->completion_method =
        &TcpSocketIoCompletionPortWin::DidCompleteWrite;
    context.release();

    return ERR_IO_PENDING;
  }

  // "Any other error code [than WSA_IO_PENDING] indicates that [...] no
  // completion indication will occur", so free `context` here.
  context.reset();

  int net_error = MapSystemError(wsa_error);
  NetLogSocketError(net_log_, NetLogEventType::SOCKET_WRITE_ERROR, net_error,
                    wsa_error);
  return net_error;
}

scoped_refptr<TCPSocketWin::Core> TcpSocketIoCompletionPortWin::CreateCore() {
  return base::MakeRefCounted<CoreImpl>(this);
}

bool TcpSocketIoCompletionPortWin::HasPendingRead() const {
  return num_pending_reads_ != 0;
}

void TcpSocketIoCompletionPortWin::OnClosed() {}

bool TcpSocketIoCompletionPortWin::EnsureOverlappedIOInitialized() {
  CHECK_NE(socket_, INVALID_SOCKET);
  if (registered_as_io_handler_) {
    return true;
  }

  // Register the `CoreImpl` as an I/O handler for the socket.
  CoreImpl& core = GetCoreImpl();
  registered_as_io_handler_ = base::CurrentIOThread::Get()->RegisterIOHandler(
      reinterpret_cast<HANDLE>(socket_), &core);
  if (!registered_as_io_handler_) {
    return false;
  }

  // Activate an option to skip the completion port when an operation completes
  // immediately.
  static const bool skip_completion_port_on_success_is_supported =
      SkipCompletionPortOnSuccessIsSupported();
  if (g_skip_completion_port_on_success_enabled &&
      skip_completion_port_on_success_is_supported) {
    BOOL result = ::SetFileCompletionNotificationModes(
        reinterpret_cast<HANDLE>(socket_),
        FILE_SKIP_COMPLETION_PORT_ON_SUCCESS);
    skip_completion_port_on_success_ = (result != 0);
  }

  // Report the outcome of activating an option to skip the completion port when
  // an operation completes immediately to UMA. Subsampled for efficiency.
  if (ShouldRecordSubsampledHistogram()) {
    SkipCompletionPortOnSuccessOutcome outcome;
    if (skip_completion_port_on_success_) {
      outcome = SkipCompletionPortOnSuccessOutcome::kSuccess;
    } else if (skip_completion_port_on_success_is_supported) {
      outcome = SkipCompletionPortOnSuccessOutcome::
          kSetFileCompletionNotificationModesFailed;
    } else {
      outcome = SkipCompletionPortOnSuccessOutcome::kNotSupported;
    }

    base::UmaHistogramEnumeration(
        "Net.Socket.SkipCompletionPortOnSuccessOutcome", outcome);
  }

  return true;
}

int TcpSocketIoCompletionPortWin::DidCompleteRead(
    DWORD bytes_transferred,
    DWORD error,
    scoped_refptr<IOBuffer> buffer,
    int buffer_length) {
  CHECK_GT(num_pending_reads_, 0);
  --num_pending_reads_;

  if (error == ERROR_SUCCESS) {
    // `bytes_transferred` should be <= `buffer_length` so cast should succeed.
    const int rv = base::checked_cast<int>(bytes_transferred);
    net_log_.AddByteTransferEvent(NetLogEventType::SOCKET_BYTES_RECEIVED, rv,
                                  buffer->data());
    return rv;
  }

  const int rv = MapSystemError(error);
  CHECK_NE(rv, ERR_IO_PENDING);
  NetLogSocketError(net_log_, NetLogEventType::SOCKET_READ_ERROR, rv, error);
  return rv;
}

int TcpSocketIoCompletionPortWin::DidCompleteWrite(
    DWORD bytes_transferred,
    DWORD error,
    scoped_refptr<IOBuffer> buffer,
    int buffer_length) {
  if (error == ERROR_SUCCESS) {
    // `bytes_transferred` should be <= `buffer_length` so cast should succeed.
    const int rv = base::checked_cast<int>(bytes_transferred);
    if (rv > buffer_length) {
      // It seems that some winsock interceptors report that more was written
      // than was available. Treat this as an error.  https://crbug.com/27870
      LOG(ERROR) << "Detected broken LSP: Asked to write " << buffer_length
                 << " bytes, but " << rv << " bytes reported.";
      return ERR_WINSOCK_UNEXPECTED_WRITTEN_BYTES;
    }

    net_log_.AddByteTransferEvent(NetLogEventType::SOCKET_BYTES_SENT, rv,
                                  buffer->data());
    return rv;
  }

  const int rv = MapSystemError(error);
  CHECK_NE(rv, ERR_IO_PENDING);
  NetLogSocketError(net_log_, NetLogEventType::SOCKET_WRITE_ERROR, rv, error);
  return rv;
}

TcpSocketIoCompletionPortWin::CoreImpl&
TcpSocketIoCompletionPortWin::GetCoreImpl() {
  return CHECK_DEREF(static_cast<CoreImpl*>(core_.get()));
}

TcpSocketIoCompletionPortWin::CoreImpl::IOContext::IOContext(
    scoped_refptr<CoreImpl> core)
    : core_keep_alive(std::move(core)) {}

TcpSocketIoCompletionPortWin::CoreImpl::CoreImpl(
    TcpSocketIoCompletionPortWin* socket)
    : base::MessagePumpForIO::IOHandler(FROM_HERE), socket_(socket) {}

void TcpSocketIoCompletionPortWin::CoreImpl::Detach() {
  StopWatchingAndCloseConnectEvent();

  // It is not possible to stop ongoing read or write operations. Clear
  // `socket_` so that the completion handler doesn't invoke completion methods.
  socket_ = nullptr;
}

HANDLE TcpSocketIoCompletionPortWin::CoreImpl::GetConnectEvent() {
  if (!connect_event_.IsValid()) {
    // Lazy-initialize the event.
    connect_event_.Set(::WSACreateEvent());
    ::WSAEventSelect(socket_->socket_, connect_event_.get(), FD_CONNECT);
  }
  return connect_event_.get();
}

void TcpSocketIoCompletionPortWin::CoreImpl::WatchForConnect() {
  CHECK(connect_event_.IsValid());
  connect_watcher_.StartWatchingOnce(connect_event_.get(), this);
}

TcpSocketIoCompletionPortWin::CoreImpl::~CoreImpl() {
  CHECK(!socket_);
}

void TcpSocketIoCompletionPortWin::CoreImpl::OnObjectSignaled(HANDLE object) {
  CHECK_EQ(object, connect_event_.get());
  CHECK(socket_);
  CHECK(!!socket_->connect_callback_);

  // Stop watching and close the event since it's no longer needed.
  StopWatchingAndCloseConnectEvent();

  socket_->DidCompleteConnect();
}

void TcpSocketIoCompletionPortWin::CoreImpl::OnIOCompleted(
    base::MessagePumpForIO::IOContext* context,
    DWORD bytes_transferred,
    DWORD error) {
  // Take ownership of `context`, which was released in `Read` or `Write`. The
  // cast is safe because all overlapped I/O operations handled by this are
  // issued with the OVERLAPPED member of an `IOContext` object.
  std::unique_ptr<IOContext> derived_context(static_cast<IOContext*>(context));

  if (socket_ && derived_context->completion_method) {
    const int rv = std::invoke(
        derived_context->completion_method, socket_, bytes_transferred, error,
        std::move(derived_context->buffer), derived_context->buffer_length);
    std::move(derived_context->completion_callback).Run(rv);
  }
}

void TcpSocketIoCompletionPortWin::CoreImpl::
    StopWatchingAndCloseConnectEvent() {
  if (connect_event_.IsValid()) {
    connect_watcher_.StopWatching();
    connect_event_.Close();
  }
}

}  // namespace net
```