Response:
My thought process for analyzing the C++ code and fulfilling the request goes like this:

1. **Understand the Goal:** The request is to analyze a C++ unit test file for network sockets in Chromium, focusing on its functionality, relationship to JavaScript (if any), logical inferences, error handling, debugging, and a summary of its purpose (for part 1).

2. **Initial Skim for Keywords:** I quickly scan the code for important keywords and structures:
    * `#include`:  Indicates dependencies (base, net, testing). This tells me it's definitely network-related and uses standard testing frameworks.
    * `namespace net`: Confirms it's within the Chromium networking stack.
    * `TEST_F`:  Highlights the presence of Google Test test cases.
    * `MockRead`, `MockWrite`:  Suggests the use of mock objects for simulating socket behavior.
    * `SequencedSocketData`:  Appears to be the core class being tested.
    * `StreamSocket`: The interface being used for socket operations.
    * `Read`, `Write`, `Connect`: Standard socket methods.
    * `ASYNC`, `SYNCHRONOUS`: Indicate different modes of operation for the mock socket.
    * `CompletionOnceCallback`:  Suggests asynchronous operations with callbacks.
    * `ReentrantHelper`: A helper class for testing reentrant calls.

3. **Identify the Core Functionality:**  The presence of `MockRead` and `MockWrite` arrays within the test cases strongly suggests that `SequencedSocketData` is designed to control the sequence of read and write operations on a socket during testing. It allows simulating various network scenarios by defining expected data to be read and written, and whether these operations should be synchronous or asynchronous.

4. **Analyze Test Case Structure:** I examine the structure of the `TEST_F` macros. Each test typically:
    * Defines `MockRead` and/or `MockWrite` arrays to set up the simulated socket behavior.
    * Initializes the test environment using `Initialize(reads, writes)`. This likely creates a `SequencedSocketData` object and a mock socket.
    * Calls `AssertSyncReadEquals`, `AssertAsyncReadEquals`, `AssertSyncWriteEquals`, `AssertAsyncWriteEquals`, or custom helper functions to perform and verify socket operations.

5. **Look for JavaScript Connections:** I search for any direct interaction with JavaScript. The code primarily deals with low-level network concepts and C++ constructs. There's no direct JavaScript code present. However, I realize that this testing framework is used to verify the behavior of network components that *are* ultimately used by the browser, including the JavaScript environment. So the connection is *indirect*.

6. **Infer Logical Reasoning and Input/Output:**  The test cases demonstrate logical reasoning. For example, testing "MultipleSyncReads" checks that multiple synchronous reads happen in the defined order with the correct data. The `MockRead` and `MockWrite` arrays serve as the *input*, defining the expected socket behavior. The assertions (`ASSERT_EQ`, `ASSERT_TRUE`, `EXPECT_NONFATAL_FAILURE`) check the *output* of the socket operations against these expectations.

7. **Identify Potential User/Programming Errors:** The tests like "SingleSyncWriteTooSmall" and "SingleSyncWriteTooEarly" specifically target error scenarios. These show how `SequencedSocketData` can help detect mismatches between expected and actual socket interactions, which are common programming errors when dealing with network protocols.

8. **Trace User Operations (Debugging):** I think about how a user action might lead to this code being relevant. A user navigating to a website triggers network requests. These requests go through various layers of the browser's network stack. If there's a bug in how data is read or written to the socket, this unit test framework would be used by developers to isolate and fix the issue. The `SequencedSocketData` helps simulate these low-level socket interactions for debugging purposes.

9. **Summarize the Functionality (Part 1):** Based on the analysis, I synthesize a concise summary of the file's purpose.

10. **Structure the Response:** I organize the findings into the categories requested: functionality, JavaScript relationship, logical inferences, common errors, debugging, and summary. I use examples from the code to illustrate each point.

**(Self-Correction during the process):**

* **Initial thought:** Maybe there's some complex multi-threading interaction being tested. **Correction:** The `ASYNC` and `SYNCHRONOUS` keywords are about controlling the *mock* behavior, not necessarily testing real-world threading complexities directly (though those might be tested in other files).
* **Initial thought:** The JavaScript connection might be more direct. **Correction:** The relationship is through the browser's network stack. JavaScript uses higher-level APIs that eventually rely on the kind of socket functionality being tested here. The connection is architectural, not a direct code linkage within this file.
* **Overly detailed explanation of a single test case.** **Correction:** Focus on the general principles and patterns demonstrated by the tests, rather than exhaustively describing every single test.

By following this thought process, I can systematically analyze the code, extract the relevant information, and address all aspects of the user's request.
好的，这是对提供的 C++ 代码文件 `net/socket/sequenced_socket_data_unittest.cc` 的第一部分进行的功能归纳：

**文件功能归纳:**

`sequenced_socket_data_unittest.cc` 是 Chromium 网络栈中的一个单元测试文件，专门用于测试 `SequencedSocketData` 类的功能。 `SequencedSocketData` 的主要作用是**模拟网络套接字的行为，以便进行可控的、可重复的读写操作测试**。 它允许开发者预先定义一系列期望的读操作（`MockRead`）和写操作（`MockWrite`），以及这些操作是同步的还是异步的。

更具体地说，`SequencedSocketData` 允许测试者：

1. **模拟同步和异步的套接字读操作：**  可以预设在特定时刻返回特定的数据，或者返回 `ERR_IO_PENDING` 来模拟异步操作。
2. **模拟同步和异步的套接字写操作：** 可以验证发送到套接字的数据是否与预期一致。
3. **控制读写操作的顺序：**  通过 `MockRead` 和 `MockWrite` 数组的顺序来定义期望的操作序列。
4. **模拟错误情况：**  可以模拟读写操作返回错误码，例如 `ERR_UNEXPECTED`。
5. **测试在完成回调中进行重入操作：**  通过 `ReentrantHelper` 类和相关的测试用例，验证在读写操作的回调函数中再次发起读写操作时的行为。
6. **测试不同大小的读写缓冲区：**  验证当提供的缓冲区大小与预期的数据大小不一致时的行为。
7. **测试挂起的读操作：**  模拟一个永远不会完成的读操作。

**与 JavaScript 功能的关系：**

虽然这段 C++ 代码本身不包含 JavaScript 代码，但它测试的网络栈组件是 JavaScript 在浏览器环境中进行网络通信的基础。

**举例说明：**

假设一个 JavaScript 应用使用 `fetch API` 发起一个 HTTP 请求。  当这个请求到达浏览器的网络栈时，底层的实现可能会使用类似 `StreamSocket` 的接口进行 TCP 连接和数据传输。 `SequencedSocketData` 提供的测试能力可以用来验证网络栈中处理这个请求的 C++ 代码是否正确地进行了套接字的读写操作。

例如，一个测试用例可能模拟服务器发送 HTTP 响应头和响应体：

```c++
MockRead reads[] = {
    MockRead(ASYNC, "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n", 38, 0),
    MockRead(ASYNC, "Hello, world!", 13, 1),
};
```

这个测试用例会断言，当 JavaScript 发起请求后，底层的 C++ 代码会先异步读取到 HTTP 响应头，然后再异步读取到响应体。

**逻辑推理和假设输入/输出：**

**假设输入：**

* `MockRead reads[] = { MockRead(SYNCHRONOUS, "test", 4, 0) };`
* 用户代码调用 `sock_->Read(buffer, 4, callback)`。

**逻辑推理：**

`SequencedSocketData` 会匹配用户代码的读操作和预设的 `MockRead`。由于 `MockRead` 被设置为 `SYNCHRONOUS`，`sock_->Read` 应该立即返回读取的字节数 (4)，并将 "test" 写入 `buffer`。

**假设输出：**

* `sock_->Read` 的返回值应为 `4`。
* `buffer` 的前 4 个字节应为 "test"。

**用户或编程常见的使用错误：**

1. **顺序错误：**  用户代码期望先发送数据 A，再接收数据 B，但在 `SequencedSocketData` 中 `MockWrite` 和 `MockRead` 的顺序不一致。例如：

   ```c++
   MockWrite writes[] = { MockWrite(SYNCHRONOUS, "A", 1, 0) };
   MockRead reads[] = { MockRead(SYNCHRONOUS, "B", 1, 0) };
   ```

   如果用户代码尝试先读取，`SequencedSocketData` 会因为找不到匹配的 `MockRead` 而可能导致断言失败或返回错误。

2. **数据不匹配：** 用户代码发送或接收的数据与 `MockWrite` 或 `MockRead` 中预设的数据不一致。例如：

   ```c++
   MockWrite writes[] = { MockWrite(SYNCHRONOUS, "expected", 8, 0) };
   // 用户代码实际发送 "actual"
   ```

   `SequencedSocketData` 会检测到发送的数据不匹配，导致测试失败。

3. **缓冲区大小错误：** 用户提供的读缓冲区大小小于 `MockRead` 中预设的数据大小，或者用户尝试写入的数据大小大于 `MockWrite` 中预设的大小。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中执行某些操作：** 例如，点击一个链接，提交一个表单，或者 JavaScript 代码发起一个网络请求（如使用 `fetch` 或 `XMLHttpRequest`）。
2. **浏览器解析用户操作，并决定发起网络请求：**  浏览器会根据 URL、请求方法等信息构建网络请求。
3. **网络请求被传递到浏览器的网络栈：**  网络栈负责处理 DNS 查询、建立 TCP 连接、发送 HTTP 请求、接收 HTTP 响应等。
4. **网络栈中的代码使用套接字 API 进行数据传输：**  底层的 C++ 代码会调用类似 `StreamSocket::Read` 和 `StreamSocket::Write` 的方法与服务器进行通信。
5. **如果网络栈中的代码存在 bug，导致套接字的读写操作不符合预期：**  开发者可能会编写或运行类似于 `sequenced_socket_data_unittest.cc` 的单元测试来复现和调试问题。
6. **在调试过程中，开发者可能会设置断点在 `SequencedSocketData` 或相关的套接字代码中：**  通过查看 `MockRead` 和 `MockWrite` 的配置，以及实际的读写操作，来定位问题所在。

**总结 (第一部分的功能):**

总而言之，`net/socket/sequenced_socket_data_unittest.cc` 的主要功能是提供一个全面的测试框架，用于验证 `SequencedSocketData` 类作为套接字行为模拟器的正确性。 它通过各种同步和异步的读写场景，以及错误情况和重入操作的测试，确保 `SequencedSocketData` 能够可靠地模拟网络套接字的行为，从而帮助开发者测试网络栈中依赖套接字操作的其他组件。

Prompt: 
```
这是目录为net/socket/sequenced_socket_data_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include <memory>
#include <string>

#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/run_loop.h"
#include "net/base/completion_once_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/test_completion_callback.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/socket_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest-spi.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

using net::test::IsError;
using net::test::IsOk;

//-----------------------------------------------------------------------------

namespace net {

namespace {

const char kMsg1[] = "\0hello!\xff";
const int kLen1 = std::size(kMsg1);
const char kMsg2[] = "\0a2345678\0";
const int kLen2 = std::size(kMsg2);
const char kMsg3[] = "bye!";
const int kLen3 = std::size(kMsg3);
const char kMsg4[] = "supercalifragilisticexpialidocious";
const int kLen4 = std::size(kMsg4);

// Helper class for starting the next operation operation reentrantly after the
// previous operation completed asynchronously. When OnIOComplete is called,
// it will first verify that the previous operation behaved as expected. This is
// specified by either SetExpectedRead or SetExpectedWrite. It will then invoke
// a read or write operation specified by SetInvokeRead or SetInvokeWrite.
class ReentrantHelper {
 public:
  explicit ReentrantHelper(StreamSocket* socket) : socket_(socket) {}

  ReentrantHelper(const ReentrantHelper&) = delete;
  ReentrantHelper& operator=(const ReentrantHelper&) = delete;

  // Expect that the previous operation will return |first_len| and will fill
  // |first_read_data_| with |first_read_data|.
  void SetExpectedRead(const char* first_read_data, int first_len) {
    verify_read_ = true;
    first_read_buf_ = base::MakeRefCounted<IOBufferWithSize>(first_len);
    first_read_data_ = first_read_data;
    first_len_ = first_len;
  }

  // Expect that the previous operation will return |first_len|.
  void SetExpectedWrite(int first_len) {
    verify_read_ = false;
    first_len_ = first_len;
  }

  // After verifying expectations, invoke a read of |read_len| bytes into
  // |read_buf|, notifying |callback| when complete.
  void SetInvokeRead(scoped_refptr<IOBuffer> read_buf,
                     int read_len,
                     int second_rv,
                     CompletionOnceCallback callback) {
    second_read_ = true;
    second_read_buf_ = read_buf;
    second_rv_ = second_rv;
    second_callback_ = std::move(callback);
    second_len_ = read_len;
  }

  // After verifying expectations, invoke a write of |write_len| bytes from
  // |write_data|, notifying |callback| when complete.
  void SetInvokeWrite(const char* write_data,
                      int write_len,
                      int second_rv,
                      CompletionOnceCallback callback) {
    second_read_ = false;
    second_rv_ = second_rv;
    second_write_data_ = write_data;
    second_callback_ = std::move(callback);
    second_len_ = write_len;
  }

  // Returns the OnIOComplete callback for this helper.
  CompletionOnceCallback callback() {
    return base::BindOnce(&ReentrantHelper::OnIOComplete,
                          base::Unretained(this));
  }

  // Retuns the buffer where data is expected to have been written,
  // when checked by SetExpectRead()
  scoped_refptr<IOBuffer> read_buf() { return first_read_buf_; }

 private:
  void OnIOComplete(int rv) {
    CHECK_NE(-1, first_len_) << "Expectation not set.";
    CHECK_NE(-1, second_len_) << "Invocation not set.";
    ASSERT_EQ(first_len_, rv);
    if (verify_read_) {
      ASSERT_EQ(std::string(first_read_data_, first_len_),
                std::string(first_read_buf_->data(), rv));
    }

    if (second_read_) {
      ASSERT_EQ(second_rv_, socket_->Read(second_read_buf_.get(), second_len_,
                                          std::move(second_callback_)));
    } else {
      auto write_buf = base::MakeRefCounted<IOBufferWithSize>(second_len_);
      memcpy(write_buf->data(), second_write_data_, second_len_);
      ASSERT_EQ(second_rv_, socket_->Write(write_buf.get(), second_len_,
                                           std::move(second_callback_),
                                           TRAFFIC_ANNOTATION_FOR_TESTS));
    }
  }

  raw_ptr<StreamSocket> socket_;

  bool verify_read_ = false;
  scoped_refptr<IOBuffer> first_read_buf_;
  const char* first_read_data_ = nullptr;
  int first_len_ = -1;

  CompletionOnceCallback second_callback_;
  bool second_read_ = false;
  int second_rv_;
  scoped_refptr<IOBuffer> second_read_buf_;
  const char* second_write_data_ = nullptr;
  int second_len_ = -1;
};

class SequencedSocketDataTest : public TestWithTaskEnvironment {
 public:
  SequencedSocketDataTest();
  ~SequencedSocketDataTest() override;

  // This method is used as the completion callback for an async read
  // operation and when invoked, it verifies that the correct data was read,
  // then reads from the socket and verifies that that it returns the correct
  // value.
  void ReentrantReadCallback(const char* data,
                             int len1,
                             int len2,
                             int expected_rv2,
                             int rv);

  // This method is used at the completion callback for an async operation.
  // When executed, verifies that |rv| equals |expected_rv| and then
  // attempts an aync read from the socket into |read_buf_| (initialized
  // to |read_buf_len|) using |callback|.
  void ReentrantAsyncReadCallback(int len1, int len2, int rv);

  // This method is used as the completion callback for an async write
  // operation and when invoked, it verifies that the write returned correctly,
  // then
  // attempts to write to the socket and verifies that that it returns the
  // correct value.
  void ReentrantWriteCallback(int expected_rv1,
                              const char* data,
                              int len,
                              int expected_rv2,
                              int rv);

  // This method is used at the completion callback for an async operation.
  // When executed, verifies that |rv| equals |expected_rv| and then
  // attempts an aync write of |data| with |callback|
  void ReentrantAsyncWriteCallback(const char* data,
                                   int len,
                                   CompletionOnceCallback callback,
                                   int expected_rv,
                                   int rv);

  // Callback which adds a failure if it's ever called.
  void FailingCompletionCallback(int rv);

 protected:
  void Initialize(base::span<const MockRead> reads,
                  base::span<const MockWrite> writes);

  void AssertSyncReadEquals(const char* data, int len);
  void AssertAsyncReadEquals(const char* data, int len);
  void AssertReadReturns(int len, int rv);
  void AssertReadBufferEquals(const char* data, int len);

  void AssertSyncWriteEquals(const char* data, int len);
  void AssertAsyncWriteEquals(const char* data, int len);
  void AssertWriteReturns(const char* data, int len, int rv);

  bool IsPaused() const;
  void Resume();
  void RunUntilPaused();

  // When a given test completes, data_.at_eof() is expected to
  // match the value specified here. Most test should consume all
  // reads and writes, but some tests verify error handling behavior
  // do not consume all data.
  void set_expect_eof(bool expect_eof) { expect_eof_ = expect_eof; }

  CompletionOnceCallback failing_callback() {
    return base::BindOnce(&SequencedSocketDataTest::FailingCompletionCallback,
                          base::Unretained(this));
  }

  TestCompletionCallback read_callback_;
  scoped_refptr<IOBuffer> read_buf_;
  TestCompletionCallback write_callback_;

  std::unique_ptr<SequencedSocketData> data_;

  MockClientSocketFactory socket_factory_;
  bool expect_eof_ = true;

  std::unique_ptr<StreamSocket> sock_;
};

SequencedSocketDataTest::SequencedSocketDataTest() = default;

SequencedSocketDataTest::~SequencedSocketDataTest() {
  // Make sure no unexpected pending tasks will cause a failure.
  base::RunLoop().RunUntilIdle();
  if (expect_eof_) {
    EXPECT_EQ(expect_eof_, data_->AllReadDataConsumed());
    EXPECT_EQ(expect_eof_, data_->AllWriteDataConsumed());
  }
}

void SequencedSocketDataTest::Initialize(base::span<const MockRead> reads,
                                         base::span<const MockWrite> writes) {
  data_ = std::make_unique<SequencedSocketData>(MockConnect(SYNCHRONOUS, OK),
                                                reads, writes);
  socket_factory_.AddSocketDataProvider(data_.get());
  sock_ = socket_factory_.CreateTransportClientSocket(
      AddressList(IPEndPoint(IPAddress::IPv4Localhost(), 443)),
      nullptr /* socket_performance_watcher */,
      nullptr /* network_quality_estimator */, nullptr /* net_log */,
      NetLogSource());
  TestCompletionCallback callback;
  EXPECT_EQ(OK, sock_->Connect(callback.callback()));
}

void SequencedSocketDataTest::AssertSyncReadEquals(const char* data, int len) {
  // Issue the read, which will complete immediately.
  AssertReadReturns(len, len);
  AssertReadBufferEquals(data, len);
}

void SequencedSocketDataTest::AssertAsyncReadEquals(const char* data, int len) {
  // Issue the read, which will be completed asynchronously.
  AssertReadReturns(len, ERR_IO_PENDING);

  EXPECT_TRUE(sock_->IsConnected());

  // Now the read should complete.
  ASSERT_EQ(len, read_callback_.WaitForResult());
  AssertReadBufferEquals(data, len);
}

void SequencedSocketDataTest::AssertReadReturns(int len, int rv) {
  read_buf_ = base::MakeRefCounted<IOBufferWithSize>(len);
  if (rv == ERR_IO_PENDING) {
    ASSERT_EQ(rv, sock_->Read(read_buf_.get(), len, read_callback_.callback()));
    ASSERT_FALSE(read_callback_.have_result());
  } else {
    ASSERT_EQ(rv, sock_->Read(read_buf_.get(), len, failing_callback()));
  }
}

void SequencedSocketDataTest::AssertReadBufferEquals(const char* data,
                                                     int len) {
  ASSERT_EQ(std::string(data, len), std::string(read_buf_->data(), len));
}

void SequencedSocketDataTest::AssertSyncWriteEquals(const char* data, int len) {
  // Issue the write, which should be complete immediately.
  AssertWriteReturns(data, len, len);
  ASSERT_FALSE(write_callback_.have_result());
}

void SequencedSocketDataTest::AssertAsyncWriteEquals(const char* data,
                                                     int len) {
  // Issue the read, which should be completed asynchronously.
  AssertWriteReturns(data, len, ERR_IO_PENDING);

  EXPECT_FALSE(read_callback_.have_result());
  EXPECT_TRUE(sock_->IsConnected());

  ASSERT_EQ(len, write_callback_.WaitForResult());
}

bool SequencedSocketDataTest::IsPaused() const {
  return data_->IsPaused();
}

void SequencedSocketDataTest::Resume() {
  data_->Resume();
}

void SequencedSocketDataTest::RunUntilPaused() {
  data_->RunUntilPaused();
}

void SequencedSocketDataTest::AssertWriteReturns(const char* data,
                                                 int len,
                                                 int rv) {
  auto buf = base::MakeRefCounted<IOBufferWithSize>(len);
  memcpy(buf->data(), data, len);

  if (rv == ERR_IO_PENDING) {
    ASSERT_EQ(rv, sock_->Write(buf.get(), len, write_callback_.callback(),
                               TRAFFIC_ANNOTATION_FOR_TESTS));
    ASSERT_FALSE(write_callback_.have_result());
  } else {
    ASSERT_EQ(rv, sock_->Write(buf.get(), len, failing_callback(),
                               TRAFFIC_ANNOTATION_FOR_TESTS));
  }
}

void SequencedSocketDataTest::ReentrantReadCallback(const char* data,
                                                    int len1,
                                                    int len2,
                                                    int expected_rv2,
                                                    int rv) {
  ASSERT_EQ(len1, rv);
  AssertReadBufferEquals(data, len1);

  AssertReadReturns(len2, expected_rv2);
}

void SequencedSocketDataTest::ReentrantAsyncReadCallback(int expected_rv,
                                                         int len,
                                                         int rv) {
  ASSERT_EQ(expected_rv, rv);

  AssertReadReturns(len, ERR_IO_PENDING);
}

void SequencedSocketDataTest::ReentrantWriteCallback(int expected_rv1,
                                                     const char* data,
                                                     int len,
                                                     int expected_rv2,
                                                     int rv) {
  ASSERT_EQ(expected_rv1, rv);

  AssertWriteReturns(data, len, expected_rv2);
}

void SequencedSocketDataTest::ReentrantAsyncWriteCallback(
    const char* data,
    int len,
    CompletionOnceCallback callback,
    int expected_rv,
    int rv) {
  EXPECT_EQ(expected_rv, rv);
  auto write_buf = base::MakeRefCounted<IOBufferWithSize>(len);
  memcpy(write_buf->data(), data, len);
  EXPECT_THAT(sock_->Write(write_buf.get(), len, std::move(callback),
                           TRAFFIC_ANNOTATION_FOR_TESTS),
              IsError(ERR_IO_PENDING));
}

void SequencedSocketDataTest::FailingCompletionCallback(int rv) {
  ADD_FAILURE() << "Callback should not have been invoked";
}

// ----------- Read

TEST_F(SequencedSocketDataTest, SingleSyncRead) {
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kMsg1, kLen1, 0),
  };

  Initialize(reads, base::span<MockWrite>());
  AssertSyncReadEquals(kMsg1, kLen1);
}

TEST_F(SequencedSocketDataTest, MultipleSyncReads) {
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kMsg1, kLen1, 0),
      MockRead(SYNCHRONOUS, kMsg2, kLen2, 1),
      MockRead(SYNCHRONOUS, kMsg3, kLen3, 2),
      MockRead(SYNCHRONOUS, kMsg3, kLen3, 3),
      MockRead(SYNCHRONOUS, kMsg2, kLen2, 4),
      MockRead(SYNCHRONOUS, kMsg3, kLen3, 5),
      MockRead(SYNCHRONOUS, kMsg1, kLen1, 6),
  };

  Initialize(reads, base::span<MockWrite>());

  AssertSyncReadEquals(kMsg1, kLen1);
  AssertSyncReadEquals(kMsg2, kLen2);
  AssertSyncReadEquals(kMsg3, kLen3);
  AssertSyncReadEquals(kMsg3, kLen3);
  AssertSyncReadEquals(kMsg2, kLen2);
  AssertSyncReadEquals(kMsg3, kLen3);
  AssertSyncReadEquals(kMsg1, kLen1);
}

TEST_F(SequencedSocketDataTest, SingleAsyncRead) {
  MockRead reads[] = {
      MockRead(ASYNC, kMsg1, kLen1, 0),
  };

  Initialize(reads, base::span<MockWrite>());

  AssertAsyncReadEquals(kMsg1, kLen1);
}

TEST_F(SequencedSocketDataTest, MultipleAsyncReads) {
  MockRead reads[] = {
      MockRead(ASYNC, kMsg1, kLen1, 0),
      MockRead(ASYNC, kMsg2, kLen2, 1),
      MockRead(ASYNC, kMsg3, kLen3, 2),
      MockRead(ASYNC, kMsg3, kLen3, 3),
      MockRead(ASYNC, kMsg2, kLen2, 4),
      MockRead(ASYNC, kMsg3, kLen3, 5),
      MockRead(ASYNC, kMsg1, kLen1, 6),
  };

  Initialize(reads, base::span<MockWrite>());

  AssertAsyncReadEquals(kMsg1, kLen1);
  AssertAsyncReadEquals(kMsg2, kLen2);
  AssertAsyncReadEquals(kMsg3, kLen3);
  AssertAsyncReadEquals(kMsg3, kLen3);
  AssertAsyncReadEquals(kMsg2, kLen2);
  AssertAsyncReadEquals(kMsg3, kLen3);
  AssertAsyncReadEquals(kMsg1, kLen1);
}

TEST_F(SequencedSocketDataTest, MixedReads) {
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kMsg1, kLen1, 0),
      MockRead(ASYNC, kMsg2, kLen2, 1),
      MockRead(SYNCHRONOUS, kMsg3, kLen3, 2),
      MockRead(ASYNC, kMsg3, kLen3, 3),
      MockRead(SYNCHRONOUS, kMsg2, kLen2, 4),
      MockRead(ASYNC, kMsg3, kLen3, 5),
      MockRead(SYNCHRONOUS, kMsg1, kLen1, 6),
  };

  Initialize(reads, base::span<MockWrite>());

  AssertSyncReadEquals(kMsg1, kLen1);
  AssertAsyncReadEquals(kMsg2, kLen2);
  AssertSyncReadEquals(kMsg3, kLen3);
  AssertAsyncReadEquals(kMsg3, kLen3);
  AssertSyncReadEquals(kMsg2, kLen2);
  AssertAsyncReadEquals(kMsg3, kLen3);
  AssertSyncReadEquals(kMsg1, kLen1);
}

TEST_F(SequencedSocketDataTest, SyncReadFromCompletionCallback) {
  MockRead reads[] = {
      MockRead(ASYNC, kMsg1, kLen1, 0), MockRead(SYNCHRONOUS, kMsg2, kLen2, 1),
  };

  Initialize(reads, base::span<MockWrite>());

  read_buf_ = base::MakeRefCounted<IOBufferWithSize>(kLen1);
  ASSERT_EQ(
      ERR_IO_PENDING,
      sock_->Read(
          read_buf_.get(), kLen1,
          base::BindOnce(&SequencedSocketDataTest::ReentrantReadCallback,
                         base::Unretained(this), kMsg1, kLen1, kLen2, kLen2)));

  base::RunLoop().RunUntilIdle();
  AssertReadBufferEquals(kMsg2, kLen2);
}

TEST_F(SequencedSocketDataTest, ManyReentrantReads) {
  MockRead reads[] = {
      MockRead(ASYNC, kMsg1, kLen1, 0),
      MockRead(ASYNC, kMsg2, kLen2, 1),
      MockRead(ASYNC, kMsg3, kLen3, 2),
      MockRead(ASYNC, kMsg4, kLen4, 3),
  };

  Initialize(reads, base::span<MockWrite>());

  read_buf_ = base::MakeRefCounted<IOBufferWithSize>(kLen4);

  ReentrantHelper helper3(sock_.get());
  helper3.SetExpectedRead(kMsg3, kLen3);
  helper3.SetInvokeRead(read_buf_, kLen4, ERR_IO_PENDING,
                        read_callback_.callback());

  ReentrantHelper helper2(sock_.get());
  helper2.SetExpectedRead(kMsg2, kLen2);
  helper2.SetInvokeRead(helper3.read_buf(), kLen3, ERR_IO_PENDING,
                        helper3.callback());

  ReentrantHelper helper(sock_.get());
  helper.SetExpectedRead(kMsg1, kLen1);
  helper.SetInvokeRead(helper2.read_buf(), kLen2, ERR_IO_PENDING,
                       helper2.callback());

  sock_->Read(helper.read_buf().get(), kLen1, helper.callback());

  ASSERT_EQ(kLen4, read_callback_.WaitForResult());
  AssertReadBufferEquals(kMsg4, kLen4);
}

TEST_F(SequencedSocketDataTest, AsyncReadFromCompletionCallback) {
  MockRead reads[] = {
      MockRead(ASYNC, kMsg1, kLen1, 0), MockRead(ASYNC, kMsg2, kLen2, 1),
  };

  Initialize(reads, base::span<MockWrite>());

  read_buf_ = base::MakeRefCounted<IOBufferWithSize>(kLen1);
  ASSERT_EQ(ERR_IO_PENDING,
            sock_->Read(
                read_buf_.get(), kLen1,
                base::BindOnce(&SequencedSocketDataTest::ReentrantReadCallback,
                               base::Unretained(this), kMsg1, kLen1, kLen2,
                               ERR_IO_PENDING)));

  ASSERT_FALSE(read_callback_.have_result());
  ASSERT_EQ(kLen2, read_callback_.WaitForResult());
  AssertReadBufferEquals(kMsg2, kLen2);
}

TEST_F(SequencedSocketDataTest, SingleSyncReadTooEarly) {
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kMsg1, kLen1, 1),
  };

  MockWrite writes[] = {MockWrite(SYNCHRONOUS, 0, 0)};

  Initialize(reads, writes);

  EXPECT_NONFATAL_FAILURE(AssertReadReturns(kLen1, ERR_UNEXPECTED),
                          "Unable to perform synchronous IO while stopped");
  set_expect_eof(false);
}

TEST_F(SequencedSocketDataTest, SingleSyncReadSmallBuffer) {
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kMsg1, kLen1, 0),
  };

  Initialize(reads, base::span<MockWrite>());

  // Read the first chunk.
  AssertReadReturns(kLen1 - 1, kLen1 - 1);
  AssertReadBufferEquals(kMsg1, kLen1 - 1);
  // Then read the second chunk.
  AssertReadReturns(1, 1);
  AssertReadBufferEquals(kMsg1 + kLen1 - 1, 1);
}

TEST_F(SequencedSocketDataTest, SingleSyncReadLargeBuffer) {
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kMsg1, kLen1, 0),
  };

  Initialize(reads, base::span<MockWrite>());
  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(2 * kLen1);
  ASSERT_EQ(kLen1, sock_->Read(read_buf.get(), 2 * kLen1, failing_callback()));
  ASSERT_EQ(std::string(kMsg1, kLen1), std::string(read_buf->data(), kLen1));
}

TEST_F(SequencedSocketDataTest, SingleAsyncReadLargeBuffer) {
  MockRead reads[] = {
      MockRead(ASYNC, kMsg1, kLen1, 0),
  };

  Initialize(reads, base::span<MockWrite>());

  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(2 * kLen1);
  ASSERT_EQ(ERR_IO_PENDING,
            sock_->Read(read_buf.get(), 2 * kLen1, read_callback_.callback()));
  ASSERT_EQ(kLen1, read_callback_.WaitForResult());
  ASSERT_EQ(std::string(kMsg1, kLen1), std::string(read_buf->data(), kLen1));
}

TEST_F(SequencedSocketDataTest, HangingRead) {
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0),
  };

  Initialize(reads, base::span<MockWrite>());

  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(1);
  ASSERT_EQ(ERR_IO_PENDING,
            sock_->Read(read_buf.get(), 1, read_callback_.callback()));
  ASSERT_FALSE(read_callback_.have_result());

  // Even though the read is scheduled to complete at sequence number 0,
  // verify that the read callback in never called.
  base::RunLoop().RunUntilIdle();
  ASSERT_FALSE(read_callback_.have_result());
}

// ----------- Write

TEST_F(SequencedSocketDataTest, SingleSyncWriteTooEarly) {
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, kMsg1, kLen1, 1),
  };

  MockRead reads[] = {MockRead(SYNCHRONOUS, 0, 0)};

  Initialize(reads, writes);

  EXPECT_NONFATAL_FAILURE(AssertWriteReturns(kMsg1, kLen1, ERR_UNEXPECTED),
                          "Unable to perform synchronous IO while stopped");

  set_expect_eof(false);
}

TEST_F(SequencedSocketDataTest, SingleSyncWriteTooSmall) {
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, kMsg1, kLen1, 0),
  };

  Initialize(base::span<MockRead>(), writes);

  // Expecting too small of a write triggers multiple expectation failures.
  //
  // The gtest infrastructure does not have a macro similar to
  // EXPECT_NONFATAL_FAILURE which works when there is more than one
  // failure.
  //
  // However, tests can gather the TestPartResultArray and directly
  // validate the test failures. That's what the rest of this test does.

  ::testing::TestPartResultArray gtest_failures;

  {
    ::testing::ScopedFakeTestPartResultReporter gtest_reporter(
        ::testing::ScopedFakeTestPartResultReporter::
            INTERCEPT_ONLY_CURRENT_THREAD,
        &gtest_failures);
    AssertSyncWriteEquals(kMsg1, kLen1 - 1);
  }

  static const char* kExpectedFailures[] = {
      "Value of: actual_data == expected_data\n  Actual: false\nExpected: true",
      "Expected equality of these values:\n  rv"};
  ASSERT_EQ(std::size(kExpectedFailures),
            static_cast<size_t>(gtest_failures.size()));

  for (int i = 0; i < gtest_failures.size(); ++i) {
    const ::testing::TestPartResult& result =
        gtest_failures.GetTestPartResult(i);
    EXPECT_TRUE(strstr(result.message(), kExpectedFailures[i]) != nullptr);
  }

  set_expect_eof(false);
}

TEST_F(SequencedSocketDataTest, SingleSyncPartialWrite) {
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, kMsg1, kLen1 - 1, 0),
      MockWrite(SYNCHRONOUS, kMsg1 + kLen1 - 1, 1, 1),
  };

  Initialize(base::span<MockRead>(), writes);

  // Attempt to write all of the message, but only some will be written.
  AssertSyncWriteEquals(kMsg1, kLen1 - 1);
  // Write the rest of the message.
  AssertSyncWriteEquals(kMsg1 + kLen1 - 1, 1);
}

TEST_F(SequencedSocketDataTest, SingleSyncWrite) {
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, kMsg1, kLen1, 0),
  };

  Initialize(base::span<MockRead>(), writes);

  AssertSyncWriteEquals(kMsg1, kLen1);
}

TEST_F(SequencedSocketDataTest, MultipleSyncWrites) {
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, kMsg1, kLen1, 0),
      MockWrite(SYNCHRONOUS, kMsg2, kLen2, 1),
      MockWrite(SYNCHRONOUS, kMsg3, kLen3, 2),
      MockWrite(SYNCHRONOUS, kMsg3, kLen3, 3),
      MockWrite(SYNCHRONOUS, kMsg2, kLen2, 4),
      MockWrite(SYNCHRONOUS, kMsg3, kLen3, 5),
      MockWrite(SYNCHRONOUS, kMsg1, kLen1, 6),
  };

  Initialize(base::span<MockRead>(), writes);

  AssertSyncWriteEquals(kMsg1, kLen1);
  AssertSyncWriteEquals(kMsg2, kLen2);
  AssertSyncWriteEquals(kMsg3, kLen3);
  AssertSyncWriteEquals(kMsg3, kLen3);
  AssertSyncWriteEquals(kMsg2, kLen2);
  AssertSyncWriteEquals(kMsg3, kLen3);
  AssertSyncWriteEquals(kMsg1, kLen1);
}

TEST_F(SequencedSocketDataTest, SingleAsyncWrite) {
  MockWrite writes[] = {
      MockWrite(ASYNC, kMsg1, kLen1, 0),
  };

  Initialize(base::span<MockRead>(), writes);

  AssertAsyncWriteEquals(kMsg1, kLen1);
}

TEST_F(SequencedSocketDataTest, MultipleAsyncWrites) {
  MockWrite writes[] = {
      MockWrite(ASYNC, kMsg1, kLen1, 0),
      MockWrite(ASYNC, kMsg2, kLen2, 1),
      MockWrite(ASYNC, kMsg3, kLen3, 2),
      MockWrite(ASYNC, kMsg3, kLen3, 3),
      MockWrite(ASYNC, kMsg2, kLen2, 4),
      MockWrite(ASYNC, kMsg3, kLen3, 5),
      MockWrite(ASYNC, kMsg1, kLen1, 6),
  };

  Initialize(base::span<MockRead>(), writes);

  AssertAsyncWriteEquals(kMsg1, kLen1);
  AssertAsyncWriteEquals(kMsg2, kLen2);
  AssertAsyncWriteEquals(kMsg3, kLen3);
  AssertAsyncWriteEquals(kMsg3, kLen3);
  AssertAsyncWriteEquals(kMsg2, kLen2);
  AssertAsyncWriteEquals(kMsg3, kLen3);
  AssertAsyncWriteEquals(kMsg1, kLen1);
}

TEST_F(SequencedSocketDataTest, MixedWrites) {
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, kMsg1, kLen1, 0),
      MockWrite(ASYNC, kMsg2, kLen2, 1),
      MockWrite(SYNCHRONOUS, kMsg3, kLen3, 2),
      MockWrite(ASYNC, kMsg3, kLen3, 3),
      MockWrite(SYNCHRONOUS, kMsg2, kLen2, 4),
      MockWrite(ASYNC, kMsg3, kLen3, 5),
      MockWrite(SYNCHRONOUS, kMsg1, kLen1, 6),
  };

  Initialize(base::span<MockRead>(), writes);

  AssertSyncWriteEquals(kMsg1, kLen1);
  AssertAsyncWriteEquals(kMsg2, kLen2);
  AssertSyncWriteEquals(kMsg3, kLen3);
  AssertAsyncWriteEquals(kMsg3, kLen3);
  AssertSyncWriteEquals(kMsg2, kLen2);
  AssertAsyncWriteEquals(kMsg3, kLen3);
  AssertSyncWriteEquals(kMsg1, kLen1);
}

TEST_F(SequencedSocketDataTest, SyncWriteFromCompletionCallback) {
  MockWrite writes[] = {
      MockWrite(ASYNC, kMsg1, kLen1, 0),
      MockWrite(SYNCHRONOUS, kMsg2, kLen2, 1),
  };

  Initialize(base::span<MockRead>(), writes);

  auto write_buf = base::MakeRefCounted<IOBufferWithSize>(kLen1);
  memcpy(write_buf->data(), kMsg1, kLen1);
  ASSERT_EQ(
      ERR_IO_PENDING,
      sock_->Write(
          write_buf.get(), kLen1,
          base::BindOnce(&SequencedSocketDataTest::ReentrantWriteCallback,
                         base::Unretained(this), kLen1, kMsg2, kLen2, kLen2),
          TRAFFIC_ANNOTATION_FOR_TESTS));

  base::RunLoop().RunUntilIdle();
}

TEST_F(SequencedSocketDataTest, AsyncWriteFromCompletionCallback) {
  MockWrite writes[] = {
      MockWrite(ASYNC, kMsg1, kLen1, 0), MockWrite(ASYNC, kMsg2, kLen2, 1),
  };

  Initialize(base::span<MockRead>(), writes);

  auto write_buf = base::MakeRefCounted<IOBufferWithSize>(kLen1);
  memcpy(write_buf->data(), kMsg1, kLen1);
  ASSERT_EQ(ERR_IO_PENDING,
            sock_->Write(
                write_buf.get(), kLen1,
                base::BindOnce(&SequencedSocketDataTest::ReentrantWriteCallback,
                               base::Unretained(this), kLen1, kMsg2, kLen2,
                               ERR_IO_PENDING),
                TRAFFIC_ANNOTATION_FOR_TESTS));

  ASSERT_FALSE(write_callback_.have_result());
  ASSERT_EQ(kLen2, write_callback_.WaitForResult());
}

TEST_F(SequencedSocketDataTest, ManyReentrantWrites) {
  MockWrite writes[] = {
      MockWrite(ASYNC, kMsg1, kLen1, 0),
      MockWrite(ASYNC, kMsg2, kLen2, 1),
      MockWrite(ASYNC, kMsg3, kLen3, 2),
      MockWrite(ASYNC, kMsg4, kLen4, 3),
  };

  Initialize(base::span<MockRead>(), writes);

  ReentrantHelper helper3(sock_.get());
  helper3.SetExpectedWrite(kLen3);
  helper3.SetInvokeWrite(kMsg4, kLen4, ERR_IO_PENDING,
                         write_callback_.callback());

  ReentrantHelper helper2(sock_.get());
  helper2.SetExpectedWrite(kLen2);
  helper2.SetInvokeWrite(kMsg3, kLen3, ERR_IO_PENDING, helper3.callback());

  ReentrantHelper helper(sock_.get());
  helper.SetExpectedWrite(kLen1);
  helper.SetInvokeWrite(kMsg2, kLen2, ERR_IO_PENDING, helper2.callback());

  auto write_buf = base::MakeRefCounted<IOBufferWithSize>(kLen1);
  memcpy(write_buf->data(), kMsg1, kLen1);
  sock_->Write(write_buf.get(), kLen1, helper.callback(),
               TRAFFIC_ANNOTATION_FOR_TESTS);

  ASSERT_EQ(kLen4, write_callback_.WaitForResult());
}

// ----------- Mixed Reads and Writes

TEST_F(SequencedSocketDataTest, MixedSyncOperations) {
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kMsg1, kLen1, 0),
      MockRead(SYNCHRONOUS, kMsg2, kLen2, 3),
  };

  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, kMsg2, kLen2, 1),
      MockWrite(SYNCHRONOUS, kMsg3, kLen3, 2),
  };

  Initialize(reads, writes);

  AssertSyncReadEquals(kMsg1, kLen1);
  AssertSyncWriteEquals(kMsg2, kLen2);
  AssertSyncWriteEquals(kMsg3, kLen3);
  AssertSyncReadEquals(kMsg2, kLen2);
}

TEST_F(SequencedSocketDataTest, MixedAsyncOperations) {
  MockRead reads[] = {
      MockRead(ASYNC, kMsg1, kLen1, 0), MockRead(ASYNC, kMsg2, kLen2, 3),
  };

  MockWrite writes[] = {
      MockWrite(ASYNC, kMsg2, kLen2, 1), MockWrite(ASYNC, kMsg3, kLen3, 2),
  };

  Initialize(reads, writes);

  AssertAsyncReadEquals(kMsg1, kLen1);
  AssertAsyncWriteEquals(kMsg2, kLen2);
  AssertAsyncWriteEquals(kMsg3, kLen3);
  AssertAsyncReadEquals(kMsg2, kLen2);
}

TEST_F(SequencedSocketDataTest, InterleavedAsyncOperations) {
  // Order of completion is read, write, write, read.
  MockRead reads[] = {
      MockRead(ASYNC, kMsg1, kLen1, 0), MockRead(ASYNC, kMsg2, kLen2, 3),
  };

  MockWrite writes[] = {
      MockWrite(ASYNC, kMsg2, kLen2, 1), MockWrite(ASYNC, kMsg3, kLen3, 2),
  };

  Initialize(reads, writes);

  // Issue the write, which will block until the read completes.
  AssertWriteReturns(kMsg2, kLen2, ERR_IO_PENDING);

  // Issue the read which will return first.
  AssertReadReturns(kLen1, ERR_IO_PENDING);

  ASSERT_EQ(kLen1, read_callback_.WaitForResult());
  AssertReadBufferEquals(kMsg1, kLen1);

  // Run posted OnWriteComplete().
  base::RunLoop().RunUntilIdle();

  ASSERT_TRUE(write_callback_.have_result());
  ASSERT_EQ(kLen2, write_callback_.WaitForResult());

  // Issue the read, which will block until the write completes.
  AssertReadReturns(kLen2, ERR_IO_PENDING);

  // Issue the writes which will return first.
  AssertWriteReturns(kMsg3, kLen3, ERR_IO_PENDING);
  ASSERT_EQ(kLen3, write_callback_.WaitForResult());

  ASSERT_EQ(kLen2, read_callback_.WaitForResult());
  AssertReadBufferEquals(kMsg2, kLen2);
}

TEST_F(SequencedSocketDataTest, InterleavedMixedOperations) {
  // Order of completion is read, write, write, read.
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kMsg1, kLen1, 0),
      MockRead(ASYNC, kMsg2, kLen2, 3),
      MockRead(ASYNC, kMsg3, kLen3, 5),
  };

  MockWrite writes[] = {
      MockWrite(ASYNC, kMsg2, kLen2, 1),
      MockWrite(SYNCHRONOUS, kMsg3, kLen3, 2),
      MockWrite(SYNCHRONOUS, kMsg1, kLen1, 4),
  };

  Initialize(reads, writes);

  // Issue the write, which will block until the read completes.
  AssertWriteReturns(kMsg2, kLen2, ERR_IO_PENDING);

  // Issue the writes which will complete immediately.
  AssertSyncReadEquals(kMsg1, kLen1);

  ASSERT_FALSE(write_callback_.have_result());
  ASSERT_EQ(kLen2, write_callback_.WaitForResult());

  // Issue the read, which will block until the write completes.
  AssertReadReturns(kLen2, ERR_IO_PENDING);

  // Issue the writes which will complete immediately.
  AssertSyncWriteEquals(kMsg3, kLen3);

  ASSERT_FALSE(read_callback_.have_result());
  ASSERT_EQ(kLen2, read_callback_.WaitForResult());
  AssertReadBufferEquals(kMsg2, kLen2);

  // Issue the read, which will block until the write completes.
  AssertReadReturns(kLen2, ERR_IO_PENDING);

  // Issue the writes which will complete immediately.
  AssertSyncWriteEquals(kMsg1, kLen1);

  ASSERT_FALSE(read_callback_.have_result());
  ASSERT_EQ(kLen3, read_callback_.WaitForResult());
  AssertReadBufferEquals(kMsg3, kLen3);
}

TEST_F(SequencedSocketDataTest, AsyncReadFromWriteCompletionCallback) {
  MockWrite writes[] = {
      MockWrite(ASYNC, kMsg1, kLen1, 0),
  };

  MockRead reads[] = {
      MockRead(ASYNC, kMsg2, kLen2, 1),
  };

  Initialize(reads, writes);

  auto write_buf = base::MakeRefCounted<IOBufferWithSize>(kLen1);
  memcpy(write_buf->data(), kMsg1, kLen1);
  ASSERT_EQ(
      ERR_IO_PENDING,
      sock_->Write(
          write_buf.get(), kLen1,
          base::BindOnce(&SequencedSocketDataTest::ReentrantAsyncReadCallback,
                         base::Unretained(this), kLen1, kLen2),
          TRAFFIC_ANNOTATION_FOR_TESTS));

  
"""


```