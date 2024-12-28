Response:
Let's break down the thought process to analyze the given C++ test file.

1. **Identify the Core Purpose:** The filename `data_pipe_bytes_consumer_test.cc` immediately suggests this file tests the `DataPipeBytesConsumer` class. The `_test.cc` suffix is a strong indicator of a unit test file.

2. **Examine Includes:**  The `#include` directives tell us about the dependencies and the class being tested:
    * `"third_party/blink/renderer/platform/loader/fetch/data_pipe_bytes_consumer.h"`:  Confirms the main class under test.
    * `<string_view>`:  Indicates the use of string views, likely for efficiency in handling data.
    * `"base/containers/span.h"`: Shows the use of `base::span` for representing contiguous memory regions.
    * `"base/task/single_thread_task_runner.h"` and `"third_party/blink/renderer/platform/scheduler/test/fake_task_runner.h"`:  Suggest asynchronous operations and the use of a mock task runner for testing. This is crucial for understanding how the consumer interacts with the event loop.
    * `"testing/gtest/include/gtest/gtest.h"`:  Confirms the use of Google Test framework for writing the tests.
    * `"third_party/blink/renderer/platform/loader/testing/bytes_consumer_test_reader.h"`:  Indicates a helper class is used for running the consumer in tests.

3. **Analyze the Test Fixture:** The `DataPipeBytesConsumerTest` class inherits from `testing::Test`. This is standard practice in Google Test for grouping related tests. The `PublicState` and `Result` type aliases indicate that the tests will verify the internal state transitions and the outcome of operations. The constructor initializes a `FakeTaskRunner`, further emphasizing the asynchronous nature of the class.

4. **Deconstruct Individual Tests (Iterative Approach):**  Go through each `TEST_F` function and understand its purpose:

    * **`TwoPhaseRead`:** This looks like a basic successful read test. It sets up a data pipe, writes data, closes the producer, creates a `DataPipeBytesConsumer`, and then uses `BytesConsumerTestReader` to execute the read operation. The `EXPECT_EQ` assertions verify the expected result (`kDone`) and the received data.

    * **`TwoPhaseRead_SignalError`:** Similar to `TwoPhaseRead`, but it explicitly signals an error via `notifier->SignalError`. This tests the error handling path.

    * **`EndOfPipeBeforeComplete`:** This test explores the scenario where the data pipe closes (producer is reset) *before* the completion signal is received. It checks the state transitions (`PublicState`) and the result of `BeginRead`. The assertion that `SignalComplete()` eventually leads to `kDone` is important.

    * **`CompleteBeforeEndOfPipe`:** This is the opposite scenario: completion is signaled *before* the data pipe closes. It verifies that the consumer waits until the pipe is closed to return `kDone`.

    * **`EndOfPipeBeforeError`:** This tests the precedence of error signals. Even if the pipe ends, if an error is signaled, the consumer should enter the `kErrored` state.

    * **`SignalSizeBeforeRead`:** This introduces the `SignalSize` mechanism, where the expected data size is provided beforehand. It verifies that `BeginRead` returns the expected amount of data.

    * **`SignalExcessSizeBeforeEndOfData`:** Tests what happens when `SignalSize` indicates more data than is actually present in the pipe. It should result in an error.

    * **`SignalExcessSizeAfterEndOfData`:**  Similar to the previous one, but the `SignalSize` arrives after the producer closes. This also should lead to an error.

    * **`SignalSizeAfterRead`:** Tests `SignalSize` after some data has already been read. It ensures the consumer can still reach the closed state.

    * **`ErrorBeforeEndOfPipe`:** Tests that an error signal immediately puts the consumer in the `kErrored` state, even if more data could potentially arrive.

    * **`DrainPipeBeforeComplete`:** Introduces the `DrainAsDataPipe` functionality. It checks that draining the pipe doesn't immediately close the consumer until `SignalComplete` is called.

    * **`CompleteBeforeDrainPipe`:** Tests the order of operations: completing before draining. It ensures draining after completion leads to the closed state.

5. **Identify Relationships to Web Technologies:** Think about how data pipes and byte consumers relate to the loading of web resources:

    * **JavaScript/HTML/CSS:**  When a browser fetches a resource (HTML, CSS, JavaScript, images, etc.), the response body often arrives as a stream of bytes. `DataPipeBytesConsumer` is likely involved in consuming this stream.

    * **Asynchronous Operations:** The use of `FakeTaskRunner` and the two-phase read pattern (`BeginRead`/`EndRead`) strongly suggest handling asynchronous data loading, a core part of web browsing.

6. **Consider User/Programming Errors:** Look for scenarios that might lead to incorrect usage or unexpected behavior:

    * **Mismatched `SignalSize`:**  Signaling an incorrect size is a clear programming error. The tests cover both signaling too much data and signaling after the data is finished.
    * **Not signaling completion/error:** Forgetting to call `SignalComplete` or `SignalError` could leave the consumer in an indefinite waiting state.
    * **Incorrectly handling `kShouldWait`:**  Failing to wait when `BeginRead` returns `kShouldWait` would result in lost data or errors.

7. **Formulate Assumptions and Outputs (for logical reasoning):**  For each test, think about the setup (input) and the expected outcome (output). For example:

    * **Input (for `TwoPhaseRead`):**  A data pipe with the string "Such hospitality. I'm underwhelmed." written to it, followed by closing the producer and signaling completion.
    * **Output:** The `BytesConsumerTestReader` should return `Result::kDone` and the data "Such hospitality. I'm underwhelmed.".

8. **Structure the Answer:** Organize the findings into logical categories: functionality, relationship to web technologies, logical reasoning (with input/output examples), and common errors. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the data pipe is just for local data transfer.
* **Correction:** The asynchronous nature and the context of "loader/fetch" strongly suggest it's related to network requests and fetching web resources.

* **Initial thought:**  Focus only on the success cases.
* **Refinement:** Realize the importance of error handling and state management, and pay close attention to the tests that cover these aspects.

By following this structured approach, combining code analysis with domain knowledge, and iterating through the tests, a comprehensive understanding of the test file and its purpose can be achieved.
这个C++源代码文件 `data_pipe_bytes_consumer_test.cc` 是 Chromium Blink 渲染引擎中的一个单元测试文件。它的主要功能是 **测试 `DataPipeBytesConsumer` 类的各种功能和状态转换**。

`DataPipeBytesConsumer` 的作用是从一个 Mojo DataPipe 中异步读取字节流。Mojo DataPipe 是 Chromium 中用于进程间通信 (IPC) 的一种高效机制。 `DataPipeBytesConsumer` 使得 Blink 渲染器能够以非阻塞的方式从其他进程（例如浏览器主进程）接收数据。

以下是该文件测试的主要功能点：

**1. 基本的两阶段读取 (Two-Phase Read):**

* **功能:** 测试 `DataPipeBytesConsumer` 能否正确地从 DataPipe 中读取数据，并最终到达完成状态。
* **假设输入:**
    * 创建一个 Mojo DataPipe。
    * 向 DataPipe 写入一段字符串数据，例如 "Such hospitality. I'm underwhelmed."。
    * 关闭 DataPipe 的生产者端。
    * 通过 `CompletionNotifier` 发出完成信号。
* **预期输出:** `BytesConsumerTestReader` 能够读取到完整的数据，并且 `DataPipeBytesConsumer` 的状态变为 `kDone`。

**2. 错误信号处理 (Signal Error):**

* **功能:** 测试 `DataPipeBytesConsumer` 在接收到错误信号时，能否正确地进入错误状态。
* **假设输入:**
    * 创建一个 Mojo DataPipe 并写入数据。
    * 关闭生产者端。
    * 通过 `CompletionNotifier` 发出错误信号。
* **预期输出:** `BytesConsumerTestReader` 返回错误状态 (`kError`)，并且 `DataPipeBytesConsumer` 的状态变为 `kError`。

**3. DataPipe 结束与完成信号的顺序:**

* **功能:** 测试 DataPipe 的结束（生产者关闭）和完成信号到达的先后顺序对 `DataPipeBytesConsumer` 状态的影响。
* **`EndOfPipeBeforeComplete` 案例:**
    * **假设输入:** DataPipe 生产者先关闭，然后才通过 `CompletionNotifier` 发出完成信号。
    * **预期输出:** `DataPipeBytesConsumer` 会先处于等待状态 (`kReadableOrWaiting`)，在收到完成信号后变为 `kClosed`，最终读取操作返回 `kDone`。
* **`CompleteBeforeEndOfPipe` 案例:**
    * **假设输入:** 先通过 `CompletionNotifier` 发出完成信号，然后 DataPipe 生产者才关闭。
    * **预期输出:** `DataPipeBytesConsumer` 会先处于等待状态，直到 DataPipe 结束才变为 `kClosed`，最终读取操作返回 `kDone`。

**4. 错误信号的优先级:**

* **功能:** 测试错误信号是否能优先于 DataPipe 的正常结束，使 `DataPipeBytesConsumer` 进入错误状态。
* **`EndOfPipeBeforeError` 案例:**
    * **假设输入:** DataPipe 生产者先关闭，然后才通过 `CompletionNotifier` 发出错误信号。
    * **预期输出:** `DataPipeBytesConsumer` 在收到错误信号后立即进入 `kErrored` 状态，后续的读取操作返回 `kError`。

**5. 预先声明数据大小 (Signal Size):**

* **功能:** 测试通过 `CompletionNotifier::SignalSize()` 预先声明数据大小时，`DataPipeBytesConsumer` 的行为。
* **`SignalSizeBeforeRead` 案例:**
    * **假设输入:**  通过 `SignalSize()` 声明数据大小为 5 字节，然后写入 "hello"。
    * **预期输出:** `BeginRead` 可以获取到预期大小的缓冲区，并且在读取相应字节数后，状态最终变为 `kClosed`。
* **错误情况 (`SignalExcessSizeBeforeEndOfData`, `SignalExcessSizeAfterEndOfData`):** 测试声明的大小超过实际数据大小时，`DataPipeBytesConsumer` 会进入错误状态。
* **`SignalSizeAfterRead` 案例:** 测试在读取部分数据后再声明大小，最终状态是否正确。

**6. 提前接收到错误信号:**

* **功能:** 测试在 DataPipe 结束前接收到错误信号的情况。
* **`ErrorBeforeEndOfPipe` 案例:**
    * **假设输入:** 在 DataPipe 生产者关闭之前，通过 `CompletionNotifier` 发出错误信号。
    * **预期输出:** `DataPipeBytesConsumer` 立即进入 `kErrored` 状态，后续的读取操作返回 `kError`。

**7. 数据管道的 Drain 操作:**

* **功能:** 测试 `DrainAsDataPipe()` 方法，该方法允许将 `DataPipeBytesConsumer` 剩余的数据以另一个 DataPipe 的形式取出。
* **`DrainPipeBeforeComplete` 案例:**
    * **假设输入:** 调用 `DrainAsDataPipe()` 获取剩余数据管道，然后发出完成信号。
    * **预期输出:** `DataPipeBytesConsumer` 在收到完成信号后进入 `kClosed` 状态。
* **`CompleteBeforeDrainPipe` 案例:**
    * **假设输入:** 先发出完成信号，然后调用 `DrainAsDataPipe()`。
    * **预期输出:** 调用 `DrainAsDataPipe()` 后，`DataPipeBytesConsumer` 进入 `kClosed` 状态。

**与 JavaScript, HTML, CSS 的关系：**

`DataPipeBytesConsumer` 直接处理的是字节流，它本身不直接与 JavaScript, HTML, CSS 代码交互。然而，它在 **资源加载** 过程中扮演着重要的角色。

* **JavaScript:** 当浏览器通过网络请求加载 JavaScript 文件时，响应体的数据会通过 Mojo DataPipe 传递给渲染进程。`DataPipeBytesConsumer` 负责读取这些字节流，然后这些字节会被解码为 JavaScript 代码，并由 V8 引擎执行。
    * **举例:**  当 `<script src="script.js"></script>` 被解析时，浏览器会发起网络请求。`DataPipeBytesConsumer` 会接收 `script.js` 的字节数据。
* **HTML:** 类似地，当浏览器加载 HTML 页面时，HTML 文件的字节流也会通过 DataPipe 传递。 `DataPipeBytesConsumer` 读取这些数据，然后 Blink 的 HTML 解析器会解析这些字节，构建 DOM 树。
    * **举例:**  当浏览器请求一个 HTML 文件时，服务器返回的 HTML 内容的字节流会被 `DataPipeBytesConsumer` 处理。
* **CSS:** 加载 CSS 文件的过程与 JavaScript 和 HTML 类似。CSS 文件的字节流会被 `DataPipeBytesConsumer` 读取，然后 Blink 的 CSS 解析器会解析这些字节，构建 CSSOM 树。
    * **举例:** 当 `<link rel="stylesheet" href="style.css">` 被解析时，`DataPipeBytesConsumer` 会接收 `style.css` 的字节数据。

**逻辑推理的假设输入与输出 (示例):**

考虑 `TEST_F(DataPipeBytesConsumerTest, TwoPhaseRead)` 这个测试用例：

* **假设输入:**
    * 创建了一个 Mojo DataPipe。
    * 向生产者端写入了字符串 "TestData"。
    * 生产者端被关闭。
    * `CompletionNotifier` 发出了完成信号。
* **预期输出:**
    * `consumer->BeginRead(buffer)` 最终会返回 `Result::kDone`。
    * `result.second` (读取到的数据) 的 UTF-8 编码等于 "TestData"。

**用户或编程常见的使用错误 (示例):**

1. **忘记调用 `SignalComplete()` 或 `SignalError()`:**  如果生产者关闭了 DataPipe，但 `CompletionNotifier` 没有发出完成或错误信号，`DataPipeBytesConsumer` 可能会一直处于等待状态，导致资源泄漏或程序卡死。
    * **例子:**  在网络请求完成或者发生错误时，负责管理 `DataPipeBytesConsumer` 的代码没有正确地通知它完成或出错。

2. **错误地处理 `BeginRead()` 返回的 `Result::kShouldWait`:**  `DataPipeBytesConsumer` 是异步的。当 `BeginRead()` 返回 `kShouldWait` 时，调用者必须等待数据到达后再尝试读取。如果立即尝试读取，可能会读取到空数据或导致错误。
    * **例子:**  没有正确地使用事件循环或回调机制来处理异步读取操作。

3. **在 `DataPipeBytesConsumer` 已经处于 `kClosed` 或 `kErrored` 状态后，仍然尝试读取数据:** 这会导致未定义的行为或者程序崩溃。
    * **例子:**  在资源加载已经完成或失败后，代码仍然尝试从 `DataPipeBytesConsumer` 中读取数据。

4. **`SignalSize()` 声明的大小与实际数据大小不符:** 这会导致 `DataPipeBytesConsumer` 进入错误状态，或者读取到不完整的数据。
    * **例子:**  在预先知道资源大小的情况下，错误地计算或传递了大小信息。

总而言之， `data_pipe_bytes_consumer_test.cc` 通过各种测试用例，确保 `DataPipeBytesConsumer` 能够可靠地从 Mojo DataPipe 中读取数据，并正确处理各种边界情况和错误状态，这对于 Blink 渲染引擎的稳定性和资源加载的效率至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/loader/fetch/data_pipe_bytes_consumer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/data_pipe_bytes_consumer.h"

#include <string_view>

#include "base/containers/span.h"
#include "base/task/single_thread_task_runner.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/loader/testing/bytes_consumer_test_reader.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_task_runner.h"

namespace blink {
class DataPipeBytesConsumerTest : public testing::Test {
 public:
  using PublicState = BytesConsumer::PublicState;
  using Result = BytesConsumer::Result;

  DataPipeBytesConsumerTest()
      : task_runner_(base::MakeRefCounted<scheduler::FakeTaskRunner>()) {}

  const scoped_refptr<scheduler::FakeTaskRunner> task_runner_;
};

TEST_F(DataPipeBytesConsumerTest, TwoPhaseRead) {
  mojo::ScopedDataPipeProducerHandle producer_handle;
  mojo::ScopedDataPipeConsumerHandle consumer_handle;
  ASSERT_EQ(mojo::CreateDataPipe(nullptr, producer_handle, consumer_handle),
            MOJO_RESULT_OK);

  const std::string_view kData = "Such hospitality. I'm underwhelmed.";
  size_t actually_written_bytes = 0;
  MojoResult rv = producer_handle->WriteData(base::as_byte_span(kData),
                                             MOJO_WRITE_DATA_FLAG_NONE,
                                             actually_written_bytes);
  ASSERT_EQ(MOJO_RESULT_OK, rv);
  ASSERT_EQ(kData.size(), actually_written_bytes);

  // Close the producer so the consumer will reach the kDone state after
  // completion is signaled below.
  producer_handle.reset();

  DataPipeBytesConsumer::CompletionNotifier* notifier = nullptr;
  DataPipeBytesConsumer* consumer = MakeGarbageCollected<DataPipeBytesConsumer>(
      task_runner_, std::move(consumer_handle), &notifier);
  notifier->SignalComplete();
  auto result = MakeGarbageCollected<BytesConsumerTestReader>(consumer)->Run(
      task_runner_.get());
  EXPECT_EQ(Result::kDone, result.first);
  EXPECT_EQ(kData, String(result.second).Utf8());
}

TEST_F(DataPipeBytesConsumerTest, TwoPhaseRead_SignalError) {
  mojo::ScopedDataPipeProducerHandle producer_handle;
  mojo::ScopedDataPipeConsumerHandle consumer_handle;
  ASSERT_EQ(mojo::CreateDataPipe(nullptr, producer_handle, consumer_handle),
            MOJO_RESULT_OK);

  const std::string_view kData = "Such hospitality. I'm underwhelmed.";
  size_t actually_written_bytes = 0;
  MojoResult rv = producer_handle->WriteData(base::as_byte_span(kData),
                                             MOJO_WRITE_DATA_FLAG_NONE,
                                             actually_written_bytes);
  ASSERT_EQ(MOJO_RESULT_OK, rv);
  ASSERT_EQ(kData.size(), actually_written_bytes);

  producer_handle.reset();

  DataPipeBytesConsumer::CompletionNotifier* notifier = nullptr;
  DataPipeBytesConsumer* consumer = MakeGarbageCollected<DataPipeBytesConsumer>(
      task_runner_, std::move(consumer_handle), &notifier);

  // Then explicitly signal an error.  This should override the pipe completion
  // and result in kError.
  notifier->SignalError(BytesConsumer::Error());

  auto result = MakeGarbageCollected<BytesConsumerTestReader>(consumer)->Run(
      task_runner_.get());
  EXPECT_EQ(Result::kError, result.first);
  EXPECT_TRUE(result.second.empty());
}

// Verify that both the DataPipe must close and SignalComplete()
// must be called for the DataPipeBytesConsumer to reach the closed
// state.
TEST_F(DataPipeBytesConsumerTest, EndOfPipeBeforeComplete) {
  mojo::ScopedDataPipeProducerHandle producer_handle;
  mojo::ScopedDataPipeConsumerHandle consumer_handle;
  ASSERT_EQ(mojo::CreateDataPipe(nullptr, producer_handle, consumer_handle),
            MOJO_RESULT_OK);

  DataPipeBytesConsumer::CompletionNotifier* notifier = nullptr;
  DataPipeBytesConsumer* consumer = MakeGarbageCollected<DataPipeBytesConsumer>(
      task_runner_, std::move(consumer_handle), &notifier);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());

  base::span<const char> buffer;
  Result rv = consumer->BeginRead(buffer);
  EXPECT_EQ(Result::kShouldWait, rv);

  producer_handle.reset();
  rv = consumer->BeginRead(buffer);
  EXPECT_EQ(Result::kShouldWait, rv);
  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());

  notifier->SignalComplete();
  EXPECT_EQ(PublicState::kClosed, consumer->GetPublicState());

  rv = consumer->BeginRead(buffer);
  EXPECT_EQ(Result::kDone, rv);
}

TEST_F(DataPipeBytesConsumerTest, CompleteBeforeEndOfPipe) {
  mojo::ScopedDataPipeProducerHandle producer_handle;
  mojo::ScopedDataPipeConsumerHandle consumer_handle;
  ASSERT_EQ(mojo::CreateDataPipe(nullptr, producer_handle, consumer_handle),
            MOJO_RESULT_OK);

  DataPipeBytesConsumer::CompletionNotifier* notifier = nullptr;
  DataPipeBytesConsumer* consumer = MakeGarbageCollected<DataPipeBytesConsumer>(
      task_runner_, std::move(consumer_handle), &notifier);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());

  base::span<const char> buffer;
  Result rv = consumer->BeginRead(buffer);
  EXPECT_EQ(Result::kShouldWait, rv);

  notifier->SignalComplete();
  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());

  rv = consumer->BeginRead(buffer);
  EXPECT_EQ(Result::kShouldWait, rv);

  producer_handle.reset();
  rv = consumer->BeginRead(buffer);
  EXPECT_EQ(Result::kDone, rv);
  EXPECT_EQ(PublicState::kClosed, consumer->GetPublicState());
}

// Verify that SignalError moves the DataPipeBytesConsumer to the
// errored state immediately without waiting for the end of the
// DataPipe.
TEST_F(DataPipeBytesConsumerTest, EndOfPipeBeforeError) {
  mojo::ScopedDataPipeProducerHandle producer_handle;
  mojo::ScopedDataPipeConsumerHandle consumer_handle;
  ASSERT_EQ(mojo::CreateDataPipe(nullptr, producer_handle, consumer_handle),
            MOJO_RESULT_OK);

  DataPipeBytesConsumer::CompletionNotifier* notifier = nullptr;
  DataPipeBytesConsumer* consumer = MakeGarbageCollected<DataPipeBytesConsumer>(
      task_runner_, std::move(consumer_handle), &notifier);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());

  base::span<const char> buffer;
  Result rv = consumer->BeginRead(buffer);
  EXPECT_EQ(Result::kShouldWait, rv);

  producer_handle.reset();
  rv = consumer->BeginRead(buffer);
  EXPECT_EQ(Result::kShouldWait, rv);
  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());

  notifier->SignalError(BytesConsumer::Error());
  EXPECT_EQ(PublicState::kErrored, consumer->GetPublicState());

  rv = consumer->BeginRead(buffer);
  EXPECT_EQ(Result::kError, rv);
}

TEST_F(DataPipeBytesConsumerTest, SignalSizeBeforeRead) {
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::ScopedDataPipeProducerHandle writable;
  const MojoCreateDataPipeOptions options{
      sizeof(MojoCreateDataPipeOptions), MOJO_CREATE_DATA_PIPE_FLAG_NONE, 1, 0};
  ASSERT_EQ(MOJO_RESULT_OK, mojo::CreateDataPipe(&options, writable, readable));
  DataPipeBytesConsumer::CompletionNotifier* notifier = nullptr;
  DataPipeBytesConsumer* consumer = MakeGarbageCollected<DataPipeBytesConsumer>(
      task_runner_, std::move(readable), &notifier);

  const std::string_view kData = "hello";
  size_t actually_written_bytes = 0;
  MojoResult write_result =
      writable->WriteData(base::as_byte_span(kData), MOJO_WRITE_DATA_FLAG_NONE,
                          actually_written_bytes);
  ASSERT_EQ(MOJO_RESULT_OK, write_result);
  ASSERT_EQ(5u, actually_written_bytes);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());

  notifier->SignalSize(5);

  base::span<const char> buffer;
  Result rv = consumer->BeginRead(buffer);
  ASSERT_EQ(Result::kOk, rv);
  EXPECT_EQ(buffer.size(), 5u);

  rv = consumer->EndRead(2);
  ASSERT_EQ(Result::kOk, rv);

  rv = consumer->BeginRead(buffer);
  ASSERT_EQ(Result::kOk, rv);
  EXPECT_EQ(buffer.size(), 3u);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());
  rv = consumer->EndRead(3);
  ASSERT_EQ(Result::kDone, rv);
  EXPECT_EQ(PublicState::kClosed, consumer->GetPublicState());
}

TEST_F(DataPipeBytesConsumerTest, SignalExcessSizeBeforeEndOfData) {
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::ScopedDataPipeProducerHandle writable;
  const MojoCreateDataPipeOptions options{
      sizeof(MojoCreateDataPipeOptions), MOJO_CREATE_DATA_PIPE_FLAG_NONE, 1, 0};
  ASSERT_EQ(MOJO_RESULT_OK, mojo::CreateDataPipe(&options, writable, readable));
  DataPipeBytesConsumer::CompletionNotifier* notifier = nullptr;
  DataPipeBytesConsumer* consumer = MakeGarbageCollected<DataPipeBytesConsumer>(
      task_runner_, std::move(readable), &notifier);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());

  notifier->SignalSize(1);

  base::span<const char> buffer;
  Result rv = consumer->BeginRead(buffer);
  ASSERT_EQ(Result::kShouldWait, rv);

  writable.reset();

  rv = consumer->BeginRead(buffer);
  ASSERT_EQ(Result::kError, rv);

  EXPECT_EQ(PublicState::kErrored, consumer->GetPublicState());
}

TEST_F(DataPipeBytesConsumerTest, SignalExcessSizeAfterEndOfData) {
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::ScopedDataPipeProducerHandle writable;
  const MojoCreateDataPipeOptions options{
      sizeof(MojoCreateDataPipeOptions), MOJO_CREATE_DATA_PIPE_FLAG_NONE, 1, 0};
  ASSERT_EQ(MOJO_RESULT_OK, mojo::CreateDataPipe(&options, writable, readable));
  DataPipeBytesConsumer::CompletionNotifier* notifier = nullptr;
  DataPipeBytesConsumer* consumer = MakeGarbageCollected<DataPipeBytesConsumer>(
      task_runner_, std::move(readable), &notifier);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());

  writable.reset();

  base::span<const char> buffer;
  Result rv = consumer->BeginRead(buffer);
  ASSERT_EQ(Result::kShouldWait, rv);

  notifier->SignalSize(1);

  rv = consumer->BeginRead(buffer);
  ASSERT_EQ(Result::kError, rv);

  EXPECT_EQ(PublicState::kErrored, consumer->GetPublicState());
}

TEST_F(DataPipeBytesConsumerTest, SignalSizeAfterRead) {
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::ScopedDataPipeProducerHandle writable;
  const MojoCreateDataPipeOptions options{
      sizeof(MojoCreateDataPipeOptions), MOJO_CREATE_DATA_PIPE_FLAG_NONE, 1, 0};
  ASSERT_EQ(MOJO_RESULT_OK, mojo::CreateDataPipe(&options, writable, readable));

  DataPipeBytesConsumer::CompletionNotifier* notifier = nullptr;
  DataPipeBytesConsumer* consumer = MakeGarbageCollected<DataPipeBytesConsumer>(
      task_runner_, std::move(readable), &notifier);

  const std::string_view kData = "hello";
  size_t actually_written_bytes = 0;
  MojoResult write_result =
      writable->WriteData(base::as_byte_span(kData), MOJO_WRITE_DATA_FLAG_NONE,
                          actually_written_bytes);
  ASSERT_EQ(MOJO_RESULT_OK, write_result);
  ASSERT_EQ(5u, actually_written_bytes);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());

  base::span<const char> buffer;
  Result rv = consumer->BeginRead(buffer);
  ASSERT_EQ(Result::kOk, rv);
  EXPECT_EQ(buffer.size(), 5u);

  rv = consumer->EndRead(5);
  ASSERT_EQ(Result::kOk, rv);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());
  notifier->SignalSize(5);
  EXPECT_EQ(PublicState::kClosed, consumer->GetPublicState());
}

TEST_F(DataPipeBytesConsumerTest, ErrorBeforeEndOfPipe) {
  mojo::ScopedDataPipeProducerHandle producer_handle;
  mojo::ScopedDataPipeConsumerHandle consumer_handle;
  ASSERT_EQ(mojo::CreateDataPipe(nullptr, producer_handle, consumer_handle),
            MOJO_RESULT_OK);

  DataPipeBytesConsumer::CompletionNotifier* notifier = nullptr;
  DataPipeBytesConsumer* consumer = MakeGarbageCollected<DataPipeBytesConsumer>(
      task_runner_, std::move(consumer_handle), &notifier);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());

  base::span<const char> buffer;
  Result rv = consumer->BeginRead(buffer);
  EXPECT_EQ(Result::kShouldWait, rv);

  notifier->SignalError(BytesConsumer::Error());
  EXPECT_EQ(PublicState::kErrored, consumer->GetPublicState());

  rv = consumer->BeginRead(buffer);
  EXPECT_EQ(Result::kError, rv);

  producer_handle.reset();
  rv = consumer->BeginRead(buffer);
  EXPECT_EQ(Result::kError, rv);
  EXPECT_EQ(PublicState::kErrored, consumer->GetPublicState());
}

// Verify that draining the DataPipe and SignalComplete() will
// close the DataPipeBytesConsumer.
TEST_F(DataPipeBytesConsumerTest, DrainPipeBeforeComplete) {
  mojo::ScopedDataPipeProducerHandle producer_handle;
  mojo::ScopedDataPipeConsumerHandle consumer_handle;
  ASSERT_EQ(mojo::CreateDataPipe(nullptr, producer_handle, consumer_handle),
            MOJO_RESULT_OK);

  DataPipeBytesConsumer::CompletionNotifier* notifier = nullptr;
  DataPipeBytesConsumer* consumer = MakeGarbageCollected<DataPipeBytesConsumer>(
      task_runner_, std::move(consumer_handle), &notifier);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());

  base::span<const char> buffer;
  Result rv = consumer->BeginRead(buffer);
  EXPECT_EQ(Result::kShouldWait, rv);

  mojo::ScopedDataPipeConsumerHandle drained = consumer->DrainAsDataPipe();
  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());

  rv = consumer->BeginRead(buffer);
  EXPECT_EQ(Result::kShouldWait, rv);
  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());

  notifier->SignalComplete();
  EXPECT_EQ(PublicState::kClosed, consumer->GetPublicState());

  rv = consumer->BeginRead(buffer);
  EXPECT_EQ(Result::kDone, rv);
}

TEST_F(DataPipeBytesConsumerTest, CompleteBeforeDrainPipe) {
  mojo::ScopedDataPipeProducerHandle producer_handle;
  mojo::ScopedDataPipeConsumerHandle consumer_handle;
  ASSERT_EQ(mojo::CreateDataPipe(nullptr, producer_handle, consumer_handle),
            MOJO_RESULT_OK);

  DataPipeBytesConsumer::CompletionNotifier* notifier = nullptr;
  DataPipeBytesConsumer* consumer = MakeGarbageCollected<DataPipeBytesConsumer>(
      task_runner_, std::move(consumer_handle), &notifier);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());

  base::span<const char> buffer;
  Result rv = consumer->BeginRead(buffer);
  EXPECT_EQ(Result::kShouldWait, rv);

  notifier->SignalComplete();
  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());

  rv = consumer->BeginRead(buffer);
  EXPECT_EQ(Result::kShouldWait, rv);

  mojo::ScopedDataPipeConsumerHandle drained = consumer->DrainAsDataPipe();
  EXPECT_EQ(PublicState::kClosed, consumer->GetPublicState());

  rv = consumer->BeginRead(buffer);
  EXPECT_EQ(Result::kDone, rv);
  EXPECT_EQ(PublicState::kClosed, consumer->GetPublicState());
}

}  // namespace blink

"""

```