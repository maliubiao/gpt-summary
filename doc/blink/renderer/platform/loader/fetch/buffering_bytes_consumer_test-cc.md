Response:
The user wants to understand the functionality of the `buffering_bytes_consumer_test.cc` file in the Chromium Blink engine. I need to:

1. **Identify the purpose of the file:** Based on the name and content, it's a test file for the `BufferingBytesConsumer` class.
2. **Explain the functionality of `BufferingBytesConsumer`:** This class likely buffers data received from a `BytesConsumer` before making it available to a reader.
3. **Check for relationships with web technologies (JavaScript, HTML, CSS):** Determine if data buffering at this level directly impacts how these technologies function.
4. **Analyze the test cases:** Examine each `TEST_F` to understand the specific scenarios being tested and infer the behavior of `BufferingBytesConsumer`.
5. **Infer input and output:** Based on the test cases, deduce the expected input to the `BufferingBytesConsumer` and the corresponding output.
6. **Identify potential usage errors:** Look for test cases that might highlight common mistakes when using the `BufferingBytesConsumer`.
这个文件 `buffering_bytes_consumer_test.cc` 是 Chromium Blink 引擎中用于测试 `BufferingBytesConsumer` 类的单元测试文件。它的主要功能是验证 `BufferingBytesConsumer` 类的各种行为和功能是否符合预期。

以下是它测试的主要功能点：

1. **基本读取 (Read):**
   - 测试 `BufferingBytesConsumer` 能否正确地从底层的 `BytesConsumer` 中读取数据，并将数据传递给读取者。
   - **假设输入:** 底层的 `ReplayingBytesConsumer` 模拟产生数据 "1", 然后等待，再产生 "23", "4", "567", "8"，最后完成。
   - **预期输出:** `BufferingBytesConsumer` 的读取者最终能接收到完整的数据 "12345678"。

2. **延迟读取 (ReadWithDelay):**
   - 测试 `BufferingBytesConsumer::CreateWithDelay` 创建的消费者，在初始延迟期间不会立即读取底层消费者的数据，但在延迟结束后仍然能够正确读取数据。
   - 这可能与资源加载的优化有关，例如，延迟加载某些资源，直到需要时才真正开始读取。

3. **缓冲行为 (Buffering):**
   - 测试 `BufferingBytesConsumer` 能否缓冲来自底层 `BytesConsumer` 的数据。即使底层消费者在读取过程中有等待（`Command::kWait`），`BufferingBytesConsumer` 仍然可以继续读取已经到达的数据。
   - 这有助于提高性能，因为它允许在数据可用时尽可能多地读取，而不需要读取者主动请求。

4. **带延迟的缓冲行为 (BufferingWithDelay):**
   - 结合了延迟读取和缓冲行为的测试。验证在初始延迟期间，`BufferingBytesConsumer` 不会主动读取底层消费者，但在延迟结束后会缓冲所有可用的数据。

5. **停止缓冲 (StopBuffering):**
   - 测试调用 `StopBuffering()` 方法后，`BufferingBytesConsumer` 是否会停止继续从底层消费者读取数据，并保持当前已读取的状态。
   - 这可能用于在某些情况下停止预加载或缓冲，以节省资源。

6. **作为数据管道排出 (DrainAsDataPipe):**
   - 测试将 `BufferingBytesConsumer` 转换为 `mojo::ScopedDataPipeConsumerHandle` 的能力。
   - **不带延迟:** 测试表明，如果没有延迟，尝试 `DrainAsDataPipe()` 会失败。这可能是因为在没有延迟的情况下，缓冲消费者可能还未准备好提供完整的管道。
   - **带延迟:** 测试表明，通过 `CreateWithDelay` 创建的缓冲消费者可以成功地被排出为数据管道。这暗示了延迟机制可能允许缓冲消费者在被排出前先完成必要的初始化或数据接收。
   - **延迟过期:** 测试表明，如果延迟已经过期，尝试 `DrainAsDataPipe()` 也会失败。这可能是因为在延迟过期后，缓冲消费者可能已经开始主动读取和处理数据，不再适合作为原始数据管道直接输出。

7. **最大缓冲字节数限制 (BufferingBytesConsumerMaxBytesTest):**
   - 这是一组参数化测试，用于测试当底层消费者产生大量数据时，`BufferingBytesConsumer` 的行为。
   - 它测试了在启用最大缓冲大小限制的情况下，读取大型资源是否成功，以及在遇到错误时的处理情况。
   - 这部分与浏览器的资源加载优化和内存管理有关，防止无限制地缓冲大量数据导致内存溢出。

**与 JavaScript, HTML, CSS 的关系:**

`BufferingBytesConsumer` 本身并不直接操作 JavaScript, HTML 或 CSS 的语法或解释执行。它处于更底层的网络数据处理层。然而，它的功能对于这些技术至关重要：

* **资源加载 (HTML, CSS, JavaScript, 图片等):** 当浏览器请求一个网页资源（例如 HTML 文件、CSS 样式表、JavaScript 文件或图片）时，网络层会下载这些数据。`BufferingBytesConsumer` 可以被用作处理这些下载数据的中间层。
    * **例子:** 当浏览器下载一个大的 JavaScript 文件时，`BufferingBytesConsumer` 可以先缓冲一部分数据，使得解析器可以尽早开始解析已经下载的部分，而不需要等待整个文件下载完成。这可以提高页面加载速度和用户体验。
    * **例子:** 对于流式 HTML 文档，`BufferingBytesConsumer` 可以缓冲一部分 HTML 内容，使得渲染引擎可以逐步渲染页面，而不是等待整个 HTML 文档下载完毕。

* **数据流处理:**  对于通过 Fetch API 或 XMLHttpRequest 获取的数据，`BufferingBytesConsumer` 可以帮助管理接收到的数据块。

**逻辑推理的假设输入与输出:**

以 `TEST_F(BufferingBytesConsumerTest, Read)` 为例：

* **假设输入:**
    * 底层 `ReplayingBytesConsumer` 按顺序产生以下命令：
        * `Command(Command::kWait)`
        * `Command(Command::kData, "1")`
        * `Command(Command::kWait)`
        * `Command(Command::kWait)`
        * `Command(Command::kData, "23")`
        * `Command(Command::kData, "4")`
        * `Command(Command::kData, "567")`
        * `Command(Command::kData, "8")`
        * `Command(Command::kDone)`
* **预期输出:**
    * `bytes_consumer->GetPublicState()` 最终变为 `PublicState::kClosed`。
    * `reader->Run(task_runner.get())` 返回的 `result.first` 为 `Result::kDone`。
    * `reader->Run(task_runner.get())` 返回的 `result.second` 转换为字符串后为 `"12345678"`。

**用户或编程常见的使用错误:**

虽然 `BufferingBytesConsumer` 主要是内部使用的类，但了解其行为有助于避免在相关场景中出现错误：

* **过早地将带延迟的缓冲消费者作为数据管道排出:**  `TEST_F(BufferingBytesConsumerTest, DrainAsDataPipeFailsWithoutDelay)` 和 `TEST_F(BufferingBytesConsumerTest, DrainAsDataPipeFailsWithExpiredDelay)` 表明，在没有完成延迟或延迟过期后，尝试将缓冲消费者直接转换为数据管道可能会失败。 开发者需要理解延迟的概念，并确保在适当的时机执行排出操作。
* **假设缓冲会立即发生:**  `TEST_F(BufferingBytesConsumerTest, ReadWithDelay)` 强调了带延迟的缓冲消费者在初始阶段不会立即读取数据。如果开发者期望数据立即可用，使用带延迟的缓冲消费者可能会导致意外的行为。
* **不理解 `StopBuffering()` 的作用:** 开发者可能会错误地认为调用 `StopBuffering()` 会清空已缓冲的数据，但实际上它只是停止继续读取底层数据。

总而言之，`buffering_bytes_consumer_test.cc` 通过各种测试用例，详细验证了 `BufferingBytesConsumer` 类的缓冲、延迟、数据管道转换等核心功能，确保其在 Chromium 引擎中能够正确高效地处理网络数据。 这对于最终用户来说意味着更快的页面加载速度和更流畅的网络体验。

Prompt: 
```
这是目录为blink/renderer/platform/loader/fetch/buffering_bytes_consumer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/buffering_bytes_consumer.h"

#include "base/strings/stringprintf.h"
#include "base/test/task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/platform/loader/fetch/data_pipe_bytes_consumer.h"
#include "third_party/blink/renderer/platform/loader/testing/bytes_consumer_test_reader.h"
#include "third_party/blink/renderer/platform/loader/testing/replaying_bytes_consumer.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_task_runner.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {
namespace {

class BufferingBytesConsumerTest : public testing::Test {
 public:
  BufferingBytesConsumerTest()
      : task_environment_(base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}

  using Command = ReplayingBytesConsumer::Command;
  using Result = BytesConsumer::Result;
  using PublicState = BytesConsumer::PublicState;

 protected:
  mojo::ScopedDataPipeConsumerHandle MakeDataPipe() {
    MojoCreateDataPipeOptions data_pipe_options{
        sizeof(MojoCreateDataPipeOptions), MOJO_CREATE_DATA_PIPE_FLAG_NONE, 1,
        0};
    mojo::ScopedDataPipeConsumerHandle consumer_handle;
    mojo::ScopedDataPipeProducerHandle producer_handle;
    CHECK_EQ(MOJO_RESULT_OK,
             mojo::CreateDataPipe(&data_pipe_options, producer_handle,
                                  consumer_handle));
    return consumer_handle;
  }

  base::test::TaskEnvironment task_environment_;
};

TEST_F(BufferingBytesConsumerTest, Read) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* replaying_bytes_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);

  replaying_bytes_consumer->Add(Command(Command::kWait));
  replaying_bytes_consumer->Add(Command(Command::kData, "1"));
  replaying_bytes_consumer->Add(Command(Command::kWait));
  replaying_bytes_consumer->Add(Command(Command::kWait));
  replaying_bytes_consumer->Add(Command(Command::kData, "23"));
  replaying_bytes_consumer->Add(Command(Command::kData, "4"));
  replaying_bytes_consumer->Add(Command(Command::kData, "567"));
  replaying_bytes_consumer->Add(Command(Command::kData, "8"));
  replaying_bytes_consumer->Add(Command(Command::kDone));

  auto* bytes_consumer =
      BufferingBytesConsumer::Create(replaying_bytes_consumer);

  EXPECT_EQ(PublicState::kReadableOrWaiting, bytes_consumer->GetPublicState());
  auto* reader = MakeGarbageCollected<BytesConsumerTestReader>(bytes_consumer);
  auto result = reader->Run(task_runner.get());

  EXPECT_EQ(PublicState::kClosed, bytes_consumer->GetPublicState());
  ASSERT_EQ(result.first, Result::kDone);
  EXPECT_EQ("12345678", String(result.second));
}

TEST_F(BufferingBytesConsumerTest, ReadWithDelay) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* replaying_bytes_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);

  replaying_bytes_consumer->Add(Command(Command::kWait));
  replaying_bytes_consumer->Add(Command(Command::kData, "1"));
  replaying_bytes_consumer->Add(Command(Command::kWait));
  replaying_bytes_consumer->Add(Command(Command::kWait));
  replaying_bytes_consumer->Add(Command(Command::kData, "23"));
  replaying_bytes_consumer->Add(Command(Command::kData, "4"));
  replaying_bytes_consumer->Add(Command(Command::kData, "567"));
  replaying_bytes_consumer->Add(Command(Command::kData, "8"));
  replaying_bytes_consumer->Add(Command(Command::kDone));

  auto* bytes_consumer = BufferingBytesConsumer::CreateWithDelay(
      replaying_bytes_consumer,
      scheduler::GetSingleThreadTaskRunnerForTesting());

  task_runner->RunUntilIdle();

  // The underlying consumer should not have been read yet due to the delay.
  EXPECT_EQ(PublicState::kReadableOrWaiting, bytes_consumer->GetPublicState());
  EXPECT_EQ(PublicState::kReadableOrWaiting,
            replaying_bytes_consumer->GetPublicState());

  auto* reader = MakeGarbageCollected<BytesConsumerTestReader>(bytes_consumer);
  auto result = reader->Run(task_runner.get());

  // Reading before the delay expires should still work correctly.
  EXPECT_EQ(PublicState::kClosed, bytes_consumer->GetPublicState());
  ASSERT_EQ(result.first, Result::kDone);
  EXPECT_EQ("12345678", String(result.second));
}

TEST_F(BufferingBytesConsumerTest, Buffering) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* replaying_bytes_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);

  replaying_bytes_consumer->Add(Command(Command::kWait));
  replaying_bytes_consumer->Add(Command(Command::kData, "1"));
  replaying_bytes_consumer->Add(Command(Command::kData, "23"));
  replaying_bytes_consumer->Add(Command(Command::kData, "4"));
  replaying_bytes_consumer->Add(Command(Command::kWait));
  replaying_bytes_consumer->Add(Command(Command::kData, "567"));
  replaying_bytes_consumer->Add(Command(Command::kData, "8"));
  replaying_bytes_consumer->Add(Command(Command::kDone));

  auto* bytes_consumer =
      BufferingBytesConsumer::Create(replaying_bytes_consumer);

  EXPECT_EQ(PublicState::kReadableOrWaiting, bytes_consumer->GetPublicState());
  EXPECT_EQ(PublicState::kReadableOrWaiting,
            replaying_bytes_consumer->GetPublicState());

  task_runner->RunUntilIdle();

  EXPECT_EQ(PublicState::kReadableOrWaiting, bytes_consumer->GetPublicState());
  EXPECT_EQ(PublicState::kClosed, replaying_bytes_consumer->GetPublicState());

  auto* reader = MakeGarbageCollected<BytesConsumerTestReader>(bytes_consumer);
  auto result = reader->Run(task_runner.get());

  EXPECT_EQ(PublicState::kClosed, bytes_consumer->GetPublicState());
  ASSERT_EQ(result.first, Result::kDone);
  EXPECT_EQ("12345678", String(result.second));
}

TEST_F(BufferingBytesConsumerTest, BufferingWithDelay) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* replaying_bytes_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);

  replaying_bytes_consumer->Add(Command(Command::kWait));
  replaying_bytes_consumer->Add(Command(Command::kData, "1"));
  replaying_bytes_consumer->Add(Command(Command::kData, "23"));
  replaying_bytes_consumer->Add(Command(Command::kData, "4"));
  replaying_bytes_consumer->Add(Command(Command::kWait));
  replaying_bytes_consumer->Add(Command(Command::kData, "567"));
  replaying_bytes_consumer->Add(Command(Command::kData, "8"));
  replaying_bytes_consumer->Add(Command(Command::kDone));

  auto* bytes_consumer = BufferingBytesConsumer::CreateWithDelay(
      replaying_bytes_consumer,
      scheduler::GetSingleThreadTaskRunnerForTesting());

  EXPECT_EQ(PublicState::kReadableOrWaiting, bytes_consumer->GetPublicState());
  EXPECT_EQ(PublicState::kReadableOrWaiting,
            replaying_bytes_consumer->GetPublicState());

  task_runner->RunUntilIdle();

  // The underlying consumer should not have been read yet due to the delay.
  EXPECT_EQ(PublicState::kReadableOrWaiting, bytes_consumer->GetPublicState());
  EXPECT_EQ(PublicState::kReadableOrWaiting,
            replaying_bytes_consumer->GetPublicState());

  task_environment_.FastForwardBy(base::Milliseconds(51));
  task_runner->RunUntilIdle();

  // After the delay expires the underlying consumer should be completely read.
  EXPECT_EQ(PublicState::kReadableOrWaiting, bytes_consumer->GetPublicState());
  EXPECT_EQ(PublicState::kClosed, replaying_bytes_consumer->GetPublicState());

  auto* reader = MakeGarbageCollected<BytesConsumerTestReader>(bytes_consumer);
  auto result = reader->Run(task_runner.get());

  EXPECT_EQ(PublicState::kClosed, bytes_consumer->GetPublicState());
  ASSERT_EQ(result.first, Result::kDone);
  EXPECT_EQ("12345678", String(result.second));
}

TEST_F(BufferingBytesConsumerTest, StopBuffering) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* replaying_bytes_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);

  replaying_bytes_consumer->Add(Command(Command::kWait));
  replaying_bytes_consumer->Add(Command(Command::kData, "1"));
  replaying_bytes_consumer->Add(Command(Command::kData, "23"));
  replaying_bytes_consumer->Add(Command(Command::kData, "4"));
  replaying_bytes_consumer->Add(Command(Command::kWait));
  replaying_bytes_consumer->Add(Command(Command::kData, "567"));
  replaying_bytes_consumer->Add(Command(Command::kData, "8"));
  replaying_bytes_consumer->Add(Command(Command::kDone));

  auto* bytes_consumer =
      BufferingBytesConsumer::Create(replaying_bytes_consumer);
  bytes_consumer->StopBuffering();

  EXPECT_EQ(PublicState::kReadableOrWaiting, bytes_consumer->GetPublicState());
  EXPECT_EQ(PublicState::kReadableOrWaiting,
            replaying_bytes_consumer->GetPublicState());

  task_runner->RunUntilIdle();

  EXPECT_EQ(PublicState::kReadableOrWaiting, bytes_consumer->GetPublicState());
  EXPECT_EQ(PublicState::kReadableOrWaiting,
            replaying_bytes_consumer->GetPublicState());

  auto* reader = MakeGarbageCollected<BytesConsumerTestReader>(bytes_consumer);
  auto result = reader->Run(task_runner.get());

  EXPECT_EQ(PublicState::kClosed, bytes_consumer->GetPublicState());
  ASSERT_EQ(result.first, Result::kDone);
  EXPECT_EQ("12345678", String(result.second));
}

TEST_F(BufferingBytesConsumerTest, DrainAsDataPipeFailsWithoutDelay) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();

  DataPipeBytesConsumer::CompletionNotifier* notifier = nullptr;
  DataPipeBytesConsumer* data_pipe_consumer =
      MakeGarbageCollected<DataPipeBytesConsumer>(task_runner, MakeDataPipe(),
                                                  &notifier);

  auto* bytes_consumer = BufferingBytesConsumer::Create(data_pipe_consumer);

  EXPECT_EQ(PublicState::kReadableOrWaiting, bytes_consumer->GetPublicState());
  auto pipe = bytes_consumer->DrainAsDataPipe();
  EXPECT_FALSE(pipe.is_valid());
}

TEST_F(BufferingBytesConsumerTest, DrainAsDataPipeSucceedsWithDelay) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();

  DataPipeBytesConsumer::CompletionNotifier* notifier = nullptr;
  DataPipeBytesConsumer* data_pipe_consumer =
      MakeGarbageCollected<DataPipeBytesConsumer>(task_runner, MakeDataPipe(),
                                                  &notifier);

  auto* bytes_consumer = BufferingBytesConsumer::CreateWithDelay(
      data_pipe_consumer, scheduler::GetSingleThreadTaskRunnerForTesting());

  EXPECT_EQ(PublicState::kReadableOrWaiting, bytes_consumer->GetPublicState());
  auto drained_consumer_handle = bytes_consumer->DrainAsDataPipe();
  EXPECT_TRUE(drained_consumer_handle.is_valid());
}

TEST_F(BufferingBytesConsumerTest, DrainAsDataPipeFailsWithExpiredDelay) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();

  DataPipeBytesConsumer::CompletionNotifier* notifier = nullptr;
  DataPipeBytesConsumer* data_pipe_consumer =
      MakeGarbageCollected<DataPipeBytesConsumer>(task_runner, MakeDataPipe(),
                                                  &notifier);

  auto* bytes_consumer = BufferingBytesConsumer::CreateWithDelay(
      data_pipe_consumer, scheduler::GetSingleThreadTaskRunnerForTesting());

  task_environment_.FastForwardBy(base::Milliseconds(51));

  EXPECT_EQ(PublicState::kReadableOrWaiting, bytes_consumer->GetPublicState());
  auto drained_consumer_handle = bytes_consumer->DrainAsDataPipe();
  EXPECT_FALSE(drained_consumer_handle.is_valid());
}

constexpr size_t kMaxBufferSize = BufferingBytesConsumer::kMaxBufferSize;

struct MaxBytesParams {
  size_t chunk_size;
  size_t total_size;
};

class BufferingBytesConsumerMaxBytesTest
    : public BufferingBytesConsumerTest,
      public ::testing::WithParamInterface<MaxBytesParams> {
 protected:
  BufferingBytesConsumerMaxBytesTest()
      : task_runner_(base::MakeRefCounted<scheduler::FakeTaskRunner>()),
        replaying_bytes_consumer_(
            MakeGarbageCollected<ReplayingBytesConsumer>(task_runner_)) {}

  size_t ChunkSize() const { return GetParam().chunk_size; }

  size_t TotalSize() const { return GetParam().total_size; }

  // Adds `TotalSize()` / `ChunkSize()` chunks to `consumer` of size
  // `ChunkSize()`.
  void FillReplayingBytesConsumer() {
    CHECK_EQ(TotalSize() % ChunkSize(), 0u);
    Vector<char> chunk(ChunkSize(), 'a');
    for (size_t size = 0; size < TotalSize(); size += ChunkSize()) {
      replaying_bytes_consumer_->Add(Command(Command::kData, chunk));
    }
  }

  std::pair<Result, Vector<char>> Read(BufferingBytesConsumer* consumer) {
    auto* reader = MakeGarbageCollected<BytesConsumerTestReader>(consumer);
    reader->set_max_chunk_size(ChunkSize());
    return reader->Run(task_runner_.get());
  }

  scoped_refptr<scheduler::FakeTaskRunner> task_runner_;
  ScopedBufferedBytesConsumerLimitSizeForTest feature_{true};
  Persistent<ReplayingBytesConsumer> replaying_bytes_consumer_;
};

TEST_P(BufferingBytesConsumerMaxBytesTest, ReadLargeResourceSuccessfully) {
  FillReplayingBytesConsumer();

  replaying_bytes_consumer_->Add(Command(Command::kDone));

  auto* bytes_consumer =
      BufferingBytesConsumer::Create(replaying_bytes_consumer_);

  EXPECT_EQ(PublicState::kReadableOrWaiting, bytes_consumer->GetPublicState());
  EXPECT_EQ(PublicState::kReadableOrWaiting,
            replaying_bytes_consumer_->GetPublicState());

  task_runner_->RunUntilIdle();

  EXPECT_EQ(PublicState::kReadableOrWaiting, bytes_consumer->GetPublicState());
  EXPECT_EQ(PublicState::kReadableOrWaiting,
            replaying_bytes_consumer_->GetPublicState());

  auto [result, data] = Read(bytes_consumer);

  EXPECT_EQ(PublicState::kClosed, bytes_consumer->GetPublicState());
  ASSERT_EQ(result, Result::kDone);
  ASSERT_EQ(data.size(), TotalSize());
}

TEST_P(BufferingBytesConsumerMaxBytesTest, ReadLargeResourceWithError) {
  FillReplayingBytesConsumer();

  replaying_bytes_consumer_->Add(Command(Command::kError));

  auto* bytes_consumer =
      BufferingBytesConsumer::Create(replaying_bytes_consumer_);

  EXPECT_EQ(PublicState::kReadableOrWaiting, bytes_consumer->GetPublicState());
  EXPECT_EQ(PublicState::kReadableOrWaiting,
            replaying_bytes_consumer_->GetPublicState());

  task_runner_->RunUntilIdle();

  EXPECT_EQ(PublicState::kReadableOrWaiting, bytes_consumer->GetPublicState());
  EXPECT_EQ(PublicState::kReadableOrWaiting,
            replaying_bytes_consumer_->GetPublicState());

  auto [result, data] = Read(bytes_consumer);

  EXPECT_EQ(PublicState::kErrored, bytes_consumer->GetPublicState());
  ASSERT_EQ(result, Result::kError);
}

std::string PrintToString(const MaxBytesParams& params) {
  auto& [chunk_size, total_size] = params;
  return base::StringPrintf("%zu_%zu", chunk_size, total_size);
}

constexpr size_t kSixDigitPrime = 665557;
constexpr size_t kNextMultipleOfSixDigitPrimeAfterMaxBufferSize =
    ((kMaxBufferSize + kSixDigitPrime) / kSixDigitPrime) * kSixDigitPrime;

INSTANTIATE_TEST_SUITE_P(
    BufferingBytesConsumerMaxBytesTest,
    BufferingBytesConsumerMaxBytesTest,
    ::testing::Values(MaxBytesParams{1024 * 1024, kMaxBufferSize + 1024 * 1024},
                      MaxBytesParams{
                          kSixDigitPrime,
                          kNextMultipleOfSixDigitPrimeAfterMaxBufferSize},
                      MaxBytesParams{1024 * 1024, kMaxBufferSize},
                      MaxBytesParams{kMaxBufferSize, kMaxBufferSize}),
    ::testing::PrintToStringParamName());

}  // namespace
}  // namespace blink

"""

```