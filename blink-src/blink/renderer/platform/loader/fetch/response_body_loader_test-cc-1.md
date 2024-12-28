Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a test file for the Chromium Blink engine. The code specifically tests the `ResponseBodyLoader` class. I need to identify what aspects of `ResponseBodyLoader` are being tested and how these relate to web functionalities (JavaScript, HTML, CSS) if at all. The prompt also asks for examples of logical reasoning (input/output scenarios) and potential user/programming errors the tests might be preventing. Finally, it asks for a summary of the code.

Here's a breakdown of the code and my thought process:

1. **Identify the Core Class Under Test:** The code uses `ResponseBodyLoader` and interacts with it through a `BytesConsumer`. This is the central component.

2. **Analyze the Test Fixtures:**  There are several test fixtures (`ResponseBodyLoaderTest`, `ResponseBodyLoaderDrainedBytesConsumerNotificationOutOfOnStateChangeTest`, `ResponseBodyLoaderDrainedBytesConsumerNotificationInOnStateChangeTest`, `ResponseBodyLoaderTestAllowDrainAsBytesConsumerInBFCache`). This suggests different scenarios and configurations for testing `ResponseBodyLoader`.

3. **Examine the Individual Tests:** Each `TEST_F` function represents a specific test case. I need to understand what each test is verifying.

    * **Basic Functionality:**  Tests like `Basic` check the initial state and successful draining of the body.
    * **Draining as Bytes Consumer:** Several tests use `DrainAsBytesConsumer()`, indicating they're testing how the body loader behaves when its content is consumed as a stream of bytes. This is important for efficiently handling large response bodies.
    * **Error Handling:** Tests with `Error` in their name (e.g., `DrainWithError`) are clearly testing how the loader handles errors during the loading process.
    * **Cancellation:** Tests involving `Cancel()` verify the cancellation mechanism.
    * **State Change Notifications:** Tests with "NotificationOutOfOnStateChange" and "NotificationInOnStateChange" are testing how the `ResponseBodyLoader` informs its clients (like `TestClient`) about changes in loading state. The "InOnStateChange" tests seem to explore scenarios where the notification happens during a specific operation.
    * **`BeginRead`, `EndRead`:**  These tests simulate a manual reading process from the `BytesConsumer`, checking the `Result` of these operations (`kShouldWait`, `kOk`, `kDone`, `kError`).
    * **Data Pipe:** The `DrainAsDataPipe` test verifies if the loader can efficiently transfer data to a Mojo data pipe, which is a mechanism for inter-process communication in Chromium.
    * **Back/Forward Cache (BFCache):** The `ResponseBodyLoaderTestAllowDrainAsBytesConsumerInBFCache` fixture and its test demonstrate how the `ResponseBodyLoader` behaves when a page is put into the BFCache and then restored. This test is particularly focused on ensuring data processing continues correctly even when the loader is suspended.

4. **Connect to Web Functionalities:**

    * **JavaScript:** When a JavaScript `fetch()` call is made, or when a resource is loaded due to an HTML tag (like `<script src="...">`), the browser uses components like `ResponseBodyLoader` to retrieve the content. The tests involving successful data transfer (`kOk`, `kDone`) and error handling (`kError`) are directly relevant to how JavaScript code will perceive the outcome of a network request. If a request fails (tested by error scenarios), JavaScript might receive an error event.
    * **HTML:** When the browser parses an HTML document, it might encounter `<img>` tags or other resources that need to be fetched. `ResponseBodyLoader` is involved in fetching the data for these resources. The tests for success and errors are relevant here. The BFCache tests are also crucial for ensuring that cached HTML pages load quickly and correctly.
    * **CSS:** Similarly, when the browser encounters `<link rel="stylesheet">` tags, `ResponseBodyLoader` fetches the CSS. The same principles of successful loading, error handling, and caching apply.

5. **Identify Logical Reasoning and Input/Output:**  The tests often set up a specific sequence of commands for the `ReplayingBytesConsumer` (acting as the data source) and then check the resulting state of the `TestClient`. For example:

    * **Input:**  `original_consumer->Add(Command(Command::kData, "hello")); original_consumer->Add(Command(Command::kDone));`
    * **Output:** `EXPECT_TRUE(client->LoadingIsFinished()); EXPECT_EQ("hello", client->GetData());`

6. **Identify Potential User/Programming Errors:** The tests help prevent various errors:

    * **Incorrect Error Handling:** Without tests for error conditions, developers might not implement proper error handling in JavaScript when network requests fail.
    * **Prematurely Assuming Loading is Complete:** Tests involving `BeginRead` and `EndRead` ensure that the client correctly waits for data and doesn't assume the data is available before it is.
    * **Race Conditions in Asynchronous Operations:** The tests involving task runners and asynchronous operations help ensure that state changes and notifications are handled correctly even when events occur out of order. The "InOnStateChange" vs. "OutOfOnStateChange" tests specifically address potential issues with how notifications are delivered.
    * **Issues with Caching:** The BFCache tests are crucial for preventing bugs that could cause cached pages to load incorrectly or fail to load at all.

7. **Summarize the Functionality:**  The code tests the `ResponseBodyLoader`'s ability to handle various scenarios during the process of loading the body of an HTTP response. This includes successful loading, error conditions, cancellation, efficient data streaming, and integration with caching mechanisms like the back/forward cache. The tests verify the correct sequencing of events and the accurate notification of loading state to clients.

By following this thought process, I can generate a comprehensive and accurate summary of the provided code snippet.
这是对 `blink/renderer/platform/loader/fetch/response_body_loader_test.cc` 文件第二部分的分析总结。结合第一部分，我们可以归纳出 `ResponseBodyLoader` 的主要功能以及相关的测试覆盖范围。

**综合两部分内容，`ResponseBodyLoader` 的主要功能是：**

`ResponseBodyLoader` 负责管理和处理 HTTP 响应的主体（body）数据的加载过程。它作为一个中间层，连接了数据源（例如网络连接）和数据的消费者（例如渲染引擎、JavaScript）。

**具体功能点和测试覆盖范围：**

1. **数据接收和传递:**
   - `ResponseBodyLoader` 从底层的数据源接收响应主体的数据。
   - 它将接收到的数据传递给 `BytesConsumer` 进行消费。
   - 测试覆盖了成功接收和传递数据的场景 (`Basic` 测试，以及其他 `BeginRead`/`EndRead` 成功的测试)。
   - 测试覆盖了数据分块接收的场景（通过 `ReplayingBytesConsumer` 模拟）。

2. **错误处理:**
   - `ResponseBodyLoader` 能够处理数据加载过程中出现的错误。
   - 当发生错误时，它会通知相应的客户端 (`TestClient`)。
   - 测试覆盖了多种错误场景，例如底层数据源返回错误 (`DrainWithError`)，以及在读取过程中发生错误 (`BeginReadAndError`)。

3. **加载完成:**
   - `ResponseBodyLoader` 能够检测到数据加载完成（无论是成功完成还是发生错误）。
   - 它会在加载完成后通知相应的客户端。
   - 测试覆盖了成功加载完成 (`Basic`, `BeginReadAndDone`, `EndReadAndDone`) 和加载失败 (`DrainWithError`, `BeginReadAndError`) 的场景。

4. **取消加载:**
   - `ResponseBodyLoader` 允许取消正在进行的加载操作。
   - 取消操作会通知相应的客户端。
   - 测试覆盖了取消加载的场景 (`Cancel`)。

5. **数据消费方式:**
   - `ResponseBodyLoader` 提供了多种消费主体数据的方式。
   - **直接消费 (`Drain`)**:  测试了直接将数据传递给 `String` 或 `Vector` 进行消费。
   - **作为 `BytesConsumer` 消费 (`DrainAsBytesConsumer`)**:  允许客户端通过 `BytesConsumer` 接口逐步读取数据。这种方式更灵活，可以处理大型响应主体。测试覆盖了 `DrainAsBytesConsumer` 的多种交互场景，包括 `BeginRead`、`EndRead` 等操作，以及错误和完成状态。
   - **作为 `DataPipe` 消费 (`DrainAsDataPipe`)**:  允许将数据通过 Mojo DataPipe 传递给其他进程或组件。测试覆盖了这种方式。

6. **状态管理和通知:**
   - `ResponseBodyLoader` 维护着加载的状态（例如，可读、等待、完成、错误）。
   - 它通过 `BytesConsumer::Client` 接口通知客户端状态变化。
   - 测试覆盖了状态变化的通知机制，包括在 `OnStateChange` 回调内部和外部进行通知 (`ResponseBodyLoaderDrainedBytesConsumerNotificationOutOfOnStateChangeTest`, `ResponseBodyLoaderDrainedBytesConsumerNotificationInOnStateChangeTest`)。这有助于确保异步操作的正确性。

7. **与 Back/Forward Cache (BFCache) 的集成:**
   - `ResponseBodyLoader` 需要支持浏览器的 Back/Forward Cache 机制。
   - 当页面被放入 BFCache 时，加载过程可能会被暂停和恢复。
   - 测试覆盖了在 `ResponseBodyLoader` 被暂停和恢复的情况下，数据消费仍然能够正确进行 (`ResponseBodyLoaderTestAllowDrainAsBytesConsumerInBFCache`)。这个测试特别关注了 `DrainAsBytesConsumer` 在 BFCache 中的行为。

**与 JavaScript, HTML, CSS 的关系举例:**

- **JavaScript `fetch()` API:** 当 JavaScript 代码使用 `fetch()` 发起网络请求时，浏览器内部会使用 `ResponseBodyLoader` 来下载响应主体。测试中模拟的成功加载场景对应着 `fetch()` 返回的 Promise resolve 的情况，而错误场景对应着 Promise reject 的情况。
- **HTML `<img>` 标签:** 当浏览器解析 HTML 遇到 `<img>` 标签时，会发起图片资源的请求。`ResponseBodyLoader` 负责下载图片数据。测试中的数据接收和传递功能与此相关。如果加载失败，`<img>` 可能会显示 broken image 图标，这与错误处理测试相关。
- **CSS `<link>` 标签:**  浏览器加载 CSS 文件的方式与加载图片类似，`ResponseBodyLoader` 负责下载 CSS 文件内容。

**逻辑推理的假设输入与输出举例:**

- **假设输入:**  `original_consumer` 按顺序添加了 `Command::kData` ("hello") 和 `Command::kDone`。
- **输出:**  `client->LoadingIsFinished()` 为 `true`，`client->GetData()` 返回 "hello"。这表明成功接收并传递了所有数据，并正确标记了加载完成。

- **假设输入:** `original_consumer` 添加了 `Command::kData` ("error occurred") 后添加了 `Command::kError`。
- **输出:** `client->LoadingIsFailed()` 为 `true`。这表明 `ResponseBodyLoader` 检测到了错误并通知了客户端。

**涉及用户或者编程常见的使用错误举例:**

- **没有正确处理加载错误:** 开发者在 JavaScript 中使用 `fetch()` 时，如果没有正确处理 `reject` 状态的 Promise，可能会导致用户界面上出现未预期的行为，例如白屏或功能失效。`ResponseBodyLoader` 的错误处理测试保证了底层能够正确传递错误信息。
- **过早地尝试访问未完成加载的数据:** 在使用 `BytesConsumer` 时，如果开发者在 `BeginRead` 返回 `kShouldWait` 的情况下就尝试访问数据缓冲区，会导致程序错误。测试中对 `BeginRead` 的返回值和状态的验证避免了这类问题。
- **在 BFCache 场景下对加载状态的错误假设:**  开发者可能假设页面恢复后加载状态会立即变为完成，但实际上可能需要等待 `ResponseBodyLoader` 恢复数据处理。`ResponseBodyLoaderTestAllowDrainAsBytesConsumerInBFCache` 这类测试确保了在 BFCache 场景下的行为符合预期。

**总结:**

`ResponseBodyLoader` 是 Blink 引擎中负责高效、可靠地加载 HTTP 响应主体数据的关键组件。其测试覆盖了数据接收、错误处理、加载完成、取消、多种数据消费方式、状态管理以及与 BFCache 等重要特性的集成。这些测试对于确保浏览器能够正确加载各种类型的网络资源（包括 JavaScript、HTML、CSS 等）至关重要，并能防止开发者在使用相关 API 时可能遇到的常见错误。

Prompt: 
```
这是目录为blink/renderer/platform/loader/fetch/response_body_loader_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
er->DrainAsBytesConsumer();

  EXPECT_TRUE(body_loader->IsDrained());
  EXPECT_NE(&consumer, original_consumer);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer.GetPublicState());
  body_loader->Abort();
  EXPECT_EQ(PublicState::kErrored, consumer.GetPublicState());

  task_runner->RunUntilIdle();

  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
}

TEST_F(ResponseBodyLoaderDrainedBytesConsumerNotificationOutOfOnStateChangeTest,
       BeginReadAndDone) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* original_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  original_consumer->Add(Command(Command::kWait));
  original_consumer->Add(Command(Command::kDataAndDone, "hello"));
  original_consumer->Add(Command(Command::kDone));

  auto* client = MakeGarbageCollected<TestClient>();

  auto* body_loader =
      MakeResponseBodyLoader(*original_consumer, *client, task_runner);
  BytesConsumer& consumer = body_loader->DrainAsBytesConsumer();

  base::span<const char> buffer;
  Result result = consumer.BeginRead(buffer);

  EXPECT_EQ(result, Result::kShouldWait);
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  task_runner->RunUntilIdle();
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  result = consumer.BeginRead(buffer);
  EXPECT_EQ(result, Result::kOk);
  ASSERT_EQ(buffer.size(), 5u);
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  result = consumer.EndRead(buffer.size());
  EXPECT_EQ(result, Result::kDone);
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  task_runner->RunUntilIdle();
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_TRUE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
}

TEST_F(ResponseBodyLoaderDrainedBytesConsumerNotificationOutOfOnStateChangeTest,
       BeginReadAndError) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* original_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  original_consumer->Add(Command(Command::kWait));
  original_consumer->Add(Command(Command::kData, "hello"));
  original_consumer->Add(Command(Command::kError));

  auto* client = MakeGarbageCollected<TestClient>();

  auto* body_loader =
      MakeResponseBodyLoader(*original_consumer, *client, task_runner);
  BytesConsumer& consumer = body_loader->DrainAsBytesConsumer();

  base::span<const char> buffer;
  Result result = consumer.BeginRead(buffer);

  EXPECT_EQ(result, Result::kShouldWait);
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  task_runner->RunUntilIdle();
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  result = consumer.BeginRead(buffer);
  EXPECT_EQ(result, Result::kOk);
  ASSERT_EQ(buffer.size(), 5u);
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  result = consumer.EndRead(buffer.size());
  EXPECT_EQ(result, Result::kOk);
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  result = consumer.BeginRead(buffer);
  EXPECT_EQ(result, Result::kError);
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  task_runner->RunUntilIdle();
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_TRUE(client->LoadingIsFailed());
}

TEST_F(ResponseBodyLoaderDrainedBytesConsumerNotificationOutOfOnStateChangeTest,
       EndReadAndDone) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* original_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  original_consumer->Add(Command(Command::kWait));
  original_consumer->Add(Command(Command::kDataAndDone, "hello"));

  auto* client = MakeGarbageCollected<TestClient>();

  auto* body_loader =
      MakeResponseBodyLoader(*original_consumer, *client, task_runner);
  BytesConsumer& consumer = body_loader->DrainAsBytesConsumer();

  base::span<const char> buffer;
  Result result = consumer.BeginRead(buffer);

  EXPECT_EQ(result, Result::kShouldWait);
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  task_runner->RunUntilIdle();
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  result = consumer.BeginRead(buffer);
  EXPECT_EQ(result, Result::kOk);
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  ASSERT_EQ(5u, buffer.size());
  EXPECT_EQ(String(base::as_bytes(buffer)), "hello");

  task_runner->RunUntilIdle();
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  result = consumer.EndRead(buffer.size());
  EXPECT_EQ(result, Result::kDone);
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  task_runner->RunUntilIdle();
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_TRUE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
}

TEST_F(ResponseBodyLoaderDrainedBytesConsumerNotificationOutOfOnStateChangeTest,
       DrainAsDataPipe) {
  mojo::ScopedDataPipeConsumerHandle consumer_end;
  mojo::ScopedDataPipeProducerHandle producer_end;
  auto result = mojo::CreateDataPipe(nullptr, producer_end, consumer_end);

  ASSERT_EQ(result, MOJO_RESULT_OK);

  DataPipeBytesConsumer::CompletionNotifier* completion_notifier = nullptr;

  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* original_consumer = MakeGarbageCollected<DataPipeBytesConsumer>(
      task_runner, std::move(consumer_end), &completion_notifier);
  auto* client = MakeGarbageCollected<TestClient>();

  auto* body_loader =
      MakeResponseBodyLoader(*original_consumer, *client, task_runner);

  BytesConsumer& consumer = body_loader->DrainAsBytesConsumer();

  EXPECT_TRUE(consumer.DrainAsDataPipe());

  task_runner->RunUntilIdle();

  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  completion_notifier->SignalComplete();

  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_TRUE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
}

TEST_F(ResponseBodyLoaderDrainedBytesConsumerNotificationOutOfOnStateChangeTest,
       Cancel) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* original_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  original_consumer->Add(Command(Command::kWait));

  auto* client = MakeGarbageCollected<TestClient>();

  auto* body_loader =
      MakeResponseBodyLoader(*original_consumer, *client, task_runner);
  BytesConsumer& consumer = body_loader->DrainAsBytesConsumer();

  task_runner->RunUntilIdle();
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  consumer.Cancel();
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());

  task_runner->RunUntilIdle();
  EXPECT_TRUE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
}

TEST_F(ResponseBodyLoaderDrainedBytesConsumerNotificationInOnStateChangeTest,
       BeginReadAndDone) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* original_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  original_consumer->Add(Command(Command::kWait));
  original_consumer->Add(Command(Command::kDone));

  auto* client = MakeGarbageCollected<TestClient>();

  auto* body_loader =
      MakeResponseBodyLoader(*original_consumer, *client, task_runner);

  BytesConsumer& consumer = body_loader->DrainAsBytesConsumer();
  auto* reading_client = MakeGarbageCollected<ReadingClient>(consumer, *client);
  consumer.SetClient(reading_client);

  base::span<const char> buffer;
  // This BeginRead posts a task which calls OnStateChange.
  Result result = consumer.BeginRead(buffer);
  EXPECT_EQ(result, Result::kShouldWait);

  // We'll see the change without waiting for another task.
  task_runner->PostTask(FROM_HERE,
                        base::BindOnce(
                            [](TestClient* client) {
                              EXPECT_FALSE(client->LoadingIsCancelled());
                              EXPECT_TRUE(client->LoadingIsFinished());
                              EXPECT_FALSE(client->LoadingIsFailed());
                            },
                            WrapPersistent(client)));

  task_runner->RunUntilIdle();

  EXPECT_TRUE(reading_client->IsOnStateChangeCalled());
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_TRUE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
}

TEST_F(ResponseBodyLoaderDrainedBytesConsumerNotificationInOnStateChangeTest,
       BeginReadAndError) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* original_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  original_consumer->Add(Command(Command::kWait));
  original_consumer->Add(Command(Command::kError));

  auto* client = MakeGarbageCollected<TestClient>();

  auto* body_loader =
      MakeResponseBodyLoader(*original_consumer, *client, task_runner);

  BytesConsumer& consumer = body_loader->DrainAsBytesConsumer();
  auto* reading_client = MakeGarbageCollected<ReadingClient>(consumer, *client);
  consumer.SetClient(reading_client);

  base::span<const char> buffer;
  // This BeginRead posts a task which calls OnStateChange.
  Result result = consumer.BeginRead(buffer);
  EXPECT_EQ(result, Result::kShouldWait);

  // We'll see the change without waiting for another task.
  task_runner->PostTask(FROM_HERE,
                        base::BindOnce(
                            [](TestClient* client) {
                              EXPECT_FALSE(client->LoadingIsCancelled());
                              EXPECT_FALSE(client->LoadingIsFinished());
                              EXPECT_TRUE(client->LoadingIsFailed());
                            },
                            WrapPersistent(client)));

  task_runner->RunUntilIdle();

  EXPECT_TRUE(reading_client->IsOnStateChangeCalled());
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_TRUE(client->LoadingIsFailed());
}

TEST_F(ResponseBodyLoaderDrainedBytesConsumerNotificationInOnStateChangeTest,
       EndReadAndDone) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* original_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  original_consumer->Add(Command(Command::kWait));
  original_consumer->Add(Command(Command::kDataAndDone, "hahaha"));

  auto* client = MakeGarbageCollected<TestClient>();

  auto* body_loader =
      MakeResponseBodyLoader(*original_consumer, *client, task_runner);

  BytesConsumer& consumer = body_loader->DrainAsBytesConsumer();
  auto* reading_client = MakeGarbageCollected<ReadingClient>(consumer, *client);
  consumer.SetClient(reading_client);

  base::span<const char> buffer;
  // This BeginRead posts a task which calls OnStateChange.
  Result result = consumer.BeginRead(buffer);
  EXPECT_EQ(result, Result::kShouldWait);

  // We'll see the change without waiting for another task.
  task_runner->PostTask(FROM_HERE,
                        base::BindOnce(
                            [](TestClient* client) {
                              EXPECT_FALSE(client->LoadingIsCancelled());
                              EXPECT_TRUE(client->LoadingIsFinished());
                              EXPECT_FALSE(client->LoadingIsFailed());
                            },
                            WrapPersistent(client)));

  task_runner->RunUntilIdle();

  EXPECT_TRUE(reading_client->IsOnStateChangeCalled());
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_TRUE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
}

class ResponseBodyLoaderTestAllowDrainAsBytesConsumerInBFCache
    : public ResponseBodyLoaderTest {
 protected:
  ResponseBodyLoaderTestAllowDrainAsBytesConsumerInBFCache() {
    scoped_feature_list_.InitWithFeatures(
        {features::kAllowDatapipeDrainedAsBytesConsumerInBFCache,
         features::kLoadingTasksUnfreezable},
        {});
    WebRuntimeFeatures::EnableBackForwardCache(true);
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

// Test that when response loader is suspended for back/forward cache and the
// datapipe is drained as bytes consumer, the data keeps processing without
// firing `DidFinishLoadingBody()`, which will be dispatched after resume.
TEST_F(ResponseBodyLoaderTestAllowDrainAsBytesConsumerInBFCache,
       DrainAsBytesConsumer) {
  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  auto* original_consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(task_runner);
  original_consumer->Add(Command(Command::kData, "he"));
  original_consumer->Add(Command(Command::kWait));
  original_consumer->Add(Command(Command::kData, "l"));
  original_consumer->Add(Command(Command::kData, "lo"));

  auto* client = MakeGarbageCollected<TestClient>();

  auto* body_loader =
      MakeResponseBodyLoader(*original_consumer, *client, task_runner);

  BytesConsumer& consumer = body_loader->DrainAsBytesConsumer();

  EXPECT_TRUE(body_loader->IsDrained());
  EXPECT_NE(&consumer, original_consumer);

  // Suspend for back-forward cache, then add some more data to |consumer|.
  body_loader->Suspend(LoaderFreezeMode::kBufferIncoming);
  original_consumer->Add(Command(Command::kData, "world"));
  original_consumer->Add(Command(Command::kDone));

  auto* reader = MakeGarbageCollected<BytesConsumerTestReader>(&consumer);

  auto result = reader->Run(task_runner.get());
  EXPECT_EQ(result.first, BytesConsumer::Result::kDone);
  EXPECT_EQ(String(result.second), "helloworld");
  // Check that `DidFinishLoadingBody()` has not been called.
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_FALSE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
  EXPECT_EQ("helloworld", client->GetData());

  // Resume the body loader.
  body_loader->Resume();
  task_runner->RunUntilIdle();
  // Check that `DidFinishLoadingBody()` has now been called.
  EXPECT_FALSE(client->LoadingIsCancelled());
  EXPECT_TRUE(client->LoadingIsFinished());
  EXPECT_FALSE(client->LoadingIsFailed());
}

}  // namespace

}  // namespace blink

"""


```