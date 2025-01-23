Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Understand the Goal:** The request asks for the functionality of the given C++ test file, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, common usage errors, and debugging steps.

2. **Initial Scan and Identification:**  Quickly scan the code for keywords and structure. I see `#include`, `namespace blink`, `TEST`, `EXPECT_EQ`, `EXPECT_CALL`, and class names like `ReadableStreamBytesConsumerTest`, `MockClient`, and `TestUnderlyingSource`. This immediately tells me it's a C++ unit test file for the Blink rendering engine, specifically testing something related to "readable streams" and "bytes consumers."

3. **Focus on the Core Class Under Test:** The main subject seems to be `ReadableStreamBytesConsumer`. The tests are named starting with this, and it's being instantiated in the `Create` test. This is the central piece of functionality we need to understand.

4. **Analyze Individual Tests:** Go through each `TEST` function:
    * **`Create`:** This test checks if a `ReadableStreamBytesConsumer` can be created successfully from a `ReadableStream`. The key takeaway is the association between the two.
    * **`EmptyStream`:**  This tests the behavior when the underlying stream is empty and then closed. It checks the state transitions (`kReadableOrWaiting` to `kClosed`) and the return values of `BeginRead` (`kShouldWait` then `kDone`).
    * **`ErroredStream`:**  Similar to `EmptyStream`, but the underlying stream is intentionally errored. It verifies the transition to the `kErrored` state and `kError` return from `BeginRead`.
    * **`TwoPhaseRead`:**  This is more complex. It involves enqueuing data (chunks of `DOMUint8Array`) into the stream and then calling `BeginRead` and `EndRead` on the consumer. The use of `EXPECT_THAT(buffer, ElementsAre(...))` confirms it's checking the data received. The "two-phase" likely refers to the `BeginRead`/`EndRead` pair, suggesting a mechanism for reading data in chunks.
    * **`TwoPhaseReadDetachedDuringRead` and `TwoPhaseReadDetachedBetweenReads`:** These test scenarios where a `DOMUint8Array` is detached (likely simulating a memory issue or external change) during the read process. They check for error conditions.
    * **`EnqueueUndefined`, `EnqueueNull`, `EnqueueString`:**  These tests explore what happens when invalid data types are enqueued into the readable stream. They all seem to lead to an error state.
    * **`Cancel`:** This checks the `Cancel` functionality of the consumer and verifies that the underlying source is notified and cancelled.

5. **Identify Key Concepts and Interactions:** From the test names and the methods called, I can identify these key concepts:
    * **Readable Streams:**  A fundamental web API for handling asynchronous data.
    * **Bytes Consumer:**  A component within Blink that consumes byte data from a readable stream.
    * **`BeginRead()` and `EndRead()`:**  The methods for initiating and completing a read operation, suggesting a two-step process.
    * **States:** The consumer has different states (`kReadableOrWaiting`, `kClosed`, `kErrored`).
    * **`MockClient`:** A test double to observe state changes.
    * **`TestUnderlyingSource`:** A test double to control the behavior of the readable stream's source.
    * **`DOMUint8Array`:** Represents an array of bytes, the typical data type for stream chunks.

6. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:**  Readable Streams are a core JavaScript API. The tests directly manipulate `ReadableStream` objects, and the data being enqueued (`DOMUint8Array`) corresponds to the data types used in JavaScript streams. The states of the consumer directly reflect the states of a JavaScript `ReadableStreamReader`.
    * **HTML:**  While not directly manipulating HTML elements, Readable Streams are crucial for fetching resources (e.g., images, videos) referenced in HTML. The `ReadableStreamBytesConsumer` is a low-level component involved in processing the byte data of these resources.
    * **CSS:** Similar to HTML, CSS resources fetched from the network use Readable Streams internally.

7. **Logical Reasoning and Examples:**
    * **Assumption:**  The `BeginRead` method provides a buffer to read into. The `EndRead` method indicates how many bytes were actually read.
    * **Example (TwoPhaseRead):**  Enqueuing [C, D, E, F] then reading would involve `BeginRead` returning a buffer, and after processing the data, `EndRead(1)` would acknowledge consumption of the first byte.
    * **Error Handling:** Enqueuing invalid types like `undefined` or `null` leads to an error state, as the consumer expects byte data.

8. **Common Usage Errors:**
    * **Not checking the return value of `BeginRead`:**  A common mistake is assuming `BeginRead` always returns data immediately. It might return `kShouldWait`.
    * **Incorrectly handling the buffer size:** Not respecting the size of the buffer provided by `BeginRead`.
    * **Calling `EndRead` with an incorrect byte count.**
    * **Detaching the underlying `ArrayBuffer`:**  Modifying the data source externally during the read operation can lead to errors.

9. **Debugging Steps:**
    * **Set breakpoints:** In the `BeginRead` and `EndRead` methods of `ReadableStreamBytesConsumer`.
    * **Inspect the state:** Check the `GetPublicState()` of the consumer.
    * **Examine the buffer:** Look at the contents of the `buffer` returned by `BeginRead`.
    * **Trace the underlying stream:** Investigate the state and queued chunks of the associated `ReadableStream`.
    * **Use logging:** Add logging within the `ReadableStreamBytesConsumer` to track its internal state transitions.

10. **Structure and Refine:** Organize the information logically, starting with the overall function, then details of each test, the connections to web technologies, and finally, debugging and error scenarios. Use clear and concise language.

This detailed breakdown demonstrates the process of dissecting the code, understanding its purpose, and connecting it to the broader context of web technologies and debugging.
这个C++源代码文件 `readable_stream_bytes_consumer_test.cc` 是 Chromium Blink 渲染引擎中的一个单元测试文件。它的主要功能是**测试 `ReadableStreamBytesConsumer` 类的行为和功能是否符合预期。**

`ReadableStreamBytesConsumer` 的作用是将来自 `ReadableStream` 的数据转换为可以被底层系统（例如网络栈）消费的字节流。它充当了 `ReadableStream` 和需要字节数据的组件之间的桥梁。

**它与 JavaScript, HTML, CSS 的功能关系如下:**

* **JavaScript:** `ReadableStream` 是 Web Streams API 的一部分，这是一个 JavaScript API，允许以异步方式处理数据流。`ReadableStreamBytesConsumer` 是 Blink 引擎内部实现这个 API 的关键组件。当 JavaScript 代码使用 `fetch` API 或创建自定义的 `ReadableStream` 并需要将其数据传递给底层系统时，`ReadableStreamBytesConsumer` 就会被用到。

    **举例说明:**

    ```javascript
    fetch('https://example.com/data.bin')
      .then(response => response.body.getReader())
      .then(reader => {
        return new ReadableStream({
          start(controller) {
            function push() {
              reader.read().then(({ done, value }) => {
                if (done) {
                  controller.close();
                  return;
                }
                // 这里可能会将 value (Uint8Array) 传递给底层系统，
                // Blink 内部会用到 ReadableStreamBytesConsumer
                // 将其转换为底层可消费的字节流
                controller.enqueue(value);
                push();
              });
            }
            push();
          }
        });
      });
    ```

    在这个例子中，`response.body` 是一个 `ReadableStream`。当 JavaScript 代码尝试读取这个流的数据时，Blink 内部的 `ReadableStreamBytesConsumer` 负责从这个 JavaScript 流中提取字节数据，并将其准备好用于网络传输或其他底层操作。

* **HTML:**  HTML 中通过 `<script>` 标签引入的 JavaScript 代码可能会使用 Fetch API 或其他涉及 `ReadableStream` 的操作。因此，间接地，`ReadableStreamBytesConsumer` 也与 HTML 的功能相关。 例如，当浏览器下载一个大的 JavaScript 文件时，它会通过一个 `ReadableStream` 来接收数据，并使用类似的机制处理字节流。

* **CSS:** 类似于 HTML，CSS 文件的下载也可能涉及 `ReadableStream` 和 `ReadableStreamBytesConsumer`。当浏览器请求一个 CSS 文件时，响应体通常是一个字节流，需要被处理。

**逻辑推理，假设输入与输出:**

测试用例中使用了 `TestUnderlyingSource` 来模拟 `ReadableStream` 的数据来源。我们可以根据 `Enqueue` 方法提供的输入来推断 `ReadableStreamBytesConsumer` 的输出。

**假设输入 (以 `TwoPhaseRead` 测试为例):**

1. `underlying_source` 接收到以下数据块 (以 `DOMUint8Array` 表示):
   - 空数组: `[]`
   - `[0x43, 0x44, 0x45, 0x46]` (对应字符 'C', 'D', 'E', 'F')
   - `[0x47, 0x48, 0x49, 0x4a]` (对应字符 'G', 'H', 'I', 'J')
2. 调用 `consumer->BeginRead(buffer)` 来尝试读取数据。
3. 调用 `consumer->EndRead(n)` 来告知消费者读取了 `n` 个字节。

**假设输出 (对应 `TwoPhaseRead` 测试中的部分断言):**

* 第一次 `BeginRead` 后，由于有数据但可能还没完全到达，`consumer->BeginRead(buffer)` 返回 `Result::kShouldWait`。
* 第一次 `test::RunPendingTasks()` 后，数据准备好，再次调用 `BeginRead` 返回 `Result::kOk`，`buffer` 为空 (因为第一个 chunk 是空的)。`EndRead(0)` 表示消费了 0 个字节。
* 下一次 `BeginRead` 返回 `Result::kShouldWait`，等待下一个 chunk。
* 第二次 `test::RunPendingTasks()` 后，`BeginRead` 返回 `Result::kOk`，`buffer` 指向 `[0x43, 0x44, 0x45, 0x46]`。
* `EndRead(0)` 后，再次 `BeginRead`，`buffer` 仍然指向 `[0x43, 0x44, 0x45, 0x46]`。
* `EndRead(1)` 后，再次 `BeginRead`，`buffer` 指向 `[0x44, 0x45, 0x46]` (跳过了第一个字节)。
* `EndRead(3)` 后，再次 `BeginRead`，`buffer` 指向 `[0x47, 0x48, 0x49, 0x4a]`。

**用户或编程常见的使用错误举例说明:**

* **没有检查 `BeginRead` 的返回值:**  `BeginRead` 可能会返回 `Result::kShouldWait`，表示当前没有足够的数据，需要等待。如果用户代码没有处理这种情况，直接尝试访问 `buffer` 可能会导致错误或读取到不完整的数据。

    **假设场景:** 用户尝试下载一个大文件，并在 JavaScript 中通过 `ReadableStream` 处理。如果底层网络速度较慢，`ReadableStreamBytesConsumer` 可能需要等待更多数据。如果用户 JavaScript 代码在 `getReader().read()` 返回的 promise resolve 后，没有正确处理 `done` 和 `value`，或者假设 `value` 总是存在且完整，就可能出错。

* **错误地使用 `EndRead` 的参数:** `EndRead` 的参数应该指示实际消费的字节数。如果传递的参数与实际处理的字节数不符，会导致数据丢失或重复处理。

    **假设场景:**  用户在 JavaScript 中读取流数据并将其写入本地文件。如果写入操作失败了一部分，但仍然调用 `EndRead` 并传递了错误的已消费字节数，那么后续的读取可能会跳过本应重新处理的数据。

* **在读取过程中分离 (detach) 底层的 `ArrayBuffer`:**  如 `TwoPhaseReadDetachedDuringRead` 和 `TwoPhaseReadDetachedBetweenReads` 测试所示，如果 `ReadableStream` 的底层数据缓冲区在 `ReadableStreamBytesConsumer` 正在读取或等待读取时被分离（例如，在 JavaScript 中对 `ArrayBuffer` 调用 `detach()`），会导致错误。

    **假设场景:**  一个复杂的 Web 应用可能涉及到多个组件共享数据缓冲区。如果一个组件在另一个组件正在通过 `ReadableStream` 读取数据时分离了缓冲区，会导致数据访问错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设一个用户在浏览器中访问了一个网页，这个网页执行了以下操作：

1. **发起网络请求 (Fetch API):** JavaScript 代码使用 `fetch()` 函数下载一个大型文件，例如图片或视频。
2. **获取响应体 (response.body):** `fetch()` 返回的 `Response` 对象包含一个 `body` 属性，它是一个 `ReadableStream`。
3. **获取 Reader (getReader()):** JavaScript 代码调用 `response.body.getReader()` 来获取一个用于读取流数据的 `ReadableStreamReader`。
4. **读取数据 (reader.read()):**  JavaScript 代码通过循环调用 `reader.read()` 来逐步读取流中的数据块。

**调试线索和如何到达 `readable_stream_bytes_consumer_test.cc`:**

如果在上述过程中出现问题，例如下载中断、数据损坏或性能问题，开发者可能会进行以下调试：

* **浏览器开发者工具的网络面板:**  检查网络请求的状态、响应头和响应体。
* **JavaScript 控制台:** 查看是否有 JavaScript 错误或异常。
* **Blink 渲染引擎的内部调试工具 (如果可以访问):**
    * **查看 `ReadableStream` 的状态:**  检查流是否处于 pending、readable、closed 或 errored 状态。
    * **查看 `ReadableStreamBytesConsumer` 的状态:** 检查其内部状态 (例如 `PublicState`)，以及是否正在等待数据或已完成读取。
    * **断点调试 C++ 代码:** 如果怀疑问题出在 Blink 内部，开发者可能会在 `ReadableStreamBytesConsumer` 的关键方法 (`BeginRead`, `EndRead`) 中设置断点，以跟踪数据流的处理过程。

**`readable_stream_bytes_consumer_test.cc` 的价值在于它可以独立地验证 `ReadableStreamBytesConsumer` 的逻辑是否正确。**  如果测试失败，说明这个类在处理各种场景（例如空流、错误流、分块读取、取消等）时存在 bug。 开发者可以通过查看测试用例，理解预期的行为，并找到导致测试失败的原因，从而修复代码。

总而言之，`readable_stream_bytes_consumer_test.cc` 是一个低级别的测试文件，用于确保 Blink 引擎中负责处理 `ReadableStream` 字节数据的核心组件的正确性，这对于实现 Web Streams API 和支持各种网络操作至关重要。

### 提示词
```
这是目录为blink/renderer/core/fetch/readable_stream_bytes_consumer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fetch/readable_stream_bytes_consumer.h"

#include <memory>

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/fetch/bytes_consumer_test_util.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/test_underlying_source.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding_macros.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

using ::testing::ElementsAre;
using ::testing::InSequence;
using ::testing::StrictMock;
using Checkpoint = StrictMock<::testing::MockFunction<void(int)>>;
using Result = BytesConsumer::Result;
using PublicState = BytesConsumer::PublicState;

class MockClient : public GarbageCollected<MockClient>,
                   public BytesConsumer::Client {
 public:
  MockClient() = default;

  MOCK_METHOD0(OnStateChange, void());
  String DebugName() const override { return "MockClient"; }

  void Trace(Visitor* visitor) const override {}
};

TEST(ReadableStreamBytesConsumerTest, Create) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  ExceptionState& exception_state = scope.GetExceptionState();

  auto* stream = ReadableStream::Create(script_state, exception_state);
  ASSERT_TRUE(stream);
  ASSERT_FALSE(exception_state.HadException());

  Persistent<BytesConsumer> consumer =
      MakeGarbageCollected<ReadableStreamBytesConsumer>(script_state, stream);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());
}

TEST(ReadableStreamBytesConsumerTest, EmptyStream) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();

  auto* underlying_source =
      MakeGarbageCollected<TestUnderlyingSource>(script_state);
  auto* stream = ReadableStream::CreateWithCountQueueingStrategy(
      script_state, underlying_source, 0);
  underlying_source->Close();

  Persistent<BytesConsumer> consumer =
      MakeGarbageCollected<ReadableStreamBytesConsumer>(script_state, stream);

  Persistent<MockClient> client = MakeGarbageCollected<MockClient>();
  consumer->SetClient(client);

  Checkpoint checkpoint;
  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*client, OnStateChange());
  EXPECT_CALL(checkpoint, Call(4));

  base::span<const char> buffer;
  checkpoint.Call(1);
  test::RunPendingTasks();
  checkpoint.Call(2);
  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());
  EXPECT_EQ(Result::kShouldWait, consumer->BeginRead(buffer));
  checkpoint.Call(3);
  test::RunPendingTasks();
  checkpoint.Call(4);
  EXPECT_EQ(PublicState::kClosed, consumer->GetPublicState());
  EXPECT_EQ(Result::kDone, consumer->BeginRead(buffer));
}

TEST(ReadableStreamBytesConsumerTest, ErroredStream) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();

  auto* underlying_source =
      MakeGarbageCollected<TestUnderlyingSource>(script_state);
  auto* stream = ReadableStream::CreateWithCountQueueingStrategy(
      script_state, underlying_source, 0);
  underlying_source->Error(ScriptValue(
      script_state->GetIsolate(), v8::Undefined(script_state->GetIsolate())));

  Persistent<BytesConsumer> consumer =
      MakeGarbageCollected<ReadableStreamBytesConsumer>(script_state, stream);
  Persistent<MockClient> client = MakeGarbageCollected<MockClient>();
  consumer->SetClient(client);
  Checkpoint checkpoint;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*client, OnStateChange());
  EXPECT_CALL(checkpoint, Call(4));

  base::span<const char> buffer;
  checkpoint.Call(1);
  test::RunPendingTasks();
  checkpoint.Call(2);
  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());
  EXPECT_EQ(Result::kShouldWait, consumer->BeginRead(buffer));
  checkpoint.Call(3);
  test::RunPendingTasks();
  checkpoint.Call(4);
  EXPECT_EQ(PublicState::kErrored, consumer->GetPublicState());
  EXPECT_EQ(Result::kError, consumer->BeginRead(buffer));
}

TEST(ReadableStreamBytesConsumerTest, TwoPhaseRead) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();

  auto* underlying_source =
      MakeGarbageCollected<TestUnderlyingSource>(script_state);
  auto* stream = ReadableStream::CreateWithCountQueueingStrategy(
      script_state, underlying_source, 0);
  {
    auto* chunk1 = DOMUint8Array::Create(0);
    auto* chunk2 =
        DOMUint8Array::Create(std::to_array<uint8_t>({0x43, 0x44, 0x45, 0x46}));
    auto* chunk3 =
        DOMUint8Array::Create(std::to_array<uint8_t>({0x47, 0x48, 0x49, 0x4a}));
    underlying_source->Enqueue(
        ScriptValue(script_state->GetIsolate(),
                    ToV8Traits<DOMUint8Array>::ToV8(script_state, chunk1)));
    underlying_source->Enqueue(
        ScriptValue(script_state->GetIsolate(),
                    ToV8Traits<DOMUint8Array>::ToV8(script_state, chunk2)));
    underlying_source->Enqueue(
        ScriptValue(script_state->GetIsolate(),
                    ToV8Traits<DOMUint8Array>::ToV8(script_state, chunk3)));
    underlying_source->Close();
  }

  Persistent<BytesConsumer> consumer =
      MakeGarbageCollected<ReadableStreamBytesConsumer>(script_state, stream);
  Persistent<MockClient> client = MakeGarbageCollected<MockClient>();
  consumer->SetClient(client);
  Checkpoint checkpoint;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*client, OnStateChange());
  EXPECT_CALL(checkpoint, Call(4));
  EXPECT_CALL(checkpoint, Call(5));
  EXPECT_CALL(*client, OnStateChange());
  EXPECT_CALL(checkpoint, Call(6));
  EXPECT_CALL(checkpoint, Call(7));
  EXPECT_CALL(*client, OnStateChange());
  EXPECT_CALL(checkpoint, Call(8));
  EXPECT_CALL(checkpoint, Call(9));
  EXPECT_CALL(*client, OnStateChange());
  EXPECT_CALL(checkpoint, Call(10));

  base::span<const char> buffer;
  checkpoint.Call(1);
  test::RunPendingTasks();
  checkpoint.Call(2);
  EXPECT_EQ(Result::kShouldWait, consumer->BeginRead(buffer));
  checkpoint.Call(3);
  test::RunPendingTasks();
  checkpoint.Call(4);
  EXPECT_EQ(Result::kOk, consumer->BeginRead(buffer));
  ASSERT_EQ(0u, buffer.size());
  EXPECT_EQ(Result::kOk, consumer->EndRead(0));
  EXPECT_EQ(Result::kShouldWait, consumer->BeginRead(buffer));
  checkpoint.Call(5);
  test::RunPendingTasks();
  checkpoint.Call(6);
  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());
  EXPECT_EQ(Result::kOk, consumer->BeginRead(buffer));
  EXPECT_THAT(buffer, ElementsAre(0x43, 0x44, 0x45, 0x46));
  EXPECT_EQ(Result::kOk, consumer->EndRead(0));
  EXPECT_EQ(Result::kOk, consumer->BeginRead(buffer));
  EXPECT_THAT(buffer, ElementsAre(0x43, 0x44, 0x45, 0x46));
  EXPECT_EQ(Result::kOk, consumer->EndRead(1));
  EXPECT_EQ(Result::kOk, consumer->BeginRead(buffer));
  EXPECT_THAT(buffer, ElementsAre(0x44, 0x45, 0x46));
  EXPECT_EQ(Result::kOk, consumer->EndRead(3));
  EXPECT_EQ(Result::kShouldWait, consumer->BeginRead(buffer));
  checkpoint.Call(7);
  test::RunPendingTasks();
  checkpoint.Call(8);
  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());
  EXPECT_EQ(Result::kOk, consumer->BeginRead(buffer));
  EXPECT_THAT(buffer, ElementsAre(0x47, 0x48, 0x49, 0x4a));
  EXPECT_EQ(Result::kOk, consumer->EndRead(4));
  EXPECT_EQ(Result::kShouldWait, consumer->BeginRead(buffer));
  checkpoint.Call(9);
  test::RunPendingTasks();
  checkpoint.Call(10);
  EXPECT_EQ(PublicState::kClosed, consumer->GetPublicState());
  EXPECT_EQ(Result::kDone, consumer->BeginRead(buffer));
}

TEST(ReadableStreamBytesConsumerTest, TwoPhaseReadDetachedDuringRead) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();

  auto* underlying_source =
      MakeGarbageCollected<TestUnderlyingSource>(script_state);
  auto* stream = ReadableStream::CreateWithCountQueueingStrategy(
      script_state, underlying_source, 0);

  auto* chunk =
      DOMUint8Array::Create(std::to_array<uint8_t>({0x43, 0x44, 0x45, 0x46}));
  underlying_source->Enqueue(
      ScriptValue(script_state->GetIsolate(),
                  ToV8Traits<DOMUint8Array>::ToV8(script_state, chunk)));
  underlying_source->Close();

  Persistent<BytesConsumer> consumer =
      MakeGarbageCollected<ReadableStreamBytesConsumer>(script_state, stream);
  Persistent<MockClient> client = MakeGarbageCollected<MockClient>();
  consumer->SetClient(client);
  Checkpoint checkpoint;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*client, OnStateChange());
  EXPECT_CALL(checkpoint, Call(4));

  base::span<const char> buffer;
  checkpoint.Call(1);
  test::RunPendingTasks();
  checkpoint.Call(2);
  EXPECT_EQ(Result::kShouldWait, consumer->BeginRead(buffer));
  checkpoint.Call(3);
  test::RunPendingTasks();
  checkpoint.Call(4);
  EXPECT_EQ(Result::kOk, consumer->BeginRead(buffer));
  EXPECT_THAT(buffer, ElementsAre(0x43, 0x44, 0x45, 0x46));
  chunk->DetachForTesting();
  EXPECT_EQ(Result::kError, consumer->EndRead(4));
  EXPECT_EQ(PublicState::kErrored, consumer->GetPublicState());
}

TEST(ReadableStreamBytesConsumerTest, TwoPhaseReadDetachedBetweenReads) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();

  auto* underlying_source =
      MakeGarbageCollected<TestUnderlyingSource>(script_state);
  auto* stream = ReadableStream::CreateWithCountQueueingStrategy(
      script_state, underlying_source, 0);

  auto* chunk =
      DOMUint8Array::Create(std::to_array<uint8_t>({0x43, 0x44, 0x45, 0x46}));
  underlying_source->Enqueue(
      ScriptValue(script_state->GetIsolate(),
                  ToV8Traits<DOMUint8Array>::ToV8(script_state, chunk)));
  underlying_source->Close();

  Persistent<BytesConsumer> consumer =
      MakeGarbageCollected<ReadableStreamBytesConsumer>(script_state, stream);
  Persistent<MockClient> client = MakeGarbageCollected<MockClient>();
  consumer->SetClient(client);
  Checkpoint checkpoint;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*client, OnStateChange());
  EXPECT_CALL(checkpoint, Call(4));

  base::span<const char> buffer;
  checkpoint.Call(1);
  test::RunPendingTasks();
  checkpoint.Call(2);
  EXPECT_EQ(Result::kShouldWait, consumer->BeginRead(buffer));
  checkpoint.Call(3);
  test::RunPendingTasks();
  checkpoint.Call(4);
  EXPECT_EQ(Result::kOk, consumer->BeginRead(buffer));
  EXPECT_THAT(buffer, ElementsAre(0x43, 0x44, 0x45, 0x46));
  EXPECT_EQ(Result::kOk, consumer->EndRead(1));
  chunk->DetachForTesting();
  EXPECT_EQ(Result::kError, consumer->BeginRead(buffer));
  EXPECT_EQ(PublicState::kErrored, consumer->GetPublicState());
}

TEST(ReadableStreamBytesConsumerTest, EnqueueUndefined) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();

  auto* underlying_source =
      MakeGarbageCollected<TestUnderlyingSource>(script_state);
  auto* stream = ReadableStream::CreateWithCountQueueingStrategy(
      script_state, underlying_source, 0);
  underlying_source->Enqueue(ScriptValue(
      script_state->GetIsolate(), v8::Undefined(script_state->GetIsolate())));
  underlying_source->Close();

  Persistent<BytesConsumer> consumer =
      MakeGarbageCollected<ReadableStreamBytesConsumer>(script_state, stream);
  Persistent<MockClient> client = MakeGarbageCollected<MockClient>();
  consumer->SetClient(client);
  Checkpoint checkpoint;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*client, OnStateChange());
  EXPECT_CALL(checkpoint, Call(4));

  base::span<const char> buffer;
  checkpoint.Call(1);
  test::RunPendingTasks();
  checkpoint.Call(2);
  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());
  EXPECT_EQ(Result::kShouldWait, consumer->BeginRead(buffer));
  checkpoint.Call(3);
  test::RunPendingTasks();
  checkpoint.Call(4);
  EXPECT_EQ(PublicState::kErrored, consumer->GetPublicState());
  EXPECT_EQ(Result::kError, consumer->BeginRead(buffer));
}

TEST(ReadableStreamBytesConsumerTest, EnqueueNull) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();

  auto* underlying_source =
      MakeGarbageCollected<TestUnderlyingSource>(script_state);
  auto* stream = ReadableStream::CreateWithCountQueueingStrategy(
      script_state, underlying_source, 0);
  underlying_source->Enqueue(ScriptValue(script_state->GetIsolate(),
                                         v8::Null(script_state->GetIsolate())));
  underlying_source->Close();

  Persistent<BytesConsumer> consumer =
      MakeGarbageCollected<ReadableStreamBytesConsumer>(script_state, stream);
  Persistent<MockClient> client = MakeGarbageCollected<MockClient>();
  consumer->SetClient(client);
  Checkpoint checkpoint;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*client, OnStateChange());
  EXPECT_CALL(checkpoint, Call(4));

  base::span<const char> buffer;
  checkpoint.Call(1);
  test::RunPendingTasks();
  checkpoint.Call(2);
  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());
  EXPECT_EQ(Result::kShouldWait, consumer->BeginRead(buffer));
  checkpoint.Call(3);
  test::RunPendingTasks();
  checkpoint.Call(4);
  EXPECT_EQ(PublicState::kErrored, consumer->GetPublicState());
  EXPECT_EQ(Result::kError, consumer->BeginRead(buffer));
}

TEST(ReadableStreamBytesConsumerTest, EnqueueString) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();

  auto* underlying_source =
      MakeGarbageCollected<TestUnderlyingSource>(script_state);
  auto* stream = ReadableStream::CreateWithCountQueueingStrategy(
      script_state, underlying_source, 0);
  underlying_source->Enqueue(
      ScriptValue(script_state->GetIsolate(),
                  V8String(script_state->GetIsolate(), "hello")));
  underlying_source->Close();

  Persistent<BytesConsumer> consumer =
      MakeGarbageCollected<ReadableStreamBytesConsumer>(script_state, stream);
  Persistent<MockClient> client = MakeGarbageCollected<MockClient>();
  consumer->SetClient(client);
  Checkpoint checkpoint;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*client, OnStateChange());
  EXPECT_CALL(checkpoint, Call(4));

  base::span<const char> buffer;
  checkpoint.Call(1);
  test::RunPendingTasks();
  checkpoint.Call(2);
  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());
  EXPECT_EQ(Result::kShouldWait, consumer->BeginRead(buffer));
  checkpoint.Call(3);
  test::RunPendingTasks();
  checkpoint.Call(4);
  EXPECT_EQ(PublicState::kErrored, consumer->GetPublicState());
  EXPECT_EQ(Result::kError, consumer->BeginRead(buffer));
}

TEST(ReadableStreamBytesConsumerTest, Cancel) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();

  auto* underlying_source =
      MakeGarbageCollected<TestUnderlyingSource>(script_state);
  auto* stream = ReadableStream::CreateWithCountQueueingStrategy(
      script_state, underlying_source, 0);
  underlying_source->Enqueue(ScriptValue(script_state->GetIsolate(),
                                         v8::Null(script_state->GetIsolate())));
  underlying_source->Close();

  Persistent<BytesConsumer> consumer =
      MakeGarbageCollected<ReadableStreamBytesConsumer>(script_state, stream);
  Persistent<MockClient> client = MakeGarbageCollected<MockClient>();
  consumer->SetClient(client);

  consumer->Cancel();

  EXPECT_TRUE(underlying_source->IsCancelled());
  EXPECT_TRUE(underlying_source->IsCancelledWithUndefined());
}

}  // namespace

}  // namespace blink
```