Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Identify the Core Subject:** The filename `incoming_stream_test.cc` and the initial includes (`IncomingStream.h`) immediately point to testing the `IncomingStream` class. The `webtransport` namespace further contextualizes it.

2. **Understand the Purpose of a Test File:** Test files in Chromium (and most software projects) aim to verify the functionality of a specific unit of code. This means we need to figure out what `IncomingStream` *does* and how the tests validate that behavior.

3. **Analyze the Includes:** The included headers provide valuable clues about `IncomingStream`'s dependencies and how it interacts with other parts of the system:
    * `<utility>`: Standard C++ utilities.
    * `base/test/mock_callback.h`: Indicates the use of mock callbacks, suggesting asynchronous interactions and the need to verify function calls.
    * `testing/gmock/include/gmock/gmock.h`, `testing/gtest/include/gtest/gtest.h`:  Confirms this is a Google Test based unit test.
    * Blink-specific headers (`renderer/bindings/...`, `renderer/core/...`, `renderer/modules/...`, `renderer/platform/...`): Show integration with Blink's binding layer (JavaScript interaction), core DOM concepts (ReadableStream), and platform-level testing utilities. The presence of `ReadableStream` is a *huge* hint about the nature of `IncomingStream`.
    * `v8/include/v8.h`: Indicates interaction with the V8 JavaScript engine.

4. **Examine the Test Fixture:** The `IncomingStreamTest` class inherits from `::testing::Test`. This is the standard setup for Google Tests. Pay attention to the member variables:
    * `mock_on_abort_`: A mocked callback, strongly suggesting that `IncomingStream` has a concept of being aborted and notifies something when that happens.
    * `task_environment_`: A Blink testing utility for managing asynchronous tasks.
    * `data_pipe_producer_`, `data_pipe_consumer_`:  Mojo data pipe handles. This is a crucial detail. It reveals that `IncomingStream` likely receives data via a Mojo data pipe. Mojo is Chromium's inter-process communication mechanism.

5. **Analyze the Helper Methods:** The `IncomingStreamTest` fixture includes several helper methods. Understanding these simplifies the interpretation of the test cases:
    * `CreateDataPipe()`:  Sets up the underlying Mojo data pipe.
    * `CreateIncomingStream()`:  Creates an `IncomingStream` instance, passing in the consumer end of the data pipe. It also initializes it, implying some setup is required.
    * `WriteToPipe()`: Sends data into the producer end of the Mojo data pipe.
    * `ClosePipe()`: Closes the producer end of the pipe, signaling the end of data.
    * `ToVector()`: Converts a V8 `Uint8Array` to a C++ `Vector<uint8_t>`. This strongly links the C++ code with JavaScript's binary data handling.
    * `Iterator`, `Read()` (overloads), `IteratorFromReadResult()`:  These methods are all about reading data from a `ReadableStream`. This confirms that `IncomingStream` exposes its received data as a `ReadableStream`.

6. **Examine the Individual Test Cases:** Now, go through each `TEST_F` function:
    * `Create`: Basic instantiation test.
    * `ReadArrayBuffer`: Verifies reading data as an `ArrayBuffer`.
    * `ReadArrayBufferWithBYOBReader`: Tests reading with a "bring your own buffer" reader, a feature of `ReadableStream` for more efficient memory management.
    * `ReadThenClosedWithFin`, `ReadThenClosedWithoutFin`: Test scenarios where the remote end closes the stream (gracefully or abruptly) *after* some data has been read. The `mock_on_abort_` usage here is important.
    * `ClosedWithFinThenRead`: Tests reading *after* the stream has been closed.
    * `ClosedWithFinWithoutRead`: Tests the `reader.closed` promise.
    * `DataPipeResetBeforeClosedWithFin`, `DataPipeResetBeforeClosedWithoutFin`:  Test scenarios where the underlying Mojo data pipe is closed before the explicit close signal.
    * `WriteToPipeWithPendingRead`: Tests writing data when a read operation is already in progress.
    * `Cancel`, `CancelWithWebTransportError`, `CancelWithWebTransportErrorWithCode`: Test the stream cancellation mechanism, including scenarios where an error is provided.

7. **Connect the Dots to WebTransport Concepts:** By this point, a clear picture emerges: `IncomingStream` is the Blink-side representation of an incoming WebTransport stream. It receives data through a Mojo data pipe and exposes this data as a JavaScript `ReadableStream`. The tests cover various aspects of the stream lifecycle, including reading, closing (graceful and abrupt), and cancellation.

8. **Address the Specific Questions in the Prompt:** Now, armed with a solid understanding of the code, it's straightforward to answer the specific questions:
    * **Functionality:** Summarize the core responsibilities based on the analysis above.
    * **Relationship to JavaScript/HTML/CSS:** Focus on the `ReadableStream` API and how it's exposed to JavaScript. No direct relationship to HTML or CSS is evident in this specific test file.
    * **Logical Reasoning (Assumptions and Outputs):**  Choose a few test cases and explain the setup (input data, actions) and expected outcomes (read data, promise resolution, mock callback invocations).
    * **User/Programming Errors:** Think about common mistakes when using `ReadableStream` in JavaScript, such as reading after close, and relate them back to the test scenarios.
    * **User Operations and Debugging:**  Imagine a user interacting with a WebTransport-enabled website and trace the path to the `IncomingStream` in the renderer process. Emphasize the asynchronous nature and the role of Mojo.

9. **Refine and Organize:** Finally, organize the findings into a clear and structured answer, using appropriate terminology and providing concrete examples. Use the information gathered from each step of the analysis to support the explanation. For instance, the presence of `ScriptPromiseTester` directly relates to the asynchronous nature of `ReadableStream` operations in JavaScript.

This systematic approach, starting with high-level identification and gradually drilling down into the details, allows for a comprehensive understanding of the code and its purpose. The key is to recognize the patterns and connections between the different parts of the code and the underlying technologies (like Mojo and `ReadableStream`).
这个C++文件 `incoming_stream_test.cc` 是 Chromium Blink 引擎中 `webtransport` 模块的一个测试文件。它的主要功能是测试 `IncomingStream` 类的功能。 `IncomingStream` 类负责处理从 WebTransport 连接接收到的单向数据流。

以下是该文件的具体功能分解，以及与 JavaScript、HTML、CSS 的关系、逻辑推理、用户/编程错误和调试线索：

**1. 主要功能:**

* **测试 `IncomingStream` 类的创建和初始化:** 验证 `IncomingStream` 对象能否被正确创建，并关联到一个数据管道（Mojo DataPipe）。
* **测试从 `IncomingStream` 读取数据:**
    * 使用 `ReadableStreamDefaultReader` 和 `ReadableStreamBYOBReader` 读取数据。
    * 验证读取到的数据是否与写入的数据一致。
    * 测试在接收到部分数据后关闭流的情况。
* **测试流的关闭和中止:**
    * 模拟远程端正常关闭流 (with FIN)。
    * 模拟远程端中止流 (without FIN)。
    * 验证在流关闭或中止后读取行为是否符合预期。
    * 测试在数据管道被重置后流的关闭行为。
* **测试在有待处理的读取操作时写入数据:** 验证在 JavaScript 中发起 `read()` 操作但数据尚未到达时，后续写入的数据能否被正确读取。
* **测试流的取消 (cancel):**
    * 验证取消操作会触发预期的回调 (mock_on_abort_)。
    * 测试使用 `WebTransportError` 对象取消流的情况，包括带错误码和不带错误码的情况。

**2. 与 JavaScript, HTML, CSS 的关系:**

这个测试文件直接测试的是 C++ 代码，但它背后的功能与 JavaScript 的 WebTransport API 密切相关。

* **JavaScript `ReadableStream` API:** `IncomingStream` 在 C++ 层将其接收到的数据暴露为一个 `ReadableStream` 对象。JavaScript 可以通过 WebTransport API 获取这个 `ReadableStream` 并使用其方法（如 `getReader()`, `read()`, `cancel()`, `closed`）来读取数据。
    * **举例说明:** 在 JavaScript 中，你可能会这样操作：
      ```javascript
      const webTransport = new WebTransport('...');
      await webTransport.ready;
      const stream = await webTransport.createUnidirectionalStream(); // 或接收到的流
      const writer = stream.writable.getWriter();
      await writer.write(new Uint8Array([1, 2, 3]));
      await writer.close();

      // 接收端（对应这里的 IncomingStream）
      webTransport.incomingUnidirectionalStreams.readable.getReader().read()
        .then(({ value, done }) => {
          if (!done) {
            // value 就是从 C++ 的 IncomingStream 读取到的数据 (Uint8Array)
            console.log('Received data:', value);
          }
        });
      ```
      这里的 JavaScript 代码与 C++ 的 `IncomingStream` 通过 `ReadableStream` 机制进行交互。C++ 的测试代码模拟了数据的写入和流的关闭，而 JavaScript 代码则负责读取这些数据。

* **HTML 和 CSS:**  `IncomingStream` 本身不直接与 HTML 或 CSS 交互。WebTransport 是一个用于在客户端和服务器之间进行双向通信的网络协议，它独立于页面的渲染和样式。 然而，WebTransport 通常被 JavaScript 代码使用，而这些 JavaScript 代码可能是在 HTML 页面中运行的，并可能影响页面的行为或展示。

**3. 逻辑推理 (假设输入与输出):**

以下以 `TEST_F(IncomingStreamTest, ReadArrayBuffer)` 为例进行逻辑推理：

* **假设输入:**
    * 创建了一个 `IncomingStream` 对象。
    * 向与该 `IncomingStream` 关联的数据管道写入了包含单个字节 'A' 的数据。
* **逻辑步骤:**
    * 获取 `IncomingStream` 的 `ReadableStream` 的默认读取器 (`ReadableStreamDefaultReader`).
    * 调用读取器的 `read()` 方法。
* **预期输出:**
    * `read()` 方法返回的 Promise 会 resolve。
    * Promise 的 value 包含一个 `done` 属性为 `false`，`value` 属性是一个包含字节 'A' 的 `Uint8Array`。

**4. 用户或者编程常见的使用错误:**

* **在流关闭后尝试读取数据:**  用户可能会在 JavaScript 中尝试在 `IncomingStream` 对应的 `ReadableStream` 已经关闭后调用 `read()` 方法。测试用例 `TEST_F(IncomingStreamTest, ClosedWithFinThenRead)` 和 `TEST_F(IncomingStreamTest, DataPipeResetBeforeClosedWithFin)` 模拟了这种情况，并验证了 C++ 层的行为。
    * **举例说明:**
      ```javascript
      const reader = stream.readable.getReader();
      await reader.cancel(); // 假设流被取消了
      reader.read().then(({ value, done }) => {
        // 常见错误：期望这里还能读取到数据
        if (!done) {
          console.log('Unexpected data:', value);
        }
      });
      ```
      正确的做法是监听 `reader.closed` promise，并在其 resolve 后停止读取。

* **未正确处理流的错误或中止:** 用户可能没有正确监听 `ReadableStream` 的错误事件或 `reader.closed` promise 的 reject 情况，导致程序无法处理流的异常终止。测试用例 `TEST_F(IncomingStreamTest, ReadThenClosedWithoutFin)` 和 `TEST_F(IncomingStreamTest, DataPipeResetBeforeClosedWithoutFin)` 覆盖了这种情况。

* **BYOB 读取器的使用不当:**  如果使用 `ReadableStreamBYOBReader`，用户需要提供一个预先分配的 `ArrayBufferView` 作为读取的缓冲区。如果提供的缓冲区太小，或者在读取过程中修改了缓冲区的内容，可能会导致未定义的行为。

**5. 用户操作是如何一步步的到达这里，作为调试线索:**

要到达 `IncomingStream` 的代码，通常涉及以下步骤：

1. **用户在浏览器中访问一个支持 WebTransport 的网站。**
2. **网站的 JavaScript 代码使用 `new WebTransport(url)` 创建一个 WebTransport 连接。**
3. **连接建立成功后，服务器可能会主动发起一个单向流，或者客户端请求创建一个单向流。**
4. **当服务器向客户端发送数据时，这些数据会通过底层的网络协议（通常是 HTTP/3）传输。**
5. **Chromium 的网络层接收到这些数据后，会将其传递给 `webtransport` 模块。**
6. **`webtransport` 模块会创建一个 `IncomingStream` 对象来处理这个接收到的数据流。**
7. **数据会被写入到与 `IncomingStream` 关联的 Mojo DataPipe 中。**
8. **在 JavaScript 侧，通过 `webTransport.incomingUnidirectionalStreams.readable` 获取的 `ReadableStream` 最终会从这个 DataPipe 中读取数据。**

**调试线索:**

* **网络请求:** 使用浏览器的开发者工具查看网络请求，确认 WebTransport 连接是否建立成功，以及是否有数据传输。
* **WebTransport API 调用:** 在 JavaScript 代码中添加断点，查看 `WebTransport` 对象的状态和 `incomingUnidirectionalStreams` 的内容。
* **Mojo 管道:** 如果需要深入调试 C++ 代码，可以使用 Mojo 的调试工具来观察数据在管道中的流动。
* **Blink 渲染器进程:**  `IncomingStream` 位于 Blink 渲染器进程中。可以使用 Chromium 的多进程调试工具来附加到渲染器进程，并在 `IncomingStream` 的相关代码中设置断点，例如 `OnDataAvailable()` 或 `OnClose()` 方法。
* **日志输出:**  在 Blink 的 `webtransport` 模块中可能存在相关的日志输出，可以帮助理解数据流的处理过程。

总而言之，`incoming_stream_test.cc` 是确保 Chromium Blink 引擎中 WebTransport 接收数据流功能正确性的关键组件。它模拟了各种场景，涵盖了正常数据接收、流的关闭和中止、以及错误处理等，保证了 WebTransport API 在浏览器中的可靠运行。

Prompt: 
```
这是目录为blink/renderer/modules/webtransport/incoming_stream_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webtransport/incoming_stream.h"

#include <utility>

#include "base/test/mock_callback.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/iterable.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream_read_result.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_byob_reader.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_reader.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/modules/webtransport/web_transport_error.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

using ::testing::ElementsAre;
using ::testing::StrictMock;

class IncomingStreamTest : public ::testing::Test {
 public:
  // The default value of |capacity| means some sensible value selected by mojo.
  void CreateDataPipe(uint32_t capacity = 0) {
    MojoCreateDataPipeOptions options;
    options.struct_size = sizeof(MojoCreateDataPipeOptions);
    options.flags = MOJO_CREATE_DATA_PIPE_FLAG_NONE;
    options.element_num_bytes = 1;
    options.capacity_num_bytes = capacity;

    MojoResult result = mojo::CreateDataPipe(&options, data_pipe_producer_,
                                             data_pipe_consumer_);
    if (result != MOJO_RESULT_OK) {
      ADD_FAILURE() << "CreateDataPipe() returned " << result;
    }
  }

  IncomingStream* CreateIncomingStream(const V8TestingScope& scope,
                                       uint32_t capacity = 0) {
    CreateDataPipe(capacity);
    auto* script_state = scope.GetScriptState();
    auto* incoming_stream = MakeGarbageCollected<IncomingStream>(
        script_state, mock_on_abort_.Get(), std::move(data_pipe_consumer_));
    incoming_stream->Init(ASSERT_NO_EXCEPTION);
    return incoming_stream;
  }

  void WriteToPipe(Vector<uint8_t> data) {
    EXPECT_EQ(data_pipe_producer_->WriteAllData(data), MOJO_RESULT_OK);
  }

  void ClosePipe() { data_pipe_producer_.reset(); }

  // Copies the contents of a v8::Value containing a Uint8Array to a Vector.
  static Vector<uint8_t> ToVector(V8TestingScope& scope,
                                  v8::Local<v8::Value> v8value) {
    Vector<uint8_t> ret;

    NotShared<DOMUint8Array> value =
        NativeValueTraits<NotShared<DOMUint8Array>>::NativeValue(
            scope.GetIsolate(), v8value, scope.GetExceptionState());
    if (!value) {
      ADD_FAILURE() << "chunk is not an Uint8Array";
      return ret;
    }
    ret.Append(static_cast<uint8_t*>(value->Data()),
               static_cast<wtf_size_t>(value->byteLength()));
    return ret;
  }

  struct Iterator {
    bool done = false;
    Vector<uint8_t> value;
  };

  // Performs a single read from |reader|, converting the output to the
  // Iterator type. Assumes that the readable stream is not errored.
  static Iterator Read(V8TestingScope& scope,
                       ReadableStreamDefaultReader* reader) {
    auto* script_state = scope.GetScriptState();
    auto read_promise = reader->read(script_state, ASSERT_NO_EXCEPTION);
    ScriptPromiseTester tester(script_state, read_promise);
    tester.WaitUntilSettled();
    EXPECT_TRUE(tester.IsFulfilled());
    return IteratorFromReadResult(scope, tester.Value().V8Value());
  }

  static Iterator Read(V8TestingScope& scope,
                       ReadableStreamBYOBReader* reader,
                       NotShared<DOMArrayBufferView> view) {
    auto* script_state = scope.GetScriptState();
    auto read_promise = reader->read(script_state, view, ASSERT_NO_EXCEPTION);
    ScriptPromiseTester tester(script_state, read_promise);
    tester.WaitUntilSettled();
    EXPECT_TRUE(tester.IsFulfilled());
    return IteratorFromReadResult(scope, tester.Value().V8Value());
  }

  static Iterator IteratorFromReadResult(V8TestingScope& scope,
                                         v8::Local<v8::Value> result) {
    CHECK(result->IsObject());
    Iterator ret;
    v8::Local<v8::Value> v8value;
    if (!V8UnpackIterationResult(scope.GetScriptState(),
                                 result.As<v8::Object>(), &v8value,
                                 &ret.done)) {
      ADD_FAILURE() << "Couldn't unpack iterator";
      return {};
    }
    if (ret.done) {
      EXPECT_TRUE(v8value->IsUndefined());
      return ret;
    }

    ret.value = ToVector(scope, v8value);
    return ret;
  }

  base::MockOnceCallback<void(std::optional<uint8_t>)> mock_on_abort_;
  test::TaskEnvironment task_environment_;
  mojo::ScopedDataPipeProducerHandle data_pipe_producer_;
  mojo::ScopedDataPipeConsumerHandle data_pipe_consumer_;
};

TEST_F(IncomingStreamTest, Create) {
  V8TestingScope scope;
  auto* incoming_stream = CreateIncomingStream(scope);
  EXPECT_TRUE(incoming_stream->Readable());
}

TEST_F(IncomingStreamTest, ReadArrayBuffer) {
  V8TestingScope scope;

  auto* incoming_stream = CreateIncomingStream(scope);
  auto* script_state = scope.GetScriptState();
  auto* reader = incoming_stream->Readable()->GetDefaultReaderForTesting(
      script_state, ASSERT_NO_EXCEPTION);
  WriteToPipe({'A'});

  Iterator result = Read(scope, reader);
  EXPECT_FALSE(result.done);
  EXPECT_THAT(result.value, ElementsAre('A'));
}

// Respond BYOB requests created before and after receiving data.
TEST_F(IncomingStreamTest, ReadArrayBufferWithBYOBReader) {
  V8TestingScope scope;

  auto* incoming_stream = CreateIncomingStream(scope);
  auto* script_state = scope.GetScriptState();
  auto* reader = incoming_stream->Readable()->GetBYOBReaderForTesting(
      script_state, ASSERT_NO_EXCEPTION);
  NotShared<DOMArrayBufferView> view =
      NotShared<DOMUint8Array>(DOMUint8Array::Create(1));
  auto read_promise = reader->read(script_state, view, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, read_promise);
  EXPECT_FALSE(tester.IsFulfilled());

  WriteToPipe({'A', 'B', 'C'});

  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  Iterator result = IteratorFromReadResult(scope, tester.Value().V8Value());
  EXPECT_FALSE(result.done);
  EXPECT_THAT(result.value, ElementsAre('A'));

  view = NotShared<DOMUint8Array>(DOMUint8Array::Create(2));
  result = Read(scope, reader, view);
  EXPECT_FALSE(result.done);
  EXPECT_THAT(result.value, ElementsAre('B', 'C'));
}

// Reading data followed by a remote close should not lose data.
TEST_F(IncomingStreamTest, ReadThenClosedWithFin) {
  V8TestingScope scope;

  auto* incoming_stream = CreateIncomingStream(scope);

  EXPECT_CALL(mock_on_abort_, Run(std::optional<uint8_t>()));

  auto* script_state = scope.GetScriptState();
  auto* reader = incoming_stream->Readable()->GetDefaultReaderForTesting(
      script_state, ASSERT_NO_EXCEPTION);
  WriteToPipe({'B'});
  incoming_stream->OnIncomingStreamClosed(true);

  Iterator result1 = Read(scope, reader);
  EXPECT_FALSE(result1.done);
  EXPECT_THAT(result1.value, ElementsAre('B'));

  // This write arrives "out of order" due to the data pipe not being
  // synchronised with the mojo interface.
  WriteToPipe({'C'});
  ClosePipe();

  Iterator result2 = Read(scope, reader);
  EXPECT_FALSE(result2.done);
  EXPECT_THAT(result2.value, ElementsAre('C'));

  Iterator result3 = Read(scope, reader);
  EXPECT_TRUE(result3.done);
}

// Reading data followed by a remote abort should not lose data.
TEST_F(IncomingStreamTest, ReadThenClosedWithoutFin) {
  V8TestingScope scope;

  auto* incoming_stream = CreateIncomingStream(scope);

  EXPECT_CALL(mock_on_abort_, Run(std::optional<uint8_t>()));

  auto* script_state = scope.GetScriptState();
  auto* reader = incoming_stream->Readable()->GetDefaultReaderForTesting(
      script_state, ASSERT_NO_EXCEPTION);
  WriteToPipe({'B'});
  incoming_stream->OnIncomingStreamClosed(false);

  Iterator result1 = Read(scope, reader);
  EXPECT_FALSE(result1.done);
  EXPECT_THAT(result1.value, ElementsAre('B'));

  // This write arrives "out of order" due to the data pipe not being
  // synchronized with the mojo interface.
  WriteToPipe({'C'});
  ClosePipe();

  Iterator result2 = Read(scope, reader);
  EXPECT_FALSE(result2.done);

  // Even if the stream is not cleanly closed, we still endeavour to deliver all
  // data.
  EXPECT_THAT(result2.value, ElementsAre('C'));

  auto result3 = reader->read(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester result3_tester(script_state, result3);
  result3_tester.WaitUntilSettled();
  EXPECT_TRUE(result3_tester.IsRejected());
  DOMException* exception = V8DOMException::ToWrappable(
      scope.GetIsolate(), result3_tester.Value().V8Value());
  ASSERT_TRUE(exception);
  EXPECT_EQ(exception->code(),
            static_cast<uint16_t>(DOMExceptionCode::kNetworkError));
  EXPECT_EQ(exception->message(),
            "The stream was aborted by the remote server");
}

// Reading after remote close should not lose data.
TEST_F(IncomingStreamTest, ClosedWithFinThenRead) {
  V8TestingScope scope;

  auto* incoming_stream = CreateIncomingStream(scope);

  EXPECT_CALL(mock_on_abort_, Run(std::optional<uint8_t>()));

  auto* script_state = scope.GetScriptState();
  auto* reader = incoming_stream->Readable()->GetDefaultReaderForTesting(
      script_state, ASSERT_NO_EXCEPTION);
  WriteToPipe({'B'});
  incoming_stream->OnIncomingStreamClosed(true);
  ClosePipe();

  Iterator result1 = Read(scope, reader);
  EXPECT_FALSE(result1.done);
  EXPECT_THAT(result1.value, ElementsAre('B'));

  Iterator result2 = Read(scope, reader);
  EXPECT_TRUE(result2.done);
}

// reader.closed is fulfilled without any read() call, when the stream is empty.
TEST_F(IncomingStreamTest, ClosedWithFinWithoutRead) {
  V8TestingScope scope;

  auto* incoming_stream = CreateIncomingStream(scope);

  EXPECT_CALL(mock_on_abort_, Run(std::optional<uint8_t>()));

  auto* script_state = scope.GetScriptState();
  auto* reader = incoming_stream->Readable()->GetDefaultReaderForTesting(
      script_state, ASSERT_NO_EXCEPTION);
  incoming_stream->OnIncomingStreamClosed(true);
  ClosePipe();

  ScriptPromiseTester tester(script_state, reader->closed(script_state));
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
}

TEST_F(IncomingStreamTest, DataPipeResetBeforeClosedWithFin) {
  V8TestingScope scope;

  auto* incoming_stream = CreateIncomingStream(scope);

  EXPECT_CALL(mock_on_abort_, Run(std::optional<uint8_t>()));

  auto* script_state = scope.GetScriptState();
  auto* reader = incoming_stream->Readable()->GetDefaultReaderForTesting(
      script_state, ASSERT_NO_EXCEPTION);
  WriteToPipe({'E'});
  ClosePipe();
  incoming_stream->OnIncomingStreamClosed(true);

  Iterator result1 = Read(scope, reader);
  EXPECT_FALSE(result1.done);
  EXPECT_THAT(result1.value, ElementsAre('E'));

  Iterator result2 = Read(scope, reader);
  EXPECT_TRUE(result2.done);
}

TEST_F(IncomingStreamTest, DataPipeResetBeforeClosedWithoutFin) {
  V8TestingScope scope;

  auto* incoming_stream = CreateIncomingStream(scope);

  EXPECT_CALL(mock_on_abort_, Run(std::optional<uint8_t>()));

  auto* script_state = scope.GetScriptState();
  auto* reader = incoming_stream->Readable()->GetDefaultReaderForTesting(
      script_state, ASSERT_NO_EXCEPTION);
  WriteToPipe({'F'});
  ClosePipe();
  incoming_stream->OnIncomingStreamClosed(false);

  Iterator result1 = Read(scope, reader);
  EXPECT_FALSE(result1.done);
  EXPECT_THAT(result1.value, ElementsAre('F'));

  auto result2 = reader->read(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester result2_tester(script_state, result2);
  result2_tester.WaitUntilSettled();
  EXPECT_TRUE(result2_tester.IsRejected());
  DOMException* exception = V8DOMException::ToWrappable(
      scope.GetIsolate(), result2_tester.Value().V8Value());
  ASSERT_TRUE(exception);
  EXPECT_EQ(exception->code(),
            static_cast<uint16_t>(DOMExceptionCode::kNetworkError));
  EXPECT_EQ(exception->message(),
            "The stream was aborted by the remote server");
}

TEST_F(IncomingStreamTest, WriteToPipeWithPendingRead) {
  V8TestingScope scope;

  auto* incoming_stream = CreateIncomingStream(scope);
  auto* script_state = scope.GetScriptState();
  auto* reader = incoming_stream->Readable()->GetDefaultReaderForTesting(
      script_state, ASSERT_NO_EXCEPTION);
  auto read_promise = reader->read(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, read_promise);

  test::RunPendingTasks();

  WriteToPipe({'A'});

  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());

  Iterator result = IteratorFromReadResult(scope, tester.Value().V8Value());
  EXPECT_FALSE(result.done);
  EXPECT_THAT(result.value, ElementsAre('A'));
}

TEST_F(IncomingStreamTest, Cancel) {
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();

  auto* incoming_stream = CreateIncomingStream(scope);

  EXPECT_CALL(mock_on_abort_, Run(std::make_optional<uint8_t>(0)));

  auto* reader = incoming_stream->Readable()->GetDefaultReaderForTesting(
      script_state, ASSERT_NO_EXCEPTION);
  auto promise = reader->cancel(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, promise);

  test::RunPendingTasks();

  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
}

TEST_F(IncomingStreamTest, CancelWithWebTransportError) {
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  v8::Isolate* isolate = scope.GetIsolate();

  auto* incoming_stream = CreateIncomingStream(scope);

  EXPECT_CALL(mock_on_abort_, Run(std::make_optional<uint8_t>(0)));

  v8::Local<v8::Value> error =
      WebTransportError::Create(isolate,
                                /*stream_error_code=*/std::nullopt, "foobar",
                                V8WebTransportErrorSource::Enum::kStream);
  auto* reader = incoming_stream->Readable()->GetDefaultReaderForTesting(
      script_state, ASSERT_NO_EXCEPTION);
  auto promise = reader->cancel(script_state, ScriptValue(isolate, error),
                                ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, promise);

  test::RunPendingTasks();

  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
}

TEST_F(IncomingStreamTest, CancelWithWebTransportErrorWithCode) {
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  v8::Isolate* isolate = scope.GetIsolate();

  auto* incoming_stream = CreateIncomingStream(scope);

  EXPECT_CALL(mock_on_abort_, Run(std::make_optional<uint8_t>(19)));

  v8::Local<v8::Value> error =
      WebTransportError::Create(isolate,
                                /*stream_error_code=*/19, "foobar",
                                V8WebTransportErrorSource::Enum::kStream);
  auto* reader = incoming_stream->Readable()->GetDefaultReaderForTesting(
      script_state, ASSERT_NO_EXCEPTION);
  auto promise = reader->cancel(script_state, ScriptValue(isolate, error),
                                ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, promise);

  test::RunPendingTasks();

  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
}

}  // namespace

}  // namespace blink

"""

```