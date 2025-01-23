Response:
Let's break down the thought process for analyzing this C++ unit test file.

**1. Understanding the Core Question:**

The request asks for the functionality of `tcp_readable_stream_wrapper_unittest.cc`, its relationship to web technologies, examples of logic, common errors, and debugging tips.

**2. Initial Scan for Key Information:**

The filename itself (`tcp_readable_stream_wrapper_unittest.cc`) is a huge clue. The `unittest` suffix immediately tells us it's for testing. The `tcp_readable_stream_wrapper` part points to the core component being tested. Knowing it's in the `blink/renderer/modules/direct_sockets` directory suggests it's related to low-level network communication directly from the browser, bypassing some higher-level abstractions.

**3. Identifying the Tested Class:**

The `#include` statements confirm the primary class under test: `TCPReadableStreamWrapper`.

**4. Recognizing Testing Frameworks and Helpers:**

The presence of `#include` statements like:

* `"third_party/blink/renderer/platform/testing/unit_test_helpers.h"`
* `"third_party/blink/renderer/platform/testing/task_environment.h"`
* `"third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"`
* `"third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"`

clearly indicates the use of Blink's testing infrastructure and V8-specific testing utilities. This suggests the class interacts with JavaScript somehow.

**5. Analyzing the Test Structure:**

The file contains several `TEST` macros. Each test function focuses on a specific aspect of `TCPReadableStreamWrapper`'s functionality. Common patterns emerge:

* **Setup:** Creating a `V8TestingScope` and a `StreamCreator`. The `StreamCreator` seems responsible for setting up the underlying data pipe used by the `TCPReadableStreamWrapper`.
* **Action:** Interacting with the `TCPReadableStreamWrapper`, usually by getting its `ReadableStream` and its reader. Simulating data being written to the pipe.
* **Assertion:** Using `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, and `EXPECT_THAT` to verify the expected behavior. The `ScriptPromiseTester` is used to handle asynchronous operations.

**6. Deciphering the `StreamCreator` Class:**

The `StreamCreator` class is crucial. It manages the Mojo data pipe, which serves as the underlying communication channel for the readable stream. Key methods:

* `Create()`: Creates the `TCPReadableStreamWrapper` and the underlying data pipe.
* `ResetPipe()`: Simulates the data pipe being closed.
* `WriteToPipe()`: Sends data through the data pipe.
* `Read()`: Reads data from the readable stream using JavaScript API.
* `ToVector()`: Converts JavaScript `Uint8Array` to a C++ vector.

**7. Connecting to JavaScript, HTML, and CSS:**

The presence of `ReadableStream`, `Uint8Array`, and `ScriptPromise` in the test code strongly suggests interaction with the JavaScript Streams API. While this specific file doesn't directly manipulate HTML or CSS, the `TCPReadableStreamWrapper` is designed to be exposed to JavaScript, allowing web developers to handle TCP socket data. The connection is indirect but important.

**8. Identifying Logic and Scenarios:**

Each test case demonstrates a specific scenario:

* `Create`: Basic creation of the wrapper.
* `ReadArrayBuffer`: Reading data from the stream.
* `WriteToPipeWithPendingRead`: Handling data arrival when a read is pending.
* `TriggerClose`: Simulating graceful and abrupt closure of the underlying socket from the C++ side.
* `TriggerCloseInReverseOrder`: Testing the order of closure events.
* `ErrorCancelReset` and `ResetCancelError`: Investigating the interaction between closing the socket and calling `readable.cancel()` from JavaScript.

**9. Identifying Potential User Errors and Debugging Clues:**

By analyzing the tests, potential user errors become apparent:

* Incorrectly handling stream closure (not checking `done` or errors).
* Assuming data will arrive immediately without waiting for the promise.
* Not understanding the difference between graceful closure and abrupt abortion.

The tests themselves provide debugging clues by demonstrating the expected behavior in different scenarios. If a real-world implementation deviates from these tests, it indicates a bug. The stepping stones in the debugging scenario were derived from the test flow: open socket, get readable stream, get reader, attempt to read, then trigger a close.

**10. Structuring the Answer:**

Finally, organize the findings into the requested categories: Functionality, Relationship to web technologies, Logic examples, User errors, and Debugging clues. Use clear and concise language, and provide specific examples from the code. For the logic examples,  clearly state the assumptions and expected outcomes.
这个文件 `tcp_readable_stream_wrapper_unittest.cc` 是 Chromium Blink 引擎中用于测试 `TCPReadableStreamWrapper` 类的单元测试文件。它的主要功能是验证 `TCPReadableStreamWrapper` 类的各种行为是否符合预期。

**功能列举:**

1. **创建和初始化测试环境:**  使用 `V8TestingScope` 创建一个模拟的 V8 JavaScript 引擎环境，用于执行与 JavaScript API 相关的测试。
2. **创建 `TCPReadableStreamWrapper` 实例:**  测试 `TCPReadableStreamWrapper` 对象的创建和基本属性（例如，是否具有可读流）。
3. **模拟数据管道交互:** 使用 Mojo 数据管道模拟底层的 TCP 连接数据传输。`StreamCreator` 类负责创建和管理这个数据管道。
4. **测试从可读流读取数据:**  验证通过 `TCPReadableStreamWrapper` 暴露的 JavaScript `ReadableStream` API 读取数据的能力，包括读取 `Uint8Array` 数据块。
5. **测试数据写入和挂起读取的交互:**  测试当 JavaScript 代码发起读取操作后，底层数据到达时，数据是否能正确传递给 JavaScript。
6. **测试流的关闭和错误处理:** 涵盖了正常关闭（graceful close）和异常关闭（aborted close）两种情况，并测试了在不同关闭触发顺序下的行为。
7. **测试 `readable.cancel()` 方法:** 验证 JavaScript 中调用 `readable.cancel()` 方法对底层数据管道和 `TCPReadableStreamWrapper` 状态的影响。
8. **断言测试结果:** 使用 `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `EXPECT_THAT` 等宏来验证测试的预期结果。
9. **处理异步操作:** 使用 `ScriptPromiseTester` 来处理与 JavaScript Promise 相关的异步操作，确保测试的正确性。

**与 JavaScript, HTML, CSS 的关系:**

`TCPReadableStreamWrapper` 本身并不直接操作 HTML 或 CSS。它的作用是提供一个桥梁，将底层的 TCP socket 数据流暴露给 JavaScript，作为 `ReadableStream` API 的一个实例。

* **JavaScript:** `TCPReadableStreamWrapper` 的核心作用是与 JavaScript 的 Streams API (特别是 `ReadableStream`) 交互。JavaScript 代码可以使用 `getReader()` 方法获取 `ReadableStreamDefaultReader`，然后使用 `read()` 方法从流中读取数据。
    * **举例说明:** 在测试代码中，可以看到以下模式：
        ```c++
        auto* reader =
            tcp_readable_stream_wrapper->Readable()->GetDefaultReaderForTesting(
                script_state, ASSERT_NO_EXCEPTION);
        auto read_promise = reader->read(script_state, ASSERT_NO_EXCEPTION);
        ScriptPromiseTester tester(script_state, read_promise);
        ```
        这段代码模拟了 JavaScript 获取可读流的 reader 并调用 `read()` 方法。`TCPReadableStreamWrapper` 内部会将从底层数据管道接收到的数据转换为 JavaScript 可以处理的格式（通常是 `Uint8Array`）。

* **HTML:**  在实际应用中，JavaScript 可以通过各种方式获取到这个由 `TCPReadableStreamWrapper` 提供的 `ReadableStream` 实例。例如，可以通过一个自定义的 JavaScript API 暴露出来，然后在 HTML 中的 `<script>` 标签里使用。
    * **举例说明:** 假设有一个 JavaScript 函数 `connectToTCPSocket(host, port)` 返回一个 `ReadableStream`，而这个 `ReadableStream` 的底层就是由 `TCPReadableStreamWrapper` 实现的。HTML 中可能会有这样的代码：
        ```html
        <script>
          connectToTCPSocket('example.com', 8080).then(readableStream => {
            const reader = readableStream.getReader();
            let done = false;
            const read = () => {
              reader.read().then(({ value, done: readDone }) => {
                if (readDone) {
                  console.log('Stream finished');
                  return;
                }
                // 处理接收到的数据 (value 是 Uint8Array)
                console.log('Received data:', value);
                read();
              });
            };
            read();
          });
        </script>
        ```

* **CSS:**  `TCPReadableStreamWrapper` 与 CSS 没有直接关系。

**逻辑推理的假设输入与输出:**

**测试用例: `ReadArrayBuffer`**

* **假设输入:**
    * 底层 Mojo 数据管道写入了包含字符 'A' 的字节数据。
    * JavaScript 代码已经获取了可读流的 reader 并调用了 `read()` 方法。
* **逻辑推理:** `TCPReadableStreamWrapper` 应该从数据管道读取数据，将其转换为 `Uint8Array`，并通过 Promise 将其返回给 JavaScript。
* **预期输出:** `ScriptPromiseTester` 应该处于 fulfilled 状态，并且返回的 value 应该是一个包含单个字节 'A' 的 `Uint8Array`。

**测试用例: `TriggerClose` (graceful = true)**

* **假设输入:**
    * JavaScript 代码已经获取了可读流的 reader 并调用了 `read()` 方法。
    * `TCPReadableStreamWrapper` 的 `ErrorStream` 方法被调用，参数为 `net::OK` (表示正常关闭)。
    * 底层 Mojo 数据管道被重置 (模拟连接关闭)。
* **逻辑推理:**  `TCPReadableStreamWrapper` 应该将流的状态标记为 closed，并且当之前挂起的 `read()` Promise resolve 时，其 `done` 属性应该为 true。
* **预期输出:** `ScriptPromiseTester` 应该处于 fulfilled 状态，并且返回的 value 应该是 `undefined`，`done` 属性为 `true`。`TCPReadableStreamWrapper` 的状态应该是 `StreamWrapper::State::kClosed`。

**用户或编程常见的使用错误举例:**

1. **没有正确处理流结束:** 用户可能没有检查 `reader.read()` 返回的 Promise 的 `done` 属性，导致在流已经结束的情况下仍然尝试读取数据。
    * **错误示例 (JavaScript):**
        ```javascript
        reader.read().then(({ value }) => {
          console.log('Received data:', value); // 假设 value 总是存在
        });
        ```
    * **正确示例 (JavaScript):**
        ```javascript
        reader.read().then(({ value, done }) => {
          if (done) {
            console.log('Stream finished');
            return;
          }
          console.log('Received data:', value);
        });
        ```

2. **假设数据会立即到达:** 用户可能在调用 `reader.read()` 后立即尝试访问数据，而没有等待 Promise resolve。
    * **错误示例 (JavaScript):**
        ```javascript
        const readPromise = reader.read();
        console.log('Trying to access data:', readPromise.value); // 错误：Promise 还没有 resolve
        ```
    * **正确示例 (JavaScript):**
        ```javascript
        reader.read().then(({ value }) => {
          console.log('Received data:', value);
        });
        ```

3. **对流的关闭状态处理不当:** 用户可能没有正确处理流的错误或关闭状态，导致程序出现异常。例如，在流已经关闭后仍然尝试写入数据（尽管这个文件主要关注读取）。

**用户操作如何一步步到达这里作为调试线索:**

假设用户在使用一个基于 Chromium 内核的浏览器访问一个使用了 Direct Sockets API 的网页应用。以下是可能的操作步骤：

1. **用户打开网页:** 用户在浏览器地址栏输入网址或点击链接，访问一个使用了 Direct Sockets API 的网页。
2. **网页 JavaScript 代码尝试建立 TCP 连接:** 网页的 JavaScript 代码使用 `navigator.connectToTCPPort()` (或者类似的 API) 尝试连接到远程 TCP 服务器。
3. **浏览器内部创建 Direct Socket:**  浏览器内部会处理这个连接请求，并创建一个底层的 TCP socket。
4. **Blink 引擎创建 `TCPReadableStreamWrapper`:** 为了将底层的 TCP socket 数据暴露给 JavaScript，Blink 引擎会创建一个 `TCPReadableStreamWrapper` 实例，将底层的 socket 数据流包装成一个 JavaScript `ReadableStream`。
5. **JavaScript 代码获取 ReadableStream 的 reader:** 网页的 JavaScript 代码调用 `readableStream.getReader()` 获取一个 reader 对象。
6. **JavaScript 代码调用 reader.read():**  JavaScript 代码调用 `reader.read()` 尝试从流中读取数据。此时，如果底层 socket 没有数据，这个 Promise 将会挂起。
7. **远程服务器发送数据或关闭连接:**
    * **数据到达:** 远程服务器发送数据，底层 TCP socket 接收到数据，`TCPReadableStreamWrapper` 会将数据推送到 Mojo 数据管道，并最终传递给 JavaScript。
    * **连接关闭:** 远程服务器关闭连接，或者网络出现错误，底层的 TCP socket 会收到关闭或错误事件。`TCPReadableStreamWrapper` 的 `ErrorStream` 方法会被调用，并且 Mojo 数据管道会被重置。

**作为调试线索:**

当遇到与 Direct Sockets 相关的 bug 时，查看 `tcp_readable_stream_wrapper_unittest.cc` 中的测试用例可以帮助理解 `TCPReadableStreamWrapper` 的预期行为。例如：

* **数据读取问题:** 如果 JavaScript 代码无法正确读取数据，可以查看 `ReadArrayBuffer` 和 `WriteToPipeWithPendingRead` 测试用例，理解数据是如何从底层传递到 JavaScript 的。
* **流关闭问题:** 如果遇到流关闭相关的错误，可以查看 `TriggerClose` 和 `TriggerCloseInReverseOrder` 测试用例，了解正常关闭和异常关闭的不同处理方式。
* **`readable.cancel()` 的行为:** 如果涉及到取消流的操作，可以查看 `ErrorCancelReset` 和 `ResetCancelError` 测试用例，理解取消操作对流状态和底层连接的影响。

总而言之，这个单元测试文件是理解 `TCPReadableStreamWrapper` 功能和行为的重要参考，可以帮助开发者理解当用户在网页上执行与 Direct Sockets 相关的操作时，Blink 引擎内部是如何处理数据流的。

### 提示词
```
这是目录为blink/renderer/modules/direct_sockets/tcp_readable_stream_wrapper_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/direct_sockets/tcp_readable_stream_wrapper.h"

#include "base/containers/span.h"
#include "base/functional/callback_helpers.h"
#include "base/test/mock_callback.h"
#include "net/base/net_errors.h"
#include "third_party/blink/renderer/bindings/core/v8/iterable.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream_read_result.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/modules/direct_sockets/stream_wrapper.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

namespace {

using ::testing::ElementsAre;

// The purpose of this class is to ensure that the data pipe is reset before the
// V8TestingScope is destroyed, so that the TCPReadableStreamWrapper object
// doesn't try to create a DOMException after the ScriptState has gone away.
class StreamCreator : public GarbageCollected<StreamCreator> {
 public:
  StreamCreator() = default;
  ~StreamCreator() = default;

  // The default value of |capacity| means some sensible value selected by mojo.
  TCPReadableStreamWrapper* Create(V8TestingScope& scope,
                                   uint32_t capacity = 0) {
    MojoCreateDataPipeOptions options;
    options.struct_size = sizeof(MojoCreateDataPipeOptions);
    options.flags = MOJO_CREATE_DATA_PIPE_FLAG_NONE;
    options.element_num_bytes = 1;
    options.capacity_num_bytes = capacity;

    mojo::ScopedDataPipeConsumerHandle data_pipe_consumer;
    MojoResult result =
        mojo::CreateDataPipe(&options, data_pipe_producer_, data_pipe_consumer);
    if (result != MOJO_RESULT_OK) {
      ADD_FAILURE() << "CreateDataPipe() returned " << result;
    }

    auto* script_state = scope.GetScriptState();
    stream_wrapper_ = MakeGarbageCollected<TCPReadableStreamWrapper>(
        script_state,
        WTF::BindOnce(&StreamCreator::Close, WrapWeakPersistent(this)),
        std::move(data_pipe_consumer));

    scope.PerformMicrotaskCheckpoint();
    test::RunPendingTasks();

    return stream_wrapper_.Get();
  }

  void ResetPipe() { data_pipe_producer_.reset(); }

  void WriteToPipe(Vector<uint8_t> data) {
    EXPECT_EQ(data_pipe_producer_->WriteAllData(data), MOJO_RESULT_OK);
  }

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
  // static Iterator Read(const V8TestingScope& scope,
  Iterator Read(V8TestingScope& scope, ReadableStreamDefaultReader* reader) {
    auto* script_state = scope.GetScriptState();
    auto read_promise = reader->read(script_state, ASSERT_NO_EXCEPTION);
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

  bool CloseCalledWith(bool error) const { return close_called_with_ == error; }

  void Trace(Visitor* visitor) const { visitor->Trace(stream_wrapper_); }

  void Cleanup() { data_pipe_producer_.reset(); }

 private:
  void Close(ScriptValue exception) {
    close_called_with_ = !exception.IsEmpty();
  }

  std::optional<bool> close_called_with_;
  mojo::ScopedDataPipeProducerHandle data_pipe_producer_;
  Member<TCPReadableStreamWrapper> stream_wrapper_;
};

class ScopedStreamCreator {
 public:
  explicit ScopedStreamCreator(StreamCreator* stream_creator)
      : stream_creator_(stream_creator) {}

  ~ScopedStreamCreator() { stream_creator_->Cleanup(); }

  StreamCreator* operator->() const { return stream_creator_; }

 private:
  Persistent<StreamCreator> stream_creator_;
};

TEST(TCPReadableStreamWrapperTest, Create) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(MakeGarbageCollected<StreamCreator>());
  auto* tcp_readable_stream_wrapper = stream_creator->Create(scope);

  EXPECT_TRUE(tcp_readable_stream_wrapper->Readable());
}

TEST(TCPReadableStreamWrapperTest, ReadArrayBuffer) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(MakeGarbageCollected<StreamCreator>());
  auto* tcp_readable_stream_wrapper = stream_creator->Create(scope);

  auto* script_state = scope.GetScriptState();
  auto* reader =
      tcp_readable_stream_wrapper->Readable()->GetDefaultReaderForTesting(
          script_state, ASSERT_NO_EXCEPTION);
  stream_creator->WriteToPipe({'A'});

  StreamCreator::Iterator result = stream_creator->Read(scope, reader);
  EXPECT_FALSE(result.done);
  EXPECT_THAT(result.value, ElementsAre('A'));
}

TEST(TCPReadableStreamWrapperTest, WriteToPipeWithPendingRead) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(MakeGarbageCollected<StreamCreator>());
  auto* tcp_readable_stream_wrapper = stream_creator->Create(scope);

  auto* script_state = scope.GetScriptState();
  auto* reader =
      tcp_readable_stream_wrapper->Readable()->GetDefaultReaderForTesting(
          script_state, ASSERT_NO_EXCEPTION);
  auto read_promise = reader->read(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, read_promise);

  stream_creator->WriteToPipe({'A'});

  tester.WaitUntilSettled();
  ASSERT_TRUE(tester.IsFulfilled());

  StreamCreator::Iterator result =
      stream_creator->IteratorFromReadResult(scope, tester.Value().V8Value());
  EXPECT_FALSE(result.done);
  EXPECT_THAT(result.value, ElementsAre('A'));
}

class TCPReadableStreamWrapperCloseTest : public testing::TestWithParam<bool> {
};

INSTANTIATE_TEST_SUITE_P(/**/,
                         TCPReadableStreamWrapperCloseTest,
                         testing::Bool());

TEST_P(TCPReadableStreamWrapperCloseTest, TriggerClose) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(MakeGarbageCollected<StreamCreator>());
  auto* tcp_readable_stream_wrapper = stream_creator->Create(scope);

  auto* script_state = scope.GetScriptState();
  auto* reader =
      tcp_readable_stream_wrapper->Readable()->GetDefaultReaderForTesting(
          script_state, ASSERT_NO_EXCEPTION);
  auto read_promise = reader->read(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, read_promise);

  stream_creator->WriteToPipe({'A'});

  bool graceful = GetParam();

  // 1. OnReadError(...) is called.
  tcp_readable_stream_wrapper->ErrorStream(graceful ? net::OK
                                                    : net::ERR_UNEXPECTED);

  // 2. pipe reset event arrives.
  stream_creator->ResetPipe();
  test::RunPendingTasks();

  tester.WaitUntilSettled();

  ASSERT_TRUE(tester.IsFulfilled());
  ASSERT_EQ(tcp_readable_stream_wrapper->GetState(),
            graceful ? StreamWrapper::State::kClosed
                     : StreamWrapper::State::kAborted);
}

TEST_P(TCPReadableStreamWrapperCloseTest, TriggerCloseInReverseOrder) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(MakeGarbageCollected<StreamCreator>());
  auto* tcp_readable_stream_wrapper = stream_creator->Create(scope);

  auto* script_state = scope.GetScriptState();
  auto* reader =
      tcp_readable_stream_wrapper->Readable()->GetDefaultReaderForTesting(
          script_state, ASSERT_NO_EXCEPTION);
  auto read_promise = reader->read(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, read_promise);

  stream_creator->WriteToPipe({'A'});

  bool graceful = GetParam();

  // 1. pipe reset event arrives.
  stream_creator->ResetPipe();
  test::RunPendingTasks();

  // 2. OnReadError(...) is called.
  tcp_readable_stream_wrapper->ErrorStream(graceful ? net::OK
                                                    : net::ERR_UNEXPECTED);
  tester.WaitUntilSettled();

  ASSERT_TRUE(stream_creator->CloseCalledWith(!graceful));

  ASSERT_TRUE(tester.IsFulfilled());
  ASSERT_EQ(tcp_readable_stream_wrapper->GetState(),
            graceful ? StreamWrapper::State::kClosed
                     : StreamWrapper::State::kAborted);
}

TEST_P(TCPReadableStreamWrapperCloseTest, ErrorCancelReset) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(MakeGarbageCollected<StreamCreator>());
  auto* tcp_readable_stream_wrapper = stream_creator->Create(scope);

  auto* script_state = scope.GetScriptState();

  bool graceful = GetParam();

  // 1. OnReadError(...) is called.
  tcp_readable_stream_wrapper->ErrorStream(graceful ? net::OK
                                                    : net::ERR_UNEXPECTED);

  // 2. readable.cancel() is called.
  auto tester = ScriptPromiseTester(
      script_state, tcp_readable_stream_wrapper->Readable()->cancel(
                        script_state, ASSERT_NO_EXCEPTION));
  tester.WaitUntilSettled();
  ASSERT_TRUE(tester.IsFulfilled());

  // 3. pipe reset event arrives.
  stream_creator->ResetPipe();
  test::RunPendingTasks();

  ASSERT_EQ(tcp_readable_stream_wrapper->GetState(),
            graceful ? StreamWrapper::State::kClosed
                     : StreamWrapper::State::kAborted);
}

TEST_P(TCPReadableStreamWrapperCloseTest, ResetCancelError) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(MakeGarbageCollected<StreamCreator>());
  auto* tcp_readable_stream_wrapper = stream_creator->Create(scope);

  auto* script_state = scope.GetScriptState();

  bool graceful = GetParam();

  // 1. pipe reset event arrives.
  stream_creator->ResetPipe();
  test::RunPendingTasks();

  // 2. readable.cancel() is called.
  auto tester = ScriptPromiseTester(
      script_state, tcp_readable_stream_wrapper->Readable()->cancel(
                        script_state, ASSERT_NO_EXCEPTION));
  tester.WaitUntilSettled();
  ASSERT_TRUE(tester.IsFulfilled());

  // 3. OnReadError(...) is called.
  tcp_readable_stream_wrapper->ErrorStream(graceful ? net::OK
                                                    : net::ERR_UNEXPECTED);

  stream_creator->ResetPipe();

  // cancel() always has priority.
  ASSERT_EQ(tcp_readable_stream_wrapper->GetState(),
            StreamWrapper::State::kClosed);
}

}  // namespace

}  // namespace blink
```