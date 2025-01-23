Response:
Let's break down the thought process for analyzing this C++ unit test file.

**1. Initial Understanding of the Goal:**

The first thing is to recognize this is a unit test file. Unit tests verify the behavior of individual components in isolation. The filename `tcp_writable_stream_wrapper_unittest.cc` strongly suggests it tests the `TCPWritableStreamWrapper` class.

**2. Identifying Key Components and Their Roles:**

* **`TCPWritableStreamWrapper`:**  The core subject of the tests. The name implies it's a wrapper around a writable stream, likely related to TCP sockets.
* **`StreamCreator`:** A helper class. Its methods `Create` and `ResetPipe` hint at managing the creation and destruction of the `TCPWritableStreamWrapper` and its underlying data pipe. The purpose is to handle setup and teardown, potentially to avoid issues with V8 garbage collection.
* **`ScopedStreamCreator`:** A RAII (Resource Acquisition Is Initialization) wrapper around `StreamCreator`. It ensures `ResetPipe` is called when it goes out of scope. This is crucial for resource management.
* **`V8TestingScope`:**  Indicates this code interacts with the V8 JavaScript engine (Blink is the rendering engine for Chromium). It provides the necessary context for creating JavaScript objects and promises.
* **`DOMArrayBuffer`, `DOMUint8Array`:** These are JavaScript Typed Array counterparts in the C++ Blink codebase. They represent binary data that can be written to the stream.
* **`WritableStream`, `WritableStreamDefaultWriter`:** These are Web Streams API classes in the Blink implementation. The tests interact with the `TCPWritableStreamWrapper` through the standard Web Streams interface.
* **`mojo::ScopedDataPipeProducerHandle`, `mojo::ScopedDataPipeConsumerHandle`:** These are Mojo primitives for inter-process communication. The `TCPWritableStreamWrapper` likely uses a Mojo data pipe to send data.
* **`ScriptPromiseTester`:** A testing utility for working with JavaScript Promises in C++.
* **`net::` and `base::` namespaces:** Indicate use of networking and general utility classes from Chromium's base libraries.

**3. Analyzing Individual Tests:**

For each test function (`TEST(...)`), the goal is to understand what specific behavior of `TCPWritableStreamWrapper` is being verified.

* **`Create`:**  Basic instantiation test. Checks if a `TCPWritableStreamWrapper` can be created and if its `Writable()` method returns a valid `WritableStream`.
* **`WriteArrayBuffer`:**  Tests writing an `ArrayBuffer` to the stream. It checks if the data is correctly written to the underlying pipe. The use of `ScriptPromiseTester` suggests asynchronous behavior.
* **`WriteArrayBufferView`:** Similar to the previous test, but uses an `ArrayBufferView` (specifically `Uint8Array`), testing that views into buffers are handled correctly.
* **`AsyncWrite`:**  Focuses on asynchronous writing. It writes a large chunk of data that exceeds the pipe capacity and verifies that the writing happens in chunks and eventually completes successfully.
* **`WriteThenClose`:** Tests the interaction between writing data and closing the stream. It ensures that data written before closing is not lost.
* **`DISABLED_TriggerHasAborted`:** Tests the `ErrorStream` method and its effect on the stream's state. It's disabled, meaning it might be flaky or under development.
* **`TriggerClose` and `TriggerCloseInReverseOrder` (with `TCPWritableStreamWrapperCloseTestWithMaybePendingWrite`):** These parameterized tests explore the interaction between an error condition (`ErrorStream`) and the closing of the underlying data pipe. The parameterization (`testing::Bool()`) likely tests the behavior with and without a pending write operation. The "reverse order" test checks the sequence of events.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

The key connection point is the use of Web Streams API classes (`WritableStream`). This immediately tells us the `TCPWritableStreamWrapper` is intended to be used from JavaScript.

* **How it relates to JavaScript:**  JavaScript code would create a `WritableStream` (likely obtained through a direct sockets API) which is backed by the C++ `TCPWritableStreamWrapper`. JavaScript would then use the `WritableStream`'s `getWriter()` method and the writer's `write()` and `close()` methods.
* **HTML and CSS:**  Less directly related. Direct sockets are about network communication, which is typically initiated or managed by JavaScript. While the *result* of this communication might affect the DOM (and thus CSS styling), the `TCPWritableStreamWrapper` itself is lower-level infrastructure.

**5. Logical Reasoning (Assumptions and Outputs):**

For each test, consider the setup (input) and the expected outcome (output/assertion). The assumptions are usually based on the test's name and the methods being called.

* **Example (from `WriteArrayBuffer`):**
    * **Assumption:**  The `Create` method sets up a functional data pipe. The `getWriter` method returns a valid writer.
    * **Input:**  An `ArrayBuffer` containing "A".
    * **Action:**  Call `writer->write()` with the buffer.
    * **Expected Output:** The promise returned by `write()` is fulfilled. The data pipe contains the byte 'A'.

**6. Identifying Potential User/Programming Errors:**

Think about how a developer might misuse the API or encounter errors.

* **Writing after closing:**  Attempting to `write()` to a stream that has already been closed will likely result in an error.
* **Not handling errors:**  Failing to check the status of the promises returned by `write()` or `close()` can lead to unexpected behavior if the underlying socket encounters an issue.
* **Incorrect data types:**  Trying to write data that is not an `ArrayBuffer` or `ArrayBufferView` might cause an error.
* **Resource leaks:**  If the underlying resources (like the data pipe) are not properly managed (though `ScopedStreamCreator` helps with this), it could lead to leaks.

**7. Tracing User Operations (Debugging Clues):**

Imagine how a user's action in a web browser might lead to this code being executed.

1. **User Action:** User clicks a button or performs an action that triggers a JavaScript function.
2. **JavaScript Code:** This function uses a direct sockets API (e.g., `navigator.directSockets.connect(...)`).
3. **Blink Implementation:** The JavaScript call is handled by C++ code in Blink, potentially involving the creation of a `TCPWritableStreamWrapper`.
4. **`write()` calls:**  The JavaScript code obtains a `WritableStream` and its writer, then calls `writer.write(data)`.
5. **`TCPWritableStreamWrapper` interaction:** The `write()` call in JavaScript eventually calls the `write()` method of the `TCPWritableStreamWrapper`, which writes data to the Mojo data pipe.
6. **Unit Test Simulation:** The unit tests simulate these JavaScript interactions by directly creating and manipulating the C++ objects and using `ScriptPromiseTester` to mimic promise resolution.

**Self-Correction/Refinement during Analysis:**

* **Initial thought:** "This just tests writing data."
* **Correction:** "No, it also tests asynchronous writing, error handling (aborting), and the interaction between writing and closing."
* **Initial thought:** "The `StreamCreator` is just for setup."
* **Refinement:** "It's specifically designed to handle the lifetime of the data pipe to avoid issues with V8 garbage collection during testing."
* **Realization:**  The parameterized tests for closing are important because the order of events (error vs. pipe reset) can affect the outcome.

By following these steps, you can systematically analyze C++ unit test code, understand its purpose, and connect it to the broader context of web technologies. The key is to break down the code into its components, understand their roles, and then analyze the behavior being tested in each test case.
这个文件 `tcp_writable_stream_wrapper_unittest.cc` 是 Chromium Blink 引擎中 `direct_sockets` 模块的单元测试文件。它专门用于测试 `TCPWritableStreamWrapper` 类的功能。

**`TCPWritableStreamWrapper` 的功能：**

从代码和测试用例来看，`TCPWritableStreamWrapper` 的主要功能是：

1. **封装 TCP 可写流：** 它作为一个包装器，管理一个用于向 TCP 连接写入数据的底层机制（通过 Mojo data pipe 实现）。
2. **与 JavaScript Web Streams API 集成：**  它实现了 Web Streams API 中的 `WritableStream` 接口，使得 JavaScript 可以通过标准的 `WritableStream` API 来操作底层的 TCP 连接。
3. **数据写入：** 允许将 JavaScript 中的 `ArrayBuffer` 或 `ArrayBufferView` 类型的数据写入到 TCP 连接中。
4. **异步写入：** 处理数据量较大时的异步写入，确保不会阻塞渲染主线程。
5. **流的关闭和错误处理：**  能够正常关闭流，并在发生错误时通知 JavaScript。
6. **状态管理：** 维护流的状态，例如是否已关闭、是否已发生错误等。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`TCPWritableStreamWrapper` 直接与 **JavaScript** 相关，因为它实现了 Web Streams API，这是 JavaScript 中用于处理流数据的标准接口。

* **JavaScript 如何使用：**  在 JavaScript 中，开发者可以使用 `navigator.directSockets.connect()` API（假设存在这样的 API，从代码路径推测）来建立一个 TCP 连接。这个连接的写入端可能会被表示为一个 `WritableStream` 对象，而这个 `WritableStream` 的底层实现很可能就是 `TCPWritableStreamWrapper`。

   ```javascript
   // 假设存在 Direct Sockets API
   navigator.directSockets.connect('example.com', 80).then(socket => {
     const writableStream = socket.writable;
     const writer = writableStream.getWriter();
     const data = new TextEncoder().encode('Hello, server!');
     writer.write(data).then(() => {
       console.log('Data written successfully!');
       writer.close();
     });
   }).catch(error => {
     console.error('Connection failed:', error);
   });
   ```

   在这个例子中，`socket.writable` 返回的 `WritableStream` 对象，在 Blink 内部就可能由 `TCPWritableStreamWrapper` 来管理。`writer.write(data)` 操作最终会调用 `TCPWritableStreamWrapper` 的相关方法，将数据通过 Mojo data pipe 发送出去。

* **与 HTML 和 CSS 的关系：**  `TCPWritableStreamWrapper` 本身不直接与 HTML 或 CSS 交互。它的作用是提供底层的网络通信能力，JavaScript 可以利用这个能力来获取或发送数据，而这些数据最终可能会影响到 HTML 的结构或 CSS 的样式。

   **举例：**  一个网页应用可能需要通过 WebSocket 或自定义的 TCP 连接实时接收服务器推送的数据，并根据这些数据动态更新页面内容。`TCPWritableStreamWrapper` 可以作为这种自定义 TCP 连接的写入端实现，JavaScript 通过它将用户输入或其他状态信息发送给服务器。服务器处理后，可能会推送新的数据，JavaScript 接收到后会操作 DOM，从而改变 HTML 结构或元素的 CSS 样式。

**逻辑推理、假设输入与输出：**

以 `TCPWritableStreamWrapperTest.WriteArrayBuffer` 测试用例为例：

* **假设输入：**
    * 一个已经创建好的 `TCPWritableStreamWrapper` 实例。
    * 一个包含字符串 "A" 的 `DOMArrayBuffer` 对象。
* **操作：**
    1. 从 `TCPWritableStreamWrapper` 获取 `WritableStream`。
    2. 获取 `WritableStream` 的 writer。
    3. 调用 writer 的 `write()` 方法，传入包含 "A" 的 `DOMArrayBuffer`。
* **预期输出：**
    * `write()` 方法返回的 Promise 成功 fulfilled。
    * 底层的 Mojo data pipe 中包含了字节 'A'。
    * `stream_creator->ReadAllPendingData()` 返回一个包含字节 65 ('A' 的 ASCII 码) 的 Vector。

**用户或编程常见的使用错误举例：**

1. **在流关闭后尝试写入：**  用户可能会在 JavaScript 中调用 `writer.close()` 关闭流之后，仍然尝试调用 `writer.write()` 写入数据。这会导致错误，并且 `write()` 方法返回的 Promise 会被 reject。

   ```javascript
   navigator.directSockets.connect('example.com', 80).then(socket => {
     const writableStream = socket.writable;
     const writer = writableStream.getWriter();
     writer.close().then(() => {
       const data = new TextEncoder().encode('Trying to write after close!');
       writer.write(data).catch(error => {
         console.error('Write failed after close:', error); // 预期会进入这里
       });
     });
   });
   ```

   在 `TCPWritableStreamWrapper` 的测试中，相关的测试用例（例如 `WriteThenClose`）会验证在调用 `close()` 之后再进行写入操作的行为。

2. **没有正确处理写入 Promise 的 rejection：**  在网络环境不稳定的情况下，或者服务器端出现错误时，`write()` 操作可能会失败，导致 Promise 被 reject。如果开发者没有正确地处理 Promise 的 rejection，可能会导致程序出现未知的行为。

   ```javascript
   navigator.directSockets.connect('example.com', 80).then(socket => {
     const writableStream = socket.writable;
     const writer = writableStream.getWriter();
     const data = new TextEncoder().encode('Some data');
     writer.write(data).then(() => {
       console.log('Write successful');
     }); // 缺少 .catch 来处理错误
   });
   ```

   如果 `write()` 操作失败，上面的代码不会打印任何错误信息，可能会让开发者难以排查问题。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **用户在浏览器中访问一个网页：** 用户在地址栏输入网址或点击链接。
2. **网页 JavaScript 代码尝试建立 TCP 连接：** 网页的 JavaScript 代码使用 Direct Sockets API (例如 `navigator.directSockets.connect()`) 尝试连接到远程服务器。
3. **Blink 引擎处理连接请求：** Chromium Blink 引擎接收到 JavaScript 的连接请求，并创建相应的 C++ 对象来处理这个连接，其中可能包括创建 `TCPWritableStreamWrapper` 实例来管理写入流。
4. **JavaScript 发送数据：** 网页的 JavaScript 代码获取到连接的 `WritableStream` 对象，并调用 `writer.write(data)` 方法发送数据。
5. **`TCPWritableStreamWrapper` 处理写入请求：**  `writer.write()` 方法最终会调用到 `TCPWritableStreamWrapper` 的相关逻辑。
6. **数据通过 Mojo Data Pipe 发送：** `TCPWritableStreamWrapper` 将要写入的数据放入 Mojo data pipe 中，该 pipe 连接到浏览器的网络进程。
7. **网络进程发送数据：** 浏览器的网络进程负责实际的 TCP 数据包发送。

**调试线索：**

如果在调试一个涉及到 TCP Direct Sockets 的问题，可以关注以下几点：

* **JavaScript 代码中的错误处理：** 检查 `connect()` 和 `writer.write()` 返回的 Promise 是否有 `.catch()` 处理，以及错误信息是否足够详细。
* **Blink 内部日志：**  Chromium 提供了大量的内部日志，可以查看与 Direct Sockets 相关的日志信息，例如连接状态、数据传输情况、错误信息等。
* **网络抓包：** 使用 Wireshark 等工具抓取网络包，查看实际发送的 TCP 数据包内容和交互过程，确认数据是否按预期发送。
* **断点调试 Blink 源代码：**  如果问题涉及到 Blink 引擎内部，可以在 `TCPWritableStreamWrapper` 的相关方法中设置断点，例如 `Write()` 方法，逐步跟踪代码执行流程，查看数据是如何被处理和发送的，以及是否有错误发生。
* **检查 Mojo 通信：** 如果怀疑是 Mojo data pipe 的问题，可以查看与该 pipe 相关的状态和消息。

总之，`tcp_writable_stream_wrapper_unittest.cc` 文件通过一系列单元测试，确保了 `TCPWritableStreamWrapper` 类的各项功能正常运行，为 Chromium 中 Direct Sockets 功能的稳定性和可靠性提供了保障。理解这个文件的内容有助于理解 Blink 引擎中 TCP 可写流的实现细节，以及 JavaScript 如何通过 Web Streams API 与底层的网络通信机制进行交互。

### 提示词
```
这是目录为blink/renderer/modules/direct_sockets/tcp_writable_stream_wrapper_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/direct_sockets/tcp_writable_stream_wrapper.h"

#include "base/containers/span.h"
#include "base/functional/callback_helpers.h"
#include "base/ranges/algorithm.h"
#include "base/test/mock_callback.h"
#include "net/base/net_errors.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_writer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/modules/direct_sockets/stream_wrapper.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

namespace {

using ::testing::ElementsAre;
using ::testing::StrictMock;

// The purpose of this class is to ensure that the data pipe is reset before the
// V8TestingScope is destroyed, so that the TCPWritableStreamWrapper object
// doesn't try to create a DOMException after the ScriptState has gone away.
class StreamCreator : public GarbageCollected<StreamCreator> {
 public:
  StreamCreator() = default;
  ~StreamCreator() = default;

  // The default value of |capacity| means some sensible value selected by mojo.
  TCPWritableStreamWrapper* Create(const V8TestingScope& scope,
                                   uint32_t capacity = 1) {
    MojoCreateDataPipeOptions options;
    options.struct_size = sizeof(MojoCreateDataPipeOptions);
    options.flags = MOJO_CREATE_DATA_PIPE_FLAG_NONE;
    options.element_num_bytes = 1;
    options.capacity_num_bytes = capacity;

    mojo::ScopedDataPipeProducerHandle data_pipe_producer;
    MojoResult result =
        mojo::CreateDataPipe(&options, data_pipe_producer, data_pipe_consumer_);
    if (result != MOJO_RESULT_OK) {
      ADD_FAILURE() << "CreateDataPipe() returned " << result;
    }

    auto* script_state = scope.GetScriptState();
    stream_wrapper_ = MakeGarbageCollected<TCPWritableStreamWrapper>(
        script_state, base::DoNothing(), std::move(data_pipe_producer));
    return stream_wrapper_.Get();
  }

  void ResetPipe() { data_pipe_consumer_.reset(); }

  // Reads everything from |data_pipe_consumer_| and returns it in a vector.
  Vector<uint8_t> ReadAllPendingData() {
    Vector<uint8_t> data;
    base::span<const uint8_t> buffer;
    MojoResult result = data_pipe_consumer_->BeginReadData(
        MOJO_BEGIN_READ_DATA_FLAG_NONE, buffer);

    switch (result) {
      case MOJO_RESULT_OK:
        break;

      case MOJO_RESULT_SHOULD_WAIT:  // No more data yet.
        return data;

      default:
        ADD_FAILURE() << "BeginReadData() failed: " << result;
        return data;
    }

    data.AppendRange(buffer.begin(), buffer.end());
    data_pipe_consumer_->EndReadData(buffer.size());
    return data;
  }

  void Close(bool error) {}

  void Trace(Visitor* visitor) const { visitor->Trace(stream_wrapper_); }

 private:
  mojo::ScopedDataPipeConsumerHandle data_pipe_consumer_;
  Member<TCPWritableStreamWrapper> stream_wrapper_;
};

class ScopedStreamCreator {
 public:
  explicit ScopedStreamCreator(StreamCreator* stream_creator)
      : stream_creator_(stream_creator) {}

  ~ScopedStreamCreator() { stream_creator_->ResetPipe(); }

  StreamCreator* operator->() const { return stream_creator_; }

 private:
  Persistent<StreamCreator> stream_creator_;
};

TEST(TCPWritableStreamWrapperTest, Create) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedStreamCreator stream_creator(MakeGarbageCollected<StreamCreator>());
  auto* tcp_writable_stream_wrapper = stream_creator->Create(scope);
  EXPECT_TRUE(tcp_writable_stream_wrapper->Writable());
}

TEST(TCPWritableStreamWrapperTest, WriteArrayBuffer) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedStreamCreator stream_creator(MakeGarbageCollected<StreamCreator>());
  auto* tcp_writable_stream_wrapper = stream_creator->Create(scope);

  auto* script_state = scope.GetScriptState();
  auto* writer = tcp_writable_stream_wrapper->Writable()->getWriter(
      script_state, ASSERT_NO_EXCEPTION);
  auto* chunk = DOMArrayBuffer::Create(base::byte_span_from_cstring("A"));
  auto result =
      writer->write(script_state, ScriptValue::From(script_state, chunk),
                    ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, result);
  tester.WaitUntilSettled();
  ASSERT_TRUE(tester.IsFulfilled());
  EXPECT_THAT(stream_creator->ReadAllPendingData(), ElementsAre('A'));
}

TEST(TCPWritableStreamWrapperTest, WriteArrayBufferView) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedStreamCreator stream_creator(MakeGarbageCollected<StreamCreator>());
  auto* tcp_writable_stream_wrapper = stream_creator->Create(scope);

  auto* script_state = scope.GetScriptState();
  auto* writer = tcp_writable_stream_wrapper->Writable()->getWriter(
      script_state, ASSERT_NO_EXCEPTION);
  auto* buffer = DOMArrayBuffer::Create(base::byte_span_from_cstring("*B"));
  // Create a view into the buffer with offset 1, ie. "B".
  auto* chunk = DOMUint8Array::Create(buffer, 1, 1);
  auto result =
      writer->write(script_state, ScriptValue::From(script_state, chunk),
                    ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, result);
  tester.WaitUntilSettled();
  ASSERT_TRUE(tester.IsFulfilled());
  EXPECT_THAT(stream_creator->ReadAllPendingData(), ElementsAre('B'));
}

bool IsAllNulls(base::span<const uint8_t> data) {
  return base::ranges::all_of(data, [](uint8_t c) { return !c; });
}

TEST(TCPWritableStreamWrapperTest, AsyncWrite) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedStreamCreator stream_creator(MakeGarbageCollected<StreamCreator>());
  // Set a large pipe capacity, so any platform-specific excess is dwarfed in
  // size.
  constexpr uint32_t kPipeCapacity = 512u * 1024u;
  auto* tcp_writable_stream_wrapper =
      stream_creator->Create(scope, kPipeCapacity);

  auto* script_state = scope.GetScriptState();
  auto* writer = tcp_writable_stream_wrapper->Writable()->getWriter(
      script_state, ASSERT_NO_EXCEPTION);

  // Write a chunk that definitely will not fit in the pipe.
  const size_t kChunkSize = kPipeCapacity * 3;
  auto* chunk = DOMArrayBuffer::Create(kChunkSize, 1);
  auto result =
      writer->write(script_state, ScriptValue::From(script_state, chunk),
                    ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, result);

  // Let the first pipe write complete.
  test::RunPendingTasks();

  // Let microtasks run just in case write() returns prematurely.
  scope.PerformMicrotaskCheckpoint();
  ASSERT_FALSE(tester.IsFulfilled());

  // Read the first part of the data.
  auto data1 = stream_creator->ReadAllPendingData();
  EXPECT_LT(data1.size(), kChunkSize);

  // Verify the data wasn't corrupted.
  EXPECT_TRUE(IsAllNulls(data1));

  // Allow the asynchronous pipe write to happen.
  test::RunPendingTasks();

  // Read the second part of the data.
  auto data2 = stream_creator->ReadAllPendingData();
  EXPECT_TRUE(IsAllNulls(data2));

  test::RunPendingTasks();

  // Read the final part of the data.
  auto data3 = stream_creator->ReadAllPendingData();
  EXPECT_TRUE(IsAllNulls(data3));
  EXPECT_EQ(data1.size() + data2.size() + data3.size(), kChunkSize);

  // Now the write() should settle.
  tester.WaitUntilSettled();
  ASSERT_TRUE(tester.IsFulfilled());

  // Nothing should be left to read.
  EXPECT_THAT(stream_creator->ReadAllPendingData(), ElementsAre());
}

// Writing immediately followed by closing should not lose data.
TEST(TCPWritableStreamWrapperTest, WriteThenClose) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedStreamCreator stream_creator(MakeGarbageCollected<StreamCreator>());
  auto* tcp_writable_stream_wrapper = stream_creator->Create(scope);

  auto* script_state = scope.GetScriptState();
  auto* writer = tcp_writable_stream_wrapper->Writable()->getWriter(
      script_state, ASSERT_NO_EXCEPTION);
  auto* chunk = DOMArrayBuffer::Create(base::byte_span_from_cstring("D"));
  auto write_promise =
      writer->write(script_state, ScriptValue::From(script_state, chunk),
                    ASSERT_NO_EXCEPTION);

  auto close_promise = writer->close(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester write_tester(script_state, write_promise);
  ScriptPromiseTester close_tester(script_state, close_promise);

  // Make sure that write() and close() both run before the event loop is
  // serviced.
  scope.PerformMicrotaskCheckpoint();

  write_tester.WaitUntilSettled();
  ASSERT_TRUE(write_tester.IsFulfilled());
  close_tester.WaitUntilSettled();
  ASSERT_TRUE(close_tester.IsFulfilled());

  EXPECT_THAT(stream_creator->ReadAllPendingData(), ElementsAre('D'));
}

TEST(TCPWritableStreamWrapperTest, DISABLED_TriggerHasAborted) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedStreamCreator stream_creator(MakeGarbageCollected<StreamCreator>());
  auto* tcp_writable_stream_wrapper = stream_creator->Create(scope);

  auto* script_state = scope.GetScriptState();
  auto* writer = tcp_writable_stream_wrapper->Writable()->getWriter(
      script_state, ASSERT_NO_EXCEPTION);
  auto* chunk = DOMArrayBuffer::Create(base::byte_span_from_cstring("D"));
  auto write_promise =
      writer->write(script_state, ScriptValue::From(script_state, chunk),
                    ASSERT_NO_EXCEPTION);
  ScriptPromiseTester write_tester(script_state, write_promise);

  tcp_writable_stream_wrapper->ErrorStream(net::ERR_UNEXPECTED);
  write_tester.WaitUntilSettled();

  ASSERT_FALSE(write_tester.IsFulfilled());

  EXPECT_EQ(tcp_writable_stream_wrapper->GetState(),
            StreamWrapper::State::kAborted);
}

class TCPWritableStreamWrapperCloseTestWithMaybePendingWrite
    : public testing::TestWithParam<bool> {};

INSTANTIATE_TEST_SUITE_P(/**/,
                         TCPWritableStreamWrapperCloseTestWithMaybePendingWrite,
                         testing::Bool());

TEST_P(TCPWritableStreamWrapperCloseTestWithMaybePendingWrite, TriggerClose) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedStreamCreator stream_creator(MakeGarbageCollected<StreamCreator>());
  auto* tcp_writable_stream_wrapper = stream_creator->Create(scope);

  bool pending_write = GetParam();
  std::optional<ScriptPromiseTester> tester;
  if (pending_write) {
    auto* script_state = scope.GetScriptState();
    auto* chunk =
        DOMArrayBuffer::Create(base::byte_span_with_nul_from_cstring("D"));
    auto write_promise =
        tcp_writable_stream_wrapper->Writable()
            ->getWriter(script_state, ASSERT_NO_EXCEPTION)
            ->write(script_state, ScriptValue::From(script_state, chunk),
                    ASSERT_NO_EXCEPTION);
    tester.emplace(script_state, write_promise);
    test::RunPendingTasks();
  }

  // 1. OnWriteError(...) is called.
  tcp_writable_stream_wrapper->ErrorStream(net::ERR_UNEXPECTED);

  // 2. pipe reset event arrives.
  stream_creator->ResetPipe();
  test::RunPendingTasks();

  if (pending_write) {
    tester->WaitUntilSettled();
    ASSERT_TRUE(tester->IsRejected());
  }

  ASSERT_EQ(tcp_writable_stream_wrapper->GetState(),
            StreamWrapper::State::kAborted);
}

TEST_P(TCPWritableStreamWrapperCloseTestWithMaybePendingWrite,
       TriggerCloseInReverseOrder) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedStreamCreator stream_creator(MakeGarbageCollected<StreamCreator>());
  auto* tcp_writable_stream_wrapper = stream_creator->Create(scope);

  bool pending_write = GetParam();
  std::optional<ScriptPromiseTester> tester;
  if (pending_write) {
    auto* script_state = scope.GetScriptState();
    auto* chunk =
        DOMArrayBuffer::Create(base::byte_span_with_nul_from_cstring("D"));
    auto write_promise =
        tcp_writable_stream_wrapper->Writable()
            ->getWriter(script_state, ASSERT_NO_EXCEPTION)
            ->write(script_state, ScriptValue::From(script_state, chunk),
                    ASSERT_NO_EXCEPTION);
    tester.emplace(script_state, write_promise);
    test::RunPendingTasks();
  }

  // 1. pipe reset event arrives.
  stream_creator->ResetPipe();
  test::RunPendingTasks();

  // 2. OnWriteError(...) is called.
  tcp_writable_stream_wrapper->ErrorStream(net::ERR_UNEXPECTED);

  if (pending_write) {
    tester->WaitUntilSettled();
    ASSERT_TRUE(tester->IsRejected());
  }

  ASSERT_EQ(tcp_writable_stream_wrapper->GetState(),
            StreamWrapper::State::kAborted);
}

}  // namespace

}  // namespace blink
```