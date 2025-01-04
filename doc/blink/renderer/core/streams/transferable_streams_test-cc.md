Response:
Let's break down the thought process for analyzing this C++ test file for Blink's `transferable_streams`.

1. **Identify the Core Purpose:** The filename `transferable_streams_test.cc` immediately signals that this file contains tests related to the `transferable_streams` feature in Blink. The `#include "third_party/blink/renderer/core/streams/transferable_streams.h"` confirms this.

2. **Scan for Key Concepts and Classes:**  Quickly read through the `#include` directives and the code itself to identify the main classes and concepts being tested. Keywords like `ReadableStream`, `WritableStream`, `MessageChannel`, `Promise`, `reader`, `writer`, `ConcatenatedReadableStream`, and `UnderlyingSource` jump out. The `TEST` macros indicate the presence of unit tests.

3. **Understand the Testing Framework:** The inclusion of `testing/gtest/include/gtest/gtest.h` reveals that Google Test is used for the unit testing. This means we should expect `TEST` macros defining individual test cases.

4. **Analyze Individual Test Cases:** Go through each `TEST` function and understand what it's verifying:
    * **`SmokeTest`:** This name suggests a basic functionality test, likely checking if the core mechanism of transferring streams between contexts (using `MessageChannel`) works without crashing. The creation of `CrossRealmTransformWritable` and `CrossRealmTransformReadable` is a key indicator of inter-context communication.
    * **`ConcatenatedReadableStreamTest` (and its variations):** These tests are clearly focused on the `CreateConcatenatedReadableStream` function. The different variations (`Empty`, `SuccessfulRead`, `ErrorInSource1`, `Cancel1`, `PendingStart1`, etc.) indicate testing various scenarios of combining multiple readable streams. The `TestUnderlyingSource` class is specifically designed for these tests.

5. **Deconstruct `TestUnderlyingSource`:** This custom class is crucial for the `ConcatenatedReadableStreamTest` suite. Notice its members: `SourceType` (push/pull), `sequence_` (data to emit), `start_promise_`, `started_`, `cancelled_`, `cancel_reason_`. This reveals that the tests are simulating different types of stream sources (push vs. pull) with predefined data and the ability to control start and cancellation.

6. **Relate to Web Standards:**  The names `ReadableStream` and `WritableStream` are strong indicators of the [Streams API](https://developer.mozilla.org/en-US/docs/Web/API/Streams_API) in JavaScript. The concept of "transferable" suggests the ability to send these streams between different execution contexts (like iframes or web workers).

7. **Identify JavaScript/HTML/CSS Connections:** Based on the knowledge of the Streams API, recognize its direct connection to JavaScript. Although CSS isn't directly involved with stream manipulation, the underlying data being streamed *could* be related to rendering (e.g., image data, video chunks). HTML is relevant because these streams are often created and manipulated within the context of a web page.

8. **Infer User Actions and Debugging:** Think about how a user might trigger the execution paths tested in this file. Actions like:
    * Fetching data using `fetch()` and accessing the `body` as a readable stream.
    * Creating a `TransformStream` or `ReadableStream` in JavaScript and sending it to a web worker using `postMessage()`.
    * Concatenating multiple `ReadableStream` instances using a custom JavaScript implementation (though this test file verifies the Blink implementation).
    For debugging, the test names themselves offer clues about specific failure scenarios (e.g., "ErrorInSource1").

9. **Construct Examples:**  Based on the understanding of the code and related web technologies, create concrete examples of JavaScript code that would use the Streams API and potentially involve transferable streams.

10. **Address Potential Errors:** Think about common mistakes developers might make when working with the Streams API, such as:
    * Not handling errors properly.
    * Trying to read from a closed or errored stream.
    * Issues with transferring streams between contexts (e.g., incorrect usage of `postMessage`).

11. **Refine and Structure the Answer:**  Organize the findings into logical sections (Functionality, JavaScript/HTML/CSS Relation, Logical Reasoning, User Errors, Debugging). Use clear and concise language, providing code snippets where appropriate. Ensure that the explanations are accessible to someone with a general understanding of web development concepts.

**(Self-Correction during the process):**  Initially, I might focus too much on the C++ details. I need to constantly remind myself to connect it back to the user-facing aspects (JavaScript, HTML) and the purpose of the feature. Also, while `MessageChannel` is used for testing, the actual transfer mechanism in a browser might involve different internal mechanisms, so it's important not to overstate the direct connection in all scenarios. Finally, remember that this is a *test* file, so its primary goal is to verify the correctness of the `transferable_streams` implementation, not to be a comprehensive demonstration of all its uses.
This C++ source code file, `transferable_streams_test.cc`, is a **unit test file** within the Chromium Blink rendering engine. Its primary function is to **test the functionality of transferable streams**.

Let's break down the different aspects of its functionality and its relationship to web technologies:

**1. Functionality of `transferable_streams_test.cc`:**

* **Testing Core Stream Transfer Mechanisms:** The file tests the ability to transfer `ReadableStream` and `WritableStream` objects between different execution contexts within the browser. This likely involves scenarios where streams are sent between a main document and an iframe or a web worker.
* **Testing `CreateCrossRealmTransformWritable` and `CreateCrossRealmTransformReadable`:**  These functions, mentioned in the `SmokeTest`, are key to creating streams that can be transferred across realms (different JavaScript execution environments).
* **Testing `CreateConcatenatedReadableStream`:**  A significant portion of the file is dedicated to testing the functionality of concatenating multiple `ReadableStream` instances into a single stream. This involves testing various scenarios like successful reads, errors in individual streams, and cancellation.
* **Verifying Stream States and Behavior:** The tests check the state of the streams (e.g., whether they are started, cancelled, closed), the values read from the streams, and how errors are propagated.
* **Using Mock Underlying Sources:** The `TestUnderlyingSource` class is a custom implementation of `UnderlyingSourceBase`. It's used to simulate different types of readable stream sources (push and pull) with predefined data sequences and the ability to inject errors or delays.
* **Asynchronous Testing with Promises:** The tests heavily rely on JavaScript Promises to handle asynchronous operations involved in stream reading and writing. They check the resolution and rejection of these promises.
* **Utilizing `MessageChannel` for Inter-Context Communication:** The `SmokeTest` uses `MessageChannel` to simulate the transfer of streams between different JavaScript realms.

**2. Relationship to JavaScript, HTML, and CSS:**

* **JavaScript:**  Transferable streams are a feature exposed to JavaScript through the Streams API. This test file directly validates the underlying C++ implementation that makes the JavaScript Streams API work for transferring streams.
    * **Example:** In JavaScript, you can create a transferable stream using `pipeThrough()` on a `ReadableStream` and then send the resulting streams to a web worker using `postMessage()`. The C++ code in this test file verifies the correct handling of these transferred streams.

    ```javascript
    // In the main thread:
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue("hello");
        controller.close();
      }
    });

    const { readable, writable } = stream.pipeThrough(new TransformStream());

    const worker = new Worker('worker.js');
    worker.postMessage({ readable, writable }, [readable, writable]); // Transferring the streams

    // In worker.js:
    onmessage = async (event) => {
      const readableStream = event.data.readable;
      const reader = readableStream.getReader();
      const { value, done } = await reader.read();
      console.log("Received:", value); // Expected output: "hello"
    };
    ```
* **HTML:**  Transferable streams can be relevant in scenarios involving HTML elements that deal with streams, such as:
    * **`<video>` and `<audio>` elements:**  While not directly creating transferable streams, these elements consume media streams, and the underlying mechanisms might involve similar concepts.
    * **`<iframe>`:** Transferable streams are crucial for communication and data sharing between the main document and iframes, allowing for more efficient transfer of streaming data.
* **CSS:**  CSS has no direct relationship with the core functionality of transferable streams. However, the *data* being transferred through these streams could potentially be related to visual elements controlled by CSS (e.g., image data).

**3. Logical Reasoning and Assumptions:**

The tests make several assumptions and follow a logical flow:

* **Assumption:** The underlying message passing mechanism (`MessageChannel`) works correctly.
* **Assumption:** The V8 JavaScript engine and its binding layer are functioning as expected.
* **Logical Flow (for `ConcatenatedReadableStreamTest`):**
    * **Input:** Two `ReadableStream` objects (potentially with different underlying sources and data).
    * **Process:** Create a concatenated stream from the two input streams.
    * **Action:** Read data from the concatenated stream.
    * **Expected Output:** The data should be read sequentially from the first stream and then the second stream. Errors in either source stream should be correctly propagated. Cancellation of the concatenated stream should cancel both underlying streams.

**Example Input and Output (for `ConcatenatedReadableStreamTest.SuccessfulRead`):**

* **Input:**
    * `source1`: A `TestUnderlyingSource` (pull-based) with data `[1]`.
    * `source2`: A `TestUnderlyingSource` (pull-based) with data `[5, 6]`.
* **Action:** Create a concatenated stream and read from it.
* **Output:**
    * First `read()`: Resolves with `{ value: 1, done: false }`.
    * Second `read()`: Resolves with `{ value: 5, done: false }`.
    * Third `read()`: Resolves with `{ value: 6, done: false }`.
    * Fourth `read()`: Resolves with `{ value: undefined, done: true }`.

**4. Common User or Programming Errors:**

This test file helps to prevent common errors developers might encounter when working with transferable streams:

* **Attempting to use a transferred stream in the original context after it's been transferred:** Transferable streams can only exist in one JavaScript realm at a time. Trying to operate on a stream after it has been transferred will lead to errors.
* **Incorrectly handling errors during stream transfer or processing:**  The tests with `ErrorInSource1` and `ErrorInSource2` ensure that errors in the underlying streams are correctly propagated to the consumer of the concatenated stream. If these errors are not handled in JavaScript, it can lead to unexpected behavior or crashes.
* **Not understanding the asynchronous nature of streams:**  Operations on streams are asynchronous, and developers need to use Promises or async/await to handle the results correctly. Failing to do so can lead to race conditions or incorrect data processing.
* **Trying to read from or write to a closed or errored stream:**  The tests implicitly verify that operations on closed or errored streams behave as expected (e.g., `read()` returning a done result or a rejected promise).
* **Forgetting to transfer the stream objects correctly in `postMessage`:** When using `postMessage`, the stream objects themselves need to be included in the transfer list (the second argument to `postMessage`). Failing to do so will result in the receiving context not having access to the actual stream.

**5. User Operations Leading to This Code (Debugging Clues):**

As a debugger, reaching this C++ code often means tracing the execution flow triggered by JavaScript code interacting with the Streams API:

1. **User Action in JavaScript:** A user action in a web page (e.g., clicking a button, receiving data from a network request) triggers JavaScript code.
2. **JavaScript Stream Operations:** This JavaScript code might involve:
    * Creating a `ReadableStream` or `WritableStream`.
    * Using `pipeThrough()` or `tee()` to create new streams.
    * Transferring streams to a web worker or iframe using `postMessage()`.
    * Reading data from a `ReadableStream` using a `reader`.
    * Writing data to a `WritableStream` using a `writer`.
    * Concatenating multiple `ReadableStream` instances (if a custom JavaScript implementation or a future browser feature is used).
3. **Blink Engine Interaction:** When these JavaScript stream operations are performed, the V8 JavaScript engine calls into the corresponding C++ code within the Blink rendering engine (specifically in the `blink::core::streams` namespace).
4. **`transferable_streams.h` and Related Files:** The C++ code in `transferable_streams.h` and related files like `readable_stream.h`, `writable_stream.h`, and `transferable_streams_test.cc` is executed to handle these operations.
5. **Debugging Entry Point:** If you're debugging a problem related to transferring streams or concatenating readable streams, you might set breakpoints in functions like `CreateCrossRealmTransformWritable`, `CreateCrossRealmTransformReadable`, `CreateConcatenatedReadableStream`, or within the `ReadableStream` and `WritableStream` C++ classes.

**Example Debugging Scenario:**

Imagine a user reports that a web worker is not receiving data correctly after a `ReadableStream` is transferred to it. As a debugger, you might:

1. **Start in the JavaScript code:** Examine the `postMessage()` call where the stream is transferred.
2. **Trace into Blink:** If the transfer seems to be the issue, you might step into the C++ code responsible for handling `postMessage` with transferable objects.
3. **Reach `transferable_streams_test.cc` (Indirectly):** While you wouldn't directly step into the *test* file during debugging a live application, understanding the tests helps you know which C++ code is responsible for the functionality being tested. For instance, the `SmokeTest` in this file validates the basic transfer mechanism using `MessageChannel`, so you might investigate the C++ implementation related to message channel handling of transferable streams.
4. **Investigate `CreateCrossRealm...` functions:** If the issue is specifically with transferring streams across realms, you might focus on the implementation of `CreateCrossRealmTransformWritable` and `CreateCrossRealmTransformReadable`.

In summary, `transferable_streams_test.cc` is a crucial part of ensuring the correctness and reliability of the transferable streams feature in Blink, which directly impacts the functionality of the JavaScript Streams API and its ability to efficiently handle streaming data across different contexts in web applications.

Prompt: 
```
这是目录为blink/renderer/core/streams/transferable_streams_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/streams/transferable_streams.h"

#include "base/types/strong_alias.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/iterable.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream_default_reader.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream_read_result.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_writable_stream_default_writer.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/messaging/message_channel.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_controller_with_script_scope.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_reader.h"
#include "third_party/blink/renderer/core/streams/readable_stream_transferring_optimizer.h"
#include "third_party/blink/renderer/core/streams/underlying_source_base.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_writer.h"
#include "third_party/blink/renderer/core/streams/writable_stream_transferring_optimizer.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

enum class SourceType { kPush, kPull };

class TestUnderlyingSource final : public UnderlyingSourceBase {
 public:
  TestUnderlyingSource(SourceType source_type,
                       ScriptState* script_state,
                       Vector<int> sequence,
                       ScriptPromise<IDLUndefined> start_promise)
      : UnderlyingSourceBase(script_state),
        type_(source_type),
        sequence_(std::move(sequence)),
        start_promise_(start_promise) {}
  TestUnderlyingSource(SourceType source_type,
                       ScriptState* script_state,
                       Vector<int> sequence)
      : TestUnderlyingSource(source_type,
                             script_state,
                             std::move(sequence),
                             ToResolvedUndefinedPromise(script_state)) {}
  ~TestUnderlyingSource() override = default;

  ScriptPromise<IDLUndefined> Start(ScriptState* script_state) override {
    started_ = true;
    if (type_ == SourceType::kPush) {
      for (int element : sequence_) {
        EnqueueOrError(script_state, element);
      }
      index_ = sequence_.size();
      Controller()->Close();
    }
    return start_promise_;
  }
  ScriptPromise<IDLUndefined> Pull(ScriptState* script_state,
                                   ExceptionState&) override {
    if (type_ == SourceType::kPush) {
      return ToResolvedUndefinedPromise(script_state);
    }
    if (index_ == sequence_.size()) {
      Controller()->Close();
      return ToResolvedUndefinedPromise(script_state);
    }
    EnqueueOrError(script_state, sequence_[index_]);
    ++index_;
    return ToResolvedUndefinedPromise(script_state);
  }
  ScriptPromise<IDLUndefined> Cancel(ScriptState* script_state,
                                     ScriptValue reason,
                                     ExceptionState&) override {
    cancelled_ = true;
    cancel_reason_ = reason;
    return ToResolvedUndefinedPromise(script_state);
  }

  bool IsStarted() const { return started_; }
  bool IsCancelled() const { return cancelled_; }
  ScriptValue CancelReason() const { return cancel_reason_; }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(start_promise_);
    visitor->Trace(cancel_reason_);
    UnderlyingSourceBase::Trace(visitor);
  }

 private:
  void EnqueueOrError(ScriptState* script_state, int num) {
    if (num < 0) {
      Controller()->Error(V8ThrowException::CreateRangeError(
          script_state->GetIsolate(), "foo"));
      return;
    }
    Controller()->Enqueue(v8::Integer::New(script_state->GetIsolate(), num));
  }

  const SourceType type_;
  const Vector<int> sequence_;
  wtf_size_t index_ = 0;

  const MemberScriptPromise<IDLUndefined> start_promise_;
  bool started_ = false;
  bool cancelled_ = false;
  ScriptValue cancel_reason_;
};

void ExpectValue(int line,
                 ScriptState* script_state,
                 v8::Local<v8::Value> result,
                 int32_t expectation) {
  SCOPED_TRACE(testing::Message() << "__LINE__ = " << line);
  if (!result->IsObject()) {
    ADD_FAILURE() << "The result is not an Object.";
    return;
  }
  v8::Local<v8::Value> value;
  bool done = false;
  if (!V8UnpackIterationResult(script_state, result.As<v8::Object>(), &value,
                               &done)) {
    ADD_FAILURE() << "Failed to unpack the iterator result.";
    return;
  }
  EXPECT_FALSE(done);
  if (!value->IsInt32()) {
    ADD_FAILURE() << "The value is not an int32.";
    return;
  }
  EXPECT_EQ(value.As<v8::Number>()->Value(), expectation);
}

void ExpectDone(int line,
                ScriptState* script_state,
                v8::Local<v8::Value> result) {
  SCOPED_TRACE(testing::Message() << "__LINE__ = " << line);
  v8::Local<v8::Value> value;
  bool done = false;
  if (!V8UnpackIterationResult(script_state, result.As<v8::Object>(), &value,
                               &done)) {
    ADD_FAILURE() << "Failed to unpack the iterator result.";
    return;
  }
  EXPECT_TRUE(done);
}

// We only do minimal testing here. The functionality of transferable streams is
// tested in the layout tests.
TEST(TransferableStreamsTest, SmokeTest) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  auto* channel =
      MakeGarbageCollected<MessageChannel>(scope.GetExecutionContext());
  auto* script_state = scope.GetScriptState();
  auto* writable = CreateCrossRealmTransformWritable(
      script_state, channel->port1(), AllowPerChunkTransferring(false),
      /*optimizer=*/nullptr, ASSERT_NO_EXCEPTION);
  ASSERT_TRUE(writable);
  auto* readable = CreateCrossRealmTransformReadable(
      script_state, channel->port2(), /*optimizer=*/nullptr,
      ASSERT_NO_EXCEPTION);
  ASSERT_TRUE(readable);

  auto* writer = writable->getWriter(script_state, ASSERT_NO_EXCEPTION);
  auto* reader =
      readable->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);

  writer->write(script_state, ScriptValue::CreateNull(scope.GetIsolate()),
                ASSERT_NO_EXCEPTION);

  class ExpectNullResponse
      : public ThenCallable<ReadableStreamReadResult, ExpectNullResponse> {
   public:
    explicit ExpectNullResponse(bool* got_response)
        : got_response_(got_response) {}

    void React(ScriptState* script_state, ReadableStreamReadResult* result) {
      *got_response_ = true;
      EXPECT_FALSE(result->done());
      EXPECT_TRUE(result->value().IsNull());
    }

    bool* got_response_;
  };

  // TODO(ricea): This is copy-and-pasted from transform_stream_test.cc. Put it
  // in a shared location.
  class ExpectNotReached : public ThenCallable<IDLAny, ExpectNotReached> {
   public:
    ExpectNotReached() = default;

    void React(ScriptState*, ScriptValue) {
      ADD_FAILURE() << "ExpectNotReached was reached";
    }
  };

  bool got_response = false;
  reader->read(script_state, ASSERT_NO_EXCEPTION)
      .Then(script_state,
            MakeGarbageCollected<ExpectNullResponse>(&got_response),
            MakeGarbageCollected<ExpectNotReached>());

  // Need to run the event loop to pass messages through the MessagePort.
  test::RunPendingTasks();

  // Resolve promises.
  scope.PerformMicrotaskCheckpoint();

  EXPECT_TRUE(got_response);
}

TEST(ConcatenatedReadableStreamTest, Empty) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* script_state = scope.GetScriptState();

  TestUnderlyingSource* source1 = MakeGarbageCollected<TestUnderlyingSource>(
      SourceType::kPull, script_state, Vector<int>({}));
  TestUnderlyingSource* source2 = MakeGarbageCollected<TestUnderlyingSource>(
      SourceType::kPull, script_state, Vector<int>({}));

  ReadableStream* stream =
      CreateConcatenatedReadableStream(script_state, source1, source2);
  ASSERT_TRUE(stream);

  auto* reader =
      stream->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  ASSERT_TRUE(reader);

  {
    v8::Local<v8::Promise> read_promise =
        reader->read(script_state, ASSERT_NO_EXCEPTION).V8Promise();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kFulfilled);
    ExpectDone(__LINE__, script_state, read_promise->Result());
  }
  EXPECT_TRUE(source1->IsStarted());
  EXPECT_TRUE(source2->IsStarted());
  EXPECT_FALSE(source1->IsCancelled());
  EXPECT_FALSE(source2->IsCancelled());
}

TEST(ConcatenatedReadableStreamTest, SuccessfulRead) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* script_state = scope.GetScriptState();

  TestUnderlyingSource* source1 = MakeGarbageCollected<TestUnderlyingSource>(
      SourceType::kPull, script_state, Vector<int>({1}));
  TestUnderlyingSource* source2 = MakeGarbageCollected<TestUnderlyingSource>(
      SourceType::kPull, script_state, Vector<int>({5, 6}));

  ReadableStream* stream =
      CreateConcatenatedReadableStream(script_state, source1, source2);
  ASSERT_TRUE(stream);

  auto* reader =
      stream->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  ASSERT_TRUE(reader);

  {
    v8::Local<v8::Promise> read_promise =
        reader->read(script_state, ASSERT_NO_EXCEPTION).V8Promise();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kFulfilled);
    ExpectValue(__LINE__, script_state, read_promise->Result(), 1);
    EXPECT_TRUE(source1->IsStarted());
    EXPECT_FALSE(source2->IsStarted());
  }
  {
    v8::Local<v8::Promise> read_promise =
        reader->read(script_state, ASSERT_NO_EXCEPTION).V8Promise();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kFulfilled);
    ExpectValue(__LINE__, script_state, read_promise->Result(), 5);
    EXPECT_TRUE(source2->IsStarted());
  }
  {
    v8::Local<v8::Promise> read_promise =
        reader->read(script_state, ASSERT_NO_EXCEPTION).V8Promise();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kFulfilled);
    ExpectValue(__LINE__, script_state, read_promise->Result(), 6);
  }
  {
    v8::Local<v8::Promise> read_promise =
        reader->read(script_state, ASSERT_NO_EXCEPTION).V8Promise();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kFulfilled);
    ExpectDone(__LINE__, script_state, read_promise->Result());
  }
  EXPECT_FALSE(source1->IsCancelled());
  EXPECT_FALSE(source2->IsCancelled());
}

TEST(ConcatenatedReadableStreamTest, SuccessfulReadForPushSources) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* script_state = scope.GetScriptState();

  TestUnderlyingSource* source1 = MakeGarbageCollected<TestUnderlyingSource>(
      SourceType::kPush, script_state, Vector<int>({1}));
  TestUnderlyingSource* source2 = MakeGarbageCollected<TestUnderlyingSource>(
      SourceType::kPush, script_state, Vector<int>({5, 6}));

  ReadableStream* stream =
      CreateConcatenatedReadableStream(script_state, source1, source2);
  ASSERT_TRUE(stream);

  auto* reader =
      stream->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  ASSERT_TRUE(reader);

  {
    v8::Local<v8::Promise> read_promise =
        reader->read(script_state, ASSERT_NO_EXCEPTION).V8Promise();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kFulfilled);
    ExpectValue(__LINE__, script_state, read_promise->Result(), 1);
    EXPECT_TRUE(source1->IsStarted());
    EXPECT_FALSE(source2->IsStarted());
  }
  {
    v8::Local<v8::Promise> read_promise =
        reader->read(script_state, ASSERT_NO_EXCEPTION).V8Promise();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kFulfilled);
    ExpectValue(__LINE__, script_state, read_promise->Result(), 5);
    EXPECT_TRUE(source2->IsStarted());
  }
  {
    v8::Local<v8::Promise> read_promise =
        reader->read(script_state, ASSERT_NO_EXCEPTION).V8Promise();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kFulfilled);
    ExpectValue(__LINE__, script_state, read_promise->Result(), 6);
  }
  {
    v8::Local<v8::Promise> read_promise =
        reader->read(script_state, ASSERT_NO_EXCEPTION).V8Promise();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kFulfilled);
    ExpectDone(__LINE__, script_state, read_promise->Result());
  }
  EXPECT_FALSE(source1->IsCancelled());
  EXPECT_FALSE(source2->IsCancelled());
}

TEST(ConcatenatedReadableStreamTest, ErrorInSource1) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* script_state = scope.GetScriptState();

  TestUnderlyingSource* source1 = MakeGarbageCollected<TestUnderlyingSource>(
      SourceType::kPull, script_state, Vector<int>({1, -2}));
  TestUnderlyingSource* source2 = MakeGarbageCollected<TestUnderlyingSource>(
      SourceType::kPull, script_state, Vector<int>({5, 6}));

  ReadableStream* stream =
      CreateConcatenatedReadableStream(script_state, source1, source2);
  ASSERT_TRUE(stream);

  auto* reader =
      stream->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  ASSERT_TRUE(reader);

  {
    v8::Local<v8::Promise> read_promise =
        reader->read(script_state, ASSERT_NO_EXCEPTION).V8Promise();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kFulfilled);
    ExpectValue(__LINE__, script_state, read_promise->Result(), 1);
  }
  {
    v8::Local<v8::Promise> read_promise =
        reader->read(script_state, ASSERT_NO_EXCEPTION).V8Promise();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kRejected);
  }
  EXPECT_TRUE(source1->IsStarted());
  EXPECT_FALSE(source1->IsCancelled());
  EXPECT_TRUE(source2->IsStarted());
  EXPECT_TRUE(source2->IsCancelled());
}

TEST(ConcatenatedReadableStreamTest, ErrorInSource2) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* script_state = scope.GetScriptState();

  TestUnderlyingSource* source1 = MakeGarbageCollected<TestUnderlyingSource>(
      SourceType::kPull, script_state, Vector<int>({1}));
  TestUnderlyingSource* source2 = MakeGarbageCollected<TestUnderlyingSource>(
      SourceType::kPull, script_state, Vector<int>({-2}));

  ReadableStream* stream =
      CreateConcatenatedReadableStream(script_state, source1, source2);
  ASSERT_TRUE(stream);

  auto* reader =
      stream->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  ASSERT_TRUE(reader);

  {
    v8::Local<v8::Promise> read_promise =
        reader->read(script_state, ASSERT_NO_EXCEPTION).V8Promise();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kFulfilled);
    ExpectValue(__LINE__, script_state, read_promise->Result(), 1);
  }
  {
    v8::Local<v8::Promise> read_promise =
        reader->read(script_state, ASSERT_NO_EXCEPTION).V8Promise();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kRejected);
  }
  EXPECT_TRUE(source1->IsStarted());
  EXPECT_FALSE(source1->IsCancelled());
  EXPECT_TRUE(source2->IsStarted());
  EXPECT_FALSE(source2->IsCancelled());
}

TEST(ConcatenatedReadableStreamTest, Cancel1) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* script_state = scope.GetScriptState();

  TestUnderlyingSource* source1 = MakeGarbageCollected<TestUnderlyingSource>(
      SourceType::kPull, script_state, Vector<int>({1, 2}));
  TestUnderlyingSource* source2 = MakeGarbageCollected<TestUnderlyingSource>(
      SourceType::kPull, script_state, Vector<int>({5, 6}));

  ScriptValue reason(script_state->GetIsolate(),
                     V8String(script_state->GetIsolate(), "hello"));

  ReadableStream* stream =
      CreateConcatenatedReadableStream(script_state, source1, source2);
  ASSERT_TRUE(stream);

  auto* reader =
      stream->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  ASSERT_TRUE(reader);

  {
    v8::Local<v8::Promise> read_promise =
        reader->read(script_state, ASSERT_NO_EXCEPTION).V8Promise();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kFulfilled);
    ExpectValue(__LINE__, script_state, read_promise->Result(), 1);
  }
  EXPECT_TRUE(source1->IsStarted());
  EXPECT_FALSE(source1->IsCancelled());
  EXPECT_FALSE(source2->IsStarted());
  EXPECT_FALSE(source2->IsCancelled());
  {
    reader->cancel(script_state, reason, ASSERT_NO_EXCEPTION);
    scope.PerformMicrotaskCheckpoint();
  }
  EXPECT_TRUE(source1->IsStarted());
  EXPECT_TRUE(source1->IsCancelled());
  EXPECT_EQ(reason, source1->CancelReason());
  EXPECT_TRUE(source2->IsStarted());
  EXPECT_TRUE(source2->IsCancelled());
  EXPECT_EQ(reason, source2->CancelReason());
}

TEST(ConcatenatedReadableStreamTest, Cancel2) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* script_state = scope.GetScriptState();

  TestUnderlyingSource* source1 = MakeGarbageCollected<TestUnderlyingSource>(
      SourceType::kPull, script_state, Vector<int>({}));
  TestUnderlyingSource* source2 = MakeGarbageCollected<TestUnderlyingSource>(
      SourceType::kPull, script_state, Vector<int>({5}));

  ScriptValue reason(script_state->GetIsolate(),
                     V8String(script_state->GetIsolate(), "hello"));

  ReadableStream* stream =
      CreateConcatenatedReadableStream(script_state, source1, source2);
  ASSERT_TRUE(stream);

  auto* reader =
      stream->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  ASSERT_TRUE(reader);

  {
    v8::Local<v8::Promise> read_promise =
        reader->read(script_state, ASSERT_NO_EXCEPTION).V8Promise();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kFulfilled);
    ExpectValue(__LINE__, script_state, read_promise->Result(), 5);
  }
  {
    reader->cancel(script_state, reason, ASSERT_NO_EXCEPTION);
    scope.PerformMicrotaskCheckpoint();
  }
  EXPECT_TRUE(source1->IsStarted());
  EXPECT_FALSE(source1->IsCancelled());
  EXPECT_TRUE(source2->IsStarted());
  EXPECT_TRUE(source2->IsCancelled());
  EXPECT_EQ(reason, source2->CancelReason());
}

TEST(ConcatenatedReadableStreamTest, PendingStart1) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* script_state = scope.GetScriptState();

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  TestUnderlyingSource* source1 = MakeGarbageCollected<TestUnderlyingSource>(
      SourceType::kPull, script_state, Vector<int>({1, 2}),
      resolver->Promise());
  TestUnderlyingSource* source2 = MakeGarbageCollected<TestUnderlyingSource>(
      SourceType::kPull, script_state, Vector<int>({5, 6}));

  ReadableStream* stream =
      CreateConcatenatedReadableStream(script_state, source1, source2);
  ASSERT_TRUE(stream);

  auto* reader =
      stream->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  ASSERT_TRUE(reader);

  {
    v8::Local<v8::Promise> read_promise =
        reader->read(script_state, ASSERT_NO_EXCEPTION).V8Promise();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kPending);

    resolver->Resolve();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kFulfilled);
    ExpectValue(__LINE__, script_state, read_promise->Result(), 1);
  }
  EXPECT_TRUE(source1->IsStarted());
  EXPECT_FALSE(source2->IsStarted());
}

TEST(ConcatenatedReadableStreamTest, PendingStart2) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* script_state = scope.GetScriptState();

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  TestUnderlyingSource* source1 = MakeGarbageCollected<TestUnderlyingSource>(
      SourceType::kPull, script_state, Vector<int>({1}));
  TestUnderlyingSource* source2 = MakeGarbageCollected<TestUnderlyingSource>(
      SourceType::kPull, script_state, Vector<int>({5, 6}),
      resolver->Promise());

  ReadableStream* stream =
      CreateConcatenatedReadableStream(script_state, source1, source2);
  ASSERT_TRUE(stream);

  auto* reader =
      stream->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  ASSERT_TRUE(reader);

  {
    v8::Local<v8::Promise> read_promise =
        reader->read(script_state, ASSERT_NO_EXCEPTION).V8Promise();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kFulfilled);
    ExpectValue(__LINE__, script_state, read_promise->Result(), 1);
  }
  {
    v8::Local<v8::Promise> read_promise =
        reader->read(script_state, ASSERT_NO_EXCEPTION).V8Promise();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kPending);

    resolver->Resolve();
    scope.PerformMicrotaskCheckpoint();
    ASSERT_EQ(read_promise->State(), v8::Promise::kFulfilled);
    ExpectValue(__LINE__, script_state, read_promise->Result(), 5);
  }
  EXPECT_TRUE(source1->IsStarted());
  EXPECT_TRUE(source2->IsStarted());
}

}  // namespace

}  // namespace blink

"""

```