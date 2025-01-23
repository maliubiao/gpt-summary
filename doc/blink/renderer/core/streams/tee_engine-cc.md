Response:
Let's break down the thought process for analyzing the `tee_engine.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship with web technologies, logical inferences, potential user errors, and debugging information. The core task is to decipher the purpose of `TeeEngine`.

2. **Initial Scan and Keywords:**  Quickly read through the code, looking for significant keywords and class names. Words like `TeeEngine`, `ReadableStream`, `StructuredClone`, `PullAlgorithm`, `CancelAlgorithm`, `ChunkSteps`, `Enqueue`, `Error`, and mentions of `branch1`, `branch2` stand out. The presence of `// https://streams.spec.whatwg.org/` strongly suggests this relates to the Streams API.

3. **Identify Core Functionality (Mental Model):**  Based on the keywords, the name "tee," and the context of streams, the core function is likely to *split* a readable stream into two independent streams (branches). This is analogous to a "T" pipe.

4. **Examine Key Methods:**  Focus on the important methods:
    * **`StructuredClone`:** This immediately points to the ability to create independent copies of data chunks. The comment and the use of `SerializedScriptValue` are crucial for understanding *how* the cloning happens. This relates directly to JavaScript's ability to pass data between different contexts.
    * **`PullAlgorithm::Run`:** This seems to be the core logic for fetching data from the *source* stream. The `ReadableStreamDefaultReader::Read` call confirms this. The `reading_` and `read_again_` flags suggest handling asynchronous operations.
    * **`TeeReadRequest::ChunkSteps`:** This is where the actual splitting and processing of data chunks happens. The looping through `branch` (0 and 1), the conditional cloning, and the calls to `ReadableStreamDefaultControllerEnqueue` are key. This directly interacts with how data is pushed into the output streams.
    * **`TeeReadRequest::CloseSteps`:** This handles the closing of the output streams when the source stream closes. The `canceled_` flags are important for understanding conditional closing.
    * **`TeeReadRequest::ErrorSteps`:**  Handles error propagation.
    * **`CancelAlgorithm::Run`:** This manages the cancellation of either of the output streams and potentially the source stream. The logic for combining reasons and the call to `ReadableStream::Cancel` are significant.
    * **`TeeEngine::Start`:** This is the initialization method, setting up the readers, branches, and algorithms. The creation of the two `ReadableStream` instances (`branch_[0]` and `branch_[1]`) is essential. The `RejectFunction` for error handling on the source stream is also important.

5. **Connect to Web Technologies:**
    * **JavaScript:** The entire Streams API is a JavaScript feature. The `TeeEngine` is a behind-the-scenes implementation detail, but it directly enables the functionality exposed in JavaScript through methods like `pipeThrough` and the `tee()` method on `ReadableStream`.
    * **HTML:** While not directly manipulating HTML structure, the Streams API is frequently used with features like `<video>`, `<audio>`, `fetch`, and WebSockets, which *do* interact with HTML. The `tee()` operation can be used to process the same stream data in multiple ways for different parts of the HTML page.
    * **CSS:**  Less direct connection. Potentially, if stream data is used to dynamically generate or update CSS properties (though less common).

6. **Infer Logical Flows and Input/Output:** Consider the sequence of events:
    * A JavaScript program calls `stream.tee()`.
    * The `TeeEngine::Start` method is invoked.
    * When the original stream produces a chunk, `PullAlgorithm` triggers a read.
    * `TeeReadRequest::ChunkSteps` receives the chunk.
    * The chunk is potentially cloned and then enqueued into both output streams.
    * If one branch is canceled, `CancelAlgorithm` is triggered.
    * If the source stream errors, `ErrorSteps` is called.
    * If the source stream closes, `CloseSteps` is called.

7. **Identify Potential Errors:** Think about what could go wrong:
    * **Cloning Errors:**  The `StructuredClone` operation can fail if the data contains non-cloneable objects.
    * **Backpressure:** If the output streams are consumed at different rates, the source stream might experience backpressure. The code mentions `CanCloseOrEnqueue`, hinting at handling such scenarios.
    * **Cancellation Race Conditions:**  If both branches are canceled simultaneously or close to each other.
    * **Incorrect Usage in JavaScript:**  For example, trying to `tee()` a stream that's already locked.

8. **Debugging Information:** Think about how a developer would reach this code:
    * They would be working with the Streams API in JavaScript.
    * They might encounter unexpected behavior after using `tee()`.
    * They might be looking at Chromium's source code to understand the underlying implementation.
    * Breakpoints could be set in `TeeEngine::Start`, `PullAlgorithm::Run`, or `TeeReadRequest::ChunkSteps` to observe the flow of data.

9. **Structure the Answer:** Organize the information logically with clear headings: Functionality, Relationship with Web Technologies, Logical Inference, User Errors, and Debugging. Use examples to illustrate the concepts.

10. **Refine and Review:** Read through the answer, ensuring clarity, accuracy, and completeness. Double-check the code snippets and explanations. For instance, initially, I might have overlooked the `RejectFunction` in `TeeEngine::Start`, but a closer look reveals its importance for error propagation from the source stream. Ensure the language is accessible to someone with a general understanding of web development concepts.

This systematic approach helps to thoroughly analyze the code and extract the relevant information requested in the prompt. It involves understanding the code's purpose, its interactions with other parts of the system, and potential issues that might arise during its use.
好的，我们来分析一下 `blink/renderer/core/streams/tee_engine.cc` 这个文件。

**文件功能：**

`tee_engine.cc` 实现了 `TeeEngine` 类，这个类是 Chromium Blink 引擎中用于支持 `ReadableStream.tee()` 方法的核心逻辑。 `tee()` 方法允许将一个可读流（ReadableStream）拆分成两个独立的、相同的流分支。这意味着从原始流中读取的每个数据块都会被复制并推送到这两个分支流中。

具体来说，`TeeEngine` 的主要功能包括：

1. **创建和管理两个分支流：**  `TeeEngine` 负责创建两个新的 `ReadableStream` 对象，作为原始流的分支。
2. **读取原始流：** 它使用 `ReadableStreamDefaultReader` 从原始流中读取数据块。
3. **复制数据块：** 当从原始流读取到数据块时，`TeeEngine` 负责将数据块复制到两个分支流中。为了保证分支流的独立性，可以选择对数据块进行结构化克隆 (`StructuredClone`)。
4. **处理流的关闭和错误：**  当原始流关闭或发生错误时，`TeeEngine` 会将这些事件传递给两个分支流，确保它们也正确关闭或进入错误状态。
5. **处理分支流的取消：**  如果其中一个分支流被取消，`TeeEngine` 会记录这个状态，并可能取消原始流（如果两个分支都被取消）。
6. **同步读取操作：**  `TeeEngine` 内部使用状态变量 (`reading_`, `read_again_`) 来管理读取操作，避免并发问题。

**与 JavaScript, HTML, CSS 的关系：**

`TeeEngine` 直接支持了 JavaScript 中的 `ReadableStream.tee()` 方法，这是 Web Streams API 的一部分。

* **JavaScript:**
    * **示例：** 在 JavaScript 中，你可以使用 `tee()` 方法来复制一个 `fetch` API 返回的响应体流，或者一个自定义的 `ReadableStream`：
      ```javascript
      fetch('data.txt')
        .then(response => {
          const [branch1, branch2] = response.body.tee();

          // branch1 用于显示数据
          const reader1 = branch1.getReader();
          reader1.read().then(function processText({ done, value }) {
            if (done) {
              console.log("Branch 1 stream finished.");
              return;
            }
            console.log("Branch 1 received:", new TextDecoder().decode(value));
            return reader1.read().then(processText);
          });

          // branch2 用于分析数据
          const reader2 = branch2.getReader();
          reader2.read().then(function processAnalysis({ done, value }) {
            if (done) {
              console.log("Branch 2 stream finished.");
              return;
            }
            // 对数据进行分析处理
            console.log("Branch 2 analyzing:", value);
            return reader2.read().then(processAnalysis);
          });
        });
      ```
    * **功能关联：**  `TeeEngine` 的 `Start` 方法是在 JavaScript 调用 `stream.tee()` 时被调用的。  `PullAlgorithm` 中对 `ReadableStreamDefaultReader::Read` 的调用对应着从 JavaScript 可读流中读取数据的操作。 `StructuredClone` 方法对应着在 JavaScript 中复制数据的需求。

* **HTML:**
    * **示例：**  你可以使用 `tee()` 来处理通过 `<video>` 或 `<audio>` 标签的媒体流，例如，一个分支用于渲染视频，另一个分支用于进行实时分析或添加水印。
      ```html
      <video id="myVideo" src="my_video.mp4"></video>
      <script>
        const video = document.getElementById('myVideo');
        video.onloadedmetadata = () => {
          const mediaSource = new MediaSource();
          video.src = URL.createObjectURL(mediaSource);
          mediaSource.addEventListener('sourceopen', () => {
            // ... (获取视频流的操作) ...
            if (videoStream && videoStream.tee) {
              const [displayStream, analysisStream] = videoStream.tee();
              // 使用 displayStream 显示视频
              // 使用 analysisStream 进行分析
            }
          });
        };
      </script>
      ```
    * **功能关联：**  虽然 `tee_engine.cc` 本身不直接操作 HTML 元素，但它支持的 Web Streams API 是在处理 HTML5 媒体元素和 Fetch API 返回的响应体时非常重要的底层机制。

* **CSS:**
    * **关系较弱：**  `tee_engine.cc` 与 CSS 的功能没有直接的交互。CSS 主要负责页面的样式和布局。虽然可以通过 JavaScript 处理流数据并动态修改 CSS，但这并不是 `tee_engine.cc` 的核心职责。

**逻辑推理（假设输入与输出）：**

假设有一个包含字符串 "Hello" 和 "World" 的可读流 `sourceStream`：

**输入：** `sourceStream`

1. **调用 `sourceStream.tee()`:** JavaScript 代码调用 `sourceStream.tee()` 方法。
2. **`TeeEngine::Start` 被调用：**  创建了两个新的可读流 `branch1` 和 `branch2`。
3. **首次读取：** `PullAlgorithm` 触发对 `sourceStream` 的读取。假设读取到 "Hello"。
4. **`TeeReadRequest::ChunkSteps` 执行：**
    *   `chunk1` 和 `chunk2` 都被赋值为 "Hello"。
    *   如果 `clone_for_branch2_` 为 true，则 "Hello" 会被克隆到 `chunk2`。
    *   "Hello" 被加入到 `branch1` 和 `branch2` 的内部队列中。
5. **再次读取：**  `PullAlgorithm` 再次触发读取，假设读取到 "World"。
6. **`TeeReadRequest::ChunkSteps` 再次执行：**
    *   `chunk1` 和 `chunk2` 都被赋值为 "World"。
    *   如果 `clone_for_branch2_` 为 true，则 "World" 会被克隆到 `chunk2`。
    *   "World" 被加入到 `branch1` 和 `branch2` 的内部队列中。
7. **`sourceStream` 关闭：**  `sourceStream` 完成读取并关闭。
8. **`TeeReadRequest::CloseSteps` 执行：**  `branch1` 和 `branch2` 也被关闭。

**输出：**

*   `branch1`:  一个可读流，按顺序包含数据块 "Hello" 和 "World"。
*   `branch2`:  一个可读流，按顺序包含数据块 "Hello" (或其克隆) 和 "World" (或其克隆)。

**用户或编程常见的使用错误：**

1. **过早锁定原始流：**  如果在调用 `tee()` 之前就已经获取了原始流的读取器，那么 `tee()` 方法会抛出错误，因为流已经被锁定。
    *   **示例：**
        ```javascript
        fetch('data.txt')
          .then(response => {
            const reader = response.body.getReader(); // 锁定流
            const [branch1, branch2] = response.body.tee(); // 错误：流已锁定
          });
        ```
    *   **调试线索：**  错误信息会指示流已被锁定，检查 JavaScript 代码中是否在 `tee()` 之前调用了 `getReader()` 或其他锁定流的操作。

2. **假设分支流是完全独立的，但不理解克隆行为：**  如果 `clone_for_branch2` 为 `false`（默认情况下可能是这样的，具体取决于 `tee()` 的实现），那么两个分支流可能会共享相同的数据块引用。对一个分支中的数据进行修改可能会影响另一个分支。
    *   **示例：**  如果流中的数据是对象，并且没有进行克隆，那么修改 `branch1` 中读取到的对象可能会影响 `branch2` 中读取到的相同对象。
    *   **调试线索：**  在 `TeeReadRequest::ChunkSteps` 中检查 `clone_for_branch2_` 的值以及 `StructuredClone` 的调用。观察两个分支流中数据的变化是否相互影响。

3. **忘记处理其中一个分支流：**  如果只使用了 `tee()` 返回的一个分支，而忽略了另一个，可能会导致资源泄漏或未预期的行为，尤其是在原始流会持续推送数据的情况下。
    *   **示例：**
        ```javascript
        fetch('long-live-stream')
          .then(response => {
            const [branch1, _] = response.body.tee(); // 忽略了第二个分支
            const reader1 = branch1.getReader();
            // ... 只处理 branch1 的数据 ...
          });
        ```
    *   **调试线索：**  检查 JavaScript 代码中 `tee()` 的返回值是否都被使用。监控浏览器的内存使用情况，看是否有持续增长的趋势，这可能表明有未被消费的流数据。

**用户操作是如何一步步到达这里的（调试线索）：**

1. **用户发起网络请求或访问包含流数据的页面：**  例如，用户点击了一个链接，浏览器开始下载一个大文件，或者用户访问了一个包含 `<video>` 标签的页面，浏览器开始接收视频流数据。

2. **JavaScript 代码使用 `ReadableStream.tee()` 方法：**  开发者编写的 JavaScript 代码中，获取了一个 `ReadableStream` 对象（例如，从 `fetch` API 的响应体中获取），并调用了其 `tee()` 方法。

3. **Blink 引擎接收到 `tee()` 调用：**  JavaScript 引擎将 `tee()` 方法的调用传递给 Blink 渲染引擎中对应的 C++ 代码。

4. **`TeeEngine::Start` 被调用：**  在 `blink/renderer/core/streams/readable_stream.cc` 中，`ReadableStream::Tee` 方法会创建 `TeeEngine` 对象并调用其 `Start` 方法。

5. **数据开始流动：**
    *   当原始流有数据可读时，`ReadableStreamDefaultReader::Read` 方法会被调用，最终触发 `TeeEngine` 的 `PullAlgorithm`。
    *   `TeeReadRequest::ChunkSteps` 方法负责处理读取到的数据块，并将其分发到两个分支流的控制器中。

6. **如果发生错误或流关闭：**  `TeeReadRequest::CloseSteps` 或 `TeeReadRequest::ErrorSteps` 会被调用，处理流的终止状态。

**调试线索：**

*   **在 `TeeEngine::Start` 方法处设置断点：**  可以检查 `stream` 参数是否是预期的 `ReadableStream` 对象，以及 `clone_for_branch2` 的值。
*   **在 `PullAlgorithm::Run` 方法处设置断点：**  可以观察读取操作是否按预期发生。
*   **在 `TeeReadRequest::ChunkSteps` 方法处设置断点：**  可以检查读取到的 `chunk` 的内容，以及数据是如何被复制到两个分支的。
*   **检查 `canceled_` 标志和 `reason_` 变量：**  可以了解分支流是否被取消以及取消的原因。
*   **监控 `controller_` 指针：**  确保分支流的控制器已正确初始化。

通过以上分析，我们可以更深入地理解 `tee_engine.cc` 文件的作用以及它在 Web Streams API 实现中的关键地位。

### 提示词
```
这是目录为blink/renderer/core/streams/tee_engine.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/streams/tee_engine.h"

#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/streams/miscellaneous_operations.h"
#include "third_party/blink/renderer/core/streams/read_request.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_controller.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_controller.h"
#include "third_party/blink/renderer/core/streams/stream_algorithms.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

v8::MaybeLocal<v8::Value> TeeEngine::StructuredClone(
    ScriptState* script_state,
    v8::Local<v8::Value> chunk,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#abstract-opdef-structuredclone
  v8::Context::Scope scope(script_state->GetContext());
  v8::Isolate* isolate = script_state->GetIsolate();

  // 1. Let serialized be ? StructuredSerialize(v).
  scoped_refptr<SerializedScriptValue> serialized =
      SerializedScriptValue::Serialize(
          isolate, chunk,
          SerializedScriptValue::SerializeOptions(
              SerializedScriptValue::kNotForStorage),
          exception_state);
  if (exception_state.HadException()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                      "chunk could not be cloned.");
    return v8::MaybeLocal<v8::Value>();
  }

  // 2. Return ? StructuredDeserialize(serialized, the current Realm).
  return serialized->Deserialize(isolate);
}

class TeeEngine::PullAlgorithm final : public StreamAlgorithm {
 public:
  explicit PullAlgorithm(TeeEngine* engine) : engine_(engine) {}

  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int,
                                  v8::Local<v8::Value>[]) override {
    // https://streams.spec.whatwg.org/#readable-stream-tee
    // 13. Let pullAlgorithm be the following steps:
    //   a. If reading is true,
    if (engine_->reading_) {
      //      i. Set readAgain to true.
      engine_->read_again_ = true;
      //      ii. Return a promise resolved with undefined.
      return ToResolvedUndefinedPromise(script_state);
    }

    ExceptionState exception_state(script_state->GetIsolate(),
                                   v8::ExceptionContext::kUnknown, "", "");

    //   b. Set reading to true.
    engine_->reading_ = true;
    //   c. Let readRequest be a read request with the following items:
    auto* read_request = MakeGarbageCollected<TeeReadRequest>(engine_);
    //   d. Perform ! ReadableStreamDefaultReaderRead(reader, readRequest).
    ReadableStreamDefaultReader::Read(script_state, engine_->reader_,
                                      read_request, exception_state);
    //   e. Return a promise resolved with undefined.
    return ToResolvedUndefinedPromise(script_state);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(engine_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  class TeeReadRequest final : public ReadRequest {
   public:
    explicit TeeReadRequest(TeeEngine* engine) : engine_(engine) {}

    void ChunkSteps(ScriptState* script_state,
                    v8::Local<v8::Value> chunk,
                    ExceptionState&) const override {
      scoped_refptr<scheduler::EventLoop> event_loop =
          ExecutionContext::From(script_state)->GetAgent()->event_loop();
      v8::Global<v8::Value> value(script_state->GetIsolate(), chunk);
      event_loop->EnqueueMicrotask(
          WTF::BindOnce(&TeeReadRequest::ChunkStepsBody, WrapPersistent(this),
                        WrapPersistent(script_state), std::move(value)));
    }

    void CloseSteps(ScriptState* script_state) const override {
      // 1. Set reading to false.
      engine_->reading_ = false;

      // 2. If canceled1 is false, perform !
      // ReadableStreamDefaultControllerClose(branch1.[[controller]]).
      // 3. If canceled2 is false, perform !
      // ReadableStreamDefaultControllerClose(branch2.[[controller]]).
      for (int branch = 0; branch < 2; ++branch) {
        if (!engine_->canceled_[branch] &&
            ReadableStreamDefaultController::CanCloseOrEnqueue(
                engine_->controller_[branch])) {
          ReadableStreamDefaultController::Close(script_state,
                                                 engine_->controller_[branch]);
        }
      }

      // 4. If canceled1 is false or canceled2 is false, resolve
      // cancelPromise with undefined.
      if (!engine_->canceled_[0] || !engine_->canceled_[1]) {
        engine_->cancel_promise_->Resolve();
      }
    }

    void ErrorSteps(ScriptState* script_state,
                    v8::Local<v8::Value> e) const override {
      // 1. Set reading to false.
      engine_->reading_ = false;
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(engine_);
      ReadRequest::Trace(visitor);
    }

   private:
    void ChunkStepsBody(ScriptState* script_state,
                        v8::Global<v8::Value> value) const {
      // This is called in a microtask, the ScriptState needs to be put back
      // in scope.
      ScriptState::Scope scope(script_state);
      v8::Isolate* isolate = script_state->GetIsolate();
      v8::TryCatch try_catch(isolate);
      // 1. Set readAgain to false.
      engine_->read_again_ = false;

      // 2. Let chunk1 and chunk2 be chunk.
      std::array<v8::Local<v8::Value>, 2> chunk;
      chunk[0] = value.Get(isolate);
      chunk[1] = chunk[0];

      // 3. If canceled2 is false and cloneForBranch2 is true,
      if (!engine_->canceled_[1] && engine_->clone_for_branch2_) {
        //   a. Let cloneResult be StructuredClone(chunk2).
        v8::MaybeLocal<v8::Value> clone_result_maybe = engine_->StructuredClone(
            script_state, chunk[1], PassThroughException(isolate));
        v8::Local<v8::Value> clone_result;
        //   b. If cloneResult is an abrupt completion,
        if (!clone_result_maybe.ToLocal(&clone_result)) {
          CHECK(try_catch.HasCaught());
          v8::Local<v8::Value> exception = try_catch.Exception();
          //     i. Perform !
          //     ReadableStreamDefaultControllerError(branch1.[[controller]],
          //     cloneResult.[[Value]]).
          ReadableStreamDefaultController::Error(
              script_state, engine_->controller_[0], exception);
          //     ii. Perform !
          //     ReadableStreamDefaultControllerError(branch2.[[controller]],
          //     cloneResult.[[Value]]).
          ReadableStreamDefaultController::Error(
              script_state, engine_->controller_[1], exception);
          //     iii. Resolve cancelPromise with !
          //     ReadableStreamCancel(stream, cloneResult.[[Value]]).
          engine_->cancel_promise_->Resolve(ReadableStream::Cancel(
              script_state, engine_->stream_, exception));
          //     iv. Return.
          return;
        } else {
          DCHECK(!try_catch.HasCaught());
          //   c. Otherwise, set chunk2 to cloneResult.[[Value]].
          chunk[1] = clone_result;
        }
      }

      // 4. If canceled1 is false, perform !
      // ReadableStreamDefaultControllerEnqueue(branch1.[[controller]], chunk1).
      // 5. If canceled2 is false, perform !
      // ReadableStreamDefaultControllerEnqueue(branch2.[[controller]], chunk2).
      for (int branch = 0; branch < 2; ++branch) {
        if (!engine_->canceled_[branch] &&
            ReadableStreamDefaultController::CanCloseOrEnqueue(
                engine_->controller_[branch])) {
          ReadableStreamDefaultController::Enqueue(
              script_state, engine_->controller_[branch], chunk[branch],
              PassThroughException(isolate));
          if (try_catch.HasCaught()) {
            // Instead of returning a rejection, which is inconvenient here,
            // call ControllerError(). The only difference this makes is that it
            // happens synchronously, but that should not be observable.
            ReadableStreamDefaultController::Error(script_state,
                                                   engine_->controller_[branch],
                                                   try_catch.Exception());
            return;
          }
        }
      }

      // 6. Set reading to false.
      engine_->reading_ = false;

      // 7. If readAgain is true, perform pullAlgorithm.
      if (engine_->read_again_) {
        auto* pull_algorithm = MakeGarbageCollected<PullAlgorithm>(engine_);
        pull_algorithm->Run(script_state, 0, nullptr);
      }
    }

    Member<TeeEngine> engine_;
  };

  Member<TeeEngine> engine_;
};

class TeeEngine::CancelAlgorithm final : public StreamAlgorithm {
 public:
  CancelAlgorithm(TeeEngine* engine, int branch)
      : engine_(engine), branch_(branch) {
    DCHECK(branch == 0 || branch == 1);
  }

  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    // https://streams.spec.whatwg.org/#readable-stream-tee
    // This implements both cancel1Algorithm and cancel2Algorithm as they are
    // identical except for the index they operate on. Standard comments are
    // from cancel1Algorithm.
    // 13. Let cancel1Algorithm be the following steps, taking a reason
    //     argument:
    auto* isolate = script_state->GetIsolate();

    // a. Set canceled1 to true.
    engine_->canceled_[branch_] = true;
    DCHECK_EQ(argc, 1);

    // b. Set reason1 to reason.
    engine_->reason_[branch_].Reset(isolate, argv[0]);

    const int other_branch = 1 - branch_;

    // c. If canceled2 is true,
    if (engine_->canceled_[other_branch]) {
      // i. Let compositeReason be ! CreateArrayFromList(« reason1, reason2 »).
      v8::Local<v8::Value> reason[] = {engine_->reason_[0].Get(isolate),
                                       engine_->reason_[1].Get(isolate)};
      v8::Local<v8::Value> composite_reason =
          v8::Array::New(script_state->GetIsolate(), reason, 2);

      // ii. Let cancelResult be ! ReadableStreamCancel(stream,
      //    compositeReason).
      auto cancel_result = ReadableStream::Cancel(
          script_state, engine_->stream_, composite_reason);

      // iii. Resolve cancelPromise with cancelResult.
      engine_->cancel_promise_->Resolve(cancel_result);
    }
    return engine_->cancel_promise_->Promise();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(engine_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  Member<TeeEngine> engine_;
  const int branch_;
};

void TeeEngine::Start(ScriptState* script_state,
                      ReadableStream* stream,
                      bool clone_for_branch2,
                      ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#abstract-opdef-readablestreamdefaulttee
  //  1. Assert: stream implements ReadableStream.
  DCHECK(stream);
  stream_ = stream;

  // 2. Assert: cloneForBranch2 is a boolean.
  clone_for_branch2_ = clone_for_branch2;

  // 3. Let reader be ? AcquireReadableStreamDefaultReader(stream).
  reader_ = ReadableStream::AcquireDefaultReader(script_state, stream,
                                                 exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // These steps are performed by the constructor:
  //  4. Let reading be false.
  DCHECK(!reading_);

  //  5. Let readAgain be false.
  DCHECK(!read_again_);

  //  6. Let canceled1 be false.
  DCHECK(!canceled_[0]);

  //  7. Let canceled2 be false.
  DCHECK(!canceled_[1]);

  //  8. Let reason1 be undefined.
  DCHECK(reason_[0].IsEmpty());

  //  9. Let reason2 be undefined.
  DCHECK(reason_[1].IsEmpty());

  // 10. Let branch1 be undefined.
  DCHECK(!branch_[0]);

  // 11. Let branch2 be undefined.
  DCHECK(!branch_[1]);

  // 12. Let cancelPromise be a new promise.
  cancel_promise_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);

  // 13. Let pullAlgorithm be the following steps:
  // (steps are defined in PullAlgorithm::Run()).
  auto* pull_algorithm = MakeGarbageCollected<PullAlgorithm>(this);

  // 14. Let cancel1Algorithm be the following steps, taking a reason argument:
  // (see CancelAlgorithm::Run()).
  auto* cancel1_algorithm = MakeGarbageCollected<CancelAlgorithm>(this, 0);

  // 15. Let cancel2Algorithm be the following steps, taking a reason argument:
  // (both algorithms share a single implementation).
  auto* cancel2_algorithm = MakeGarbageCollected<CancelAlgorithm>(this, 1);

  // 16. Let startAlgorithm be an algorithm that returns undefined.
  auto* start_algorithm = CreateTrivialStartAlgorithm();

  auto* size_algorithm = CreateDefaultSizeAlgorithm();

  // 17. Set branch1 to ! CreateReadableStream(startAlgorithm, pullAlgorithm,
  //   cancel1Algorithm).
  branch_[0] = ReadableStream::Create(script_state, start_algorithm,
                                      pull_algorithm, cancel1_algorithm, 1.0,
                                      size_algorithm, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // 18. Set branch2 to ! CreateReadableStream(startAlgorithm, pullAlgorithm,
  //   cancel2Algorithm).
  branch_[1] = ReadableStream::Create(script_state, start_algorithm,
                                      pull_algorithm, cancel2_algorithm, 1.0,
                                      size_algorithm, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  for (int branch = 0; branch < 2; ++branch) {
    ReadableStreamController* controller =
        branch_[branch]->readable_stream_controller_;
    // We just created the branches above. It is obvious that the controllers
    // are default controllers.
    controller_[branch] = To<ReadableStreamDefaultController>(controller);
  }

  class RejectFunction final : public ThenCallable<IDLAny, RejectFunction> {
   public:
    explicit RejectFunction(TeeEngine* engine) : engine_(engine) {}

    void React(ScriptState* script_state, ScriptValue r) {
      // 18. Upon rejection of reader.[[closedPromise]] with reason r,
      //   a. Perform ! ReadableStreamDefaultControllerError(branch1.
      //      [[readableStreamController]], r).
      ReadableStreamDefaultController::Error(
          script_state, engine_->controller_[0], r.V8Value());

      //   b. Perform ! ReadableStreamDefaultControllerError(branch2.
      //      [[readableStreamController]], r).
      ReadableStreamDefaultController::Error(
          script_state, engine_->controller_[1], r.V8Value());

      // TODO(ricea): Implement https://github.com/whatwg/streams/pull/1045 so
      // this step can be numbered correctly.
      // If canceled1 is false or canceled2 is false, resolve |cancelPromise|
      // with undefined.
      if (!engine_->canceled_[0] || !engine_->canceled_[1]) {
        engine_->cancel_promise_->Resolve();
      }
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(engine_);
      ThenCallable<IDLAny, RejectFunction>::Trace(visitor);
    }

   private:
    Member<TeeEngine> engine_;
  };

  // 19. Upon rejection of reader.[[closedPromise]] with reason r,
  reader_->closed(script_state)
      .Catch(script_state, MakeGarbageCollected<RejectFunction>(this));

  // Step "20. Return « branch1, branch2 »."
  // is performed by the caller.
}

}  // namespace blink
```