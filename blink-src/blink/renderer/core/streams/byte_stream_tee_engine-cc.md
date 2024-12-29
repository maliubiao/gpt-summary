Response:
Let's break down the thought process for analyzing this C++ file.

1. **Understand the Core Purpose:** The file name `byte_stream_tee_engine.cc` and the namespace `blink::streams` immediately suggest this code deals with *streams* in the Blink rendering engine and specifically a "tee" operation for *byte streams*. The "tee" analogy from plumbing or command-line tools (like `| tee`) hints at splitting a stream into two.

2. **Identify Key Classes:** Scan the file for class definitions. The main class is `ByteStreamTeeEngine`. It also has nested classes `PullAlgorithm`, `CancelAlgorithm`, `ByteTeeReadRequest`, and `ByteTeeReadIntoRequest`. These inner classes likely represent specific steps or states within the teeing process.

3. **Map to Web Streams API:**  Recognize the terms like "ReadableStream," "ReadableByteStreamController," "BYOB (Bring Your Own Buffer)," "pull," "cancel," and "enqueue." These are strong indicators that this code implements parts of the Web Streams API, specifically the `tee()` method on `ReadableByteStream`.

4. **Analyze the `ByteStreamTeeEngine` Class:**
    * **Members:**  Examine the member variables:
        * `stream_`: The original readable stream being teed.
        * `reader_`: A reader for the original stream.
        * `branch_`:  An array holding the two *new* readable streams created by the tee operation.
        * `controller_`: An array holding the controllers for the two new streams.
        * `reading_`: A boolean indicating if the engine is currently reading from the source stream.
        * `read_again_for_branch_`: Flags to signal that a branch needs more data after a chunk is processed.
        * `canceled_`: Flags indicating if each branch has been canceled.
        * `reason_`: Reasons for cancellation of each branch.
        * `cancel_promise_`: A promise associated with the overall tee operation's cancellation.
    * **Methods:** Look at the public methods:
        * `Start()`:  Likely initializes the teeing process.
        * `ForwardReaderError()`: Handles errors from the source stream's reader.
        * `PullWithDefaultReader()`:  Handles pulling data when using a default reader.
        * `PullWithBYOBReader()`: Handles pulling data when using a BYOB reader.
        * `CloneAsUint8Array()`:  Crucial for teeing – creating a copy of the data for the second branch.

5. **Analyze the Inner Classes:**
    * **`PullAlgorithm`:**  This class implements the "pull" logic for each of the teed streams. It checks if reading is already in progress and initiates a read from the source stream using either a default or BYOB reader. The `branch_` member distinguishes between the two output streams.
    * **`CancelAlgorithm`:** This class handles the cancellation of each teed stream. It records the cancellation reason and, if both branches are canceled, cancels the original stream. It uses `composite_reason` to provide both reasons.
    * **`ByteTeeReadRequest`:**  This class handles the result of a `read()` operation from the *original* stream when using a *default reader*. It clones the data (if necessary), enqueues it into the controllers of the two teed streams, and manages the `reading_` flag and potential subsequent pulls.
    * **`ByteTeeReadIntoRequest`:** This class handles the result of a `read()` operation from the *original* stream when using a *BYOB reader*. It's more complex as it needs to manage the provided buffer and ensure both branches receive appropriate data or signals.

6. **Identify Relationships and Data Flow:**  Trace how the different parts interact. `Start()` sets up the engine and creates the branches. The `PullAlgorithm` triggers reads from the source stream. The `ByteTeeReadRequest`/`ByteTeeReadIntoRequest` receive data and distribute it. The `CancelAlgorithm` handles termination.

7. **Connect to Web Concepts:** Explicitly link the code to JavaScript, HTML, and CSS where applicable. The Web Streams API is a JavaScript API, so the connection is direct. Give concrete examples of how a JavaScript `tee()` call would lead to this C++ code being executed.

8. **Infer Logical Flows and Scenarios:** Imagine different use cases:
    * A simple tee: Data flows through, gets duplicated.
    * One branch cancels early: The other continues until the source ends or is cancelled.
    * Errors in the source stream: How are they propagated?
    * Use of BYOB readers: How does that affect the flow?

9. **Consider Potential Errors:** Think about what could go wrong:
    * Trying to read after cancellation.
    * Incorrectly handling BYOB buffers.
    * Race conditions (though the stream API aims to prevent these at the user level).

10. **Construct Debugging Steps:**  Imagine you encounter an issue. How would you trace the execution? What information would be relevant?  Focus on the entry point (JavaScript `tee()`), the key classes and their interactions, and the conditions that trigger different execution paths.

11. **Refine and Organize:**  Structure the analysis logically with clear headings and bullet points. Ensure the explanations are concise and accurate. Use terms from the Web Streams specification where appropriate.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This just duplicates data."  **Correction:**  It also needs to handle cancellation, errors, and different reader types (default vs. BYOB).
* **Confusion about `readAgainForBranch`:**  Initially, it might not be clear why these flags are needed. **Clarification:** They allow a branch to request more data *after* a chunk has been processed, without immediately blocking the original stream's reading process.
* **Overlooking `ForwardReaderError`:** It's important to recognize that errors from the *source* stream need to be propagated to the teed streams.

By following these steps, moving from the general purpose to the specific details and connecting the code to the broader web platform, a comprehensive analysis like the example provided can be constructed.
好的，让我们来详细分析一下 `blink/renderer/core/streams/byte_stream_tee_engine.cc` 这个文件。

**文件功能概述**

这个文件实现了 Chromium Blink 引擎中用于 `ReadableByteStream` 的 `tee()` 方法的核心逻辑。 `tee()` 方法可以将一个可读的字节流（`ReadableByteStream`）拆分成两个独立的、完全相同的副本（两个新的 `ReadableByteStream`）。  这两个新的流可以被独立地读取、取消或关闭，而不会相互影响。

**与 JavaScript, HTML, CSS 的关系**

这个文件直接关联到 Web Streams API 中的 `ReadableByteStream.prototype.tee()` 方法。当 JavaScript 代码调用这个方法时，Blink 引擎会调用这里的 C++ 代码来创建和管理这两个分支流。

**举例说明:**

**JavaScript:**

```javascript
const response = await fetch('my_large_file.bin');
const readableByteStream = response.body;

// 调用 tee() 方法创建两个分支流
const [branch1, branch2] = readableByteStream.tee();

// 独立地读取和处理两个分支流
const reader1 = branch1.getReader();
const reader2 = branch2.getReader();

// ... 可以将 branch1 用于下载进度条，将 branch2 用于实际数据处理
```

**HTML:**  虽然这个 C++ 文件本身不直接操作 HTML 结构，但 `tee()` 创建的流可以在 JavaScript 中被用于多种与 HTML 交互的场景，例如：

* **下载进度条:**  一个分支流可以被用来计算已下载的字节数，并更新 HTML 中的进度条元素。
* **Worker 线程处理:**  可以将一个分支流传递给 Web Worker 进行异步处理，而主线程可以继续处理另一个分支。
* **MediaSource API:**  可以将一个分支流提供给 `MediaSource` 对象，用于播放音视频。

**CSS:**  CSS 与此文件没有直接关系。

**逻辑推理 (假设输入与输出)**

假设我们有一个包含 10 个字节的 `ReadableByteStream`，其内容为 `[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]`。

**假设输入:**

* 一个 `ReadableByteStream` 对象（`stream_`）。
* 当 JavaScript 调用 `stream_.tee()` 时，Blink 引擎会创建 `ByteStreamTeeEngine` 实例并调用其 `Start()` 方法。

**逻辑推理过程 (简化):**

1. **`Start()` 方法:**
   - 创建两个新的 `ReadableByteStream` 对象 (`branch_[0]`, `branch_[1]`)。
   - 为这两个新的流创建对应的 `ReadableByteStreamController` (`controller_[0]`, `controller_[1]`)。
   - 获取原始流的默认读取器 (`reader_`)。
   - 设置一些内部状态变量，例如 `reading_`, `canceled_` 等。
   - 创建 `pull` 和 `cancel` 算法的实例，用于控制分支流的数据拉取和取消。
   - 将错误处理逻辑连接到原始流的读取器。

2. **数据读取:** 当需要从分支流读取数据时（例如，调用 `branch1.getReader().read()`）：
   - 分支流的 `pull` 算法（`PullAlgorithm`）会被调用。
   - `PullAlgorithm` 检查当前是否正在从原始流读取数据。
   - 如果没有正在读取，则标记为正在读取 (`engine_->reading_ = true`)，并从原始流的读取器读取数据。
   - 原始流读取到数据后，会调用 `ByteTeeReadRequest::ChunkSteps()` 或 `ByteTeeReadIntoRequest::ChunkSteps()`（取决于原始流的读取器类型）。
   - 在 `ChunkSteps()` 中，数据会被复制（`CloneAsUint8Array()`），并分别放入两个分支流的控制器队列中 (`ReadableByteStreamController::Enqueue()`)。

3. **假设输出 (在读取部分数据后):**

   - `branch1` 的内部队列可能包含一些字节，例如 `[0, 1, 2, 3, 4]`。
   - `branch2` 的内部队列也会包含相同的字节副本 `[0, 1, 2, 3, 4]`。
   - 如果其中一个分支流被读取，它的队列会被清空一部分。

**用户或编程常见的使用错误**

1. **过早关闭或取消原始流:** 如果在两个分支流都完成读取之前关闭或取消原始流，可能会导致数据丢失或错误。`ByteStreamTeeEngine` 会处理这种情况，尝试将错误传播到分支流。

   **例子:**

   ```javascript
   const response = await fetch('my_large_file.bin');
   const readableByteStream = response.body;
   const [branch1, branch2] = readableByteStream.tee();

   readableByteStream.cancel('premature cancellation'); // 过早取消原始流

   const reader1 = branch1.getReader();
   const result1 = await reader1.read(); // 可能会得到错误或提前结束
   ```

2. **不消费所有分支流:** 如果创建了 tee 的分支流，但只读取其中一个，另一个分支流可能会保持挂起状态，占用资源。虽然最终会被垃圾回收，但应该避免这种情况。

   **例子:**

   ```javascript
   const response = await fetch('my_large_file.bin');
   const readableByteStream = response.body;
   const [branch1, branch2] = readableByteStream.tee();

   const reader1 = branch1.getReader();
   while (true) {
       const { done, value } = await reader1.read();
       if (done) break;
       // 处理 branch1 的数据
   }
   // 没有读取 branch2
   ```

3. **在 BYOB (Bring Your Own Buffer) 模式下的错误使用:** 如果原始流使用 BYOB 读取器，tee 操作需要特别小心地处理缓冲区，确保两个分支都能正确地访问或复制数据。错误地管理缓冲区可能导致数据损坏。

**用户操作如何一步步到达这里 (调试线索)**

以下是一个典型的用户操作流程，最终会触发 `byte_stream_tee_engine.cc` 中的代码：

1. **用户在浏览器中发起网络请求:** 例如，用户点击一个链接下载文件，或者 JavaScript 代码使用 `fetch()` API 发起请求。
2. **浏览器接收到响应头:**  `fetch()` API 返回的 `Response` 对象中的 `body` 属性是一个 `ReadableByteStream`。
3. **JavaScript 代码调用 `tee()` 方法:**  开发者在 JavaScript 中获取到 `response.body` 后，调用其 `tee()` 方法来创建两个分支流。
   ```javascript
   const response = await fetch('large_file.bin');
   const readableStream = response.body;
   const [branchA, branchB] = readableStream.tee();
   ```
4. **Blink 引擎接收到 `tee()` 调用:**  V8 引擎会将这个 JavaScript 调用转发到 Blink 引擎的相应 C++ 代码。
5. **创建 `ByteStreamTeeEngine` 实例:** Blink 引擎会创建一个 `ByteStreamTeeEngine` 的实例来管理这次 tee 操作。
6. **调用 `ByteStreamTeeEngine::Start()`:**  新创建的引擎实例的 `Start()` 方法会被调用，进行初始化，创建分支流和控制器。
7. **后续的读取操作:**  当 JavaScript 代码尝试从 `branchA` 或 `branchB` 读取数据时，会触发 `PullAlgorithm` 和相关的数据处理逻辑，例如 `ByteTeeReadRequest::ChunkSteps()`。
8. **取消操作:** 如果 JavaScript 代码调用 `branchA.cancel()` 或 `branchB.cancel()`，会触发 `CancelAlgorithm`。

**调试线索:**

如果在调试与 `ReadableByteStream.tee()` 相关的问题，可以关注以下几点：

* **JavaScript 调用栈:** 检查 JavaScript 代码中调用 `tee()` 的位置。
* **Blink 内部日志:** Chromium 的内部日志（可以使用 `--vmodule` 命令行参数来启用更详细的日志）可能会显示 `ByteStreamTeeEngine` 的创建和方法调用。
* **断点调试:** 在 `byte_stream_tee_engine.cc` 中的关键方法（如 `Start()`, `PullAlgorithm::Run()`, `ByteTeeReadRequest::ChunkSteps()`, `CancelAlgorithm::Run()`）设置断点，可以跟踪代码的执行流程和变量状态。
* **检查 `ReadableStream` 和 `ReadableByteStreamController` 的状态:**  查看原始流和分支流的内部状态，例如是否已关闭、是否已取消、内部队列中的数据等。

总而言之，`byte_stream_tee_engine.cc` 是 Blink 引擎中实现 `ReadableByteStream` 的 `tee()` 功能的关键部分，它负责创建和管理两个独立的字节流副本，并处理数据的复制、读取和取消等操作。理解这个文件的功能有助于理解 Web Streams API 中 `tee()` 的底层实现。

Prompt: 
```
这是目录为blink/renderer/core/streams/byte_stream_tee_engine.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/streams/byte_stream_tee_engine.h"

#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/streams/miscellaneous_operations.h"
#include "third_party/blink/renderer/core/streams/read_into_request.h"
#include "third_party/blink/renderer/core/streams/read_request.h"
#include "third_party/blink/renderer/core/streams/readable_byte_stream_controller.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_byob_reader.h"
#include "third_party/blink/renderer/core/streams/readable_stream_byob_request.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_reader.h"
#include "third_party/blink/renderer/core/streams/stream_algorithms.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

class ByteStreamTeeEngine::PullAlgorithm final : public StreamAlgorithm {
 public:
  PullAlgorithm(ByteStreamTeeEngine* engine, int branch)
      : engine_(engine), branch_(branch) {
    DCHECK(branch == 0 || branch == 1);
  }

  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    // https://streams.spec.whatwg.org/#abstract-opdef-readablebytestreamtee
    // This implements both pull1Algorithm and pull2Algorithm as they are
    // identical except for the index they operate on. Standard comments are
    // from pull1Algorithm.
    // 17. Let pull1Algorithm be the following steps:
    //   a. If reading is true,
    ExceptionState exception_state(script_state->GetIsolate());
    if (engine_->reading_) {
      //     i. Set readAgainForBranch1 to true.
      engine_->read_again_for_branch_[branch_] = true;
      //     ii. Return a promise resolved with undefined.
      return ToResolvedUndefinedPromise(script_state);
    }
    //   b. Set reading to true.
    engine_->reading_ = true;
    //   c. Let byobRequest be !
    //   ReadableByteStreamControllerGetBYOBRequest(branch1.[[controller]]).
    ReadableStreamBYOBRequest* byob_request =
        ReadableByteStreamController::GetBYOBRequest(
            engine_->controller_[branch_]);
    //   d. If byobRequest is null, perform pullWithDefaultReader.
    if (!byob_request) {
      engine_->PullWithDefaultReader(script_state, exception_state);
    } else {
      //   e. Otherwise, perform pullWithBYOBReader, given byobRequest.[[view]]
      //   and false.
      engine_->PullWithBYOBReader(script_state, byob_request->view(), branch_,
                                  exception_state);
    }
    //   f. Return a promise resolved with undefined.
    return ToResolvedUndefinedPromise(script_state);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(engine_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  Member<ByteStreamTeeEngine> engine_;
  const int branch_;
};

class ByteStreamTeeEngine::CancelAlgorithm final : public StreamAlgorithm {
 public:
  CancelAlgorithm(ByteStreamTeeEngine* engine, int branch)
      : engine_(engine), branch_(branch) {
    DCHECK(branch == 0 || branch == 1);
  }

  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    // https://streams.spec.whatwg.org/#abstract-opdef-readablebytestreamtee
    // This implements both cancel1Algorithm and cancel2Algorithm as they are
    // identical except for the index they operate on. Standard comments are
    // from cancel1Algorithm.
    // 19. Let cancel1Algorithm be the following steps, taking a reason
    // argument:
    auto* isolate = script_state->GetIsolate();
    //   a. Set canceled1 to true.
    engine_->canceled_[branch_] = true;
    //   b. Set reason1 to reason.
    DCHECK_EQ(argc, 1);
    engine_->reason_[branch_].Reset(isolate, argv[0]);
    //   c. If canceled2 is true,
    const int other_branch = 1 - branch_;
    if (engine_->canceled_[other_branch]) {
      //     i. Let compositeReason be ! CreateArrayFromList(« reason1, reason2
      //     »).
      v8::Local<v8::Value> reason[] = {engine_->reason_[0].Get(isolate),
                                       engine_->reason_[1].Get(isolate)};
      v8::Local<v8::Value> composite_reason =
          v8::Array::New(script_state->GetIsolate(), reason, 2);
      //     ii. Let cancelResult be ! ReadableStreamCancel(stream,
      //     compositeReason).
      auto cancel_result = ReadableStream::Cancel(
          script_state, engine_->stream_, composite_reason);
      //     iii. Resolve cancelPromise with cancelResult.
      engine_->cancel_promise_->Resolve(cancel_result);
    }
    //   d. Return cancelPromise.
    return engine_->cancel_promise_->Promise();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(engine_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  Member<ByteStreamTeeEngine> engine_;
  const int branch_;
};

class ByteStreamTeeEngine::ByteTeeReadRequest final : public ReadRequest {
 public:
  explicit ByteTeeReadRequest(ByteStreamTeeEngine* engine) : engine_(engine) {}

  void ChunkSteps(ScriptState* script_state,
                  v8::Local<v8::Value> chunk,
                  ExceptionState&) const override {
    scoped_refptr<scheduler::EventLoop> event_loop =
        ExecutionContext::From(script_state)->GetAgent()->event_loop();
    v8::Global<v8::Value> value(script_state->GetIsolate(), chunk);
    event_loop->EnqueueMicrotask(
        WTF::BindOnce(&ByteTeeReadRequest::ChunkStepsBody, WrapPersistent(this),
                      WrapPersistent(script_state), std::move(value)));
  }

  void CloseSteps(ScriptState* script_state) const override {
    // 1. Set reading to false.
    engine_->reading_ = false;
    v8::Isolate* isolate = script_state->GetIsolate();
    v8::TryCatch try_catch(isolate);
    // 2. If canceled1 is false, perform !
    // ReadableByteStreamControllerClose(branch1.[[controller]]).
    // 3. If canceled2 is false, perform !
    // ReadableByteStreamControllerClose(branch2.[[controller]]).
    for (int branch = 0; branch < 2; ++branch) {
      if (!engine_->canceled_[branch]) {
        engine_->controller_[branch]->Close(script_state,
                                            engine_->controller_[branch]);
        if (try_catch.HasCaught()) {
          // Instead of returning a rejection, which is inconvenient here,
          // call ControllerError(). The only difference this makes is that it
          // happens synchronously, but that should not be observable.
          ReadableByteStreamController::Error(script_state,
                                              engine_->controller_[branch],
                                              try_catch.Exception());
          return;
        }
      }
    }
    // 4. If branch1.[[controller]].[[pendingPullIntos]] is not empty, perform
    // ! ReadableByteStreamControllerRespond(branch1.[[controller]], 0).
    // 5. If branch2.[[controller]].[[pendingPullIntos]] is not empty, perform
    // ! ReadableByteStreamControllerRespond(branch2.[[controller]], 0).
    for (int branch = 0; branch < 2; ++branch) {
      if (!engine_->controller_[branch]->pending_pull_intos_.empty()) {
        ReadableByteStreamController::Respond(script_state,
                                              engine_->controller_[branch], 0,
                                              PassThroughException(isolate));
        if (try_catch.HasCaught()) {
          // Instead of returning a rejection, which is inconvenient here,
          // call ControllerError(). The only difference this makes is that it
          // happens synchronously, but that should not be observable.
          ReadableByteStreamController::Error(script_state,
                                              engine_->controller_[branch],
                                              try_catch.Exception());
          return;
        }
      }
    }
    // 6. If canceled1 is false or canceled2 is false, resolve cancelPromise
    // with undefined.
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
    ScriptState::Scope scope(script_state);
    v8::Isolate* isolate = script_state->GetIsolate();
    // 1. Set readAgainForBranch1 to false.
    engine_->read_again_for_branch_[0] = false;
    // 2. Set readAgainForBranch2 to false.
    engine_->read_again_for_branch_[1] = false;

    ExceptionState exception_state(isolate);

    // 3. Let chunk1 and chunk2 be chunk.
    NotShared<DOMUint8Array> buffer_view =
        NativeValueTraits<NotShared<DOMUint8Array>>::NativeValue(
            isolate, value.Get(isolate), exception_state);
    std::array<NotShared<DOMUint8Array>, 2> chunk = {buffer_view, buffer_view};

    // 4. If canceled1 is false and canceled2 is false,
    if (!engine_->canceled_[0] && !engine_->canceled_[1]) {
      //   a. Let cloneResult be CloneAsUint8Array(chunk).
      auto* clone_result = engine_->CloneAsUint8Array(buffer_view.Get());
      //   b. If cloneResult is an abrupt completion,
      //     i. Perform !
      //     ReadableByteStreamControllerError(branch1.[[controller]],
      //     cloneResult.[[Value]]).
      //     ii. Perform !
      //     ReadableByteStreamControllerError(branch2.[[controller]],
      //     cloneResult.[[Value]]).
      //     iii. Resolve cancelPromise with !
      //     ReadableStreamCancel(stream, cloneResult.[[Value]]).
      //     iv. Return.
      //   This is not needed as DOMArrayBuffer::Create(), which is used in
      //   CloneAsUint8Array(), is designed to crash if it cannot allocate the
      //   memory.

      //   c. Otherwise, set chunk2 to cloneResult.[[Value]].
      chunk[1] = NotShared<DOMUint8Array>(clone_result);
    }

    // 5. If canceled1 is false, perform !
    // ReadableByteStreamControllerEnqueue(branch1.[[controller]], chunk1).
    // 6. If canceled2 is false, perform !
    // ReadableByteStreamControllerEnqueue(branch2.[[controller]], chunk2).
    for (int branch = 0; branch < 2; ++branch) {
      if (!engine_->canceled_[branch]) {
        v8::TryCatch try_catch(isolate);
        ReadableByteStreamController::Enqueue(
            script_state, engine_->controller_[branch], chunk[branch],
            PassThroughException(isolate));
        if (try_catch.HasCaught()) {
          // Instead of returning a rejection, which is inconvenient here,
          // call ControllerError(). The only difference this makes is that it
          // happens synchronously, but that should not be observable.
          ReadableByteStreamController::Error(script_state,
                                              engine_->controller_[branch],
                                              try_catch.Exception());
          return;
        }
      }
    }

    // 7. Set reading to false.
    engine_->reading_ = false;

    // 8. If readAgainForBranch1 is true, perform pull1Algorithm.
    if (engine_->read_again_for_branch_[0]) {
      auto* pull_algorithm = MakeGarbageCollected<PullAlgorithm>(engine_, 0);
      pull_algorithm->Run(script_state, 0, nullptr);
      // 9. Otherwise, if readAgainForBranch2 is true, perform pull2Algorithm.
    } else if (engine_->read_again_for_branch_[1]) {
      auto* pull_algorithm = MakeGarbageCollected<PullAlgorithm>(engine_, 1);
      pull_algorithm->Run(script_state, 0, nullptr);
    }
  }

  Member<ByteStreamTeeEngine> engine_;
};

class ByteStreamTeeEngine::ByteTeeReadIntoRequest final
    : public ReadIntoRequest {
 public:
  explicit ByteTeeReadIntoRequest(ByteStreamTeeEngine* engine,
                                  ReadableStream* byob_branch,
                                  ReadableStream* other_branch,
                                  bool for_branch_2)
      : engine_(engine),
        byob_branch_(byob_branch),
        other_branch_(other_branch),
        for_branch_2_(for_branch_2) {}

  void ChunkSteps(ScriptState* script_state,
                  DOMArrayBufferView* chunk,
                  ExceptionState&) const override {
    scoped_refptr<scheduler::EventLoop> event_loop =
        ExecutionContext::From(script_state)->GetAgent()->event_loop();
    event_loop->EnqueueMicrotask(WTF::BindOnce(
        &ByteTeeReadIntoRequest::ChunkStepsBody, WrapPersistent(this),
        WrapPersistent(script_state), WrapPersistent(chunk)));
  }

  void CloseSteps(ScriptState* script_state,
                  DOMArrayBufferView* chunk) const override {
    // 1. Set reading to false.
    engine_->reading_ = false;
    // 2. Let byobCanceled be canceled2 if forBranch2 is true, and canceled1
    //    otherwise.
    auto byob_canceled =
        for_branch_2_ ? engine_->canceled_[1] : engine_->canceled_[0];
    // 3. Let otherCanceled be canceled2 if forBranch2 is false, and canceled1
    //    otherwise.
    auto other_canceled =
        !for_branch_2_ ? engine_->canceled_[1] : engine_->canceled_[0];
    // 4. If byobCanceled is false, perform !
    //    ReadableByteStreamControllerClose(byobBranch.[[controller]]).
    if (!byob_canceled) {
      ReadableStreamController* controller =
          byob_branch_->readable_stream_controller_;
      ReadableByteStreamController* byte_controller =
          To<ReadableByteStreamController>(controller);
      byte_controller->Close(script_state, byte_controller);
    }
    // 5. If otherCanceled is false, perform !
    //    ReadableByteStreamControllerClose(otherBranch.[[controller]]).
    if (!other_canceled) {
      ReadableStreamController* controller =
          other_branch_->readable_stream_controller_;
      ReadableByteStreamController* byte_controller =
          To<ReadableByteStreamController>(controller);
      byte_controller->Close(script_state, byte_controller);
    }
    // 6. If chunk is not undefined,
    if (chunk) {
      //   a. Assert: chunk.[[ByteLength]] is 0.
      DCHECK_EQ(chunk->byteLength(), 0u);
      //   b. If byobCanceled is false, perform !
      //      ReadableByteStreamControllerRespondWithNewView(byobBranch.[[controller]],
      //      chunk).
      ExceptionState exception_state(script_state->GetIsolate());
      if (!byob_canceled) {
        ReadableStreamController* controller =
            byob_branch_->readable_stream_controller_;
        ReadableByteStreamController::RespondWithNewView(
            script_state, To<ReadableByteStreamController>(controller),
            NotShared<DOMArrayBufferView>(chunk), exception_state);
        DCHECK(!exception_state.HadException());
      }
      //   c. If otherCanceled is false and
      //      otherBranch.[[controller]].[[pendingPullIntos]] is not empty,
      //      perform !
      //      ReadableByteStreamControllerRespond(otherBranch.[[controller]],
      //      0).
      ReadableStreamController* controller =
          other_branch_->readable_stream_controller_;
      if (!other_canceled && !To<ReadableByteStreamController>(controller)
                                  ->pending_pull_intos_.empty()) {
        ReadableByteStreamController::Respond(
            script_state, To<ReadableByteStreamController>(controller), 0,
            exception_state);
        DCHECK(!exception_state.HadException());
      }
    }
    // 7. If byobCanceled is false or otherCanceled is false, resolve
    //    cancelPromise with undefined.
    if (!byob_canceled || !other_canceled) {
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
    visitor->Trace(byob_branch_);
    visitor->Trace(other_branch_);
    ReadIntoRequest::Trace(visitor);
  }

 private:
  void ChunkStepsBody(ScriptState* script_state,
                      DOMArrayBufferView* chunk) const {
    // This is called in a microtask, the ScriptState needs to be put back
    // in scope.
    ScriptState::Scope scope(script_state);
    // 1. Set readAgainForBranch1 to false.
    engine_->read_again_for_branch_[0] = false;
    // 2. Set readAgainForBranch2 to false.
    engine_->read_again_for_branch_[1] = false;
    // 3. Let byobCanceled be canceled2 if forBranch2 is true, and canceled1
    // otherwise.
    auto byob_canceled =
        for_branch_2_ ? engine_->canceled_[1] : engine_->canceled_[0];
    // 4. Let otherCanceled be canceled2 if forBranch2 is false, and canceled1
    // otherwise.
    auto other_canceled =
        !for_branch_2_ ? engine_->canceled_[1] : engine_->canceled_[0];
    // 5. If otherCanceled is false,
    ExceptionState exception_state(script_state->GetIsolate());
    if (!other_canceled) {
      //   a. Let cloneResult be CloneAsUint8Array(chunk).
      auto* clone_result = engine_->CloneAsUint8Array(chunk);
      //   b. If cloneResult is an abrupt completion,
      //     i. Perform !
      //     ReadableByteStreamControllerError(byobBranch.[[controller]],
      //     cloneResult.[[Value]]).
      //     ii. Perform !
      //     ReadableByteStreamControllerError(otherBranch.[[controller]],
      //     cloneResult.[[Value]]).
      //     iii. Resolve cancelPromise with !
      //     ReadableStreamCancel(stream, cloneResult.[[Value]]).
      //     iv. Return.
      //   This is not needed as DOMArrayBuffer::Create(), which is used in
      //   CloneAsUint8Array(), is designed to crash if it cannot allocate the
      //   memory.

      //   c. Otherwise, let clonedChunk be cloneResult.[[Value]].
      NotShared<DOMArrayBufferView> cloned_chunk =
          NotShared<DOMArrayBufferView>(clone_result);

      //   d. If byobCanceled is false, perform !
      //   ReadableByteStreamControllerRespondWithNewView(byobBranch.[[controller]],
      //   chunk).
      if (!byob_canceled) {
        ReadableStreamController* byob_controller =
            byob_branch_->readable_stream_controller_;
        ReadableByteStreamController::RespondWithNewView(
            script_state, To<ReadableByteStreamController>(byob_controller),
            NotShared<DOMArrayBufferView>(chunk), exception_state);
        DCHECK(!exception_state.HadException());
      }
      //   e. Perform !
      //   ReadableByteStreamControllerEnqueue(otherBranch.[[controller]],
      //   clonedChunk).
      ReadableStreamController* other_controller =
          other_branch_->readable_stream_controller_;
      ReadableByteStreamController::Enqueue(
          script_state, To<ReadableByteStreamController>(other_controller),
          cloned_chunk, exception_state);
      DCHECK(!exception_state.HadException());
      // 6. Otherwise, if byobCanceled is false, perform !
      // ReadableByteStreamControllerRespondWithNewView(byobBranch.[[controller]],
      // chunk).
    } else if (!byob_canceled) {
      ReadableStreamController* controller =
          byob_branch_->readable_stream_controller_;
      ReadableByteStreamController::RespondWithNewView(
          script_state, To<ReadableByteStreamController>(controller),
          NotShared<DOMArrayBufferView>(chunk), exception_state);
      DCHECK(!exception_state.HadException());
    }
    // 7. Set reading to false.
    engine_->reading_ = false;
    // 8. If readAgainForBranch1 is true, perform pull1Algorithm.
    if (engine_->read_again_for_branch_[0]) {
      auto* pull_algorithm = MakeGarbageCollected<PullAlgorithm>(engine_, 0);
      pull_algorithm->Run(script_state, 0, nullptr);
      // 9. Otherwise, if readAgainForBranch2 is true, perform pull2Algorithm.
    } else if (engine_->read_again_for_branch_[1]) {
      auto* pull_algorithm = MakeGarbageCollected<PullAlgorithm>(engine_, 1);
      pull_algorithm->Run(script_state, 0, nullptr);
    }
  }

  Member<ByteStreamTeeEngine> engine_;
  Member<ReadableStream> byob_branch_;
  Member<ReadableStream> other_branch_;
  bool for_branch_2_;
};

void ByteStreamTeeEngine::ForwardReaderError(
    ScriptState* script_state,
    ReadableStreamGenericReader* this_reader) {
  // 14. Let forwardReaderError be the following steps, taking a thisReader
  // argument:
  class RejectFunction final : public ThenCallable<IDLAny, RejectFunction> {
   public:
    explicit RejectFunction(ByteStreamTeeEngine* engine,
                            ReadableStreamGenericReader* reader)
        : engine_(engine), reader_(reader) {}

    void React(ScriptState* script_state, ScriptValue r) {
      //   a. Upon rejection of thisReader.[[closedPromise]] with reason r,
      //     i. If thisReader is not reader, return.
      if (engine_->reader_ != reader_) {
        return;
      }
      //     ii. Perform !
      //     ReadableByteStreamControllerError(branch1.[[controller]], r).
      ReadableByteStreamController::Error(script_state, engine_->controller_[0],
                                          r.V8Value());
      //     iii. Perform !
      //     ReadableByteStreamControllerError(branch2.[[controller]], r).
      ReadableByteStreamController::Error(script_state, engine_->controller_[1],
                                          r.V8Value());
      //     iv. If canceled1 is false or canceled2 is false, resolve
      //     cancelPromise with undefined.
      if (!engine_->canceled_[0] || !engine_->canceled_[1]) {
        engine_->cancel_promise_->Resolve();
      }
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(engine_);
      visitor->Trace(reader_);
      ThenCallable<IDLAny, RejectFunction>::Trace(visitor);
    }

   private:
    Member<ByteStreamTeeEngine> engine_;
    Member<ReadableStreamGenericReader> reader_;
  };

  this_reader->closed(script_state)
      .Catch(script_state,
             MakeGarbageCollected<RejectFunction>(this, this_reader));
}

void ByteStreamTeeEngine::PullWithDefaultReader(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  // 15. Let pullWithDefaultReader be the following steps:
  //   a. If reader implements ReadableStreamBYOBReader,
  if (reader_->IsBYOBReader()) {
    //     i. Assert: reader.[[readIntoRequests]] is empty.
    ReadableStreamGenericReader* reader = reader_;
    ReadableStreamBYOBReader* byob_reader =
        To<ReadableStreamBYOBReader>(reader);
    DCHECK(byob_reader->read_into_requests_.empty());
    //     ii. Perform ! ReadableStreamBYOBReaderRelease(reader).
    ReadableStreamBYOBReader::Release(script_state, byob_reader);
    //     iii. Set reader to ! AcquireReadableStreamDefaultReader(stream).
    reader_ = ReadableStream::AcquireDefaultReader(script_state, stream_,
                                                   exception_state);
    DCHECK(!exception_state.HadException());
    //     iv. Perform forwardReaderError, given reader.
    ForwardReaderError(script_state, reader_);
  }
  //   b. Let readRequest be a read request with the following items:
  auto* read_request = MakeGarbageCollected<ByteTeeReadRequest>(this);
  //   c. Perform ! ReadableStreamDefaultReaderRead(reader, readRequest).
  ReadableStreamGenericReader* reader = reader_;
  ReadableStreamDefaultReader::Read(script_state,
                                    To<ReadableStreamDefaultReader>(reader),
                                    read_request, exception_state);
}

void ByteStreamTeeEngine::PullWithBYOBReader(ScriptState* script_state,
                                             NotShared<DOMArrayBufferView> view,
                                             bool for_branch_2,
                                             ExceptionState& exception_state) {
  // 16. Let pullWithBYOBReader be the following steps, given view and
  // forBranch2:
  //   a. If reader implements ReadableStreamDefaultReader,
  if (reader_->IsDefaultReader()) {
    //     i. Assert: reader.[[readRequests]] is empty.
    ReadableStreamGenericReader* reader = reader_;
    ReadableStreamDefaultReader* default_reader =
        To<ReadableStreamDefaultReader>(reader);
    DCHECK(default_reader->read_requests_.empty());
    //     ii. Perform ! ReadableStreamDefaultReaderRelease(reader).
    ReadableStreamDefaultReader::Release(script_state, default_reader);
    //     iii. Set reader to ! AcquireReadableStreamBYOBReader(stream).
    reader_ = ReadableStream::AcquireBYOBReader(script_state, stream_,
                                                exception_state);
    DCHECK(!exception_state.HadException());
    //     iv. Perform forwardReaderError, given reader.
    ForwardReaderError(script_state, reader_);
  }
  //   b. Let byobBranch be branch2 if forBranch2 is true, and branch1
  //   otherwise.
  ReadableStream* byob_branch = for_branch_2 ? branch_[1] : branch_[0];
  //   c. Let otherBranch be branch2 if forBranch2 is false, and branch1
  //   otherwise.
  ReadableStream* other_branch = !for_branch_2 ? branch_[1] : branch_[0];
  //   d. Let readIntoRequest be a read-into request with the following items:
  auto* read_into_request = MakeGarbageCollected<ByteTeeReadIntoRequest>(
      this, byob_branch, other_branch, for_branch_2);
  //   e. Perform ! ReadableStreamBYOBReaderRead(reader, view,
  //   readIntoRequest).
  ReadableStreamGenericReader* reader = reader_;
  ReadableStreamBYOBReader::Read(script_state,
                                 To<ReadableStreamBYOBReader>(reader), view,
                                 read_into_request, exception_state);
  DCHECK(!exception_state.HadException());
}

DOMUint8Array* ByteStreamTeeEngine::CloneAsUint8Array(
    DOMArrayBufferView* chunk) {
  auto* cloned_buffer = DOMArrayBuffer::Create(chunk->ByteSpan());
  return DOMUint8Array::Create(cloned_buffer, 0, chunk->byteLength());
}

void ByteStreamTeeEngine::Start(ScriptState* script_state,
                                ReadableStream* stream,
                                ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#abstract-opdef-readablebytestreamtee
  // 1. Assert: stream implements ReadableStream.
  DCHECK(stream);

  stream_ = stream;

  // 2. Assert: stream.[[controller]] implements ReadableByteStreamController.
  DCHECK(stream->readable_stream_controller_->IsByteStreamController());

  // 3. Let reader be ? AcquireReadableStreamDefaultReader(stream).
  reader_ = ReadableStream::AcquireDefaultReader(script_state, stream,
                                                 exception_state);

  // 4. Let reading be false.
  DCHECK(!reading_);

  // 5. Let readAgainForBranch1 be false.
  DCHECK(!read_again_for_branch_[0]);

  // 6. Let readAgainForBranch2 be false.
  DCHECK(!read_again_for_branch_[1]);

  // 7. Let canceled1 be false.
  DCHECK(!canceled_[0]);

  // 8. Let canceled2 be false.
  DCHECK(!canceled_[1]);

  // 9. Let reason1 be undefined.
  DCHECK(reason_[0].IsEmpty());

  // 10. Let reason2 be undefined.
  DCHECK(reason_[1].IsEmpty());

  // 11. Let branch1 be undefined.
  DCHECK(!branch_[0]);

  // 12. Let branch2 be undefined.
  DCHECK(!branch_[1]);

  // 13. Let cancelPromise be a new promise.
  cancel_promise_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);

  // 17. Let pull1Algorithm be the following steps:
  // (See PullAlgorithm::Run()).
  auto* pull1_algorithm = MakeGarbageCollected<PullAlgorithm>(this, 0);

  // 18. Let pull2Algorithm be the following steps:
  // (both algorithms share a single implementation).
  auto* pull2_algorithm = MakeGarbageCollected<PullAlgorithm>(this, 1);

  // 19. Let cancel1Algorithm be the following steps, taking a reason argument:
  // (See CancelAlgorithm::Run()).
  auto* cancel1_algorithm = MakeGarbageCollected<CancelAlgorithm>(this, 0);

  // 20. Let cancel2Algorithm be the following steps, taking a reason argument:
  // (both algorithms share a single implementation).
  auto* cancel2_algorithm = MakeGarbageCollected<CancelAlgorithm>(this, 1);

  // 21. Let startAlgorithm be an algorithm that returns undefined.
  auto* start_algorithm = CreateTrivialStartAlgorithm();

  // 22. Set branch1 to ! CreateReadableByteStream(startAlgorithm,
  // pull1Algorithm, cancel1Algorithm).
  branch_[0] = ReadableStream::CreateByteStream(
      script_state, start_algorithm, pull1_algorithm, cancel1_algorithm,
      exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // 23. Set branch2 to ! CreateReadableByteStream(startAlgorithm,
  // pull2Algorithm, cancel2Algorithm).
  branch_[1] = ReadableStream::CreateByteStream(
      script_state, start_algorithm, pull2_algorithm, cancel2_algorithm,
      exception_state);
  if (exception_state.HadException()) {
    return;
  }

  for (int branch = 0; branch < 2; ++branch) {
    ReadableStreamController* controller =
        branch_[branch]->readable_stream_controller_;
    // We just created the branches above. It is obvious that they are byte
    // stream controllers.
    controller_[branch] = To<ReadableByteStreamController>(controller);
  }

  // 24. Perform forwardReaderError, given reader.
  ForwardReaderError(script_state, reader_);

  // Step 25. Return « branch1, branch2 ».
  // is performed by the caller.
}

}  // namespace blink

"""

```