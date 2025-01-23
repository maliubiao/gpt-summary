Response:
Let's break down the thought process for analyzing the `writable_stream_default_writer.cc` file.

1. **Understand the Goal:** The request asks for the functionalities of this specific Chromium Blink engine file, its relationship with web technologies (JavaScript, HTML, CSS), examples of logical reasoning, common usage errors, and debugging steps.

2. **Initial Scan and Identification of Key Entities:**  I first scanned the code for keywords and familiar patterns. I immediately recognized:
    * `#include` directives:  These point to dependencies and suggest the file's context. Seeing `writable_stream.h`, `writable_stream_default_controller.h`, `script_promise.h`, and binding-related headers (`v8_binding.h`, `script_state.h`) strongly indicates this file is about implementing the "Writable Streams" API in the browser.
    * Class name: `WritableStreamDefaultWriter`. The "Writer" part is a crucial clue. Streams have readers and writers. The "Default" suggests this is the standard way to write to a writable stream.
    * Methods like `write`, `abort`, `close`, `releaseLock`, `desiredSize`, `closed`, `ready`. These directly correspond to methods in the Writable Streams API in JavaScript.
    * `ScriptPromise` usage: This indicates asynchronous operations and integration with JavaScript promises.
    * `ExceptionState`: This signals error handling and the possibility of throwing JavaScript exceptions.
    *  `owner_writable_stream_`: A member variable holding a pointer to the associated `WritableStream`.

3. **Core Functionality Extraction:**  Based on the class name and methods, the primary function is clearly managing the writing end of a Writable Stream. I mentally categorized the methods:
    * **Lifecycle Management:** `Create`, destructor, `releaseLock`.
    * **Control Operations:** `abort`, `close`.
    * **Data Writing:** `write`.
    * **State Observation:** `desiredSize`, `closed`, `ready`.
    * **Internal Helpers:**  Methods with names like `EnsureReadyPromiseRejected`, `EnsureClosedPromiseRejected`, `CloseWithErrorPropagation`, `Write` (the internal implementation), `Abort`, `Close`, `GetDesiredSizeInternal`, `GetDesiredSize` (the public interface).

4. **Mapping to JavaScript/Web Standards:**  The method names strongly suggest a direct mapping to the JavaScript Writable Streams API. I made the connection:
    * `WritableStreamDefaultWriter` <-> The object returned by `writableStream.getWriter()`.
    * `write()` <-> `writer.write(chunk)`
    * `abort()` <-> `writer.abort(reason)`
    * `close()` <-> `writer.close()`
    * `releaseLock()` <-> `writer.releaseLock()`
    * `desiredSize` (property) <-> `writer.desiredSize`
    * `closed` (property, returns a promise) <-> `writer.closed`
    * `ready` (property, returns a promise) <-> `writer.ready`

5. **Explaining the Relationship with HTML/CSS:**  While the core functionality is JavaScript-driven, I considered how Writable Streams are *used* in the web context. The key connection is with web APIs that generate or consume streams of data:
    * **`fetch()` API (request body):**  A `WritableStream` can be used as the `body` of a `fetch()` request.
    * **`CompressionStream`, `DecompressionStream`:** These APIs operate on streams. The output of a compression stream could be piped to a `WritableStream`.
    * **`FileSystemFileHandle.createWritable()`:**  Writing to files in the browser involves `WritableStream`.
    * **Custom JavaScript:**  Developers can create their own logic to process data and write it to a `WritableStream`.

6. **Logical Reasoning (Input/Output):**  For methods like `write`, `abort`, and `close`, I considered simple scenarios:
    * **`write(data)`:**  Input: some data. Output: a promise that resolves when the write succeeds (or rejects if it fails).
    * **`abort(reason)`:** Input: a reason for aborting. Output: a promise that resolves when the abort is complete. The stream transitions to an error state.
    * **`close()`:** Input: none. Output: a promise that resolves when the stream is closed. The stream transitions to a closed state.

7. **Common Usage Errors:** I thought about typical mistakes developers might make when working with Writable Streams:
    * **Writing to a closed or errored stream:** This is a common source of errors.
    * **Calling `getWriter()` multiple times on the same stream:** This locks the stream, and subsequent calls will throw errors.
    * **Not handling promise rejections:** Forgetting to catch errors from `write`, `abort`, or `close`.
    * **Releasing the lock prematurely:**  Releasing the writer and then trying to use it.

8. **Debugging Steps (User Actions):** I traced a potential user interaction leading to this code:
    1. **User action triggers JavaScript:**  A button click, form submission, or some other event.
    2. **JavaScript creates a WritableStream:**  `const writableStream = new WritableStream({...});`
    3. **JavaScript gets a writer:** `const writer = writableStream.getWriter();`  This is where `WritableStreamDefaultWriter::Create` is likely called.
    4. **JavaScript performs operations:** `writer.write(...)`, `writer.close()`, `writer.abort()`. These call the corresponding methods in the C++ file.
    5. **Errors occur:** If something goes wrong in the stream's underlying processing, the error handling logic in this file will be triggered, and JavaScript promises will be rejected. A developer debugging might set breakpoints in this C++ code to understand the root cause.

9. **Refinement and Structuring:** I organized the information into logical sections (Functionalities, Relationship with Web Technologies, Logical Reasoning, Common Errors, Debugging) for clarity and readability. I used bullet points and examples to make the explanation more concrete. I also ensured I addressed each part of the original request.

10. **Review:** I reread my explanation and the original code to double-check for accuracy and completeness. I made sure the examples were relevant and the explanations were easy to understand. For instance, initially, I might have only focused on the JavaScript API but then realized the importance of explaining *how* those APIs are connected to browser features like `fetch` and file system access.
This C++ source file, `writable_stream_default_writer.cc`, is a core component of the Blink rendering engine, specifically responsible for implementing the **default writer** for a WritableStream, as defined in the WHATWG Streams Standard.

Let's break down its functionalities:

**Core Functionalities:**

1. **Manages the Writing End of a Writable Stream:** This file defines the `WritableStreamDefaultWriter` class, which represents the object obtained when you call `writableStream.getWriter()` in JavaScript. It provides methods to interact with the underlying writable stream.

2. **Provides Methods for Writing Data:** The `write()` method allows writing data (chunks) to the associated writable stream. This involves interacting with the stream's controller to enqueue the data.

3. **Handles Stream Lifecycle Operations:**
   - `close()`:  Initiates the process of closing the writable stream.
   - `abort()`:  Immediately aborts the writable stream, potentially with a reason.
   - `releaseLock()`: Releases the lock on the writable stream held by this writer, making it available for other writers (though usually a stream has only one writer).

4. **Monitors Stream State:**
   - `desiredSize()`: Returns the desired size of the stream's internal queue, indicating backpressure. A negative value suggests the queue is under pressure (full), zero means it's at capacity, and positive means there's space.
   - `closed()`: Returns a Promise that resolves when the stream is closed or rejects if the stream errors.
   - `ready()`: Returns a Promise that resolves when the stream is ready for more data to be written (i.e., not experiencing backpressure) or rejects if the stream errors.

5. **Manages Promises Associated with Stream Operations:**  The writer maintains promises (`closed_resolver_`, `ready_resolver_`) that reflect the state of the stream and its readiness for writing. These promises are exposed to JavaScript.

6. **Implements Internal Logic for Stream Management:**  It includes helper functions like `EnsureReadyPromiseRejected`, `EnsureClosedPromiseRejected`, and `CloseWithErrorPropagation` to manage the promises and handle error scenarios.

**Relationship with JavaScript, HTML, and CSS:**

This file is directly related to **JavaScript**. The `WritableStream` API is a JavaScript API, and this C++ code is the underlying implementation within the Blink engine.

* **JavaScript Interaction:** When JavaScript code uses the `WritableStream` API, it interacts with the functionality implemented in this C++ file. For example:
    ```javascript
    const writableStream = new WritableStream({
      write(chunk) {
        console.log('Writing chunk:', chunk);
        // ... potentially asynchronous operation ...
        return new Promise(resolve => setTimeout(resolve, 1000));
      },
      close() {
        console.log('Stream closed');
      },
      abort(reason) {
        console.error('Stream aborted due to:', reason);
      }
    });

    const writer = writableStream.getWriter();
    writer.write('Hello');
    writer.write('World');
    writer.close();
    ```
    - `new WritableStream(...)` creates a `WritableStream` object.
    - `writableStream.getWriter()` returns an instance of `WritableStreamDefaultWriter` (implemented here).
    - `writer.write('Hello')` calls the `WritableStreamDefaultWriter::write` method in this C++ file.
    - `writer.close()` calls the `WritableStreamDefaultWriter::close` method.

* **HTML:** While not directly related to the structure of HTML, Writable Streams are often used in conjunction with HTML elements for tasks like:
    - **Downloading files:**  A `WritableStream` can be used to receive data from a server and pipe it to the user's file system (via the File System Access API).
    - **Streaming data to a `<video>` or `<audio>` element:**  Although more complex, streams could theoretically be used to provide media data.
    - **Form submissions:**  The body of a `fetch()` request can be a `ReadableStream` or, in some scenarios, a `WritableStream` could be used on the server-side.

* **CSS:** CSS has no direct relationship with the `WritableStream` API. CSS is for styling, while streams deal with data flow.

**Logical Reasoning (Hypothetical Input and Output):**

Let's consider the `write()` method:

**Assumption:** The writable stream is in a "writable" state and not experiencing backpressure.

**Input (from JavaScript):**
- `script_state`: Represents the JavaScript execution context.
- `chunk`: A JavaScript value (can be a string, ArrayBuffer, etc.) representing the data to be written.
- `exception_state`:  For reporting JavaScript exceptions.

**Processing (simplified):**
1. Checks if the writer is still associated with a valid stream.
2. Checks the stream's current state.
3. If the stream is writable, it gets the stream's controller.
4. It calculates the size of the `chunk`.
5. It adds a write request to the stream's internal queue.
6. It calls the controller's `Write` method to enqueue the `chunk`.
7. It returns a JavaScript Promise that will eventually resolve or reject based on the success of the write operation.

**Output (to JavaScript):**
- A JavaScript `Promise`. This promise will:
    - **Resolve** when the chunk has been successfully processed by the underlying sink of the writable stream.
    - **Reject** if there's an error during the write process or if the stream is no longer writable (e.g., it's been closed or aborted).

**User or Programming Common Usage Errors:**

1. **Writing to a Closed or Errored Stream:**
   ```javascript
   const writer = writableStream.getWriter();
   writableStream.close(); // Or an error occurs
   writer.write('Trying to write after close'); // This will likely cause an error.
   ```
   **Explanation:**  Once a stream is closed or has errored, further attempts to write to it will result in a rejected promise with a `TypeError`.

2. **Calling `getWriter()` Multiple Times on the Same Stream:**
   ```javascript
   const writer1 = writableStream.getWriter();
   const writer2 = writableStream.getWriter(); // This will throw an error.
   ```
   **Explanation:** A default writable stream can only have one active writer at a time. Trying to get another writer without releasing the existing one will throw a `TypeError`.

3. **Not Handling Promise Rejections:**
   ```javascript
   writer.write('Some data').catch(error => {
     console.error('Write failed:', error);
   });
   ```
   **Explanation:**  If the `write()` operation fails (e.g., due to backpressure or stream errors), the returned promise will be rejected. If this rejection is not handled with a `.catch()`, it can lead to unhandled promise rejections, which are generally undesirable.

4. **Releasing the Lock and Then Trying to Use the Writer:**
   ```javascript
   const writer = writableStream.getWriter();
   writer.releaseLock();
   writer.write('Trying to write after releasing'); // This will cause an error.
   ```
   **Explanation:** After `releaseLock()`, the writer is no longer associated with the stream, and attempting to use it will result in a `TypeError`.

**User Operation Steps to Reach This Code (Debugging Clues):**

Let's imagine a scenario where a user is downloading a file in their browser:

1. **User Initiates Download:** The user clicks a link or a button that triggers a download.
2. **JavaScript Fetches Data:** JavaScript code uses the `fetch()` API to request the file content from a server.
3. **Accessing the Response Body as a ReadableStream:** The `response.body` of the `fetch()` API is a `ReadableStream`.
4. **Creating a WritableStream for Saving:** JavaScript might create a `WritableStream` using the File System Access API to write the downloaded data to a file on the user's computer.
   ```javascript
   const fileHandle = await window.showSaveFilePicker();
   const writableStream = await fileHandle.createWritable();
   const writer = writableStream.getWriter();
   ```
5. **Piping the ReadableStream to the WritableStream:** The data from the `response.body` (ReadableStream) is read in chunks and written to the `writableStream` using a pipe:
   ```javascript
   const reader = response.body.getReader();
   let readResult;
   while (!(readResult = await reader.read()).done) {
     await writer.write(readResult.value); // <--- This is where WritableStreamDefaultWriter::write is called
   }
   await writer.close();
   ```

**Debugging a Problem in this Scenario:**

If a developer is debugging an issue where the download fails or the file is corrupted, they might set breakpoints or log statements in `writable_stream_default_writer.cc` to investigate:

- **Breakpoint in `WritableStreamDefaultWriter::write`:** To see if data is being written correctly, what the chunks contain, and if any errors occur during the write.
- **Breakpoint in `WritableStreamDefaultWriter::close` or `abort`:** To understand how the stream is being terminated.
- **Logging the stream's state (`owner_writable_stream_->GetState()`)** within the writer's methods to track its lifecycle.
- **Examining the `exception_state`** to see if any JavaScript exceptions are being thrown from the C++ code.

By tracing the execution flow through this C++ file, developers can gain insights into the low-level operations of the WritableStream and identify the root cause of issues.

### 提示词
```
这是目录为blink/renderer/core/streams/writable_stream_default_writer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/streams/writable_stream_default_writer.h"

#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/core/streams/miscellaneous_operations.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_controller.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

String CreateWriterLockReleasedMessage(const char* verbed) {
  return String::Format(
      "This writable stream writer has been released and cannot be %s", verbed);
}

v8::Local<v8::Value> CreateWriterLockReleasedException(v8::Isolate* isolate,
                                                       const char* verbed) {
  return v8::Exception::TypeError(
      V8String(isolate, CreateWriterLockReleasedMessage(verbed)));
}

}  // namespace

WritableStreamDefaultWriter* WritableStreamDefaultWriter::Create(
    ScriptState* script_state,
    WritableStream* stream,
    ExceptionState& exception_state) {
  auto* writer = MakeGarbageCollected<WritableStreamDefaultWriter>(
      script_state, static_cast<WritableStream*>(stream), exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }
  return writer;
}

// TODO(ricea): Does using the ScriptState supplied by IDL result in promises
// being created with the correct global?
WritableStreamDefaultWriter::WritableStreamDefaultWriter(
    ScriptState* script_state,
    WritableStream* stream,
    ExceptionState& exception_state)
    //  3. Set this.[[ownerWritableStream]] to stream.
    : owner_writable_stream_(stream),
      closed_resolver_(
          MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
              script_state)),
      ready_resolver_(MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
          script_state)) {
  // https://streams.spec.whatwg.org/#default-writer-constructor 2. If !
  //  IsWritableStreamLocked(stream) is true, throw a TypeError exception.
  if (WritableStream::IsLocked(stream)) {
    exception_state.ThrowTypeError(
        "Cannot create writer when WritableStream is locked");
    return;
  }
  //  4. Set stream.[[writer]] to this.
  stream->SetWriter(this);

  //  5. Let state be stream.[[state]].
  const auto state = stream->GetState();
  auto* isolate = script_state->GetIsolate();

  switch (state) {
    //  6. If state is "writable",
    case WritableStream::kWritable: {
      //      a. If ! WritableStreamCloseQueuedOrInFlight(stream) is false and
      //         stream.[[backpressure]] is true, set this.[[readyPromise]] to
      //         a new promise.
      // The step above is done in the initializer list.

      if (WritableStream::CloseQueuedOrInFlight(stream) ||
          !stream->HasBackpressure()) {
        //      b. Otherwise, set this.[[readyPromise]] to a promise resolved
        //         with undefined.
        ready_resolver_->Resolve();
      }
      //      c. Set this.[[closedPromise]] to a new promise.
      break;
    }

    //  7. Otherwise, if state is "erroring",
    case WritableStream::kErroring: {
      //      a. Set this.[[readyPromise]] to a promise rejected with
      //         stream.[[storedError]].
      ready_resolver_->Promise().MarkAsSilent();
      ready_resolver_->Reject(stream->GetStoredError(isolate));

      //      b. Set this.[[readyPromise]].[[PromiseIsHandled]] to true.
      ready_resolver_->Promise().MarkAsHandled();

      //      c. Set this.[[closedPromise]] to a new promise.
      break;
    }

    //  8. Otherwise, if state is "closed",
    case WritableStream::kClosed: {
      //      a. Set this.[[readyPromise]] to a promise resolved with undefined.
      ready_resolver_->Resolve();

      //      b. Set this.[[closedPromise]] to a promise resolved with
      //         undefined.
      closed_resolver_->Resolve();
      break;
    }

    //  9. Otherwise,
    case WritableStream::kErrored: {
      //      a. Assert: state is "errored".
      // Check omitted as it is not meaningful.

      //      b. Let storedError be stream.[[storedError]].
      const auto stored_error =
          ScriptValue(isolate, stream->GetStoredError(isolate));

      //      c. Set this.[[readyPromise]] to a promise rejected with
      //         storedError.
      ready_resolver_->Promise().MarkAsSilent();
      ready_resolver_->Reject(stored_error);

      //      d. Set this.[[readyPromise]].[[PromiseIsHandled]] to true.
      ready_resolver_->Promise().MarkAsHandled();

      //      e. Set this.[[closedPromise]] to a promise rejected with
      //         storedError.
      closed_resolver_->Promise().MarkAsSilent();
      closed_resolver_->Reject(stored_error);

      //      f. Set this.[[closedPromise]].[[PromiseIsHandled]] to true.
      closed_resolver_->Promise().MarkAsHandled();
      break;
    }
  }
}

WritableStreamDefaultWriter::~WritableStreamDefaultWriter() = default;

ScriptPromise<IDLUndefined> WritableStreamDefaultWriter::closed(
    ScriptState* script_state) const {
  // https://streams.spec.whatwg.org/#default-writer-closed
  //  2. Return this.[[closedPromise]].
  return closed_resolver_->Promise();
}

ScriptValue WritableStreamDefaultWriter::desiredSize(
    ScriptState* script_state,
    ExceptionState& exception_state) const {
  auto* isolate = script_state->GetIsolate();
  // https://streams.spec.whatwg.org/#default-writer-desired-size
  //  2. If this.[[ownerWritableStream]] is undefined, throw a TypeError
  //     exception.
  if (!owner_writable_stream_) {
    exception_state.ThrowTypeError(
        CreateWriterLockReleasedMessage("used to get the desiredSize"));
    return ScriptValue();
  }

  //  3. Return ! WritableStreamDefaultWriterGetDesiredSize(this).
  return ScriptValue(isolate, GetDesiredSize(isolate, this));
}

ScriptPromise<IDLUndefined> WritableStreamDefaultWriter::ready(
    ScriptState* script_state) const {
  // https://streams.spec.whatwg.org/#default-writer-ready
  //  2. Return this.[[readyPromise]].
  return ready_resolver_->Promise();
}

ScriptPromise<IDLUndefined> WritableStreamDefaultWriter::abort(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  return abort(script_state,
               ScriptValue(script_state->GetIsolate(),
                           v8::Undefined(script_state->GetIsolate())),
               exception_state);
}

ScriptPromise<IDLUndefined> WritableStreamDefaultWriter::abort(
    ScriptState* script_state,
    ScriptValue reason,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#default-writer-abort
  //  2. If this.[[ownerWritableStream]] is undefined, return a promise rejected
  //     with a TypeError exception.
  if (!owner_writable_stream_) {
    exception_state.ThrowTypeError(CreateWriterLockReleasedMessage("aborted"));
    return EmptyPromise();
  }

  //  3. Return ! WritableStreamDefaultWriterAbort(this, reason).
  return Abort(script_state, this, reason.V8Value());
}

ScriptPromise<IDLUndefined> WritableStreamDefaultWriter::close(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#default-writer-close
  //  2. Let stream be this.[[ownerWritableStream]].
  WritableStream* stream = owner_writable_stream_;

  //  3. If stream is undefined, return a promise rejected with a TypeError
  //     exception.
  if (!stream) {
    exception_state.ThrowTypeError(CreateWriterLockReleasedMessage("closed"));
    return EmptyPromise();
  }

  //  4. If ! WritableStreamCloseQueuedOrInFlight(stream) is true, return a
  //      promise rejected with a TypeError exception.
  if (WritableStream::CloseQueuedOrInFlight(stream)) {
    exception_state.ThrowTypeError(
        "Cannot close a writable stream that has "
        "already been requested to be closed");
    return EmptyPromise();
  }

  //  5. Return ! WritableStreamDefaultWriterClose(this).
  return Close(script_state, this);
}

void WritableStreamDefaultWriter::releaseLock(ScriptState* script_state) {
  // https://streams.spec.whatwg.org/#default-writer-release-lock
  //  2. Let stream be this.[[ownerWritableStream]].
  WritableStream* stream = owner_writable_stream_;

  //  3. If stream is undefined, return.
  if (!stream) {
    return;
  }

  //  4. Assert: stream.[[writer]] is not undefined.
  DCHECK(stream->Writer());

  //  5. Perform ! WritableStreamDefaultWriterRelease(this).
  Release(script_state, this);
}

ScriptPromise<IDLUndefined> WritableStreamDefaultWriter::write(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  return write(script_state,
               ScriptValue(script_state->GetIsolate(),
                           v8::Undefined(script_state->GetIsolate())),
               exception_state);
}

ScriptPromise<IDLUndefined> WritableStreamDefaultWriter::write(
    ScriptState* script_state,
    ScriptValue chunk,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#default-writer-write
  //  2. If this.[[ownerWritableStream]] is undefined, return a promise rejected
  //     with a TypeError exception.
  if (!owner_writable_stream_) {
    exception_state.ThrowTypeError(
        CreateWriterLockReleasedMessage("written to"));
    return EmptyPromise();
  }

  if (!script_state->ContextIsValid()) {
    exception_state.ThrowTypeError("invalid realm");
    return EmptyPromise();
  }

  //  3. Return ! WritableStreamDefaultWriterWrite(this, chunk).
  return Write(script_state, this, chunk.V8Value(), exception_state);
}

void WritableStreamDefaultWriter::EnsureReadyPromiseRejected(
    ScriptState* script_state,
    WritableStreamDefaultWriter* writer,
    v8::Local<v8::Value> error) {
  if (!script_state->ContextIsValid()) {
    return;
  }
  // https://streams.spec.whatwg.org/#writable-stream-default-writer-ensure-ready-promise-rejected
  //  1. If writer.[[readyPromise]].[[PromiseState]] is "pending", reject
  //     writer.[[readyPromise]] with error.
  if (writer->ready_resolver_->Promise().V8Promise()->State() !=
      v8::Promise::kPending) {
    //  2. Otherwise, set writer.[[readyPromise]] to a promise rejected with
    //     error.
    writer->ready_resolver_ =
        MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  }
  writer->ready_resolver_->Promise().MarkAsSilent();
  writer->ready_resolver_->Reject(error);

  //  3. Set writer.[[readyPromise]].[[PromiseIsHandled]] to true.
  writer->ready_resolver_->Promise().MarkAsHandled();
}

ScriptPromise<IDLUndefined>
WritableStreamDefaultWriter::CloseWithErrorPropagation(
    ScriptState* script_state,
    WritableStreamDefaultWriter* writer) {
  // https://streams.spec.whatwg.org/#writable-stream-default-writer-close-with-error-propagation
  //  1. Let stream be writer.[[ownerWritableStream]].
  WritableStream* stream = writer->owner_writable_stream_;

  //  2. Assert: stream is not undefined.
  DCHECK(stream);

  //  3. Let state be stream.[[state]].
  const auto state = stream->GetState();

  //  4. If ! WritableStreamCloseQueuedOrInFlight(stream) is true or state is
  //     "closed", return a promise resolved with undefined.
  if (WritableStream::CloseQueuedOrInFlight(stream) ||
      state == WritableStream::kClosed) {
    return ToResolvedUndefinedPromise(script_state);
  }

  //  5. If state is "errored", return a promise rejected with
  //     stream.[[storedError]].
  if (state == WritableStream::kErrored) {
    return ScriptPromise<IDLUndefined>::Reject(
        script_state, stream->GetStoredError(script_state->GetIsolate()));
  }

  //  6. Assert: state is "writable" or "erroring".
  CHECK(state == WritableStream::kWritable ||
        state == WritableStream::kErroring);

  //  7. Return ! WritableStreamDefaultWriterClose(writer).
  return Close(script_state, writer);
}

void WritableStreamDefaultWriter::Release(ScriptState* script_state,
                                          WritableStreamDefaultWriter* writer) {
  // https://streams.spec.whatwg.org/#writable-stream-default-writer-release
  //  1. Let stream be writer.[[ownerWritableStream]].
  WritableStream* stream = writer->owner_writable_stream_;

  //  2. Assert: stream is not undefined.
  DCHECK(stream);

  //  3. Assert: stream.[[writer]] is writer.
  DCHECK_EQ(stream->Writer(), writer);

  //  4. Let releasedError be a new TypeError.
  const auto released_error = v8::Exception::TypeError(V8String(
      script_state->GetIsolate(),
      "This writable stream writer has been released and cannot be used to "
      "monitor the stream\'s state"));

  //  5. Perform ! WritableStreamDefaultWriterEnsureReadyPromiseRejected(writer,
  //     releasedError).
  EnsureReadyPromiseRejected(script_state, writer, released_error);

  //  6. Perform !
  //     WritableStreamDefaultWriterEnsureClosedPromiseRejected(writer,
  //     releasedError).
  EnsureClosedPromiseRejected(script_state, writer, released_error);

  //  7. Set stream.[[writer]] to undefined.
  stream->SetWriter(nullptr);

  //  8. Set writer.[[ownerWritableStream]] to undefined.
  writer->owner_writable_stream_ = nullptr;
}

ScriptPromise<IDLUndefined> WritableStreamDefaultWriter::Write(
    ScriptState* script_state,
    WritableStreamDefaultWriter* writer,
    v8::Local<v8::Value> chunk,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#writable-stream-default-writer-write
  //  1. Let stream be writer.[[ownerWritableStream]].
  WritableStream* stream = writer->owner_writable_stream_;

  //  2. Assert: stream is not undefined.
  DCHECK(stream);

  //  3. Let controller be stream.[[writableStreamController]].
  WritableStreamDefaultController* controller = stream->Controller();

  auto* isolate = script_state->GetIsolate();
  //  4. Let chunkSize be !
  //     WritableStreamDefaultControllerGetChunkSize(controller, chunk).
  double chunk_size = WritableStreamDefaultController::GetChunkSize(
      script_state, controller, chunk);

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);

  //  5. If stream is not equal to writer.[[ownerWritableStream]], return a
  //     promise rejected with a TypeError exception.
  if (stream != writer->owner_writable_stream_) {
    resolver->Reject(CreateWriterLockReleasedException(isolate, "written to"));
    return resolver->Promise();
  }

  //  6. Let state be stream.[[state]].
  const auto state = stream->GetState();

  //  7. If state is "errored", return a promise rejected with
  //     stream.[[storedError]].
  if (state == WritableStream::kErrored) {
    resolver->Reject(stream->GetStoredError(isolate));
    return resolver->Promise();
  }

  //  8. If ! WritableStreamCloseQueuedOrInFlight(stream) is true or state is
  //     "closed", return a promise rejected with a TypeError exception
  //     indicating that the stream is closing or closed.
  if (WritableStream::CloseQueuedOrInFlight(stream)) {
    resolver->Reject(v8::Exception::TypeError(
        WritableStream::CreateCannotActionOnStateStreamMessage(
            isolate, "write to", "closing")));
    return resolver->Promise();
  }
  if (state == WritableStream::kClosed) {
    resolver->Reject(WritableStream::CreateCannotActionOnStateStreamException(
        isolate, "write to", WritableStream::kClosed));
    return resolver->Promise();
  }

  //  9. If state is "erroring", return a promise rejected with
  //     stream.[[storedError]].
  if (state == WritableStream::kErroring) {
    resolver->Reject(stream->GetStoredError(isolate));
    return resolver->Promise();
  }

  // 10. Assert: state is "writable".
  DCHECK_EQ(state, WritableStream::kWritable);

  // 11. Let promise be ! WritableStreamAddWriteRequest(stream).
  WritableStream::AddWriteRequest(stream, resolver);

  // 12. Perform ! WritableStreamDefaultControllerWrite(controller, chunk,
  //     chunkSize).
  WritableStreamDefaultController::Write(script_state, controller, chunk,
                                         chunk_size, exception_state);

  // 13. Return promise.
  return resolver->Promise();
}

std::optional<double> WritableStreamDefaultWriter::GetDesiredSizeInternal()
    const {
  // https://streams.spec.whatwg.org/#writable-stream-default-writer-get-desired-size
  //  1. Let stream be writer.[[ownerWritableStream]].
  const WritableStream* stream = owner_writable_stream_;

  //  2. Let state be stream.[[state]].
  const auto state = stream->GetState();

  switch (state) {
    //  3. If state is "errored" or "erroring", return null.
    case WritableStream::kErrored:
    case WritableStream::kErroring:
      return std::nullopt;

      //  4. If state is "closed", return 0.
    case WritableStream::kClosed:
      return 0.0;

    default:
      //  5. Return ! WritableStreamDefaultControllerGetDesiredSize(
      //     stream.[[writableStreamController]]).
      return WritableStreamDefaultController::GetDesiredSize(
          stream->Controller());
  }
}

void WritableStreamDefaultWriter::ResetReadyPromise(ScriptState* script_state) {
  ready_resolver_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
}

void WritableStreamDefaultWriter::Trace(Visitor* visitor) const {
  visitor->Trace(owner_writable_stream_);
  visitor->Trace(closed_resolver_);
  visitor->Trace(ready_resolver_);
  ScriptWrappable::Trace(visitor);
}

// Writable Stream Writer Abstract Operations

ScriptPromise<IDLUndefined> WritableStreamDefaultWriter::Abort(
    ScriptState* script_state,
    WritableStreamDefaultWriter* writer,
    v8::Local<v8::Value> reason) {
  // https://streams.spec.whatwg.org/#writable-stream-default-writer-abort
  //  1. Let stream be writer.[[ownerWritableStream]].
  WritableStream* stream = writer->owner_writable_stream_;

  //  2. Assert: stream is not undefined.
  DCHECK(stream);

  //  3. Return ! WritableStreamAbort(stream, reason).
  return WritableStream::Abort(script_state, stream, reason);
}

ScriptPromise<IDLUndefined> WritableStreamDefaultWriter::Close(
    ScriptState* script_state,
    WritableStreamDefaultWriter* writer) {
  // https://streams.spec.whatwg.org/#writable-stream-default-writer-close
  //  1. Let stream be writer.[[ownerWritableStream]].
  WritableStream* stream = writer->owner_writable_stream_;

  //  2. Assert: stream is not undefined.
  DCHECK(stream);

  //  3. Return ! WritableStreamClose(stream).
  return WritableStream::Close(script_state, stream);
}

void WritableStreamDefaultWriter::EnsureClosedPromiseRejected(
    ScriptState* script_state,
    WritableStreamDefaultWriter* writer,
    v8::Local<v8::Value> error) {
  if (!script_state->ContextIsValid()) {
    return;
  }

  // https://streams.spec.whatwg.org/#writable-stream-default-writer-ensure-closed-promise-rejected
  //  1. If writer.[[closedPromise]].[[PromiseState]] is "pending", reject
  //     writer.[[closedPromise]] with error.
  if (writer->closed_resolver_->Promise().V8Promise()->State() !=
      v8::Promise::kPending) {
    //  2. Otherwise, set writer.[[closedPromise]] to a promise rejected with
    //     error.
    writer->closed_resolver_ =
        MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  }
  writer->closed_resolver_->Promise().MarkAsSilent();
  writer->closed_resolver_->Reject(error);

  //  3. Set writer.[[closedPromise]].[[PromiseIsHandled]] to true.
  writer->closed_resolver_->Promise().MarkAsHandled();
}

v8::Local<v8::Value> WritableStreamDefaultWriter::GetDesiredSize(
    v8::Isolate* isolate,
    const WritableStreamDefaultWriter* writer) {
  // https://streams.spec.whatwg.org/#writable-stream-default-writer-get-desired-size
  //  1. Let stream be writer.[[ownerWritableStream]].
  //  2. Let state be stream.[[state]].
  //  3. If state is "errored" or "erroring", return null.
  std::optional<double> desired_size = writer->GetDesiredSizeInternal();
  if (!desired_size.has_value()) {
    return v8::Null(isolate);
  }

  //  4. If state is "closed", return 0.
  //  5. Return ! WritableStreamDefaultControllerGetDesiredSize(
  //     stream.[[writableStreamController]]).
  return v8::Number::New(isolate, desired_size.value());
}

}  // namespace blink
```