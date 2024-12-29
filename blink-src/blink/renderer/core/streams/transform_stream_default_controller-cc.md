Response:
Let's break down the request and the provided code to construct a comprehensive answer.

**1. Understanding the Goal:**

The request asks for an analysis of the `TransformStreamDefaultController.cc` file in the Chromium Blink engine. The key aspects to cover are:

* **Functionality:** What does this class *do*?
* **Relationship to web technologies:** How does it connect to JavaScript, HTML, and CSS?
* **Logic and Examples:**  Illustrate its behavior with hypothetical inputs and outputs.
* **Common Errors:**  Identify potential mistakes developers might make.
* **Debugging Context:**  Explain how a user action could lead to this code being executed.

**2. Initial Code Scan and Keyword Identification:**

Reading through the code, certain keywords and patterns jump out:

* **`TransformStreamDefaultController`:**  This is the central class.
* **`TransformStream`:** The class it controls.
* **`ReadableStreamDefaultController`:**  Interaction with the readable side of the transform stream.
* **`enqueue`:**  Adding data to the readable side.
* **`error`:** Signaling an error in the stream.
* **`terminate`:**  Closing the stream.
* **`transform` (method and algorithm):** The core transformation logic.
* **`flush` (method and algorithm):**  Handling the finalization of the transformation.
* **`desiredSize`:**  Managing backpressure.
* **`ScriptState`, `ScriptValue`, `v8::Local<v8::Value>`:**  Interaction with the V8 JavaScript engine.
* **Promises:** Asynchronous operations and error handling.

**3. Deconstructing the Class and its Methods:**

* **Constructor/Destructor:**  Basic setup and teardown (default implementations).
* **`GetDefaultController`:**  Downcasting to get the `ReadableStreamDefaultController`. This hints at a structural relationship.
* **`desiredSize`:**  Delegates to the readable stream controller, indicating it manages the output buffer size.
* **`enqueue` (various overloads):**  This is how data is pushed *out* of the transform stream. It involves checking if the readable side can accept more data.
* **`error` (various overloads):**  Propagating errors.
* **`terminate`:** Closing the output stream.
* **`Trace`:** For debugging and garbage collection.
* **Inner Classes (`DefaultTransformAlgorithm`, `PerformTransformRejectFunction`):** These encapsulate specific pieces of logic related to the transform process and error handling.
* **`SetUp`:**  Initializes the controller and links it to the stream.
* **`SetUpFromTransformer`:** The crucial method for configuring the controller based on a JavaScript transformer object. This is where the user-defined `transform` and `flush` methods are integrated.
* **`ClearAlgorithms`:**  Releasing references to the transformation and flush logic.
* **`Enqueue` (internal):** The core logic of adding data to the readable stream, including backpressure handling.
* **`Error` (internal):**  Propagating errors within the stream pipeline.
* **`PerformTransform`:**  Actually executes the user-provided `transform` function.
* **`Terminate` (internal):**  The internal mechanism for closing the output stream and handling errors.

**4. Identifying Relationships to Web Technologies:**

* **JavaScript:** The code heavily interacts with V8, indicating a close relationship with JavaScript APIs. The `TransformStream` API itself is a JavaScript feature. The `transformer` object passed to the constructor is a JavaScript object.
* **HTML:**  `TransformStream` is often used in conjunction with other streaming APIs like `fetch` (for reading data) or the `WritableStream` (for writing data to sinks like files or network connections). These APIs are exposed to JavaScript and used within HTML.
* **CSS:** While less direct, CSS might be indirectly involved if the transformed data is used to dynamically update the style or content of a web page. For instance, a server-sent event stream processed by a `TransformStream` could update CSS variables.

**5. Crafting Examples and Scenarios:**

* **Logic/Input-Output:**  Focus on the `enqueue` and `transform` methods. Simple transformations (uppercase, length) are good illustrations.
* **User Errors:** Think about what could go wrong when using the JavaScript `TransformStream` API: providing incorrect transformer objects, throwing errors in `transform`/`flush`, etc.
* **Debugging:** Trace back from a user action to how the `TransformStreamDefaultController` might be involved. A `fetch` request piped through a `TransformStream` is a good example.

**6. Structuring the Answer:**

Organize the information logically:

* Start with a general overview of the file's purpose.
* Detail the key functionalities.
* Explain the relationships to web technologies with concrete examples.
* Provide logical examples with hypothetical inputs and outputs.
* Describe common user errors.
* Explain the debugging process and how to reach this code.

**7. Refining and Adding Detail:**

* Ensure accuracy and clarity in the explanations.
* Use terminology consistent with the Streams specification.
* Provide sufficient detail in the examples without making them too complex.
* Double-check the connections between user actions and the internal code.

**Self-Correction/Refinement during the Thought Process:**

* **Initial Thought:** Focus heavily on the internal workings of each method.
* **Correction:**  Shift focus to the *purpose* of each method within the context of the `TransformStream` API and its interaction with JavaScript.
* **Initial Thought:**  Assume direct CSS involvement.
* **Correction:**  Recognize that CSS involvement is likely indirect, through manipulation of the DOM based on transformed data.
* **Initial Thought:**  Provide overly technical examples.
* **Correction:** Simplify examples to illustrate the core concepts without overwhelming detail.

By following these steps, including breaking down the code, identifying key concepts, and thinking about the user's perspective, a comprehensive and informative answer can be constructed.
This C++ source file, `transform_stream_default_controller.cc`, within the Chromium Blink engine, implements the core logic for the `TransformStreamDefaultController`. This controller is a crucial component of the JavaScript Streams API, specifically for `TransformStream`.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Manages the Transformation Process:**  The primary role of this controller is to orchestrate the transformation of data chunks flowing through a `TransformStream`. It handles the interaction between the input (writable) side and the output (readable) side of the stream.

2. **Connects to the User-Provided Transformer:** It interacts with a JavaScript object (the "transformer") provided by the user when creating a `TransformStream`. This transformer object contains `transform` and optionally `flush` methods that define the actual data transformation logic.

3. **Enqueues Transformed Chunks:** When a new chunk of data arrives on the writable side of the `TransformStream`, this controller uses the user-provided `transform` method to process it. The resulting transformed chunk(s) are then enqueued onto the readable side of the stream, making them available for consumption.

4. **Handles Errors:** It manages error propagation within the `TransformStream`. If an error occurs during the transformation process (either in the user's `transform` method or internally), this controller ensures the error is signaled on both the readable and writable sides of the stream.

5. **Manages Stream Termination:** It handles the process of gracefully closing the `TransformStream`. This includes invoking the user-provided `flush` method (if defined) to perform any final transformations before the stream is fully closed.

6. **Backpressure Management:** It interacts with the readable stream's controller to manage backpressure. If the readable side is not ready to accept more data, the controller can signal backpressure to the writable side, preventing over-buffering.

**Relationship to JavaScript, HTML, and CSS:**

This C++ code directly implements the behavior of the JavaScript `TransformStream` API. Here's how it relates to web technologies:

* **JavaScript:**
    * **API Implementation:** This file is a core part of the underlying implementation of the `TransformStream` JavaScript API. When JavaScript code creates and interacts with `TransformStream` objects, it's ultimately this C++ code that executes the core logic.
    * **`transformer` Object:** The JavaScript code provides a `transformer` object with `transform` and optional `flush` methods. This C++ code retrieves and invokes these JavaScript methods using the V8 JavaScript engine bindings.
    * **Promises:** The `PerformTransform` method shows the use of `ScriptPromise`. The `transform` method of the transformer is expected to return a Promise, and this C++ code handles the resolution or rejection of that promise.

    **Example:**

    ```javascript
    const transformStream = new TransformStream({
      transform(chunk, controller) {
        const transformedChunk = chunk.toUpperCase();
        controller.enqueue(transformedChunk);
      },
      flush(controller) {
        controller.enqueue("DONE");
      }
    });

    const writableStream = transformStream.writable;
    const readableStream = transformStream.readable;

    const writer = writableStream.getWriter();
    writer.write("hello");
    writer.write("world");
    writer.close();

    const reader = readableStream.getReader();
    reader.read().then(({ value, done }) => console.log(value)); // Output: HELLO
    reader.read().then(({ value, done }) => console.log(value)); // Output: WORLD
    reader.read().then(({ value, done }) => console.log(value)); // Output: DONE
    reader.read().then(({ value, done }) => console.log(done));  // Output: true
    ```
    In this JavaScript code, when `new TransformStream(...)` is called, the Blink engine internally creates a `TransformStreamDefaultController` instance (implemented by this C++ file) and sets up the `transform` and `flush` methods provided in the JavaScript object. When `writer.write("hello")` is called, the C++ code within this file will eventually call the JavaScript `transform` method with "hello" as the `chunk`.

* **HTML:** While this code doesn't directly manipulate HTML elements, `TransformStream` is often used in scenarios involving:
    * **Streaming data from the network (using `fetch`):**  You might use a `TransformStream` to process data received from a server before displaying it in the HTML.
    * **Processing user input:** If a user uploads a file, a `TransformStream` could be used to process the file content before further actions.

* **CSS:**  Similar to HTML, the interaction with CSS is indirect. The output of a `TransformStream` could be used to dynamically update the style of elements on a web page. For example, a stream of sensor data could be transformed and then used to update CSS variables, changing the appearance of a visualization.

**Logical Reasoning and Examples:**

Let's consider the `enqueue` method and the `transform` algorithm:

**Hypothetical Input:**

1. **JavaScript creates a `TransformStream`:**
   ```javascript
   const uppercaseStream = new TransformStream({
     transform(chunk, controller) {
       controller.enqueue(chunk.toUpperCase());
     }
   });
   const writer = uppercaseStream.writable.getWriter();
   ```

2. **JavaScript writes data to the writable side:**
   ```javascript
   writer.write("lowercase");
   ```

**Processing in `transform_stream_default_controller.cc`:**

1. When `writer.write("lowercase")` is called, the Blink engine routes this to the writable side of the `TransformStream`.
2. The `TransformStreamDefaultController`'s internal mechanism detects the incoming chunk.
3. The `PerformTransform` method (in this C++ file) is invoked.
4. `PerformTransform` calls the user-provided `transform` function (the JavaScript function that uppercases the string) via V8 bindings.
5. The JavaScript `transform` function executes and calls `controller.enqueue("LOWERCASE")`.
6. The `enqueue` method in `TransformStreamDefaultController` receives "LOWERCASE".
7. This `enqueue` method checks if the readable side can accept data (backpressure).
8. If the readable side is ready, the transformed chunk "LOWERCASE" is enqueued onto the readable side's buffer.

**Hypothetical Output:**

When the readable side of `uppercaseStream` is read, the value "LOWERCASE" will be received.

**Common User or Programming Errors:**

1. **Throwing Errors in `transform` or `flush` without Handling:** If the user's JavaScript `transform` or `flush` methods throw an error, this C++ code will catch it and propagate it as an error on the stream. However, if the user doesn't handle these errors in their JavaScript code (e.g., using `.catch()` on promises), it can lead to unhandled promise rejections or unexpected stream termination.

    **Example:**

    ```javascript
    const errorStream = new TransformStream({
      transform(chunk, controller) {
        if (chunk === "bad") {
          throw new Error("Something went wrong!");
        }
        controller.enqueue(chunk);
      }
    });

    const writer = errorStream.writable.getWriter();
    writer.write("good");
    writer.write("bad"); // This will cause an error

    const reader = errorStream.readable.getReader();
    reader.read().then(({ value, done }) => console.log(value));
    reader.read().catch(error => console.error("Stream error:", error)); // Need to handle the error
    ```

2. **Calling `controller.enqueue` with Incorrect Data Types:** The `enqueue` method expects data chunks compatible with the stream's underlying type. Passing incompatible data might lead to errors or unexpected behavior.

3. **Not Handling Backpressure:**  While the browser tries to manage backpressure, if the user's `transform` method performs very slow operations or produces data much faster than the readable side can consume, it can lead to memory issues.

**User Operations Leading to This Code (Debugging Clues):**

1. **Creating a `TransformStream` in JavaScript:** When a user's JavaScript code executes `new TransformStream(...)`, the Blink engine will create an instance of `TransformStreamDefaultController`.

2. **Writing Data to the Writable Side:** When the user calls `writableStream.getWriter().write(chunk)`, this will eventually trigger the `PerformTransform` method in this C++ file.

3. **Closing the Writable Side:** When the user calls `writableStream.getWriter().close()` or if the writable side encounters an error, the `TransformStreamDefaultController` will initiate the stream closure process, potentially calling the user's `flush` method.

4. **Reading Data from the Readable Side:** While reading data from the readable side doesn't directly execute code in this file, it relies on the enqueued data produced by the transformation process managed by this controller. If there are issues with the data being read, the problem likely originates from the transformation logic within this file.

**Debugging Steps to Reach Here:**

If you are debugging an issue involving a `TransformStream`:

1. **Set Breakpoints in JavaScript:** Start by placing breakpoints in your JavaScript code where you create the `TransformStream`, write data to it, and read data from it.

2. **Step Through JavaScript:** Use the browser's developer tools to step through the JavaScript code and observe the flow of data.

3. **Inspect Stream State:** Use the developer tools to inspect the state of the `TransformStream` object (e.g., its readable and writable sides, its controller).

4. **If Errors Occur in Transformation:** If you suspect the issue lies within the transformation logic, you might need to delve into the Blink source code. You could set breakpoints in `transform_stream_default_controller.cc`, specifically in methods like `PerformTransform`, `Enqueue`, and the `SetUpFromTransformer` method (which sets up the connection to the JavaScript transformer).

5. **Trace the Call Stack:** If a crash or unexpected behavior occurs, examine the call stack to see if the execution path leads through the methods in this file. This can help pinpoint where the problem might be.

By understanding the functionality of `transform_stream_default_controller.cc` and how it interacts with the JavaScript `TransformStream` API, developers can better debug issues related to data transformation and streaming in web applications.

Prompt: 
```
这是目录为blink/renderer/core/streams/transform_stream_default_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/streams/transform_stream_default_controller.h"

#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/core/streams/miscellaneous_operations.h"
#include "third_party/blink/renderer/core/streams/promise_handler.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_controller.h"
#include "third_party/blink/renderer/core/streams/stream_algorithms.h"
#include "third_party/blink/renderer/core/streams/transform_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"

namespace blink {

TransformStreamDefaultController::TransformStreamDefaultController() = default;
TransformStreamDefaultController::~TransformStreamDefaultController() = default;

ReadableStreamDefaultController*
TransformStreamDefaultController::GetDefaultController(
    TransformStream* stream) {
  // The TransformStreamDefaultController will always use a
  // ReadableStreamDefaultController. Hence, it is safe to down-cast here.
  return To<ReadableStreamDefaultController>(
      stream->readable_->GetController());
}

std::optional<double> TransformStreamDefaultController::desiredSize() const {
  // https://streams.spec.whatwg.org/#ts-default-controller-desired-size
  // 2. Let readableController be
  //    this.[[controlledTransformStream]].[[readable]].
  //    [[readableStreamController]].
  const auto* readable_controller =
      GetDefaultController(controlled_transform_stream_);

  // 3. Return !
  //    ReadableStreamDefaultControllerGetDesiredSize(readableController).
  // Use the accessor instead as it already has the semantics we need and can't
  // be interfered with from JavaScript.
  return readable_controller->desiredSize();
}

// The handling of undefined arguments is implicit in the standard, but needs to
// be done explicitly with IDL.
void TransformStreamDefaultController::enqueue(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#ts-default-controller-enqueue
  // 2. Perform ? TransformStreamDefaultControllerEnqueue(this, chunk).
  Enqueue(script_state, this, v8::Undefined(script_state->GetIsolate()),
          exception_state);
}

void TransformStreamDefaultController::enqueue(
    ScriptState* script_state,
    ScriptValue chunk,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#ts-default-controller-enqueue
  // 2. Perform ? TransformStreamDefaultControllerEnqueue(this, chunk).
  Enqueue(script_state, this, chunk.V8Value(), exception_state);
}

void TransformStreamDefaultController::error(ScriptState* script_state) {
  // https://streams.spec.whatwg.org/#ts-default-controller-error
  // 2. Perform ! TransformStreamDefaultControllerError(this, reason).
  Error(script_state, this, v8::Undefined(script_state->GetIsolate()));
}

void TransformStreamDefaultController::error(ScriptState* script_state,
                                             ScriptValue reason) {
  // https://streams.spec.whatwg.org/#ts-default-controller-error
  // 2. Perform ! TransformStreamDefaultControllerError(this, reason).
  Error(script_state, this, reason.V8Value());
}

void TransformStreamDefaultController::terminate(ScriptState* script_state) {
  // https://streams.spec.whatwg.org/#ts-default-controller-terminate
  // 2. Perform ! TransformStreamDefaultControllerTerminate(this).
  Terminate(script_state, this);
}

void TransformStreamDefaultController::Trace(Visitor* visitor) const {
  visitor->Trace(controlled_transform_stream_);
  visitor->Trace(flush_algorithm_);
  visitor->Trace(transform_algorithm_);
  visitor->Trace(reject_function_);
  ScriptWrappable::Trace(visitor);
}

// This algorithm is not explicitly named, but is described as part of the
// SetUpTransformStreamDefaultControllerFromTransformer abstract operation in
// the standard.
class TransformStreamDefaultController::DefaultTransformAlgorithm final
    : public StreamAlgorithm {
 public:
  explicit DefaultTransformAlgorithm(
      TransformStreamDefaultController* controller)
      : controller_(controller) {}

  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    DCHECK_EQ(argc, 1);
    v8::Isolate* isolate = script_state->GetIsolate();
    v8::TryCatch try_catch(isolate);

    // https://streams.spec.whatwg.org/#set-up-transform-stream-default-controller-from-transformer
    // 3. Let transformAlgorithm be the following steps, taking a chunk
    //    argument:
    //    a. Let result be TransformStreamDefaultControllerEnqueue(controller,
    //       chunk).
    Enqueue(script_state, controller_, argv[0], PassThroughException(isolate));

    //    b. If result is an abrupt completion, return a promise rejected with
    //       result.[[Value]].
    if (try_catch.HasCaught()) {
      return ScriptPromise<IDLUndefined>::Reject(script_state,
                                                 try_catch.Exception());
    }

    //    c. Otherwise, return a promise resolved with undefined.
    return ToResolvedUndefinedPromise(script_state);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(controller_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  Member<TransformStreamDefaultController> controller_;
};

class TransformStreamDefaultController::PerformTransformRejectFunction final
    : public ThenCallable<IDLAny, PerformTransformRejectFunction> {
 public:
  explicit PerformTransformRejectFunction(TransformStream* stream)
      : stream_(stream) {}

  void React(ScriptState* script_state, ScriptValue r) {
    // 2. Return the result of transforming transformPromise with a rejection
    //    handler that, when called with argument r, performs the following
    //    steps:
    //    a. Perform ! TransformStreamError(controller.
    //       [[controlledTransformStream]], r).
    TransformStream::Error(script_state, stream_, r.V8Value());

    //    b. Throw r.
    V8ThrowException::ThrowException(script_state->GetIsolate(), r.V8Value());
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(stream_);
    ThenCallable<IDLAny, PerformTransformRejectFunction>::Trace(visitor);
  }

 private:
  Member<TransformStream> stream_;
};

void TransformStreamDefaultController::SetUp(
    ScriptState* script_state,
    TransformStream* stream,
    TransformStreamDefaultController* controller,
    StreamAlgorithm* transform_algorithm,
    StreamAlgorithm* flush_algorithm) {
  // https://streams.spec.whatwg.org/#set-up-transform-stream-default-controller
  // 1. Assert: ! IsTransformStream(stream) is true.
  DCHECK(stream);

  // 2. Assert: stream.[[transformStreamController]] is undefined.
  DCHECK(!stream->transform_stream_controller_);

  // 3. Set controller.[[controlledTransformStream]] to stream.
  controller->controlled_transform_stream_ = stream;

  // 4. Set stream.[[transformStreamController]] to controller.
  stream->transform_stream_controller_ = controller;

  // 5. Set controller.[[transformAlgorithm]] to transformAlgorithm.
  controller->transform_algorithm_ = transform_algorithm;

  // 6. Set controller.[[flushAlgorithm]] to flushAlgorithm.
  controller->flush_algorithm_ = flush_algorithm;

  controller->reject_function_ =
      MakeGarbageCollected<PerformTransformRejectFunction>(
          controller->controlled_transform_stream_);
}

v8::Local<v8::Value> TransformStreamDefaultController::SetUpFromTransformer(
    ScriptState* script_state,
    TransformStream* stream,
    v8::Local<v8::Object> transformer,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#set-up-transform-stream-default-controller-from-transformer
  // 1. Assert: transformer is not undefined.
  DCHECK(!transformer->IsUndefined());

  // 2. Let controller be ObjectCreate(the original value of
  //    TransformStreamDefaultController's prototype property).
  auto* controller = MakeGarbageCollected<TransformStreamDefaultController>();

  // This method is only called when a TransformStream is being constructed by
  // JavaScript. So the execution context should be valid and this call should
  // not crash.
  auto controller_value = ToV8Traits<TransformStreamDefaultController>::ToV8(
      script_state, controller);

  // The following steps are reordered from the standard for efficiency, but the
  // effect is the same.
  StreamAlgorithm* transform_algorithm = nullptr;

  // 4. Let transformMethod be ? GetV(transformer, "transform").
  v8::MaybeLocal<v8::Value> method_maybe =
      ResolveMethod(script_state, transformer, "transform",
                    "transformer.transform", exception_state);
  v8::Local<v8::Value> transform_method;
  if (!method_maybe.ToLocal(&transform_method)) {
    CHECK(exception_state.HadException());
    return v8::Local<v8::Value>();
  }
  DCHECK(!exception_state.HadException());

  if (transform_method->IsUndefined()) {
    // 3. Let transformAlgorithm be the following steps, taking a chunk
    // argument:
    //    i. Let result be TransformStreamDefaultControllerEnqueue(controller,
    //       chunk).
    //   ii. If result is an abrupt completion, return a promise rejected with
    //       result.[[Value]].
    //  iii. Otherwise, return a promise resolved with undefined.
    transform_algorithm =
        MakeGarbageCollected<DefaultTransformAlgorithm>(controller);
  } else {
    // 5. If transformMethod is not undefined,
    //    a. If ! IsCallable(transformMethod) is false, throw a TypeError
    //       exception.
    // (The IsCallable() check has already been done by ResolveMethod).

    //    b. Set transformAlgorithm to the following steps, taking a chunk
    //       argument:
    //       i. Return ! PromiseCall(transformMethod, transformer, « chunk,
    //          controller »).
    transform_algorithm = CreateAlgorithmFromResolvedMethod(
        script_state, transformer, transform_method, controller_value);
  }

  // 6. Let flushAlgorithm be ? CreateAlgorithmFromUnderlyingMethod(transformer,
  //    "flush", 0, « controller »).
  auto* flush_algorithm = CreateAlgorithmFromUnderlyingMethod(
      script_state, transformer, "flush", "transformer.flush", controller_value,
      exception_state);

  // 7. Perform ! SetUpTransformStreamDefaultController(stream, controller,
  //    transformAlgorithm, flushAlgorithm).
  SetUp(script_state, stream, controller, transform_algorithm, flush_algorithm);

  // This operation doesn't have a return value in the standard, but it's useful
  // to return the JavaScript wrapper here so that it can be used when calling
  // transformer.start().
  return controller_value;
}

void TransformStreamDefaultController::ClearAlgorithms(
    TransformStreamDefaultController* controller) {
  // https://streams.spec.whatwg.org/#transform-stream-default-controller-clear-algorithms
  // 1. Set controller.[[transformAlgorithm]] to undefined.
  controller->transform_algorithm_ = nullptr;

  // 2. Set controller.[[flushAlgorithm]] to undefined.
  controller->flush_algorithm_ = nullptr;
}

void TransformStreamDefaultController::Enqueue(
    ScriptState* script_state,
    TransformStreamDefaultController* controller,
    v8::Local<v8::Value> chunk,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#transform-stream-default-controller-enqueue
  // 1. Let stream be controller.[[controlledTransformStream]].
  TransformStream* stream = controller->controlled_transform_stream_;

  // 2. Let readableController be
  //    stream.[[readable]].[[readableStreamController]].
  auto* readable_controller = GetDefaultController(stream);

  // 3. If !
  //    ReadableStreamDefaultControllerCanCloseOrEnqueue(readableController) is
  //    false, throw a TypeError exception.
  if (!ReadableStreamDefaultController::CanCloseOrEnqueue(
          readable_controller)) {
    exception_state.ThrowTypeError(
        ReadableStreamDefaultController::EnqueueExceptionMessage(
            readable_controller));
    return;
  }

  // 4. Let enqueueResult be ReadableStreamDefaultControllerEnqueue(
  //    readableController, chunk).
  v8::Isolate* isolate = script_state->GetIsolate();
  TryRethrowScope rethrow_scope(isolate, exception_state);
  ReadableStreamDefaultController::Enqueue(
      script_state, readable_controller, chunk, PassThroughException(isolate));

  // 5. If enqueueResult is an abrupt completion,
  if (rethrow_scope.HasCaught()) {
    // a. Perform ! TransformStreamErrorWritableAndUnblockWrite(stream,
    //    enqueueResult.[[Value]]).
    TransformStream::ErrorWritableAndUnblockWrite(script_state, stream,
                                                  rethrow_scope.GetException());

    // b. Throw stream.[[readable]].[[storedError]].
    V8ThrowException::ThrowException(
        isolate, stream->readable_->GetStoredError(isolate));
    return;
  }

  // 6. Let backpressure be ! ReadableStreamDefaultControllerHasBackpressure(
  //    readableController).
  bool backpressure =
      ReadableStreamDefaultController::HasBackpressure(readable_controller);

  // 7. If backpressure is not stream.[[backpressure]],
  if (backpressure != stream->had_backpressure_) {
    // a. Assert: backpressure is true.
    DCHECK(backpressure);

    // b. Perform ! TransformStreamSetBackpressure(stream, true).
    TransformStream::SetBackpressure(script_state, stream, true);
  }
}

void TransformStreamDefaultController::Error(
    ScriptState* script_state,
    TransformStreamDefaultController* controller,
    v8::Local<v8::Value> e) {
  // https://streams.spec.whatwg.org/#transform-stream-default-controller-error
  // 1. Perform ! TransformStreamError(controller.[[controlledTransformStream]],
  //    e).
  TransformStream::Error(script_state, controller->controlled_transform_stream_,
                         e);
}

ScriptPromise<IDLUndefined> TransformStreamDefaultController::PerformTransform(
    ScriptState* script_state,
    TransformStreamDefaultController* controller,
    v8::Local<v8::Value> chunk) {
  if (!script_state->ContextIsValid()) {
    v8::Local<v8::Value> error = V8ThrowException::CreateTypeError(
        script_state->GetIsolate(), "invalid realm");
    Error(script_state, controller, error);
    return EmptyPromise();
  }
  // https://streams.spec.whatwg.org/#transform-stream-default-controller-perform-transform
  // 1. Let transformPromise be the result of performing controller.
  //    [[transformAlgorithm]], passing chunk.
  // This is needed because the result of transforming the transform promise
  // needs to be returned to the outer scope.
  ScriptState::EscapableScope scope(script_state);
  ScriptPromise<IDLUndefined> transform_promise =
      controller->transform_algorithm_->Run(script_state, 1, &chunk);
  DCHECK(!transform_promise.IsEmpty());

  // 2. Return the result of transforming transformPromise ...
  v8::Local<v8::Value> escapable_streamed_promise = scope.Escape(
      transform_promise.Catch(script_state, controller->reject_function_.Get())
          .V8Promise());
  return ScriptPromise<IDLUndefined>::FromV8Value(script_state,
                                                  escapable_streamed_promise);
}

void TransformStreamDefaultController::Terminate(
    ScriptState* script_state,
    TransformStreamDefaultController* controller) {
  // https://streams.spec.whatwg.org/#transform-stream-default-controller-terminate
  // 1. Let stream be controller.[[controlledTransformStream]].
  TransformStream* stream = controller->controlled_transform_stream_;

  // 2. Let readableController be
  //    stream.[[readable]].[[readableStreamController]].
  ReadableStreamDefaultController* readable_controller =
      GetDefaultController(stream);

  // 3. If !
  //    ReadableStreamDefaultControllerCanCloseOrEnqueue(readableController) is
  //    true, perform ! ReadableStreamDefaultControllerClose(
  //    readableController).
  if (ReadableStreamDefaultController::CanCloseOrEnqueue(readable_controller)) {
    ReadableStreamDefaultController::Close(script_state, readable_controller);
  }

  // 4. Let error be a TypeError exception indicating that the stream has been
  //    terminated.
  const auto error = v8::Exception::TypeError(V8String(
      script_state->GetIsolate(), "The transform stream has been terminated"));

  // 5. Perform ! TransformStreamErrorWritableAndUnblockWrite(stream, error).
  TransformStream::ErrorWritableAndUnblockWrite(script_state, stream, error);
}

}  // namespace blink

"""

```