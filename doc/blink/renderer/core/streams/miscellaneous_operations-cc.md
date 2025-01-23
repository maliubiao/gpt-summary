Response:
Let's break down the thought process for analyzing the `miscellaneous_operations.cc` file.

**1. Initial Understanding of the File's Purpose (Based on Filename and Header):**

* **Filename:** `miscellaneous_operations.cc` within `blink/renderer/core/streams`. This immediately suggests it contains utility functions or shared logic related to the Streams API in Blink (Chromium's rendering engine). The "miscellaneous" part hints that it might not fit neatly into specific ReadableStream or WritableStream implementations but is used by both.
* **Header:**  The comment `// Implementation of functions that are shared between ReadableStream and WritableStream.` reinforces the above understanding. The includes give further clues:
    * `<math.h>`: Might involve numerical calculations.
    * `<optional>`: Indicates the use of optional values, likely for cases where a value might be absent.
    * Includes from `third_party/blink/renderer/bindings/core/v8`:  Strongly suggests interaction with JavaScript and V8 (Chromium's JavaScript engine). Specifically, it mentions `v8_readable_stream.h` and `v8_writable_stream.h`, confirming the Streams API connection.
    * Includes from `third_party/blink/renderer/core/streams`: References to `readable_stream.h` and `stream_algorithms.h`, indicating internal stream logic.
    * Includes from `third_party/blink/renderer/platform/bindings`:  Points to the interface between Blink's C++ and JavaScript bindings.
    * Other platform includes: Basic utility and memory management.

**2. Identifying Key Functionalities (Scanning the Code):**

Now, I'd start reading through the code, paying attention to function names and their arguments. I'd look for patterns and groupings of related functions.

* **Promise Handling:**  The functions `PromiseRejectInternal`, `PromiseResolve`, `PromiseResolveWithUndefined`, and `PromiseReject`, along with `PromiseCall`, clearly deal with JavaScript Promises. The comments and logic confirm this.
* **Strategy Algorithms:** The classes `DefaultSizeAlgorithm`, `JavaScriptSizeAlgorithm`, and the function `MakeSizeAlgorithmFromSizeFunction` are related to the `size` property in the queuing strategy of streams.
* **Stream Algorithms (Generic):**  The base class `StreamAlgorithm` and its implementations like `TrivialStreamAlgorithm`, `JavaScriptStreamAlgorithmWithoutExtraArg`, and `JavaScriptStreamAlgorithmWithExtraArg` suggest different ways to handle stream operations, especially involving JavaScript callbacks. The `CreateAlgorithmFromUnderlyingMethod` function appears to be a factory for creating these algorithms.
* **Stream Start Algorithms:**  Similarly, `StreamStartAlgorithm`, `JavaScriptStreamStartAlgorithm`, `JavaScriptByteStreamStartAlgorithm`, and `TrivialStartAlgorithm` handle the initial setup of streams.
* **Utility/Helper Functions:**  Functions like `ResolveMethod`, `CallOrNoop1`, `ValidateAndNormalizeHighWaterMark`, `CreateTrivialQueuingStrategy`, and `ScriptValueToObject` provide supporting functionalities.
* **Strategy Unpacking:** The `StrategyUnpacker` class seems to be responsible for extracting and validating the `size` and `highWaterMark` properties from a queuing strategy object.

**3. Connecting to JavaScript, HTML, and CSS:**

With the functionalities identified, I'd consider how these relate to the web platform:

* **Streams API in JavaScript:** The core connection is the implementation of the WHATWG Streams API. The functions here are the C++ underpinnings for JavaScript stream objects. I'd think about how a JavaScript developer would interact with `ReadableStream` and `WritableStream` and how those actions would trigger these C++ functions. For example, calling `pipeTo`, writing to a `WritableStream`, or reading from a `ReadableStream`.
* **HTML:**  Streams are often used in conjunction with HTML elements. For instance, `fetch` API returns a `ReadableStream` for the response body. The `<img>` tag might eventually use streams internally for progressive image decoding (though this file might not be directly involved in that specific implementation).
* **CSS:** Direct connections to CSS are less likely for *this specific file*. Streams are more about data flow.

**4. Hypothesizing Inputs and Outputs (Logical Reasoning):**

For functions like `ValidateAndNormalizeHighWaterMark`, the logic is straightforward. For more complex functions like `CreateAlgorithmFromUnderlyingMethod`, I'd consider different scenarios:

* **Input:** A JavaScript object with a "start" method.
* **Output:** A `JavaScriptStreamStartAlgorithm` object.
* **Input:** A JavaScript object without a "start" method.
* **Output:** A `TrivialStartAlgorithm` object.

For `MakeSizeAlgorithmFromSizeFunction`:

* **Input:** A JavaScript function.
* **Output:** A `JavaScriptSizeAlgorithm` object.
* **Input:** `undefined`.
* **Output:** A `DefaultSizeAlgorithm` object.

**5. Identifying Potential User/Programming Errors:**

Knowing how the code interacts with JavaScript allows me to infer potential errors:

* **Incorrect `highWaterMark`:**  Providing a negative number or `NaN` to the queuing strategy.
* **Invalid `size` function:** Providing something that isn't a function as the `size` property.
* **Underlying methods not being functions:** If the `start`, `pull`, or `write` methods on the underlying source/sink aren't functions or are missing.

**6. Tracing User Operations (Debugging Clues):**

This requires thinking about how a user's action in a web page might lead to this code being executed.

* **Fetching a large file:**  Using the `fetch` API. The browser might create a `ReadableStream` for the download. Operations on this stream (like reading chunks) would eventually involve the functions in this file.
* **Using the `WritableStream` API:**  A JavaScript developer explicitly creates a `WritableStream` and defines its `start`, `write`, and `close` methods. When data is written to the stream, the corresponding algorithms in this file are invoked.
* **Piping streams:** Using `readableStream.pipeTo(writableStream)`. This sets up a connection between two streams, and the underlying mechanics would involve the functions here.

**7. Iterative Refinement:**

My initial analysis might not be perfect. I would then re-read the code, paying closer attention to details and comments. I might also consult the WHATWG Streams specification to get a deeper understanding of the concepts being implemented. For instance, understanding the exact steps of "CreateAlgorithmFromUnderlyingMethod" in the spec helps in accurately describing the function's purpose.

By following these steps, I can systematically analyze the C++ source code and connect it to its role in the broader web platform, as demonstrated in the provided answer.
好的，让我们来详细分析一下 `blink/renderer/core/streams/miscellaneous_operations.cc` 这个文件。

**文件功能概述:**

这个文件正如其注释所言，实现了一些在 `ReadableStream` 和 `WritableStream` 之间共享的函数。这些函数主要负责处理与 Streams API 相关的底层操作，特别是与 JavaScript 交互的部分。核心功能包括：

1. **Promise 处理:** 提供了用于创建和处理 JavaScript Promise 的辅助函数，例如 `PromiseRejectInternal`, `PromiseResolve`, `PromiseCall` 等。这在异步的流操作中至关重要。
2. **算法创建:**  定义了创建和管理各种 Stream 算法的机制，例如 `CreateAlgorithmFromUnderlyingMethod` 用于从 JavaScript 对象的方法创建算法，以及 `CreateStartAlgorithm` 和 `CreateByteStreamStartAlgorithm` 用于创建启动流的算法。
3. **策略（Strategy）处理:** 实现了与流的排队策略 (queuing strategy) 相关的逻辑，包括 `ValidateAndNormalizeHighWaterMark` 用于验证和规范化 `highWaterMark`，以及 `MakeSizeAlgorithmFromSizeFunction` 用于根据 JavaScript 函数创建 size 算法。
4. **调用 JavaScript 方法:**  提供了安全调用 JavaScript 方法的辅助函数，例如 `CallOrNoop1` 和 `PromiseCall`，并处理可能的异常情况。
5. **类型转换和检查:**  进行一些类型转换和检查，例如将 ScriptValue 转换为 v8::Object。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件是 Blink 引擎中实现 Web Streams API 的关键部分，因此与 JavaScript 有着直接而深厚的联系。它负责将 JavaScript 中对 Streams API 的操作转化为底层的 C++ 实现。

* **JavaScript `ReadableStream` 和 `WritableStream` 的构造和操作:** 当 JavaScript 代码创建 `ReadableStream` 或 `WritableStream` 的实例时，或者调用它们的方法（如 `pipeTo`, `getReader`, `getWriter`, `enqueue`, `write` 等），最终会调用到这个文件中定义的 C++ 函数。

   **举例说明:**

   ```javascript
   // JavaScript 代码
   const readableStream = new ReadableStream({
     start(controller) {
       controller.enqueue("Hello");
       controller.close();
     }
   });

   readableStream.getReader().read().then(result => {
     console.log(result.value); // 输出 "Hello"
   });
   ```

   在这个例子中，`ReadableStream` 构造函数接收一个对象，该对象包含一个 `start` 方法。Blink 引擎在处理这个构造函数时，会调用 `CreateStartAlgorithm` 或类似的函数，将 JavaScript 的 `start` 方法封装成一个 C++ 的 `StreamStartAlgorithm` 对象。当流开始时，这个算法会被执行，从而调用到 JavaScript 中定义的 `start` 方法。

* **与 HTML 的关系:**  Streams API 经常用于处理来自 HTML 元素（如 `<video>`, `<audio>`, `<canvas>`）或其他 Web API（如 `fetch`）的数据流。

   **举例说明:**

   ```javascript
   // JavaScript 代码，使用 fetch API 获取数据并作为流处理
   fetch('data.txt')
     .then(response => response.body) // response.body 是一个 ReadableStream
     .then(readableStream => {
       const reader = readableStream.getReader();
       return reader.read();
     })
     .then(result => {
       console.log(result.value); // 输出数据块
     });
   ```

   在这个例子中，`fetch` API 返回的 `response.body` 就是一个 `ReadableStream`。当 JavaScript 代码调用 `getReader()` 或 `read()` 方法时，Blink 引擎会调用这个文件中的相关 C++ 函数来执行底层的读取操作。

* **与 CSS 的关系:**  一般来说，这个文件与 CSS 的功能没有直接的联系。Streams API 主要用于处理数据流，而不是样式渲染。

**逻辑推理的假设输入与输出:**

让我们以 `ValidateAndNormalizeHighWaterMark` 函数为例进行逻辑推理：

**假设输入:**

* `high_water_mark`: 一个 double 类型的数值。
* `exception_state`: 一个 `ExceptionState` 对象，用于报告错误。

**逻辑:**

该函数根据 WHATWG Streams 规范验证 `high_water_mark` 的值。如果 `high_water_mark` 是 `NaN` 或者小于 0，则会抛出一个 `RangeError` 异常。否则，返回 `high_water_mark` 的值。

**假设输出:**

* 如果输入 `high_water_mark` 为有效值（非负数且非 NaN），则返回该 `high_water_mark` 值。
* 如果输入 `high_water_mark` 为无效值，则 `exception_state` 对象会被设置为抛出一个 `RangeError` 异常，函数本身返回 0（虽然这个返回值在这种错误情况下可能并不重要，重要的是异常状态）。

**涉及用户或编程常见的使用错误及举例说明:**

1. **在排队策略中提供无效的 `highWaterMark` 值:**

   ```javascript
   // 错误示例
   const writableStream = new WritableStream({
     // ...
   }, { highWaterMark: -1 }); // 错误：highWaterMark 不能为负数
   ```

   当 JavaScript 代码尝试创建一个 `WritableStream` 或 `ReadableStream` 并提供了无效的 `highWaterMark` 值（如负数或 `NaN`）时，Blink 引擎会调用 `ValidateAndNormalizeHighWaterMark` 函数进行验证，并抛出一个 `RangeError` 异常。

2. **在排队策略中提供非函数的 `size` 属性:**

   ```javascript
   // 错误示例
   const readableStream = new ReadableStream({
     // ...
   }, { size: 10 }); // 错误：size 应该是一个函数
   ```

   如果排队策略的 `size` 属性不是一个函数，`MakeSizeAlgorithmFromSizeFunction` 函数会检测到这个错误并抛出一个 `TypeError` 异常。

3. **在 Underlying Source/Sink 中提供非函数的方法 (如 `start`, `pull`, `write`):**

   ```javascript
   // 错误示例 (WritableStream)
   const writableStream = new WritableStream({
     start: 'not a function' // 错误：start 必须是一个函数或 undefined
   });
   ```

   当创建流时，Blink 引擎会尝试获取 Underlying Source 或 Sink 中的 `start`, `pull`, `write`, `close` 等方法。如果这些属性存在但不是函数，`ResolveMethod` 函数会检测到这个错误并抛出一个 `TypeError` 异常。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在网页上进行了一个操作，导致一个 `WritableStream` 的 `write` 方法被调用。以下是可能到达 `miscellaneous_operations.cc` 的路径：

1. **用户交互/JavaScript 代码触发:** 用户在网页上执行某些操作（例如，点击按钮、提交表单），导致 JavaScript 代码被执行。
2. **调用 `WritableStream.prototype.write()`:**  JavaScript 代码调用了某个 `WritableStream` 实例的 `write()` 方法，尝试向流中写入数据。
3. **Blink 的 JavaScript 绑定:**  V8 引擎执行 JavaScript 代码时，遇到了 `writableStream.write()` 调用。Blink 的 JavaScript 绑定层会将这个调用路由到对应的 C++ 代码。
4. **`WritableStream::Write()` 或相关方法:** 在 Blink 的 `writable_stream.cc` 文件中，可能会有 `WritableStream::Write()` 方法处理 JavaScript 的 `write()` 调用。
5. **调用 Stream 算法:** `WritableStream::Write()` 方法会根据流的状态和配置，调用相应的 Stream 算法来执行实际的写入操作。这个算法可能是在 `miscellaneous_operations.cc` 中创建的，特别是当涉及到自定义的 Underlying Sink 和其 `write` 方法时。
6. **`CreateAlgorithmFromUnderlyingMethod()` 或类似函数:** 如果 Underlying Sink 的 `write` 方法是一个 JavaScript 函数，那么在创建 `WritableStream` 时，`CreateAlgorithmFromUnderlyingMethod()` 函数会被调用，将 JavaScript 的 `write` 方法包装成一个 C++ 的 `StreamAlgorithm` 对象。
7. **`PromiseCall()` 或 `CallOrNoop1()`:** 当需要执行 JavaScript 的 `write` 方法时，可能会使用 `PromiseCall()` 或 `CallOrNoop1()` 函数来安全地调用该方法并处理 Promise 返回值。这些函数就在 `miscellaneous_operations.cc` 中定义。

**调试线索:**

* **断点:** 在 `miscellaneous_operations.cc` 中设置断点，例如在 `CreateAlgorithmFromUnderlyingMethod`、`PromiseCall`、`ValidateAndNormalizeHighWaterMark` 等关键函数上，可以观察代码执行流程和变量值。
* **调用栈:** 查看调用栈可以帮助你追踪从 JavaScript 代码到 C++ 代码的调用路径，了解用户操作是如何一步步触发到这里的。
* **日志输出:** 在关键函数中添加日志输出，可以记录函数的输入参数和返回值，帮助理解函数的行为。
* **审查 JavaScript 代码:**  检查触发流操作的 JavaScript 代码，确认是否正确使用了 Streams API，例如 Underlying Source/Sink 的方法是否定义正确，排队策略的属性是否有效。

总而言之，`blink/renderer/core/streams/miscellaneous_operations.cc` 文件是 Blink 引擎中实现 Web Streams API 的重要组成部分，它连接了 JavaScript 和底层的 C++ 实现，处理了流操作中常见的任务，并确保了 API 的正确性和安全性。理解这个文件的功能对于深入理解 Web Streams API 的工作原理以及调试相关的代码至关重要。

### 提示词
```
这是目录为blink/renderer/core/streams/miscellaneous_operations.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

// Implementation of functions that are shared between ReadableStream and
// WritableStream.

#include "third_party/blink/renderer/core/streams/miscellaneous_operations.h"

#include <math.h>

#include <optional>

#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_writable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/stream_algorithms.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/trace_wrapper_v8_reference.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

// PromiseRejectInternal() implements Promise.reject(_r_) from the ECMASCRIPT
// standard, https://tc39.github.io/ecma262/#sec-promise.reject.
// The |recursion_depth| argument is used to prevent infinite recursion in the
// case that we can't create a promise.
v8::Local<v8::Promise> PromiseRejectInternal(ScriptState* script_state,
                                             v8::Local<v8::Value> value,
                                             int recursion_depth) {
  auto context = script_state->GetContext();
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::MicrotasksScope microtasks_scope(
      isolate, ToMicrotaskQueue(script_state),
      v8::MicrotasksScope::kDoNotRunMicrotasks);
  v8::TryCatch trycatch(isolate);
  // TODO(ricea): Can this fail for reasons other than memory exhaustion? Can we
  // recover if it does?
  auto resolver = v8::Promise::Resolver::New(context).ToLocalChecked();
  if (resolver->Reject(context, value).IsNothing()) {
    // Assume that the exception can be successfully used to create a Promise.
    // TODO(ricea): Can the body of this if statement actually be reached?
    if (recursion_depth >= 2) {
      LOG(FATAL) << "Recursion depth exceeded in PromiseRejectInternal";
    }
    return PromiseRejectInternal(script_state, trycatch.Exception(),
                                 recursion_depth + 1);
  }
  return resolver->GetPromise();
}

class DefaultSizeAlgorithm final : public StrategySizeAlgorithm {
 public:
  std::optional<double> Run(ScriptState*, v8::Local<v8::Value>) override {
    return 1;
  }
};

class JavaScriptSizeAlgorithm final : public StrategySizeAlgorithm {
 public:
  JavaScriptSizeAlgorithm(v8::Isolate* isolate, v8::Local<v8::Function> size)
      : function_(isolate, size) {}

  std::optional<double> Run(ScriptState* script_state,
                            v8::Local<v8::Value> chunk) override {
    auto* isolate = script_state->GetIsolate();
    auto context = script_state->GetContext();
    v8::Local<v8::Value> argv[] = {chunk};

    // https://streams.spec.whatwg.org/#make-size-algorithm-from-size-function
    // 3.a. Return ? Call(size, undefined, « chunk »).
    v8::MaybeLocal<v8::Value> result_maybe =
        function_.Get(isolate)->Call(context, v8::Undefined(isolate), 1, argv);
    v8::Local<v8::Value> result;
    if (!result_maybe.ToLocal(&result)) {
      return std::nullopt;
    }

    // This conversion to double comes from the EnqueueValueWithSize
    // operation: https://streams.spec.whatwg.org/#enqueue-value-with-size
    // 2. Let size be ? ToNumber(size).
    v8::MaybeLocal<v8::Number> number_maybe = result->ToNumber(context);
    v8::Local<v8::Number> number;
    if (!number_maybe.ToLocal(&number)) {
      return std::nullopt;
    }
    return number->Value();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(function_);
    StrategySizeAlgorithm::Trace(visitor);
  }

 private:
  TraceWrapperV8Reference<v8::Function> function_;
};

class TrivialStreamAlgorithm final : public StreamAlgorithm {
 public:
  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    return ToResolvedUndefinedPromise(script_state);
  }
};

class JavaScriptStreamAlgorithmWithoutExtraArg final : public StreamAlgorithm {
 public:
  JavaScriptStreamAlgorithmWithoutExtraArg(v8::Isolate* isolate,
                                           v8::Local<v8::Function> method,
                                           v8::Local<v8::Object> recv)
      : recv_(isolate, recv), method_(isolate, method) {}

  // |argc| is equivalent to the "algoArgCount" argument to
  // CreateAlgorithmFromUnderlyingMethod() in the standard, but it is
  // determined when the algorithm is called rather than when the algorithm is
  // created.
  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    // This method technically supports any number of arguments, but we only
    // call it with 0 or 1 in practice.
    DCHECK_GE(argc, 0);
    auto* isolate = script_state->GetIsolate();
    // https://streams.spec.whatwg.org/#create-algorithm-from-underlying-method
    // 6.b.i. Return ! PromiseCall(method, underlyingObject, extraArgs).
    // In this class extraArgs is always empty, but there may be other arguments
    // supplied to the method.
    return PromiseCall(script_state, method_.Get(isolate), recv_.Get(isolate),
                       argc, argv);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(recv_);
    visitor->Trace(method_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  TraceWrapperV8Reference<v8::Object> recv_;
  TraceWrapperV8Reference<v8::Function> method_;
};

class JavaScriptStreamAlgorithmWithExtraArg final : public StreamAlgorithm {
 public:
  JavaScriptStreamAlgorithmWithExtraArg(v8::Isolate* isolate,
                                        v8::Local<v8::Function> method,
                                        v8::Local<v8::Value> extra_arg,
                                        v8::Local<v8::Object> recv)
      : recv_(isolate, recv),
        method_(isolate, method),
        extra_arg_(isolate, extra_arg) {}

  // |argc| is equivalent to the "algoArgCount" argument to
  // CreateAlgorithmFromUnderlyingMethod() in the standard,
  ScriptPromise<IDLUndefined> Run(ScriptState* script_state,
                                  int argc,
                                  v8::Local<v8::Value> argv[]) override {
    DCHECK_GE(argc, 0);
    DCHECK_LE(argc, 1);
    auto* isolate = script_state->GetIsolate();
    // https://streams.spec.whatwg.org/#create-algorithm-from-underlying-method
    // 6.c.
    //      i. Let fullArgs be a List consisting of arg followed by the
    //         elements of extraArgs in order.
    std::array<v8::Local<v8::Value>, 2> full_argv;
    if (argc != 0) {
      full_argv[0] = argv[0];
    }
    full_argv[argc] = extra_arg_.Get(isolate);
    int full_argc = argc + 1;

    //     ii. Return ! PromiseCall(method, underlyingObject, fullArgs).
    return PromiseCall(script_state, method_.Get(isolate), recv_.Get(isolate),
                       full_argc, full_argv.data());
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(recv_);
    visitor->Trace(method_);
    visitor->Trace(extra_arg_);
    StreamAlgorithm::Trace(visitor);
  }

 private:
  TraceWrapperV8Reference<v8::Object> recv_;
  TraceWrapperV8Reference<v8::Function> method_;
  TraceWrapperV8Reference<v8::Value> extra_arg_;
};

class JavaScriptByteStreamStartAlgorithm : public StreamStartAlgorithm {
 public:
  JavaScriptByteStreamStartAlgorithm(v8::Isolate* isolate,
                                     v8::Local<v8::Function> method,
                                     v8::Local<v8::Object> recv,
                                     v8::Local<v8::Value> controller)
      : recv_(isolate, recv),
        method_(isolate, method),
        controller_(isolate, controller) {}

  ScriptPromise<IDLUndefined> Run(ScriptState* script_state) override {
    auto* isolate = script_state->GetIsolate();

    v8::Local<v8::Value> controller = controller_.Get(isolate);
    auto value_maybe = method_.Get(isolate)->Call(
        script_state->GetContext(), recv_.Get(isolate), 1, &controller);
    if (isolate->HasPendingException()) {
      return EmptyPromise();
    }

    return ScriptPromise<IDLUndefined>::FromV8Value(
        script_state, value_maybe.ToLocalChecked());
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(recv_);
    visitor->Trace(method_);
    visitor->Trace(controller_);
    StreamStartAlgorithm::Trace(visitor);
  }

 private:
  TraceWrapperV8Reference<v8::Object> recv_;
  TraceWrapperV8Reference<v8::Function> method_;
  TraceWrapperV8Reference<v8::Value> controller_;
};

class JavaScriptStreamStartAlgorithm : public StreamStartAlgorithm {
 public:
  JavaScriptStreamStartAlgorithm(v8::Isolate* isolate,
                                 v8::Local<v8::Object> recv,
                                 const char* method_name_for_error,
                                 v8::Local<v8::Value> controller)
      : recv_(isolate, recv),
        method_name_for_error_(method_name_for_error),
        controller_(isolate, controller) {}

  ScriptPromise<IDLUndefined> Run(ScriptState* script_state) override {
    auto* isolate = script_state->GetIsolate();
    // https://streams.spec.whatwg.org/#set-up-writable-stream-default-controller-from-underlying-sink
    // 3. Let startAlgorithm be the following steps:
    //    a. Return ? InvokeOrNoop(underlyingSink, "start", « controller »).
    auto value_maybe = CallOrNoop1(
        script_state, recv_.Get(isolate), "start", method_name_for_error_,
        controller_.Get(isolate), PassThroughException(isolate));
    if (isolate->HasPendingException()) {
      return EmptyPromise();
    }
    return ScriptPromise<IDLUndefined>::FromV8Value(
        script_state, value_maybe.ToLocalChecked());
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(recv_);
    visitor->Trace(controller_);
    StreamStartAlgorithm::Trace(visitor);
  }

 private:
  TraceWrapperV8Reference<v8::Object> recv_;
  const char* const method_name_for_error_;
  TraceWrapperV8Reference<v8::Value> controller_;
};

class TrivialStartAlgorithm : public StreamStartAlgorithm {
 public:
  ScriptPromise<IDLUndefined> Run(ScriptState* script_state) override {
    return ToResolvedUndefinedPromise(script_state);
  }
};

}  // namespace

// TODO(ricea): For optimal performance, method_name should be cached as an
// atomic v8::String. It's not clear who should own the cache.
CORE_EXPORT StreamAlgorithm* CreateAlgorithmFromUnderlyingMethod(
    ScriptState* script_state,
    v8::Local<v8::Object> underlying_object,
    const char* method_name,
    const char* method_name_for_error,
    v8::MaybeLocal<v8::Value> extra_arg,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#create-algorithm-from-underlying-method
  // 5. Let method be ? GetV(underlyingObject, methodName).
  // 6. If method is not undefined,
  //    a. If ! IsCallable(method) is false, throw a TypeError exception.
  v8::MaybeLocal<v8::Value> method_maybe =
      ResolveMethod(script_state, underlying_object, method_name,
                    method_name_for_error, exception_state);
  v8::Local<v8::Value> method;
  if (!method_maybe.ToLocal(&method)) {
    DCHECK(exception_state.HadException());
    return nullptr;
  }

  if (method->IsUndefined()) {
    // 7. Return an algorithm which returns a promise resolved with undefined.
    return MakeGarbageCollected<TrivialStreamAlgorithm>();
  }

  return CreateAlgorithmFromResolvedMethod(script_state, underlying_object,
                                           method, extra_arg);
}

CORE_EXPORT v8::MaybeLocal<v8::Value> ResolveMethod(
    ScriptState* script_state,
    v8::Local<v8::Object> object,
    const char* method_name,
    const char* name_for_error,
    ExceptionState& exception_state) {
  auto* isolate = script_state->GetIsolate();
  TryRethrowScope rethrow_scope(isolate, exception_state);

  // Algorithm steps from CreateAlgorithmFromUnderlyingMethod in the standard.
  // https://streams.spec.whatwg.org/#create-algorithm-from-underlying-method
  // 5. Let method be ? GetV(underlyingObject, methodName).
  auto method_maybe = object->Get(script_state->GetContext(),
                                  V8AtomicString(isolate, method_name));
  v8::Local<v8::Value> method;
  if (!method_maybe.ToLocal(&method)) {
    return v8::MaybeLocal<v8::Value>();
  }

  // 6. If method is not undefined,
  //    a. If ! IsCallable(method) is false, throw a TypeError exception.
  if (!method->IsFunction() && !method->IsUndefined()) {
    exception_state.ThrowTypeError(String(name_for_error) +
                                   " must be a function or undefined");
    return v8::MaybeLocal<v8::Value>();
  }

  return method;
}

CORE_EXPORT StreamAlgorithm* CreateAlgorithmFromResolvedMethod(
    ScriptState* script_state,
    v8::Local<v8::Object> underlying_object,
    v8::Local<v8::Value> method,
    v8::MaybeLocal<v8::Value> extra_arg) {
  DCHECK(method->IsFunction());

  auto* isolate = script_state->GetIsolate();

  // The standard switches on the number of arguments to be passed to the
  // algorithm, but this implementation doesn't care about that. Instead we
  // switch on whether or not there is an extraArg, as that decides whether or
  // not we need to reconstruct the argument list at runtime.
  v8::Local<v8::Value> extra_arg_local;
  if (!extra_arg.ToLocal(&extra_arg_local)) {
    return MakeGarbageCollected<JavaScriptStreamAlgorithmWithoutExtraArg>(
        isolate, method.As<v8::Function>(), underlying_object);
  }

  return MakeGarbageCollected<JavaScriptStreamAlgorithmWithExtraArg>(
      isolate, method.As<v8::Function>(), extra_arg_local, underlying_object);
}

CORE_EXPORT StreamStartAlgorithm* CreateStartAlgorithm(
    ScriptState* script_state,
    v8::Local<v8::Object> underlying_object,
    const char* method_name_for_error,
    v8::Local<v8::Value> controller) {
  return MakeGarbageCollected<JavaScriptStreamStartAlgorithm>(
      script_state->GetIsolate(), underlying_object, method_name_for_error,
      controller);
}

CORE_EXPORT StreamStartAlgorithm* CreateByteStreamStartAlgorithm(
    ScriptState* script_state,
    v8::Local<v8::Object> underlying_object,
    v8::Local<v8::Value> method,
    v8::Local<v8::Value> controller) {
  return MakeGarbageCollected<JavaScriptByteStreamStartAlgorithm>(
      script_state->GetIsolate(), method.As<v8::Function>(), underlying_object,
      controller);
}

CORE_EXPORT StreamStartAlgorithm* CreateTrivialStartAlgorithm() {
  return MakeGarbageCollected<TrivialStartAlgorithm>();
}

CORE_EXPORT StreamAlgorithm* CreateTrivialStreamAlgorithm() {
  return MakeGarbageCollected<TrivialStreamAlgorithm>();
}

CORE_EXPORT ScriptValue CreateTrivialQueuingStrategy(v8::Isolate* isolate,
                                                     size_t high_water_mark) {
  v8::Local<v8::Name> high_water_mark_string =
      V8AtomicString(isolate, "highWaterMark");
  v8::Local<v8::Value> high_water_mark_value =
      v8::Number::New(isolate, high_water_mark);

  auto strategy =
      v8::Object::New(isolate, v8::Null(isolate), &high_water_mark_string,
                      &high_water_mark_value, 1);

  return ScriptValue(isolate, strategy);
}

CORE_EXPORT v8::MaybeLocal<v8::Value> CallOrNoop1(
    ScriptState* script_state,
    v8::Local<v8::Object> object,
    const char* method_name,
    const char* name_for_error,
    v8::Local<v8::Value> arg0,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#invoke-or-noop
  // 4. Let method be ? GetV(O, P).
  v8::MaybeLocal<v8::Value> method_maybe = ResolveMethod(
      script_state, object, method_name, name_for_error, exception_state);
  v8::Local<v8::Value> method;
  if (!method_maybe.ToLocal(&method)) {
    DCHECK(exception_state.HadException());
    return v8::MaybeLocal<v8::Value>();
  }

  // 5. If method is undefined, return undefined.
  if (method->IsUndefined()) {
    return v8::Undefined(script_state->GetIsolate());
  }
  DCHECK(method->IsFunction());

  // 6. Return ? Call(method, O, args).
  TryRethrowScope rethrow_scope(script_state->GetIsolate(), exception_state);
  return method.As<v8::Function>()->Call(script_state->GetContext(), object, 1,
                                         &arg0);
}

CORE_EXPORT ScriptPromise<IDLUndefined> PromiseCall(
    ScriptState* script_state,
    v8::Local<v8::Function> method,
    v8::Local<v8::Object> recv,
    int argc,
    v8::Local<v8::Value> argv[]) {
  DCHECK_GE(argc, 0);
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::TryCatch trycatch(isolate);
  v8::MicrotasksScope microtasks_scope(
      isolate, ToMicrotaskQueue(script_state),
      v8::MicrotasksScope::kDoNotRunMicrotasks);

  // https://streams.spec.whatwg.org/#promise-call
  // 4. Let returnValue be Call(F, V, args).
  v8::MaybeLocal<v8::Value> result_maybe =
      method->Call(script_state->GetContext(), recv, argc, argv);

  v8::Local<v8::Value> result;
  // 5. If returnValue is an abrupt completion, return a promise rejected with
  //    returnValue.[[Value]].
  if (!result_maybe.ToLocal(&result)) {
    return ScriptPromise<IDLUndefined>::Reject(script_state,
                                               trycatch.Exception());
  }

  // 6. Otherwise, return a promise resolved with returnValue.[[Value]].
  return ScriptPromise<IDLUndefined>::FromV8Value(script_state, result);
}

CORE_EXPORT double ValidateAndNormalizeHighWaterMark(
    double high_water_mark,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#validate-and-normalize-high-water-mark
  // 2. If highWaterMark is NaN or highWaterMark < 0, throw a RangeError
  //    exception.
  if (isnan(high_water_mark) || high_water_mark < 0) {
    exception_state.ThrowRangeError(
        "A queuing strategy's highWaterMark property must be a nonnegative, "
        "non-NaN number");
    return 0;
  }

  // 3. Return highWaterMark.
  return high_water_mark;
}

CORE_EXPORT StrategySizeAlgorithm* MakeSizeAlgorithmFromSizeFunction(
    ScriptState* script_state,
    v8::Local<v8::Value> size,
    ExceptionState& exception_state) {
  // 1. If size is undefined, return an algorithm that returns 1.
  if (size->IsUndefined()) {
    return MakeGarbageCollected<DefaultSizeAlgorithm>();
  }

  // 2. If ! IsCallable(size) is false, throw a TypeError exception.
  if (!size->IsFunction()) {
    exception_state.ThrowTypeError(
        "A queuing strategy's size property must be a function");
    return nullptr;
  }

  // 3. Return an algorithm that performs the following steps, taking a chunk
  // argument:
  //    a. Return ? Call(size, undefined, « chunk »).
  return MakeGarbageCollected<JavaScriptSizeAlgorithm>(
      script_state->GetIsolate(), size.As<v8::Function>());
}

CORE_EXPORT StrategySizeAlgorithm* CreateDefaultSizeAlgorithm() {
  return MakeGarbageCollected<DefaultSizeAlgorithm>();
}

// PromiseResolve implements Promise.resolve(_x_) from the ECMASCRIPT standard,
// https://tc39.github.io/ecma262/#sec-promise.resolve, except that the
// Get(_x_, "constructor") step is skipped.
CORE_EXPORT v8::Local<v8::Promise> PromiseResolve(ScriptState* script_state,
                                                  v8::Local<v8::Value> value) {
  if (value->IsPromise()) {
    return value.As<v8::Promise>();
  }
  auto context = script_state->GetContext();
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::MicrotasksScope microtasks_scope(
      isolate, ToMicrotaskQueue(script_state),
      v8::MicrotasksScope::kDoNotRunMicrotasks);
  v8::TryCatch trycatch(isolate);
  // TODO(ricea): Can this fail for reasons other than memory exhaustion? Can we
  // recover if it does?
  auto resolver = v8::Promise::Resolver::New(context).ToLocalChecked();
  if (resolver->Resolve(context, value).IsNothing()) {
    // TODO(ricea): Is this actually reachable?
    return PromiseReject(script_state, trycatch.Exception());
  }
  return resolver->GetPromise();
}

CORE_EXPORT v8::Local<v8::Promise> PromiseResolveWithUndefined(
    ScriptState* script_state) {
  return PromiseResolve(script_state,
                        v8::Undefined(script_state->GetIsolate()));
}

CORE_EXPORT v8::Local<v8::Promise> PromiseReject(ScriptState* script_state,
                                                 v8::Local<v8::Value> value) {
  return PromiseRejectInternal(script_state, value, 0);
}

void ScriptValueToObject(ScriptState* script_state,
                         ScriptValue value,
                         v8::Local<v8::Object>* object,
                         ExceptionState& exception_state) {
  auto* isolate = script_state->GetIsolate();
  DCHECK(!value.IsEmpty());
  auto v8_value = value.V8Value();
  // All the object parameters in the standard are default-initialised to an
  // empty object.
  if (v8_value->IsUndefined()) {
    *object = v8::Object::New(isolate);
    return;
  }
  TryRethrowScope rethrow_scope(isolate, exception_state);
  std::ignore = v8_value->ToObject(script_state->GetContext()).ToLocal(object);
}

StrategyUnpacker::StrategyUnpacker(ScriptState* script_state,
                                   ScriptValue strategy,
                                   ExceptionState& exception_state) {
  auto* isolate = script_state->GetIsolate();
  auto context = script_state->GetContext();
  v8::Local<v8::Object> strategy_object;
  ScriptValueToObject(script_state, strategy, &strategy_object,
                      exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // This is used in several places. The steps here are taken from
  // https://streams.spec.whatwg.org/#ws-constructor.
  // 2. Let size be ? GetV(strategy, "size").
  TryRethrowScope rethrow_scope(isolate, exception_state);
  if (!strategy_object->Get(context, V8AtomicString(isolate, "size"))
           .ToLocal(&size_)) {
    return;
  }

  // 3. Let highWaterMark be ? GetV(strategy, "highWaterMark").
  if (!strategy_object->Get(context, V8AtomicString(isolate, "highWaterMark"))
           .ToLocal(&high_water_mark_)) {
    return;
  }
}

StrategySizeAlgorithm* StrategyUnpacker::MakeSizeAlgorithm(
    ScriptState* script_state,
    ExceptionState& exception_state) const {
  DCHECK(!size_.IsEmpty());
  // 6. Let sizeAlgorithm be ? MakeSizeAlgorithmFromSizeFunction(size).
  return MakeSizeAlgorithmFromSizeFunction(script_state, size_,
                                           exception_state);
}

double StrategyUnpacker::GetHighWaterMark(
    ScriptState* script_state,
    int default_value,
    ExceptionState& exception_state) const {
  DCHECK(!high_water_mark_.IsEmpty());
  // 7. If highWaterMark is undefined, let highWaterMark be 1.
  if (high_water_mark_->IsUndefined()) {
    return default_value;
  }

  TryRethrowScope rethrow_scope(script_state->GetIsolate(), exception_state);
  v8::Local<v8::Number> high_water_mark_as_number;
  if (!high_water_mark_->ToNumber(script_state->GetContext())
           .ToLocal(&high_water_mark_as_number)) {
    return 0.0;
  }

  // 8. Set highWaterMark to ? ValidateAndNormalizeHighWaterMark(highWaterMark)
  return ValidateAndNormalizeHighWaterMark(high_water_mark_as_number->Value(),
                                           exception_state);
}

bool StrategyUnpacker::IsSizeUndefined() const {
  return size_->IsUndefined();
}

}  // namespace blink
```