Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Subject:** The filename `transform_stream_test.cc` immediately tells us this file tests the `TransformStream` class within the Blink rendering engine.

2. **Understand the Purpose of Testing:**  Test files verify the functionality of a particular piece of code. They aim to cover various scenarios, including successful operations, error conditions, and edge cases.

3. **Scan for Key Components and Concepts:**  Look for familiar terms and data structures related to streams and JavaScript interactions:
    * `TransformStream`, `ReadableStream`, `WritableStream`: These are the central classes being tested.
    * `TransformStreamTransformer`:  This suggests a mechanism for customizing the transformation process.
    * `Transform`, `Flush`, `enqueue`: These are likely methods involved in the transformation process.
    * `ScriptState`, `ScriptPromise`, `ScriptValue`: These indicate interaction with JavaScript and asynchronous operations.
    * `V8TestingScope`, `EvalWithPrintingError`: These suggest the use of V8, the JavaScript engine, for testing.
    * `MockTransformStreamTransformer`: This signals the use of mocking for testing specific interactions.
    * `ASSERT_NO_EXCEPTION`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_CALL`: These are standard testing macros from Google Test, indicating assertions and expectations about the code's behavior.

4. **Analyze the Test Structure:**  Notice the use of `TEST_F`. This signifies the use of Google Test fixtures, allowing for shared setup (`Init`, `CopyReadableAndWritableToGlobal`). The individual tests (`Construct`, `Accessors`, `TransformIsCalled`, etc.) each target a specific aspect of `TransformStream` functionality.

5. **Deconstruct Individual Tests:**  For each test case, consider:
    * **Setup:** What objects are being created and initialized?  What initial state is being established?
    * **Action:** What function or operation is being performed on the `TransformStream`?  This often involves interacting with the `readable` and `writable` ends via JavaScript code using `EvalWithPrintingError`.
    * **Assertion:** What is being checked to verify the expected outcome?  This often uses `EXPECT_TRUE`, `EXPECT_FALSE`, or checks against mocked objects using `EXPECT_CALL`.

6. **Identify Relationships to Web Technologies (JavaScript, HTML, CSS):**
    * The presence of `ScriptState`, `ScriptPromise`, and the use of `EvalWithPrintingError` strongly indicate interaction with JavaScript. The tests are essentially exercising the JavaScript API for `TransformStream`.
    * While the tests themselves don't directly involve HTML or CSS, `TransformStream` is a fundamental building block for processing streaming data, which is relevant in various web contexts (e.g., handling network responses, processing media streams). *Initial thought might be that there's no direct link, but a more nuanced understanding recognizes the underlying purpose.*

7. **Infer Logic and Reasoning:**  Look for patterns in the test cases:
    * Testing construction and basic property access.
    * Verifying that `Transform` and `Flush` callbacks are invoked at the appropriate times.
    * Checking how data is enqueued and read from the stream.
    * Testing error handling (throwing exceptions from `Transform` and `Flush`).
    * Exploring asynchronous behavior using promises.

8. **Consider User/Programming Errors:** Analyze scenarios that might lead to incorrect usage:
    * Not handling errors thrown in `Transform` or `Flush`.
    * Incorrectly managing backpressure.
    * Expecting synchronous behavior when the operations are asynchronous.

9. **Trace User Operations to Reach the Code:**  Think about how a user's actions in a web browser could trigger the execution of this code:
    * A JavaScript application using the `TransformStream` API to process data.
    * Fetching data using `fetch()` and piping it through a transform stream.
    * Processing media streams.
    * In essence, any scenario where JavaScript utilizes the Streams API and a transform stream is involved.

10. **Refine and Organize:**  Structure the findings into clear categories (Functionality, Relationship to Web Tech, Logic/Reasoning, Usage Errors, Debugging). Provide concrete examples to illustrate each point.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This file just tests C++ code."  **Correction:** While it *is* C++ test code, it's specifically testing the *implementation* of a web API (`TransformStream`) that is directly accessible from JavaScript. The tests use JavaScript code to interact with the C++ implementation.
* **Initial thought:** "The tests are purely internal." **Correction:** The tests simulate real-world usage by mimicking how a JavaScript developer would interact with `TransformStream`. This makes the tests more valuable for ensuring the API works as intended.
* **Missing link:**  Initially, I might not have immediately connected `TransformStream` to specific web use cases like `fetch()` or media streams. **Refinement:**  By understanding the broader purpose of streams in web development, the connection becomes clearer.

By following these steps and engaging in this kind of detailed analysis, we can effectively understand the purpose and functionality of a complex code file like the one provided.
这个文件 `transform_stream_test.cc` 是 Chromium Blink 引擎中用于测试 `TransformStream` 类的单元测试文件。它的主要功能是验证 `TransformStream` 类的各种行为和功能是否符合预期。

**以下是该文件的功能详细列表：**

1. **构造测试 (Construct):**
   - 测试 `TransformStream` 对象能否成功创建。
   - 使用 `IdentityTransformer` (一个简单的透传转换器) 进行初始化。
   - **假设输入:** 一个 `IdentityTransformer` 实例。
   - **预期输出:**  `TransformStream` 对象被成功创建。

2. **访问器测试 (Accessors):**
   - 测试 `TransformStream` 对象是否能正确返回其关联的 `ReadableStream` 和 `WritableStream` 对象。
   - **假设输入:** 一个已创建的 `TransformStream` 对象。
   - **预期输出:** 可以成功获取到非空的 `ReadableStream` 和 `WritableStream` 对象。

3. **`Transform` 方法调用测试 (TransformIsCalled):**
   - 测试当有数据写入 `TransformStream` 的 `WritableStream` 时，其内部的 `Transform` 方法是否会被调用。
   - 使用 `MockTransformStreamTransformer` 模拟转换器，并使用 `EXPECT_CALL` 验证 `Transform` 方法是否被调用。
   - **与 JavaScript 关系:**  `TransformStream` 在 JavaScript 中通过 `TransformStream` 构造函数创建，并通过其 `writable` 属性获取 `WritableStream`，使用 `WritableStream` 的 `getWriter().write()` 方法写入数据会触发此测试验证的逻辑。
   - **假设输入:**  向 `writable` 端写入数据。
   - **预期输出:**  模拟的转换器的 `Transform` 方法被调用。
   - **用户/编程常见错误:**  假设用户创建了一个 `TransformStream`，但其 `transform` 函数没有被正确执行，这个测试可以帮助开发者发现这类问题。

4. **`Flush` 方法调用测试 (FlushIsCalled):**
   - 测试当 `TransformStream` 的 `WritableStream` 被关闭时，其内部的 `Flush` 方法是否会被调用。
   - 同样使用 `MockTransformStreamTransformer` 模拟转换器，并验证 `Flush` 方法的调用。
   - **与 JavaScript 关系:** JavaScript 代码中调用 `writable.getWriter().close()` 会触发此测试。
   - **假设输入:**  关闭 `writable` 端。
   - **预期输出:**  模拟的转换器的 `Flush` 方法被调用。

5. **`Transform` 中入队数据测试 (EnqueueFromTransform):**
   - 测试在 `Transform` 方法中通过 `controller.enqueue()` 向可读端写入数据后，这些数据能否被成功读取。
   - 使用 `IdentityTransformer`，它会将接收到的数据直接入队到可读端。
   - **与 JavaScript 关系:**  JavaScript 代码可以通过 `readable.getReader().read()` 读取到 `Transform` 函数处理后的数据。
   - **假设输入:**  向 `writable` 端写入字符串 "a"。
   - **预期输出:**  从 `readable` 端读取到的数据是 "a"。

6. **`Flush` 中入队数据测试 (EnqueueFromFlush):**
   - 测试在 `Flush` 方法中通过 `controller.enqueue()` 向可读端写入数据后，这些数据能否在 `WritableStream` 关闭后被成功读取。
   - 创建一个自定义的 `EnqueueFromFlushTransformer`，在 `Flush` 方法中入队数据。
   - **与 JavaScript 关系:**  用户关闭 `writable` 后，期望 `flush` 函数能够添加一些最终的数据到 `readable` 端。
   - **假设输入:**  关闭 `writable` 端。
   - **预期输出:**  从 `readable` 端读取到的数据是在 `flush` 函数中入队的数据 "a"。

7. **`Transform` 中抛出异常测试 (ThrowFromTransform):**
   - 测试当 `Transform` 方法抛出异常时，`WritableStream` 的写入操作和 `ReadableStream` 的读取操作会如何处理。
   - 创建一个 `ThrowFromTransformTransformer`，使其在 `Transform` 方法中抛出 `TypeError`。
   - **与 JavaScript 关系:**  这模拟了 JavaScript 中 `transform` 函数发生错误的情况，浏览器需要正确地将错误传递到 `writable` 和 `readable` 的 promise 中。
   - **假设输入:**  向 `writable` 端写入数据。
   - **预期输出:**  `writable.getWriter().write()` 返回的 Promise 被拒绝，`readable.getReader().read()` 返回的 Promise 也被拒绝，并且错误类型是 `TypeError`，错误信息是 "errorInTransform"。
   - **用户/编程常见错误:**  如果用户的 `transform` 函数中存在未捕获的异常，这个测试验证了浏览器是否能正确处理这种情况，防止程序崩溃或出现未定义的行为。

8. **`Flush` 中抛出异常测试 (ThrowFromFlush):**
   - 测试当 `Flush` 方法抛出异常时，`WritableStream` 的关闭操作和 `ReadableStream` 的读取操作会如何处理。
   - 创建一个 `ThrowFromFlushTransformer`，使其在 `Flush` 方法中抛出 `TypeError`。
   - **与 JavaScript 关系:**  模拟 JavaScript 中 `flush` 函数发生错误。
   - **假设输入:**  关闭 `writable` 端。
   - **预期输出:**  `writable.getWriter().close()` 返回的 Promise 被拒绝，`readable.getReader().read()` 返回的 Promise 也被拒绝，错误类型为 `TypeError`，错误信息是 "errorInFlush"。

9. **从 `ReadableStream` 和 `WritableStream` 对创建测试 (CreateFromReadableWritablePair):**
   - 测试能否直接使用已有的 `ReadableStream` 和 `WritableStream` 对象创建 `TransformStream`。
   - **与 JavaScript 关系:**  虽然 JavaScript 标准中没有直接提供这种创建方式，但在 Blink 内部可能存在这种需求。
   - **假设输入:**  一个 `ReadableStream` 对象和一个 `WritableStream` 对象。
   - **预期输出:**  成功创建 `TransformStream` 对象，并且其 `readable` 和 `writable` 属性指向传入的对象。

10. **`Transform` 中等待 Promise 测试 (WaitInTransform):**
    - 测试当 `Transform` 方法返回一个未完成的 Promise 时，`WritableStream` 的写入操作会如何等待。
    - 创建一个 `WaitInTransformTransformer`，其 `Transform` 方法返回一个由 `ScriptPromiseResolver` 控制的 Promise。
    - **与 JavaScript 关系:**  模拟 `transform` 函数中执行异步操作，例如发起网络请求，需要在 Promise 完成后才能继续处理。
    - **假设输入:**  向 `writable` 端写入数据并关闭 `writable` 端。
    - **预期输出:**  `writer.write()` 返回的 Promise 在 `Transform` 方法中的 Promise resolve 之前不会完成，`Flush` 方法也不会被调用。当 `Transform` 中的 Promise resolve 后，`writer.write()` 的 Promise 完成，并且 `Flush` 方法被调用。
    - **用户/编程常见错误:**  如果用户的 `transform` 函数返回的 Promise 没有被正确 resolve 或 reject，可能会导致流永远处于等待状态。

11. **`Flush` 中等待 Promise 测试 (WaitInFlush):**
    - 测试当 `Flush` 方法返回一个未完成的 Promise 时，`WritableStream` 的关闭操作会如何等待。
    - 创建一个 `WaitInFlushTransformer`，其 `Flush` 方法返回一个未完成的 Promise。
    - **与 JavaScript 关系:**  模拟 `flush` 函数中执行异步的清理操作。
    - **假设输入:**  关闭 `writable` 端。
    - **预期输出:**  `writer.close()` 返回的 Promise 在 `Flush` 方法中的 Promise resolve 之前不会完成。当 `Flush` 中的 Promise resolve 后，`writer.close()` 的 Promise 完成。

**与 JavaScript, HTML, CSS 的关系举例说明:**

- **JavaScript:**  `TransformStream` 是 JavaScript Streams API 的一部分。开发者可以在 JavaScript 中创建 `TransformStream` 实例，并通过其 `readable` 和 `writable` 属性与数据流进行交互。例如，可以使用 `fetch()` API 获取数据，并通过 `pipeThrough()` 方法将其管道到一个 `TransformStream` 进行处理，然后再管道到另一个流进行进一步操作或显示。
  ```javascript
  fetch('data.txt')
    .then(response => {
      const transformStream = new TransformStream({
        transform(chunk, controller) {
          const transformedChunk = chunk.toUpperCase(); // 简单转换
          controller.enqueue(transformedChunk);
        }
      });
      return response.body.pipeThrough(transformStream);
    })
    .then(transformedReadable => {
      const reader = transformedReadable.getReader();
      return reader.read();
    })
    .then(result => {
      console.log(result.value); // 输出大写后的数据
    });
  ```

- **HTML:** `TransformStream` 本身不直接操作 HTML 元素，但它可以用于处理从 HTML 元素（如 `<video>` 或 `<audio>` 的 MediaStreamTrack）获取的数据，或者用于生成动态的 HTML 内容。

- **CSS:** `TransformStream` 与 CSS 没有直接的功能关系。

**逻辑推理的假设输入与输出:**

例如，在 `EnqueueFromTransform` 测试中：

- **假设输入:**  JavaScript 代码执行 `writer.write('a');` 将字符串 "a" 写入 `TransformStream` 的 `writable` 端。
- **逻辑推理:**  由于使用了 `IdentityTransformer`，其 `transform` 函数会将接收到的 chunk 直接通过 `controller.enqueue()` 发送到 `readable` 端。
- **预期输出:**  JavaScript 代码执行 `readable.getReader().read()` 将会读取到包含字符串 "a" 的结果。

**用户或编程常见的使用错误举例说明:**

1. **未处理 `Transform` 或 `Flush` 中抛出的异常:** 如果开发者在 `transform` 或 `flush` 函数中编写了可能抛出异常的代码，但没有使用 `try...catch` 或返回 rejected 的 Promise 进行处理，会导致流的异常传播，可能会影响到后续的数据处理或引发程序错误。测试用例 `ThrowFromTransform` 和 `ThrowFromFlush` 就是为了验证 Blink 引擎在这种情况下是否能正确处理。

2. **错误地管理背压 (Backpressure):**  `TransformStream` 具有背压机制，当可读端消费数据的速度慢于写入端生产数据的速度时，会产生背压。如果开发者在 `transform` 函数中没有正确处理背压信号，例如没有等待之前的 `enqueue` 操作完成就继续处理新的 chunk，可能会导致内存溢出或数据丢失。虽然这个测试文件没有直接测试背压，但 `WaitInTransform` 可以看作是与异步处理相关的一个方面。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为一个 Chromium 开发者，在开发或调试与 `TransformStream` 相关的特性时，可能会遇到一些问题，导致需要查看或修改 `transform_stream_test.cc` 文件。以下是一些可能的用户操作路径：

1. **修改或添加 Streams API 相关的功能:**  当需要在 Blink 引擎中修改或添加与 Streams API（包括 `TransformStream`）相关的功能时，开发者需要编写或修改 C++ 代码来实现这些功能，并编写相应的单元测试来验证其正确性。`transform_stream_test.cc` 就是用于此目的的文件。

2. **修复 Streams API 相关的 Bug:**  如果在 Chromium 的测试或使用过程中发现了与 `TransformStream` 相关的 bug，开发者需要定位问题代码，进行修复，并编写新的测试用例或修改现有的测试用例来覆盖该 bug 的场景，防止其再次发生。

3. **性能优化:**  对 `TransformStream` 的性能进行优化后，可能需要修改测试用例来衡量优化效果，或者添加新的性能测试。

4. **代码审查:**  在代码审查过程中，reviewer 可能会查看测试文件以确保新提交的代码具有足够的测试覆盖率。

**调试线索:**

当测试用例失败时，开发者可以根据以下线索进行调试：

- **失败的测试用例名称:**  明确指出哪个测试用例失败，可以帮助定位到需要检查的具体功能点。
- **测试用例中的断言 (ASSERT/EXPECT):**  查看失败的断言，了解期望的结果和实际的结果之间的差异。
- **测试用例中模拟的 JavaScript 代码:**  理解测试用例中执行的 JavaScript 代码是如何与 C++ 代码交互的，可以帮助理解问题的触发路径。
- **逐步调试 C++ 代码:**  使用调试器（如 gdb）逐步执行 `TransformStream` 相关的 C++ 代码，观察变量的值和程序的执行流程，找出与预期不符的地方。
- **查看日志输出:**  Blink 引擎通常会有详细的日志输出，可以帮助开发者了解程序运行时的状态。

总而言之，`transform_stream_test.cc` 是 Blink 引擎中至关重要的一个测试文件，它确保了 `TransformStream` 类的功能正确性和稳定性，对于保证 Chromium 浏览器的 Web 标准兼容性和功能完整性起着关键作用。

Prompt: 
```
这是目录为blink/renderer/core/streams/transform_stream_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/streams/transform_stream.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/iterable.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream_read_result.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/test_utils.h"
#include "third_party/blink/renderer/core/streams/transform_stream_default_controller.h"
#include "third_party/blink/renderer/core/streams/transform_stream_transformer.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

using ::testing::_;
using ::testing::ByMove;
using ::testing::Mock;
using ::testing::Return;

class TransformStreamTest : public ::testing::Test {
 public:
  TransformStreamTest() = default;

  TransformStream* Stream() const { return stream_; }

  void Init(TransformStreamTransformer* transformer,
            ScriptState* script_state,
            ExceptionState& exception_state) {
    stream_ =
        TransformStream::Create(script_state, transformer, exception_state);
  }

  // This takes the |readable| and |writable| properties of the TransformStream
  // and copies them onto the global object so they can be accessed by Eval().
  void CopyReadableAndWritableToGlobal(const V8TestingScope& scope) {
    auto* script_state = scope.GetScriptState();
    ReadableStream* readable = Stream()->Readable();
    WritableStream* writable = Stream()->Writable();
    v8::Local<v8::Object> global = script_state->GetContext()->Global();
    EXPECT_TRUE(
        global
            ->Set(scope.GetContext(), V8String(scope.GetIsolate(), "readable"),
                  ToV8Traits<ReadableStream>::ToV8(script_state, readable))
            .IsJust());
    EXPECT_TRUE(
        global
            ->Set(scope.GetContext(), V8String(scope.GetIsolate(), "writable"),
                  ToV8Traits<WritableStream>::ToV8(script_state, writable))
            .IsJust());
  }

 private:
  test::TaskEnvironment task_environment_;
  Persistent<TransformStream> stream_;
};

// A convenient base class to make tests shorter. Subclasses need not implement
// both Transform() and Flush(), and can override the void versions to avoid the
// need to create a promise to return. Not appropriate for use in production.
class TestTransformer : public TransformStreamTransformer {
 public:
  explicit TestTransformer(ScriptState* script_state)
      : script_state_(script_state) {}

  virtual void TransformVoid(v8::Local<v8::Value>,
                             TransformStreamDefaultController*,
                             ExceptionState&) {}

  ScriptPromise<IDLUndefined> Transform(
      v8::Local<v8::Value> chunk,
      TransformStreamDefaultController* controller,
      ExceptionState& exception_state) override {
    TransformVoid(chunk, controller, exception_state);
    return ToResolvedUndefinedPromise(script_state_.Get());
  }

  virtual void FlushVoid(TransformStreamDefaultController*, ExceptionState&) {}

  ScriptPromise<IDLUndefined> Flush(
      TransformStreamDefaultController* controller,
      ExceptionState& exception_state) override {
    FlushVoid(controller, exception_state);
    return ToResolvedUndefinedPromise(script_state_.Get());
  }

  ScriptState* GetScriptState() override { return script_state_.Get(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(script_state_);
    TransformStreamTransformer::Trace(visitor);
  }

 private:
  const Member<ScriptState> script_state_;
};

class IdentityTransformer final : public TestTransformer {
 public:
  explicit IdentityTransformer(ScriptState* script_state)
      : TestTransformer(script_state) {}

  void TransformVoid(v8::Local<v8::Value> chunk,
                     TransformStreamDefaultController* controller,
                     ExceptionState& exception_state) override {
    controller->enqueue(GetScriptState(),
                        ScriptValue(GetScriptState()->GetIsolate(), chunk),
                        exception_state);
  }
};

class MockTransformStreamTransformer : public TransformStreamTransformer {
 public:
  explicit MockTransformStreamTransformer(ScriptState* script_state)
      : script_state_(script_state) {}

  MOCK_METHOD3(Transform,
               ScriptPromise<IDLUndefined>(v8::Local<v8::Value> chunk,
                                           TransformStreamDefaultController*,
                                           ExceptionState&));
  MOCK_METHOD2(Flush,
               ScriptPromise<IDLUndefined>(TransformStreamDefaultController*,
                                           ExceptionState&));

  ScriptState* GetScriptState() override { return script_state_.Get(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(script_state_);
    TransformStreamTransformer::Trace(visitor);
  }

 private:
  const Member<ScriptState> script_state_;
};

// If this doesn't work then nothing else will.
TEST_F(TransformStreamTest, Construct) {
  V8TestingScope scope;
  Init(MakeGarbageCollected<IdentityTransformer>(scope.GetScriptState()),
       scope.GetScriptState(), ASSERT_NO_EXCEPTION);
  EXPECT_TRUE(Stream());
}

TEST_F(TransformStreamTest, Accessors) {
  V8TestingScope scope;
  Init(MakeGarbageCollected<IdentityTransformer>(scope.GetScriptState()),
       scope.GetScriptState(), ASSERT_NO_EXCEPTION);
  ReadableStream* readable = Stream()->Readable();
  WritableStream* writable = Stream()->Writable();
  EXPECT_TRUE(readable);
  EXPECT_TRUE(writable);
}

TEST_F(TransformStreamTest, TransformIsCalled) {
  V8TestingScope scope;
  auto* mock = MakeGarbageCollected<MockTransformStreamTransformer>(
      scope.GetScriptState());
  Init(mock, scope.GetScriptState(), ASSERT_NO_EXCEPTION);
  // Need to run microtasks so the startAlgorithm promise resolves.
  scope.PerformMicrotaskCheckpoint();
  CopyReadableAndWritableToGlobal(scope);

  EXPECT_CALL(*mock, Transform(_, _, _))
      .WillOnce(
          Return(ByMove(ToResolvedUndefinedPromise(scope.GetScriptState()))));

  // The initial read is needed to relieve backpressure.
  EvalWithPrintingError(&scope,
                        "readable.getReader().read();\n"
                        "const writer = writable.getWriter();\n"
                        "writer.write('a');\n");

  Mock::VerifyAndClear(mock);
  Mock::AllowLeak(mock);
}

TEST_F(TransformStreamTest, FlushIsCalled) {
  V8TestingScope scope;
  auto* mock = MakeGarbageCollected<MockTransformStreamTransformer>(
      scope.GetScriptState());
  Init(mock, scope.GetScriptState(), ASSERT_NO_EXCEPTION);
  // Need to run microtasks so the startAlgorithm promise resolves.
  scope.PerformMicrotaskCheckpoint();
  CopyReadableAndWritableToGlobal(scope);

  EXPECT_CALL(*mock, Flush(_, _))
      .WillOnce(
          Return(ByMove(ToResolvedUndefinedPromise(scope.GetScriptState()))));

  EvalWithPrintingError(&scope,
                        "const writer = writable.getWriter();\n"
                        "writer.close();\n");

  Mock::VerifyAndClear(mock);
  Mock::AllowLeak(mock);
}

bool IsIteratorForStringMatching(ScriptState* script_state,
                                 ScriptValue value,
                                 const String& expected) {
  if (!value.IsObject()) {
    return false;
  }
  v8::Local<v8::Value> chunk;
  bool done = false;
  if (!V8UnpackIterationResult(script_state,
                               value.V8Value()
                                   ->ToObject(script_state->GetContext())
                                   .ToLocalChecked(),
                               &chunk, &done)) {
    return false;
  }
  if (done)
    return false;
  return ToCoreStringWithUndefinedOrNullCheck(script_state->GetIsolate(),
                                              chunk) == expected;
}

bool IsTypeError(ScriptState* script_state,
                 ScriptValue value,
                 const String& message) {
  v8::Local<v8::Object> object;
  if (!value.V8Value()->ToObject(script_state->GetContext()).ToLocal(&object)) {
    return false;
  }
  if (!object->IsNativeError())
    return false;

  const auto& Has = [script_state, object](const String& key,
                                           const String& value) -> bool {
    v8::Local<v8::Value> actual;
    return object
               ->Get(script_state->GetContext(),
                     V8AtomicString(script_state->GetIsolate(), key))
               .ToLocal(&actual) &&
           ToCoreStringWithUndefinedOrNullCheck(script_state->GetIsolate(),
                                                actual) == value;
  };

  return Has("name", "TypeError") && Has("message", message);
}

TEST_F(TransformStreamTest, EnqueueFromTransform) {
  V8TestingScope scope;
  auto* script_state = scope.GetScriptState();
  Init(MakeGarbageCollected<IdentityTransformer>(scope.GetScriptState()),
       script_state, ASSERT_NO_EXCEPTION);

  CopyReadableAndWritableToGlobal(scope);

  EvalWithPrintingError(&scope,
                        "const writer = writable.getWriter();\n"
                        "writer.write('a');\n");

  ReadableStream* readable = Stream()->Readable();
  auto* reader =
      readable->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state,
                             reader->read(script_state, ASSERT_NO_EXCEPTION));
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  EXPECT_TRUE(IsIteratorForStringMatching(script_state, tester.Value(), "a"));
}

TEST_F(TransformStreamTest, EnqueueFromFlush) {
  class EnqueueFromFlushTransformer final : public TestTransformer {
   public:
    explicit EnqueueFromFlushTransformer(ScriptState* script_state)
        : TestTransformer(script_state) {}

    void FlushVoid(TransformStreamDefaultController* controller,
                   ExceptionState& exception_state) override {
      controller->enqueue(
          GetScriptState(),
          ScriptValue(GetScriptState()->GetIsolate(),
                      V8String(GetScriptState()->GetIsolate(), "a")),
          exception_state);
    }
  };

  V8TestingScope scope;
  auto* script_state = scope.GetScriptState();
  Init(MakeGarbageCollected<EnqueueFromFlushTransformer>(script_state),
       script_state, ASSERT_NO_EXCEPTION);

  CopyReadableAndWritableToGlobal(scope);

  EvalWithPrintingError(&scope,
                        "const writer = writable.getWriter();\n"
                        "writer.close();\n");

  ReadableStream* readable = Stream()->Readable();
  auto* reader =
      readable->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state,
                             reader->read(script_state, ASSERT_NO_EXCEPTION));
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  EXPECT_TRUE(IsIteratorForStringMatching(script_state, tester.Value(), "a"));
}

TEST_F(TransformStreamTest, ThrowFromTransform) {
  static constexpr char kMessage[] = "errorInTransform";
  class ThrowFromTransformTransformer final : public TestTransformer {
   public:
    explicit ThrowFromTransformTransformer(ScriptState* script_state)
        : TestTransformer(script_state) {}

    void TransformVoid(v8::Local<v8::Value>,
                       TransformStreamDefaultController*,
                       ExceptionState& exception_state) override {
      exception_state.ThrowTypeError(kMessage);
    }
  };

  V8TestingScope scope;
  auto* script_state = scope.GetScriptState();
  Init(MakeGarbageCollected<ThrowFromTransformTransformer>(
           scope.GetScriptState()),
       script_state, ASSERT_NO_EXCEPTION);

  CopyReadableAndWritableToGlobal(scope);

  ScriptValue promise =
      EvalWithPrintingError(&scope,
                            "const writer = writable.getWriter();\n"
                            "writer.write('a');\n");

  ReadableStream* readable = Stream()->Readable();
  auto* reader =
      readable->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester read_tester(
      script_state, reader->read(script_state, ASSERT_NO_EXCEPTION));
  read_tester.WaitUntilSettled();
  EXPECT_TRUE(read_tester.IsRejected());
  EXPECT_TRUE(IsTypeError(script_state, read_tester.Value(), kMessage));
  ScriptPromiseTester write_tester(
      script_state, ToResolvedPromise<IDLAny>(script_state, promise));
  write_tester.WaitUntilSettled();
  EXPECT_TRUE(write_tester.IsRejected());
  EXPECT_TRUE(IsTypeError(script_state, write_tester.Value(), kMessage));
}

TEST_F(TransformStreamTest, ThrowFromFlush) {
  static constexpr char kMessage[] = "errorInFlush";
  class ThrowFromFlushTransformer final : public TestTransformer {
   public:
    explicit ThrowFromFlushTransformer(ScriptState* script_state)
        : TestTransformer(script_state) {}

    void FlushVoid(TransformStreamDefaultController*,
                   ExceptionState& exception_state) override {
      exception_state.ThrowTypeError(kMessage);
    }
  };
  V8TestingScope scope;
  auto* script_state = scope.GetScriptState();
  Init(MakeGarbageCollected<ThrowFromFlushTransformer>(scope.GetScriptState()),
       script_state, ASSERT_NO_EXCEPTION);

  CopyReadableAndWritableToGlobal(scope);

  ScriptValue promise =
      EvalWithPrintingError(&scope,
                            "const writer = writable.getWriter();\n"
                            "writer.close();\n");

  ReadableStream* readable = Stream()->Readable();
  auto* reader =
      readable->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester read_tester(
      script_state, reader->read(script_state, ASSERT_NO_EXCEPTION));
  read_tester.WaitUntilSettled();
  EXPECT_TRUE(read_tester.IsRejected());
  EXPECT_TRUE(IsTypeError(script_state, read_tester.Value(), kMessage));
  ScriptPromiseTester write_tester(
      script_state, ToResolvedPromise<IDLAny>(script_state, promise));
  write_tester.WaitUntilSettled();
  EXPECT_TRUE(write_tester.IsRejected());
  EXPECT_TRUE(IsTypeError(script_state, write_tester.Value(), kMessage));
}

TEST_F(TransformStreamTest, CreateFromReadableWritablePair) {
  V8TestingScope scope;
  ReadableStream* readable =
      ReadableStream::Create(scope.GetScriptState(), ASSERT_NO_EXCEPTION);
  WritableStream* writable =
      WritableStream::Create(scope.GetScriptState(), ASSERT_NO_EXCEPTION);
  TransformStream* transform =
      MakeGarbageCollected<TransformStream>(readable, writable);
  EXPECT_EQ(readable, transform->Readable());
  EXPECT_EQ(writable, transform->Writable());
}

TEST_F(TransformStreamTest, WaitInTransform) {
  class WaitInTransformTransformer final : public TestTransformer {
   public:
    explicit WaitInTransformTransformer(ScriptState* script_state)
        : TestTransformer(script_state),
          transform_promise_resolver_(
              MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
                  script_state)) {}

    ScriptPromise<IDLUndefined> Transform(v8::Local<v8::Value>,
                                          TransformStreamDefaultController*,
                                          ExceptionState&) override {
      return transform_promise_resolver_->Promise();
    }

    void FlushVoid(TransformStreamDefaultController*,
                   ExceptionState&) override {
      flush_called_ = true;
    }

    void ResolvePromise() { transform_promise_resolver_->Resolve(); }
    bool FlushCalled() const { return flush_called_; }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(transform_promise_resolver_);
      TestTransformer::Trace(visitor);
    }

   private:
    const Member<ScriptPromiseResolver<IDLUndefined>>
        transform_promise_resolver_;
    bool flush_called_ = false;
  };

  V8TestingScope scope;
  auto* script_state = scope.GetScriptState();
  auto* transformer =
      MakeGarbageCollected<WaitInTransformTransformer>(script_state);
  Init(transformer, script_state, ASSERT_NO_EXCEPTION);
  CopyReadableAndWritableToGlobal(scope);

  ScriptValue promise =
      EvalWithPrintingError(&scope,
                            "const writer = writable.getWriter();\n"
                            "const promise = writer.write('a');\n"
                            "writer.close();\n"
                            "promise;\n");
  // Need to read to relieve backpressure.
  Stream()
      ->Readable()
      ->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION)
      ->read(script_state, ASSERT_NO_EXCEPTION);

  ScriptPromiseTester write_tester(
      script_state, ToResolvedPromise<IDLAny>(script_state, promise));

  // Give Transform() the opportunity to be called.
  scope.PerformMicrotaskCheckpoint();

  EXPECT_FALSE(write_tester.IsFulfilled());
  EXPECT_FALSE(transformer->FlushCalled());

  transformer->ResolvePromise();

  write_tester.WaitUntilSettled();
  EXPECT_TRUE(write_tester.IsFulfilled());
  EXPECT_TRUE(transformer->FlushCalled());
}

TEST_F(TransformStreamTest, WaitInFlush) {
  class WaitInFlushTransformer final : public TestTransformer {
   public:
    explicit WaitInFlushTransformer(ScriptState* script_state)
        : TestTransformer(script_state),
          flush_promise_resolver_(
              MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
                  script_state)) {}

    ScriptPromise<IDLUndefined> Flush(TransformStreamDefaultController*,
                                      ExceptionState&) override {
      return flush_promise_resolver_->Promise();
    }

    void ResolvePromise() { flush_promise_resolver_->Resolve(); }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(flush_promise_resolver_);
      TestTransformer::Trace(visitor);
    }

   private:
    const Member<ScriptPromiseResolver<IDLUndefined>> flush_promise_resolver_;
  };

  V8TestingScope scope;
  auto* script_state = scope.GetScriptState();
  auto* transformer =
      MakeGarbageCollected<WaitInFlushTransformer>(script_state);
  Init(transformer, script_state, ASSERT_NO_EXCEPTION);
  CopyReadableAndWritableToGlobal(scope);

  ScriptValue promise =
      EvalWithPrintingError(&scope,
                            "const writer = writable.getWriter();\n"
                            "writer.close();\n");

  // Need to read to relieve backpressure.
  Stream()
      ->Readable()
      ->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION)
      ->read(script_state, ASSERT_NO_EXCEPTION);

  ScriptPromiseTester close_tester(
      script_state, ToResolvedPromise<IDLAny>(script_state, promise));

  // Give Flush() the opportunity to be called.
  scope.PerformMicrotaskCheckpoint();

  EXPECT_FALSE(close_tester.IsFulfilled());
  transformer->ResolvePromise();
  close_tester.WaitUntilSettled();
  EXPECT_TRUE(close_tester.IsFulfilled());
}

}  // namespace
}  // namespace blink

"""

```