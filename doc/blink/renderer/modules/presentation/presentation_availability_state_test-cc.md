Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request asks for the functionality of the `presentation_availability_state_test.cc` file. This immediately tells us it's a *test file* for a component named `PresentationAvailabilityState`. The core goal is to verify the behavior of this component.

2. **Identify the Tested Class:**  The `#include` directives are crucial. The inclusion of `blink/renderer/modules/presentation/presentation_availability_state.h` confirms that the `PresentationAvailabilityState` class is the primary focus of these tests.

3. **Scan for Key Entities and Concepts:** Quickly read through the code, looking for important class names, methods, and variables. This reveals:
    * `PresentationAvailabilityState`: The class under test.
    * `PresentationAvailability`:  Seems related to the availability status.
    * `PresentationAvailabilityObserver`:  An interface for receiving availability updates.
    * `MockPresentationService`: A mock object, indicating interaction with an external service.
    * `ScreenAvailability`: An enum likely representing the different availability states (AVAILABLE, UNAVAILABLE, etc.).
    * `ScriptPromise`:  JavaScript Promise integration.
    * `KURL`: Likely a URL representation.
    * `MockPresentationAvailabilityObserver`: A mock observer for testing notifications.
    * `TEST_F`:  Indicates Google Test framework test cases.

4. **Analyze Test Case Structure:** Notice the `TEST_F` macros. Each `TEST_F` represents an individual test of a specific aspect of `PresentationAvailabilityState`. Look for patterns in the test names:
    * "RequestAvailability...": Tests related to requesting availability.
    * "ScreenAvailabilitySourceNotSupported": Tests a specific availability state.
    * "StartListening...": Tests the starting of listening for availability changes.
    * "StopListening...": Tests the stopping of listening.
    * "UpdateAvailability...": Tests how availability updates are handled.

5. **Examine Individual Test Cases:**  Pick a few representative test cases and understand their logic. For example, look at `RequestAvailability`.
    * It sets up expectations for calls to `mock_presentation_service_` (`ListenForScreenAvailability`, `StopListeningForScreenAvailability`).
    * It creates a `PresentationAvailability` object.
    * It calls `state_->RequestAvailability()`.
    * It uses `state_->UpdateAvailability()` to simulate changes in availability.
    * It uses `state_->AddObserver()` and `state_->RemoveObserver()`.
    * It uses `EXPECT_CALL` to verify that the mock observer receives the correct notifications.

6. **Connect to Broader Concepts (JavaScript, HTML, CSS):**  The filename "modules/presentation" suggests this is related to the Presentation API in web browsers. Recall that the Presentation API allows web pages to interact with external displays.
    * **JavaScript:** The `ScriptPromise` usage directly links this to JavaScript's asynchronous programming model. The API would be exposed to JavaScript.
    * **HTML:**  While not directly manipulated in *this* test file, the Presentation API is triggered by JavaScript code within a web page loaded in an HTML document.
    * **CSS:**  Less direct, but CSS might be used to style the UI elements related to presentation selection or status (though this test focuses on the core logic, not UI).

7. **Infer Logic and Input/Output (where applicable):** Some tests lend themselves to simple input/output reasoning. For instance, in `RequestAvailabilityOneUrlBecomesAvailable`, the input is a request for availability for `url1_`, and the output is a fulfilled promise indicating availability when the state is updated to `AVAILABLE`.

8. **Identify Potential Usage Errors:** Think about how a developer might misuse the Presentation API. For example, failing to handle promise rejections, adding/removing observers incorrectly, or making assumptions about the timing of availability updates.

9. **Trace User Actions (Debugging Clues):** Consider how a user's interaction with a web page could lead to this code being executed. This involves understanding the flow of the Presentation API:
    * A user visits a website that uses the Presentation API.
    * JavaScript code on the page calls methods like `navigator.presentation.requestAvailability()`.
    * This triggers the browser's internal logic, eventually leading to the `PresentationAvailabilityState` component being invoked.
    * The test file simulates the responses from the underlying presentation service.

10. **Structure the Explanation:** Organize the findings into clear categories: functionality, relationship to web technologies, logical reasoning, potential errors, and debugging. Use clear and concise language. Provide specific examples from the code to illustrate points.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just about checking availability."
* **Correction:**  Realized it's not just a simple boolean check. It involves different availability states, asynchronous operations (Promises), and managing multiple observers.
* **Initial thought:** "How does CSS fit in?"
* **Refinement:** Acknowledged the indirect relationship – CSS might style related UI, but the core logic is independent.
* **Initial thought:** "Focus only on the positive cases."
* **Correction:**  Noticed the tests include cases for unavailability, not supported, and disabled, highlighting the need to handle different outcomes.

By following this structured approach, the analysis becomes more thorough and accurate. The process involves understanding the specific code, connecting it to broader web development concepts, and considering practical usage scenarios.
这个文件 `presentation_availability_state_test.cc` 是 Chromium Blink 引擎中关于 Presentation API 的一个测试文件。它的主要功能是**测试 `PresentationAvailabilityState` 类的行为**。`PresentationAvailabilityState` 类负责管理和跟踪 Presentation API 中屏幕是否可用的状态，并通知相关的观察者。

以下是根据代码内容对该文件功能的详细解释和与 Web 技术的关系：

**1. 功能概览:**

* **测试核心逻辑:**  该文件包含了多个单元测试用例，用于验证 `PresentationAvailabilityState` 类的各种功能，例如：
    * 请求屏幕可用性 (RequestAvailability)
    * 更新屏幕可用性状态 (UpdateAvailability)
    * 添加和移除可用性状态观察者 (AddObserver, RemoveObserver)
    * 处理不同屏幕可用性状态 (AVAILABLE, UNAVAILABLE, SOURCE_NOT_SUPPORTED, DISABLED)
    * 确保在可用性状态改变时通知到正确的观察者

* **模拟外部依赖:**  使用了 `MockPresentationService` 来模拟与底层 Presentation Service 的交互，这样测试可以独立进行，不需要实际的物理设备或网络连接。

* **异步测试:**  使用了 `ScriptPromise` 和 `base::RunLoop` 来处理 Presentation API 中异步的特性，例如 `requestAvailability()` 方法返回的 Promise。

* **使用 Google Test 框架:**  该文件使用了 Google Test 框架进行测试，提供了清晰的测试结构和断言 (EXPECT_CALL, EXPECT_TRUE, EXPECT_FALSE)。

**2. 与 JavaScript, HTML, CSS 的关系:**

`PresentationAvailabilityState` 类是浏览器内部实现 Presentation API 的一部分，该 API 允许网页与第二屏幕（例如 Chromecast 或 Miracast 设备）进行交互。

* **JavaScript:**
    * **接口实现:** `PresentationAvailabilityState` 的功能最终会通过 JavaScript 的 `navigator.presentation.requestAvailability()` 方法暴露给开发者。
    * **Promise 的处理:** 测试中使用了 `ScriptPromise`，这直接对应于 JavaScript 中 Promise 的概念。当 JavaScript 代码调用 `requestAvailability()` 时，会返回一个 Promise，该 Promise 会在屏幕可用性状态确定后被 resolve 或 reject。
    * **事件通知:**  当 `PresentationAvailabilityState` 中的状态发生变化时，会通知实现了 `PresentationAvailabilityObserver` 接口的对象。在实际的浏览器实现中，这可能会触发 JavaScript 中 `onavailabilitychanged` 事件或通过 Promise 的 resolve/reject 来通知网页。

    **举例说明:**
    ```javascript
    navigator.presentation.requestAvailability(['https://example.com/presentation'])
      .then(availability => {
        if (availability.value) {
          console.log("屏幕可用");
        } else {
          console.log("屏幕不可用");
        }
        availability.onavailabilitychanged = (event) => {
          console.log("屏幕可用性状态改变:", event.value);
        };
      })
      .catch(error => {
        console.error("请求可用性时出错:", error);
      });
    ```
    这个 JavaScript 代码片段使用了 `navigator.presentation.requestAvailability()` 来请求指定 URL 的演示文稿的可用性。`PresentationAvailabilityState` 的测试就是为了确保这个方法在各种情况下能够正确返回 Promise 并触发相应的事件。

* **HTML:**
    * **触发 API 调用:**  HTML 页面中的 JavaScript 代码会调用 Presentation API 的方法。例如，用户点击一个按钮可能会触发 `navigator.presentation.requestAvailability()`。

    **举例说明:**
    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>Presentation Test</title>
    </head>
    <body>
      <button id="requestButton">检查屏幕可用性</button>
      <script>
        document.getElementById('requestButton').addEventListener('click', () => {
          navigator.presentation.requestAvailability(['https://example.com/presentation']);
        });
      </script>
    </body>
    </html>
    ```

* **CSS:**
    * **间接影响:** CSS 本身不直接与 `PresentationAvailabilityState` 交互。但是，页面的样式可能会影响用户如何与 Presentation API 相关的 UI 元素交互，例如显示可用屏幕的列表或状态。

**3. 逻辑推理与假设输入/输出:**

以下是一些测试用例的逻辑推理和假设输入/输出：

* **测试用例: `RequestAvailabilityOneUrlBecomesAvailable`**
    * **假设输入:**  请求 `url1_` 的可用性，然后模拟 `url1_` 的可用性状态变为 `AVAILABLE`。
    * **预期输出:**  `requestAvailability()` 返回的 Promise 应该被 resolve，并且 `PresentationAvailability` 对象的 `value` 属性应该为 `true`。
    * **逻辑推理:**  当请求的 URL 变为可用时，Promise 应该成功解析，指示屏幕可用。

* **测试用例: `RequestAvailabilityMultipleUrlsAllBecomesUnavailable`**
    * **假设输入:** 请求 `url1_` 和 `url2_` 的可用性，然后模拟这两个 URL 的可用性状态都变为 `UNAVAILABLE`。
    * **预期输出:** `requestAvailability()` 返回的 Promise 应该被 resolve，并且 `PresentationAvailability` 对象的 `value` 属性应该为 `false`。
    * **逻辑推理:** 当请求的所有 URL 都不可用时，Promise 应该成功解析，指示屏幕不可用。

* **测试用例: `RequestAvailabilityOneUrlBecomesUnsupported`**
    * **假设输入:** 请求 `url1_` 的可用性，然后模拟 `url1_` 的可用性状态变为 `DISABLED` (在某些上下文中可能表示不支持)。
    * **预期输出:** `requestAvailability()` 返回的 Promise 应该被 reject。
    * **逻辑推理:**  当屏幕功能被禁用或不支持时，Promise 应该被拒绝，指示操作无法完成。

**4. 用户或编程常见的使用错误:**

* **未处理 Promise 的 rejection:** 开发者可能会忘记处理 `requestAvailability()` 返回的 Promise 的 rejection 情况，例如当屏幕功能被禁用时。这会导致未捕获的错误。
    ```javascript
    navigator.presentation.requestAvailability(['https://example.com'])
      .then(availability => {
        // ... 处理可用性
      }); // 缺少 .catch() 处理 rejection
    ```

* **错误地假设可用性状态:**  开发者可能会错误地假设屏幕在请求后立即可用，而没有正确监听 `onavailabilitychanged` 事件或检查 Promise 的结果。

* **滥用 `requestAvailability()`:**  频繁地调用 `requestAvailability()` 可能会导致不必要的资源消耗。应该根据用户的操作或页面的状态合理地调用此方法。

* **忘记移除事件监听器:** 如果在组件销毁时没有移除 `onavailabilitychanged` 事件监听器，可能会导致内存泄漏。

**5. 用户操作如何一步步到达这里 (调试线索):**

1. **用户访问一个包含 Presentation API 代码的网页:**  用户在浏览器中打开一个网页，该网页的代码中使用了 `navigator.presentation.requestAvailability()` 方法。

2. **JavaScript 代码执行 `requestAvailability()`:**  当网页加载或用户执行某些操作（例如点击按钮）时，JavaScript 代码会调用 `navigator.presentation.requestAvailability()`，传入一个或多个演示文稿的 URL。

3. **浏览器内部处理请求:**  浏览器接收到 JavaScript 的请求后，会调用 Blink 引擎中相应的 C++ 代码，最终会涉及到 `PresentationAvailabilityState` 类。

4. **`PresentationAvailabilityState` 与底层服务交互:**  `PresentationAvailabilityState` 会与底层的 Presentation Service (在测试中被 `MockPresentationService` 模拟) 交互，以获取屏幕的可用性信息。

5. **状态更新和通知:**  当底层服务的状态发生变化时，`PresentationAvailabilityState` 会更新其内部状态，并通知已注册的观察者 (例如，对应于 JavaScript 中 `onavailabilitychanged` 事件的处理函数)。

6. **Promise 的 resolve 或 reject:**  `requestAvailability()` 返回的 Promise 会根据屏幕的最终可用性状态被 resolve 或 reject。

**作为调试线索，当遇到 Presentation API 相关的问题时，可以关注以下几点:**

* **检查 JavaScript 代码中的 Promise 处理:** 确保正确处理了 Promise 的 resolve 和 reject 情况。
* **查看 `onavailabilitychanged` 事件是否被正确触发和处理:**  在屏幕可用性状态发生变化时，`onavailabilitychanged` 事件应该被触发。
* **使用浏览器的开发者工具:**  查看控制台是否有与 Presentation API 相关的错误或警告信息。
* **检查浏览器的 Presentation API 支持:**  确保用户使用的浏览器支持 Presentation API。
* **模拟不同的网络和设备环境:**  Presentation API 的行为可能受到网络连接和可用设备的影响。

总而言之，`presentation_availability_state_test.cc` 是一个至关重要的测试文件，用于确保 Chromium Blink 引擎中 Presentation API 的核心组件 `PresentationAvailabilityState` 的正确性和稳定性，从而保证 Web 开发者可以可靠地使用 Presentation API 功能。

### 提示词
```
这是目录为blink/renderer/modules/presentation/presentation_availability_state_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/presentation/presentation_availability_state.h"

#include "base/run_loop.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_presentation_availability.h"
#include "third_party/blink/renderer/modules/presentation/mock_presentation_service.h"
#include "third_party/blink/renderer/modules/presentation/presentation_availability.h"
#include "third_party/blink/renderer/modules/presentation/presentation_availability_observer.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

using testing::_;

namespace blink {

using mojom::blink::ScreenAvailability;

class MockPresentationAvailabilityObserver
    : public GarbageCollected<MockPresentationAvailabilityObserver>,
      public PresentationAvailabilityObserver {
 public:
  explicit MockPresentationAvailabilityObserver(const Vector<KURL>& urls)
      : urls_(urls) {}
  ~MockPresentationAvailabilityObserver() override = default;

  MOCK_METHOD1(AvailabilityChanged, void(ScreenAvailability availability));
  const Vector<KURL>& Urls() const override { return urls_; }

 private:
  const Vector<KURL> urls_;
};

// Helper classes for WaitForPromise{Fulfillment,Rejection}(). Provides a
// function that invokes |callback| when a ScriptPromise is resolved/rejected.
class ClosureOnResolve final
    : public ThenCallable<PresentationAvailability, ClosureOnResolve> {
 public:
  explicit ClosureOnResolve(base::OnceClosure callback)
      : callback_(std::move(callback)) {}

  void React(ScriptState*, PresentationAvailability*) {
    CHECK(callback_);
    std::move(callback_).Run();
  }

 private:
  base::OnceClosure callback_;
};

class ClosureOnReject final : public ThenCallable<IDLAny, ClosureOnReject> {
 public:
  explicit ClosureOnReject(base::OnceClosure callback)
      : callback_(std::move(callback)) {}

  void React(ScriptState*, ScriptValue) {
    CHECK(callback_);
    std::move(callback_).Run();
  }

 private:
  base::OnceClosure callback_;
};

class PresentationAvailabilityStateTestingContext final {
  STACK_ALLOCATED();

 public:
  PresentationAvailabilityStateTestingContext() = default;
  ~PresentationAvailabilityStateTestingContext() = default;

  ExecutionContext* GetExecutionContext() {
    return testing_scope_.GetExecutionContext();
  }

  ScriptState* GetScriptState() { return testing_scope_.GetScriptState(); }

  const ExceptionContext& GetExceptionContext() {
    return testing_scope_.GetExceptionState().GetContext();
  }

  // Synchronously waits for |promise| to be fulfilled.
  void WaitForPromiseFulfillment(
      ScriptPromise<PresentationAvailability> promise) {
    base::RunLoop run_loop;
    promise.Then(GetScriptState(), MakeGarbageCollected<ClosureOnResolve>(
                                       run_loop.QuitClosure()));
    // Execute pending microtasks, otherwise it can take a few seconds for the
    // promise to resolve.
    GetScriptState()->GetContext()->GetMicrotaskQueue()->PerformCheckpoint(
        GetScriptState()->GetIsolate());
    run_loop.Run();
  }

  // Synchronously waits for |promise| to be rejected.
  void WaitForPromiseRejection(
      ScriptPromise<PresentationAvailability> promise) {
    base::RunLoop run_loop;
    promise.Catch(GetScriptState(), MakeGarbageCollected<ClosureOnReject>(
                                        run_loop.QuitClosure()));
    // Execute pending microtasks, otherwise it can take a few seconds for the
    // promise to resolve.
    GetScriptState()->GetContext()->GetMicrotaskQueue()->PerformCheckpoint(
        GetScriptState()->GetIsolate());
    run_loop.Run();
  }

  PresentationAvailability* GetPromiseResolutionAsPresentationAvailability(
      const ScriptPromise<PresentationAvailability>& promise) {
    return V8PresentationAvailability::ToWrappable(
        GetScriptState()->GetIsolate(), promise.V8Promise()->Result());
  }

 private:
  V8TestingScope testing_scope_;
};

class PresentationAvailabilityStateTest : public testing::Test {
 public:
  PresentationAvailabilityStateTest()
      : url1_(KURL("https://www.example.com/1.html")),
        url2_(KURL("https://www.example.com/2.html")),
        url3_(KURL("https://www.example.com/3.html")),
        url4_(KURL("https://www.example.com/4.html")),
        urls_({url1_, url2_, url3_, url4_}),
        mock_observer_all_urls_(
            MakeGarbageCollected<MockPresentationAvailabilityObserver>(urls_)),
        mock_observer1_(
            MakeGarbageCollected<MockPresentationAvailabilityObserver>(
                Vector<KURL>({url1_, url2_, url3_}))),
        mock_observer2_(
            MakeGarbageCollected<MockPresentationAvailabilityObserver>(
                Vector<KURL>({url2_, url3_, url4_}))),
        mock_observer3_(
            MakeGarbageCollected<MockPresentationAvailabilityObserver>(
                Vector<KURL>({url2_, url3_}))),
        mock_observers_({mock_observer1_, mock_observer2_, mock_observer3_}),
        mock_presentation_service_(),
        state_(MakeGarbageCollected<PresentationAvailabilityState>(
            &mock_presentation_service_)) {}

  ~PresentationAvailabilityStateTest() override = default;

  void ChangeURLState(const KURL& url, ScreenAvailability state) {
    if (state != ScreenAvailability::UNKNOWN) {
      state_->UpdateAvailability(url, state);
    }
  }

  void RequestAvailabilityAndAddObservers(ExecutionContext* execution_context) {
    for (auto& mock_observer : mock_observers_) {
      state_->RequestAvailability(
          MakeGarbageCollected<PresentationAvailability>(
              execution_context, mock_observer->Urls(), false));
      state_->AddObserver(mock_observer);
    }
  }

  // Tests that PresenationService is called for getAvailability(urls), after
  // `urls` change state to `states`. This function takes ownership of
  // `promise`.
  void TestRequestAvailability(const Vector<ScreenAvailability>& states,
                               PresentationAvailability* availability) {
    auto urls = availability->Urls();
    DCHECK_EQ(urls.size(), states.size());

    state_->RequestAvailability(availability);
    for (wtf_size_t i = 0; i < urls.size(); i++) {
      ChangeURLState(urls[i], states[i]);
    }
  }

 protected:
  const KURL url1_;
  const KURL url2_;
  const KURL url3_;
  const KURL url4_;
  const Vector<KURL> urls_;
  test::TaskEnvironment task_environment_;
  Persistent<MockPresentationAvailabilityObserver> mock_observer_all_urls_;
  Persistent<MockPresentationAvailabilityObserver> mock_observer1_;
  Persistent<MockPresentationAvailabilityObserver> mock_observer2_;
  Persistent<MockPresentationAvailabilityObserver> mock_observer3_;
  Vector<Persistent<MockPresentationAvailabilityObserver>> mock_observers_;

  MockPresentationService mock_presentation_service_;
  Persistent<PresentationAvailabilityState> state_;
};

TEST_F(PresentationAvailabilityStateTest, RequestAvailability) {
  PresentationAvailabilityStateTestingContext context;
  for (const auto& url : urls_) {
    EXPECT_CALL(mock_presentation_service_, ListenForScreenAvailability(url));
    EXPECT_CALL(mock_presentation_service_,
                StopListeningForScreenAvailability(url));
  }

  state_->RequestAvailability(MakeGarbageCollected<PresentationAvailability>(
      context.GetExecutionContext(), urls_, false));
  state_->UpdateAvailability(url1_, ScreenAvailability::AVAILABLE);

  for (const auto& url : urls_) {
    EXPECT_CALL(mock_presentation_service_, ListenForScreenAvailability(url));
  }

  state_->AddObserver(mock_observer_all_urls_);

  EXPECT_CALL(*mock_observer_all_urls_,
              AvailabilityChanged(ScreenAvailability::UNAVAILABLE));
  state_->UpdateAvailability(url1_, ScreenAvailability::UNAVAILABLE);
  EXPECT_CALL(*mock_observer_all_urls_,
              AvailabilityChanged(ScreenAvailability::AVAILABLE));
  state_->UpdateAvailability(url1_, ScreenAvailability::AVAILABLE);
  for (const auto& url : urls_) {
    EXPECT_CALL(mock_presentation_service_,
                StopListeningForScreenAvailability(url));
  }
  state_->RemoveObserver(mock_observer_all_urls_);

  // After RemoveObserver(), |mock_observer_all_urls_| should no longer be
  // notified.
  EXPECT_CALL(*mock_observer_all_urls_,
              AvailabilityChanged(ScreenAvailability::UNAVAILABLE))
      .Times(0);
  state_->UpdateAvailability(url1_, ScreenAvailability::UNAVAILABLE);
}

TEST_F(PresentationAvailabilityStateTest,
       ScreenAvailabilitySourceNotSupported) {
  for (const auto& url : urls_) {
    EXPECT_CALL(mock_presentation_service_, ListenForScreenAvailability(url));
  }

  state_->AddObserver(mock_observer_all_urls_);

  EXPECT_CALL(*mock_observer_all_urls_,
              AvailabilityChanged(ScreenAvailability::SOURCE_NOT_SUPPORTED));
  state_->UpdateAvailability(url1_, ScreenAvailability::SOURCE_NOT_SUPPORTED);

  for (const auto& url : urls_) {
    EXPECT_CALL(mock_presentation_service_,
                StopListeningForScreenAvailability(url));
  }
  state_->RemoveObserver(mock_observer_all_urls_);
}

TEST_F(PresentationAvailabilityStateTest,
       RequestAvailabilityOneUrlNoAvailabilityChange) {
  PresentationAvailabilityStateTestingContext context;
  EXPECT_CALL(mock_presentation_service_, ListenForScreenAvailability(url1_))
      .Times(1);

  state_->RequestAvailability(MakeGarbageCollected<PresentationAvailability>(
      context.GetExecutionContext(), Vector<KURL>({url1_}), false));
}

TEST_F(PresentationAvailabilityStateTest,
       RequestAvailabilityOneUrlBecomesAvailable) {
  PresentationAvailabilityStateTestingContext context;
  EXPECT_CALL(mock_presentation_service_, ListenForScreenAvailability(url1_))
      .Times(1);

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PresentationAvailability>>(
          context.GetScriptState(), context.GetExceptionContext());
  auto* availability = MakeGarbageCollected<PresentationAvailability>(
      context.GetExecutionContext(), Vector<KURL>({url1_}), false);
  availability->AddResolver(resolver);
  state_->AddObserver(availability);
  auto promise = resolver->Promise();

  TestRequestAvailability({ScreenAvailability::AVAILABLE}, availability);
  context.WaitForPromiseFulfillment(promise);
  auto* presentation_availability =
      context.GetPromiseResolutionAsPresentationAvailability(promise);
  EXPECT_TRUE(presentation_availability->value());

  EXPECT_CALL(mock_presentation_service_,
              StopListeningForScreenAvailability(url1_))
      .Times(1);
  state_->RemoveObserver(availability);
}

TEST_F(PresentationAvailabilityStateTest,
       RequestAvailabilityOneUrlBecomesNotCompatible) {
  PresentationAvailabilityStateTestingContext context;
  EXPECT_CALL(mock_presentation_service_, ListenForScreenAvailability(url1_))
      .Times(1);

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PresentationAvailability>>(
          context.GetScriptState(), context.GetExceptionContext());
  auto* availability = MakeGarbageCollected<PresentationAvailability>(
      context.GetExecutionContext(), Vector<KURL>({url1_}), false);
  availability->AddResolver(resolver);
  state_->AddObserver(availability);
  auto promise = resolver->Promise();

  TestRequestAvailability({ScreenAvailability::SOURCE_NOT_SUPPORTED},
                          availability);
  context.WaitForPromiseFulfillment(promise);
  auto* presentation_availability =
      context.GetPromiseResolutionAsPresentationAvailability(promise);
  EXPECT_FALSE(presentation_availability->value());

  EXPECT_CALL(mock_presentation_service_,
              StopListeningForScreenAvailability(url1_))
      .Times(1);
  state_->RemoveObserver(availability);
}

TEST_F(PresentationAvailabilityStateTest,
       RequestAvailabilityOneUrlBecomesUnavailable) {
  PresentationAvailabilityStateTestingContext context;
  EXPECT_CALL(mock_presentation_service_, ListenForScreenAvailability(url1_))
      .Times(1);

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PresentationAvailability>>(
          context.GetScriptState(), context.GetExceptionContext());
  auto* availability = MakeGarbageCollected<PresentationAvailability>(
      context.GetExecutionContext(), Vector<KURL>({url1_}), false);
  availability->AddResolver(resolver);
  state_->AddObserver(availability);
  auto promise = resolver->Promise();

  TestRequestAvailability({ScreenAvailability::UNAVAILABLE}, availability);
  context.WaitForPromiseFulfillment(promise);
  auto* presentation_availability =
      context.GetPromiseResolutionAsPresentationAvailability(promise);
  EXPECT_FALSE(presentation_availability->value());

  EXPECT_CALL(mock_presentation_service_,
              StopListeningForScreenAvailability(url1_))
      .Times(1);
  state_->RemoveObserver(availability);
}

TEST_F(PresentationAvailabilityStateTest,
       RequestAvailabilityOneUrlBecomesUnsupported) {
  PresentationAvailabilityStateTestingContext context;
  EXPECT_CALL(mock_presentation_service_, ListenForScreenAvailability(url1_))
      .Times(1);

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PresentationAvailability>>(
          context.GetScriptState(), context.GetExceptionContext());
  auto* availability = MakeGarbageCollected<PresentationAvailability>(
      context.GetExecutionContext(), Vector<KURL>({url1_}), false);
  availability->AddResolver(resolver);
  state_->AddObserver(availability);
  auto promise = resolver->Promise();

  TestRequestAvailability({ScreenAvailability::DISABLED}, availability);
  context.WaitForPromiseRejection(promise);

  EXPECT_CALL(mock_presentation_service_,
              StopListeningForScreenAvailability(url1_))
      .Times(1);
  state_->RemoveObserver(availability);
}

TEST_F(PresentationAvailabilityStateTest,
       RequestAvailabilityMultipleUrlsAllBecomesAvailable) {
  PresentationAvailabilityStateTestingContext context;
  Vector<KURL> urls = {url1_, url2_};
  for (const auto& url : urls) {
    EXPECT_CALL(mock_presentation_service_, ListenForScreenAvailability(url))
        .Times(1);
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PresentationAvailability>>(
          context.GetScriptState(), context.GetExceptionContext());
  auto* availability = MakeGarbageCollected<PresentationAvailability>(
      context.GetExecutionContext(), urls, false);
  availability->AddResolver(resolver);
  state_->AddObserver(availability);
  auto promise = resolver->Promise();

  TestRequestAvailability(
      {ScreenAvailability::AVAILABLE, ScreenAvailability::AVAILABLE},
      availability);
  context.WaitForPromiseFulfillment(promise);
  auto* presentation_availability =
      context.GetPromiseResolutionAsPresentationAvailability(promise);
  EXPECT_TRUE(presentation_availability->value());

  for (const auto& url : urls) {
    EXPECT_CALL(mock_presentation_service_,
                StopListeningForScreenAvailability(url))
        .Times(1);
  }
  state_->RemoveObserver(availability);
}

TEST_F(PresentationAvailabilityStateTest,
       RequestAvailabilityMultipleUrlsAllBecomesUnavailable) {
  PresentationAvailabilityStateTestingContext context;
  Vector<KURL> urls = {url1_, url2_};
  for (const auto& url : urls) {
    EXPECT_CALL(mock_presentation_service_, ListenForScreenAvailability(url))
        .Times(1);
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PresentationAvailability>>(
          context.GetScriptState(), context.GetExceptionContext());
  auto* availability = MakeGarbageCollected<PresentationAvailability>(
      context.GetExecutionContext(), urls, false);
  availability->AddResolver(resolver);
  state_->AddObserver(availability);
  auto promise = resolver->Promise();

  TestRequestAvailability(
      {ScreenAvailability::UNAVAILABLE, ScreenAvailability::UNAVAILABLE},
      availability);
  context.WaitForPromiseFulfillment(promise);
  auto* presentation_availability =
      context.GetPromiseResolutionAsPresentationAvailability(promise);
  EXPECT_FALSE(presentation_availability->value());

  for (const auto& url : urls) {
    EXPECT_CALL(mock_presentation_service_,
                StopListeningForScreenAvailability(url))
        .Times(1);
  }
  state_->RemoveObserver(availability);
}

TEST_F(PresentationAvailabilityStateTest,
       RequestAvailabilityMultipleUrlsAllBecomesNotCompatible) {
  PresentationAvailabilityStateTestingContext context;
  Vector<KURL> urls = {url1_, url2_};
  for (const auto& url : urls) {
    EXPECT_CALL(mock_presentation_service_, ListenForScreenAvailability(url))
        .Times(1);
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PresentationAvailability>>(
          context.GetScriptState(), context.GetExceptionContext());
  auto* availability = MakeGarbageCollected<PresentationAvailability>(
      context.GetExecutionContext(), urls, false);
  availability->AddResolver(resolver);
  state_->AddObserver(availability);
  auto promise = resolver->Promise();

  TestRequestAvailability({ScreenAvailability::SOURCE_NOT_SUPPORTED,
                           ScreenAvailability::SOURCE_NOT_SUPPORTED},
                          availability);
  context.WaitForPromiseFulfillment(promise);
  auto* presentation_availability =
      context.GetPromiseResolutionAsPresentationAvailability(promise);
  EXPECT_FALSE(presentation_availability->value());

  for (const auto& url : urls) {
    EXPECT_CALL(mock_presentation_service_,
                StopListeningForScreenAvailability(url))
        .Times(1);
  }
  state_->RemoveObserver(availability);
}

TEST_F(PresentationAvailabilityStateTest,
       RequestAvailabilityMultipleUrlsAllBecomesUnsupported) {
  PresentationAvailabilityStateTestingContext context;
  Vector<KURL> urls = {url1_, url2_};
  for (const auto& url : urls) {
    EXPECT_CALL(mock_presentation_service_, ListenForScreenAvailability(url))
        .Times(1);
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PresentationAvailability>>(
          context.GetScriptState(), context.GetExceptionContext());
  auto* availability = MakeGarbageCollected<PresentationAvailability>(
      context.GetExecutionContext(), urls, false);
  availability->AddResolver(resolver);
  state_->AddObserver(availability);
  auto promise = resolver->Promise();

  TestRequestAvailability(
      {ScreenAvailability::DISABLED, ScreenAvailability::DISABLED},
      availability);
  context.WaitForPromiseRejection(promise);

  for (const auto& url : urls) {
    EXPECT_CALL(mock_presentation_service_,
                StopListeningForScreenAvailability(url))
        .Times(1);
  }
  state_->RemoveObserver(availability);
}

TEST_F(PresentationAvailabilityStateTest, StartListeningListenToEachURLOnce) {
  PresentationAvailabilityStateTestingContext context;
  for (const auto& url : urls_) {
    EXPECT_CALL(mock_presentation_service_, ListenForScreenAvailability(url))
        .Times(1);
  }

  RequestAvailabilityAndAddObservers(context.GetExecutionContext());
}

TEST_F(PresentationAvailabilityStateTest, StopListeningListenToEachURLOnce) {
  PresentationAvailabilityStateTestingContext context;
  for (const auto& url : urls_) {
    EXPECT_CALL(mock_presentation_service_, ListenForScreenAvailability(url))
        .Times(1);
    EXPECT_CALL(mock_presentation_service_,
                StopListeningForScreenAvailability(url))
        .Times(1);
  }

  EXPECT_CALL(*mock_observer1_,
              AvailabilityChanged(ScreenAvailability::UNAVAILABLE));
  EXPECT_CALL(*mock_observer2_,
              AvailabilityChanged(ScreenAvailability::UNAVAILABLE));
  EXPECT_CALL(*mock_observer3_,
              AvailabilityChanged(ScreenAvailability::UNAVAILABLE));

  RequestAvailabilityAndAddObservers(context.GetExecutionContext());

  // Clean up callbacks.
  ChangeURLState(url2_, ScreenAvailability::UNAVAILABLE);

  for (auto& mock_observer : mock_observers_) {
    state_->RemoveObserver(mock_observer);
  }
}

TEST_F(PresentationAvailabilityStateTest,
       StopListeningDoesNotStopIfURLListenedByOthers) {
  PresentationAvailabilityStateTestingContext context;
  for (const auto& url : urls_) {
    EXPECT_CALL(mock_presentation_service_, ListenForScreenAvailability(url))
        .Times(1);
  }

  //  |url1_| is only listened to by |observer1_|.
  EXPECT_CALL(mock_presentation_service_,
              StopListeningForScreenAvailability(url1_))
      .Times(1);
  EXPECT_CALL(mock_presentation_service_,
              StopListeningForScreenAvailability(url2_))
      .Times(0);
  EXPECT_CALL(mock_presentation_service_,
              StopListeningForScreenAvailability(url3_))
      .Times(0);

  RequestAvailabilityAndAddObservers(context.GetExecutionContext());

  for (auto& mock_observer : mock_observers_) {
    state_->AddObserver(mock_observer);
  }

  EXPECT_CALL(*mock_observer1_,
              AvailabilityChanged(ScreenAvailability::UNAVAILABLE));
  EXPECT_CALL(*mock_observer2_,
              AvailabilityChanged(ScreenAvailability::UNAVAILABLE));
  EXPECT_CALL(*mock_observer3_,
              AvailabilityChanged(ScreenAvailability::UNAVAILABLE));

  // Clean up callbacks.
  ChangeURLState(url2_, ScreenAvailability::UNAVAILABLE);
  state_->RemoveObserver(mock_observer1_);
}

TEST_F(PresentationAvailabilityStateTest,
       UpdateAvailabilityInvokesAvailabilityChanged) {
  PresentationAvailabilityStateTestingContext context;
  for (const auto& url : urls_) {
    EXPECT_CALL(mock_presentation_service_, ListenForScreenAvailability(url))
        .Times(1);
  }

  EXPECT_CALL(*mock_observer1_,
              AvailabilityChanged(ScreenAvailability::AVAILABLE));

  RequestAvailabilityAndAddObservers(context.GetExecutionContext());

  ChangeURLState(url1_, ScreenAvailability::AVAILABLE);

  EXPECT_CALL(*mock_observer1_,
              AvailabilityChanged(ScreenAvailability::UNAVAILABLE));
  ChangeURLState(url1_, ScreenAvailability::UNAVAILABLE);

  EXPECT_CALL(*mock_observer1_,
              AvailabilityChanged(ScreenAvailability::SOURCE_NOT_SUPPORTED));
  ChangeURLState(url1_, ScreenAvailability::SOURCE_NOT_SUPPORTED);
}

TEST_F(PresentationAvailabilityStateTest,
       UpdateAvailabilityInvokesMultipleAvailabilityChanged) {
  PresentationAvailabilityStateTestingContext context;
  for (const auto& url : urls_) {
    EXPECT_CALL(mock_presentation_service_, ListenForScreenAvailability(url))
        .Times(1);
  }

  for (auto& mock_observer : mock_observers_) {
    EXPECT_CALL(*mock_observer,
                AvailabilityChanged(ScreenAvailability::AVAILABLE));
  }

  RequestAvailabilityAndAddObservers(context.GetExecutionContext());

  ChangeURLState(url2_, ScreenAvailability::AVAILABLE);

  for (auto& mock_observer : mock_observers_) {
    EXPECT_CALL(*mock_observer,
                AvailabilityChanged(ScreenAvailability::UNAVAILABLE));
  }
  ChangeURLState(url2_, ScreenAvailability::UNAVAILABLE);
}

TEST_F(PresentationAvailabilityStateTest,
       SourceNotSupportedPropagatedToMultipleObservers) {
  PresentationAvailabilityStateTestingContext context;
  for (const auto& url : urls_) {
    EXPECT_CALL(mock_presentation_service_, ListenForScreenAvailability(url))
        .Times(1);
  }

  RequestAvailabilityAndAddObservers(context.GetExecutionContext());
  for (auto& mock_observer : mock_observers_) {
    EXPECT_CALL(*mock_observer,
                AvailabilityChanged(ScreenAvailability::SOURCE_NOT_SUPPORTED));
  }
  ChangeURLState(url2_, ScreenAvailability::SOURCE_NOT_SUPPORTED);
}

}  // namespace blink
```