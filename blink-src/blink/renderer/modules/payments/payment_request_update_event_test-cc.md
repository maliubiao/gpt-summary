Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Subject:** The filename `payment_request_update_event_test.cc` immediately tells us this file is for testing the `PaymentRequestUpdateEvent` class. The `_test.cc` suffix is a common convention for unit tests in Chromium.

2. **Understand the Purpose of Testing:**  Unit tests verify the correct behavior of individual units of code (in this case, the `PaymentRequestUpdateEvent` class). They aim to isolate the class and test its various functionalities and edge cases.

3. **Analyze the Includes:**  The included headers provide valuable context:
    * `payment_request_update_event.h`:  The header file for the class being tested. This confirms our initial understanding.
    * `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h`:  Indicate the use of Google Mock and Google Test frameworks for writing tests. This tells us the structure of the tests will involve `TEST` macros and assertions like `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, and mock objects.
    * Other Blink-specific headers (`mojom`, `bindings`, `core`, `modules`, `platform`): These reveal that `PaymentRequestUpdateEvent` is part of the Blink rendering engine and interacts with other Blink components, especially within the `payments` module. Keywords like "bindings" and "v8" suggest interaction with JavaScript.

4. **Examine the Test Structure:** The code is organized into a namespace `blink` and an anonymous namespace within it. Inside the anonymous namespace, we see a `MockPaymentRequest` class and several `TEST` functions. This is a typical pattern for unit tests in C++.

5. **Deconstruct `MockPaymentRequest`:** This class is crucial. It inherits from `PaymentRequestDelegate` and uses `MOCK_METHOD` to define mock functions (`OnUpdatePaymentDetails`, `OnUpdatePaymentDetailsFailure`). This tells us:
    * `PaymentRequestUpdateEvent` likely interacts with a `PaymentRequestDelegate`.
    * The tests will verify how `PaymentRequestUpdateEvent` triggers calls to these delegate methods.
    * The `IsInteractive()` method suggests the state of the `PaymentRequest` is relevant.

6. **Analyze Individual `TEST` Functions:**  Each `TEST` function focuses on a specific aspect of `PaymentRequestUpdateEvent`'s behavior. Let's look at some examples and the thinking process:

    * **`OnUpdatePaymentDetailsCalled`:**
        * Creates a `PaymentRequestUpdateEvent`.
        * Creates a `MockPaymentRequest`.
        * Sets up the event (trusted, associated request, capturing phase).
        * Creates a `ScriptPromiseResolver`. This is the key link to JavaScript promises.
        * Calls `event->updateWith()` with the promise. This is the core method being tested.
        * Uses `EXPECT_CALL` to assert that `OnUpdatePaymentDetails` on the mock object will be called.
        * Resolves the promise. This should trigger the success callback.
        * **Inference:** This test checks if resolving the promise passed to `updateWith` correctly triggers the success callback on the delegate.

    * **`OnUpdatePaymentDetailsFailureCalled`:** Similar to the above, but the promise is *rejected*. This verifies the error handling path.

    * **`CannotUpdateWithoutDispatching`:**
        * Creates an event and a mock request.
        * Calls `updateWith` *without* setting the event phase or trust.
        * Expects an exception.
        * **Inference:** This tests a precondition – `updateWith` should only work if the event is properly dispatched (part of the event lifecycle).

    * **`CannotUpdateTwice`:** Calls `updateWith` twice. Expects an exception on the second call. This checks that `updateWith` can only be called once per event.

    * **`AddressChangeUpdateWithTimeout` and `OptionChangeUpdateWithTimeout`:**  These are more complex. They involve:
        * Creating a real `PaymentRequest`.
        * Simulating user interaction (using `LocalFrame::NotifyUserActivation`).
        * Calling `request->show()` which returns a promise.
        * Triggering `OnShippingAddressChange` (simulating a browser event).
        * Calling `request->OnUpdatePaymentDetailsTimeoutForTesting()`.
        * Checking if the `request->show()` promise is rejected with a specific error message.
        * Then, attempting to call `event->updateWith()` *after* the timeout and expecting an error.
        * **Inference:** These tests check the timeout mechanism for `updateWith` and how it interacts with the overall `PaymentRequest` lifecycle. They also show how browser events trigger `PaymentRequestUpdateEvent`s.

    * **`NotAllowUntrustedEvent`:** Creates an untrusted event and calls `updateWith`. Expects an exception. This enforces security restrictions.

7. **Connect to JavaScript, HTML, and CSS:**

    * **JavaScript:** The presence of `ScriptPromiseResolver` and the interaction with the `PaymentRequest` API directly relate to JavaScript. The `PaymentRequestUpdateEvent` is triggered in response to JavaScript actions (e.g., the website handling `shippingaddresschange` or `shippingoptionchange` events). The `updateWith` method takes a JavaScript promise.
    * **HTML:**  The Payment Request API is invoked by JavaScript running within an HTML page. The user interacts with UI elements on the page, which can trigger these events.
    * **CSS:** While CSS isn't directly involved in the *logic* of this test, the rendering and appearance of the payment sheet (which triggers these events) are styled with CSS.

8. **Identify Potential User/Programming Errors:**

    * Calling `updateWith` outside the event dispatching phase.
    * Calling `updateWith` multiple times for the same event.
    * Not resolving or rejecting the promise passed to `updateWith`, leading to timeouts.
    * Expecting `updateWith` to work on untrusted events.

9. **Trace User Operations:**  Think about the user flow:

    * User visits a website that uses the Payment Request API.
    * The website calls `new PaymentRequest(...)`.
    * The website registers event listeners for `shippingaddresschange` or `shippingoptionchange`.
    * The user interacts with the payment sheet (e.g., changes the shipping address).
    * This triggers a browser event, leading to the creation of a `PaymentRequestUpdateEvent`.
    * The website's event listener is invoked.
    * The website calls `event.updateWith(promise)`.
    * The promise resolves or rejects, updating the payment details.

This systematic approach, combining code analysis with an understanding of the underlying concepts and user interactions, allows for a comprehensive explanation of the test file's functionality.
This C++ source code file, `payment_request_update_event_test.cc`, contains unit tests for the `PaymentRequestUpdateEvent` class within the Chromium Blink rendering engine. Essentially, it verifies that the `PaymentRequestUpdateEvent` class behaves as expected in various scenarios.

Here's a breakdown of its functionalities:

**Core Functionality:**

* **Testing `PaymentRequestUpdateEvent`'s lifecycle and behavior:** The tests simulate different situations related to the `PaymentRequestUpdateEvent` and assert that the event triggers the correct actions and callbacks.
* **Verifying the `updateWith()` method:**  A key function of `PaymentRequestUpdateEvent` is `updateWith()`, which allows the website to provide updated payment details (like total price or shipping options) in response to events like `shippingaddresschange` or `shippingoptionchange`. The tests check if this method works correctly when the promise it takes is resolved or rejected.
* **Testing error conditions:** The tests also cover scenarios where things go wrong, such as calling `updateWith()` multiple times, calling it before the event is dispatched, or when the promise provided to `updateWith()` times out.
* **Ensuring security:** One test specifically verifies that `updateWith()` cannot be called on an untrusted event.
* **Testing timeout scenarios:** Several tests focus on what happens when the website doesn't respond within a reasonable time to a `shippingaddresschange` or `shippingoptionchange` event by calling `updateWith()`.

**Relationship with JavaScript, HTML, and CSS:**

This C++ code is part of the underlying implementation of the Payment Request API in the browser, which is exposed to web developers through JavaScript.

* **JavaScript:**
    * **Event Handling:** The `PaymentRequestUpdateEvent` is dispatched to JavaScript event listeners when specific events occur during the payment flow, such as the user changing their shipping address or shipping option. For example, a website might have JavaScript code like this:
      ```javascript
      paymentRequest.addEventListener('shippingaddresschange', async (evt) => {
        // Fetch updated shipping options and total based on the new address
        const shippingOptions = await fetchShippingOptions(evt.shippingAddress);
        const updatedTotal = calculateTotal(shippingOptions);

        // Update the payment request with the new details
        evt.updateWith({
          shippingOptions: shippingOptions,
          total: updatedTotal
        });
      });
      ```
    * **`updateWith()` method:** The `evt.updateWith()` call in the JavaScript example directly corresponds to the `updateWith()` method being tested in this C++ file. The promise passed to `updateWith()` in JavaScript is handled by the code in this test file.

* **HTML:**
    * The Payment Request API is initiated from JavaScript within an HTML page. User interactions within the payment UI (provided by the browser) trigger the events that lead to the `PaymentRequestUpdateEvent`. For instance, the user selecting a different address in the payment sheet.

* **CSS:**
    * While this specific C++ file doesn't directly interact with CSS, the overall Payment Request UI that triggers these events is styled using the browser's default styles and potentially some influence from the website's CSS.

**Logical Reasoning with Assumptions:**

Let's consider the `OnUpdatePaymentDetailsCalled` test as an example of logical reasoning:

* **Assumption Input:** A `PaymentRequestUpdateEvent` of type `shippingaddresschange` is created and associated with a `MockPaymentRequest`. A JavaScript Promise is created using `ScriptPromiseResolver`. This promise is passed to the `event->updateWith()` method.
* **Logical Step:** The `PaymentRequestUpdateEvent`'s internal logic should then signal the associated `PaymentRequest` (in this case, the mock) to update its payment details. If the promise passed to `updateWith()` is resolved, the `OnUpdatePaymentDetails` method of the `MockPaymentRequest` should be called.
* **Expected Output:** The test asserts that `request->OnUpdatePaymentDetails(testing::_)` is called. The `testing::_` is a Google Mock matcher that matches any argument. The test also asserts that `OnUpdatePaymentDetailsFailure` is *not* called.

**User or Programming Common Usage Errors:**

* **Calling `updateWith()` outside an event handler:** A common mistake would be trying to call `updateWith()` when no `shippingaddresschange` or `shippingoptionchange` event is being processed. The test `CannotUpdateWithoutDispatching` verifies that this results in an error.
    * **Example:**
      ```javascript
      // Incorrect: Trying to update without an event
      paymentRequest.updateWith({ total: { label: 'Total', amount: { currency: 'USD', value: '10.00' } } });
      ```
* **Calling `updateWith()` multiple times within the same event handler:** The specification likely intends for a single update per event. The test `CannotUpdateTwice` ensures that calling `updateWith()` more than once throws an error.
    * **Example:**
      ```javascript
      paymentRequest.addEventListener('shippingaddresschange', async (evt) => {
        evt.updateWith({ shippingOptions: [...] });
        // Incorrect: Trying to update again in the same handler
        evt.updateWith({ total: { label: 'Total', amount: { currency: 'USD', value: '12.00' } } });
      });
      ```
* **Not resolving or rejecting the promise passed to `updateWith()`:** If the website's JavaScript code doesn't eventually resolve or reject the promise provided to `updateWith()`, the payment flow might get stuck, and the browser might time out. The tests like `AddressChangePromiseTimeout` and `OptionChangePromiseTimeout` simulate this and verify the timeout behavior.
    * **Example:**
      ```javascript
      paymentRequest.addEventListener('shippingaddresschange', async (evt) => {
        // Imagine an error occurs during fetching shipping options, but the promise is never rejected.
        try {
          const shippingOptions = await fetchShippingOptions(evt.shippingAddress);
          evt.updateWith({ shippingOptions: shippingOptions });
        } catch (error) {
          console.error("Error fetching shipping options:", error);
          // Missing: evt.updateWith(Promise.reject(error));
        }
      });
      ```
* **Expecting `updateWith()` to work on untrusted events:** For security reasons, only trusted events (those initiated by the browser in response to user interaction) should allow calling `updateWith()`. The `NotAllowUntrustedEvent` test enforces this.

**User Operations as Debugging Clues:**

To understand how a user operation might lead to this code being executed, consider the following steps:

1. **User Initiates Payment:** The user clicks a "Buy" button or a similar element on a website that uses the Payment Request API.
2. **JavaScript Creates Payment Request:** The website's JavaScript code creates a `PaymentRequest` object, specifying payment methods and details.
3. **Event Listeners are Registered:** The website registers event listeners for events like `shippingaddresschange` or `shippingoptionchange` on the `PaymentRequest` object.
4. **Payment Sheet is Shown:** The browser displays the payment sheet to the user, allowing them to select payment methods, shipping addresses, etc.
5. **User Changes Shipping Address:** The user interacts with the payment sheet and changes their shipping address.
6. **`shippingaddresschange` Event Dispatched:** The browser detects this change and dispatches a `shippingaddresschange` event to the JavaScript event listener.
7. **JavaScript Handles the Event:** The JavaScript event listener is triggered. Inside this listener:
    * The website might fetch updated shipping options and calculate the new total based on the new address.
    * The website calls `event.updateWith(promise)`, where `promise` represents the asynchronous operation of fetching and calculating the new details.
8. **C++ `PaymentRequestUpdateEvent` is Involved:** This is where the C++ code in `payment_request_update_event_test.cc` comes into play (although this file itself is just for testing). The browser's rendering engine creates a `PaymentRequestUpdateEvent` object (the class being tested).
9. **`updateWith()` Method is Called (Internally):** The JavaScript call to `event.updateWith(promise)` is translated into a call to the underlying C++ implementation of the `PaymentRequestUpdateEvent`'s `updateWith()` method.
10. **Promise Resolution or Rejection:**
    * **Success:** If the website successfully fetches and calculates the new details, the promise passed to `updateWith()` is resolved with the updated payment details. The C++ code handles this resolution and updates the payment request accordingly.
    * **Failure:** If an error occurs (e.g., network issue fetching shipping options), the promise is rejected. The C++ code handles the rejection and informs the Payment Request API about the failure.
11. **Payment Flow Continues or Aborts:** Based on the resolution or rejection of the promise, the payment flow continues with the updated details or is aborted.

Therefore, a user changing their shipping address in the payment sheet is a direct user action that can trigger the code being tested in this file as part of the browser's internal handling of the Payment Request API. The tests in this file ensure that this process works correctly and handles various success and error scenarios.

Prompt: 
```
这是目录为blink/renderer/modules/payments/payment_request_update_event_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/payments/payment_request_update_event.h"

#include <memory>

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/payments/payment_request.h"
#include "third_party/blink/renderer/modules/payments/payment_request_delegate.h"
#include "third_party/blink/renderer/modules/payments/payment_response.h"
#include "third_party/blink/renderer/modules/payments/payment_test_helper.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {
namespace {

class MockPaymentRequest : public GarbageCollected<MockPaymentRequest>,
                           public PaymentRequestDelegate {
 public:
  MockPaymentRequest() = default;

  MockPaymentRequest(const MockPaymentRequest&) = delete;
  MockPaymentRequest& operator=(const MockPaymentRequest&) = delete;

  ~MockPaymentRequest() override = default;

  MOCK_METHOD1(OnUpdatePaymentDetails, void(PaymentDetailsUpdate* details));
  MOCK_METHOD1(OnUpdatePaymentDetailsFailure, void(const String& error));
  bool IsInteractive() const override { return true; }

  void Trace(Visitor* visitor) const override {}
};

TEST(PaymentRequestUpdateEventTest, OnUpdatePaymentDetailsCalled) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  PaymentRequestUpdateEvent* event = PaymentRequestUpdateEvent::Create(
      scope.GetExecutionContext(), event_type_names::kShippingaddresschange);
  MockPaymentRequest* request = MakeGarbageCollected<MockPaymentRequest>();
  event->SetTrusted(true);
  event->SetPaymentRequest(request);
  event->SetEventPhase(Event::PhaseType::kCapturingPhase);
  auto* payment_details =
      MakeGarbageCollected<ScriptPromiseResolver<PaymentDetailsUpdate>>(
          scope.GetScriptState());
  event->updateWith(scope.GetScriptState(), payment_details->Promise(),
                    scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());

  EXPECT_CALL(*request, OnUpdatePaymentDetails(testing::_));
  EXPECT_CALL(*request, OnUpdatePaymentDetailsFailure(testing::_)).Times(0);

  payment_details->Resolve();
}

TEST(PaymentRequestUpdateEventTest, OnUpdatePaymentDetailsFailureCalled) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  PaymentRequestUpdateEvent* event = PaymentRequestUpdateEvent::Create(
      scope.GetExecutionContext(), event_type_names::kShippingaddresschange);
  MockPaymentRequest* request = MakeGarbageCollected<MockPaymentRequest>();
  event->SetTrusted(true);
  event->SetPaymentRequest(request);
  event->SetEventPhase(Event::PhaseType::kCapturingPhase);
  auto* payment_details =
      MakeGarbageCollected<ScriptPromiseResolver<PaymentDetailsUpdate>>(
          scope.GetScriptState());
  event->updateWith(scope.GetScriptState(), payment_details->Promise(),
                    scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());

  EXPECT_CALL(*request, OnUpdatePaymentDetails(testing::_)).Times(0);
  EXPECT_CALL(*request, OnUpdatePaymentDetailsFailure(testing::_));

  payment_details->Reject("oops");
}

TEST(PaymentRequestUpdateEventTest, CannotUpdateWithoutDispatching) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  PaymentRequestUpdateEvent* event = PaymentRequestUpdateEvent::Create(
      scope.GetExecutionContext(), event_type_names::kShippingaddresschange);
  event->SetPaymentRequest((MakeGarbageCollected<MockPaymentRequest>()));

  event->updateWith(
      scope.GetScriptState(),
      MakeGarbageCollected<ScriptPromiseResolver<PaymentDetailsUpdate>>(
          scope.GetScriptState())
          ->Promise(),
      scope.GetExceptionState());

  EXPECT_TRUE(scope.GetExceptionState().HadException());
}

TEST(PaymentRequestUpdateEventTest, CannotUpdateTwice) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  PaymentRequestUpdateEvent* event = PaymentRequestUpdateEvent::Create(
      scope.GetExecutionContext(), event_type_names::kShippingaddresschange);
  MockPaymentRequest* request = MakeGarbageCollected<MockPaymentRequest>();
  event->SetTrusted(true);
  event->SetPaymentRequest(request);
  event->SetEventPhase(Event::PhaseType::kCapturingPhase);
  event->updateWith(
      scope.GetScriptState(),
      MakeGarbageCollected<ScriptPromiseResolver<PaymentDetailsUpdate>>(
          scope.GetScriptState())
          ->Promise(),
      scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());

  event->updateWith(
      scope.GetScriptState(),
      MakeGarbageCollected<ScriptPromiseResolver<PaymentDetailsUpdate>>(
          scope.GetScriptState())
          ->Promise(),
      scope.GetExceptionState());

  EXPECT_TRUE(scope.GetExceptionState().HadException());
}

TEST(PaymentRequestUpdateEventTest, UpdaterNotRequired) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  PaymentRequestUpdateEvent* event = PaymentRequestUpdateEvent::Create(
      scope.GetExecutionContext(), event_type_names::kShippingaddresschange);
  event->SetTrusted(true);

  event->updateWith(
      scope.GetScriptState(),
      MakeGarbageCollected<ScriptPromiseResolver<PaymentDetailsUpdate>>(
          scope.GetScriptState())
          ->Promise(),
      scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
}

TEST(PaymentRequestUpdateEventTest, AddressChangeUpdateWithTimeout) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), scope.GetExceptionState());
  PaymentRequestUpdateEvent* event = PaymentRequestUpdateEvent::Create(
      scope.GetExecutionContext(), event_type_names::kShippingaddresschange);
  event->SetPaymentRequest(request);
  event->SetTrusted(true);
  EXPECT_FALSE(scope.GetExceptionState().HadException());

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), scope.GetExceptionState()));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnShippingAddressChange(BuildPaymentAddressForTest());
  request->OnUpdatePaymentDetailsTimeoutForTesting();

  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_EQ(
      "AbortError: Timed out waiting for a "
      "PaymentRequestUpdateEvent.updateWith(promise) to resolve.",
      promise_tester.ValueAsString());

  event->updateWith(
      scope.GetScriptState(),
      MakeGarbageCollected<ScriptPromiseResolver<PaymentDetailsUpdate>>(
          scope.GetScriptState())
          ->Promise(),
      scope.GetExceptionState());

  EXPECT_TRUE(scope.GetExceptionState().HadException());
  EXPECT_EQ("PaymentRequest is no longer interactive",
            scope.GetExceptionState().Message());
}

TEST(PaymentRequestUpdateEventTest, OptionChangeUpdateWithTimeout) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), scope.GetExceptionState());
  PaymentRequestUpdateEvent* event = PaymentRequestUpdateEvent::Create(
      scope.GetExecutionContext(), event_type_names::kShippingoptionchange);
  event->SetTrusted(true);
  event->SetPaymentRequest(request);
  EXPECT_FALSE(scope.GetExceptionState().HadException());

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), scope.GetExceptionState()));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnShippingAddressChange(BuildPaymentAddressForTest());
  request->OnUpdatePaymentDetailsTimeoutForTesting();

  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_EQ(
      "AbortError: Timed out waiting for a "
      "PaymentRequestUpdateEvent.updateWith(promise) to resolve.",
      promise_tester.ValueAsString());

  event->updateWith(
      scope.GetScriptState(),
      MakeGarbageCollected<ScriptPromiseResolver<PaymentDetailsUpdate>>(
          scope.GetScriptState())
          ->Promise(),
      scope.GetExceptionState());

  EXPECT_TRUE(scope.GetExceptionState().HadException());
  EXPECT_EQ("PaymentRequest is no longer interactive",
            scope.GetExceptionState().Message());
}

TEST(PaymentRequestUpdateEventTest, AddressChangePromiseTimeout) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());
  PaymentRequestUpdateEvent* event = PaymentRequestUpdateEvent::Create(
      scope.GetExecutionContext(), event_type_names::kShippingaddresschange);
  event->SetTrusted(true);
  event->SetPaymentRequest(request);
  event->SetEventPhase(Event::PhaseType::kCapturingPhase);

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), scope.GetExceptionState()));
  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnShippingAddressChange(BuildPaymentAddressForTest());
  auto* payment_details =
      MakeGarbageCollected<ScriptPromiseResolver<PaymentDetailsUpdate>>(
          scope.GetScriptState());
  event->updateWith(scope.GetScriptState(), payment_details->Promise(),
                    scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());

  request->OnUpdatePaymentDetailsTimeoutForTesting();

  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_EQ(
      "AbortError: Timed out waiting for a "
      "PaymentRequestUpdateEvent.updateWith(promise) to resolve.",
      promise_tester.ValueAsString());

  payment_details->Resolve();
}

TEST(PaymentRequestUpdateEventTest, OptionChangePromiseTimeout) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());
  PaymentRequestUpdateEvent* event = PaymentRequestUpdateEvent::Create(
      scope.GetExecutionContext(), event_type_names::kShippingoptionchange);
  event->SetTrusted(true);
  event->SetPaymentRequest(request);
  event->SetEventPhase(Event::PhaseType::kCapturingPhase);

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), scope.GetExceptionState()));
  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnShippingAddressChange(BuildPaymentAddressForTest());
  auto* payment_details =
      MakeGarbageCollected<ScriptPromiseResolver<PaymentDetailsUpdate>>(
          scope.GetScriptState());
  event->updateWith(scope.GetScriptState(), payment_details->Promise(),
                    scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());

  request->OnUpdatePaymentDetailsTimeoutForTesting();

  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_EQ(
      "AbortError: Timed out waiting for a "
      "PaymentRequestUpdateEvent.updateWith(promise) to resolve.",
      promise_tester.ValueAsString());

  payment_details->Resolve();
}

TEST(PaymentRequestUpdateEventTest, NotAllowUntrustedEvent) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  PaymentRequestUpdateEvent* event = PaymentRequestUpdateEvent::Create(
      scope.GetExecutionContext(), event_type_names::kShippingaddresschange);
  event->SetTrusted(false);

  event->updateWith(
      scope.GetScriptState(),
      MakeGarbageCollected<ScriptPromiseResolver<PaymentDetailsUpdate>>(
          scope.GetScriptState())
          ->Promise(),
      scope.GetExceptionState());

  EXPECT_TRUE(scope.GetExceptionState().HadException());
}

}  // namespace
}  // namespace blink

"""

```