Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Question:** The request is about analyzing a C++ test file (`payment_request_test.cc`) for the Chromium Blink engine's Payments API. The key is to understand what aspects of the PaymentRequest functionality this file tests and how it relates to web technologies (JavaScript, HTML, CSS) and user interaction.

2. **Identify the File's Purpose:** The file name itself (`payment_request_test.cc`) strongly suggests that it contains unit tests for the `PaymentRequest` C++ class. This class is a core part of the Payment Request API in Blink.

3. **Analyze the Includes:** The included headers provide vital clues about the file's functionality:
    * `payment_request.h`:  Confirms this file is testing the `PaymentRequest` class.
    * `testing/gtest/include/gtest/gtest.h`:  Indicates the use of Google Test for unit testing.
    * `mojom/frame/user_activation_notification_type.mojom-blink.h`: Shows interaction with user activation concepts.
    * `bindings/core/v8/...`:  Highlights the integration with the V8 JavaScript engine. This is a crucial link to JavaScript.
    * `core/dom/document.h`, `core/dom/events/...`, `core/frame/local_frame.h`: Points to the DOM and frame interactions, connecting to HTML.
    * `modules/payments/...`:  Shows it's part of the Payments module.
    * `platform/bindings/exception_code.h`: Indicates handling of errors and exceptions, which are important in both C++ and JavaScript contexts.
    * The other includes are generally support/utility headers for testing.

4. **Examine the Test Cases (The `TEST()` blocks):**  This is the most important part. Each `TEST()` block focuses on testing a specific aspect of the `PaymentRequest` class. I'll go through them logically:

    * **Basic Creation and Validation:**  Tests like `NoExceptionWithValidData` and `SupportedMethodListRequired` check the basic creation and input validation of `PaymentRequest` objects. This relates to how a developer would instantiate the `PaymentRequest` in JavaScript.
    * **Shipping Options:**  Several tests (`NullShippingOptionWhenNoOptionsAvailable`, `DontSelectSingleAvailableShippingOptionByDefault`, etc.) focus on how shipping options are handled. This directly relates to the `PaymentDetailsInit` dictionary in the JavaScript API and how developers provide shipping information.
    * **Shipping Type:** Tests like `NullShippingTypeWhenRequestShippingIsFalse` and `DeliveryShippingTypeWhenShippingTypeIsDelivery` verify the behavior of the `shippingType` option, which is also configurable in JavaScript.
    * **`show()` Method and Promises:** Tests involving `RejectShowPromiseOnInvalidShippingAddress`, `CannotCallShowTwice`, `ShowConsumesUserActivation`, `RejectShowPromiseOnError...`, etc., examine the `show()` method. This method returns a Promise in JavaScript, and these tests check different success and failure scenarios of that Promise.
    * **Event Handling (`onshippingaddresschange`, `onshippingoptionchange`, `onpaymentmethodchange`):**  Tests like `OnShippingOptionChange` and `NoCrashWhenPaymentMethodChangeEventDestroysContext` verify the functionality of the event handlers that developers can set in JavaScript.
    * **`abort()` Method:** The test `CannotShowAfterAborted` checks the behavior after the `abort()` method is called, reflecting how a merchant might cancel the payment flow in JavaScript.
    * **Activation and User Gestures:** Tests like `ShowConsumesUserActivation` and `ActivationlessShow` explore how the `show()` method interacts with user activation, a security feature in browsers.
    * **`updateWith()`/`OnUpdatePaymentDetails...`:**  Tests related to `IgnoreUpdatePaymentDetailsAfterShowPromiseResolved`, `ClearShippingOptionOnPaymentDetailsUpdate...`, and `UseTheSelectedShippingOptionFromPaymentDetailsUpdate` focus on the `updateWith()` functionality (often implicitly triggered by events in the Payment Request flow), which allows the merchant to dynamically update the payment details.
    * **Error Handling:** Tests like `ShouldResolveWithExceptionIfIDsOfShippingOptionsAreDuplicated` check for specific error conditions.
    * **`id` Property:** The `DetailsIdIsSet` test verifies the `id` property of the `PaymentRequest`.
    * **Secure Payment Confirmation (SPC):** Tests like `SPCActivationlessShow` and `SPCActivationlessNotConsumedWithActivation` cover specific behavior related to the Secure Payment Confirmation extension of the Payment Request API.
    * **Deprecated Payment Methods:** The tests `DeprecatedPaymentMethod` and `NotDeprecatedPaymentMethod` check for the correct identification of deprecated payment method identifiers.

5. **Relate to JavaScript, HTML, and CSS:**

    * **JavaScript:** The `PaymentRequest` class is directly exposed to JavaScript. The tests mirror how a developer would use the API in JavaScript (creating the object, setting options, calling `show()`, handling promises and events). The tests that use `ScriptPromiseTester` are explicitly testing the asynchronous behavior exposed through JavaScript Promises.
    * **HTML:** The Payment Request API is invoked from JavaScript within the context of a web page (an HTML document). The tests touch upon document-level concepts (like `IsUseCounted` for feature usage). The user interaction that triggers the Payment Request flow happens through HTML elements and JavaScript event handlers.
    * **CSS:** While this specific test file doesn't directly test CSS, the visual presentation of the payment sheet (triggered by `show()`) is styled using the browser's internal stylesheets and can sometimes be influenced by platform-specific CSS.

6. **Logical Inference, Assumptions, and Output:** For each test, I consider the setup (the input data, the actions taken) and the expected outcome (the assertions). For example, in `SupportedMethodListRequired`, the assumption is that providing an empty list of payment methods is invalid, and the expected output is a `TypeError`.

7. **User and Programming Errors:**  I look for tests that specifically check for scenarios that might arise due to incorrect usage of the API. Examples include:
    * Not providing supported payment methods.
    * Calling `show()` multiple times.
    * Trying to use `show()` after aborting.
    * Providing invalid shipping address data.
    * Duplicating shipping option IDs.

8. **User Operation Flow and Debugging:** I think about how a user interacting with a web page might trigger the code being tested. This involves imagining the sequence of actions:
    * User clicks a "Buy Now" button.
    * JavaScript code on the page creates a `PaymentRequest` object.
    * The developer provides payment method data, details, and options.
    * The `show()` method is called.
    * The browser displays the payment sheet.
    * The user interacts with the payment sheet (selects payment method, shipping address, etc.).
    * The merchant website might update details based on user selections (triggering `updateWith()`).
    * The user confirms or cancels the payment.

    As a debugger, knowing the steps in the test cases helps reproduce issues and understand the state of the `PaymentRequest` object at various stages. The test failures point to potential bugs or unexpected behavior in the C++ implementation.

By following these steps, I can systematically analyze the provided C++ test file and generate a comprehensive explanation that addresses all aspects of the request. The key is to connect the C++ test code back to the corresponding JavaScript API and the broader context of web development and user interaction.
This C++ file, `payment_request_test.cc`, is a unit test file within the Chromium Blink engine. Its primary function is to **test the functionality of the `PaymentRequest` class**. The `PaymentRequest` class is a core component of the browser's implementation of the **Payment Request API**, a web standard that allows websites to streamline the checkout process.

Here's a breakdown of its functionalities and relationships:

**Core Functionality Being Tested:**

* **Creation of `PaymentRequest` objects:**  Tests if the `PaymentRequest` object can be created successfully with valid data and throws errors with invalid data.
* **Handling of Payment Method Data:** Verifies that providing a list of supported payment methods is mandatory.
* **Shipping Options Logic:** Tests how shipping options are handled, including:
    * Whether a default shipping option is selected automatically.
    * How selected shipping options are identified.
    * How updates to shipping options via `PaymentDetailsUpdate` are processed.
* **Shipping Type Logic:** Tests the handling of the `shippingType` option (e.g., "shipping", "delivery", "pickup").
* **The `show()` method:** This is a crucial part of the API. The tests cover:
    * Successful invocation of `show()`.
    * Rejection of the promise returned by `show()` under various error conditions (invalid shipping address, payment method not supported, user cancellation, update details failure).
    * Prevention of calling `show()` multiple times.
    * Behavior of `show()` after the request has been aborted.
    * User activation requirements for `show()`.
    * Testing of "activationless show" scenarios (where user interaction isn't strictly required).
* **Event Handling:** Tests the functionality of event handlers like `onshippingaddresschange`, `onshippingoptionchange`, and `onpaymentmethodchange`.
* **The `abort()` method:** Tests if calling `abort()` prevents further actions.
* **Updating Payment Details:** Tests the `OnUpdatePaymentDetails` callback, which reflects the JavaScript `details.updateWith()` method or events like `shippingaddresschange` and `shippingoptionchange`. It checks how updates affect shipping options and handles errors.
* **Error Handling:** Verifies that specific errors are thrown or promises are rejected as expected when invalid input or state occurs (e.g., duplicate shipping option IDs).
* **The `id` property:** Tests if the `id` property of the `PaymentRequest` object is correctly set.
* **Interaction with the underlying payment app/service:** While these tests don't directly mock the payment app, they simulate the callbacks the `PaymentRequest` object receives from the browser's payment handling logic.
* **Secure Payment Confirmation (SPC):** Tests specific behaviors related to the Secure Payment Confirmation extension of the Payment Request API, including activationless show scenarios.
* **Handling of deprecated payment methods:** Checks if using a deprecated payment method is correctly identified and potentially flagged.

**Relationship with JavaScript, HTML, and CSS:**

This C++ test file directly tests the underlying implementation of the **JavaScript Payment Request API**. Here's how they relate:

* **JavaScript:**  Developers use the `PaymentRequest` object in JavaScript to initiate the payment flow. The C++ code in this file is the engine that powers that JavaScript API. Each test case often mirrors a scenario that a JavaScript developer might encounter.
    * **Example:** The JavaScript code `const request = new PaymentRequest(methodData, details, options);` corresponds to the `PaymentRequest::Create()` calls in the C++ tests. The tests verify that passing different `methodData`, `details`, and `options` results in the expected behavior.
    * **Example:** The JavaScript promise returned by `request.show()` is tested by the `ScriptPromiseTester` in the C++ tests, verifying its resolution and rejection under various conditions.
    * **Example:** JavaScript event listeners like `request.onshippingaddresschange = function(event) { ... };` are indirectly tested by simulating the browser calling the corresponding C++ methods like `OnShippingAddressChange`.

* **HTML:** The Payment Request API is invoked from JavaScript running within an HTML page. While this test file doesn't directly manipulate HTML, it tests the logic triggered by user interactions within a web page that lead to JavaScript calling the Payment Request API.
    * **Example:** A user clicking a "Buy Now" button in an HTML form might trigger the JavaScript code that creates and shows a `PaymentRequest`. The C++ tests ensure the `PaymentRequest` behaves correctly after such an action.

* **CSS:**  CSS is primarily responsible for the visual presentation of the payment sheet displayed by the browser when `request.show()` is called. This C++ test file doesn't directly test CSS. However, the functionality it tests ensures that the data and logic used to populate that payment sheet are correct.

**Logical Inference, Assumptions, and Output:**

Each `TEST()` block in the file represents a specific scenario and makes certain assumptions.

* **Assumption Example:** The test `PaymentRequestTest, NoExceptionWithValidData` assumes that if valid payment method data and details are provided, creating a `PaymentRequest` should not throw an exception.
* **Input Example (Implicit):** In `PaymentRequestTest, SupportedMethodListRequired`, the implicit input is an empty `HeapVector<Member<PaymentMethodData>>`.
* **Expected Output Example:** The `EXPECT_TRUE(scope.GetExceptionState().HadException());` in `PaymentRequestTest, SupportedMethodListRequired` asserts that creating a `PaymentRequest` with an empty method list should result in an exception.

**User or Programming Common Usage Errors:**

This test file helps identify and prevent common errors developers might make when using the Payment Request API:

* **Not providing payment method data:** The `SupportedMethodListRequired` test highlights that this is a mandatory parameter.
* **Calling `show()` without user activation:** Some tests check that `show()` might require a user gesture (like a button click) for security reasons.
* **Calling `show()` multiple times:** The `CannotCallShowTwice` test prevents unexpected behavior from repeated calls.
* **Incorrectly handling shipping options:** Tests related to shipping options ensure that developers understand how to set and update them correctly.
* **Not handling errors from the `show()` promise:** The tests that reject the `show()` promise force developers to implement proper error handling in their JavaScript code.
* **Providing invalid data structures:** Tests implicitly check the correct format of the `PaymentMethodData` and `PaymentDetailsInit` objects.

**User Operation Flow as a Debugging Clue:**

Understanding how a user interacts with a webpage leading to the Payment Request API is crucial for debugging issues related to this code:

1. **User navigates to a website:** The user lands on a page that implements the Payment Request API.
2. **User initiates a purchase:** This might involve clicking a "Buy Now" button or proceeding to checkout.
3. **JavaScript code is executed:** The website's JavaScript code creates a `PaymentRequest` object, providing payment method data, details (items being purchased, total cost), and options (like requesting shipping address).
4. **`request.show()` is called:** This triggers the browser to display the payment sheet.
5. **Browser interacts with the payment app:** The browser communicates with the user's preferred payment methods (e.g., saved credit cards, Google Pay).
6. **User selects payment information and shipping address:** The user interacts with the payment sheet.
7. **Browser sends updates to the website:**  Events like `shippingaddresschange` and `shippingoptionchange` are triggered, and the website can update payment details using `details.updateWith()`. This corresponds to the `OnShippingAddressChange` and `OnUpdatePaymentDetails` callbacks in the C++ code.
8. **User confirms or cancels the payment:**
    * **Confirmation:** The browser sends a payment response to the website. This relates to the `OnPaymentResponse` callback.
    * **Cancellation:** The `show()` promise is rejected with an "AbortError."
9. **Website processes the payment response:** The website completes the order.

**Debugging Clues:** If a test in `payment_request_test.cc` fails, it indicates a potential bug in the underlying C++ implementation of the `PaymentRequest` class. This could manifest in various ways for the user:

* The payment sheet might not display correctly.
* Incorrect shipping options might be presented.
* Errors might occur during the payment process.
* The website might not receive the correct payment information.

By examining the failing test case, developers can pinpoint the specific scenario where the `PaymentRequest` logic is flawed and then investigate the C++ code to identify and fix the bug. The test file acts as a safety net to ensure the Payment Request API functions as expected.

### 提示词
```
这是目录为blink/renderer/modules/payments/payment_request_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/payments/payment_request.h"

#include <memory>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/modules/payments/payment_response.h"
#include "third_party/blink/renderer/modules/payments/payment_test_helper.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {
namespace {

TEST(PaymentRequestTest, NoExceptionWithValidData) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
}

TEST(PaymentRequestTest, SupportedMethodListRequired) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentRequest::Create(
      scope.GetExecutionContext(), HeapVector<Member<PaymentMethodData>>(),
      BuildPaymentDetailsInitForTest(), scope.GetExceptionState());

  EXPECT_TRUE(scope.GetExceptionState().HadException());
  EXPECT_EQ(ESErrorType::kTypeError,
            scope.GetExceptionState().CodeAs<ESErrorType>());
}

TEST(PaymentRequestTest, NullShippingOptionWhenNoOptionsAvailable) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentDetailsInit* details = PaymentDetailsInit::Create();
  details->setTotal(BuildPaymentItemForTest());
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);

  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(), details,
      options, scope.GetExceptionState());

  EXPECT_TRUE(request->shippingOption().IsNull());
}

TEST(PaymentRequestTest, NullShippingOptionWhenMultipleOptionsAvailable) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentDetailsInit* details = PaymentDetailsInit::Create();
  details->setTotal(BuildPaymentItemForTest());
  HeapVector<Member<PaymentShippingOption>> shipping_options;
  shipping_options.push_back(BuildShippingOptionForTest());
  shipping_options.push_back(BuildShippingOptionForTest());
  details->setShippingOptions(shipping_options);
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);

  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(), details,
      options, scope.GetExceptionState());

  EXPECT_TRUE(request->shippingOption().IsNull());
}

TEST(PaymentRequestTest, DontSelectSingleAvailableShippingOptionByDefault) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentDetailsInit* details = PaymentDetailsInit::Create();
  details->setTotal(BuildPaymentItemForTest());
  details->setShippingOptions(HeapVector<Member<PaymentShippingOption>>(
      1, BuildShippingOptionForTest(kPaymentTestDataId,
                                    kPaymentTestOverwriteValue, "standard")));

  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(), details,
      scope.GetExceptionState());

  EXPECT_TRUE(request->shippingOption().IsNull());
}

TEST(PaymentRequestTest,
     DontSelectSingleAvailableShippingOptionWhenShippingNotRequested) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentDetailsInit* details = PaymentDetailsInit::Create();
  details->setTotal(BuildPaymentItemForTest());
  details->setShippingOptions(HeapVector<Member<PaymentShippingOption>>(
      1, BuildShippingOptionForTest()));
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(false);

  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(), details,
      options, scope.GetExceptionState());

  EXPECT_TRUE(request->shippingOption().IsNull());
}

TEST(PaymentRequestTest,
     DontSelectSingleUnselectedShippingOptionWhenShippingRequested) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentDetailsInit* details = PaymentDetailsInit::Create();
  details->setTotal(BuildPaymentItemForTest());
  details->setShippingOptions(HeapVector<Member<PaymentShippingOption>>(
      1, BuildShippingOptionForTest()));
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);

  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(), details,
      options, scope.GetExceptionState());

  EXPECT_TRUE(request->shippingOption().IsNull());
}

TEST(PaymentRequestTest,
     SelectSingleSelectedShippingOptionWhenShippingRequested) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentDetailsInit* details = PaymentDetailsInit::Create();
  details->setTotal(BuildPaymentItemForTest());
  HeapVector<Member<PaymentShippingOption>> shipping_options(
      1, BuildShippingOptionForTest(kPaymentTestDataId,
                                    kPaymentTestOverwriteValue, "standard"));
  shipping_options[0]->setSelected(true);
  details->setShippingOptions(shipping_options);
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);

  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(), details,
      options, scope.GetExceptionState());

  EXPECT_EQ("standard", request->shippingOption());
}

TEST(PaymentRequestTest,
     SelectOnlySelectedShippingOptionWhenShippingRequested) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentDetailsInit* details = PaymentDetailsInit::Create();
  details->setTotal(BuildPaymentItemForTest());
  HeapVector<Member<PaymentShippingOption>> shipping_options(2);
  shipping_options[0] = BuildShippingOptionForTest(
      kPaymentTestDataId, kPaymentTestOverwriteValue, "standard");
  shipping_options[0]->setSelected(true);
  shipping_options[1] = BuildShippingOptionForTest(
      kPaymentTestDataId, kPaymentTestOverwriteValue, "express");
  details->setShippingOptions(shipping_options);
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);

  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(), details,
      options, scope.GetExceptionState());

  EXPECT_EQ("standard", request->shippingOption());
}

TEST(PaymentRequestTest,
     SelectLastSelectedShippingOptionWhenShippingRequested) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentDetailsInit* details = PaymentDetailsInit::Create();
  details->setTotal(BuildPaymentItemForTest());
  HeapVector<Member<PaymentShippingOption>> shipping_options(2);
  shipping_options[0] = BuildShippingOptionForTest(
      kPaymentTestDataId, kPaymentTestOverwriteValue, "standard");
  shipping_options[0]->setSelected(true);
  shipping_options[1] = BuildShippingOptionForTest(
      kPaymentTestDataId, kPaymentTestOverwriteValue, "express");
  shipping_options[1]->setSelected(true);
  details->setShippingOptions(shipping_options);
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);

  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(), details,
      options, scope.GetExceptionState());

  EXPECT_EQ("express", request->shippingOption());
}

TEST(PaymentRequestTest, NullShippingTypeWhenRequestShippingIsFalse) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentDetailsInit* details = PaymentDetailsInit::Create();
  details->setTotal(BuildPaymentItemForTest());
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(false);

  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(), details,
      options, scope.GetExceptionState());

  EXPECT_FALSE(request->shippingType().has_value());
}

TEST(PaymentRequestTest,
     DefaultShippingTypeWhenRequestShippingIsTrueWithNoSpecificType) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentDetailsInit* details = PaymentDetailsInit::Create();
  details->setTotal(BuildPaymentItemForTest());
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);

  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(), details,
      options, scope.GetExceptionState());

  EXPECT_EQ("shipping", request->shippingType());
}

TEST(PaymentRequestTest, DeliveryShippingTypeWhenShippingTypeIsDelivery) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentDetailsInit* details = PaymentDetailsInit::Create();
  details->setTotal(BuildPaymentItemForTest());
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);
  options->setShippingType("delivery");

  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(), details,
      options, scope.GetExceptionState());

  EXPECT_EQ("delivery", request->shippingType());
}

TEST(PaymentRequestTest, PickupShippingTypeWhenShippingTypeIsPickup) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentDetailsInit* details = PaymentDetailsInit::Create();
  details->setTotal(BuildPaymentItemForTest());
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);
  options->setShippingType("pickup");

  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(), details,
      options, scope.GetExceptionState());

  EXPECT_EQ("pickup", request->shippingType());
}

TEST(PaymentRequestTest, RejectShowPromiseOnInvalidShippingAddress) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), ASSERT_NO_EXCEPTION);

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnShippingAddressChange(payments::mojom::blink::PaymentAddress::New());
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

TEST(PaymentRequestTest, OnShippingOptionChange) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), ASSERT_NO_EXCEPTION);

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION);

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnShippingOptionChange("standardShipping");
}

TEST(PaymentRequestTest, CannotCallShowTwice) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), ASSERT_NO_EXCEPTION);
  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION);

  // The second show() call will be rejected before user activation is checked,
  // so there is no need to re-trigger user-activation here.
  request->show(scope.GetScriptState(), scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().Code(),
            ToExceptionCode(DOMExceptionCode::kInvalidStateError));
}

TEST(PaymentRequestTest, CannotShowAfterAborted) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), ASSERT_NO_EXCEPTION);

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION);
  request->abort(scope.GetScriptState(), ASSERT_NO_EXCEPTION);
  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)->OnAbort(
      true);

  // The second show() call will be rejected before user activation is checked,
  // so there is no need to re-trigger user-activation here.
  request->show(scope.GetScriptState(), scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().Code(),
            ToExceptionCode(DOMExceptionCode::kInvalidStateError));
  ;
}

TEST(PaymentRequestTest, ShowConsumesUserActivation) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), ASSERT_NO_EXCEPTION);

  LocalFrame::NotifyUserActivation(
      &(scope.GetFrame()), mojom::UserActivationNotificationType::kTest);
  request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION);
  EXPECT_FALSE(LocalFrame::HasTransientUserActivation(&(scope.GetFrame())));
  EXPECT_FALSE(scope.GetDocument().IsUseCounted(
      WebFeature::kPaymentRequestShowWithoutGestureOrToken));
}

TEST(PaymentRequestTest, ActivationlessShow) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), ASSERT_NO_EXCEPTION);

  EXPECT_FALSE(LocalFrame::HasTransientUserActivation(&(scope.GetFrame())));
  EXPECT_FALSE(scope.GetDocument().IsUseCounted(
      WebFeature::kPaymentRequestActivationlessShow));
  EXPECT_FALSE(scope.GetDocument().IsUseCounted(
      WebFeature::kPaymentRequestShowWithoutGestureOrToken));

  request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION);
  EXPECT_TRUE(scope.GetDocument().IsUseCounted(
      WebFeature::kPaymentRequestActivationlessShow));
  EXPECT_TRUE(scope.GetDocument().IsUseCounted(
      WebFeature::kPaymentRequestShowWithoutGestureOrToken));
}

TEST(PaymentRequestTest, RejectShowPromiseOnErrorPaymentMethodNotSupported) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), ASSERT_NO_EXCEPTION);

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)->OnError(
      payments::mojom::blink::PaymentErrorReason::NOT_SUPPORTED,
      "The payment method \"foo\" is not supported");

  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_EQ("NotSupportedError: The payment method \"foo\" is not supported",
            promise_tester.ValueAsString());
}

TEST(PaymentRequestTest, RejectShowPromiseOnErrorCancelled) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), ASSERT_NO_EXCEPTION);

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)->OnError(
      payments::mojom::blink::PaymentErrorReason::USER_CANCEL,
      "Request cancelled");

  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_EQ("AbortError: Request cancelled", promise_tester.ValueAsString());
}

TEST(PaymentRequestTest, RejectShowPromiseOnUpdateDetailsFailure) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), ASSERT_NO_EXCEPTION);

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnShippingAddressChange(BuildPaymentAddressForTest());
  request->OnUpdatePaymentDetailsFailure("oops");

  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_EQ("AbortError: oops", promise_tester.ValueAsString());
}

TEST(PaymentRequestTest, IgnoreUpdatePaymentDetailsAfterShowPromiseResolved) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), ASSERT_NO_EXCEPTION);

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));
  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(BuildPaymentResponseForTest());

  request->OnUpdatePaymentDetails(nullptr);
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsFulfilled());
}

TEST(PaymentRequestTest,
     ClearShippingOptionOnPaymentDetailsUpdateWithoutShippingOptions) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentDetailsInit* details = PaymentDetailsInit::Create();
  details->setTotal(BuildPaymentItemForTest());
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(), details,
      options, ASSERT_NO_EXCEPTION);
  EXPECT_TRUE(request->shippingOption().IsNull());

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION);

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnShippingAddressChange(BuildPaymentAddressForTest());
  String detail_with_shipping_options =
      "{\"total\": {\"label\": \"Total\", \"amount\": {\"currency\": \"USD\", "
      "\"value\": \"5.00\"}},"
      "\"shippingOptions\": [{\"id\": \"standardShippingOption\", \"label\": "
      "\"Standard shipping\", \"amount\": {\"currency\": \"USD\", \"value\": "
      "\"5.00\"}, \"selected\": true}]}";
  request->OnUpdatePaymentDetails(PaymentDetailsUpdate::Create(
      scope.GetIsolate(),
      FromJSONString(scope.GetScriptState(), detail_with_shipping_options),
      ASSERT_NO_EXCEPTION));

  EXPECT_EQ("standardShippingOption", request->shippingOption());
  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnShippingAddressChange(BuildPaymentAddressForTest());
  String detail_without_shipping_options =
      "{\"total\": {\"label\": \"Total\", \"amount\": {\"currency\": \"USD\", "
      "\"value\": \"5.00\"}}}";
  request->OnUpdatePaymentDetails(PaymentDetailsUpdate::Create(
      scope.GetIsolate(),
      FromJSONString(scope.GetScriptState(), detail_without_shipping_options),
      ASSERT_NO_EXCEPTION));

  EXPECT_TRUE(request->shippingOption().IsNull());
}

TEST(
    PaymentRequestTest,
    ClearShippingOptionOnPaymentDetailsUpdateWithMultipleUnselectedShippingOptions) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION);

  String detail =
      "{\"total\": {\"label\": \"Total\", \"amount\": {\"currency\": \"USD\", "
      "\"value\": \"5.00\"}},"
      "\"shippingOptions\": [{\"id\": \"slow\", \"label\": \"Slow\", "
      "\"amount\": {\"currency\": \"USD\", \"value\": \"5.00\"}},"
      "{\"id\": \"fast\", \"label\": \"Fast\", \"amount\": {\"currency\": "
      "\"USD\", \"value\": \"50.00\"}}]}";

  request->OnUpdatePaymentDetails(PaymentDetailsUpdate::Create(
      scope.GetIsolate(), FromJSONString(scope.GetScriptState(), detail),
      ASSERT_NO_EXCEPTION));

  EXPECT_TRUE(request->shippingOption().IsNull());
}

TEST(PaymentRequestTest, UseTheSelectedShippingOptionFromPaymentDetailsUpdate) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION);
  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnShippingAddressChange(BuildPaymentAddressForTest());

  String detail =
      "{\"total\": {\"label\": \"Total\", \"amount\": {\"currency\": \"USD\", "
      "\"value\": \"5.00\"}},"
      "\"shippingOptions\": [{\"id\": \"slow\", \"label\": \"Slow\", "
      "\"amount\": {\"currency\": \"USD\", \"value\": \"5.00\"}},"
      "{\"id\": \"fast\", \"label\": \"Fast\", \"amount\": {\"currency\": "
      "\"USD\", \"value\": \"50.00\"}, \"selected\": true}]}";

  request->OnUpdatePaymentDetails(PaymentDetailsUpdate::Create(
      scope.GetIsolate(), FromJSONString(scope.GetScriptState(), detail),
      ASSERT_NO_EXCEPTION));

  EXPECT_EQ("fast", request->shippingOption());
}

TEST(PaymentRequestTest, NoExceptionWithErrorMessageInUpdate) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), ASSERT_NO_EXCEPTION);

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION);
  String detail_with_error_msg =
      "{\"total\": {\"label\": \"Total\", \"amount\": {\"currency\": \"USD\", "
      "\"value\": \"5.00\"}},"
      "\"error\": \"This is an error message.\"}";

  request->OnUpdatePaymentDetails(PaymentDetailsUpdate::Create(
      scope.GetIsolate(),
      FromJSONString(scope.GetScriptState(), detail_with_error_msg),
      ASSERT_NO_EXCEPTION));
}

TEST(PaymentRequestTest,
     ShouldResolveWithExceptionIfIDsOfShippingOptionsAreDuplicated) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentDetailsInit* details = PaymentDetailsInit::Create();
  details->setTotal(BuildPaymentItemForTest());
  HeapVector<Member<PaymentShippingOption>> shipping_options(2);
  shipping_options[0] = BuildShippingOptionForTest(
      kPaymentTestDataId, kPaymentTestOverwriteValue, "standard");
  shipping_options[0]->setSelected(true);
  shipping_options[1] = BuildShippingOptionForTest(
      kPaymentTestDataId, kPaymentTestOverwriteValue, "standard");
  details->setShippingOptions(shipping_options);
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);
  PaymentRequest::Create(scope.GetExecutionContext(),
                         BuildPaymentMethodDataForTest(), details, options,
                         scope.GetExceptionState());
  EXPECT_TRUE(scope.GetExceptionState().HadException());
}

TEST(PaymentRequestTest, DetailsIdIsSet) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentDetailsInit* details = PaymentDetailsInit::Create();
  details->setTotal(BuildPaymentItemForTest());
  details->setId("my_payment_id");

  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(), details,
      scope.GetExceptionState());

  EXPECT_EQ("my_payment_id", request->id());
}

// An event listener that owns a page and destroys it when the event is invoked.
class PageDeleter final : public NativeEventListener {
 public:
  PageDeleter()
      : holder_(DummyPageHolder::CreateAndCommitNavigation(
            KURL("https://www.example.com"))) {}
  ~PageDeleter() override = default;

  // NativeEventListener:
  void Invoke(ExecutionContext*, Event*) override { holder_.reset(); }

  DummyPageHolder* page() { return holder_.get(); }

 private:
  std::unique_ptr<DummyPageHolder> holder_;
};

TEST(PaymentRequestTest, NoCrashWhenPaymentMethodChangeEventDestroysContext) {
  test::TaskEnvironment task_environment;
  PageDeleter* page_deleter = MakeGarbageCollected<PageDeleter>();
  LocalFrame& frame = page_deleter->page()->GetFrame();
  auto* isolate = ToIsolate(&frame);
  v8::HandleScope handle_scope(isolate);
  ScriptState* script_state = ScriptState::From(
      isolate,
      ToV8ContextEvenIfDetached(&frame, DOMWrapperWorld::MainWorld(isolate)));
  v8::Local<v8::Context> context(script_state->GetContext());
  v8::Context::Scope context_scope(context);

  HeapVector<Member<PaymentMethodData>> method_data =
      BuildPaymentMethodDataForTest();
  PaymentRequest* request = PaymentRequest::Create(
      ExecutionContext::From(script_state), method_data,
      BuildPaymentDetailsInitForTest(), ASSERT_NO_EXCEPTION);
  request->setOnpaymentmethodchange(page_deleter);
  LocalFrame::NotifyUserActivation(
      &frame, mojom::UserActivationNotificationType::kTest);
  request->show(script_state, ASSERT_NO_EXCEPTION);

  // Trigger the event listener that deletes the execution context.
  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentMethodChange(method_data.front()->supportedMethod(),
                              /*stringified_details=*/"{}");
}

TEST(PaymentRequestTest, SPCActivationlessShow) {
  test::TaskEnvironment task_environment;

  PaymentRequestV8TestingScope scope;

  {
    PaymentRequest* request = PaymentRequest::Create(
        ExecutionContext::From(scope.GetScriptState()),
        BuildSecurePaymentConfirmationMethodDataForTest(scope),
        BuildPaymentDetailsInitForTest(), ASSERT_NO_EXCEPTION);

    EXPECT_FALSE(scope.GetDocument().IsUseCounted(
        WebFeature::kSecurePaymentConfirmationActivationlessShow));
    EXPECT_FALSE(scope.GetDocument().IsUseCounted(
        WebFeature::kPaymentRequestShowWithoutGestureOrToken));
    request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION);
    EXPECT_FALSE(LocalFrame::HasTransientUserActivation(&(scope.GetFrame())));
    EXPECT_TRUE(scope.GetDocument().IsUseCounted(
        WebFeature::kSecurePaymentConfirmationActivationlessShow));
    EXPECT_TRUE(scope.GetDocument().IsUseCounted(
        WebFeature::kPaymentRequestShowWithoutGestureOrToken));
  }
}

TEST(PaymentRequestTest, SPCActivationlessNotConsumedWithActivation) {
  test::TaskEnvironment task_environment;

  PaymentRequestV8TestingScope scope;

  // The first show call has an activation, so activationless SPC shouldn't be
  // recorded or consumed.
  {
    PaymentRequest* request = PaymentRequest::Create(
        ExecutionContext::From(scope.GetScriptState()),
        BuildSecurePaymentConfirmationMethodDataForTest(scope),
        BuildPaymentDetailsInitForTest(), ASSERT_NO_EXCEPTION);

    LocalFrame::NotifyUserActivation(
        &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
    request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION);
    EXPECT_FALSE(scope.GetDocument().IsUseCounted(
        WebFeature::kSecurePaymentConfirmationActivationlessShow));
    EXPECT_FALSE(scope.GetDocument().IsUseCounted(
        WebFeature::kPaymentRequestShowWithoutGestureOrToken));
  }

  // A following activationless SPC show call should be allowed, since the first
  // did not consume the one allowed activationless call.
  {
    PaymentRequest* request = PaymentRequest::Create(
        ExecutionContext::From(scope.GetScriptState()),
        BuildSecurePaymentConfirmationMethodDataForTest(scope),
        BuildPaymentDetailsInitForTest(), ASSERT_NO_EXCEPTION);

    request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION);
    EXPECT_TRUE(scope.GetDocument().IsUseCounted(
        WebFeature::kSecurePaymentConfirmationActivationlessShow));
    EXPECT_TRUE(scope.GetDocument().IsUseCounted(
        WebFeature::kPaymentRequestShowWithoutGestureOrToken));
  }
}

TEST(PaymentRequestTest, DeprecatedPaymentMethod) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  HeapVector<Member<PaymentMethodData>> method_data(
      1, PaymentMethodData::Create());
  method_data[0]->setSupportedMethod("https://android.com/pay");

  PaymentRequest::Create(ExecutionContext::From(scope.GetScriptState()),
                         method_data, BuildPaymentDetailsInitForTest(),
                         ASSERT_NO_EXCEPTION);

  EXPECT_TRUE(scope.GetDocument().IsUseCounted(
      WebFeature::kPaymentRequestDeprecatedPaymentMethod));
}

TEST(PaymentRequestTest, NotDeprecatedPaymentMethod) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  HeapVector<Member<PaymentMethodData>> method_data(
      1, PaymentMethodData::Create());
  method_data[0]->setSupportedMethod("https://example.test/pay");

  PaymentRequest::Create(ExecutionContext::From(scope.GetScriptState()),
                         method_data, BuildPaymentDetailsInitForTest(),
                         ASSERT_NO_EXCEPTION);

  EXPECT_FALSE(scope.GetDocument().IsUseCounted(
      WebFeature::kPaymentRequestDeprecatedPaymentMethod));
}

}  // namespace
}  // namespace blink
```