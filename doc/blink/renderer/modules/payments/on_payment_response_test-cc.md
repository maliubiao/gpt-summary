Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The first step is to recognize that this is a *test file*. The name `on_payment_response_test.cc` immediately suggests it's testing the `OnPaymentResponse` functionality within the Payments module of Blink.

2. **Identify the Core Functionality Under Test:** Look for keywords or function names that are central to the file's purpose. The comment "// Tests for PaymentRequest::OnPaymentResponse()." clearly states the target. This means the file will be setting up scenarios and verifying how `PaymentRequest::OnPaymentResponse()` behaves.

3. **Examine the Test Structure:**  Notice the use of `TEST()` macros. This indicates the use of the Google Test framework. Each `TEST()` block represents an individual test case.

4. **Analyze Individual Test Cases:**  For each test case, identify:
    * **The Scenario:** What specific situation is being set up?  Look at the `PaymentOptions` and the `PaymentResponse` objects being created. What data is being requested by the merchant, and what data (if any) is provided by the browser (simulated by the test)?
    * **The Expected Outcome:** What should happen in this scenario?  Is the `show()` promise expected to be resolved or rejected?  Look for `EXPECT_TRUE(promise_tester.IsRejected())` or how the resolved promise is handled (e.g., using `PaymentResponseFunction`).
    * **Key Objects and Methods:**  Identify the main classes involved (e.g., `PaymentRequest`, `PaymentOptions`, `PaymentResponse`) and the key methods being called (e.g., `Create`, `show`, `OnPaymentResponse`).

5. **Look for Patterns and Themes:** As you analyze individual tests, you'll notice recurring themes. In this file, the primary theme is validating the data exchange between the merchant's website (via `PaymentRequest`) and the browser's payment handling logic (simulated by providing a `PaymentResponse`). The tests focus on whether the required information (shipping address, payer name, email, phone) is correctly handled based on the merchant's requests.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Think about how this C++ code relates to the web development experience.
    * **JavaScript API:** The `PaymentRequest` API is a JavaScript API. This C++ code is the *implementation* of that API within the browser. The tests are verifying the correct behavior as seen from the JavaScript side (the promise resolution/rejection).
    * **HTML (Indirectly):**  While not directly manipulating HTML, the Payment Request flow is initiated from a webpage. The user interaction on the webpage (e.g., clicking a "Pay" button) leads to the JavaScript `PaymentRequest` being invoked.
    * **CSS (No Direct Relation):** CSS is primarily for styling. It doesn't directly influence the core logic of the Payment Request API being tested here.

7. **Consider User and Developer Errors:**  Think about common mistakes a web developer might make when using the Payment Request API, and how these tests might catch those errors. For example, a merchant might forget to request shipping when it's needed. The tests with `RejectMissingShippingOption` would catch this scenario. Similarly, a browser implementation could incorrectly provide data that wasn't requested. Tests like `RejectNotRequestedAddress` address this.

8. **Trace User Interaction:** Imagine the steps a user takes to trigger the payment flow. This helps understand how the browser gets to the point where `OnPaymentResponse` is called. The "User Operation to Reach This Point" section is crucial for this.

9. **Formulate the Summary:**  Based on the above analysis, synthesize the key functionalities of the file, its relationship to web technologies, the logical assumptions and outputs, potential errors, and the user journey.

**Self-Correction/Refinement during Analysis:**

* **Initial thought:** "This file tests the `PaymentResponse` class."
* **Correction:**  While `PaymentResponse` is involved, the tests are specifically about the `OnPaymentResponse` *method* of the `PaymentRequest` class. The file verifies how `PaymentRequest` handles receiving a `PaymentResponse`.

* **Initial thought:** "These tests directly interact with the UI."
* **Correction:** These are *unit tests*. They are isolated and don't involve the actual browser UI. They simulate the browser's response. The `PaymentRequestV8TestingScope` and the direct calls to `OnPaymentResponse` confirm this.

* **Thinking about assumptions:** What if the `BuildPaymentResponseForTest()` function returns different values in different scenarios? The tests rely on this function to create specific test responses. This highlights the importance of the implementation of the test helper functions.

By following these steps and continually refining your understanding, you can effectively analyze and explain the purpose and functionality of a complex code file like this one.
这个文件 `on_payment_response_test.cc` 是 Chromium Blink 引擎中 Payment Request API 的一个测试文件。它的主要功能是**测试 `PaymentRequest` 类中的 `OnPaymentResponse()` 方法的行为**。

`OnPaymentResponse()` 方法在支付流程中扮演着关键角色：当用户在支付界面完成支付操作（例如，选择了支付方式并确认）后，浏览器会将用户的支付信息封装成一个 `PaymentResponse` 对象，并通过 `OnPaymentResponse()` 方法传递给 `PaymentRequest` 对象。

**以下是该文件功能的详细解释和相关的举例说明：**

**1. 功能：验证 `OnPaymentResponse()` 方法对不同支付响应的处理逻辑。**

这个测试文件通过创建不同的 `PaymentRequest` 对象和模拟不同的 `PaymentResponse` 对象，来测试 `OnPaymentResponse()` 方法在各种情况下的行为。这些情况包括：

* **商家请求了特定信息（如收货地址、付款人姓名、邮箱、电话），而浏览器没有提供或提供了空值。**  测试预期 `show()` 方法返回的 Promise 会被拒绝。
* **商家没有请求特定信息，但浏览器提供了这些信息。** 测试预期 `show()` 方法返回的 Promise 会被拒绝。
* **商家请求了特定信息，浏览器也正确提供了这些信息。** 测试预期 `show()` 方法返回的 Promise 会被 resolve，并且包含相应的信息。
* **浏览器提供了无效的收货地址。** 测试预期 `show()` 方法返回的 Promise 会被拒绝。

**2. 与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  Payment Request API 是一个 JavaScript API，允许网站发起支付请求。`PaymentRequest` 类在 JavaScript 中被实例化和调用。这个 C++ 测试文件验证了 Blink 引擎中 `PaymentRequest` 类的内部实现逻辑，确保它能正确响应来自浏览器的支付响应。
    * **举例说明:**  在 JavaScript 中，网站可以创建 `PaymentRequest` 对象并调用 `show()` 方法来启动支付流程。当用户完成支付后，浏览器会调用 C++ 层的 `OnPaymentResponse()` 方法，该方法会根据测试文件中的逻辑来处理支付响应，并最终决定 JavaScript 的 `show()` 方法返回的 Promise 是 resolve 还是 reject。

* **HTML:**  虽然这个测试文件本身不直接涉及 HTML，但 Payment Request API 的使用通常与 HTML 元素（如按钮）相关联，用户点击这些元素来触发支付流程。
    * **举例说明:**  一个网页可能有一个 "立即购买" 的按钮。当用户点击该按钮时，JavaScript 代码会创建一个 `PaymentRequest` 对象并调用 `show()` 方法。

* **CSS:** CSS 用于网页的样式，与 `OnPaymentResponse()` 的核心逻辑没有直接关系。CSS 可以影响支付界面的外观，但不会影响 `PaymentRequest` 如何处理支付响应。

**3. 逻辑推理，假设输入与输出：**

* **假设输入 1：**
    * 商家创建 `PaymentRequest` 时，`PaymentOptions` 设置为需要收货地址 (`requestShipping = true`)。
    * 浏览器返回的 `PaymentResponse` 中缺少 `shipping_address`。
    * **预期输出：** `show()` 方法返回的 Promise 被拒绝 (rejected)。

* **假设输入 2：**
    * 商家创建 `PaymentRequest` 时，`PaymentOptions` 设置为不需要收货地址 (`requestShipping = false`)。
    * 浏览器返回的 `PaymentResponse` 中包含了 `shipping_address`。
    * **预期输出：** `show()` 方法返回的 Promise 被拒绝 (rejected)。

* **假设输入 3：**
    * 商家创建 `PaymentRequest` 时，`PaymentOptions` 设置为需要付款人姓名 (`requestPayerName = true`)。
    * 浏览器返回的 `PaymentResponse` 中包含了付款人姓名 (`payer->name = "John Doe"`)。
    * **预期输出：** `show()` 方法返回的 Promise 被 resolve，并且可以通过回调函数访问到付款人姓名 "John Doe"。

**4. 涉及用户或编程常见的使用错误：**

* **商家错误地配置了 `PaymentOptions`：**
    * **错误示例：** 商家需要用户的收货地址，但在创建 `PaymentRequest` 时忘记设置 `requestShipping = true`。  `OnPaymentResponseTest` 中的 `RejectNotRequestedAddress` 测试会覆盖这种情况，如果浏览器提供了地址，Promise 将会被拒绝，这有助于发现配置错误。
    * **用户操作影响：** 用户可能无法完成需要收货地址的购买流程。

* **浏览器支付实现的问题：**
    * **错误示例：** 浏览器在用户没有提供收货地址的情况下，仍然发送了一个包含空收货地址的 `PaymentResponse`。 `OnPaymentResponseTest` 中的 `RejectEmptyAddress` 测试会捕获这种情况，确保 `PaymentRequest` 不会接受不完整的数据。
    * **用户操作影响：** 可能导致支付流程中断或错误。

* **商家对支付响应数据的处理不当：**  虽然这个测试文件主要关注 `OnPaymentResponse()` 的处理，但商家在 JavaScript 中如何处理 `show()` 方法 resolve 后返回的 `PaymentResponse` 也很重要。
    * **错误示例：** 商家假设 `shippingAddress` 始终存在，但实际上用户可能没有提供地址，导致 JavaScript 代码出错。Payment Request API 的设计旨在让商家明确请求所需信息，并根据实际收到的信息进行处理。

**5. 用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户浏览到支持 Payment Request API 的电商网站。**
2. **用户将商品添加到购物车，并点击 "结算" 或类似的按钮。**
3. **网站的 JavaScript 代码创建一个 `PaymentRequest` 对象，指定支付方式、商品总价以及商家需要的用户信息（如收货地址）。** 例如：
   ```javascript
   const supportedPaymentMethods = [/* ... */];
   const paymentDetails = {/* ... */};
   const paymentOptions = {
       requestShipping: true, // 商家请求收货地址
       requestPayerName: true, // 商家请求付款人姓名
       // ... 其他选项
   };
   const paymentRequest = new PaymentRequest(supportedPaymentMethods, paymentDetails, paymentOptions);
   paymentRequest.show()
       .then(paymentResponse => {
           // 处理支付响应
           console.log(paymentResponse);
           paymentResponse.complete('success');
       })
       .catch(error => {
           // 处理错误
           console.error(error);
       });
   ```
4. **浏览器接收到 `paymentRequest.show()` 的调用，并显示支付界面。** 这个界面可能由浏览器自身提供，或者由底层的支付处理程序提供。
5. **用户在支付界面选择支付方式，并根据商家的请求填写必要的信息（例如，收货地址、姓名等）。**
6. **用户确认支付。**
7. **浏览器的支付处理逻辑将用户的支付信息封装成 `payments::mojom::blink::PaymentResponsePtr` 对象。**
8. **浏览器调用 Blink 渲染引擎中 `PaymentRequest` 对象的 `OnPaymentResponse()` 方法，并将 `PaymentResponsePtr` 作为参数传递给它。** 这就是 `on_payment_response_test.cc` 文件测试的入口点。
9. **`OnPaymentResponse()` 方法根据接收到的 `PaymentResponse` 和之前 `PaymentRequest` 的配置，更新内部状态，并最终决定 `paymentRequest.show()` 返回的 Promise 是 resolve 还是 reject。**

**作为调试线索：**

* 如果在支付流程中遇到问题，例如 `show()` 方法返回的 Promise 意外地被拒绝，可以检查 `on_payment_response_test.cc` 中的测试用例，看看是否有类似的场景被覆盖。
* 通过分析测试用例，可以了解 `PaymentRequest` 对各种支付响应的预期行为，从而帮助定位问题是出在商家前端代码、浏览器支付实现，还是两者之间的交互上。
* 例如，如果商家怀疑浏览器没有正确返回用户提供的收货地址，可以查看 `RejectMissingAddress` 或 `RejectEmptyAddress` 等测试用例，理解 `PaymentRequest` 在这些情况下的行为。

总而言之，`on_payment_response_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎中 `PaymentRequest` 类能够正确、可靠地处理来自浏览器的支付响应，从而保证了 Payment Request API 的正常运行。

### 提示词
```
这是目录为blink/renderer/modules/payments/on_payment_response_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

// Tests for PaymentRequest::OnPaymentResponse().

#include <utility>

#include "base/memory/raw_ptr_exclusion.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_response.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/payments/payment_address.h"
#include "third_party/blink/renderer/modules/payments/payment_request.h"
#include "third_party/blink/renderer/modules/payments/payment_response.h"
#include "third_party/blink/renderer/modules/payments/payment_test_helper.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {
namespace {

// If the merchant requests shipping information, but the browser does not
// provide the shipping option, reject the show() promise.
TEST(OnPaymentResponseTest, RejectMissingShippingOption) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->shipping_address = payments::mojom::blink::PaymentAddress::New();
  response->shipping_address->country = "US";

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

// If the merchant requests shipping information, but the browser does not
// provide a shipping address, reject the show() promise.
TEST(OnPaymentResponseTest, RejectMissingAddress) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->shipping_option = "standardShipping";

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

// If the merchant requests a payer name, but the browser does not provide it,
// reject the show() promise.
TEST(OnPaymentResponseTest, RejectMissingName) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestPayerName(true);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

// If the merchant requests an email address, but the browser does not provide
// it, reject the show() promise.
TEST(OnPaymentResponseTest, RejectMissingEmail) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestPayerEmail(true);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

// If the merchant requests a phone number, but the browser does not provide it,
// reject the show() promise.
TEST(OnPaymentResponseTest, RejectMissingPhone) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestPayerPhone(true);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

// If the merchant requests shipping information, but the browser provides an
// empty string for shipping option, reject the show() promise.
TEST(OnPaymentResponseTest, RejectEmptyShippingOption) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->shipping_option = "";
  response->shipping_address = payments::mojom::blink::PaymentAddress::New();
  response->shipping_address->country = "US";

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

// If the merchant requests shipping information, but the browser provides an
// empty shipping address, reject the show() promise.
TEST(OnPaymentResponseTest, RejectEmptyAddress) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  ;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->shipping_option = "standardShipping";
  response->shipping_address = payments::mojom::blink::PaymentAddress::New();

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

// If the merchant requests a payer name, but the browser provides an empty
// string for name, reject the show() promise.
TEST(OnPaymentResponseTest, RejectEmptyName) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestPayerName(true);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->payer->name = "";

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

// If the merchant requests an email, but the browser provides an empty string
// for email, reject the show() promise.
TEST(OnPaymentResponseTest, RejectEmptyEmail) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestPayerEmail(true);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->payer->email = "";

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

// If the merchant requests a phone number, but the browser provides an empty
// string for the phone number, reject the show() promise.
TEST(OnPaymentResponseTest, RejectEmptyPhone) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestPayerPhone(true);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->payer->phone = "";

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

// If the merchant does not request shipping information, but the browser
// provides a shipping address, reject the show() promise.
TEST(OnPaymentResponseTest, RejectNotRequestedAddress) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(false);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->shipping_address = payments::mojom::blink::PaymentAddress::New();
  response->shipping_address->country = "US";

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

// If the merchant does not request shipping information, but the browser
// provides a shipping option, reject the show() promise.
TEST(OnPaymentResponseTest, RejectNotRequestedShippingOption) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(false);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->shipping_option = "";

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

// If the merchant does not request a payer name, but the browser provides it,
// reject the show() promise.
TEST(OnPaymentResponseTest, RejectNotRequestedName) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestPayerName(false);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->payer->name = "";

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

// If the merchant does not request an email, but the browser provides it,
// reject the show() promise.
TEST(OnPaymentResponseTest, RejectNotRequestedEmail) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestPayerEmail(false);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->payer->email = "";

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

// If the merchant does not request a phone number, but the browser provides it,
// reject the show() promise.
TEST(OnPaymentResponseTest, RejectNotRequestedPhone) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestPayerPhone(false);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->payer->phone = "";

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

// If the merchant requests shipping information, but the browser provides an
// invalid shipping address, reject the show() promise.
TEST(OnPaymentResponseTest, RejectInvalidAddress) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->shipping_option = "standardShipping";
  response->shipping_address = payments::mojom::blink::PaymentAddress::New();
  response->shipping_address->country = "Atlantis";

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  ScriptPromiseTester promise_tester(
      scope.GetScriptState(),
      request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION));

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));
  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(promise_tester.IsRejected());
}

class PaymentResponseFunction
    : public ThenCallable<PaymentResponse, PaymentResponseFunction> {
 public:
  void React(ScriptState*, PaymentResponse* response) { response_ = response; }
  PaymentResponse* Response() const { return response_; }
  void Trace(Visitor* visitor) const override {
    ThenCallable<PaymentResponse, PaymentResponseFunction>::Trace(visitor);
    visitor->Trace(response_);
  }

 private:
  Member<PaymentResponse> response_;
};

// If the merchant requests shipping information, the resolved show() promise
// should contain a shipping option and an address.
TEST(OnPaymentResponseTest, CanRequestShippingInformation) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->shipping_option = "standardShipping";
  response->shipping_address = payments::mojom::blink::PaymentAddress::New();
  response->shipping_address->country = "US";

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  auto* response_function = MakeGarbageCollected<PaymentResponseFunction>();
  request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION)
      .Then(scope.GetScriptState(), response_function);

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));

  scope.PerformMicrotaskCheckpoint();
  EXPECT_EQ("standardShipping",
            response_function->Response()->shippingOption());
}

// If the merchant requests a payer name, the resolved show() promise should
// contain a payer name.
TEST(OnPaymentResponseTest, CanRequestName) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestPayerName(true);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->payer = payments::mojom::blink::PayerDetail::New();
  response->payer->name = "Jon Doe";

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  auto* response_function = MakeGarbageCollected<PaymentResponseFunction>();
  request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION)
      .Then(scope.GetScriptState(), response_function);

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));

  scope.PerformMicrotaskCheckpoint();
  EXPECT_EQ("Jon Doe", response_function->Response()->payerName());
}

// If the merchant requests an email address, the resolved show() promise should
// contain an email address.
TEST(OnPaymentResponseTest, CanRequestEmail) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestPayerEmail(true);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->payer->email = "abc@gmail.com";

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  auto* response_function = MakeGarbageCollected<PaymentResponseFunction>();
  request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION)
      .Then(scope.GetScriptState(), response_function);

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));

  scope.PerformMicrotaskCheckpoint();
  EXPECT_EQ("abc@gmail.com", response_function->Response()->payerEmail());
}

// If the merchant requests a phone number, the resolved show() promise should
// contain a phone number.
TEST(OnPaymentResponseTest, CanRequestPhone) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestPayerPhone(true);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->payer->phone = "0123";

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  auto* response_function = MakeGarbageCollected<PaymentResponseFunction>();
  request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION)
      .Then(scope.GetScriptState(), response_function);

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));
  scope.PerformMicrotaskCheckpoint();
  EXPECT_EQ("0123", response_function->Response()->payerPhone());
}

// If the merchant does not request shipping information, the resolved show()
// promise should contain null shipping option and address.
TEST(OnPaymentResponseTest, ShippingInformationNotRequired) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(false);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  auto* response_function = MakeGarbageCollected<PaymentResponseFunction>();
  request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION)
      .Then(scope.GetScriptState(), response_function);

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(BuildPaymentResponseForTest());

  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(response_function->Response()->shippingOption().IsNull());
  EXPECT_EQ(nullptr, response_function->Response()->shippingAddress());
}

// If the merchant does not request a phone number, the resolved show() promise
// should contain null phone number.
TEST(OnPaymentResponseTest, PhoneNotRequired) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestPayerPhone(false);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->payer->phone = String();

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  auto* response_function = MakeGarbageCollected<PaymentResponseFunction>();
  request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION)
      .Then(scope.GetScriptState(), response_function);

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));

  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(response_function->Response()->payerPhone().IsNull());
}

// If the merchant does not request a payer name, the resolved show() promise
// should contain null payer name.
TEST(OnPaymentResponseTest, NameNotRequired) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestPayerName(false);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->payer->name = String();

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  auto* response_function = MakeGarbageCollected<PaymentResponseFunction>();
  request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION)
      .Then(scope.GetScriptState(), response_function);

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));

  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(response_function->Response()->payerName().IsNull());
}

// If the merchant does not request an email address, the resolved show()
// promise should contain null email address.
TEST(OnPaymentResponseTest, EmailNotRequired) {
  test::TaskEnvironment task_environment;
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestPayerEmail(false);
  PaymentRequest* request = PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      BuildPaymentDetailsInitForTest(), options, ASSERT_NO_EXCEPTION);
  payments::mojom::blink::PaymentResponsePtr response =
      BuildPaymentResponseForTest();
  response->payer->email = String();

  LocalFrame::NotifyUserActivation(
      &scope.GetFrame(), mojom::UserActivationNotificationType::kTest);
  auto* response_function = MakeGarbageCollected<PaymentResponseFunction>();
  request->show(scope.GetScriptState(), ASSERT_NO_EXCEPTION)
      .Then(scope.GetScriptState(), response_function);

  static_cast<payments::mojom::blink::PaymentRequestClient*>(request)
      ->OnPaymentResponse(std::move(response));

  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(response_function->Response()->payerEmail().IsNull());
}

}  // namespace
}  // namespace blink
```