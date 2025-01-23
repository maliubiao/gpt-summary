Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Understand the Goal:** The request is to analyze a Chromium Blink engine test file (`payment_response_test.cc`) and explain its purpose, relationships with web technologies (JavaScript, HTML, CSS), logical deductions, potential user errors, and how a user might trigger this code.

2. **Identify the Core Subject:** The filename immediately tells us this file tests the `PaymentResponse` class within the Blink rendering engine's Payments module. This is the central object we need to understand.

3. **Scan for Key Imports and Namespaces:**  Look at the `#include` directives and the `namespace blink` and nested namespaces. This reveals the dependencies and the context of the code. We see imports related to:
    * **Testing:** `gmock`, `gtest` (clearly a test file).
    * **Blink Core:**  `ScriptValue`, `V8 bindings`, `ExceptionState`, `ScriptState`. This indicates interaction with JavaScript via the V8 engine.
    * **Blink Modules:**  Specific payment-related classes like `PaymentComplete`, `PaymentValidationErrors`, `PaymentAddress`, `PaymentStateResolver`. This confirms the file's domain.
    * **Platform:** `TaskEnvironment` (for asynchronous testing).
    * **Mojom:** `payments::mojom::blink::PaymentResponsePtr`. This tells us it interacts with the browser process through Mojo interfaces.

4. **Analyze the Test Structure:**  The file uses Google Test (`TEST`). Each `TEST` macro defines a distinct test case. This helps isolate the functionalities being tested.

5. **Examine Individual Test Cases:** Go through each `TEST` block and understand its intent:
    * **`DataCopiedOver`:**  This test checks if data from the `payments::mojom::blink::PaymentResponsePtr` (received from the browser process) is correctly copied into the `PaymentResponse` object. It checks properties like `methodName`, `shippingOption`, `payerName`, `payerEmail`, `payerPhone`, and extracts details from the JSON string.
    * **`PaymentResponseDetailsContainsSpcExtensionsPRF`:** This test focuses on a specific scenario involving Strong Customer Authentication (SCA) and the `prf` (pseudorandom function) extension. It verifies that if the browser provides PRF values, they are accessible in the `details` property of the `PaymentResponse`. The use of `GetClientExtensionResults` and `GetArrayBuffer` are key helper functions here.
    * **`PaymentResponseDetailsWithUnexpectedJSONFormatString`:** This handles the case where the `stringified_details` from the browser is not a valid JSON object. It verifies that the `details` property still returns an empty JavaScript object (`{}`). This is a good example of testing error handling.
    * **`PaymentResponseDetailsRetrunsTheSameObject`:** A simple test to ensure that calling the `details()` method multiple times returns the same JavaScript object instance. This is important for consistency.
    * **`CompleteCalledWithSuccess` and `CompleteCalledWithFailure`:** These test the `complete()` method of `PaymentResponse`. They use a mock `PaymentStateResolver` to verify that the correct completion status (`kSuccess` or `kFail`) is passed back to the payment processing logic.
    * **`JSONSerializerTest`:**  This test examines the `toJSONForBinding` method, which is used to serialize the `PaymentResponse` object into a JSON string for use in JavaScript. It checks that all relevant data is included and formatted correctly.

6. **Identify Relationships with Web Technologies:**
    * **JavaScript:** The `PaymentResponse` class is directly exposed to JavaScript through the Payment Request API. The tests manipulate `ScriptValue` and `v8::Object`, demonstrating the bridge between C++ and JavaScript. The `details` property is a key piece of JavaScript interaction.
    * **HTML:** While this test file doesn't directly involve HTML parsing, the Payment Request API is triggered by JavaScript code within a web page. The user interacts with HTML elements (like buttons) that initiate the payment flow.
    * **CSS:** CSS is not directly related to the *functionality* being tested here. However, CSS styles the UI elements that the user interacts with to initiate the payment process.

7. **Deduce Logical Inferences (Assumptions and Outputs):**
    * **Assumption:** The browser process (outside of Blink) is responsible for handling the actual payment processing and providing the initial `payments::mojom::blink::PaymentResponsePtr`.
    * **Output of `DataCopiedOver`:** Given a specific `input` Mojo object, the `PaymentResponse` object will have the corresponding properties set, and the JSON string in `stringified_details` will be parsed into a JavaScript object.
    * **Output of `PaymentResponseDetailsContainsSpcExtensionsPRF`:** If the browser provides PRF extensions, they will be accessible under the `prf.results` property in the JavaScript `details` object as ArrayBuffers.
    * **Output of `PaymentResponseDetailsWithUnexpectedJSONFormatString`:**  Even with invalid JSON, the `details` property will be a valid (empty) JavaScript object.

8. **Consider User and Programming Errors:**
    * **User Error:** A user might enter incorrect payment information, which would be reflected in the data sent back by the payment handler and potentially lead to a `PaymentStateResolver::kFail` scenario.
    * **Programming Error (Web Developer):** A web developer might expect a specific structure for the `details` property and not handle cases where `stringified_details` is invalid JSON. This test helps ensure Blink handles this gracefully.
    * **Programming Error (Blink Developer):** A bug in the C++ code could lead to data not being copied correctly from the Mojo object to the `PaymentResponse`, which these tests are designed to catch.

9. **Trace User Operations:** Think about the steps a user takes to reach this code:
    1. User visits a website with a payment form.
    2. JavaScript code on the website uses the Payment Request API (`new PaymentRequest(...)`).
    3. The user interacts with the payment UI (e.g., selects a payment method, enters details).
    4. The browser (outside of Blink) communicates with a payment handler (e.g., a third-party payment app or service).
    5. The payment handler responds with the payment details.
    6. The browser translates this response into a `payments::mojom::blink::PaymentResponsePtr` and sends it to the Blink renderer.
    7. Blink creates the `PaymentResponse` object (the focus of this test) using that Mojo data.
    8. The website's JavaScript can then access the data in the `PaymentResponse` object (e.g., `paymentResponse.details`).
    9. The website can call `paymentResponse.complete()` or `paymentResponse.retry()`.

10. **Structure the Explanation:** Organize the findings into logical sections based on the request's prompts: Functionality, Relationship with Web Tech, Logical Deductions, User/Programming Errors, and User Operations. Use clear language and examples.

By following these steps, we can systematically analyze the C++ test file and provide a comprehensive explanation of its purpose and context within the broader web development landscape.
这个C++源代码文件 `payment_response_test.cc` 是 Chromium Blink 引擎中 **Payment Request API** 的一个测试文件。它的主要功能是 **测试 `PaymentResponse` 类的行为和功能是否符合预期**。

更具体地说，它测试了以下几个方面：

**1. 数据复制 (Data Copied Over):**

* **功能:** 验证从浏览器进程接收到的支付响应数据 (`payments::mojom::blink::PaymentResponsePtr`) 是否正确地复制到了 `PaymentResponse` 对象中。这包括支付方法名、详细信息（JSON 字符串）、送货选项、付款人信息等。
* **与 JavaScript 的关系:**  `PaymentResponse` 对象最终会暴露给 JavaScript 代码，允许网站获取支付处理的结果。测试确保 C++ 层正确地处理了数据，以便 JavaScript 可以访问到正确的信息。
* **举例说明:**
    * **假设输入 (来自浏览器进程的 Mojo 数据):**
        ```
        payments::mojom::blink::PaymentResponsePtr input;
        input->method_name = "basic-card";
        input->stringified_details = "{\"transactionId\": \"txn-123\"}";
        input->payer->name = "Alice";
        ```
    * **预期输出 (在 `PaymentResponse` 对象中):**
        ```
        output->methodName() == "basic-card"
        output->details(...)  // 返回的 JavaScript 对象中应该包含 "transactionId": "txn-123"
        output->payerName() == "Alice"
        ```

**2. 处理支付响应详细信息 (PaymentResponseDetails...):**

* **功能:** 测试 `PaymentResponse` 如何处理支付响应的详细信息，特别是将其 JSON 字符串转换为 JavaScript 对象。
* **与 JavaScript 的关系:**  `details()` 方法会将 C++ 中存储的 JSON 字符串转换为 JavaScript 可以操作的对象。测试确保转换过程正确，即使输入的 JSON 格式不完全符合预期（例如，不是一个完整的 JSON 对象）。
* **举例说明:**
    * **正常情况:** 如果 `input->stringified_details` 是 `{"transactionId": 123}`，则 `output->details(scope.GetScriptState())` 将返回一个 JavaScript 对象 `{transactionId: 123}`。
    * **异常情况:** 如果 `input->stringified_details` 是 `"transactionId"` (不是一个有效的 JSON 对象)，测试验证 `details()` 方法仍然返回一个空的 JavaScript 对象 `{}`，避免 JavaScript 代码出错。

**3. 处理 SPC 扩展 (PaymentResponseDetailsContainsSpcExtensionsPRF):**

* **功能:**  测试当支付响应包含来自 Strong Customer Authentication (SCA) 协议的扩展信息时，`PaymentResponse` 如何处理。 特别是测试了 "prf" (Pseudorandom Function) 扩展，该扩展用于安全支付凭据。
* **与 JavaScript 的关系:** 这些扩展信息最终会通过 `details()` 方法暴露给 JavaScript。测试确保 JavaScript 可以访问到这些二进制数据 (ArrayBuffer)。
* **举例说明:**
    * **假设输入 (包含 SPC 扩展的 Mojo 数据):**
        ```
        input->get_assertion_authenticator_response->extensions->echo_prf = true;
        input->get_assertion_authenticator_response->extensions->prf_results =
            mojom::blink::PRFValues::New(/*id=*/std::nullopt,
                                          /*first=*/{1, 2, 3},
                                          /*second=*/{4, 5, 6});
        ```
    * **预期输出 (在 JavaScript 的 `details` 对象中):**
        ```javascript
        paymentResponse.details.getClientExtensionResults().prf.results.first // ArrayBuffer 包含 [1, 2, 3]
        paymentResponse.details.getClientExtensionResults().prf.results.second // ArrayBuffer 包含 [4, 5, 6]
        ```

**4. 保证 `details()` 方法返回相同的对象 (PaymentResponseDetailsRetrunsTheSameObject):**

* **功能:** 确保多次调用 `details()` 方法返回的是同一个 JavaScript 对象实例，而不是每次都创建一个新的对象。这有助于提高性能并避免潜在的 JavaScript 代码错误。

**5. 测试 `complete()` 方法 (CompleteCalledWithSuccess/Failure):**

* **功能:** 测试 `PaymentResponse` 对象的 `complete()` 方法，该方法用于通知浏览器支付流程已成功或失败。
* **与 JavaScript 的关系:**  网站的 JavaScript 代码会调用 `paymentResponse.complete()` 来结束支付流程。
* **逻辑推理:**
    * **假设输入 (JavaScript 调用):** `paymentResponse.complete({ result: 'success' })`
    * **预期输出 (C++ 层):** `MockPaymentStateResolver::Complete` 方法会被调用，并传入 `PaymentStateResolver::kSuccess`。
    * **假设输入 (JavaScript 调用):** `paymentResponse.complete({ result: 'fail' })`
    * **预期输出 (C++ 层):** `MockPaymentStateResolver::Complete` 方法会被调用，并传入 `PaymentStateResolver::kFail`。

**6. 测试 `toJSONForBinding()` 方法 (JSONSerializerTest):**

* **功能:** 测试将 `PaymentResponse` 对象序列化为 JSON 字符串的功能，用于在 Blink 和其他进程之间传递数据。
* **与 JavaScript 的关系:**  虽然不是直接与 JavaScript 代码交互，但这个 JSON 字符串可能会被用于 DevTools 或其他需要序列化表示的场景。
* **举例说明:** 测试验证了各种属性（requestId, methodName, details, shippingAddress 等）都被正确地包含在了生成的 JSON 字符串中。

**与 HTML 和 CSS 的关系:**

虽然此测试文件本身不直接涉及 HTML 或 CSS 的功能，但 `PaymentResponse` 对象是 Payment Request API 的核心组成部分，而 Payment Request API 是 **由 JavaScript 代码在网页中调用的**。

* **HTML:**  用户与网页上的 HTML 元素（例如，“立即支付”按钮）交互，触发 JavaScript 代码调用 Payment Request API。
* **CSS:** CSS 用于美化网页上的元素，包括可能触发支付流程的按钮或其他 UI 组件。

**用户或编程常见的使用错误举例说明:**

* **用户错误:** 用户在支付过程中输入了错误的信用卡信息或地址信息。这会导致支付处理失败，最终通过 `paymentResponse.complete('fail')` 反馈给网站。
* **编程错误 (Web 开发人员):**
    *  **未处理 `details` 属性的异常情况:**  Web 开发人员可能假设 `paymentResponse.details` 始终是一个有效的 JSON 对象，但如果支付处理程序返回了格式错误的字符串，可能会导致 JavaScript 错误。此测试确保即使 `stringified_details` 不是有效的 JSON，Blink 也不会崩溃，并返回一个空对象。
    * **过早调用 `complete()`:**  在支付流程完成之前就调用 `paymentResponse.complete()` 可能会导致支付状态不一致。
* **编程错误 (Blink 开发人员):**
    * **数据复制错误:**  如果在 C++ 代码中复制 `payments::mojom::blink::PaymentResponsePtr` 的数据到 `PaymentResponse` 对象时出现错误，例如拼写错误或类型转换错误，测试 `DataCopiedOver` 可以捕获这些问题。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户访问包含支付功能的网页:** 用户在浏览器中打开一个支持 Payment Request API 的网站。
2. **用户触发支付流程:** 用户点击“购买”、“结账”或其他触发支付的按钮或操作。
3. **网页 JavaScript 调用 Payment Request API:** 网页的 JavaScript 代码使用 `new PaymentRequest(...)` 创建一个支付请求，并调用 `show()` 方法启动支付流程。
4. **浏览器显示支付界面:** 浏览器会根据用户的支付设置显示一个支付界面，让用户选择支付方式并输入相关信息。
5. **用户授权支付:** 用户选择支付方式并完成支付授权。
6. **浏览器与支付处理程序通信:** 浏览器（在 Blink 渲染进程之外）与支付处理程序（例如，银行、支付网关）进行通信。
7. **支付处理程序返回支付响应:** 支付处理程序返回支付结果和相关信息。
8. **浏览器将支付响应传递给 Blink:** 浏览器将支付处理程序的响应转换为 `payments::mojom::blink::PaymentResponsePtr` Mojo 对象，并发送到 Blink 渲染进程。
9. **Blink 创建 `PaymentResponse` 对象:** 在 Blink 渲染进程中，会创建一个 `PaymentResponse` 对象，并将 `payments::mojom::blink::PaymentResponsePtr` 中的数据复制到该对象中。 **`payment_response_test.cc` 就是用来测试这个创建和数据复制过程是否正确的。**
10. **网页 JavaScript 接收 `PaymentResponse` 对象:** 之前调用 `paymentRequest.show()` 返回的 Promise 会 resolve，并将创建的 `PaymentResponse` 对象传递给网页的 JavaScript 代码。
11. **网页 JavaScript 处理支付结果:** 网页的 JavaScript 代码可以访问 `PaymentResponse` 对象的属性（例如 `methodName`, `details`）来获取支付结果，并调用 `complete()` 或 `retry()` 方法来结束或重试支付流程.

当开发者需要调试 Payment Request API 相关的问题时，他们可能会关注以下几点，而 `payment_response_test.cc` 的测试用例可以作为验证这些点的工具：

* **浏览器是否正确地将支付处理程序的响应传递给了 Blink?**  可以查看 `payments::mojom::blink::PaymentResponsePtr` 中的数据。
* **Blink 是否正确地解析和存储了这些数据到 `PaymentResponse` 对象中?**  `DataCopiedOver` 测试可以验证这一点。
* **JavaScript 代码是否能够正确地访问 `PaymentResponse` 对象中的数据?**  可以检查 `details()` 方法返回的对象内容。
* **`complete()` 方法是否能够正确地通知浏览器支付结果?** `CompleteCalledWithSuccess/Failure` 测试可以验证这一点。

总而言之，`payment_response_test.cc` 是一个重要的单元测试文件，用于确保 Blink 引擎中 `PaymentResponse` 类的正确性和稳定性，从而保证 Payment Request API 的功能正常运作。

### 提示词
```
这是目录为blink/renderer/modules/payments/payment_response_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/payments/payment_response.h"

#include <memory>
#include <utility>

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_object_builder.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_complete.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_validation_errors.h"
#include "third_party/blink/renderer/modules/credentialmanagement/public_key_credential.h"
#include "third_party/blink/renderer/modules/payments/payment_address.h"
#include "third_party/blink/renderer/modules/payments/payment_state_resolver.h"
#include "third_party/blink/renderer/modules/payments/payment_test_helper.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {
namespace {

class MockPaymentStateResolver final
    : public GarbageCollected<MockPaymentStateResolver>,
      public PaymentStateResolver {
 public:
  MockPaymentStateResolver() {
    ON_CALL(*this, Complete(testing::_, testing::_, testing::_))
        .WillByDefault(testing::Return(dummy_promise_));
  }

  MockPaymentStateResolver(const MockPaymentStateResolver&) = delete;
  MockPaymentStateResolver& operator=(const MockPaymentStateResolver&) = delete;

  ~MockPaymentStateResolver() override = default;

  MOCK_METHOD3(Complete,
               ScriptPromise<IDLUndefined>(ScriptState*,
                                           PaymentComplete result,
                                           ExceptionState&));
  MOCK_METHOD3(
      Retry,
      ScriptPromise<IDLUndefined>(ScriptState*,
                                  const PaymentValidationErrors* errorFields,
                                  ExceptionState&));

  void Trace(Visitor* visitor) const override {
    visitor->Trace(dummy_promise_);
  }

 private:
  MemberScriptPromise<IDLUndefined> dummy_promise_;
};

TEST(PaymentResponseTest, DataCopiedOver) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  payments::mojom::blink::PaymentResponsePtr input =
      BuildPaymentResponseForTest();
  input->method_name = "foo";
  input->stringified_details = "{\"transactionId\": 123}";
  input->shipping_option = "standardShippingOption";
  input->payer->name = "Jon Doe";
  input->payer->email = "abc@gmail.com";
  input->payer->phone = "0123";
  MockPaymentStateResolver* complete_callback =
      MakeGarbageCollected<MockPaymentStateResolver>();

  PaymentResponse* output = MakeGarbageCollected<PaymentResponse>(
      scope.GetScriptState(), std::move(input), nullptr, complete_callback,
      "id");

  EXPECT_EQ("foo", output->methodName());
  EXPECT_EQ("standardShippingOption", output->shippingOption());
  EXPECT_EQ("Jon Doe", output->payerName());
  EXPECT_EQ("abc@gmail.com", output->payerEmail());
  EXPECT_EQ("0123", output->payerPhone());
  EXPECT_EQ("id", output->requestId());

  ScriptValue details = output->details(scope.GetScriptState());

  ASSERT_FALSE(scope.GetExceptionState().HadException());
  ASSERT_TRUE(details.V8Value()->IsObject());

  ScriptValue transaction_id(
      scope.GetIsolate(),
      details.V8Value()
          .As<v8::Object>()
          ->Get(scope.GetContext(),
                V8String(scope.GetIsolate(), "transactionId"))
          .ToLocalChecked());

  ASSERT_TRUE(transaction_id.V8Value()->IsNumber());
  EXPECT_EQ(123, transaction_id.V8Value().As<v8::Number>()->Value());
}

MATCHER_P(ArrayBufferEqualTo, other_buffer, "equal to") {
  if (arg->ByteLength() != std::size(other_buffer)) {
    return false;
  }

  uint8_t* data = (uint8_t*)arg->Data();
  return std::equal(data, data + arg->ByteLength(), std::begin(other_buffer));
}

// Calls getClientExtensionResults on the given public_key_credential.
static v8::Local<v8::Object> GetClientExtensionResults(
    V8TestingScope& scope,
    v8::Local<v8::Object> public_key_credential) {
  v8::Local<v8::Function> get_client_extension_results_method =
      public_key_credential.As<v8::Object>()
          ->Get(scope.GetContext(),
                V8String(scope.GetIsolate(), "getClientExtensionResults"))
          .ToLocalChecked()
          .As<v8::Function>();
  return get_client_extension_results_method
      ->Call(scope.GetContext(), public_key_credential,
             /*argc=*/0,
             /*argv=*/nullptr)
      .ToLocalChecked()
      .As<v8::Object>();
}

// Gets a v8 object property of array_buffer type.
static v8::Local<v8::ArrayBuffer> GetArrayBuffer(V8TestingScope& scope,
                                                 v8::Local<v8::Object>& object,
                                                 const char* property_key) {
  return object
      ->Get(scope.GetContext(), V8String(scope.GetIsolate(), property_key))
      .ToLocalChecked()
      .As<v8::ArrayBuffer>();
}

TEST(PaymentResponseTest, PaymentResponseDetailsContainsSpcExtensionsPRF) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  payments::mojom::blink::PaymentResponsePtr input =
      BuildPaymentResponseForTest();
  input->get_assertion_authenticator_response =
      blink::mojom::blink::GetAssertionAuthenticatorResponse::New();
  input->get_assertion_authenticator_response->info =
      blink::mojom::blink::CommonCredentialInfo::New();
  input->get_assertion_authenticator_response->info->id = "rpid";
  input->get_assertion_authenticator_response->extensions =
      blink::mojom::blink::AuthenticationExtensionsClientOutputs::New();
  input->get_assertion_authenticator_response->extensions->echo_prf = true;
  input->get_assertion_authenticator_response->extensions->prf_results =
      mojom::blink::PRFValues::New(
          /*id=*/std::nullopt,
          /*first=*/WTF::Vector<uint8_t>{1, 2, 3},
          /*second=*/WTF::Vector<uint8_t>{4, 5, 6});
  MockPaymentStateResolver* complete_callback =
      MakeGarbageCollected<MockPaymentStateResolver>();

  PaymentResponse* output = MakeGarbageCollected<PaymentResponse>(
      scope.GetScriptState(), std::move(input), /*shipping_address=*/nullptr,
      complete_callback, "request_id");

  v8::Local<v8::Object> details =
      output->details(scope.GetScriptState()).V8Value().As<v8::Object>();
  v8::Local<v8::Object> prf =
      GetClientExtensionResults(scope, details)
          ->Get(scope.GetContext(), V8String(scope.GetIsolate(), "prf"))
          .ToLocalChecked()
          .As<v8::Object>();
  v8::Local<v8::Object> results =
      prf->Get(scope.GetContext(), V8String(scope.GetIsolate(), "results"))
          .ToLocalChecked()
          .As<v8::Object>();
  EXPECT_THAT(GetArrayBuffer(scope, results, "first"),
              ArrayBufferEqualTo(WTF::Vector{1, 2, 3}));
  EXPECT_THAT(GetArrayBuffer(scope, results, "second"),
              ArrayBufferEqualTo(WTF::Vector{4, 5, 6}));
}

TEST(PaymentResponseTest,
     PaymentResponseDetailsWithUnexpectedJSONFormatString) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  payments::mojom::blink::PaymentResponsePtr input =
      BuildPaymentResponseForTest();
  input->stringified_details = "transactionId";
  MockPaymentStateResolver* complete_callback =
      MakeGarbageCollected<MockPaymentStateResolver>();
  PaymentResponse* output = MakeGarbageCollected<PaymentResponse>(
      scope.GetScriptState(), std::move(input), nullptr, complete_callback,
      "id");

  ScriptValue details = output->details(scope.GetScriptState());
  ASSERT_TRUE(details.V8Value()->IsObject());

  String stringified_details = ToBlinkString<String>(
      scope.GetIsolate(),
      v8::JSON::Stringify(scope.GetContext(),
                          details.V8Value().As<v8::Object>())
          .ToLocalChecked(),
      kDoNotExternalize);

  EXPECT_EQ("{}", stringified_details);
}

TEST(PaymentResponseTest, PaymentResponseDetailsRetrunsTheSameObject) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  payments::mojom::blink::PaymentResponsePtr input =
      BuildPaymentResponseForTest();
  input->method_name = "foo";
  input->stringified_details = "{\"transactionId\": 123}";
  MockPaymentStateResolver* complete_callback =
      MakeGarbageCollected<MockPaymentStateResolver>();
  PaymentResponse* output = MakeGarbageCollected<PaymentResponse>(
      scope.GetScriptState(), std::move(input), nullptr, complete_callback,
      "id");
  EXPECT_EQ(output->details(scope.GetScriptState()),
            output->details(scope.GetScriptState()));
}

TEST(PaymentResponseTest, CompleteCalledWithSuccess) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  payments::mojom::blink::PaymentResponsePtr input =
      BuildPaymentResponseForTest();
  input->method_name = "foo";
  input->stringified_details = "{\"transactionId\": 123}";
  MockPaymentStateResolver* complete_callback =
      MakeGarbageCollected<MockPaymentStateResolver>();
  PaymentResponse* output = MakeGarbageCollected<PaymentResponse>(
      scope.GetScriptState(), std::move(input), nullptr, complete_callback,
      "id");

  EXPECT_CALL(*complete_callback,
              Complete(scope.GetScriptState(), PaymentStateResolver::kSuccess,
                       testing::_));

  output->complete(scope.GetScriptState(),
                   V8PaymentComplete(V8PaymentComplete::Enum::kSuccess),
                   scope.GetExceptionState());
}

TEST(PaymentResponseTest, CompleteCalledWithFailure) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  payments::mojom::blink::PaymentResponsePtr input =
      BuildPaymentResponseForTest();
  input->method_name = "foo";
  input->stringified_details = "{\"transactionId\": 123}";
  MockPaymentStateResolver* complete_callback =
      MakeGarbageCollected<MockPaymentStateResolver>();
  PaymentResponse* output = MakeGarbageCollected<PaymentResponse>(
      scope.GetScriptState(), std::move(input), nullptr, complete_callback,
      "id");

  EXPECT_CALL(*complete_callback,
              Complete(scope.GetScriptState(), PaymentStateResolver::kFail,
                       testing::_));

  output->complete(scope.GetScriptState(),
                   V8PaymentComplete(V8PaymentComplete::Enum::kFail),
                   scope.GetExceptionState());
}

TEST(PaymentResponseTest, JSONSerializerTest) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  payments::mojom::blink::PaymentResponsePtr input =
      BuildPaymentResponseForTest();
  input->method_name = "foo";
  input->stringified_details = "{\"transactionId\": 123}";
  input->shipping_option = "standardShippingOption";
  input->payer->email = "abc@gmail.com";
  input->payer->phone = "0123";
  input->payer->name = "Jon Doe";
  input->shipping_address = payments::mojom::blink::PaymentAddress::New();
  input->shipping_address->country = "US";
  input->shipping_address->address_line.push_back("340 Main St");
  input->shipping_address->address_line.push_back("BIN1");
  input->shipping_address->address_line.push_back("First floor");
  PaymentAddress* address =
      MakeGarbageCollected<PaymentAddress>(std::move(input->shipping_address));

  PaymentResponse* output = MakeGarbageCollected<PaymentResponse>(
      scope.GetScriptState(), std::move(input), address,
      MakeGarbageCollected<MockPaymentStateResolver>(), "id");
  ScriptValue json_object = output->toJSONForBinding(scope.GetScriptState());
  EXPECT_TRUE(json_object.IsObject());

  String json_string = ToBlinkString<String>(
      scope.GetIsolate(),
      v8::JSON::Stringify(scope.GetContext(),
                          json_object.V8Value().As<v8::Object>())
          .ToLocalChecked(),
      kDoNotExternalize);
  String expected =
      "{\"requestId\":\"id\",\"methodName\":\"foo\",\"details\":{"
      "\"transactionId\":123},"
      "\"shippingAddress\":{\"country\":\"US\",\"addressLine\":[\"340 Main "
      "St\","
      "\"BIN1\",\"First "
      "floor\"],\"region\":\"\",\"city\":\"\",\"dependentLocality\":"
      "\"\",\"postalCode\":\"\",\"sortingCode\":\"\","
      "\"organization\":\"\",\"recipient\":\"\",\"phone\":\"\"},"
      "\"shippingOption\":"
      "\"standardShippingOption\",\"payerName\":\"Jon Doe\","
      "\"payerEmail\":\"abc@gmail.com\",\"payerPhone\":\"0123\"}";
  EXPECT_EQ(expected, json_string);
}

}  // namespace
}  // namespace blink
```