Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The user wants a breakdown of the functionality of the provided C++ test file (`payment_request_details_test.cc`). They are particularly interested in its relation to web technologies (JavaScript, HTML, CSS), any logical reasoning within the code, potential user/programmer errors, and debugging information. Finally, they want a summary of the file's function for this first part.

2. **Initial Scan and Identify Key Components:** I quickly scanned the code for recognizable keywords and patterns. I noticed:
    * Includes of various Blink headers (e.g., `v8_payment_details_init.h`, `payment_request.h`). This signals it's related to the Payment Request API.
    * The use of Google Test (`testing/gtest/include/gtest/gtest.h`). This confirms it's a unit test file.
    * The `DetailsTestCase` class and the `PaymentRequestDetailsTest` test fixture. These are structures for organizing test cases.
    * The `INSTANTIATE_TEST_SUITE_P` macro, which indicates parameterization of tests.
    * The various `DetailsTestCase` instantiations with different `kPaymentTestDetail...`, `kPaymentTestData...`, and `kPaymentTest...` constants. These suggest different scenarios being tested.
    * The `ValidatesDetails` test function, which likely creates a `PaymentRequest` and checks for exceptions.

3. **Formulate a High-Level Functionality Summary:** Based on the initial scan, I concluded that the file's primary function is to test the validation logic of `PaymentRequest` details. It checks if the `PaymentDetailsInit` object (which holds payment information) is correctly validated based on various input scenarios.

4. **Address Relationships with Web Technologies:**
    * **JavaScript:**  The Payment Request API is directly exposed to JavaScript. The test file is indirectly related because it validates the backend implementation of this API. I need to explain how JavaScript developers use the `PaymentRequest` constructor and the `details` parameter.
    * **HTML:**  The Payment Request API is triggered by user interaction on a webpage. I need to mention the HTML elements and JavaScript events that lead to calling the Payment Request API.
    * **CSS:** CSS doesn't directly interact with the core logic being tested, but it influences the user experience around payment requests. I should mention the visual aspects of payment forms and how CSS might be involved in styling them.

5. **Analyze Logical Reasoning and Provide Examples:** The core logic lies within the `ValidatesDetails` test and the way `DetailsTestCase` is structured.
    * **Hypothesis:** The tests hypothesize that certain combinations of input details (like invalid amounts, missing labels, etc.) will cause the `PaymentRequest` constructor to throw an exception.
    * **Input/Output:** I need to provide concrete examples of `DetailsTestCase` parameters (like trying to set an empty string for the total amount's value) and the expected outcome (a `TypeError` exception).

6. **Identify Potential User/Programmer Errors:** Based on the test cases, I can deduce common errors:
    * Providing incorrect or empty values for required fields (like the total amount).
    * Using invalid currency codes.
    * Misunderstanding the data types expected for different fields.
    * Incorrectly structuring the `PaymentDetailsInit` object in JavaScript.

7. **Trace User Operations to Reach the Code:** This involves thinking about the typical user flow:
    * User visits a website with a payment form.
    * User interacts with a button or link that initiates the payment process.
    * The website's JavaScript code constructs a `PaymentRequest` object, passing in payment details.
    * The browser's rendering engine (Blink in this case) processes this request, which involves the validation logic being tested in this file.

8. **Refine the Functionality Summary for Part 1:** Based on the deeper analysis, I can now provide a more accurate and detailed summary for the first part of the request. It's not just about "testing"; it's specifically about testing the *validation* of payment request details.

9. **Structure the Answer:**  I organize the information into clear sections with headings to make it easier for the user to understand. I use bullet points for lists of examples and explanations.

10. **Review and Refine:** I re-read my answer to ensure it's accurate, comprehensive, and easy to understand. I check for any jargon that needs clarification. I make sure the examples are clear and directly related to the code.

By following these steps, I can systematically analyze the code and provide a thorough and helpful response to the user's request. The key is to go beyond a superficial understanding and delve into the purpose and implications of the code within the broader context of the Payment Request API and web development.
```
功能列举:

1. **测试 `PaymentRequest` API 中 `PaymentDetailsInit` 对象的验证逻辑:**  该文件包含了一系列单元测试，用于验证在创建 `PaymentRequest` 对象时，传递的 `PaymentDetailsInit` 对象（包含支付相关的详细信息，如总价、商品信息等）是否按照规范进行了正确的格式和内容校验。

2. **覆盖不同支付细节字段的有效和无效场景:** 测试用例涵盖了 `PaymentDetailsInit` 中各个重要的字段，例如 `total` (总计), `displayItems` (商品条目), `shippingOptions` (运送选项), 以及 `modifiers` (支付方式修饰符) 中的 `total` 和 `displayItems`。

3. **验证不同类型的数据修改:** 测试不仅验证了字段值的覆盖，还包括了字段的移除操作。

4. **检查异常处理:**  测试用例显式地标记了哪些场景预期会抛出异常，并验证是否抛出了预期的异常类型 (`ESErrorType::kTypeError`)。

与 Javascript, HTML, CSS 的关系:

该文件是 Chromium 浏览器引擎 Blink 的一部分，Blink 负责渲染网页并将 HTML, CSS 和 JavaScript 代码转化为用户可见的页面。`PaymentRequest` API 是一个 Web API，由 JavaScript 暴露给网页开发者，用于发起支付请求。

* **JavaScript:**
    * **功能关系:**  `payment_request_details_test.cc` 中测试的正是 JavaScript 中 `PaymentRequest` 构造函数接收的 `details` 参数的有效性。当 JavaScript 代码调用 `new PaymentRequest(methodData, details, options)` 时，`details` 参数的结构和内容会经过 Blink 引擎的校验，这个测试文件就是为了确保这个校验过程的正确性。
    * **举例说明:** 在 JavaScript 中，开发者可能会这样创建一个 `PaymentRequest` 对象：
      ```javascript
      const methodData = [{
        supportedMethods: ['basic-card']
      }];
      const details = {
        total: {
          label: '总计',
          amount: { currency: 'USD', value: '10.00' }
        },
        displayItems: [{
          label: '商品 A',
          amount: { currency: 'USD', value: '5.00' }
        }, {
          label: '商品 B',
          amount: { currency: 'USD', value: '5.00' }
        }]
      };
      const options = {};
      const request = new PaymentRequest(methodData, details, options);
      ```
      `payment_request_details_test.cc` 中的测试用例就是模拟各种合法的和非法的 `details` 对象，来确保 Blink 引擎能够正确处理。

* **HTML:**
    * **功能关系:**  HTML 提供了用户界面元素，用户通过这些元素触发支付流程。例如，一个 "立即购买" 的按钮可能会绑定 JavaScript 代码来调用 `PaymentRequest` API。
    * **举例说明:**  一个简单的 HTML 按钮：
      ```html
      <button id="buyButton">立即购买</button>
      <script>
        document.getElementById('buyButton').addEventListener('click', function() {
          // ... 上面的 JavaScript 代码创建 PaymentRequest ...
          request.show();
        });
      </script>
      ```
      当用户点击这个按钮时，JavaScript 代码会执行，进而触发 Blink 引擎中与 `PaymentRequest` 相关的逻辑，包括此处测试的 `details` 参数的验证。

* **CSS:**
    * **功能关系:** CSS 负责控制网页的样式和布局，虽然不直接参与 `PaymentRequest` 核心逻辑的验证，但会影响用户与支付界面的交互体验。
    * **举例说明:** CSS 可以用来美化支付请求弹出的界面，或者控制网页上触发支付按钮的样式。

逻辑推理 (假设输入与输出):

该文件中的逻辑推理主要体现在 `DetailsTestCase` 的定义和使用上。每个 `DetailsTestCase` 包含了特定的输入（要修改的细节字段、修改的数据、修改类型、以及要使用的值）以及预期的输出（是否抛出异常，以及异常类型）。

**假设输入与输出示例:**

* **假设输入:**  `DetailsTestCase(kPaymentTestDetailTotal, kPaymentTestDataValue, kPaymentTestOverwriteValue, "", true, ESErrorType::kTypeError)`
    * **推理:**  这个测试用例尝试将 `total` 字段的 `value` 设置为空字符串。根据 Payment Request API 的规范，总价的 value 不能为空，应该是一个表示金额的字符串。
    * **预期输出:**  由于 value 为空字符串不符合规范，因此预期会抛出一个 `TypeError` 异常。

* **假设输入:** `DetailsTestCase(kPaymentTestDetailItem, kPaymentTestDataLabel, kPaymentTestOverwriteValue, "新的商品名称", false)`
    * **推理:** 这个测试用例尝试将一个商品条目的 `label` 更新为 "新的商品名称"。商品条目的 label 是一个字符串，可以被修改。
    * **预期输出:** 不会抛出异常，因为这是一个合法的操作。

用户或编程常见的使用错误:

* **提供空字符串或格式错误的金额值:**  正如测试用例所示，将 `total.amount.value` 或 `displayItems[i].amount.value` 设置为空字符串或非数字字符串（除非规范允许，但通常金额需要特定格式）会导致错误。
    * **示例:**  在 JavaScript 中设置 `details.total.amount.value = "";` 或 `details.total.amount.value = "abc";` 会导致验证失败。
* **缺少必要的字段:**  某些字段可能是强制性的，例如 `total` 字段。如果 `PaymentDetailsInit` 对象缺少这些字段，会导致错误。
    * **示例:**  在 JavaScript 中创建一个 `details` 对象时，没有包含 `total` 属性，会导致验证失败。
* **使用无效的货币代码:**  `amount.currency` 字段需要使用符合 ISO 4217 标准的货币代码。使用错误的货币代码会导致验证失败。
    * **示例:**  在 JavaScript 中设置 `details.total.amount.currency = "XXX";`，如果 "XXX" 不是一个有效的货币代码，就会出错。
* **在不应该修改的地方进行修改:**  开发者可能尝试修改只读的属性，或者以不符合规范的方式修改数据结构。

用户操作如何一步步到达这里 (调试线索):

1. **用户在网页上与支付相关的元素交互:**  用户点击 "购买", "结账" 等按钮或链接。
2. **JavaScript 代码被触发:** 网页上的 JavaScript 代码响应用户的操作，开始构建支付请求。
3. **`PaymentRequest` 对象被创建:** JavaScript 代码使用 `new PaymentRequest(methodData, details, options)` 创建一个支付请求对象，其中 `details` 参数包含了支付的详细信息。
4. **Blink 引擎接收到 `PaymentRequest` 创建的请求:** 浏览器引擎（Blink）接收到 JavaScript 的请求，开始处理。
5. **`PaymentDetailsInit` 对象的验证:** Blink 引擎会根据 Payment Request API 的规范，对传入的 `details` 对象进行验证，检查其结构和内容是否合法。
6. **`payment_request_details_test.cc` 中测试的逻辑被执行:**  在开发和测试阶段，以及在用户使用过程中，当 Blink 引擎进行 `PaymentDetailsInit` 对象的验证时，`payment_request_details_test.cc` 中编写的测试用例所覆盖的逻辑就会被执行到。如果用户提供的支付信息不符合规范，验证过程会抛出异常，这可能导致支付流程中断或显示错误信息。

作为调试线索，当开发者遇到 `PaymentRequest` 相关的错误，例如创建 `PaymentRequest` 对象时抛出异常，或者支付流程失败，可以检查以下几点，这些都与 `payment_request_details_test.cc` 测试的场景相关：

* **`details` 对象的结构是否符合规范:**  是否包含必要的字段，字段的类型是否正确。
* **`amount.value` 的格式是否正确:** 是否为表示金额的有效字符串。
* **`amount.currency` 是否为有效的 ISO 4217 货币代码。**
* **是否存在空字符串或无效字符的字段值。**

**归纳一下它的功能 (第1部分):**

`blink/renderer/modules/payments/payment_request_details_test.cc` 文件的主要功能是**测试 Chromium Blink 引擎中 Payment Request API 的 `PaymentDetailsInit` 对象（支付详情）的验证逻辑**。 它通过创建各种包含合法和非法支付详情的 `PaymentDetailsInit` 对象，并使用 Google Test 框架进行断言，来确保 Blink 引擎能够按照 Payment Request API 的规范正确地校验支付信息，并在遇到非法数据时抛出预期的异常。 这个测试文件覆盖了支付总额、商品信息、运送选项以及支付方式修饰符等关键字段的不同有效和无效场景，旨在保证支付请求的稳定性和安全性。
```

### 提示词
```
这是目录为blink/renderer/modules/payments/payment_request_details_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <ostream>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_details_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_options.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/modules/payments/payment_request.h"
#include "third_party/blink/renderer/modules/payments/payment_test_helper.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"

namespace blink {
namespace {

class DetailsTestCase {
 public:
  DetailsTestCase(
      PaymentTestDetailToChange detail,
      PaymentTestDataToChange data,
      PaymentTestModificationType mod_type,
      const char* value_to_use,
      bool expect_exception = false,
      ESErrorType expected_exception_code = static_cast<ESErrorType>(0))
      : detail_(detail),
        data_(data),
        mod_type_(mod_type),
        value_to_use_(value_to_use),
        expect_exception_(expect_exception),
        expected_exception_code_(expected_exception_code) {}

  ~DetailsTestCase() = default;

  PaymentDetailsInit* BuildDetails() const {
    return BuildPaymentDetailsInitForTest(detail_, data_, mod_type_,
                                          value_to_use_);
  }

  bool ExpectException() const { return expect_exception_; }

  ESErrorType GetExpectedExceptionCode() const {
    return expected_exception_code_;
  }

 private:
  friend std::ostream& operator<<(std::ostream&, DetailsTestCase);
  PaymentTestDetailToChange detail_;
  PaymentTestDataToChange data_;
  PaymentTestModificationType mod_type_;
  const char* value_to_use_;
  bool expect_exception_;
  ESErrorType expected_exception_code_;
};

std::ostream& operator<<(std::ostream& out, DetailsTestCase test_case) {
  if (test_case.expect_exception_)
    out << "Expecting an exception when ";
  else
    out << "Not expecting an exception when ";

  switch (test_case.detail_) {
    case kPaymentTestDetailTotal:
      out << "total ";
      break;
    case kPaymentTestDetailItem:
      out << "displayItem ";
      break;
    case kPaymentTestDetailShippingOption:
      out << "shippingOption ";
      break;
    case kPaymentTestDetailModifierTotal:
      out << "modifiers.total ";
      break;
    case kPaymentTestDetailModifierItem:
      out << "modifiers.displayItem ";
      break;
    case kPaymentTestDetailError:
      out << "error ";
      break;
    case kPaymentTestDetailNone:
      NOTREACHED();
  }

  switch (test_case.data_) {
    case kPaymentTestDataId:
      out << "id ";
      break;
    case kPaymentTestDataLabel:
      out << "label ";
      break;
    case kPaymentTestDataAmount:
      out << "amount ";
      break;
    case kPaymentTestDataCurrencyCode:
      out << "currency ";
      break;
    case kPaymentTestDataValue:
      out << "value ";
      break;
    case kPaymentTestDataNone:
      NOTREACHED();
  }

  switch (test_case.mod_type_) {
    case kPaymentTestOverwriteValue:
      out << "is overwritten by \"" << test_case.value_to_use_ << "\"";
      break;
    case kPaymentTestRemoveKey:
      out << "is removed";
      break;
  }

  return out;
}

class PaymentRequestDetailsTest
    : public testing::TestWithParam<DetailsTestCase> {
 protected:
  test::TaskEnvironment task_environment_;
};

TEST_P(PaymentRequestDetailsTest, ValidatesDetails) {
  PaymentRequestV8TestingScope scope;
  PaymentOptions* options = PaymentOptions::Create();
  options->setRequestShipping(true);
  PaymentRequest::Create(
      scope.GetExecutionContext(), BuildPaymentMethodDataForTest(),
      GetParam().BuildDetails(), options, scope.GetExceptionState());

  EXPECT_EQ(GetParam().ExpectException(),
            scope.GetExceptionState().HadException());
  if (GetParam().ExpectException()) {
    EXPECT_EQ(GetParam().GetExpectedExceptionCode(),
              scope.GetExceptionState().CodeAs<ESErrorType>());
  }
}

INSTANTIATE_TEST_SUITE_P(
    EmptyData,
    PaymentRequestDetailsTest,
    testing::Values(DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataLabel,
                                    kPaymentTestOverwriteValue,
                                    "",
                                    false),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataLabel,
                                    kPaymentTestOverwriteValue,
                                    "",
                                    false),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataId,
                                    kPaymentTestOverwriteValue,
                                    "",
                                    false),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataLabel,
                                    kPaymentTestOverwriteValue,
                                    "",
                                    false),
                    DetailsTestCase(kPaymentTestDetailModifierTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailModifierTotal,
                                    kPaymentTestDataLabel,
                                    kPaymentTestOverwriteValue,
                                    "",
                                    false),
                    DetailsTestCase(kPaymentTestDetailModifierItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailModifierItem,
                                    kPaymentTestDataLabel,
                                    kPaymentTestOverwriteValue,
                                    "",
                                    false)));

INSTANTIATE_TEST_SUITE_P(
    ValidCurrencyCodeFormat,
    PaymentRequestDetailsTest,
    testing::Values(DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataCurrencyCode,
                                    kPaymentTestOverwriteValue,
                                    "USD"),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataCurrencyCode,
                                    kPaymentTestOverwriteValue,
                                    "USD"),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataCurrencyCode,
                                    kPaymentTestOverwriteValue,
                                    "USD"),
                    DetailsTestCase(kPaymentTestDetailModifierTotal,
                                    kPaymentTestDataCurrencyCode,
                                    kPaymentTestOverwriteValue,
                                    "USD"),
                    DetailsTestCase(kPaymentTestDetailModifierItem,
                                    kPaymentTestDataCurrencyCode,
                                    kPaymentTestOverwriteValue,
                                    "USD")));

INSTANTIATE_TEST_SUITE_P(
    ValidValueFormat,
    PaymentRequestDetailsTest,
    testing::Values(DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "0"),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "1"),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "10"),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "10.99"),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "01234567890123456789.0123456789"),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "01234567890123456789012345678.9"),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "012345678901234567890123456789"),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "0"),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-0"),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "1"),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "10"),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-3"),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "10.99"),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-3.00"),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "01234567890123456789.0123456789"),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "01234567890123456789012345678.9"),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "012345678901234567890123456789"),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-01234567890123456789.0123456789"),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-01234567890123456789012345678.9"),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-012345678901234567890123456789"),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "0"),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-0"),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "1"),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "10"),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-3"),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "10.99"),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-3.00"),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "01234567890123456789.0123456789"),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "01234567890123456789012345678.9"),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "012345678901234567890123456789"),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-01234567890123456789.0123456789"),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-01234567890123456789012345678.9"),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-012345678901234567890123456789")));

INSTANTIATE_TEST_SUITE_P(
    ValidValueFormatForModifier,
    PaymentRequestDetailsTest,
    testing::Values(DetailsTestCase(kPaymentTestDetailModifierTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "0"),
                    DetailsTestCase(kPaymentTestDetailModifierTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "1"),
                    DetailsTestCase(kPaymentTestDetailModifierTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "10"),
                    DetailsTestCase(kPaymentTestDetailModifierTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "10.99"),
                    DetailsTestCase(kPaymentTestDetailModifierTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "01234567890123456789.0123456789"),
                    DetailsTestCase(kPaymentTestDetailModifierTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "01234567890123456789012345678.9"),
                    DetailsTestCase(kPaymentTestDetailModifierTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "012345678901234567890123456789"),
                    DetailsTestCase(kPaymentTestDetailModifierItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "0"),
                    DetailsTestCase(kPaymentTestDetailModifierItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-0"),
                    DetailsTestCase(kPaymentTestDetailModifierItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "1"),
                    DetailsTestCase(kPaymentTestDetailModifierItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "10"),
                    DetailsTestCase(kPaymentTestDetailModifierItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-3"),
                    DetailsTestCase(kPaymentTestDetailModifierItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "10.99"),
                    DetailsTestCase(kPaymentTestDetailModifierItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-3.00"),
                    DetailsTestCase(kPaymentTestDetailModifierItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "01234567890123456789.0123456789"),
                    DetailsTestCase(kPaymentTestDetailModifierItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "01234567890123456789012345678.9"),
                    DetailsTestCase(kPaymentTestDetailModifierItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "012345678901234567890123456789"),
                    DetailsTestCase(kPaymentTestDetailModifierItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-01234567890123456789.0123456789"),
                    DetailsTestCase(kPaymentTestDetailModifierItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-01234567890123456789012345678.9"),
                    DetailsTestCase(kPaymentTestDetailModifierItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-012345678901234567890123456789")));

INSTANTIATE_TEST_SUITE_P(
    InvalidValueFormat,
    PaymentRequestDetailsTest,
    testing::Values(DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-0",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-3",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-3.00",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "notdigits",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "ALSONOTDIGITS",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "10.",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    ".99",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-10.",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "10-",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "1-0",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "1.0.0",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "1/3",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-01234567890123456789.0123456789",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-01234567890123456789012345678.9",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailTotal,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-012345678901234567890123456789",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "notdigits",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "ALSONOTDIGITS",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "10.",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    ".99",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-10.",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "10-",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "1-0",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "1.0.0",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailItem,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "1/3",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "-",
                                    true,
                                    ESErrorType::kTypeError),
                    DetailsTestCase(kPaymentTestDetailShippingOption,
                                    kPaymentTestDataValue,
                                    kPaymentTestOverwriteValue,
                                    "notdigits",
                                    tr
```