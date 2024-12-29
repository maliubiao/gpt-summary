Response:
The user wants to understand the functionality of the `payment_request.cc` file in the Chromium Blink engine. They are particularly interested in its relationship with web technologies like JavaScript, HTML, and CSS, as well as potential user errors and debugging steps.

**Plan:**

1. **Identify Core Functionality:**  Analyze the included headers and the general structure of the code to determine the primary purpose of this file. It likely deals with handling the `PaymentRequest` API.
2. **Explain Interactions with Web Technologies:** Look for code sections that involve data conversion or validation related to payment information. These are likely points of interaction with JavaScript objects defined by the Payment Request API.
3. **Illustrate with Examples:** Provide concrete examples of how JavaScript code using the Payment Request API interacts with the C++ code in this file.
4. **Identify Logical Reasoning and Assumptions:** Pinpoint areas where the code makes decisions based on input data. Provide hypothetical input and output scenarios.
5. **Highlight Common User/Programming Errors:** Examine validation logic and potential error conditions that could arise from incorrect usage of the Payment Request API.
6. **Describe User Interaction Flow:** Outline the steps a user would take on a webpage that would lead to the execution of this code.
7. **Summarize Functionality:**  Provide a concise overview of the file's purpose based on the above analysis.
```
功能归纳：
```

这个 `payment_request.cc` 文件是 Chromium Blink 引擎中实现 Web Payments API 的核心组件之一。它主要负责处理 `PaymentRequest` 接口的逻辑，包括：

1. **接收和验证来自 JavaScript 的支付请求参数:**  它接收由 JavaScript 代码创建的 `PaymentRequest` 对象中包含的支付方法数据 (payment method data)、支付详情 (payment details) 和支付选项 (payment options)。它会对这些数据进行各种格式和内容的验证，以确保其符合规范。

2. **与浏览器进程通信:**  它通过 Mojo 接口与浏览器进程中的支付处理模块进行通信，发起支付流程。这涉及到将 JavaScript 中的数据转换为 Mojo 消息，并发送给浏览器进程。

3. **处理来自浏览器进程的支付响应和更新:**  它接收来自浏览器进程的支付响应信息，例如支付凭证 (payment credentials) 和任何需要更新的支付详情。它会将这些信息传递回 JavaScript 代码，以便网站可以完成支付流程。

4. **管理支付流程中的事件:**  它处理 `shippingaddresschange` 和 `shippingoptionchange` 等事件，这些事件允许网站根据用户的选择动态更新支付详情。

5. **实现 `canMakePayment()` 和 `hasEnrolledInstrument()` 方法:**  它实现了 `PaymentRequest` 接口的这两个方法，用于检查用户是否可以进行支付以及是否已注册支付工具。

6. **处理安全相关的逻辑:**  它涉及到一些安全相关的检查，例如内容安全策略 (CSP) 的检查，以确保支付方法的来源是可信的。

7. **支持多种支付方式:**  代码中可以看到对 Google Pay, Android Pay 和 Secure Payment Confirmation 等支付方式的支持，并对这些特定支付方式的数据进行处理。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个 C++ 文件直接响应并驱动着 JavaScript 中 `PaymentRequest` API 的行为。

**JavaScript 交互举例：**

```javascript
// 在 JavaScript 中创建一个 PaymentRequest 对象
const paymentMethods = [
  {
    supportedMethods: 'basic-card',
    data: {
      supportedNetworks: ['visa', 'mastercard'],
      supportedTypes: ['debit', 'credit'],
Prompt: 
```
这是目录为blink/renderer/modules/payments/payment_request.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/payments/payment_request.h"

#include <stddef.h>

#include <utility>

#include "base/functional/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_string_resource.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_address_errors.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_android_pay_method_data.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_google_play_billing_method_data.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payer_errors.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_details_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_details_modifier.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_details_update.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_item.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_shipping_option.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_validation_errors.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/event_queue.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/frame_owner.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/modules/event_target_modules_names.h"
#include "third_party/blink/renderer/modules/payments/payment_address.h"
#include "third_party/blink/renderer/modules/payments/payment_method_change_event.h"
#include "third_party/blink/renderer/modules/payments/payment_request_update_event.h"
#include "third_party/blink/renderer/modules/payments/payment_response.h"
#include "third_party/blink/renderer/modules/payments/payments_validators.h"
#include "third_party/blink/renderer/modules/payments/secure_payment_confirmation_helper.h"
#include "third_party/blink/renderer/modules/payments/update_payment_details_function.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/reporting_disposition.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/uuid.h"

namespace {

using ::payments::mojom::blink::AddressErrors;
using ::payments::mojom::blink::AddressErrorsPtr;
using ::payments::mojom::blink::CanMakePaymentQueryResult;
using ::payments::mojom::blink::HasEnrolledInstrumentQueryResult;
using ::payments::mojom::blink::PayerErrors;
using ::payments::mojom::blink::PayerErrorsPtr;
using ::payments::mojom::blink::PaymentAddress;
using ::payments::mojom::blink::PaymentAddressPtr;
using ::payments::mojom::blink::PaymentCurrencyAmount;
using ::payments::mojom::blink::PaymentCurrencyAmountPtr;
using ::payments::mojom::blink::PaymentDetailsModifierPtr;
using ::payments::mojom::blink::PaymentDetailsPtr;
using ::payments::mojom::blink::PaymentErrorReason;
using ::payments::mojom::blink::PaymentItemPtr;
using ::payments::mojom::blink::PaymentMethodDataPtr;
using ::payments::mojom::blink::PaymentOptionsPtr;
using ::payments::mojom::blink::PaymentResponsePtr;
using ::payments::mojom::blink::PaymentShippingOptionPtr;
using ::payments::mojom::blink::PaymentShippingType;
using ::payments::mojom::blink::PaymentValidationErrors;
using ::payments::mojom::blink::PaymentValidationErrorsPtr;

const char kHasEnrolledInstrumentDebugName[] = "hasEnrolledInstrument";
const char kGooglePayMethod[] = "https://google.com/pay";
const char kGooglePayAuthenticationMethod[] =
    "https://pay.google.com/authentication";
const char kAndroidPayMethod[] = "https://android.com/pay";
const char kGooglePlayBillingMethod[] = "https://play.google.com/billing";
const char kUnknownCurrency[] = "ZZZ";
const char kAppStoreBillingLabelPlaceHolder[] = "AppStoreBillingPlaceHolder";
const char kSecurePaymentConfirmationMethod[] = "secure-payment-confirmation";

}  // namespace

namespace mojo {

template <>
struct TypeConverter<PaymentCurrencyAmountPtr, blink::PaymentCurrencyAmount> {
  static PaymentCurrencyAmountPtr Convert(
      const blink::PaymentCurrencyAmount& input) {
    PaymentCurrencyAmountPtr output = PaymentCurrencyAmount::New();
    output->currency = input.currency().UpperASCII();
    output->value = input.value();
    return output;
  }
};

template <>
struct TypeConverter<PaymentItemPtr, blink::PaymentItem> {
  static PaymentItemPtr Convert(const blink::PaymentItem& input) {
    PaymentItemPtr output = payments::mojom::blink::PaymentItem::New();
    output->label = input.label();
    output->amount = PaymentCurrencyAmount::From(*input.amount());
    output->pending = input.pending();
    return output;
  }
};

template <>
struct TypeConverter<PaymentShippingOptionPtr, blink::PaymentShippingOption> {
  static PaymentShippingOptionPtr Convert(
      const blink::PaymentShippingOption& input) {
    PaymentShippingOptionPtr output =
        payments::mojom::blink::PaymentShippingOption::New();
    output->id = input.id();
    output->label = input.label();
    output->amount = PaymentCurrencyAmount::From(*input.amount());
    output->selected = input.hasSelected() && input.selected();
    return output;
  }
};

template <>
struct TypeConverter<PaymentOptionsPtr, blink::PaymentOptions> {
  static PaymentOptionsPtr Convert(const blink::PaymentOptions& input) {
    PaymentOptionsPtr output = payments::mojom::blink::PaymentOptions::New();
    output->request_payer_name = input.requestPayerName();
    output->request_payer_email = input.requestPayerEmail();
    output->request_payer_phone = input.requestPayerPhone();
    output->request_shipping = input.requestShipping();

    if (input.shippingType() == "delivery") {
      output->shipping_type = PaymentShippingType::DELIVERY;
    } else if (input.shippingType() == "pickup") {
      output->shipping_type = PaymentShippingType::PICKUP;
    } else {
      output->shipping_type = PaymentShippingType::SHIPPING;
    }

    return output;
  }
};

template <>
struct TypeConverter<PaymentValidationErrorsPtr,
                     blink::PaymentValidationErrors> {
  static PaymentValidationErrorsPtr Convert(
      const blink::PaymentValidationErrors& input) {
    PaymentValidationErrorsPtr output =
        payments::mojom::blink::PaymentValidationErrors::New();
    output->error = input.hasError() ? input.error() : g_empty_string;
    auto* payer_errors =
        input.hasPayer() ? input.payer() : blink::PayerErrors::Create();
    output->payer = PayerErrors::From(*payer_errors);
    auto* address_errors = input.hasShippingAddress()
                               ? input.shippingAddress()
                               : blink::AddressErrors::Create();
    output->shipping_address = AddressErrors::From(*address_errors);
    return output;
  }
};

template <>
struct TypeConverter<PayerErrorsPtr, blink::PayerErrors> {
  static PayerErrorsPtr Convert(const blink::PayerErrors& input) {
    PayerErrorsPtr output = payments::mojom::blink::PayerErrors::New();
    output->email = input.hasEmail() ? input.email() : g_empty_string;
    output->name = input.hasName() ? input.name() : g_empty_string;
    output->phone = input.hasPhone() ? input.phone() : g_empty_string;
    return output;
  }
};

template <>
struct TypeConverter<AddressErrorsPtr, blink::AddressErrors> {
  static AddressErrorsPtr Convert(const blink::AddressErrors& input) {
    AddressErrorsPtr output = payments::mojom::blink::AddressErrors::New();
    output->address_line =
        input.hasAddressLine() ? input.addressLine() : g_empty_string;
    output->city = input.hasCity() ? input.city() : g_empty_string;
    output->country = input.hasCountry() ? input.country() : g_empty_string;
    output->dependent_locality = input.hasDependentLocality()
                                     ? input.dependentLocality()
                                     : g_empty_string;
    output->organization =
        input.hasOrganization() ? input.organization() : g_empty_string;
    output->phone = input.hasPhone() ? input.phone() : g_empty_string;
    output->postal_code =
        input.hasPostalCode() ? input.postalCode() : g_empty_string;
    output->recipient =
        input.hasRecipient() ? input.recipient() : g_empty_string;
    output->region = input.hasRegion() ? input.region() : g_empty_string;
    output->sorting_code =
        input.hasSortingCode() ? input.sortingCode() : g_empty_string;
    return output;
  }
};

}  // namespace mojo

namespace blink {
namespace {

// Validates ShippingOption or PaymentItem, which happen to have identical
// fields, except for "id", which is present only in ShippingOption.
template <typename T>
void ValidateShippingOptionOrPaymentItem(const T* item,
                                         const String& item_name,
                                         ExecutionContext& execution_context,
                                         ExceptionState& exception_state) {
  DCHECK(item->hasLabel());
  DCHECK(item->hasAmount());
  DCHECK(item->amount()->hasValue());
  DCHECK(item->amount()->hasCurrency());

  if (item->label().length() > PaymentRequest::kMaxStringLength) {
    exception_state.ThrowTypeError("The label for " + item_name +
                                   " cannot be longer than 1024 characters");
    return;
  }

  if (item->amount()->currency().length() > PaymentRequest::kMaxStringLength) {
    exception_state.ThrowTypeError("The currency code for " + item_name +
                                   " cannot be longer than 1024 characters");
    return;
  }

  if (item->amount()->value().length() > PaymentRequest::kMaxStringLength) {
    exception_state.ThrowTypeError("The amount value for " + item_name +
                                   " cannot be longer than 1024 characters");
    return;
  }

  String error_message;
  if (!PaymentsValidators::IsValidCurrencyCodeFormat(
          execution_context.GetIsolate(), item->amount()->currency(),
          &error_message)) {
    exception_state.ThrowRangeError(error_message);
    return;
  }

  if (!PaymentsValidators::IsValidAmountFormat(execution_context.GetIsolate(),
                                               item->amount()->value(),
                                               item_name, &error_message)) {
    exception_state.ThrowTypeError(error_message);
    return;
  }

  if (item->label().empty()) {
    execution_context.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kError,
        "Empty " + item_name + " label may be confusing the user"));
    return;
  }
}

bool IsAppStoreBillingMethod(const StringView& billing_method) {
  return billing_method == kGooglePlayBillingMethod;
}

bool RequestingOnlyAppStoreBillingMethods(
    const Vector<payments::mojom::blink::PaymentMethodDataPtr>& method_data) {
  DCHECK(!method_data.empty());
  for (const auto& method : method_data) {
    if (!IsAppStoreBillingMethod(method->supported_method)) {
      return false;
    }
  }
  return true;
}

void ValidateAndConvertDisplayItems(
    const HeapVector<Member<PaymentItem>>& input,
    const String& item_names,
    Vector<PaymentItemPtr>& output,
    ExecutionContext& execution_context,
    ExceptionState& exception_state) {
  if (input.size() > PaymentRequest::kMaxListSize) {
    exception_state.ThrowTypeError("At most 1024 " + item_names + " allowed");
    return;
  }

  for (PaymentItem* item : input) {
    ValidateShippingOptionOrPaymentItem(item, item_names, execution_context,
                                        exception_state);
    if (exception_state.HadException()) {
      return;
    }
    output.push_back(payments::mojom::blink::PaymentItem::From(*item));
  }
}

// Validates and converts |input| shipping options into |output|. Throws an
// exception if the data is not valid, except for duplicate identifiers, which
// returns an empty |output| instead of throwing an exception. There's no need
// to clear |output| when an exception is thrown, because the caller takes care
// of deleting |output|.
void ValidateAndConvertShippingOptions(
    const HeapVector<Member<PaymentShippingOption>>& input,
    Vector<PaymentShippingOptionPtr>& output,
    String& shipping_option_output,
    ExecutionContext& execution_context,
    ExceptionState& exception_state) {
  if (input.size() > PaymentRequest::kMaxListSize) {
    exception_state.ThrowTypeError("At most 1024 shipping options allowed");
    return;
  }

  HashSet<String> unique_ids;
  for (PaymentShippingOption* option : input) {
    ValidateShippingOptionOrPaymentItem(option, "shippingOptions",
                                        execution_context, exception_state);
    if (exception_state.HadException()) {
      return;
    }

    DCHECK(option->hasId());
    if (option->id().length() > PaymentRequest::kMaxStringLength) {
      exception_state.ThrowTypeError(
          "Shipping option ID cannot be longer than 1024 characters");
      return;
    }

    if (option->id().empty()) {
      execution_context.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::ConsoleMessageSource::kJavaScript,
          mojom::ConsoleMessageLevel::kWarning,
          "Empty shipping option ID may be hard to debug"));
      return;
    }

    if (unique_ids.Contains(option->id())) {
      exception_state.ThrowTypeError(
          "Cannot have duplicate shipping option identifiers");
      return;
    }

    if (option->selected()) {
      shipping_option_output = option->id();
    }

    unique_ids.insert(option->id());

    output.push_back(
        payments::mojom::blink::PaymentShippingOption::From(*option));
  }
}

void ValidateAndConvertTotal(const PaymentItem* input,
                             const String& item_name,
                             PaymentItemPtr& output,
                             ExecutionContext& execution_context,
                             ExceptionState& exception_state) {
  ValidateShippingOptionOrPaymentItem(input, item_name, execution_context,
                                      exception_state);
  if (exception_state.HadException()) {
    return;
  }

  if (input->amount()->value()[0] == '-') {
    exception_state.ThrowTypeError("Total amount value should be non-negative");
    return;
  }

  output = payments::mojom::blink::PaymentItem::From(*input);
}

// Parses Android Pay data to avoid parsing JSON in the browser.
void SetAndroidPayMethodData(v8::Isolate* isolate,
                             const ScriptValue& input,
                             PaymentMethodDataPtr& output,
                             ExceptionState& exception_state) {
  AndroidPayMethodData* android_pay =
      NativeValueTraits<AndroidPayMethodData>::NativeValue(
          isolate, input.V8Value(), exception_state);
  if (exception_state.HadException()) {
    return;
  }

  if (android_pay->hasEnvironment() && android_pay->environment() == "TEST") {
    output->environment = payments::mojom::blink::AndroidPayEnvironment::TEST;
  }

  // 0 means the merchant did not specify or it was an invalid value
  output->min_google_play_services_version = 0;
  if (android_pay->hasMinGooglePlayServicesVersion()) {
    bool ok = false;
    int min_google_play_services_version =
        android_pay->minGooglePlayServicesVersion().ToIntStrict(&ok);
    if (ok) {
      output->min_google_play_services_version =
          min_google_play_services_version;
    }
  }

  // 0 means the merchant did not specify or it was an invalid value
  output->api_version = 0;
  if (android_pay->hasApiVersion()) {
    output->api_version = android_pay->apiVersion();
  }
}

void MeasureGooglePlayBillingPriceChangeConfirmation(
    ExecutionContext& execution_context,
    const ScriptValue& input) {
  v8::Isolate* isolate = execution_context.GetIsolate();
  v8::TryCatch try_catch(isolate);
  GooglePlayBillingMethodData* google_play_billing =
      NativeValueTraits<GooglePlayBillingMethodData>::NativeValue(
          isolate, input.V8Value(), PassThroughException(isolate));
  if (try_catch.HasCaught()) {
    // No need to report this exception, because this function is
    // only for measuring usage of a deprecated field.
    return;
  }

  if (google_play_billing->hasPriceChangeConfirmation()) {
    UseCounter::Count(&execution_context, WebFeature::kPriceChangeConfirmation);
  }
}

void StringifyAndParseMethodSpecificData(ExecutionContext& execution_context,
                                         const String& supported_method,
                                         const ScriptValue& input,
                                         PaymentMethodDataPtr& output,
                                         ExceptionState& exception_state) {
  PaymentsValidators::ValidateAndStringifyObject(
      execution_context.GetIsolate(), input, output->stringified_data,
      exception_state);
  if (exception_state.HadException()) {
    return;
  }

  if (supported_method == kGooglePlayBillingMethod) {
    MeasureGooglePlayBillingPriceChangeConfirmation(execution_context, input);
  }

  // Serialize payment method specific data to be sent to the payment apps. The
  // payment apps are responsible for validating and processing their method
  // data asynchronously. Do not throw exceptions here.
  if (supported_method == kGooglePayMethod ||
      supported_method == kAndroidPayMethod ||
      supported_method == kGooglePayAuthenticationMethod) {
    SetAndroidPayMethodData(execution_context.GetIsolate(), input, output,
                            IGNORE_EXCEPTION);
  }

  // Parse method data to avoid parsing JSON in the browser.
  if (supported_method == kSecurePaymentConfirmationMethod &&
      RuntimeEnabledFeatures::SecurePaymentConfirmationEnabled(
          &execution_context)) {
    UseCounter::Count(&execution_context,
                      WebFeature::kSecurePaymentConfirmation);
    output->secure_payment_confirmation =
        SecurePaymentConfirmationHelper::ParseSecurePaymentConfirmationData(
            input, execution_context, exception_state);
  }
}

void ValidateAndConvertPaymentDetailsModifiers(
    const HeapVector<Member<PaymentDetailsModifier>>& input,
    Vector<PaymentDetailsModifierPtr>& output,
    ExecutionContext& execution_context,
    ExceptionState& exception_state) {
  if (input.size() > PaymentRequest::kMaxListSize) {
    exception_state.ThrowTypeError("At most 1024 modifiers allowed");
    return;
  }

  for (const PaymentDetailsModifier* modifier : input) {
    output.push_back(payments::mojom::blink::PaymentDetailsModifier::New());
    if (modifier->hasTotal()) {
      ValidateAndConvertTotal(modifier->total(), "modifier total",
                              output.back()->total, execution_context,
                              exception_state);
      if (exception_state.HadException()) {
        return;
      }
    }

    if (modifier->hasAdditionalDisplayItems()) {
      ValidateAndConvertDisplayItems(modifier->additionalDisplayItems(),
                                     "additional display items in modifier",
                                     output.back()->additional_display_items,
                                     execution_context, exception_state);
      if (exception_state.HadException()) {
        return;
      }
    }

    if (!PaymentsValidators::IsValidMethodFormat(execution_context.GetIsolate(),
                                                 modifier->supportedMethod())) {
      exception_state.ThrowRangeError(
          "Invalid payment method identifier format");
      return;
    }

    output.back()->method_data =
        payments::mojom::blink::PaymentMethodData::New();
    output.back()->method_data->supported_method = modifier->supportedMethod();

    if (modifier->hasData() && !modifier->data().IsEmpty()) {
      StringifyAndParseMethodSpecificData(
          execution_context, modifier->supportedMethod(), modifier->data(),
          output.back()->method_data, exception_state);
    } else {
      output.back()->method_data->stringified_data = "";
    }
  }
}

void ValidateAndConvertPaymentDetailsBase(const PaymentDetailsBase* input,
                                          const PaymentOptions* options,
                                          PaymentDetailsPtr& output,
                                          String& shipping_option_output,
                                          ExecutionContext& execution_context,
                                          ExceptionState& exception_state) {
  if (input->hasDisplayItems()) {
    output->display_items = Vector<PaymentItemPtr>();
    ValidateAndConvertDisplayItems(input->displayItems(), "display items",
                                   *output->display_items, execution_context,
                                   exception_state);
    if (exception_state.HadException()) {
      return;
    }
  }

  // If requestShipping is specified and there are shipping options to validate,
  // proceed with validation.
  if (options->requestShipping() && input->hasShippingOptions()) {
    output->shipping_options = Vector<PaymentShippingOptionPtr>();
    ValidateAndConvertShippingOptions(
        input->shippingOptions(), *output->shipping_options,
        shipping_option_output, execution_context, exception_state);
    if (exception_state.HadException()) {
      return;
    }
  } else {
    shipping_option_output = String();
  }

  if (input->hasModifiers()) {
    output->modifiers = Vector<PaymentDetailsModifierPtr>();
    ValidateAndConvertPaymentDetailsModifiers(
        input->modifiers(), *output->modifiers, execution_context,
        exception_state);
  }
}

PaymentItemPtr CreateTotalPlaceHolderForAppStoreBilling(
    ExecutionContext& execution_context) {
  PaymentItemPtr total = payments::mojom::blink::PaymentItem::New();
  total->label = kAppStoreBillingLabelPlaceHolder;
  total->amount = payments::mojom::blink::PaymentCurrencyAmount::New();
  total->amount->currency = kUnknownCurrency;
  total->amount->value = "0";

  return total;
}

void ValidateAndConvertPaymentDetailsInit(const PaymentDetailsInit* input,
                                          const PaymentOptions* options,
                                          PaymentDetailsPtr& output,
                                          String& shipping_option_output,
                                          bool ignore_total,
                                          ExecutionContext& execution_context,
                                          ExceptionState& exception_state) {
  if (ignore_total) {
    output->total = CreateTotalPlaceHolderForAppStoreBilling(execution_context);
    if (input->hasTotal()) {
      execution_context.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kJavaScript,
          mojom::blink::ConsoleMessageLevel::kWarning,
          "Specified total is ignored for in-app purchases with app stores. "
          "User will be shown the total derived from the product identifier."));
    }
  } else {
    // Whether details (i.e., input) being omitted, null, defined or {} is
    // indistinguishable, so we check all of its attributes to decide whether it
    // has been provided.
    if (!input->hasTotal() && !input->hasId()) {
      exception_state.ThrowTypeError("required member details is undefined.");
      return;
    }
    if (!input->hasTotal()) {
      exception_state.ThrowTypeError("required member total is undefined.");
      return;
    }
    ValidateAndConvertTotal(input->total(), "total", output->total,
                            execution_context, exception_state);
    if (exception_state.HadException()) {
      return;
    }
  }

  ValidateAndConvertPaymentDetailsBase(input, options, output,
                                       shipping_option_output,
                                       execution_context, exception_state);
}

void ValidateAndConvertPaymentDetailsUpdate(const PaymentDetailsUpdate* input,
                                            const PaymentOptions* options,
                                            PaymentDetailsPtr& output,
                                            String& shipping_option_output,
                                            bool ignore_total,
                                            ExecutionContext& execution_context,
                                            ExceptionState& exception_state) {
  ValidateAndConvertPaymentDetailsBase(input, options, output,
                                       shipping_option_output,
                                       execution_context, exception_state);
  if (exception_state.HadException()) {
    return;
  }
  if (input->hasTotal()) {
    if (ignore_total) {
      output->total =
          CreateTotalPlaceHolderForAppStoreBilling(execution_context);
    } else {
      ValidateAndConvertTotal(input->total(), "total", output->total,
                              execution_context, exception_state);
      if (exception_state.HadException()) {
        return;
      }
    }
  }

  if (input->hasError()) {
    String error_message;
    if (!PaymentsValidators::IsValidErrorMsgFormat(input->error(),
                                                   &error_message)) {
      exception_state.ThrowTypeError(error_message);
      return;
    }
    output->error = input->error();
  }

  if (input->hasShippingAddressErrors()) {
    String error_message;
    if (!PaymentsValidators::IsValidAddressErrorsFormat(
            input->shippingAddressErrors(), &error_message)) {
      exception_state.ThrowTypeError(error_message);
      return;
    }
    output->shipping_address_errors =
        payments::mojom::blink::AddressErrors::From(
            *input->shippingAddressErrors());
  }

  if (input->hasPaymentMethodErrors()) {
    PaymentsValidators::ValidateAndStringifyObject(
        execution_context.GetIsolate(), input->paymentMethodErrors(),
        output->stringified_payment_method_errors, exception_state);
  }
}

// Checks whether Content Security Policy (CSP) allows a connection to the
// given `url`. If it does not, then a CSP violation will be reported in the
// developer console.
bool CSPAllowsConnectToSource(const KURL& url,
                              const KURL& url_before_redirects,
                              bool did_follow_redirect,
                              ExecutionContext& context) {
  return context.GetContentSecurityPolicy()->AllowConnectToSource(
      url, url_before_redirects,
      did_follow_redirect ? RedirectStatus::kFollowedRedirect
                          : RedirectStatus::kNoRedirect,
      ReportingDisposition::kReport);
}

void ValidateAndConvertPaymentMethodData(
    const HeapVector<Member<PaymentMethodData>>& input,
    const PaymentOptions* options,
    Vector<payments::mojom::blink::PaymentMethodDataPtr>& output,
    HashSet<String>& method_names,
    ExecutionContext& execution_context,
    ExceptionState& exception_state) {
  if (input.empty()) {
    exception_state.ThrowTypeError("At least one payment method is required");
    return;
  }

  if (input.size() > PaymentRequest::kMaxListSize) {
    exception_state.ThrowTypeError(
        "At most 1024 payment methods are supported");
    return;
  }

  for (const PaymentMethodData* payment_method_data : input) {
    if (!PaymentsValidators::IsValidMethodFormat(
            execution_context.GetIsolate(),
            payment_method_data->supportedMethod())) {
      exception_state.ThrowRangeError(
          "Invalid payment method identifier format");
      return;
    }

    if (method_names.Contains(payment_method_data->supportedMethod())) {
      exception_state.ThrowRangeError(
          "Cannot have duplicate payment method identifiers");
      return;
    }

    if (payment_method_data->supportedMethod() ==
            kSecurePaymentConfirmationMethod &&
        RuntimeEnabledFeatures::SecurePaymentConfirmationEnabled(
            &execution_context)) {
      if (input.size() > 1) {
        exception_state.ThrowRangeError(
            String(kSecurePaymentConfirmationMethod) +
            " must be the only payment method identifier specified in the "
            "PaymentRequest constructor.");
        return;
      } else if (options->requestShipping() || options->requestPayerName() ||
                 options->requestPayerEmail() || options->requestPayerPhone()) {
        exception_state.ThrowRangeError(
            String(kSecurePaymentConfirmationMethod) +
            " payment method identifier cannot be used with "
            "\"requestShipping\", \"requestPayerName\", \"requestPayerEmail\", "
            "or \"requestPayerPhone\" options.");
        return;
      }
    }

    KURL url(payment_method_data->supportedMethod());
    if (url.IsValid() &&
        !CSPAllowsConnectToSource(url, /*url_before_redirects=*/url,
                                  /*did_follow_redirect=*/false,
                                  execution_context)) {
      exception_state.ThrowRangeError(
          payment_method_data->supportedMethod() +
          " payment method identifier violates Content Security Policy.");
      return;
    }

    method_names.insert(payment_method_data->supportedMethod());

    if (payment_method_data->supportedMethod() == kAndroidPayMethod) {
      UseCounter::Count(&execution_context,
                        WebFeature::kPaymentRequestDeprecatedPaymentMethod);
    }

    output.push_back(payments::mojom::blink::PaymentMethodData::New());
    output.back()->supported_method = payment_method_data->supportedMethod();

    if (payment_method_data->hasData() &&
        !payment_method_data->data().IsEmpty()) {
      StringifyAndParseMethodSpecificData(
          execution_context, payment_method_data->supportedMethod(),
          payment_method_data->data(), output.back(), exception_state);
      if (exception_state.HadException()) {
        continue;
      }
    } else {
      output.back()->stringified_data = "";
    }
  }
}

bool AllowedToUsePaymentRequest(ExecutionContext* execution_context) {
  // To determine whether a Document object |document| is allowed to use the
  // feature indicated by attribute name |allowpaymentrequest|, run these steps:

  // Note: PaymentRequest is only exposed to Window and not workers.
  // 1. If |document| has no browsing context, then return false.
  if (execution_context->IsContextDestroyed()) {
    return false;
  }

  // 2. If Permissions Policy is enabled, return the policy for "payment"
  // feature.
  return execution_context->IsFeatureEnabled(
      mojom::blink::PermissionsPolicyFeature::kPayment,
      ReportOptions::kReportOnFailure);
}

void WarnIgnoringQueryQuotaForCanMakePayment(
    ExecutionContext& execution_context,
    const char* method_name) {
  const Strin
"""


```