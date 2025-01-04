Response:
Let's break down the thought process for analyzing the `payment_instruments.cc` file.

1. **Understand the Goal:** The request is to analyze the functionality of the provided C++ source code file (`payment_instruments.cc`) within the Chromium Blink rendering engine. The analysis needs to cover its purpose, relation to web technologies (JavaScript, HTML, CSS), logical reasoning with examples, common usage errors, and how a user might reach this code during debugging.

2. **High-Level Overview (Skim the Code):**  The first step is to quickly read through the code to get a general sense of what it does. Keywords like "PaymentInstruments", "deleteInstrument", "get", "keys", "has", "set", "clear", "ScriptPromise", "PaymentInstrument", and the namespace `payments` strongly suggest this code is about managing payment instrument data. The inclusion of Mojo bindings (`payments::mojom::blink::...`) indicates interaction with other browser processes.

3. **Identify Core Functionality (Focus on Public Methods):**  The public methods of the `PaymentInstruments` class are the primary entry points for its functionality. These are:
    * `deleteInstrument`:  Deletes a payment instrument.
    * `get`: Retrieves a payment instrument.
    * `keys`:  Gets a list of payment instrument keys.
    * `has`: Checks if a payment instrument exists.
    * `set`: Creates or updates a payment instrument.
    * `clear`: Deletes all payment instruments.

4. **Relate to Web Technologies:** Now, think about how these actions relate to web development. The names of the methods directly correspond to methods that might be exposed in a JavaScript API. The `PaymentInstrument` itself likely represents data that could be structured and manipulated in JavaScript.

    * **JavaScript:**  The `ScriptPromise` return types immediately suggest that these methods are designed to be called from JavaScript and return asynchronous results. The method names like `deleteInstrument`, `get`, etc., align with typical JavaScript API patterns for data management.

    * **HTML:**  HTML is where users initiate actions. A payment flow might start with a button click or form submission in HTML. The `allow="payment"` attribute mentioned in an error message suggests an HTML integration point for iframes.

    * **CSS:** CSS is less directly involved but can style the UI elements that trigger payment flows.

5. **Logical Reasoning and Examples:** For each core function, consider:
    * **Input:** What data is passed to the function? (e.g., `instrument_key`, `PaymentInstrument` object).
    * **Process:** What are the internal steps involved? (Interaction with `payment_manager_`, permission checks, Mojo calls).
    * **Output:** What does the function return? (A `ScriptPromise` resolving to a boolean, a `PaymentInstrument`, a list of strings, or undefined).
    * **Assumptions:** What conditions must be true for the function to work correctly? (e.g., Payment Manager is available, permissions are granted).

    Construct simple examples to illustrate the input and output. For instance, deleting an instrument requires the `instrument_key` as input and returns a promise that resolves to `true` or `false`.

6. **Common Usage Errors:** Think about what could go wrong when a developer uses these APIs.
    * **Permissions:**  The permission check is a major source of potential errors.
    * **Invalid State:** The "Payment manager unavailable" error is another key point.
    * **Invalid Input:** Incorrect URLs for icons or missing required data can cause issues.
    * **Service Workers:** The code comments mention potential issues related to service workers and user gestures.

7. **User Operations and Debugging:**  Trace the user's journey that leads to this code. The starting point is usually a user interacting with a website.
    * **Initial Action:** User clicks a "Pay" button.
    * **JavaScript Execution:** JavaScript code uses the Payment Request API or a related API that interacts with `PaymentInstruments`.
    * **Blink Invocation:** The JavaScript call translates into a call to the C++ `PaymentInstruments` methods.
    * **Debugging:** Explain how a developer can set breakpoints in this C++ code to observe the execution flow, inspect variables, and identify potential issues.

8. **Code Details and Specifics:**  Go back through the code and pick out important details:
    * **Mojo Interface:** Note the use of `payments::mojom::blink::PaymentInstrumentPtr` and other Mojo types, highlighting the inter-process communication.
    * **Error Handling:** Pay attention to how different error conditions are handled (e.g., `rejectError` template).
    * **Permission Handling:**  Describe the permission check using `PermissionsPolicy` and the `RequestPermission` mechanism.
    * **Data Structures:**  Mention the `PaymentInstrument` class and its members (name, icons, method).
    * **Use Counters:** Explain the purpose of `UseCounter::Count`.

9. **Structure and Refine:** Organize the information logically using headings and bullet points. Ensure clear and concise explanations. Review for accuracy and completeness. For instance, initially, I might have just said "manages payment instruments."  But refining that to "manages the storage, retrieval, and deletion of payment instrument details..." is more precise. Similarly, explaining the flow from user action to C++ code requires stepping through the layers.

10. **Self-Correction/Refinement Example During the Process:**  Initially, I might have overlooked the significance of the `allow="payment"` attribute. However, when I encountered the `ThrowNotAllowedToUsePaymentFeatures` function, I'd look closer and see the comment about iframes. This would lead me to refine my understanding and add the HTML aspect. Similarly, realizing that the `rejectError` function handles multiple `PaymentHandlerStatus` values would prompt me to list them out for a more complete analysis.

By following these steps, combining high-level understanding with detailed code inspection, and thinking about the interaction between different parts of the system, a comprehensive analysis of the `payment_instruments.cc` file can be generated.
好的，让我们来分析一下 `blink/renderer/modules/payments/payment_instruments.cc` 这个文件。

**文件功能概述：**

`payment_instruments.cc` 文件实现了 Blink 渲染引擎中与 **Payment Instruments API** 相关的核心功能。Payment Instruments API 允许网站存储和管理用户的支付方式（例如信用卡、银行账户等），以便在后续的支付流程中更便捷地使用。

该文件主要负责：

1. **管理已保存的支付工具信息：** 提供增、删、改、查（CRUD）支付工具的功能。
2. **与浏览器进程交互：**  通过 Mojo 接口与浏览器进程中的 Payment Handler 进行通信，实际的支付工具数据存储和管理可能在浏览器进程中进行。
3. **处理权限请求：**  在网站尝试存储或访问支付工具信息时，处理权限请求，确保用户授权。
4. **提供 JavaScript 接口的底层实现：**  该文件中的 C++ 代码为 JavaScript 中 `PaymentInstruments` 接口提供了具体的实现逻辑。
5. **处理异步操作：**  使用 `ScriptPromise` 来处理与浏览器进程的异步通信。

**与 JavaScript, HTML, CSS 的关系：**

`payment_instruments.cc` 文件是 Payment Instruments API 的底层实现，它直接与 JavaScript API 交互。

* **JavaScript:**
    * **功能关系：**  网站开发者通过 JavaScript 中的 `navigator.paymentInstruments` 对象来调用该文件中实现的 C++ 功能。例如，`navigator.paymentInstruments.get("my-credit-card")` 会最终调用到 `PaymentInstruments::get` 方法。
    * **举例说明：**
        ```javascript
        // JavaScript 代码
        navigator.paymentInstruments.has('my-credit-card')
          .then(function(hasInstrument) {
            if (hasInstrument) {
              console.log('已保存该支付方式');
            } else {
              console.log('未保存该支付方式');
            }
          });

        navigator.paymentInstruments.set('new-debit-card', {
          name: '我的借记卡',
          icons: [{ src: '/images/debit-card.png', sizes: '64x64' }],
          method: 'https://example.com/payment-method-debit'
        }).then(() => {
          console.log('支付方式已保存');
        });
        ```
        上述 JavaScript 代码中调用的 `has` 和 `set` 方法，其背后的 C++ 实现逻辑就在 `payment_instruments.cc` 文件中。

* **HTML:**
    * **功能关系：** HTML 用于构建网页结构，用户在网页上的操作（例如点击按钮触发支付）可能会间接地调用到 Payment Instruments API。
    * **举例说明：**
        ```html
        <!-- HTML 代码 -->
        <button id="checkPaymentMethod">检查支付方式</button>
        <script>
          document.getElementById('checkPaymentMethod').addEventListener('click', function() {
            navigator.paymentInstruments.has('default-card')
              .then(console.log);
          });
        </script>
        ```
        当用户点击 "检查支付方式" 按钮时，JavaScript 代码会调用 `navigator.paymentInstruments.has`，最终会执行到 `payment_instruments.cc` 中的 `PaymentInstruments::has` 方法。
    * **`allow="payment"` 属性：**  代码中提到了 `allow="payment"`，这指的是 iframe 元素的 `allow` 属性。为了在 iframe 中使用 Payment Instruments API，该 iframe 需要显式声明允许使用 payment 功能：
        ```html
        <iframe src="payment-page.html" allow="payment"></iframe>
        ```

* **CSS:**
    * **功能关系：** CSS 主要负责网页的样式，与 `payment_instruments.cc` 的功能没有直接关系。但 CSS 可以用于美化用户交互界面，例如支付按钮、支付方式列表等。

**逻辑推理（假设输入与输出）：**

**假设输入：** JavaScript 代码调用 `navigator.paymentInstruments.get("my-visa-card")`。

**逻辑推理过程：**

1. JavaScript 调用被 Blink 引擎接收。
2. Blink 引擎找到 `PaymentInstruments` 对象的 `get` 方法（对应 `PaymentInstruments::get`）。
3. `PaymentInstruments::get` 方法首先检查权限，确保当前上下文允许使用 Payment API。
4. 如果权限允许，`get` 方法通过 Mojo 向浏览器进程中的 Payment Handler 发送请求，请求获取键为 "my-visa-card" 的支付工具信息。
5. 浏览器进程中的 Payment Handler 查询本地存储或其他方式，查找对应的支付工具信息。
6. Payment Handler 将查询结果通过 Mojo 发送回 Blink 进程。
7. `PaymentInstruments::onGetPaymentInstrument` 方法接收到来自浏览器进程的响应。
8. 如果找到支付工具，`onGetPaymentInstrument` 将其转换为 `PaymentInstrument` 对象，并通过 Promise 返回给 JavaScript。
9. 如果未找到，Promise 可能会 resolve 为 `undefined` 或者 reject (取决于具体实现和错误类型)。

**假设输出（成功情况）：**  一个 Promise，resolve 的值为一个 `PaymentInstrument` 对象，包含 "my-visa-card" 的名称、图标 URL、支付方法标识符等信息。

**假设输出（失败情况）：** 一个 Promise，reject 的值为一个 `DOMException`，例如如果权限被拒绝，或者 Payment Manager 不可用。

**用户或编程常见的使用错误：**

1. **权限错误：**
   * **错误示例：** 在一个没有启用 Payment API 的 iframe 中调用 `navigator.paymentInstruments.set`。
   * **错误信息：**  `"Must be in a top-level browsing context or an iframe needs to specify allow=\"payment\" explicitly"` (代码中已包含此错误提示)。
   * **原因：**  出于安全考虑，Payment Instruments API 的使用受到权限限制。
2. **Payment Manager 不可用：**
   * **错误示例：**  在浏览器 Payment Handler 服务出现问题时尝试调用 `navigator.paymentInstruments` 的任何方法。
   * **错误信息：** `"Payment manager unavailable"` (代码中已包含此错误提示)。
   * **原因：**  Blink 进程无法连接到负责管理支付工具的浏览器进程服务。
3. **无效的支付工具信息：**
   * **错误示例：**  调用 `set` 方法时，提供的图标 URL 无效或不是 HTTP/HTTPS 协议。
   * **错误信息：**  `"'<invalid URL>' is not a valid URL."` (代码中已包含此错误提示)。
   * **原因：**  需要提供有效的支付工具信息。
4. **未处理 Promise 的 rejection：**
   * **错误示例：**  调用 `navigator.paymentInstruments.get` 但没有正确处理 Promise 被 reject 的情况（例如支付工具不存在）。
   * **后果：**  可能会导致 JavaScript 错误或未预期的行为。开发者应该始终使用 `.then()` 和 `.catch()` 或 `async/await` 来处理 Promise 的结果。
5. **Service Worker 上下文中的使用限制：** 代码注释中提到了 Service Worker 可能会缺少用户手势，这可能会导致某些操作失败。 这是因为某些敏感操作可能需要用户的主动触发。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户在网页上触发了与支付相关的操作：** 例如，点击了一个 "保存支付方式" 的按钮，或者在支付流程中选择了 "记住我的支付信息"。
2. **网页上的 JavaScript 代码调用了 Payment Instruments API：**  例如，`navigator.paymentInstruments.set(key, details)`。
3. **浏览器接收到 JavaScript 调用：**  Blink 渲染引擎负责执行网页的 JavaScript 代码。
4. **Blink 引擎内部将 JavaScript 调用路由到 `PaymentInstruments` 对象的相应 C++ 方法：** 例如，`navigator.paymentInstruments.set` 会调用 `PaymentInstruments::set`。
5. **`PaymentInstruments::set` 方法执行相应的逻辑：**
   * **权限检查：** 检查当前上下文是否允许使用 Payment API。
   * **Mojo 调用：**  通过 Mojo 接口向浏览器进程的 Payment Handler 发送请求，传递支付工具的信息。
   * **异步处理：**  使用 `ScriptPromise` 来处理与浏览器进程的异步通信。
6. **浏览器进程的 Payment Handler 处理请求：**  例如，将支付工具信息存储到本地。
7. **浏览器进程将结果通过 Mojo 发送回 Blink 进程。**
8. **Blink 进程的 `PaymentInstruments` 对象接收到结果，并 resolve 或 reject 相应的 JavaScript Promise。**

**调试线索：**

* **在 JavaScript 代码中设置断点：**  查看 JavaScript 调用 Payment Instruments API 时的参数和上下文。
* **在 `payment_instruments.cc` 的关键方法中设置断点：** 例如 `PaymentInstruments::set`, `PaymentInstruments::get`，可以观察 C++ 层的执行流程、变量值以及与浏览器进程的通信情况。
* **查看 Chrome 的开发者工具 Console 面板：**  检查是否有与 Payment Instruments API 相关的错误或警告信息。
* **使用 `chrome://inspect/#devices` 或 `chrome://serviceworker-internals/`：**  检查 Service Worker 的状态，如果涉及到 Service Worker 的使用。
* **查看 `netlog` (chrome://net-export/)：**  可以查看网络请求和 Mojo 消息的详细信息，有助于诊断与浏览器进程通信相关的问题。

希望以上分析能够帮助你理解 `blink/renderer/modules/payments/payment_instruments.cc` 文件的功能和作用。

Prompt: 
```
这是目录为blink/renderer/modules/payments/payment_instruments.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/payments/payment_instruments.h"

#include <utility>

#include "base/location.h"
#include "third_party/blink/public/common/permissions_policy/permissions_policy.h"
#include "third_party/blink/public/mojom/manifest/manifest.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_icon_sizes_parser.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_image_object.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_instrument.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/modules/payments/payment_manager.h"
#include "third_party/blink/renderer/modules/permissions/permission_utils.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {
namespace {

// Maximum size of a PaymentInstrument icon's type when passed over mojo.
const size_t kMaxTypeLength = 4096;

static const char kPaymentManagerUnavailable[] = "Payment manager unavailable";

template <typename IDLType>
bool rejectError(ScriptPromiseResolver<IDLType>* resolver,
                 payments::mojom::blink::PaymentHandlerStatus status) {
  switch (status) {
    case payments::mojom::blink::PaymentHandlerStatus::SUCCESS:
      return false;
    case payments::mojom::blink::PaymentHandlerStatus::NOT_FOUND:
      resolver->Resolve();
      return true;
    case payments::mojom::blink::PaymentHandlerStatus::NO_ACTIVE_WORKER:
      resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                       "No active service worker");
      return true;
    case payments::mojom::blink::PaymentHandlerStatus::STORAGE_OPERATION_FAILED:
      resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                       "Storage operation is failed");
      return true;
    case payments::mojom::blink::PaymentHandlerStatus::
        FETCH_INSTRUMENT_ICON_FAILED: {
      resolver->RejectWithTypeError("Fetch or decode instrument icon failed");
      return true;
    }
    case payments::mojom::blink::PaymentHandlerStatus::
        FETCH_PAYMENT_APP_INFO_FAILED:
      // FETCH_PAYMENT_APP_INFO_FAILED indicates everything works well except
      // fetching payment handler's name and/or icon from its web app manifest.
      // The origin or name will be used to label this payment handler in
      // UI in this case, so only show warnning message instead of reject the
      // promise. The warning message was printed by
      // payment_app_info_fetcher.cc.
      return false;
  }
}

bool AllowedToUsePaymentFeatures(ScriptState* script_state) {
  if (!script_state->ContextIsValid())
    return false;
  return ExecutionContext::From(script_state)
      ->GetSecurityContext()
      .GetPermissionsPolicy()
      ->IsFeatureEnabled(mojom::blink::PermissionsPolicyFeature::kPayment);
}

void ThrowNotAllowedToUsePaymentFeatures(ExceptionState& exception_state) {
  exception_state.ThrowSecurityError(
      "Must be in a top-level browsing context or an iframe needs to specify "
      "allow=\"payment\" explicitly");
}

ScriptPromise<IDLUndefined> RejectNotAllowedToUsePaymentFeatures(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  ThrowNotAllowedToUsePaymentFeatures(exception_state);
  return EmptyPromise();
}

}  // namespace

PaymentInstruments::PaymentInstruments(const PaymentManager& payment_manager,
                                       ExecutionContext* context)
    : payment_manager_(payment_manager), permission_service_(context) {}

ScriptPromise<IDLBoolean> PaymentInstruments::deleteInstrument(
    ScriptState* script_state,
    const String& instrument_key,
    ExceptionState& exception_state) {
  if (!AllowedToUsePaymentFeatures(script_state)) {
    ThrowNotAllowedToUsePaymentFeatures(exception_state);
    return EmptyPromise();
  }

  if (!payment_manager_->manager().is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kPaymentManagerUnavailable);
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  payment_manager_->manager()->DeletePaymentInstrument(
      instrument_key,
      WTF::BindOnce(&PaymentInstruments::onDeletePaymentInstrument,
                    WrapPersistent(this), WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<PaymentInstrument> PaymentInstruments::get(
    ScriptState* script_state,
    const String& instrument_key,
    ExceptionState& exception_state) {
  if (!AllowedToUsePaymentFeatures(script_state)) {
    ThrowNotAllowedToUsePaymentFeatures(exception_state);
    return EmptyPromise();
  }

  if (!payment_manager_->manager().is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kPaymentManagerUnavailable);
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PaymentInstrument>>(
          script_state, exception_state.GetContext());

  payment_manager_->manager()->GetPaymentInstrument(
      instrument_key,
      WTF::BindOnce(&PaymentInstruments::onGetPaymentInstrument,
                    WrapPersistent(this), WrapPersistent(resolver)));
  return resolver->Promise();
}

ScriptPromise<IDLSequence<IDLString>> PaymentInstruments::keys(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!AllowedToUsePaymentFeatures(script_state)) {
    ThrowNotAllowedToUsePaymentFeatures(exception_state);
    return ScriptPromise<IDLSequence<IDLString>>();
  }

  if (!payment_manager_->manager().is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kPaymentManagerUnavailable);
    return ScriptPromise<IDLSequence<IDLString>>();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<IDLString>>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  payment_manager_->manager()->KeysOfPaymentInstruments(
      WTF::BindOnce(&PaymentInstruments::onKeysOfPaymentInstruments,
                    WrapPersistent(this), WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLBoolean> PaymentInstruments::has(
    ScriptState* script_state,
    const String& instrument_key,
    ExceptionState& exception_state) {
  if (!AllowedToUsePaymentFeatures(script_state)) {
    ThrowNotAllowedToUsePaymentFeatures(exception_state);
    return EmptyPromise();
  }

  if (!payment_manager_->manager().is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kPaymentManagerUnavailable);
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  payment_manager_->manager()->HasPaymentInstrument(
      instrument_key,
      WTF::BindOnce(&PaymentInstruments::onHasPaymentInstrument,
                    WrapPersistent(this), WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLUndefined> PaymentInstruments::set(
    ScriptState* script_state,
    const String& instrument_key,
    const PaymentInstrument* details,
    ExceptionState& exception_state) {
  if (!AllowedToUsePaymentFeatures(script_state))
    return RejectNotAllowedToUsePaymentFeatures(script_state, exception_state);

  if (!payment_manager_->manager().is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kPaymentManagerUnavailable);
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());

  // TODO(crbug.com/1311953): A service worker can get here without a frame to
  // check for a user gesture. We should consider either removing the user
  // gesture requirement or not exposing PaymentInstruments to service workers.
  LocalDOMWindow* window = LocalDOMWindow::From(script_state);
  bool user_gesture =
      window ? LocalFrame::HasTransientUserActivation(window->GetFrame())
             : false;

  // Should move this permission check to browser process.
  // Please see http://crbug.com/795929
  GetPermissionService(script_state)
      ->RequestPermission(
          CreatePermissionDescriptor(
              mojom::blink::PermissionName::PAYMENT_HANDLER),
          user_gesture,
          WTF::BindOnce(&PaymentInstruments::OnRequestPermission,
                        WrapPersistent(this), WrapPersistent(resolver),
                        instrument_key, WrapPersistent(details)));
  return resolver->Promise();
}

ScriptPromise<IDLUndefined> PaymentInstruments::clear(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!AllowedToUsePaymentFeatures(script_state))
    return RejectNotAllowedToUsePaymentFeatures(script_state, exception_state);

  if (!payment_manager_->manager().is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kPaymentManagerUnavailable);
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  payment_manager_->manager()->ClearPaymentInstruments(
      WTF::BindOnce(&PaymentInstruments::onClearPaymentInstruments,
                    WrapPersistent(this), WrapPersistent(resolver)));
  return promise;
}

void PaymentInstruments::Trace(Visitor* visitor) const {
  visitor->Trace(payment_manager_);
  visitor->Trace(permission_service_);
  ScriptWrappable::Trace(visitor);
}

mojom::blink::PermissionService* PaymentInstruments::GetPermissionService(
    ScriptState* script_state) {
  if (!permission_service_.is_bound()) {
    ConnectToPermissionService(
        ExecutionContext::From(script_state),
        permission_service_.BindNewPipeAndPassReceiver(
            ExecutionContext::From(script_state)
                ->GetTaskRunner(TaskType::kMiscPlatformAPI)));
  }
  return permission_service_.get();
}

void PaymentInstruments::OnRequestPermission(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    const String& instrument_key,
    const PaymentInstrument* details,
    mojom::blink::PermissionStatus status) {
  DCHECK(resolver);
  if (!resolver->GetExecutionContext() ||
      resolver->GetExecutionContext()->IsContextDestroyed())
    return;

  if (status != mojom::blink::PermissionStatus::GRANTED) {
    resolver->RejectWithDOMException(
        DOMExceptionCode::kNotAllowedError,
        "Not allowed to install this payment handler");
    return;
  }

  payments::mojom::blink::PaymentInstrumentPtr instrument =
      payments::mojom::blink::PaymentInstrument::New();
  instrument->name = details->hasName() ? details->name() : WTF::g_empty_string;
  if (details->hasIcons()) {
    ExecutionContext* context =
        ExecutionContext::From(resolver->GetScriptState());
    for (const ImageObject* image_object : details->icons()) {
      KURL parsed_url = context->CompleteURL(image_object->src());
      if (!parsed_url.IsValid() || !parsed_url.ProtocolIsInHTTPFamily()) {
        resolver->RejectWithTypeError("'" + image_object->src() +
                                      "' is not a valid URL.");
        return;
      }

      mojom::blink::ManifestImageResourcePtr icon =
          mojom::blink::ManifestImageResource::New();
      icon->src = parsed_url;
      // Truncate the type to avoid passing too-large strings to Mojo (see
      // https://crbug.com/810792). We could additionally verify that the type
      // is a MIME type, but the browser side will do that anyway.
      icon->type = image_object->getTypeOr("").Left(kMaxTypeLength);
      icon->purpose.push_back(blink::mojom::ManifestImageResource_Purpose::ANY);
      WebVector<gfx::Size> web_sizes =
          WebIconSizesParser::ParseIconSizes(image_object->getSizesOr(""));
      for (const auto& web_size : web_sizes) {
        icon->sizes.push_back(web_size);
      }
      instrument->icons.push_back(std::move(icon));
    }
  }

  instrument->method =
      details->hasMethod() ? details->method() : WTF::g_empty_string;
  // TODO(crbug.com/1209835): Remove stringified_capabilities entirely.
  instrument->stringified_capabilities = WTF::g_empty_string;

  UseCounter::Count(resolver->GetExecutionContext(),
                    WebFeature::kPaymentHandler);

  payment_manager_->manager()->SetPaymentInstrument(
      instrument_key, std::move(instrument),
      WTF::BindOnce(&PaymentInstruments::onSetPaymentInstrument,
                    WrapPersistent(this), WrapPersistent(resolver)));
}

void PaymentInstruments::onDeletePaymentInstrument(
    ScriptPromiseResolver<IDLBoolean>* resolver,
    payments::mojom::blink::PaymentHandlerStatus status) {
  DCHECK(resolver);
  resolver->Resolve(status ==
                    payments::mojom::blink::PaymentHandlerStatus::SUCCESS);
}

void PaymentInstruments::onGetPaymentInstrument(
    ScriptPromiseResolver<PaymentInstrument>* resolver,
    payments::mojom::blink::PaymentInstrumentPtr stored_instrument,
    payments::mojom::blink::PaymentHandlerStatus status) {
  DCHECK(resolver);
  if (!resolver->GetExecutionContext() ||
      resolver->GetExecutionContext()->IsContextDestroyed())
    return;

  ScriptState::Scope scope(resolver->GetScriptState());

  if (rejectError(resolver, status))
    return;
  PaymentInstrument* instrument = PaymentInstrument::Create();
  instrument->setName(stored_instrument->name);

  HeapVector<Member<ImageObject>> icons;
  for (const auto& icon : stored_instrument->icons) {
    ImageObject* image_object = ImageObject::Create();
    image_object->setSrc(icon->src.GetString());
    image_object->setType(icon->type);
    String sizes = WTF::g_empty_string;
    for (const auto& size : icon->sizes) {
      sizes = sizes + String::Format("%dx%d ", size.width(), size.height());
    }
    image_object->setSizes(sizes.StripWhiteSpace());
    icons.push_back(image_object);
  }
  instrument->setIcons(icons);
  instrument->setMethod(stored_instrument->method);

  resolver->Resolve(instrument);
}

void PaymentInstruments::onKeysOfPaymentInstruments(
    ScriptPromiseResolver<IDLSequence<IDLString>>* resolver,
    const Vector<String>& keys,
    payments::mojom::blink::PaymentHandlerStatus status) {
  DCHECK(resolver);
  if (rejectError(resolver, status))
    return;
  resolver->Resolve(keys);
}

void PaymentInstruments::onHasPaymentInstrument(
    ScriptPromiseResolver<IDLBoolean>* resolver,
    payments::mojom::blink::PaymentHandlerStatus status) {
  DCHECK(resolver);
  resolver->Resolve(status ==
                    payments::mojom::blink::PaymentHandlerStatus::SUCCESS);
}

void PaymentInstruments::onSetPaymentInstrument(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    payments::mojom::blink::PaymentHandlerStatus status) {
  DCHECK(resolver);
  if (rejectError(resolver, status))
    return;
  resolver->Resolve();
}

void PaymentInstruments::onClearPaymentInstruments(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    payments::mojom::blink::PaymentHandlerStatus status) {
  DCHECK(resolver);
  if (rejectError(resolver, status))
    return;
  resolver->Resolve();
}

}  // namespace blink

"""

```