Response:
Let's break down the thought process for analyzing this C++ file.

1. **Understand the Goal:** The request asks for the functionality of the `PaymentRequestEvent.cc` file within the Chromium Blink rendering engine, its relationship to web technologies (JavaScript, HTML, CSS), potential usage errors, and debugging context.

2. **Initial Scan for Keywords and Structure:** I'd first skim the file, looking for:
    * Class names: `PaymentRequestEvent`, `PaymentRequestRespondWithFulfill`.
    * Included headers:  Headers like `v8.h`, `mojom`, and those related to `payments` and `service_worker` are strong indicators of the file's purpose. The presence of `ScriptPromiseResolver` and `ExceptionState` suggests interaction with JavaScript.
    * Method names:  `Create`, the constructor, getters for various properties (`topOrigin`, `paymentRequestOrigin`, etc.), and methods like `openWindow`, `changePaymentMethod`, `changeShippingAddress`, `changeShippingOption`, `respondWith`. These are crucial for understanding the file's actions.
    * Namespaces: `blink`.
    * Comments:  The copyright notice and the `TODO` comment offer some context.

3. **Identify Core Functionality:** Based on the keywords, class names, and methods, the primary purpose seems to be handling events related to the Payment Request API. The name `PaymentRequestEvent` itself is a strong clue. The methods suggest it's about responding to and manipulating payment requests.

4. **Analyze Key Methods and Data Members:**
    * **Constructor and `Create`:**  These are responsible for initializing the `PaymentRequestEvent` object. The parameters of the constructor and `Create` method (like `PaymentRequestEventInit`, `PaymentHandlerHost`, `PaymentRequestRespondWithObserver`) provide insight into the data the event holds and the components it interacts with.
    * **Getters:** Methods like `topOrigin()`, `paymentRequestOrigin()`, `methodData()`, `total()`, etc., indicate the information that this event encapsulates. This data likely comes from the initial payment request made by the website.
    * **`openWindow()`:** This suggests the payment handler can open a new window, likely for handling payment authorization. The security checks within this method (trust, same-origin, user activation) are important.
    * **`changePaymentMethod()`, `changeShippingAddress()`, `changeShippingOption()`:** These methods allow the payment handler to request updates to the payment request details. The use of `ScriptPromise` indicates asynchronous operations and interaction with JavaScript.
    * **`respondWith()`:** This is the core method for the payment handler to provide a response to the initial payment request. The use of `ScriptPromise` again highlights the asynchronous nature.
    * **`PaymentRequestRespondWithFulfill`:** This looks like a callback used when the promise returned by `respondWith` is fulfilled.
    * **`OnChangePaymentRequestDetailsResponse()`:**  This method handles the response from the browser process after a `changePaymentMethod`, `changeShippingAddress`, or `changeShippingOption` call. It parses the response data and updates the JavaScript promise.
    * **Data Members:** Members like `method_data_`, `total_`, `modifiers_`, `payment_options_`, `shipping_options_`, `payment_handler_host_`, and `observer_` store the state and manage interactions. The `payment_handler_host_` being a `mojo::PendingRemote` signifies communication with another process (the browser process).

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The heavy use of `ScriptPromise`, `ScriptValue`, `ExceptionState`, and the inclusion of V8 headers clearly show the connection to JavaScript. The `PaymentRequestEvent` is an event object that would be dispatched to a JavaScript event listener. Methods like `openWindow`, `changePaymentMethod`, etc., are callable from JavaScript. The data structures (like `PaymentMethodData`, `PaymentCurrencyAmount`, `AddressInit`) map to JavaScript objects.
    * **HTML:**  While this specific C++ file doesn't directly manipulate HTML, the Payment Request API is triggered by JavaScript code running in an HTML page. The user interaction leading to a payment request starts with HTML elements and JavaScript event handlers.
    * **CSS:** CSS is less directly involved, but the visual presentation of the payment UI (which might be influenced by the payment handler) is styled with CSS. The `openWindow` method might open a page with custom CSS.

6. **Infer Logical Reasoning and Example:**  Consider the `changeShippingAddress` method. The logic is:
    * Receive a new shipping address from the JavaScript handler.
    * Validate the address.
    * Send the address to the browser process (`payment_handler_host_->ChangeShippingAddress`).
    * Receive an update from the browser process (via `OnChangePaymentRequestDetailsResponse`).
    * Resolve or reject the JavaScript promise based on the update.

    * **Hypothetical Input:**  JavaScript calls `event.changeShippingAddress({ recipient: 'New Name', ... })`.
    * **Output:** The `OnChangePaymentRequestDetailsResponse` method receives a `PaymentRequestDetailsUpdatePtr` from the browser. If the address is valid and results in a change (e.g., updated shipping costs), the promise resolves with a `PaymentRequestDetailsUpdate` object containing the new total. If there's an error, the promise is rejected.

7. **Identify User/Programming Errors:**
    * **Invalid State Errors:** Calling `changePaymentMethod` while a previous change is pending. Calling `openWindow` or `respondWith` when the event is not trusted.
    * **Type Errors:** Passing an invalid URL to `openWindow`.
    * **Syntax Errors:** Providing a null shipping address to `changeShippingAddress` or an invalid `shipping_option_id`.
    * **Security Errors:** Trying to open a window to a different origin.

8. **Trace User Actions:**  Think about the steps a user takes that eventually trigger the code in this file:
    * User interacts with a website (clicks a "Pay" button, for example).
    * JavaScript on the page initiates a `PaymentRequest` object.
    * The browser dispatches a `paymentrequest` event to a registered service worker (if present).
    * The service worker's event listener receives the `PaymentRequestEvent`.
    * The code in this file within the service worker handles this event, potentially calling methods like `openWindow`, `changeShippingAddress`, or `respondWith`.

9. **Structure the Response:** Organize the findings into clear sections: Functionality, Relationship to Web Technologies, Logical Reasoning, Usage Errors, and User Operation Trace. Use bullet points and examples to make the information easy to understand. Use code snippets where appropriate to illustrate points.

10. **Review and Refine:**  Read through the generated response to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For example, initially, I might not have explicitly mentioned the service worker involvement, but recognizing the headers related to service workers prompts me to include that crucial piece of the puzzle.
好的，这是一份对 `blink/renderer/modules/payments/payment_request_event.cc` 文件功能的详细分析：

**文件功能：**

`PaymentRequestEvent.cc` 文件定义了 `PaymentRequestEvent` 类，该类是 Blink 渲染引擎中处理支付请求事件的核心组件。它的主要功能是：

1. **表示支付请求事件：**  `PaymentRequestEvent` 对象封装了当网站发起支付请求时所产生的所有相关信息。这些信息包括：
    * **请求来源：**  `topOrigin_` (顶级页面的 origin) 和 `payment_request_origin_` (发起支付请求的页面的 origin)。
    * **请求标识符：** `payment_request_id_`，用于唯一标识一个支付请求。
    * **支付方法数据：** `method_data_`，包含了网站支持的支付方式（例如，信用卡、Google Pay 等）以及这些支付方式的特定数据。
    * **总金额：** `total_`，表示需要支付的总金额和货币类型。
    * **支付详情修改器：** `modifiers_`，允许网站根据特定条件（如支付方式、送货地址）修改支付详情（例如，添加服务费）。
    * **支付工具密钥：** `instrument_key_`，用于标识特定的支付工具。
    * **支付选项：** `payment_options_`，包含了请求支付的一些选项，例如是否需要送货地址、是否需要联系方式等。
    * **送货选项：** `shipping_options_`，如果需要送货，则包含可用的送货方式和价格。
2. **提供与支付处理程序交互的能力：**  `PaymentRequestEvent` 类提供了与支付处理程序（通常是一个 Service Worker）进行交互的方法：
    * **`openWindow(url)`:** 允许支付处理程序打开一个新的窗口，通常用于显示支付授权界面。
    * **`changePaymentMethod(method_name, method_details)`:** 允许支付处理程序通知浏览器支付方式已更改，并提供新的支付方式详情。浏览器会根据此更新支付请求的信息。
    * **`changeShippingAddress(shipping_address)`:** 允许支付处理程序通知浏览器送货地址已更改，浏览器会根据新的送货地址更新支付请求的信息（例如，计算新的运费）。
    * **`changeShippingOption(shipping_option_id)`:** 允许支付处理程序通知浏览器用户选择了特定的送货方式。
    * **`respondWith(payment_handler_response_promise)`:** 允许支付处理程序使用一个 `PaymentHandlerResponse` 对象来响应支付请求，最终完成或拒绝支付。
3. **管理异步操作：** 上述的交互方法通常是异步的，因此 `PaymentRequestEvent` 使用 `ScriptPromise` 来处理这些操作的结果。例如，`changePaymentMethod` 返回一个 Promise，该 Promise 会在浏览器完成支付详情更新后 resolve。
4. **处理生命周期：**  `PaymentRequestEvent` 继承自 `ExtendableEvent`，这意味着它可以被 Service Worker 拦截并使用 `waitUntil()` 方法来延长事件的生命周期，直到一些异步操作完成。

**与 JavaScript, HTML, CSS 的关系：**

`PaymentRequestEvent` 是 Web Payments API 的一部分，它在 JavaScript 中被创建和使用，并与 HTML 页面和 CSS 样式间接相关。

* **JavaScript:**
    * **事件触发：** 当网页的 JavaScript 代码调用 `PaymentRequest` 接口发起支付请求时，浏览器会创建一个 `PaymentRequestEvent` 对象，并将其派发给注册了 `paymentrequest` 事件监听器的 Service Worker。
    * **事件处理：** Service Worker 中的 JavaScript 代码会监听 `paymentrequest` 事件，并获取 `PaymentRequestEvent` 对象。通过这个对象，Service Worker 可以访问支付请求的详细信息（例如 `event.total`, `event.methodData`）。
    * **API 调用：** Service Worker 的 JavaScript 代码可以使用 `PaymentRequestEvent` 对象提供的方法（例如 `event.openWindow()`, `event.changeShippingAddress()`, `event.respondWith()`）与浏览器进行交互，完成支付流程。

    **举例说明：**

    ```javascript
    // 在 Service Worker 中监听 paymentrequest 事件
    self.addEventListener('paymentrequest', async (event) => {
      console.log('收到支付请求事件', event);
      console.log('支付总额:', event.total.amount.value);

      // 假设用户选择了 "basic-card" 支付方式
      if (event.methodData.some(method => method.supportedMethods === 'basic-card')) {
        // ... 获取用户信用卡信息 ...
        const response = {
          methodName: 'basic-card',
          details: {
            cardNumber: '...',
            expiryMonth: '...',
            expiryYear: '...',
            cvv: '...'
          }
        };
        event.respondWith(Promise.resolve(response));
      } else {
        event.respondWith(Promise.reject('不支持的支付方式'));
      }
    });
    ```

* **HTML:**
    * **发起支付：** HTML 页面上的按钮或其他交互元素通常会触发 JavaScript 代码来创建和显示 `PaymentRequest` 对象。用户在 HTML 页面上的操作（例如点击支付按钮）是触发支付流程的起点。

    **举例说明：**

    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>支付页面</title>
    </head>
    <body>
      <button id="payButton">立即支付</button>
      <script>
        const payButton = document.getElementById('payButton');
        payButton.addEventListener('click', async () => {
          const supportedPaymentMethods = [
            {
              supportedMethods: "basic-card",
              data: {
                supportedCardNetworks: ["visa", "mastercard"]
              }
            }
          ];
          const paymentDetails = {
            total: {
              label: "总计",
              amount: { currency: "USD", value: "10.00" }
            }
          };
          const request = new PaymentRequest(supportedPaymentMethods, paymentDetails);
          try {
            const result = await request.show();
            console.log('支付成功', result);
          } catch (error) {
            console.error('支付失败', error);
          }
        });
      </script>
    </body>
    </html>
    ```

* **CSS:**
    * **样式呈现：** CSS 用于控制网页上元素的外观，包括触发支付请求的按钮和可能由支付处理程序打开的支付授权窗口的样式。虽然 `PaymentRequestEvent.cc` 本身不直接处理 CSS，但它所涉及的支付流程最终会通过用户界面呈现给用户，而用户界面的样式由 CSS 定义。

**逻辑推理、假设输入与输出：**

**假设输入：**  一个网站发起了一个支付请求，指定了 "basic-card" 和 "google-pay" 两种支付方式，总金额为 10 美元。Service Worker 拦截了这个 `PaymentRequestEvent`。

```javascript
// PaymentRequestEvent 对象的部分信息
{
  type: "paymentrequest",
  topOrigin: "https://example.com",
  paymentRequestOrigin: "https://example.com",
  paymentRequestId: "unique-request-id",
  methodData: [
    { supportedMethods: "basic-card", data: { supportedCardNetworks: ["visa", "mastercard"] } },
    { supportedMethods: "https://google.com/pay", data: { /* Google Pay specific data */ } }
  ],
  total: { label: "总计", amount: { currency: "USD", value: "10.00" } }
  // ... 其他属性
}
```

**逻辑推理：**

1. Service Worker 的 `paymentrequest` 事件监听器接收到这个 `PaymentRequestEvent`。
2. Service Worker 的代码可能会检查 `event.methodData` 来确定可用的支付方式。
3. 如果 Service Worker 需要额外的用户授权，它可能会调用 `event.openWindow('https://payment-handler.example.com/authorize')` 打开一个新的窗口。
4. 如果用户更改了送货地址，Service Worker 可能会调用 `event.changeShippingAddress({ /* 新的地址信息 */ })`。
5. 最终，当用户完成支付授权后，Service Worker 会构建一个 `PaymentHandlerResponse` 对象，并通过 `event.respondWith(Promise.resolve(response))` 将其发送回浏览器。

**假设输出（成功支付）：**

```javascript
// PaymentHandlerResponse 对象
const response = {
  methodName: "basic-card", // 用户选择的支付方式
  details: {
    cardNumber: "************1234",
    cardholderName: "John Doe",
    expiryMonth: "12",
    expiryYear: "2024",
    // ... 其他支付详情
  }
};
```

**假设输出（支付失败）：**

```javascript
// PaymentHandlerResponse 对象，指示支付失败
const response = {
  methodName: "basic-card",
  details: {}, // 可以为空
  error: "支付被拒绝，余额不足"
};
event.respondWith(Promise.resolve(response));
```

**用户或编程常见的使用错误：**

1. **Service Worker 未正确注册或作用域不正确：** 如果 Service Worker 没有正确注册或者其作用域不包含发起支付请求的页面，那么 `paymentrequest` 事件将不会被拦截，支付流程将无法正常工作。

    **举例：**  Service Worker 的脚本位于 `/sw.js`，但支付请求是从 `https://example.com/checkout` 发起的，如果 Service Worker 的作用域被设置为 `/`，则该事件可以被拦截。但如果作用域被限制为 `/payment/`，则事件不会被拦截。

2. **在 `respondWith` 中传递非 Promise 对象或 rejected 的 Promise：** `respondWith` 方法期望接收一个 resolve 的 Promise，其值是 `PaymentHandlerResponse` 对象。传递非 Promise 对象或 rejected 的 Promise 会导致支付流程异常。

    **举例：**

    ```javascript
    // 错误示例：传递非 Promise 对象
    event.respondWith({ methodName: 'basic-card', details: {} });

    // 错误示例：传递 rejected 的 Promise
    event.respondWith(Promise.reject('支付处理出错'));
    ```

3. **在 `paymentrequest` 事件处理程序中没有调用 `respondWith`：** 如果在 `paymentrequest` 事件处理程序的生命周期内没有调用 `respondWith` 方法，浏览器会认为支付处理程序没有响应，最终可能导致支付超时或失败。

4. **尝试在 `respondWith` 之后再次调用 `respondWith` 或调用其他修改支付状态的方法：** 一旦调用了 `respondWith`，就不能再更改支付请求的状态或再次尝试响应。

5. **在不信任的事件中调用 `openWindow` 或 `respondWith`：**  出于安全考虑，只有当事件是受信任的（例如，由浏览器直接派发）时，才能调用 `openWindow` 和 `respondWith` 方法。

    **举例：**  如果通过 `dispatchEvent` 手动创建一个 `PaymentRequestEvent` 并尝试调用这些方法，将会抛出异常。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户访问网页并添加到购物车/进入结算页面：** 用户在电商网站等进行浏览，并将商品添加到购物车，最终点击 "去结算" 或类似的按钮。
2. **网页 JavaScript 发起支付请求：** 网页的 JavaScript 代码调用 `new PaymentRequest(supportedPaymentMethods, paymentDetails, paymentOptions)` 创建一个支付请求对象，并调用 `request.show()` 方法来启动支付流程。
3. **浏览器查找并激活相关的 Service Worker：** 浏览器根据当前页面的作用域查找已注册的 Service Worker。如果 Service Worker 尚未激活，浏览器会先激活它。
4. **浏览器派发 `paymentrequest` 事件到 Service Worker：**  一旦 Service Worker 处于活动状态，浏览器会创建一个 `PaymentRequestEvent` 对象，并将该事件派发到 Service Worker 的 `paymentrequest` 事件监听器。
5. **Service Worker 的事件监听器被调用：** `PaymentRequestEvent.cc` 中定义的 `PaymentRequestEvent` 对象会被传递给 Service Worker 中注册的 `paymentrequest` 事件处理函数。
6. **Service Worker 处理支付请求：**  Service Worker 的 JavaScript 代码会接收到 `PaymentRequestEvent` 对象，并可以访问其属性（例如 `event.total`）并调用其方法（例如 `event.respondWith()`）。
7. **Service Worker 与支付处理程序交互（可能）：** Service Worker 可能会与第三方的支付处理程序进行通信，获取支付凭证等信息。
8. **Service Worker 调用 `event.respondWith()`：**  Service Worker 使用 `event.respondWith()` 方法将支付结果返回给浏览器。

**调试线索：**

* **在 Service Worker 中添加 `console.log`：** 在 Service Worker 的 `paymentrequest` 事件监听器中添加日志，可以查看 `PaymentRequestEvent` 对象的属性值，以及 Service Worker 的处理逻辑是否按预期执行。
* **使用 Chrome DevTools 的 Service Worker 面板：**  可以查看 Service Worker 的状态、网络请求、控制台输出等信息，帮助理解支付流程中 Service Worker 的行为。
* **断点调试 Service Worker 代码：**  在 Chrome DevTools 的 Sources 面板中，可以为 Service Worker 的代码设置断点，逐步执行代码，查看变量的值，帮助定位问题。
* **检查 `navigator.serviceWorker.controller`：**  在发起支付请求的页面上，可以检查 `navigator.serviceWorker.controller` 是否存在且处于活动状态，以确认 Service Worker 是否正常控制了页面。
* **查看浏览器的 Payment Request API 日志：**  在 Chrome 中，可以通过 `chrome://payments-internals/` 查看 Payment Request API 的内部日志，了解支付请求的详细过程和可能出现的错误。
* **网络请求分析：**  使用 Chrome DevTools 的 Network 面板，可以查看支付流程中发出的网络请求，例如与支付处理程序的通信，是否有异常或错误。

总而言之，`PaymentRequestEvent.cc` 文件是 Blink 渲染引擎中处理支付请求事件的关键部分，它连接了网页的支付请求和支付处理程序，并提供了必要的接口来实现安全的、用户友好的在线支付体验。理解其功能和交互方式对于开发和调试 Web Payments API 相关的功能至关重要。

### 提示词
```
这是目录为blink/renderer/modules/payments/payment_request_event.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/payments/payment_request_event.h"

#include <utility>

#include "third_party/blink/public/mojom/payments/payment_request.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_address_errors.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_currency_amount.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_details_modifier.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_handler_response.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_item.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_method_data.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_request_details_update.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_payment_shipping_option.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/core/workers/worker_location.h"
#include "third_party/blink/renderer/modules/payments/address_init_type_converter.h"
#include "third_party/blink/renderer/modules/payments/payment_request_respond_with_observer.h"
#include "third_party/blink/renderer/modules/payments/payments_validators.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_global_scope.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_window_client.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"

namespace blink {

class PaymentRequestRespondWithFulfill final
    : public ThenCallable<PaymentHandlerResponse,
                          PaymentRequestRespondWithFulfill> {
 public:
  explicit PaymentRequestRespondWithFulfill(
      PaymentRequestRespondWithObserver* observer)
      : observer_(observer) {}

  void Trace(Visitor* visitor) const override {
    visitor->Trace(observer_);
    ThenCallable<PaymentHandlerResponse,
                 PaymentRequestRespondWithFulfill>::Trace(visitor);
  }

  void React(ScriptState* script_state, PaymentHandlerResponse* response) {
    DCHECK(observer_);
    observer_->OnResponseFulfilled(script_state, response);
  }

 private:
  Member<PaymentRequestRespondWithObserver> observer_;
};

PaymentRequestEvent* PaymentRequestEvent::Create(
    const AtomicString& type,
    const PaymentRequestEventInit* initializer,
    mojo::PendingRemote<payments::mojom::blink::PaymentHandlerHost> host,
    PaymentRequestRespondWithObserver* respond_with_observer,
    WaitUntilObserver* wait_until_observer,
    ExecutionContext* execution_context) {
  return MakeGarbageCollected<PaymentRequestEvent>(
      type, initializer, std::move(host), respond_with_observer,
      wait_until_observer, execution_context);
}

// TODO(crbug.com/1070871): Use fooOr() in members' initializers.
PaymentRequestEvent::PaymentRequestEvent(
    const AtomicString& type,
    const PaymentRequestEventInit* initializer,
    mojo::PendingRemote<payments::mojom::blink::PaymentHandlerHost> host,
    PaymentRequestRespondWithObserver* respond_with_observer,
    WaitUntilObserver* wait_until_observer,
    ExecutionContext* execution_context)
    : ExtendableEvent(type, initializer, wait_until_observer),
      top_origin_(initializer->hasTopOrigin() ? initializer->topOrigin()
                                              : String()),
      payment_request_origin_(initializer->hasPaymentRequestOrigin()
                                  ? initializer->paymentRequestOrigin()
                                  : String()),
      payment_request_id_(initializer->hasPaymentRequestId()
                              ? initializer->paymentRequestId()
                              : String()),
      method_data_(initializer->hasMethodData()
                       ? initializer->methodData()
                       : HeapVector<Member<PaymentMethodData>>()),
      total_(initializer->hasTotal() ? initializer->total()
                                     : PaymentCurrencyAmount::Create()),
      modifiers_(initializer->hasModifiers()
                     ? initializer->modifiers()
                     : HeapVector<Member<PaymentDetailsModifier>>()),
      instrument_key_(initializer->hasInstrumentKey()
                          ? initializer->instrumentKey()
                          : String()),
      payment_options_(initializer->hasPaymentOptions()
                           ? initializer->paymentOptions()
                           : PaymentOptions::Create()),
      shipping_options_(initializer->hasShippingOptions()
                            ? initializer->shippingOptions()
                            : HeapVector<Member<PaymentShippingOption>>()),
      observer_(respond_with_observer),
      payment_handler_host_(execution_context) {
  if (!host.is_valid())
    return;

  if (execution_context) {
    payment_handler_host_.Bind(
        std::move(host),
        execution_context->GetTaskRunner(TaskType::kMiscPlatformAPI));
    payment_handler_host_.set_disconnect_handler(WTF::BindOnce(
        &PaymentRequestEvent::OnHostConnectionError, WrapWeakPersistent(this)));
  }
}

PaymentRequestEvent::~PaymentRequestEvent() = default;

const AtomicString& PaymentRequestEvent::InterfaceName() const {
  return event_interface_names::kPaymentRequestEvent;
}

const String& PaymentRequestEvent::topOrigin() const {
  return top_origin_;
}

const String& PaymentRequestEvent::paymentRequestOrigin() const {
  return payment_request_origin_;
}

const String& PaymentRequestEvent::paymentRequestId() const {
  return payment_request_id_;
}

const HeapVector<Member<PaymentMethodData>>& PaymentRequestEvent::methodData()
    const {
  return method_data_;
}

const ScriptValue PaymentRequestEvent::total(ScriptState* script_state) const {
  return ScriptValue::From(script_state, total_.Get());
}

const HeapVector<Member<PaymentDetailsModifier>>&
PaymentRequestEvent::modifiers() const {
  return modifiers_;
}

const String& PaymentRequestEvent::instrumentKey() const {
  return instrument_key_;
}

const ScriptValue PaymentRequestEvent::paymentOptions(
    ScriptState* script_state) const {
  if (!payment_options_)
    return ScriptValue::CreateNull(script_state->GetIsolate());
  return ScriptValue::From(script_state, payment_options_.Get());
}

std::optional<HeapVector<Member<PaymentShippingOption>>>
PaymentRequestEvent::shippingOptions() const {
  if (shipping_options_.empty())
    return std::nullopt;
  return shipping_options_;
}

ScriptPromise<IDLNullable<ServiceWorkerWindowClient>>
PaymentRequestEvent::openWindow(ScriptState* script_state, const String& url) {
  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLNullable<ServiceWorkerWindowClient>>>(
      script_state);
  auto promise = resolver->Promise();
  ExecutionContext* context = ExecutionContext::From(script_state);

  if (!isTrusted()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError,
        "Cannot open a window when the event is not trusted"));
    return promise;
  }

  KURL parsed_url_to_open = context->CompleteURL(url);
  if (!parsed_url_to_open.IsValid()) {
    resolver->Reject(V8ThrowException::CreateTypeError(
        script_state->GetIsolate(), "'" + url + "' is not a valid URL."));
    return promise;
  }

  if (!context->GetSecurityOrigin()->IsSameOriginWith(
          SecurityOrigin::Create(parsed_url_to_open).get())) {
    resolver->Resolve(nullptr);
    return promise;
  }

  if (!context->IsWindowInteractionAllowed()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotAllowedError,
        "Not allowed to open a window without user activation"));
    return promise;
  }
  context->ConsumeWindowInteraction();

  To<ServiceWorkerGlobalScope>(context)
      ->GetServiceWorkerHost()
      ->OpenPaymentHandlerWindow(
          parsed_url_to_open,
          ServiceWorkerWindowClient::CreateResolveWindowClientCallback(
              resolver));
  return promise;
}

ScriptPromise<IDLNullable<PaymentRequestDetailsUpdate>>
PaymentRequestEvent::changePaymentMethod(ScriptState* script_state,
                                         const String& method_name,
                                         const ScriptValue& method_details,
                                         ExceptionState& exception_state) {
  if (change_payment_request_details_resolver_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Waiting for response to the previous "
                                      "payment request details change");
    return ScriptPromise<IDLNullable<PaymentRequestDetailsUpdate>>();
  }

  if (!payment_handler_host_.is_bound()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "No corresponding PaymentRequest object found");
    return ScriptPromise<IDLNullable<PaymentRequestDetailsUpdate>>();
  }

  auto method_data = payments::mojom::blink::PaymentHandlerMethodData::New();
  if (!method_details.IsNull()) {
    DCHECK(!method_details.IsEmpty());
    PaymentsValidators::ValidateAndStringifyObject(
        script_state->GetIsolate(), method_details,
        method_data->stringified_data, exception_state);
    if (exception_state.HadException())
      return ScriptPromise<IDLNullable<PaymentRequestDetailsUpdate>>();
  }

  method_data->method_name = method_name;
  payment_handler_host_->ChangePaymentMethod(
      std::move(method_data),
      WTF::BindOnce(&PaymentRequestEvent::OnChangePaymentRequestDetailsResponse,
                    WrapWeakPersistent(this)));
  change_payment_request_details_resolver_ = MakeGarbageCollected<
      ScriptPromiseResolver<IDLNullable<PaymentRequestDetailsUpdate>>>(
      script_state);
  return change_payment_request_details_resolver_->Promise();
}

ScriptPromise<IDLNullable<PaymentRequestDetailsUpdate>>
PaymentRequestEvent::changeShippingAddress(ScriptState* script_state,
                                           AddressInit* shipping_address,
                                           ExceptionState& exception_state) {
  if (change_payment_request_details_resolver_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Waiting for response to the previous "
                                      "payment request details change");
    return ScriptPromise<IDLNullable<PaymentRequestDetailsUpdate>>();
  }

  if (!payment_handler_host_.is_bound()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "No corresponding PaymentRequest object found");
    return ScriptPromise<IDLNullable<PaymentRequestDetailsUpdate>>();
  }
  if (!shipping_address) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "Shipping address cannot be null");
    return ScriptPromise<IDLNullable<PaymentRequestDetailsUpdate>>();
  }

  auto shipping_address_ptr =
      payments::mojom::blink::PaymentAddress::From(shipping_address);
  String shipping_address_error;
  if (!PaymentsValidators::IsValidShippingAddress(script_state->GetIsolate(),
                                                  shipping_address_ptr,
                                                  &shipping_address_error)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      shipping_address_error);
    return ScriptPromise<IDLNullable<PaymentRequestDetailsUpdate>>();
  }

  payment_handler_host_->ChangeShippingAddress(
      std::move(shipping_address_ptr),
      WTF::BindOnce(&PaymentRequestEvent::OnChangePaymentRequestDetailsResponse,
                    WrapWeakPersistent(this)));
  change_payment_request_details_resolver_ = MakeGarbageCollected<
      ScriptPromiseResolver<IDLNullable<PaymentRequestDetailsUpdate>>>(
      script_state);
  return change_payment_request_details_resolver_->Promise();
}

ScriptPromise<IDLNullable<PaymentRequestDetailsUpdate>>
PaymentRequestEvent::changeShippingOption(ScriptState* script_state,
                                          const String& shipping_option_id,
                                          ExceptionState& exception_state) {
  if (change_payment_request_details_resolver_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Waiting for response to the previous payment request details change");
    return ScriptPromise<IDLNullable<PaymentRequestDetailsUpdate>>();
  }

  if (!payment_handler_host_.is_bound()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "No corresponding PaymentRequest object found");
    return ScriptPromise<IDLNullable<PaymentRequestDetailsUpdate>>();
  }

  bool shipping_option_id_is_valid = false;
  for (const auto& option : shipping_options_) {
    if (option->id() == shipping_option_id) {
      shipping_option_id_is_valid = true;
      break;
    }
  }
  if (!shipping_option_id_is_valid) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "Shipping option identifier is invalid");
    return ScriptPromise<IDLNullable<PaymentRequestDetailsUpdate>>();
  }

  payment_handler_host_->ChangeShippingOption(
      shipping_option_id,
      WTF::BindOnce(&PaymentRequestEvent::OnChangePaymentRequestDetailsResponse,
                    WrapWeakPersistent(this)));
  change_payment_request_details_resolver_ = MakeGarbageCollected<
      ScriptPromiseResolver<IDLNullable<PaymentRequestDetailsUpdate>>>(
      script_state);
  return change_payment_request_details_resolver_->Promise();
}

void PaymentRequestEvent::respondWith(
    ScriptState* script_state,
    ScriptPromise<PaymentHandlerResponse> script_promise,
    ExceptionState& exception_state) {
  if (!isTrusted()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Cannot respond with data when the event is not trusted");
    return;
  }

  stopImmediatePropagation();
  if (observer_) {
    observer_->RespondWith(
        script_state, script_promise,
        MakeGarbageCollected<PaymentRequestRespondWithFulfill>(observer_),
        exception_state);
  }
}

void PaymentRequestEvent::Trace(Visitor* visitor) const {
  visitor->Trace(method_data_);
  visitor->Trace(total_);
  visitor->Trace(modifiers_);
  visitor->Trace(payment_options_);
  visitor->Trace(shipping_options_);
  visitor->Trace(change_payment_request_details_resolver_);
  visitor->Trace(observer_);
  visitor->Trace(payment_handler_host_);
  ExtendableEvent::Trace(visitor);
}

void PaymentRequestEvent::OnChangePaymentRequestDetailsResponse(
    payments::mojom::blink::PaymentRequestDetailsUpdatePtr response) {
  if (!change_payment_request_details_resolver_)
    return;

  auto* dictionary = MakeGarbageCollected<PaymentRequestDetailsUpdate>();
  if (!response->error.IsNull() && !response->error.empty()) {
    dictionary->setError(response->error);
  }

  if (response->total) {
    auto* total = MakeGarbageCollected<PaymentCurrencyAmount>();
    total->setCurrency(response->total->currency);
    total->setValue(response->total->value);
    dictionary->setTotal(total);
  }

  ScriptState* script_state =
      change_payment_request_details_resolver_->GetScriptState();
  ScriptState::Scope scope(script_state);

  if (response->modifiers) {
    HeapVector<Member<PaymentDetailsModifier>> modifiers;
    for (const auto& response_modifier : *response->modifiers) {
      if (!response_modifier)
        continue;

      auto* mod = MakeGarbageCollected<PaymentDetailsModifier>();
      mod->setSupportedMethod(response_modifier->method_data->method_name);

      if (response_modifier->total) {
        auto* amount = MakeGarbageCollected<PaymentCurrencyAmount>();
        amount->setCurrency(response_modifier->total->currency);
        amount->setValue(response_modifier->total->value);
        auto* total = MakeGarbageCollected<PaymentItem>();
        total->setAmount(amount);
        total->setLabel("");
        mod->setTotal(total);
      }

      if (!response_modifier->method_data->stringified_data.empty()) {
        v8::TryCatch try_catch(script_state->GetIsolate());
        v8::Local<v8::Value> parsed_value = FromJSONString(
            script_state, response_modifier->method_data->stringified_data);
        if (try_catch.HasCaught()) {
          change_payment_request_details_resolver_->Reject(
              try_catch.Exception());
          change_payment_request_details_resolver_.Clear();
          return;
        }
        mod->setData(ScriptValue(script_state->GetIsolate(), parsed_value));
        modifiers.emplace_back(mod);
      }
    }
    dictionary->setModifiers(modifiers);
  }

  if (response->shipping_options) {
    HeapVector<Member<PaymentShippingOption>> shipping_options;
    for (const auto& response_shipping_option : *response->shipping_options) {
      if (!response_shipping_option)
        continue;

      auto* shipping_option = MakeGarbageCollected<PaymentShippingOption>();
      auto* amount = MakeGarbageCollected<PaymentCurrencyAmount>();
      amount->setCurrency(response_shipping_option->amount->currency);
      amount->setValue(response_shipping_option->amount->value);
      shipping_option->setAmount(amount);
      shipping_option->setId(response_shipping_option->id);
      shipping_option->setLabel(response_shipping_option->label);
      shipping_option->setSelected(response_shipping_option->selected);
      shipping_options.emplace_back(shipping_option);
    }
    dictionary->setShippingOptions(shipping_options);
  }

  if (response->stringified_payment_method_errors &&
      !response->stringified_payment_method_errors.empty()) {
    v8::TryCatch try_catch(script_state->GetIsolate());
    v8::Local<v8::Value> parsed_value = FromJSONString(
        script_state, response->stringified_payment_method_errors);
    if (try_catch.HasCaught()) {
      change_payment_request_details_resolver_->Reject(try_catch.Exception());
      change_payment_request_details_resolver_.Clear();
      return;
    }
    dictionary->setPaymentMethodErrors(
        ScriptValue(script_state->GetIsolate(), parsed_value));
  }

  if (response->shipping_address_errors) {
    auto* shipping_address_errors = MakeGarbageCollected<AddressErrors>();
    shipping_address_errors->setAddressLine(
        response->shipping_address_errors->address_line);
    shipping_address_errors->setCity(response->shipping_address_errors->city);
    shipping_address_errors->setCountry(
        response->shipping_address_errors->country);
    shipping_address_errors->setDependentLocality(
        response->shipping_address_errors->dependent_locality);
    shipping_address_errors->setOrganization(
        response->shipping_address_errors->organization);
    shipping_address_errors->setPhone(response->shipping_address_errors->phone);
    shipping_address_errors->setPostalCode(
        response->shipping_address_errors->postal_code);
    shipping_address_errors->setRecipient(
        response->shipping_address_errors->recipient);
    shipping_address_errors->setRegion(
        response->shipping_address_errors->region);
    shipping_address_errors->setSortingCode(
        response->shipping_address_errors->sorting_code);
    dictionary->setShippingAddressErrors(shipping_address_errors);
  }

  change_payment_request_details_resolver_->Resolve(
      dictionary->hasError() || dictionary->hasTotal() ||
              dictionary->hasModifiers() ||
              dictionary->hasPaymentMethodErrors() ||
              dictionary->hasShippingOptions() ||
              dictionary->hasShippingAddressErrors()
          ? dictionary
          : nullptr);
  change_payment_request_details_resolver_.Clear();
}

void PaymentRequestEvent::OnHostConnectionError() {
  if (change_payment_request_details_resolver_) {
    change_payment_request_details_resolver_->Reject(
        MakeGarbageCollected<DOMException>(DOMExceptionCode::kAbortError,
                                           "Browser process disconnected"));
  }
  change_payment_request_details_resolver_.Clear();
  payment_handler_host_.reset();
}

}  // namespace blink
```