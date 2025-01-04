Response:
The user wants me to summarize the functionality of the provided C++ code snippet from `payment_request.cc`. This is the second part of a three-part file. I need to focus on the functions defined within this specific section and their roles in the payment request lifecycle. I also need to identify connections to JavaScript, HTML, and CSS, provide examples, and discuss potential user/developer errors. Finally, I need to describe how a user's interaction might lead to the execution of this code.

**Plan:**

1. **Identify Key Functions:** Read through the code and list the main functions defined in this section.
2. **Summarize Functionality:** Briefly describe what each key function does within the PaymentRequest lifecycle.
3. **JavaScript/HTML/CSS Relationship:**  Analyze how these C++ functions interact with the JavaScript PaymentRequest API, potentially affecting the rendering or behavior in the browser (although the direct influence on CSS is likely minimal).
4. **Examples:** Provide concrete examples of how JavaScript calls these C++ functions and the expected outcomes.
5. **Logic and Assumptions:** If any logical deductions or assumptions are made within the functions, highlight them. For example, the quota mechanism and its exceptions for localhost.
6. **User/Developer Errors:**  Point out common mistakes a developer might make when using the PaymentRequest API that would trigger error handling within this C++ code.
7. **User Interaction to Code Execution:**  Describe the sequence of user actions on a webpage that would lead to the invocation of these C++ functions in the browser.
目录为 `blink/renderer/modules/payments/payment_request.cc` 的 Chromium Blink 引擎源代码文件，这是第 2 部分，它主要负责实现 `PaymentRequest` 接口的核心功能，包括启动支付流程、处理支付详情更新、中止支付、查询支付能力等。

**功能归纳:**

这部分代码主要实现了 `PaymentRequest` 类的以下核心功能：

1. **`show()` 方法的实现:**
    *   处理 JavaScript 中调用 `paymentRequest.show()` 启动支付流程的请求。
    *   检查当前状态是否允许发起支付（例如，是否已经调用过 `show()`）。
    *   处理用户激活状态（是否有用户手势或委托激活）。
    *   通过 `payment_provider_` 发送 `Show` 请求到浏览器进程。
    *   处理带有 `detailsPromise` 的 `show()` 调用，并在超时或 Promise resolve/reject 时更新支付详情。
    *   创建并返回一个 `Promise`，该 Promise 将在支付流程完成时 resolve 或 reject。

2. **`abort()` 方法的实现:**
    *   处理 JavaScript 中调用 `paymentRequest.abort()` 中止支付流程的请求。
    *   检查当前状态是否允许中止（例如，是否有正在进行的 `show()` 或 `retry()`）。
    *   通过 `payment_provider_` 发送 `Abort` 请求到浏览器进程。
    *   创建并返回一个 `Promise`，该 Promise 将在中止操作完成时 resolve 或 reject。

3. **`canMakePayment()` 方法的实现:**
    *   处理 JavaScript 中调用 `paymentRequest.canMakePayment()` 查询用户是否可以进行支付的请求。
    *   检查当前状态是否允许查询。
    *   通过 `payment_provider_` 发送 `CanMakePayment` 请求到浏览器进程。
    *   创建并返回一个 `Promise`，该 Promise 将在收到查询结果时 resolve。

4. **`hasEnrolledInstrument()` 方法的实现:**
    *   处理 JavaScript 中调用 `paymentRequest.hasEnrolledInstrument()` 查询用户是否已注册支付工具的请求。
    *   检查当前状态是否允许查询。
    *   通过 `payment_provider_` 发送 `HasEnrolledInstrument` 请求到浏览器进程。
    *   创建并返回一个 `Promise`，该 Promise 将在收到查询结果时 resolve。

5. **`Retry()` 方法的实现:**
    *   处理 JavaScript 中调用 `paymentRequest.retry()`，当支付失败时，提供新的支付验证错误信息并重新尝试支付。
    *   检查当前状态是否允许重试。
    *   验证传入的支付验证错误信息格式。
    *   向开发者发出关于 `requestPayerName`, `requestPayerEmail`, `requestPayerPhone`, `requestShipping` 和 `errors` 对象之间不一致的警告信息。
    *   通过 `payment_provider_` 发送带有错误信息的 `Retry` 请求到浏览器进程。
    *   创建并返回一个 `Promise`，该 Promise 将在收到支付响应时 resolve。

6. **`Complete()` 方法的实现:**
    *   处理 JavaScript 中调用 `paymentRequest.complete()`，告知浏览器支付流程已完成（成功或失败）。
    *   检查当前状态是否允许完成。
    *   检查是否在超时时间内调用。
    *   通过 `payment_provider_` 发送 `Complete` 请求到浏览器进程。
    *   创建并返回一个 `Promise`，该 Promise 将在操作完成时 resolve。

7. **处理来自浏览器进程的异步回调:**
    *   `OnUpdatePaymentDetails()`:  接收并处理来自浏览器进程的支付详情更新信息，通常是响应 `paymentmethodchange` 或 `shippingaddresschange` 事件。
    *   `OnUpdatePaymentDetailsFailure()`:  处理支付详情更新失败的情况。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **JavaScript:** 这个 C++ 文件直接实现了 JavaScript `PaymentRequest` API 的底层逻辑。JavaScript 代码通过调用 `paymentRequest` 对象的方法（如 `show()`, `abort()`, `canMakePayment()`, `retry()`, `complete()`）来触发这里定义的 C++ 代码执行。

    *   **例子:**  当 JavaScript 代码执行 `paymentRequest.show()` 时，就会调用 C++ 中的 `PaymentRequest::show()` 方法。

    ```javascript
    const paymentRequest = new PaymentRequest(methodData, details, options);
    paymentRequest.show()
      .then(paymentResponse => {
        // 处理支付成功的情况
        paymentResponse.complete('success');
      })
      .catch(error => {
        // 处理支付失败的情况
        console.error('Payment failed:', error);
      });
    ```

*   **HTML:** HTML 定义了网页的结构，其中可能包含触发支付请求的按钮或其他交互元素。用户的操作（如点击按钮）会触发 JavaScript 代码，进而调用 `PaymentRequest` API。

    *   **例子:** 一个 HTML 按钮的 `onclick` 事件处理器中调用了 `paymentRequest.show()`。

    ```html
    <button id="payButton">Pay Now</button>
    <script>
      const payButton = document.getElementById('payButton');
      payButton.onclick = function() {
        // ... 初始化 paymentRequest ...
        paymentRequest.show();
      };
    </script>
    ```

*   **CSS:** CSS 主要负责网页的样式和布局，与 `payment_request.cc` 文件的功能没有直接关系。然而，CSS 可以影响触发支付请求的 HTML 元素的呈现方式。浏览器显示的支付界面（例如支付表单）的样式是由浏览器自身控制的，不受网页 CSS 的直接影响。

**逻辑推理及假设输入与输出:**

*   **假设输入:** JavaScript 调用 `paymentRequest.show()`，且 `detailsPromise` 不为空。
*   **逻辑推理:**  `is_waiting_for_show_promise_to_resolve_` 被设置为 `true`，一个定时器 `update_payment_details_timer_` 被启动，并且 `detailsPromise` 被附加了 resolve 和 reject 的回调函数 (`UpdatePaymentDetailsResolve` 和 `UpdatePaymentDetailsReject`)。
*   **输出:**  浏览器进程会显示支付界面，等待用户操作。同时，C++ 代码也在等待 `detailsPromise` 的结果。如果 `detailsPromise` 在 10 秒内 resolve，`OnUpdatePaymentDetails` 会被调用；如果 reject，`OnUpdatePaymentDetailsFailure` 会被调用；如果超时，`OnUpdatePaymentDetailsTimeout` 会被调用。

**用户或编程常见的使用错误及举例说明:**

1. **多次调用 `show()`:** 用户在同一个 `PaymentRequest` 实例上多次调用 `show()` 方法会导致 `InvalidStateError` 异常。

    ```javascript
    const paymentRequest = new PaymentRequest(methodData, details, options);
    paymentRequest.show();
    paymentRequest.show(); // 抛出 InvalidStateError
    ```

2. **在没有用户激活的情况下调用 `show()`:**  在某些情况下，浏览器要求调用 `show()` 必须在用户手势（如点击）的上下文中进行。否则，支付请求可能会被阻止或显示警告。

    ```javascript
    // 错误示例：在定时器中调用 show()，可能没有用户激活
    setTimeout(() => {
      paymentRequest.show(); // 可能被阻止或显示警告
    }, 1000);
    ```

3. **在 `complete()` 被调用后再次调用 `retry()` 或 `complete()`:**  一旦 `complete()` 被调用，支付流程已经结束，再次调用 `retry()` 或 `complete()` 会导致 `InvalidStateError` 异常。

    ```javascript
    paymentRequest.show()
      .then(paymentResponse => {
        paymentResponse.complete('success');
        paymentRequest.retry({}); // 抛出 InvalidStateError
      });
    ```

4. **在 `retry()` 仍在处理时调用另一个 `retry()`:**  在上次 `retry()` 的 Promise resolve 或 reject 之前再次调用 `retry()` 会导致 `InvalidStateError` 异常。

    ```javascript
    paymentRequest.show()
      .then(paymentResponse => {
        paymentRequest.retry({})
          .then(() => {
            console.log('Retry success');
          });
        paymentRequest.retry({}); // 抛出 InvalidStateError
      });
    ```

5. **在超过 60 秒后调用 `complete()`:** 如果在 `show()` Promise resolve 后 60 秒内没有调用 `complete()`，则会超时，此时再调用 `complete()` 会抛出 `InvalidStateError`。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户访问包含支付功能的网页:** 用户在浏览器中打开一个包含支付功能的网页。
2. **用户与网页交互:** 用户点击 "立即支付" 按钮或执行其他触发支付操作的动作。
3. **JavaScript 代码执行:**  用户的交互触发了网页上的 JavaScript 代码执行。
4. **创建 `PaymentRequest` 实例:** JavaScript 代码创建了一个 `PaymentRequest` 对象，并传入支付方式、支付详情和支付选项。这会调用 C++ 中的 `PaymentRequest::PaymentRequest()` 构造函数（在文件的其他部分）。
5. **调用 `paymentRequest.show()`:** JavaScript 代码调用了 `paymentRequest.show()` 方法，希望启动支付流程。
6. **进入 `PaymentRequest::show()`:** 此时，代码执行流程进入了 `blink/renderer/modules/payments/payment_request.cc` 文件的 `PaymentRequest::show()` 方法（本部分代码）。
7. **后续流程:**  `show()` 方法会进行各种检查，并通过 `payment_provider_` 与浏览器进程通信，最终显示支付界面。后续用户在支付界面上的操作（选择支付方式、确认支付等）以及网页 JavaScript 对支付事件的处理（如 `paymentmethodchange`, `shippingaddresschange`）都会触发 `payment_request.cc` 中的其他方法执行。

作为调试线索，如果开发者在 JavaScript 中调用 `paymentRequest.show()` 后遇到问题，他们可以：

*   **在 JavaScript 中设置断点:**  在调用 `show()` 的前后设置断点，检查 `PaymentRequest` 对象的状态和参数。
*   **在 C++ 代码中设置断点:** 在 `PaymentRequest::show()` 方法的开头设置断点，查看 C++ 层的执行流程和变量值，例如用户激活状态、是否已经调用过 `show()` 等。
*   **查看控制台输出:**  `RecordActivationlessShow` 函数中调用 `AddConsoleMessage` 可能会在控制台输出关于无用户激活调用 `show()` 的警告信息。
*   **检查网络请求:**  开发者工具的网络面板可以帮助查看浏览器与支付服务提供商之间的网络请求。
*   **利用 Chromium 的 tracing 工具:**  Chromium 提供了 tracing 工具，可以记录更底层的执行信息，帮助定位问题。

Prompt: 
```
这是目录为blink/renderer/modules/payments/payment_request.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
g& error = String::Format(
      "Quota reached for PaymentRequest.%s(). This would normally "
      "reject the promise, but allowing continued usage on localhost and "
      "file:// scheme origins.",
      method_name);
  execution_context.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kJavaScript,
      mojom::ConsoleMessageLevel::kWarning, error));
}

// Records metrics for an activationless Show() call based on the request
// method.
void RecordActivationlessShow(ExecutionContext* execution_context,
                              const HashSet<String>& method_names) {
  if (method_names.size() == 1 &&
      method_names.Contains(kSecurePaymentConfirmationMethod)) {
    UseCounter::Count(execution_context,
                      WebFeature::kSecurePaymentConfirmationActivationlessShow);
  } else {
    UseCounter::Count(execution_context,
                      WebFeature::kPaymentRequestActivationlessShow);
  }
}

}  // namespace

PaymentRequest* PaymentRequest::Create(
    ExecutionContext* execution_context,
    const HeapVector<Member<PaymentMethodData>>& method_data,
    const PaymentDetailsInit* details,
    ExceptionState& exception_state) {
  return MakeGarbageCollected<PaymentRequest>(
      execution_context, method_data, details, PaymentOptions::Create(),
      mojo::NullRemote(), exception_state);
}

PaymentRequest* PaymentRequest::Create(
    ExecutionContext* execution_context,
    const HeapVector<Member<PaymentMethodData>>& method_data,
    const PaymentDetailsInit* details,
    const PaymentOptions* options,
    ExceptionState& exception_state) {
  return MakeGarbageCollected<PaymentRequest>(
      execution_context, method_data, details, options, mojo::NullRemote(),
      exception_state);
}

PaymentRequest::~PaymentRequest() = default;

ScriptPromise<PaymentResponse> PaymentRequest::show(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  return show(script_state, ScriptPromise<PaymentDetailsUpdate>(),
              exception_state);
}

ScriptPromise<PaymentResponse> PaymentRequest::show(
    ScriptState* script_state,
    ScriptPromise<PaymentDetailsUpdate> details_promise,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid() || !LocalDOMWindow::From(script_state) ||
      !LocalDOMWindow::From(script_state)->GetFrame()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kAbortError,
                                      "Cannot show the payment request");
    return EmptyPromise();
  }

  if (!not_supported_for_invalid_origin_or_ssl_error_.empty()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        not_supported_for_invalid_origin_or_ssl_error_);
    return EmptyPromise();
  }

  if (!payment_provider_.is_bound() || accept_resolver_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Already called show() once");
    return EmptyPromise();
  }

  LocalFrame* local_frame = DomWindow()->GetFrame();

  bool has_transient_user_activation =
      LocalFrame::HasTransientUserActivation(local_frame);
  bool has_delegated_activation = DomWindow()->IsPaymentRequestTokenActive();
  bool has_activation =
      has_transient_user_activation || has_delegated_activation;

  if (!has_transient_user_activation) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kPaymentRequestShowWithoutGesture);

    if (!has_delegated_activation) {
      UseCounter::Count(GetExecutionContext(),
                        WebFeature::kPaymentRequestShowWithoutGestureOrToken);
    }
  }

  // The user activation requirement is enforced in the browser side
  // PaymentRequest::Show in order to track the state of activationless show
  // across navigations.
  if (!has_activation) {
    RecordActivationlessShow(GetExecutionContext(), method_names_);
  }

  DomWindow()->ConsumePaymentRequestToken();
  LocalFrame::ConsumeTransientUserActivation(local_frame);

  VLOG(2) << "Renderer: PaymentRequest (" << id_.Utf8() << "): show()";

  UseCounter::Count(GetExecutionContext(), WebFeature::kPaymentRequestShow);

  is_waiting_for_show_promise_to_resolve_ = !details_promise.IsEmpty();
  payment_provider_->Show(is_waiting_for_show_promise_to_resolve_,
                          has_activation);
  if (is_waiting_for_show_promise_to_resolve_) {
    // If the website does not calculate the final shopping cart contents within
    // 10 seconds, abort payment.
    update_payment_details_timer_.StartOneShot(base::Seconds(10), FROM_HERE);
    details_promise.Then(
        script_state, MakeGarbageCollected<UpdatePaymentDetailsResolve>(this),
        MakeGarbageCollected<UpdatePaymentDetailsReject>(this));
  }

  accept_resolver_ =
      MakeGarbageCollected<ScriptPromiseResolver<PaymentResponse>>(
          script_state, exception_state.GetContext());
  return accept_resolver_->Promise();
}

ScriptPromise<IDLUndefined> PaymentRequest::abort(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot abort payment");
    return EmptyPromise();
  }

  if (abort_resolver_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot abort() again until the previous "
                                      "abort() has resolved or rejected");
    return EmptyPromise();
  }

  if (!GetPendingAcceptPromiseResolver()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "No show() or retry() in progress, so nothing to abort");
    return EmptyPromise();
  }

  VLOG(2) << "Renderer: PaymentRequest (" << id_.Utf8() << "): abort()";

  abort_resolver_ = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  payment_provider_->Abort();
  return abort_resolver_->Promise();
}

ScriptPromise<IDLBoolean> PaymentRequest::canMakePayment(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!not_supported_for_invalid_origin_or_ssl_error_.empty()) {
    return ToResolvedPromise<IDLBoolean>(script_state, false);
  }

  if (!payment_provider_.is_bound() || GetPendingAcceptPromiseResolver() ||
      can_make_payment_resolver_ || !script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot query payment request");
    return EmptyPromise();
  }

  VLOG(2) << "Renderer: PaymentRequest (" << id_.Utf8()
          << "): canMakePayment()";

  payment_provider_->CanMakePayment();

  can_make_payment_resolver_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(
          script_state, exception_state.GetContext());
  return can_make_payment_resolver_->Promise();
}

ScriptPromise<IDLBoolean> PaymentRequest::hasEnrolledInstrument(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!not_supported_for_invalid_origin_or_ssl_error_.empty()) {
    return ToResolvedPromise<IDLBoolean>(script_state, false);
  }

  if (!payment_provider_.is_bound() || GetPendingAcceptPromiseResolver() ||
      has_enrolled_instrument_resolver_ || !script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot query payment request");
    return EmptyPromise();
  }

  VLOG(2) << "Renderer: PaymentRequest (" << id_.Utf8()
          << "): hasEnrolledInstrument()";

  payment_provider_->HasEnrolledInstrument();

  has_enrolled_instrument_resolver_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(
          script_state, exception_state.GetContext());
  return has_enrolled_instrument_resolver_->Promise();
}

bool PaymentRequest::HasPendingActivity() const {
  return accept_resolver_ || retry_resolver_ || complete_resolver_ ||
         has_enrolled_instrument_resolver_ || can_make_payment_resolver_ ||
         abort_resolver_;
}

const AtomicString& PaymentRequest::InterfaceName() const {
  return event_target_names::kPaymentRequest;
}

ExecutionContext* PaymentRequest::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

ScriptPromise<IDLUndefined> PaymentRequest::Retry(
    ScriptState* script_state,
    const PaymentValidationErrors* errors,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid() || !LocalDOMWindow::From(script_state) ||
      !LocalDOMWindow::From(script_state)->GetFrame()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kAbortError,
                                      "Cannot retry the payment request");
    return EmptyPromise();
  }

  if (complete_resolver_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Cannot call retry() because already called complete()");
    return EmptyPromise();
  }

  if (retry_resolver_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot call retry() again until "
                                      "the previous retry() is finished");
    return EmptyPromise();
  }

  if (!payment_provider_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Payment request terminated");
    return EmptyPromise();
  }

  String error_message;
  if (!PaymentsValidators::IsValidPaymentValidationErrorsFormat(
          errors, &error_message)) {
    exception_state.ThrowTypeError(error_message);
    return EmptyPromise();
  }

  if (!options_->requestPayerName() && errors->hasPayer() &&
      errors->payer()->hasName()) {
    GetExecutionContext()->AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::ConsoleMessageSource::kJavaScript,
            mojom::ConsoleMessageLevel::kWarning,
            "The payer.name passed to retry() may not be "
            "shown because requestPayerName is false"));
  }

  if (!options_->requestPayerEmail() && errors->hasPayer() &&
      errors->payer()->hasEmail()) {
    GetExecutionContext()->AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::ConsoleMessageSource::kJavaScript,
            mojom::ConsoleMessageLevel::kWarning,
            "The payer.email passed to retry() may not be "
            "shown because requestPayerEmail is false"));
  }

  if (!options_->requestPayerPhone() && errors->hasPayer() &&
      errors->payer()->hasPhone()) {
    GetExecutionContext()->AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::ConsoleMessageSource::kJavaScript,
            mojom::ConsoleMessageLevel::kWarning,
            "The payer.phone passed to retry() may not be "
            "shown because requestPayerPhone is false"));
  }

  if (!options_->requestShipping() && errors->hasShippingAddress()) {
    GetExecutionContext()->AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::ConsoleMessageSource::kJavaScript,
            mojom::ConsoleMessageLevel::kWarning,
            "The shippingAddress passed to retry() may not "
            "be shown because requestShipping is false"));
  }

  complete_timer_.Stop();

  // The payment provider should respond in PaymentRequest::OnPaymentResponse().
  payment_provider_->Retry(
      payments::mojom::blink::PaymentValidationErrors::From(*errors));

  retry_resolver_ = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());

  return retry_resolver_->Promise();
}

ScriptPromise<IDLUndefined> PaymentRequest::Complete(
    ScriptState* script_state,
    PaymentComplete result,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot complete payment");
    return EmptyPromise();
  }

  if (complete_resolver_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Already called complete() once");
    return EmptyPromise();
  }

  if (retry_resolver_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Cannot call complete() before retry() is finished");
    return EmptyPromise();
  }

  if (!complete_timer_.IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Timed out after 60 seconds, complete() called too late");
    return EmptyPromise();
  }

  // User has cancelled the transaction while the website was processing it.
  if (!payment_provider_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kAbortError,
                                      "Request cancelled");
    return EmptyPromise();
  }

  UseCounter::Count(GetExecutionContext(), WebFeature::kPaymentRequestComplete);

  complete_timer_.Stop();

  // The payment provider should respond in PaymentRequest::OnComplete().
  payment_provider_->Complete(payments::mojom::blink::PaymentComplete(result));

  complete_resolver_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
          script_state, exception_state.GetContext());
  return complete_resolver_->Promise();
}

void PaymentRequest::OnUpdatePaymentDetails(PaymentDetailsUpdate* details) {
  ScriptPromiseResolverBase* resolver = GetPendingAcceptPromiseResolver();
  if (!resolver || !payment_provider_.is_bound() ||
      !update_payment_details_timer_.IsActive()) {
    return;
  }

  update_payment_details_timer_.Stop();

  v8::Isolate* isolate = resolver->GetScriptState()->GetIsolate();
  v8::TryCatch try_catch(isolate);
  PaymentDetailsPtr validated_details =
      payments::mojom::blink::PaymentDetails::New();
  ValidateAndConvertPaymentDetailsUpdate(
      details, options_, validated_details, shipping_option_, ignore_total_,
      *GetExecutionContext(), PassThroughException(isolate));
  if (try_catch.HasCaught()) {
    ApplyContextToException(resolver->GetScriptState(), try_catch.Exception(),
                            ExceptionContext(v8::ExceptionContext::kConstructor,
                                             "PaymentDetailsUpdate"));
    resolver->Reject(try_catch.Exception());
    ClearResolversAndCloseMojoConnection();
    return;
  }

  if (!options_->requestShipping()) {
    validated_details->shipping_options = std::nullopt;
  }

  if (is_waiting_for_show_promise_to_resolve_) {
    is_waiting_for_show_promise_to_resolve_ = false;

    if (!validated_details->error.empty()) {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kInvalidStateError,
          "Cannot specify 'error' when resolving the "
          "promise passed into PaymentRequest.show()"));
      ClearResolversAndCloseMojoConnection();
      return;
    }
  }

  payment_provider_->UpdateWith(std::move(validated_details));
}

void PaymentRequest::OnUpdatePaymentDetailsFailure(const String& error) {
  if (!payment_provider_.is_bound()) {
    return;
  }
  if (update_payment_details_timer_.IsActive()) {
    update_payment_details_timer_.Stop();
  }
  ScriptPromiseResolverBase* resolver = GetPendingAcceptPromiseResolver();
  if (resolver) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kAbortError, error));
  }
  if (complete_resolver_) {
    complete_resolver_->RejectWithDOMException(DOMExceptionCode::kAbortError,
                                               error);
  }
  ClearResolversAndCloseMojoConnection();
}

bool PaymentRequest::IsInteractive() const {
  return !!GetPendingAcceptPromiseResolver();
}

void PaymentRequest::Trace(Visitor* visitor) const {
  visitor->Trace(options_);
  visitor->Trace(shipping_address_);
  visitor->Trace(payment_response_);
  visitor->Trace(accept_resolver_);
  visitor->Trace(retry_resolver_);
  visitor->Trace(complete_resolver_);
  visitor->Trace(abort_resolver_);
  visitor->Trace(can_make_payment_resolver_);
  visitor->Trace(has_enrolled_instrument_resolver_);
  visitor->Trace(payment_provider_);
  visitor->Trace(client_receiver_);
  visitor->Trace(complete_timer_);
  visitor->Trace(update_payment_details_timer_);
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

void PaymentRequest::OnCompleteTimeoutForTesting() {
  complete_timer_.Stop();
  OnCompleteTimeout(nullptr);
}

void PaymentRequest::OnUpdatePaymentDetailsTimeoutForTesting() {
  update_payment_details_timer_.Stop();
  OnUpdatePaymentDetailsTimeout(nullptr);
}

void PaymentRequest::OnConnectionError() {
  OnError(PaymentErrorReason::UNKNOWN,
          "Renderer process could not establish or lost IPC connection to the "
          "PaymentRequest service in the browser process.");
}

PaymentRequest::PaymentRequest(
    ExecutionContext* execution_context,
    const HeapVector<Member<PaymentMethodData>>& method_data,
    const PaymentDetailsInit* details,
    const PaymentOptions* options,
    mojo::PendingRemote<payments::mojom::blink::PaymentRequest>
        mock_payment_provider,
    ExceptionState& exception_state)
    : ExecutionContextLifecycleObserver(execution_context),
      ActiveScriptWrappable<PaymentRequest>({}),
      options_(options),
      payment_provider_(execution_context),
      client_receiver_(this, execution_context),
      complete_timer_(
          execution_context->GetTaskRunner(TaskType::kMiscPlatformAPI),
          this,
          &PaymentRequest::OnCompleteTimeout),
      update_payment_details_timer_(
          execution_context->GetTaskRunner(TaskType::kMiscPlatformAPI),
          this,
          &PaymentRequest::OnUpdatePaymentDetailsTimeout),
      is_waiting_for_show_promise_to_resolve_(false) {
  // options_, details has default value, so could never be null, according to
  // payment_request.idl.
  DCHECK(options_);
  DCHECK(details);

  DCHECK(GetExecutionContext()->IsSecureContext());
  if (!AllowedToUsePaymentRequest(execution_context)) {
    exception_state.ThrowSecurityError(
        "Must be in a top-level browsing context or an iframe needs to specify "
        "allow=\"payment\" explicitly");
    return;
  }

  if (details->hasId() &&
      details->id().length() > PaymentRequest::kMaxStringLength) {
    exception_state.ThrowTypeError("ID cannot be longer than 1024 characters");
    return;
  }

  PaymentDetailsPtr validated_details =
      payments::mojom::blink::PaymentDetails::New();
  validated_details->id = id_ =
      details->hasId() ? details->id() : WTF::CreateCanonicalUUIDString();

  VLOG(2) << "Renderer: New PaymentRequest (" << id_.Utf8() << ")";

  Vector<payments::mojom::blink::PaymentMethodDataPtr> validated_method_data;
  ValidateAndConvertPaymentMethodData(method_data, options_,
                                      validated_method_data, method_names_,
                                      *GetExecutionContext(), exception_state);
  if (exception_state.HadException()) {
    return;
  }

  ignore_total_ =
      RuntimeEnabledFeatures::DigitalGoodsEnabled(GetExecutionContext()) &&
      RequestingOnlyAppStoreBillingMethods(validated_method_data);
  ValidateAndConvertPaymentDetailsInit(details, options_, validated_details,
                                       shipping_option_, ignore_total_,
                                       *GetExecutionContext(), exception_state);
  if (exception_state.HadException()) {
    return;
  }

  for (const PaymentMethodDataPtr& data : validated_method_data) {
    if (IsAppStoreBillingMethod(data->supported_method) &&
        (options_->requestShipping() || options_->requestPayerName() ||
         options_->requestPayerEmail() || options_->requestPayerPhone())) {
      execution_context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kJavaScript,
          mojom::blink::ConsoleMessageLevel::kError,
          "Payment method \"" + data->supported_method +
              "\" cannot be used with \"requestShipping\", "
              "\"requestPayerName\", "
              "\"requestPayerEmail\", or \"requestPayerPhone\"."));
    }
  }

  if (options_->requestShipping()) {
    shipping_type_ = options_->shippingType();
  } else {
    validated_details->shipping_options = std::nullopt;
  }

  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      execution_context->GetTaskRunner(TaskType::kUserInteraction);

  if (mock_payment_provider) {
    payment_provider_.Bind(
        std::move(mock_payment_provider),
        execution_context->GetTaskRunner(TaskType::kMiscPlatformAPI));
  } else {
    DomWindow()->GetBrowserInterfaceBroker().GetInterface(
        payment_provider_.BindNewPipeAndPassReceiver(task_runner));
  }
  payment_provider_.set_disconnect_handler(WTF::BindOnce(
      &PaymentRequest::OnConnectionError, WrapWeakPersistent(this)));

  UseCounter::Count(execution_context, WebFeature::kPaymentRequestInitialized);
  mojo::PendingRemote<payments::mojom::blink::PaymentRequestClient> client;
  client_receiver_.Bind(client.InitWithNewPipeAndPassReceiver(), task_runner);
  payment_provider_->Init(
      std::move(client), std::move(validated_method_data),
      std::move(validated_details),
      payments::mojom::blink::PaymentOptions::From(*options_));
}

void PaymentRequest::ContextDestroyed() {
  ClearResolversAndCloseMojoConnection();
}

void PaymentRequest::OnPaymentMethodChange(const String& method_name,
                                           const String& stringified_details) {
  DCHECK(GetPendingAcceptPromiseResolver());
  DCHECK(!complete_resolver_);

  if (!RuntimeEnabledFeatures::PaymentMethodChangeEventEnabled()) {
    payment_provider_->OnPaymentDetailsNotUpdated();
    return;
  }

  UseCounter::Count(GetExecutionContext(),
                    WebFeature::kPaymentRequestPaymentMethodChange);

  ScriptState* script_state =
      GetPendingAcceptPromiseResolver()->GetScriptState();
  ScriptState::Scope scope(script_state);

  PaymentMethodChangeEventInit* init =
      PaymentMethodChangeEventInit::Create(script_state->GetIsolate());
  init->setMethodName(method_name);

  if (!stringified_details.empty()) {
    v8::TryCatch try_catch(script_state->GetIsolate());
    v8::Local<v8::Value> parsed_value =
        FromJSONString(script_state, stringified_details);
    if (try_catch.HasCaught()) {
      GetPendingAcceptPromiseResolver()->Reject(try_catch.Exception());
      ClearResolversAndCloseMojoConnection();
      return;
    }
    init->setMethodDetails(
        ScriptValue(script_state->GetIsolate(), parsed_value));
  }

  PaymentRequestUpdateEvent* event = PaymentMethodChangeEvent::Create(
      script_state, event_type_names::kPaymentmethodchange, init);
  DispatchPaymentRequestUpdateEvent(this, event);
}

void PaymentRequest::OnShippingAddressChange(PaymentAddressPtr address) {
  DCHECK(GetPendingAcceptPromiseResolver());
  DCHECK(!complete_resolver_);

  String error_message;
  if (!PaymentsValidators::IsValidShippingAddress(
          GetPendingAcceptPromiseResolver()->GetScriptState()->GetIsolate(),
          address, &error_message)) {
    GetPendingAcceptPromiseResolver()->Reject(
        MakeGarbageCollected<DOMException>(DOMExceptionCode::kSyntaxError,
                                           error_message));
    ClearResolversAndCloseMojoConnection();
    return;
  }

  UseCounter::Count(GetExecutionContext(),
                    WebFeature::kPaymentRequestShippingAddressChange);

  shipping_address_ = MakeGarbageCollected<PaymentAddress>(std::move(address));

  PaymentRequestUpdateEvent* event = PaymentRequestUpdateEvent::Create(
      GetExecutionContext(), event_type_names::kShippingaddresschange);
  DispatchPaymentRequestUpdateEvent(this, event);
}

void PaymentRequest::OnShippingOptionChange(const String& shipping_option_id) {
  DCHECK(GetPendingAcceptPromiseResolver());
  DCHECK(!complete_resolver_);

  UseCounter::Count(GetExecutionContext(),
                    WebFeature::kPaymentRequestShippingOptionChange);

  shipping_option_ = shipping_option_id;
  PaymentRequestUpdateEvent* event = PaymentRequestUpdateEvent::Create(
      GetExecutionContext(), event_type_names::kShippingoptionchange);
  DispatchPaymentRequestUpdateEvent(this, event);
}

void PaymentRequest::OnPayerDetailChange(
    payments::mojom::blink::PayerDetailPtr detail) {
  DCHECK(payment_response_);
  DCHECK(GetPendingAcceptPromiseResolver());
  DCHECK(!complete_resolver_);

  payment_response_->UpdatePayerDetail(std::move(detail));
  PaymentRequestUpdateEvent* event = PaymentRequestUpdateEvent::Create(
      GetExecutionContext(), event_type_names::kPayerdetailchange);
  DispatchPaymentRequestUpdateEvent(payment_response_, event);
}

void PaymentRequest::OnPaymentResponse(PaymentResponsePtr response) {
  DCHECK(GetPendingAcceptPromiseResolver());
  DCHECK(!complete_resolver_);

  ScriptPromiseResolverBase* resolver = GetPendingAcceptPromiseResolver();
  if (options_->requestShipping()) {
    if (!response->shipping_address || response->shipping_option.empty()) {
      resolver->Reject(
          MakeGarbageCollected<DOMException>(DOMExceptionCode::kSyntaxError));
      ClearResolversAndCloseMojoConnection();
      return;
    }

    String error_message;
    if (!PaymentsValidators::IsValidShippingAddress(
            resolver->GetScriptState()->GetIsolate(),
            response->shipping_address, &error_message)) {
      resolver->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kSyntaxError, error_message));
      ClearResolversAndCloseMojoConnection();
      return;
    }

    shipping_address_ = MakeGarbageCollected<PaymentAddress>(
        std::move(response->shipping_address));
    shipping_option_ = response->shipping_option;
  } else {
    if (response->shipping_address || !response->shipping_option.IsNull()) {
      resolver->Reject(
          MakeGarbageCollected<DOMException>(DOMExceptionCode::kSyntaxError));
      ClearResolversAndCloseMojoConnection();
      return;
    }
  }

  DCHECK(response->payer);
  if ((options_->requestPayerName() && response->payer->name.empty()) ||
      (options_->requestPayerEmail() && response->payer->email.empty()) ||
      (options_->requestPayerPhone() && response->payer->phone.empty()) ||
      (!options_->requestPayerName() && !response->payer->name.IsNull()) ||
      (!options_->requestPayerEmail() && !response->payer->email.IsNull()) ||
      (!options_->requestPayerPhone() && !response->payer->phone.IsNull())) {
    resolver->Reject(
        MakeGarbageCollected<DOMException>(DOMExceptionCode::kSyntaxError));
    ClearResolversAndCloseMojoConnection();
    return;
  }

  UseCounter::Count(GetExecutionContext(), WebFeature::kPaymentRequestResponse);

  // If the website does not call complete() 60 seconds after show() has been
  // resolved, then behave as if the website called complete("fail").
  complete_timer_.StartOneShot(base::Seconds(60), FROM_HERE);

  if (retry_resolver_) {
    DCHECK(payment_response_);
    payment_response_->Update(retry_resolver_->GetScriptState(),
                              std::move(response), shipping_address_.Get());
    retry_resolver_->Resolve();

    // Do not close the mojo connection here. The merchant website should call
    // PaymentResponse::complete(String), which will be forwarded over the mojo
    // connection to display a success or failure message to the user.
    retry_resolver_.Clear();
  } else if (accept_resolver_) {
    payment_response_ = MakeGarbageCollected<PaymentResponse>(
        accept_resolver_->GetScriptState(), std::move(response),
        shipping_address_.Get(), this, id_);
    accept_resolver_->Resolve(payment_response_);

    // Do not close the mojo connection here. The merchant website should call
    // PaymentResponse::complete(String), which will be forwarded over the mojo
    // connection to display a success or failure message to the user.
    accept_resolver_.Clear();
  }
}

void PaymentRequest::OnError(PaymentErrorReason error,
                             const String& error_message) {
  DCHECK(!error_message.empty());
  DOMExceptionCode exception_code = DOMExceptionCode::kUnknownError;

  switch (error) {
    case PaymentErrorReason::USER_CANCEL:
    // Intentional fall through.
    case PaymentErrorReason::INVALID_DATA_FROM_RENDERER:
    // Intentional fall through.
    case PaymentErrorReason::ALREADY_SHOWING:
      exception_code = DOMExceptionCode::kAbortError;
      break;

    case PaymentErrorReason::NOT_SUPPORTED:
      exception_code = DOMExceptionCode::kNotSupportedError;
      break;

    case PaymentErrorReason::NOT_SUPPORTED_FOR_INVALID_ORIGIN_OR_SSL:
      exception_code = DOMExceptionCode::kNotSupportedError;
      not_supported_for_invalid_origin_or_ssl_error_ = error_message;
      break;

    case PaymentErrorReason::NOT_ALLOWED_ERROR:
      exception_code = DOMExceptionCode::kNotAllowedError;
      break;

    case PaymentErrorReason::USER_OPT_OUT:
      exception_code = DOMExceptionCode::kOptOutError;
      break;

    case PaymentErrorReason::USER_ACTIVATION_REQUIRED:
      exception_code = DOMExceptionCode::kSecurityError;
      break;

    case PaymentErrorReason::UNKNOWN:
      break;
  }

  // If the user closes PaymentRequest UI after PaymentResponse.complete() has
  // been called, the PaymentResponse.complete() promise should be resolved with
  // undefined instead of rejecting.
  if (complete_resolver_) {
    DCHECK(error == PaymentErrorReason::USER_CANCEL ||
           error == PaymentErrorReason::UNKNOWN);
    complete_resolver_->Resolve();
  }

  ScriptPromiseResolverBase* resolver = GetPendingAcceptPromiseResolver();
  if (resolver) {
    resolver->Reject(
        MakeGarbageCollected<DOMException>(exception_code, error_message));
  }

  if (abort_resolver_) {
    abort_resolver_->RejectWithDOMException(exception_code, error_message);
  }

  if (can_make_payment_resolver_) {
    if (!not_supported_for_invalid_origin_or_ssl_error_.empty()) {
      can_make_payment_resolver_->Reject(false);
    } else {
      can_make_payment_resolver_->Reject(
          MakeGarbageCollected<DOMException>(exception_code, error_message));
    }
  }

  if (has_enrolled_instrument_resolver_) {
    if (!not_supported_for_invalid_origin_or_ssl_error_.empty()) {
      has_enrolled_instrument_resolver_->Reject(false);
    } else {
      has_enrolled_instrument_resolver_->Reject(
          MakeGarbageCollected<DOMException>(exception_code, error_message));
    }
  }

  ClearResolversAndCloseMojoConnection();
}

void PaymentRequest::OnComplete() {
  DCHECK(complete_resolver_);
  complete_resolver_->Resolve();
  ClearResolversAndCloseMojoConnection();
}

void PaymentRequest::OnAbort(bool aborted_successfully) {
  DCHECK(abort_resolver_);
  DCHECK(GetPendingAcceptPromiseResolver());

  if (!aborted_successfully) {
    abort_resolver_->RejectWithDOMException(
        DOMExceptionCode::kInvalidStateError, "Unable to abort the payment");
    abort_resolver_.Clear();
    return;
  }

  ScriptPromiseResolverBase* resolver = GetPendingAcceptPromiseResolver();
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kAbortError, "The website has aborted the payment"));
  abort_resolver_->Resolve();
  ClearResolversAndCloseMojoConnection();
}

void PaymentRequest::OnCanMakePayment(CanMakePaymentQueryResult result) {
  // TODO(https://crbug.com/891371): Understand how the resolver could be null
  // here and prevent it.
  if (!can_make_payment_resolver_) {
    return;
  }

  switch (result) {
    case CanMakePaymentQueryResult::CAN_MAKE_PAYMENT:
      can_make_payment_resolver_->Resolve(true);
      break;
    case CanMakePaymentQueryResult::CANNOT_MAKE_PAYMENT:
      can_make_payment_resolver_->Resolve(false);
      break;
  }

  can_make_payment_resolver_.Clear();
}

void PaymentRequest::OnHasEnrolledInstrument(
    HasEnrolledInstrumentQueryResult result) {
  // TODO(https://crbug.com/891371): Understand how the resolver could be null
  // here and prevent it.
  if (!has_enrolled_instrument_resolver_) {
    return;
  }

  switch (result) {
    case HasEnrolledInstrumentQueryResult::WARNING_HAS_ENROLLED_INSTRUMENT:
      WarnIgnoringQueryQuotaForCanMakePayment(*GetExecutionContext(),
                                              kHasEnrolledInstrumentDebugName);
      [[fallthrough]];
    case HasEnrolled
"""


```