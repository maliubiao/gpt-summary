Response:
The user wants a summary of the C++ source code file `blink/renderer/modules/ad_auction/navigator_auction.cc`. I need to identify the main functionalities implemented in this file, paying attention to its interaction with JavaScript, HTML, and CSS. I also need to provide examples of logical reasoning (with input/output), common user errors, and debugging steps.

Based on the included headers and the class name `NavigatorAuction`, it seems this file implements the core logic for the `navigator.runAdAuction()` JavaScript API. This API is part of the Privacy Sandbox's Protected Audience API (formerly FLEDGE) and allows websites to run on-device auctions for displaying ads.

Here's a breakdown of the file's key areas:

1. **`NavigatorAuction` Class:** This class likely handles the initiation and management of ad auctions triggered by JavaScript. It interfaces with the browser process (via Mojo) to perform various auction-related tasks.

2. **`AuctionHandle` Inner Class:** This seems to be a helper class for managing the lifecycle of an ongoing auction, particularly handling asynchronous operations and promise resolutions. It uses `AbortSignal` to allow cancellation of the auction.

3. **Helper Functions:** The file contains numerous helper functions for:
    * **Error Handling:**  Formatting error messages related to invalid input.
    * **Console Logging:**  Adding warnings and messages to the browser's console.
    * **Data Conversion:** Converting data types between JavaScript (WebIDL) and the internal Chromium representation (Mojo). This involves handling JSON serialization and deserialization, parsing URLs, and converting BigInts.
    * **Validation:** Checking the validity of input parameters for interest groups and auction configurations.

4. **Integration with JavaScript, HTML, and CSS:** The code interacts with JavaScript through the `navigator.runAdAuction()` API. The outcome of the auction can influence the HTML structure (e.g., by displaying an ad in an iframe or a fenced frame) and the CSS styling of the displayed ad.

5. **Logical Reasoning Examples:**  The code performs logical checks on the input parameters. For example, it verifies that URLs are valid, required fields are present, and enum values are recognized.

6. **Common User Errors:**  Incorrectly formatted URLs, missing required parameters in the JavaScript configuration, or providing invalid data types are potential user errors.

7. **Debugging Steps:** The code uses console logging, which can be helpful for debugging. Tracing the execution flow from the JavaScript call to `navigator.runAdAuction()` into this C++ file would be a key debugging step.

**Plan for the response:**

* **Summarize the main function:** Focus on the implementation of the `navigator.runAdAuction()` API.
* **Explain the role of `AuctionHandle`:** Highlight its promise management and cancellation capabilities.
* **Illustrate JavaScript interaction:** Show how JavaScript calls the API and how the results are returned.
* **Describe HTML and CSS relevance:** Explain how the auction outcome affects ad display.
* **Provide a simple logical reasoning example:** Demonstrate input validation.
* **Give an example of a common user error:** Focus on incorrect API usage.
* **Suggest debugging steps:** Emphasize the starting point from the JavaScript call.
这是 `blink/renderer/modules/ad_auction/navigator_auction.cc` 文件的第一部分，主要功能是 **实现了 `navigator.runAdAuction()` 这个 JavaScript API 的核心逻辑**，用于发起和管理浏览器内的广告拍卖。这个 API 是 Privacy Sandbox 的 Protected Audience API (原 FLEDGE) 的一部分。

**功能归纳：**

这部分代码主要关注以下几个方面：

1. **`NavigatorAuction` 类的定义：** 这个类负责处理来自 JavaScript 的 `navigator.runAdAuction()` 调用，并协调后续的拍卖流程。它管理着与浏览器进程中实际执行拍卖逻辑的组件 (`mojom::blink::AbortableAdAuction`) 的通信。

2. **`AuctionHandle` 内部类的定义：** 这是一个辅助类，用于管理正在进行的拍卖的生命周期，特别是处理与异步操作相关的 Promise。它允许在拍卖过程中取消操作，并负责连接拍卖过程中各个异步步骤的 Promise。

3. **Promise 管理和 AbortSignal 集成：**  `AuctionHandle` 实现了 `AbortSignal::Algorithm` 接口，允许通过 `AbortSignal` 来取消正在进行的拍卖。它还包含一系列内部类（如 `JsonResolved`, `PerBuyerSignalsResolved` 等），这些类用于处理拍卖配置中各种异步获取的数据（例如来自 URL 的 JSON 数据）的 Promise 的成功和失败情况。

4. **数据类型转换和验证：** 代码中包含大量的辅助函数，用于在 JavaScript (WebIDL) 和 Blink 内部的 Mojo 类型之间进行数据转换。同时，也进行各种输入参数的验证，例如 URL 的有效性、必填字段的存在等。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  这个文件是 `navigator.runAdAuction()` API 在 Blink 渲染引擎中的实现部分。JavaScript 代码调用 `navigator.runAdAuction()` 并传递拍卖所需的配置信息（例如参与拍卖的买方、卖方、出价逻辑的 URL 等）。这个 C++ 代码负责接收这些配置，并启动和管理拍卖流程。

   **举例：**  JavaScript 代码可能会这样调用 `runAdAuction()`：

   ```javascript
   navigator.runAdAuction({
     seller: 'https://example-seller.com',
     decisionLogicUrl: 'https://example-seller.com/decision-logic.js',
     // ... 其他配置
     interestGroupBuyers: ['https://buyer1.com', 'https://buyer2.com']
   }).then(adConfig => {
     if (adConfig) {
       // 展示广告
       console.log('Auction won!', adConfig);
     } else {
       // 没有赢得拍卖
       console.log('Auction lost.');
     }
   });
   ```

* **HTML:** 拍卖的结果可能会影响最终渲染的 HTML 内容。例如，如果拍卖成功，可能会返回一个包含广告渲染地址的 `FencedFrameConfig` 或一个 URL，用于在 `<iframe>` 或 `<fencedframe>` 中加载广告。

   **举例：**  如果拍卖成功并且返回了一个 `FencedFrameConfig`，渲染引擎会创建一个 `<fencedframe>` 元素并使用这个配置来加载广告内容。

* **CSS:**  与 HTML 类似，虽然这个 C++ 文件本身不直接操作 CSS，但拍卖的结果（例如选择哪个广告进行展示）最终会影响到页面上应用的 CSS 样式。

**逻辑推理举例：**

**假设输入：**

```javascript
navigator.runAdAuction({
  seller: 'https://example-seller.com',
  decisionLogicUrl: 'invalid-url', // 无效的 URL
  interestGroupBuyers: ['https://buyer.com']
});
```

**逻辑推理：**

代码中的 `CopyBiddingLogicUrlFromIdlToMojo` 函数（在后续部分）会尝试将 JavaScript 传递的 `decisionLogicUrl` 转换为内部的 `KURL` 对象。

**输出：**

由于 `invalid-url` 不是一个有效的 URL，`KURL` 的构造会失败。`CopyBiddingLogicUrlFromIdlToMojo` 函数会检测到这个错误，并调用 `exception_state.ThrowTypeError` 抛出一个 JavaScript 异常，指出 `decisionLogicUrl` 不能解析为一个有效的 URL。因此，`runAdAuction()` 返回的 Promise 会被拒绝 (rejected)。

**用户或编程常见的使用错误：**

1. **配置对象中缺少必填字段：**  例如，`runAdAuction()` 的配置中缺少 `seller` 或 `decisionLogicUrl` 字段。

   **错误示例：**

   ```javascript
   navigator.runAdAuction({
     // 缺少 seller 和 decisionLogicUrl
     interestGroupBuyers: ['https://buyer.com']
   });
   ```

   这会导致代码中相关的验证逻辑检测到缺失的字段，并抛出 `TypeError`。

2. **提供了无效的 URL：**  例如，`decisionLogicUrl` 或其他配置项中的 URL 拼写错误或格式不正确。

   **错误示例：**

   ```javascript
   navigator.runAdAuction({
     seller: 'htps://example-seller.com', // 协议头拼写错误
     decisionLogicUrl: 'https://example-seller.com/decision-logic.js',
     interestGroupBuyers: ['https://buyer.com']
   });
   ```

   代码中的 URL 解析逻辑会发现 `htps` 不是有效的协议，并抛出错误。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户访问网页：** 用户在浏览器中打开一个包含广告功能的网页。
2. **JavaScript 代码执行：** 网页上的 JavaScript 代码被执行，其中可能包含调用 `navigator.runAdAuction()` 的逻辑。
3. **`navigator.runAdAuction()` 调用：**  JavaScript 代码调用 `navigator.runAdAuction()` API，并传递拍卖配置对象。
4. **Blink 接收请求：**  浏览器将这个 API 调用传递给 Blink 渲染引擎。
5. **`NavigatorAuction::runAdAuction` (或其他相关方法) 被调用：**  在 `navigator_auction.cc` 文件中，对应的 C++ 方法会被调用，开始处理拍卖请求。
6. **参数解析和验证：**  代码会解析 JavaScript 传递的配置对象，并进行各种验证，例如检查 URL 的有效性、必填字段是否存在等。
7. **与浏览器进程通信：**  `NavigatorAuction` 类会通过 Mojo 接口与浏览器进程中的广告拍卖服务进行通信，发起实际的拍卖流程。

**调试线索：**

* **在 JavaScript 代码中设置断点：** 在调用 `navigator.runAdAuction()` 的地方设置断点，检查传递给 API 的配置对象是否正确。
* **使用浏览器的开发者工具：** 查看浏览器的控制台，检查是否有 JavaScript 错误或警告信息输出。
* **在 C++ 代码中设置断点：** 如果需要深入调试 Blink 的实现，可以在 `navigator_auction.cc` 文件中的相关方法（例如 `runAdAuction`，或者 `AuctionHandle` 中的方法）设置断点，跟踪代码的执行流程，查看参数的值以及中间状态。
* **查看网络请求：** 检查浏览器发出的与广告拍卖相关的网络请求，例如获取买方和卖方脚本的请求，以及上报拍卖结果的请求。

总而言之，这部分代码是浏览器广告拍卖功能的核心入口点，负责接收 JavaScript 的指令，并协调整个拍卖过程的启动和管理。它与 JavaScript 紧密相关，并间接影响着最终在 HTML 页面上展示的广告内容和样式。

Prompt: 
```
这是目录为blink/renderer/modules/ad_auction/navigator_auction.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/ad_auction/navigator_auction.h"

#include <stdint.h>

#include <optional>
#include <utility>

#include "base/check.h"
#include "base/containers/contains.h"
#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/numerics/checked_math.h"
#include "base/time/time.h"
#include "base/types/expected.h"
#include "base/types/expected_macros.h"
#include "base/types/pass_key.h"
#include "base/unguessable_token.h"
#include "base/uuid.h"
#include "components/aggregation_service/aggregation_coordinator_utils.h"
#include "mojo/public/cpp/bindings/map_traits_wtf_hash_map.h"
#include "third_party/abseil-cpp/absl/numeric/int128.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/fenced_frame/fenced_frame_utils.h"
#include "third_party/blink/public/common/frame/fenced_frame_sandbox_flags.h"
#include "third_party/blink/public/common/interest_group/ad_auction_constants.h"
#include "third_party/blink/public/common/interest_group/ad_auction_currencies.h"
#include "third_party/blink/public/common/interest_group/ad_display_size_utils.h"
#include "third_party/blink/public/common/interest_group/interest_group.h"
#include "third_party/blink/public/mojom/interest_group/ad_auction_service.mojom-blink.h"
#include "third_party/blink/public/mojom/interest_group/interest_group_types.mojom-blink.h"
#include "third_party/blink/public/mojom/parakeet/ad_request.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/web/web_console_message.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_fencedframeconfig_usvstring.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_usvstring_usvstringsequence.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ad_auction_data.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ad_auction_data_buyer_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ad_auction_data_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ad_properties.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ad_request_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ad_targeting.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ads.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_auction_ad.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_auction_ad_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_auction_ad_interest_group.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_auction_ad_interest_group_key.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_auction_ad_interest_group_size.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_auction_additional_bid_signature.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_auction_real_time_reporting_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_auction_report_buyer_debug_mode_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_auction_report_buyers_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_protected_audience_private_aggregation_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_adproperties_adpropertiessequence.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/scoped_abort_state.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/csp/csp_directive_list.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/fenced_frame/fenced_frame_config.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/modules/ad_auction/ads.h"
#include "third_party/blink/renderer/modules/ad_auction/join_leave_queue.h"
#include "third_party/blink/renderer/modules/ad_auction/protected_audience.h"
#include "third_party/blink/renderer/modules/ad_auction/validate_blink_interest_group.h"
#include "third_party/blink/renderer/modules/geolocation/geolocation_coordinates.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/heap_traits.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_operators.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/boringssl/src/include/openssl/curve25519.h"
#include "url/url_constants.h"
#include "v8/include/v8-primitive.h"
#include "v8/include/v8-value.h"

namespace blink {

// Helper to manage runtime of abort + promise resolution pipe.
// Can interface to AbortController itself, and has helper classes that can be
// connected to promises via Then and ScriptFunction.
class NavigatorAuction::AuctionHandle final : public AbortSignal::Algorithm {
 public:
  class Rejected;
  class AuctionHandleFunction : public GarbageCollectedMixin {
   public:
    virtual void Attach(ScriptState*, Rejected*) = 0;

    void Trace(Visitor* visitor) const override {
      visitor->Trace(auction_handle_);
    }

    AuctionHandle* auction_handle() { return auction_handle_.Get(); }

   protected:
    explicit AuctionHandleFunction(AuctionHandle* auction_handle)
        : auction_handle_(auction_handle) {}

   private:
    Member<AuctionHandle> auction_handle_;
  };

  template <typename IDLType, typename Derived>
  class AuctionHandleFunctionImpl : public ThenCallable<IDLType, Derived>,
                                    public AuctionHandleFunction {
   public:
    AuctionHandleFunctionImpl(AuctionHandle* auction_handle,
                              const MemberScriptPromise<IDLType>& promise)
        : AuctionHandleFunction(auction_handle), promise_(promise) {
      ThenCallable<IDLType, Derived>::SetExceptionContext(
          ExceptionContext(v8::ExceptionContext::kOperation, "NavigatorAuction",
                           "runAdAuction"));
    }

    void Trace(Visitor* visitor) const override {
      ThenCallable<IDLType, Derived>::Trace(visitor);
      AuctionHandleFunction::Trace(visitor);
      visitor->Trace(promise_);
    }

    void Attach(ScriptState* script_state, Rejected* rejected) final {
      promise_.Unwrap().Then(script_state, this, rejected);
    }

   private:
    MemberScriptPromise<IDLType> promise_;
  };

  class JsonResolved : public AuctionHandleFunctionImpl<IDLAny, JsonResolved> {
   public:
    // `field_name` is expected to point to a literal.
    JsonResolved(AuctionHandle* auction_handle,
                 const MemberScriptPromise<IDLAny>&,
                 mojom::blink::AuctionAdConfigAuctionIdPtr auction_id,
                 mojom::blink::AuctionAdConfigField field,
                 const String& seller_name,
                 const char* field_name);

    void React(ScriptState* script_state, ScriptValue value);

   private:
    const mojom::blink::AuctionAdConfigAuctionIdPtr auction_id_;
    const mojom::blink::AuctionAdConfigField field_;
    const String seller_name_;
    const char* const field_name_;
  };

  class PerBuyerSignalsResolved
      : public AuctionHandleFunctionImpl<
            IDLNullable<IDLRecord<IDLUSVString, IDLAny>>,
            PerBuyerSignalsResolved> {
   public:
    PerBuyerSignalsResolved(
        AuctionHandle* auction_handle,
        const MemberScriptPromise<
            IDLNullable<IDLRecord<IDLUSVString, IDLAny>>>&,
        mojom::blink::AuctionAdConfigAuctionIdPtr auction_id,
        const String& seller_name);

    void React(ScriptState* script_state,
               const std::optional<
                   HeapVector<std::pair<String, blink::ScriptValue>>>&);

   private:
    const mojom::blink::AuctionAdConfigAuctionIdPtr auction_id_;
    const String seller_name_;
  };

  // This is used for perBuyerTimeouts and perBuyerCumulativeTimeouts, with
  // `field` indicating which of the two fields an object is being used for.
  class BuyerTimeoutsResolved
      : public AuctionHandleFunctionImpl<
            IDLNullable<IDLRecord<IDLUSVString, IDLUnsignedLongLong>>,
            BuyerTimeoutsResolved> {
   public:
    BuyerTimeoutsResolved(
        AuctionHandle* auction_handle,
        const MemberScriptPromise<
            IDLNullable<IDLRecord<IDLUSVString, IDLUnsignedLongLong>>>&,
        mojom::blink::AuctionAdConfigAuctionIdPtr auction_id,
        mojom::blink::AuctionAdConfigBuyerTimeoutField field,
        const String& seller_name);

    void React(ScriptState* script_state,
               const std::optional<Vector<std::pair<String, uint64_t>>>&);

   private:
    const mojom::blink::AuctionAdConfigAuctionIdPtr auction_id_;
    const mojom::blink::AuctionAdConfigBuyerTimeoutField field_;
    const String seller_name_;
  };

  class BuyerCurrenciesResolved
      : public AuctionHandleFunctionImpl<
            IDLNullable<IDLRecord<IDLUSVString, IDLUSVString>>,
            BuyerCurrenciesResolved> {
   public:
    BuyerCurrenciesResolved(
        AuctionHandle* auction_handle,
        const MemberScriptPromise<
            IDLNullable<IDLRecord<IDLUSVString, IDLUSVString>>>&,
        mojom::blink::AuctionAdConfigAuctionIdPtr auction_id,
        const String& seller_name);

    void React(ScriptState* script_state,
               const std::optional<Vector<std::pair<String, String>>>&);

   private:
    const mojom::blink::AuctionAdConfigAuctionIdPtr auction_id_;
    const String seller_name_;
  };

  class DirectFromSellerSignalsResolved
      : public AuctionHandleFunctionImpl<IDLNullable<IDLUSVString>,
                                         DirectFromSellerSignalsResolved> {
   public:
    DirectFromSellerSignalsResolved(
        AuctionHandle* auction_handle,
        const MemberScriptPromise<IDLNullable<IDLUSVString>>&,
        mojom::blink::AuctionAdConfigAuctionIdPtr auction_id,
        const String& seller_name,
        const scoped_refptr<const SecurityOrigin>& seller_origin,
        const std::optional<Vector<scoped_refptr<const SecurityOrigin>>>&
            interest_group_buyers);

    void React(ScriptState* script_state, const String&);

   private:
    const mojom::blink::AuctionAdConfigAuctionIdPtr auction_id_;
    const String seller_name_;
    const scoped_refptr<const SecurityOrigin> seller_origin_;
    std::optional<Vector<scoped_refptr<const SecurityOrigin>>>
        interest_group_buyers_;
  };

  class DirectFromSellerSignalsHeaderAdSlotResolved
      : public AuctionHandleFunctionImpl<
            IDLNullable<IDLString>,
            DirectFromSellerSignalsHeaderAdSlotResolved> {
   public:
    DirectFromSellerSignalsHeaderAdSlotResolved(
        AuctionHandle* auction_handle,
        const MemberScriptPromise<IDLNullable<IDLString>>&,
        mojom::blink::AuctionAdConfigAuctionIdPtr auction_id,
        const String& seller_name);

    void React(ScriptState* script_state, const String&);

   private:
    const mojom::blink::AuctionAdConfigAuctionIdPtr auction_id_;
    const String seller_name_;
  };

  class DeprecatedRenderURLReplacementsResolved
      : public AuctionHandleFunctionImpl<
            IDLNullable<IDLRecord<IDLUSVString, IDLUSVString>>,
            DeprecatedRenderURLReplacementsResolved> {
   public:
    DeprecatedRenderURLReplacementsResolved(
        AuctionHandle* auction_handle,
        const MemberScriptPromise<
            IDLNullable<IDLRecord<IDLUSVString, IDLUSVString>>>&,
        mojom::blink::AuctionAdConfigAuctionIdPtr auction_id,
        const String& seller_name);

    void React(ScriptState* script_state,
               const std::optional<Vector<std::pair<String, String>>>&);

   private:
    const mojom::blink::AuctionAdConfigAuctionIdPtr auction_id_;
    const String seller_name_;
  };

  class ServerResponseResolved
      : public AuctionHandleFunctionImpl<NotShared<DOMUint8Array>,
                                         ServerResponseResolved> {
   public:
    ServerResponseResolved(AuctionHandle* auction_handle,
                           const MemberScriptPromise<NotShared<DOMUint8Array>>&,
                           mojom::blink::AuctionAdConfigAuctionIdPtr auction_id,
                           const String& seller_name);

    void React(ScriptState* script_state, NotShared<DOMUint8Array>);

   private:
    const mojom::blink::AuctionAdConfigAuctionIdPtr auction_id_;
    const String seller_name_;
  };

  class AdditionalBidsResolved
      : public AuctionHandleFunctionImpl<IDLUndefined, AdditionalBidsResolved> {
   public:
    AdditionalBidsResolved(AuctionHandle* auction_handle,
                           const MemberScriptPromise<IDLUndefined>&,
                           mojom::blink::AuctionAdConfigAuctionIdPtr auction_id,
                           const String& seller_name);

    void React(ScriptState* script_state);

   private:
    const mojom::blink::AuctionAdConfigAuctionIdPtr auction_id_;
    const String seller_name_;
  };

  class ResolveToConfigResolved
      : public ThenCallable<IDLAny, ResolveToConfigResolved>,
        public AuctionHandleFunction {
   public:
    ResolveToConfigResolved(AuctionHandle* auction_handle,
                            const MemberScriptPromise<IDLBoolean>&);

    void Trace(Visitor* visitor) const override {
      ThenCallable<IDLAny, ResolveToConfigResolved>::Trace(visitor);
      AuctionHandleFunction::Trace(visitor);
      visitor->Trace(promise_);
    }

    void Attach(ScriptState* script_state, Rejected* rejected) final {
      promise_.Unwrap().ThenWithNoTypeChecks(script_state, this, rejected);
    }

    void React(ScriptState* script_state, ScriptValue);

   private:
    MemberScriptPromise<IDLBoolean> promise_;
  };

  class Rejected : public AuctionHandleFunctionImpl<IDLAny, Rejected> {
   public:
    explicit Rejected(AuctionHandle* auction_handle)
        : AuctionHandleFunctionImpl(auction_handle,
                                    MemberScriptPromise<IDLAny>()) {}

    // Abort the auction if any input promise rejects
    void React(ScriptState*, ScriptValue) { auction_handle()->Abort(); }
  };

  AuctionHandle(ExecutionContext* context,
                mojo::PendingRemote<mojom::blink::AbortableAdAuction> remote)
      : abortable_ad_auction_(context) {
    abortable_ad_auction_.Bind(
        std::move(remote), context->GetTaskRunner(TaskType::kMiscPlatformAPI));
  }

  ~AuctionHandle() override = default;

  void QueueAttachPromiseHandler(AuctionHandleFunction* success_helper) {
    queued_promises_.emplace_back(success_helper);
  }

  void AttachQueuedPromises(ScriptState* script_state) {
    auto* rejected = MakeGarbageCollected<Rejected>(this);
    for (auto& success_helper : queued_promises_) {
      success_helper->Attach(script_state, rejected);
    }
    queued_promises_.clear();
  }

  void Abort() { abortable_ad_auction_->Abort(); }

  // AbortSignal::Algorithm implementation:
  void Run() override { Abort(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(abortable_ad_auction_);
    visitor->Trace(auction_resolver_);
    visitor->Trace(queued_promises_);
    AbortSignal::Algorithm::Trace(visitor);
  }

  void AuctionComplete(
      ScriptPromiseResolver<IDLNullable<V8UnionFencedFrameConfigOrUSVString>>*,
      std::unique_ptr<ScopedAbortState>,
      base::TimeTicks start_time,
      bool is_server_auction,
      bool aborted_by_script,
      const std::optional<FencedFrame::RedactedFencedFrameConfig>&);

  bool MaybeResolveAuction();

  void SetResolveToConfig(bool value) { resolve_to_config_ = value; }

  mojom::blink::AbortableAdAuction* mojo_pipe() {
    return abortable_ad_auction_.get();
  }

 private:
  HeapVector<Member<AuctionHandleFunction>> queued_promises_;
  HeapMojoRemote<mojom::blink::AbortableAdAuction> abortable_ad_auction_;

  std::optional<bool> resolve_to_config_;
  Member<
      ScriptPromiseResolver<IDLNullable<V8UnionFencedFrameConfigOrUSVString>>>
      auction_resolver_;
  std::optional<FencedFrame::RedactedFencedFrameConfig> auction_config_;
};

namespace {

// The maximum number of active cross-site joins and leaves. Once these are hit,
// cross-site joins/leaves are queued until they drop below this number. Queued
// pending operations are dropped on destruction / navigation away.
const int kMaxActiveCrossSiteJoins = 20;
const int kMaxActiveCrossSiteLeaves = 20;
const int kMaxActiveCrossSiteClears = 20;

// Error string builders.
String ErrorInvalidInterestGroup(const AuctionAdInterestGroup& group,
                                 const String& field_name,
                                 const String& field_value,
                                 const String& error) {
  StringBuilder error_builder;
  if (!field_name.empty()) {
    error_builder.AppendFormat("%s '%s' for ", field_name.Utf8().c_str(),
                               field_value.Utf8().c_str());
  }
  error_builder.AppendFormat(
      "AuctionAdInterestGroup with owner '%s' and name '%s' ",
      group.owner().Utf8().c_str(), group.name().Utf8().c_str());
  error_builder.Append(error);
  return error_builder.ReleaseString();
}

String ErrorInvalidInterestGroupJson(const AuctionAdInterestGroup& group,
                                     const String& field_name) {
  return String::Format(
      "%s for AuctionAdInterestGroup with owner '%s' and name '%s' must be a "
      "JSON-serializable object.",
      field_name.Utf8().c_str(), group.owner().Utf8().c_str(),
      group.name().Utf8().c_str());
}

String ErrorInvalidAuctionConfigSeller(const String& seller_name,
                                       const String& field_name,
                                       const String& field_value,
                                       const String& error) {
  return String::Format("%s '%s' for AuctionAdConfig with seller '%s' %s",
                        field_name.Utf8().c_str(), field_value.Utf8().c_str(),
                        seller_name.Utf8().c_str(), error.Utf8().c_str());
}

String ErrorInvalidAuctionConfig(const AuctionAdConfig& config,
                                 const String& field_name,
                                 const String& field_value,
                                 const String& error) {
  return ErrorInvalidAuctionConfigSeller(config.seller(), field_name,
                                         field_value, error);
}

String ErrorInvalidAuctionConfigSellerJson(const String& seller_name,
                                           const String& field_name) {
  return String::Format(
      "%s for AuctionAdConfig with seller '%s' must be a JSON-serializable "
      "object.",
      field_name.Utf8().c_str(), seller_name.Utf8().c_str());
}

String ErrorInvalidAdRequestConfig(const AdRequestConfig& config,
                                   const String& field_name,
                                   const String& field_value,
                                   const String& error) {
  return String::Format("%s '%s' for AdRequestConfig with URL '%s' %s",
                        field_name.Utf8().c_str(), field_value.Utf8().c_str(),
                        config.adRequestUrl().Utf8().c_str(),
                        error.Utf8().c_str());
}

String ErrorInvalidAuctionConfigUint(const AuctionAdConfig& config,
                                     const String& field_name,
                                     const String& error) {
  return String::Format("%s for AuctionAdConfig with seller '%s': %s",
                        field_name.Utf8().c_str(),
                        config.seller().Utf8().c_str(), error.Utf8().c_str());
}

String ErrorRenameMismatch(const String& old_field_name,
                           const String& old_field_value,
                           const String& new_field_name,
                           const String& new_field_value) {
  return String::Format(
      "%s doesn't have the same value as %s ('%s' vs '%s')",
      old_field_name.Utf8().c_str(), new_field_name.Utf8().c_str(),
      old_field_value.Utf8().c_str(), new_field_value.Utf8().c_str());
}

String ErrorMissingRequired(const String& required_field_name) {
  return String::Format("Missing required field %s",
                        required_field_name.Utf8().c_str());
}

// Console warnings.

void AddWarningMessageToConsole(const ExecutionContext& execution_context,
                                const String& message) {
  auto* window = To<LocalDOMWindow>(&execution_context);
  WebLocalFrameImpl::FromFrame(window->GetFrame())
      ->AddMessageToConsole(
          WebConsoleMessage(mojom::blink::ConsoleMessageLevel::kWarning,
                            message),
          /*discard_duplicates=*/true);
}

void ConsoleWarnDeprecatedEnum(const ExecutionContext& execution_context,
                               String enum_name,
                               String deprecated_value) {
  AddWarningMessageToConsole(
      execution_context,
      String::Format("Enum %s used deprecated value %s -- \"dashed-naming\" "
                     "should be used instead of \"camelCase\".",
                     enum_name.Utf8().c_str(),
                     deprecated_value.Utf8().c_str()));
}

// JSON and Origin conversion helpers.

bool Jsonify(const ScriptState& script_state,
             const v8::Local<v8::Value>& value,
             String& output) {
  v8::Local<v8::String> v8_string;
  // v8::JSON throws on certain inputs that can't be converted to JSON (like
  // recursive structures). Use TryCatch to consume them. Otherwise, they'd take
  // precedence over the returned ExtensionState for methods that return
  // ScriptPromises, since ExceptionState is used to generate a rejected
  // promise, which V8 exceptions take precedence over.
  v8::TryCatch try_catch(script_state.GetIsolate());
  if (!v8::JSON::Stringify(script_state.GetContext(), value)
           .ToLocal(&v8_string) ||
      try_catch.HasCaught()) {
    return false;
  }

  output = ToCoreString(script_state.GetIsolate(), v8_string);
  // JSON.stringify can fail to produce a string value in one of two ways: it
  // can throw an exception (as with unserializable objects), or it can return
  // `undefined` (as with e.g. passing a function). If JSON.stringify returns
  // `undefined`, the v8 API then coerces it to the string value "undefined".
  // Check for this, and consider it a failure (since we didn't properly
  // serialize a value, and v8::JSON::Parse() rejects "undefined").
  return output != "undefined";
}

base::expected<uint64_t, String> CopyBigIntToUint64(const BigInt& bigint) {
  if (bigint.IsNegative()) {
    return base::unexpected("Negative BigInt cannot be converted to uint64");
  }
  std::optional<absl::uint128> value = bigint.ToUInt128();
  if (!value.has_value() || absl::Uint128High64(*value) != 0) {
    return base::unexpected("Too large BigInt; Must fit in 64 bits");
  }
  return absl::Uint128Low64(*value);
}

base::expected<absl::uint128, String> CopyBigIntToUint128(
    const BigInt& bigint) {
  if (!bigint.FitsIn128Bits()) {
    return base::unexpected("Too large BigInt; Must fit in 128 bits");
  }
  if (bigint.IsNegative()) {
    return base::unexpected("Negative BigInt cannot be converted to uint128");
  }
  return *bigint.ToUInt128();
}

// Returns nullptr if |origin_string| couldn't be parsed into an acceptable
// origin.
scoped_refptr<const SecurityOrigin> ParseOrigin(const String& origin_string) {
  scoped_refptr<const SecurityOrigin> origin =
      SecurityOrigin::CreateFromString(origin_string);
  if (origin->Protocol() != url::kHttpsScheme) {
    return nullptr;
  }
  return origin;
}

// WebIDL -> Mojom copy functions -- each return true if successful (including
// the not present, nothing to copy case), returns false and throws JS exception
// for invalid input.

// joinAdInterestGroup() copy functions.

// TODO(crbug.com/1451034): Remove method when old expiration is removed.
bool CopyLifetimeIdlToMojo(ExceptionState& exception_state,
                           std::optional<double> lifetime_seconds,
                           const AuctionAdInterestGroup& input,
                           mojom::blink::InterestGroup& output) {
  std::optional<base::TimeDelta> lifetime_old =
      lifetime_seconds
          ? std::optional<base::TimeDelta>(base::Seconds(*lifetime_seconds))
          : std::nullopt;
  std::optional<base::TimeDelta> lifetime_new =
      input.hasLifetimeMs() ? std::optional<base::TimeDelta>(
                                  base::Milliseconds(input.lifetimeMs()))
                            : std::nullopt;
  if (lifetime_old && !lifetime_new) {
    lifetime_new = lifetime_old;
  }
  if (!lifetime_new) {
    exception_state.ThrowTypeError(ErrorMissingRequired("lifetimeMs"));
    return false;
  }
  output.expiry = base::Time::Now() + *lifetime_new;
  return true;
}

bool CopyOwnerFromIdlToMojo(const ExecutionContext& execution_context,
                            ExceptionState& exception_state,
                            const AuctionAdInterestGroup& input,
                            mojom::blink::InterestGroup& output) {
  scoped_refptr<const SecurityOrigin> owner = ParseOrigin(input.owner());
  if (!owner) {
    exception_state.ThrowTypeError(String::Format(
        "owner '%s' for AuctionAdInterestGroup with name '%s' must be a valid "
        "https origin.",
        input.owner().Utf8().c_str(), input.name().Utf8().c_str()));
    return false;
  }

  output.owner = std::move(owner);
  return true;
}

// Converts a sparse vector used in `priority_vector` and
// `priority_signals_overrides` to a WTF::HashMap, as is used in mojom structs.
// Has no failure cases.
WTF::HashMap<WTF::String, double> ConvertSparseVectorIdlToMojo(
    const Vector<std::pair<WTF::String, double>>& priority_signals_in) {
  WTF::HashMap<WTF::String, double> priority_signals_out;
  for (const auto& key_value_pair : priority_signals_in) {
    priority_signals_out.insert(key_value_pair.first, key_value_pair.second);
  }
  return priority_signals_out;
}

mojom::blink::SellerCapabilitiesPtr ConvertSellerCapabilitiesTypeFromIdlToMojo(
    const ExecutionContext& execution_context,
    const Vector<String>& capabilities_vector) {
  auto seller_capabilities = mojom::blink::SellerCapabilities::New();
  for (const String& capability_str : capabilities_vector) {
    const bool used_deprecated_names =
        capability_str == "interestGroupCounts" ||
        capability_str == "latencyStats";
    base::UmaHistogramBoolean(
        "Ads.InterestGroup.EnumNaming.Renderer.SellerCapabilities",
        used_deprecated_names);
    if (used_deprecated_names) {
      ConsoleWarnDeprecatedEnum(execution_context, "SellerCapabilities",
                                capability_str);
    }
    if (capability_str == "interest-group-counts" ||
        capability_str == "interestGroupCounts") {
      seller_capabilities->allows_interest_group_counts = true;
    } else if (capability_str == "latency-stats" ||
               capability_str == "latencyStats") {
      seller_capabilities->allows_latency_stats = true;
    } else {
      // For forward compatibility with new values, don't throw.
      continue;
    }
  }
  return seller_capabilities;
}

bool CopySellerCapabilitiesFromIdlToMojo(
    const ExecutionContext& execution_context,
    ExceptionState& exception_state,
    const AuctionAdInterestGroup& input,
    mojom::blink::InterestGroup& output) {
  output.all_sellers_capabilities = mojom::blink::SellerCapabilities::New();
  if (!input.hasSellerCapabilities()) {
    return true;
  }

  for (const auto& [origin_string, capabilities_vector] :
       input.sellerCapabilities()) {
    mojom::blink::SellerCapabilitiesPtr seller_capabilities =
        ConvertSellerCapabilitiesTypeFromIdlToMojo(execution_context,
                                                   capabilities_vector);
    if (origin_string == "*") {
      output.all_sellers_capabilities = std::move(seller_capabilities);
    } else {
      if (!output.seller_capabilities) {
        output.seller_capabilities.emplace();
      }
      output.seller_capabilities->insert(
          SecurityOrigin::CreateFromString(origin_string),
          std::move(seller_capabilities));
    }
  }

  return true;
}

bool CopyExecutionModeFromIdlToMojo(const ExecutionContext& execution_context,
                                    ExceptionState& exception_state,
                                    const AuctionAdInterestGroup& input,
                                    mojom::blink::InterestGroup& output) {
  if (!input.hasExecutionMode()) {
    return true;
  }
  const bool used_deprecated_names = input.executionMode() == "groupByOrigin";
  base::UmaHistogramBoolean(
      "Ads.InterestGroup.EnumNaming.Renderer.WorkletExecutionMode",
      used_deprecated_names);
  if (used_deprecated_names) {
    ConsoleWarnDeprecatedEnum(execution_context, "executionMode",
                              input.executionMode());
  }

  if (input.executionMode() == "compatibility") {
    output.execution_mode =
        mojom::blink::InterestGroup::ExecutionMode::kCompatibilityMode;
  } else if (input.executionMode() == "group-by-origin" ||
             input.executionMode() == "groupByOrigin") {
    output.execution_mode =
        mojom::blink::InterestGroup::ExecutionMode::kGroupedByOriginMode;
  } else if (input.executionMode() == "frozen-context") {
    output.execution_mode =
        mojom::blink::InterestGroup::ExecutionMode::kFrozenContext;
  }
  // For forward compatibility with new values, don't throw if unrecognized enum
  // values encountered.
  return true;
}

bool CopyBiddingLogicUrlFromIdlToMojo(const ExecutionContext& context,
                                      ExceptionState& exception_state,
                                      const AuctionAdInterestGroup& input,
                                      mojom::blink::InterestGroup& output) {
  if (!input.hasBiddingLogicURL()) {
    return true;
  }
  KURL bidding_url = context.CompleteURL(input.biddingLogicURL());
  if (!bidding_url.IsValid()) {
    exception_state.ThrowTypeError(ErrorInvalidInterestGroup(
        input, "biddingLogicURL", input.biddingLogicURL(),
        "cannot be resolved to a valid URL."));
    return false;
  }
  output.bidding_url = bidding_url;
  return true;
}

bool CopyWasmHelperUrlFromIdlToMojo(const ExecutionContext& context,
                                    ExceptionState& exception_state,
                                    const AuctionAdInterestGroup& input,
                                    mojom::blink::InterestGroup& output) {
  if (!input.hasBiddingWasmHelperURL()) {
    return true;
  }
  KURL wasm_url = context.CompleteURL(input.biddingWasmHelperURL());
  if (!wasm_url.IsValid()) {
    exception_state.ThrowTypeError(ErrorInvalidInterestGroup(
        input, "biddingWasmHelperURL", input.biddingWasmHelperURL(),
        "cannot be resolved to a valid URL."));
    return false;
  }
  // ValidateBlinkInterestGroup will checks whether this follows all the rules.
  output.bidding_wasm_helper_url = wasm_url;
  return true;
}

bool CopyUpdateUrlFromIdlToMojo(const ExecutionContext& context,
                               
"""


```