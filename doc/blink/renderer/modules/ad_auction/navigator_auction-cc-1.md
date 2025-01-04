Response:
The user wants a summary of the functionality of the provided C++ code snippet from a Chromium file. I need to identify the core purpose of the code and its interactions with web technologies like JavaScript, HTML, and CSS. I also need to look for error handling related to user input and provide a hypothetical user journey to this code.

**Plan:**

1. **Identify the Core Functionality:** Scan the code for keywords and patterns that indicate the main purpose. The presence of `Copy...FromIdlToMojo` suggests data transfer and conversion between different representations. The frequent checks for URL validity and data formats point to input validation. The terms "InterestGroup", "AuctionAdConfig", and related fields strongly suggest this code is involved in the FLEDGE/Protected Audience API.

2. **Analyze Interactions with Web Technologies:** Look for references to JavaScript types (like `ScriptState`, `V8Value`, `Promise`), HTML concepts (URLs), and CSS (though less likely in this specific file, but keep an eye out). The use of `CompleteURL` and checks for `https` indicate interaction with web addresses.

3. **Examine Logical Reasoning:**  Identify any conditional logic (if/else statements) that performs data transformations or validations based on input. I can create hypothetical inputs and trace the expected output.

4. **Identify Common User Errors:**  Look for `ThrowTypeError` calls. These indicate scenarios where user-provided data is invalid. I'll extract the error messages and relate them to potential user mistakes in JavaScript.

5. **Trace User Operations:**  Consider the sequence of user actions in a web browser that could trigger this code. This likely involves JavaScript calls to the FLEDGE API.

6. **Summarize the Functionality:** Condense the findings into a concise description of the code's role.

**Execution:**

- The code is primarily about copying and validating data from IDL (Interface Definition Language) representations of auction configurations and interest groups into Mojo (a Chromium IPC system) structures.
- It directly relates to the JavaScript FLEDGE API, specifically the `navigator.runAdAuction()` and potentially related methods for joining interest groups.
-  The code validates URLs, JSON data, and specific fields like `updateURL`, `trustedBiddingSignalsURL`, `userBiddingSignals`, ad metadata, etc.
-  It handles potential errors like invalid URLs, mismatched update URLs, invalid JSON, and incorrect data formats.
- User interaction starts with JavaScript calls to the FLEDGE API (e.g., `navigator.joinAdInterestGroup()` or `navigator.runAdAuction()`) with specific configurations.

**Summary (for part 2):** This part of the code focuses on copying and validating data related to interest groups and ad auction configurations from their JavaScript representations (IDL) to internal Chromium structures (Mojo). It ensures data integrity and throws errors for invalid user-provided information.
这是 `blink/renderer/modules/ad_auction/navigator_auction.cc` 文件的第 2 部分，主要负责将 JavaScript 中定义的广告竞价和兴趣组的配置信息，从 IDL (Interface Definition Language) 的表示形式转换并复制到 Blink 内部使用的 Mojo 结构中。Mojo 是一种用于 Chromium 内部组件间通信的接口定义语言。

**本部分代码的功能归纳如下：**

1. **复制和验证 Interest Group 的配置信息：**
   - `CopyUpdateURLFromIdlToMojo`:  复制和验证兴趣组的 `updateURL` 和 `dailyUpdateUrl`，确保 URL 的有效性，并在两者同时存在时，确保它们的值一致。
   - `CopyTrustedBiddingSignalsUrlFromIdlToMojo`: 复制和验证兴趣组的 `trustedBiddingSignalsURL`，确保 URL 的有效性。
   - `CopyTrustedBiddingSignalsKeysFromIdlToMojo`: 复制兴趣组的 `trustedBiddingSignalsKeys` 数组。
   - `CopyTrustedBiddingSignalsSlotSizeModeFromIdlToMojo`: 复制兴趣组的 `trustedBiddingSignalsSlotSizeMode` 枚举值。
   - `CopyMaxTrustedBiddingSignalsURLLengthFromIdlToMojo`: 复制和验证兴趣组的 `maxTrustedBiddingSignalsURLLength`，确保其非负。
   - `CopyTrustedBiddingSignalsCoordinatorFromIdlToMojo`: 复制和验证兴趣组的 `trustedBiddingSignalsCoordinator`，确保其是一个有效的 HTTPS Origin。
   - `CopyUserBiddingSignalsFromIdlToMojo`: 复制兴趣组的 `userBiddingSignals`，并验证其是否为有效的 JSON 字符串。
   - `CopyAdsFromIdlToMojo`: 复制兴趣组的 `ads` 数组，包括广告的渲染 URL、大小组、买方报告 ID、元数据等信息，并验证渲染 URL 和允许报告的 Origin 的有效性。
   - `CopyAdComponentsFromIdlToMojo`: 复制兴趣组的 `adComponents` 数组，类似于 `ads`，但通常用于组合广告。
   - `CopyAdSizesFromIdlToMojo`: 复制兴趣组的 `adSizes` 映射，包含广告尺寸的名称和宽高信息。
   - `CopySizeGroupsFromIdlToMojo`: 复制兴趣组的 `sizeGroups` 映射。
   - `CopyAuctionServerRequestFlagsFromIdlToMojo`: 复制兴趣组的 `auctionServerRequestFlags` 数组，用于指定发送到竞价服务器的请求标志。
   - `CopyAdditionalBidKeyFromIdlToMojo`: 复制和验证兴趣组的 `additionalBidKey`，确保其是有效的 Base64 编码的 ED25519 公钥。
   - `CopyAggregationCoordinatorOriginFromIdlToMojo`: 复制和验证兴趣组的 `aggregationCoordinatorOrigin`，用于指定私有聚合的协调器 Origin。

2. **复制和验证 Ad Request 配置信息 (用于 `createAdRequest`)：**
   - `CopyAdRequestUrlFromIdlToMojo`: 复制和验证广告请求的 URL (`adRequestUrl`)，确保其是有效的 HTTPS URL。
   - `CopyAdPropertiesFromIdlToMojo`: 复制和验证广告请求的属性 (`adProperties`)，可以是单个对象或对象数组。
   - `CopyTargetingFromIdlToMojo`: 复制广告请求的定向信息 (`targeting`)。
   - `CopyAdSignalsFromIdlToMojo`: 复制广告请求的匿名代理信号 (`anonymizedProxiedSignals`)。
   - `CopyFallbackSourceFromIdlToMojo`: 复制和验证广告请求的回退源 (`fallbackSource`)，确保其是有效的 HTTPS URL。

3. **复制和验证 Auction Ad 配置信息 (用于 `runAdAuction`)：**
   - `CopySellerFromIdlToMojo`: 复制和验证卖方 Origin (`seller`)，确保其是一个有效的 HTTPS Origin。
   - `CopyServerResponseFromIdlToMojo`: 处理来自服务器的响应 (`serverResponse`)，通常是一个 Promise。
   - `CopyDecisionLogicUrlFromIdlToMojo`: 复制和验证卖方的决策逻辑 URL (`decisionLogicURL`)，确保其与卖方 Origin 一致且为 HTTPS。
   - `CopyTrustedScoringSignalsFromIdlToMojo`: 复制和验证卖方的可信评分信号 URL (`trustedScoringSignalsURL`)，确保其为 HTTPS 且不包含查询参数、片段或凭据。
   - `CopyMaxTrustedScoringSignalsURLLengthFromIdlToMojo`: 复制和验证卖方的 `maxTrustedScoringSignalsURLLength`，确保其非负。
   - `CopyTrustedScoringSignalsCoordinatorFromIdlToMojo`: 复制和验证卖方的可信评分信号协调器 Origin (`trustedScoringSignalsCoordinator`)。
   - `CopyInterestGroupBuyersFromIdlToMojo`: 复制允许参与竞价的兴趣组买方 Origin 列表 (`interestGroupBuyers`)。
   - `CopyAuctionSignalsFromIdlToMojo`: 复制卖方的竞价信号 (`auctionSignals`)，可以是一个 Promise。
   - `CopySellerSignalsFromIdlToMojo`: 复制卖方的卖方信号 (`sellerSignals`)，可以是一个 Promise。

4. **处理 Promise：**
   - 许多配置项的值可以是 Promise，代码中会使用 `NavigatorAuction::AuctionHandle` 来处理这些 Promise 的解析，并在 Promise resolve 后将结果传递给 Mojo 结构。`ConvertJsonPromiseFromIdlToMojo` 函数用于处理 JSON 类型的 Promise。

5. **错误处理：**
   -  代码中大量使用了 `exception_state.ThrowTypeError` 和 `exception_state.ThrowDOMException` 来处理各种无效的输入，例如无效的 URL、格式错误的 JSON、不匹配的 Origin 等。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **JavaScript:**  这些函数直接处理来自 JavaScript 的数据。例如，当 JavaScript 代码调用 `navigator.joinAdInterestGroup()` 时，传递的配置对象（例如包含 `updateURL`, `ads`, `userBiddingSignals` 等属性）会被转换成 IDL 表示，然后这里的代码会将这些 IDL 数据复制到 Mojo 结构中。
  * **假设输入 (JavaScript):**
    ```javascript
    navigator.joinAdInterestGroup({
      name: 'my-interest-group',
      owner: 'https://example.com',
      biddingLogicUrl: 'https://example.com/bid.js',
      updateURL: 'https://example.com/update.json',
      ads: [{ renderUrl: 'https://cdn.example.com/ad1.html', metadata: { campaign: 'spring-sale' } }],
      userBiddingSignals: JSON.stringify({ region: 'US' })
    });
    ```
  * **输出 (Mojo 结构 - 示例部分):**  `output.update_url` 将会是解析后的 `KURL("https://example.com/update.json")`，`output.ads` 将会包含一个 `mojom::blink::InterestGroupAd` 对象，其 `render_url` 为 `KURL("https://cdn.example.com/ad1.html")`，`metadata` 为 JSON 字符串 `"{ \"campaign\": \"spring-sale\" }"`, `output.user_bidding_signals` 为 JSON 字符串 `"{ \"region\": \"US\" }"`.

* **HTML:**  `renderURL` 指向的是用于渲染广告的 HTML 页面。代码会验证这个 URL 的有效性。
  * **举例:** 如果 JavaScript 中 `ads` 数组中的某个 `renderUrl` 是 `"invalid-url"`,  `CopyAdsFromIdlToMojo` 中的 `context.CompleteURL(ad->renderURL())` 会返回一个无效的 `KURL`，导致 `exception_state.ThrowTypeError` 被调用，阻止无效的广告数据被传递到 Blink 内部。

* **CSS:** 虽然这段代码本身不直接处理 CSS，但最终渲染的广告页面（由 `renderURL` 指定）可能会使用 CSS 来控制样式。

**逻辑推理的假设输入与输出：**

* **假设输入:**  `input.hasUpdateURL()` 为 true, `input.hasDailyUpdateUrl()` 为 true, 并且 `input.updateURL()` 的值为 `"https://example.com/update1.json"`, `input.dailyUpdateUrl()` 的值为 `"https://example.com/update2.json"`.
* **输出:** `CopyUpdateURLFromIdlToMojo` 函数会检测到 `input.updateURL() != input.dailyUpdateUrl()`，从而调用 `exception_state.ThrowTypeError` 并返回 `false`。

**用户或编程常见的使用错误举例说明：**

* **错误使用 `updateURL` 和 `dailyUpdateUrl`:**  用户在调用 `navigator.joinAdInterestGroup()` 时，同时设置了 `updateURL` 和 `dailyUpdateUrl`，但它们的值不一致。
  * **错误示例 (JavaScript):**
    ```javascript
    navigator.joinAdInterestGroup({
      // ... other properties
      updateURL: 'https://example.com/updates.json',
      dailyUpdateUrl: 'https://anotherexample.com/daily-updates.json'
    });
    ```
  * **错误信息:** "TypeError: The updateURL of the interest group '...' with value 'https://example.com/updates.json' must match dailyUpdateUrl, when both are present."

* **提供无效的 URL:** 用户提供的 `trustedBiddingSignalsURL` 不是一个有效的 URL。
  * **错误示例 (JavaScript):**
    ```javascript
    navigator.joinAdInterestGroup({
      // ... other properties
      trustedBiddingSignalsURL: 'invalid-url'
    });
    ```
  * **错误信息:** "TypeError: The trustedBiddingSignalsURL of the interest group '...' with value 'invalid-url' cannot be resolved to a valid URL."

* **提供格式错误的 JSON 数据:** 用户提供的 `userBiddingSignals` 不是一个有效的 JSON 字符串。
  * **错误示例 (JavaScript):**
    ```javascript
    navigator.joinAdInterestGroup({
      // ... other properties
      userBiddingSignals: '{ "key": value }' // 缺少引号
    });
    ```
  * **错误信息:** "TypeError: The userBiddingSignals of the interest group '...' is not valid JSON."

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在网页上执行了 JavaScript 代码。**
2. **JavaScript 代码调用了 FLEDGE API，例如 `navigator.joinAdInterestGroup()` 或 `navigator.runAdAuction()`。**  这些 API 允许网站加入或创建一个用于广告竞价的兴趣组，或者发起一次广告竞价。
3. **传递给这些 API 的配置对象（例如 `AuctionAdInterestGroup` 或 `AuctionAdConfig`）包含了各种属性，例如 URL、JSON 数据等。**
4. **Blink 引擎接收到这个 JavaScript 调用，并将配置对象转换为内部的 IDL 表示形式。**
5. **`blink/renderer/modules/ad_auction/navigator_auction.cc` 文件中的这些 `Copy...FromIdlToMojo` 函数被调用，负责将 IDL 数据复制到 Mojo 消息中，以便在 Chromium 内部的不同进程之间传递和处理。**
6. **如果配置对象中的数据存在错误（例如无效的 URL、格式错误的 JSON），这些函数会检测到错误并抛出 JavaScript 异常，从而阻止无效的配置被使用。**

作为调试线索，当遇到与 FLEDGE API 相关的错误时，可以检查以下几点：

* **传递给 `navigator.joinAdInterestGroup()` 或 `navigator.runAdAuction()` 的配置对象是否符合规范。**
* **配置对象中的 URL 是否有效且使用 HTTPS 协议。**
* **配置对象中包含的 JSON 数据是否格式正确。**
* **是否违反了 FLEDGE API 的其他限制，例如 Origin 的匹配规则。**

通过查看控制台的错误信息和调用栈，可以定位到是哪个配置项导致了错误，并最终追溯到 `navigator_auction.cc` 文件中的这些验证逻辑。

Prompt: 
```
这是目录为blink/renderer/modules/ad_auction/navigator_auction.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能

"""
 ExceptionState& exception_state,
                                const AuctionAdInterestGroup& input,
                                mojom::blink::InterestGroup& output) {
  if (input.hasUpdateURL()) {
    if (input.hasDailyUpdateUrl() &&
        input.updateURL() != input.dailyUpdateUrl()) {
      exception_state.ThrowTypeError(ErrorInvalidInterestGroup(
          input, "updateURL", input.updateURL(),
          "must match dailyUpdateUrl, when both are present."));
      return false;
    }
    KURL update_url = context.CompleteURL(input.updateURL());
    if (!update_url.IsValid()) {
      exception_state.ThrowTypeError(
          ErrorInvalidInterestGroup(input, "updateURL", input.updateURL(),
                                    "cannot be resolved to a valid URL."));
      return false;
    }
    output.update_url = update_url;
    return true;
  }
  if (input.hasDailyUpdateUrl()) {
    KURL daily_update_url = context.CompleteURL(input.dailyUpdateUrl());
    if (!daily_update_url.IsValid()) {
      exception_state.ThrowTypeError(ErrorInvalidInterestGroup(
          input, "dailyUpdateUrl", input.dailyUpdateUrl(),
          "cannot be resolved to a valid URL."));
      return false;
    }
    output.update_url = daily_update_url;
  }
  return true;
}

bool CopyTrustedBiddingSignalsUrlFromIdlToMojo(
    const ExecutionContext& context,
    ExceptionState& exception_state,
    const AuctionAdInterestGroup& input,
    mojom::blink::InterestGroup& output) {
  if (!input.hasTrustedBiddingSignalsURL()) {
    return true;
  }
  KURL trusted_bidding_signals_url =
      context.CompleteURL(input.trustedBiddingSignalsURL());
  if (!trusted_bidding_signals_url.IsValid()) {
    exception_state.ThrowTypeError(ErrorInvalidInterestGroup(
        input, "trustedBiddingSignalsURL", input.trustedBiddingSignalsURL(),
        "cannot be resolved to a valid URL."));
    return false;
  }
  output.trusted_bidding_signals_url = trusted_bidding_signals_url;
  return true;
}

bool CopyTrustedBiddingSignalsKeysFromIdlToMojo(
    const AuctionAdInterestGroup& input,
    mojom::blink::InterestGroup& output) {
  if (!input.hasTrustedBiddingSignalsKeys()) {
    return true;
  }
  output.trusted_bidding_signals_keys.emplace();
  for (const auto& key : input.trustedBiddingSignalsKeys()) {
    output.trusted_bidding_signals_keys->push_back(key);
  }
  return true;
}

bool CopyTrustedBiddingSignalsSlotSizeModeFromIdlToMojo(
    const AuctionAdInterestGroup& input,
    mojom::blink::InterestGroup& output) {
  if (!input.hasTrustedBiddingSignalsSlotSizeMode()) {
    output.trusted_bidding_signals_slot_size_mode =
        mojom::blink::InterestGroup::TrustedBiddingSignalsSlotSizeMode::kNone;
  } else {
    output.trusted_bidding_signals_slot_size_mode =
        blink::InterestGroup::ParseTrustedBiddingSignalsSlotSizeMode(
            input.trustedBiddingSignalsSlotSizeMode());
  }
  return true;
}

bool CopyMaxTrustedBiddingSignalsURLLengthFromIdlToMojo(
    ExceptionState& exception_state,
    const AuctionAdInterestGroup& input,
    mojom::blink::InterestGroup& output) {
  // `maxTrustedBiddingSignalsURLLength` will be set as 0 by default in mojom,
  // if it is not present in IDL.
  if (!input.hasMaxTrustedBiddingSignalsURLLength()) {
    return true;
  }

  if (input.maxTrustedBiddingSignalsURLLength() < 0) {
    exception_state.ThrowTypeError(String::Format(
        "maxTrustedBiddingSignalsURLLength of interest group "
        "'%s' is less than 0 which is '%d'.",
        input.name().Characters8(), input.maxTrustedBiddingSignalsURLLength()));
    return false;
  }

  output.max_trusted_bidding_signals_url_length =
      input.maxTrustedBiddingSignalsURLLength();
  return true;
}

// TODO(crbug.com/352420077):
// 1. Add an allow list for `trustedBiddingSignalsCoordinator`, and return an
// error or warning if the given coordinator is not in the list.
// 2. Test input with invalid https origin in web platform tests.
bool CopyTrustedBiddingSignalsCoordinatorFromIdlToMojo(
    ExceptionState& exception_state,
    const AuctionAdInterestGroup& input,
    mojom::blink::InterestGroup& output) {
  if (!input.hasTrustedBiddingSignalsCoordinator()) {
    return true;
  }

  scoped_refptr<const SecurityOrigin> trustedBiddingSignalsCoordinator =
      ParseOrigin(input.trustedBiddingSignalsCoordinator());
  if (!trustedBiddingSignalsCoordinator) {
    exception_state.ThrowTypeError(String::Format(
        "trustedBiddingSignalsCoordinator '%s' for AuctionAdInterestGroup with "
        "name '%s' must be a valid https origin.",
        input.trustedBiddingSignalsCoordinator().Utf8().c_str(),
        input.name().Utf8().c_str()));
    return false;
  }

  output.trusted_bidding_signals_coordinator =
      std::move(trustedBiddingSignalsCoordinator);
  return true;
}

bool CopyUserBiddingSignalsFromIdlToMojo(const ScriptState& script_state,
                                         ExceptionState& exception_state,
                                         const AuctionAdInterestGroup& input,
                                         mojom::blink::InterestGroup& output) {
  if (!input.hasUserBiddingSignals()) {
    return true;
  }
  if (!Jsonify(script_state, input.userBiddingSignals().V8Value(),
               output.user_bidding_signals)) {
    exception_state.ThrowTypeError(
        ErrorInvalidInterestGroupJson(input, "userBiddingSignals"));
    return false;
  }

  return true;
}

bool CopyAdsFromIdlToMojo(const ExecutionContext& context,
                          const ScriptState& script_state,
                          ExceptionState& exception_state,
                          const AuctionAdInterestGroup& input,
                          mojom::blink::InterestGroup& output) {
  if (!input.hasAds()) {
    return true;
  }
  output.ads.emplace();
  for (const auto& ad : input.ads()) {
    auto mojo_ad = mojom::blink::InterestGroupAd::New();
    KURL render_url = context.CompleteURL(ad->renderURL());
    if (!render_url.IsValid()) {
      exception_state.ThrowTypeError(
          ErrorInvalidInterestGroup(input, "ad renderURL", ad->renderURL(),
                                    "cannot be resolved to a valid URL."));
      return false;
    }
    mojo_ad->render_url = render_url;
    if (ad->hasSizeGroup()) {
      mojo_ad->size_group = ad->sizeGroup();
    }
    if (ad->hasBuyerReportingId()) {
      mojo_ad->buyer_reporting_id = ad->buyerReportingId();
    }
    if (ad->hasBuyerAndSellerReportingId()) {
      mojo_ad->buyer_and_seller_reporting_id = ad->buyerAndSellerReportingId();
    }
    if (ad->hasSelectableBuyerAndSellerReportingIds() &&
        base::FeatureList::IsEnabled(
            blink::features::kFledgeAuctionDealSupport)) {
      mojo_ad->selectable_buyer_and_seller_reporting_ids =
          ad->selectableBuyerAndSellerReportingIds();
    }
    if (ad->hasMetadata()) {
      if (!Jsonify(script_state, ad->metadata().V8Value(), mojo_ad->metadata)) {
        exception_state.ThrowTypeError(
            ErrorInvalidInterestGroupJson(input, "ad metadata"));
        return false;
      }
    }
    if (ad->hasAdRenderId()) {
      mojo_ad->ad_render_id = ad->adRenderId();
    }
    if (ad->hasAllowedReportingOrigins()) {
      mojo_ad->allowed_reporting_origins.emplace();
      for (const String& origin_string : ad->allowedReportingOrigins()) {
        scoped_refptr<const SecurityOrigin> origin = ParseOrigin(origin_string);
        if (origin) {
          mojo_ad->allowed_reporting_origins->push_back(std::move(origin));
        } else {
          exception_state.ThrowTypeError(
              ErrorInvalidInterestGroup(input, "ad allowedReportingOrigins", "",
                                        "must all be https origins."));
          return false;
        }
      }
    }
    output.ads->push_back(std::move(mojo_ad));
  }
  return true;
}

bool CopyAdComponentsFromIdlToMojo(const ExecutionContext& context,
                                   const ScriptState& script_state,
                                   ExceptionState& exception_state,
                                   const AuctionAdInterestGroup& input,
                                   mojom::blink::InterestGroup& output) {
  if (!input.hasAdComponents()) {
    return true;
  }
  output.ad_components.emplace();
  for (const auto& ad : input.adComponents()) {
    auto mojo_ad = mojom::blink::InterestGroupAd::New();
    KURL render_url = context.CompleteURL(ad->renderURL());
    if (!render_url.IsValid()) {
      exception_state.ThrowTypeError(
          ErrorInvalidInterestGroup(input, "ad renderURL", ad->renderURL(),
                                    "cannot be resolved to a valid URL."));
      return false;
    }
    mojo_ad->render_url = render_url;
    if (ad->hasSizeGroup()) {
      mojo_ad->size_group = ad->sizeGroup();
    }
    if (ad->hasMetadata()) {
      if (!Jsonify(script_state, ad->metadata().V8Value(), mojo_ad->metadata)) {
        exception_state.ThrowTypeError(
            ErrorInvalidInterestGroupJson(input, "ad metadata"));
        return false;
      }
    }
    if (ad->hasAdRenderId()) {
      mojo_ad->ad_render_id = ad->adRenderId();
    }
    output.ad_components->push_back(std::move(mojo_ad));
  }
  return true;
}

bool CopyAdSizesFromIdlToMojo(const ExecutionContext& context,
                              const ScriptState& script_state,
                              ExceptionState& exception_state,
                              const AuctionAdInterestGroup& input,
                              mojom::blink::InterestGroup& output) {
  if (!input.hasAdSizes()) {
    return true;
  }
  output.ad_sizes.emplace();
  for (const auto& [name, size] : input.adSizes()) {
    auto [width_val, width_units] =
        blink::ParseAdSizeString(size->width().Ascii());
    auto [height_val, height_units] =
        blink::ParseAdSizeString(size->height().Ascii());

    output.ad_sizes->insert(
        name, mojom::blink::AdSize::New(width_val, width_units, height_val,
                                        height_units));
  }
  return true;
}

bool CopySizeGroupsFromIdlToMojo(const ExecutionContext& context,
                                 const ScriptState& script_state,
                                 ExceptionState& exception_state,
                                 const AuctionAdInterestGroup& input,
                                 mojom::blink::InterestGroup& output) {
  if (!input.hasSizeGroups()) {
    return true;
  }
  output.size_groups.emplace();
  for (const auto& group : input.sizeGroups()) {
    output.size_groups->insert(group.first, group.second);
  }
  return true;
}

bool CopyAuctionServerRequestFlagsFromIdlToMojo(
    const ExecutionContext& execution_context,
    ExceptionState& exception_state,
    const AuctionAdInterestGroup& input,
    mojom::blink::InterestGroup& output) {
  output.auction_server_request_flags =
      mojom::blink::AuctionServerRequestFlags::New();
  if (!input.hasAuctionServerRequestFlags()) {
    return true;
  }

  for (const String& flag : input.auctionServerRequestFlags()) {
    if (flag == "omit-ads") {
      output.auction_server_request_flags->omit_ads = true;
    } else if (flag == "include-full-ads") {
      output.auction_server_request_flags->include_full_ads = true;
    } else if (flag == "omit-user-bidding-signals") {
      output.auction_server_request_flags->omit_user_bidding_signals = true;
    }
  }
  return true;
}

bool CopyAdditionalBidKeyFromIdlToMojo(
    const ExecutionContext& execution_context,
    ExceptionState& exception_state,
    const AuctionAdInterestGroup& input,
    mojom::blink::InterestGroup& output) {
  if (!input.hasAdditionalBidKey()) {
    return true;
  }
  WTF::Vector<char> decoded_key;
  if (!WTF::Base64Decode(input.additionalBidKey(), decoded_key,
                         WTF::Base64DecodePolicy::kForgiving)) {
    exception_state.ThrowTypeError(ErrorInvalidInterestGroup(
        input, "additionalBidKey", input.additionalBidKey(),
        "cannot be base64 decoded."));
    return false;
  }
  if (decoded_key.size() != ED25519_PUBLIC_KEY_LEN) {
    exception_state.ThrowTypeError(ErrorInvalidInterestGroup(
        input, "additionalBidKey", input.additionalBidKey(),
        String::Format("must be exactly %d' bytes, was %u.",
                       ED25519_PUBLIC_KEY_LEN, decoded_key.size())));
    return false;
  }
  output.additional_bid_key.emplace(ED25519_PUBLIC_KEY_LEN);
  std::copy(decoded_key.begin(), decoded_key.end(),
            output.additional_bid_key->begin());
  return true;
}

bool GetAggregationCoordinatorFromConfig(
    ExceptionState& exception_state,
    const ProtectedAudiencePrivateAggregationConfig& config,
    scoped_refptr<const SecurityOrigin>& aggregation_coordinator_origin_out) {
  if (!config.hasAggregationCoordinatorOrigin()) {
    return true;
  }

  scoped_refptr<const SecurityOrigin> aggregation_coordinator_origin =
      ParseOrigin(config.aggregationCoordinatorOrigin());
  if (!aggregation_coordinator_origin) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        String::Format(
            "aggregationCoordinatorOrigin '%s' must be a valid https origin.",
            config.aggregationCoordinatorOrigin().Utf8().c_str()));
    return false;
  }
  if (!aggregation_service::IsAggregationCoordinatorOriginAllowed(
          aggregation_coordinator_origin->ToUrlOrigin())) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kDataError,
        String::Format("aggregationCoordinatorOrigin '%s' is not a recognized "
                       "coordinator origin.",
                       config.aggregationCoordinatorOrigin().Utf8().c_str()));
    return false;
  }
  aggregation_coordinator_origin_out =
      std::move(aggregation_coordinator_origin);
  return true;
}

bool CopyAggregationCoordinatorOriginFromIdlToMojo(
    ExceptionState& exception_state,
    const AuctionAdInterestGroup& input,
    mojom::blink::InterestGroup& output) {
  if (!input.hasPrivateAggregationConfig()) {
    return true;
  }

  return GetAggregationCoordinatorFromConfig(
      exception_state, *input.privateAggregationConfig(),
      output.aggregation_coordinator_origin);
}

// createAdRequest copy functions.
bool CopyAdRequestUrlFromIdlToMojo(const ExecutionContext& context,
                                   ExceptionState& exception_state,
                                   const AdRequestConfig& input,
                                   mojom::blink::AdRequestConfig& output) {
  KURL ad_request_url = context.CompleteURL(input.adRequestUrl());
  if (!ad_request_url.IsValid() ||
      (ad_request_url.Protocol() != url::kHttpsScheme)) {
    exception_state.ThrowTypeError(
        String::Format("adRequestUrl '%s' for AdRequestConfig must "
                       "be a valid https origin.",
                       input.adRequestUrl().Utf8().c_str()));
    return false;
  }
  output.ad_request_url = ad_request_url;
  return true;
}

bool CopyAdPropertiesFromIdlToMojo(const ExecutionContext& context,
                                   ExceptionState& exception_state,
                                   const AdRequestConfig& input,
                                   mojom::blink::AdRequestConfig& output) {
  if (!input.hasAdProperties()) {
    exception_state.ThrowTypeError(
        ErrorInvalidAdRequestConfig(input, "adProperties", input.adRequestUrl(),
                                    "must be provided to createAdRequest."));
    return false;
  }

  // output.ad_properties = mojom::blink::AdProperties::New();
  switch (input.adProperties()->GetContentType()) {
    case V8UnionAdPropertiesOrAdPropertiesSequence::ContentType::
        kAdProperties: {
      const auto* ad_properties = input.adProperties()->GetAsAdProperties();
      auto mojo_ad_properties = mojom::blink::AdProperties::New();
      mojo_ad_properties->width =
          ad_properties->hasWidth() ? ad_properties->width() : "";
      mojo_ad_properties->height =
          ad_properties->hasHeight() ? ad_properties->height() : "";
      mojo_ad_properties->slot =
          ad_properties->hasSlot() ? ad_properties->slot() : "";
      mojo_ad_properties->lang =
          ad_properties->hasLang() ? ad_properties->lang() : "";
      mojo_ad_properties->ad_type =
          ad_properties->hasAdtype() ? ad_properties->adtype() : "";
      mojo_ad_properties->bid_floor =
          ad_properties->hasBidFloor() ? ad_properties->bidFloor() : 0.0;

      output.ad_properties.push_back(std::move(mojo_ad_properties));
      break;
    }
    case V8UnionAdPropertiesOrAdPropertiesSequence::ContentType::
        kAdPropertiesSequence: {
      if (input.adProperties()->GetAsAdPropertiesSequence().size() <= 0) {
        exception_state.ThrowTypeError(ErrorInvalidAdRequestConfig(
            input, "adProperties", input.adRequestUrl(),
            "must be non-empty to createAdRequest."));
        return false;
      }

      for (const auto& ad_properties :
           input.adProperties()->GetAsAdPropertiesSequence()) {
        auto mojo_ad_properties = mojom::blink::AdProperties::New();
        mojo_ad_properties->width =
            ad_properties->hasWidth() ? ad_properties->width() : "";
        mojo_ad_properties->height =
            ad_properties->hasHeight() ? ad_properties->height() : "";
        mojo_ad_properties->slot =
            ad_properties->hasSlot() ? ad_properties->slot() : "";
        mojo_ad_properties->lang =
            ad_properties->hasLang() ? ad_properties->lang() : "";
        mojo_ad_properties->ad_type =
            ad_properties->hasAdtype() ? ad_properties->adtype() : "";
        mojo_ad_properties->bid_floor =
            ad_properties->hasBidFloor() ? ad_properties->bidFloor() : 0.0;

        output.ad_properties.push_back(std::move(mojo_ad_properties));
      }
      break;
    }
  }
  return true;
}

bool CopyTargetingFromIdlToMojo(const ExecutionContext& context,
                                ExceptionState& exception_state,
                                const AdRequestConfig& input,
                                mojom::blink::AdRequestConfig& output) {
  if (!input.hasTargeting()) {
    // Targeting information is not required.
    return true;
  }

  output.targeting = mojom::blink::AdTargeting::New();

  if (input.targeting()->hasInterests()) {
    output.targeting->interests.emplace();
    for (const auto& interest : input.targeting()->interests()) {
      output.targeting->interests->push_back(interest);
    }
  }

  if (input.targeting()->hasGeolocation()) {
    output.targeting->geolocation = mojom::blink::AdGeolocation::New();
    output.targeting->geolocation->latitude =
        input.targeting()->geolocation()->latitude();
    output.targeting->geolocation->longitude =
        input.targeting()->geolocation()->longitude();
  }

  return true;
}

bool CopyAdSignalsFromIdlToMojo(const ExecutionContext& context,
                                ExceptionState& exception_state,
                                const AdRequestConfig& input,
                                mojom::blink::AdRequestConfig& output) {
  if (!input.hasAnonymizedProxiedSignals()) {
    // AdSignals information is not required.
    return true;
  }

  output.anonymized_proxied_signals.emplace();

  for (const auto& signal : input.anonymizedProxiedSignals()) {
    if (signal == "coarse-geolocation") {
      output.anonymized_proxied_signals->push_back(
          blink::mojom::AdSignals::kCourseGeolocation);
    } else if (signal == "coarse-ua") {
      output.anonymized_proxied_signals->push_back(
          blink::mojom::AdSignals::kCourseUserAgent);
    } else if (signal == "targeting") {
      output.anonymized_proxied_signals->push_back(
          blink::mojom::AdSignals::kTargeting);
    } else if (signal == "user-ad-interests") {
      output.anonymized_proxied_signals->push_back(
          blink::mojom::AdSignals::kUserAdInterests);
    }
  }
  return true;
}

bool CopyFallbackSourceFromIdlToMojo(const ExecutionContext& context,
                                     ExceptionState& exception_state,
                                     const AdRequestConfig& input,
                                     mojom::blink::AdRequestConfig& output) {
  if (!input.hasFallbackSource()) {
    // FallbackSource information is not required.
    return true;
  }

  KURL fallback_source = context.CompleteURL(input.fallbackSource());
  if (!fallback_source.IsValid() ||
      (fallback_source.Protocol() != url::kHttpsScheme)) {
    exception_state.ThrowTypeError(
        String::Format("fallbackSource '%s' for AdRequestConfig must "
                       "be a valid https origin.",
                       input.fallbackSource().Utf8().c_str()));
    return false;
  }
  output.fallback_source = fallback_source;
  return true;
}

// runAdAuction() copy functions.

bool CopySellerFromIdlToMojo(ExceptionState& exception_state,
                             const AuctionAdConfig& input,
                             mojom::blink::AuctionAdConfig& output) {
  scoped_refptr<const SecurityOrigin> seller = ParseOrigin(input.seller());
  if (!seller) {
    exception_state.ThrowTypeError(String::Format(
        "seller '%s' for AuctionAdConfig must be a valid https origin.",
        input.seller().Utf8().c_str()));
    return false;
  }
  output.seller = seller;
  return true;
}

bool CopyServerResponseFromIdlToMojo(
    NavigatorAuction::AuctionHandle* auction_handle,
    mojom::blink::AuctionAdConfigAuctionId* auction_id,
    ExceptionState& exception_state,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasServerResponse()) {
    if (input.hasRequestId()) {
      exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
          input, "requestId", input.requestId(),
          "should not be specified without 'serverResponse'"));
      return false;
    }
    // If it has neither field we have nothing to do, so return success.
    return true;
  }
  if (!input.hasRequestId()) {
    exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
        input, "serverResponse", "Promise",
        "should not be specified without 'requestId'"));
    return false;
  }
  output.server_response = mojom::blink::AuctionAdServerResponseConfig::New();
  base::Uuid request_id = base::Uuid::ParseLowercase(input.requestId().Ascii());
  if (!request_id.is_valid()) {
    exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
        input, "serverResponse.requestId", input.requestId(),
        "must be a valid request ID provided by the API."));
    return false;
  }
  output.server_response->request_id = std::move(request_id);

  if (!auction_handle) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "serverResponse for AuctionAdConfig is not supported");
    return false;
  }

  auction_handle->QueueAttachPromiseHandler(
      MakeGarbageCollected<
          NavigatorAuction::AuctionHandle::ServerResponseResolved>(
          auction_handle, input.serverResponse(), auction_id->Clone(),
          input.seller()));
  return true;
}

bool CopyDecisionLogicUrlFromIdlToMojo(const ExecutionContext& context,
                                       ExceptionState& exception_state,
                                       const AuctionAdConfig& input,
                                       mojom::blink::AuctionAdConfig& output) {
  if (!input.hasDecisionLogicURL()) {
    return true;
  }
  KURL decision_logic_url = context.CompleteURL(input.decisionLogicURL());
  if (!decision_logic_url.IsValid()) {
    exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
        input, "decisionLogicURL", input.decisionLogicURL(),
        "cannot be resolved to a valid URL."));
    return false;
  }

  // Need to check scheme of the URL in addition to comparing origins because
  // FLEDGE currently only supports HTTPS URLs, and some non-HTTPS URLs can have
  // HTTPS origins.
  if (decision_logic_url.Protocol() != url::kHttpsScheme ||
      !output.seller->IsSameOriginWith(
          SecurityOrigin::Create(decision_logic_url).get())) {
    exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
        input, "decisionLogicURL", input.decisionLogicURL(),
        "must match seller origin."));
    return false;
  }

  output.decision_logic_url = decision_logic_url;
  return true;
}

bool CopyTrustedScoringSignalsFromIdlToMojo(
    const ExecutionContext& context,
    ExceptionState& exception_state,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasTrustedScoringSignalsURL()) {
    return true;
  }
  KURL trusted_scoring_signals_url =
      context.CompleteURL(input.trustedScoringSignalsURL());
  if (!trusted_scoring_signals_url.IsValid()) {
    exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
        input, "trustedScoringSignalsURL", input.trustedScoringSignalsURL(),
        "cannot be resolved to a valid URL."));
    return false;
  }

  // Need to check scheme of the URL because FLEDGE currently only supports
  // HTTPS URLs, and some non-HTTPS URLs can have HTTPS origins.
  if (trusted_scoring_signals_url.Protocol() != url::kHttpsScheme) {
    exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
        input, "trustedScoringSignalsURL", input.trustedScoringSignalsURL(),
        "must be HTTPS."));
    return false;
  }

  if (!trusted_scoring_signals_url.User().empty() ||
      !trusted_scoring_signals_url.Pass().empty() ||
      trusted_scoring_signals_url.HasFragmentIdentifier() ||
      !trusted_scoring_signals_url.Query().IsNull()) {
    exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
        input, "trustedScoringSignalsURL", input.trustedScoringSignalsURL(),
        "must not include a query, a fragment string, or "
        "embedded credentials."));
    return false;
  }

  output.trusted_scoring_signals_url = trusted_scoring_signals_url;
  return true;
}

bool CopyMaxTrustedScoringSignalsURLLengthFromIdlToMojo(
    ExceptionState& exception_state,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasMaxTrustedScoringSignalsURLLength()) {
    return true;
  }

  // TODO(xtlsheep): Add a test to join-leave-ad-interest-group.https.window.js
  // for the negative length case
  if (input.maxTrustedScoringSignalsURLLength() < 0) {
    exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
        input, "maxTrustedScoringSignalsURLLength",
        String::Number(input.maxTrustedScoringSignalsURLLength()),
        "must not be negative."));
    return false;
  }

  output.auction_ad_config_non_shared_params
      ->max_trusted_scoring_signals_url_length =
      input.maxTrustedScoringSignalsURLLength();
  return true;
}

// TODO(crbug.com/352420077):
// 1. Add an allow list for `trustedBiddingSignalsCoordinator`, and return an
// error or warning if the given coordinator is not in the list.
// 2. Test input with invalid https origin in web platform tests.
bool CopyTrustedScoringSignalsCoordinatorFromIdlToMojo(
    ExceptionState& exception_state,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasTrustedScoringSignalsCoordinator()) {
    return true;
  }

  scoped_refptr<const SecurityOrigin> trustedScoringSignalsCoordinator =
      ParseOrigin(input.trustedScoringSignalsCoordinator());
  if (!trustedScoringSignalsCoordinator) {
    exception_state.ThrowTypeError(
        ErrorInvalidAuctionConfig(input, "trustedScoringSignalsCoordinator",
                                  input.trustedScoringSignalsCoordinator(),
                                  "must be a valid https origin."));
    return false;
  }

  output.auction_ad_config_non_shared_params
      ->trusted_scoring_signals_coordinator =
      std::move(trustedScoringSignalsCoordinator);
  return true;
}

bool CopyInterestGroupBuyersFromIdlToMojo(
    ExceptionState& exception_state,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  DCHECK(!output.auction_ad_config_non_shared_params->interest_group_buyers);

  if (!input.hasInterestGroupBuyers()) {
    return true;
  }

  Vector<scoped_refptr<const SecurityOrigin>> buyers;
  for (const auto& buyer_str : input.interestGroupBuyers()) {
    scoped_refptr<const SecurityOrigin> buyer = ParseOrigin(buyer_str);
    if (!buyer) {
      exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
          input, "interestGroupBuyers buyer", buyer_str,
          "must be a valid https origin."));
      return false;
    }
    buyers.push_back(buyer);
  }
  output.auction_ad_config_non_shared_params->interest_group_buyers =
      std::move(buyers);
  return true;
}

mojom::blink::AuctionAdConfigMaybePromiseJsonPtr
ConvertJsonPromiseFromIdlToMojo(
    NavigatorAuction::AuctionHandle* auction_handle,
    mojom::blink::AuctionAdConfigAuctionId* auction_id,
    const AuctionAdConfig& input,
    const MemberScriptPromise<IDLAny>& promise,
    mojom::blink::AuctionAdConfigField field,
    const char* field_name) {
  auction_handle->QueueAttachPromiseHandler(
      MakeGarbageCollected<NavigatorAuction::AuctionHandle::JsonResolved>(
          auction_handle, promise, auction_id->Clone(), field, input.seller(),
          field_name));
  return mojom::blink::AuctionAdConfigMaybePromiseJson::NewPromise(0);
}

// null `auction_handle` disables promise handling.
// `auction_id` should be null iff `auction_handle` is.
void CopyAuctionSignalsFromIdlToMojo(
    NavigatorAuction::AuctionHandle* auction_handle,
    mojom::blink::AuctionAdConfigAuctionId* auction_id,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  DCHECK_EQ(auction_id == nullptr, auction_handle == nullptr);

  if (!input.hasAuctionSignals()) {
    output.auction_ad_config_non_shared_params->auction_signals =
        mojom::blink::AuctionAdConfigMaybePromiseJson::NewValue(String());
    return;
  }

  output.auction_ad_config_non_shared_params->auction_signals =
      ConvertJsonPromiseFromIdlToMojo(
          auction_handle, auction_id, input, input.auctionSignals(),
          mojom::blink::AuctionAdConfigField::kAuctionSignals,
          "auctionSignals");
}

void CopySellerSignalsFromIdlToMojo(
    NavigatorAuction::AuctionHandle* auction_handle,
    mojom::blink::AuctionAdConfigAuctionId* auction_id,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasSellerSignals()) {
    output.auction_ad_config_non_shared_params->seller_signals =
        mojom::blink::AuctionAdConfigMaybePromiseJson::NewValue(String());
    return;
  }

  output.auction_ad_config_non_shared_params->seller_signals =
      ConvertJsonPromiseFromIdlToMojo(
          auction_handle, auction_id, input, input.sellerSignals(),
          mojom::blink::AuctionAdConfigField::kSellerSignals, "sellerSignals");
}

// Attempts to build a DirectFromSellerSignalsSubresource. If there is no
// registered subresource URL `subresource_url` returns nullptr -- processing
// may continue with the next `subresource_url`.
mojom::blink::DirectFromSellerSignalsSubresourcePtr
TryToBuildDirectFromSellerSignalsSubresource(
    const KURL& subresource_url,
    const SecurityOrigin& seller,
    const ResourceFetcher& resource_fetcher) {
  DCHECK(subresource_url.IsValid());
  DCHECK(
      subresource_url.ProtocolIs(url::kHttpsScheme) &&
      seller.IsSameOriginWith(SecurityOrigin::Create(subresource_url).get()));
  // NOTE: If subresource bundles are disabled, GetSubresourceBundleToken() will
  // always return std::nullopt.
  std::optional<base::UnguessableToken> token =
      resource_fetcher.GetSubresourceBundleToken(subresource_url);
  if (!token) {
    return nullptr;
  }
  std::optional<KURL> bundle_url =
      resource_fetcher.GetSubresourceBundleSourceUrl(subresource_url);
  DCHECK(bundle_url->ProtocolIs(url::kHttpsScheme));
  DCHECK(seller.IsSameOriginWith(SecurityOrigin::Create(*bundle_url).get()));
  auto mojo_bundle = mojom::blink::DirectFromSellerSignalsSubresource::New();
  mojo_bundle->token = *token;
  mojo_bundle->bundle_url = *bundle_url;
  return mojo_bundle;
}

mojom::blink::DirectFromSellerSignalsPtr
ConvertDirectFromSellerSignalsFromV8ToMojo(
    ScriptState* script_state,
    const ExecutionContext& context,
    const ResourceFetcher& resource_fetcher,
    const String& seller_name,
    const SecurityOrigin& seller_origin,
    const std::optional<Vector<scoped_refptr<const SecurityOrigin>>>&
        interest_group_buyers,
    const String& prefix_string) {
  if (prefix_string.IsNull()) {
    return nullptr;
  }

  const KURL direct_from_seller_signals_prefix =
      context.Com
"""


```