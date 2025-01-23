Response:
The user wants to understand the functionality of the provided C++ code snippet from the Chromium Blink engine, specifically the `navigator_auction.cc` file. This part focuses on copying data from the JavaScript/IDL representation of auction configurations (`AuctionAdConfig`) to the internal Mojo representation (`mojom::blink::AuctionAdConfig`).

Here's a breakdown of the thought process to analyze the code:

1. **Identify the core purpose:** The function names like `Copy...FromIdlToMojo` and the presence of `AuctionAdConfig` and `mojom::blink::AuctionAdConfig` clearly indicate that this code is responsible for converting auction configuration data from the JavaScript side to the C++ side. This involves handling different data types and structures.

2. **Examine individual functions:** Analyze each function to understand what specific piece of the configuration it handles. Look for patterns in how the data is processed:
    * **DirectFromSellerSignals related functions:** These functions (`ConvertNonPromiseDirectFromSellerSignalsFromV8ToMojo`, `CopyDirectFromSellerSignalsFromIdlToMojo`, `CopyDirectFromSellerSignalsHeaderAdSlotFromIdlToMojo`) deal with fetching and validating signals directly from the seller's domain. They check URL validity, origin matching, and query string presence. Notice the handling of promises, indicating asynchronous operations.
    * **DeprecatedRenderURLReplacements related functions:** These functions (`ConvertNonPromiseDeprecatedRenderURLReplacementsFromV8ToMojo`, `CopyDeprecatedRenderURLReplacementsFromIdlToMojo`) handle the replacement of keywords in render URLs, again involving promise handling.
    * **AdditionalBids related function:** This function (`CopyAdditionalBidsFromIdlToMojo`) manages the provision of additional bids, requiring an `auctionNonce` and non-empty `interestGroupBuyers`.
    * **AggregationCoordinatorOrigin related function:** This function (`CopyAggregationCoordinatorOriginFromIdlToMojo`) deals with setting the origin for private aggregation.
    * **RealTimeReporting related functions:** These functions (`GetRealTimeReportingTypeFromConfig`, `CopyPerBuyerRealTimeReportingTypesFromIdlToMojo`) handle configuration related to real-time reporting.
    * **PerBuyerSignals related functions:** These functions (`ConvertNonPromisePerBuyerSignalsFromV8ToMojo`, `CopyPerBuyerSignalsFromIdlToMojo`) manage signals specific to individual buyers, requiring JSON serialization.
    * **PerBuyerTimeouts/CumulativeTimeouts related functions:** These functions (`ConvertNonPromisePerBuyerTimeoutsFromV8ToMojo`, `CopyPerBuyerTimeoutsFromIdlToMojo`, `CopyPerBuyerCumulativeTimeoutsFromIdlToMojo`) handle timeouts for individual buyers, including a wildcard option.
    * **PerBuyerCurrencies related functions:** These functions (`ConvertNonPromisePerBuyerCurrenciesFromV8ToMojo`, `CopyPerBuyerCurrenciesFromIdlToMojo`) handle currencies specific to individual buyers, including a wildcard option and validation of currency codes.
    * **PerBuyerExperimentIds related function:** This function (`CopyPerBuyerExperimentIdsFromIdlToMojo`) deals with experiment group IDs for individual buyers.
    * **PerBuyerGroupLimits related function:** This function (`CopyPerBuyerGroupLimitsFromIdlToMojo`) manages limits on the number of groups per buyer.
    * **PerBuyerPrioritySignals related functions:** These functions (`ConvertAuctionConfigPrioritySignalsFromIdlToMojo`, `CopyPerBuyerPrioritySignalsFromIdlToMojo`) handle priority signals for individual buyers, preventing the use of the "browserSignals." prefix.
    * **AuctionReportBuyerKeys/Buyers/DebugModeConfig related functions:** These functions (`CopyAuctionReportBuyerKeysFromIdlToMojo`, `CopyAuctionReportBuyersFromIdlToMojo`, `CopyAuctionReportBuyerDebugModeConfigFromIdlToMojo`) manage configurations for reporting buyer-specific data.
    * **RequiredSellerCapabilities related function:** This function (`CopyRequiredSellerSignalsFromIdlToMojo`) handles the seller's required capabilities.
    * **Ad Size related functions:** These functions (`ParseAdSize`, `CopyRequestedSizeFromIdlToMojo`, `CopyAllSlotsRequestedSizesFromIdlToMojo`) deal with parsing and validating ad sizes, both for single requests and for all slots.

3. **Identify relationships with web technologies:** Look for mentions of JavaScript, HTML, CSS, URLs, and origins.
    * **JavaScript:** The code interacts with JavaScript values (`blink::ScriptValue`), throws JavaScript exceptions (`V8ThrowException`), and handles promises, clearly showing a connection to JavaScript functionality. The input `AuctionAdConfig` originates from JavaScript.
    * **HTML:**  The concept of "render URLs" suggests these URLs are used in HTML to display ads.
    * **CSS:** While not explicitly mentioned in this snippet, the concept of ad sizes (px, sw, sh units) relates to how ads are displayed and styled, often involving CSS.
    * **URLs and Origins:**  The code heavily uses `KURL` and `SecurityOrigin` to validate URLs and ensure same-origin policies are respected, which are fundamental concepts in web security and how browsers handle resources.

4. **Infer logical reasoning and potential errors:** Analyze the validation logic within the functions.
    * **Input Validation:**  The code performs various checks on the input values (e.g., valid URLs, HTTPS scheme, no query parameters, valid currency codes, positive numbers).
    * **Error Handling:** When validation fails, the code throws `TypeError` exceptions, which are propagated back to the JavaScript environment.
    * **Assumptions:**  The code assumes that the input `AuctionAdConfig` adheres to a specific structure defined by the IDL.
    * **Common Errors:**  Users might provide invalid URLs, incorrect currency codes, negative or zero values where positive values are expected, or attempt to use reserved prefixes.

5. **Determine user actions to reach this code:** Think about the sequence of user actions that would trigger an ad auction.
    * A website (controlled by a seller) wants to display an ad.
    * The website uses JavaScript to call a browser API (likely `navigator.runAdAuction()`).
    * The JavaScript code provides an `AuctionAdConfig` object containing the auction parameters.
    * The browser then processes this configuration, and this C++ code is responsible for converting the JavaScript configuration to the internal representation.

6. **Summarize the functionality:** Combine the understanding of individual functions to provide a concise overview of the code's purpose.

7. **Address the "part 3 of 6" instruction:** Acknowledge that this is a specific part of a larger process and focus the summary on the actions within this part.
This code snippet, part 3 of 6 in the `navigator_auction.cc` file, primarily focuses on **transferring and validating auction configuration data from its JavaScript representation (`AuctionAdConfig`) to its internal C++ representation (`mojom::blink::AuctionAdConfig`) within the Blink rendering engine.**

Here's a breakdown of its functions:

**Core Functionality:**

* **Copying and Conversion:** The majority of the functions (e.g., `CopyDirectFromSellerSignalsFromIdlToMojo`, `CopyDeprecatedRenderURLReplacementsFromIdlToMojo`, `CopyPerBuyerSignalsFromIdlToMojo`) are responsible for taking specific fields from the JavaScript `AuctionAdConfig` object and copying their values into the corresponding fields of the `mojom::blink::AuctionAdConfig` structure. This often involves converting data types (e.g., JavaScript strings to C++ strings, JavaScript arrays to C++ vectors).
* **Validation:**  Crucially, many functions include validation logic to ensure the data provided by JavaScript is valid according to the auction specification. This includes checks for:
    * **Valid URLs:**  Ensuring URLs are well-formed, use HTTPS, and match origin requirements.
    * **Data types and formats:**  Verifying that values are of the expected type (e.g., numbers, strings) and format (e.g., currency codes).
    * **Logical constraints:** Checking for conditions like requiring `auctionNonce` when `additionalBids` is specified, or that `interestGroupBuyers` is not empty in certain scenarios.
* **Handling Promises:** Some configuration options in JavaScript can be asynchronous (represented by Promises). Functions like `CopyDirectFromSellerSignalsFromIdlToMojo` handle these Promises by scheduling handlers that will be executed when the Promise resolves. This allows the auction to proceed even if some configuration data is not immediately available.
* **Error Reporting:** When validation fails, the code uses `V8ThrowException::ThrowTypeError` to report errors back to the JavaScript environment, informing the website developer about the invalid configuration.
* **Feature Gating:**  Some features are enabled or disabled based on feature flags (e.g., `kPrivateAggregationAuctionReportBuyerDebugModeConfig`). The code checks these flags before processing related configuration options.

**Relationship with JavaScript, HTML, and CSS:**

* **JavaScript:** This code directly interacts with JavaScript. The input `AuctionAdConfig` originates from JavaScript code, likely when a website calls `navigator.runAdAuction()`. The validation errors are reported back to the JavaScript environment.
    * **Example:** The `ConvertNonPromisePerBuyerSignalsFromV8ToMojo` function takes a `blink::ScriptValue` (a representation of a JavaScript value) as input for `perBuyerSignals`. It then uses `Jsonify` to convert this JavaScript value into a JSON string.
* **HTML:** While this specific code doesn't directly manipulate HTML, the ad auction process is fundamentally about selecting and displaying ads within a webpage. The configuration options handled here (like `deprecatedRenderURLReplacements` and `requestedSize`) influence how the winning ad will be rendered in the HTML.
    * **Example:** `deprecatedRenderURLReplacements` allows for dynamic modification of the render URL, which is the URL of the HTML content of the ad.
* **CSS:** The `requestedSize` and `allSlotsRequestedSizes` options directly relate to the desired dimensions of the ad slot. These dimensions are often enforced using CSS on the webpage.
    * **Example:** If `requestedSize` is set to "{width: '300px', height: '250px'}", the browser will attempt to find an ad that matches this size, and the website's CSS might enforce these dimensions for the ad container.

**Logical Reasoning (with assumptions):**

Let's take the `ConvertNonPromiseDirectFromSellerSignalsFromV8ToMojo` function as an example:

* **Assumption Input:**  A JavaScript object for a seller's configuration within the `AuctionAdConfig` includes a `directFromSellerSignals` property with a string value, e.g., `"https://example.com/signals/"`. The `seller_origin` is `"https://example.com"`.
* **Step-by-step processing:**
    1. The function receives the `prefix_string` (e.g., `"https://example.com/signals/"`).
    2. It attempts to create a `KURL` object from this string. If the string is not a valid URL, a `TypeError` is thrown.
    3. It checks if the protocol of the URL is HTTPS and if the origin of the URL matches the `seller_origin`. If not, a `TypeError` is thrown.
    4. It checks if the URL prefix has a query string. If it does, a `TypeError` is thrown.
    5. If all checks pass, it creates a `mojom::blink::DirectFromSellerSignals` object.
    6. If `interest_group_buyers` is provided, it iterates through each buyer and constructs subresource URLs like `"https://example.com/signals/?perBuyerSignals=https%3A%2F%2Fbuyer1.com"`. It then attempts to fetch signals for each buyer.
    7. It also constructs URLs for `sellerSignals` and `auctionSignals` like `"https://example.com/signals/?sellerSignals"` and `"https://example.com/signals/?auctionSignals"` and attempts to fetch those.
* **Output:** A `mojom::blink::DirectFromSellerSignalsPtr` containing the prefix URL and potentially fetched signals for individual buyers, the seller, and the auction. If any validation fails, it returns `nullptr`.

**User/Programming Common Usage Errors:**

* **Invalid URLs in configuration:** Providing a non-HTTPS URL or a URL with a different origin for `directFromSellerSignals`.
    * **Example:** `directFromSellerSignals: "http://insecure.com/signals/"` would trigger an error.
* **Including query parameters in `directFromSellerSignals` prefix:**
    * **Example:** `directFromSellerSignals: "https://example.com/signals/?extra=param"` would cause an error.
* **Using incorrect currency codes in `perBuyerCurrencies`:**
    * **Example:** `perBuyerCurrencies: { "https://buyer.com": "USDollar" }` would result in an error because "USDollar" is not a valid 3-letter currency code.
* **Providing negative or zero values for timeouts or group limits:**
    * **Example:** `perBuyerTimeouts: { "https://buyer.com": 0 }` would throw an error.
* **Incorrectly specifying wildcard values:**  For example, using a wildcard character other than "*" in `perBuyerTimeouts`.
* **Providing a `debugKey` for `auctionReportBuyerDebugModeConfig` when debug mode is not enabled.**

**User Operations to Reach This Code (Debugging Clues):**

1. **A website implements an ad auction using the FLEDGE (or related) API:** The website's JavaScript code calls `navigator.runAdAuction()`.
2. **The website provides an `AuctionAdConfig` object as an argument to `runAdAuction()`:** This object contains the configuration for the auction.
3. **The browser's rendering engine (Blink) receives this call:** The `NavigatorAuction::RunAdAuction` method is invoked.
4. **The `AuctionAdConfig` object is passed from JavaScript to C++:**  This involves converting the JavaScript object into its C++ representation.
5. **The functions in this code snippet are called to copy and validate the data from the JavaScript `AuctionAdConfig` to the `mojom::blink::AuctionAdConfig`:**  Each function handles a specific part of the configuration.

**For debugging, if you encounter issues with ad auctions, you might:**

* **Set breakpoints in these `Copy...FromIdlToMojo` functions:** This allows you to inspect the values being passed from JavaScript and see if the validation logic is behaving as expected.
* **Examine the `ExceptionState` object:** If an exception is thrown, this object will contain information about the error.
* **Check the browser's developer console for `TypeError` messages:** These messages often indicate validation failures in this part of the code.

**Summary of Functionality (Part 3 of 6):**

This section of the code is responsible for **bridging the gap between the JavaScript representation of an ad auction configuration and its internal C++ representation within the Blink rendering engine.** It performs crucial tasks of **transferring data, validating its correctness according to the auction specification, handling asynchronous data (Promises), and reporting errors back to the JavaScript environment.** This ensures that the browser has a valid and consistent understanding of the auction parameters before proceeding with the auction process.

### 提示词
```
这是目录为blink/renderer/modules/ad_auction/navigator_auction.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
pleteURL(prefix_string);
  if (!direct_from_seller_signals_prefix.IsValid()) {
    V8ThrowException::ThrowTypeError(
        script_state->GetIsolate(),
        ErrorInvalidAuctionConfigSeller(seller_name, "directFromSellerSignals",
                                        prefix_string,
                                        "cannot be resolved to a valid URL."));
    return nullptr;
  }
  if (!direct_from_seller_signals_prefix.ProtocolIs(url::kHttpsScheme) ||
      !seller_origin.IsSameOriginWith(
          SecurityOrigin::Create(direct_from_seller_signals_prefix).get())) {
    V8ThrowException::ThrowTypeError(
        script_state->GetIsolate(),
        ErrorInvalidAuctionConfigSeller(
            seller_name, "directFromSellerSignals", prefix_string,
            "must match seller origin; only https scheme is supported."));
    return nullptr;
  }
  if (!direct_from_seller_signals_prefix.Query().empty()) {
    V8ThrowException::ThrowTypeError(
        script_state->GetIsolate(),
        ErrorInvalidAuctionConfigSeller(
            seller_name, "directFromSellerSignals", prefix_string,
            "URL prefix must not have a query string."));
    return nullptr;
  }
  auto mojo_direct_from_seller_signals =
      mojom::blink::DirectFromSellerSignals::New();
  mojo_direct_from_seller_signals->prefix = direct_from_seller_signals_prefix;

  if (interest_group_buyers) {
    for (scoped_refptr<const SecurityOrigin> buyer : *interest_group_buyers) {
      // Replace "/" with "%2F" to match the behavior of
      // base::EscapeQueryParamValue(). Also, the subresource won't be found if
      // the URL doesn't match.
      const KURL subresource_url(
          direct_from_seller_signals_prefix.GetString() + "?perBuyerSignals=" +
          EncodeWithURLEscapeSequences(buyer->ToString()).Replace("/", "%2F"));
      mojom::blink::DirectFromSellerSignalsSubresourcePtr maybe_mojo_bundle =
          TryToBuildDirectFromSellerSignalsSubresource(
              subresource_url, seller_origin, resource_fetcher);
      if (!maybe_mojo_bundle) {
        continue;  // The bundle wasn't found, try the next one.
      }
      mojo_direct_from_seller_signals->per_buyer_signals.insert(
          buyer, std::move(maybe_mojo_bundle));
    }
  }

  {
    const KURL subresource_url(direct_from_seller_signals_prefix.GetString() +
                               "?sellerSignals");
    mojom::blink::DirectFromSellerSignalsSubresourcePtr maybe_mojo_bundle =
        TryToBuildDirectFromSellerSignalsSubresource(
            subresource_url, seller_origin, resource_fetcher);
    // May be null if the signals weren't found.
    mojo_direct_from_seller_signals->seller_signals =
        std::move(maybe_mojo_bundle);
  }

  {
    const KURL subresource_url(direct_from_seller_signals_prefix.GetString() +
                               "?auctionSignals");
    mojom::blink::DirectFromSellerSignalsSubresourcePtr maybe_mojo_bundle =
        TryToBuildDirectFromSellerSignalsSubresource(
            subresource_url, seller_origin, resource_fetcher);
    // May be null if the signals weren't found.
    mojo_direct_from_seller_signals->auction_signals =
        std::move(maybe_mojo_bundle);
  }

  return mojo_direct_from_seller_signals;
}

void CopyDirectFromSellerSignalsFromIdlToMojo(
    NavigatorAuction::AuctionHandle* auction_handle,
    const mojom::blink::AuctionAdConfigAuctionId* auction_id,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasDirectFromSellerSignals()) {
    output.direct_from_seller_signals = mojom::blink::
        AuctionAdConfigMaybePromiseDirectFromSellerSignals::NewValue(nullptr);
    return;
  }

  auction_handle->QueueAttachPromiseHandler(
      MakeGarbageCollected<
          NavigatorAuction::AuctionHandle::DirectFromSellerSignalsResolved>(
          auction_handle, input.directFromSellerSignals(), auction_id->Clone(),
          input.seller(), output.seller,
          output.auction_ad_config_non_shared_params->interest_group_buyers));
  output.direct_from_seller_signals = mojom::blink::
      AuctionAdConfigMaybePromiseDirectFromSellerSignals::NewPromise(0);
}

void CopyDirectFromSellerSignalsHeaderAdSlotFromIdlToMojo(
    NavigatorAuction::AuctionHandle* auction_handle,
    const mojom::blink::AuctionAdConfigAuctionId* auction_id,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasDirectFromSellerSignalsHeaderAdSlot()) {
    output.expects_direct_from_seller_signals_header_ad_slot = false;
    return;
  }

  auction_handle->QueueAttachPromiseHandler(
      MakeGarbageCollected<NavigatorAuction::AuctionHandle::
                               DirectFromSellerSignalsHeaderAdSlotResolved>(
          auction_handle, input.directFromSellerSignalsHeaderAdSlot(),
          auction_id->Clone(), input.seller()));
  output.expects_direct_from_seller_signals_header_ad_slot = true;
}

WTF::Vector<mojom::blink::AdKeywordReplacementPtr>
ConvertNonPromiseDeprecatedRenderURLReplacementsFromV8ToMojo(
    const std::optional<Vector<std::pair<String, String>>>& input) {
  WTF::Vector<mojom::blink::AdKeywordReplacementPtr> output;
  if (!input.has_value()) {
    return output;
  }
  for (const auto& key_value_pair : *input) {
    auto local_replacement = mojom::blink::AdKeywordReplacement::New();
    local_replacement->match = std::move(key_value_pair.first);
    local_replacement->replacement = std::move(key_value_pair.second);
    output.emplace_back(std::move(local_replacement));
  }
  return output;
}

void CopyDeprecatedRenderURLReplacementsFromIdlToMojo(
    NavigatorAuction::AuctionHandle* auction_handle,
    const mojom::blink::AuctionAdConfigAuctionId* auction_id,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasDeprecatedRenderURLReplacements()) {
    // If the page passed no ad replacements, do nothing and pass an empty map.
    output.auction_ad_config_non_shared_params
        ->deprecated_render_url_replacements = mojom::blink::
        AuctionAdConfigMaybePromiseDeprecatedRenderURLReplacements::NewValue(
            {});
    return;
  }
  auction_handle->QueueAttachPromiseHandler(
      MakeGarbageCollected<NavigatorAuction::AuctionHandle::
                               DeprecatedRenderURLReplacementsResolved>(
          auction_handle, input.deprecatedRenderURLReplacements(),
          auction_id->Clone(), input.seller()));
  output.auction_ad_config_non_shared_params
      ->deprecated_render_url_replacements = mojom::blink::
      AuctionAdConfigMaybePromiseDeprecatedRenderURLReplacements::NewPromise(0);
}

bool CopyAdditionalBidsFromIdlToMojo(
    NavigatorAuction::AuctionHandle* auction_handle,
    const mojom::blink::AuctionAdConfigAuctionId* auction_id,
    ExceptionState& exception_state,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasAdditionalBids()) {
    output.expects_additional_bids = false;
    return true;
  }

  if (!input.hasAuctionNonce()) {
    exception_state.ThrowTypeError(
        String::Format("additionalBids specified for AuctionAdConfig with "
                       "seller '%s' which does not have an auctionNonce.",
                       input.seller().Utf8().c_str()));
    return false;
  }

  if (!input.hasInterestGroupBuyers() || input.interestGroupBuyers().empty()) {
    exception_state.ThrowTypeError(
        String::Format("additionalBids specified for AuctionAdConfig with "
                       "seller '%s' which has no interestGroupBuyers. All "
                       "additionalBid buyers must be in interestGroupBuyers.",
                       input.seller().Utf8().c_str()));
    return false;
  }

  auction_handle->QueueAttachPromiseHandler(
      MakeGarbageCollected<
          NavigatorAuction::AuctionHandle::AdditionalBidsResolved>(
          auction_handle, input.additionalBids(), auction_id->Clone(),
          input.seller()));
  output.expects_additional_bids = true;
  return true;
}

bool CopyAggregationCoordinatorOriginFromIdlToMojo(
    ExceptionState& exception_state,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasPrivateAggregationConfig()) {
    return true;
  }

  return GetAggregationCoordinatorFromConfig(
      exception_state, *input.privateAggregationConfig(),
      output.aggregation_coordinator_origin);
}

std::optional<
    mojom::blink::AuctionAdConfigNonSharedParams::RealTimeReportingType>
GetRealTimeReportingTypeFromConfig(
    const AuctionRealTimeReportingConfig& config) {
  mojom::blink::AuctionAdConfigNonSharedParams::RealTimeReportingType
      report_type;
  if (config.type() == "default-local-reporting") {
    report_type = mojom::blink::AuctionAdConfigNonSharedParams::
        RealTimeReportingType::kDefaultLocalReporting;
  } else {
    // Don't throw an error if an unknown type is provided to provide forward
    // compatibility with new fields added later.
    return std::nullopt;
  }
  return report_type;
}

bool CopyPerBuyerRealTimeReportingTypesFromIdlToMojo(
    ExceptionState& exception_state,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasPerBuyerRealTimeReportingConfig()) {
    return true;
  }
  output.auction_ad_config_non_shared_params
      ->per_buyer_real_time_reporting_types.emplace();
  for (const auto& per_buyer_config : input.perBuyerRealTimeReportingConfig()) {
    scoped_refptr<const SecurityOrigin> buyer =
        ParseOrigin(per_buyer_config.first);
    if (!buyer) {
      exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
          input, "perBuyerRealTimeReportingConfig buyer",
          per_buyer_config.first, "must be a valid https origin."));
      return false;
    }
    std::optional<
        mojom::blink::AuctionAdConfigNonSharedParams::RealTimeReportingType>
        type = GetRealTimeReportingTypeFromConfig(*per_buyer_config.second);
    if (type.has_value()) {
      output.auction_ad_config_non_shared_params
          ->per_buyer_real_time_reporting_types->insert(buyer, *type);
    }
  }
  return true;
}

// Returns nullopt + sets exception on failure, or returns a concrete value.
std::optional<HashMap<scoped_refptr<const SecurityOrigin>, String>>
ConvertNonPromisePerBuyerSignalsFromV8ToMojo(
    ScriptState* script_state,
    const String& seller_name,
    std::optional<HeapVector<std::pair<String, blink::ScriptValue>>> value) {
  if (!value.has_value()) {
    return std::nullopt;
  }

  std::optional<HashMap<scoped_refptr<const SecurityOrigin>, String>>
      per_buyer_signals;

  per_buyer_signals.emplace();
  for (const auto& per_buyer_signal : *value) {
    scoped_refptr<const SecurityOrigin> buyer =
        ParseOrigin(per_buyer_signal.first);
    if (!buyer) {
      V8ThrowException::ThrowTypeError(
          script_state->GetIsolate(),
          ErrorInvalidAuctionConfigSeller(seller_name, "perBuyerSignals buyer",
                                          per_buyer_signal.first,
                                          "must be a valid https origin."));
      return std::nullopt;
    }
    String buyer_signals_str;
    if (!Jsonify(*script_state, per_buyer_signal.second.V8Value(),
                 buyer_signals_str)) {
      V8ThrowException::ThrowTypeError(
          script_state->GetIsolate(),
          ErrorInvalidAuctionConfigSellerJson(seller_name, "perBuyerSignals"));
      return std::nullopt;
    }
    per_buyer_signals->insert(buyer, std::move(buyer_signals_str));
  }

  return per_buyer_signals;
}

void CopyPerBuyerSignalsFromIdlToMojo(
    NavigatorAuction::AuctionHandle* auction_handle,
    const mojom::blink::AuctionAdConfigAuctionId* auction_id,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasPerBuyerSignals()) {
    output.auction_ad_config_non_shared_params->per_buyer_signals =
        mojom::blink::AuctionAdConfigMaybePromisePerBuyerSignals::NewValue(
            std::nullopt);
    return;
  }

  auction_handle->QueueAttachPromiseHandler(
      MakeGarbageCollected<
          NavigatorAuction::AuctionHandle::PerBuyerSignalsResolved>(
          auction_handle, input.perBuyerSignals(), auction_id->Clone(),
          input.seller()));
  output.auction_ad_config_non_shared_params->per_buyer_signals =
      mojom::blink::AuctionAdConfigMaybePromisePerBuyerSignals::NewPromise(0);
}

// Returns nullptr + sets exception on failure, or returns a concrete value.
//
// This is shared logic for `perBuyerTimeouts` and `perBuyerCumulativeTimeouts`,
// with `field` indicating which name to use in error messages. The logic is
// identical in both cases.
mojom::blink::AuctionAdConfigBuyerTimeoutsPtr
ConvertNonPromisePerBuyerTimeoutsFromV8ToMojo(
    ScriptState* script_state,
    const String& seller_name,
    std::optional<Vector<std::pair<String, uint64_t>>> value,
    mojom::blink::AuctionAdConfigBuyerTimeoutField field) {
  if (!value.has_value()) {
    return mojom::blink::AuctionAdConfigBuyerTimeouts::New();
  }

  mojom::blink::AuctionAdConfigBuyerTimeoutsPtr buyer_timeouts =
      mojom::blink::AuctionAdConfigBuyerTimeouts::New();
  buyer_timeouts->per_buyer_timeouts.emplace();
  for (const auto& per_buyer_timeout : *value) {
    if (per_buyer_timeout.first == "*") {
      buyer_timeouts->all_buyers_timeout =
          base::Milliseconds(per_buyer_timeout.second);
      continue;
    }
    scoped_refptr<const SecurityOrigin> buyer =
        ParseOrigin(per_buyer_timeout.first);
    if (!buyer) {
      String field_name;
      switch (field) {
        case mojom::blink::AuctionAdConfigBuyerTimeoutField::kPerBuyerTimeouts:
          field_name = "perBuyerTimeouts buyer";
          break;
        case mojom::blink::AuctionAdConfigBuyerTimeoutField::
            kPerBuyerCumulativeTimeouts:
          field_name = "perBuyerCumulativeTimeouts buyer";
          break;
      }
      V8ThrowException::ThrowTypeError(
          script_state->GetIsolate(),
          ErrorInvalidAuctionConfigSeller(
              seller_name, field_name, per_buyer_timeout.first,
              "must be \"*\" (wildcard) or a valid https origin."));
      return mojom::blink::AuctionAdConfigBuyerTimeouts::New();
    }
    buyer_timeouts->per_buyer_timeouts->insert(
        buyer, base::Milliseconds(per_buyer_timeout.second));
  }

  return buyer_timeouts;
}

void CopyPerBuyerTimeoutsFromIdlToMojo(
    NavigatorAuction::AuctionHandle* auction_handle,
    const mojom::blink::AuctionAdConfigAuctionId* auction_id,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasPerBuyerTimeouts()) {
    output.auction_ad_config_non_shared_params->buyer_timeouts =
        mojom::blink::AuctionAdConfigMaybePromiseBuyerTimeouts::NewValue(
            mojom::blink::AuctionAdConfigBuyerTimeouts::New());
    return;
  }

  auction_handle->QueueAttachPromiseHandler(
      MakeGarbageCollected<
          NavigatorAuction::AuctionHandle::BuyerTimeoutsResolved>(
          auction_handle, input.perBuyerTimeouts(), auction_id->Clone(),
          mojom::blink::AuctionAdConfigBuyerTimeoutField::kPerBuyerTimeouts,
          input.seller()));
  output.auction_ad_config_non_shared_params->buyer_timeouts =
      mojom::blink::AuctionAdConfigMaybePromiseBuyerTimeouts::NewPromise(0);
}

void CopyPerBuyerCumulativeTimeoutsFromIdlToMojo(
    NavigatorAuction::AuctionHandle* auction_handle,
    const mojom::blink::AuctionAdConfigAuctionId* auction_id,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasPerBuyerCumulativeTimeouts()) {
    output.auction_ad_config_non_shared_params->buyer_cumulative_timeouts =
        mojom::blink::AuctionAdConfigMaybePromiseBuyerTimeouts::NewValue(
            mojom::blink::AuctionAdConfigBuyerTimeouts::New());
    return;
  }

  auction_handle->QueueAttachPromiseHandler(
      MakeGarbageCollected<
          NavigatorAuction::AuctionHandle::BuyerTimeoutsResolved>(
          auction_handle, input.perBuyerCumulativeTimeouts(),
          auction_id->Clone(),
          mojom::blink::AuctionAdConfigBuyerTimeoutField::
              kPerBuyerCumulativeTimeouts,
          input.seller()));
  output.auction_ad_config_non_shared_params->buyer_cumulative_timeouts =
      mojom::blink::AuctionAdConfigMaybePromiseBuyerTimeouts::NewPromise(0);
}

// Returns nullptr + sets exception on failure, or returns a concrete value.
mojom::blink::AuctionAdConfigBuyerCurrenciesPtr
ConvertNonPromisePerBuyerCurrenciesFromV8ToMojo(
    ScriptState* script_state,
    const String& seller_name,
    std::optional<Vector<std::pair<String, String>>> value) {
  if (!value.has_value()) {
    return mojom::blink::AuctionAdConfigBuyerCurrencies::New();
  }

  mojom::blink::AuctionAdConfigBuyerCurrenciesPtr buyer_currencies =
      mojom::blink::AuctionAdConfigBuyerCurrencies::New();
  buyer_currencies->per_buyer_currencies.emplace();
  for (const auto& per_buyer_currency : *value) {
    std::string per_buyer_currency_str = per_buyer_currency.second.Ascii();
    if (!IsValidAdCurrencyCode(per_buyer_currency_str)) {
      V8ThrowException::ThrowTypeError(
          script_state->GetIsolate(),
          ErrorInvalidAuctionConfigSeller(
              seller_name, "perBuyerCurrencies currency",
              per_buyer_currency.second,
              "must be a 3-letter uppercase currency code."));
      return mojom::blink::AuctionAdConfigBuyerCurrencies::New();
    }

    if (per_buyer_currency.first == "*") {
      buyer_currencies->all_buyers_currency =
          blink::AdCurrency::From(per_buyer_currency_str);
      continue;
    }
    scoped_refptr<const SecurityOrigin> buyer =
        ParseOrigin(per_buyer_currency.first);
    if (!buyer) {
      V8ThrowException::ThrowTypeError(
          script_state->GetIsolate(),
          ErrorInvalidAuctionConfigSeller(
              seller_name, "perBuyerCurrencies buyer", per_buyer_currency.first,
              "must be \"*\" (wildcard) or a valid https origin."));
      return mojom::blink::AuctionAdConfigBuyerCurrencies::New();
    }
    buyer_currencies->per_buyer_currencies->insert(
        buyer, blink::AdCurrency::From(per_buyer_currency_str));
  }

  return buyer_currencies;
}

void CopyPerBuyerCurrenciesFromIdlToMojo(
    NavigatorAuction::AuctionHandle* auction_handle,
    const mojom::blink::AuctionAdConfigAuctionId* auction_id,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasPerBuyerCurrencies()) {
    output.auction_ad_config_non_shared_params->buyer_currencies =
        mojom::blink::AuctionAdConfigMaybePromiseBuyerCurrencies::NewValue(
            mojom::blink::AuctionAdConfigBuyerCurrencies::New());
    return;
  }

  auction_handle->QueueAttachPromiseHandler(
      MakeGarbageCollected<
          NavigatorAuction::AuctionHandle::BuyerCurrenciesResolved>(
          auction_handle, input.perBuyerCurrencies(), auction_id->Clone(),
          input.seller()));
  output.auction_ad_config_non_shared_params->buyer_currencies =
      mojom::blink::AuctionAdConfigMaybePromiseBuyerCurrencies::NewPromise(0);
}

bool CopyPerBuyerExperimentIdsFromIdlToMojo(
    const ScriptState& script_state,
    ExceptionState& exception_state,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasPerBuyerExperimentGroupIds()) {
    return true;
  }
  for (const auto& per_buyer_experiment_id :
       input.perBuyerExperimentGroupIds()) {
    if (per_buyer_experiment_id.first == "*") {
      output.all_buyer_experiment_group_id = per_buyer_experiment_id.second;
      continue;
    }
    scoped_refptr<const SecurityOrigin> buyer =
        ParseOrigin(per_buyer_experiment_id.first);
    if (!buyer) {
      exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
          input, "perBuyerExperimentGroupIds buyer",
          per_buyer_experiment_id.first,
          "must be \"*\" (wildcard) or a valid https origin."));
      return false;
    }
    output.per_buyer_experiment_group_ids.insert(
        buyer, per_buyer_experiment_id.second);
  }

  return true;
}

bool CopyPerBuyerGroupLimitsFromIdlToMojo(
    const ScriptState& script_state,
    ExceptionState& exception_state,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasPerBuyerGroupLimits()) {
    return true;
  }
  for (const auto& per_buyer_group_limit : input.perBuyerGroupLimits()) {
    if (per_buyer_group_limit.second <= 0) {
      exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
          input, "perBuyerGroupLimits value",
          String::Number(per_buyer_group_limit.second),
          "must be greater than 0."));
      return false;
    }
    if (per_buyer_group_limit.first == "*") {
      output.auction_ad_config_non_shared_params->all_buyers_group_limit =
          per_buyer_group_limit.second;
      continue;
    }
    scoped_refptr<const SecurityOrigin> buyer =
        ParseOrigin(per_buyer_group_limit.first);
    if (!buyer) {
      exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
          input, "perBuyerGroupLimits buyer", per_buyer_group_limit.first,
          "must be \"*\" (wildcard) or a valid https origin."));
      return false;
    }
    output.auction_ad_config_non_shared_params->per_buyer_group_limits.insert(
        buyer, per_buyer_group_limit.second);
  }

  return true;
}

bool ConvertAuctionConfigPrioritySignalsFromIdlToMojo(
    ExceptionState& exception_state,
    const AuctionAdConfig& input,
    const Vector<std::pair<WTF::String, double>>& priority_signals_in,
    WTF::HashMap<WTF::String, double>& priority_signals_out) {
  for (const auto& key_value_pair : priority_signals_in) {
    if (key_value_pair.first.StartsWith("browserSignals.")) {
      exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
          input, "perBuyerPrioritySignals key", key_value_pair.first,
          "must not start with reserved \"browserSignals.\" prefix."));
      return false;
    }
    priority_signals_out.insert(key_value_pair.first, key_value_pair.second);
  }
  return true;
}

bool CopyPerBuyerPrioritySignalsFromIdlToMojo(
    ExceptionState& exception_state,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasPerBuyerPrioritySignals()) {
    return true;
  }

  output.auction_ad_config_non_shared_params->per_buyer_priority_signals
      .emplace();
  for (const auto& per_buyer_priority_signals :
       input.perBuyerPrioritySignals()) {
    WTF::HashMap<WTF::String, double> signals;
    if (!ConvertAuctionConfigPrioritySignalsFromIdlToMojo(
            exception_state, input, per_buyer_priority_signals.second,
            signals)) {
      return false;
    }
    if (per_buyer_priority_signals.first == "*") {
      output.auction_ad_config_non_shared_params->all_buyers_priority_signals =
          std::move(signals);
      continue;
    }
    scoped_refptr<const SecurityOrigin> buyer =
        ParseOrigin(per_buyer_priority_signals.first);
    if (!buyer) {
      exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
          input, "perBuyerPrioritySignals buyer",
          per_buyer_priority_signals.first,
          "must be \"*\" (wildcard) or a valid https origin."));
      return false;
    }
    output.auction_ad_config_non_shared_params->per_buyer_priority_signals
        ->insert(buyer, std::move(signals));
  }

  return true;
}

// TODO(caraitto): Consider validating keys -- no bucket base + offset
// conflicts, no overflow, etc.
bool CopyAuctionReportBuyerKeysFromIdlToMojo(
    ExecutionContext& execution_context,
    ExceptionState& exception_state,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasAuctionReportBuyerKeys()) {
    return true;
  }

  UseCounter::Count(execution_context,
                    blink::WebFeature::kFledgeAuctionReportBuyers);

  output.auction_ad_config_non_shared_params->auction_report_buyer_keys
      .emplace();
  for (const BigInt& value : input.auctionReportBuyerKeys()) {
    ASSIGN_OR_RETURN(
        auto bucket, CopyBigIntToUint128(value), [&](String error) {
          exception_state.ThrowTypeError(ErrorInvalidAuctionConfigUint(
              input, "auctionReportBuyerKeys", std::move(error)));
          return false;
        });
    output.auction_ad_config_non_shared_params->auction_report_buyer_keys
        ->push_back(std::move(bucket));
  }

  return true;
}

bool CopyAuctionReportBuyersFromIdlToMojo(
    ExecutionContext& execution_context,
    ExceptionState& exception_state,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasAuctionReportBuyers()) {
    return true;
  }

  UseCounter::Count(execution_context,
                    blink::WebFeature::kFledgeAuctionReportBuyers);

  output.auction_ad_config_non_shared_params->auction_report_buyers.emplace();
  for (const auto& [report_type_string, report_config] :
       input.auctionReportBuyers()) {
    mojom::blink::AuctionAdConfigNonSharedParams::BuyerReportType report_type;
    if (report_type_string == "interestGroupCount") {
      report_type = mojom::blink::AuctionAdConfigNonSharedParams::
          BuyerReportType::kInterestGroupCount;
    } else if (report_type_string == "bidCount") {
      report_type = mojom::blink::AuctionAdConfigNonSharedParams::
          BuyerReportType::kBidCount;
    } else if (report_type_string == "totalGenerateBidLatency") {
      report_type = mojom::blink::AuctionAdConfigNonSharedParams::
          BuyerReportType::kTotalGenerateBidLatency;
    } else if (report_type_string == "totalSignalsFetchLatency") {
      report_type = mojom::blink::AuctionAdConfigNonSharedParams::
          BuyerReportType::kTotalSignalsFetchLatency;
    } else {
      // Don't throw an error if an unknown type is provided to provide forward
      // compatibility with new fields added later.
      continue;
    }
    ASSIGN_OR_RETURN(
        auto bucket, CopyBigIntToUint128(report_config->bucket()),
        [&](String error) {
          exception_state.ThrowTypeError(ErrorInvalidAuctionConfigUint(
              input, "auctionReportBuyers", error));
          return false;
        });
    output.auction_ad_config_non_shared_params->auction_report_buyers->insert(
        report_type, mojom::blink::AuctionReportBuyersConfig::New(
                         std::move(bucket), report_config->scale()));
  }

  return true;
}

bool CopyAuctionReportBuyerDebugModeConfigFromIdlToMojo(
    ExecutionContext& execution_context,
    ExceptionState& exception_state,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!base::FeatureList::IsEnabled(
          blink::features::
              kPrivateAggregationAuctionReportBuyerDebugModeConfig) ||
      !input.hasAuctionReportBuyerDebugModeConfig()) {
    return true;
  }

  UseCounter::Count(
      execution_context,
      blink::WebFeature::kFledgeAuctionReportBuyerDebugModeConfig);

  const AuctionReportBuyerDebugModeConfig* debug_mode_config =
      input.auctionReportBuyerDebugModeConfig();
  bool enabled = debug_mode_config->enabled();
  std::optional<uint64_t> debug_key;
  if (debug_mode_config->hasDebugKeyNonNull()) {
    ASSIGN_OR_RETURN(
        debug_key, CopyBigIntToUint64(debug_mode_config->debugKeyNonNull()),
        [&](String error) {
          exception_state.ThrowTypeError(ErrorInvalidAuctionConfigUint(
              input, "auctionReportBuyerDebugModeConfig", error));
          return false;
        });
    if (!enabled) {
      exception_state.ThrowTypeError(ErrorInvalidAuctionConfigUint(
          input, "auctionReportBuyerDebugModeConfig",
          "debugKey can only be specified when debug mode is enabled."));
      return false;
    }
  }

  output.auction_ad_config_non_shared_params
      ->auction_report_buyer_debug_mode_config =
      mojom::blink::AuctionReportBuyerDebugModeConfig::New(enabled, debug_key);

  return true;
}

bool CopyRequiredSellerSignalsFromIdlToMojo(
    const ExecutionContext& execution_context,
    ExceptionState& exception_state,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  output.auction_ad_config_non_shared_params->required_seller_capabilities =
      mojom::blink::SellerCapabilities::New();
  if (!input.hasRequiredSellerCapabilities()) {
    return true;
  }

  output.auction_ad_config_non_shared_params->required_seller_capabilities =
      ConvertSellerCapabilitiesTypeFromIdlToMojo(
          execution_context, input.requiredSellerCapabilities());
  return true;
}

mojom::blink::AdSizePtr ParseAdSize(const AuctionAdConfig& input,
                                    const AuctionAdInterestGroupSize& size,
                                    const char* field_name,
                                    ExceptionState& exception_state) {
  auto [width_val, width_units] =
      blink::ParseAdSizeString(size.width().Ascii());
  auto [height_val, height_units] =
      blink::ParseAdSizeString(size.height().Ascii());
  if (width_units == blink::AdSize::LengthUnit::kInvalid) {
    exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
        input, String::Format("%s width", field_name), size.width(),
        "must use units '', 'px', 'sw', or 'sh'."));
    return mojom::blink::AdSizePtr();
  }
  if (height_units == blink::AdSize::LengthUnit::kInvalid) {
    exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
        input, String::Format("%s height", field_name), size.height(),
        "must use units '', 'px', 'sw', or 'sh'."));
    return mojom::blink::AdSizePtr();
  }
  if (width_val <= 0 || !std::isfinite(width_val)) {
    exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
        input, String::Format("%s width", field_name), size.width(),
        "must be finite and positive."));
    return mojom::blink::AdSizePtr();
  }
  if (height_val <= 0 || !std::isfinite(height_val)) {
    exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
        input, String::Format("%s height", field_name), size.height(),
        "must be finite and positive."));
    return mojom::blink::AdSizePtr();
  }
  return mojom::blink::AdSize::New(width_val, width_units, height_val,
                                   height_units);
}

bool CopyRequestedSizeFromIdlToMojo(const ExecutionContext& execution_context,
                                    ExceptionState& exception_state,
                                    const AuctionAdConfig& input,
                                    mojom::blink::AuctionAdConfig& output) {
  // This must be called before CopyAllSlotsRequestedSizesFromIdlToMojo().
  DCHECK(
      !output.auction_ad_config_non_shared_params->all_slots_requested_sizes);
  if (!input.hasRequestedSize()) {
    return true;
  }

  mojom::blink::AdSizePtr size = ParseAdSize(input, *input.requestedSize(),
                                             "requestedSize", exception_state);
  if (!size) {
    return false;
  }

  output.auction_ad_config_non_shared_params->requested_size = std::move(size);
  return true;
}

// This must be called after CopyRequestedSizeFromIdlToMojo(), since it verifies
// that if both `all_slots_requested_sizes` and `requested_size` are set, then
// the former contains the latter.
bool CopyAllSlotsRequestedSizesFromIdlToMojo(
    const ExecutionContext& execution_context,
    ExceptionState& exception_state,
    const AuctionAdConfig& input,
    mojom::blink::AuctionAdConfig& output) {
  if (!input.hasAllSlotsRequestedSizes()) {
    return true;
  }

  if (input.allSlotsRequestedSizes().empty()) {
    exception_state.ThrowTypeError(
        String::Format("allSlotsRequestedSizes for AuctionAdConfig with seller "
                       "'%s' may not be empty.",
                       input.seller().Utf8().c_str()));
    return false;
  }

  std::set<mojom::blink::AdSize> distinct_sizes;
  output.auction_ad_config_non_shared_params->all_slots_requested_sizes
      .emplace();
  for (const auto& unparsed_size : input.allSlotsRequestedSizes()) {
    mojom::blink::AdSizePtr size = ParseAdSize(
        input, *unparsed_size, "allSlotsRequestedSizes", exception_state);
    if (!size) {
      return false;
    }

    if (!distinct_sizes.insert(*size).second) {
      exception_state.ThrowTypeError(ErrorInvalidAuctionConfig(
          input, "allSlotsRequestedSizes",
          String::Format(R"({"width": "%s", "height": "%s"})",
                         unparsed_size->width().Utf8().c_str(),
                         unparsed_size->height().Utf8().c_str()),
          "must be distinct from other sizes in the list."));
```