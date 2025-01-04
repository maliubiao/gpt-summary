Response: Let's break down the thought process for analyzing the provided C++ code.

**1. Understanding the Goal:**

The initial request asks for the functionality of the `devtools_serialization.cc` file within the Chromium Blink engine. It also specifically requests connections to JavaScript, HTML, CSS, logical reasoning examples, and common usage errors.

**2. Initial Code Scan - Identifying Key Elements:**

The first step is to quickly scan the code for keywords and patterns. I notice:

* **Includes:**  `#include` directives point to external dependencies. `devtools_serialization.h`, `base/values.h`, `third_party/blink/public/common/interest_group/...`, and `mojom/interest_group/...` are prominent. This suggests the file deals with data serialization, particularly for interest groups and auction configurations, likely for developer tools.
* **Namespaces:** `namespace blink { namespace { ... } namespace blink { ... }`  This indicates the code is within the Blink rendering engine's namespace. The anonymous namespace `namespace { ... }` suggests helper functions not meant for external use.
* **Functions:**  The most prominent functions are `SerializeIntoValue` and `SerializeIntoDict`, and the top-level functions `SerializeAuctionConfigForDevtools` and `SerializeInterestGroupForDevtools`. This strongly hints at the core purpose: converting C++ data structures into a format suitable for DevTools.
* **Data Structures:**  References to `AuctionConfig`, `InterestGroup`, `url::Origin`, `GURL`, `base::TimeDelta`, `base::flat_map`, `std::optional`, `std::vector`, `base::Value`, and various enums and structs from the included headers. This confirms the focus on interest group and auction-related data.
* **String Manipulation:**  Use of `std::string_view`, `base::ToString`, and `base::Base64Encode`. This indicates data transformation into string formats.
* **Conditional Logic:**  `if` statements and `switch` statements are used, suggesting branching based on data types or values.
* **Template Usage:**  The presence of `template <typename T>` strongly suggests generic programming, allowing the serialization logic to work with different data types.

**3. Deconstructing the Functionality - "What does it do?":**

Based on the initial scan, the core functionality seems to be:

* **Serialization:** Converting complex C++ data structures (`AuctionConfig`, `InterestGroup`) into a simpler, key-value format suitable for DevTools. The use of `base::Value::Dict` and `base::Value::List` confirms this.
* **DevTools Focus:** The function names (`...ForDevtools`) explicitly state the target.
* **Interest Group and Auction Specific:** The types being serialized are directly related to the FLEDGE/Protected Audience API concepts.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

This requires understanding how FLEDGE/Protected Audience interacts with the browser and how DevTools are used.

* **JavaScript:**  The FLEDGE API is accessed and controlled via JavaScript. The data serialized by this code reflects the internal state and configurations set by JavaScript. Examples would involve:
    * `navigator.joinAdInterestGroup()`: The parameters of this function map directly to fields in `InterestGroup`.
    * `navigator.runAdAuction()`: The `AuctionConfig` parameters are set in the JavaScript auction configuration.
* **HTML:**  While not directly related to the serialization process itself, the results of an auction (rendered ads) are displayed in HTML. The serialized data helps developers understand *why* a particular ad was chosen.
* **CSS:** Similar to HTML, CSS styles the displayed ads. Again, the serialization helps developers understand the auction outcome leading to the display of a specific, styled ad.

**5. Logical Reasoning (Assumptions and Outputs):**

This involves tracing the code flow for specific inputs. The template nature of the code requires focusing on concrete examples:

* **Example 1 (Simple String):**  If `SerializeIntoValue` receives a `std::string`, it will return a `base::Value` of type string with the same content.
* **Example 2 (URL):**  If it receives a `GURL`, it will extract the URL string using `.spec()` and return that in a `base::Value`.
* **Example 3 (Optional Value):**  If it receives `std::optional<int>{5}`, it will serialize the `5`. If it receives an empty `std::optional<int>`, it will return an empty `base::Value`.
* **Example 4 (Flat Map):**  For a `base::flat_map<std::string, int>`, the keys and values will be recursively serialized into a `base::Value::Dict`.

**6. Common Usage Errors:**

This requires thinking about how developers might interact with the data *represented* by this code, even though they don't directly call these C++ functions. The errors stem from misunderstandings of the FLEDGE API or incorrect configuration:

* **Incorrect URLs:**  Providing malformed URLs for bidding logic, update URLs, etc.
* **Mismatched Data Types:** Providing data that doesn't match the expected types in the FLEDGE API calls.
* **Invalid Timeouts:** Setting timeout values that are too short or too long.
* **Incorrectly Formatted Metadata:** Providing metadata in the wrong JSON format.

**7. Structuring the Answer:**

Finally, organizing the findings into a clear and structured answer is crucial. This involves:

* **Starting with a concise summary of the file's purpose.**
* **Listing the key functionalities.**
* **Providing concrete examples for connections to JavaScript, HTML, and CSS.**
* **Giving clear "Assumption -> Output" examples for logical reasoning.**
* **Listing specific and understandable common usage errors.**

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This just converts data to JSON."  **Correction:** While it converts to a JSON-like structure (`base::Value`), the primary purpose is for DevTools inspection, not general-purpose JSON serialization.
* **Initial thought:** "The connections to web tech are direct." **Correction:** The connection is indirect. This code serializes internal state *resulting from* JavaScript API calls and influences what is displayed in HTML/CSS.
* **Focusing too much on the C++ implementation details.** **Correction:** Shift the focus to the *user-facing* implications and how this code helps developers using DevTools.

By following this thought process, combining code analysis with an understanding of the broader context (FLEDGE, DevTools), and refining the initial assumptions, we arrive at a comprehensive and accurate answer.
这个文件 `blink/common/interest_group/devtools_serialization.cc` 的主要功能是将 Blink 引擎中与 **Interest Group API (也称为 FLEDGE 或 Protected Audience API)** 相关的 C++ 数据结构序列化为 **DevTools (开发者工具)** 可以理解的格式。 它的目的是为了方便开发者在 Chrome 的 DevTools 中查看和调试 Interest Group 的状态和拍卖配置等信息。

**具体功能列举:**

1. **序列化 AuctionConfig:**  `SerializeAuctionConfigForDevtools` 函数负责将 `AuctionConfig` 对象（代表一次广告拍卖的配置信息）序列化成 `base::Value::Dict` 类型的字典。这个字典包含了拍卖的各种参数，例如：
    * 卖方 (seller) 的信息
    * 服务器响应配置 (serverResponse)
    * 决策逻辑 URL (decisionLogicURL)
    * 受信任的评分信号 URL (trustedScoringSignalsURL)
    * 买方 (buyer) 列表 (interestGroupBuyers)
    * 拍卖信号 (auctionSignals)
    * 卖方信号 (sellerSignals)
    * 超时设置 (timeouts)
    * 货币设置 (currencies)
    * 报告配置 (reporting configuration)
    * 大小限制 (size limits)
    * 以及其他更高级的配置选项。

2. **序列化 InterestGroup:** `SerializeInterestGroupForDevtools` 函数负责将 `InterestGroup` 对象（代表一个用户所属的兴趣组）序列化成 `base::Value::Dict` 类型的字典。这个字典包含了兴趣组的各种属性，例如：
    * 过期时间 (expirationTime)
    * 所有者 (ownerOrigin)
    * 名称 (name)
    * 优先级 (priority)
    * 竞价逻辑 URL (biddingLogicURL)
    * 更新 URL (updateURL)
    * 受信任的竞价信号 URL (trustedBiddingSignalsURL)
    * 受信任的竞价信号键 (trustedBiddingSignalsKeys)
    * 用户竞价信号 (userBiddingSignals)
    * 广告列表 (ads)
    * 广告组件列表 (adComponents)
    * 允许的广告尺寸 (adSizes, sizeGroups)
    * 拍卖服务器请求标志 (auctionServerRequestFlags)
    * 其他配置信息。

3. **提供通用的序列化辅助函数:** 文件中定义了许多模板函数 `SerializeIntoValue` 和 `SerializeIntoDict`，用于将不同类型的 C++ 数据类型（例如 `url::Origin`, `GURL`, `std::string`, `int`, `double`, `base::TimeDelta`, `std::optional`, `base::flat_map`, `std::vector` 等）转换为 `base::Value` 可以表示的类型。这些辅助函数使得序列化 `AuctionConfig` 和 `InterestGroup` 的过程更加简洁和可维护。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件本身是用 C++ 编写的，主要负责 Blink 引擎内部的数据序列化，并不直接与 JavaScript, HTML, CSS 代码交互。但是，它序列化的数据正是 JavaScript API (例如 `navigator.joinAdInterestGroup()`, `navigator.runAdAuction()`) 操作的对象，并且这些操作最终会影响到浏览器渲染的 HTML 和 CSS。

* **JavaScript:**
    * **功能关系:** 当 JavaScript 代码调用 `navigator.joinAdInterestGroup()` 创建或更新一个兴趣组时，传递给该函数的参数（例如 `name`, `biddingLogicUrl`, `ads` 等）会被存储在 Blink 引擎的 `InterestGroup` 对象中。 `SerializeInterestGroupForDevtools` 函数会将这些信息提取并序列化，以便开发者在 DevTools 的 "Application" -> "Interest Groups" 面板中看到这些 JavaScript 代码设置的属性。
    * **举例:**  假设以下 JavaScript 代码执行：
        ```javascript
        navigator.joinAdInterestGroup({
          name: 'my-product-ads',
          owner: 'https://example.com',
          biddingLogicUrl: 'https://example.com/bid.js',
          ads: [{ renderUrl: 'https://example.com/ad1.html', metadata: { productId: 123 } }]
        }, 3600);
        ```
        `SerializeInterestGroupForDevtools` 会将 `name`, `owner`, `biddingLogicUrl`, 以及 `ads` 数组中的 `renderUrl` 和 `metadata` 序列化成 DevTools 可以显示的格式。

    * **假设输入:** 一个包含上述 JavaScript 代码创建的 `InterestGroup` 对象的 C++ 数据结构。
    * **输出:**  一个 `base::Value::Dict`，其中包含类似以下的键值对：
        ```json
        {
          "name": "my-product-ads",
          "ownerOrigin": "https://example.com",
          "biddingLogicURL": "https://example.com/bid.js",
          "ads": [
            {
              "renderURL": "https://example.com/ad1.html",
              "metadata": {
                "productId": 123
              }
            }
          ]
          // ... 其他属性
        }
        ```

* **HTML:**
    * **功能关系:**  Interest Group API 的最终目的是展示相关的广告。当广告拍卖成功后，胜出的广告的 `renderUrl` 会被用于渲染 HTML 内容。 DevTools 中显示的 `AuctionConfig` 和 `InterestGroup` 信息可以帮助开发者理解为什么选择了特定的广告进行展示。
    * **举例:**  如果一个广告拍卖根据特定的 `AuctionConfig` 配置和 `InterestGroup` 的 `ads` 列表，最终选择了 `https://example.com/ad1.html` 这个 URL 的广告，那么 `SerializeAuctionConfigForDevtools` 和 `SerializeInterestGroupForDevtools` 序列化的信息可以帮助开发者追溯这个决策过程。

* **CSS:**
    * **功能关系:**  与 HTML 类似，CSS 负责广告的样式。虽然序列化过程不直接涉及 CSS 代码，但通过 DevTools 查看拍卖配置和兴趣组信息，开发者可以了解广告选择的上下文，这有助于他们理解为什么某个特定样式的广告被展示出来。

**逻辑推理的假设输入与输出:**

以下是一些更细致的逻辑推理示例：

1. **假设输入 (AuctionConfig):**  一个 `AuctionConfig` 对象，其 `non_shared_params.per_buyer_timeouts` 成员包含以下数据：
    ```cpp
    base::flat_map<url::Origin, base::TimeDelta> per_buyer_timeouts = {
        { url::Origin::Create(GURL("https://buyer1.com")), base::Milliseconds(100) },
        { url::Origin::Create(GURL("https://buyer2.com")), base::Milliseconds(200) }
    };
    ```
    并且 `non_shared_params.all_buyers_timeout` 是 `std::nullopt`。

    **输出:** `SerializeAuctionConfigForDevtools` 会生成一个包含以下结构的 `base::Value::Dict`:
    ```json
    {
      // ... 其他字段
      "perBuyerTimeouts": {
        "https://buyer1.com": 0.1,
        "https://buyer2.com": 0.2
      },
      // ...
    }
    ```

2. **假设输入 (InterestGroup):** 一个 `InterestGroup` 对象，其 `ads` 成员包含以下数据：
    ```cpp
    std::vector<InterestGroup::Ad> ads = {
        { GURL("https://adserver.com/ad1.html"), "{\"price\": 1.0}" },
        { GURL("https://adserver.com/ad2.html"), "{\"price\": 1.5}" }
    };
    ```

    **输出:** `SerializeInterestGroupForDevtools` 会生成一个包含以下结构的 `base::Value::Dict`:
    ```json
    {
      // ... 其他字段
      "ads": [
        {
          "renderURL": "https://adserver.com/ad1.html",
          "metadata": "{\"price\": 1.0}"
        },
        {
          "renderURL": "https://adserver.com/ad2.html",
          "metadata": "{\"price\": 1.5}"
        }
      ]
      // ...
    }
    ```

**涉及用户或编程常见的使用错误及举例说明:**

虽然这个 C++ 文件本身不容易直接导致用户或编程错误，但它序列化的信息可以帮助开发者发现他们在 JavaScript 代码中或者在服务器配置中可能犯的错误。

1. **URL 拼写错误或无效的 URL:**
    * **错误:**  在 JavaScript 的 `joinAdInterestGroup` 中提供的 `biddingLogicUrl` 或广告的 `renderUrl` 拼写错误，或者指向一个不存在的资源。
    * **DevTools 中的体现:**  通过查看 DevTools 中序列化的 `InterestGroup` 对象，开发者可以检查 `biddingLogicURL` 和 `ads` 中的 `renderURL` 是否正确。

2. **metadata 格式错误:**
    * **错误:**  在 JavaScript 中提供的广告 `metadata` 不是有效的 JSON 字符串。
    * **DevTools 中的体现:**  序列化后的 `metadata` 会以字符串形式显示在 DevTools 中。如果格式不正确，开发者可能会看到一些异常的字符或者无法解析的结构。

3. **超时配置不当:**
    * **错误:**  在 `runAdAuction` 中设置了过短的超时时间，导致竞价逻辑或评分逻辑没有足够的时间执行完成。
    * **DevTools 中的体现:**  通过查看序列化的 `AuctionConfig`，开发者可以检查 `sellerTimeout`, `perBuyerTimeouts` 等超时配置是否合理。

4. **对 Interest Group 的理解偏差:**
    * **错误:**  开发者可能对 Interest Group 的生命周期、更新机制或者权限模型理解有误，导致他们期望的行为与实际不符。
    * **DevTools 中的体现:**  通过查看 DevTools 中 Interest Group 的 `expirationTime`, `ownerOrigin` 等信息，开发者可以更好地理解 Interest Group 的状态，从而发现潜在的逻辑错误。

总之，`devtools_serialization.cc` 文件在 Blink 引擎中扮演着重要的角色，它将复杂的内部数据结构转化为开发者友好的格式，方便了 Interest Group API 的调试和理解，间接地帮助开发者避免了常见的编程错误和配置问题。

Prompt: 
```
这是目录为blink/common/interest_group/devtools_serialization.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/interest_group/devtools_serialization.h"

#include <cmath>
#include <string_view>
#include <tuple>

#include "base/base64.h"
#include "base/strings/to_string.h"
#include "base/values.h"
#include "third_party/blink/public/common/interest_group/ad_display_size_utils.h"
#include "third_party/blink/public/common/interest_group/auction_config.h"
#include "third_party/blink/public/common/interest_group/interest_group.h"
#include "third_party/blink/public/mojom/interest_group/ad_auction_service.mojom.h"

namespace blink {

namespace {

std::string SerializeIntoKey(const url::Origin& in) {
  return in.Serialize();
}

std::string SerializeIntoKey(const std::string& in) {
  return in;
}

using BuyerReportType = AuctionConfig::NonSharedParams::BuyerReportType;
std::string SerializeIntoKey(BuyerReportType report_type) {
  switch (report_type) {
    case BuyerReportType::kInterestGroupCount:
      return "interestGroupCount";
    case BuyerReportType::kBidCount:
      return "bidCount";
    case BuyerReportType::kTotalGenerateBidLatency:
      return "totalGenerateBidLatency";
    case BuyerReportType::kTotalSignalsFetchLatency:
      return "totalSignalsFetchLatency";
  };
  NOTREACHED();
}

using RealTimeReportingType =
    AuctionConfig::NonSharedParams::RealTimeReportingType;
std::string SerializeIntoValue(RealTimeReportingType report_type) {
  switch (report_type) {
    case RealTimeReportingType::kDefaultLocalReporting:
      return "default-local-reporting";
  };
  NOTREACHED();
}

template <typename T>
base::Value SerializeIntoValue(const T& in) {
  return base::Value(in);
}

// Forward declare for mutual recursion.
template <typename K, typename V>
base::Value SerializeIntoValue(const base::flat_map<K, V>&);

template <typename T>
void SerializeIntoDict(std::string_view field,
                       const T& value,
                       base::Value::Dict& out);

template <typename T>
void SerializeIntoDict(std::string_view field,
                       const std::optional<T>& value,
                       base::Value::Dict& out);

template <typename T>
base::Value SerializeIntoValue(const std::optional<T>& value) {
  if (value.has_value()) {
    return SerializeIntoValue(*value);
  } else {
    return base::Value();
  }
}

template <>
base::Value SerializeIntoValue(const url::Origin& value) {
  return base::Value(value.Serialize());
}

template <>
base::Value SerializeIntoValue(const GURL& value) {
  return base::Value(value.spec());
}

template <>
base::Value SerializeIntoValue(const base::TimeDelta& value) {
  return base::Value(value.InMillisecondsF());
}

template <>
base::Value SerializeIntoValue(const absl::uint128& value) {
  return base::Value(base::ToString(value));
}

template <>
base::Value SerializeIntoValue(
    const blink::AuctionConfig::AdKeywordReplacement& value) {
  base::Value::Dict result;
  result.Set("match", SerializeIntoValue(value.match));
  result.Set("replacement", SerializeIntoValue(value.replacement));
  return base::Value(std::move(result));
}

template <>
base::Value SerializeIntoValue(const double& value) {
  // base::Value, like JSON, can only store finite numbers, so we encode the
  // rest as strings.
  if (std::isfinite(value)) {
    return base::Value(value);
  }
  if (std::isnan(value)) {
    return base::Value("NaN");
  }
  if (std::signbit(value)) {
    return base::Value("-Infinity");
  } else {
    return base::Value("Infinity");
  }
}

template <>
base::Value SerializeIntoValue(
    const AuctionConfig::NonSharedParams::AuctionReportBuyersConfig& value) {
  base::Value::Dict result;
  result.Set("bucket", SerializeIntoValue(value.bucket));
  result.Set("scale", SerializeIntoValue(value.scale));
  return base::Value(std::move(result));
}

template <>
base::Value SerializeIntoValue(const SellerCapabilitiesType& value) {
  base::Value::List result;
  for (blink::SellerCapabilities cap : value) {
    switch (cap) {
      case blink::SellerCapabilities::kInterestGroupCounts:
        result.Append("interest-group-counts");
        break;
      case blink::SellerCapabilities::kLatencyStats:
        result.Append("latency-stats");
        break;
    }
  }
  return base::Value(std::move(result));
}

template <>
base::Value SerializeIntoValue(const base::Uuid& uuid) {
  return base::Value(uuid.AsLowercaseString());
}

template <>
base::Value SerializeIntoValue(
    const blink::AuctionConfig::ServerResponseConfig& server_config) {
  base::Value::Dict result;
  result.Set("requestId", SerializeIntoValue(server_config.request_id));
  return base::Value(std::move(result));
}

template <typename T>
base::Value SerializeIntoValue(const std::vector<T>& values) {
  base::Value::List out;
  for (const T& in_val : values) {
    out.Append(SerializeIntoValue(in_val));
  }
  return base::Value(std::move(out));
}

template <typename T>
base::Value SerializeIntoValue(const AuctionConfig::MaybePromise<T>& promise) {
  base::Value::Dict result;
  result.Set("pending", promise.is_promise());
  if (!promise.is_promise()) {
    result.Set("value", SerializeIntoValue(promise.value()));
  }
  return base::Value(std::move(result));
}

template <>
base::Value SerializeIntoValue(
    const AuctionConfig::NonSharedParams::AuctionReportBuyerDebugModeConfig&
        value) {
  base::Value::Dict result;
  result.Set("enabled", value.is_enabled);
  if (value.debug_key.has_value()) {
    // debug_key is uint64, so it doesn't fit into regular JS numeric types.
    result.Set("debugKey", base::ToString(value.debug_key.value()));
  }
  return base::Value(std::move(result));
}

template <typename K, typename V>
base::Value SerializeIntoValue(const base::flat_map<K, V>& value) {
  base::Value::Dict result;
  for (const auto& kv : value) {
    result.Set(SerializeIntoKey(kv.first), SerializeIntoValue(kv.second));
  }
  return base::Value(std::move(result));
}

// Helper to put the split out all_/'*' value back into a single map.
// Annoyingly we are quite inconsistent about how optional is used. This handles
// both cases for the map; for the value the caller can just use make_optional.
template <typename T>
base::Value::Dict SerializeSplitMapHelper(
    const std::optional<T>& all_value,
    const std::optional<base::flat_map<url::Origin, T>>& per_values) {
  base::Value::Dict result;
  if (all_value.has_value()) {
    result.Set("*", SerializeIntoValue(*all_value));
  }
  if (per_values.has_value()) {
    for (const auto& kv : *per_values) {
      result.Set(SerializeIntoKey(kv.first), SerializeIntoValue(kv.second));
    }
  }

  return result;
}

template <typename T>
base::Value::Dict SerializeSplitMapHelper(
    const std::optional<T>& all_value,
    const base::flat_map<url::Origin, T>& per_values) {
  base::Value::Dict result;
  if (all_value.has_value()) {
    result.Set("*", SerializeIntoValue(*all_value));
  }

  for (const auto& kv : per_values) {
    result.Set(SerializeIntoKey(kv.first), SerializeIntoValue(kv.second));
  }

  return result;
}

template <>
base::Value SerializeIntoValue(const AuctionConfig::BuyerTimeouts& in) {
  return base::Value(
      SerializeSplitMapHelper(in.all_buyers_timeout, in.per_buyer_timeouts));
}

template <>
base::Value SerializeIntoValue(const AuctionConfig::BuyerCurrencies& in) {
  return base::Value(
      SerializeSplitMapHelper(in.all_buyers_currency, in.per_buyer_currencies));
}

template <>
base::Value SerializeIntoValue(const AdCurrency& in) {
  return base::Value(in.currency_code());
}

template <>
base::Value SerializeIntoValue(const AdSize& ad_size) {
  base::Value::Dict result;
  result.Set("width",
             ConvertAdDimensionToString(ad_size.width, ad_size.width_units));
  result.Set("height",
             ConvertAdDimensionToString(ad_size.height, ad_size.height_units));
  return base::Value(std::move(result));
}

template <>
base::Value SerializeIntoValue(
    const blink::mojom::InterestGroup::ExecutionMode& in) {
  switch (in) {
    case blink::mojom::InterestGroup::ExecutionMode::kCompatibilityMode:
      return SerializeIntoValue("compatibility");

    case blink::mojom::InterestGroup::ExecutionMode::kGroupedByOriginMode:
      return SerializeIntoValue("group-by-origin");

    case blink::mojom::InterestGroup::ExecutionMode::kFrozenContext:
      return SerializeIntoValue("frozen-context");
  }
}

template <>
base::Value SerializeIntoValue(const InterestGroup::AdditionalBidKey& in) {
  return base::Value(base::Base64Encode(in));
}

template <>
base::Value SerializeIntoValue(const InterestGroup::Ad& ad) {
  base::Value::Dict result;
  SerializeIntoDict("renderURL", ad.render_url(), result);
  SerializeIntoDict("metadata", ad.metadata, result);
  SerializeIntoDict("buyerReportingId", ad.buyer_reporting_id, result);
  SerializeIntoDict("buyerAndSellerReportingId",
                    ad.buyer_and_seller_reporting_id, result);
  SerializeIntoDict("selectableBuyerAndSellerReportingIds",
                    ad.selectable_buyer_and_seller_reporting_ids, result);
  SerializeIntoDict("adRenderId", ad.ad_render_id, result);
  SerializeIntoDict("allowedReportingOrigins", ad.allowed_reporting_origins,
                    result);
  return base::Value(std::move(result));
}

template <>
base::Value SerializeIntoValue(const AuctionServerRequestFlags& flags) {
  base::Value::List result;
  for (auto flag : flags) {
    switch (flag) {
      case AuctionServerRequestFlagsEnum::kOmitAds:
        result.Append("omit-ads");
        break;

      case AuctionServerRequestFlagsEnum::kIncludeFullAds:
        result.Append("include-full-ads");
        break;
      case AuctionServerRequestFlagsEnum::kOmitUserBiddingSignals:
        result.Append("omit-user-bidding-signals");
        break;
    }
  }
  return base::Value(std::move(result));
}

template <typename T>
void SerializeIntoDict(std::string_view field,
                       const T& value,
                       base::Value::Dict& out) {
  out.Set(field, SerializeIntoValue(value));
}

// Unlike the value serializer this just makes the field not set, rather than
// explicitly null.
template <typename T>
void SerializeIntoDict(std::string_view field,
                       const std::optional<T>& value,
                       base::Value::Dict& out) {
  if (value.has_value()) {
    out.Set(field, SerializeIntoValue(*value));
  }
}

// For use with SerializeSplitMapHelper.
void SerializeIntoDict(std::string_view field,
                       base::Value::Dict value,
                       base::Value::Dict& out) {
  out.Set(field, std::move(value));
}

}  // namespace

base::Value::Dict SerializeAuctionConfigForDevtools(const AuctionConfig& conf) {
  base::Value::Dict result;
  SerializeIntoDict("seller", conf.seller, result);
  SerializeIntoDict("serverResponse", conf.server_response, result);
  SerializeIntoDict("decisionLogicURL", conf.decision_logic_url, result);
  SerializeIntoDict("trustedScoringSignalsURL",
                    conf.trusted_scoring_signals_url, result);
  SerializeIntoDict("deprecatedRenderURLReplacements",
                    conf.non_shared_params.deprecated_render_url_replacements,
                    result);
  SerializeIntoDict("interestGroupBuyers",
                    conf.non_shared_params.interest_group_buyers, result);
  SerializeIntoDict("auctionSignals", conf.non_shared_params.auction_signals,
                    result);
  SerializeIntoDict("sellerSignals", conf.non_shared_params.seller_signals,
                    result);
  SerializeIntoDict("sellerTimeout", conf.non_shared_params.seller_timeout,
                    result);
  SerializeIntoDict("perBuyerSignals", conf.non_shared_params.per_buyer_signals,
                    result);
  SerializeIntoDict("perBuyerTimeouts", conf.non_shared_params.buyer_timeouts,
                    result);
  SerializeIntoDict("perBuyerCumulativeTimeouts",
                    conf.non_shared_params.buyer_cumulative_timeouts, result);
  SerializeIntoDict("reportingTimeout",
                    conf.non_shared_params.reporting_timeout, result);
  SerializeIntoDict("sellerCurrency", conf.non_shared_params.seller_currency,
                    result);
  SerializeIntoDict("perBuyerCurrencies",
                    conf.non_shared_params.buyer_currencies, result);
  SerializeIntoDict(
      "perBuyerGroupLimits",
      SerializeSplitMapHelper(
          std::make_optional(conf.non_shared_params.all_buyers_group_limit),
          conf.non_shared_params.per_buyer_group_limits),
      result);
  SerializeIntoDict("perBuyerPrioritySignals",
                    SerializeSplitMapHelper(
                        conf.non_shared_params.all_buyers_priority_signals,
                        conf.non_shared_params.per_buyer_priority_signals),
                    result);
  SerializeIntoDict("auctionReportBuyerKeys",
                    conf.non_shared_params.auction_report_buyer_keys, result);
  SerializeIntoDict("auctionReportBuyers",
                    conf.non_shared_params.auction_report_buyers, result);
  SerializeIntoDict("requiredSellerCapabilities",
                    conf.non_shared_params.required_seller_capabilities,
                    result);
  SerializeIntoDict(
      "auctionReportBuyerDebugModeConfig",
      conf.non_shared_params.auction_report_buyer_debug_mode_config, result);
  SerializeIntoDict("requestedSize", conf.non_shared_params.requested_size,
                    result);
  SerializeIntoDict("allSlotsRequestedSizes",
                    conf.non_shared_params.all_slots_requested_sizes, result);
  SerializeIntoDict(
      "perBuyerMultiBidLimit",
      SerializeSplitMapHelper(
          std::make_optional(conf.non_shared_params.all_buyers_multi_bid_limit),
          conf.non_shared_params.per_buyer_multi_bid_limits),
      result);
  SerializeIntoDict("auctionNonce", conf.non_shared_params.auction_nonce,
                    result);
  SerializeIntoDict("sellerRealTimeReportingType",
                    conf.non_shared_params.seller_real_time_reporting_type,
                    result);
  SerializeIntoDict("perBuyerRealTimeReportingTypes",
                    conf.non_shared_params.per_buyer_real_time_reporting_types,
                    result);

  // For component auctions, we only serialize the seller names to give a
  // quick overview, since they'll get their own events.
  if (!conf.non_shared_params.component_auctions.empty()) {
    base::Value::List component_auctions;
    for (const auto& child_config : conf.non_shared_params.component_auctions) {
      component_auctions.Append(child_config.seller.Serialize());
    }
    result.Set("componentAuctions", std::move(component_auctions));
  }

  SerializeIntoDict(
      "maxTrustedScoringSignalsURLLength",
      conf.non_shared_params.max_trusted_scoring_signals_url_length, result);

  SerializeIntoDict("trustedScoringSignalsCoordinator",
                    conf.non_shared_params.trusted_scoring_signals_coordinator,
                    result);

  // direct_from_seller_signals --- skipped.
  SerializeIntoDict("expectsDirectFromSellerSignalsHeaderAdSlot",
                    conf.expects_direct_from_seller_signals_header_ad_slot,
                    result);
  SerializeIntoDict("sellerExperimentGroupId", conf.seller_experiment_group_id,
                    result);
  SerializeIntoDict(
      "perBuyerExperimentGroupIds",
      SerializeSplitMapHelper(conf.all_buyer_experiment_group_id,
                              conf.per_buyer_experiment_group_ids),
      result);
  SerializeIntoDict("expectsAdditionalBids", conf.expects_additional_bids,
                    result);
  SerializeIntoDict("aggregationCoordinatorOrigin",
                    conf.aggregation_coordinator_origin, result);

  return result;
}

base::Value::Dict SerializeInterestGroupForDevtools(const InterestGroup& ig) {
  base::Value::Dict result;
  // This used to have its own type in Devtools protocol
  // ("InterestGroupDetails"); the fields that existed there are named to match;
  // otherwise the WebIDL is generally followed.
  SerializeIntoDict("expirationTime", ig.expiry.InSecondsFSinceUnixEpoch(),
                    result);
  SerializeIntoDict("ownerOrigin", ig.owner, result);
  SerializeIntoDict("name", ig.name, result);

  SerializeIntoDict("priority", ig.priority, result);
  SerializeIntoDict("enableBiddingSignalsPrioritization",
                    ig.enable_bidding_signals_prioritization, result);
  SerializeIntoDict("priorityVector", ig.priority_vector, result);
  SerializeIntoDict("prioritySignalsOverrides", ig.priority_signals_overrides,
                    result);

  SerializeIntoDict(
      "sellerCapabilities",
      SerializeSplitMapHelper(std::make_optional(ig.all_sellers_capabilities),
                              ig.seller_capabilities),
      result);
  SerializeIntoDict("executionMode", ig.execution_mode, result);

  SerializeIntoDict("biddingLogicURL", ig.bidding_url, result);
  SerializeIntoDict("biddingWasmHelperURL", ig.bidding_wasm_helper_url, result);
  SerializeIntoDict("updateURL", ig.update_url, result);
  SerializeIntoDict("trustedBiddingSignalsURL", ig.trusted_bidding_signals_url,
                    result);
  SerializeIntoDict("trustedBiddingSignalsKeys",
                    ig.trusted_bidding_signals_keys, result);

  SerializeIntoDict("trustedBiddingSignalsSlotSizeMode",
                    InterestGroup::TrustedBiddingSignalsSlotSizeModeToString(
                        ig.trusted_bidding_signals_slot_size_mode),
                    result);
  SerializeIntoDict("maxTrustedBiddingSignalsURLLength",
                    ig.max_trusted_bidding_signals_url_length, result);
  SerializeIntoDict("trustedBiddingSignalsCoordinator",
                    ig.trusted_bidding_signals_coordinator, result);
  SerializeIntoDict("userBiddingSignals", ig.user_bidding_signals, result);
  SerializeIntoDict("ads", ig.ads, result);
  SerializeIntoDict("adComponents", ig.ad_components, result);
  SerializeIntoDict("adSizes", ig.ad_sizes, result);
  SerializeIntoDict("sizeGroups", ig.size_groups, result);
  SerializeIntoDict("auctionServerRequestFlags",
                    ig.auction_server_request_flags, result);
  SerializeIntoDict("additionalBidKey", ig.additional_bid_key, result);
  SerializeIntoDict("aggregationCoordinatorOrigin",
                    ig.aggregation_coordinator_origin, result);

  return result;
}

}  // namespace blink

"""

```