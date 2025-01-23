Response: Let's break down the thought process for analyzing the `interest_group.cc` file.

1. **Understand the Core Purpose:** The filename `interest_group.cc` and the namespace `blink` immediately suggest this file is central to the Interest Group API within the Chromium Blink engine. Interest Groups are a key component of the Privacy Sandbox's Protected Audience API (formerly FLEDGE).

2. **Identify Key Data Structures:**  The first include, `interest_group.h`, is a huge hint. Looking at the provided code, the primary class is `InterestGroup` and its nested class `Ad`. These are the fundamental building blocks.

3. **Analyze the `InterestGroup` Class:**  Read through the member variables of the `InterestGroup` class. Note the types and names. This reveals the core attributes of an interest group:
    * `owner`: The website that owns the group.
    * `name`:  A user-defined name for the group.
    * Various URLs (`bidding_url`, `update_url`, etc.):  URLs used for bidding, updating, and fetching trusted signals.
    * `ads` and `ad_components`:  The actual ads associated with the group.
    * `priority`, `priority_vector`, `priority_signals_overrides`: Mechanisms for prioritizing bids.
    * `seller_capabilities`, `all_sellers_capabilities`: Controls over which sellers can participate.
    * `execution_mode`:  Different ways the bidding process can execute.
    * Trusted signals related fields (`trusted_bidding_signals_url`, `trusted_bidding_signals_keys`, etc.).
    * Size-related fields (`ad_sizes`, `size_groups`).
    * Security and privacy features (`additional_bid_key`, `aggregation_coordinator_origin`).

4. **Analyze the `Ad` Class:** Examine the members of the `Ad` class:
    * `render_url_`: The URL where the ad content is fetched.
    * `metadata`:  Arbitrary data associated with the ad.
    * `size_group`:  A reference to a predefined size group.
    * Reporting IDs (`buyer_reporting_id`, `buyer_and_seller_reporting_id`, `selectable_buyer_and_seller_reporting_ids`): Used for reporting auction outcomes.
    * `ad_render_id`: A unique identifier for the ad render.
    * `allowed_reporting_origins`: Limits where reporting data can be sent.

5. **Identify Key Functions:**  Scan the methods of both classes and standalone functions. Group them by functionality:
    * **Constructors/Destructors/Assignment:** Basic object lifecycle management.
    * **Validation (`IsValid`):**  Crucial for ensuring the integrity of the `InterestGroup` data. Pay close attention to the checks performed.
    * **Size Estimation (`EstimateSize`):** Important for resource management and preventing excessively large interest groups.
    * **URL Handling (`IsUrlAllowed`, `IsUrlAllowedForRenderUrls`, `IsUrlAllowedForTrustedBiddingSignals`):**  Focus on the security and origin restrictions.
    * **K-Anonymity Key Generation (`DEPRECATED_KAnonKeyForAdBid`, `HashedKAnonKeyForAdBid`, `HashedKAnonKeyForAdComponentBid`, `DEPRECATED_KAnonKeyForAdNameReporting`, `HashedKAnonKeyForAdNameReporting`, `HashedKAnonKeyForAdNameReportingWithoutInterestGroup`):**  These are vital for privacy, ensuring that reporting data isn't directly linkable to individual users. Note the different variations for different reporting scenarios.
    * **Helper Functions (`EstimateFlatMapSize`, `AppendReportingIdForSelectedReportingKeyKAnonKey`, `InternalPlainTextKAnonKeyForAdNameReporting`):** Understand their roles in supporting the main functions.
    * **Enum Conversion (`TrustedBiddingSignalsSlotSizeModeToString`):**  Simple utility for converting enum values to strings.
    * **Comparison (`operator==` in `Ad`):** For equality checks.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):** Now, think about how these C++ structures and functions relate to the web.
    * **JavaScript API:**  Consider how JavaScript running on a website interacts with Interest Groups. The browser provides JavaScript APIs to join an interest group, update it, and participate in auctions. The data structures in this file represent the underlying state managed by the browser.
    * **HTML:**  Interest Groups are conceptually linked to the websites a user visits. The `owner` of an `InterestGroup` directly corresponds to the origin of a website. Ads are ultimately rendered within HTML pages.
    * **CSS:** While less direct, CSS can be used to style the ads fetched by the `render_url_`. The `ad_sizes` and `size_groups` might influence how ads are selected based on available space, which can be determined by CSS layout.

7. **Identify Logical Inferences (Assumptions and Outputs):**  For the validation functions, try to think about what happens when certain inputs are provided.
    * **Example:** If `owner` is not HTTPS, `IsValid` will return `false`. If a bidding URL is on a different origin, `IsValid` will return `false`.

8. **Consider User/Programming Errors:**  Think about common mistakes developers might make when using the Interest Group API:
    * Providing invalid URLs (non-HTTPS, wrong origin).
    * Exceeding size limits for interest groups or ad render IDs.
    * Incorrectly setting up reporting URLs.
    * Confusing the purpose of different reporting IDs.
    * Not understanding the implications of `execution_mode`.

9. **Structure the Output:** Organize the information logically, covering the requested points: functionality, relation to web technologies, logical inferences, and common errors. Use clear and concise language.

10. **Review and Refine:**  Read through the analysis to ensure accuracy and completeness. Check for any missing links or areas where the explanation could be clearer. For example, initially, I might have overlooked the nuances of the different K-anonymity key generation functions and their purpose. A second pass would help clarify those distinctions.
这是 Chromium Blink 引擎中 `blink/common/interest_group/interest_group.cc` 文件的功能列表和相关说明：

**核心功能：定义和管理 Interest Group 数据结构**

该文件定义了 `InterestGroup` 类和其内部类 `Ad`，这些类是 Chromium 中表示用户兴趣组的核心数据结构。Interest Group 是 Privacy Sandbox 中 Protected Audience API (以前称为 FLEDGE) 的关键组成部分，它允许网站将用户添加到由特定广告商“拥有”的组中，以便在稍后的竞价中向他们展示相关广告，同时保护用户隐私。

**`InterestGroup` 类功能：**

* **存储 Interest Group 的基本信息:**
    * `owner`:  拥有该兴趣组的网站的来源 (Origin)。
    * `name`: 兴趣组的名称。
    * `bidding_url`:  用于获取竞价逻辑的 URL。
    * `update_url`:  用于定期更新兴趣组信息的 URL。
    * `ads`:  与该兴趣组关联的广告列表 (`std::vector<Ad>`)。
    * `ad_components`:  与该兴趣组关联的广告组件列表 (`std::vector<Ad>`)，用于多部分广告。
    * `priority`:  该兴趣组的优先级，用于在竞价中进行排序。
    * `priority_vector`:  一个 map，用于存储基于信号名称的优先级调整值。
    * `priority_signals_overrides`:  一个 map，用于存储在特定情况下覆盖优先级信号的值。
    * `user_bidding_signals`:  传递给竞价函数的用户信号 (通常是 JSON 字符串)。
    * `trusted_bidding_signals_url`:  用于获取受信任竞价信号的 URL。
    * `trusted_bidding_signals_keys`:  在请求受信任竞价信号时需要提供的键值列表。
    * `trusted_bidding_signals_slot_size_mode`:  指定如何处理受信任竞价信号的槽位大小。
    * `max_trusted_bidding_signals_url_length`:  限制受信任竞价信号 URL 的最大长度。
    * `trusted_bidding_signals_coordinator`:  受信任竞价信号的协调者来源。
    * `execution_mode`:  指定竞价脚本的执行模式 (例如，兼容模式、按来源分组模式、冻结上下文)。
    * `seller_capabilities`:  一个 map，用于指定允许哪些卖方参与竞价。
    * `all_sellers_capabilities`:  一个枚举，指示是否允许所有卖方参与竞价。
    * `ad_sizes`:  一个 map，定义了不同广告尺寸的规范。
    * `size_groups`:  一个 map，将广告尺寸名称分组。
    * `auction_server_request_flags`:  用于控制竞价服务器请求的标志。
    * `additional_bid_key`:  用于负面定向的额外竞价密钥。
    * `aggregation_coordinator_origin`:  用于 Private Aggregation API 的协调者来源。

* **验证 Interest Group 的有效性 (`IsValid`)**:  该方法检查 `InterestGroup` 对象的各种属性是否符合规范和安全要求，例如：
    * `owner` 必须是 HTTPS 来源。
    * 优先级必须是有限值。
    * 关联的 URL 必须是同源的 (除了广告渲染 URL)。
    * 广告渲染 URL 必须是 HTTPS 且不包含嵌入式凭据。
    * 广告组件不能包含买方报告 ID 等属性。
    * 广告尺寸和尺寸组的定义必须一致。
    * 兴趣组的大小不能超过限制。

* **估计 Interest Group 的大小 (`EstimateSize`)**:  计算 `InterestGroup` 对象所占用的内存大小，用于资源管理和限制。

* **提供受信任竞价信号槽位大小模式的字符串表示 (`TrustedBiddingSignalsSlotSizeModeToString`)**

**`Ad` 类功能：**

* **存储单个广告的信息:**
    * `render_url_`:  广告渲染的 URL。
    * `metadata`:  与广告相关的元数据 (通常是 JSON 字符串)。
    * `size_group`:  广告所属的尺寸组名称。
    * `buyer_reporting_id`:  买方报告 ID。
    * `buyer_and_seller_reporting_id`:  买方和卖方共享的报告 ID。
    * `selectable_buyer_and_seller_reporting_ids`:  可选的买方和卖方共享的报告 ID 列表。
    * `ad_render_id`:  广告渲染的唯一标识符。
    * `allowed_reporting_origins`:  允许向其发送报告的来源列表。

* **估计 Ad 对象的大小 (`EstimateSize`)**:  计算 `Ad` 对象所占用的内存大小。

* **比较两个 Ad 对象是否相等 (`operator==`)**

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**
    * **API 暴露:**  JavaScript 通过浏览器提供的 API (例如 `navigator.joinAdInterestGroup()`, `navigator.leaveAdInterestGroup()`) 来创建、管理和加入/离开 Interest Group。  `InterestGroup` 类在 C++ 中表示了这些 API 操作所操作的数据。
    * **竞价脚本:**  `bidding_url` 指向的 JavaScript 代码在竞价过程中被执行，该代码会访问和使用与 Interest Group 关联的信息 (例如，`ads`, `user_bidding_signals`) 来生成出价。
    * **报告:**  JavaScript 代码可以使用 `sendReportTo()` 等函数来发送竞价结果报告，这些报告的生成可能涉及到 `buyer_reporting_id` 等属性。

    **举例:**
    ```javascript
    // JavaScript 代码，用于加入一个兴趣组
    navigator.joinAdInterestGroup({
      owner: 'https://example.com',
      name: 'custom-bikes',
      biddingLogicUrl: 'https://example.com/bid.js',
      ads: [
        { renderUrl: 'https://cdn.example.com/bike1.html', metadata: '{ "model": "mountain" }' },
        { renderUrl: 'https://cdn.example.com/bike2.html', metadata: '{ "model": "road" }' }
      ]
    }, 30 * 24 * 60 * 60 * 1000); // 有效期 30 天
    ```
    这段 JavaScript 代码会最终在 Blink 引擎中创建一个 `InterestGroup` 对象，其 `owner` 为 `https://example.com`，`name` 为 `custom-bikes`，`bidding_url` 为 `https://example.com/bid.js`，`ads` 包含两个 `Ad` 对象。

* **HTML:**
    * **广告渲染:**  `Ad` 对象的 `render_url_` 指向的 HTML 文件会被加载并渲染以展示广告。
    * **iframe:**  通常，Protected Audience API 的广告会在一个独立的 `<iframe>` 中渲染，以实现隔离。

    **举例:**  如果一个竞价胜出，且胜出广告的 `render_url_` 是 `https://cdn.example.com/bike1.html`，那么浏览器会创建一个 `<iframe>` 并加载该 URL 来展示广告内容。

* **CSS:**
    * **广告样式:**  虽然 `interest_group.cc` 本身不直接处理 CSS，但最终渲染的广告会使用 CSS 来控制其外观和布局。
    * **广告尺寸:**  `Ad` 对象的 `size_group` 属性可能与 CSS 媒体查询或容器查询相关联，用于选择合适的广告变体。`ad_sizes` 和 `size_groups` 定义了广告的尺寸信息，这些信息可能被用于广告选择和布局。

    **举例:**  `ad_sizes` 可能定义了名为 "small" 的广告尺寸为 300x250。当一个广告的 `size_group` 为 "small" 时，浏览器可能会选择一个适合 300x250 尺寸的广告位进行展示。广告的 `render_url_` 指向的 HTML 文件可以使用 CSS 来填充这个 300x250 的区域。

**逻辑推理示例 (假设输入与输出):**

假设有以下 `InterestGroup` 对象：

```c++
blink::InterestGroup group;
group.owner = url::Origin::Create(GURL("https://example.com"));
group.name = "test-group";
group.bidding_url = GURL("https://example.com/bid.js");
group.ads.emplace();
group.ads->push_back(blink::InterestGroup::Ad(
    base::PassKey<content::InterestGroupStorage>(), "https://cdn.example.com/ad1.html"));

// 假设调用 IsValid() 方法
bool isValid = group.IsValid();
```

**推理过程:**

1. **检查 `owner`:** `group.owner` 是 "https://example.com"，是 HTTPS，符合要求。
2. **检查 `priority`:**  `priority` 默认值为 0.0，是有限值，符合要求。
3. **检查 `bidding_url`:** `group.bidding_url` 是 "https://example.com/bid.js"。`IsUrlAllowed()` 会检查其来源是否与 `group.owner` 相同，这里是相同的，且是 HTTPS，不包含 fragment，符合要求。
4. **检查 `ads`:** `group.ads` 包含一个广告，其 `render_url_` 是 "https://cdn.example.com/ad1.html"。`IsUrlAllowedForRenderUrls()` 会检查其是否是 HTTPS 且不包含嵌入式凭据，这里符合要求。
5. **其他字段:**  其他字段没有设置，或者有默认值，且满足基本要求。

**假设输出:** `isValid` 将为 `true`。

**用户或编程常见的使用错误举例：**

1. **`owner` 不是 HTTPS:**

   ```javascript
   navigator.joinAdInterestGroup({
     owner: 'http://example.com', // 错误：不是 HTTPS
     name: 'test-group',
     biddingLogicUrl: 'https://example.com/bid.js'
   });
   ```
   **错误:** `IsValid()` 会返回 `false`，因为 `owner.scheme()` 不等于 `url::kHttpsScheme`。

2. **`biddingLogicUrl` 不是同源:**

   ```javascript
   navigator.joinAdInterestGroup({
     owner: 'https://example.com',
     name: 'test-group',
     biddingLogicUrl: 'https://different-domain.com/bid.js' // 错误：非同源
   });
   ```
   **错误:** `IsValid()` 会返回 `false`，因为 `IsUrlAllowed(*bidding_url, *this)` 会检查来源是否一致。

3. **广告 `renderUrl` 不是 HTTPS:**

   ```javascript
   navigator.joinAdInterestGroup({
     owner: 'https://example.com',
     name: 'test-group',
     biddingLogicUrl: 'https://example.com/bid.js',
     ads: [{ renderUrl: 'http://cdn.example.com/ad.html' }] // 错误：不是 HTTPS
   });
   ```
   **错误:** `IsValid()` 会返回 `false`，因为 `IsUrlAllowedForRenderUrls(GURL(ad.render_url()))` 会检查 HTTPS。

4. **超出最大 Interest Group 大小:**  如果 `ads` 或其他字段包含大量数据，使得 `EstimateSize()` 的返回值超过 `blink::mojom::kMaxInterestGroupSize`，`IsValid()` 将返回 `false`。这通常发生在尝试在一个兴趣组中添加过多广告时。

5. **在广告组件中设置了买方报告 ID:**

   ```javascript
   navigator.joinAdInterestGroup({
     owner: 'https://example.com',
     name: 'test-group',
     biddingLogicUrl: 'https://example.com/bid.js',
     adComponents: [{
       renderUrl: 'https://cdn.example.com/component.html',
       buyerReportingId: 'some-id' // 错误：不应在组件中设置
     }]
   });
   ```
   **错误:** `IsValid()` 会返回 `false`，因为在 `ad_components` 中的 `Ad` 对象中检测到 `buyer_reporting_id`。

6. **广告尺寸组中的尺寸未在 `ad_sizes` 中定义:**

   ```javascript
   navigator.joinAdInterestGroup({
     owner: 'https://example.com',
     name: 'test-group',
     biddingLogicUrl: 'https://example.com/bid.js',
     ads: [{ renderUrl: 'https://cdn.example.com/ad.html', sizeGroup: 'banner' }],
     sizeGroups: { banner: ['non-existent-size'] } // 错误：未定义的尺寸
   });
   ```
   **错误:** `IsValid()` 会返回 `false`，因为在 `size_groups` 中引用的 "non-existent-size" 没有在 `ad_sizes` 中定义。

总而言之，`interest_group.cc` 文件是 Blink 引擎中关于 Privacy Sandbox Interest Group 功能的核心实现，它定义了数据结构、验证逻辑，并与 JavaScript API 和网页内容 (HTML, CSS) 的渲染和交互密切相关。理解这个文件有助于深入了解 Protected Audience API 的内部工作原理。

### 提示词
```
这是目录为blink/common/interest_group/interest_group.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/interest_group/interest_group.h"

#include <stdint.h>

#include <cmath>
#include <cstring>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "base/containers/contains.h"
#include "base/containers/span.h"
#include "base/feature_list.h"
#include "base/numerics/byte_conversions.h"
#include "base/strings/strcat.h"
#include "base/time/time.h"
#include "base/types/optional_ref.h"
#include "crypto/sha2.h"
#include "third_party/blink/public/common/common_export.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/interest_group/ad_display_size_utils.h"
#include "third_party/blink/public/mojom/interest_group/interest_group_types.mojom.h"
#include "third_party/boringssl/src/include/openssl/curve25519.h"
#include "url/gurl.h"
#include "url/origin.h"
#include "url/url_constants.h"

namespace blink {

namespace {

constexpr char kKAnonKeyForAdNameReportingSelectedBuyerAndSellerIdPrefix[] =
    "SelectedBuyerAndSellerReportId\n";
constexpr char kKAnonKeyForAdNameReportingBuyerAndSellerIdPrefix[] =
    "BuyerAndSellerReportId\n";
constexpr char kKAnonKeyForAdNameReportingBuyerReportIdPrefix[] =
    "BuyerReportId\n";
constexpr char kKAnonKeyForAdNameReportingNamePrefix[] = "NameReport\n";

const size_t kMaxAdRenderIdSize = 12;

// Check if `url` can be used as an interest group's ad render URL. Ad URLs can
// be cross origin, unlike other interest group URLs, but are still restricted
// to HTTPS with no embedded credentials.
bool IsUrlAllowedForRenderUrls(const GURL& url) {
  if (!url.is_valid() || !url.SchemeIs(url::kHttpsScheme)) {
    return false;
  }

  return !url.has_username() && !url.has_password();
}

// Check if `url` can be used with the specified interest group for any of
// script URL, update URL. Ad render URLs should be checked with
// IsUrlAllowedForRenderUrls(), which doesn't have the same-origin
// check, and allows references.
bool IsUrlAllowed(const GURL& url, const InterestGroup& group) {
  if (url::Origin::Create(url) != group.owner) {
    return false;
  }

  return IsUrlAllowedForRenderUrls(url) && !url.has_ref();
}

// Check if `url` can be used with the specified interest group for trusted
// bidding signals URL.
bool IsUrlAllowedForTrustedBiddingSignals(const GURL& url,
                                          const InterestGroup& group) {
  return IsUrlAllowedForRenderUrls(url) && !url.has_ref() && !url.has_query();
}

size_t EstimateFlatMapSize(
    const base::flat_map<std::string, double>& flat_map) {
  size_t result = 0;
  for (const auto& pair : flat_map) {
    result += pair.first.length() + sizeof(pair.second);
  }
  return result;
}

void AppendReportingIdForSelectedReportingKeyKAnonKey(
    base::optional_ref<const std::string> reporting_id,
    std::string& k_anon_key) {
  if (!reporting_id.has_value()) {
    base::StrAppend(&k_anon_key,
                    {"\n", std::string_view("\x00\x00\x00\x00\x00", 5)});
    return;
  }

  std::array<uint8_t, 4u> size_in_bytes =
      base::U32ToBigEndian(reporting_id->size());
  base::StrAppend(
      &k_anon_key,
      {"\n", std::string_view("\x01", 1),
       base::as_string_view(base::as_chars(base::make_span(size_in_bytes))),
       *reporting_id});
}

std::string InternalPlainTextKAnonKeyForAdNameReporting(
    const url::Origin& interest_group_owner,
    const std::string& interest_group_name,
    const GURL& interest_group_bidding_url,
    const std::string& ad_render_url,
    base::optional_ref<const std::string> buyer_reporting_id,
    base::optional_ref<const std::string> buyer_and_seller_reporting_id,
    base::optional_ref<const std::string>
        selected_buyer_and_seller_reporting_id) {
  std::string middle =
      base::StrCat({interest_group_owner.GetURL().spec(), "\n",
                    interest_group_bidding_url.spec(), "\n", ad_render_url});

  if (selected_buyer_and_seller_reporting_id.has_value()) {
    // In the case where the reporting functions get
    // `selected_buyer_and_seller_reporting_id`, it's possible for more than one
    // reporting id to be provided. As such, all of the reporting ids passed
    // into the reporting functions will need to be in the k-anon key. To ensure
    // that the k-anon key uniquely reflects the values of all provided
    // reporting ids, we construct the k-anon key so that each reporting id is
    // prefixed by a fixed number of bytes representing its presence and length.
    std::string k_anon_key = base::StrCat(
        {kKAnonKeyForAdNameReportingSelectedBuyerAndSellerIdPrefix, middle});
    AppendReportingIdForSelectedReportingKeyKAnonKey(
        selected_buyer_and_seller_reporting_id, k_anon_key);
    AppendReportingIdForSelectedReportingKeyKAnonKey(
        buyer_and_seller_reporting_id, k_anon_key);
    AppendReportingIdForSelectedReportingKeyKAnonKey(buyer_reporting_id,
                                                     k_anon_key);
    return k_anon_key;
  }

  if (buyer_and_seller_reporting_id.has_value()) {
    return base::StrCat({kKAnonKeyForAdNameReportingBuyerAndSellerIdPrefix,
                         middle, "\n", *buyer_and_seller_reporting_id});
  }

  if (buyer_reporting_id.has_value()) {
    return base::StrCat({kKAnonKeyForAdNameReportingBuyerReportIdPrefix, middle,
                         "\n", *buyer_reporting_id});
  }

  return base::StrCat({kKAnonKeyForAdNameReportingNamePrefix, middle, "\n",
                       interest_group_name});
}
}  // namespace

InterestGroup::Ad::Ad() = default;

InterestGroup::Ad::Ad(base::PassKey<content::InterestGroupStorage>,
                      std::string&& render_url)
    : render_url_(std::move(render_url)) {}
InterestGroup::Ad::Ad(base::PassKey<content::InterestGroupStorage>,
                      const std::string& render_url)
    : render_url_(render_url) {}
InterestGroup::Ad::Ad(
    GURL render_gurl,
    std::optional<std::string> metadata,
    std::optional<std::string> size_group,
    std::optional<std::string> buyer_reporting_id,
    std::optional<std::string> buyer_and_seller_reporting_id,
    std::optional<std::vector<std::string>>
        selectable_buyer_and_seller_reporting_ids,
    std::optional<std::string> ad_render_id,
    std::optional<std::vector<url::Origin>> allowed_reporting_origins)
    : size_group(std::move(size_group)),
      metadata(std::move(metadata)),
      buyer_reporting_id(std::move(buyer_reporting_id)),
      buyer_and_seller_reporting_id(std::move(buyer_and_seller_reporting_id)),
      selectable_buyer_and_seller_reporting_ids(
          std::move(selectable_buyer_and_seller_reporting_ids)),
      ad_render_id(std::move(ad_render_id)),
      allowed_reporting_origins(std::move(allowed_reporting_origins)) {
  if (render_gurl.is_valid()) {
    render_url_ = render_gurl.spec();
  }
}

InterestGroup::Ad::~Ad() = default;

size_t InterestGroup::Ad::EstimateSize() const {
  size_t size = 0u;
  size += render_url_.length();
  if (size_group) {
    size += size_group->size();
  }
  if (metadata) {
    size += metadata->size();
  }
  if (buyer_reporting_id) {
    size += buyer_reporting_id->size();
  }
  if (buyer_and_seller_reporting_id) {
    size += buyer_and_seller_reporting_id->size();
  }
  if (selectable_buyer_and_seller_reporting_ids) {
    for (auto& id : *selectable_buyer_and_seller_reporting_ids) {
      size += id.size();
    }
  }
  if (ad_render_id) {
    size += ad_render_id->size();
  }
  if (allowed_reporting_origins) {
    for (const url::Origin& origin : *allowed_reporting_origins) {
      size += origin.Serialize().size();
    }
  }
  return size;
}

bool InterestGroup::Ad::operator==(const Ad& other) const {
  return std::tie(render_url_, size_group, metadata, buyer_reporting_id,
                  buyer_and_seller_reporting_id,
                  selectable_buyer_and_seller_reporting_ids, ad_render_id,
                  allowed_reporting_origins) ==
         std::tie(other.render_url_, other.size_group, other.metadata,
                  other.buyer_reporting_id, other.buyer_and_seller_reporting_id,
                  other.selectable_buyer_and_seller_reporting_ids,
                  other.ad_render_id, other.allowed_reporting_origins);
}

InterestGroup::InterestGroup() = default;
InterestGroup::~InterestGroup() = default;
InterestGroup::InterestGroup(InterestGroup&& other) = default;
InterestGroup& InterestGroup::operator=(InterestGroup&& other) = default;
InterestGroup::InterestGroup(const InterestGroup& other) = default;
InterestGroup& InterestGroup::operator=(const InterestGroup& other) = default;

// The logic in this method must be kept in sync with ValidateBlinkInterestGroup
// in blink/renderer/modules/ad_auction/. The tests for this logic are also
// there, so they can be compared against each other.
bool InterestGroup::IsValid() const {
  if (owner.scheme() != url::kHttpsScheme) {
    return false;
  }

  if (!std::isfinite(priority)) {
    return false;
  }

  if (priority_vector) {
    for (const auto& [unused_signal_name, value] : *priority_vector) {
      if (!std::isfinite(value)) {
        return false;
      }
    }
  }

  if (priority_signals_overrides) {
    for (const auto& [unused_signal_name, value] :
         *priority_signals_overrides) {
      if (!std::isfinite(value)) {
        return false;
      }
    }
  }

  if (seller_capabilities) {
    for (const auto& [seller_origin, flags] : *seller_capabilities) {
      if (seller_origin.scheme() != url::kHttpsScheme) {
        return false;
      }
    }
  }

  if (execution_mode !=
          blink::mojom::InterestGroup::ExecutionMode::kCompatibilityMode &&
      execution_mode !=
          blink::mojom::InterestGroup::ExecutionMode::kGroupedByOriginMode &&
      execution_mode !=
          blink::mojom::InterestGroup::ExecutionMode::kFrozenContext) {
    return false;
  }

  if (bidding_url && !IsUrlAllowed(*bidding_url, *this)) {
    return false;
  }

  if (bidding_wasm_helper_url &&
      !IsUrlAllowed(*bidding_wasm_helper_url, *this)) {
    return false;
  }

  if (update_url && !IsUrlAllowed(*update_url, *this)) {
    return false;
  }

  if (trusted_bidding_signals_url) {
    if (!IsUrlAllowedForTrustedBiddingSignals(*trusted_bidding_signals_url,
                                              *this)) {
      return false;
    }
  }

  if (trusted_bidding_signals_slot_size_mode !=
          blink::mojom::InterestGroup::TrustedBiddingSignalsSlotSizeMode::
              kNone &&
      trusted_bidding_signals_slot_size_mode !=
          blink::mojom::InterestGroup::TrustedBiddingSignalsSlotSizeMode::
              kSlotSize &&
      trusted_bidding_signals_slot_size_mode !=
          blink::mojom::InterestGroup::TrustedBiddingSignalsSlotSizeMode::
              kAllSlotsRequestedSizes) {
    return false;
  }

  // `max_trusted_bidding_signals_url_length` must not be negative.
  if (max_trusted_bidding_signals_url_length < 0) {
    return false;
  }

  if (trusted_bidding_signals_coordinator) {
    if (trusted_bidding_signals_coordinator->scheme() != url::kHttpsScheme) {
      return false;
    }
  }

  if (ads) {
    for (const auto& ad : ads.value()) {
      if (!IsUrlAllowedForRenderUrls(GURL(ad.render_url()))) {
        return false;
      }
      if (ad.size_group) {
        if (ad.size_group->empty() || !size_groups ||
            !size_groups->contains(ad.size_group.value())) {
          return false;
        }
      }
      if (ad.ad_render_id) {
        if (ad.ad_render_id->size() > kMaxAdRenderIdSize) {
          return false;
        }
      }
      if (ad.allowed_reporting_origins) {
        if (ad.allowed_reporting_origins->size() >
            blink::mojom::kMaxAllowedReportingOrigins) {
          return false;
        }
        for (const auto& origin : ad.allowed_reporting_origins.value()) {
          if (origin.scheme() != url::kHttpsScheme) {
            return false;
          }
        }
      }
    }
  }

  if (ad_components) {
    for (const auto& ad : ad_components.value()) {
      if (!IsUrlAllowedForRenderUrls(GURL(ad.render_url()))) {
        return false;
      }
      if (ad.size_group) {
        if (ad.size_group->empty() || !size_groups ||
            !size_groups->contains(ad.size_group.value())) {
          return false;
        }
      }
      if (ad.ad_render_id) {
        if (ad.ad_render_id->size() > kMaxAdRenderIdSize) {
          return false;
        }
      }
      // These shouldn't be in components array.
      if (ad.buyer_reporting_id || ad.buyer_and_seller_reporting_id ||
          ad.selectable_buyer_and_seller_reporting_ids ||
          ad.allowed_reporting_origins) {
        return false;
      }
    }
  }

  if (ad_sizes) {
    for (auto const& [size_name, size_obj] : ad_sizes.value()) {
      if (size_name == "") {
        return false;
      }
      if (!IsValidAdSize(size_obj)) {
        return false;
      }
    }
  }

  if (size_groups) {
    // Sizes in a size group must also be in the ad_sizes map.
    if (!ad_sizes) {
      return false;
    }
    for (auto const& [group_name, size_list] : size_groups.value()) {
      if (group_name == "") {
        return false;
      }
      for (auto const& size_name : size_list) {
        if (size_name == "" || !ad_sizes->contains(size_name)) {
          return false;
        }
      }
    }
  }

  if (additional_bid_key) {
    if (additional_bid_key->size() != ED25519_PUBLIC_KEY_LEN) {
      return false;
    }
  }

  // InterestGroups used for negative targeting may not also have ads.
  // They are also not updatable.
  if (additional_bid_key && (ads || update_url)) {
    return false;
  }

  if (aggregation_coordinator_origin &&
      aggregation_coordinator_origin->scheme() != url::kHttpsScheme) {
    return false;
  }

  return EstimateSize() < blink::mojom::kMaxInterestGroupSize;
}

size_t InterestGroup::EstimateSize() const {
  size_t size = 0u;
  size += owner.Serialize().size();
  size += name.size();

  size += sizeof(priority);
  size += sizeof(execution_mode);
  size += sizeof(enable_bidding_signals_prioritization);

  if (priority_vector) {
    size += EstimateFlatMapSize(*priority_vector);
  }
  if (priority_signals_overrides) {
    size += EstimateFlatMapSize(*priority_signals_overrides);
  }
  if (seller_capabilities) {
    for (const auto& [seller_origin, flags] : *seller_capabilities) {
      size +=
          seller_origin.Serialize().size() + sizeof(decltype(flags)::EnumType);
    }
  }
  size += sizeof(decltype(all_sellers_capabilities)::EnumType);
  if (bidding_url) {
    size += bidding_url->spec().length();
  }
  if (bidding_wasm_helper_url) {
    size += bidding_wasm_helper_url->spec().length();
  }
  if (update_url) {
    size += update_url->spec().length();
  }
  if (trusted_bidding_signals_url) {
    size += trusted_bidding_signals_url->spec().length();
  }
  if (trusted_bidding_signals_keys) {
    for (const std::string& key : *trusted_bidding_signals_keys) {
      size += key.size();
    }
  }
  size += sizeof(trusted_bidding_signals_slot_size_mode);
  size += sizeof(max_trusted_bidding_signals_url_length);
  if (trusted_bidding_signals_coordinator) {
    size += trusted_bidding_signals_coordinator->Serialize().size();
  }
  if (user_bidding_signals) {
    size += user_bidding_signals->size();
  }
  if (ads) {
    for (const Ad& ad : *ads) {
      size += ad.EstimateSize();
    }
  }
  if (ad_components) {
    for (const Ad& ad : *ad_components) {
      size += ad.EstimateSize();
    }
  }
  if (ad_sizes) {
    for (const auto& [size_name, size_obj] : *ad_sizes) {
      size += size_name.length();
      size += sizeof(size_obj.width);
      size += sizeof(size_obj.height);
      size += sizeof(size_obj.width_units);
      size += sizeof(size_obj.height_units);
    }
  }
  if (size_groups) {
    for (const auto& size_group : size_groups.value()) {
      size += size_group.first.length();
      for (const auto& size_name : size_group.second) {
        size += size_name.length();
      }
    }
  }
  size += sizeof(decltype(auction_server_request_flags)::EnumType);
  if (additional_bid_key) {
    size += ED25519_PUBLIC_KEY_LEN;
  }
  if (aggregation_coordinator_origin) {
    size += aggregation_coordinator_origin->Serialize().size();
  }
  return size;
}

std::string_view InterestGroup::TrustedBiddingSignalsSlotSizeModeToString(
    TrustedBiddingSignalsSlotSizeMode slot_size_mode) {
  switch (slot_size_mode) {
    case TrustedBiddingSignalsSlotSizeMode::kNone:
      return "none";
    case TrustedBiddingSignalsSlotSizeMode::kSlotSize:
      return "slot-size";
    case TrustedBiddingSignalsSlotSizeMode::kAllSlotsRequestedSizes:
      return "all-slots-requested-sizes";
  }
}

std::string DEPRECATED_KAnonKeyForAdBid(
    const url::Origin& owner,
    const GURL& bidding_url,
    const std::string& ad_url_from_gurl_spec) {
  return base::StrCat({kKAnonKeyForAdBidPrefix, owner.GetURL().spec(), "\n",
                       bidding_url.spec(), "\n", ad_url_from_gurl_spec});
}

std::string DEPRECATED_KAnonKeyForAdBid(
    const InterestGroup& group,
    const std::string& ad_url_from_gurl_spec) {
  DCHECK(group.ads);
  DCHECK(base::Contains(
      *group.ads, ad_url_from_gurl_spec,
      [](const blink::InterestGroup::Ad& ad) { return ad.render_url(); }))
      << "No such ad: " << ad_url_from_gurl_spec;
  DCHECK(group.bidding_url);
  return DEPRECATED_KAnonKeyForAdBid(
      group.owner, group.bidding_url.value_or(GURL()), ad_url_from_gurl_spec);
}

std::string HashedKAnonKeyForAdBid(const url::Origin& owner,
                                   const GURL& bidding_url,
                                   const std::string& ad_url_from_gurl_spec) {
  return crypto::SHA256HashString(
      DEPRECATED_KAnonKeyForAdBid(owner, bidding_url, ad_url_from_gurl_spec));
}

std::string HashedKAnonKeyForAdBid(const InterestGroup& group,
                                   const std::string& ad_url_from_gurl_spec) {
  return crypto::SHA256HashString(
      DEPRECATED_KAnonKeyForAdBid(group, ad_url_from_gurl_spec));
}

std::string HashedKAnonKeyForAdBid(const InterestGroup& group,
                                   const blink::AdDescriptor& ad_descriptor) {
  return HashedKAnonKeyForAdBid(group, ad_descriptor.url.spec());
}

std::string DEPRECATED_KAnonKeyForAdComponentBid(
    const std::string& ad_url_from_gurl_spec) {
  return base::StrCat(
      {kKAnonKeyForAdComponentBidPrefix, ad_url_from_gurl_spec});
}

std::string HashedKAnonKeyForAdComponentBid(
    const std::string& ad_url_from_gurl_spec) {
  return crypto::SHA256HashString(
      DEPRECATED_KAnonKeyForAdComponentBid(ad_url_from_gurl_spec));
}

std::string HashedKAnonKeyForAdComponentBid(const GURL& ad_url) {
  return crypto::SHA256HashString(
      DEPRECATED_KAnonKeyForAdComponentBid(ad_url.spec()));
}

std::string HashedKAnonKeyForAdComponentBid(
    const blink::AdDescriptor& ad_descriptor) {
  // TODO(crbug.com/40266862): Add size back to this check.
  return HashedKAnonKeyForAdComponentBid(ad_descriptor.url.spec());
}
std::string DEPRECATED_KAnonKeyForAdNameReporting(
    const blink::InterestGroup& group,
    const blink::InterestGroup::Ad& ad,
    base::optional_ref<const std::string>
        selected_buyer_and_seller_reporting_id) {
  DCHECK(group.ads);
  DCHECK(base::Contains(*group.ads, ad)) << "No such ad: " << ad.render_url();
  DCHECK(group.bidding_url);
  return InternalPlainTextKAnonKeyForAdNameReporting(
      group.owner, group.name, group.bidding_url.value_or(GURL()),
      ad.render_url(), ad.buyer_reporting_id, ad.buyer_and_seller_reporting_id,
      selected_buyer_and_seller_reporting_id);
}

std::string HashedKAnonKeyForAdNameReporting(
    const blink::InterestGroup& group,
    const blink::InterestGroup::Ad& ad,
    base::optional_ref<const std::string>
        selected_buyer_and_seller_reporting_id) {
  return crypto::SHA256HashString(DEPRECATED_KAnonKeyForAdNameReporting(
      group, ad, selected_buyer_and_seller_reporting_id));
}

std::string HashedKAnonKeyForAdNameReportingWithoutInterestGroup(
    const url::Origin& interest_group_owner,
    const std::string& interest_group_name,
    const GURL& interest_group_bidding_url,
    const std::string& ad_render_url,
    base::optional_ref<const std::string> buyer_reporting_id,
    base::optional_ref<const std::string> buyer_and_seller_reporting_id,
    base::optional_ref<const std::string>
        selected_buyer_and_seller_reporting_id) {
  return crypto::SHA256HashString(InternalPlainTextKAnonKeyForAdNameReporting(
      interest_group_owner, interest_group_name, interest_group_bidding_url,
      ad_render_url, buyer_reporting_id, buyer_and_seller_reporting_id,
      selected_buyer_and_seller_reporting_id));
}
}  // namespace blink
```