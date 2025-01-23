Response: Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The filename `auction_config_mojom_traits_test.cc` immediately suggests testing the serialization and deserialization of `AuctionConfig` objects, specifically through Mojo (indicated by `mojom_traits`). This is crucial for inter-process communication in Chromium.

2. **Scan for Key Data Structures:** Look for the main data structure being tested. The `#include "third_party/blink/public/common/interest_group/auction_config.h"` confirms that `AuctionConfig` is the central object of interest.

3. **Understand the Testing Strategy:** Notice the pervasive use of `SerializeAndDeserialize`. This function is clearly the workhorse of the tests. It serializes an `AuctionConfig` object and then deserializes it back. The tests then check if the original and the deserialized objects are equal using `EXPECT_EQ`. This establishes a clear pattern for how the tests are structured.

4. **Categorize the Tests:** As you read through the `TEST` blocks, start grouping them based on what aspect of `AuctionConfig` they are testing. Common categories emerge:
    * **Basic Functionality:**  Empty config, basic config.
    * **URL Validation:** Seller URL, decision logic URL, trusted scoring signals URL, component auction URLs, direct-from-seller signals URLs. Pay attention to HTTPS requirements and origin checks.
    * **Data Constraints:** Length limits (URLs), numerical ranges (timeouts), allowed values (currencies).
    * **Logical Constraints/Invariants:**  Relationships between different fields (e.g., `expects_additional_bids` and `auction_nonce`). Look for tests that check for illegal combinations of settings.
    * **"MaybePromise" Types:** Note the tests specifically for `MaybePromiseJson`, `MaybePromisePerBuyerSignals`, etc. This indicates a pattern of handling asynchronous or optional data.
    * **Specific Field Tests:** Tests focusing on individual fields like `seller_timeout`, `buyer_timeouts`, `reporting_timeout`, `buyer_currencies`.
    * **Direct-from-Seller Signals:**  A large section is dedicated to testing the different configurations and constraints of direct-from-seller signals.

5. **Look for Connections to Web Technologies:** Consider how the `AuctionConfig` relates to web technologies. Keywords like "interest group," "auction," "buyer," "seller," and the URLs themselves hint at the FLEDGE/Protected Audience API. The mention of "render URL replacements" directly links to how ads are displayed in the browser. Think about how these settings in `AuctionConfig` would influence the behavior of JavaScript APIs and how the browser renders content.

6. **Identify Potential User/Developer Errors:** As you examine the validation tests (the ones that `EXPECT_FALSE` for `SerializeAndDeserialize`), think about the common mistakes a developer configuring a Protected Audience auction might make. Examples include:
    * Using HTTP instead of HTTPS for critical URLs.
    * Providing URLs from the wrong origin.
    * Exceeding length limits for URLs.
    * Setting conflicting or illogical configurations.
    * Using incorrect data formats.

7. **Focus on Logical Reasoning and Assumptions:** When a test has a clear setup and expectation (e.g., setting a timeout to a negative value), articulate the underlying logical rule being tested. For instance, timeouts should be non-negative. Try to express these rules in terms of "if input X, then output Y (success/failure)."

8. **Address the "mojom_traits" Aspect:**  Remember that this is a *traits* test. This means it's specifically verifying that the Mojo serialization/deserialization mechanism correctly handles the `AuctionConfig` structure. This is less about the business logic of the auction itself and more about the technical correctness of the IPC.

9. **Structure the Output:** Organize your findings clearly. Start with the high-level purpose and then delve into the details, categorizing the functionality. Use bullet points and clear language. Provide specific examples for the web technology connections and user errors.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This file just tests serialization."  **Correction:**  It tests *serialization and deserialization* and also implicitly validates the structure and constraints of `AuctionConfig`.
* **Initial thought:** "The tests are just random." **Correction:** The tests are systematically checking various valid and invalid configurations of `AuctionConfig`, covering different fields and combinations.
* **Stuck on a specific test:** "Why does this test fail with `SellerDecisionUrlMismatch`?" **Analysis:** The test checks that the `decision_logic_url` is same-origin with the `seller` URL (or a blob URL with the same origin and HTTPS scheme). This is a security measure.
* **Realizing a pattern:** "Many tests involve URLs and HTTPS." **Observation:** This highlights the importance of secure communication in the Protected Audience API.

By following this systematic approach, you can effectively analyze the C++ test file and extract the required information.
这个文件 `auction_config_mojom_traits_test.cc` 是 Chromium Blink 引擎中，专门用于测试 `AuctionConfig` 结构体（定义在 `third_party/blink/public/common/interest_group/auction_config.h`）通过 Mojo 进行序列化和反序列化的功能。

**它的主要功能是：**

1. **测试 `AuctionConfig` 结构体的 Mojo 序列化和反序列化:**  Mojo 是 Chromium 中用于进程间通信 (IPC) 的系统。这个测试文件确保了 `AuctionConfig` 对象可以在不同的进程之间正确地传递。它通过将一个 `AuctionConfig` 对象序列化成 Mojo 消息，然后再反序列化回对象，并对比原始对象和反序列化后的对象是否一致来完成测试。

2. **验证 `AuctionConfig` 结构体中各个字段的序列化和反序列化规则:**  `AuctionConfig` 包含了大量用于配置 Protected Audience API (原 FLEDGE) 竞价流程的参数。这个测试会针对 `AuctionConfig` 中的各种字段，包括基本类型、URL、枚举、容器（如 `std::vector` 和 `base::flat_map`）、自定义结构体（如 `AdSize`）等，进行序列化和反序列化测试，确保数据在传输过程中不会丢失或损坏。

3. **检查 `AuctionConfig` 结构体中定义的各种约束和校验逻辑:**  `AuctionConfig` 中定义了很多关于 URL 格式、HTTPS 要求、字段取值范围等约束。这个测试文件会创建各种合法的和非法的 `AuctionConfig` 对象，并测试序列化和反序列化是否按照预期工作。例如，某些 URL 必须是 HTTPS，某些字段不能为负数等。如果违反了这些约束，序列化或反序列化过程应该失败，或者得到预期的错误结果。

**与 JavaScript, HTML, CSS 的功能关系：**

这个 C++ 测试文件直接测试的是 Blink 引擎内部的 Mojo 通信机制，而不是直接测试 JavaScript, HTML 或 CSS 的功能。然而，`AuctionConfig` 结构体承载的是 Protected Audience API 的配置信息，而 Protected Audience API 是一个 Web API，主要通过 JavaScript 进行调用和控制。

* **JavaScript:** JavaScript 代码会创建并配置 `AuctionConfig` 对象（实际上是通过浏览器内部的机制将 JavaScript 的配置转换为 `AuctionConfig` 对象）。这个测试文件确保了这些配置信息可以通过 Mojo 正确地传递到负责执行竞价逻辑的 Blink 引擎组件。例如，在 JavaScript 中设置竞价脚本的 URL，最终会被体现在 `AuctionConfig` 的 `decision_logic_url` 字段中，而这个测试会验证该 URL 的序列化和反序列化是否正确。

* **HTML:**  HTML 中可能会包含触发 Protected Audience API 调用的 JavaScript 代码。`AuctionConfig` 的配置会影响这些调用的行为。

* **CSS:** CSS 本身与 `AuctionConfig` 的序列化和反序列化没有直接关系。然而，Protected Audience API 的目的是支持基于用户兴趣的广告展示，CSS 可以用于控制广告的样式。

**举例说明：**

假设 JavaScript 代码创建了一个 `AuctionConfig` 对象，设置了卖方决策逻辑的 URL：

```javascript
const config = {
  seller: 'https://seller.example',
  decisionLogicUrl: 'https://seller.example/auction_logic.js',
  // ...其他配置
};
```

当浏览器内部需要将这个配置传递给 Blink 引擎进行竞价时，会将其转换为 `AuctionConfig` C++ 对象。 `auction_config_mojom_traits_test.cc` 中的一个测试用例可能会创建这样一个 `AuctionConfig` 对象：

```c++
TEST(AuctionConfigMojomTraitsTest, Basic) {
  AuctionConfig auction_config = CreateBasicAuctionConfig();
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));
}

// CreateBasicAuctionConfig 可能会创建包含如下配置的 AuctionConfig 对象
AuctionConfig CreateBasicAuctionConfig(const GURL& seller_url = GURL("https://seller.test")) {
  AuctionConfig config;
  config.seller = url::Origin::Create(seller_url);
  config.decision_logic_url = GURL("https://seller.test/auction_logic.js");
  // ...
  return config;
}
```

这个测试用例会调用 `SerializeAndDeserialize(auction_config)`，内部会将 `auction_config` 序列化成 Mojo 消息，然后再反序列化回一个新的 `AuctionConfig` 对象。`EXPECT_TRUE` 会检查序列化和反序列化是否成功，并验证原始对象的 `decision_logic_url` 和反序列化后的对象是否一致。

**逻辑推理的假设输入与输出：**

**假设输入：** 一个 `AuctionConfig` 对象，其中 `seller` 为 `https://seller.test`，`decision_logic_url` 为 `https://seller.test/auction_logic.js`。

**预期输出：** `SerializeAndDeserialize` 函数返回 `true`，表示序列化和反序列化成功，并且反序列化后的 `AuctionConfig` 对象的 `seller` 和 `decision_logic_url` 与输入对象相同。

**假设输入：** 一个 `AuctionConfig` 对象，其中 `seller` 为 `https://seller.test`，`decision_logic_url` 为 `http://seller.test/auction_logic.js`（注意 `decision_logic_url` 是 HTTP）。

**预期输出：** `SerializeAndDeserialize` 函数返回 `false`，因为 `decision_logic_url` 必须是 HTTPS，违反了 `AuctionConfig` 的约束。

**用户或编程常见的使用错误举例：**

1. **URL 协议错误：** 用户在 JavaScript 中配置 `AuctionConfig` 时，可能会错误地使用 HTTP URL 而不是 HTTPS URL，例如 `decisionLogicUrl: 'http://seller.example/auction_logic.js'`。这个测试文件中的相关测试用例（如 `SellerNotHttps`, `SellerDecisionUrlMismatch`）会验证 Blink 引擎是否正确处理这种情况，通常会导致竞价失败。

2. **URL 来源错误：**  某些 URL（如决策逻辑 URL）必须与卖方来源相同。用户可能会配置一个来自不同来源的 URL，例如 `decisionLogicUrl: 'https://attacker.example/evil.js'`。相关的测试用例会验证这种错误配置是否被正确检测到。

3. **超出长度限制：** `AuctionConfig` 中某些字符串或 URL 可能有长度限制。用户可能会提供过长的字符串，例如很长的 `trusted_scoring_signals_url`。测试用例 `SellerDecisionAndTrustedSignalsUrlsTooLong` 验证了这种情况。

4. **使用非法的枚举值或取值范围：**  `AuctionConfig` 中可能包含枚举类型的字段或有特定取值范围的数字字段。用户可能会提供不合法的取值。例如，`seller_timeout` 字段应该是非负数，测试用例 `SellerTimeout` 验证了提供负数的情况。

5. **配置冲突：** 某些配置之间可能存在互斥或依赖关系。例如，如果启用了 `expects_additional_bids`，则必须设置 `auction_nonce`。测试用例 `AdditionalBidsNoNonce` 验证了这种依赖关系。

总而言之，`auction_config_mojom_traits_test.cc` 是一个重要的测试文件，它确保了 Protected Audience API 的配置信息可以在 Chromium 的不同组件之间可靠地传递，并且验证了配置的正确性，从而避免了因配置错误导致的功能异常或安全问题。它虽然不直接操作 JavaScript, HTML 或 CSS，但其测试结果直接影响着这些 Web 技术在 Protected Audience API 中的行为。

### 提示词
```
这是目录为blink/common/interest_group/auction_config_mojom_traits_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/interest_group/auction_config_mojom_traits.h"

#include <limits>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include "base/containers/flat_map.h"
#include "base/time/time.h"
#include "base/unguessable_token.h"
#include "base/uuid.h"
#include "mojo/public/cpp/test_support/test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/abseil-cpp/absl/numeric/int128.h"
#include "third_party/blink/common/interest_group/auction_config_test_util.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/interest_group/auction_config.h"
#include "third_party/blink/public/common/interest_group/seller_capabilities.h"
#include "third_party/blink/public/mojom/interest_group/interest_group_types.mojom.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace blink {

namespace {

// Cases for direct_from_seller_signals test parameterization.

constexpr char kPerBuyerSignals[] = "per-buyer-signals";
constexpr char kSellerSignals[] = "seller-signals";
constexpr char kAuctionSignals[] = "auction-signals";

constexpr char kBundleUrl[] = "bundle-url";
constexpr char kPrefix[] = "prefix";

// Attempts to serialize and then deserialize `auction_config`, returning true
// if deserialization succeeded. On success, also checks that the resulting
// config matches the original config.
bool SerializeAndDeserialize(const AuctionConfig& auction_config) {
  AuctionConfig auction_config_clone;
  bool success =
      mojo::test::SerializeAndDeserialize<blink::mojom::AuctionAdConfig>(
          auction_config, auction_config_clone);

  if (success) {
    EXPECT_EQ(auction_config, auction_config_clone);
    // This *should* be implied by the above, but let's check...
    EXPECT_EQ(auction_config.non_shared_params,
              auction_config_clone.non_shared_params);
  }
  return success;
}

template <class MojoType, class PromiseValue>
bool SerializeAndDeserialize(
    const AuctionConfig::MaybePromise<PromiseValue>& in) {
  AuctionConfig::MaybePromise<PromiseValue> out;
  bool success = mojo::test::SerializeAndDeserialize<MojoType>(in, out);
  if (success) {
    EXPECT_EQ(in, out);
  }
  return success;
}

bool SerializeAndDeserialize(const AuctionConfig::AdKeywordReplacement& in) {
  AuctionConfig::AdKeywordReplacement out;
  bool success =
      mojo::test::SerializeAndDeserialize<blink::mojom::AdKeywordReplacement>(
          in, out);
  if (success) {
    EXPECT_EQ(in, out);
  }
  return success;
}

bool SerializeAndDeserialize(const AuctionConfig::BuyerTimeouts& in) {
  AuctionConfig::BuyerTimeouts out;
  bool success = mojo::test::SerializeAndDeserialize<
      blink::mojom::AuctionAdConfigBuyerTimeouts>(in, out);
  if (success) {
    EXPECT_EQ(in, out);
  }
  return success;
}

bool SerializeAndDeserialize(const AuctionConfig::BuyerCurrencies& in) {
  AuctionConfig::BuyerCurrencies out;
  bool success = mojo::test::SerializeAndDeserialize<
      blink::mojom::AuctionAdConfigBuyerCurrencies>(in, out);
  if (success) {
    EXPECT_EQ(in, out);
  }
  return success;
}

bool SerializeAndDeserialize(const AdCurrency& in) {
  AdCurrency out;
  bool success =
      mojo::test::SerializeAndDeserialize<blink::mojom::AdCurrency>(in, out);
  if (success) {
    EXPECT_EQ(in.currency_code(), out.currency_code());
  }
  return success;
}

bool SerializeAndDeserialize(const AuctionConfig::ServerResponseConfig& in) {
  AuctionConfig::ServerResponseConfig out;
  bool success = mojo::test::SerializeAndDeserialize<
      blink::mojom::AuctionAdServerResponseConfig>(in, out);
  if (success) {
    EXPECT_EQ(in.request_id, out.request_id);
  }
  return success;
}

TEST(AuctionConfigMojomTraitsTest, Empty) {
  AuctionConfig auction_config;
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, Basic) {
  AuctionConfig auction_config = CreateBasicAuctionConfig();
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, SellerNotHttps) {
  AuctionConfig auction_config =
      CreateBasicAuctionConfig(GURL("http://seller.test"));
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, SellerDecisionUrlMismatch) {
  AuctionConfig auction_config =
      CreateBasicAuctionConfig(GURL("http://seller.test"));
  // Different origin than seller, but same scheme.
  auction_config.decision_logic_url = GURL("https://not.seller.test/foo");
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));

  auction_config = CreateBasicAuctionConfig(GURL("https://seller.test"));
  // This blob URL should be considered same-origin to the seller, but the
  // scheme is wrong.
  auction_config.decision_logic_url = GURL("blob:https://seller.test/foo");
  ASSERT_EQ(auction_config.seller,
            url::Origin::Create(*auction_config.decision_logic_url));
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

// Tests that decision logic and trusted scoring signals GURLs exceeding max
// length can be passed through Mojo and will be converted into invalid, empty
// GURLs, and passing in invalid URLs works as well.
TEST(AuctionConfigMojomTraitsTest, SellerDecisionAndTrustedSignalsUrlsTooLong) {
  GURL too_long_url =
      GURL("https://seller.test/" + std::string(url::kMaxURLChars, '1'));
  AuctionConfig auction_config = CreateBasicAuctionConfig(too_long_url);
  auction_config.trusted_scoring_signals_url = too_long_url;

  AuctionConfig auction_config_clone;
  bool success =
      mojo::test::SerializeAndDeserialize<blink::mojom::AuctionAdConfig>(
          auction_config, auction_config_clone);
  ASSERT_TRUE(success);
  EXPECT_EQ(auction_config.seller, auction_config_clone.seller);
  EXPECT_EQ(GURL(), auction_config_clone.decision_logic_url);
  EXPECT_EQ(GURL(), auction_config_clone.trusted_scoring_signals_url);

  EXPECT_TRUE(SerializeAndDeserialize(auction_config_clone));
}

TEST(AuctionConfigMojomTraitsTest, TrustedScoringSignalsUrl) {
  AuctionConfig auction_config =
      CreateBasicAuctionConfig(GURL("https://seller.test"));

  const struct {
    const char* url_str;
    bool expected_ok = false;
  } kTests[] = {
      {"https://seller.test/foo.json", /*expected_ok=*/true},
      {"https://seller.test/foo.json?query"},
      {"https://seller.test/foo.json?"},
      {"https://seller.test/foo.json#foo"},
      {"https://seller.test/foo.json#"},
      {"https://user:pass@seller.test/foo.json"},
      // Cross-site and cross-origin URLs are allowed.
      {"https://not.seller.test/foo.json", /*expected_ok=*/true},
      {"https://not-seller.test/foo.json", /*expected_ok=*/true},
      // This is actually the same as https://seller.test/foo.json
      {"https://:@seller.test/foo.json", /*expected_ok=*/true},
      // This blob URL should be considered same-origin to the seller, but the
      // scheme is wrong.
      {"blob:https://seller.test/foo"},
  };

  for (const auto& test : kTests) {
    SCOPED_TRACE(test.url_str);

    auction_config.trusted_scoring_signals_url = GURL(test.url_str);
    EXPECT_EQ(test.expected_ok, SerializeAndDeserialize(auction_config));
  }
}

TEST(AuctionConfigMojomTraitsTest, FullConfig) {
  AuctionConfig auction_config = CreateFullAuctionConfig();
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest,
     perBuyerPrioritySignalsCannotOverrideBrowserSignals) {
  const url::Origin kBuyer = url::Origin::Create(GURL("https://buyer.test"));

  AuctionConfig auction_config = CreateBasicAuctionConfig();
  auction_config.non_shared_params.interest_group_buyers.emplace();
  auction_config.non_shared_params.interest_group_buyers->push_back(kBuyer);
  auction_config.non_shared_params.per_buyer_priority_signals.emplace();
  (*auction_config.non_shared_params.per_buyer_priority_signals)[kBuyer] = {
      {"browserSignals.hats", 1}};

  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest,
     allBuyersPrioritySignalsCannotOverrideBrowserSignals) {
  AuctionConfig auction_config = CreateBasicAuctionConfig();
  auction_config.non_shared_params.all_buyers_priority_signals = {
      {"browserSignals.goats", 2}};
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, SerializeAndDeserializeNonFinite) {
  double test_cases[] = {
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::signaling_NaN(),
      std::numeric_limits<double>::infinity(),
      -std::numeric_limits<double>::infinity(),
  };
  size_t i = 0u;
  for (double test_case : test_cases) {
    SCOPED_TRACE(i++);
    const url::Origin kBuyer = url::Origin::Create(GURL("https://buyer.test"));

    AuctionConfig auction_config_bad_per_buyer_priority_signals =
        CreateBasicAuctionConfig();
    auction_config_bad_per_buyer_priority_signals.non_shared_params
        .interest_group_buyers.emplace();
    auction_config_bad_per_buyer_priority_signals.non_shared_params
        .interest_group_buyers = {{kBuyer}};
    auction_config_bad_per_buyer_priority_signals.non_shared_params
        .per_buyer_priority_signals.emplace();
    (*auction_config_bad_per_buyer_priority_signals.non_shared_params
          .per_buyer_priority_signals)[kBuyer] = {{"foo", test_case}};
    EXPECT_FALSE(
        SerializeAndDeserialize(auction_config_bad_per_buyer_priority_signals));

    AuctionConfig auction_config_bad_all_buyers_priority_signals =
        CreateBasicAuctionConfig();
    auction_config_bad_all_buyers_priority_signals.non_shared_params
        .all_buyers_priority_signals = {{"foo", test_case}};
    EXPECT_FALSE(SerializeAndDeserialize(
        auction_config_bad_all_buyers_priority_signals));

    AuctionConfig auction_config_bad_auction_report_buyers_scale =
        CreateBasicAuctionConfig();
    auction_config_bad_auction_report_buyers_scale.non_shared_params
        .auction_report_buyers = {
        {blink::AuctionConfig::NonSharedParams::BuyerReportType::
             kTotalSignalsFetchLatency,
         {absl::uint128(1), test_case}}};
    EXPECT_FALSE(SerializeAndDeserialize(
        auction_config_bad_auction_report_buyers_scale));
  }
}

TEST(AuctionConfigMojomTraitsTest, BuyerNotHttps) {
  AuctionConfig auction_config = CreateBasicAuctionConfig();
  auction_config.non_shared_params.interest_group_buyers.emplace();
  auction_config.non_shared_params.interest_group_buyers->push_back(
      url::Origin::Create(GURL("http://buyer.test")));
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, BuyerNotHttpsMultipleBuyers) {
  AuctionConfig auction_config = CreateBasicAuctionConfig();
  auction_config.non_shared_params.interest_group_buyers.emplace();
  auction_config.non_shared_params.interest_group_buyers->push_back(
      url::Origin::Create(GURL("https://buyer1.test")));
  auction_config.non_shared_params.interest_group_buyers->push_back(
      url::Origin::Create(GURL("http://buyer2.test")));
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, ComponentAuctionUrlHttps) {
  AuctionConfig auction_config = CreateBasicAuctionConfig();
  auction_config.non_shared_params.component_auctions.emplace_back(
      CreateBasicAuctionConfig(GURL("http://seller.test")));
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, ComponentAuctionTooDeep) {
  AuctionConfig auction_config = CreateBasicAuctionConfig();
  auction_config.non_shared_params.component_auctions.emplace_back(
      CreateBasicAuctionConfig());
  auction_config.non_shared_params.component_auctions[0]
      .non_shared_params.component_auctions.emplace_back(
          CreateBasicAuctionConfig());
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, ComponentAuctionWithNonce) {
  AuctionConfig auction_config = CreateBasicAuctionConfig();
  auction_config.non_shared_params.component_auctions.emplace_back(
      CreateBasicAuctionConfig());
  auction_config.non_shared_params.component_auctions[0]
      .non_shared_params.auction_nonce = base::Uuid::GenerateRandomV4();
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest,
     TopLevelAuctionHasBuyersAndComponentAuction) {
  AuctionConfig auction_config = CreateBasicAuctionConfig();
  auction_config.non_shared_params.component_auctions.emplace_back(
      CreateBasicAuctionConfig());
  auction_config.non_shared_params.interest_group_buyers.emplace();
  auction_config.non_shared_params.interest_group_buyers->emplace_back(
      url::Origin::Create(GURL("https://buyer.test")));
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, ComponentAuctionSuccessSingleBasic) {
  AuctionConfig auction_config = CreateBasicAuctionConfig();
  auction_config.non_shared_params.component_auctions.emplace_back(
      CreateBasicAuctionConfig());
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, ComponentAuctionSuccessMultipleFull) {
  AuctionConfig auction_config = CreateFullAuctionConfig();
  // The top-level auction cannot have buyers in a component auction.
  auction_config.non_shared_params.interest_group_buyers = {};
  auction_config.direct_from_seller_signals.mutable_value_for_testing()
      .value()
      .per_buyer_signals.clear();
  // Or additional bids.
  auction_config.expects_additional_bids = false;

  auction_config.non_shared_params.component_auctions.emplace_back(
      CreateFullAuctionConfig());
  auction_config.non_shared_params.component_auctions.emplace_back(
      CreateFullAuctionConfig());

  EXPECT_TRUE(SerializeAndDeserialize(auction_config));

  // Turning `expects_additional_bids` on at top-level makes it fail.
  auction_config.expects_additional_bids = true;
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, DuplicateAllSlotsRequestedSizes) {
  const AdSize kSize1 = AdSize(70.5, AdSize::LengthUnit::kScreenWidth, 70.6,
                               AdSize::LengthUnit::kScreenHeight);
  const AdSize kSize2 = AdSize(100, AdSize::LengthUnit::kPixels, 110,
                               AdSize::LengthUnit::kPixels);

  AuctionConfig auction_config = CreateBasicAuctionConfig();
  // An empty list is not allowed.
  auction_config.non_shared_params.all_slots_requested_sizes.emplace();
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));

  // Add one AdSize. List should be allowed.
  auction_config.non_shared_params.all_slots_requested_sizes->emplace_back(
      kSize1);
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));

  // Set `requested_size` to a different AdSize. List should not be allowed,
  // since it doesn't include `requested_size`.
  auction_config.non_shared_params.requested_size = kSize2;
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));

  // Set `requested_size` to the same AdSize. List should be allowed.
  auction_config.non_shared_params.requested_size = kSize1;
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));

  // Add the same AdSize again, list should no longer be allowed.
  auction_config.non_shared_params.all_slots_requested_sizes->emplace_back(
      kSize1);
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));

  // Replace the second AdSize with a different value, the list should still be
  // allowed again.
  auction_config.non_shared_params.all_slots_requested_sizes->back() = kSize2;
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));

  // Set the `requested_size` to the size of the second AdList. The list should
  // still be allowed.
  auction_config.non_shared_params.requested_size = kSize2;
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));

  // Add the second AdSize a second time, and the list should not be allowed
  // again.
  auction_config.non_shared_params.all_slots_requested_sizes->emplace_back(
      kSize2);
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, MaxTrustedScoringSignalsUrlLength) {
  AuctionConfig auction_config = CreateBasicAuctionConfig();
  auction_config.non_shared_params.max_trusted_scoring_signals_url_length =
      8000;
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));

  auction_config.non_shared_params.max_trusted_scoring_signals_url_length = 0;
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));

  auction_config.non_shared_params.max_trusted_scoring_signals_url_length = -1;
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, TrustedScoringSignalsCoordinator) {
  AuctionConfig auction_config = CreateBasicAuctionConfig();
  auction_config.non_shared_params.trusted_scoring_signals_coordinator =
      url::Origin::Create(GURL("https://example.test"));
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));

  auction_config.non_shared_params.trusted_scoring_signals_coordinator =
      url::Origin::Create(GURL("http://example.test"));
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));

  auction_config.non_shared_params.trusted_scoring_signals_coordinator =
      url::Origin::Create(GURL("data:,foo"));
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest,
     DirectFromSellerSignalsPrefixWithQueryString) {
  AuctionConfig auction_config = CreateFullAuctionConfig();
  auction_config.direct_from_seller_signals.mutable_value_for_testing()
      ->prefix = GURL("https://seller.test/json?queryPart");
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, DirectFromSellerSignalsBuyerNotPresent) {
  AuctionConfig auction_config = CreateFullAuctionConfig();
  DirectFromSellerSignalsSubresource& buyer2_subresource =
      auction_config.direct_from_seller_signals.mutable_value_for_testing()
          ->per_buyer_signals[url::Origin::Create(GURL("https://buyer2.test"))];
  buyer2_subresource.bundle_url = GURL("https://seller.test/bundle");
  buyer2_subresource.token = base::UnguessableToken::Create();
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest,
     DirectFromSellerSignalsNoDirectFromSellerSignals) {
  AuctionConfig auction_config = CreateFullAuctionConfig();
  auction_config.direct_from_seller_signals =
      AuctionConfig::MaybePromiseDirectFromSellerSignals::FromValue(
          std::nullopt);
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, DirectFromSellerSignalsNoPerBuyerSignals) {
  AuctionConfig auction_config = CreateFullAuctionConfig();
  auction_config.direct_from_seller_signals.mutable_value_for_testing()
      ->per_buyer_signals.clear();
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, DirectFromSellerSignalsNoSellerSignals) {
  AuctionConfig auction_config = CreateFullAuctionConfig();
  auction_config.direct_from_seller_signals.mutable_value_for_testing()
      ->seller_signals = std::nullopt;
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, DirectFromSellerSignalsNoAuctionSignals) {
  AuctionConfig auction_config = CreateFullAuctionConfig();
  auction_config.direct_from_seller_signals.mutable_value_for_testing()
      ->auction_signals = std::nullopt;
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, DirectFromSellerSignalsHeaderAdSlot) {
  AuctionConfig auction_config = CreateFullAuctionConfig();
  auction_config.direct_from_seller_signals =
      AuctionConfig::MaybePromiseDirectFromSellerSignals::FromValue(
          std::nullopt);
  auction_config.expects_direct_from_seller_signals_header_ad_slot = true;
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest,
     DirectFromSellerSignalsCantHaveBothBundlesAndHeaderAdSlot) {
  AuctionConfig auction_config = CreateFullAuctionConfig();
  auction_config.expects_direct_from_seller_signals_header_ad_slot = true;
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest,
     DirectFromSellerSignalsCantHaveBothBundlesAndHeaderAdSlotPromise) {
  AuctionConfig auction_config = CreateFullAuctionConfig();
  auction_config.direct_from_seller_signals =
      AuctionConfig::MaybePromiseDirectFromSellerSignals::FromPromise();
  auction_config.expects_direct_from_seller_signals_header_ad_slot = true;
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

TEST(AuctionConfigMojomTraitsTest, MaybePromiseJson) {
  {
    AuctionConfig::MaybePromiseJson json =
        AuctionConfig::MaybePromiseJson::FromValue("{A: 42}");
    EXPECT_TRUE(
        SerializeAndDeserialize<blink::mojom::AuctionAdConfigMaybePromiseJson>(
            json));
  }

  {
    AuctionConfig::MaybePromiseJson nothing =
        AuctionConfig::MaybePromiseJson::FromValue(std::nullopt);
    EXPECT_TRUE(
        SerializeAndDeserialize<blink::mojom::AuctionAdConfigMaybePromiseJson>(
            nothing));
  }

  {
    AuctionConfig::MaybePromiseJson promise =
        AuctionConfig::MaybePromiseJson::FromPromise();
    EXPECT_TRUE(
        SerializeAndDeserialize<blink::mojom::AuctionAdConfigMaybePromiseJson>(
            promise));
  }
}

TEST(AuctionConfigMojomTraitsTest, MaybePromisePerBuyerSignals) {
  {
    std::optional<base::flat_map<url::Origin, std::string>> value;
    value.emplace();
    value->emplace(url::Origin::Create(GURL("https://example.com")), "42");
    AuctionConfig::MaybePromisePerBuyerSignals signals =
        AuctionConfig::MaybePromisePerBuyerSignals::FromValue(std::move(value));
    EXPECT_TRUE(
        SerializeAndDeserialize<
            blink::mojom::AuctionAdConfigMaybePromisePerBuyerSignals>(signals));
  }

  {
    AuctionConfig::MaybePromisePerBuyerSignals signals =
        AuctionConfig::MaybePromisePerBuyerSignals::FromPromise();
    EXPECT_TRUE(
        SerializeAndDeserialize<
            blink::mojom::AuctionAdConfigMaybePromisePerBuyerSignals>(signals));
  }
}

TEST(AuctionConfigMojomTraitsTest,
     MaybePromiseDeprecatedRenderURLReplacements) {
  {
    std::vector<blink::AuctionConfig::AdKeywordReplacement> value;
    value.push_back(blink::AuctionConfig::AdKeywordReplacement(
        "${INTEREST_GROUP_NAME}", "cars"));
    AuctionConfig::MaybePromiseDeprecatedRenderURLReplacements replacements =
        AuctionConfig::MaybePromiseDeprecatedRenderURLReplacements::FromValue(
            std::move(value));
    EXPECT_TRUE(SerializeAndDeserialize<
                blink::mojom::
                    AuctionAdConfigMaybePromiseDeprecatedRenderURLReplacements>(
        replacements));
  }

  {
    AuctionConfig::MaybePromiseDeprecatedRenderURLReplacements replacements =
        AuctionConfig::MaybePromiseDeprecatedRenderURLReplacements::
            FromPromise();
    EXPECT_TRUE(SerializeAndDeserialize<
                blink::mojom::
                    AuctionAdConfigMaybePromiseDeprecatedRenderURLReplacements>(
        replacements));
  }
}

TEST(AuctionConfigMojomTraitsTest, DeprecatedRenderURLReplacements) {
  {
    AuctionConfig::AdKeywordReplacement value;
    value.match = "${INTEREST_GROUP_NAME}";
    value.replacement = "cars";
    EXPECT_TRUE(SerializeAndDeserialize(value));
  }

  {
    AuctionConfig::AdKeywordReplacement value;
    value.match = "%%INTEREST_GROUP_NAME%%";
    value.replacement = "BOATS";
    EXPECT_TRUE(SerializeAndDeserialize(value));
  }
}

TEST(AuctionConfigMojomTraitsTest,
     DeprecatedRenderURLReplacementsBadFormatting) {
  {
    AuctionConfig::AdKeywordReplacement value;
    value.match = "${NO_END_BRACKET";
    value.replacement = "cars";
    EXPECT_FALSE(SerializeAndDeserialize(value));
  }

  {
    AuctionConfig::AdKeywordReplacement value;
    value.match = "%%NO_END_PERCENT";
    value.replacement = "cars";
    EXPECT_FALSE(SerializeAndDeserialize(value));
  }

  {
    AuctionConfig::AdKeywordReplacement value;
    value.match = "%SINGLE_START_PERCENT%%";
    value.replacement = "cars";
    EXPECT_FALSE(SerializeAndDeserialize(value));
  }
  {
    AuctionConfig::AdKeywordReplacement value;
    value.match = "{NO_DOLLAR_SIGN}";
    value.replacement = "cars";
    EXPECT_FALSE(SerializeAndDeserialize(value));
  }
}

TEST(AuctionConfigMojomTraitsTest, SellerTimeout) {
  {
    AuctionConfig auction_config = CreateBasicAuctionConfig();
    auction_config.non_shared_params.seller_timeout = base::Milliseconds(50);
    EXPECT_TRUE(SerializeAndDeserialize(auction_config));
  }
  {
    AuctionConfig auction_config = CreateBasicAuctionConfig();
    auction_config.non_shared_params.seller_timeout = base::Milliseconds(0);
    EXPECT_TRUE(SerializeAndDeserialize(auction_config));
  }
  {
    AuctionConfig auction_config = CreateBasicAuctionConfig();
    auction_config.non_shared_params.seller_timeout = base::Milliseconds(-50);
    EXPECT_FALSE(SerializeAndDeserialize(auction_config));
  }
}

TEST(AuctionConfigMojomTraitsTest, BuyerTimeouts) {
  {
    AuctionConfig::BuyerTimeouts value;
    value.all_buyers_timeout.emplace(base::Milliseconds(10));
    value.per_buyer_timeouts.emplace();
    value.per_buyer_timeouts->emplace(
        url::Origin::Create(GURL("https://example.com")),
        base::Milliseconds(50));
    value.per_buyer_timeouts->emplace(
        url::Origin::Create(GURL("https://example.org")),
        base::Milliseconds(0));
    EXPECT_TRUE(SerializeAndDeserialize(value));
  }
  {
    AuctionConfig::BuyerTimeouts value;
    EXPECT_TRUE(SerializeAndDeserialize(value));
  }
  {
    AuctionConfig::BuyerTimeouts value;
    value.all_buyers_timeout.emplace(base::Milliseconds(-10));
    EXPECT_FALSE(SerializeAndDeserialize(value));
  }
  {
    AuctionConfig::BuyerTimeouts value;
    value.per_buyer_timeouts.emplace();
    value.per_buyer_timeouts->emplace(
        url::Origin::Create(GURL("https://example.com")),
        base::Milliseconds(-50));
    EXPECT_FALSE(SerializeAndDeserialize(value));
  }
}

TEST(AuctionConfigMojomTraitsTest, MaybePromiseBuyerTimeouts) {
  {
    AuctionConfig::BuyerTimeouts value;
    value.all_buyers_timeout.emplace(base::Milliseconds(10));
    value.per_buyer_timeouts.emplace();
    value.per_buyer_timeouts->emplace(
        url::Origin::Create(GURL("https://example.com")),
        base::Milliseconds(50));
    AuctionConfig::MaybePromiseBuyerTimeouts timeouts =
        AuctionConfig::MaybePromiseBuyerTimeouts::FromValue(std::move(value));
    EXPECT_TRUE(
        SerializeAndDeserialize<
            blink::mojom::AuctionAdConfigMaybePromiseBuyerTimeouts>(timeouts));
  }

  {
    AuctionConfig::MaybePromiseBuyerTimeouts timeouts =
        AuctionConfig::MaybePromiseBuyerTimeouts::FromPromise();
    EXPECT_TRUE(
        SerializeAndDeserialize<
            blink::mojom::AuctionAdConfigMaybePromiseBuyerTimeouts>(timeouts));
  }

  {
    AuctionConfig::BuyerTimeouts value;
    value.all_buyers_timeout.emplace(base::Milliseconds(-10));
    AuctionConfig::MaybePromiseBuyerTimeouts timeouts =
        AuctionConfig::MaybePromiseBuyerTimeouts::FromValue(std::move(value));
    EXPECT_FALSE(
        SerializeAndDeserialize<
            blink::mojom::AuctionAdConfigMaybePromiseBuyerTimeouts>(timeouts));
  }

  {
    AuctionConfig::BuyerTimeouts value;
    value.per_buyer_timeouts.emplace();
    value.per_buyer_timeouts->emplace(
        url::Origin::Create(GURL("https://example.com")),
        base::Milliseconds(-50));
    AuctionConfig::MaybePromiseBuyerTimeouts timeouts =
        AuctionConfig::MaybePromiseBuyerTimeouts::FromValue(std::move(value));
    EXPECT_FALSE(
        SerializeAndDeserialize<
            blink::mojom::AuctionAdConfigMaybePromiseBuyerTimeouts>(timeouts));
  }
}

TEST(AuctionConfigMojomTraitsTest, ReportingTimeout) {
  {
    AuctionConfig auction_config = CreateBasicAuctionConfig();
    auction_config.non_shared_params.reporting_timeout = base::Milliseconds(50);
    EXPECT_TRUE(SerializeAndDeserialize(auction_config));
  }
  {
    AuctionConfig auction_config = CreateBasicAuctionConfig();
    auction_config.non_shared_params.reporting_timeout = base::Milliseconds(0);
    EXPECT_TRUE(SerializeAndDeserialize(auction_config));
  }
  {
    AuctionConfig auction_config = CreateBasicAuctionConfig();
    auction_config.non_shared_params.reporting_timeout =
        base::Milliseconds(-50);
    EXPECT_FALSE(SerializeAndDeserialize(auction_config));
  }
}

TEST(AuctionConfigMojomTraitsTest, BuyerCurrencies) {
  {
    AuctionConfig::BuyerCurrencies value;
    value.all_buyers_currency = blink::AdCurrency::From("EUR");
    value.per_buyer_currencies.emplace();
    value.per_buyer_currencies->emplace(
        url::Origin::Create(GURL("https://example.co.uk")),
        blink::AdCurrency::From("GBP"));
    value.per_buyer_currencies->emplace(
        url::Origin::Create(GURL("https://example.ca")),
        blink::AdCurrency::From("CAD"));
    EXPECT_TRUE(SerializeAndDeserialize(value));
  }
  {
    AuctionConfig::BuyerCurrencies value;
    EXPECT_TRUE(SerializeAndDeserialize(value));
  }
}

TEST(AuctionConfigMojomTraitsTest, AdCurrency) {
  {
    AdCurrency value = AdCurrency::From("EUR");
    EXPECT_TRUE(SerializeAndDeserialize(value));
  }
  {
    AdCurrency value;
    value.SetCurrencyCodeForTesting("eur");
    EXPECT_FALSE(SerializeAndDeserialize(value));
  }
  {
    AdCurrency value;
    value.SetCurrencyCodeForTesting("EURO");
    EXPECT_FALSE(SerializeAndDeserialize(value));
  }
}

TEST(AuctionConfigMojomTraitsTest, MaybePromiseDirectFromSellerSignals) {
  {
    AuctionConfig::MaybePromiseDirectFromSellerSignals signals =
        CreateFullAuctionConfig().direct_from_seller_signals;
    EXPECT_TRUE(
        SerializeAndDeserialize<
            blink::mojom::AuctionAdConfigMaybePromiseDirectFromSellerSignals>(
            signals));
  }

  {
    AuctionConfig::MaybePromiseDirectFromSellerSignals signals =
        AuctionConfig::MaybePromiseDirectFromSellerSignals::FromPromise();
    EXPECT_TRUE(
        SerializeAndDeserialize<
            blink::mojom::AuctionAdConfigMaybePromiseDirectFromSellerSignals>(
            signals));
  }
}

TEST(AuctionConfigMojomTraitsTest, ServerResponseConfig) {
  {
    AuctionConfig::ServerResponseConfig config;
    config.request_id = base::Uuid::GenerateRandomV4();
    EXPECT_TRUE(SerializeAndDeserialize(config));
  }
}

// Can't have `expects_additional_bids` without a nonce.
TEST(AuctionConfigMojomTraitsTest, AdditionalBidsNoNonce) {
  AuctionConfig auction_config = CreateFullAuctionConfig();
  ASSERT_TRUE(auction_config.expects_additional_bids);
  auction_config.non_shared_params.auction_nonce.reset();
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));

  auction_config.expects_additional_bids = false;
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));
}

// Can't have `expects_additional_bids` with no interestGroupBuyers.
TEST(AuctionConfigMojomTraitsTest, AdditionalBidsNoInterestGroupBuyers) {
  AuctionConfig auction_config = CreateFullAuctionConfig();
  // These rely on interestGroupBuyers, so we have to clear these for this test.
  auction_config.direct_from_seller_signals.mutable_value_for_testing().reset();

  ASSERT_TRUE(auction_config.expects_additional_bids);
  auction_config.non_shared_params.interest_group_buyers.reset();
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));

  auction_config.expects_additional_bids = false;
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));
}

// Can't have `expects_additional_bids` with empty interestGroupBuyers.
TEST(AuctionConfigMojomTraitsTest, AdditionalBidsEmptyInterestGroupBuyers) {
  AuctionConfig auction_config = CreateFullAuctionConfig();
  // These rely on interestGroupBuyers, so we have to clear these for this test.
  auction_config.direct_from_seller_signals.mutable_value_for_testing().reset();

  ASSERT_TRUE(auction_config.expects_additional_bids);
  auction_config.non_shared_params.interest_group_buyers->clear();
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));

  auction_config.expects_additional_bids = false;
  EXPECT_TRUE(SerializeAndDeserialize(auction_config));
}

class AuctionConfigMojomTraitsDirectFromSellerSignalsTest
    : public ::testing::TestWithParam<std::tuple<const char*, const char*>> {
 public:
  GURL& GetMutableURL(AuctionConfig& auction_config) const {
    const std::string which_path = WhichPath();
    DCHECK(!auction_config.direct_from_seller_signals.is_promise());
    if (which_path == kPrefix) {
      return auction_config.direct_from_seller_signals
          .mutable_value_for_testing()
          ->prefix;
    } else {
      EXPECT_EQ(which_path, kBundleUrl);
      const std::string which_bundle = WhichBundle();
      if (which_bundle == kPerBuyerSignals) {
        return auction_config.direct_from_seller_signals
            .mutable_value_for_testing()
            ->per_buyer_signals
            .at(url::Origin::Create(GURL("https://buyer.test")))
            .bundle_url;
      } else if (which_bundle == kSellerSignals) {
        return auction_config.direct_from_seller_signals
            .mutable_value_for_testing()
            ->seller_signals->bundle_url;
      } else {
        EXPECT_EQ(which_bundle, kAuctionSignals);
        return auction_config.direct_from_seller_signals
            .mutable_value_for_testing()
            ->auction_signals->bundle_url;
      }
    }
  }

  std::string GetURLPath() const {
    const std::string which_path = WhichPath();
    if (which_path == kBundleUrl) {
      return "/bundle";
    } else {
      EXPECT_EQ(which_path, kPrefix);
      return "/json";
    }
  }

 private:
  std::string WhichBundle() const { return std::get<0>(GetParam()); }
  std::string WhichPath() const { return std::get<1>(GetParam()); }
};

TEST_P(AuctionConfigMojomTraitsDirectFromSellerSignalsTest, NotHttps) {
  AuctionConfig auction_config = CreateFullAuctionConfig();
  GetMutableURL(auction_config) = GURL("http://seller.test" + GetURLPath());
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

TEST_P(AuctionConfigMojomTraitsDirectFromSellerSignalsTest, WrongOrigin) {
  AuctionConfig auction_config = CreateFullAuctionConfig();
  GetMutableURL(auction_config) = GURL("https://seller2.test" + GetURLPath());
  EXPECT_FALSE(SerializeAndDeserialize(auction_config));
}

INSTANTIATE_TEST_SUITE_P(All,
                         AuctionConfigMojomTraitsDirectFromSellerSignalsTest,
                         ::testing::Combine(::testing::Values(kPerBuyerSignals,
                                                              kSellerSignals,
                                                              kAuctionSignals),
                                            ::testing::Values(kBundleUrl,
                                                              kPrefix)));

}  // namespace

}  // namespace blink
```