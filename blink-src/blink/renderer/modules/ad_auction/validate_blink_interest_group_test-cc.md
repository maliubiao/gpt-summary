Response:
The user wants a summary of the functionality of the provided C++ test file. I need to identify the main purpose of the tests and how they relate to web technologies.

**Plan:**

1. Identify the core functionality being tested in the file.
2. Determine if this functionality is related to JavaScript, HTML, or CSS.
3. Summarize the file's purpose based on the identified functionalities.
这是 `blink/renderer/modules/ad_auction/validate_blink_interest_group_test.cc` 文件的第一部分，主要功能是**测试 `ValidateBlinkInterestGroup` 函数的正确性**。这个函数的作用是**验证 `mojom::blink::InterestGroup` 结构体（Blink引擎内部表示兴趣组的数据结构）的有效性**。

**功能归纳:**

该文件包含了针对 `ValidateBlinkInterestGroup` 函数的各种测试用例，旨在确保该函数能够正确地识别出有效和无效的 `mojom::blink::InterestGroup` 对象。这些测试覆盖了兴趣组的各个字段，并验证了不同类型的值是否符合预期。

**与 JavaScript, HTML, CSS 的关系:**

虽然这个文件本身是 C++ 代码，但它所测试的功能直接关系到 **JavaScript API** 中用于管理兴趣组的部分，即 **Fenced Frames API 和 Protected Audience API (以前称为 TURTLEDOVE)**。

*   **JavaScript:** 网站可以使用 JavaScript 调用浏览器提供的 API 来创建、加入和管理兴趣组。`ValidateBlinkInterestGroup` 函数用于在 Blink 引擎内部验证通过 JavaScript API 传递的兴趣组数据是否符合规范。例如，当一个网站通过 JavaScript 调用 `navigator.joinAdInterestGroup()` 方法来创建一个新的兴趣组时，Blink 引擎会使用 `ValidateBlinkInterestGroup` 来验证传递的参数（如兴趣组的名称、所有者、竞价脚本 URL 等）。

*   **HTML:** 兴趣组信息最终会影响到广告的展示。在 Fenced Frames 中，兴趣组信息会影响到哪个兴趣组的广告可以被渲染在特定的 `<iframe>` 标签中。在 Protected Audience API 中，兴趣组信息被用于在竞价过程中选择合适的广告。

*   **CSS:** 虽然这个文件本身不直接涉及 CSS，但最终选择展示的广告会使用 HTML 和 CSS 来进行渲染。

**逻辑推理 (假设输入与输出):**

假设 `ValidateBlinkInterestGroup` 函数接收一个 `mojom::blink::InterestGroupPtr` 作为输入。

*   **假设输入 1 (有效的兴趣组):**
    ```c++
    mojom::blink::InterestGroupPtr valid_group = mojom::blink::InterestGroup::New();
    valid_group->owner = SecurityOrigin::CreateFromString(String::FromUTF8("https://example.com"));
    valid_group->name = String::FromUTF8("my-interest-group");
    valid_group->bidding_url = KURL(String::FromUTF8("https://example.com/bid.js"));
    // ... 其他必要的有效字段
    ```
    **预期输出:** `ValidateBlinkInterestGroup` 函数返回 `true`，并且错误信息为空。

*   **假设输入 2 (无效的兴趣组 - 所有者不是 HTTPS):**
    ```c++
    mojom::blink::InterestGroupPtr invalid_group = mojom::blink::InterestGroup::New();
    invalid_group->owner = SecurityOrigin::CreateFromString(String::FromUTF8("http://example.com"));
    invalid_group->name = String::FromUTF8("my-interest-group");
    // ... 其他字段
    ```
    **预期输出:** `ValidateBlinkInterestGroup` 函数返回 `false`，并且会提供错误字段名称 (例如 "owner")，错误字段值 (例如 "http://example.com") 以及具体的错误信息 (例如 "owner origin must be HTTPS.")。

**用户或编程常见的使用错误 (举例说明):**

*   **错误的 URL 协议:** 开发者可能在设置兴趣组的 URL 时使用了 `http://` 而不是 `https://`，例如设置 `bidding_url` 为 `http://example.com/bid.js`。`ValidateBlinkInterestGroup` 会检测到这个错误并拒绝该兴趣组。

*   **URL 中包含用户名或密码:**  为了安全考虑，兴趣组的某些 URL（如竞价脚本 URL）不允许包含用户名和密码。如果开发者不小心在 URL 中包含了这些信息，`ValidateBlinkInterestGroup` 会标记为无效。

*   **兴趣组大小超出限制:** 兴趣组的大小是有限制的。如果开发者向兴趣组添加了过多的广告或其他数据，导致其大小超过了限制，`ValidateBlinkInterestGroup` 会报错。

**用户操作如何一步步到达这里 (调试线索):**

1. **网站开发者编写 JavaScript 代码:** 网站开发者使用 JavaScript 的 Fenced Frames API 或 Protected Audience API 来创建或更新兴趣组。例如，调用 `navigator.joinAdInterestGroup()`。
2. **浏览器接收到 JavaScript 调用:** 浏览器接收到 JavaScript 的请求，开始处理兴趣组的创建或更新操作。
3. **数据传递到 Blink 引擎:** JavaScript 传递的兴趣组数据（例如，通过 `joinAdInterestGroup` 的参数）会被转换为 Blink 引擎内部的 `mojom::blink::InterestGroup` 结构体。
4. **调用 `ValidateBlinkInterestGroup`:** Blink 引擎会调用 `ValidateBlinkInterestGroup` 函数来验证接收到的 `mojom::blink::InterestGroup` 结构体的有效性。
5. **验证失败并抛出错误 (如果验证失败):** 如果 `ValidateBlinkInterestGroup` 检测到任何不符合规范的地方，它会返回错误信息。这些错误信息可能会被浏览器捕获，并通过 JavaScript 的 Promise rejection 或其他机制反馈给网站开发者，告知他们兴趣组创建或更新失败的原因。

**总结 (第 1 部分的功能):**

`validate_blink_interest_group_test.cc` 文件的第一部分主要负责测试 Blink 引擎中用于验证兴趣组数据结构 (`mojom::blink::InterestGroup`) 的 `ValidateBlinkInterestGroup` 函数。这些测试旨在确保该函数能够正确识别出符合规范的兴趣组，并有效地拒绝不合规的配置，从而保证 Fenced Frames 和 Protected Audience API 的安全性和正确性。它间接地与 JavaScript API 相关联，因为该函数验证的数据正是通过 JavaScript API 传递到 Blink 引擎的。

Prompt: 
```
这是目录为blink/renderer/modules/ad_auction/validate_blink_interest_group_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/ad_auction/validate_blink_interest_group.h"

#include "base/memory/scoped_refptr.h"
#include "base/strings/stringprintf.h"
#include "base/test/scoped_feature_list.h"
#include "mojo/public/cpp/bindings/map_traits_wtf_hash_map.h"
#include "mojo/public/cpp/bindings/message.h"
#include "mojo/public/cpp/test_support/test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/interest_group/interest_group.h"
#include "third_party/blink/public/mojom/interest_group/ad_display_size.mojom-blink.h"
#include "third_party/blink/public/mojom/interest_group/interest_group_types.mojom-blink.h"
#include "third_party/blink/public/mojom/interest_group/interest_group_types.mojom.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace blink {

namespace {

constexpr char kOriginString[] = "https://origin.test/";
constexpr char kNameString[] = "name";
constexpr char kCoordinatorOriginString[] = "https://example.test/";

mojom::blink::InterestGroupAdPtr MakeAdWithUrl(const KURL& url) {
  return mojom::blink::InterestGroupAd::New(
      url, /*size_group=*/String(),
      /*buyer_reporting_id=*/String(),
      /*buyer_and_seller_reporting_id=*/String(),
      /*selectable_buyer_and_seller_reporting_ids=*/std::nullopt,
      /*metadata=*/String(), /*ad_render_id=*/String(),
      /*allowed_reporting_origins=*/std::nullopt);
}

}  // namespace

// Test fixture for testing both ValidateBlinkInterestGroup() and
// ValidateInterestGroup(), and making sure they behave the same.
class ValidateBlinkInterestGroupTest : public testing::Test {
 public:
  // Check that `blink_interest_group` is valid, if added from its owner origin.
  void ExpectInterestGroupIsValid(
      const mojom::blink::InterestGroupPtr& blink_interest_group) {
    String error_field_name;
    String error_field_value;
    String error;
    EXPECT_TRUE(ValidateBlinkInterestGroup(
        *blink_interest_group, error_field_name, error_field_value, error));
    EXPECT_TRUE(error_field_name.IsNull());
    EXPECT_TRUE(error_field_value.IsNull());
    EXPECT_TRUE(error.IsNull());

    blink::InterestGroup interest_group;
    EXPECT_TRUE(
        mojo::test::SerializeAndDeserialize<mojom::blink::InterestGroup>(
            blink_interest_group, interest_group));
    EXPECT_EQ(EstimateBlinkInterestGroupSize(*blink_interest_group),
              interest_group.EstimateSize());
  }

  // Check that `blink_interest_group` is not valid, if added from
  // `blink_origin`, and returns the provided error values.
  void ExpectInterestGroupIsNotValid(
      const mojom::blink::InterestGroupPtr& blink_interest_group,
      String expected_error_field_name,
      String expected_error_field_value,
      String expected_error,
      bool check_deserialization = true) {
    String error_field_name;
    String error_field_value;
    String error;
    EXPECT_FALSE(ValidateBlinkInterestGroup(
        *blink_interest_group, error_field_name, error_field_value, error));
    EXPECT_EQ(expected_error_field_name, error_field_name);
    EXPECT_EQ(expected_error_field_value, error_field_value);
    EXPECT_EQ(expected_error, error);

    if (check_deserialization) {
      blink::InterestGroup interest_group;
      // mojo deserialization will call InterestGroup::IsValid.
      EXPECT_FALSE(
          mojo::test::SerializeAndDeserialize<mojom::blink::InterestGroup>(
              blink_interest_group, interest_group));
    }
  }

  // Creates and returns a minimally populated mojom::blink::InterestGroup.
  mojom::blink::InterestGroupPtr CreateMinimalInterestGroup() {
    mojom::blink::InterestGroupPtr blink_interest_group =
        mojom::blink::InterestGroup::New();
    blink_interest_group->owner = kOrigin;
    blink_interest_group->name = kName;
    blink_interest_group->all_sellers_capabilities =
        mojom::blink::SellerCapabilities::New();
    blink_interest_group->auction_server_request_flags =
        mojom::blink::AuctionServerRequestFlags::New();
    return blink_interest_group;
  }

  // Creates an interest group with all fields populated with valid values.
  mojom::blink::InterestGroupPtr CreateFullyPopulatedInterestGroup() {
    mojom::blink::InterestGroupPtr blink_interest_group =
        CreateMinimalInterestGroup();

    // Url that's allowed in every field. Populate all portions of the URL that
    // are allowed in most places.
    const KURL kAllowedUrl =
        KURL(String::FromUTF8("https://origin.test/foo?bar"));
    blink_interest_group->bidding_url = kAllowedUrl;
    blink_interest_group->update_url = kAllowedUrl;
    blink_interest_group->bidding_wasm_helper_url = kAllowedUrl;

    // `trusted_bidding_signals_url` doesn't allow query strings, unlike the
    // above ones.
    blink_interest_group->trusted_bidding_signals_url =
        KURL(String::FromUTF8("https://origin.test/foo"));

    blink_interest_group->trusted_bidding_signals_keys.emplace();
    blink_interest_group->trusted_bidding_signals_keys->push_back(
        String::FromUTF8("1"));
    blink_interest_group->trusted_bidding_signals_keys->push_back(
        String::FromUTF8("2"));
    blink_interest_group->max_trusted_bidding_signals_url_length = 8000;
    blink_interest_group->trusted_bidding_signals_coordinator =
        kCoordinatorOrigin;
    blink_interest_group->user_bidding_signals =
        String::FromUTF8("\"This field isn't actually validated\"");

    // Add two ads. Use different URLs, with references.
    blink_interest_group->ads.emplace();
    auto mojo_ad1 = mojom::blink::InterestGroupAd::New();
    mojo_ad1->render_url =
        KURL(String::FromUTF8("https://origin.test/foo?bar#baz"));
    mojo_ad1->metadata =
        String::FromUTF8("\"This field isn't actually validated\"");
    mojo_ad1->ad_render_id = String::FromUTF8("\"NotTooLong\"");
    mojo_ad1->allowed_reporting_origins.emplace();
    mojo_ad1->allowed_reporting_origins->emplace_back(kOrigin);
    blink_interest_group->ads->push_back(std::move(mojo_ad1));
    auto mojo_ad2 = mojom::blink::InterestGroupAd::New();
    mojo_ad2->render_url =
        KURL(String::FromUTF8("https://origin.test/foo?bar#baz2"));
    blink_interest_group->ads->push_back(std::move(mojo_ad2));

    // Add two ad components. Use different URLs, with references.
    blink_interest_group->ad_components.emplace();
    auto mojo_ad_component1 = mojom::blink::InterestGroupAd::New();
    mojo_ad_component1->render_url =
        KURL(String::FromUTF8("https://origin.test/components?bar#baz"));
    mojo_ad_component1->metadata =
        String::FromUTF8("\"This field isn't actually validated\"");
    mojo_ad_component1->ad_render_id = String::FromUTF8("\"NotTooLong\"");
    blink_interest_group->ad_components->push_back(
        std::move(mojo_ad_component1));
    auto mojo_ad_component2 = mojom::blink::InterestGroupAd::New();
    mojo_ad_component2->render_url =
        KURL(String::FromUTF8("https://origin.test/foo?component#baz2"));
    blink_interest_group->ad_components->push_back(
        std::move(mojo_ad_component2));

    blink_interest_group->auction_server_request_flags =
        mojom::blink::AuctionServerRequestFlags::New();
    blink_interest_group->auction_server_request_flags->omit_ads = true;
    blink_interest_group->auction_server_request_flags
        ->omit_user_bidding_signals = true;

    blink_interest_group->aggregation_coordinator_origin = kCoordinatorOrigin;

    return blink_interest_group;
  }

 protected:
  // SecurityOrigin used as the owner in most tests.
  const scoped_refptr<const SecurityOrigin> kOrigin =
      SecurityOrigin::CreateFromString(String::FromUTF8(kOriginString));

  const String kName = String::FromUTF8(kNameString);
  const scoped_refptr<const SecurityOrigin> kCoordinatorOrigin =
      SecurityOrigin::CreateFromString(
          String::FromUTF8(kCoordinatorOriginString));
  test::TaskEnvironment task_environment_;
};

// Test behavior with an InterestGroup with as few fields populated as allowed.
TEST_F(ValidateBlinkInterestGroupTest, MinimallyPopulated) {
  mojom::blink::InterestGroupPtr blink_interest_group =
      CreateMinimalInterestGroup();
  ExpectInterestGroupIsValid(blink_interest_group);
}

// Test behavior with an InterestGroup with all fields populated with valid
// values.
TEST_F(ValidateBlinkInterestGroupTest, FullyPopulated) {
  mojom::blink::InterestGroupPtr blink_interest_group =
      CreateFullyPopulatedInterestGroup();
  ExpectInterestGroupIsValid(blink_interest_group);
}

// Make sure that non-HTTPS origins are rejected, both as the frame origin, and
// as the owner. HTTPS frame origins with non-HTTPS owners are currently
// rejected due to origin mismatch, but once sites can add users to 3P interest
// groups, they should still be rejected for being non-HTTPS.
TEST_F(ValidateBlinkInterestGroupTest, NonHttpsOriginRejected) {
  mojom::blink::InterestGroupPtr blink_interest_group =
      CreateMinimalInterestGroup();
  blink_interest_group->owner =
      SecurityOrigin::CreateFromString(String::FromUTF8("http://origin.test/"));
  ExpectInterestGroupIsNotValid(
      blink_interest_group,
      /*expected_error_field_name=*/String::FromUTF8("owner"),
      /*expected_error_field_value=*/String::FromUTF8("http://origin.test"),
      /*expected_error=*/String::FromUTF8("owner origin must be HTTPS."));

  blink_interest_group->owner =
      SecurityOrigin::CreateFromString(String::FromUTF8("data:,foo"));
  // Data URLs have opaque origins, which are mapped to the string "null".
  ExpectInterestGroupIsNotValid(
      blink_interest_group,
      /*expected_error_field_name=*/String::FromUTF8("owner"),
      /*expected_error_field_value=*/String::FromUTF8("null"),
      /*expected_error=*/String::FromUTF8("owner origin must be HTTPS."));
}

// Same as NonHttpsOriginRejected, but for `seller_capabilities`.
TEST_F(ValidateBlinkInterestGroupTest,
       NonHttpsOriginRejectedSellerCapabilities) {
  mojom::blink::InterestGroupPtr blink_interest_group =
      CreateMinimalInterestGroup();
  blink_interest_group->seller_capabilities.emplace();
  blink_interest_group->seller_capabilities->insert(
      SecurityOrigin::CreateFromString(
          String::FromUTF8("https://origin.test/")),
      mojom::blink::SellerCapabilities::New());
  blink_interest_group->seller_capabilities->insert(
      SecurityOrigin::CreateFromString(String::FromUTF8("http://origin.test/")),
      mojom::blink::SellerCapabilities::New());
  ExpectInterestGroupIsNotValid(
      blink_interest_group,
      /*expected_error_field_name=*/String::FromUTF8("sellerCapabilities"),
      /*expected_error_field_value=*/String::FromUTF8("http://origin.test"),
      /*expected_error=*/
      String::FromUTF8("sellerCapabilities origins must all be HTTPS."));

  blink_interest_group->seller_capabilities->clear();
  blink_interest_group->seller_capabilities->insert(
      SecurityOrigin::CreateFromString(String::FromUTF8("data:,foo")),
      mojom::blink::SellerCapabilities::New());
  blink_interest_group->seller_capabilities->insert(
      SecurityOrigin::CreateFromString(
          String::FromUTF8("https://origin.test/")),
      mojom::blink::SellerCapabilities::New());
  // Data URLs have opaque origins, which are mapped to the string "null".
  ExpectInterestGroupIsNotValid(
      blink_interest_group,
      /*expected_error_field_name=*/String::FromUTF8("sellerCapabilities"),
      /*expected_error_field_value=*/String::FromUTF8("null"),
      /*expected_error=*/
      String::FromUTF8("sellerCapabilities origins must all be HTTPS."));

  blink_interest_group->seller_capabilities->clear();
  blink_interest_group->seller_capabilities->insert(
      SecurityOrigin::CreateFromString(String::FromUTF8("https://origin.test")),
      mojom::blink::SellerCapabilities::New());
  blink_interest_group->seller_capabilities->insert(
      SecurityOrigin::CreateFromString(String::FromUTF8("https://invalid^&")),
      mojom::blink::SellerCapabilities::New());
  // Data URLs have opaque origins, which are mapped to the string "null".
  ExpectInterestGroupIsNotValid(
      blink_interest_group,
      /*expected_error_field_name=*/String::FromUTF8("sellerCapabilities"),
      /*expected_error_field_value=*/String::FromUTF8("null"),
      /*expected_error=*/
      String::FromUTF8("sellerCapabilities origins must all be HTTPS."));
}

// Check that `bidding_url`, `bidding_wasm_helper_url`, `update_url`, and
// `trusted_bidding_signals_url` must be same-origin and HTTPS.
//
// Ad URLs do not have to be same origin, so they're checked in a different
// test.
TEST_F(ValidateBlinkInterestGroupTest, RejectedUrls) {
  // Strings when each field has a bad URL, copied from cc file.
  const char kBadBiddingUrlError[] =
      "biddingLogicURL must have the same origin as the InterestGroup owner "
      "and have no fragment identifier or embedded credentials.";
  const char kBadBiddingWasmHelperUrlError[] =
      "biddingWasmHelperURL must have the same origin as the InterestGroup "
      "owner and have no fragment identifier or embedded credentials.";
  const char kBadUpdateUrlError[] =
      "updateURL must have the same origin as the InterestGroup owner "
      "and have no fragment identifier or embedded credentials.";

  // Nested URL schemes, like filesystem URLs, are the only cases where a URL
  // being same origin with an HTTPS origin does not imply the URL itself is
  // also HTTPS.
  const KURL kFileSystemUrl =
      KURL(String::FromUTF8("filesystem:https://origin.test/foo"));
  EXPECT_TRUE(
      kOrigin->IsSameOriginWith(SecurityOrigin::Create(kFileSystemUrl).get()));

  const KURL kRejectedUrls[] = {
      // HTTP URLs is rejected: it's both the wrong scheme, and cross-origin.
      KURL(String::FromUTF8("filesystem:http://origin.test/foo")),
      // Cross origin HTTPS URLs are rejected.
      KURL(String::FromUTF8("https://origin2.test/foo")),
      // URL with different ports are cross-origin.
      KURL(String::FromUTF8("https://origin.test:1234/")),
      // URLs with opaque origins are cross-origin.
      KURL(String::FromUTF8("data://text/html,payload")),
      // Unknown scheme.
      KURL(String::FromUTF8("unknown-scheme://foo/")),

      // filesystem URLs are rejected, even if they're same-origin with the page
      // origin.
      kFileSystemUrl,

      // URLs with user/ports are rejected.
      KURL(String::FromUTF8("https://user:pass@origin.test/")),
      // References also aren't allowed, as they aren't sent over HTTP.
      KURL(String::FromUTF8("https://origin.test/#foopy")),
      // Even empty ones.
      KURL(String::FromUTF8("https://origin.test/#")),

      // Invalid URLs.
      KURL(String::FromUTF8("")),
      KURL(String::FromUTF8("invalid url")),
      KURL(String::FromUTF8("https://!@#$%^&*()/")),
      KURL(String::FromUTF8("https://[1::::::2]/")),
      KURL(String::FromUTF8("https://origin%00.test")),
  };

  for (const KURL& rejected_url : kRejectedUrls) {
    SCOPED_TRACE(rejected_url.GetString());

    // Test `bidding_url`.
    mojom::blink::InterestGroupPtr blink_interest_group =
        CreateMinimalInterestGroup();
    blink_interest_group->bidding_url = rejected_url;
    ExpectInterestGroupIsNotValid(
        blink_interest_group,
        /*expected_error_field_name=*/String::FromUTF8("biddingLogicURL"),
        /*expected_error_field_value=*/rejected_url.GetString(),
        /*expected_error=*/String::FromUTF8(kBadBiddingUrlError));

    // Test `bidding_wasm_helper_url`
    blink_interest_group = CreateMinimalInterestGroup();
    blink_interest_group->bidding_wasm_helper_url = rejected_url;
    ExpectInterestGroupIsNotValid(
        blink_interest_group,
        /*expected_error_field_name=*/String::FromUTF8("biddingWasmHelperURL"),
        /*expected_error_field_value=*/rejected_url.GetString(),
        /*expected_error=*/String::FromUTF8(kBadBiddingWasmHelperUrlError));

    // Test `update_url`.
    blink_interest_group = CreateMinimalInterestGroup();
    blink_interest_group->update_url = rejected_url;
    ExpectInterestGroupIsNotValid(
        blink_interest_group,
        /*expected_error_field_name=*/String::FromUTF8("updateURL"),
        /*expected_error_field_value=*/rejected_url.GetString(),
        /*expected_error=*/String::FromUTF8(kBadUpdateUrlError));
  }
}

// The trusted bidding signals URL has slightly different logic, so test it
// separately. In particular, cross origin URLs are allowed, while query strings
// are not.
TEST_F(ValidateBlinkInterestGroupTest, TrustedBiddingSignalsUrl) {
  // Note that cross-origin checks here refer to the group's owner,
  // https://origin.test
  const struct {
    KURL url;
    bool ok = false;
  } kTests[] = {
      // HTTP URLs is rejected: it's wrong scheme.
      {KURL(String::FromUTF8("http://origin.test/foo"))},
      // Cross origin HTTPS URLs are OK with flag on.
      {KURL(String::FromUTF8("https://origin2.test/foo")), /*ok=*/true},
      // URL with different ports are cross-origin.
      {KURL(String::FromUTF8("https://origin.test:1234/")), /*ok=*/true},
      // URLs with opaque origins are cross-origin, but not OK since they're
      // not https.
      {KURL(String::FromUTF8("data://text/html,payload"))},
      // Unknown scheme.
      {KURL(String::FromUTF8("unknown-scheme://foo/"))},

      // filesystem URLs are rejected, even if they're same-origin with the page
      // origin.
      {KURL(String::FromUTF8("filesystem:https://origin.test/foo"))},

      // URLs with user/ports are rejected.
      {KURL(String::FromUTF8("https://user:pass@origin.test/"))},
      // References also aren't allowed, as they aren't sent over HTTP.
      {KURL(String::FromUTF8("https://origin.test/#foopy"))},
      // Even empty ones.
      {KURL(String::FromUTF8("https://origin.test/#"))},

      // Invalid URLs.
      {KURL(String::FromUTF8(""))},
      {KURL(String::FromUTF8("invalid url"))},
      {KURL(String::FromUTF8("https://!@#$%^&*()/"))},
      {KURL(String::FromUTF8("https://[1::::::2]/"))},
      {KURL(String::FromUTF8("https://origin%00.test"))},

      // `trusted_bidding_signals_url` also can't include query strings.
      {KURL(String::FromUTF8("https://origin.test/?query"))},

      // That includes an empty query string.
      {KURL(String::FromUTF8("https://origin.test/?"))}};

  for (const auto& test : kTests) {
    const KURL& test_url = test.url;
    SCOPED_TRACE(test_url.GetString());
    mojom::blink::InterestGroupPtr blink_interest_group =
        CreateMinimalInterestGroup();
    blink_interest_group->trusted_bidding_signals_url = test_url;
    if (test.ok) {
      ExpectInterestGroupIsValid(blink_interest_group);
    } else {
      ExpectInterestGroupIsNotValid(
          blink_interest_group,
          /*expected_error_field_name=*/
          String::FromUTF8("trustedBiddingSignalsURL"),
          /*expected_error_field_value=*/test_url.GetString(),
          /*expected_error=*/
          String::FromUTF8(
              "trustedBiddingSignalsURL must have https schema and have no "
              "query string, fragment identifier or embedded credentials."));
    }
  }
}

// Tests valid and invalid ad render URLs.
TEST_F(ValidateBlinkInterestGroupTest, AdRenderUrlValidation) {
  const char kBadAdUrlError[] =
      "renderURLs must be HTTPS and have no embedded credentials.";

  const struct {
    bool expect_allowed;
    const char* url;
  } kTestCases[] = {
      // Same origin URLs are allowed.
      {true, "https://origin.test/foo?bar"},

      // Cross origin URLs are allowed, as long as they're HTTPS.
      {true, "https://b.test/"},
      {true, "https://a.test:1234/"},

      // URLs with %00 escaped path are allowed.
      {true, "https://origin.test/%00"},

      // URLs with the wrong scheme are rejected.
      {false, "http://a.test/"},
      {false, "data://text/html,payload"},
      {false, "filesystem:https://a.test/foo"},
      {false, "blob:https://a.test:/2987fb0b-034b-4c79-85ae-cc6d3ef9c56e"},
      {false, "about:blank"},
      {false, "about:srcdoc"},
      {false, "about:newtab"},
      {false, "chrome:hang"},

      // URLs with user/ports are rejected.
      {false, "https://user:pass@a.test/"},

      // References are allowed for ads, though not other requests, since they
      // only have an effect when loading a page in a renderer.
      {true, "https://a.test/#foopy"},
  };

  for (const auto& test_case : kTestCases) {
    SCOPED_TRACE(test_case.url);

    KURL test_case_url = KURL(String::FromUTF8(test_case.url));

    // Add an InterestGroup with the test cases's URL as the only ad's URL.
    mojom::blink::InterestGroupPtr blink_interest_group =
        CreateMinimalInterestGroup();
    blink_interest_group->ads.emplace();
    blink_interest_group->ads->emplace_back(MakeAdWithUrl(test_case_url));
    if (test_case.expect_allowed) {
      ExpectInterestGroupIsValid(blink_interest_group);
    } else {
      ExpectInterestGroupIsNotValid(
          blink_interest_group,
          /*expected_error_field_name=*/String::FromUTF8("ads[0].renderURL"),
          /*expected_error_field_value=*/test_case_url.GetString(),
          /*expected_error=*/String::FromUTF8(kBadAdUrlError));
    }

    // Add an InterestGroup with the test cases's URL as the second ad's URL.
    blink_interest_group = CreateMinimalInterestGroup();
    blink_interest_group->ads.emplace();
    blink_interest_group->ads->emplace_back(
        MakeAdWithUrl(KURL(String::FromUTF8("https://origin.test/"))));
    blink_interest_group->ads->emplace_back(MakeAdWithUrl(test_case_url));
    if (test_case.expect_allowed) {
      ExpectInterestGroupIsValid(blink_interest_group);
    } else {
      ExpectInterestGroupIsNotValid(
          blink_interest_group,
          /*expected_error_field_name=*/String::FromUTF8("ads[1].renderURL"),
          /*expected_error_field_value=*/test_case_url.GetString(),
          /*expected_error=*/String::FromUTF8(kBadAdUrlError));
    }
  }
}

// Tests valid and invalid ad render URLs.
TEST_F(ValidateBlinkInterestGroupTest, AdComponentRenderUrlValidation) {
  const char kBadAdUrlError[] =
      "renderURLs must be HTTPS and have no embedded credentials.";

  const struct {
    bool expect_allowed;
    const char* url;
  } kTestCases[] = {
      // Same origin URLs are allowed.
      {true, "https://origin.test/foo?bar"},

      // Cross origin URLs are allowed, as long as they're HTTPS.
      {true, "https://b.test/"},
      {true, "https://a.test:1234/"},

      // URLs with %00 escaped path are allowed.
      {true, "https://origin.test/%00"},

      // URLs with the wrong scheme are rejected.
      {false, "http://a.test/"},
      {false, "data://text/html,payload"},
      {false, "filesystem:https://a.test/foo"},
      {false, "blob:https://a.test:/2987fb0b-034b-4c79-85ae-cc6d3ef9c56e"},
      {false, "about:blank"},
      {false, "about:srcdoc"},
      {false, "about:newtab"},
      {false, "chrome:hang"},

      // URLs with user/ports are rejected.
      {false, "https://user:pass@a.test/"},

      // References are allowed for ads, though not other requests, since they
      // only have an effect when loading a page in a renderer.
      {true, "https://a.test/#foopy"},
  };

  for (const auto& test_case : kTestCases) {
    SCOPED_TRACE(test_case.url);

    KURL test_case_url = KURL(String::FromUTF8(test_case.url));

    // Add an InterestGroup with the test cases's URL as the only ad
    // component's URL.
    mojom::blink::InterestGroupPtr blink_interest_group =
        CreateMinimalInterestGroup();
    blink_interest_group->ad_components.emplace();
    blink_interest_group->ad_components->emplace_back(
        MakeAdWithUrl(test_case_url));
    if (test_case.expect_allowed) {
      ExpectInterestGroupIsValid(blink_interest_group);
    } else {
      ExpectInterestGroupIsNotValid(
          blink_interest_group,
          /*expected_error_field_name=*/
          String::FromUTF8("adComponents[0].renderURL"),
          /*expected_error_field_value=*/test_case_url.GetString(),
          /*expected_error=*/String::FromUTF8(kBadAdUrlError));
    }

    // Add an InterestGroup with the test cases's URL as the second ad
    // component's URL.
    blink_interest_group = CreateMinimalInterestGroup();
    blink_interest_group->ad_components.emplace();
    blink_interest_group->ad_components->emplace_back(
        MakeAdWithUrl(KURL(String::FromUTF8("https://origin.test/"))));
    blink_interest_group->ad_components->emplace_back(
        MakeAdWithUrl(test_case_url));
    if (test_case.expect_allowed) {
      ExpectInterestGroupIsValid(blink_interest_group);
    } else {
      ExpectInterestGroupIsNotValid(
          blink_interest_group,
          /*expected_error_field_name=*/
          String::FromUTF8("adComponents[1].renderURL"),
          /*expected_error_field_value=*/test_case_url.GetString(),
          /*expected_error=*/String::FromUTF8(kBadAdUrlError));
    }
  }
}

// Mojo rejects malformed URLs when converting mojom::blink::InterestGroup to
// blink::InterestGroup. Since the rejection happens internally in Mojo,
// typemapping code that invokes blink::InterestGroup::IsValid() isn't run, so
// adding a AdRenderUrlValidation testcase to verify malformed URLs wouldn't
// exercise blink::InterestGroup::IsValid(). Since blink::InterestGroup users
// can call IsValid() directly (i.e when not using Mojo), we need a test that
// also calls IsValid() directly.
TEST_F(ValidateBlinkInterestGroupTest, MalformedUrl) {
  constexpr char kMalformedUrl[] = "https://invalid^";

  // First, check against mojom::blink::InterestGroup.
  constexpr char kBadAdUrlError[] =
      "renderURLs must be HTTPS and have no embedded credentials.";
  mojom::blink::InterestGroupPtr blink_interest_group =
      mojom::blink::InterestGroup::New();
  blink_interest_group->owner = kOrigin;
  blink_interest_group->name = kName;
  blink_interest_group->ads.emplace();
  blink_interest_group->ads->emplace_back(MakeAdWithUrl(KURL(kMalformedUrl)));
  String error_field_name;
  String error_field_value;
  String error;
  EXPECT_FALSE(ValidateBlinkInterestGroup(
      *blink_interest_group, error_field_name, error_field_value, error));
  EXPECT_EQ(error_field_name, String::FromUTF8("ads[0].renderURL"));
  // The invalid ^ gets escaped.
  EXPECT_EQ(error_field_value, String::FromUTF8("https://invalid%5E/"));
  EXPECT_EQ(error, String::FromUTF8(kBadAdUrlError));

  // Now, test against blink::InterestGroup.
  blink::InterestGroup interest_group;
  interest_group.owner = url::Origin::Create(GURL(kOriginString));
  interest_group.name = kNameString;
  interest_group.ads.emplace();
  interest_group.ads->emplace_back(
      blink::InterestGroup::Ad(GURL(kMalformedUrl), /*metadata=*/""));
  EXPECT_FALSE(interest_group.IsValid());
}

TEST_F(ValidateBlinkInterestGroupTest, TooLarge) {
  mojom::blink::InterestGroupPtr blink_interest_group =
      CreateMinimalInterestGroup();

  // Name length that will result in a `blink_interest_group` having an
  // estimated size of exactly `kMaxInterestGroupSize`, which is 1048576 bytes.
  // Note that kMaxInterestGroupSize is actually one greater than the maximum
  // size, so no need to add 1 to exceed it.
  blink_interest_group->name = "";
  const size_t kTooLongNameLength =
      mojom::blink::kMaxInterestGroupSize -
      EstimateBlinkInterestGroupSize(*blink_interest_group);

  std::string long_string(kTooLongNameLength, 'n');
  blink_interest_group->name = String(long_string);
  ExpectInterestGroupIsNotValid(
      blink_interest_group,
      /*expected_error_field_name=*/String::FromUTF8("size"),
      /*expected_error_field_value=*/String::FromUTF8("1048576"),
      /*expected_error=*/
      String::FromUTF8("interest groups must be less than 1048576 bytes"));

  // Almost too long should still work.
  long_string = std::string(kTooLongNameLength - 1, 'n');
  blink_interest_group->name = String(long_string);
  ExpectInterestGroupIsValid(blink_interest_group);
}

TEST_F(ValidateBlinkInterestGroupTest, TooLargePriorityVector) {
  mojom::blink::InterestGroupPtr blink_interest_group =
      CreateMinimalInterestGroup();
  blink_interest_group->name = "";

  size_t initial_estimate =
      EstimateBlinkInterestGroupSize(*blink_interest_group);
  blink_interest_group->priority_vector.emplace();
  // Set 510 entries with 92-byte keys.  Adding in the 8 byte double values,
  // this should be estimated to be 51000 bytes.
  for (int i = 0; i < 510; ++i) {
    // Use a unique 92-byte value for each key.
    String key = String::FromUTF8(base::StringPrintf("%92i", i));
    blink_interest_group->priority_vector->Set(key, i);
  }
  size_t current_estimate =
      EstimateBlinkInterestGroupSize(*blink_interest_group);
  EXPECT_EQ(51000 + initial_estimate, current_estimate);

  // Name that should cause the group to exactly exceed the maximum name length.
  // Need to call into ExpectInterestGroupIsNotValid() to make sure name length
  // estimate for mojom::blink::InterestGroupPtr and blink::InterestGroup
  // equivalent values exactly match.
  const size_t kTooLongNameLength =
      mojom::blink::kMaxInterestGroupSize - current_estimate;
  std::string too_long_name(kTooLongNameLength, 'n');
  blink_interest_group->name = String(too_long_name);

  ExpectInterestGroupIsNotValid(
      blink_interest_group,
      /*expected_error_field_name=*/String::FromUTF8("size"),
      /*expected_error_field_value=*/String::FromUTF8("1048576"),
      /*expected_error=*/
      String::FromUTF8("interest groups must be less than 1048576 bytes"));

  // Almost too long should still work.
  too_long_name = std::string(kTooLongNameLength - 1, 'n');
  blink_interest_group->name = String(too_long_name);
  ExpectInterestGroupIsValid(blink_interest_group);
}

TEST_F(ValidateBlinkInterestGroupTest, TooLargePrioritySignalsOverride) {
  mojom::blink::InterestGroupPtr blink_interest_group =
      CreateMinimalInterestGroup();
  blink_interest_group->name = "";

  size_t initial_estimate =
      EstimateBlinkInterestGroupSize(*blink_interest_group);
  blink_interest_group->priority_signals_overrides.emplace();
  // Set 510 entries with 92-byte keys.  Adding in the 8 byte double values,
  // this should be estimated to be 51000 bytes.
  for (int i = 0; i < 510; ++i) {
    // Use a unique 92-byte value for each key.
    String key = String::FromUTF8(base::StringPrintf("%92i", i));
    blink_interest_group->priority_signals_overrides->Set(key, i);
  }
  size_t current_estimate =
      EstimateBlinkInterestGroupSize(*blink_interest_group);
  EXPECT_EQ(51000 + initial_estimate, current_estimate);

  // Name that should cause the group to exactly exceed the maximum name length.
  // Need to call into ExpectInterestGroupIsNotValid() to make sure name length
  // estimate for mojom::blink::InterestGroupPtr and blink::InterestGroup
  // equivalent values exactly match.
  const size_t kTooLongNameLength =
      mojom::blink::kMaxInterestGroupSize - current_estimate;
  std::string too_long_name(kTooLongNameLength, 'n');
  blink_interest_group->name = String(too_long_name);

  ExpectInterestGroupIsNotValid(
      blink_interest_group,
      /*expected_error_field_name=*/String::FromUTF8("size"),
      /*expected_error_field_value=*/String::FromUTF8("1048576"),
      /*expected_error=*/
      String::FromUTF8("interest groups must be less than 1048576 bytes"));

  // Almost too long should still work.
  too_long_name = std::string(kTooLongNameLength - 1, 'n');
  blink_interest_group->name = String(too_long_name);
  ExpectInterestGroupIsValid(blink_interest_group);
}

TEST_F(ValidateBlinkInterestGroupTest, TooLargeSellerCapabilities) {
  mojom::blink::InterestGroupPtr blink_interest_group =
      CreateMinimalInterestGroup();
  blink_interest_group->name = "";

  size_t initial_estimate =
      EstimateBlinkInterestGroupSize(*blink_interest_group);
  blink_interest_group->seller_capabilities.emplace();
  // Set 510 entries with 100-byte origin values. This should be estimated to be
  // 51000 bytes.
  for (int i = 0; i < 510; ++i) {
    // Use a unique 100-byt
"""


```