Response: The user wants a summary of the functionality of the provided C++ code snippet. The code is a unit test file for the `PermissionsPolicy` class in the Chromium Blink engine.

Here's a breakdown of the functionalities to look for:

1. **Core Functionality:** The file tests the behavior of the `PermissionsPolicy` class.
2. **Relationship to Web Technologies:**  The `PermissionsPolicy` class deals with controlling access to features based on the origin of a frame, which directly relates to JavaScript, HTML (iframe `allow` attribute), and potentially CSS (though less directly).
3. **Logic and Assumptions:**  Unit tests involve setting up scenarios (inputs) and asserting expected outcomes (outputs).
4. **Common Errors:** Unit tests often implicitly or explicitly highlight potential misuses or errors in the system being tested.

Based on the code, the key areas of functionality being tested are:

* **Policy Inheritance:** How permissions policies are inherited from parent frames to child frames.
* **Origin-Based Permissions:** How permissions are granted or denied based on the origin of the frame.
* **`Permissions-Policy` Header:** How the `Permissions-Policy` HTTP header affects feature availability.
* **`iframe allow` Attribute:** How the `allow` attribute on iframes influences the permissions policy of the iframe.
* **Default Feature Behaviors:** How features with different default settings (on, off, self) are handled.
* **Feature Delegation:** How permissions can be explicitly delegated to subframes.

I will now process the provided code snippet and extract these functionalities, providing examples and highlighting potential issues.
这是对 Chromium Blink 引擎中 `blink/common/permissions_policy/permissions_policy_unittest.cc` 文件**第一部分**的功能归纳：

**功能总览：**

这个文件是 `PermissionsPolicy` 类的单元测试，用于验证权限策略在不同场景下的行为和逻辑。它主要测试了以下核心功能：

1. **权限策略的创建和初始化：** 测试了在不同情况下如何创建 `PermissionsPolicy` 对象，例如从父策略继承、从解析后的策略创建等。
2. **权限策略的继承：**  详细测试了权限策略在父子 frame 之间的继承关系，包括同源和跨域的情况。
3. **通过 HTTP 头部设置权限策略：** 验证了如何通过 `Permissions-Policy` HTTP 头部来控制特定功能的启用和禁用。
4. **通过 `iframe allow` 属性委派权限：**  测试了 `iframe` 标签的 `allow` 属性如何将权限委派给子 frame。
5. **不同默认行为的权限特性：**  测试了具有不同默认行为（例如默认启用、默认仅自身启用、默认禁用）的权限特性在不同场景下的表现。
6. **判断特定来源是否启用特性：**  测试了 `IsFeatureEnabledForOrigin` 方法，用于判断特定来源是否启用了某个权限特性。
7. **子资源请求的权限判断：** 测试了 `IsFeatureEnabledForSubresourceRequestAssumingOptIn` 方法，用于判断子资源请求是否允许使用某个特性。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`PermissionsPolicy` 直接影响 Web 开发中 JavaScript API 的可用性，并通过 HTML 的 `iframe allow` 属性进行配置。 虽然 CSS 本身不受权限策略直接控制，但某些可能影响 CSS 行为的底层 Web 功能可能会受到权限策略的限制。

**JavaScript 举例：**

假设有一个权限特性 `camera`，默认是禁用的。

* **场景：** 网站 `https://example.com` 的权限策略中允许了 `camera` 特性。页面上的 JavaScript 代码可以成功调用 `navigator.mediaDevices.getUserMedia({ video: true })` 来访问摄像头。
* **场景：** 如果该网站的权限策略中没有允许 `camera` 特性，那么 JavaScript 调用 `navigator.mediaDevices.getUserMedia({ video: true })` 将会失败，通常会抛出一个 `SecurityError` 异常。

**HTML 举例：**

假设有一个权限特性 `microphone`，默认是仅自身启用的。

* **场景：** 网站 `https://example.com` 有以下 HTML 结构：
  ```html
  <iframe src="https://another-example.com" allow="microphone"></iframe>
  ```
  `another-example.com` 这个 iframe 内部的 JavaScript 代码可以成功调用 `navigator.mediaDevices.getUserMedia({ audio: true })` 来访问麦克风，因为父页面通过 `allow="microphone"` 将权限委派给了它。
* **场景：** 如果父页面的 iframe 标签没有 `allow="microphone"` 属性，那么 `another-example.com` 的 JavaScript 代码访问麦克风将会失败。

**CSS 关系（间接）：**

一些可能影响 CSS 行为的底层功能，例如加载字体，也可能受到权限策略的影响。虽然 CSS 本身没有直接的权限策略语法，但权限策略可以阻止某些资源加载，从而间接影响页面的渲染。

**逻辑推理的假设输入与输出：**

**假设输入：**

* **父 Frame (Origin A):**  没有设置任何权限策略。
* **子 Frame (Origin B):** 设置了 `Permissions-Policy: microphone=self`。

**输出：**

* 在父 Frame 中，`microphone` 特性默认是启用的（因为是 top-level frame，并且默认是 self）。
* 在子 Frame 中，`microphone` 特性是启用的，因为它通过 HTTP 头部声明了允许自身。

**假设输入：**

* **父 Frame (Origin A):** 设置了 `Permissions-Policy: geolocation=()` (禁用地理位置)。
* **子 Frame (Origin A):** 没有设置任何权限策略。

**输出：**

* 在父 Frame 中，`geolocation` 特性被禁用。
* 在子 Frame 中，`geolocation` 特性也被禁用，因为权限策略会向下继承，即使子 Frame 与父 Frame 同源。

**涉及用户或者编程常见的使用错误及举例说明：**

1. **在子 Frame 中尝试启用父 Frame 禁止的特性：** 用户可能会在子 Frame 的 HTTP 头部或 `iframe allow` 属性中尝试启用父 Frame 已经明确禁止的特性，但这不会生效。父 Frame 的策略拥有更高的优先级。

   **例子：**
   * 父 Frame (Origin A) 设置了 `Permissions-Policy: camera=()`。
   * 子 Frame (Origin B) 尝试设置 `Permissions-Policy: camera=*`。
   * 结果：子 Frame 及其后代 Frame 仍然无法使用摄像头。

2. **忘记在父 Frame 中使用 `iframe allow` 委派权限：**  开发者可能希望跨域的子 Frame 能够使用某个特性，但在父 Frame 的 `iframe` 标签中忘记添加对应的 `allow` 属性。

   **例子：**
   * 父 Frame (Origin A) 没有设置任何权限策略。
   * 子 Frame (Origin B) 设置了 `Permissions-Policy: microphone=self`。
   * 父 Frame 的 HTML 中有 `<iframe src="https://origin-b.com"></iframe>`，但没有 `allow="microphone"`。
   * 结果：子 Frame 无法使用麦克风，即使它自身声明了允许。

3. **对默认关闭的特性不加任何声明就期望启用：**  开发者可能假设某个默认关闭的特性在所有情况下都是可用的，而没有在 HTTP 头部或 `iframe allow` 属性中显式启用它。

   **例子：** 假设 `default-off-feature` 是一个默认关闭的特性。
   * 网站没有设置任何权限策略。
   * JavaScript 代码尝试使用 `default-off-feature` 相关的 API。
   * 结果：该特性不可用，因为默认是关闭的，并且没有被显式启用。

**本部分功能归纳：**

总而言之，这份代码的**第一部分**主要集中在验证 `PermissionsPolicy` 类在基本的权限继承、HTTP 头部策略应用以及 `iframe allow` 属性委派权限等核心机制上的正确性。它通过各种不同的父子 Frame 结构和策略配置，测试了权限特性在不同来源的 Frame 中是否按照预期启用或禁用。 核心目标是确保权限策略能够有效地控制 Web 功能的访问，并防止未经授权的跨域访问。

Prompt: 
```
这是目录为blink/common/permissions_policy/permissions_policy_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/permissions_policy/permissions_policy.h"

#include <optional>
#include <unordered_set>

#include "base/containers/contains.h"
#include "base/strings/stringprintf.h"
#include "base/test/gtest_util.h"
#include "base/test/scoped_feature_list.h"
#include "services/network/public/cpp/resource_request.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/common/permissions_policy/permissions_policy_features_internal.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/frame/fenced_frame_permissions_policies.h"
#include "third_party/blink/public/common/permissions_policy/permissions_policy_features.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy_feature.mojom-shared.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy_feature.mojom.h"
#include "third_party/blink/public/mojom/permissions_policy/policy_value.mojom.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace blink {

namespace {

const mojom::PermissionsPolicyFeature kDefaultOnFeature =
    static_cast<mojom::PermissionsPolicyFeature>(
        static_cast<int>(mojom::PermissionsPolicyFeature::kMaxValue) + 1);

const mojom::PermissionsPolicyFeature kDefaultSelfFeature =
    static_cast<mojom::PermissionsPolicyFeature>(
        static_cast<int>(mojom::PermissionsPolicyFeature::kMaxValue) + 2);

const mojom::PermissionsPolicyFeature kDefaultOffFeature =
    static_cast<mojom::PermissionsPolicyFeature>(
        static_cast<int>(mojom::PermissionsPolicyFeature::kMaxValue) + 3);

// This feature is defined in code, but not present in the feature list.
const mojom::PermissionsPolicyFeature kUnavailableFeature =
    static_cast<mojom::PermissionsPolicyFeature>(
        static_cast<int>(mojom::PermissionsPolicyFeature::kMaxValue) + 4);

}  // namespace

class PermissionsPolicyTest : public testing::Test {
 protected:
  PermissionsPolicyTest()
      : feature_list_(
            {{kDefaultOnFeature, PermissionsPolicyFeatureDefault::EnableForAll},
             {kDefaultSelfFeature,
              PermissionsPolicyFeatureDefault::EnableForSelf},
             {kDefaultOffFeature,
              PermissionsPolicyFeatureDefault::EnableForNone},
             {mojom::PermissionsPolicyFeature::kBrowsingTopics,
              PermissionsPolicyFeatureDefault::EnableForSelf},
             {mojom::PermissionsPolicyFeature::kClientHintDPR,
              PermissionsPolicyFeatureDefault::EnableForSelf},
             {mojom::PermissionsPolicyFeature::kAttributionReporting,
              PermissionsPolicyFeatureDefault::EnableForSelf},
             {mojom::PermissionsPolicyFeature::kSharedStorage,
              PermissionsPolicyFeatureDefault::EnableForSelf},
             {mojom::PermissionsPolicyFeature::kSharedStorageSelectUrl,
              PermissionsPolicyFeatureDefault::EnableForSelf},
             {mojom::PermissionsPolicyFeature::kPrivateAggregation,
              PermissionsPolicyFeatureDefault::EnableForSelf}}) {}

  ~PermissionsPolicyTest() override = default;

  std::unique_ptr<PermissionsPolicy> CreateFromParentPolicy(
      const PermissionsPolicy* parent,
      ParsedPermissionsPolicy header_policy,
      const url::Origin& origin) {
    ParsedPermissionsPolicy empty_container_policy;
    return PermissionsPolicy::CreateFromParentPolicy(
        parent, header_policy, empty_container_policy, origin, feature_list_);
  }

  std::unique_ptr<PermissionsPolicy> CreateFromParsedPolicy(
      const ParsedPermissionsPolicy& parsed_policy,
      const url::Origin& origin) {
    return PermissionsPolicy::CreateFromParsedPolicy(
        parsed_policy, std::nullopt, origin, feature_list_);
  }

  std::unique_ptr<PermissionsPolicy> CreateFromParentWithFramePolicy(
      const PermissionsPolicy* parent,
      ParsedPermissionsPolicy header_policy,
      const ParsedPermissionsPolicy& frame_policy,
      const url::Origin& origin) {
    return PermissionsPolicy::CreateFromParentPolicy(
        parent, header_policy, frame_policy, origin, feature_list_);
  }

  std::unique_ptr<PermissionsPolicy> CreateFlexibleForFencedFrame(
      const PermissionsPolicy* parent,
      ParsedPermissionsPolicy header_policy,
      const url::Origin& origin) {
    ParsedPermissionsPolicy empty_container_policy;
    return PermissionsPolicy::CreateFlexibleForFencedFrame(
        parent, header_policy, empty_container_policy, origin, feature_list_);
  }

  std::unique_ptr<PermissionsPolicy> CreateFixedForFencedFrame(
      const url::Origin& origin,
      ParsedPermissionsPolicy header_policy,
      base::span<const blink::mojom::PermissionsPolicyFeature>
          effective_enabled_permissions) {
    return PermissionsPolicy::CreateFixedForFencedFrame(
        origin, header_policy, feature_list_, effective_enabled_permissions);
  }

  bool IsFeatureEnabledForSubresourceRequestAssumingOptIn(
      PermissionsPolicy* policy,
      mojom::PermissionsPolicyFeature feature,
      const url::Origin& origin) const {
    return policy->IsFeatureEnabledForSubresourceRequestAssumingOptIn(feature,
                                                                      origin);
  }

  bool PolicyContainsInheritedValue(const PermissionsPolicy* policy,
                                    mojom::PermissionsPolicyFeature feature) {
    return base::Contains(policy->inherited_policies_, feature);
  }

  url::Origin origin_a_ = url::Origin::Create(GURL("https://example.com/"));
  url::Origin origin_b_ = url::Origin::Create(GURL("https://example.net/"));
  url::Origin origin_c_ = url::Origin::Create(GURL("https://example.org/"));

 private:
  // Contains the list of controlled features, so that we are guaranteed to
  // have at least one of each kind of default behaviour represented.
  PermissionsPolicyFeatureList feature_list_;
};

TEST_F(PermissionsPolicyTest, TestInitialPolicy) {
  // +-------------+
  // |(1)Origin A  |
  // |No Policy    |
  // +-------------+
  // Default-on and top-level-only features should be enabled in top-level
  // frame.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  EXPECT_TRUE(policy1->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_TRUE(policy1->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy1->IsFeatureEnabled(kDefaultOffFeature));
}

TEST_F(PermissionsPolicyTest, TestCanEnableOffFeatureWithAll) {
  // +-----------------------------------+
  // |(1)Origin A                        |
  // |Permissions-Policy: default-off=*  |
  // +-----------------------------------+
  // Default-off feature be enabled with header policy *.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultOffFeature,
                                /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/true,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  EXPECT_TRUE(policy1->IsFeatureEnabled(kDefaultOffFeature));
}

TEST_F(PermissionsPolicyTest, TestCanEnableOffFeatureWithSelf) {
  // +--------------------------------------+
  // |(1)Origin A                           |
  // |Permissions-Policy: default-off=self  |
  // +--------------------------------------+
  // Default-off feature be enabled with header policy self.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultOffFeature,
                                /*allowed_origins=*/{},
                                /*self_if_matches=*/origin_a_,
                                /*matches_all_origins=*/false,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  EXPECT_TRUE(policy1->IsFeatureEnabled(kDefaultOffFeature));
}

TEST_F(PermissionsPolicyTest, TestInitialSameOriginChildPolicy) {
  // +-----------------+
  // |(1)Origin A      |
  // |No Policy        |
  // | +-------------+ |
  // | |(2)Origin A  | |
  // | |No Policy    | |
  // | +-------------+ |
  // +-----------------+
  // Default-on and Default-self features should be enabled in a same-origin
  // child frame. Default-off feature should be disabled.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_a_);
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultOffFeature));
}

TEST_F(PermissionsPolicyTest, TestInitialCrossOriginChildPolicy) {
  // +-----------------+
  // |(1)Origin A      |
  // |No Policy        |
  // | +-------------+ |
  // | |(2)Origin B  | |
  // | |No Policy    | |
  // | +-------------+ |
  // +-----------------+
  // Default-on features should be enabled in child frame. Default-self and
  // Default-off feature should be disabled.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_b_);
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultOffFeature));
}

TEST_F(PermissionsPolicyTest, TestCrossOriginChildCannotEnableFeature) {
  // +------------------------------------------+
  // |(1) Origin A                              |
  // |No Policy                                 |
  // | +--------------------------------------+ |
  // | |(2) Origin B                          | |
  // | |Permissions-Policy: default-self=self | |
  // | +--------------------------------------+ |
  // +------------------------------------------+
  // Default-self feature should be disabled in cross origin frame, even if no
  // policy was specified in the parent frame.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(),
                             {{{kDefaultSelfFeature,
                                /*allowed_origins=*/{},
                                /*self_if_matches=*/origin_b_,
                                /*matches_all_origins=*/false,
                                /*matches_opaque_src=*/false}}},
                             origin_b_);
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, TestSameOriginChildCannotEnableOffFeature) {
  // +------------------------------------------+
  // |(1) Origin A                              |
  // |No Policy                                 |
  // | +--------------------------------------+ |
  // | |(2) Origin A                          | |
  // | |Permissions-Policy: default-off=*     | |
  // | +--------------------------------------+ |
  // +------------------------------------------+
  // Default-off feature should be disabled in same origin frame, if no
  // policy was specified in the parent frame.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  EXPECT_FALSE(policy1->IsFeatureEnabled(kDefaultOffFeature));

  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(),
                             {{{kDefaultOffFeature,
                                /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/true,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultOffFeature));
}

TEST_F(PermissionsPolicyTest,
       TestSameOriginChildWithParentEnabledCannotEnableOffFeature) {
  // +------------------------------------------+
  // |(1) Origin A                              |
  // |Permissions-Policy: default-off=*         |
  // | +--------------------------------------+ |
  // | |(2) Origin A                          | |
  // | |No Policy                             | |
  // | +--------------------------------------+ |
  // +------------------------------------------+
  // Default-off feature should be disabled in same origin subframe, if no
  // policy was specified in the subframe.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultOffFeature,
                                /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/true,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  ASSERT_TRUE(policy1->IsFeatureEnabled(kDefaultOffFeature));
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_a_);
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultOffFeature));
}

TEST_F(PermissionsPolicyTest,
       TestSameOriginChildWithParentEnabledCannotEnableOffFeatureWithoutAllow) {
  // +------------------------------------------+
  // |(1) Origin A                              |
  // |Permissions-Policy: default-off=*         |
  // | +--------------------------------------+ |
  // | |(2) Origin A                          | |
  // | |Permissions-Policy: default-off=*     | |
  // | +--------------------------------------+ |
  // | +--------------------------------------+ |
  // | |(3) Origin B                          | |
  // | |Permissions-Policy: default-off=*     | |
  // | +--------------------------------------+ |
  // +------------------------------------------+
  // Default-off feature should be disabled in same origin subframe, if no
  // iframe allow is present.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultOffFeature,
                                /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/true,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  ASSERT_TRUE(policy1->IsFeatureEnabled(kDefaultOffFeature));
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(),
                             {{{kDefaultOffFeature,
                                /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/true,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultOffFeature));
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy1.get(),
                             {{{kDefaultOffFeature,
                                /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/true,
                                /*matches_opaque_src=*/false}}},
                             origin_b_);
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultOffFeature));
}

TEST_F(PermissionsPolicyTest,
       TestSameOriginChildWithParentEnabledCanEnableOffFeatureWithAllow) {
  // +-----------------------------------------------+
  // |(1) Origin A                                   |
  // |Permissions-Policy: default-off=self           |
  // | <iframe allow="default-off OriginA OriginB">  |
  // | +--------------------------------------+      |
  // | |(2) Origin A                          |      |
  // | |Permissions-Policy: default-off=self |       |
  // | +--------------------------------------+      |
  // | +--------------------------------------+      |
  // | |(3) Origin B                          |      |
  // | |Permissions-Policy: default-off=self |       |
  // | +--------------------------------------+      |
  // +-----------------------------------------------+
  // Default-off feature should be enabled in same origin subframe, if a
  // self policy was specified in both subframe and main frame and an iframe
  // allow is present for that origin. It should not be enabled in a
  // cross-origin subframe.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultOffFeature,
                                /*allowed_origins=*/{},
                                /*self_if_matches=*/origin_a_,
                                /*matches_all_origins=*/false,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  ASSERT_TRUE(policy1->IsFeatureEnabled(kDefaultOffFeature));
  ParsedPermissionsPolicy frame_policy = {
      {{kDefaultOffFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
            origin_a_,
            /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false},
       {kDefaultOffFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
            origin_b_,
            /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentWithFramePolicy(policy1.get(),
                                      {{{kDefaultOffFeature,
                                         /*allowed_origins=*/{},
                                         /*self_if_matches=*/origin_a_,
                                         /*matches_all_origins=*/false,
                                         /*matches_opaque_src=*/false}}},
                                      frame_policy, origin_a_);
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultOffFeature));
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentWithFramePolicy(policy1.get(),
                                      {{{kDefaultOffFeature,
                                         /*allowed_origins=*/{},
                                         /*self_if_matches=*/origin_b_,
                                         /*matches_all_origins=*/false,
                                         /*matches_opaque_src=*/false}}},
                                      frame_policy, origin_b_);
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultOffFeature));
}

TEST_F(PermissionsPolicyTest,
       TestCrossOriginChildWithParentEnabledCanEnableOffFeatureWithAllow) {
  // +------------------------------------------+
  // |(1) Origin A                              |
  // |Permissions-Policy: default-off=*         |
  // | <iframe allow="default-off OriginB">     |
  // | +--------------------------------------+ |
  // | |(2) Origin B                          | |
  // | |Permissions-Policy: default-off=self  | |
  // | +--------------------------------------+ |
  // +------------------------------------------+
  // Default-off feature should be enabled in cross origin subframe, if a
  // policy was specified in both frames and an iframe allow is present.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultOffFeature,
                                /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/true,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  ASSERT_TRUE(policy1->IsFeatureEnabled(kDefaultOffFeature));
  ParsedPermissionsPolicy frame_policy = {
      {{kDefaultOffFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
            origin_b_,
            /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentWithFramePolicy(policy1.get(),
                                      {{{kDefaultOffFeature,
                                         /*allowed_origins=*/{},
                                         /*self_if_matches=*/origin_b_,
                                         /*matches_all_origins=*/false,
                                         /*matches_opaque_src=*/false}}},
                                      frame_policy, origin_b_);
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultOffFeature));
}

TEST_F(PermissionsPolicyTest, TestFrameSelfInheritance) {
  // +------------------------------------------+
  // |(1) Origin A                              |
  // |Permissions-Policy: default-self=self     |
  // | +-----------------+  +-----------------+ |
  // | |(2) Origin A     |  |(4) Origin B     | |
  // | |No Policy        |  |No Policy        | |
  // | | +-------------+ |  | +-------------+ | |
  // | | |(3)Origin A  | |  | |(5)Origin B  | | |
  // | | |No Policy    | |  | |No Policy    | | |
  // | | +-------------+ |  | +-------------+ | |
  // | +-----------------+  +-----------------+ |
  // +------------------------------------------+
  // Feature should be enabled at the top-level, and through the chain of
  // same-origin frames 2 and 3. It should be disabled in frames 4 and 5, as
  // they are at a different origin.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultSelfFeature,
                                /*allowed_origins=*/{},
                                /*self_if_matches=*/origin_a_,
                                /*matches_all_origins=*/false,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_a_);
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_a_);
  std::unique_ptr<PermissionsPolicy> policy4 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_b_);
  std::unique_ptr<PermissionsPolicy> policy5 =
      CreateFromParentPolicy(policy4.get(), /*header_policy=*/{}, origin_b_);
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_TRUE(policy3->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy4->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy5->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, TestReflexiveFrameSelfInheritance) {
  // +--------------------------------------+
  // |(1) Origin A                          |
  // |Permissions-Policy: default-self=self |
  // | +-----------------+                  |
  // | |(2) Origin B     |                  |
  // | |No Policy        |                  |
  // | | +-------------+ |                  |
  // | | |(3)Origin A  | |                  |
  // | | |No Policy    | |                  |
  // | | +-------------+ |                  |
  // | +-----------------+                  |
  // +--------------------------------------+
  // Feature which is enabled at top-level should be disabled in frame 3, as
  // it is embedded by frame 2, for which the feature is not enabled.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultSelfFeature,
                                /*allowed_origins=*/{},
                                /*self_if_matches=*/origin_a_,
                                /*matches_all_origins=*/false,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_b_);
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_a_);
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, TestReflexiveFrameOriginAInheritance) {
  // +-------------------------------------------+
  // |(1) Origin A                               |
  // |Permissions-Policy: default-self="OriginA" |
  // | +-----------------+                       |
  // | |(2) Origin B     |                       |
  // | |No Policy        |                       |
  // | | +-------------+ |                       |
  // | | |(3)Origin A  | |                       |
  // | | |No Policy    | |                       |
  // | | +-------------+ |                       |
  // | +-----------------+                       |
  // +-------------------------------------------+
  // Feature which is enabled at top-level should be disabled in frame 3, as
  // it is embedded by frame 2, for which the feature is not enabled.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultSelfFeature, /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/false,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_b_);
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_a_);
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, TestSelectiveFrameInheritance) {
  // +------------------------------------------+
  // |(1) Origin A                              |
  // |Permissions-Policy: default-self="OriginB"|
  // | +-----------------+  +-----------------+ |
  // | |(2) Origin B     |  |(3) Origin C     | |
  // | |No Policy        |  |No Policy        | |
  // | |                 |  | +-------------+ | |
  // | |                 |  | |(4)Origin B  | | |
  // | |                 |  | |No Policy    | | |
  // | |                 |  | +-------------+ | |
  // | +-----------------+  +-----------------+ |
  // +------------------------------------------+
  // Feature should be disabled in all frames, even though the
  // header indicates Origin B, there is no container policy to explicitly
  // delegate to that origin, in either frame 2 or 4.
  std::unique_ptr<PermissionsPolicy> policy1 = CreateFromParentPolicy(
      nullptr,
      {{{kDefaultSelfFeature, /*allowed_origins=*/
         {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
             origin_b_,
             /*has_subdomain_wildcard=*/false)},
         /*self_if_matches=*/std::nullopt,
         /*matches_all_origins=*/false,
         /*matches_opaque_src=*/false}}},
      origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_b_);
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_c_);
  std::unique_ptr<PermissionsPolicy> policy4 =
      CreateFromParentPolicy(policy3.get(), /*header_policy=*/{}, origin_b_);
  EXPECT_FALSE(policy1->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy4->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, TestSelectiveFrameInheritance2) {
  // +------------------------------------------+
  // |(1) Origin A                              |
  // |Permissions-Policy: default-self="OriginB"|
  // | <iframe allow="default-self OriginB">    |
  // | +-----------------+  +-----------------+ |
  // | |(2) Origin B     |  |(3) Origin C     | |
  // | |No Policy        |  |No Policy        | |
  // | |                 |  | +-------------+ | |
  // | |                 |  | |(4)Origin B  | | |
  // | |                 |  | |No Policy    | | |
  // | |                 |  | +-------------+ | |
  // | +-----------------+  +-----------------+ |
  // +------------------------------------------+
  // Feature should be enabled in second level Origin B frame, but disabled in
  // Frame 4, because it is embedded by frame 3, where the feature is not
  // enabled.
  std::unique_ptr<PermissionsPolicy> policy1 = CreateFromParentPolicy(
      nullptr,
      {{{kDefaultSelfFeature, /*allowed_origins=*/
         {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
             origin_b_,
             /*has_subdomain_wildcard=*/false)},
         /*self_if_matches=*/std::nullopt,
         /*matches_all_origins=*/false,
         /*matches_opaque_src=*/false}}},
      origin_a_);
  ParsedPermissionsPolicy frame_policy = {
      {{kDefaultSelfFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
            origin_b_,
            /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy, origin_b_);
  std::unique_ptr<PermissionsPolicy> policy3 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy, origin_c_);
  std::unique_ptr<PermissionsPolicy> policy4 =
      CreateFromParentPolicy(policy3.get(), /*header_policy=*/{}, origin_b_);
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy4->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, TestPolicyCanBlockSelf) {
  // +----------------------------------+
  // |(1)Origin A                       |
  // |Permissions-Policy: default-on=() |
  // +----------------------------------+
  // Default-on feature should be disabled in top-level frame.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultOnFeature, /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/false,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  EXPECT_FALSE(policy1->IsFeatureEnabled(kDefaultOnFeature));
}

TEST_F(PermissionsPolicyTest, TestParentPolicyBlocksSameOriginChildPolicy) {
  // +----------------------------------+
  // |(1)Origin A                       |
  // |Permissions-Policy: default-on=() |
  // | +-------------+                  |
  // | |(2)Origin A  |                  |
  // | |No Policy    |                  |
  // | +-------------+                  |
  // +----------------------------------+
  // Feature should be disabled in child frame.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultOnFeature, /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/false,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_a_);
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultOnFeature));
}

TEST_F(PermissionsPolicyTest, TestChildPolicyCanBlockSelf) {
  // +--------------------------------------+
  // |(1)Origin A                           |
  // |No Policy                             |
  // | +----------------------------------+ |
  // | |(2)Origin B                       | |
  // | |Permissions-Policy: default-on=() | |
  // | +----------------------------------+ |
  // +--------------------------------------+
  // Default-on feature should be disabled by cross-origin child frame.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(),
                             {{{kDefaultOnFeature, /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/false,
                                /*matches_opaque_src=*/false}}},
                             origin_b_);
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultOnFeature));
}

TEST_F(PermissionsPolicyTest, TestChildPolicyCanBlockChildren) {
  // +----------------------------------------+
  // |(1)Origin A                             |
  // |No Policy                               |
  // | +------------------------------------+ |
  // | |(2)Origin B                         | |
  // | |Permissions-Policy: default-on=self | |
  // | | +-------------+                    | |
  // | | |(3)Origin C  |                    | |
  // | | |No Policy    |                    | |
  // | | +-------------+                    | |
  // | +------------------------------------+ |
  // +----------------------------------------+
  // Default-on feature should be enabled in frames 1 and 2; disabled in frame
  // 3 by child frame policy.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(),
                             {{{kDefaultOnFeature,
                                /*allowed_origins=*/{},
                                /*self_if_matches=*/origin_b_,
                                /*matches_all_origins=*/false,
                                /*matches_opaque_src=*/false}}},
                             origin_b_);
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_c_);
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultOnFeature));
}

TEST_F(PermissionsPolicyTest, TestParentPolicyBlocksCrossOriginChildPolicy) {
  // +----------------------------------+
  // |(1)Origin A                       |
  // |Permissions-Policy: default-on=() |
  // | +-------------+                  |
  // | |(2)Origin B  |                  |
  // | |No Policy    |                  |
  // | +-------------+                  |
  // +----------------------------------+
  // Default-on feature should be disabled in cross-origin child frame.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultOnFeature, /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/false,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_b_);
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultOnFeature));
}

TEST_F(PermissionsPolicyTest, TestEnableForAllOrigins) {
  // +----------------------------------+
  // |(1) Origin A                      |
  // |Permissions-Policy: default-self=*|
  // | +-----------------+              |
  // | |(2) Origin B     |              |
  // | |No Policy        |              |
  // | | +-------------+ |              |
  // | | |(3)Origin A  | |              |
  // | | |No Policy    | |              |
  // | | +-------------+ |              |
  // | +-----------------+              |
  // +----------------------------------+
  // Feature should be enabled in top level; disabled in frame 2 and 3.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultSelfFeature, /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/true,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_b_);
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_a_);
  EXPECT_TRUE(policy1->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, TestEnableForAllOriginsAndDelegate) {
  // +--------------------------------------+
  // |(1) Origin A                          |
  // |Permissions-Policy: default-self=*    |
  // |<iframe allow="default-self OriginB"> |
  // | +-----------------+                  |
  // | |(2) Origin B     |                  |
  // | |No Policy        |                  |
  // | | +-------------+ |                  |
  // | | |(3)Origin A  | |                  |
  // | | |No Policy    | |                  |
  // | | +-------------+ |                  |
  // | +-----------------+                  |
  // +--------------------------------------+
  // Feature should be enabled in top and second level; disabled in frame 3.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultSelfFeature, /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/true,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  ParsedPermissionsPolicy frame_policy = {
      {{kDefaultSelfFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
            origin_b_,
            /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy, origin_b_);
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_a_);
  EXPECT_TRUE(policy1->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, TestDefaultOnStillNeedsSelf) {
  // +-----------------------------------------+
  // |(1) Origin A                             |
  // |Permissions-Policy: default-on="OriginB" |
  // | +-----------------------------------+   |
  // | |(2) Origin B                       |   |
  // | |No Policy                          |   |
  // | | +-------------+   +-------------+ |   |
  // | | |(3)Origin B  |   |(4)Origin C  | |   |
  // | | |No Policy    |   |No Policy    | |   |
  // | | +-------------+   +-------------+ |   |
  // | +-----------------------------------+   |
  // +-----------------------------------------+
  // Feature should be disabled in all frames.
  std::unique_ptr<PermissionsPolicy> policy1 = CreateFromParentPolicy(
      nullptr,
      {{{kDefaultOnFeature, /*allowed_origins=*/
         {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
             origin_b_,
             /*has_subdomain_wildcard=*/false)},
         /*self_if_matches=*/std::nullopt,
         /*matches_all_origins=*/false,
         /*matches_opaque_src=*/false}}},
      origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_b_);
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_b_);
  std::unique_ptr<PermissionsPolicy> policy4 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_c_);
  EXPECT_FALSE(policy1->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_FALSE(policy4->IsFeatureEnabled(kDefaultOnFeature));
}

TEST_F(PermissionsPolicyTest, TestDefaultOnEnablesForAllDescendants) {
  // +------------------------------------------------+
  // |(1) Origin A                                    |
  // |Permissions-Policy: default-on=(self "OriginB") |
  // | +-----------------------------------+          |
  // | |(2) Origin B                       |          |
  // | |No Policy                          |          |
  // | | +-------------+   +-------------+ |          |
  // | | |(3)Origin B  |   |(4)Origin C  | |          |
  // | | |No Policy    |   |No Policy    | |          |
  // | | +-------------+   +-------------+ |          |
  // | +-----------------------------------+          |
  // +------------------------------------------------+
  // Feature should be enabled in all frames.
  std::unique_ptr<PermissionsPolicy> policy1 = CreateFromParentPolicy(
      nullptr,
      {{{kDefaultOnFeature, /*allowed_origins=*/
         {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
             origin_b_,
             /*has_subdomain_wildcard=*/false)},
         /*self_if_matches=*/origin_a_,
         /*matches_all_origins=*/false,
         /*matches_opaque_src=*/false}}},
      origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_b_);
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_b_);
  std::unique_ptr<PermissionsPolicy> policy4 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_c_);
  EXPECT_TRUE(policy1->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_TRUE(policy3->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_TRUE(policy4->IsFeatureEnabled(kDefaultOnFeature));
}

TEST_F(PermissionsPolicyTest, TestDefaultSelfRequiresDelegation) {
  // +------------------------------------------+
  // |(1) Origin A                              |
  // |Permissions-Policy: default-self="OriginB"|
  // | +-----------------------------------+    |
  // | |(2) Origin B                       |    |
  // | |No Policy                          |    |
  // | | +-------------+   +-------------+ |    |
  // | | |(3)Origin B  |   |(4)Origin C  | |    |
  // | | |No Policy    |   |No Policy    | |    |
  // | | +-------------+   +-------------+ |    |
  // | +-----------------------------------+    |
  // +------------------------------------------+
  // Feature should be disabled in all frames.
  std::unique_ptr<PermissionsPolicy> policy1 = CreateFromParentPolicy(
      nullptr,
      {{{kDefaultSelfFeature, /*allowed_origins=*/
         {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
             origin_b_,
             /*has_subdomain_wildcard=*/false)},
         /*self_if_matches=*/std::nullopt,
         /*matches_all_origins=*/false,
         /*matches_opaque_src=*/false}}},
      origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_b_);
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_b_);
  std::unique_ptr<PermissionsPolicy> policy4 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_c_);
  EXPECT_FALSE(policy1->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy4->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, TestDefaultSelfRespectsSameOriginEmbedding) {
  // +--------------------------------------------------+
  // |(1) Origin A                                      |
  // |Permissions-Policy: default-self=(self "OriginB") |
  // |<iframe allow="default-self">                     |
  // | +-----------------------------------+            |
  // | |(2) Origin B                       |            |
  // | |No Policy                          |            |
  // | | +-------------+   +-------------+ |            |
  // | | |(3)Origin B  |   |(4)Origin C  | |            |
  // | | |No Policy    |   |No Policy    | |            |
  // | | +-------------+   +-------------+ |            |
  // | +-----------------------------------+            |
  // +--------------------------------------------------+
  // Feature should be disabled in frame 4; enabled in frames 1, 2 and 3.
  std::unique_ptr<PermissionsPolicy> policy1 = CreateFromParentPolicy(
      nullptr,
      {{{kDefaultSelfFeature, /*allowed_origins=*/
         {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
             origin_b_,
             /*has_subdomain_wildcard=*/false)},
         /*self_if_matches=*/origin_a_,
         /*matches_all_origins=*/false,
         /*matches_opaque_src=*/false}}},
      origin_a_);
  ParsedPermissionsPolicy frame_policy = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/origin_b_,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy, origin_b_);
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_b_);
  std::unique_ptr<PermissionsPolicy> policy4 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_c_);
  EXPECT_TRUE(policy1->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_TRUE(policy3->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy4->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, TestDelegationRequiredAtAllLevels) {
  // +------------------------------------+
  // |(1) Origin A                        |
  // |<iframe allow="default-self *">     |
  // | +--------------------------------+ |
  // | |(2) Origin B                    | |
  // | |No Policy                       | |
  // | | +-------------+                | |
  // | | |(3)Origin A  |                | |
  // | | |No Policy    |                | |
  // | | +-------------+                | |
  // | +--------------------------------+ |
  // +------------------------------------+
  // Feature should be enabled in frames 1 and 2. Feature is not enabled in
  // frame 3, even though it is the same origin as the top-level, because it is
  // not explicitly delegated.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultSelfFeature, /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/true,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  ParsedPermissionsPolicy frame_policy = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/true,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy, origin_b_);
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_a_);
  EXPECT_TRUE(policy1->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, TestBlockedFrameCannotReenable) {
  // +----------------------------------------+
  // |(1)Origin A                             |
  // |Permissions-Policy: default-self=self   |
  // | +----------------------------------+   |
  // | |(2)Origin B                       |   |
  // | |Permissions-Policy: default-self=*|   |
  // | | +-------------+  +-------------+ |   |
  // | | |(3)Origin A  |  |(4)Origin C  | |   |
  // | | |No Policy    |  |No Policy    | |   |
  // | | +-------------+  +-------------+ |   |
  // | +----------------------------------+   |
  // +----------------------------------------+
  // Feature should be enabled at the top level; disabled in all other frames.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultSelfFeature,
                                /*allowed_origins=*/{},
                                /*self_if_matches=*/origin_a_,
                                /*matches_all_origins=*/false,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(),
                             {{{kDefaultSelfFeature, /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/true,
                                /*matches_opaque_src=*/false}}},
                             origin_b_);
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_a_);
  std::unique_ptr<PermissionsPolicy> policy4 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_c_);
  EXPECT_TRUE(policy1->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy4->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, TestEnabledFrameCanDelegate) {
  // +---------------------------------------------------+
  // |(1) Origin A                                       |
  // |No Policy                                          |
  // |<iframe allow="default-self">                      |
  // | +-----------------------------------------------+ |
  // | |(2) Origin B                                   | |
  // | |No Policy                                      | |
  // | |<iframe allow="default-self">                  | |
  // | | +-------------+                               | |
  // | | |(3)Origin C  |                               | |
  // | | |No Policy    |                               | |
  // | | +-------------+                               | |
  // | +-----------------------------------------------+ |
  // +---------------------------------------------------+
  // Feature should be enabled in all frames.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  ParsedPermissionsPolicy frame_policy = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/origin_b_,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy, origin_b_);
  ParsedPermissionsPolicy frame_policy2 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/origin_c_,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy3 = CreateFromParentWithFramePolicy(
      policy2.get(), /*header_policy=*/{}, frame_policy2, origin_c_);
  EXPECT_TRUE(policy1->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_TRUE(policy3->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, TestEnabledFrameCanDelegateByDefault) {
  // +-----------------------------------------------+
  // |(1) Origin A                                   |
  // |Permissions-Policy: default-on=(self "OriginB")|
  // | +--------------------+ +--------------------+ |
  // | |(2) Origin B        | | (4) Origin C       | |
  // | |No Policy           | | No Policy          | |
  // | | +-------------+    | |                    | |
  // | | |(3)Origin C  |    | |                    | |
  // | | |No Policy    |    | |                    | |
  // | | +-------------+    | |                    | |
  // | +--------------------+ +--------------------+ |
  // +-----------------------------------------------+
  // Feature should be enabled in frames 1, 2, and 3, and disabled in frame 4.
  std::unique_ptr<PermissionsPolicy> policy1 = CreateFromParentPolicy(
      nullptr,
      {{
          {kDefaultOnFeature, /*allowed_origins=*/
           {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
               origin_b_,
               /*has_subdomain_wildcard=*/false)},
           /*self_if_matches=*/origin_a_,
           /*matches_all_origins=*/false,
           /*matches_opaque_src=*/false},
      }},
      origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_b_);
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_c_);
  std::unique_ptr<PermissionsPolicy> policy4 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_c_);
  EXPECT_TRUE(policy1->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_TRUE(policy3->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_FALSE(policy4->IsFeatureEnabled(kDefaultOnFeature));
}

TEST_F(PermissionsPolicyTest, TestFeaturesDontDelegateByDefault) {
  // +-------------------------------------------------+
  // |(1) Origin A                                     |
  // |Permissions-Policy: default-self=(self "OriginB")|
  // | +--------------------+ +--------------------+   |
  // | |(2) Origin B        | | (4) Origin C       |   |
  // | |No Policy           | | No Policy          |   |
  // | | +-------------+    | |                    |   |
  // | | |(3)Origin C  |    | |                    |   |
  // | | |No Policy    |    | |                    |   |
  // | | +-------------+    | |                    |   |
  // | +--------------------+ +--------------------+   |
  // +-------------------------------------------------+
  // Feature should be enabled in frames 1 only. Without a container policy, the
  // feature is not delegated to any child frames.
  std::unique_ptr<PermissionsPolicy> policy1 = CreateFromParentPolicy(
      nullptr,
      {{{kDefaultSelfFeature, /*allowed_origins=*/
         {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
             origin_b_,
             /*has_subdomain_wildcard=*/false)},
         /*self_if_matches=*/origin_a_,
         /*matches_all_origins=*/false,
         /*matches_opaque_src=*/false}}},
      origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_b_);
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_c_);
  std::unique_ptr<PermissionsPolicy> policy4 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_c_);
  EXPECT_TRUE(policy1->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy4->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, TestFeaturesAreIndependent) {
  // +-----------------------------------------------+
  // |(1) Origin A                                   |
  // |No Policy                                      |
  // |<iframe allow="default-self 'self' OriginB;    |
  // |               default-on 'self'>              |
  // | +-------------------------------------------+ |
  // | |(2) Origin B                               | |
  // | |No Policy                                  | |
  // | |<iframe allow="default-self 'self' OriginC;| |
  // | |               default-on 'self'>          | |
  // | | +-------------+                           | |
  // | | |(3)Origin C  |                           | |
  // | | |No Policy    |                           | |
  // | | +-------------+                           | |
  // | +-------------------------------------------+ |
  // +-----------------------------------------------+
  // Default-self feature should be enabled in all frames; Default-on feature
  // should be enabled in frame 1, and disabled in frames 2 and 3.
  std::unique_ptr<PermissionsPolicy> policy1 = CreateFromParentPolicy(
      nullptr,
      {{{kDefaultSelfFeature, /*allowed_origins=*/
         {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
             origin_b_,
             /*has_subdomain_wildcard=*/false)},
         /*self_if_matches=*/origin_a_,
         /*matches_all_origins=*/false,
         /*matches_opaque_src=*/false},
        {kDefaultOnFeature,
         /*allowed_origins=*/{},
         /*self_if_matches=*/origin_a_,
         /*matches_all_origins=*/false,
         /*matches_opaque_src=*/false}}},
      origin_a_);
  ParsedPermissionsPolicy frame_policy = {
      {{kDefaultSelfFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
            origin_b_,
            /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/origin_a_,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false},
       {kDefaultOnFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/origin_a_,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy, origin_b_);
  ParsedPermissionsPolicy frame_policy2 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
            origin_c_,
            /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/origin_a_,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false},
       {kDefaultOnFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/origin_b_,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy3 = CreateFromParentWithFramePolicy(
      policy2.get(), /*header_policy=*/{}, frame_policy2, origin_c_);
  EXPECT_TRUE(policy1->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_TRUE(policy1->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_TRUE(policy3->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultOnFeature));
}

// Test frame policies

TEST_F(PermissionsPolicyTest, TestSimpleFramePolicy) {
  // +--------------------------------------+
  // |(1)Origin A                           |
  // |No Policy                             |
  // |                                      |
  // |<iframe allow="default-self OriginB"> |
  // | +-------------+                      |
  // | |(2)Origin B  |                      |
  // | |No Policy    |                      |
  // | +-------------+                      |
  // +--------------------------------------+
  // Default-self feature should be enabled in cross-origin child frame because
  // permission was delegated through frame policy.
  // This is the same scenario as when the iframe is declared as
  // <iframe allow="default-self">
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  ParsedPermissionsPolicy frame_policy = {
      {{kDefaultSelfFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
            origin_b_,
            /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy, origin_b_);
  EXPECT_TRUE(
      policy1->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_a_));
  EXPECT_TRUE(
      policy2->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_b_));
}

TEST_F(PermissionsPolicyTest, TestAllOriginFramePolicy) {
  // +--------------------------------+
  // |(1)Origin A                     |
  // |No Policy                       |
  // |                                |
  // |<iframe allow="default-self *"> |
  // | +-------------+                |
  // | |(2)Origin B  |                |
  // | |No Policy    |                |
  // | +-------------+                |
  // +--------------------------------+
  // Default-self feature should be enabled in cross-origin child frame because
  // permission was delegated through frame policy.
  // This is the same scenario that arises when the iframe is declared as
  // <iframe allowfullscreen>
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  ParsedPermissionsPolicy frame_policy = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/true,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy, origin_b_);
  EXPECT_TRUE(
      policy1->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_a_));
  EXPECT_TRUE(
      policy2->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_b_));
}

TEST_F(PermissionsPolicyTest, TestFramePolicyCanBeFurtherDelegated) {
  // +------------------------------------------+
  // |(1)Origin A                               |
  // |No Policy                                 |
  // |                                          |
  // |<iframe allow="default-self OriginB">     |
  // | +--------------------------------------+ |
  // | |(2)Origin B                           | |
  // | |No Policy                             | |
  // | |                                      | |
  // | |<iframe allow="default-self OriginC"> | |
  // | | +-------------+                      | |
  // | | |(3)Origin C  |                      | |
  // | | |No Policy    |                      | |
  // | | +-------------+                      | |
  // | |                                      | |
  // | |<iframe> (No frame policy)            | |
  // | | +-------------+                      | |
  // | | |(4)Origin C  |                      | |
  // | | |No Policy    |                      | |
  // | | +-------------+                      | |
  // | +--------------------------------------+ |
  // +------------------------------------------+
  // Default-self feature should be enabled in cross-origin child frames 2 and
  // 3. Feature should be disabled in frame 4 because it was not further
  // delegated through frame policy.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  ParsedPermissionsPolicy frame_policy1 = {{
      {kDefaultSelfFeature, /*allowed_origins=*/
       {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
           origin_b_,
           /*has_subdomain_wildcard=*/false)},
       /*self_if_matches=*/std::nullopt,
       /*matches_all_origins=*/false,
       /*matches_opaque_src=*/false},
  }};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy1, origin_b_);
  ParsedPermissionsPolicy frame_policy2 = {{
      {kD
"""


```