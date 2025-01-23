Response:
My thinking process to analyze the C++ test file and generate the explanation goes like this:

1. **Understand the Goal:** The request asks for the functionality of the `resource_request_test.cc` file, its relation to web technologies (JavaScript, HTML, CSS), logical inferences with examples, and common usage errors.

2. **High-Level Overview:**  I first look at the `#include` directives. They immediately tell me this file is about testing the `ResourceRequest` class. The includes for `gtest`, `features.h`, `permissions_policy`, `web_url_request.h`, `encoded_form_data.h`, `kurl.h`, and `referrer.h` give strong hints about what aspects of `ResourceRequest` are being tested. Specifically, I see network requests, permissions, URLs, and form data.

3. **Focus on `TEST` Macros:** The core of the file is the set of `TEST` macros. Each test function focuses on a specific aspect of the `ResourceRequest` class. I go through each one individually:

    * **`SetHasUserGesture`:**  This is straightforward. It tests setting and getting the `HasUserGesture` flag. I know this flag is important for browser behavior based on user interaction.

    * **`SetIsAdResource`:** Similar to the previous one, this tests setting and getting the `IsAdResource` flag and verifies it persists across redirects. This flag is relevant to ad blocking and tracking prevention.

    * **`UpgradeIfInsecureAcrossRedirects`:** This tests the `UpgradeIfInsecure` flag, related to upgrading HTTP requests to HTTPS. The "across redirects" part is important for maintaining this setting throughout the navigation.

    * **`IsFeatureEnabledForSubresourceRequestAssumingOptIn`:** This is the most complex test. It involves `PermissionsPolicy` and feature flags (`kBrowsingTopics`, `kSharedStorageAPI`). The name suggests it tests how permissions are handled for subresource requests when an explicit opt-in is present. The various nested blocks with different `PermissionsPolicy` configurations are key to understanding the different scenarios being tested.

4. **Identify Core Functionality:** Based on the individual tests, I can summarize the main functionalities being tested:

    * Setting and getting request properties (`HasUserGesture`, `IsAdResource`, `UpgradeIfInsecure`).
    * Ensuring certain properties persist across redirects.
    * Handling feature opt-ins in subresource requests and their interaction with Permissions Policy.

5. **Relate to Web Technologies:** Now, I connect these functionalities to JavaScript, HTML, and CSS:

    * **JavaScript:**  The `fetch` API is the most direct connection. I can explain how JavaScript code using `fetch` might influence these `ResourceRequest` properties (e.g., the `userGesture` option, potential flags set by the browser based on the request context). I can also link the feature opt-ins to potential JavaScript APIs (like the Shared Storage API).

    * **HTML:**  HTML elements that trigger resource requests (like `<img>`, `<script>`, `<link>`, `<iframe>`, and form submissions) are relevant. I can discuss how attributes or the context of these elements might affect the `ResourceRequest`. The Permissions Policy, often set via HTTP headers or the `<iframe>` `allow` attribute, directly ties into the `IsFeatureEnabledForSubresourceRequestAssumingOptIn` test.

    * **CSS:** CSS can trigger resource requests for stylesheets, images, and fonts. The same principles apply as with HTML elements.

6. **Logical Inferences and Examples:** For the more complex tests (especially the Permissions Policy one), I can create simplified scenarios with input (JavaScript `fetch` calls with specific options or HTML with certain attributes) and expected output (whether the feature is enabled or not). This makes the logic clearer.

7. **Common Usage Errors:** I think about common mistakes developers might make related to the tested features:

    * Forgetting to handle user gestures properly.
    * Not understanding how redirects affect request properties.
    * Misconfiguring Permissions Policy and expecting features to work when they are blocked.
    * Incorrectly assuming feature availability without explicit opt-in when required.

8. **Structure and Language:** Finally, I organize the information logically, using clear and concise language. I use bullet points, code examples (even if simplified), and headings to make the explanation easy to read and understand. I avoid overly technical jargon where possible and explain concepts in a way that a developer familiar with web technologies can grasp.

Essentially, I decompose the test file into its individual test cases, understand the purpose of each test, and then connect those purposes back to the broader context of web development and how these low-level C++ details impact the behavior of web pages. The key is to bridge the gap between the implementation details and the developer-facing APIs and concepts.
这个文件 `resource_request_test.cc` 是 Chromium Blink 渲染引擎中的一个 C++ 测试文件，专门用来测试 `ResourceRequest` 类的功能。 `ResourceRequest` 类在 Blink 中代表一个资源请求，例如请求一个网页、图片、CSS 文件或 JavaScript 文件。

**主要功能:**

这个测试文件的主要目的是验证 `ResourceRequest` 类的各种方法和属性的行为是否符合预期。它通过编写一系列的单元测试用例来实现这一点，每个测试用例针对 `ResourceRequest` 的特定功能点。

**与 JavaScript, HTML, CSS 的关系及举例:**

`ResourceRequest` 类在浏览器加载和渲染网页的过程中扮演着核心角色，因此它与 JavaScript, HTML, CSS 的功能有着密切的关系。

* **JavaScript:**
    * **`fetch` API:** 当 JavaScript 代码中使用 `fetch` API 发起网络请求时，底层会创建一个 `ResourceRequest` 对象来描述这个请求。
        * **假设输入:** JavaScript 代码 `fetch('https://example.com/data.json', { method: 'POST', body: JSON.stringify({key: 'value'}), userGesture: true });`
        * **输出 (在 `ResourceRequest` 对象中):**
            * `url`: `https://example.com/data.json`
            * `httpMethod`: `POST`
            * `body`:  包含 `{"key": "value"}` 的 `EncodedFormData` 对象
            * `hasUserGesture`: `true`
    * **`XMLHttpRequest` (XHR):** 类似于 `fetch`，当使用 XHR 发起请求时，也会使用 `ResourceRequest`。
        * **例子:**  JavaScript 代码 `xhr.open('GET', 'image.png'); xhr.send();` 会创建一个 `ResourceRequest`，其 `url` 为 `image.png`， `httpMethod` 为 `GET`。

* **HTML:**
    * **`<link>` 标签 (CSS):** 当浏览器解析到 `<link rel="stylesheet" href="style.css">` 时，会创建一个 `ResourceRequest` 来请求 `style.css` 文件。
        * **输出 (在 `ResourceRequest` 对象中):**
            * `url`: 指向 `style.css` 的完整 URL。
            *  可能包含一些与缓存相关的头部信息。
    * **`<script>` 标签 (JavaScript):**  当遇到 `<script src="script.js"></script>` 时，会创建一个 `ResourceRequest` 来获取 `script.js` 文件。
        * **输出 (在 `ResourceRequest` 对象中):**
            * `url`: 指向 `script.js` 的完整 URL。
            *  可能包含指示是否异步加载的信息。
    * **`<img>` 标签 (Images):** `<img src="image.jpg">` 会导致创建一个 `ResourceRequest` 来加载 `image.jpg`。
        * **输出 (在 `ResourceRequest` 对象中):**
            * `url`: 指向 `image.jpg` 的完整 URL。
    * **`<form>` 提交:**  当 HTML 表单提交时，浏览器会根据表单的 `action` 属性和 `method` 属性创建一个 `ResourceRequest`。
        * **假设输入:** HTML 代码 `<form action="/submit" method="POST"><input name="data" value="info"></form>`，用户点击提交按钮。
        * **输出 (在 `ResourceRequest` 对象中):**
            * `url`:  指向 `/submit` 的完整 URL。
            * `httpMethod`: `POST`
            * `body`:  包含 `data=info` 的 `EncodedFormData` 对象。

* **CSS:**
    * **`url()` 函数 (Images, Fonts等):**  CSS 中使用 `url()` 函数引用资源，例如 `background-image: url('bg.png');` 或 `@font-face { src: url('font.woff2'); }`，都会导致创建 `ResourceRequest` 来加载这些资源。
        * **输出 (在 `ResourceRequest` 对象中):**
            * `url`: 指向 `bg.png` 或 `font.woff2` 的完整 URL。

**逻辑推理与假设输入/输出:**

测试文件中的 `IsFeatureEnabledForSubresourceRequestAssumingOptIn` 测试用例展示了逻辑推理。这个测试检查了在子资源请求中，即使某个特性默认是禁用的，如果请求明确选择启用该特性（通过某些标志位），并且满足 Permissions Policy 的要求，该特性是否会被认为是启用的。

* **假设输入:**
    * Permissions Policy 设置为 `browsing-topics=(self)`，表示只允许同源使用 Browsing Topics API。
    * JavaScript 代码在 `https://example.com` 页面发起 `fetch('https://example.net/data', { browsingTopics: true })`。
* **输出:**  根据测试用例的逻辑，由于 Permissions Policy 不允许跨域使用 Browsing Topics，即使 `fetch` 请求中设置了 `browsingTopics: true`， `IsFeatureEnabledForSubresourceRequestAssumingOptIn` 方法应该返回 `false`。

* **假设输入:**
    * Permissions Policy 设置为 `browsing-topics=*`，表示允许所有来源使用 Browsing Topics API。
    * JavaScript 代码在 `https://example.com` 页面发起 `fetch('https://example.net/data', { browsingTopics: true })`。
* **输出:**  因为 Permissions Policy 允许跨域使用，且 `fetch` 请求中设置了 `browsingTopics: true`，`IsFeatureEnabledForSubresourceRequestAssumingOptIn` 方法应该返回 `true`。

**用户或编程常见的使用错误及举例:**

虽然这个文件是测试代码，但它所测试的功能点与用户或编程中可能出现的错误密切相关：

* **忽略用户手势要求:**  某些浏览器 API 或功能可能要求操作必须由用户手势触发才能执行。如果 JavaScript 代码尝试在没有用户手势的情况下执行此类操作，相关的 `ResourceRequest` 可能会因为 `hasUserGesture` 为 `false` 而被阻止或受到限制。
    * **错误示例:**  在没有用户点击事件的情况下，尝试自动播放视频，这可能会导致请求被阻止。
* **不理解跨域策略 (CORS):**  当 JavaScript 代码尝试从与当前页面不同源的服务器请求资源时，可能会遇到 CORS 错误。这会导致 `ResourceRequest` 被服务器拒绝，除非服务器配置了允许跨域请求的 CORS 头部。
    * **错误示例:**  一个在 `https://example.com` 上运行的网页，尝试使用 `fetch` 请求 `https://api.different-domain.com/data`，但 `api.different-domain.com` 的响应头中缺少必要的 CORS 头部。
* **Permissions Policy 限制:**  开发者可能会尝试使用被 Permissions Policy 禁止的功能。例如，如果一个页面的 Permissions Policy 设置为 `camera 'none'`, 那么即使 JavaScript 代码尝试访问摄像头，相关的 `ResourceRequest` 也不会被允许。
    * **错误示例:**  一个嵌入在 `<iframe>` 中的页面，其父页面设置了限制摄像头访问的 Permissions Policy，该 `<iframe>` 内的 JavaScript 代码尝试使用 `navigator.mediaDevices.getUserMedia()` 访问摄像头将会失败。
* **Referrer Policy 误用:**  `Referrer Policy` 控制着在发起请求时发送的 `Referer` 头信息。如果配置不当，可能会导致隐私泄露或服务器无法正确处理请求。
    * **错误示例:**  将 Referrer Policy 设置为 `unsafe-url` 可能会在跨域请求中泄露完整的 URL，包括路径和查询参数。
* **Service Worker 干预:**  Service Worker 可以拦截网络请求。如果 Service Worker 的逻辑不正确，可能会导致请求失败或返回意外的结果。
    * **错误示例:**  一个 Service Worker 意外地拦截了所有图片请求，并返回了一个默认的占位符图片，导致网页上的图片无法正常显示。

总而言之， `resource_request_test.cc` 文件通过测试 `ResourceRequest` 类的各个方面，间接地验证了 Blink 引擎处理网络请求的正确性，这对于确保网页的功能正常运行至关重要，并直接影响到 JavaScript, HTML, CSS 等前端技术的功能实现。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/resource_request_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"

#include <memory>
#include "base/test/scoped_feature_list.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/permissions_policy/permissions_policy.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy_feature.mojom-blink.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/renderer/platform/network/encoded_form_data.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/referrer.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "url/origin.h"

namespace blink {

namespace {

std::unique_ptr<PermissionsPolicy> CreateFromParentPolicy(
    const PermissionsPolicy* parent,
    ParsedPermissionsPolicy header_policy,
    const url::Origin& origin) {
  ParsedPermissionsPolicy empty_container_policy;
  return PermissionsPolicy::CreateFromParentPolicy(
      parent, header_policy, empty_container_policy, origin);
}

}  // namespace

TEST(ResourceRequestTest, SetHasUserGesture) {
  ResourceRequest original;
  EXPECT_FALSE(original.HasUserGesture());
  original.SetHasUserGesture(true);
  EXPECT_TRUE(original.HasUserGesture());
  original.SetHasUserGesture(false);
  EXPECT_TRUE(original.HasUserGesture());
}

TEST(ResourceRequestTest, SetIsAdResource) {
  ResourceRequest original;
  EXPECT_FALSE(original.IsAdResource());
  original.SetIsAdResource();
  EXPECT_TRUE(original.IsAdResource());

  // Should persist across redirects.
  std::unique_ptr<ResourceRequest> redirect_request =
      original.CreateRedirectRequest(
          KURL("https://example.test/redirect"), original.HttpMethod(),
          original.SiteForCookies(), original.ReferrerString(),
          original.GetReferrerPolicy(), original.GetSkipServiceWorker());
  EXPECT_TRUE(redirect_request->IsAdResource());
}

TEST(ResourceRequestTest, UpgradeIfInsecureAcrossRedirects) {
  ResourceRequest original;
  EXPECT_FALSE(original.UpgradeIfInsecure());
  original.SetUpgradeIfInsecure(true);
  EXPECT_TRUE(original.UpgradeIfInsecure());

  // Should persist across redirects.
  std::unique_ptr<ResourceRequest> redirect_request =
      original.CreateRedirectRequest(
          KURL("https://example.test/redirect"), original.HttpMethod(),
          original.SiteForCookies(), original.ReferrerString(),
          original.GetReferrerPolicy(), original.GetSkipServiceWorker());
  EXPECT_TRUE(redirect_request->UpgradeIfInsecure());
}

// A cross-origin subresource request that explicitly sets an opt-in flag (e.g.
// `browsingTopics`, `sharedStorageWritable`) should have the corresponding
// permission as long as it passes the allowlist check, regardless of the
// feature's default state.
TEST(ResourceRequestTest, IsFeatureEnabledForSubresourceRequestAssumingOptIn) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures(
      {blink::features::kBrowsingTopics, blink::features::kSharedStorageAPI},
      /*disabled_features=*/{});

  ResourceRequest request_with_topics_opt_in;
  request_with_topics_opt_in.SetBrowsingTopics(true);

  ResourceRequest request_with_shared_storage_opt_in;
  request_with_shared_storage_opt_in.SetSharedStorageWritableOptedIn(true);

  ResourceRequest request_with_both_opt_in;
  request_with_both_opt_in.SetBrowsingTopics(true);
  request_with_both_opt_in.SetSharedStorageWritableOptedIn(true);

  const url::Origin origin_a =
      url::Origin::Create(GURL("https://example.com/"));
  const url::Origin origin_b =
      url::Origin::Create(GURL("https://example.net/"));
  const url::Origin origin_c =
      url::Origin::Create(GURL("https://example.org/"));

  {
    // +--------------------------------------------------------+
    // |(1)Origin A                                             |
    // |No Policy                                               |
    // |                                                        |
    // | fetch(<Origin B's url>, {browsingTopics: true})        |
    // | fetch(<Origin B's url>, {sharedStorageWritable: true}) |
    // | fetch(<Origin B's url>, {browsingTopics: true,         |
    // |                          sharedStorageWritable: true}) |
    // +--------------------------------------------------------+

    std::unique_ptr<PermissionsPolicy> policy =
        CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a);

    EXPECT_TRUE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics, origin_a));
    EXPECT_TRUE(request_with_topics_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                        origin_a));
    EXPECT_TRUE(request_with_both_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                        origin_a));

    EXPECT_TRUE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kSharedStorage, origin_a));
    EXPECT_TRUE(request_with_shared_storage_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                        origin_a));
    EXPECT_TRUE(request_with_both_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                        origin_a));

    EXPECT_TRUE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics, origin_b));
    EXPECT_TRUE(request_with_topics_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                        origin_b));
    EXPECT_TRUE(request_with_both_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                        origin_b));

    EXPECT_TRUE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kSharedStorage, origin_b));
    EXPECT_TRUE(request_with_shared_storage_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                        origin_b));
    EXPECT_TRUE(request_with_both_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                        origin_b));
  }

  {
    // +--------------------------------------------------------+
    // |(1)Origin A                                             |
    // |Permissions-Policy: browsing-topics=(self),             |
    // |                    shared-storage=(self)               |
    // |                                                        |
    // | fetch(<Origin B's url>, {browsingTopics: true})        |
    // | fetch(<Origin B's url>, {sharedStorageWritable: true}) |
    // | fetch(<Origin B's url>, {browsingTopics: true,         |
    // |                          sharedStorageWritable: true}) |
    // +--------------------------------------------------------+

    std::unique_ptr<PermissionsPolicy> policy = CreateFromParentPolicy(
        nullptr,
        {{{mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
           /*allowed_origins=*/{},
           /*self_if_matches=*/origin_a,
           /*matches_all_origins=*/false,
           /*matches_opaque_src=*/false},
          {mojom::blink::PermissionsPolicyFeature::kSharedStorage,
           /*allowed_origins=*/{},
           /*self_if_matches=*/origin_a,
           /*matches_all_origins=*/false,
           /*matches_opaque_src=*/false}}},
        origin_a);

    EXPECT_TRUE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics, origin_a));
    EXPECT_TRUE(request_with_topics_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                        origin_a));
    EXPECT_TRUE(request_with_both_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                        origin_a));

    EXPECT_TRUE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kSharedStorage, origin_a));
    EXPECT_TRUE(request_with_shared_storage_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                        origin_a));
    EXPECT_TRUE(request_with_both_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                        origin_a));

    EXPECT_FALSE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics, origin_b));
    EXPECT_FALSE(
        request_with_topics_opt_in
            .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                policy.get(),
                mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                origin_b));
    EXPECT_FALSE(
        request_with_both_opt_in
            .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                policy.get(),
                mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                origin_b));

    EXPECT_FALSE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kSharedStorage, origin_b));
    EXPECT_FALSE(request_with_shared_storage_opt_in
                     .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                         policy.get(),
                         mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                         origin_b));
    EXPECT_FALSE(request_with_both_opt_in
                     .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                         policy.get(),
                         mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                         origin_b));
  }

  {
    // +--------------------------------------------------------+
    // |(1)Origin A                                             |
    // |Permissions-Policy: browsing-topics=(none),             |
    // |                    shared-storage=(none)               |
    // |                                                        |
    // | fetch(<Origin B's url>, {browsingTopics: true})        |
    // | fetch(<Origin B's url>, {sharedStorageWritable: true}) |
    // | fetch(<Origin B's url>, {browsingTopics: true,         |
    // |                          sharedStorageWritable: true}) |
    // +--------------------------------------------------------+

    std::unique_ptr<PermissionsPolicy> policy = CreateFromParentPolicy(
        nullptr,
        {{{mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
           /*allowed_origins=*/{},
           /*self_if_matches=*/std::nullopt,
           /*matches_all_origins=*/false,
           /*matches_opaque_src=*/false},
          {mojom::blink::PermissionsPolicyFeature::kSharedStorage,
           /*allowed_origins=*/{},
           /*self_if_matches=*/std::nullopt,
           /*matches_all_origins=*/false,
           /*matches_opaque_src=*/false}}},
        origin_a);

    EXPECT_FALSE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics, origin_a));
    EXPECT_FALSE(
        request_with_topics_opt_in
            .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                policy.get(),
                mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                origin_a));
    EXPECT_FALSE(
        request_with_both_opt_in
            .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                policy.get(),
                mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                origin_a));

    EXPECT_FALSE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kSharedStorage, origin_a));
    EXPECT_FALSE(request_with_shared_storage_opt_in
                     .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                         policy.get(),
                         mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                         origin_a));
    EXPECT_FALSE(request_with_both_opt_in
                     .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                         policy.get(),
                         mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                         origin_a));

    EXPECT_FALSE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics, origin_b));
    EXPECT_FALSE(
        request_with_topics_opt_in
            .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                policy.get(),
                mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                origin_b));
    EXPECT_FALSE(
        request_with_both_opt_in
            .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                policy.get(),
                mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                origin_b));

    EXPECT_FALSE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kSharedStorage, origin_b));
    EXPECT_FALSE(request_with_shared_storage_opt_in
                     .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                         policy.get(),
                         mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                         origin_b));
    EXPECT_FALSE(request_with_both_opt_in
                     .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                         policy.get(),
                         mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                         origin_b));
  }

  {
    // +--------------------------------------------------------+
    // |(1)Origin A                                             |
    // |Permissions-Policy: browsing-topics=*,                  |
    // |                    shared-storage=*                    |
    // |                                                        |
    // | fetch(<Origin B's url>, {browsingTopics: true})        |
    // | fetch(<Origin B's url>, {sharedStorageWritable: true}) |
    // | fetch(<Origin B's url>, {browsingTopics: true,         |
    // |                          sharedStorageWritable: true}) |
    // +--------------------------------------------------------+

    std::unique_ptr<PermissionsPolicy> policy = CreateFromParentPolicy(
        nullptr,
        {{{mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
           /*allowed_origins=*/{},
           /*self_if_matches=*/std::nullopt,
           /*matches_all_origins=*/true,
           /*matches_opaque_src=*/false},
          {mojom::blink::PermissionsPolicyFeature::kSharedStorage,
           /*allowed_origins=*/{},
           /*self_if_matches=*/std::nullopt,
           /*matches_all_origins=*/true,
           /*matches_opaque_src=*/false}}},
        origin_a);

    EXPECT_TRUE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics, origin_a));
    EXPECT_TRUE(request_with_topics_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                        origin_a));
    EXPECT_TRUE(request_with_both_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                        origin_a));

    EXPECT_TRUE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kSharedStorage, origin_a));
    EXPECT_TRUE(request_with_shared_storage_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                        origin_a));
    EXPECT_TRUE(request_with_both_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                        origin_a));

    EXPECT_TRUE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics, origin_b));
    EXPECT_TRUE(request_with_topics_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                        origin_b));
    EXPECT_TRUE(request_with_both_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                        origin_b));

    EXPECT_TRUE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kSharedStorage, origin_b));
    EXPECT_TRUE(request_with_shared_storage_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                        origin_b));
    EXPECT_TRUE(request_with_both_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                        origin_b));
  }

  {
    // +--------------------------------------------------------+
    // |(1)Origin A                                             |
    // |Permissions-Policy: browsing-topics=(Origin B),         |
    // |                    shared-storage=(Origin B)           |
    // |                                                        |
    // | fetch(<Origin B's url>, {browsingTopics: true})        |
    // | fetch(<Origin B's url>, {sharedStorageWritable: true}) |
    // | fetch(<Origin B's url>, {browsingTopics: true,         |
    // |                          sharedStorageWritable: true}) |
    // | fetch(<Origin C's url>, {browsingTopics: true})        |
    // | fetch(<Origin C's url>, {sharedStorageWritable: true}) |
    // | fetch(<Origin C's url>, {browsingTopics: true,         |
    // |                          sharedStorageWritable: true}) |
    // +--------------------------------------------------------+

    std::unique_ptr<PermissionsPolicy> policy = CreateFromParentPolicy(
        nullptr,
        {{{mojom::blink::PermissionsPolicyFeature::
               kBrowsingTopics, /*allowed_origins=*/
           {*blink::OriginWithPossibleWildcards::FromOrigin(origin_b)},
           /*self_if_matches=*/std::nullopt,
           /*matches_all_origins=*/false,
           /*matches_opaque_src=*/false},
          {mojom::blink::PermissionsPolicyFeature::
               kSharedStorage, /*allowed_origins=*/
           {*blink::OriginWithPossibleWildcards::FromOrigin(origin_b)},
           /*self_if_matches=*/std::nullopt,
           /*matches_all_origins=*/false,
           /*matches_opaque_src=*/false}}},
        origin_a);

    EXPECT_FALSE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics, origin_a));
    EXPECT_FALSE(
        request_with_topics_opt_in
            .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                policy.get(),
                mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                origin_a));
    EXPECT_FALSE(
        request_with_both_opt_in
            .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                policy.get(),
                mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                origin_a));

    EXPECT_FALSE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kSharedStorage, origin_a));
    EXPECT_FALSE(request_with_shared_storage_opt_in
                     .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                         policy.get(),
                         mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                         origin_a));
    EXPECT_FALSE(request_with_both_opt_in
                     .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                         policy.get(),
                         mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                         origin_a));

    EXPECT_TRUE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics, origin_b));
    EXPECT_TRUE(request_with_topics_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                        origin_b));
    EXPECT_TRUE(request_with_both_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                        origin_b));

    EXPECT_TRUE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kSharedStorage, origin_b));
    EXPECT_TRUE(request_with_shared_storage_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                        origin_b));
    EXPECT_TRUE(request_with_both_opt_in
                    .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                        policy.get(),
                        mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                        origin_b));

    EXPECT_FALSE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kBrowsingTopics, origin_c));
    EXPECT_FALSE(
        request_with_topics_opt_in
            .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                policy.get(),
                mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                origin_c));
    EXPECT_FALSE(
        request_with_both_opt_in
            .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                policy.get(),
                mojom::blink::PermissionsPolicyFeature::kBrowsingTopics,
                origin_c));

    EXPECT_FALSE(policy->IsFeatureEnabledForOrigin(
        mojom::blink::PermissionsPolicyFeature::kSharedStorage, origin_c));
    EXPECT_FALSE(request_with_shared_storage_opt_in
                     .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                         policy.get(),
                         mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                         origin_c));
    EXPECT_FALSE(request_with_both_opt_in
                     .IsFeatureEnabledForSubresourceRequestAssumingOptIn(
                         policy.get(),
                         mojom::blink::PermissionsPolicyFeature::kSharedStorage,
                         origin_c));
  }
}

}  // namespace blink
```