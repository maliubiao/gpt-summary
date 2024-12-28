Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. The file is `permissions_policy_unittest.cc`, so it's a unit test file for the Permissions Policy feature.

Here's a plan to generate the summary:

1. **Identify the core purpose:** The file tests the Permissions Policy implementation.
2. **Analyze each `TEST_F` function:** Each test function focuses on a specific aspect of the Permissions Policy.
3. **Relate to web technologies:** Determine if the tested functionality has connections to JavaScript, HTML, or CSS (Permissions Policy interacts with these).
4. **Identify logical reasoning:** Look for tests that demonstrate how policies are inherited, combined, and enforced in different scenarios.
5. **Find potential usage errors:**  Examine tests that might highlight common mistakes developers could make when using Permissions Policy.
6. **Synthesize the information:** Combine the individual test functionalities into a comprehensive summary.
这是对`blink/common/permissions_policy/permissions_policy_unittest.cc` 文件功能的归纳总结，基于你提供的最后一部分代码。

**功能归纳：**

这部分代码主要测试了 Chromium Blink 引擎中 Permissions Policy 功能在以下几个方面的行为：

1. **提议的跨域子帧策略 (Proposed Cross-Origin Child Policy):**  验证了在新的 Permissions Policy 模型下，即使父级文档通过 HTTP 头部明确允许某个功能给特定源，子框架要启用该功能，**仍然需要自己的帧策略明确授予**。这与现有的策略有所不同，在现有策略中，如果帧策略没有明确提及某个功能，则会继承父策略。代码通过创建不同源的父子框架，并设置不同的头部策略和帧策略组合，来断言子框架是否启用了 `default-self` 功能。

2. **提议的允许所有跨域子帧策略 (Proposed Allow All Cross-Origin Child Policy):**  与上一点类似，但父级文档的头部策略允许该功能给所有源 (`default-self=*`)。测试仍然验证了子框架即使在父级允许所有的情况下，**也需要自己的帧策略明确授予该功能**。

3. **提议的嵌套策略传播 (Proposed Nested Policy Propagates):**  测试了新的策略变更是否会沿着框架树向下传播。即使功能的测试发生在与策略变更不同的框架中，变更也应该被感知到。

4. **为 Fenced Frame 创建灵活的策略 (Create Flexible for Fenced Frame):**  测试了为 Fenced Frame 创建 Permissions Policy 的能力。 Fenced Frame 是一种隔离的嵌入式内容，它有自己特殊的策略限制。测试验证了对于 Fenced Frame 创建的策略，某些功能默认是禁用的 (`kDefaultOnFeature`, `kDefaultSelfFeature`, `kAttributionReporting`)，而某些功能是默认启用的 (`kSharedStorage`, `kSharedStorageSelectUrl`, `kPrivateAggregation`)。

5. **为 FLEDGE Fenced Frame 创建策略 (Create for Fledge Fenced Frame):**  测试了为 FLEDGE (一种隐私保护的广告技术) 相关的 Fenced Frame 创建策略。它验证了特定的一组功能 (`kFencedFrameFledgeDefaultRequiredFeatures`) 在这种 Fenced Frame 中是默认启用的，而其他功能则不是。

6. **为 Shared Storage Fenced Frame 创建策略 (Create for Shared Storage Fenced Frame):** 测试了为 Shared Storage 相关的 Fenced Frame 创建策略。它验证了特定的一组功能 (`kFencedFrameSharedStorageDefaultRequiredFeatures`) 在这种 Fenced Frame 中是默认启用的。

7. **从解析后的策略创建 (Create From Parsed Policy):**  测试了从已解析的策略数据结构 (`ParsedPermissionsPolicy`) 创建 `PermissionsPolicy` 对象的能力。测试了允许特定源，排除自身，以及允许列表为空的情况。

8. **覆盖客户端提示的头部策略 (Overwrite Header Policy for Client Hints):**  测试了如何通过 `WithClientHints` 方法来设置或覆盖客户端提示相关的 Permissions Policy 头部。验证了可以启用、禁用和修改客户端提示策略，并断言了不能用这个方法修改非客户端提示的策略（会导致 DCHECK 失败）。

9. **获取现有功能的允许列表 (GetAllowlistForFeatureIfExists):** 测试了如何获取特定功能的允许源列表。验证了在设置了策略、未设置策略以及覆盖策略后，能否正确获取到允许列表。

10. **`unload` 事件的默认行为由弃用标志控制 (Unload Default Enabled For All/None):**  测试了 `unload` 事件的 Permissions Policy 默认行为是否受一个弃用 Feature Flag 控制。根据 Feature Flag 的设置，`unload` 事件的默认行为可以是 "对所有源启用" 或 "对所有源禁用"。

11. **根据 rollout 百分比获取 `unload` 的策略列表 (GetPermissionsPolicyFeatureListForUnload):**  测试了在灰度发布的情况下，对于给定的 URL 和 rollout 百分比，`unload` 事件应该有多少比例的网站被设置为 "禁用"。这涉及到 Feature Flag 的参数配置和哈希分桶逻辑。

12. **`unload` 弃用允许的主机列表 (Unload Deprecation Allowed Hosts):** 测试了如何通过 Feature Flag 的参数来配置一个允许启用 `unload` 弃用的主机白名单。

13. **`unload` 弃用允许的主机列表（空主机）(Unload Deprecation Allowed Hosts Empty):** 类似于上一点，但测试了允许列表包含空字符串的情况，确保能正确处理。

14. **`UnloadDeprecationAllowedForHost` 的主机列表测试 (Unload DeprecationAllowedForHost Host Lists):** 测试了 `UnloadDeprecationAllowedForHost` 函数在有和没有主机白名单时的行为，验证了只有在白名单中的主机才会受到 `unload` 弃用的影响。

15. **`UnloadDeprecationAllowedForOrigin` 对于非 HTTP 源的处理 (UnloadDeprecationAllowedForOrigin_NonHttp):** 测试了对于非 HTTP(S) 的源（例如 `chrome://` ），`unload` 弃用是否被允许。

16. **`UnloadDeprecationAllowedForOrigin` 的渐进式灰度发布 (UnloadDeprecationAllowedForOrigin_GradualRollout):** 测试了在不同的灰度发布百分比下，`UnloadDeprecationAllowedForOrigin` 函数的返回值是否符合预期，并且验证了主机白名单和灰度发布共同作用时的行为。

**与 JavaScript, HTML, CSS 的关系：**

Permissions Policy 是一个 Web 平台的功能，它通过 HTTP 头部或 HTML 元素的属性来声明。

* **HTTP 头部：**  例如 `Permissions-Policy: camera=(self "example.com")` 声明了当前文档及其 `example.com` 的同源可以访问摄像头 API。 代码中 `CreateFromParentPolicy` 方法模拟了从 HTTP 头部创建策略的过程。
* **HTML `<iframe>` 标签的 `allow` 属性：** 例如 `<iframe src="child.html" allow="camera 'none'"></iframe>` 声明了嵌入的 `child.html` 无法访问摄像头 API。 代码中的 `CreateFromParentWithFramePolicy` 方法模拟了这种场景。
* **JavaScript API (虽然代码中没有直接体现)：**  JavaScript 可以通过 `navigator.permissions.query()` 方法查询当前 Permissions Policy 的状态，虽然这个测试文件不直接测试 JS API，但它测试了 Permissions Policy 引擎的逻辑，这会影响 JS API 的行为。

**逻辑推理的假设输入与输出：**

以 `ProposedTestAllowedCrossOriginChildPolicy` 这个测试为例：

* **假设输入：**
    * 父文档（Origin A）的 HTTP 头部设置了 `Permissions-Policy: default-self=(self "OriginB")`
    * 子框架 2（Origin A）没有设置帧策略。
    * 子框架 3（Origin B）没有设置帧策略。
    * 子框架 4（Origin B）的帧策略设置为 `<allow="default-self *">`。
    * 子框架 5（Origin B）的帧策略设置为 `<allow="default-self OriginB">`。
    * 子框架 6（Origin C）的帧策略设置为 `<allow="default-self OriginC">`。
* **预期输出：**
    * `policy2->IsFeatureEnabled(kDefaultSelfFeature)` 为 `true` (Origin A 的子框架可以继承父策略的 self)。
    * `policy3->IsFeatureEnabled(kDefaultSelfFeature)` 为 `false` (Origin B 的子框架即使父级允许，但自身未明确允许，则不启用)。
    * `policy4->IsFeatureEnabled(kDefaultSelfFeature)` 为 `true` (Origin B 的子框架通过 `<allow="default-self *">` 明确允许)。
    * `policy5->IsFeatureEnabled(kDefaultSelfFeature)` 为 `true` (Origin B 的子框架通过 `<allow="default-self OriginB">` 明确允许)。
    * `policy6->IsFeatureEnabled(kDefaultSelfFeature)` 为 `false` (Origin B 的子框架虽然设置了帧策略，但只允许了 Origin C，自身不是 Origin C)。

**用户或编程常见的使用错误：**

* **未能理解帧策略的重要性：** 开发者可能认为父级文档设置了 Permissions Policy 后，所有子框架都会自动继承，而忽略了子框架需要通过 `allow` 属性或 HTTP 头部明确声明。例如，在 `ProposedTestAllowedCrossOriginChildPolicy` 中，如果开发者期望 `policy3` 的 `default-self` 功能被启用，就会犯错。
* **客户端提示策略覆盖的误用：**  开发者可能会尝试使用 `WithClientHints` 方法去修改非客户端提示的策略，这会导致断言失败。`OverwriteHeaderPolicyForClientHints` 测试就演示了这种错误。
* **对 `unload` 事件行为的误解：**  开发者可能没有注意到 `unload` 事件的默认行为可以通过 Feature Flag 进行控制，或者不了解主机白名单的配置，导致他们的网站在预期之外受到了 `unload` 弃用的影响。

总而言之，这个测试文件全面地验证了 Permissions Policy 功能在各种场景下的行为，特别是针对新的策略模型和 Fenced Frame 等新特性，同时也覆盖了一些常见的配置和使用情况，并指出了潜在的错误使用方式。

Prompt: 
```
这是目录为blink/common/permissions_policy/permissions_policy_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能

"""
EST_F(PermissionsPolicyTest, ProposedTestAllowedCrossOriginChildPolicy) {
  // +---------------------------------------------------+
  // |(1)Origin A                                        |
  // |Permissions-Policy: default-self=(self "OriginB")  |
  // | +--------------+  +--------------+                |
  // | |(2)Origin A   |  |(3)Origin B   |                |
  // | |No Policy     |  |No Policy     |                |
  // | +--------------+  +--------------+                |
  // | <allow="default-self *">                          |
  // | +--------------+                                  |
  // | |(4)Origin B   |                                  |
  // | |No Policy     |                                  |
  // | +--------------+                                  |
  // | <allow="default-self OriginB">                    |
  // | +--------------+                                  |
  // | |(5)Origin B   |                                  |
  // | |No Policy     |                                  |
  // | +--------------+                                  |
  // | <allow="default-self OriginB">                    |
  // | +--------------+                                  |
  // | |(6)Origin C   |                                  |
  // | |No Policy     |                                  |
  // | +--------------+                                  |
  // +---------------------------------------------------+
  // When a feature is explicitly enabled for an origin by the header in the
  // parent document, it still requires that the frame policy also grant it to
  // that frame in order to be enabled in the child. (This is different from the
  // current algorithm, in the case where the frame policy does not mention the
  // feature explicitly.)
  std::unique_ptr<PermissionsPolicy> policy1 = CreateFromParentPolicy(
      nullptr,
      {{{kDefaultSelfFeature, /*allowed_origins=*/
         {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
             origin_b_,
             /*has_subdomain_wildcard=*/false)},
         /*self_if_matches=*/origin_a_,
         /*matches_all_origins=*/true,
         /*matches_opaque_src=*/false}}},
      origin_a_);

  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_a_);
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultSelfFeature));

  // This is a critical change from the existing semantics.
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_b_);
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultSelfFeature));

  ParsedPermissionsPolicy frame_policy4 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/true,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy4 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy4, origin_b_);
  EXPECT_TRUE(policy4->IsFeatureEnabled(kDefaultSelfFeature));

  ParsedPermissionsPolicy frame_policy5 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
            origin_b_,
            /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy5 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy5, origin_b_);
  EXPECT_TRUE(policy5->IsFeatureEnabled(kDefaultSelfFeature));

  ParsedPermissionsPolicy frame_policy6 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
            origin_c_,
            /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy6 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy6, origin_b_);
  EXPECT_FALSE(policy6->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, ProposedTestAllAllowedCrossOriginChildPolicy) {
  // +------------------------------------+
  // |(1)Origin A                         |
  // |Permissions-Policy: default-self=*  |
  // | +--------------+  +--------------+ |
  // | |(2)Origin A   |  |(3)Origin B   | |
  // | |No Policy     |  |No Policy     | |
  // | +--------------+  +--------------+ |
  // | <allow="default-self *">           |
  // | +--------------+                   |
  // | |(4)Origin B   |                   |
  // | |No Policy     |                   |
  // | +--------------+                   |
  // | <allow="default-self OriginB">     |
  // | +--------------+                   |
  // | |(5)Origin B   |                   |
  // | |No Policy     |                   |
  // | +--------------+                   |
  // | <allow="default-self OriginB">     |
  // | +--------------+                   |
  // | |(6)Origin C   |                   |
  // | |No Policy     |                   |
  // | +--------------+                   |
  // +------------------------------------+
  // When a feature is explicitly enabled for all origins by the header in the
  // parent document, it still requires that the frame policy also grant it to
  // that frame in order to be enabled in the child. (This is different from the
  // current algorithm, in the case where the frame policy does not mention the
  // feature explicitly.)
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultSelfFeature, /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/true,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);

  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_a_);
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultSelfFeature));

  // This is a critical change from the existing semantics.
  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_b_);
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultSelfFeature));

  ParsedPermissionsPolicy frame_policy4 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/true,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy4 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy4, origin_b_);
  EXPECT_TRUE(policy4->IsFeatureEnabled(kDefaultSelfFeature));

  ParsedPermissionsPolicy frame_policy5 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
            origin_b_,
            /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy5 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy5, origin_b_);
  EXPECT_TRUE(policy5->IsFeatureEnabled(kDefaultSelfFeature));

  ParsedPermissionsPolicy frame_policy6 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
            origin_c_,
            /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy6 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy6, origin_b_);
  EXPECT_FALSE(policy6->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, ProposedTestNestedPolicyPropagates) {
  // +-------------------------------------------------+
  // |(1)Origin A                                      |
  // |Permissions-Policy: default-self=(self "OriginB")|
  // | +--------------------------------+              |
  // | |(2)Origin B                     |              |
  // | |No Policy                       |              |
  // | | <allow="default-self *">       |              |
  // | | +--------------+               |              |
  // | | |(3)Origin B   |               |              |
  // | | |No Policy     |               |              |
  // | | +--------------+               |              |
  // | +--------------------------------+              |
  // +-------------------------------------------------+
  // Ensures that a proposed policy change will propagate down the frame tree.
  // This is important so that we can tell when a change has happened, even if
  // the feature is tested in a different one than where the
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

  // This is where the change first occurs.
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_b_);
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultSelfFeature));

  // The proposed value in frame 2 should affect the proposed value in frame 3.
  ParsedPermissionsPolicy frame_policy3 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/true,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy3 = CreateFromParentWithFramePolicy(
      policy2.get(), /*header_policy=*/{}, frame_policy3, origin_b_);
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, CreateFlexibleForFencedFrame) {
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultOnFeature, /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/true,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  std::unique_ptr<PermissionsPolicy> policy = CreateFlexibleForFencedFrame(
      policy1.get(), /*header_policy=*/{}, origin_a_);
  EXPECT_FALSE(policy->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_FALSE(policy->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy->IsFeatureEnabled(
      mojom::PermissionsPolicyFeature::kAttributionReporting));
  EXPECT_TRUE(policy->IsFeatureEnabled(
      mojom::PermissionsPolicyFeature::kSharedStorage));
  EXPECT_TRUE(policy->IsFeatureEnabled(
      mojom::PermissionsPolicyFeature::kSharedStorageSelectUrl));
  EXPECT_TRUE(policy->IsFeatureEnabled(
      mojom::PermissionsPolicyFeature::kPrivateAggregation));
}

TEST_F(PermissionsPolicyTest, CreateForFledgeFencedFrame) {
  std::vector<blink::mojom::PermissionsPolicyFeature>
      effective_enabled_permissions;
  effective_enabled_permissions.insert(
      effective_enabled_permissions.end(),
      std::begin(blink::kFencedFrameFledgeDefaultRequiredFeatures),
      std::end(blink::kFencedFrameFledgeDefaultRequiredFeatures));

  std::unique_ptr<PermissionsPolicy> policy = CreateFixedForFencedFrame(
      origin_a_, /*header_policy=*/{}, effective_enabled_permissions);
  EXPECT_FALSE(policy->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_FALSE(policy->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_TRUE(policy->IsFeatureEnabled(
      mojom::PermissionsPolicyFeature::kAttributionReporting));
  EXPECT_TRUE(policy->IsFeatureEnabled(
      mojom::PermissionsPolicyFeature::kSharedStorage));
}

TEST_F(PermissionsPolicyTest, CreateForSharedStorageFencedFrame) {
  std::vector<blink::mojom::PermissionsPolicyFeature>
      effective_enabled_permissions;
  effective_enabled_permissions.insert(
      effective_enabled_permissions.end(),
      std::begin(blink::kFencedFrameSharedStorageDefaultRequiredFeatures),
      std::end(blink::kFencedFrameSharedStorageDefaultRequiredFeatures));

  std::unique_ptr<PermissionsPolicy> policy = CreateFixedForFencedFrame(
      origin_a_, /*header_policy=*/{}, effective_enabled_permissions);
  EXPECT_FALSE(policy->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_FALSE(policy->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_TRUE(policy->IsFeatureEnabled(
      mojom::PermissionsPolicyFeature::kAttributionReporting));
  EXPECT_TRUE(policy->IsFeatureEnabled(
      mojom::PermissionsPolicyFeature::kSharedStorage));
}

TEST_F(PermissionsPolicyTest, CreateFromParsedPolicy) {
  ParsedPermissionsPolicy parsed_policy = {
      {{kDefaultSelfFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
             origin_a_,
             /*has_subdomain_wildcard=*/false),
         *blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
             origin_b_,
             /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  auto policy = CreateFromParsedPolicy(parsed_policy, origin_a_);
  EXPECT_TRUE(
      policy->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_a_));
  EXPECT_TRUE(
      policy->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_b_));
}

TEST_F(PermissionsPolicyTest, CreateFromParsedPolicyExcludingSelf) {
  ParsedPermissionsPolicy parsed_policy = {
      {{kDefaultSelfFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
            origin_b_,
            /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  auto policy = CreateFromParsedPolicy(parsed_policy, origin_a_);
  EXPECT_FALSE(
      policy->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_a_));
  EXPECT_FALSE(
      policy->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_b_));
}

TEST_F(PermissionsPolicyTest, CreateFromParsedPolicyWithEmptyAllowlist) {
  ParsedPermissionsPolicy parsed_policy = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  auto policy = CreateFromParsedPolicy(parsed_policy, origin_a_);
  EXPECT_FALSE(policy->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, OverwriteHeaderPolicyForClientHints) {
  // We can construct a policy, set/overwrite the same header, and then check.
  auto policy1 = CreateFromParentPolicy(
      nullptr,
      {{{mojom::PermissionsPolicyFeature::kClientHintDPR,
         /*allowed_origins=*/
         {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
             origin_b_,
             /*has_subdomain_wildcard=*/false)},
         /*self_if_matches=*/std::nullopt,
         /*matches_all_origins=*/false,
         /*matches_opaque_src=*/false}}},
      origin_a_);
  policy1 = policy1->WithClientHints(
      {{{mojom::PermissionsPolicyFeature::kClientHintDPR,
         /*allowed_origins=*/
         {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
             origin_a_,
             /*has_subdomain_wildcard=*/false)},
         /*self_if_matches=*/std::nullopt,
         /*matches_all_origins=*/false,
         /*matches_opaque_src=*/false}}});
  EXPECT_TRUE(policy1->IsFeatureEnabled(
      mojom::PermissionsPolicyFeature::kClientHintDPR));

  // If we overwrite an enabled header with a disabled header it's now disabled.
  auto policy2 = CreateFromParentPolicy(
      nullptr,
      {{{mojom::PermissionsPolicyFeature::kClientHintDPR,
         /*allowed_origins=*/
         {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
             origin_a_,
             /*has_subdomain_wildcard=*/false)},
         /*self_if_matches=*/std::nullopt,
         /*matches_all_origins=*/false,
         /*matches_opaque_src=*/false}}},
      origin_a_);
  policy2 = policy2->WithClientHints(
      {{{mojom::PermissionsPolicyFeature::kClientHintDPR,
         /*allowed_origins=*/
         {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
             origin_b_,
             /*has_subdomain_wildcard=*/false)},
         /*self_if_matches=*/std::nullopt,
         /*matches_all_origins=*/false,
         /*matches_opaque_src=*/false}}});
  EXPECT_FALSE(policy2->IsFeatureEnabled(
      mojom::PermissionsPolicyFeature::kClientHintDPR));

  // We can construct a policy, set/overwrite different headers, and then check.
  auto policy3 = CreateFromParentPolicy(
      nullptr,
      {{{kDefaultSelfFeature, /*allowed_origins=*/
         {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
             origin_b_,
             /*has_subdomain_wildcard=*/false)},
         /*self_if_matches=*/std::nullopt,
         /*matches_all_origins=*/false,
         /*matches_opaque_src=*/false}}},
      origin_a_);
  policy3 = policy3->WithClientHints(
      {{{mojom::PermissionsPolicyFeature::kClientHintDPR,
         /*allowed_origins=*/
         {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
             origin_a_,
             /*has_subdomain_wildcard=*/false)},
         /*self_if_matches=*/std::nullopt,
         /*matches_all_origins=*/false,
         /*matches_opaque_src=*/false}}});
  EXPECT_TRUE(policy3->IsFeatureEnabled(
      mojom::PermissionsPolicyFeature::kClientHintDPR));

  // We can't overwrite a non-client-hint header.
  auto policy4 = CreateFromParentPolicy(nullptr, {}, origin_a_);
  EXPECT_DCHECK_DEATH(policy4->WithClientHints(
      {{{kDefaultSelfFeature, /*allowed_origins=*/
         {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
             origin_a_,
             /*has_subdomain_wildcard=*/false)},
         /*self_if_matches=*/std::nullopt,
         /*matches_all_origins=*/false,
         /*matches_opaque_src=*/false}}}));
}

TEST_F(PermissionsPolicyTest, GetAllowlistForFeatureIfExists) {
  const std::vector<blink::OriginWithPossibleWildcards> origins1(
      {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
          origin_b_,
          /*has_subdomain_wildcard=*/false)});
  // If we set a policy, then we can extract it.
  auto policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{mojom::PermissionsPolicyFeature::kClientHintDPR,
                                origins1, /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/false,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  const auto& maybe_allow_list1 = policy1->GetAllowlistForFeatureIfExists(
      mojom::PermissionsPolicyFeature::kClientHintDPR);
  EXPECT_TRUE(maybe_allow_list1.has_value());
  EXPECT_FALSE(maybe_allow_list1.value().MatchesAll());
  EXPECT_FALSE(maybe_allow_list1.value().MatchesOpaqueSrc());
  EXPECT_THAT(maybe_allow_list1.value().AllowedOrigins(),
              testing::ContainerEq(origins1));

  // If we don't set a policy, then we can't extract it.
  auto policy2 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  const auto& maybe_allow_list2 = policy2->GetAllowlistForFeatureIfExists(
      mojom::PermissionsPolicyFeature::kClientHintDPR);
  EXPECT_FALSE(maybe_allow_list2.has_value());

  const std::vector<blink::OriginWithPossibleWildcards> origins3(
      {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
          origin_a_,
          /*has_subdomain_wildcard=*/false)});
  // If we set a policy, then overwrite it, we can extract it.
  auto policy3 =
      CreateFromParentPolicy(nullptr,
                             {{{mojom::PermissionsPolicyFeature::kClientHintDPR,
                                {},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/false,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  auto new_policy3 = policy3->WithClientHints(
      {{{mojom::PermissionsPolicyFeature::kClientHintDPR, origins3,
         /*self_if_matches=*/std::nullopt,
         /*matches_all_origins=*/false,
         /*matches_opaque_src=*/false}}});
  const auto& maybe_allow_list3 = new_policy3->GetAllowlistForFeatureIfExists(
      mojom::PermissionsPolicyFeature::kClientHintDPR);
  EXPECT_TRUE(maybe_allow_list3.has_value());
  EXPECT_FALSE(maybe_allow_list3.value().MatchesAll());
  EXPECT_FALSE(maybe_allow_list3.value().MatchesOpaqueSrc());
  EXPECT_THAT(maybe_allow_list3.value().AllowedOrigins(),
              testing::ContainerEq(origins3));

  // If we don't set a policy, then overwrite it, we can extract it.
  auto policy4 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  const std::vector<blink::OriginWithPossibleWildcards> origins4(
      {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
           origin_a_,
           /*has_subdomain_wildcard=*/false),
       *blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
           origin_b_,
           /*has_subdomain_wildcard=*/false)});
  policy4 = policy4->WithClientHints(
      {{{mojom::PermissionsPolicyFeature::kClientHintDPR, origins4,
         /*self_if_matches=*/std::nullopt,
         /*matches_all_origins=*/false,
         /*matches_opaque_src=*/false}}});
  const auto& maybe_allow_list4 = policy4->GetAllowlistForFeatureIfExists(
      mojom::PermissionsPolicyFeature::kClientHintDPR);
  EXPECT_TRUE(maybe_allow_list4.has_value());
  EXPECT_FALSE(maybe_allow_list4.value().MatchesAll());
  EXPECT_FALSE(maybe_allow_list4.value().MatchesOpaqueSrc());
  EXPECT_THAT(maybe_allow_list4.value().AllowedOrigins(),
              testing::ContainerEq(origins4));
}

// Tests that "unload"'s default is controlled by the deprecation flag.
TEST_F(PermissionsPolicyTest, UnloadDefaultEnabledForAll) {
  {
    base::test::ScopedFeatureList scoped_feature_list;
    scoped_feature_list.InitWithFeatures({},
                                         {blink::features::kDeprecateUnload});
    std::unique_ptr<PermissionsPolicy> policy =
        CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
    EXPECT_EQ(PermissionsPolicyFeatureDefault::EnableForAll,
              GetPermissionsPolicyFeatureList(origin_a_)
                  .find(mojom::PermissionsPolicyFeature::kUnload)
                  ->second);
  }
}

// Tests that "unload"'s default is controlled by the deprecation flag.
TEST_F(PermissionsPolicyTest, UnloadDefaultEnabledForNone) {
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitWithFeatures({blink::features::kDeprecateUnload},
                                  /*disabled_features=*/{});
    std::unique_ptr<PermissionsPolicy> policy =
        CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
    EXPECT_EQ(PermissionsPolicyFeatureDefault::EnableForNone,
              GetPermissionsPolicyFeatureList(origin_a_)
                  .find(mojom::PermissionsPolicyFeature::kUnload)
                  ->second);
  }
}

blink::PermissionsPolicyFeatureDefault GetDefaultForUnload(
    const url::Origin& origin) {
  return GetPermissionsPolicyFeatureList(origin)
      .find(mojom::PermissionsPolicyFeature::kUnload)
      ->second;
}

// Test that for a given URL and rollout-percent, that all buckets get the
// correct fraction of EnabledForNone vs EnableForAll.
TEST_F(PermissionsPolicyTest, GetPermissionsPolicyFeatureListForUnload) {
  const url::Origin origin = url::Origin::Create(GURL("http://testing/"));
  int total_count = 0;
  for (int percent = 0; percent < 100; percent++) {
    SCOPED_TRACE(base::StringPrintf("percent=%d", percent));
    // Will count how many case result in EnableForNone.
    int count = 0;
    for (int bucket = 0; bucket < 100; bucket++) {
      SCOPED_TRACE(base::StringPrintf("bucket=%d", bucket));
      base::test::ScopedFeatureList feature_list;
      feature_list.InitWithFeaturesAndParameters(
          {{blink::features::kDeprecateUnload,
            {{features::kDeprecateUnloadPercent.name,
              base::StringPrintf("%d", percent)},
             {features::kDeprecateUnloadBucket.name,
              base::StringPrintf("%d", bucket)}}}},
          /*disabled_features=*/{});
      const PermissionsPolicyFeatureDefault unload_default =
          GetDefaultForUnload(origin);
      ASSERT_EQ(GetDefaultForUnload(origin.DeriveNewOpaqueOrigin()),
                unload_default);
      if (unload_default == PermissionsPolicyFeatureDefault::EnableForNone) {
        count++;
      } else {
        ASSERT_EQ(unload_default,
                  PermissionsPolicyFeatureDefault::EnableForAll);
      }
    }
    // Because the bucket is used as salt, the percentage of users who see
    // EnableForNone for a given site is not exactly equal to `percent`. All we
    // can do is make sure it is close.
    // If we change the hashing this might need updating but it should not be
    // different run-to-run.
    ASSERT_NEAR(count, percent, 6);
    total_count += count;
  }
  ASSERT_NEAR(total_count, 99 * 100 / 2, 71);
}

// Test that parameter parsing works.
TEST_F(PermissionsPolicyTest, UnloadDeprecationAllowedHosts) {
  EXPECT_EQ(std::unordered_set<std::string>({}),
            UnloadDeprecationAllowedHosts());

  // Now set the parameter and try again.
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeaturesAndParameters(
      {{blink::features::kDeprecateUnloadByAllowList,
        {{features::kDeprecateUnloadAllowlist.name, "testing1,testing2"}}}},
      /*disabled_features=*/{});

  EXPECT_EQ(std::unordered_set<std::string>({"testing1", "testing2"}),
            UnloadDeprecationAllowedHosts());
}

// Test that parameter parsing handles empty hosts.
TEST_F(PermissionsPolicyTest, UnloadDeprecationAllowedHostsEmpty) {
  EXPECT_EQ(std::unordered_set<std::string>({}),
            UnloadDeprecationAllowedHosts());

  // Now set the parameter and try again.
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeaturesAndParameters(
      {{blink::features::kDeprecateUnloadByAllowList,
        {{features::kDeprecateUnloadAllowlist.name,
          "testing1,, testing2,testing1"}}}},
      /*disabled_features=*/{});

  EXPECT_EQ(std::unordered_set<std::string>({"testing1", "testing2"}),
            UnloadDeprecationAllowedHosts());
}

// Test that the UnloadDeprecationAllowedForHost works correctly with
// an empty and a non-empty allowlist.
TEST_F(PermissionsPolicyTest, UnloadDeprecationAllowedForHostHostLists) {
  const url::Origin http_origin1 =
      url::Origin::Create(GURL("http://testing1/"));
  const url::Origin https_origin1 =
      url::Origin::Create(GURL("https://testing1/"));
  const url::Origin http_origin2 =
      url::Origin::Create(GURL("http://testing2/"));
  const url::Origin https_origin2 =
      url::Origin::Create(GURL("https://testing2/"));
  const url::Origin http_origin3 =
      url::Origin::Create(GURL("http://testing3/"));
  const url::Origin https_origin3 =
      url::Origin::Create(GURL("https://testing3/"));

  {
    const auto hosts = UnloadDeprecationAllowedHosts();
    // With no allowlist, every origin is allowed.
    EXPECT_TRUE(UnloadDeprecationAllowedForHost(http_origin1.host(), hosts));
    EXPECT_TRUE(UnloadDeprecationAllowedForHost(https_origin1.host(), hosts));
    EXPECT_TRUE(UnloadDeprecationAllowedForHost(http_origin2.host(), hosts));
    EXPECT_TRUE(UnloadDeprecationAllowedForHost(https_origin2.host(), hosts));
    EXPECT_TRUE(UnloadDeprecationAllowedForHost(http_origin3.host(), hosts));
    EXPECT_TRUE(UnloadDeprecationAllowedForHost(https_origin3.host(), hosts));
  }

  // Now set an allowlist and check that only the allowed domains see
  // deprecation.
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitWithFeaturesAndParameters(
        {{blink::features::kDeprecateUnloadByAllowList,
          {{features::kDeprecateUnloadAllowlist.name, "testing1,testing2"}}}},
        /*disabled_features=*/{});

    const auto hosts = UnloadDeprecationAllowedHosts();
    EXPECT_TRUE(UnloadDeprecationAllowedForHost(http_origin1.host(), hosts));
    EXPECT_TRUE(UnloadDeprecationAllowedForHost(https_origin1.host(), hosts));
    EXPECT_TRUE(UnloadDeprecationAllowedForHost(http_origin2.host(), hosts));
    EXPECT_TRUE(UnloadDeprecationAllowedForHost(https_origin2.host(), hosts));
    EXPECT_FALSE(UnloadDeprecationAllowedForHost(http_origin3.host(), hosts));
    EXPECT_FALSE(UnloadDeprecationAllowedForHost(https_origin3.host(), hosts));
  }
}

TEST_F(PermissionsPolicyTest, UnloadDeprecationAllowedForOrigin_NonHttp) {
  const url::Origin chrome_origin =
      url::Origin::Create(GURL("chrome://settings"));
  EXPECT_FALSE(UnloadDeprecationAllowedForOrigin(chrome_origin));
  EXPECT_FALSE(
      UnloadDeprecationAllowedForOrigin(chrome_origin.DeriveNewOpaqueOrigin()));
}

TEST_F(PermissionsPolicyTest,
       UnloadDeprecationAllowedForOrigin_GradualRollout) {
  const url::Origin testing_origin =
      url::Origin::Create(GURL("http://testing"));
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitWithFeaturesAndParameters(
        {{blink::features::kDeprecateUnload,
          {{features::kDeprecateUnloadPercent.name, "0"},
           {features::kDeprecateUnloadBucket.name, "0"}}}},
        /*disabled_features=*/{});
    EXPECT_FALSE(UnloadDeprecationAllowedForOrigin(testing_origin));
    EXPECT_FALSE(UnloadDeprecationAllowedForOrigin(
        testing_origin.DeriveNewOpaqueOrigin()));
  }
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitWithFeaturesAndParameters(
        {{blink::features::kDeprecateUnload,
          {{features::kDeprecateUnloadPercent.name, "100"},
           {features::kDeprecateUnloadBucket.name, "0"}}}},
        /*disabled_features=*/{});
    EXPECT_TRUE(UnloadDeprecationAllowedForOrigin(testing_origin));
    EXPECT_TRUE(UnloadDeprecationAllowedForOrigin(
        testing_origin.DeriveNewOpaqueOrigin()));
  }
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitWithFeaturesAndParameters(
        {{blink::features::kDeprecateUnload,
          {{features::kDeprecateUnloadPercent.name, "100"},
           {features::kDeprecateUnloadBucket.name, "0"}}},
         {blink::features::kDeprecateUnloadByAllowList,
          {{features::kDeprecateUnloadAllowlist.name, "testing"}}}},
        /*disabled_features=*/{});
    EXPECT_TRUE(UnloadDeprecationAllowedForOrigin(testing_origin));
    EXPECT_TRUE(UnloadDeprecationAllowedForOrigin(
        testing_origin.DeriveNewOpaqueOrigin()));
    const url::Origin disallowed_testing_origin =
        url::Origin::Create(GURL("http://disallowed-testing"));
    EXPECT_FALSE(UnloadDeprecationAllowedForOrigin(disallowed_testing_origin));
  }
}
}  // namespace blink

"""


```