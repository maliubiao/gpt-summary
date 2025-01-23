Response: The user is asking for a summary of the functionality of the provided C++ code snippet, which is part of a unit test file for the Permissions Policy feature in the Chromium Blink engine.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Functionality:** The filename `permissions_policy_unittest.cc` strongly suggests that the code is testing the `PermissionsPolicy` class. The test function names like `ProposedTestAllowedCrossOriginChildPolicy`, `ProposedTestAllAllowedCrossOriginChildPolicy`, and `ProposedTestNestedPolicyPropagates` indicate that it's testing how permissions policies are applied and inherited in different scenarios, especially in nested browsing contexts (iframes).

2. **Analyze Test Cases Focusing on Policy Inheritance:**  The ASCII art diagrams in the initial test cases are key. They visually represent parent and child frames with different origins and Permissions Policy headers. The tests then use `CreateFromParentPolicy` and `CreateFromParentWithFramePolicy` to simulate the creation of `PermissionsPolicy` objects for these frames. The `EXPECT_TRUE` and `EXPECT_FALSE` calls check if a particular feature (`kDefaultSelfFeature`) is enabled or disabled in the child frames, based on the parent's policy and the child frame's `allow` attribute. This points to the core functionality being about testing the correct inheritance and application of permissions policies in cross-origin iframes.

3. **Identify Tests for Specific Scenarios:**  Look for test functions with names that suggest specific use cases or policy types. `CreateFlexibleForFencedFrame`, `CreateForFledgeFencedFrame`, and `CreateForSharedStorageFencedFrame` clearly test the creation of specialized policies for fenced frames, a security feature in Chromium. These tests verify which features are enabled by default for these frame types.

4. **Examine Tests for Policy Creation and Manipulation:** `CreateFromParsedPolicy` tests the creation of a policy directly from a structured data representation. `OverwriteHeaderPolicyForClientHints` tests the ability to modify or set specific policies related to Client Hints. `GetAllowlistForFeatureIfExists` verifies the retrieval of the allowed origins for a specific feature.

5. **Analyze Tests Related to Feature Defaults and Configuration:**  The tests involving `kDeprecateUnload` explore how feature defaults are configured and potentially controlled by feature flags. The tests with `ScopedFeatureList` and parameters demonstrate how to influence these defaults, especially for features undergoing deprecation.

6. **Synthesize the Findings:** Combine the observations from steps 2-5 to formulate a comprehensive summary. Start with the general purpose of the file and then detail the specific areas being tested.

7. **Address Specific Questions in the Prompt:**  Actively look for connections to JavaScript, HTML, and CSS. In this case, the "allow" attribute mentioned in the test setup directly relates to the HTML `<iframe>` tag. The Permissions Policy itself is typically set via HTTP headers, which influence how web pages behave. While not directly manipulating JavaScript or CSS, the Permissions Policy dictates what browser features these technologies can access. Provide concrete examples based on the code.

8. **Identify Logical Reasoning and Provide Examples:** The tests involving parent-child policy inheritance demonstrate logical reasoning. For example, if a parent policy allows a feature for "OriginB" and a child frame from "OriginB" has `<allow="default-self *">`, the test verifies if the feature is enabled. This showcases the interaction between header policies and the `allow` attribute. Construct explicit input/output scenarios based on the test setups.

9. **Look for Common Usage Errors:**  The `EXPECT_DCHECK_DEATH` in `OverwriteHeaderPolicyForClientHints` highlights a potential programming error: trying to overwrite a non-Client-Hint header using a Client-Hint specific method. This is a good example of a usage error that the tests are designed to catch.

10. **Structure the Summary:** Organize the information logically, starting with a general overview and then drilling down into specific functionalities. Use clear and concise language.

By following these steps, we can generate a detailed and accurate summary of the `permissions_policy_unittest.cc` file, addressing all the points raised in the user's prompt.
这是名为 `permissions_policy_unittest.cc` 的 Chromium Blink 引擎源代码文件的第三部分，延续了前两部分的功能，主要用于测试 Blink 引擎中权限策略 (Permissions Policy) 的相关功能。

**归纳一下它的功能：**

这部分代码延续了测试权限策略的核心功能，着重于以下几个方面：

1. **验证提议的权限策略变更对跨域子框架的影响 (Proposed Policy Changes for Cross-Origin Child Frames):**  这部分测试用例验证了一个重要的提议变更：即使父文档的 HTTP 头允许某个功能在特定源或所有源上使用，子框架的 `allow` 属性仍然需要显式授予该功能，才能在子框架中启用。这与现有的算法有所不同，尤其是在子框架策略没有明确提及该功能的情况下。

2. **测试提议的策略在嵌套框架中的传播 (Nested Policy Propagation):**  这部分测试确保了提议的权限策略变更能够正确地向下传播到框架树中。即使在与策略变更发生地不同的框架中测试某个功能，也能反映出策略的变更。

3. **测试为 Fenced Frames 创建灵活和固定的权限策略 (Policy Creation for Fenced Frames):** 这部分测试针对 Fenced Frames 这种特殊的嵌入式内容形式，测试了创建权限策略的特定方法。`CreateFlexibleForFencedFrame` 创建一个更宽松的策略，而 `CreateFixedForFencedFrame` 则创建具有预定义启用权限的策略，例如针对 FLEDGE 和 Shared Storage Fenced Frames。

4. **测试从已解析的策略数据创建权限策略 (Creating Policy from Parsed Data):**  `CreateFromParsedPolicy` 测试了直接从已解析的权限策略数据结构创建 `PermissionsPolicy` 对象的能力。这允许更灵活地构造和测试策略。

5. **测试覆盖 Client Hints 的 HTTP 头策略 (Overwriting Header Policy for Client Hints):** 这部分测试验证了可以创建、设置或覆盖与 Client Hints 相关的权限策略。它还检查了是否能够用禁用状态的策略覆盖启用状态的策略，并验证了不能覆盖非 Client Hints 相关的头部策略。

6. **测试获取特定功能的允许列表 (Getting Allowlist for a Feature):** `GetAllowlistForFeatureIfExists` 测试了获取已设置的特定权限策略功能的允许源列表的能力。

7. **测试 `unload` 事件的默认行为是否受弃用标志控制 (Unload Event Default Behavior and Deprecation):** 这部分测试关注 `unload` 事件的权限策略，并验证其默认启用状态是否受名为 `kDeprecateUnload` 的实验性功能标志控制。它还测试了基于允许列表控制 `unload` 事件弃用的功能。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:**
    * **`<iframe>` 标签的 `allow` 属性:**  在 "验证提议的权限策略变更对跨域子框架的影响" 的测试中，`<iframe>` 标签的 `allow` 属性被用来显式地授予子框架特定的功能。例如：
      ```html
      <iframe src="originB.com" allow="default-self 'self'"></iframe>
      ```
      这里的 `allow="default-self 'self'"` 指示该 iframe 允许自身源使用 `default-self` 功能。
    * **Fenced Frames:**  `CreateFlexibleForFencedFrame` 和 `CreateFixedForFencedFrame` 测试直接关系到 HTML 中 `<fencedframe>` 标签的行为，权限策略决定了 fenced frame 内部可以使用的浏览器功能。

* **JavaScript:**
    * **权限策略限制 JavaScript API 的访问:**  权限策略最终会影响到 JavaScript 代码能否成功调用某些浏览器 API。例如，如果某个策略禁止了地理位置 API，那么页面中的 JavaScript 代码尝试使用 `navigator.geolocation` 将会失败。

* **CSS:**
    * **间接影响通过 JavaScript 控制的 CSS:** 虽然权限策略不直接控制 CSS 属性，但如果 JavaScript 代码被权限策略限制，那么通过 JavaScript 动态修改 CSS 的能力也会受到影响。

**逻辑推理的假设输入与输出:**

**假设输入 (针对 `ProposedTestAllowedCrossOriginChildPolicy`):**

* **父文档 (Origin A) 的 HTTP 头:** `Permissions-Policy: default-self=(self "OriginB")`
* **子框架 (Origin B) 的 `allow` 属性 (policy4):** `allow="default-self *"`
* **预期输出 (policy4->IsFeatureEnabled(kDefaultSelfFeature)):** `true`

**推理过程:**

1. 父文档允许自身源 (Origin A) 和 Origin B 使用 `default-self` 功能。
2. 子框架 (policy4) 的 `allow` 属性显式允许所有源 (`*`) 使用 `default-self` 功能。
3. 由于父文档和子框架都允许 Origin B 使用该功能，因此该功能在子框架中被启用。

**用户或编程常见的使用错误举例说明:**

* **忘记在子框架的 `allow` 属性中显式授予权限:** 在提议的策略变更下，一个常见的错误是假设如果父文档允许某个功能，子框架就可以自动使用。例如，在 `ProposedTestAllowedCrossOriginChildPolicy` 中，如果子框架 (3) Origin B 没有 `allow` 属性，即使父文档允许 Origin B 使用 `default-self`，该功能在子框架中仍然会被禁用。这是对新策略理解不足造成的。

* **尝试使用 Client Hints 相关的方法覆盖非 Client Hints 策略:**  `OverwriteHeaderPolicyForClientHints` 测试中，尝试使用 `WithClientHints` 方法来修改 `kDefaultSelfFeature` 的策略会导致 `DCHECK` 失败。这是一个编程错误，因为 `WithClientHints` 应该只用于修改 Client Hints 相关的策略。

总而言之，这部分测试代码专注于验证 Chromium Blink 引擎中权限策略在复杂场景下的行为，特别是针对跨域 iframe 和新的策略提案。它涵盖了策略的继承、传播、以及针对特定类型内容（如 Fenced Frames）的策略创建，并关注了如何通过功能标志控制特定功能的默认行为。 这些测试确保了权限策略能够有效地限制 Web 功能的使用，从而提高 Web 安全性和用户隐私。

### 提示词
```
这是目录为blink/common/permissions_policy/permissions_policy_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
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
```