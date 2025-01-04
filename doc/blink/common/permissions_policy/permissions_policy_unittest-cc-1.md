Response: The user wants to understand the functionality of the provided C++ code snippet, which is part of a unit test file for the Permissions Policy feature in the Chromium Blink engine.

Here's a breakdown of the thought process to analyze the code and fulfill the user's request:

1. **Identify the core purpose:** The file is a unit test (`*_unittest.cc`). This means its primary function is to test the behavior of a specific piece of code. In this case, it's testing the `PermissionsPolicy` class.

2. **Recognize the testing methodology:** The code uses the `TEST_F` macro, which indicates the use of Google Test framework. Each `TEST_F` block defines an individual test case.

3. **Analyze individual test cases:**  Each test case sets up a scenario involving different origins (A, B, C), permissions policies (defined in headers or via the `allow` attribute on `<iframe>` tags), and then asserts whether a specific feature (`kDefaultSelfFeature`, `kDefaultOnFeature`, etc.) is enabled for a given origin.

4. **Look for patterns in the test scenarios:**  Notice how many tests involve nested `<iframe>` structures. This suggests the tests are heavily focused on how permissions policies are inherited and modified across frame boundaries.

5. **Connect to web technologies (JavaScript, HTML, CSS):**  Permissions Policy is directly related to web security and controls the availability of certain browser features.
    * **HTML:** The `<iframe>` tag's `allow` attribute is explicitly used in the tests to define frame-level policies.
    * **HTTP Headers:**  The `Permissions-Policy` HTTP header is mentioned and simulated in the test setup.
    * **JavaScript:** While not directly present in this C++ test file, the features being tested (like camera access, microphone access, etc.) are often accessed and controlled via JavaScript APIs in a real web page.

6. **Infer functionality from the test names and assertions:** Test names like `TestDefaultSelfDelegatedToSameOriginFrame`, `TestDefaultOnCanBeDisabledByFramePolicy`, `TestFeatureDeclinedAtTopLevel`, etc., clearly indicate what aspect of the `PermissionsPolicy` is being tested. The `EXPECT_TRUE` and `EXPECT_FALSE` statements confirm the expected behavior.

7. **Identify logical reasoning:** The tests often involve creating a parent policy and then deriving child policies based on header policies and frame policies. The assertions then check if the feature is enabled or disabled based on the combination of these policies. This is where the "logical reasoning" comes in – how the policy inheritance and merging work.

8. **Identify potential user/programming errors:**  The tests implicitly demonstrate common mistakes. For instance, a developer might expect a feature to be enabled in a child frame because of the `allow` attribute, but the parent policy might block it. Or, they might misunderstand how default-on features can be disabled.

9. **Address the "assumptions and outputs" for logical reasoning:**  For each test case, the setup defines the "input" (parent policy, frame policy, origins). The `EXPECT_TRUE`/`EXPECT_FALSE` statements define the expected "output" (whether a feature is enabled for a given origin).

10. **Synthesize the functionality:** Combine the observations from the individual test cases to summarize the overall functionality being tested. The key aspects are policy inheritance, frame policy overrides, handling of default features, and the interaction between header policies and frame policies.

11. **Address the specific request for part 2:** The user explicitly asks for a summary of the functionality covered in this specific code snippet (part 2). This requires focusing on the tests present in this section and avoiding drawing conclusions based on knowledge of the entire file.

12. **Refine the summary:** Ensure the summary is clear, concise, and directly addresses the user's request. Use examples to illustrate the concepts and connect them to web technologies.

By following these steps, we can effectively analyze the C++ unit test code and provide a comprehensive answer to the user's question.
好的，让我们分析一下这个代码片段的功能。

**功能归纳：**

这段代码是 `blink/common/permissions_policy/permissions_policy_unittest.cc` 文件的一部分，主要功能是**测试 `PermissionsPolicy` 类的在各种场景下的行为，特别是涉及到 iframe 的权限策略继承和覆盖的情况**。 它专注于测试以下几个核心概念：

* **默认开启的 Feature (Default-on Feature):**  测试了默认情况下开启的 feature 如何被父级策略和 iframe 的 `allow` 属性影响。
* **默认自身 Feature (Default-self Feature):** 测试了只能由自身 origin 启用的 feature 如何在 iframe 中被继承和覆盖。
* **父级策略对子级策略的影响：**  验证了父级的 Permissions Policy 如何限制子级 iframe 的权限，即使子级 iframe 通过 `allow` 属性声明了不同的策略。
* **iframe 的 `allow` 属性的作用：** 测试了 `allow` 属性如何修改从父级继承下来的权限策略。
* **沙箱 (Sandbox) 环境下的权限策略：**  专门测试了在 `sandbox` 属性的 iframe 中，权限策略的行为，包括如何通过 `allow` 属性放开沙箱的限制。
* **未定义 Feature 的处理：**  验证了当 iframe 的 `allow` 属性中包含未定义的 feature 时，会被忽略。
* **针对子资源请求的权限策略 (Proposed Algorithm Change):** 这部分测试了当发起子资源请求时，如何根据请求中携带的特定标识 (例如 `browsingTopics` 和 `sharedStorageWritable`) 来判断是否允许访问相应的 feature。这涉及到提案中的算法变更。

**与 JavaScript, HTML, CSS 的关系和举例说明：**

这段 C++ 代码虽然本身不是 JavaScript, HTML 或 CSS，但它测试的 `PermissionsPolicy` 类直接影响这些技术的功能。

* **HTML (iframe 标签和 `allow` 属性):**
    * 代码中大量使用了模拟的 iframe 场景，通过 `CreateFromParentWithFramePolicy` 函数来模拟 iframe 的创建，并使用 `frame_policy` 来模拟 `allow` 属性的效果。
    * **举例：**  在 `TEST_F(PermissionsPolicyTest, TestDefaultOnCanBeDisabledByFramePolicy)` 中，模拟了如下 HTML 结构：
      ```html
      <iframe allow="default-on 'none'"></iframe>
      ```
      这个 `allow="default-on 'none'"`  指示这个 iframe 禁用了 `default-on` feature。测试代码验证了在父级允许 `default-on` 的情况下，子 iframe 正确地禁用了它。

* **HTTP Header (`Permissions-Policy`):**
    * 代码使用 `header_policy` 参数来模拟 HTTP 响应头中的 `Permissions-Policy`。
    * **举例：** 在 `TEST_F(PermissionsPolicyTest, TestFramePolicyModifiesHeaderPolicy)` 中，模拟了父级拥有如下 HTTP 头：
      ```
      Permissions-Policy: default-self=(self "OriginB")
      ```
      这意味着父级允许自身 (Origin A) 和 Origin B 使用 `default-self` feature。然后，测试代码验证了即使父级 HTTP 头允许，子 iframe 通过 `allow="default-self 'none'"` 仍然可以禁用该 feature。

* **JavaScript (间接关系):**
    * Permissions Policy 最终会影响 JavaScript API 的可用性。例如，如果某个 feature (如摄像头访问) 被 Permissions Policy 禁用，那么相应的 JavaScript API (如 `navigator.mediaDevices.getUserMedia()`) 将无法使用或会抛出错误。
    * **虽然代码中没有直接的 JavaScript 代码，但它测试的逻辑决定了 JavaScript 在运行时的行为。**

**逻辑推理的假设输入与输出：**

让我们以 `TEST_F(PermissionsPolicyTest, TestDefaultSelfDelegatedToSameOriginFrame)` 这个测试为例：

* **假设输入:**
    * **父级 Origin (Origin A):** 没有设置任何 Permissions Policy HTTP 头。
    * **子级 Origin (Origin A):**  与父级相同。
    * **iframe `allow` 属性:**  `allow="default-self"`

* **逻辑推理:**
    1. 父级没有设置 `default-self`，所以默认情况下父级自身可以使用 `default-self` feature。
    2. 因为子级是同源的，并且 iframe 的 `allow="default-self"` 允许了该 feature，所以子级也应该可以使用 `default-self` feature。

* **预期输出:**
    * `policy2->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_a_)` 返回 `true`。

**用户或编程常见的使用错误举例：**

* **误解 `allow` 属性的覆盖性：**  开发者可能认为只要在 iframe 的 `allow` 属性中声明了某个 feature，该 feature 就一定会被启用。但实际上，父级的 Permissions Policy 可能会限制该 feature 的可用性。
    * **举例：**  `TEST_F(PermissionsPolicyTest, TestFeatureDeclinedAtTopLevel)`  演示了这种情况。即使子 iframe 使用 `allow="default-self OriginB"` 或 `allow="default-self *"` 尝试启用 `default-self`，但由于顶级父 frame 的 Permissions Policy 设置了 `default-self=()` (禁用)，子 iframe 仍然无法使用该 feature。

* **忘记默认开启的 Feature 可以被禁用：** 开发者可能假设某些默认开启的 feature (如 `default-on`) 在任何情况下都可用，但实际上可以通过父级策略或 iframe 的 `allow` 属性禁用。
    * **举例：** `TEST_F(PermissionsPolicyTest, TestDefaultOnCanBeDisabledByFramePolicy)` 展示了如何使用 `allow="default-on 'none'"` 来禁用默认开启的 feature。

* **在沙箱环境中使用未被允许的 Feature：**  开发者可能在使用了 `sandbox` 属性的 iframe 中尝试使用某些 feature，而没有通过 `allow` 属性显式地允许它们。
    * **举例：** `TEST_F(PermissionsPolicyTest, TestDefaultSandboxedFramePolicy)`  展示了在默认的沙箱 iframe 中，除了 `default-on` 之外的大部分 feature 都是被禁用的。开发者需要使用 `allow` 属性来放开特定的 feature。

**总结这段代码的功能 (作为第 2 部分):**

作为 `blink/common/permissions_policy/permissions_policy_unittest.cc` 的第二部分，这段代码主要集中于**测试 `PermissionsPolicy` 类在处理 iframe 权限策略继承和覆盖时的行为**。它详细验证了默认开启和默认自身类型的 feature 如何受到父级策略和 iframe `allow` 属性的影响。此外，它还测试了沙箱环境下的权限策略以及如何处理未定义的 feature。这部分测试用例旨在确保 `PermissionsPolicy` 类能够正确地管理和控制跨 frame 的权限，并防止常见的配置错误。 特别值得注意的是，这部分代码也开始测试一些提案中的针对子资源请求的权限策略算法变更。

Prompt: 
```
这是目录为blink/common/permissions_policy/permissions_policy_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
efaultSelfFeature, /*allowed_origins=*/
       {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
           origin_c_,
           /*has_subdomain_wildcard=*/false)},
       /*self_if_matches=*/std::nullopt,
       /*matches_all_origins=*/false,
       /*matches_opaque_src=*/false},
  }};
  std::unique_ptr<PermissionsPolicy> policy3 = CreateFromParentWithFramePolicy(
      policy2.get(), /*header_policy=*/{}, frame_policy2, origin_c_);
  std::unique_ptr<PermissionsPolicy> policy4 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_c_);
  EXPECT_TRUE(
      policy1->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_a_));
  EXPECT_TRUE(
      policy2->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_b_));
  EXPECT_TRUE(
      policy3->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_c_));
  EXPECT_FALSE(
      policy4->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_c_));
}

TEST_F(PermissionsPolicyTest, TestDefaultOnCanBeDisabledByFramePolicy) {
  // +-----------------------------------+
  // |(1)Origin A                        |
  // |No Policy                          |
  // |                                   |
  // |<iframe allow="default-on 'none'"> |
  // | +-------------+                   |
  // | |(2)Origin A  |                   |
  // | |No Policy    |                   |
  // | +-------------+                   |
  // |                                   |
  // |<iframe allow="default-on 'none'"> |
  // | +-------------+                   |
  // | |(3)Origin B  |                   |
  // | |No Policy    |                   |
  // | +-------------+                   |
  // +-----------------------------------+
  // Default-on feature should be disabled in both same-origin and cross-origin
  // child frames because permission was removed through frame policy.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  ParsedPermissionsPolicy frame_policy1 = {
      {{kDefaultOnFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy1, origin_a_);
  ParsedPermissionsPolicy frame_policy2 = {
      {{kDefaultOnFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy3 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy2, origin_b_);
  EXPECT_TRUE(policy1->IsFeatureEnabledForOrigin(kDefaultOnFeature, origin_a_));
  EXPECT_TRUE(policy1->IsFeatureEnabledForOrigin(kDefaultOnFeature, origin_b_));
  EXPECT_TRUE(policy1->IsFeatureEnabledForOrigin(kDefaultOnFeature, origin_c_));
  EXPECT_FALSE(
      policy2->IsFeatureEnabledForOrigin(kDefaultOnFeature, origin_a_));
  EXPECT_FALSE(
      policy2->IsFeatureEnabledForOrigin(kDefaultOnFeature, origin_b_));
  EXPECT_FALSE(
      policy2->IsFeatureEnabledForOrigin(kDefaultOnFeature, origin_c_));
  EXPECT_FALSE(
      policy3->IsFeatureEnabledForOrigin(kDefaultOnFeature, origin_a_));
  EXPECT_FALSE(
      policy3->IsFeatureEnabledForOrigin(kDefaultOnFeature, origin_b_));
  EXPECT_FALSE(
      policy3->IsFeatureEnabledForOrigin(kDefaultOnFeature, origin_c_));
}

TEST_F(PermissionsPolicyTest, TestFramePolicyModifiesHeaderPolicy) {
  // +-------------------------------------------------+
  // |(1)Origin A                                      |
  // |Permissions-Policy: default-self=(self "OriginB")|
  // |                                                 |
  // |<iframe allow="default-self 'none'">             |
  // | +-----------------------------------------+     |
  // | |(2)Origin B                              |     |
  // | |No Policy                                |     |
  // | +-----------------------------------------+     |
  // |                                                 |
  // |<iframe allow="default-self 'none'">             |
  // | +-----------------------------------------+     |
  // | |(3)Origin B                              |     |
  // | |Permissions-Policy: default-self=self    |     |
  // | +-----------------------------------------+     |
  // +-------------------------------------------------+
  // Default-self feature should be disabled in both cross-origin child frames
  // by frame policy, even though the parent frame's header policy would
  // otherwise enable it. This is true regardless of the child frame's header
  // policy.
  std::unique_ptr<PermissionsPolicy> policy1 = CreateFromParentPolicy(
      nullptr,
      {{
          {kDefaultSelfFeature, /*allowed_origins=*/
           {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
               origin_b_,
               /*has_subdomain_wildcard=*/false)},
           /*self_if_matches=*/origin_a_,
           /*matches_all_origins=*/false,
           /*matches_opaque_src=*/false},
      }},
      origin_a_);
  ParsedPermissionsPolicy frame_policy1 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy1, origin_b_);
  ParsedPermissionsPolicy frame_policy2 = {{
      {kDefaultSelfFeature, /*allowed_origins=*/{},
       /*self_if_matches=*/std::nullopt,
       /*matches_all_origins=*/false,
       /*matches_opaque_src=*/false},
  }};
  std::unique_ptr<PermissionsPolicy> policy3 = CreateFromParentWithFramePolicy(
      policy1.get(),
      {{
          {kDefaultSelfFeature, /*allowed_origins=*/{},
           /*self_if_matches=*/origin_b_,
           /*matches_all_origins=*/false,
           /*matches_opaque_src=*/false},
      }},
      frame_policy2, origin_b_);
  EXPECT_FALSE(
      policy2->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_b_));
  EXPECT_FALSE(
      policy3->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_b_));
}

TEST_F(PermissionsPolicyTest, TestCombineFrameAndHeaderPolicies) {
  // +-----------------------------------------+
  // |(1)Origin A                              |
  // |No Policy                                |
  // |                                         |
  // |<iframe allow="default-self OriginB">    |
  // | +-------------------------------------+ |
  // | |(2)Origin B                          | |
  // | |Permissions-Policy: default-self=*   | |
  // | |                                     | |
  // | |<iframe allow="default-self 'none'"> | |
  // | | +-------------+                     | |
  // | | |(3)Origin C  |                     | |
  // | | |No Policy    |                     | |
  // | | +-------------+                     | |
  // | |                                     | |
  // | |<iframe> (No frame policy)           | |
  // | | +-------------+                     | |
  // | | |(4)Origin C  |                     | |
  // | | |No Policy    |                     | |
  // | | +-------------+                     | |
  // | +-------------------------------------+ |
  // +-----------------------------------------+
  // Default-self feature should be enabled in cross-origin child frames 2 and
  // 4. Feature should be disabled in frame 3 by frame policy.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  ParsedPermissionsPolicy frame_policy1 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
            origin_b_,
            /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(),
      {{{kDefaultSelfFeature, /*allowed_origins=*/{},
         /*self_if_matches=*/std::nullopt,
         /*matches_all_origins=*/true,
         /*matches_opaque_src=*/false}}},
      frame_policy1, origin_b_);
  ParsedPermissionsPolicy frame_policy2 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy3 = CreateFromParentWithFramePolicy(
      policy2.get(), /*header_policy=*/{}, frame_policy2, origin_c_);
  std::unique_ptr<PermissionsPolicy> policy4 =
      CreateFromParentPolicy(policy2.get(), /*header_policy=*/{}, origin_c_);
  EXPECT_TRUE(
      policy1->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_a_));
  EXPECT_TRUE(
      policy2->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_b_));
  EXPECT_FALSE(
      policy3->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_c_));
}

TEST_F(PermissionsPolicyTest, TestFeatureDeclinedAtTopLevel) {
  // +-----------------------------------------+
  // |(1)Origin A                              |
  // |Permissions-Policy: default-self=()      |
  // |                                         |
  // |<iframe allow="default-self OriginB">    |
  // | +-------------------------------------+ |
  // | |(2)Origin B                          | |
  // | |No Policy                            | |
  // | +-------------------------------------+ |
  // |                                         |
  // |<iframe allow="default-self *">          |
  // | +-------------------------------------+ |
  // | |(3)Origin A                          | |
  // | |No Policy                            | |
  // | +-------------------------------------+ |
  // +-----------------------------------------+
  // Default-self feature should be disabled in all frames.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{
                                 {kDefaultSelfFeature, /*allowed_origins=*/{},
                                  /*self_if_matches=*/std::nullopt,
                                  /*matches_all_origins=*/false,
                                  /*matches_opaque_src=*/false},
                             }},
                             origin_a_);
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
  ParsedPermissionsPolicy frame_policy2 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/true,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy3 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy2, origin_a_);
  EXPECT_FALSE(
      policy1->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_a_));
  EXPECT_FALSE(
      policy2->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_b_));
  EXPECT_FALSE(
      policy3->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_a_));
}

TEST_F(PermissionsPolicyTest, TestFeatureDelegatedAndAllowed) {
  // +--------------------------------------------------+
  // |(1)Origin A                                       |
  // |Permissions-Policy: default-self=(self "OriginB") |
  // |                                                  |
  // |<iframe allow="default-self OriginA">             |
  // | +-------------------------------------+          |
  // | |(2)Origin B                          |          |
  // | |No Policy                            |          |
  // | +-------------------------------------+          |
  // |                                                  |
  // |<iframe allow="default-self OriginB">             |
  // | +-------------------------------------+          |
  // | |(3)Origin B                          |          |
  // | |No Policy                            |          |
  // | +-------------------------------------+          |
  // |                                                  |
  // |<iframe allow="default-self *">                   |
  // | +-------------------------------------+          |
  // | |(4)Origin B                          |          |
  // | |No Policy                            |          |
  // | +-------------------------------------+          |
  // +--------------------------------------------------+
  // Default-self feature should be disabled in frame 2, as the origin does not
  // match, and enabled in the remaining frames.
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
  ParsedPermissionsPolicy frame_policy1 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
            origin_a_,
            /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy1, origin_b_);
  ParsedPermissionsPolicy frame_policy2 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
            origin_b_,
            /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy3 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy2, origin_b_);
  ParsedPermissionsPolicy frame_policy3 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/true,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy4 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy3, origin_b_);
  EXPECT_TRUE(
      policy1->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_a_));
  EXPECT_TRUE(
      policy1->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_b_));
  EXPECT_FALSE(
      policy2->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_a_));
  EXPECT_FALSE(
      policy2->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_b_));
  EXPECT_TRUE(
      policy3->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_b_));
  EXPECT_TRUE(
      policy4->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_b_));
}

TEST_F(PermissionsPolicyTest, TestDefaultSandboxedFramePolicy) {
  // +------------------+
  // |(1)Origin A       |
  // |No Policy         |
  // |                  |
  // |<iframe sandbox>  |
  // | +-------------+  |
  // | |(2)Sandboxed |  |
  // | |No Policy    |  |
  // | +-------------+  |
  // +------------------+
  // Default-on feature should be enabled in child frame with opaque origin.
  // Other features should be disabled.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  url::Origin sandboxed_origin = url::Origin();
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentPolicy(
      policy1.get(), /*header_policy=*/{}, sandboxed_origin);
  EXPECT_TRUE(policy2->IsFeatureEnabledForOrigin(kDefaultOnFeature, origin_a_));
  EXPECT_TRUE(
      policy2->IsFeatureEnabledForOrigin(kDefaultOnFeature, sandboxed_origin));
  EXPECT_FALSE(
      policy2->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_a_));
  EXPECT_FALSE(policy2->IsFeatureEnabledForOrigin(kDefaultSelfFeature,
                                                  sandboxed_origin));
}

TEST_F(PermissionsPolicyTest, TestSandboxedFramePolicyForAllOrigins) {
  // +----------------------------------------+
  // |(1)Origin A                             |
  // |No Policy                               |
  // |                                        |
  // |<iframe sandbox allow="default-self *"> |
  // | +-------------+                        |
  // | |(2)Sandboxed |                        |
  // | |No Policy    |                        |
  // | +-------------+                        |
  // +----------------------------------------+
  // Default-self feature should be enabled in child frame with opaque origin,
  // only for that origin, because container policy matches all origins.
  // However, it will not pass that on to any other origin
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  url::Origin sandboxed_origin = url::Origin();
  ParsedPermissionsPolicy frame_policy = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/true,
        /*matches_opaque_src=*/true}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy, sandboxed_origin);
  EXPECT_TRUE(policy2->IsFeatureEnabledForOrigin(kDefaultOnFeature, origin_a_));
  EXPECT_TRUE(
      policy2->IsFeatureEnabledForOrigin(kDefaultOnFeature, sandboxed_origin));
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_TRUE(policy2->IsFeatureEnabledForOrigin(kDefaultSelfFeature,
                                                 sandboxed_origin));
}

TEST_F(PermissionsPolicyTest, TestSandboxedFramePolicyForSelf) {
  // +-------------------------------------------+
  // |(1)Origin A                                |
  // |No Policy                                  |
  // |                                           |
  // |<iframe sandbox allow="default-self self"> |
  // | +-------------+                           |
  // | |(2)Sandboxed |                           |
  // | |No Policy    |                           |
  // | +-------------+                           |
  // +-------------------------------------------+
  // Default-self feature should be enabled in child frame with opaque origin,
  // only for that origin, because container policy matches all origins.
  // However, it will not pass that on to any other origin
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  url::Origin sandboxed_origin = url::Origin();
  ParsedPermissionsPolicy frame_policy = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/sandboxed_origin,
        /*matches_all_origins=*/true,
        /*matches_opaque_src=*/true}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy, sandboxed_origin);
  EXPECT_TRUE(policy2->IsFeatureEnabledForOrigin(kDefaultOnFeature, origin_a_));
  EXPECT_TRUE(
      policy2->IsFeatureEnabledForOrigin(kDefaultOnFeature, sandboxed_origin));
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_TRUE(policy2->IsFeatureEnabledForOrigin(kDefaultSelfFeature,
                                                 sandboxed_origin));
}

TEST_F(PermissionsPolicyTest, TestSandboxedFramePolicyForOpaqueSrcOrigin) {
  // +--------------------------------------+
  // |(1)Origin A                           |
  // |No Policy                             |
  // |                                      |
  // |<iframe sandbox allow="default-self"> |
  // | +-------------+                      |
  // | |(2)Sandboxed |                      |
  // | |No Policy    |                      |
  // | +-------------+                      |
  // +--------------------------------------+
  // Default-self feature should be enabled in child frame with opaque origin,
  // only for that origin, because container policy matches the opaque src.
  // However, it will not pass that on to any other origin
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  url::Origin sandboxed_origin = url::Origin();
  ParsedPermissionsPolicy frame_policy = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/true}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy, sandboxed_origin);
  EXPECT_TRUE(policy2->IsFeatureEnabledForOrigin(kDefaultOnFeature, origin_a_));
  EXPECT_TRUE(
      policy2->IsFeatureEnabledForOrigin(kDefaultOnFeature, sandboxed_origin));
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_TRUE(policy2->IsFeatureEnabledForOrigin(kDefaultSelfFeature,
                                                 sandboxed_origin));
}

TEST_F(PermissionsPolicyTest, TestSandboxedFrameFromHeaderPolicy) {
  // +--------------------------------------+
  // |(1)Origin A                           |
  // |Permissions-Policy: default-self=*    |
  // |                                      |
  // | +-------------+                      |
  // | |(2)Sandboxed |                      |
  // | |No Policy    |                      |
  // | +-------------+                      |
  // +--------------------------------------+
  // Default-self feature should not be enabled in child frame with opaque
  // origin, as it is cross-origin with its parent, and there is no container
  // policy.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultSelfFeature, /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/true,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  url::Origin sandboxed_origin = url::Origin();
  ParsedPermissionsPolicy frame_policy = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/true}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy, sandboxed_origin);
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(policy2->IsFeatureEnabledForOrigin(kDefaultSelfFeature,
                                                  sandboxed_origin));
}

TEST_F(PermissionsPolicyTest, TestSandboxedPolicyIsNotInherited) {
  // +----------------------------------------+
  // |(1)Origin A                             |
  // |No Policy                               |
  // |                                        |
  // |<iframe sandbox allow="default-self *"> |
  // | +------------------------------------+ |
  // | |(2)Sandboxed                        | |
  // | |No Policy                           | |
  // | |                                    | |
  // | | +-------------+                    | |
  // | | |(3)Sandboxed |                    | |
  // | | |No Policy    |                    | |
  // | | +-------------+                    | |
  // | +------------------------------------+ |
  // +----------------------------------------+
  // Default-on feature should be enabled in frame 3 with opaque origin, but all
  // other features should be disabled.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  url::Origin sandboxed_origin_1 = url::Origin();
  url::Origin sandboxed_origin_2 = url::Origin();
  ParsedPermissionsPolicy frame_policy = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/true,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy, sandboxed_origin_1);
  std::unique_ptr<PermissionsPolicy> policy3 = CreateFromParentPolicy(
      policy2.get(), /*header_policy=*/{}, sandboxed_origin_2);
  EXPECT_TRUE(policy3->IsFeatureEnabledForOrigin(kDefaultOnFeature, origin_a_));
  EXPECT_TRUE(policy3->IsFeatureEnabledForOrigin(kDefaultOnFeature,
                                                 sandboxed_origin_1));
  EXPECT_TRUE(policy3->IsFeatureEnabledForOrigin(kDefaultOnFeature,
                                                 sandboxed_origin_2));
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_FALSE(
      policy3->IsFeatureEnabledForOrigin(kDefaultSelfFeature, origin_a_));
  EXPECT_FALSE(policy3->IsFeatureEnabledForOrigin(kDefaultSelfFeature,
                                                  sandboxed_origin_1));
  EXPECT_FALSE(policy3->IsFeatureEnabledForOrigin(kDefaultSelfFeature,
                                                  sandboxed_origin_2));
}

TEST_F(PermissionsPolicyTest, TestSandboxedPolicyCanBePropagated) {
  // +--------------------------------------------+
  // |(1)Origin A                                 |
  // |No Policy                                   |
  // |                                            |
  // |<iframe sandbox allow="default-self *">     |
  // | +----------------------------------------+ |
  // | |(2)Sandboxed                            | |
  // | |No Policy                               | |
  // | |                                        | |
  // | |<iframe sandbox allow="default-self *"> | |
  // | | +-------------+                        | |
  // | | |(3)Sandboxed |                        | |
  // | | |No Policy    |                        | |
  // | | +-------------+                        | |
  // | +----------------------------------------+ |
  // +--------------------------------------------+
  // Default-self feature should be enabled in child frame with opaque origin,
  // only for that origin, because container policy matches all origins.
  // However, it will not pass that on to any other origin
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  url::Origin sandboxed_origin_1 = origin_a_.DeriveNewOpaqueOrigin();
  url::Origin sandboxed_origin_2 = sandboxed_origin_1.DeriveNewOpaqueOrigin();
  ParsedPermissionsPolicy frame_policy_1 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/true,
        /*matches_opaque_src=*/true}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy_1, sandboxed_origin_1);
  ParsedPermissionsPolicy frame_policy_2 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/true,
        /*matches_opaque_src=*/true}}};
  std::unique_ptr<PermissionsPolicy> policy3 = CreateFromParentWithFramePolicy(
      policy2.get(), /*header_policy=*/{}, frame_policy_2, sandboxed_origin_2);
  EXPECT_TRUE(policy3->IsFeatureEnabledForOrigin(kDefaultOnFeature, origin_a_));
  EXPECT_TRUE(policy3->IsFeatureEnabledForOrigin(kDefaultOnFeature,
                                                 sandboxed_origin_2));
  EXPECT_TRUE(policy3->IsFeatureEnabled(kDefaultSelfFeature));
  EXPECT_TRUE(policy3->IsFeatureEnabledForOrigin(kDefaultSelfFeature,
                                                 sandboxed_origin_2));
}

TEST_F(PermissionsPolicyTest, TestUndefinedFeaturesInFramePolicy) {
  // +---------------------------------------------------+
  // |(1)Origin A                                        |
  // |No Policy                                          |
  // |                                                   |
  // |<iframe allow="nosuchfeature; unavailablefeature"> |
  // | +-------------+                                   |
  // | |(2)Origin B  |                                   |
  // | |No Policy    |                                   |
  // | +-------------+                                   |
  // +---------------------------------------------------+
  // A feature which is not in the declared feature list should be ignored if
  // present in a container policy.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  ParsedPermissionsPolicy frame_policy = {
      {{mojom::PermissionsPolicyFeature::kNotFound, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/true},
       {kUnavailableFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/false,
        /*matches_opaque_src=*/true}}};
  std::unique_ptr<PermissionsPolicy> policy2 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy, origin_b_);
  EXPECT_FALSE(PolicyContainsInheritedValue(
      policy1.get(), mojom::PermissionsPolicyFeature::kNotFound));
  EXPECT_FALSE(
      PolicyContainsInheritedValue(policy1.get(), kUnavailableFeature));
  EXPECT_FALSE(PolicyContainsInheritedValue(
      policy2.get(), mojom::PermissionsPolicyFeature::kNotFound));
  EXPECT_FALSE(
      PolicyContainsInheritedValue(policy2.get(), kUnavailableFeature));
}

// Tests for proposed algorithm change in
// https://github.com/w3c/webappsec-permissions-policy/pull/499 to construct
// the policy for subresource request when there exists an equivalent and
// enabled opt-in flag for the request.

// A cross-origin subresource request that explicitly sets the browsingTopics
// flag should have the browsing-topics permission as long as it passes
// allowlist check, regardless of the feature's default state. Similarly for the
// sharedStorageWritable flag.
TEST_F(PermissionsPolicyTest,
       ProposedTestIsFeatureEnabledForSubresourceRequest) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      {blink::features::kBrowsingTopics, blink::features::kSharedStorageAPI},
      /*disabled_features=*/{});

  network::ResourceRequest request_without_any_opt_in;

  network::ResourceRequest request_with_topics_opt_in;
  request_with_topics_opt_in.browsing_topics = true;

  network::ResourceRequest request_with_shared_storage_opt_in;
  request_with_shared_storage_opt_in.shared_storage_writable_eligible = true;

  network::ResourceRequest request_with_both_opt_in;
  request_with_both_opt_in.browsing_topics = true;
  request_with_both_opt_in.shared_storage_writable_eligible = true;

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
        CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);

    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_a_,
        request_without_any_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_a_,
        request_with_topics_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_a_,
        request_with_both_opt_in));

    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_,
        request_without_any_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_,
        request_with_shared_storage_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_,
        request_with_both_opt_in));

    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_b_,
        request_without_any_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_b_,
        request_with_topics_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_b_,
        request_with_both_opt_in));

    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_,
        request_without_any_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_,
        request_with_shared_storage_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_,
        request_with_both_opt_in));
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
        {{{mojom::PermissionsPolicyFeature::kBrowsingTopics,
           /*allowed_origins=*/{},
           /*self_if_matches=*/origin_a_,
           /*matches_all_origins=*/false,
           /*matches_opaque_src=*/false},
          {mojom::PermissionsPolicyFeature::kSharedStorage,
           /*allowed_origins=*/{},
           /*self_if_matches=*/origin_a_,
           /*matches_all_origins=*/false,
           /*matches_opaque_src=*/false}}},
        origin_a_);

    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_a_,
        request_without_any_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_a_,
        request_with_topics_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_a_,
        request_with_both_opt_in));

    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_,
        request_without_any_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_,
        request_with_shared_storage_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_,
        request_with_both_opt_in));

    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_b_,
        request_without_any_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_b_,
        request_with_topics_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_b_,
        request_with_both_opt_in));

    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_,
        request_without_any_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_,
        request_with_shared_storage_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_,
        request_with_both_opt_in));
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
        {{{mojom::PermissionsPolicyFeature::kBrowsingTopics,
           /*allowed_origins=*/{},
           /*self_if_matches=*/std::nullopt,
           /*matches_all_origins=*/false,
           /*matches_opaque_src=*/false},
          {mojom::PermissionsPolicyFeature::kSharedStorage,
           /*allowed_origins=*/{},
           /*self_if_matches=*/std::nullopt,
           /*matches_all_origins=*/false,
           /*matches_opaque_src=*/false}}},
        origin_a_);

    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_a_,
        request_without_any_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_a_,
        request_with_topics_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_a_,
        request_with_both_opt_in));

    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_,
        request_without_any_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_,
        request_with_shared_storage_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_,
        request_with_both_opt_in));

    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_b_,
        request_without_any_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_b_,
        request_with_topics_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_b_,
        request_with_both_opt_in));

    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_,
        request_without_any_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_,
        request_with_shared_storage_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_,
        request_with_both_opt_in));
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
        {{{mojom::PermissionsPolicyFeature::kBrowsingTopics,
           /*allowed_origins=*/{},
           /*self_if_matches=*/std::nullopt,
           /*matches_all_origins=*/true,
           /*matches_opaque_src=*/false},
          {mojom::PermissionsPolicyFeature::kSharedStorage,
           /*allowed_origins=*/{},
           /*self_if_matches=*/std::nullopt,
           /*matches_all_origins=*/true,
           /*matches_opaque_src=*/false}}},
        origin_a_);

    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_a_,
        request_without_any_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_a_,
        request_with_topics_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_a_,
        request_with_both_opt_in));

    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_,
        request_without_any_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_,
        request_with_shared_storage_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_,
        request_with_both_opt_in));

    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_b_,
        request_without_any_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_b_,
        request_with_topics_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_b_,
        request_with_both_opt_in));

    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_,
        request_without_any_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_,
        request_with_shared_storage_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_,
        request_with_both_opt_in));
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
        {{{mojom::PermissionsPolicyFeature::
               kBrowsingTopics, /*allowed_origins=*/
           {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
               origin_b_,
               /*has_subdomain_wildcard=*/false)},
           /*self_if_matches=*/std::nullopt,
           /*matches_all_origins=*/false,
           /*matches_opaque_src=*/false},
          {mojom::PermissionsPolicyFeature::kSharedStorage, /*allowed_origins=*/
           {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
               origin_b_,
               /*has_subdomain_wildcard=*/false)},
           /*self_if_matches=*/std::nullopt,
           /*matches_all_origins=*/false,
           /*matches_opaque_src=*/false}}},
        origin_a_);

    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_a_,
        request_without_any_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_a_,
        request_with_topics_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_a_,
        request_with_both_opt_in));

    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_,
        request_without_any_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_,
        request_with_shared_storage_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_,
        request_with_both_opt_in));

    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_b_,
        request_without_any_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_b_,
        request_with_topics_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_b_,
        request_with_both_opt_in));

    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_,
        request_without_any_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_,
        request_with_shared_storage_opt_in));
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_,
        request_with_both_opt_in));

    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_c_,
        request_without_any_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_c_,
        request_with_topics_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_c_,
        request_with_both_opt_in));

    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_c_,
        request_without_any_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_c_,
        request_with_shared_storage_opt_in));
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_c_,
        request_with_both_opt_in));
  }
}

// A cross-origin subresource request that explicitly sets the
// sharedStorageWritable flag should have the Shared Storage permission as long
// as it passes the allowlist check, regardless of the feature's default state.
TEST_F(PermissionsPolicyTest,
       ProposedTestIsFeatureEnabledForSubresourceRequestAssumingOptIn) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures({blink::features::kSharedStorageAPI},
                                /*disabled_features=*/{});

  {
    // +--------------------------------------------------------+
    // |(1)Origin A                                             |
    // |No Policy                                               |
    // |                                                        |
    // | fetch(<Origin B's url>, {sharedStorageWritable: true}) |
    // +--------------------------------------------------------+

    std::unique_ptr<PermissionsPolicy> policy =
        CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);

    EXPECT_TRUE(policy->IsFeatureEnabledForOrigin(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_));
    EXPECT_TRUE(IsFeatureEnabledForSubresourceRequestAssumingOptIn(
        policy.get(), mojom::PermissionsPolicyFeature::kSharedStorage,
        origin_a_));

    EXPECT_FALSE(policy->IsFeatureEnabledForOrigin(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_));
    EXPECT_TRUE(IsFeatureEnabledForSubresourceRequestAssumingOptIn(
        policy.get(), mojom::PermissionsPolicyFeature::kSharedStorage,
        origin_b_));
  }

  {
    // +--------------------------------------------------------+
    // |(1)Origin A                                             |
    // |Permissions-Policy: shared-storage=(self)              |
    // |                                                        |
    // | fetch(<Origin B's url>, {sharedStorageWritable: true}) |
    // +--------------------------------------------------------+

    std::unique_ptr<PermissionsPolicy> policy = CreateFromParentPolicy(
        nullptr,
        {{{mojom::PermissionsPolicyFeature::kSharedStorage,
           /*allowed_origins=*/{},
           /*self_if_matches=*/origin_a_,
           /*matches_all_origins=*/false,
           /*matches_opaque_src=*/false}}},
        origin_a_);

    EXPECT_TRUE(policy->IsFeatureEnabledForOrigin(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_));
    EXPECT_TRUE(IsFeatureEnabledForSubresourceRequestAssumingOptIn(
        policy.get(), mojom::PermissionsPolicyFeature::kSharedStorage,
        origin_a_));

    EXPECT_FALSE(policy->IsFeatureEnabledForOrigin(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_));
    EXPECT_FALSE(IsFeatureEnabledForSubresourceRequestAssumingOptIn(
        policy.get(), mojom::PermissionsPolicyFeature::kSharedStorage,
        origin_b_));
  }

  {
    // +--------------------------------------------------------+
    // |(1)Origin A                                             |
    // |Permissions-Policy: shared-storage=(none)              |
    // |                                                        |
    // | fetch(<Origin B's url>, {sharedStorageWritable: true}) |
    // +--------------------------------------------------------+

    std::unique_ptr<PermissionsPolicy> policy = CreateFromParentPolicy(
        nullptr,
        {{{mojom::PermissionsPolicyFeature::kSharedStorage,
           /*allowed_origins=*/{},
           /*self_if_matches=*/std::nullopt,
           /*matches_all_origins=*/false,
           /*matches_opaque_src=*/false}}},
        origin_a_);

    EXPECT_FALSE(policy->IsFeatureEnabledForOrigin(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_));
    EXPECT_FALSE(IsFeatureEnabledForSubresourceRequestAssumingOptIn(
        policy.get(), mojom::PermissionsPolicyFeature::kSharedStorage,
        origin_a_));

    EXPECT_FALSE(policy->IsFeatureEnabledForOrigin(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_));
    EXPECT_FALSE(IsFeatureEnabledForSubresourceRequestAssumingOptIn(
        policy.get(), mojom::PermissionsPolicyFeature::kSharedStorage,
        origin_b_));
  }

  {
    // +--------------------------------------------------------+
    // |(1)Origin A                                             |
    // |Permissions-Policy: shared-storage=*                   |
    // |                                                        |
    // | fetch(<Origin B's url>, {sharedStorageWritable: true}) |
    // +--------------------------------------------------------+

    std::unique_ptr<PermissionsPolicy> policy = CreateFromParentPolicy(
        nullptr,
        {{{mojom::PermissionsPolicyFeature::kSharedStorage,
           /*allowed_origins=*/{},
           /*self_if_matches=*/std::nullopt,
           /*matches_all_origins=*/true,
           /*matches_opaque_src=*/false}}},
        origin_a_);

    EXPECT_TRUE(policy->IsFeatureEnabledForOrigin(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_));
    EXPECT_TRUE(IsFeatureEnabledForSubresourceRequestAssumingOptIn(
        policy.get(), mojom::PermissionsPolicyFeature::kSharedStorage,
        origin_a_));

    EXPECT_TRUE(policy->IsFeatureEnabledForOrigin(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_));
    EXPECT_TRUE(IsFeatureEnabledForSubresourceRequestAssumingOptIn(
        policy.get(), mojom::PermissionsPolicyFeature::kSharedStorage,
        origin_b_));
  }

  {
    // +--------------------------------------------------------+
    // |(1)Origin A                                             |
    // |Permissions-Policy: shared-storage=(Origin B)          |
    // |                                                        |
    // | fetch(<Origin B's url>, {sharedStorageWritable: true}) |
    // | fetch(<Origin C's url>, {sharedStorageWritable: true}) |
    // +--------------------------------------------------------+

    std::unique_ptr<PermissionsPolicy> policy = CreateFromParentPolicy(
        nullptr,
        {{{mojom::PermissionsPolicyFeature::kSharedStorage, /*allowed_origins=*/
           {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
               origin_b_,
               /*has_subdomain_wildcard=*/false)},
           /*self_if_matches=*/std::nullopt,
           /*matches_all_origins=*/false,
           /*matches_opaque_src=*/false}}},
        origin_a_);

    EXPECT_FALSE(policy->IsFeatureEnabledForOrigin(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_a_));
    EXPECT_FALSE(IsFeatureEnabledForSubresourceRequestAssumingOptIn(
        policy.get(), mojom::PermissionsPolicyFeature::kSharedStorage,
        origin_a_));

    EXPECT_TRUE(policy->IsFeatureEnabledForOrigin(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_b_));
    EXPECT_TRUE(IsFeatureEnabledForSubresourceRequestAssumingOptIn(
        policy.get(), mojom::PermissionsPolicyFeature::kSharedStorage,
        origin_b_));

    EXPECT_FALSE(policy->IsFeatureEnabledForOrigin(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_c_));
    EXPECT_FALSE(IsFeatureEnabledForSubresourceRequestAssumingOptIn(
        policy.get(), mojom::PermissionsPolicyFeature::kSharedStorage,
        origin_c_));
  }
}

// Tests for proposed algorithm change. These tests construct policies in
// various embedding scenarios, and verify that the proposed value for "should
// feature be allowed in the child frame" matches what we expect. The points
// where this differs from the current feature policy algorithm are called
// out specifically. See https://crbug.com/937131 for additional context.

TEST_F(PermissionsPolicyTest, ProposedTestImplicitPolicy) {
  // +-----------------+
  // |(1)Origin A      |
  // |No Policy        |
  // | +-------------+ |
  // | |(2)Origin A  | |
  // | |No Policy    | |
  // | +-------------+ |
  // | +-------------+ |
  // | |(3)Origin B  | |
  // | |No Policy    | |
  // | +-------------+ |
  // +-----------------+
  // With no policy specified at all, Default-on and Default-self features
  // should be enabled at the top-level, and in a same-origin child frame.
  // Default-self features should be disabled in a cross-origin child frame.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr, /*header_policy=*/{}, origin_a_);
  EXPECT_TRUE(policy1->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_TRUE(policy1->IsFeatureEnabled(kDefaultSelfFeature));

  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_a_);
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultSelfFeature));

  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_b_);
  EXPECT_TRUE(policy3->IsFeatureEnabled(kDefaultOnFeature));
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultSelfFeature));
}

TEST_F(PermissionsPolicyTest, ProposedTestCompletelyBlockedPolicy) {
  // +------------------------------------+
  // |(1)Origin A                         |
  // |Permissions-Policy: default-self=() |
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
  // When a feature is disabled in the parent frame, it should be disabled in
  // all child frames, regardless of any declared frame policies.
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultSelfFeature, /*allowed_origins=*/{},
                                /*self_if_matches=*/std::nullopt,
                                /*matches_all_origins=*/false,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);
  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_a_);
  EXPECT_FALSE(policy2->IsFeatureEnabled(kDefaultSelfFeature));

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
  EXPECT_FALSE(policy4->IsFeatureEnabled(kDefaultSelfFeature));

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
  EXPECT_FALSE(policy5->IsFeatureEnabled(kDefaultSelfFeature));

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

TEST_F(PermissionsPolicyTest, ProposedTestDisallowedCrossOriginChildPolicy) {
  // +--------------------------------------+
  // |(1)Origin A                           |
  // |Permissions-Policy: default-self=self |
  // | +--------------+  +--------------+   |
  // | |(2)Origin A   |  |(3)Origin B   |   |
  // | |No Policy     |  |No Policy     |   |
  // | +--------------+  +--------------+   |
  // | <allow="default-self *">             |
  // | +--------------+                     |
  // | |(4)Origin B   |                     |
  // | |No Policy     |                     |
  // | +--------------+                     |
  // | <allow="default-self OriginB">       |
  // | +--------------+                     |
  // | |(5)Origin B   |                     |
  // | |No Policy     |                     |
  // | +--------------+                     |
  // | <allow="default-self OriginB">       |
  // | +--------------+                     |
  // | |(6)Origin C   |                     |
  // | |No Policy     |                     |
  // | +--------------+                     |
  // +--------------------------------------+
  // When a feature is not explicitly enabled for an origin, it should be
  // disabled in any frame at that origin, regardless of the declared frame
  // policy. (This is different from the current algorithm, in the case where
  // the frame policy declares that the feature should be allowed.)
  std::unique_ptr<PermissionsPolicy> policy1 =
      CreateFromParentPolicy(nullptr,
                             {{{kDefaultSelfFeature, /*allowed_origins=*/{},
                                /*self_if_matches=*/origin_a_,
                                /*matches_all_origins=*/false,
                                /*matches_opaque_src=*/false}}},
                             origin_a_);

  std::unique_ptr<PermissionsPolicy> policy2 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_a_);
  EXPECT_TRUE(policy2->IsFeatureEnabled(kDefaultSelfFeature));

  std::unique_ptr<PermissionsPolicy> policy3 =
      CreateFromParentPolicy(policy1.get(), /*header_policy=*/{}, origin_b_);
  EXPECT_FALSE(policy3->IsFeatureEnabled(kDefaultSelfFeature));

  // This is a critical change from the existing semantics.
  ParsedPermissionsPolicy frame_policy4 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/{},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/true,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy4 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy4, origin_b_);
  EXPECT_FALSE(policy4->IsFeatureEnabled(kDefaultSelfFeature));

  // This is a critical change from the existing semantics.
  ParsedPermissionsPolicy frame_policy5 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
            origin_b_,
            /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/true,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy5 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy5, origin_b_);
  EXPECT_FALSE(policy5->IsFeatureEnabled(kDefaultSelfFeature));

  ParsedPermissionsPolicy frame_policy6 = {
      {{kDefaultSelfFeature, /*allowed_origins=*/
        {*blink::OriginWithPossibleWildcards::FromOriginAndWildcardsForTest(
            origin_c_,
            /*has_subdomain_wildcard=*/false)},
        /*self_if_matches=*/std::nullopt,
        /*matches_all_origins=*/true,
        /*matches_opaque_src=*/false}}};
  std::unique_ptr<PermissionsPolicy> policy6 = CreateFromParentWithFramePolicy(
      policy1.get(), /*header_policy=*/{}, frame_policy6, origin_b_);
  EXPECT_FALSE(policy6->IsFeatureEnabled(kDefaultSelfFeature));
}

T
"""


```