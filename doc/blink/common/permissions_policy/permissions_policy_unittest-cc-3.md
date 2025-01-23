Response:
The user wants me to analyze a C++ unit test file for the Chromium Blink engine's Permissions Policy implementation.

Here's a breakdown of the thought process to address the request:

1. **Identify the core functionality being tested:** The code heavily uses `EXPECT_TRUE` and `EXPECT_FALSE` with calls to `policy->IsFeatureEnabledForSubresourceRequest` and `IsFeatureEnabledForOrigin`, indicating that the primary function is to test if features governed by Permissions Policy are enabled or disabled under various conditions. The tests also involve setting up different Permission-Policy headers.

2. **Relate to web technologies (JavaScript, HTML, CSS):** Permissions Policy directly impacts how web features (like `browsingTopics` and `sharedStorage`) can be used. This connects directly to JavaScript APIs (like `fetch` with specific options) and how these features are controlled through HTTP headers (which are part of the HTML loading process). CSS isn't directly mentioned in the code snippet, but Permissions Policy can sometimes interact with CSS features indirectly by controlling the availability of underlying browser functionalities.

3. **Analyze the test cases:** Each test case within the larger `TEST_F` blocks sets up a specific scenario. These scenarios involve:
    * Different Permission-Policy header configurations.
    * Different origins for the main document and the subresource request.
    * Different opt-in flags in the `fetch` requests (e.g., `browsingTopics: true`, `sharedStorageWritable: true`).

4. **Infer logical reasoning:** The tests are asserting whether a feature is enabled or disabled based on the policy and the request's characteristics. This involves understanding the logic of how Permissions Policy is designed to work:
    * **Default behavior:** Features might be enabled or disabled by default.
    * **Policy directives:** The `Permissions-Policy` header overrides default behavior.
    * **Origin matching:** Policies can be scoped to specific origins.
    * **Opt-in mechanisms:** Some features might require explicit opt-in during subresource requests.

5. **Consider user/programming errors:**  While this is a *unit test*,  the scenarios it tests can highlight potential user errors in configuring Permissions Policy headers. For instance, incorrectly specifying allowed origins can lead to features being unexpectedly blocked or allowed.

6. **Address the "subresource request" aspect:**  Several test cases use `IsFeatureEnabledForSubresourceRequest`. This highlights a key function of Permissions Policy: controlling features in the context of requests for resources loaded by a page (like images, scripts, etc.).

7. **Focus on the provided code snippet (Part 4):** The prompt specifies this is part 4 of 5. This means I should avoid repeating information extensively covered in the previous parts (which I don't have access to, so I should keep the summary focused on the current piece).

8. **Formulate the response:** Structure the answer to address each part of the user's request:
    * Overall functionality.
    * Relationship to JavaScript, HTML, CSS with examples.
    * Logical reasoning with examples of input and output.
    * Common user/programming errors with examples.
    * Summarize the functionality of this specific part.

**(Self-correction during thought process):** Initially, I might have overemphasized the details of specific features like "Shared Storage" and "Browsing Topics." However, the core function being tested is the *mechanism* of Permissions Policy, not the specifics of these individual features. Therefore, the explanation should focus on how the tests verify the policy's enforcement. Also, the prompt specifically asks to focus on *this part* of the code, so I need to avoid speculating too much on what might be covered in other parts.
这是 `blink/common/permissions_policy/permissions_policy_unittest.cc` 文件的第 4 部分，其功能是**测试 Permissions Policy 在子资源请求场景下的功能，特别是当请求中显式地声明了对某个 Policy Feature 的需求时，以及测试新的 Permissions Policy 提议算法在嵌套 frame 中的行为。**

让我们分解一下它与 javascript, html, css 的关系，并给出相应的例子：

**1. 与 JavaScript 的关系：**

* **`fetch` API 和 Feature Opt-in：** 代码中模拟了 JavaScript 的 `fetch` API 发起子资源请求，并且可以携带一些特定的选项，例如 `browsingTopics: true` 和 `sharedStorageWritable: true`。这些选项对应了 Permissions Policy 控制的特定功能。

   * **例子：**
     ```javascript
     // JavaScript 发起请求，声明需要使用 browsingTopics 功能
     fetch('https://example.com/data', { browsingTopics: true });

     // JavaScript 发起请求，声明需要写入 Shared Storage
     fetch('https://example.com/resource', { sharedStorageWritable: true });
     ```

* **Permissions Policy 对 JavaScript API 的限制：**  Permissions Policy 的目标是限制某些 Web API 或浏览器功能的访问权限。如果 Permissions Policy 不允许某个 origin 使用 `browsingTopics`，即使 JavaScript 代码尝试使用 `fetch` API 并设置了 `browsingTopics: true`，浏览器也会阻止该功能的访问。

**2. 与 HTML 的关系：**

* **`<iframe>` 标签和 `allow` 属性：** 代码中涉及到了嵌套 frame 的场景，并且提到了 `<allow>` 属性。HTML 的 `<iframe>` 标签的 `allow` 属性可以用来声明 frame 对某些 Permissions Policy 控制的 features 的访问权限。

   * **例子：**
     ```html
     <!-- 父页面 (Origin A) 设置了 default-self=()，禁止了 default-self feature -->
     <!-- 子 frame (Origin B) 尝试通过 allow 属性重新启用 default-self feature -->
     <iframe src="https://origin-b.example.com" allow="default-self *"></iframe>
     ```
     这个代码片段测试了当父页面通过 Permissions Policy 禁止了某个 feature 后，子 frame 是否能通过 `allow` 属性重新启用它（根据新的提议算法，答案是否定的）。

* **`Permissions-Policy` HTTP Header：** Permissions Policy 的配置主要通过 HTTP 响应头 `Permissions-Policy` 来实现。测试代码中创建 `PermissionsPolicy` 对象时，模拟了各种 `Permissions-Policy` 头的配置。

   * **例子：**
     ```
     Permissions-Policy: browsing-topics=(self), shared-storage=(self)
     Permissions-Policy: browsing-topics=(none), shared-storage=(none)
     Permissions-Policy: browsing-topics=*, shared-storage=*
     Permissions-Policy: browsing-topics=(https://origin-b.example.com), shared-storage=(https://origin-b.example.com)
     ```

**3. 与 CSS 的关系：**

虽然这段代码片段没有直接涉及到 CSS，但 Permissions Policy 也可以控制一些与 CSS 相关的特性，例如：

* **`sync-xhr`:**  控制是否允许在文档卸载时发起同步的 XMLHttpRequest 请求，这可能会影响页面的渲染和性能。
* **`document-domain`:**  控制是否允许修改 `document.domain`，这可能会影响跨域脚本的访问。

如果 Permissions Policy 禁止了某个与 CSS 相关的特性，那么即使 CSS 代码尝试使用该特性，浏览器也会阻止。

**逻辑推理 (假设输入与输出):**

考虑以下测试用例：

```c++
  {
    // +--------------------------------------------------------+
    // |(1)Origin A                                             |
    // |Permissions-Policy: browsing-topics=(Origin B),         |
    // |                    shared-storage=(Origin B)           |
    // |                                                        |
    // | fetch(<Origin B's url>, {browsingTopics: true})        |
    // | fetch(<Origin C's url>, {sharedStorageWritable: true}) |
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

    // 假设输入：子资源请求的目标 Origin 是 origin_b_，且请求携带了 browsingTopics opt-in
    EXPECT_TRUE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kBrowsingTopics, origin_b_,
        request_with_topics_opt_in)); // 输出：true，因为 Policy 允许 Origin B 使用 browsing-topics

    // 假设输入：子资源请求的目标 Origin 是 origin_c_，且请求携带了 sharedStorageWritable opt-in
    EXPECT_FALSE(policy->IsFeatureEnabledForSubresourceRequest(
        mojom::PermissionsPolicyFeature::kSharedStorage, origin_c_,
        request_with_shared_storage_opt_in)); // 输出：false，因为 Policy 不允许 Origin C 使用 shared-storage
  }
```

**用户或编程常见的使用错误举例：**

1. **Permissions-Policy Header 配置错误：**
   * **错误示例：**  `Permissions-Policy: camera=(self "https://example.com")`  （语法错误，`self` 后面不应该有额外的 origin）。
   * **后果：** 浏览器可能无法正确解析该 header，导致 Policy 未生效或部分生效，与预期行为不符。

2. **在子资源请求中错误地假设 Feature 总是可用：**
   * **错误示例：**  JavaScript 代码直接使用 `navigator.sharedStorage` API，而没有检查 Permissions Policy 是否允许当前 origin 使用该功能。
   * **后果：** 代码可能会抛出异常或功能无法正常工作。

3. **对 `allow` 属性的理解偏差（特别是在新的提议算法下）：**
   * **错误示例：** 父页面禁止了某个 feature，开发者错误地认为子 frame 可以通过 `allow` 属性无条件地重新启用它。
   * **后果：**  在新的提议算法下，子 frame 仍然无法使用该 feature。

**功能归纳 (针对第 4 部分):**

这部分代码主要测试了以下 Permissions Policy 的功能：

* **子资源请求的 Feature 控制：**  验证了在发起子资源请求时，Permissions Policy 如何根据目标 origin 和请求中携带的 feature opt-in 信息来决定是否允许使用特定的 feature (例如 `browsingTopics`, `sharedStorage`).
* **显式 opt-in 的影响：** 测试了当子资源请求显式声明需要使用某个 feature 时，Policy 的判断逻辑。
* **新的提议算法在嵌套 frame 中的行为：**  重点测试了在父 frame 禁用某个 feature 的情况下，子 frame 是否能通过 HTML 的 `allow` 属性重新启用该 feature (根据新的提议，答案是否定的)。 这部分旨在验证新的 Policy 继承和覆盖机制。

总而言之，第 4 部分深入测试了 Permissions Policy 在更复杂的场景下的行为，特别是涉及到子资源请求和嵌套 frame 时，Policy 是如何生效和继承的，并对未来的 Policy 行为进行了验证。

### 提示词
```
这是目录为blink/common/permissions_policy/permissions_policy_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
tureEnabledForSubresourceRequest(
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
```