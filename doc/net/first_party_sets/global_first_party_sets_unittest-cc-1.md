Response:
Let's break down the thought process for analyzing this C++ unit test file.

1. **Understand the Goal:** The core request is to understand the *functionality* of the C++ test file `global_first_party_sets_unittest.cc` within the Chromium network stack, and relate it to JavaScript if possible.

2. **Identify the Core Subject:** The filename itself gives a strong hint: "FirstPartySets". This immediately tells me the code is related to how Chromium handles the concept of First-Party Sets. The `unittest.cc` suffix confirms this is a file containing unit tests for the `GlobalFirstPartySets` class.

3. **Analyze the Test Structure:** Unit tests typically have a clear structure:
    * **Includes:**  Start by examining the included header files. These will reveal the main classes and dependencies being tested. In this case, we see includes related to GURL, SchemefulSite, FirstPartySetEntry, and importantly, `global_first_party_sets.h`. This confirms the tests are focused on the `GlobalFirstPartySets` class.
    * **Test Fixtures:** Look for `TEST_F`. This indicates the use of test fixtures. `GlobalFirstPartySetsTest` and `GlobalFirstPartySetsWithConfigTest` are the key fixtures. Analyzing the setup within these fixtures (though not fully shown in this snippet) would provide context about the initial state of the `GlobalFirstPartySets` object being tested. In this snippet, we see direct instantiation of `GlobalFirstPartySets` within the test cases, providing immediate context.
    * **Individual Test Cases:**  Each `TEST_F` block represents a specific test scenario. The names of the test cases are crucial for understanding their purpose. For example, `ComputeMetadata_InSets`, `ComputeConfig_Empty`, `ComputeConfig_Replacements_NoIntersection_NoRemoval`, etc., clearly describe what aspect of `GlobalFirstPartySets` is being tested.
    * **Assertions:**  Within each test case, look for assertion macros like `EXPECT_EQ`, `EXPECT_THAT`, `ASSERT_TRUE`, `EXPECT_FALSE`. These are the core of the tests, verifying expected behavior. The arguments to these assertions (e.g., calling methods of `global_sets()` or the directly instantiated `GlobalFirstPartySets` object) demonstrate *how* the functionality is being tested.

4. **Focus on Key Functionality Being Tested:** Based on the test case names and assertions, identify the primary functions of `GlobalFirstPartySets` being exercised:
    * **`ComputeMetadata()`:** Tests how the system determines the metadata (specifically `FirstPartySetEntry`) for a given site, considering the context of another site. The different scenarios (both sites in the same set, one in, one out, both out) are explicitly tested.
    * **`ComputeConfig()`:** This function appears to be about applying *mutations* (replacements and additions) to the set configuration. The test cases explore various scenarios of these mutations: no intersection, replacements affecting existing sites, additions with overlaps, and transitive overlaps.
    * **`FindEntries()`:** Although not the central focus of every test, it's used to verify the *result* of `ComputeConfig`, ensuring the sets are updated correctly after mutations.

5. **Relate to JavaScript (if applicable):**  The prompt specifically asks about JavaScript. First-Party Sets are a web platform feature that *impacts* JavaScript behavior. Consider:
    * **`document.cookie`:**  First-Party Sets influence which sites can access each other's cookies. This is the most direct link.
    * **Storage APIs (localStorage, sessionStorage, IndexedDB):** Similar to cookies, First-Party Sets can affect the scoping of these storage mechanisms.
    * **Fetch API, XHR:**  The `SameSite` attribute of cookies, relevant to First-Party Sets, influences how these requests are handled.

6. **Infer Logical Reasoning and Provide Examples:** For `ComputeMetadata` and `ComputeConfig`, the tests themselves provide excellent examples of input (site URLs) and expected output (`FirstPartySetMetadata` or the updated set configuration). Summarize these examples in a more user-friendly way. Think about "if I give this input, what should the output be according to the tests?".

7. **Consider User/Programming Errors:** Think about how someone might misuse the First-Party Sets API or introduce errors in their configuration. Examples include:
    * Conflicting set definitions.
    * Incorrect site type assignments (e.g., marking an associated site as primary).
    * Issues with the format or syntax of the set configuration data.

8. **Trace User Operations (Debugging Clues):**  How does a user interaction lead to this code being executed?  Think about the browser's lifecycle:
    * The browser loads a page.
    * The browser needs to determine the First-Party Set relationship between the current site and subresources or navigated-to sites.
    * The `GlobalFirstPartySets` class is responsible for providing this information based on the currently configured sets.

9. **Summarize the Functionality (Part 2):**  After analyzing the individual tests, provide a concise summary of the overall purpose of the file and the `GlobalFirstPartySets` class. Emphasize the core responsibilities: storing, managing, and querying First-Party Set information.

10. **Refine and Organize:** Structure the answer logically with clear headings and bullet points. Use precise terminology related to First-Party Sets. Ensure the examples are easy to understand.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this file directly handles network requests related to FPS. **Correction:** The filename and test names point more towards *managing the data* of FPS rather than the network layer itself.
* **Initial thought:** Focus heavily on the C++ implementation details. **Correction:** Balance this with explaining the *purpose* of the code and its relation to web concepts.
* **Review:**  Read through the generated explanation. Is it clear and accurate?  Are the examples helpful?  Is the connection to JavaScript explained effectively?  Are the potential errors and debugging steps realistic?  Make adjustments as needed.
这是 Chromium 网络栈中 `net/first_party_sets/global_first_party_sets_unittest.cc` 文件的第二部分，延续了第一部分的内容，继续测试 `GlobalFirstPartySets` 类的功能。该类负责管理全局的第一方集合 (First-Party Sets)。

**归纳一下它的功能：**

这部分测试文件主要集中在测试 `GlobalFirstPartySets` 类的以下功能：

1. **`ComputeConfig(SetsMutation)` 方法的各种场景测试：**  `ComputeConfig` 方法负责根据 `SetsMutation` 对象（包含要替换或添加的 First-Party Sets）来更新当前的全局 First-Party Sets 配置。这部分测试了各种复杂的更新场景，包括：
    * **替换 (Replacements)：**
        * 替换的集合与现有集合没有交集。
        * 替换的集合替换了现有集合中的关联站点，导致该关联站点从旧集合中移除。
        * 替换的集合替换了现有集合的主站点，导致旧集合中的关联站点因不再有主站点而移除。
        * 替换的集合替换了现有集合中的关联站点，导致旧集合变为单例集合并被移除。
    * **添加 (Additions)：**
        * 添加的集合与现有集合没有交集，直接添加。
        * 添加的集合的主站点是现有集合的关联站点，导致现有集合被吸收到新集合中。
        * 添加的集合的主站点是现有集合的主站点，导致新集合吸收现有集合的关联站点。
    * **替换和添加的组合：** 测试替换和添加操作同时发生，且可能与同一个现有集合有重叠的情况。
    * **传递性重叠 (Transitive Overlap)：** 测试多个要添加的集合之间存在重叠，以及与现有集合存在重叠的情况，验证最终合并后的集合的正确性。
    * **无效的公共集合版本 (Invalid Public Sets Version)：** 测试当底层公共 First-Party Sets 数据版本无效时，`ComputeConfig` 的行为。

2. **与配置对象 (`FirstPartySetsContextConfig`) 结合的测试：**  `GlobalFirstPartySetsWithConfigTest` 测试夹具用于测试当存在外部提供的配置 (`FirstPartySetsContextConfig`) 时，`ComputeMetadata` 方法的行为。这允许覆盖或修改默认的全局 First-Party Sets 配置。测试了以下场景：
    * **移除条目：**  验证配置可以移除已存在的 First-Party Set 条目。
    * **添加条目：** 验证配置可以添加新的 First-Party Set 条目。
    * **重映射条目：** 验证配置可以将一个站点重映射到不同的 First-Party Set 中。
    * **移除别名：** 验证配置可以移除别名。
    * **结合配置计算元数据：** 测试 `ComputeMetadata` 方法在应用外部配置后，能否正确计算站点的 First-Party Set 元数据。

**与 JavaScript 功能的关系：**

虽然此 C++ 代码本身不直接包含 JavaScript，但它所测试的 First-Party Sets 功能是 Web 平台的一部分，对 JavaScript 有重要的影响。

**举例说明：**

* **Cookie 访问控制：** JavaScript 可以通过 `document.cookie` API 访问和设置 Cookie。First-Party Sets 允许将多个相关的域名声明为一个集合，使得这些域名可以像同一个第一方一样访问彼此的 Cookie（需要 Cookie 设置了合适的 `SameSite` 属性）。`GlobalFirstPartySets` 的功能直接影响浏览器如何判断两个域名是否在同一个第一方集合中，从而决定 JavaScript 能否跨这些域名访问 Cookie。
    * **假设输入：** 用户访问了 `https://primary1.test` 页面，该页面包含一个 JavaScript 脚本尝试读取 `https://associatedsite1.test` 设置的 Cookie。
    * **逻辑推理：** `GlobalFirstPartySets` 需要判断 `primary1.test` 和 `associatedsite1.test` 是否在同一个集合中。如果根据配置它们在同一个集合中，并且 Cookie 的 `SameSite` 属性允许，则 JavaScript 可以成功读取 Cookie。
    * **输出：** JavaScript 代码成功获取到 `https://associatedsite1.test` 设置的 Cookie 值。

* **存储 API (例如 localStorage)：** 类似于 Cookie，First-Party Sets 也可能影响 JavaScript 通过 `localStorage` 等 Web Storage API 存储的数据的隔离范围。尽管目前的 First-Party Sets 主要关注 Cookie，但未来可能会扩展到影响其他存储机制。

**逻辑推理的假设输入与输出：**

以 `TEST_F(GlobalFirstPartySetsTest, ComputeConfig_Additions_PolicyPrimaryIsExistingAssociatedSite_PolicySetAbsorbsExistingSet)` 这个测试为例：

* **假设输入：**
    * 现有的全局 First-Party Sets 配置包含 `{kPrimary, kAssociated1}`。
    * 接收到一个要添加的 First-Party Set：`{kAssociated1, kAssociated2, kAssociated3}`（注意 `kAssociated1` 是新集合的主站点）。
* **逻辑推理：**  由于要添加的集合的主站点 `kAssociated1` 是现有集合的关联站点，根据 First-Party Sets 的逻辑，新的集合会吸收现有集合。
* **输出：** 更新后的全局 First-Party Sets 配置将包含 `{kAssociated1, kPrimary, kAssociated2, kAssociated3}`，其中 `kAssociated1` 是主站点，`kPrimary`、`kAssociated2` 和 `kAssociated3` 是关联站点。

**涉及用户或编程常见的使用错误：**

* **配置冲突：** 管理员可能会配置相互冲突的 First-Party Sets，导致某些站点无法确定所属的集合。例如，将同一个站点同时声明为两个不同集合的主站点。`GlobalFirstPartySets` 的实现需要处理和解决这些冲突。
    * **举例：** 假设管理员错误地配置了两个集合：`{primary1.test, associated1.test}` 和 `{primary2.test, associated1.test}`。`associated1.test` 同时属于两个集合，这会导致不一致性。`GlobalFirstPartySets` 在加载或应用配置时应该能够检测到这种错误。
* **错误的站点类型声明：**  在配置 First-Party Sets 时，将站点声明为错误的类型（例如，将关联站点声明为主站点）会导致意外的行为。
    * **举例：** 管理员将 `associated1.test` 错误地声明为 `PRIMARY` 类型，而不是 `ASSOCIATED` 类型，可能会导致该站点被误认为是一个独立的 First-Party Set 的主站点。
* **版本不匹配：**  当公共的 First-Party Sets 数据版本与浏览器实现不兼容时，可能会导致功能异常。测试用例 `InvalidPublicSetsVersion_ComputeConfig` 就是为了验证这种情况。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户浏览网页：** 用户在浏览器中访问一个网页，例如 `https://example.com`。
2. **页面加载资源或导航：** 该页面可能加载来自其他域名的资源（例如，图片来自 `https://cdn.example.com`）或者用户点击链接导航到另一个域名（例如 `https://service.example.com`）。
3. **浏览器检查 First-Party Set 关系：**  当浏览器需要决定如何处理跨域请求的 Cookie 或其他安全策略时，它会查询 `GlobalFirstPartySets` 来确定涉及的域名是否属于同一个 First-Party Set。
4. **`ComputeMetadata` 被调用：**  浏览器会调用 `GlobalFirstPartySets::ComputeMetadata` 方法，传入源站和目标站点的 URL，以及当前的配置上下文。
5. **`GlobalFirstPartySets` 查询内部数据：**  `ComputeMetadata` 方法会根据其内部存储的 First-Party Sets 配置数据（可能来自静态配置、管理员策略或公共的 First-Party Sets 数据）来查找这两个域名是否在同一个集合中。
6. **返回元数据：**  `ComputeMetadata` 返回一个 `FirstPartySetMetadata` 对象，指示这两个域名的 First-Party Set 关系。
7. **浏览器根据元数据采取行动：** 浏览器根据返回的元数据来决定是否允许跨域 Cookie 访问或其他操作。

**作为调试线索：** 如果在 First-Party Sets 相关的功能上出现问题（例如，Cookie 访问被意外阻止），开发者可能会：

1. **检查浏览器的 First-Party Sets 配置：**  开发者可以查看浏览器的内部设置或使用开发者工具来检查当前生效的 First-Party Sets 配置。
2. **查看网络请求的 Cookie：**  检查网络请求的 Cookie 头部，确认 `SameSite` 属性的设置是否符合预期。
3. **断点调试 `ComputeMetadata`：**  如果怀疑是 First-Party Sets 的判断逻辑错误，开发者可能会在 `GlobalFirstPartySets::ComputeMetadata` 方法中设置断点，查看传入的参数和返回的结果，以及内部的查找逻辑，以确定浏览器是如何判断两个域名是否属于同一个集合的。
4. **分析 `ComputeConfig` 的更新过程：** 如果怀疑是配置更新过程中出现了问题，可以分析 `ComputeConfig` 方法的执行流程，特别是当应用管理员策略或公共 First-Party Sets 数据时，查看配置是如何被修改和应用的。

总而言之，这部分单元测试深入测试了 `GlobalFirstPartySets` 类在处理 First-Party Sets 配置更新和查询时的各种复杂场景，确保了 Chromium 能够正确地管理和使用 First-Party Sets 信息，从而影响到 Web 平台上与安全和隐私相关的关键功能。

### 提示词
```
这是目录为net/first_party_sets/global_first_party_sets_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
etadata) {
  SchemefulSite nonmember(GURL("https://nonmember.test"));
  FirstPartySetEntry primary_entry(kPrimary, SiteType::kPrimary, std::nullopt);
  FirstPartySetEntry associated_entry(kPrimary, SiteType::kAssociated, 0);

  // Works as usual for sites that are in First-Party sets.
  EXPECT_EQ(global_sets().ComputeMetadata(kAssociated1, &kAssociated1,
                                          FirstPartySetsContextConfig()),
            FirstPartySetMetadata(associated_entry, associated_entry));
  EXPECT_EQ(global_sets().ComputeMetadata(kPrimary, &kAssociated1,
                                          FirstPartySetsContextConfig()),
            FirstPartySetMetadata(primary_entry, associated_entry));
  EXPECT_EQ(global_sets().ComputeMetadata(kAssociated1, &kPrimary,
                                          FirstPartySetsContextConfig()),
            FirstPartySetMetadata(associated_entry, primary_entry));

  EXPECT_EQ(global_sets().ComputeMetadata(nonmember, &kAssociated1,
                                          FirstPartySetsContextConfig()),
            FirstPartySetMetadata(std::nullopt, associated_entry));
  EXPECT_EQ(global_sets().ComputeMetadata(kAssociated1, &nonmember,
                                          FirstPartySetsContextConfig()),
            FirstPartySetMetadata(associated_entry, std::nullopt));

  EXPECT_EQ(global_sets().ComputeMetadata(nonmember, &nonmember,
                                          FirstPartySetsContextConfig()),
            FirstPartySetMetadata(std::nullopt, std::nullopt));
}

TEST_F(GlobalFirstPartySetsTest, ComputeConfig_Empty) {
  EXPECT_EQ(GlobalFirstPartySets(
                kVersion,
                /*entries=*/
                {
                    {kPrimary, FirstPartySetEntry(kPrimary, SiteType::kPrimary,
                                                  std::nullopt)},
                    {kAssociated1,
                     FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
                },
                /*aliases=*/{})
                .ComputeConfig(SetsMutation({}, {})),
            FirstPartySetsContextConfig());
}

TEST_F(GlobalFirstPartySetsTest,
       ComputeConfig_Replacements_NoIntersection_NoRemoval) {
  GlobalFirstPartySets sets(
      kVersion,
      /*entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated1,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{});
  FirstPartySetsContextConfig config = sets.ComputeConfig(SetsMutation(
      /*replacement_sets=*/
      {
          {
              {kPrimary2,
               FirstPartySetEntry(kPrimary2, SiteType::kPrimary, std::nullopt)},
              {kAssociated2,
               FirstPartySetEntry(kPrimary2, SiteType::kAssociated,
                                  std::nullopt)},
          },
      },
      /*addition_sets=*/{}));
  EXPECT_THAT(
      sets.FindEntries({kAssociated2, kPrimary2}, config),
      UnorderedElementsAre(
          Pair(kAssociated2,
               FirstPartySetEntry(kPrimary2, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(kPrimary2, FirstPartySetEntry(kPrimary2, SiteType::kPrimary,
                                             std::nullopt))));
}

// The common associated site between the policy and existing set is removed
// from its previous set.
TEST_F(
    GlobalFirstPartySetsTest,
    ComputeConfig_Replacements_ReplacesExistingAssociatedSite_RemovedFromFormerSet) {
  GlobalFirstPartySets sets(
      kVersion,
      /*entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated1,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
          {kAssociated2,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 1)},
      },
      /*aliases=*/{});
  FirstPartySetsContextConfig config = sets.ComputeConfig(SetsMutation(
      /*replacement_sets=*/
      {
          {
              {kPrimary2,
               FirstPartySetEntry(kPrimary2, SiteType::kPrimary, std::nullopt)},
              {kAssociated2,
               FirstPartySetEntry(kPrimary2, SiteType::kAssociated,
                                  std::nullopt)},
          },
      },
      /*addition_sets=*/{}));
  EXPECT_THAT(
      sets.FindEntries({kPrimary2, kAssociated2}, config),
      UnorderedElementsAre(
          Pair(kAssociated2,
               FirstPartySetEntry(kPrimary2, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(kPrimary2, FirstPartySetEntry(kPrimary2, SiteType::kPrimary,
                                             std::nullopt))));
}

// The common primary between the policy and existing set is removed and its
// former associated sites are removed since they are now unowned.
TEST_F(
    GlobalFirstPartySetsTest,
    ComputeConfig_Replacements_ReplacesExistingPrimary_RemovesFormerAssociatedSites) {
  GlobalFirstPartySets sets(
      kVersion,
      /*entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated1,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
          {kAssociated2,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 1)},
      },
      /*aliases=*/{});
  FirstPartySetsContextConfig config = sets.ComputeConfig(SetsMutation(
      /*replacement_sets=*/
      {
          {
              {kPrimary,
               FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
              {kAssociated3, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)},
          },
      },
      /*addition_sets=*/{}));
  EXPECT_THAT(
      sets.FindEntries({kAssociated3, kPrimary, kAssociated1, kAssociated2},
                       config),
      UnorderedElementsAre(
          Pair(kAssociated3, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)),
          Pair(kPrimary, FirstPartySetEntry(kPrimary, SiteType::kPrimary,
                                            std::nullopt))));
}

// The common associated site between the policy and existing set is removed and
// any leftover singletons are deleted.
TEST_F(
    GlobalFirstPartySetsTest,
    ComputeConfig_Replacements_ReplacesExistingAssociatedSite_RemovesSingletons) {
  GlobalFirstPartySets sets(
      kVersion,
      /*entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated1,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{});
  FirstPartySetsContextConfig config = sets.ComputeConfig(SetsMutation(
      /*replacement_sets=*/
      {
          {
              {kPrimary3,
               FirstPartySetEntry(kPrimary3, SiteType::kPrimary, std::nullopt)},
              {kAssociated1,
               FirstPartySetEntry(kPrimary3, SiteType::kAssociated,
                                  std::nullopt)},
          },
      },
      /*addition_sets=*/{}));
  EXPECT_THAT(
      sets.FindEntries({kAssociated1, kPrimary3, kPrimary}, config),
      UnorderedElementsAre(
          Pair(kAssociated1,
               FirstPartySetEntry(kPrimary3, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(kPrimary3, FirstPartySetEntry(kPrimary3, SiteType::kPrimary,
                                             std::nullopt))));
}

// The policy set and the existing set have nothing in common so the policy set
// gets added in without updating the existing set.
TEST_F(GlobalFirstPartySetsTest,
       ComputeConfig_Additions_NoIntersection_AddsWithoutUpdating) {
  GlobalFirstPartySets sets(
      kVersion,
      /*entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated1,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{});
  FirstPartySetsContextConfig config = sets.ComputeConfig(SetsMutation(
      /*replacement_sets=*/{},
      /*addition_sets=*/{
          {
              {kPrimary2,
               FirstPartySetEntry(kPrimary2, SiteType::kPrimary, std::nullopt)},
              {kAssociated2,
               FirstPartySetEntry(kPrimary2, SiteType::kAssociated,
                                  std::nullopt)},
          },
      }));
  EXPECT_THAT(
      sets.FindEntries({kAssociated2, kPrimary2}, config),
      UnorderedElementsAre(
          Pair(kAssociated2,
               FirstPartySetEntry(kPrimary2, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(kPrimary2, FirstPartySetEntry(kPrimary2, SiteType::kPrimary,
                                             std::nullopt))));
}

// The primary of a policy set is also an associated site in an existing set.
// The policy set absorbs all sites in the existing set into its
// associated sites.
TEST_F(
    GlobalFirstPartySetsTest,
    ComputeConfig_Additions_PolicyPrimaryIsExistingAssociatedSite_PolicySetAbsorbsExistingSet) {
  GlobalFirstPartySets sets(
      kVersion,
      /*entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated1,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{});
  FirstPartySetsContextConfig config = sets.ComputeConfig(SetsMutation(
      /*replacement_sets=*/{},
      /*addition_sets=*/{
          {
              {kAssociated1,
               FirstPartySetEntry(kAssociated1, SiteType::kPrimary,
                                  std::nullopt)},
              {kAssociated2,
               FirstPartySetEntry(kAssociated1, SiteType::kAssociated,
                                  std::nullopt)},
              {kAssociated3,
               FirstPartySetEntry(kAssociated1, SiteType::kAssociated,
                                  std::nullopt)},
          },
      }));
  EXPECT_THAT(
      sets.FindEntries({kPrimary, kAssociated2, kAssociated3, kAssociated1},
                       config),
      UnorderedElementsAre(
          Pair(kPrimary, FirstPartySetEntry(kAssociated1, SiteType::kAssociated,
                                            std::nullopt)),
          Pair(kAssociated2,
               FirstPartySetEntry(kAssociated1, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(kAssociated3,
               FirstPartySetEntry(kAssociated1, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(kAssociated1,
               FirstPartySetEntry(kAssociated1, SiteType::kPrimary,
                                  std::nullopt))));
}

// The primary of a policy set is also a primary of an existing set.
// The policy set absorbs all of its primary's existing associated sites into
// its associated sites.
TEST_F(
    GlobalFirstPartySetsTest,
    ComputeConfig_Additions_PolicyPrimaryIsExistingPrimary_PolicySetAbsorbsExistingAssociatedSites) {
  GlobalFirstPartySets sets(
      kVersion,
      /*entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated1,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
          {kAssociated3,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 1)},
      },
      /*aliases=*/{});
  FirstPartySetsContextConfig config = sets.ComputeConfig(SetsMutation(
      /*replacement_sets=*/{},
      /*addition_sets=*/{{
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated2,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, std::nullopt)},
      }}));
  EXPECT_THAT(
      sets.FindEntries({kAssociated1, kAssociated2, kAssociated3, kPrimary},
                       config),
      UnorderedElementsAre(
          Pair(kAssociated1, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)),
          Pair(kAssociated2, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)),
          Pair(kAssociated3, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)),
          Pair(kPrimary, FirstPartySetEntry(kPrimary, SiteType::kPrimary,
                                            std::nullopt))));
}

// Existing set overlaps with both replacement and addition set.
TEST_F(
    GlobalFirstPartySetsTest,
    ComputeConfig_ReplacementsAndAdditions_SetListsOverlapWithSameExistingSet) {
  GlobalFirstPartySets sets(
      kVersion,
      /*entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated1,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
          {kAssociated2,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 1)},
      },
      /*aliases=*/{});
  FirstPartySetsContextConfig config = sets.ComputeConfig(SetsMutation(
      /*replacement_sets=*/
      {
          {
              {kPrimary2,
               FirstPartySetEntry(kPrimary2, SiteType::kPrimary, std::nullopt)},
              {kAssociated1,
               FirstPartySetEntry(kPrimary2, SiteType::kAssociated,
                                  std::nullopt)},
          },
      },
      /*addition_sets=*/{
          {
              {kPrimary,
               FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
              {kAssociated3, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)},
          },
      }));
  EXPECT_THAT(
      sets.FindEntries(
          {kAssociated1, kAssociated2, kAssociated3, kPrimary, kPrimary2},
          config),
      UnorderedElementsAre(
          Pair(kAssociated1,
               FirstPartySetEntry(kPrimary2, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(kAssociated2, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)),
          Pair(kAssociated3, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)),
          Pair(kPrimary,
               FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)),
          Pair(kPrimary2, FirstPartySetEntry(kPrimary2, SiteType::kPrimary,
                                             std::nullopt))));
}

TEST_F(GlobalFirstPartySetsTest, TransitiveOverlap_TwoCommonPrimaries) {
  SchemefulSite primary0(GURL("https://primary0.test"));
  SchemefulSite associated_site0(GURL("https://associatedsite0.test"));
  SchemefulSite primary1(GURL("https://primary1.test"));
  SchemefulSite associated_site1(GURL("https://associatedsite1.test"));
  SchemefulSite primary2(GURL("https://primary2.test"));
  SchemefulSite associated_site2(GURL("https://associatedsite2.test"));
  SchemefulSite primary42(GURL("https://primary42.test"));
  SchemefulSite associated_site42(GURL("https://associatedsite42.test"));
  // {primary1, {associated_site1}} and {primary2, {associated_site2}}
  // transitively overlap with the existing set. primary1 takes primaryship of
  // the normalized addition set since it was provided first. The other addition
  // sets are unaffected.
  GlobalFirstPartySets sets(
      kVersion,
      /*entries=*/
      {
          {primary1,
           FirstPartySetEntry(primary1, SiteType::kPrimary, std::nullopt)},
          {primary2, FirstPartySetEntry(primary1, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{});
  FirstPartySetsContextConfig config = sets.ComputeConfig(SetsMutation(
      /*replacement_sets=*/{},
      /*addition_sets=*/{
          {{primary0,
            FirstPartySetEntry(primary0, SiteType::kPrimary, std::nullopt)},
           {associated_site0,
            FirstPartySetEntry(primary0, SiteType::kAssociated, std::nullopt)}},
          {{primary1,
            FirstPartySetEntry(primary1, SiteType::kPrimary, std::nullopt)},
           {associated_site1,
            FirstPartySetEntry(primary1, SiteType::kAssociated, std::nullopt)}},
          {{primary2,
            FirstPartySetEntry(primary2, SiteType::kPrimary, std::nullopt)},
           {associated_site2,
            FirstPartySetEntry(primary2, SiteType::kAssociated, std::nullopt)}},
          {{primary42,
            FirstPartySetEntry(primary42, SiteType::kPrimary, std::nullopt)},
           {associated_site42,
            FirstPartySetEntry(primary42, SiteType::kAssociated,
                               std::nullopt)}},
      }));
  EXPECT_THAT(
      sets.FindEntries(
          {
              associated_site0,
              associated_site1,
              associated_site2,
              associated_site42,
              primary0,
              primary1,
              primary2,
              primary42,
          },
          config),
      UnorderedElementsAre(
          Pair(associated_site0,
               FirstPartySetEntry(primary0, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(associated_site1,
               FirstPartySetEntry(primary1, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(associated_site2,
               FirstPartySetEntry(primary1, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(associated_site42,
               FirstPartySetEntry(primary42, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(primary0,
               FirstPartySetEntry(primary0, SiteType::kPrimary, std::nullopt)),
          Pair(primary1,
               FirstPartySetEntry(primary1, SiteType::kPrimary, std::nullopt)),
          Pair(primary2, FirstPartySetEntry(primary1, SiteType::kAssociated,
                                            std::nullopt)),
          Pair(primary42, FirstPartySetEntry(primary42, SiteType::kPrimary,
                                             std::nullopt))));
}

TEST_F(GlobalFirstPartySetsTest, TransitiveOverlap_TwoCommonAssociatedSites) {
  SchemefulSite primary0(GURL("https://primary0.test"));
  SchemefulSite associated_site0(GURL("https://associatedsite0.test"));
  SchemefulSite primary1(GURL("https://primary1.test"));
  SchemefulSite associated_site1(GURL("https://associatedsite1.test"));
  SchemefulSite primary2(GURL("https://primary2.test"));
  SchemefulSite associated_site2(GURL("https://associatedsite2.test"));
  SchemefulSite primary42(GURL("https://primary42.test"));
  SchemefulSite associated_site42(GURL("https://associatedsite42.test"));
  // {primary1, {associated_site1}} and {primary2, {associated_site2}}
  // transitively overlap with the existing set. primary2 takes primaryship of
  // the normalized addition set since it was provided first. The other addition
  // sets are unaffected.
  GlobalFirstPartySets sets(
      kVersion,
      /*entries=*/
      {
          {primary2,
           FirstPartySetEntry(primary2, SiteType::kPrimary, std::nullopt)},
          {primary1, FirstPartySetEntry(primary2, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{});
  FirstPartySetsContextConfig config = sets.ComputeConfig(SetsMutation(
      /*replacement_sets=*/{},
      /*addition_sets=*/{
          {{primary0,
            FirstPartySetEntry(primary0, SiteType::kPrimary, std::nullopt)},
           {associated_site0,
            FirstPartySetEntry(primary0, SiteType::kAssociated, std::nullopt)}},
          {{primary2,
            FirstPartySetEntry(primary2, SiteType::kPrimary, std::nullopt)},
           {associated_site2,
            FirstPartySetEntry(primary2, SiteType::kAssociated, std::nullopt)}},
          {{primary1,
            FirstPartySetEntry(primary1, SiteType::kPrimary, std::nullopt)},
           {associated_site1,
            FirstPartySetEntry(primary1, SiteType::kAssociated, std::nullopt)}},
          {{primary42,
            FirstPartySetEntry(primary42, SiteType::kPrimary, std::nullopt)},
           {associated_site42,
            FirstPartySetEntry(primary42, SiteType::kAssociated,
                               std::nullopt)}},
      }));
  EXPECT_THAT(
      sets.FindEntries(
          {
              associated_site0,
              associated_site1,
              associated_site2,
              associated_site42,
              primary0,
              primary1,
              primary2,
              primary42,
          },
          config),
      UnorderedElementsAre(
          Pair(associated_site0,
               FirstPartySetEntry(primary0, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(associated_site1,
               FirstPartySetEntry(primary2, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(associated_site2,
               FirstPartySetEntry(primary2, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(associated_site42,
               FirstPartySetEntry(primary42, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(primary0,
               FirstPartySetEntry(primary0, SiteType::kPrimary, std::nullopt)),
          Pair(primary1, FirstPartySetEntry(primary2, SiteType::kAssociated,
                                            std::nullopt)),
          Pair(primary2,
               FirstPartySetEntry(primary2, SiteType::kPrimary, std::nullopt)),
          Pair(primary42, FirstPartySetEntry(primary42, SiteType::kPrimary,
                                             std::nullopt))));
}

TEST_F(GlobalFirstPartySetsTest, InvalidPublicSetsVersion_ComputeConfig) {
  const GlobalFirstPartySets sets(
      base::Version(), /*entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated1,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{});
  ASSERT_TRUE(sets.empty());

  FirstPartySetsContextConfig config = sets.ComputeConfig(SetsMutation(
      /*replacement_sets=*/
      {
          {
              {kPrimary2,
               FirstPartySetEntry(kPrimary2, SiteType::kPrimary, std::nullopt)},
              {kAssociated2,
               FirstPartySetEntry(kPrimary2, SiteType::kAssociated,
                                  std::nullopt)},
          },
      },
      /*addition_sets=*/{}));

  // The config should still be nonempty, even though the component was invalid.
  EXPECT_FALSE(config.empty());

  EXPECT_THAT(
      sets.FindEntries(
          {
              kPrimary,
              kPrimary2,
              kAssociated1,
              kAssociated2,
          },
          config),
      UnorderedElementsAre(
          Pair(kAssociated2,
               FirstPartySetEntry(kPrimary2, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(kPrimary2, FirstPartySetEntry(kPrimary2, SiteType::kPrimary,
                                             std::nullopt))));
}

class GlobalFirstPartySetsWithConfigTest
    : public PopulatedGlobalFirstPartySetsTest {
 public:
  GlobalFirstPartySetsWithConfigTest()
      : config_({
            // New entry:
            {kPrimary3, net::FirstPartySetEntryOverride(
                            FirstPartySetEntry(kPrimary3,
                                               SiteType::kPrimary,
                                               std::nullopt))},
            // Removed entry:
            {kAssociated1, net::FirstPartySetEntryOverride()},
            // Remapped entry:
            {kAssociated3,
             net::FirstPartySetEntryOverride(
                 FirstPartySetEntry(kPrimary3, SiteType::kAssociated, 0))},
            // Removed alias:
            {kAssociated1Cctld, net::FirstPartySetEntryOverride()},
        }) {}

  FirstPartySetsContextConfig& config() { return config_; }

 private:
  FirstPartySetsContextConfig config_;
};

TEST_F(GlobalFirstPartySetsWithConfigTest, ComputeMetadata) {
  // kAssociated1 has been removed from its set.
  EXPECT_EQ(global_sets().ComputeMetadata(kAssociated1, &kPrimary, config()),
            FirstPartySetMetadata(
                std::nullopt, FirstPartySetEntry(kPrimary, SiteType::kPrimary,
                                                 std::nullopt)));

  // kAssociated3 and kPrimary3 are sites in a new set.
  EXPECT_EQ(
      global_sets().ComputeMetadata(kAssociated3, &kPrimary3, config()),
      FirstPartySetMetadata(
          FirstPartySetEntry(kPrimary3, SiteType::kAssociated, 0),
          FirstPartySetEntry(kPrimary3, SiteType::kPrimary, std::nullopt)));
}

}  // namespace net
```