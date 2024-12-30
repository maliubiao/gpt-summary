Response:
The user wants a summary of the functionality of the C++ code provided, specifically the `global_first_party_sets_unittest.cc` file within the Chromium network stack. I need to identify the main purpose of this file and any relationships to JavaScript functionality, logic, common errors, and debugging context.

**Functionality:**

The file name strongly suggests this is a unit test file for the `GlobalFirstPartySets` class. The `#include` statements confirm this, along with inclusions for testing frameworks like `gtest` and `gmock`. Therefore, the primary function is to test the behavior and correctness of the `GlobalFirstPartySets` class. This likely involves:

*   Creating instances of `GlobalFirstPartySets` with various configurations.
*   Calling methods of `GlobalFirstPartySets` like `FindEntry`, `FindEntries`, `ApplyManuallySpecifiedSet`, `ComputeConfig`, etc.
*   Asserting the expected outcomes of these method calls using `EXPECT_THAT`, `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, etc.

**Relationship to JavaScript:**

First-Party Sets are a web platform feature affecting how browsers handle website identity and cookies. While the *implementation* is in C++, the *concept* is exposed to JavaScript. JavaScript on a webpage can interact with the browser's understanding of First-Party Sets through APIs related to cookie access and storage partitioning.

**Logic and Examples:**

The tests demonstrate various logical scenarios related to First-Party Sets, including:

*   Looking up entries.
*   Handling aliases.
*   Applying overrides and manual sets.
*   Checking for empty sets.
*   Iterating through sets.

I can provide examples by examining the existing test cases and describing their input and expected output.

**User/Programming Errors:**

Common errors might involve:

*   Incorrectly defining First-Party Sets (e.g., overlapping primaries).
*   Misunderstanding how overrides or manual sets affect the global state.
*   Expecting a site to be part of a set when it isn't due to policy or manual configuration.

I can extract examples from the tests or create hypothetical ones.

**Debugging Context:**

This unit test file is used by Chromium developers to ensure the `GlobalFirstPartySets` class functions correctly. If a user encounters issues related to First-Party Sets (e.g., a website not behaving as expected due to incorrect set configuration), developers might use these tests to reproduce or diagnose the problem. The steps to reach this code during debugging would involve tracing the code flow related to First-Party Set lookups and modifications within the Chromium network stack.

**Part 1 Summary:**

The goal for Part 1 is to summarize the core functionality of the file.

**Plan:**

1. State that this is a unit test file for `GlobalFirstPartySets`.
2. Describe the general purpose of unit tests.
3. List the key functionalities being tested based on the method names and test case structures.
4. Explain the connection to JavaScript conceptually, providing an example of how JavaScript might be affected.
5. Select a few illustrative test cases and describe their input and expected output as logic examples.
6. Identify potential user/programming errors related to First-Party Sets and provide examples.
7. Describe how a developer might reach this code during debugging, linking it to user-facing issues.
这是 Chromium 网络栈中 `net/first_party_sets/global_first_party_sets_unittest.cc` 文件的第一部分，它的主要功能是**测试 `GlobalFirstPartySets` 类的功能和正确性**。`GlobalFirstPartySets` 类负责管理全局的第一方集合 (First-Party Sets, FPS) 数据，包括从配置文件加载的公共集合以及用户或策略手动指定的集合。

以下是该文件功能的详细归纳：

**核心功能：测试 `GlobalFirstPartySets` 类的各种方法和场景**

*   **构造函数测试:**
    *   测试构造函数是否正确处理无效的版本号。
    *   测试拷贝构造函数 (`Clone`) 是否能创建对象的深拷贝。
    *   测试在构造函数中处理别名 (aliases) 的情况，特别是当别名指向集合中的 primary 站点时。
*   **查找条目测试 (`FindEntry`, `FindEntries`):**
    *   测试在不存在的站点上查找条目是否返回空。
    *   测试在存在的站点上查找条目是否返回正确的 `FirstPartySetEntry`。
    *   测试查找条目是否区分协议 (例如 `https` 和 `wss`)。
    *   测试通过策略覆盖 (override) 查找条目的情况，包括覆盖已存在的条目和移除条目。
    *   测试通过别名查找条目的情况。
    *   测试策略覆盖是否优先于别名。
*   **判空测试 (`empty`):**
    *   测试当 `GlobalFirstPartySets` 对象为空时是否返回 `true`。
    *   测试当对象包含公共集合或手动指定的集合时是否返回 `false`。
    *   测试即使公共集合版本无效，手动指定的集合仍然存在的情况。
*   **迭代测试 (`ForEachEffectiveSetEntry`, `ForEachPublicSetEntry`):**
    *   测试 `ForEachEffectiveSetEntry` 方法是否能正确遍历所有生效的集合条目，包括公共集合和手动指定的集合，并考虑策略配置。
    *   测试 `ForEachPublicSetEntry` 方法是否能正确遍历所有公共集合的条目。
    *   测试迭代方法中的提前返回机制。
*   **应用手动指定集合测试 (`ApplyManuallySpecifiedSet`):**
    *   测试应用手动指定的集合是否会覆盖或合并已有的公共集合。
    *   测试在手动指定的集合与公共集合存在重叠站点时的处理逻辑，包括 primary 站点与 primary 站点、primary 站点与非 primary 站点、非 primary 站点与 primary 站点、非 primary 站点与非 primary 站点的重叠。
    *   测试应用手动指定集合后，是否会移除因成员减少而变成单例的集合。
    *   测试手动指定的别名是否会覆盖公共集合中的别名。

**与 Javascript 的关系：**

虽然此代码是 C++ 实现，但它直接影响着浏览器如何理解和处理网页的来源和身份，这与 Javascript 的功能息息相关。

**举例说明：**

假设一个网站 `primary.test` 设置了一个第一方集合，包含了 `associated1.test`。  网页上的 Javascript 代码想要访问 `associated1.test` 存储的 Cookie。  `GlobalFirstPartySets` 的数据会告诉浏览器，`associated1.test` 属于 `primary.test` 的第一方集合，从而允许 Javascript 代码在特定情况下访问这些 Cookie (取决于具体的 Cookie 策略和 SameSite 属性)。

**逻辑推理和假设输入输出：**

以 `TEST_F(GlobalFirstPartySetsTest, FindEntry_Exists)` 为例：

*   **假设输入:**
    *   一个 `GlobalFirstPartySets` 对象，包含站点 `https://example.test` 及其对应的 `FirstPartySetEntry`。
    *   要查找的站点 `https://example.test`。
    *   一个空的 `FirstPartySetsContextConfig`。
*   **预期输出:**
    *   返回一个 `std::optional<FirstPartySetEntry>`，其中包含与 `https://example.test` 关联的 `FirstPartySetEntry`。

**用户或编程常见的使用错误：**

*   **错误配置第一方集合:** 用户或开发者可能会错误地配置第一方集合的声明，例如将不相关的域名放在同一个集合中，或者定义了重叠的 primary 站点。 例如，如果两个不同的站点 `primary1.test` 和 `primary2.test` 都被声明为各自集合的 primary 站点，并且在手动配置时同时添加，则 `GlobalFirstPartySets` 的逻辑会处理这种冲突，具体行为取决于实现。
*   **误解策略覆盖:** 用户或开发者可能没有意识到通过企业策略或命令行参数进行的覆盖会优先于默认的公共集合。 例如，用户可能期望一个站点属于某个公共集合，但管理员通过策略将其移除了。
*   **别名冲突:**  当公共集合和手动指定的集合都定义了同一个域名的别名，但指向不同的 primary 站点时，可能会导致混淆。该文件中的测试用例 `TEST_F(PopulatedGlobalFirstPartySetsTest, ApplyManuallySpecifiedSet_RespectsManualAlias)` 就是为了测试这种情况。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户报告网站行为异常:** 用户可能遇到某个网站的功能不正常，例如无法记住登录状态，或者跨子域名或相关域名共享的信息不一致。
2. **开发者检查网络请求和 Cookie:** 开发者可能会使用浏览器开发者工具检查网络请求的 Cookie 头信息，发现 Cookie 的设置或发送行为与预期不符。
3. **怀疑第一方集合配置问题:** 开发者可能会怀疑该网站或相关的域名是否被错误地包含在某个第一方集合中，或者由于策略覆盖导致了意外的行为。
4. **检查 Chromium 的 FPS 实现:** 开发者可能会深入 Chromium 的源代码，查看与第一方集合相关的代码，例如 `GlobalFirstPartySets` 类的实现，以理解浏览器的行为。
5. **运行或查看单元测试:**  为了验证 `GlobalFirstPartySets` 的行为是否符合预期，开发者可能会运行这些单元测试，或者参考这些测试用例来理解特定场景下的逻辑。 `global_first_party_sets_unittest.cc` 文件就提供了这样的测试用例，帮助开发者理解和调试 FPS 的相关问题。

**总结一下它的功能 (Part 1):**

总而言之，`net/first_party_sets/global_first_party_sets_unittest.cc` 文件的第一部分主要负责测试 `GlobalFirstPartySets` 类的基本功能，包括对象的创建、条目的查找、判空以及手动指定集合的应用等核心操作。这些测试覆盖了各种正常和异常情况，旨在确保该类能够正确地管理和查询第一方集合的数据，为 Chromium 浏览器中与 FPS 相关的其他功能提供可靠的基础。

Prompt: 
```
这是目录为net/first_party_sets/global_first_party_sets_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/first_party_sets/global_first_party_sets.h"

#include <optional>

#include "base/containers/flat_map.h"
#include "base/version.h"
#include "net/base/schemeful_site.h"
#include "net/first_party_sets/first_party_set_entry.h"
#include "net/first_party_sets/first_party_set_entry_override.h"
#include "net/first_party_sets/first_party_set_metadata.h"
#include "net/first_party_sets/first_party_sets_context_config.h"
#include "net/first_party_sets/local_set_declaration.h"
#include "net/first_party_sets/sets_mutation.h"
#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

using ::testing::IsEmpty;
using ::testing::Optional;
using ::testing::Pair;
using ::testing::UnorderedElementsAre;

namespace net {

namespace {

const base::Version kVersion("1.2.3");
const SchemefulSite kPrimary(GURL("https://primary.test"));
const SchemefulSite kPrimaryCctld(GURL("https://primary.ccltd"));
const SchemefulSite kPrimary2(GURL("https://primary2.test"));
const SchemefulSite kPrimary3(GURL("https://primary3.test"));
const SchemefulSite kAssociated1(GURL("https://associated1.test"));
const SchemefulSite kAssociated1Cctld(GURL("https://associated1.cctld"));
const SchemefulSite kAssociated1Cctld2(GURL("https://associated1.cctld2"));
const SchemefulSite kAssociated2(GURL("https://associated2.test"));
const SchemefulSite kAssociated3(GURL("https://associated3.test"));
const SchemefulSite kAssociated4(GURL("https://associated4.test"));
const SchemefulSite kAssociated5(GURL("https://associated5.test"));
const SchemefulSite kService(GURL("https://service.test"));

base::flat_map<SchemefulSite, FirstPartySetEntry> CollectEffectiveSetEntries(
    const GlobalFirstPartySets& sets,
    const FirstPartySetsContextConfig& config) {
  base::flat_map<SchemefulSite, FirstPartySetEntry> got;
  sets.ForEachEffectiveSetEntry(
      config, [&](const SchemefulSite& site, const FirstPartySetEntry& entry) {
        EXPECT_FALSE(got.contains(site));
        got[site] = entry;
        return true;
      });

  // Consistency check: verify that all of the returned entries are what we'd
  // get if we called FindEntry directly.
  for (const auto& [site, entry] : got) {
    EXPECT_EQ(sets.FindEntry(site, config).value(), entry);
  }
  return got;
}

}  // namespace

class GlobalFirstPartySetsTest : public ::testing::Test {
 public:
  GlobalFirstPartySetsTest() = default;
};

TEST_F(GlobalFirstPartySetsTest, CtorSkipsInvalidVersion) {
  GlobalFirstPartySets sets(
      base::Version(), /*entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated1,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{});

  EXPECT_THAT(
      sets.FindEntries({kPrimary, kAssociated1}, FirstPartySetsContextConfig()),
      IsEmpty());
}

TEST_F(GlobalFirstPartySetsTest, Clone) {
  base::Version version("1.2.3.4.5");
  const SchemefulSite example(GURL("https://example.test"));
  const SchemefulSite example_cctld(GURL("https://example.cctld"));
  const SchemefulSite member1(GURL("https://member1.test"));
  const FirstPartySetEntry entry(example, SiteType::kPrimary, std::nullopt);
  const FirstPartySetEntry member1_entry(example, SiteType::kAssociated, 1);

  const SchemefulSite foo(GURL("https://foo.test"));
  const SchemefulSite member2(GURL("https://member2.test"));
  const FirstPartySetEntry foo_entry(foo, SiteType::kPrimary, std::nullopt);
  const FirstPartySetEntry member2_entry(foo, SiteType::kAssociated, 1);

  GlobalFirstPartySets sets(version,
                            /*entries=*/
                            {{example, entry}, {member1, member1_entry}},
                            /*aliases=*/{{example_cctld, example}});
  sets.ApplyManuallySpecifiedSet(LocalSetDeclaration(
      /*set_entries=*/{{foo, foo_entry}, {member2, member2_entry}},
      /*aliases=*/{}));

  EXPECT_EQ(sets, sets.Clone());
}

TEST_F(GlobalFirstPartySetsTest, Ctor_PrimaryWithAlias_Valid) {
  GlobalFirstPartySets global_sets(
      kVersion, /*entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
      },
      /*aliases=*/
      {
          {kPrimaryCctld, kPrimary},
      });

  EXPECT_THAT(
      CollectEffectiveSetEntries(global_sets, FirstPartySetsContextConfig()),
      UnorderedElementsAre(
          Pair(kPrimaryCctld,
               FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)),
          Pair(kPrimary, FirstPartySetEntry(kPrimary, SiteType::kPrimary,
                                            std::nullopt))));
}

TEST_F(GlobalFirstPartySetsTest, FindEntry_Nonexistent) {
  SchemefulSite example(GURL("https://example.test"));

  EXPECT_THAT(
      GlobalFirstPartySets().FindEntry(example, FirstPartySetsContextConfig()),
      std::nullopt);
}

TEST_F(GlobalFirstPartySetsTest, FindEntry_Exists) {
  SchemefulSite example(GURL("https://example.test"));
  SchemefulSite decoy_site(GURL("https://decoy.test"));
  FirstPartySetEntry entry(example, SiteType::kPrimary, std::nullopt);
  FirstPartySetEntry decoy_entry(example, SiteType::kAssociated, 1);

  EXPECT_THAT(GlobalFirstPartySets(kVersion,
                                   {
                                       {example, entry},
                                       {decoy_site, decoy_entry},
                                   },
                                   {})
                  .FindEntry(example, FirstPartySetsContextConfig()),
              Optional(entry));
}

TEST_F(GlobalFirstPartySetsTest, FindEntry_NoNormalization) {
  SchemefulSite https_example(GURL("https://example.test"));
  SchemefulSite associated(GURL("https://associated.test"));
  SchemefulSite wss_example(GURL("wss://example.test"));
  FirstPartySetEntry entry(https_example, SiteType::kPrimary, std::nullopt);
  FirstPartySetEntry assoc_entry(https_example, SiteType::kAssociated, 0);

  EXPECT_THAT(GlobalFirstPartySets(kVersion,
                                   {
                                       {https_example, entry},
                                       {associated, assoc_entry},
                                   },
                                   {})
                  .FindEntry(wss_example, FirstPartySetsContextConfig()),
              std::nullopt);
}

TEST_F(GlobalFirstPartySetsTest, FindEntry_ExistsViaOverride) {
  SchemefulSite example(GURL("https://example.test"));
  SchemefulSite associated(GURL("https://associated.test"));
  FirstPartySetEntry public_entry(example, SiteType::kPrimary, std::nullopt);
  FirstPartySetEntry assoc_entry(example, SiteType::kAssociated, 0);
  FirstPartySetEntry override_entry(example, SiteType::kAssociated, 1);

  FirstPartySetsContextConfig config(
      {{example, net::FirstPartySetEntryOverride(override_entry)}});

  EXPECT_THAT(GlobalFirstPartySets(kVersion,
                                   {
                                       {example, public_entry},
                                       {associated, assoc_entry},
                                   },
                                   {})
                  .FindEntry(example, config),
              Optional(override_entry));
}

TEST_F(GlobalFirstPartySetsTest, FindEntry_RemovedViaOverride) {
  SchemefulSite example(GURL("https://example.test"));
  SchemefulSite associated(GURL("https://associated.test"));
  FirstPartySetEntry public_entry(example, SiteType::kPrimary, std::nullopt);
  FirstPartySetEntry assoc_entry(example, SiteType::kAssociated, 0);

  FirstPartySetsContextConfig config(
      {{example, net::FirstPartySetEntryOverride()}});

  EXPECT_THAT(GlobalFirstPartySets(kVersion,
                                   {
                                       {example, public_entry},
                                       {associated, assoc_entry},
                                   },
                                   {})
                  .FindEntry(example, config),
              std::nullopt);
}

TEST_F(GlobalFirstPartySetsTest, FindEntry_ExistsViaAlias) {
  SchemefulSite example(GURL("https://example.test"));
  SchemefulSite example_cctld(GURL("https://example.cctld"));
  FirstPartySetEntry entry(example, SiteType::kPrimary, std::nullopt);

  EXPECT_THAT(GlobalFirstPartySets(kVersion,
                                   {
                                       {example, entry},
                                   },
                                   {{example_cctld, example}})
                  .FindEntry(example_cctld, FirstPartySetsContextConfig()),
              Optional(entry));
}

TEST_F(GlobalFirstPartySetsTest, FindEntry_ExistsViaOverrideWithDecoyAlias) {
  SchemefulSite example(GURL("https://example.test"));
  SchemefulSite example_cctld(GURL("https://example.cctld"));
  FirstPartySetEntry public_entry(example, SiteType::kPrimary, std::nullopt);
  FirstPartySetEntry override_entry(example, SiteType::kAssociated, 1);

  FirstPartySetsContextConfig config(
      {{example_cctld, net::FirstPartySetEntryOverride(override_entry)}});

  EXPECT_THAT(GlobalFirstPartySets(kVersion,
                                   {
                                       {example, public_entry},
                                   },
                                   {{example_cctld, example}})
                  .FindEntry(example_cctld, config),
              Optional(override_entry));
}

TEST_F(GlobalFirstPartySetsTest, FindEntry_RemovedViaOverrideWithDecoyAlias) {
  SchemefulSite example(GURL("https://example.test"));
  SchemefulSite example_cctld(GURL("https://example.cctld"));
  FirstPartySetEntry public_entry(example, SiteType::kPrimary, std::nullopt);

  FirstPartySetsContextConfig config(
      {{example_cctld, net::FirstPartySetEntryOverride()}});

  EXPECT_THAT(GlobalFirstPartySets(kVersion,
                                   {
                                       {example, public_entry},
                                   },
                                   {{example_cctld, example}})
                  .FindEntry(example_cctld, config),
              std::nullopt);
}

TEST_F(GlobalFirstPartySetsTest, FindEntry_AliasesIgnoredForConfig) {
  SchemefulSite example(GURL("https://example.test"));
  SchemefulSite example_cctld(GURL("https://example.cctld"));
  FirstPartySetEntry public_entry(example, SiteType::kPrimary, std::nullopt);
  FirstPartySetEntry override_entry(example, SiteType::kAssociated, 1);

  FirstPartySetsContextConfig config(
      {{example, net::FirstPartySetEntryOverride(override_entry)}});

  // FindEntry should ignore aliases when using the customizations. Public
  // aliases only apply to sites in the public sets.
  EXPECT_THAT(GlobalFirstPartySets(kVersion,
                                   {
                                       {example, public_entry},
                                   },
                                   {{example_cctld, example}})
                  .FindEntry(example_cctld, config),
              public_entry);
}

TEST_F(GlobalFirstPartySetsTest, Empty_Empty) {
  EXPECT_TRUE(GlobalFirstPartySets().empty());
}

TEST_F(GlobalFirstPartySetsTest, Empty_NonemptyEntries) {
  EXPECT_FALSE(
      GlobalFirstPartySets(
          kVersion,
          {
              {kPrimary,
               FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
              {kAssociated4,
               FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
          },
          {})
          .empty());
}

TEST_F(GlobalFirstPartySetsTest, Empty_NonemptyManualSet) {
  GlobalFirstPartySets sets;
  sets.ApplyManuallySpecifiedSet(LocalSetDeclaration(
      /*set_entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated4,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{}));
  EXPECT_FALSE(sets.empty());
}

TEST_F(GlobalFirstPartySetsTest, InvalidPublicSetsVersion_NonemptyManualSet) {
  GlobalFirstPartySets sets(
      base::Version(), /*entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated1,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{});
  ASSERT_TRUE(sets.empty());
  sets.ApplyManuallySpecifiedSet(LocalSetDeclaration(
      /*set_entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated4,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{}));

  // The manual set should still be available, even though the component was
  // invalid.
  EXPECT_FALSE(sets.empty());
  EXPECT_THAT(
      sets.FindEntries({kPrimary, kAssociated1, kAssociated4},
                       FirstPartySetsContextConfig()),
      UnorderedElementsAre(
          Pair(kPrimary,
               FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)),
          Pair(kAssociated4,
               FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0))));
}

TEST_F(GlobalFirstPartySetsTest,
       ForEachEffectiveSetEntry_ManualSetAndConfig_FullIteration) {
  GlobalFirstPartySets global_sets;
  global_sets.ApplyManuallySpecifiedSet(LocalSetDeclaration(
      /*set_entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated4,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
          {kAssociated5,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 1)},
      },
      /*aliases=*/{}));

  // Modify kPrimary's set by removing kAssociated5 and modifying kAssociated4,
  // via policy.
  FirstPartySetsContextConfig config = global_sets.ComputeConfig(SetsMutation(
      /*replacement_sets=*/
      {
          {
              {kPrimary,
               FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
              {kAssociated1, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)},
              {kAssociated1Cctld,
               FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                  std::nullopt)},
              {kAssociated4, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)},
              {kService,
               FirstPartySetEntry(kPrimary, SiteType::kService, std::nullopt)},
          },
      },
      /*addition_sets=*/{}));

  // Note that since the policy sets take precedence over the manual set,
  // kAssociated5 is no longer in an FPS.
  EXPECT_THAT(
      CollectEffectiveSetEntries(global_sets, config),
      UnorderedElementsAre(
          Pair(kAssociated1Cctld,
               FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(kAssociated1, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)),
          Pair(kAssociated4, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)),
          Pair(kPrimary,
               FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)),
          Pair(kService, FirstPartySetEntry(kPrimary, SiteType::kService,
                                            std::nullopt))));
}

class PopulatedGlobalFirstPartySetsTest : public GlobalFirstPartySetsTest {
 public:
  PopulatedGlobalFirstPartySetsTest()
      : global_sets_(
            kVersion,
            {
                {kPrimary, FirstPartySetEntry(kPrimary,
                                              SiteType::kPrimary,
                                              std::nullopt)},
                {kAssociated1,
                 FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
                {kAssociated2,
                 FirstPartySetEntry(kPrimary, SiteType::kAssociated, 1)},
                {kService, FirstPartySetEntry(kPrimary,
                                              SiteType::kService,
                                              std::nullopt)},
                {kPrimary2, FirstPartySetEntry(kPrimary2,
                                               SiteType::kPrimary,
                                               std::nullopt)},
                {kAssociated3,
                 FirstPartySetEntry(kPrimary2, SiteType::kAssociated, 0)},
            },
            {
                {kAssociated1Cctld, kAssociated1},
            }) {}

  GlobalFirstPartySets& global_sets() { return global_sets_; }

 private:
  GlobalFirstPartySets global_sets_;
};

TEST_F(PopulatedGlobalFirstPartySetsTest,
       ApplyManuallySpecifiedSet_DeduplicatesPrimaryPrimary) {
  // kPrimary overlaps as primary of both sets, so the existing set should be
  // wiped out.
  global_sets().ApplyManuallySpecifiedSet(LocalSetDeclaration(
      /*set_entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated4,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{}));

  EXPECT_THAT(
      global_sets().FindEntries(
          {
              kPrimary,
              kAssociated1,
              kAssociated2,
              kAssociated4,
              kService,
              kAssociated1Cctld,
          },
          FirstPartySetsContextConfig()),
      UnorderedElementsAre(
          Pair(kPrimary,
               FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)),
          Pair(kAssociated4,
               FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0))));
}

TEST_F(PopulatedGlobalFirstPartySetsTest,
       ApplyManuallySpecifiedSet_DeduplicatesPrimaryNonprimary) {
  // kPrimary overlaps as a primary of the public set and non-primary of the CLI
  // set, so the existing set should be wiped out.
  global_sets().ApplyManuallySpecifiedSet(LocalSetDeclaration(
      /*set_entries=*/
      {
          {kPrimary3,
           FirstPartySetEntry(kPrimary3, SiteType::kPrimary, std::nullopt)},
          {kPrimary, FirstPartySetEntry(kPrimary3, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{}));

  EXPECT_THAT(
      global_sets().FindEntries(
          {
              kPrimary,
              kAssociated1,
              kAssociated2,
              kAssociated4,
              kService,
              kPrimary3,
              kAssociated1Cctld,
          },
          FirstPartySetsContextConfig()),
      UnorderedElementsAre(
          Pair(kPrimary3,
               FirstPartySetEntry(kPrimary3, SiteType::kPrimary, std::nullopt)),
          Pair(kPrimary,
               FirstPartySetEntry(kPrimary3, SiteType::kAssociated, 0))));
}

TEST_F(PopulatedGlobalFirstPartySetsTest,
       ApplyManuallySpecifiedSet_DeduplicatesNonprimaryPrimary) {
  // kAssociated1 overlaps as a non-primary of the public set and primary of the
  // CLI set, so the CLI set should steal it and wipe out its alias, but
  // otherwise leave the set intact.
  global_sets().ApplyManuallySpecifiedSet(LocalSetDeclaration(
      /*set_entries=*/
      {
          {kAssociated1,
           FirstPartySetEntry(kAssociated1, SiteType::kPrimary, std::nullopt)},
          {kAssociated4,
           FirstPartySetEntry(kAssociated1, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{}));

  EXPECT_THAT(
      global_sets().FindEntries(
          {
              kPrimary,
              kAssociated1,
              kAssociated2,
              kAssociated4,
              kService,
              kPrimary3,
              kAssociated1Cctld,
          },
          FirstPartySetsContextConfig()),
      UnorderedElementsAre(
          Pair(kPrimary,
               FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)),
          Pair(kAssociated2,
               FirstPartySetEntry(kPrimary, SiteType::kAssociated, 1)),
          Pair(kService,
               FirstPartySetEntry(kPrimary, SiteType::kService, std::nullopt)),
          Pair(kAssociated1,
               FirstPartySetEntry(kAssociated1, SiteType::kPrimary,
                                  std::nullopt)),
          Pair(kAssociated4,
               FirstPartySetEntry(kAssociated1, SiteType::kAssociated, 0))));
}

TEST_F(PopulatedGlobalFirstPartySetsTest,
       ApplyManuallySpecifiedSet_DeduplicatesNonprimaryNonprimary) {
  // kAssociated1 overlaps as a non-primary of the public set and non-primary of
  // the CLI set, so the CLI set should steal it and wipe out its alias.
  global_sets().ApplyManuallySpecifiedSet(LocalSetDeclaration(
      /*set_entries=*/
      {
          {kPrimary3,
           FirstPartySetEntry(kPrimary3, SiteType::kPrimary, std::nullopt)},
          {kAssociated1,
           FirstPartySetEntry(kPrimary3, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{}));

  EXPECT_THAT(
      global_sets().FindEntries(
          {
              kPrimary,
              kAssociated1,
              kAssociated2,
              kAssociated4,
              kService,
              kPrimary3,
              kAssociated1Cctld,
          },
          FirstPartySetsContextConfig()),
      UnorderedElementsAre(
          Pair(kPrimary,
               FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)),
          Pair(kAssociated2,
               FirstPartySetEntry(kPrimary, SiteType::kAssociated, 1)),
          Pair(kService,
               FirstPartySetEntry(kPrimary, SiteType::kService, std::nullopt)),
          Pair(kPrimary3,
               FirstPartySetEntry(kPrimary3, SiteType::kPrimary, std::nullopt)),
          Pair(kAssociated1,
               FirstPartySetEntry(kPrimary3, SiteType::kAssociated, 0))));
}

TEST_F(PopulatedGlobalFirstPartySetsTest,
       ApplyManuallySpecifiedSet_PrunesInducedSingletons) {
  // Steal kAssociated3, so that kPrimary2 becomes a singleton, and verify that
  // kPrimary2 is no longer considered in a set.
  global_sets().ApplyManuallySpecifiedSet(LocalSetDeclaration(
      /*set_entries=*/
      {
          {kPrimary3,
           FirstPartySetEntry(kPrimary3, SiteType::kPrimary, std::nullopt)},
          {kAssociated3,
           FirstPartySetEntry(kPrimary3, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{}));

  EXPECT_THAT(
      global_sets().FindEntries({kPrimary2}, FirstPartySetsContextConfig()),
      IsEmpty());
}

TEST_F(PopulatedGlobalFirstPartySetsTest,
       ApplyManuallySpecifiedSet_RespectsManualAlias) {
  // Both the public sets and the locally-defined set define an alias for
  // kAssociated1, but both define a different set for that site too.  Only the
  // locally-defined alias should be observable.
  global_sets().ApplyManuallySpecifiedSet(LocalSetDeclaration(
      /*set_entries=*/
      {
          {kPrimary3,
           FirstPartySetEntry(kPrimary3, SiteType::kPrimary, std::nullopt)},
          {kAssociated1,
           FirstPartySetEntry(kPrimary3, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{
          {kAssociated1Cctld2, kAssociated1},
      }));

  EXPECT_THAT(
      global_sets().FindEntries(
          {
              kAssociated1,
              kAssociated1Cctld,
              kAssociated1Cctld2,
          },
          FirstPartySetsContextConfig()),
      UnorderedElementsAre(
          Pair(kAssociated1,
               FirstPartySetEntry(kPrimary3, SiteType::kAssociated, 0)),
          Pair(kAssociated1Cctld2,
               FirstPartySetEntry(kPrimary3, SiteType::kAssociated, 0))));
}

TEST_F(PopulatedGlobalFirstPartySetsTest, ForEachPublicSetEntry_FullIteration) {
  int count = 0;
  EXPECT_TRUE(global_sets().ForEachPublicSetEntry(
      [&](const SchemefulSite& site, const FirstPartySetEntry& entry) {
        ++count;
        return true;
      }));
  EXPECT_EQ(count, 7);
}

TEST_F(PopulatedGlobalFirstPartySetsTest, ForEachPublicSetEntry_EarlyReturn) {
  int count = 0;
  EXPECT_FALSE(global_sets().ForEachPublicSetEntry(
      [&](const SchemefulSite& site, const FirstPartySetEntry& entry) {
        ++count;
        return count < 4;
      }));
  EXPECT_EQ(count, 4);
}

TEST_F(PopulatedGlobalFirstPartySetsTest,
       ForEachEffectiveSetEntry_PublicSetsOnly_FullIteration) {
  EXPECT_THAT(
      CollectEffectiveSetEntries(global_sets(), FirstPartySetsContextConfig()),
      UnorderedElementsAre(
          Pair(kAssociated1Cctld,
               FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)),
          Pair(kAssociated1,
               FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)),
          Pair(kAssociated2,
               FirstPartySetEntry(kPrimary, SiteType::kAssociated, 1)),
          Pair(kAssociated3,
               FirstPartySetEntry(kPrimary2, SiteType::kAssociated, 0)),
          Pair(kPrimary,
               FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)),
          Pair(kPrimary2,
               FirstPartySetEntry(kPrimary2, SiteType::kPrimary, std::nullopt)),
          Pair(kService, FirstPartySetEntry(kPrimary, SiteType::kService,
                                            std::nullopt))));
}

TEST_F(PopulatedGlobalFirstPartySetsTest,
       ForEachEffectiveSetEntry_PublicSetsWithManualSet_FullIteration) {
  // Replace kPrimary's set (including the alias and service site) with just
  // {kPrimary, kAssociated4}.
  global_sets().ApplyManuallySpecifiedSet(LocalSetDeclaration(
      /*set_entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated4,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{}));

  EXPECT_THAT(
      CollectEffectiveSetEntries(global_sets(), FirstPartySetsContextConfig()),
      UnorderedElementsAre(
          Pair(kAssociated3,
               FirstPartySetEntry(kPrimary2, SiteType::kAssociated, 0)),
          Pair(kAssociated4,
               FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)),
          Pair(kPrimary,
               FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)),
          Pair(kPrimary2, FirstPartySetEntry(kPrimary2, SiteType::kPrimary,
                                             std::nullopt))));
}

TEST_F(PopulatedGlobalFirstPartySetsTest,
       ForEachEffectiveSetEntry_PublicSetsWithConfig_FullIteration) {
  // Modify kPrimary's set by removing kAssociated2 and adding kAssociated4, via
  // policy.
  FirstPartySetsContextConfig config = global_sets().ComputeConfig(SetsMutation(
      /*replacement_sets=*/
      {
          {
              {kPrimary,
               FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
              {kAssociated1, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)},
              {kAssociated1Cctld,
               FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                  std::nullopt)},
              {kAssociated4, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)},
              {kService,
               FirstPartySetEntry(kPrimary, SiteType::kService, std::nullopt)},
          },
      },
      /*addition_sets=*/{}));

  EXPECT_THAT(
      CollectEffectiveSetEntries(global_sets(), config),
      UnorderedElementsAre(
          Pair(kAssociated1Cctld,
               FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(kAssociated1, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)),
          Pair(kAssociated3,
               FirstPartySetEntry(kPrimary2, SiteType::kAssociated, 0)),
          Pair(kAssociated4, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)),
          Pair(kPrimary,
               FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)),
          Pair(kPrimary2,
               FirstPartySetEntry(kPrimary2, SiteType::kPrimary, std::nullopt)),
          Pair(kService, FirstPartySetEntry(kPrimary, SiteType::kService,
                                            std::nullopt))));
}

TEST_F(
    PopulatedGlobalFirstPartySetsTest,
    ForEachEffectiveSetEntry_PublicSetsWithManualSetAndConfig_FullIteration) {
  // Replace kPrimary's set (including the alias and service site) with just
  // {kPrimary, kAssociated4, kAssociated5}.
  global_sets().ApplyManuallySpecifiedSet(LocalSetDeclaration(
      /*set_entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated4,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
          {kAssociated5,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 1)},
      },
      /*aliases=*/{}));

  // Modify kPrimary's set by removing kAssociated2 and adding kAssociated4, via
  // policy.
  FirstPartySetsContextConfig config = global_sets().ComputeConfig(SetsMutation(
      /*replacement_sets=*/
      {
          {
              {kPrimary,
               FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
              {kAssociated1, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)},
              {kAssociated1Cctld,
               FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                  std::nullopt)},
              {kAssociated4, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)},
              {kService,
               FirstPartySetEntry(kPrimary, SiteType::kService, std::nullopt)},
          },
      },
      /*addition_sets=*/{}));

  // Note that since the policy sets take precedence over the manual set,
  // kAssociated5 is no longer in an FPS.
  EXPECT_THAT(
      CollectEffectiveSetEntries(global_sets(), config),
      UnorderedElementsAre(
          Pair(kAssociated1Cctld,
               FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(kAssociated1, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)),
          Pair(kAssociated3,
               FirstPartySetEntry(kPrimary2, SiteType::kAssociated, 0)),
          Pair(kAssociated4, FirstPartySetEntry(kPrimary, SiteType::kAssociated,
                                                std::nullopt)),
          Pair(kPrimary,
               FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)),
          Pair(kPrimary2,
               FirstPartySetEntry(kPrimary2, SiteType::kPrimary, std::nullopt)),
          Pair(kService, FirstPartySetEntry(kPrimary, SiteType::kService,
                                            std::nullopt))));
}

TEST_F(
    PopulatedGlobalFirstPartySetsTest,
    ForEachEffectiveSetEntry_PublicSetsWithManualSetAndConfig_ManualAliasOverlap) {
  global_sets().ApplyManuallySpecifiedSet(LocalSetDeclaration(
      /*set_entries=*/
      {
          {kPrimary,
           FirstPartySetEntry(kPrimary, SiteType::kPrimary, std::nullopt)},
          {kAssociated1,
           FirstPartySetEntry(kPrimary, SiteType::kAssociated, 0)},
      },
      /*aliases=*/{
          {kAssociated1Cctld2, kAssociated1},
      }));

  FirstPartySetsContextConfig config = global_sets().ComputeConfig(SetsMutation(
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
      /*addition_sets=*/{}));

  EXPECT_THAT(
      CollectEffectiveSetEntries(global_sets(), config),
      UnorderedElementsAre(
          Pair(kAssociated1,
               FirstPartySetEntry(kPrimary2, SiteType::kAssociated,
                                  std::nullopt)),
          Pair(kPrimary2, FirstPartySetEntry(kPrimary2, SiteType::kPrimary,
                                             std::nullopt))));
}

TEST_F(PopulatedGlobalFirstPartySetsTest, ComputeM
"""


```