Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

1. **Understand the Goal:** The request asks for the functionality of `global_first_party_sets.cc`, its relation to JavaScript, logical reasoning with examples, common errors, and debugging tips. This means I need to go beyond a simple description of the code and consider its practical implications.

2. **Initial Skim and Keyword Identification:** I'd start by quickly reading through the code, looking for key terms and structures. Keywords like "FirstPartySet," "alias," "config," "entry," "metadata," "manual," "public," and the use of `base::flat_map` and `base::flat_set` immediately stand out. This gives me a high-level understanding that this code is about managing and querying data related to First-Party Sets.

3. **Core Functionality Identification (The "What"):**  I'd focus on the public methods and their purpose:
    * Constructors: How is the object initialized?  Notice the different constructors handling public sets, manual configurations, and the combination.
    * `FindEntry`: This is a crucial method for looking up information about a given site.
    * `FindEntries`:  Similar to `FindEntry`, but for multiple sites.
    * `ComputeMetadata`:  Calculates metadata, likely used for making decisions about site interactions.
    * `ApplyManuallySpecifiedSet`: Allows overriding the default sets.
    * `UnsafeSetManualConfig`:  Suggests a more direct (and potentially risky) way to set manual configurations.
    * `ComputeConfig`:  A complex method that seems to handle mutations and generate a configuration object.
    * `NormalizeAdditionSets`:  Deals with combining sets.
    * `ForEach*`:  Iteration methods for accessing the stored data.
    * `IsValid`:  Checks the consistency of the data.
    * Overloaded operators (`==`, `!=`, `<<`): Standard comparison and output.

4. **Data Structures (The "How"):**  Pay attention to the types used:
    * `SchemefulSite`: Represents a web origin (scheme + domain + optional port).
    * `FirstPartySetEntry`:  Contains information about a site's role within a First-Party Set (primary, associated, etc.).
    * `FirstPartySetEntryOverride`:  Used for overriding default entries.
    * `FirstPartySetsContextConfig`:  Holds configuration data, potentially from policies or user settings.
    * `FlattenedSets`, `SingleSet`: Type aliases for maps representing sets.

5. **Relationship to JavaScript:** This is where I need to bridge the gap between the C++ backend and the frontend. I'd think about:
    * **Browser Behavior:**  First-Party Sets impact how the browser handles cookies, storage access, and other security-sensitive features. These are things JavaScript code interacts with directly.
    * **JavaScript APIs:**  Are there any JavaScript APIs that expose or are influenced by First-Party Sets?  While the direct manipulation of FPS is usually not exposed, their *effects* are.
    * **Example Scenario:** A concrete example of a website in a First-Party Set trying to access cookies of another website in the same set is a good illustration.

6. **Logical Reasoning and Examples:**  For methods like `FindEntry` and `ComputeMetadata`, I'd consider:
    * **Input:** What are the possible inputs?  Consider different types of sites (primary, associated, alias, not in any set), different configurations.
    * **Process:** How does the method work step-by-step? (e.g., check manual overrides, then aliases, then public sets).
    * **Output:** What is the expected output for various inputs?  This is where the "Hypothetical Input/Output" examples come from.

7. **User/Programming Errors:**  Think about common mistakes when dealing with configurations and data:
    * **Invalid Input:**  Providing incorrect site formats.
    * **Conflicting Configurations:**  Setting up manual overrides that create inconsistencies.
    * **Incorrect Assumptions:**  Misunderstanding how aliases or overrides work.

8. **Debugging Clues (User Operations):** How does a user action lead to this code being executed?
    * **Navigation:** Visiting websites.
    * **Cookie/Storage Access:**  JavaScript trying to interact with storage.
    * **Configuration Changes:**  Enterprise policies or browser settings related to First-Party Sets.
    * **Developer Tools:**  Inspecting network requests, cookies, or storage.

9. **Structure and Refinement:** Organize the information logically. Use headings and bullet points for clarity. Start with a general overview and then delve into specifics. Ensure the language is clear and accessible. Review and refine the explanation for accuracy and completeness. For example, initially, I might just say "manages First-Party Sets."  But then I'd refine it to be more specific, like "manages and provides access to the global, canonical definitions of First-Party Sets..."

10. **Iterative Improvement:**  If I were unsure about certain aspects, I might:
    * **Refer to Chromium Documentation:** Look for official explanations of First-Party Sets.
    * **Search for Related Code:** Examine other files in the `net/first_party_sets` directory.
    * **Hypothesize and Test (Mentally):** Imagine different scenarios and trace how the code would behave.

By following these steps, I can systematically analyze the C++ code and generate a comprehensive and informative explanation that addresses all aspects of the original request. The key is to go beyond just describing the code and to consider its context, purpose, and practical implications.
这个文件 `global_first_party_sets.cc` 是 Chromium 网络栈中负责管理和提供全局第一方集合 (First-Party Sets, FPS) 定义的核心组件。它存储了当前浏览器所知的、所有网站的 FPS 归属信息。

以下是它的主要功能：

**核心功能：**

1. **存储和管理全局 FPS 数据:**
   - 它维护了两个主要的内部数据结构：
     - `entries_`:  一个 `base::flat_map`，将 `SchemefulSite` (包含协议的站点) 映射到 `FirstPartySetEntry`。`FirstPartySetEntry` 包含了该站点所属的 FPS 的主要站点 (primary site) 以及该站点在集合中的角色 (primary, associated, constituent)。
     - `aliases_`: 一个 `base::flat_map`，将别名 `SchemefulSite` 映射到规范的 `SchemefulSite`。这意味着某些站点可能是其他站点的别名，它们在 FPS 的上下文中被视为同一个站点。

2. **查找给定站点的 FPS 条目:**
   - `FindEntry(const SchemefulSite& site, const FirstPartySetsContextConfig& config) const`:  这是核心的查询方法。它接收一个站点和一个配置对象 `FirstPartySetsContextConfig` 作为输入，并返回一个 `std::optional<FirstPartySetEntry>`，表示该站点所属的 FPS 条目。
   - 此方法会考虑不同的数据来源：
     - **配置覆盖 (Configuration Overrides):** 首先检查传入的 `config` 中是否针对该站点有自定义的覆盖规则 (例如，强制将该站点视为不属于任何 FPS，或者属于特定的 FPS)。
     - **手动配置 (Manual Configuration):**  如果配置中没有覆盖，则检查 `manual_config_` 中是否有手动设置的 FPS 规则。这通常用于测试或企业策略。
     - **别名 (Aliases):** 如果以上都没有，则检查该站点是否是某个规范站点的别名。如果是，则查找规范站点的 FPS 条目。
     - **全局 FPS 数据 (Global FPS Data):** 最后，在 `entries_` 中查找该站点的 FPS 条目。

3. **批量查找多个站点的 FPS 条目:**
   - `FindEntries(const base::flat_set<SchemefulSite>& sites, const FirstPartySetsContextConfig& config) const`:  允许一次查找多个站点的 FPS 条目。

4. **计算 FPS 元数据:**
   - `ComputeMetadata(const SchemefulSite& site, base::optional_ref<const SchemefulSite> top_frame_site, const FirstPartySetsContextConfig& fps_context_config) const`:  计算给定站点的 FPS 元数据，包括该站点自身的 FPS 条目以及顶级 frame 站点的 FPS 条目（如果存在）。这对于确定两个站点是否属于同一个 FPS 非常重要。

5. **应用手动指定的 FPS 集合:**
   - `ApplyManuallySpecifiedSet(const LocalSetDeclaration& local_set_declaration)`:  允许通过 `LocalSetDeclaration` 对象来设置手动指定的 FPS 集合。这会覆盖当前的 `manual_config_` 和 `manual_aliases_`。

6. **不安全地设置手动配置 (主要用于测试):**
   - `UnsafeSetManualConfig(FirstPartySetsContextConfig manual_config)`: 提供了一种直接设置 `manual_config_` 的方式，但标记为 "Unsafe"，表明其主要用于测试目的，可能绕过了一些正常的验证和处理流程。

7. **处理 FPS 集合的变更 (添加和替换):**
   - `ComputeConfig(const SetsMutation& mutation) const`:  根据提供的 `SetsMutation` 对象（包含要添加或替换的 FPS 集合），计算出一个新的 `FirstPartySetsContextConfig` 对象，其中包含了这些变更。这个方法比较复杂，需要处理各种边缘情况，例如集合的合并、拆分、以及与现有 FPS 的冲突。
   - `NormalizeAdditionSets(...)`:  用于规范化要添加的 FPS 集合，处理集合之间的重叠。
   - `FindPrimariesAffectedByAdditions(...)` 和 `FindPrimariesAffectedByReplacements(...)`: 用于识别受添加或替换操作影响的 primary 站点。

8. **遍历 FPS 数据:**
   - `ForEachPublicSetEntry(...)`: 遍历全局的 FPS 条目。
   - `ForEachManualConfigEntry(...)`: 遍历手动配置的 FPS 条目。
   - `ForEachEffectiveSetEntry(...)`: 遍历最终生效的 FPS 条目，会考虑配置覆盖、手动配置和全局 FPS 数据。
   - `ForEachAlias(...)`: 遍历所有的别名。

9. **验证 FPS 集合的有效性:**
   - `IsValid(const FirstPartySetsContextConfig* config) const`:  检查当前的 FPS 集合（考虑可选的配置）是否有效，例如，确保没有站点既是 primary 又是其他站点的成员，没有孤立的成员站点等。

**与 JavaScript 的关系：**

`global_first_party_sets.cc` 本身是用 C++ 编写的，不直接包含 JavaScript 代码。但是，它提供的 FPS 数据 **直接影响** 浏览器的 JavaScript 行为，特别是涉及到以下方面：

* **Cookie 访问:**  JavaScript 可以通过 `document.cookie` API 访问 Cookie。FPS 定义了哪些站点属于同一个 "第一方"。浏览器会根据 FPS 的定义来决定是否允许一个站点访问属于同一个 FPS 中其他站点的 Cookie (尤其是当 `SameSite=Lax` 或 `SameSite=None` 属性与 `Partitioned` 属性结合使用时)。

* **Storage Access (LocalStorage, SessionStorage, IndexedDB):** 类似于 Cookie，FPS 也影响 JavaScript 访问这些存储机制的行为。如果两个站点在同一个 FPS 中，浏览器可能会允许它们共享某些类型的存储。

* **其他 Web API (例如, Network APIs, Permissions API):**  FPS 的概念也可能影响到其他 Web API 的行为，例如决定哪些站点可以被认为是 "相关的"，从而影响权限请求或网络访问策略。

**JavaScript 示例：**

假设以下 FPS 定义（简化）：

```
{
  "https://example.com": { "primary": "https://example.com" },
  "https://associate.example": { "primary": "https://example.com" }
}
```

当 JavaScript 代码在 `https://example.com` 上运行时，它可以设置一个带有 `SameSite=None; Partitioned` 属性的 Cookie。如果用户随后访问 `https://associate.example`，由于这两个站点属于同一个 FPS，`https://associate.example` 上的 JavaScript 代码 **可能** 能够访问 `https://example.com` 设置的 Cookie (取决于具体的浏览器实现和配置)。

**逻辑推理示例：**

假设输入以下内容：

**场景 1: 查找普通站点**

* **输入:**
    * `site`: `https://www.example.com`
    * `entries_` 包含条目: `{"https://www.example.com", FirstPartySetEntry("https://www.example.com", SiteType::kPrimary, std::nullopt)}`
    * `aliases_` 为空
    * `manual_config_` 为空
    * `config` 指向一个空的 `FirstPartySetsContextConfig`

* **输出:** `std::optional` 包含 `FirstPartySetEntry("https://www.example.com", SiteType::kPrimary, std::nullopt)`

**场景 2: 查找别名站点**

* **输入:**
    * `site`: `https://alias.example.com`
    * `entries_` 包含条目: `{"https://canonical.example.com", FirstPartySetEntry("https://canonical.example.com", SiteType::kPrimary, std::nullopt)}`
    * `aliases_` 包含条目: `{"https://alias.example.com", "https://canonical.example.com"}`
    * `manual_config_` 为空
    * `config` 指向一个空的 `FirstPartySetsContextConfig`

* **输出:** `std::optional` 包含 `FirstPartySetEntry("https://canonical.example.com", SiteType::kPrimary, std::nullopt)`

**场景 3: 查找被配置覆盖的站点**

* **输入:**
    * `site`: `https://www.example.com`
    * `entries_` 包含条目: `{"https://www.example.com", FirstPartySetEntry("https://www.example.net", SiteType::kAssociated, std::nullopt)}`
    * `aliases_` 为空
    * `manual_config_` 为空
    * `config` 指向一个 `FirstPartySetsContextConfig`，其中包含针对 `https://www.example.com` 的覆盖规则，将其声明为不属于任何 FPS。

* **输出:** `std::nullopt`

**用户或编程常见的使用错误：**

1. **手动配置错误:**
   - **错误示例:**  在手动配置中，将一个站点既声明为某个 FPS 的 primary，又声明为另一个 FPS 的成员。这会导致 FPS 定义不一致。
   - **后果:**  `IsValid()` 方法会检测到这种错误，并可能导致依赖 FPS 的功能出现异常行为。

2. **误解别名的作用:**
   - **错误示例:**  认为别名站点和规范站点是完全独立的实体，但在 FPS 的上下文中，它们被视为同一个站点。
   - **后果:**  在查询 FPS 信息时，可能会对别名站点的归属产生错误的理解。

3. **不理解配置覆盖的优先级:**
   - **错误示例:**  期望全局 FPS 数据生效，但存在应用于该站点的配置覆盖，导致行为不符合预期。
   - **后果:**  需要仔细检查生效的 `FirstPartySetsContextConfig`，以了解最终的 FPS 定义。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户访问网站:** 当用户在浏览器中输入 URL 或点击链接访问一个网站时，网络栈会开始工作。

2. **请求处理:** 浏览器会向服务器发送 HTTP 请求。

3. **Cookie 和存储访问:**  在请求和响应的过程中，浏览器可能会检查和设置 Cookie。JavaScript 代码也可能尝试访问 LocalStorage、SessionStorage 或 IndexedDB。

4. **FPS 检查:**  在处理 Cookie 和存储访问请求时，浏览器需要确定相关的站点是否属于同一个 FPS。这就会触发对 `GlobalFirstPartySets::FindEntry()` 或 `GlobalFirstPartySets::ComputeMetadata()` 的调用。

5. **配置加载:**  在某些情况下，例如启动浏览器或加载企业策略时，可能会加载或更新 FPS 配置，这可能会涉及到 `GlobalFirstPartySets::ApplyManuallySpecifiedSet()` 或 `GlobalFirstPartySets::ComputeConfig()`。

**调试线索：**

* **网络请求和响应头:**  检查 `Set-Cookie` 头部中的 `SameSite` 和 `Partitioned` 属性，以及请求头中的 `Cookie`。
* **Application 面板 (开发者工具):**  查看 Cookies、LocalStorage、SessionStorage 和 IndexedDB 的内容，观察 FPS 是否影响了它们的隔离。
* **`chrome://settings/cookies/detail` 或 `chrome://settings/siteData`:**  查看特定站点的 Cookie 和站点数据，了解其 FPS 状态。
* **`chrome://flags`:**  某些 FPS 相关的功能可能由实验性标志控制，检查这些标志的设置。
* **`chrome://net-internals/#first-party-sets`:**  这是一个专门用于查看当前浏览器中 FPS 状态的内部页面，可以提供详细的 FPS 配置信息。
* **抓包工具 (如 Wireshark):**  可以用于分析网络请求和响应，更底层地了解 Cookie 的传递情况。

总而言之，`global_first_party_sets.cc` 是 Chromium 中管理 FPS 定义的关键 C++ 组件。它不直接涉及 JavaScript 代码，但其维护的数据直接影响着浏览器中 JavaScript 的行为，特别是与 Cookie 和存储访问相关的安全和隐私特性。 理解这个文件的功能对于调试与 FPS 相关的网络问题至关重要。

Prompt: 
```
这是目录为net/first_party_sets/global_first_party_sets.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/first_party_sets/global_first_party_sets.h"

#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <tuple>
#include <utility>

#include "base/containers/contains.h"
#include "base/containers/flat_map.h"
#include "base/containers/flat_set.h"
#include "base/functional/function_ref.h"
#include "base/not_fatal_until.h"
#include "base/ranges/algorithm.h"
#include "base/types/optional_ref.h"
#include "net/base/schemeful_site.h"
#include "net/first_party_sets/addition_overlaps_union_find.h"
#include "net/first_party_sets/first_party_set_entry.h"
#include "net/first_party_sets/first_party_set_entry_override.h"
#include "net/first_party_sets/first_party_set_metadata.h"
#include "net/first_party_sets/first_party_sets_context_config.h"
#include "net/first_party_sets/first_party_sets_validator.h"
#include "net/first_party_sets/local_set_declaration.h"

namespace net {

namespace {

using FlattenedSets = base::flat_map<SchemefulSite, FirstPartySetEntry>;
using SingleSet = base::flat_map<SchemefulSite, FirstPartySetEntry>;

// Converts a list of First-Party Sets from a SingleSet to a FlattenedSet
// representation.
FlattenedSets Flatten(const std::vector<SingleSet>& set_list) {
  FlattenedSets sets;
  for (const auto& set : set_list) {
    for (const auto& site_and_entry : set) {
      bool inserted = sets.emplace(site_and_entry).second;
      CHECK(inserted);
    }
  }
  return sets;
}

std::pair<SchemefulSite, FirstPartySetEntryOverride>
SiteAndEntryToSiteAndOverride(
    const std::pair<SchemefulSite, FirstPartySetEntry>& pair) {
  return std::make_pair(pair.first, FirstPartySetEntryOverride(pair.second));
}

}  // namespace

GlobalFirstPartySets::GlobalFirstPartySets() = default;

GlobalFirstPartySets::GlobalFirstPartySets(
    base::Version public_sets_version,
    base::flat_map<SchemefulSite, FirstPartySetEntry> entries,
    base::flat_map<SchemefulSite, SchemefulSite> aliases)
    : GlobalFirstPartySets(
          public_sets_version,
          public_sets_version.IsValid()
              ? std::move(entries)
              : base::flat_map<SchemefulSite, FirstPartySetEntry>(),
          public_sets_version.IsValid()
              ? std::move(aliases)
              : base::flat_map<SchemefulSite, SchemefulSite>(),
          FirstPartySetsContextConfig(),
          base::flat_map<SchemefulSite, SchemefulSite>()) {}

GlobalFirstPartySets::GlobalFirstPartySets(
    base::Version public_sets_version,
    base::flat_map<SchemefulSite, FirstPartySetEntry> entries,
    base::flat_map<SchemefulSite, SchemefulSite> aliases,
    FirstPartySetsContextConfig manual_config,
    base::flat_map<SchemefulSite, SchemefulSite> manual_aliases)
    : public_sets_version_(std::move(public_sets_version)),
      entries_(std::move(entries)),
      aliases_(std::move(aliases)),
      manual_config_(std::move(manual_config)),
      manual_aliases_(std::move(manual_aliases)) {
  if (!public_sets_version_.IsValid()) {
    CHECK(entries_.empty());
    CHECK(aliases_.empty());
  }

  CHECK(base::ranges::all_of(aliases_, [&](const auto& pair) {
    return entries_.contains(pair.second);
  }));
  CHECK(IsValid(), base::NotFatalUntil::M130) << "Sets must be valid";
}

GlobalFirstPartySets::GlobalFirstPartySets(GlobalFirstPartySets&&) = default;
GlobalFirstPartySets& GlobalFirstPartySets::operator=(GlobalFirstPartySets&&) =
    default;

GlobalFirstPartySets::~GlobalFirstPartySets() = default;

bool GlobalFirstPartySets::operator==(const GlobalFirstPartySets& other) const =
    default;

bool GlobalFirstPartySets::operator!=(const GlobalFirstPartySets& other) const =
    default;

GlobalFirstPartySets GlobalFirstPartySets::Clone() const {
  return GlobalFirstPartySets(public_sets_version_, entries_, aliases_,
                              manual_config_.Clone(), manual_aliases_);
}

std::optional<FirstPartySetEntry> GlobalFirstPartySets::FindEntry(
    const SchemefulSite& site,
    const FirstPartySetsContextConfig& config) const {
  return FindEntry(site, &config);
}

std::optional<FirstPartySetEntry> GlobalFirstPartySets::FindEntry(
    const SchemefulSite& site,
    const FirstPartySetsContextConfig* config) const {
  // Check if `site` can be found in the customizations first.
  if (config) {
    if (const auto override = config->FindOverride(site);
        override.has_value()) {
      return override->IsDeletion() ? std::nullopt
                                    : std::make_optional(override->GetEntry());
    }
  }

  // Now see if it's in the manual config (with or without a manual alias).
  if (const auto manual_override = manual_config_.FindOverride(site);
      manual_override.has_value()) {
    return manual_override->IsDeletion()
               ? std::nullopt
               : std::make_optional(manual_override->GetEntry());
  }

  // Finally, look up in `entries_`, applying an alias if applicable.
  const auto canonical_it = aliases_.find(site);
  const SchemefulSite& canonical_site =
      canonical_it == aliases_.end() ? site : canonical_it->second;
  if (const auto entry_it = entries_.find(canonical_site);
      entry_it != entries_.end()) {
    return entry_it->second;
  }

  return std::nullopt;
}

base::flat_map<SchemefulSite, FirstPartySetEntry>
GlobalFirstPartySets::FindEntries(
    const base::flat_set<SchemefulSite>& sites,
    const FirstPartySetsContextConfig& config) const {
  std::vector<std::pair<SchemefulSite, FirstPartySetEntry>> sites_to_entries;
  for (const SchemefulSite& site : sites) {
    const std::optional<FirstPartySetEntry> entry = FindEntry(site, config);
    if (entry.has_value()) {
      sites_to_entries.emplace_back(site, entry.value());
    }
  }
  return sites_to_entries;
}

FirstPartySetMetadata GlobalFirstPartySets::ComputeMetadata(
    const SchemefulSite& site,
    base::optional_ref<const SchemefulSite> top_frame_site,
    const FirstPartySetsContextConfig& fps_context_config) const {
  return FirstPartySetMetadata(
      FindEntry(site, fps_context_config),
      top_frame_site ? FindEntry(*top_frame_site, fps_context_config)
                     : std::nullopt);
}

void GlobalFirstPartySets::ApplyManuallySpecifiedSet(
    const LocalSetDeclaration& local_set_declaration) {
  CHECK(manual_config_.empty());
  CHECK(manual_aliases_.empty());
  if (local_set_declaration.empty()) {
    // Nothing to do.
    return;
  }

  base::flat_map<SchemefulSite, SchemefulSite> manual_aliases =
      local_set_declaration.aliases();

  base::flat_map<SchemefulSite, FirstPartySetEntry> manual_entries =
      local_set_declaration.entries();
  for (const auto& [alias, canonical] : manual_aliases) {
    manual_entries.emplace(alias, manual_entries.find(canonical)->second);
  }

  // We handle the manually-specified set the same way as we handle
  // replacement enterprise policy sets.
  manual_config_ = ComputeConfig(SetsMutation(
      /*replacement_sets=*/{manual_entries},
      /*addition_sets=*/{}));
  manual_aliases_ = std::move(manual_aliases);

  CHECK(IsValid(), base::NotFatalUntil::M130) << "Sets must be valid";
}

void GlobalFirstPartySets::UnsafeSetManualConfig(
    FirstPartySetsContextConfig manual_config) {
  CHECK(manual_config_.empty());
  manual_config_ = std::move(manual_config);
}

base::flat_map<SchemefulSite, FirstPartySetEntry>
GlobalFirstPartySets::FindPrimariesAffectedByAdditions(
    const FlattenedSets& additions) const {
  std::vector<std::pair<SchemefulSite, FirstPartySetEntry>>
      addition_intersected_primaries;
  for (const auto& [new_member, new_entry] : additions) {
    if (const auto entry = FindEntry(new_member, /*config=*/nullptr);
        entry.has_value()) {
      // Found an overlap with the existing list of sets.
      addition_intersected_primaries.emplace_back(entry->primary(), new_entry);
    }
  }
  return addition_intersected_primaries;
}

std::pair<base::flat_map<SchemefulSite, base::flat_set<SchemefulSite>>,
          base::flat_set<SchemefulSite>>
GlobalFirstPartySets::FindPrimariesAffectedByReplacements(
    const FlattenedSets& replacements,
    const FlattenedSets& additions,
    const base::flat_map<SchemefulSite, FirstPartySetEntry>&
        addition_intersected_primaries) const {
  if (replacements.empty()) {
    return {{}, {}};
  }

  const auto canonicalize = [&](const SchemefulSite& site) {
    const auto it = aliases_.find(site);
    return it != aliases_.end() ? it->second : site;
  };
  std::map<SchemefulSite, std::set<SchemefulSite>> canonical_to_aliases;
  ForEachAlias([&](const SchemefulSite& alias, const SchemefulSite& canonical) {
    canonical_to_aliases[canonical].insert(alias);
  });
  // Runs the given FunctionRef for all (existing) variants of the given site,
  // i.e. all the aliases and the "canonical" variant.
  const auto for_all_variants =
      [canonical_to_aliases = std::move(canonical_to_aliases),
       canonicalize = std::move(canonicalize)](
          const SchemefulSite& site,
          const base::FunctionRef<void(const SchemefulSite&)> f) {
        const SchemefulSite canonical = canonicalize(site);
        f(canonical);
        if (const auto it = canonical_to_aliases.find(canonical);
            it != canonical_to_aliases.end()) {
          for (const auto& alias : it->second) {
            f(alias);
          }
        }
      };

  // Maps an existing primary site to the members it lost due to replacement.
  base::flat_map<SchemefulSite, base::flat_set<SchemefulSite>>
      potential_singletons;
  // Stores existing primary sites which have left their sets (via
  // replacement), and whose existing members should be removed from the set
  // (excluding any custom sets that those members are involved in).
  base::flat_set<SchemefulSite> replaced_existing_primaries;
  for (const auto& [new_site, unused_entry] : replacements) {
    const auto existing_entry = FindEntry(new_site, /*config=*/nullptr);
    if (!existing_entry.has_value()) {
      continue;
    }
    if (!addition_intersected_primaries.contains(existing_entry->primary()) &&
        !additions.contains(existing_entry->primary()) &&
        !replacements.contains(existing_entry->primary())) {
      // The existing site's primary isn't involved in any of the customized
      // sets, so it might become a singleton (if all of its variants and
      // non-primaries [and their variants] are replaced by the
      // customizations).
      for_all_variants(new_site, [&](const SchemefulSite& variant) {
        if (existing_entry->primary() != variant) {
          potential_singletons[existing_entry->primary()].insert(variant);
        }
      });
    }

    if (existing_entry->primary() == new_site) {
      // `new_site` was a primary in the existing sets, but is in the
      // replacement sets, so its non-primaries (and aliases) might need to be
      // deleted/hidden.
      bool inserted =
          replaced_existing_primaries.emplace(existing_entry->primary()).second;
      CHECK(inserted);
    }
  }

  return std::make_pair(potential_singletons, replaced_existing_primaries);
}

FirstPartySetsContextConfig GlobalFirstPartySets::ComputeConfig(
    const SetsMutation& mutation) const {
  if (base::ranges::all_of(mutation.replacements(), &SingleSet::empty) &&
      base::ranges::all_of(mutation.additions(), &SingleSet::empty)) {
    // Nothing to do.
    return FirstPartySetsContextConfig();
  }

  const FlattenedSets replacements = Flatten(mutation.replacements());
  const FlattenedSets additions =
      Flatten(NormalizeAdditionSets(mutation.additions()));

  // Maps a site to its override.
  std::vector<std::pair<SchemefulSite, FirstPartySetEntryOverride>>
      site_to_override;
  base::ranges::transform(replacements, std::back_inserter(site_to_override),
                          SiteAndEntryToSiteAndOverride);
  base::ranges::transform(additions, std::back_inserter(site_to_override),
                          SiteAndEntryToSiteAndOverride);

  // Maps old primary site to new entry.
  const base::flat_map<SchemefulSite, FirstPartySetEntry>
      addition_intersected_primaries =
          FindPrimariesAffectedByAdditions(additions);

  auto [potential_singletons, replaced_existing_primaries] =
      FindPrimariesAffectedByReplacements(replacements, additions,
                                          addition_intersected_primaries);

  if (!addition_intersected_primaries.empty() ||
      !potential_singletons.empty() || !replaced_existing_primaries.empty()) {
    // Find out which potential singletons are actually singletons; delete
    // members whose primaries left; and reparent the sets that intersected with
    // an addition set.
    // Note: use a null config here, to avoid taking unrelated policy sets into
    // account.
    ForEachEffectiveSetEntry(
        /*config=*/nullptr,
        [&](const SchemefulSite& member, const FirstPartySetEntry& set_entry) {
          // Reparent all sites in any intersecting addition sets.
          if (const auto entry =
                  addition_intersected_primaries.find(set_entry.primary());
              entry != addition_intersected_primaries.end() &&
              !replacements.contains(member)) {
            site_to_override.emplace_back(
                member, FirstPartySetEntry(entry->second.primary(),
                                           member == entry->second.primary()
                                               ? SiteType::kPrimary
                                               : SiteType::kAssociated,
                                           std::nullopt));
          }
          if (member == set_entry.primary())
            return true;
          // Remove non-singletons from the potential list.
          if (const auto entry = potential_singletons.find(set_entry.primary());
              entry != potential_singletons.end() &&
              !entry->second.contains(member)) {
            // This primary lost members, but it still has at least one
            // (`member`), so it's not a singleton.
            potential_singletons.erase(entry);
          }
          // Remove members from sets whose primary left.
          if (replaced_existing_primaries.contains(set_entry.primary()) &&
              !replacements.contains(member) &&
              !addition_intersected_primaries.contains(set_entry.primary())) {
            site_to_override.emplace_back(member, FirstPartySetEntryOverride());
          }

          return true;
        });

    // Any primary remaining in `potential_singleton` is a real singleton, so
    // delete it:
    for (const auto& [primary, members] : potential_singletons) {
      site_to_override.emplace_back(primary, FirstPartySetEntryOverride());
    }
  }

  // For every pre-existing alias that would now refer to a site in the overlay,
  // which is not already contained in the overlay, we explicitly ignore that
  // alias.
  ForEachAlias([&](const SchemefulSite& alias, const SchemefulSite& canonical) {
    if (base::Contains(
            site_to_override, canonical,
            &std::pair<SchemefulSite, FirstPartySetEntryOverride>::first) &&
        !base::Contains(
            site_to_override, alias,
            &std::pair<SchemefulSite, FirstPartySetEntryOverride>::first)) {
      site_to_override.emplace_back(alias, FirstPartySetEntryOverride());
    }
  });

  FirstPartySetsContextConfig config(std::move(site_to_override));
  CHECK(IsValid(&config), base::NotFatalUntil::M130)
      << "Sets must not contain singleton or orphan";
  return config;
}

std::vector<base::flat_map<SchemefulSite, FirstPartySetEntry>>
GlobalFirstPartySets::NormalizeAdditionSets(
    const std::vector<base::flat_map<SchemefulSite, FirstPartySetEntry>>&
        addition_sets) const {
  if (base::ranges::all_of(addition_sets, &SingleSet::empty)) {
    // Nothing to do.
    return {};
  }

  // Find all the addition sets that intersect with any given public set.
  base::flat_map<SchemefulSite, base::flat_set<size_t>> addition_set_overlaps;
  for (size_t set_idx = 0; set_idx < addition_sets.size(); set_idx++) {
    for (const auto& site_and_entry : addition_sets[set_idx]) {
      if (const auto entry =
              FindEntry(site_and_entry.first, /*config=*/nullptr);
          entry.has_value()) {
        addition_set_overlaps[entry->primary()].insert(set_idx);
      }
    }
  }

  // Union together all transitively-overlapping addition sets.
  AdditionOverlapsUnionFind union_finder(addition_sets.size());
  for (const auto& [public_site, addition_set_indices] :
       addition_set_overlaps) {
    for (size_t representative : addition_set_indices) {
      union_finder.Union(*addition_set_indices.begin(), representative);
    }
  }

  // Now build the new addition sets, with all transitive overlaps eliminated.
  std::vector<SingleSet> normalized_additions;
  for (const auto& [rep, children] : union_finder.SetsMapping()) {
    SingleSet normalized = addition_sets[rep];
    const SchemefulSite& rep_primary =
        addition_sets[rep].begin()->second.primary();
    for (size_t child_set_idx : children) {
      for (const auto& child_site_and_entry : addition_sets[child_set_idx]) {
        bool inserted =
            normalized
                .emplace(child_site_and_entry.first,
                         FirstPartySetEntry(rep_primary, SiteType::kAssociated,
                                            std::nullopt))
                .second;
        CHECK(inserted);
      }
    }
    normalized_additions.push_back(normalized);
  }
  return normalized_additions;
}

bool GlobalFirstPartySets::ForEachPublicSetEntry(
    base::FunctionRef<bool(const SchemefulSite&, const FirstPartySetEntry&)> f)
    const {
  for (const auto& [site, entry] : entries_) {
    if (!f(site, entry))
      return false;
  }
  for (const auto& [alias, canonical] : aliases_) {
    auto it = entries_.find(canonical);
    CHECK(it != entries_.end());
    if (!f(alias, it->second))
      return false;
  }
  return true;
}

bool GlobalFirstPartySets::ForEachManualConfigEntry(
    base::FunctionRef<bool(const SchemefulSite&,
                           const FirstPartySetEntryOverride&)> f) const {
  return manual_config_.ForEachCustomizationEntry(f);
}

bool GlobalFirstPartySets::ForEachEffectiveSetEntry(
    const FirstPartySetsContextConfig& config,
    base::FunctionRef<bool(const SchemefulSite&, const FirstPartySetEntry&)> f)
    const {
  return ForEachEffectiveSetEntry(&config, f);
}

bool GlobalFirstPartySets::ForEachEffectiveSetEntry(
    const FirstPartySetsContextConfig* config,
    base::FunctionRef<bool(const SchemefulSite&, const FirstPartySetEntry&)> f)
    const {
  // Policy sets have highest precedence:
  if (config != nullptr) {
    if (!config->ForEachCustomizationEntry(
            [&](const SchemefulSite& site,
                const FirstPartySetEntryOverride& override) {
              if (!override.IsDeletion())
                return f(site, override.GetEntry());
              return true;
            })) {
      return false;
    }
  }

  // Then the manual set:
  if (!manual_config_.ForEachCustomizationEntry(
          [&](const SchemefulSite& site,
              const FirstPartySetEntryOverride& override) {
            if (!override.IsDeletion() && (!config || !config->Contains(site)))
              return f(site, override.GetEntry());
            return true;
          })) {
    return false;
  }

  // Finally, the public sets.
  return ForEachPublicSetEntry([&](const SchemefulSite& site,
                                   const FirstPartySetEntry& entry) {
    if ((!config || !config->Contains(site)) && !manual_config_.Contains(site))
      return f(site, entry);
    return true;
  });
}

void GlobalFirstPartySets::ForEachAlias(
    base::FunctionRef<void(const SchemefulSite&, const SchemefulSite&)> f)
    const {
  for (const auto& [alias, site] : manual_aliases_) {
    f(alias, site);
  }
  for (const auto& [alias, site] : aliases_) {
    if (manual_config_.Contains(alias)) {
      continue;
    }
    f(alias, site);
  }
}

bool GlobalFirstPartySets::IsValid(
    const FirstPartySetsContextConfig* config) const {
  FirstPartySetsValidator validator;
  ForEachEffectiveSetEntry(
      config,
      [&](const SchemefulSite& site, const FirstPartySetEntry& entry) -> bool {
        validator.Update(site, entry.primary());
        return true;
      });

  return validator.IsValid();
}

std::ostream& operator<<(std::ostream& os, const GlobalFirstPartySets& sets) {
  os << "{entries = {";
  for (const auto& [site, entry] : sets.entries_) {
    os << "{" << site.Serialize() << ": " << entry << "}, ";
  }
  os << "}, aliases = {";
  for (const auto& [alias, canonical] : sets.aliases_) {
    os << "{" << alias.Serialize() << ": " << canonical.Serialize() << "}, ";
  }
  os << "}, manual_config = {";
  sets.ForEachManualConfigEntry(
      [&](const net::SchemefulSite& site,
          const FirstPartySetEntryOverride& override) {
        os << "{" << site.Serialize() << ": " << override << "},";
        return true;
      });
  os << "}, manual_aliases = {";
  for (const auto& [alias, canonical] : sets.manual_aliases_) {
    os << "{" << alias.Serialize() << ": " << canonical.Serialize() << "}, ";
  }
  os << "}}";
  return os;
}

}  // namespace net

"""

```