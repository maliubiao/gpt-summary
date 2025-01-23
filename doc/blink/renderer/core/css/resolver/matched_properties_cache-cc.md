Response:
Let's break down the thought process for analyzing this `matched_properties_cache.cc` file.

1. **Understand the Core Purpose:** The name "matched_properties_cache" immediately suggests it's about caching. The location within the `resolver` directory hints at its involvement in CSS property resolution. The comments at the top also point towards style calculations and optimizations.

2. **Identify Key Data Structures:** Look for class definitions and member variables. The main ones that stand out are:
    * `MatchedPropertiesCache`: The central cache class.
    * `CachedMatchedProperties`: Represents a cached set of properties for a specific style.
    * `Key`:  Used to identify entries in the cache.
    * `Entry` (within `CachedMatchedProperties`): Stores the actual cached data (computed styles and last usage time).
    * `cache_` (a `HashMap`): The underlying storage for the cache.
    * `matched_properties` (within `CachedMatchedProperties`):  Stores the `CSSPropertyValueSet` and associated data.

3. **Analyze Key Methods:** Focus on the public methods of `MatchedPropertiesCache` and important internal ones:
    * `Find()`:  The crucial method for retrieving cached data. Pay attention to the checks and conditions for a cache hit.
    * `Add()`:  How new results are added to the cache.
    * `Clear()`:  How the cache is emptied.
    * `IsCacheable()` (two versions): Determines if a style or a style resolution state is eligible for caching. This is important for understanding the cache's limitations.
    * `ComputeMatchedPropertiesHash()`: How the cache key is generated (hashing).
    * `CorrespondsTo()`:  How the cache verifies if a potentially matching entry is actually the right one.
    * `RefreshKey()`:  How the weak pointers in the cache are updated.
    * `CleanMatchedPropertiesCache()`: The garbage collection/pruning mechanism.

4. **Trace the Workflow (Conceptual):** Imagine the steps involved in resolving CSS properties:
    * A style needs to be calculated for an element.
    * The `StyleResolver` (or related component) checks the `MatchedPropertiesCache` using `Find()`.
    * If a hit occurs (a matching `Key` and valid `Entry`), the cached `ComputedStyle` is reused, saving computation.
    * If a miss occurs, the style is calculated, and if `IsCacheable()` returns true, the result is added to the cache using `Add()`.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):** Consider how the cache interacts with these core technologies:
    * **CSS:** The cache stores results related to CSS property matching. Changes in CSS rules can invalidate cached entries.
    * **HTML:** The structure of the HTML document and attributes influence style calculations and therefore the cache. Dynamic HTML changes can lead to cache invalidation.
    * **JavaScript:** JavaScript can manipulate the DOM and CSS styles, which can affect the cache. For example, setting inline styles or changing class names can invalidate cached entries.

6. **Consider Edge Cases and Limitations:**  Examine the `IsCacheable()` methods for conditions that prevent caching. This reveals the situations where the cache is not effective. Think about why these restrictions exist (e.g., dynamic content, dependencies on external factors).

7. **Infer Logic and Assumptions:** Based on the code, make educated guesses about the underlying logic. For example:
    * The use of hashing suggests an optimization for quick lookups.
    * The `clock_` variable implies a Least Recently Used (LRU) eviction strategy.
    * The weak pointers suggest a need to avoid keeping objects alive indefinitely.

8. **Consider Debugging and Error Scenarios:** Think about how a developer might end up investigating this code. What kind of bugs or performance issues might lead them here?  What are common mistakes related to CSS and styling that could interact with the cache?

9. **Structure the Explanation:** Organize the findings into logical sections: functionality, relationship to web technologies, logic/assumptions, common errors, and debugging.

10. **Refine and Elaborate:** Review the initial analysis and add more detail, examples, and explanations to make it clear and comprehensive. For instance, when explaining `IsCacheable()`, provide concrete examples of CSS features that make a style non-cacheable.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  The cache might be very simple, just storing computed styles.
* **Correction:**  Realizing the `Key` includes `MatchedProperties`, it becomes clear the cache is more granular, based on the *matched* CSS rules. This makes it more efficient.
* **Initial thought:**  Cache invalidation might be simple.
* **Correction:**  The `CleanMatchedPropertiesCache` function shows a more complex LRU mechanism and checks for modifications, indicating a more robust invalidation strategy.
* **Initial thought:** The connection to JavaScript might be indirect.
* **Correction:**  Recognizing that JavaScript DOM manipulation directly triggers style recalculations and potentially cache invalidation establishes a stronger relationship.

By following these steps, iterating, and refining the analysis, we can arrive at a comprehensive understanding of the `matched_properties_cache.cc` file and its role in the Blink rendering engine.
这个`blink/renderer/core/css/resolver/matched_properties_cache.cc` 文件实现了 Chromium Blink 引擎中的 **匹配属性缓存 (Matched Properties Cache, MPC)**。它的主要功能是：

**功能：**

1. **缓存 CSS 属性匹配结果:**  当浏览器需要计算一个元素的最终样式时，它需要将 CSS 规则与 HTML 元素进行匹配，找出所有适用于该元素的 CSS 属性及其值。 MPC 缓存了这种匹配的结果，避免在重复的匹配过程中进行昂贵的计算。

2. **提高样式计算性能:** 通过重用之前匹配过的属性，MPC 显著减少了样式计算的时间，从而提升了网页加载和渲染的速度，尤其是在存在大量相似元素或复杂的 CSS 规则时。

3. **作为样式解析的优化手段:**  MPC 是 Blink 样式解析流程中的一个关键优化环节，它通过缓存中间结果来加速整个过程。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **CSS:** MPC 直接与 CSS 相关。它缓存的是 CSS 规则与元素的匹配结果。
    * **例子:** 假设一个网页有多个 `<div>` 元素使用了相同的 CSS 类名，例如 `.box`。当浏览器第一次计算其中一个 `.box` 元素的样式时，MPC 会缓存该类名对应的 CSS 属性匹配结果。当后续计算其他 `.box` 元素的样式时，如果它们满足缓存的条件，MPC 就能直接提供缓存的结果，而无需重新执行 CSS 匹配过程。

* **HTML:**  MPC 的缓存基于 HTML 元素及其相关的 CSS 规则。HTML 结构的变化可能导致缓存失效。
    * **例子:** 如果通过 JavaScript 动态地向一个元素添加或删除 CSS 类名，或者改变元素的 `style` 属性，那么与该元素相关的 MPC 缓存可能会失效，因为元素的匹配属性集合发生了变化。

* **JavaScript:** JavaScript 可以通过操作 DOM 和 CSSOM 来间接地影响 MPC。
    * **例子:**  JavaScript 可以使用 `element.classList.add('new-class')` 来添加新的 CSS 类。这会触发元素的样式重新计算。如果 `new-class` 的匹配结果之前没有被缓存过，则会被添加到 MPC 中。如果 `new-class` 的添加使得之前缓存的匹配结果不再适用，那么缓存可能会被清除或更新。

**逻辑推理与假设输入输出：**

假设我们有一个简单的 HTML 结构和一个 CSS 规则：

```html
<div class="box">Hello</div>
```

```css
.box {
  color: blue;
  font-size: 16px;
}
```

**假设输入:**  浏览器需要计算上述 `<div>` 元素的样式。`MatchedPropertiesCache` 中尚未缓存任何关于 `.box` 类的信息。

**逻辑推理过程:**

1. 样式解析器首先尝试在 MPC 中查找与该元素（及其相关的 CSS 匹配信息）对应的缓存条目。
2. 由于是首次计算，MPC 中没有找到匹配的条目（Cache Miss）。
3. 样式解析器执行完整的 CSS 规则匹配过程，确定 `.box` 类匹配该 `<div>` 元素，并且该规则定义了 `color: blue;` 和 `font-size: 16px;`。
4. 这些匹配的属性（`.box` 对应 `color: blue;` 和 `font-size: 16px;`）以及相关的元数据（例如应用这些属性的样式表规则）被存储到 MPC 中，并与该元素的一些关键信息关联起来（例如元素的类名、当前状态等）。

**假设输出（添加到缓存中的信息）：**

```
Key: { .box -> [color: blue, font-size: 16px] }
Value: {
  ComputedStyle:  指向该 <div> 元素计算出的样式对象 (color: blue, font-size: 16px)
  ParentComputedStyle: 指向父元素的计算出的样式对象
  LastUsedTime:  时间戳
}
```

**假设输入（第二次计算）：**  浏览器需要再次计算同一个 `<div>` 元素的样式，或者计算另一个具有相同类名 `.box` 的 `<div>` 元素的样式，并且相关的条件（例如父元素样式等）没有发生改变。

**逻辑推理过程:**

1. 样式解析器尝试在 MPC 中查找与该元素对应的缓存条目。
2. MPC 中找到了匹配的条目（Cache Hit），因为之前已经缓存了 `.box` 类的匹配结果。
3. MPC 返回缓存的匹配属性信息，避免了重新执行 CSS 规则匹配。
4. 缓存条目的 `LastUsedTime` 被更新。

**假设输出（从缓存中获取的信息）：**

直接从缓存中获取之前计算出的样式信息，或者用于加速后续的样式计算步骤。

**涉及用户或编程常见的使用错误：**

1. **过度依赖内联样式或 JavaScript 修改样式:** 如果开发者频繁地使用 JavaScript 或内联样式来动态修改元素样式，MPC 的命中率会降低，因为这些动态修改通常不会被缓存。
    * **例子:**  在 JavaScript 中使用 `element.style.color = 'red'` 会直接修改元素的样式，绕过了 CSS 规则，使得基于 CSS 规则匹配的 MPC 无法发挥作用。

2. **CSS 选择器过于复杂:**  过于复杂的 CSS 选择器（例如嵌套很深的后代选择器或属性选择器）在匹配时本身就需要更多计算。即使 MPC 缓存了结果，但首次计算的成本仍然较高。

3. **不理解缓存失效机制:**  开发者可能没有意识到某些操作会导致 MPC 缓存失效，从而错误地认为样式计算应该很快。
    * **例子:**  修改了应用于某个元素的 CSS 规则后，与该元素相关的缓存条目会被标记为无效，下次计算时需要重新匹配。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器中打开一个网页:**  浏览器开始解析 HTML，构建 DOM 树。
2. **浏览器解析 CSS:**  浏览器解析 `<style>` 标签或外部 CSS 文件，构建 CSSOM 树。
3. **布局阶段开始:**  浏览器需要计算每个元素的最终样式，这涉及到 CSS 规则的匹配。
4. **样式解析器尝试匹配 CSS 规则到 DOM 元素:**
   * 对于每个元素，样式解析器会遍历相关的 CSS 规则，找出所有匹配该元素的规则。
   * 在这个过程中，会查询 `MatchedPropertiesCache`，尝试找到之前匹配过的结果。
5. **如果找到缓存 (Cache Hit):**  直接使用缓存的结果，跳过重复的匹配计算。
6. **如果没有找到缓存 (Cache Miss):**
   * 执行完整的 CSS 规则匹配过程。
   * 将匹配到的属性和相关信息存储到 `MatchedPropertiesCache` 中。

**调试线索:**

当开发者在 Chrome 的开发者工具中进行性能分析时，可能会看到与样式计算相关的耗时。如果发现样式计算耗时较长，并且怀疑是由于重复的 CSS 匹配导致的，可以关注以下几点：

* **检查是否存在大量的相同或相似元素的样式计算:** 如果有很多元素使用了相同的类名或 CSS 规则，但 MPC 的命中率不高，可能存在问题。
* **查看 CSS 规则的复杂度:**  过于复杂的选择器可能导致匹配过程缓慢，即使有缓存也无法完全避免首次计算的开销。
* **分析 JavaScript 的 DOM 和 CSS 操作:**  频繁的动态样式修改可能会导致缓存失效，降低 MPC 的效率。
* **使用 Chrome 的性能面板 (Performance Panel):**  可以录制网页加载和交互过程，然后在 "Rendering" 或 "Paint" 部分查看样式计算的详细信息，例如哪些样式被重新计算了，哪些可能从缓存中获取了。

总而言之，`matched_properties_cache.cc` 文件是 Blink 引擎中一个重要的性能优化模块，它通过缓存 CSS 属性匹配的结果来加速网页的渲染过程。理解其工作原理和影响因素对于开发高性能的 Web 应用至关重要。

### 提示词
```
这是目录为blink/renderer/core/css/resolver/matched_properties_cache.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 2004-2005 Allan Sandfeld Jensen (kde@carewolf.com)
 * Copyright (C) 2006, 2007 Nicholas Shanks (webkit@nickshanks.com)
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013 Apple Inc.
 * All rights reserved.
 * Copyright (C) 2007 Alexey Proskuryakov <ap@webkit.org>
 * Copyright (C) 2007, 2008 Eric Seidel <eric@webkit.org>
 * Copyright (C) 2008, 2009 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 * Copyright (c) 2011, Code Aurora Forum. All rights reserved.
 * Copyright (C) Research In Motion Limited 2011. All rights reserved.
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/css/resolver/matched_properties_cache.h"

#include <algorithm>
#include <array>
#include <utility>

#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hasher.h"

namespace blink {

static unsigned ComputeMatchedPropertiesHash(const MatchResult& result) {
  DCHECK(result.IsCacheable());
  const MatchedPropertiesHashVector& hashes = result.GetMatchedPropertiesHash();
  DCHECK(!std::any_of(hashes.begin(), hashes.end(),
                      [](const MatchedPropertiesHash& hash) {
                        return hash.hash ==
                               WTF::HashTraits<unsigned>::DeletedValue();
                      }))
      << "This should have been checked in AddMatchedProperties()";
  unsigned hash = StringHasher::HashMemory(base::as_byte_span(hashes));

  // See CSSPropertyValueSet::ComputeHash() for asserts that this is safe.
  if (hash == WTF::HashTraits<unsigned>::EmptyValue() ||
      hash == WTF::HashTraits<unsigned>::DeletedValue()) {
    hash ^= 0x80000000;
  }

  return hash;
}

CachedMatchedProperties::CachedMatchedProperties(
    const ComputedStyle* style,
    const ComputedStyle* parent_style,
    const MatchedPropertiesVector& properties,
    unsigned clock)
    : entries({Entry{style, parent_style, clock}}) {
  matched_properties.ReserveInitialCapacity(properties.size());
  for (const auto& new_matched_properties : properties) {
    matched_properties.emplace_back(new_matched_properties.properties,
                                    new_matched_properties.data_);
  }
}

void CachedMatchedProperties::Clear() {
  matched_properties.clear();
  entries.clear();
}

MatchedPropertiesCache::MatchedPropertiesCache() = default;

MatchedPropertiesCache::Key::Key(const MatchResult& result)
    : Key(result,
          result.IsCacheable() ? ComputeMatchedPropertiesHash(result)
                               : HashTraits<unsigned>::EmptyValue()) {}

MatchedPropertiesCache::Key::Key(const MatchResult& result, unsigned hash)
    : result_(result), hash_(hash) {}

const CachedMatchedProperties::Entry* MatchedPropertiesCache::Find(
    const Key& key,
    const StyleResolverState& style_resolver_state) {
  // Matches the corresponding test in IsStyleCacheable().
  if (style_resolver_state.TextAutosizingMultiplier() != 1.0f) {
    return nullptr;
  }

  Cache::iterator it = cache_.find(key.hash_);
  if (it == cache_.end()) {
    return nullptr;
  }
  CachedMatchedProperties* cache_item = it->value.Get();
  if (!cache_item->CorrespondsTo(key.result_.GetMatchedProperties())) {
    // A hash collision (rare), or the key is not usable anymore.
    // Take out the existing entry entirely and start anew.
    // (We could possibly have reused its memory, but for simplicity,
    // we just treat it as a miss.)
    if (it->value) {
      cache_entries_ -= it->value->entries.size();
    }
    cache_.erase(it);
    return nullptr;
  }
  for (CachedMatchedProperties::Entry& entry : cache_item->entries) {
    if (IsAtShadowBoundary(&style_resolver_state.GetElement()) &&
        entry.parent_computed_style->UserModify() !=
            ComputedStyleInitialValues::InitialUserModify()) {
      // An element at a shadow boundary will reset UserModify() back to its
      // initial value for inheritance. If the cached item was computed for an
      // element not at a shadow boundary, the cached computed style will not
      // have that reset, and we cannot use it as a cache hit unless the parent
      // UserModify() is the initial value.
      continue;
    }
    if ((entry.parent_computed_style->IsEnsuredInDisplayNone() ||
         entry.computed_style->IsEnsuredOutsideFlatTree()) &&
        !style_resolver_state.ParentStyle()->IsEnsuredInDisplayNone() &&
        !style_resolver_state.IsOutsideFlatTree()) {
      // If we cached a ComputedStyle in a display:none subtree, or outside the
      // flat tree,  we would not have triggered fetches for external resources
      // and have StylePendingImages in the ComputedStyle. Instead of having to
      // inspect the cached ComputedStyle for such resources, don't use a cached
      // ComputedStyle when it was cached in display:none but is now rendered.
      continue;
    }
    if (style_resolver_state.ParentStyle()->InheritedDataShared(
            *entry.parent_computed_style)) {
      entry.last_used = clock_++;

      // Since we have a cache hit, refresh it using the most recent property
      // sets (in case they have differing pointers but same content); the key
      // is weak, and using more recently seen sets make it less likely that
      // they will go away and GC the entry.
      //
      // Ideally, we would not be using weak pointers in the MPC at all,
      // but CSSValues keep StyleImages alive (see
      // StyleImageCacheTest.WeakReferenceGC), so if we used regular pointers,
      // we'd need to find some other way of making sure these images do not
      // live forever in the cache.
      cache_item->RefreshKey(key.result_.GetMatchedProperties());

      return &entry;
    }
  }
  return nullptr;
}

bool CachedMatchedProperties::CorrespondsTo(
    const MatchedPropertiesVector& lookup_properties) const {
  if (lookup_properties.size() != matched_properties.size()) {
    return false;
  }

  // These incantations are to make Clang realize it does not have to
  // bounds-check.
  auto lookup_it = lookup_properties.begin();
  auto cached_it = matched_properties.begin();
  for (; lookup_it != lookup_properties.end();
       std::advance(lookup_it, 1), std::advance(cached_it, 1)) {
    CSSPropertyValueSet* cached_properties = cached_it->first.Get();
    DCHECK(!lookup_it->properties->ModifiedSinceHashing())
        << "This should have been checked in AddMatchedProperties()";
    if (cached_properties->ModifiedSinceHashing()) {
      // These properties were mutated as some point after original
      // insertion, so it is not safe to use them in the MPC
      // (Equals() below would be comparing against the current state,
      // not the state it had when the ComputedStyle in the cache
      // was built). Note that this is very unlikely to actually
      // happen in practice, since even getting here would also require
      // a hash collision.
      return false;
    }
    if (!lookup_it->properties->Equals(*cached_properties)) {
      return false;
    }
    if (lookup_it->data_ != cached_it->second) {
      return false;
    }
  }
  return true;
}

void CachedMatchedProperties::RefreshKey(
    const MatchedPropertiesVector& lookup_properties) {
  DCHECK(CorrespondsTo(lookup_properties));
  auto lookup_it = lookup_properties.begin();
  auto cached_it = matched_properties.begin();
  for (; lookup_it != lookup_properties.end();
       std::advance(lookup_it, 1), std::advance(cached_it, 1)) {
    cached_it->first = lookup_it->properties;
  }
}

void MatchedPropertiesCache::Add(const Key& key,
                                 const ComputedStyle* style,
                                 const ComputedStyle* parent_style) {
  Member<CachedMatchedProperties>& cache_item =
      cache_.insert(key.hash_, nullptr).stored_value->value;

  if (!cache_item) {
    cache_item = MakeGarbageCollected<CachedMatchedProperties>(
        style, parent_style, key.result_.GetMatchedProperties(), clock_++);
  } else {
    cache_item->entries.emplace_back(style, parent_style, clock_++);
  }
  ++cache_entries_;
}

void MatchedPropertiesCache::Clear() {
  // MatchedPropertiesCache must be cleared promptly because some
  // destructors in the properties (e.g., ~FontFallbackList) expect that
  // the destructors are called promptly without relying on a GC timing.
  for (auto& cache_entry : cache_) {
    if (cache_entry.value) {
      cache_entry.value->Clear();
    }
  }
  cache_.clear();
  cache_entries_ = 0;
}

void MatchedPropertiesCache::ClearViewportDependent() {
  EraseEntriesIf([](const CachedMatchedProperties::Entry& entry) {
    return entry.computed_style->HasViewportUnits();
  });
}

bool MatchedPropertiesCache::IsStyleCacheable(
    const ComputedStyleBuilder& builder) {
  // Properties with attr() values depend on the attribute value of the
  // originating element, thus we cannot cache based on the matched properties
  // because the value of content is retrieved from the attribute at apply time.
  if (builder.HasAttrFunction()) {
    return false;
  }
  if (builder.Zoom() != ComputedStyleInitialValues::InitialZoom()) {
    return false;
  }
  if (builder.TextAutosizingMultiplier() != 1) {
    return false;
  }
  if (builder.HasContainerRelativeUnits()) {
    return false;
  }
  if (builder.HasAnchorFunctions()) {
    // The result of anchor() and anchor-size() functions can depend on
    // the 'anchor' attribute on the element.
    return false;
  }
  if (builder.HasSiblingFunctions()) {
    // The result of sibling-index() and sibling-count() depends on the
    // element's position in the DOM.
    return false;
  }
  // Avoiding cache for ::highlight styles, and the originating styles they are
  // associated with, because the style depends on the highlight names involved
  // and they're not cached.
  if (builder.HasPseudoElementStyle(kPseudoIdHighlight) ||
      builder.StyleType() == kPseudoIdHighlight) {
    return false;
  }
  return true;
}

bool MatchedPropertiesCache::IsCacheable(const StyleResolverState& state) {
  const ComputedStyle& parent_style = *state.ParentStyle();

  if (!IsStyleCacheable(state.StyleBuilder())) {
    return false;
  }

  // If we allowed styles with explicit inheritance in, we would have to mark
  // them as partial hits (different parents could mean that _non-inherited_
  // properties would need to be reapplied, similar to the situation with
  // ForcedColors). We don't bother tracking this, and instead just never
  // insert them.
  //
  // The “explicit inheritance” flag is stored on the parent, not the style
  // itself, since that's where we need it 90%+ of the time. This means that
  // if we do not know the flat-tree parent, StyleBuilder::ApplyProperty() will
  // not SetChildHasExplicitInheritance() on the parent style, and we do not
  // know whether this flag is true or false. However, the only two cases where
  // this can happen (root element, and unused slots in shadow trees),
  // it doesn't actually matter whether we have explicit inheritance or not,
  // since the parent style is the initial style. So even if the test returns
  // a false positive, that's fine.
  if (parent_style.ChildHasExplicitInheritance()) {
    return false;
  }

  // Matched properties can be equal for style resolves from elements in
  // different TreeScopes if StyleSheetContents is shared between stylesheets in
  // different trees. In those cases ScopedCSSNames need to be constructed with
  // the correct TreeScope and cannot be cached.
  //
  // We used to include TreeScope pointer hashes in the MPC key, but that
  // didn't allow for MPC cache hits across instances of the same web component.
  // That also caused an ever-growing cache because the TreeScopes were not
  // handled in CleanMatchedPropertiesCache().
  // See: https://crbug,com/1473836
  if (state.HasTreeScopedReference()) {
    return false;
  }

  // Do not cache computed styles for shadow root children which have a
  // different UserModify value than its shadow host.
  //
  // UserModify is modified to not inherit from the shadow host for shadow root
  // children. That means that if we get a MatchedPropertiesCache match for a
  // style stored for a shadow root child against a non shadow root child, we
  // would end up with an incorrect match.
  if (IsAtShadowBoundary(&state.GetElement()) &&
      state.StyleBuilder().UserModify() != parent_style.UserModify()) {
    return false;
  }

  // See StyleResolver::ApplyMatchedCache() for comments.
  if (state.UsesHighlightPseudoInheritance()) {
    return false;
  }
  if (!state.GetElement().GetCascadeFilter().IsEmpty()) {
    // The result of applying properties with the same matching declarations can
    // be different if the cascade filter is different.
    return false;
  }

  return true;
}

void MatchedPropertiesCache::Trace(Visitor* visitor) const {
  visitor->Trace(cache_);
  visitor->RegisterWeakCallbackMethod<
      MatchedPropertiesCache,
      &MatchedPropertiesCache::CleanMatchedPropertiesCache>(this);
}

static inline bool ShouldRemoveMPCEntry(CachedMatchedProperties& value,
                                        const LivenessBroker& info) {
  for (const auto& [properties, metadata] : value.matched_properties) {
    if (!info.IsHeapObjectAlive(properties) ||
        properties->ModifiedSinceHashing()) {
      return true;
    }
  }
  return false;
}

// Erase all MPC entries where the given predicate returns true,
// and updates the counter. Removes all keys that have no entries left.
template <class Predicate>
void MatchedPropertiesCache::EraseEntriesIf(Predicate&& pred) {
  cache_.erase_if([inner_pred{std::forward<Predicate>(pred)},
                   this](const auto& entry_pair) {
    if (!entry_pair.value) {
      return false;
    }
    HeapVector<CachedMatchedProperties::Entry, 4>& entries =
        entry_pair.value->entries;
    auto new_end = std::remove_if(entries.begin(), entries.end(), inner_pred);
    cache_entries_ -= entries.end() - new_end;
    if (new_end == entries.begin()) {
      return true;
    } else {
      entries.erase(new_end, entries.end());
      return false;
    }
  });
}

void MatchedPropertiesCache::CleanMatchedPropertiesCache(
    const LivenessBroker& info) {
  constexpr unsigned kCacheLimit = 500;
  constexpr unsigned kPruneCacheTarget = 300;

  if (cache_entries_ <= kCacheLimit) {
    // Fast path with no LRU pruning.
    cache_.erase_if([&info, this](const auto& entry_pair) {
      // A nullptr value indicates that the entry is currently being
      // created; see |MatchedPropertiesCache::Add|. Keep such entries.
      if (!entry_pair.value) {
        return false;
      }
      if (ShouldRemoveMPCEntry(*entry_pair.value, info)) {
        cache_entries_ -= entry_pair.value->entries.size();
        return true;
      }
      return false;
    });
    // Allocation of Oilpan memory is forbidden during executing weak callbacks,
    // so the data structure will not be rehashed here (ShouldShrink() internal
    // to the map returns false during such callbacks). The next
    // insertion/deletion from regular code will take care of shrinking
    // accordingly.
    return;
  }

  // Our MPC is larger than the cap; since GC happens when we are under
  // memory pressure and we are iterating over the entire map already,
  // this is a good time to enforce the cap and remove the entries that
  // are least recently used. In order not to have to do work for every
  // call, we don't prune down to the cap (500 entries), but a little
  // further (300 entries).

  Vector<unsigned> live_entries;
  live_entries.ReserveInitialCapacity(cache_entries_);
  cache_.erase_if([&info, &live_entries, this](const auto& entry_pair) {
    if (!entry_pair.value) {
      return false;
    }
    if (ShouldRemoveMPCEntry(*entry_pair.value, info)) {
      cache_entries_ -= entry_pair.value->entries.size();
      return true;
    } else {
      for (const auto& entry : entry_pair.value->entries) {
        live_entries.emplace_back(entry.last_used);
      }
      return false;
    }
  });

  DCHECK_EQ(live_entries.size(), cache_entries_);

  // If removals didn't take us back under the pruning limit,
  // remove everything older than the 300th newest LRU entry.
  if (live_entries.size() > kPruneCacheTarget) {
    unsigned cutoff_idx = live_entries.size() - kPruneCacheTarget - 1;
    // SAFETY: We just bounds-checked it above.
    std::nth_element(live_entries.begin(),
                     UNSAFE_BUFFERS(live_entries.begin() + cutoff_idx),
                     live_entries.end());
    unsigned min_last_used = live_entries[cutoff_idx];

    EraseEntriesIf(
        [min_last_used](const CachedMatchedProperties::Entry& entry) {
          return entry.last_used <= min_last_used;
        });
  }
}

std::ostream& operator<<(std::ostream& stream,
                         MatchedPropertiesCache::Key& key) {
  stream << "Key{";
  for (const MatchedProperties& matched_properties :
       key.result_.GetMatchedProperties()) {
    stream << matched_properties.properties->AsText();
    stream << ",";
  }
  stream << "}";
  return stream;
}

}  // namespace blink
```