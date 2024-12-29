Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

**1. Initial Understanding and Goal:**

The core request is to understand the functionality of `v8_code_cache.cc` within the Chromium Blink rendering engine. This immediately suggests a focus on how JavaScript code execution is optimized using caching. The keywords "v8" and "cache" are prominent.

**2. High-Level Skim and Keyword Spotting:**

I started by skimming the code, looking for recognizable patterns and keywords. This helps to quickly grasp the main themes. Key observations were:

* **Includes:**  The included headers provide clues. `v8.h`, `module_record.h`, `classic_script.h`, `cached_metadata.h`, `code_cache_host.h`, `web_settings.h`, `features.h`, `histogram_functions.h`, etc. These point to interactions with V8, script management, caching mechanisms, feature flags, and performance metrics.
* **Namespaces:**  The code is within the `blink` namespace.
* **Classes and Functions:**  The `V8CodeCache` class is the central focus. Functions like `GetCompileOptions`, `ProduceCache`, `HasCodeCache`, `HasHotTimestamp`, `SetCacheTimeStamp`, `GenerateFullCodeCache`, and the `TagFor...` functions stand out.
* **Enums:** `CacheTagKind`, `DetailFlags`, and the nested enums like `GetMetadataType` and `ProduceCacheOptions` indicate different states and options related to the code cache.
* **Constants:**  `kMinimalCodeLength`, histogram names (`kCacheGetHistogram`, `kCacheSetHistogram`).
* **Feature Flags:** Mentions of `kConfigurableV8CodeCacheHotHours`, `kLocalCompileHints`, `kProduceCompileHints2`.
* **V8 API Calls:**  Calls to `v8::ScriptCompiler::...` functions like `CreateCodeCache`, `CompileUnboundScript`, `CachedDataVersionTag`.

**3. Categorizing Functionality:**

Based on the initial skim, I started to categorize the functions into logical groups:

* **Cache Management (Reading/Checking):**  Functions like `HasCodeCache`, `HasHotTimestamp`, `HasCompileHints`, `GetCachedMetadata`, `ReadGetMetadataType`.
* **Cache Management (Writing/Setting):** Functions like `ProduceCache`, `SetCacheTimeStamp`, `SetCachedMetadata` (implicitly used within `ProduceCache`).
* **Compilation Options:** Functions related to determining how scripts should be compiled, especially with caching considerations (`GetCompileOptions`).
* **Tagging and Metadata:** Functions for generating and interpreting cache tags (`TagFor...`), and handling metadata like timestamps and flags (`DetailFlags`).
* **Metrics and Debugging:**  Histogram recording functions (`RecordCacheGetStatistics`, `RecordCacheSetStatistics`), and the use of trace events.
* **Full Code Cache Generation:** The specialized `GenerateFullCodeCache` function.

**4. Detailed Analysis of Key Functions and Concepts:**

For each category, I dove into the specifics:

* **`GetCompileOptions`:** I recognized the logic for deciding whether to use the code cache, generate it, or just store a timestamp. The influence of feature flags and the `V8CacheOptions` enum was apparent. The different `NoCacheReason` values also provided insights.
* **`ProduceCache`:**  The core function for writing cache data. The different `ProduceCacheOptions` and the use of `v8::ScriptCompiler::CreateCodeCache` were key.
* **`HasHotTimestamp`:** The logic for checking the recency of cached timestamps and compile hints.
* **Cache Tags:** Understanding how the tags are constructed using `CacheTagKind` and the script encoding was important.
* **Feature Flags:**  Noting how feature flags like `kLocalCompileHints` and `kProduceCompileHints2` modify the caching behavior.

**5. Connecting to JavaScript, HTML, and CSS:**

This required understanding how these web technologies interact with the code cache:

* **JavaScript:**  The primary beneficiary of the code cache. Examples showing how the cache speeds up script execution on subsequent visits were straightforward.
* **HTML:**  The `<script>` tag is the entry point for JavaScript. The `src` attribute (external scripts) and inline scripts have different caching characteristics.
* **CSS:**  While not directly cached by this module, I considered the indirect relationship where faster JavaScript execution can improve overall page load performance, including rendering and CSS application. I initially thought about *if* CSS was related, and concluded the connection was indirect but worth mentioning in the broader context of web performance.

**6. Logical Reasoning (Input/Output):**

For functions like `HasHotTimestamp` or `HasCodeCache`, I considered simple inputs (a `CachedMetadataHandler` or `CachedMetadata` object) and the boolean output. For `GetCompileOptions`, the input is more complex (various options and the `ClassicScript` object), and the output is a tuple of compilation settings.

**7. Common User/Programming Errors:**

I thought about common mistakes developers might make that would interact with the code cache:

* **Cache-Control Headers:** Incorrect headers preventing caching.
* **Service Workers:** How service workers can interfere with or enhance caching.
* **Code Changes Without Versioning:**  Leading to cache invalidation issues.
* **Testing with Disabled Cache:**  Forgetting that local testing might not reflect real-world caching behavior.

**8. Debugging Steps:**

I considered how a developer might arrive at this code during debugging:

* **Performance Issues:**  Investigating slow script execution.
* **Cache Invalidation Problems:**  Troubleshooting why cached scripts aren't being updated.
* **Feature Flag Experiments:**  Verifying the behavior of code cache-related flags.
* **Following Call Stacks:** Using developer tools to trace script loading and compilation.

**9. Structuring the Explanation:**

Finally, I organized the information logically, using headings and bullet points to make it easier to read and understand. I aimed for a clear and comprehensive explanation, covering the various aspects of the code. The structure followed the prompts in the original request: functionality, relation to web technologies, logical reasoning, common errors, and debugging.

**Self-Correction/Refinement:**

During the process, I might have initially focused too much on the V8 internals. I then realized the importance of explaining the *Blink* context and how this code fits into the broader rendering pipeline. I also made sure to explicitly connect the code to the user's web browsing experience and developer workflows. I also refined the language to be more accessible and less overly technical where possible.
好的，让我们来详细分析一下 `blink/renderer/bindings/core/v8/v8_code_cache.cc` 这个文件的功能。

**文件功能概述:**

`v8_code_cache.cc` 文件在 Chromium Blink 渲染引擎中负责管理 JavaScript 代码的缓存机制。它的主要功能是：

1. **存储和检索 JavaScript 代码的编译结果 (Code Cache):**  为了提高页面加载速度和脚本执行效率，Blink 会将 JavaScript 代码编译后的结果缓存起来。当下次加载相同的脚本时，可以直接使用缓存的编译结果，避免重复编译。
2. **存储和检索 JavaScript 代码的编译提示 (Compile Hints):** 除了完整的编译结果，Blink 还可以存储一些编译提示信息。这些提示可以帮助 V8 引擎在后续编译过程中做出更优的决策，即使没有完整的代码缓存。
3. **管理代码缓存的生命周期:**  例如，决定何时生成、存储、使用和清除代码缓存。
4. **与 V8 引擎交互:**  调用 V8 引擎的 API 来创建和使用代码缓存。
5. **集成到 Blink 的加载流程:** 在资源加载过程中，判断是否可以使用缓存，并将缓存的数据传递给 V8 引擎。
6. **记录缓存相关的统计信息:**  用于监控缓存的命中率、性能影响等。
7. **支持不同的缓存策略:**  例如，根据资源的“热度”来决定是否缓存。
8. **处理与缓存相关的配置选项:**  例如，是否启用代码缓存，以及缓存的过期时间等。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**  这是此文件直接关联的核心。
    * **功能举例:** 当浏览器加载一个包含 JavaScript 代码的网页时，`v8_code_cache.cc` 会检查这个脚本是否有可用的代码缓存。
        * **假设输入:**  浏览器请求 `example.com/script.js`，并且该脚本之前已经被加载过并成功缓存。
        * **输出:**  `v8_code_cache.cc` 从缓存中读取编译后的代码，并将其传递给 V8 引擎执行，而不是重新编译源代码。
    * **功能举例:**  如果代码缓存不存在或者过期，并且满足一定的条件 (例如，脚本足够大，并且最近被执行过)，`v8_code_cache.cc` 会指示 V8 引擎生成代码缓存，并将结果存储起来。
        * **假设输入:**  浏览器首次请求 `example.com/new_script.js`。
        * **输出:**  `v8_code_cache.cc` 在脚本执行完成后，调用 V8 引擎的 API 生成代码缓存，并将缓存数据写入到存储系统中。
    * **功能举例 (编译提示):**  如果代码缓存不可用，但存在编译提示，`v8_code_cache.cc` 会将这些提示传递给 V8 引擎，帮助其进行更优化的编译。
        * **假设输入:**  浏览器请求 `example.com/infrequent_script.js`，该脚本不满足生成完整代码缓存的条件，但之前生成过编译提示。
        * **输出:** `v8_code_cache.cc` 从缓存中读取编译提示，并将其传递给 V8 引擎用于编译 `infrequent_script.js`。

* **HTML:**  HTML 中的 `<script>` 标签引入 JavaScript 代码，因此与代码缓存机制间接相关。
    * **功能举例:**  当浏览器解析 HTML 文档，遇到 `<script src="script.js"></script>` 时，会触发资源加载流程，最终可能会调用 `v8_code_cache.cc` 来处理该脚本的代码缓存。
    * **用户操作:** 用户在地址栏输入 `example.com` 并按下回车，服务器返回包含上述 `<script>` 标签的 HTML。
    * **调试线索:**  如果页面加载缓慢，开发者可能会检查 Network 面板，发现 `script.js` 的加载时间很长。进一步调试可能会进入 Blink 的源代码，最终发现 `v8_code_cache.cc` 中的逻辑在判断是否可以使用缓存。

* **CSS:**  CSS 本身不通过 `v8_code_cache.cc` 直接缓存。但 JavaScript 可以操作 CSS，而 `v8_code_cache.cc` 优化了 JavaScript 的执行，间接地可能影响 CSS 的应用速度。
    * **功能举例:**  一个网页使用了大量的 JavaScript 来实现动态样式效果。如果这些 JavaScript 代码的代码缓存命中，执行速度会更快，从而更快地应用 CSS 样式。
    * **用户操作:** 用户与网页上的交互触发了大量的 JavaScript 代码执行，这些代码会修改元素的 CSS 样式。
    * **调试线索:**  如果动态样式效果的响应很慢，开发者可能会首先检查 JavaScript 代码的性能，包括是否使用了代码缓存。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  `V8CodeCache::HasHotTimestamp(cache_handler)` 被调用，`cache_handler` 指向一个包含了最近 24 小时内存储的时间戳的缓存元数据。
* **输出:**  `HasHotTimestamp` 函数返回 `true`，因为时间戳在“热”时间范围内 (默认 72 小时，但可以通过 Feature Flag `kConfigurableV8CodeCacheHotHours` 配置)。

* **假设输入:** `V8CodeCache::GetCompileOptions` 被调用，`cache_options` 为 `mojom::blink::V8CacheOptions::kCode`，并且对应的脚本的缓存处理器 (`cache_handler`) 中存在一个“冷”的时间戳 (超过热时间范围)。
* **输出:** `GetCompileOptions` 函数会返回一个元组，其中包含的编译选项会指示 V8 引擎 **不使用** 代码缓存，并且 `ProduceCacheOptions` 会设置为 `kSetTimeStamp`，意味着在脚本执行后会更新时间戳，但不会立即生成代码缓存。

**用户或编程常见的使用错误及举例说明:**

* **错误使用场景:** 开发者在本地开发环境频繁修改 JavaScript 代码，但浏览器缓存没有被正确清理，导致浏览器仍然使用旧的代码缓存，出现与预期不符的行为。
    * **用户操作:** 开发者修改了 `script.js` 文件，然后在浏览器中刷新页面。
    * **问题:** 浏览器可能仍然加载旧版本的 `script.js` 的代码缓存。
    * **解决方法:**  开发者需要清除浏览器缓存或使用开发者工具中的“禁用缓存”选项进行测试。

* **错误使用场景:**  网站配置了不合适的 HTTP 缓存头，例如 `Cache-Control: no-cache` 或 `Cache-Control: no-store`，这会阻止浏览器缓存 JavaScript 代码，包括代码缓存，从而降低性能。
    * **用户操作:** 用户访问一个配置了错误缓存头的网站。
    * **问题:**  每次加载页面，JavaScript 代码都需要重新编译，即使代码没有改变。
    * **解决方法:**  网站开发者需要配置正确的 HTTP 缓存头，例如 `Cache-Control: public, max-age=...`。

* **编程错误:**  Service Worker 的不当使用可能会干扰代码缓存。例如，Service Worker 总是返回网络请求而不检查缓存，或者错误地缓存了旧版本的代码。
    * **用户操作:** 用户访问一个使用了 Service Worker 的网站。
    * **问题:**  即使浏览器有可用的代码缓存，Service Worker 也可能绕过缓存，导致性能下降。
    * **解决方法:**  开发者需要仔细设计 Service Worker 的缓存策略，确保代码缓存能够被有效利用。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设一个用户访问一个网页，并且开发者发现该网页的 JavaScript 执行性能不佳。以下是用户操作和可能的调试步骤，最终可能会涉及到 `v8_code_cache.cc`：

1. **用户操作:** 用户在浏览器地址栏输入网址 `slow-example.com` 并按下回车。
2. **浏览器行为:** 浏览器开始请求 `slow-example.com` 的 HTML 文档。
3. **HTML 解析:** 浏览器接收到 HTML 文档并开始解析，遇到 `<script src="app.js"></script>` 标签。
4. **资源请求:** 浏览器发起对 `app.js` 的请求。
5. **缓存检查 (HTTP 缓存):** 浏览器首先检查 HTTP 缓存，看是否有 `app.js` 的有效副本。
6. **代码缓存检查:**  如果 HTTP 缓存没有命中，或者需要重新验证，浏览器会下载 `app.js`。在下载完成后，Blink 引擎会检查是否存在 `app.js` 的代码缓存。这部分逻辑就在 `v8_code_cache.cc` 中。
7. **`V8CodeCache::HasCodeCache` 调用:**  `v8_code_cache.cc` 中的 `HasCodeCache` 函数会被调用，检查缓存系统中是否存在与 `app.js` 对应的代码缓存。
8. **缓存读取:** 如果代码缓存存在且有效，`v8_code_cache.cc` 会读取缓存的数据。
9. **V8 编译 (如果缓存未命中):** 如果代码缓存不存在或已过期，V8 引擎会开始编译 `app.js` 的源代码。`v8_code_cache.cc` 中的 `GetCompileOptions` 函数会根据配置和缓存状态，决定编译选项。
10. **代码执行:** V8 引擎执行编译后的 JavaScript 代码。
11. **生成代码缓存 (如果适用):**  如果配置允许且满足条件，`v8_code_cache.cc` 中的 `ProduceCache` 函数会被调用，指示 V8 引擎生成代码缓存并存储起来。

**调试线索:**

* **Performance 面板:** 开发者可以使用 Chrome 开发者工具的 Performance 面板来分析页面加载和脚本执行的耗时。如果脚本的 “Scripting” 时间很长，可能意味着代码缓存没有命中或者编译时间过长。
* **Network 面板:** 开发者可以查看 Network 面板，确认 `app.js` 的加载状态和时间，以及 HTTP 缓存头信息。
* **`chrome://v8-cache`:**  在 Chrome 浏览器中输入 `chrome://v8-cache` 可以查看 V8 代码缓存的状态，例如缓存命中率和已缓存的脚本数量。
* **Blink 源代码调试:**  如果需要深入了解代码缓存的细节，开发者可以使用 Chromium 的源代码调试工具，设置断点在 `v8_code_cache.cc` 中的关键函数 (例如 `HasCodeCache`, `GetCompileOptions`, `ProduceCache`)，来跟踪代码的执行流程，查看缓存的读取和写入过程。

希望以上分析能够帮助你理解 `blink/renderer/bindings/core/v8/v8_code_cache.cc` 文件的功能和作用。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/v8_code_cache.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/bindings/core/v8/v8_code_cache.h"

#include <optional>

#include "base/containers/span_reader.h"
#include "base/feature_list.h"
#include "base/metrics/histogram_functions.h"
#include "build/build_config.h"
#include "components/miracle_parameter/common/public/miracle_parameter.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/v8_cache_options.mojom-blink.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/renderer/bindings/core/v8/module_record.h"
#include "third_party/blink/renderer/bindings/core/v8/referrer_script_info.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_initializer.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/loader/fetch/cached_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/code_cache_host.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"

namespace blink {

namespace {

BASE_FEATURE(kConfigurableV8CodeCacheHotHours,
             "ConfigurableV8CodeCacheHotHours",
             base::FEATURE_DISABLED_BY_DEFAULT);

MIRACLE_PARAMETER_FOR_INT(GetV8CodeCacheHotHours,
                          kConfigurableV8CodeCacheHotHours,
                          "HotHours",
                          72)

enum CacheTagKind {
  kCacheTagCode = 0,
  kCacheTagTimeStamp = 1,
  kCacheTagCompileHints = 2,
  kCacheTagLast
};

static const int kCacheTagKindSize = 2;

static_assert((1 << kCacheTagKindSize) >= kCacheTagLast,
              "CacheTagLast must be large enough");

uint32_t CacheTag(CacheTagKind kind, const String& encoding) {
  static uint32_t v8_cache_data_version =
      v8::ScriptCompiler::CachedDataVersionTag() << kCacheTagKindSize;

  // A script can be (successfully) interpreted with different encodings,
  // depending on the page it appears in. The cache doesn't know anything
  // about encodings, but the cached data is specific to one encoding. If we
  // later load the script from the cache and interpret it with a different
  // encoding, the cached data is not valid for that encoding.
  return (v8_cache_data_version | kind) +
         (encoding.IsNull() ? 0 : WTF::GetHash(encoding));
}

bool TimestampIsRecent(const CachedMetadata* cached_metadata) {
  const base::TimeDelta kHotHours = base::Hours(GetV8CodeCacheHotHours());
  base::SpanReader reader(cached_metadata->Data());
  uint64_t time_stamp_ms;
  CHECK(reader.ReadU64NativeEndian(time_stamp_ms));
  base::TimeTicks time_stamp =
      base::TimeTicks() + base::Milliseconds(time_stamp_ms);
  return (base::TimeTicks::Now() - time_stamp) < kHotHours;
}

// Flags that can be set in the CacheMetadata header, describing how the code
// cache data was produced so that the consumer can generate better trace
// messages.
enum class DetailFlags : uint64_t {
  kNone = 0,
  kFull = 1,
};

V8CodeCache::GetMetadataType ReadGetMetadataType(
    const CachedMetadataHandler* cache_handler) {
  // Check the metadata types in the same preference order they're checked in
  // the code: code cache, local compile hints, timestamp. That way we get the
  // right sample in case several metadata types are set.
  uint32_t code_cache_tag = V8CodeCache::TagForCodeCache(cache_handler);
  if (cache_handler
          ->GetCachedMetadata(code_cache_tag,
                              CachedMetadataHandler::kAllowUnchecked)
          .get()) {
    return V8CodeCache::GetMetadataType::kCodeCache;
  }
  scoped_refptr<CachedMetadata> cached_metadata =
      cache_handler->GetCachedMetadata(
          V8CodeCache::TagForCompileHints(cache_handler),
          CachedMetadataHandler::kAllowUnchecked);
  if (cached_metadata) {
    return TimestampIsRecent(cached_metadata.get())
               ? V8CodeCache::GetMetadataType::
                     kLocalCompileHintsWithHotTimestamp
               : V8CodeCache::GetMetadataType::
                     kLocalCompileHintsWithColdTimestamp;
  }
  cached_metadata = cache_handler->GetCachedMetadata(
      V8CodeCache::TagForTimeStamp(cache_handler),
      CachedMetadataHandler::kAllowUnchecked);
  if (cached_metadata) {
    return TimestampIsRecent(cached_metadata.get())
               ? V8CodeCache::GetMetadataType::kHotTimestamp
               : V8CodeCache::GetMetadataType::kColdTimestamp;
  }
  return V8CodeCache::GetMetadataType::kNone;
}

V8CodeCache::GetMetadataType ReadGetMetadataType(
    const CachedMetadata* cached_metadata,
    const String& encoding) {
  if (!cached_metadata) {
    return V8CodeCache::GetMetadataType::kNone;
  }

  // Check the metadata types in the same preference order they're checked in
  // the code: code cache, local compile hints, timestamp. That way we get the
  // right sample in case several metadata types are set.
  if (cached_metadata->DataTypeID() == CacheTag(kCacheTagCode, encoding)) {
    return V8CodeCache::GetMetadataType::kCodeCache;
  }

  if (cached_metadata->DataTypeID() ==
      CacheTag(kCacheTagCompileHints, encoding)) {
    return TimestampIsRecent(cached_metadata)
               ? V8CodeCache::GetMetadataType::
                     kLocalCompileHintsWithHotTimestamp
               : V8CodeCache::GetMetadataType::
                     kLocalCompileHintsWithColdTimestamp;
  }

  if (cached_metadata->DataTypeID() == CacheTag(kCacheTagTimeStamp, encoding)) {
    return TimestampIsRecent(cached_metadata)
               ? V8CodeCache::GetMetadataType::kHotTimestamp
               : V8CodeCache::GetMetadataType::kColdTimestamp;
  }
  return V8CodeCache::GetMetadataType::kNone;
}

constexpr const char* kCacheGetHistogram =
    "WebCore.Scripts.V8CodeCacheMetadata.Get";
constexpr const char* kCacheSetHistogram =
    "WebCore.Scripts.V8CodeCacheMetadata.Set";

}  // namespace

// Check previously stored timestamp (either from the code cache or compile
// hints cache).
bool V8CodeCache::HasHotTimestamp(const CachedMetadataHandler* cache_handler) {
  if (!cache_handler) {
    return false;
  }
  scoped_refptr<CachedMetadata> cached_metadata =
      cache_handler->GetCachedMetadata(
          V8CodeCache::TagForTimeStamp(cache_handler),
          CachedMetadataHandler::kAllowUnchecked);
  if (cached_metadata) {
    return TimestampIsRecent(cached_metadata.get());
  }
  cached_metadata = cache_handler->GetCachedMetadata(
      V8CodeCache::TagForCompileHints(cache_handler),
      CachedMetadataHandler::kAllowUnchecked);
  if (cached_metadata) {
    return TimestampIsRecent(cached_metadata.get());
  }
  return false;
}

bool V8CodeCache::HasHotTimestamp(const CachedMetadata& data,
                                  const String& encoding) {
  if (data.DataTypeID() != CacheTag(kCacheTagCompileHints, encoding) &&
      data.DataTypeID() != CacheTag(kCacheTagTimeStamp, encoding)) {
    return false;
  }
  return TimestampIsRecent(&data);
}

bool V8CodeCache::HasCodeCache(
    const CachedMetadataHandler* cache_handler,
    CachedMetadataHandler::GetCachedMetadataBehavior behavior) {
  if (!cache_handler)
    return false;

  uint32_t code_cache_tag = V8CodeCache::TagForCodeCache(cache_handler);
  return cache_handler->GetCachedMetadata(code_cache_tag, behavior).get();
}

bool V8CodeCache::HasCodeCache(const CachedMetadata& data,
                               const String& encoding) {
  return data.DataTypeID() == CacheTag(kCacheTagCode, encoding);
}

bool V8CodeCache::HasCompileHints(
    const CachedMetadataHandler* cache_handler,
    CachedMetadataHandler::GetCachedMetadataBehavior behavior) {
  if (!cache_handler) {
    return false;
  }

  uint32_t code_cache_tag = V8CodeCache::TagForCompileHints(cache_handler);
  scoped_refptr<CachedMetadata> cached_metadata =
      cache_handler->GetCachedMetadata(code_cache_tag, behavior);
  if (!cached_metadata) {
    return false;
  }
  return true;
}

bool V8CodeCache::HasHotCompileHints(const CachedMetadata& data,
                                     const String& encoding) {
  if (data.DataTypeID() != CacheTag(kCacheTagCompileHints, encoding)) {
    return false;
  }
  return TimestampIsRecent(&data);
}

std::unique_ptr<v8::ScriptCompiler::CachedData> V8CodeCache::CreateCachedData(
    const CachedMetadataHandler* cache_handler) {
  return V8CodeCache::CreateCachedData(GetCachedMetadata(cache_handler));
}

std::unique_ptr<v8::ScriptCompiler::CachedData> V8CodeCache::CreateCachedData(
    scoped_refptr<CachedMetadata> cached_metadata) {
  DCHECK(cached_metadata);
  base::span<const uint8_t> metadata = cached_metadata->Data();
  return std::make_unique<v8::ScriptCompiler::CachedData>(
      metadata.data(), base::checked_cast<int>(metadata.size()),
      v8::ScriptCompiler::CachedData::BufferNotOwned);
}

scoped_refptr<CachedMetadata> V8CodeCache::GetCachedMetadata(
    const CachedMetadataHandler* cache_handler,
    CachedMetadataHandler::GetCachedMetadataBehavior behavior) {
  DCHECK(cache_handler);
  uint32_t code_cache_tag = V8CodeCache::TagForCodeCache(cache_handler);
  scoped_refptr<CachedMetadata> cached_metadata =
      cache_handler->GetCachedMetadata(code_cache_tag, behavior);
  DCHECK(cached_metadata);
  return cached_metadata;
}

scoped_refptr<CachedMetadata> V8CodeCache::GetCachedMetadataForCompileHints(
    const CachedMetadataHandler* cache_handler,
    CachedMetadataHandler::GetCachedMetadataBehavior behavior) {
  CHECK(cache_handler);
  uint32_t code_cache_tag = V8CodeCache::TagForCompileHints(cache_handler);
  scoped_refptr<CachedMetadata> cached_metadata =
      cache_handler->GetCachedMetadata(code_cache_tag, behavior);
  CHECK(cached_metadata);
  return cached_metadata;
}

namespace {

bool CanAddCompileHintsMagicToCompileOption(
    v8::ScriptCompiler::CompileOptions compile_options) {
  // Adding compile hints to kConsumeCodeCache or kEagerCompile doesn't make
  // sense. kProduceCompileHints and kConsumeCompileHints can be combined with
  // kFollowCompileHintsMagicComment, since they still affect scripts which
  // don't have the magic comment.

  // This fails if new compile options are added.
  DCHECK((compile_options &
          ~(v8::ScriptCompiler::CompileOptions::kConsumeCodeCache |
            v8::ScriptCompiler::CompileOptions::kEagerCompile |
            v8::ScriptCompiler::CompileOptions::kProduceCompileHints |
            v8::ScriptCompiler::CompileOptions::kConsumeCompileHints)) == 0);

  return (compile_options &
          (v8::ScriptCompiler::CompileOptions::kConsumeCodeCache |
           v8::ScriptCompiler::CompileOptions::kEagerCompile)) == 0;
}

std::tuple<v8::ScriptCompiler::CompileOptions,
           V8CodeCache::ProduceCacheOptions,
           v8::ScriptCompiler::NoCacheReason>
MaybeAddCompileHintsMagic(
    std::tuple<v8::ScriptCompiler::CompileOptions,
               V8CodeCache::ProduceCacheOptions,
               v8::ScriptCompiler::NoCacheReason> input,
    v8_compile_hints::MagicCommentMode magic_comment_mode) {
  auto [compile_options, produce_cache_options, no_cache_reason] = input;
  if (CanAddCompileHintsMagicToCompileOption(compile_options) &&
      (magic_comment_mode == v8_compile_hints::MagicCommentMode::kAlways ||
       (magic_comment_mode ==
            v8_compile_hints::MagicCommentMode::kWhenProducingCodeCache &&
        produce_cache_options ==
            V8CodeCache::ProduceCacheOptions::kProduceCodeCache))) {
    return std::make_tuple(
        v8::ScriptCompiler::CompileOptions(
            compile_options |
            v8::ScriptCompiler::kFollowCompileHintsMagicComment),
        produce_cache_options, no_cache_reason);
  }
  return input;
}

}  // namespace

std::tuple<v8::ScriptCompiler::CompileOptions,
           V8CodeCache::ProduceCacheOptions,
           v8::ScriptCompiler::NoCacheReason>
V8CodeCache::GetCompileOptions(
    mojom::blink::V8CacheOptions cache_options,
    const ClassicScript& classic_script,
    bool might_generate_crowdsourced_compile_hints,
    bool can_use_crowdsourced_compile_hints,
    v8_compile_hints::MagicCommentMode magic_comment_mode) {
  return MaybeAddCompileHintsMagic(
      GetCompileOptionsInternal(cache_options, classic_script.CacheHandler(),
                                classic_script.SourceText().length(),
                                classic_script.SourceLocationType(),
                                classic_script.SourceUrl(),
                                might_generate_crowdsourced_compile_hints,
                                can_use_crowdsourced_compile_hints),
      magic_comment_mode);
}

std::tuple<v8::ScriptCompiler::CompileOptions,
           V8CodeCache::ProduceCacheOptions,
           v8::ScriptCompiler::NoCacheReason>
V8CodeCache::GetCompileOptions(
    mojom::blink::V8CacheOptions cache_options,
    const CachedMetadataHandler* cache_handler,
    size_t source_text_length,
    ScriptSourceLocationType source_location_type,
    const KURL& url,
    bool might_generate_crowdsourced_compile_hints,
    bool can_use_crowdsourced_compile_hints,
    v8_compile_hints::MagicCommentMode magic_comment_mode) {
  return MaybeAddCompileHintsMagic(
      GetCompileOptionsInternal(cache_options, cache_handler,
                                source_text_length, source_location_type, url,
                                might_generate_crowdsourced_compile_hints,
                                can_use_crowdsourced_compile_hints),
      magic_comment_mode);
}

std::tuple<v8::ScriptCompiler::CompileOptions,
           V8CodeCache::ProduceCacheOptions,
           v8::ScriptCompiler::NoCacheReason>
V8CodeCache::GetCompileOptionsInternal(
    mojom::blink::V8CacheOptions cache_options,
    const CachedMetadataHandler* cache_handler,
    size_t source_text_length,
    ScriptSourceLocationType source_location_type,
    const KURL& url,
    bool might_generate_crowdsourced_compile_hints,
    bool can_use_crowdsourced_compile_hints) {
  static const int kMinimalCodeLength = 1024;
  v8::ScriptCompiler::NoCacheReason no_cache_reason;

  auto no_code_cache_compile_options = v8::ScriptCompiler::kNoCompileOptions;

  if (might_generate_crowdsourced_compile_hints) {
    DCHECK(base::FeatureList::IsEnabled(features::kProduceCompileHints2));

    // If we end up compiling the script without forced eager compilation, we'll
    // also produce compile hints. This is orthogonal to producing the code
    // cache: if we don't want to create a code cache for some reason
    // (e.g., script too small, or not hot enough) we still want to produce
    // compile hints.

    // When we're forcing eager compilation, we cannot produce compile hints
    // (we won't gather data about which eagerly compiled functions are
    // actually used).

    // We also disable reading the script from the code cache when producing
    // compile hints. This is because we cannot generate compile hints for
    // cached scripts (especially if they've been eagerly compiled by a
    // ServiceWorker) and omitting cached scripts would deteriorate the data.
    no_code_cache_compile_options = v8::ScriptCompiler::kProduceCompileHints;
  } else if (can_use_crowdsourced_compile_hints) {
    // This doesn't need to be gated behind a runtime flag, because there won't
    // be any data unless the v8_compile_hints::kConsumeCompileHints
    // flag is on.
    no_code_cache_compile_options = v8::ScriptCompiler::kConsumeCompileHints;
  }

  switch (source_location_type) {
    case ScriptSourceLocationType::kInline:
      no_cache_reason = v8::ScriptCompiler::kNoCacheBecauseInlineScript;
      break;
    case ScriptSourceLocationType::kInlineInsideDocumentWrite:
      no_cache_reason = v8::ScriptCompiler::kNoCacheBecauseInDocumentWrite;
      break;
    case ScriptSourceLocationType::kExternalFile:
      no_cache_reason =
          v8::ScriptCompiler::kNoCacheBecauseResourceWithNoCacheHandler;
      break;
    // TODO(leszeks): Possibly differentiate between the other kinds of script
    // origin also.
    default:
      no_cache_reason = v8::ScriptCompiler::kNoCacheBecauseNoResource;
      break;
  }

  if (!cache_handler) {
    return std::make_tuple(no_code_cache_compile_options,
                           ProduceCacheOptions::kNoProduceCache,
                           no_cache_reason);
  }

  if (cache_options == mojom::blink::V8CacheOptions::kNone) {
    no_cache_reason = v8::ScriptCompiler::kNoCacheBecauseCachingDisabled;
    return std::make_tuple(no_code_cache_compile_options,
                           ProduceCacheOptions::kNoProduceCache,
                           no_cache_reason);
  }

  if (source_text_length < kMinimalCodeLength) {
    no_cache_reason = v8::ScriptCompiler::kNoCacheBecauseScriptTooSmall;
    return std::make_tuple(no_code_cache_compile_options,
                           ProduceCacheOptions::kNoProduceCache,
                           no_cache_reason);
  }

  // By recording statistics at this point we exclude scripts for which we're
  // not going to generate metadata.
  RecordCacheGetStatistics(cache_handler);

  if (HasCodeCache(cache_handler) &&
      (no_code_cache_compile_options &
       v8::ScriptCompiler::kProduceCompileHints) == 0) {
    return std::make_tuple(v8::ScriptCompiler::kConsumeCodeCache,
                           ProduceCacheOptions::kNoProduceCache,
                           no_cache_reason);
  }

  // If the resource is served from CacheStorage, generate the V8 code cache in
  // the first load.
  if (cache_handler->IsServedFromCacheStorage())
    cache_options = mojom::blink::V8CacheOptions::kCodeWithoutHeatCheck;

  bool local_compile_hints_enabled =
      base::FeatureList::IsEnabled(features::kLocalCompileHints) &&
      !might_generate_crowdsourced_compile_hints &&
      !can_use_crowdsourced_compile_hints;

  switch (cache_options) {
    case mojom::blink::V8CacheOptions::kDefault:
    case mojom::blink::V8CacheOptions::kCode: {
      if (!HasHotTimestamp(cache_handler)) {
        if (local_compile_hints_enabled) {
          // If the resource is not yet hot for caching, set the timestamp and
          // produce compile hints. Setting the time stamp first is important,
          // because compile hints are only produced later (when the page turns
          // interactive). If the user navigates away before that happens, we
          // don't want to end up with no cache at all, since the resource would
          // then appear to be cold during the next run.

          // TODO(1495723): This branch doesn't check HasCompileHints. It's not
          // clear what we should do if the resource is not hot but we have
          // compile hints. 1) Consume compile hints and produce new ones
          // (currently not possible in the API) and combine both compile hints.
          // 2) Ignore existing compile hints (we're anyway not creating the
          // code cache yet) and produce new ones.
          return std::make_tuple(
              v8::ScriptCompiler::kProduceCompileHints,
              ProduceCacheOptions::kSetTimeStamp,
              v8::ScriptCompiler::kNoCacheBecauseCacheTooCold);
        }
        return std::make_tuple(no_code_cache_compile_options,
                               ProduceCacheOptions::kSetTimeStamp,
                               v8::ScriptCompiler::kNoCacheBecauseCacheTooCold);
      }
      if (local_compile_hints_enabled && HasCompileHints(cache_handler)) {
        // In this branch, the timestamp in the compile hints is hot.
        return std::make_tuple(
            v8::ScriptCompiler::kConsumeCompileHints,
            ProduceCacheOptions::kProduceCodeCache,
            v8::ScriptCompiler::kNoCacheBecauseDeferredProduceCodeCache);
      }
      return std::make_tuple(
          no_code_cache_compile_options, ProduceCacheOptions::kProduceCodeCache,
          v8::ScriptCompiler::kNoCacheBecauseDeferredProduceCodeCache);
    }
    case mojom::blink::V8CacheOptions::kCodeWithoutHeatCheck:
      return std::make_tuple(
          no_code_cache_compile_options, ProduceCacheOptions::kProduceCodeCache,
          v8::ScriptCompiler::kNoCacheBecauseDeferredProduceCodeCache);
    case mojom::blink::V8CacheOptions::kFullCodeWithoutHeatCheck:
      return std::make_tuple(
          v8::ScriptCompiler::kEagerCompile,
          ProduceCacheOptions::kProduceCodeCache,
          v8::ScriptCompiler::kNoCacheBecauseDeferredProduceCodeCache);
    case mojom::blink::V8CacheOptions::kNone:
      // Shouldn't happen, as this is handled above.
      // Case is here so that compiler can check all cases are handled.
      NOTREACHED();
  }

  // All switch branches should return and we should never get here.
  NOTREACHED();
}

bool V8CodeCache::IsFull(const CachedMetadata* metadata) {
  const uint64_t full_flag = static_cast<uint64_t>(DetailFlags::kFull);
  return (metadata->tag() & full_flag) != 0;
}

template <typename UnboundScript>
static void ProduceCacheInternal(
    v8::Isolate* isolate,
    CodeCacheHost* code_cache_host,
    v8::Local<UnboundScript> unbound_script,
    CachedMetadataHandler* cache_handler,
    size_t source_text_length,
    const KURL& source_url,
    const TextPosition& source_start_position,
    const char* trace_name,
    V8CodeCache::ProduceCacheOptions produce_cache_options) {
  TRACE_EVENT0("v8", trace_name);
  RuntimeCallStatsScopedTracer rcs_scoped_tracer(isolate);
  RUNTIME_CALL_TIMER_SCOPE(isolate, RuntimeCallStats::CounterId::kV8);

  switch (produce_cache_options) {
    case V8CodeCache::ProduceCacheOptions::kSetTimeStamp:
      V8CodeCache::SetCacheTimeStamp(code_cache_host, cache_handler);
      break;
    case V8CodeCache::ProduceCacheOptions::kProduceCodeCache: {
      // TODO(crbug.com/938269): Investigate why this can be empty here.
      if (unbound_script.IsEmpty())
        break;

      constexpr const char* kTraceEventCategoryGroup = "v8,devtools.timeline";
      TRACE_EVENT_BEGIN1(kTraceEventCategoryGroup, trace_name, "fileName",
                         source_url.GetString().Utf8());

      base::ElapsedTimer timer;
      std::unique_ptr<v8::ScriptCompiler::CachedData> cached_data(
          v8::ScriptCompiler::CreateCodeCache(unbound_script));
      if (cached_data) {
        V8CodeCache::RecordCacheSetStatistics(
            V8CodeCache::SetMetadataType::kCodeCache);
        const uint8_t* data = cached_data->data;
        int length = cached_data->length;
        cache_handler->ClearCachedMetadata(
            code_cache_host, CachedMetadataHandler::kClearLocally);
        cache_handler->SetCachedMetadata(
            code_cache_host, V8CodeCache::TagForCodeCache(cache_handler), data,
            length);
        base::UmaHistogramMicrosecondsTimes("V8.ProduceCodeCacheMicroseconds",
                                            timer.Elapsed());
      }

      TRACE_EVENT_END1(kTraceEventCategoryGroup, trace_name, "data",
                       [&](perfetto::TracedValue context) {
                         inspector_produce_script_cache_event::Data(
                             std::move(context), source_url.GetString(),
                             source_start_position,
                             cached_data ? cached_data->length : 0);
                       });
      break;
    }
    case V8CodeCache::ProduceCacheOptions::kNoProduceCache:
      break;
  }
}

void V8CodeCache::ProduceCache(v8::Isolate* isolate,
                               CodeCacheHost* code_cache_host,
                               v8::Local<v8::Script> script,
                               CachedMetadataHandler* cache_handler,
                               size_t source_text_length,
                               const KURL& source_url,
                               const TextPosition& source_start_position,
                               ProduceCacheOptions produce_cache_options) {
  ProduceCacheInternal(isolate, code_cache_host, script->GetUnboundScript(),
                       cache_handler, source_text_length, source_url,
                       source_start_position, "v8.produceCache",
                       produce_cache_options);
}

void V8CodeCache::ProduceCache(v8::Isolate* isolate,
                               CodeCacheHost* code_cache_host,
                               ModuleRecordProduceCacheData* produce_cache_data,
                               size_t source_text_length,
                               const KURL& source_url,
                               const TextPosition& source_start_position) {
  ProduceCacheInternal(
      isolate, code_cache_host, produce_cache_data->UnboundScript(isolate),
      produce_cache_data->CacheHandler(), source_text_length, source_url,
      source_start_position, "v8.produceModuleCache",
      produce_cache_data->GetProduceCacheOptions());
}

uint32_t V8CodeCache::TagForCodeCache(
    const CachedMetadataHandler* cache_handler) {
  return CacheTag(kCacheTagCode, cache_handler->Encoding());
}

uint32_t V8CodeCache::TagForTimeStamp(
    const CachedMetadataHandler* cache_handler) {
  return CacheTag(kCacheTagTimeStamp, cache_handler->Encoding());
}

uint32_t V8CodeCache::TagForCompileHints(
    const CachedMetadataHandler* cache_handler) {
  return CacheTag(kCacheTagCompileHints, cache_handler->Encoding());
}

// Store a timestamp to the cache as hint.
void V8CodeCache::SetCacheTimeStamp(CodeCacheHost* code_cache_host,
                                    CachedMetadataHandler* cache_handler) {
  RecordCacheSetStatistics(V8CodeCache::SetMetadataType::kTimestamp);
  uint64_t now_ms = GetTimestamp();
  cache_handler->ClearCachedMetadata(code_cache_host,
                                     CachedMetadataHandler::kClearLocally);
  cache_handler->SetCachedMetadata(
      code_cache_host, TagForTimeStamp(cache_handler),
      reinterpret_cast<uint8_t*>(&now_ms), sizeof(now_ms));
}

uint64_t V8CodeCache::GetTimestamp() {
  return base::TimeTicks::Now().since_origin().InMilliseconds();
}

// static
scoped_refptr<CachedMetadata> V8CodeCache::GenerateFullCodeCache(
    ScriptState* script_state,
    const String& script_string,
    const KURL& source_url,
    const WTF::TextEncoding& encoding,
    OpaqueMode opaque_mode) {
  const String file_name = source_url.GetString();

  constexpr const char* kTraceEventCategoryGroup = "v8,devtools.timeline";
  TRACE_EVENT_BEGIN1(kTraceEventCategoryGroup, "v8.compile", "fileName",
                     file_name.Utf8());

  ScriptState::Scope scope(script_state);
  v8::Isolate* isolate = script_state->GetIsolate();
  // v8::TryCatch is needed to suppress all exceptions thrown during the code
  // cache generation.
  v8::TryCatch block(isolate);
  ReferrerScriptInfo referrer_info;
  v8::ScriptOrigin origin(
      V8String(isolate, file_name),
      0,                                      // line_offset
      0,                                      // column_offset
      opaque_mode == OpaqueMode::kNotOpaque,  // is_shared_cross_origin
      -1,                                     // script_id
      V8String(isolate, String("")),          // source_map_url
      opaque_mode == OpaqueMode::kOpaque,     // is_opaque
      false,                                  // is_wasm
      false,                                  // is_module
      referrer_info.ToV8HostDefinedOptions(isolate, source_url));
  v8::Local<v8::String> code(V8String(isolate, script_string));
  v8::ScriptCompiler::Source source(code, origin);
  scoped_refptr<CachedMetadata> cached_metadata;

  v8::MaybeLocal<v8::UnboundScript> maybe_unbound_script =
      v8::ScriptCompiler::CompileUnboundScript(
          isolate, &source, v8::ScriptCompiler::kEagerCompile);

  TRACE_EVENT_END1(
      kTraceEventCategoryGroup, "v8.compile", "data",
      [&](perfetto::TracedValue context) {
        inspector_compile_script_event::Data(
            std::move(context), file_name, TextPosition::MinimumPosition(),
            std::nullopt, true, false,
            ScriptStreamer::NotStreamingReason::kStreamingDisabled);
      });

  v8::Local<v8::UnboundScript> unbound_script;
  // When failed to compile the script with syntax error, the exceptions is
  // suppressed by the v8::TryCatch, and returns null.
  if (maybe_unbound_script.ToLocal(&unbound_script)) {
    TRACE_EVENT_BEGIN1(kTraceEventCategoryGroup, "v8.produceCache", "fileName",
                       file_name.Utf8());

    std::unique_ptr<v8::ScriptCompiler::CachedData> cached_data(
        v8::ScriptCompiler::CreateCodeCache(unbound_script));
    if (cached_data && cached_data->length) {
      cached_metadata = CachedMetadata::Create(
          CacheTag(kCacheTagCode, encoding.GetName()), cached_data->data,
          cached_data->length, static_cast<uint64_t>(DetailFlags::kFull));
    }

    TRACE_EVENT_END1(kTraceEventCategoryGroup, "v8.produceCache", "data",
                     [&](perfetto::TracedValue context) {
                       inspector_produce_script_cache_event::Data(
                           std::move(context), file_name,
                           TextPosition::MinimumPosition(),
                           cached_data ? cached_data->length : 0);
                     });
  }

  return cached_metadata;
}

void V8CodeCache::RecordCacheGetStatistics(
    const CachedMetadataHandler* cache_handler) {
  base::UmaHistogramEnumeration(kCacheGetHistogram,
                                ReadGetMetadataType(cache_handler));
}

void V8CodeCache::RecordCacheGetStatistics(
    const CachedMetadata* cached_metadata,
    const String& encoding) {
  base::UmaHistogramEnumeration(kCacheGetHistogram,
                                ReadGetMetadataType(cached_metadata, encoding));
}

void V8CodeCache::RecordCacheGetStatistics(
    V8CodeCache::GetMetadataType metadata_type) {
  base::UmaHistogramEnumeration(kCacheGetHistogram, metadata_type);
}

void V8CodeCache::RecordCacheSetStatistics(
    V8CodeCache::SetMetadataType metadata_type) {
  base::UmaHistogramEnumeration(kCacheSetHistogram, metadata_type);
}

}  // namespace blink

"""

```