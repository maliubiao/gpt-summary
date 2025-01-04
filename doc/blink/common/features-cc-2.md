Response:
The user wants a summary of the functionality of the provided C++ code snippet from `blink/common/features.cc`. This file seems to define various feature flags and their associated parameters used within the Chromium Blink engine.

Here's a breakdown of the thinking process:

1. **Identify the Core Purpose:** The primary function of this code is to define and manage feature flags. These flags control whether certain features in the Blink rendering engine are enabled or disabled, and often allow for configuration through parameters.

2. **Categorize Functionality:**  Go through the code and group related feature flags. Look for patterns in the naming and descriptions to understand the categories. Some initial categories that emerge are:
    * **Performance Optimization:** Features related to improving page load times, reducing resource usage, and enhancing responsiveness (e.g., LCP-related features, preloading, caching, script execution prioritization).
    * **Security/Privacy:** Features dealing with security policies, referrer behavior, and privacy-related APIs (e.g., mixed content upgrade, private aggregation API, referrer reduction).
    * **Rendering/Compositing:** Features affecting how the page is rendered and displayed (e.g., compositing preferences, canvas features, font handling).
    * **Resource Loading:** Features concerning how resources like images, scripts, and fonts are loaded and managed (e.g., lazy loading, prefetching, caching).
    * **Experimental/New APIs:**  Features that are either under development or introducing new web platform capabilities (e.g., Private Aggregation API, Link Preview).
    * **Developer Tools/Debugging:** Features related to logging and debugging (e.g., logging unexpected IPC).

3. **Explain the Relationship to Web Technologies (JavaScript, HTML, CSS):**  For each category (or individual feature if it's prominent), consider how it might interact with JavaScript, HTML, and CSS.
    * **JavaScript:**  Script execution prioritization, precompilation, streaming, and features interacting with new JavaScript APIs (like Private Aggregation) are key connections.
    * **HTML:** Features related to preloading (using `<link rel="...">`), lazy loading (`<img loading="lazy">`), and elements that trigger prefetching/prerendering (like `<a>` tags with `prefetch`/`prerender`).
    * **CSS:** Font loading, rendering optimization, and potentially features that affect layout and paint (though less directly from these flag definitions).

4. **Provide Examples (Hypothetical Inputs and Outputs):**  Since these are flags, the "input" is typically the state of the flag (enabled/disabled) and the parameters. The "output" is the *behavior* of the browser. Create simple examples to illustrate this. For example, if `kLowPriorityAsyncScriptExecution` is enabled, asynchronous scripts might be executed later.

5. **Address User/Programming Errors:** Think about how misconfiguration or misunderstanding of these flags could lead to problems. For example, aggressively enabling preloading features could consume excessive bandwidth. Disabling essential rendering optimizations could lead to a poor user experience.

6. **Focus on Summarization for Part 3:**  This is part 3 of 4, so the goal is to provide a mid-level summary, building upon previous potential parts and setting the stage for the final part. Emphasize the overall function of the file and the *types* of features being controlled.

7. **Review and Refine:** Ensure the explanation is clear, concise, and accurate. Check for any jargon that needs clarification. Ensure the examples are easy to understand. Make sure the summary addresses the specific request for Part 3.

**Self-Correction/Refinement During Thinking:**

* **Initial thought:**  List every feature individually. **Correction:** This would be too long and not very informative for a summary. Grouping by functionality is better.
* **Initial thought:** Focus only on direct JavaScript/HTML/CSS interaction. **Correction:** Broaden the scope to include how these features *affect* those technologies, even if the implementation is in C++. For example, preloading directly impacts resource loading initiated by HTML.
* **Initial thought:**  Provide very technical details of each feature. **Correction:** Keep the explanations at a higher level, suitable for a general understanding of the file's purpose. The details are less important for a summary than the overall categories.
这是提供的 `blink/common/features.cc` 文件代码片段的第三部分，主要延续了前一部分定义和声明 Blink 引擎的各种**Feature (特性)** 及其相关的**Feature Parameters (特性参数)**。

**归纳其功能:**

这部分代码的核心功能是**定义和控制 Blink 引擎的实验性或可配置的功能特性**。  它通过 `base::Feature` 和 `base::FeatureParam` 宏来声明各种开关和配置项，允许在不修改代码的情况下，通过命令行参数、实验性标志（chrome://flags）或者远程配置等方式来启用、禁用或调整这些特性的行为。

**具体来说，这部分代码定义了以下类型的功能特性：**

* **性能优化相关的特性:**  例如 `kPreloadSystemFonts` (预加载系统字体), `kHttpDiskCachePrewarming` (HTTP 磁盘缓存预热), `kOptimizeLoadingDataUrls` (优化加载 data URLs),  `kParkableImagesToDisk` (将可停放的图片写入磁盘), `kScriptStreaming` (脚本流式传输) 等，旨在提升页面加载速度、降低资源消耗。
* **渲染相关的特性:** 例如 `kLowLatencyCanvas2dImageChromium` (低延迟 Canvas 2D), `kLowLatencyWebGLImageChromium` (低延迟 WebGL), `kPath2DPaintCache` (Path2D 绘制缓存), `kPreferCompositingToLCDText` (优先使用合成而非 LCD 文本) 等，涉及到图形渲染的优化和控制。
* **预加载/预渲染相关的特性:** 例如 `kNavigationPredictor` (导航预测器), `kPrerender2InNewTab` (在新标签页中预渲染), `kPrerender2MainFrameNavigation` (主框架导航预渲染), `kPreloadingHeuristicsMLModel` (预加载启发式机器学习模型) 等，用于提前加载或渲染页面，提升导航速度。
* **资源加载控制相关的特性:** 例如 `kLightweightNoStatePrefetch` (轻量级无状态预取), `kLowPriorityScriptLoading` (低优先级脚本加载), `kSaveDataImgSrcset` (节省流量模式下的 srcset 图片选择) 等，控制资源的加载行为和优先级。
* **新的 Web API 或实验性 API:** 例如 `kPrivateAggregationApi` (私有聚合 API),  涉及到正在开发或实验阶段的新 Web 平台功能。
* **安全性/隐私性相关的特性:** 例如 `kMixedContentAutoupgrade` (混合内容自动升级), `kReducedReferrerGranularity` (减少 Referrer 粒度), `kPrefetchPrivacyChanges` (预取隐私性变更) 等，旨在增强用户的安全和隐私保护。
* **开发者工具/调试相关的特性:** 例如 `kLogUnexpectedIPCPostedToBackForwardCachedDocuments` (记录发送到后退/前进缓存文档的意外 IPC) 等，用于辅助开发和调试。
* **与 Service Worker 相关的特性:** 例如 `kPlzDedicatedWorker` (浏览器发起的 Dedicated Worker 脚本加载)。
* **与 Back/Forward Cache 相关的特性:** 例如 `kRegisterJSSourceLocationBlockingBFCache` (注册阻止 BFCache 的 JS 源代码位置)。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这些特性虽然在 C++ 代码中定义，但直接影响浏览器如何解析、加载和渲染网页内容，因此与 JavaScript, HTML, CSS 的行为息息相关。

* **JavaScript:**
    * **`kLowPriorityAsyncScriptExecution` (低优先级异步脚本执行):**  如果启用，带有 `async` 属性的 JavaScript 脚本可能会以较低的优先级执行，这会影响 JavaScript 的执行顺序和页面交互的响应速度。
        * **假设输入:** 一个 HTML 页面包含多个带有 `async` 属性的 `<script>` 标签。`kLowPriorityAsyncScriptExecution` 被启用。
        * **输出:** 这些异步脚本的执行可能会被延迟，优先执行其他更高优先级的任务，例如渲染相关的任务。
    * **`kScriptStreaming` (脚本流式传输):**  如果启用，浏览器可以边下载边解析 JavaScript 代码，提升首次交互时间 (TTI)。
        * **假设输入:**  一个包含大型 JavaScript 文件的 HTML 页面。`kScriptStreaming` 被启用。
        * **输出:**  浏览器在 JavaScript 文件完全下载完成前就开始解析和执行部分代码，可能更快地让页面变得可交互。
    * **`kPrivateAggregationApi` (私有聚合 API):** 这是一组新的 JavaScript API，允许网站在保护用户隐私的前提下收集聚合数据。JavaScript 代码可以调用这些 API 来发送聚合请求。
        * **假设输入:**  JavaScript 代码使用 `privateAggregation.selectHistogramContributions()` 或 `privateAggregation.sendBeacon()` 等方法。 `kPrivateAggregationApi` 被启用。
        * **输出:** 浏览器会处理这些 API 调用，并根据配置将聚合数据发送到服务端。

* **HTML:**
    * **`kLCPPLazyLoadImagePreload` (LCP 元素图片懒加载预加载):**  这个特性可能影响浏览器如何处理带有 `loading="lazy"` 属性的 `<img>` 标签，特别是对于影响 Largest Contentful Paint (LCP) 的图片。
        * **假设输入:** HTML 中一个关键的 `<img>` 标签带有 `loading="lazy"` 属性，并且是 LCP 元素。 `kLCPPLazyLoadImagePreload` 被启用并配置为 `kNativeLazyLoading`。
        * **输出:** 浏览器可能会更早地开始加载该图片，即使它带有懒加载属性，以优化 LCP。
    * **`kPreloadSystemFonts` (预加载系统字体):**  如果启用，浏览器可能会在页面渲染前预先加载一些常用的系统字体，减少渲染阻塞。
        * **假设输入:**  一个网页使用了系统字体，例如 `font-family: sans-serif;`。 `kPreloadSystemFonts` 被启用。
        * **输出:** 浏览器可能会在渲染页面文本之前，尝试从操作系统中加载这些字体。
    * **`kLinkPreview` (链接预览):**  如果启用，用户可以通过特定交互（例如 Alt+点击或长按）来预览链接的目标页面。
        * **假设输入:** 用户在启用了 `kLinkPreview` 的浏览器中，按住 Alt 键并悬停在一个链接上。
        * **输出:**  浏览器可能会显示一个目标页面的预览快照。

* **CSS:**
    * **`kRenderBlockingFonts` (渲染阻塞字体):**  这个特性控制字体加载对首次内容绘制 (FCP) 的影响。
        * **假设输入:** 一个网页使用了自定义字体，并且没有使用 `font-display: optional;` 等属性。 `kRenderBlockingFonts` 被启用。
        * **输出:**  浏览器在字体加载完成之前可能会阻止文本的渲染，从而避免出现“闪烁的不可见文本” (FOIT)。
    * **`kPreferCompositingToLCDText` (优先使用合成而非 LCD 文本):** 这会影响浏览器如何渲染文本，可能会为了更好的动画性能而牺牲 LCD 文本渲染的清晰度。
        * **假设输入:** 包含动画或复杂 CSS 效果的页面。 `kPreferCompositingToLCDText` 被启用。
        * **输出:** 浏览器可能会选择将文本渲染到合成层，即使这意味着文本边缘可能不如 LCD 渲染清晰。

**用户或编程常见的使用错误举例:**

* **过度激进地启用实验性特性:** 用户可能会在 `chrome://flags` 中启用大量实验性特性，导致浏览器行为不稳定或者出现意外的错误。例如，同时启用多个预加载特性可能会消耗过多带宽和 CPU 资源。
* **错误理解 Feature Param 的含义:** 开发者可能会错误地配置 Feature Param 的值，导致特性行为与预期不符。例如，将 `kLowPriorityAsyncScriptExecutionFeatureLimitParam` 设置为一个很小的值，可能会导致该特性在页面加载的早期就被禁用，失去了优化的效果。
* **依赖未发布的实验性特性:**  开发者可能会依赖一些实验性特性进行开发，但这些特性可能会在未来的 Chrome 版本中被移除或修改，导致网站或应用出现兼容性问题。
* **忽略 Feature 的平台限制:** 某些 Feature 可能只在特定平台上生效，开发者需要注意这些限制，避免在不支持的平台上进行相关的假设或配置。

总而言之，这个代码片段定义了一系列用于控制 Blink 引擎行为的开关和配置项，这些开关和配置项能够影响浏览器加载、解析和渲染网页内容的方式，从而与 JavaScript, HTML, CSS 的行为产生密切的联系。理解这些 Feature 的作用对于优化网页性能、利用新的 Web 平台特性以及进行浏览器开发至关重要。

Prompt: 
```
这是目录为blink/common/features.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
equest.
BASE_FEATURE_PARAM(bool,
                   kLCPPLazyLoadImagePreloadDryRun,
                   &kLCPPLazyLoadImagePreload,
                   "lcpp_lazy_load_image_preload_dry_run",
                   false);

const base::FeatureParam<
    LcppPreloadLazyLoadImageType>::Option lcpp_preload_lazy_load_image[] = {
    {LcppPreloadLazyLoadImageType::kNone, "none"},
    {LcppPreloadLazyLoadImageType::kNativeLazyLoading, "native_lazy_loading"},
    {LcppPreloadLazyLoadImageType::kCustomLazyLoading, "custom_lazy_loading"},
    {LcppPreloadLazyLoadImageType::kAll, "all"},
};
BASE_FEATURE_ENUM_PARAM(LcppPreloadLazyLoadImageType,
                        kLCPCriticalPathPredictorPreloadLazyLoadImageType,
                        &kLCPPLazyLoadImagePreload,
                        "lcpp_preload_lazy_load_image_type",
                        LcppPreloadLazyLoadImageType::kNone,
                        &lcpp_preload_lazy_load_image);

BASE_FEATURE(kPreloadSystemFonts,
             "PreloadSystemFonts",
             base::FEATURE_DISABLED_BY_DEFAULT);

const base::FeatureParam<std::string> kPreloadSystemFontsTargets{
    &kPreloadSystemFonts, "preload_system_fonts_targets", "[]"};

BASE_FEATURE_PARAM(int,
                   kPreloadSystemFontsRequiredMemoryGB,
                   &kPreloadSystemFonts,
                   "preload_system_fonts_required_memory_gb",
                   4);

BASE_FEATURE(kLCPPMultipleKey,
             "LCPPMultipleKey",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE_PARAM(size_t,
                   kLCPPMultipleKeyMaxPathLength,
                   &kLCPPMultipleKey,
                   "lcpp_multiple_key_max_path_length",
                   15);

const base::FeatureParam<LcppMultipleKeyTypes>::Option
    lcpp_multiple_key_types[] = {
        {LcppMultipleKeyTypes::kDefault, "default"},
        {LcppMultipleKeyTypes::kLcppKeyStat, "lcpp_key_stat"},
};

BASE_FEATURE_ENUM_PARAM(LcppMultipleKeyTypes,
                        kLcppMultipleKeyType,
                        &kLCPPMultipleKey,
                        "lcpp_multiple_key_type",
                        LcppMultipleKeyTypes::kDefault,
                        &lcpp_multiple_key_types);

BASE_FEATURE_PARAM(int,
                   kLcppMultipleKeyHistogramSlidingWindowSize,
                   &kLCPPMultipleKey,
                   "lcpp_multiple_key_histogram_sliding_window_size",
                   1000);

BASE_FEATURE_PARAM(int,
                   kLcppMultipleKeyMaxHistogramBuckets,
                   &kLCPPMultipleKey,
                   "lcpp_multiple_key_max_histogram_buckets",
                   10);

BASE_FEATURE(kLCPPPrefetchSubresource,
             "LCPPPrefetchSubresource",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kHttpDiskCachePrewarming,
             "HttpDiskCachePrewarming",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE_PARAM(size_t,
                   kHttpDiskCachePrewarmingMaxUrlLength,
                   &kHttpDiskCachePrewarming,
                   "http_disk_cache_prewarming_max_url_length",
                   1024);

BASE_FEATURE_PARAM(int,
                   kHttpDiskCachePrewarmingHistorySize,
                   &kHttpDiskCachePrewarming,
                   "http_disk_cache_prewarming_history_size",
                   1024);

BASE_FEATURE_PARAM(base::TimeDelta,
                   kHttpDiskCachePrewarmingReprewarmPeriod,
                   &kHttpDiskCachePrewarming,
                   "http_disk_cache_prewarming_reprewarm_period",
                   base::Minutes(10));

BASE_FEATURE_PARAM(bool,
                   kHttpDiskCachePrewarmingTriggerOnNavigation,
                   &kHttpDiskCachePrewarming,
                   "http_disk_cache_prewarming_trigger_on_navigation",
                   true);

BASE_FEATURE_PARAM(
    bool,
    kHttpDiskCachePrewarmingTriggerOnPointerDownOrHover,
    &kHttpDiskCachePrewarming,
    "http_disk_cache_prewarming_trigger_on_pointer_down_or_hover",
    true);

BASE_FEATURE_PARAM(
    bool,
    kHttpDiskCachePrewarmingUseReadAndDiscardBodyOption,
    &kHttpDiskCachePrewarming,
    "http_disk_cache_prewarming_use_read_and_discard_body_option",
    false);

BASE_FEATURE_PARAM(bool,
                   kHttpDiskCachePrewarmingSkipDuringBrowserStartup,
                   &kHttpDiskCachePrewarming,
                   "http_disk_cache_prewarming_skip_during_browser_startup",
                   true);

BASE_FEATURE(kLegacyParsingOfXContentTypeOptions,
             "LegacyParsingOfXContentTypeOptions",
             base::FEATURE_DISABLED_BY_DEFAULT);

// A feature to reduce the set of resources fetched by No-State Prefetch.
BASE_FEATURE(kLightweightNoStatePrefetch,
             "LightweightNoStatePrefetch",
#if BUILDFLAG(IS_ANDROID)
             base::FEATURE_ENABLED_BY_DEFAULT
#else
             base::FEATURE_DISABLED_BY_DEFAULT
#endif
);

BASE_FEATURE(kLinkPreview, "LinkPreview", base::FEATURE_DISABLED_BY_DEFAULT);

constexpr base::FeatureParam<LinkPreviewTriggerType>::Option
    link_preview_trigger_type_options[] = {
        {LinkPreviewTriggerType::kAltClick, "alt_click"},
        {LinkPreviewTriggerType::kAltHover, "alt_hover"},
        {LinkPreviewTriggerType::kLongPress, "long_press"}};
BASE_FEATURE_ENUM_PARAM(LinkPreviewTriggerType,
                        kLinkPreviewTriggerType,
                        &kLinkPreview,
                        "trigger_type",
                        LinkPreviewTriggerType::kAltHover,
                        &link_preview_trigger_type_options);

// A feature to control whether the loading phase should be extended beyond
// First Meaningful Paint by a configurable buffer.
BASE_FEATURE(kLoadingPhaseBufferTimeAfterFirstMeaningfulPaint,
             "LoadingPhaseBufferTimeAfterFirstMeaningfulPaint",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Makes network loading tasks unfreezable so that they can be processed while
// the page is frozen.
BASE_FEATURE(kLoadingTasksUnfreezable,
             "LoadingTasksUnfreezable",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kLogUnexpectedIPCPostedToBackForwardCachedDocuments,
             "LogUnexpectedIPCPostedToBackForwardCachedDocuments",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Allow low latency canvas 2D to be in overlay (generally meaning scanned out
// directly to display), even if regular canvas are not in overlay
// (Canvas2DImageChromium is disabled).
BASE_FEATURE(kLowLatencyCanvas2dImageChromium,
             "LowLatencyCanvas2dImageChromium",
#if BUILDFLAG(IS_CHROMEOS_ASH) || BUILDFLAG(IS_ANDROID)
             base::FEATURE_ENABLED_BY_DEFAULT
#else
             base::FEATURE_DISABLED_BY_DEFAULT
#endif  // BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_ANDROID)
);

// Allow low latency WebGL to be in overlay (generally meaning scanned out
// directly to display), even if regular canvas are not in overlay
// (WebGLImageChromium is disabled).
BASE_FEATURE(kLowLatencyWebGLImageChromium,
             "LowLatencyWebGLImageChromium",
#if BUILDFLAG(IS_ANDROID)
             base::FEATURE_ENABLED_BY_DEFAULT
#else
             base::FEATURE_DISABLED_BY_DEFAULT
#endif
);

BASE_FEATURE(kLowPriorityAsyncScriptExecution,
             "LowPriorityAsyncScriptExecution",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE_PARAM(base::TimeDelta,
                   kTimeoutForLowPriorityAsyncScriptExecution,
                   &kLowPriorityAsyncScriptExecution,
                   "low_pri_async_exec_timeout",
                   base::Milliseconds(0));

// kLowPriorityAsyncScriptExecution will be disabled after document elapsed more
// than |low_pri_async_exec_feature_limit|. Zero value means no limit.
BASE_FEATURE_PARAM(base::TimeDelta,
                   kLowPriorityAsyncScriptExecutionFeatureLimitParam,
                   &kLowPriorityAsyncScriptExecution,
                   "low_pri_async_exec_feature_limit",
                   base::Seconds(0));

// kLowPriorityAsyncScriptExecution will be applied only for cross site scripts.
BASE_FEATURE_PARAM(bool,
                   kLowPriorityAsyncScriptExecutionCrossSiteOnlyParam,
                   &kLowPriorityAsyncScriptExecution,
                   "low_pri_async_exec_cross_site_only",
                   false);

BASE_FEATURE_PARAM(bool,
                   kLowPriorityAsyncScriptExecutionMainFrameOnlyParam,
                   &kLowPriorityAsyncScriptExecution,
                   "low_pri_async_exec_main_frame_only",
                   false);

// kLowPriorityAsyncScriptExecution will exclude scripts that influence LCP
// element.
BASE_FEATURE_PARAM(bool,
                   kLowPriorityAsyncScriptExecutionExcludeLcpInfluencersParam,
                   &kLowPriorityAsyncScriptExecution,
                   "low_pri_async_exec_exclude_lcp_influencers",
                   false);

// kLowPriorityAsyncScriptExecution will exclude scripts on pages where LCP
// element isn't directly embedded in HTML.
BASE_FEATURE_PARAM(bool,
                   kLowPriorityAsyncScriptExecutionDisableWhenLcpNotInHtmlParam,
                   &kLowPriorityAsyncScriptExecution,
                   "low_pri_async_exec_disable_when_lcp_not_in_html",
                   false);

// kLowPriorityAsyncScriptExecution will use the specified priority as a lower
// task priority.
const base::FeatureParam<AsyncScriptPrioritisationType>::Option
    async_script_prioritisation_types[] = {
        {AsyncScriptPrioritisationType::kHigh, "high"},
        {AsyncScriptPrioritisationType::kLow, "low"},
        {AsyncScriptPrioritisationType::kBestEffort, "best_effort"},
};
BASE_FEATURE_ENUM_PARAM(AsyncScriptPrioritisationType,
                        kLowPriorityAsyncScriptExecutionLowerTaskPriorityParam,
                        &kLowPriorityAsyncScriptExecution,
                        "low_pri_async_exec_lower_task_priority",
                        AsyncScriptPrioritisationType::kBestEffort,
                        &async_script_prioritisation_types);
// kLowPriorityAsyncScriptExecution will change evaluation schedule for the
// specified target.
BASE_FEATURE_ENUM_PARAM(AsyncScriptExperimentalSchedulingTarget,
                        kLowPriorityAsyncScriptExecutionTargetParam,
                        &kLowPriorityAsyncScriptExecution,
                        "low_pri_async_exec_target",
                        AsyncScriptExperimentalSchedulingTarget::kBoth,
                        &async_script_experimental_scheduling_targets);
// If true, kLowPriorityAsyncScriptExecution will not change the script
// evaluation timing for the non parser inserted script.
BASE_FEATURE_PARAM(
    bool,
    kLowPriorityAsyncScriptExecutionExcludeNonParserInsertedParam,
    &kLowPriorityAsyncScriptExecution,
    "low_pri_async_exec_exclude_non_parser_inserted",
    false);
// If true, kLowPriorityAsyncScriptExecution will not change the script
// evaluation timing for the scripts that were added via document.write().
BASE_FEATURE_PARAM(bool,
                   kLowPriorityAsyncScriptExecutionExcludeDocumentWriteParam,
                   &kLowPriorityAsyncScriptExecution,
                   "low_pri_async_exec_exclude_document_write",
                   false);

// kLowPriorityAsyncScriptExecution will be opted-out when FetchPriorityHint is
// low.
BASE_FEATURE_PARAM(
    bool,
    kLowPriorityAsyncScriptExecutionOptOutLowFetchPriorityHintParam,
    &kLowPriorityAsyncScriptExecution,
    "low_pri_async_exec__opt_out_low_fetch_priority_hint",
    false);
// kLowPriorityAsyncScriptExecution will be opted-out when FetchPriorityHint is
// auto.
BASE_FEATURE_PARAM(
    bool,
    kLowPriorityAsyncScriptExecutionOptOutAutoFetchPriorityHintParam,
    &kLowPriorityAsyncScriptExecution,
    "low_pri_async_exec_opt_out_auto_fetch_priority_hint",
    false);
// kLowPriorityAsyncScriptExecution will be opted-out when FetchPriorityHint is
// high.
BASE_FEATURE_PARAM(
    bool,
    kLowPriorityAsyncScriptExecutionOptOutHighFetchPriorityHintParam,
    &kLowPriorityAsyncScriptExecution,
    "low_pri_async_exec_opt_out_high_fetch_priority_hint",
    false);

BASE_FEATURE(kLowPriorityScriptLoading,
             "LowPriorityScriptLoading",
             base::FEATURE_DISABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(bool,
                   kLowPriorityScriptLoadingCrossSiteOnlyParam,
                   &kLowPriorityScriptLoading,
                   "low_pri_async_loading_cross_site_only",
                   false);
BASE_FEATURE_PARAM(base::TimeDelta,
                   kLowPriorityScriptLoadingFeatureLimitParam,
                   &kLowPriorityScriptLoading,
                   "low_pri_async_loading_feature_limit",
                   base::Seconds(0));
const base::FeatureParam<std::string> kLowPriorityScriptLoadingDenyListParam{
    &kLowPriorityScriptLoading, "low_pri_async_loading_deny_list", ""};
BASE_FEATURE_PARAM(bool,
                   kLowPriorityScriptLoadingMainFrameOnlyParam,
                   &kLowPriorityScriptLoading,
                   "low_pri_async_loading_main_frame_only",
                   false);

BASE_FEATURE(kMixedContentAutoupgrade,
             "AutoupgradeMixedContent",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kResourceFetcherStoresStrongReferences,
             "ResourceFetcherStoresStrongReferences",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kMemoryCacheStrongReference,
             "MemoryCacheStrongReference",
// Finch study showed no improvement on Android for strong memory cache.
#if BUILDFLAG(IS_ANDROID)
             base::FEATURE_DISABLED_BY_DEFAULT
#else
             base::FEATURE_ENABLED_BY_DEFAULT
#endif
);

BASE_FEATURE_PARAM(int,
                   kMemoryCacheStrongReferenceTotalSizeThresholdParam,
                   &kMemoryCacheStrongReference,
                   "memory_cache_strong_ref_total_size_threshold",
                   15 * 1024 * 1024);
BASE_FEATURE_PARAM(int,
                   kMemoryCacheStrongReferenceResourceSizeThresholdParam,
                   &kMemoryCacheStrongReference,
                   "memory_cache_strong_ref_resource_size_threshold",
                   3 * 1024 * 1024);

BASE_FEATURE(kMHTML_Improvements,
             "MHTML_Improvements",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Used to control the collection of anchor element metrics (crbug.com/856683).
// If kNavigationPredictor is enabled, then metrics of anchor elements
// in the first viewport after the page load and the metrics of the clicked
// anchor element will be extracted and recorded.
// Note that the desktop roll out is being done separately from android. See
// https://crbug.com/40258405
BASE_FEATURE(kNavigationPredictor,
             "NavigationPredictor",
             base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(int,
                   kPredictorTrafficClientEnabledPercent,
                   &kNavigationPredictor,
                   "traffic_client_enabled_percent",
#if BUILDFLAG(IS_ANDROID)
                   100
#else
                   5
#endif
);

// Used to control the collection of new viewport related anchor element
// metrics. Metrics will not be recorded if either this or kNavigationPredictor
// is disabled.
BASE_FEATURE(kNavigationPredictorNewViewportFeatures,
             "NavigationPredictorNewViewportFeatures",
#if BUILDFLAG(IS_ANDROID)
             base::FEATURE_ENABLED_BY_DEFAULT
#else
             base::FEATURE_DISABLED_BY_DEFAULT
#endif
);

BASE_FEATURE(kNoForcedFrameUpdatesForWebTests,
             "NoForcedFrameUpdatesForWebTests",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kNoThrottlingVisibleAgent,
             "NoThrottlingVisibleAgent",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kOptimizeLoadingDataUrls,
             "OptimizeLoadingDataUrls",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kOriginAgentClusterDefaultEnabled,
             "OriginAgentClusterDefaultEnable",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kOriginTrialStateHostApplyFeatureDiff,
             "OriginTrialStateHostApplyFeatureDiff",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Enable defer commits to avoid flash of unstyled content, for all navigations.
BASE_FEATURE(kPaintHolding, "PaintHolding", base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kParkableImagesToDisk,
             "ParkableImagesToDisk",
             base::FEATURE_ENABLED_BY_DEFAULT);

#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_CHROMEOS)
// A parameter to exclude or not exclude CanvasFontCache from
// PartialLowModeOnMidRangeDevices. This is used to see how
// CanvasFontCache affects graphics smoothness and renderer memory usage.
BASE_FEATURE_PARAM(bool,
                   kPartialLowEndModeExcludeCanvasFontCache,
                   &base::features::kPartialLowEndModeOnMidRangeDevices,
                   "exclude-canvas-font-cache",
                   false);
#endif  // BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_CHROMEOS)

// When enabled, this flag partitions the :visited link hashtable by
// <link url, top-level site, frame origin>
BASE_FEATURE(kPartitionVisitedLinkDatabase,
             "PartitionVisitedLinkDatabase",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Enables the use of the PaintCache for Path2D objects that are rasterized
// out of process.  Has no effect when kCanvasOopRasterization is disabled.
BASE_FEATURE(kPath2DPaintCache,
             "Path2DPaintCache",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Enable browser-initiated dedicated worker script loading
// (PlzDedicatedWorker). https://crbug.com/906991
BASE_FEATURE(kPlzDedicatedWorker,
             "PlzDedicatedWorker",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kDedicatedWorkerAblationStudyEnabled,
             "DedicatedWorkerAblationStudyEnabled",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE_PARAM(int,
                   kDedicatedWorkerStartDelayInMs,
                   &kDedicatedWorkerAblationStudyEnabled,
                   "DedicatedWorkerStartDelayInMs",
                   0);

BASE_FEATURE(kUseAncestorRenderFrameForWorker,
             "UseAncestorRenderFrameForWorker",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kPrecompileInlineScripts,
             "PrecompileInlineScripts",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Whether we should composite a PLSA (paint layer scrollable area) even if it
// means losing lcd text.
BASE_FEATURE(kPreferCompositingToLCDText,
             "PreferCompositingToLCDText",
// On Android we never have LCD text. On Chrome OS we prefer composited
// scrolling for better scrolling performance.
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_CHROMEOS)
             base::FEATURE_ENABLED_BY_DEFAULT
#else
             base::FEATURE_DISABLED_BY_DEFAULT
#endif
);

#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_ANDROID)
BASE_FEATURE(kPrefetchFontLookupTables,
             "PrefetchFontLookupTables",
#if BUILDFLAG(IS_WIN)
             base::FEATURE_DISABLED_BY_DEFAULT
#else
             base::FEATURE_ENABLED_BY_DEFAULT
#endif
);
#endif

// Prefetch request properties are updated to be privacy-preserving. See
// crbug.com/988956.
BASE_FEATURE(kPrefetchPrivacyChanges,
             "PrefetchPrivacyChanges",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kPreloadingHeuristicsMLModel,
             "PreloadingHeuristicsMLModel",
             base::FEATURE_DISABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(int,
                   kPreloadingModelTimerStartDelay,
                   &kPreloadingHeuristicsMLModel,
                   "timer_start_delay",
                   0);
BASE_FEATURE_PARAM(int,
                   kPreloadingModelTimerInterval,
                   &kPreloadingHeuristicsMLModel,
                   "timer_interval",
                   100);
BASE_FEATURE_PARAM(bool,
                   kPreloadingModelOneExecutionPerHover,
                   &kPreloadingHeuristicsMLModel,
                   "one_execution_per_hover",
                   true);
// The default max hover time of 10s covers the 98th percentile of hovering
// cases that are relevant to the model.
BASE_FEATURE_PARAM(base::TimeDelta,
                   kPreloadingModelMaxHoverTime,
                   &kPreloadingHeuristicsMLModel,
                   "max_hover_time",
                   base::Seconds(10));
BASE_FEATURE_PARAM(bool,
                   kPreloadingModelEnactCandidates,
                   &kPreloadingHeuristicsMLModel,
                   "enact_candidates",
                   false);
BASE_FEATURE_PARAM(int,
                   kPreloadingModelPrefetchModerateThreshold,
                   &kPreloadingHeuristicsMLModel,
                   "prefetch_moderate_threshold",
                   50);
BASE_FEATURE_PARAM(int,
                   kPreloadingModelPrerenderModerateThreshold,
                   &kPreloadingHeuristicsMLModel,
                   "prerender_moderate_threshold",
                   50);

BASE_FEATURE(kPreloadingViewportHeuristics,
             "PreloadingViewportHeuristics",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kPrerender2InNewTab,
             "Prerender2InNewTab",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kPrerender2MainFrameNavigation,
             "Prerender2MainFrameNavigation",
             base::FEATURE_ENABLED_BY_DEFAULT);

const char kPrerender2MaxNumOfRunningSpeculationRules[] =
    "max_num_of_running_speculation_rules";

BASE_FEATURE(kPrerender2MemoryControls,
             "Prerender2MemoryControls",
             base::FEATURE_ENABLED_BY_DEFAULT);
const char kPrerender2MemoryThresholdParamName[] = "memory_threshold_in_mb";
const char kPrerender2MemoryAcceptablePercentOfSystemMemoryParamName[] =
    "acceptable_percent_of_system_memory";

BASE_FEATURE(kPrerender2EarlyDocumentLifecycleUpdate,
             "Prerender2EarlyDocumentLifecycleUpdate",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kPrerender2NoVarySearch,
             "Prerender2NoVarySearch",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kPrerender2WarmUpCompositor,
             "Prerender2WarmUpCompositor",
             base::FEATURE_ENABLED_BY_DEFAULT);
const base::FeatureParam<Prerender2WarmUpCompositorTriggerPoint>::Option
    prerender2_warm_up_compositor_trigger_point[] = {
        {Prerender2WarmUpCompositorTriggerPoint::kDidCommitLoad,
         "did_commit_load"},
        {Prerender2WarmUpCompositorTriggerPoint::
             kDidDispatchDOMContentLoadedEvent,
         "did_dispatch_dom_content_loaded_event"},
        {Prerender2WarmUpCompositorTriggerPoint::kDidFinishLoad,
         "did_finish_load"},
};
BASE_FEATURE_ENUM_PARAM(Prerender2WarmUpCompositorTriggerPoint,
                        kPrerender2WarmUpCompositorTriggerPoint,
                        &kPrerender2WarmUpCompositor,
                        "trigger_point",
                        Prerender2WarmUpCompositorTriggerPoint::kDidCommitLoad,
                        &prerender2_warm_up_compositor_trigger_point);

// Enable limiting previews loading hints to specific resource types.
BASE_FEATURE(kPreviewsResourceLoadingHintsSpecificResourceTypes,
             "PreviewsResourceLoadingHintsSpecificResourceTypes",
             base::FEATURE_DISABLED_BY_DEFAULT);

#if BUILDFLAG(IS_WIN)
BASE_FEATURE(kPrewarmDefaultFontFamilies,
             "PrewarmDefaultFontFamilies",
             base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(bool,
                   kPrewarmStandard,
                   &kPrewarmDefaultFontFamilies,
                   "prewarm_standard",
                   false);
BASE_FEATURE_PARAM(bool,
                   kPrewarmFixed,
                   &kPrewarmDefaultFontFamilies,
                   "prewarm_fixed",
                   false);
BASE_FEATURE_PARAM(bool,
                   kPrewarmSerif,
                   &kPrewarmDefaultFontFamilies,
                   "prewarm_serif",
                   true);
BASE_FEATURE_PARAM(bool,
                   kPrewarmSansSerif,
                   &kPrewarmDefaultFontFamilies,
                   "prewarm_sans_serif",
                   true);
BASE_FEATURE_PARAM(bool,
                   kPrewarmCursive,
                   &kPrewarmDefaultFontFamilies,
                   "prewarm_cursive",
                   false);
BASE_FEATURE_PARAM(bool,
                   kPrewarmFantasy,
                   &kPrewarmDefaultFontFamilies,
                   "prewarm_fantasy",
                   false);
#endif

// Enables the Private Aggregation API. Note that this API also requires the
// `kPrivacySandboxAggregationService` to be enabled to successfully send
// reports.
BASE_FEATURE(kPrivateAggregationApi,
             "PrivateAggregationApi",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Selectively allows the JavaScript API to be disabled in just one of the
// contexts. The Protected Audience param's name has not been updated (from
// "fledge") for consistency across versions
BASE_FEATURE_PARAM(bool,
                   kPrivateAggregationApiEnabledInSharedStorage,
                   &kPrivateAggregationApi,
                   "enabled_in_shared_storage",
                   /*default_value=*/true);
BASE_FEATURE_PARAM(bool,
                   kPrivateAggregationApiEnabledInProtectedAudience,
                   &kPrivateAggregationApi,
                   "enabled_in_fledge",
                   /*default_value=*/true);

// Selectively allows the Protected Audience-specific extensions to be disabled.
// The name has not been updated (from "fledge") for consistency across versions
BASE_FEATURE_PARAM(bool,
                   kPrivateAggregationApiProtectedAudienceExtensionsEnabled,
                   &kPrivateAggregationApi,
                   "fledge_extensions_enabled",
                   /*default_value=*/true);

// Selectively allows the debug mode to be disabled while leaving the rest of
// the API in place. If disabled, any `enableDebugMode()` calls will essentially
// have no effect.
BASE_FEATURE_PARAM(bool,
                   kPrivateAggregationApiDebugModeEnabledAtAll,
                   &kPrivateAggregationApi,
                   "debug_mode_enabled_at_all",
                   /*default_value=*/true);

// Adds some additional functionality (new reserved event types, base values)
// to things enabled by
// kPrivateAggregationApiProtectedAudienceExtensionsEnabled.
BASE_FEATURE(kPrivateAggregationApiProtectedAudienceAdditionalExtensions,
             "PrivateAggregationApiProtectedAudienceAdditionalExtensions",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kProcessHtmlDataImmediately,
             "ProcessHtmlDataImmediately",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE_PARAM(bool,
                   kProcessHtmlDataImmediatelyChildFrame,
                   &kProcessHtmlDataImmediately,
                   "child",
                   false);

BASE_FEATURE_PARAM(bool,
                   kProcessHtmlDataImmediatelyFirstChunk,
                   &kProcessHtmlDataImmediately,
                   "first",
                   false);

BASE_FEATURE_PARAM(bool,
                   kProcessHtmlDataImmediatelyMainFrame,
                   &kProcessHtmlDataImmediately,
                   "main",
                   false);

BASE_FEATURE_PARAM(bool,
                   kProcessHtmlDataImmediatelySubsequentChunks,
                   &kProcessHtmlDataImmediately,
                   "rest",
                   false);

BASE_FEATURE(kProduceCompileHints2,
             "ProduceCompileHints2",
             base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(double,
                   kProduceCompileHintsNoiseLevel,
                   &kProduceCompileHints2,
                   "noise-probability",
                   0.5);
BASE_FEATURE_PARAM(double,
                   kProduceCompileHintsDataProductionLevel,
                   &kProduceCompileHints2,
                   "data-production-probability",
                   0.005);
BASE_FEATURE(kForceProduceCompileHints,
             "ForceProduceCompileHints",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kConsumeCompileHints,
             "ConsumeCompileHints",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kLocalCompileHints,
             "LocalCompileHints",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kQuoteEmptySecChUaStringHeadersConsistently,
             "QuoteEmptySecChUaStringHeadersConsistently",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Reduce the amount of information in the default 'referer' header for
// cross-origin requests.
BASE_FEATURE(kReducedReferrerGranularity,
             "ReducedReferrerGranularity",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE_PARAM(std::string,
                   kUserAgentFrozenBuildVersion,
                   &kReduceUserAgentMinorVersion,
                   "build_version",
                   "0");

BASE_FEATURE_PARAM(bool,
                   kAllExceptLegacyWindowsPlatform,
                   &kReduceUserAgentPlatformOsCpu,
                   "all_except_legacy_windows_platform",
                   true);

// When enabled, Source Location blocking BFCache is captured
// to send it to the browser.
BASE_FEATURE(kRegisterJSSourceLocationBlockingBFCache,
             "RegisterJSSourceLocationBlockingBFCache",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kRemoveAuthroizationOnCrossOriginRedirect,
             "RemoveAutorizationOnCrossOriginRedirect",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kInteractiveDetectorIgnoreFcp,
             "InteractiveDetectorIgnoreFcp",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kRenderBlockingFonts,
             "RenderBlockingFonts",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE_PARAM(int,
                   kMaxBlockingTimeMsForRenderBlockingFonts,
                   &features::kRenderBlockingFonts,
                   "max-blocking-time",
                   1500);

BASE_FEATURE_PARAM(int,
                   kMaxFCPDelayMsForRenderBlockingFonts,
                   &features::kRenderBlockingFonts,
                   "max-fcp-delay",
                   100);

BASE_FEATURE(kRenderSizeInScoreAdBrowserSignals,
             "RenderSizeInScoreAdBrowserSignals",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kResamplingInputEvents,
             "ResamplingInputEvents",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kResamplingScrollEvents,
             "ResamplingScrollEvents",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kRunTextInputUpdatePostLifecycle,
             "RunTextInputUpdatePostLifecycle",
             base::FEATURE_ENABLED_BY_DEFAULT);

// https://html.spec.whatwg.org/multipage/system-state.html#safelisted-scheme
BASE_FEATURE(kSafelistFTPToRegisterProtocolHandler,
             "SafelistFTPToRegisterProtocolHandler",
             base::FEATURE_ENABLED_BY_DEFAULT);

// https://html.spec.whatwg.org/multipage/system-state.html#safelisted-scheme
BASE_FEATURE(kSafelistPaytoToRegisterProtocolHandler,
             "SafelistPaytoToRegisterProtocolHandler",
             base::FEATURE_DISABLED_BY_DEFAULT);

// A feature to enable using the smallest image specified within image srcset
// for users with Save Data enabled.
BASE_FEATURE(kSaveDataImgSrcset,
             "SaveDataImgSrcset",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kPausePagesPerBrowsingContextGroup,
             "PausePagesPerBrowsingContextGroup",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kShowHudDisplayForPausedPages,
             "ShowHudDisplayForPausedPages",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Controls script streaming for http and https scripts.
BASE_FEATURE(kScriptStreaming,
             "ScriptStreaming",
             base::FEATURE_ENABLED_BY_DEFAULT);
// Enables script streaming for non-http scripts.
BASE_FEATURE(kScriptStreamingForNonHTTP,
             "ScriptStreamingForNonHTTP",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kSelectiveInOrderScript,
             "SelectiveInOrderScript",
             base::FEATURE_DISABLED_BY_DEFAULT);
BASE_FEATURE(kSelectiveInOrderScriptTarget,
             "SelectiveInOrderScriptTarget",
             base::FEATURE_DISABLED_BY_DEFAULT);
const base::FeatureParam<std::string> kSelectiveInOrderScriptAllowList{
    &kSelectiveInOrderScriptTarget, "allow_list", ""};

// When enabled, the SubresourceFilter receives calls from the ResourceLoader
// to perform additional checks against any aliases found from DNS CNAME records
// for the requested URL.
BASE_FEATURE
"""


```