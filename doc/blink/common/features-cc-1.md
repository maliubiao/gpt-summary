Response: The user wants to understand the functionality of the provided C++ code snippet from `blink/common/features.cc`. This file defines various "features" within the Chromium Blink engine, which are essentially flags that can be enabled or disabled to control certain behaviors or experiment with new functionalities.

The request asks for:
1. **Listing the functionalities** of the features defined in the code.
2. **Relating them to Javascript, HTML, and CSS**, providing examples.
3. **Illustrating logical reasoning** with hypothetical inputs and outputs.
4. **Pointing out common user errors** related to these features.
5. **A summary of the file's functionality** as part 2 of a 2-part request.

**Plan:**

1. **Parse the code:** Identify each `BASE_FEATURE`, `BASE_FEATURE_PARAM`, and `BASE_FEATURE_ENUM_PARAM`.
2. **Describe each feature:** Based on the name and description string provided in the code.
3. **Relate to web technologies:**  Think about how each feature might affect the rendering, scripting, or styling of web pages.
4. **Logical reasoning (limited):**  For some features with parameters, illustrate how the parameter value might influence behavior. Since these are mostly feature flags, the logic is primarily about whether the feature is enabled or disabled, and parameter values modify that behavior.
5. **User errors (limited):**  Consider how a developer or user might interact with or be affected by these features, especially if they are experimental or control performance-related aspects.
6. **Summarize:**  Provide a concise overview of the file's purpose.

**Mental Sandbox:**

* **LCP related features:** These directly impact performance metrics and can affect how quickly the most important content is displayed. Relate to user experience.
* **Prefetching/Prerendering:**  These features aim to speed up navigation and can be linked to HTML `<link>` tags and browser behavior.
* **Scripting features:** Features related to async script execution and priority directly impact Javascript execution order and performance.
* **Cache related features:**  These influence how browser caching works, impacting load times.
* **WebRTC features:**  These are specific to real-time communication and less directly related to basic HTML/CSS/JS but are part of the browser's capabilities.
* **Shared Storage API:**  This is a newer web API and directly interacts with Javascript.

**Key Insight:** The `features.cc` file is not about *implementing* the functionalities of Javascript, HTML, or CSS but about *controlling* various aspects of how Blink (the rendering engine) handles them.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 与javascript, html, css的功能有关系: Yes
* 做出对应的举例说明: Yes
* 如果做了逻辑推理，请给出假设输入与输出: Partially - Logic is mostly about enabling/disabling and parameter influence.
* 如果涉及用户常见的使用错误，请举例说明: Partially - User errors are less direct with feature flags, more about potential performance implications or unintended behavior if enabled/disabled.
* 这是第2部分，共2部分，请归纳一下它的功能: Yes

Confidence Score: 4/5 (Slight uncertainty on "logical reasoning" and "user errors" due to the nature of feature flags).
好的，这是对 `blink/common/features.cc` 文件功能的归纳总结，并结合之前提供的第一部分内容进行整合。

**功能归纳总结 (结合第一部分和第二部分):**

`blink/common/features.cc` 文件是 Chromium Blink 引擎中一个核心的配置文件，它的主要功能是**集中定义和管理各种功能特性（Features）的开关和参数**。 这些特性可以控制 Blink 引擎在渲染网页、执行 JavaScript、处理网络请求等方面的行为。

具体来说，这个文件：

* **声明了大量的布尔型、枚举型和参数化的 Feature Flags。**  每个 Feature Flag 代表一个特定的功能或实验性特性，可以通过全局开关或参数进行启用、禁用或配置。
* **为每个 Feature Flag 提供了人类可读的名称和描述。** 这有助于开发者理解该 Feature 的作用。
* **定义了部分 Feature Flag 的可选参数。** 这些参数允许更细粒度地控制 Feature 的行为，例如设置超时时间、阈值、策略等。
* **为部分枚举类型的 Feature Flag 定义了可选项。** 允许在预定义的几个选项中选择 Feature 的行为模式。
* **提供了一些辅助函数，用于在代码中查询特定 Feature Flag 的状态。** 例如 `IsFencedFramesEnabled()`。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

虽然 `features.cc` 文件本身不包含直接的 JavaScript、HTML 或 CSS 代码，但它定义的 Feature Flags **直接影响着 Blink 引擎如何解析、渲染和执行这些 Web 技术**。以下是一些例子：

* **JavaScript:**
    * **`kLowPriorityAsyncScriptExecution`:**  控制异步 JavaScript 脚本的执行优先级。如果启用，可以降低某些非关键脚本的优先级，从而可能影响页面的加载和交互性能。
        * **假设输入：**  一个包含多个 `<script async>` 标签的 HTML 页面。
        * **输出：** 如果 `kLowPriorityAsyncScriptExecution` 启用，某些被判断为非关键的异步脚本可能会延迟执行。
    * **`kPrecompileInlineScripts`:**  控制是否预编译内联 JavaScript 脚本。启用后可以提升 JavaScript 的执行效率。
    * **`kSetTimeoutWithoutClamp`:**  允许 `setTimeout(..., 0)` 不被限制为 1ms 的最小延迟。这会影响 JavaScript 定时器的精确度。
* **HTML:**
    * **`kFencedFrames`:**  启用或禁用 Fenced Frames 功能，这是一种隔离嵌入内容的方式，与 HTML 的 `<iframe>` 元素类似但具有更强的隐私保护特性。
    * **`kLinkPreview`:**  控制链接预览功能的启用与否，用户可以通过特定交互（例如 Alt+点击/悬停）预览链接指向的页面。
    * **`kSpeculationRulesPrefetchFuture`:** 启用基于推测规则的预加载机制，可以通过 HTML 中的 `<script type="speculationrules">` 标签来指定预加载的资源或页面。
* **CSS:**
    * **`kPaintHolding`:**  控制是否启用 Paint Holding 功能，可以延迟页面的首次渲染，以避免 FOUC (Flash of Unstyled Content)。这影响 CSS 样式的应用时机。
    * **`kWebFontsCacheAwareTimeoutAdaption`:**  影响 Web Fonts 的加载策略，可以根据缓存情况调整字体加载的超时时间，从而影响页面文本的渲染。
    * **`kPreferCompositingToLCDText`:**  决定在某些情况下是否优先使用 Compositing (合成层) 而不是 LCD 文本渲染，这会影响文本的显示效果。

**逻辑推理的假设输入与输出 (更多基于参数化的 Feature):**

* **`kLCPPMultipleKey` (启用) 和 `kLCPPMultipleKeyMaxPathLength` (设置为 10):**
    * **假设输入：** 一个网页的 LCP (Largest Contentful Paint) 元素路径长度为 12。
    * **输出：** 由于 `kLCPPMultipleKeyMaxPathLength` 设置为 10，该 LCP 元素可能不会被完整地追踪，可能会截断路径信息。
* **`kHttpDiskCachePrewarming` (启用) 和 `kHttpDiskCachePrewarmingMaxUrlLength` (设置为 512):**
    * **假设输入：**  一个需要预热的 URL 长度为 700 字符。
    * **输出：** 该 URL 由于超过 `kHttpDiskCachePrewarmingMaxUrlLength` 的限制，可能不会被预热到 HTTP 磁盘缓存中。
* **`kLowPriorityAsyncScriptExecution` (启用) 和 `kTimeoutForLowPriorityAsyncScriptExecution` (设置为 500ms):**
    * **假设输入：**  一个低优先级的异步脚本开始执行，并在 400ms 后完成。
    * **输出：** 该脚本正常执行完成。
    * **假设输入：**  另一个低优先级的异步脚本开始执行，但在 500ms 后仍未完成。
    * **输出：** 该脚本可能被终止或降级处理，具体行为取决于 Blink 的内部实现。

**用户常见的使用错误举例:**

由于这些 Feature Flags 主要影响浏览器引擎的内部行为，普通用户直接配置它们的机会较少。 常见的使用错误更多发生在开发者和测试人员层面：

* **错误地理解 Feature Flag 的作用:** 启用或禁用某个 Feature Flag 而不清楚其具体影响，可能导致意外的性能问题或功能异常。例如，禁用 `kThreadedBodyLoader` 可能会影响某些网页的加载速度。
* **在不合适的场景下启用实验性 Feature:**  某些 Feature 可能是实验性的，启用后可能引入 bug 或不稳定性。
* **忘记 Feature Flag 的依赖关系:**  某些 Feature 的启用可能依赖于其他 Feature 的状态。例如，`IsParkableStringsToDiskEnabled()` 的前提是 `kCompressParkableStrings` 已启用。
* **过度依赖 Feature Flags 进行 A/B 测试:**  虽然 Feature Flags 可以用于 A/B 测试，但如果不进行充分的监控和分析，可能会得出错误的结论。
* **在生产环境中使用不稳定的 Feature Flags:**  这可能导致难以预测的行为和用户体验问题。

**总结:**

`blink/common/features.cc` 定义了 Blink 引擎的各种功能开关和参数，是控制浏览器行为的核心配置文件。 这些 Feature Flags 深刻影响着网页的加载、渲染、脚本执行以及各种 Web API 的行为。 理解这些 Feature Flags 的作用对于 Blink 引擎的开发、测试以及性能优化至关重要。 开发者可以通过配置这些 Flags 来启用或禁用特定功能，进行实验，或者调整浏览器的行为以适应不同的场景。

### 提示词
```
这是目录为blink/common/features.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
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
BASE_FEATURE(kSendCnameAliasesToSubresourceFilterFromRenderer,
             "SendCnameAliasesToSubresourceFilterFromRenderer",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Experiment of the delay from navigation to starting an update of a service
// worker's script.
BASE_FEATURE(kServiceWorkerUpdateDelay,
             "ServiceWorkerUpdateDelay",
             base::FEATURE_DISABLED_BY_DEFAULT);

// If disabled, client_id and resultingClientId behavior keeps the old
// Chromium behavior even after the PlzDedicatedWorker is enabled.
// This is workaround for crbug.com/1520512 until the fix gets ready.
BASE_FEATURE(kServiceWorkerClientIdAlignedWithSpec,
             "ServiceWorkerClientIdAlignedWithSpec",
             base::FEATURE_ENABLED_BY_DEFAULT);

// When enabled, beacons (and friends) have ResourceLoadPriority::kLow,
// not ResourceLoadPriority::kVeryLow.
BASE_FEATURE(kSetLowPriorityForBeacon,
             "SetLowPriorityForBeacon",
             base::FEATURE_DISABLED_BY_DEFAULT);

// If enabled, the setTimeout(..., 0) will not clamp to 1ms.
// Tracking bug: https://crbug.com/402694.
BASE_FEATURE(kSetTimeoutWithoutClamp,
             "SetTimeoutWithoutClamp",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Enable the shared storage API. Note that enabling this feature does not
// automatically expose this API to the web, it only allows the element to be
// enabled by the runtime enabled feature, for origin trials.
// https://github.com/pythagoraskitty/shared-storage/blob/main/README.md
BASE_FEATURE(kSharedStorageAPI,
             "SharedStorageAPI",
             base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(size_t,
                   kSharedStorageURLSelectionOperationInputURLSizeLimit,
                   &kSharedStorageAPI,
                   "url_selection_operation_input_url_size_limit",
                   8);
BASE_FEATURE_PARAM(int,
                   kMaxSharedStoragePageSize,
                   &kSharedStorageAPI,
                   "MaxSharedStoragePageSize",
                   4096);
BASE_FEATURE_PARAM(int,
                   kMaxSharedStorageCacheSize,
                   &kSharedStorageAPI,
                   "MaxSharedStorageCacheSize",
                   1024);
BASE_FEATURE_PARAM(int,
                   kMaxSharedStorageInitTries,
                   &kSharedStorageAPI,
                   "MaxSharedStorageInitTries",
                   2);
BASE_FEATURE_PARAM(int,
                   kMaxSharedStorageIteratorBatchSize,
                   &kSharedStorageAPI,
                   "MaxSharedStorageIteratorBatchSize",
                   100);
BASE_FEATURE_PARAM(int,
                   kSharedStorageBitBudget,
                   &kSharedStorageAPI,
                   "SharedStorageBitBudget",
                   12);
BASE_FEATURE_PARAM(base::TimeDelta,
                   kSharedStorageBudgetInterval,
                   &kSharedStorageAPI,
                   "SharedStorageBudgetInterval",
                   base::Hours(24));
BASE_FEATURE_PARAM(base::TimeDelta,
                   kSharedStorageStalePurgeInitialInterval,
                   &kSharedStorageAPI,
                   "SharedStorageStalePurgeInitialInterval",
                   base::Minutes(2));
BASE_FEATURE_PARAM(base::TimeDelta,
                   kSharedStorageStalePurgeRecurringInterval,
                   &kSharedStorageAPI,
                   "SharedStorageStalePurgeRecurringInterval",
                   base::Hours(2));
BASE_FEATURE_PARAM(base::TimeDelta,
                   kSharedStorageStalenessThreshold,
                   &kSharedStorageAPI,
                   "SharedStorageStalenessThreshold",
                   base::Days(30));
BASE_FEATURE_PARAM(size_t,
                   kSharedStorageMaxAllowedFencedFrameDepthForSelectURL,
                   &kSharedStorageAPI,
                   "SharedStorageMaxAllowedFencedFrameDepthForSelectURL",
                   1);
// NOTE: To preserve user privacy, the
// `kSharedStorageExposeDebugMessageForSettingsStatus` feature param MUST remain
// false by default.
BASE_FEATURE_PARAM(bool,
                   kSharedStorageExposeDebugMessageForSettingsStatus,
                   &kSharedStorageAPI,
                   "ExposeDebugMessageForSettingsStatus",
                   false);

BASE_FEATURE(kSharedStorageWorkletSharedBackingThreadImplementation,
             "SharedStorageWorkletSharedBackingThreadImplementation",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kSharedStorageAPIM118,
             "SharedStorageAPIM118",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kSharedStorageAPIM125,
             "SharedStorageAPIM125",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kSharedStorageCrossOriginScript,
             "SharedStorageCrossOriginScript",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kSharedStorageCreateWorkletUseContextOriginByDefault,
             "SharedStorageCreateWorkletUseContextOriginByDefault",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kSharedStorageCreateWorkletCustomDataOrigin,
             "SharedStorageCreateWorkletCustomDataOrigin",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kSharedStorageSelectURLSavedQueries,
             "SharedStorageSelectURLSavedQueries",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kSharedStorageAPIEnableWALForDatabase,
             "SharedStorageAPIEnableWALForDatabase",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kSimplifyLoadingTransparentPlaceholderImage,
             "SimplifyLoadingTransparentPlaceholderImage",
             base::FEATURE_ENABLED_BY_DEFAULT);

const char kSkipTouchEventFilterTypeParamName[] = "type";
const char kSkipTouchEventFilterTypeParamValueDiscrete[] = "discrete";
const char kSkipTouchEventFilterTypeParamValueAll[] = "all";
const char kSkipTouchEventFilterFilteringProcessParamName[] =
    "skip_filtering_process";
const char kSkipTouchEventFilterFilteringProcessParamValueBrowser[] = "browser";
const char kSkipTouchEventFilterFilteringProcessParamValueBrowserAndRenderer[] =
    "browser_and_renderer";

BASE_FEATURE(kSpeculationRulesPrefetchFuture,
             "SpeculationRulesPrefetchFuture",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kSpeculativeImageDecodes,
             "SpeculativeImageDecodes",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Enable service worker warming-up feature. (https://crbug.com/1431792)
BASE_FEATURE(kSpeculativeServiceWorkerWarmUp,
             "SpeculativeServiceWorkerWarmUp",
             base::FEATURE_DISABLED_BY_DEFAULT);

// kSpeculativeServiceWorkerWarmUp warms up service workers up to this max
// count.
BASE_FEATURE_PARAM(int,
                   kSpeculativeServiceWorkerWarmUpMaxCount,
                   &kSpeculativeServiceWorkerWarmUp,
                   "sw_warm_up_max_count",
                   10);

// Duration to keep worker warmed-up.
BASE_FEATURE_PARAM(base::TimeDelta,
                   kSpeculativeServiceWorkerWarmUpDuration,
                   &kSpeculativeServiceWorkerWarmUp,
                   "sw_warm_up_duration",
                   base::Minutes(10));

// Warms up service workers when a pointerover event is triggered on an anchor.
const base::FeatureParam<bool> kSpeculativeServiceWorkerWarmUpOnPointerover{
    &kSpeculativeServiceWorkerWarmUp, "sw_warm_up_on_pointerover", true};

// Warms up service workers when a pointerdown event is triggered on an anchor.
const base::FeatureParam<bool> kSpeculativeServiceWorkerWarmUpOnPointerdown{
    &kSpeculativeServiceWorkerWarmUp, "sw_warm_up_on_pointerdown", true};

// Warms up service worker after service worker is stopped on idle timeout.
const base::FeatureParam<bool> kSpeculativeServiceWorkerWarmUpOnIdleTimeout{
    &kSpeculativeServiceWorkerWarmUp, "sw_warm_up_on_idle_timeout", true};

// If enabled, ServiceWorkerStorage suppresses posting tasks when it is
// possible. This behavior is expected to improve performance by getting rid of
// redundant posting tasks.
BASE_FEATURE(kServiceWorkerStorageSuppressPostTask,
             "ServiceWorkerStorageSuppressPostTask",
             base::FEATURE_ENABLED_BY_DEFAULT);

// If enabled, force renderer process foregrounded from CommitNavigation to
// DOMContentLoad (crbug/351953350).
BASE_FEATURE(kBoostRenderProcessForLoading,
             "BoostRenderProcessForLoading",
             base::FEATURE_DISABLED_BY_DEFAULT);

// An empty json array means that this feature is applied unconditionally. If
// specified, it means that the specified URLs will be the target of the new
// behavior.
BASE_FEATURE_PARAM(std::string,
                   kBoostRenderProcessForLoadingTargetUrls,
                   &kBoostRenderProcessForLoading,
                   "target_urls",
                   "[]");

// If true is specified, kBoostRenderProcessForLoading feature also prioritizes
// the renderer process that is used for prerendering. This is a part of an
// ablation study. See https://crbug.com/351953350.
BASE_FEATURE_PARAM(bool,
                   kBoostRenderProcessForLoadingPrioritizePrerendering,
                   &kBoostRenderProcessForLoading,
                   "prioritize_prerendering",
                   false);

// If true is specified, kBoostRenderProcessForLoading feature only prioritizes
// the renderer process that is used for prerendering. This is a part of an
// ablation study. See https://crbug.com/351953350.
BASE_FEATURE_PARAM(bool,
                   kBoostRenderProcessForLoadingPrioritizePrerenderingOnly,
                   &kBoostRenderProcessForLoading,
                   "prioritize_prerendering_only",
                   false);

// Freeze scheduler task queues in background after allowed grace time.
// "stop" is a legacy name.
BASE_FEATURE(kStopInBackground,
             "stop-in-background",
// b/248036988 - Disable this for Chromecast on Android builds to prevent apps
// that play audio in the background from stopping.
#if BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_CAST_ANDROID) && \
    !BUILDFLAG(IS_DESKTOP_ANDROID)
             base::FEATURE_ENABLED_BY_DEFAULT
#else
             base::FEATURE_DISABLED_BY_DEFAULT
#endif
);

// Reduces the work done during renderer initialization.
BASE_FEATURE(kStreamlineRendererInit,
             "StreamlineRendererInit",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kSubSampleWindowProxyUsageMetrics,
             "SubSampleWindowProxyUsageMetrics",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kStylusPointerAdjustment,
             "StylusPointerAdjustment",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kStylusRichGestures,
             "StylusRichGestures",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kThreadedBodyLoader,
             "ThreadedBodyLoader",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kThreadedPreloadScanner,
             "ThreadedPreloadScanner",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Enable throttling of fetch() requests from service workers in the
// installing state.  The limit of 3 was chosen to match the limit
// in background main frames.  In addition, trials showed that this
// did not cause excessive timeouts and resulted in a net improvement
// in successful install rate on some platforms.
BASE_FEATURE(kThrottleInstallingServiceWorker,
             "ThrottleInstallingServiceWorker",
             base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(int,
                   kInstallingServiceWorkerOutstandingThrottledLimit,
                   &kThrottleInstallingServiceWorker,
                   "limit",
                   3);

// Throttles Javascript timer wake ups of unimportant frames (cross origin
// frames with small proportion of the page's visible area and no user
// activation) on foreground pages.
BASE_FEATURE(kThrottleUnimportantFrameTimers,
             "ThrottleUnimportantFrameTimers",
             base::FEATURE_DISABLED_BY_DEFAULT);
// Interval between Javascript timer wake ups for unimportant frames (small
// cross origin frames with no user activation) when the
// "ThrottleUnimportantFrameTimers" feature is enabled.
BASE_FEATURE_PARAM(int,
                   kUnimportantFrameTimersThrottledWakeUpIntervalMills,
                   &features::kThrottleUnimportantFrameTimers,
                   "unimportant_frame_timers_throttled_wake_up_interval_millis",
                   32);
// The percentage of the page's visible area below which a frame is considered
// small. Only small frames can be throttled by ThrottleUnimportantFrameTimers.
BASE_FEATURE_PARAM(int,
                   kLargeFrameSizePercentThreshold,
                   &features::kThrottleUnimportantFrameTimers,
                   "large_frame_size_percent_threshold",
                   75);

BASE_FEATURE(kTimedHTMLParserBudget,
             "TimedHTMLParserBudget",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kTreatHTTPExpiresHeaderValueZeroAsExpiredInBlink,
             "TreatHTTPExpiresHeaderValueZeroAsExpiredInBlink",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Changes behavior of User-Agent Client Hints to send blank headers when the
// User-Agent string is overridden, instead of disabling the headers altogether.
BASE_FEATURE(kUACHOverrideBlank,
             "UACHOverrideBlank",
             base::FEATURE_DISABLED_BY_DEFAULT);

// If enabled, the body of `EmulateLoadStartedForInspector` is executed only
// once per Resource per ResourceFetcher, and thus duplicated network load
// entries in DevTools caused by `EmulateLoadStartedForInspector` are removed.
// https://crbug.com/1502591
BASE_FEATURE(kEmulateLoadStartedForInspectorOncePerResource,
             "kEmulateLoadStartedForInspectorOncePerResource",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kBlinkSchedulerDiscreteInputMatchesResponsivenessMetrics,
             "BlinkSchedulerDiscreteInputMatchesResponsivenessMetrics",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kThreadedScrollPreventRenderingStarvation,
             "ThreadedScrollPreventRenderingStarvation",
             base::FEATURE_DISABLED_BY_DEFAULT);

// If enabled, the usage of unload handlers causes a blocklisted reason for
// BFCache. The purpose is to capture their source location.
BASE_FEATURE(kUnloadBlocklisted,
             "UnloadBlocklisted",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Whether to use 'TexImage2D' instead of 'TexStorage2DEXT' when creating a
// staging texture for |DrawingBuffer|. This is a killswitch; remove when
// launched.
BASE_FEATURE(kUseImageInsteadOfStorageForStagingBuffer,
             "UseImageInsteadOfStorageForStagingBuffer",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Uses page viewport instead of frame viewport in the Largest Contentful Paint
// heuristic where images occupying the full viewport are ignored.
BASE_FEATURE(kUsePageViewportInLCP,
             "UsePageViewportInLCP",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Enabling this will cause parkable strings to use Snappy for compression iff
// kCompressParkableStrings is enabled.
BASE_FEATURE(kUseSnappyForParkableStrings,
             "UseSnappyForParkableStrings",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Use the zstd compression algorithm for ParkableString compression.
BASE_FEATURE(kUseZstdForParkableStrings,
             "UseZstdForParkableStrings",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Allows to tweak the compression / speed tradeoff.
//
// According to https://github.com/facebook/zstd, level 1 should be:
// - Much faster than zlib, with a similar compression ratio
// - Roughly as fast as snappy, with a better compression ratio.
//
// And even -3 should be smaller *and* faster than snappy.
BASE_FEATURE_PARAM(int,
                   kZstdCompressionLevel,
                   &features::kUseZstdForParkableStrings,
                   "compression_level",
                   1);

BASE_FEATURE(kUseThreadPoolForMediaStreamVideoTaskRunner,
             "UseThreadPoolForMediaStreamVideoTaskRunner",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kVSyncDecoding,
             "VSyncDecoding",
             base::FEATURE_DISABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(base::TimeDelta,
                   kVSyncDecodingHiddenOccludedTickDuration,
                   &kVSyncDecoding,
                   "occluded_tick_duration",
                   base::Hertz(10));

BASE_FEATURE(kVSyncEncoding,
             "VSyncEncoding",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kWebRtcUseCaptureBeginTimestamp,
             "WebRtcUseCaptureBeginTimestamp",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kWebRtcAudioSinkUseTimestampAligner,
             "WebRtcAudioSinkUseTimestampAligner",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Enable borderless mode for desktop PWAs. go/borderless-mode
BASE_FEATURE(kWebAppBorderless,
             "WebAppBorderless",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Controls scope extensions feature in web apps. Controls parsing of
// "scope_extensions" field in web app manifests. See explainer for more
// information:
// https://github.com/WICG/manifest-incubations/blob/gh-pages/scope_extensions-explainer.md
BASE_FEATURE(kWebAppEnableScopeExtensions,
             "WebAppEnableScopeExtensions",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Controls URL handling feature in web apps. Controls parsing of "url_handlers"
// field in web app manifests. See explainer for more information:
// https://github.com/WICG/pwa-url-handler/blob/main/explainer.md
BASE_FEATURE(kWebAppEnableUrlHandlers,
             "WebAppEnableUrlHandlers",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Controls parsing of the "lock_screen" dictionary field and its "start_url"
// entry in web app manifests.  See explainer for more information:
// https://github.com/WICG/lock-screen/
// Note: the lock screen API and OS integration is separately controlled by
// the content feature `kWebLockScreenApi`.
BASE_FEATURE(kWebAppManifestLockScreen,
             "WebAppManifestLockScreen",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Parameters can be used to control to which latency hints the feature is
// applied.
BASE_FEATURE_PARAM(bool,
                   kWebAudioBypassOutputBufferingInteractive,
                   &kWebAudioBypassOutputBuffering,
                   "latency_interactive",
                   true);
BASE_FEATURE_PARAM(bool,
                   kWebAudioBypassOutputBufferingBalanced,
                   &kWebAudioBypassOutputBuffering,
                   "latency_balanced",
                   true);
BASE_FEATURE_PARAM(bool,
                   kWebAudioBypassOutputBufferingPlayback,
                   &kWebAudioBypassOutputBuffering,
                   "latency_playback",
                   true);
BASE_FEATURE_PARAM(bool,
                   kWebAudioBypassOutputBufferingExact,
                   &kWebAudioBypassOutputBuffering,
                   "latency_exact",
                   true);

/// Enables cache-aware WebFonts loading. See https://crbug.com/570205.
// The feature is disabled on Android for WebView API issue discussed at
// https://crbug.com/942440.
BASE_FEATURE(kWebFontsCacheAwareTimeoutAdaption,
             "WebFontsCacheAwareTimeoutAdaption",
#if BUILDFLAG(IS_ANDROID)
             base::FEATURE_DISABLED_BY_DEFAULT
#else
             base::FEATURE_ENABLED_BY_DEFAULT
#endif
);

BASE_FEATURE(kWebRtcCombinedNetworkAndWorkerThread,
             "WebRtcCombinedNetworkAndWorkerThread",
             base::FEATURE_ENABLED_BY_DEFAULT);

// TODO(crbug.com/355256378): OpenH264 for encoding and FFmpeg for H264 decoding
// should be detangled such that software decoding can be enabled without
// software encoding.
#if BUILDFLAG(RTC_USE_H264) && BUILDFLAG(ENABLE_FFMPEG_VIDEO_DECODERS) && \
    BUILDFLAG(ENABLE_OPENH264)
// Run-time feature for the |rtc_use_h264| encoder/decoder.
BASE_FEATURE(kWebRtcH264WithOpenH264FFmpeg,
             "WebRTC-H264WithOpenH264FFmpeg",
             base::FEATURE_ENABLED_BY_DEFAULT);
#endif  // BUILDFLAG(RTC_USE_H264) && BUILDFLAG(ENABLE_FFMPEG_VIDEO_DECODERS) &&
        // BUILDFLAG(ENABLE_OPENH264)

// Causes WebRTC to replace host ICE candidate IP addresses with generated
// names ending in ".local" and resolve them using mDNS.
// http://crbug.com/878465
BASE_FEATURE(kWebRtcHideLocalIpsWithMdns,
             "WebRtcHideLocalIpsWithMdns",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Causes WebRTC to not set the color space of video frames on the receive side
// in case it's unspecified. Otherwise we will guess that the color space is
// BT709. http://crbug.com/1129243
BASE_FEATURE(kWebRtcIgnoreUnspecifiedColorSpace,
             "WebRtcIgnoreUnspecifiedColorSpace",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kWebRtcThreadsUseResourceEfficientType,
             "WebRtcThreadsUseResourceEfficientType",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Instructs WebRTC to honor the Min/Max Video Encode Accelerator dimensions.
BASE_FEATURE(kWebRtcUseMinMaxVEADimensions,
             "WebRtcUseMinMaxVEADimensions",
// TODO(crbug.com/1008491): enable other platforms.
#if BUILDFLAG(IS_CHROMEOS)
             base::FEATURE_ENABLED_BY_DEFAULT
#else
             base::FEATURE_DISABLED_BY_DEFAULT
#endif
);

// Allow access to WebSQL APIs.
BASE_FEATURE(kWebSQLAccess, "kWebSQLAccess", base::FEATURE_DISABLED_BY_DEFAULT);

// Kill switch for https://crbug.com/338955051.
BASE_FEATURE(kWebUSBTransferSizeLimit,
             "WebUSBTransferSizeLimit",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Enables small accelerated canvases for webview (crbug.com/1004304)
BASE_FEATURE(kWebviewAccelerateSmallCanvases,
             "WebviewAccelerateSmallCanvases",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Whether `blink::MemoryCache` and `blink::ResourceFetcher` release their
// strong references to resources on memory pressure.
BASE_FEATURE(kReleaseResourceStrongReferencesOnMemoryPressure,
             "ReleaseResourceStrongReferencesOnMemoryPressure",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Whether `blink::Resource` deletes its decoded data on memory pressure.
BASE_FEATURE(kReleaseResourceDecodedDataOnMemoryPressure,
             "ReleaseResourceDecodedDataOnMemoryPressure",
             base::FEATURE_ENABLED_BY_DEFAULT);

// When adding new features or constants for features, please keep the features
// sorted by identifier name (e.g. `kAwesomeFeature`), and the constants for
// that feature grouped with the associated feature.
//
// When defining feature params for auto-generated features (e.g. from
// `RuntimeEnabledFeatures)`, they should still be ordered in this section based
// on the identifier name of the generated feature.

// ---------------------------------------------------------------------------
// Helper functions for querying feature status. Please define any features or
// constants for features in the section above.

bool IsAllowURNsInIframeEnabled() {
  return base::FeatureList::IsEnabled(blink::features::kAllowURNsInIframes);
}

bool IsCanvas2DHibernationEnabled() {
  return base::FeatureList::IsEnabled(features::kCanvas2DHibernation);
}

bool DisplayWarningDeprecateURNIframesUseFencedFrames() {
  return base::FeatureList::IsEnabled(
      blink::features::kDisplayWarningDeprecateURNIframesUseFencedFrames);
}

bool IsFencedFramesEnabled() {
  return base::FeatureList::IsEnabled(blink::features::kFencedFrames);
}

bool IsParkableStringsToDiskEnabled() {
  // Always enabled as soon as compression is enabled.
  return base::FeatureList::IsEnabled(kCompressParkableStrings);
}

bool IsParkableImagesToDiskEnabled() {
  return base::FeatureList::IsEnabled(kParkableImagesToDisk);
}

bool IsSetTimeoutWithoutClampEnabled() {
  return base::FeatureList::IsEnabled(features::kSetTimeoutWithoutClamp);
}

bool IsUnloadBlocklisted() {
  return base::FeatureList::IsEnabled(kUnloadBlocklisted);
}

bool ParkableStringsUseSnappy() {
  return base::FeatureList::IsEnabled(kUseSnappyForParkableStrings);
}

bool IsKeepAliveURLLoaderServiceEnabled() {
  return base::FeatureList::IsEnabled(kKeepAliveInBrowserMigration) ||
         base::FeatureList::IsEnabled(kFetchLaterAPI);
}

bool IsLinkPreviewTriggerTypeEnabled(LinkPreviewTriggerType type) {
  return base::FeatureList::IsEnabled(blink::features::kLinkPreview) &&
         type == blink::features::kLinkPreviewTriggerType.Get();
}

// DO NOT ADD NEW FEATURES HERE.
//
// The section above is for helper functions for querying feature status. The
// section below should have nothing. Please add new features in the giant block
// of features that already exist in this file, trying to keep newly-added
// features in sorted order.
//
// DO NOT ADD NEW FEATURES HERE.

}  // namespace blink::features
```