Response:
The user wants to understand the functionality of the `blink/common/features.cc` file in the Chromium Blink engine. Specifically, they are interested in:

1. **General Functionality:** What is the purpose of this file?
2. **Relationship to Web Technologies:** How do the features relate to JavaScript, HTML, and CSS? Provide examples.
3. **Logical Reasoning:**  If there are features that involve conditional behavior, provide examples of input and output.
4. **Common User/Programming Errors:** Identify potential mistakes users or developers might make related to these features.
5. **Summary:** A concise overview of the file's role.

The provided code snippet is a collection of `base::FEATURE` and `base::FEATURE_PARAM` definitions. These are flags used to control the behavior of the Blink rendering engine. Each flag can be enabled or disabled, and some have associated parameters.

**Mental Sandbox:**

* **Core Idea:** This file defines a set of feature flags that can be toggled on or off in the Blink engine. This allows for experimenting with new functionality, A/B testing, and controlling the behavior of the engine in different scenarios.
* **Relationship to Web Technologies:**  Many of these flags directly impact how JavaScript, HTML, and CSS are processed and rendered. For instance, flags related to `setTimeout`, Service Workers, Shared Storage, and WebRTC directly affect JavaScript APIs and their behavior. Flags related to speculation rules and image decoding impact how HTML content is loaded and rendered. CSS itself is not directly manipulated by these flags at a high level, but features like font loading and rendering performance can be affected.
* **Logical Reasoning:** The flags themselves represent a binary choice (enabled/disabled). The parameters add a layer of configuration. For example, the `kSetTimeoutWithoutClamp` flag determines if `setTimeout(..., 0)` behaves in a specific way. Input: `setTimeout(myFunction, 0)`. Output: If the flag is enabled, `myFunction` will execute as soon as possible; if disabled, there might be a 1ms clamp.
* **User/Programming Errors:**  Misunderstanding the default state of a feature or incorrectly configuring its parameters could lead to unexpected behavior. For example, relying on a feature that is disabled by default in production.
* **Structure:** The file is essentially a list of feature definitions. The helper functions at the end provide a way to easily check the status of specific features within the Blink codebase.

**Constraint Checklist & Confidence Score:**

1. List functionality: Yes.
2. Relation to JS/HTML/CSS with examples: Yes.
3. Logical reasoning with input/output: Yes.
4. Common user/programming errors with examples: Yes.
5. Part 4 of 4 and summary: Yes.

Confidence Score: 5/5

**Plan of Action:**

1. Explain that the file defines feature flags for the Blink engine.
2. For each category (JS, HTML, CSS), select a few relevant flags and explain their impact, providing code examples.
3. Choose a flag with parameters and demonstrate the effect of different parameter values.
4. Discuss common errors like assuming a feature is enabled or misconfiguring parameters.
5. Summarize the file's function as a central location for controlling Blink's behavior.

Strategizing complete. Proceeding with response generation.

`blink/common/features.cc` 是 Chromium Blink 引擎中的一个关键文件，它定义了一系列**特性标志 (feature flags)**，用于控制 Blink 引擎的各种功能和行为。 这些特性标志允许开发者在不修改大量代码的情况下，启用或禁用特定的功能，进行实验、A/B 测试或者控制功能的发布。

**它的主要功能可以归纳为：**

1. **功能开关:**  定义了大量的布尔型标志（`BASE_FEATURE`），用于启用或禁用 Blink 引擎的特定功能。
2. **参数配置:**  定义了带参数的特性标志（`BASE_FEATURE_PARAM`），允许对特定功能的行为进行更细粒度的配置，例如设置阈值、时间间隔、大小限制等。

**与 JavaScript, HTML, CSS 的功能关系及举例说明：**

这个文件中的许多特性标志都直接或间接地影响着 JavaScript, HTML 和 CSS 的处理和渲染行为。

**与 JavaScript 的关系：**

* **`kSetTimeoutWithoutClamp`:**  控制 `setTimeout(..., 0)` 的行为。
    * **如果启用：** `setTimeout(myFunction, 0)` 会尽可能快地执行 `myFunction`，不会被限制到至少 1 毫秒。
    * **如果禁用（默认）：** `setTimeout(myFunction, 0)` 会被限制到至少 1 毫秒的延迟。
    * **假设输入：** JavaScript 代码 `setTimeout(() => console.log("Hello"), 0);`
    * **输出：** 启用时，"Hello" 几乎立即输出；禁用时，可能会有短暂的延迟（至少 1 毫秒）。
* **`kServiceWorkerUpdateDelay`:**  影响 Service Worker 脚本更新的延迟。这直接关系到 JavaScript 编写的 Service Worker 的行为。
* **`kSharedStorageAPI`:** 启用共享存储 API，这是一个新的 Web API，允许网站存储和访问跨站点的、与用户分区的数据。这需要在 JavaScript 中使用相应的 API 进行操作。
    * **假设输入：**  JavaScript 代码尝试调用 `sharedStorage.selectURL(...)`。
    * **输出：** 只有当 `kSharedStorageAPI` 启用并且相关 Runtime Enabled Feature 也启用时，该 API 才能正常工作。
* **`kThrottleUnimportantFrameTimers`:** 节流不重要帧（例如，跨域 iframe）的 JavaScript 定时器唤醒。
    * **假设输入：** 一个包含跨域 iframe 的页面，iframe 中有一个频繁触发的 `setInterval` 定时器。
    * **输出：** 如果 `kThrottleUnimportantFrameTimers` 启用，并且 iframe 被认为是“不重要”的，其定时器触发频率会降低，从而节省资源。

**与 HTML 的关系：**

* **`kSpeculationRulesPrefetchFuture`:** 启用预测规则预加载功能，这允许浏览器根据 HTML 中指定的 `<link rel="prefetch">` 等规则提前加载资源。
    * **假设输入：** HTML 代码包含 `<link rel="prefetch" href="/next-page">`。
    * **输出：** 如果 `kSpeculationRulesPrefetchFuture` 启用，浏览器可能会在用户访问之前就加载 `/next-page` 资源，从而加快页面加载速度。
* **`kFencedFrames`:** 启用隔离框架（Fenced Frames），这是一种新的 HTML 功能，用于在保护隐私的情况下嵌入内容。
* **`kSimplifyLoadingTransparentPlaceholderImage`:** 优化透明占位符图片的加载。
* **`kWebAppManifestLockScreen`:**  控制对 Web App Manifest 中 "lock_screen" 字段的解析，该字段允许 Web 应用在锁屏界面上显示内容。

**与 CSS 的关系：**

虽然这个文件中的特性标志很少直接操作 CSS 属性，但它们可以影响 CSS 的加载和应用，以及相关的渲染性能。

* **`kWebFontsCacheAwareTimeoutAdaption`:** 启用缓存感知 WebFonts 加载。这会影响浏览器如何以及何时加载 CSS 中引用的字体文件。
    * **假设输入：**  CSS 文件中使用了 `@font-face` 规则引用了外部字体。
    * **输出：** 如果 `kWebFontsCacheAwareTimeoutAdaption` 启用，并且字体已经存在于缓存中，加载速度会更快，避免不必要的超时。
* **`kThreadedPreloadScanner`:**  启用线程化的预加载扫描器，这可以加速 HTML 文档的解析，从而更快地发现和加载 CSS 资源。

**逻辑推理的假设输入与输出：**

很多特性标志是简单的开关，其逻辑推理比较直接。例如 `kSetTimeoutWithoutClamp`：

* **假设输入：**  `base::FeatureList::IsEnabled(features::kSetTimeoutWithoutClamp)` 在 Blink 引擎代码中被调用。
* **输出：**  如果该特性标志在 Chrome 或 Edge 浏览器中被启用（例如，通过命令行参数或实验性功能设置），则返回 `true`；否则返回 `false`。

对于带参数的特性标志，例如 `kSharedStorageBitBudget`：

* **假设输入：** `features::kSharedStorageBitBudget.Get()` 被调用。
* **输出：**  如果 `kSharedStorageAPI` 特性标志启用，并且没有通过命令行参数显式设置 `SharedStorageBitBudget` 的值，则返回默认值 `12`。如果通过命令行参数设置了不同的值，则返回该设置的值。如果 `kSharedStorageAPI` 特性标志被禁用，则可能不会返回有意义的值或导致程序错误（取决于具体的实现）。

**涉及用户或编程常见的使用错误：**

1. **假设特性已启用：** 开发者可能会错误地假设某个实验性特性在所有用户的浏览器中都是启用的，并在代码中依赖该特性，导致在未启用该特性的环境中出现错误或不兼容问题。
    * **示例：**  使用 Shared Storage API 而没有先检查 `kSharedStorageAPI` 是否启用。
2. **错误配置参数：** 对于带参数的特性，错误地配置参数值可能导致功能行为异常或性能问题。
    * **示例：** 将 `kUnimportantFrameTimersThrottledWakeUpIntervalMills` 设置为一个非常小的值，可能导致即使是“不重要”的帧也会频繁唤醒，抵消了节流的目的。
3. **忽略特性依赖关系：** 某些特性可能依赖于其他特性。如果只启用了部分依赖，可能导致功能无法正常工作。
    * **示例：**  可能存在一个假设性的特性依赖于 `kSharedStorageAPI`，如果只启用了这个依赖特性而没有启用 `kSharedStorageAPI`，则该特性可能无法正常工作。
4. **不了解特性的默认状态：**  开发者需要清楚每个特性的默认启用/禁用状态，以便正确地进行功能测试和部署。

**功能归纳（作为第 4 部分的总结）：**

`blink/common/features.cc` 文件是 Blink 引擎的核心配置中心，它通过定义一系列可开关的特性标志和可配置的参数，实现了对 Blink 引擎各种功能和行为的灵活控制。这些特性标志直接或间接地影响着 JavaScript 的 API 行为、HTML 的解析和渲染、CSS 的加载以及各种 Web 标准的实现。  开发者可以通过这些标志进行实验性功能的开发、A/B 测试、性能调优以及控制功能的发布流程。 然而，不当的使用和配置这些特性标志也可能导致错误和不兼容性问题，因此理解其作用和默认状态至关重要。

### 提示词
```
这是目录为blink/common/features.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
(kSendCnameAliasesToSubresourceFilterFromRenderer,
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