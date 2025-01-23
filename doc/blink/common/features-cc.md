Response: My thinking process to analyze the provided C++ code snippet and generate the summary goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the `blink/common/features.cc` file, including its relationship to web technologies (JavaScript, HTML, CSS), examples with hypothetical inputs/outputs, common user errors, and a general overview.

2. **Initial Code Scan - Identify Core Purpose:**  I quickly scanned the code, noticing the heavy use of `BASE_FEATURE` and `BASE_FEATURE_PARAM`. This immediately signals that the primary function of this file is to define and manage *feature flags* within the Chromium/Blink engine. These flags control the enabling/disabling of various functionalities.

3. **Categorize Feature Flags:**  I started reading the feature flag names. I tried to group them conceptually. Some initial categories that emerged were:
    * **Performance:**  Flags related to speed and efficiency (e.g., `kCacheCodeOnIdle`, `kBoostImagePriority`, `kDeferRendererTasksAfterInput`).
    * **Privacy/Security:** Flags related to user data protection and security (e.g., `kInterestGroupStorage`, `kBrowsingTopics`).
    * **New Web Platform Features:** Flags enabling experimental or upcoming web standards (e.g., `kFencedFrames`, `kBrowsingTopicsDocumentAPI`).
    * **Rendering/Display:** Flags affecting how content is displayed (e.g., `kForceWebContentsDarkMode`, `kCanvas2DHibernation`).
    * **Back/Forward Cache:** Flags specifically controlling the browser's back/forward navigation behavior.
    * **Developer Tools:**  Flags related to debugging and development (e.g., `kDevToolsImprovedNetworkError`).
    * **Autofill:** Flags related to the browser's form-filling capabilities.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):**  As I went through the flags, I considered how each might interact with the core web technologies:
    * **JavaScript:**  Flags like `kDelayAsyncScriptExecution`, `kCacheCodeOnIdle`, and those related to the FLEDGE API directly impact JavaScript execution and behavior. The Interest Group API and Browsing Topics also have JavaScript APIs.
    * **HTML:** Flags related to new elements (`kFencedFrames`), form behavior (`kAutofillFixFieldsAssociatedWithNestedFormsByParser`), and speculative loading (`kAutoSpeculationRules`) are clearly linked to HTML.
    * **CSS:**  Flags like `kForceWebContentsDarkMode` and those involving rendering optimizations affect how CSS is processed and applied.

5. **Hypothetical Inputs and Outputs (Logical Reasoning):**  For certain flags, I could devise simple input/output scenarios:
    * **`kForceWebContentsDarkMode`:**  *Input:* User enables the flag. *Output:* Websites without explicit dark themes are rendered with an inverted color scheme.
    * **`kDelayAsyncScriptExecution`:** *Input:* A webpage contains `<script async src="...">`. *Output:* If the flag is enabled, the script's execution might be delayed based on the configured parameters (e.g., until after parsing).
    * **`kFencedFrames`:** *Input:* HTML code uses the `<fencedframe>` tag. *Output:* If the flag is enabled, the browser will attempt to render the fenced frame according to its specifications. If disabled, it won't recognize the tag.

6. **Common User Errors:** This required thinking about how enabling/disabling these flags might cause unexpected behavior for users or developers:
    * **Experimental Features:** Enabling flags without fully understanding their implications could lead to broken websites or unexpected behavior. I highlighted the risk of enabling features still under development.
    * **Performance Flags:**  Incorrectly configuring performance-related flags might have unintended consequences (e.g., excessively delaying scripts).
    * **Privacy Flags:**  Disabling certain privacy features could expose user data.

7. **Synthesize the Summary:**  Finally, I compiled my findings into a concise summary. I focused on:
    * **Core Function:** Defining and controlling feature flags.
    * **Impact on Web Development:** How these flags influence the behavior of JavaScript, HTML, and CSS.
    * **Examples:** Concrete examples illustrating the effects of specific flags.
    * **User Errors:** Potential pitfalls of modifying these flags.
    * **Overall Purpose:**  Enabling experimentation, gradual rollout of new features, and conditional enabling/disabling of functionalities.

8. **Refine and Organize:** I reviewed the generated summary for clarity, accuracy, and organization. I ensured the language was accessible and the key takeaways were prominent. I also made sure to explicitly mention that this was only part 1 and more functionality would likely be in part 2.

This iterative process of scanning, categorizing, relating, reasoning, and synthesizing allowed me to generate a comprehensive and accurate summary of the provided code snippet. The key was recognizing the central role of feature flags and then exploring the implications of those flags across different aspects of the browser and web development.
这是对位于 `blink/common/features.cc` 的 Chromium Blink 引擎源代码文件第一部分的分析和功能归纳。

**文件功能总览：**

这个文件的主要功能是**定义和管理 Blink 引擎中的各种特性（features）开关**。这些特性开关允许 Chromium 团队在不修改代码的情况下启用或禁用某些功能，主要用于：

* **实验性功能上线:**  逐步向用户推出新功能，先在一部分用户中测试，观察效果后再全面推广。
* **A/B 测试:**  对比不同功能版本的效果，例如通过 feature flag 控制使用旧版或新版的某个功能。
* **灰度发布/金丝雀发布:**  逐步将新功能推送到一部分用户，监控其稳定性和性能。
* **紧急回滚:**  如果某个功能引入了问题，可以通过关闭对应的 feature flag 快速回滚。
* **平台/环境差异化:**  针对不同的操作系统、设备或构建配置，启用或禁用某些特性。
* **开发者选项:**  允许开发者手动开启或关闭一些用于调试或测试的特性。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个文件定义的特性开关直接影响着浏览器如何解析、渲染和执行网页内容，因此与 JavaScript, HTML, CSS 的功能息息相关。以下是一些例子：

* **JavaScript:**
    * **`kAdAuctionReportingWithMacroApi` (启用 Protected Audience 的 reporting with ad macro API):**  这个特性关系到 Privacy Sandbox 中的 Protected Audience API，它允许在广告竞价过程中使用 JavaScript API 进行报告。如果这个特性被启用，那么 JavaScript 代码中可以使用相关的 API。
        * **假设输入:** JavaScript 代码调用了 `navigator.sendBeacon()` 发送广告竞价相关的报告，报告内容包含宏。
        * **输出:** 如果 `kAdAuctionReportingWithMacroApi` 启用，报告会被发送；否则，可能会被阻止或宏处理方式不同。
    * **`kDelayAsyncScriptExecution` (延迟异步脚本执行):** 这个特性控制着浏览器如何处理带有 `async` 属性的 JavaScript 脚本的执行时机。启用后，可以配置延迟策略。
        * **假设输入:** 一个 HTML 页面包含 `<script async src="script.js"></script>`。
        * **输出:**  如果 `kDelayAsyncScriptExecution` 启用，`script.js` 的执行可能会被延迟到页面解析完成或首次渲染之后。
    * **`kBrowsingTopicsDocumentAPI` (启用通过 Javascript 调用 Topics API):** 这个特性允许 JavaScript 代码通过 `document.browsingTopics()`  API 访问用户的浏览主题。
        * **假设输入:** JavaScript 代码调用 `document.browsingTopics()`。
        * **输出:** 如果特性启用，返回用户的主题信息；否则，可能会抛出异常或返回空值。

* **HTML:**
    * **`kFencedFrames` (启用 `<fencedframe>` 元素):** 这个特性控制着是否支持新的 HTML 元素 `<fencedframe>`，用于隔离显示不同来源的内容。
        * **假设输入:** HTML 代码包含 `<fencedframe src="https://example.com"></fencedframe>`。
        * **输出:** 如果 `kFencedFrames` 启用，浏览器会尝试加载并渲染 `https://example.com` 的内容在一个隔离的 fenced frame 中；否则，浏览器可能无法识别该标签或以 `<iframe>` 的方式处理。
    * **`kAutoSpeculationRules` (自动推测规则):** 这个特性影响浏览器如何根据 HTML 中定义的 `<script type="speculationrules">` 来进行预加载或预渲染。
        * **假设输入:** HTML 代码包含 `<script type="speculationrules"> { "prerender": [...] } </script>`。
        * **输出:** 如果 `kAutoSpeculationRules` 启用，浏览器会尝试预渲染指定的页面。
    * **`kClientHintsDPR_DEPRECATED`, `kClientHintsDeviceMemory_DEPRECATED` 等 (客户端提示):** 这些特性控制着浏览器是否发送特定的客户端提示 HTTP 请求头，例如设备像素比 (DPR) 或设备内存信息，这些信息可以被服务器用来优化返回的 HTML 或其他资源。

* **CSS:**
    * **`kForceWebContentsDarkMode` (自动将浅色主题页面转换为 Blink 生成的深色主题):** 这个特性控制着浏览器是否自动对没有深色主题的网页应用深色模式。
        * **假设输入:**  用户启用了深色模式，访问了一个只有浅色主题的网站。
        * **输出:** 如果 `kForceWebContentsDarkMode` 启用，浏览器会尝试反转颜色，生成一个深色版本。
    * **`kBakedGamutMapping` (重新定义 oklab 和 oklch 色彩空间，使其具有内置的色域映射):** 这个特性影响浏览器如何处理 CSS 中定义的 `oklab` 和 `oklch` 颜色，并可能影响最终的颜色渲染效果。
    * **`kFetchDestinationJsonCssModules` (对 CSS 和 JSON 模块使用 "style" 和 "json" 目标):** 这个特性影响浏览器如何请求和处理 CSS 模块 (`type="module" rel="stylesheet"`) 和 JSON 模块 (`type="module"`)。

**逻辑推理的假设输入与输出：**

由于这个文件主要是定义开关，而不是执行具体逻辑，直接进行逻辑推理的输入输出可能不太直观。不过，我们可以从 *控制特性行为* 的角度进行假设：

* **假设输入 (针对 `kAdInterestGroupAPIRestrictedPolicyByDefault`):**
    * 特性 `kAdInterestGroupAPIRestrictedPolicyByDefault` 被启用。
    * 一个网页尝试使用 `navigator.permissions.query({ name: 'join-ad-interest-group' })` 或 `navigator.permissions.query({ name: 'run-ad-auction' })` 查询权限。
* **输出:** 默认情况下，这些权限策略可能会是 `granted` 或 `prompt`。但是，如果 `kAdInterestGroupAPIRestrictedPolicyByDefault` 启用，默认策略会更严格，可能是 `denied`，除非有明确的授权。

* **假设输入 (针对 `kBoostImagePriority`):**
    * 特性 `kBoostImagePriority` 被启用。
    * 浏览器开始加载一个包含多个 `<img>` 标签的网页。
    * 参数 `kBoostImagePriorityImageCount` 设置为 5。
* **输出:**  前 5 个非小尺寸的图片资源会被赋予更高的加载优先级，从而更快地加载完成。

**涉及用户常见的使用错误及举例说明：**

用户通常不会直接修改这个文件，但开发者或高级用户可能会通过 Chrome 的 `chrome://flags` 页面来手动启用或禁用这些特性。常见的使用错误包括：

* **启用不稳定的实验性功能:**  用户可能会启用带有 "Experimental" 标签的特性，导致浏览器出现崩溃、性能问题或功能异常。
    * **例子:** 启用一个正在开发的渲染特性，可能导致网页显示错乱或 GPU 占用过高。
* **禁用关键功能:**  不小心禁用了某些核心功能，导致网页无法正常工作。
    * **例子:**  禁用了某个 JavaScript 特性，导致依赖该特性的网站无法交互。
* **错误配置特性参数:** 一些特性有相关的参数可以配置，错误的配置可能会导致意想不到的结果。
    * **例子:**  `kDelayAsyncScriptExecution` 的延迟时间设置过长，导致网页交互延迟。
* **理解偏差:**  用户可能对某些特性的作用理解不准确，导致启用或禁用后没有达到预期的效果。

**功能归纳 (Part 1):**

这个 `features.cc` 文件的第一部分主要负责定义大量的 **Blink 引擎特性开关**。 这些开关通过 `BASE_FEATURE` 宏定义，并且可以包含通过 `BASE_FEATURE_PARAM` 宏定义的参数来进一步配置特性的行为。

这些特性覆盖了 Blink 引擎的各个方面，包括：

* **广告相关的 API 和功能 (Protected Audience API, Topics API)。**
* **性能优化 (资源加载优先级、代码缓存、任务调度)。**
* **新的 Web Platform API 和 HTML 元素 (Fenced Frames)。**
* **渲染和显示 (深色模式、Canvas)。**
* **安全性和隐私 (权限策略、第三方 Cookie 分区)。**
* **浏览器行为 (Back/Forward Cache)。**
* **开发者工具的增强。**
* **以及一些特定场景下的功能开关。**

总而言之，这个文件是 Blink 引擎中一个非常重要的配置中心，它允许 Chromium 团队灵活地管理和控制引擎的各种功能和行为，对于新功能的推出、测试和问题排查至关重要。

### 提示词
```
这是目录为blink/common/features.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/features.h"

#include "base/command_line.h"
#include "base/feature_list.h"
#include "base/features.h"
#include "base/time/time.h"
#include "build/android_buildflags.h"
#include "build/build_config.h"
#include "build/chromecast_buildflags.h"
#include "build/chromeos_buildflags.h"
#include "services/network/public/cpp/features.h"
#include "third_party/blink/public/common/features_generated.h"
#include "third_party/blink/public/common/forcedark/forcedark_switches.h"
#include "third_party/blink/public/common/interest_group/ad_auction_constants.h"
#include "third_party/blink/public/common/switches.h"

namespace blink::features {

// -----------------------------------------------------------------------------
// Feature definitions and associated constants (feature params, et cetera)
//
// When adding new features or constants for features, please keep the features
// sorted by identifier name (e.g. `kAwesomeFeature`), and the constants for
// that feature grouped with the associated feature.
//
// When defining feature params for auto-generated features (e.g. from
// `RuntimeEnabledFeatures)`, they should still be ordered in this section based
// on the identifier name of the generated feature.

// Enable the Protected Audience's reporting with ad macro API.
BASE_FEATURE(kAdAuctionReportingWithMacroApi,
             "AdAuctionReportingWithMacroApi",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Controls the capturing of the Ad-Auction-Signals header, and the maximum
// allowed Ad-Auction-Signals header value.
BASE_FEATURE(kAdAuctionSignals,
             "AdAuctionSignals",
             base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(int,
                   kAdAuctionSignalsMaxSizeBytes,
                   &kAdAuctionSignals,
                   "ad-auction-signals-max-size-bytes",
                   10000);

// See https://github.com/WICG/turtledove/blob/main/FLEDGE.md
// Changes default Permissions Policy for features join-ad-interest-group and
// run-ad-auction to a more restricted EnableForSelf.
BASE_FEATURE(kAdInterestGroupAPIRestrictedPolicyByDefault,
             "AdInterestGroupAPIRestrictedPolicyByDefault",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Allow DeprecatedRenderURLReplacements when
// CookieDeprecationFacilitatedTesting is enabled.
BASE_FEATURE(kAlwaysAllowFledgeDeprecatedRenderURLReplacements,
             "kAlwaysAllowFledgeDeprecatedRenderURLReplacements",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Block all MIDI access with the MIDI_SYSEX permission
BASE_FEATURE(kBlockMidiByDefault,
             "BlockMidiByDefault",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kComputePressureRateObfuscationMitigation,
             "ComputePressureRateObfuscationMitigation",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kLowerHighResolutionTimerThreshold,
             "LowerHighResolutionTimerThreshold",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kAllowDatapipeDrainedAsBytesConsumerInBFCache,
             "AllowDatapipeDrainedAsBytesConsumerInBFCache",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kAllowDevToolsMainThreadDebuggerForMultipleMainFrames,
             "AllowDevToolsMainThreadDebuggerForMultipleMainFrames",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Enables URN URLs like those produced by Protected Audience auctions to be
// displayed by iframes (instead of requiring fenced frames).
BASE_FEATURE(kAllowURNsInIframes,
             "AllowURNsInIframes",
             base::FEATURE_ENABLED_BY_DEFAULT);

// A console warning is shown when the opaque url returned from Protected
// Audience/selectUrl is used to navigate an iframe. Since fenced frames are not
// going to be enforced for these APIs in the short-medium term, disabling this
// warning for now.
BASE_FEATURE(kDisplayWarningDeprecateURNIframesUseFencedFrames,
             "DisplayWarningDeprecateURNIframesUseFencedFrames",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kAndroidExtendedKeyboardShortcuts,
             "AndroidExtendedKeyboardShortcuts",
             base::FEATURE_ENABLED_BY_DEFAULT);

// A server-side switch for the kRealtimeAudio thread type of
// RealtimeAudioWorkletThread object. This can be controlled by a field trial,
// it will use the kNormal type thread when disabled.
BASE_FEATURE(kAudioWorkletThreadRealtimePriority,
             "AudioWorkletThreadRealtimePriority",
             base::FEATURE_ENABLED_BY_DEFAULT);

#if BUILDFLAG(IS_APPLE)
// When enabled, RealtimeAudioWorkletThread scheduling is optimized taking into
// account how often the worklet logic is executed (which is determined by the
// AudioContext buffer duration).
BASE_FEATURE(kAudioWorkletThreadRealtimePeriodMac,
             "AudioWorkletThreadRealtimePeriodMac",
             base::FEATURE_ENABLED_BY_DEFAULT);
#endif

// A thread pool system for effective usage of RealtimeAudioWorkletThread
// instances.
BASE_FEATURE(kAudioWorkletThreadPool,
             "AudioWorkletThreadPool",
             base::FEATURE_ENABLED_BY_DEFAULT);

// If enabled, WebFormElement applies the same special case to nested forms
// as it does for the outermost form. The fix is relevant only to Autofill.
// For other callers of HTMLFormElement::ListedElements(), which don't traverse
// shadow trees and flatten nested forms, are not affected by the feature at
// all. This is a kill switch.
BASE_FEATURE(kAutofillFixFieldsAssociatedWithNestedFormsByParser,
             "AutofillFixFieldsAssociatedWithNestedFormsByParser",
             base::FEATURE_ENABLED_BY_DEFAULT);

// If disabled (default for many years), autofilling triggers KeyDown and
// KeyUp events that do not send any key codes. If enabled, these events
// contain the "Unidentified" key.
BASE_FEATURE(kAutofillSendUnidentifiedKeyAfterFill,
             "AutofillSendUnidentifiedKeyAfterFill",
             base::FEATURE_DISABLED_BY_DEFAULT);

// https://crbug.com/1472970
BASE_FEATURE(kAutoSpeculationRules,
             "AutoSpeculationRules",
             base::FEATURE_DISABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(bool,
                   kAutoSpeculationRulesHoldback,
                   &kAutoSpeculationRules,
                   "holdback",
                   false);

BASE_FEATURE(kAvifGainmapHdrImages,
             "AvifGainmapHdrImages",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kAvoidForcedLayoutOnInitialEmptyDocumentInSubframe,
             "AvoidForcedLayoutOnInitialEmptyDocumentInSubframe",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kBFCacheOpenBroadcastChannel,
             "BFCacheOpenBroadcastChannel",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kBackForwardCacheDWCOnJavaScriptExecution,
             "BackForwardCacheDWCOnJavaScriptExecution",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Allows pages with keepalive requests to stay eligible for the back/forward
// cache. See https://crbug.com/1347101 for more details.
BASE_FEATURE(kBackForwardCacheWithKeepaliveRequest,
             "BackForwardCacheWithKeepaliveRequest",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Enable background resource fetch in Blink. See https://crbug.com/1379780 for
// more details.
BASE_FEATURE(kBackgroundResourceFetch,
             "BackgroundResourceFetch",
             base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(bool,
                   kBackgroundFontResponseProcessor,
                   &kBackgroundResourceFetch,
                   "background-font-response-processor",
                   true);
BASE_FEATURE_PARAM(bool,
                   kBackgroundScriptResponseProcessor,
                   &kBackgroundResourceFetch,
                   "background-script-response-processor",
                   true);
BASE_FEATURE_PARAM(bool,
                   kBackgroundCodeCacheDecoderStart,
                   &kBackgroundResourceFetch,
                   "background-code-cache-decoder-start",
                   true);

// Redefine the oklab and oklch spaces to have gamut mapping baked into them.
// https://crbug.com/1508329
BASE_FEATURE(kBakedGamutMapping,
             "BakedGamutMapping",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Used to configure a per-origin allowlist of performance.mark events that are
// permitted to be included in slow reports traces. See crbug.com/1181774.
BASE_FEATURE(kBackgroundTracingPerformanceMark,
             "BackgroundTracingPerformanceMark",
             base::FEATURE_DISABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(std::string,
                   kBackgroundTracingPerformanceMark_AllowList,
                   &kBackgroundTracingPerformanceMark,
                   "allow_list",
                   "");

// See https://github.com/WICG/turtledove/blob/main/FLEDGE.md
// Feature flag to enable debug reporting APIs.
BASE_FEATURE(kBiddingAndScoringDebugReportingAPI,
             "BiddingAndScoringDebugReportingAPI",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Boost the priority of the first N not-small images.
// crbug.com/1431169
BASE_FEATURE(kBoostImagePriority,
             "BoostImagePriority",
             base::FEATURE_ENABLED_BY_DEFAULT);
// The number of images to bopost the priority of before returning
// to the default (low) priority.
BASE_FEATURE_PARAM(int,
                   kBoostImagePriorityImageCount,
                   &kBoostImagePriority,
                   "image_count",
                   5);
// Maximum size of an image (in px^2) to be considered "small".
// Small images, where dimensions are specified in the markup, are not boosted.
BASE_FEATURE_PARAM(int,
                   kBoostImagePriorityImageSize,
                   &kBoostImagePriority,
                   "image_size",
                   10000);
// Number of medium-priority requests to allow in tight-mode independent of the
// total number of outstanding requests.
BASE_FEATURE_PARAM(int,
                   kBoostImagePriorityTightMediumLimit,
                   &kBoostImagePriority,
                   "tight_medium_limit",
                   2);

// Boost the priority of certain loading tasks (https://crbug.com/1470003).
BASE_FEATURE(kBoostImageSetLoadingTaskPriority,
             "BoostImageSetLoadingTaskPriority",
             base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE(kBoostFontLoadingTaskPriority,
             "BoostFontLoadingTaskPriority",
             base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE(kBoostVideoLoadingTaskPriority,
             "BoostVideoLoadingTaskPriority",
             base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE(kBoostRenderBlockingStyleLoadingTaskPriority,
             "BoostRenderBlockingStyleLoadingTaskPriority",
             base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE(kBoostNonRenderBlockingStyleLoadingTaskPriority,
             "BoostNonRenderBlockingStyleLoadingTaskPriority",
             base::FEATURE_ENABLED_BY_DEFAULT);

// https://github.com/patcg-individual-drafts/topics
// Kill switch for the Topics API.
BASE_FEATURE(kBrowsingTopics,
             "BrowsingTopics",
             base::FEATURE_ENABLED_BY_DEFAULT);

// If enabled, the check for whether the IP address is publicly routable will be
// bypassed when determining the eligibility for a page to be included in topics
// calculation. This is useful for developers to test in local environment.
BASE_FEATURE(kBrowsingTopicsBypassIPIsPubliclyRoutableCheck,
             "BrowsingTopicsBypassIPIsPubliclyRoutableCheck",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Enables calling the Topics API through Javascript (i.e.
// document.browsingTopics()). For this feature to take effect, the main Topics
// feature has to be enabled first (i.e. `kBrowsingTopics` is enabled, and,
// either a valid Origin Trial token exists or `kPrivacySandboxAdsAPIsOverride`
// is enabled.)
BASE_FEATURE(kBrowsingTopicsDocumentAPI,
             "BrowsingTopicsDocumentAPI",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Decoupled with the main `kBrowsingTopics` feature, so it allows us to
// decouple the server side configs.
BASE_FEATURE(kBrowsingTopicsParameters,
             "BrowsingTopicsParameters",
             base::FEATURE_ENABLED_BY_DEFAULT);
// The periodic topics calculation interval.
BASE_FEATURE_PARAM(base::TimeDelta,
                   kBrowsingTopicsTimePeriodPerEpoch,
                   &kBrowsingTopicsParameters,
                   "time_period_per_epoch",
                   base::Days(7));
// The number of epochs from where to calculate the topics to give to a
// requesting contexts.
BASE_FEATURE_PARAM(int,
                   kBrowsingTopicsNumberOfEpochsToExpose,
                   &kBrowsingTopicsParameters,
                   "number_of_epochs_to_expose",
                   3);
// The number of top topics to derive and to keep for each epoch (week).
BASE_FEATURE_PARAM(int,
                   kBrowsingTopicsNumberOfTopTopicsPerEpoch,
                   &kBrowsingTopicsParameters,
                   "number_of_top_topics_per_epoch",
                   5);
// The probability (in percent number) to return the random topic to a site. The
// "random topic" is per-site, and is selected from the full taxonomy uniformly
// at random, and each site has a
// `kBrowsingTopicsUseRandomTopicProbabilityPercent`% chance to see their random
// topic instead of one of the top topics.
BASE_FEATURE_PARAM(int,
                   kBrowsingTopicsUseRandomTopicProbabilityPercent,
                   &kBrowsingTopicsParameters,
                   "use_random_topic_probability_percent",
                   5);
// Maximum delay between the calculation of the latest epoch and when a site
// starts seeing that epoch's topics. Each site transitions to the latest epoch
// at a per-site, per-epoch random time within
// [calculation time, calculation time + max delay).
BASE_FEATURE_PARAM(base::TimeDelta,
                   kBrowsingTopicsMaxEpochIntroductionDelay,
                   &kBrowsingTopicsParameters,
                   "max_epoch_introduction_delay",
                   base::Days(2));
// The duration an epoch is retained before deletion.
BASE_FEATURE_PARAM(base::TimeDelta,
                   kBrowsingTopicsEpochRetentionDuration,
                   &kBrowsingTopicsParameters,
                   "epoch_retention_duration",
                   base::Days(28));
// Maximum time offset between when a site stops seeing an epoch's topics and
// when the epoch is actually deleted. Each site transitions away from the
// epoch at a per-site, per-epoch random time within
// [deletion time - max offset, deletion time].
//
// Note: The actual phase-out time can be influenced by the
// 'kBrowsingTopicsNumberOfEpochsToExpose' setting. If this setting enforces a
// more restrictive phase-out, that will take precedence.
BASE_FEATURE_PARAM(base::TimeDelta,
                   kBrowsingTopicsMaxEpochPhaseOutTimeOffset,
                   &kBrowsingTopicsParameters,
                   "max_epoch_phase_out_time_offset",
                   base::Days(2));
// How many epochs (weeks) of API usage data (i.e. topics observations) will be
// based off for the filtering of topics for a calling context.
BASE_FEATURE_PARAM(
    int,
    kBrowsingTopicsNumberOfEpochsOfObservationDataToUseForFiltering,
    &kBrowsingTopicsParameters,
    "number_of_epochs_of_observation_data_to_use_for_filtering",
    3);
// The max number of observed-by context domains to keep for each top topic
// during the epoch topics calculation. The final number of domains associated
// with each topic may be larger than this threshold, because that set of
// domains will also include all domains associated with the topic's descendant
// topics. The intent is to cap the in-use memory.
BASE_FEATURE_PARAM(
    int,
    kBrowsingTopicsMaxNumberOfApiUsageContextDomainsToKeepPerTopic,
    &kBrowsingTopicsParameters,
    "max_number_of_api_usage_context_domains_to_keep_per_topic",
    1000);
// The max number of entries allowed to be retrieved from the
// `BrowsingTopicsSiteDataStorage` database for each query for the API usage
// contexts. The query will occur once per epoch (week) at topics calculation
// time. The intent is to cap the peak memory usage.
BASE_FEATURE_PARAM(
    int,
    kBrowsingTopicsMaxNumberOfApiUsageContextEntriesToLoadPerEpoch,
    &kBrowsingTopicsParameters,
    "max_number_of_api_usage_context_entries_to_load_per_epoch",
    100000);
// The max number of API usage context domains allowed to be stored per page
// load.
BASE_FEATURE_PARAM(
    int,
    kBrowsingTopicsMaxNumberOfApiUsageContextDomainsToStorePerPageLoad,
    &kBrowsingTopicsParameters,
    "max_number_of_api_usage_context_domains_to_store_per_page_load",
    30);
// The taxonomy version. This only affects the topics classification that occurs
// during this browser session, and doesn't affect the pre-existing epochs.
BASE_FEATURE_PARAM(int,
                   kBrowsingTopicsTaxonomyVersion,
                   &kBrowsingTopicsParameters,
                   "taxonomy_version",
                   kBrowsingTopicsTaxonomyVersionDefault);
// Comma separated Topic IDs to be blocked. Descendant topics of each blocked
// topic will be blocked as well.
BASE_FEATURE_PARAM(std::string,
                   kBrowsingTopicsDisabledTopicsList,
                   &kBrowsingTopicsParameters,
                   "disabled_topics_list",
                   "");
// Comma separated list of Topic IDs. Prioritize these topics and their
// descendants during top topic selection.
BASE_FEATURE_PARAM(std::string,
                   kBrowsingTopicsPrioritizedTopicsList,
                   &kBrowsingTopicsParameters,
                   "prioritized_topics_list",
                   "57,86,126,149,172,180,196,207,239,254,263,272,289,299,332");
// When a topics calculation times out for the first time, the duration to wait
// before starting a new one.
BASE_FEATURE_PARAM(base::TimeDelta,
                   kBrowsingTopicsFirstTimeoutRetryDelay,
                   &kBrowsingTopicsParameters,
                   "first_timeout_retry_delay",
                   base::Minutes(1));

// When enabled, code cache is produced asynchronously from the script execution
// (https://crbug.com/1260908).
BASE_FEATURE(kCacheCodeOnIdle,
             "CacheCodeOnIdle",
             base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(int,
                   kCacheCodeOnIdleDelayParam,
                   &kCacheCodeOnIdle,
                   "delay-in-ms",
                   1);
// Apply CacheCodeOnIdle only for service workers (https://crbug.com/1410082).
BASE_FEATURE_PARAM(bool,
                   kCacheCodeOnIdleDelayServiceWorkerOnlyParam,
                   &kCacheCodeOnIdle,
                   "service-worker-only",
                   true);

// When enabled allows the header name used in the blink
// CacheStorageCodeCacheHint runtime feature to be modified.  This runtime
// feature disables generating full code cache for responses stored in
// cache_storage during a service worker install event.  The runtime feature
// must be enabled via the blink runtime feature mechanism, however.
BASE_FEATURE(kCacheStorageCodeCacheHintHeader,
             "CacheStorageCodeCacheHintHeader",
             base::FEATURE_DISABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(std::string,
                   kCacheStorageCodeCacheHintHeaderName,
                   &kCacheStorageCodeCacheHintHeader,
                   "name",
                   "x-CacheStorageCodeCacheHint");

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_CHROMEOS) && !BUILDFLAG(IS_FUCHSIA)
// Enables camera preview in permission bubble and site settings.
BASE_FEATURE(kCameraMicPreview,
             "CameraMicPreview",
             base::FEATURE_DISABLED_BY_DEFAULT);
#endif

// Temporarily disabled due to issues:
// - PDF blank previews
// - Canvas corruption on ARM64 macOS
// See https://g-issues.chromium.org/issues/328755781
BASE_FEATURE(kCanvas2DHibernation,
             "Canvas2DHibernation",
             base::FeatureState::FEATURE_DISABLED_BY_DEFAULT);

// When hibernating, make sure that the just-used transfer memory (to transfer
// the snapshot) is freed.
BASE_FEATURE(kCanvas2DHibernationReleaseTransferMemory,
             "Canvas2DHibernationReleaseTransferMemory",
             base::FeatureState::FEATURE_DISABLED_BY_DEFAULT);

// Whether to capture the source location of JavaScript execution, which is one
// of the renderer eviction reasons for Back/Forward Cache.
BASE_FEATURE(kCaptureJSExecutionLocation,
             "CaptureJSExecutionLocation",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kCheckHTMLParserBudgetLessOften,
             "CheckHTMLParserBudgetLessOften",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Enable legacy `dpr` client hint.
BASE_FEATURE(kClientHintsDPR_DEPRECATED,
             "ClientHintsDPR_DEPRECATED",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Enable legacy `device-memory` client hint.
BASE_FEATURE(kClientHintsDeviceMemory_DEPRECATED,
             "ClientHintsDeviceMemory_DEPRECATED",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Enable legacy `width` client hint.
BASE_FEATURE(kClientHintsResourceWidth_DEPRECATED,
             "ClientHintsResourceWidth_DEPRECATED",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Enable `form-factor` client hint for XR devices.
BASE_FEATURE(kClientHintsXRFormFactor,
             "ClientHintsXRFormFactor",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Enable legacy `viewport-width` client hint.
BASE_FEATURE(kClientHintsViewportWidth_DEPRECATED,
             "ClientHintsViewportWidth_DEPRECATED",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Disabling this will cause parkable strings to never be compressed.
// This is useful for headless mode + virtual time. Since virtual time advances
// quickly, strings may be parked too eagerly in that mode.
BASE_FEATURE(kCompressParkableStrings,
             "CompressParkableStrings",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Enables more conservative settings for ParkableString: suspend parking in
// foreground, and increase aging tick intervals.
BASE_FEATURE(kLessAggressiveParkableString,
             "LessAggressiveParkableString",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Limits maximum capacity of disk data allocator per renderer process.
// DiskDataAllocator and its clients(ParkableString, ParkableImage) will try
// to keep the limitation.
BASE_FEATURE_PARAM(int,
                   kMaxDiskDataAllocatorCapacityMB,
                   &kCompressParkableStrings,
                   "max_disk_capacity_mb",
                   -1);

// Controls off-thread code cache consumption.
BASE_FEATURE(kConsumeCodeCacheOffThread,
             "ConsumeCodeCacheOffThread",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Enables the constant streaming in the ContentCapture task.
BASE_FEATURE(kContentCaptureConstantStreaming,
             "ContentCaptureConstantStreaming",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kCorrectFloatExtensionTestForWebGL,
             "CorrectFloatExtensionTestForWebGL",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kCrabbyAvif, "CrabbyAvif", base::FEATURE_ENABLED_BY_DEFAULT);

// When enabled, add a new option, {imageOrientation: 'none'}, to
// createImageBitmap, which ignores the image orientation metadata of the source
// and renders the image as encoded.
BASE_FEATURE(kCreateImageBitmapOrientationNone,
             "CreateImageBitmapOrientationNone",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kDeferRendererTasksAfterInput,
             "DeferRendererTasksAfterInput",
             base::FEATURE_DISABLED_BY_DEFAULT);

const char kDeferRendererTasksAfterInputPolicyParamName[] = "policy";
const char kDeferRendererTasksAfterInputMinimalTypesPolicyName[] =
    "minimal-types";
const char
    kDeferRendererTasksAfterInputNonUserBlockingDeferrableTypesPolicyName[] =
        "non-user-blocking-deferrable-types";
const char kDeferRendererTasksAfterInputNonUserBlockingTypesPolicyName[] =
    "non-user-blocking-types";
const char kDeferRendererTasksAfterInputAllDeferrableTypesPolicyName[] =
    "all-deferrable-types";
const char kDeferRendererTasksAfterInputAllTypesPolicyName[] = "all-types";

const base::FeatureParam<TaskDeferralPolicy>::Option kTaskDeferralOptions[] = {
    {TaskDeferralPolicy::kMinimalTypes,
     kDeferRendererTasksAfterInputMinimalTypesPolicyName},
    {TaskDeferralPolicy::kNonUserBlockingDeferrableTypes,
     kDeferRendererTasksAfterInputNonUserBlockingDeferrableTypesPolicyName},
    {TaskDeferralPolicy::kNonUserBlockingTypes,
     kDeferRendererTasksAfterInputNonUserBlockingTypesPolicyName},
    {TaskDeferralPolicy::kAllDeferrableTypes,
     kDeferRendererTasksAfterInputAllDeferrableTypesPolicyName},
    {TaskDeferralPolicy::kAllTypes,
     kDeferRendererTasksAfterInputAllTypesPolicyName}};

BASE_FEATURE_ENUM_PARAM(TaskDeferralPolicy,
                        kTaskDeferralPolicyParam,
                        &kDeferRendererTasksAfterInput,
                        kDeferRendererTasksAfterInputPolicyParamName,
                        TaskDeferralPolicy::kAllDeferrableTypes,
                        &kTaskDeferralOptions);

BASE_FEATURE(kDelayAsyncScriptExecution,
             "DelayAsyncScriptExecution",
             base::FEATURE_DISABLED_BY_DEFAULT);

const base::FeatureParam<DelayAsyncScriptDelayType>::Option
    delay_async_script_execution_delay_types[] = {
        {DelayAsyncScriptDelayType::kFinishedParsing, "finished_parsing"},
        {DelayAsyncScriptDelayType::kFirstPaintOrFinishedParsing,
         "first_paint_or_finished_parsing"},
        {DelayAsyncScriptDelayType::kTillFirstLcpCandidate,
         "till_first_lcp_candidate"},
};

BASE_FEATURE_ENUM_PARAM(DelayAsyncScriptDelayType,
                        kDelayAsyncScriptExecutionDelayParam,
                        &kDelayAsyncScriptExecution,
                        "delay_async_exec_delay_type",
                        DelayAsyncScriptDelayType::kFinishedParsing,
                        &delay_async_script_execution_delay_types);

const base::FeatureParam<DelayAsyncScriptTarget>::Option
    delay_async_script_target_types[] = {
        {DelayAsyncScriptTarget::kAll, "all"},
        {DelayAsyncScriptTarget::kCrossSiteOnly, "cross_site_only"},
        {DelayAsyncScriptTarget::kCrossSiteWithAllowList,
         "cross_site_with_allow_list"},
        {DelayAsyncScriptTarget::kCrossSiteWithAllowListReportOnly,
         "cross_site_with_allow_list_report_only"},
};
BASE_FEATURE_ENUM_PARAM(DelayAsyncScriptTarget,
                        kDelayAsyncScriptTargetParam,
                        &kDelayAsyncScriptExecution,
                        "delay_async_exec_target",
                        DelayAsyncScriptTarget::kAll,
                        &delay_async_script_target_types);

// kDelayAsyncScriptExecution will delay executing async script at max
// |delay_async_exec_delay_limit|.
BASE_FEATURE_PARAM(base::TimeDelta,
                   kDelayAsyncScriptExecutionDelayLimitParam,
                   &kDelayAsyncScriptExecution,
                   "delay_async_exec_delay_limit",
                   base::Seconds(0));

// kDelayAsyncScriptExecution will be disabled after document elapsed more than
// |delay_async_exec_feature_limit|. Zero value means no limit.
// This is to avoid unnecessary async script delay after LCP (for
// kEachLcpCandidate or kEachPaint). Because we can't determine the LCP timing
// while loading, we use timeout instead.
BASE_FEATURE_PARAM(base::TimeDelta,
                   kDelayAsyncScriptExecutionFeatureLimitParam,
                   &kDelayAsyncScriptExecution,
                   "delay_async_exec_feature_limit",
                   base::Seconds(0));

BASE_FEATURE_PARAM(bool,
                   kDelayAsyncScriptExecutionDelayByDefaultParam,
                   &kDelayAsyncScriptExecution,
                   "delay_async_exec_delay_by_default",
                   true);

BASE_FEATURE_PARAM(bool,
                   kDelayAsyncScriptExecutionMainFrameOnlyParam,
                   &kDelayAsyncScriptExecution,
                   "delay_async_exec_main_frame_only",
                   false);

BASE_FEATURE_PARAM(bool,
                   kDelayAsyncScriptExecutionWhenLcpFoundInHtml,
                   &kDelayAsyncScriptExecution,
                   "delay_async_exec_when_lcp_found_in_html",
                   false);

// kDelayAsyncScriptExecution will change evaluation schedule for the
// specified target.
const base::FeatureParam<AsyncScriptExperimentalSchedulingTarget>::Option
    async_script_experimental_scheduling_targets[] = {
        {AsyncScriptExperimentalSchedulingTarget::kAds, "ads"},
        {AsyncScriptExperimentalSchedulingTarget::kNonAds, "non_ads"},
        {AsyncScriptExperimentalSchedulingTarget::kBoth, "both"},
};
BASE_FEATURE_ENUM_PARAM(AsyncScriptExperimentalSchedulingTarget,
                        kDelayAsyncScriptExecutionTargetParam,
                        &kDelayAsyncScriptExecution,
                        "delay_async_exec_target",
                        AsyncScriptExperimentalSchedulingTarget::kBoth,
                        &async_script_experimental_scheduling_targets);

BASE_FEATURE_PARAM(bool,
                   kDelayAsyncScriptExecutionOptOutLowFetchPriorityHintParam,
                   &kDelayAsyncScriptExecution,
                   "delay_async_exec_opt_out_low_fetch_priority_hint",
                   false);
BASE_FEATURE_PARAM(bool,
                   kDelayAsyncScriptExecutionOptOutAutoFetchPriorityHintParam,
                   &kDelayAsyncScriptExecution,
                   "delay_async_exec_opt_out_auto_fetch_priority_hint",
                   false);
BASE_FEATURE_PARAM(bool,
                   kDelayAsyncScriptExecutionOptOutHighFetchPriorityHintParam,
                   &kDelayAsyncScriptExecution,
                   "delay_async_exec_opt_out_high_fetch_priority_hint",
                   false);

BASE_FEATURE(kDelayLayerTreeViewDeletionOnLocalSwap,
             "DelayLayerTreeViewDeletionOnLocalSwap",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE_PARAM(base::TimeDelta,
                   kDelayLayerTreeViewDeletionOnLocalSwapTaskDelayParam,
                   &kDelayLayerTreeViewDeletionOnLocalSwap,
                   "deletion_task_delay",
                   base::Milliseconds(1000));

// Improves the signal-to-noise ratio of network error related messages in the
// DevTools Console.
// See http://crbug.com/124534.
BASE_FEATURE(kDevToolsImprovedNetworkError,
             "DevToolsImprovedNetworkError",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kDirectCompositorThreadIpc,
             "DirectCompositorThreadIpc",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kDisableArrayBufferSizeLimitsForTesting,
             "DisableArrayBufferSizeLimitsForTesting",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kDiscardInputEventsToRecentlyMovedFrames,
             "DiscardInputEventsToRecentlyMovedFrames",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kDisableThirdPartyStoragePartitioningDeprecationTrial2,
             "DisableThirdPartyStoragePartitioningDeprecationTrial2",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Drop input events before user sees first paint https://crbug.com/1255485
BASE_FEATURE(kDropInputEventsBeforeFirstPaint,
             "DropInputEventsBeforeFirstPaint",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kEstablishGpuChannelAsync,
             "EstablishGpuChannelAsync",
#if BUILDFLAG(IS_ANDROID)
             base::FEATURE_ENABLED_BY_DEFAULT
#else
             // TODO(crbug.com/1278147): Experiment with this more on desktop to
             // see if it can help.
             base::FEATURE_DISABLED_BY_DEFAULT
#endif
);

// Enables unload handler deprecation via Permissions-Policy.
// https://crbug.com/1324111
BASE_FEATURE(kDeprecateUnload,
             "DeprecateUnload",
             base::FEATURE_DISABLED_BY_DEFAULT);
// If < 100, each user experiences the deprecation on this % of origins.
// Which origins varies per user.
BASE_FEATURE_PARAM(int,
                   kDeprecateUnloadPercent,
                   &kDeprecateUnload,
                   "rollout_percent",
                   100);
// This buckets users, with users in each bucket having a consistent experience
// of the unload deprecation rollout.
BASE_FEATURE_PARAM(int,
                   kDeprecateUnloadBucket,
                   &kDeprecateUnload,
                   "rollout_bucket",
                   0);

// Only used if `kDeprecateUnload` is enabled. The deprecation will only apply
// if the host is on the allow-list.
BASE_FEATURE(kDeprecateUnloadByAllowList,
             "DeprecateUnloadByAllowList",
             base::FEATURE_DISABLED_BY_DEFAULT);
// A list of hosts for which deprecation of unload is allowed. If it's empty
// the all hosts are allowed.
BASE_FEATURE_PARAM(std::string,
                   kDeprecateUnloadAllowlist,
                   &kDeprecateUnloadByAllowList,
                   "allowlist",
                   "");

// Prevents an opener from being returned when a BlobURL is cross-site to the
// window's top-level site.
BASE_FEATURE(kEnforceNoopenerOnBlobURLNavigation,
             "EnforceNoopenerOnBlobURLNavigation",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Controls whether LCP calculations should exclude low-entropy images. If
// enabled, then the associated parameter sets the cutoff, expressed as the
// minimum number of bits of encoded image data used to encode each rendered
// pixel. Note that this is not just pixels of decoded image data; the rendered
// size includes any scaling applied by the rendering engine to display the
// content.
BASE_FEATURE(kExcludeLowEntropyImagesFromLCP,
             "ExcludeLowEntropyImagesFromLCP",
             base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(double,
                   kMinimumEntropyForLCP,
                   &kExcludeLowEntropyImagesFromLCP,
                   "min_bpp",
                   0.05);

BASE_FEATURE(kExemptSpeculationRulesHeaderFromCSP,
             "ExemptSpeculationRulesHeaderFromCSP",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kExpandCompositedCullRect,
             "ExpandCompositedCullRect",
             base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(int,
                   kCullRectPixelDistanceToExpand,
                   &kExpandCompositedCullRect,
                   "pixels",
                   4000);
BASE_FEATURE_PARAM(double,
                   kCullRectExpansionDPRCoef,
                   &kExpandCompositedCullRect,
                   "dpr_coef",
                   0);
BASE_FEATURE_PARAM(bool,
                   kSmallScrollersUseMinCullRect,
                   &kExpandCompositedCullRect,
                   "small_scroller_opt",
                   false);

// Enable the <fencedframe> element; see crbug.com/1123606. Note that enabling
// this feature does not automatically expose this element to the web, it only
// allows the element to be enabled by the runtime enabled feature, for origin
// trials.
BASE_FEATURE(kFencedFrames, "FencedFrames", base::FEATURE_ENABLED_BY_DEFAULT);

// Enable sending event-level reports through reportEvent() in cross-origin
// subframes. This requires opt-in both from the cross-origin subframe that is
// sending the beacon as well as the document that contains information about
// the reportEvent() endpoints.
// The "UnlabeledTraffic" flag only allows cross-origin reportEvent() beacons
// for non-Mode A/B 3PCD Chrome-facilitated testing traffic. See the
// "CookieDeprecationFacilitatedTesting" feature in
// `content/public/common/content_features.cc` for more information.
BASE_FEATURE(kFencedFramesCrossOriginEventReportingUnlabeledTraffic,
             "FencedFramesCrossOriginEventReportingUnlabeledTraffic",
             base::FEATURE_ENABLED_BY_DEFAULT);
// The "AllTraffic" flag allows the feature for all traffic regardless of label.
BASE_FEATURE(kFencedFramesCrossOriginEventReportingAllTraffic,
             "FencedFramesCrossOriginEventReportingAllTraffic",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Temporarily un-disable credentials on fenced frame automatic beacons until
// third party cookie deprecation.
// TODO(crbug.com/1496395): Remove this after 3PCD.
BASE_FEATURE(kFencedFramesAutomaticBeaconCredentials,
             "FencedFramesAutomaticBeaconCredentials",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Controls functionality related to network revocation/local unpartitioned
// data access in fenced frames.
BASE_FEATURE(kFencedFramesLocalUnpartitionedDataAccess,
             "FencedFramesLocalUnpartitionedDataAccess",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kFencedFramesReportEventHeaderChanges,
             "FencedFramesReportEventHeaderChanges",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Enables a bug fix that allows a 'src' allowlist in the |allow| parameter of a
// <fencedframe> or <iframe> loaded with a FencedFrameConfig to behave as
// expected. See: https://crbug.com/349080952
BASE_FEATURE(kFencedFramesSrcPermissionsPolicy,
             "FencedFramesSrcPermissionsPolicy",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Controls access to an API to exempt certain URLs from fenced frame
// network revocation to facilitate testing.
BASE_FEATURE(kExemptUrlFromNetworkRevocationForTesting,
             "ExemptUrlFromNetworkRevocationForTesting",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Use "style" and "json" destinations for CSS and JSON modules.
// https://crbug.com/1491336
BASE_FEATURE(kFetchDestinationJsonCssModules,
             "kFetchDestinationJsonCssModules",
             base::FEATURE_ENABLED_BY_DEFAULT);

// File handling icons. https://crbug.com/1218213
BASE_FEATURE(kFileHandlingIcons,
             "FileHandlingIcons",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kFileSystemUrlNavigation,
             "FileSystemUrlNavigation",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kFileSystemUrlNavigationForChromeAppsOnly,
             "FileSystemUrlNavigationForChromeAppsOnly",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kFilteringScrollPrediction,
             "FilteringScrollPrediction",
#if BUILDFLAG(IS_ANDROID)
             base::FEATURE_ENABLED_BY_DEFAULT
#else
             // TODO(b/284271126): Run the experiment on desktop and enable if
             // positive.
             base::FEATURE_DISABLED_BY_DEFAULT
#endif
);
BASE_FEATURE_PARAM(std::string,
                   kFilteringScrollPredictionFilterParam,
                   &kFilteringScrollPrediction,
                   "filter",
                   "one_euro_filter");

// See https://github.com/WICG/turtledove/blob/main/FLEDGE.md
// Enables FLEDGE implementation. See https://crbug.com/1186444.
BASE_FEATURE(kFledge, "Fledge", base::FEATURE_ENABLED_BY_DEFAULT);

// See
// https://github.com/WICG/turtledove/blob/main/FLEDGE_browser_bidding_and_auction_API.md
BASE_FEATURE(kFledgeBiddingAndAuctionServer,
             "FledgeBiddingAndAuctionServer",
             base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(std::string,
                   kFledgeBiddingAndAuctionKeyURL,
                   &kFledgeBiddingAndAuctionServer,
                   "FledgeBiddingAndAuctionKeyURL",
                   "");
BASE_FEATURE_PARAM(std::string,
                   kFledgeBiddingAndAuctionKeyConfig,
                   &kFledgeBiddingAndAuctionServer,
                   "FledgeBiddingAndAuctionKeyConfig",
                   "");

// See in the header.
BASE_FEATURE(kFledgeConsiderKAnonymity,
             "FledgeConsiderKAnonymity",
             base::FEATURE_DISABLED_BY_DEFAULT);
BASE_FEATURE(kFledgeEnforceKAnonymity,
             "FledgeEnforceKAnonymity",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kFledgePassKAnonStatusToReportWin,
             "FledgePassKAnonStatusToReportWin",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kFledgePassRecencyToGenerateBid,
             "FledgePassRecencyToGenerateBid",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kFledgeSampleDebugReports,
             "FledgeSampleDebugReports",
             base::FEATURE_ENABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(base::TimeDelta,
                   kFledgeDebugReportLockout,
                   &kFledgeSampleDebugReports,
                   "fledge_debug_report_lockout",
                   base::Days(365 * 3));
BASE_FEATURE_PARAM(base::TimeDelta,
                   kFledgeDebugReportRestrictedCooldown,
                   &kFledgeSampleDebugReports,
                   "fledge_debug_report_restricted_cooldown",
                   base::Days(365));
BASE_FEATURE_PARAM(base::TimeDelta,
                   kFledgeDebugReportShortCooldown,
                   &kFledgeSampleDebugReports,
                   "fledge_debug_report_short_cooldown",
                   base::Days(14));
BASE_FEATURE_PARAM(int,
                   kFledgeDebugReportSamplingRandomMax,
                   &kFledgeSampleDebugReports,
                   "fledge_debug_report_sampling_random_max",
                   1000);
BASE_FEATURE_PARAM(
    int,
    kFledgeDebugReportSamplingRestrictedCooldownRandomMax,
    &kFledgeSampleDebugReports,
    "fledge_debug_report_sampling_restricted_cooldown_random_max",
    10);
BASE_FEATURE_PARAM(base::TimeDelta,
                   kFledgeEnableFilteringDebugReportStartingFrom,
                   &kFledgeSampleDebugReports,
                   "fledge_enable_filtering_debug_report_starting_from",
                   base::Milliseconds(0));

BASE_FEATURE(kFledgeSplitTrustedSignalsFetchingURL,
             "FledgeSplitTrustedSignalsFetchingURL",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE_PARAM(int,
                   kFledgeCustomMaxAuctionAdComponentsValue,
                   &kFledgeCustomMaxAuctionAdComponents,
                   "FledgeAdComponentLimit",
                   40);

BASE_FEATURE(kFledgeNumberBidderWorkletGroupByOriginContextsToKeep,
             "FledgeBidderWorkletGroupByOriginContextsToKeep",
             base::FEATURE_DISABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(int,
                   kFledgeNumberBidderWorkletGroupByOriginContextsToKeepValue,
                   &kFledgeNumberBidderWorkletGroupByOriginContextsToKeep,
                   "GroupByOriginContextLimit",
                   10);
BASE_FEATURE_PARAM(bool,
                   kFledgeNumberBidderWorkletContextsIncludeFacilitedTesting,
                   &kFledgeNumberBidderWorkletGroupByOriginContextsToKeep,
                   "IncludeFacilitatedTestingGroups",
                   false);

BASE_FEATURE(kFledgeAlwaysReuseBidderContext,
             "FledgeAlwaysReuseBidderContext",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kFledgeAlwaysReuseSellerContext,
             "FledgeAlwaysReuseSellerContext",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kFledgePrepareBidderContextsInAdvance,
             "FledgePrepareBidderContextsInAdvance",
             base::FEATURE_DISABLED_BY_DEFAULT);
BASE_FEATURE_PARAM(int,
                   kFledgeMaxBidderContextsPerThreadInAdvance,
                   &kFledgePrepareBidderContextsInAdvance,
                   "MaxBidderContextsPerThread",
                   10);
BASE_FEATURE_PARAM(int,
                   kFledgeBidderContextsDivisor,
                   &kFledgePrepareBidderContextsInAdvance,
                   "BidderContextsDivisor",
                   2);
BASE_FEATURE_PARAM(int,
                   kFledgeBidderContextsMultiplier,
                   &kFledgePrepareBidderContextsInAdvance,
                   "BidderContextsMultiplier",
                   1);

BASE_FEATURE_PARAM(int,
                   kFledgeRealTimeReportingNumBuckets,
                   &kFledgeRealTimeReporting,
                   "FledgeRealTimeReportingNumBuckets",
                   1024);
BASE_FEATURE_PARAM(double,
                   kFledgeRealTimeReportingEpsilon,
                   &kFledgeRealTimeReporting,
                   "FledgeRealTimeReportingEpsilon",
                   1);
BASE_FEATURE_PARAM(double,
                   kFledgeRealTimeReportingPlatformContributionPriority,
                   &kFledgeRealTimeReporting,
                   "FledgeRealTimeReportingPlatformContributionPriority",
                   1);
BASE_FEATURE_PARAM(base::TimeDelta,
                   kFledgeRealTimeReportingWindow,
                   &kFledgeRealTimeReporting,
                   "FledgeRealTimeReportingWindow",
                   base::Seconds(20));
BASE_FEATURE_PARAM(int,
                   kFledgeRealTimeReportingMaxReports,
                   &kFledgeRealTimeReporting,
                   "FledgeRealTimeReportingMaxReports",
                   10);

// Enable enforcement of permission policy for
// privateAggregation.contributeToHistogramOnEvent.
BASE_FEATURE(kFledgeEnforcePermissionPolicyContributeOnEvent,
             "FledgeEnforcePermissionPolicyContributeOnEvent",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kFledgeNoWasmLazyCompilation,
             "FledgeNoWasmLazyCompilation",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kForceHighPerformanceGPUForWebGL,
             "ForceHighPerformanceGPUForWebGL",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kForceInOrderScript,
             "ForceInOrderScript",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Automatically convert light-themed pages to use a Blink-generated dark theme
BASE_FEATURE(kForceWebContentsDarkMode,
             "WebContentsForceDark",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Which algorithm should be used for color inversion?
const base::FeatureParam<ForceDarkInversionMethod>::Option
    forcedark_inversion_method_options[] = {
        {ForceDarkInversionMethod::kUseBlinkSettings,
         "use_blink_settings_for_method"},
        {ForceDarkInversionMethod::kHslBased, "hsl_based"},
        {ForceDarkInversionMethod::kCielabBased, "cielab_based"},
        {ForceDarkInversionMethod::kRgbBased, "rgb_based"}};

BASE_FEATURE_ENUM_PARAM(ForceDarkInversionMethod,
                        kForceDarkInversionMethodParam,
                        &kForceWebContentsDarkMode,
                        "inversion_method",
                        ForceDarkInversionMethod::kUseBlinkSettings,
                        &forcedark_inversion_method_options);

// Should images be inverted?
const base::FeatureParam<ForceDarkImageBehavior>::Option
    forcedark_image_behavior_options[] = {
        {ForceDarkImageBehavior::kUseBlinkSettings,
         "use_blink_settings_for_images"},
        {ForceDarkImageBehavior::kInvertNone, "none"},
        {ForceDarkImageBehavior::kInvertSelectively, "selective"}};

BASE_FEATURE_ENUM_PARAM(ForceDarkImageBehavior,
                        kForceDarkImageBehaviorParam,
                        &kForceWebContentsDarkMode,
                        "image_behavior",
                        ForceDarkImageBehavior::kUseBlinkSettings,
                        &forcedark_image_behavior_options);

// Do not invert text lighter than this.
// Range: 0 (do not invert any text) to 255 (invert all text)
// Can also set to -1 to let Blink's internal settings control the value
BASE_FEATURE_PARAM(int,
                   kForceDarkForegroundLightnessThresholdParam,
                   &kForceWebContentsDarkMode,
                   "foreground_lightness_threshold",
                   -1);

// Do not invert backgrounds darker than this.
// Range: 0 (invert all backgrounds) to 255 (invert no backgrounds)
// Can also set to -1 to let Blink's internal settings control the value
BASE_FEATURE_PARAM(int,
                   kForceDarkBackgroundLightnessThresholdParam,
                   &kForceWebContentsDarkMode,
                   "background_lightness_threshold",
                   -1);

const base::FeatureParam<ForceDarkImageClassifier>::Option
    forcedark_image_classifier_policy_options[] = {
        {ForceDarkImageClassifier::kUseBlinkSettings,
         "use_blink_settings_for_image_policy"},
        {ForceDarkImageClassifier::kNumColorsWithMlFallback,
         "num_colors_with_ml_fallback"},
        {ForceDarkImageClassifier::kTransparencyAndNumColors,
         "transparency_and_num_colors"},
};

BASE_FEATURE_ENUM_PARAM(ForceDarkImageClassifier,
                        kForceDarkImageClassifierParam,
                        &kForceWebContentsDarkMode,
                        "classifier_policy",
                        ForceDarkImageClassifier::kUseBlinkSettings,
                        &forcedark_image_classifier_policy_options);

// Enables the frequency capping for detecting large sticky ads.
// Large-sticky-ads are those ads that stick to the bottom of the page
// regardless of a user’s efforts to scroll, and take up more than 30% of the
// screen’s real estate.
BASE_FEATURE(kFrequencyCappingForLargeStickyAdDetection,
             "FrequencyCappingForLargeStickyAdDetection",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Enables the frequency capping for detecting overlay popups. Overlay-popups
// are the interstitials that pop up and block the main content of the page.
BASE_FEATURE(kFrequencyCappingForOverlayPopupDetection,
             "FrequencyCappingForOverlayPopupDetection",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kGMSCoreEmoji, "GMSCoreEmoji", base::FEATURE_ENABLED_BY_DEFAULT);

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_CHROMEOS) && !BUILDFLAG(IS_FUCHSIA)
// Defers device selection until after permission is granted.
BASE_FEATURE(kGetUserMediaDeferredDeviceSettingsSelection,
             "GetUserMediaDeferredDeviceSettingsSelection",
             base::FEATURE_DISABLED_BY_DEFAULT);
#endif

BASE_FEATURE(kHiddenSelectionBounds,
             "HiddenSelectionBounds",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kImageLoadingPrioritizationFix,
             "ImageLoadingPrioritizationFix",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kIndexedDBCompressValuesWithSnappy,
             "IndexedDBCompressValuesWithSnappy",
             base::FEATURE_ENABLED_BY_DEFAULT);
constexpr base::FeatureParam<int>
    kIndexedDBCompressValuesWithSnappyCompressionThreshold{
        &features::kIndexedDBCompressValuesWithSnappy,
        /*name=*/"compression-threshold",
        /*default_value=*/-1};

BASE_FEATURE(kInputPredictorTypeChoice,
             "InputPredictorTypeChoice",
             base::FEATURE_DISABLED_BY_DEFAULT);

// When enabled, wake ups from throttleable TaskQueues are limited to 1 per
// minute in a page that has been backgrounded for 5 minutes.
//
// Intensive wake up throttling is enforced in addition to other throttling
// mechanisms:
//  - 1 wake up per second in a background page or hidden cross-origin frame
//  - 1% CPU time in a page that has been backgrounded for 10 seconds
//
// Feature tracking bug: https://crbug.com/1075553
//
// The base::Feature should not be read from; rather the provided accessors
// should be used, which also take into account the managed policy override of
// the feature.
//
// The base::Feature is enabled by default on all platforms. However, on
// Android, it has no effect because page freezing kicks in at the same time. It
// would have an effect if the grace period ("grace_period_seconds" param) was
// reduced.
BASE_FEATURE(kIntensiveWakeUpThrottling,
             "IntensiveWakeUpThrottling",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Name of the parameter that controls the grace period during which there is no
// intensive wake up throttling after a page is hidden. Defined here to allow
// access from about_flags.cc. The FeatureParam is defined in
// third_party/blink/renderer/platform/scheduler/common/features.cc.
const char kIntensiveWakeUpThrottling_GracePeriodSeconds_Name[] =
    "grace_period_seconds";

// Kill switch for the Interest Group API, i.e. if disabled, the
// API exposure will be disabled regardless of the OT config.
BASE_FEATURE(kInterestGroupStorage,
             "InterestGroupStorage",
             base::FEATURE_ENABLED_BY_DEFAULT);
// TODO(crbug.com/1197209): Adjust these limits in response to usage.
BASE_FEATURE_PARAM(int,
                   kInterestGroupStorageMaxOwners,
                   &kInterestGroupStorage,
                   "max_owners",
                   1000);
BASE_FEATURE_PARAM(int,
                   kInterestGroupStorageMaxStoragePerOwner,
                   &kInterestGroupStorage,
                   "max_storage_per_owner",
                   10 * 1024 * 1024);
BASE_FEATURE_PARAM(int,
                   kInterestGroupStorageMaxGroupsPerOwner,
                   &kInterestGroupStorage,
                   "max_groups_per_owner",
                   2000);
BASE_FEATURE_PARAM(int,
                   kInterestGroupStorageMaxNegativeGroupsPerOwner,
                   &kInterestGroupStorage,
                   "max_negative_groups_per_owner",
                   20000);
BASE_FEATURE_PARAM(int,
                   kInterestGroupStorageMaxOpsBeforeMaintenance,
                   &kInterestGroupStorage,
                   "max_ops_before_maintenance",
                   1000);

// Allow process isolation of iframes with the 'sandbox' attribute set. Whether
// or not such an iframe will be isolated may depend on options specified with
// the attribute. Note: At present, only iframes with origin-restricted
// sandboxes are isolated.
BASE_FEATURE(kIsolateSandboxedIframes,
             "IsolateSandboxedIframes",
             base::FEATURE_ENABLED_BY_DEFAULT);
const base::FeatureParam<IsolateSandboxedIframesGrouping>::Option
    isolated_sandboxed_iframes_grouping_types[] = {
        {IsolateSandboxedIframesGrouping::kPerSite, "per-site"},
        {IsolateSandboxedIframesGrouping::kPerOrigin, "per-origin"},
        {IsolateSandboxedIframesGrouping::kPerDocument, "per-document"}};
BASE_FEATURE_ENUM_PARAM(IsolateSandboxedIframesGrouping,
                        kIsolateSandboxedIframesGroupingParam,
                        &kIsolateSandboxedIframes,
                        "grouping",
                        IsolateSandboxedIframesGrouping::kPerOrigin,
                        &isolated_sandboxed_iframes_grouping_types);

BASE_FEATURE(kKalmanDirectionCutOff,
             "KalmanDirectionCutOff",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kKalmanHeuristics,
             "KalmanHeuristics",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kKeepAliveInBrowserMigration,
             "KeepAliveInBrowserMigration",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kAttributionReportingInBrowserMigration,
             "AttributionReportingInBrowserMigration",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kLCPCriticalPathPredictor,
             "LCPCriticalPathPredictor",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE_PARAM(bool,
                   kLCPCriticalPathAdjustImageLoadPriority,
                   &kLCPCriticalPathPredictor,
                   "lcpp_adjust_image_load_priority",
                   false);

BASE_FEATURE_PARAM(size_t,
                   kLCPCriticalPathPredictorMaxElementLocatorLength,
                   &kLCPCriticalPathPredictor,
                   "lcpp_max_element_locator_length",
                   1024);

BASE_FEATURE_PARAM(bool,
                   kLCPCriticalPathAdjustImageLoadPriorityOverrideFirstNBoost,
                   &kLCPCriticalPathPredictor,
                   "lcpp_adjust_image_load_priority_override_first_n_boost",
                   false);

const base::FeatureParam<LcppRecordedLcpElementTypes>::Option
    lcpp_recorded_element_types[] = {
        {LcppRecordedLcpElementTypes::kAll, "all"},
        {LcppRecordedLcpElementTypes::kImageOnly, "image_only"},
};
BASE_FEATURE_ENUM_PARAM(LcppRecordedLcpElementTypes,
                        kLCPCriticalPathPredictorRecordedLcpElementTypes,
                        &kLCPCriticalPathPredictor,
                        "lcpp_recorded_lcp_element_types",
                        LcppRecordedLcpElementTypes::kImageOnly,
                        &lcpp_recorded_element_types);

const base::FeatureParam<LcppResourceLoadPriority>::Option
    lcpp_resource_load_priorities[] = {
        {LcppResourceLoadPriority::kMedium, "medium"},
        {LcppResourceLoadPriority::kHigh, "high"},
        {LcppResourceLoadPriority::kVeryHigh, "very_high"},
};
BASE_FEATURE_ENUM_PARAM(LcppResourceLoadPriority,
                        kLCPCriticalPathPredictorImageLoadPriority,
                        &kLCPCriticalPathPredictor,
                        "lcpp_image_load_priority",
                        LcppResourceLoadPriority::kVeryHigh,
                        &lcpp_resource_load_priorities);

BASE_FEATURE_PARAM(
    bool,
    kLCPCriticalPathPredictorImageLoadPriorityEnabledForHTMLImageElement,
    &kLCPCriticalPathPredictor,
    "lcpp_enable_image_load_priority_for_htmlimageelement",
    false);

BASE_FEATURE_PARAM(int,
                   kLCPCriticalPathPredictorMaxHostsToTrack,
                   &kLCPCriticalPathPredictor,
                   "lcpp_max_hosts_to_track",
                   1000);

BASE_FEATURE_PARAM(int,
                   kLCPCriticalPathPredictorHistogramSlidingWindowSize,
                   &kLCPCriticalPathPredictor,
                   "lcpp_histogram_sliding_window_size",
                   1000);

BASE_FEATURE_PARAM(int,
                   kLCPCriticalPathPredictorMaxHistogramBuckets,
                   &kLCPCriticalPathPredictor,
                   "lcpp_max_histogram_buckets",
                   10);

BASE_FEATURE(kLCPScriptObserver,
             "LCPScriptObserver",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE_ENUM_PARAM(LcppResourceLoadPriority,
                        kLCPScriptObserverScriptLoadPriority,
                        &kLCPScriptObserver,
                        "lcpscriptobserver_script_load_priority",
                        LcppResourceLoadPriority::kVeryHigh,
                        &lcpp_resource_load_priorities);

BASE_FEATURE_ENUM_PARAM(LcppResourceLoadPriority,
                        kLCPScriptObserverImageLoadPriority,
                        &kLCPScriptObserver,
                        "lcpscriptobserver_image_load_priority",
                        LcppResourceLoadPriority::kVeryHigh,
                        &lcpp_resource_load_priorities);

BASE_FEATURE_PARAM(size_t,
                   kLCPScriptObserverMaxUrlLength,
                   &kLCPScriptObserver,
                   "lcpscriptobserver_script_max_url_length",
                   1024);

BASE_FEATURE_PARAM(size_t,
                   kLCPScriptObserverMaxUrlCountPerOrigin,
                   &kLCPScriptObserver,
                   "lcpscriptobserver_script_max_url_count_per_origin",
                   5);

BASE_FEATURE_PARAM(bool,
                   kLCPScriptObserverAdjustImageLoadPriority,
                   &kLCPScriptObserver,
                   "lcpscriptobserver_adjust_image_load_priority",
                   false);

BASE_FEATURE(kLCPTimingPredictorPrerender2,
             "LCPTimingPredictorPrerender2",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE(kLCPPAutoPreconnectLcpOrigin,
             "LCPPAutoPreconnectLcpOrigin",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE_PARAM(double,
                   kLCPPAutoPreconnectFrequencyThreshold,
                   &kLCPPAutoPreconnectLcpOrigin,
                   "lcpp_preconnect_frequency_threshold",
                   0.5);

BASE_FEATURE_PARAM(int,
                   kkLCPPAutoPreconnectMaxPreconnectOriginsCount,
                   &kLCPPAutoPreconnectLcpOrigin,
                   "lcpp_preconnect_max_origins",
                   2);

BASE_FEATURE(kLCPPDeferUnusedPreload,
             "LCPPDeferUnusedPreload",
             base::FEATURE_DISABLED_BY_DEFAULT);

const base::FeatureParam<LcppDeferUnusedPreloadExcludedResourceType>::Option
    lcpp_defer_unused_preload_excluded_resource_type[] = {
        {LcppDeferUnusedPreloadExcludedResourceType::kNone, "none"},
        {LcppDeferUnusedPreloadExcludedResourceType::kStyleSheet, "stylesheet"},
        {LcppDeferUnusedPreloadExcludedResourceType::kScript, "script"},
        {LcppDeferUnusedPreloadExcludedResourceType::kMock, "mock"},
};

BASE_FEATURE_ENUM_PARAM(LcppDeferUnusedPreloadExcludedResourceType,
                        kLcppDeferUnusedPreloadExcludedResourceType,
                        &kLCPPDeferUnusedPreload,
                        "excluded_resource_type",
                        LcppDeferUnusedPreloadExcludedResourceType::kNone,
                        &lcpp_defer_unused_preload_excluded_resource_type);

BASE_FEATURE_PARAM(double,
                   kLCPPDeferUnusedPreloadFrequencyThreshold,
                   &kLCPPDeferUnusedPreload,
                   "lcpp_unused_preload_frequency_threshold",
                   0.5);

const base::FeatureParam<LcppDeferUnusedPreloadPreloadedReason>::Option
    lcpp_defer_unused_preload_preloaded_reason[] = {
        {LcppDeferUnusedPreloadPreloadedReason::kAll, "all"},
        {LcppDeferUnusedPreloadPreloadedReason::kLinkPreloadOnly,
         "link_preload"},
        {LcppDeferUnusedPreloadPreloadedReason::kBrowserSpeculativePreloadOnly,
         "speculative_preload"},
};

BASE_FEATURE_ENUM_PARAM(LcppDeferUnusedPreloadPreloadedReason,
                        kLcppDeferUnusedPreloadPreloadedReason,
                        &kLCPPDeferUnusedPreload,
                        "preloaded_reason",
                        LcppDeferUnusedPreloadPreloadedReason::kAll,
                        &lcpp_defer_unused_preload_preloaded_reason);

const base::FeatureParam<LcppDeferUnusedPreloadTiming>::Option
    lcpp_defer_unused_preload_timing[] = {
        {LcppDeferUnusedPreloadTiming::kPostTask, "post_task"},
        {LcppDeferUnusedPreloadTiming::kLcpTimingPredictor,
         "lcp_timing_predictor"},
        {LcppDeferUnusedPreloadTiming::kLcpTimingPredictorWithPostTask,
         "lcp_timing_predictor_with_post_task"},
};

BASE_FEATURE_ENUM_PARAM(LcppDeferUnusedPreloadTiming,
                        kLcppDeferUnusedPreloadTiming,
                        &kLCPPDeferUnusedPreload,
                        "load_timing",
                        LcppDeferUnusedPreloadTiming::kPostTask,
                        &lcpp_defer_unused_preload_timing);

BASE_FEATURE(kLCPPFontURLPredictor,
             "LCPPFontURLPredictor",
             base::FEATURE_DISABLED_BY_DEFAULT);

BASE_FEATURE_PARAM(size_t,
                   kLCPPFontURLPredictorMaxUrlLength,
                   &kLCPPFontURLPredictor,
                   "lcpp_max_font_url_length",
                   1024);

BASE_FEATURE_PARAM(size_t,
                   kLCPPFontURLPredictorMaxUrlCountPerOrigin,
                   &kLCPPFontURLPredictor,
                   "lcpp_max_font_url_count_per_origin",
                   10);

BASE_FEATURE_PARAM(double,
                   kLCPPFontURLPredictorFrequencyThreshold,
                   &kLCPPFontURLPredictor,
                   "lcpp_font_url_frequency_threshold",
                   0.5);

BASE_FEATURE_PARAM(int,
                   kLCPPFontURLPredictorMaxPreloadCount,
                   &kLCPPFontURLPredictor,
                   "lcpp_max_font_url_to_preload",
                   5);

BASE_FEATURE_PARAM(bool,
                   kLCPPFontURLPredictorEnablePrefetch,
                   &kLCPPFontURLPredictor,
                   "lcpp_enable_font_prefetch",
                   false);

// Negative value is used for disabling this threshold.
BASE_FEATURE_PARAM(double,
                   kLCPPFontURLPredictorThresholdInMbps,
                   &kLCPPFontURLPredictor,
                   "lcpp_font_prefetch_threshold",
                   -1);

const base::FeatureParam<std::string> kLCPPFontURLPredictorExcludedHosts{
    &kLCPPFontURLPredictor, "lcpp_font_prefetch_excluded_hosts", ""};

BASE_FEATURE_PARAM(bool,
                   kLCPPCrossSiteFontPredictionAllowed,
                   &kLCPPFontURLPredictor,
                   "lcpp_cross_site_font_prediction_allowed",
                   false);

BASE_FEATURE(kLCPPInitiatorOrigin,
             "LCPPInitiatorOrigin",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE_PARAM(int,
                   kLcppInitiatorOriginHistogramSlidingWindowSize,
                   &kLCPPInitiatorOrigin,
                   "lcpp_initiator_origin_histogram_sliding_window_size",
                   10000);

BASE_FEATURE_PARAM(int,
                   kLcppInitiatorOriginMaxHistogramBuckets,
                   &kLCPPInitiatorOrigin,
                   "lcpp_initiator_origin_max_histogram_buckets",
                   100);

BASE_FEATURE(kLCPPLazyLoadImagePreload,
             "LCPPLazyLoadImagePreload",
             base::FEATURE_DISABLED_BY_DEFAULT);

// If true, do not make a preload r
```