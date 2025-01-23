Response:
Let's break down the thought process for analyzing this `layer_tree_settings.cc` file.

1. **Understand the Goal:** The request asks for the *functionality* of the file, its relationship to web technologies (JS, HTML, CSS), examples of these relationships, logical reasoning with inputs/outputs, and common user/programming errors.

2. **Initial Scan and Keywords:**  A quick scan reveals important keywords and concepts:
    * `LayerTreeSettings`: This is the core of the file. It strongly suggests configuration related to how the rendering engine builds and manages the layer tree, which is fundamental to how web pages are displayed.
    * `#include`: Many includes point to dependencies like `cc` (Chromium Compositor), `base` (Chromium base library), `third_party/blink/public`, `ui`, etc. This tells us the file interacts with various parts of the Chromium ecosystem.
    * `base::FeatureList`, `base::CommandLine`, `switches::`: These indicate the file uses feature flags and command-line switches to control behavior. This is a common pattern in Chromium for experimenting with and configuring features.
    * `gfx::Size`, `base::Milliseconds`: These are data types related to graphics and timing, reinforcing the rendering/compositing aspect.
    * `BUILDFLAG`:  Conditional compilation based on the build target (e.g., Android).
    * Scrollbar-related variables (`scrollbar_fade_delay`, `scrollbar_fade_duration`, etc.):  Indicates control over the appearance of scrollbars.
    * Tile-related variables (`default_tile_size`, `max_untiled_layer_size`, etc.):  Points to how the rendering engine divides content into tiles for efficient rendering.
    * Memory policy (`memory_policy`): Shows involvement in managing GPU memory.
    * Debug settings (`show_debug_borders`, `show_fps_counter`, etc.):  Configuration for debugging and performance analysis.

3. **Identify the Core Function:** The primary function is `GenerateLayerTreeSettings`. This function takes parameters like `is_threaded`, `is_for_embedded_frame`, screen size, and device scale factor and returns a `cc::LayerTreeSettings` object. This object encapsulates a wide range of configuration options. This is the central piece of functionality.

4. **Break Down Functionality by Category:**  To organize the analysis, it's helpful to group the settings into logical categories based on the code:

    * **Basic Compositing Settings:**  Things like `enable_synchronized_scrolling`, `commit_to_active_tree`, `is_for_embedded_frame`, etc. These define the fundamental compositing model.
    * **Checker Imaging:**  Settings related to displaying checkerboard patterns for unloaded or in-progress images (`enable_checker_imaging`).
    * **Tiling:**  Configuration of how the page is divided into tiles for rasterization (`default_tile_size`, `max_untiled_layer_size`).
    * **GPU Rasterization:** Settings related to using the GPU for rasterization, including MSAA (`gpu_rasterization_msaa_sample_count`).
    * **Zero-Copy and Partial Raster:** Optimizations for rendering (`use_zero_copy`, `use_partial_raster`).
    * **Overscroll:** Behavior when scrolling beyond the content boundaries (`enable_elastic_overscroll`).
    * **Browser Controls:** Settings for how the browser's UI (like the address bar) interacts with the page (`top_controls_show_threshold`, `top_controls_hide_threshold`).
    * **Scrolling:** Features like smooth scrolling and fractional scroll offsets (`enable_smooth_scroll`, `commit_fractional_scroll_deltas`).
    * **Debugging:**  A significant section deals with debug visualizations (`show_composited_layer_borders`, `show_fps_counter`, etc.).
    * **Scrollbar Appearance:**  Customization of scrollbar behavior and animations (`scrollbar_fade_delay`, `scrollbar_fade_duration`, `scrollbar_animator`).
    * **Memory Management:**  Policies for managing GPU memory, especially for tiles and images (`memory_policy`, `decoded_image_working_set_budget_bytes`).
    * **Low-End Device Optimizations:**  Specific settings for devices with limited resources (`use_rgba_4444`, `create_low_res_tiling`).
    * **Frame Rate Limiting:** Controlling the maximum rendering frame rate (`disable_frame_rate_limit`).
    * **Hit Testing:** Settings related to how the browser determines which element the user interacts with (`enable_hit_test_opaqueness`).
    * **Variable Refresh Rate:** Support for displays with variable refresh rates (`enable_variable_refresh_rate`).
    * **Tiling Interest Area:** Configuration for optimizing rendering around the visible viewport (`tiling_interest_area_padding`, `skewport_extrapolation_limit_in_screen_pixels`).

5. **Relate to Web Technologies (JS, HTML, CSS):**  This is crucial. Think about how each category of settings can be influenced or observed from the web development perspective:

    * **HTML Structure:** The layer tree is directly based on the HTML DOM. Changes in HTML structure will lead to changes in the layer tree.
    * **CSS Styling:** CSS properties (especially those causing stacking contexts, transformations, filters, opacity, etc.) heavily influence layer creation and compositing. CSS animations and transitions also interact with the timing settings. Scrollbar styling is directly related.
    * **JavaScript Interaction:** JavaScript can trigger changes that affect the layer tree (DOM manipulation, CSS changes, animations). JavaScript libraries might rely on certain compositing behaviors. Scroll events in JS are relevant to scrollbar settings. The `requestAnimationFrame` API is related to frame rate.

6. **Provide Concrete Examples:**  For each relationship, provide a short, illustrative example. Don't need extensive code, just enough to demonstrate the connection.

7. **Logical Reasoning (Assumptions and Outputs):** This requires thinking about how the settings *affect* the rendering process. Choose a few key settings and describe what happens with different input values. For instance, change the tile size and describe the impact on memory usage and rendering performance.

8. **Common Errors:**  Think about mistakes developers or users might make that relate to these settings (even indirectly):

    * **Forcing GPU Rasterization on Low-End Devices:**  Potentially causing performance issues.
    * **Incorrectly Assuming Zero-Copy is Always Beneficial:**  Might have downsides in certain scenarios.
    * **Not Understanding the Impact of CSS on Compositing:**  Leading to unexpected layer creation and performance problems.
    * **Misconfiguring Debug Flags:**  Showing incorrect information or impacting performance in production.
    * **Overriding Default Settings Without Understanding the Consequences:** Leading to unintended side effects.

9. **Structure and Refine:** Organize the information clearly using headings and bullet points. Ensure the language is precise and avoids jargon where possible. Review and refine the explanation for clarity and accuracy.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus solely on the `GenerateLayerTreeSettings` function. **Correction:** Realized the request asks for the file's *functions* (plural), so need to encompass the overall purpose and the individual settings it manages.
* **Initial examples:** Might be too technical. **Correction:** Simplify the examples to be more accessible to developers with varying levels of Blink/Chromium knowledge.
* **Focus too much on code:**  **Correction:**  Shift the emphasis to the *functionality* and its implications, rather than just describing the code itself.
* **Overlook the "user" aspect of common errors:** **Correction:**  Think about how users might experience the effects of these settings (e.g., janky scrolling due to improper compositing).

By following these steps, including the iterative refinement, you can generate a comprehensive and accurate explanation of the `layer_tree_settings.cc` file.
这个文件 `blink/renderer/platform/widget/compositing/layer_tree_settings.cc` 的主要功能是 **定义和生成 `cc::LayerTreeSettings` 对象**。 `cc::LayerTreeSettings`  包含了大量的配置项，用于控制 Blink 渲染引擎中 **合成（Compositing）** 过程的行为。  合成是将渲染过程分解成多个独立的层，然后由合成器独立地绘制这些层，从而实现更流畅的动画和滚动效果。

更具体地说，这个文件做了以下事情：

1. **定义默认值和通过 Feature Flags 进行配置:**  它使用 `base::FeatureList` 来启用或禁用某些实验性或可选的合成特性。这些 Feature Flags 可以通过 Chromium 的命令行参数或 Finch 实验进行配置。

2. **读取命令行参数进行配置:** 它读取 Chromium 的命令行参数（通过 `base::CommandLine`）来覆盖某些 `cc::LayerTreeSettings` 的默认值。这允许开发者或测试人员在不重新编译代码的情况下调整合成器的行为。

3. **根据平台和设备特性进行调整:**  它根据不同的平台（例如 Android）和设备特性（例如是否为低端设备，屏幕尺寸）来调整默认的合成设置，以优化性能和用户体验。

4. **提供一个工厂函数:** `GenerateLayerTreeSettings` 函数是主要的工厂方法，它根据各种输入（例如是否为嵌入式 frame，屏幕尺寸，设备缩放因子）来生成一个配置好的 `cc::LayerTreeSettings` 对象。

**它与 Javascript, HTML, CSS 的功能关系：**

`layer_tree_settings.cc` 本身不直接处理 Javascript, HTML, 或 CSS 的解析或执行。但是，它配置的合成器行为**直接影响**这些技术在页面上的最终呈现方式和性能。

以下是一些例子：

* **CSS `transform` 和 `opacity` 属性 (CSS):**
    * **功能关系:** 当你在 CSS 中使用 `transform` 或 `opacity` 时，浏览器通常会将这些元素提升到它们自己的合成层。`layer_tree_settings.cc` 中的配置（例如是否启用某些合成优化）会影响这些层的创建、管理和渲染方式。
    * **举例说明:**  `settings.use_partial_raster` 设置决定了是否启用部分栅格化。如果启用，当一个变换或透明度动画发生时，只有受影响的图块会被重新绘制，而不是整个层，从而提高性能。如果禁用，即使只改变了一小部分，整个层也可能需要重新绘制。
    * **假设输入与输出:** 假设一个带有 CSS `transform: translateX(10px);` 动画的 `div` 元素。
        * **输入 (启用 `use_partial_raster`)**:  动画开始，合成器会只重新栅格化 `div` 元素移动过程中覆盖的图块。
        * **输出 (启用 `use_partial_raster`)**:  动画更流畅，CPU/GPU 消耗更低。
        * **输入 (禁用 `use_partial_raster`)**: 动画开始，合成器可能会重新栅格化包含 `div` 元素的整个合成层。
        * **输出 (禁用 `use_partial_raster`)**:  动画可能出现卡顿，CPU/GPU 消耗更高。

* **`<iframe>` 元素 (HTML):**
    * **功能关系:**  `settings.is_for_embedded_frame` 参数指示是否正在为一个 `<iframe>` 元素生成合成设置。嵌入式 frame 的合成方式可能与主 frame 不同。
    * **举例说明:**  某些优化或限制可能只应用于嵌入式 frame，以提高整体性能或隔离不同 frame 的渲染。
    * **假设输入与输出:**
        * **输入 (`is_for_embedded_frame` 为 true)**:  合成器可能采用更保守的内存策略，或者禁用某些高级优化，以避免与主 frame 的渲染冲突。
        * **输出**:  `<iframe>` 内容的渲染可能略有不同，以确保稳定性。

* **滚动行为 (受 CSS `overflow` 和 Javascript 滚动 API 影响):**
    * **功能关系:**  `settings.enable_synchronized_scrolling` 和 `settings.enable_smooth_scroll` 等设置控制了滚动事件的处理方式和滚动动画的呈现效果。这些设置会影响 Javascript 滚动监听器和 CSS `overflow: scroll` 的行为。
    * **举例说明:** `settings.scrollbar_fade_delay` 和 `settings.scrollbar_fade_duration` 设置控制了滚动条在一段时间不活动后消失的动画效果，这直接影响用户在网页上滚动时的视觉体验。
    * **假设输入与输出:**
        * **输入 (`settings.scrollbar_fade_delay` 设置为 500ms)**:  用户停止滚动后，滚动条会在 500 毫秒后开始淡出。
        * **输出**:  用户能观察到滚动条在停止滚动一段时间后逐渐消失的动画效果。
        * **输入 (`settings.enable_smooth_scroll` 为 true)**: 用户使用鼠标滚轮或触控板滚动页面。
        * **输出**:  页面会以平滑的动画效果滚动，而不是瞬间跳跃。

**逻辑推理的假设输入与输出:**

* **假设输入:** Chromium 启动时使用了命令行参数 `--enable-checker-imaging`.
* **逻辑推理:** 代码中会检查该命令行参数，并且 `settings.enable_checker_imaging` 会被设置为 `true`.
* **输出:** 当图片加载缓慢时，会显示棋盘格图案代替空白区域，提示用户图片正在加载中。

* **假设输入:**  在一个低端 Android 设备上运行 Chromium，且屏幕尺寸较小。
* **逻辑推理:** 代码中会检查 `BUILDFLAG(IS_ANDROID)` 和设备内存以及屏幕尺寸。
* **输出:**  `settings.use_rgba_4444` 可能被设置为 `true`，以使用更节省内存的 RGBA_4444 纹理格式，牺牲一些颜色精度来降低内存消耗。

**用户或编程常见的使用错误举例:**

* **用户错误:** 用户可能会在性能较差的设备上手动禁用硬件加速（尽管这不是直接通过修改此文件完成的）。这会导致合成过程回退到软件渲染，性能会显著下降。虽然 `layer_tree_settings.cc` 不直接处理用户输入，但它配置的合成器行为会影响用户体验。

* **编程错误:** 开发者可能会错误地假设所有浏览器都支持某些高级合成特性，而没有进行特性检测。例如，如果开发者依赖于部分栅格化（`settings.use_partial_raster`），但在某些不支持的浏览器或配置下，性能可能会下降，因为会回退到全层栅格化。

* **配置错误:** 开发者或测试人员可能会错误地使用命令行参数来配置合成器，导致意想不到的渲染问题。例如，错误地设置了非常小的瓦片尺寸（通过 `--default-tile-width` 和 `--default-tile-height`），可能导致过多的图块管理开销，反而降低性能。

* **忽略平台差异:**  开发者可能会忽略不同平台上的默认合成设置差异。例如，在 Android 上，由于内存限制，默认的瓦片大小可能与桌面平台不同。如果开发者没有考虑到这些差异，可能会导致在某些平台上出现性能问题。

总而言之，`layer_tree_settings.cc` 是 Blink 渲染引擎中合成器的核心配置中心。它通过 Feature Flags、命令行参数和平台特性来灵活地控制合成器的行为，从而直接影响网页的渲染性能和用户体验，并与 Javascript, HTML, CSS 的功能紧密相关。 开发者理解这些设置对于优化网页性能至关重要。

### 提示词
```
这是目录为blink/renderer/platform/widget/compositing/layer_tree_settings.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/widget/compositing/layer_tree_settings.h"

#include <algorithm>
#include <tuple>

#include "base/base_switches.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/metrics/field_trial_params.h"
#include "base/strings/string_number_conversions.h"
#include "base/system/sys_info.h"
#include "build/build_config.h"
#include "cc/base/features.h"
#include "cc/base/switches.h"
#include "cc/tiles/image_decode_cache_utils.h"
#include "cc/trees/layer_tree_settings.h"
#include "components/viz/common/features.h"
#include "components/viz/common/switches.h"
#include "gpu/command_buffer/service/gpu_switches.h"
#include "gpu/config/gpu_finch_features.h"
#include "media/base/media_switches.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/switches.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "ui/base/ui_base_features.h"
#include "ui/base/ui_base_switches.h"
#include "ui/native_theme/native_theme_features.h"
#include "ui/native_theme/native_theme_utils.h"
#include "ui/native_theme/overlay_scrollbar_constants_aura.h"

namespace blink {

namespace {

BASE_FEATURE(kUnpremultiplyAndDitherLowBitDepthTiles,
             "UnpremultiplyAndDitherLowBitDepthTiles",
             base::FEATURE_ENABLED_BY_DEFAULT);

// When enabled, scrollbar fade animations' delay and duration are scaled
// according to `kFadeDelayScalingFactor` and `kFadeDurationScalingFactor`
// below, respectively. For more context, please see https://crbug.com/1245964.
BASE_FEATURE(kScaleScrollbarAnimationTiming,
             "ScaleScrollbarAnimationTiming",
             base::FEATURE_DISABLED_BY_DEFAULT);

constexpr base::FeatureParam<double> kFadeDelayScalingFactor{
    &kScaleScrollbarAnimationTiming, "fade_delay_scaling_factor",
    /*default_value=*/1.0};

constexpr base::FeatureParam<double> kFadeDurationScalingFactor{
    &kScaleScrollbarAnimationTiming, "fade_duration_scaling_factor",
    /*default_value=*/1.0};

void InitializeScrollbarFadeAndDelay(cc::LayerTreeSettings& settings) {
  // Default settings that may be overridden below for specific platforms.
  settings.scrollbar_fade_delay = base::Milliseconds(300);
  settings.scrollbar_fade_duration = base::Milliseconds(300);

#if !BUILDFLAG(IS_ANDROID)
  if (ui::IsOverlayScrollbarEnabled()) {
    settings.idle_thickness_scale = ui::kOverlayScrollbarIdleThicknessScale;
    if (ui::IsFluentOverlayScrollbarEnabled()) {
      settings.scrollbar_fade_delay = ui::kFluentOverlayScrollbarFadeDelay;
      settings.scrollbar_fade_duration =
          ui::kFluentOverlayScrollbarFadeDuration;
    } else {
      settings.scrollbar_fade_delay = ui::kOverlayScrollbarFadeDelay;
      settings.scrollbar_fade_duration = ui::kOverlayScrollbarFadeDuration;
    }
  }
#endif  // !BUILDFLAG(IS_ANDROID)

  if (base::FeatureList::IsEnabled(kScaleScrollbarAnimationTiming)) {
    settings.scrollbar_fade_delay *= kFadeDelayScalingFactor.Get();
    settings.scrollbar_fade_duration *= kFadeDurationScalingFactor.Get();
  }
}

#if BUILDFLAG(IS_ANDROID)
// With 32 bit pixels, this would mean less than 400kb per buffer. Much less
// than required for, say, nHD.
static const int kSmallScreenPixelThreshold = 1e5;
bool IsSmallScreen(const gfx::Size& size) {
  int area = 0;
  if (!size.GetCheckedArea().AssignIfValid(&area))
    return false;
  return area < kSmallScreenPixelThreshold;
}
#endif

std::pair<int, int> GetTilingInterestAreaSizes() {
  int interest_area_size_in_pixels;

  if (base::FeatureList::IsEnabled(::features::kSmallerInterestArea) &&
      ::features::kInterestAreaSizeInPixels.Get() ==
          ::features::kInterestAreaSizeInPixels.default_value) {
    interest_area_size_in_pixels =
        ::features::kDefaultInterestAreaSizeInPixelsWhenEnabled;
  } else {
    interest_area_size_in_pixels = ::features::kInterestAreaSizeInPixels.Get();
  }

  if (interest_area_size_in_pixels ==
      ::features::kInterestAreaSizeInPixels.default_value) {
    return {
        ::features::kDefaultInterestAreaSizeInPixels,
        cc::LayerTreeSettings::kDefaultSkewportExtrapolationLimitInScrenPixels};
  }
  // Keep the same ratio we have by default.
  static_assert(
      cc::LayerTreeSettings::kDefaultSkewportExtrapolationLimitInScrenPixels ==
      2 * ::features::kDefaultInterestAreaSizeInPixels / 3);
  return {interest_area_size_in_pixels, (2 * interest_area_size_in_pixels) / 3};
}

#if !BUILDFLAG(IS_ANDROID)
// Adjusting tile memory size in case a lot more websites need more tile
// memory than the current calculation.
BASE_FEATURE(kAdjustTileGpuMemorySize,
             "AdjustTileGpuMemorySize",
             base::FEATURE_DISABLED_BY_DEFAULT);

constexpr size_t kLargeResolutionMemoryMB = 1152;
constexpr size_t kDefaultMemoryMB = 512;

constexpr base::FeatureParam<int> kNewLargeResolutionMemoryMB{
    &kAdjustTileGpuMemorySize, "new_large_resolution_memory_mb",
    /*default_value=*/kLargeResolutionMemoryMB};

constexpr base::FeatureParam<int> kNewDefaultMemoryMB{
    &kAdjustTileGpuMemorySize, "new_default_memory_mb",
    /*default_value=*/kDefaultMemoryMB};

size_t GetLargeResolutionMemoryMB() {
  if (base::FeatureList::IsEnabled(kAdjustTileGpuMemorySize)) {
    return kNewLargeResolutionMemoryMB.Get();
  } else {
    return kLargeResolutionMemoryMB;
  }
}

size_t GetDefaultMemoryMB() {
  if (base::FeatureList::IsEnabled(kAdjustTileGpuMemorySize)) {
    return kNewDefaultMemoryMB.Get();
  } else {
    return kDefaultMemoryMB;
  }
}
#endif

}  // namespace

// static
cc::ManagedMemoryPolicy GetGpuMemoryPolicy(
    const cc::ManagedMemoryPolicy& default_policy,
    const gfx::Size& initial_screen_size,
    float initial_device_scale_factor) {
  cc::ManagedMemoryPolicy actual = default_policy;
  actual.bytes_limit_when_visible = 0;

  // If the value was overridden on the command line, use the specified value.
  static bool client_hard_limit_bytes_overridden =
      base::CommandLine::ForCurrentProcess()->HasSwitch(
          ::switches::kForceGpuMemAvailableMb);
  if (client_hard_limit_bytes_overridden) {
    if (base::StringToSizeT(
            base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
                ::switches::kForceGpuMemAvailableMb),
            &actual.bytes_limit_when_visible))
      actual.bytes_limit_when_visible *= 1024 * 1024;
    return actual;
  }

#if BUILDFLAG(IS_ANDROID)
  if (base::SysInfo::IsLowEndDevice() ||
      base::SysInfo::AmountOfPhysicalMemoryMB() < 2000) {
    actual.bytes_limit_when_visible = 96 * 1024 * 1024;
  } else {
    actual.bytes_limit_when_visible = 256 * 1024 * 1024;
  }
#else
  // This calculation will increase the tile memory size. It should apply to
  // the other plateforms if no regression on Mac.
  //
  // For large monitors with high resolution, increase the tile memory to
  // avoid frequent out of memory problems. With Mac M1 on
  // https://www.334-28th.com/, it seems 512 MB works fine on 1920x1080 * 2
  // (scale) and 1152 MB on 2056x1329 * 2 (scale). Use this ratio for the
  // formula to increase |bytes_limit_when_visible| proportionally.
  // For mobile platforms with small display (roughly less than 3k x 1.6k),
  // mb_limit will still be 512 MB.
  constexpr size_t kLargeResolution = 2056 * 1329 * 2 * 2;
  size_t display_size =
      std::round(initial_screen_size.width() * initial_device_scale_factor *
                 initial_screen_size.height() * initial_device_scale_factor);

  size_t large_resolution_memory_mb = GetLargeResolutionMemoryMB();
  size_t mb_limit_when_visible =
      large_resolution_memory_mb * (display_size * 1.0 / kLargeResolution);

  // Cap the memory size to one fourth of the total system memory so it won't
  // consume too much of the system memory. Still keep the minimum to the
  // default of 512MB.
  size_t default_memory_mb = GetDefaultMemoryMB();
  size_t memory_cap_mb = base::SysInfo::AmountOfPhysicalMemoryMB() / 4;
  if (mb_limit_when_visible > memory_cap_mb) {
    mb_limit_when_visible = memory_cap_mb;
  } else if (mb_limit_when_visible < default_memory_mb) {
    mb_limit_when_visible = default_memory_mb;
  }

  actual.bytes_limit_when_visible = mb_limit_when_visible * 1024 * 1024;
#endif
  actual.priority_cutoff_when_visible =
      gpu::MemoryAllocation::CUTOFF_ALLOW_NICE_TO_HAVE;

  return actual;
}

// static
cc::LayerTreeSettings GenerateLayerTreeSettings(
    bool is_threaded,
    bool is_for_embedded_frame,
    bool is_for_scalable_page,
    const gfx::Size& initial_screen_size,
    float initial_device_scale_factor) {
  const base::CommandLine& cmd = *base::CommandLine::ForCurrentProcess();
  cc::LayerTreeSettings settings;

  settings.enable_synchronized_scrolling =
      base::FeatureList::IsEnabled(::features::kSynchronizedScrolling);
  Platform* platform = Platform::Current();
  settings.percent_based_scrolling =
      ::features::IsPercentBasedScrollingEnabled();

  settings.commit_to_active_tree = !is_threaded;
  settings.is_for_embedded_frame = is_for_embedded_frame;
  settings.is_for_scalable_page = is_for_scalable_page;

  settings.main_frame_before_activation_enabled =
      cmd.HasSwitch(::switches::kEnableMainFrameBeforeActivation);

  // Checkerimaging is not supported for synchronous single-threaded mode, which
  // is what the renderer uses if its not threaded.
  settings.enable_checker_imaging =
      !cmd.HasSwitch(::switches::kDisableCheckerImaging) && is_threaded;

#if BUILDFLAG(IS_ANDROID)
  // WebView should always raster in the default color space.
  // Synchronous compositing indicates WebView.
  if (!platform->IsSynchronousCompositingEnabledForAndroidWebView())
    settings.prefer_raster_in_srgb = ::features::IsDynamicColorGamutEnabled();

  // We can use a more aggressive limit on Android since decodes tend to take
  // longer on these devices.
  settings.min_image_bytes_to_checker = 512 * 1024;  // 512kB

  // Re-rasterization of checker-imaged content with software raster can be too
  // costly on Android.
  settings.only_checker_images_with_gpu_raster = true;
#endif

  auto switch_value_as_int = [](const base::CommandLine& command_line,
                                const std::string& switch_string, int min_value,
                                int max_value, int* result) {
    std::string string_value = command_line.GetSwitchValueASCII(switch_string);
    int int_value;
    if (base::StringToInt(string_value, &int_value) && int_value >= min_value &&
        int_value <= max_value) {
      *result = int_value;
      return true;
    } else {
      DLOG(WARNING) << "Failed to parse switch " << switch_string << ": "
                    << string_value;
      return false;
    }
  };

  int default_tile_size = 256;
#if BUILDFLAG(IS_ANDROID)
  const gfx::Size screen_size =
      gfx::ScaleToFlooredSize(initial_screen_size, initial_device_scale_factor);
  int display_width = screen_size.width();
  int display_height = screen_size.height();
  int numTiles = (display_width * display_height) / (256 * 256);
  if (numTiles > 16)
    default_tile_size = 384;
  if (numTiles >= 40)
    default_tile_size = 512;

  // Adjust for some resolutions that barely straddle an extra
  // tile when in portrait mode. This helps worst case scroll/raster
  // by not needing a full extra tile for each row.
  constexpr int tolerance = 10;  // To avoid rounding errors.
  int portrait_width = std::min(display_width, display_height);
  if (default_tile_size == 256 && std::abs(portrait_width - 768) < tolerance)
    default_tile_size += 32;
  if (default_tile_size == 384 && std::abs(portrait_width - 1200) < tolerance)
    default_tile_size += 32;
#elif BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_MAC)
  // Use 512 for high DPI (dsf=2.0f) devices.
  if (initial_device_scale_factor >= 2.0f)
    default_tile_size = 512;
#endif

  // TODO(danakj): This should not be a setting O_O; it should change when the
  // device scale factor on LayerTreeHost changes.
  settings.default_tile_size = gfx::Size(default_tile_size, default_tile_size);
  if (cmd.HasSwitch(switches::kDefaultTileWidth)) {
    int tile_width = 0;
    switch_value_as_int(cmd, switches::kDefaultTileWidth, 1,
                        std::numeric_limits<int>::max(), &tile_width);
    settings.default_tile_size.set_width(tile_width);
  }
  if (cmd.HasSwitch(switches::kDefaultTileHeight)) {
    int tile_height = 0;
    switch_value_as_int(cmd, switches::kDefaultTileHeight, 1,
                        std::numeric_limits<int>::max(), &tile_height);
    settings.default_tile_size.set_height(tile_height);
  }

  if (cmd.HasSwitch(switches::kMinHeightForGpuRasterTile)) {
    int min_height_for_gpu_raster_tile = 0;
    switch_value_as_int(cmd, switches::kMinHeightForGpuRasterTile, 1,
                        std::numeric_limits<int>::max(),
                        &min_height_for_gpu_raster_tile);
    settings.min_height_for_gpu_raster_tile = min_height_for_gpu_raster_tile;
  }

  int max_untiled_layer_width = settings.max_untiled_layer_size.width();
  if (cmd.HasSwitch(switches::kMaxUntiledLayerWidth)) {
    switch_value_as_int(cmd, switches::kMaxUntiledLayerWidth, 1,
                        std::numeric_limits<int>::max(),
                        &max_untiled_layer_width);
  }
  int max_untiled_layer_height = settings.max_untiled_layer_size.height();
  if (cmd.HasSwitch(switches::kMaxUntiledLayerHeight)) {
    switch_value_as_int(cmd, switches::kMaxUntiledLayerHeight, 1,
                        std::numeric_limits<int>::max(),
                        &max_untiled_layer_height);
  }

  settings.max_untiled_layer_size =
      gfx::Size(max_untiled_layer_width, max_untiled_layer_height);

  int gpu_rasterization_msaa_sample_count = -1;
  if (cmd.HasSwitch(switches::kGpuRasterizationMSAASampleCount)) {
    std::string string_value =
        cmd.GetSwitchValueASCII(switches::kGpuRasterizationMSAASampleCount);
    bool parsed_msaa_sample_count =
        base::StringToInt(string_value, &gpu_rasterization_msaa_sample_count);
    DCHECK(parsed_msaa_sample_count) << string_value;
    DCHECK_GE(gpu_rasterization_msaa_sample_count, 0);
  }
  settings.gpu_rasterization_msaa_sample_count =
      gpu_rasterization_msaa_sample_count;

  settings.can_use_lcd_text = platform->IsLcdTextEnabled();
  settings.use_zero_copy = cmd.HasSwitch(switches::kEnableZeroCopy);
  settings.use_partial_raster = !cmd.HasSwitch(switches::kDisablePartialRaster);
  // Partial raster is not supported with RawDraw
  settings.use_partial_raster &= !::features::IsUsingRawDraw();
  settings.enable_elastic_overscroll = platform->IsElasticOverscrollEnabled();
  settings.use_gpu_memory_buffer_resources =
      cmd.HasSwitch(switches::kEnableGpuMemoryBufferCompositorResources);
  settings.use_painted_device_scale_factor = true;

  // Build LayerTreeSettings from command line args.
  if (cmd.HasSwitch(::switches::kBrowserControlsShowThreshold)) {
    std::string top_threshold_str =
        cmd.GetSwitchValueASCII(::switches::kBrowserControlsShowThreshold);
    double show_threshold;
    if (base::StringToDouble(top_threshold_str, &show_threshold) &&
        show_threshold >= 0.f && show_threshold <= 1.f)
      settings.top_controls_show_threshold = show_threshold;
  }

  if (cmd.HasSwitch(::switches::kBrowserControlsHideThreshold)) {
    std::string top_threshold_str =
        cmd.GetSwitchValueASCII(::switches::kBrowserControlsHideThreshold);
    double hide_threshold;
    if (base::StringToDouble(top_threshold_str, &hide_threshold) &&
        hide_threshold >= 0.f && hide_threshold <= 1.f)
      settings.top_controls_hide_threshold = hide_threshold;
  }

  // Blink sends cc a layer list and property trees.
  settings.use_layer_lists = true;

  // Blink currently doesn't support setting fractional scroll offsets so CC
  // must send integer values. We plan to eventually make Blink use fractional
  // offsets internally: https://crbug.com/414283.
  settings.commit_fractional_scroll_deltas =
      RuntimeEnabledFeatures::FractionalScrollOffsetsEnabled();

  settings.enable_smooth_scroll = platform->IsScrollAnimatorEnabled();

  // The means the renderer compositor has 2 possible modes:
  // - Threaded compositing with a scheduler.
  // - Single threaded compositing without a scheduler (for web tests only).
  // Using the scheduler in web tests introduces additional composite steps
  // that create flakiness.
  settings.single_thread_proxy_scheduler = false;

  // These flags should be mirrored by UI versions in ui/compositor/.
  if (cmd.HasSwitch(::switches::kShowCompositedLayerBorders)) {
    settings.initial_debug_state.show_debug_borders.set();
  }
  settings.initial_debug_state.show_fps_counter =
      cmd.HasSwitch(::switches::kShowFPSCounter);
  settings.initial_debug_state.show_layer_animation_bounds_rects =
      cmd.HasSwitch(::switches::kShowLayerAnimationBounds);
  settings.initial_debug_state.show_paint_rects =
      cmd.HasSwitch(switches::kShowPaintRects);
  settings.initial_debug_state.show_layout_shift_regions =
      cmd.HasSwitch(switches::kShowLayoutShiftRegions);
  settings.initial_debug_state.show_property_changed_rects =
      cmd.HasSwitch(::switches::kShowPropertyChangedRects);
  settings.initial_debug_state.show_surface_damage_rects =
      cmd.HasSwitch(::switches::kShowSurfaceDamageRects);
  settings.initial_debug_state.show_screen_space_rects =
      cmd.HasSwitch(::switches::kShowScreenSpaceRects);
  settings.initial_debug_state.highlight_non_lcd_text_layers =
      cmd.HasSwitch(::switches::kHighlightNonLCDTextLayers);

  settings.initial_debug_state.SetRecordRenderingStats(
      cmd.HasSwitch(::switches::kEnableGpuBenchmarking));

  if (cmd.HasSwitch(::switches::kSlowDownRasterScaleFactor)) {
    const int kMinSlowDownScaleFactor = 0;
    const int kMaxSlowDownScaleFactor = INT_MAX;
    switch_value_as_int(
        cmd, ::switches::kSlowDownRasterScaleFactor, kMinSlowDownScaleFactor,
        kMaxSlowDownScaleFactor,
        &settings.initial_debug_state.slow_down_raster_scale_factor);
  }

  settings.scrollbar_animator = cc::LayerTreeSettings::ANDROID_OVERLAY;

  InitializeScrollbarFadeAndDelay(settings);

  if (cmd.HasSwitch(::switches::kCCScrollAnimationDurationForTesting)) {
    const int kMinScrollAnimationDuration = 0;
    const int kMaxScrollAnimationDuration = INT_MAX;
    int duration;
    if (switch_value_as_int(cmd,
                            ::switches::kCCScrollAnimationDurationForTesting,
                            kMinScrollAnimationDuration,
                            kMaxScrollAnimationDuration, &duration)) {
      settings.scroll_animation_duration_for_testing = base::Seconds(duration);
    }
  }

#if BUILDFLAG(IS_ANDROID)
  // Synchronous compositing is used only for the outermost main frame.
  bool use_synchronous_compositor =
      platform->IsSynchronousCompositingEnabledForAndroidWebView() &&
      !is_for_embedded_frame;
  // Do not use low memory policies for Android WebView.
  bool using_low_memory_policy =
      base::SysInfo::IsLowEndDevice() && !IsSmallScreen(screen_size) &&
      !platform->IsSynchronousCompositingEnabledForAndroidWebView();

  settings.use_stream_video_draw_quad = true;
  settings.using_synchronous_renderer_compositor = use_synchronous_compositor;
  if (use_synchronous_compositor) {
    // Root frame in Android WebView uses system scrollbars, so make ours
    // invisible. http://crbug.com/677348: This can't be done using
    // hide_scrollbars setting because supporting -webkit custom scrollbars is
    // still desired on sublayers.
    settings.scrollbar_animator = cc::LayerTreeSettings::NO_ANIMATOR;
    // Rendering of scrollbars will be disabled in cc::SolidColorScrollbarLayer.

    // Early damage check works in combination with synchronous compositor.
    settings.enable_early_damage_check =
        cmd.HasSwitch(::switches::kCheckDamageEarly);
  }
  if (using_low_memory_policy) {
    // On low-end we want to be very careful about killing other
    // apps. So initially we use 50% more memory to avoid flickering
    // or raster-on-demand.
    settings.max_memory_for_prepaint_percentage = 67;
  } else {
    // On other devices we have increased memory excessively to avoid
    // raster-on-demand already, so now we reserve 50% _only_ to avoid
    // raster-on-demand, and use 50% of the memory otherwise.
    settings.max_memory_for_prepaint_percentage = 50;
  }

  // TODO(danakj): Only do this on low end devices.
  settings.create_low_res_tiling = true;

#else   // BUILDFLAG(IS_ANDROID)
  const bool using_low_memory_policy = base::SysInfo::IsLowEndDevice();

  settings.enable_fluent_scrollbar = ui::IsFluentScrollbarEnabled();
  settings.enable_fluent_overlay_scrollbar =
      ui::IsFluentOverlayScrollbarEnabled();

  if (ui::IsOverlayScrollbarEnabled()) {
    settings.scrollbar_animator = cc::LayerTreeSettings::AURA_OVERLAY;
    settings.scrollbar_thinning_duration =
        ui::kOverlayScrollbarThinningDuration;
    settings.scrollbar_flash_after_any_scroll_update =
        !settings.enable_fluent_overlay_scrollbar;
    // Avoid animating in web tests to improve reliability.
    if (settings.enable_fluent_overlay_scrollbar) {
      settings.scrollbar_thinning_duration =
          ui::kFluentOverlayScrollbarThinningDuration;
      if (WebTestSupport::IsRunningWebTest()) {
        settings.scrollbar_thinning_duration = base::Milliseconds(0);
        settings.scrollbar_fade_delay = base::Milliseconds(0);
        settings.scrollbar_fade_duration = base::Milliseconds(0);
      }
    }
  }
#endif  // BUILDFLAG(IS_ANDROID)

  settings.decoded_image_working_set_budget_bytes =
      cc::ImageDecodeCacheUtils::GetWorkingSetBytesForImageDecode(
          /*for_renderer=*/true);

  if (using_low_memory_policy) {
    // RGBA_4444 textures are only enabled:
    //  - If the user hasn't explicitly disabled them
    //  - If system ram is <= 512MB (1GB devices are sometimes low-end).
    //  - If we are not running in a WebView, where 4444 isn't supported.
    //  - If we are not using vulkan, since some GPU drivers don't support
    //    using RGBA4444 as color buffer.
    // TODO(penghuang): query supported formats from GPU process.
    if (!cmd.HasSwitch(switches::kDisableRGBA4444Textures) &&
        base::SysInfo::AmountOfPhysicalMemoryMB() <= 512 &&
        !::features::IsUsingVulkan()) {
      settings.use_rgba_4444 = true;

      // If we are going to unpremultiply and dither these tiles, we need to
      // allocate an additional RGBA_8888 intermediate for each tile
      // rasterization when rastering to RGBA_4444 to allow for dithering.
      // Setting a reasonable sized max tile size allows this intermediate to
      // be consistently reused.
      if (base::FeatureList::IsEnabled(
              kUnpremultiplyAndDitherLowBitDepthTiles)) {
        settings.max_gpu_raster_tile_size = gfx::Size(512, 256);
        settings.unpremultiply_and_dither_low_bit_depth_tiles = true;
      }
    }
  }

  if (cmd.HasSwitch(switches::kEnableLowResTiling))
    settings.create_low_res_tiling = true;
  if (cmd.HasSwitch(switches::kDisableLowResTiling))
    settings.create_low_res_tiling = false;

  if (cmd.HasSwitch(switches::kEnableRGBA4444Textures) &&
      !cmd.HasSwitch(switches::kDisableRGBA4444Textures)) {
    settings.use_rgba_4444 = true;
  }

  settings.max_staging_buffer_usage_in_bytes = 32 * 1024 * 1024;  // 32MB
  // Use 1/4th of staging buffers on low-end devices.
  if (base::SysInfo::IsLowEndDevice())
    settings.max_staging_buffer_usage_in_bytes /= 4;

  cc::ManagedMemoryPolicy defaults = settings.memory_policy;
  settings.memory_policy = GetGpuMemoryPolicy(defaults, initial_screen_size,
                                              initial_device_scale_factor);

  settings.disallow_non_exact_resource_reuse =
      cmd.HasSwitch(::switches::kDisallowNonExactResourceReuse);
#if BUILDFLAG(IS_ANDROID)
  // TODO(crbug.com/746931): This feature appears to be causing visual
  // corruption on certain android devices. Will investigate and re-enable.
  settings.disallow_non_exact_resource_reuse = true;
#endif

  settings.wait_for_all_pipeline_stages_before_draw =
      cmd.HasSwitch(::switches::kRunAllCompositorStagesBeforeDraw);

  settings.enable_image_animation_resync =
      !cmd.HasSwitch(switches::kDisableImageAnimationResync);

  settings.enable_backface_visibility_interop =
      RuntimeEnabledFeatures::BackfaceVisibilityInteropEnabled();

  settings.disable_frame_rate_limit =
      cmd.HasSwitch(::switches::kDisableFrameRateLimit);

  settings.enable_hit_test_opaqueness =
      RuntimeEnabledFeatures::HitTestOpaquenessEnabled();

  settings.enable_variable_refresh_rate =
      ::features::IsVariableRefreshRateAlwaysOn();

  std::tie(settings.tiling_interest_area_padding,
           settings.skewport_extrapolation_limit_in_screen_pixels) =
      GetTilingInterestAreaSizes();
  return settings;
}

}  // namespace blink
```