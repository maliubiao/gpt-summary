Response:
Let's break down the thought process to arrive at the explanation of `lcp_critical_path_predictor.cc`.

1. **Understand the Core Purpose from the Filename and Initial Code:**

   * The name `lcp_critical_path_predictor.cc` immediately suggests its function: predicting the critical path for the Largest Contentful Paint (LCP). This hints at performance optimization.
   * The `#include` statements confirm this. We see references to:
      * `base/metrics/histogram_functions.h`:  Indicating data collection for analysis.
      * `third_party/blink/public/common/features.h`:  Signaling feature flags to control behavior.
      * `third_party/blink/public/common/loader/lcp_critical_path_predictor_util.h`:  Suggesting shared utilities for LCP prediction.
      * Frame-related headers (`LocalDomWindow.h`, `LocalFrame.h`).
      * HTML elements (`html_image_element.h`).
      * Element location (`element_locator.h`).
      * Loader components (`document_loader.h`, `resource_fetcher.h`).

2. **Identify Key Data Members:**

   * Scanning the class definition reveals important member variables:
      * `lcp_element_locators_`, `lcp_element_locator_strings_`:  Storing potential LCP element locations as hints.
      * `lcp_influencer_scripts_`:  Tracking scripts that might influence LCP.
      * `preconnected_origins_`:  Hints for origins to preconnect to improve LCP.
      * `unused_preloads_`:  Information about preloads that weren't used.
      * `lcp_predicted_callbacks_`:  Callbacks to execute when LCP is predicted.
      * `has_lcp_occurred_`, `is_outermost_main_frame_document_loaded_`, `has_sent_unused_preloads_`:  State flags to manage the prediction process.

3. **Analyze Key Methods and their Functionality:**

   * **Setters (`set_lcp_element_locators`, `set_lcp_influencer_scripts`, etc.):** These methods are for receiving prediction hints from external sources (likely the browser process). The parsing logic in `set_lcp_element_locators` is important.
   * **`HasAnyHintData()`:**  A simple check to see if any prediction data has been received.
   * **`Reset()`:**  Clears all prediction data and state.
   * **`AddLCPPredictedCallback()`:** Allows registering functions to be called when an LCP element is predicted. The logic to handle cases where callbacks are added after prediction is important.
   * **`MayRunPredictedCallbacks()`:** Executes the registered callbacks.
   * **`IsElementMatchingLocator()`:**  Checks if a given element matches a predicted LCP element based on its locator.
   * **`OnLargestContentfulPaintUpdated()`:** The core logic triggered when the browser identifies an LCP element. This is where predictions are compared to reality and data is sent to the browser process. Pay attention to the feature flag checks (`kLCPCriticalPathPredictor`, etc.) and the recording of LCP element locators and influencer scripts. The preconnect logic is also here.
   * **`OnFontFetched()`:**  Tracks fetched fonts, potentially for later analysis or prediction.
   * **`OnStartPreload()`:**  Records information about preloaded resources.
   * **`GetHost()`:**  Manages the communication channel to the browser process.
   * **`IsLcpInfluencerScript()`:**  A simple check for whether a script is considered an LCP influencer.
   * **`OnOutermostMainFrameDocumentLoad()`:**  Handles the event when the main document is loaded. This is a fallback point for triggering callbacks if LCP hasn't occurred earlier.
   * **`OnWarnedUnusedPreloads()`:**  Handles notifications about unused preloads.

4. **Identify Relationships with Web Technologies (JavaScript, HTML, CSS):**

   * **HTML:** The code directly interacts with HTML elements (`HTMLImageElement`). The LCP is a metric tied to the rendering of HTML content. The `ElementLocator` mechanism relies on the structure of the HTML DOM.
   * **CSS:** While not explicitly manipulating CSS properties, the LCP is influenced by CSS (e.g., styling that delays rendering). The prediction of LCP elements might implicitly consider CSS.
   * **JavaScript:** The code tracks "influencer scripts," suggesting JavaScript plays a role in determining the LCP element. Scripts can dynamically modify the DOM and load resources, thus impacting LCP.

5. **Consider Logic and Assumptions:**

   * **Assumption:** The code assumes that the browser process can provide valuable hints about potential LCP elements, influencer scripts, and important origins.
   * **Logic:** The prediction mechanism is based on matching element locators. This implies a prior analysis or historical data is used to generate these locators. The timing predictor relies on the idea that knowing the LCP element in advance allows for optimizations.

6. **Think about User/Developer Errors:**

   * **Corrupted Hints:** The code explicitly handles the case of invalid `lcp_element_locator` hints, indicating this is a potential issue.
   * **Incorrect Predictions:** The code has mechanisms to measure the accuracy of its predictions (e.g., tracking prediction matches for preconnects). Incorrect predictions could lead to wasted resources or missed optimization opportunities.

7. **Trace User Actions Leading to the Code:**

   * Start with a user navigating to a webpage.
   * The browser process might have historical data or heuristics to generate LCP prediction hints.
   * These hints are passed to the renderer process and stored in the `LCPCriticalPathPredictor`.
   * As the page loads, the `OnLargestContentfulPaintUpdated` method is called when the browser identifies an LCP element.
   * The code then compares the actual LCP element with the predictions and takes actions (e.g., triggers callbacks, sends data back to the browser process).

8. **Structure the Explanation:**

   Organize the findings into logical sections: Core Functionality, Relationships, Logic and Assumptions, User Errors, Debugging, and then provide concrete examples for each relationship.

9. **Refine and Clarify:**

   Review the explanation for clarity and accuracy. Ensure that the examples are easy to understand and that the connection between the code and web technologies is clearly articulated. For instance, initially, I might have just said "It relates to HTML elements," but refining it to explain *how* it relates through `ElementLocator` and the LCP metric itself is crucial.

By following this thought process, systematically examining the code, and connecting it to the broader context of web development and browser behavior, a comprehensive and accurate explanation can be constructed.
这个 `lcp_critical_path_predictor.cc` 文件是 Chromium Blink 渲染引擎中负责**预测 Largest Contentful Paint (LCP) 的关键路径**的组件。它的主要功能是尝试在页面加载早期识别出可能成为 LCP 元素的元素，并据此向浏览器发出提示，以便浏览器可以优化资源加载顺序，从而加速 LCP 的渲染。

下面详细列举它的功能以及与 JavaScript、HTML、CSS 的关系：

**主要功能：**

1. **接收和存储 LCP 预测提示数据：**
   - 从浏览器进程接收关于可能成为 LCP 元素的定位器 (`lcp_element_locators_`)。这些定位器通常是基于历史数据或启发式方法生成的。
   - 接收可能影响 LCP 的脚本的 URL (`lcp_influencer_scripts_`).
   - 接收已获取的字体 URL (`fetched_fonts_`).
   - 接收建议预连接的源 (`preconnected_origins_`).
   - 接收未使用的预加载资源 URL (`unused_preloads_`).

2. **解析和处理 LCP 元素定位器：**
   - 将接收到的字符串形式的元素定位器解析为 `ElementLocator` 对象，方便后续的匹配。
   - 存储原始的定位器字符串，用于后续与实际 LCP 元素的定位器进行比较。

3. **管理 LCP 预测回调：**
   - 允许注册回调函数 (`lcp_predicted_callbacks_`)，这些回调函数在预测到 LCP 元素时会被执行。这主要用于在页面加载早期执行一些优化操作，例如启动对预测到的 LCP 资源的预加载。

4. **判断元素是否匹配预测的 LCP 元素：**
   - 提供 `IsElementMatchingLocator()` 方法，用于判断给定的 HTML 元素是否与存储的任何预测 LCP 元素定位器相匹配。

5. **监听和处理 LCP 事件：**
   - 监听 `LargestContentfulPaintUpdated` 事件，当浏览器确定了实际的 LCP 元素时，该方法会被调用。
   - 在此方法中，它会比较实际的 LCP 元素的定位器与预测的定位器，以评估预测的准确性。
   - 如果实际的 LCP 元素与预测的元素匹配，则执行之前注册的回调函数。
   - 它还会记录实际 LCP 元素的定位器信息，并发送给浏览器进程，用于未来的预测改进。

6. **处理预连接提示：**
   - 当实际的 LCP 元素是一个跨域图片时，它会向浏览器进程发送预连接该图片源的提示。
   - 它还会记录预测的预连接与实际 LCP 图片源的匹配情况。

7. **识别 LCP 影响脚本：**
   - 当实际的 LCP 元素是图片时，它会记录创建该图片的脚本 URL，并与预测的 LCP 影响脚本进行比较，评估预测的准确性。

8. **记录已获取的字体：**
   - 记录已获取的字体 URL，并通知浏览器进程，用于字体加载优化。

9. **记录预加载信息：**
   - 记录页面发起的预加载请求，并将相关信息发送给浏览器进程，用于预加载策略的优化。

10. **处理文档加载完成事件：**
    - 监听最外层主文档的加载完成事件，如果此时 LCP 尚未发生，则执行预测回调作为一种回退机制。

11. **处理未使用预加载的警告：**
    - 接收关于未使用预加载的警告，并将这些信息发送给浏览器进程，用于优化预加载策略。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:**
    - 该组件的核心任务是预测 HTML 元素，即 LCP 元素。
    - `ElementLocator` 用于描述 HTML 元素在 DOM 树中的位置和属性，因此与 HTML 的结构紧密相关。
    - `OnLargestContentfulPaintUpdated` 方法接收的 `lcp_element` 参数就是一个 HTML 元素。
    - **例子：** 假设预测的 LCP 元素是一个 `<img>` 标签，其定位器可能包含其父元素的 ID 和自身的类名。如果实际的 LCP 元素与这个定位器匹配，说明预测成功。

* **CSS:**
    - 虽然该组件不直接操作 CSS，但 CSS 的加载和解析会影响 LCP 的渲染时间。
    - 预测 LCP 元素有助于浏览器优先加载与该元素相关的 CSS 样式。
    - **例子：** 如果预测到某个 `<div>` 是 LCP 元素，浏览器可能会优先加载包含该 `<div>` 样式规则的 CSS 文件。

* **JavaScript:**
    - JavaScript 可能会动态地创建、修改或加载影响 LCP 的元素。
    - `lcp_influencer_scripts_` 存储了被认为可能影响 LCP 的 JavaScript 脚本的 URL。这些脚本可能负责动态插入 LCP 元素或加载其资源。
    - `OnLargestContentfulPaintUpdated` 方法会尝试识别创建 LCP 图片元素的 JavaScript 脚本。
    - **例子：** 假设一个 JavaScript 脚本在页面加载后动态地创建并插入了一个大的 `<img>` 标签作为 LCP 元素。该组件可能会预测到这个脚本，以便浏览器可以提前开始加载它或它所依赖的资源。

**逻辑推理的假设输入与输出：**

**假设输入：**

1. **预测的 LCP 元素定位器：** `{"tag_name": "IMG", "attributes": {"id": "main-image"}}`
2. **预测的 LCP 影响脚本：** `https://example.com/js/load_image.js`
3. **实际发生的 LCP 元素：** 一个 ID 为 "main-image" 的 `<img>` 标签。
4. **创建该 LCP 元素的脚本 URL：** `https://example.com/js/load_image.js`

**输出：**

1. `IsElementMatchingLocator()` 方法针对该实际 LCP 元素返回 `true`。
2. `OnLargestContentfulPaintUpdated()` 方法会识别到预测成功。
3. 可能会执行预先注册的 LCP 预测回调。
4. 会记录 `https://example.com/js/load_image.js` 为 LCP 影响脚本，并与预测的脚本匹配。

**用户或编程常见的使用错误：**

1. **预测数据不准确或过时：** 如果浏览器进程提供的预测数据与实际页面结构和加载行为不符，会导致预测失败，甚至可能产生负面影响。
    - **例子：** 预测了一个不存在的元素 ID 或类名作为 LCP 元素，导致浏览器浪费资源去寻找它。
2. **修改了 ElementLocator 的 schema 但没有更新浏览器进程的预测逻辑：** 这会导致 `ParseFromString` 失败，从而忽略预测提示。
    - **例子：**  如果 `ElementLocator` 的结构发生了变化，而浏览器进程仍然发送旧格式的定位器字符串，解析就会失败，预测功能失效。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **用户在浏览器地址栏输入网址或点击链接，发起页面加载。**
2. **浏览器进程（Browser Process）根据历史数据、启发式规则或服务器提示，生成 LCP 预测数据（包括元素定位器、影响脚本 URL 等）。**
3. **浏览器进程将这些预测数据通过 IPC 发送给渲染器进程（Renderer Process）。**
4. **渲染器进程的 `LCPCriticalPathPredictor` 对象接收到这些数据，并存储起来。**
5. **渲染器进程开始解析 HTML，构建 DOM 树。**
6. **当构建 DOM 树时，`LCPCriticalPathPredictor` 可能会调用 `IsElementMatchingLocator()` 来判断当前解析的元素是否与预测的 LCP 元素匹配。**
7. **当浏览器引擎确定了 Largest Contentful Paint 元素后，会触发 `LargestContentfulPaintUpdated` 事件。**
8. **`LCPCriticalPathPredictor::OnLargestContentfulPaintUpdated()` 方法被调用，接收实际的 LCP 元素信息。**
9. **在该方法中，会进行实际 LCP 元素与预测信息的对比，记录统计数据，并可能执行预先注册的回调函数。**
10. **如果启用了 LCP 影响脚本的跟踪，并且实际的 LCP 元素是图片，则会尝试获取创建该图片的 JavaScript 脚本的 URL。**
11. **如果启用了预连接优化，并且 LCP 元素是跨域资源，则会向浏览器进程发送预连接提示。**

通过分析这些步骤，开发者可以了解 LCP 预测的整个流程，从而更容易定位问题，例如：

* **为什么预测不准确？** 可能是浏览器进程提供的预测数据有问题，或者页面的结构与历史数据差异较大。
* **为什么预连接没有生效？** 可能是预测的 LCP 元素不正确，或者实际的 LCP 元素不是跨域资源。
* **为什么 LCP 预测回调没有执行？** 可能是预测失败，或者回调函数注册的时机不对。

总而言之，`lcp_critical_path_predictor.cc` 是 Blink 引擎中一个关键的性能优化组件，它通过预测 LCP 元素来指导浏览器的资源加载策略，从而提升用户体验。它与 HTML 结构、CSS 加载和 JavaScript 的执行都有着密切的联系。

Prompt: 
```
这是目录为blink/renderer/core/lcp_critical_path_predictor/lcp_critical_path_predictor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/lcp_critical_path_predictor/lcp_critical_path_predictor.h"

#include "base/metrics/histogram_functions.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/loader/lcp_critical_path_predictor_util.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/lcp_critical_path_predictor/element_locator.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"

namespace blink {

namespace {

size_t GetLCPPFontURLPredictorMaxUrlLength() {
  return features::kLCPPFontURLPredictorMaxUrlLength.Get();
}

bool IsTimingPredictorEnabled() {
  if (base::FeatureList::IsEnabled(
          blink::features::kLCPTimingPredictorPrerender2)) {
    return true;
  }
  if (base::FeatureList::IsEnabled(blink::features::kLCPPDeferUnusedPreload)) {
    switch (features::kLcppDeferUnusedPreloadTiming.Get()) {
      case features::LcppDeferUnusedPreloadTiming::kPostTask:
        return false;
      case features::LcppDeferUnusedPreloadTiming::kLcpTimingPredictor:
      case features::LcppDeferUnusedPreloadTiming::
          kLcpTimingPredictorWithPostTask:
        return true;
    }
  }

  return false;
}

}  // namespace

LCPCriticalPathPredictor::LCPCriticalPathPredictor(LocalFrame& frame)
    : frame_(&frame),
      host_(frame.DomWindow()),
      task_runner_(frame.GetTaskRunner(TaskType::kInternalLoading)) {
  CHECK(LcppEnabled());
}

LCPCriticalPathPredictor::~LCPCriticalPathPredictor() = default;

bool LCPCriticalPathPredictor::HasAnyHintData() const {
  return !lcp_element_locators_.empty() || !lcp_influencer_scripts_.empty() ||
         !preconnected_origins_.empty();
}

void LCPCriticalPathPredictor::set_lcp_element_locators(
    const std::vector<std::string>& lcp_element_locator_strings) {
  // Clear current set of locators before receiving replacements.
  lcp_element_locators_.clear();
  lcp_element_locator_strings_.clear();
  const wtf_size_t reserved_size =
      base::checked_cast<wtf_size_t>(lcp_element_locator_strings.size());
  lcp_element_locators_.reserve(reserved_size);
  lcp_element_locator_strings_.reserve(reserved_size);
  for (const std::string& serialized_locator : lcp_element_locator_strings) {
    lcp_element_locators_.push_back(ElementLocator());
    bool result =
        lcp_element_locators_.back().ParseFromString(serialized_locator);
    if (!result) {
      // This can happen when the host LCPP database is corrupted or we
      // updated the ElementLocator schema in an incompatible way.
      LOG(INFO) << "Ignoring an invalid lcp_element_locator hint.";
      lcp_element_locators_.pop_back();
    } else {
      lcp_element_locator_strings_.push_back(std::move(serialized_locator));
    }
  }
  CHECK_EQ(lcp_element_locators_.size(), lcp_element_locator_strings_.size());
}

void LCPCriticalPathPredictor::set_lcp_influencer_scripts(
    HashSet<KURL> scripts) {
  lcp_influencer_scripts_ = std::move(scripts);
}

void LCPCriticalPathPredictor::set_fetched_fonts(Vector<KURL> fonts) {
  fetched_fonts_ = std::move(fonts);
}

void LCPCriticalPathPredictor::set_preconnected_origins(
    const Vector<url::Origin>& origins) {
  preconnected_origins_ = std::move(origins);
}

void LCPCriticalPathPredictor::set_unused_preloads(Vector<KURL> preloads) {
  unused_preloads_ = std::move(preloads);
}

void LCPCriticalPathPredictor::Reset() {
  lcp_element_locators_.clear();
  lcp_element_locator_strings_.clear();
  lcp_influencer_scripts_.clear();
  fetched_fonts_.clear();
  preconnected_origins_.clear();
  unused_preloads_.clear();

  lcp_predicted_callbacks_.clear();
  are_predicted_callbacks_called_ = false;
  has_lcp_occurred_ = false;
  is_outermost_main_frame_document_loaded_ = false;
  has_sent_unused_preloads_ = false;
}

void LCPCriticalPathPredictor::AddLCPPredictedCallback(LCPCallback callback) {
  CHECK(IsTimingPredictorEnabled());
  if (are_predicted_callbacks_called_) {
    std::move(callback).Run(/*lcp_element=*/nullptr);
    return;
  }
  lcp_predicted_callbacks_.push_back(std::move(callback));
}

void LCPCriticalPathPredictor::AddLCPPredictedCallback(
    base::OnceClosure callback) {
  LCPCallback lcp_callback =
      WTF::BindOnce([](base::OnceClosure callback,
                       const Element*) { std::move(callback).Run(); },
                    std::move(callback));
  AddLCPPredictedCallback(std::move(lcp_callback));
}

void LCPCriticalPathPredictor::MayRunPredictedCallbacks(
    const Element* lcp_element) {
  if (are_predicted_callbacks_called_) {
    return;
  }
  are_predicted_callbacks_called_ = true;
  // TODO(crbug.com/1493255): Trigger callbacks for the entire frame tree.
  Vector<LCPCallback> callbacks;
  callbacks.swap(lcp_predicted_callbacks_);
  for (auto& callback : callbacks) {
    std::move(callback).Run(lcp_element);
  }
}

bool LCPCriticalPathPredictor::IsElementMatchingLocator(
    const Element& element) {
  std::string lcp_element_locator_string =
      element_locator::OfElement(element).SerializeAsString();
  return lcp_element_locator_strings_.Contains(lcp_element_locator_string);
}

void LCPCriticalPathPredictor::OnLargestContentfulPaintUpdated(
    const Element& lcp_element,
    std::optional<const KURL> maybe_image_url) {
  if (base::FeatureList::IsEnabled(features::kLCPCriticalPathPredictor) ||
      base::FeatureList::IsEnabled(features::kLCPPLazyLoadImagePreload) ||
      IsTimingPredictorEnabled()) {
    std::string lcp_element_locator_string =
        element_locator::OfElement(lcp_element).SerializeAsString();

    has_lcp_occurred_ = true;
    // Regard `lcp_element` is the candidate if its locator is found in
    // set_lcp_element_locators(lcp_element_locator_strings).
    // See PredictLcpElementLocators() for the contents detail.
    const wtf_size_t predicted_lcp_index =
        lcp_element_locator_strings_.Find(lcp_element_locator_string);
    if (predicted_lcp_index != kNotFound) {
      MayRunPredictedCallbacks(&lcp_element);
    }
    if (is_outermost_main_frame_document_loaded_) {
      // Call callbacks as fallback regardless of prediction because
      // This LCP is much too late.
      MayRunPredictedCallbacks(nullptr);
    }

    features::LcppRecordedLcpElementTypes recordable_lcp_element_type =
        features::kLCPCriticalPathPredictorRecordedLcpElementTypes.Get();
    bool should_record_element_locator =
        (recordable_lcp_element_type ==
         features::LcppRecordedLcpElementTypes::kAll) ||
        (recordable_lcp_element_type ==
             features::LcppRecordedLcpElementTypes::kImageOnly &&
         IsA<HTMLImageElement>(lcp_element));

    if (should_record_element_locator) {
      base::UmaHistogramCounts10000(
          "Blink.LCPP.LCPElementLocatorSize",
          base::checked_cast<int>(lcp_element_locator_string.size()));

      if (lcp_element_locator_string.size() <=
          features::kLCPCriticalPathPredictorMaxElementLocatorLength.Get()) {
        GetHost().SetLcpElementLocator(
            lcp_element_locator_string,
            predicted_lcp_index == kNotFound
                ? std::nullopt
                : std::optional<wtf_size_t>(predicted_lcp_index));
      }
    }
  }

  if (base::FeatureList::IsEnabled(features::kLCPPAutoPreconnectLcpOrigin)) {
    auto root_origin =
        url::Origin::Create((GURL)lcp_element.GetDocument().Url());
    if (maybe_image_url.has_value()) {
      const KURL& lcp_image_url = *maybe_image_url;
      if (!lcp_image_url.IsEmpty() && lcp_image_url.IsValid() &&
          lcp_image_url.ProtocolIsInHTTPFamily()) {
        auto lcp_origin = url::Origin::Create((GURL)lcp_image_url);
        bool is_lcp_cross_origin = !lcp_origin.IsSameOriginWith(root_origin);
        base::UmaHistogramBoolean("Blink.LCPP.CrossOriginLcpImage",
                                  is_lcp_cross_origin);
        if (is_lcp_cross_origin) {
          GetHost().SetPreconnectOrigins({(KURL)lcp_origin.GetURL()});
        }

        // Calculate accuracy against predicted.
        int count_prediction_matches = 0;
        for (const auto& predicted_origin : preconnected_origins_) {
          if (lcp_origin.IsSameOriginWith(predicted_origin)) {
            count_prediction_matches++;
          }
        }

        base::UmaHistogramCounts1000(
            "Blink.LCPP.PreconnectPredictionMatchCount",
            base::checked_cast<int>(preconnected_origins_.size()));
        if (!preconnected_origins_.empty()) {
          base::UmaHistogramCounts100(
              "Blink.LCPP.PreconnectPredictionMatchPercent",
              base::checked_cast<int>((double)count_prediction_matches /
                                      preconnected_origins_.size() * 100));
        }
      }
    }
  }

  if (blink::LcppScriptObserverEnabled()) {
    if (const HTMLImageElement* image_element =
            DynamicTo<HTMLImageElement>(lcp_element)) {
      auto& creators = image_element->creator_scripts();
      size_t max_allowed_url_length =
          features::kLCPScriptObserverMaxUrlLength.Get();
      size_t max_allowed_url_count =
          features::kLCPScriptObserverMaxUrlCountPerOrigin.Get();
      size_t max_url_length_encountered = 0;
      size_t prediction_match_count = 0;

      Vector<KURL> filtered_script_urls;

      for (auto& url : creators) {
        max_url_length_encountered =
            std::max<size_t>(max_url_length_encountered, url.length());
        if (url.length() >= max_allowed_url_length) {
          continue;
        }
        KURL parsed_url(url);
        if (parsed_url.IsEmpty() || !parsed_url.IsValid() ||
            !parsed_url.ProtocolIsInHTTPFamily()) {
          continue;
        }
        filtered_script_urls.push_back(parsed_url);
        if (lcp_influencer_scripts_.Contains(parsed_url)) {
          prediction_match_count++;
        }
        if (filtered_script_urls.size() >= max_allowed_url_count) {
          break;
        }
      }
      GetHost().SetLcpInfluencerScriptUrls(filtered_script_urls);

      base::UmaHistogramCounts10000(
          "Blink.LCPP.LCPInfluencerUrlsCount",
          base::checked_cast<int>(filtered_script_urls.size()));
      base::UmaHistogramCounts10000(
          "Blink.LCPP.LCPInfluencerUrlsMaxLength",
          base::checked_cast<int>(max_url_length_encountered));
      base::UmaHistogramCounts10000(
          "Blink.LCPP.LCPInfluencerUrlsPredictionMatchCount",
          base::checked_cast<int>(prediction_match_count));
      if (!lcp_influencer_scripts_.empty()) {
        base::UmaHistogramCounts10000(
            "Blink.LCPP.LCPInfluencerUrlsPredictionMatchPercent",
            base::checked_cast<int>((double)prediction_match_count /
                                    lcp_influencer_scripts_.size() * 100));
      }
    }
  }
}

void LCPCriticalPathPredictor::OnFontFetched(const KURL& url) {
  if (!base::FeatureList::IsEnabled(blink::features::kLCPPFontURLPredictor)) {
    return;
  }
  if (!url.ProtocolIsInHTTPFamily()) {
    return;
  }
  if (url.GetString().length() > GetLCPPFontURLPredictorMaxUrlLength()) {
    return;
  }
  GetHost().NotifyFetchedFont(url, fetched_fonts_.Contains(url));
}

void LCPCriticalPathPredictor::OnStartPreload(
    const KURL& url,
    const ResourceType& resource_type) {
  if (!base::FeatureList::IsEnabled(
          blink::features::kHttpDiskCachePrewarming) &&
      !base::FeatureList::IsEnabled(
          blink::features::kLCPPPrefetchSubresource)) {
    return;
  }
  if (!frame_->IsOutermostMainFrame()) {
    return;
  }
  if (!url.ProtocolIsInHTTPFamily()) {
    return;
  }
  if (url.GetString().length() >
      features::kHttpDiskCachePrewarmingMaxUrlLength.Get()) {
    return;
  }
  Document* document = frame_->GetDocument();
  if (!document || !document->Loader()) {
    return;
  }
  base::TimeDelta resource_load_start =
      base::TimeTicks::Now() -
      document->Loader()->GetTiming().NavigationStart();
  CHECK_GE(resource_load_start, base::Seconds(0));
  GetHost().NotifyFetchedSubresource(
      url, resource_load_start,
      ResourceFetcher::DetermineRequestDestination(resource_type));
}

mojom::blink::LCPCriticalPathPredictorHost&
LCPCriticalPathPredictor::GetHost() {
  if (!host_.is_bound() || !host_.is_connected()) {
    host_.reset();
    GetFrame().GetBrowserInterfaceBroker().GetInterface(
        host_.BindNewPipeAndPassReceiver(task_runner_));
  }
  return *host_.get();
}

bool LCPCriticalPathPredictor::IsLcpInfluencerScript(const KURL& url) {
  return lcp_influencer_scripts_.Contains(url);
}

void LCPCriticalPathPredictor::OnOutermostMainFrameDocumentLoad() {
  if (!IsTimingPredictorEnabled()) {
    return;
  }
  is_outermost_main_frame_document_loaded_ = true;
  // Call callbacks as fallback because we can not detect
  // which is lcp in the lcps before onload.
  if (has_lcp_occurred_ || lcp_element_locators_.empty()) {
    MayRunPredictedCallbacks(nullptr);
  }
}

void LCPCriticalPathPredictor::OnWarnedUnusedPreloads(
    const Vector<KURL>& unused_preloads) {
  // This should be sent in the outermost main frame. It's fine without checking
  // |frame_->IsOutermostMainFrame()| here because the caller side
  // LocalFrame::GetLCPP() has the outermost main frame check.
  if (!base::FeatureList::IsEnabled(features::kLCPPDeferUnusedPreload) ||
      has_sent_unused_preloads_) {
    return;
  }
  // Limit the list of preload requests to be sent once. This function can be
  // called after the load event, but we only take care of unused preloads
  // dispatched before LCP.
  has_sent_unused_preloads_ = true;
  GetHost().SetUnusedPreloads(unused_preloads);
}

void LCPCriticalPathPredictor::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
  visitor->Trace(host_);
}

}  // namespace blink

"""

```