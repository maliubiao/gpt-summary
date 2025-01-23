Response:
The user wants a summary of the functionality of the `html_document_parser.cc` file in the Chromium Blink engine. I need to identify its main responsibilities, its relationship with HTML, JavaScript, and CSS, provide examples of logical reasoning, and point out potential user or programming errors.

Here's a plan:

1. **Identify Core Functionality:** Focus on the class `HTMLDocumentParser` and its main methods related to parsing HTML.
2. **Relate to Web Technologies:** Explain how the parser interacts with HTML structure, JavaScript execution during parsing, and CSS loading/blocking.
3. **Logical Reasoning Example:** Demonstrate how the parser handles different input and states, perhaps involving token processing or error handling.
4. **Common Errors:** Think about scenarios where incorrect HTML or asynchronous operations might lead to issues.
5. **Summarize the First Part:**  Condense the information from the first part of the file into a concise overview of its functions.
```
这是目录为blink/renderer/core/html/parser/html_document_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

**功能列举:**

1. **HTML文档解析的核心驱动:** `HTMLDocumentParser` 类是Blink引擎中解析HTML文档的关键组件。它的主要职责是将接收到的HTML数据流转换成浏览器可以理解的DOM（文档对象模型）树结构。

2. **同步与异步解析支持:** 文件中定义了 `ParserSynchronizationPolicy`，表明该解析器支持同步和异步两种解析模式。这允许在需要时立即解析HTML，或者在不阻塞主线程的情况下逐步解析。

3. **分块解析和预算控制:**  代码中出现了 `kDefaultMaxTokenizationBudget` 和 `kInfiniteTokenizationBudget` 等常量，以及 `TimedParserBudgetEnabled` 等功能标志，暗示了解析器可以将HTML数据分成多个小块进行处理，并可以根据时间或令牌数量设置预算，以避免长时间阻塞主线程，提高页面加载性能。

4. **预加载扫描 (Preload Scanning):**  文件中包含了 `HTMLPreloadScanner`、`BackgroundHTMLScanner` 等相关类，以及 `ThreadedPreloadScannerEnabled` 等功能标志。这表明解析器在主解析过程之前或并行地进行预加载扫描，提前识别和请求关键资源（如CSS、JavaScript、图片），以优化页面加载速度。

5. **脚本执行管理:**  `HTMLParserScriptRunner` 类负责在HTML解析过程中管理和执行JavaScript代码。解析器需要识别 `<script>` 标签，并协调脚本的加载和执行。

6. **CSS处理交互:**  虽然没有直接解析CSS，但解析器需要感知CSS的存在，例如，遇到 `<link rel="stylesheet">` 时会触发CSS资源的加载，并在某些情况下（阻塞渲染的CSS）会暂停HTML解析，直到CSS加载完成。

7. **错误处理和容错:**  虽然代码中没有明显的错误处理逻辑，但HTML解析器在设计上需要具有一定的容错能力，能够处理不规范或有错误的HTML代码，并尽力构建出可用的DOM结构。

8. **性能监控和指标收集:**  代码中引入了 `HTMLParserMetrics` 类和相关的直方图记录函数（如 `base::UmaHistogramTimes`），表明该解析器会收集解析过程中的性能数据，用于分析和优化。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:**  `HTMLDocumentParser` 的主要输入就是 HTML 文本数据。它负责识别HTML标签、属性，构建DOM树。例如，解析到 `<div>` 标签时，会在DOM树中创建一个 `div` 元素节点。

* **JavaScript:**
    * 当解析到 `<script>` 标签时，解析器会创建对应的 `HTMLScriptElement`，并可能暂停HTML解析，等待脚本加载和执行完成（对于阻塞型脚本）。
    *  `HTMLParserScriptRunner` 负责执行内联脚本或者加载外部脚本。
    *  假设输入 HTML 包含 `<script>console.log("Hello");</script>`，解析器会识别出该脚本标签，并调用 `HTMLParserScriptRunner` 执行 `console.log("Hello");` 这段 JavaScript 代码。

* **CSS:**
    * 当解析到 `<link rel="stylesheet" href="style.css">` 时，解析器会通知资源加载器去加载 `style.css` 这个CSS文件。
    * 如果CSS被标记为渲染阻塞型（通常是默认情况），解析器会暂停DOM树的构建，直到 `style.css` 加载和解析完成，再继续解析后续的HTML。这保证了渲染时页面样式是完整的。

**逻辑推理的假设输入与输出:**

**假设输入:**  一段包含内联脚本的 HTML 片段：

```html
<div>
  <p>Hello</p>
  <script>
    var message = "World";
  </script>
  <p>Goodbye, <script>document.write(message);</script>!</p>
</div>
```

**逻辑推理:**

1. 解析器开始解析，创建 `div` 和第一个 `p` 元素。
2. 遇到 `<script>` 标签，识别为内联脚本。
3. 解析器可能会暂停 HTML 解析（取决于解析策略），并将脚本内容 "var message = "World";" 交给 `HTMLParserScriptRunner` 处理。
4. 继续解析，创建第二个 `p` 元素。
5. 遇到第二个 `<script>` 标签，识别为内联脚本。
6. 解析器再次暂停，并将 "document.write(message);" 交给 `HTMLParserScriptRunner` 执行。
7. `document.write(message)` 会将 "World" 插入到当前解析的位置。
8. 最终输出的 DOM 结构中，第二个 `p` 元素的内容会是 "Goodbye, World!".

**用户或编程常见的使用错误举例说明:**

* **未闭合的标签:** 用户编写 HTML 时可能会忘记闭合标签，例如 `<p>This is a paragraph`，缺少 `</p>`。解析器通常会尝试容错处理，但可能会导致 DOM 结构不符合预期，甚至影响后续的脚本或样式应用。

* **脚本错误:**  用户在 `<script>` 标签中编写了错误的 JavaScript 代码，例如 `console.logg("Error");` (`logg` 是错误的)。当解析器执行这段脚本时，会导致 JavaScript 错误，可能会阻止页面的正常功能。

* **阻塞渲染的 CSS 导致延迟加载:** 用户引入了大量的阻塞渲染的 CSS 文件，但这些 CSS 文件加载缓慢。这会导致 HTML 解析器在遇到这些 CSS 文件时暂停，从而延迟页面的首次渲染，影响用户体验。  开发者可能会错误地认为页面加载缓慢是网络问题，而忽略了阻塞渲染的 CSS 带来的影响。

**第1部分的功能归纳:**

这部分代码主要负责 `HTMLDocumentParser` 类的基础架构和核心功能。它定义了 HTML 文档解析器的基本结构，包括同步/异步解析策略、分块解析机制、预加载扫描的启用与配置、与脚本执行和 CSS 处理的基本交互。 核心目标是高效且准确地将 HTML 文本流转换为浏览器可用的 DOM 结构，并为后续的渲染和脚本执行做好准备。 此外，它也关注解析性能，并为此引入了预算控制和性能指标收集机制。

### 提示词
```
这是目录为blink/renderer/core/html/parser/html_document_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2010 Google, Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/html/parser/html_document_parser.h"

#include <memory>
#include <utility>

#include "base/feature_list.h"
#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/strcat.h"
#include "base/synchronization/lock.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/types/optional_util.h"
#include "components/miracle_parameter/common/public/miracle_parameter.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/loader/loading_behavior_flag.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/css/media_values_cached.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_meta_element.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/html/nesting_level_incrementer.h"
#include "third_party/blink/renderer/core/html/parser/atomic_html_token.h"
#include "third_party/blink/renderer/core/html/parser/background_html_scanner.h"
#include "third_party/blink/renderer/core/html/parser/html_element_stack.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_metrics.h"
#include "third_party/blink/renderer/core/html/parser/html_preload_scanner.h"
#include "third_party/blink/renderer/core/html/parser/html_resource_preloader.h"
#include "third_party/blink/renderer/core/html/parser/html_tree_builder.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/prefetched_signed_exchange_manager.h"
#include "third_party/blink/renderer/core/loader/preload_helper.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/script/html_parser_script_runner.h"
#include "third_party/blink/renderer/platform/bindings/runtime_call_stats.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/cooperative_scheduling_manager.h"
#include "third_party/blink/renderer/platform/scheduler/public/non_main_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/thread_safe_ref_counted.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"

namespace blink {

// This sets the (default) maximum number of tokens which the foreground HTML
// parser should try to process in one go. Lower values generally mean faster
// first paints, larger values delay first paint, but make sure it's closer to
// the final page. This is the default value to use, if no Finch-provided
// value exists.
constexpr int kDefaultMaxTokenizationBudget = 250;
constexpr int kInfiniteTokenizationBudget = 1e7;
constexpr int kNumYieldsWithDefaultBudget = 2;

class EndIfDelayedForbiddenScope;
class ShouldCompleteScope;
class AttemptToEndForbiddenScope;

enum class FeatureResetMode {
  kUseCached,
  kResetForTesting,
};

const char kHistogramScanAndPreloadTime[] = "Blink.ScanAndPreloadTime2";

bool ThreadedPreloadScannerEnabled(
    FeatureResetMode reset_mode = FeatureResetMode::kUseCached) {
  // Cache the feature value since checking for each parser regresses some micro
  // benchmarks.
  static bool kEnabled =
      base::FeatureList::IsEnabled(features::kThreadedPreloadScanner);
  if (reset_mode == FeatureResetMode::kResetForTesting)
    kEnabled = base::FeatureList::IsEnabled(features::kThreadedPreloadScanner);
  return kEnabled;
}

bool TimedParserBudgetEnabled() {
  // Cache the feature value since checking for each parser regresses some micro
  // benchmarks.
  static const bool kEnabled =
      base::FeatureList::IsEnabled(features::kTimedHTMLParserBudget);
  return kEnabled;
}

bool CheckParserBudgetLessOften() {
  // Cache the feature value since checking for each parser regresses some micro
  // benchmarks.
  static const bool kEnabled =
      base::FeatureList::IsEnabled(features::kCheckHTMLParserBudgetLessOften);
  return kEnabled;
}

bool PrecompileInlineScriptsEnabled(
    FeatureResetMode reset_mode = FeatureResetMode::kUseCached) {
  // Cache the feature value since checking for each parser regresses some micro
  // benchmarks.
  static bool kEnabled =
      base::FeatureList::IsEnabled(features::kPrecompileInlineScripts);
  if (reset_mode == FeatureResetMode::kResetForTesting)
    kEnabled = base::FeatureList::IsEnabled(features::kPrecompileInlineScripts);
  return kEnabled;
}

NonMainThread* GetPreloadScannerThread() {
  DCHECK(ThreadedPreloadScannerEnabled());

  // The preload scanner relies on parsing CSS, which requires creating garbage
  // collected objects. This means the thread the scanning runs on must be GC
  // enabled.
  DEFINE_STATIC_LOCAL(
      std::unique_ptr<NonMainThread>, preload_scanner_thread,
      (NonMainThread::CreateThread(
          ThreadCreationParams(ThreadType::kPreloadScannerThread)
              .SetSupportsGC(true))));
  return preload_scanner_thread.get();
}

PreloadProcessingMode GetPreloadProcessingMode() {
  if (!ThreadedPreloadScannerEnabled())
    return PreloadProcessingMode::kNone;

  static const base::FeatureParam<PreloadProcessingMode>::Option
      kPreloadProcessingModeOptions[] = {
          {PreloadProcessingMode::kNone, "none"},
          {PreloadProcessingMode::kImmediate, "immediate"},
          {PreloadProcessingMode::kYield, "yield"},
      };

  static const base::FeatureParam<PreloadProcessingMode>
      kPreloadProcessingModeParam{
          &features::kThreadedPreloadScanner, "preload-processing-mode",
          PreloadProcessingMode::kImmediate, &kPreloadProcessingModeOptions};

  // Cache the value to avoid parsing the param string more than once.
  static const PreloadProcessingMode kPreloadProcessingModeValue =
      kPreloadProcessingModeParam.Get();
  return kPreloadProcessingModeValue;
}

bool BackgroundScanMainFrameOnly() {
  static const base::FeatureParam<bool> kScanMainFrameOnlyParam{
      &features::kThreadedPreloadScanner, "scan-main-frame-only", true};
  // Cache the value to avoid parsing the param string more than once.
  static const bool kScanMainFrameOnlyValue = kScanMainFrameOnlyParam.Get();
  return kScanMainFrameOnlyValue;
}

bool IsPreloadScanningEnabled(Document* document) {
  if (BackgroundScanMainFrameOnly() && !document->IsInOutermostMainFrame())
    return false;
  return document->GetSettings() &&
         document->GetSettings()->GetDoHtmlPreloadScanning();
}

MIRACLE_PARAMETER_FOR_TIME_DELTA(GetDefaultParserBudget,
                                 features::kTimedHTMLParserBudget,
                                 "default-parser-budget",
                                 base::Milliseconds(10))

// These constants were chosen using experiment data from the field to
// optimize Core Web Vitals metrics: https://web.dev/vitals/#core-web-vitals
// Experiments were run on both Android and desktop to determine the values
// that gave the best aggregate CWV pass rate.
constexpr int kNumYieldsWithDefaultBudgetDefaultValue =
#if BUILDFLAG(IS_ANDROID)
    2
#else
    6
#endif
    ;

MIRACLE_PARAMETER_FOR_INT(GetNumYieldsWithDefaultBudget,
                          features::kTimedHTMLParserBudget,
                          "num-yields-with-default-budget",
                          kNumYieldsWithDefaultBudgetDefaultValue)

// These constants were chosen using experiment data from the field to
// optimize Core Web Vitals metrics: https://web.dev/vitals/#core-web-vitals
// Experiments were run on both Android and desktop to determine the values
// that gave the best aggregate CWV pass rate.
constexpr base::TimeDelta kLongParserBudgetDefaultValue =
#if BUILDFLAG(IS_ANDROID)
    base::Milliseconds(50)
#else
    base::Milliseconds(500)
#endif
    ;

MIRACLE_PARAMETER_FOR_TIME_DELTA(GetLongParserBudget,
                                 features::kTimedHTMLParserBudget,
                                 "long-parser-budget",
                                 kLongParserBudgetDefaultValue)

base::TimeDelta GetDefaultTimedBudget() {
  // Cache the value to avoid parsing the param string more than once.
  static const base::TimeDelta kDefaultParserBudgetValue =
      GetDefaultParserBudget();
  return kDefaultParserBudgetValue;
}

base::TimeDelta GetTimedBudget(int times_yielded) {
  // Cache the value to avoid parsing the param string more than once.
  static const int kNumYieldsWithDefaultBudgetValue =
      GetNumYieldsWithDefaultBudget();

  // Cache the value to avoid parsing the param string more than once.
  static const base::TimeDelta kLongParserBudgetValue = GetLongParserBudget();

  if (times_yielded <= kNumYieldsWithDefaultBudgetValue) {
    return GetDefaultTimedBudget();
  }
  return kLongParserBudgetValue;
}

class EndIfDelayedForbiddenScope {
  STACK_ALLOCATED();

 public:
  explicit EndIfDelayedForbiddenScope(HTMLDocumentParserState* state)
      : state_(state) {
    state_->EnterEndIfDelayedForbidden();
  }
  ~EndIfDelayedForbiddenScope() { state_->ExitEndIfDelayedForbidden(); }

 private:
  HTMLDocumentParserState* state_;
};

class AttemptToEndForbiddenScope {
  STACK_ALLOCATED();

 public:
  explicit AttemptToEndForbiddenScope(HTMLDocumentParserState* state)
      : state_(state) {
    state_->EnterAttemptToEndForbidden();
  }

 private:
  HTMLDocumentParserState* state_;
};

class ShouldCompleteScope {
  STACK_ALLOCATED();

 public:
  explicit ShouldCompleteScope(HTMLDocumentParserState* state) : state_(state) {
    state_->EnterShouldComplete();
  }
  ~ShouldCompleteScope() { state_->ExitShouldComplete(); }

 private:
  HTMLDocumentParserState* state_;
};

// This is a direct transcription of step 4 from:
// http://www.whatwg.org/specs/web-apps/current-work/multipage/the-end.html#fragment-case
static HTMLTokenizer::State TokenizerStateForContextElement(
    Element* context_element,
    bool report_errors,
    const HTMLParserOptions& options) {
  if (!context_element)
    return HTMLTokenizer::kDataState;

  const QualifiedName& context_tag = context_element->TagQName();

  if (context_tag.Matches(html_names::kTitleTag) ||
      context_tag.Matches(html_names::kTextareaTag))
    return HTMLTokenizer::kRCDATAState;
  if (context_tag.Matches(html_names::kStyleTag) ||
      context_tag.Matches(html_names::kXmpTag) ||
      context_tag.Matches(html_names::kIFrameTag) ||
      context_tag.Matches(html_names::kNoembedTag) ||
      (context_tag.Matches(html_names::kNoscriptTag) &&
       options.scripting_flag) ||
      context_tag.Matches(html_names::kNoframesTag))
    return report_errors ? HTMLTokenizer::kRAWTEXTState
                         : HTMLTokenizer::kPLAINTEXTState;
  if (context_tag.Matches(html_names::kScriptTag))
    return report_errors ? HTMLTokenizer::kScriptDataState
                         : HTMLTokenizer::kPLAINTEXTState;
  if (context_tag.Matches(html_names::kPlaintextTag))
    return HTMLTokenizer::kPLAINTEXTState;
  return HTMLTokenizer::kDataState;
}

HTMLDocumentParserState::HTMLDocumentParserState(
    ParserSynchronizationPolicy mode,
    int budget)
    : state_(DeferredParserState::kNotScheduled),
      mode_(mode),
      preload_processing_mode_(GetPreloadProcessingMode()),
      budget_(budget) {}

// Wrap pending preloads in a thread safe and ref-counted object since the
// vector is added to from a background thread and taken from from the main
// thread.
class HTMLDocumentParser::PendingPreloads
    : public ThreadSafeRefCounted<PendingPreloads> {
 public:
  PendingPreloads() = default;

  Vector<std::unique_ptr<PendingPreloadData>> Take() {
    base::AutoLock auto_lock(lock_);
    return std::move(preloads_);
  }

  // Returns the number of items pending preload after `preload_data` has been
  // added.
  size_t Add(std::unique_ptr<PendingPreloadData> preload_data) {
    base::AutoLock auto_lock(lock_);
    preloads_.push_back(std::move(preload_data));
    return preloads_.size();
  }

  bool IsEmpty() {
    base::AutoLock auto_lock(lock_);
    return preloads_.empty();
  }

 private:
  base::Lock lock_;
  Vector<std::unique_ptr<PendingPreloadData>> preloads_ GUARDED_BY(lock_);
};

HTMLDocumentParser::HTMLDocumentParser(HTMLDocument& document,
                                       ParserSynchronizationPolicy sync_policy,
                                       ParserPrefetchPolicy prefetch_policy)
    : HTMLDocumentParser(document,
                         kAllowScriptingContent,
                         sync_policy,
                         prefetch_policy) {
  script_runner_ =
      HTMLParserScriptRunner::Create(ReentryPermit(), &document, this);

  // Allow declarative shadow DOM for the document parser, if not explicitly
  // disabled.
  bool include_shadow_roots = document.GetDeclarativeShadowRootAllowState() !=
                              Document::DeclarativeShadowRootAllowState::kDeny;
  tree_builder_ = MakeGarbageCollected<HTMLTreeBuilder>(
      this, document, kAllowScriptingContent, options_, include_shadow_roots);
}

HTMLDocumentParser::HTMLDocumentParser(
    DocumentFragment* fragment,
    Element* context_element,
    ParserContentPolicy parser_content_policy,
    ParserPrefetchPolicy parser_prefetch_policy)
    : HTMLDocumentParser(fragment->GetDocument(),
                         parser_content_policy,
                         kForceSynchronousParsing,
                         parser_prefetch_policy) {
  // Allow declarative shadow DOM for the fragment parser only if explicitly
  // enabled.
  bool include_shadow_roots =
      fragment->GetDocument().GetDeclarativeShadowRootAllowState() ==
      Document::DeclarativeShadowRootAllowState::kAllow;

  // For now document fragment parsing never reports errors.
  bool report_errors = false;
  tokenizer_.SetState(TokenizerStateForContextElement(context_element,
                                                      report_errors, options_));

  // No script_runner_ in fragment parser.
  tree_builder_ = MakeGarbageCollected<HTMLTreeBuilder>(
      this, fragment, context_element, parser_content_policy, options_,
      include_shadow_roots);
}

HTMLDocumentParser::HTMLDocumentParser(Document& document,
                                       ParserContentPolicy content_policy,
                                       ParserSynchronizationPolicy sync_policy,
                                       ParserPrefetchPolicy prefetch_policy)
    : ScriptableDocumentParser(document, content_policy),
      options_(&document),
      tokenizer_(options_),
      loading_task_runner_(sync_policy == kForceSynchronousParsing
                               ? nullptr
                               : document.GetTaskRunner(TaskType::kNetworking)),
      task_runner_state_(MakeGarbageCollected<HTMLDocumentParserState>(
          sync_policy,
          // Parser yields in chrome-extension:// or file:// documents can
          // cause UI flickering. To mitigate, use_infinite_budget will
          // parse all the way up to the mojo limit.
          (document.Url().ProtocolIs("chrome-extension") ||
           document.Url().IsLocalFile())
              ? kInfiniteTokenizationBudget
              : kDefaultMaxTokenizationBudget)),
      pending_preloads_(base::MakeRefCounted<PendingPreloads>()),
      scheduler_(sync_policy == kAllowDeferredParsing
                     ? Thread::Current()->Scheduler()
                     : nullptr) {
  TRACE_EVENT_WITH_FLOW0("blink", "HTMLDocumentParser::HTMLDocumentParser",
                         TRACE_ID_LOCAL(this), TRACE_EVENT_FLAG_FLOW_OUT);
  // Make sure the preload scanner thread will be ready when needed.
  if (ThreadedPreloadScannerEnabled() && !task_runner_state_->IsSynchronous())
    GetPreloadScannerThread();

  // Report metrics for async document parsing or forced synchronous parsing.
  // The document must be outermost main frame to meet UKM requirements, and
  // must have a high resolution clock for high quality data. Additionally, only
  // report metrics for http urls, which excludes things such as the ntp.
  if (sync_policy == kAllowDeferredParsing &&
      document.IsInOutermostMainFrame() &&
      base::TimeTicks::IsHighResolution() &&
      document.Url().ProtocolIsInHTTPFamily()) {
    metrics_reporter_ = std::make_unique<HTMLParserMetrics>(
        document.UkmSourceID(), document.UkmRecorder());
  }

  // Don't create preloader for parsing clipboard content.
  if (content_policy == kDisallowScriptingAndPluginContent)
    return;

  // Create preloader only when the document is:
  // - attached to a frame (likely the prefetched resources will be loaded
  // soon),
  // - is for no-state prefetch (made specifically for running preloader).
  if (!document.GetFrame() && !document.IsPrefetchOnly())
    return;

  if (prefetch_policy == kAllowPrefetching)
    preloader_ = MakeGarbageCollected<HTMLResourcePreloader>(document);

  should_skip_preload_scan_ = ShouldSkipPreloadScan();
}

HTMLDocumentParser::~HTMLDocumentParser() {
  TRACE_EVENT_WITH_FLOW0("blink", "HTMLDocumentParser::~HTMLDocumentParser",
                         TRACE_ID_LOCAL(this), TRACE_EVENT_FLAG_FLOW_IN);
}

void HTMLDocumentParser::Trace(Visitor* visitor) const {
  visitor->Trace(reentry_permit_);
  visitor->Trace(tree_builder_);
  visitor->Trace(script_runner_);
  visitor->Trace(preloader_);
  visitor->Trace(task_runner_state_);
  ScriptableDocumentParser::Trace(visitor);
  HTMLParserScriptRunnerHost::Trace(visitor);
}

bool HTMLDocumentParser::HasPendingWorkScheduledForTesting() const {
  return task_runner_state_->IsScheduled();
}

unsigned HTMLDocumentParser::GetChunkCountForTesting() const {
  // If `metrics_reporter_` is not set, chunk count is not tracked.
  DCHECK(metrics_reporter_);
  return metrics_reporter_->chunk_count();
}

void HTMLDocumentParser::Detach() {
  // Deschedule any pending tokenizer pumps.
  task_runner_state_->SetState(
      HTMLDocumentParserState::DeferredParserState::kNotScheduled);
  DocumentParser::Detach();
  if (script_runner_)
    script_runner_->Detach();
  if (tree_builder_)
    tree_builder_->Detach();
  // FIXME: It seems wrong that we would have a preload scanner here. Yet during
  // fast/dom/HTMLScriptElement/script-load-events.html we do.
  preload_scanner_.reset();
  insertion_preload_scanner_.reset();
  background_script_scanner_.Reset();
  background_scanner_.reset();
  tokenizer_.Reset();
}

void HTMLDocumentParser::StopParsing() {
  DocumentParser::StopParsing();
  task_runner_state_->SetState(
      HTMLDocumentParserState::DeferredParserState::kNotScheduled);
}

// This kicks off "Once the user agent stops parsing" as described by:
// http://www.whatwg.org/specs/web-apps/current-work/multipage/the-end.html#the-end
void HTMLDocumentParser::PrepareToStopParsing() {
  TRACE_EVENT_WITH_FLOW1("blink", "HTMLDocumentParser::PrepareToStopParsing",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                         "parser", (void*)this);
  base::ElapsedTimer timer;
  DCHECK(!HasInsertionPoint());

  // If we've already been detached, e.g. in
  // WebFrameTest.SwapMainFrameWhileLoading, bail out.
  if (IsDetached())
    return;

  // NOTE: This pump should only ever emit buffered character tokens.
  if (!GetDocument()->IsPrefetchOnly()) {
    ShouldCompleteScope should_complete(task_runner_state_);
    EndIfDelayedForbiddenScope should_not_end_if_delayed(task_runner_state_);
    PumpTokenizerIfPossible();
  }

  if (base::FeatureList::IsEnabled(features::kDelayAsyncScriptExecution) &&
      features::kDelayAsyncScriptExecutionWhenLcpFoundInHtml.Get()) {
    // If kDelayAsyncScriptExecutionWhenLcpFoundInHtml flag is turned on, and an
    // LCP element wasn't found during Preload scan, there is no need to delay
    // async scripts further.
    if (!GetDocument()->IsLcpElementFoundInHtml()) {
      GetDocument()->ResumeAsyncScriptExecution();
    }
  }

  if (IsStopped())
    return;

  DocumentParser::PrepareToStopParsing();

  // We will not have a scriptRunner when parsing a DocumentFragment.
  if (script_runner_)
    GetDocument()->SetReadyState(Document::kInteractive);

  // Setting the ready state above can fire mutation event and detach us from
  // underneath. In that case, just bail out.
  if (IsDetached())
    return;

  GetDocument()->OnPrepareToStopParsing();

  AttemptToRunDeferredScriptsAndEnd();

  base::TimeDelta elapsed_time = timer.Elapsed();
  if (metrics_sub_sampler_.ShouldSample(0.01)) {
    base::UmaHistogramTimes("Blink.PrepareToStopParsingTime", elapsed_time);
  }
  if (metrics_reporter_) {
    metrics_reporter_->AddPrepareToStopParsingTime(
        elapsed_time.InMicroseconds());
  }
}

bool HTMLDocumentParser::IsParsingFragment() const {
  return tree_builder_->IsParsingFragment();
}

void HTMLDocumentParser::DeferredPumpTokenizerIfPossible(
    bool from_finish_append,
    base::TimeTicks schedule_time) {
  // This method is called asynchronously, continues building the HTML document.

  // If we're scheduled for a tokenizer pump, then document should be attached
  // and the parser should not be stopped, but sometimes a script completes
  // loading (so we schedule a pump) but the Document is stopped in the meantime
  // (e.g. fast/parser/iframe-onload-document-close-with-external-script.html).
  DCHECK(task_runner_state_->GetState() ==
             HTMLDocumentParserState::DeferredParserState::kNotScheduled ||
         !IsDetached());
  TRACE_EVENT_WITH_FLOW2(
      "blink", "HTMLDocumentParser::DeferredPumpTokenizerIfPossible",
      TRACE_ID_LOCAL(this),
      TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT, "parser",
      (void*)this, "state", task_runner_state_->GetStateAsString());

  if (metrics_reporter_ && from_finish_append && !did_pump_tokenizer_) {
    base::UmaHistogramCustomMicrosecondsTimes(
        "Blink.HTMLParsing.TimeToDeferredPumpTokenizer4",
        base::TimeTicks::Now() - schedule_time, base::Microseconds(1),
        base::Seconds(1), 100);
  }

  // This method is called when the post task is executed, marking the end of
  // a yield. Report the yielded time.
  DCHECK(yield_timer_);
  if (metrics_reporter_) {
    metrics_reporter_->AddYieldInterval(yield_timer_->Elapsed());
  }
  yield_timer_.reset();

  bool should_call_delay_end =
      task_runner_state_->GetState() ==
      HTMLDocumentParserState::DeferredParserState::kScheduledWithEndIfDelayed;
  if (task_runner_state_->IsScheduled()) {
    task_runner_state_->SetState(
        HTMLDocumentParserState::DeferredParserState::kNotScheduled);
    if (should_call_delay_end) {
      EndIfDelayedForbiddenScope should_not_end_if_delayed(task_runner_state_);
      PumpTokenizerIfPossible();
      EndIfDelayed();
    } else {
      PumpTokenizerIfPossible();
    }
  }
}

void HTMLDocumentParser::PumpTokenizerIfPossible() {
  // This method is called synchronously, builds the HTML document up to
  // the current budget, and optionally completes.
  TRACE_EVENT_WITH_FLOW1("blink", "HTMLDocumentParser::PumpTokenizerIfPossible",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                         "parser", (void*)this);

  bool yielded = false;
  CheckIfBlockingStylesheetAdded();
  if (!IsStopped() &&
      (!IsPaused() || task_runner_state_->ShouldEndIfDelayed())) {
    yielded = PumpTokenizer();
  }

  if (yielded) {
    DCHECK(!task_runner_state_->ShouldComplete());
    SchedulePumpTokenizer(/*from_finish_append=*/false);
  } else if (task_runner_state_->ShouldAttemptToEndOnEOF()) {
    // Fall into this branch if ::Finish has been previously called and we've
    // just finished asynchronously parsing everything.
    if (metrics_reporter_)
      metrics_reporter_->ReportMetricsAtParseEnd();
    AttemptToEnd();
  } else if (task_runner_state_->ShouldEndIfDelayed()) {
    // If we did not exceed the budget or parsed everything there was to
    // parse, check if we should complete the document.
    if (task_runner_state_->ShouldComplete() || IsStopped() || IsStopping()) {
      if (metrics_reporter_)
        metrics_reporter_->ReportMetricsAtParseEnd();
      EndIfDelayed();
    } else {
      ScheduleEndIfDelayed();
    }
  }
}

void HTMLDocumentParser::RunScriptsForPausedTreeBuilder() {
  TRACE_EVENT_WITH_FLOW1("blink",
                         "HTMLDocumentParser::RunScriptsForPausedTreeBuilder",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                         "parser", (void*)this);
  DCHECK(ScriptingContentIsAllowed(GetParserContentPolicy()));

  TextPosition script_start_position = TextPosition::BelowRangePosition();
  Element* script_element =
      tree_builder_->TakeScriptToProcess(script_start_position);
  // We will not have a scriptRunner when parsing a DocumentFragment.
  if (script_runner_)
    script_runner_->ProcessScriptElement(script_element, script_start_position);
  CheckIfBlockingStylesheetAdded();
}

void HTMLDocumentParser::ForcePlaintextForTextDocument() {
  tokenizer_.SetState(HTMLTokenizer::kPLAINTEXTState);
}

bool HTMLDocumentParser::PumpTokenizer() {
  DCHECK(!GetDocument()->IsPrefetchOnly());
  DCHECK(!IsStopped());

  did_pump_tokenizer_ = true;

  NestingLevelIncrementer session = task_runner_state_->ScopedPumpSession();

  // If we're in kForceSynchronousParsing, always run until all available input
  // is consumed.
  bool should_run_until_completion = task_runner_state_->ShouldComplete() ||
                                     task_runner_state_->IsSynchronous() ||
                                     task_runner_state_->InNestedPumpSession();

  bool is_tracing;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED("blink", &is_tracing);
  unsigned starting_bytes;
  if (is_tracing) {
    starting_bytes = input_.length();
    TRACE_EVENT_BEGIN2("blink", "HTMLDocumentParser::PumpTokenizer",
                       "should_complete", should_run_until_completion,
                       "bytes_queued", starting_bytes);
  }
  base::ElapsedTimer pump_tokenizer_timer;

  // We tell the InspectorInstrumentation about every pump, even if we end up
  // pumping nothing.  It can filter out empty pumps itself.
  // FIXME: input_.Current().length() is only accurate if we end up parsing the
  // whole buffer in this pump.  We should pass how much we parsed as part of
  // DidWriteHTML instead of WillWriteHTML.
  probe::ParseHTML probe(GetDocument(), this);

  bool should_yield = false;
  // If we've yielded more than 2 times, then set the budget to a very large
  // number, to attempt to consume all available tokens in one go. This
  // heuristic is intended to allow a quick first contentful paint, followed by
  // a larger rendering lifecycle that processes the remainder of the page.
  int budget =
      (task_runner_state_->TimesYielded() <= kNumYieldsWithDefaultBudget)
          ? task_runner_state_->GetDefaultBudget()
          : kInfiniteTokenizationBudget;

  if (RuntimeEnabledFeatures::HTMLParserYieldAndDelayOftenForTestingEnabled()) {
    budget = 2;
  }

  base::TimeDelta timed_budget;
  if (TimedParserBudgetEnabled())
    timed_budget = GetTimedBudget(task_runner_state_->TimesYielded());

  const bool should_process_preloading =
      task_runner_state_->ShouldProcessPreloads();
  base::ElapsedTimer chunk_parsing_timer;
  base::TimeDelta elapsed_time;
  unsigned tokens_parsed = 0;
  int characters_consumed_before_token = 0;
  base::TimeDelta time_executing_script;
  v8::Isolate* isolate = GetDocument()->GetAgent().isolate();
  while (true) {
    if (should_process_preloading)
      FlushPendingPreloads();

    const auto next_token_status = CanTakeNextToken(time_executing_script);
    if (next_token_status == kNoTokens) {
      // No tokens left to process in this pump, so break
      break;
    }
    if (next_token_status == kHaveTokensAfterScript &&
        task_runner_state_->HaveExitedHeader()) {
      // Just executed a parser-blocking script in the body. We'd probably like
      // to yield at some point soon, especially if we're in "extended budget"
      // mode. So reduce the budget back to at most the default.
      budget = std::min(budget, task_runner_state_->GetDefaultBudget());
      if (TimedParserBudgetEnabled()) {
        timed_budget = std::min(timed_budget, chunk_parsing_timer.Elapsed() +
                                                  GetDefaultTimedBudget());
      }
    }
    HTMLToken* token;
    {
      RUNTIME_CALL_TIMER_SCOPE(
          isolate, RuntimeCallStats::CounterId::kHTMLTokenizerNextToken);
      token = tokenizer_.NextToken(input_.Current());
      if (!token)
        break;
      budget--;
      tokens_parsed++;
    }
    AtomicHTMLToken atomic_html_token(*token);
    // Clear the HTMLToken in case ConstructTree() synchronously re-enters the
    // parser. This has to happen after creating AtomicHTMLToken as it needs
    // state in the HTMLToken.
    tokenizer_.ClearToken();
    ConstructTreeFromToken(atomic_html_token);

    // Late preload for anything deferred due to CSP
    MaybeFetchQueuedPreloads();

    if (!should_run_until_completion && !IsPaused()) {
      DCHECK_EQ(task_runner_state_->GetMode(), kAllowDeferredParsing);
      if (TimedParserBudgetEnabled() &&
          !RuntimeEnabledFeatures::
              HTMLParserYieldAndDelayOftenForTestingEnabled()) {
        if (CheckParserBudgetLessOften()) {
          int newly_consumed_characters =
              input_.Current().NumberOfCharactersConsumed() -
              characters_consumed_before_token;
          characters_consumed_before_token =
              input_.Current().NumberOfCharactersConsumed();
          // On android calling chunk_parsing_timer.Elapsed seems fairly slow
          // compared to the parsing time of small tokens. Only update the
          //
```