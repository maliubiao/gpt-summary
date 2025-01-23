Response:
My thinking process to analyze the `TextFragmentAnchor.cc` file and generate the explanation went through these steps:

1. **Understand the Goal:** The request asks for a comprehensive overview of the `TextFragmentAnchor.cc` file, including its functionality, relationships with web technologies (JavaScript, HTML, CSS), logical reasoning with examples, and common user/programming errors.

2. **Initial Skim for Core Functionality:** I quickly scanned the file for keywords and class names. I noticed:
    * `#include` statements indicating dependencies on various Blink components (DOM, editing, layout, scrolling, etc.).
    * Class name `TextFragmentAnchor`.
    * Methods like `TryCreate`, `InvokeSelector`, `Installed`, `FinalizeAnchor`, `ApplyEffectsToFirstMatch`, `EnsureFirstMatchInViewIfNeeded`.
    * Mentions of `TextDirective`, `TextAnnotationSelector`, `AnnotationAgentImpl`.
    * Timers (`post_load_timer_`, `post_load_timeout_timer_`).
    * Interactions with scrolling and highlighting.

3. **Identify Key Responsibilities:** Based on the skim, I inferred the core purpose: handling navigation to specific text fragments within a web page using the `#:~:text=` syntax. This involves:
    * **Parsing the fragment directive:** Extracting the text to be searched for.
    * **Searching the DOM:** Locating the matching text on the page.
    * **Scrolling to the match:** Bringing the identified text into the viewport.
    * **Highlighting the match:** Visually indicating the located text.
    * **Security checks:**  Ensuring the operation is allowed in the current context.

4. **Map to Web Technologies:**  I then considered how this functionality relates to the specified web technologies:
    * **HTML:** The target of the text fragment anchor is content within the HTML document. The `#:~:text=` syntax is part of the URL fragment, which points to a specific part of the HTML.
    * **CSS:** Highlighting the matched text likely involves applying CSS styles (e.g., background color). The `:target` pseudo-class is used to style the element containing the matched text.
    * **JavaScript:** While this C++ code doesn't directly execute JavaScript, it interacts with JavaScript through the Blink rendering engine. It might trigger JavaScript events or modify the DOM in ways that JavaScript can observe.

5. **Analyze Key Methods and Logic:** I went through the more important methods to understand their specific roles:
    * **`TryCreate`:**  The entry point, responsible for parsing the URL, performing security checks, and creating the `TextFragmentAnchor` object if appropriate.
    * **`InvokeSelector`:** The main driver, managing the state machine of the text fragment matching process (searching, waiting for DOM, applying effects, keeping in view).
    * **`Installed`:**  Sets up observation of DOM changes.
    * **`FinalizeAnchor`:** Cleans up and notifies the JavaScript side of the result.
    * **`ApplyEffectsToFirstMatch`:** Applies the visual changes (highlighting, scrolling, focus).
    * **`EnsureFirstMatchInViewIfNeeded`:**  Performs the actual scrolling.
    * **`CheckSecurityRestrictions`:**  Enforces rules about when text fragment navigation is allowed.
    * **Timers:** Used to handle asynchronous operations and delays after page load.

6. **Infer Logical Reasoning and Examples:** Based on the method names and their actions, I deduced the underlying logic. For example:
    * **Security:** The `CheckSecurityRestrictions` function clearly implements conditional logic based on the origin of the navigation, frame type, and browsing context.
    * **Asynchronous Handling:** The timers and the state machine in `InvokeSelector` indicate an asynchronous approach to handle DOM loading and potential mutations.
    * **Matching:** The interaction with `TextDirective` and `TextAnnotationSelector` implies a matching algorithm is being used.

7. **Identify Potential Errors:** I considered common mistakes users or programmers might make related to this functionality:
    * **Incorrect syntax:** Users might type the `#:~:text=` directive wrong.
    * **Ambiguous matches:** The specified text might appear multiple times on the page.
    * **Security restrictions:**  Cross-origin iframes or certain navigation types might prevent the text fragment from working.
    * **Dynamic content:**  If the target text is added to the page after the initial load, the timing might be off.

8. **Structure the Explanation:** I organized the information into logical sections as requested:
    * **Functionality:** A high-level summary of what the file does.
    * **Relationship with Web Technologies:** Specific examples of how the code interacts with HTML, CSS, and JavaScript.
    * **Logical Reasoning:** Illustrative examples with hypothetical inputs and outputs to demonstrate the logic.
    * **Common Errors:**  Examples of user and programming errors.

9. **Refine and Elaborate:**  I reread the code and my initial analysis to add more detail and clarity. For instance, I expanded on the specific security checks and the different states in the matching process. I also clarified the purpose of the timers.

10. **Review and Verify:** I reviewed the generated explanation to ensure accuracy and completeness, comparing it back to the code to avoid misinterpretations.

This iterative process of skimming, analyzing, inferring, and structuring allowed me to create a comprehensive explanation of the `TextFragmentAnchor.cc` file's functionality and its context within the Blink rendering engine. The focus was on extracting the *what*, *why*, and *how* of the code, making it understandable to someone familiar with web development concepts.好的，让我们来分析一下 `blink/renderer/core/fragment_directive/text_fragment_anchor.cc` 文件的功能。

**主要功能:**

`TextFragmentAnchor.cc` 文件的核心功能是**处理文本片段锚点 (Text Fragment Anchors)**，这是 Web 浏览器的特性，允许用户通过 URL 中的特定指令直接导航到网页中的特定文本片段并高亮显示。  它实现了 Scroll To Text Fragment 功能规范中关于客户端处理的部分。

**更具体的功能点包括:**

1. **解析文本指令 (Text Directives):**  当浏览器加载一个包含文本片段指令的 URL（例如 `https://example.com/#:~:text=find%20this%20text`）时，该文件中的代码负责解析 URL fragment 中的 `text=` 指令，提取出需要查找的文本内容。

2. **搜索匹配文本:**  在页面加载完成后，它会在 DOM 树中搜索与解析出的文本内容相匹配的片段。搜索过程会考虑文本的精确匹配、前缀匹配等。

3. **滚动到匹配位置:**  一旦找到匹配的文本片段，代码会控制浏览器滚动到该片段所在的位置，使其在视口中可见。

4. **高亮显示匹配文本:**  为了让用户清楚地看到匹配的文本，该代码会应用高亮样式到匹配的文本片段上。这通常涉及到添加特定的 CSS 类或使用 Annotation API。

5. **安全限制检查:**  为了防止恶意利用，该代码会进行一些安全限制检查，例如：
    * 验证导航是否是用户发起的。
    * 检查内容类型是否为 `text/html` 或 `text/plain`。
    * 限制跨域子框架的文本片段导航。

6. **异步处理和优化:**  文本片段的搜索和滚动操作可能需要在页面加载和渲染完成后进行，因此代码中使用了定时器 (`post_load_timer_`, `post_load_timeout_timer_`) 和状态管理来处理异步操作，并优化性能。例如，它会延迟搜索，以便在主要的 DOM 结构稳定后再进行。

7. **与辅助功能 (Accessibility) 集成:**  代码会与 Blink 的辅助功能模块 (`AXObjectCache`) 交互，以便辅助技术（如屏幕阅读器）能够识别和处理高亮的文本片段。

8. **性能指标收集:**  `TextFragmentAnchorMetrics` 类用于收集关于文本片段锚点功能的性能指标，例如匹配是否成功、是否为模糊匹配等。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * **关系:**  `TextFragmentAnchor` 的目标是操作 HTML 文档的内容。它在 HTML 结构中查找特定的文本节点。
    * **举例:** 当 URL 为 `https://example.com/#:~:text=important%20info` 时，代码会在页面的 HTML 内容中查找包含 "important info" 的文本节点。

* **CSS:**
    * **关系:**  高亮显示匹配的文本片段通常是通过应用 CSS 样式来实现的。
    * **举例:** 代码可能会添加一个 CSS 类（例如 `.text-fragment-highlight`) 到匹配的文本所在的元素上，然后在 CSS 中定义该类的样式，例如设置背景色为黄色。

* **JavaScript:**
    * **关系:**  尽管 `TextFragmentAnchor.cc` 是 C++ 代码，但它与 JavaScript 有交互。
        * 它会通知 JavaScript  文本片段匹配完成，并将匹配的 Range 对象传递给 JavaScript。
        * JavaScript 可以通过 `document.fragmentDirective` API 访问和管理文本片段相关的信息。
    * **举例:**  在 `FinalizeAnchor` 方法中，代码会调用 `text_directive->DidFinishMatching(attached_range)`，这会通知 JavaScript 侧的 `TextDirective` 对象匹配完成。同时，JavaScript 可以监听 `fragmentchange` 事件来感知 URL fragment 的变化，并可能根据文本片段锚点的结果执行某些操作。

**逻辑推理、假设输入与输出:**

**假设输入:**

1. **URL:** `https://example.com/long_page.html#:~:text=the%20quick%20brown,jumps%20over%20the%20lazy%20dog.`
2. **页面内容 (HTML):**
    ```html
    <!DOCTYPE html>
    <html>
    <head>
        <title>Example Page</title>
    </head>
    <body>
        <p>This is some introductory text.</p>
        <p>The quick brown fox jumps over the lazy dog. This is the sentence we are looking for.</p>
        <p>Some more content.</p>
    </body>
    </html>
    ```

**逻辑推理:**

1. `TextFragmentAnchor::TryCreate` 会解析 URL，提取出要查找的文本 `"the quick brown,jumps over the lazy dog."`。
2. `InvokeSelector` 方法会启动搜索过程。
3. 代码会在 DOM 树中查找与指定文本精确匹配的片段。
4. 假设找到了 `<p>` 元素中的 "The quick brown fox jumps over the lazy dog." 这部分文本。
5. `ApplyEffectsToFirstMatch` 会将该文本滚动到视口中，并应用高亮样式。

**预期输出:**

1. 浏览器会自动滚动页面，使得包含 "The quick brown fox jumps over the lazy dog." 的段落在浏览器窗口中可见。
2. "The quick brown fox jumps over the lazy dog." 这部分文本会被高亮显示，例如背景色变为黄色。

**涉及用户或编程常见的使用错误及举例说明:**

1. **URL 中文本片段指令语法错误:**
    * **错误示例:** `https://example.com/#:~text=find%20me` (缺少冒号) 或 `https://example.com/#:~:textfindme` (缺少等号)。
    * **结果:** 浏览器可能无法正确解析文本片段指令，导致无法找到或高亮显示目标文本。`UseCounter::Count(frame.GetDocument(), WebFeature::kInvalidFragmentDirective);` 这行代码表明 Blink 会记录这种无效指令的使用情况。

2. **指定的文本在页面上不存在:**
    * **错误示例:**  URL 为 `https://example.com/#:~:text=this%20text%20does%20not%20exist`，但页面内容中没有完全匹配的文本。
    * **结果:** 浏览器无法找到匹配的文本，因此不会滚动或高亮显示任何内容。`DidFinishSearch` 方法中的 `if (!did_find_any_matches)` 分支会处理这种情况。

3. **指定的文本片段过于 Ambiguous (模糊匹配):**
    * **错误示例:** URL 为 `https://example.com/#:~:text=the`，而页面上 "the" 这个词出现了很多次。
    * **结果:** 浏览器可能会高亮显示第一个匹配项，但 `metrics_->DidFindAmbiguousMatch();` 表明代码会记录这种模糊匹配的情况，这可能影响用户体验，因为用户可能期望的是其他的 "the"。

4. **跨域安全限制导致的失败:**
    * **错误示例:** 从 `https://evil.com` 导航到一个包含文本片段的 `https://example.com` 页面，并且 `https://example.com` 中包含不允许跨域访问的 iframe。
    * **结果:** `CheckSecurityRestrictions` 函数中的相关检查会阻止文本片段导航的执行，以保护用户安全。

5. **在非 HTML 或纯文本类型的文档中使用文本片段:**
    * **错误示例:**  尝试使用文本片段锚点导航到 PDF 文件或图片链接。
    * **结果:** `CheckSecurityRestrictions` 函数会检查 `content_type`，如果不是 `text/html` 或 `text/plain`，则会返回 `false`，阻止文本片段功能的执行。

6. **依赖于页面加载完成前的行为:**
    * **编程错误:**  开发者可能会错误地认为文本片段的匹配和高亮会立即发生，并在页面加载完成前就执行依赖于此的操作的 JavaScript 代码。
    * **结果:** 由于 `TextFragmentAnchor` 的操作是异步的，并且通常在页面加载完成后进行，过早执行的 JavaScript 代码可能无法获取到正确的高亮状态或匹配结果。

通过分析 `TextFragmentAnchor.cc` 文件的内容，我们可以了解到 Blink 引擎是如何实现文本片段锚点这一重要功能的，以及它与 Web 标准、安全性和用户体验的联系。

### 提示词
```
这是目录为blink/renderer/core/fragment_directive/text_fragment_anchor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fragment_directive/text_fragment_anchor.h"

#include "base/auto_reset.h"
#include "base/trace_event/typed_macros.h"
#include "components/shared_highlighting/core/common/fragment_directives_utils.h"
#include "third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/annotation/annotation_agent_container_impl.h"
#include "third_party/blink/renderer/core/annotation/annotation_agent_impl.h"
#include "third_party/blink/renderer/core/annotation/text_annotation_selector.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/fragment_directive/fragment_directive.h"
#include "third_party/blink/renderer/core/fragment_directive/fragment_directive_utils.h"
#include "third_party/blink/renderer/core/fragment_directive/text_directive.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_handler.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_selector.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/scroll/scroll_alignment.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/core/scroll/scrollable_area.h"
#include "third_party/blink/renderer/platform/search_engine_utils.h"

namespace blink {

namespace {

bool CheckSecurityRestrictions(LocalFrame& frame) {
  // This algorithm checks the security restrictions detailed in
  // https://wicg.github.io/ScrollToTextFragment/#should-allow-a-text-fragment
  // TODO(bokan): These are really only relevant for observable actions like
  // scrolling. We should consider allowing highlighting regardless of these
  // conditions. See the TODO in the relevant spec section:
  // https://wicg.github.io/ScrollToTextFragment/#restricting-the-text-fragment

  if (!frame.Loader().GetDocumentLoader()->ConsumeTextFragmentToken()) {
    TRACE_EVENT_INSTANT("blink", "CheckSecurityRestrictions", "Result",
                        "No Token");
    return false;
  }

  AtomicString content_type = frame.GetDocument()->contentType();
  if (content_type != "text/html" && content_type != "text/plain") {
    TRACE_EVENT_INSTANT("blink", "CheckSecurityRestrictions", "Result",
                        "Invalid ContentType");
    return false;
  }

  // TODO(bokan): Reevaluate whether it's safe to allow text fragments inside a
  // fenced frame. https://crbug.com/1334788.
  if (frame.IsFencedFrameRoot()) {
    TRACE_EVENT_INSTANT("blink", "CheckSecurityRestrictions", "Result",
                        "Fenced Frame");
    return false;
  }

  // For cross origin initiated navigations, we only allow text
  // fragments if the frame is not script accessible by another frame, i.e. no
  // cross origin iframes or window.open.
  if (!frame.Loader()
           .GetDocumentLoader()
           ->LastNavigationHadTrustedInitiator()) {
    if (frame.Tree().Parent()) {
      TRACE_EVENT_INSTANT("blink", "CheckSecurityRestrictions", "Result",
                          "Cross-Origin Subframe");
      return false;
    }

    if (frame.GetPage()->RelatedPages().size()) {
      TRACE_EVENT_INSTANT("blink", "CheckSecurityRestrictions", "Result",
                          "Non-Empty Browsing Context Group");
      return false;
    }
  }

  TRACE_EVENT_INSTANT("blink", "CheckSecurityRestrictions", "Result", "Pass");
  return true;
}

}  // namespace

// static
base::TimeDelta TextFragmentAnchor::PostLoadTaskDelay() {
  // The amount of time to wait after load without a DOM mutation before
  // invoking the text search. Each time a DOM mutation occurs the text search
  // is pushed back by this delta. Experimentally determined.
  return base::Milliseconds(500);
}

// static
base::TimeDelta TextFragmentAnchor::PostLoadTaskTimeout() {
  // The maximum amount of time to wait after load before performing the text
  // search. Experimentally determined.
  return base::Milliseconds(3000);
}

// static
bool TextFragmentAnchor::GenerateNewToken(const DocumentLoader& loader) {
  // Avoid invoking the text fragment for history, reload as they'll be
  // clobbered by scroll restoration anyway. In particular, history navigation
  // is considered browser initiated even if performed via non-activated script
  // so we don't want this case to produce a token. See
  // https://crbug.com/1042986 for details. Note: this also blocks form
  // navigations.
  if (loader.GetNavigationType() != kWebNavigationTypeLinkClicked &&
      loader.GetNavigationType() != kWebNavigationTypeOther) {
    return false;
  }

  // A new permission to invoke should only be granted if the navigation had a
  // transient user activation attached to it. Browser initiated navigations
  // (e.g. typed address in the omnibox) don't carry the transient user
  // activation bit so we have to check that separately but we consider that
  // user initiated as well.
  return loader.LastNavigationHadTransientUserActivation() ||
         loader.IsBrowserInitiated();
}

// static
bool TextFragmentAnchor::GenerateNewTokenForSameDocument(
    const DocumentLoader& loader,
    WebFrameLoadType load_type,
    mojom::blink::SameDocumentNavigationType same_document_navigation_type) {
  if ((load_type != WebFrameLoadType::kStandard &&
       load_type != WebFrameLoadType::kReplaceCurrentItem) ||
      same_document_navigation_type !=
          mojom::blink::SameDocumentNavigationType::kFragment)
    return false;

  // Same-document text fragment navigations are allowed only when initiated
  // from the browser process (e.g. typing in the omnibox) or a same-origin
  // document. This is restricted by the spec:
  // https://wicg.github.io/scroll-to-text-fragment/#restricting-the-text-fragment.
  if (!loader.LastNavigationHadTrustedInitiator()) {
    return false;
  }

  // Only generate a token if it's going to be consumed (i.e. the new fragment
  // has a text fragment in it).
  FragmentDirective& fragment_directive =
      loader.GetFrame()->GetDocument()->fragmentDirective();
  if (!fragment_directive.LastNavigationHadFragmentDirective() ||
      fragment_directive.GetDirectives<TextDirective>().empty()) {
    return false;
  }

  return true;
}

// static
TextFragmentAnchor* TextFragmentAnchor::TryCreate(const KURL& url,
                                                  LocalFrame& frame,
                                                  bool should_scroll) {
  DCHECK(RuntimeEnabledFeatures::TextFragmentIdentifiersEnabled(
      frame.DomWindow()));

  HeapVector<Member<TextDirective>> text_directives =
      frame.GetDocument()->fragmentDirective().GetDirectives<TextDirective>();
  if (text_directives.empty()) {
    if (frame.GetDocument()
            ->fragmentDirective()
            .LastNavigationHadFragmentDirective()) {
      UseCounter::Count(frame.GetDocument(),
                        WebFeature::kInvalidFragmentDirective);
    }
    return nullptr;
  }

  TRACE_EVENT("blink", "TextFragmentAnchor::TryCreate", "url", url,
              "should_scroll", should_scroll);

  if (!CheckSecurityRestrictions(frame)) {
    return nullptr;
  } else if (!should_scroll) {
    if (frame.Loader().GetDocumentLoader() &&
        !frame.Loader().GetDocumentLoader()->NavigationScrollAllowed()) {
      // We want to record a use counter whenever a text-fragment is blocked by
      // ForceLoadAtTop.  If we passed security checks but |should_scroll| was
      // passed in false, we must have calculated |block_fragment_scroll| in
      // FragmentLoader::ProcessFragment. This can happen in one of two cases:
      //   1) Blocked by ForceLoadAtTop - what we want to measure
      //   2) Blocked because we're restoring from history. However, in this
      //      case we'd not pass security restrictions because we filter out
      //      history navigations.
      UseCounter::Count(frame.GetDocument(),
                        WebFeature::kTextFragmentBlockedByForceLoadAtTop);
    }
  }

  return MakeGarbageCollected<TextFragmentAnchor>(text_directives, frame,
                                                  should_scroll);
}

TextFragmentAnchor::TextFragmentAnchor(
    HeapVector<Member<TextDirective>>& text_directives,
    LocalFrame& frame,
    bool should_scroll)
    : SelectorFragmentAnchor(frame, should_scroll),
      post_load_timer_(frame.GetTaskRunner(TaskType::kInternalFindInPage),
                       this,
                       &TextFragmentAnchor::PostLoadTask),
      post_load_timeout_timer_(
          frame.GetTaskRunner(TaskType::kInternalFindInPage),
          this,
          &TextFragmentAnchor::PostLoadTask),
      metrics_(MakeGarbageCollected<TextFragmentAnchorMetrics>(
          frame_->GetDocument())) {
  TRACE_EVENT("blink", "TextFragmentAnchor::TextFragmentAnchor");
  DCHECK(!text_directives.empty());
  DCHECK(frame_->View());

  metrics_->DidCreateAnchor(text_directives.size());

  AnnotationAgentContainerImpl* annotation_container =
      AnnotationAgentContainerImpl::CreateIfNeeded(*frame_->GetDocument());
  DCHECK(annotation_container);

  directive_annotation_pairs_.reserve(text_directives.size());
  for (Member<TextDirective>& directive : text_directives) {
    auto* selector =
        MakeGarbageCollected<TextAnnotationSelector>(directive->GetSelector());
    AnnotationAgentImpl* agent = annotation_container->CreateUnboundAgent(
        mojom::blink::AnnotationType::kSharedHighlight, *selector);

    // TODO(bokan): This is a stepping stone in refactoring the
    // TextFragmentHandler. When we replace it with a browser-side manager it
    // may make for a better API to have components register a handler for an
    // annotation type with AnnotationAgentContainer.
    // https://crbug.com/1303887.
    TextFragmentHandler::DidCreateTextFragment(*agent, *frame_->GetDocument());

    directive_annotation_pairs_.push_back(std::make_pair(directive, agent));
  }
}

bool TextFragmentAnchor::InvokeSelector() {
  UpdateCurrentState();

  switch (state_) {
    case kSearching:
      if (iteration_ == kDone) {
        DidFinishSearch();
      }
      break;
    case kWaitingForDOMMutations:
      // A match was found but requires some kind of DOM mutation to make it
      // visible and ready so don't try to finish the search yet.
      CHECK(first_match_);
      if (first_match_->IsAttachmentPending()) {
        // Still waiting.
        break;
      }

      // Move to ApplyEffects immediately.
      state_ = kApplyEffects;
      [[fallthrough]];
    case kApplyEffects:
      // Now that the event - if needed - has been processed, apply the
      // necessary effects to the matching DOM nodes.
      ApplyEffectsToFirstMatch();
      state_ = kKeepInView;
      [[fallthrough]];
    case kKeepInView:
      // Until the load event ensure the matched text is kept in view in the
      // face of layout changes.
      EnsureFirstMatchInViewIfNeeded();
      if (iteration_ == kDone) {
        DidFinishSearch();
      }
      break;
    case kFinalized:
      break;
  }

  // We return true to keep this anchor alive as long as we need another invoke
  // or have to finish up at the next rAF.
  return !(state_ == kFinalized && iteration_ == kDone);
}

void TextFragmentAnchor::Installed() {
  AnnotationAgentContainerImpl* container =
      Supplement<Document>::From<AnnotationAgentContainerImpl>(
          frame_->GetDocument());
  CHECK(container);
  container->AddObserver(this);
}

void TextFragmentAnchor::NewContentMayBeAvailable() {
  // The post load task will only be invoked once so don't restart an inactive
  // timer (if it's inactive it's because it's already been invoked).
  if (iteration_ != kPostLoad || !post_load_timer_.IsActive()) {
    return;
  }

  // Restart the timer.
  post_load_timer_.StartOneShot(PostLoadTaskDelay(), FROM_HERE);
}

void TextFragmentAnchor::FinalizeAnchor() {
  CHECK_EQ(iteration_, kDone);
  CHECK_LT(state_, kFinalized);

  if (element_fragment_anchor_) {
    element_fragment_anchor_->Installed();
    element_fragment_anchor_->Invoke();
    element_fragment_anchor_ = nullptr;
  }

  // Notify the DOM object exposed to JavaScript that we've completed the
  // search and pass it the range we found.
  for (DirectiveAnnotationPair& directive_annotation_pair :
       directive_annotation_pairs_) {
    TextDirective* text_directive = directive_annotation_pair.first.Get();
    AnnotationAgentImpl* annotation = directive_annotation_pair.second.Get();
    const RangeInFlatTree* attached_range =
        annotation->IsAttached() ? &annotation->GetAttachedRange() : nullptr;
    text_directive->DidFinishMatching(attached_range);
  }
  state_ = kFinalized;
}

void TextFragmentAnchor::Trace(Visitor* visitor) const {
  visitor->Trace(element_fragment_anchor_);
  visitor->Trace(metrics_);
  visitor->Trace(directive_annotation_pairs_);
  visitor->Trace(first_match_);
  visitor->Trace(matched_annotations_);
  visitor->Trace(post_load_timer_);
  visitor->Trace(post_load_timeout_timer_);
  SelectorFragmentAnchor::Trace(visitor);
}

void TextFragmentAnchor::WillPerformAttach() {
  if (iteration_ == kParsing && frame_->GetDocument()->IsLoadCompleted()) {
    iteration_ = kLoad;
    MarkFailedAttachmentsForRetry();
  }
}

void TextFragmentAnchor::UpdateCurrentState() {
  bool all_found = true;
  bool any_needs_attachment = false;
  for (auto& directive_annotation_pair : directive_annotation_pairs_) {
    AnnotationAgentImpl* annotation = directive_annotation_pair.second;

    // This method is called right after AnnotationAgentContainerImpl calls
    // PerformInitialAttachments. However, it may have avoided attachment if
    // the page is hidden. If that's the case, avoid moving to kPostLoad so
    // that we don't finish the search until the page becomes visible.
    if (annotation->NeedsAttachment()) {
      any_needs_attachment = true;
    }

    bool found_match =
        annotation->IsAttachmentPending() || annotation->IsAttached();
    if (!found_match) {
      all_found = false;
      continue;
    }

    // Text fragments apply effects (scroll, focus) only to the first
    // *matching* directive into view so that's the directive that reflects the
    // `state_`. The Attach() call matches synchronously (but may
    // ansynchronously perform DOMMutations) so the first such matching agent
    // will be set to first_match_.
    if (!first_match_) {
      CHECK_EQ(state_, kSearching);
      state_ = annotation->IsAttachmentPending() ? kWaitingForDOMMutations
                                                 : kApplyEffects;
      first_match_ = annotation;
    }

    if (matched_annotations_.insert(annotation).is_new_entry) {
      metrics_->DidFindMatch();
      const AnnotationSelector* selector = annotation->GetSelector();
      // Selector must be a TextAnnotationSelector since this is the
      // *Text*FragmentAnchor.
      if (selector && !To<TextAnnotationSelector>(selector)->WasMatchUnique()) {
        metrics_->DidFindAmbiguousMatch();
      }
    }
  }

  if (all_found) {
    iteration_ = kDone;
  } else if (iteration_ == kLoad && !any_needs_attachment) {
    iteration_ = kPostLoad;
    post_load_timer_.StartOneShot(PostLoadTaskDelay(), FROM_HERE);
    post_load_timeout_timer_.StartOneShot(PostLoadTaskTimeout(), FROM_HERE);
  }
}

void TextFragmentAnchor::ApplyEffectsToFirstMatch() {
  DCHECK(first_match_);
  DCHECK_EQ(state_, kApplyEffects);

  // TODO(jarhar): Consider what to do based on DOM/style modifications made by
  // the beforematch event here and write tests for it once we decide on a
  // behavior here: https://github.com/WICG/display-locking/issues/150

  // It's possible the DOM the match was attached to was removed by this time.
  if (!first_match_->IsAttached())
    return;

  // If we're attached, we must have already waited for DOM mutations.
  CHECK(!first_match_->IsAttachmentPending());

  const RangeInFlatTree& range = first_match_->GetAttachedRange();

  // Apply :target pseudo class.
  ApplyTargetToCommonAncestor(range.ToEphemeralRange());
  frame_->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kFindInPage);

  // Scroll the match into view.
  if (!EnsureFirstMatchInViewIfNeeded())
    return;

  if (AXObjectCache* cache = frame_->GetDocument()->ExistingAXObjectCache()) {
    Node& first_node = *range.ToEphemeralRange().Nodes().begin();
    cache->HandleScrolledToAnchor(&first_node);
  }

  metrics_->DidInvokeScrollIntoView();

  // Set the sequential focus navigation to the start of selection.
  // Even if this element isn't focusable, "Tab" press will
  // start the search to find the next focusable element from this element.
  frame_->GetDocument()->SetSequentialFocusNavigationStartingPoint(
      range.StartPosition().NodeAsRangeFirstNode());
}

bool TextFragmentAnchor::EnsureFirstMatchInViewIfNeeded() {
  CHECK_GE(state_, kApplyEffects);
  CHECK(first_match_);

  if (!should_scroll_ || user_scrolled_)
    return false;

  // It's possible the DOM the match was attached to was removed by this time.
  if (!first_match_->IsAttached())
    return false;

  // Ensure we don't treat the text fragment ScrollIntoView as a user scroll
  // so reset user_scrolled_ when it's done.
  base::AutoReset<bool> reset_user_scrolled(&user_scrolled_, user_scrolled_);
  first_match_->ScrollIntoView();

  return true;
}

void TextFragmentAnchor::DidFinishSearch() {
  CHECK_EQ(iteration_, kDone);
  CHECK_LT(state_, kFinalized);

  if (finalize_pending_) {
    return;
  }

  AnnotationAgentContainerImpl* container =
      Supplement<Document>::From<AnnotationAgentContainerImpl>(
          frame_->GetDocument());
  CHECK(container);
  container->RemoveObserver(this);

  metrics_->SetSearchEngineSource(HasSearchEngineSource());
  metrics_->ReportMetrics();

  bool did_find_any_matches = first_match_ != nullptr;

  if (!did_find_any_matches) {
    DCHECK(!element_fragment_anchor_);
    // ElementFragmentAnchor needs to be invoked from FinalizeAnchor
    // since it can cause script to run and we may be in a ScriptForbiddenScope
    // here.
    element_fragment_anchor_ = ElementFragmentAnchor::TryCreate(
        frame_->GetDocument()->Url(), *frame_, should_scroll_);
  }

  DCHECK(!did_find_any_matches || !element_fragment_anchor_);

  // Finalizing the anchor may cause script execution so schedule a new frame
  // to perform finalization.
  frame_->GetDocument()->EnqueueAnimationFrameTask(WTF::BindOnce(
      &TextFragmentAnchor::FinalizeAnchor, WrapWeakPersistent(this)));
  finalize_pending_ = true;
}

void TextFragmentAnchor::ApplyTargetToCommonAncestor(
    const EphemeralRangeInFlatTree& range) {
  Node* common_node = range.CommonAncestorContainer();
  while (common_node && common_node->getNodeType() != Node::kElementNode) {
    common_node = common_node->parentNode();
  }

  DCHECK(common_node);
  if (common_node) {
    auto* target = DynamicTo<Element>(common_node);
    frame_->GetDocument()->SetCSSTarget(target);
  }
}

void TextFragmentAnchor::SetTickClockForTesting(
    const base::TickClock* tick_clock) {
  metrics_->SetTickClockForTesting(tick_clock);
}

bool TextFragmentAnchor::HasSearchEngineSource() {
  if (!frame_->GetDocument() || !frame_->GetDocument()->Loader())
    return false;

  // Client side redirects should not happen for links opened from search
  // engines. If a redirect occurred, we can't rely on the requestorOrigin as
  // it won't point to the original requestor anymore.
  if (frame_->GetDocument()->Loader()->IsClientRedirect())
    return false;

  // TODO(crbug.com/1133823): Add test case for valid referrer.
  if (!frame_->GetDocument()->Loader()->GetRequestorOrigin())
    return false;

  return IsKnownSearchEngine(
      frame_->GetDocument()->Loader()->GetRequestorOrigin()->ToString());
}

bool TextFragmentAnchor::MarkFailedAttachmentsForRetry() {
  bool did_mark = false;
  for (auto& directive_annotation_pair : directive_annotation_pairs_) {
    AnnotationAgentImpl* annotation = directive_annotation_pair.second;
    if (!annotation->IsAttached() && !annotation->IsAttachmentPending()) {
      annotation->SetNeedsAttachment();
      did_mark = true;
    }
  }

  return did_mark;
}

void TextFragmentAnchor::PostLoadTask(TimerBase*) {
  CHECK_NE(iteration_, kDone);

  // Stop both timers - the post load task is run just once.
  post_load_timer_.Stop();
  post_load_timeout_timer_.Stop();
  if (!frame_->IsDetached() && MarkFailedAttachmentsForRetry()) {
    frame_->GetPage()->GetChromeClient().ScheduleAnimation(frame_->View());
  }

  iteration_ = kDone;
}

}  // namespace blink
```