Response:
The user wants a summary of the functionality of the C++ test file `display_lock_context_test.cc`. I need to analyze the included headers and the test cases defined in the file to understand its purpose.

Based on the file name and included headers, this test file is specifically designed to test the `DisplayLockContext` class, which is part of Blink's rendering engine and is related to controlling the rendering lifecycle of elements. It seems to focus on how `DisplayLockContext` interacts with various features like styling, layout, painting, Find-in-Page, and focus.

Here's a breakdown of the key functionalities being tested:

1. **Locking and Unlocking Elements:** The tests demonstrate how to lock and unlock elements using `content-visibility: hidden` or `hidden="until-found"`.
2. **Impact on Style and Layout:** Tests verify that locked elements and their children are not styled or laid out until unlocked, and how dirty bits are propagated.
3. **Find-in-Page Integration:** Several tests focus on how the Find-in-Page functionality interacts with locked elements, specifically:
    - Locked elements are not searchable.
    - Elements locked with `hidden="until-found"` (activatable) become searchable and trigger scrolling to the element when found.
    - Find-in-Page continues working even after an element is relocked.
    - Find-in-Page can target elements within containers that have `contain-intrinsic-size`.
    - Find-in-Page tick marks are placed on the locked root elements.
    - Content changes within locked elements during Find-in-Page don't cause crashes.
    - Find-in-Page works correctly even with dynamically changed content within locked elements.
    - Finding no matches in a locked element doesn't unlock it.
    - Nested locked elements behave correctly with Find-in-Page.
4. **`UpdateStyleAndLayout` Behavior:** Tests examine how `UpdateStyleAndLayout` interacts with locked elements, ensuring that style and layout are not unnecessarily triggered on locked subtrees.
5. **Focusability:** Tests confirm that locked elements and their descendants are not focusable.
6. **Activation Prevention:**  The final (incomplete) test hints at verifying that display locks prevent element activation.

I will now formulate a summary based on these observations, keeping in mind the constraint of this being part 1 of 5.
这个C++源代码文件 `display_lock_context_test.cc` 的主要功能是为 Blink 渲染引擎中的 `DisplayLockContext` 类编写单元测试。`DisplayLockContext` 用于控制页面元素的渲染生命周期，允许在某些条件下“锁定”元素的渲染，直到满足特定条件才进行渲染。

以下是该文件测试的主要功能点归纳：

1. **锁定和解锁元素:**  测试了如何通过设置 CSS 属性 `content-visibility: hidden` 或 HTML 属性 `hidden="until-found"` 来锁定元素，以及解锁元素后的行为。

2. **对样式和布局的影响:**  测试了当元素被锁定时，其子元素是否会跳过样式计算和布局计算。验证了样式变更的脏位 (dirty bits) 在锁定和解锁过程中的传播。

3. **与 Find-in-Page 功能的集成:**  这是本部分代码重点测试的功能，具体包括：
    * **不可搜索:** 测试了被锁定的元素是否无法通过 Find-in-Page 功能找到。
    * **可激活锁定 (`hidden="until-found"`):** 测试了使用 `hidden="until-found"` 锁定的元素在 Find-in-Page 中可以被找到，并且会触发滚动使元素可见。
    * **重新锁定后继续查找:** 测试了在 Find-in-Page 过程中，如果元素被重新锁定，查找功能是否能正常继续。
    * **目标位于锁定大小之下:** 测试了当 Find-in-Page 的目标位于具有 `contain-intrinsic-size` 属性的锁定元素内部时，滚动位置是否正确。
    * **标记位于锁定根节点:** 测试了 Find-in-Page 的标记 (tickmarks) 是否正确地显示在可激活锁定元素的根节点上。
    * **锁定内容变化时查找不崩溃:** 测试了在 Find-in-Page 过程中，修改锁定元素的内容是否会导致崩溃。
    * **已更改内容的查找:** 测试了当锁定元素的内容发生变化后，Find-in-Page 功能是否还能找到匹配项。
    * **无匹配项时不解锁:** 测试了当在可激活锁定元素中找不到匹配项时，该元素是否会保持锁定状态。
    * **嵌套可激活锁定元素:** 测试了嵌套的可激活锁定元素在 Find-in-Page 中的行为，例如哪些元素可以被找到，解锁状态如何。

**与 Javascript, HTML, CSS 的关系举例说明:**

* **HTML:**
    *  使用 HTML 属性 `hidden="until-found"` 来创建可激活的锁定元素。例如： `<div id="container" hidden="until-found">...</div>`。
    *  通过 HTML 结构定义元素的层级关系，用于测试嵌套锁定元素的情况。

* **CSS:**
    *  使用 CSS 属性 `content-visibility: hidden` 来锁定元素，阻止其渲染。例如： `#container { content-visibility: hidden; }`。
    *  使用 CSS 属性 `contain: style layout paint;` 来创建包含上下文，限制锁定对外部的影响，并进行更精细的控制。
    *  测试 CSS 样式的更改（例如 `color: red;`）如何影响锁定和解锁元素的样式重算。

* **Javascript:**  尽管本测试文件是 C++ 代码，它模拟了 Javascript 触发的一些行为。例如，通过 C++ 代码设置 HTML 元素的属性和内容，这与 Javascript 操作 DOM 类似。在实际浏览器环境中，Javascript 可以通过 API 来请求显示锁，或者修改元素的属性和样式，从而触发这里测试的各种场景。

**逻辑推理的假设输入与输出 (针对 Find-in-Page 功能):**

**假设输入:**

1. **HTML 结构:**  包含一个带有文本内容的 `div` 元素，该元素被设置为 `hidden="until-found"` (可激活锁定)。
   ```html
   <div id="locked-element" hidden="until-found">要查找的文本</div>
   ```
2. **Find-in-Page 请求:** 用户在页面上发起查找 "要查找的文本" 的请求。

**预期输出:**

1. **元素解锁:** `locked-element` 元素的锁定状态被解除，变得可见。
2. **滚动到元素:** 页面滚动到 `locked-element` 元素的位置，使其在视口中可见。
3. **Find-in-Page 匹配:** Find-in-Page 功能高亮显示 "要查找的文本"。
4. **`client.Count()` 输出:**  `DisplayLockTestFindInPageClient` 的 `Count()` 方法返回匹配项的数量 (至少为 1)。
5. **`client.ActiveIndex()` 输出:** `DisplayLockTestFindInPageClient` 的 `ActiveIndex()` 方法返回当前激活匹配项的索引 (通常为 1)。

**用户或编程常见的使用错误举例:**

1. **错误地假设非可激活锁定元素可以被 Find-in-Page 找到:**  用户可能会认为设置了 `content-visibility: hidden` 的元素仍然可以通过查找找到，但实际上会被忽略。
   ```html
   <div id="non-activatable" style="content-visibility: hidden;">这段文字找不到</div>
   <script>
     // 用户可能错误地认为这段代码会成功激活并滚动到该元素
     window.find("这段文字找不到");
   </script>
   ```

2. **忘记处理可激活锁定元素的解锁和滚动:**  开发者在使用 `hidden="until-found"` 时，需要意识到 Find-in-Page 会自动解锁并滚动元素。如果开发者有其他的交互逻辑依赖于元素是否隐藏，就需要考虑 Find-in-Page 的影响。

3. **在锁定元素内部进行不必要的 DOM 操作:** 虽然锁定元素可以提升性能，但在锁定的元素内部进行频繁的 DOM 操作可能仍然会导致性能问题，因为解锁后这些操作的影响需要重新计算。

**功能归纳 (针对第 1 部分):**

这部分 `display_lock_context_test.cc` 文件主要集中测试了 `DisplayLockContext` 类与 **Find-in-Page** 功能的集成。它验证了不同锁定状态的元素在 Find-in-Page 中的可搜索性、解锁行为、以及相关的渲染和生命周期管理，确保 Find-in-Page 功能能够正确地与显示锁定机制协同工作。

Prompt: 
```
这是目录为blink/renderer/core/display_lock/display_lock_context_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/display_lock/display_lock_context.h"

#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "base/test/scoped_feature_list.h"
#include "cc/base/features.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/finder/text_finder.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/find_in_page.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {
namespace {
class DisplayLockTestFindInPageClient : public mojom::blink::FindInPageClient {
 public:
  DisplayLockTestFindInPageClient()
      : find_results_are_ready_(false), active_index_(-1), count_(-1) {}

  ~DisplayLockTestFindInPageClient() override = default;

  void SetFrame(WebLocalFrameImpl* frame) {
    frame->GetFindInPage()->SetClient(receiver_.BindNewPipeAndPassRemote());
  }

  void SetNumberOfMatches(
      int request_id,
      unsigned int current_number_of_matches,
      mojom::blink::FindMatchUpdateType final_update) final {
    count_ = current_number_of_matches;
    find_results_are_ready_ =
        (final_update == mojom::blink::FindMatchUpdateType::kFinalUpdate);
  }

  void SetActiveMatch(int request_id,
                      const gfx::Rect& active_match_rect,
                      int active_match_ordinal,
                      mojom::blink::FindMatchUpdateType final_update) final {
    active_match_rect_ = active_match_rect;
    active_index_ = active_match_ordinal;
    find_results_are_ready_ =
        (final_update == mojom::blink::FindMatchUpdateType::kFinalUpdate);
  }

  bool FindResultsAreReady() const { return find_results_are_ready_; }
  int Count() const { return count_; }
  int ActiveIndex() const { return active_index_; }
  gfx::Rect ActiveMatchRect() const { return active_match_rect_; }

  void Reset() {
    find_results_are_ready_ = false;
    count_ = -1;
    active_index_ = -1;
    active_match_rect_ = gfx::Rect();
  }

 private:
  gfx::Rect active_match_rect_;
  bool find_results_are_ready_;
  int active_index_;

  int count_;
  mojo::Receiver<mojom::blink::FindInPageClient> receiver_{this};
};

class DisplayLockEmptyEventListener final : public NativeEventListener {
 public:
  void Invoke(ExecutionContext*, Event*) final {}
};
}  // namespace

class DisplayLockContextTest : public testing::Test {
 public:
  void SetUp() override { web_view_helper_.Initialize(); }

  void TearDown() override { web_view_helper_.Reset(); }

  Document& GetDocument() {
    return *static_cast<Document*>(
        web_view_helper_.LocalMainFrame()->GetDocument());
  }
  FindInPage* GetFindInPage() {
    return web_view_helper_.LocalMainFrame()->GetFindInPage();
  }
  WebLocalFrameImpl* LocalMainFrame() {
    return web_view_helper_.LocalMainFrame();
  }

  FrameSelection& Selection() {
    return LocalMainFrame()->GetFrame()->Selection();
  }

  void UpdateAllLifecyclePhasesForTest() {
    GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  }

  void SetHtmlInnerHTML(const char* content) {
    GetDocument().documentElement()->setInnerHTML(String::FromUTF8(content));
    UpdateAllLifecyclePhasesForTest();
  }

  void ResizeAndFocus() {
    web_view_helper_.Resize(gfx::Size(640, 480));
    web_view_helper_.GetWebView()->MainFrameWidget()->SetFocus(true);
    test::RunPendingTasks();
  }

  void LockElement(Element& element, bool activatable) {
    if (activatable) {
      element.setAttribute(html_names::kHiddenAttr,
                           AtomicString("until-found"));
    } else {
      element.setAttribute(html_names::kStyleAttr,
                           AtomicString("content-visibility: hidden"));
    }
    UpdateAllLifecyclePhasesForTest();
  }

  void CommitElement(Element& element, bool update_lifecycle = true) {
    element.setAttribute(html_names::kStyleAttr, g_empty_atom);
    if (update_lifecycle)
      UpdateAllLifecyclePhasesForTest();
  }

  void UnlockImmediate(DisplayLockContext* context) {
    context->SetRequestedState(EContentVisibility::kVisible);
  }

  mojom::blink::FindOptionsPtr FindOptions(bool new_session = true) {
    auto find_options = mojom::blink::FindOptions::New();
    find_options->run_synchronously_for_testing = true;
    find_options->new_session = new_session;
    find_options->forward = true;
    return find_options;
  }

  void Find(String search_text,
            DisplayLockTestFindInPageClient& client,
            bool new_session = true) {
    client.Reset();
    GetFindInPage()->Find(FAKE_FIND_ID, search_text, FindOptions(new_session));
    test::RunPendingTasks();
  }

  bool ReattachWasBlocked(DisplayLockContext* context) {
    return context->blocked_child_recalc_change_.ReattachLayoutTree();
  }

  bool HasSelection(DisplayLockContext* context) {
    return context->render_affecting_state_[static_cast<int>(
        DisplayLockContext::RenderAffectingState::kSubtreeHasSelection)];
  }
  DisplayLockUtilities::ScopedForcedUpdate GetScopedForcedUpdate(
      const Node* node,
      DisplayLockContext::ForcedPhase phase,
      bool include_self = false) {
    return DisplayLockUtilities::ScopedForcedUpdate(node, phase, include_self);
  }

  const int FAKE_FIND_ID = 1;

 private:
  test::TaskEnvironment task_environment;

  frame_test_helpers::WebViewHelper web_view_helper_;
};

TEST_F(DisplayLockContextTest, LockAfterAppendStyleDirtyBits) {
  SetHtmlInnerHTML(R"HTML(
    <style>
    div {
      width: 100px;
      height: 100px;
      contain: style layout paint;
    }
    </style>
    <body><div id="container"><div id="child"></div></div></body>
  )HTML");

  auto* element = GetDocument().getElementById(AtomicString("container"));
  LockElement(*element, false);

  // Finished acquiring the lock.
  EXPECT_FALSE(element->GetDisplayLockContext()->ShouldStyleChildren());
  EXPECT_FALSE(element->GetDisplayLockContext()->ShouldLayoutChildren());
  EXPECT_FALSE(element->GetDisplayLockContext()->ShouldPaintChildren());
  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 1);

  // If the element is dirty, style recalc would handle it in the next recalc.
  element->setAttribute(
      html_names::kStyleAttr,
      AtomicString("content-visibility: hidden; color: red;"));
  EXPECT_TRUE(GetDocument().body()->ChildNeedsStyleRecalc());
  EXPECT_TRUE(element->NeedsStyleRecalc());
  EXPECT_FALSE(element->ChildNeedsStyleRecalc());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(element->NeedsStyleRecalc());
  EXPECT_FALSE(element->ChildNeedsStyleRecalc());
  EXPECT_TRUE(element->GetComputedStyle());
  EXPECT_EQ(
      element->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()),
      Color::FromRGB(255, 0, 0));
  // Manually commit the lock so that we can verify which dirty bits get
  // propagated.
  UnlockImmediate(element->GetDisplayLockContext());
  element->setAttribute(html_names::kStyleAttr, AtomicString("color: red;"));

  auto* child = GetDocument().getElementById(AtomicString("child"));
  EXPECT_TRUE(GetDocument().body()->ChildNeedsStyleRecalc());
  EXPECT_TRUE(element->NeedsStyleRecalc());
  EXPECT_FALSE(element->ChildNeedsStyleRecalc());
  EXPECT_FALSE(child->NeedsStyleRecalc());
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(GetDocument().body()->ChildNeedsStyleRecalc());
  EXPECT_FALSE(element->NeedsStyleRecalc());
  EXPECT_FALSE(element->ChildNeedsStyleRecalc());
  EXPECT_FALSE(child->NeedsStyleRecalc());

  // Lock the child.
  child->setAttribute(html_names::kStyleAttr,
                      AtomicString("content-visibility: hidden; color: blue;"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(GetDocument().body()->ChildNeedsStyleRecalc());
  EXPECT_FALSE(element->NeedsStyleRecalc());
  EXPECT_FALSE(element->ChildNeedsStyleRecalc());
  EXPECT_FALSE(child->NeedsStyleRecalc());
  ASSERT_TRUE(child->GetComputedStyle());
  EXPECT_EQ(
      child->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()),
      Color::FromRGB(0, 0, 255));

  UnlockImmediate(child->GetDisplayLockContext());
  child->setAttribute(html_names::kStyleAttr, AtomicString("color: blue;"));
  EXPECT_TRUE(GetDocument().body()->ChildNeedsStyleRecalc());
  EXPECT_FALSE(element->NeedsStyleRecalc());
  EXPECT_TRUE(element->ChildNeedsStyleRecalc());
  EXPECT_TRUE(child->NeedsStyleRecalc());
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(GetDocument().body()->ChildNeedsStyleRecalc());
  EXPECT_FALSE(element->NeedsStyleRecalc());
  EXPECT_FALSE(element->ChildNeedsStyleRecalc());
  EXPECT_FALSE(child->NeedsStyleRecalc());
  ASSERT_TRUE(child->GetComputedStyle());
  EXPECT_EQ(
      child->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()),
      Color::FromRGB(0, 0, 255));
}

TEST_F(DisplayLockContextTest, LockedElementIsNotSearchableViaFindInPage) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    #container {
      width: 100px;
      height: 100px;
      contain: style layout paint;
    }
    </style>
    <body><div id="container">testing</div></body>
  )HTML");

  const String search_text = "testing";
  DisplayLockTestFindInPageClient client;
  client.SetFrame(LocalMainFrame());

  auto* container = GetDocument().getElementById(AtomicString("container"));
  LockElement(*container, false /* activatable */);
  Find(search_text, client);
  EXPECT_EQ(0, client.Count());

  // Check if we can find the result after we commit.
  CommitElement(*container);
  Find(search_text, client);
  EXPECT_EQ(1, client.Count());
}

TEST_F(DisplayLockContextTest,
       ActivatableLockedElementIsSearchableViaFindInPage) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    .spacer {
      height: 10000px;
    }
    #container {
      width: 100px;
      height: 100px;
      contain: style layout paint;
    }
    </style>
    <body><div class=spacer></div><div id="container">testing</div></body>
  )HTML");

  const String search_text = "testing";
  DisplayLockTestFindInPageClient client;
  client.SetFrame(LocalMainFrame());

  // Finds on a normal element.
  Find(search_text, client);
  EXPECT_EQ(1, client.Count());
  // Clears selections since we're going to use the same query next time.
  GetFindInPage()->StopFinding(
      mojom::StopFindAction::kStopFindActionClearSelection);

  auto* container = GetDocument().getElementById(AtomicString("container"));
  LockElement(*container, true /* activatable */);

  EXPECT_TRUE(container->GetDisplayLockContext()->IsLocked());
  // Check if we can still get the same result with the same query.
  Find(search_text, client);
  EXPECT_EQ(1, client.Count());
  EXPECT_FALSE(container->GetDisplayLockContext()->IsLocked());
  EXPECT_GT(GetDocument().scrollingElement()->scrollTop(), 1000);
}

TEST_F(DisplayLockContextTest, FindInPageContinuesAfterRelock) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    .spacer {
      height: 10000px;
    }
    #container {
      width: 100px;
      height: 100px;
    }
    .auto { content-visibility: auto }
    </style>
    <body><div class=spacer></div><div id="container" class=auto>testing</div></body>
  )HTML");

  const String search_text = "testing";
  DisplayLockTestFindInPageClient client;
  client.SetFrame(LocalMainFrame());

  // Finds on a normal element.
  Find(search_text, client);
  EXPECT_EQ(1, client.Count());

  auto* container = GetDocument().getElementById(AtomicString("container"));
  GetDocument().scrollingElement()->setScrollTop(0);

  UpdateAllLifecyclePhasesForTest();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(container->GetDisplayLockContext()->IsLocked());

  // Clears selections since we're going to use the same query next time.
  GetFindInPage()->StopFinding(
      mojom::StopFindAction::kStopFindActionKeepSelection);

  UpdateAllLifecyclePhasesForTest();

  // This should not crash.
  Find(search_text, client, false);

  EXPECT_EQ(1, client.Count());
}

TEST_F(DisplayLockContextTest, FindInPageTargetBelowLockedSize) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    .spacer { height: 1000px; }
    #container { contain-intrinsic-size: 1px; }
    .auto { content-visibility: auto }
    </style>
    <body>
      <div class=spacer></div>
      <div id=container class=auto>
        <div class=spacer></div>
        <div id=target>testing</div>
      </div>
      <div class=spacer></div>
      <div class=spacer></div>
    </body>
  )HTML");

  const String search_text = "testing";
  DisplayLockTestFindInPageClient client;
  client.SetFrame(LocalMainFrame());

  Find(search_text, client);
  EXPECT_EQ(1, client.Count());

  auto* container = GetDocument().getElementById(AtomicString("container"));
  // The container should be unlocked.
  EXPECT_FALSE(container->GetDisplayLockContext()->IsLocked());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(container->GetDisplayLockContext()->IsLocked());

  if (RuntimeEnabledFeatures::FractionalScrollOffsetsEnabled())
    EXPECT_FLOAT_EQ(GetDocument().scrollingElement()->scrollTop(), 1768.5);
  else
    EXPECT_FLOAT_EQ(GetDocument().scrollingElement()->scrollTop(), 1768);
}

TEST_F(DisplayLockContextTest,
       ActivatableLockedElementTickmarksAreAtLockedRoots) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    body {
      margin: 0;
      padding: 0;
    }
    .small {
      width: 100px;
      height: 100px;
    }
    .medium {
      width: 150px;
      height: 150px;
    }
    .large {
      width: 200px;
      height: 200px;
    }
    </style>
    <body>
      testing
      <div id="container1" class=small>testing</div>
      <div id="container2" class=medium>testing</div>
      <div id="container3" class=large>
        <div id="container4" class=medium>testing</div>
      </div>
      <div id="container5" class=small>testing</div>
    </body>
  )HTML");

  const String search_text = "testing";
  DisplayLockTestFindInPageClient client;
  client.SetFrame(LocalMainFrame());

  auto* container1 = GetDocument().getElementById(AtomicString("container1"));
  auto* container2 = GetDocument().getElementById(AtomicString("container2"));
  auto* container3 = GetDocument().getElementById(AtomicString("container3"));
  auto* container4 = GetDocument().getElementById(AtomicString("container4"));
  auto* container5 = GetDocument().getElementById(AtomicString("container5"));
  LockElement(*container5, false /* activatable */);
  LockElement(*container4, true /* activatable */);
  LockElement(*container3, true /* activatable */);
  LockElement(*container2, true /* activatable */);
  LockElement(*container1, true /* activatable */);

  EXPECT_TRUE(container1->GetDisplayLockContext()->IsLocked());
  EXPECT_TRUE(container2->GetDisplayLockContext()->IsLocked());
  EXPECT_TRUE(container3->GetDisplayLockContext()->IsLocked());
  EXPECT_TRUE(container4->GetDisplayLockContext()->IsLocked());
  EXPECT_TRUE(container5->GetDisplayLockContext()->IsLocked());

  // Do a find-in-page.
  Find(search_text, client);
  // "testing" outside of the container divs, and 3 inside activatable divs.
  EXPECT_EQ(4, client.Count());

  auto tick_rects = GetDocument().Markers().LayoutRectsForTextMatchMarkers();
  ASSERT_EQ(4u, tick_rects.size());

  // Sort the layout rects by y coordinate for deterministic checks below.
  std::sort(
      tick_rects.begin(), tick_rects.end(),
      [](const gfx::Rect& a, const gfx::Rect& b) { return a.y() < b.y(); });

  int y_offset = tick_rects[0].height();

  // The first tick rect will be based on the text itself, so we don't need to
  // check that. The next three should be the small, medium and large rects,
  // since those are the locked roots.
  EXPECT_EQ(gfx::Rect(0, y_offset, 100, 100), tick_rects[1]);
  y_offset += tick_rects[1].height();
  EXPECT_EQ(gfx::Rect(0, y_offset, 150, 150), tick_rects[2]);
  y_offset += tick_rects[2].height();
  EXPECT_EQ(gfx::Rect(0, y_offset, 200, 200), tick_rects[3]);
}

TEST_F(DisplayLockContextTest,
       FindInPageWhileLockedContentChangesDoesNotCrash) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    #container {
      width: 100px;
      height: 100px;
      contain: style layout paint;
    }
    </style>
    <body>testing<div id="container">testing</div></body>
  )HTML");

  const String search_text = "testing";
  DisplayLockTestFindInPageClient client;
  client.SetFrame(LocalMainFrame());

  // Lock the container.
  auto* container = GetDocument().getElementById(AtomicString("container"));
  LockElement(*container, true /* activatable */);
  EXPECT_TRUE(container->GetDisplayLockContext()->IsLocked());

  // Find the first "testing", container still locked since the match is outside
  // the container.
  Find(search_text, client);
  EXPECT_EQ(2, client.Count());
  EXPECT_TRUE(container->GetDisplayLockContext()->IsLocked());

  // Change the inner text, this should not DCHECK.
  container->setInnerHTML("please don't DCHECK");
  UpdateAllLifecyclePhasesForTest();
}

TEST_F(DisplayLockContextTest, FindInPageWithChangedContent) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    #container {
      width: 100px;
      height: 100px;
      contain: style layout paint;
    }
    </style>
    <body><div id="container">testing</div></body>
  )HTML");

  // Check if the result is correct if we update the contents.
  auto* container = GetDocument().getElementById(AtomicString("container"));
  LockElement(*container, true /* activatable */);
  EXPECT_TRUE(container->GetDisplayLockContext()->IsLocked());
  container->setInnerHTML(
      "testing"
      "<div>testing</div>"
      "tes<div style='display:none;'>x</div>ting");

  DisplayLockTestFindInPageClient client;
  client.SetFrame(LocalMainFrame());
  Find("testing", client);
  EXPECT_EQ(3, client.Count());
  EXPECT_FALSE(container->GetDisplayLockContext()->IsLocked());
}

TEST_F(DisplayLockContextTest, FindInPageWithNoMatchesWontUnlock) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    #container {
      width: 100px;
      height: 100px;
      contain: style layout paint;
    }
    </style>
    <body><div id="container">tes<div>ting</div><div style='display:none;'>testing</div></div></body>
  )HTML");

  auto* container = GetDocument().getElementById(AtomicString("container"));
  LockElement(*container, true /* activatable */);
  LockElement(*container, true /* activatable */);
  EXPECT_TRUE(container->GetDisplayLockContext()->IsLocked());

  DisplayLockTestFindInPageClient client;
  client.SetFrame(LocalMainFrame());
  Find("testing", client);
  // No results found, container stays locked.
  EXPECT_EQ(0, client.Count());
  EXPECT_TRUE(container->GetDisplayLockContext()->IsLocked());
}

TEST_F(DisplayLockContextTest,
       NestedActivatableLockedElementIsSearchableViaFindInPage) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <body>
      <style>
        div {
          width: 100px;
          height: 100px;
          contain: style layout;
        }
      </style>
      <div id='container'>
        <div>testing1</div>
        <div id='activatable'>
        testing2
          <div id='nestedNonActivatable'>
            testing3
          </div>
        </div>
        <div id='nonActivatable'>testing4</div>
      </div>
    "</body>"
  )HTML");

  auto* container = GetDocument().getElementById(AtomicString("container"));
  auto* activatable = GetDocument().getElementById(AtomicString("activatable"));
  auto* non_activatable =
      GetDocument().getElementById(AtomicString("nonActivatable"));
  auto* nested_non_activatable =
      GetDocument().getElementById(AtomicString("nestedNonActivatable"));

  LockElement(*non_activatable, false /* activatable */);
  LockElement(*nested_non_activatable, false /* activatable */);
  LockElement(*activatable, true /* activatable */);
  LockElement(*container, true /* activatable */);

  EXPECT_TRUE(container->GetDisplayLockContext()->IsLocked());
  EXPECT_TRUE(activatable->GetDisplayLockContext()->IsLocked());
  EXPECT_TRUE(non_activatable->GetDisplayLockContext()->IsLocked());
  EXPECT_TRUE(nested_non_activatable->GetDisplayLockContext()->IsLocked());

  // We can find testing1 and testing2.
  DisplayLockTestFindInPageClient client;
  client.SetFrame(LocalMainFrame());
  Find("testing", client);
  EXPECT_EQ(2, client.Count());
  EXPECT_EQ(1, client.ActiveIndex());

  EXPECT_FALSE(container->GetDisplayLockContext()->IsLocked());
  EXPECT_TRUE(activatable->GetDisplayLockContext()->IsLocked());
  EXPECT_TRUE(non_activatable->GetDisplayLockContext()->IsLocked());
  EXPECT_TRUE(nested_non_activatable->GetDisplayLockContext()->IsLocked());
}

TEST_F(DisplayLockContextTest,
       NestedActivatableLockedElementIsNotUnlockedByFindInPage) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <body>
      <style>
        div {
          width: 100px;
          height: 100px;
          contain: style layout;
        }
      </style>
      <div id='container'>
        <div id='child'>testing1</div>
      </div>
  )HTML");
  auto* container = GetDocument().getElementById(AtomicString("container"));
  auto* child = GetDocument().getElementById(AtomicString("child"));
  LockElement(*child, true /* activatable */);
  LockElement(*container, true /* activatable */);

  EXPECT_TRUE(container->GetDisplayLockContext()->IsLocked());
  EXPECT_TRUE(child->GetDisplayLockContext()->IsLocked());
  // We can find testing1 and testing2.
  DisplayLockTestFindInPageClient client;
  client.SetFrame(LocalMainFrame());
  Find("testing", client);
  EXPECT_EQ(1, client.Count());
  EXPECT_EQ(1, client.ActiveIndex());

  EXPECT_FALSE(container->GetDisplayLockContext()->IsLocked());
  EXPECT_FALSE(child->GetDisplayLockContext()->IsLocked());
}

TEST_F(DisplayLockContextTest, CallUpdateStyleAndLayoutAfterChange) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    #container {
      width: 100px;
      height: 100px;
      contain: style layout paint;
    }
    </style>
    <body><div id="container"><b>t</b>esting</div></body>
  )HTML");
  auto* element = GetDocument().getElementById(AtomicString("container"));
  LockElement(*element, false);

  // Sanity checks to ensure the element is locked.
  EXPECT_TRUE(element->GetDisplayLockContext()->IsLocked());
  EXPECT_FALSE(element->GetDisplayLockContext()->ShouldStyleChildren());
  EXPECT_FALSE(element->GetDisplayLockContext()->ShouldLayoutChildren());
  EXPECT_FALSE(element->GetDisplayLockContext()->ShouldPaintChildren());
  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 1);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            1);

  EXPECT_FALSE(element->NeedsStyleRecalc());
  EXPECT_FALSE(element->ChildNeedsStyleRecalc());
  EXPECT_FALSE(element->NeedsReattachLayoutTree());
  EXPECT_FALSE(element->ChildNeedsReattachLayoutTree());

  // Testing whitespace reattachment, shouldn't mark for reattachment.
  element->firstChild()->remove();

  EXPECT_FALSE(element->NeedsStyleRecalc());
  EXPECT_FALSE(element->ChildNeedsStyleRecalc());
  EXPECT_FALSE(element->NeedsReattachLayoutTree());
  EXPECT_FALSE(element->ChildNeedsReattachLayoutTree());

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  EXPECT_FALSE(element->NeedsStyleRecalc());
  EXPECT_FALSE(element->ChildNeedsStyleRecalc());
  EXPECT_FALSE(element->NeedsReattachLayoutTree());
  EXPECT_FALSE(element->ChildNeedsReattachLayoutTree());

  // Testing whitespace reattachment + dirty style.
  element->setInnerHTML("<div>something</div>");

  EXPECT_FALSE(element->NeedsStyleRecalc());
  EXPECT_TRUE(element->ChildNeedsStyleRecalc());
  EXPECT_FALSE(element->NeedsReattachLayoutTree());
  EXPECT_FALSE(element->ChildNeedsReattachLayoutTree());

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  EXPECT_FALSE(element->NeedsStyleRecalc());
  EXPECT_TRUE(element->ChildNeedsStyleRecalc());
  EXPECT_FALSE(element->NeedsReattachLayoutTree());
  EXPECT_FALSE(element->ChildNeedsReattachLayoutTree());

  // Manually start commit, so that we can verify which dirty bits get
  // propagated.
  CommitElement(*element, false);
  EXPECT_TRUE(element->NeedsStyleRecalc());
  EXPECT_TRUE(element->ChildNeedsStyleRecalc());
  EXPECT_TRUE(GetDocument().body()->ChildNeedsStyleRecalc());
  EXPECT_FALSE(element->NeedsReattachLayoutTree());
  EXPECT_FALSE(element->ChildNeedsReattachLayoutTree());

  // Simulating style recalc happening, will mark for reattachment.
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  GetDocument().GetStyleEngine().RecalcStyle();
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kStyleClean);

  EXPECT_FALSE(element->ChildNeedsStyleRecalc());
  EXPECT_FALSE(element->NeedsReattachLayoutTree());
  EXPECT_TRUE(element->ChildNeedsReattachLayoutTree());
}

TEST_F(DisplayLockContextTest, CallUpdateStyleAndLayoutAfterChangeCSS) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    #container {
      width: 100px;
      height: 100px;
      contain: style layout paint;
    }
    .bg {
      background: blue;
    }
    .locked {
      content-visibility: hidden;
    }
    </style>
    <body><div class=locked id="container"><b>t</b>esting<div id=inner></div></div></body>
  )HTML");
  auto* element = GetDocument().getElementById(AtomicString("container"));
  auto* inner = GetDocument().getElementById(AtomicString("inner"));

  // Sanity checks to ensure the element is locked.
  EXPECT_FALSE(element->GetDisplayLockContext()->ShouldStyleChildren());
  EXPECT_FALSE(element->GetDisplayLockContext()->ShouldLayoutChildren());
  EXPECT_FALSE(element->GetDisplayLockContext()->ShouldPaintChildren());
  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 1);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            1);

  EXPECT_TRUE(ReattachWasBlocked(element->GetDisplayLockContext()));
  // Note that we didn't create a layout object for inner, since the layout tree
  // attachment was blocked.
  EXPECT_FALSE(inner->GetLayoutObject());

  EXPECT_FALSE(element->NeedsStyleRecalc());
  EXPECT_FALSE(element->ChildNeedsStyleRecalc());
  EXPECT_FALSE(element->NeedsReattachLayoutTree());
  EXPECT_FALSE(element->ChildNeedsReattachLayoutTree());

  element->classList().Remove(AtomicString("locked"));

  // Class list changed, so we should need self style change.
  EXPECT_TRUE(element->NeedsStyleRecalc());
  EXPECT_FALSE(element->ChildNeedsStyleRecalc());
  EXPECT_FALSE(element->NeedsReattachLayoutTree());
  EXPECT_FALSE(element->ChildNeedsReattachLayoutTree());

  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(element->NeedsStyleRecalc());
  EXPECT_FALSE(element->ChildNeedsStyleRecalc());
  EXPECT_FALSE(element->NeedsReattachLayoutTree());
  EXPECT_FALSE(element->ChildNeedsReattachLayoutTree());
  // Because we upgraded our style change, we created a layout object for inner.
  EXPECT_TRUE(inner->GetLayoutObject());
}

TEST_F(DisplayLockContextTest, LockedElementAndDescendantsAreNotFocusable) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    #container {
      width: 100px;
      height: 100px;
      contain: style layout paint;
    }
    </style>
    <body>
    <div id="container">
      <input id="textfield", type="text">
    </div>
    </body>
  )HTML");

  // We start off as being focusable.
  ASSERT_TRUE(GetDocument()
                  .getElementById(AtomicString("textfield"))
                  ->IsKeyboardFocusable());
  ASSERT_TRUE(
      GetDocument().getElementById(AtomicString("textfield"))->IsFocusable());
  ASSERT_TRUE(
      GetDocument().getElementById(AtomicString("textfield"))->IsFocusable());
  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 0);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            0);

  auto* element = GetDocument().getElementById(AtomicString("container"));
  LockElement(*element, false);

  // Sanity checks to ensure the element is locked.
  EXPECT_FALSE(element->GetDisplayLockContext()->ShouldStyleChildren());
  EXPECT_FALSE(element->GetDisplayLockContext()->ShouldLayoutChildren());
  EXPECT_FALSE(element->GetDisplayLockContext()->ShouldPaintChildren());
  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 1);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            1);

  // The input should not be focusable now.
  EXPECT_FALSE(GetDocument()
                   .getElementById(AtomicString("textfield"))
                   ->IsKeyboardFocusable());
  EXPECT_FALSE(
      GetDocument().getElementById(AtomicString("textfield"))->IsFocusable());
  EXPECT_FALSE(
      GetDocument().getElementById(AtomicString("textfield"))->IsFocusable());

  // Calling explicit focus() should also not focus the element.
  GetDocument().getElementById(AtomicString("textfield"))->Focus();
  EXPECT_FALSE(GetDocument().FocusedElement());

  // Now commit the lock and ensure we can focus the input
  CommitElement(*element);

  EXPECT_TRUE(element->GetDisplayLockContext()->ShouldStyleChildren());
  EXPECT_TRUE(element->GetDisplayLockContext()->ShouldLayoutChildren());
  EXPECT_TRUE(element->GetDisplayLockContext()->ShouldPaintChildren());

  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 0);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            0);
  EXPECT_TRUE(GetDocument()
                  .getElementById(AtomicString("textfield"))
                  ->IsKeyboardFocusable());
  EXPECT_TRUE(
      GetDocument().getElementById(AtomicString("textfield"))->IsFocusable());
  EXPECT_TRUE(
      GetDocument().getElementById(AtomicString("textfield"))->IsFocusable());

  // Calling explicit focus() should focus the element
  GetDocument().getElementById(AtomicString("textfield"))->Focus();
  EXPECT_EQ(GetDocument().FocusedElement(),
            GetDocument().getElementById(AtomicString("textfield")));
}

TEST_F(DisplayLockContextTest, DisplayLockPreventsActivation) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <body>
    <div id="shadowHost">
      <div id="slotted"></div>
    </div>
    </body>
  )HTML");

  auto* host = GetDocument().getElementById(AtomicString("shadowHost"));
  auto* slotted = GetDocument().getElementById(AtomicString("slotted"));

  ASSERT_FALSE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
      *host, DisplayLockActivationReason::kAny));
"""


```