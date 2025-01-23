Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of a test file for the Chromium Blink engine related to layout shift tracking.

To fulfill the request, I need to:

1. **Summarize the overall purpose of the code:**  It tests the `LayoutShiftTracker` class in Blink.
2. **Identify how the tests relate to web technologies (JavaScript, HTML, CSS):** The tests manipulate the DOM structure and CSS properties to simulate scenarios that can cause layout shifts.
3. **Explain the logic of each test case:**  Describe the setup, actions, and expected outcomes.
4. **Provide examples of user/programming errors related to layout shifts:** Think about common causes of unexpected layout changes on web pages.
这是对 `blink/renderer/core/layout/layout_shift_tracker_test.cc` 文件第二部分的分析和总结。

**功能归纳:**

这部分代码延续了第一部分的功能，主要用于测试 Blink 引擎中 `LayoutShiftTracker` 类的各种场景和行为。`LayoutShiftTracker` 负责跟踪页面布局的意外移动，并计算累积布局偏移分数 (CLS)。  这部分测试涵盖了更多复杂的布局场景，特别是与 `content-visibility` 属性、固定定位、可视视口、滚动锚定以及不同类型的 HTML 元素相关的布局偏移。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这些测试直接通过 JavaScript 操作 DOM (Document Object Model) 结构，设置 HTML 元素的属性和 CSS 样式，以模拟各种可能导致布局偏移的场景。

* **HTML:**  HTML 结构定义了页面内容和元素的层级关系，是布局的基础。测试用例中通过 `SetBodyInnerHTML` 和 `SetHtmlInnerHTML` 设置不同的 HTML 结构，例如包含嵌套的 `div` 元素，设置特定的 `id` 属性以便后续操作。
    ```html
    <div id=target class=auto>
      <div style="width: 100px; height: 100px; background: blue"></div>
    </div>
    ```
* **CSS:** CSS 样式规则控制元素的视觉呈现和布局方式。测试用例中大量使用了 CSS 属性，例如 `position: fixed`, `content-visibility`, `width`, `height`, `top`, `left`, `background`, `border`, `outline`, `box-shadow`, `animation`, `translate` 等，来创建特定的布局情境，并验证 `LayoutShiftTracker` 是否能正确检测到由这些样式变化引起的布局偏移。
    ```css
    .auto {
      content-visibility: hidden;
      contain-intrinsic-size: 1px;
      width: 100px;
    }
    ```
* **JavaScript:** JavaScript 用于动态地修改 DOM 和 CSS，触发布局更新。测试用例中使用了 `GetElementById`, `setAttribute`, `classList.Remove`, `classList.Add`, `scrollTo`, `scrollBy` 等 JavaScript API 来改变元素的状态和样式，并模拟用户的交互行为（例如滚动）。
    ```javascript
    GetElementById("target")->setAttribute(html_names::kStyleAttr, AtomicString("top: 100px"));
    GetDocument().domWindow()->scrollTo(0, 100000 + 100);
    ```

**逻辑推理、假设输入与输出:**

以下是部分测试用例的逻辑推理和假设输入输出：

* **`ContentVisibilityHiddenFirstPaint`:**
    * **假设输入:**  HTML 包含一个设置了 `content-visibility: hidden` 的 `div` 元素。
    * **逻辑推理:**  初始渲染时，由于 `content-visibility: hidden`，该元素及其子树被跳过，不参与布局偏移的计算。
    * **预期输出:** `GetLayoutShiftTracker().Score()` 为 0，该元素的尺寸由 `contain-intrinsic-size` 决定。

* **`ContentVisibilityAutoResize`:**
    * **假设输入:** HTML 包含设置了 `content-visibility: auto` 的 `div` 元素。
    * **逻辑推理:**  初始渲染时，虽然设置了 `content-visibility: auto`，但由于还没有进入可视区域，子树可能被跳过，布局偏移分数为 0。当元素进入可视区域后，可能会重新渲染。
    * **预期输出:** 初始 `GetLayoutShiftTracker().Score()` 为 0，元素的尺寸可能由 `contain-intrinsic-size` 决定，或者在重新渲染后根据内容调整。

* **`ContentVisibilityAutoOnscreenAndOffscreenAfterScrollFirstPaint`:**
    * **假设输入:** HTML 包含两个设置了 `content-visibility: auto` 的 `div` 元素，一个初始在屏幕内，一个在屏幕外。
    * **逻辑推理:**  初始渲染时，屏幕外的元素被跳过，不计入 CLS。当通过滚动使其进入屏幕后，会经历一个从跳过到不跳过的过程，并可能触发重新布局。在元素移动后，会计算布局偏移。当元素再次滚出屏幕，可能会恢复跳过状态。
    * **预期输出:**  初始 `GetLayoutShiftTracker().Score()` 为 0。滚动后，分数仍然为 0，直到元素实际发生移动。元素移动后，分数会大于 0。再次滚出屏幕后，分数保持不变，但元素的尺寸可能因为跳过状态而改变。

* **`ClipByVisualViewport`:**
    * **假设输入:** HTML 包含一个绝对定位的元素，并且设置了视口元数据和初始的视觉视口大小和位置。然后，通过 JavaScript 修改该元素的 `top` 属性。
    * **逻辑推理:**  布局偏移的计算需要考虑元素在视觉视口内的可见部分。当元素移动时，只有可见部分的移动才会被计算在内。
    * **预期输出:**  初始 `GetLayoutShiftTracker().Score()` 为 0。修改 `top` 属性后，分数会根据可见区域的移动距离和视觉视口的面积计算出来。计算公式中包含了可见宽度、高度变化以及视觉视口的面积。

* **`ScrollThenCauseScrollAnchoring`:**
    * **假设输入:** HTML 包含一系列 `div` 元素，其中一个带有 `id="target"`。先滚动窗口，然后修改 `#target` 元素的 class，导致其尺寸变化。
    * **逻辑推理:**  滚动操作本身会记录滚动偏移，但这里主要测试的是滚动锚定的行为。当内容在滚动容器中发生变化导致其他内容移动时，如果浏览器支持滚动锚定，则会尝试调整滚动位置以减少用户的视觉干扰，这种调整不应计入 CLS。
    * **预期输出:**  滚动后，`GetLayoutShiftTracker().Score()` 仍然为 0。修改 `#target` 的 class 后，由于滚动锚定的作用，分数仍然为 0。

* **`NeedsToTrack`:**
    * **假设输入:** HTML 包含各种不同类型的元素，例如小尺寸元素、sticky 定位元素、带有装饰的块级元素、包含隐藏或可见子元素的块级和内联元素、SVG 元素、替换元素和特殊块级元素。
    * **逻辑推理:**  `NeedsToTrack` 函数判断一个 `LayoutObject` 是否需要被布局偏移跟踪器跟踪。不同的元素类型和样式可能会影响是否需要跟踪。例如，非常小的元素或 sticky 定位的元素可能不需要跟踪。带有背景、边框、轮廓或阴影的元素以及包含其他可见子元素的元素通常需要跟踪。
    * **预期输出:**  根据元素的类型和样式，`tracker.NeedsToTrack()` 返回 `true` 或 `false`。

* **`AnimatingTransformCreatesLayoutShiftRoot`:**
    * **假设输入:** HTML 包含一个应用了动画 `transform` 属性的父元素和一个子元素。然后，通过 JavaScript 修改父元素的 `top` 属性，并修改子元素的 `top` 属性。
    * **逻辑推理:**  应用了动画 `transform` 的元素会创建一个新的布局偏移根。这意味着其子元素的布局偏移是相对于该根计算的，父元素的移动不会直接导致子元素产生大的布局偏移。只有子元素相对于父元素的移动才会被计算，但如果移动量很小，可能低于阈值而不被记录。
    * **预期输出:**  初始 `GetLayoutShiftTracker().Score()` 为 0。修改父元素的 `top` 属性后，分数仍然为 0。修改子元素的 `top` 属性后，如果移动量足够小（如 2px），分数仍然为 0。

**涉及用户或者编程常见的使用错误:**

* **忘记设置 `contain-intrinsic-size` 导致 `content-visibility: auto` 元素尺寸突变:** 当使用 `content-visibility: auto` 时，如果没有设置 `contain-intrinsic-size`，元素在初始渲染时可能尺寸为 0，当进入视口后突然膨胀，导致明显的布局偏移。
    ```html
    <!-- 错误示例 -->
    <div style="content-visibility: auto;">
      <img src="long-image.jpg">
    </div>

    <!-- 正确示例 -->
    <div style="content-visibility: auto; contain-intrinsic-size: 500px;">
      <img src="long-image.jpg">
    </div>
    ```
* **在滚动事件中直接修改 DOM 导致不必要的布局偏移:**  在滚动事件处理函数中修改 DOM 结构或样式，会导致浏览器重新布局和重绘，如果这些修改导致页面元素的位置或尺寸发生变化，就会产生布局偏移。应该尽量避免在滚动处理函数中进行此类操作，或者使用节流或防抖技术优化。
    ```javascript
    window.addEventListener('scroll', () => {
      // 错误示例：直接修改 DOM
      document.getElementById('myElement').style.top = window.scrollY + 'px';
    });
    ```
* **在可视视口变化时没有考虑到布局偏移的影响:**  例如，在移动设备上，地址栏的显示和隐藏会导致可视视口的高度变化，如果没有妥善处理，可能会导致页面元素向上或向下移动，产生布局偏移。可以使用 CSS 的 `viewport-fit=cover` 和 `safe-area-inset-*` 属性来更好地控制页面在不同视口下的布局。
* **动画不使用 `transform` 属性:**  对元素的位置或尺寸进行动画时，如果直接修改 `top`, `left`, `width`, `height` 等属性，会导致布局发生变化，从而产生布局偏移。应该优先使用 `transform` 属性（例如 `translate`, `scale`）进行动画，因为这些变换不会触发布局。
    ```css
    /* 错误示例：触发布局 */
    .animate-position {
      animation: move 1s infinite alternate;
    }
    @keyframes move {
      from { top: 0; }
      to { top: 100px; }
    }

    /* 正确示例：不触发布局 */
    .animate-position {
      animation: move-transform 1s infinite alternate;
    }
    @keyframes move-transform {
      from { transform: translateY(0); }
      to { transform: translateY(100px); }
    }
    ```

总而言之，这部分测试用例深入验证了 `LayoutShiftTracker` 在处理各种复杂的布局场景下的准确性和鲁棒性，涵盖了现代 Web 开发中常见的 CSS 属性和用户交互模式。理解这些测试用例有助于开发者更好地理解布局偏移的原理，并避免在实际开发中引入不必要的布局偏移，从而提升用户体验。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_shift_tracker_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
esForTest();
  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());
  EXPECT_EQ(PhysicalSize(100, 1), target->Size());

  // Now the subtree is unskipped, and #target renders at size 100x100.
  // Nevertheless, there is no impact on CLS.
  UpdateAllLifecyclePhasesForTest();
  // Target's LayoutObject gets re-attached.
  target = To<LayoutBox>(GetLayoutObjectByElementId("target"));
  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());
  EXPECT_EQ(PhysicalSize(100, 100), target->Size());
}

TEST_F(LayoutShiftTrackerTest, ContentVisibilityHiddenFirstPaint) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .auto {
        content-visibility: hidden;
        contain-intrinsic-size: 1px;
        width: 100px;
      }
    </style>
    <div id=target class=auto>
      <div style="width: 100px; height: 100px; background: blue"></div>
    </div>
  )HTML");
  auto* target = To<LayoutBox>(GetLayoutObjectByElementId("target"));

  // Skipped subtrees don't cause CLS impact.
  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());
  EXPECT_EQ(PhysicalSize(100, 1), target->Size());
}

TEST_F(LayoutShiftTrackerTest, ContentVisibilityAutoResize) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .auto {
        content-visibility: auto;
        contain-intrinsic-size: 10px 3000px;
        width: 100px;
      }
      .contained {
        height: 100px;
        background: blue;
      }
    </style>
    <div class=auto><div class=contained></div></div>
    <div class=auto id=target><div class=contained></div></div>
  )HTML");

  // Skipped subtrees don't cause CLS impact.
  UpdateAllLifecyclePhasesForTest();
  auto* target = To<LayoutBox>(GetLayoutObjectByElementId("target"));
  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());
  EXPECT_EQ(PhysicalSize(100, 100), target->Size());
}

TEST_F(LayoutShiftTrackerTest,
       ContentVisibilityAutoOnscreenAndOffscreenAfterScrollFirstPaint) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .auto {
        content-visibility: auto;
        contain-intrinsic-size: 1px;
        width: 100px;
      }
    </style>
    <div id=onscreen class=auto>
      <div style="width: 100px; height: 100px; background: blue"></div>
    </div>
    <div id=offscreen class=auto style="position: relative; top: 100000px">
      <div style="width: 100px; height: 100px; background: blue"></div>
    </div>
  )HTML");
  auto* offscreen = To<LayoutBox>(GetLayoutObjectByElementId("offscreen"));
  auto* onscreen = To<LayoutBox>(GetLayoutObjectByElementId("onscreen"));

  // #offscreen starts offsceen, which doesn't count for CLS.
  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());
  EXPECT_EQ(PhysicalSize(100, 1), offscreen->Size());
  EXPECT_EQ(PhysicalSize(100, 100), onscreen->Size());

  // In the next frame, we scroll it onto the screen, but it still doesn't
  // count for CLS, and its subtree is not yet unskipped, because the
  // intersection observation takes effect on the subsequent frame.
  GetDocument().domWindow()->scrollTo(0, 100000 + 100);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());
  EXPECT_EQ(PhysicalSize(100, 1), offscreen->Size());
  EXPECT_EQ(PhysicalSize(100, 100), onscreen->Size());

  // Now the subtree is unskipped, and #offscreen renders at size 100x100.
  // Nevertheless, there is no impact on CLS.
  UpdateAllLifecyclePhasesForTest();
  offscreen = To<LayoutBox>(GetLayoutObjectByElementId("offscreen"));
  onscreen = To<LayoutBox>(GetLayoutObjectByElementId("onscreen"));

  // Target's LayoutObject gets re-attached.
  offscreen = To<LayoutBox>(GetLayoutObjectByElementId("offscreen"));
  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());
  EXPECT_EQ(PhysicalSize(100, 100), offscreen->Size());
  // Because content-visibility: auto implies contain-intrinsic-size auto, the
  // size stays at 100x100.
  EXPECT_EQ(PhysicalSize(100, 100), onscreen->Size());

  // Move |offscreen| (which is visible and unlocked now), for which we should
  // report layout shift.
  To<Element>(offscreen->GetNode())
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("position: relative; top: 100100px"));
  UpdateAllLifecyclePhasesForTest();
  auto score = GetLayoutShiftTracker().Score();
  EXPECT_GT(score, 0);

  // Now scroll the element back off-screen.
  GetDocument().domWindow()->scrollTo(0, 0);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FLOAT_EQ(score, GetLayoutShiftTracker().Score());
  EXPECT_EQ(PhysicalSize(100, 100), offscreen->Size());
  EXPECT_EQ(PhysicalSize(100, 100), onscreen->Size());

  // In the subsequent frame, #offscreen becomes locked and changes its
  // layout size (and vice-versa for #onscreen).
  UpdateAllLifecyclePhasesForTest();
  offscreen = To<LayoutBox>(GetLayoutObjectByElementId("offscreen"));
  onscreen = To<LayoutBox>(GetLayoutObjectByElementId("onscreen"));

  EXPECT_FLOAT_EQ(score, GetLayoutShiftTracker().Score());
  EXPECT_EQ(PhysicalSize(100, 100), offscreen->Size());
  EXPECT_EQ(PhysicalSize(100, 100), onscreen->Size());
}

TEST_F(LayoutShiftTrackerTest, NestedFixedPos) {
  SetBodyInnerHTML(R"HTML(
    <div id=parent style="position: fixed; top: 0; left: -100%; width: 100%">
      <div id=target style="position: fixed; top: 0; width: 100%; height: 100%;
                            left: 0"; background: blue></div>
    </div>
    <div style="height: 5000px"></div>
  </div>
  )HTML");

  auto* target = To<LayoutBox>(GetLayoutObjectByElementId("target"));
  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());

  // Test that repaint of #target does not record a layout shift.
  target->SetNeedsPaintPropertyUpdate();
  target->SetSubtreeShouldDoFullPaintInvalidation();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());
}

TEST_F(LayoutShiftTrackerTest, ClipByVisualViewport) {
  SetHtmlInnerHTML(R"HTML(
    <meta name="viewport" content="width=200, initial-scale=2">
    <style>
      #target {
        position: absolute;
        top: 0;
        left: 150px;
        width: 200px;
        height: 200px;
        background: blue;
      }
    </style>
    <div id=target></div>
  )HTML");

  GetDocument().GetPage()->GetVisualViewport().SetSize(gfx::Size(200, 500));
  GetDocument().GetPage()->GetVisualViewport().SetLocation(gfx::PointF(0, 100));
  UpdateAllLifecyclePhasesForTest();
  // The visual viewport.
  EXPECT_EQ(gfx::Rect(0, 100, 200, 500),
            GetDocument().View()->GetScrollableArea()->VisibleContentRect());
  // The layout viewport .
  EXPECT_EQ(gfx::Rect(0, 0, 800, 600),
            GetDocument().View()->LayoutViewport()->VisibleContentRect());
  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());

  GetElementById("target")->setAttribute(html_names::kStyleAttr,
                                         AtomicString("top: 100px"));
  UpdateAllLifecyclePhasesForTest();
  // 50.0: visible width
  // 100.0 + 100.0: visible height + vertical shift
  // 200.0 * 500.0: visual viewport area
  // 100.0 / 500.0: shift distance fraction
  EXPECT_FLOAT_EQ(50.0 * (100.0 + 100.0) / (200.0 * 500.0) * (100.0 / 500.0),
                  GetLayoutShiftTracker().Score());
}

TEST_F(LayoutShiftTrackerTest, ScrollThenCauseScrollAnchoring) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .big {
        width: 100px;
        height: 500px;
        background: blue;
      }
      .small {
        width: 100px;
        height: 100px;
        background: green;
      }
    </style>
    <div class=big id=target></div>
    <div class=big></div>
    <div class=big></div>
    <div class=big></div>
    <div class=big></div>
    <div class=big></div>
  )HTML");
  auto* target_element = GetElementById("target");

  // Scroll the window which accumulates a scroll in the layout shift tracker.
  GetDocument().domWindow()->scrollBy(0, 1000);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());

  target_element->classList().Remove(AtomicString("big"));
  target_element->classList().Add(AtomicString("small"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());

  target_element->classList().Remove(AtomicString("small"));
  target_element->classList().Add(AtomicString("big"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());
}

TEST_F(LayoutShiftTrackerTest, NeedsToTrack) {
  SetBodyInnerHTML(R"HTML(
    <style>* { width: 50px; height: 50px; }</style>
    <div id="tiny" style="width: 0.3px; height: 0.3px; background: blue"></div>
    <div id="sticky" style="background: blue; position: sticky"></div>

    <!-- block with decoration -->
    <div id="scroll" style="overflow: scroll"></div>
    <div id="background" style="background: blue"></div>
    <div id="border" style="border: 1px solid black"></div>
    <div id="outline" style="outline: 1px solid black"></div>
    <div id="shadow" style="box-shadow: 2px 2px black"></div>

    <!-- block with block children, some invisible -->
    <div id="hidden-parent">
      <div id="hidden" style="background: blue; visibility: hidden">
        <div id="visible-under-hidden"
             style="background:blue; visibility: visible"></div>
      </div>
    </div>

    <!-- block with inline children, some invisible -->
    <div id="empty-parent">
      <div id="empty"></div>
    </div>
    <div id="text-block">Text</div>
    <br id="br">

    <svg id="svg">
      <rect id="svg-rect" width="10" height="10" fill="green">
    </svg>

    <!-- replaced, special blocks, etc. -->
    <video id="video"></video>
    <img id="img">
    <textarea id="textarea">Text</textarea>
    <input id="text-input" type="text">
    <input id="file" type="file">
    <input id="radio" type="radio">
    <progress id="progress"></progress>
    <ul>
      <li id="li"></li>
    </ul>
    <hr id="hr">
  )HTML");

  const auto& tracker = GetLayoutShiftTracker();
  EXPECT_FALSE(tracker.NeedsToTrack(GetLayoutView()));
  EXPECT_FALSE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("tiny")));
  EXPECT_FALSE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("sticky")));

  // Blocks with decorations.
  EXPECT_TRUE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("scroll")));
  EXPECT_TRUE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("background")));
  EXPECT_TRUE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("border")));
  EXPECT_TRUE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("outline")));
  EXPECT_TRUE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("shadow")));

  // Blocks with block children, some invisible. We don't check descendants for
  // visibility. Just assume there are visible descendants.
  EXPECT_TRUE(
      tracker.NeedsToTrack(*GetLayoutObjectByElementId("empty-parent")));
  EXPECT_FALSE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("empty")));
  EXPECT_TRUE(
      tracker.NeedsToTrack(*GetLayoutObjectByElementId("hidden-parent")));
  EXPECT_FALSE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("hidden")));
  EXPECT_TRUE(tracker.NeedsToTrack(
      *GetLayoutObjectByElementId("visible-under-hidden")));

  // Blocks with inline children, some invisible. We don't check descendants for
  // visibility. Just assume there are visible descendants.
  auto* text_block = To<LayoutBlock>(GetLayoutObjectByElementId("text-block"));
  EXPECT_TRUE(tracker.NeedsToTrack(*text_block));
  // No ContainingBlockScope.
  EXPECT_FALSE(tracker.NeedsToTrack(*text_block->FirstChild()));
  {
    LayoutShiftTracker::ContainingBlockScope scope(
        PhysicalSize(1, 2), PhysicalSize(2, 3), PhysicalRect(1, 2, 3, 4),
        PhysicalRect(2, 3, 4, 5));
    EXPECT_TRUE(tracker.NeedsToTrack(*text_block->FirstChild()));
  }
  auto* br = GetLayoutObjectByElementId("br");
  EXPECT_FALSE(tracker.NeedsToTrack(*br));
  EXPECT_TRUE(br->Parent()->IsAnonymous());
  EXPECT_FALSE(tracker.NeedsToTrack(*br->Parent()));

  EXPECT_TRUE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("svg")));
  // We don't track SVG children.
  EXPECT_FALSE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("svg-rect")));

  // Replaced, special blocks, etc.
  EXPECT_TRUE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("video")));
  EXPECT_TRUE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("img")));
  EXPECT_TRUE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("textarea")));
  EXPECT_TRUE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("text-input")));
  EXPECT_TRUE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("file")));
  EXPECT_TRUE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("radio")));
  EXPECT_TRUE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("progress")));
  EXPECT_TRUE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("li")));
  EXPECT_TRUE(tracker.NeedsToTrack(*GetLayoutObjectByElementId("hr")));
}

TEST_F(LayoutShiftTrackerTest, AnimatingTransformCreatesLayoutShiftRoot) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @keyframes move {
        to { translate: 10px; }
      }
      #animation {
        animation: move 10s infinite;
        position: absolute;
        width: 0;
        height: 0;
        top: 0;
      }
      #child {
        position: relative;
        width: 200px;
        height: 200px;
        background: blue;
      }
    </style>
    <div id="animation">
      <div id="child"></div>
    </div>
  )HTML");

  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());

  GetElementById("animation")
      ->setAttribute(html_names::kStyleAttr, AtomicString("top: 400px"));
  // `animation` creates a layout shift root, so `child`'s shift doesn't
  // include the shift of `animation`. The 2px shift is below the threshold of
  // reporting a layout shift.
  GetElementById("child")->setAttribute(html_names::kStyleAttr,
                                        AtomicString("top: 2px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());
}

}  // namespace blink
```