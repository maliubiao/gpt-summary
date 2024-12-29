Response:
The user wants to understand the functionality of the `annotation_agent_impl_test.cc` file in the Chromium Blink engine.

Here's a breakdown of the request and how to approach it:

1. **List the functions:** Analyze the code to identify the primary purpose of the test file. This will involve looking at the test cases and the setup/helper functions.
2. **Relationship with JS/HTML/CSS:** Determine if the tested functionality directly interacts with or affects JavaScript, HTML, or CSS features. Provide examples if there is a connection.
3. **Logical Reasoning (Hypothetical Input/Output):**  For test cases that simulate certain scenarios, describe a simplified input and the expected output. This clarifies the logic being tested.
4. **Common User/Programming Errors:** Identify potential mistakes developers or users might make when interacting with the functionalities being tested.
5. **User Operation to Reach This Code:** Describe how a user's actions in a browser could trigger the code being tested. This relates to the debugging context.
6. **Summarize Functionality:**  Provide a concise overview of the file's purpose based on the analysis.

**Mental Walkthrough of the Code:**

* The file is a C++ test file (`*_test.cc`) using the `gtest` framework, indicating it's for unit testing.
* It includes headers related to annotations (`annotation_agent_impl.h`, `annotation.mojom-blink.h`, etc.), suggesting it tests the `AnnotationAgentImpl` class.
* The test cases are named descriptively (e.g., `AgentType`, `CreatingDoesntBindOrAttach`, `Bind`), giving hints about what is being tested.
* Helper functions like `CreateRangeToExpectedText`, `CreateAgentForRange`, and `CreateTextFinderAgent` are used to set up test scenarios.
* The tests interact with the DOM (creating elements, setting attributes) and simulate browser behavior (loading URLs, triggering compositor frames).
* Some tests involve mocking (`MockAnnotationAgentHost`), indicating testing of interactions with other components.
* Tests related to viewport visibility (`ExpectInViewport`, `ExpectNotInViewport`) and scrolling (`ScrollIntoView`) suggest testing of how annotations interact with the visible area of the page.
* Tests involving `<details>` and `hidden="until-found"` attributes indicate testing of how annotations handle elements with specific visibility behaviors.

**Constraint Checklist & Confidence Score:**

* List functions: Yes
* Relationship with JS/HTML/CSS: Yes
* Examples for JS/HTML/CSS: Yes
* Logical Reasoning: Yes
* Input/Output examples: Yes
* Common User/Programming Errors: Yes
* Steps to reach the code: Yes
* Summarize Functionality: Yes
* Part 1 of 2: Acknowledge and focus on summarizing the current content.

Confidence Score: 5/5 - I have a good understanding of the code and can fulfill all the requirements.

**Strategizing for Part 1:**

Since this is part 1, I will focus on summarizing the functionality observed so far. I will address the other points (JS/HTML/CSS relationship, logical reasoning, errors, user operations) in the subsequent response for part 2, as requested. This keeps the response for part 1 concise and focused on the summary.这个文件 `blink/renderer/core/annotation/annotation_agent_impl_test.cc` 是 Chromium Blink 引擎的源代码文件，它专门用于测试 `AnnotationAgentImpl` 类的功能。`AnnotationAgentImpl` 负责在渲染引擎中管理和操作各种类型的注解（annotations），例如共享高亮、用户笔记等。

**功能归纳：**

这个测试文件的主要功能是验证 `AnnotationAgentImpl` 类的各种行为和交互，包括：

1. **创建和类型管理:** 测试 `AnnotationAgentImpl` 实例的创建，并验证其正确地维护了注解类型（例如，`kSharedHighlight` 或 `kUserNote`）。
2. **生命周期管理:** 测试 `AnnotationAgentImpl` 的生命周期，包括创建、绑定到 Mojo 接口、附加到 DOM、移除以及状态清理等。
3. **DOM 交互:**  测试 `AnnotationAgentImpl` 如何与文档对象模型 (DOM) 进行交互，例如：
    * **附加到 DOM:** 验证 `AnnotationAgentImpl` 能否成功地在 DOM 中找到与注解选择器匹配的内容，并在找到的内容上创建标记（marker）。
    * **移除 DOM 标记:** 验证当 `AnnotationAgentImpl` 被移除时，其对应的 DOM 标记也会被移除。
    * **处理附加失败:** 测试当注解选择器无法在 DOM 中找到匹配内容时，`AnnotationAgentImpl` 的行为。
4. **Mojo 绑定:** 测试 `AnnotationAgentImpl` 与外部（例如，浏览器进程）通过 Mojo 接口进行通信的能力，包括绑定和断开连接。
5. **视口滚动:** 测试 `AnnotationAgentImpl` 的 `ScrollIntoView` 功能，确保当注解关联的内容不在视口内时，能够正确地滚动页面使其可见。这包括处理页面缩放和布局更新的情况。
6. **处理隐藏元素:** 测试 `AnnotationAgentImpl` 如何处理注解目标位于隐藏元素（例如，`<details>` 元素或 `hidden="until-found"` 的元素）内的情况，验证它是否能够正确地展开或显示这些元素。
7. **`content-visibility: auto` 支持:** 测试 `AnnotationAgentImpl` 是否能正确地激活 `content-visibility: auto` 的元素。
8. **文本查找器类型注解:** 测试特定类型的注解（例如，文本查找器）的行为，确保它们不会产生不期望的副作用，例如修改 DOM 结构。

**与 JavaScript, HTML, CSS 的关系举例：**

`AnnotationAgentImpl` 的功能直接关联到用户在浏览器中看到的网页内容及其交互方式，因此与 JavaScript、HTML 和 CSS 都有密切关系：

* **HTML:**
    * **选择目标元素:** `AnnotationAgentImpl` 使用选择器（通常基于文本片段）来定位 HTML 元素中的特定内容。例如，一个注解可能针对 `<p id="target">This is the target text.</p>` 中的 "target text"。
    * **创建 DOM 标记:**  当注解成功附加时，会在选中的文本范围内创建特定的 DOM 标记（DocumentMarker），这些标记可能会影响文本的渲染。
    * **处理隐藏元素:**  测试用例中涉及到 `<details>` 元素和 `hidden="until-found"` 属性，验证了 `AnnotationAgentImpl` 在处理这些 HTML 结构时的行为。例如，当注解指向 `<details>` 元素内部的文本时，`AnnotationAgentImpl` 需要触发 `<details>` 元素的展开。
* **CSS:**
    * **影响渲染:**  `AnnotationAgentImpl` 创建的 DOM 标记可能会有默认的样式，或者可以通过 CSS 来定制，以视觉上区分被注解的内容（例如，高亮显示）。
    * **视口滚动:** `ScrollIntoView` 功能的正确性依赖于浏览器对 CSS 布局的计算和视口的管理。测试用例中使用了 CSS 来设置元素的位置，模拟需要滚动的场景。例如，将一个元素定位在视口之外，然后测试 `ScrollIntoView` 是否能将其滚动到可见区域。
    * **`content-visibility`:** 测试用例验证了当注解的目标位于 `content-visibility: auto` 的元素内时，`AnnotationAgentImpl` 的行为，这涉及到 CSS 的渲染优化机制。
* **JavaScript:**
    * **可能由 JavaScript 触发:**  虽然这个测试文件是 C++ 代码，但实际的注解操作可能由 JavaScript 代码发起。例如，一个 Web 应用的 JavaScript 代码可能会调用浏览器提供的 API 来创建或管理注解。
    * **事件交互:**  注解的创建或激活可能会触发 JavaScript 事件，供网页脚本监听和处理。

**逻辑推理 (假设输入与输出):**

假设有一个简单的 HTML 结构：

```html
<!DOCTYPE html>
<html>
<body>
  <p id="myParagraph">This is some text to annotate.</p>
</body>
</html>
```

并且我们创建了一个 `AnnotationAgentImpl` 实例，其选择器目标是 "some text"。

* **假设输入:**
    * HTML 内容如上。
    * `AnnotationAgentImpl` 的类型为 `kSharedHighlight`。
    * 选择器指定 "some text" 作为目标。
* **预期输出:**
    * 当 `AnnotationAgentImpl` 附加到 DOM 后，会在 `<p>` 元素内部的 "some text" 文本节点上创建一个 `DocumentMarker`。
    * `NumMarkersInRange` 函数在包含 "some text" 的 `RangeInFlatTree` 上调用时，应该返回 1。
    * 如果调用 `ScrollIntoView`，并且 "some text" 当前不在视口内，浏览器会滚动页面，使包含 "some text" 的区域可见。

**用户或编程常见的使用错误举例：**

* **用户错误:**
    * **注解目标不存在:** 用户尝试创建一个注解，但选择的文本片段在页面上不存在或已被修改，导致 `AnnotationAgentImpl` 无法找到目标并附加。测试用例 `AgentFailsAttachment` 就是为了覆盖这种情况。
* **编程错误:**
    * **选择器错误:**  在创建 `AnnotationAgentImpl` 时，提供的选择器不正确或过于宽泛，导致注解意外地附加到错误的内容上。
    * **过早移除 Agent:**  在注解还未完成其操作（例如，展开 `<details>` 元素）时就将其移除，可能导致状态不一致。
    * **假设同步附加:** 开发者可能错误地假设 `AnnotationAgentImpl` 的附加操作是同步的，而实际上某些情况下（例如，需要展开隐藏元素）可能是异步的，需要等待 Compositor 帧更新。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中访问一个包含可注解内容的网页。**
2. **用户执行某个操作来创建注解。** 这可能是通过浏览器内置的功能（例如，右键菜单中的 "共享" 或 "添加笔记"），或者是由网页上的 JavaScript 代码触发。
3. **浏览器接收到创建注解的请求，并根据用户的选择生成一个注解对象和相应的选择器（通常是文本片段）。**
4. **浏览器内部会创建一个 `AnnotationAgentImpl` 实例，并将其与该注解对象和选择器关联。**
5. **`AnnotationAgentImpl` 尝试将自身附加到当前的 DOM 结构上。** 这涉及到使用选择器在 DOM 树中查找匹配的内容。
6. **在测试环境中，`annotation_agent_impl_test.cc` 文件中的测试用例会模拟上述步骤，创建 `AnnotationAgentImpl` 实例，并断言其行为是否符合预期。** 例如，测试用例会加载一个包含特定 HTML 结构的网页，创建一个针对特定文本片段的 `AnnotationAgentImpl`，然后验证是否创建了正确的 `DocumentMarker`。

作为调试线索，如果开发者在实现或修改注解相关功能时遇到问题，可以通过运行这些测试用例来验证他们的代码是否正确工作。例如，如果一个新功能涉及到处理特定类型的隐藏元素，可以添加新的测试用例来覆盖这种情况，并确保 `AnnotationAgentImpl` 的行为符合预期。

**这是第1部分，共2部分，请归纳一下它的功能:**

总而言之，`blink/renderer/core/annotation/annotation_agent_impl_test.cc` 的主要功能是 **作为单元测试，全面验证 `AnnotationAgentImpl` 类的各种功能和在不同场景下的行为，确保其能够正确地管理和操作网页中的注解，并与 DOM、Mojo 接口以及浏览器的其他组件进行有效的交互。**  它涵盖了注解的创建、生命周期管理、DOM 交互（包括附加、移除标记以及处理隐藏元素）、视口滚动以及与其他 Web 技术（如 CSS 的 `content-visibility`）的协同工作。

Prompt: 
```
这是目录为blink/renderer/core/annotation/annotation_agent_impl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/annotation/annotation_agent_impl.h"

#include <gtest/gtest.h>

#include "base/containers/span.h"
#include "base/run_loop.h"
#include "base/test/bind.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "third_party/blink/public/mojom/annotation/annotation.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_font_face_descriptors.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview_string.h"
#include "third_party/blink/renderer/core/annotation/annotation_agent_container_impl.h"
#include "third_party/blink/renderer/core/annotation/annotation_test_utils.h"
#include "third_party/blink/renderer/core/annotation/text_annotation_selector.h"
#include "third_party/blink/renderer/core/css/font_face.h"
#include "third_party/blink/renderer/core/css/font_face_set_document.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/range_in_flat_tree.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/root_frame_viewport.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

class AnnotationAgentImplTest : public SimTest {
 public:
  void SetUp() override {
    SimTest::SetUp();
    WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  }

 protected:
  // Helper to create a range to some text within a single element. Verifies
  // the Range selects the `expected` text.
  RangeInFlatTree* CreateRangeToExpectedText(Element* element,
                                             int start_offset,
                                             int end_offset,
                                             const String& expected) {
    EXPECT_TRUE(element);
    if (!element)
      return nullptr;

    const auto& range_start = Position(element->firstChild(), start_offset);
    const auto& range_end = Position(element->firstChild(), end_offset);

    String actual = PlainText(EphemeralRange(range_start, range_end));
    EXPECT_EQ(expected, actual);
    if (expected != actual)
      return nullptr;

    return MakeGarbageCollected<RangeInFlatTree>(
        ToPositionInFlatTree(range_start), ToPositionInFlatTree(range_end));
  }

  RangeInFlatTree* CreateRangeForWholeDocument(Document& document) {
    const auto& range_start = PositionInFlatTree::FirstPositionInNode(document);
    const auto& range_end = PositionInFlatTree::LastPositionInNode(document);
    return MakeGarbageCollected<RangeInFlatTree>(
        ToPositionInFlatTree(range_start), ToPositionInFlatTree(range_end));
  }

  // Returns the number of annotation markers that intersect the given range.
  wtf_size_t NumMarkersInRange(RangeInFlatTree& range) {
    return GetDocument()
        .Markers()
        .MarkersIntersectingRange(range.ToEphemeralRange(),
                                  DocumentMarker::MarkerTypes::TextFragment())
        .size();
  }

  // Creates an agent with a mock selector that will relect the given range
  // when attached.
  AnnotationAgentImpl* CreateAgentForRange(
      RangeInFlatTree* range,
      mojom::blink::AnnotationType type =
          mojom::blink::AnnotationType::kSharedHighlight) {
    EXPECT_TRUE(range);
    if (!range)
      return nullptr;

    auto* container =
        AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());
    EXPECT_TRUE(container);
    if (!container)
      return nullptr;

    auto* mock_selector = MakeGarbageCollected<MockAnnotationSelector>(*range);
    return container->CreateUnboundAgent(type, *mock_selector);
  }

  // Creates an agent with a mock selector that will always fail to find a
  // range when attaching.
  AnnotationAgentImpl* CreateAgentFailsAttach() {
    auto* container =
        AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());
    EXPECT_TRUE(container);
    if (!container)
      return nullptr;

    auto* null_range = MakeGarbageCollected<RangeInFlatTree>();
    DCHECK(null_range->IsNull());

    auto* mock_selector =
        MakeGarbageCollected<MockAnnotationSelector>(*null_range);
    return container->CreateUnboundAgent(
        mojom::blink::AnnotationType::kSharedHighlight, *mock_selector);
  }

  // Creates an agent with a real text selector that will perform a real search
  // of the DOM tree. Use a text selector string of the same format as a URL's
  // text directive. (i.e. the part that comes after ":~:text=")
  AnnotationAgentImpl* CreateTextFinderAgent(
      const String& text_selector,
      mojom::blink::AnnotationType type =
          mojom::blink::AnnotationType::kSharedHighlight) {
    auto* selector = MakeGarbageCollected<TextAnnotationSelector>(
        TextFragmentSelector::FromTextDirective(text_selector));
    auto* container =
        AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());
    return container->CreateUnboundAgent(type, *selector);
  }
  // Performs a check that the given node is fully visible in the visual
  // viewport - that is, it's entire bounding rect is contained in the visual
  // viewport. Returns whether the check passed so it can be used as an ASSERT
  // in tests.
  bool ExpectInViewport(Node& node) {
    VisualViewport& viewport =
        GetDocument().View()->GetPage()->GetVisualViewport();
    gfx::Rect rect_in_visual_viewport = viewport.RootFrameToViewport(
        node.GetLayoutObject()->AbsoluteBoundingBoxRect(
            kTraverseDocumentBoundaries));
    gfx::Rect viewport_rect(viewport.Size());

    bool is_contained = viewport_rect.Contains(rect_in_visual_viewport);
    EXPECT_TRUE(is_contained)
        << "Expected [" << node.DebugName()
        << "] to be visible in viewport. Bounds relative to viewport: ["
        << rect_in_visual_viewport.ToString() << "] vs. viewport bounds [ "
        << viewport_rect.ToString() << " ]";
    return is_contained;
  }

  // Opposite of above. Duplicated to provide correct error message when
  // expectation fails.
  bool ExpectNotInViewport(Node& node) {
    VisualViewport& viewport =
        GetDocument().View()->GetPage()->GetVisualViewport();
    gfx::Rect rect_in_visual_viewport = viewport.RootFrameToViewport(
        node.GetLayoutObject()->AbsoluteBoundingBoxRect(
            kTraverseDocumentBoundaries));
    gfx::Rect viewport_rect(viewport.Size());

    bool is_contained = viewport_rect.Contains(rect_in_visual_viewport);
    EXPECT_FALSE(is_contained)
        << "Expected [" << node.DebugName()
        << "] to be visible in viewport. Bounds relative to viewport: ["
        << rect_in_visual_viewport.ToString() << "] vs. viewport bounds [ "
        << viewport_rect.ToString() << " ]";
    return !is_contained;
  }

  mojom::blink::AnnotationType GetAgentType(AnnotationAgentImpl* agent) {
    return agent->type_;
  }

  bool IsRemoved(AnnotationAgentImpl* agent) { return agent->IsRemoved(); }

  void LoadAhem() {
    std::optional<Vector<char>> data =
        test::ReadFromFile(test::CoreTestDataPath("Ahem.ttf"));
    ASSERT_TRUE(data);
    auto* buffer =
        MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferViewOrString>(
            DOMArrayBuffer::Create(base::as_byte_span(*data)));
    FontFace* ahem = FontFace::Create(GetDocument().GetFrame()->DomWindow(),
                                      AtomicString("Ahem"), buffer,
                                      FontFaceDescriptors::Create());

    ScriptState* script_state =
        ToScriptStateForMainWorld(GetDocument().GetFrame());
    DummyExceptionStateForTesting exception_state;
    FontFaceSetDocument::From(GetDocument())
        ->addForBinding(script_state, ahem, exception_state);
  }
};

// Tests that the agent type is correctly set.
TEST_F(AnnotationAgentImplTest, AgentType) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    TEST PAGE
  )HTML");

  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());
  ASSERT_TRUE(container);
  auto* shared_highlight_agent = container->CreateUnboundAgent(
      mojom::blink::AnnotationType::kSharedHighlight,
      *MakeGarbageCollected<MockAnnotationSelector>());

  auto* user_note_agent = container->CreateUnboundAgent(
      mojom::blink::AnnotationType::kUserNote,
      *MakeGarbageCollected<MockAnnotationSelector>());

  EXPECT_EQ(GetAgentType(shared_highlight_agent),
            mojom::blink::AnnotationType::kSharedHighlight);
  EXPECT_EQ(GetAgentType(user_note_agent),
            mojom::blink::AnnotationType::kUserNote);
}

// Ensure that simply creating an (unbound) agent doesn't automatically try to
// attach to DOM or bind to a mojo endpoint.
TEST_F(AnnotationAgentImplTest, CreatingDoesntBindOrAttach) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    TEST PAGE
  )HTML");

  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());
  ASSERT_TRUE(container);
  auto* agent = container->CreateUnboundAgent(
      mojom::blink::AnnotationType::kSharedHighlight,
      *MakeGarbageCollected<MockAnnotationSelector>());

  EXPECT_FALSE(agent->IsBoundForTesting());
  EXPECT_FALSE(agent->IsAttached());
}

// Tests that binding works.
TEST_F(AnnotationAgentImplTest, Bind) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    TEST PAGE
  )HTML");

  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());
  ASSERT_TRUE(container);
  auto* agent = container->CreateUnboundAgent(
      mojom::blink::AnnotationType::kSharedHighlight,
      *MakeGarbageCollected<MockAnnotationSelector>());

  MockAnnotationAgentHost host;
  host.BindToAgent(*agent);

  EXPECT_TRUE(host.agent_.is_connected());
  EXPECT_FALSE(host.did_disconnect_);
}

// Tests that removing the agent disconnects bindings.
TEST_F(AnnotationAgentImplTest, RemoveDisconnectsBindings) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    TEST PAGE
  )HTML");

  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());
  ASSERT_TRUE(container);
  auto* agent = container->CreateUnboundAgent(
      mojom::blink::AnnotationType::kSharedHighlight,
      *MakeGarbageCollected<MockAnnotationSelector>());

  MockAnnotationAgentHost host;
  host.BindToAgent(*agent);

  ASSERT_TRUE(host.agent_.is_connected());
  ASSERT_FALSE(host.did_disconnect_);

  agent->Remove();
  host.FlushForTesting();

  EXPECT_FALSE(host.agent_.is_connected());
  EXPECT_TRUE(host.did_disconnect_);
}

// Tests that removing an agent clears all its state.
TEST_F(AnnotationAgentImplTest, RemoveClearsState) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    TEST PAGE
  )HTML");
  Compositor().BeginFrame();

  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());
  ASSERT_TRUE(container);
  auto* agent = container->CreateUnboundAgent(
      mojom::blink::AnnotationType::kSharedHighlight,
      *MakeGarbageCollected<MockAnnotationSelector>());

  EXPECT_FALSE(IsRemoved(agent));

  Compositor().BeginFrame();
  ASSERT_TRUE(agent->IsAttached());

  agent->Remove();

  EXPECT_TRUE(IsRemoved(agent));
  EXPECT_FALSE(agent->IsAttached());
}

// Tests that attaching an agent to DOM in the document happens in a BeginFrame.
TEST_F(AnnotationAgentImplTest, AttachDuringBeginFrame) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    TEST PAGE
  )HTML");
  Compositor().BeginFrame();

  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());
  ASSERT_TRUE(container);
  auto* agent = container->CreateUnboundAgent(
      mojom::blink::AnnotationType::kSharedHighlight,
      *MakeGarbageCollected<MockAnnotationSelector>());

  ASSERT_FALSE(agent->IsAttached());
  Compositor().BeginFrame();
  EXPECT_TRUE(agent->IsAttached());
}

// Tests that attaching an agent to DOM will cause a document marker to be
// placed at the attached Range.
TEST_F(AnnotationAgentImplTest, SuccessfulAttachCreatesMarker) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='text'>TEST FOO PAGE BAR</p>
  )HTML");
  Compositor().BeginFrame();

  Element* p = GetDocument().getElementById(AtomicString("text"));

  RangeInFlatTree* range_foo = CreateRangeToExpectedText(p, 5, 8, "FOO");
  auto* agent_foo = CreateAgentForRange(range_foo);
  ASSERT_TRUE(agent_foo);

  RangeInFlatTree* range_bar = CreateRangeToExpectedText(p, 14, 17, "BAR");
  auto* agent_bar = CreateAgentForRange(range_bar);
  ASSERT_TRUE(agent_bar);

  Compositor().BeginFrame();

  ASSERT_TRUE(agent_foo->IsAttached());
  ASSERT_TRUE(agent_bar->IsAttached());

  // Both "FOO" and "BAR" should each have a single marker.
  EXPECT_EQ(NumMarkersInRange(*range_foo), 1ul);
  EXPECT_EQ(NumMarkersInRange(*range_bar), 1ul);

  // Ensure we didn't create markers outside of the selected text.
  RangeInFlatTree* range_test = CreateRangeToExpectedText(p, 0, 4, "TEST");
  RangeInFlatTree* range_page = CreateRangeToExpectedText(p, 9, 13, "PAGE");
  EXPECT_EQ(NumMarkersInRange(*range_test), 0ul);
  EXPECT_EQ(NumMarkersInRange(*range_page), 0ul);
}

// Tests that removing an agent will cause its corresponding document marker to
// be removed as well.
TEST_F(AnnotationAgentImplTest, RemovedAgentRemovesMarkers) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='text'>TEST FOO PAGE BAR</p>
  )HTML");
  Compositor().BeginFrame();

  Element* p = GetDocument().getElementById(AtomicString("text"));

  RangeInFlatTree* range_foo = CreateRangeToExpectedText(p, 5, 8, "FOO");
  auto* agent_foo = CreateAgentForRange(range_foo);
  ASSERT_TRUE(agent_foo);

  RangeInFlatTree* range_bar = CreateRangeToExpectedText(p, 14, 17, "BAR");
  auto* agent_bar = CreateAgentForRange(range_bar);
  ASSERT_TRUE(agent_bar);

  Compositor().BeginFrame();
  ASSERT_EQ(NumMarkersInRange(*range_foo), 1ul);
  ASSERT_EQ(NumMarkersInRange(*range_bar), 1ul);

  agent_foo->Remove();

  ASSERT_EQ(NumMarkersInRange(*range_foo), 0ul);
  ASSERT_EQ(NumMarkersInRange(*range_bar), 1ul);

  agent_bar->Remove();

  ASSERT_EQ(NumMarkersInRange(*range_foo), 0ul);
  ASSERT_EQ(NumMarkersInRange(*range_bar), 0ul);
}

// Tests the case where an agent's selector fails to attach to any content in
// the DOM. Ensure markers aren't created but the agent remains in a live
// state.
TEST_F(AnnotationAgentImplTest, AgentFailsAttachment) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='text'>TEST FOO PAGE BAR</p>
  )HTML");
  Compositor().BeginFrame();

  auto* agent = CreateAgentFailsAttach();
  ASSERT_TRUE(agent);

  Element* p = GetDocument().getElementById(AtomicString("text"));
  RangeInFlatTree* range =
      CreateRangeToExpectedText(p, 0, 17, "TEST FOO PAGE BAR");
  ASSERT_EQ(NumMarkersInRange(*range), 0ul);

  Compositor().BeginFrame();

  EXPECT_EQ(NumMarkersInRange(*range), 0ul);
  EXPECT_FALSE(agent->IsAttached());
  EXPECT_FALSE(IsRemoved(agent));
}

// Tests that failing to attach is still reported to the host the attempt
// completes.
TEST_F(AnnotationAgentImplTest, AgentFailsAttachmentReportsToHost) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='text'>TEST FOO PAGE BAR</p>
  )HTML");
  Compositor().BeginFrame();

  auto* agent = CreateAgentFailsAttach();
  ASSERT_TRUE(agent);

  MockAnnotationAgentHost host;
  host.BindToAgent(*agent);

  ASSERT_FALSE(host.did_disconnect_);
  ASSERT_TRUE(host.agent_.is_connected());
  ASSERT_FALSE(host.did_finish_attachment_rect_);

  Compositor().BeginFrame();
  host.FlushForTesting();

  ASSERT_TRUE(host.did_finish_attachment_rect_);
  EXPECT_TRUE(host.did_finish_attachment_rect_->IsEmpty());
}

// Tests that an overlapping marker still reports a completed attachment to the
// host.
TEST_F(AnnotationAgentImplTest, AttachmentToOverlappingMarkerReportsToHost) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='text'>TEST FOO PAGE BAR</p>
  )HTML");
  Compositor().BeginFrame();

  Element* element_text = GetDocument().getElementById(AtomicString("text"));

  auto* agent = CreateAgentFailsAttach();
  ASSERT_TRUE(agent);
  RangeInFlatTree* range_foo =
      CreateRangeToExpectedText(element_text, 5, 13, "FOO PAGE");
  auto* agent_foo = CreateAgentForRange(range_foo);
  ASSERT_TRUE(agent_foo);

  RangeInFlatTree* range_bar =
      CreateRangeToExpectedText(element_text, 9, 17, "PAGE BAR");
  auto* agent_bar = CreateAgentForRange(range_bar);
  ASSERT_TRUE(agent_bar);

  MockAnnotationAgentHost host_foo;
  MockAnnotationAgentHost host_bar;
  host_foo.BindToAgent(*agent_foo);
  host_bar.BindToAgent(*agent_bar);

  ASSERT_FALSE(host_foo.did_finish_attachment_rect_);
  ASSERT_FALSE(host_bar.did_finish_attachment_rect_);

  Compositor().BeginFrame();

  ASSERT_TRUE(agent_foo->IsAttached());
  ASSERT_TRUE(agent_bar->IsAttached());

  host_foo.FlushForTesting();

  EXPECT_TRUE(host_foo.did_finish_attachment_rect_);
  EXPECT_TRUE(host_bar.did_finish_attachment_rect_);
}

// Tests that attached agents report the document-coordinate rects of the
// ranges to the host.
TEST_F(AnnotationAgentImplTest, AttachmentReportsRectsToHost) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      p {
        font: 10px/1 Ahem;
      }
      #foo {
        position: absolute;
        top: 1000px;
      }
      #bar {
        position: absolute;
        top: 2000px;
      }
      body {
        height: 5000px;
        margin: 0;
      }
    </style>
    <p id='foo'>FOO<p>
    <p id='bar'>BAR</p>
  )HTML");

  LoadAhem();
  Compositor().BeginFrame();

  // Zoom and scroll to non-default values so we can ensure the coordinates of
  // the attached ranges are in the document coordinate space.
  {
    WebView().SetPageScaleFactor(2);
    GetDocument().View()->GetRootFrameViewport()->SetScrollOffset(
        ScrollOffset(123, 3000), mojom::blink::ScrollType::kProgrammatic,
        mojom::blink::ScrollBehavior::kInstant,
        ScrollableArea::ScrollCallback());

    // The visual viewport consumes all the horizontal scroll and 300px (its
    // max scroll offset) of the vertical scroll.
    VisualViewport& viewport =
        GetDocument().View()->GetPage()->GetVisualViewport();
    ASSERT_EQ(viewport.Scale(), 2.f);
    ASSERT_EQ(viewport.GetScrollOffset(), ScrollOffset(123, 300));
    ASSERT_EQ(GetDocument().View()->LayoutViewport()->GetScrollOffset(),
              ScrollOffset(0, 2700));
  }

  Element* element_foo = GetDocument().getElementById(AtomicString("foo"));
  Element* element_bar = GetDocument().getElementById(AtomicString("bar"));

  RangeInFlatTree* range_foo =
      CreateRangeToExpectedText(element_foo, 0, 3, "FOO");
  auto* agent_foo = CreateAgentForRange(range_foo);
  ASSERT_TRUE(agent_foo);

  RangeInFlatTree* range_bar =
      CreateRangeToExpectedText(element_bar, 0, 3, "BAR");
  auto* agent_bar = CreateAgentForRange(range_bar);
  ASSERT_TRUE(agent_bar);

  MockAnnotationAgentHost host_foo;
  MockAnnotationAgentHost host_bar;

  host_foo.BindToAgent(*agent_foo);
  host_bar.BindToAgent(*agent_bar);

  ASSERT_FALSE(host_foo.did_finish_attachment_rect_);
  ASSERT_FALSE(host_bar.did_finish_attachment_rect_);

  Compositor().BeginFrame();

  EXPECT_TRUE(agent_foo->IsAttached());
  EXPECT_TRUE(agent_bar->IsAttached());

  host_foo.FlushForTesting();
  host_bar.FlushForTesting();

  ASSERT_TRUE(host_foo.did_finish_attachment_rect_);
  ASSERT_TRUE(host_bar.did_finish_attachment_rect_);

  EXPECT_EQ(*host_foo.did_finish_attachment_rect_, gfx::Rect(0, 1010, 30, 10));
  EXPECT_EQ(*host_bar.did_finish_attachment_rect_, gfx::Rect(0, 2010, 30, 10));
}

// Tests that calling ScrollIntoView will ensure the marker is in the viewport.
TEST_F(AnnotationAgentImplTest, AgentScrollIntoView) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      p {
        font: 10px/1 Ahem;
      }
      #foo {
        position: absolute;
        top: 1000px;
      }
      body {
        height: 5000px;
        margin: 0;
      }
    </style>
    <p id='foo'>FOO<p>
  )HTML");

  LoadAhem();
  Compositor().BeginFrame();

  Element* element_foo = GetDocument().getElementById(AtomicString("foo"));

  RangeInFlatTree* range_foo =
      CreateRangeToExpectedText(element_foo, 0, 3, "FOO");
  auto* agent_foo = CreateAgentForRange(range_foo);
  ASSERT_TRUE(agent_foo);

  ASSERT_TRUE(ExpectNotInViewport(*element_foo));
  ASSERT_EQ(GetDocument().View()->GetRootFrameViewport()->GetScrollOffset(),
            ScrollOffset());

  MockAnnotationAgentHost host_foo;
  host_foo.BindToAgent(*agent_foo);
  Compositor().BeginFrame();
  ASSERT_TRUE(agent_foo->IsAttached());

  host_foo.FlushForTesting();

  // Attachment must not cause any scrolling.
  ASSERT_TRUE(ExpectNotInViewport(*element_foo));
  ASSERT_EQ(GetDocument().View()->GetRootFrameViewport()->GetScrollOffset(),
            ScrollOffset());

  // Invoking ScrollIntoView on the agent should cause the attached content
  // into the viewport.
  host_foo.agent_->ScrollIntoView();
  host_foo.FlushForTesting();

  EXPECT_TRUE(ExpectInViewport(*element_foo));
}

// Tests that calling ScrollIntoView will ensure the marker is in the viewport
// when the page has been pinch-zoomed.
TEST_F(AnnotationAgentImplTest, AgentScrollIntoViewZoomed) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      p {
        font: 10px/1 Ahem;
      }
      #foo {
        position: absolute;
        top: 5000px;
        left: 400px;
      }
      body {
        margin: 0;
        height: 10000px;
      }
    </style>
    <p id='foo'>FOO<p>
  )HTML");

  LoadAhem();
  Compositor().BeginFrame();

  // The page is non-horizontally scrollable but pinch-zoom so that the "FOO"
  // text is just off-screen on the right. This will ensure ScrollIntoView also
  // moves the visual viewport if the user pinch-zoomed in.
  WebView().SetPageScaleFactor(2);

  Element* element_foo = GetDocument().getElementById(AtomicString("foo"));

  RangeInFlatTree* range_foo =
      CreateRangeToExpectedText(element_foo, 0, 3, "FOO");
  auto* agent_foo = CreateAgentForRange(range_foo);
  ASSERT_TRUE(agent_foo);

  ASSERT_TRUE(ExpectNotInViewport(*element_foo));
  ASSERT_EQ(GetDocument().View()->GetRootFrameViewport()->GetScrollOffset(),
            ScrollOffset());

  MockAnnotationAgentHost host_foo;
  host_foo.BindToAgent(*agent_foo);
  Compositor().BeginFrame();
  ASSERT_TRUE(agent_foo->IsAttached());

  host_foo.FlushForTesting();

  // Invoking ScrollIntoView on the agent should cause the attached content
  // into the viewport.
  host_foo.agent_->ScrollIntoView();
  host_foo.FlushForTesting();

  EXPECT_TRUE(ExpectInViewport(*element_foo));
}

// Test that calling ScrollIntoView while layout is dirty causes the page to
// update layout and correctly ScrollIntoView the agent.
TEST_F(AnnotationAgentImplTest, ScrollIntoViewWithDirtyLayout) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      p {
        position: absolute;
        top: 100px;
      }
    </style>
    <p id='text'>FOO BAR</p>
  )HTML");

  Compositor().BeginFrame();

  Element* element_text = GetDocument().getElementById(AtomicString("text"));

  RangeInFlatTree* range_foo =
      CreateRangeToExpectedText(element_text, 0, 3, "FOO");
  auto* agent_foo = CreateAgentForRange(range_foo);
  ASSERT_TRUE(agent_foo);

  ASSERT_TRUE(ExpectInViewport(*element_text));
  ASSERT_EQ(GetDocument().View()->GetRootFrameViewport()->GetScrollOffset(),
            ScrollOffset());

  MockAnnotationAgentHost host_foo;
  host_foo.BindToAgent(*agent_foo);
  Compositor().BeginFrame();
  ASSERT_TRUE(agent_foo->IsAttached());

  element_text->setAttribute(html_names::kStyleAttr,
                             AtomicString("top: 2000px"));

  // Invoking ScrollIntoView on the agent should perform layout and then cause
  // the attached content to scroll into the viewport.
  host_foo.agent_->ScrollIntoView();
  host_foo.FlushForTesting();

  EXPECT_TRUE(ExpectInViewport(*element_text));
  EXPECT_GT(GetDocument().View()->GetRootFrameViewport()->GetScrollOffset().y(),
            1000);
}

// Degenerate case but make sure it doesn't crash. This constructs a
// RangeInFlatTree that isn't collapsed but turns into a collapsed
// EphmemeralRangeInFlatTree.
TEST_F(AnnotationAgentImplTest, ScrollIntoViewCollapsedRange) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      p {
        position: absolute;
        top: 2000px;
      }
    </style>
    <p id='text'>a</p>

  )HTML");

  Compositor().BeginFrame();

  Element* element_text = GetDocument().getElementById(AtomicString("text"));

  const auto& range_start =
      Position(element_text->firstChild(), PositionAnchorType::kBeforeAnchor);
  const auto& range_end = Position(element_text, 0);

  RangeInFlatTree* range = MakeGarbageCollected<RangeInFlatTree>(
      ToPositionInFlatTree(range_start), ToPositionInFlatTree(range_end));

  // TODO(bokan): Is this an editing bug?
  ASSERT_FALSE(range->IsCollapsed());
  ASSERT_TRUE(range->ToEphemeralRange().IsCollapsed());

  auto* agent = CreateAgentForRange(range);
  ASSERT_TRUE(agent);

  ASSERT_EQ(GetDocument().View()->GetRootFrameViewport()->GetScrollOffset(),
            ScrollOffset());

  MockAnnotationAgentHost host;
  host.BindToAgent(*agent);
  Compositor().BeginFrame();

  // Attachment should fail for this collapsed range.
  EXPECT_FALSE(agent->IsAttached());
  host.FlushForTesting();

  // Ensure calling ScrollIntoView doesn't crash.
  host.agent_->ScrollIntoView();
  host.FlushForTesting();
  EXPECT_EQ(GetDocument().View()->GetRootFrameViewport()->GetScrollOffset().y(),
            0);
}

// Ensure an annotation causes a hidden <details> section to be opened when
// text inside it is attached.
TEST_F(AnnotationAgentImplTest, OpenDetailsElement) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      details {
        position: absolute;
        top: 2000px;
      }
    </style>
    <details id='details'>foobar</p>
  )HTML");

  Compositor().BeginFrame();

  Element* element_details =
      GetDocument().getElementById(AtomicString("details"));
  ASSERT_FALSE(element_details->FastHasAttribute(html_names::kOpenAttr));

  auto* agent = CreateTextFinderAgent("foobar");
  MockAnnotationAgentHost host;
  host.BindToAgent(*agent);

  EXPECT_FALSE(agent->IsAttachmentPending());
  Compositor().BeginFrame();
  host.FlushForTesting();

  // Since the matching text is inside a <details> it is initially hidden. The
  // attachment will be asynchronous as the <details> element must be opened
  // which needs to happen in a safe place during the document lifecycle.
  EXPECT_TRUE(agent->IsAttachmentPending());
  EXPECT_FALSE(agent->IsAttached());
  EXPECT_FALSE(host.did_finish_attachment_rect_);
  EXPECT_FALSE(element_details->FastHasAttribute(html_names::kOpenAttr));

  // ScrollIntoView, if called, shouldn't cause a scroll yet.
  agent->ScrollIntoView();
  EXPECT_EQ(GetDocument().View()->GetRootFrameViewport()->GetScrollOffset(),
            ScrollOffset());

  // Produce a compositor frame. This should process the DOM mutations and
  // finish attaching the agent.
  Compositor().BeginFrame();
  host.FlushForTesting();

  EXPECT_TRUE(element_details->FastHasAttribute(html_names::kOpenAttr));
  EXPECT_FALSE(agent->IsAttachmentPending());
  EXPECT_TRUE(agent->IsAttached());
  EXPECT_TRUE(host.did_finish_attachment_rect_);

  // ScrollIntoView should now correctly scroll to the expanded details element.
  agent->ScrollIntoView();
  EXPECT_GT(GetDocument().View()->GetRootFrameViewport()->GetScrollOffset().y(),
            100.f);
}

// Ensure an annotation causes a `hidden=until-found` section to be shown when
// text inside it is attached.
TEST_F(AnnotationAgentImplTest, OpenHiddenUntilFoundElement) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      p {
        position: absolute;
        top: 2000px;
      }
    </style>
    <p id="section" hidden="until-found">foobar</p>
  )HTML");

  Compositor().BeginFrame();

  Element* element = GetDocument().getElementById(AtomicString("section"));

  auto* agent = CreateTextFinderAgent("foobar");

  Compositor().BeginFrame();

  EXPECT_TRUE(element->FastHasAttribute(html_names::kHiddenAttr));
  EXPECT_TRUE(agent->IsAttachmentPending());

  // Produce a compositor frame. This should process the DOM mutations and
  // finish attaching the agent.
  Compositor().BeginFrame();

  EXPECT_FALSE(element->FastHasAttribute(html_names::kHiddenAttr));
  EXPECT_TRUE(agent->IsAttached());
}

// Ensure an annotation can target a content-visibility: auto section.
TEST_F(AnnotationAgentImplTest, ActivatesContentVisibilityAuto) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      p {
        position: absolute;
        contain: strict;
        width: 200px;
        height: 20px;
        left: 0;
        top: 2000px;
        content-visibility: auto;
      }
    </style>
    <p id="section">foobar</p>
  )HTML");

  Compositor().BeginFrame();

  auto* agent = CreateTextFinderAgent("foobar");

  Compositor().BeginFrame();

  EXPECT_TRUE(agent->IsAttachmentPending());

  // Produce a compositor frame. This should process the DOM mutations and
  // finish attaching the agent.
  Compositor().BeginFrame();

  EXPECT_TRUE(agent->IsAttached());

  Element* element = GetDocument().getElementById(AtomicString("section"));
  RangeInFlatTree* range = CreateRangeToExpectedText(element, 0, 6, "foobar");
  EXPECT_FALSE(DisplayLockUtilities::NeedsActivationForFindInPage(
      range->ToEphemeralRange()));
}

// kTextFinder type annotations must not cause side-effects. Ensure they do not
// expand a hidden=until-found element.
TEST_F(AnnotationAgentImplTest, TextFinderDoesntMutateDom) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p hidden="until-found" id="text">TEST FOO PAGE BAR</p>
  )HTML");
  Compositor().BeginFram
"""


```