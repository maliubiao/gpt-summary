Response:
The user wants to understand the functionality of the `annotation_agent_container_impl_test.cc` file in the Chromium Blink engine. I need to analyze the code and describe its purpose, its relationship with web technologies, provide examples of its behavior, and explain how a user's actions could lead to the code being executed.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The filename ends with `_test.cc`, indicating this file contains unit tests for the `AnnotationAgentContainerImpl` class. Therefore, its main function is to verify the correct behavior of this class.

2. **Analyze the included headers:** The headers provide clues about the functionality being tested:
    * `annotation_agent_container_impl.h`: This is the header for the class being tested.
    * `<gtest/gtest.h>`: Indicates the use of the Google Test framework.
    * `base/run_loop.h`, `base/test/bind.h`:  Suggests asynchronous operations and testing of callbacks.
    * `components/shared_highlighting/...`: Points to functionality related to text highlighting and selection sharing.
    * `mojo/public/cpp/bindings/...`: Implies the use of Mojo for inter-process communication.
    * `third_party/blink/public/mojom/annotation/...`:  Defines the Mojo interfaces for annotation features.
    * `annotation_agent_impl.h`: Indicates the `AnnotationAgentContainerImpl` manages `AnnotationAgentImpl` instances.
    * `annotation_test_utils.h`: Contains helper functions for testing annotation features.
    * `editing/...`: Suggests interaction with text editing, selection, and finding functionalities.
    * `html/html_element.h`: Indicates interaction with HTML elements.
    * `testing/sim/...`: Implies the use of a simulation testing environment.

3. **Examine the test structure:** The file uses the `TEST_F` macro from Google Test, indicating individual test cases within the `AnnotationAgentContainerImplTest` class. Each test case focuses on a specific aspect of the `AnnotationAgentContainerImpl`'s functionality.

4. **Deconstruct individual test cases:** Analyze each test case to understand what it's testing:
    * `IsConstructedLazily`: Checks if the container is created only when needed.
    * `BindingCreatesContainer`: Verifies that binding a Mojo interface creates a container.
    * `NavigationBreaksBinding`: Tests that navigation disconnects the Mojo binding.
    * `NavigationReplacesContainer`: Ensures a new container is created on navigation.
    * `CreateUnboundAgent`: Checks the creation of an agent without a Mojo connection.
    * `CreateBoundAgent`: Verifies the creation of an agent with a Mojo connection and its attachment.
    * `DeferAttachmentUntilFinishedParsing`: Tests if attachment is deferred until the document finishes parsing.
    * `ManuallyRemoveAgent`: Checks if removing an agent also removes it from the container.
    * `NavigationRemovesBoundAgents`: Verifies that navigation disconnects agents.
    * `DetachedDocumentContainerBecomesInaccessible`: Ensures the container of a detached document cannot be accessed.
    * `CreateAgentFromSelectionWithNoSelection`: Tests the behavior when creating an agent from an empty selection.
    * `CreateAgentFromSelectionWithCollapsedSelection`: Tests the behavior when creating an agent from a collapsed selection.
    * `CreateAgentFromSelectionWithPreemptiveGeneration`: Verifies the handling of preemptively generated selectors.
    * `CreateAgentFromSelection`: Tests the creation of an agent from a valid selection.
    * `ShutdownDocumentWhileGenerating`: Checks the graceful cancellation of agent creation during navigation.

5. **Identify relationships with web technologies:** Based on the tested functionalities, identify connections to JavaScript, HTML, and CSS:
    * **JavaScript:**  While not directly testing JavaScript code, the annotation features are likely exposed to JavaScript for web developers to use. Creating annotations programmatically would involve JavaScript.
    * **HTML:** The tests involve loading HTML content and interacting with HTML elements. The annotation functionality adds visual elements (highlights) to the HTML structure.
    * **CSS:** Annotation highlights are typically styled using CSS to control their appearance (color, etc.).

6. **Provide examples and reasoning:**  For each relationship, create specific scenarios that illustrate the connection. This involves imagining how a web developer or user might interact with these features.

7. **Consider user/programming errors:** Think about common mistakes developers might make when using the annotation APIs or how user actions could lead to unexpected states.

8. **Describe user steps to reach the code:** Trace back user interactions in a browser that could trigger the annotation functionalities being tested. This often involves selecting text, right-clicking, and using context menu options related to sharing or saving content.

9. **Structure the answer:** Organize the information clearly with headings and bullet points to make it easy to understand.

10. **Review and refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any logical inconsistencies or missing information. For instance, initially, I might have overlooked the preemptive generation scenario, but a closer look at the test cases reveals this specific functionality. Similarly, ensuring the explanation of how right-clicking triggers the preemptive generation is crucial for understanding the user's path.
这个文件 `annotation_agent_container_impl_test.cc` 是 Chromium Blink 引擎中用于测试 `AnnotationAgentContainerImpl` 类的单元测试文件。它的主要功能是验证 `AnnotationAgentContainerImpl` 类的各种行为和功能是否符合预期。

以下是该文件功能的详细列表，以及与 JavaScript、HTML、CSS 的关系，逻辑推理，常见错误和调试线索：

**文件功能:**

1. **测试 `AnnotationAgentContainerImpl` 的生命周期管理:**
   - 测试容器是否在需要时才被创建（懒加载）。
   - 测试通过 Mojo 接口绑定是否会创建容器。
   - 测试导航到新页面时，旧页面的容器绑定是否会被断开。
   - 测试导航到新页面时，是否会创建新的容器。
   - 测试文档被移除时，容器是否不可访问。

2. **测试 `AnnotationAgentImpl` 的创建和管理:**
   - 测试容器能否创建未绑定的 `AnnotationAgentImpl` 实例。
   - 测试容器能否创建已绑定的 `AnnotationAgentImpl` 实例，并自动执行附加操作。
   - 测试在文档解析完成前创建的 Agent 是否会延迟附加，并在解析完成后尝试附加。
   - 测试 Agent 能否自行移除，并从容器中移除。
   - 测试导航到新页面时，已绑定的 Agent 是否会被断开连接。

3. **测试通过用户选择创建 `AnnotationAgentImpl` 的功能 (`CreateAgentFromSelection`)**
   - 测试在没有选择文本的情况下调用 `CreateAgentFromSelection` 是否不会创建 Agent，并返回空的绑定。
   - 测试在选择文本折叠的情况下调用 `CreateAgentFromSelection` 是否不会创建 Agent，并返回空的绑定。
   - 测试 `CreateAgentFromSelection` 是否能为选定的文本创建 Agent，并返回选择器和 Agent 的绑定。
   - 测试 `CreateAgentFromSelection` 是否能同步返回预先生成的结果（如果可用）。
   - 测试在异步生成选择器过程中导航到新页面，生成过程是否能被优雅地取消。

**与 JavaScript, HTML, CSS 的关系:**

虽然此测试文件本身是用 C++ 编写的，用于测试 Blink 引擎的内部实现，但它所测试的功能直接关系到 Web 开发者可以使用 JavaScript API 操作的功能，并且最终会影响到 HTML 元素的呈现和样式。

* **JavaScript:**  `AnnotationAgentContainerImpl` 和 `AnnotationAgentImpl` 提供的功能，如创建和管理注释或高亮，通常会通过 JavaScript API 暴露给 Web 开发者。开发者可以使用 JavaScript 代码来触发创建注释、修改注释、或者查询页面上的注释。 `CreateAgentFromSelection` 功能对应用户在页面上选择文本后，通过某种 JavaScript 触发的操作（例如，点击一个 "添加注释" 按钮），或者浏览器内置的上下文菜单操作。
    * **举例说明:** 一个 Web 应用可能使用 JavaScript 监听用户的文本选择事件，并在用户右键点击时，调用 Blink 提供的 API (底层会用到 `AnnotationAgentContainerImpl`) 来创建一个基于用户选择的注释。

* **HTML:**  `AnnotationAgentImpl` 的主要功能是在 HTML 文档中创建视觉上的标记，例如高亮选中文本。这通常涉及到在 DOM 树中添加额外的 HTML 元素或者修改现有元素的样式。`AnnotationAgentContainerImpl` 负责管理这些与特定文档关联的 Agent。
    * **举例说明:** 当通过 `CreateAgentFromSelection` 创建一个高亮时，Blink 可能会在选中的文本周围插入 `<span>` 标签，并应用特定的 CSS 类来实现高亮效果。

* **CSS:**  注释或高亮的视觉呈现（例如，颜色、背景色、边框等）通常是通过 CSS 来定义的。`AnnotationAgentImpl` 在附加到 HTML 元素时，可能会添加特定的 CSS 类或内联样式。
    * **举例说明:**  为高亮文本添加一个 `highlight` 的 CSS 类，然后在 CSS 中定义 `.highlight { background-color: yellow; }`。

**逻辑推理 (假设输入与输出):**

以下是一些基于测试用例的逻辑推理示例：

* **假设输入:**  一个已经加载的 HTML 文档，并且用户使用鼠标选中了一段文本 "example"。然后，JavaScript 代码调用一个创建注释的 API，该 API 最终会调用 `AnnotationAgentContainerImpl::CreateAgentFromSelection`。
* **输出:**  `CreateAgentFromSelection` 将会：
    1. 创建一个新的 `AnnotationAgentImpl` 实例。
    2. 生成一个描述所选文本的选择器（例如，文本内容，起始和结束位置）。
    3. 通过 Mojo 将 Agent 连接到渲染进程外部的宿主 (host)。
    4. 在 HTML 文档中添加相应的标记（例如，带有特定 CSS 类的 `<span>` 标签）来高亮 "example" 这段文本。

* **假设输入:** 用户在一个包含多个段落的 HTML 文档中选中了一个段落，并右键点击。浏览器的上下文菜单中包含一个 "分享" 或 "添加注释" 的选项，用户点击了这个选项。
* **输出:**  `AnnotationAgentContainerImpl` 将会：
    1. 接收到创建 Agent 的请求。
    2. 由于用户已经选择了文本，`CreateAgentFromSelection` 会被调用。
    3. 创建一个与该选择关联的 `AnnotationAgentImpl`。
    4. 生成一个可以唯一标识该选择的 "selector"。
    5. 返回一个包含 Agent 远程接口和选择器信息的对象，以便外部服务可以使用这个选择器来恢复或分享这个高亮。

**用户或编程常见的使用错误:**

* **在没有选择任何文本的情况下尝试创建注释:**  如果用户没有选择任何文本就触发了创建注释的操作，`CreateAgentFromSelection` 应该返回错误，并且不会创建任何 Agent。测试用例 `CreateAgentFromSelectionWithNoSelection` 验证了这一点。
* **在文档加载完成前尝试操作注释:**  如果在文档完全加载和解析完成之前，JavaScript 代码尝试创建或操作注释，可能会导致错误，因为相关的 DOM 结构可能尚未完全构建。测试用例 `DeferAttachmentUntilFinishedParsing` 模拟了这种情况，确保 Agent 在文档解析完成后才尝试附加。
* **在页面卸载或导航时未清理注释相关的资源:** 如果 Web 开发者在页面卸载或导航时没有正确清理与注释相关的资源（例如，断开 Mojo 连接），可能会导致内存泄漏或其他问题。测试用例 `NavigationBreaksBinding` 和 `NavigationRemovesBoundAgents` 验证了 Blink 引擎在这方面的处理。
* **尝试为已删除的文档创建注释:**  在导航到新页面后，尝试为旧页面创建注释是无效的。测试用例 `DetachedDocumentContainerBecomesInaccessible` 验证了对已分离文档的容器的访问应该被阻止。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户加载一个网页:**  当用户在浏览器中输入网址或点击链接时，浏览器会加载 HTML、CSS 和 JavaScript 资源。
2. **用户与网页交互:** 用户可能会选择网页上的文本。
3. **用户触发创建注释/高亮的操作:** 这可以通过以下几种方式发生：
   * **右键点击并选择上下文菜单项:** 现代浏览器通常提供与文本选择相关的上下文菜单项，例如 "分享" 或某些扩展提供的 "添加注释" 功能。点击这些选项可能会触发调用 Blink 引擎内部的注释创建逻辑。
   * **点击网页上的按钮或链接:** 网页上的 JavaScript 代码可以监听用户的点击事件，并在用户点击特定按钮（例如，一个 "高亮" 按钮）时，调用相关的 API 来创建注释。
   * **使用浏览器扩展:** 浏览器扩展可以监听用户的文本选择，并提供创建注释或高亮的功能。这些扩展通常会通过浏览器提供的 API 与 Blink 引擎进行交互。
4. **Blink 引擎接收到创建注释的请求:**  无论是通过上下文菜单、网页 JavaScript 还是浏览器扩展，最终都会调用到 Blink 引擎提供的 C++ API。
5. **`AnnotationAgentContainerImpl::CreateAgentFromSelection` 被调用:** 如果用户的操作是基于已选择的文本创建注释，那么 `CreateAgentFromSelection` 方法会被调用。
6. **测试文件的作用:**  `annotation_agent_container_impl_test.cc` 中的测试用例会模拟上述各种用户操作和场景，例如：
   * `SendRightClick` 函数模拟用户在特定位置点击鼠标右键。
   * `FrameSelection` 对象用于模拟用户在页面上选择文本。
   * `LoadURL` 函数模拟用户导航到不同的页面。

**调试线索:**

当调试与注释功能相关的问题时，可以考虑以下线索：

* **检查 Mojo 通信:**  `AnnotationAgentContainerImpl` 和 `AnnotationAgentImpl` 使用 Mojo 进行进程间通信。检查相关的 Mojo 消息是否按预期发送和接收，可以帮助诊断问题。
* **查看 DOM 树的变化:**  当创建注释或高亮时，DOM 树会发生变化。检查是否添加了预期的 HTML 元素，以及是否应用了正确的 CSS 类。
* **断点调试 C++ 代码:** 在 `annotation_agent_container_impl.cc` 和 `annotation_agent_impl.cc` 中设置断点，可以跟踪代码的执行流程，查看变量的值，并理解代码在特定场景下的行为。
* **查看控制台输出:**  相关的错误信息或日志可能会输出到浏览器的开发者工具控制台。
* **分析网络请求:**  如果注释功能涉及到与外部服务的通信（例如，同步或分享注释），检查相关的网络请求是否成功。

总而言之，`annotation_agent_container_impl_test.cc` 是一个关键的测试文件，用于确保 Blink 引擎中负责管理注释代理的组件能够正确地工作，并且与用户的交互和 Web 开发者的 API 使用保持一致。理解这个文件的功能有助于理解 Blink 引擎内部如何处理网页上的注释和高亮功能。

Prompt: 
```
这是目录为blink/renderer/core/annotation/annotation_agent_container_impl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/annotation/annotation_agent_container_impl.h"

#include <gtest/gtest.h>

#include "base/run_loop.h"
#include "base/test/bind.h"
#include "components/shared_highlighting/core/common/shared_highlighting_metrics.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "third_party/blink/public/mojom/annotation/annotation.mojom-blink.h"
#include "third_party/blink/renderer/core/annotation/annotation_agent_impl.h"
#include "third_party/blink/renderer/core/annotation/annotation_test_utils.h"
#include "third_party/blink/renderer/core/editing/finder/async_find_buffer.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"

namespace blink {

class AnnotationAgentContainerImplTest : public SimTest {
 public:
  void SetUp() override {
    SimTest::SetUp();
    WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  }

 protected:
  bool IsInContainer(AnnotationAgentImpl& agent,
                     AnnotationAgentContainerImpl& container) const {
    return container.agents_.Contains(&agent);
  }

  size_t GetAgentCount(AnnotationAgentContainerImpl& container) {
    return container.agents_.size();
  }

  void SendRightClick(const gfx::Point& click_point) {
    auto event = frame_test_helpers::CreateMouseEvent(
        WebMouseEvent::Type::kMouseDown, WebMouseEvent::Button::kRight,
        click_point, /*modifiers=*/0);
    event.click_count = 1;
    WebView().MainFrameViewWidget()->HandleInputEvent(
        WebCoalescedInputEvent(event, ui::LatencyInfo()));
  }

  ScopedUseMockAnnotationSelector use_mock_annotation_selector_;
};

// Ensure containers aren't supplementing a document until they're requested.
TEST_F(AnnotationAgentContainerImplTest, IsConstructedLazily) {
  SimRequest request("https://example.com/test.html", "text/html");
  SimRequest child_request("https://example.com/subframe.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    TEST PAGE
    <iframe src="https://example.com/subframe.html"></iframe>
  )HTML");
  child_request.Complete(R"HTML(
    <!DOCTYPE html>
    SUBFRAME
  )HTML");
  Compositor().BeginFrame();

  ASSERT_TRUE(GetDocument().GetFrame());
  ASSERT_TRUE(GetDocument().GetFrame()->FirstChild());
  LocalFrame* child_frame =
      DynamicTo<LocalFrame>(GetDocument().GetFrame()->FirstChild());
  ASSERT_TRUE(child_frame);

  Document* child_document = child_frame->GetDocument();
  ASSERT_TRUE(child_document);

  // Initially, the container supplement should not exist on either document.
  EXPECT_FALSE(AnnotationAgentContainerImpl::FromIfExists(GetDocument()));
  EXPECT_FALSE(AnnotationAgentContainerImpl::FromIfExists(*child_document));

  // Calling the getter on the container should create the supplement but only
  // for the child document.
  auto* child_container =
      AnnotationAgentContainerImpl::CreateIfNeeded(*child_document);
  EXPECT_TRUE(child_container);
  EXPECT_EQ(child_container,
            AnnotationAgentContainerImpl::FromIfExists(*child_document));
  EXPECT_FALSE(AnnotationAgentContainerImpl::FromIfExists(GetDocument()));

  // Calling the getter for the main document should now create that supplement.
  auto* main_container =
      AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());
  EXPECT_EQ(main_container,
            AnnotationAgentContainerImpl::FromIfExists(GetDocument()));

  // The child and main documents should each have their own containers.
  EXPECT_NE(main_container, child_container);
}

// Test that binding the mojo interface creates a new container.
TEST_F(AnnotationAgentContainerImplTest, BindingCreatesContainer) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    TEST PAGE
  )HTML");
  Compositor().BeginFrame();

  mojo::Remote<mojom::blink::AnnotationAgentContainer> remote;
  ASSERT_FALSE(remote.is_bound());
  ASSERT_FALSE(AnnotationAgentContainerImpl::FromIfExists(GetDocument()));

  AnnotationAgentContainerImpl::BindReceiver(
      GetDocument().GetFrame(), remote.BindNewPipeAndPassReceiver());

  EXPECT_TRUE(remote.is_connected());
  EXPECT_TRUE(AnnotationAgentContainerImpl::FromIfExists(GetDocument()));
}

// Test that navigating to a new document breaks the binding on the old
// document's container.
TEST_F(AnnotationAgentContainerImplTest, NavigationBreaksBinding) {
  SimRequest request("https://example.com/test.html", "text/html");
  SimRequest request_next("https://example.com/next.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    TEST PAGE
  )HTML");
  Compositor().BeginFrame();

  mojo::Remote<mojom::blink::AnnotationAgentContainer> remote;
  AnnotationAgentContainerImpl::BindReceiver(
      GetDocument().GetFrame(), remote.BindNewPipeAndPassReceiver());
  ASSERT_TRUE(remote.is_connected());

  LoadURL("https://example.com/next.html");
  request_next.Complete(R"HTML(
    <!DOCTYPE html>
    NEXT PAGE
  )HTML");
  Compositor().BeginFrame();

  remote.FlushForTesting();

  EXPECT_FALSE(remote.is_connected());
}

// Test that navigating to a new document installs a new container.
TEST_F(AnnotationAgentContainerImplTest, NavigationReplacesContainer) {
  SimRequest request("https://example.com/test.html", "text/html");
  SimRequest request_next("https://example.com/next.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    TEST PAGE
  )HTML");
  Compositor().BeginFrame();

  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());

  LoadURL("https://example.com/next.html");
  request_next.Complete(R"HTML(
    <!DOCTYPE html>
    NEXT PAGE
  )HTML");
  Compositor().BeginFrame();

  auto* container_next =
      AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());

  EXPECT_NE(container, container_next);
}

// Test that the container can create an unbound agent.
TEST_F(AnnotationAgentContainerImplTest, CreateUnboundAgent) {
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

  EXPECT_TRUE(agent);
  EXPECT_FALSE(agent->IsBoundForTesting());
  EXPECT_FALSE(agent->IsAttached());

  EXPECT_TRUE(IsInContainer(*agent, *container));
}

// Test that the container can create a bound agent. It should automatically
// perform attachment at creation time.
TEST_F(AnnotationAgentContainerImplTest, CreateBoundAgent) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    TEST PAGE
  )HTML");
  Compositor().BeginFrame();

  MockAnnotationAgentHost host;
  auto remote_receiver_pair = host.BindForCreateAgent();

  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());
  ASSERT_TRUE(container);
  container->CreateAgent(std::move(remote_receiver_pair.first),
                         std::move(remote_receiver_pair.second),
                         mojom::blink::AnnotationType::kSharedHighlight,
                         "MockAnnotationSelector");

  EXPECT_EQ(GetAgentCount(*container), 1ul);

  EXPECT_TRUE(host.agent_.is_connected());

  // Creating an agent from selection should automatically attach, which will
  // happen in the next BeginFrame.
  Compositor().BeginFrame();
  host.FlushForTesting();
  EXPECT_TRUE(host.did_finish_attachment_rect_);
  EXPECT_FALSE(host.did_disconnect_);
}

// Test that creating an agent in a document that hasn't yet completed parsing
// will cause agents to defer attachment and attempt it when the document
// finishes parsing.
TEST_F(AnnotationAgentContainerImplTest, DeferAttachmentUntilFinishedParsing) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Write(R"HTML(
    <!DOCTYPE html>
    <body>TEST PAGE</body>
  )HTML");
  Compositor().BeginFrame();

  ASSERT_FALSE(GetDocument().HasFinishedParsing());

  MockAnnotationAgentHost host;
  auto remote_receiver_pair = host.BindForCreateAgent();

  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());
  ASSERT_TRUE(container);
  container->CreateAgent(std::move(remote_receiver_pair.first),
                         std::move(remote_receiver_pair.second),
                         mojom::blink::AnnotationType::kUserNote,
                         "MockAnnotationSelector");

  // The agent should be created and bound.
  EXPECT_EQ(GetAgentCount(*container), 1ul);
  EXPECT_TRUE(host.agent_.is_connected());

  // Attachment should not have been attempted yet.
  host.FlushForTesting();
  EXPECT_FALSE(host.did_finish_attachment_rect_);
  EXPECT_FALSE(host.did_disconnect_);

  request.Finish();
  ASSERT_TRUE(GetDocument().HasFinishedParsing());

  // Now that parsing finished, attachment should be completed.
  host.FlushForTesting();
  EXPECT_TRUE(host.did_finish_attachment_rect_);
}

// Test that an agent removing itself also removes it from its container.
TEST_F(AnnotationAgentContainerImplTest, ManuallyRemoveAgent) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    TEST PAGE
  )HTML");
  Compositor().BeginFrame();

  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());
  ASSERT_TRUE(container);
  auto* agent1 = container->CreateUnboundAgent(
      mojom::blink::AnnotationType::kSharedHighlight,
      *MakeGarbageCollected<MockAnnotationSelector>());
  auto* agent2 = container->CreateUnboundAgent(
      mojom::blink::AnnotationType::kSharedHighlight,
      *MakeGarbageCollected<MockAnnotationSelector>());

  ASSERT_TRUE(agent1);
  ASSERT_TRUE(agent2);
  EXPECT_EQ(GetAgentCount(*container), 2ul);
  EXPECT_TRUE(IsInContainer(*agent1, *container));
  EXPECT_TRUE(IsInContainer(*agent2, *container));

  agent1->Remove();

  EXPECT_EQ(GetAgentCount(*container), 1ul);
  EXPECT_FALSE(IsInContainer(*agent1, *container));
  EXPECT_TRUE(IsInContainer(*agent2, *container));

  agent2->Remove();

  EXPECT_EQ(GetAgentCount(*container), 0ul);
  EXPECT_FALSE(IsInContainer(*agent2, *container));
}

// Test that navigating to a new document causes the agents to be disconnected
// from their hosts.
TEST_F(AnnotationAgentContainerImplTest, NavigationRemovesBoundAgents) {
  SimRequest request("https://example.com/test.html", "text/html");
  SimRequest request_next("https://example.com/next.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    TEST PAGE
  )HTML");
  Compositor().BeginFrame();

  MockAnnotationAgentHost host;
  auto remote_receiver_pair = host.BindForCreateAgent();

  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());
  container->CreateAgent(std::move(remote_receiver_pair.first),
                         std::move(remote_receiver_pair.second),
                         mojom::blink::AnnotationType::kSharedHighlight,
                         "MockAnnotationSelector");
  ASSERT_EQ(GetAgentCount(*container), 1ul);
  ASSERT_FALSE(host.did_disconnect_);

  LoadURL("https://example.com/next.html");
  request_next.Complete(R"HTML(
    <!DOCTYPE html>
    NEXT PAGE
  )HTML");

  host.FlushForTesting();
  EXPECT_TRUE(host.did_disconnect_);
}

// Test that a detached document's container is no longer accessible.
TEST_F(AnnotationAgentContainerImplTest,
       DetachedDocumentContainerBecomesInaccessible) {
  SimRequest request("https://example.com/test.html", "text/html");
  SimRequest request_next("https://example.com/next.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    TEST PAGE
  )HTML");
  Compositor().BeginFrame();

  auto& first_document = GetDocument();

  LoadURL("https://example.com/next.html");
  request_next.Complete(R"HTML(
    <!DOCTYPE html>
    NEXT PAGE
  )HTML");

  EXPECT_FALSE(AnnotationAgentContainerImpl::CreateIfNeeded(first_document));
}

// When the document has no selection, calling CreateAgentFromSelection must
// not create an agent and it must return empty null bindings back to the
// caller.
TEST_F(AnnotationAgentContainerImplTest,
       CreateAgentFromSelectionWithNoSelection) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <body>TEST PAGE</body>
  )HTML");
  Compositor().BeginFrame();

  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());

  bool did_reply = false;
  container->CreateAgentFromSelection(
      mojom::blink::AnnotationType::kUserNote,
      base::BindLambdaForTesting(
          [&did_reply](
              mojom::blink::SelectorCreationResultPtr selector_creation_result,
              shared_highlighting::LinkGenerationError error,
              shared_highlighting::LinkGenerationReadyStatus ready_status) {
            did_reply = true;

            EXPECT_FALSE(selector_creation_result);
            EXPECT_EQ(
                error,
                shared_highlighting::LinkGenerationError::kEmptySelection);
            // Test that the generation was not preemptive, the result was not
            // ready by the time we called CreateAgentFromSelection.
            EXPECT_EQ(ready_status,
                      shared_highlighting::LinkGenerationReadyStatus::
                          kRequestedBeforeReady);
          }));

  EXPECT_TRUE(did_reply);
  EXPECT_EQ(GetAgentCount(*container), 0ul);
}

// CreateAgentFromSelection must create an agent and return a selector for the
// selected text and bindings to the agent. It should also attach the agent to
// show the highlight.
TEST_F(AnnotationAgentContainerImplTest,
       CreateAgentFromSelectionWithCollapsedSelection) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <body>TEST PAGE</body>
  )HTML");
  Compositor().BeginFrame();

  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());

  FrameSelection& frame_selection = GetDocument().GetFrame()->Selection();

  Element* body = GetDocument().body();
  frame_selection.SetSelection(SelectionInDOMTree::Builder()
                                   .Collapse(Position(body->firstChild(), 0))
                                   .Build(),
                               SetSelectionOptions());

  bool did_reply = false;
  container->CreateAgentFromSelection(
      mojom::blink::AnnotationType::kUserNote,
      base::BindLambdaForTesting(
          [&did_reply](
              mojom::blink::SelectorCreationResultPtr selector_creation_result,
              shared_highlighting::LinkGenerationError error,
              shared_highlighting::LinkGenerationReadyStatus ready_status) {
            did_reply = true;

            EXPECT_FALSE(selector_creation_result);
            EXPECT_EQ(
                error,
                shared_highlighting::LinkGenerationError::kEmptySelection);
            EXPECT_EQ(ready_status,
                      shared_highlighting::LinkGenerationReadyStatus::
                          kRequestedBeforeReady);
          }));

  EXPECT_TRUE(did_reply);
  EXPECT_EQ(GetAgentCount(*container), 0ul);
}

// CreateAgentFromSelection should synchronously return a preemptively generated
// result if one is available.
TEST_F(AnnotationAgentContainerImplTest,
       CreateAgentFromSelectionWithPreemptiveGeneration) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <body>TEST PAGE</body>
  )HTML");
  Compositor().BeginFrame();

  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());

  FrameSelection& frame_selection = GetDocument().GetFrame()->Selection();

  Element* body = GetDocument().body();
  EphemeralRange range = EphemeralRange(Position(body->firstChild(), 0),
                                        Position(body->firstChild(), 5));
  ASSERT_EQ("TEST ", PlainText(range));

  frame_selection.SetSelection(
      SelectionInDOMTree::Builder().SetBaseAndExtent(range).Build(),
      SetSelectionOptions());

  // Right click on the selected text
  const auto& selection_rect = CreateRange(range)->BoundingBox();
  SendRightClick(selection_rect.origin());

  MockAnnotationAgentHost host;

  base::RunLoop run_loop;

  run_loop.RunUntilIdle();

  bool did_reply = false;
  container->CreateAgentFromSelection(
      mojom::blink::AnnotationType::kUserNote,
      base::BindLambdaForTesting(
          [&did_reply, &host](
              mojom::blink::SelectorCreationResultPtr selector_creation_result,
              shared_highlighting::LinkGenerationError error,
              shared_highlighting::LinkGenerationReadyStatus ready_status) {
            did_reply = true;

            EXPECT_EQ(selector_creation_result->selected_text, "TEST");
            EXPECT_EQ(selector_creation_result->serialized_selector,
                      "TEST,-PAGE");
            EXPECT_TRUE(selector_creation_result->host_receiver.is_valid());
            EXPECT_TRUE(selector_creation_result->agent_remote.is_valid());
            EXPECT_EQ(error, shared_highlighting::LinkGenerationError::kNone);
            // Test that the generation was preemptive, the result was ready by
            // the time we called CreateAgentFromSelection.
            EXPECT_EQ(ready_status,
                      shared_highlighting::LinkGenerationReadyStatus::
                          kRequestedAfterReady);

            host.Bind(std::move(selector_creation_result->host_receiver),
                      std::move(selector_creation_result->agent_remote));
          }));

  // Test that the callback from CreateAgentFromSelection invoked synchronously.
  EXPECT_TRUE(did_reply);

  EXPECT_TRUE(host.agent_.is_connected());

  // Creating an agent from selection should automatically attach, which will
  // happen in the next BeginFrame.
  Compositor().BeginFrame();
  host.FlushForTesting();
  EXPECT_TRUE(host.did_finish_attachment_rect_);

  EXPECT_EQ(GetAgentCount(*container), 1ul);
}

// When the document has a collapsed selection, calling
// CreateAgentFromSelection must not create an agent and it must return empty
// null bindings back to the caller.
TEST_F(AnnotationAgentContainerImplTest, CreateAgentFromSelection) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <body>TEST PAGE</body>
  )HTML");
  Compositor().BeginFrame();

  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());

  FrameSelection& frame_selection = GetDocument().GetFrame()->Selection();

  Element* body = GetDocument().body();
  EphemeralRange range = EphemeralRange(Position(body->firstChild(), 0),
                                        Position(body->firstChild(), 5));
  ASSERT_EQ("TEST ", PlainText(range));

  frame_selection.SetSelection(
      SelectionInDOMTree::Builder().SetBaseAndExtent(range).Build(),
      SetSelectionOptions());

  const auto& selection_rect = CreateRange(range)->BoundingBox();
  SendRightClick(selection_rect.origin());

  MockAnnotationAgentHost host;

  base::RunLoop run_loop;
  container->CreateAgentFromSelection(
      mojom::blink::AnnotationType::kUserNote,
      base::BindLambdaForTesting(
          [&run_loop, &host](
              mojom::blink::SelectorCreationResultPtr selector_creation_result,
              shared_highlighting::LinkGenerationError error,
              shared_highlighting::LinkGenerationReadyStatus ready_status) {
            run_loop.Quit();

            EXPECT_EQ(selector_creation_result->selected_text, "TEST");
            EXPECT_EQ(selector_creation_result->serialized_selector,
                      "TEST,-PAGE");
            EXPECT_TRUE(selector_creation_result->host_receiver.is_valid());
            EXPECT_TRUE(selector_creation_result->agent_remote.is_valid());
            EXPECT_EQ(error, shared_highlighting::LinkGenerationError::kNone);
            // Test that the generation was preemptive, the result was ready by
            // the time we called CreateAgentFromSelection.
            EXPECT_EQ(ready_status,
                      shared_highlighting::LinkGenerationReadyStatus::
                          kRequestedAfterReady);

            host.Bind(std::move(selector_creation_result->host_receiver),
                      std::move(selector_creation_result->agent_remote));
          }));
  run_loop.Run();

  EXPECT_TRUE(host.agent_.is_connected());

  // Creating an agent from selection should automatically attach, which will
  // happen in the next BeginFrame.
  Compositor().BeginFrame();
  host.FlushForTesting();
  EXPECT_TRUE(host.did_finish_attachment_rect_);

  EXPECT_EQ(GetAgentCount(*container), 1ul);
}

// Test that an in-progress, asynchronous generation is canceled gracefully if
// a new document is navigated.
TEST_F(AnnotationAgentContainerImplTest, ShutdownDocumentWhileGenerating) {
  SimRequest request("https://example.com/test.html", "text/html");
  SimRequest request_next("https://example.com/next.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <body>
      <p>Multiple blocks</p>
      <p>Multiple blocks</p>
      <p>Multiple blocks</p>
      <p>Multiple blocks</p>
      <p>Multiple blocks</p>
      <p id="target">TARGET</p>
      <p>Multiple blocks</p>
    </body>
  )HTML");
  Compositor().BeginFrame();

  // Set a tiny timeout so that the generator takes many tasks to finish its
  // work.
  auto auto_reset_timeout =
      AsyncFindBuffer::OverrideTimeoutForTesting(base::TimeDelta::Min());

  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());

  FrameSelection& frame_selection = GetDocument().GetFrame()->Selection();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  EphemeralRange range =
      EphemeralRange(Position(target, 0), Position(target, 1));
  ASSERT_EQ("TARGET", PlainText(range));

  frame_selection.SetSelection(
      SelectionInDOMTree::Builder().SetBaseAndExtent(range).Build(),
      SetSelectionOptions());

  // Right click on the selected text
  const auto& selection_rect = CreateRange(range)->BoundingBox();
  SendRightClick(selection_rect.origin());

  base::RunLoop run_loop;
  bool did_finish = false;

  container->CreateAgentFromSelection(
      mojom::blink::AnnotationType::kUserNote,
      base::BindLambdaForTesting(
          [&did_finish](
              mojom::blink::SelectorCreationResultPtr selector_creation_result,
              shared_highlighting::LinkGenerationError error,
              shared_highlighting::LinkGenerationReadyStatus ready_status) {
            did_finish = true;
            EXPECT_FALSE(selector_creation_result);
            EXPECT_EQ(
                error,
                shared_highlighting::LinkGenerationError::kIncorrectSelector);
            // Test that the generation was preemptive, the result was ready by
            // the time we called CreateAgentFromSelection.
            EXPECT_EQ(ready_status,
                      shared_highlighting::LinkGenerationReadyStatus::
                          kRequestedAfterReady);
          }));

  // The above will have posted the first generator task to
  // kInternalFindInPage. Post a task after it to exit back to test code after
  // that task runs.
  GetDocument()
      .GetTaskRunner(TaskType::kInternalFindInPage)
      ->PostTask(FROM_HERE, run_loop.QuitClosure());
  run_loop.Run();

  // The generator should still not have completed. Navigate the page to a new
  // document.
  EXPECT_FALSE(did_finish);
  LoadURL("https://example.com/next.html");
  request_next.Complete(R"HTML(
    <!DOCTYPE html>
    NEXT PAGE
  )HTML");

  // The generation should complete but return failure, the agent should not
  // have been created.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(did_finish);
  EXPECT_EQ(GetAgentCount(*container), 0ul);

  // Ensure the new document doesn't somehow get involved.
  auto* new_container =
      AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());
  ASSERT_NE(new_container, container);
  EXPECT_EQ(GetAgentCount(*new_container), 0ul);
}

}  // namespace blink

"""

```