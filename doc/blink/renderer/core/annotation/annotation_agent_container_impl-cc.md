Response:
Let's break down the thought process for analyzing this Chromium source code file. The goal is to understand its function, its relationships to web technologies, and potential usage scenarios and errors.

**1. Initial Reading and High-Level Understanding:**

* **Keywords:**  "annotation," "agent," "container."  This immediately suggests it's about adding or managing annotations within a web page.
* **File Path:** `blink/renderer/core/annotation/annotation_agent_container_impl.cc`. The `blink/renderer/core` part tells us it's a core part of the rendering engine. The `annotation` directory confirms the theme. `_impl.cc` suggests this is an implementation file.
* **Includes:** Look at the included headers. They provide clues about dependencies and functionality:
    * `base/functional/callback.h`, `base/trace_event/typed_macros.h`:  Suggests asynchronous operations and performance tracing.
    * `components/shared_highlighting/...`:  Points to a feature related to sharing highlighted text.
    * `third_party/blink/renderer/core/annotation/...`:  References other annotation-related classes within Blink.
    * `third_party/blink/renderer/core/editing/...`:  Indicates interaction with text editing and selection.
    * `third_party/blink/renderer/core/execution_context/...`:  Relates to the environment where JavaScript runs.
    * `third_party/blink/renderer/core/fragment_directive/...`:  Suggests handling of URL fragments for specific text portions.
    * `third_party/blink/renderer/core/frame/...`, `third_party/blink/renderer/core/page/...`:  Indicates interaction with the frame and page structure.

**2. Identifying Key Classes and Methods:**

* **`AnnotationAgentContainerImpl`:** This is the main class. The methods within it will define its functionality.
* **Static Methods:**  `CreateIfNeeded`, `FromIfExists`, `BindReceiver`. These suggest a pattern for managing a single instance per document and binding it to Mojo (Chromium's inter-process communication system).
* **Core Functionality Methods:**
    * `AddObserver`, `RemoveObserver`:  Observability pattern.
    * `CreateUnboundAgent`, `CreateAgent`, `CreateAgentFromSelection`:  Methods for creating annotation agents. The "Unbound" part is interesting – suggesting a two-step creation process.
    * `RemoveAgent`:  For removing agents.
    * `PerformInitialAttachments`:  Indicates a lifecycle event related to activating annotations.
    * `DidFinishSelectorGeneration`:  Callback for asynchronous selector generation.
    * `OpenedContextMenuOverSelection`:  Handles context menu interactions.
    * `IsLifecycleCleanForAttachment`, `ShouldPreemptivelyGenerate`:  Logic for controlling when annotations are created.
    * `ScheduleBeginMainFrame`:  Triggers a rendering update.
    * `GetAgentsOfType`: Retrieves agents based on type.

**3. Tracing the Flow and Interactions:**

* **Mojo Bindings:** The `BindReceiver` method is crucial. It shows how this C++ code communicates with other parts of Chromium (likely browser UI or other renderers) via Mojo interfaces (`mojom::blink::AnnotationAgentContainer`).
* **Agent Creation:** The various `CreateAgent` methods show different pathways for creating annotations:
    * `CreateAgent`: Directly from a serialized selector (likely from a persisted annotation or an external source).
    * `CreateAgentFromSelection`: Based on the user's current text selection.
* **Annotation Types:** The `mojom::blink::AnnotationType` enum (SharedHighlight, UserNote, TextFinder) reveals the different kinds of annotations supported.
* **Selector Generation:** The interaction with `AnnotationAgentGenerator` and the `DidFinishSelectorGeneration` callback is important for understanding how the precise location of the annotation is determined. The involvement of `TextFragmentSelector` links this to URL fragment directives.
* **Attachment:** The `PerformInitialAttachments` method and the `NeedsAttachment` check within `AnnotationAgentImpl` highlight the mechanism for activating the annotations once the document is ready.

**4. Connecting to Web Technologies (HTML, CSS, JavaScript):**

* **HTML:** Annotations are tied to specific elements or text nodes in the HTML structure. The selectors generated will identify these locations.
* **CSS:** The rendering and styling of annotations (highlights, underlines, etc.) are likely handled by CSS, though this file doesn't directly manage that. The creation of annotations might trigger CSS updates.
* **JavaScript:**  JavaScript can trigger the creation of annotations through the Mojo interface. For instance, a browser extension might use this API to create user notes. The `CreateAgentFromSelection` flow implies a user action (selecting text) that JavaScript can be aware of and initiate the annotation process.

**5. Considering User Actions and Errors:**

* **User Selection:** The `CreateAgentFromSelection` path directly involves user interaction. Selecting text and then triggering an action (e.g., a context menu item) leads to this code.
* **Invalid Selectors:** The code explicitly handles the case where `AnnotationSelector::Deserialize` returns null, indicating a corrupted or invalid selector. This could happen if persisted annotation data is malformed.
* **Asynchronous Operations:** The asynchronous nature of selector generation (using callbacks) introduces potential timing issues if not handled correctly.

**6. Debugging Clues:**

* **Tracing:** The `TRACE_EVENT` macros are valuable debugging tools, allowing developers to track the execution flow and performance of annotation creation.
* **Assertions (`DCHECK`, `CHECK`):** These sanity checks help identify unexpected states during development. A failing assertion provides a clear indication of a bug.
* **Mojo Communication:**  Debugging issues often involves examining the Mojo messages being passed between components.

**Self-Correction/Refinement during Analysis:**

* **Initial Thought:**  Might have initially focused solely on visual highlighting.
* **Correction:** Realized that annotations can have different types (UserNote, TextFinder) and aren't just about visual highlighting.
* **Initial Thought:**  Assumed JavaScript directly calls these C++ methods.
* **Correction:** Recognized the role of Mojo as the intermediary for communication between different processes.
* **Initial Thought:**  Overlooked the importance of the `PerformInitialAttachments` method.
* **Correction:** Understood this is a crucial step in the document lifecycle for activating annotations.

By following this systematic approach, combining code reading with knowledge of the Chromium architecture and web technologies, we can arrive at a comprehensive understanding of the functionality of this source code file.
好的，让我们来分析一下 `blink/renderer/core/annotation/annotation_agent_container_impl.cc` 这个 Chromium Blink 引擎源代码文件。

**文件功能概述:**

`AnnotationAgentContainerImpl` 的主要职责是作为文档（Document）中 `AnnotationAgentImpl` 的容器和管理器。简单来说，它负责以下几个核心功能：

1. **创建和管理 `AnnotationAgentImpl` 实例:**  根据不同的 Annotation 类型（例如，SharedHighlight，UserNote，TextFinder）和选择器 (Selector) 信息，创建并维护文档中所有 `AnnotationAgentImpl` 的实例。
2. **与外部通信:** 通过 Mojo 接口 `mojom::blink::AnnotationAgentContainer`，接收来自浏览器或其他进程的请求，例如创建 Annotation Agent。
3. **处理用户选择:** 响应用户在页面上的文本选择操作，并基于选择生成相应的 Annotation Agent。
4. **生命周期管理:**  在文档的不同生命周期阶段（例如，页面可见时）执行与 Annotation 相关的操作，例如激活 SharedHighlight。
5. **观察者模式:** 提供观察者机制，允许其他组件监听 Annotation Agent 容器的状态变化。
6. **集成 Text Fragment 功能:**  与 Text Fragment API 集成，利用 TextFragmentSelector 来创建和定位 Annotation。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件虽然是 C++ 代码，但在 Blink 渲染引擎中扮演着桥梁的角色，连接了底层的渲染机制和上层的 JavaScript API 以及页面的 HTML 和 CSS。

* **JavaScript:**
    * **触发 Annotation 创建:** JavaScript 代码可以通过 Chromium 提供的扩展 API 或内部机制，调用到这个 C++ 模块来创建 Annotation。例如，一个浏览器扩展想要创建一个用户笔记 (UserNote)，它可能会发送一个消息到浏览器进程，最终浏览器进程会调用 `AnnotationAgentContainerImpl::CreateAgentFromSelection` 或 `AnnotationAgentContainerImpl::CreateAgent`。
    * **获取 Annotation 信息:** 虽然这个文件本身不直接暴露 JavaScript API，但它管理的 `AnnotationAgentImpl` 可能会有方法将信息传递回 JavaScript 环境（通常通过 Mojo 接口）。例如，JavaScript 可以查询当前页面有哪些 SharedHighlight。

    **举例说明:**  假设一个网页应用想要实现一个 "分享高亮" 功能。当用户在网页上选择一段文字并点击 "分享" 按钮时，JavaScript 代码可能会执行以下操作：
    1. 获取用户选择的文本范围。
    2. 调用 Chromium 提供的 API (可能封装了 Mojo 调用)  请求创建一个 `SharedHighlight` 类型的 Annotation Agent，并将选择的文本范围信息传递给后端。
    3. 后端（浏览器进程）接收到请求后，会调用 `AnnotationAgentContainerImpl::CreateAgentFromSelection` 或 `CreateAgent`，并传入必要的参数。

* **HTML:**
    * **Annotation 的目标:** Annotation 最终会关联到 HTML 文档中的特定元素或文本节点。`AnnotationSelector` 和 `TextFragmentSelector` 的作用就是精确地定位这些 HTML 内容。
    * **Text Fragment 指令:**  SharedHighlight 功能与 URL 中的 Text Fragment 指令紧密相关。当用户通过包含 `#text=...` 的 URL 访问页面时，Blink 引擎会解析这个指令，并调用到 `AnnotationAgentContainerImpl` 来创建相应的 `SharedHighlight` Annotation Agent，从而高亮指定的文本。

    **举例说明:**  用户分享了一个包含高亮文本的链接，例如 `https://example.com/page#text=start:,end:`。当浏览器加载这个页面时，Blink 引擎会：
    1. 解析 URL 中的 `#text=start:,end:`  Text Fragment 指令。
    2. 调用 `AnnotationAgentContainerImpl` 创建一个 `SharedHighlight` 类型的 Annotation Agent。
    3. `AnnotationAgentImpl` 会根据 Text Fragment 指令的信息，在 HTML 文档中找到对应的文本范围。
    4. 通过某种方式（可能涉及到 CSS 操作，但这部分不在本文件的职责范围内），将该文本高亮显示。

* **CSS:**
    * **Annotation 的样式:**  虽然 `AnnotationAgentContainerImpl` 不直接处理 CSS，但 Annotation 的视觉呈现（例如，高亮颜色、下划线等）通常是通过 CSS 来实现的。  `AnnotationAgentImpl` 的创建和激活可能会触发相应的 CSS 样式应用。

    **举例说明:** 当一个 `SharedHighlight` Annotation Agent 被创建并激活后，可能会有一个预定义的 CSS 规则被应用到被高亮的文本上，例如设置背景颜色为黄色。这个 CSS 规则可能是在 Blink 引擎内部定义的，或者是由网页开发者提供的。

**逻辑推理 (假设输入与输出):**

假设用户在页面上选中了 "这是一段需要高亮的文本"。

**假设输入:**

* 用户操作: 选中文本 "这是一段需要高亮的文本"。
* 触发事件:  用户点击了 "分享高亮" 按钮（假设网页提供了这样的功能）。
* `AnnotationAgentContainerImpl::CreateAgentFromSelection` 被调用，参数包括:
    * `type`: `mojom::blink::AnnotationType::kSharedHighlight`
    * 当前 Frame 的选择信息（包含选中文本的起始和结束位置）。

**逻辑推理过程:**

1. `AnnotationAgentContainerImpl::CreateAgentFromSelection` 调用 `annotation_agent_generator_->GetForCurrentSelection()` 来生成一个 `TextFragmentSelector`。
2. `AnnotationAgentGenerator` 会分析当前的选择，生成一个能够唯一标识这段文本的 `TextFragmentSelector`，例如 `{ "strategy": "exact", "textStart": "这是一段需要", "textEnd": "亮的文本" }`。
3. `AnnotationAgentContainerImpl::DidFinishSelectorGeneration`  回调函数被调用，接收到生成的 `TextFragmentSelector`。
4. 创建一个 `TextAnnotationSelector` 实例，封装了 `TextFragmentSelector`。
5. 创建一个未绑定的 `AnnotationAgentImpl` 实例，类型为 `kSharedHighlight`，使用创建的 `TextAnnotationSelector`。
6. 创建 Mojo 管道，用于与外部 (例如，浏览器进程) 通信。
7. 调用回调函数 `callback`，将包含 `serialized_selector` (序列化后的 `TextAnnotationSelector`) 的 `SelectorCreationResult` 返回给调用者（JavaScript 代码）。
8. 将 `AnnotationAgentImpl` 绑定到创建的 Mojo 管道。
9. 在适当的时机（例如，页面可见时），`AnnotationAgentImpl::Attach` 被调用，实际执行高亮操作（可能涉及到 DOM 操作和 CSS 样式应用）。

**预期输出:**

* 一个 `SharedHighlight` 类型的 `AnnotationAgentImpl` 实例被成功创建并添加到 `agents_` 列表中。
* 通过 Mojo 管道，调用者 (JavaScript 代码) 接收到一个包含 `serialized_selector` 的结果，该 `serialized_selector` 可以用于生成包含 `#text=...` 的分享链接。
* 当页面完成渲染后，选中的文本 "这是一段需要高亮的文本" 会被高亮显示。

**用户或编程常见的使用错误:**

1. **在错误的生命周期阶段创建 Annotation:**  例如，在文档尚未加载完成或处于非激活状态时尝试创建 Annotation Agent，可能会导致失败或不可预测的行为。`AnnotationAgentContainerImpl::CreateIfNeeded` 的检查就是为了避免这种情况。
2. **传递无效的选择器数据:**  如果外部传递的 `serialized_selector` 无效，`AnnotationSelector::Deserialize` 会返回 null，导致 Annotation Agent 创建失败。这可能是由于数据损坏或不兼容的版本导致的。
3. **Mojo 管道错误:**  Mojo 管道的连接断开或错误配置会导致通信失败，Annotation Agent 无法正常工作。
4. **假设 Annotation 会立即生效:**  Annotation 的创建和激活可能是异步的。开发者不能假设在调用创建方法后，Annotation 会立即生效并显示在页面上。需要处理异步操作完成的回调。
5. **未处理 `CreateAgentFromSelectionCallback` 的错误情况:**  `DidFinishSelectorGeneration` 方法中会检查 `shared_highlighting::LinkGenerationError`。如果开发者没有正确处理错误情况，可能会导致功能异常。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户想要使用 "分享高亮" 功能，并最终触发了 `AnnotationAgentContainerImpl::CreateAgentFromSelection`。以下是可能的步骤：

1. **用户选择文本:** 用户在浏览器页面上使用鼠标或键盘选中了一段文本。
2. **用户触发分享操作:**  用户可能点击了页面上的 "分享高亮" 按钮，或者使用了浏览器的右键菜单中的 "分享" 功能，或者使用了浏览器扩展提供的分享功能。
3. **JavaScript 代码介入:** 网页上的 JavaScript 代码或者浏览器扩展的 JavaScript 代码监听到了用户的操作。
4. **调用 Chromium API:** JavaScript 代码调用 Chromium 提供的 API (可能是 `navigator.share` API 的扩展，或者是特定的扩展 API)，请求创建一个 SharedHighlight。
5. **浏览器进程接收请求:** 浏览器进程接收到来自渲染进程的创建 Annotation 的请求。
6. **Mojo 调用:** 浏览器进程通过 Mojo 接口，调用渲染进程中对应 Frame 的 `AnnotationAgentContainerImpl::CreateAgentFromSelection` 方法。
7. **AnnotationAgentContainerImpl 处理:** `AnnotationAgentContainerImpl` 接收到调用，开始创建 Annotation Agent 的流程。

**调试线索:**

* **检查 JavaScript 代码:**  确认 JavaScript 代码是否正确获取了用户选择的文本范围，并正确调用了 Chromium 提供的 API。
* **Mojo 日志:**  查看 Chromium 的 Mojo 日志，确认浏览器进程和渲染进程之间的通信是否正常，请求和响应是否正确传递。
* **断点调试:** 在 `AnnotationAgentContainerImpl::CreateAgentFromSelection` 和 `AnnotationAgentGenerator::GetForCurrentSelection` 等关键方法设置断点，查看参数值和执行流程。
* **Trace 事件:**  代码中使用了 `TRACE_EVENT` 宏。在 Chromium 的 tracing 系统 (chrome://tracing) 中查看相关的事件，可以了解 Annotation Agent 的创建过程和性能。
* **检查选择 API:**  确认 `Frame.selection()` 返回的选择是否符合预期。
* **检查 Text Fragment 生成逻辑:**  如果高亮结果不正确，可能需要检查 `AnnotationAgentGenerator` 中生成 `TextFragmentSelector` 的逻辑。

希望以上分析能够帮助你理解 `AnnotationAgentContainerImpl` 的功能和作用。

Prompt: 
```
这是目录为blink/renderer/core/annotation/annotation_agent_container_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/annotation/annotation_agent_container_impl.h"

#include "base/functional/callback.h"
#include "base/trace_event/typed_macros.h"
#include "components/shared_highlighting/core/common/disabled_sites.h"
#include "components/shared_highlighting/core/common/shared_highlighting_features.h"
#include "third_party/blink/renderer/core/annotation/annotation_agent_generator.h"
#include "third_party/blink/renderer/core/annotation/annotation_agent_impl.h"
#include "third_party/blink/renderer/core/annotation/annotation_selector.h"
#include "third_party/blink/renderer/core/annotation/text_annotation_selector.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_handler.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_selector.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"

namespace blink {

namespace {
const char* ToString(mojom::blink::AnnotationType type) {
  switch (type) {
    case mojom::blink::AnnotationType::kSharedHighlight:
      return "SharedHighlight";
    case mojom::blink::AnnotationType::kUserNote:
      return "UserNote";
    case mojom::blink::AnnotationType::kTextFinder:
      return "TextFinder";
  }
}
}  // namespace

// static
const char AnnotationAgentContainerImpl::kSupplementName[] =
    "AnnotationAgentContainerImpl";

void AnnotationAgentContainerImpl::AddObserver(Observer* observer) {
  observers_.insert(observer);
}

void AnnotationAgentContainerImpl::RemoveObserver(Observer* observer) {
  observers_.erase(observer);
}

// static
AnnotationAgentContainerImpl* AnnotationAgentContainerImpl::CreateIfNeeded(
    Document& document) {
  if (!document.IsActive()) {
    return nullptr;
  }

  AnnotationAgentContainerImpl* container = FromIfExists(document);
  if (!container) {
    container =
        MakeGarbageCollected<AnnotationAgentContainerImpl>(document, PassKey());
    Supplement<Document>::ProvideTo(document, container);
  }

  return container;
}

// static
AnnotationAgentContainerImpl* AnnotationAgentContainerImpl::FromIfExists(
    Document& document) {
  return Supplement<Document>::From<AnnotationAgentContainerImpl>(document);
}

// static
void AnnotationAgentContainerImpl::BindReceiver(
    LocalFrame* frame,
    mojo::PendingReceiver<mojom::blink::AnnotationAgentContainer> receiver) {
  DCHECK(frame);
  DCHECK(frame->GetDocument());
  Document& document = *frame->GetDocument();

  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(document);
  if (!container)
    return;

  container->Bind(std::move(receiver));
}

AnnotationAgentContainerImpl::AnnotationAgentContainerImpl(Document& document,
                                                           PassKey)
    : Supplement<Document>(document),
      receivers_(this, document.GetExecutionContext()) {
  LocalFrame* frame = document.GetFrame();
  DCHECK(frame);

  annotation_agent_generator_ =
      MakeGarbageCollected<AnnotationAgentGenerator>(frame);
}

void AnnotationAgentContainerImpl::Bind(
    mojo::PendingReceiver<mojom::blink::AnnotationAgentContainer> receiver) {
  receivers_.Add(std::move(receiver),
                 GetDocument().GetTaskRunner(TaskType::kInternalDefault));
}

void AnnotationAgentContainerImpl::Trace(Visitor* visitor) const {
  visitor->Trace(receivers_);
  visitor->Trace(agents_);
  visitor->Trace(annotation_agent_generator_);
  visitor->Trace(observers_);
  Supplement<Document>::Trace(visitor);
}

void AnnotationAgentContainerImpl::PerformInitialAttachments() {
  TRACE_EVENT("blink",
              "AnnotationAgentContainerImpl::PerformInitialAttachments",
              "num_agents", agents_.size());
  CHECK(IsLifecycleCleanForAttachment());

  if (GetFrame().GetPage()->IsPageVisible()) {
    page_has_been_visible_ = true;
  }

  for (Observer* observer : observers_) {
    observer->WillPerformAttach();
  }

  for (auto& agent : agents_) {
    if (agent->NeedsAttachment()) {
      // SharedHighlights must wait until the page has been made visible at
      // least once before searching. See:
      // https://wicg.github.io/scroll-to-text-fragment/#search-timing:~:text=If%20a%20UA,in%20background%20documents.
      if (agent->GetType() == mojom::blink::AnnotationType::kSharedHighlight &&
          !page_has_been_visible_) {
        continue;
      }

      agent->Attach(PassKey());
    }
  }
}

AnnotationAgentImpl* AnnotationAgentContainerImpl::CreateUnboundAgent(
    mojom::blink::AnnotationType type,
    AnnotationSelector& selector) {
  auto* agent_impl = MakeGarbageCollected<AnnotationAgentImpl>(
      *this, type, selector, PassKey());
  agents_.push_back(agent_impl);

  // Attachment will happen as part of the document lifecycle in a new frame.
  ScheduleBeginMainFrame();

  return agent_impl;
}

void AnnotationAgentContainerImpl::RemoveAgent(AnnotationAgentImpl& agent,
                                               AnnotationAgentImpl::PassKey) {
  DCHECK(!agent.IsAttached());
  wtf_size_t index = agents_.Find(&agent);
  DCHECK_NE(index, kNotFound);
  agents_.EraseAt(index);
}

HeapHashSet<Member<AnnotationAgentImpl>>
AnnotationAgentContainerImpl::GetAgentsOfType(
    mojom::blink::AnnotationType type) {
  HeapHashSet<Member<AnnotationAgentImpl>> agents_of_type;
  for (auto& agent : agents_) {
    if (agent->GetType() == type)
      agents_of_type.insert(agent);
  }

  return agents_of_type;
}

void AnnotationAgentContainerImpl::CreateAgent(
    mojo::PendingRemote<mojom::blink::AnnotationAgentHost> host_remote,
    mojo::PendingReceiver<mojom::blink::AnnotationAgent> agent_receiver,
    mojom::blink::AnnotationType type,
    const String& serialized_selector) {
  TRACE_EVENT("blink", "AnnotationAgentContainerImpl::CreateAgent", "type",
              ToString(type), "selector", serialized_selector);
  DCHECK(GetSupplementable());

  AnnotationSelector* selector =
      AnnotationSelector::Deserialize(serialized_selector);

  // If the selector was invalid, we should drop the bindings which the host
  // will see as a disconnect.
  // TODO(bokan): We could support more graceful fallback/error reporting by
  // calling an error method on the host.
  if (!selector) {
    TRACE_EVENT_INSTANT("blink", "Failed to deserialize selector");
    return;
  }

  auto* agent_impl = CreateUnboundAgent(type, *selector);
  agent_impl->Bind(std::move(host_remote), std::move(agent_receiver));
}

void AnnotationAgentContainerImpl::CreateAgentFromSelection(
    mojom::blink::AnnotationType type,
    CreateAgentFromSelectionCallback callback) {
  TRACE_EVENT("blink", "AnnotationAgentContainerImpl::CreateAgentFromSelection",
              "type", ToString(type));
  DCHECK(annotation_agent_generator_);
  annotation_agent_generator_->GetForCurrentSelection(
      type,
      WTF::BindOnce(&AnnotationAgentContainerImpl::DidFinishSelectorGeneration,
                    WrapWeakPersistent(this), std::move(callback)));
}

// TODO(cheickcisse@): Move shared highlighting enums, also used in user note to
// annotation.mojom.
void AnnotationAgentContainerImpl::DidFinishSelectorGeneration(
    CreateAgentFromSelectionCallback callback,
    mojom::blink::AnnotationType type,
    shared_highlighting::LinkGenerationReadyStatus ready_status,
    const String& selected_text,
    const TextFragmentSelector& selector,
    shared_highlighting::LinkGenerationError error) {
  TRACE_EVENT("blink",
              "AnnotationAgentContainerImpl::DidFinishSelectorGeneration",
              "type", ToString(type));

  if (error != shared_highlighting::LinkGenerationError::kNone) {
    std::move(callback).Run(/*SelectorCreationResult=*/nullptr, error,
                            ready_status);
    return;
  }

  // If the document was detached then selector generation must have returned
  // an error.
  CHECK(GetSupplementable());

  // TODO(bokan): Why doesn't this clear selection?
  GetFrame().Selection().Clear();

  mojo::PendingRemote<mojom::blink::AnnotationAgentHost> pending_host_remote;
  mojo::PendingReceiver<mojom::blink::AnnotationAgent> pending_agent_receiver;

  // TODO(bokan): This replies with the selector before performing attachment
  // (i.e. before the highlight is shown). If we'd prefer to guarantee the
  // highlight is showing before the creation flow begins we can swap these.
  auto* annotation_selector =
      MakeGarbageCollected<TextAnnotationSelector>(selector);

  mojom::blink::SelectorCreationResultPtr selector_creation_result =
      mojom::blink::SelectorCreationResult::New();
  selector_creation_result->host_receiver =
      pending_host_remote.InitWithNewPipeAndPassReceiver();
  selector_creation_result->agent_remote =
      pending_agent_receiver.InitWithNewPipeAndPassRemote();
  selector_creation_result->serialized_selector =
      annotation_selector->Serialize();
  DCHECK(!selector_creation_result->serialized_selector.empty())
      << "User note creation received an empty selector for mojo binding "
         "result";
  selector_creation_result->selected_text = selected_text;
  DCHECK(!selector_creation_result->selected_text.empty())
      << "User note creation received an empty text for mojo binding result";

  std::move(callback).Run(std::move(selector_creation_result), error,
                          ready_status);

  AnnotationAgentImpl* agent_impl =
      CreateUnboundAgent(type, *annotation_selector);
  agent_impl->Bind(std::move(pending_host_remote),
                   std::move(pending_agent_receiver));
}

void AnnotationAgentContainerImpl::OpenedContextMenuOverSelection() {
  DCHECK(annotation_agent_generator_);
  if (!ShouldPreemptivelyGenerate())
    return;

  annotation_agent_generator_->PreemptivelyGenerateForCurrentSelection();
}

bool AnnotationAgentContainerImpl::IsLifecycleCleanForAttachment() const {
  return GetDocument().HasFinishedParsing() &&
         !GetDocument().NeedsLayoutTreeUpdate() &&
         !GetFrame().View()->NeedsLayout();
}

bool AnnotationAgentContainerImpl::ShouldPreemptivelyGenerate() {
  if (!shared_highlighting::ShouldOfferLinkToText(GURL(GetDocument().Url()))) {
    return false;
  }

  if (GetFrame().Selection().SelectedText().empty()) {
    return false;
  }

  if (GetFrame().IsOutermostMainFrame()) {
    return true;
  }

  // Only generate for iframe urls if they are supported
  return shared_highlighting::SupportsLinkGenerationInIframe(
      GURL(GetFrame().GetDocument()->Url()));
}

void AnnotationAgentContainerImpl::ScheduleBeginMainFrame() {
  GetFrame().GetPage()->GetChromeClient().ScheduleAnimation(GetFrame().View());
}

Document& AnnotationAgentContainerImpl::GetDocument() const {
  Document* document = GetSupplementable();
  CHECK(document);
  return *document;
}

LocalFrame& AnnotationAgentContainerImpl::GetFrame() const {
  LocalFrame* frame = GetDocument().GetFrame();
  CHECK(frame);
  return *frame;
}

}  // namespace blink

"""

```