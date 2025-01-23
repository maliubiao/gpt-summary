Response:
My thought process for analyzing the `page_test_base.cc` file and generating the response went through these stages:

1. **Understanding the Purpose:** The file name and the `#include` directives immediately signal that this is a base class for writing Blink renderer unit tests. The "page" part suggests it deals with simulating a web page environment.

2. **Core Functionality Identification (High-Level):** I scanned the class definition (`class PageTestBase`) and its public methods. Keywords like `SetUp`, `TearDown`, `GetDocument`, `GetFrame`, `SetBodyInnerHTML`, `InsertStyleElement`, `NavigateTo`, etc., pointed to its role in setting up and manipulating a testing environment that mimics a web page.

3. **Detailed Feature Breakdown (Method-by-Method):** I went through each public method and identified its specific purpose:
    * **Lifecycle Management:** `SetUp`, `TearDown` (creating and destroying the testing page). The different `SetUp` overloads indicated flexibility in configuration.
    * **DOM Access:** `GetDocument`, `GetFrame`, `GetElementById` (accessing core web page components).
    * **Content Manipulation:** `SetBodyInnerHTML`, `SetBodyContent`, `SetHtmlInnerHTML` (setting the HTML content).
    * **Styling:** `InsertStyleElement`, `LoadAhem`, `LoadNoto`, `GetStyleEngine` (dealing with CSS).
    * **Navigation:** `NavigateTo` (simulating page loads).
    * **Rendering and Layout:** `UpdateAllLifecyclePhasesForTest`, `ToSimpleLayoutTree` (forcing layout and visualizing the layout tree).
    * **Testing Utilities:** `EnableCompositing`, `EnablePlatform`, `FastForwardBy`, `AdvanceClock` (controlling test execution environment and time).
    * **Clipboard Mocking:** The nested `MockClipboardHostProvider` class was clearly for isolating clipboard interactions in tests.
    * **Font Handling:** `LoadFontFromFile` (loading custom fonts).
    * **Selection:** `Selection()` (accessing the selected content).
    * **Animation:** `GetAnimationClock`, `GetPendingAnimations`.
    * **Focus:** `GetFocusController`.
    * **Settings:** `SetPreferCompositingToLCDText`,  The `Settings` manipulation within `SetUp`.

4. **Relating to Web Technologies (JavaScript, HTML, CSS):**  As I identified the functionalities, I consciously linked them to their corresponding web technologies:
    * **HTML:**  Methods like `SetBodyInnerHTML`, `GetElementById`, and the inclusion of `<head>`, `<body>` tags in examples directly relate to HTML structure.
    * **CSS:** `InsertStyleElement`, `LoadAhem`, and the concept of style engines are direct connections to CSS styling.
    * **JavaScript:** While the base class doesn't directly execute JavaScript, it sets up the environment where JavaScript would run. The inclusion of V8 bindings (`V8FontFaceDescriptors`) and the ability to manipulate the DOM are key for JavaScript interaction. The `FontFaceSetDocument` also hints at JavaScript's font API.

5. **Identifying Logic and Assumptions:**  I looked for methods that involved decision-making or specific sequences:
    * `GetOrCreateElement`: The logic of checking for existing elements before creating new ones is a simple but important piece of code. I formulated an input/output example for this.
    * `ToSimpleLayoutTree`: The recursive structure and the way it traverses the layout tree are key to its functionality. I provided an example of how the tree structure is represented in the output.
    * `NavigateTo`: The process of creating `WebNavigationParams`, setting headers, and handling CSP is a series of logical steps.

6. **Pinpointing Potential User/Programming Errors:** I thought about common mistakes developers might make when using this base class:
    * Calling `SetUp` multiple times.
    * Calling `EnableCompositing` after `SetUp`.
    * Incorrectly formatted HTML or CSS passed to setter methods.
    * Forgetting to call `UpdateAllLifecyclePhasesForTest` when expecting layout changes.

7. **Tracing User Operations (Debugging Scenario):**  I considered how a developer might end up looking at this file during debugging:
    * A test failure related to rendering, layout, or styling.
    * Investigating unexpected behavior with DOM manipulation.
    * Issues with navigation or resource loading in tests.
    * Problems with clipboard interactions in tests.

8. **Structuring the Response:**  I organized the information logically with clear headings and bullet points to improve readability:
    * **功能 (Functions):**  A concise summary of the class's purpose.
    * **与 JavaScript, HTML, CSS 的关系 (Relationship with JavaScript, HTML, CSS):**  Detailed explanations with specific examples.
    * **逻辑推理 (Logical Reasoning):**  Examples of the internal logic with input/output scenarios.
    * **用户或编程常见的使用错误 (Common User/Programming Errors):**  Practical examples of mistakes.
    * **用户操作及调试线索 (User Operations and Debugging Clues):** Scenarios that would lead a developer to this file.

9. **Refinement and Language:**  I reviewed the generated text for clarity, accuracy, and appropriate terminology, ensuring it matched the context of Chromium and Blink development. I paid attention to the Chinese translation for accuracy and natural flow.

Essentially, I approached this like a code review and documentation exercise, combining technical understanding with the perspective of a developer who might need to use or debug code related to this base class. I iteratively built up the response, starting with the big picture and then drilling down into the details.
`blink/renderer/core/testing/page_test_base.cc` 文件是 Chromium Blink 引擎中用于编写页面相关单元测试的基础类。它提供了一系列工具和方法，用于方便地创建和操作一个模拟的 web 页面环境，以便测试 Blink 渲染引擎的各种功能。

以下是该文件的主要功能：

**1. 提供一个模拟的页面环境:**

* **创建和管理 `DummyPageHolder`:**  `PageTestBase` 内部使用 `DummyPageHolder` 类来创建一个最小化的、可控制的页面环境。这个环境包含了 `Document`、`LocalFrame`、`Page` 等核心的 Blink 对象，允许测试在没有完整浏览器 shell 的情况下模拟页面行为。
* **可配置的页面设置:**  通过 `SetUp` 方法，可以配置模拟页面的各种设置，例如是否启用硬件加速合成（compositing），页面大小等。
* **访问核心 Blink 对象:**  提供了便捷的方法来获取模拟页面的 `Document`、`Page`、`LocalFrame` 等对象，方便测试代码直接操作这些对象。

**2. 操作 DOM 结构和内容:**

* **设置 HTML 内容:**  提供了 `SetBodyInnerHTML`、`SetBodyContent`、`SetHtmlInnerHTML` 等方法，可以方便地设置模拟页面的 `<body>` 或 `<html>` 标签的内部 HTML 内容。
* **插入样式:**  `InsertStyleElement` 方法允许在模拟页面中插入 `<style>` 标签，方便测试 CSS 样式效果。
* **查找元素:**  `GetElementById` 方法用于根据 ID 查找页面中的元素。

**3. 模拟资源加载和导航:**

* **加载字体:**  `LoadAhem` 和 `LoadNoto` 方法预加载了特定的测试字体，`LoadFontFromFile` 方法允许加载自定义字体，用于测试字体相关的渲染功能。
* **模拟页面导航:**  `NavigateTo` 方法允许模拟页面导航到指定的 URL，并可以设置 HTTP 头部，用于测试导航和资源加载相关的逻辑。

**4. 控制渲染和布局过程:**

* **更新生命周期阶段:**  `UpdateAllLifecyclePhasesForTest` 方法强制执行包括样式计算、布局、绘制等所有渲染生命周期阶段，确保测试代码能够观察到渲染结果。
* **获取布局树:**  `ToSimpleLayoutTree` 方法提供了一种将当前页面的布局树以文本形式输出的方式，方便测试代码检查布局结构。

**5. 提供测试辅助功能:**

* **模拟剪贴板操作:**  通过 `MockClipboardHostProvider` 内部类，可以模拟剪贴板的读写操作，避免测试之间的互相干扰。
* **控制时间:**  提供了 `FastForwardBy`、`FastForwardUntilNoTasksRemain`、`AdvanceClock` 等方法，允许在测试中控制时间流逝，用于测试动画、定时器等时间相关的逻辑。
* **启用平台支持:**  `EnablePlatform` 方法用于启用一些底层的平台支持功能，用于特定场景的测试。

**与 JavaScript, HTML, CSS 的关系：**

该文件是测试 Blink 渲染引擎的核心组件，而 JavaScript、HTML 和 CSS 是 Web 页面的三大基石，因此 `page_test_base.cc` 与它们有着密切的关系。

* **HTML:**
    * **举例说明:**  `SetBodyInnerHTML("<div id='test'>Hello</div>")`  会创建一个包含一个 `div` 元素的页面结构。 `GetElementById("test")` 可以获取到这个 `div` 元素。这直接测试了 Blink 对 HTML 结构的处理能力。
    * **用户操作:**  开发者在编写测试时，会使用这些方法来构建测试所需的 DOM 结构，模拟用户在页面上创建和操作元素的过程。

* **CSS:**
    * **举例说明:** `InsertStyleElement("#test { color: red; }")`  会在页面中插入一条 CSS 规则，将 ID 为 `test` 的元素的文字颜色设置为红色。后续的渲染和绘制测试会验证这条 CSS 规则是否生效。
    * **用户操作:** 开发者使用 `InsertStyleElement` 来设置测试场景所需的样式，例如测试特定 CSS 属性的效果，或者测试样式层叠和继承的逻辑。

* **JavaScript:**
    * **举例说明:**  虽然 `PageTestBase` 本身不直接执行 JavaScript 代码，但它提供的环境是 JavaScript 代码运行的基础。例如，当测试 JavaScript 操作 DOM 时，会先使用 `SetBodyInnerHTML` 创建初始的 DOM 结构，然后执行 JavaScript 代码来修改 DOM，最后通过 `UpdateAllLifecyclePhasesForTest` 和检查 DOM 结构来验证 JavaScript 代码的执行结果。`FontFaceSetDocument::From(document)->addForBinding(...)` 这个方法涉及到将字体信息暴露给 JavaScript。
    * **用户操作:** 开发者通常会结合其他的测试工具（例如，模拟执行 JavaScript 代码的框架）来使用 `PageTestBase` 提供的环境，测试 JavaScript 与 HTML 和 CSS 的交互。

**逻辑推理：**

* **假设输入 (针对 `GetOrCreateElement` 方法):**
    * `parent`: 一个 `ContainerNode` 对象，例如 `Document` 或一个 `HTMLElement`。
    * `tag_name`: 一个 `HTMLQualifiedName` 对象，例如 `html_names::kDivTag`。
    * **场景 1：父节点下不存在指定标签名的子元素。**
    * **场景 2：父节点下已存在指定标签名的子元素。**

* **输出:**
    * **场景 1：**  返回一个新的、由 `parent` 文档创建的指定标签名的 `Element` 对象。
    * **场景 2：**  返回父节点下已存在的第一个指定标签名的 `Element` 对象。

* **逻辑:**  `GetOrCreateElement` 方法首先尝试在 `parent` 节点下查找指定标签名的子元素。如果找到，则直接返回已存在的元素；否则，创建一个新的元素并返回。

* **假设输入 (针对 `ToSimpleLayoutTree` 方法):**
    * `layout_object`: 一个 `LayoutObject` 对象，代表页面中的一个渲染对象。
    * 一个包含嵌套的 `div` 和文本节点的简单 DOM 结构。

* **输出:**
```
<root> 
+--div #document 
  |  +--#text "Hello" 
  +--div #document 
    |  +--#text "World" 
```

* **逻辑:**  `ToSimpleLayoutTree` 方法递归遍历 `layout_object` 的子树，并以带有缩进和层级符号的文本格式输出每个 `LayoutObject` 的信息，包括其类型和关联的 DOM 节点（如果存在）。

**用户或编程常见的使用错误：**

* **未调用 `SetUp`:**  如果在测试用例中直接使用 `GetDocument()` 或 `GetFrame()` 等方法而没有先调用 `SetUp()`，会导致程序崩溃，因为模拟的页面环境尚未初始化。
* **在 `SetUp` 后调用 `EnableCompositing`:** `EnableCompositing()` 必须在 `SetUp()` 调用之前调用，因为它会影响 `DummyPageHolder` 的初始化方式。如果在 `SetUp()` 之后调用，将不会生效。
* **忘记调用 `UpdateAllLifecyclePhasesForTest`:**  在修改 DOM 结构或样式后，如果期望这些修改立即生效并反映在布局和渲染结果中，必须调用 `UpdateAllLifecyclePhasesForTest()`。否则，后续的检查可能基于旧的渲染状态。
    * **举例说明:**  开发者设置了元素的样式，然后立即去检查元素的布局属性，但忘记调用 `UpdateAllLifecyclePhasesForTest()`，导致获取到的布局信息仍然是修改前的。
* **错误地使用字体加载方法:**  例如，提供的字体文件路径不正确，或者字体名称与 CSS 中使用的名称不匹配，会导致字体加载失败，影响与字体相关的测试。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设开发者正在编写一个关于 CSS 动画的单元测试，并且遇到了测试失败的情况。以下是一些可能导致开发者查看 `page_test_base.cc` 文件的操作和调试线索：

1. **编写测试用例:** 开发者创建了一个继承自 `PageTestBase` 的测试类，并在其中编写了一个测试方法，用于测试 CSS 动画效果。
2. **运行测试:** 开发者运行该测试用例，发现测试结果与预期不符，例如动画没有按预期执行，或者动画的某个属性值不正确。
3. **检查测试代码:** 开发者首先检查自己的测试代码，确认 DOM 结构、CSS 样式和动画定义是否正确。
4. **怀疑环境问题:** 如果测试代码看起来没有问题，开发者可能会怀疑是不是测试环境的配置有问题，例如是否正确启用了硬件加速合成，或者是否正确加载了所需的字体。
5. **查看 `PageTestBase` 的 `SetUp` 方法:**  开发者可能会查看 `page_test_base.cc` 文件中的 `SetUp` 方法，确认测试环境的默认配置，例如页面大小、是否启用了 compositing 等。
6. **查看与 CSS 相关的辅助方法:**  开发者可能会查看 `InsertStyleElement` 方法，确认样式是否被正确地添加到测试页面中。
7. **查看与时间控制相关的方法:**  由于是动画测试，开发者可能会查看 `FastForwardBy` 或 `AdvanceClock` 等方法，确认是否正确地控制了测试中的时间流逝。
8. **使用布局树输出进行调试:**  如果怀疑是布局问题导致动画异常，开发者可能会使用 `ToSimpleLayoutTree` 方法输出布局树，以便更详细地了解元素的布局结构。
9. **断点调试:** 开发者可能会在 `PageTestBase` 的相关方法中设置断点，例如在 `UpdateAllLifecyclePhasesForTest` 中，以便更深入地了解测试执行过程中 Blink 引擎的内部状态。

总而言之，`blink/renderer/core/testing/page_test_base.cc` 文件是 Blink 渲染引擎单元测试的关键基础设施，开发者在编写和调试页面相关的测试时会频繁地与之交互。理解其功能和使用方法对于有效地进行 Blink 引擎的开发和维护至关重要。

### 提示词
```
这是目录为blink/renderer/core/testing/page_test_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/testing/page_test_base.h"

#include <sstream>

#include "base/containers/span.h"
#include "base/functional/callback.h"
#include "base/test/bind.h"
#include "base/time/default_clock.h"
#include "base/time/default_tick_clock.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_font_face_descriptors.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview_string.h"
#include "third_party/blink/renderer/core/css/css_default_style_sheets.h"
#include "third_party/blink/renderer/core/css/font_face_set_document.h"
#include "third_party/blink/renderer/core/frame/csp/conversion_util.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_collection.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"
#include "third_party/blink/renderer/core/testing/mock_policy_container_host.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

Element* GetOrCreateElement(ContainerNode* parent,
                            const HTMLQualifiedName& tag_name) {
  HTMLCollection* elements = parent->getElementsByTagNameNS(
      tag_name.NamespaceURI(), tag_name.LocalName());
  if (!elements->IsEmpty())
    return elements->item(0);
  return parent->ownerDocument()->CreateRawElement(
      tag_name, CreateElementFlags::ByCreateElement());
}

void ToSimpleLayoutTree(std::ostream& ostream,
                        const LayoutObject& layout_object,
                        int depth) {
  for (int i = 1; i < depth; ++i)
    ostream << "|  ";
  ostream << (depth ? "+--" : "") << layout_object.GetName() << " ";
  if (auto* node = layout_object.GetNode())
    ostream << *node;
  else
    ostream << "(anonymous)";
  if (auto* layout_text_fragment =
          DynamicTo<LayoutTextFragment>(layout_object)) {
    ostream << " (" << layout_text_fragment->TransformedText() << ")";
  } else if (auto* layout_text = DynamicTo<LayoutText>(layout_object)) {
    if (!layout_object.GetNode())
      ostream << " " << layout_text->TransformedText();
  }
  ostream << std::endl;
  for (auto* child = layout_object.SlowFirstChild(); child;
       child = child->NextSibling()) {
    ostream << "  ";
    ToSimpleLayoutTree(ostream, *child, depth + 1);
  }
}

}  // namespace

PageTestBase::MockClipboardHostProvider::MockClipboardHostProvider(
    const blink::BrowserInterfaceBrokerProxy& interface_broker) {
  Install(interface_broker);
}

PageTestBase::MockClipboardHostProvider::MockClipboardHostProvider() = default;

PageTestBase::MockClipboardHostProvider::~MockClipboardHostProvider() {
  if (interface_broker_) {
    interface_broker_->SetBinderForTesting(
        blink::mojom::blink::ClipboardHost::Name_, {});
  }
}

void PageTestBase::MockClipboardHostProvider::Install(
    const blink::BrowserInterfaceBrokerProxy& interface_broker) {
  interface_broker_ = &interface_broker;
  interface_broker_->SetBinderForTesting(
      blink::mojom::blink::ClipboardHost::Name_,
      WTF::BindRepeating(
          &PageTestBase::MockClipboardHostProvider::BindClipboardHost,
          base::Unretained(this)));
}

void PageTestBase::MockClipboardHostProvider::BindClipboardHost(
    mojo::ScopedMessagePipeHandle handle) {
  host_.Bind(mojo::PendingReceiver<blink::mojom::blink::ClipboardHost>(
      std::move(handle)));
}

PageTestBase::PageTestBase() = default;

PageTestBase::PageTestBase(base::test::TaskEnvironment::TimeSource time_source)
    : task_environment_(time_source) {}

PageTestBase::~PageTestBase() {
  dummy_page_holder_.reset();
  MemoryCache::Get()->EvictResources();
  // Clear lazily loaded style sheets.
  CSSDefaultStyleSheets::Instance().PrepareForLeakDetection();
  // Run garbage collection before the task environment is destroyed so task
  // time observers shutdown during GC can unregister themselves.
  ThreadState::Current()->CollectAllGarbageForTesting();
}

void PageTestBase::EnableCompositing() {
  DCHECK(!dummy_page_holder_)
      << "EnableCompositing() must be called before set up";
  enable_compositing_ = true;
}

void PageTestBase::SetUp() {
  DCHECK(!dummy_page_holder_) << "Page should be set up only once";
  auto setter = base::BindLambdaForTesting([&](Settings& settings) {
    if (enable_compositing_)
      settings.SetAcceleratedCompositingEnabled(true);
  });
  dummy_page_holder_ = std::make_unique<DummyPageHolder>(
      gfx::Size(800, 600), nullptr, nullptr, std::move(setter), GetTickClock());

  // Mock out clipboard calls so that tests don't mess
  // with each other's copies/pastes when running in parallel.
  mock_clipboard_host_provider_.Install(GetFrame().GetBrowserInterfaceBroker());

  // Use no-quirks (ake "strict") mode by default.
  GetDocument().SetCompatibilityMode(Document::kNoQuirksMode);

  // Use desktop page scale limits by default.
  GetPage().SetDefaultPageScaleLimits(1, 4);

  // We do a lot of one-offs in unit tests, so update this so that every
  // single test doesn't have to.
  GetStyleEngine().UpdateViewportSize();
}

void PageTestBase::SetUp(gfx::Size size) {
  DCHECK(!dummy_page_holder_) << "Page should be set up only once";
  auto setter = base::BindLambdaForTesting([&](Settings& settings) {
    if (enable_compositing_)
      settings.SetAcceleratedCompositingEnabled(true);
  });
  dummy_page_holder_ = std::make_unique<DummyPageHolder>(
      size, nullptr, nullptr, std::move(setter), GetTickClock());

  // Use no-quirks (ake "strict") mode by default.
  GetDocument().SetCompatibilityMode(Document::kNoQuirksMode);

  // Use desktop page scale limits by default.
  GetPage().SetDefaultPageScaleLimits(1, 4);

  // We do a lot of one-offs in unit tests, so update this so that every
  // single test doesn't have to.
  GetStyleEngine().UpdateViewportSize();
}

void PageTestBase::SetupPageWithClients(
    ChromeClient* chrome_client,
    LocalFrameClient* local_frame_client,
    FrameSettingOverrideFunction setting_overrider,
    gfx::Size size) {
  DCHECK(!dummy_page_holder_) << "Page should be set up only once";
  auto setter = base::BindLambdaForTesting([&](Settings& settings) {
    if (setting_overrider)
      setting_overrider(settings);
    if (enable_compositing_)
      settings.SetAcceleratedCompositingEnabled(true);
  });

  dummy_page_holder_ =
      std::make_unique<DummyPageHolder>(size, chrome_client, local_frame_client,
                                        std::move(setter), GetTickClock());

  // Use no-quirks (ake "strict") mode by default.
  GetDocument().SetCompatibilityMode(Document::kNoQuirksMode);

  // Use desktop page scale limits by default.
  GetPage().SetDefaultPageScaleLimits(1, 4);

  // We do a lot of one-offs in unit tests, so update this so that every
  // single test doesn't have to.
  GetStyleEngine().UpdateViewportSize();
}

void PageTestBase::TearDown() {
  dummy_page_holder_ = nullptr;
  MemoryCache::Get()->EvictResources();
}

Document& PageTestBase::GetDocument() const {
  return dummy_page_holder_->GetDocument();
}

Page& PageTestBase::GetPage() const {
  return dummy_page_holder_->GetPage();
}

LocalFrame& PageTestBase::GetFrame() const {
  return GetDummyPageHolder().GetFrame();
}

FrameSelection& PageTestBase::Selection() const {
  return GetFrame().Selection();
}

void PageTestBase::LoadAhem() {
  LoadAhem(GetFrame());
}

void PageTestBase::LoadAhem(LocalFrame& frame) {
  LoadFontFromFile(frame, test::CoreTestDataPath("Ahem.ttf"),
                   AtomicString("Ahem"));
}

void PageTestBase::LoadFontFromFile(LocalFrame& frame,
                                    String font_path,
                                    const AtomicString& family_name) {
  Document& document = *frame.DomWindow()->document();
  std::optional<Vector<char>> data = test::ReadFromFile(font_path);
  ASSERT_TRUE(data);
  auto* buffer =
      MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferViewOrString>(
          DOMArrayBuffer::Create(base::as_byte_span(*data)));
  FontFace* ahem = FontFace::Create(frame.DomWindow(), family_name, buffer,
                                    FontFaceDescriptors::Create());

  ScriptState* script_state = ToScriptStateForMainWorld(&frame);
  DummyExceptionStateForTesting exception_state;
  FontFaceSetDocument::From(document)->addForBinding(script_state, ahem,
                                                     exception_state);
}

void PageTestBase::LoadNoto() {
  LoadNoto(GetFrame());
}

void PageTestBase::LoadNoto(LocalFrame& frame) {
  LoadFontFromFile(frame,
                   blink::test::PlatformTestDataPath(
                       "third_party/Noto/NotoNaskhArabic-regular.woff2"),
                   AtomicString("NotoArabic"));
}

// Both sets the inner html and runs the document lifecycle.
void PageTestBase::SetBodyInnerHTML(const String& body_content) {
  GetDocument().body()->setInnerHTML(body_content, ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();
}

void PageTestBase::SetBodyContent(const std::string& body_content) {
  SetBodyInnerHTML(String::FromUTF8(body_content));
}

void PageTestBase::SetHtmlInnerHTML(const std::string& html_content) {
  GetDocument().documentElement()->setInnerHTML(String::FromUTF8(html_content));
  UpdateAllLifecyclePhasesForTest();
}

void PageTestBase::InsertStyleElement(const std::string& style_rules) {
  Element* const head =
      GetOrCreateElement(&GetDocument(), html_names::kHeadTag);
  DCHECK_EQ(head, GetOrCreateElement(&GetDocument(), html_names::kHeadTag));
  Element* const style = GetDocument().CreateRawElement(
      html_names::kStyleTag, CreateElementFlags::ByCreateElement());
  style->setTextContent(String(style_rules));
  head->appendChild(style);
}

void PageTestBase::NavigateTo(const KURL& url,
                              const WTF::HashMap<String, String>& headers) {
  auto params = WebNavigationParams::CreateWithEmptyHTMLForTesting(url);

  for (const auto& header : headers)
    params->response.SetHttpHeaderField(header.key, header.value);

  MockPolicyContainerHost mock_policy_container_host;
  params->policy_container = std::make_unique<WebPolicyContainer>(
      WebPolicyContainerPolicies(),
      mock_policy_container_host.BindNewEndpointAndPassDedicatedRemote());

  // Add parsed Content Security Policies to the policy container, simulating
  // what the browser does.
  for (auto& csp : ParseContentSecurityPolicies(
           params->response.HttpHeaderField("content-security-policy"),
           network::mojom::blink::ContentSecurityPolicyType::kEnforce,
           network::mojom::blink::ContentSecurityPolicySource::kHTTP, url)) {
    params->policy_container->policies.content_security_policies.emplace_back(
        ConvertToPublic(std::move(csp)));
  }

  GetFrame().Loader().CommitNavigation(std::move(params),
                                       nullptr /* extra_data */);

  blink::test::RunPendingTasks();
  ASSERT_EQ(url.GetString(), GetDocument().Url().GetString());
}

void PageTestBase::UpdateAllLifecyclePhasesForTest() {
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
}

StyleEngine& PageTestBase::GetStyleEngine() {
  return GetDocument().GetStyleEngine();
}

Element* PageTestBase::GetElementById(const char* id) const {
  return GetDocument().getElementById(AtomicString(id));
}

AnimationClock& PageTestBase::GetAnimationClock() {
  return GetDocument().GetAnimationClock();
}

PendingAnimations& PageTestBase::GetPendingAnimations() {
  return GetDocument().GetPendingAnimations();
}

FocusController& PageTestBase::GetFocusController() const {
  return GetDocument().GetPage()->GetFocusController();
}

void PageTestBase::EnablePlatform() {
  DCHECK(!platform_);
  platform_ =
      std::make_unique<ScopedTestingPlatformSupport<TestingPlatformSupport>>();
}

// See also LayoutTreeAsText to dump with geometry and paint layers.
// static
std::string PageTestBase::ToSimpleLayoutTree(
    const LayoutObject& layout_object) {
  std::ostringstream ostream;
  ostream << std::endl;
  ::blink::ToSimpleLayoutTree(ostream, layout_object, 0);
  return ostream.str();
}

void PageTestBase::SetPreferCompositingToLCDText(bool enable) {
  GetPage().GetSettings().SetPreferCompositingToLCDTextForTesting(enable);
}

const base::TickClock* PageTestBase::GetTickClock() {
  return base::DefaultTickClock::GetInstance();
}

void PageTestBase::FastForwardBy(base::TimeDelta delta) {
  return task_environment_.FastForwardBy(delta);
}

void PageTestBase::FastForwardUntilNoTasksRemain() {
  return task_environment_.FastForwardUntilNoTasksRemain();
}

void PageTestBase::AdvanceClock(base::TimeDelta delta) {
  return task_environment_.AdvanceClock(delta);
}

}  // namespace blink
```