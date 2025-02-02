Response:
The user is asking for a summary of the functionality of the `inspector_accessibility_agent.cc` file in the Chromium Blink engine. I need to analyze the code and identify its main purpose. The file name suggests it's related to the accessibility inspector in developer tools.

Here's a breakdown of the steps to address the request:

1. **Identify the core responsibility:** The file is named `inspector_accessibility_agent.cc`, implying it acts as an agent for the accessibility inspector. This likely involves fetching and formatting accessibility information for display in the inspector.

2. **Analyze key classes and methods:**
    - `InspectorAccessibilityAgent`:  The main class, responsible for coordinating the accessibility information retrieval.
    - `getPartialAXTree`:  A method suggesting the ability to retrieve a portion of the accessibility tree.
    - `BuildProtocolAXNodeForAXObject`:  Indicates the conversion of internal accessibility objects (`AXObject`) into a protocol format suitable for the inspector.
    - Methods like `FillLiveRegionProperties`, `FillGlobalStates`, etc.: These methods suggest the gathering of specific accessibility properties.

3. **Determine its relationship with web technologies:** Accessibility directly relates to HTML structure (ARIA attributes), CSS (visual presentation impacting accessibility), and JavaScript (dynamic updates and interactions affecting accessibility).

4. **Infer logic and data flow:**  The code likely takes a DOM node as input and retrieves its corresponding accessibility information, potentially including its ancestors and descendants. It then converts this information into a structured format for the developer tools.

5. **Identify potential user errors and debugging steps:** Misconfigured ARIA attributes or incorrect HTML structure can lead to inaccurate accessibility information displayed by this agent. Developers would typically use the browser's developer tools to inspect the accessibility tree.

6. **Focus on the provided first part of the file:** I need to summarize the functionality based *only* on the code provided in the first part.

**Mental Sandbox Simulation:**

- Imagine a user right-clicks an element and selects "Inspect". The DOM inspector shows the HTML structure. The user then switches to the "Accessibility" tab. This `InspectorAccessibilityAgent` is likely involved in fetching and presenting that accessibility information.
- Consider a case where an element has `aria-label="My Label"`. This agent would be responsible for extracting that information and presenting it in the inspector.
- Think about dynamic updates. If JavaScript changes an element's ARIA attributes, this agent might need to update the accessibility tree in the inspector.

**Constraint Checklist & Confidence Score:**

1. List the functions: Yes.
2. Relationship with JavaScript, HTML, CSS: Yes.
3. Examples for the relationship: Yes.
4. Logical reasoning (input/output): Yes.
5. User/programming errors: Yes.
6. User steps to reach here: Yes.
7. Summarize functionality (part 1): Yes.

Confidence Score: 5/5

Strategizing complete. I will now proceed with generating the response based on these insights.
这是 `blink/renderer/modules/accessibility/inspector_accessibility_agent.cc` 文件的第一部分，主要负责将 Blink 渲染引擎内部的 Accessibility (可访问性) 信息转化为开发者工具可以理解的协议格式，以便在浏览器的开发者工具的 "Accessibility" 面板中展示。

以下是该文件的功能归纳：

**主要功能:**

1. **作为 Accessibility 信息的桥梁:**  该文件充当了 Blink 内部的 Accessibility 模块 (如 `AXObjectCache`, `AXObject`) 和开发者工具 (通过 Inspector 协议) 之间的桥梁。它的主要任务是从内部的 `AXObject` 结构中提取信息，并将其转换为预定义的协议消息格式 (`protocol::Accessibility::AXNode` 等)。

2. **提供 Accessibility 树的部分视图:**  `getPartialAXTree` 方法允许开发者工具请求特定 DOM 节点的 Accessibility 信息，以及其相关的祖先和后代节点的信息，从而构建 Accessibility 树的部分视图。

3. **构建用于协议传输的 AXNode 对象:**  文件中包含多个函数 (例如 `BuildProtocolAXNodeForAXObject`, `BuildProtocolAXNodeForIgnoredAXObject`, `BuildProtocolAXNodeForUnignoredAXObject`)，负责将内部的 `AXObject` 对象转换为 `protocol::Accessibility::AXNode` 对象。这个转换过程包括提取节点的角色、名称、状态、属性、与其他节点的关系等信息。

4. **处理忽略的 Accessibility 节点:**  该文件能够识别并处理被 Accessibility 树忽略的节点，并在协议中标记它们以及它们被忽略的原因。

5. **收集并格式化各种 Accessibility 属性:**  文件中定义了多个辅助函数 (例如 `FillLiveRegionProperties`, `FillGlobalStates`, `FillWidgetProperties`, `FillRelationships`, `FillSparseAttributes`)，用于收集并格式化各种与 Accessibility 相关的属性，例如 ARIA 属性、状态、角色、层级关系、以及与其他节点的关系（例如 `aria-describedby`, `aria-owns`）。

**与 Javascript, HTML, CSS 的关系:**

这个文件间接地与 JavaScript, HTML, CSS 有关，因为它处理的 Accessibility 信息正是基于这些 Web 技术构建的：

* **HTML:**  HTML 元素及其 ARIA 属性 (例如 `role`, `aria-label`, `aria-live`) 是 Accessibility 信息的重要来源。该文件会读取这些属性，并将它们转化为协议中的相应字段。
    * **举例:**  如果一个 HTML 元素有 `role="button"` 和 `aria-label="关闭"`,  `BuildProtocolAXNodeForAXObject` 函数会提取这些信息，并在生成的 `AXNode` 对象中设置 `role` 和 `name` 属性。

* **CSS:** CSS 的渲染结果会影响 Accessibility 树的构建。例如，`display: none` 的元素通常不会出现在 Accessibility 树中 (会被忽略)。该文件会处理这种被忽略的情况，并在协议中提供忽略原因。
    * **举例:** 如果一个元素因为 CSS 样式 `visibility: hidden;` 而被 Accessibility 树忽略， `BuildProtocolAXNodeForIgnoredAXObject` 函数会识别出这个原因，并在 `ignoredReasons` 字段中体现出来。

* **JavaScript:** JavaScript 可以动态地修改 DOM 结构和 ARIA 属性，从而影响 Accessibility 信息。当 JavaScript 做出更改时，Blink 的 Accessibility 模块会更新 `AXObjectCache`，而 `InspectorAccessibilityAgent` 会反映这些更新。
    * **举例:**  JavaScript 使用 `element.setAttribute('aria-valuenow', '50')` 修改了一个滑块的值。当开发者工具请求该元素的 Accessibility 信息时，`FillWidgetProperties` 函数会读取最新的 `aria-valuenow` 值，并将其包含在协议消息中。

**逻辑推理 (假设输入与输出):**

假设开发者工具请求 ID 为 123 的 DOM 节点的 Accessibility 信息 (`dom_node_id = 123`)。

* **假设输入:** `dom_node_id = 123`
* **内部处理:**
    1. `getPartialAXTree` 方法被调用。
    2. 通过 `dom_agent_` 获取对应的 DOM 节点。
    3. 从 `AXObjectCache` 中获取与该 DOM 节点关联的 `AXObject`。
    4. 调用 `BuildProtocolAXNodeForAXObject` 将 `AXObject` 转换为 `protocol::Accessibility::AXNode` 对象。
    5. 在转换过程中，会调用 `Fill...Properties` 系列函数来填充各种 Accessibility 属性。
* **可能的输出 (部分):**  一个 `protocol::Accessibility::AXNode` 对象，可能包含以下信息：
    ```json
    {
      "nodeId": "456", // AXObject 的 ID
      "ignored": false,
      "role": {
        "type": "role",
        "value": "button"
      },
      "chromeRole": {
        "type": "InternalRole",
        "value": 17
      },
      "name": {
        "type": "ComputedString",
        "value": "关闭"
      },
      "backendDOMNodeId": 123,
      "childIds": ["457", "458"]
      // ... 其他属性
    }
    ```

**用户或编程常见的使用错误:**

* **错误的 ARIA 属性:** 开发者可能会使用不正确的 ARIA 属性或属性值，导致 Accessibility 信息不准确。例如，将 `aria-hidden="false"` 错误地用在仍然应该被隐藏的元素上。
    * **调试线索:** 开发者在 Accessibility 面板中可能会看到与预期不符的角色、名称或状态信息。他们可以检查 HTML 源代码中相关的 ARIA 属性。

* **动态更新后 Accessibility 信息未同步:**  JavaScript 动态修改了 DOM 结构或 ARIA 属性，但 Accessibility 树没有及时更新。
    * **调试线索:**  开发者在 Accessibility 面板中看到的信息与页面的实际状态不符。他们可以尝试刷新 Accessibility 树或重新加载页面。

* **过度使用或滥用 ARIA:**  在可以使用语义化 HTML 元素的情况下仍然使用 ARIA，或者使用了不必要的 ARIA 属性，可能会导致 Accessibility 树过于复杂或难以理解。
    * **调试线索:** 开发者在 Accessibility 面板中看到大量冗余或意义不明的 Accessibility 节点或属性。

**用户操作到达此处的步骤 (作为调试线索):**

1. **打开开发者工具:** 用户在 Chrome 浏览器中打开开发者工具 (通常通过右键点击页面元素并选择 "检查"，或使用 F12 快捷键)。
2. **切换到 "Elements" (元素) 或 "Accessibility" (可访问性) 面板:**
    * 如果用户在 "Elements" 面板中操作，他们可能会选择一个 DOM 节点。
    * 如果用户直接切换到 "Accessibility" 面板，开发者工具会自动尝试加载当前页面的 Accessibility 信息。
3. **在 "Accessibility" 面板中查看 Accessibility 树:**  开发者工具会向 Blink 进程发送请求，要求提供当前页面或选定元素的 Accessibility 信息。
4. **`getPartialAXTree` 方法被调用:** 当开发者工具需要加载或更新 Accessibility 树的某个部分时，`InspectorAccessibilityAgent` 的 `getPartialAXTree` 方法会被调用。开发者工具可能会指定要加载的根节点 (通过 `dom_node_id`)，以及是否需要加载相关的祖先和后代节点 (`fetch_relatives`)。
5. **信息转换和展示:**  `InspectorAccessibilityAgent` 从 Blink 内部获取 Accessibility 信息，并将其转换为协议格式发送回开发者工具，最终在 "Accessibility" 面板中呈现给用户。

**功能归纳 (基于提供的第一部分):**

该文件的第一部分主要定义了 `InspectorAccessibilityAgent` 类及其核心功能，用于将 Blink 内部的 Accessibility 信息转换为开发者工具可以理解的协议格式。它专注于构建 `protocol::Accessibility::AXNode` 对象，处理忽略的节点，并提供获取部分 Accessibility 树的功能。其中包含用于收集和格式化各种 Accessibility 属性的辅助函数，并初步展示了与 HTML, CSS 之间的联系。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/inspector_accessibility_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/accessibility/inspector_accessibility_agent.h"

#include <memory>

#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/node_list.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/inspector_dom_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_style_sheet.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object_cache_impl.h"
#include "third_party/blink/renderer/modules/accessibility/inspector_type_builder_helper.h"
#include "third_party/blink/renderer/platform/wtf/deque.h"
#include "ui/accessibility/ax_enums.mojom-blink.h"
#include "ui/accessibility/ax_mode.h"
#include "ui/accessibility/ax_node_data.h"

namespace blink {

using protocol::Maybe;
using protocol::Accessibility::AXNode;
using protocol::Accessibility::AXNodeId;
using protocol::Accessibility::AXProperty;
using protocol::Accessibility::AXPropertyName;
using protocol::Accessibility::AXRelatedNode;
using protocol::Accessibility::AXValue;
using protocol::Accessibility::AXValueSource;
using protocol::Accessibility::AXValueType;
namespace AXPropertyNameEnum = protocol::Accessibility::AXPropertyNameEnum;

namespace {

static const AXID kIDForInspectedNodeWithNoAXNode = 0;
// Send node updates to the frontend not more often than once within the
// `kNodeSyncThrottlePeriod` time frame.
static const base::TimeDelta kNodeSyncThrottlePeriod = base::Milliseconds(250);
// Interval at which we check if there is a need to schedule visual updates.
static const base::TimeDelta kVisualUpdateCheckInterval =
    kNodeSyncThrottlePeriod + base::Milliseconds(10);

void AddHasPopupProperty(ax::mojom::blink::HasPopup has_popup,
                         protocol::Array<AXProperty>& properties) {
  switch (has_popup) {
    case ax::mojom::blink::HasPopup::kFalse:
      break;
    case ax::mojom::blink::HasPopup::kTrue:
      properties.emplace_back(
          CreateProperty(AXPropertyNameEnum::HasPopup,
                         CreateValue("true", AXValueTypeEnum::Token)));
      break;
    case ax::mojom::blink::HasPopup::kMenu:
      properties.emplace_back(
          CreateProperty(AXPropertyNameEnum::HasPopup,
                         CreateValue("menu", AXValueTypeEnum::Token)));
      break;
    case ax::mojom::blink::HasPopup::kListbox:
      properties.emplace_back(
          CreateProperty(AXPropertyNameEnum::HasPopup,
                         CreateValue("listbox", AXValueTypeEnum::Token)));
      break;
    case ax::mojom::blink::HasPopup::kTree:
      properties.emplace_back(
          CreateProperty(AXPropertyNameEnum::HasPopup,
                         CreateValue("tree", AXValueTypeEnum::Token)));
      break;
    case ax::mojom::blink::HasPopup::kGrid:
      properties.emplace_back(
          CreateProperty(AXPropertyNameEnum::HasPopup,
                         CreateValue("grid", AXValueTypeEnum::Token)));
      break;
    case ax::mojom::blink::HasPopup::kDialog:
      properties.emplace_back(
          CreateProperty(AXPropertyNameEnum::HasPopup,
                         CreateValue("dialog", AXValueTypeEnum::Token)));
      break;
  }
}

void FillLiveRegionProperties(AXObject& ax_object,
                              const ui::AXNodeData& node_data,
                              protocol::Array<AXProperty>& properties) {
  if (!node_data.IsActiveLiveRegionRoot())
    return;

  const String& live =
      node_data
          .GetStringAttribute(
              ax::mojom::blink::StringAttribute::kContainerLiveStatus)
          .c_str();
  properties.emplace_back(CreateProperty(
      AXPropertyNameEnum::Live, CreateValue(live, AXValueTypeEnum::Token)));

  const bool atomic = node_data.GetBoolAttribute(
      ax::mojom::blink::BoolAttribute::kContainerLiveAtomic);
  properties.emplace_back(
      CreateProperty(AXPropertyNameEnum::Atomic, CreateBooleanValue(atomic)));

  const String& relevant =
      node_data
          .GetStringAttribute(
              ax::mojom::blink::StringAttribute::kContainerLiveRelevant)
          .c_str();
  properties.emplace_back(
      CreateProperty(AXPropertyNameEnum::Relevant,
                     CreateValue(relevant, AXValueTypeEnum::TokenList)));

  if (!ax_object.IsLiveRegionRoot()) {
    properties.emplace_back(CreateProperty(
        AXPropertyNameEnum::Root,
        CreateRelatedNodeListValue(*(ax_object.LiveRegionRoot()))));
  }
}

void FillGlobalStates(AXObject& ax_object,
                      const ui::AXNodeData& node_data,
                      protocol::Array<AXProperty>& properties) {
  if (node_data.GetRestriction() == ax::mojom::blink::Restriction::kDisabled) {
    properties.emplace_back(
        CreateProperty(AXPropertyNameEnum::Disabled, CreateBooleanValue(true)));
  }

  if (const AXObject* hidden_root = ax_object.AriaHiddenRoot()) {
    properties.emplace_back(
        CreateProperty(AXPropertyNameEnum::Hidden, CreateBooleanValue(true)));
    properties.emplace_back(
        CreateProperty(AXPropertyNameEnum::HiddenRoot,
                       CreateRelatedNodeListValue(*hidden_root)));
  }

  ax::mojom::blink::InvalidState invalid_state = node_data.GetInvalidState();
  switch (invalid_state) {
    case ax::mojom::blink::InvalidState::kNone:
      break;
    case ax::mojom::blink::InvalidState::kFalse:
      properties.emplace_back(
          CreateProperty(AXPropertyNameEnum::Invalid,
                         CreateValue("false", AXValueTypeEnum::Token)));
      break;
    case ax::mojom::blink::InvalidState::kTrue:
      properties.emplace_back(
          CreateProperty(AXPropertyNameEnum::Invalid,
                         CreateValue("true", AXValueTypeEnum::Token)));
      break;
    default:
      // TODO(aboxhall): expose invalid: <nothing> and source: aria-invalid as
      // invalid value
      properties.emplace_back(CreateProperty(
          AXPropertyNameEnum::Invalid,
          CreateValue(
              node_data
                  .GetStringAttribute(ax::mojom::blink::StringAttribute::
                                          kAriaInvalidValueDeprecated)
                  .c_str(),
              AXValueTypeEnum::String)));
      break;
  }

  if (node_data.HasState(ax::mojom::blink::State::kFocusable)) {
    properties.emplace_back(CreateProperty(
        AXPropertyNameEnum::Focusable,
        CreateBooleanValue(true, AXValueTypeEnum::BooleanOrUndefined)));
  }
  if (ax_object.IsFocused()) {
    properties.emplace_back(CreateProperty(
        AXPropertyNameEnum::Focused,
        CreateBooleanValue(true, AXValueTypeEnum::BooleanOrUndefined)));
  }

  if (node_data.HasState(ax::mojom::blink::State::kEditable)) {
    properties.emplace_back(CreateProperty(
        AXPropertyNameEnum::Editable,
        CreateValue(node_data.HasState(ax::mojom::blink::State::kRichlyEditable)
                        ? "richtext"
                        : "plaintext",
                    AXValueTypeEnum::Token)));
  }
  if (node_data.HasAction(ax::mojom::blink::Action::kSetValue)) {
    properties.emplace_back(CreateProperty(
        AXPropertyNameEnum::Settable,
        CreateBooleanValue(true, AXValueTypeEnum::BooleanOrUndefined)));
  }
}

bool RoleAllowsMultiselectable(ax::mojom::Role role) {
  return role == ax::mojom::Role::kGrid || role == ax::mojom::Role::kListBox ||
         role == ax::mojom::Role::kTabList ||
         role == ax::mojom::Role::kTreeGrid || role == ax::mojom::Role::kTree;
}

bool RoleAllowsReadonly(ax::mojom::Role role) {
  return role == ax::mojom::Role::kGrid || role == ax::mojom::Role::kGridCell ||
         role == ax::mojom::Role::kTextField ||
         role == ax::mojom::Role::kColumnHeader ||
         role == ax::mojom::Role::kRowHeader ||
         role == ax::mojom::Role::kTreeGrid;
}

bool RoleAllowsRequired(ax::mojom::Role role) {
  return role == ax::mojom::Role::kComboBoxGrouping ||
         role == ax::mojom::Role::kComboBoxMenuButton ||
         role == ax::mojom::Role::kGridCell ||
         role == ax::mojom::Role::kListBox ||
         role == ax::mojom::Role::kRadioGroup ||
         role == ax::mojom::Role::kSpinButton ||
         role == ax::mojom::Role::kTextField ||
         role == ax::mojom::Role::kTextFieldWithComboBox ||
         role == ax::mojom::Role::kTree ||
         role == ax::mojom::Role::kColumnHeader ||
         role == ax::mojom::Role::kRowHeader ||
         role == ax::mojom::Role::kTreeGrid;
}

void FillWidgetProperties(AXObject& ax_object,
                          const ui::AXNodeData& node_data,
                          protocol::Array<AXProperty>& properties) {
  ax::mojom::blink::Role role = node_data.role;
  const String& autocomplete =
      node_data
          .GetStringAttribute(ax::mojom::blink::StringAttribute::kAutoComplete)
          .c_str();
  if (!autocomplete.empty())
    properties.emplace_back(
        CreateProperty(AXPropertyNameEnum::Autocomplete,
                       CreateValue(autocomplete, AXValueTypeEnum::Token)));

  AddHasPopupProperty(node_data.GetHasPopup(), properties);

  const int hierarchical_level = node_data.GetIntAttribute(
      ax::mojom::blink::IntAttribute::kHierarchicalLevel);
  if (hierarchical_level > 0) {
    properties.emplace_back(CreateProperty(AXPropertyNameEnum::Level,
                                           CreateValue(hierarchical_level)));
  }

  if (RoleAllowsMultiselectable(role)) {
    const bool multiselectable =
        node_data.HasState(ax::mojom::blink::State::kMultiselectable);
    properties.emplace_back(
        CreateProperty(AXPropertyNameEnum::Multiselectable,
                       CreateBooleanValue(multiselectable)));
  }

  if (node_data.HasState(ax::mojom::blink::State::kVertical)) {
    properties.emplace_back(
        CreateProperty(AXPropertyNameEnum::Orientation,
                       CreateValue("vertical", AXValueTypeEnum::Token)));
  } else if (node_data.HasState(ax::mojom::blink::State::kHorizontal)) {
    properties.emplace_back(
        CreateProperty(AXPropertyNameEnum::Orientation,
                       CreateValue("horizontal", AXValueTypeEnum::Token)));
  }

  if (role == ax::mojom::Role::kTextField) {
    properties.emplace_back(CreateProperty(
        AXPropertyNameEnum::Multiline,
        CreateBooleanValue(
            node_data.HasState(ax::mojom::blink::State::kMultiline))));
  }

  if (RoleAllowsReadonly(role)) {
    properties.emplace_back(CreateProperty(
        AXPropertyNameEnum::Readonly,
        CreateBooleanValue(node_data.GetRestriction() ==
                           ax::mojom::blink::Restriction::kReadOnly)));
  }

  if (RoleAllowsRequired(role)) {
    properties.emplace_back(CreateProperty(
        AXPropertyNameEnum::Required,
        CreateBooleanValue(
            node_data.HasState(ax::mojom::blink::State::kRequired))));
  }

  if (ax_object.IsRangeValueSupported()) {
    properties.emplace_back(CreateProperty(
        AXPropertyNameEnum::Valuemin,
        CreateValue(node_data.GetFloatAttribute(
            ax::mojom::blink::FloatAttribute::kMinValueForRange))));
    properties.emplace_back(CreateProperty(
        AXPropertyNameEnum::Valuemax,
        CreateValue(node_data.GetFloatAttribute(
            ax::mojom::blink::FloatAttribute::kMaxValueForRange))));
    properties.emplace_back(CreateProperty(
        AXPropertyNameEnum::Valuetext,
        CreateValue(
            node_data
                .GetStringAttribute(ax::mojom::blink::StringAttribute::kValue)
                .c_str())));
  }
}

void FillWidgetStates(AXObject& ax_object,
                      const ui::AXNodeData& node_data,
                      protocol::Array<AXProperty>& properties) {
  ax::mojom::blink::Role role = node_data.role;
  const char* checked_prop_val = nullptr;
  switch (node_data.GetCheckedState()) {
    case ax::mojom::CheckedState::kTrue:
      checked_prop_val = "true";
      break;
    case ax::mojom::CheckedState::kMixed:
      checked_prop_val = "mixed";
      break;
    case ax::mojom::CheckedState::kFalse:
      checked_prop_val = "false";
      break;
    case ax::mojom::CheckedState::kNone:
      break;
  }
  if (checked_prop_val) {
    auto* const checked_prop_name = role == ax::mojom::Role::kToggleButton
                                        ? AXPropertyNameEnum::Pressed
                                        : AXPropertyNameEnum::Checked;
    properties.emplace_back(CreateProperty(
        checked_prop_name,
        CreateValue(checked_prop_val, AXValueTypeEnum::Tristate)));
  }

  if (node_data.HasState(ax::mojom::blink::State::kCollapsed)) {
    properties.emplace_back(CreateProperty(
        AXPropertyNameEnum::Expanded,
        CreateBooleanValue(false, AXValueTypeEnum::BooleanOrUndefined)));
  } else if (node_data.HasState(ax::mojom::blink::State::kExpanded)) {
    properties.emplace_back(CreateProperty(
        AXPropertyNameEnum::Expanded,
        CreateBooleanValue(true, AXValueTypeEnum::BooleanOrUndefined)));
  }

  if (node_data.HasBoolAttribute(ax::mojom::blink::BoolAttribute::kSelected)) {
    properties.emplace_back(CreateProperty(
        AXPropertyNameEnum::Selected,
        CreateBooleanValue(node_data.GetBoolAttribute(
                               ax::mojom::blink::BoolAttribute::kSelected),
                           AXValueTypeEnum::BooleanOrUndefined)));
  }

  if (node_data.HasBoolAttribute(ax::mojom::blink::BoolAttribute::kModal)) {
    properties.emplace_back(
        CreateProperty(AXPropertyNameEnum::Modal,
                       CreateBooleanValue(node_data.GetBoolAttribute(
                           ax::mojom::blink::BoolAttribute::kModal))));
  }
}

// TODO(crbug/41469336): also show related elements from ElementInternals
void AccessibilityChildrenFromAttribute(const AXObject& ax_object,
                                        const QualifiedName& attribute,
                                        AXObject::AXObjectVector& children) {
  if (!ax_object.GetElement()) {
    return;
  }
  HeapVector<Member<Element>>* elements =
      ax_object.GetElement()->GetAttrAssociatedElements(
          attribute,
          /*resolve_reference_target=*/true);
  if (!elements) {
    return;
  }
  AXObjectCacheImpl& cache = ax_object.AXObjectCache();
  for (const auto& element : *elements) {
    if (AXObject* child = cache.Get(element)) {
      // Only aria-labelledby and aria-describedby can target hidden elements.
      if (!child) {
        continue;
      }
      if (child->IsIgnored() && attribute != html_names::kAriaLabelledbyAttr &&
          attribute != html_names::kAriaLabeledbyAttr &&
          attribute != html_names::kAriaDescribedbyAttr) {
        continue;
      }
      children.push_back(child);
    }
  }
}

void AriaDescribedbyElements(AXObject& ax_object,
                             AXObject::AXObjectVector& describedby) {
  AccessibilityChildrenFromAttribute(
      ax_object, html_names::kAriaDescribedbyAttr, describedby);
}

void AriaOwnsElements(AXObject& ax_object, AXObject::AXObjectVector& owns) {
  AccessibilityChildrenFromAttribute(ax_object, html_names::kAriaOwnsAttr,
                                     owns);
}

std::unique_ptr<AXProperty> CreateRelatedNodeListProperty(
    const String& key,
    AXRelatedObjectVector& nodes) {
  std::unique_ptr<AXValue> node_list_value =
      CreateRelatedNodeListValue(nodes, AXValueTypeEnum::NodeList);
  return CreateProperty(key, std::move(node_list_value));
}

std::unique_ptr<AXProperty> CreateRelatedNodeListProperty(
    const String& key,
    AXObject::AXObjectVector& nodes,
    const QualifiedName& attr,
    AXObject& ax_object) {
  std::unique_ptr<AXValue> node_list_value = CreateRelatedNodeListValue(nodes);
  const AtomicString& attr_value = ax_object.AriaAttribute(attr);
  node_list_value->setValue(protocol::StringValue::create(attr_value));
  return CreateProperty(key, std::move(node_list_value));
}

void FillRelationships(AXObject& ax_object,
                       protocol::Array<AXProperty>& properties) {
  AXObject::AXObjectVector results;
  AriaDescribedbyElements(ax_object, results);
  if (!results.empty()) {
    properties.emplace_back(CreateRelatedNodeListProperty(
        AXPropertyNameEnum::Describedby, results,
        html_names::kAriaDescribedbyAttr, ax_object));
  }
  results.clear();

  AriaOwnsElements(ax_object, results);
  if (!results.empty()) {
    properties.emplace_back(
        CreateRelatedNodeListProperty(AXPropertyNameEnum::Owns, results,
                                      html_names::kAriaOwnsAttr, ax_object));
  }
  results.clear();
}

void GetObjectsFromAXIDs(const AXObjectCacheImpl& cache,
                         const std::vector<int32_t>& ax_ids,
                         AXObject::AXObjectVector* ax_objects) {
  for (const auto& ax_id : ax_ids) {
    AXObject* ax_object = cache.ObjectFromAXID(ax_id);
    if (!ax_object)
      continue;
    ax_objects->push_back(ax_object);
  }
}

void FillSparseAttributes(AXObject& ax_object,
                          const ui::AXNodeData& node_data,
                          protocol::Array<AXProperty>& properties) {
  if (node_data.HasBoolAttribute(ax::mojom::blink::BoolAttribute::kBusy)) {
    const auto is_busy =
        node_data.GetBoolAttribute(ax::mojom::blink::BoolAttribute::kBusy);
    properties.emplace_back(
        CreateProperty(AXPropertyNameEnum::Busy,
                       CreateValue(is_busy, AXValueTypeEnum::Boolean)));
  }

  if (node_data.HasStringAttribute(ax::mojom::blink::StringAttribute::kUrl)) {
    const auto url =
        node_data.GetStringAttribute(ax::mojom::blink::StringAttribute::kUrl);
    properties.emplace_back(CreateProperty(
        AXPropertyNameEnum::Url,
        CreateValue(WTF::String(url.c_str()), AXValueTypeEnum::String)));
  }

  if (node_data.HasStringAttribute(
          ax::mojom::blink::StringAttribute::kKeyShortcuts)) {
    const auto key_shortcuts = node_data.GetStringAttribute(
        ax::mojom::blink::StringAttribute::kKeyShortcuts);
    properties.emplace_back(
        CreateProperty(AXPropertyNameEnum::Keyshortcuts,
                       CreateValue(WTF::String(key_shortcuts.c_str()),
                                   AXValueTypeEnum::String)));
  }

  if (node_data.HasStringAttribute(
          ax::mojom::blink::StringAttribute::kRoleDescription)) {
    const auto role_description = node_data.GetStringAttribute(
        ax::mojom::blink::StringAttribute::kRoleDescription);
    properties.emplace_back(
        CreateProperty(AXPropertyNameEnum::Roledescription,
                       CreateValue(WTF::String(role_description.c_str()),
                                   AXValueTypeEnum::String)));
  }

  if (node_data.HasIntListAttribute(
          ax::mojom::blink::IntListAttribute::kActionsIds)) {
    const auto ax_ids = node_data.GetIntListAttribute(
        ax::mojom::blink::IntListAttribute::kActionsIds);
    AXObject::AXObjectVector ax_objects;
    GetObjectsFromAXIDs(ax_object.AXObjectCache(), ax_ids, &ax_objects);
    properties.emplace_back(
        CreateRelatedNodeListProperty(AXPropertyNameEnum::Actions, ax_objects,
                                      html_names::kAriaActionsAttr, ax_object));
  }

  if (node_data.HasIntAttribute(
          ax::mojom::blink::IntAttribute::kActivedescendantId)) {
    AXObject* target =
        ax_object.AXObjectCache().ObjectFromAXID(node_data.GetIntAttribute(
            ax::mojom::blink::IntAttribute::kActivedescendantId));
    properties.emplace_back(
        CreateProperty(AXPropertyNameEnum::Activedescendant,
                       CreateRelatedNodeListValue(*target)));
  }

  if (node_data.HasIntListAttribute(
          ax::mojom::blink::IntListAttribute::kErrormessageIds)) {
    const auto ax_ids = node_data.GetIntListAttribute(
        ax::mojom::blink::IntListAttribute::kErrormessageIds);
    AXObject::AXObjectVector ax_objects;
    GetObjectsFromAXIDs(ax_object.AXObjectCache(), ax_ids, &ax_objects);
    properties.emplace_back(CreateRelatedNodeListProperty(
        AXPropertyNameEnum::Errormessage, ax_objects,
        html_names::kAriaErrormessageAttr, ax_object));
  }

  if (node_data.HasIntListAttribute(
          ax::mojom::blink::IntListAttribute::kControlsIds)) {
    const auto ax_ids = node_data.GetIntListAttribute(
        ax::mojom::blink::IntListAttribute::kControlsIds);
    AXObject::AXObjectVector ax_objects;
    GetObjectsFromAXIDs(ax_object.AXObjectCache(), ax_ids, &ax_objects);
    properties.emplace_back(CreateRelatedNodeListProperty(
        AXPropertyNameEnum::Controls, ax_objects, html_names::kAriaControlsAttr,
        ax_object));
  }

  if (node_data.HasIntListAttribute(
          ax::mojom::blink::IntListAttribute::kDetailsIds)) {
    const auto ax_ids = node_data.GetIntListAttribute(
        ax::mojom::blink::IntListAttribute::kDetailsIds);
    AXObject::AXObjectVector ax_objects;
    GetObjectsFromAXIDs(ax_object.AXObjectCache(), ax_ids, &ax_objects);
    properties.emplace_back(
        CreateRelatedNodeListProperty(AXPropertyNameEnum::Details, ax_objects,
                                      html_names::kAriaDetailsAttr, ax_object));
  }

  if (node_data.HasIntListAttribute(
          ax::mojom::blink::IntListAttribute::kFlowtoIds)) {
    const auto ax_ids = node_data.GetIntListAttribute(
        ax::mojom::blink::IntListAttribute::kFlowtoIds);
    AXObject::AXObjectVector ax_objects;
    GetObjectsFromAXIDs(ax_object.AXObjectCache(), ax_ids, &ax_objects);
    properties.emplace_back(
        CreateRelatedNodeListProperty(AXPropertyNameEnum::Flowto, ax_objects,
                                      html_names::kAriaFlowtoAttr, ax_object));
  }
  return;
}

// Creates a role name value that is easy to read by developers. This function
// reduces the granularity of the role and uses ARIA role strings when possible.
std::unique_ptr<AXValue> CreateRoleNameValue(ax::mojom::Role role) {
  bool is_internal = false;
  const String& role_name = AXObject::RoleName(role, &is_internal);
  const auto& value_type =
      is_internal ? AXValueTypeEnum::InternalRole : AXValueTypeEnum::Role;
  return CreateValue(role_name, value_type);
}

// Creates an integer role value that is fixed over releases, is not lossy, and
// is more suitable for machine learning models or automation.
std::unique_ptr<AXValue> CreateInternalRoleValue(ax::mojom::Role role) {
  return CreateValue(static_cast<int>(role), AXValueTypeEnum::InternalRole);
}

}  // namespace

using EnabledAgentsMultimap =
    HeapHashMap<WeakMember<LocalFrame>,
                Member<HeapHashSet<Member<InspectorAccessibilityAgent>>>>;

EnabledAgentsMultimap& EnabledAgents() {
  DEFINE_STATIC_LOCAL(Persistent<EnabledAgentsMultimap>, enabled_agents,
                      (MakeGarbageCollected<EnabledAgentsMultimap>()));
  return *enabled_agents;
}

InspectorAccessibilityAgent::InspectorAccessibilityAgent(
    InspectedFrames* inspected_frames,
    InspectorDOMAgent* dom_agent)
    : inspected_frames_(inspected_frames),
      dom_agent_(dom_agent),
      enabled_(&agent_state_, /*default_value=*/false) {}

protocol::Response InspectorAccessibilityAgent::getPartialAXTree(
    Maybe<int> dom_node_id,
    Maybe<int> backend_node_id,
    Maybe<String> object_id,
    Maybe<bool> fetch_relatives,
    std::unique_ptr<protocol::Array<AXNode>>* nodes) {
  Node* dom_node = nullptr;
  protocol::Response response =
      dom_agent_->AssertNode(dom_node_id, backend_node_id, object_id, dom_node);
  if (!response.IsSuccess())
    return response;

  Document& document = dom_node->GetDocument();
  LocalFrame* local_frame = document.GetFrame();
  if (!local_frame)
    return protocol::Response::ServerError("Frame is detached.");

  auto& cache = AttachToAXObjectCache(&document);
  cache.UpdateAXForAllDocuments();
  ScopedFreezeAXCache freeze(cache);

  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      document.Lifecycle());

  AXObject* inspected_ax_object = cache.Get(dom_node);
  *nodes = std::make_unique<protocol::Array<protocol::Accessibility::AXNode>>();
  if (inspected_ax_object) {
    (*nodes)->emplace_back(
        BuildProtocolAXNodeForAXObject(*inspected_ax_object));
  } else {
    (*nodes)->emplace_back(BuildProtocolAXNodeForDOMNodeWithNoAXNode(
        IdentifiersFactory::IntIdForNode(dom_node)));
  }

  if (!fetch_relatives.value_or(true)) {
    return protocol::Response::Success();
  }

  if (inspected_ax_object && !inspected_ax_object->IsIgnored())
    AddChildren(*inspected_ax_object, true, *nodes, cache);

  AXObject* parent_ax_object;
  if (inspected_ax_object) {
    parent_ax_object = inspected_ax_object->ParentObjectIncludedInTree();
  } else {
    // Walk up parents until an AXObject can be found.
    auto* shadow_root = DynamicTo<ShadowRoot>(dom_node);
    Node* parent_node = shadow_root ? &shadow_root->host()
                                    : FlatTreeTraversal::Parent(*dom_node);
    parent_ax_object = cache.Get(parent_node);
    while (parent_node && !parent_ax_object) {
      shadow_root = DynamicTo<ShadowRoot>(parent_node);
      parent_node = shadow_root ? &shadow_root->host()
                                : FlatTreeTraversal::Parent(*parent_node);
      parent_ax_object = cache.Get(parent_node);
    }
  }
  if (!parent_ax_object)
    return protocol::Response::Success();
  AddAncestors(*parent_ax_object, inspected_ax_object, *nodes, cache);

  return protocol::Response::Success();
}

void InspectorAccessibilityAgent::AddAncestors(
    AXObject& first_ancestor,
    AXObject* inspected_ax_object,
    std::unique_ptr<protocol::Array<AXNode>>& nodes,
    AXObjectCacheImpl& cache) const {
  std::unique_ptr<AXNode> first_parent_node_object =
      BuildProtocolAXNodeForAXObject(first_ancestor);
  // Since the inspected node is ignored it is missing from the first ancestors
  // childIds. We therefore add it to maintain the tree structure:
  if (!inspected_ax_object || inspected_ax_object->IsIgnored()) {
    auto child_ids = std::make_unique<protocol::Array<AXNodeId>>();
    auto* existing_child_ids = first_parent_node_object->getChildIds(nullptr);

    // put the ignored node first regardless of DOM structure.
    child_ids->insert(
        child_ids->begin(),
        String::Number(inspected_ax_object ? inspected_ax_object->AXObjectID()
                                           : kIDForInspectedNodeWithNoAXNode));
    if (existing_child_ids) {
      for (auto id : *existing_child_ids)
        child_ids->push_back(id);
    }
    first_parent_node_object->setChildIds(std::move(child_ids));
  }
  nodes->emplace_back(std::move(first_parent_node_object));
  AXObject* ancestor = first_ancestor.ParentObjectIncludedInTree();
  while (ancestor) {
    std::unique_ptr<AXNode> parent_node_object =
        BuildProtocolAXNodeForAXObject(*ancestor);
    nodes->emplace_back(std::move(parent_node_object));
    ancestor = ancestor->ParentObjectIncludedInTree();
  }
}

std::unique_ptr<AXNode>
InspectorAccessibilityAgent::BuildProtocolAXNodeForDOMNodeWithNoAXNode(
    int backend_node_id) const {
  AXID ax_id = kIDForInspectedNodeWithNoAXNode;
  std::unique_ptr<AXNode> ignored_node_object =
      AXNode::create()
          .setNodeId(String::Number(ax_id))
          .setIgnored(true)
          .build();
  ax::mojom::blink::Role role = ax::mojom::blink::Role::kNone;
  ignored_node_object->setRole(CreateRoleNameValue(role));
  ignored_node_object->setChromeRole(CreateInternalRoleValue(role));
  auto ignored_reason_properties =
      std::make_unique<protocol::Array<AXProperty>>();
  ignored_reason_properties->emplace_back(
      CreateProperty(IgnoredReason(kAXNotRendered)));
  ignored_node_object->setIgnoredReasons(std::move(ignored_reason_properties));
  ignored_node_object->setBackendDOMNodeId(backend_node_id);
  return ignored_node_object;
}

std::unique_ptr<AXNode>
InspectorAccessibilityAgent::BuildProtocolAXNodeForAXObject(
    AXObject& ax_object,
    bool force_name_and_role) const {
  std::unique_ptr<protocol::Accessibility::AXNode> protocol_node;
  if (ax_object.IsIgnored()) {
    protocol_node =
        BuildProtocolAXNodeForIgnoredAXObject(ax_object, force_name_and_role);
  } else {
    protocol_node = BuildProtocolAXNodeForUnignoredAXObject(ax_object);
  }
  const AXObject::AXObjectVector& children =
      ax_object.ChildrenIncludingIgnored();
  auto child_ids = std::make_unique<protocol::Array<AXNodeId>>();
  for (AXObject* child : children)
    child_ids->emplace_back(String::Number(child->AXObjectID()));
  protocol_node->setChildIds(std::move(child_ids));

  Node* node = ax_object.GetNode();
  if (node)
    protocol_node->setBackendDOMNodeId(IdentifiersFactory::IntIdForNode(node));

  const AXObject* parent = ax_object.ParentObjectIncludedInTree();
  if (parent) {
    protocol_node->setParentId(String::Number(parent->AXObjectID()));
  } else {
    DCHECK(ax_object.GetDocument() && ax_object.GetDocument()->GetFrame());
    auto& frame_token =
        ax_object.GetDocument()->GetFrame()->GetDevToolsFrameToken();
    protocol_node->setFrameId(IdentifiersFactory::IdFromToken(frame_token));
  }
  return protocol_node;
}

std::unique_ptr<AXNode>
InspectorAccessibilityAgent::BuildProtocolAXNodeForIgnoredAXObject(
    AXObject& ax_object,
    bool force_name_and_role) const {
  std::unique_ptr<AXNode> ignored_node_object =
      AXNode::create()
          .setNodeId(String::Number(ax_object.AXObjectID()))
          .setIgnored(true)
          .build();
  ax::mojom::blink::Role role = ax::mojom::blink::Role::kNone;
  ignored_node_object->setRole(CreateRoleNameValue(role));
  ignored_node_object->setChromeRole(CreateInternalRoleValue(role));

  if (force_name_and_role) {
    // Compute accessible name and sources and attach to protocol node:
    AXObject::NameSources name_sources;
    String computed_name = ax_object.GetName(&name_sources);
    std::unique_ptr<AXValue> name =
        CreateValue(computed_name, AXValueTypeEnum::ComputedString);
    ignored_node_object->setName(std::move(name));
    ignored_node_object->setRole(CreateRoleNameValue(ax_object.RoleValue()));
    ignored_node_object->setChromeRole(
        CreateInternalRoleValue(ax_object.RoleValue()));
  }

  // Compute and attach reason for node to be ignored:
  AXObject::IgnoredReasons ignored_reasons;
  ax_object.ComputeIsIgnored(&ignored_reasons);
  auto ignored_reason_properties =
      std::make_unique<protocol::Array<AXProperty>>();
  for (IgnoredReason& reason : ignored_reasons)
    ignored_reason_properties->emplace_back(CreateProperty(reason));
  ignored_node_object->setIgnoredReasons(std::move(ignored_reason_properties));

  return ignored_node_object;
}

std::unique_ptr<AXNode>
InspectorAccessibilityAgent::BuildProtocolAXNodeForUnignoredAXObject(
    AXObject& ax_object) const {
  std::unique_ptr<AXNode> node_object =
      AXNode::create()
          .setNodeId(String::Number(ax_object.AXObjectID()))
          .setIgnored(false)
          .build();
  auto properties = std::make_unique<protocol::Array<AXProperty>>();
  ui::AXNodeData node_data;
  ax_object.Serialize(&node_data, ui::kAXModeComplete);
  node_object->setRole(CreateRoleNameValue(node_data.role));
  node_object->setChromeRole(CreateInternalRoleValue(node_data.role));
  FillLiveRegionProperties(ax_object, node_data, *(properties.get()));
  FillGlobalStates(ax_object, node_data, *(properties.get()));
  FillWidgetProperties(ax_object, node_data, *(properties.get()));
  FillWidgetStates(ax_object, node_data, *(properties.get()));
  FillRelationships(ax_object, *(properties.get()));
  FillSparseAttributes(ax_object, node_data, *(properties.get()));

  AXObject::NameSources name_sources;
  String computed_name = ax_object.GetName(&name_sources);
  if (!name_sources.empty()) {
    std::unique_ptr<AXValue> name =
        CreateValue(computed_name, AXValueTypeEnum::ComputedString);
    if (!name_sources.empty()) {
      auto name_source_properties =
          std::make_unique<protocol::Array<AXValueSource>>();
      for (NameSour
```