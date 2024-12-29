Response:
Let's break down the thought process for analyzing the `data_transfer.cc` file.

1. **Understand the Core Function:** The filename and the initial comments immediately suggest this file handles data transfer operations, specifically within the Blink rendering engine. Keywords like "clipboard," "drag and drop," and "data transfer" are strong indicators.

2. **Identify Key Classes and Structures:**  A quick scan reveals the central class: `DataTransfer`. Other important classes mentioned in the includes and within the code itself are:
    * `DataObject`:  Likely holds the actual data being transferred.
    * `DataTransferItem`, `DataTransferItemList`: Represent individual data items and collections, crucial for the HTML5 drag and drop API.
    * `FileList`:  Specifically for handling file transfers.
    * `DragImage`: Represents the image shown during a drag operation.
    * Various layout and painting related classes (`LayoutObject`, `PaintLayer`, etc.):  Indicate the handling of visual representations during drag.
    * Classes related to selection and editing (`FrameSelection`, `VisibleSelection`): Suggest integration with copy/paste operations.

3. **Analyze Functionality by Public Methods:**  The public methods of `DataTransfer` provide the best overview of its capabilities. I'd go through them systematically:
    * **Creation (`Create()`):**  Different creation methods suggest different usage scenarios (copy/paste vs. drag and drop).
    * **`setDropEffect()`, `setEffectAllowed()`:** Clearly related to drag and drop, controlling the allowed operations. The comments within the code about ignoring invalid values are important.
    * **`clearData()`, `getData()`, `setData()`:** Core methods for manipulating the data being transferred, essential for both copy/paste and drag and drop. The type normalization logic is a key detail.
    * **`types()`:**  Retrieving the available data types.
    * **`files()`:**  Accessing the transferred files.
    * **`setDragImage()`:**  Customizing the drag feedback.
    * **`WriteURL()`, `WriteSelection()`, `DeclareAndWriteDragImage()`:**  Higher-level functions for populating the `DataObject` with specific content.
    * **`items()`:**  Accessing the data items through the `DataTransferItemList`.
    * **Getter methods (`GetDataObject()`, etc.):**  Provide access to internal state.

4. **Examine Interactions with Web Technologies:**  Based on the function names and included headers, I'd start drawing connections:
    * **JavaScript:**  Methods like `getData()`, `setData()`, `types()`, `files()`, `setDragImage()`, and the `items()` property directly correspond to the JavaScript `DataTransfer` API.
    * **HTML:** The file deals with creating HTML snippets (`CreateMarkup`), setting URLs, and handling image elements, all core HTML concepts. The interaction with form elements during selection is also notable.
    * **CSS:** The `DraggedNodeImageBuilder` uses the `-webkit-drag` pseudo-class, indicating a CSS-based styling mechanism during drag. The coordinate transformations also touch on layout and rendering which are influenced by CSS.

5. **Look for Logical Reasoning and Assumptions:** The code comments and the logic within functions reveal assumptions and reasoning:
    * **Type Normalization:**  The `NormalizeType()` function explicitly converts certain types (like `text/plain` variations and `URL` to `text/uri-list`), indicating a need to handle different ways of representing the same data.
    * **Effect Allowed Conversion:** The `ConvertEffectAllowedToDragOperationsMask()` and its reverse demonstrate mapping between string-based effect descriptions and bitmask representations used internally.
    * **Drag Image Creation:** The `DraggedNodeImageBuilder` makes assumptions about layout and painting to capture a visual representation of the dragged node.

6. **Consider Potential User and Programming Errors:**  Knowing the purpose of the file helps in identifying common mistakes:
    * **Incorrect `effectAllowed` values:** The code explicitly ignores invalid values, highlighting a potential user error in JavaScript.
    * **Accessing data without permission:** The `DataTransferAccessPolicy` suggests scenarios where reading or writing might be restricted.
    * **Misunderstanding `clearData()`:** The special case for file items in `clearData()` is a point of potential confusion.
    * **Incorrect Drag Image Usage:** Setting a drag image without ensuring the element is properly loaded or connected.

7. **Trace User Operations (Debugging Perspective):**  Thinking about how a user interacts with the browser to trigger this code is essential for debugging:
    * **Copy/Paste:** Selecting text or an image, using keyboard shortcuts (Ctrl+C/V or Cmd+C/V), or context menu options.
    * **Drag and Drop:** Starting a drag operation by clicking and holding on a draggable element (image, text, link), moving the mouse, and dropping onto a target. JavaScript event listeners (`dragstart`, `dragover`, `drop`) are key entry points.

8. **Structure the Output:**  Organize the findings into clear categories (Functionality, Relationship to Web Tech, Logic & Assumptions, Errors, User Operations). Use examples to illustrate the points. Provide hypothetical input/output for logical reasoning where applicable.

**(Self-Correction Example During the Process):**

Initially, I might have just listed the methods without fully understanding their implications. However, by looking at the method implementations and their interactions with other classes (like `DataObject` and the layout/painting components), I would realize the deeper purpose of each method. For instance, simply stating "sets the drag image" isn't as informative as explaining *how* it does this, including the use of `DraggedNodeImageBuilder` and the CSS pseudo-class. Similarly, understanding the type normalization logic requires looking at the `NormalizeType` function and realizing why it's necessary (handling browser inconsistencies).
好的，我们来分析一下 `blink/renderer/core/clipboard/data_transfer.cc` 这个文件。

**文件功能总览:**

`data_transfer.cc` 文件实现了 Blink 渲染引擎中 `DataTransfer` 接口的核心功能。`DataTransfer` 接口是 HTML5 拖放 (Drag and Drop) API 和剪贴板 API 的关键组成部分，它用于在这些操作过程中传递数据。

**具体功能分解:**

1. **数据存储和管理:**
   -  维护一个 `DataObject` 实例 (`data_object_`)，用于实际存储要传输的数据，可以是文本、URL、HTML 片段或文件。
   -  提供 `setData(type, data)` 方法来设置指定类型的数据。
   -  提供 `getData(type)` 方法来获取指定类型的数据。
   -  提供 `clearData(type)` 方法来清除指定类型的数据，或清除所有非文件数据。
   -  维护一个 `FileList` 实例 (`files_`)，用于存储拖放或复制的文件列表。

2. **拖放操作支持:**
   -  管理拖放操作的效果允许类型 (`effectAllowed_`)，例如 "copy", "move", "link" 等。
   -  管理拖放操作的目标放置效果 (`drop_effect_`)，这是在 `dragover` 或 `drop` 事件中设置的。
   -  提供 `setDragImage(element, x, y)` 方法来设置拖动时显示的自定义图像。
   -  提供 `ClearDragImage()` 方法来清除自定义的拖动图像。
   -  内部使用 `DraggedNodeImageBuilder` 类来创建基于 DOM 节点的拖动图像。

3. **剪贴板操作支持:**
   -  虽然主要关注拖放，但 `DataTransfer` 接口也被用于剪贴板操作（例如，通过 `document.execCommand('copy'/'cut')` 和 `navigator.clipboard.read/write`）。
   -  与 `DataObject` 协同工作，存储复制或剪切的数据。

4. **数据类型处理和转换:**
   -  实现 `NormalizeType(type)` 函数，用于规范化 MIME 类型字符串，例如将 `"text"` 或 `"text/plain"` 统一为 `"text/plain"`。
   -  处理 URL 类型的特殊情况，将其转换为 `text/uri-list`。

5. **访问控制:**
   -  使用 `DataTransferAccessPolicy` 枚举来控制对 `DataTransfer` 对象数据的访问级别（例如，只读、只写）。

6. **与底层平台的交互:**
   -  虽然代码本身不直接涉及平台调用，但 `DataTransfer` 对象在底层会与操作系统的剪贴板和拖放机制进行交互。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:** `DataTransfer` 对象是 JavaScript 拖放和剪贴板 API 的核心。
    * **拖放事件:** 在 `dragstart` 事件中，可以通过 `event.dataTransfer` 获取 `DataTransfer` 对象，并使用其方法来设置要拖动的数据 (`setData`) 和拖动图像 (`setDragImage`).
        ```javascript
        const element = document.getElementById('draggable');
        element.addEventListener('dragstart', (event) => {
          event.dataTransfer.setData('text/plain', 'This is some text');
          event.dataTransfer.setDragImage(element, 10, 10);
        });
        ```
    * **放置事件:** 在 `dragover` 和 `drop` 事件中，可以通过 `event.dataTransfer` 获取 `DataTransfer` 对象，读取拖动的数据 (`getData`) 和设置放置效果 (`dropEffect`).
        ```javascript
        const dropZone = document.getElementById('dropzone');
        dropZone.addEventListener('dragover', (event) => {
          event.preventDefault(); // 允许放置
          event.dataTransfer.dropEffect = 'copy';
        });
        dropZone.addEventListener('drop', (event) => {
          event.preventDefault();
          const data = event.dataTransfer.getData('text/plain');
          console.log('Dropped data:', data);
        });
        ```
    * **剪贴板 API:**  `navigator.clipboard.write()` 和 `navigator.clipboard.read()` 等方法在底层可能会使用类似的机制来传递数据。虽然 `data_transfer.cc` 主要处理拖放，但其数据管理部分与剪贴板也有关联。

* **HTML:** HTML 元素可以通过设置 `draggable="true"` 属性变为可拖动的。
    ```html
    <div id="draggable" draggable="true">Drag me!</div>
    <div id="dropzone">Drop here</div>
    ```

* **CSS:** CSS 可以影响拖动元素的样式和拖动反馈。
    * **`-webkit-user-drag` 属性:**  控制元素是否可以被拖动。
    * **`DraggedNodeImageBuilder` 类:**  在创建拖动图像时，会考虑元素的布局和样式。特别是，它会使用 `-webkit-drag` 伪类（虽然在提供的代码中没有直接看到 CSS 代码，但逻辑上是相关的），允许开发者为拖动状态的元素设置特殊样式。

**逻辑推理及假设输入与输出:**

**假设输入:** 用户在网页上拖动一个 `draggable` 的 `<div>` 元素。该 `<div>` 元素的 `dragstart` 事件处理程序设置了 `text/plain` 类型的数据为 "Hello Drag"。

**逻辑推理:**

1. 当 `dragstart` 事件触发时，JavaScript 代码调用 `event.dataTransfer.setData('text/plain', 'Hello Drag')`。
2. 这将调用 `DataTransfer::setData("text/plain", "Hello Drag")` 函数。
3. `NormalizeType("text/plain")` 返回 `"text/plain"`。
4. `data_object_->SetData("text/plain", "Hello Drag")` 被调用，将数据存储到 `DataObject` 对象中。

**输出:**  `DataObject` 对象内部会存储一个键值对，其中键为 `"text/plain"`，值为 `"Hello Drag"`。

**用户或编程常见的使用错误及举例说明:**

1. **在 `dragover` 事件中忘记调用 `event.preventDefault()`:** 这会导致浏览器默认行为（通常是拒绝放置），阻止 `drop` 事件的触发。
    ```javascript
    dropZone.addEventListener('dragover', (event) => {
      // 错误：忘记调用 preventDefault()
      event.dataTransfer.dropEffect = 'copy'; // 设置 dropEffect 但可能无效
    });
    ```

2. **尝试在非拖放事件中修改 `dropEffect` 或 `effectAllowed`:** 这些属性主要用于拖放操作。在其他事件中设置可能没有效果或导致意外行为。

3. **MIME 类型不匹配:** 在 `setData` 中设置的数据类型与在 `getData` 中尝试获取的数据类型不一致，会导致 `getData` 返回空字符串。
    ```javascript
    // 设置数据时使用 'text/html'
    event.dataTransfer.setData('text/html', '<p>Some HTML</p>');

    // 尝试获取数据时使用 'text/plain'
    const data = event.dataTransfer.getData('text/plain'); // data 将为空
    ```

4. **设置无效的 `effectAllowed` 值:**  `DataTransfer::setEffectAllowed` 方法会忽略无效的值。
    ```javascript
    event.dataTransfer.effectAllowed = 'invalid-effect'; // 将被忽略
    ```

**用户操作是如何一步步的到达这里，作为调试线索:**

假设开发者想要调试在拖放操作中，`setData` 函数是否正确存储了数据。

1. **用户操作:** 用户在浏览器中，点击并按住一个设置了 `draggable="true"` 的元素，然后开始拖动该元素。

2. **浏览器事件触发:** 拖动开始时，浏览器会触发 `dragstart` 事件。

3. **JavaScript 代码执行:**  开发者在 `dragstart` 事件监听器中，使用 JavaScript 代码调用 `event.dataTransfer.setData(type, data)`。

4. **Blink 引擎代码执行:**
   - 浏览器将事件传递给 Blink 引擎进行处理。
   - Blink 引擎的事件处理代码会找到对应的 `DataTransfer` 对象。
   - 调用 `DataTransfer::setData(type, data)` 方法，这是 `data_transfer.cc` 文件中的代码。

5. **调试线索:**
   - 可以在 `DataTransfer::setData` 方法中设置断点。
   - 检查传入的 `type` 和 `data` 参数是否与 JavaScript 代码中设置的一致。
   - 检查 `data_object_` 成员变量的状态，确认数据是否被正确存储。

**总结:**

`blink/renderer/core/clipboard/data_transfer.cc` 文件是 Blink 引擎中处理数据传输操作的核心组件，它实现了 `DataTransfer` 接口的各种功能，包括数据存储、拖放效果管理、数据类型处理等。理解这个文件的功能对于理解浏览器如何处理拖放和剪贴板操作至关重要，也有助于调试相关的 Web 开发问题。

Prompt: 
```
这是目录为blink/renderer/core/clipboard/data_transfer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2006, 2007, 2008 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/clipboard/data_transfer.h"

#include <memory>
#include <optional>

#include "build/build_config.h"
#include "third_party/blink/renderer/core/clipboard/clipboard_mime_types.h"
#include "third_party/blink/renderer/core/clipboard/clipboard_utilities.h"
#include "third_party/blink/renderer/core/clipboard/data_object.h"
#include "third_party/blink/renderer/core/clipboard/data_transfer_access_policy.h"
#include "third_party/blink/renderer/core/clipboard/data_transfer_item.h"
#include "third_party/blink/renderer/core/clipboard/data_transfer_item_list.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/fileapi/file_list.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/layout/layout_image.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"
#include "third_party/blink/renderer/core/page/drag_image.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/cull_rect_updater.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_painter.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_canvas.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_record_builder.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_registry.h"
#include "third_party/skia/include/core/SkSurface.h"
#include "ui/base/dragdrop/mojom/drag_drop_types.mojom-blink.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

namespace {

class DraggedNodeImageBuilder {
  STACK_ALLOCATED();

 public:
  DraggedNodeImageBuilder(LocalFrame& local_frame, Node& node)
      : local_frame_(&local_frame),
        node_(&node)
#if DCHECK_IS_ON()
        ,
        dom_tree_version_(node.GetDocument().DomTreeVersion())
#endif
  {
    for (Node& descendant : NodeTraversal::InclusiveDescendantsOf(*node_))
      descendant.SetDragged(true);
  }

  ~DraggedNodeImageBuilder() {
#if DCHECK_IS_ON()
    DCHECK_EQ(dom_tree_version_, node_->GetDocument().DomTreeVersion());
#endif
    for (Node& descendant : NodeTraversal::InclusiveDescendantsOf(*node_))
      descendant.SetDragged(false);
  }

  std::unique_ptr<DragImage> CreateImage() {
#if DCHECK_IS_ON()
    DCHECK_EQ(dom_tree_version_, node_->GetDocument().DomTreeVersion());
#endif
    // Construct layout object for |node_| with pseudo class "-webkit-drag"
    local_frame_->View()->UpdateAllLifecyclePhasesExceptPaint(
        DocumentUpdateReason::kDragImage);
    LayoutObject* const dragged_layout_object = node_->GetLayoutObject();
    if (!dragged_layout_object)
      return nullptr;
    // Paint starting at the nearest stacking context, clipped to the object
    // itself. This will also paint the contents behind the object if the
    // object contains transparency and there are other elements in the same
    // stacking context which stacked below.
    PaintLayer* layer = dragged_layout_object->EnclosingLayer();
    if (!layer->GetLayoutObject().IsStackingContext())
      layer = layer->AncestorStackingContext();

    gfx::Rect absolute_bounding_box =
        dragged_layout_object->AbsoluteBoundingBoxRectIncludingDescendants();

    gfx::RectF bounding_box =
        layer->GetLayoutObject()
            .AbsoluteToLocalQuad(gfx::QuadF(gfx::RectF(absolute_bounding_box)))
            .BoundingBox();
    gfx::RectF cull_rect = bounding_box;
    cull_rect.Offset(
        gfx::Vector2dF(layer->GetLayoutObject().FirstFragment().PaintOffset()));
    OverriddenCullRectScope cull_rect_scope(
        *layer, CullRect(gfx::ToEnclosingRect(cull_rect)),
        /*disable_expansion*/ true);
    PaintRecordBuilder builder;

    dragged_layout_object->GetDocument().Lifecycle().AdvanceTo(
        DocumentLifecycle::kInPaint);
    PaintLayerPainter(*layer).Paint(builder.Context(),
                                    PaintFlag::kOmitCompositingInfo);
    dragged_layout_object->GetDocument().Lifecycle().AdvanceTo(
        DocumentLifecycle::kPaintClean);

    gfx::Vector2dF paint_offset = bounding_box.OffsetFromOrigin();
    PropertyTreeState border_box_properties = layer->GetLayoutObject()
                                                  .FirstFragment()
                                                  .LocalBorderBoxProperties()
                                                  .Unalias();
    // We paint in the containing transform node's space. Add the offset from
    // the layer to this transform space.
    paint_offset +=
        gfx::Vector2dF(layer->GetLayoutObject().FirstFragment().PaintOffset());

    return DataTransfer::CreateDragImageForFrame(
        *local_frame_, 1.0f, bounding_box.size(), paint_offset, builder,
        border_box_properties);
  }

 private:
  LocalFrame* const local_frame_;
  Node* const node_;
#if DCHECK_IS_ON()
  const uint64_t dom_tree_version_;
#endif
};

std::optional<DragOperationsMask> ConvertEffectAllowedToDragOperationsMask(
    const AtomicString& op) {
  // Values specified in
  // https://html.spec.whatwg.org/multipage/dnd.html#dom-datatransfer-effectallowed
  if (op == "uninitialized")
    return kDragOperationEvery;
  if (op == "none")
    return kDragOperationNone;
  if (op == "copy")
    return kDragOperationCopy;
  if (op == "link")
    return kDragOperationLink;
  if (op == "move")
    return kDragOperationMove;
  if (op == "copyLink") {
    return static_cast<DragOperationsMask>(kDragOperationCopy |
                                           kDragOperationLink);
  }
  if (op == "copyMove") {
    return static_cast<DragOperationsMask>(kDragOperationCopy |
                                           kDragOperationMove);
  }
  if (op == "linkMove") {
    return static_cast<DragOperationsMask>(kDragOperationLink |
                                           kDragOperationMove);
  }
  if (op == "all")
    return kDragOperationEvery;
  return std::nullopt;
}

AtomicString ConvertDragOperationsMaskToEffectAllowed(DragOperationsMask op) {
  if (((op & kDragOperationMove) && (op & kDragOperationCopy) &&
       (op & kDragOperationLink)) ||
      (op == kDragOperationEvery))
    return AtomicString("all");
  if ((op & kDragOperationMove) && (op & kDragOperationCopy))
    return AtomicString("copyMove");
  if ((op & kDragOperationMove) && (op & kDragOperationLink))
    return AtomicString("linkMove");
  if ((op & kDragOperationCopy) && (op & kDragOperationLink))
    return AtomicString("copyLink");
  if (op & kDragOperationMove)
    return AtomicString("move");
  if (op & kDragOperationCopy)
    return AtomicString("copy");
  if (op & kDragOperationLink)
    return AtomicString("link");
  return keywords::kNone;
}

// We provide the IE clipboard types (URL and Text), and the clipboard types
// specified in the HTML spec. See
// https://html.spec.whatwg.org/multipage/dnd.html#the-datatransfer-interface
String NormalizeType(const String& type, bool* convert_to_url = nullptr) {
  String clean_type = type.StripWhiteSpace().LowerASCII();
  if (clean_type == kMimeTypeText ||
      clean_type.StartsWith(kMimeTypeTextPlainEtc))
    return kMimeTypeTextPlain;
  if (clean_type == kMimeTypeURL) {
    if (convert_to_url)
      *convert_to_url = true;
    return kMimeTypeTextURIList;
  }
  return clean_type;
}

}  // namespace

// static
DataTransfer* DataTransfer::Create() {
  DataTransfer* data = Create(
      kCopyAndPaste, DataTransferAccessPolicy::kWritable, DataObject::Create());
  data->drop_effect_ = keywords::kNone;
  data->effect_allowed_ = keywords::kNone;
  return data;
}

// static
DataTransfer* DataTransfer::Create(DataTransferType type,
                                   DataTransferAccessPolicy policy,
                                   DataObject* data_object) {
  return MakeGarbageCollected<DataTransfer>(type, policy, data_object);
}

DataTransfer::~DataTransfer() = default;

void DataTransfer::setDropEffect(const AtomicString& effect) {
  if (!IsForDragAndDrop())
    return;

  // The attribute must ignore any attempts to set it to a value other than
  // none, copy, link, and move.
  if (effect != "none" && effect != "copy" && effect != "link" &&
      effect != "move")
    return;

  // The specification states that dropEffect can be changed at all times, even
  // if the DataTransfer instance is protected or neutered.
  drop_effect_ = effect;
}

void DataTransfer::setEffectAllowed(const AtomicString& effect) {
  if (!IsForDragAndDrop())
    return;

  if (!ConvertEffectAllowedToDragOperationsMask(effect)) {
    // This means that there was no conversion, and the effectAllowed that
    // we are passed isn't a valid effectAllowed, so we should ignore it,
    // and not set |effect_allowed_|.

    // The attribute must ignore any attempts to set it to a value other than
    // none, copy, copyLink, copyMove, link, linkMove, move, all, and
    // uninitialized.
    return;
  }

  if (CanWriteData())
    effect_allowed_ = effect;
}

void DataTransfer::clearData(const String& type) {
  if (!CanWriteData()) {
    return;
  }
  if (type.IsNull()) {
    // As per spec
    // https://html.spec.whatwg.org/multipage/dnd.html#dom-datatransfer-cleardata,
    // `clearData()` doesn't remove `kFileKind` objects from `item_list_`.
    data_object_->ClearStringItems();
  } else {
    data_object_->ClearData(NormalizeType(type));
  }
}

String DataTransfer::getData(const String& type) const {
  if (!CanReadData())
    return String();

  bool convert_to_url = false;
  String data = data_object_->GetData(NormalizeType(type, &convert_to_url));
  if (!convert_to_url)
    return data;
  return ConvertURIListToURL(data);
}

void DataTransfer::setData(const String& type, const String& data) {
  if (!CanWriteData())
    return;

  data_object_->SetData(NormalizeType(type), data);
}

bool DataTransfer::hasDataStoreItemListChanged() const {
  return data_store_item_list_changed_ || !CanReadTypes();
}

void DataTransfer::OnItemListChanged() {
  data_store_item_list_changed_ = true;
  files_->clear();

  if (!CanReadData()) {
    return;
  }

  for (uint32_t i = 0; i < data_object_->length(); ++i) {
    if (data_object_->Item(i)->Kind() == DataObjectItem::kFileKind) {
      File* file = data_object_->Item(i)->GetAsFile();
      if (file) {
        files_->Append(file);
      }
    }
  }
}

Vector<String> DataTransfer::types() {
  if (!CanReadTypes())
    return Vector<String>();

  data_store_item_list_changed_ = false;
  return data_object_->Types();
}

FileList* DataTransfer::files() const {
  if (!CanReadData()) {
    files_->clear();
    return files_.Get();
  }
  return files_.Get();
}

void DataTransfer::setDragImage(Element* image, int x, int y) {
  DCHECK(image);

  if (!IsForDragAndDrop())
    return;

  // Convert `drag_loc_` from CSS px to physical pixels.
  // `LocalFrame::LayoutZoomFactor` converts from CSS px to physical px by
  // taking into account both device scale factor and page zoom.
  LocalFrame* frame = image->GetDocument().GetFrame();
  gfx::Point location =
      gfx::ScaleToRoundedPoint(gfx::Point(x, y), frame->LayoutZoomFactor());

  auto* html_image_element = DynamicTo<HTMLImageElement>(image);
  if (html_image_element && !image->isConnected())
    SetDragImageResource(html_image_element->CachedImage(), location);
  else
    SetDragImageElement(image, location);
}

void DataTransfer::ClearDragImage() {
  setDragImage(nullptr, nullptr, gfx::Point());
}

void DataTransfer::SetDragImageResource(ImageResourceContent* img,
                                        const gfx::Point& loc) {
  setDragImage(img, nullptr, loc);
}

void DataTransfer::SetDragImageElement(Node* node, const gfx::Point& loc) {
  setDragImage(nullptr, node, loc);
}

// static
gfx::RectF DataTransfer::ClipByVisualViewport(const gfx::RectF& absolute_rect,
                                              const LocalFrame& frame) {
  gfx::Rect viewport_in_root_frame =
      ToEnclosingRect(frame.GetPage()->GetVisualViewport().VisibleRect());
  gfx::RectF absolute_viewport(
      frame.View()->ConvertFromRootFrame(viewport_in_root_frame));
  return IntersectRects(absolute_viewport, absolute_rect);
}

// Returns a DragImage whose bitmap contains |contents|, positioned and scaled
// in device space.
//
// static
std::unique_ptr<DragImage> DataTransfer::CreateDragImageForFrame(
    LocalFrame& frame,
    float opacity,
    const gfx::SizeF& layout_size,
    const gfx::Vector2dF& paint_offset,
    PaintRecordBuilder& builder,
    const PropertyTreeState& property_tree_state) {
  float layout_to_device_scale = frame.GetPage()->GetVisualViewport().Scale();

  gfx::SizeF device_size = gfx::ScaleSize(layout_size, layout_to_device_scale);
  AffineTransform transform;
  gfx::Vector2dF device_paint_offset =
      gfx::ScaleVector2d(paint_offset, layout_to_device_scale);
  transform.Translate(-device_paint_offset.x(), -device_paint_offset.y());
  transform.Scale(layout_to_device_scale);

  // Rasterize upfront, since DragImage::create() is going to do it anyway
  // (SkImage::asLegacyBitmap).
  SkSurfaceProps surface_props;
  sk_sp<SkSurface> surface = SkSurfaces::Raster(
      SkImageInfo::MakeN32Premul(device_size.width(), device_size.height()),
      &surface_props);
  if (!surface)
    return nullptr;

  SkiaPaintCanvas skia_paint_canvas(surface->getCanvas());
  skia_paint_canvas.concat(AffineTransformToSkM44(transform));
  builder.EndRecording(skia_paint_canvas, property_tree_state);

  scoped_refptr<Image> image =
      UnacceleratedStaticBitmapImage::Create(surface->makeImageSnapshot());

  // There is no orientation information in the image, so pass
  // kDoNotRespectImageOrientation in order to avoid wasted work looking
  // at orientation.
  return DragImage::Create(image.get(), kDoNotRespectImageOrientation,
                           GetDefaultInterpolationQuality(), opacity);
}

// static
std::unique_ptr<DragImage> DataTransfer::NodeImage(LocalFrame& frame,
                                                   Node& node) {
  DraggedNodeImageBuilder image_node(frame, node);
  return image_node.CreateImage();
}

std::unique_ptr<DragImage> DataTransfer::CreateDragImage(
    gfx::Point& loc,
    float device_scale_factor,
    LocalFrame* frame) const {
  loc = drag_loc_;
  if (drag_image_element_) {
    return NodeImage(*frame, *drag_image_element_);
  }
  std::unique_ptr<DragImage> drag_image =
      drag_image_ ? DragImage::Create(drag_image_->GetImage()) : nullptr;
  if (drag_image) {
    drag_image->Scale(device_scale_factor, device_scale_factor);
    return drag_image;
  }
  return nullptr;
}

static ImageResourceContent* GetImageResourceContent(Element* element) {
  // Attempt to pull ImageResourceContent from element
  DCHECK(element);
  if (auto* image = DynamicTo<LayoutImage>(element->GetLayoutObject())) {
    if (image->CachedImage() && !image->CachedImage()->ErrorOccurred())
      return image->CachedImage();
  }
  return nullptr;
}

static void WriteImageToDataObject(DataObject* data_object,
                                   Element* element,
                                   const KURL& image_url) {
  // Shove image data into a DataObject for use as a file
  ImageResourceContent* cached_image = GetImageResourceContent(element);
  if (!cached_image || !cached_image->GetImage() || !cached_image->IsLoaded())
    return;

  Image* image = cached_image->GetImage();
  scoped_refptr<SharedBuffer> image_buffer = image->Data();
  if (!image_buffer || !image_buffer->size())
    return;

  data_object->AddFileSharedBuffer(
      image_buffer, cached_image->IsAccessAllowed(), image_url,
      image->FilenameExtension(),
      cached_image->GetResponse().HttpHeaderFields().Get(
          http_names::kContentDisposition));
}

void DataTransfer::DeclareAndWriteDragImage(Element* element,
                                            const KURL& link_url,
                                            const KURL& image_url,
                                            const String& title) {
  if (!data_object_)
    return;

  data_object_->SetURLAndTitle(link_url.IsValid() ? link_url : image_url,
                               title);

  // Write the bytes in the image to the file format.
  WriteImageToDataObject(data_object_.Get(), element, image_url);

  // Put img tag on the clipboard referencing the image
  data_object_->SetData(kMimeTypeTextHTML,
                        CreateMarkup(element, kIncludeNode, kResolveAllURLs));
}

void DataTransfer::WriteURL(Node* node, const KURL& url, const String& title) {
  if (!data_object_)
    return;
  DCHECK(!url.IsEmpty());

  data_object_->SetURLAndTitle(url, title);

  // The URL can also be used as plain text.
  data_object_->SetData(kMimeTypeTextPlain, url.GetString());

  // The URL can also be used as an HTML fragment.
  data_object_->SetHTMLAndBaseURL(
      CreateMarkup(node, kIncludeNode, kResolveAllURLs), url);
}

void DataTransfer::WriteSelection(const FrameSelection& selection) {
  if (!data_object_)
    return;

  if (!EnclosingTextControl(
          selection.ComputeVisibleSelectionInDOMTree().Start())) {
    data_object_->SetHTMLAndBaseURL(selection.SelectedHTMLForClipboard(),
                                    selection.GetFrame()->GetDocument()->Url());
  }

  String str = selection.SelectedTextForClipboard();
#if BUILDFLAG(IS_WIN)
  ReplaceNewlinesWithWindowsStyleNewlines(str);
#endif
  ReplaceNBSPWithSpace(str);
  data_object_->SetData(kMimeTypeTextPlain, str);
}

void DataTransfer::SetAccessPolicy(DataTransferAccessPolicy policy) {
  // once you go numb, can never go back
  DCHECK(policy_ != DataTransferAccessPolicy::kNumb ||
         policy == DataTransferAccessPolicy::kNumb);
  policy_ = policy;
}

bool DataTransfer::CanReadTypes() const {
  return policy_ == DataTransferAccessPolicy::kReadable ||
         policy_ == DataTransferAccessPolicy::kTypesReadable ||
         policy_ == DataTransferAccessPolicy::kWritable;
}

bool DataTransfer::CanReadData() const {
  return policy_ == DataTransferAccessPolicy::kReadable ||
         policy_ == DataTransferAccessPolicy::kWritable;
}

bool DataTransfer::CanWriteData() const {
  return policy_ == DataTransferAccessPolicy::kWritable;
}

bool DataTransfer::CanSetDragImage() const {
  return policy_ == DataTransferAccessPolicy::kWritable;
}

DragOperationsMask DataTransfer::SourceOperation() const {
  std::optional<DragOperationsMask> op =
      ConvertEffectAllowedToDragOperationsMask(effect_allowed_);
  DCHECK(op);
  return *op;
}

ui::mojom::blink::DragOperation DataTransfer::DestinationOperation() const {
  DCHECK(DropEffectIsInitialized());
  std::optional<DragOperationsMask> op =
      ConvertEffectAllowedToDragOperationsMask(drop_effect_);
  return static_cast<ui::mojom::blink::DragOperation>(*op);
}

void DataTransfer::SetSourceOperation(DragOperationsMask op) {
  effect_allowed_ = ConvertDragOperationsMaskToEffectAllowed(op);
}

void DataTransfer::SetDestinationOperation(ui::mojom::blink::DragOperation op) {
  drop_effect_ = ConvertDragOperationsMaskToEffectAllowed(
      static_cast<DragOperationsMask>(op));
}

DataTransferItemList* DataTransfer::items() {
  // TODO(crbug.com/331320416): According to the spec, we are supposed to
  // return the same collection of items each time. We now return a wrapper
  // that always wraps the *same* set of items, so JS shouldn't be able to
  // tell, but we probably still want to fix this.
  return MakeGarbageCollected<DataTransferItemList>(this, data_object_);
}

DataObject* DataTransfer::GetDataObject() const {
  return data_object_.Get();
}

DataTransfer::DataTransfer(DataTransferType type,
                           DataTransferAccessPolicy policy,
                           DataObject* data_object)
    : policy_(policy),
      effect_allowed_("uninitialized"),
      transfer_type_(type),
      data_object_(data_object),
      data_store_item_list_changed_(true),
      files_(MakeGarbageCollected<FileList>()) {
  data_object_->AddObserver(this);
  OnItemListChanged();
}

void DataTransfer::setDragImage(ImageResourceContent* image,
                                Node* node,
                                const gfx::Point& loc) {
  if (!CanSetDragImage())
    return;

  drag_image_ = image;
  drag_loc_ = loc;
  drag_image_element_ = node;
}

bool DataTransfer::HasFileOfType(const String& type) const {
  if (!CanReadTypes())
    return false;

  for (uint32_t i = 0; i < data_object_->length(); ++i) {
    if (data_object_->Item(i)->Kind() == DataObjectItem::kFileKind) {
      Blob* blob = data_object_->Item(i)->GetAsFile();
      if (blob && blob->IsFile() &&
          DeprecatedEqualIgnoringCase(blob->type(), type))
        return true;
    }
  }
  return false;
}

bool DataTransfer::HasStringOfType(const String& type) const {
  if (!CanReadTypes())
    return false;

  return data_object_->Types().Contains(type);
}

void DataTransfer::Trace(Visitor* visitor) const {
  visitor->Trace(data_object_);
  visitor->Trace(drag_image_);
  visitor->Trace(drag_image_element_);
  visitor->Trace(files_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink

"""

```