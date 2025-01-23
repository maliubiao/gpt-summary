Response:
Let's break down the thought process for analyzing the `image_document.cc` file.

1. **Understand the Goal:** The request is to understand the purpose and functionality of this specific Chromium Blink engine file. Key areas to address are its relation to web technologies (HTML, CSS, JavaScript), its internal logic, and potential user/developer errors.

2. **Initial Scan and Keyword Recognition:**  Quickly read through the code, looking for recognizable terms and structures. Immediately, these stand out:
    * `ImageDocument`: This is the central class, indicating the file deals with documents specifically for displaying images.
    * `#include`:  The included headers provide clues about dependencies and functionality. Notice includes for `HTMLImageElement`, `HTMLBodyElement`, `CSSPropertyID`, `MouseEvent`, `TouchEvent`, `DocumentLoader`, `ImageResource`, etc. These point to interactions with the DOM, styling, event handling, and image loading.
    * `CreateDocumentStructure`:  This suggests how the basic HTML structure of an image document is built.
    * `UpdateTitle`, `UpdateImageStyle`, `ResizeImageToFit`:  These indicate methods for manipulating the presentation of the image.
    * Event listeners (`kResize`, `kClick`, `kTouchend`, `kTouchcancel`):  This confirms event handling within the document.
    * `ShouldShrinkToFit`: This suggests a feature for adjusting the image size based on the viewport.

3. **Focus on the Core Class: `ImageDocument`:**  Since this is the main class, understanding its methods is crucial. Analyze each public method and some key private ones:
    * **Constructor:**  Initialization, setting compatibility mode.
    * **`CreateParser()`:**  Connects to the `ImageDocumentParser`, indicating how the image data is processed.
    * **`ImageSize()`:** Gets the intrinsic size of the image.
    * **`CreateDocumentStructure()`:**  Crucial for understanding how the HTML for an image document is generated. Note the creation of `<html>`, `<head>`, `<meta>`, `<body>`, `<div>` (potentially), and `<img>` elements. The `viewport` meta tag is significant.
    * **`UpdateTitle()`:**  How the document title is dynamically generated.
    * **`Scale()`, `ResizeImageToFit()`, `ImageClicked()`, `ImageLoaded()`, `ComputeMouseCursorMode()`, `UpdateImageStyle()`, `ImageUpdated()`, `RestoreImageSize()`, `ImageFitsInWindow()`, `CalculateDivWidth()`, `WindowSizeChanged()`:**  These methods handle the core logic of displaying, resizing, and interacting with the image. Pay attention to the different behavior based on `shrink_to_fit_mode_` (desktop vs. viewport).
    * **`CachedImage()`:**  Retrieves the loaded image resource.
    * **`ShouldShrinkToFit()`:** Determines if the image should be initially resized.

4. **Analyze Related Classes:**
    * **`ImageDocumentParser`:** This class handles the actual parsing of the image data. It interacts with `ImageResource` to decode the image. The `AppendBytes()` and `Finish()` methods are key to understanding the data processing pipeline.
    * **`ImageEventListener`:**  This class handles events within the `ImageDocument`. Note the different event types handled and their corresponding actions in the `ImageDocument`.

5. **Identify Relationships with Web Technologies:**
    * **HTML:**  The code directly manipulates HTML elements (`HTMLImageElement`, `HTMLBodyElement`, etc.) and their attributes. The `CreateDocumentStructure` method is the primary example.
    * **CSS:**  Inline styles are applied to elements to control their appearance (`display`, `margin`, `height`, `width`, `background-color`, `cursor`, etc.). This connects the C++ logic to the visual presentation.
    * **JavaScript:**  While this specific file doesn't *directly* execute JavaScript, it provides the underlying structure and rendering for image documents that JavaScript within those documents (if iframes were involved, though unlikely for a pure image document) could interact with. The event handling mechanism is a bridge to potential JavaScript interaction.

6. **Infer Logic and Scenarios:** Based on the code, reason about how it behaves in different situations:
    * **Loading an image:** The `ImageDocumentParser` receives the image data and feeds it to the `ImageResource`. Once loaded, the `ImageDocument` updates the title and styles.
    * **Resizing the window:**  The `WindowSizeChanged()` method adjusts the image size and positioning based on the `shrink_to_fit_mode_`.
    * **Clicking on the image (desktop mode):** The `ImageClicked()` method toggles between the "shrink to fit" view and the actual image size.
    * **Touch events (viewport mode):**  Touch events trigger style updates.

7. **Consider Potential Errors and Edge Cases:** Think about what could go wrong:
    * **Failed image loading:** The code checks the `ResourceStatus` and handles potential decode errors.
    * **Disabled images:** The code respects the frame's image loading settings.
    * **Large images:**  The `CalculateDivWidth()` method handles potentially very large images in viewport mode.
    * **Incorrect usage:** Developers might misunderstand how the `shrink_to_fit_mode_` affects behavior. Users might expect different zooming behavior.

8. **Structure the Answer:**  Organize the findings logically. Start with the main function, then detail the interactions with web technologies, provide concrete examples, illustrate logical flow with input/output scenarios, and finally, discuss potential errors. Use clear headings and bullet points for readability.

9. **Refine and Elaborate:**  Review the initial analysis and add more detail where necessary. For example, explicitly mention the purpose of the `<meta name="viewport">` tag. Expand on the implications of the different `shrink_to_fit_mode_` values.

By following this thought process, systematically analyzing the code, and connecting it to relevant web technologies and user scenarios, a comprehensive understanding of the `image_document.cc` file can be achieved.
这个文件 `blink/renderer/core/html/image_document.cc` 的主要功能是 **处理和渲染单独的图像文件**。当浏览器加载一个独立的图像资源（例如，直接访问一个 `.jpg` 或 `.png` 文件），Blink 引擎会创建一个 `ImageDocument` 对象来显示这个图像。

以下是其功能的详细说明，并根据要求进行了分类和举例：

**1. 创建和管理图像文档的结构:**

*   **功能:**  `ImageDocument` 类继承自 `HTMLDocument`，负责构建一个最基本的 HTML 页面结构来承载图像。这包括创建 `<html>`, `<head>`, `<meta>`, `<body>` 和 `<img>` 元素。
*   **HTML 关系:**  该文件直接操作 HTML 元素来构建文档结构。例如，`CreateDocumentStructure` 方法会创建 `HTMLHtmlElement`, `HTMLHeadElement`, `HTMLBodyElement`, 和 `HTMLImageElement` 的实例，并将它们添加到文档树中。
*   **假设输入与输出:**
    *   **假设输入:**  浏览器接收到一个类型为 `image/jpeg` 的响应，其 URL 为 `https://example.com/image.jpg`。
    *   **逻辑推理:**  `ImageDocument` 会被创建来处理这个响应。
    *   **输出:**  会生成一个基本的 HTML 文档，其中 `<body>` 元素会包含一个 `<img>` 元素，其 `src` 属性指向 `https://example.com/image.jpg`。  `<head>` 中可能包含一个 `viewport` 的 `<meta>` 标签，用于控制图像在不同设备上的显示。

**2. 加载和显示图像:**

*   **功能:**  `ImageDocument` 负责加载图像资源，并将其显示在页面上。它使用 `ImageResource` 来管理图像的加载和解码。
*   **HTML 关系:**  通过创建 `HTMLImageElement` 并设置其属性来显示图像。
*   **逻辑推理:**
    *   **假设输入:**  `ImageDocumentParser` 接收到图像
### 提示词
```
这是目录为blink/renderer/core/html/image_document.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2006, 2007, 2008, 2010 Apple Inc. All rights reserved.
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
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/html/image_document.h"

#include <limits>

#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "third_party/blink/public/platform/web_content_settings_client.h"
#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/dom/raw_data_document_parser.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/events/touch_event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_meta_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

class ImageEventListener : public NativeEventListener {
 public:
  ImageEventListener(ImageDocument* document) : doc_(document) {}

  bool Matches(const EventListener& other) const override;

  void Invoke(ExecutionContext*, Event*) override;

  void Trace(Visitor* visitor) const override {
    visitor->Trace(doc_);
    NativeEventListener::Trace(visitor);
  }

  bool IsImageEventListener() const override { return true; }

 private:
  Member<ImageDocument> doc_;
};

template <>
struct DowncastTraits<ImageEventListener> {
  static bool AllowFrom(const EventListener& event_listener) {
    const NativeEventListener* native_event_listener =
        DynamicTo<NativeEventListener>(event_listener);
    return native_event_listener &&
           native_event_listener->IsImageEventListener();
  }
};

class ImageDocumentParser : public RawDataDocumentParser {
 public:
  ImageDocumentParser(ImageDocument* document)
      : RawDataDocumentParser(document),
        world_(document->GetExecutionContext()->GetCurrentWorld()) {}

  ImageDocument* GetDocument() const {
    return To<ImageDocument>(RawDataDocumentParser::GetDocument());
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(image_resource_);
    visitor->Trace(world_);
    RawDataDocumentParser::Trace(visitor);
  }

 private:
  void AppendBytes(base::span<const uint8_t>) override;
  void Finish() override;

  Member<ImageResource> image_resource_;
  const Member<const DOMWrapperWorld> world_;
};

// --------

static String ImageTitle(const String& filename, const gfx::Size& size) {
  StringBuilder result;
  result.Append(filename);
  result.Append(" (");
  // FIXME: Localize numbers. Safari/OSX shows localized numbers with group
  // separaters. For example, "1,920x1,080".
  result.AppendNumber(size.width());
  result.Append(static_cast<UChar>(0xD7));  // U+00D7 (multiplication sign)
  result.AppendNumber(size.height());
  result.Append(')');
  return result.ToString();
}

void ImageDocumentParser::AppendBytes(base::span<const uint8_t> data) {
  if (data.empty()) {
    return;
  }

  if (IsDetached())
    return;

  LocalFrame* frame = GetDocument()->GetFrame();
  bool allow_image = frame->ImagesEnabled();
  if (!allow_image) {
    auto* client = frame->GetContentSettingsClient();
    if (client) {
      client->DidNotAllowImage();
    }
    return;
  }

  if (!image_resource_) {
    ResourceRequest request(GetDocument()->Url());
    request.SetCredentialsMode(network::mojom::CredentialsMode::kOmit);
    image_resource_ = ImageResource::Create(request, world_);
    image_resource_->NotifyStartLoad();

    GetDocument()->CreateDocumentStructure(image_resource_->GetContent());

    if (IsStopped())
      return;

    if (DocumentLoader* loader = GetDocument()->Loader())
      image_resource_->ResponseReceived(loader->GetResponse());
  }

  CHECK_LE(data.size(), std::numeric_limits<unsigned>::max());
  // If decoding has already failed, there's no point in sending additional
  // data to the ImageResource.
  if (image_resource_->GetStatus() != ResourceStatus::kDecodeError) {
    image_resource_->AppendData(base::as_chars(data));
  }

  if (!IsDetached())
    GetDocument()->ImageUpdated();
}

void ImageDocumentParser::Finish() {
  if (!IsStopped() && image_resource_) {
    // TODO(hiroshige): Use ImageResourceContent instead of ImageResource.
    DocumentLoader* loader = GetDocument()->Loader();
    image_resource_->SetResponse(loader->GetResponse());
    image_resource_->Finish(
        loader->GetTiming().ResponseEnd(),
        GetDocument()->GetTaskRunner(TaskType::kInternalLoading).get());

    if (GetDocument()->CachedImage()) {
      GetDocument()->UpdateTitle();

      if (IsDetached())
        return;

      GetDocument()->ImageUpdated();
      GetDocument()->ImageLoaded();
    }
  }

  if (!IsDetached()) {
    GetDocument()->SetReadyState(Document::kInteractive);
    GetDocument()->FinishedParsing();
  }
}

// --------

ImageDocument::ImageDocument(const DocumentInit& initializer)
    : HTMLDocument(initializer, {DocumentClass::kImage}),
      div_element_(nullptr),
      image_element_(nullptr),
      image_size_is_known_(false),
      did_shrink_image_(false),
      should_shrink_image_(ShouldShrinkToFit()),
      image_is_loaded_(false),
      shrink_to_fit_mode_(GetFrame()->GetSettings()->GetViewportEnabled()
                              ? kViewport
                              : kDesktop) {
  SetCompatibilityMode(kNoQuirksMode);
  LockCompatibilityMode();
}

DocumentParser* ImageDocument::CreateParser() {
  return MakeGarbageCollected<ImageDocumentParser>(this);
}

gfx::Size ImageDocument::ImageSize() const {
  DCHECK(image_element_);
  DCHECK(image_element_->CachedImage());
  return image_element_->CachedImage()->IntrinsicSize(
      LayoutObject::GetImageOrientation(image_element_->GetLayoutObject()));
}

void ImageDocument::CreateDocumentStructure(
    ImageResourceContent* image_content) {
  auto* root_element = MakeGarbageCollected<HTMLHtmlElement>(*this);
  root_element->SetInlineStyleProperty(
      CSSPropertyID::kHeight, 100, CSSPrimitiveValue::UnitType::kPercentage);
  AppendChild(root_element);
  root_element->InsertedByParser();

  if (IsStopped())
    return;  // runScriptsAtDocumentElementAvailable can detach the frame.

  auto* head = MakeGarbageCollected<HTMLHeadElement>(*this);
  auto* meta =
      MakeGarbageCollected<HTMLMetaElement>(*this, CreateElementFlags());
  meta->setAttribute(html_names::kNameAttr, AtomicString("viewport"));
  meta->setAttribute(html_names::kContentAttr,
                     AtomicString("width=device-width, minimum-scale=0.1"));
  head->AppendChild(meta);

  auto* body = MakeGarbageCollected<HTMLBodyElement>(*this);

  body->SetInlineStyleProperty(CSSPropertyID::kMargin, 0.0,
                               CSSPrimitiveValue::UnitType::kPixels);
  body->SetInlineStyleProperty(CSSPropertyID::kHeight, 100.0,
                               CSSPrimitiveValue::UnitType::kPercentage);
  if (ShouldShrinkToFit()) {
    // Display the image prominently centered in the frame.
    body->SetInlineStyleProperty(
        CSSPropertyID::kBackgroundColor,
        *cssvalue::CSSColor::Create(Color::FromRGB(14, 14, 14)));

    // See w3c example on how to center an element:
    // https://www.w3.org/Style/Examples/007/center.en.html
    div_element_ = MakeGarbageCollected<HTMLDivElement>(*this);
    div_element_->SetInlineStyleProperty(CSSPropertyID::kDisplay,
                                         CSSValueID::kFlex);
    div_element_->SetInlineStyleProperty(CSSPropertyID::kFlexDirection,
                                         CSSValueID::kColumn);
    div_element_->SetInlineStyleProperty(CSSPropertyID::kAlignItems,
                                         CSSValueID::kFlexStart);
    div_element_->SetInlineStyleProperty(CSSPropertyID::kMinWidth,
                                         CSSValueID::kMinContent);
    div_element_->SetInlineStyleProperty(
        CSSPropertyID::kHeight, 100.0,
        CSSPrimitiveValue::UnitType::kPercentage);
    div_element_->SetInlineStyleProperty(
        CSSPropertyID::kWidth, 100.0, CSSPrimitiveValue::UnitType::kPercentage);
    HTMLSlotElement* slot = MakeGarbageCollected<HTMLSlotElement>(*this);
    div_element_->AppendChild(slot);

    // Adding a UA shadow root here is because the container <div> should be
    // hidden so that only the <img> element should be visible in <body>,
    // according to the spec:
    // https://html.spec.whatwg.org/C/#read-media
    ShadowRoot& shadow_root = body->EnsureUserAgentShadowRoot();
    shadow_root.AppendChild(div_element_);
  }

  WillInsertBody();

  image_element_ = MakeGarbageCollected<HTMLImageElement>(*this);
  UpdateImageStyle();
  image_element_->StartLoadingImageDocument(image_content);
  body->AppendChild(image_element_.Get());

  if (ShouldShrinkToFit()) {
    // Add event listeners
    auto* listener = MakeGarbageCollected<ImageEventListener>(this);
    if (LocalDOMWindow* dom_window = domWindow())
      dom_window->addEventListener(event_type_names::kResize, listener, false);

    if (shrink_to_fit_mode_ == kDesktop) {
      image_element_->addEventListener(event_type_names::kClick, listener,
                                       false);
    } else if (shrink_to_fit_mode_ == kViewport) {
      image_element_->addEventListener(event_type_names::kTouchend, listener,
                                       false);
      image_element_->addEventListener(event_type_names::kTouchcancel, listener,
                                       false);
    }
  }

  root_element->AppendChild(head);
  root_element->AppendChild(body);

  if (IsStopped())
    image_element_ = nullptr;
}

void ImageDocument::UpdateTitle() {
  // Report the natural image size in the page title, regardless of zoom
  // level.  At a zoom level of 1 the image is guaranteed to have an integer
  // size.
  gfx::Size size = ImageSize();
  if (!size.width())
    return;
  // Compute the title, we use the decoded filename of the resource, falling
  // back on the (decoded) hostname if there is no path.
  String file_name = DecodeURLEscapeSequences(Url().LastPathComponent(),
                                              DecodeURLMode::kUTF8OrIsomorphic);
  if (file_name.empty()) {
    file_name = Url().Host().ToString();
  }
  setTitle(ImageTitle(file_name, size));
}

float ImageDocument::Scale() const {
  DCHECK_EQ(shrink_to_fit_mode_, kDesktop);
  if (!image_element_ || image_element_->GetDocument() != this)
    return 1.0f;

  LocalFrameView* view = GetFrame()->View();
  if (!view)
    return 1.0f;

  gfx::Size image_size = ImageSize();
  if (image_size.IsEmpty())
    return 1.0f;

  // We want to pretend the viewport is larger when the user has zoomed the
  // page in (but not when the zoom is coming from device scale).
  const float viewport_zoom =
      view->GetChromeClient()->WindowToViewportScalar(GetFrame(), 1.f);
  float width_scale = view->Width() / (viewport_zoom * image_size.width());
  float height_scale = view->Height() / (viewport_zoom * image_size.height());

  return std::min(width_scale, height_scale);
}

void ImageDocument::ResizeImageToFit() {
  DCHECK_EQ(shrink_to_fit_mode_, kDesktop);
  if (!image_element_ || image_element_->GetDocument() != this)
    return;

  gfx::Size image_size = gfx::ScaleToFlooredSize(ImageSize(), Scale());

  image_element_->setWidth(image_size.width());
  image_element_->setHeight(image_size.height());

  UpdateImageStyle();
}

void ImageDocument::ImageClicked(int x, int y) {
  DCHECK_EQ(shrink_to_fit_mode_, kDesktop);

  if (!image_size_is_known_ || ImageFitsInWindow())
    return;

  should_shrink_image_ = !should_shrink_image_;

  if (should_shrink_image_) {
    WindowSizeChanged();
  } else {
    // Adjust the coordinates to account for the fact that the image was
    // centered on the screen.
    float image_x = x - image_element_->OffsetLeft();
    float image_y = y - image_element_->OffsetTop();

    RestoreImageSize();

    UpdateStyleAndLayout(DocumentUpdateReason::kInput);

    double scale = Scale();
    double device_scale_factor =
        GetFrame()->View()->GetChromeClient()->WindowToViewportScalar(
            GetFrame(), 1.f);

    float scroll_x = (image_x * device_scale_factor) / scale -
                     static_cast<float>(GetFrame()->View()->Width()) / 2;
    float scroll_y = (image_y * device_scale_factor) / scale -
                     static_cast<float>(GetFrame()->View()->Height()) / 2;

    GetFrame()->View()->LayoutViewport()->SetScrollOffset(
        ScrollOffset(scroll_x, scroll_y),
        mojom::blink::ScrollType::kProgrammatic);
  }
}

void ImageDocument::ImageLoaded() {
  image_is_loaded_ = true;
  UpdateImageStyle();
}

ImageDocument::MouseCursorMode ImageDocument::ComputeMouseCursorMode() const {
  if (!image_is_loaded_)
    return kDefault;
  if (shrink_to_fit_mode_ != kDesktop || !ShouldShrinkToFit())
    return kDefault;
  if (ImageFitsInWindow())
    return kDefault;
  return should_shrink_image_ ? kZoomIn : kZoomOut;
}

void ImageDocument::UpdateImageStyle() {
  StringBuilder image_style;
  image_style.Append("display: block;");
  image_style.Append("-webkit-user-select: none;");

  if (ShouldShrinkToFit()) {
    if (shrink_to_fit_mode_ == kViewport)
      image_style.Append("max-width: 100%;");
    image_style.Append("margin: auto;");
  }

  MouseCursorMode cursor_mode = ComputeMouseCursorMode();
  if (cursor_mode == kZoomIn)
    image_style.Append("cursor: zoom-in;");
  else if (cursor_mode == kZoomOut)
    image_style.Append("cursor: zoom-out;");

  if (GetFrame()->IsOutermostMainFrame()) {
    if (image_is_loaded_) {
      image_style.Append("background-color: hsl(0, 0%, 90%);");
      DCHECK(image_element_);
      DCHECK(image_element_->CachedImage());
      if (!image_element_->CachedImage()->IsAnimatedImage()) {
        image_style.Append("transition: background-color 300ms;");
      }
    } else if (image_size_is_known_) {
      image_style.Append("background-color: hsl(0, 0%, 25%);");
    }
  }

  image_element_->setAttribute(html_names::kStyleAttr,
                               image_style.ToAtomicString());
}

void ImageDocument::ImageUpdated() {
  DCHECK(image_element_);

  if (image_size_is_known_)
    return;

  UpdateStyleAndLayoutTree();
  if (!image_element_->CachedImage() || ImageSize().IsEmpty())
    return;

  image_size_is_known_ = true;
  UpdateImageStyle();

  if (ShouldShrinkToFit()) {
    // Force resizing of the image
    WindowSizeChanged();
  }
}

void ImageDocument::RestoreImageSize() {
  DCHECK_EQ(shrink_to_fit_mode_, kDesktop);

  if (!image_element_ || !image_size_is_known_ ||
      image_element_->GetDocument() != this)
    return;

  gfx::Size image_size = ImageSize();
  image_element_->setWidth(image_size.width());
  image_element_->setHeight(image_size.height());
  UpdateImageStyle();

  did_shrink_image_ = false;
}

bool ImageDocument::ImageFitsInWindow() const {
  DCHECK_EQ(shrink_to_fit_mode_, kDesktop);
  return Scale() >= 1;
}

int ImageDocument::CalculateDivWidth() {
  // Zooming in and out of an image being displayed within a viewport is done
  // by changing the page scale factor of the page instead of changing the
  // size of the image.  The size of the image is set so that:
  // * Images wider than the viewport take the full width of the screen.
  // * Images taller than the viewport are initially aligned with the top of
  //   of the frame.
  // * Images smaller in either dimension are centered along that axis.
  int viewport_width =
      GetFrame()->GetPage()->GetVisualViewport().Size().width() /
      GetFrame()->LayoutZoomFactor();

  // For huge images, minimum-scale=0.1 is still too big on small screens.
  // Set the <div> width so that the image will shrink to fit the width of the
  // screen when the scale is minimum.
  int max_width = std::min(ImageSize().width(), viewport_width * 10);
  return std::max(viewport_width, max_width);
}

void ImageDocument::WindowSizeChanged() {
  if (!image_element_ || !image_size_is_known_ ||
      image_element_->GetDocument() != this)
    return;

  if (shrink_to_fit_mode_ == kViewport) {
    int div_width = CalculateDivWidth();
    div_element_->SetInlineStyleProperty(CSSPropertyID::kWidth, div_width,
                                         CSSPrimitiveValue::UnitType::kPixels);

    // Explicitly set the height of the <div> containing the <img> so that it
    // can display the full image without shrinking it, allowing a full-width
    // reading mode for normal-width-huge-height images. Use the LayoutSize
    // for height rather than viewport since that doesn't change based on the
    // URL bar coming in and out - thus preventing the image from jumping
    // around. i.e. The div should fill the viewport when minimally zoomed and
    // the URL bar is showing, but won't fill the new space when the URL bar
    // hides.
    gfx::Size layout_size = View()->GetLayoutSize();
    float aspect_ratio =
        static_cast<float>(layout_size.width()) / layout_size.height();
    int div_height = std::max(ImageSize().height(),
                              static_cast<int>(div_width / aspect_ratio));
    div_element_->SetInlineStyleProperty(CSSPropertyID::kHeight, div_height,
                                         CSSPrimitiveValue::UnitType::kPixels);
    return;
  }

  bool fits_in_window = ImageFitsInWindow();

  // If the image has been explicitly zoomed in, restore the cursor if the image
  // fits and set it to a zoom out cursor if the image doesn't fit
  if (!should_shrink_image_) {
    UpdateImageStyle();
    return;
  }

  if (did_shrink_image_) {
    // If the window has been resized so that the image fits, restore the image
    // size otherwise update the restored image size.
    if (fits_in_window)
      RestoreImageSize();
    else
      ResizeImageToFit();
  } else {
    // If the image isn't resized but needs to be, then resize it.
    if (!fits_in_window) {
      ResizeImageToFit();
      did_shrink_image_ = true;
    }
  }
}

ImageResourceContent* ImageDocument::CachedImage() {
  if (!image_element_)
    return nullptr;
  return image_element_->CachedImage();
}

bool ImageDocument::ShouldShrinkToFit() const {
  // WebView automatically resizes to match the contents, causing an infinite
  // loop as the contents then resize to match the window. To prevent this,
  // disallow images from shrinking to fit for WebViews.
  bool is_wrap_content_web_view =
      GetPage() ? GetPage()->GetSettings().GetForceZeroLayoutHeight() : false;
  return GetFrame()->IsOutermostMainFrame() && !is_wrap_content_web_view;
}

void ImageDocument::Trace(Visitor* visitor) const {
  visitor->Trace(div_element_);
  visitor->Trace(image_element_);
  HTMLDocument::Trace(visitor);
}

// --------

void ImageEventListener::Invoke(ExecutionContext*, Event* event) {
  auto* mouse_event = DynamicTo<MouseEvent>(event);
  if (event->type() == event_type_names::kResize) {
    doc_->WindowSizeChanged();
  } else if (event->type() == event_type_names::kClick && mouse_event) {
    doc_->ImageClicked(mouse_event->x(), mouse_event->y());
  } else if ((event->type() == event_type_names::kTouchend ||
              event->type() == event_type_names::kTouchcancel) &&
             IsA<TouchEvent>(event)) {
    doc_->UpdateImageStyle();
  }
}

bool ImageEventListener::Matches(const EventListener& listener) const {
  if (const ImageEventListener* image_event_listener =
          DynamicTo<ImageEventListener>(listener)) {
    return doc_ == image_event_listener->doc_;
  }
  return false;
}

}  // namespace blink
```