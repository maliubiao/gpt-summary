Response:
Let's break down the thought process for analyzing this `FontFaceSet.cc` file.

**1. Initial Reading and High-Level Understanding:**

* **Keywords:** The file name itself, `FontFaceSet`, immediately suggests it's about managing a collection of font faces. The `.cc` extension indicates it's C++ code, part of the Chromium/Blink rendering engine.
* **Copyright Notice:**  Confirms it's Chromium code.
* **Includes:**  The included headers provide vital clues. `third_party/blink/renderer/bindings/core/v8/...` points to JavaScript integration. `.../core/css/...` confirms its role in CSS handling. Headers like `.../platform/fonts/...` and `.../platform/heap/...` suggest low-level font management and memory management aspects.
* **Namespace:** `namespace blink` confirms the context.

**2. Identifying Key Functionalities (Core Responsibilities):**

* **Adding Font Faces:** The `addForBinding` method is a clear indicator of how font faces are added to the set. The binding aspect suggests a JavaScript interface.
* **Removing Font Faces:** `clearForBinding` and `deleteForBinding` handle removal.
* **Checking for Font Faces:** `hasForBinding` is the counterpart to adding.
* **Loading and Status:** The `status()` method and mentions of `is_loading_`, `loading_fonts_`, `loaded_fonts_`, and `failed_fonts_` strongly point towards managing the loading state of fonts.
* **Promises and Events:** The `ready_` member, `HandlePendingEventsAndPromises`, `FireLoadingEvent`, `FireDoneEvent`, and the `load()` method returning a `ScriptPromise` clearly show asynchronous operations and event handling related to font loading.
* **Matching and Checking:** The `load()` and `check()` methods, along with mentions of `FontFaceCache`, suggest the ability to find and verify the availability of specific font faces based on CSS properties and text content.
* **Iteration:**  `CreateIterationSource` hints at allowing iteration over the font faces in the set, likely for JavaScript access.

**3. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **JavaScript:** The `*ForBinding` methods, `ScriptState*`, and `ScriptPromise` are direct links to JavaScript interaction. The `load()` and `check()` methods are also exposed to JavaScript. The iteration capability is also crucial for JavaScript.
* **CSS:** The file resides within the `css` directory. The usage of `FontSelector`, `FontFaceCache`, `CSSSegmentedFontFace`, and the handling of font strings directly relate to CSS font declarations.
* **HTML:**  While not directly manipulated, the loading of fonts is triggered by the browser parsing HTML and encountering `<link>` elements for CSS files or inline `<style>` tags that define `@font-face` rules. The results affect the rendering of HTML text.

**4. Detailed Examination of Specific Code Blocks:**

* **`addForBinding`:**  The logic of checking for existing faces and adding to the `non_css_connected_faces_` set is important. The call to `font_selector->GetFontFaceCache()->AddFontFace()` and handling the loading state are key steps.
* **`load`:**  This method is complex. Recognizing the parsing of the `font_string`, the interaction with `FontFaceCache`, and the creation of the `LoadFontPromiseResolver` is crucial.
* **`check`:**  This method iterates through the text, checks character by character, and uses the `FontFaceCache` to verify font availability.
* **Event Handling (`FireLoadingEvent`, `FireDoneEvent`):**  Understanding how these events are dispatched is essential for understanding the asynchronous nature of font loading.

**5. Logical Reasoning and Examples:**

* **Input/Output for `load`:**  Consider the input parameters and what the method aims to achieve (a promise resolving with font faces). Thinking about different font strings and text samples helps illustrate the functionality.
* **Input/Output for `check`:** Similar to `load`, focus on the inputs (font string, text) and the boolean output indicating whether the text can be rendered with the specified font.

**6. Identifying Potential User/Programming Errors:**

* **Invalid Font Strings:** The `load` and `check` methods explicitly handle syntax errors in the font string.
* **Adding the Same Font Face Multiple Times:** The code prevents redundant additions.
* **Incorrect Usage of the API:**  Calling methods in the wrong order or with incorrect parameters can lead to unexpected behavior.

**7. Tracing User Actions to Code Execution:**

* **Initial Font Request:**  The browser encounters a CSS rule or HTML attribute requiring a specific font.
* **Font Loading Process:** The browser attempts to locate and download the font file if it's not already available.
* **`FontFaceSet` Involvement:**  The `FontFaceSet` is involved in managing these font faces, tracking their loading status, and making them available for rendering.

**Self-Correction/Refinement during the Analysis:**

* **Initial Focus on Public API:** Start with the methods that seem to be exposed for external use (e.g., the `*ForBinding` methods).
* **Understanding Asynchronous Operations:** Recognize the significance of promises and events for managing font loading.
* **Connecting Internal Components:**  See how `FontFaceSet` interacts with other classes like `FontSelector` and `FontFaceCache`.
* **Iterative Reading:**  Go back and re-read sections of the code to clarify any ambiguities. Pay attention to comments and variable names.

By following these steps, we can systematically analyze the `FontFaceSet.cc` file and understand its role in the Blink rendering engine. The emphasis is on understanding the core functionalities, their connection to web technologies, and how they contribute to the overall font rendering process.
这个文件 `blink/renderer/core/css/font_face_set.cc` 定义了 `FontFaceSet` 类，它是 Chromium Blink 引擎中用于管理和跟踪字体加载的对象。 可以将其理解为一个**字体集合管理器**。

以下是它的主要功能，并结合 JavaScript, HTML, CSS 的关系进行说明：

**核心功能:**

1. **管理字体集合:** `FontFaceSet` 维护一个由 `FontFace` 对象组成的集合。这些 `FontFace` 对象代表了通过 CSS `@font-face` 规则或者 JavaScript 创建的字体。

2. **跟踪字体加载状态:**  它负责跟踪集合中各个字体的加载状态（例如：加载中、已加载、加载失败）。

3. **触发加载事件:** 当集合中的字体开始加载或加载完成（成功或失败）时，它会触发相应的事件 (`loading`, `loadingdone`, `loadingerror`)。这些事件可以通过 JavaScript 监听。

4. **提供加载 Promise:**  它提供 `ready` 属性，返回一个 Promise，该 Promise 在 `FontFaceSet` 中的所有字体都加载完成后 resolve。

5. **按需加载字体:**  通过 `load()` 方法，可以根据 CSS 字体描述符和可选的文本内容，来触发特定字体的加载。

6. **检查字体可用性:**  `check()` 方法允许检查给定的字体描述符和文本是否可以使用当前已加载的字体进行渲染。

7. **与 JavaScript 绑定:**  提供了与 JavaScript `FontFaceSet` API 对应的功能，允许 JavaScript 代码添加、删除、检查和管理字体。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS (@font-face):**
    * **关系:** 当浏览器解析包含 `@font-face` 规则的 CSS 时，Blink 引擎会创建相应的 `FontFace` 对象，并将它们添加到文档的 `FontFaceSet` 中。
    * **举例:**
      ```css
      /* style.css */
      @font-face {
        font-family: 'MyCustomFont';
        src: url('my-custom-font.woff2') format('woff2');
      }
      ```
      当浏览器加载 `style.css` 时，`FontFaceSet` 会添加一个代表 'MyCustomFont' 的 `FontFace` 对象，并开始加载 `my-custom-font.woff2`。

* **JavaScript (FontFaceSet API):**
    * **关系:** JavaScript 提供了 `document.fonts` 属性，返回一个 `FontFaceSet` 对象，允许开发者通过 JavaScript 直接操作字体。
    * **举例:**
      ```javascript
      // HTML 中可能没有定义 'MyOtherCustomFont'
      const newFontFace = new FontFace('MyOtherCustomFont', 'url(my-other-custom-font.woff2)');
      document.fonts.add(newFontFace); // 将字体添加到 FontFaceSet 并触发加载

      document.fonts.ready.then(function() {
        console.log('所有字体都加载完成！');
      });

      document.fonts.load("italic bold 16px MyCustomFont").then(function(fontFaces) {
        console.log("加载了匹配的字体：", fontFaces);
      });

      if (document.fonts.check("12px Arial", "Hello")) {
        console.log("Arial 字体可以用于显示 'Hello'");
      }
      ```
      这段 JavaScript 代码展示了如何使用 `FontFaceSet` API 添加新的字体，监听加载完成事件，按需加载特定字体，以及检查字体的可用性。

* **HTML (文本渲染):**
    * **关系:** `FontFaceSet` 管理的字体最终用于渲染 HTML 元素中的文本。当浏览器需要渲染使用特定字体的文本时，它会查找 `FontFaceSet` 中是否有可用的匹配字体。
    * **举例:**
      ```html
      <!DOCTYPE html>
      <html>
      <head>
        <link rel="stylesheet" href="style.css">
        <style>
          body {
            font-family: 'MyCustomFont', sans-serif;
          }
        </style>
      </head>
      <body>
        <p>This text uses MyCustomFont.</p>
      </body>
      </html>
      ```
      当浏览器渲染 `<p>` 元素时，会查找 `FontFaceSet` 中名为 'MyCustomFont' 的字体。如果该字体已加载，则使用该字体渲染文本；否则，可能使用回退字体（如 `sans-serif`）。

**逻辑推理 (假设输入与输出):**

假设 JavaScript 代码执行以下操作：

* **假设输入:**
  ```javascript
  const myFont = new FontFace('MyNewFont', 'url(my-new-font.woff2)');
  document.fonts.add(myFont);
  document.fonts.load("20px MyNewFont", "Test").then(function(loadedFonts) {
    console.log("Loaded fonts:", loadedFonts);
  });
  ```

* **逻辑推理:**
    1. `new FontFace(...)` 创建一个新的 `FontFace` 对象，但此时字体可能并未开始加载。
    2. `document.fonts.add(myFont)` 将 `myFont` 添加到 `FontFaceSet`，触发 Blink 引擎开始加载 `my-new-font.woff2`。`FontFaceSet` 的内部状态会更新，`is_loading_` 可能变为 true。
    3. `document.fonts.load("20px MyNewFont", "Test")` 请求加载能够渲染 "Test" 文本且符合 "20px MyNewFont" 描述符的字体。`FontFaceSet` 会检查是否有匹配的已加载字体，如果没有，则会等待 `myFont` 加载完成。
    4. 当 `my-new-font.woff2` 加载完成后 (假设加载成功)，`FontFaceSet` 会触发 `loadingdone` 事件，并 resolve `document.fonts.ready` 的 Promise。
    5. `document.fonts.load(...)` 的 Promise 也会 resolve，`loadedFonts` 数组中会包含 `myFont` 对象。

* **假设输出:**
  ```
  Loaded fonts: [FontFace]
  ```
  控制台会输出包含 `FontFace` 对象的数组。

**用户或编程常见的使用错误:**

1. **错误的字体文件路径:** 如果 `@font-face` 规则或 `FontFace` 构造函数中指定的字体文件路径不正确，字体将无法加载，`FontFaceSet` 会将该字体标记为加载失败，并可能触发 `loadingerror` 事件。
   * **举例:**
     ```css
     /* 错误的文件路径 */
     @font-face {
       font-family: 'BrokenFont';
       src: url('wrong-path/broken-font.woff2') format('woff2');
     }
     ```
     或者
     ```javascript
     const badFont = new FontFace('BadFont', 'url(typo-in-path.woff2)');
     document.fonts.add(badFont);
     ```

2. **不支持的字体格式:** 如果浏览器不支持 `@font-face` 规则中指定的字体格式，字体也无法加载。
   * **举例:**
     ```css
     @font-face {
       font-family: 'UnsupportedFont';
       src: url('unsupported.eot'); /* 现代浏览器可能不支持 .eot */
     }
     ```

3. **跨域问题 (CORS):** 如果字体文件托管在不同的域上，并且没有设置正确的 CORS 头信息，浏览器会阻止字体加载。
   * **举例:** 字体文件在 `otherdomain.com/fonts/myfont.woff2`，而网页在 `yourdomain.com`，`otherdomain.com` 需要设置 `Access-Control-Allow-Origin` 头。

4. **忘记等待字体加载完成:** 在字体加载完成之前就尝试使用该字体进行渲染，可能会导致文本显示不正确或使用回退字体。应该使用 `document.fonts.ready` Promise 或监听加载事件。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中打开一个网页。**
2. **浏览器解析 HTML 文档。**
3. **浏览器解析 HTML 中引用的 CSS 文件或 `<style>` 标签中的样式。**
4. **如果 CSS 中包含 `@font-face` 规则，Blink 引擎的 CSS 解析器会创建 `FontFace` 对象。**
5. **这些 `FontFace` 对象会被添加到当前文档的 `FontFaceSet` 中。**  `FontFaceSet::addForBinding` 方法会被调用，将新创建的 `FontFace` 对象添加到内部的集合中。
6. **Blink 引擎开始尝试加载 `@font-face` 规则中指定的字体文件。**  这可能涉及到网络请求。
7. **如果 JavaScript 代码使用了 `document.fonts.add()` 方法添加了新的 `FontFace` 对象，也会到达 `FontFaceSet::addForBinding`。**
8. **当字体加载状态发生变化（开始加载、加载成功、加载失败），`FontFace` 对象会通知 `FontFaceSet`。**
9. **`FontFaceSet` 会根据字体加载状态更新其内部状态 (`is_loading_`, `loading_fonts_`, `loaded_fonts_`, `failed_fonts_`)，并可能触发事件。** `FontFaceSet::HandlePendingEventsAndPromisesSoon` 和 `FontFaceSet::HandlePendingEventsAndPromises` 方法负责管理和触发这些事件。
10. **如果 JavaScript 代码调用了 `document.fonts.load()` 或 `document.fonts.check()`，会调用 `FontFaceSet` 对应的 `load()` 或 `check()` 方法。** 这些方法会与 `FontFaceCache` 交互，检查或触发字体加载。

**调试线索:**

* **查看 "Network" 面板:**  检查字体文件是否成功下载，以及是否有 CORS 错误。
* **使用 "Application" 或 "Sources" 面板 (浏览器的开发者工具):** 可以查看 `document.fonts` 对象的状态，包括已添加的字体及其加载状态。
* **在 JavaScript 代码中添加断点:**  在 `document.fonts.add()`, `document.fonts.load()`, 以及监听加载事件的代码处设置断点，查看 `FontFaceSet` 的状态变化。
* **在 Blink 渲染引擎源代码中设置断点 (如果可以):**  例如在 `FontFaceSet::addForBinding`, `FontFaceSet::HandlePendingEventsAndPromises`, `FontFaceSet::LoadFontPromiseResolver::NotifyLoaded` 等关键方法中设置断点，深入了解字体加载流程。

总而言之，`blink/renderer/core/css/font_face_set.cc` 文件实现了 `FontFaceSet` 类的核心逻辑，负责管理字体集合、跟踪加载状态、触发事件，并与 JavaScript 的 `FontFaceSet` API 紧密结合，最终影响着网页文本的渲染。 理解这个文件有助于深入理解浏览器如何处理字体加载以及如何通过 JavaScript 进行字体管理。

Prompt: 
```
这是目录为blink/renderer/core/css/font_face_set.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/font_face_set.h"

#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_font_face_set_load_status.h"
#include "third_party/blink/renderer/core/css/font_face_cache.h"
#include "third_party/blink/renderer/core/css/font_face_set_load_event.h"
#include "third_party/blink/renderer/platform/font_family_names.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

const int FontFaceSet::kDefaultFontSize = 10;

// static
const AtomicString& FontFaceSet::DefaultFontFamily() {
  return font_family_names::kSansSerif;
}

void FontFaceSet::HandlePendingEventsAndPromisesSoon() {
  if (!pending_task_queued_) {
    if (auto* context = GetExecutionContext()) {
      pending_task_queued_ = true;
      context->GetTaskRunner(TaskType::kFontLoading)
          ->PostTask(FROM_HERE,
                     WTF::BindOnce(&FontFaceSet::HandlePendingEventsAndPromises,
                                   WrapPersistent(this)));
    }
  }
}

void FontFaceSet::HandlePendingEventsAndPromises() {
  pending_task_queued_ = false;
  if (!GetExecutionContext()) {
    return;
  }
  FireLoadingEvent();
  FireDoneEventIfPossible();
}

void FontFaceSet::FireLoadingEvent() {
  if (should_fire_loading_event_) {
    should_fire_loading_event_ = false;
    DispatchEvent(
        *FontFaceSetLoadEvent::CreateForFontFaces(event_type_names::kLoading));
  }
}

V8FontFaceSetLoadStatus FontFaceSet::status() const {
  return V8FontFaceSetLoadStatus(is_loading_
                                     ? V8FontFaceSetLoadStatus::Enum::kLoading
                                     : V8FontFaceSetLoadStatus::Enum::kLoaded);
}

FontFaceSet* FontFaceSet::addForBinding(ScriptState*,
                                        FontFace* font_face,
                                        ExceptionState&) {
  DCHECK(font_face);
  if (!InActiveContext()) {
    return this;
  }
  if (non_css_connected_faces_.Contains(font_face)) {
    return this;
  }
  if (IsCSSConnectedFontFace(font_face)) {
    return this;
  }
  FontSelector* font_selector = GetFontSelector();
  non_css_connected_faces_.insert(font_face);
  font_selector->GetFontFaceCache()->AddFontFace(font_face, false);
  if (font_face->LoadStatus() == FontFace::kLoading) {
    AddToLoadingFonts(font_face);
  }
  font_selector->FontFaceInvalidated(
      FontInvalidationReason::kGeneralInvalidation);
  return this;
}

void FontFaceSet::clearForBinding(ScriptState*, ExceptionState&) {
  if (!InActiveContext() || non_css_connected_faces_.empty()) {
    return;
  }
  FontSelector* font_selector = GetFontSelector();
  FontFaceCache* font_face_cache = font_selector->GetFontFaceCache();
  for (const auto& font_face : non_css_connected_faces_) {
    font_face_cache->RemoveFontFace(font_face.Get(), false);
    if (font_face->LoadStatus() == FontFace::kLoading) {
      RemoveFromLoadingFonts(font_face);
    }
  }
  non_css_connected_faces_.clear();
  font_selector->FontFaceInvalidated(
      FontInvalidationReason::kGeneralInvalidation);
}

bool FontFaceSet::deleteForBinding(ScriptState*,
                                   FontFace* font_face,
                                   ExceptionState&) {
  DCHECK(font_face);
  if (!InActiveContext()) {
    return false;
  }
  HeapLinkedHashSet<Member<FontFace>>::iterator it =
      non_css_connected_faces_.find(font_face);
  if (it != non_css_connected_faces_.end()) {
    non_css_connected_faces_.erase(it);
    FontSelector* font_selector = GetFontSelector();
    font_selector->GetFontFaceCache()->RemoveFontFace(font_face, false);
    if (font_face->LoadStatus() == FontFace::kLoading) {
      RemoveFromLoadingFonts(font_face);
    }
    font_selector->FontFaceInvalidated(
        FontInvalidationReason::kFontFaceDeleted);
    return true;
  }
  return false;
}

bool FontFaceSet::hasForBinding(ScriptState*,
                                FontFace* font_face,
                                ExceptionState&) const {
  DCHECK(font_face);
  if (!InActiveContext()) {
    return false;
  }
  return non_css_connected_faces_.Contains(font_face) ||
         IsCSSConnectedFontFace(font_face);
}

void FontFaceSet::Trace(Visitor* visitor) const {
  visitor->Trace(non_css_connected_faces_);
  visitor->Trace(loading_fonts_);
  visitor->Trace(loaded_fonts_);
  visitor->Trace(failed_fonts_);
  visitor->Trace(ready_);
  ExecutionContextClient::Trace(visitor);
  EventTarget::Trace(visitor);
  FontFace::LoadFontCallback::Trace(visitor);
}

wtf_size_t FontFaceSet::size() const {
  if (!InActiveContext()) {
    return non_css_connected_faces_.size();
  }
  return CSSConnectedFontFaceList().size() + non_css_connected_faces_.size();
}

void FontFaceSet::AddFontFacesToFontFaceCache(FontFaceCache* font_face_cache) {
  for (const auto& font_face : non_css_connected_faces_) {
    font_face_cache->AddFontFace(font_face, false);
  }
}

void FontFaceSet::AddToLoadingFonts(FontFace* font_face) {
  if (!is_loading_) {
    is_loading_ = true;
    should_fire_loading_event_ = true;
    if (ready_->GetState() != ReadyProperty::kPending) {
      ready_->Reset();
    }
    HandlePendingEventsAndPromisesSoon();
  }
  loading_fonts_.insert(font_face);
  font_face->AddCallback(this);
}

void FontFaceSet::RemoveFromLoadingFonts(FontFace* font_face) {
  loading_fonts_.erase(font_face);
  if (loading_fonts_.empty()) {
    HandlePendingEventsAndPromisesSoon();
  }
}

void FontFaceSet::LoadFontPromiseResolver::LoadFonts() {
  if (!num_loading_) {
    resolver_->Resolve(font_faces_);
    return;
  }

  for (wtf_size_t i = 0; i < font_faces_.size(); i++) {
    font_faces_[i]->LoadWithCallback(this);
    font_faces_[i]->DidBeginImperativeLoad();
  }
}

ScriptPromise<IDLSequence<FontFace>> FontFaceSet::load(
    ScriptState* script_state,
    const String& font_string,
    const String& text) {
  if (!InActiveContext()) {
    return ScriptPromise<IDLSequence<FontFace>>();
  }

  Font font;
  if (!ResolveFontStyle(font_string, font)) {
    return ScriptPromise<IDLSequence<FontFace>>::RejectWithDOMException(
        script_state,
        MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kSyntaxError,
            "Could not resolve '" + font_string + "' as a font."));
  }

  FontFaceCache* font_face_cache = GetFontSelector()->GetFontFaceCache();
  FontFaceArray* faces = MakeGarbageCollected<FontFaceArray>();
  for (const FontFamily* f = &font.GetFontDescription().Family(); f;
       f = f->Next()) {
    if (f->FamilyIsGeneric()) {
      continue;
    }
    CSSSegmentedFontFace* segmented_font_face =
        font_face_cache->Get(font.GetFontDescription(), f->FamilyName());
    if (segmented_font_face) {
      segmented_font_face->Match(text, faces);
    }
  }

  auto* resolver =
      MakeGarbageCollected<LoadFontPromiseResolver>(faces, script_state);
  auto promise = resolver->Promise();
  // After this, resolver->promise() may return null.
  resolver->LoadFonts();
  return promise;
}

bool FontFaceSet::check(const String& font_string,
                        const String& text,
                        ExceptionState& exception_state) {
  if (!InActiveContext()) {
    return false;
  }

  Font font;
  if (!ResolveFontStyle(font_string, font)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "Could not resolve '" + font_string + "' as a font.");
    return false;
  }

  FontSelector* font_selector = GetFontSelector();
  FontFaceCache* font_face_cache = font_selector->GetFontFaceCache();

  unsigned index = 0;
  while (index < text.length()) {
    UChar32 c = text.CharacterStartingAt(index);
    index += U16_LENGTH(c);

    for (const FontFamily* f = &font.GetFontDescription().Family(); f;
         f = f->Next()) {
      if (f->FamilyIsGeneric() || font_selector->IsPlatformFamilyMatchAvailable(
                                      font.GetFontDescription(), *f)) {
        continue;
      }

      CSSSegmentedFontFace* face =
          font_face_cache->Get(font.GetFontDescription(), f->FamilyName());
      if (face && !face->CheckFont(c)) {
        return false;
      }
    }
  }
  return true;
}

void FontFaceSet::FireDoneEvent() {
  if (is_loading_) {
    FontFaceSetLoadEvent* done_event = nullptr;
    FontFaceSetLoadEvent* error_event = nullptr;
    done_event = FontFaceSetLoadEvent::CreateForFontFaces(
        event_type_names::kLoadingdone, loaded_fonts_);
    loaded_fonts_.clear();
    if (!failed_fonts_.empty()) {
      error_event = FontFaceSetLoadEvent::CreateForFontFaces(
          event_type_names::kLoadingerror, failed_fonts_);
      failed_fonts_.clear();
    }
    is_loading_ = false;
    DispatchEvent(*done_event);
    if (error_event) {
      DispatchEvent(*error_event);
    }
  }

  if (ready_->GetState() == ReadyProperty::kPending) {
    ready_->Resolve(this);
  }
}

bool FontFaceSet::ShouldSignalReady() const {
  if (!loading_fonts_.empty()) {
    return false;
  }
  return is_loading_ || ready_->GetState() == ReadyProperty::kPending;
}

void FontFaceSet::LoadFontPromiseResolver::NotifyLoaded(FontFace* font_face) {
  num_loading_--;
  if (num_loading_ || error_occured_) {
    return;
  }

  resolver_->Resolve(font_faces_);
}

void FontFaceSet::LoadFontPromiseResolver::NotifyError(FontFace* font_face) {
  num_loading_--;
  if (!error_occured_) {
    error_occured_ = true;
    resolver_->Reject(font_face->GetError());
  }
}

void FontFaceSet::LoadFontPromiseResolver::Trace(Visitor* visitor) const {
  visitor->Trace(font_faces_);
  visitor->Trace(resolver_);
  LoadFontCallback::Trace(visitor);
}

bool FontFaceSet::IterationSource::FetchNextItem(ScriptState*,
                                                 FontFace*& value,
                                                 ExceptionState&) {
  if (font_faces_.size() <= index_) {
    return false;
  }
  value = font_faces_[index_++];
  return true;
}

FontFaceSetIterable::IterationSource* FontFaceSet::CreateIterationSource(
    ScriptState*,
    ExceptionState&) {
  // Setlike should iterate each item in insertion order, and items should
  // be keep on up to date. But since blink does not have a way to hook up CSS
  // modification, take a snapshot here, and make it ordered as follows.
  HeapVector<Member<FontFace>> font_faces;
  if (InActiveContext()) {
    const HeapLinkedHashSet<Member<FontFace>>& css_connected_faces =
        CSSConnectedFontFaceList();
    font_faces.ReserveInitialCapacity(css_connected_faces.size() +
                                      non_css_connected_faces_.size());
    for (const auto& font_face : css_connected_faces) {
      font_faces.push_back(font_face);
    }
    for (const auto& font_face : non_css_connected_faces_) {
      font_faces.push_back(font_face);
    }
  }
  return MakeGarbageCollected<IterationSource>(std::move(font_faces));
}

}  // namespace blink

"""

```