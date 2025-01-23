Response:
My thought process to answer the request about `blink/renderer/core/dom/document.cc` went through these stages:

1. **Understanding the Core Request:** The request asks for the functionalities of the `Document` class as evidenced by the provided code snippet. It also specifically asks about relationships with JavaScript, HTML, and CSS, requests examples, asks for logical reasoning (with assumptions and outputs), common user/programming errors, debugging clues based on user actions, and finally, a summary of the functionalities of *this specific part* of the file.

2. **Initial Code Scan and Keyword Identification:** I started by quickly scanning the code for obvious keywords and patterns. Things that jumped out included:
    * `AriaNotify`: Accessibility features.
    * `IsValidName`, `ParseQualifiedName`: Handling XML/HTML element and attribute names.
    * `SetEncodingData`: Character encoding.
    * `CompleteURL`: URL resolution.
    * `OpenSearchDescriptionURL`:  Discovery of OpenSearch.
    * `currentScriptForBinding`, `PushCurrentScript`, `PopCurrentScript`: Managing currently executing scripts.
    * `designMode`:  The `contenteditable` attribute equivalent for the entire document.
    * `createAttribute`, `createAttributeNS`:  DOM manipulation.
    * `images`, `applets`, `embeds`, `scripts`, `links`, `forms`, `anchors`, `all`:  HTML collections.
    * `defaultView`:  Accessing the window object.
    * `MaybeExecuteDelayedAsyncScripts`, `MarkFirstPaint`, `OnLargestContentfulPaintUpdated`, `OnPrepareToStopParsing`, `FinishedParsing`:  Document lifecycle events and script execution.
    * `IconURLs`:  Fetching favicons.
    * `ThemeColor`: Handling the theme color meta tag.
    * `ColorSchemeMetaChanged`: Handling the color-scheme meta tag.
    * `SupportsReducedMotionMetaChanged`: Handling the `supports-reduced-motion` meta tag.

3. **Categorizing Functionalities:**  I then started grouping these observations into broader categories of functionality:
    * **Accessibility:** `AriaNotify`.
    * **Naming and Validation:** `IsValidName`, `ParseQualifiedName`.
    * **URL Handling:** `CompleteURL`, `OpenSearchDescriptionURL`.
    * **Character Encoding:** `SetEncodingData`.
    * **Scripting:**  `currentScriptForBinding`, `PushCurrentScript`, `PopCurrentScript`, lifecycle event handling related to scripts.
    * **DOM Manipulation:** `createAttribute`, `createAttributeNS`.
    * **Document Editing:** `designMode`.
    * **Document Structure and Relationships:** `ParentDocument`, `TopDocument`.
    * **HTML Collections:**  `images`, `applets`, etc.
    * **Document Lifecycle:** `MarkFirstPaint`, `FinishedParsing`, etc.
    * **Resource Loading and Hints:**  (Implicit in discussions of preloads and parsing).
    * **Metadata and Styling:** `IconURLs`, `ThemeColor`, `ColorSchemeMetaChanged`, `SupportsReducedMotionMetaChanged`.

4. **Connecting to JavaScript, HTML, and CSS:** For each category, I considered how it relates to the core web technologies:
    * **JavaScript:**  Script execution management, DOM manipulation methods are directly exposed to JS. Document lifecycle events trigger JS event handlers.
    * **HTML:**  Parsing and validation of HTML structure and attributes. Interpretation of meta tags.
    * **CSS:**  Character encoding affects CSS parsing. `designMode` influences rendering. Meta tags like `theme-color` and `color-scheme` directly affect styling.

5. **Generating Examples:**  I then came up with concrete examples for each connection:
    * **JavaScript:** Using `document.createElement()`, `document.querySelector()`, attaching event listeners to `DOMContentLoaded`.
    * **HTML:**  Invalid attribute names, incorrect qualified names in XML, `<meta charset>`, `<link rel="icon">`, `<meta name="theme-color">`.
    * **CSS:**  Incorrect encoding leading to garbled characters, the effect of `designMode` on content editing, how the theme color changes the browser UI, and how `color-scheme` affects default styles.

6. **Logical Reasoning (Assumptions and Outputs):**  For areas like name validation and qualified name parsing, I formulated simple scenarios with input and expected output (success or failure, specific error types).

7. **Identifying Common Errors:** I thought about typical mistakes developers make related to these functionalities:
    * Incorrect attribute names.
    * Incorrectly formatted qualified names.
    * Not understanding character encoding issues.
    * Misusing `designMode`.
    * Expecting HTML collections to be live when they are not in all cases.
    * Incorrectly handling or expecting the timing of `DOMContentLoaded`.
    * Issues with favicon paths.
    * Incorrect `theme-color` values.

8. **Debugging Clues and User Actions:**  I considered how user actions could lead to this code being executed and what developers might observe while debugging:
    * Typing in the address bar and loading a page.
    * Clicking links.
    * Interacting with JavaScript that modifies the DOM.
    * Observing network requests for favicons.
    * Inspecting the DOM in developer tools.
    * Looking at the "Elements" panel to see meta tags.

9. **Summarizing the Section's Functionality:** Finally, I focused specifically on the provided code snippet. I noted that it largely deals with:
    * **Accessibility notifications:** `aNotify`.
    * **Validation of names:** `IsValidName`.
    * **Parsing of qualified names:** `ParseQualifiedName`.
    * **Handling of document encoding:** `SetEncodingData`.

This structured approach allowed me to systematically analyze the code, connect it to the broader web platform, and generate the comprehensive answer requested. The initial scan and categorization were crucial for organizing my thoughts and ensuring I covered all the key aspects of the code snippet.
这是 `blink/renderer/core/dom/document.cc` 文件的一部分代码，主要关注以下功能：

**核心功能归纳 (基于提供的代码片段):**

1. **ARIA 通知 (Accessibility):**
   - `aNotify`:  负责发送 ARIA (Accessible Rich Internet Applications) 通知给辅助技术。

2. **名称合法性校验:**
   - `IsValidName`:  校验给定的字符串是否是一个合法的 XML/HTML 名称 (例如，元素或属性名)。它区分 ASCII 和非 ASCII 字符，并遵循名称起始字符和后续字符的规则。

3. **限定名解析 (Qualified Name Parsing):**
   - `ParseQualifiedName`:  解析带有命名空间前缀的限定名（例如 `prefix:localName`）。它会提取前缀和本地名，并检查限定名的格式是否正确，包括是否包含多个冒号、是否以无效字符开头或包含无效字符，以及前缀或本地名是否为空。

4. **文档编码设置:**
   - `SetEncodingData`:  设置文档的编码信息。当文档编码改变时，它会尝试重新解码 `<title>` 元素的内容，以确保用户看到正确的标题。

**与其他 Web 技术 (JavaScript, HTML, CSS) 的关系及举例:**

* **JavaScript:**
    * **`aNotify`:** JavaScript 可以通过 `document.dispatchEvent(new CustomEvent('aria-request', { detail: { announcement: '...', options: {} } }))` (或者类似的方式，具体 API 可能需要查看 Blink 的实现) 来触发辅助技术的通知。
        * **假设输入:** JavaScript 代码 `document.dispatchEvent(new CustomEvent('aria-request', { detail: { announcement: '加载完成', options: { live: 'polite' } } }))`
        * **输出:**  辅助技术可能会播报 "加载完成"，并根据 `options` 中的 `live` 属性决定播报的优先级。
    * **`IsValidName` 和 `ParseQualifiedName`:** 当 JavaScript 需要创建或操作 DOM 元素和属性时，Blink 内部会调用这些函数来验证名称的合法性。例如，使用 `document.createElement('my-element')` 或 `element.setAttribute('data-my-attr', 'value')` 时。如果名称不合法，会抛出错误。
        * **假设输入:** JavaScript 代码 `document.createElement(':invalid-tag')`
        * **输出:**  Blink 的 C++ 代码 (`IsValidName`) 检测到 `:` 是无效的起始字符，会返回 `false`，最终 JavaScript 会抛出一个 `DOMException`。

* **HTML:**
    * **`IsValidName` 和 `ParseQualifiedName`:**  在 HTML 解析过程中，当遇到元素标签和属性时，Blink 会使用这些函数来验证它们的名称是否符合 HTML 规范。
        * **假设输入:** HTML 代码 `<invalid.tag>`
        * **输出:**  Blink 的 HTML 解析器会调用 `IsValidName`，检测到 `.` 是无效的起始字符，可能导致解析错误或将该标签视为未知元素。
        * **假设输入:** HTML 代码 `<prefix:element>` (在 XML 或 SVG 文档中，或者使用了命名空间)
        * **输出:** Blink 的解析器会调用 `ParseQualifiedName` 来分离 `prefix` 和 `element`，并根据命名空间规则进行处理.
    * **`SetEncodingData`:**  HTML 文档的 `<meta charset="...">` 标签会影响文档的编码。当解析器遇到这个标签并确定了新的编码时，会调用 `SetEncodingData`。
        * **用户操作:** 用户访问一个包含 `<meta charset="gbk">` 的 HTML 页面。
        * **内部流程:** Blink 的 HTML 解析器读取到 `<meta>` 标签，提取编码信息 "gbk"，创建 `DocumentEncodingData` 对象，并调用 `SetEncodingData`。
        * **`SetEncodingData` 内部逻辑:** 如果在解析 `<head>` 阶段且遇到 `<title>` 标签，且原始编码是 Latin1，`SetEncodingData` 会尝试使用新的 "gbk" 编码重新解码标题内容。

* **CSS:**
    * 文档的编码设置 (`SetEncodingData`) 也会影响 CSS 的解析。如果 CSS 文件的编码与文档的编码不一致，可能会导致字符显示错误。

**逻辑推理及假设输入输出:**

* **`IsValidName` 逻辑推理:**
    * **假设输入 (ASCII):** 字符串 "myElement"
    * **内部流程:** 遍历字符串，检查每个字符是否是合法的名称字符（字母、数字、`:`、`_`、`-`、`.`）。
    * **输出:** `true`
    * **假设输入 (ASCII):** 字符串 "1element"
    * **内部流程:** 检查第一个字符 '1'，发现不是合法的起始字符。
    * **输出:** `false`
    * **假设输入 (非 ASCII):** 字符串 "你好"
    * **内部流程:** 遍历字符串，检查每个字符是否是合法的名称字符 (Unicode 字符集中的 NameStart 和 NamePart)。
    * **输出:** `true` (假设 "你好" 在 Unicode 中是合法的名称字符)

* **`ParseQualifiedName` 逻辑推理:**
    * **假设输入:** 原子字符串 "prefix:local"
    * **内部流程:** 找到冒号，将字符串分割为 "prefix" 和 "local"。
    * **输出:** `status = kQNValid`, `prefix = "prefix"`, `local_name = "local"`
    * **假设输入:** 原子字符串 "invalid::name"
    * **内部流程:** 找到第二个冒号，判断为多个冒号。
    * **输出:** `status = kQNMultipleColons`
    * **假设输入:** 原子字符串 ":local"
    * **内部流程:** 找到冒号，但前缀为空。
    * **输出:** `status = kQNEmptyPrefix`
    * **假设输入:** 原子字符串 "prefix:"
    * **内部流程:** 找到冒号，但本地名为空。
    * **输出:** `status = kQNEmptyLocalName`

**用户或编程常见的使用错误:**

* **使用无效的 HTML 元素或属性名:** 例如 `<1tag>` 或 `<div data-my- attr="value">`。Blink 会在解析或通过 JavaScript 操作 DOM 时捕获这些错误。
* **错误地使用命名空间:** 在需要命名空间的地方，提供了不正确的限定名格式，例如使用了多个冒号或空的命名空间前缀/本地名。
* **字符编码问题:**
    * 文档的编码声明与实际编码不符，导致页面显示乱码。
    * 在 JavaScript 中创建包含非 ASCII 字符的元素或属性时，没有考虑编码问题。
* **ARIA 属性使用不当:**  提供给 `aNotify` 的 `announcement` 文本不清晰或不提供有用的上下文信息，或者 `options` 中的属性设置不当。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 URL 并访问网页。**
   - Blink 开始加载 HTML 资源。
   - HTML 解析器开始解析 HTML 内容。
   - 如果遇到 `<meta charset="...">` 标签，会调用 `SetEncodingData`。
   - 如果遇到元素标签或属性，会调用 `IsValidName` 和 `ParseQualifiedName` 进行验证。

2. **用户与网页交互，触发 JavaScript 代码执行。**
   - JavaScript 代码可能调用 DOM API (例如 `document.createElement`, `element.setAttribute`) 来创建或修改 DOM 结构。这些 API 内部会调用 `IsValidName` 和 `ParseQualifiedName`。
   - JavaScript 代码也可能触发 ARIA 通知，间接调用 `aNotify`。

3. **网页包含动态内容或通过 AJAX 加载内容。**
   - 新加载的 HTML 片段会被解析，同样会触发 `IsValidName` 和 `ParseQualifiedName`。
   - 如果新加载的内容声明了不同的编码，可能会导致 `SetEncodingData` 被调用。

4. **开发者在开发者工具中操作 DOM。**
   - 例如，在 "Elements" 面板中编辑元素属性，浏览器内部会调用相应的 DOM 操作函数，这些函数可能会触发名称验证。

**第 9 部分功能归纳:**

这段代码片段主要负责文档对象模型中与**名称处理、编码设置和辅助功能支持**相关的核心基础功能。具体来说，它提供了：

* **用于发送 ARIA 通知的机制。**
* **用于验证 HTML/XML 名称合法性的方法。**
* **用于解析带有命名空间的限定名的方法。**
* **用于设置和处理文档编码的功能，并在编码变化时尝试修正潜在的显示问题。**

这些功能是 Blink 引擎处理 HTML 文档的基础组成部分，确保了文档结构的正确性、字符的正确显示以及为辅助技术提供必要的信息。

### 提示词
```
这是目录为blink/renderer/core/dom/document.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
aNotify(const String& announcement,
                          const AriaNotificationOptions* options) {
  DCHECK(RuntimeEnabledFeatures::AriaNotifyEnabled());

  if (auto* cache = ExistingAXObjectCache()) {
    cache->HandleAriaNotification(this, announcement, options);
  }
}

static bool IsValidNameNonASCII(base::span<const LChar> characters) {
  if (!IsValidNameStart(characters[0]))
    return false;

  for (size_t i = 1; i < characters.size(); ++i) {
    if (!IsValidNamePart(characters[i]))
      return false;
  }

  return true;
}

static bool IsValidNameNonASCII(base::span<const UChar> characters) {
  for (size_t i = 0; i < characters.size();) {
    bool first = i == 0;
    UChar32 c;
    U16_NEXT(characters, i, characters.size(), c);  // Increments i.
    if (first ? !IsValidNameStart(c) : !IsValidNamePart(c))
      return false;
  }

  return true;
}

template <typename CharType>
static inline bool IsValidNameASCII(base::span<const CharType> characters) {
  CharType c = characters[0];
  if (!(IsASCIIAlpha(c) || c == ':' || c == '_'))
    return false;

  for (size_t i = 1; i < characters.size(); ++i) {
    c = characters[i];
    if (!(IsASCIIAlphanumeric(c) || c == ':' || c == '_' || c == '-' ||
          c == '.'))
      return false;
  }

  return true;
}

bool Document::IsValidName(const StringView& name) {
  unsigned length = name.length();
  if (!length)
    return false;
  return WTF::VisitCharacters(name, [](auto chars) {
    if (IsValidNameASCII(chars)) {
      return true;
    }
    return IsValidNameNonASCII(chars);
  });
}

enum QualifiedNameStatus {
  kQNValid,
  kQNMultipleColons,
  kQNInvalidStartChar,
  kQNInvalidChar,
  kQNEmptyPrefix,
  kQNEmptyLocalName
};

struct ParseQualifiedNameResult {
  QualifiedNameStatus status;
  UChar32 character;
  ParseQualifiedNameResult() = default;
  explicit ParseQualifiedNameResult(QualifiedNameStatus status)
      : status(status) {}
  ParseQualifiedNameResult(QualifiedNameStatus status, UChar32 character)
      : status(status), character(character) {}
};

template <typename CharType>
static ParseQualifiedNameResult ParseQualifiedNameInternal(
    const AtomicString& qualified_name,
    base::span<const CharType> characters,
    AtomicString& prefix,
    AtomicString& local_name) {
  bool name_start = true;
  bool saw_colon = false;
  size_t colon_pos = 0;

  for (size_t i = 0; i < characters.size();) {
    UChar32 c;
    U16_NEXT(characters, i, characters.size(), c);
    if (c == ':') {
      if (saw_colon)
        return ParseQualifiedNameResult(kQNMultipleColons);
      name_start = true;
      saw_colon = true;
      colon_pos = i - 1;
    } else if (name_start) {
      if (!IsValidNameStart(c))
        return ParseQualifiedNameResult(kQNInvalidStartChar, c);
      name_start = false;
    } else {
      if (!IsValidNamePart(c))
        return ParseQualifiedNameResult(kQNInvalidChar, c);
    }
  }

  if (!saw_colon) {
    prefix = g_null_atom;
    local_name = qualified_name;
  } else {
    auto [prefix_span, rest] = characters.split_at(colon_pos);
    prefix = AtomicString(prefix_span);
    if (prefix.empty())
      return ParseQualifiedNameResult(kQNEmptyPrefix);
    local_name = AtomicString(rest.subspan(1u));
  }

  if (local_name.empty())
    return ParseQualifiedNameResult(kQNEmptyLocalName);

  return ParseQualifiedNameResult(kQNValid);
}

bool Document::ParseQualifiedName(const AtomicString& qualified_name,
                                  AtomicString& prefix,
                                  AtomicString& local_name,
                                  ExceptionState& exception_state) {
  if (qualified_name.empty()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidCharacterError,
                                      "The qualified name provided is empty.");
    return false;
  }

  ParseQualifiedNameResult return_value = WTF::VisitCharacters(
      qualified_name, [&qualified_name, &prefix, &local_name](auto chars) {
        return ParseQualifiedNameInternal(qualified_name, chars, prefix,
                                          local_name);
      });
  if (return_value.status == kQNValid)
    return true;

  StringBuilder message;
  message.Append("The qualified name provided ('");
  message.Append(qualified_name);
  message.Append("') ");

  if (return_value.status == kQNMultipleColons) {
    message.Append("contains multiple colons.");
  } else if (return_value.status == kQNInvalidStartChar) {
    message.Append("contains the invalid name-start character '");
    message.Append(return_value.character);
    message.Append("'.");
  } else if (return_value.status == kQNInvalidChar) {
    message.Append("contains the invalid character '");
    message.Append(return_value.character);
    message.Append("'.");
  } else if (return_value.status == kQNEmptyPrefix) {
    message.Append("has an empty namespace prefix.");
  } else {
    DCHECK_EQ(return_value.status, kQNEmptyLocalName);
    message.Append("has an empty local name.");
  }

  exception_state.ThrowDOMException(DOMExceptionCode::kInvalidCharacterError,
                                    message.ReleaseString());
  return false;
}

void Document::SetEncodingData(const DocumentEncodingData& new_data) {
  // It's possible for the encoding of the document to change while we're
  // decoding data. That can only occur while we're processing the <head>
  // portion of the document. There isn't much user-visible content in the
  // <head>, but there is the <title> element. This function detects that
  // situation and re-decodes the document's title so that the user doesn't see
  // an incorrectly decoded title in the title bar.
  if (title_element_ && Encoding() != new_data.Encoding() &&
      !ElementTraversal::FirstWithin(*title_element_) &&
      Encoding() == Latin1Encoding() &&
      title_element_->textContent().ContainsOnlyLatin1OrEmpty()) {
    std::string original_bytes = title_element_->textContent().Latin1();
    std::unique_ptr<TextCodec> codec = NewTextCodec(new_data.Encoding());
    String correctly_decoded_title = codec->Decode(
        base::as_byte_span(original_bytes), WTF::FlushBehavior::kDataEOF);
    title_element_->setTextContent(correctly_decoded_title);
  }

  DCHECK(new_data.Encoding().IsValid());
  encoding_data_ = new_data;

  // FIXME: Should be removed as part of
  // https://code.google.com/p/chromium/issues/detail?id=319643
  bool should_use_visual_ordering =
      encoding_data_.Encoding().UsesVisualOrdering();
  if (should_use_visual_ordering != visually_ordered_) {
    visually_ordered_ = should_use_visual_ordering;
    GetStyleEngine().MarkViewportStyleDirty();
    GetStyleEngine().MarkAllElementsForStyleRecalc(
        StyleChangeReasonForTracing::Create(
            style_change_reason::kVisuallyOrdered));
  }
}

KURL Document::CompleteURL(
    const String& url,
    const CompleteURLPreloadStatus preload_status) const {
  return CompleteURLWithOverride(url, base_url_, preload_status);
}

KURL Document::CompleteURLWithOverride(
    const String& url,
    const KURL& base_url_override,
    CompleteURLPreloadStatus preload_status) const {
  DCHECK(base_url_override.IsEmpty() || base_url_override.IsValid());

  // Always return a null URL when passed a null string.
  // FIXME: Should we change the KURL constructor to have this behavior?
  // See also [CSS]StyleSheet::completeURL(const String&)
  if (url.IsNull())
    return KURL();

  KURL result = Encoding().IsValid() ? KURL(base_url_override, url, Encoding())
                                     : KURL(base_url_override, url);
  // If the conditions are met for
  // `should_record_sandboxed_srcdoc_baseurl_metrics_` to be set, we should
  // only record the metric if there's no `base_element_url_` set via a base
  // element. We must also check the preload status below, since a
  // PreloadRequest could call this function before `base_element_url_` is set.
  if (should_record_sandboxed_srcdoc_baseurl_metrics_ &&
      base_element_url_.IsEmpty() && preload_status != kIsPreload) {
    // Compute the same thing assuming an empty base url, to see if it changes.
    // This will allow us to ignore trivial changes, such as 'https://foo.com'
    // resolving as 'https://foo.com/', which happens whether the base url is
    // specified or not.
    // While the following computation is non-trivial overhead, it's not
    // expected to be needed often enough to be problematic, and it will be
    // removed once we've collected data for https://crbug.com/330744612.
    KURL empty_baseurl_result = Encoding().IsValid()
                                    ? KURL(KURL(), url, Encoding())
                                    : KURL(KURL(), url);
    if (result != empty_baseurl_result) {
      CountUse(WebFeature::kSandboxedSrcdocFrameResolvesRelativeURL);
      // Let's not repeat the parallel computation again now we've found a
      // instance to record.
      should_record_sandboxed_srcdoc_baseurl_metrics_ = false;
    }
  }
  return result;
}

// static
bool Document::ShouldInheritSecurityOriginFromOwner(const KURL& url) {
  // https://html.spec.whatwg.org/C/#origin
  //
  // If a Document is the initial "about:blank" document, the origin and
  // effective script origin of the Document are those it was assigned when its
  // browsing context was created.
  //
  // Note: We generalize this to all "blank" URLs and invalid URLs because we
  // treat all of these URLs as about:blank.  This is okay to do for
  // "about:mumble" because the Browser process will translate such URLs into
  // "about:blank#blocked".  This is necessary, because of practices pointed out
  // in https://crbug.com/1220186.
  return url.IsEmpty() || url.ProtocolIsAbout();
}

KURL Document::OpenSearchDescriptionURL() {
  static const char kOpenSearchMIMEType[] =
      "application/opensearchdescription+xml";
  static const char kOpenSearchRelation[] = "search";

  // FIXME: Why do only top-level frames have openSearchDescriptionURLs?
  if (!GetFrame() || GetFrame()->Tree().Parent())
    return KURL();

  // FIXME: Why do we need to wait for load completion?
  if (!LoadEventFinished())
    return KURL();

  if (!head())
    return KURL();

  for (HTMLLinkElement* link_element =
           Traversal<HTMLLinkElement>::FirstChild(*head());
       link_element;
       link_element = Traversal<HTMLLinkElement>::NextSibling(*link_element)) {
    if (!EqualIgnoringASCIICase(link_element->GetType(), kOpenSearchMIMEType) ||
        !EqualIgnoringASCIICase(link_element->Rel(), kOpenSearchRelation))
      continue;
    if (link_element->Href().IsEmpty())
      continue;

    // Count usage; perhaps we can lock this to secure contexts.
    WebFeature osd_disposition;
    scoped_refptr<const SecurityOrigin> target =
        SecurityOrigin::Create(link_element->Href());
    if (execution_context_->IsSecureContext()) {
      osd_disposition = target->IsPotentiallyTrustworthy()
                            ? WebFeature::kOpenSearchSecureOriginSecureTarget
                            : WebFeature::kOpenSearchSecureOriginInsecureTarget;
    } else {
      osd_disposition =
          target->IsPotentiallyTrustworthy()
              ? WebFeature::kOpenSearchInsecureOriginSecureTarget
              : WebFeature::kOpenSearchInsecureOriginInsecureTarget;
    }
    UseCounter::Count(*this, osd_disposition);

    return link_element->Href();
  }

  return KURL();
}

V8HTMLOrSVGScriptElement* Document::currentScriptForBinding() const {
  if (current_script_stack_.empty())
    return nullptr;
  ScriptElementBase* script_element_base = current_script_stack_.back();
  if (!script_element_base)
    return nullptr;
  return script_element_base->AsV8HTMLOrSVGScriptElement();
}

void Document::PushCurrentScript(ScriptElementBase* new_current_script) {
  current_script_stack_.push_back(new_current_script);
}

void Document::PopCurrentScript(ScriptElementBase* script) {
  DCHECK(!current_script_stack_.empty());
  DCHECK_EQ(current_script_stack_.back(), script);
  current_script_stack_.pop_back();
}

void Document::SetTransformSource(std::unique_ptr<TransformSource> source) {
  transform_source_ = std::move(source);
}

String Document::designMode() const {
  return InDesignMode() ? keywords::kOn : keywords::kOff;
}

void Document::setDesignMode(const String& value) {
  bool new_value = design_mode_;
  if (EqualIgnoringASCIICase(value, keywords::kOn)) {
    new_value = true;
    UseCounter::Count(*this, WebFeature::kDocumentDesignModeEnabeld);
  } else if (EqualIgnoringASCIICase(value, keywords::kOff)) {
    new_value = false;
  }
  if (new_value == design_mode_)
    return;
  design_mode_ = new_value;
  GetStyleEngine().MarkViewportStyleDirty();
  GetStyleEngine().MarkAllElementsForStyleRecalc(
      StyleChangeReasonForTracing::Create(style_change_reason::kDesignMode));
}

Document* Document::ParentDocument() const {
  if (!GetFrame())
    return nullptr;
  auto* parent_local_frame = DynamicTo<LocalFrame>(GetFrame()->Tree().Parent());
  if (!parent_local_frame)
    return nullptr;
  return parent_local_frame->GetDocument();
}

Document& Document::TopDocument() const {
  // FIXME: Not clear what topDocument() should do in the OOPI case--should it
  // return the topmost available Document, or something else?
  Document* doc = const_cast<Document*>(this);
  for (HTMLFrameOwnerElement* element = doc->LocalOwner(); element;
       element = doc->LocalOwner())
    doc = &element->GetDocument();

  DCHECK(doc);
  return *doc;
}

ExecutionContext* Document::GetExecutionContext() const {
  return execution_context_.Get();
}

Agent& Document::GetAgent() const {
  return *agent_;
}

Attr* Document::createAttribute(const AtomicString& name,
                                ExceptionState& exception_state) {
  if (!IsValidName(name)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidCharacterError,
                                      "The localName provided ('" + name +
                                          "') contains an invalid character.");
    return nullptr;
  }
  return MakeGarbageCollected<Attr>(
      *this, QualifiedName(ConvertLocalName(name)), g_empty_atom);
}

Attr* Document::createAttributeNS(const AtomicString& namespace_uri,
                                  const AtomicString& qualified_name,
                                  ExceptionState& exception_state) {
  AtomicString prefix, local_name;
  if (!ParseQualifiedName(qualified_name, prefix, local_name, exception_state))
    return nullptr;

  QualifiedName q_name(prefix, local_name, namespace_uri);

  if (!HasValidNamespaceForAttributes(q_name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNamespaceError,
        "The namespace URI provided ('" + namespace_uri +
            "') is not valid for the qualified name provided ('" +
            qualified_name + "').");
    return nullptr;
  }

  return MakeGarbageCollected<Attr>(*this, q_name, g_empty_atom);
}

const SVGDocumentExtensions* Document::SvgExtensions() const {
  return svg_extensions_.Get();
}

SVGDocumentExtensions& Document::AccessSVGExtensions() {
  if (!svg_extensions_)
    svg_extensions_ = MakeGarbageCollected<SVGDocumentExtensions>(this);
  return *svg_extensions_;
}

bool Document::HasSVGRootNode() const {
  return IsA<SVGSVGElement>(documentElement());
}

HTMLCollection* Document::images() {
  return EnsureCachedCollection<HTMLCollection>(kDocImages);
}

HTMLCollection* Document::applets() {
  return EnsureCachedCollection<HTMLCollection>(kDocApplets);
}

HTMLCollection* Document::embeds() {
  return EnsureCachedCollection<HTMLCollection>(kDocEmbeds);
}

HTMLCollection* Document::scripts() {
  return EnsureCachedCollection<HTMLCollection>(kDocScripts);
}

HTMLCollection* Document::links() {
  return EnsureCachedCollection<HTMLCollection>(kDocLinks);
}

HTMLCollection* Document::forms() {
  return EnsureCachedCollection<HTMLCollection>(kDocForms);
}

HTMLCollection* Document::anchors() {
  return EnsureCachedCollection<HTMLCollection>(kDocAnchors);
}

HTMLAllCollection* Document::all() {
  return EnsureCachedCollection<HTMLAllCollection>(kDocAll);
}

HTMLCollection* Document::WindowNamedItems(const AtomicString& name) {
  return EnsureCachedCollection<WindowNameCollection>(kWindowNamedItems, name);
}

DocumentNameCollection* Document::DocumentNamedItems(const AtomicString& name) {
  return EnsureCachedCollection<DocumentNameCollection>(kDocumentNamedItems,
                                                        name);
}

HTMLCollection* Document::DocumentAllNamedItems(const AtomicString& name) {
  return EnsureCachedCollection<DocumentAllNameCollection>(
      kDocumentAllNamedItems, name);
}

void Document::IncrementImmediateChildFrameCreationCount() {
  data_->immediate_child_frame_creation_count_++;
}

int Document::GetImmediateChildFrameCreationCount() const {
  return data_->immediate_child_frame_creation_count_;
}

DOMWindow* Document::defaultView() const {
  return dom_window_;
}

AllowState Document::GetDeclarativeShadowRootAllowState() const {
  return declarative_shadow_root_allow_state_;
}

void Document::setAllowDeclarativeShadowRoots(bool val) {
  declarative_shadow_root_allow_state_ =
      val ? AllowState::kAllow : AllowState::kDeny;
}

void Document::MaybeExecuteDelayedAsyncScripts(
    MilestoneForDelayedAsyncScript milestone) {
  // This is called on each paint when DelayAsyncScriptDelayType is kEachPaint,
  // which causes regression. Cache the feature status to avoid frequent
  // calculation.
  static const bool delay_async_script_execution_is_enabled =
      base::FeatureList::IsEnabled(features::kDelayAsyncScriptExecution);
  if (!delay_async_script_execution_is_enabled)
    return;

  const features::DelayAsyncScriptDelayType delay_async_script_delay_type =
      features::kDelayAsyncScriptExecutionDelayParam.Get();
  switch (delay_async_script_delay_type) {
    case features::DelayAsyncScriptDelayType::kFirstPaintOrFinishedParsing:
      // Notify the ScriptRunner if the first paint has been recorded and
      // we're delaying async scripts until first paint or finished parsing
      // (whichever comes first).
      if (milestone == MilestoneForDelayedAsyncScript::kFirstPaint ||
          milestone == MilestoneForDelayedAsyncScript::kFinishedParsing) {
        script_runner_delayer_->Deactivate();
      }
      break;
    case features::DelayAsyncScriptDelayType::kFinishedParsing:
      // Notify the ScriptRunner if we're finished parsing and we're delaying
      // async scripts until finished parsing occurs.
      if (milestone == MilestoneForDelayedAsyncScript::kFinishedParsing)
        script_runner_delayer_->Deactivate();
      break;
    case features::DelayAsyncScriptDelayType::kTillFirstLcpCandidate:
      // Notify the ScriptRunner if a LCP candidate is reported.
      if (milestone == MilestoneForDelayedAsyncScript::kLcpCandidate) {
        // Flush all async scripts that are already prepared but forced to be
        // delayed.
        script_runner_delayer_->Deactivate();
      }
      break;
  }
}

void Document::MarkFirstPaint() {
  MaybeExecuteDelayedAsyncScripts(MilestoneForDelayedAsyncScript::kFirstPaint);
}

void Document::OnLargestContentfulPaintUpdated() {
  MaybeExecuteDelayedAsyncScripts(
      MilestoneForDelayedAsyncScript::kLcpCandidate);
}

void Document::OnPrepareToStopParsing() {
  if (render_blocking_resource_manager_) {
    render_blocking_resource_manager_->ClearPendingParsingElements();
  }
  MaybeExecuteDelayedAsyncScripts(
      MilestoneForDelayedAsyncScript::kFinishedParsing);
}

void Document::FinishedParsing() {
  TRACE_EVENT_WITH_FLOW0("blink", "Document::FinishedParsing",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  DCHECK(!GetScriptableDocumentParser() || !parser_->IsParsing());
  DCHECK(!GetScriptableDocumentParser() || ready_state_ != kLoading);
  SetParsingState(kInDOMContentLoaded);
  DocumentParserTiming::From(*this).MarkParserStop();

  // FIXME: DOMContentLoaded is dispatched synchronously, but this should be
  // dispatched in a queued task, see https://crbug.com/961428
  if (document_timing_.DomContentLoadedEventStart().is_null())
    document_timing_.MarkDomContentLoadedEventStart();
  if (!ScriptForbiddenScope::IsScriptForbidden()) {
    DispatchEvent(*Event::CreateBubble(event_type_names::kDOMContentLoaded));

    if (LocalFrame* frame = GetFrame()) {
      if (frame->IsAttached()) {
        DEVTOOLS_TIMELINE_TRACE_EVENT_INSTANT(
            "MarkDOMContent", inspector_mark_load_event::Data, frame);
        probe::DomContentLoadedEventFired(frame);
      }
    }
  }

  if (document_timing_.DomContentLoadedEventEnd().is_null())
    document_timing_.MarkDomContentLoadedEventEnd();
  SetParsingState(kFinishedParsing);

  // Ensure Custom Element callbacks are drained before DOMContentLoaded.
  // FIXME: Remove this ad-hoc checkpoint when DOMContentLoaded is dispatched in
  // a queued task, which will do a checkpoint anyway. https://crbug.com/425790
  agent_->event_loop()->PerformMicrotaskCheckpoint();

  ScriptableDocumentParser* parser = GetScriptableDocumentParser();
  well_formed_ = parser && parser->WellFormed();

  if (LocalFrame* frame = GetFrame()) {
    // Guarantee at least one call to the client specifying a title. (If
    // |title_| is not empty, then the title has already been dispatched.)
    if (title_.empty())
      DispatchDidReceiveTitle();

    // Don't update the layout tree if we haven't requested the main resource
    // yet to avoid adding extra latency. Note that the first layout tree update
    // can be expensive since it triggers the parsing of the default stylesheets
    // which are compiled-in.
    // FrameLoader::finishedParsing() might end up calling
    // Document::implicitClose() if all resource loads are
    // complete. HTMLObjectElements can start loading their resources from post
    // attach callbacks triggered by recalcStyle().  This means if we parse out
    // an <object> tag and then reach the end of the document without updating
    // styles, we might not have yet started the resource load and might fire
    // the window load event too early.  To avoid this we force the styles to be
    // up to date before calling FrameLoader::finishedParsing().  See
    // https://bugs.webkit.org/show_bug.cgi?id=36864 starting around comment 35.
    if (!is_initial_empty_document_ && HaveRenderBlockingStylesheetsLoaded()) {
      // The is_initial_empty_document_ flag is only true when the document is
      // initialized, but then it is synchronously loaded and the flag goes out
      // of sync. Loader()->HasLoadedNonInitialEmptyDocument() is more correct.
      // Keeping both for now behind a flag so that it's finch-testable.
      if (GetFrame()->IsMainFrame() ||
          Loader()->HasLoadedNonInitialEmptyDocument() ||
          !base::FeatureList::IsEnabled(
              blink::features::
                  kAvoidForcedLayoutOnInitialEmptyDocumentInSubframe)) {
        UpdateStyleAndLayoutTree();
        if (base::FeatureList::IsEnabled(
                features::kPrerender2EarlyDocumentLifecycleUpdate) &&
            IsPrerendering() && GetFrame()->IsLocalRoot() &&
            GetPage()->ShouldPreparePaintTreeOnPrerender()) {
          View()->DryRunPaintingForPrerender();
        }
      }
    }

    BeginLifecycleUpdatesIfRenderingReady();

    frame->GetIdlenessDetector()->DomContentLoadedEventFired();

    if (ShouldMarkFontPerformance()) {
      FontPerformance::MarkDomContentLoaded();
    }

    frame->Loader().FinishedParsing();
  }

  // Schedule dropping of the ElementDataCache. We keep it alive for a while
  // after parsing finishes so that dynamically inserted content can also
  // benefit from sharing optimizations.  Note that we don't refresh the timer
  // on cache access since that could lead to huge caches being kept alive
  // indefinitely by something innocuous like JS setting .innerHTML repeatedly
  // on a timer.
  element_data_cache_clear_timer_.StartOneShot(base::Seconds(10), FROM_HERE);

  // Parser should have picked up all preloads by now
  fetcher_->ClearPreloads(ResourceFetcher::kClearSpeculativeMarkupPreloads);

  if (IsInOutermostMainFrame() && !IsInitialEmptyDocument() &&
      Url().ProtocolIsInHTTPFamily()) {
    // Record histograms of ShapeText.
    base::UmaHistogramMicrosecondsTimes(
        "Blink.Layout.InlineNode.ShapeText.TotalTime.InOutermostMainFrame3",
        data_->accumulated_shape_text_elapsed_time_);
    base::UmaHistogramMicrosecondsTimes(
        "Blink.Layout.InlineNode.ShapeText.MaxTime.InOutermostMainFrame3",
        data_->max_shape_text_elapsed_time_);

    // Record histograms of SVGImage.
    base::UmaHistogramCounts100(
        "Blink.Layout.SVGImage.Count.InOutermostMainFrame",
        data_->svg_image_processed_count_);
    base::UmaHistogramMicrosecondsTimes(
        "Blink.Layout.SVGImage.TotalTime.InOutermostMainFrame",
        data_->accumulated_svg_image_elapsed_time_);

    // UKM data is sampled at a frequency of `kUkmSamplingRate`.
    if (base::RandDouble() < kUkmSamplingRate) {
      ukm::builders::Blink_ShapeText(UkmSourceID())
          .SetTotalTime(
              data_->accumulated_shape_text_elapsed_time_.InMicroseconds())
          .SetMaxTime(data_->max_shape_text_elapsed_time_.InMicroseconds())
          .Record(UkmRecorder());
      ukm::builders::Blink_SVGImage(UkmSourceID())
          .SetCount(ukm::GetExponentialBucketMinForCounts1000(
              data_->svg_image_processed_count_))
          .SetTotalTime(
              data_->accumulated_svg_image_elapsed_time_.InMicroseconds())
          .Record(UkmRecorder());
    }
  }
}

void Document::ElementDataCacheClearTimerFired(TimerBase*) {
  element_data_cache_.Clear();
}

void Document::BeginLifecycleUpdatesIfRenderingReady() {
  TRACE_EVENT2("blink", "Document::BeginLifecycleUpdatesIfRenderingReady",
               "is_active", IsActive(), "have_render_blocking_resources_loaded",
               HaveRenderBlockingResourcesLoaded());
  if (!IsActive())
    return;
  if (!HaveRenderBlockingResourcesLoaded())
    return;
  if (!rendering_has_begun_) {
    RenderBlockingMetricsReporter::From(*this).RenderBlockingResourcesLoaded();
    rendering_has_begun_ = true;
  }
  // TODO(japhet): If IsActive() is true, View() should always be non-null.
  // Speculative fix for https://crbug.com/1171891
  if (auto* view = View()) {
    view->BeginLifecycleUpdates();
  } else {
    NOTREACHED();
  }
}

Vector<IconURL> Document::IconURLs(int icon_types_mask) {
  IconURL first_favicon;
  IconURL first_touch_icon;
  IconURL first_touch_precomposed_icon;
  Vector<IconURL> secondary_icons;

  using TraversalFunction = HTMLLinkElement* (*)(const Node&);
  TraversalFunction find_next_candidate =
      &Traversal<HTMLLinkElement>::NextSibling;

  HTMLLinkElement* first_element = nullptr;
  if (head()) {
    first_element = Traversal<HTMLLinkElement>::FirstChild(*head());
  } else if (IsSVGDocument() && IsA<SVGSVGElement>(documentElement())) {
    first_element = Traversal<HTMLLinkElement>::FirstWithin(*documentElement());
    find_next_candidate = &Traversal<HTMLLinkElement>::Next;
  }

  // Start from the first child node so that icons seen later take precedence as
  // required by the spec.
  for (HTMLLinkElement* link_element = first_element; link_element;
       link_element = find_next_candidate(*link_element)) {
    if (!((1 << static_cast<int>(link_element->GetIconType())) &
          icon_types_mask)) {
      continue;
    }
    if (link_element->Href().IsEmpty())
      continue;

    if (!link_element->Media().empty()) {
      auto* media_query =
          GetMediaQueryMatcher().MatchMedia(link_element->Media());
      if (!media_query->matches())
        continue;
    }

    IconURL new_url(link_element->Href(), link_element->IconSizes(),
                    link_element->GetType(), link_element->GetIconType());
    if (link_element->GetIconType() ==
        mojom::blink::FaviconIconType::kFavicon) {
      if (first_favicon.icon_type_ != mojom::blink::FaviconIconType::kInvalid)
        secondary_icons.push_back(first_favicon);
      first_favicon = new_url;
    } else if (link_element->GetIconType() ==
               mojom::blink::FaviconIconType::kTouchIcon) {
      if (first_touch_icon.icon_type_ !=
          mojom::blink::FaviconIconType::kInvalid)
        secondary_icons.push_back(first_touch_icon);
      first_touch_icon = new_url;
    } else if (link_element->GetIconType() ==
               mojom::blink::FaviconIconType::kTouchPrecomposedIcon) {
      if (first_touch_precomposed_icon.icon_type_ !=
          mojom::blink::FaviconIconType::kInvalid)
        secondary_icons.push_back(first_touch_precomposed_icon);
      first_touch_precomposed_icon = new_url;
    } else {
      NOTREACHED();
    }
  }

  Vector<IconURL> icon_urls;
  if (first_favicon.icon_type_ != mojom::blink::FaviconIconType::kInvalid) {
    icon_urls.push_back(first_favicon);
  } else if (url_.ProtocolIsInHTTPFamily() &&
             icon_types_mask & 1 << static_cast<int>(
                                   mojom::blink::FaviconIconType::kFavicon)) {
    IconURL default_favicon = IconURL::DefaultFavicon(url_);
    if (DefaultFaviconAllowedByCSP(this, default_favicon))
      icon_urls.push_back(std::move(default_favicon));
  }

  if (first_touch_icon.icon_type_ != mojom::blink::FaviconIconType::kInvalid)
    icon_urls.push_back(first_touch_icon);
  if (first_touch_precomposed_icon.icon_type_ !=
      mojom::blink::FaviconIconType::kInvalid)
    icon_urls.push_back(first_touch_precomposed_icon);
  for (int i = secondary_icons.size() - 1; i >= 0; --i)
    icon_urls.push_back(secondary_icons[i]);
  return icon_urls;
}

void Document::UpdateThemeColorCache() {
  meta_theme_color_elements_.clear();
  auto* root_element = documentElement();
  if (!root_element)
    return;

  for (HTMLMetaElement& meta_element :
       Traversal<HTMLMetaElement>::DescendantsOf(*root_element)) {
    if (EqualIgnoringASCIICase(meta_element.GetName(), "theme-color"))
      meta_theme_color_elements_.push_back(meta_element);
  }
}

std::optional<Color> Document::ThemeColor() {
  // Returns the color of the first meta[name=theme-color] element in
  // tree order that matches and is valid.
  // https://html.spec.whatwg.org/multipage/semantics.html#meta-theme-color
  for (auto& element : meta_theme_color_elements_) {
    if (!element->Media().empty()) {
      auto* media_query = GetMediaQueryMatcher().MatchMedia(
          element->Media().GetString().StripWhiteSpace());
      if (!media_query->matches())
        continue;
    }
    Color color;
    if (CSSParser::ParseColor(
            color, element->Content().GetString().StripWhiteSpace(), true)) {
      return color;
    }
  }
  return std::nullopt;
}

void Document::UpdateAppTitle() {
  auto* root_element = documentElement();
  if (!root_element) {
    return;
  }

  for (HTMLMetaElement& meta_element :
       Traversal<HTMLMetaElement>::DescendantsOf(*root_element)) {
    if (EqualIgnoringASCIICase(meta_element.GetName(), "app-title")) {
      GetFrame()->GetLocalFrameHostRemote().UpdateAppTitle(
          meta_element.Content().GetString());
      return;
    }
  }

  // Handle case of meta tag being removed by setting app title to empty string.
  GetFrame()->GetLocalFrameHostRemote().UpdateAppTitle(String(""));
}

void Document::ColorSchemeMetaChanged() {
  const CSSValue* color_scheme = nullptr;
  if (auto* root_element = documentElement()) {
    for (HTMLMetaElement& meta_element :
         Traversal<HTMLMetaElement>::DescendantsOf(*root_element)) {
      if (EqualIgnoringASCIICase(meta_element.GetName(),
                                 keywords::kColorScheme)) {
        if ((color_scheme = CSSParser::ParseSingleValue(
                 CSSPropertyID::kColorScheme,
                 meta_element.Content().GetString().StripWhiteSpace(),
                 ElementSheet().Contents()->ParserContext()))) {
          break;
        }
      }
    }
  }
  GetStyleEngine().SetPageColorSchemes(color_scheme);
}

void Document::SupportsReducedMotionMetaChanged() {
  auto* root_element = documentElement();
  if (!root_element)
    return;

  bool supports_reduced_motion = false;
  for (HTMLMetaElement& meta_element :
       Traversal<HTMLMetaElement>::DescendantsOf(*root_element)) {
    if (EqualIgnoringASCIICase(meta_element.GetName(),
                               "supports-reduced-motion")) {
      SpaceSplitString split_content(
          AtomicString(meta_element.Content().GetString().LowerASCII()));
```