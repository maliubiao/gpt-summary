Response:
The user wants a summary of the functionalities of the `FrameSerializer.cc` file, focusing on its relationship with web technologies like JavaScript, HTML, and CSS. I need to identify the core purpose of the code and illustrate its interactions with these technologies through examples and logical inferences. I also need to highlight potential user or programming errors related to this code.

Here's a plan:

1. **Identify the core functionality:** The file seems to be responsible for serializing a frame's content, likely for saving web pages.
2. **Analyze interactions with HTML:** Look for code that manipulates or generates HTML elements and attributes.
3. **Analyze interactions with CSS:**  Identify how stylesheets (inline and external) are handled and how CSS resources are processed.
4. **Analyze interactions with JavaScript:** Focus on the `AddScriptResource` function and its purpose in restoring functionality.
5. **Provide concrete examples:**  For each interaction, create illustrative scenarios with hypothetical inputs and outputs.
6. **Identify potential errors:**  Think about common mistakes developers or users might make that could be related to this serialization process.
7. **Synthesize a summary:** Combine all the findings into a concise overview of the file's functionalities.
好的，这是对 `blink/renderer/core/frame/frame_serializer.cc` 文件功能的归纳总结，基于您提供的第二部分代码：

**文件功能归纳总结 (基于第二部分代码):**

`FrameSerializer.cc` 的主要功能是**将一个 Frame 的内容序列化，用于保存网页。**  这包括将 HTML 结构、CSS 样式以及相关的资源（如图片、字体、脚本）转换为一种可以存储和重新加载的格式，特别是针对 MHTML (MIME HTML) 格式的生成。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * **功能:**  代码负责生成和处理 HTML 标签和属性，例如 `<link>` 标签用于引入 CSS， `<script>` 标签用于嵌入 JavaScript。
    * **举例:** `AppendLinkElement` 函数会向序列化的 HTML 中添加 `<link>` 标签来引用外部 CSS 文件或内联的样式。  `AppendAttribute` 会处理元素的属性，并可能根据需要重写链接。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:** 一个包含 `<img src="image.png">` 的 HTML 元素。
        * **输出:** 序列化的 HTML 中会保留 `<img>` 标签，并且 `FrameSerializer` 会将 `image.png` 这个资源添加到待保存的资源列表中。
* **CSS:**
    * **功能:**  代码负责提取和序列化 CSS 样式，包括内联样式（`<style>` 标签）和外部样式表（通过 `<link>` 标签引入）。它还会处理 CSS 中引用的资源，例如背景图片、字体等。
    * **举例:** `AppendStylesheet` 函数处理 `<style>` 标签或通过 `<link>` 引入的 CSS 文件。 `SerializeCSSStyleSheet` 函数负责将 CSS 内容转换为文本格式，并处理 `@charset` 声明。 `SerializeCSSResources` 和 `RetrieveResourcesForProperties` 函数用于查找和处理 CSS 规则中引用的图片、字体等资源。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:** 一个 CSS 文件包含 `body { background-image: url('bg.jpg'); }`。
        * **输出:** 序列化的 CSS 文件会包含上述规则，并且 `FrameSerializer` 会将 `bg.jpg` 这个图片资源添加到待保存的资源列表中。
* **JavaScript:**
    * **功能:**  代码会嵌入一段 JavaScript 代码，用于在重新加载保存的页面时恢复一些功能，特别是自定义元素的注册信息，以确保 CSS 的 `:defined` 选择器能够正常工作。
    * **举例:** `AddScriptResource` 函数会生成一个 `<script>` 标签，并嵌入一段 JavaScript 代码，这段代码会读取保存的自定义元素元数据，并使用 `window.customElements.define` 重新注册这些元素。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:** 页面中定义了一个自定义元素 `<my-element>`。
        * **输出:** 序列化的 HTML 中会包含嵌入的 JavaScript 代码，这段代码会包含 `<my-element>` 的定义信息。当重新加载页面时，这段 JavaScript 代码会被执行，使得 `:defined(my-element)` 选择器可以正确匹配到该元素。

**用户或编程常见的使用错误及举例说明:**

* **外部 CSS 资源路径错误:** 如果 HTML 中引用的外部 CSS 文件路径不正确，`FrameSerializer` 尝试获取该资源时可能会失败，导致保存的页面样式不完整。
    * **举例:**  `<link rel="stylesheet" href="styles/main.css">`，但 `styles/main.css` 文件不存在或路径错误。
* **CSS 中引用的图片或字体资源路径错误:**  类似于 CSS 文件路径错误，如果 CSS 中引用的图片或字体路径不正确，这些资源将无法被正确保存和加载。
    * **举例:** `body { background-image: url('../images/bg.png'); }`，但实际图片路径并非如此。
* **修改了嵌入的 JavaScript 代码:** 用户或开发者不应修改 `AddScriptResource` 中生成的 JavaScript 代码，因为这段代码负责恢复关键功能。修改可能导致保存的页面功能异常。
* **假设输入与输出 (针对用户错误):**
    * **假设用户错误:**  用户在本地开发时使用了相对路径引用 CSS 文件，例如 `href="css/style.css"`。但在保存页面后，由于文件结构变化，该相对路径在新的上下文中失效。
    * **预期输出:** 保存的 MHTML 文件中可能没有包含正确的 CSS 样式，导致页面显示异常。 `FrameSerializer` 在尝试获取资源时可能会遇到问题，但这通常不会导致程序崩溃，而是会导致保存内容不完整。

**总结该部分功能:**

这部分代码专注于**处理样式和脚本相关的序列化工作**。它负责：

1. **收集和嵌入 JavaScript 代码**，用于恢复自定义元素注册。
2. **处理和序列化 CSS 样式表**，包括内联样式和外部样式表。
3. **提取 CSS 中引用的资源** (如图片、字体) 并将其添加到待保存的资源列表中。
4. **生成 `<link>` 和 `<script>` 标签**，以便在重新加载页面时能够应用样式和执行脚本。
5. **处理和重写 HTML 元素的链接属性**。

总而言之，这部分代码确保了保存的网页不仅包含 HTML 结构，还包含了必要的样式和脚本信息，以尽可能地还原原始页面的外观和部分交互功能。

Prompt: 
```
这是目录为blink/renderer/core/frame/frame_serializer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
cument_->StyleSheets(), true /*style_element_only*/);
    }

    if (MHTMLImprovementsEnabled()) {
      markup_.Append("<script src=\"");
      KURL script_url = MakePseudoUrl("js");
      markup_.Append(script_url.GetString());
      markup_.Append("\"></script>");
      AddScriptResource(*document_, script_url);
    }
  }

  // Adds a script resource to restore some functionality to the serialized
  // HTML. We're including this self-contained blob of JS in the MHTML file
  // instead of compiling it into Chromium because it requires additional
  // information about custom elements, and packaging the metadata in another
  // format would require versioning, whereas JS allows it to be all
  // encapsulated.
  void AddScriptResource(Document& document, const KURL& script_url) {
    // Currently, the embedded JS here has one job. It restores the custom
    // element registry when loading the saved page, to enough fidelity to
    // ensure the CSS 'defined' selector works.
    // https://html.spec.whatwg.org/multipage/semantics-other.html#selector-defined.
    // Note that we do not need to actually restore any other functionality to
    // the custom elements because we are already saving a snapshot of the
    // element's shadow DOM, and our goal is to save a static snapshot of the
    // page.
    auto metadata = std::make_unique<JSONObject>();
    auto custom_elements = std::make_unique<JSONArray>();
    CustomElementRegistry* custom_registry = CustomElement::Registry(document);
    if (custom_registry) {
      for (const AtomicString& name : custom_registry->DefinedNames()) {
        CustomElementDefinition* definition =
            custom_registry->DefinitionForName(name);
        auto saved_definition = std::make_unique<JSONObject>();
        // There are two types of custom elements.
        // 1. autonomous elements, which always extend HTMLElement.
        // 2. customized built-in elements, which can extend standard HTML
        // elements. Here, "local_name" is the name of the extended element,
        // i.e. HTMLParagraphElement.
        saved_definition->SetString("name", name);
        saved_definition->SetBoolean("is_autonomous",
                                     definition->Descriptor().IsAutonomous());
        if (!definition->Descriptor().IsAutonomous()) {
          saved_definition->SetString("local_name",
                                      definition->Descriptor().LocalName());
        }
        custom_elements->PushObject(std::move(saved_definition));
      }
    }
    metadata->SetArray("custom_elements", std::move(custom_elements));

    // Note that we try/catch for addCustomElement below because it's possible
    // but not expected for it to fail, i.e. if standard HTML element type is
    // removed.
    StringView main_script = R"js(
function addCustomElement(def) {
  if (def.is_autonomous) {
      window.customElements.define(def.name, class extends HTMLElement{});
  } else {
    const templateElement = document.createElement(def.local_name);
    const baseName = Object.getPrototypeOf(templateElement).constructor.name;
    const ElementBase = window[baseName];
    window.customElements.define(def.name, class extends ElementBase {},
      {extends: def.local_name});
  }
}

function addCustomElements(metadata) {
  for (const def of metadata.custom_elements) {
    try {
      addCustomElement(def);
    } catch (e) {
      console.log(e);
    }
  }
}

function main(metadata) {
  addCustomElements(metadata);
}
)js";

    StringBuilder builder;
    builder.Append("(()=>{");
    {
      builder.Append(main_script);
      builder.Append("main(");
      metadata->WriteJSON(&builder);
      builder.Append(");");
    }
    builder.Append("})();");
    resource_serializer_->AddToResources(SerializedResource(
        script_url, "text/javascript",
        SharedBuffer::Create(builder.ToString().RawByteSpan())));
  }

  // Add `sheet` as a new resource and emit a <link> element to load it.
  void AppendStylesheet(StyleSheet& sheet) {
    if (!sheet.IsCSSStyleSheet() || sheet.disabled()) {
      return;
    }

    KURL pseudo_sheet_url = MakePseudoCSSUrl();
    AppendLinkElement(markup_, pseudo_sheet_url);
    SerializeCSSStyleSheet(static_cast<CSSStyleSheet&>(sheet),
                           pseudo_sheet_url);
  }

  void AppendStylesheets(StyleSheetList& sheets, bool style_element_only) {
    for (unsigned i = 0; i < sheets.length(); ++i) {
      StyleSheet* sheet = sheets.item(i);
      if (style_element_only && !IsA<HTMLStyleElement>(sheet->ownerNode())) {
        continue;
      }
      AppendStylesheet(*sheet);
    }
  }

  // Appends <link> elements to construct the same styles from `root`'s
  // `AdoptedStyleSheets()`.
  void AppendAdoptedStyleSheets(TreeScope* root) {
    auto* sheets = root->AdoptedStyleSheets();
    if (!sheets) {
      return;
    }

    for (blink::CSSStyleSheet* sheet : *sheets) {
      // Serialize the stylesheet only the first time it's visited.
      KURL pseudo_sheet_url;
      auto iter = stylesheet_pseudo_urls_.find(sheet);
      if (iter != stylesheet_pseudo_urls_.end()) {
        pseudo_sheet_url = iter->value;
      } else {
        pseudo_sheet_url = MakePseudoCSSUrl();
        SerializeCSSStyleSheet(static_cast<CSSStyleSheet&>(*sheet),
                               pseudo_sheet_url);
        stylesheet_pseudo_urls_.insert(sheet, pseudo_sheet_url);
      }

      AppendLinkElement(markup_, pseudo_sheet_url);
    }
  }

  void AppendStylesheets(Document* document, bool style_element_only) {
    StyleSheetList& sheets = document->StyleSheets();
    for (unsigned i = 0; i < sheets.length(); ++i) {
      StyleSheet* sheet = sheets.item(i);
      if (!sheet->IsCSSStyleSheet() || sheet->disabled()) {
        continue;
      }
      if (style_element_only && !IsA<HTMLStyleElement>(sheet->ownerNode())) {
        continue;
      }

      KURL pseudo_sheet_url = MakePseudoCSSUrl();
      AppendLinkElement(markup_, pseudo_sheet_url);
      SerializeCSSStyleSheet(static_cast<CSSStyleSheet&>(*sheet),
                             pseudo_sheet_url);
    }
  }

  void AppendAttribute(const Element& element,
                       const Attribute& attribute) override {
    // Check if link rewriting can affect the attribute.
    bool is_link_attribute = element.HasLegalLinkAttribute(attribute.GetName());
    bool is_src_doc_attribute = IsA<HTMLFrameElementBase>(element) &&
                                attribute.GetName() == html_names::kSrcdocAttr;
    if (is_link_attribute || is_src_doc_attribute) {
      // Check if the delegate wants to do link rewriting for the element.
      String new_link_for_the_element;
      if (RewriteLink(element, new_link_for_the_element)) {
        if (is_link_attribute) {
          // Rewrite element links.
          AppendRewrittenAttribute(element, attribute.GetName().ToString(),
                                   new_link_for_the_element);
        } else {
          DCHECK(is_src_doc_attribute);
          // Emit src instead of srcdoc attribute for frame elements - we want
          // the serialized subframe to use html contents from the link provided
          // by Delegate::rewriteLink rather than html contents from srcdoc
          // attribute.
          AppendRewrittenAttribute(element, html_names::kSrcAttr.LocalName(),
                                   new_link_for_the_element);
        }
        return;
      }
    }

    // Fallback to appending the original attribute.
    MarkupAccumulator::AppendAttribute(element, attribute);
  }

  void AppendAttributeValue(const String& attribute_value) {
    MarkupFormatter::AppendAttributeValue(
        markup_, attribute_value, IsA<HTMLDocument>(document_), *document_);
  }

  void AppendRewrittenAttribute(const Element& element,
                                const String& attribute_name,
                                const String& attribute_value) {
    if (elements_with_rewritten_links_.Contains(&element)) {
      return;
    }
    elements_with_rewritten_links_.insert(&element);

    // Append the rewritten attribute.
    // TODO(tiger): Refactor MarkupAccumulator so it is easier to append an
    // attribute like this.
    markup_.Append(' ');
    markup_.Append(attribute_name);
    markup_.Append("=\"");
    AppendAttributeValue(attribute_value);
    markup_.Append("\"");
  }

  void AddResourceForElement(Document& document, const Element& element) {
    // We have to process in-line style as it might contain some resources
    // (typically background images).
    if (element.IsStyledElement()) {
      RetrieveResourcesForProperties(element.InlineStyle(), document);
      RetrieveResourcesForProperties(
          const_cast<Element&>(element).PresentationAttributeStyle(), document);
    }

    if (const auto* image = DynamicTo<HTMLImageElement>(element)) {
      AtomicString image_url_value;
      const Element* parent = element.parentElement();
      if (parent && IsA<HTMLPictureElement>(parent)) {
        // If parent element is <picture>, use ImageSourceURL() to get best fit
        // image URL from sibling source.
        image_url_value = image->ImageSourceURL();
      } else {
        // Otherwise, it is single <img> element. We should get image url
        // contained in href attribute. ImageSourceURL() may return a different
        // URL from srcset attribute.
        image_url_value = image->FastGetAttribute(html_names::kSrcAttr);
      }
      ImageResourceContent* cached_image = image->CachedImage();
      resource_serializer_->AddImageToResources(
          cached_image, document.CompleteURL(image_url_value));
    } else if (const auto* svg_image = DynamicTo<SVGImageElement>(element)) {
      if (MHTMLImprovementsEnabled()) {
        ImageResourceContent* cached_image = svg_image->CachedImage();
        if (cached_image) {
          resource_serializer_->AddImageToResources(
              cached_image, document.CompleteURL(svg_image->SourceURL()));
        }
      }
    } else if (const auto* input = DynamicTo<HTMLInputElement>(element)) {
      if (input->FormControlType() == FormControlType::kInputImage &&
          input->ImageLoader()) {
        KURL image_url = input->Src();
        ImageResourceContent* cached_image = input->ImageLoader()->GetContent();
        resource_serializer_->AddImageToResources(cached_image, image_url);
      }
    } else if (const auto* link = DynamicTo<HTMLLinkElement>(element)) {
      if (CSSStyleSheet* sheet = link->sheet()) {
        KURL sheet_url =
            document.CompleteURL(link->FastGetAttribute(html_names::kHrefAttr));
        if (MHTMLImprovementsEnabled()) {
          SerializeCSSResources(*sheet);
          SerializeCSSFile(document, sheet_url);
        } else {
          SerializeCSSStyleSheet(*sheet, sheet_url);
        }
      }
    } else if (const auto* style = DynamicTo<HTMLStyleElement>(element)) {
      if (CSSStyleSheet* sheet = style->sheet()) {
        SerializeCSSStyleSheet(*sheet, NullURL());
      }
    } else if (const auto* plugin = DynamicTo<HTMLPlugInElement>(&element)) {
      if (plugin->IsImageType() && plugin->ImageLoader()) {
        KURL image_url = document.CompleteURL(plugin->Url());
        ImageResourceContent* cached_image =
            plugin->ImageLoader()->GetContent();
        resource_serializer_->AddImageToResources(cached_image, image_url);
      }
    }
  }

  // Serializes `style_sheet` as text that can be added to an inline <style>
  // tag. Ensures the style sheet does not include the </style> end tag.
  String SerializeInlineCSSStyleSheet(CSSStyleSheet& style_sheet) {
    StringBuilder css_text;
    for (unsigned i = 0; i < style_sheet.length(); ++i) {
      CSSRule* rule = style_sheet.ItemInternal(i);
      String item_text = rule->cssText();
      if (!item_text.empty()) {
        css_text.Append(item_text);
        if (i < style_sheet.length() - 1) {
          css_text.Append("\n\n");
        }
      }
    }

    // `css_text` is the text that has already been parsed from the <style> tag,
    // so it does not retain escape sequences. The only time we would need to
    // emit an escape sequence is if the </style> tag appears within `css_text`.
    // Parsing <style> contents is described in
    // https://html.spec.whatwg.org/multipage/parsing.html#rawtext-state.
    // Note that when replacing the "style" text. HTML tags are case
    // insensitive, but this is escaped, so it's not not actually an HTML end
    // tag.
    return blink::internal::ReplaceAllCaseInsensitive(
        css_text.ToString(), "</style", [](const String& text) {
          StringBuilder builder;
          builder.Append("\\3C/");  // \3C = '<'.
          builder.Append(text.Substring(2));
          return builder.ReleaseString();
        });
  }

  void SerializeCSSFile(Document& document, const KURL& url) {
    if (!url.IsValid() || !url.ProtocolIsInHTTPFamily()) {
      return;
    }

    resource_serializer_->FetchAndAddResource(
        document, url, mojom::blink::RequestContextType::STYLE,
        // A missing CSS file will usually have a large impact on page
        // appearance. Allow fetching from the cache or network to improve the
        // chances of getting the resource.
        mojom::blink::FetchCacheMode::kDefault);
  }

  // Attempts to serialize a stylesheet, if necessary. Does a couple things:
  // 1. If `url` is valid and not a data URL, and we haven't already serialized
  // this url, then serialize the stylesheet into a new resource. Note that this
  // process is lossy, and may not perfectly reflect the intended style.
  // 2. Even if `url` is invalid or a data URL, serialize the resources within
  // `style_sheet`.
  void SerializeCSSStyleSheet(CSSStyleSheet& style_sheet, const KURL& url) {
    // If the URL is invalid or if it is a data URL this means that this CSS is
    // defined inline, respectively in a <style> tag or in the data URL itself.
    bool is_inline_css = !url.IsValid() || url.ProtocolIsData();
    // If this CSS is not inline then it is identifiable by its URL. So just
    // skip it if it has already been analyzed before.
    if (!is_inline_css && !resource_serializer_->ShouldAddURL(url)) {
      return;
    }

    TRACE_EVENT2("page-serialization",
                 "FrameSerializer::serializeCSSStyleSheet", "type", "CSS",
                 "url", url.ElidedString().Utf8());

    const auto& charset = style_sheet.Contents()->Charset();

    // If this CSS is inlined its definition was already serialized with the
    // frame HTML code that was previously generated. No need to regenerate it
    // here.
    if (!is_inline_css) {
      StringBuilder css_text;
      // Adopted stylesheets may not have a defined charset, so use UTF-8 in
      // that case.
      css_text.Append("@charset \"");
      css_text.Append(charset.IsValid()
                          ? charset.GetName().GetString().DeprecatedLower()
                          : "utf-8");
      css_text.Append("\";\n\n");

      for (unsigned i = 0; i < style_sheet.length(); ++i) {
        CSSRule* rule = style_sheet.ItemInternal(i);
        String item_text = rule->cssText();
        if (!item_text.empty()) {
          css_text.Append(item_text);
          if (i < style_sheet.length() - 1) {
            css_text.Append("\n\n");
          }
        }
      }

      String text_string = css_text.ToString();
      std::string text;
      if (charset.IsValid()) {
        WTF::TextEncoding text_encoding(charset);
        text = text_encoding.Encode(text_string,
                                    WTF::kCSSEncodedEntitiesForUnencodables);
      } else {
        text = WTF::UTF8Encoding().Encode(
            text_string, WTF::kCSSEncodedEntitiesForUnencodables);
      }

      resource_serializer_->AddToResources(
          String("text/css"), SharedBuffer::Create(text.c_str(), text.length()),
          url);
    }

    // Sub resources need to be serialized even if the CSS definition doesn't
    // need to be.
    SerializeCSSResources(style_sheet);
  }

  // Serializes resources referred to by `style_sheet`.
  void SerializeCSSResources(CSSStyleSheet& style_sheet) {
    for (unsigned i = 0; i < style_sheet.length(); ++i) {
      SerializeCSSRuleResources(style_sheet.ItemInternal(i));
    }
  }

  void SerializeCSSRuleResources(CSSRule* rule) {
    DCHECK(rule->parentStyleSheet()->OwnerDocument());
    Document& document = *rule->parentStyleSheet()->OwnerDocument();

    switch (rule->GetType()) {
      case CSSRule::kStyleRule:
        RetrieveResourcesForProperties(
            &To<CSSStyleRule>(rule)->GetStyleRule()->Properties(), document);
        break;

      case CSSRule::kImportRule: {
        CSSImportRule* import_rule = To<CSSImportRule>(rule);
        KURL sheet_base_url = rule->parentStyleSheet()->BaseURL();
        DCHECK(sheet_base_url.IsValid());
        KURL import_url = KURL(sheet_base_url, import_rule->href());
        if (import_rule->styleSheet()) {
          if (MHTMLImprovementsEnabled()) {
            SerializeCSSResources(*import_rule->styleSheet());
            SerializeCSSFile(document, import_url);
          } else {
            SerializeCSSStyleSheet(*import_rule->styleSheet(), import_url);
          }
        }
        break;
      }

      // Rules inheriting CSSGroupingRule
      case CSSRule::kNestedDeclarationsRule:
      case CSSRule::kMediaRule:
      case CSSRule::kSupportsRule:
      case CSSRule::kContainerRule:
      case CSSRule::kLayerBlockRule:
      case CSSRule::kScopeRule:
      case CSSRule::kStartingStyleRule: {
        CSSRuleList* rule_list = rule->cssRules();
        for (unsigned i = 0; i < rule_list->length(); ++i) {
          SerializeCSSRuleResources(rule_list->item(i));
        }
        break;
      }

      case CSSRule::kFontFaceRule:
        RetrieveResourcesForProperties(
            &To<CSSFontFaceRule>(rule)->StyleRule()->Properties(), document);
        break;

      case CSSRule::kCounterStyleRule:
        // TODO(crbug.com/1176323): Handle image symbols in @counter-style rules
        // when we implement it.
        break;

      case CSSRule::kMarginRule:
      case CSSRule::kPageRule:
        // TODO(crbug.com/40341678): Both page and margin rules may contain
        // external resources (e.g. via background-image). FrameSerializer is at
        // the mercy of whatever resource loading has already been triggered (by
        // regular lifecycle updates). See crbug.com/364331857 . As such, unless
        // the user has actually tried to print the page, resources inside @page
        // rules won't have been loaded. Rather than introducing flaky behavior
        // (sometimes @page resources are loaded, sometimes not), let's wait for
        // that bug to be fixed.
        break;

      // Rules in which no external resources can be referenced
      case CSSRule::kCharsetRule:
      case CSSRule::kFontPaletteValuesRule:
      case CSSRule::kFontFeatureRule:
      case CSSRule::kFontFeatureValuesRule:
      case CSSRule::kPropertyRule:
      case CSSRule::kKeyframesRule:
      case CSSRule::kKeyframeRule:
      case CSSRule::kNamespaceRule:
      case CSSRule::kLayerStatementRule:
      case CSSRule::kViewTransitionRule:
      case CSSRule::kPositionTryRule:
        break;
    }
  }

  void RetrieveResourcesForProperties(
      const CSSPropertyValueSet* style_declaration,
      Document& document) {
    if (!style_declaration) {
      return;
    }

    // The background-image and list-style-image (for ul or ol) are the CSS
    // properties that make use of images. We iterate to make sure we include
    // any other image properties there might be.
    unsigned property_count = style_declaration->PropertyCount();
    for (unsigned i = 0; i < property_count; ++i) {
      const CSSValue& css_value = style_declaration->PropertyAt(i).Value();
      RetrieveResourcesForCSSValue(css_value, document);
    }
  }

  void RetrieveResourcesForCSSValue(const CSSValue& css_value,
                                    Document& document) {
    if (const auto* image_value = DynamicTo<CSSImageValue>(css_value)) {
      if (image_value->IsCachePending()) {
        return;
      }
      StyleImage* style_image = image_value->CachedImage();
      if (!style_image || !style_image->IsImageResource()) {
        return;
      }

      resource_serializer_->AddImageToResources(
          style_image->CachedImage(), style_image->CachedImage()->Url());
    } else if (const auto* font_face_src_value =
                   DynamicTo<CSSFontFaceSrcValue>(css_value)) {
      if (font_face_src_value->IsLocal()) {
        return;
      }

      resource_serializer_->AddFontToResources(
          document,
          font_face_src_value->Fetch(document.GetExecutionContext(), nullptr));
    } else if (const auto* css_value_list =
                   DynamicTo<CSSValueList>(css_value)) {
      for (unsigned i = 0; i < css_value_list->length(); i++) {
        RetrieveResourcesForCSSValue(css_value_list->Item(i), document);
      }
    }
  }

  MultiResourcePacker* resource_serializer_;
  WebFrameSerializer::MHTMLPartsGenerationDelegate* web_delegate_;
  Document* document_;

  mutable HeapHashSet<WeakMember<const Element>> shadow_template_elements_;
  mutable bool popup_overlays_skipped_ = false;

  // Elements with links rewritten via appendAttribute method.
  HeapHashSet<Member<const Element>> elements_with_rewritten_links_;
  // Adopted stylesheets can be reused. This stores the set of stylesheets
  // already serialized as resources, along with their URL.
  HeapHashMap<Member<blink::CSSStyleSheet>, KURL> stylesheet_pseudo_urls_;

  // Style elements whose contents will be serialized just before inserting
  // </style>.
  HeapHashSet<Member<const HTMLStyleElement>>
      style_elements_to_replace_contents_;
};

}  // namespace

// TODO(tiger): Right now there is no support for rewriting URLs inside CSS
// documents which leads to bugs like <https://crbug.com/251898>. Not being
// able to rewrite URLs inside CSS documents means that resources imported from
// url(...) statements in CSS might not work when rewriting links for the
// "Webpage, Complete" method of saving a page. It will take some work but it
// needs to be done if we want to continue to support non-MHTML saved pages.

// static
void FrameSerializer::SerializeFrame(
    WebFrameSerializer::MHTMLPartsGenerationDelegate& web_delegate,
    LocalFrame& frame,
    base::OnceCallback<void(Deque<SerializedResource>)> done_callback) {
  TRACE_EVENT0("page-serialization", "FrameSerializer::serializeFrame");
  DCHECK(frame.GetDocument());
  Document& document = *frame.GetDocument();
  KURL url = document.Url();
  auto* resource_serializer =
      MakeGarbageCollected<MultiResourcePacker>(&web_delegate);
  auto callback = std::move(done_callback);
  // If frame is an image document, add the image and don't continue
  if (auto* image_document = DynamicTo<ImageDocument>(document)) {
    resource_serializer->AddImageToResources(image_document->CachedImage(),
                                             url);
    resource_serializer->Finish(std::move(callback));
    return;
  }

  {
    TRACE_EVENT0("page-serialization", "FrameSerializer::serializeFrame HTML");
    SerializerMarkupAccumulator accumulator(resource_serializer, &web_delegate,
                                            document);
    String text =
        accumulator.SerializeNodes<EditingStrategy>(document, kIncludeNode);

    std::string frame_html =
        document.Encoding().Encode(text, WTF::kEntitiesForUnencodables);
    resource_serializer->AddMainResource(
        document.SuggestedMIMEType(),
        SharedBuffer::Create(frame_html.c_str(), frame_html.length()), url);
    resource_serializer->Finish(std::move(callback));
  }
}

// Returns MOTW (Mark of the Web) declaration before html tag which is in
// HTML comment, e.g. "<!-- saved from url=(%04d)%s -->"
// See http://msdn2.microsoft.com/en-us/library/ms537628(VS.85).aspx.
// static
String FrameSerializer::MarkOfTheWebDeclaration(const KURL& url) {
  StringBuilder builder;
  bool emits_minus = false;
  for (const char ch : url.GetString().Ascii()) {
    if (ch == '-' && emits_minus) {
      builder.Append("%2D");
      emits_minus = false;
      continue;
    }
    emits_minus = ch == '-';
    builder.Append(ch);
  }
  std::string escaped_url = builder.ToString().Ascii();
  return String::Format("saved from url=(%04d)%s",
                        static_cast<int>(escaped_url.length()),
                        escaped_url.c_str());
}

// static
String FrameSerializer::GetContentID(Frame* frame) {
  DCHECK(frame);
  const String& frame_id = frame->GetFrameIdForTracing();
  return "<frame-" + frame_id + "@mhtml.blink>";
}

}  // namespace blink

"""


```