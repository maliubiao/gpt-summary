Response:
Let's break down the thought process for analyzing the provided C++ code snippet. The goal is to understand the functionality of `markup_accumulator.cc` and relate it to web technologies (HTML, CSS, JavaScript).

**1. Initial Reading and High-Level Understanding:**

* **File Path:**  `blink/renderer/core/editing/serializers/markup_accumulator.cc`  This immediately tells me the file is part of the Blink rendering engine, specifically dealing with *editing*, *serialization*, and accumulating *markup*. The "serializers" directory is a strong hint about its purpose.
* **Copyright Notice:**  Indicates the code has been around for a while and has contributions from Apple and Google. This is common for Chromium code.
* **Includes:**  The included headers give valuable clues:
    * `dom/attr.h`, `dom/element.h`, `dom/document.h`, etc.:  Deals with the Document Object Model (DOM).
    * `editing/editing_utilities.h`, `editing/editor.h`: Relates to the editing functionality within the browser.
    * `serializers/serialization.h`: Suggests this class is part of a larger serialization framework.
    * `html/html_element.h`, `html_names.h`: Specifically handles HTML elements.
    * `xml_names.h`, `xmlns_names.h`: Deals with XML namespaces.
    * `platform/weborigin/kurl.h`:  Handles URLs.
    * `wtf/text/character_names.h`:  Provides character-related utilities.
* **Namespace:** `namespace blink { ... }` confirms it's part of the Blink engine.
* **Class `MarkupAccumulator`:** This is the central class. The comments about "serializing an element" and "not inherited to child node serialization" are key.

**2. Identifying Key Functionality - Method by Method (Skimming and Focused Reading):**

I'll go through the methods, focusing on their names and any comments.

* **Constructor & Destructor:** Basic setup and cleanup.
* **`AppendString`:**  Simple string appending, likely to the output markup.
* **`AppendEndTag`:** Handles closing HTML/XML tags. The `formatter_` member is important here.
* **`AppendStartMarkup`:**  Handles the beginning of elements and other nodes. The switch statement tells me it handles different node types.
* **`AppendCustomAttributes`:**  A hook for adding specific attributes in subclasses.
* **`WillProcessAttribute`, `WillProcessElement`:** These look like hooks for filtering or modifying what gets serialized.
* **`AppendElement`:**  The core method for processing an element. It calls `AppendStartTagOpen`, handles attributes, `AppendCustomAttributes`, and `AppendStartTagClose`.
* **`AppendStartTagOpen`:** This is where the complex namespace handling seems to happen. The comments and the `NamespaceContext` inner class are crucial here.
* **`AppendStartTagClose`:**  Closes the opening tag.
* **`AppendAttribute`:**  Handles attribute serialization, distinguishing between HTML and XML.
* **`AppendAttributeAsXMLWithNamespace`:**  Specifically deals with XML attribute serialization and namespace considerations.
* **`ShouldAddNamespaceAttribute`:**  Logic for deciding when to add namespace declarations.
* **`AppendNamespace`:** Adds namespace declarations to the output.
* **`EntityMaskForText`:**  Deals with character escaping for text content.
* **`PushNamespaces`, `PopNamespaces`:**  Manages a stack of namespace contexts, essential for correct XML serialization.
* **`NamespaceContext` (Inner Class):**  This is critical for understanding how namespaces are tracked and managed during serialization. I'll need to pay close attention to its methods like `Add`, `RecordNamespaceInformation`, `LookupNamespaceURI`, etc. The comments referencing the DOM Parsing specification are valuable.
* **`RetrievePreferredPrefixString`, `AddPrefix`, `LookupNamespaceURI`, `GeneratePrefix`:**  These methods within `MarkupAccumulator` and `NamespaceContext` work together to handle namespace prefix management.
* **`SerializeAsHTML`:** A helper to check the serialization mode.
* **`GetShadowTree`:**  Deals with serializing shadow DOM, a key feature of web components. The different `ShadowRootInclusion` behaviors are important.
* **`SerializeNodesWithNamespaces`:**  The main recursive function for serializing a node and its children, taking namespaces into account.
* **`SerializeNodes`:**  The entry point for serialization, setting up the initial namespace context for XML.

**3. Relating to Web Technologies:**

As I understand the methods, I start making connections to HTML, CSS, and JavaScript:

* **HTML:** The class directly deals with serializing HTML elements and attributes. Methods like `AppendAttributeAsHTML`, handling of `<template shadowrootmode>`, and the `SerializeAsHTML` flag are clear indicators.
* **CSS:** While this class doesn't directly manipulate CSS styles, the *output* of the serialization process can be used to represent HTML that *will* be styled by CSS. For example, the correct namespace prefixes are important for CSS selectors in XML-based formats like SVG.
* **JavaScript:**  JavaScript often interacts with the DOM and can trigger serialization. For instance, using `innerHTML` to get the HTML of an element internally uses a serialization mechanism. The `MarkupAccumulator` is likely involved in such operations within the Blink engine. Also, the shadow DOM serialization is very relevant to JavaScript and web components.

**4. Logical Reasoning and Examples:**

Now I can start formulating examples and reasoning about inputs and outputs.

* **Namespace Handling:** I'll focus on how the `NamespaceContext` works with different XML structures. Examples involving default namespaces, prefixed namespaces, and nested elements with different namespaces are good.
* **Shadow DOM:** I'll consider cases where shadow DOM is present, both open and closed, and how the `ShadowRootInclusion` settings affect the output.
* **Attribute Serialization:**  I'll think about how attributes with and without namespaces are handled in both HTML and XML modes.

**5. Common Usage Errors and Debugging:**

* **Incorrect Namespace Handling:**  A common error when dealing with XML is using incorrect or missing namespace prefixes. The `MarkupAccumulator`'s logic is designed to prevent this, but understanding the rules is important for debugging.
* **Shadow DOM Serialization Issues:**  Not understanding the `ShadowRootInclusion` settings can lead to unexpected results when serializing elements with shadow DOM.

**6. User Actions and Debugging Clues:**

I'll think about how a user action in the browser can lead to this code being executed:

* **Copying and Pasting:** When a user copies content from a web page, the browser needs to serialize the selected DOM nodes.
* **`innerHTML` or `outerHTML` in JavaScript:**  JavaScript code using these properties will trigger serialization.
* **Saving a Web Page:**  The browser needs to serialize the entire DOM to save the page.
* **Developer Tools:**  Inspecting element HTML in the DevTools involves serialization.

By following this systematic approach, combining code reading with knowledge of web technologies and focusing on the purpose of the file, I can arrive at a comprehensive understanding of the `markup_accumulator.cc` file's functionality and its relevance within the Chromium browser.
好的，让我们来详细分析一下 `blink/renderer/core/editing/serializers/markup_accumulator.cc` 这个文件的功能。

**功能概述:**

`MarkupAccumulator` 类是 Blink 渲染引擎中负责将 DOM (Document Object Model) 树或其一部分序列化为字符串表示形式的核心组件。 简单来说，它的主要功能是将 DOM 结构转换成 HTML 或 XML 格式的文本。

**核心功能点:**

1. **DOM 树遍历和处理:**  `MarkupAccumulator` 能够递归地遍历 DOM 树的节点（元素、文本、注释等）。
2. **生成 HTML/XML 标记:**  针对遍历到的不同类型的 DOM 节点，生成相应的 HTML 或 XML 标记字符串。这包括：
    * **元素标签:** 生成开始标签 `<tag>` 和结束标签 `</tag>`，并处理属性。
    * **文本内容:**  直接输出文本内容，并进行必要的转义（例如，将 `<` 转义为 `&lt;`）。
    * **注释:** 生成注释 `<!-- comment -->`。
    * **CDATA 区块:** 生成 CDATA 区块 `<![CDATA[ ... ]]>`。
    * **文档类型声明:** 生成文档类型声明 `<!DOCTYPE ...>`。
    * **处理指令:** 生成处理指令 `<? ... ?>`。
3. **属性处理:**  能够提取和格式化元素的属性，包括：
    * **标准属性:**  例如 `id`, `class`, `href` 等。
    * **自定义属性:**  任何添加到元素上的属性。
    * **命名空间处理:**  正确处理 XML 命名空间前缀和 URI。
4. **命名空间管理:**  在 XML 序列化过程中，维护一个命名空间上下文栈，以确保正确地添加和使用命名空间声明 (`xmlns` 属性)。
5. **URL 解析:**  可以根据配置解析属性值中的相对 URL，将其转换为绝对 URL。
6. **HTML 特性处理:**  针对 HTML 序列化，会考虑 HTML 的特定规则，例如：
    * **自闭合标签:**  例如 `<br>`, `<meta>` 等。
    * **属性值的引号:**  根据需要添加或省略属性值的引号。
    * **布尔属性:**  例如 `<input checked>`。
7. **Shadow DOM 支持:**  可以根据配置选择性地序列化元素的 Shadow DOM (影子 DOM)。
8. **可扩展性:**  提供了一些钩子方法 (`AppendCustomAttributes`, `WillProcessAttribute`, `WillProcessElement`)，允许子类扩展其行为，添加自定义的序列化逻辑。

**与 JavaScript, HTML, CSS 的关系:**

`MarkupAccumulator` 在浏览器内部扮演着关键的角色，连接了 JavaScript 操作 DOM 和最终呈现的 HTML/XML。

* **JavaScript:**
    * **`innerHTML` 和 `outerHTML`:** 当 JavaScript 代码访问元素的 `innerHTML` 或 `outerHTML` 属性时，Blink 引擎内部会使用类似 `MarkupAccumulator` 的机制将 DOM 结构序列化成字符串返回给 JavaScript。
    * **DOM 操作:** JavaScript 对 DOM 的修改最终会反映在 DOM 树上。当需要将这些修改后的 DOM 结构发送到服务器或以其他形式保存时，就需要用到序列化，`MarkupAccumulator` 就是执行这个任务的组件。
    * **`XMLSerializer` API:**  JavaScript 提供了 `XMLSerializer` API，允许开发者将 DOM 树序列化为 XML 字符串。`MarkupAccumulator` 的 XML 序列化部分就是实现这个 API 的基础。
* **HTML:**
    * **渲染过程:**  当浏览器加载 HTML 页面时，会解析 HTML 代码并构建 DOM 树。反过来，`MarkupAccumulator` 的作用就是将 DOM 树转换回 HTML 格式的字符串。
    * **复制粘贴:**  当用户在网页上复制内容时，浏览器需要将选中的 DOM 结构序列化成 HTML 格式，以便粘贴到其他应用程序中。
* **CSS:**
    * **样式应用:** CSS 规则是基于 HTML 结构进行应用的。虽然 `MarkupAccumulator` 本身不直接处理 CSS，但它生成的 HTML 字符串是 CSS 样式作用的对象。正确的 HTML 结构对于 CSS 样式能够正确应用至关重要。
    * **Shadow DOM 样式隔离:**  `MarkupAccumulator` 对 Shadow DOM 的处理也间接影响了 CSS 的作用域，因为它决定了 Shadow DOM 的内容是否以及如何被包含在序列化结果中。

**功能举例说明:**

**HTML 关系:**

假设有以下 HTML 结构：

```html
<div id="container">
  <p class="text">这是一个段落。</p>
  <img src="image.png" alt="图片">
</div>
```

当使用 `MarkupAccumulator` 对这个 DOM 结构进行 HTML 序列化时，可能会得到类似的字符串：

```html
<div id="container">
  <p class="text">这是一个段落。</p>
  <img src="image.png" alt="图片">
</div>
```

**JavaScript 关系:**

假设 JavaScript 代码如下：

```javascript
const container = document.getElementById('container');
const htmlString = container.innerHTML;
console.log(htmlString);
```

当执行这段代码时，Blink 引擎内部会调用类似 `MarkupAccumulator` 的机制来获取 `container` 元素内部的 HTML 字符串，输出结果可能为：

```html
  <p class="text">这是一个段落。</p>
  <img src="image.png" alt="图片">
```

**CSS 关系:**

虽然 `MarkupAccumulator` 不直接处理 CSS，但它生成的 HTML 结构会影响 CSS 的应用。例如，如果序列化过程中错误地移除了某个元素的 `class` 属性，那么针对该 `class` 的 CSS 样式将不再生效。

**逻辑推理 (假设输入与输出):**

**假设输入:**  一个简单的 DOM 树，包含一个带有属性的 `<div>` 元素和一个文本子节点。

```
<div id="example" class="container">Hello</div>
```

**预期输出 (HTML 序列化):**

```
<div id="example" class="container">Hello</div>
```

**假设输入:**  一个包含 XML 命名空间的 DOM 树。

```xml
<root xmlns:custom="http://example.com/ns">
  <custom:element attr="value">Content</custom:element>
</root>
```

**预期输出 (XML 序列化):**

```xml
<root xmlns:custom="http://example.com/ns">
  <custom:element attr="value">Content</custom:element>
</root>
```

**用户或编程常见的使用错误:**

1. **不正确的命名空间处理 (XML):**  在 XML 序列化时，如果命名空间前缀没有正确声明或使用，会导致生成的 XML 不符合规范。例如，忘记在根元素上声明命名空间。

   ```xml
   <!-- 错误示例：缺少 xmlns:custom 声明 -->
   <root>
     <custom:element>Content</custom:element>
   </root>
   ```

2. **URL 解析错误:**  如果配置了 URL 解析，但基础 URL 不正确，会导致相对 URL 解析为错误的绝对 URL。

3. **Shadow DOM 序列化配置错误:**  如果没有正确配置 `ShadowRootInclusion`，可能会导致 Shadow DOM 内容被意外地包含或排除在序列化结果之外。

4. **手动拼接 HTML 字符串的替代:**  新手可能会尝试手动拼接 HTML 字符串，而不是使用类似 `MarkupAccumulator` 这样的工具。这容易出错，并且难以处理复杂的 DOM 结构和转义。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中进行复制操作:**
   * 用户选中网页上的部分内容，例如一段文字和一个图片。
   * 用户按下 `Ctrl+C` (或 `Cmd+C`) 进行复制。
   * 浏览器捕获复制事件，并需要将选中的 DOM 节点序列化成 HTML 格式，以便存储到剪贴板。
   * 这个过程中，Blink 引擎会调用相关的序列化代码，`MarkupAccumulator` 很可能参与其中。

2. **JavaScript 代码访问 `innerHTML` 或 `outerHTML`:**
   * 网页上的 JavaScript 代码执行了类似 `document.getElementById('someId').innerHTML` 的操作。
   * Blink 引擎接收到这个请求，需要将对应元素的子树序列化成 HTML 字符串返回给 JavaScript。
   * `MarkupAccumulator` 会被用来执行这个序列化任务。

3. **使用开发者工具查看元素:**
   * 用户在浏览器中打开开发者工具 (通常按 `F12`)。
   * 用户选择 "Elements" 面板，并选中一个 DOM 元素。
   * 开发者工具需要显示该元素的 HTML 源代码。
   * Blink 引擎会使用序列化机制 (可能涉及 `MarkupAccumulator`) 将该元素的 DOM 结构转换为 HTML 字符串显示在开发者工具中。

4. **保存网页:**
   * 用户选择浏览器的 "保存网页" 功能。
   * 浏览器需要将当前页面的 DOM 结构序列化成 HTML 文件保存到本地。
   * `MarkupAccumulator` 会参与到这个将整个文档树转换为 HTML 代码的过程中。

**总结:**

`MarkupAccumulator` 是 Blink 渲染引擎中一个至关重要的组件，负责将 DOM 结构转换为字符串表示形式，主要用于 HTML 和 XML 的序列化。它与 JavaScript 操作 DOM、HTML 的渲染以及 CSS 样式的应用都有着密切的关系。理解它的功能对于深入了解浏览器内部工作原理以及进行 Web 开发和调试都非常有帮助。

### 提示词
```
这是目录为blink/renderer/core/editing/serializers/markup_accumulator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2012 Apple Inc. All
 * rights reserved. Copyright (C) 2009, 2010 Google Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "third_party/blink/renderer/core/editing/serializers/markup_accumulator.h"

#include "base/containers/adapters.h"
#include "third_party/blink/renderer/core/dom/attr.h"
#include "third_party/blink/renderer/core/dom/cdata_section.h"
#include "third_party/blink/renderer/core/dom/comment.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/document_type.h"
#include "third_party/blink/renderer/core/dom/processing_instruction.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/keywords.h"
#include "third_party/blink/renderer/core/xml_names.h"
#include "third_party/blink/renderer/core/xmlns_names.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"

namespace blink {

class MarkupAccumulator::NamespaceContext final {
  USING_FAST_MALLOC(MarkupAccumulator::NamespaceContext);

 public:
  // https://w3c.github.io/DOM-Parsing/#dfn-add
  //
  // This function doesn't accept empty prefix and empty namespace URI.
  //  - The default namespace is managed separately.
  //  - Namespace URI never be empty if the prefix is not empty.
  void Add(const AtomicString& prefix, const AtomicString& namespace_uri) {
    DCHECK(!prefix.empty())
        << " prefix=" << prefix << " namespace_uri=" << namespace_uri;
    DCHECK(!namespace_uri.empty())
        << " prefix=" << prefix << " namespace_uri=" << namespace_uri;
    prefix_ns_map_.Set(prefix, namespace_uri);
    auto result =
        ns_prefixes_map_.insert(namespace_uri, Vector<AtomicString>());
    result.stored_value->value.push_back(prefix);
  }

  // https://w3c.github.io/DOM-Parsing/#dfn-recording-the-namespace-information
  AtomicString RecordNamespaceInformation(const Element& element) {
    AtomicString local_default_namespace;
    // 2. For each attribute attr in element's attributes, in the order they are
    // specified in the element's attribute list:
    for (const auto& attr : element.Attributes()) {
      // We don't check xmlns namespace of attr here because xmlns attributes in
      // HTML documents don't have namespace URI. Some web tests serialize
      // HTML documents with XMLSerializer, and Firefox has the same behavior.
      if (attr.Prefix().empty() && attr.LocalName() == g_xmlns_atom) {
        // 3.1. If attribute prefix is null, then attr is a default namespace
        // declaration. Set the default namespace attr value to attr's value
        // and stop running these steps, returning to Main to visit the next
        // attribute.
        local_default_namespace = attr.Value();
      } else if (attr.Prefix() == g_xmlns_atom) {
        Add(attr.Prefix() ? attr.LocalName() : g_empty_atom, attr.Value());
      }
    }
    // 3. Return the value of default namespace attr value.
    return local_default_namespace;
  }

  AtomicString LookupNamespaceURI(const AtomicString& prefix) const {
    auto it = prefix_ns_map_.find(prefix ? prefix : g_empty_atom);
    return it != prefix_ns_map_.end() ? it->value : g_null_atom;
  }

  const AtomicString& ContextNamespace() const { return context_namespace_; }
  void SetContextNamespace(const AtomicString& context_ns) {
    context_namespace_ = context_ns;
  }

  void InheritLocalDefaultNamespace(
      const AtomicString& local_default_namespace) {
    if (!local_default_namespace)
      return;
    SetContextNamespace(local_default_namespace.empty()
                            ? g_null_atom
                            : local_default_namespace);
  }

  Vector<AtomicString> PrefixList(const AtomicString& ns) const {
    auto it = ns_prefixes_map_.find(ns ? ns : g_empty_atom);
    return it != ns_prefixes_map_.end() ? it->value : Vector<AtomicString>();
  }

 private:
  using PrefixToNamespaceMap = HashMap<AtomicString, AtomicString>;
  PrefixToNamespaceMap prefix_ns_map_;

  // Map a namespace URI to a list of prefixes.
  // https://w3c.github.io/DOM-Parsing/#the-namespace-prefix-map
  using NamespaceToPrefixesMap = HashMap<AtomicString, Vector<AtomicString>>;
  NamespaceToPrefixesMap ns_prefixes_map_;

  // https://w3c.github.io/DOM-Parsing/#dfn-context-namespace
  AtomicString context_namespace_;
};

// This stores values used to serialize an element. The values are not
// inherited to child node serialization.
class MarkupAccumulator::ElementSerializationData final {
  STACK_ALLOCATED();

 public:
  // https://w3c.github.io/DOM-Parsing/#dfn-ignore-namespace-definition-attribute
  bool ignore_namespace_definition_attribute_ = false;

  AtomicString serialized_prefix_;
};

MarkupAccumulator::MarkupAccumulator(
    AbsoluteURLs resolve_urls_method,
    SerializationType serialization_type,
    const ShadowRootInclusion& shadow_root_inclusion,
    AttributesMode attributes_mode)
    : formatter_(resolve_urls_method, serialization_type),
      shadow_root_inclusion_(shadow_root_inclusion),
      attributes_mode_(attributes_mode) {}

MarkupAccumulator::~MarkupAccumulator() = default;

void MarkupAccumulator::AppendString(const String& string) {
  markup_.Append(string);
}

void MarkupAccumulator::AppendEndTag(const Element& element,
                                     const AtomicString& prefix) {
  formatter_.AppendEndMarkup(markup_, element, prefix, element.localName());
}

void MarkupAccumulator::AppendStartMarkup(const Node& node) {
  switch (node.getNodeType()) {
    case Node::kTextNode:
      formatter_.AppendText(markup_, To<Text>(node));
      break;
    case Node::kElementNode:
      NOTREACHED();
    case Node::kAttributeNode:
      // Only XMLSerializer can pass an Attr.  So, |documentIsHTML| flag is
      // false.
      formatter_.AppendAttributeValue(markup_, To<Attr>(node).value(), false,
                                      node.GetDocument());
      break;
    default:
      formatter_.AppendStartMarkup(markup_, node);
      break;
  }
}

void MarkupAccumulator::AppendCustomAttributes(const Element&) {}

MarkupAccumulator::EmitAttributeChoice MarkupAccumulator::WillProcessAttribute(
    const Element& element,
    const Attribute& attribute) const {
  return EmitAttributeChoice::kEmit;
}

MarkupAccumulator::EmitElementChoice MarkupAccumulator::WillProcessElement(
    const Element& element) {
  return EmitElementChoice::kEmit;
}

AtomicString MarkupAccumulator::AppendElement(const Element& element) {
  const ElementSerializationData data = AppendStartTagOpen(element);
  AttributeCollection attributes =
      attributes_mode_ == AttributesMode::kSynchronized
          ? element.Attributes()
          : element.AttributesWithoutUpdate();
  if (SerializeAsHTML()) {
    // https://html.spec.whatwg.org/C/#html-fragment-serialisation-algorithm

    // 3.2. Element: If current node's is value is not null, and the
    // element does not have an is attribute in its attribute list, ...
    const AtomicString& is_value = element.IsValue();
    if (!is_value.IsNull() && !attributes.Find(html_names::kIsAttr)) {
      AppendAttribute(element, Attribute(html_names::kIsAttr, is_value));
    }
    for (const auto& attribute : attributes) {
      if (EmitAttributeChoice::kEmit ==
          WillProcessAttribute(element, attribute)) {
        AppendAttribute(element, attribute);
      }
    }
  } else {
    // https://w3c.github.io/DOM-Parsing/#xml-serializing-an-element-node

    for (const auto& attribute : attributes) {
      if (data.ignore_namespace_definition_attribute_ &&
          attribute.NamespaceURI() == xmlns_names::kNamespaceURI &&
          attribute.Prefix().empty()) {
        // Drop xmlns= only if it's inconsistent with element's namespace.
        // https://github.com/w3c/DOM-Parsing/issues/47
        if (!EqualIgnoringNullity(attribute.Value(), element.namespaceURI()))
          continue;
      }
      if (EmitAttributeChoice::kEmit ==
          WillProcessAttribute(element, attribute)) {
        AppendAttribute(element, attribute);
      }
    }
  }

  // Give an opportunity to subclasses to add their own attributes.
  AppendCustomAttributes(element);

  AppendStartTagClose(element);
  return data.serialized_prefix_;
}

MarkupAccumulator::ElementSerializationData
MarkupAccumulator::AppendStartTagOpen(const Element& element) {
  ElementSerializationData data;
  data.serialized_prefix_ = element.prefix();
  if (SerializeAsHTML()) {
    formatter_.AppendStartTagOpen(markup_, element);
    return data;
  }

  // https://w3c.github.io/DOM-Parsing/#xml-serializing-an-element-node

  NamespaceContext& namespace_context = namespace_stack_.back();

  // 5. Let ignore namespace definition attribute be a boolean flag with value
  // false.
  data.ignore_namespace_definition_attribute_ = false;
  // 8. Let local default namespace be the result of recording the namespace
  // information for node given map and local prefixes map.
  AtomicString local_default_namespace =
      namespace_context.RecordNamespaceInformation(element);
  // 9. Let inherited ns be a copy of namespace.
  AtomicString inherited_ns = namespace_context.ContextNamespace();
  // 10. Let ns be the value of node's namespaceURI attribute.
  AtomicString ns = element.namespaceURI();

  // 11. If inherited ns is equal to ns, then:
  if (inherited_ns == ns) {
    // 11.1. If local default namespace is not null, then set ignore namespace
    // definition attribute to true.
    data.ignore_namespace_definition_attribute_ =
        !local_default_namespace.IsNull();
    // 11.3. Otherwise, append to qualified name the value of node's
    // localName. The node's prefix if it exists, is dropped.

    // 11.4. Append the value of qualified name to markup.
    formatter_.AppendStartTagOpen(markup_, g_null_atom, element.localName());
    data.serialized_prefix_ = g_null_atom;
    return data;
  }

  // 12. Otherwise, inherited ns is not equal to ns (the node's own namespace is
  // different from the context namespace of its parent). Run these sub-steps:
  // 12.1. Let prefix be the value of node's prefix attribute.
  AtomicString prefix = element.prefix();
  // 12.2. Let candidate prefix be the result of retrieving a preferred prefix
  // string prefix from map given namespace ns.
  AtomicString candidate_prefix;
  if (!ns.empty() && (!prefix.empty() || ns != local_default_namespace)) {
    candidate_prefix = RetrievePreferredPrefixString(ns, prefix);
  }
  // 12.4. if candidate prefix is not null (a namespace prefix is defined which
  // maps to ns), then:
  if (!candidate_prefix.IsNull() && LookupNamespaceURI(candidate_prefix)) {
    // 12.4.1. Append to qualified name the concatenation of candidate prefix,
    // ":" (U+003A COLON), and node's localName.
    // 12.4.3. Append the value of qualified name to markup.
    formatter_.AppendStartTagOpen(markup_, candidate_prefix,
                                  element.localName());
    data.serialized_prefix_ = candidate_prefix;
    // 12.4.2. If the local default namespace is not null (there exists a
    // locally-defined default namespace declaration attribute) and its value is
    // not the XML namespace, then let inherited ns get the value of local
    // default namespace unless the local default namespace is the empty string
    // in which case let it get null (the context namespace is changed to the
    // declared default, rather than this node's own namespace).
    if (local_default_namespace != xml_names::kNamespaceURI)
      namespace_context.InheritLocalDefaultNamespace(local_default_namespace);
    return data;
  }

  // 12.5. Otherwise, if prefix is not null, then:
  if (!prefix.empty()) {
    // 12.5.1. If the local prefixes map contains a key matching prefix, then
    // let prefix be the result of generating a prefix providing as input map,
    // ns, and prefix index
    if (element.hasAttribute(
            AtomicString(String(WTF::g_xmlns_with_colon + prefix)))) {
      prefix = GeneratePrefix(ns);
    } else {
      // 12.5.2. Add prefix to map given namespace ns.
      AddPrefix(prefix, ns);
    }
    // 12.5.3. Append to qualified name the concatenation of prefix, ":" (U+003A
    // COLON), and node's localName.
    // 12.5.4. Append the value of qualified name to markup.
    formatter_.AppendStartTagOpen(markup_, prefix, element.localName());
    data.serialized_prefix_ = prefix;
    // 12.5.5. Append the following to markup, in the order listed:
    MarkupFormatter::AppendAttribute(markup_, g_xmlns_atom, prefix, ns, false,
                                     element.GetDocument());
    // 12.5.5.7. If local default namespace is not null (there exists a
    // locally-defined default namespace declaration attribute), then let
    // inherited ns get the value of local default namespace unless the local
    // default namespace is the empty string in which case let it get null.
    namespace_context.InheritLocalDefaultNamespace(local_default_namespace);
    return data;
  }

  // 12.6. Otherwise, if local default namespace is null, or local default
  // namespace is not null and its value is not equal to ns, then:
  if (local_default_namespace.IsNull() ||
      !EqualIgnoringNullity(local_default_namespace, ns)) {
    // 12.6.1. Set the ignore namespace definition attribute flag to true.
    data.ignore_namespace_definition_attribute_ = true;
    // 12.6.3. Let the value of inherited ns be ns.
    namespace_context.SetContextNamespace(ns);
    // 12.6.4. Append the value of qualified name to markup.
    formatter_.AppendStartTagOpen(markup_, element);
    // 12.6.5. Append the following to markup, in the order listed:
    MarkupFormatter::AppendAttribute(markup_, g_null_atom, g_xmlns_atom, ns,
                                     false, element.GetDocument());
    return data;
  }

  // 12.7. Otherwise, the node has a local default namespace that matches
  // ns. Append to qualified name the value of node's localName, let the value
  // of inherited ns be ns, and append the value of qualified name to markup.
  DCHECK(EqualIgnoringNullity(local_default_namespace, ns));
  namespace_context.SetContextNamespace(ns);
  formatter_.AppendStartTagOpen(markup_, element);
  return data;
}

void MarkupAccumulator::AppendStartTagClose(const Element& element) {
  formatter_.AppendStartTagClose(markup_, element);
}

void MarkupAccumulator::AppendAttribute(const Element& element,
                                        const Attribute& attribute) {
  String value = formatter_.ResolveURLIfNeeded(element, attribute);
  if (SerializeAsHTML()) {
    MarkupFormatter::AppendAttributeAsHTML(markup_, attribute, value,
                                           element.GetDocument());
  } else {
    AppendAttributeAsXMLWithNamespace(element, attribute, value);
  }
}

void MarkupAccumulator::AppendAttributeAsXMLWithNamespace(
    const Element& element,
    const Attribute& attribute,
    const String& value) {
  // https://w3c.github.io/DOM-Parsing/#serializing-an-element-s-attributes

  // 3.3. Let attribute namespace be the value of attr's namespaceURI value.
  const AtomicString& attribute_namespace = attribute.NamespaceURI();

  // 3.4. Let candidate prefix be null.
  AtomicString candidate_prefix;

  if (attribute_namespace.IsNull()) {
    MarkupFormatter::AppendAttribute(markup_, candidate_prefix,
                                     attribute.LocalName(), value, false,
                                     element.GetDocument());
    return;
  }
  // 3.5. If attribute namespace is not null, then run these sub-steps:

  // 3.5.1. Let candidate prefix be the result of retrieving a preferred
  // prefix string from map given namespace attribute namespace with preferred
  // prefix being attr's prefix value.
  candidate_prefix =
      RetrievePreferredPrefixString(attribute_namespace, attribute.Prefix());

  // 3.5.2. If the value of attribute namespace is the XMLNS namespace, then
  // run these steps:
  if (attribute_namespace == xmlns_names::kNamespaceURI) {
    if (!attribute.Prefix() && attribute.LocalName() != g_xmlns_atom)
      candidate_prefix = g_xmlns_atom;
  } else {
    // 3.5.3. Otherwise, the attribute namespace in not the XMLNS namespace.
    // Run these steps:
    if (ShouldAddNamespaceAttribute(attribute, candidate_prefix)) {
      if (!candidate_prefix || LookupNamespaceURI(candidate_prefix)) {
        // 3.5.3.1. Let candidate prefix be the result of generating a prefix
        // providing map, attribute namespace, and prefix index as input.
        candidate_prefix = GeneratePrefix(attribute_namespace);
        // 3.5.3.2. Append the following to result, in the order listed:
        MarkupFormatter::AppendAttribute(markup_, g_xmlns_atom,
                                         candidate_prefix, attribute_namespace,
                                         false, element.GetDocument());
      } else {
        DCHECK(candidate_prefix);
        AppendNamespace(candidate_prefix, attribute_namespace,
                        element.GetDocument());
      }
    }
  }
  MarkupFormatter::AppendAttribute(markup_, candidate_prefix,
                                   attribute.LocalName(), value, false,
                                   element.GetDocument());
}

bool MarkupAccumulator::ShouldAddNamespaceAttribute(
    const Attribute& attribute,
    const AtomicString& candidate_prefix) {
  // xmlns and xmlns:prefix attributes should be handled by another branch in
  // AppendAttributeAsXMLWithNamespace().
  DCHECK_NE(attribute.NamespaceURI(), xmlns_names::kNamespaceURI);
  // Null namespace is checked earlier in AppendAttributeAsXMLWithNamespace().
  DCHECK(attribute.NamespaceURI());

  // Attributes without a prefix will need one generated for them, and an xmlns
  // attribute for that prefix.
  if (!candidate_prefix)
    return true;

  return !EqualIgnoringNullity(LookupNamespaceURI(candidate_prefix),
                               attribute.NamespaceURI());
}

void MarkupAccumulator::AppendNamespace(const AtomicString& prefix,
                                        const AtomicString& namespace_uri,
                                        const Document& document) {
  AtomicString found_uri = LookupNamespaceURI(prefix);
  if (!EqualIgnoringNullity(found_uri, namespace_uri)) {
    AddPrefix(prefix, namespace_uri);
    if (prefix.empty()) {
      MarkupFormatter::AppendAttribute(markup_, g_null_atom, g_xmlns_atom,
                                       namespace_uri, false, document);
    } else {
      MarkupFormatter::AppendAttribute(markup_, g_xmlns_atom, prefix,
                                       namespace_uri, false, document);
    }
  }
}

EntityMask MarkupAccumulator::EntityMaskForText(const Text& text) const {
  return formatter_.EntityMaskForText(text);
}

void MarkupAccumulator::PushNamespaces(const Element& element) {
  if (SerializeAsHTML())
    return;
  DCHECK_GT(namespace_stack_.size(), 0u);
  // TODO(tkent): Avoid to copy the whole map.
  // We can't do |namespace_stack_.emplace_back(namespace_stack_.back())|
  // because back() returns a reference in the vector backing, and
  // emplace_back() can reallocate it.
  namespace_stack_.push_back(NamespaceContext(namespace_stack_.back()));
}

void MarkupAccumulator::PopNamespaces(const Element& element) {
  if (SerializeAsHTML())
    return;
  namespace_stack_.pop_back();
}

// https://w3c.github.io/DOM-Parsing/#dfn-retrieving-a-preferred-prefix-string
AtomicString MarkupAccumulator::RetrievePreferredPrefixString(
    const AtomicString& ns,
    const AtomicString& preferred_prefix) {
  DCHECK(!ns.empty()) << ns;
  AtomicString ns_for_preferred = LookupNamespaceURI(preferred_prefix);
  // Preserve the prefix if the prefix is used in the scope and the namespace
  // for it is matches to the node's one.
  // This is equivalent to the following step in the specification:
  // 2.1. If prefix matches preferred prefix, then stop running these steps and
  // return prefix.
  if (!preferred_prefix.empty() && !ns_for_preferred.IsNull() &&
      EqualIgnoringNullity(ns_for_preferred, ns))
    return preferred_prefix;

  const Vector<AtomicString>& candidate_list =
      namespace_stack_.back().PrefixList(ns);
  // Get the last effective prefix.
  //
  // <el1 xmlns:p="U1" xmlns:q="U1">
  //   <el2 xmlns:q="U2">
  //    el2.setAttributeNS(U1, 'n', 'v');
  // We should get 'p'.
  //
  // <el1 xmlns="U1">
  //  el1.setAttributeNS(U1, 'n', 'v');
  // We should not get '' for attributes.
  for (const auto& candidate_prefix : base::Reversed(candidate_list)) {
    DCHECK(!candidate_prefix.empty());
    AtomicString ns_for_candidate = LookupNamespaceURI(candidate_prefix);
    if (EqualIgnoringNullity(ns_for_candidate, ns))
      return candidate_prefix;
  }

  // No prefixes for |ns|.
  // Preserve the prefix if the prefix is not used in the current scope.
  if (!preferred_prefix.empty() && ns_for_preferred.IsNull())
    return preferred_prefix;
  // If a prefix is not specified, or the prefix is mapped to a
  // different namespace, we should generate new prefix.
  return g_null_atom;
}

void MarkupAccumulator::AddPrefix(const AtomicString& prefix,
                                  const AtomicString& namespace_uri) {
  namespace_stack_.back().Add(prefix, namespace_uri);
}

AtomicString MarkupAccumulator::LookupNamespaceURI(const AtomicString& prefix) {
  return namespace_stack_.back().LookupNamespaceURI(prefix);
}

// https://w3c.github.io/DOM-Parsing/#dfn-generating-a-prefix
AtomicString MarkupAccumulator::GeneratePrefix(
    const AtomicString& new_namespace) {
  AtomicString generated_prefix;
  do {
    // 1. Let generated prefix be the concatenation of the string "ns" and the
    // current numerical value of prefix index.
    generated_prefix = "ns" + String::Number(prefix_index_);
    // 2. Let the value of prefix index be incremented by one.
    ++prefix_index_;
  } while (LookupNamespaceURI(generated_prefix));
  // 3. Add to map the generated prefix given the new namespace namespace.
  AddPrefix(generated_prefix, new_namespace);
  // 4. Return the value of generated prefix.
  return generated_prefix;
}

bool MarkupAccumulator::SerializeAsHTML() const {
  return formatter_.SerializeAsHTML();
}

// This serializes the shadow root of this element, if present. The behavior
// is controlled by shadow_root_inclusion_:
//  - If behavior is kIncludeSerializableShadowRoots, then any open shadow
//    root that also has its `serializable` bit set will be serialized.
//  - If behavior is kIncludeAllOpenShadowRoots, then any open shadow root
//    will be serialized, *regardless* of the state of its `serializable` bit.
//  - Any shadow root included in the `include_shadow_roots` collection will be
//    serialized.
using Behavior = ShadowRootInclusion::Behavior;
std::pair<ShadowRoot*, HTMLTemplateElement*> MarkupAccumulator::GetShadowTree(
    const Element& element) const {
  ShadowRoot* shadow_root = element.GetShadowRoot();
  if (!shadow_root || shadow_root->GetMode() == ShadowRootMode::kUserAgent) {
    // User agent shadow roots are never serialized.
    return std::pair<ShadowRoot*, HTMLTemplateElement*>();
  }
  if (!shadow_root_inclusion_.include_shadow_roots.Contains(shadow_root)) {
    std::pair<ShadowRoot*, HTMLTemplateElement*> no_serialization;
    switch (shadow_root_inclusion_.behavior) {
      case Behavior::kOnlyProvidedShadowRoots:
        return no_serialization;
      case Behavior::kIncludeAllOpenShadowRoots:
        if (shadow_root->GetMode() == ShadowRootMode::kClosed) {
          return no_serialization;
        }
        break;
      case Behavior::kIncludeAnySerializableShadowRoots:
        if (!shadow_root->serializable()) {
          return no_serialization;
        }
        break;
    }
  }

  // Wrap the shadowroot into a declarative Shadow DOM <template shadowrootmode>
  // element.
  HTMLTemplateElement* template_element =
      MakeGarbageCollected<HTMLTemplateElement>(element.GetDocument());
  template_element->setAttribute(html_names::kShadowrootmodeAttr,
                                 shadow_root->GetMode() == ShadowRootMode::kOpen
                                     ? keywords::kOpen
                                     : keywords::kClosed);
  if (shadow_root->delegatesFocus()) {
    template_element->SetBooleanAttribute(
        html_names::kShadowrootdelegatesfocusAttr, true);
  }
  if (shadow_root->serializable()) {
    template_element->SetBooleanAttribute(
        html_names::kShadowrootserializableAttr, true);
  }
  if (shadow_root->clonable()) {
    template_element->SetBooleanAttribute(html_names::kShadowrootclonableAttr,
                                          true);
  }
  return std::pair<ShadowRoot*, HTMLTemplateElement*>(shadow_root,
                                                      template_element);
}

template <typename Strategy>
void MarkupAccumulator::SerializeNodesWithNamespaces(
    const Node& target_node,
    ChildrenOnly children_only) {
  if (!target_node.IsElementNode()) {
    if (!children_only)
      AppendStartMarkup(target_node);
    for (const Node& child : Strategy::ChildrenOf(target_node))
      SerializeNodesWithNamespaces<Strategy>(child, kIncludeNode);
    return;
  }

  const auto& target_element = To<Element>(target_node);
  EmitElementChoice emit_choice = WillProcessElement(target_element);
  if (emit_choice == EmitElementChoice::kIgnore) {
    return;
  }

  PushNamespaces(target_element);

  AtomicString prefix_override;
  if (!children_only)
    prefix_override = AppendElement(target_element);

  bool has_end_tag =
      !(SerializeAsHTML() && ElementCannotHaveEndTag(target_element));
  if (has_end_tag) {
    if (emit_choice != EmitElementChoice::kEmitButIgnoreChildren) {
      const Node* parent = &target_element;
      if (auto* template_element =
              DynamicTo<HTMLTemplateElement>(target_element)) {
        // Declarative shadow roots that are currently being parsed will have a
        // null content() - don't serialize contents in this case.
        parent = template_element->content();
      }

      // Traverses the shadow tree.
      std::pair<ShadowRoot*, Element*> auxiliary_pair =
          GetShadowTree(target_element);
      if (ShadowRoot* auxiliary_tree = auxiliary_pair.first) {
        Element* enclosing_element = auxiliary_pair.second;
        AtomicString enclosing_element_prefix;
        if (enclosing_element) {
          enclosing_element_prefix = AppendElement(*enclosing_element);
        }
        for (const Node& child : Strategy::ChildrenOf(*auxiliary_tree)) {
          SerializeNodesWithNamespaces<Strategy>(child, kIncludeNode);
        }
        if (enclosing_element) {
          WillCloseSyntheticTemplateElement(*auxiliary_tree);
          AppendEndTag(*enclosing_element, enclosing_element_prefix);
        }
      }

      if (parent) {
        for (const Node& child : Strategy::ChildrenOf(*parent)) {
          SerializeNodesWithNamespaces<Strategy>(child, kIncludeNode);
        }
      }
    }

    if (!children_only)
      AppendEndTag(target_element, prefix_override);
  }

  PopNamespaces(target_element);
}

template <typename Strategy>
CORE_EXPORT String
MarkupAccumulator::SerializeNodes(const Node& target_node,
                                  ChildrenOnly children_only) {
  if (!SerializeAsHTML()) {
    // https://w3c.github.io/DOM-Parsing/#dfn-xml-serialization
    DCHECK_EQ(namespace_stack_.size(), 0u);
    // 2. Let prefix map be a new namespace prefix map.
    namespace_stack_.emplace_back();
    // 3. Add the XML namespace with prefix value "xml" to prefix map.
    AddPrefix(g_xml_atom, xml_names::kNamespaceURI);
    // 4. Let prefix index be a generated namespace prefix index with value 1.
    prefix_index_ = 1;
  }

  SerializeNodesWithNamespaces<Strategy>(target_node, children_only);
  return ToString();
}

template String MarkupAccumulator::SerializeNodes<EditingStrategy>(
    const Node&,
    ChildrenOnly);

}  // namespace blink
```